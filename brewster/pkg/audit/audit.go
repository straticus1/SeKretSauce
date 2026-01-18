package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/afterdarktech/brewster/internal/config"
	"github.com/afterdarktech/brewster/pkg/brew"
)

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingType categorizes the type of security issue
type FindingType string

const (
	FindingCVE          FindingType = "CVE"
	FindingAbandoned    FindingType = "ABANDONED"
	FindingHTTP         FindingType = "INSECURE_HTTP"
	FindingDeprecated   FindingType = "DEPRECATED"
	FindingNoChecksum   FindingType = "NO_CHECKSUM"
	FindingUntrustedTap FindingType = "UNTRUSTED_TAP"
	FindingDeadURL      FindingType = "DEAD_URL"
)

// Finding represents a security finding
type Finding struct {
	Package     string      `json:"package"`
	Type        FindingType `json:"type"`
	Severity    Severity    `json:"severity"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	URL         string      `json:"url,omitempty"`
	CVE         string      `json:"cve,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
}

// AuditResult holds the results of an audit
type AuditResult struct {
	Timestamp      time.Time `json:"timestamp"`
	PackagesScanned int      `json:"packages_scanned"`
	TapsScanned     int      `json:"taps_scanned"`
	Findings        []Finding `json:"findings"`
	Summary         Summary   `json:"summary"`
}

// Summary provides counts by severity
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// RunLocalAudit performs a security audit on locally installed packages
func RunLocalAudit(cfg config.AuditConfig) (*AuditResult, error) {
	result := &AuditResult{
		Timestamp: time.Now(),
		Findings:  []Finding{},
	}

	// Get installed packages
	packages, err := brew.GetInstalledFormulae()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}
	result.PackagesScanned = len(packages)

	// Get installed taps
	taps, err := brew.GetInstalledTaps()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed taps: %w", err)
	}
	result.TapsScanned = len(taps)

	if cfg.Verbose {
		fmt.Printf("  Scanning %d packages and %d taps...\n", len(packages), len(taps))
	}

	// Check for HTTP URLs
	if cfg.CheckHTTP {
		for _, pkg := range packages {
			if brew.IsHTTPURL(pkg.URL) {
				result.Findings = append(result.Findings, Finding{
					Package:     pkg.FullName,
					Type:        FindingHTTP,
					Severity:    SeverityMedium,
					Title:       "Package uses insecure HTTP URL",
					Description: fmt.Sprintf("Package %s downloads from an HTTP URL which could be intercepted", pkg.Name),
					URL:         pkg.URL,
					Remediation: "Consider reporting this to the tap maintainer",
				})
			}
		}
	}

	// Check for untrusted taps
	for _, tap := range taps {
		if !tap.Official {
			result.Findings = append(result.Findings, Finding{
				Package:     tap.Name,
				Type:        FindingUntrustedTap,
				Severity:    SeverityInfo,
				Title:       "Third-party tap installed",
				Description: fmt.Sprintf("Tap %s is not an official Homebrew tap", tap.Name),
				URL:         tap.Remote,
				Remediation: "Verify the tap source is trustworthy",
			})
		}
	}

	// Check for abandoned/deprecated packages
	if cfg.CheckAbandoned {
		for _, pkg := range packages {
			findings := checkAbandoned(pkg, cfg.Verbose)
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Check for CVEs
	if cfg.CheckCVE {
		findings := checkCVEs(packages, cfg.Verbose)
		result.Findings = append(result.Findings, findings...)
	}

	// Calculate summary
	result.Summary = calculateSummary(result.Findings)

	return result, nil
}

func checkAbandoned(pkg brew.InstalledPackage, verbose bool) []Finding {
	var findings []Finding

	// Check if it's a GitHub repo and if so, check activity
	owner, repo, ok := brew.ExtractGitHubRepo(pkg.Homepage)
	if !ok {
		owner, repo, ok = brew.ExtractGitHubRepo(pkg.URL)
	}

	if ok {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET",
			fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
		if err != nil {
			return findings
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return findings
		}
		defer resp.Body.Close()

		if resp.StatusCode == 404 {
			findings = append(findings, Finding{
				Package:     pkg.FullName,
				Type:        FindingDeadURL,
				Severity:    SeverityHigh,
				Title:       "Repository not found",
				Description: fmt.Sprintf("The GitHub repository for %s no longer exists", pkg.Name),
				URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
				Remediation: "Consider uninstalling this package or finding an alternative",
			})
			return findings
		}

		if resp.StatusCode == 200 {
			var repoInfo struct {
				Archived  bool      `json:"archived"`
				PushedAt  time.Time `json:"pushed_at"`
				OpenIssues int      `json:"open_issues_count"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err == nil {
				// Check if archived
				if repoInfo.Archived {
					findings = append(findings, Finding{
						Package:     pkg.FullName,
						Type:        FindingAbandoned,
						Severity:    SeverityMedium,
						Title:       "Repository is archived",
						Description: fmt.Sprintf("The upstream repository for %s has been archived", pkg.Name),
						URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
						Remediation: "Consider finding an actively maintained alternative",
					})
				}

				// Check for inactivity (no commits in 2 years)
				if time.Since(repoInfo.PushedAt) > 2*365*24*time.Hour {
					findings = append(findings, Finding{
						Package:     pkg.FullName,
						Type:        FindingAbandoned,
						Severity:    SeverityLow,
						Title:       "Repository appears abandoned",
						Description: fmt.Sprintf("No commits to %s/%s in over 2 years (last: %s)",
							owner, repo, repoInfo.PushedAt.Format("2006-01-02")),
						URL:         fmt.Sprintf("https://github.com/%s/%s", owner, repo),
						Remediation: "Monitor for security issues; consider alternatives",
					})
				}
			}
		}
	}

	return findings
}

func checkCVEs(packages []brew.InstalledPackage, verbose bool) []Finding {
	var findings []Finding

	// Query OSV.dev for known vulnerabilities
	for _, pkg := range packages {
		cves := queryOSV(pkg.Name, pkg.Version)
		for _, cve := range cves {
			findings = append(findings, Finding{
				Package:     pkg.FullName,
				Type:        FindingCVE,
				Severity:    cve.Severity,
				Title:       fmt.Sprintf("Known vulnerability: %s", cve.ID),
				Description: cve.Summary,
				CVE:         cve.ID,
				URL:         cve.Reference,
				Remediation: "Update to a patched version or apply workarounds",
			})
		}
	}

	return findings
}

type osvVuln struct {
	ID        string
	Summary   string
	Severity  Severity
	Reference string
}

func queryOSV(name, version string) []osvVuln {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query OSV.dev API
	payload := fmt.Sprintf(`{"package":{"name":"%s","ecosystem":"Homebrew"},"version":"%s"}`, name, version)
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.osv.dev/v1/query",
		strings.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result struct {
		Vulns []struct {
			ID         string `json:"id"`
			Summary    string `json:"summary"`
			Severity   []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			References []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	var vulns []osvVuln
	for _, v := range result.Vulns {
		sev := SeverityMedium // default
		for _, s := range v.Severity {
			if s.Type == "CVSS_V3" {
				// Parse CVSS score
				sev = cvssToSeverity(s.Score)
				break
			}
		}

		ref := ""
		for _, r := range v.References {
			if r.Type == "ADVISORY" || ref == "" {
				ref = r.URL
			}
		}

		vulns = append(vulns, osvVuln{
			ID:        v.ID,
			Summary:   v.Summary,
			Severity:  sev,
			Reference: ref,
		})
	}

	return vulns
}

func cvssToSeverity(score string) Severity {
	// CVSS v3 score ranges
	// This is a simplified parsing
	if strings.Contains(score, "9.") || strings.Contains(score, "10.") {
		return SeverityCritical
	}
	if strings.Contains(score, "7.") || strings.Contains(score, "8.") {
		return SeverityHigh
	}
	if strings.Contains(score, "4.") || strings.Contains(score, "5.") || strings.Contains(score, "6.") {
		return SeverityMedium
	}
	return SeverityLow
}

func calculateSummary(findings []Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.Critical++
		case SeverityHigh:
			s.High++
		case SeverityMedium:
			s.Medium++
		case SeverityLow:
			s.Low++
		case SeverityInfo:
			s.Info++
		}
		s.Total++
	}
	return s
}
