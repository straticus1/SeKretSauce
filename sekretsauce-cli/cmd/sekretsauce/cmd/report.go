package cmd

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Findings are the single source for totals, display, and snapshot comparison.
// Evidence here is metadata only; secret matches and browser contents stay out.
type Finding struct {
	ID          string `json:"id"`
	ScannerID   string `json:"scanner_id"`
	TargetID    string `json:"target_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Remediation string `json:"remediation"`
}

type ScanComponent struct {
	ScannerID     string    `json:"scanner_id"`
	Version       int       `json:"version"`
	Status        string    `json:"status"`
	Errors        []string  `json:"errors"`
	SkippedReason string    `json:"skipped_reason"`
	Findings      []Finding `json:"findings"`
}

func (r *ScanResults) addComponent(id, status string, errors []string, skipped string) {
	if errors == nil {
		errors = []string{}
	}
	r.Components = append(r.Components, ScanComponent{ScannerID: id, Version: 1, Status: status, Errors: errors, SkippedReason: skipped, Findings: []Finding{}})
}

func (r *ScanResults) normalize() {
	r.Findings = []Finding{}
	add := func(scanner, target, category, severity, title, remediation string) {
		severity = strings.ToLower(severity)
		switch severity {
		case "critical", "high", "medium", "low":
		default:
			severity = "medium"
		}
		sum := sha256.Sum256([]byte(scanner + "\x00" + target + "\x00" + category + "\x00" + title))
		r.Findings = append(r.Findings, Finding{ID: fmt.Sprintf("%x", sum), ScannerID: scanner, TargetID: target, Category: category, Severity: severity, Title: title, Remediation: remediation})
	}
	if r.Keychain != nil {
		for _, x := range r.Keychain.WeakItems {
			add("keychain", x.Item.Service+"/"+x.Item.Server+"/"+x.Item.Account, "Keychain", x.Severity, x.Reason, "Review the flagged Keychain metadata")
		}
	}
	if r.Hidden != nil {
		for _, x := range r.Hidden.SuspiciousProcesses {
			add("hidden", fmt.Sprintf("%d:%s", x.PID, x.Path), "Processes", x.Severity, x.SuspicionReason, "Review the process and its executable")
		}
		for _, x := range r.Hidden.SuspiciousLaunchAgents {
			add("hidden", x.PlistPath, "Launch Agents", x.Severity, x.SuspicionReason, "Review the launch agent before removing it")
		}
		for _, x := range r.Hidden.HiddenFiles {
			add("hidden", x.Path, "Hidden Files", "medium", x.Reason, "Review the hidden file")
		}
	}
	if r.Apps != nil {
		for _, x := range r.Apps.Issues {
			add("apps", x.AppPath, x.Category, x.Severity, x.Description, "Review the application and its provenance")
		}
	}
	if r.Breaches != nil {
		for _, x := range r.Breaches.Compromised {
			add("breach", x.Account, "Breach", "critical", strings.Join(x.BreachNames, ", "), "Change credentials for the affected account")
		}
	}
	if r.Secrets != nil {
		for _, x := range r.Secrets.SecretsFound {
			add("secrets", fmt.Sprintf("%s:%d", x.File, x.Line), "Secrets", x.Severity, x.Type, "Review and rotate the exposed secret")
		}
		for _, x := range r.Secrets.PasswordFiles {
			add("secrets", x.Path, "Password Files", x.Severity, x.Type, "Review file permissions and credential storage")
		}
	}
	if r.Wallets != nil {
		for _, x := range r.Wallets.SeedPhrases {
			add("wallets", fmt.Sprintf("%s:%d", x.File, x.Line), "Seed Phrases", x.Risk, "Potential plaintext seed phrase", "Review the finding and secure sensitive wallet material")
		}
	}
	if r.CAs != nil {
		for _, x := range r.CAs.SuspiciousCAs {
			add("cas", x.Certificate.Fingerprint, "Certificate Authorities", x.Severity, x.Reason, "Review the certificate authority and its trust settings")
		}
	}
	if r.Certs != nil {
		for _, x := range r.Certs.Suspicious {
			add("certs", x.Certificate.SerialNumber, "Certificates", x.Severity, x.Reason, "Review certificate issuance for the requested domain")
		}
	}
	// A scanner can report the same evidence more than once; count its stable ID once.
	unique := map[string]Finding{}
	for _, f := range r.Findings {
		unique[f.ID] = f
	}
	r.Findings = r.Findings[:0]
	for _, f := range unique {
		r.Findings = append(r.Findings, f)
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	r.Summary = &ScanSummary{Recommendations: []string{}}
	recommendations := map[string]bool{}
	for _, f := range r.Findings {
		r.Summary.TotalFindings++
		if f.Severity == "critical" {
			r.Summary.CriticalIssues++
		} else {
			r.Summary.Warnings++
		}
		if !recommendations[f.Remediation] {
			r.Summary.Recommendations = append(r.Summary.Recommendations, f.Remediation)
			recommendations[f.Remediation] = true
		}
	}
	complete, failed := 0, 0
	for i := range r.Components {
		c := &r.Components[i]
		c.Findings = []Finding{}
		for _, f := range r.Findings {
			if f.ScannerID == c.ScannerID {
				c.Findings = append(c.Findings, f)
			}
		}
		switch c.Status {
		case "completed":
			complete++
		case "failed", "partial":
			failed++
		}
	}
	r.Status = "completed"
	if failed > 0 {
		r.Status = "partial"
		if complete == 0 {
			r.Status = "failed"
		}
	}
	r.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
}

type IncompleteScanError struct{ Status string }

func (e *IncompleteScanError) Error() string {
	return "Scan " + e.Status + "; inspect component errors and coverage"
}
