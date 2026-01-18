package brew

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Formula represents a Homebrew formula
type Formula struct {
	Name             string   `json:"name"`
	FullName         string   `json:"full_name"`
	Tap              string   `json:"tap"`
	Version          string   `json:"versions,omitempty"`
	Homepage         string   `json:"homepage"`
	URL              string   `json:"url"`
	Sha256           string   `json:"sha256,omitempty"`
	Deprecated       bool     `json:"deprecated"`
	Disabled         bool     `json:"disabled"`
	DeprecationDate  string   `json:"deprecation_date,omitempty"`
	DeprecationReason string  `json:"deprecation_reason,omitempty"`
	InstalledVersion string   `json:"-"`
}

// Tap represents a Homebrew tap
type Tap struct {
	Name       string `json:"name"`
	Remote     string `json:"remote"`
	Path       string `json:"path"`
	Official   bool   `json:"official"`
	FormulaCount int  `json:"-"`
	CaskCount    int  `json:"-"`
}

// InstalledPackage represents an installed package
type InstalledPackage struct {
	Name             string   `json:"name"`
	FullName         string   `json:"full_name"`
	Tap              string   `json:"tap"`
	Version          string   `json:"installed_version"`
	Homepage         string   `json:"homepage"`
	URL              string   `json:"url"`
	Dependencies     []string `json:"dependencies"`
	BuildDependencies []string `json:"build_dependencies"`
}

// GetBrewPrefix returns the Homebrew prefix
func GetBrewPrefix() (string, error) {
	out, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get brew prefix: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// GetInstalledFormulae returns all installed formulae
func GetInstalledFormulae() ([]InstalledPackage, error) {
	out, err := exec.Command("brew", "info", "--json=v2", "--installed").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed formulae: %w", err)
	}

	var result struct {
		Formulae []struct {
			Name      string `json:"name"`
			FullName  string `json:"full_name"`
			Tap       string `json:"tap"`
			Homepage  string `json:"homepage"`
			URLs      struct {
				Stable struct {
					URL string `json:"url"`
				} `json:"stable"`
			} `json:"urls"`
			Installed []struct {
				Version string `json:"version"`
			} `json:"installed"`
			Dependencies      []string `json:"dependencies"`
			BuildDependencies []string `json:"build_dependencies"`
		} `json:"formulae"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse brew info: %w", err)
	}

	var packages []InstalledPackage
	for _, f := range result.Formulae {
		version := ""
		if len(f.Installed) > 0 {
			version = f.Installed[0].Version
		}

		packages = append(packages, InstalledPackage{
			Name:              f.Name,
			FullName:          f.FullName,
			Tap:               f.Tap,
			Version:           version,
			Homepage:          f.Homepage,
			URL:               f.URLs.Stable.URL,
			Dependencies:      f.Dependencies,
			BuildDependencies: f.BuildDependencies,
		})
	}

	return packages, nil
}

// GetInstalledTaps returns all installed taps
func GetInstalledTaps() ([]Tap, error) {
	out, err := exec.Command("brew", "tap").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get taps: %w", err)
	}

	prefix, err := GetBrewPrefix()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var taps []Tap

	for _, name := range lines {
		if name == "" {
			continue
		}

		tap := Tap{
			Name:     name,
			Official: strings.HasPrefix(name, "homebrew/"),
		}

		// Get tap path
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			tap.Path = filepath.Join(prefix, "Homebrew", "Library", "Taps", parts[0], "homebrew-"+parts[1])
		}

		// Try to get remote URL
		if tap.Path != "" {
			gitDir := filepath.Join(tap.Path, ".git")
			if _, err := os.Stat(gitDir); err == nil {
				remoteOut, err := exec.Command("git", "-C", tap.Path, "remote", "get-url", "origin").Output()
				if err == nil {
					tap.Remote = strings.TrimSpace(string(remoteOut))
				}
			}
		}

		taps = append(taps, tap)
	}

	return taps, nil
}

// GetFormulaInfo gets detailed info for a specific formula
func GetFormulaInfo(name string) (*Formula, error) {
	out, err := exec.Command("brew", "info", "--json=v2", name).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get formula info: %w", err)
	}

	var result struct {
		Formulae []struct {
			Name              string `json:"name"`
			FullName          string `json:"full_name"`
			Tap               string `json:"tap"`
			Homepage          string `json:"homepage"`
			Deprecated        bool   `json:"deprecated"`
			Disabled          bool   `json:"disabled"`
			DeprecationDate   string `json:"deprecation_date"`
			DeprecationReason string `json:"deprecation_reason"`
			URLs              struct {
				Stable struct {
					URL    string `json:"url"`
					Sha256 string `json:"checksum"`
				} `json:"stable"`
			} `json:"urls"`
			Versions struct {
				Stable string `json:"stable"`
			} `json:"versions"`
		} `json:"formulae"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse formula info: %w", err)
	}

	if len(result.Formulae) == 0 {
		return nil, fmt.Errorf("formula not found: %s", name)
	}

	f := result.Formulae[0]
	return &Formula{
		Name:              f.Name,
		FullName:          f.FullName,
		Tap:               f.Tap,
		Version:           f.Versions.Stable,
		Homepage:          f.Homepage,
		URL:               f.URLs.Stable.URL,
		Sha256:            f.URLs.Stable.Sha256,
		Deprecated:        f.Deprecated,
		Disabled:          f.Disabled,
		DeprecationDate:   f.DeprecationDate,
		DeprecationReason: f.DeprecationReason,
	}, nil
}

// IsHTTPURL checks if a URL uses HTTP instead of HTTPS
func IsHTTPURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "http://")
}

// ExtractGitHubRepo extracts owner/repo from a GitHub URL
func ExtractGitHubRepo(url string) (owner, repo string, ok bool) {
	// Handle various GitHub URL formats
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	patterns := []string{
		"github.com/",
		"raw.githubusercontent.com/",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(url, pattern); idx != -1 {
			parts := strings.Split(url[idx+len(pattern):], "/")
			if len(parts) >= 2 {
				return parts[0], parts[1], true
			}
		}
	}

	return "", "", false
}
