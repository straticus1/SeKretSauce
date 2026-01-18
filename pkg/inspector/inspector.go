package inspector

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ScanOptions configures the app inspection
type ScanOptions struct {
	IncludeSystem bool
	ScanAll       bool
	AppPaths      []string // Specific apps to scan
}

// ScanResult contains app inspection results
type ScanResult struct {
	TotalApps       int           `json:"total_apps"`
	AppsScanned     []AppInfo     `json:"apps_scanned,omitempty"`
	Issues          []SecurityIssue `json:"issues,omitempty"`
}

// AppInfo represents information about an application
type AppInfo struct {
	Name            string            `json:"name"`
	Path            string            `json:"path"`
	BundleID        string            `json:"bundle_id"`
	Version         string            `json:"version"`
	Signed          bool              `json:"signed"`
	SigningIdentity string            `json:"signing_identity,omitempty"`
	Notarized       bool              `json:"notarized"`
	Entitlements    []string          `json:"entitlements,omitempty"`
	Frameworks      []string          `json:"frameworks,omitempty"`
	SuspiciousFiles []string          `json:"suspicious_files,omitempty"`
}

// SecurityIssue represents a security finding in an app
type SecurityIssue struct {
	AppName     string `json:"app_name"`
	AppPath     string `json:"app_path"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // critical, high, medium, low
	Details     string `json:"details,omitempty"`
}

// Scan performs security inspection of installed applications
func Scan(opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		AppsScanned: []AppInfo{},
		Issues:      []SecurityIssue{},
	}

	// Get list of apps to scan
	appPaths := opts.AppPaths
	if len(appPaths) == 0 {
		appPaths = getApplicationPaths(opts.IncludeSystem, opts.ScanAll)
	}

	for _, appPath := range appPaths {
		info, issues := inspectApp(appPath)
		if info != nil {
			result.AppsScanned = append(result.AppsScanned, *info)
			result.Issues = append(result.Issues, issues...)
		}
	}

	result.TotalApps = len(result.AppsScanned)

	return result, nil
}

// getApplicationPaths returns paths to applications to scan
func getApplicationPaths(includeSystem bool, scanAll bool) []string {
	var paths []string

	// User applications
	homeDir, _ := os.UserHomeDir()
	userApps := filepath.Join(homeDir, "Applications")
	paths = append(paths, getAppsInDir(userApps)...)

	// System applications
	paths = append(paths, getAppsInDir("/Applications")...)

	if includeSystem {
		paths = append(paths, getAppsInDir("/System/Applications")...)
	}

	// Limit unless scanning all
	if !scanAll && len(paths) > 50 {
		paths = paths[:50]
	}

	return paths
}

// getAppsInDir returns all .app bundles in a directory
func getAppsInDir(dir string) []string {
	var apps []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return apps
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".app") {
			apps = append(apps, filepath.Join(dir, entry.Name()))
		}
	}

	return apps
}

// inspectApp inspects a single application bundle
func inspectApp(appPath string) (*AppInfo, []SecurityIssue) {
	info := &AppInfo{
		Path: appPath,
		Name: strings.TrimSuffix(filepath.Base(appPath), ".app"),
	}

	var issues []SecurityIssue

	// Read Info.plist for basic info
	infoPlistPath := filepath.Join(appPath, "Contents", "Info.plist")
	if plistData, err := readPlistAsMap(infoPlistPath); err == nil {
		if bundleID, ok := plistData["CFBundleIdentifier"].(string); ok {
			info.BundleID = bundleID
		}
		if version, ok := plistData["CFBundleShortVersionString"].(string); ok {
			info.Version = version
		}
	}

	// Check code signature
	signInfo, signIssues := checkCodeSignature(appPath, info.Name)
	info.Signed = signInfo.Signed
	info.SigningIdentity = signInfo.Identity
	info.Notarized = signInfo.Notarized
	issues = append(issues, signIssues...)

	// Check entitlements
	entitlements, entIssues := checkEntitlements(appPath, info.Name)
	info.Entitlements = entitlements
	issues = append(issues, entIssues...)

	// Check for suspicious files in bundle
	suspicious, susIssues := checkSuspiciousFiles(appPath, info.Name)
	info.SuspiciousFiles = suspicious
	issues = append(issues, susIssues...)

	// Check frameworks
	info.Frameworks = getFrameworks(appPath)

	return info, issues
}

// SignatureInfo contains code signing information
type SignatureInfo struct {
	Signed    bool
	Identity  string
	Notarized bool
}

// checkCodeSignature verifies an app's code signature
func checkCodeSignature(appPath string, appName string) (SignatureInfo, []SecurityIssue) {
	info := SignatureInfo{}
	var issues []SecurityIssue

	// Check signature with codesign
	cmd := exec.Command("codesign", "-dv", "--verbose=4", appPath)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// No valid signature
		issues = append(issues, SecurityIssue{
			AppName:     appName,
			AppPath:     appPath,
			Category:    "Code Signing",
			Description: "Application is not signed",
			Severity:    "high",
			Details:     string(output),
		})
		return info, issues
	}

	info.Signed = true
	outputStr := string(output)

	// Extract signing identity
	if match := regexp.MustCompile(`Authority=(.+)`).FindStringSubmatch(outputStr); len(match) > 1 {
		info.Identity = match[1]
	}

	// Check for ad-hoc signature
	if strings.Contains(outputStr, "Signature=adhoc") {
		issues = append(issues, SecurityIssue{
			AppName:     appName,
			AppPath:     appPath,
			Category:    "Code Signing",
			Description: "Application has ad-hoc signature (not from Apple or identified developer)",
			Severity:    "medium",
		})
	}

	// Check notarization
	cmd = exec.Command("spctl", "-a", "-vv", appPath)
	output, err = cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "accepted") {
		info.Notarized = true
	} else {
		issues = append(issues, SecurityIssue{
			AppName:     appName,
			AppPath:     appPath,
			Category:    "Notarization",
			Description: "Application is not notarized by Apple",
			Severity:    "low",
		})
	}

	// Verify signature integrity
	cmd = exec.Command("codesign", "--verify", "--deep", "--strict", appPath)
	if err := cmd.Run(); err != nil {
		issues = append(issues, SecurityIssue{
			AppName:     appName,
			AppPath:     appPath,
			Category:    "Code Signing",
			Description: "Application signature verification failed (may have been modified)",
			Severity:    "critical",
		})
	}

	return info, issues
}

// checkEntitlements inspects app entitlements for dangerous capabilities
func checkEntitlements(appPath string, appName string) ([]string, []SecurityIssue) {
	var entitlements []string
	var issues []SecurityIssue

	// Extract entitlements
	cmd := exec.Command("codesign", "-d", "--entitlements", "-", appPath)
	output, err := cmd.Output()
	if err != nil {
		return entitlements, issues
	}

	content := string(output)

	// Dangerous entitlements to flag
	dangerousEntitlements := map[string]struct {
		description string
		severity    string
	}{
		"com.apple.security.cs.allow-dyld-environment-variables": {
			"App allows DYLD environment variables (potential code injection)",
			"high",
		},
		"com.apple.security.cs.disable-library-validation": {
			"App disables library validation (can load unsigned libraries)",
			"high",
		},
		"com.apple.security.cs.allow-unsigned-executable-memory": {
			"App allows unsigned executable memory (JIT compilation)",
			"medium",
		},
		"com.apple.security.get-task-allow": {
			"App allows debugging (get-task-allow)",
			"medium",
		},
		"com.apple.security.cs.debugger": {
			"App has debugger entitlement",
			"medium",
		},
		"com.apple.private.security.clear-library-validation": {
			"App uses private entitlement to clear library validation",
			"critical",
		},
		"com.apple.security.device.camera": {
			"App has camera access",
			"low",
		},
		"com.apple.security.device.microphone": {
			"App has microphone access",
			"low",
		},
		"com.apple.security.personal-information.location": {
			"App has location access",
			"low",
		},
		"com.apple.security.files.all": {
			"App has full disk access",
			"medium",
		},
		"com.apple.security.automation.apple-events": {
			"App can send Apple Events (automation)",
			"low",
		},
	}

	// Check for each dangerous entitlement
	for entitlement, info := range dangerousEntitlements {
		if strings.Contains(content, entitlement) {
			entitlements = append(entitlements, entitlement)

			// Only flag high/critical as issues
			if info.severity == "high" || info.severity == "critical" {
				issues = append(issues, SecurityIssue{
					AppName:     appName,
					AppPath:     appPath,
					Category:    "Entitlements",
					Description: info.description,
					Severity:    info.severity,
				})
			}
		}
	}

	return entitlements, issues
}

// checkSuspiciousFiles looks for suspicious files within app bundles
func checkSuspiciousFiles(appPath string, appName string) ([]string, []SecurityIssue) {
	var suspicious []string
	var issues []SecurityIssue

	// Walk the app bundle looking for suspicious files
	filepath.Walk(appPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		name := info.Name()
		relPath, _ := filepath.Rel(appPath, path)

		// Check for hidden files
		if strings.HasPrefix(name, ".") && name != ".DS_Store" {
			suspicious = append(suspicious, relPath)
			issues = append(issues, SecurityIssue{
				AppName:     appName,
				AppPath:     appPath,
				Category:    "Suspicious Files",
				Description: "Hidden file in app bundle",
				Severity:    "medium",
				Details:     relPath,
			})
		}

		// Check for scripts in unexpected locations
		scriptExts := []string{".sh", ".py", ".pl", ".rb", ".php"}
		for _, ext := range scriptExts {
			if strings.HasSuffix(strings.ToLower(name), ext) {
				// Scripts in Resources might be okay, elsewhere suspicious
				if !strings.Contains(relPath, "Resources") {
					suspicious = append(suspicious, relPath)
					issues = append(issues, SecurityIssue{
						AppName:     appName,
						AppPath:     appPath,
						Category:    "Suspicious Files",
						Description: "Script file in unexpected location",
						Severity:    "medium",
						Details:     relPath,
					})
				}
			}
		}

		// Check for shell commands/tools embedded in app
		suspiciousNames := []string{
			"nc", "ncat", "netcat", "curl", "wget",
			"ssh", "telnet", "nmap", "hydra", "burp",
		}
		for _, susName := range suspiciousNames {
			if name == susName || name == susName+".exe" {
				suspicious = append(suspicious, relPath)
				issues = append(issues, SecurityIssue{
					AppName:     appName,
					AppPath:     appPath,
					Category:    "Suspicious Files",
					Description: "Security/network tool embedded in app",
					Severity:    "high",
					Details:     relPath,
				})
			}
		}

		return nil
	})

	return suspicious, issues
}

// getFrameworks returns list of frameworks used by the app
func getFrameworks(appPath string) []string {
	var frameworks []string

	frameworksPath := filepath.Join(appPath, "Contents", "Frameworks")
	entries, err := os.ReadDir(frameworksPath)
	if err != nil {
		return frameworks
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".framework") || strings.HasSuffix(entry.Name(), ".dylib") {
			frameworks = append(frameworks, entry.Name())
		}
	}

	return frameworks
}

// readPlistAsMap reads a plist file and returns it as a map
func readPlistAsMap(path string) (map[string]interface{}, error) {
	// Use plutil to convert to JSON for easy parsing
	cmd := exec.Command("plutil", "-convert", "json", "-o", "-", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse JSON into map
	var result map[string]interface{}

	// Simple extraction for common fields
	content := string(output)

	result = make(map[string]interface{})

	// Extract CFBundleIdentifier
	if match := regexp.MustCompile(`"CFBundleIdentifier"\s*:\s*"([^"]+)"`).FindStringSubmatch(content); len(match) > 1 {
		result["CFBundleIdentifier"] = match[1]
	}

	// Extract CFBundleShortVersionString
	if match := regexp.MustCompile(`"CFBundleShortVersionString"\s*:\s*"([^"]+)"`).FindStringSubmatch(content); len(match) > 1 {
		result["CFBundleShortVersionString"] = match[1]
	}

	return result, nil
}

// InspectSingleApp inspects a single application and returns detailed info
func InspectSingleApp(appPath string) (*AppInfo, []SecurityIssue, error) {
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		return nil, nil, err
	}

	info, issues := inspectApp(appPath)
	return info, issues, nil
}
