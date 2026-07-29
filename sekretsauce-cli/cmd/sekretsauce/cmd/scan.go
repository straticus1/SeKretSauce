package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/afterdarktech/sekretsauce/pkg/breach"
	"github.com/afterdarktech/sekretsauce/pkg/ca"
	"github.com/afterdarktech/sekretsauce/pkg/certs"
	"github.com/afterdarktech/sekretsauce/pkg/hunter"
	"github.com/afterdarktech/sekretsauce/pkg/inspector"
	"github.com/afterdarktech/sekretsauce/pkg/keychain"
	"github.com/afterdarktech/sekretsauce/pkg/secrets"
	"github.com/afterdarktech/sekretsauce/pkg/wallet"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a comprehensive security scan",
	Long: `Run a full security scan of the system including:
  • Keychain analysis
  • Certificate transparency checks
  • Hidden process detection
  • Launch agent inspection
  • Breach detection for found credentials`,
	RunE: runFullScan,
}

var scanKeychainCmd = &cobra.Command{
	Use:   "keychain",
	Short: "Scan macOS Keychain for stored credentials",
	RunE:  runKeychainScan,
}

var scanCertsCmd = &cobra.Command{
	Use:     "certs",
	Aliases: []string{"certificates", "ct"},
	Short:   "Check certificate transparency logs",
	RunE:    runCertsScan,
}

var scanHiddenCmd = &cobra.Command{
	Use:     "hidden",
	Aliases: []string{"hunt"},
	Short:   "Hunt for hidden processes and launch agents",
	RunE:    runHiddenScan,
}

var scanAppsCmd = &cobra.Command{
	Use:     "apps",
	Aliases: []string{"inspect"},
	Short:   "Inspect installed applications for security issues",
	RunE:    runAppsScan,
}

var scanBreachCmd = &cobra.Command{
	Use:     "breach",
	Aliases: []string{"pwned", "hibp"},
	Short:   "Check credentials against known breaches",
	RunE:    runBreachScan,
}

var scanSecretsCmd = &cobra.Command{
	Use:     "secrets",
	Aliases: []string{"keys", "credentials"},
	Short:   "Scan files for exposed secrets, API keys, and credentials",
	RunE:    runSecretsScan,
}

var scanWalletsCmd = &cobra.Command{
	Use:     "wallets",
	Aliases: []string{"crypto", "wallet"},
	Short:   "Find cryptocurrency wallets and seed phrases",
	RunE:    runWalletsScan,
}

var scanCAsCmd = &cobra.Command{
	Use:     "cas",
	Aliases: []string{"certificates-authorities", "root-certs"},
	Short:   "Audit installed Certificate Authorities",
	RunE:    runCAsScan,
}

var (
	scanDomain     string
	scanEmail      string
	scanDeep       bool
	checkBreaches  bool
	scanAllApps    bool
	includeSysApps bool
	scanPaths      []string
	includeGit     bool
	scanWalletHome bool
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanKeychainCmd)
	scanCmd.AddCommand(scanCertsCmd)
	scanCmd.AddCommand(scanHiddenCmd)
	scanCmd.AddCommand(scanAppsCmd)
	scanCmd.AddCommand(scanBreachCmd)
	scanCmd.AddCommand(scanSecretsCmd)
	scanCmd.AddCommand(scanWalletsCmd)
	scanCmd.AddCommand(scanCAsCmd)

	// Full scan flags
	scanCmd.Flags().BoolVar(&scanDeep, "deep", false, "Perform deep scan (slower, more thorough)")
	scanCmd.Flags().BoolVar(&checkBreaches, "check-breaches", false, "Opt in to sending account identifiers to HIBP")

	// Cert scan flags
	scanCertsCmd.Flags().StringVarP(&scanDomain, "domain", "d", "", "Domain to check for certificate transparency")

	// Breach scan flags
	scanBreachCmd.Flags().StringVarP(&scanEmail, "email", "e", "", "Email address to check")
	scanBreachCmd.Flags().StringVarP(&scanDomain, "domain", "d", "", "Domain to check for breached accounts")

	// App scan flags
	scanAppsCmd.Flags().BoolVar(&scanAllApps, "all", false, "Scan all applications (not just user-installed)")
	scanAppsCmd.Flags().BoolVar(&includeSysApps, "system", false, "Include system applications")

	// Secrets scan flags
	scanSecretsCmd.Flags().StringSliceVarP(&scanPaths, "path", "p", []string{"."}, "Paths to scan for secrets")
	scanSecretsCmd.Flags().BoolVar(&includeGit, "include-git", false, "Include .git directories in scan")
	scanSecretsCmd.Flags().BoolVar(&scanDeep, "deep", false, "Deep scan (more thorough, slower)")

	// Wallet scan flags
	scanWalletsCmd.Flags().BoolVar(&scanWalletHome, "home", true, "Scan user's home directory for wallets")
	scanWalletsCmd.Flags().StringSliceVarP(&scanPaths, "path", "p", []string{}, "Additional paths to scan")
	scanWalletsCmd.Flags().BoolVar(&scanDeep, "deep", false, "Deep scan for seed phrases in files")

	// CA scan flags
	scanCAsCmd.Flags().BoolVar(&includeSysApps, "system", true, "Include system CA certificates")
}

// ScanResults holds all scan results for JSON output
type ScanResults struct {
	Keychain *keychain.ScanResult  `json:"keychain,omitempty"`
	Certs    *certs.ScanResult     `json:"certificates,omitempty"`
	Hidden   *hunter.ScanResult    `json:"hidden_processes,omitempty"`
	Apps     *inspector.ScanResult `json:"applications,omitempty"`
	Breaches *breach.ScanResult    `json:"breaches,omitempty"`
	Secrets  *secrets.ScanResult   `json:"secrets,omitempty"`
	Wallets  *wallet.ScanResult    `json:"wallets,omitempty"`
	CAs      *ca.ScanResult        `json:"certificate_authorities,omitempty"`
	Summary  *ScanSummary          `json:"summary"`
}

type ScanSummary struct {
	TotalFindings   int      `json:"total_findings"`
	CriticalIssues  int      `json:"critical_issues"`
	Warnings        int      `json:"warnings"`
	Recommendations []string `json:"recommendations"`
}

func runFullScan(cmd *cobra.Command, args []string) error {
	printSection("SeKretSauce Full Security Scan")

	results := &ScanResults{
		Summary: &ScanSummary{
			Recommendations: []string{},
		},
	}

	// Keychain scan
	printInfo("Scanning Keychain...")
	if kcResult, err := keychain.Scan(keychain.ScanOptions{Deep: scanDeep}); err != nil {
		printWarning(fmt.Sprintf("Keychain scan: %v", err))
	} else {
		results.Keychain = kcResult
		printSuccess(fmt.Sprintf("Found %d keychain items", kcResult.TotalItems))
	}

	// Hidden process scan
	printInfo("Hunting hidden processes...")
	if hiddenResult, err := hunter.Scan(hunter.ScanOptions{Deep: scanDeep}); err != nil {
		printWarning(fmt.Sprintf("Hidden scan: %v", err))
	} else {
		results.Hidden = hiddenResult
		if len(hiddenResult.SuspiciousProcesses) > 0 {
			printWarning(fmt.Sprintf("Found %d suspicious processes", len(hiddenResult.SuspiciousProcesses)))
			results.Summary.Warnings += len(hiddenResult.SuspiciousProcesses)
		} else {
			printSuccess("No suspicious processes found")
		}
	}

	// App inspection
	printInfo("Inspecting applications...")
	if appResult, err := inspector.Scan(inspector.ScanOptions{
		IncludeSystem: includeSysApps,
		ScanAll:       scanAllApps,
	}); err != nil {
		printWarning(fmt.Sprintf("App scan: %v", err))
	} else {
		results.Apps = appResult
		printSuccess(fmt.Sprintf("Scanned %d applications", appResult.TotalApps))
		if len(appResult.Issues) > 0 {
			results.Summary.Warnings += len(appResult.Issues)
		}
	}

	// Breach check (if we found credentials and flag is set)
	if checkBreaches && results.Keychain != nil {
		printInfo("Checking for breached credentials...")
		if breachResult, err := breach.CheckCredentials(results.Keychain.Items); err != nil {
			printWarning(fmt.Sprintf("Breach check: %v", err))
		} else {
			results.Breaches = breachResult
			if len(breachResult.Compromised) > 0 {
				printError(fmt.Sprintf("ALERT: %d compromised accounts found!", len(breachResult.Compromised)))
				results.Summary.CriticalIssues += len(breachResult.Compromised)
			} else {
				printSuccess("No breached credentials detected")
			}
		}
	}

	// Secrets scan
	printInfo("Scanning for exposed secrets...")
	if secretsResult, err := secrets.ScanHomeDirectory(); err != nil {
		printWarning(fmt.Sprintf("Secrets scan: %v", err))
	} else {
		results.Secrets = secretsResult
		if secretsResult.Summary.CriticalFindings > 0 {
			printError(fmt.Sprintf("Found %d exposed secrets!", secretsResult.Summary.CriticalFindings))
			results.Summary.CriticalIssues += secretsResult.Summary.CriticalFindings
		} else if len(secretsResult.SecretsFound) > 0 {
			printWarning(fmt.Sprintf("Found %d potential secrets", len(secretsResult.SecretsFound)))
			results.Summary.Warnings += len(secretsResult.SecretsFound)
		} else {
			printSuccess("No exposed secrets found")
		}
	}

	// Wallet scan
	printInfo("Scanning for cryptocurrency wallets...")
	if walletResult, err := wallet.Scan(wallet.ScanOptions{
		ScanHome:   true,
		ScanCommon: true,
	}); err != nil {
		printWarning(fmt.Sprintf("Wallet scan: %v", err))
	} else {
		results.Wallets = walletResult
		if len(walletResult.SeedPhrases) > 0 {
			printError(fmt.Sprintf("CRITICAL: Found %d seed phrases in plaintext!", len(walletResult.SeedPhrases)))
			results.Summary.CriticalIssues += len(walletResult.SeedPhrases)
		}
		if len(walletResult.WalletsFound) > 0 {
			printSuccess(fmt.Sprintf("Found %d cryptocurrency wallets", len(walletResult.WalletsFound)))
		} else {
			printSuccess("No cryptocurrency wallets found")
		}
	}

	// CA certificate scan
	printInfo("Auditing CA certificates...")
	if caResult, err := ca.Scan(ca.ScanOptions{
		IncludeSystem: true,
		IncludeUser:   true,
	}); err != nil {
		printWarning(fmt.Sprintf("CA scan: %v", err))
	} else {
		results.CAs = caResult
		if len(caResult.SuspiciousCAs) > 0 {
			for _, sus := range caResult.SuspiciousCAs {
				if sus.Severity == "critical" || sus.Severity == "high" {
					results.Summary.CriticalIssues++
				} else {
					results.Summary.Warnings++
				}
			}
			printWarning(fmt.Sprintf("Found %d suspicious CA certificates", len(caResult.SuspiciousCAs)))
		} else {
			printSuccess(fmt.Sprintf("Scanned %d CA certificates", caResult.Summary.TotalCAs))
		}
	}

	// Calculate summary
	results.Summary.TotalFindings = results.Summary.CriticalIssues + results.Summary.Warnings

	// Generate recommendations
	if results.Summary.CriticalIssues > 0 {
		results.Summary.Recommendations = append(results.Summary.Recommendations,
			"Change passwords for all compromised accounts immediately")
	}
	if results.Hidden != nil && len(results.Hidden.SuspiciousLaunchAgents) > 0 {
		results.Summary.Recommendations = append(results.Summary.Recommendations,
			"Review and remove suspicious launch agents")
	}
	if results.Secrets != nil && results.Secrets.Summary.CriticalFindings > 0 {
		results.Summary.Recommendations = append(results.Summary.Recommendations,
			"Rotate all exposed API keys and secrets immediately")
	}
	if results.Wallets != nil && len(results.Wallets.SeedPhrases) > 0 {
		results.Summary.Recommendations = append(results.Summary.Recommendations,
			"URGENT: Move seed phrases to secure storage and transfer funds to new wallets")
	}
	if results.CAs != nil && results.CAs.Summary.SuspiciousCAs > 0 {
		results.Summary.Recommendations = append(results.Summary.Recommendations,
			"Review and remove suspicious CA certificates")
	}

	// Output
	if outputJSON {
		return outputAsJSON(results)
	}

	printSection("Scan Summary")
	fmt.Printf("Total findings: %d\n", results.Summary.TotalFindings)
	fmt.Printf("Critical issues: %d\n", results.Summary.CriticalIssues)
	fmt.Printf("Warnings: %d\n", results.Summary.Warnings)

	if len(results.Summary.Recommendations) > 0 {
		fmt.Println("\nRecommendations:")
		for _, rec := range results.Summary.Recommendations {
			fmt.Printf("  • %s\n", rec)
		}
	}

	return nil
}

func runKeychainScan(cmd *cobra.Command, args []string) error {
	printSection("Keychain Scan")

	result, err := keychain.Scan(keychain.ScanOptions{Deep: scanDeep})
	if err != nil {
		return fmt.Errorf("keychain scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	fmt.Printf("Total items: %d\n", result.TotalItems)
	fmt.Printf("Password items: %d\n", result.PasswordItems)
	fmt.Printf("Certificate items: %d\n", result.CertificateItems)
	fmt.Printf("Key items: %d\n", result.KeyItems)

	if len(result.WeakItems) > 0 {
		printWarning(fmt.Sprintf("Found %d items with potential issues", len(result.WeakItems)))
	}

	return nil
}

func runCertsScan(cmd *cobra.Command, args []string) error {
	printSection("Certificate Transparency Scan")

	if scanDomain == "" {
		return fmt.Errorf("--domain flag is required")
	}

	result, err := certs.CheckTransparency(scanDomain)
	if err != nil {
		return fmt.Errorf("certificate scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	fmt.Printf("Domain: %s\n", scanDomain)
	fmt.Printf("Certificates found: %d\n", len(result.Certificates))

	for _, cert := range result.Certificates {
		fmt.Printf("\n  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Not Before: %s\n", cert.NotBefore)
		fmt.Printf("  Not After: %s\n", cert.NotAfter)
		fmt.Printf("  SANs: %v\n", cert.SubjectAltNames)
	}

	if len(result.Suspicious) > 0 {
		printWarning(fmt.Sprintf("Found %d suspicious certificates!", len(result.Suspicious)))
		for _, s := range result.Suspicious {
			fmt.Printf("  ⚠ %s: %s\n", s.Reason, s.Certificate.Issuer)
		}
	}

	return nil
}

func runHiddenScan(cmd *cobra.Command, args []string) error {
	printSection("Hidden Process & Launch Agent Hunt")

	result, err := hunter.Scan(hunter.ScanOptions{Deep: scanDeep})
	if err != nil {
		return fmt.Errorf("hidden scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	fmt.Printf("Processes scanned: %d\n", result.ProcessesScanned)
	fmt.Printf("Launch agents checked: %d\n", result.LaunchAgentsChecked)

	if len(result.SuspiciousProcesses) > 0 {
		printSection("Suspicious Processes")
		for _, proc := range result.SuspiciousProcesses {
			printWarning(fmt.Sprintf("PID %d: %s", proc.PID, proc.Name))
			fmt.Printf("    Path: %s\n", proc.Path)
			fmt.Printf("    Reason: %s\n", proc.SuspicionReason)
		}
	}

	if len(result.SuspiciousLaunchAgents) > 0 {
		printSection("Suspicious Launch Agents")
		for _, agent := range result.SuspiciousLaunchAgents {
			printWarning(agent.Label)
			fmt.Printf("    Path: %s\n", agent.PlistPath)
			fmt.Printf("    Program: %s\n", agent.Program)
			fmt.Printf("    Reason: %s\n", agent.SuspicionReason)
		}
	}

	if len(result.SuspiciousProcesses) == 0 && len(result.SuspiciousLaunchAgents) == 0 {
		printSuccess("No suspicious items found")
	}

	return nil
}

func runAppsScan(cmd *cobra.Command, args []string) error {
	printSection("Application Security Inspection")

	result, err := inspector.Scan(inspector.ScanOptions{
		IncludeSystem: includeSysApps,
		ScanAll:       scanAllApps,
	})
	if err != nil {
		return fmt.Errorf("app scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	fmt.Printf("Applications scanned: %d\n", result.TotalApps)

	if len(result.Issues) > 0 {
		printSection("Security Issues Found")
		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				printError(fmt.Sprintf("%s: %s", issue.AppName, issue.Description))
			case "warning":
				printWarning(fmt.Sprintf("%s: %s", issue.AppName, issue.Description))
			default:
				printInfo(fmt.Sprintf("%s: %s", issue.AppName, issue.Description))
			}
		}
	} else {
		printSuccess("No security issues found in applications")
	}

	return nil
}

func runBreachScan(cmd *cobra.Command, args []string) error {
	printSection("Breach Detection")

	if scanEmail == "" && scanDomain == "" {
		return fmt.Errorf("either --email or --domain flag is required")
	}

	var result *breach.ScanResult
	var err error

	if scanEmail != "" {
		result, err = breach.CheckEmail(scanEmail)
	} else {
		result, err = breach.CheckDomain(scanDomain)
	}

	if err != nil {
		return fmt.Errorf("breach check failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	if len(result.Compromised) > 0 {
		printError(fmt.Sprintf("Found %d breached accounts!", len(result.Compromised)))
		for _, comp := range result.Compromised {
			fmt.Printf("\n  Account: %s\n", comp.Account)
			fmt.Printf("  Breaches: %v\n", comp.BreachNames)
			fmt.Printf("  Data exposed: %v\n", comp.DataTypes)
		}
	} else {
		printSuccess("No breaches found")
	}

	return nil
}

func outputAsJSON(v interface{}) error {
	writer := os.Stdout
	if outputFile != "" {
		info, err := os.Lstat(outputFile)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write JSON through symbolic link: %s", outputFile)
		}
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("inspect output file: %w", err)
		}
		file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open output file: %w", err)
		}
		defer file.Close()
		if err := file.Chmod(0o600); err != nil {
			return fmt.Errorf("secure output file permissions: %w", err)
		}
		writer = file
	}
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runSecretsScan(cmd *cobra.Command, args []string) error {
	printSection("Secrets Scanner")

	printInfo("Scanning for exposed secrets, API keys, and credentials...")

	result, err := secrets.Scan(secrets.ScanOptions{
		Paths:      scanPaths,
		IncludeGit: includeGit,
		Concurrent: 4,
	})
	if err != nil {
		return fmt.Errorf("secrets scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	fmt.Printf("Files scanned: %d\n", result.TotalFilesScanned)

	// Show summary
	if result.Summary.CriticalFindings > 0 {
		printError(fmt.Sprintf("CRITICAL: Found %d critical security issues!", result.Summary.CriticalFindings))
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  API Keys: %d\n", result.Summary.APIKeys)
	fmt.Printf("  Private Keys: %d\n", result.Summary.PrivateKeys)
	fmt.Printf("  Passwords: %d\n", result.Summary.Passwords)
	fmt.Printf("  Tokens: %d\n", result.Summary.Tokens)
	fmt.Printf("  Connection Strings: %d\n", result.Summary.ConnectionStrings)

	// Show secrets found
	if len(result.SecretsFound) > 0 {
		printSection("Secrets Found")
		for _, secret := range result.SecretsFound {
			severity := ""
			switch secret.Severity {
			case "critical":
				severity = "\033[31m[CRITICAL]\033[0m"
			case "high":
				severity = "\033[33m[HIGH]\033[0m"
			case "medium":
				severity = "\033[33m[MEDIUM]\033[0m"
			default:
				severity = "[LOW]"
			}
			fmt.Printf("%s %s\n", severity, secret.Type)
			fmt.Printf("    File: %s:%d\n", secret.File, secret.Line)
			fmt.Printf("    Match: %s\n", secret.Match)
		}
	}

	// Show password files
	if len(result.PasswordFiles) > 0 {
		printSection("Password/Config Files Found")
		for _, pf := range result.PasswordFiles {
			printWarning(fmt.Sprintf("%s (%s)", pf.Path, pf.Type))
			fmt.Printf("    Permissions: %s\n", pf.Permissions)
		}
	}

	// Show env files
	if len(result.EnvFiles) > 0 {
		printSection("Environment Files")
		for _, ef := range result.EnvFiles {
			if ef.HasSecrets {
				printWarning(fmt.Sprintf("%s (contains sensitive variables)", ef.Path))
			} else {
				printInfo(ef.Path)
			}
			fmt.Printf("    Variables: %d\n", len(ef.Variables))
		}
	}

	if len(result.SecretsFound) == 0 && len(result.PasswordFiles) == 0 {
		printSuccess("No exposed secrets found")
	}

	return nil
}

func runWalletsScan(cmd *cobra.Command, args []string) error {
	printSection("Cryptocurrency Wallet Scanner")

	printInfo("Scanning for cryptocurrency wallets and seed phrases...")

	result, err := wallet.Scan(wallet.ScanOptions{
		Paths:      scanPaths,
		ScanHome:   scanWalletHome,
		ScanCommon: true,
		Deep:       scanDeep,
	})
	if err != nil {
		return fmt.Errorf("wallet scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	// Summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total Wallets Found: %d\n", result.Summary.TotalWallets)
	fmt.Printf("  Bitcoin Wallets: %d\n", result.Summary.BitcoinWallets)
	fmt.Printf("  Ethereum Wallets: %d\n", result.Summary.EthereumWallets)
	fmt.Printf("  Other Wallets: %d\n", result.Summary.OtherWallets)
	fmt.Printf("  Seed Phrases Found: %d\n", result.Summary.SeedPhrasesFound)

	if result.Summary.CriticalFindings > 0 {
		printError(fmt.Sprintf("CRITICAL: %d critical findings!", result.Summary.CriticalFindings))
	}

	// Show wallets found
	if len(result.WalletsFound) > 0 {
		printSection("Wallets Found")
		for _, w := range result.WalletsFound {
			encrypted := ""
			if w.Encrypted {
				encrypted = " (encrypted)"
			} else {
				encrypted = " \033[31m(UNENCRYPTED!)\033[0m"
			}
			fmt.Printf("  %s - %s%s\n", w.Application, w.Type, encrypted)
			fmt.Printf("    Path: %s\n", w.Path)
			fmt.Printf("    Modified: %s\n", w.Modified)
		}
	}

	// Show seed phrases (critical!)
	if len(result.SeedPhrases) > 0 {
		printSection("SEED PHRASES FOUND - CRITICAL!")
		printError("Seed phrases found in plaintext files - this is extremely dangerous!")
		for _, sp := range result.SeedPhrases {
			printError(fmt.Sprintf("File: %s:%d", sp.File, sp.Line))
			fmt.Printf("    Words: %s\n", sp.Redacted)
		}
	}

	// Show wallet files
	if len(result.WalletFiles) > 0 {
		printSection("Potential Wallet Files")
		for _, wf := range result.WalletFiles {
			printWarning(fmt.Sprintf("%s (%s)", wf.Path, wf.Type))
		}
	}

	// Show addresses found
	if len(result.AddressesInFiles) > 0 && len(result.AddressesInFiles) <= 20 {
		printSection("Crypto Addresses in Files")
		for _, addr := range result.AddressesInFiles {
			fmt.Printf("  %s: %s\n", addr.Type, addr.Address)
			fmt.Printf("    File: %s:%d\n", addr.File, addr.Line)
		}
	} else if len(result.AddressesInFiles) > 20 {
		printInfo(fmt.Sprintf("Found %d crypto addresses in files (showing first 20)", len(result.AddressesInFiles)))
		for _, addr := range result.AddressesInFiles[:20] {
			fmt.Printf("  %s: %s\n", addr.Type, addr.Address)
		}
	}

	if len(result.WalletsFound) == 0 && len(result.SeedPhrases) == 0 {
		printSuccess("No cryptocurrency wallets or seed phrases found")
	}

	return nil
}

func runCAsScan(cmd *cobra.Command, args []string) error {
	printSection("Certificate Authority Audit")

	printInfo("Scanning installed CA certificates...")

	result, err := ca.Scan(ca.ScanOptions{
		IncludeSystem:  includeSysApps,
		IncludeUser:    true,
		IncludeExpired: true,
	})
	if err != nil {
		return fmt.Errorf("CA scan failed: %w", err)
	}

	if outputJSON {
		return outputAsJSON(result)
	}

	// Summary
	fmt.Printf("\nPlatform: %s\n", result.Platform)
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total CAs: %d\n", result.Summary.TotalCAs)
	fmt.Printf("  System CAs: %d\n", result.Summary.SystemCAs)
	fmt.Printf("  User-Installed CAs: %d\n", result.Summary.UserInstalledCAs)
	fmt.Printf("  Self-Signed CAs: %d\n", result.Summary.SelfSignedCAs)
	fmt.Printf("  Weak Algorithms: %d\n", result.Summary.WeakAlgorithms)
	fmt.Printf("  Expired CAs: %d\n", result.Summary.ExpiredCAs)

	// Show suspicious CAs
	if len(result.SuspiciousCAs) > 0 {
		printSection("Suspicious CA Certificates")
		for _, sus := range result.SuspiciousCAs {
			switch sus.Severity {
			case "critical":
				printError(fmt.Sprintf("[CRITICAL] %s", sus.Reason))
			case "high":
				printWarning(fmt.Sprintf("[HIGH] %s", sus.Reason))
			case "medium":
				printWarning(fmt.Sprintf("[MEDIUM] %s", sus.Reason))
			default:
				printInfo(fmt.Sprintf("[LOW] %s", sus.Reason))
			}
			fmt.Printf("    Subject: %s\n", sus.Certificate.Subject)
			fmt.Printf("    Issuer: %s\n", sus.Certificate.Issuer)
			fmt.Printf("    Source: %s\n", sus.Certificate.Source)
			if sus.Details != "" {
				fmt.Printf("    Details: %s\n", sus.Details)
			}
		}
	}

	// Show user-installed CAs
	if len(result.UserCAs) > 0 {
		printSection("User-Installed CA Certificates")
		for _, ca := range result.UserCAs {
			fmt.Printf("  %s\n", ca.Subject)
			fmt.Printf("    Valid: %s to %s\n",
				ca.NotBefore.Format("2006-01-02"),
				ca.NotAfter.Format("2006-01-02"))
			fmt.Printf("    Algorithm: %s\n", ca.SignatureAlg)
		}
	}

	// Show expired CAs
	if len(result.ExpiredCAs) > 0 {
		printSection("Expired CA Certificates")
		for _, ca := range result.ExpiredCAs {
			printWarning(ca.Subject)
			fmt.Printf("    Expired: %s\n", ca.NotAfter.Format("2006-01-02"))
		}
	}

	if len(result.SuspiciousCAs) == 0 {
		printSuccess("No suspicious CA certificates found")
	}

	return nil
}
