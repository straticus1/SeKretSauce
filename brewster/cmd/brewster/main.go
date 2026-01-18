package main

import (
	"fmt"
	"os"

	"github.com/afterdarktech/brewster/internal/config"
	"github.com/afterdarktech/brewster/pkg/audit"
	"github.com/afterdarktech/brewster/pkg/monitor"
	"github.com/afterdarktech/brewster/pkg/report"
	"github.com/afterdarktech/brewster/pkg/vetting"
	"github.com/spf13/cobra"
)

var (
	version   = "0.1.0"
	outputFmt string
	verbose   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "brewster",
		Short: "Security scanner for the Homebrew ecosystem",
		Long: `Brewster - Find and flag security incidents in the Homebrew ecosystem.

Detect bad distributors, abandoned projects, supply chain risks, and more.`,
		Version: version,
	}

	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json, yaml")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Subcommands
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(vetCmd())
	rootCmd.AddCommand(monitorCmd())
	rootCmd.AddCommand(scanCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// auditCmd - scan local brew installation
func auditCmd() *cobra.Command {
	var checkCVE bool
	var checkAbandoned bool
	var checkHTTP bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit your local Homebrew installation",
		Long:  `Scan installed packages and taps for security issues.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.AuditConfig{
				CheckCVE:       checkCVE,
				CheckAbandoned: checkAbandoned,
				CheckHTTP:      checkHTTP,
				Verbose:        verbose,
			}

			results, err := audit.RunLocalAudit(cfg)
			if err != nil {
				return fmt.Errorf("audit failed: %w", err)
			}

			return report.Output(results, outputFmt)
		},
	}

	cmd.Flags().BoolVar(&checkCVE, "cve", true, "Check for known CVEs")
	cmd.Flags().BoolVar(&checkAbandoned, "abandoned", true, "Check for abandoned upstream projects")
	cmd.Flags().BoolVar(&checkHTTP, "http", true, "Flag packages using HTTP instead of HTTPS")

	return cmd
}

// vetCmd - vet a tap or formula before installing
func vetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vet [tap/formula]",
		Short: "Vet a tap or formula before installing",
		Long: `Analyze a tap or formula for security risks before installation.

Examples:
  brewster vet homebrew/cask
  brewster vet user/tap/formula`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := vetting.VetTarget(args[0], vetting.VetConfig{
				Verbose: verbose,
			})
			if err != nil {
				return fmt.Errorf("vetting failed: %w", err)
			}

			return report.Output(results, outputFmt)
		},
	}

	return cmd
}

// monitorCmd - ecosystem monitoring
func monitorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Monitor the Homebrew ecosystem for threats",
		Long:  `Gather intelligence on Homebrew packages, CVEs, and suspicious activity.`,
	}

	cmd.AddCommand(monitorCVECmd())
	cmd.AddCommand(monitorTapsCmd())

	return cmd
}

func monitorCVECmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cve",
		Short: "Check ecosystem for CVE-affected packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := monitor.CheckCVEs(monitor.Config{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("CVE check failed: %w", err)
			}
			return report.Output(results, outputFmt)
		},
	}
}

func monitorTapsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "taps",
		Short: "Analyze third-party taps for suspicious activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			results, err := monitor.AnalyzeTaps(monitor.Config{Verbose: verbose})
			if err != nil {
				return fmt.Errorf("tap analysis failed: %w", err)
			}
			return report.Output(results, outputFmt)
		},
	}
}

// scanCmd - full comprehensive scan
func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "Run a comprehensive security scan",
		Long:  `Performs full audit, vetting of installed taps, and ecosystem checks.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("🍺 Brewster Comprehensive Security Scan")
			fmt.Println("========================================")

			// Run local audit
			fmt.Println("\n[1/3] Auditing local installation...")
			auditResults, err := audit.RunLocalAudit(config.AuditConfig{
				CheckCVE:       true,
				CheckAbandoned: true,
				CheckHTTP:      true,
				Verbose:        verbose,
			})
			if err != nil {
				fmt.Printf("  ⚠️  Audit error: %v\n", err)
			}

			// Vet installed taps
			fmt.Println("\n[2/3] Vetting installed taps...")
			vetResults, err := vetting.VetInstalledTaps(vetting.VetConfig{Verbose: verbose})
			if err != nil {
				fmt.Printf("  ⚠️  Vetting error: %v\n", err)
			}

			// Ecosystem check
			fmt.Println("\n[3/3] Checking ecosystem intelligence...")
			monitorResults, err := monitor.CheckCVEs(monitor.Config{Verbose: verbose})
			if err != nil {
				fmt.Printf("  ⚠️  Monitor error: %v\n", err)
			}

			// Combine results
			combined := report.CombinedReport{
				Audit:   auditResults,
				Vetting: vetResults,
				Monitor: monitorResults,
			}

			fmt.Println("\n========================================")
			return report.Output(combined, outputFmt)
		},
	}
}
