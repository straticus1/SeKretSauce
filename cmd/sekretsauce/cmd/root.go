package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	outputJSON   bool
	outputFile   string
	verbose      bool
	Version      = "0.1.0"
)

var rootCmd = &cobra.Command{
	Use:   "sekretsauce",
	Short: "SeKretSauce - Security Swiss Army Knife",
	Long: `
███████╗███████╗██╗  ██╗██████╗ ███████╗████████╗███████╗ █████╗ ██╗   ██╗ ██████╗███████╗
██╔════╝██╔════╝██║ ██╔╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝
███████╗█████╗  █████╔╝ ██████╔╝█████╗     ██║   ███████╗███████║██║   ██║██║     █████╗
╚════██║██╔══╝  ██╔═██╗ ██╔══██╗██╔══╝     ██║   ╚════██║██╔══██║██║   ██║██║     ██╔══╝
███████║███████╗██║  ██╗██║  ██║███████╗   ██║   ███████║██║  ██║╚██████╔╝╚██████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝

A multi-tool for network and security professionals on macOS.

Features:
  • Browser credential & settings export (Firefox, Chrome)
  • Certificate transparency monitoring
  • macOS Keychain scanning
  • Hidden process & launch agent detection
  • App bundle security inspection
  • Breach detection (HaveIBeenPwned integration)
`,
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "Output results as JSON")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}

// Helper functions for consistent output
func printSuccess(msg string) {
	fmt.Fprintf(os.Stdout, "\033[32m✓\033[0m %s\n", msg)
}

func printWarning(msg string) {
	fmt.Fprintf(os.Stdout, "\033[33m⚠\033[0m %s\n", msg)
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "\033[31m✗\033[0m %s\n", msg)
}

func printInfo(msg string) {
	fmt.Fprintf(os.Stdout, "\033[36mℹ\033[0m %s\n", msg)
}

func printSection(title string) {
	fmt.Printf("\n\033[1;34m━━━ %s ━━━\033[0m\n\n", title)
}
