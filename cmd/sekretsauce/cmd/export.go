package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/afterdarktech/sekretsauce/pkg/browser"
	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export browser data (settings, bookmarks, history)",
	Long: `Export browser data from installed browsers.

This command extracts settings, bookmarks, and history from browsers.
Note: Password extraction requires explicit --passwords flag and proper authorization.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExport([]string{"firefox", "chrome", "safari"})
	},
}

var exportFirefoxCmd = &cobra.Command{
	Use:     "firefox",
	Aliases: []string{"ff"},
	Short:   "Export Firefox browser data",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExport([]string{"firefox"})
	},
}

var exportChromeCmd = &cobra.Command{
	Use:     "chrome",
	Aliases: []string{"gc"},
	Short:   "Export Chrome browser data",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExport([]string{"chrome"})
	},
}

var exportSafariCmd = &cobra.Command{
	Use:   "safari",
	Short: "Export Safari browser data",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runExport([]string{"safari"})
	},
}

var (
	includePasswords bool
	includeHistory   bool
	includeBookmarks bool
	includeSettings  bool
)

func init() {
	rootCmd.AddCommand(exportCmd)
	exportCmd.AddCommand(exportFirefoxCmd)
	exportCmd.AddCommand(exportChromeCmd)
	exportCmd.AddCommand(exportSafariCmd)

	// Add flags to all export commands
	for _, cmd := range []*cobra.Command{exportCmd, exportFirefoxCmd, exportChromeCmd, exportSafariCmd} {
		cmd.Flags().BoolVar(&includePasswords, "passwords", false, "Include saved passwords (requires authorization)")
		cmd.Flags().BoolVar(&includeHistory, "history", true, "Include browsing history")
		cmd.Flags().BoolVar(&includeBookmarks, "bookmarks", true, "Include bookmarks")
		cmd.Flags().BoolVar(&includeSettings, "settings", true, "Include browser settings")
	}
}

func runExport(browsers []string) error {
	printSection("Browser Export")

	results := make(map[string]*browser.ExportResult)
	var errors []string

	for _, b := range browsers {
		printInfo(fmt.Sprintf("Scanning %s...", b))

		opts := browser.ExportOptions{
			IncludePasswords: includePasswords,
			IncludeHistory:   includeHistory,
			IncludeBookmarks: includeBookmarks,
			IncludeSettings:  includeSettings,
		}

		result, err := browser.Export(b, opts)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", b, err))
			printWarning(fmt.Sprintf("%s: %v", b, err))
			continue
		}

		results[b] = result
		printSuccess(fmt.Sprintf("%s: found %d profiles", b, len(result.Profiles)))
	}

	// Output results
	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	} else {
		for browserName, result := range results {
			fmt.Printf("\n%s:\n", browserName)
			for _, profile := range result.Profiles {
				fmt.Printf("  Profile: %s\n", profile.Name)
				fmt.Printf("    Bookmarks: %d\n", len(profile.Bookmarks))
				fmt.Printf("    History entries: %d\n", len(profile.History))
				if includePasswords {
					fmt.Printf("    Saved passwords: %d\n", len(profile.Passwords))
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("completed with %d error(s)", len(errors))
	}

	return nil
}
