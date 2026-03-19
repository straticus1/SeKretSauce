package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Formatter handles output formatting
type Formatter struct {
	JSONOutput bool
	Writer     io.Writer
	UseColor   bool
}

// New creates a new output formatter
func New(jsonOutput bool) *Formatter {
	return &Formatter{
		JSONOutput: jsonOutput,
		Writer:     os.Stdout,
		UseColor:   true,
	}
}

// Colors for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// WriteJSON outputs data as JSON
func (f *Formatter) WriteJSON(v interface{}) error {
	enc := json.NewEncoder(f.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Success prints a success message
func (f *Formatter) Success(msg string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "%s✓%s %s\n", ColorGreen, ColorReset, msg)
	} else {
		fmt.Fprintf(f.Writer, "[OK] %s\n", msg)
	}
}

// Warning prints a warning message
func (f *Formatter) Warning(msg string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "%s⚠%s %s\n", ColorYellow, ColorReset, msg)
	} else {
		fmt.Fprintf(f.Writer, "[WARN] %s\n", msg)
	}
}

// Error prints an error message
func (f *Formatter) Error(msg string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "%s✗%s %s\n", ColorRed, ColorReset, msg)
	} else {
		fmt.Fprintf(f.Writer, "[ERROR] %s\n", msg)
	}
}

// Info prints an info message
func (f *Formatter) Info(msg string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "%sℹ%s %s\n", ColorCyan, ColorReset, msg)
	} else {
		fmt.Fprintf(f.Writer, "[INFO] %s\n", msg)
	}
}

// Section prints a section header
func (f *Formatter) Section(title string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "\n%s%s━━━ %s ━━━%s\n\n", ColorBold, ColorBlue, title, ColorReset)
	} else {
		fmt.Fprintf(f.Writer, "\n=== %s ===\n\n", title)
	}
}

// Critical prints a critical alert
func (f *Formatter) Critical(msg string) {
	if f.UseColor {
		fmt.Fprintf(f.Writer, "%s%s⚠ CRITICAL: %s%s\n", ColorBold, ColorRed, msg, ColorReset)
	} else {
		fmt.Fprintf(f.Writer, "[CRITICAL] %s\n", msg)
	}
}

// Table prints data in a table format
func (f *Formatter) Table(headers []string, rows [][]string) {
	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print headers
	for i, h := range headers {
		fmt.Fprintf(f.Writer, "%-*s  ", widths[i], h)
	}
	fmt.Fprintln(f.Writer)

	// Print separator
	for i := range headers {
		for j := 0; j < widths[i]; j++ {
			fmt.Fprint(f.Writer, "-")
		}
		fmt.Fprint(f.Writer, "  ")
	}
	fmt.Fprintln(f.Writer)

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Fprintf(f.Writer, "%-*s  ", widths[i], cell)
			}
		}
		fmt.Fprintln(f.Writer)
	}
}

// Progress prints a progress indicator
func (f *Formatter) Progress(current, total int, msg string) {
	pct := float64(current) / float64(total) * 100
	if f.UseColor {
		fmt.Fprintf(f.Writer, "\r%s[%3.0f%%]%s %s", ColorCyan, pct, ColorReset, msg)
	} else {
		fmt.Fprintf(f.Writer, "\r[%3.0f%%] %s", pct, msg)
	}
	if current == total {
		fmt.Fprintln(f.Writer)
	}
}
