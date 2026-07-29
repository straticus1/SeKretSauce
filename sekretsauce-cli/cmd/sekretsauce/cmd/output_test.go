package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputAsJSONRejectsSymbolicLink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "report.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	previous := outputFile
	outputFile = link
	t.Cleanup(func() { outputFile = previous })

	if err := outputAsJSON(map[string]string{"status": "ok"}); err == nil {
		t.Fatal("expected symbolic-link output to be rejected")
	}
}
