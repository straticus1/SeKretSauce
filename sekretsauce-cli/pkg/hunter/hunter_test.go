package hunter

import "testing"

func TestParseProcessLine(t *testing.T) {
	process, ok := parseProcessLine("  42  1 alice /usr/bin/curl curl https://example.com")
	if !ok {
		t.Fatal("expected process line to parse")
	}
	if process.PID != 42 || process.PPID != 1 || process.Name != "curl" {
		t.Fatalf("unexpected process: %#v", process)
	}
	if process.CommandLine != "curl https://example.com" {
		t.Fatalf("unexpected command: %q", process.CommandLine)
	}
}

func TestParseProcessLineDoesNotPanicOnShortInput(t *testing.T) {
	if _, ok := parseProcessLine("1 2 root"); ok {
		t.Fatal("expected short line to be rejected")
	}
}

func TestRedactCommandLine(t *testing.T) {
	redacted := redactCommandLine("tool --token abc https://alice:secret@example.com")
	if redacted != "tool --token <redacted> https://<redacted>@example.com" {
		t.Fatalf("unexpected redaction: %q", redacted)
	}
}
