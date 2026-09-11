package cmd

import (
	"bytes"
	"encoding/json"
	"github.com/afterdarktech/sekretsauce/pkg/hunter"
	"github.com/afterdarktech/sekretsauce/pkg/inspector"
	"github.com/afterdarktech/sekretsauce/pkg/keychain"
	"os"
	"strings"
	"testing"
)

func TestSummaryUsesEveryFindingAndActualSeverity(t *testing.T) {
	r := &ScanResults{
		Keychain: &keychain.ScanResult{WeakItems: []keychain.WeakItem{{Reason: "Weak metadata", Severity: "medium"}}},
		Hidden:   &hunter.ScanResult{SuspiciousLaunchAgents: []hunter.SuspiciousAgent{{PlistPath: "/example.plist", SuspicionReason: "Unexpected persistence", Severity: "high"}}},
		Apps:     &inspector.ScanResult{Issues: []inspector.SecurityIssue{{AppPath: "/example.app", Description: "Tampered", Severity: "critical"}}},
	}
	r.addComponent("keychain", "completed", nil, "")
	r.addComponent("hidden", "completed", nil, "")
	r.addComponent("apps", "completed", nil, "")
	r.normalize()
	if r.Summary.TotalFindings != 3 || r.Summary.CriticalIssues != 1 || r.Summary.Warnings != 2 {
		t.Fatalf("summary=%+v", r.Summary)
	}
	for _, x := range r.Summary.Recommendations {
		if strings.Contains(x, "account") {
			t.Fatal("unrelated breach recommendation")
		}
	}
}
func TestCoverageAndErrorsSurviveJSON(t *testing.T) {
	r := &ScanResults{}
	r.addComponent("keychain", "failed", []string{"permission denied"}, "")
	r.addComponent("apps", "completed", nil, "")
	r.addComponent("breach", "skipped", nil, "Not requested")
	r.normalize()
	if r.Status != "partial" {
		t.Fatal(r.Status)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"errors":["permission denied"]`, `"findings":[]`, `"skipped_reason":"Not requested"`} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("missing %s: %s", expected, data)
		}
	}
	r.Components[1].Status = "failed"
	r.normalize()
	if r.Status != "failed" {
		t.Fatal(r.Status)
	}
}

// This producer fixture is also decoded by the Swift GUI test suite.
func TestSharedScanReportFixture(t *testing.T) {
	r := &ScanResults{Target: "fixture:501", SchemaVersion: 1, RunID: "fixture-v1", Profile: "quick", StartedAt: "2026-09-10T12:00:00Z"}
	r.addComponent("keychain", "failed", []string{"permission denied"}, "")
	r.addComponent("apps", "completed", nil, "")
	r.normalize()
	r.FinishedAt = "2026-09-10T12:00:01Z"
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := "../../../../Tests/Fixtures/scan-report-v1.json"
	if os.Getenv("UPDATE_SCAN_FIXTURE") == "1" {
		if err := os.MkdirAll("../../../../Tests/Fixtures", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(expected), data) {
		t.Fatal("shared scan report fixture changed")
	}
}
