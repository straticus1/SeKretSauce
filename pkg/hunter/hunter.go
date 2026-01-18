package hunter

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ScanOptions configures the hidden process scan
type ScanOptions struct {
	Deep bool
}

// ScanResult contains hidden process scan results
type ScanResult struct {
	ProcessesScanned        int                `json:"processes_scanned"`
	LaunchAgentsChecked     int                `json:"launch_agents_checked"`
	SuspiciousProcesses     []SuspiciousProc   `json:"suspicious_processes,omitempty"`
	SuspiciousLaunchAgents  []SuspiciousAgent  `json:"suspicious_launch_agents,omitempty"`
	HiddenFiles             []HiddenFile       `json:"hidden_files,omitempty"`
}

// SuspiciousProc represents a potentially suspicious process
type SuspiciousProc struct {
	PID             int      `json:"pid"`
	PPID            int      `json:"ppid"`
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	User            string   `json:"user"`
	CommandLine     string   `json:"command_line"`
	SuspicionReason string   `json:"suspicion_reason"`
	Severity        string   `json:"severity"`
	Connections     []string `json:"connections,omitempty"`
}

// SuspiciousAgent represents a potentially suspicious launch agent/daemon
type SuspiciousAgent struct {
	Label           string   `json:"label"`
	PlistPath       string   `json:"plist_path"`
	Program         string   `json:"program"`
	ProgramArgs     []string `json:"program_args,omitempty"`
	RunAtLoad       bool     `json:"run_at_load"`
	KeepAlive       bool     `json:"keep_alive"`
	SuspicionReason string   `json:"suspicion_reason"`
	Severity        string   `json:"severity"`
}

// HiddenFile represents a hidden file in suspicious locations
type HiddenFile struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	Reason   string `json:"reason"`
}

// Scan performs a comprehensive hidden process and agent scan
func Scan(opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		SuspiciousProcesses:    []SuspiciousProc{},
		SuspiciousLaunchAgents: []SuspiciousAgent{},
		HiddenFiles:            []HiddenFile{},
	}

	// Scan running processes
	procs, err := scanProcesses()
	if err == nil {
		result.ProcessesScanned = len(procs)
		result.SuspiciousProcesses = filterSuspiciousProcesses(procs)
	}

	// Scan launch agents and daemons
	agents, err := scanLaunchAgents()
	if err == nil {
		result.LaunchAgentsChecked = len(agents)
		result.SuspiciousLaunchAgents = filterSuspiciousAgents(agents)
	}

	// Deep scan: check for hidden files in common persistence locations
	if opts.Deep {
		result.HiddenFiles = scanHiddenFiles()
	}

	return result, nil
}

// Process represents a running process
type Process struct {
	PID         int
	PPID        int
	Name        string
	Path        string
	User        string
	CommandLine string
}

// scanProcesses gets all running processes
func scanProcesses() ([]Process, error) {
	cmd := exec.Command("ps", "aux", "-o", "pid,ppid,user,comm,command")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var processes []Process
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		pid, _ := strconv.Atoi(fields[1])
		ppid, _ := strconv.Atoi(fields[2])

		proc := Process{
			User: fields[0],
			PID:  pid,
			PPID: ppid,
			Name: fields[10],
		}

		if len(fields) > 11 {
			proc.CommandLine = strings.Join(fields[10:], " ")
			proc.Path = fields[10]
		}

		processes = append(processes, proc)
	}

	return processes, nil
}

// filterSuspiciousProcesses identifies potentially suspicious processes
func filterSuspiciousProcesses(procs []Process) []SuspiciousProc {
	var suspicious []SuspiciousProc

	suspiciousPatterns := []struct {
		pattern  *regexp.Regexp
		reason   string
		severity string
	}{
		{regexp.MustCompile(`(?i)/tmp/.*\.(sh|py|pl|rb)`), "Script running from /tmp", "high"},
		{regexp.MustCompile(`(?i)/var/tmp/`), "Process running from /var/tmp", "high"},
		{regexp.MustCompile(`(?i)nc\s+-l`), "Netcat listener detected", "high"},
		{regexp.MustCompile(`(?i)ncat\s+-l`), "Ncat listener detected", "high"},
		{regexp.MustCompile(`(?i)python.*-c.*socket`), "Python socket one-liner", "high"},
		{regexp.MustCompile(`(?i)curl.*\|\s*(ba)?sh`), "Curl piped to shell", "critical"},
		{regexp.MustCompile(`(?i)wget.*\|\s*(ba)?sh`), "Wget piped to shell", "critical"},
		{regexp.MustCompile(`(?i)base64.*decode`), "Base64 decoding in command", "medium"},
		{regexp.MustCompile(`(?i)/dev/tcp/`), "Bash /dev/tcp connection", "critical"},
		{regexp.MustCompile(`(?i)osascript.*-e.*do shell`), "AppleScript executing shell", "high"},
		{regexp.MustCompile(`(?i)\\.app/.*MacOS/[^/]+$`), "App bundle executable without expected name", "medium"},
		{regexp.MustCompile(`(?i)cryptominer|xmrig|minerd`), "Potential cryptocurrency miner", "critical"},
	}

	// Suspicious parent processes (orphan indicators)
	for _, proc := range procs {
		// Check command line against suspicious patterns
		for _, sp := range suspiciousPatterns {
			if sp.pattern.MatchString(proc.CommandLine) {
				suspicious = append(suspicious, SuspiciousProc{
					PID:             proc.PID,
					PPID:            proc.PPID,
					Name:            proc.Name,
					Path:            proc.Path,
					User:            proc.User,
					CommandLine:     proc.CommandLine,
					SuspicionReason: sp.reason,
					Severity:        sp.severity,
				})
				break
			}
		}

		// Check for processes with hidden/deleted binary
		if strings.Contains(proc.Path, "(deleted)") {
			suspicious = append(suspicious, SuspiciousProc{
				PID:             proc.PID,
				Name:            proc.Name,
				Path:            proc.Path,
				SuspicionReason: "Process binary has been deleted",
				Severity:        "critical",
			})
		}

		// Check for unusual binary locations
		if strings.HasPrefix(proc.Path, "/Users/") &&
			!strings.Contains(proc.Path, "/Applications/") &&
			!strings.Contains(proc.Path, "Library") {
			suspicious = append(suspicious, SuspiciousProc{
				PID:             proc.PID,
				Name:            proc.Name,
				Path:            proc.Path,
				SuspicionReason: "Binary in non-standard user location",
				Severity:        "low",
			})
		}
	}

	return suspicious
}

// LaunchAgent represents a launch agent/daemon plist
type LaunchAgent struct {
	Label       string
	PlistPath   string
	Program     string
	ProgramArgs []string
	RunAtLoad   bool
	KeepAlive   bool
	Disabled    bool
}

// scanLaunchAgents scans all launch agent and daemon directories
func scanLaunchAgents() ([]LaunchAgent, error) {
	homeDir, _ := os.UserHomeDir()

	// All launch agent/daemon locations on macOS
	locations := []string{
		filepath.Join(homeDir, "Library/LaunchAgents"),
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}

	var agents []LaunchAgent

	for _, loc := range locations {
		entries, err := os.ReadDir(loc)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			plistPath := filepath.Join(loc, entry.Name())
			agent, err := parseLaunchAgentPlist(plistPath)
			if err != nil {
				continue
			}

			agents = append(agents, *agent)
		}
	}

	return agents, nil
}

// parseLaunchAgentPlist parses a launch agent plist file
func parseLaunchAgentPlist(path string) (*LaunchAgent, error) {
	// Use plutil to convert plist to XML for parsing
	cmd := exec.Command("plutil", "-convert", "xml1", "-o", "-", path)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	agent := &LaunchAgent{
		PlistPath: path,
	}

	// Simple XML parsing for key fields
	content := string(output)

	// Extract Label
	if match := regexp.MustCompile(`<key>Label</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(content); len(match) > 1 {
		agent.Label = match[1]
	}

	// Extract Program
	if match := regexp.MustCompile(`<key>Program</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(content); len(match) > 1 {
		agent.Program = match[1]
	}

	// Extract ProgramArguments (first argument as Program if Program not set)
	if match := regexp.MustCompile(`<key>ProgramArguments</key>\s*<array>\s*<string>([^<]+)</string>`).FindStringSubmatch(content); len(match) > 1 {
		if agent.Program == "" {
			agent.Program = match[1]
		}
		// Get all program arguments
		argsMatch := regexp.MustCompile(`<key>ProgramArguments</key>\s*<array>(.*?)</array>`).FindStringSubmatch(content)
		if len(argsMatch) > 1 {
			argStrings := regexp.MustCompile(`<string>([^<]+)</string>`).FindAllStringSubmatch(argsMatch[1], -1)
			for _, arg := range argStrings {
				if len(arg) > 1 {
					agent.ProgramArgs = append(agent.ProgramArgs, arg[1])
				}
			}
		}
	}

	// Check RunAtLoad
	agent.RunAtLoad = strings.Contains(content, "<key>RunAtLoad</key>") &&
		strings.Contains(content, "<true/>")

	// Check KeepAlive
	agent.KeepAlive = strings.Contains(content, "<key>KeepAlive</key>") &&
		strings.Contains(content, "<true/>")

	// Check Disabled
	agent.Disabled = strings.Contains(content, "<key>Disabled</key>") &&
		strings.Contains(content, "<true/>")

	return agent, nil
}

// filterSuspiciousAgents identifies potentially suspicious launch agents
func filterSuspiciousAgents(agents []LaunchAgent) []SuspiciousAgent {
	var suspicious []SuspiciousAgent

	// Known legitimate Apple prefixes
	legitimatePrefixes := []string{
		"com.apple.",
		"com.google.",
		"com.microsoft.",
		"com.adobe.",
		"com.dropbox.",
		"org.mozilla.",
	}

	suspiciousIndicators := []struct {
		check    func(LaunchAgent) bool
		reason   string
		severity string
	}{
		{
			check: func(a LaunchAgent) bool {
				return strings.Contains(a.Program, "/tmp/") ||
					strings.Contains(a.Program, "/var/tmp/")
			},
			reason:   "Program runs from temporary directory",
			severity: "critical",
		},
		{
			check: func(a LaunchAgent) bool {
				return strings.Contains(strings.ToLower(a.Program), "curl") ||
					strings.Contains(strings.ToLower(a.Program), "wget")
			},
			reason:   "Agent executes download tool",
			severity: "high",
		},
		{
			check: func(a LaunchAgent) bool {
				for _, arg := range a.ProgramArgs {
					if strings.Contains(arg, "base64") {
						return true
					}
				}
				return false
			},
			reason:   "Agent uses base64 encoding",
			severity: "high",
		},
		{
			check: func(a LaunchAgent) bool {
				return strings.HasPrefix(a.Program, "/Users/") &&
					!strings.Contains(a.Program, "/Applications/") &&
					!strings.Contains(a.Program, "/Library/")
			},
			reason:   "Program in non-standard user directory",
			severity: "medium",
		},
		{
			check: func(a LaunchAgent) bool {
				if a.Program == "" {
					return false
				}
				_, err := os.Stat(a.Program)
				return os.IsNotExist(err)
			},
			reason:   "Program binary does not exist",
			severity: "high",
		},
		{
			check: func(a LaunchAgent) bool {
				return a.KeepAlive && a.RunAtLoad && !a.Disabled
			},
			reason:   "Persistent agent (RunAtLoad + KeepAlive)",
			severity: "low",
		},
	}

	for _, agent := range agents {
		if agent.Disabled {
			continue
		}

		// Skip known legitimate agents
		isLegitimate := false
		for _, prefix := range legitimatePrefixes {
			if strings.HasPrefix(agent.Label, prefix) {
				isLegitimate = true
				break
			}
		}

		// Even legitimate prefixes should be checked for tampering
		for _, indicator := range suspiciousIndicators {
			if indicator.check(agent) {
				// Higher severity for legitimate-looking but suspicious
				severity := indicator.severity
				if isLegitimate && indicator.severity != "low" {
					severity = "critical" // Potential hijacking
				}

				suspicious = append(suspicious, SuspiciousAgent{
					Label:           agent.Label,
					PlistPath:       agent.PlistPath,
					Program:         agent.Program,
					ProgramArgs:     agent.ProgramArgs,
					RunAtLoad:       agent.RunAtLoad,
					KeepAlive:       agent.KeepAlive,
					SuspicionReason: indicator.reason,
					Severity:        severity,
				})
				break
			}
		}

		// Flag unknown agents (not from known vendors)
		if !isLegitimate && agent.RunAtLoad {
			// Check if it's in user's LaunchAgents (more suspicious for unknown)
			if strings.Contains(agent.PlistPath, "/Users/") {
				suspicious = append(suspicious, SuspiciousAgent{
					Label:           agent.Label,
					PlistPath:       agent.PlistPath,
					Program:         agent.Program,
					RunAtLoad:       agent.RunAtLoad,
					SuspicionReason: "Unknown user-installed persistent agent",
					Severity:        "medium",
				})
			}
		}
	}

	return suspicious
}

// scanHiddenFiles looks for hidden files in suspicious locations
func scanHiddenFiles() []HiddenFile {
	var hidden []HiddenFile

	homeDir, _ := os.UserHomeDir()

	// Locations to scan for hidden files
	locations := []string{
		homeDir,
		"/tmp",
		"/var/tmp",
		"/usr/local/bin",
	}

	for _, loc := range locations {
		entries, err := os.ReadDir(loc)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Check for hidden files (starting with .)
			if !strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			// Skip common legitimate hidden files
			legitimateHidden := []string{
				".bash_profile", ".bashrc", ".zshrc", ".profile",
				".gitconfig", ".gitignore", ".ssh", ".gnupg",
				".vimrc", ".vim", ".config", ".local",
				".Trash", ".DS_Store", ".CFUserTextEncoding",
			}

			isLegitimate := false
			for _, lh := range legitimateHidden {
				if entry.Name() == lh {
					isLegitimate = true
					break
				}
			}

			if isLegitimate {
				continue
			}

			fullPath := filepath.Join(loc, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check for executable hidden files
			if info.Mode()&0111 != 0 && !info.IsDir() {
				hidden = append(hidden, HiddenFile{
					Path:     fullPath,
					Size:     info.Size(),
					Modified: info.ModTime().Format("2006-01-02 15:04:05"),
					Reason:   "Executable hidden file",
				})
			}

			// Check for recently created hidden files in sensitive locations
			if loc == "/tmp" || loc == "/var/tmp" {
				hidden = append(hidden, HiddenFile{
					Path:     fullPath,
					Size:     info.Size(),
					Modified: info.ModTime().Format("2006-01-02 15:04:05"),
					Reason:   fmt.Sprintf("Hidden file in %s", loc),
				})
			}
		}
	}

	return hidden
}
