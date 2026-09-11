# SeKretSauce

SeKretSauce is a macOS security toolkit with three related products:

- a privileged local security agent built with Endpoint Security;
- a Go CLI and SwiftUI dashboard for security inventory and investigation;
- ProtectX, a packet-filter and Application Firewall manager.

The agent runs in local-only mode by default. Connecting it to a remote service
is optional and requires an HTTPS endpoint plus an API key configured through a
root-owned terminal.

## Current features

### Behavioral malware and ransomware detection

- Correlates process execution, code-signing state, obfuscated interpreter
  commands, persistence changes, credential-file changes, security-control
  tampering, rapid document writes, ransomware extensions, and canary files.
- Records incidents with correlated verdicts. A signed bulk editor does not
  become containment-worthy from document volume alone.
- Task-bound suspend/resume is implemented but disabled by default pending live
  validation on a signed macOS test installation.
- The GUI asks the authenticated daemon to install private canaries in the
  current user's Documents directory; setup no longer writes through the GUI.

This requires Apple's Endpoint Security entitlement and Full Disk Access. The
monitor operates on notification events. Any enabled containment follows the
observed operation and cannot undo an earlier file change.

### Process and tunnel monitoring

- Endpoint Security process, file-open, file-write, rename, kext-load, mount,
  fork, signal, and exit subscriptions.
- Detection for SSH forwarding, Cloudflare Tunnel, ngrok, Tailscale,
  WireGuard, OpenVPN, DNS-tunnel-like names, and related tools.
- Exact DNS-label and executable-name matching to reduce lookalike false
  positives.
- Sensitive command-line values are redacted before audit logging.

### SSH session auditing

- SSH option and forwarding detection.
- Optional asciicast v2 output recording with private directories and `0600`
  files.
- Terminal input is never recorded by default, and recording is opt-in when no
  configuration exists.

Users must invoke or alias the installed `ssh-wrapper` explicitly. Set
`SEKRETSAUCE_RECORD_SSH=1` for an individual invocation to opt into output
recording; ordinary `ssh` is never silently replaced.

### Security inventory CLI

- Keychain metadata review.
- Browser bookmark, history, and settings export for Safari, Chrome, Firefox.
- Installed app, launch-agent, process, secret, wallet, CA, and certificate
  transparency checks.
- HIBP password range checks using k-anonymity. Account lookups are opt-in and
  require both `--check-breaches` and `HIBP_API_KEY`.
- Versioned full/quick scan reports with explicit component failures, normalized
  findings, and GUI cancellation.
- Private local scan history distinguishes new, continuing, resolved, and
  unobserved findings using each scanner's latest comparable successful run.
- Machine-readable JSON with private output files and symlink protection.

### ProtectX firewall management

- Dedicated PF anchor that preserves the system's existing `/etc/pf.conf`.
- Strict PF rule validation, stable rule IDs, revision conflicts, and change previews.
- Canonical policy with staged validation, rollback journals, and startup recovery.
- Application Firewall management without shell interpolation.
- A privileged XPC helper that accepts only approved, same-team signed clients.

### Camera and microphone privacy controls

The GUI displays the real macOS authorization state, can request access when
the user explicitly asks, and opens the correct System Settings privacy pane
for revocation. macOS does not provide third-party apps a supported global
camera or microphone hardware-off API, so the UI does not claim to offer one.

## Deliberately disabled

The DNS and transparent proxy providers refuse to start. Their earlier
implementation reflected bytes back to the originating app instead of creating
a genuine upstream relay, which could loop or corrupt traffic. The passive
content-filter and Endpoint Security paths remain available. A future proxy
must bridge an independently authenticated `NWConnection` in both directions
and receive a separate security review before activation.

## Requirements

- macOS 13 or later for the agent; macOS 14 for the GUI.
- Root privileges for the launch daemon and firewall changes.
- Apple-approved Endpoint Security entitlement for behavioral monitoring.
- Developer ID signing and the relevant Network/System Extension entitlements
  for packaged distribution.

## Build and test

```bash
# Go CLI
make build

# Security agent
swift build
swift test

# GUI
cd gui-apps/app
swift build

# ProtectX
cd protectx/FirewallKit
swift test
```

## Install and configure

```bash
swift build -c release
sudo ./scripts/install.sh

# Optional remote log service configuration; the API key is read without echo.
sudo "/Library/Application Support/SeKretSauce/sekretsauced" --setup
```

The agent continues local protection if remote authentication is unavailable.
Remote endpoints must use HTTPS and may not contain embedded credentials.

## Data locations and privacy

- Audit logs: `/Library/Application Support/SeKretSauce/logs/`
- Launch-daemon stdout/stderr: `/Library/Logs/SeKretSauce/`
- Per-user SSH recordings:
  `~/Library/Application Support/SeKretSauce/recordings/`

Audit and recording directories use mode `0700`; files use `0600`. Logs are not
application-layer encrypted. Deployments that require encrypted log payloads
should use FileVault for local data and add an organization-approved encryption
scheme before remote export.

## Project layout

```text
Sources/
  Common/             shared models, Keychain, redaction, audit logging
  Daemon/             authentication and component lifecycle
  EndpointSecurity/   process/file event integration
  ThreatDetection/    behavioral scoring and ransomware correlation
  TunnelDetection/    tunnel indicators and correlation
  SSHRecorder/        SSH parsing and optional asciicast capture
  NetworkExtension/   passive filter and disabled proxy placeholders
sekretsauce-cli/      Go investigation CLI
gui-apps/app/         SwiftUI dashboard and privacy controls
gui-apps/installer/   signed installer
protectx/             firewall library, GUI, CLI, and privileged helper
```

## License

Proprietary — all rights reserved.

## Roadmap implementation notes

See [implementation progress](reviews/2026-09-10/IMPLEMENTATION.md) for delivered
work, test evidence, and remaining design acceptance checks.

`sekretsauce scan --profile quick --json` runs Keychain, hidden-process/launch-agent,
and application checks. `--profile full` also scans secrets, wallets, and certificate
authorities. Account breach lookups remain opt-in; certificate transparency needs
an explicit `scan certs --domain` target. Exit 0 means completed, exit 2 means the
report is partial or failed, and exit 1 means invocation/output failure. Findings
alone do not change the exit code. Individual scanner commands retain their legacy
JSON formats. Full report schema version 1 includes compatibility raw scanner data;
only normalized metadata is saved in GUI history.

The GUI keeps 20 reports under `~/Library/Application Support/SeKretSauce/scan-history`
with directory mode `0700` and file mode `0600`. Cancelling a GUI run discards late
results and terminates its CLI process; descendant subprocess cancellation and
persistent cancelled reports are not yet implemented.

`sekretsauced --status --json` queries the running daemon. Both it and the GUI must
be signed by the same Apple development team, with identifiers
`com.sekretsauce.daemon` and `com.afterdarktech.sekretsauce` respectively. Set
`CODE_SIGN_IDENTITY` when using the build scripts; ad-hoc builds cannot use the
agent control interface. Install the updated launch-daemon plist to register its
Mach service. Endpoint Security entitlement and Full Disk Access are still required.

Incidents live in the daemon-owned `/Library/Application Support/SeKretSauce/incidents`
store. Their recommendation and actual response state are separate. For an isolated,
signed test deployment, `SEKRETSAUCE_ENABLE_TASK_RESPONSE=1` in the daemon's launch
environment opts into task suspension after a critical verdict. It uses a verified
audit token and a task-specific suspension token; denied access is recorded as a
failure. The Incidents view can resume a live applied response for the authenticated
user. A daemon restart marks outstanding responses interrupted and never replays a
stored PID. Validate task exit, exec, restart, and permissions before production use.
