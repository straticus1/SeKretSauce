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
- Suspends a process only after a critical correlated verdict. A signed bulk
  editor is reported but is not suspended based on volume alone.
- Includes a GUI action that installs private ransomware canaries in the
  current user's Documents directory.

This requires Apple's Endpoint Security entitlement and Full Disk Access. The
monitor operates on notification events, so containment happens immediately
after a high-confidence event rather than before the filesystem operation.

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
- Machine-readable JSON with private output files and symlink protection.

### ProtectX firewall management

- Dedicated PF anchor that preserves the system's existing `/etc/pf.conf`.
- Strict PF rule validation, atomic configuration writes, and syntax checks.
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
