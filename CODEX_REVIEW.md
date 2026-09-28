# Codex Review: SeKretSauce

Review date: 2026-08-03

## Executive Summary

SeKretSauce is a macOS security toolkit containing a privileged local security
agent, a Go security-inventory CLI, a SwiftUI dashboard, an installer, and the
ProtectX firewall components.

The original CLI-oriented `TODO` is largely complete, but several completion
claims are overstated. The newer `ENHANCEMENTS_TODO.md` describes a much larger
roadmap toward a lightweight endpoint detection and response product and is
mostly future work.

The current code is a useful foundation, but completing the entire enhancement
roadmap to production quality is a substantial multi-person project rather than
a short feature pass.

## Repository Structure

This is **one Git repository organized as a monorepo**.

- Git root: the `afterdark-secretsauce` checkout
- Remote: `https://github.com/straticus1/SeKretSauce.git`
- Git submodules: none
- Tracked Swift and Go code: approximately 19,000 lines
- Tracked files at review time: 114

The `.git` directory under
`protectx/CLI/.build/checkouts/swift-argument-parser/` belongs to a downloaded
Swift package dependency. It is not a separate project repository or
submodule.

The monorepo contains:

- Seven Swift packages
- One Go module
- One Xcode GUI project
- The root security agent and shared libraries
- The Go investigation CLI
- The SwiftUI user application
- The signed installer
- ProtectX firewall libraries, GUI, CLI, and privileged helper

Important package and project roots include:

```text
Package.swift                         Root Swift security agent
sekretsauce-cli/go.mod                Go CLI
gui-apps/app/Package.swift            SwiftUI application
gui-apps/app/SeKretSauce.xcodeproj    Xcode application project
gui-apps/installer/Package.swift      Installer support
protectx/CLI/Package.swift            ProtectX CLI
protectx/FirewallHelper/Package.swift Privileged firewall helper
protectx/FirewallKit/Package.swift    Firewall library
protectx/GUI/Package.swift            ProtectX GUI
```

## What the Project Does

The repository combines three related products:

1. A privileged macOS security agent that monitors processes and file activity
   for suspicious execution, persistence changes, ransomware behavior,
   security-control tampering, and tunneling tools.
2. A Go CLI and SwiftUI dashboard for reviewing Keychain metadata, browsers,
   applications, processes, exposed secrets, cryptocurrency wallets,
   certificates, certificate authorities, and breach exposure.
3. ProtectX, which manages macOS PF and Application Firewall configuration
   through libraries, a GUI, a CLI, and a privileged helper.

The repository also includes an optional SSH wrapper that detects forwarding
and can record terminal output in asciicast format. Remote authentication and
log synchronization are optional; the agent is designed to continue local
protection without a remote service.

## Original TODO Assessment

The command set described by the root `TODO` exists:

- Firefox, Chrome, Safari, and combined browser export commands
- Keychain scanning
- Certificate-transparency checks
- Hidden-process and launch-agent detection
- Application inspection
- HIBP breach checks
- Secret scanning
- Cryptocurrency-wallet detection
- Certificate-authority auditing
- JSON output
- File output for JSON results
- Shell-completion generation
- A SwiftUI GUI
- Modular Go packages

### Overstated or Incomplete Claims

The following items should not currently be represented as fully complete:

#### Verbose mode

The `--verbose`/`-v` flag is declared, but the associated variable is not used
to alter output or behavior. The CLI accepts the flag without providing a
meaningful verbose mode.

#### Browser-password export

The `--passwords` option and `IncludePasswords` field exist, but the browser
export implementations do not use them to retrieve password data. Firefox,
Chrome, and Safari exports currently cover other browser data, not actual saved
password export.

#### GUI feature parity

The GUI does not expose every CLI scan. It has no dedicated interfaces for the
secret, wallet, or certificate-authority scanners. Therefore, the statement
that the GUI contains all scan features is inaccurate.

#### Comprehensive full scan

The full scan does not run certificate-transparency checks because those
require a domain. Breach checking is also opt-in and requires the necessary
HIBP configuration. Calling the default scan comprehensive should be qualified.

#### Deployed behavioral monitoring

The behavioral-monitoring code and tests exist, but real deployment requires:

- Root installation
- Full Disk Access where applicable
- Apple's restricted Endpoint Security entitlement
- Correct signing and notarization
- Appropriate system/network-extension packaging

Passing local unit tests does not verify the complete installed product path.

## Enhancement Roadmap Assessment

The roadmap in `ENHANCEMENTS_TODO.md` is not complete. Its phase checkboxes are
all open.

Some useful groundwork already exists:

- Local deterministic behavioral scoring
- Correlation of several process and file indicators
- Rapid document-write detection
- Ransomware extensions and canary detection
- High-confidence process suspension using `SIGSTOP`
- Sensitive-file monitoring
- Persistence and security-control path detection
- Tunnel and suspicious-DNS detection
- Command-line secret redaction
- PF and Application Firewall management foundations

Major remaining areas include:

- Proper Endpoint Security system-extension packaging
- Apple Endpoint Security entitlement approval
- Stable normalized event schema
- Reliable process ancestry and responsible-process tracking
- Event-loss and callback-performance monitoring
- Encrypted local incident storage
- Code-signing, notarization, hash, and provenance enrichment
- Process and incident graphs
- Interactive incident timelines
- Plain-language verdict explanations
- MITRE ATT&CK mappings
- Trust, quarantine, recovery, and reversible response workflows
- Detector simulation and replay testing
- A genuine Network Extension content-filter implementation
- Joining network flows to Endpoint Security process identities
- Per-application outbound rules
- Learning mode and temporary permissions
- Destination history and novelty scoring
- Local behavioral baselines and anomaly detection
- Fleet policy, health, telemetry, isolation, and administration
- SIEM-compatible export and comprehensive remote-action auditing

The DNS and transparent proxy providers are deliberately disabled because the
previous approach did not implement a safe upstream relay. They should not be
counted as completed network protection.

## Verification Performed

At review time:

- The Go CLI built successfully.
- The CLI exposed the documented `scan`, `export`, and `completion` command
  families.
- Zsh completion generation succeeded.
- The SwiftUI GUI package built successfully, with warnings about unhandled
  `Info.plist` and `build.sh` files.
- Eleven Go tests passed.
- Forty-three Swift tests passed.
- No test failures were observed.

The automated tests cover several important security properties, including:

- Symlink-safe JSON output
- Domain and email validation
- Safari bookmark parsing
- Certificate fingerprint handling
- Process parsing and command-line redaction
- Private audit-log permissions and symlink rejection
- Behavioral verdicts and ransomware correlation
- SSH recording privacy
- HTTPS endpoint validation
- Tunnel detection and lookalike false-positive handling

Test coverage is still modest relative to the safety requirements of a product
that can suspend processes, alter firewall state, and run privileged system
components. Passing tests should be viewed as foundation validation, not full
product certification.

## Estimated Remaining Work

These estimates are engineering estimates, not delivery commitments. They
assume engineers experienced with macOS security frameworks, Swift
concurrency, privileged XPC, Network Extension, code signing, and security
product testing.

| Scope | Estimated effort |
|---|---:|
| Correct the gaps in the original `TODO` | 2-5 engineer-weeks |
| Deliver a credible behavioral-security MVP | 9-15 engineer-months |
| Complete the entire five-phase roadmap | 25-40 engineer-months |

Approximate effort by roadmap area:

| Area | Estimated effort |
|---|---:|
| Trustworthy Endpoint Security sensor | 4-7 engineer-months |
| Behavioral correlation, graph, explanations, and response | 5-8 engineer-months |
| Network filtering and endpoint/network fusion | 4-7 engineer-months |
| Local baselines and anomaly detection | 3-5 engineer-months |
| Fleet and small-business management | 6-10 engineer-months |

Production packaging, compatibility testing, performance work, security
review, release engineering, and operational tooling run across all phases and
are reflected mainly in the upper ends of these estimates.

### Approximate Calendar Duration

- One senior macOS/security engineer: approximately 2.5-4 years
- Three experienced engineers: approximately 12-20 months
- Five engineers with dedicated QA/release support: approximately 8-14 months

A prototype with reduced safety, compatibility, and operational requirements
could be produced sooner, but it should not be treated as a production endpoint
security product.

## Principal Sources of Effort and Risk

The difficult work is not limited to adding commands or screens. A reliable
endpoint security product must address:

- High-volume Endpoint Security event handling
- Strict callback deadlines and bounded memory use
- Dropped-event detection and confidence reduction
- PID reuse and durable process identity
- Process-tree and responsible-process attribution
- False positives in automatic containment
- Correct linkage of network flows to process identities
- Secure privileged IPC and client identity verification
- Safe, reversible suspension, quarantine, and recovery
- System-extension installation, upgrades, rollback, and removal
- Signing, notarization, and macOS compatibility
- Incident-data security and schema migration
- Performance regression and adversarial testing
- Fleet authorization, policy signing, telemetry minimization, and audit trails

Apple's Endpoint Security entitlement is an external dependency. Engineering
can begin before approval, but real distribution and field validation depend
on Apple granting the entitlement. Its approval schedule should not be assumed
to match the engineering schedule.

## Recommended Delivery Sequence

1. Correct documentation and finish the narrow original TODO gaps: meaningful
   verbose behavior, an explicit browser-password decision, GUI feature parity,
   and integration tests.
2. Stabilize repository and product boundaries, shared models, signing
   identities, bundle identifiers, and build/release automation.
3. Package and validate the Endpoint Security sensor, including event health,
   process identity, performance metrics, and safe update/rollback behavior.
4. Build deterministic detector replay and simulation infrastructure before
   enabling broader automatic containment.
5. Add incident storage, process graphs, timelines, explanations, and
   reversible response controls.
6. Implement and independently security-review a real Network Extension
   content filter before enabling proxy or outbound-control claims.
7. Add local baselines only after deterministic telemetry and incident data are
   stable enough to evaluate false positives.
8. Treat fleet management as a separate product phase with its own threat
   model, authorization design, privacy review, and operational plan.

## Working Tree Note

At review time, the repository had uncommitted ProtectX changes and untracked
files, including `ENHANCEMENTS_TODO.md`, new XPC/helper files, and `.omc/`.
Those changes belong to the current working tree and were not modified as part
of this review. They should be reviewed and committed, split into focused
commits, or otherwise preserved before broad roadmap implementation begins.

## Bottom Line

The original CLI MVP is largely implemented and builds successfully, but it
has several overstated completion claims. The enhancement roadmap describes a
far larger product: a Mac-native, local-first endpoint detection and response
platform. Completing that roadmap safely and credibly is approximately
25-40 engineer-months of work, plus the uncertainty of Apple entitlement and
distribution approval.
