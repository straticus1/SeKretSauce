# ProtectX Enhancements Roadmap

## Product Direction

ProtectX should be positioned as an **explainable, local-first behavioral
security platform for macOS**, rather than another signature-based antivirus
product.

macOS already includes Gatekeeper, notarization, XProtect, System Integrity
Protection (SIP), Transparency, Consent, and Control (TCC), FileVault, and an
application firewall. XProtect also includes some behavioral analysis. The
remaining product opportunity is to make system security activity visible,
understandable, correlated, and actionable for users.

ProtectX can fill that gap by:

- explaining what applications are doing;
- correlating related behavior across processes, files, persistence, and the
  network;
- detecting suspicious sequences instead of relying only on signatures;
- giving users safe and reversible response controls;
- operating locally by default, with optional privacy-filtered cloud features.

Reference:
[Apple's macOS malware protection overview](https://support.apple.com/en-mide/guide/security/sec469d47bd8/web)

## Behavior Monitor

The proposed "syscall monitoring" capability should be presented to users as
the **Behavior Monitor**, **Execution Monitor**, or **Threat Graph**.

Intercepting every raw syscall with a kernel extension is not the appropriate
architecture on modern macOS. Apple intends security products to use the
Endpoint Security framework, which replaces unsupported kernel authorization
hooks and the OpenBSM audit event stream.

Endpoint Security exposes semantic events including:

- process execution, fork, exit, and signals;
- file creation, writes, renames, deletion, and metadata changes;
- memory mapping and memory-protection changes;
- task-port access and process inspection;
- mounts and kernel or system extension activity;
- authentication and privilege events;
- Gatekeeper bypasses and XProtect detections on newer macOS versions.

It provides two event classes:

- `AUTH` events, which allow a client to permit or deny an operation before its
  deadline;
- `NOTIFY` events, which report an operation asynchronously.

Distribution requires Apple's restricted Endpoint Security entitlement.

References:

- [Build an Endpoint Security app](https://developer.apple.com/videos/play/wwdc2020/10159/)
- [Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t)
- [Endpoint Security entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client)

## Target Architecture

```text
Endpoint Security events ─┐
Network Extension flows ──┼─> Entity graph ─> Correlation engine ─> Verdict
DNS and firewall events ──┤         │                │
System posture changes ───┘         │                ├─ Allow
                                    │                ├─ Warn
                                    │                ├─ Suspend
                                    │                ├─ Kill/quarantine
                                    │                └─ Block network
                                    └─ Incident timeline and explanation
```

The central design principle is correlation. Individual activities are often
benign; suspicious sequences provide much stronger evidence.

Example sequence:

```text
Browser downloads unsigned executable
  → executable removes quarantine attribute
  → launches from Downloads
  → invokes osascript
  → reads SSH keys
  → creates a LaunchAgent
  → contacts a new external destination
```

No single event proves malware. Taken together, the events form a compelling,
explainable incident.

## High-Priority Features

### 1. Explainable Behavioral Detection

Make behavioral detection the central ProtectX feature.

Every verdict should tell the user:

- which process initiated the behavior;
- the complete parent and child process tree;
- who signed the application;
- whether it was notarized;
- what sensitive files it accessed;
- what persistence it established;
- which destinations it contacted;
- why its risk score increased;
- which MITRE ATT&CK techniques matched;
- what ProtectX did in response.

Example:

> **Critical: probable credential theft**
>
> `InvoiceViewer` was downloaded three minutes ago, bypassed quarantine,
> launched an unsigned shell, read four SSH private keys, and connected to a
> previously unseen server.
>
> Confidence: 94%.
>
> Actions: process suspended; outbound connection blocked.

Explainability should be a stronger product differentiator than a generic
"AI-powered detection" claim.

### 2. Process and Incident Graph

Build an execution and activity graph from:

- parent PID and process identity;
- responsible process and audit token;
- executable identity, hash, and signing certificate;
- files read and modified;
- network connections;
- persistence changes;
- child processes and scripts;
- user and login-session identity.

The GUI should show an interactive incident timeline:

```text
Safari
└── Installer.pkg
    └── bash
        ├── curl → unusual.example
        ├── chmod +x /tmp/update
        └── /tmp/update
            ├── read ~/.ssh/id_ed25519
            └── write ~/Library/LaunchAgents/com.fake.update.plist
```

This should give ordinary users a comprehensible story and technical users
useful forensic evidence.

### 3. Persistence Watchdog

Continuously inventory and detect changes to:

- LaunchAgents and LaunchDaemons;
- login and background items;
- cron and `at` jobs;
- shell initialization files;
- configuration profiles;
- authorization plug-ins;
- browser extensions;
- system extensions;
- privileged helper tools;
- `sudoers`;
- SSH `authorized_keys`;
- dynamic-loader configuration;
- installed application bundles.

Distinguish legitimate installers from suspicious persistence by correlating:

- the writing process;
- its signature and notarization;
- installer ancestry;
- download provenance;
- execution path;
- the timing between creation and execution.

### 4. Credential-Access Protection

Monitor unusual access to:

- `~/.ssh`;
- AWS, Azure, GCP, and other cloud credentials;
- Git credential stores;
- cryptocurrency wallets;
- browser cookie and login databases;
- password-manager data locations;
- Keychain databases and export operations;
- environment and dotenv files;
- developer secrets;
- Kubernetes configuration;
- VPN profiles and private keys.

Do not alert merely because a sensitive file was opened. Score the surrounding
context:

- Does this application normally need the file?
- Was the application recently downloaded?
- Is it signed and notarized?
- Did it access several unrelated credential sources?
- Did outbound network activity follow the read?

### 5. Ransomware Protection 2.0

Extend the existing canary and mass-write detection with:

- per-process file-write rate baselines;
- entropy changes that indicate encryption;
- rapid file-extension changes;
- attempts to destroy backups or snapshots;
- writes across many unrelated document directories;
- canary documents using multiple file types;
- network-share monitoring;
- removable-volume monitoring;
- immediate process suspension;
- an affected-file manifest for recovery;
- optional automatic network isolation.

Prefer suspension over immediate termination. Explain the evidence and let the
user release or terminate the process unless the confidence and impact are both
extreme.

### 6. Outbound Application Firewall

ProtectX currently manages PF and Apple's application firewall. The larger
consumer benefit is outbound application visibility and control.

Use Network Extension flows to implement:

- per-application outbound allow and block rules;
- first-connection prompts;
- learning mode;
- one-time or time-limited permission;
- rules based on signing identity instead of only file path;
- new-domain and rare-destination alerts;
- DNS-over-HTTPS and tunnel visibility;
- connection history grouped by application and process;
- automatic temporary blocking after a critical behavioral verdict.

Example user question:

> Why is this unsigned PDF converter connecting to servers in six countries?

Endpoint Security intentionally excludes ordinary network events. Apple directs
security products to Network Extension for this layer.

References:

- [Endpoint Security and Network Extension guidance](https://developer.apple.com/videos/play/wwdc2020/10159/)
- [Network content filters](https://developer.apple.com/documentation/NetworkExtension/content-filter-providers)

### 7. Download and Execution Provenance

Create a "Where did this come from?" view containing:

- the downloading application;
- original URL when macOS provenance permits it;
- quarantine state;
- first-seen time;
- notarization status;
- code-signing chain;
- installer-package history;
- whether the file changed after signing;
- whether the user bypassed Gatekeeper;
- processes spawned after first execution.

On macOS 15 and later, incorporate Endpoint Security events for Gatekeeper
bypasses and XProtect detections.

Reference:
[Apple's XProtect documentation](https://support.apple.com/en-mide/guide/security/sec469d47bd8/web)

### 8. Security Posture Dashboard

Give users a concise, actionable security assessment covering:

- FileVault status;
- firewall and stealth-mode status;
- SIP and secure-boot state;
- automatic security-update status;
- Gatekeeper state;
- unexpected configuration profiles;
- sharing and remote-login exposure;
- open listening services;
- unnecessary privileged helpers;
- Full Disk Access grants;
- camera, microphone, accessibility, and automation grants;
- browser security settings;
- stale software and risky extensions.

Explain the practical impact and provide safe remediation steps. Do not present
every unusual configuration as malware.

### 9. Incident Response

For high-confidence incidents, support:

- suspend or terminate a process tree;
- block outbound network access;
- quarantine the executable;
- disable malicious persistence;
- preserve hashes and metadata;
- export an incident report;
- restore modified configuration;
- create a temporary deny rule;
- trust or allow a known application;
- collect a minimally scoped forensic bundle.

All destructive actions should be reversible where practical.

### 10. Honeytokens and Deception

Extend canaries beyond ransomware documents:

- fake SSH key filenames;
- decoy cloud credential files;
- decoy wallet metadata;
- a canary browser-cookie database;
- honey documents;
- a canary LaunchAgent location;
- unique DNS tokens that trigger if decoy data is exfiltrated.

Reading a decoy resource is generally a much higher-quality signal than reading
a common sensitive file.

## Initial Behavioral Detection Pack

Begin with deterministic, sequence-based detectors:

1. Downloaded executable → quarantine removal → execution.
2. Browser or document reader → shell or interpreter.
3. Unsigned process → sensitive credential access → outbound connection.
4. Process → LaunchAgent creation → immediate execution.
5. Rapid document writes → extension changes → backup destruction.
6. `curl` or `wget` → `chmod` → execution from a temporary directory.
7. AppleScript or JXA spawning shell commands from an unusual parent.
8. Attempts to terminate ProtectX or modify security controls.
9. Task-port acquisition plus suspicious memory-protection changes.
10. New privileged helper or system extension installed outside a trusted
    installer.
11. Hidden executable launched from a user-writable directory.
12. Tunnel utility launched by an application that has no history of using one.

Map each detector to the
[MITRE ATT&CK macOS matrix](https://attack.mitre.org/matrices/enterprise/macos/)
so incidents use a standard defensive vocabulary.

## Analytics Strategy

Do not begin with a black-box malware classifier. Develop four layers:

### Layer 1: Hard Facts

- Code signature
- Notarization status
- Execution path
- Process ancestry
- Entitlements
- File operations
- Network destinations
- Quarantine and download provenance

### Layer 2: Deterministic Detections

- Known-dangerous event combinations
- Security-policy violations
- Unambiguous tampering
- Canary and honeytoken access

### Layer 3: Behavioral Correlation

- Accumulate related events per process tree
- Use sliding windows measured in seconds or minutes
- Correlate endpoint, persistence, credential, and network activity
- Raise or lower confidence as additional evidence arrives

### Layer 4: Local Anomaly Models

Learn patterns such as:

- this application has never spawned a shell;
- this application has never read SSH keys;
- this signer has never created persistence;
- this process has never contacted this destination;
- this process normally operates from a different path;
- this parent and child combination has never appeared before.

An illustrative score:

```text
Risk =
    execution provenance
  + sensitive-resource access
  + persistence
  + defense evasion
  + network novelty
  + destructive behavior
  - trusted identity
  - established local baseline
```

Machine learning should initially be used for ranking, anomaly detection, and
noise reduction. It should not be solely responsible for blocking an
operation.

## Engineering Requirements

### Two-Speed Decision Engine

Keep `AUTH` decisions extremely fast. Apple gives each authorization event an
individual deadline and terminates clients that fail to respond in time.

Use:

- a **fast path** for deterministic allow or deny decisions;
- a **slow path** for graph correlation, anomaly scoring, enrichment, and
  retrospective containment.

The slow path may allow an initial operation, then suspend the associated
process tree or isolate its network access after a critical correlated verdict.

### Event Integrity

- Track per-event and global Endpoint Security sequence numbers.
- Detect and report dropped events.
- Reduce verdict confidence when the event history is incomplete.
- Expose event-loss health in diagnostics and telemetry.

Reference:
[Endpoint Security sequence numbers](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num)

### Performance

- Cache code-signing and notarization results.
- Cache file hashes using stable file identity where possible.
- Perform minimal work inside Endpoint Security callbacks.
- Never make network requests in authorization callbacks.
- Normalize events before sending them to higher-level analysis.
- Bound queues and memory usage.
- Measure callback latency and deadline headroom.

### Safety

- Default to observation until a detector demonstrates a very low false-positive
  rate.
- Suspend before killing when practical.
- Never block solely because an application is unsigned.
- Treat trusted signing identity as evidence, not proof of safety.
- Make exceptions narrowly scoped and visible.
- Keep user recovery paths available.

### Privacy

- Keep raw event analysis on the device by default.
- Make cloud intelligence optional.
- Redact secrets and command-line credentials.
- Upload only minimized, documented fields.
- Give users retention controls.
- Explain what is collected and why.

### Sensor Protection

Package the Behavior Monitor as an Endpoint Security system extension:

- gain SIP-backed protection;
- resist accidental or malicious unloading;
- support early-boot monitoring;
- subscribe before ordinary third-party execution when early boot is enabled;
- sign and notarize every distributed component;
- verify the identities of all local IPC clients.

## Phased Roadmap

### Phase 1: Trustworthy Sensor

- [ ] Convert the existing monitor into a properly packaged Endpoint Security
      system extension.
- [ ] Obtain Apple's Endpoint Security entitlement.
- [ ] Normalize events into a stable internal schema.
- [ ] Build reliable process ancestry and responsible-process tracking.
- [ ] Track dropped events and callback performance.
- [ ] Add a local encrypted incident database.
- [ ] Implement signing, notarization, hash, and provenance enrichment.
- [ ] Add sensor health and diagnostic reporting.
- [ ] Add secure update and rollback support.

### Phase 2: Behavioral MVP

- [ ] Implement the initial 10–12 sequence-based detectors.
- [ ] Build the process graph and incident timeline.
- [ ] Add plain-language verdict explanations.
- [ ] Map incidents to MITRE ATT&CK.
- [ ] Add trust, quarantine, and suspension workflows.
- [ ] Add detector simulation and replay tests.
- [ ] Measure false positives before enabling automatic containment.

### Phase 3: Network Fusion

- [ ] Implement a genuine Network Extension content filter.
- [ ] Join network flows to Endpoint Security process identities.
- [ ] Add per-application outbound rules.
- [ ] Add learning mode and temporary permission.
- [ ] Add destination history and novelty scoring.
- [ ] Let critical endpoint verdicts create temporary network blocks.
- [ ] Detect tunneling and suspicious DNS behavior.

### Phase 4: Personal Baselines

- [ ] Learn normal parent and child process relationships.
- [ ] Learn expected sensitive-file access by application.
- [ ] Learn common execution locations.
- [ ] Learn common destinations and connection schedules.
- [ ] Detect meaningful deviations.
- [ ] Keep baseline training and evaluation local by default.
- [ ] Provide reset, export, and explanation controls for learned baselines.

### Phase 5: Small-Business Mode

- [ ] Signed policy bundles.
- [ ] Fleet health and incident overview.
- [ ] Tamper detection.
- [ ] Remote isolation with explicit authorization.
- [ ] Privacy-filtered centralized telemetry.
- [ ] SIEM-compatible event export.
- [ ] Role-based administration.
- [ ] Organization-wide trust and deny policies.
- [ ] Audit trails for every remote action.

## Product Principle

> ProtectX watches the story of what an application does—not merely what its
> file looks like—and gives the user an understandable, reversible response.

That is the path from a collection of macOS security utilities toward a
Mac-native, lightweight endpoint detection and response platform.
