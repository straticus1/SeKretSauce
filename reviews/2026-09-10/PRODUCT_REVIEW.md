# SeKretSauce product correctness review

Date: 2026-09-10. Baseline: `3c340687069254c4b7f61c0b147aedc1fb92bdb9`, including the existing uncommitted ProtectX changes.

**Verdict: request changes before treating automatic containment and firewall editing as release-ready.** The most consequential defects are false process suspension, incorrect executable trust attribution, and firewall rules changing meaning after refresh. The investigation CLI and both GUIs build, but passing tests do not cover these workflows.

This is a product-wide review of the current implementation, not only the latest diff. Existing code and the earlier `CODEX_REVIEW.md` and `ENHANCEMENTS_TODO.md` were preserved. Findings below distinguish isolated reproductions from source-traced integration defects. No privileged service was installed, no process was suspended, no firewall configuration was applied, and no personal inventory was scanned. Feature proposals are in [FEATURE_DESIGNS.md](FEATURE_DESIGNS.md).

## Findings

### F1 — P1: one additional document write suspends a benign signed editor

Location: [BehavioralThreatDetector.swift](../../Sources/ThreatDetection/BehavioralThreatDetector.swift), lines 150–159 and 185–187.

The detector deduplicates risk contributions using the human-readable reason. The burst reason embeds `uniqueFiles`, so 12 files and 13 files are counted as independent 60-point signals. With default settings, a signed editor in `/Applications` receives score 60/observe at 12 rapid writes and score 100/suspend at 13. `ProcessMonitor.handleThreatVerdict` executes that recommendation with `SIGSTOP`.

**Evidence:** reproduced against the current detector source with synthetic events. The existing signed-editor test stops at exactly its configured threshold and therefore passes.

**Fix:** use stable signal identifiers, keep changing counts as evidence, and require an independent qualifying signal for automatic suspension. Expire window-dependent evidence rather than accumulating its score forever.

**Acceptance:** signed editors remain observe-only at threshold, threshold + 1, and hundreds of writes; the same burst never contributes twice; a separate qualifying ransomware signal can still trigger containment; expired bursts do not contribute to later incidents.

### F2 — P1: installing or refreshing canaries can suspend SeKretSauce itself

Locations: [RansomwareShieldControls.swift](../../gui-apps/app/RansomwareShieldControls.swift), lines 23–42; [BehavioralThreatDetector.swift](../../Sources/ThreatDetection/BehavioralThreatDetector.swift), lines 142–143; [ProcessMonitor.swift](../../Sources/EndpointSecurity/ProcessMonitor.swift), lines 291–312 and 454–463.

The GUI writes canary content atomically into the monitored directory. The monitor evaluates rename destinations, and every mutation under that directory contributes 100 points. The response excludes the daemon's PID and system paths, but not an authorized GUI installation operation. With an active sensor, the application's own setup/refresh operation can be classified as ransomware and suspended.

**Evidence:** a synthetic rename observation using the GUI executable path and its actual canary destination produces `suspend`. End-to-end GUI suspension was deliberately not executed.

**Fix:** move canary lifecycle operations behind authenticated daemon IPC. Authorize a narrowly scoped operation against exact registered files and process identity, with an expiry. Do not exempt any executable merely because its path or name resembles the GUI.

**Acceptance:** install, refresh, and repair complete with an active sensor; unrelated writers still trigger a verdict; expired authorization cannot suppress events. Test deletion too: the detector models `.delete`, but the sensor currently does not subscribe to unlink events.

### F3 — P1: EXEC scoring combines the new executable with the old executable's signing state

Location: [ProcessMonitor.swift](../../Sources/EndpointSecurity/ProcessMonitor.swift), lines 171–203 and 384–398.

`handleExecEvent` takes the executable path from `event.target`, but takes platform/signature state from `message.process`. These represent different execution images. A signed shell launching an unsigned program can cause the new program to inherit the shell's trusted classification; the inverse can inflate a trusted program's risk. This changes containment decisions.

**Evidence:** source trace, verified against the installed Apple SDK's `ESMessage.h` EXEC documentation. Apple identifies `target` as the executed process in its [EXEC event reference](https://developer.apple.com/documentation/endpointsecurity/es_event_exec_t). The SDK further documents that `message.process` describes the image before replacement and that the audit-token pidversion changes.

**Fix:** derive the observation's executable identity, effective user, signing state, and execution identity from `event.target`. Retain the pre-exec identity separately for attribution. Scope detector state to an execution identity rather than PID alone.

**Acceptance:** signed-to-unsigned, unsigned-to-signed, and setuid exec fixtures attribute the target correctly; exec and PID reuse cannot inherit unrelated scores. A live entitled sensor test remains necessary.

### F4 — P1: first-time PF rule creation references a file that does not exist yet

Locations: [PFManager.swift](../../protectx/FirewallKit/Sources/FirewallKit/PF/PFManager.swift), lines 48–55 and 97–119; [ManagedPFConfiguration.swift](../../protectx/FirewallKit/Sources/FirewallKit/PF/ManagedPFConfiguration.swift), lines 15–20.

`addRule` installs and validates the main configuration's `load anchor` reference before `writeAndLoadManagedRules` creates the anchor file. On a clean installation without `/etc/pf.anchors/com.afterdark.protectx`, validation fails and the first rule cannot be added. The installation/build scripts do not bootstrap that file.

**Evidence:** the system's `pfctl -n -f` rejected an isolated temporary configuration referencing a nonexistent temporary anchor, with exit status 1. `-n` was used; no live rules were loaded.

**Fix:** stage a complete, valid configuration graph before activation, including an initial anchor. Preserve both previous disk state and active state for rollback. Merely swapping the two calls is insufficient unless an unattached anchor and partial failures are handled explicitly.

**Acceptance:** first rule succeeds on a clean VM; injected validation/load failures preserve the previous rules and main configuration; unrelated system anchors remain intact.

### F5 — P1: PF refresh and subsequent editing corrupt supported rule semantics

Locations: [PFRule.swift](../../protectx/FirewallKit/Sources/FirewallKit/PF/PFRule.swift), lines 430–445 and 467–479; [PFManager.swift](../../protectx/FirewallKit/Sources/FirewallKit/PF/PFManager.swift), lines 87–94 and 52–54.

The parser reads exactly one token after `port`, defaults unrecognized values to port 0, and ignores flags. It cannot round-trip even its own emitted port-list syntax. Refresh replaces the model with these parsed rules; a later add/remove serializes the corrupted model back into the anchor.

**Evidence:** isolated source reproductions:

```text
pass in proto tcp from any to any port { 80, 443 }
  → pass in proto tcp from any to any port 0

pass in proto tcp from any to any port = 443 flags S/SA keep state
  → pass in proto tcp from any to any port 0 keep state
```

The second fixture exercises operator syntax; the first proves the defect without relying on platform-specific formatting of `pfctl` output.

**Fix:** persist a versioned structured rule document as the editing source of truth. Use kernel output for reconciliation, not lossy reconstruction. Unsupported syntax must return an explicit error, never a fabricated port or default pass rule.

**Acceptance:** all supported address/port/state/flag variants preserve semantics across save, restart, refresh, add, and remove; unknown tokens cannot be silently rewritten.

### F6 — P1: Keychain access failures become a successful empty scan

Location: [keychain.go](../../sekretsauce-cli/pkg/keychain/keychain.go), lines 49–117.

Every `dumpKeychainItems` error is discarded. If `security dump-keychain` fails for every category, `Scan` returns an empty result and a nil error. Users cannot distinguish an unreadable Keychain from an inspected Keychain with no findings.

**Evidence:** a temporary `security` executable that always exits 1 was supplied through the probe process's PATH. The current scanner returned `error=<nil> total_items=0`. No real Keychain was accessed.

**Fix:** propagate unavailable/permission-denied status, preserve category-level partial results, and report which categories were actually inspected. Execute and parse the metadata dump once where possible, rather than invoking the same command five times.

**Acceptance:** all-failed scans return failure; mixed outcomes return explicit partial coverage; a successful empty scan remains distinguishable from an unreadable one.

### F7 — P1: full-scan orchestration hides incomplete results

Locations: [scan.go](../../sekretsauce-cli/cmd/sekretsauce/cmd/scan.go), lines 158–309; [root.go](../../sekretsauce-cli/cmd/sekretsauce/cmd/root.go), `printWarning`; [ViewModel.swift](../../gui-apps/app/ViewModel.swift), lines 197–208 and the three `perform…Scan` methods.

The CLI catches scanner errors, emits warnings that disappear in JSON mode, and returns successful JSON without an error/coverage envelope. Separately, the GUI's individual scan methods catch failures internally; the full-scan method unconditionally finishes with `Scan complete!`. Its children also toggle the shared `isScanning` flag between stages, allowing overlapping work.

**Evidence:** source trace. This is an orchestration defect even after individual scanner errors such as F6 are fixed.

**Fix:** have scanners return typed outcomes; aggregate `completed`, `partial`, `failed`, and `skipped` statuses. Own run lifecycle in one coordinator, preserve errors in JSON, and reject stale responses using a run ID. Show persistent completion/error state outside the progress indicator.

**Acceptance:** missing CLI, failed scanner, cancellation, and malformed JSON never display a clean completion; JSON preserves per-scanner errors; a second run cannot overwrite an active run's results.

### F8 — P2: clean scans can retain findings from the previous target

Location: [ViewModel.swift](../../gui-apps/app/ViewModel.swift), lines 479–499; related conditional assignments in app, hidden-process, and Keychain scans.

The Go result models omit empty arrays with `omitempty`. After a breached account is scanned, a clean account's response omits `compromised`; the GUI leaves the old `breaches` array intact and sets `breachCheckComplete = true`. Breach findings are also appended without clearing the previous run. Similar conditional array replacement retains old app issues and suspicious processes after clean rescans.

**Evidence:** matched producer JSON tags to consumer branches. No external breach lookup was performed.

**Fix:** decode typed result models with absent arrays defaulting to empty and replace the entire result for the requested target. Key findings by run and target; retain previous scans only as explicitly labeled history.

**Acceptance:** affected → clean, affected A → clean B, repeated affected scans, and malformed responses do not retain or duplicate another run's current findings.

### F9 — P2: full-scan totals omit findings and flatten severity

Location: [scan.go](../../sekretsauce-cli/cmd/sekretsauce/cmd/scan.go), lines 166–202 and 282–308.

Keychain weak items never enter the summary. Suspicious launch agents are also omitted: the hidden-scan branch counts only suspicious processes. All application issues are counted as warnings regardless of their individual severity. A result can therefore contain suspicious persistence while reporting zero total findings, or critical application findings while reporting zero critical issues.

**Evidence:** source trace between nested result fields and summary accumulation.

**Fix:** normalize findings once and derive summary totals and recommendations from that collection. Base recommendations on the corresponding finding type; currently any critical issue adds a compromised-account password recommendation.

**Acceptance:** each scanner's findings appear exactly once; severity counts match the displayed findings; a launch-agent-only result has nonzero findings; unrelated critical findings do not generate account-breach advice.

## Feature completeness and enhancements

| Area | Current implementation | Recommended enhancement |
|---|---|---|
| Protection health | Sensor startup failures are logged; daemon can continue without the sensor. Canary UI checks file existence. | Show sensor readiness, entitlement/permission errors, last event, and stale state independently of canary installation. |
| Containment | Sends `SIGSTOP` and writes an audit event; no product resume workflow was found. | Incident record, durable response ledger, identity-checked resume, and recovery after daemon restart. |
| Full scan | GUI runs Keychain, hidden-process, and app scans; CLI also includes secrets, wallets, and CA audit. | Shared scan manifest with selectable scope and explicit skipped reasons. Keep network lookups opt-in. |
| Scan history | Current arrays and summary counts. | Compare successful snapshots, distinguish new/resolved/unobserved findings, and preserve target/scope. |
| Browser export | Password flag is exposed; export implementations do not provide saved-password extraction. | Reject unsupported `--passwords` explicitly or remove the flag until there is a designed implementation. |
| Verbose mode | Flag is declared without meaningful behavior. | Structured diagnostics on stderr with timings, coverage, and redaction; preserve JSON stdout. |
| Firewall UX | Index-based deletion and split status/rule requests. | Stable rule IDs, document revisions, atomic status snapshots, preview, and conflict detection. |
| Long-running operations | CLI and helper subprocess reads have no deadline; XPC awaits a callback indefinitely. | Cancellation, bounded output, operation deadlines, and an explicit unknown outcome followed by reconciliation. |
| SSH recording | PTY output capture exists. Input/output writes ignore partial-write results. | Verify terminal resize, EOF, large paste/output, reconnect, and exit-code fidelity using a local test child. These paths were inspected but not integration-tested here. |
| Network protection | Passive provider always allows flows; coordinator activation throws unavailable; proxy providers are deliberately disabled. | Label availability accurately. Plan outbound enforcement as a separate delivered feature with its own packaging and data-path tests. |

The earlier enhancement roadmap is directionally useful, but its broad incident graph, network enforcement, anomaly detection, and fleet ambitions should not displace the correctness work above. See the companion designs for an incremental sequence with testable outcomes.

## Verification and limits

| Check | Result |
|---|---|
| `go test ./...` in `sekretsauce-cli` | Passed. Keychain, inspector, secrets, and wallet packages have no test files. |
| Root `swift test` | 43 passed. |
| FirewallKit `swift test` | 8 passed. |
| FirewallHelper `swift test` | 4 passed. |
| SeKretSauce GUI `swift build` | Passed; warnings for unhandled `Info.plist` and `build.sh`. |
| ProtectX GUI `swift build` | Passed. |
| Detector simulation | Reproduced F1 and the detector-level trigger for F2. |
| PF parser simulation | Reproduced F5. |
| `pfctl -n` with missing temporary anchor | Exit 1, reproducing the validation prerequisite behind F4. |
| Keychain probe with failing temporary `security` command | Returned nil error and zero items, reproducing F6. |

Probe scripts and temporary inputs were placed in `/tmp/sekretsauce-product-review/`. The Swift probe combines the current detector and PF rule source with synthetic inputs; its output was:

```text
files=12 score=60 action=observe reasons=["rapidly modified 12 user documents"]
files=13 score=100 action=suspend reasons=["rapidly modified 12 user documents", "rapidly modified 13 user documents"]
own canary install: suspend
canonical PF: pass in proto tcp from any to any port 0 keep state
port list before: pass in proto tcp from any to any port { 80, 443 }
port list after: pass in proto tcp from any to any port 0
```

The standalone Swift invocation initially hit a compiler-cache sandbox restriction and then ran with approved cache access. These are detector/parser simulations, not privileged end-to-end tests.

The graph was refreshed and used for review context. It reported no execution flows or architecture communities; graph test-gap counts were not treated as proof that a function is untested. Source traces and actual tests supplied the evidence.

Not verified: live Endpoint Security delivery and containment, signed app/helper registration, actual PF traffic behavior, installer upgrade/uninstall, external breach/certificate services, and VoiceOver interaction. These require separate integration checks; successful builds do not establish them.
