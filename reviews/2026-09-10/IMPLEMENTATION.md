# Implementation progress

Work started from `53fc81e`. The review and designs remain historical specifications;
this document distinguishes implemented behavior from outstanding acceptance work.

## Delivered

- F1: stable detector signals prevent changing document counts from adding risk
  repeatedly; burst evidence expires and process execution versions reset state.
- F2: canary setup runs inside the daemon; only the daemon PID bypasses mutation
  evaluation. Fixed paths, no-follow descriptors, private modes, and content checks
  protect setup and readiness reporting.
- F3: EXEC metadata comes from the target process, including its signing state and
  audit-token execution version.
- F4/F5: first-install validation stages a real anchor; strict PF parsing handles
  numeric ports, lists, ranges and supported flags without inventing defaults.
- F6/F7: Keychain dump failures propagate. Full scans retain component errors and
  return incomplete reports; GUI failures, invalid JSON, and timeouts remain visible.
- F8/F9: GUI arrays replace previous snapshots, and normalized findings drive
  counts, severity, and remediation rather than independent summary branches.
- Quick/full CLI and GUI scans share schema version 1, component coverage, stable
  finding IDs, and a producer/consumer fixture. GUI runs are exclusive and cancellable.
- Same-team authenticated XPC health and canary installation; daemon status CLI;
  sensor startup errors and received/dropped event counts in the GUI.
- Bounded private incident persistence, recommendation/result separation, execution
  identity including boot and audit token, task-bound suspend/resume, owner checks,
  duplicate-response handling, and interrupted-state reconciliation after restart.
  Automatic containment is gated off by default pending live validation.
- Canonical firewall policy with stable IDs, expected revisions, draft preview,
  staged validation, serialized writes, drift refusal, rollback journal, and startup
  recovery. Policy changes load the owned anchor after initial registration.
- Private scan history with 20-report retention and per-scanner successful baselines;
  unavailable or changed-version coverage produces “not rechecked,” never resolved.

## Validation

Regression suites cover detector bursts/expiry/PID reuse; canary ownership and
symlinks; incident ownership, duplicate requests, denied responses, deployment gate,
and restart; Go summary/error contracts; the Go-produced report decoded by Swift;
stale GUI arrays, cancellation, malformed reports and process timeout; private
history and failed-scanner comparisons; PF round trips, clean first install, stale
revisions, external drift, rollback and failed-rollback startup recovery.

Final verification on 2026-09-10:

| Check | Result |
|---|---|
| Root `swift test` | 51 passed |
| Main GUI `swift test` | 8 passed |
| FirewallKit `swift test` | 13 passed |
| FirewallHelper `swift test` | 4 passed |
| ProtectX GUI `swift build` | Passed |
| CLI `go test ./...` | All packages passed |
| `git diff --check` | Passed |

No test modifies the host PF configuration, suspends a real target, or scans user
credentials; privileged operations use fake runners/controllers and temporary paths.

## Remaining design work

- Signed, entitled macOS end-to-end validation: XPC identity rejection, Full Disk
  Access failures, sensor events, task access/exit/exec/restart, and actual PF traffic.
  Unit tests and package builds do not establish these outcomes.
- Full health contract (version/boot metadata, per-component observation times,
  queue depth and diagnostic event), guided setup, and unified firewall health.
- Structured incident evidence/response records, asynchronous bounded event queue,
  request IDs across clients, and richer response reconciliation. Current store
  supports at most 500 incidents and refuses new containment if all slots are active.
- Custom scan selection, live per-component progress, cancellation propagated into
  all Go scanners and descendants, cancelled report persistence, sanitized report
  export, history browsing and user-configurable retention. Single-scanner command
  formats remain legacy; nested scanners may still have incomplete coverage reporting.
- Firewall timed trial/confirmation surviving GUI disconnect, desired-versus-active
  kernel reconciliation, complete crash-point testing, and traffic/anchor-order
  acceptance checks. First registration loads pf.conf and needs system integration
  validation; subsequent policy edits use the dedicated anchor.

These are still open roadmap items; this implementation does not claim the entire
feature design or production acceptance is complete.
