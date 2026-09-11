# Feature designs and delivery sequence

These are proposed designs grounded in the current code and [correctness findings](PRODUCT_REVIEW.md), not implemented features or delivery commitments.

## Product direction

Make the first complete user journey: **know what is active → run an understandable scan → inspect evidence → take a reversible action → verify the outcome**. The repository already has useful detectors, inventory modules, audit events, and a privileged firewall boundary. The missing integration contracts are a better first investment than adding more detectors.

Use SeKretSauce as the suite and ProtectX as the firewall experience unless a later branding decision changes that. Present inventory, continuous protection, and firewall management as distinct capabilities with individual readiness states.

## 1. Protection status and guided setup

**User outcome:** a user can tell whether monitoring is running, why it is unavailable, and what action restores it. Installing canary files must not imply that a sensor is active.

**Experience:** show rows for behavioral monitoring, canaries, firewall helper, PF, and optional remote sync. Each row shows `Not installed`, `Needs permission`, `Starting`, `Active`, `Degraded`, or `Unavailable`, a plain-language reason, and the last successful observation time. An active daemon with a failed sensor is degraded. Unavailable or stale information is never converted to an off/false Boolean. Network proxy controls remain unavailable until there is an implemented provider.

**Contract:** introduce an authenticated, read-only daemon status endpoint returning:

```text
AgentHealth {
  schemaVersion, agentVersion, bootID, observedAt,
  components: [{ id, state, reasonCode, lastSuccessAt, details }],
  sensor: { lastEventAt, eventsReceived, eventsDropped, queueDepth },
  canaries: { registeredCount, intactCount, armed }
}
```

The daemon is authoritative for component state. GUI and CLI consume the same snapshot. Readiness and activity are separate: a quiet machine can have a healthy sensor even without a recent event. The GUI marks its cached status stale when transport freshness expires; it does not guess that monitoring stopped.

**Implementation seams:** `ComponentCoordinator`, `ProcessMonitor`, daemon command handling, and `RansomwareShieldControls`. Publish exact startup errors and reconnect state. Build canary registration into this service so setup and detection share one lifecycle.

**Acceptance:** entitlement failure, denied permission, stopped daemon, lost connection, and stale data produce accurate states. A successful diagnostic event confirms receipt without generating a real threat or suspending a process. All status changes have text equivalents and predictable VoiceOver focus.

## 2. Explainable incidents with reversible containment

**User outcome:** a user sees why an application was stopped and can safely resume the same execution after review.

**Experience:** an incident opens with application identity, observed behaviors, time range, coverage gaps, and the action actually completed. Keep detector recommendation separate from response result. Show rule-based risk as a score with reasons, not an uncalibrated probability. A failed signal must display “Could not suspend,” not “Suspended.”

**Model:**

```text
ProcessExecution { bootID, auditToken, pid, pidversion, startTime,
                   executablePath, signingID, teamID, cdhash }
Evidence { id, executionID, kind, observedAt, detectorVersion,
           signalID, attributes, expiresAt }
Incident { id, executionID, evidenceIDs, score, recommendedAction,
           state, firstSeenAt, lastSeenAt }
Response { id, incidentID, requestID, actor, action, executionID,
           requestedAt, completedAt, result, errorCode }
```

Use a private, versioned local store owned by the daemon. Keep raw command lines and secret contents out of incident summaries; redaction occurs before persistence. Store stable evidence identifiers so changing a display count cannot increase risk again. A bounded event queue must expose dropped-event information to the incident and health service.

**Response lifecycle:** `recommended → pending → applied | failed | targetExited`. A resume references an applied suspension and revalidates the same execution. PID mismatch, exit, exec replacement, or stale identity makes the action unavailable. Record requests and results durably, reconcile pending records on restart, and make duplicate request IDs idempotent. Validate the strongest available identity-bound signaling mechanism on supported macOS versions before enabling automatic response; a bare PID check followed by `kill` leaves a race.

**Initial scope:** observe, suspend, and resume. Defer quarantine, kill, fleet commands, and process-tree termination until individual response/recovery is reliable. Do not add automatic network blocking to the incident UI before it exists.

**Acceptance:** deterministic event replay verifies F1–F3 fixes; no benign bulk-edit suspension; authorized canary maintenance is excluded narrowly; malicious writes remain detected; repeated responses are safe; daemon restart, process exit, and PID reuse cannot resume another process. A live test validates actual signal results separately from detector replay.

## 3. Reliable scan center with history and changes

**User outcome:** every scan shows its actual coverage, current findings, and changes since a comparable successful scan.

**Experience:** choose a Quick or Custom scan and see its components before starting. Display running/completed/failed/skipped states per component. Optional domain/account lookups require a target and explicit selection. On completion, show new findings, continuing findings, and resolved findings only where the relevant component succeeded. If Keychain access fails, prior Keychain findings become “not rechecked,” not resolved.

**Contract:**

```text
ScanReport {
  schemaVersion, runID, target, scope, startedAt, finishedAt, status,
  components: [{ scannerID, version, status, coverage,
                 errors, skippedReason, findings }],
  summary
}
Finding { id, scannerID, targetID, category, severity,
          title, evidence, remediation, observedAt }
```

Always encode arrays, including empty arrays. Strictly decode supported schema versions; allow additive fields. stdout contains the report only; stderr carries redacted diagnostics. Define exit codes for complete, incomplete/failed, and invalid invocation, with optional fail-on-finding behavior documented separately. A security finding is not itself a scanner crash.

**Orchestration:** one run coordinator owns progress and cancellation. Scanner errors are values retained in the report. The GUI invokes the same manifest as the CLI, rejecting late responses with an old run ID. Snapshot replacement is atomic. Derive counts and recommendations from normalized findings, not separate counter branches.

**History:** use stable finding identity from scanner rule, target, and normalized resource identity. Scope and detector version are part of comparison eligibility. Persist local metadata with a user-controlled retention limit. Export sanitized reports through the private-output path; do not include browser history or secret values by default.

**Acceptance:** fixtures cover clean, affected, partial, failed, cancelled, and incompatible-schema results. Producer JSON is decoded by GUI tests. Affected A → clean B does not retain A. Denied access never resolves old findings. All summary counts equal the normalized list. Quick scan coverage is identical between GUI and CLI.

## 4. Transactional firewall editor with preview and recovery

**User outcome:** adding or removing a rule changes precisely the requested policy, and failed changes leave a recoverable state.

**Experience:** show a draft and a plain-language diff with direction, protocol, address, and port. Use stable IDs for selection and deletion. Surface conflicts if another client edited the policy. For changes that may cut off connectivity, offer an explicit timed trial with confirmation and rollback; keep that transaction in the helper so closing the GUI cannot lose recovery state.

**Contract:**

```text
FirewallSnapshot { schemaVersion, revision, observedAt,
                   desiredRules, activeState, errors }
ApplyRulesRequest { requestID, expectedRevision, proposedRules,
                    trialExpiry? }
ApplyRulesResult { requestID, revision, status, validationErrors,
                   reconciliationRequired }
```

**Authority:** the privileged helper owns a canonical structured policy and serializes mutations across all XPC clients. One snapshot includes both status and rules. A revision mismatch refuses stale edits. Treat externally observed rules as unmanaged/drift until reconciled; never silently turn unsupported PF tokens into editable model defaults.

**Transaction:** validate the model; stage all referenced files, including the first anchor; validate the complete configuration; record previous state; apply using the dedicated anchor; read back and reconcile; then publish the committed revision. On failure, attempt rollback and report whether restoration succeeded. Persist a transaction journal so restart can distinguish committed, failed, and unknown outcomes. Test crash points around both disk replacement and kernel loading.

**Boundaries:** a dedicated PF anchor does not imply per-application outbound enforcement. Keep Application Firewall controls labeled by their actual supported behavior. Preserve unrelated system configuration and assess anchor ordering on supported macOS versions with traffic tests.

**Acceptance:** clean-machine first rule; all supported syntax round trips; two simultaneous clients with stale revisions; helper restart during apply; load and rollback failure; GUI disconnect during timed trial; IPv4/IPv6 traffic behavior; unchanged unrelated anchors.

## Delivery order

| Sequence | Deliverable | Exit criteria |
|---|---|---|
| 1 | Correctness repairs F1–F9 | Reproductions become regression tests; existing checks pass; no silent clean results or lossy PF edits. |
| 2 | Shared scan contract and run coordinator | CLI/GUI contract fixtures pass; coverage and cancellation are explicit. |
| 3 | Health service and canary lifecycle | Real sensor readiness and authorized maintenance verified on a signed installation. |
| 4 | Incident persistence and response recovery | Replay evaluation plus live identity/restart tests pass before expanding containment. |
| 5 | Firewall transactions and preview | Clean-install, concurrency, crash recovery, and traffic tests pass. |
| 6 | Scan history and persistence-change view | Comparable snapshots distinguish new, resolved, and unobserved findings. |

Do not assign calendar estimates until distribution/signing capability, target macOS versions, and the test-machine matrix are known. Fleet management, baseline anomaly detection, and outbound Network Extension enforcement should each receive a separate design once these local workflows are dependable.
