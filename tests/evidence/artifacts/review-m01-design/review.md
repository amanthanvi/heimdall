# M01-T00-design-review

Commit: `f5616784992770b84bd96a342f23ac8e1b3299c4`

**Verdict: proceed after fixes.** 1 blocker, 8 major, 1 minor.

This is an independent static architecture/public-contract review. Expected todo bodies are not defects by themselves. Findings identify contradictory semantics, missing shared interfaces, or required evidence paths that the proposed unit contracts cannot supply. No implementation was changed.

## Findings

### F01 — blocker: docs/architecture/overview.md §5; crates/domain/src/time.rs:19,109; crates/runtime/src/supervisor.rs:47; docs/architecture/m01-plan.md U3

The proposed time contract can extend authority after downtime/rollback. Clock.monotonic is process-relative Instant elapsed; TimeAnchor has process_generation but no boot ID or per-grant continuous budget, and there is no persisted accepted-time high-water mark or synchronized-time assessment. Example: stop at 10:00, deadline 11:00, restart at real 12:00 with wall 10:01: the prior wall anchor is not violated and a new process cannot compare monotonic readings. The baseline can accept expired authority. It also says forward jumps are Safe, contradicting ADR-0005. The supervisor flag is private to Supervisor and is not shared with Operations/adapters, so its planned issuance gate is not represented in their inputs.

**Evidence:** Spec §6.4: "Sleep stops local execution; it does not suspend the deadline" and "stop issuance when the authority cannot establish safe time". Plan §6.3: "restart cannot reset the clock". ADR-0005 §3.6: "It never rebuilds a budget from the current wall clock"; after reboot both high-water and synchronized time are required; implausible forward skew is uncertain. ADR-0005 §12 explicitly assigns this time rule to M01-T02.

**Fix:** Revise Clock, per-grant anchors, store APIs, startup and shared time gate before implementation: boot-scoped continuous time including sleep, a budget that only shortens, persisted high-water, reboot synchronization/attended confirmation, and fail-closed checks before admission/signature/issuance. Replace U3 forward-jump expectations with ADR-consistent cases, including above-high-water rollback after downtime, same-boot restart, reboot without sync, and wake. Native clock-source proof remains platform-specific.

### F02 — major: docs/decisions/0006-public-contract-baseline.md §7.3–7.4; crates/domain/src/idempotency.rs:98; crates/store/src/lib.rs:209; crates/store/migrations/0001_init.sql idempotency

Expired request keys become indistinguishable from new keys after the specified purge. classify(None, ...) returns New; purge deletes idempotency rows (also ON DELETE CASCADE from operations), while RequestId is an opaque caller token with no epoch/age. Thus an old retry creates new work instead of the promised REQUEST_EXPIRED. expires_at is mandatory at insertion, but retention is specified relative to terminal completion with no renewal/update API for a long-pending operation.

**Evidence:** Spec §11.4: "retention is documented and a too-old key cannot silently claim deduplication". ADR-0006 §7.3: "Record past expires_at → REQUEST_EXPIRED, never silently new"; §7.4 promises retries after configured retention are REQUEST_EXPIRED. Plan §6.3 requires retry convergence.

**Fix:** Define an implementable stale-key protocol: retain compact expired-key markers or reject expired server-issued request epochs, even after result/history purge. Start retention at terminal completion, keep pending keys live, and add purge/restart/retry and long-pending tests. Coordinate schema and store signature changes before U4/U5 split.

### F03 — major: docs/decisions/0006-public-contract-baseline.md §13.1(1); crates/contract/src/request.rs:470; crates/app/src/operations.rs:214; crates/domain/src/principal.rs; crates/app/src/ports.rs DecisionChannel

The attended-confirmation ruling has no application-boundary representation or complete decision path. PolicyAction Resume/ClearCutoff carries no interaction context; Operations::policy receives only principal/role and action. Every local caller is Owner. DecisionChannel can only register a delta and returns a string; there is no approve/deny completion API or durable decision contract. A CLI-only confirmation would leave API widening unguarded; refusing all API widening leaves the attended CLI unable to perform it through the same operations.

**Evidence:** ADR-0006 §13.1: widening actions and approval "require an attended interactive confirmation" and are refused "on every non-interactive API path". Spec §13.2 says same-user credentials identify a principal, not a friendly application; R-SE-02: "approval claims do not establish authorization". Spec §11.3: a separately authorized UI can present the decision and observe the same operation. A29 attempts false approval.

**Fix:** Define the owner-present confirmation flow through the shared application layer, including durable decision identity, exact delta/generation, consume-once completion and stale-decision refusal. Carry server-established attended context or a specified owner-channel interaction, with the same-user terminal imitation limitation disclosed. Test API widening denial and CLI/TUI confirmation for both policy actions and approval; do not treat an agent-supplied interactive boolean as proof of confirmation.

### F04 — major: crates/store/src/lib.rs Txn; crates/domain/src/grant.rs:63; docs/architecture/m01-plan.md U4/U5/U8

The store port cannot support the planned operations as-is. Bindings exist in SQL but have no domain record or Txn insert/read/release methods. GrantReference has no caller ownership or released state. There are tables but no APIs to read/write profile snapshots or environment records, discover applicable policies from profile/environment, or read tombstones/ancestor denial. OperationsConfig supplies neither those records nor an alternative repository. U5 cannot resolve EnsureRequest, return/persist pinned bindings, authorize release/delegate by binding, or reconstruct state through the private SQLite connection without changing shared interfaces.

**Evidence:** Spec §13.3: "Persist operations, policy revisions, grant deadlines, resource generations ... and revocation tombstones". Spec §6.3: "Reference counts are ownership-aware". Plan §4.2 requires loading policy/profile/parent before preparation; plan §4.3 requires immutable snapshots. M01 plan says "No unit changes a signature" and U4/U5 consume skeleton methods.

**Fix:** Complete the minimal binding/ownership/snapshot and policy/environment/tombstone lookup contract before parallel implementation. Specify repeat-release behavior and pinned profile revision storage. Add a cross-crate fixture that resolves ensure, binds, delegates, restarts, and releases through public store APIs, including foreign-principal binding denial. Update ownership packets so U4/U5 do not invent separate persistence paths.

### F05 — major: crates/domain/src/operation.rs:76,87; crates/app/src/ensure.rs; docs/architecture/m01-plan.md U5/U8

Recovery stores a request hash and last_stage but not the recoverable original request, resolved authority/profile snapshot, operation-to-grant association or prepared credential handle. Hashes cannot reconstruct parameters. A crash after Coalesce or adapter completion cannot resume the same ensure intent or determine whether prepare happened merely from the completed-stage string. The adapter has no inspect/reconcile method to resolve an uncertain preparation. Replaying prepare blindly, or always failing the operation, does not meet the advertised resumable/one-effect tests.

**Evidence:** Plan §4.2: "The pipeline must be interruptible/recoverable between each stage". Plan §4.3: "journal intent, perform the scoped action, record outcome, and reconcile ambiguity". Spec §11.4: retries retrieve the same result, arbitrary remote mutations are not automatically replayable. A06 requires one logical effect across caller/service death. U5 requires retry resumes without a second prepare.

**Fix:** Define durable, redacted recovery intent and stage receipts before the effect, including resolved deadline/snapshot and stable adapter identity. Provide a scoped reconciliation/query port or specify which adapter effects are truly replay-safe and how unknown outcomes stay unknown. Test crashes before effect, after effect but before receipt, and after receipt; never use the hash or a stage marker as an effect receipt.

### F06 — major: docs/architecture/overview.md §3/§6; crates/ipc/src/endpoint.rs EndpointKind; crates/domain/src; crates/store/migrations/0001_init.sql; docs/architecture/m01-plan.md U4/U7

ADR-0005 issuance substrate is absent from the M01 baseline: EndpointKind has only Control/Signing; no credential-instance/issuance-log model, reserved/published/voided states, or transactional reserve/publish store methods exist. Generic resources and prepare(grant) do not encode a reservation with certificate bounds or the publish-generation recheck. The documentation defers the issuer endpoint to M03 even though ADR-0005 explicitly assigns its boundary and model to M01. Consequently A07 model tests only exercise slow prepare, not reserve/sign/publish/delivery races or conservative residual accounting.

**Evidence:** ADR-0005 §12: "M01 must provide a third local interface for issuance" and an issuance log with "reserved/published/voided states, sharing a transactional store with grants and tombstones". §3.5: "only then release the certificate" after publication, and reserved entries stay counted after crash. Spec §6.7 requires truthful maximum residual validity; plan G09 requires expiry during prepare/issue/bind.

**Fix:** Add the issuer-purpose boundary and pure issuance/credential records plus transactional reserve/publish/void and residual queries to the baseline; actual cryptographic issuer implementation can remain M03. Add model interleavings for revoke/cutoff/time uncertainty/deadline passage at reserve, sign, publish and delivery, including lost delivery and reserved-at-crash counted but never republished.

### F07 — major: crates/contract/src/state.rs:30; crates/domain/src/lifecycle.rs operation_transition; crates/store/src/lib.rs:203,209

OutcomeUnknown is simultaneously terminal and transitionable. is_terminal returns true and says no further transition without new operation, but operation_transition reconciles that same operation to Succeeded/Failed. open_operations promises only nonterminal operations, so restart recovery omits exactly the uncertain mutations that need reconciliation; terminal retention also makes them purge candidates. This is a public semantic disagreement, independent of todo bodies.

**Evidence:** Spec §11.4 separates "outcome_unknown" from failure and prohibits blind replay. Plan §6.3: "uncertain effects are not represented as not-applied"; §6.4 requires recovery after lost acknowledgment. ADR-0006 §4.1 allows ReconciledApplied/ReconciledNotApplied transitions.

**Fix:** Distinguish quiescent/wait-complete from settled/final states, and explicitly include unresolved outcomes in restart reconciliation and safe retention rules. Keep their authority/effect receipts until resolved or an explicit conservative recovery decision. Test restart of an uncertain operation and verify no blind replay or history purge destroys its reconciliation evidence.

### F08 — major: crates/app/src/events.rs:84,103; crates/ipc/src/session.rs:139,163; crates/contract/src/ipc.rs Subscribe/Subscribed

The event contract omits the replay-to-live and snapshot handoff needed for its resumption promise. Dispatcher::subscribe returns only a cursor and live broadcast receiver, with no snapshot or durable backlog representation; ControlClient exposes only request, so U9 follow/unsubscribe cannot use it without adding signatures. EventPublisher persists and broadcasts one Event including one cursor, whereas cursors are reader-scoped; no layer is assigned cursor personalization. There is no specified atomic snapshot/read-head boundary, so separately taking snapshot and head can skip intervening changes.

**Evidence:** Spec §11.5: "A snapshot includes its cursor boundary so a reconnecting observer can resume without silently missing state" and delivery is at least once. ADR-0006 §8 requires reader-scoped cursors, durable resume and fresh snapshot for no-cursor observation. U9 requires NDJSON follow/resume through ControlClient.

**Fix:** Define a bounded subscription result/stream supporting a transactionally consistent snapshot or durable replay boundary followed by live delivery, with overlap deduplicated and lag requiring resync. Assign reader cursor construction at delivery (store neutral sequence IDs), and add client subscribe/next/unsubscribe APIs. Test a mutation during snapshot, publish during replay-to-live, two readers receiving the same event with usable scoped cursors, and disconnect/reconnect with retained backlog.

### F09 — major: docs/architecture/m01-plan.md U1–U10; Cargo.toml; crates/app/src/operations.rs:52; crates/app/src/ensure.rs:97

The planned acceptance tests are not yet executable through the claimed frozen surfaces. The root is a virtual workspace and metadata lists only the eight bin/lib targets: files under root tests/model, tests/contracts, tests/integration or tests/e2e will not run merely by adding tests/model/mod.rs. No unit owns Cargo test-target wiring. StageHook is declared but OperationsConfig/start/ensure has no injection point, so U5 cannot inject its required pipeline faults through production code without shared changes. U3 currently mandates the wrong forward-jump rule and U10 omits the stronger ADR-0005 time/issuance traces.

**Evidence:** Plan §6.3 requires bounded exploration/randomized traces with reproducible seeds; §6.4 requires interruption before/after each durable write, external mutation, verification and activation. Plan §5 M01 requires model/local variants A06/A07/A08/A19/A29. M01 plan forbids unit signature changes and claims existing hooks suffice.

**Fix:** Assign an integrator-owned Cargo harness (or place tests under actual crate tests targets), dependencies/features and production hook injection before parallel work. List discoverable target/test names and run them in check.sh. Add the missing time, issuance, stale cleanup at the actual deletion boundary, retained-key expiry and confirmation cases; explicitly track A17 local coverage. Verify test discovery rather than treating a zero-test harness as a pass.

### F10 — minor: crates/ipc/src/session.rs:61–70

Hello required capabilities are checked against the server offer, but not against the negotiated intersection. A hello can require events/1 while omitting it from capabilities and still succeed with events/1 absent from ServerHello.capabilities. The resulting required-capability guarantee is ambiguous.

**Evidence:** Spec §11.2 requires explicit rejection of unsupported required capabilities. ADR-0006 §2.3 calls ServerHello.capabilities the intersection and rejects missing required capability.

**Fix:** Require required to be a subset of negotiated capabilities (or explicitly normalize required into the client offer) and add an inconsistent-hello fixture.

## Checked and limits

- Reviewed HEAD f5616784992770b84bd96a342f23ac8e1b3299c4; initial tracked status was clean. Reviewed architecture/plan/dependency documents, ADR-0006 including section 13.1, accepted Rust/Ratatui and delegated decisions, and ADR-0005 relevant rules against the requested spec/plan sections.
- All 14 stable codes listed by spec 11.6 are represented; code spelling, retryability, effect defaults and next actions are total. Exit classes 0 through 7 exist; Accepted sync override and OutcomeUnknown nonretryable/unknown effect have passing tests.
- Envelope carries version, state, code, operation reference, warnings and next; errors include effect/retry/resource/next. Caller timeout is not a transition; explicit cancel records possible external effect. Final grant states are absorbing in the executable table, with expiry/revocation tests passing.
- Hash input includes resolved environment, profile reference/explicit revision, requested scope, verbatim deadline intent, work ID, minimum capabilities, parent and kind extras. Principal+role+kind+request ID namespace prevents direct cross-owner collisions; canonical JSON sorts object keys and kind/domain separates SHA-256. Replay must use the original pinned snapshot (see recovery finding).
- IPC design specifies owner-only directories/sockets, peer uid/SID validation, separate control/signing protocols, bounded length-before-allocation frames, negotiation, connection/request/subscriber bounds, exact agent allow-list, Windows first-instance protection, remote rejection and identification-only client SQOS. These are design provisions, not native implementation evidence.
- Store design separates secret references from material, specifies WAL/FULL/foreign keys, newer-schema refusal, integrity checking and transactional backed-up migrations. Windows backup/rename/share-mode and ACL behavior remains unverified and needs native store tests, including WAL-consistent backup; no existing native persistence result is claimed.
- Current-thread Tokio with blocking work offloaded and bounded operation/adapter queues is a coherent choice. Declared limits support bounded work; actual queue admission, blocking-pool cap, sign concurrency and idle CPU/RSS are not implemented or measured.
- Cargo.lock and exact direct pins are present. Offline locked metadata resolves 185 packages with license expressions matching the dependency ledger and permissive alternatives for the r-efi LGPL OR expression. Ratatui choice matches ADR-0002/0004; own project license is explicitly pending. No dependency vulnerability, source-license or packaging audit was performed.
- bash tools/validation/check.sh completed with fmt=0, clippy=0, test=0, overall=0; 43 unit tests passed and all doc-test groups had zero tests. Generated-schema diff is currently commented out, planned for U1. This pass does not execute the planned M01 model/native workflows.

## Commands and observed validation

- Read-only inspection: `pwd`, `rg`/`rg --files`, `cat`, `sed`, targeted Python reads, `git rev-parse HEAD`, `git status --short`.
- Memory registry query for Heimdall returned no relevant entries; no historical project facts were used.
- `bash tools/validation/check.sh`: exit **0**. Observed step output:

```text
== fmt: exit 0
== clippy: exit 0
== test: exit 0
== overall: exit 0
```

- Unit test counts: binary 2, app 4, contract 16, domain 9, ipc 6, runtime 3, store 1, testkit 2; total 43, no failures. Doc-test groups: zero tests.
- `cargo metadata --offline --locked --format-version 1` with a JSON field filter: exit 0; 185 resolved packages, only bin/lib workspace targets.
- Required build-size inspection `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist`: zsh initially rejected an unmatched glob; bash retry found no prototype target directory (du exit 1), existing TS node_modules 99M, Go dist 20M, Rust dist 3.4M. No prototype cleanup threshold was triggered. No new build directories or fixture files were created; Cargo used ./target.
- Review artifact JSON parsed and exact top-level/per-finding schema fields and counts checked after writing.

## Write scope and concurrency

Created only `tests/evidence/artifacts/review-m01-design/review.json` and `review.md`. No tracked file edited, no commit/push. Cargo updated only ordinary root target build outputs. Concurrent changes to `progress.md`, `schemas/examples/` and `tests/contracts/` appeared after the initial clean status; they were not touched by this review. The reviewed skeleton and design findings are against the pinned commit; newly appearing test fixtures were not used as evidence.

Native Windows/WSL/macOS secure-store, lock, sleep/reboot, cross-user and file semantics were not exercised. Passing skeleton checks do not establish those claims or close G08/G09.
