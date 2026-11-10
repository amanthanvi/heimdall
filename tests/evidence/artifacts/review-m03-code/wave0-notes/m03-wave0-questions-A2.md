# M03 wave 0 — questions and readings from A2 (app interfaces, signing gates)

Each item: the question, the options, the evidence, and the fail-closed reading A2 built.

## A2-Q1. `tokio::time::pause` is not available to app (or runtime) tests
- Evidence: `Cargo.toml:64` (workspace tokio features: rt, net, io-util, time, sync, macros, signal,
  process); only `crates/ipc/Cargo.toml:37` adds `test-util` (a dev-dependency, so it is not unified
  into `cargo test -p heimdall-app` or `-p heimdall-runtime`). `start_paused` is used only in ipc
  tests.
- Impact: row 24's tests were written without virtual time (single polls, guard drops, explicit clock
  readings, 1 ms timeouts whose outcome cannot depend on timing). G's row 20 tests (bounds such as
  `H + R(N)`, `narrowing_commit_target_20s_at_budgets`, the countermodels) need virtual time; they are
  hosted by `heimdall-runtime` (`model_narrowing_m03`), whose dev-dependencies also lack it.
- Options: (a) add `tokio = { workspace = true, features = ["test-util"] }` to `[dev-dependencies]` of
  `heimdall-runtime` (and `heimdall-app` if wanted); no new crate, `Cargo.lock` unchanged; (b) keep
  virtual time out and inject an explicit clock into the narrowing protocol.
- A2 did not edit any manifest. Recommendation: (a), integrator-owned.

## A2-Q2. `issuance_ro::assess` fail-closed verdict in wave 0
- The issuer refusal set is frozen as the `IssuanceRefusal` and `VerificationRefusal` sets plus
  `entry_not_reserved`, `entry_stale`, `subject_mismatch`, `ceiling_exceeded`, `ca_not_loaded`,
  `rate_limited` (m03-plan §5 item 20). There is no "unavailable" refusal.
- Reading built: wave 0 answers `Ok(Err(IssuerRefusal::EntryNotReserved))` (no reservation is confirmed,
  nothing is signed). Alternative: add `IssuerRefusal::Unavailable` (a change to the frozen set).
- Signature built: `assess(txn: &mut Txn, entry: &IssuanceRef, subject: &str, now: &TimeAnchor,
  time: &TimeStatus) -> heimdall_store::Result<Result<CertificateBounds, IssuerRefusal>>` (the
  `TxnGate::check` pattern). U3 may want `now` folded into `time`.

## A2-Q3. `TimeGate::assess_read_only` is a method
- Plan text: `TimeGate::assess_read_only(&Store) -> TimeStatus` (m03-plan U3 l.731). The gate needs its
  clock, sync source and policy, so it is built as `pub fn assess_read_only(&self, store: &Store) ->
  TimeStatus` (synchronous; blocking pool). Wave 0 answers `Uncertain(Unsynchronized { sync: Unknown })`.
- The release check needs a non-blocking reading (`ipc::signing::ReleaseCheck::may_release` "must not
  block"), so `SignPermit` takes an injected `SafeTime` (in-memory) rather than this store read; who
  keeps that reading current is U2/G's design.

## A2-Q4. Shapes the plan names but does not define (readings built; frozen once wave 0 lands)
- `SignatureRequestFacts { endpoint: SignerEndpoint, subject: SignatureSubject, pair: AccessPair,
  key_fingerprint: String }`; `SignRefusal` (13 variants, `code()` for the audit event).
- `IssuerStatusSnapshot { status: contract::issuer::IssuerStatus }`.
- `VerificationOutcome { positive: AttemptResult, negative: AttemptResult, client: Option<String> }`.
- `KeyRegistration { public_key, fingerprint, slot }`, `MaterializeSpec`, `MaterializedFiles`,
  `ManagedSlot`, `PreparedCertificate`, `ManagedPrepared`, `ManagedSources`.
- `ConnError { RegistrationRefused(String), Unverified, Unavailable(String), Timeout, Failed(String) }`.
- `LockState` = `contract::managed::SessionLockState` (re-export); `RevokeOutcome.remote_effects:
  Vec<contract::managed::RemoteEffectReport>` (the plan's `RemoteEffect`).
- `IssuerRefusal` lives in `app::ports` (the port's error carries it and app cannot name the issuer
  crate); serde is externally tagged, snake_case; U3's golden fixes the wire form.

## A2-Q5. Limits split into fields where the plan gives a compound value
- `enrollment_step_timeout` 120 s and `enrollment_step_timeout_interactive` 300 s;
  `enrollment_not_after_allowance` 60 s and `enrollment_hard_deadline_margin` 30 s, with methods
  `Limits::enrollment_not_after(interactive)` (timeout + 60 s) and
  `Limits::enrollment_step_hard_deadline(interactive)` (timeout + 60 s + 30 s);
  `verification_skew_lag` 60 s and `verification_skew_lead` 300 s; `remote_stderr_max` 64 KiB and
  `remote_stderr_excerpt` 4 KiB.

## A2-Q6. The delegation hold's wait
- D2 item 3a bounds the hold (`delegation_gate_hold_max`) but names no bound for *acquiring* the chain.
  `SigningGates::hold_for_delegation(parent, ancestors, wait)` takes the bound from its caller (one
  deadline for the whole chain). Suggested: `signing_gate_wait`. The hold-time bound is the caller's
  (`DelegationHold::held_for`).

## A2-Q7. Grants without a gate in a narrowing set
- A gate exists only while the grant has a credential instance. `Narrowing::acquire` answers
  `Acquired::NoGate` for a grant without one (nothing can sign with it), and `sort_global` omits such
  grants. Pending marks are independent of gates (a mark on any grant ID covers every gated
  descendant through the chain recorded at gate creation).
