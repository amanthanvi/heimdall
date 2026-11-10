# M03 wave 0: landed interfaces (integrator's index; read the code for exact signatures)

## A1 (contract + domain), landed
Contract:
- `ids`: `EnrollmentId` (`enr`), `CaFingerprint`(+Error), `ConnectionId` (`conn`), `ForeignRemovalId` (`frm`).
- `issuer`: `IssuerRequest`(kind()), `StoreKind` (no test variant), `IssuerState`, `CaState`, `CaStatus`,
  `EnrollmentCounts`, `OrphanStoreItem`, `IssuerStatus`, `RecoveryBundle`, `BundleCa`, `BundleEnrollment`,
  `BundleLateWrite`, `RECOVERY_BUNDLE_SCHEMA`.
- `enrollment`: `EnrollmentState` (20, ALL, is_final, as_str), `EnrollmentForm`, `VerifyMode`, `EnrollmentRequest`
  (kind()), `EnrollmentSpec`, `RemovalTarget`, `ForeignRemovalTarget`, `RegistryRef`, `RegistryCanonical`,
  `RegistryResolvedBy`, `RemoteStage`, `RemoteStep`, `StepPins`, `TargetPins`, `TrustPins`, `AccessPins`,
  `NarrowingPins`, `SshOption`, `ApprovedTarget`, `ApprovedHostKey`, `NoProxy`, `EndpointSource`,
  `ExistingAccessPlan`, `BootstrapPlan`, `VerificationPlan`, `RollbackPlan`, `DisclosureKind`, `EnrollmentPlan`,
  `EnrollmentEvidenceView`, `EnrollmentNext`, `EnrollmentNoteKind`, `EnrollmentNote`, `EnrollmentResult`,
  `RemovalPurpose`, `TargetSummary`, `EnrollmentView`, `EnrollmentsView`.
- `managed`: `LockBehavior`, `ExistingConnectionsMode`, `MultiplexingMode`, `ConnectionPolicy`, `ConnectionRequest`,
  `LockContinuityReport`, `ReadinessCondition`, `RefreshTrigger`, `RefreshCondition`, `LocalRevocation`,
  `RemoteRevocation`, `ClockMeasurement`, `DestinationClock`, `RevocationSemantics`, `EvidenceSource`,
  `EvidenceEntry`, `ConnectionPolicyReport`, `IdentitySelectionEnforcement`, `NewSigningExpiry`,
  `OwnedMultiplexing`, `RemoteProcesses`, `UnmanagedConnections`, `IssuerIsolation`, `ResidualStatus`,
  `RemoteEffectReport`, `ConnectionKind`, `OwnedConnectionReportState`, `OwnedConnectionReport`, `RevokeNote`,
  `ConnectionsRequest`(kind()), `ConnectionState`, `ConnectionEntry`, `ConnectionsView`, `PreferredMechanism`,
  `CredentialLifecycleEvent`, `EnrollmentEventPayload`, `ConnectionEventKind`, `CloseReason`,
  `ConnectionEventPayload`, `SessionLockState`, `SessionLockEventPayload`.
- `request`: `ExistingConnectionsPolicy::NotControlled`; `InspectSubject::{Enrollments, Issuer, Connections}`;
  `EnsureRequest.connection` (NOT yet in the hash: row 9 adds it, only when present, in
  `domain::idempotency::HashInput`); `Enforcement` 6 new `Option` fields + getters reading `unknown` +
  `Enforcement::new(..)`; `EnsureData` 6 new fields + `lock_continuity()`; `RevokeData.{remote_effects,
  owned_connections, notes, requested_at, committed_at}`; `PolicyAction::{SetLockBehavior,
  SetConnectionPolicy}`, `PolicyAction::is_widening()`; `Request::{Issuer, Enrollment, Connections}` (kind,
  admission, required_capability, requires_attended_session(Issuer::Unlock)).
- `catalog::CatalogRequest::SetPreference` (with request_id).
- `event::EventType::{Enrollment, Connection, SessionLock}`.
- `ipc::capability::{ISSUER_V1, ENROLLMENT_V1, MANAGED_CREDENTIALS_V1, CONNECTIONS_V1, M03_DECLARED}` (not offered).
- `envelope::reason::*` constants + `reason::M03: &[(&str, Code)]` (`ALL` unchanged = M02 list);
  `envelope::m03_warning::{…, ALL}`; `doctor::finding::{…, M03}`.
- `schema::public_schemas()` adds enrollment-plan, enrollment-result, issuer-status, recovery-bundle.

Domain:
- `enrollment`: `transition`, `foreign_transition`, `target_change_outcome`, `in_foreign_subset`, `marker_for`,
  `removal_purpose`, `EnrollmentEvent { record: RecordFacts, kind }` (`all()`), `EnrollmentEventKind` (`all()`),
  `RecordFacts::ALL`, `ReverifyFrom`, `InvalidTransition`, `EnrollmentRecord`, `EnrollmentHold`, `HoldReason`,
  `HoldKind`, `ExistingAccessRecord`, `EnrollmentEvidence`, `RemovalOrigin`, `LateWrite`, `PairPreference`,
  `ProjectionStatus`, `ForeignRemovalRecord`, `FOREIGN_SUBSET`, `RawHostKey`, `ProxyRoute`, `Determinism`,
  `TargetEvaluation`, `CatalogView`.
- `verification`: `check`, `VerificationCheck`, `VerifyingOperation`, `VerificationRefusal`, `VerificationPurpose`,
  `VerificationEntry`, `TraceEvents`, `AttemptResult`, `VerificationPhase`, `InconclusiveReason`,
  `VerificationVerdict`, `classify` (wave 0: always inconclusive).
- `connection`: `effective_connection_policy`, `ConnectionEnd`, `dedicated_closes`, `master_closes`, `closes`.
- `managed`: `SlotState`, `SlotEvent`, `SlotRefusal`, `slot_transition`, `OwnedConnection`, `OwnedConnectionState`,
  `LockEpoch` (`observe_lock`, `acknowledge`).
- `procstat`: `parse(impl AsRef<[u8]>)`, `ProcStat { state, process_group, start_time }`, `ProcStatError`.
- `issuance`: `CertificateBounds.ca_fingerprint: Option<CaFingerprint>`, `IssuanceRefusal::{UnknownCa,
  CaNotVerifiedForPair, CaRetiring}`, `CredentialState::Lost`, `IssuanceCheck.enrolled_cas: Option<EnrolledCas>`
  (None = M01 path), `extension_profile`, `EXTENSION_PTY`, `CaEvent`, `ca_transition`, `InvalidCaTransition`.
- `revocation`: `RevocationCause::SessionLocked`, `RemoteObligation.kind: ObligationKind`,
  `residual_step(&obligation, safe_now: Option<Timestamp>)`, `measured_completion_bound`, `RESIDUAL_DRIFT_PPM`.
- `grant`: `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`, `sign_rule`,
  `permits_signing`, `DegradedSignRule`, `GrantOrigin.{lock_behavior, connection}`.
- `policy`: `StandingPolicy.{lock_behavior, connection}`, `strictest_lock_behavior`,
  `strictest_connection_policy`, `merge_lock_and_connection` (app's `merged_policy` must call it, row 11).
- `decision`: 6 new `DecisionKind`s, `is_m03()`, `EnrollmentPlanSummary(from_plan)`, `SystemFormLines`,
  `RemovalTargetRef`, `DisclosureKind`.
- `operation`: `EnrollmentApply/Verify/Remove` (ALL = 15), `ENROLLMENT`, `is_enrollment`, `m03_effect_class`,
  `enrollment_stage::*`, `CancelRefusal`, `enrollment_cancel_allowed`.
- `resource::ResourceKind::{MaterializedFile, Connection}`.
- `claims` (integrator): `Claim`, `Platform`, `VersionRange`, `BuildProfile`, `CLAIMS` (empty), `CUSTODY_FIELDS`,
  `product_store_kinds`, `claims_for`.

Fail-closed arms A1 added (comment `// M03 wave 0 (A1): fail closed until U0b`): runtime/src/dispatch.rs
(Issuer/Enrollment/Connections → driver_unavailable), app/src/catalog.rs (SetPreference refused), app/src/
operations.rs (M03 kinds never driven at restart; new inspect subjects; new policy actions refused; new
decision kinds refused not consumed), app/src/error.rs (CA refusals → CAPABILITY_UNAVAILABLE).
`grep -rn 'M03 wave 0 (A1)' crates tests` lists them.

## B2 (ipc row 1), landed: `heimdall_ipc::signing`
`ReleaseCheck { may_release(), expires_at() -> tokio::time::Instant }`, `PermitGuard(pub Box<dyn ReleaseCheck +
Send + Sync>)`, `SignOutcome { frame, permit: Option<PermitGuard> }` (failure(), signature()), `SigningSession {
peer: PeerIdentity, endpoint: EndpointRef, bind: Option<SessionBindRecord> }`, `Signer { identities(&session),
sign(&session, key_blob, data, flags) -> SignOutcome, session_bind(&self, &mut session, payload) -> bool }`,
`ServeLimits { idle, enqueue_timeout (2 s), outbound_frames (4) }`, `serve`, `serve_with_limits`, `NoIdentities`.

## Integrator readings (escalated in .m03-wave0-questions.md; build to these)
- E4: M01's "not available in this build" text is guarded against in M02 sources (`cli.rs` test
  `w0_m02_commands_answer_not_available...`, `M02_SOURCES`). M03 handlers that answer it live in a NEW module
  not in `M02_SOURCES`; build the text so no M02 source line contains it.
- E6: (a) env-permission removal is covered by the re-validation path; (b) re-validation withdrawals: detect
  read-only, take the gates, then re-run `end_in` under the gates; (c) cutoff narrowing set = active/degraded
  grants of the policy's profile whose bound the cutoff lowers; (d) `SigningGates` lives in `Inner`,
  exposed as `Operations::signing_gates()`.
- E7: `EndpointKind::Issuer` refused by both listener constructors (ipc unix/windows `Listener::bind`).
- E8: separate M03 reason list (done: `reason::M03`); restart helper writes `owner_reconcile` for M03 kinds.
- E9: `process_start_time` keeps accepting process group 0 (uses the parser's start-time without requiring
  the group, or an equivalent), so its semantics are unchanged.
- E10: cancel of an enrollment operation refused in phase 1 (`remote_step_in_progress` only once a receipt
  exists; none can exist; before that, `driver_unavailable`? — use domain `enrollment_cancel_allowed`).
- E12: `Txn::open_enrollments()`; a schema-5 file opened read-only (no table) means none.
- E14: `tests/model/operations.rs:12832` pins exact counts of adapter calls in operations.rs; new managed
  port calls go in `crates/app/src/managed.rs`, never operations.rs.

## A2 (app interfaces), landed
`app::managed`: `SigningGates` (retain/release lifecycle, `admit_shared`, `hold_for_delegation`,
`begin_narrowing` → `Narrowing { mark, earlier_covering, defer_to_earlier, acquire, acquire_all, release_all,
finish }`, `is_pending(_with)`, `sort_global`, `permit(gate, PermitExpiry, Arc<dyn SafeTime>) -> SignPermit`),
`GateOrder`, `GateError`, `Acquired`, `SharedGate`, `DelegationHold`, `SafeTime`, `PermitExpiry`,
`ReleaseRefusal`, `SignPermit { expires_at, may_release(_at), release_refusal_at }`, `drive_preparation`
(fails closed), `driver_results`. `Operations::signing_gates()`.
`app::ports`: `SignatureAuthority { precheck, admit }`, `IssuerPort`, `VerificationRunner`, `VerificationEndpoints`,
`VerificationSession`, `TargetEvaluator`, `ManagedEffects`, `SessionLockSource { state, lock_epoch, acknowledge,
changed }`, `ConnectionControl`; `SignatureRequestFacts`, `SignRefusal` (+code()), `IssuanceRef`, `IssuerRefusal`
(lives in app::ports; issuer crate reuses), `IssuerError`, `IssuerStatusSnapshot`, `ManagedSources`, … ;
`AdapterDescriptor.remote_credential_effect`, `RevokeOutcome.remote_effects`, `IntegrationSnapshot.managed`.
`Limits`: every §5 item 17 limit. `issuance_ro::assess` (refuses, U3), `TimeGate::assess_read_only` (Uncertain, U3).
Tests: `tests/model/signing_gates.rs` (19).
tokio `test-util` is enabled for app and runtime dev-deps (virtual time available in tests).

## Code placement rule for phase 2 (operations.rs is shared by G, O and R)
New `impl Operations` code goes in a child module file `crates/app/src/operations/<name>.rs`, declared with one
`mod <name>;` line in operations.rs (a child module sees the parent's private items). Edit operations.rs only at
the call sites your rows require; re-read right before every edit; never reformat regions you did not change
(`rustfmt` only your own child files; for operations.rs, run `rustfmt --edition 2024 --check` and fix only your hunks).
Managed-port calls (ManagedEffects/IssuerPort/…) never go in operations.rs (E14 source scan).
