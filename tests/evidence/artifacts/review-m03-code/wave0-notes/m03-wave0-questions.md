# M03 wave 0: escalation index

Wave 0 of M03 (U0 together with U0b phase 1) was built by parallel agents. Whenever the plan
(`docs/architecture/m03-plan.md` revision 6) and ADR-0008 (revision 6) conflicted, or a shape was not
fixed, the agent that hit it wrote the question to its own file (`.m03-wave0-questions-<agent>.md`),
took the most fail-closed reading and continued. This file merges all thirteen files (A1, A2, B2, C, D,
G, N, O, R, S, T, V, X): the index below is the working list, and the full text of each file follows
verbatim (a snapshot; the per-agent files stay in place). Statuses: **ruled** (the orchestrator decided),
**resolved by integrator** (fixed in the code or tools at wave 0), **open** (the reading taken stands
until confirmed; the contract-relevant ones are recorded in ADR-0006 §16.2). ADR-0006 revision 4 §16.3
records the three rulings. A row naming several IDs merges true duplicates.

## Index

Orchestrator rulings of 2026-11-08 are recorded in ADR-0008 §17.15 (items 1–11). Rows still `open` carry the reading taken as a provisional default; each later unit's brief lists the open rows in its scope, to confirm or escalate (§17.15 item 11).

| ID | Question (one line) | Reading taken / ruling | Status |
|---|---|---|---|
| A1-Q1 | `Enforcement` and `EnsureData` new fields: bare `T` (plan) or `Option<T>`? | Accepted (§17.15 item 8) | ruled |
| A1-Q2 | Shape of `IssuanceCheck.enrolled_cas` (U0b row 2 writes `&[String]`) | Accepted (§17.15 item 8) | ruled |
| A1-Q3 | Type of `CertificateBounds.ca_fingerprint` (`Option<String>` or `Option<CaFingerprint>`) | `Option<CaFingerprint>`, same wire string | open: provisional default (§17.15 item 11) |
| A1-Q4 | Two ID types outside §5 item 1 | `ConnectionId` (`conn`) and `ForeignRemovalId` (`frm`) | open: provisional default (§17.15 item 11) |
| A1-Q5, X-Q7 | Does `Connections::Register` carry `image` (plan item 4a omits it, ADR-0008 D8 and U0b row 26 have it)? | Included, required; only the plan text needs fixing | open: provisional default (§17.15 item 11) |
| A1-Q6, V-E8 | Where M03 reasons live; `owner_reconcile` cannot reuse `local_driver_unavailable` | `reason::M03`, `m03_warning::ALL`, `doctor::finding::M03` beside the unchanged M02 lists; restart helper writes `owner_reconcile` (integrator reading) | open: provisional default (§17.15 item 11) |
| A1-Q7 | `SetPreference` carries `request_id`; domain `CatalogAction` | `request_id` included; A1 refused it fail-closed, O implemented it (O-Q11) | open: provisional default (§17.15 item 11) |
| A1-Q8 | `residual_step` clock input, measurement freshness, drift | `safe_now: Option<Timestamp>`; stale measurement recorded `unmeasured` by the builder; drift `ceil(age_ms * 100 / 10^6)` ms | open: provisional default (§17.15 item 11) |
| A1-Q9 | Enrollment transition-table choices where ADR-0008 D5 §6.2 is silent | Listed in the A1 file (form and subset checks, manual-recovery events, self-transitions) | open: provisional default (§17.15 item 11) |
| A1-Q10 | Enrollment cancel rule and stage names | Refused once a non-`NotAttempted` receipt exists for append, rollback or remove; bootstrap does not block; stage names chosen | open: provisional default (§17.15 item 11) |
| A1-Q11, V-E1, X-Q8 | Owner of `verification::check` and its `valid_after` predicate | Body written (pure); predicate `valid_after <= now` within a 360 s window, looser than "now - 60 s" | open: provisional default (§17.15 item 11) |
| A1-Q12 | Smaller choices (slot re-claim, `DisclosureKind`, lifecycle values, `DestinationClock` tagging) | As listed in the A1 file | open: provisional default (§17.15 item 11) |
| A2-Q1 | `tokio::time::pause` unavailable to app and runtime tests | tokio `test-util` enabled for the app and runtime dev-dependencies | resolved by integrator |
| A2-Q2 | `issuance_ro::assess` verdict in wave 0 (no "unavailable" refusal exists) | `Ok(Err(EntryNotReserved))`; nothing confirmed, nothing signed | open: provisional default (§17.15 item 11) |
| A2-Q3 | `TimeGate::assess_read_only` is a method; the release check needs a non-blocking reading | Method, wave 0 answers `Uncertain`; `SignPermit` takes an injected `SafeTime` | open: provisional default (§17.15 item 11) |
| A2-Q4 | Shapes the plan names but does not define (`SignatureRequestFacts`, `SignRefusal`, `ConnError`, …) | As built in `app::ports`; `IssuerRefusal` lives in `app::ports` | open: provisional default (§17.15 item 11) |
| A2-Q5 | `Limits` fields where the plan gives a compound value | Split into fields with `Limits` methods for the sums | open: provisional default (§17.15 item 11) |
| A2-Q6 | Wait bound for acquiring a delegation chain | The caller passes one deadline (suggested `signing_gate_wait`) | open: provisional default (§17.15 item 11) |
| A2-Q7 | Grants without a gate in a narrowing set | `Acquired::NoGate`; marks are independent of gates (see G-Q1) | open: provisional default (§17.15 item 11) |
| B2-Q1, V-E5 | `SigningSession.peer: PeerInfo` is the wrong type for the signing endpoint | `PeerIdentity` (transport principal); the plan text should say so | open: provisional default (§17.15 item 11) |
| B2-Q2 | When the permit guard drops on the expiry path | Dropped at the expiry, before waiting for room for the failure frame | open: provisional default (§17.15 item 11) |
| B2-Q3 | A signature frame with no permit | Ruled (§17.15 item 2): a permit-less signature is sent only when its grant has no signing gate; otherwise refused and recorded (implemented) | ruled |
| B2-Q4 | Shape of `Signer::session_bind` | Synchronous, default body returns `false`; structural-only `SessionBindRecord::parse` | open: provisional default (§17.15 item 11) |
| B2-Q5 | Release check strictness | Releases only if `Instant::now() < expires_at()` and `may_release()` | open: provisional default (§17.15 item 11) |
| B2-Q6 | Replies without a permit | Same outbound queue (4 frames), wait bounded by the idle timeout | open: provisional default (§17.15 item 11) |
| B2-Q7 | `crates/ipc/src/lib.rs` docs should list `integration_ipc_signing_m03` | Listed by the integrator (with `adversarial_agent_client_frames`) | resolved by integrator |
| C-Q1, V-E4 | Wave-0 envelope: `USAGE_ERROR` exit 2 (M01's) or `CAPABILITY_UNAVAILABLE` exit 4; M01's text is guarded in M02 sources | Accepted (§17.15 item 8) | ruled |
| C-Q2 | Reason and code of the uninstall refusal while enrollments remain | `CONFIG_CONFLICT` exit 6, no reason; `bundle_required` for `--keep-remote-enrollments` without `--bundle` | open: provisional default (§17.15 item 11) |
| C-Q3 | An unreadable state store with `--purge-state` | Refused (`CONFIG_CONFLICT`); `OlderSchema` means none | open: provisional default (§17.15 item 11) |
| C-Q4 | `catalog_cmd.rs` (not C's) got one arm for `DestinationCommand::Prefer` | Arm added so the exhaustive match compiles | open: provisional default (§17.15 item 11) |
| C-Q5 | `enroll --yes` appears in a note but not in the command column | Not added | open: provisional default (§17.15 item 11) |
| C-Q6 | `access ensure --strict` handling | Answered by the wave-0 envelope whole, before any request is built | open: provisional default (§17.15 item 11) |
| C-Q7 | `service run` with an M03 variable in a debug build | Enters `testcfg::prepare`; `ALL_ENV` unchanged | open: provisional default (§17.15 item 11) |
| C-Q8 | `release-gate.sh` lacks an `enroll` probe for `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` | Probe added to `release-gate.sh` | resolved by integrator |
| D-Q1 | secret-service 5.2.0 (Linux duplicates) or 5.1.0 | 5.2.0 | open: provisional default (§17.15 item 11) |
| D-Q2 | Accept the three informational "unmaintained" advisories zbus 5 brings (RUSTSEC-2026-0370, -0371, -0372) | Accepted (§17.15 item 8): M08 cargo-deny carries the ignore, revisit at secret-service 6 | ruled |
| D-Q3 | Which RNG key generation uses (`ssh-key` takes rand_core 0.6) | Ruled (§17.15 item 9): OS CSPRNG only, through `getrandom`, never a userspace PRNG; U2/U3 implement | ruled |
| D-Q4 | ADR-0008 §18 omits dependencies its `sys.rs` modules need (`libc`, `windows-sys` features, three macOS externs) | Recorded in `dependencies.md` §5; ADR-0008 §18 and the U0 unsafe inventory should say so | open: provisional default (§17.15 item 11) |
| G-Q1 | Zero-gate narrowing: one transaction without marks, or always mark? | Ruled: no gated member, one transaction without marks; any gated member, the full protocol for the whole set | ruled |
| G-Q2 | Where `requested_at` and `committed_at` are stored (row 27) | Accepted (§17.15 item 8) | ruled |
| G-Q3 | Authorization time seam | Accepted (§17.15 item 8): `TimeGate::peek` behind its switch until U3's `assess_read_only` replaces it, before the U2 signer lands (wave-2 acceptance) | ruled |
| G-Q4 | The release check's in-memory time assessment | `AdmittedTime` (boot, continuous clock, skew bound); U2/U3 may replace it | open: provisional default (§17.15 item 11) |
| G-Q5 | `admit` records a re-validation (a write in the authorization transaction) | Recorded; the high-water mark is not written (F21) | open: provisional default (§17.15 item 11) |
| G-Q6 | How `narrowing_over_target` and `narrowing_set_grew` are reported (no wire value) | `tracing::warn!`, `Operations::narrowing_reports`; a `RevokeNote` variant would be a contract change | open: provisional default (§17.15 item 11) |
| G-Q7 | Row 7: which answers keep the cleanup intent | Only `OutcomeUnknown(ADAPTER_CALL_TIMED_OUT)` from a remote-effect adapter | open: provisional default (§17.15 item 11) |
| G-Q8 | Row 26: "the pending mark first" | One store read (binding to grant and chain) precedes the pending check | open: provisional default (§17.15 item 11) |
| G-Q9 | `admit` also checks the mark before queuing | In-memory check before the wait and again after acquisition | open: provisional default (§17.15 item 11) |
| G-Q10 | Narrowing paths not built or not gated | OVERTURNED (ADR-0008 §17.16, review R1): every authority-reducing policy change (incl. `SetLockBehavior` → `revoke_on_lock`) runs the full narrowing protocol for the affected grants and descendants before its commit | ruled |
| G-Q11 | The environment endpoint's "served" predicate | The grant has a binding in the environment that holds a slot (none exist in wave 0) | open: provisional default (§17.15 item 11) |
| G-Q12 | Lock pass acknowledgment | Epoch stored in the revocation's commit; `acknowledge` called after the commit | open: provisional default (§17.15 item 11) |
| G-Q13 | `SigningGates::release` drops a gate while a signer still holds it, so a later narrowing sees no gate (reachable only once U10 destroys instances outside a narrowing) | Ruled (ADR-0008 §17.15 item 1): both — a gate entry is never dropped while it has a holder or a pending mark (implemented in wave 0), and the release of a last instance takes the gate exclusively (U10) | ruled |
| G-Req, R-Req | Clippy findings in `runtime_m03.rs:1468,1559` (`needless_update`) and `narrowing_m03.rs:252` (`type_complexity`) | Owners report later runs exit 0; confirmed: check.sh run 2 clippy and clippy-windows exit 0 | resolved by integrator |
| N1 | `IssuerRefusal` wire form for the frozen `heimdall-issuer/1` | A2's type, one-string wire form (`issuance.<reason>`, `verification.<reason>`, own reasons by name); golden fixes it | open: provisional default (§17.15 item 11) |
| N2 | Golden file name `issuer-protocol.json` or `issuer-protocol.golden.json` | Renamed to `tests/contracts/golden/issuer-protocol.json` | resolved by integrator |
| N3 | `SecretStore` signature details (test store kind, `Result` returns) | `kind() -> SecretStoreKind { Product, Test }`; `delete` and `list` return `Result`; `put` never overwrites | open: provisional default (§17.15 item 11) |
| N4 | HM1 value shapes not fixed by ADR-0008 D5 §6.3 | Booleans `yes`/`no`, `ls -ldn` modes, decimal `remote_now`; else an ADR revision | open: provisional default (§17.15 item 11) |
| N5 | Signatures returning `Result` where the plan shows a bare value | `SshStepRunner::run`, `plan_digest`, `expected_line` return `Result`; wave 0 `Err(Unavailable)` | open: provisional default (§17.15 item 11) |
| N6 | `child::run` parameter types | Generic `Read + IsTerminal` stdin; wave 0 returns `EXIT_UNAVAILABLE` (69) | open: provisional default (§17.15 item 11) |
| N7 | Field-less protocol requests | Empty struct variants so unknown fields are refused; wire form unchanged | open: provisional default (§17.15 item 11) |
| N8 | Runtime's own third-party lines (`zbus`, `core-foundation`) | Added by N; no new lock package | open: provisional default (§17.15 item 11) |
| N9 | `SecretCaKey` created in U1's file | Minimal definition in `credential::cert`; U1 adds the rest | open: provisional default (§17.15 item 11) |
| O-Q1 | How the M01 issuance path is recognized | M03 path when a CA is named or the mechanism is `managed_certificate` | open: provisional default (§17.15 item 11) |
| O-Q2 | Sub-reasons of the CA refusals | `ca_retiring`, `pair_not_enrolled`; `UnknownCa` no reason | open: provisional default (§17.15 item 11) |
| O-Q3 | `next` of a pending-projection success | `setup_apply` with the binding kept, plus the warning | open: provisional default (§17.15 item 11) |
| O-Q4 | Missing `interaction_required` reason in `reason::M03` | Ruled: no `interaction_required` in wave 0; the first unit that produces it adds it to `reason::M03` and the golden | ruled |
| O-Q5 | A mixed `SetConnectionPolicy` (widens one field, narrows the other) | Widening as a whole; nothing applies before the decision | open: provisional default (§17.15 item 11) |
| O-Q6 | "The launch's program is the verified client" without `localenv` | Written only when `executable` equals the stored `ssh` executable path byte for byte | open: provisional default (§17.15 item 11) |
| O-Q7 | D6 item 7 versus M02's unattended control test | `select_adapter` unchanged; only the refusal gains its reason | open: provisional default (§17.15 item 11) |
| O-Q8 | Limits of the per-pair resolution | Four limits listed in the O file | open: provisional default (§17.15 item 11) |
| O-Q9 | Verification facts (`VerificationEntry` has no attempt number) | Attempts from `enroll.verify.started` receipts; `apply` and target change unauthorized in wave 0 | open: provisional default (§17.15 item 11) |
| O-Q10 | What a grant origin records (lock behaviour, connection policy) | The merged strictest values; a default is recorded as absent | open: provisional default (§17.15 item 11) |
| O-Q11 | Journaling `SetPreference` needs a `CatalogAction` variant | Added to `domain::catalog` (A1's file); destination must exist; hooks `add_issuing_ca` and `remove_issuing_ca` | open: provisional default (§17.15 item 11) |
| O-Q12 | The lock source for the policy path | G's source; none or `unavailable` refuses `revoke_on_lock` with `lock_signal_unavailable` | open: provisional default (§17.15 item 11) |
| O-Q13, V-E10 | No U0b row covers `Operations::cancel` for the enrollment kinds | Before `Attempted`: `driver_unavailable`; after: `remote_step_in_progress`, next `reconcile`; both write nothing (integrator reading: domain `enrollment_cancel_allowed`) | open: provisional default (§17.15 item 11) |
| O-Q14 | Row 12: which degraded reasons refuse use | Only `sign_rule() == Refuse` (`mechanism_unavailable`); `degraded_refuses_use` | open: provisional default (§17.15 item 11) |
| R1 | What "resumes at start" may do without an issuer child (row 23) | `deleted` to `retired` completes; `retiring` and `unloaded` stay; `CaStoreItemDeletion` trait lives in `app::operations` | open: provisional default (§17.15 item 11) |
| R2, V-E9 | Row 28: shared parser has no start-time-only entry; `process_start_time` semantics | `heimdall_domain::procstat::parse_start_time` (group not checked) replaced R's workaround; platform uses it | resolved by integrator |
| R3 | `lock_behavior` is a typed M01 key (`[session] lock_behavior`) | Ruled (§17.15 item 10): M01 `[session] lock_behavior` kept as a floor, merged fail-closed (revoke from either side wins); U9 implements; comment added at the key | ruled |
| R4 | Settled bounded obligations; two one-line edits in M01 code | Ruled (§17.15 item 3): a `nominally_expired` obligation keeps its record (grant may still become revoked); bounded_complete-only records may be removed (implemented) | ruled |
| R5 | Order of the owner-role refusal | Attended check, then owner role (`CAPABILITY_UNAVAILABLE`, no reason), then `driver_unavailable` | open: provisional default (§17.15 item 11) |
| R6 | `owner_reconcile` has no contract constant | `app::operations::OWNER_RECONCILE` | open: provisional default (§17.15 item 11) |
| R7 | Row 7: back-off scope and cap | Per-intent schedule only when a remote-effect adapter is configured | open: provisional default (§17.15 item 11) |
| S1 | The partial unique index versus removing an abandoned line | Ruled: the index covers enrollment-path states only; cancel returns to `removal_origin` | ruled |
| S1 follow-up | Cancel naming another origin; a removal `held` beside a live enrollment | Ruled: the wrong-origin cancel is refused; `held` with `removal_origin` set is outside the index (`removal_origin_set` column) | ruled |
| S1 manual_pending | Is `manual_pending` inside the index? | Confirmed inside | ruled |
| S2 | `verified_cas_for_pair` leaves out `reverifying` | Only `verified` counts (fail closed) | open: provisional default (§17.15 item 11) |
| S3 | `IssuerRecord.store_kind` cannot hold the test store kind | Typed `StoreKind`; U4 decides the test-only path | open: provisional default (§17.15 item 11) |
| S4, V-E12 | `uninstall` read on a schema-5 file; no all-open-enrollments read in the plan | `Txn::open_enrollments`, missing table means none; `open_read_only` unchanged | open: provisional default (§17.15 item 11) |
| S5 | Foreign keys beyond the plan's list | `managed_slots.binding_id`, `owned_connections.binding_id` and `.grant_id`; none on `foreign_removals` | open: provisional default (§17.15 item 11) |
| S6 | Not done in the store (TableCounts, meta-key methods, `seed_enrollment`) | For the owners of those files | open: provisional default (§17.15 item 11) |
| T-Q1 | How an evidence record represents "verified for that platform row" | Platform-string match, every matching row must be `verified` | open: provisional default (§17.15 item 11) |
| T-Q2 | `product_store_kinds` and `CUSTODY_FIELDS` mirrored in the validator | Mirror with an agreement check | open: provisional default (§17.15 item 11) |
| T-Q3 | Registry-purity self-test lives inside an existing self-test name | Asserted inside `crate_graph_step_rejects_cycle_and_ipc_to_app_edge` | open: provisional default (§17.15 item 11) |
| T-Q4, V-E3 | "check.sh's release-gate step" does not exist; the release refusal is narrower than described | `release-gate.sh` (check.sh step `release-gate`) probes every M01–M03 variable on each command that reads it: 22 probes, `enroll` included, exit 0 in check.sh run 1 | resolved by integrator |
| V-E2 | `enrollment_recovery_paths_each_tested` needs tests and a case index that do not exist | Accepted (§17.15 item 8) | ruled |
| V-E6 | U0b row 20 cannot be built as worded in four respects | (a) OVERTURNED (ADR-0008 §17.16, review R2): an environment-permission removal runs under the narrowing protocol in its own transaction; re-validation stays as recovery. (b)–(d) as recorded (provisional) | ruled (a); open (b)–(d) |
| V-E7 | `issuer_endpoint_kind_reserved_never_bound` is false as worded | Integrator reading: both listener constructors refuse `EndpointKind::Issuer` (built by R) | open: provisional default (§17.15 item 11) |
| V-E11 | "M01 and M02 suites run unchanged" cannot be literal (about 100 literals) | Mechanical edits only, reviewed as such | open: provisional default (§17.15 item 11) |
| V-E13 | Plan statements that do not match the code (corrections) | `Supervisor::holder_pass`, `Launch(LaunchBinding)`, stale `SETUP_V1` comment, stale commit citations | open: provisional default (§17.15 item 11) |
| V-E14 | Exact-count source scan in `operations.rs` | New managed port calls go in `crates/app/src/managed.rs` (integrator reading) | open: provisional default (§17.15 item 11) |
| X-D1 | A foreign system-form record cannot cancel back to an `abandoned` origin | Code fixed: foreign `cancel_target` accepts `abandoned` | resolved by integrator |
| X-D2 | Grant issuance accepts a `pending` CA | Code fixed: `pending` CA refused `UnknownCa` for grant certificates | resolved by integrator |
| X-D3 | `DestinationClock` refuses an unknown sibling field | Code fixed: hand-written `Deserialize` ignoring unknown siblings | resolved by integrator |
| X-Q1 | Inputs that cannot arise; system-form manual recovery gives `withdrawn` for a foreign record | Ruled (§17.15 item 4): system-form records refuse the manual-recovery events (table and golden amended) | ruled |
| X-Q2 | `reconcile_damaged` in `rollback_unknown` and `remove_unknown` (table versus §6.7) | Ruled (§17.15 item 5): §6.7 wins — damaged line in remove_unknown/rollback_unknown → held, removal_origin kept (table and golden amended) | ruled |
| X-Q3 | Manual recovery of a removal held by `lock_holder_unresolved` | Ruled (§17.15 item 6): manual recovery of a removal keeps its purpose — absent → removed, present → held with removal_origin kept (table and golden amended) | ruled |
| X-Q4 | `plan_digest` form (`sha256:…` in the plan, bare hex in code and examples) | Ruled (§17.15 item 7): bare 64-hex; plan §5 item 3 example fixed | ruled |
| X-Q5 | `consumer.pairs` of a managed `ensure` result has no defined shape | `ensure-data.managed.json` omits `pairs` | open: provisional default (§17.15 item 11) |
| X-Q6 | No public schema for the inspect views (§5 item 23 says regenerated) | Validated against the generated schemas inside the test only | open: provisional default (§17.15 item 11) |


### Rulings recorded after the index (ADR-0008 §17.15 item 6, orchestrator, 2026-11-08)
| ID | Question | Ruling | Status |
|---|---|---|---|
| A1-R1 | Manual recovery of a rollback (own account): which states? | "Keeps its purpose" covers rollbacks: line absent → `verification_failed`; line present → `held`, `removal_origin` kept; golden has the same rows | ruled |
| A1-R2 | `purpose` field (`append` \| `rollback` \| `removal`) on `manual_recovery_line_present`/`_absent` | Accepted as part of the wave-0 freeze (serde default `append`, omitted when `append`) | ruled |

## Per-agent files (verbatim)

## A1

# M03 wave 0 — questions and choices from A1 (types foundation)

Each item: what I chose (the fail-closed option where there was one), the alternatives, and the
evidence. None blocks compilation; each is behind the named type or function.

## Q-A1-1. `Enforcement` / `EnsureData` M03 fields are `Option<T>` (plan §5 items 7–8 write bare `T`)
* Evidence: plan §5 item 7 `#[serde(default)] pub lock_continuity: LockContinuityReport` (no
  `skip_serializing_if`); item 8 "each is `#[serde(default)]` and reads `unknown` when absent". The
  managed example (§5 item 7) writes `"lock_continuity": "not_verified"` and
  `"new_signing_expiry": "unknown"` explicitly. The brief: M01/M02 documents and hashes must not change.
  `Enforcement` is also **stored** inside every grant (`domain::evidence::EnforcementEvidence.report`),
  and `schemas/examples/envelope.success.ensure*.json` round-trip exactly (`tests/contracts/examples.rs`).
* Chosen: `Option<T>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`, plus accessors
  that read the default when absent (`Enforcement::identity_selection()` … `issuer_isolation()`,
  `EnsureData::lock_continuity()`), and `Enforcement::new(..5 M01 fields..)`. M01/M02 documents and
  stored grants re-encode byte-identically, and the managed example still round-trips with its explicit
  `unknown`/`not_verified` values.
* Alternatives: (b) bare `T`, always serialized: changes every M02 ensure result and every re-encoded
  grant record; the M01/M02 examples must be regenerated. (c) bare `T` skipped when default: the
  managed example's explicit `unknown` values no longer round-trip.

## Q-A1-2. `IssuanceCheck.enrolled_cas` shape (U0b row 2 writes `&[String]`)
* Chosen: `enrolled_cas: Option<EnrolledCas<'a>>` with `EnrolledCas { verified_for_pair:
  &[CaFingerprint] (newest first), ca_state: Option<CaState> }`. `None` = the M01 input (no CA check,
  M01 behaviour unchanged). Refusals, in order, after `WrongPrincipal`: `UnknownCa` (bounds name no CA,
  or the CA is not registered, or bounds name a CA but no CA inputs were given), `CaRetiring`
  (`retiring | unloaded | deleted | retired`), `CaNotVerifiedForPair` (registered, not in the set).
* Why: a bare slice cannot tell an M01 call from a managed pair with an empty verified set, and
  `CaRetiring`/`UnknownCa` need the CA's registered state.

## Q-A1-3. `CertificateBounds.ca_fingerprint` type
* U0 "frozen" list says `Option<String>`; §5 item 16 and my task say `Option<CaFingerprint>`. Chosen:
  `Option<CaFingerprint>` (same wire string, validated on decode).

## Q-A1-4. Two ID types not in §5 item 1
* `ConnectionId` (prefix `conn`) for `owned_connections.id`, `ConnectionsRequest::Close.connection_id`,
  `ConnectionsView`/`OwnedConnectionReport`/`Connection` event `id`.
* `ForeignRemovalId` (prefix `frm`) for `ForeignRemovalRecord.id` (never the bundle's marker).
* Alternatives: plain `String`; reuse `EnrollmentId` for foreign records (confusable with own records).

## Q-A1-5. `ConnectionsRequest::Register` carries `image`
* Plan §5 item 4a lists `{binding_id, pid, created_at}`; ADR-0008 D8 item 2 (revision 3) writes
  `Register { binding_id, pid, created_at, image }`, and the `ConnectionControl::register` port takes
  `image`. Chosen: include `image: String` (required). Drop it if the integrator prefers the plan text.

## Q-A1-6. Where the M03 reasons are registered
* `tests/contracts/m02.rs::error_reasons_are_stable_snake_case_and_complete` asserts
  `reason::ALL ∪ conflicts ∪ manual == M02's list` (equality). Extending `reason::ALL` breaks it.
* Chosen: `heimdall_contract::envelope::reason::M03: &[(&str, Code)]` (every §5 item 14 reason with its
  code, table order; `driver_unavailable` not repeated) plus one `pub const` per reason;
  `envelope::m03_warning::{…, ALL}` for the four warnings; `doctor::finding::M03` for the four findings.
  `reason::ALL` and `finding::ALL` stay M02's. If the integrator wants one list, m02.rs's equality must
  become "M02 list ⊆ ALL".

## Q-A1-7. `CatalogRequest::SetPreference` has `request_id`; domain `CatalogAction` not extended
* Every catalog action carries `request_id` (journaled under `catalog`); plan §5 item 4b omits it.
* `domain::catalog::CatalogAction::from_request` returns `None` for it (unchanged code path), and
  `app::catalog::catalog` refuses it with `CAPABILITY_UNAVAILABLE`/`driver_unavailable` **before**
  admission (mechanical fail-closed arm). U0b row 22 adds the `CatalogAction` variant and the driver.

## Q-A1-8. `revocation::residual_step(&RemoteObligation, safe_now: Option<Timestamp>)`
* `safe_now` stands in for `app::timegate::SafeNow`: `Some(wall)` only when the gate is `Safe`.
* `needs_remote_action` → always `pending_until` (adapter rounds settle it; not time-driven).
* A stale measurement (older than the verification freshness, D5 §6.5 item 4) is expected to be
  recorded as `unmeasured` by whoever builds the obligation; `residual_step` takes no freshness input.
  Alternative: add a `max_measurement_age` parameter.
* Drift: `ceil(age_ms × 100 / 10⁶)` ms, negative age = 0; any overflow = not passed (fail closed).

## Q-A1-9. Enrollment table: choices where ADR-0008 D5 §6.2 is silent (all in `enrollment::target`)
* Events carry `RecordFacts { form, foreign }`; `transition` also refuses any `from`/`to` state whose
  form column excludes the record's form, and any state outside `FOREIGN_SUBSET` for a foreign record.
* `held → applied_unverified | withdrawn` (manual-recovery reconcile) is allowed for every hold of kind
  `lock_holder_unresolved` (also removal-purpose holds); for a foreign record only `withdrawn` (the other
  target is outside the subset).
* `manual_removal_pending → abandoned` only for foreign records (the table lists it for foreign only).
* `abandoned → removing | manual_removal_pending` also for foreign records (subset allows it).
* A cancel of an **own** record carrying `ca_not_held_seen = true` is refused (cannot happen).
* `removal_verifying` + `AbsenceVerified` is refused for foreign records (Q28: the check cannot pass).
* `held → reverifying` (owner re-verify, approved target change) for own records only.
* `verification_failed` admits both forms (table form "—"), though only account form reaches it.
* `reverifying` + host-key mismatch → `held` (both starts), per the classification table's
  re-verification column.
* Self-transitions included where the table says "stays": `applying` (busy, confirmed bootstrap), and
  `outcome_unknown`/`rollback_unknown`/`remove_unknown` on an unresolved reconcile.
* `target_change_outcome` refuses a record whose hold is not `host_key_changed`; on a pass it also
  clears the hold.

## Q-A1-10. Enrollment cancel rule and stage names
* `operation::enrollment_cancel_allowed(kind, receipts)` refuses (`remote_step_in_progress`) once a
  receipt whose effect is not `NotAttempted` exists for stage `enroll.append`, `enroll.rollback` or
  `enroll.remove`. The E2b bootstrap (`enroll.bootstrap`) does not block cancel, following ADR-0008 D5
  §6.4 "allowed until the E3 `Attempted` receipt exists" literally (a late `mkdir` creates at most an
  empty 0700 directory). Fail-closed alternative: include the bootstrap.
* The stage names in `operation::enrollment_stage` are my choice (`enroll.inspect.started`,
  `enroll.inspect.observed`, `enroll.bootstrap`, `enroll.append`, `enroll.verify.started`,
  `enroll.verify.outcome`, `enroll.rollback`, `enroll.remove`); the ADR names only some of them.

## Q-A1-11. Verification validity predicate
* "valid_after = now − 60 s and valid_before ≤ now + 300 s" read so that the publish re-check (later
  `now`) still passes: `valid_after < valid_before`, `valid_after ≤ now`, `valid_before ≤ now +
  max_validity`, and `valid_before − valid_after ≤ max_validity + 60 s`. `max_validity` is an input
  (the app's `verification_max_validity`), counts are inputs (`entries_in_attempt`, `attempts`).

## Q-A1-12. Smaller choices
* Slot table: a re-claim by the **same** binding is idempotent (`held(b,g)` unchanged); only another
  binding is `managed_slot_held`.
* `DisclosureKind` is one contract enum (`contract::enrollment`) used by the enrollment plan and
  `RegisterIssuer`; `domain::decision` re-exports it. `RemovalTargetRef` is a type alias of
  `contract::enrollment::RemovalTarget`.
* `CredentialLifecycleEvent` also lists M01's emitted values (`expired`, `revoked_locally`,
  `authority_withdrawn`) besides §5 item 13's.
* `DestinationClock` is externally tagged (`{"measured":{…}}` / `"unmeasured"`, as the plan's example);
  its schema drops `additionalProperties` (outside the contract's supported keyword set,
  `tests/contracts/schema_export.rs`).
* `ResidualStatus`, `ClockMeasurement`, `DestinationClock`, `CaState`, `EnrollmentState`, policy and
  connection enums live in the contract (wire-visible) and are re-exported from the domain modules
  the plan names.

## A2

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

## B2

# M03 wave 0: B2 (ipc signing, U0b row 1) questions and decisions taken

1. **`SigningSession.peer` type.** m03-plan U0b row 1 (docs/architecture/m03-plan.md:491) names
   `peer: PeerInfo`. The only `PeerInfo` is `heimdall_contract::ipc::PeerInfo` (crates/contract/src/ipc.rs:63-70):
   the program name/version from the control hello, "informational only, never authority". The SSH agent
   protocol has no hello, so there is nothing to fill it with. The transport-authenticated principal is
   `heimdall_ipc::endpoint::PeerIdentity` (Unix uid/gid/pid, Windows SID/pid), which the accept loops already
   return (crates/runtime/src/service.rs `serve_signing`). Options: (a) `PeerIdentity` (taken); (b) a new
   ipc type named `PeerInfo`; (c) contract `PeerInfo` with placeholder values. Taken: (a), the field name
   `peer` kept. The plan text should say `PeerIdentity`.

2. **Guard drop on the expiry path.** Row 1 says the guard is dropped "only after that enqueue". On the
   expiry path (ADR-0008 D2 item 3a step 6, last bullet) the signature is discarded and a failure is sent
   once room frees within the same window. Taken: the guard is dropped **at the expiry**, before waiting
   for room for the failure. Reason: after expiry nothing of the signature can be released, so the gate
   protects nothing, and holding it up to 2 s more would exceed `signing_holder_max` (5 s = 2 + 1 + 2,
   m03-plan §5 item 17), which `signing_gate_max_wait` (H) is derived from. On the normal path the guard
   is dropped strictly after `Permit::send` (tested). Alternative: hold it until the failure is queued.

3. **A signature frame with no permit.** `SignOutcome.permit` is an `Option` (row 1); `serve` sends a
   permit-less frame as is, so M01 fixture signers keep working without a release check. The production
   `ManagedSigner` (U2) must always attach a permit to a signature. Fail-closed option if wanted: `serve`
   replaces any `SSH_AGENT_SIGN_RESPONSE` (type 14) that has no permit with `SSH_AGENT_FAILURE` (the M01
   adversarial fixture would then attach an always-true permit). Not done; ruling requested.

4. **`Signer::session_bind` shape.** Plan: `session_bind(&mut SigningSession, payload) -> bool`. Taken: a
   synchronous `fn` with a default body returning `false` (fail-closed; `NoIdentities` and the M01
   fixtures refuse every bind, as M01 did). `payload` is the extension contents after the name string.
   `SessionBindRecord` is plain data (`host_key`, `session_id`, `signature`, `is_forwarding`); I added a
   structural-only `SessionBindRecord::parse` (lengths, bool 0/1, no trailing bytes; verifies nothing).
   U1 owns real verification and may ignore the helper.

5. **Belt and braces at the release check.** `serve` releases only if `Instant::now() < expires_at()`
   **and** `may_release()`; both are non-waiting. `may_release()` remains the authority (both clocks,
   `Safe` time, pending mark).

6. **Replies without a permit** (identities, failures, session-bind answers) use the same queue; their wait
   for room is bounded by the idle timeout (30 s), as the M01 per-reply write was. Each socket write by
   the writer is also bounded by the idle timeout (M01 behaviour). Default queue capacity:
   `OUTBOUND_QUEUE_FRAMES = 4` frames (≤ 1 MiB per connection at the 256 KiB frame limit).

7. **For the integrator (paths I do not own):** `crates/ipc/src/lib.rs` crate docs list the test targets
   hosted by ipc; add `integration_ipc_signing_m03` there (I did not edit lib.rs: no re-export needed).
   The row's plan text and ADR-0006 rev 4 should name the final API (see the B2 report).

## C

# Agent C questions (CLI tree, test gates, uninstall refusal)

1. **Wave-0 envelope: USAGE_ERROR (exit 2) or CAPABILITY_UNAVAILABLE (exit 4)?** Brief §2 and plan line 307 say "M01's 'not available in
   this build' envelope"; git history (d57bf7c4, `not_available_envelope`) shows M01's was `USAGE_ERROR`, effect `none`, next `fix_request`,
   exit 2, message "this command is not available in this build (planned for M02)". verify-doc E4 option (a) proposed
   `CAPABILITY_UNAVAILABLE`/`driver_unavailable`/exit 4 with different wording; api.md E4 only fixes the placement. *Built:* M01's envelope
   exactly (exit 2), message ending "(planned for M03)", built at run time in `crates/heimdall/src/m03_cmd.rs` (not in `M02_SOURCES`). One
   function (`not_available_envelope`) to change if the integrator prefers (a); `tests/e2e/cli_m03.rs` asserts code/exit/message.
2. **Reason and code of the uninstall refusal.** No reason constant fits "purge refused while enrollments remain". *Built:* `CONFIG_CONFLICT`
   (exit 6, the existing purge-refusal class), effect `none`, no `reason`, `data.enrollments[] = {marker, destination_id, state}`.
   `--keep-remote-enrollments` without `--bundle`: `CAPABILITY_UNAVAILABLE` + `bundle_required` (ADR-0008 D4 item 6, existing reason).
   With `--bundle`: the wave-0 envelope (nothing can verify freshness; U12). If the integrator wants a dedicated reason
   (e.g. `enrollments_remain`), it needs a row in `reason::M03` (contract, not mine).
3. **A state store that cannot be read** (not just older schema) refuses `--purge-state` (`CONFIG_CONFLICT`): fail closed, since the
   remaining enrollments are unknown. A pre-6 file (`OlderSchema`) means none (no table existed).
4. **`catalog_cmd.rs` (not in my paths) got one arm** (`DestinationCommand::Prefer(_) => crate::m03_cmd::not_available_outcome()`):
   the exhaustive match in `destination_flow` would not compile otherwise. `dispatch` answers `prefer` first; the arm is the fallback.
5. **`enroll --yes`** appears in plan §5 item 24's note ("`--yes` never skips the decision") but not in the command column; not added.
6. **`access ensure --strict`** is accepted by the tree and answered by the wave-0 envelope whole, before any request is built
   (`EnsureArgs.strict`; `dispatch` guard). Non-strict `ensure` is unchanged.
7. **`service run` with an M03 variable in a debug build** now enters `testcfg::prepare` (as for every variable of `requested_by`), i.e. the
   M01 fixture seeding and fake adapter apply, and the M03 values are validated; U10 wires what they select. `ALL_ENV` is unchanged
   (7 entries); `tools/validation/release-gate.sh` adds the M03 variables itself and reads only `ALL_ENV`/`LAUNCH_ENV`.
8. **Release refusal for `enroll`** is not probed by `release-gate.sh` (it probes `service run` for all four). I checked by hand that the
   release binary exits 2 for `enroll lab` with `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` set and creates nothing. Suggest T add an
   `enroll lab` probe for `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`.

## D

# Questions from subagent D (dependency pins), M03 wave 0

Each question has a default D took (recorded in dependencies.md section 5). Evidence is in
`.m03-wave0-deps.md`.

## Q1. secret-service 5.2.0 (Linux duplicates) or 5.1.0 (none)?

- ADR-0008 §18 / m03-plan U0: "pins exact versions at least two weeks old" and P3 "the dependency weight is
  recorded". dependencies.md section 1 (sha2 row) says sha2 0.11 "would duplicate sha2 in the graph".
- 5.2.0 (2026-08-29, newest eligible): GitHub release notes list "check initialization vector length" and
  "error instead of panicking in exec_prompt". Its `crypto-rust` feature uses the RustCrypto 0.11 generation:
  Linux-only duplicate pairs aes, block-buffer, block-padding, cbc, cipher, const-oid, crypto-common, digest, hmac,
  inout, sha2; +15 lock packages over 5.1.0.
- 5.1.0 (2025-09-03): uses the 0.10 generation ssh-key already has: no new duplicates; lacks the IV check and
  panics instead of erroring on a failed prompt.
- **Default taken:** 5.2.0 (custody-critical decrypt path; duplicates are Linux-only and pure Rust). Switching is
  one line in the root `Cargo.toml` plus the table row.

## Q2. Accept the three informational "unmaintained" advisories that zbus 5 brings?

- RUSTSEC-2026-0370 (zvariant), -0371 (zbus_names), -0372 (zvariant_derive), all 2026-10-16, no patched
  version. They apply to the zbus 5 line because zbus 6.0.0 merged those crates.
- Options: (a) zbus 5.19.0 + secret-service 5.2.0 now, revisit at secret-service 6.0.0 stable (rc.1 published
  2026-11-06); (b) zbus 6.x for logind plus our own Secret Service client (rejected: custody crypto we would own);
  (c) wait for secret-service 6.0.0 before pinning (blocks Linux K_ca work only; the Linux product row is already
  blocked on B11).
- **Default taken:** (a). M08's `cargo-deny` will need a recorded ignore with that revisit trigger.

## Q3. Which RNG does key generation use?

- `ssh-key` 0.6.7 key generation takes a `rand_core` 0.6 RNG. `rand_core::OsRng` exists in this graph only because
  p521's `getrandom` feature is switched on through ssh-agent-lib's `ssh-key/crypto` (feature unification by
  accident). ADR-0008 §18 names only the `rand_core` feature.
- Options: (a) add `getrandom` to the ssh-key feature list (declares it; adds no package; uses getrandom 0.2 for
  key generation while IDs use 0.4); (b) a small adapter in `heimdall-credential` implementing rand_core 0.6
  `RngCore + CryptoRng` over the pinned getrandom 0.4.3, which needs a direct `rand_core = "=0.6.4"` dependency
  (package already in the lock); (c) rely on the accident (fragile).
- **Default taken:** none applied to the manifests; the root `ssh-key` line carries exactly the ADR's three
  features. The unit that writes key generation (U2/U3) decides between (a) and (b). (b) keeps one OS-entropy path.

## Q4. ADR-0008 §18's dependency list is missing items its own `sys.rs` modules need

- `crates/credential/src/sys.rs` (mlock/VirtualLock/prctl/setrlimit) needs `libc` (Unix) and `windows-sys` with
  `Win32_System_Memory` (Windows) as `heimdall-credential` dependencies; the ADR lists neither.
- `crates/runtime/src/session_lock/sys.rs` (message-only window) needs `Win32_System_LibraryLoader`
  (`GetModuleHandleW`).
- macOS externs that exist in no pinned crate (checked in security-framework 3.7.0, security-framework-sys 2.17.0,
  core-foundation 0.10.1, core-foundation-sys 0.8.7): `SecAccessCreate`, `SecTrustedApplicationCreateFromPath` (issuer
  `sys.rs`), `CGSessionCopyCurrentDictionary` (runtime `sys.rs`, `#[link(name = "CoreGraphics", kind = "framework")]`).
  The `unsafe` inventory already names these modules, but the inventory text does not say these three functions are
  hand-declared.
- **Default taken:** D recorded all of them in dependencies.md section 5 and put `Win32_System_Memory` and
  `Win32_System_LibraryLoader` in the proposed root windows-sys list. Request to the integrator: have ADR-0008 §18
  and m03-plan U0's unsafe-inventory rows say so (D does not own those files).

## G

# M03 wave 0: questions and readings from G (signature authorization, narrowing protocol)

Each item: the question, the options, the evidence, and the reading G built (fail closed where
there was a choice).

## G-Q1. The zero-gate case of the narrowing protocol — **ruled: accepted with condition**
- Ruling (orchestrator): (1) a narrowing whose affected grants have no signing gate commits in one
  transaction without pending marks; (2) the moment ANY affected grant has a gate, the full
  protocol applies to the WHOLE set without exception (marks on every member, ordered acquisition,
  rounds, key destruction under the gates, release then cleanup after release).
- Applied: the shortcut is decided on the full set read inside the transaction that commits
  (`narrowing.rs` step (1), comment "G-Q1, ruled"). A gate created after that check cannot admit a
  signature released after the commit: the signer's fresh read is a store transaction serialized
  after the commit, so it refuses. The slow path marks every member (gated or not), and the
  commit's re-read now sends ANY member no round knew (gated or not) to another round, so the whole
  set is always marked. Tests: `gated_member_of_cascade_takes_full_protocol`,
  `mixed_gated_and_ungated_set_takes_full_protocol_for_whole_set`.
- Evidence: `crates/app/src/operations/narrowing.rs` (`Operations::narrow`, step (1)); A2-Q7
  (`Narrowing::acquire` answers `NoGate`; `admit_shared` refuses `NoGate`).
- Reading built: the first read of the set runs in a write transaction that also looks for a gate
  on any member. If no member has a gate, the same transaction commits: reads, re-validation and
  commit collapse into one serializable transaction, with no marks (nothing can wait). A gate
  created while it runs admits nobody before it commits, because a signer's fresh read is a store
  transaction that the store serializes after this one. In wave 0 every narrowing takes this path,
  so M01/M02 transaction counts and fault points are unchanged (the preserve suites pass).
- Options: (a) this reading; (b) always mark and run round 0 (two extra transactions per narrowing,
  which moves store fault points that M01 tests arm, e.g. `tests/model/operations.rs:4876`).

## G-Q2. Where the revoke timestamps are stored (row 27)
- `requested_at` is `OperationRecord.created_at`, which `admit` stores from the `now` that `revoke`
  reads before the hash, the visibility check and any gate wait (verify doc row 27 inference). No
  `RecoveryIntent` field was added (about 20 literal sites; `intent_update_allowed` forbids changing
  `request`).
- `committed_at` is read inside the tombstone transaction (`narrowing::commit_time`: the gate's
  accepted time, else the raw wall clock, as `narrowing_now`) and written as `Tombstone.revoked_at`.
  No new tombstone field.
- A second revoke of an already tombstoned grant (`insert_tombstone` keeps the first): its
  `committed_at` is that drive's own reading. If its drive is interrupted between the commit and the
  settle, the later drive falls back to the stored tombstone's `revoked_at` (the first revocation's).
  Options: store `committed_at` in the operation's receipts instead.

## G-Q3. The authorization time seam (row 5; integrator reading)
- `narrowing::AuthorizationTime::{Peek (default), ReadOnly}`, set by `Operations::set_authorization_time`.
  `Peek` evaluates `heimdall_domain::time::gate` over the authorization's own transaction
  (`runtime_anchor`, `high_water_mark`, `time_confirmation`, the clock, the sync report) and writes
  nothing (`TxnGate::assess` is private to `timegate.rs`, so `authorize.rs` repeats its reads).
  `ReadOnly` calls `TimeGate::assess_read_only` on the blocking pool (wave 0: always `Uncertain`, so
  every signature is refused). U3 switches the default.

## G-Q4. The release check's in-memory time assessment
- `SignPermit` needs a non-blocking `SafeTime`. Reading built (`authorize.rs`, `AdmittedTime`): `Safe`
  while the clock is in the admitted observation's boot, its continuous reading did not go back, and
  wall progress since admission is within `TimePolicy::max_tolerated_skew` of continuous progress.
  It cannot see a store-side change (a high-water mark raised elsewhere). U2/U3 may replace it.

## G-Q5. `admit` records a re-validation
- `revalidate_chain` (ADR-0006 §13.5 ruling 2) records the new validated generation, a write inside
  the authorization transaction. F21 forbids the high-water mark write, which is not made. Option:
  a verdict-only variant that records nothing.

## G-Q6. How `narrowing_over_target` and `narrowing_set_grew` are reported
- No wire value exists for either (`RevokeNote` has `ordinary_connections_not_closed` only;
  `reason::M03` has neither). Reading built: `tracing::warn!` with the terms, the
  `NarrowingReport` (`Operations::narrowing_reports`, the hook's `NarrowingPoint::Reported`), and
  `RevokeData.{requested_at, committed_at}`. If they must reach `RevokeData.notes`, `RevokeNote`
  needs two variants (a contract change for A1/X and the golden).

## G-Q7. Row 7: which answers keep the intent
- Built: for an adapter with `remote_credential_effect`, an immediate call answering
  `OutcomeUnknown(ADAPTER_CALL_TIMED_OUT)` keeps the cleanup intent; every other answer behaves as
  in M02. ADR-0008 D7 item 5 names the timeout only. Fail-closed alternative: any non-confirming
  answer (an error or `remote_pending`) keeps it. The back-off schedule is R's
  (`process_cleanup_intent_reporting` answers `Kept`); G changed no runtime code.

## G-Q8. Row 26: "the pending mark first"
- The binding ID does not name the grant, so one store read (binding → grant and its ancestor chain)
  precedes the pending check; the pending check precedes every check of the grant and the gate wait.
  A grant with no gate registers without one: it is ordered with its narrowing by the store alone
  (G-Q1). The refusal reasons are fixed words in `ConnError::RegistrationRefused`
  (`connections.rs` `refused::*`).

## G-Q9. `admit` also checks the mark before queuing
- `tokio::sync::RwLock` queues a new reader behind a waiting writer (A3), so a signer arriving after
  the mark would wait the full `signing_gate_wait` behind the narrowing and then refuse
  `GateTimeout`. `admit` therefore checks the mark before the wait too (in memory), and still first
  after the awaited acquisition (`admit_shared`).

## G-Q10. Narrowing paths not built, or not gated
- `PolicyAction::SetLockBehavior` (O's narrowing branch) takes no gate: it revokes nothing until a
  lock (row 25 does). The enrollment hold or removal that degrades a pair is U10's. A cutoff destroys
  no key: the affected grants end at the cutoff like expiry (ADR-0008 D7 item 8).
- An `end_in` withdrawal of a gated cascade is deferred (`Ended.gated`) and re-run under the gates by
  `complete_withdrawals`; a withdrawal found under them that needs gates outside the set defers
  again, at most `MAX_ANCESTRY` times, then is left to the next use or scheduler pass.

## G-Q11. The environment endpoint's "served" predicate
- Built: the grant has a binding in this environment that holds a slot (`Txn::slots_for_binding`
  non-empty). Wave 0 has no slots, so every environment-endpoint request is `KeyNotServed`. The key
  fingerprint is not compared (no instance table read in wave 0; the vault resolves the subject).

## G-Q12. Lock pass acknowledgment
- The acknowledged epoch is stored in the revocation's commit transaction (only when higher than the
  stored one, since `set_acknowledged_lock_epoch` refuses a lower one), and `source.acknowledge` is
  called right after the commit, before the adapters' local-denial rounds. A failed commit leaves
  the lock latched.

## G-Q13. A gate dropped while a holder still holds it (A2's lifecycle; found checking G-Q1)
- `SigningGates::release` removes the gate when the last instance goes, even if a signer still holds
  it shared ("a holder … keeps its own reference", `managed.rs:196`). A narrowing that starts after
  that sees no gate for the grant, in the zero-gate path and the full protocol alike (`acquire`
  answers `NoGate`), so it cannot wait for that holder. If the holder had already signed and was
  waiting for capacity, its release check (expiry, safe time, pending) could pass after the commit.
  It is reachable only once U10 destroys instances outside a narrowing (expiry, release of the last
  reference); in wave 0 no instance exists.
- Options (fail closed): (a) `release` keeps the gate entry while its lock has outstanding holders
  (`Arc::strong_count > 1`) and drops it when they end; (b) U10 destroys the last instance only
  under the exclusive gate, whatever the cause. Not changed by G: it alters A2's semantics.

## Requests to other agents
- R: `tests/integration/runtime_m03.rs:1468` and `:1559` fail `clippy -D warnings`
  (`needless_update` on `..Backoff::default()`); seen while running
  `cargo clippy -p heimdall-runtime --all-targets`.

## N

# Questions from subagent N (new crates, dependencies, testkit `managed`), M03 wave 0

Each question names the default N took (the most fail-closed or least-committing choice) and where.

## N1. `IssuerRefusal` wire form (frozen `heimdall-issuer/1`)

- ADR-0008 D3 item 3 shows `{"t":"refused","request_id":"…","reason":"<IssuerRefusal>"}` (one string), and
  m03-plan §5 item 20 says the variants are the `IssuanceRefusal` and `VerificationRefusal` sets plus six.
  The two domain sets share names (`wrong_principal`, `unknown_subject_key`, `time_uncertain`), and
  `IssuanceRefusal::GrantNotIssuable(GrantState)` carries data.
- A2 defined the variant set as `heimdall_app::ports::IssuerRefusal` with a derived, externally tagged serde
  (`{"issuance":{"reason":"stale_generation"}}`, `"entry_stale"`), which is not a one-string form.
- **Default taken:** the protocol reuses A2's type (re-exported from `heimdall_issuer::protocol`) and
  freezes its own wire form through `#[serde(with)]` on `Response::Refused.reason`: own reasons as their
  snake_case names; `issuance.<reason>` / `verification.<reason>` (the domain enums' own serde names);
  `issuance.grant_not_issuable.<grant_state>`. Fixed in `tests/contracts/golden/issuer-protocol.golden.json`
  (38 refusal strings). A refusal without a wire name fails to encode (closed).
  `crates/issuer/src/protocol.rs` (`refusal_to_wire`, `refusal_from_wire`, `is_generation_only`).

## N2. Golden file name

- m03-plan U3 acceptance and the `app::ports::IssuerRefusal` doc comment say
  `tests/contracts/golden/issuer-protocol.json`; N's task packet says `issuer-protocol.golden.json`
  (the existing `*.golden.json` convention). **Default taken:** `issuer-protocol.golden.json`. The plan
  line and A2's doc comment in `crates/app/src/ports.rs` should be aligned (N does not own them).

## N3. `SecretStore` signature details (frozen trait, `crates/issuer/src/store/mod.rs`)

- m03-plan U4 lists `kind() -> StoreKind`, `delete(&StoreItemRef)` (no result) and `list() -> Vec<…>`.
- `StoreKind` has no test variant (F23), so `ScratchSecretStore` cannot return one. **Default taken:**
  `kind() -> SecretStoreKind { Product(StoreKind) | Test(&'static str) }` (testkit names `scratch_test`;
  `product()` is `None` for it); `delete` and `list` return `Result<_, StoreError>` (an unavailable store
  cannot list, and an empty list would hide orphans). `put` never overwrites (`AlreadyExists`).
- `domain::claims::product_store_kinds` / the claims validator should treat any `SecretStoreKind::Test` as
  fixture custody (integrator check).

## N4. HM1 value shapes not fixed by ADR-0008 D5 §6.3

- The ADR fixes the key names and "decimal, a fixed token, or lowercase hex", but not the tokens of the
  boolean keys (`dir_owner_self`, `owner_self`, `last_byte_newline`, `group_listed`), the mode strings
  (`dir_mode`, `mode`), `status`/`reason`, or `remote_now`'s unit.
- **Default taken** (`crates/registry/src/hm1.rs`): booleans `yes|no`; modes as the `ls -ldn` 10 characters
  plus an optional `+`/`@`/`.`; `status`/`reason` `[a-z0-9_]+`; `remote_now` decimal (remote epoch seconds,
  matching `RemoteStep.not_after_remote`); `lock_holder` `hm1-[0-9a-z-]*`; `fence_signals` `""|TERM|TERM,KILL`.
  If U5 needs other tokens this is an ADR-0008 revision (the grammar is frozen).
- Related inconsistency (A1's file): `domain::verification::AttemptResult.remote_now` doc says "the `HM1 now=`
  reading"; §5 item 21's key is `remote_now`.

## N5. Signatures that return a `Result` where the plan shows a bare value

- `enroll::remote::SshStepRunner::run(&RemoteStep, TtyMode) -> Result<StepReport, StepRunError>` (plan:
  `-> StepReport`). A wave-0 bare `StepReport` would have to invent an exit status for a step that never
  ran. **Default taken:** `Result`, wave 0 `Err(Unavailable)`, nothing spawned.
- `registry::plan::plan_digest(&EnrollmentPlan) -> Result<PlanDigest, PlanRefusal>` (wave 0
  `DriverUnavailable`), `registry::line::expected_line(..) -> Result<String, LineError>`.

## N6. `child::run` parameter types

- Plan: `child::run(stdin, stdout, store: Box<dyn SecretStore>, db: &Path, clock: Arc<dyn Clock>) -> i32`; it
  must refuse a terminal stdin. **Default taken:** `run<R: Read + IsTerminal, W: Write>(stdin: R, stdout: W,
  …) -> i32` (std's `Stdin` and `File` satisfy it); wave 0 returns `EXIT_UNAVAILABLE` (69) touching nothing.

## N7. Field-less protocol requests are empty struct variants

- serde ignores `deny_unknown_fields` for unit variants of an internally tagged enum, so `{"t":"load","x":1}`
  was accepted. **Default taken:** `Request::{Load {}, Status {}, Shutdown {}}`; the wire form is unchanged
  (`{"t":"load"}`), and an unknown field is refused for every kind. `MAX_FRAME_BYTES` (65 536) bounds the
  JSON body; the 4-byte length prefix is not counted.

## N8. Runtime's own third-party lines

- `.m03-wave0-deps.md` §2 lists `zbus` (Linux) and `core-foundation`/`core-foundation-sys` (macOS) for
  `heimdall-runtime`. N added them (they add no lock package; the U9 session-lock source uses them). If the
  integrator meant the runtime unit to add them, they are three lines in `crates/runtime/Cargo.toml`.

## N9. `SecretCaKey` created in U1's file

- The frozen `SecretStore` trait names `SecretCaKey`, which m03-plan U1/U4 place in `heimdall-credential`
  (`cert::build_and_sign(.., ca: &SecretCaKey)`). **Default taken:** `crates/credential/src/cert.rs` defines
  `SecretCaKey { key: ssh_key::PrivateKey }` with only `from_private_key` and `public_key` (no `Clone`,
  `Debug`, serde). U1 adds the rest; U4's backup needs an accessor U1 must add.

## O

# M03 wave 0: questions and readings of agent O (rows 2-4, 9-12, 19, 21, 22, E10)

Each item names the reading built (fail closed) and the options. File:line at the time of writing.

- **O-Q1 (row 3, how the M01 path is recognized).** `IssuanceRequest` (`crates/app/src/operations.rs`,
  struct `IssuanceRequest`) has no CA field, and its three full literals live in files O does not own
  (`tests/model/operations.rs:1996`, `:3238`; `tests/model/revocation.rs:525`). Built: the request is on
  the **M03 path** when it names a CA through the new `Operations::reserve_issuance_naming_ca(req, ca)`
  (`crates/app/src/operations/ca_issuance_m03.rs`) **or** the grant's recorded `GrantOrigin.mechanism` is
  `managed_certificate`; otherwise the M01 path (no CA selected, bounds name none, `enrolled_cas: None`).
  An entry whose bounds name a CA is always checked on the M03 path (publish too).
  Options: (a) as built; (b) later wave adds `IssuanceRequest.ca_fingerprint: Option<CaFingerprint>`
  with the three mechanical literal edits and drops the extra method.
- **O-Q2 (row 2, sub-reasons of the CA refusals).** `OpError::from_issuance_refusal` (A1, `error.rs`)
  maps all three to one `CAPABILITY_UNAVAILABLE` message. Built (wrapper `ca_issuance_m03::refusal_error`,
  `error.rs` untouched): `CaRetiring` → reason `ca_retiring`; `CaNotVerifiedForPair` → `pair_not_enrolled`;
  `UnknownCa` → no reason. Options: other reasons (`enrollment_unverified` for the second), or a reason
  for `UnknownCa`.
- **O-Q3 (row 9, `next` of a pending-projection success).** ADR-0008 §6.6 says the result carries the
  warning `managed_projection_pending` **and** `next: setup_apply`. Built: `next.action = setup_apply`
  with `next.binding_id` kept (it replaces `use_binding`). Option: keep `use_binding` and carry the
  hint only in the warning.
- **O-Q4 (row 9, missing reason).** ADR-0008 D6 item 7 names `interaction_required` as an `unattended`
  refusal reason; it is not in `envelope::reason::M03`. Built: a local constant
  (`pair_mechanism_m03::INTERACTION_REQUIRED`), never produced in wave 0. **Request to the contract
  owner:** add it to `reason::M03` (`CAPABILITY_UNAVAILABLE`) and its golden.
- **O-Q5 (row 11, a mixed `SetConnectionPolicy`).** An action that widens one field and narrows the
  other (e.g. `existing: graceful` + `multiplexing: disabled` from strict/owned_masters) is widening as a
  whole (contract `PolicyAction::is_widening`): nothing applies before the attended decision; the
  approval applies the whole recorded action with `upsert_policy(.., false)` (the generation does not
  move for its narrowing part). Classification is against the current values (as `Cutoff`): a no-op field
  never widens. Options: (a) as built; (b) apply the narrowing part at once and record a decision for the
  widening part only; (c) refuse mixed actions `USAGE_ERROR`.
- **O-Q6 (row 19, "the launch's program is the verified client").** The application cannot resolve paths
  (no `localenv`). Built, fail closed: the row is written only when the launch's `executable` equals, byte
  for byte, the `path` of an `ssh` `ConsumerExecutable` in the grant's stored `PreparedFacts.executables`
  (`bind_connection_m03::verified_client_image`); no stored integration, a symlinked or otherwise
  different path writes nothing. Also: a dedicated row has `generation: 0`; a replayed launch that claims
  its holder registers too (`claim_replayed_launch`); the row closes in the holder pass's release
  transaction (`release_checked`, only for the exact exited holder). A failed exec leaves the launcher
  as the holder, so it is cleared when the pass observes that exit. Escalation: confirm the reading, or
  have the CLI pass a `verified_client: bool` it computed with `localenv` (a contract field).
- **O-Q7 (row 9, D6 item 7 vs M02).** D6 item 7: `unattended` is met only with `managed_certificate`.
  M02's `u0b_unattended_minimum_unknown_is_capability_unavailable` (`tests/model/operations.rs:10822`)
  has a control where an existing-access fake adapter with `lock_continuity: Verified` meets it. Built:
  `select_adapter` unchanged (preserve list); only the refusal gains its reason
  (`lock_continuity_unverified`, or `projection_pending` while a projection is pending). Production M02
  adapters never report `Verified` (`crates/adapters/src/lib.rs:91`), so D6 holds in production. Ruling
  needed if the control should change.
- **O-Q8 (row 9, limits of the per-pair resolution).** (a) "Projection applied" is
  `ProjectionStatus::Applied { .. }`, not compared with the current projection generation. (b) The
  `offline_until` minimum is checked after preparation (`unmet_minimum`), so a pending projection whose
  offline minimum the existing mechanism cannot meet fails with M01's message, not `projection_pending`.
  (c) The reconcile stage's mechanism re-check (`stage_reconcile`, `catalog_pairs`/`catalog_mechanism`)
  still reads the catalog identity only (no managed grant can prepare in wave 0). (d) The pre-admission
  check refuses only the `managed_certificate` resolution (`driver_unavailable`) and `connection: graceful`
  before any record; `pair_not_enrolled` and `mixed_mechanisms` are refused by resolution (a failed
  operation), as M02 does for `mixed_mechanisms`.
- **O-Q9 (row 4, verification facts).** `VerificationEntry` has no attempt number. Built: attempts =
  the operation's `enroll.verify.started` receipts; entries in the attempt = its entries reserved at or
  after the latest of them; at the verification stage = operation `running`, enrollment `verifying` or
  `reverifying`, and ≥ 1 started attempt. Authorization: a presence/absence `enrollment.verify` naming the
  enrollment is authorized; `enrollment.apply` (its `EnrollAccount` basis) and a target change (its
  `ApproveTargetChange`) are unauthorized in wave 0 (`operation_not_verifying`). The plan's pair and CA
  are the enrollment record's. No event is emitted for verification reserve/publish/void (U5 decides).
  Publish/void use an in-memory map of this instance's reservations (`Inner::managed_ops`), so an entry
  reserved before a restart is never published (it stays counted).
- **O-Q10 (row 10, what is recorded).** The merged (strictest) applicable policy's lock behaviour and
  connection policy, narrowed by the request's `connection.existing: strict`, are recorded in the
  creating transaction; a **default** value is recorded as absent, so M01/M02 origins stay byte-identical.
  The store already refuses any later change (`Txn::set_grant_origin` fills only `covered`/`adapter`).
  For an owner-decision grant the approval prompt's own choice (D9 item 2) is U10's.
- **O-Q11 (row 22).** Journaling `SetPreference` under `catalog` needs a `CatalogAction` variant: added
  `CatalogAction::SetPreference { destination, account, mechanism }` and its `from_request` arm to
  `crates/domain/src/catalog.rs` (A1's file; additive, marked `// M03 wave 0 (O)`). Also built: the
  destination must exist (`NOT_FOUND`); `existing` is a narrowing catalog action (no safe-time wait);
  `existing` on a pair with no stored preference changes nothing; `setup apply` does not mark a
  preference `applied` in wave 0 (the managed projection is U10's). Hooks: `Operations::add_issuing_ca(pair,
  ca, e5)` (refused `pair_not_enrolled` unless `ca` is verified for the pair; `e5` sets managed/pending
  only when not already managed+applied) and `Operations::remove_issuing_ca(pair, ca)` (back to
  `existing`/pending when no verified CA remains), in `crates/app/src/catalog.rs`.
- **O-Q12 (row 11, the lock source).** Agent G owns `Inner.narrowing.lock_source` and
  `Operations::set_session_lock_source` (`operations/authorize.rs`); the policy path reads that source (no
  second one). No source (wave 0 runtime) or `unavailable` refuses `revoke_on_lock` with
  `lock_signal_unavailable`. Linux's `signal_unverified` warning is not added (U9).
- **O-Q13 (E10).** Before a remote mutation's `Attempted` receipt: `CAPABILITY_UNAVAILABLE`,
  `driver_unavailable` (the cancel is allowed by the rule but its driver is U10's); after it:
  `remote_step_in_progress`, `next: reconcile`. Both write nothing. A settled or unresolved enrollment
  operation answers as M01 (idempotent, unchanged).
- **O-Q14 (row 12).** `mechanism_refuses` now refuses a degraded grant only when its reason's
  `sign_rule()` is `Refuse` (today exactly `mechanism_unavailable`, so M01 behaviour is identical);
  `credential_reissue_pending` (`NoKey`) is the signer's refusal, never the re-issue's. The rule is the
  public free fn `operations::degraded_refuses_use`.

## Q4, ruled (orchestrator)
Accepted: no `interaction_required` reason in wave 0. Whichever later unit first produces it adds it to the
reason table (`reason::M03`) and the golden (`tests/contracts/golden/m03-reasons.golden.json`).

## R

# M03 wave 0: questions and escalations from agent R (runtime rows 6, 7 supervisor, 8, 13, 14, 17, 23, 28; E7; §5 item 22)

Each item names the fail-closed reading built now. None is decided by R.

## R1. Row 23: what "resumes at start" may do without an issuer child (escalated reading)
* ADR-0008 D4 item 3 (`docs/decisions/0008-managed-credential-integration.md:899–909`): `retiring → unloaded`
  needs the child's unload confirmation; `unloaded → deleted` needs the store item deleted and a re-read finding it
  absent; `deleted → retired` needs nothing external. Wave 0 has no issuer child and no store step.
* Built: `Operations::resume_ca_retirements(issuer: Option<&dyn IssuerPort>, store_items: Option<&dyn
  CaStoreItemDeletion>)` (`crates/app/src/operations/restart_m03.rs`). Each step is a CAS persisted only after its
  effect is confirmed. Restart recovery calls it with `None, None`: `retiring` and `unloaded` stay (listed
  `stalled`), **`deleted → retired` completes** (store-only step; the plan names only `retiring`/`unloaded`, the ADR
  says "each step is idempotent"). `do_not_load` = every CA not `pending`/`active`: the value U3 must hand to the
  issuer child ("told not to load a `retiring` CA"); wave 0 has nobody to tell, so it is only returned and logged.
* `CaStoreItemDeletion` is a new small **synchronous** trait in `app::operations` (the issuer crate's `SecretStore`
  is synchronous), not in `app::ports` (A2's file). Options: (a) keep it there; (b) move it to `app::ports` beside
  `IssuerPort` (integrator/A2). Also: should `deleted → retired` wait for an issuer as well (option: stop at
  `deleted`)? R's reading: complete it.

## R2. Row 28 / E9: the shared parser has no start-time-only entry
* `heimdall_domain::procstat` exposes only `parse`, which requires the process group ≥ 1 (`procstat.rs:57`). E9
  reading (a) asks for "a start-time-only entry … or an equivalent".
* Built (equivalent, in `crates/runtime/src/platform.rs::stat_start_time`): call `parse`; if it refuses with
  `BadProcessGroup` alone, call `parse` again on the same text with that one token read as `1`; then apply the
  `Z`/`X` rule. All other validation is the shared parser's. The test keeps the old rule verbatim as the oracle and
  agrees on > 1000 synthetic lines (group 0 included).
* Documented deltas, all for text no kernel produces: a multi-letter state (old accepted, new refuses), a start time
  with leading zeros (old kept the text `007`, new yields `7`), a start time beyond `u64` (old accepted, new
  refuses). Non-UTF-8 `comm` is unchanged only because `read_to_string` is kept (it returned `None` before and
  still does; with byte reading it would parse). Request (A1/X, owner of `procstat.rs`): add
  `procstat::start_time(text) -> Result<(char, u64), ProcStatError>` (no group requirement) and R's helper becomes
  one call.

## R3. §5 item 22: `lock_behavior` exists as a typed M01 key (`[session] lock_behavior`)
* `crates/runtime/src/config.rs:19–50` has `SessionConfig.lock_behavior: LockBehavior {Continue, Revoke}` (M01, spec
  §6.4), exercised by `tests/integration/runtime.rs:185`. Adding `lock_behavior` to the depth-wide
  `FORBIDDEN_KEYS` broke that M01 test, so the two keys are refused **under `[x]` only**, as the plan's wording says
  (`FORBIDDEN_UNDER_X`; `registry_path` outside `[x]` is an unknown key, refused by `deny_unknown_fields`).
* Open question (integrator/ADR-0008): in M03 lock behaviour is a standing policy (`StandingPolicy.lock_behavior`,
  widening needs an attended decision). Does the M01 config key `session.lock_behavior = "revoke"` still mean
  anything, is it ignored, or should it be retired (a config schema change)? Nothing reads it in wave 0 as far as R
  saw; R changed nothing about it.

## R4. Row 6: what happens to settled bounded obligations, and two one-line edits in M01 code
* Built (`Operations::settle_bounded_obligations`, run by `Supervisor::revocation_pass` only when a record holds a
  bounded obligation, so M01/M02 passes are byte-identical): a grant whose every obligation in every record is
  `bounded_complete`/`nominally_expired` moves `revoking → revoked`; a record left holding only such obligations is
  **removed**; in a record with other work a `nominally_expired` obligation stays recorded as such. No event names
  the residual status (no `CredentialLifecycleEvent` variant fits); a later unit may want one ("never shown as
  cleared" is then visible only in the record while it exists and in the pass report). Option: keep settled records
  (they would linger forever) — R chose removal.
* Two edits outside the restart region of `operations.rs`, required for "no adapter call, no attempt counted":
  `plan_obligation_calls` skips non-`needs_remote_action` obligations (no call, no attempt, no reason), and
  `complete_round_in` never lets an adapter confirmation clear a bounded obligation (found by the test: the
  obligation's adapter identity matched the configured fake and its answer cleared it). Both are no-ops for M01/M02
  records (every one is `needs_remote_action`).

## R5. Row 13: order of the owner-role refusal
* Built: attended-only check (dispatcher, as before) → **owner role** for `Enrollment::{Step, StepResult,
  Reconcile}` and `Connections::{Close, Register}` (`CAPABILITY_UNAVAILABLE`, no reason, effect `none`, message
  "this request needs the owner role") → `driver_unavailable`. Reason: authorization before capability, so a non-owner
  learns nothing about which drivers this build has; neither answer touches the store. The other M03 requests answer
  `driver_unavailable` to any role. Is a reason wanted for the role refusal (none exists in `reason::M03`)? The M02
  precedent (`setup`, `catalog`) has none.

## R6. Row 17: `owner_reconcile` has no constant in the contract
* E8 says the M03 reason list is separate; `owner_reconcile` is a `runtime_lifecycle` payload value, not an error
  reason, and is not in `reason::M03`. Built: `heimdall_app::operations::OWNER_RECONCILE`. Option: move it to the
  contract (`envelope::reason` or an event-payload module) when ADR-0006 rev 4 lists it.

## R7. Row 7: back-off scope and cap
* Built in `Supervisor::revocation_pass`: only when some configured adapter has `remote_credential_effect`, each
  cleanup intent runs on its own schedule (new: at once; kept: after `retry_delay(revocation backoff, n, jitter)`;
  capped at `max_attempts` processings per process, then kept for the next restart, which processes every intent
  once). Without such an adapter the M02 path (`process_cleanup_intents`, every intent every pass) is unchanged.
  While a remote-effect adapter is configured, an intent kept for another reason (its applying adapter not
  configured) is backed off too. G's app part (`keep_intent` on a timed-out remote-effect call) is in
  `operations.rs` and calls R's `process_cleanup_intent_reporting` contract; R's test covers both.

## Requests to other owners
* A1/X (`crates/domain/src/procstat.rs`): R2's `start_time` entry.
* Integrator: `tests/model/narrowing_m03.rs:252` (G's) failed `clippy --all-targets -D warnings` (`type_complexity`)
  during R's first clippy run; a later run of the same command exited 0 (resolved by its owner).

## S

# M03 wave 0: questions from agent S (store: migration 0006, ext_m03)

Each names the choice taken (the most fail-closed one) and the options.

## S1, ruled: the partial UNIQUE index versus removing an abandoned line
Original question: once a (pair, CA) had a new open enrollment, the plan's index (excluding only final
states and `abandoned`) refused `abandoned → removing`, so the old line could not be removed.

Ruling (orchestrator): the index exists so each (destination, account, CA) has at most one **live**
enrollment, and a removal in progress is not a live enrollment.
1. The index covers only the enrollment-path states: `planned`, `applying`, `outcome_unknown`,
   `verifying`, `applied_unverified`, `verified`, `reverifying`, `held`. It excludes every removal and
   rollback state (`removing`, `remove_unknown`, `removal_verifying`, `manual_removal_pending`,
   `rollback_pending`, `rollback_unknown`), `abandoned`, and every final state.
2. Cancelling a removal returns the row to its persisted `removal_origin` (ADR-0008 §17.4 item 5). From an
   abandoned origin that is `abandoned` (outside the index). From an enrollment-path origin the row was
   already the pair's one live enrollment, so a second live row cannot normally exist; a cancel that would
   collide fails cleanly (`GenerationConflict`), never silently.

`manual_pending` (the system form's enrollment-path state) is inside the index: the integrator added it as
fail-closed and the orchestrator confirmed it is covered by the ruling.

Applied:
* `0006_managed_credentials.sql` (edited in place; not shipped): `WHERE state IN ('planned', 'applying',
  'outcome_unknown', 'applied_unverified', 'manual_pending', 'verifying', 'verified', 'reverifying',
  'held')`, a positive list, so a future state is outside the index only by an explicit decision.
* `ext_m03` unit test `indexed_states_are_the_enrollment_path`: the list equals the domain's states that
  are not final, not `abandoned` and not a removal or rollback state, and equals the SQL's list.
* `Txn::transition_enrollment`: the domain `transition` decides the target and the CAS writes it. An
  `OwnerCancelsManualRemoval` or `AbsenceVerified` event whose `origin` (and `ca_not_held_seen`) differs
  from the record's persisted `removal_origin` is refused (inner `Err(InvalidTransition)`, nothing
  written). A move onto the enrollment path that collides is a `GenerationConflict`.
* Tests: `removing_abandoned_line_while_new_enrollment_open_is_allowed`,
  `cancelling_that_removal_returns_to_abandoned` (also covers the wrong-origin refusal and a colliding cancel
  back to `verified`), `second_live_enrollment_for_pair_and_ca_still_refused` (every live state blocks,
  every other state does not, and `abandoned → removing → held` beside a live enrollment conflicts).

## S1 follow-up, ruled
1. **Confirmed:** a cancel (or absence result) naming an origin other than the persisted `removal_origin` is
   refused and writes nothing (the fail-closed addition to `transition_enrollment` stays).
2. **Ruled:** `held` reached by a removal is a residual, not a live enrollment. A `held` row whose
   `removal_origin` is set is outside the uniqueness index; a `held` row reached on the enrollment path
   (`removal_origin` unset) stays inside.

Applied (0006 edited in place, unshipped):
* `enrollments.removal_origin_set INTEGER NOT NULL DEFAULT 0 CHECK (removal_origin_set IN (0, 1))`, written
  by every enrollment write (`write_new_enrollment`, `transition_enrollment`) from the same record that
  becomes `record_json`. Every enrollment read selects it with `state` and refuses a row where either
  disagrees with the document (`StoreError::Corrupt`), so the column and the JSON cannot silently diverge.
  No JSON function in the index predicate.
* Predicate: `WHERE state IN (<enrollment path incl. manual_pending>) AND NOT (state = 'held' AND
  removal_origin_set = 1)`. The `ext_m03` unit test also asserts the exclusion clause.
* Tests: `removal_held_residual_outside_index_beside_live_enrollment` (abandoned → removing → held beside a
  live planned enrollment of the same pair and CA: no conflict; the residual can be removed again);
  `second_live_enrollment_for_pair_and_ca_still_refused` updated (the residual is allowed; leaving it onto
  the enrollment path, `held → applied_unverified`, conflicts with nothing written; an enrollment-path
  `held` without a removal origin still blocks a second live row).
* Callers: the residual is outside the index only if the caller sets `removal_origin` in the record it
  passes for the move into removal; without it the `held` is treated as live (fail closed).
* Not tested: the column/document disagreement read (no public way to write a disagreeing row).

## S2. `verified_cas_for_pair` leaves out `reverifying`
Evidence: `EnrollmentRecord::issuable(reverify_from)` counts `reverifying` that started from `verified`, but
the record does not store where a `reverifying` run started, so the store cannot tell.
Built: only `verified` counts (fail closed: a pair being re-verified from `verified` is briefly not issuable
through this read). Options: (a) keep; (b) A1 adds `reverify_from: Option<ReverifyFrom>` (serde default) to
`EnrollmentRecord` and the store counts `reverifying` with `Some(Verified)`.

## S3. `IssuerRecord.store_kind` cannot hold the test store kind
Evidence: `contract::issuer::StoreKind` has no test variant (F23); plan §5 item 2 says test builds
"register it through a test-only path". The `issuers` row's `record_json` is typed with `StoreKind`, so a
`scratch_test` row would not decode.
Built: typed `StoreKind` (U4 decides the test-only path). Options: (a) the scratch store registers a real
`StoreKind` value plus a testkit-side marker; (b) the store gains a `#[doc(hidden)]` store-kind string
column/field for test builds.

## S4. E12 and `open_read_only` on a schema-5 file
Evidence: `Store::open_read_only` refuses any older schema with `OlderSchema` (unchanged behaviour), so a
read-only open never reaches a schema without `enrollments`. `uninstall_cmd.rs:272` (`read_counts`) on an
M02 file that M03 never migrated still fails as it did for schema 4 under M02.
Built: `Txn::open_enrollments` treats a missing `enrollments` table as "none" (tested through
`Store::open_at_schema_version(.., 5)`), and `open_read_only` is unchanged.
Options: (a) keep; (b) a separate read-only open that accepts an older schema (a behaviour change, so the
integrator's call).

## S5. Foreign keys beyond the plan's list
Added: `managed_slots.binding_id → bindings(id)`, `owned_connections.binding_id → bindings(id)`,
`owned_connections.grant_id → grants(id)` (both parents are never deleted; M02's `binding_holders` and
`grant_prepared_facts` do the same). Not added: any `operation_id` FK (operations are purged by retention)
and any `destination_id` FK (destinations can be removed). `foreign_removals` has none (F07). Confirm.

## S6. Not done here, for the owners of these files
* `ext::TableCounts` (uninstall's purge counts, ADR-0007 §12.32 item 7) counts no M03 table (ext.rs is not S's).
* No methods yet for the `session_lock_last` and `windows_environment_pipe_token` meta keys (U9/U2 add them).
* `Txn::seed_enrollment` is a `#[doc(hidden)]` test-support insert in any state (for model tests that need a
  `verified` enrollment); production uses `insert_enrollment` (`planned` only).

## T

# Questions from T (validation tools), M03 wave 0

## Q1. How does an M03 evidence record represent "verified for that platform row"?
`tests/evidence/record.schema.json` has no platform-row field. The M02 records
(`tests/evidence/m02-exit-claims.json`, README "One record, one row per platform") use
`observed_result.rows[]`, each row `{ "platform": "macos-arm64 (build host)", "status": ... }`.
`tools/validation/claims_table.py` therefore matches a claim's `platform.os`/`platform.arch` against
`observed_result.rows` (a list, or a mapping keyed by platform) by the row's `platform` string (first
token `macos|linux|windows`; arch token `aarch64|arm64` or `x86_64|x64|amd64`), or by `os` and `arch`
keys. Fail-closed rule: at least one matching row, and **every** matching row must be `verified`.
Consequence to confirm: an M02-style record with an extra row such as `"macos-arm64 ordinary ssh without -F
(a real ~/.ssh/config)"` also matches `macos/aarch64`, so a blocked sibling row would block the claim. If
the M03 records (`m03-a03`, `m03-a07`, `m03-a23`) should instead carry an explicit per-claim marker (for
example `rows[].claims: ["lock_continuity"]`, or one row per `field`), say so and the matcher changes.
Option A (current): platform-string match, all matching rows verified. Option B: a row must name the
claimed field. Evidence: the real record check run against `m02-exit-claims.json` reports 11 non-verified
macOS-arm64 rows.

## Q2. product_store_kinds and CUSTODY_FIELDS are mirrored in the validator
`claims_table.py` keeps a mirror of `CUSTODY_FIELDS` (`["lock_continuity"]`) and `product_store_kinds`
(macos: `macos_login_keychain`, `macos_data_protection_keychain`; windows: `windows_dpapi`; linux:
`linux_secret_service`) and fails if `crates/domain/src/claims.rs` disagrees (the brief asked for read-or-mirror
with an agreement check). Adding a custody field or a store kind in Rust therefore needs the same edit in
`tools/validation/claims_table.py` (`MIRROR_*`). `scratch` and `scratch_test` are rejected for a custody claim
regardless of the Rust table.

## Q3. Registry-purity rule is covered inside an existing self-test name
The brief names exactly three crate-graph self-tests plus a positive control. The `heimdall-registry` purity
mutant (`registry -> store` rejected) is asserted inside
`crate_graph_step_rejects_cycle_and_ipc_to_app_edge` rather than under a fourth name.

## Q4. release-gate probes for the M03 variables use `service run` only
The M03 variables are expected to join `testcfg::requested()` (the `service run` gate and the TUI gate). If the
refusal instead lands in another command, add it to the probe list in `tools/validation/release-gate.sh`
(the `for v in ${service_vars}` loop). A probe passes only on exit 2 **and** the refusal text (`HEIMDALL_TEST_`
or `test configuration`) **and** an untouched scratch HEIMDALL_HOME; the M03 refusal message must keep one of
those two substrings.

## V

# M03 wave 0: questions and escalations from the verifier (agent V)

Base `410ec237`. Evidence is `file:line` at that commit; the full reading is in
`docs/architecture/m03-wave0-verify.md` §5 (same numbering). Nothing here is decided. "Reading used"
is the fail-closed choice wave 0 can build against.

## E1. `domain::verification::check` has no owner for its body
* Plan U0 (`m03-plan.md:344`) freezes `verification::check` as "signature only". U0b row 4 (phase 1, `:494`)
  calls it and tests "one refusal per predicate". ADR-0008 D5 §6.5 item 2 and D3 (`:701`) define the predicates.
  No other plan line mentions the function.
* Options: (a) U0b phase 1 writes the body (pure, like `issuance::check`); (b) row 4 moves to phase 2;
  (c) U0 ships a refuse-everything body and row 4's per-predicate tests wait.
* Reading used: (a). Owner: integrator.

## E2. `enrollment_recovery_paths_each_tested` needs tests and a case index that do not exist in wave 0
* Plan `:424`, `:433`; ADR-0008 `:1147`, `:3250`. Targets are U5/U10 tests; the case index
  (`tests/native/m03/case-index.json`) is U13's; `tests/native/m03` does not exist.
* Options: (a) structural half now (stable path IDs in `domain::enrollment`, each naming a planned test;
  the existence check `blocked` until U5/U10/U13); (b) `ignored` with the missing input recorded; (c) move to U13.
* Reading used: (a), existence half reported `blocked`. Owner: integrator.

## E3. Row 16: "check.sh's release-gate step" does not exist; the release refusal is narrower than described
* `tools/validation/check.sh:91`–`:145` builds nothing in release mode. The refusal exists only in
  `service run` (`heimdall/src/service_cmd.rs:113`–`:118`, over `ALL_ENV` = `[&str; 7]`, `testcfg.rs:203`) and in
  `launch_hooks` (`testcfg.rs:150`–`:157`). `main.rs:15`–`:30` has no early check. `release_build_ignores_m03_test_gates`
  never existed.
* Options: (a) add the variables to `ALL_ENV`, an early check in `main`, and a `check.sh` step building
  `-p heimdall --release` once and running it with each variable; (b) restrict the claim to `service run`;
  (c) unit-test `testcfg::refusal(false, true)` and record the release build as `blocked`.
* Reading used: (c) now, (a) proposed. Owner: integrator (T owns `check.sh`).

## E4. "M01's 'not available in this build' envelope" is retired and guarded against
* `heimdall/src/cli.rs:12`–`:14` (retired, ADR-0007 §12.30 item 4); `cli.rs:1808` fails if any M02 source line
  contains the phrase; `tests/e2e/cli_m01.rs:1884`–`:1976` fails if any M02 command prints it.
* Options: (a) M03 commands answer `CAPABILITY_UNAVAILABLE`/`driver_unavailable`, exit 4, wording without the phrase;
  (b) reuse the phrase and amend both tests; (c) `USAGE_ERROR`, exit 2.
* Reading used: (a). Owner: integrator (U0, U12).

## E5. Row 1: `SigningSession.peer: PeerInfo` is the wrong type for the signing endpoint
* `PeerInfo` is the control hello's software name/version (`contract/src/ipc.rs:63`). The signing accept loop has
  `PeerIdentity` (`ipc/src/endpoint.rs:104`, used `runtime/src/service.rs:767`ff). ADR-0008 D2 never names `PeerInfo`.
* Options: (a) `peer: PeerIdentity`; (b) a new ipc struct. Reading used: (a). Owner: integrator.

## E6. Row 20 cannot be built as worded in four respects
* (a) Environment-permission removal has no `operations.rs` path: permissions change only through
  `Txn::upsert_environment` (`store/src/ext.rs:828`; callers `app/src/holders.rs:305`, `heimdall/src/testcfg.rs:401`,
  tests); the withdrawal is found by re-validation (`grant_end` `operations.rs:2013` → `end_in` `:2077`).
  Options: covered by the re-validation path; or a new `Operations::set_environment_permissions` that gates.
  Reading used: covered by re-validation, tested through the store.
* (b) Withdrawal at re-validation commits inside a blocking `write` closure (`end_in`, callers `:5675`, `:8566`,
  `:9568`, `:10233`, `:10388`, `:10536`); an async gate cannot be awaited there. Options: read-only detection, gate,
  then re-run `end_in` under the gates; or `end_in` returns the set and each caller loops. Reading used: the first.
* (c) The grant set of a cutoff narrowing (`Operations::policy`, `:9663`–`:9670`) is unspecified. Reading used:
  active or degraded grants of the policy's profile whose bound the cutoff lowers.
* (d) Ownership of `SigningGates` is unspecified: `Inner` (`:404`, built `:4929`) or `OperationsConfig`
  (`:360`, about 40 literals). Reading used: `Inner` + `Operations::signing_gates()`.
* Owner: integrator.

## E7. `issuer_endpoint_kind_reserved_never_bound` is false as worded
* `ipc::unix::Listener::bind(path, kind)` (`unix.rs:66`) and `windows::Listener::bind(name, kind, sid)`
  (`windows.rs:163`) accept `EndpointKind::Issuer`. The runtime binds Control and Signing only
  (`runtime/src/service.rs:648`–`:650`, `:690`–`:698`).
* Options: (a) refuse `Issuer` in both constructors; (b) a source-scan test that only Control and Signing reach a bind.
* Reading used: (b), (a) proposed. Owner: integrator (ipc).

## E8. Row 17's reason `owner_reconcile` cannot reuse `local_driver_unavailable`
* `app/src/operations.rs:5419`–`:5447` writes `driver_unavailable` (`:5428`). Plan `:2688` also lists
  `driver_unavailable (exists)` as an M03 reason, and the registry location is unstated:
  `contract::envelope::reason::ALL` is compared by equality with a transcribed M02 list
  (`tests/contracts/m02.rs:545`–`:628`), so M03 reasons need a separate list.
* Reading used: a second helper with `owner_reconcile`; a separate M03 reason list. Owner: integrator.

## E9. Row 28's validation changes `process_start_time` for some PIDs
* Linux `process_start_time` (`runtime/src/platform.rs:671`–`:692`) ignores the process group and accepts group 0
  (kernel threads; inference). The shared parser requires token 3 ≥ 1. `ProcStat` must also expose the state letter
  for the `Z`/`X` rule. Test `platform_start_time_uses_shared_parser_semantics_unchanged` and the validation disagree.
* Options: (a) `process_start_time` uses a start-time entry that does not require the group; (b) accept the change
  and rewrite the "unchanged" test. Reading used: (a). Owner: integrator.

## E10. No U0b row covers `Operations::cancel` for the enrollment kinds
* `cancel` (`operations.rs:8793`) special-cases setup and catalog (`:8816`) and settles anything else `cancelled`.
  Plan §5 item 11 and ADR-0008 §6.4 (`:1622`) require `CAPABILITY_UNAVAILABLE`/`remote_step_in_progress` once the E3
  `Attempted` receipt exists.
* Reading used: in phase 1, refuse always (no receipt can exist), write nothing. Owner: integrator (new row).

## E11. "M01 and M02 suites run unchanged" cannot be literal
* About 100 test literals break (StandingPolicy ~21, EnsureRequest 30, AdapterDescriptor 8, GrantOrigin 4,
  RemoteObligation ~7, Tombstone ~6, Enforcement 2, RevokeOutcome 1 …); `tests/integration/store.rs:1324`, `:4197`
  assert `SCHEMA_VERSION == 5`; `tests/contracts/m02.rs` sample list must cover the new `op`s; `ScriptedSigner`
  (`tests/adversarial/agent_frames.rs:58`) implements the old trait.
* Reading used: mechanical edits only (added fields at M01/M02-equivalent values; no assertion or scenario change),
  reviewed as such. Owner: integrator.

## E12. Row 18 needs a store read the plan does not list
* §5 item 18's `Txn` list has no "all non-final enrollments"; `Store::open_read_only` never migrates, so a schema-5
  file has no `enrollments` table (`uninstall_cmd.rs:272`).
* Reading used: `Txn::open_enrollments()` in `ext_m03.rs`; "table absent means none". Owner: integrator.

## E13. Plan statements that do not match the code (corrections)
* Row 19 `holders::holder_pass` is `Supervisor::holder_pass` (`supervisor.rs:440`) → `Operations::release_exited_holders`
  (`app/src/holders.rs:114`). M5's `BindForm::Launch { executable, holder }` is `Launch(LaunchBinding)` (`request.rs:532`).
  M13 is landed. `SETUP_V1`'s doc comment (`contract/src/ipc.rs:56`) is stale. §0.4 and U0b cite `7f6f1c05`/`1f5b8156`.

## E14. Exact-count source scan in `operations.rs`
* `tests/model/operations.rs:12832` pins `.reconcile(` ×4, `.revoke(` ×3, `.prepare_from(` ×1, 8 bound spans and one
  `.read_sources(` in the production part of `crates/app/src/operations.rs`. The plan does not say where the
  `ManagedEffects` calls (row 21) go.
* Reading used: `crates/app/src/managed.rs`. Owner: integrator.

## X

# M03 wave 0, agent X (independent goldens): disagreements and questions

These expectations come from m03-plan rev 6 and ADR-0008 rev 6 (the rulings win). I did not change
any code. Each failing test below asserts what the documents say.

## Disagreements (failing tests)

### X-D1. A foreign system-form record cannot cancel back to an `abandoned` origin
- Test: `model_managed_domain::enrollment_transition_table_golden`. Two pairs fail:
  * `manual_removal_pending [foreign_system] owner_cancels_manual_removal{origin: abandoned,
    ca_not_held_seen: false}`: the documents expect `abandoned`; the code refuses it.
  * the same with `ca_not_held_seen: true`: the documents expect `manual_removal_pending`; the code
    refuses it.
- Code: `crates/domain/src/enrollment.rs:776-797` (`cancel_target`). Its foreign branch accepts
  only the `planned` and `held` origins. But `transition` does let a foreign system record enter
  `abandoned → manual_removal_pending` (`ManualRemovalConfirmed`, origin `abandoned`; that golden
  row passes). So the code admits a removal it can never cancel.
- Documents:
  * ADR-0008 D5 §6.2, `abandoned` row: "`manual_removal_pending` (system; origin `abandoned`)",
    with no own-only restriction. `abandoned` is in the foreign subset (D4 item 5).
  * The `manual_removal_pending` row: a cancel returns to "the origin state … `verified`, `held`,
    `abandoned` or `manual_pending`, ⟨r4⟩ or `planned` for a foreign record".
  * D4 item 5 ⟨r5⟩ and §17.10 item 2: after `ca_not_held`, a cancel "leaves it in
    `manual_removal_pending`, or returns it to `held` when a held foreign record began the removal".
- Options:
  * (a) extend the foreign `cancel_target` to accept the `abandoned` origin (`false` → `abandoned`,
    `true` → `manual_removal_pending`). This is my literal reading.
  * (b) rule that a foreign record never re-enters a removal from `abandoned`. Then
    `abandoned → manual_removal_pending | removing` must also be refused for foreign facts, and the
    golden's two `abandoned` rows narrow to the own facts.
  * Either option is fail-closed. As the code stands, the two parts of the table do not agree.

### X-D2. Grant issuance accepts a `pending` CA
- Test: `model_managed_domain::issuance_refuses_pending_ca_for_grant_certificates`.
- Expected: refused, under any variant. Actual: `Ok(())`.
- Code: `crates/domain/src/issuance.rs`, `check_ca`, the arm `Some(CaState::Active | CaState::Pending) => {}`.
- Documents: ADR-0008 D4 item 3 says "A `pending` CA signs only verification certificates for its
  own enrollments", and "Issuance for a pair uses the **newest `active` CA** that the pair has a
  `verified` enrollment for". U0b row 3 says "newest `active` CA with a `verified` enrollment".
- `pending` plus a verified enrollment may be only a transient state, if E5 activates the CA in the
  same transaction. Even so, the predicate should refuse it (fail closed).
- Which variant should apply? `CaNotVerifiedForPair`, `UnknownCa`, or a new one? The test asserts
  only `is_err()`.

### X-D3. `DestinationClock` refuses an unknown sibling field
- Test: `contracts::examples::unknown_fields_are_tolerated_at_every_nesting_level` fails on
  `ensure-data.managed.json`, `revoke-data.managed.json` and `inspect.enrollments.json`.
- Error: `invalid value: map, expected map with a single key`.
- Cause: `crates/contract/src/managed.rs`, `DestinationClock` is externally tagged
  (`{"measured": {...}}`, the shape of m03-plan §5 item 8). A reader then refuses
  `{"measured": {...}, "x_future_field": …}`.
- Documents: ADR-0006 §9 and spec §11.2 say readers tolerate unknown non-critical fields, and
  m03-plan §5 says "readers built before M03 tolerate unknown fields". This is the first
  externally tagged object in the public examples; every M01/M02 example passes.
- Options:
  * (a) a hand-written `Deserialize` that keeps the wire shape and ignores keys other than
    `measured`, with the schema left open (`open_tagged_object` already strips
    `additionalProperties`);
  * (b) change the shape to an internally tagged object, which is a plan §5 item 8 change.

## Questions (pairs the documents do not determine; the golden's `unspecified` list skips them)

I recorded what the code does in each case. The test does not assert these.

- **X-Q1. Inputs that cannot arise.** These are an own record with `ca_not_held_seen: true`, a
  `ca_not_held` verdict on an own record, and the system form with `lock_holder_unresolved`.
  * Code: the own cancel with `ca_not_held_seen: true` is refused. A `ca_not_held` verdict in
    `verifying`/`reverifying` is treated as any other inconclusive result.
  * Concern: `held [own_system | foreign_system] manual_recovery_line_absent{lock_holder_unresolved}`
    gives `withdrawn`. For a foreign system record that is a final state with no absence proof.
    That conflicts with §17.10 item 2's "a residual that is known and unresolved is never
    discarded".
  * Recommendation (fail closed): refuse the manual-recovery events for the system form.
- **X-Q2. `reconcile_damaged` in `rollback_unknown` and `remove_unknown`.**
  * ADR §6.7 says "for a removal or rollback step, the same table applies", which gives a damaged
    line → `held`. The §6.2 rows for `rollback_unknown` and `remove_unknown` do not list that.
  * Code: refused. Which source wins: the table or §6.7?
- **X-Q3. Manual recovery of a removal held by `lock_holder_unresolved`.**
  * §6.7's `--after-manual-recovery` classification (one exact line → `applied_unverified`, none →
    `withdrawn`) is written for an append.
  * For a removal (own `remove_unknown`/`rollback_unknown` → `held`, or a foreign account record),
    the code applies the same events. So line absent gives `withdrawn`, where `removed` or
    `verification_failed` would be the truthful state. For an own record, line present gives
    `applied_unverified` and loses the removal purpose.
  * The ADR does not say. The golden marks the foreign line-absent case unspecified and keeps the
    literal reading for the own account form.
- **X-Q4. `plan_digest` form.**
  * m03-plan §5 item 3's JSON shows `"plan_digest": "sha256:…"`.
  * The same section's Rust sketch and the code use `PlanDigest`: 64 lowercase hex characters with
    no prefix (`crates/contract/src/setup.rs:36`).
  * The examples use bare hex. Only the plan text needs fixing.
- **X-Q5. `consumer.pairs` in the managed `ensure` example (§5 item 8, shown as `["…"]`).**
  * `PairIntegration` (`crates/contract/src/request.rs:612`) is the existing-access shape. It
    requires an adopted `identity` and an interaction basis.
  * No shape is defined for a managed pair's entry. `ensure-data.managed.json` omits `pairs`.
- **X-Q6. No public schema for the inspect views.**
  * §5 item 23 says "the `ensure-data`, `revoke-data` and `inspect` schemas are regenerated", but
    `public_schemas()` has no inspect schema.
  * `inspect.enrollments.json` and `inspect.connections.json` therefore validate only against the
    schemars-generated schema of `EnrollmentsView` and `ConnectionsView`, inside the test.
  * Whether to publish schema files for them is a decision for ADR-0006 rev 4.
- **X-Q7. `Connections::Register` in the plan.**
  * m03-plan §5 item 4a has no `image`. ADR-0008 D8 (line 2303) and U0b row 26 have it, and the
    code follows the ADR.
  * Only the plan text needs fixing.
- **X-Q8. The `valid_after` rule in `verification::check`.**
  * ADR §6.5 item 2 says `valid_after` = now − 60 s. The code accepts any `valid_after ≤ now` within
    a 360 s window (`crates/domain/src/verification.rs`, `check`).
  * Exact equality cannot hold at publish, so I tested only clear violations: a future
    `valid_after`, and an hour of backdating. Please confirm the looser predicate is intended.

## Requests to other owners
- `tests/fixtures/MANIFEST.md` has no row for the new `tests/fixtures/procstat/` set (synthetic,
  README included). The integrator may add one.
- `enrollment_recovery_paths_each_tested` checks that each named test appears under its owner's
  unit in m03-plan. It does not check that the test exists. That check becomes enforceable when
  U5 and U10 land; the index statuses then move from `planned`.
