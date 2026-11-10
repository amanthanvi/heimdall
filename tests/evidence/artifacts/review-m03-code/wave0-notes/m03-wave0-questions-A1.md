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
