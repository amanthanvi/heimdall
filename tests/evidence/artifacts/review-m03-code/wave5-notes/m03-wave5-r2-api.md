# M03 wave 5, round 2: shared seams

## R0 (landed by C)

Every seam is additive: `#[serde(default)]` and omitted when absent, so earlier wire forms, stored
records and goldens are byte-identical. Nothing below is filled or emitted yet: every new field is
`None` (or empty), and the new request fails closed. Recorded in ADR-0006 §16.5 (one row per item),
§16.1 row 14 (the warning reason), and m03-plan §0.4 M2 and §5 item 14. Open shape choices: questions
C-Q1 to C-Q5.

### Item 4: `EnrollmentView.hold` (filled by E2, read by T2)
- Type: `heimdall_contract::enrollment::EnrollmentHoldView { reason: String, next: Vec<String> }`
  (`crates/contract/src/enrollment.rs:833`). Field `EnrollmentView.hold: Option<EnrollmentHoldView>`
  (`:827`).
- Wire: key `hold` on each `inspect enrollments` item:
  `{"reason": "<HoldReason snake_case name>", "next": ["<command>", ...]}`. `next` is omitted when
  empty, and `hold` is omitted when `None`.
- `reason` is the `snake_case` serde name of `heimdall_domain::enrollment::HoldReason`
  (`principals_not_enforced`, `positive_refused`, `host_key_changed`, `lock_holder_unresolved`,
  `registry_line_damaged`, `registry_changed`, `registry_not_rewritable`,
  `post_write_check_failed`). It is a `String`, as `data.error.reason` is, because `HoldReason` lives
  in `domain` (C-Q2).
- `next` is the ordered commands or manual instruction, as `EnrollmentResult.commands` carries
  commands. A host-key change has two exits, so it is not one `NextAction` or `String` (C-Q1).
- Today it is `hold: None` at `crates/app/src/operations/enrollment_m03.rs:1079` (the view builder).
  E2 fills it there from `r.hold` and computes `next` in app, so the CLI and the TUI share it.
- The round-1 TUI reads `next` as a string (`tui/m03.rs:273`). T2 must read the array.

### Item 8: `IssuerRequest::BundleWritten` (filled by IS2; sent by the CLI)
- Variant: `IssuerRequest::BundleWritten { created_at: Timestamp, sha256: String }`
  (`crates/contract/src/issuer.rs:85`). Wire:
  `{"op":"issuer","action":"bundle_written","created_at":"<RFC 3339>","sha256":"<64 lowercase hex>"}`.
  Example: `schemas/examples/request.issuer.bundle-written.json`.
- Kind `issuer.bundle_written` (`issuer.rs:104`). Admission `Synchronous` (`request.rs:1084`), because
  it writes. Capability `issuer/1` (the existing `Request::Issuer(_)` arm), not attended-only. Not
  in `owner_only_m03`, but `issuer_request` already refuses any non-owner first.
- Golden: `journaled-kinds.golden.json` `synchronous` gains `issuer.bundle_written`.
- Shape choice: a new variant, not a field on `Bundle`. `Bundle` is `ReadOnly`, and a write inside it
  would break the admission class and its "read-only" journal reading.
- Dispatch: the existing `Request::Issuer(r) => ops.issuer_request(..)` arm covers it
  (`crates/runtime/src/dispatch.rs:333`). No dispatch edit was needed.
- Fail-closed placeholder: `crates/app/src/operations/issuer_m03.rs:567` returns
  `OpError::driver_unavailable(..)` (`CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, effect
  `none`). It records nothing. IS2 replaces that arm.
- Store (`crates/store/src/ext_m03.rs`), beside `last_bundle_at`, with no migration:
  - `Txn::record_bundle_digest(&mut self, sha256: &str, created_at: Timestamp) -> Result<Timestamp>`
    (`:1919`). It writes `meta` key `issuer_bundle_sha256:<sha256>` (`META_BUNDLE_DIGEST_PREFIX`,
    `:63`) with value `created_at`, never lowers it, and returns the stored value.
  - `Txn::bundle_digest_recorded_at(&mut self, sha256: &str) -> Result<Option<Timestamp>>`
    (`:1941`).
  - Both refuse anything but 64 lowercase hex characters with a store error, so nothing else is
    recorded (`bundle_digest_key`, `:2001`). The path is never stored.
  - The existing `set_last_bundle_at`/`last_bundle_at` are unchanged. IS2 decides the semantics,
    including whether to call both in one transaction. A digest does not move `last_bundle_at`.
  - Unit test: `ext_m03::tests::bundle_digest_records_never_lower_and_refuse_other_forms`.
- Still in place: `RECORD_LAST_BUNDLE_AT_ON_REPLY = false` (`issuer_m03.rs:259`) and U's
  `BUNDLE_WRITE_RECORD_REQUIRED` (`heimdall/src/uninstall_cmd.rs`). Their owners resolve them.

### Item 15: `Warning.reason` and `time_confirmation_after_reboot` (emitted by R2 or the runtime owner, read by T2)
- Field `heimdall_contract::envelope::Warning.reason: Option<String>`
  (`crates/contract/src/envelope.rs:98`). Wire key `reason`, omitted when `None`.
- Constants: `m03_warning::TIME_CONFIRMATION_AFTER_REBOOT = "time_confirmation_after_reboot"` (`:557`),
  and `m03_warning::REASONS: &[(&str, &str)] = &[(TIME_CONFIRMATION_AFTER_REBOOT, "TIME_UNCERTAIN")]`
  (`:561`), as (reason, the warning code it refines).
- Golden: `m03-reasons.golden.json` key `warning_reasons: [{"reason", "warning"}]`. It is checked both
  ways in `contract_reason_golden`, and fails (exit 101) when the row is changed.
- Where it goes: the passive-read `TIME_UNCERTAIN` warning at `crates/app/src/operations.rs:8646`
  (`inspect`) has `reason: None` today. Set it to `Some(TIME_CONFIRMATION_AFTER_REBOOT)` only when the
  cause is no time reference for this boot (§17.25 item 15). It must not be set for skew or rollback.
- Every other `Warning { .. }` literal got `reason: None` (C-Q3).

### Item 18: `PrepareOutcome.managed` (filled by R2)
- `heimdall_app::ports::PrepareOutcome.managed: Option<ManagedResultFacts>`
  (`crates/app/src/ports.rs:259`).
- `heimdall_app::ports::ManagedResultFacts` (`:268`) derives `Debug, Clone, PartialEq, Eq` and has
  public fields:
  - `lock_continuity: LockContinuityReport`
  - `conditions: Vec<ReadinessCondition>`
  - `refresh_condition: RefreshCondition`
  - `revocation: RevocationSemantics`
  - `evidence: Vec<EvidenceEntry>`
  - `connection_policy: ConnectionPolicyReport`

  They are the `EnsureData` fields' contract types (`heimdall_contract::managed`), not wrapped in
  `Option`: the adapter's `ManagedReport` has all six, and absence is `managed: None`. `ensure_data`
  copies the scalar ones as `Some(..)`.
- Every `PrepareOutcome { .. }` literal in the workspace has `managed: None`, including
  `adapters/src/managed/prepare.rs` (R2 fills it from `report::compute`, on prepare and on reissue)
  and the restart rebuild in `operations.rs` (~6510, stays `None`).
- Carrier: `Facts.managed` (`crates/app/src/operations.rs:4838`). `from_outcome` copies
  `o.managed.clone()` (`:4851`). `from_data` and `conservative` are `None` (fail closed after a
  restart or replay).
- It carries `#[allow(dead_code)]` until R2 reads it in `ensure_data` (`:5142`, unchanged). Remove the
  allow then.
- Not stored: `PreparedFacts` is unchanged. m03-plan §0.4 M2 records the amendment.

### Item 19: `inspect destinations` `preference.connection_policy` (untyped; filled by the app owner, read by T2)
- `destination_view` (`crates/app/src/operations.rs:5225`) builds untyped JSON, so no type was added.
- Key: inside an item's existing `preference` object (present only when a `pair_preferences` row
  exists), `"connection_policy": {"existing": <ExistingConnectionsMode>, "multiplexing":
  <MultiplexingMode>, "wording": "<runtime D8 wording>"}`. That is exactly the serde form of
  `heimdall_contract::managed::ConnectionPolicyReport`, so serialize that type.
- Omit the key when it cannot be computed (C-Q5). The round-1 TUI parser
  (`tui/m03.rs` `Preference::of`) already reads this key.

### Item 21: `inspect capabilities` `lock` (untyped; filled by the app owner, read by T2)
- The capabilities data is `serde_json::json!({"capabilities": [...]})`
  (`crates/app/src/operations.rs:8662`). No type was added.
- Key: top-level `"lock": {"behavior": <LockBehavior>, "disclosure": "<LockDisclosure.text>",
  "acknowledged_at": <Timestamp>}`.
  - `behavior` is `continue` or `revoke_on_lock`.
  - `acknowledged_at` is omitted while unacknowledged.
  - The values come from `Operations::lock_disclosure` (`crates/app/src/lock.rs`).
- The round-1 TUI reads `lock.behavior` and `lock.disclosure`.

### Item 22: the two M03 policy results (untyped; filled by the app owner, read by A2/T2)
- `policy_view` (`crates/app/src/operations.rs:12250`) builds `{policy_id, revision, paused, cutoff_at,
  changed}`.
- For `SetLockBehavior` and `SetConnectionPolicy` results only, add:
  - `"lock_behavior": <LockBehavior>`
  - `"connection": {"existing": <ExistingConnectionsMode>, "multiplexing": <MultiplexingMode>}`, the
    serde form of `heimdall_contract::managed::ConnectionPolicy`.
- Leave every M01 action's result unchanged. Which values to report (this policy's or the effective
  ones) is C-Q4; the recommendation is this policy's.
- The CLI's `output::m03_lines` already reads `lock_behavior`.

### Schemas, goldens, docs
- `heimdall schema export` regenerated 7 files, with additions only:
  - `envelope{,.ensure,.error,.revoke}.schema.json` and `ipc.server-message.schema.json` gain
    `Warning.reason`.
  - `request.schema.json` and `ipc.client-message.schema.json` gain `bundle_written`.
  - The configuration schema is untouched.
  - The `inspect` views have no schema file (ADR-0006 §16.2 item 18).
- Changed goldens, each by hand and additive: `tests/contracts/golden/journaled-kinds.golden.json`
  (one kind added) and `tests/contracts/golden/m03-reasons.golden.json` (`warning_reasons`, and its
  `source` sentence).
- No other golden changed.
- Contract tests added or extended:
  - `wave5_round2_additive_fields_round_trip_and_omit_when_absent`
  - `contract_reason_golden`
  - the issuer capability cases
  - the example list
  - `one_of_every_request`

## R1. Round-2 ownership (integrator; write only these + your worklog/questions heading/section)
Integrator readings on C's questions: C-Q1 (`next` a list) and C-Q2 (`reason` a string) are built as
proposed and stay open for the orchestrator; C-Q3 (C's `None` literals outside its grant) confirmed;
C-Q4: the two M03 policy results report **this policy's own stored values** (provisional); C-Q5:
`preference.connection_policy` only when the runtime can compute it, absent otherwise (provisional).

| Worker | §17.25 items | Owner files |
|---|---|---|
| **E2** enroll | 3, 4 (fill + CLI), 5, the 120 s typed-yes timeout | `crates/heimdall/src/{enroll_cmd.rs,enroll_cmd/**,prompt.rs}`; `tests/e2e/cli_m03/enroll.rs`; `crates/app/src/operations/enrollment_m03.rs` (except R2's ack edit, below); in `crates/app/src/operations.rs` **only** the `inspect Enrollments` handler fn (to fill `hold`); the runtime/app code that builds a step's script, wherever it lives (to insert the debug pause points from `ManagedOptions::script_pause_dir`; in `crates/runtime/src/service.rs` only the lines that pass that option through — tell R2 under Requests); moving `slot_free_command` to a crate `app` may depend on (e.g. `heimdall-domain`), re-exported from its old path so every caller compiles unchanged |
| **IS2** issuer | 7 (b)+(d), 8 (CLI confirmation + runtime record + `bundle_stale`), 9 (the shared retire entry), 10 (public, complete `disclosure_text`) | `crates/heimdall/src/{issuer_cmd.rs,issuer_cmd/**}`; `crates/issuer/src/**` (ceremony, retire, store); `crates/app/src/operations/issuer_m03.rs` (except R2's ack edit); `crates/store/src/ext_m03.rs` bundle accessors; **`crates/heimdall/src/testcfg.rs` and `m03_cmd::issuer_store`** (the selector, integrator-granted) plus `tools/validation/release-gate.sh` (a probe for the new selector value); `crates/testkit/src/ca.rs`; `tests/e2e/cli_m03/issuer.rs`, `tests/e2e/issuer_ceremony.rs` |
| **U2** uninstall/doctor | 8 (uninstall digest match), 9 (inline retire), 11, 12, 13 | `crates/heimdall/src/{uninstall_cmd,doctor_cmd}.rs`; `crates/localenv/src/doctor.rs`; `tests/e2e/cli_m03/uninstall_doctor.rs`; in `crates/heimdall/src/cli.rs` **only** `UninstallArgs` (item 11) |
| **R2** runtime/app/adapters | 15, 18, 19, 21 (incl. the ack fix), 22, 23 | `crates/app/src/operations.rs` (all except E2's handler fn), `crates/app/src/{lock.rs,operations/lock.rs,operations/narrowing.rs,operations/pair_mechanism_m03.rs}` and other `operations/*.rs` not listed for E2/IS2; the lock-ack recording sites in `issuer_m03.rs` and `enrollment_m03.rs` (named fns only, tell IS2/E2); `crates/adapters/**`; `crates/runtime/src/service.rs`; app/runtime/adapters tests |
| **T2** TUI | 4, 10 (Approve limit), 15, 19/20, 21 (read side) | `crates/heimdall/src/tui/**`; `tests/e2e/tui_m03.rs` |
| **A2** (after R2 and IS2) | 16, rendering items 19/22, managed halves of the access tests | `crates/heimdall/src/{connections_cmd,output,m03_cmd}.rs`; `tests/e2e/cli_m03/access.rs` |

Not anyone's: `crates/contract/**` (ask the integrator; §17.25 seams are landed), store migrations,
`app::ports` (beyond C's amendment), `Cargo.toml`/`Cargo.lock`, `crates/enroll/src/trace.rs` recorded rows.

## Requests

- **U2 → IS2 (item 9):** `uninstall_cmd::retire_offered` calls your
  `crate::issuer_cmd::retire_to_retired(&mut Client, &mut P, &Ctx, &CaFingerprint) -> Outcome`
  (generic `S: cli::Session, P: Prompter`) inline, before the runtime stops, only on an
  interactive terminal. Please keep that signature (or tell me under U2). It reads
  `out.env.code` (success → the item is `retired`) and `data.error.{reason,message}`.
- **U2 → integrator (item 11, your tests/docs):** `tests/e2e/cli_m03.rs:373`
  (`m03_cli_commands_answer_without_a_runtime_and_never_panic`): `uninstall
  --keep-remote-enrollments` is no longer a usage error; on a home with no state database it
  exits 0 and starts nothing (observed: `{"code":"OK",...,"runtime_stopped":false}`). Move it out
  of the usage list; line 374 (`--purge-state --bundle f`) stays exit 2.
  `uninstall_refuses_purge_with_live_enrollments` (~798) still passes; its comment naming
  `BUNDLE_WRITE_RECORD_REQUIRED` is stale (now: an unreadable/unrecorded bundle is
  `bundle_required`). m03-plan §5 item 24's synopsis row: `heimdall uninstall
  [--keep-remote-enrollments] [--purge-state [--bundle <file>]]`.
- **U2 → IS2:** `bash tools/validation/linux-xcheck.sh -p heimdall-localenv -p heimdall` exits 101
  on `crates/issuer/src/store/test_product.rs:162` (`write_marker` never used on Linux); 12 retries
  over ~6 min, so U2's Linux type-check is unconfirmed until that is gated.
- **U2 → T2 (item 12):** `doctor_cmd::pending_chores(&Ctx) -> Vec<PendingChore>` keeps its
  signature; its predicate is now the time gate's (`TimeGate::assess_read_only_in` →
  `Unsynchronized`) **and** an issuer CA registered. `time_confirmation_pending` changed to
  `(&TimeStatus, ca_registered: bool) -> bool` (the TUI does not call it today).
- [from E2 to T2] **E2-R1** (§17.25 item 4, landed): `inspect enrollments` items now carry
  `hold: {"reason": "<HoldReason snake_case>", "next": ["<command or manual step>", ...]}` for
  every record whose `state` is `held` and whose record has a `hold` (absent otherwise; `next`
  never empty when filled). Built in `app::operations::enrollment_m03::hold_view`. `next` per kind:
  `host_key_changed` -> [`heimdall enroll verify <e> --approve-target-change`, `heimdall enroll remove <e>`];
  evidence-based (`principals_not_enforced`/`positive_refused` with `evidence_based`) ->
  [`heimdall enroll verify <e>`, `heimdall enroll remove <e>`]; `lock_holder_unresolved` ->
  [manual step text (`LOCK_HOLDER_MANUAL_STEP`), `heimdall enroll reconcile <op> --after-manual-recovery`]
  (`heimdall enroll remove <e>` when no operation is open); any other -> [`heimdall enroll remove <e>`,
  `heimdall enroll abandon <e>`]. Read `hold.next` as an array of strings, verbatim.
- [from E2 to R2] **E2-R2** (§17.25 item 3; my grant: the pass-through lines only): in
  `crates/runtime/src/service.rs` `ManagedParts::start`, just before `let verifier = match (ssh, ...)`,
  I added 4 lines: `#[cfg(debug_assertions)] ops.set_script_pause_dir(m.script_pause_dir.as_deref());`
  plus a comment. Please keep them when you edit `start`.
- [from E2 to IS2] **E2-R3**: `bash tools/validation/linux-xcheck.sh -p heimdall` fails (exit 101) on
  `crates/issuer/src/store/test_product.rs:162` `fn write_marker` never used (dead_code, Linux
  target only). Please gate it like its callers.
- [from R2 to E2] **R2-R1** (§17.25 item 21, my granted ack edit): in
  `crates/app/src/operations/enrollment_m03.rs` I changed only `decision_apply` (the wrapper
  around `admit::decision_apply`: it now records `tx.set_lock_disclosure_ack(now)` after a
  successful `Approve` of a decision that displayed `lock_continuity_once`) and added the private
  helper `displayed_lock_disclosure(&DecisionKind)` right below it. Please keep both.
- [from R2 to IS2] **R2-R2**: no edit to `issuer_m03.rs`; its `RegisterIssuer` ack site
  (`decision_apply`, `tx.set_lock_disclosure_ack(now)` when `disclosures` contains
  `LockContinuityOnce`) already matches item 21. Please keep it.
- [from R2 to integrator] **R2-R3**: `tests/model/operations_m03.rs`
  `existing_access_prepare_contract_unchanged` failed (exit 101) on C's seam line
  (`operations.rs` `managed: o.managed.clone(),`): its source scan forbids any `.managed` read in
  `operations.rs`. I amended it to allow exactly the two `PrepareOutcome.managed` result-fact reads
  (`managed: o.managed.clone(),`, `let managed = facts.managed…`); the snapshot rule is unchanged.
- [from R2 to A2] item 22's keys and item 18's fields are in "### R2" below.
- [from IS2 to E2] **IS2-R1** (§17.25 item 10): the shared text is
  `heimdall_issuer::ceremony::disclosure_text(kind: DisclosureKind, context: &DisclosureContext<'_>) -> String`
  with `pub struct DisclosureContext<'a> { pub alias: Option<&'a str>, pub lock: Option<&'a str> }`
  (`Default`; `lock` = the runtime's `inspect capabilities` `lock.disclosure` when you have it) and
  `pub const UNKNOWN_DISCLOSURE: &str` (only for a kind this build does not know). It covers all 9
  kinds, including your two enrollment ones with the alias and `heimdall_domain::managed::slot_free_command`.
  Please make `enroll_cmd::render::disclosure_text(kind, alias)` a thin call
  (`heimdall_issuer::ceremony::disclosure_text(kind, &DisclosureContext { alias: Some(alias), lock: None })`)
  so the preview retypes nothing; the wording is now full sentences (capitalized, ending in `.`).
- [from IS2 to U2] **IS2-R2** (item 8, the digest read): exactly what you built:
  `heimdall_issuer::backup::sha256_hex(&bytes)` over the file's exact bytes, then on the read-only
  store `Store::open_read_only(&<state>/state.db, Arc::new(NoFaults))?.transaction(|tx|
  tx.bundle_digest_recorded_at(&sha))` → `Some(created_at)` iff this installation recorded it. The
  CLI sends `issuer.bundle_written {created_at: bundle.created_at, sha256}` only for an
  **unredacted** bundle, after `write_all` + `sync_all` (and a best-effort directory fsync), and the
  runtime records digest → `created_at` and `last_bundle_at = created_at` (both never lower). So a
  match also means "`created_at` == the recorded value": you may compare it with the file's
  `created_at` as an extra check.
- [from IS2 to U2] **IS2-R3** (item 9): `issuer_cmd::retire_to_retired<S: cli::Session, P: Prompter>(s:
  &mut S, p: &mut P, ctx: &Ctx, ca: &CaFingerprint) -> Outcome` is kept as you call it. It attends
  first (interactive TTY), sends `issuer.retire`, shows the `RetireIssuer` decision with its typed
  `yes` (through `p`), `Decide approve`, polls `issuer.status` until `unloaded` (60 s bound), deletes
  exactly the recorded locator (`retire::delete_awaiting`; a scratch test-kind item too in debug
  builds), confirms `deleted_locator`, then the CA's displaced items. Unattended it leaves the
  decision pending (exit 3, `next.decision_ref`). It needs the runtime up: call it before stopping it.
- [from IS2 to integrator] **IS2-R4**: `tests/integration/issuer_store.rs:1491-1495`
  (`retire::delete_awaiting(&a, ..)` on a `SecretStoreKind::Test` store `== Err(LocatorMismatch)`,
  "a test store is never a product store (S3)") contradicts §17.25 item 7 (d): in a debug build
  that call now deletes exactly `a_item` (b's item kept). Suggested assertion:
  `if heimdall_issuer::retire::TEST_STORE_DELETION { assert_eq!(.., Ok(())); assert_eq!(b.list()…, [b_item]) } else { assert_eq!(.., Err(LocatorMismatch)) }`.
  Same for `tests/integration/issuer_store.rs:1315-1324` (`retire_deletes_store_item_and_issuer_zeroizes`,
  scratch store, `StoreKind::WindowsDpapi`, `other_locator`): in a debug build it now deletes
  `other`'s item. Observed: `cargo test -p heimdall-issuer --test integration_issuer_store` → exit
  101, exactly these two failed (28 passed). Also `tests/integration/testkit_m03.rs:14-15` says the ceremony self-test "is not here: it needs
  U12's handler": it now lives in `e2e_cli_m03` (`issuer::test_ca_ceremony_captures_passphrase_only_from_pty`).
  And `tests/integration/issuer_m03.rs:1100` "(which refuses a test kind, S3)" is stale text only.

- [from A2 to integrator] **A2-R1** (A2-Q1, defect) — **done by the integrator (driver
  `validity_start`); switch removed by A2.** Was: the real issuer child refused every managed
  activation (`ceiling_exceeded`: the driver's truncated `valid_after` vs the issuer's
  `deadline − starts_at + 60 s` ceiling). Needs a fix in `crates/app/src/managed/driver.rs` (rec.
  `valid_after = ceil_second(grant.starts_at) − 60 s`) or `crates/issuer/src/check.rs`; then flip
  `tests/e2e/cli_m03/access.rs::REAL_ISSUER_SIGNS_MANAGED_ACTIVATIONS` to `true`.
- [from A2 to integrator] **A2-R2**: `m03_cmd::tests` and `tests/e2e/cli_m03.rs` assert nothing of
  `connections close`'s exit; no integrator test changes for item 16.

## Worker sections

### E2
- **Item 3** (debug builds only): `Operations::set_script_pause_dir(&self, Option<&Path>)`
  (`#[cfg(debug_assertions)]`, `app/src/operations/enrollment_m03.rs`); the runtime calls it from
  `ManagedOptions::script_pause_dir`. `enrollment_m03/steps.rs::issue` then rewrites the built step's
  `script` with `heimdall_registry::script::test_form::insert_pause_points` before anything is written;
  a dir that is not a `PauseDir`, or a failed insertion, refuses the step `driver_unavailable`.
  CLI: `enroll_cmd::SCRIPT_PAUSE_POINTS_CONSUMED` and its refusal are gone; `testcfg::enroll_hooks`
  still validates (release refuses, relative refused). No new crate edge.
- **Item 4**: `hold` filled (E2-R1 above); `enroll status` human + `data.guidance[].next_commands`
  use the runtime's `hold.next` (`render::held_of`), the round-1 fallback only when `hold` is absent.
- **Item 5**: `slot_free_command` lives in `heimdall_domain::managed`; re-exported as
  `heimdall_localenv::projection::plan::slot_free_command` (callers unchanged). The verified
  result's `ordinary_ssh_needs_held_slot` note: `command = slot_free_command(<alias>)`
  (`heimdall run --profile <profile> -- ssh <alias>`, `<profile>` a literal placeholder as in the
  preview/status/doctor); `command` omitted when the destination's alias is unknown.
- **Item 1 residual**: `drive::HANDOFF_NOTICE` now says a server falling back to password or
  keyboard-interactive authentication stalls the step until its time bound.
- **Prompt**: `prompt::ask` delegates to `prompt::ask_within(text, read, timeout)` (`pub(crate)`).

### IS2
- **Item 7 (b), the product-file test store** (debug builds + test configuration only):
  `HEIMDALL_TEST_SECRET_STORE=product-file:<absolute path>`. macOS: a file keychain
  (`MacosLoginKeychain::disposable_file_keychain`, kind `macos_login_keychain`); Windows: the DPAPI
  directory (`WindowsDpapi::in_dir`); **Linux: refused at parse** (usage error, exit 2: no disposable
  Secret Service). Parsed by `testcfg::m03_config_in` into `M03Config.product_file_store`; selected by
  `testcfg::test_store(&M03Config, home: Option<&Path>) -> Result<TestStore, String>`
  (`TestStore::{Platform, Scratch, ProductFile(PathBuf)}`), which both `issuer_cmd::test_config` (CLI)
  and `internal issuer` call; `m03_cmd::issuer_store(ctx, paths, env, &TestStore)` re-checks.
  The runtime's own selection: it spawns `internal issuer` with the inherited environment
  (`ChildCommand::internal_issuer`, no `env_clear`), so it uses the same selector: no `service.rs` edit.
- **Refusals** (`heimdall_issuer::store::test_product::refusal(store, scratch_home, account_home)`,
  module `#[cfg(debug_assertions)]`): relative or `.`/`..` components; canonical path not strictly
  under the canonical explicit `HEIMDALL_HOME` (the test's scratch home), or a home that is the
  account home or one of its ancestors; any `Library/Keychains` component pair, or under the account
  home's `Library/Keychains`; not created by the test: the marker `<path>.heimdall-test-store` must
  exist (regular file, not a link, content `heimdall-test-product-store/1\n<file name>\n`, owner-only
  and same uid as the home and the store on Unix) and its birth time must be ≤ the store's (no birth
  times: refused). The test creates both with `test_product::create(path, password)` (macOS; marker
  first, `O_EXCL`, then `SecKeychainCreate` by path) / `create(path)` (Windows) and removes them with
  `test_product::remove(path, home)`. Release builds: module compiled out, variable refused (exit 2);
  `release-gate.sh` probes `product-file:` through `service run`, `issuer status`, `issuer init`.
- **Item 7 (d):** `retire::delete_awaiting` deletes a `SecretStoreKind::Test` store's item by the
  exact locator when `retire::TEST_STORE_DELETION` (= `cfg!(debug_assertions)`); `issuer_cmd::
  S3_TEST_STORE_DELETION` and its test mirror are gone.
- **Item 8:** `IssuerRequest::BundleWritten` handler: `issuer_m03::record_bundle_written(tx,
  created_at, sha256, now)`: refuses a non-lowercase-hex digest and a `created_at` later than the
  runtime clock (`USAGE_ERROR`, nothing recorded); else `record_bundle_digest` + `set_last_bundle_at`
  in one transaction; answers the `issuer.status` data. `RECORD_LAST_BUNDLE_AT_ON_REPLY` removed;
  `issuer.bundle` records nothing. A refused confirmation makes `issuer bundle` answer the runtime's
  envelope (the file stays written; the human text says uninstall will not accept it).
- **Item 9:** `retire_to_retired` (IS2-R3) is the one entry.
- **Item 10:** `disclosure_text` (IS2-R1), tested against every `DisclosureKind` in
  `schemas/public-api/enrollment-plan.schema.json`.
- **Ceremony terminal:** while a ceremony reads a line, Unix `ISIG` is off and `VEOL` = Ctrl-C, so
  Ctrl-C at any ceremony prompt ends `NotConfirmed` (exit 3, nothing more sent) instead of killing
  the CLI (`ceremony::ControllingTerminal::read_in_mode`). Windows keeps the console default.

### U2
- Item 8: `uninstall_cmd::check_bundle` = content check (unredacted `/1`, `created_at` ≥ last
  enrollment/CA change, every CA and non-final enrollment in its current state) + SHA-256
  (`heimdall_issuer::backup::sha256_hex` of the exact bytes) found by
  `Txn::bundle_digest_recorded_at` on the read-only store. `BUNDLE_WRITE_RECORD_REQUIRED` removed.
- Item 11: `cli.rs` `UninstallArgs`: `--keep-remote-enrollments` no longer requires
  `--purge-state`; `--bundle` now `requires_all = [keep_remote_enrollments, purge_state]`.
  `PLAIN_UNINSTALL_ACK_REQUIRED` removed (the rule is unconditional).
- Item 13: `heimdall_localenv::doctor::{EnrollmentFact, reverify_command}`,
  `ManagedFacts.{stale_evidence, inconclusive_reverifications}` (additive, default empty);
  `doctor_cmd::client_trace_finding(&DoctorReport, windows: bool) -> Option<Finding>`.

### R2
All landed and tested (worklog `.m03-wave5-r2-worklog-R2.md`). Keys exactly as emitted:
- **Item 18, `ensure` result (`EnsureData`, typed):** for a `managed_certificate` binding whose
  commit used this process's outcome, `lock_continuity`, `conditions`, `refresh_condition`,
  `revocation`, `evidence`, `connection_policy` are the managed adapter's report
  (`adapters::managed::prepare::result_facts(&ManagedReport)`, filled in `prepare::outcome`, so
  `prepare_from` and `reissue_from` both carry it). `connection_policy` =
  `{"existing": "graceful"|"strict", "multiplexing": "disabled"|"owned_masters", "wording": "<D8 text>"}`;
  with `--strict` (`connection.existing: strict`) `existing` is `strict` and `wording` is the strict
  text (`DEADLINE_STRICT_EXCLUSIVE`, or `DEADLINE_STRICT_NOT_EXCLUSIVE` for a not-exclusive /
  undetermined selection; `+ " " + OWNED_MASTERS_DISCLOSURE` when owned masters apply). Absent
  (keys omitted, `conditions`/`evidence` empty) after a restart (`Facts::conservative`, e.g. a
  `bind`), for an attached binding (`Facts::from_data`), and for every other mechanism (M01/M02
  results byte-identical). Render "unknown" when absent.
- **Item 19, `inspect destinations`:** an item's existing `preference` object gains
  `"connection_policy": {"existing", "multiplexing", "wording"}` (the `ConnectionPolicyReport`
  serde form) only when: the preference's `mechanism` is `managed_certificate`, at least one current
  standing policy in this environment covers the pair (policy = the strictest over all of them,
  `effective_connection_policy`), and the runtime wired its wording source (the managed runtime
  does: `service.rs` `AdapterWording` → `ManagedCertificateAdapter::connection_policy_report(alias,
  policy)`, the alias's observed selection, `undetermined` when unobserved). Otherwise the key is
  absent. `wording` is the same sentence an `ensure` result carries for that alias and policy (no
  request narrowing: a `--strict` request shows only in its own result).
- **Item 21, `inspect capabilities`:** top-level `"lock": {"behavior": "continue"|"revoke_on_lock",
  "disclosure": "<LockDisclosure.text>", "acknowledged_at": "<RFC 3339>"}`; `acknowledged_at`
  omitted while unacknowledged; `behavior` is the strictest over the floor and every applicable
  policy; `continuity_verified` = a wired managed adapter whose descriptor says `Verified` (today
  none). The key is absent only if the store read fails. Ack: approving an `EnrollAccount` (or
  `EnrollSystemForm`) decision whose summary's `disclosures` contains `lock_continuity_once` records
  `meta.lock_disclosure_acknowledged_at` once (first time kept), as an approved `RegisterIssuer`
  already did.
- **Item 15:** the passive-read `TIME_UNCERTAIN` warning has `"reason":
  "time_confirmation_after_reboot"` iff the gate's verdict (`TimeGate::peek`) is
  `Uncertain(Unsynchronized)` (no same-boot anchor or confirmation, clock not reported
  synchronized). No `reason` for `BelowHighWater` (rollback), `Skew`, `ContinuousWentBackwards`.
  Same variant U2's chore keys on (`assess_read_only_in` → `Unsynchronized`); note the read-only
  gate also reports `Unsynchronized` for a synchronized clock with no anchor, where `peek` is `Safe`
  and no warning is emitted at all.
- **Item 22, policy results:** `SetLockBehavior` and `SetConnectionPolicy` results (applied,
  changed or not) = `{policy_id, revision, paused, cutoff_at, changed, "lock_behavior":
  "continue"|"revoke_on_lock", "connection": {"existing": ..., "multiplexing": ...}}`, this policy's
  own stored values after the action (C-Q4 reading). Pause/Resume/Cutoff/ClearCutoff unchanged
  (exactly the five keys). A widening action still answers `APPROVAL_REQUIRED` (no result data).
- **Item 23:** `service.rs` calls `ops.set_session_lock_signal(p.signal())` for the platform source
  when its signal is not `LockSignal::None` (a source reading `unavailable` reports `None`; storing it
  would drop the label if it later read a state).
- **New app API (not `app::ports`):** `heimdall_app::operations::ConnectionWording` (trait:
  `fn report(&self, alias: &str, policy: &ConnectionPolicy) -> Option<ConnectionPolicyReport>`) and
  `Operations::set_connection_wording(Arc<dyn ConnectionWording>)`;
  `heimdall_adapters::managed::prepare::{result_facts, alias_selection}`,
  `ManagedCertificateAdapter::connection_policy_report`.
- E2-R2 kept (`set_script_pause_dir` lines in `ManagedParts::start`).

### T2
Reads only (no shared file edited); all in `crates/heimdall/src/tui/m03.rs` unless named.
- **Item 4**: `Enrollment.hold = Hold {reason, next: Vec<String>}` from `hold.next` (array,
  verbatim, terminal-sanitized). No local derivation; absent `hold` -> "reason unknown (not reported
  by the runtime)"; present with empty `next` -> "next: none named by the runtime".
- **Item 10**: `m03::cli_only(&Decision) -> Option<String>` (the CLI command) for `enroll_account`,
  `enroll_system_form`, `register_issuer` (init / `rotate begin` / restore), `retire_issuer`,
  `remove_enrollment` (own and foreign): read-only, Approve never offered or sent; per §17.26
  (Q-T2-1/2) Deny is their one verdict, sent after the typed `yes` (model `decision_key` forces
  `Verdict::Deny`; Tab never toggles to Approve). `approve_target_change` keeps Approve/Deny. Disclosures: `heimdall_issuer::ceremony::disclosure_text(kind,
  &DisclosureContext {alias, lock: capabilities.lock.disclosure})`; an unknown wire kind shows
  `UNKNOWN_DISCLOSURE` and blocks Approve. Round 1's `switch` module is gone.
- **Item 15**: `Listings.time_uncertain` only for `code == TIME_UNCERTAIN` and `reason ==
  m03_warning::TIME_CONFIRMATION_AFTER_REBOOT` (R2's fill observed in e2e).
- **Items 19/20**: `preference.connection_policy.wording` verbatim, else "unknown: the runtime
  reports no connection policy for this pair". `OWNED_MASTERS_LINE` and the "[??]" line removed.
- **Item 21**: `LockReport {behavior, disclosure, acknowledged_at}` from `capabilities.lock`.
- **Item 17**: managed detail prints `crate::output::ORDINARY_CONNECTIONS_NOTE` (A2: please keep
  the name and visibility).

### A2
- **Item 16:** `connections_cmd::INCOMPLETE_CLOSE_IS_NONZERO` removed: `close_outcome` keeps the
  runtime's envelope and its exit (`OK` → 0 for `closed`, `closing`, `unverified`, any other state);
  human text: `unverified` → "was not closed: its identity was not verified, so nothing was
  signalled…", `closing` → "is not closed yet: the close is still pending…".
- **Items 19/22 (CLI rendering):** `output::m03_lines` adds `Connections: existing <e>, multiplexing
  <m>.` for a policy result's `connection` (after `Lock behaviour: <b>.`), and
  `output::CONNECTION_POLICY_UNKNOWN` for a `managed_certificate` ensure result without
  `connection_policy`. New `output::destination_lines(&Value) -> Vec<String>` (`pub(crate)`):
  `destination show` (one object) / `destination list` / `inspect destinations`
  (`destinations[]`): `<alias>: connection policy: existing <e>, multiplexing <m>.` then the
  runtime's `wording` verbatim, or `<alias>: connection policy unknown (the runtime reports none for
  this pair).` for a managed preference without it; nothing for M02 data. Printed by
  `emit_rendered` (catalog reads) and `m03_lines` (`emit`).
- **Item 17:** `output::ORDINARY_CONNECTIONS_NOTE` unchanged (`pub(crate)`, same name).
- **IS2-R1:** `enroll_cmd::render::disclosure_text(kind, alias)` = `heimdall_issuer::ceremony::
  disclosure_text(kind, &DisclosureContext { alias: Some(alias), lock: None })`.
- **Managed rig:** `tests/e2e/cli_m03/access.rs` `ManagedPair::set_up(&Rt::managed(..))` and
  `ManagedPair::ensure(..) -> Out` (Unix): a managed pair through the real binary and its real
  issuer child; the managed halves run unconditionally (no switch).
