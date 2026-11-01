# M02 wave 0: design verified against the code (task M02-W0-verify)

**Status:** `implemented_unverified` (documentation only; no code changed).

**What this is.** ADR-0007 §12.11 and §12.13 make the first step of wave 0 a check of the
design against the code: U0b's "Today" column, its preserve list, and the revision-5 fixes
(M2-T01 to M2-T06 and the interface reconciliation, item 7). This note records that check.
It is one verifier's reading. It is not the independent review of wave 0's code, which
§12.13 schedules after wave 0.

**Base.** Commit `9c458501`. `git diff --stat b89743ae 9c458501 -- crates tests/model
tests/integration tests/e2e tests/contracts` printed nothing, so the code at the base is
the M01 exit code (`b89743ae`, recorded by `c90d3235`). Every `file:line` below is at
`9c458501`. Wave 0 will move them.

**Sources read in full for the parts checked:** m02-plan revision 5 (§0, §1 U0, U0b and
U4 interfaces and tests, §5 items 1 to 19, §6 P12), ADR-0007 revision 5 (§5.3 to §5.7, §7
"Every call is bounded", §10, §12.1 to §12.13, §15.3), ADR-0006 §13.19 and §13.20, and the
code files named in the task.

**What changed in m02-plan.md.** Only U0b's "Today" cells, row 17's function cell and two
preserve-list bullets. Each correction is marked **⟨w0v⟩**. No row's "M02 change" column
and no design text was edited.

## 1. U0b rows 1 to 24: "Today" against the code

| Row | Code at the base | Verdict | Correction (⟨w0v⟩ in m02-plan) |
|---|---|---|---|
| 1 | `crates/app/src/operations.rs:7982` `decide`; `:8032` `waiting` match; `:8120` application match | Matches | Added what runs before the `waiting` match, without writing (`:7985`–`:8030`): unattended caller `INTERACTION_REQUIRED`, non-owner `CAPABILITY_UNAVAILABLE`, unknown record `NOT_FOUND`, not pending or expired `DECISION_STALE`, approval needs safe time (`gate.check`), denial uses `narrowing_now`. `ConfirmTime`'s refusal is `DECISION_STALE` (`error.rs:303`). The `w0_decide_*` test must therefore use an attended owner, a pending unexpired record, and safe time |
| 2 | `operations.rs:3754` `decision_view`; `crates/app/src/events.rs:722` `decision_kind_name` | Matches | None |
| 3 | `operations.rs:6684`–`:6707`; `crates/contract/src/request.rs:22` (`MAX_ARGV_BYTES`), `:363` (`BindForm`) | Matches | None |
| 4 | `drive_bind` `operations.rs:6918`; `stage_commit` `:5704`–`:5754`, `:5809` | **Mismatch** | "Or a restart after `reconcile` gave no facts" was wrong. A restart `reconcile` either gives facts (`Applied`, `:5730`) or returns before the fallback (`NotApplied` fails the operation, `:5731`; `Unknown` or an error returns `SERVICE_UNAVAILABLE` with effect `partial`, `:5743`). The fallback runs only when no facts are held: an attached binding with neither the leader's result nor a reconciled owner outcome, or an unattached drive with no prepare outcome and no recorded adapter or token, so no `reconcile` is made. Corrected |
| 5 | `operations.rs:3676`–`:3738` | Matches | None |
| 6 | `confirm` `operations.rs:5352`–`:5399`; `stage_reconcile` `:5153`, `:5327`; `reconcile_unresolved` `:4987`–`:5008`; `stage_commit` `:5730`; `continued_preparation` `:4724`; `attach_to_owner` `:4827` | **Imprecise** | "The facts live only in `DriveLocal.prepared`" left out `stage_commit`'s restart `reconcile`, whose outcome becomes a local `Facts`. The `Applied` arms of `stage_commit` and `continued_preparation` write no receipt and nothing to the store. `confirm` keeps the outcome only while the operation still runs or continues for others. Corrected (see N3) |
| 7 | `select_adapter` `operations.rs:3037`, called only from `resolve_in` `:3235`, which `stage_resolve` (`:4447`) and `preview` (`:6607`) use | **Incomplete** | Added that `inspect --preview` uses the same selection, so row 7's catalog-based selection also changes previews |
| 8 | `operations.rs:5314`–`:5323` | Wording | The field is `effect_token`; `grant.deadline.effective` is narrowed to the recorded bound (`:5266`). The request is built once, in `stage_reconcile`. Corrected |
| 9 | `WorkSpec::from_request` `operations.rs:3070`; `select_adapter` `:3041`–`:3046`; `unmet_minimum` `:1502`, called at `:5833` | **Mismatch** | `offline_until` is not checked beside `select_adapter`. `select_adapter` checks `capabilities` and `destination_scope_at_least` against each adapter's declaration. `offline_until`, the achieved destination scope and the grant's capabilities are checked at commit, against the prepared facts, by `unmet_minimum`. Corrected |
| 10 | `operations.rs:4213`–`:4230` | Matches | None |
| 11 | `operations.rs:4020`–`:4100` | Matches | Added that `runtime_lifecycle` `started` carries only `phase`, `open_operations` and `unresolved_operations` (counts, no IDs) and is emitted before any operation is led (`:4029`–`:4039`). See E2 |
| 12 | `crates/domain/src/operation.rs:211`–`:217` | Matches | None |
| 13 | `operation.rs:15`–`:48` | Matches | None |
| 14 | `crates/app/src/error.rs:33`–`:47`, `:141`–`:163`; `crates/contract/src/envelope.rs:156`–`:177` | Precision | Added that `OpError` has no reason field and that the wire error is `ErrorDetail` (`data.error`); `ErrorData` only wraps it. See E3 |
| 15 | `crates/testkit/src/lib.rs:249`–`:256`, `:558`–`:566`; `crates/heimdall/src/testcfg.rs:279`–`:286` | Matches | None |
| 16 | `crates/store/src/ext.rs:140`–`:164`, `:1263`–`:1281` | Matches | Added that the rule runs only when an intent is already stored; a first write is not checked. See N4 |
| 17 | `crates/runtime/src/dispatch.rs:175`–`:211` | **Mismatch (function cell)** | The match is in `OperationsDispatcher::handle_as`, reached from `Dispatcher::dispatch` (`:284`) through `handle` (`:162`). Added that `requires_attended_session()` refuses `Decide` and `ConfirmTime` from an unattended caller before the `Shutdown` check (`:181`), and that `Request` is `#[non_exhaustive]` (`request.rs:547`), so the wildcard is mandatory outside `heimdall-contract` |
| 18 | `crates/app/src/{setup,catalog}.rs` do not exist | n/a ("—") | None |
| 19 | `crates/ipc/src/session.rs:101`–`:112`; `operations.rs:6358`–`:6365`; `request.rs:601`–`:606`; session gate `session.rs:846` | Precision | The five capabilities are listed twice, in `server_capabilities()` and in a separate literal in `Operations::inspect`. `required_capability()` has a `_ => None` wildcard. Added. See N2 |
| 20 | `crates/store/src/ext_m02.rs` does not exist | n/a ("—") | None |
| 21 | `operations.rs:6391`–`:6527` | Matches | None |
| 22 | `crates/domain/src/catalog.rs` does not exist | n/a ("—") | None |
| 23 | `admit` `operations.rs:5955`–`:6035` (`allow_new` `:5971`, `classify` `:5979`, backpressure test `:5983`, `Authenticate` only with `pipeline` `:6017`) | Matches | None |
| 24 | `prepare` `operations.rs:5315`; `reconcile` `:4722`, `:4984`, `:5149`, `:5727`; `revoke` `:5526`, `:5545`, `:7517`; slots `:4721`, `:4980`, `:5145`, `:5183`, `:5723`; `Preparing` `:5189`, dropped `:5325`; in-flight skip `:5482`; `lead_bounded` `:4155`; `Limits` `:218` | Matches | Added that `prepare` and the four `reconcile` calls take an adapter slot and the three `revoke` calls take none. No other `prepare`, `reconcile`, `revoke` or `renew` call exists in `crates/` |

## 2. The preserve list against the code

Every bullet holds at the base:

* **`admit` order**: `operations.rs:5971` (`allow_new` before the transaction), `:5979`
  (`classify`), `:5983` (backpressure test), `:6009` (insert), `:6017` (`Authenticate`
  only with `pipeline`).
* **Recovery steps around the restart loop**: `operations.rs:4054`–`:4079` (capture before
  the loop), `:4080`–`:4089` (loop), `:4093` (`complete_interrupted_withdrawals`), `:4096`
  (`process_cleanup_intents`). **Corrected wording:** revision 5 headed the bullet "after
  the restart loop", but the interrupted-round capture comes before it.
* **Claim and effect sequences**: `crates/domain/src/revocation.rs:168` (`claim_seq`),
  `:251` (`effect_round`), `:259` (`effect_seq`), `:293` (`migrate_claim_seq`), `:400`
  (`cleared_by_claim`); migration on load `operations.rs:2267`; the counter
  `ext.rs:1129` and its uses `operations.rs:2452`, `:2531`. `cleared_by_round` no longer
  exists; only a stale intra-doc link names it (`revocation.rs:244`, N8).
* **Durable cleanup intent**: `revocation.rs:350`–`:375`; meta keys and counter
  `ext.rs:67`–`:72`; lifecycle `ext.rs:1148`–`:1192`.
* **`settle_effect_in`**: `operations.rs:2962`; called at `:4933` (`mark_uncertain`),
  `:5388` (`confirm`), `:5647` (`stage_recheck`), `:5860` (`stage_commit`), `:7236`
  (`cancel`). The call-site list was added to the bullet.
* **`cleanup_pending`**: `operations.rs:6428`–`:6516`; the regression test
  `r1320_1_a_pending_cleanup_intent_is_visible_until_its_call_is_made` is at
  `tests/model/operations.rs:9054`.

## 3. Notes for wave-0 implementers

These are readings of the design against the code. None changes the design.

* **N1. Struct literals that the new fields break.** `RecoveryIntent { request, resolved }`
  at `operations.rs:3995` and `:6012` and in `tests/integration/store.rs` (nine literals
  without a `..` spread); `StageReceipt { … }` at 12 sites (3 in `operations.rs`, 9 in
  `tests/integration/store.rs`); `OperationsConfig { … }` (no `Default`) without a `..` spread at
  `crates/runtime/src/service.rs:335`, `tests/model/operations.rs:428` and `:2415`,
  `tests/model/events.rs:212`, `tests/model/idempotency.rs:200` and
  `tests/model/revocation.rs:470` (the other nine in `tests/model/operations.rs` spread a
  base config); `PrepareOutcome { … }` in `crates/testkit/src/lib.rs`,
  `crates/heimdall/src/testcfg.rs`, `tests/model/*.rs` and `tests/integration/runtime.rs`.
  `Limits { … }` literals already use `..Limits::default()`. See E13 for the "run
  unchanged" rule.
* **N2. Two contract helpers do not fail closed by themselves.** `required_capability()`
  (`request.rs:601`) ends in `_ => None`, so `Setup` and `Catalog` need explicit
  `setup/1` arms, or the session gate lets them through to dispatch and
  `w0_setup_and_catalog_on_a_session_are_never_dispatched` fails. `is_effectful()`
  (`:638`) is a negative match, so `Setup(Preview)` must be named explicitly to be
  non-effectful (§5 item 2). `requires_attended_session()` (`:614`) already returns `false`
  for new variants, as §5 item 2 requires.
* **N3. Where row 6 writes prepared facts.** Only two transactions append `Confirmed`:
  `confirm` (`:5366`) and `reconcile_unresolved` (`:4992`). The `Applied` arms of
  `stage_commit` and `continued_preparation` have no receipt transaction. The facts of
  those attempts were written when their own `Confirmed` was recorded. A `Confirmed`
  written by M01 code has none, so the result then reports an empty integration, which
  fails closed.
* **N4. Row 16's exclusivity on the first write.** `intent_update_allowed` runs only when
  an intent is stored (`ext.rs:1268`). The rule "a `local` and a `resolved` on the same
  intent are refused" should also apply to a first write, in `set_recovery_intent` and
  `insert_setup_operation`; otherwise a first write could store both.
* **N5. Store kind columns versus wire names.** `operations.kind` and `idempotency.kind`
  hold `OperationKind::as_str()` (`crates/store/src/lib.rs:594`, `:616`, `:640`). So
  `open_setup_operations` filters on the dotted names. `record_json`, the
  `operation_state_changed` payload (`operations.rs:609`), `inspect operations`
  (`:3743`) and the idempotency-key hash (`crates/domain/src/idempotency.rs:52`) use the
  serde form. See E4.
* **N6. No `CHECK` constraint** constrains `kind` or `owner_json` in the migrations, so
  migration 0005 can add tables only, as §5 item 18 says.
* **N7. `OperationsConfig.projection`** is declared in phase 1 with value `None` (U5
  interfaces). Every construction site in N1 needs it.
* **N8. Outside wave 0's scope:** the doc comment at `revocation.rs:244` links to the
  removed `RemoteObligation::cleared_by_round`.

## 4. The revision-5 fixes: ADR-0007 against m02-plan §1 and §5

* **M2-T01 (Git name transitions).** ADR-0007 §5.6 (lock holder K, replace, restore,
  abort and create tables, crash vectors), §5.7 (`git_lock` step, rows K0 to K4, T0, T2,
  T3) and m02-plan U0, U4 and §5 items 17 and 17a agree on: K staged at a random name and
  receipted before the claim; the claim by no-replace rename; B_git with ordinary names
  (Unix D at N_s, Windows D at `.<name>.hm-displaced-<generation>`); K released last;
  ownership by K's identity and the birth-time rule; the step order P_git, `git_lock`,
  B_git. Gaps: E9 (a third `Rendered` producer) and E11 (cardinality, `commit`, the
  holder line's terminator).
* **M2-T02 (materializer).** ADR-0007 §5.3 step 3 and §5.7 "The materializer checks both
  digests itself" agree with U0's frozen signature `content::materialize(&FileStep,
  Option<&[u8]>) -> Result<Materialized, ContentError>`, U4's error variants, and U0's
  validation cases. One divergence: E12.
* **M2-T03 (held fingerprints).** ADR-0007 §5.7 "Held previews carry content
  fingerprints" and m02-plan §5 item 15, U4 `observe_fingerprint` and U5's two controls
  agree field by field. Placement: E8.
* **M2-T04 (`RecoveryState`).** The fields agree (`phase`, `restore`, `settlement`, `item`,
  `release_due`), as do the order check and `contradictory_receipts`. The builder's
  signature cannot compute what both documents define: E7.
* **M2-T05 (properties).** The eight properties, the effect alphabet, normalization and
  the negative controls agree. U4's seeded faults add "K released while B_git is not final",
  which property 5 catches. One wording difference: E15.
* **M2-T06 (adapter bound).** ADR-0007 §7 "Every call is bounded", §12.12 QR17 and §12.13
  agree with U0b row 24, and each per-site timeout arm in row 24 is the code's existing
  error arm (`:5156`, `:5024`, `:5743`, `:4724`; `:5528`, `:5545`, `:7524`). Row 24's
  paraphrase of `mark_uncertain` omits that it calls `settle_effect_in` only when the
  operation is not `outcome_unknown` and nothing continues for others (`:4928`–`:4933`).
  That behaviour stays unchanged. One ambiguity: E14.
* **Item 7 (reconciliation and preserve list).** ADR-0007 §12.11 item 7 and the plan's
  six preserve bullets match one for one, and §2 above checks each against the code.
  U0's migration test covers the M01 meta records and counters, and U0's identity test
  covers `Some(birth)` and `None` in both directions. "T01–T07" (ADR-0007 §12.11 and
  §12.13, m02-plan line 75) is read as T01 to T06 plus item 7; there is no M2-T07 (E16).

## 5. Escalations: contradictions and gaps, not corrected

Each item names the conflict, the fail-closed reading that wave 0 builds against, and who
should rule. None is a "Today" error, so none was edited.

* **E1. Cancelling a setup or catalog operation has no owner.** `Operations::cancel`
  (`operations.rs:7117`–`:7264`) settles any non-quiescent operation `cancelled`, whatever
  its kind. For a setup operation it would also release `setup_in_progress`. ADR-0007 §5.4
  honours cancellation only before the first commit point, and m02-plan §5 item 4 keeps an
  open operation of a new kind untouched in wave 0. No U0b row covers `cancel`, and a
  pending `ApplyProjection` or `DeclareInteraction` record is not withdrawn on cancel.
  *Reading:* in phase 1, `cancel` of `SetupApply`, `SetupRollback`, `SetupRepair` or
  `Catalog` answers `CAPABILITY_UNAVAILABLE`, reason `driver_unavailable`, and writes
  nothing. *Ruling needed:* a U0b row for phase 2. *Owner:* orchestrator.
* **E2. `runtime_lifecycle` has no per-operation payload.** Row 10 and
  `w0_open_setup_and_catalog_operations_stay_unresolved_at_restart` require the event to
  list each such operation with `driver_unavailable`. §5 item 17a does the same for
  `unreadable_receipts`. Today one `started` event carries counts only, before the loop
  (`:4029`). No §5 item defines the payload. *Reading:* `local_driver_unavailable(id)`
  emits one additive `runtime_lifecycle` event per operation, with the operation ID, its
  kind and the reason, and changes nothing else. *Ruling needed:* the payload (ADR-0006
  revision 3). *Owner:* integrator.
* **E3. `ErrorData.reason` names the wrong type.** §5 item 14, ADR-0007 §10 and row 14 say
  `ErrorData.reason`. Error fields live in `ErrorDetail` (`data.error`,
  `envelope.rs:156`). *Reading:* `ErrorDetail.reason: Option<String>` (wire
  `data.error.reason`, omitted when absent), carried by `OpError` and kept by `detail()`
  and `from_detail()`, so a replayed failure keeps its reason. *Owner:* integrator (§5
  item 14 wording).
* **E4. `OperationKind` gets two wire names.** `#[serde(rename_all = "snake_case")]`
  (`operation.rs:14`) gives `setup_apply` in events, `inspect operations`, `record_json`
  and the idempotency-key hash. `as_str()`, `Request::kind()` and the store columns use
  `setup.apply`. The design names only the dotted form, and the type's documentation says
  "the string form is the idempotency namespace". *Reading:* add `#[serde(rename =
  "setup.apply")]` and the same for the other new kinds, so that both forms agree as they
  do for every M01 kind, and assert serde == `as_str()` for every kind in U0's kind test.
  *Owner:* integrator (U0).
* **E5. U0's kind test cannot match `Request` without a wildcard outside the contract.**
  `Request` is `#[non_exhaustive]` (`request.rs:547`), and `OperationKind` is in
  `heimdall-domain`, which `heimdall-contract` cannot depend on. *Reading:* an exhaustive
  classification function in `heimdall-contract` (journaled with its kind string,
  effectful but not journaled, or read-only), unit-tested there. The domain-side test
  then compares strings. *Owner:* integrator (U0).
* **E6. One wave-0 test cannot run in the target that hosts it.**
  `w0_m02_cli_commands_report_not_available_and_never_panic` is placed in
  `tests/e2e/wave0_fail_closed.rs`, hosted by `heimdall-runtime`. Only targets of the
  `heimdall` package get `CARGO_BIN_EXE_heimdall`, and `heimdall-runtime` cannot depend
  on the binary-only `heimdall` crate, which depends on it. *Reading:* host that test in a
  `heimdall`-package target, such as a new `e2e_wave0_cli` at `tests/e2e/wave0_cli.rs`,
  and keep the others where planned. *Owner:* integrator (U0b test layout).
* **E7. `RecoveryState::build(step: u16, &[StageReceipt])` lacks inputs its definition
  needs.** This interface is frozen (U0 list; U4; ADR-0007 §5.7 `build(step, receipts)`).
  The phase order is per shape. `release_due` needs to know which steps belong to the Git
  item, which are removals ("handed to the cleaner") and whether the item is aborting
  ("never staged in an aborted item"). None of this follows from a step index and
  receipts. An abort has no receipt until `item.finished{not_applied}`, which comes after
  K's release. *Reading:* the builder also takes the intent's `files` (`&[FileStep]`).
  A never-staged sibling counts as final only when `decide_item` has decided `Abort` in
  the same run. Until then K2 keeps the lock, which has no effect. *Ruling needed before
  the freeze. Owner:* orchestrator (ADR-0007 §5.7) and integrator (U0).
* **E8. Port types depend on `heimdall-localenv` types.** `HeldStep { observed:
  StepObservation, fingerprint: StepFingerprint }` belongs to the app port
  `ProjectionWriter::observe_held` (§5 item 15; `crates/app/src/ports.rs`). U4 defines
  `StepObservation`, its normalizing constructor (which takes `&RecoveryState` and the
  shape), `EntryObs`, `StepFingerprint` and `EntryFingerprint` in `heimdall-localenv`.
  That crate implements the app ports, so it depends on `heimdall-app`, and the app
  cannot name its types. U0 must also freeze these types, but its owner paths give it only
  a skeleton `lib.rs` in `crates/localenv`, while `projection/{recovery,content}.rs` are
  U4's. *Reading:* the types that cross the port, with the constructor they need
  (`StepObservation`, `EntryObs`, `RecoveryState` and its parts, `StepShape`,
  `StepFingerprint`, `EntryFingerprint`, `HoldReason`), live in `heimdall-domain`, are
  owned by the integrator and are frozen. `decide`, `decide_item`, `observe_*` and
  `materialize` stay in `heimdall-localenv`. The integrator creates the localenv files
  that hold frozen signatures in wave 0. *Owner:* integrator.
* **E9. The provenance rule for `Rendered`.** ADR-0007 §5.7 and §5 item 17 say that only
  `sshconf::render::*` and `materialize::public_key_bytes` produce `Rendered`. U4's
  `git::lock_holder(…) -> Rendered` (revision 5) is a third producer. Rust visibility
  cannot limit a domain type's constructor to two other crates, and serde builds a
  `StepContent` whenever an intent is read. *Reading:* `StepContent`'s only constructor
  outside serde takes `Rendered`. A source-scan test, like
  `production_code_never_unlinks_outside_quarantine`, shows that `Rendered` is built
  only in `sshconf::render`, `localenv::materialize` and `localenv::projection::git`.
  Decoded intents always pass `SetupIntent::validate`. *Owner:* integrator (§5 item 17
  wording, U0).
* **E10. The canary and armor checks cannot see base64 content.** Stored intents carry
  base64 bytes (§5 item 17). The store's armor refusal (`crates/store/src/codec.rs:64`)
  and `assert_no_canary` (`crates/testkit/src/lib.rs:24`) are substring checks, so
  encoded content passes both. That defeats ADR-0007 §5.7 "The canary scan covers stored
  intents" and U4's `intent_content_nonsecret_and_bounded`. *Reading:*
  `SetupIntent::validate` decodes every content field and refuses private-key armor, as
  the store already does for documents. The test scans the decoded bytes as well as the
  JSON. *Owner:* integrator (U0) and U4.
* **E11. `git_lock` cardinality and form.** ADR-0007 §5.7 allows "exactly one … only when
  the plan has a `git_include` step, and only directly before it". §5 item 17 says "at
  most one". Neither says whether a `git_include` step without a `git_lock` step is
  refused. U0's validation cases omit `commit: true` on `git_lock`. Neither document says
  whether the holder line ends with a newline. *Reading:* each `git_include` step is
  directly preceded by exactly one `git_lock` step, and each `git_lock` step is directly
  followed by a `git_include` step; `commit` must be `false`; `validate` accepts exactly
  the bytes `git::lock_holder` renders, with the terminator fixed by U0. *Owner:*
  integrator (U0, frozen).
* **E12. `BaseMissing`.** ADR-0007 §5.7 says a present base without matching bytes gives
  `CONFIG_CONFLICT`. U4 maps `BaseMissing` (no bytes passed for a present base) to
  `IntentInvalid`. *Reading:* U4's mapping. Missing bytes for a present base can only be
  a caller error, because `validate` always returns them; it is not a user edit. A
  digest mismatch stays `CONFIG_CONFLICT`. *Owner:* integrator (wording).
* **E13. The M01 suites cannot "run unchanged".** The preserve list says the M01 model,
  integration and property suites run unchanged. The new fields (N1) break their struct
  literals. *Reading:* no assertion or scenario changes. The only edits allowed are
  mechanical additions of the new fields at their M01-equivalent values (`local: None`,
  `projection: None`, empty integration), and they are reviewed as such. *Owner:*
  integrator.
* **E14. `adapter_call_timeout` minimum.** P12 says "at least 1 s" and also "tests set it
  lower" (row 24 uses 200 ms). *Reading:* `Operations::start` does not enforce the
  floor. It applies only where a production value is set, and M02 sets none (default
  30 s). *Owner:* integrator (phase 2).
* **E15. Wording of the recognition rule in U4's generated test.** U4 says "with `restore`
  started, the path `D` or `Foreign` and the aside `S`". ADR-0007 property 4 and rows F5b
  and F5c say: path D (V, V′ or the recorded mismatch identity) or X, aside S or S′.
  *Reading:* the ADR. *Owner:* U4 (test text).
* **E16. "T01–T07"** in ADR-0007 §12.11 and §12.13 and m02-plan line 75 refers to a
  finding that does not exist. *Reading:* T01 to T06 plus item 7. *Owner:* integrator
  (wording).

## 6. Frozen wave-0 interfaces and where they live

"Frozen" means m02-plan §5 items 4, 17 and 17a, plus the parts of items 15 and 18 that U0's
frozen list names (m02-plan U0 "Frozen in wave 0"). Later units build on these and change
them only through an ADR-0007 revision. "Base" gives the existing definition at
`9c458501`. "New" means the file or item does not exist yet. The design does not name the
module of every new type; where it does not, the cell says so.

| Interface | Location | Created by | Notes |
|---|---|---|---|
| Capability `setup/1` constant | `crates/contract/src/ipc.rs`, `capability` module (base `:43`–`:56`) | U0 | §5 item 4 |
| `Request::{Setup, Catalog}` and the arms of `kind()`, `is_effectful()`, `required_capability()`, `requires_attended_session()` | `crates/contract/src/request.rs` (base `:548`–`:644`) | U0 | §5 items 2 to 4; N2; E5 |
| Fail-closed landing: `server_capabilities()` unchanged | `crates/ipc/src/session.rs:101` | — | Phase 1 offers no `setup/1` |
| Fail-closed landing: the session gate, unchanged | `crates/ipc/src/session.rs:846` | — | `SCHEMA_UNSUPPORTED` |
| Fail-closed landing: `inspect capabilities` list, unchanged | `crates/app/src/operations.rs:6358` | — | Row 19 |
| Fail-closed landing: dispatcher arms `Request::Setup`, `Request::Catalog` | `crates/runtime/src/dispatch.rs`, `handle_as` (base `:191`–`:210`) | U0b | Row 17; wildcard stays |
| Fail-closed landing: `Operations::{setup, catalog}` | `crates/app/src/{setup,catalog}.rs` (new) | U0b (U5 replaces the bodies) | Row 18: `CAPABILITY_UNAVAILABLE`, `driver_unavailable`, effect `none`, before admission |
| Fail-closed landing: `Operations::drive` new arms → `local_driver_unavailable` | `crates/app/src/operations.rs:4213` | U0b | Row 10; E2 |
| Fail-closed landing: `Operations::decide` new arms (refused, record pending) | `crates/app/src/operations.rs:8032`, `:8120` | U0b | Row 1; E1 |
| Fail-closed landing: CLI "not available in this build" envelope (`USAGE_ERROR`) | `crates/heimdall/src/cli.rs:497`–`:507` | U0 (clap tree) | Every M02 command until its unit lands |
| `OperationKind::{SetupApply, SetupRollback, SetupRepair, Catalog}`, `as_str` | `crates/domain/src/operation.rs` (base `:15`, `:37`) | U0 | Rows 13, 10; journaled-kind mapping; E4 |
| `RecoveryIntent.local: Option<LocalIntent>`, `LocalIntent { Setup, Catalog }` | `crates/domain/src/operation.rs` (base `:211`); `LocalIntent`'s module is not named | U0; add-only rule in `crates/store/src/ext.rs:140` by U0b | Rows 12, 16; N4 |
| `StageReceipt.local: Option<LocalReceipt>`; `LocalReceipt`, `FilePhase`, `ItemPhase`, `HoldReason` (with `contradictory_receipts`), `ObservedName`, `PreservedEntry` | `crates/domain/src/operation.rs` (base `:254`); the payload types' module is not named | U0 | §5 item 17a |
| `DecisionKind::{ApplyProjection, DeclareInteraction}` | `crates/domain/src/decision.rs` (base `:23`) | U0 | Rows 1, 2 |
| `ProjectionApproval` (only in `SetupIntent`), `DeclarationApproval` (only in `CatalogIntent`) | `crates/domain/src/{projection,catalog}.rs` (new) | U0 | `LocalApproval` withdrawn |
| `SetupIntent` (and `validate`), `FileStep`, `FileRole` (with `GitLock`), `Base`/`Target`, `StepContent { whole, splice, absent, lock_holder }`, bounds, `Rendered`, `FileIdentity` (optional Unix `birth`; equality), `ProjectionLocator`, `ConsentRecord`, `BehaviorState`, `ProjectionSpec`, `ProjectionPlan`, `ProjectionRecord`, `ProjectionSummary` | `crates/domain/src/projection.rs` (new) | U0 | §5 item 17; E9, E10, E11 |
| `CatalogIntent`, catalog records, `InteractionDeclaration`; `eligibility` and `fallback_clearance` signatures | `crates/domain/src/catalog.rs` (new) | U0 (U0b writes the bodies in phase 1) | Rows 5, 21, 22 |
| `ProcessHolder`, `HolderState` | `crates/domain/src/holder.rs` (new) | U0 | |
| `OwnerRef::Projection { environment }` | `crates/domain/src/resource.rs` (base `:37`) | U0 | |
| `PreparedFacts` (history only) | `heimdall-domain`; module not named | U0 | Rows 4 to 6 |
| `ProjectionWriter { preview, apply, reconcile, observe, observe_held }` and its stateless contract; `StageSink { append, commit_item }`, `ItemCommit`; `ProjectionReceipt`, `ProjectionReconcile`, `ItemOutcome` (with `Held`), `HeldStep` (with `fingerprint`), `ReconcileError { UnreadableReceipt, IntentInvalid }` | `crates/app/src/ports.rs` (base `:1`–`:201`) | U0 | §5 item 15; E8 |
| `recovery::decide(shape, &RecoveryState, &StepObservation) -> StepDecision`; `StepShape { Replace, Create, GitLock, Removal }`; `RecoveryState` and `RecoveryState::build`; `EffectivePhase`, `RestoreCtx`, `SettleCtx`, `ItemState`; `StepObservation` and `StepObservation::normalize`; `EntryObs`; `StepDecision` | Design: `crates/localenv/src/projection/recovery.rs` (new; U4 path). Recommended for the types that cross the port: `heimdall-domain` (E8) | U0 (signatures), U4 (bodies) | E7, E8 |
| `EntryFingerprint`, `StepFingerprint` | Not placed by the design; recommended in `heimdall-domain` (E8) | U0 | M2-T03 |
| `content::materialize(&FileStep, Option<&[u8]>) -> Result<Materialized, ContentError>` and the `ContentError` variants | `crates/localenv/src/projection/content.rs` (new; U4 path) | U0 (signature), U4 (body) | M2-T02; E12 |
| The `replace` primitive and quarantine interface (`DirHandle`, `Quarantine`, `Expected`, `validate`, `stage`, `recheck`, `exchange`, `post_validate`, `restore`, `settle`, `remove_verified`, `observe_step`, `observe_fingerprint`) | `crates/localenv/src/projection/replace.rs` (new; U4 path); quarantine removal in `crates/localenv/src/sys.rs` (`sys::QuarantineDir`, U3 path) | U0 (signatures), U4 and U3 (bodies) | Frozen by U0's list |
| `Txn::insert_setup_operation(&OperationRecord, &IdempotencyRecord, &RecoveryIntent, Option<&OperationId>) -> Result<SetupAdmitted { Inserted, InProgress(Vec<OperationId>) }>` | Signature by U0 in `heimdall-store`; body in `crates/store/src/ext_m02.rs` (new) by U0b; runs inside `BEGIN IMMEDIATE` (`crates/store/src/lib.rs:290`) | U0, U0b | §5 item 18; row 23 |

Also delivered in wave 0, but not frozen, so these may still change through the
integrator: the other §5 contract deltas (`BindForm::Launch(LaunchBinding)` at
`request.rs:363`, `RequiredCapabilities.unattended` at `:178`, `EnsureData` at `:306`,
`ConsumerIntegration` at `:348`, `InspectSubject` at `:226`, `Code::LaunchFailed` in
`crates/contract/src/code.rs` with 29 rows today, `NextAction.provider_interaction` at
`envelope.rs:98`, `ids::IdentityId`, and the `doctor`, `provider` and `run_record`
modules); the other `Txn` methods of §5 item 18, migration `0005_existing_access.sql`
and `SCHEMA_VERSION` 5 (`crates/store/src/migrations.rs:17`, 4 today); `admit`'s
`exclusive` parameter (row 23); `PrepareRequest.pairs` and the new `PrepareOutcome` fields
(`ports.rs:100`, `:122`). Phase 2 adds `Limits.adapter_call_timeout` and
`bounded_adapter_call` (row 24).

## 7. Commands run

All were read-only except the edits to `docs/architecture/m02-plan.md` and this file, and
the build output that check.sh writes to the shared `./target`.

* `git log --oneline -3`, `git status --short`; the tree was clean at the start.
* `git diff --stat b89743ae 9c458501 -- crates tests/model tests/integration tests/e2e
  tests/contracts` and `git diff --stat c90d3235 9c458501 -- crates`: both printed
  nothing.
* `grep`, `sed` and file reads over the files named in the task, plus
  `crates/store/src/codec.rs`, `crates/store/migrations/*.sql`,
  `crates/runtime/src/service.rs`, `crates/testkit/src/lib.rs`,
  `crates/heimdall/src/testcfg.rs`, `crates/*/Cargo.toml` (test-target hosting) and
  `tests/model/*.rs`, `tests/integration/store.rs` (struct-literal sites).
* `git diff -U0 docs/architecture/m02-plan.md`: the hunks are confined to the U0b table
  (lines 401 to 424) and the preserve list (lines 431 to 446).

* `bash tools/validation/check.sh`: exit 0, with every step at exit 0 (fmt, clippy,
  clippy-windows, test, test-discovery, schema, native-harness-selftest,
  evidence-selftest, evidence-records with 86 records and 0 invalid). It ran against the
  base plus these two documentation files; `git status --short` showed no other change.
  check.sh does not read `docs/architecture`, so this result only shows that the
  workspace was green at that time.
* The AGENTS.md `du -sh` check over `prototypes/*/{target,node_modules,dist}`: no
  `prototypes/rust/target` exists, so nothing needed pruning.
