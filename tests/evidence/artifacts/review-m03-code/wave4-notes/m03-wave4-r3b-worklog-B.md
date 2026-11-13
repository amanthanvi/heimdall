# M03 wave 4, round 3b — X-B (issuer) worklog

Goal: ADR-0008 §17.23 item 3 (R3B-Q2, option (a)): the second `issuer.register` (the store-item report
after the put) repeats the pending registration's facts **exactly** and only attaches the locator, once.
A mismatch or a second different locator refuses (nothing created, changed or consumed); the same locator
again is an idempotent answer.

## Findings (before coding)
- Round 3's join (`issuer_m03.rs` `issuer_register`) already joined only on every fact (`RegisterAsk::same`),
  but a report that **did not** match fell through to the create path: it created a **second**
  `RegisterIssuer` decision carrying the locator (the ceremony then stopped on `DecisionMismatch`, leaving an
  extra pending record). That is the exactness gap: a mismatched report must refuse, not create.
- `Txn::attach_register_issuer_store_locator(id, locator)` attached to any pending `RegisterIssuer`
  without looking at its facts (the app's join was the only guard).
- No ceremony path sends a locator on the **first** registration of an unregistered CA (D4 item 1: the
  put, step 6, follows `register`, step 3): `ceremony.rs` reports through `report_store_item` only, and the
  one first-request-with-locator path (`restore`, ~994) is a **registered** CA's re-registration. Other test
  files reach the real `Operations` with `store_locator: None` only (`issuer_store.rs`/`issuer_ceremony.rs`
  use fakes).

## Decisions
- XB-D1. One definition of "the same registration": `heimdall_store::ext_m03::same_registration_facts(a, b)`
  (pub, issuer region). Exhaustive destructuring of both `RegisterIssuer`s; compares fingerprint, store
  kind, backup digest, rotation_of, restored_without_log, ca_public_key, backup_created_at,
  expected_store_locator. Not facts: `store_locator` (what the report adds) and `disclosures` (derived from
  the runtime's acknowledgement state, not from the request). A new field fails to compile until classified.
- XB-D2. `Txn::attach_register_issuer_store_locator(id, report: &DecisionKind)` (signature changed: the
  report as a `RegisterIssuer`, its `store_locator` the item). Re-checks every fact
  (`GenerationConflict`, nothing written), then the once-only CAS as before (same locator: no-op; another:
  conflict). A report without a locator: document error. Only caller: `issuer_m03.rs`.
- XB-D3. App: `RegisterAsk::same` delegates to `same_registration_facts`; `RegisterAsk::kind(disclosures)`
  builds both the new record and the report. **A locator-carrying `register` for an unregistered CA that
  repeats no live pending registration never creates one** (reading, `.m03-wave4-r3b-questions.md` X-B):
  `CONFIG_CONFLICT` when a live `RegisterIssuer` of that CA is pending with other facts, `DECISION_STALE`
  when none is (expired, generation moved, never registered). Both with resource `issuer`. Registered-CA
  reports (log-intact restore re-registration) are unchanged: `register_admissible` decides them.
- XB-D4. Reason codes: none added; `Code::ConfigConflict` / `Code::DecisionStale` as this request already
  uses (no `crates/contract/**` edit).
- XB-D5. Test fix-up: `issuer_restore_store_locator_compare_and_swap_and_orphan_listing` registered CA 1 in
  one request carrying a locator (a shortcut no ceremony takes); now `register_req` then the report (D4
  order), asserting the report joins.

## Files
- `crates/store/src/ext_m03.rs`: `same_registration_facts` (new, pub), `attach_register_issuer_store_locator`
  (exact facts; new signature).
- `crates/app/src/operations/issuer_m03.rs`: module docs, import, `RegisterAsk::{kind, same}`, the join in
  `issuer_register`, the never-creates refusal, record construction via `kind`.
- `tests/integration/issuer_m03.rs`: helpers `pending_bytes`, `with_field`; tests
  `issuer_register_store_locator_report_must_repeat_every_fact`,
  `issuer_register_store_locator_report_attaches_once`; CAS test setup (XB-D5).
- `tests/integration/store_m03.rs`: `register_issuer_store_locator_report_repeats_every_fact`.

## Refusal cases (as tested)
App (`issuer_register_store_locator_report_must_repeat_every_fact`, before **and** after the exact report
attached; each leaves the pending record's encoding and the World snapshot — table counts, pending decisions,
issuers, environment, authority generation — identical, one pending record):
| differing fact | answer |
|---|---|
| public key (hence fingerprint: `ca_line(3)`) | `DECISION_STALE` (no pending registration of that CA; none created) |
| store kind (`windows_dpapi`) | `CONFIG_CONFLICT` |
| backup digest | `CONFIG_CONFLICT` |
| backup_created_at (+1 s) | `CONFIG_CONFLICT` |
| rotation_of (an active CA 2) | `CONFIG_CONFLICT` |
| restored_without_log | `CONFIG_CONFLICT` |
| expected_store_locator | `CONFIG_CONFLICT` (`register_admissible`: none recorded for an unregistered CA) |
`issuer_register_store_locator_report_attaches_once`: the same locator twice more → `APPROVAL_REQUIRED` naming
the same decision, record identical; another locator → `CONFIG_CONFLICT`, record identical; approval records the
first locator.
Store (`register_issuer_store_locator_report_repeats_every_fact`): each single-fact difference (fingerprint,
store kind, digest, rotation, key-only, public key, no public key, backup time, no backup time, expected
locator) → `GenerationConflict`, stored record identical, before and after the attach; a report without a
locator → error; same locator → no-op; second locator → conflict.
"Byte-identical" is the stored record read back and encoded as the store writes it (`serde_json`): the store
has no raw accessor for `decisions` and `crates/store/src/lib.rs` (`RawDocuments`) is outside my region.

## Commands (exit codes)
- `cargo test -p heimdall-runtime --test integration_issuer_m03`: first run 101 (the CAS test's one-shot
  registration with a locator, XB-D5); after its fix 0 (21 passed); final rerun after the revert runs 0 (21).
- `cargo test -p heimdall-testkit --test integration_store_m03`: 0 (31 passed), final rerun 0 (31).
- `cargo test -p heimdall-issuer`: 0 (unit 12, issuer_child 33, issuer_store 30, 6, doc 0), final rerun 0.
- `cargo clippy -p heimdall-app -p heimdall-store -p heimdall-runtime --all-targets -- -D warnings`: 0 (not narrowed).
- `rustfmt --edition 2024 --check` on `issuer_m03.rs`, `ext_m03.rs`, `tests/integration/{issuer_m03,store_m03}.rs`: 0.
- `bash tools/validation/clippy-windows.sh` (workspace-wide; not required): 101, only W's in-progress
  `tests/e2e/enroll_m03.rs:49` (`couldn't find file tests/e2e/enroll_m03/windows.rs`). My files have no cfg code.

## Revert runs (mutation → exit; restored → exit)
Harness `/tmp/xb-r3b-scripts/revert.py` (exact-string mutation, test, restore in `finally`, test; removed at
the end); sha1 of both source files checked equal after the run (`shasum -c`: OK, OK). Every reverted
failure was checked to be the test's own assertion (`test result: FAILED`, the named case), not a build error.
APP-every = `integration_issuer_m03 issuer_register_store_locator_report_must_repeat_every_fact`; APP-once =
`… issuer_register_store_locator_report_attaches_once`; STORE = `integration_store_m03
register_issuer_store_locator_report_repeats_every_fact`.

| # | Mutation (fix reverted) | Test | Reverted | Restored |
|---|---|---|---|---|
| M1 | a locator report for an unregistered CA may create a decision (round-3 behaviour) | APP-every | 101 (`public key`: `APPROVAL_REQUIRED`, a new decision) | 0 |
| M2 | fact not compared: fingerprint | STORE | 101 | 0 |
| M3 | fact not compared: store kind | STORE / APP-every | 101 / 101 | 101* / 0 |
| M4 | fact not compared: backup digest | STORE / APP-every | 101 / 101 | 0 / 0 |
| M5 | fact not compared: rotation_of | STORE / APP-every | 101 / 101 | 0 / 0 |
| M6 | fact not compared: restored_without_log | STORE / APP-every | 101 / 101 | 0 / 0 |
| M7 | fact not compared: public key | STORE | 101 | 0 |
| M8 | fact not compared: backup_created_at | STORE / APP-every | 101 / 101 | 0 / 0 |
| M9 | fact not compared: expected_store_locator | STORE | 101 | 0 |
| M10 | store attach: facts check removed | STORE | 101 | 0 |
| M11 | app: same locator again not idempotent | APP-once | 101 | 0 |
| M12 | app: a second different locator answered as a join | APP-once | 101 | 0 |
| M13 | store: a second different locator overwrites | STORE | 101 | 0 |
| M14 | a refused report writes the locator on the pending decision (app refusal attaches + M10) | APP-every | 101 (`store kind: nothing created or changed`) | 0 |

\* M3's restored STORE run hit W's transient `crates/testkit/src/sshd.rs:665` build error (`missing fields
harness_registry, registry_remote`), not a test result; rerun after the harness: 0.
Fingerprint/public key/expected locator are single-fact mutations the app test cannot isolate (the fingerprint
derives from the key; an expected locator on an unregistered CA is refused first by `register_admissible`):
STORE proves them.

## U12 contract delta (to round 3's "U12 contract", R3-B worklog)
- Step 1/2 unchanged in shape, now enforced: the report (`issuer.register` after the put) must send
  **exactly** the first request's fields plus `store_locator`. Any difference answers `CONFIG_CONFLICT`
  (a live registration of that CA is pending with other facts) or `DECISION_STALE` (none pending: expired,
  authority generation moved, never registered), with resource `issuer` and **no** decision: the CLI stops,
  the put's item is an orphan (D4 crash point 6–7; delete it with the owner present), and the owner reruns
  the ceremony. Previously a mismatched report created a second decision and the ceremony stopped on
  `DecisionMismatch`; `ceremony::report_store_item` now gets `SessionError::Refused { code, .. }` from
  `OwnerSession::register` (U12 maps the refusal envelope to it), propagated as a `CeremonyError` (same
  outcome: nothing more is sent, no `Decide`). No ceremony code change is needed.
- The first `issuer.register` of an unregistered CA must not carry `store_locator` (it never could under D4's
  order); one that does is treated as a report and refused as above.
- Same report again → `APPROVAL_REQUIRED` with the same decision (safe to retry); another locator →
  `CONFIG_CONFLICT`, nothing changed.
- Step 3 (log-intact restore of a registered CA) unchanged.
