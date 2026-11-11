# M03 wave 4, round 2 — worklog R2-F (R2E-Q1 preference switch, R2E-Q3 issuer store reason)

## R2E-Q3 (D3 item 7: "issuer_unavailable (or the store reason)") — done
- `crates/app/src/managed/driver.rs` `sign`: `IssuerError::Unavailable(why)` with `why` one of the
  issuer's **store** reasons (`issuer_store_locked`, `issuer_store_unavailable`) →
  `AdapterError::Unavailable("issuer_sign_failed:<reason>")`; every other failure (timeout, restart,
  protocol, other unavailability) stays `Unavailable("issuer_sign_failed")`. New
  `pub fn issuer_sign_failure_reason(&AdapterError) -> Option<&'static str>` decodes it (never echoes
  issuer text: only the two registered constants or `issuer_unavailable`). No port/contract change
  (`AdapterError` is a frozen port type, so a string carrier, not a new variant).
- `crates/app/src/operations.rs` `prepare_error` (R2-E's managed early return only): uses that reason.
- Decision: only the **store** reasons are carried (D3 item 7's wording); `issuer_not_initialized` /
  `issuer_restarting` give `issuer_unavailable` (D3's ruled reason). Not an open question.
- Regression: `tests/integration/runtime_m03.rs` `issuer_crash::refused_activation_carries_issuer_store_reason`
  (`FlakyIssuer` gained `down: Mutex<Down>`; default `issuer_unavailable` as before).
  - with fix: `cargo test -p heimdall-runtime --test integration_runtime_m03 issuer_crash` → 2 passed, exit 0.
  - fix reverted (the new `Unavailable(why)` arm removed from `sign`): same command → exit 101,
    `left: (CapabilityUnavailable, Some("issuer_unavailable")) right: (…, Some("issuer_store_locked"))`.
  - restored → 2 passed, exit 0.

## R2E-Q1 (D5 §6.6 / U0b row 9 preference switch) — done
### Decisions
- **Where the "what was rendered" comes from (narrowest change):** the intent carries P's bytes only
  when P changes, and alias → pair would then need the catalog read at commit time (or parsing the
  renderer's format in `app`, which does not depend on `sshconf`). So an **additive serde-default
  field** `managed_pairs: BTreeSet<AccessPair>` (`#[serde(default, skip_serializing_if =
  "BTreeSet::is_empty")]`) on `heimdall_domain::projection::{ProjectionPlan, SetupIntent}`;
  `ProjectionPlan::intent()` copies it. No ruling forbids it (grep ADR-0008/m03-plan: no ruling on
  `SetupIntent`); M02 intents are byte-identical (empty → omitted; old documents decode `{}`); the
  plan digest is untouched (it already binds P's steps and the `slot_free` findings).
- **Filled by the writer at preview** (`crates/localenv/src/projection/plan.rs`): `plan_ssh_apply`
  records the pairs whose section it rendered `ManagedCertificate` (after the quarantine refusal);
  `finish` keeps them only when the plan has an SSH-item step (a conflict plans none).
- **Recorded in the SSH item's commit transaction** (`crates/app/src/setup.rs`
  `StoreSink::commit_item` → `record_managed_projection`): for every catalog managed destination's
  pair (plus the rendered ones) whose preference is `managed_certificate`: in `managed_pairs` →
  `Applied { generation: <committed SSH generation> }`, otherwise → `Pending`. Intent kinds: apply,
  `rerender`, `manual_mode` use `managed_pairs`; rollback (and any other kind) renders none →
  pending; the block repairs (`remove_duplicate_markers`, `move_include_to_top`, P unchanged) change
  nothing. A preference that is `existing` (or absent: every M02 pair) is **never written**.
  `retry_held` commits through the held operation's own intent (its kind decides).
- Not ruled, fail-closed choices (questions R2F-Q1..Q4; Q4: `manual_mode` counts as applied): `existing` + switch-back apply is not
  recorded `applied`; an apply whose P is unchanged and commits nothing leaves `pending`; a pair whose
  destination left the catalog is not visited (no list-all store query).
- **e2e:** the World's harness **can** host a projection writer: managed worlds now get the
  runtime's own writer (`wire_runtime_projection`) with the runtime's store-backed pair source over a
  separate owner-only scratch account home (`setup-home*`, `setup-etc*`, `setup-config*`,
  `setup-state*`), so P/include never reach the ssh leg's `-F` config. `record_projection_applied`
  is **removed**; `World::setup_apply` runs preview → apply → approve `ApplyProjection` → replay.
  For that the runtime gained `pub fn heimdall_runtime::service::store_pair_source(..)` (the exact
  `StorePairSource` `Service` wires; `ManagedParts::pair_source` now calls it).
### Shared files touched (why)
- `crates/domain/src/projection.rs` (the field + unit test `setup_intent_managed_pairs_additive`),
  `crates/localenv/src/projection/plan.rs` (fill it), `crates/app/src/setup.rs` (record it; held
  plan literal), `crates/runtime/src/service.rs` (`store_pair_source`, R2-D's file),
  `tests/e2e/enroll_m03.rs` (R2-A/R2-E's file: the setup-apply leg), `tests/integration/runtime_m03.rs`
  (R2-D's file: new `setup_switch` module, `issuer_crash` additions).
- Mechanical `managed_pairs: Default::default()` in full-struct literals only:
  `crates/domain/src/operation.rs` (test), `crates/app/src/setup.rs` (tests),
  `tests/integration/projection.rs` (3), `tests/integration/store.rs` (1),
  `tests/integration/store_m03.rs` (1), `tests/model/operations.rs` (2). No assertion changed.
### Regressions (`integration_runtime_m03`, module `setup_switch`, real `Service` + setup driver)
- `setup_apply_managed_rendering_marks_only_that_pair_applied`
- `setup_rollback_or_existing_rendering_never_marks_pair_applied`
- `stale_preview_cannot_mark_pair_applied` (stale digest refused; a preference flipped to managed
  between the driver's recomputation and the commit by a writer hook stays `pending`; the reverse
  leaves `existing` unwritten)
- e2e `enroll_preview_apply_verify_setup_apply_ensure_ssh` (+ both `a10_*`, same `managed_legs`).
### Commands (real exit codes)
- `cargo test -p heimdall-runtime --test integration_runtime_m03 setup_switch` → 3 passed, exit 0.
- `cargo test -p heimdall --test e2e_enroll_m03 -- enroll_preview_apply_verify_setup_apply_ensure_ssh a10_narrow`
  → 3 passed, exit 0.
- `cargo test -p heimdall-domain --lib setup_intent` → 2 passed, exit 0.
- Revert R1 (the `record_managed_projection` call removed from `commit_item`): `setup_switch` → exit
  101 (`marks_only_that_pair_applied` and `rollback_or_existing…` FAILED); e2e
  `enroll_preview_apply_verify_setup_apply_ensure_ssh` → exit 101 (`left: Pending right: Applied
  { generation: 1 }`).
- Revert R2 (mark every managed preference applied on a non-rollback commit, i.e. from the
  preference read at commit time): `setup_switch` → exit 101, `stale_preview_cannot_mark_pair_applied`
  FAILED (`projection: Applied { generation: 1 }` vs `Pending`, the race leg).
- Revert R3 (a rollback leaves preferences untouched): `setup_switch` → exit 101,
  `setup_rollback_or_existing…` FAILED (`Applied { generation: 3 }` after rollback).
- Restored: `setup_switch` → 3 passed, exit 0.
- Harness note: a rollback plan must be sent as `SetupRequest::Rollback` (an `Apply` of a rollback
  digest answers "preview is stale" in M02 too; probe run showed the same with no managed pair).
