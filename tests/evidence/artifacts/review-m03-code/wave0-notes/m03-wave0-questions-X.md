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

- **X-Q1 — ruled (§17.15): the system form (own and foreign) refuses the manual-recovery events.** Inputs that cannot arise. These are an own record with `ca_not_held_seen: true`, a
  `ca_not_held` verdict on an own record, and the system form with `lock_holder_unresolved`.
  * Code: the own cancel with `ca_not_held_seen: true` is refused. A `ca_not_held` verdict in
    `verifying`/`reverifying` is treated as any other inconclusive result.
  * Concern: `held [own_system | foreign_system] manual_recovery_line_absent{lock_holder_unresolved}`
    gives `withdrawn`. For a foreign system record that is a final state with no absence proof.
    That conflicts with §17.10 item 2's "a residual that is known and unresolved is never
    discarded".
  * Recommendation (fail closed): refuse the manual-recovery events for the system form.
- **X-Q2 — ruled (§17.15): §6.7 wins, damaged → `held` with `removal_origin` kept.** `reconcile_damaged` in `rollback_unknown` and `remove_unknown`.
  * ADR §6.7 says "for a removal or rollback step, the same table applies", which gives a damaged
    line → `held`. The §6.2 rows for `rollback_unknown` and `remove_unknown` do not list that.
  * Code: refused. Which source wins: the table or §6.7?
- **X-Q3 — ruled (§17.15): a removal's manual recovery keeps its purpose; line absent → `removed`, line present → `held` (origin kept), never `applied_unverified`.** Manual recovery of a removal held by `lock_holder_unresolved`.
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

## After the §17.15 rulings (X-Q1–X-Q3)
- The goldens were amended from the rulings, and A1's code then landed. `cargo test -p heimdall-domain --test model_managed_domain` exits 0 (21 passed). The X-D1 and X-D2 tests now pass too.
- **Rollback reading: ruled by §17.15 item 6.** Manual recovery of a rollback keeps its purpose: line absent → `verification_failed`, line present → `held`. The `purpose` field on the two manual-recovery events is part of the wave-0 freeze. The golden rows cite item 6.
