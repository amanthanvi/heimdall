# M03 wave 4, round 3b — worklog X-M (managed)

Goal: ADR-0008 §17.23 items 6 (typed materialization source; created locator; follower names it), 1 (descriptor
advertises `verified_server_principals`), 5 (per-pair selection fed; `exclusive` fixture; non-interactive managed
`delegate`; §17.22 item 10's regression through a real child delegation). Regions per `.m03-wave4-r3b-api.md`.

## Decisions
- XM-1 (item 6). `app::ports::MaterializeSource { Fresh { public_key, certificates }, InstalledKeyOf { grant },
  SlotsOnly }` replaces `MaterializeSpec.{public_key, certificates}` (not serialized; every constructor is in my
  regions). The slots-only form (empty key + no certificates) was also a convention overloading the spec, so it is a
  named variant too. `MaterializedFiles.endpoint: Option<EndpointRef>` = the endpoint the call **created** (None:
  slots-only or one already ran). Effects: `Fresh` checks the key is the live K_env of the attached / key-owning
  grant and refuses empty certificates (`no_certificates`); `InstalledKeyOf` needs a live K_env generated here
  (`no_live_key`), each stored-scope pair installed (`not_installed`), and refuses a binding attached to another grant
  (`binding_grant_mismatch`); `SlotsOnly` needs `environment_slots`. By-reference form, `BY_REFERENCE_PREFIX`,
  `grant_of_fingerprint`, `follower_locator`, `with_follower_endpoint` deleted.
- XM-2 (item 6). Follower: `materialize_follower(op, grant, binding) -> EndpointRef` (no leader argument; the store
  read only checks an `installed` instance), refusal when `files.endpoint` is `None`; `name_follower_endpoint` sets
  `consumer.signing_endpoint` and each pair's `endpoint` to that `EndpointRef`. Re-issue `restore_consumers` uses
  `InstalledKeyOf { grant }` (+ `SlotsOnly`), the follower's source. The leader's `prepare::binding_endpoint`
  prefers `materialized.endpoint` (tag + layout only when the call reused a running endpoint).
- XM-3 (item 1). `adapters::managed::advertised_enforcement()` = baseline with `destination_scope:
  verified_server_principals`, used only by the managed descriptor (`baseline_enforcement` unchanged). No M01/M02
  descriptor or resolution code changed (`git diff` of `crates/app/src/operations/pair_mechanism_m03.rs`,
  `crates/adapters/src/{existing,m01…}`: none by me).
- XM-4 (items 1, 5; harness). `managed_store.rs` `live_tests`: `LiveFeed` (observations, target evaluations,
  client) read through `Observed` (the harness's `Observing`) wrapped in `prepare::WithEvidenceFeed` (the runtime's
  `LateEvidenceFeed`), i.e. exactly where production reads them; empty by default (no behaviour change for the
  existing live tests). `FixtureIssuer.others` + `Live::add_ca()` (created later than the seeded CA, so the
  newest-verified selection picks it) for the other-CA case. `service.rs` `mod sources` not touched.
- XM-5 (item 5, the gap). The per-pair selection was already fed on every managed path (the delegation's child
  pairs come out `exclusive`), but **every non-interactive managed request was refused `interaction_unknown`**:
  `Facts::from_outcome` → `history_only` resets each pair to `unknown`/not eligible and `fresh_pair`'s managed arm
  (integrator, R2C-Q1 option a) only moved the check time. Fix in `operations.rs` `fresh_pair` (the commit's
  eligibility, called from `stage_commit`; outside the R3-C2 function list — recorded under Requests): the managed
  arm restores the adapter's constant values (`none`, inferred, eligible), exactly what `pair_integrations` sets.
  `fresh_fallback_refusal` still refuses a non-`exclusive` managed pair (regression `undetermined_…`).
- XM-6 (item 5). `live_tests::cleanup::parent_with_second_reference` → `parent_with_child_delegation` (a real
  non-interactive `delegate`, aliases observed `exclusive`); used by both cleanup tests that had the seeded reference.

- XM-7 (item 1, the M01/M02 check). With the descriptor alone moved, `integration_managed_adapter::
  projection_pending_refused_only_for_managed_only_minimums` failed (exit 101, :4164, reason `None` instead of
  `projection_pending`): `select_adapter` with **no** resolved mechanism (the M01 selection: a pending projection's
  existing path, a pair with no catalog identity) picked the managed adapter for a scope minimum. Fix in
  `operations.rs` `select_adapter` (outside my listed functions; under Requests): for `mechanism == None` the managed
  adapter's scope counts as `unknown`, as before; with pairs resolved to `managed_certificate` its advertised scope
  counts. So M01/M02 resolution is unchanged.

## Progress
- [x] item 6 - [x] item 1 - [x] item 5 - [x] revert runs - [x] checks

## Commands (exit codes)
- `cargo test -p heimdall-runtime --lib managed_store` (after item 6): 0 (21 passed).
- `cargo test -p heimdall-adapters --test integration_managed_adapter` (after item 6): 0 (48). `cargo test -p heimdall
  --test e2e_managed_m03`: 0 (16).
- `cargo test -p heimdall-runtime --lib selection` ×6 after the CA-ordering fix: 0 each (an earlier version was flaky
  ~50%: both CAs had `created_at` t0, so the issuing CA was the fingerprint order; fixed by `add_ca`'s later
  `created_at`).

- Final, after the last edit: `cargo test -p heimdall-runtime --no-fail-fast`: 0 (lib 52, all targets);
  `cargo test -p heimdall --test e2e_managed_m03 --test e2e_enroll_m03 --test e2e_run_m02 --test e2e_cli_m02 --test
  e2e_consumer_m03 --no-fail-fast`: 0 (16; 66; 54 + 1 ignored; 42 + 1 ignored; 7); `cargo test -p heimdall-adapters
  --test integration_managed_adapter`: 0 (48); `cargo test -p heimdall-app --tests`: 0 (50, 3, 16, 54, 29). Summed:
  1001 passed, 0 failed.
- `cargo clippy --workspace --all-targets -- -D warnings`: 0 (not narrowed). `bash tools/validation/clippy-windows.sh`:
  0. `bash tools/validation/linux-xcheck.sh -p heimdall-runtime`: 0.
- `rustfmt --edition 2024 --check` on every file I touched: 0.
- Scratch `/tmp/xm-revert.*` (revert script, logs) removed; no `XM-REVERT` marker left. `target/x86_64-pc-windows-gnu`
  (2.4 GB) left in place: other workers build into it concurrently.

## Revert runs (`/tmp/xm-revert.*/revert.py <key> revert|restore`: one exact in-place substitution each; removed after)
| Key | Fix reverted | Regression | Reverted | Restored |
|---|---|---|---|---|
| r6a | follower result not renamed (names the leader's endpoint) | `pipeline::follower_names_exactly_the_endpoint_its_materialization_created` | 101 (:1071) | 0 |
| r6b | `files.endpoint == None` → a derived `<dir>/agent.sock` instead of the refusal | `pipeline::follower_refused_when_its_materialization_created_no_endpoint` | 101 (:1106 ACCESS_READY) | 0 |
| r6c1 | `InstalledKeyOf` grant ≠ attached grant not refused | `pipeline::materialize_refuses_a_spec_with_an_inconsistent_source` | 101 (another live grant's key written into the binding) | 0 |
| r6c2 | `Fresh` without certificates not refused | same | 101 (endpoint + key-only files created) | 0 |
| r1 | descriptor advertises `baseline_enforcement()` (`unknown`) | `selection::scope_minimum_met_with_valid_evidence_refused_at_the_comparison_when_invalidated` | 101 (valid evidence refused at resolution, "no configured credential mechanism…") | 0 |
| r5a | `fresh_pair` managed arm keeps history's `interaction_unknown` | `selection::exclusive_alias_delegates_non_interactively` | 101 (`INTERACTION_REQUIRED interaction_unknown`) | 0 |
| r5a | same | `cleanup::released_slot_holder_frees_its_slots_while_grant_stays_live` | 101 (delegate refused) | 0 |
| r5b | `fresh_fallback_refusal` skips managed pairs | `selection::undetermined_alias_delegation_refused_interaction_required` | 101 (undetermined pair delegated) | 0 |
| r5c | `pair_integrations` ignores the observation (always `undetermined`) | `selection::exclusive_alias_delegates_non_interactively` | 101 | 0 |
| r5c | same | `selection::undetermined_alias_delegation_refused_interaction_required` | 101 (exclusive pair alone refused) | 0 |
| r5d | R3-C1's `release_binding_slots_in` moves no slot | `cleanup::released_slot_holder_frees_its_slots_while_grant_stays_live` (real delegation) | 101 (:348) | 0 |
| r1b | `select_adapter` counts the managed advertised scope for `mechanism == None` | `integration_managed_adapter::projection_pending_refused_only_for_managed_only_minimums` | 101 (:4164 reason `None`) | 0 |
