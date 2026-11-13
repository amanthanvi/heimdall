# M03 wave 4, round 5 — worker Y-S (W4-C02) worklog

## Goal
W4-C02 (high): every newly committed managed follower (coalesced, decision-joined, attached to an active
equivalent grant, recovered/continued) recomputes its own `destination_scope` from evidence read at its commit
(grant's pairs, current client, current target evaluation, the CA of the installed certificate per pair); the
leader's historical result never satisfies the follower's minimum. ADR-0008 §17.22 item 7, §17.23 items 1, 6.

## Decisions
- YS-1. Judgement shared: `managed_driver_m03::pair_evidence_under_ca(managed, pair, ca)` (newest `verified`
  evidence under `ca`, the exact iterator that was inline in `prepare::pair_evidence`), re-exported
  `heimdall_app::operations::pair_evidence_under_ca`; `prepare::pair_evidence` now calls it (same semantics).
- YS-2. Evidence read: `Operations::follower_scope(grant, adapter)` (managed_driver_m03): one store transaction
  (grant scope pairs, `catalog_pairs`, `installed_cas_in`: CA of each pair's entry attached to an `installed`
  instance; a pair with conflicting/absent CA has none), then the managed adapter's own `read_sources` through
  `read_prepare_sources` (blocking pool) — so the R3-A comparison (`invalidate_evidence`: target + client) runs
  exactly as for a fresh preparation. Wrong/missing adapter, grant or catalog pair → no claim.
- YS-3. `FollowerScope::claim(now)`: `verified_server_principals` iff the grant has pairs and every pair has an
  installed CA whose evidence holds with `fresh_until > now` (report::compute's rule; report.rs not in my region,
  so the two-line freshness/all-pairs rule is mirrored, not shared), else `unknown`.
- YS-4. `stage_commit`: for `attached && managed`, `follower_scope` is read after `materialize_follower`, before
  the commit transaction; inside it the facts' `destination_scope` is replaced by `claim(now)` (commit's
  accepted time) before `unmet_minimum`. Refusal takes the existing attached path (CAPABILITY_UNAVAILABLE,
  effect none, follower cleanup intent processed). Leader and existing-access paths untouched (`follower_scope`
  is `None` for them). No contract reason added: `minimum_not_met` is the adapter-internal reason; the follower's
  refusal is `unmet_minimum`'s scope message (no registered envelope reason exists for it).
- YS-5. Outside my listed functions: one line `pub use managed_driver_m03::pair_evidence_under_ca;` beside the
  other `pub use` lines in `operations.rs` (needed for `adapters` to call the shared helper).

## Coordination
- ~23:22–23:23 Y-C restored the whole `managed_driver_m03.rs` from an old copy during a revert proof. My hunk
  survived; my first `cas` mutation was overwritten mid-run, so that run (exit 0) is void and was repeated. My
  reverts are in-place substitutions only (`/tmp/ys-r5/revert.py`, `YS-REVERT` marker, checked after each run).

## Regressions (`crates/runtime/src/managed_store/live_tests/follower_scope.rs`)
- `decision_joined_follower_refused_when_evidence_changes_after_leader_commit` (reviewer's scenario + control)
- `coalesced_follower_refused_when_evidence_changes_after_leader_commit` (+ control)
- `follower_without_minimum_commits_reporting_unknown_after_the_change`
- `follower_with_valid_evidence_meets_the_minimum` (decision-joined and coalesced)

## Revert proofs (`cargo test -p heimdall-runtime --lib follower_scope`)
| Key | Mutation | Reverted | Restored |
|---|---|---|---|
| override | stage_commit never applies the follower's claim (`.filter(\|_\| false)`) | 101: 3 failed (joined/coalesced "accepted invalidated evidence: scope=VerifiedServerPrincipals, same_grant=true"; no-minimum reports `VerifiedServerPrincipals`) | 0 (4 passed) |
| cas | `installed_cas_in` reads `pending` instead of `installed` instances (no CA → over-strict) | 101: `follower_with_valid_evidence_meets_the_minimum` (joined refused CAPABILITY_UNAVAILABLE) | 0 (4 passed) |

## Commands (exit codes)
- `cargo clippy -p heimdall-app -p heimdall-adapters --all-targets -- -D warnings`: 0.
- `cargo test -p heimdall-runtime --lib follower_scope`: 0 (4 passed).
