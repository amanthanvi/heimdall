# M03-W0-code-review — m03/wave0 (410ec237..87b9a263) — fix first

**Reviewer:** Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high). Independent and read-only, in a separate worktree; it added scratch probes.

Saved by the orchestrator on 2026-11-08, verbatim in substance. Orchestrator resolution: ADR-0008 §17.16.

The six requested validation commands passed. The scratch probes reproduced five correctness gaps.

## Findings

| ID | Severity | Location | Defect | Evidence | Fix |
|---|---|---|---|---|---|
| M03-W0-R1 | P1 | `crates/app/src/operations/narrowing.rs:1050` | `policy_commit` gates only `Cutoff`. Changing `Continue` to `RevokeOnLock` commits through an ordinary store write, so an already-admitted permit neither sees a pending mark nor rechecks the lock policy at release. The provisional reading G-Q10 is wrong. | **Observed.** A permit was admitted while the source said `Locked` and the policy was `Continue`. `SetLockBehavior(RevokeOnLock)` then committed, and the old permit still returned `may_release() == true`, while a fresh admission refused with `SessionNotUnlocked`. | Route this authority-reducing change through the full narrowing protocol for the affected grants and their descendants. Add a regression for the held-permit trace. |
| M03-W0-R2 | P1 | `narrowing.rs:993`; the mutation is at `crates/store/src/ext.rs:828` | `narrow_withdrawals` gates the withdrawal that the next revalidation discovers, after the permission-removal transaction has already committed. The provisional reading V-E6(a) is wrong. | **Observed.** After a permit was admitted, `upsert_environment(automatic_activation=false)` committed, and the old permit stayed releasable before any tick. A fresh admission refused with `StaleGeneration`. | Gate the permission-removal transaction itself, including the affected grants and their descendants. Keep the revalidation as recovery. |
| M03-W0-R3 | P1 | `crates/app/src/managed.rs:718` | `defer_to_earlier` waits for an earlier narrowing while keeping the gates it has already acquired, and those gates can join the earlier narrowing's set when that set grows. The earlier narrowing marks B. The later one marks {A, B}, acquires A and defers at B. The earlier one then finds A, marks it, releases its gates and waits on the later one's gate, so each waits for the other. | **Observed**, both with a primitive-level probe and with two real `Operations::policy(Cutoff)` calls: neither commits after 100 virtual seconds. | Before deferring to an earlier narrowing, release every exclusive hold, keep the pending marks, and restart acquisition in global order. Add a regression with a growing multi-root set. |
| M03-W0-R4 | P1 | `crates/app/src/operations/authorize.rs:300` | The remaining continuous budget is computed from `auth.safe.anchor.continuous`, observed inside the transaction, but is added to `Instant::now()` after the awaited transaction returns. The time the read and commit take is added back to the budget. | **Observed.** With a 500 ms authorization-commit delay and 500 ms of wall-clock lag, the permit still passed `may_release()` 100 ms after the original budget ended. | Map the budget to an absolute expiry using paired clock readings from the same observation, or subtract the elapsed authorization time. Refuse when the budget has already expired. |
| M03-W0-R5 | P2 | `crates/store/src/ext_m03.rs:1264` | Unlike `transition_enrollment`, `transition_foreign_removal` does not check a cancellation's `origin` and `ca_not_held_seen` against the stored `removal_origin`. | **Observed.** A foreign system-form removal persisted `ca_not_held_seen = true`. A cancellation carrying `false` was accepted back to `Planned`, then went `DecisionWithdrawn → Withdrawn` without proof of absence. That contradicts §17.10 item 2 and ADR-0006 §16.2 item 14. | Validate the cancellation's facts against the persisted origin, as the own-enrollment method does, and never downgrade the persisted absence-history flag. |

## Sound
- **Release queue:** it reserves capacity before the release check, and holds the permit through the enqueue.
- **Gate retirement:** it keeps holders and pending marks.
- **Migration 0006:** it preserves populated version-5 data.
- **S1 index:** it implements the recorded follow-up.
- **Mechanical literal edits:** behavioural assertions are preserved, and the schema-version assertions were updated explicitly.
- **Skeletons:** no new reachable `todo!()`, `unimplemented!()` or production panic. The later-unit skeletons fail closed, the claims table is empty, and both listener constructors refuse the issuer endpoint.

## Commands (reviewer)

| Command | Exit |
|---|---|
| `cargo test -p heimdall-app` | 0 |
| `cargo test -p heimdall-domain` | 0 |
| `cargo test -p heimdall-store` | 0 |
| `cargo test -p heimdall-ipc` | 0 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 |
| `crate_graph.py` | 0 |
| `claims_table.py` | 0 |
| `release-gate.sh` | 0 (22 probes) |
| `model_narrowing_m03` | 0 (48) |
| `integration_store_m03` | 0 (25) |
| `contracts` | 0 (89) |
| Scratch probes | 0 |

Not run: the full workspace suite and native runs. The reviewed head lacks ADR-0008 §17.15, so the reviewer read the recorded rulings in the escalation index instead.
