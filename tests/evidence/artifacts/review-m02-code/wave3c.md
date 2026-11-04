# M02-W3c-code-review — 6066df3e — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03; the finding and the
validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007 §12.27.

**Reviewed range:** `29d42da6..6066df3e`, validated at HEAD `6066df3e`.

The original U01 cancellation defect and U02 blocking-source defect are fixed under the accepted
rulings, and their regressions discriminate. All three required workspace checks passed. One
snapshot race remains: a non-interactive ensure can activate a grant and return `ACCESS_READY`
after its declaration has been withdrawn.

## Findings

### S01 — Medium (P2) — Declaration withdrawal after the snapshot does not prevent non-interactive activation

**Location:** `crates/app/src/operations.rs:6268`, `:6878`, `:6902`.

**Defect:** `read_prepare_sources` captures declaration rows before the bounded adapter call. A
declaration can be withdrawn after that read, while `prepare_from` still accepts the snapshot's
live declaration. The commit transaction recomputes fresh eligibility through
`Facts::with_eligibility`, but neither `activation_refusal` nor `unmet_minimum` refuses a
non-interactive request whose pair is now ineligible. The grant is activated and `ACCESS_READY`
returned, with contradictory fresh pair fields. ADR-0007 §7's results table requires
`INTERACTION_REQUIRED` when fresh eligibility shows a withdrawn or lapsed declaration.

**Evidence:** A scratch probe over the model harness, with the production `Operations`,
`NativeAgentAdapter`, a real in-memory store and `RuntimeSources`, withdrew the declaration right
after the snapshot captured its rows. It asserted: the stored declaration is `Withdrawn`; the
non-interactive ensure returned `ACCESS_READY`; the grant is `Active`; the returned pair has
`noninteractive.eligible == false`; the disposable agent was never contacted. Exit 0.
**Observed** under controlled interleaving. The concurrent owner case is **inferred**. No CLI
launch bypass was shown, because the CLI's own fresh eligibility check limits the impact.

**Fix:** In the final activation transaction, enforce the request's non-interactive requirement
against fresh store eligibility before activating the grant or creating its binding, including
fresh declaration eligibility for any fallback clearance it relies on. Keep the snapshot design.
Add the withdrawal interleaving as a regression expecting `INTERACTION_REQUIRED` and no new
active binding.

## Earlier findings re-checked

* **U01 — closed for the reviewed paths.** `start_repair` atomically moves a runnable repair to
  `running` and records its own `setup.attempt` before any work against the held operation.
  `held_repair_paused_before_the_writer_refuses_cancel_and_a_second_repair` passes and would fail
  without the attempt recording.
* **U02 — the blocking-source defect is closed; the freshness gap remains as S01.** Production
  adapters read their inputs through `read_sources` before `bounded_adapter_call`, and a late
  answer is rejected. Both behavioural regressions pass and discriminate.

## Checks found sound (summary)

* The catalog listings check `ctx.is_owner()`.
* Observed-alias `connect` reaches the shared eligibility check.
* Replayed bindings are refused when released.
* Decision completion checks state, expiry, intent and generation; stale reissue binds the
  current identity and endpoint.
* The manual first-adoption regression is in place.
* `ErrorDetail.entries` is wire-compatible.
* The privacy scan was clean.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | passed |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| targeted U01 regression | 0 | passed |
| U02 behavioural regressions (scratch harness) | 0 | passed |
| `review_withdrawal_after_snapshot_still_activates_noninteractive_ensure` | 0 | reproduced S01 |
| `git diff --check`; privacy scans; cleanup; final `git status` | 0 | clean |

Not checked: native Windows and WSL, live 1Password or hardware, owner-account production wiring,
power-loss recovery, production-duration hangs. No mutation testing.
