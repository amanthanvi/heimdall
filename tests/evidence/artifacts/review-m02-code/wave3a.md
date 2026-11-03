# M02-W3a-code-review — 482c9e70 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03; the findings and the
validation table are kept verbatim in substance. Orchestrator resolution: ADR-0007 §12.23.

**Reviewed range:** `9023d017..482c9e70`, validated at HEAD `482c9e70`.

The activation change set needs two fixes before shipping. A running held repair can keep
changing durable state after a cancel reports no effect, and the adapter timeout does not bound
the synchronous work the real adapters do. Disposable probes over the production components
reproduced both. All three required workspace checks passed.

## Findings

### U01 — High (P1) — Cancellation reports no effect while a held repair continues settling files

**Location:** `crates/app/src/setup.rs:1847`, `:1905`; the cancellation check is at
`crates/app/src/operations.rs:1613`.

**Defect:** A held repair never records an attempt on the repair operation. `start_repair` only
moves it to `running`, and `retry_held` then calls `reconcile_op` on the original held operation,
whose sink receives every later receipt. Cancellation looks only at the repair operation's
receipts. With none, it marks the running repair `cancelled` with effect `none` and settles its
idempotency record, and the driver carries on against the original operation. This contradicts
ADR-0007 §12.22 item 1.

**Scenario:** An update is held because its displaced file is missing. The file is restored and a
`retry_held` repair is submitted, then cancelled while it is entering reconciliation. The cancel
succeeds (`cancelled`, effect `none`). Reconciliation continues, settles filesystem entries and
completes the original operation; the repair stays recorded as cancelled. While the original
operation still appears held, cancelling its repair also lifts the extra admission blocker. The
store's held-repair exception (`crates/store/src/ext.rs:2278`) can then admit a second repair of
the same operation while the first is still running.

**Evidence:** A scratch probe over the setup fixture, the real `Operations`, the real store and
the real projection writer paused the repair just before the writer's reconcile. It asserted:
no receipts on the running repair; `cancelled` with effect `none`; after release, the filesystem
tree changed through settlement; the original operation reached `succeeded`; the repair stayed
`cancelled`. The probe exited 0, confirming the defect. **Observed.** The second concurrent
repair is **inferred** from the store predicate.

**Fix:** Atomically record the repair's attempt when it starts, before any reconcile or closure
receipt against the original operation, and proceed only if that transaction confirms the
repair is still runnable. After that point, cancellation returns `OUTCOME_UNKNOWN` with
reconcile guidance. Add a regression that cancels a held repair paused before the writer's work.

### U02 — High (P1) — The timeout wrapper cannot interrupt synchronous work in real adapter calls

**Location:** `crates/app/src/operations.rs:287`; the production path is at
`crates/adapters/src/native_agent.rs:97` and `crates/runtime/src/service.rs:1047`.

**Defect:** `bounded_adapter_call` wraps the adapter future in `tokio::time::timeout`, but the
real adapter's `prepare` runs its synchronous core without yielding. That core calls synchronous
runtime sources, including store transactions and projection observation. If one blocks, Tokio
cannot poll the deadline or drop the future. When the work returns, the wrapper accepts the
result even after the deadline. A permanently blocked call also keeps the adapter slot and the
preparing marker. This fails ADR-0006 §13.20 item 3 and m02-plan U0b row 24.

**Evidence:** A scratch probe used the production `NativeAgentAdapter` and `RuntimeSources`, a
real in-memory `Store`, a disposable fake-agent endpoint, a thread holding a store transaction
for 80 ms, and the real `bounded_adapter_call` with a 10 ms deadline. The call stayed blocked
past the deadline, returned success, and left an integration that `reconcile` reported as
applied. A second probe with a deliberately slow source callback reproduced the same behaviour.
`u0b_every_adapter_call_is_bounded` checks where the wrapper is placed in the source text, so it
cannot detect this. **Observed** with a shortened deadline. The production 30 s case and a
permanently retained marker are **inferred** from the same path.

**Fix:** Make the real adapter's execution deadline-aware and cancellable across its store and
filesystem work, keeping the rule that no work continues after the timeout (detaching the work
into `spawn_blocking` alone does not meet it). Add a behavioural regression with the real
adapter and runtime sources under controlled contention.

## Checks found sound (summary)

* Decision binding requires an awaiting operation and a matching local intent; setup approvals
  bind the plan digest.
* The regular setup driver recomputes the plan before an attempt and refuses a differing digest.
* Replay and restart are classified before recomputing; `setup.attempt` is recorded before
  `apply`.
* Setup admission is atomic in one `BEGIN IMMEDIATE` transaction.
* A regular apply's cancel is refused once started.
* Fallback clearance is checked against the adopted fingerprint.
* Wire compatibility: the contract tests pass and the schemas match.
* The targeted content scan was clean.
* The deferred wave-3b work was assessed against the rulings and is not reported.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | passed |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `git diff --check 9023d017..482c9e70`; targeted privacy scan | 0 | clean |
| `review_cancel_running_held_repair` probe | 0 | reproduced U01 |
| `review_real_prepare_exceeds_timeout`, `review_runtime_store_wait_exceeds_timeout` probes | 0 | reproduced U02 |
| cleanup of target/ (4.4 GB) and probes; final `git status` | 0 | clean |

Not checked: native Windows and WSL, live 1Password or hardware, owner-account production
wiring, power-loss recovery, the production 30 s stall, and the second concurrent repair.
