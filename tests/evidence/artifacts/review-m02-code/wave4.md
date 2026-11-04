# M02-W4-code-review — bac4be49 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03; the findings, the re-check
table and the validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007
§12.31.

**Reviewed range:** `e7fdbb35..bac4be49`, validated at HEAD `bac4be49`.

Four defects need correcting:
* an unattended state purge bypasses the required confirmation;
* doctor can run a real-tree probe after skipping its authorization;
* two TUI rendering paths hide information the owner needs for an informed approval.

S01 and R01 are closed for their reviewed scenarios. The full workspace rerun, fmt and clippy
passed. The first workspace run had one failure, in an unchanged pipe test (below).

## Findings

### Q01 — High (P1) — State purging bypasses attended confirmation

**Location:** `crates/heimdall/src/uninstall_cmd.rs:333`, `:336`, `:460`.

**Defect:** Once rollback is complete and the projection resources are absent, `--purge-state`
calls `purge_state` directly. It does not require an interactive session, does not show the
authority and recovery data that will be lost, and does not ask for typed confirmation.
ADR-0007 Q6, accepted by §12.1, requires an attended typed confirmation that lists the loss.

**Evidence:** With a scratch runtime, a scratch home, a real scratch database and a disposable
backup, `heimdall --json --non-interactive uninstall --purge-state` with stdin from `/dev/null`
exited 0 with `OK`, `runtime_stopped: true` and `purged: true`. The database and the backup were
deleted, and nothing prompted. **Observed** against the real binary.

**Fix:** A separate purge confirmation that lists the database contents and the backups being
discarded. Require an attended typed `y`/`yes`; non-TTY, `--non-interactive`, EOF, interruption,
timeout and any other answer keep the state. Add a successful-purge regression covering both
refusal and an affirmative confirmation.

### Q02 — High (P1) — A skipped doctor authorization can become permission to execute

**Location:** `crates/heimdall/src/doctor_cmd.rs:120`, `:128`, `:232`.

**Defect:** When `authorization_text` finds no runnable alias, for example because the
configuration cannot be fully read, `authorize` returns `Ok(())` without prompting. `doctor` then
runs a fresh assessment with the original `allow_config_commands: true`. If the tree has become
readable between the two passes, the fresh assessment runs the real-tree level although no typed
authorization happened. This is not the accepted mutable-tree residual: no authorization was ever
obtained.

**Evidence:** A deterministic scratch reproduction combined:
* a configuration with an unexpandable Include;
* TTY stdin with no affirmative answer;
* a disposable `ssh` stub whose permitted `-V` query rewrites the configuration into a readable,
  inert one;
* a marker that only the later evaluation writes.

`doctor --alias alpha --active-probe evaluate --allow-config-commands` exited 0 with `OK` and the
evaluate probe `ok`. The marker existed and no prompt appeared. **Observed**; an external editor
racing the same way is **inferred**.

**Fix:** Distinguish "typed authorization obtained" from "nothing was runnable". When
authorization is skipped, decline real-tree execution for that invocation. Add the
unreadable-to-readable regression, asserting that no evaluation runs.

### Q03 — Medium (P2) — Projection decisions permanently truncate the action being approved

**Location:** `crates/heimdall/src/tui/view.rs:1151`, `:1153`, `:1165`.

**Defect:** The wide projection-decision layout truncates each before/after/restore cell with
`chars().take(...)`. Vertical scrolling cannot recover the discarded suffix, and there is no
full-text view. The committed `decision_apply_120x40.txt` snapshot shows an Include line cut off
mid-path. Typing `yes` still approves the complete recorded plan, contrary to ADR-0006 §3.1.
**Observed** in the snapshot and the renderer.

**Fix:** Keep the complete diff text: wrap instead of discarding, use the stacked layout, or offer
a full-text view. Add a regression with meaningful suffixes beyond the cell width.

### Q04 — Medium (P2) — Configuration-command authorization hides list entries with no way to scroll

**Location:** `crates/heimdall/src/tui/view.rs:1293`, `:1306`; `crates/heimdall/src/tui/model.rs:1389`.

**Defect:** The authorization modal renders its configuration-command inventory with `scroll: 0`,
and its key handler cannot scroll. When the inventory is taller than the space available, later
file:line entries cannot be reached, yet the affirmative prompt still works.

**Evidence:** The real binary in a 40×12 scratch TUI, with 15 static `Match exec` constructs and
a harmless ssh stub: `config:2` was visible; `config:30` stayed invisible after twelve Page Down
presses; typing `yes` ran the evaluation stub. **Observed**; no real configuration command or
network connection was run.

**Fix:** Give the authorization content a scroll offset and navigation controls, keeping the
prompt separate. Add a small-terminal regression proving that the last entry can be reached.

## Earlier findings re-checked

| Finding | Result | Regression fails without the fix? |
|---|---|---|
| S01 | closed: `s01_declaration_withdrawn_after_the_snapshot_refuses_noninteractive_activation`, `s01_fallback_clearance_that_no_longer_holds_refuses_noninteractive_activation` | yes (inferred from the diff and assertions; no mutation run) |
| R01 | closed: `a_replaced_adopted_public_key_is_refused_before_anything_runs` | yes (inferred) |

## Checks found sound (summary)

* Approval: the CLI shows the recorded request and accepts only a trimmed `y`/`yes`.
* The setup preview comes before any effect, and approval binds the plan digest.
* The TUI decision modal requires typed confirmation.
* The ordinary doctor authorization path shows the effects text, and the non-interactive flag
  exception is as documented.
* Readiness combines every invocation profile.
* The optional `local_user` is implemented.
* A decided operation resumes in its own interaction mode.
* TUI search runs in memory; terminal restoration (child exit, signal, panic, hangup, Ctrl-Z)
  and no cursor queries.
* Uninstall rolls back through the setup transaction.
* The content scan was clean.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` (first run) | 101 | failed in the unchanged `heimdall-launch` test `meta::tests::fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal`: `unwrap_err()` got `Ok(())` at `crates/launch/src/meta.rs:624` |
| that test alone (`--exact`) | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` (full rerun) | 0 | 1625 passed, 0 failed, 7 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| scratch reproductions (purge, doctor authorization, 40×12 TUI inventory) | 0 | reproduced Q01, Q02 and Q04 |
| `git diff --check`; content scan; cleanup; final `git status` | 0 | clean |

Not checked: native Windows and WSL, live provider dialogs, owner material, power loss, mutation
runs, full-duration prompt timeouts. The cause of the pipe-test failure is unresolved.
