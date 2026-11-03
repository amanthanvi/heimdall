# M02-W3b-code-review — 7b5015ef — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03; the findings and the
validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007 §12.25.

**Reviewed range:** `11e2069a..7b5015ef`, validated at HEAD `7b5015ef`.

All three required checks passed: 1480 tests passed and 0 failed, fmt passed, and clippy passed
with warnings denied. Four scratch probes nevertheless reproduced defects in non-interactive
eligibility and holder tracking. They are separate from the wave-3c work of §12.23–§12.24.

## Findings

### T01 — High (P1) — The pre-launch selection check misses exec-only and subsystem-only identities

**Location:** `crates/heimdall/src/launch_flow.rs:420`; `crates/localenv/src/projection/observe.rs:75`.

**Defect:** `fresh_selection` delegates to `projection::observe`, whose query always uses
`Invocation::Shell`. So the check verifies the shell's identity selection even when `run`
launches Git-over-SSH, a remote command, SCP or SFTP. An identity behind `Match sessiontype
exec`, `Match sessiontype subsystem` or an applicable `Match command` can be missing from the
checked selection.

**Scenario and evidence:** A binding uses declared key K1. After the bind, the configuration
gains `Match sessiontype exec` with an undeclared, agent-backed K2. Probe
`review_exec_only_fallback_passes_the_prelaunch_check` used the A11 fixture, the real runtime, the
real CLI and the pre-check pause; it observed the child marker and the `launching` record. The
production evaluator over the same configuration gives `Shell`: `Exclusive` and `Exec(None)`:
`NotExclusive` (two entries). **Observed.** A provider prompt that follows is **inferred**.

**Fix:** Check every invocation profile the launched work can use. For an arbitrary `run`, cover
shell, unknown exec and SFTP, failing closed on an uncleared or undetermined selection. The
authentication probe evaluates its actual exec invocation.

### T02 — High (P1) — `Match localuser` uses environment metadata instead of the OS account

**Location:** `crates/heimdall/src/launch_flow.rs:420`; `crates/localenv/src/projection/observe.rs:65`.

**Defect:** The observation behind the pre-launch gate takes `local_user` from `USER` or
`USERNAME`, defaulting to an empty string. On Unix, OpenSSH takes the local user from the
account database. With the environment missing or different, Heimdall can decide a condition is
false where OpenSSH applies it.

**Evidence:** Probe `review_localuser_fallback_passes_with_user_unset` cleared `USER`, then
during the pre-check pause appended a `Match localuser <the OS account>` rule that adds an
undeclared fallback. The real non-interactive CLI launched its marker child. Evaluating with the
OS account name gives `NotExclusive`, with the fallback present. The correct lookup already
exists as `LocalContext::local_user` in `crates/localenv/src/doctor.rs`. **Observed.**

**Fix:** Use the OS account lookup in every Unix query builder, including projection consent.
If the account cannot be established, treat the condition as undetermined. Add a regression
with `USER` absent and one with it set to a different name.

### T03 — High (P1) — The authentication probe accepts an exclusive key through an undeclared agent

**Location:** `crates/localenv/src/probe/auth.rs:141–156`.

**Defect:** `noninteractive_refusal` returns success as soon as the selection is `Exclusive`. It
never checks that the effective `IdentityAgent` is the endpoint the adopted identity's
declaration covers; `effective_agent` is consulted only on the fallback branch.

**Evidence:** Probe `review_authentication_probe_ignores_changed_agent_for_exclusive_key`
(production `LocalContext`, `ProbeContext` and `authenticate_observed`) set an exclusive selection
of K1 while the effective configuration named a different agent endpoint. The result: no refusal,
`ProbeOutcome::Ok`, and the client stub's marker existed. **Observed.**

**Fix:** Before either success path, establish the effective agent and require it to match the
adopted identity's declared endpoint. Refuse an unknown or mismatched endpoint. Add an
exclusive-selection regression that changes only `IdentityAgent`.

### T04 — High (P1) — Overlapping invocations share one holder and release a live child's binding

**Location:** `crates/heimdall/src/run_cmd.rs:217–228`; `crates/app/src/operations.rs:7869–7889`;
`crates/app/src/holders.rs:113–120`.

**Defect:** A second explicit `run` with the same request ID replays the successful bind and
launches another child, but the settled bind does not register the second process as a holder.
Both children use one binding that only the first process holds.

**Evidence:** Probe `review_replayed_live_binding_releases_while_second_child_lives` started two
real CLI invocations, each blocked on its own scratch FIFO. Both got the same operation and
binding IDs and the binding was active. After A was released and reaped, the binding left the
active listing and the store showed `BindingState::Released`, while B's exact child handle still
reported a running process. **Observed** through the production binary, supervisor and liveness
check. This is separate from §12.24's re-check of an already-released binding: the binding is
active when B launches.

**Fix:** Track each permitted live invocation as its own reference, or refuse a second launch
while the request's binding already has a live holder. Do not just overwrite the holder.

## Checks found sound (summary)

* Consent v3 covers shell, unknown exec and SFTP, binds their ordered digests and requires every
  profile to be determined.
* Fresh declaration checks: revision, endpoint and expiry.
* Argument privacy: arguments are absent from the bind, meta records and logs (canary tests).
* The meta file is created exclusively, without following links, close-on-exec, mode 0600.
* Unix exec, signal, PTY and failed-exec metadata.
* The holder-replacement race fix.
* Profile removal semantics.
* The committed-content scan was clean.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1480 passed, 0 failed, 5 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `git diff --check 11e2069a..7b5015ef`; added-line scan | 0 | clean |
| final scratch probes `review_*` | 0 | all four defects reproduced (asserting the defective behaviour) |
| cleanup of target/ and probes; final `git status` | 0 | clean |

Not checked: native Windows and WSL; live provider approval dialogs.
