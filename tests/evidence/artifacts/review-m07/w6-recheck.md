<!-- M07 wave 6 scoped re-check (Opus), of 6416aeb4..e924b244, 2026-11-23. Archived verbatim by the M07 integrator; its probes are not archived. -->

# Heimdall M07 W6: scoped re-check of the W5 findings and the two rulings

**Verdict: CLOSED (merge).** Nothing in this re-check blocks. M07-W5-R01, R02, R03 and R04 are closed. Ruling 1 (a request that got no answer is remembered and observed before the close) is closed for every no-answer case. Its extension to "an `ACCEPTED` whose wait times out" is **partly closed**. Ruling 2 (attribution) is closed: no probe got H2 to release a binding that fails the ruled checks. There are three new findings, all nonblocking: one moderate, two low. The moderate one, M07-W6-R01, is the part of the ruling extension that is not closed. It belongs with the next wave's known-open group.

Candidate: `e924b24465e7b613c9a20756f4d9fb0496ee5994`, checked out detached in my worktree. Scope: `git diff 6416aeb4 e924b244 -- examples/harnesses/goal-loop docs/architecture/m07-plan.md docs/architecture/m07-u0-handoff.md`, which covers 5 files, +2888/−306 lines. Everything ran on macOS arm64 with Python 3.15.2. I edited no repository file, made no commit and did not push.

## Table

| Item | Status | Evidence |
|---|---|---|
| **M07-W5-R01**: a timed-out release is forgotten and resent, and the close skips other bindings | **closed** | Probes R01a–e and X2, all as expected. In R01a, the reviewer's case: the release prints a complete `OUTCOME_UNKNOWN` naming `op_r1`, then hangs. Observed calls: `ensure`, `release`, `wait op_r1`. There is no second release. The stop records `outcome_unknown` with `operation_id` and `fault: timed_out`, and the close records `released` after observing it. In R01b, three bindings are held and every call hangs. Each release is sent exactly once, the close makes 3 × `inspect bindings` and no resend, all three stay held, and the exit is 1. R01c (garbled answer) and R01d (an `OK` that names another binding) are each one release and then an observation, never a resend. In R01e the operation ends `failed` with effect `none` (exit 4), so the only resend is release, wait, release. X2: of 8 refused bindings, each is asked once by the goal stops (6 + 2) and once by the close. The same probes on the W5 baseline `6416aeb4` fail R01a–e. |
| **M07-W5-R02**: a nonterminal view is read as a completed release | **closed** | 15 view variants (R02-*). Only `succeeded` gives `released` (with code `OK` or null). Only `failed` + code + effect `none` in the code's class gives `not_run` and one resend. These all stay `still_unknown`, with nothing sent and the binding held: `running`/exit 0 (inconsistent), `queued`, `awaiting_approval` or `running` carrying a refusal code, `failed` with no code, `failed` + `CAPABILITY_UNAVAILABLE` with exit 0 (inconsistent), `cancelled`/partial, the unknown state `paused`, `outcome_unknown`, `failed` with code `OK`, a view of another operation, and `succeeded` with `next: observe`. Baseline: 6 of these fail. |
| **M07-W5-R03**: known codes outside the reduced table get no inconsistency marker | **closed** | R03a: `SERVICE_UNAVAILABLE` with exit 0 gives `refused`, `inconsistent: true`, and a detail ending "a probable product defect" (frozen table). R03b: `NOVEL_X`, a code only the installed table lists (class 6), with exit 0, gives `refused` + `inconsistent`. R03c: a code no table lists gives `refused` with no marker (no class to check, as documented). R03d: the installed class overrides the frozen one. Baseline fails R03a and R03b. |
| **M07-W5-R04**: the handoff overstates two consumer behaviours | **closed** | `m07-u0-handoff.md:40`: the H7 row now names H1 and the wrapper and calls H2 a prospective consumer. `:128–132`: Q7's consequence now separates `active`/unreadable (`still_unknown`), listed `released`, and missing (`not_listed`), matching the README and §5a. |
| **Ruling 1**: a timed-out or unreadable `access ensure`/`run` is remembered as uncertain and observed before close | **closed** | Q1a–f, all as expected, each with exactly one request. Silent `ensure`: the close lists, finds the one candidate and releases it, and the bystander is untouched. Printed `OUTCOME_UNKNOWN` then hung: the close waits on the named operation, then releases. Garbled output: the next stop lists and releases. Printed `ACCESS_READY` then hung: the binding is held at once and released by the close, and the goal fails. `run` that writes its record and then no line: the recorded binding is released, the child PID is gone afterwards, and the exit is 1. Silent `run`: list, then release, child gone. Every request with no answer appears in `request_attempts` and the run exits 1. Baseline fails Q1a–d and Q1f. |
| **Ruling 1 extension**: an answered `OUTCOME_UNKNOWN` that ends `unresolved` | **closed** | Q1i: 5 waits find the operation `running`, so the goal ends `unresolved`. The request is recorded as `outcome_unknown` with code and exit 7. The close waits once more, gets `ACCESS_READY`, and releases. One `ensure`. |
| **Ruling 1 extension**: an `ACCEPTED` whose wait times out | **partly closed** | Closed where the wait brought no answer. Q1g: the CLI wait hangs, the goal ends `failed(OUTCOME_UNKNOWN, request_id, operation_id)`, and the close waits and releases. Q1h: same with an unreadable wait. **Not closed** where Heimdall's own wait timed out (`OK`, `next.action: observe`, exit 5) until the step limit. That accepted request is not remembered and the close never asks about it (G1). The same holds for an approval still pending at the step limit (G3) and for a wait answered with a transient refusal (G2). See M07-W6-R01. |
| **Ruling 2**: never release a binding without positive attribution | **closed** | A1–A14, all as expected. Two candidates: nothing released, `still_unknown`, `candidates` names both, exit 1. Each of these gives no candidate and no release: another profile, a binding created before the send, undated, a `+00:00` offset, state `released`, another work, the same ID twice with different ties, a malformed ID, a binding H2 was given before (A13: it is released once, by the normal path only), and an operation result naming a binding H2 was given before (A14: released once). One candidate among noise releases only that one. The same ID listed twice with the same ties is one release. A list with one candidate in the wrong exit class (exit 4): the binding is held and released, `still_unknown`, `inconsistent: true`, and the request stays uncertain (`uncertain: true`). Baseline fails A1–A11. Two low edges are in M07-W6-R02. |

## New findings

### M07-W6-R01: moderate, nonblocking. An answered request whose operation is still open at the step limit (or whose wait is refused for a transient reason) is not remembered, except in `reconciling`

**Locations:** `examples/harnesses/goal-loop/harness.py:565` and `:1775–1787`. The step limit has a row only for `reconciling`. `KEPT` at `:439` holds only `unresolved`. `:1706–1708` and `TRACKED` at `:293–294` remember an accepted request only when the wait brought no answer (`"fault" in answer.facts`). `:556–562` and `unmatched` at `:718–726` handle a wait answered with a code that has no row. The README states this scope at `:24–25` and `:224–229` ("Only `reconciling` has a row for that"). So does `m07-plan.md:600` ("one answered `ACCEPTED` whose `operation wait` timed out, was unreadable or could not be started").

**Failure:** after `ACCEPTED` (in `observing`) or `APPROVAL_REQUIRED`/`INTERACTION_REQUIRED` (in `pending_approval`), every `operation wait --timeout-ms 20000` can come back `OK`, `next.action: observe`, exit 5. H2's own `EXIT_EXCEPTIONS` calls that "an observation that found its operation unfinished when the wait ran out". After the request and 5 such waits the goal hits the step limit and fails "where it stands". Nothing is added to `requests`/`asked`, so no later stop or close observes it. The operation is still live. If it then succeeds, for example because the provider finishes or the owner approves after H2 gave up, the binding it makes is never released. The `OUTCOME_UNKNOWN` case in exactly the same position is remembered (`unresolved`, which Q1i confirms). A wait answered `SERVICE_UNAVAILABLE` (exit 5, `retry_after`) in `observing` hits no row and fails the same way, unremembered. As a side note, the detail for that case calls this published code "unknown code SERVICE_UNAVAILABLE", because `no_row` (`:780–784`) knows only the codes in `TRANSITIONS`.

**Reproductions** (probe `G1`–`G3`, my own stub, `CALL_SECONDS` 1 s; the scratch scenario's next wait would return `ACCESS_READY` with a binding):

```text
G1 ACCEPTED + 5 waits running/exit 5: calls ensure, wait×5. close: no call. request_attempts {}. final_state observing(op_j). exit 1
G2 ACCEPTED + wait SERVICE_UNAVAILABLE exit 5: calls ensure, wait. close: no call. request_attempts {}. detail "unknown code SERVICE_UNAVAILABLE". exit 1
G3 APPROVAL_REQUIRED + 5 waits awaiting_approval/exit 5: calls ensure, wait×5. close: no call. request_attempts {}. exit 1
```

**Why nonblocking (ADR-0009 §2.1):** the run exits 1 and H2 stays a fixture-only example harness. A binding left active lasts only until its grant expires. No lasting effect on remote trust, recovery records or owner data, and no consent bypass, was shown. The trigger (a slow provider, an owner who approves late) is an ordinary one. This is a gap in what the ruling covers, not a regression: the same behaviour exists at `6416aeb4`.

**Suggested correction:** give `observing` and `pending_approval` a step-limit row like `reconciling`'s and add them to `KEPT`. Treat a wait answered with an unsettled transient code in `TRACKED`/`IN_FLIGHT` the way a wait with no answer is treated. If the ruling meant only CLI-level no-answer, record that, and treat this finding as the same class as the known-open item "a wait with no answer while reconciling or pending approval".

### M07-W6-R02: low, nonblocking. With two remembered requests for the same work and profile, the oldest-first single pass misattributes or leaves one of H2's own bindings

**Locations:** `harness.py:1305–1310` (`open_requests`: oldest first, once per stop), `:1483–1491` (`conclude`: `SEVERAL` against `NEW`), `:934–939` (`ATTRIBUTION`: only a lower bound on `created_at`). README `:545` claims the rule leaves "another request's" binding alone.

**Reproductions** (A15 and A16; two `access` goals with the same work and profile, both silent; `created_at` set 1 ms after each request's own launch):
- **A15.** Each request made one binding. The close observes R1, sees both, and records `still_unknown` with `candidates [r1, r2]`. It then observes R2, finds `binding_r2` and releases it. R1 is not observed again in that close, so `binding_r1`, also H2's own, stays active. Exit 1.
- **A16.** Only R2 made a binding. R1 is observed first, finds `binding_r2` as its one candidate, records `binding_found`, and is marked settled (`uncertain: false`). R2, the request that made it, ends `still_unknown`. The binding released is H2's own, but the record names the wrong request. R1 is closed although nothing showed what became of it.

**Impact:** no binding outside the ruled checks is released and the run exits 1. The gap is in record accuracy and cleanup completeness, and the README sentence overclaims. **Possible fixes:** observe the newest request first, or re-observe a `SEVERAL` request once another request in the same stop has settled. A `created_at` that is later than another uncertain request's send could count as ambiguous. At minimum, narrow README `:545`.

### M07-W6-R03: low, nonblocking, pre-existing (part of the known-open item "an `OUTCOME_UNKNOWN` whose `next` names no operation"). It can exit 0

**Locations:** `harness.py:538–539` and `:1754–1757`. Both rows exist unchanged at `6416aeb4` (`baseline:329`, `:1072–1074`).

**Reproduction (E2):** a goal `{"goal":"access", …, "expect_refusal":"OUTCOME_UNKNOWN"}` is answered `OUTCOME_UNKNOWN`, `next: {action: reconcile}` with no operation, `data.error.effect_status: "none"`, exit 7. The goal counts as a success ("OUTCOME_UNKNOWN (effect none)"). Nothing is remembered, and **the run exits 0**. With effect `unknown` (E3), the code's default per `schemas/public-api/codes.json`, it exits 1. So the known-open item is worse than "open" only under a contradictory answer plus a goal that expects `OUTCOME_UNKNOWN`. A one-line guard would close it: never accept `OUTCOME_UNKNOWN` as an expected refusal.

## Regression sweep (requested areas)

- **Resend after `OUTCOME_UNKNOWN`:** none found. No probe sent a second `access ensure`/`run` for a remembered request (Q1*, A*). The only release resend is the documented one after a terminal `failed`/`cancelled` view with effect `none` in its own class (R01e, R02 failed-cap-none-exit4). The close does not observe or resend its own uncertain release (X1: one release, binding held, exit 1). Each later goal is a new request with a new ID, by design.
- **Release without positive attribution:** none found beyond the U0-Q7 residual (no field names the caller) and M07-W6-R02's within-H2 edges. By source, the only ways a binding enters `held` are: answers that name it (`next.binding_id`, `data.result.binding_id` of the request's own operation, run records in H2's own meta file), the first complete line of the request's own timed-out output, and `conclude` with exactly one candidate (`:1503–1509`). `next.binding_id` is documented only as "Binding to use" (`envelope.schema.json` `NextAction`). Product check: `crates/app/src/operations.rs:9754–9762` emits `binding_id, grant_id, work_id, profile, profile_revision, state, created_at` (jiff `Timestamp`, RFC 3339 `Z`), and `ProfileId` is the profile name, so H2's checks match the real shape. The list holds only bindings that reference a grant, and the local owner sees every binding (`may_act_on`, `crates/domain/src/binding.rs:78`). Those are U0-Q7 territory.
- **Child process leak:** none found. In C1–C4, Q1e and Q1f, every process the stub logged (CLI and child) was gone after the run. That covers a stop whose release is uncertain or hangs with a child running (the close ends it), close-only, a run record naming another PID, and a launch timeout with and without a record.
- **Exit 0 while held or uncertain:** only E2 (M07-W6-R03, pre-existing, contradictory answer). Every other probe with something held, uncertain or not listed exited 1. The clean control (E1, C2) exited 0.

## Known-open items (not reported as new), and whether any is worse than "open"

- **An `OUTCOME_UNKNOWN` whose `next` names no operation:** open as stated. It is worse only via M07-W6-R03 (exit 0 under `expect_refusal: OUTCOME_UNKNOWN` with effect `none`).
- **A wait with no answer while reconciling or pending approval:** open as stated. The related *answered*-but-unsettled cases, in `observing` and in `pending_approval` at the step limit, are not in this list. They are M07-W6-R01.
- **An observation inside a goal in the wrong exit class,** and **an operation whose own code is `OUTCOME_UNKNOWN`:** I saw nothing worse than open.
- **The attribution residual (U0-Q7):** as described. On the same host it rests on two wall clocks (H2's and the runtime's). I did not check a platform where the runtime's clock domain differs, such as a WSL-hosted runtime.

## Commands and observed results

| Command | Result |
|---|---|
| `git fetch origin && git checkout --detach e924b244…` | exit 0, HEAD `e924b244` |
| `python3 -I -B -m unittest discover -s examples/harnesses/goal-loop/tests -v` (Python 3.15.2) | exit 0. 94 run, 93 ok, 1 skipped (`DiscoverySmoke`: fixture debug binary not supplied), 84.9 s. Matches the lead's 94. |
| `/tmp/hm-tools/heavy-gate.sh cargo test -p heimdall --test e2e_harness_m07` | exit 0. 3 passed, 0 failed, 0 ignored (8.25 s after a 53 s build). Debug binary, the test's own fixture world. |
| `python3 -I -B probe/probe.py <candidate harness.py>` | probe exit 0. 53 of 59 as expected. The 6 others are the gap probes G1–G3, A15, A16 and E2 above, each a finding. |
| `python3 -I -B probe/probe2.py <candidate harness.py>` | exit 0, 2 of 2 (X1, X2) |
| `python3 -I -B probe/probe.py <baseline 6416aeb4 harness.py>` | probe exit 1. 47 scenarios ran and 35 failed (R01a–e, 6 × R02, R03a–b, Q1a–d/f–i, G1–3, A1–A11). It then stopped at A12 with `KeyError: 'request_attempts'`, because the baseline summary has no such field. This shows the probes tell the fix from the baseline. |
| Output scan (`HEIMDALL_CANARY_`, `PRIVATE KEY`, `/Users/`) over the unittest log, probe logs and results | 0 / 0 / 0. In the e2e log, 0 / 0 and 20 home-path lines, all Cargo `Compiling` lines. That log was removed. |

The probes are my own. `probe/stub.py` is a scenario-driven stub written independently of the lead's `STUB`. `probe/driver.py` runs `harness.main()` in a separate process with `CALL_SECONDS` 1 s, `LAUNCH_SECONDS` 1.5 s and `CHILD_END_SECONDS` 2 s. Every launch is checked in the stub for scratch `HOME`, `HEIMDALL_HOME`, `HEIMDALL_TEST_SSH_HOME`, fixture stores, `HEIMDALL_TEST_SECRET_STORE=scratch`, and no `SSH_AUTH_SOCK`. The per-scenario records are in `results.json` / `results2.json`, and the baseline run's PASS/FAIL lines are in `probe-baseline.log` (it stopped before writing a results file). None of these ran Heimdall.

## What I did not check

- No native Windows/WSL or devbox run. H2's Windows variable handling and child cleanup on Windows are not covered here.
- No real-binary `OUTCOME_UNKNOWN`, timed-out request, `inspect bindings` attribution or uncertain release. All the probes are stub-driven. The only real-binary run was the e2e nominal journey.
- `tools/validation/check.sh` and the H1 and reference-wrapper suites were not run (outside scope).
- The lead's revert proofs were not re-executed. My baseline probe run stands in for them.
- No review of the rest of the merged-main content in `6416aeb4..e924b244` (M08 W0 files): out of scope.
- I did not check clock behaviour across clock domains (WSL2 drift), or a `subprocess.run` that raises `OSError` after it has started (it would be misread as `not_sent`). The second is a theoretical edge I found while reading the source and did not reproduce.
- No hostile same-user program, and no crash or kill fault injection against a real runtime.

## Cleanup

Repository: no tracked change (`git status` clean). I removed the worktree's `target/` (3.7 GB), the probe scratch roots, the baseline copy and the e2e build log. What remains in `/tmp/hm-tools/m07-w6-recheck-out/` is this report, `DONE`, the probe scripts (`probe/`), the results JSON files, and the unittest and probe logs (no home paths, canaries or keys).
