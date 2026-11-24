# M06 exit record — connect environments without making the controller essential

**Date:** 2026-11-24 · **Build:** `0a5def0357548cad7f5dbf55427607153a551722` (the records' build commit: the generator's HEAD at
`--write`). The runs it cites ran at four exit builds, each named per platform with its reason (see
"Build identity") · **Decided by:** the orchestrator, under the owner's delegation (ADR-0004).

**Decision:** the generator (`--write` at `0a5def03`) puts every row at `verified`, `blocked` on a named owner
input, or `deferred_with_decision` with its decision cited (ruling E6, the M05 bar); every record is
`blocked`, on owner inputs only.

> M06 exits. Every platform row of every M06 claim is `verified` on macOS arm64, Linux x86-64 (the
> devbox), the cross-host journey (a Mac controller and a devbox runner) and, where the claim has one,
> Windows 11 x64 (the cargo row and the Windows controller journey). Each record is `blocked` only on
> named owner inputs (§4); the rows outside V1 are `deferred_with_decision`, citing ADR-0015 or
> m06-plan §5 (§6). Iroh is a named preview, built from source only (ADR-0015). Contract revision 6.x
> is closed at 6.6.

**The rule** (ruling E6, the M05 bar; m06-plan §3):
- every row is `verified`, `blocked` on a named owner input, or `deferred_with_decision` with its
  decision cited;
- blocked rows stay `blocked` with `blocked_on`, and no claim is widened to cover them;
- a `deferred_with_decision` row is not part of the claim and does not count (`tests/evidence/README.md`);
- the lowest-row rule applies, so a record with any owner-input row is `blocked`.

**Build identity.**
- **The records' build commit:** `0a5def0357548cad7f5dbf55427607153a551722`, the generator's HEAD (C10.1 `0a5def03`, or the
  inventory commit after it). The product code it holds is the code of exit build 4 (`aa87c34c`):
  C10 and C10.1 change the evidence tooling and the case index only.
- **The exit builds** (each is an inventory-only commit whose tree is the gated tree):

  | Exit build | Commit | Changes since the previous exit build | What ran there |
  |---|---|---|---|
  | 1 | `a10eec638c2b1531de5c81c7c51510ed0dad5be1` | from `0cffdead` (the W5 records): C2 `ca881f30` the M06 launches fill `ProgramData` and related variables from the OS; C3 `7db78298` the `Protect-Reason` nit (harness); C4 `b9feef25` ADR-0015, contract 6.6 `RouteFailureClass::driver_unavailable` and ruling Q-B; C5 `6f2cc7eb` exit-prep (harness fixes, the D16 restart-replay test, the A07 `POLICY_CUTOFF` step, the eight exit journeys indexed) | the devbox (13 batches); the cross-host journey; PC job 53 (supporting); a macOS run, not of record |
  | 2 | `9399e768…` | C7 `978c2be4`: the shared OpenSSH fill works on Windows without the caller's `SystemDrive` (`crates/localenv` `openssh_env.rs`, `mod.rs`; three platform-neutral helpers) | PC job 55 (the fill fix's native proof); a macOS run, not of record |
  | 3 | `842044c74931a5bfb4c69cd0d4296aae43559eb1` | C8 `10a3349d` (a test's marker line); C9 `54fd3766` and C9.1 `509b234a` (the fixture sshd sessions get a scratch `HOME`; tests and testkit only) | PC job 58 (the Windows rows of record); the C9 devbox batches; a macOS run, not of record; the bisection |
  | 4 | `aa87c34c50b77bb5fa4d50d182131832943492c2` | C11 `55407b3f`: no test forwards an agent through the account's own sshd on OpenSSH ≥ 10.1; `ordinary_login` pins `CheckHostIP=no` (exit review R05); the runner helpers set scratch fixture stores and `HEIMDALL_HOME`; tests and testkit only | the macOS row of record; the devbox forwarding run (supporting) |

  After exit build 4: C10 `fffc8f8f` (the shared generator's `blocked_commands`, the E1 case-index
  rows, the A07 limitations, `e2e_environment_runner_m06` as an observation target, and
  `fill-run-facts`' per-platform `run_commit` with its drift check) and C10.1 `0a5def03` (the case
  index marks the runner's clean-launch unit test Unix-only). Neither changes Rust code.
- **Per-platform run commits** (`run_commit` and `run_commit_reason` in the exit configuration,
  `tests/evidence/artifacts/m06/exit-runs.json`; the record schema has one `build_commit`, §5):

  | Platform | Run commit | Reason (as recorded) | Product drift to the records' build commit |
  |---|---|---|---|
  | macOS arm64 | `aa87c34c` (exit build 4) | C10 after it changes the evidence tooling and the case index only (no Rust code) | 0 files (`git diff --stat` over `crates`, excluding `crates/testkit`) (recorded by `fill-run-facts.py` at `0a5def03`) |
  | Windows 11, cargo row and controller journey | `842044c7` (exit build 3) | PC rows at 842044c7; the exit build's Windows-compiled delta is the removal of route_m04.rs's dead local guard (its only caller is cfg(unix)) | 0 files (recorded by `fill-run-facts.py` at `0a5def03`) |
  | Linux x86-64, the devbox | `a10eec63` (13 batches), with the C9 targets at `842044c7` (4 batches) and the two forwarding tests at `aa87c34c` (supporting) | product code as at the final exit build except C7 (Windows-only callers); C8, C9, C9.1 and C11 are tests and testkit only | stated in the platform label (no `run_commit` field for a platform that ran at several commits) |
  | Cross-host (Mac controller, devbox runner) | `a10eec63` | as the devbox; the journey's own runner sshd (`crosshost-runner.sh`) is untouched by C9 and C11 | stated in the platform label |

- **The PC rows at `842044c7`.** What separates them from exit build 4 is C11, `git diff 842044c7 55407b3f --stat`:

  | File | Lines |
  |---|---|
  | `crates/testkit/src/sshd.rs` | +93 |
  | `tests/e2e/environment_runner_m06.rs` | 67 (+/−) |
  | `tests/e2e/exit_m06/a25.rs` | 148 (+/−) |
  | `tests/e2e/exit_m06/routes.rs` | 6 (+/−) |
  | `tests/e2e/exit_m06/world.rs` | 34 (+/−) |
  | `tests/e2e/route_m04.rs` | 46 (+/−) |
  | **Total** | 6 files, 265 insertions, 129 deletions |

  The ruled sentence: **"PC rows at 842044c7; the exit build's Windows-compiled delta is the removal
  of route_m04.rs's dead local guard (its only caller is cfg(unix))."** The testkit guard and both M06
  journeys' changes are `cfg(unix)`.
- **Sources digest:** `sources_sha256` in `tests/native/m06/required-inventory.json`, regenerated at
  `55407b3f` and committed as `aa87c34c`; unchanged by C10's gate. C10.1's inventory step left it unchanged
  (exit 0).
- **Artifacts:** `tests/evidence/artifacts/m06/`: the exit configuration `exit-runs.json`;
  `digests.txt` (written by `fill-run-facts.py`); and one directory per exit build, `exit-a10eec63/`,
  `exit-9399e768/`, `exit-842044c7/` and `exit-aa87c34c/` (with `case-summary.json`). The run's
  `artifact_digest` is the sha256 of `digests.txt`: `5c5ef026c0c31fe5…` (the same at the C10 and C10.1 fills: the inputs did not change). Per-platform digests as filled at C10: macOS `f9b6e290…`, the devbox
  `741093c0…`, Windows `ce12f285…`, the Windows controller journey `980452b6…`, cross-host `25c9263f…`.
- **Binaries** (sha256, from each platform's `build.txt` and `digests.txt`):

  | Binary | Commit | sha256 |
  |---|---|---|
  | Windows `heimdall.exe` (the e2e suites' CLI) | `842044c7` | `cfae8500…` |
  | Windows `heimdall.exe`, `--features iroh` | `842044c7` | `17695fb7…` |
  | Windows controller journey: `heimdall.exe`; driver `e2e_windows_controller_m06.exe` | `842044c7` | `00959e42…`; `68a6e52e…` |
  | Windows controller journey: the Linux runner `heimdall`; driver | `842044c7` | `f3f2aa07…`; `2a55d240…` |
  | Cross-host: the Linux runner `heimdall` (native-test profile); driver | `a10eec63` | `b27e51bd…`; `c1d45c6a…` |
  | Cross-host: the macOS controller `heimdall`; driver | `a10eec63` | `3b3c1f85…`; `a77e91b2…` |
  | macOS `heimdall` (`--bin`, `target/debug/heimdall` at the fill) | `aa87c34c` [I] | `0fa36b2f…` |

  [I]: the macOS run's own artifacts record no binary digest; the `--bin` file's identity with the
  run's binary is an inference from its build time and the HEAD at the fill.
- **`started_at`:** `2026-11-24T02:57:21Z`, the exit-build-1 runs' start.

## 1. Exit evidence (plan §5 M06; m06-plan §3)

Every m06-plan §3 row. Record and row statuses are the generator's (`--write` at `0a5def03`; `tests/evidence/artifacts/m06/exit-aa87c34c/case-summary.json`). Platform columns: macOS arm64 (`aa87c34c`), the devbox
(`a10eec63`, C9 targets at `842044c7`), cross-host (`a10eec63`), Windows 11 cargo row (`842044c7`),
Windows controller journey (`842044c7`).

| m06-plan §3 row | Record (status) | macOS | Devbox | Cross-host | Windows cargo | Windows controller | Rows not verified (owner input or decision) |
|---|---|---|---|---|---|---|---|
| **A24** (R-EN-05, R-AU-08) | `m06-a24-runner-without-controller.json` (`blocked`) | `verified` | `verified` | `verified` (`a24_*`, 8 steps) | `verified` (C10.1: the clean-launch unit test is Unix-only) | `verified` (10 of 10) | blocked: a native linux-arm64 host (B9); the disposable Linux lifecycle environment (no linger, `KillUserProcesses=yes`, reboot) |
| "No silent controller socket" | inside A24 | — | — | `verified` (`a24_no_controller_socket`: three ordered observations) | — | — | as A24 |
| **A25** (R-EN-08, R-SE-06) | `m06-a25-roles-invitations.json` (`blocked`) | `verified` | `verified` | `verified` (4 steps) | `verified` (the version and capability rows) | n/a | blocked: B9; an operator-installed sshd drop-in (root) for limited roles on a runner whose default policy fails a check (owner-only there). Not a row (ruling E1): the limited client in a container |
| "Remote access and owner control distinct" | inside A25 | as A25 | as A25 | as A25 | — | — | as A25 |
| **A26** (R-SS-05, R-SS-07, R-SS-08, R-SE-04, R-DI-07) | `m06-a26-iroh-routes-trust.json` (`blocked`) | `verified` (both iroh-feature targets) | `verified` | n/a | `verified` | n/a | blocked: the verified-store persistence journey (macOS Keychain dialer) on B3; the Windows steps that may bind a non-loopback address on the owner at the console (G06 §8 W4). deferred_with_decision: the container private-relay mechanism rows and the profile's own capture (ADR-0015); a direct path across real NATs (m06-plan §5) |
| `n0-public` capture row (U56) | inside A26 | — | — | — | — | — | blocked: the owner's authorization of the bounded capture (ruling E1) |
| A26 `n0-public` row | — (not a V1 row) | — | — | — | — | — | not part of V1: the profile stays outside V1 (ADR-0012 §2.2, ADR-0015); it would follow the capture row |
| **T06** second controller (U4b) | `m06-t06-second-controller.json` (`blocked`) | `verified` | `verified` | `verified` (8 steps) | `verified` | — | blocked: B2 (a second Windows account) for the Windows controller row; B9 |
| **A07 runner rows** | `m06-a07-runner-disconnected.json` (`blocked`) | `verified` | `verified` | `verified` (12 steps, including `a07_cutoff_refused`) | `verified` | — | blocked: B9 |
| G07 closure rows | g07 §1.1 (hand-written gate; no `g07-*` closure record) | — | — | — | — | — | A24, A25, the A07 runner rows: as above. The incompatibility run: A25's version rows. Native K_mgmt stores: Windows DPAPI through the controller journey (PC jobs 45, 48, 55, 58); the macOS Keychain rows, with the locked-store row, blocked on B3 (ruling E5); the Linux desktop (Secret Service) row blocked on B11. The declared runner lifecycle: blocked on the lifecycle environment |
| G06 closure rows and transport scope | ADR-0015 (accepted 2026-11-23) + A26 + ADR-0012 §2.6 + the §2.7 ruling | — | — | — | — | — | G06 closes as a recorded transport-specific preview (ADR-0015 (c)), not as support. `g06-windows-bind.json` stays blocked (W1's trace: the owner's decision; W4: the owner at the console) |
| **All of the above** | `m06-exit-claims.json` (`blocked`) | | | | | | the union of the rows above |

**What proves each claim** (the case index, `tests/native/m06/case-index.json`, is authoritative):
- **A24:** `e2e_exit_m06::a24_runner_without_controller` and `connect_on_a_runner_is_a_clean_launch`;
  `e2e_environment_runner_m06`, `integration_runner_runtime_m06`, `integration_controller_driver_m06`,
  `integration_issuer_remote_m06`; the clean-launch exact-set test
  `heimdall_runtime-unit::runner::launch::tests::a_real_child_gets_exactly_the_pass_list_and_never_the_parents_agent`
  (Unix-only, C10.1); the cross-host steps `a24_*` (8); the Windows controller journey's 10 steps. The
  run-refusal step for an undetermined `IdentityAgent` is unit-test evidence only (w5o item 14,
  accepted).
- **A25:** `e2e_exit_m06::a25_roles_invitations_decisions`,
  `a25_pairing_invite_join_through_the_product_cli` and the two runner-local lift journeys
  (`a_delivered_cutoff_on_a_policy_less_runner_is_lifted_locally`,
  `a_delivered_pause_of_a_held_policy_is_named_by_access_resume`); `model_remote_roles`,
  `integration_remote_runtime_m06` (with D16's restart-replay test
  `decision_backed_replay_after_a_store_restart_answers_each_record_state`),
  `integration_paired_scope_m06`, `integration_remote_env_mgmt_m06`, `e2e_environment_cli_m06`; the
  cross-host steps `a25_pair`, `a25_sshd_policy_verified`, `a25_limited_after_verification` and
  `a25_sshd_policy_unverified`. The limited client's evidence is single-host steps 6a–6d and the
  cross-host `a25_limited_after_verification` (ruling E1).
- **A26:** `e2e_exit_m06_iroh::{a26_iroh_routes_trust, a26_iroh_through_a_projected_alias,
  local_widening_adopt_roost_on_a_controller}`; `e2e_exit_m06::{a26_routes_and_host_trust_without_iroh,
  local_widening_route_add_on_a_controller}`; `integration_transport_supervise_m06`,
  `integration_route_m06`, `integration_route_enroll_m06`; `heimdall_transport_iroh-unit`.
- **T06:** `e2e_exit_m06::t06_second_controller`, `integration_runner_effects_m06::t06_*`, the
  cross-host steps `t06_*` (8).
- **A07 runner rows:** `e2e_exit_m06::a07_runner_disconnected` with its `cutoff-refused` step
  (`fresh_work_id=POLICY_CUTOFF issued=nothing`); `model_remote_sync`, `model_runner_delivery` and
  three `integration_runner_effects_m06` tests; the cross-host steps `a07_*` (12).

## 2. Native runs at the exit builds

Observed in the run artifacts (`tests/evidence/artifacts/m06/`):

- **macOS arm64, the row of record** (`aa87c34c`; `exit-aa87c34c/macos/`): `run-macos.sh` exit 0, run
  2026-11-24T17:16:52Z–17:47:38Z with every other track paused (re-confirmed 17:16:25Z). Every recorded
  command exit 0: the fixture sshd preflight; `check.sh`, every step (4143 passed, 0 failed, 203
  ignored); the observation pass; both iroh-feature commands; "the home .ssh directory and Git
  configuration metadata unchanged by the run" (`owner-ssh` `44:3b359564…` before and after; Git and
  the keychain list unchanged); the canary-prefix scan (0); the leak scan (0); the scratch removal.
  macOS 27.2.1, OpenSSH 10.5p1, Apple Git 2.54.0. C11's gate before it left the digest unchanged
  (`3b359564…`).
  - **The two guarded steps:** `observations.txt` carries `a25 positive-control: blocked (sshd >= 10.1
    places forwarded agent sockets under the account's real ~/.ssh/agent)`. The run also executed
    `e2e_environment_runner_m06`, but `check.sh` discards what passing tests print and it was not yet an
    observation target, so its blocked line is not in the run's output. By ruling (b) the line is
    copied, with its source named, into `exit-aa87c34c/macos-supplement/` from the C11 worker's focused
    run on this Mac (the tree that became `55407b3f`); C10 makes the target an observation target.
- **macOS, earlier runs** (recorded, not of record): each exited 1 only on the owner-metadata step,
  every other command 0; the `~/.ssh` entry count stayed 44 and the Git digest was unchanged:

  | Build | Window | `owner-ssh` before → after | Conditions |
  |---|---|---|---|
  | `a10eec63` | 2026-11-23 22:40 – 2026-11-24 02:05 EST | `6e851b2d…` → `23118ef1…` | load 25–32; the orchestrator's ssh pollers to the PC and scp copies in the window; listing `~/.ssh` metadata was denied by permissions |
  | `9399e768` | 10:08:13Z – 11:05:55Z | `9c31eeff…` → `c507ef60…` | the quiet window; other tracks' gates and the owner's other projects running |
  | `842044c7` | 14:46:39Z – 15:15:28Z | `d4d2f268…` → `72771eba…` | every other track paused; `check.sh` 4142 passed, 0 failed, 203 ignored |

  Each "before" differed from the previous "after". The `check.sh` gates between the runs also ran
  the two tests the bisection named (§5), which accounts for that [I]. The settle check at 15:16:42Z read `72771eba…`, and a watcher saw no
  change in seven samples from 15:16:56Z to 15:46:56Z, so there was no steady outside writer.
- **Linux x86-64, the devbox** (`a10eec63`; `exit-a10eec63/linux-b01`…`b13`):
  `run-linux-batches.sh`, 13 batches covering 140 targets, each exit 0: 4100 passed, 0 failed, 208
  ignored. About 5.5 GiB free before each batch (never under the 3 GiB floor), about 5 GiB after.
  Canary 0 and leak 0 per batch; no leftover test process or scratch directory; the owner's `~/.ssh` and
  Git digests equal before and after. Linux 6.8.0-147, glibc 2.39, OpenSSH 9.6p1, git 2.43.0.
  - **The C9 batches** (`842044c7`; `exit-842044c7/linux-c1`…`c4`): the fixture-sshd targets, the new
    fixture test's target and `service_login_m04`'s, each batch exit 0: 701 passed, 0 failed, 190
    ignored; about 5.4 GiB free; no scratch left. The fixture session environment observed:
    `home=scratch zdotdir=scratch bash_env=empty login_shell=bash`.
  - **The forwarding run** (`aa87c34c`; `exit-aa87c34c/linux-fwd/`, supporting): the two
    agent-forwarding targets on OpenSSH 9.6p1, where the guard lets them run: exit 0, 19 passed, 0
    failed; a25's positive control forwarded for real; no blocked line; nothing left over; the host's
    `~/.ssh` and Git metadata unchanged.
- **Cross-host journey** (`a10eec63`; `exit-a10eec63/runner-crosshost/`): `run-crosshost.sh` exit 0,
  32 of 32 steps (A24 8, A07 12, T06 8, A25 4); canary 0, leaks 0, cleanup clean, 6 GiB free on the
  runner. The controller's K_mgmt and K_iroh are fixture stores; the login keychain was checked by
  service name only: no Heimdall item.
- **Windows 11 x64, PC job 58** (`842044c7`; `exit-842044c7/windows/` and `windows-controller/`):
  - **Step 1, the cargo row:** 140 binaries, 3494 passed, 0 failed, 44 ignored, every binary exit 0;
    27 recorded commands exit 0, only `windows_launch` skipped; the `SystemDrive` fill test passed;
    canary 0, leak 0.
  - **Step 3b, the fill test's revert proof:** unreverted, 1 passed; reverted, exit 101 (the child's
    `inherits=false` saw `None` instead of `Some(c:\programdata)`; the parent saw the child's exit
    `Some(101)`); restored, clean; the control passed. On a pass the child's marker is not visible,
    because the parent captures the child's output; the parent requires it.
  - **Step 4, the Windows controller journey:** the self-tests 0 failed (P08, D01); the journey 10 of 10,
    cleanup clean; its one recorded command exit 0; `build.txt` names `842044c7` and the digests above.
  - **Host conditions:** Credential Manager 173 names before and after; `%LOCALAPPDATA%\Heimdall`
    absent before and after.
- **Windows, PC job 55** (`9399e768`; `exit-9399e768/windows-fill/`, supporting): the fill fix's native
  proof. Step 5 `-WithoutProgramData` 10 of 10; step 6 the guard run refused, its control 10 of 10;
  step 4 34 passed, 0 failed, 5 passed, 0 failed and 10 of 10; canary 0, leak 0; Credential Manager 173
  before and after. Its step 1 failed one test (3482 passed, 1 failed, 44 ignored): a parent-check bug
  under `--nocapture`, fixed test-only in C8 and passed in job 58.
- **Windows, PC job 53** (`a10eec63`, supporting): 140 binaries, 3492 passed, 0 failed, 44 ignored;
  canary 0, leak 0; the controller journey 10 of 10. Its steps 5 and 6 found the defect C7 fixes
  (0 of 10 with `ssh_client_not_started`: `SHGetKnownFolderPath(FOLDERID_ProgramData)` expands from the
  caller's environment and failed `0x80070003` without `SystemDrive`); its control failed identically,
  so that guard run was inconclusive. **Host conditions:** a Steam game ran the whole job (the job's
  process trees were set Idle by exact PID; DWM average 31.6%); Credential Manager 172 names after vs
  173 before, none Heimdall-like (observed; not attributed to the run).

**Observations** (`m06 observation:` lines; the full set is in the records). Examples:
- `a07 cutoff-refused: … policy_cutoff=in_force fresh_work_id=POLICY_CUTOFF issued=nothing`
- `a24 controller-leaves: controller_runtime=stopped issuer_child=stopped management_route=blocked`
- `a24 onward-managed: login=ok credential=runner_k_env_certificate signed_by=controller_ca controller=stopped route=blocked`
- `a24 onward-fixed: launched_by=heimdall_connect unattended=true controller=stopped … forwarded_agent_contacts=0 forwarded_agent_provenance=controller_dependency`
- cross-host: `a25 sshd-policy-unverified: authorized_keys_command=management_sshd_unverified force_command=management_sshd_unverified accept_env_all=management_sshd_unverified`

## 3. Independent review

One review and one scoped re-check per wave (ADR-0009 §2.1), archived in
`tests/evidence/artifacts/review-m06/`:

| Wave | Review (reviewer) | Blocking findings, and where they were fixed | Re-check |
|---|---|---|---|
| W0 (`a2576a51`) | `w0.md` (Codex): FIX FIRST | R01 (audit scope), R02 (cutoff authority), R03 (paired-owner scope); R01–R11 handled in W1 | in `w1.md`: the W0 re-check closed (fixed or deferred-ok) |
| W1 (`82158dee`) | `w1.md` (Gemini; `w1-codex-partial/` early probes): FIX FIRST | R01 (join/revoke/reconcile race, time sampled before the transaction), R02 (`sshd -T` quoting); R03–R06 too; fixed in W2 (`6d535ad6`) | in `w2.md`: R01–R06 fixed |
| W2 (`6d535ad6`) | `w2.md` (Gemini): FIX FIRST | W2-R01 (`at_commit` ignored the wall clock); R02–R06; fixed in W3 (`c19aeba0`) | in `w3.md`: fixed (R04's native evidence: PC job 26) |
| W3 (`c19aeba0`) | `w3.md` (Gemini): FIX FIRST | W3-R01 (`transport disable` cleared nothing); R02–R04; fixed in W3.1 (`dc69bbd4`) | `w3-recheck.md`: CLOSED |
| W4 (`c4e9a5b5`) | `w4.md` (Claude Sonnet): MERGE | none blocking; R01, R03 and R04 fixed in W5 (w5e, with revert proofs), R02 recorded in the W5 commit message | none: its review was MERGE; R01 to R04 were carried into W5, and W5's review and scoped re-check covered them |
| W5 (`25229f74`) | `w5.md` (Claude Opus): MERGE, one moderate and four lows | R01–R05 fixed in `cde5766b` | `w5-recheck.md` (Claude Opus, `25229f74..2305a46c`): NOT CLOSED on RC01; RC01–RC05 fixed in `5bd0bdbe` (RC01 by ruling option (b)) |
| The exit series (`0cffdead..842044c7`: C2, C4, C7/C8, C9) | `exit.md` (Claude Opus): MERGE, five findings, none blocking | none blocking. R01: a residual and follow-up M06-F5; R02: follow-up M06-F6 and the Q-A wording corrected (§5); R03: the release-scope docs narrowed (the matrix and ADR-0015), the add-time refusal follow-up M06-F7; R04: follow-up M06-F8; R05: fixed in C11 (`55407b3f`) | none: no blocking finding |

**E7** (the orchestrator's wording): "RC01's fix was read by the orchestrator only (not
independent); ADR-0009 §2 allows one re-check per wave, and it was spent." Its revert proof is
recorded in `5bd0bdbe`: the reviewer's two probes (an `all` cutoff, and a `profile` cutoff after a
paired owner's `policy remove`) and the runner owner's own `policy remove`.

**Not independently reviewed:** C3 and C5 (harness and exit-prep; read for context by the exit
review), C11 (tests and testkit only; accepted by the orchestrator), C10 and C10.1 (evidence tooling
and the case index), and the inventory commits. Each passed `check.sh`.

## 4. Blocked on owner inputs

Each row names exactly one input:
- **B9, a native linux-arm64 host:** the arm64 runner rows of A24, A25, T06 and A07 (m06-plan §7).
- **The disposable Linux lifecycle environment** (a VM or account where linger and logind settings can
  change, and which can reboot): A24's no-linger, `KillUserProcesses=yes` and reboot rows; G07's
  declared runner lifecycle.
- **An operator-installed sshd drop-in (root):** A25's limited roles on a runner whose default sshd
  policy fails a check. Without it that runner is owner-only.
- **B2, a second Windows account:** T06's Windows controller row.
- **B3, a disposable macOS standard account** (rulings E1, E5): A26's verified-store persistence
  journey (the macOS Keychain dialer); G07's native K_mgmt macOS Keychain rows, with the locked-store row.
- **B11, a Linux desktop host with a Secret Service:** G07's native K_mgmt Linux desktop row. M08's container probe has since shown a release build using a real Secret Service for K_ca; M08 W3 may extend that to K_mgmt as supplementary, non-native evidence.
- **The owner's authorization of the bounded n0-public capture** (ruling E1): the capture row.
- **The owner at the Windows console:** A26's Windows steps that may bind a non-loopback address (G06
  §8 W4). G06 W1's event trace is the owner's decision (a capture-tool install or admin rights).

No macOS row is blocked: the attribution closed (§5), so `blocked_commands` (C10) is unused at the
exit.

## 5. Limitations and residuals

- **The `~/.ssh` attribution** (closed). The account's `~/.ssh` metadata changed in three macOS runs
  (§2) with the entry count unchanged.
  - **The bisection** at `842044c7`, under the pause, with only a count and a hash recorded:
    - **Pass 1** (15:49:49Z–16:18:06Z, 181 rows, each non-test step and each `check.sh` test binary
      bracketed): the digest changed only after `e2e_environment_runner_m06` (16:01:36–16:02:08Z,
      `72771eba…` → `ee2abb43…`), after `e2e_exit_m06` (16:06:16–16:07:34Z, → `e232e7d8…`) and after
      the observation targets, which run `e2e_exit_m06` again (16:15:53–16:17:11Z, → `f15aa9a9…`). The
      count stayed 44, every step exit 0.
    - **Pass 2** (16:18:31Z–16:23:54Z, the two binaries one test at a time,
      `--test-threads=1`): the digest changed only after
      `e2e_environment_runner_m06::a_controller_reaches_a_real_runner_through_its_management_line`
      (→ `7219e9e1…`) and `e2e_exit_m06::a25_roles_invitations_decisions` (16:21:10–16:22:17Z, →
      `3b359564…`), the value the run of record then kept.
    - **Reviewer overlap:** the exit reviewer ran an `sshd -T` probe and
      `fixture_sshd_session_has_a_scratch_home_and_no_account_startup_files` at about
      15:50:19–15:52:40Z. No row in that window changed the digest.
  - **The cause:** those two tests are the only ones that make a fixture sshd running as the account
    really forward an agent (a key line with `agent-forwarding` and a client with `ForwardAgent`).
    OpenSSH ≥ 10.1 (10.5p1 here) places the forwarded agent's socket under the account database's
    home, `~/.ssh/agent/`, which a session `SetEnv HOME=` cannot redirect (ADR-0010's record of the
    behaviour; M04 already guarded its own case). The socket is transient: sshd removes it when the
    session ends. Neither test reaches a key store or the account's real `authorized_keys` (the
    runner-environment audit, by code reading).
  - **The fix,** C11 (tests and testkit only): the guard moves to `heimdall-testkit`, fails closed, and
    covers M04's `a15` and both M06 steps; each skipped step prints its blocked reason. On OpenSSH < 10.1
    (the devbox) the steps run for real (§2, the forwarding run).
  - **The ruled closing wording:** **"sshd >= 10.1 forwarded-agent sockets under ~/.ssh/agent,
    transient; fixed by C11 guard"**, confirmed by the paused macOS run at `aa87c34c` (before = after).
  - **Open owner question:** whether sshd also cleans stale sockets in `~/.ssh/agent/`, as ssh-agent
    does (ADR-0007 F21). The unchanged count argues against it but does not exclude it. Checking it
    means listing names and times in that directory, which is the owner's call.
- **A test sshd running as the account must not forward agents on OpenSSH >= 10.1.** A stated limit of
  the fixtures: on such hosts the two forwarding steps (and M04's `a15`) are `blocked` by the guard;
  they run on the devbox (OpenSSH 9.6p1) or in a disposable account.
- **The fixture sshd session's working directory is the account's real home,** in the testkit and in
  the WSL sshd. Sessions get a scratch `HOME` and `ZDOTDIR`, an empty `BASH_ENV` and `PermitUserRC no`
  (C9); the exit review found no relative remote path in the fixtures.
- **The Windows `ProgramData`/`SystemDrive` fill** (ADR-0006 §18.9 item 13): the fill no longer depends
  on the caller's `SystemDrive`; it derives the drive from `FOLDERID_Windows` and gives the child
  `SystemDrive` and `ProgramData`. Its limits: `FOLDERID_Windows` relies on the caller's `windir`
  (with neither `SystemDrive` nor `windir` set, the guard refuses); the fallback ignores a relocated
  `ProgramData` and uses the documented default.
- **An inherited `ProgramData` is trusted** (exit review R01; a same-user residual and follow-up M06-F5):
  the fill sets only variables the child lacks, the M06 guard checks only that `ProgramData` is
  non-empty, and the known folders follow Heimdall's own `SystemDrive` and `windir`. A same-user parent
  environment can therefore choose `%ProgramData%\ssh`. It gains nothing the same-user program does not
  already have (spec P03). The probe:
  `sys::openssh_env::tests::missing_openssh_vars_reads_inherited_set_removed_and_cleared`.
- **Q-A, as corrected by R02:** route verification and the jump leg inherit the environment; a Windows
  process without `ProgramData` fails closed there, `HOST_PIN_DEFEATED`: `unreadable`
  (`crates/app/src/routes_verify.rs:66-78`, `crates/app/src/routes_legs.rs:98-111`; `setup apply`'s
  after-apply check reports each helper alias that way). The guard backstop exists on the four M06
  launches only. Follow-up M06-F6.
- **Iroh in a build without it** (exit review R03): `transport` forms refuse `driver_unavailable`; route
  commands accept and record Iroh legs in any build, including the attended exposure consent; using such
  a leg in a build without `iroh` is recorded `driver_unavailable` and failed over, and an all-Iroh route
  refuses `driver_unavailable` with the preview message (ADR-0015, contract 6.6). The add-time refusal
  is follow-up M06-F7.
- **A07's runner rows** (gaps 2–4 are stated limitations: ruling E4 and the orchestrator's ruling 4 of 2026-11-24; gap 1
  is closed):
  - **gap 2, residuals:** a runner's revocation residuals carry only the `new_authentication`
    component; the other `RevocationResiduals` components are not reported for a runner, so the record
    claims nothing about them on the runner path (U0-Q14, the contract owner's at U0);
  - **gap 3, namespaced acknowledgements:** model and single-host evidence only; no cross-host step
    asserts them;
  - **gap 4, pending approval while disconnected:** not asserted on the runner path. The approval-race
    leg is covered locally by `model_revocation::a07_a_pending_approval_cannot_complete_after_a_revoke`,
    `model_revocation::a07_revoking_an_awaiting_grant_ends_its_operation_at_once`,
    `integration_store::decisions_complete_once_and_go_stale_when_the_generation_moves`,
    `integration_managed_adapter::stale_approval_cannot_reactivate_after_revoke` and
    `integration_runner_effects_m06::a_cutoff_delivered_after_the_decision_was_issued_makes_its_approval_stale`;
  - **gap 1, attribution (closed in C5):** the `cutoff-refused` step, single-host and cross-host
    (`a07_cutoff_refused`), asserts the fresh work ID is refused `POLICY_CUTOFF` with nothing issued;
    `a07_fresh_work_refused` asserts the refusal after the reconciled pause and cutoff together, without
    attributing it.
- **"No silent controller socket"** stands in for the runner runtime's descriptor table, which is
  non-dumpable: three ordered cross-host observations and the clean-launch exact-set test.
- **A25's limited client is not run in a container** (ruling E1).
- **Iroh:** a preview from source only (ADR-0015); the cargo rows use loopback only (no public relay, no
  non-loopback listener, no real NAT); Windows is an owner controller only (ADR-0012 §2.6); a runner
  does not dial onward over Iroh through a projected alias (ADR-0012 §5).
- **Single-host journeys** run the controller, the runner and the fixture sshds under one OS user with
  scratch homes; the cross-machine evidence is the cross-host journey.
- **Fixture key stores** throughout the debug runs (`HEIMDALL_TEST_MGMT_STORE`,
  `HEIMDALL_TEST_IROH_KEY_STORE`, `HEIMDALL_TEST_SECRET_STORE`); the release gate refuses each in a
  release build.
- **ADR-0012 §10 residuals:** the management and transport keys in encrypted local backups (W3 ruling
  7); the same-user path to the K_mgmt agent (`review-m06/w5.md`). The exit review's R01 (an inherited `ProgramData`
  and `windir` are trusted) is in `docs/compatibility/matrix.md`'s M06 residuals list. No `claims.rs`
  change follows the exit build: its `RESIDUALS` entry goes to the claims-table update at the M08
  candidate commit (U8), next to the version bump.
- **Pre-existing advisories** accepted as residuals: RUSTSEC-2023-0071 and RUSTSEC-2026-0387
  (`tools/validation/audit-ignore.txt`).
- **Evidence-tool gaps:**
  - the record schema has no per-platform commit: the exit configuration carries `run_commit`,
    `run_commit_reason` and the drift check per platform (C10), copied into the platform label;
  - the importers assume `artifacts_root` is the import directory's parent: the Windows outputs were
    imported through a staging configuration and transplanted into the exit configuration; the
    transplant script stayed outside the repository (by ruling);
  - `blocked_commands` (C10) landed and is unused at the exit;
  - the cross-host `build.txt` reads `commit: a10eec63… (worktree 1 changed paths)`: the one changed
    path is the untracked artifacts directory (`tests/evidence/artifacts/m06/`), not product code (Q6);
  - `fill-run-facts` reads only `commit=` lines, so it does not check that note.

## 6. Deferred and handed on

- **A07's disconnected-runner variant** (m03-plan §3, §4.5; `m03-a07-revocation.json`'s
  `deferred_with_decision` row): closed by `m06-a07-runner-disconnected.json` at this exit, whose rows
  are verified on every platform row and blocked only on B9 (the arm64 runner row). M03's record keeps its row
  `deferred_with_decision`, because the shared generator has no cross-record row; the row is superseded
  by this mapping, as M05 recorded M04's closures (the M03 claims precedent).
- **A17 beyond A17-local:** not an M06 claim; its owner is M08 U1b (ruling E3).
- **Deferred with decision:** A26's container private-relay mechanism rows and the profile's own
  capture (ADR-0015); an Iroh direct path across real NATs (m06-plan §5); the rest of m06-plan §5
  unchanged (multi-hop chains, live session migration, a managed Windows runner, K_env persisted on
  runners, a headless persistent Iroh endpoint, port mapping, bearer links and QR, `RemoteDecide`, a
  stock Pigeons client against serve, a native linux-arm64 row).
- **ADR-0015** (accepted 2026-11-23): Iroh is out of the V1 default build; a named preview from source
  (`--features iroh`), no support label, no stable claim; its gates keep running.
- **Contract:** revision 6.x is closed at **6.6** (ADR-0006 §18.10). Revision 7 (ADR-0013 §11) is
  re-based onto 6.6 by the contract owner at U0 (`docs/architecture/m06-u0-handoff.md`).
- **Follow-ups** (each assigned by the orchestrator; none blocks the exit):

  | ID | What | Owner | Evidence |
  |---|---|---|---|
  | M06-F3 | Every `HEIMDALL_TEST_*` variable is test configuration, and a debug runtime is never wired to the account's `~/.ssh` (product hardening behind C9) | M08 U1b (boundary work) | the exit's read-only `~/.ssh` audit: the fixture sessions' login shell and home (closed by C9), `tests/e2e/service_login_m04.rs` (closed by C9), the doctor probes and other product paths that fall back to the account's `~/.ssh` when no test variable is set |
  | M06-F5 | The guard requires a usable effective `ProgramData` (`is_usable_folder`), `windir` is checked, and the fill module's wording says the known folders expand from this process's `SystemDrive` and `windir` | M08 U1b (boundary work) | exit review R01 |
  | M06-F6 | Route verification (`ssh -G`) and the jump leg get the shared fill (`OpensshEnvFill`), as the M06 launches do | M08 U1b (boundary work) | exit review R02; `routes_verify.rs:67`, `routes_legs.rs:101` |
  | M06-F7 | `route add` of an Iroh route refuses in a build without the driver (`CAPABILITY_UNAVAILABLE`, `driver_unavailable`, before any decision is recorded), keeping C4's failover for existing rows. A live contract change | M07 U3 (revision 7: a live contract change) | exit review R03; `dispatch::tests::a_relay_urls_path_is_stored_and_never_shown` passes in a default-feature build |
  | M06-F8 | The Windows fill child test reports whether the fallback ran (`derived=1`), and the parent requires it; test-only, with the next Windows change | M08 U1b (boundary work) | exit review R04 |

  F1, F2: not used (F2 was reserved for Q-A, which needed no code); F4: considered, not needed (C9's
  shared helper covers the WSL sshd). The `pgrep -fl` lapse is recorded in the W5 row of `progress.md`.

## 7. Next

`progress.md` records the exit: an M06-T01..T06 row, M06-T00 and the W5 row closed, the
current-milestone line. `docs/compatibility/matrix.md`'s M06 section and `docs/user/limitations.md`
gain the exit's lines. **U0** (contract revision 7, re-based onto 6.6) takes M06's handoff:
`docs/architecture/m06-u0-handoff.md` (the files, U0-Q11 to Q14, the delta owners, and M06-F7). The
target directory is pruned after the exit gates.
