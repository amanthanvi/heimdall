# M05 exit record — quiet, concurrent trusted work

**Date:** 2026-11-20 · **Build:** `85e67bfe` (the Windows record run), with macOS and the devbox at
`84d7c44e` and the WSL hook row's `84d7c44e` binaries under the `5aa752c0` harness; `crates/` is
byte-identical across the three · **Decided by:** the orchestrator, under the owner's delegation
(ADR-0004).

**Decision:** M05 exits. Every platform row of every M05 claim is `verified` on macOS arm64, Linux
x86-64 (the devbox), Windows 11 x64 and, where the claim has one, the WSL hook row. Each record is
`blocked` only on named owner inputs (B2, B7, B9, B12; §4), and the rows that M04's exit closes are
`deferred_with_decision` (§6). The merge of `m05/w4` into main is the orchestrator's.

**The rule** (M01, M02 and ADR-0008 §17.3 item 6; m05-plan §3):
- every record is `verified`, except rows blocked only on named owner inputs;
- those rows stay `blocked` with `blocked_on`, and no claim is widened to cover them;
- a `deferred_with_decision` row cites its ruling. It is not part of the claim and does not count
  (`tests/evidence/README.md`);
- no record is written while a required test is `#[ignore]`d (orchestrator, 2026-11-18): the
  `pending_e5` tests run un-ignored since M03's E5 reached main.

**Build identity.**
- **Commits:** `85e67bfe6149d749d10ded89184e28d542f5c4a8` (build commit of the records; the Windows
  harness ran there), `84d7c44e18c9d68fc7575ea6231ff1582a9e8658` (macOS, the devbox and the WSL
  row's binaries) and `5aa752c0f7a53f26a93e7975a7145e3b5928995b` (the WSL row's harness).
  `5aa752c0` changed harness files only (the WSL hook runner, the Windows runner's redaction and the
  build host's importer); `85e67bfe` changed two `#[cfg(windows)]` `taskkill` calls in a test
  helper (`tests/e2e/exit_m05/m05.rs`), so that their output stays out of libtest's result lines.
- **Sources digest:** `sources_sha256` `9097e792b3770592be30fbf210b6d4ca2a88758…` in
  `tests/native/m05/required-inventory.json`, regenerated at `85e67bfe` with `refresh-inventory.sh`.
- **Artifacts:** `tests/evidence/artifacts/m05/exit-84d7c44e/` (`runs.json`, `digests.txt` with the
  sha256 of every artifact file of the run, `case-summary.json`). The artifact digest is the sha256
  of `digests.txt`, `4f9f6057e6c73589…` (the full values are in `runs.json` and every record).
- **Binaries:** the Linux `heimdall` (the devbox and the WSL row) `1e680325ee723902…`; the Windows
  `heimdall.exe` at `85e67bfe` `471dec119b1cdf94…` (`build.txt` per platform has every binary).

## 1. Exit evidence (plan §5 M05; m05-plan §3)

| Exit claim | Record | macOS arm64 | Linux x86-64 (devbox) | Windows 11 x64 | WSL distribution | Rows not verified |
|---|---|---|---|---|---|---|
| **A02**, a normal working week; "zero additional same-authority prompts" (R-UX-02) | `m05-a02-trusted-week.json` (blocked) | verified | verified | verified (no shell hook, Q6) | verified (the bash and zsh hook journeys) | blocked: B7 (the G01 baseline comparison), B12 (a reboot or logout inside the window), B9 (Linux arm64) |
| **A04**, edits, branches, an added destination and default changes (R-UX-06, R-AU-03) | `m05-a04-access-changes.json` (blocked) | verified | verified | verified | n/a | blocked: B9 |
| **A05**, "fresh work IDs can't evade a hard cutoff" (R-AU-02) | `m05-a05-expiry-cutoff.json` (blocked) | verified | verified | verified | n/a | blocked: B9 |
| **A16**, "defaults don't redirect running work" (R-AU-03), two environments, one OS user | `m05-a16-concurrent.json` (blocked) | verified | verified | verified | n/a | blocked: B9; deferred_with_decision: the WSL and container pairs, M04's exit (Q9) |
| **A18**, copies, clones, worktrees, moves; portable intent (R-EN-07) | `m05-a18-portable-trust.json` (blocked) | verified | verified | verified | n/a | blocked: B9 |
| **A28**, scoped delegation and the narrower binding (R-AU-07, R-SE-03) | `m05-a28-delegation.json` (blocked) | verified | verified | verified | n/a | blocked: B9; deferred_with_decision: forwarding and container rows, M04's exit (Q9) |
| **A29**, "a repository file can't become an approval instruction" (R-SE-01, R-SE-02, R-RT-03) | `m05-a29-hostile-input.json` (blocked) | verified | verified | verified | verified | blocked: B2 (cross-user rows, carried from M01's A29-local), B9 |
| G05, the agent-context gate | `m05-g05-agent-context.json` | verified (2026-11-15, hand-written gate record) | verified | verified | n/a | — |
| All of the above | `m05-exit-claims.json` (blocked) | verified | verified | verified | verified | the union of the rows above |

**What proves each claim** (the case index, `tests/native/m05/case-index.json`, is authoritative):
- **A02:** `e2e_exit_m05::a02::a02_trusted_week_zero_further_prompts` (the real binary: trust once, re-entry,
  three shells, real `ssh`, `git ls-remote` and `scp` through the managed alias, the same work again, a
  runtime crash by exact PID and recovery, expiry and fresh work IDs; 0 further decisions, attended
  prompts and provider prompts), `u5::u5_ordinary_ssh_activates_the_personal_default`;
  `e2e_context_m05::a02_trusted_week_zero_same_authority_prompts`; U5's `default_m05` live journeys;
  `e2e_hook_m05`; three `e2e_cli_m05` trust-once journeys (kept, ruling of 2026-11-18); P10; the WSL
  hook journeys. Ruling I-22: "re-issue within the grant" is both the I-1 attach and recovery's re-issue.
- **A04:** `e2e_context_m05::a04_edits_branches_and_added_destination`;
  `e2e_exit_m05::a16::a04_default_and_profile_change_never_redirects_bindings` and its live twin; P10.
- **A05:** `e2e_stop_m05::{a05_expiry_reentry_and_hard_cutoff, a05_stop_profile_revokes_and_blocks_until_resume}`;
  `model_precedence_m05`; the M01 A05 model rows.
- **A16:** `e2e_exit_m05::a16::a16_two_environments_defaults_and_cleanup` and its live twin (with M04's
  adaptation: ADR-0010 §4 item 3 allows one binding per container, so the second environment's second
  job is refused `environment_busy` and that slot clears instead of handing over; a handover inside a
  second environment is no longer proven, while the native share and handover, separate slots and
  references per environment, defaults, pins and per-environment cleanup are; A16's container row is
  M04's);
  `model_slot_accounting`; `e2e_stop_m05::stop_one_job_leaves_the_other`; `e2e_exit_m05::pending_e5::…`
  (a stopped job's grant reaches `revoked` after its residual; needs E5). Ruling I-22: the default
  moves through `access default-profile` and through a widened default-profile policy.
- **A18:** `e2e_context_m05::a18_copy_clone_worktree_symlink_move_submodule`;
  `integration_portable::{a_bastion_destination_round_trips_with_its_jump, an_unresolved_jump_refuses_its_destination_on_import, a_jump_resolves_against_the_reconciled_hop, every_row_of_a_repeated_destination_id_is_refused}`,
  `e2e_cli_m05::an_imported_routed_destination_is_never_launched_by_its_bare_alias` and the TUI's
  `a_destination_an_import_skipped_is_never_connectable_from_the_tui` (ADR-0006 revision 5.3
  items 23 and 24, ruling I-27: a route's jump travels; a routed destination the receiver does
  not have with that route is skipped, `route_required`, and nothing of it is written);
  `integration_portable::{a18_export_has_no_authority_or_secrets, a18_import_on_second_installation_creates_intent_only}`;
  `e2e_portable_m05`; `model_project_pure` (P11); `integration_workspace_observe` (the real observer on
  APFS, ext4 and NTFS).
- **A28:** `e2e_exit_m05::a28::{a28_child_subset_refusals_and_no_owner_functions, a28_parent_end_cascades_child_login_fails}`;
  the live `delegation_m05` journeys; `e2e_delegation_m05`; `model_authority`; `pending_e5` (the revoked
  parent and child reach `revoked`; needs E5).
- **A29:** `adversarial_prompt_injection` and `adversarial_prompt_injection_cli` (the prompt-injected
  agent fixture; findings A29-F1, A29-F2 and review findings M05-W4-R01 to R03 fixed in W4); M01's
  A29-local tests re-run by name (ruling I-18); the cited parser, observer, hook and rendering tests.

## 2. Native runs at the exit build

Observed in the run's artifacts (`tests/evidence/artifacts/m05/exit-84d7c44e/`):
- **macOS arm64** (the build host, `84d7c44e`): `tests/native/m05/run-macos.sh` exit 0. `check.sh`: all
  13 steps exit 0; 3455 passed, 0 failed, 199 ignored. The observation pass (`e2e_hook_m05`,
  `e2e_exit_m05`): 11 passed, 0 failed. 7 of 7 recorded commands exit 0; canary count 0; the owner's
  `~/.ssh`, Git configuration and keychain list unchanged. macOS 27.2.1, OpenSSH 10.5p1, Apple Git 2.54.0.
- **Linux x86-64, the devbox** (`84d7c44e`, cross-built with zig): `tests/native/m05/run-linux.sh` in
  five batches covering the run plan's 111 test binaries, each batch exit 0: 3424 passed, 0 failed,
  204 ignored; canary count 0; no leftover test process or scratch directory; the owner's `~/.ssh` and
  Git configuration digests equal before and after; free space checked before each batch (6.8 GB
  throughout, never under the 4 GB floor). Linux 6.8.0-147, glibc 2.39, OpenSSH 9.6p1, git 2.43.0.
- **Windows 11 x64** (`85e67bfe`, the PC, native msvc build in local mode): `run-windows-local.ps1` exit
  0 in 2335 s; 111 binaries, 2895 passed, 0 failed, 34 ignored; canary and leak counts 0; no output pipe
  left open; the tests resolved the in-box OpenSSH_for_Windows 9.5p2; the fixture `sshd`s in WSL scratch
  with their logs on the WSL file system. `e2e_exit_m05` ran with `--test-threads=1` (8 of 8). The run
  at `84d7c44e` (`windows-84d7c44e-superseded/`: exit 0, 2895 passed, 0 failed) is kept on record:
  `taskkill`'s output landed inside A02's result line there, so the generator could not read it.
- **WSL distribution** (the `84d7c44e` Linux binaries under the `5aa752c0` harness, the PC): one
  disposable distribution `hm-m05-8ff335ff` from the pinned Ubuntu 24.04.5 image; exit 0 in 51 s; all 8
  journey steps ok (bash 5.2.21 and zsh 5.9; the hook's warm-up 271 ms, the slot held when it
  returned; no leftover process); unregistered by exact name, the registered set equal to the one
  before; canary and leak counts 0. WSL 3.0.5.0, kernel 6.18.58.1-microsoft-standard-WSL2 (newer than
  the 6.8.0 Linux floor: the case M03-F1's version gating must classify, WSL included). The first
  attempt at `84d7c44e` (`wsl-distro-attempt1-failed/`) refused its own distribution (§5) and is kept on
  record.

**Observations** (`m05 observation:` lines, identical on the platforms that print them): A02
`decisions_after_first=0 attended_prompts=0 provider_prompts=0 recovered_runtime=true`; A04
`default_change=redirected_nothing profile_change=redirected_nothing`; A16 `environments=2 jobs=4
pins_unchanged=true cross_routed=0 handover_generation=2 cleanup=clear`; A28 `subset=server_enforced
wider=refused longer=refused`, `parent_end=revoke child_grant_state=revoking` and `parent_end=cutoff
child_grant_state=expired`, the child's next login refused, `states_settled_after_login_s=0`; U5
`activation_decisions=0 paused=nothing_activated resumed=activated`; the hook's warm-up 59 ms (macOS),
308 ms (the devbox), 271 ms (WSL); I-13 `failed` on macOS, Linux and Windows (§5).

**Pre-final runs** (kept beside the run, not evidence for it): `exit-d81abda6/`, `exit-959936c4/` and
`exit-056a1692/` (the devbox, macOS and the PC's Windows and WSL runs at earlier candidates; their
findings are fixed in W4, §5).

## 3. Independent review

One review and one scoped re-check per wave (ADR-0009 §2.1), archived in
`tests/evidence/artifacts/review-m05/`:

| Wave | Review | Blocking findings, fixed | Re-check |
|---|---|---|---|
| W1 (`22dfb168`) | `w1.md` | M05-W1-R01, the Git common-directory identity at trust approval (`e49f90d0`) | `w1-recheck.md`: merge |
| W2 (`28d54e3b`) | `w2.md` | M05-W2-R01, an in-flight child of stopped parent work (`27bef72a`) | `w2-recheck.md`: merge |
| W3 (`6be57b61`) | `w3.md` | R01 (the setup offer's disclosure, revision 5.2 item 22), R02 (the background bind's pause fence); R03 fixed too (`0e47249e`) | `w3-recheck.md`: merge; RC01 fixed in `1dad49c1` |
| W4 (`d7a34d4f`) | `w4.md` | none blocking; R01–R03 fixed in `2a2ad459` | not required |
| W4 final candidate (`959936c4`) | `w4-final.md` | M05-W4F-R01 (an imported routed destination reached by its bare alias), M05-W4F-R02 (a forward wall-clock step and a strict cutoff); R03–R05 too (`056a1692`) | `w4-final-recheck.md` (`056a1692`): FIX FIRST, RC-R01 to RC-R03 (route-pending leaks) and R02, R03 partly; fixed under ruling I-27 and the orchestrator's rulings (`84d7c44e`), the diff checked by the orchestrator (ADR-0009: no third independent review); RC-R04 (harness) fixed too |

Revert proofs for the blocking fixes are in `tests/evidence/artifacts/m05-w1/`, `m05-w2/`, `m05-w3/`
and `m05-w4/` (I-26, R01 under I-27, R02; and the WSL terminal hang's reproduction on the devbox,
`repro-a29-wsl-terminal-hang.json`).

## 4. Blocked on owner inputs

No new B-IDs (m05-plan §7):
- **B7:** A02's step comparison with the G01 baseline worksheet (ADR-0001 §6); the human walkthrough is M09's.
- **B12:** a reboot or logout inside the A02 window.
- **B2:** A29's cross-user rows (a second OS account against the control socket and the Windows pipe),
  carried from M01's A29-local.
- **B9:** the Linux arm64 rows.

## 5. Limitations and residuals

- **I-13, the first ordinary `ssh` after a free-slot period:** it activates the personal default and
  fails once; the next one logs in. With the shell integration the hook warms the default first, so the
  first one logs in. Native Windows has no hook and keeps the limitation. Spec §5.4 and §10.3 hold from the
  second use, and with the hook from the first (observed: `i13 macos failed`, `i13 linux failed`,
  `i13 windows failed`; with the hook, the warm-up held the slot before the first `ssh` on macOS, the
  devbox and WSL).
  The setup offer's note says so.
- **I-26, a cutoff's scheduler pass** (fixed in W4, not a residual): a timer wake that landed a few
  milliseconds before a cutoff ended nothing, and the passed bound was then dropped from the next
  wake, so a cut-off grant could stay `active` (its strict connections up) until the supervisor's
  idle bound, 300 s, while its next login was already refused. The supervisor now wakes for every
  `cutoff_at` and re-checks a usable grant's passed bound a second later (ADR-0011 §7.3; revert proof
  `tests/evidence/artifacts/m05-w4/revert-i26-passed-bound-recheck.json`). The final review's
  fix round widened the re-check to every state a bound still ends (`preparing` and
  `awaiting_approval` too; M05-W4F-R04) and measures the next pass's delay from the pass's end
  (M05-W4F-R05).
- **M05-W4F-R02, a wall clock moving ahead of the timer** (fixed in W4, not a residual): the next
  pass waited on the monotonic timer, so a wall clock moved forward past a cutoff (one step or
  several small ones) left a strict connection up past the cutoff. Every resume poll (at most
  every 2 s) now compares the wall-clock instant the next pass was scheduled for with the current
  wall time and runs a due pass at once (ADR-0011 §7.3;
  `integration_runtime_m03::wave4::{a_forward_wall_step_past_a_cutoff_ends_its_grant_at_the_next_poll, small_forward_wall_steps_past_a_cutoff_end_its_grant_at_the_next_poll}`
  drive the real timed loop with injected clocks; revert proof
  `tests/evidence/artifacts/m05-w4/revert-r02-wall-step-pass.json`).
- **M05-W4F-R01, an imported routed destination** (fixed in W4 by ruling I-27, not a residual):
  the jump fix imported a bastion's routed destination as a plain observed destination, so
  `connect` handed its bare alias to `ssh`, where a direct alias of the same name won; a first
  fix (a pending-route marker) still leaked through the TUI, a catalog edit and a replayed
  `ensure`. Import now never writes a routed destination the receiver does not have with that
  route: it is skipped (`route_required`, naming the jump and the setup command), as is a new
  profile with a pair on it, so nothing can reach it by its bare alias (ADR-0006 revision 5.3 item 24, ADR-0011 §2.4 I4; revert proof
  `tests/evidence/artifacts/m05-w4/revert-r01-routed-import-skipped.json`).
- **The WSL hook harness on a PC with no distribution** (a harness limitation, ruled in W4): the run
  stops before any import unless its first census succeeds. Where `wsl --list --quiet` exits
  nonzero with nothing registered, a PC with no distribution cannot run the WSL row; it fails
  closed. The owner's PC has its own distribution, so the exit run is unaffected.
- **The WSL hook harness's ownership check** (fixed in W4 at 5aa752c0, harness only): PC job 11's
  first WSL attempt refused its own freshly imported distribution (the registry rows came back
  wrapped in one array, so no row matched) and ran no journey; the run left it registered and the
  PC removed it by exact name. The real reader is now self-tested over a fake registry key, and the
  cleanup removes only this run's own import (name, census, pending marker, install directory). The
  same commit keeps version facts (the WSL version, the kernel release) out of the address
  redaction, in the runner and in the build host's importer.
- **M05-F1, removing a destination with live access** (a follow-up, M07 hardening; ruled in the W4
  re-check): `destination remove` ends neither the destination's live grants nor its bindings, so a
  replayed `ensure` can return the old binding until it is revoked or expires. That is access already
  held, continuing within its limits. It should refuse with a finding listing them, or end them; the
  owner decides which (`progress.md`).
- **The W4 pre-final native findings** (fixed in W4, not residuals): on Windows, A16 counted one
  `Accepted` line for an environment's two logins in both runs: the harness's WSL `sshd` logged to a
  drvfs file, where two sshd children appending at once lost a line, so the log now lives on the WSL
  file system (`tests/native/m02/run-windows-local.ps1`; two logins of one environment share its slot
  and so its certificate, one serial, which is correct). In WSL,
  `a29_cli_hook_ignores_a_hostile_environment` hung for the harness's 900 s: under the WSL session's
  terminal, an interactive `bash` outside the terminal's foreground process group (GNU `timeout`'s)
  stops its whole group with `SIGTTIN`; the test now runs its shells in a session of their own
  (`setsid -w`, no controlling terminal) and bounds each one.
- **I-7, an uncovered lock preference:** `EnsureData.uncovered` cannot report an uncovered lock
  preference; `uncovered_lock_behavior` is on M07-T03's stable-JSON list.
- **ADR-0011 §8 residuals:**
  - **R1:** a same-user agent with a terminal can drive the attended confirmation (Q8: the residual only;
    the guard was dropped). Claimed: no repository, manifest or request content becomes consent.
  - **R2:** the working directory in a request is a same-user claim (`same_user_context`).
  - **R3:** ordinary aliases are shared across an environment's jobs (`shared_environment_default`).
  - **R4:** lazy ordinary-`ssh` activation activates the default's whole covered scope.
  - **R5:** re-entry makes the window a usability bound; pause and cutoff are the stops.
  - **R6:** workspace identity on a filesystem without a stable identity is refused, not approximated.
  - **R7:** a restart while a context request is queued is covered by construction; under ruling I-9 no
    request is queued behind a trust decision.
  - **In `RESIDUALS`** (`crates/domain/src/claims.rs`; ruling I-23): R1
    `same_user_agent_with_a_terminal_can_attend` and R2
    `request_working_directory_is_a_same_user_claim` (`NeedsHostileSameUserProgram`); I-13
    `first_ordinary_ssh_after_a_free_slot_fails_once` and R6 `workspace_identity_unavailable_is_refused`
    (`FailClosedOnly`; R6's probe cites `crates/project/src/observe.rs`, since no fixture filesystem lacks
    stable identities). R3, R4, R5 and R7 are design properties, recorded here and in ADR-0011 §8 only.
- **The claims table:** M05 adds no `CLAIMS` entry (ruling I-17: M03's precedent is entries for
  platform-mechanism fields only, and no M05 claim is one).
- **Test fixtures:** on Unix the fixture `sshd` logs in as the account running the tests (the testkit's
  documented limitation), so its login shell and startup files run; the exit suite gives every login a
  scratch `HOME` and Git configuration, and `git-upload-pack` may read the account's global Git
  configuration, as M02's ordinary-ssh scenario does. The A16 environments differ by environment, CA,
  catalog and runtime, not by remote account.
- **`profile_label` in the TUI** (ruling I-21) and **paths in human output** (M05-W3-R03, RC01) are
  rendered as inert data; a same-user program that edits owner labels remains a presentation residual.

## 6. Deferred and handed on

- **M04's exit (Q9):** A16's WSL and container pairs; A28's forwarding and container rows. ⟨M04 exit,
  2026-11-20⟩ Closed by M04's records at build `50dbc86b` (Mode B at `06784973`), every row named here
  `verified`: A16's WSL pair by `m04-a13-wsl-mode-b.json`'s windows-modeb row; A16's container pair and A28's
  container row by `m04-a15-containers-bastion.json`'s wsl-containers row (the endpoint lists only the binding's
  identity; a control-protocol hello on `agent.sock` fails); A28's forwarding row by that record's route rows
  (`a15_forwarded_endpoint_bounded_to_binding`, `a15_user_dash_a_refused_without_capability`,
  `a15_non_jump_pair_cannot_open_forwarding`). M05's records keep the rows `deferred_with_decision`: the shared
  evidence generator has no cross-record row, so the mapping is recorded here, in
  `docs/architecture/m04-exit-draft.md` §3 and in the matrix's M04 section (the M03 claims precedent).
- **A later per-destination ADR:** identities through `session-bind@openssh.com`, so managed aliases can
  drop `IdentitiesOnly` and the first ordinary `ssh` logs in without the hook (I-13 option 3).
- **M07:** the exported host-key hint at first connect (I-12); PowerShell context integration (Q6).
- **M07-T03's stable-JSON list:** `EnsureData.uncovered_lock_behavior` (I-7), `PolicyView.scope` (I-14).
- **Re-deferred (Q7):** a single grant with per-pair mechanisms.
- **Later candidates:** OS user-presence approval (ADR-0011 R1); machine-local remapping of manifest
  references (M07 if needed); one workspace identity across Windows and WSL (M04 Mode A).
- **M09:** A30 comprehension and the normal-week study; the B7 walkthrough.

## 7. Next

`progress.md` records the exit and the follow-ups (M05-F1; M04-F2, found in this run's gate);
`docs/compatibility/matrix.md` gains the M05 section. The orchestrator merges `m05/w4` into main;
then M03-F1 and M04 follow.
