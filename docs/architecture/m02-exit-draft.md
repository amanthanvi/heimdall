# M02 exit draft: existing-access vertical slice

**Status:** draft. This is evidence for an exit decision, not the decision itself. **M02 does not exit on this
evidence.** Every exit record is `blocked`, and the macOS and Linux rows are `in_progress` (sections 1 and 3).

**Date:** 2026-11-06 · **Task:** M02-W5-run (the evidence half of m02-plan U11).

**Build:** base commit `bcad82de864656c0a434e21155a807da7c768ed4` plus the uncommitted wave-5 working tree. The
runs started before that tree was committed, and the following values bind them to it:
- `git diff HEAD` and the untracked files, hashed together at 03:55Z: sha256 `b4700a43…2de82a`;
- the `crates/` and `tests/` `*.rs` digest in `tests/native/m02/required-inventory.json`: `1e912184…f90b80`.

**Artifacts:** `tests/evidence/artifacts/m02/exit-bcad82de-w5/`. `digests.txt` lists every artifact file; its sha256
is the records' `artifact_digest`. **Records:** `tests/evidence/m02-*.json`, written by `m02-evidence.py --config
tests/evidence/artifacts/m02/exit-bcad82de-w5/runs.json --write` and valid against `record.schema.json` (`validate-records.py`: 100 records, 0 invalid).

The filled configuration is kept with the artifacts. `tests/native/m02/runs.json` stays the template, as its
self-test requires. The first `check.sh` after writing the records, with the filled template in place, exited 1
(native-harness-selftest: the template checks). After the template was restored, `check.sh` exited 0 on all nine
steps: 1665 passed, 0 failed, 7 ignored.

Once the tree is committed, the native runs must be repeated at that commit (ADR-0007 §12.31 item 5). Until then,
every row here describes the working tree.

## 1. Exit claims (plan.md §5 M02 "Exit evidence"; m02-plan §3)

Row statuses are per platform, in this order: macOS arm64, Linux x86-64 (devbox), Windows 11 x64, the WSL disposable
distribution, then the owner-input rows. The record's status is its lowest row.

| Exit claim | Status | macOS | Linux | Windows | WSL distro | Owner-input rows | Record |
|---|---|---|---|---|---|---|---|
| A01: no remote change, no key export, no mandatory prefix, unaffected aliases, personal profile without a repository | `blocked` | in_progress (13/13 required passed) | in_progress (5 failed: pty harness defect) | blocked (unreachable) | blocked (unreachable) | B3, B2, B9 | `m02-a01-existing-access.json` |
| A11: non-interactive use returns explicit interaction or capability state, without a popup or an unapproved fallback | `blocked` | in_progress (34/34 passed) | in_progress (2 failed, 2 harness gaps) | blocked | n/a | B1, B4, B6 | `m02-a11-provider-interaction.json` |
| A21: default doctor runs nothing; explicit probes are classified and bounded | `blocked` | in_progress (31/31 passed) | in_progress (2 failed: pty defect; 1 gap) | blocked | n/a | none | `m02-a21-passive-doctor.json` |
| A22: relevant behaviour correct, unknowns stay unknown, unrelated content and newer edits survive, generation deterministic | `blocked` | in_progress (392/392 passed) | in_progress (4 failed: three 9.6p1 client differences and one git 2.43 refusal; 11 gaps) | blocked | blocked | B10 | `m02-a22-configuration-precedence.json` |
| A27: no stdout contamination or shell injection; child streams and status kept; setup failure distinguishable | `blocked` | in_progress (95 passed, **1 failed**: `terminal::a27_ctrl_c_reaches_child_once`) | in_progress (3 failed) | blocked | n/a | B5 | `m02-a27-child-integrity.json` |
| A35: verified executable and identity used; exact limitations; existing-auth not second-class | `blocked` | in_progress (31/31 passed) | in_progress (12 failed: pty defect) | blocked | blocked | B1, B4, B9 | `m02-a35-reference-matrix.json` |
| A participant can connect without a mandatory work wrapper | `blocked` | in_progress (1/1 passed) | in_progress (1 failed: pty defect) | n/a | blocked | B7 | `m02-exit-no-mandatory-wrapper.json` |
| No remote authentication change, key export or provider-policy bypass was needed | `blocked` | in_progress (5/5 passed) | in_progress (2 failed: pty defect) | blocked | n/a | none | `m02-exit-no-remote-change.json` |
| Managed unattended access is not claimed until M03 | `blocked` | in_progress (2/2 passed) | in_progress (2/2 passed) | blocked | n/a | none | `m02-exit-no-unattended-claim.json`; matrix section "M02 existing-access rows" |
| R-RT-05: no blind replay | `blocked` | in_progress (12/12 passed) | in_progress (10 passed, 1 gap) | blocked | n/a | none | `m02-r-rt-05-no-blind-replay.json` |
| ADR-0006 §13.20 item 3: bounded adapter calls; a hung preparation's cleanup runs without a restart | `blocked` | in_progress (17/17 passed) | in_progress (15/15 passed) | blocked | n/a | none | `m02-adapter-call-bounds.json` |
| R-SE-04: host trust never weakened | `blocked` | in_progress (8/8 passed) | in_progress (1 failed: pty defect) | blocked | n/a | none | `m02-r-se-04-host-trust.json` |
| T06: clean local uninstall | `blocked` | in_progress (2/2 passed) | in_progress (2 gaps) | blocked | blocked | none | `m02-t06-clean-uninstall.json` |
| All of the above together (m02-plan §3) | `blocked` | | | | | | `m02-exit-claims.json` (654 indexed tests; 20 rows in_progress, 25 blocked) |

Why the macOS rows are `in_progress`:
- Every required test passed there, except `e2e_run_m02 terminal::a27_ctrl_c_reaches_child_once`.
- That one failure made `check.sh` exit 1, and the generator keeps a row `in_progress` whenever a required command
  exits nonzero.
- The failure is intermittent. The test passed 12 of 12 times run alone, and the whole target passed 5 of 5 times,
  in the diagnostic reruns afterwards (`macos/diagnostic-reruns.txt`).
- §12.31 forbids retrying a flaky test away, so this run stands as recorded.

"n/a" means m02-plan §4 declares no row for that platform. A "gap" is a test that reads the repository at its
compile-time path and cannot run off the build host (`build_host_paths`). It keeps the row `in_progress`.

## 2. Native runs

| Platform | Harness | Window (UTC) | Exit | Passed / failed / ignored | Canary scan | Other checks |
|---|---|---|---|---|---|---|
| (build host) | `tests/native/m02/refresh-inventory.sh` | 03:55-04:02 | 0 | n/a (both cross-builds; inventory regenerated) | n/a | none |
| macOS 27.2 (26B123) arm64, OpenSSH 10.5p1, Apple Git 2.54.0, APFS | `TMPDIR=/tmp tests/native/m02/run-macos.sh …/macos` | 04:39:51-04:45:10 | **1** | 1664 / 1 / 7 (check.sh test step exit 101; the other 8 steps exit 0; observation pass exit 0) | 0 | leak scan 0; `~/.ssh` and Git metadata unchanged; 0 leftover processes; scratch removed |
| macOS, first attempt | `tests/native/m02/run-macos.sh …/macos-run1-sun-len` | 04:02:20-04:38:53 | 1 | 1257 / 408 / 7 | 0 | Harness defect: socket paths over `SUN_LEN` under the per-user `TMPDIR`. One test hung on an unbounded FIFO open and was unblocked by opening that FIFO's read end in the run's own scratch (`NOTE.txt`). No record uses this run |
| Linux x86-64 devbox: kernel 6.8.0-147, glibc 2.39, OpenSSH 9.6p1, git 2.43.0, ext4 | `tests/native/m02/run-linux.sh …/linux devbox` | 04:01-04:23 | **101** | 1519 / 29 / 7 over 47 binaries; exit 101 in e2e_cli_m02, e2e_run_m02, heimdall-unit, integration_projection_git and integration_sshconf_vs_ssh_g | 0 | leak scan 0; `~/.ssh` and Git metadata unchanged; 0 leftover processes; scratch removed, and 0 `~/hm-m02-*` directories found afterwards |
| Windows 11 x64 | `HM_SSH_CONFIG=… HM_HOST=… tests/native/m02/run-windows.sh …/windows` | 04:47 | **1** | not run | n/a | Cross-build 0, plan 0, argvdump 0. Remote create exited 255: host unreachable. Nothing was created on the host |
| WSL2 disposable distribution | `run-wsl-distro.sh` | not run | n/a | n/a | n/a | It reaches the distribution through the same unreachable PC endpoint |
| Evidence generator | `m02-evidence.py --write` | after the runs | 1 | 14 records written | n/a | Exit 1 only because it reports the scenario and `windows_launch` tests of the unavailable platforms as "not found in any log" (it does not skip unavailable platforms in that check); `validate-records.py` exit 0 |

The Windows PC was up during the whole window: its Tailscale node answered ping, and its port 22 accepted a
connection. Its WSL ssh endpoint, the one `HM_SSH_CONFIG` names, refused every attempt. There were 22 attempts
between 03:56Z and 04:47Z, each "connection timed out" (`windows/host-unreachable.txt`).

## 3. What keeps the rows from `verified` (escalated)

**Test or harness defects.** None of these is a product result.

1. **The pseudo-terminal children lose `HEIMDALL_E2E_BIN`.**
   - Where: `tests/e2e/cli_m02.rs` (`Pty::start`) and `tests/e2e/run_m02.rs` (`Pty::start`, `start_env`).
   - What: the child test process starts with `env_clear()`, so it falls back to `env!("CARGO_BIN_EXE_heimdall")`,
     the build host's path. On Linux every pty case fails with "exec failed: No such file or directory" or "no
     envelope". That covers 20 of the 21 e2e_cli_m02 failures (the 21st is item 2), and probably `a27_ctrl_c`,
     `a27_resize` and `a11_interactive_connect` in e2e_run_m02.
   - Fix (owner: the e2e tests' unit): pass the parent's `bin()` to the child explicitly.
2. **Two tests read compile-time paths but are missing from `case-index.json` `build_host_paths`:**
   - `heimdall-unit tui::view::tests::the_refusal_is_visible_in_the_modal` (snapshot `decision_apply_refused_40x12`);
   - `e2e_cli_m02 unix::uninstall_purge_state_is_refused_without_a_typed_yes_and_keeps_everything` (reads
     `schemas/public-api`).
3. **`run-macos.sh` places the tests' `TMPDIR` too deep under the macOS per-user `TMPDIR`**, which overflows
   `SUN_LEN`. The recorded run used `TMPDIR=/tmp`. Suggested fix: create the scratch directory under `/tmp`.
4. **`e2e_run_m02 a27_exec_failure_with_failed_meta_write_is_indeterminate` opens its pause FIFO for writing with no
   bound.** If the heimdall child exits early, the test (and `check.sh`) hangs forever.
5. **Harness redaction defects.**
   - `run-windows.sh` exits before redacting `build.txt` when the host is unreachable. The build host's home path was
     left in it; it was redacted afterwards.
   - The macOS host-name redaction also rewrites a 3-character host name inside ordinary words.
6. **The generator's "not found in any log" check counts tests of unavailable platforms.**

**Product findings, or findings that need a ruling:**

7. **`e2e_run_m02 terminal::a27_ctrl_c_reaches_child_once` failed on macOS in the recorded run** ("heimdall did not
   finish", `run_m02.rs:307`). The integrator suspected this test of being flaky, and this is the first recorded
   native failure. It is intermittent: it did not reproduce in the diagnostic reruns.
8. **OpenSSH 9.6p1 (the devbox client) disagrees with the evaluator:**
   - `Match sessiontype` is unsupported there (`ssh -G` exits 255);
   - `User` and `SetEnv` are not environment-expanded, and an `Include` path is not expanded;
   - the first-pass and final-pass `IdentityFile` reports differ.

   ADR-0007 §12.15 item 4 makes this a defect, fixed by gating on client version.
9. **OpenSSH 9.6p1's default identity list** has `id_xmss` and `id_dsa`, which Heimdall's six-name list lacks. The
   §12.17 premise, that Heimdall's list is a superset, does not hold for this client. That needs a ruling.
10. **git 2.43.0:**
    `git_both_global_files_present_include_goes_to_first_read_file_and_later_user_values_in_either_win` failed. The
    setup refused both items as `unmanageable_file`. The test passed on Apple Git 2.54.0.
11. **The correctness of the integrator's §12.30 item 6 work is open.** The integrator's report puts it at
    `in_progress`: the driver's refusal is in place, but the `manual_mode` resolution of a `managed_file_edited`
    conflict is missing. Its two tests passed on both platforms; they do not cover `manual_mode`.

## 4. Blocked on inputs

| Input | Blocks |
|---|---|
| The Windows PC's WSL ssh endpoint (`HM_SSH_CONFIG`) reachable: WSL running with its sshd. An owner action on the PC | Every Windows row and the WSL disposable distribution row (A01, A11, A21, A22, A27, A35, R-RT-05, ADR-0006 §13.20 item 3, R-SE-04, T06, the three plan §5 claims). Also the Windows facts: account-name lookup, DACL, `ReplaceFileW` Git name transitions, junction, pseudoconsole Ctrl-C and resize |
| `HM_WSL_ROOTFS` (the pinned Ubuntu 24.04.5 WSL image on the PC) or authorization for `HM_WSL_DOWNLOAD=1` | the WSL disposable distribution run (ordinary ssh, git, scp and sftp without `-F`; T06 with a real home) |
| B1: a disposable 1Password account with disposable SSH keys | the 1Password live rows of A11 and A35 on every platform |
| B2: the disposable second Windows account | Windows ordinary ssh without `-F` (A01, A35) |
| B3: a disposable macOS standard user account | macOS ordinary ssh without `-F` (A01, A35) |
| B4: a disposable Windows host whose system agent may hold test keys | the Windows system-agent rows, including its confirm-constrained row (A11, A35) |
| B5: an operator at the Windows console | interactive-console Ctrl-C and resize (A27); the no-UAC-prompt observation |
| B6: a hardware security key (FIDO2) | the touch-required row of A11 |
| B7: the owner as participant | the human walkthrough of "a participant can connect without a mandatory work wrapper" |
| B9: a native Linux arm64 host | the arm64 rows of A01 and A35 |
| B10: Windows Developer Mode, or one elevation | the Windows file-symlink reparse-point row of A22 |

The compatibility matrix rows are in `docs/compatibility/matrix.md`, section "M02 existing-access rows". Every label
there stays `not-tested`: ADR-0001 §9 keeps it so until §5 and §6 close.
