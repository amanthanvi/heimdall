# M02 exit record — existing-access vertical slice

**Date:** 2026-11-10 · **Build:** `e4f43f847af1b3a7396298f5a39af6d859b080d1` ·
**Decided by:** the orchestrator, under the owner's delegation (ADR-0004).

**Decision:** **M02 exits at `e4f43f847af1b3a7396298f5a39af6d859b080d1`**, on 2026-11-10.

**The rule.** M01 used it, and ADR-0008 §17.3 item 6 states it for M03:
- every record is `verified`, except rows blocked only on named owner inputs;
- those rows stay `blocked` with `blocked_on`, and no claim is widened to cover them;
- a `deferred_with_decision` row cites its ruling. It is not part of the claim and does not count
  (`tests/evidence/README.md`).

**At this build:**
- 8 of the 14 `m02-*` records are `verified`.
- The other 6 are `blocked`. Every row in them that is not `verified` is one of these:
  - blocked on a named owner input (B1 to B7, B9);
  - `deferred_with_decision` to M04 with its ruling: ADR-0007 §12.47 item 3 (D2, D3), §12.49 item 2 or
    §12.49 item 4.
- No row is `in_progress`.
- The coverage guard (ADR-0007 §12.47 item 1) recorded no unjustified exclusion, no unmet
  `platform_required` test and no stale entry. `case-summary.json` holds none of `excluded_without_rationale`,
  `platform_required_not_passed`, `platform_only_stale`, `ran_not_in_inventory` or `evaluation_reported_errors`.

ADR-0007 §12.46 item 4 held the exit until five Windows gaps ran natively or were ruled out. Each one ran natively
at this build (section 6).

This record supersedes `docs/architecture/m02-exit-draft.md`, which described the 2026-11-06 working-tree runs
and did not exit. It also replaces the unpublished exit text written for `ce21a76f`, which was held under
§12.46 item 4.

**Build identity.**
- **Commit:** `e4f43f847af1b3a7396298f5a39af6d859b080d1`.
- **Sources digest** (`crates/` and `tests/` `*.rs`, `sources_sha256` in
  `tests/native/m02/required-inventory.json`): `63ad245b2b7170453d35df97c2a214c317ffc1b018f7fde110b37f1f3520baa5`.
  - The inventory was regenerated at `e4f43f84`, and `refresh-inventory.sh` exited 0 (`runs.json` `commands`).
  - `git diff 517160e0..e4f43f84` changes this value, and one `.rs` file: `tests/model/revocation.rs`.
- **Artifact digest** (the records' `artifact_digest`):
  `sha256:b56c259b2b31d0fdeb04c6cc9022e9d1837825c93a944a967a4543bc30ea260f`. That is the sha256 of
  `tests/evidence/artifacts/m02/exit-e4f43f84/digests.txt`.
  - That file lists 22 artifact files. I re-checked all 22 against it (`shasum -a 256 -c`: 22 OK, 0 failed).
  - I also re-checked each platform digest in `runs.json` against that platform's lines (all four equal).
- **Linux binaries** (`linux/build.txt`):
  - `heimdall`: `69422916da21511c1c2b40002b9420175e4800d29ad862ac8bbdd658a0b6891c`. The WSL disposable
    distribution ran the same binary; its `wsl-distro/build.txt` records it, checked against
    `HM_PREBUILT_SHA256` before use;
  - `hm-fixture-hook`: `ebe2ba192a06406e9000d59dcac1a4ef2d2581144e8a25378c4be4ec225405bc`.
- **Windows binaries** (`windows/build.txt`, native `x86_64-pc-windows-msvc`):
  - `heimdall.exe`: `52d20c4f79251df5e2c6305cde0c0cd870917d2d0b11741fc3bffe65bf69a06e`;
  - `hm-fixture-hook.exe`: `f6b1a9fa291efc09c72d47748fb2685378d838eea4a681bf5a049e4a0cc8c6a7`;
  - the pseudoconsole driver's helper `argvdump.exe` is a Go cross-build, `e25c37f7…1c66` (`runs.json`; no
    artifact holds the full value).
- **After the build:** `83113247` adds the artifacts, the records and a `progress.md` entry.
  `git diff --name-only e4f43f84..83113247` lists only `tests/evidence/` and `progress.md`. No product code, test,
  case index or harness tool changed after the build.

## 1. Exit evidence (plan §5 M02; m02-plan §3)

**Sources:**
- the records `tests/evidence/m02-*.json`, written by `m02-evidence.py --config
  tests/evidence/artifacts/m02/exit-e4f43f84/runs.json --write`;
- `validate-records.py`: 100 records, 0 invalid. I re-ran it on this checkout and it exited 0.

**How to read the table:**
- Each platform cell gives the row status and the `passed` value of that platform's row.
- `passed` counts the record's inventoried tests that apply on the platform. A `platform_required` test is checked
  by the guard, not counted.
- "excl. *n*" is `excluded_on_this_platform`. Every excluded test has a case-index rationale (section 6).
- "n/a" means m02-plan §4 declares no row for that platform.

| Exit claim | Record status | macOS arm64 | Linux x86-64 (devbox) | Windows 11 x64 (native, local mode) | WSL distribution | Rows not `verified` | Record |
|---|---|---|---|---|---|---|---|
| A01: no remote change, no key export, no mandatory prefix, unaffected aliases, personal profile without a repository | `blocked` | verified, 13 | verified, 13 | verified, 12 (excl. 1) | verified, 7 | blocked: B3, B2, B9. Deferred: Windows personal profile (§12.49 item 4) | `m02-a01-existing-access.json` |
| A11: non-interactive use returns explicit interaction or capability state, without a popup or an unapproved fallback | `blocked` | verified, 34 | verified, 34 | verified, 29 (excl. 5) | n/a | blocked: B1, B4, B6. Deferred: Windows interactive connect (§12.47 D3) | `m02-a11-provider-interaction.json` |
| A21: default doctor runs nothing; explicit probes are classified and bounded | `verified` | verified, 31 | verified, 31 | verified, 27 (excl. 6) | n/a | deferred: Windows TUI pty cases (§12.47 D2) | `m02-a21-passive-doctor.json` |
| A22: relevant behaviour correct, unknowns stay unknown, unrelated content and newer edits survive, generation deterministic | `verified` | verified, 462 | verified, 461 (excl. 1) | verified, 463 (excl. 4) | verified, 1 | none | `m02-a22-configuration-precedence.json` |
| A27: no stdout contamination or shell injection; child streams and status kept; setup failure distinguishable | `blocked` | verified, 97 | verified, 97 | verified, 80 (excl. 31) | n/a | blocked: B5. Deferred: Windows interactive connect (§12.47 D3) | `m02-a27-child-integrity.json` |
| A35: verified executable and identity used; exact limitations; existing-auth not second-class | `blocked` | verified, 39 | verified, 39 | verified, 38 (excl. 1) | verified, 4 | blocked: B1, B4, B9 | `m02-a35-reference-matrix.json` |
| A participant can connect without a mandatory work wrapper | `blocked` | verified, 1 | verified, 1 | verified, 1 | verified, 5 | blocked: B7 | `m02-exit-no-mandatory-wrapper.json` |
| No remote authentication change, key export or provider-policy bypass was needed | `verified` | verified, 5 | verified, 5 | verified, 5 | n/a | none | `m02-exit-no-remote-change.json` |
| Managed unattended access is not claimed until M03 | `verified` | verified, 2 | verified, 2 | verified, 2 | n/a | none | `m02-exit-no-unattended-claim.json`; matrix section "M02 existing-access rows" |
| R-RT-05: no blind replay | `verified` | verified, 12 | verified, 12 | verified, 12 | n/a | none | `m02-r-rt-05-no-blind-replay.json` |
| ADR-0006 §13.20 item 3: bounded adapter calls; a hung preparation's cleanup runs without a restart | `verified` | verified, 17 | verified, 17 | verified, 17 | n/a | none | `m02-adapter-call-bounds.json` |
| R-SE-04: host trust never weakened | `verified` | verified, 8 | verified, 8 | verified, 8 | n/a | none | `m02-r-se-04-host-trust.json` |
| T06: clean local uninstall | `verified` | verified, 4 | verified, 4 | verified, 3 (excl. 1) | verified, 2 | deferred: Windows typed-yes purge refusal, exit 6 (§12.49 item 2) | `m02-t06-clean-uninstall.json` |
| All of the above together (m02-plan §3) | `blocked` | | | | | B1, B2, B3, B4, B5, B6, B9 | `m02-exit-claims.json`: 735 indexed tests; 34 rows `verified`, 10 `blocked`, 5 `deferred_with_decision` |

**Record totals:** 14 records.
- 8 `verified`: A21, A22, adapter call bounds, no remote change, no unattended claim, R-RT-05, R-SE-04 and T06.
- 6 `blocked`: A01, A11, A27, A35, no mandatory wrapper, and the aggregate.

I recomputed the aggregate's 34, 10 and 5 from the ten case records' rows. The D3 row appears in both A11 and A27,
so the 5 deferred rows are 4 distinct deferrals.

**Two notes on the counts:**
- **Windows above macOS.** Windows A22 counts 463 against macOS's 462, because the Windows inventory holds
  Windows-only tests.
- **The WSL A22 row.** It counts 1, `a22_rename_exchange_supported_on_the_home_fs`. Its `platform_required` list also
  names `a22_birth_time_recorded_on_the_home_fs`. That test passed in `wsl-distro/tests.txt` and is checked by the
  guard.

**What a `verified` platform row means.** Every required test that applies on that platform ran and passed in this
build. A test excluded on a platform carries a written case-index rationale. A planned test that does not exist reads
as not run (§12.47 item 1, R1 and R2). It is not an independent review of the units (`runs.json`
`common_limitations`).

## 2. Native runs at the exit build

All four ran at `e4f43f84` on 2026-11-10 (`runs.json` `started_at`). Artifacts:
`tests/evidence/artifacts/m02/exit-e4f43f84/{macos,linux,windows,wsl-distro}/`.

I recomputed the passed, failed and ignored totals below from the logs' `test result` lines. Every line in each
platform's `commands.txt` reads `exit 0`.

| Platform | Harness | Exit | Passed / failed / ignored | Canary scan | Leak scan | Owner-file checks |
|---|---|---|---|---|---|---|
| macOS 27.2 (26B123) arm64, OpenSSH_10.5p1 client and server, Apple Git 2.54.0, APFS | `TMPDIR=/tmp tests/native/m02/run-macos.sh` | 0 | `check.sh`: all 9 steps exit 0 (fmt, clippy, clippy-windows, test, test-discovery, schema, native-harness-selftest, evidence-selftest, evidence-records); 1780 / 0 / 8 over 60 result lines. Observation pass: 197 passed | 0 | 0 | `~/.ssh` and Git metadata equal before and after; 0 leftover test processes; scratch removed |
| Linux 6.8.0-147 x86-64 (devbox, label `linux-a`), glibc 2.39, 4 CPUs, OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, git 2.43.0, ext4 | `tests/native/m02/run-linux.sh … devbox` | 0 | 1776 / 0 / 8 over 49 binaries, each `exit=0` | 0 | 0 | `~/.ssh` and Git metadata equal before and after; 0 leftover test processes; scratch removed and checked absent |
| Windows 11 x64 (10.0.26300.9818), Medium integrity, native `x86_64-pc-windows-msvc` (rustc 1.99.1, MSVC 18.11.2, line tables only), in-box OpenSSH_for_Windows_9.5p2, Git for Windows 2.55.0.windows.3 | `run-windows-local.ps1` by an agent on the PC (local mode), 374 s | 0 | 1655 / 0 / 1 over 49 binaries, each `exit=0`; `windows_launch` 4 of 4. Imported with 1660 results (1655 + 1 + 4) | 0 | 0 | `%USERPROFILE%\.ssh` and `.gitconfig` metadata equal before and after; test pipes 0 before and after; `%LOCALAPPDATA%\heimdall` absent before and after; both fixture sshds stopped at the end; WSL scratch, clone, build and toolchain removed and checked absent |
| WSL2 disposable distribution (pinned Ubuntu 24.04.5 image) | `run-wsl-distro.sh` in local mode, inside the controller distribution, 138 s | 0 | `wsl_ordinary_ssh` 11 of 11 | 0 | 0 | the user's SSH configuration sha256 `99344213…ef9b` before and after `uninstall` (`3bceec60…f85b` after `setup apply`); registered distributions 1 before and 1 after, the set equal; 0 leftover heimdall processes |

**Ignored tests.** These are child-process entries that other tests re-execute: 8 on macOS and on Linux, and 1 on
Windows. The devbox did not run one test, the build-host-path test
`heimdall_testkit-unit repo::tests::unset_or_empty_is_the_compile_time_root` (`linux/skipped.txt`). It is
classified neutral and ran on the build host.

**Windows details** (`windows/host.txt`, `windows/tests.txt`):
- **The fixture sshds.** The plain fixture sshd and the strict one (`MaxAuthTries 3`) ran in WSL scratch, OpenSSH
  9.6p1, non-root, each with a per-run host key.
  - Both were reached from Windows on 127.0.0.1.
  - They authenticate the WSL account (`fixture-sshd-account=differs from the Windows user`), exported as
    `HM_FIXTURE_SSHD_USER` and redacted as `<wsluser>`.
- **The clients the tests resolve.** `ssh-V-tests` is OpenSSH_for_Windows_9.5p2. A PATH-first OpenSSH 10.3p1 was
  recorded as a candidate and not selected. `e2e_cli_m02`'s A35 matrix test printed:
  - `ssh` → `C:\WINDOWS\System32\OpenSSH\ssh.exe`;
  - `scp` → `…\scp.exe`;
  - `sftp` → `…\sftp.exe`;
  - `git` → `C:\Program Files\Git\mingw64\bin\git.exe`.
- **The pseudoconsole drivers** (`windows_launch`). Each row reports `killed_by_harness: false`:

  | Row | Observed |
  |---|---|
  | `ctrlc.event` | child ready; Ctrl-C `processed`; heimdall alive 600 ms later; child interrupts 1; heimdall exit 42 |
  | `ctrlc.keystroke` | the same, with `^C` typed into the pseudoconsole input |
  | `ctrlc.break` | the same |
  | `resize` | the child saw `100x30` then `132x40`; `resize_hr` 0; heimdall exit 0 |

- **Ctrl-C inheritance.** `ctrl-c-inherited=ignored`: the agent's environment starts processes with Ctrl-C ignored.
  The driver enables Ctrl-C processing for the heimdall it creates (ADR-0007 §12.44 item 2).
- **Facts read, not changed.** `developer-mode=on`, `git-autocrlf-clone=false`, and `clone-line-endings=LF`.

**WSL details** (`wsl-distro/host.txt`, `wsl-distro/tests.txt`):
- **The image:** downloaded over https; its sha256 matches the pin.
- **The run:**
  - imported the distribution;
  - installed the OpenSSH server and `sftp-server` in it only;
  - ran the scenario as a non-root user with a disposable home;
  - terminated it and unregistered it.
- **What the run recorded:**
  - the loopback fixture sshd logged 6 accepted logins;
  - `rename-exchange=supported (renameat2 RENAME_EXCHANGE)` and `birth-time=recorded (statx STATX_BTIME)`, on the
    ext4 home;
  - `listeners-other=3` before and after the scenario, and `listeners-loopback=0`;
  - `controller-distro-name=default (os-release)`. It is neither redacted nor leak-scanned (§12.44 item 1).

## 3. What changed since the draft

**The draft.** `m02-exit-draft.md` was built on `bcad82de` plus the uncommitted wave-5 tree, and every record in it
was `blocked`. Waves 5c to 5g fixed its harness defects and ruled on its product findings (ADR-0007 §12.32 to
§12.42). Waves 6w and 6x followed. These are every exit-build attempt; I recomputed the counts from each attempt's
logs:

| Build | Date | Result | Records written |
|---|---|---|---|
| `bcad82de` + wave-5 tree (the draft; `exit-bcad82de-w5/`) | 2026-11-06 | macOS exit 1: 1664 / 1 / 7 (`a27_ctrl_c_reaches_child_once`). Linux exit 101: 1519 passed, 29 distinct tests failed over 47 binaries. Windows not run (host unreachable). WSL not run | yes, all `blocked` (the draft) |
| `cb16c2d6` (`exit-cb16c2d6/`) | 2026-11-06 | macOS exit 0, 1760 / 0 / 8. Linux exit 101, 1756 / 1 / 8 (`repo::tests::unset_or_empty_is_the_compile_time_root`, a build-host-path test). **Windows, the first native run:** 1276 / 56 / 1; 12 of 49 binaries exited 101; canary scan 2 (exit 1); `fixture-sshd-at-end=mismatch` | no |
| `1e69263d` (`exit-1e69263d/`) | 2026-11-06 to 2026-11-08 | macOS exit 0, 1760 / 0 / 8. Linux exit 0, 1756 / 0 / 8. Windows first attempt: no disk space, no tests ran. Windows second attempt exit 0, 1340 / 0 / 1. Not preserved as artifacts (`progress.md`): the WSL first run (10 of 10, script exit 1 on a leak-scan false positive) and a Windows rerun with the drivers (`ctrlc.event` and `ctrlc.keystroke` failed) | no |
| `ce21a76f` (`exit-ce21a76f/`) | 2026-11-08 | all four exit 0: macOS 1760 / 0 / 8, Linux 1756 / 0 / 8, Windows 1340 / 0 / 1 with `windows_launch` 4 of 4, WSL 10 of 10. **Held** (§12.46 item 4): Windows rows read `verified` although their declared coverage never ran | yes, later superseded |
| `c167736e` (`exit-c167736e/`), after wave 6x | 2026-11-09 | all four exit 0: macOS 1778 / 0 / 8, Linux 1774 / 0 / 8, Windows 1653 / 0 / 1, WSL 11 of 11. The coverage guard kept A22's Windows row `in_progress` (§12.51 item 5) | no (§12.51 item 6) |
| `517160e0` (`exit-517160e0/`) | 2026-11-10 | macOS exit 0, 1779 / 0 / 8. Windows exit 0, 1654 / 0 / 1. WSL exit 0, 11 of 11. **Devbox exit 101,** 1774 / 1 / 8: `model_revocation::sharing_never_merges_unrelated_scopes_or_outlives_the_deadline`, a test-timing assumption (§12.51 item 7) | no (§12.51 item 8) |
| **`e4f43f84`** (`exit-e4f43f84/`) | 2026-11-10 | all four exit 0 (section 2) | **yes, these records** |

**Wave 6w** (ADR-0007 §12.43, §12.44) made the first native Windows run pass:
- **The failures.** The 56 failures at `cb16c2d6` were mostly Unix assumptions in tests. Six units on the PC fixed
  them; the patches were integrated in `491d8f5a`, `f0635b44` and `3fe6119f`.
- **Product fixes, each with a native regression:**
  - a rooted Windows `IdentityFile` is absolute;
  - `agents::locator_for` decides a Unix socket path by a leading `/`;
  - quarantine pins (`sys/quarantine.rs`);
  - the owner-only DACL check by the handle's kind;
  - the pipe listener identifies a client only after its first write (ADR-0006 §13.21).
- **Line tables.** The native Windows test build keeps line tables only (LNK1140). This is set by the local runner
  only.
- **The WSL local mode** (`b024b994`).
- **The default distribution name and the Ctrl-C inheritance** (§12.44). Both were harness defects.

**Wave 6x** (ADR-0007 §12.46 to §12.50) closed the Windows coverage gaps the held `ce21a76f` record found:
- **The audit.** `review-m02-code/windows-coverage-audit.md` found that 314 required tests did not exist on
  Windows. The scan alone excluded 295 of them, with no rationale.
- **The guard** (§12.47 item 1). An exclusion needs a case-index rationale (R1). `platform_required` names exact
  tests (R2).
- **D7** (§12.47 item 7) withdrew the §12.45 deferral of the file-symlink row. That row is now a
  `platform_required` test.
- **The units:**
  - WU-0: the fixture sshd user, strictness and log offsets;
  - WU-1: CLI transport, plus D4;
  - WU-2a and WU-2b: the projection and Git projection on Windows;
  - WU-3: the setup drivers;
  - WU-4: the doctor and `sys::account_name` on Windows;
  - WU-5: `run` and `connect`;
  - WU-6: the guard;
  - WU-7: 9.5p2 joins the encoding and client tables (D5);
  - WU-8: the pipe fixture, which closes W6W-R02 and W6W-R03.

  They landed in `250029ea` and `c167736e`.
- **Product fixes found natively:**
  - `adopted_key` compares a record path in the renderer's form (§12.48 item 1);
  - Heimdall's own Windows directories get the protected owner-only DACL, and a `~/.ssh` it creates gets user,
    SYSTEM and Administrators (§12.48 item 4, §12.49 item 6);
  - the preview validates the quarantine in P's directory (§12.48 item 5);
  - the launch check compares one pipe spelling (§12.49 item 1).
- **Review fixes.** The review's W6X-R01 to R04 were fixed (§12.50). The re-check's remainders were fixed in the
  harness (§12.51 items 1 to 3) and in `Quarantine::validate_existing` (§12.51 item 4).
- **The last two builds.** The BOM and CRLF round trip was ungated for Windows at `517160e0` (§12.51 item 5). The
  single-flight property was made concurrent by construction at `e4f43f84` (§12.51 item 7).

## 4. Independent review

The independent code reviews (Codex, read-only) are under `tests/evidence/artifacts/review-m02-code/`. The design
reviews are `review-m02-design/`. The reviews of the M02 tree from wave 5g on:

| Review | Range | Verdict | Rulings |
|---|---|---|---|
| `wave5g.md` | `cb5139e4..1f5b8156` | its findings are ruled in §12.42 | §12.42 |
| `wave6w.md` | `1f5b8156..ce21a76f` (the wave-6w product fixes) | fix first: W6W-R01 to R03 | §12.46 |
| `windows-coverage-audit.md` | declared Windows and WSL coverage at `ce21a76f` (an audit, not a code review) | 314 required tests absent on Windows | §12.47 |
| `wave6x.md` | `421c8f41..250029ea` | fix first: W6X-R01 to R04 | §12.50 |
| `wave6x-recheck.md` | `c51b8166..c167736e` | fix first: R01 resolved, R02 to R04 partly | §12.51 items 1 to 4 |
| `exit-517160e0.md` | `9bce3f9b..517160e0` | merge, no findings | §12.51 item 8 |
| `exit-gaps.md` | `c167736e..9bce3f9b` (the evidence generator, the importer and their tests); `517160e0..e4f43f84 -- tests/model/revocation.rs`; `96611c6f -- tests/e2e/run_m02.rs` | fix first: two pre-existing medium defects (R1 exit codes, R2 doubled separators), fixed after the build; neither touches these records | §12.51 item 9 |

**The gaps between those ranges.** This record found three changes that no review covered:
- `96611c6f`'s 8 lines of `tests/e2e/run_m02.rs`;
- the evidence generator and importer changes in `c167736e..9bce3f9b`;
- `tests/model/revocation.rs` in `517160e0..e4f43f84`.

They were then reviewed independently (`exit-gaps.md`). The reviewed changes hold. The review observed two **pre-existing** medium defects, fixed in the harness after the build, each with a regression:
- **R1:** a configured `exit_codes` entry could replace a nonzero exit that the commands log recorded;
- **R2:** a doubled separator, `//home/<name>`, passed the importer's home rules.

Neither touches these records. No `runs.json` sets `exit_codes`, and no committed artifact holds a doubled separator before a home. The fixed generator rates this build exactly as before, with an identical `case-summary.json` (ADR-0007 §12.51 item 9).

## 5. Blocked on owner inputs

These rows stay `blocked`, and none is widened to cover its input. The B-numbers are m02-plan §7.

| Input | Blocks (record: row) | Matrix rows |
|---|---|---|
| B1: a disposable 1Password account with disposable SSH keys, on a host where its agent may run | A11: "1Password live rows (every platform)"; A35: "1Password (every platform)" | M02-14, M02-15, M02-16 |
| B2: the disposable second Windows account (one elevation consent) | A01: "windows-11 ordinary ssh without -F (a real %USERPROFILE%\.ssh\config)" | M02-18 |
| B3: a disposable macOS standard user account (admin consent to create and delete it) | A01: "macos-arm64 ordinary ssh without -F (a real ~/.ssh/config)" | M02-17 |
| B4: a disposable Windows host whose system ssh-agent service may hold test keys | A11: "windows-11 system agent (\\.\pipe\openssh-ssh-agent), incl. its confirm-constrained row"; A35: "windows-11 system agent" | M02-13 |
| B5: an operator at the Windows console | A27: "windows-11 interactive console Ctrl-C and resize (conhost or Windows Terminal)". m02-plan §7 also assigns the no-UAC-prompt observation to B5; no record row carries it | none |
| B6: a hardware security key (FIDO2) | A11: "hardware-key touch-required row" | M02-21 |
| B7: the owner as participant | no mandatory wrapper: "the human participant walkthrough" | none |
| B9: a native Linux arm64 host | A01: "linux-arm64 native"; A35: "linux-arm64 native" | M02-20 |

- **B2 and B3 in A35.** m02-plan §7 says B2 and B3 block the "ordinary ssh without `-F`" rows of A01 **and A35**. The
  records carry those rows in A01 only; A35's `blocked_on` is B1, B4 and B9. No claim is widened by this, because
  A35's verified rows use a scratch `-F`. The difference between the plan and the records is the orchestrator's to
  confirm.
- **B8 does not apply.** It blocks nothing in the exit: the WSL disposable distribution covers Linux ordinary ssh
  without `-F` (m02-plan §7).
- **B10 is satisfied.** Developer Mode is on, read only (`windows/host.txt`). The file-symlink row it served is now
  the test `a22_windows_file_symlink_user_config_is_manual_mode`, which passed natively (section 6).

## 6. Limitations and residuals

**From `runs.json` `common_limitations`:**
1. **Status discipline** (m02-plan, M01 rule E15). A `verified` row means the required tests ran and passed on
   that platform in this run. It is not an independent review of the units.
2. **Linux binaries are cross-built** on the macOS host with zig (glibc floor 2.31) and run natively on the devbox.
   The one build-host-path test runs on the build host only.
3. **Windows ran in local mode**, by an agent on the PC, with no remote route into WSL. Its environment starts
   processes with Ctrl-C ignored, and the driver enables Ctrl-C processing for the heimdall it creates. An
   interactive console operator (B5) is still an owner input.
4. **Proptest regression files** resolve at compile-time source paths. The persisted regression seeds replay on
   macOS only; the fixed default seeds run everywhere.
5. **Every fixture is disposable.** The owners' keys, agents, `~/.ssh` and Git configuration are never test
   material.

**The gaps that held the `ce21a76f` record** (§12.46 item 4), and what the `e4f43f84` artifacts show now:

| Gap at `ce21a76f` | At `e4f43f84` (`windows/tests.txt` unless noted) |
|---|---|
| No Windows test connected a client to a server; no test ran `scp.exe` or `sftp.exe`; A35's Windows row was 19 model-level tests | **Closed.** `e2e_cli_m02` ran 26 tests on Windows, including 12 `ssh::` tests. 8 of them start the WSL fixture sshd through `Fix::build` (read from `tests/e2e/cli_m02.rs`). Among them, `ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound` connected the System32 `ssh.exe`, `scp.exe` and `sftp.exe`, then Git through the in-box client, then a run-bound `ssh` (byte-identical copies; only the adopted key accepted; the decoy agent never contacted). `e2e_run_m02` ran 42 tests, including `a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`, `a11::a27_git_clone_and_push_over_ssh_with_binary_blob`, `a11::a27_binary_stdin_stdout_roundtrip_through_ssh` and `a11::connect_reaches_the_fixture_sshd_through_the_verified_client`. A35's Windows row is 38 tests |
| R-SE-04 host-key substitution Unix-only; Windows row 5 tests | **Closed.** `ssh::host_key_substitution_fails_closed_and_nothing_written_to_known_hosts` passed; R-SE-04's Windows row is 8 of 8, with nothing excluded |
| `integration_projection`, `_git` and `_recovery_rows` had 0 Windows tests; the `ReplaceFileW` Git name transitions never ran | **Closed.** They ran 113, 44 and 1 tests, including `git_name_transitions_crash_at_every_point_reconciles`, `git_lock_occupied_by_holder_until_settlement` and `recovery_table_rows_each_have_a_test_vector`. `integration_projection_replace` ran 30, including `windows_replace_preserves_dacl` and `windows_replace_retains_displaced_identity_without_race` |
| The junction test `a22_windows_reparse_point_user_config_is_manual_mode` did not exist | **Closed.** It passed, and so did `a22_windows_file_symlink_user_config_is_manual_mode` (D7) |
| `sys::account_name` was `cfg(unix)` (§12.28 item 4) | **Closed.** `crates/localenv/src/sys/mod.rs` has a Windows `account_name`. `integration_doctor account_name_matches_inbox_ssh_g` passed: the token lookup equals the in-box client's `user` in `ssh -G`, with `USER` and `USERNAME` set to a wrong value. So did `doctor_reads_localuser_from_the_account_database` and the projection's `observe_reads_localuser_from_the_account_database` |
| No independent review covered the wave-6w product fixes | **Closed** by `wave6w.md` (section 4). Section 4 names what is still unreviewed |

**What the Windows rows still do not cover.** Every exclusion below has a case-index rationale:
- **Interactive pty cases, deferred to M04's pseudoconsole driver:**
  - the TUI pty cases (D2);
  - the interactive `connect` after provider approval (D3);
  - the personal profile without a repository (§12.49 item 4);
  - the typed-yes purge refusal, exit 6 (§12.49 item 2).

  The rest of `e2e_cli_m02::unix::` (3 in A21, 2 in A22) are pty cases, as are `e2e_run_m02::terminal::`. Their
  Windows rows are the JSON tests and `windows_launch`.
- **Unix process-model cases** (A27's 31 Windows exclusions): signal death, SIGPIPE, `--meta-fd`, `126`, process
  groups, the `heimdall_launch` `unix::` tests and the `resolve` `unix_*` tests.
- **The confirm-constrained and locked native-agent cases** (A11, A27). They drive a disposable OpenSSH `ssh-agent`;
  their Windows row is the system agent, blocked on B4 (§12.49 item 9).
- **`integration_doctor::a21_fifo_include_does_not_block`**: a Unix FIFO.
- **`a22_foreign_owner_or_unwritable_is_manual_mode`.** A foreign owner SID cannot be set at Medium integrity, so the
  Windows owner rule of §5.3 is not exercised natively in M02 (§12.51 item 5, a stated limitation).
- **`integration_projection_replace::race_symlink_substitution_at_boundary_is_held`** (Unix symlink). The Windows
  symlink and junction rows are their own tests (above).
- **The servers.** On Windows every transport test reaches Linux OpenSSH 9.6p1 in WSL scratch, which authenticates
  the WSL account. No Windows sshd is tested.
- **Git for Windows' transport.** Every Windows Git transport test sets `GIT_SSH_COMMAND` explicitly:
  - to the in-box client, in `a35_matrix` and `a27_git_clone`;
  - to P_git's rendered command, a copy of the in-box client under a spaced path run by Git's MSYS shell, in
    `integration_projection_git git_spaced_client_path_is_quoted_and_runs`. That test passed and recorded
    `spaced_client_local_quoting=passed`.

  No test relies on Git reading `core.sshCommand` from the Q7 include, or on the run-time `GIT_CONFIG_COUNT`
  injection, to carry a transport. The injection's precedence is tested with stub clients
  (`git_run_injection_yields_to_dash_c_and_env`). The bundled MSYS `ssh` carries no transport in any test.
- **Ordinary ssh without `-F`** against a real `%USERPROFILE%\.ssh\config` is B2.

**ADR residuals (§13 and the rulings):**
- **Projection concurrency.** Heimdall's `setup apply` projection has the unsupported concurrency cases of §5.9:
  - a write through a descriptor opened before the commit point;
  - the internal `ReplaceFileW` window (`[U]`; no test injects one);
  - filesystems without exchange (manual mode);
  - a same-user process writing into a quarantine directory;
  - identity reuse without a birth time.

  They are stated, not counted.
- **The default agent** is the `SSH_AUTH_SOCK` of whatever session runs `ssh`. Consent covers "the session's agent"
  (§12.16).
- **What the doctor can see** (§6). `executed_config_commands` is "constructs found before execution" and never
  complete. `config_tree_changed` compares two observed snapshots and cannot see a change reverted before the
  second.
- **An opaque `Include` is not read** (§12.36 item 2). That is one that needs `${VAR}`, or where the client's `%`
  behaviour is unknown. A `Match exec` inside it is not listed by file and line.
- **Endpoint `stat` and holder tokens.** An endpoint `stat` on a hung network filesystem cannot be interrupted
  (§12.23). A holder with no start-time token reads as exited when the same query succeeds for the runtime's own
  process (§12.24 item 5).
- **Evidence partials** (§12.30 item 13). The artifacts do not capture:
  - the A35 matrix's fingerprints and counts. The resolved executables appear only in the Windows log;
  - the offered-key check through `HM_FIXTURE_SSHD_LOG`;
  - the TUI's first-frame latency.
- **Intermittent test** (§12.49 item 5). `integration_adapters::prepared_facts_from_outcome_drop_interaction_fields`
  is intermittent on Windows. It passed in this run, and a recurrence reopens it as a defect.
- **Release criteria are not met by these rows alone** (plan §10.1). The blocked rows above carry into the go/no-go
  worksheet (plan §10.3).
- **Matrix labels.** The compatibility matrix labels stay `not-tested` (ADR-0001 §9).

**Artifact notes:**
- `wsl-distro/host.txt` records `wsl-version=WSL version: <addr>`. The redaction replaced the WSL version string, so
  the WSL version is not recorded.
- The same file holds a UTF-16 `wsl.exe` notice ("Sparse VHDs are currently experimental").

## 7. Deferred and handed on

**To M04** (ADR-0007 §12.47 item 3, §12.49 items 2 and 4). M04 adds the pseudoconsole driver for the TUI and for
`connect`, and runs these on Windows:
- the TUI pty cases `e2e_tui_m02::pty::search_never_probes` and `config_commands_authorization_requires_typed_yes`
  (D2; A21);
- the interactive `connect` after provider approval, `a11_interactive_connect_succeeds_after_provider_approval`
  (D3; A11 and A27);
- `ssh::a01_personal_profile_without_repository` (with D3; A01). It needs its own isolation, because `connect`'s
  in-box `ssh.exe` reads the token's real profile;
- the typed-yes purge refusal, exit 6, in the incomplete-rollback state (with D2 and D3; T06).

The non-interactive refusal, exit 3, ran natively (`json::uninstall_with_incomplete_rollback_purge_state_is_refused_json`).

**Also to M04, from m02-plan §8:**
- WSL Mode A executable, Git and path behaviour as a product path;
- the Mode B bridge;
- bastion `ProxyJump` in P;
- optionally, a client-stub mode in `hm-fixture-hook` to replace WU-5's test-only `.CRT$XCU` site (§12.49 item 8).

**To M03** (ADR-0007 §13):
- **The Git residuals** (§12.41):
  - a rollback after the owner moved B_git leaves the moved block;
  - an intact-shaped B_git whose include target was edited is not detected by the update arm;
  - a user value only in a conditional include is read conservatively.
- **The opaque-`Include` residual** (§12.36 item 2).
- **An extra candidate endpoint.** `agents::identity_agent_references` expands `Include` regardless of the client,
  so the doctor may list an extra candidate endpoint (§12.34 item 3).
- **The `state_dir` guard.** Refusing an edit when a writing `ProjectionConfig` has no `state_dir` (§12.34 item 6).
- **The unknown account** (§12.30 item 9). An unknown local account has no dedicated `UnresolvedReason`.
- **The default-agent consent residual** (§12.16).
- **From m02-plan §8:**
  - grants that mix existing-access and managed mechanisms (P6);
  - an adapter whose effect can land after its call was dropped at the timeout, and a timed-out immediate cleanup
    call kept and retried.

**To later milestones (m02-plan §8):**
- personal standing policies and first-trust disclosure (M05-T02);
- catalog export and import (M05);
- the final TUI information architecture (M07);
- fuzzing of `sshconf::parse_file`, `sshconf::gitedit` and `ipc::agent_client`, and support bundles (M08).

A native test that injects a replacement inside `ReplaceFileW` waits for an independently justified harness. The
claim stays `[U]`.

## 8. Next

M03: managed credentials and meaningful deadline behavior (plan §5 M03; `docs/architecture/m03-plan.md`;
ADR-0008). Its exit rule is ADR-0008 §17.3 item 6.

The compatibility matrix rows for this build are in `docs/compatibility/matrix.md`, section "M02 existing-access
rows".
