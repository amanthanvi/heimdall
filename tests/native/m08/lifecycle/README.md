# Lifecycle journey (M08 U2a)

Install, update, roll back and uninstall from release archives (m08-plan §7.2, A31 journeys
1–3 and 6; ADR-0014 §3 and §4.3). **Provisional, to be integrated.**

| File | What it does |
|---|---|
| `install-selftest.sh` | Tests `tools/packaging/install.sh` with fake archives: no real executable is used or run, so it is safe on any host. 45 checks (43 before W2.1), including the W0 review's cases (a failed backup, symlinks at staging names, an unterminated manifest, a runtime that does not answer, an interrupted rollback) |
| `journey.sh` | The journey itself. `--build release`: archives, run as a disposable account; it sets no test variable, refuses outside a container and refuses if any `HEIMDALL_TEST_*` is set; there is no override. `--build debug`: two debug executables, on a host; it exports and verifies all six scratch variables first, runs every `ssh` with `-F` on the scratch configuration behind a default-identity guard, and **skips every `heimdall connect` step** (see the incident below) |
| `install-selftest.ps1` | The Windows counterpart, for `install.ps1`: 85 checks (77 before W2.2, 71 before W2.1). Run on the Windows PC under Windows PowerShell 5.1 and PowerShell 7, with real junctions (see Runs) |
| `install-revert-proofs.ps1` | Takes one fix at a time out of a scratch copy of `install.ps1` (by its marker comments) and shows the self-test then fails in the expected cases. For the PC job |
| `run-journey.sh` | Starts `journey.sh --build release` in the M08 container (no network, 2 CPUs, 2 GiB, an init process) |

## Runs

| Date | Archives | Result |
|---|---|---|
| 2026-11-22 | **Older:** Linux arm64, `m08/w0` at `c1a398cd` (product code = `main` at `de097dac`; newest state migration `0008_trusted_work`), sha256 `eb557652…2941f`. **Newer:** Linux arm64, the `m08/w0` tree at `8f1295f4` plus the uncommitted U2a files (newest migration `0012_remote_lift_acks`), sha256 `f60f72df…0e71a`. Both built with `--allow-dirty` (the older side with the current packaging scripts copied in), so both are rehearsal builds | **26 steps ok, 0 failed.** The update crosses migrations `0009_remote`, `0010_remote_widening`, `0011_remote_client_endpoints` and `0012_remote_lift_acks` |

| 2026-11-22 | the same two archives, with `--kill-before-update` | **28 steps ok, 0 failed.** Before the kill: main database file 4,096 bytes, the destination absent from it and present in the 1,462,632-byte write-ahead log. The runtime was ended with `SIGKILL`; the files were unchanged. After the update: `state.db.v8.backup`, 532,480 bytes, integrity ok, schema 8, 7 rows naming the destination. **The pre-migration backup held the work done before the unclean stop** |

What the first run showed:
- Both archives matched the external index before unpacking; the install used the archive's
  own script and edited no shell profile.
- An update was refused while the runtime ran and named `heimdall service stop`.
- After the update: the environment ID was unchanged, a login and a `connect` worked, the
  session held open since before the update was still alive, and a pre-migration backup
  `state.db.v8.backup` existed.
- After a rollback to the older executable: it did not serve the newer store, the
  environment ID was never different, and after rolling forward again the newer build
  served the same identity and access. **The refused rollback changed nothing.**
- After uninstall: the user's `~/.ssh/config` (with `Include`, a wildcard `Host` and a
  `Match` block of its own) was byte-identical to before setup, and an unrelated alias's
  effective configuration was unchanged.

**Two product observations from it, for the contract owner** (both are already planned
deltas in ADR-0014 §7; this is the evidence for them):
- **The older build does not say why it will not start on a newer store.** `heimdall
  connect` answered `SERVICE_UNAVAILABLE`, no reason, "the runtime did not become ready in
  time"; `status` said "no runtime is running"; `doctor` exited OK. Nothing told the user
  that the state is newer than the executable (H4).
- **Uninstall's list of what remains named the SSH configuration backup and the state
  store, and not the migration backup `state.db.v8.backup` or `heimdall.previous`** (H6).

**What this run does not cover:** a restore or a reset (not built); a corrupt store; Windows
and macOS; the WSL helper pair; an update with managed credentials, a paired environment or
the transport in use; a native (non-container) account.

**A harness defect found on the way:** the first two runs reported leftover `heimdall`
processes. They were zombies: the container had no init process to reap the older build's
failed start attempts. Both launchers now pass `--init`.

## Debug-build journey on a host

| Date | Executables | Result |
|---|---|---|
| 2026-11-22 | one debug `heimdall` of the candidate tree (`064134a3` plus the uncommitted U2a files), macOS arm64 host, as both sides | **12 steps ok, 0 failed;** the two index steps, the three `connect` steps and the six update and rollback steps skipped (one executable). Install from a staged tree, setup on a scratch SSH home, the identity guard, a login, a held session, uninstall restoring the scratch configuration byte for byte, no process of the run left. **Mechanism evidence only** (a debug build on fixture stores) |

Not run yet: a debug journey with two different executables (it needs a debug build of an
older commit), and any run on Windows.

## Incident (2026-11-22): a debug `heimdall connect` on the host read the real SSH configuration

The first debug run included `heimdall connect <alias>`. For an existing-access
destination, `connect` starts the verified `ssh` with the alias as its only argument and no
`-F`; `HEIMDALL_TEST_SSH_HOME` redirects Heimdall's own static pass, not the `ssh` child. On
the host that `ssh` therefore read the account's real `~/.ssh/config`. The step failed, the
run happened once, nothing was written under the real `~/.ssh`, and `SSH_AUTH_SOCK` was the
scratch decoy agent. The step's output was not kept, so why `ssh` failed (most likely an
unresolvable name, which would mean one DNS lookup for it) and whether any wildcard block
of the real configuration applied to that name are **not known**. That run's results were
discarded. The driver now skips every `connect` step in a debug run and says why; `connect`
runs only in the release journey, which refuses outside a container. Reported to the
orchestrator the same hour.

## After the W0 review (W0.1, 2026-11-22/23)

| Run | Archives | Result |
|---|---|---|
| Release journey | the same two Linux arm64 builds, re-packed with the fixed `install.sh` and a fresh manifest and index (nothing recompiled): older `42a49389…`, newer `f6c72866…` | **30 steps ok, 0 failed** |
| Release journey, `--kill-before-update` | the same | **30 steps ok, 0 failed** |

New in these runs: seven shell profiles and `~/.ssh` exist before the install and are
unchanged after it; the runtime is signalled only by the PID it advertises, after checking
that the process belongs to the account and was started from the run's own executable.

**R01 revert proof** (`HM_INSTALL_UNDER_TEST=<install.sh with only the R01 fix taken out>
bash install-selftest.sh`): the case prints `exit 0, cur=heimdall 3.0.0, prev=heimdall 1.0.0`
and fails, the reviewer's result. With the fix: `exit 1, cur=heimdall 2.0.0, prev=heimdall
1.0.0`, and the case passes.

## After the scoped re-check (W0.2, 2026-11-23)

| Run | Result |
|---|---|
| `install-selftest.sh` (macOS) | PASS, 35 checks: adds a rollback interrupted before its replace, and a live process from the installed path refusing the update although the executable says none is running |
| Release journey and its `--kill-before-update` variant, in the container, archives re-packed with this `install.sh` (older `eb9328f1…`, newer `b1ff91b3…`) | **31 steps ok, 0 failed, each.** Three runtime PIDs were recorded in each run; none was alive at the end |
| `install-selftest.ps1` under PowerShell 7 **on macOS** | PASS, 43 checks. A rehearsal of the script's logic only |
| `install-revert-proofs.ps1` under PowerShell 7 **on macOS** | PASS. With the W01-R01 type check replaced by the candidate's recursive cleanup, the self-test fails 10 cases, the directory-at-`.heimdall.new.exe` case among them; with the W01-R02 pair check replaced by an executable-only check, it fails 3, the mixed-pair rerun among them |

The journey now signals and counts only PIDs it recorded from the runtime's own
advertisement, each checked with `ps -p <pid>` against the account and the run's executable.
The debug-build journey was rerun after this change, on the Mac (2026-11-23, tree `c3abefbf`):
`journey.sh --build debug` with the debug `heimdall` in `./target` as both `--old` and `--new`
(sha256 `3289a31d…`; the product crates are identical at `ec985922` and `c3abefbf`). Exit 0:
14 steps ok, 9 skipped (2 for no index, 1 for `connect`, 6 for one archive), one recorded
runtime PID, none left running. Mechanism evidence only: a debug build on fixture stores,
and no update or rollback, because one executable was used.

**Windows is the open evidence.** Nothing above shows how `install.ps1` behaves on NTFS:
renaming a mapped image, junctions and other reparse points, sharing violations, Windows
PowerShell 5.1. The PC job runs `install-selftest.ps1` and `install-revert-proofs.ps1`
under 5.1 and 7.

## W0.3 (2026-11-23): the orchestrator's read of `install.ps1`

- **Manifest names are validated in both installers** when the manifest is read, before any
  write: a plain relative path only (no empty, `.` or `..` segment, no backslash, no colon,
  no leading `/`, no control character). `install-selftest.sh`: 6 names refused, 41 checks
  in all. `install-selftest.ps1`: 7 names refused.
- **`install.ps1` never reads, checks or deletes through a link inside a helper directory:**
  every intermediate component must be a real directory (`Resolve-Under`). Case: a junction
  (a symbolic link on macOS) at `.linux-x86_64.new\sub` is refused and the file behind it
  survives. `install.sh` has no counterpart to fix: it manages one file and deletes inside
  no directory.
- **`Kind` stops the script on any error other than "not there",** so a path it cannot
  inspect is never treated as free. No test injects an access-denied error; that line is
  untested.
- `install-selftest.ps1`: PASS, 53 checks, and `install-revert-proofs.ps1`: PASS, both under
  PowerShell 7 **on macOS only**.

## Windows PC runs

| Run | Result |
|---|---|
| Job 31, at `a1bb1a69` (W0.2) | `install-selftest.ps1`: PASS, 43 checks, under Windows PowerShell 5.1 and PowerShell 7, with real junctions. `install-revert-proofs.ps1`: PASS under both. The same job ran the workspace tests (134 test binaries, 3328 passed, 0 failed, 39 ignored) and the six Python self-tests |
| Job 32, at `153bf6af` (W0.3), the installer files only | `install-selftest.ps1`: PASS, 53 checks, under both. `install-revert-proofs.ps1`: PASS under both: with the W01-R01 fix taken out 11 checks fail, with W01-R02 taken out 3 fail. Nothing was left in the temporary directories and no install directory was created in the account |
| Job 33, at `c3abefbf`: the Linux x86-64 archive in the existing WSL2 distribution, as files only | Archive sha256 and `verify_artifact --index`: PASS; the inner `heimdall` matches `3b90dfc9…`. Without running it: four NEEDED libraries, each found by `ldconfig -p`; highest symbol version `GLIBC_2.30` against the distribution's 2.39. `install-selftest.sh` 41 ok, 0 failed. `install.sh` install, repeat, update to a marked copy and `--rollback` with `--assume-stopped`: exit 0 each, with the expected digests. The distribution list was unchanged. Not a clean-machine row: the distribution is the owner's, not a fresh one |
| Job 40, at `5348551b`: the real Windows archive, as files only | `install.ps1` install, repeat, update to a marked copy and `-Rollback`, all with `-AssumeStopped`: exit 0 each. The update was executable-only (the marked copy changed `heimdall.exe` alone), and the rollback left the install without its helper: **finding M08-W1-F1**, fixed in `1ea93bf2` (below). `heimdall.exe` was never run |

Jobs 31 and 32 closed the paragraph above that calls Windows the open evidence, for the
self-test's cases. Jobs 40 and 43 installed a real Windows archive, built by
`build-release.ps1` on the PC, as files (its executable never run). The `Kind`
access-denied line stays untested.

## W1: finding M08-W1-F1 (PC job 40, 2026-11-23)

**The defect.** On the PC, `-Rollback` after an executable-only update (a new executable
whose helper bytes equal the installed helper's) left the install with no WSL helper, and
every step exited 0. The update moved only the half that differed: `heimdall.exe` went to
`.previous` and the helper stayed. The rollback then moved the current helper aside and had
no `.previous` helper to put back. The same rule left a mismatched `.previous` pair after an
earlier full update, and a helper-only repair discarded the older `.previous` helper.

**The fix in `install.ps1`** (the contract owner's ruling):
- **An update** (the executable is not this version) moves the whole current pair to the
  `.previous` names as one unit, discarding the older `.previous` pair first, and stages a
  complete new pair, the helper included even when its bytes match.
- **A repair** (the executable is this version, the helper is missing or different) replaces
  the helper in place and leaves `.previous` untouched.
- **`-Rollback`** refuses, changing nothing, unless `.previous` holds a complete pair. It
  names what is missing and says to install the older archive again.
- A directory the run will remove is checked first to hold only the script's own files.
- A stop between the two renames of step 3 is finished by the next run.

**`install.sh`: not applicable.** It manages one file, `heimdall`, and has no helper
directory, so it has no half-pair path (`tools/packaging/install.sh`: `cur`, `prev`, one
rename).

**Self-test,** seven cases (`W1-F1:` in `install-selftest.ps1`, 60 checks in all):
- an executable-only update keeps the whole old pair;
- that update, then a rollback, restores both halves (by digest);
- a helper-only repair leaves `.previous` byte-identical;
- after an earlier full update, an executable-only update leaves a matched `.previous`;
- a rollback with a missing `.previous` helper file, and with no `.previous` helper
  directory, refuses with every file unchanged;
- an update whose older `.previous` helper holds a foreign file refuses before any write.

The interrupted-rollback settle (`ra1` to `rc1`) and the interrupted update (after `1` to
`4b`) still pass with complete pairs.

**Revert proofs** (`install-revert-proofs.ps1`, under PowerShell 7 on macOS, 2026-11-23):

| Taken out | Failing cases |
|---|---|
| Rule 1: the `W1-F1` block replaced with the half-pair rule | 3: the executable-only update keeps the old pair; then a rollback restores it; the matched `.previous` after a full update |
| The rollback check: the `W1-F1-ROLLBACK` block removed | 2: the incomplete-pair and the missing-directory rollbacks |

These were rehearsals of the logic. **The evidence is PC job 43, at `3c8265c5` (2026-11-23):**

| Run | Result |
|---|---|
| `install-selftest.ps1`, Windows PowerShell 5.1 and PowerShell 7 | PASS, 60 checks each; every W1-F1 case `ok` |
| `install-revert-proofs.ps1`, both | PASS. Reverted, the self-test fails: W01-R01 11 cases, W01-R02 4 (the new repair case among them), W1-F1 3, W1-F1-ROLLBACK 2 |
| The real Windows archive of `3c8265c5`, installed as files, every call with `-AssumeStopped` | Install, then again ("already installed"). An executable-only update to a marked copy keeps the whole old pair under `.previous` (`027f22fe…` and `3b90dfc9…`); `-Rollback` brings both back. An update to a marked copy that changes both halves, then `-Rollback`, restores the original pair with the marked one under `.previous`. With `linux-x86_64.previous\heimdall` deleted, `-Rollback` exits 1 with `the previous pair is incomplete: missing linux-x86_64.previous/heimdall`, and no digest changes. No staging name is left after any step. `heimdall.exe` was never run |

**M08-W1-F1 is closed on Windows.**

## W2: the W1 review's installer findings (R04 to R07)

All four are fixed in one commit, so one PC job covers them.

| Finding | The fix | Test (`install-selftest.ps1` unless said) | Shown failing without the fix |
|---|---|---|---|
| **R04** (`install.ps1`): "finish an interrupted update" was decided from which files exist, so a lost `heimdall.exe` beside an older `.previous` executable without a helper paired that executable with the newer helper | Decided before the leftover cleanup, from the interrupted run's own evidence: its staged `.heimdall.new.exe` must be there | Two cases (`W2-R04:`): the rerun does not move the helper, and the `-Rollback` that follows refuses | Revert proof `W2-R04` (the old condition put back): both fail. **Reopened by the W2 review (M08-W2-R01):** a leftover staged file also stays after a run stopped at staging, so W2's evidence was not the run's own; see W2.1 |
| **R05**: a repair whose last rename fails said both halves were put back; the header and the runbook said a stop between renames 3a and 3b leaves the previous pair under `.previous` | A failed repair now says "the helper repair failed … the helper may now be missing. Run this script again"; the header, the rollback refusal and `docs/operations/update-and-rollback.md` say what the code does (the old helper may still be at the current name; rerun the same archive's script; `-Rollback` first settles an interrupted rollback) | Two cases (`W2-R05:`): the message, and the rerun that repairs | No revert proof (not blocking: a low message fix, ADR-0009 §2.3) |
| **R07**: step 2 re-checked only the staged executable's digest | Each staged helper file is hashed against the manifest before any rename (ADR-0014 §4.3 step 2) | One case (`W2-R07:`), with a test switch that alters a staged helper file | Revert proof `W2-R07` (the check removed): it fails |
| **R06** (W0 code; both installers): the live-process check compared path strings | `install.ps1`: both sides through `Resolve-Final` (full path, every link and junction resolved). `install.sh`: `[ word -ef "$cur" ]`, the same device and inode | `install.ps1`: four cases (`W2-R06:`), with process paths handed in: a relative `-Prefix`, a prefix through a link, a process started through a link, and an unrelated `heimdall.exe` that does not block. `install-selftest.sh`: two cases, with a real stand-in process: a relative `--prefix` and one through a symbolic link | The three positive `install.ps1` cases fail with the string comparison put back; both `install.sh` cases fail on the old `install.sh` |

**Stated limits of R06.** A process started through a subst drive letter or an 8.3 short name
(Windows), or through a relative path or by name from PATH (`install.sh`, which sees only
absolute paths on the command line), is not matched by the process check. It is then caught
only by the runtime query that follows, which `-AssumeStopped` / `--assume-stopped` skips.

**Rehearsed on macOS** (pwsh 7.7): `install-selftest.ps1` PASS, 69 checks; `install-revert-proofs.ps1`
PASS; `install-selftest.sh` PASS. The Windows evidence is the PC job that follows.

**The Windows evidence: PC job 47, at `3ca2f844` (2026-11-23).**

| Run | Result |
|---|---|
| `install-selftest.ps1`, Windows PowerShell 5.1 and PowerShell 7 | PASS, 69 checks each; every W2 line `ok` |
| `install-revert-proofs.ps1`, both | PASS. Reverted, the self-test fails: W01-R01 12, W01-R02 6, W1-F1 3, W1-F1 rollback 3, W2-R04 2, W2-R07 1 |
| The real archive of `3ca2f844`, as files, every call with `-AssumeStopped` | R04: no false finish and no `linux-x86_64.previous`; the rollback then refuses with "run that archive's install.ps1 again", nothing changed. R06: a relative prefix and a prefix through a junction both refuse while a copy of `PING.EXE` (loopback, no listener) runs as `heimdall.exe` ("a process started from"; "-AssumeStopped does not override this"); each PING process was stopped by its recorded PID after re-checking it, and the junction removed as a link. R07: altering a staged helper refuses ("the staged helper file heimdall does not match the manifest"), the pair unchanged, no staging name left. `heimdall.exe` was never run |

**R05 to R07 are closed on Windows. R04 is not:** the W2 review (M08-W2-R01) showed a first
install stopped after staging, over the same state, still read as an interrupted update. The
W2.1 fix and its Windows run follow.

**One message fixed after it (PC job 47's observation, low).** After an update whose `.previous`
held only an executable (no `linux-x86_64.previous`), the script still printed "the previous pair
is kept under the .previous names (install.ps1 -Rollback puts it back)"; the rollback correctly
refused that half pair. The message now says what `.previous` holds: the pair, or "an older
executable is kept as heimdall.previous.exe without its WSL helper; install.ps1 -Rollback will
refuse it". Two self-test cases (71 checks in all, PASS under pwsh 7 on macOS); the first fails
with the old message. It runs on Windows with the candidate's PC job.

## W2.1: the W2 review's installer findings (R01 and R04)

| Finding | The fix | Test | Shown failing without the fix |
|---|---|---|---|
| **R01** (`install.ps1`; reopens W2's R04): a leftover `.heimdall.new.exe` was read as an update interrupted between its renames, but a run stopped after staging leaves one too | An update writes the marker `.heimdall.updating` (the staged executable's digest) just before rename 3a and removes it after 4b, and on the rollback of a failed update. A rerun finishes an interrupted update only when the marker is there; the marker is then removed (W2.1 left one in place on the "already installed" path and through `-Rollback`: RC01, fixed in W2.2). A directory at the marker's name is refused like the other names. `install.sh` needs no change: there a leftover staged file is only removed and decides nothing | `install-selftest.ps1`, six cases (`W2.1-R01:`): over W2-R04's state, a run stopped at staging and its rerun is not finished as an update (no `linux-x86_64.previous`), and the `-Rollback` after it refuses; an update stopped after 3a leaves the marker and its rerun finishes and removes it; a directory at the marker's name is refused | Revert proof `W2-R04` now puts back W2's leftover-file rule: the reviewer's case fails |
| **R04** (`install.sh`): with the installed file moved or deleted, `-ef` had no file to compare, so a running process started from it no longer refused the install | The process's path is compared as a string too: as given, and with its directory resolved on both sides (`pwd -P`), alongside `-ef`. The resolution is done only for a word naming `heimdall`; a failed one never matches | `install-selftest.sh`, two cases (`W2-R04:`): the installed file moved away while the stand-in runs, through an absolute and a relative `--prefix` | Both fail with `-ef` alone (checked by hand on macOS; the reviewer's `curabs` alone fails the relative case there, because `/var` is a link to `/private/var`) |

**Rehearsed on macOS:** `install-selftest.ps1` PASS, 77 checks (pwsh 7); `install-selftest.sh`
PASS, 45 checks, with `sh` and with `dash`. The Windows evidence is the PC job at the W2.1 tip.

## W2.2: the re-check's installer finding (RC01)

| Finding | The fix | Test | Shown failing without the fix |
|---|---|---|---|
| **RC01** (`install.ps1`): the update marker could outlive its update. A run stopped after 4b left it; the "already installed" rerun exited before removing it, and `-Rollback` ignored it. So after a lost executable, a later rerun "finished" an update that had completed, pairing an older helper-less executable with the newer helper (the re-check's case C) | The marker is written only when rename 3b follows (there is a current helper to move). The "already installed" rerun removes a leftover marker, and says so, only after checking that the installed pair is complete and matches the archive's manifest. `-Rollback` refuses while a marker is present, says why, and changes nothing. Only the marker's presence is read; the digest it holds is for a person looking at it | `install-selftest.ps1`, eight cases (`W2.2-RC01:`): case C (a helper-less install, an update stopped after 4b leaves no marker, the rerun after a lost executable is not finished as an update, the rollback after it refuses); an ordinary update stopped after 4b keeps its marker, `-Rollback` refuses and changes nothing, the already-installed rerun removes the marker and says so, `-Rollback` then works; with the helper damaged, `-Rollback` still refuses on the marker | Revert proof `W2-RC01` (all three changes taken out): six of the eight cases fail, case C's rerun and rollback among them (the two that pass are the ones that hold without the fix) |

**Rehearsed on macOS** (pwsh 7): `install-selftest.ps1` PASS, 85 checks; `install-revert-proofs.ps1`
PASS, run to its closing line (every revert fails its own cases). The Windows evidence is the PC
job at the W2 candidate.
