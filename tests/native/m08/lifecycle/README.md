# Lifecycle journey (M08 U2a)

Install, update, roll back and uninstall from release archives (m08-plan §7.2, A31 journeys
1–3 and 6; ADR-0014 §3 and §4.3). **Provisional, to be integrated.**

| File | What it does |
|---|---|
| `install-selftest.sh` | Tests `tools/packaging/install.sh` with fake archives: no real executable is used or run, so it is safe on any host. 41 checks, including the W0 review's cases (a failed backup, symlinks at staging names, an unterminated manifest, a runtime that does not answer, an interrupted rollback) |
| `journey.sh` | The journey itself. `--build release`: archives, run as a disposable account; it sets no test variable, refuses outside a container and refuses if any `HEIMDALL_TEST_*` is set; there is no override. `--build debug`: two debug executables, on a host; it exports and verifies all six scratch variables first, runs every `ssh` with `-F` on the scratch configuration behind a default-identity guard, and **skips every `heimdall connect` step** (see the incident below) |
| `install-selftest.ps1` | The Windows counterpart, for `install.ps1`: 53 checks. Run on the Windows PC under Windows PowerShell 5.1 and PowerShell 7, with real junctions (see Runs) |
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

These close the paragraph above that calls Windows the open evidence, for the self-test's
cases. They do not show an install of a real Windows archive: `build-release.ps1` has never
been run, so no Windows archive exists. The `Kind` access-denied line stays untested.

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
