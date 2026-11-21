# M04 exit record (draft) — platform realization: native Windows, WSL, containers and bastions

**Date:** 2026-11-20 · **Build:** `50dbc86b` (the exit commit: `m04/u7` with main `ce5b0dc2`, M05's exit
and M03-F1, merged); the Mode B harness run at `06784973` (harness files only after `50dbc86b`) ·
**Status:** draft for the orchestrator's exit decision (ADR-0004).

**Result:** every platform row of every M04 record is `verified` on macOS arm64, Linux x86-64 (the devbox),
Windows 11 x64 (the full harness) and the PC's WSL rows (Mode B, containers, systemd login), except rows
blocked only on named owner inputs (B1–B5, B8, B9, B11, B12) and the A03 Mode B lock row, blocked on the
owner's idle window. A27 and the honest-limits record are `verified` outright.

**The rule** (M01–M03, M05; m04-plan §3): every record is `verified`, except rows blocked only on named
owner inputs; those rows stay `blocked` with `blocked_on`, and no claim is widened to cover them. A
`deferred_with_decision` row cites its ruling and does not count (`tests/evidence/README.md`).

**Build identity.**
- **Commits:** `50dbc86b29df42b052071eae040bc074d148e81e` (every run but Mode B) and
  `06784973037b95fd9b31c5d5c2963e4ac444f58e` (the Mode B harness run). `088f6789` and `06784973` changed
  `tests/native/m04/run-mode-b-windows.ps1` only, so `crates/`, the sources digest and the Linux binaries are
  the same.
- **Sources digest:** `sources_sha256` `8cc0740b7cafefdabd8840258f4664e2fd62bd9bcdd3382f1fc98083d672edd2` in
  `tests/native/m04/required-inventory.json`, regenerated at this commit with `refresh-inventory.sh` (the
  Linux and Windows scans); `tests/native/m02/required-inventory.json` was regenerated there too.
- **Artifacts:** `tests/evidence/artifacts/m04/exit-50dbc86b/` (`runs.json`, `digests.txt`,
  `case-summary.json`); the artifact digest is the sha256 of `digests.txt`, `db5b514d25ac2df5…` (the full
  value is in `runs.json` and every record; `digests.txt` lists 79 files, the superseded and failed Mode B
  attempts included).
- **Linux binaries the PC runs used** (cross-built on the build host at the exit commit,
  `prebuilt-linux/build.txt` and `commands.txt`): `heimdall` `cbf82081684ed4b5…`, `e2e_platform_m04`
  `b9a0330ade05049f…`, `hm-fixture-hook` `a2bd888b7a76589f…` (`prebuilt-linux/sha256.txt` has the full values).

## 1. Exit evidence (plan §5 M04; m04-plan §3)

| Exit claim | Record | macOS | devbox | Windows (full) | Mode B | containers | systemd login | lock | Rows not verified |
|---|---|---|---|---|---|---|---|---|---|
| **A12**, WSL Mode A (R-EN-02) | `m04-a12-wsl-mode-a.json` (blocked) | verified | verified | verified | verified | n/a | n/a | n/a | blocked: B2, B5 |
| **A13**, WSL Mode B (R-EN-03) | `m04-a13-wsl-mode-b.json` (blocked) | verified | verified | n/a | verified | n/a | n/a | n/a | blocked: B2 |
| **A14**, the native Windows endpoint (R-EN-01, R-SS-03) | `m04-a14-windows-native.json` (blocked) | n/a | n/a | verified | n/a | n/a | n/a | n/a | blocked: B1, B2, B4, B5 |
| **A15**, containers, bastion routes, forwarding (R-EN-06, R-SS-06) | `m04-a15-containers-bastion.json` (blocked) | verified | verified | verified | n/a | verified | n/a | n/a | blocked: B3, B8, B9, B11 |
| **A03** (applicable), Mode B under the Windows lock | `m04-a03-mode-b-lock.json` (blocked) | n/a | n/a | n/a | n/a | n/a | n/a | blocked | blocked: B11, the owner's idle window (A03 Mode B lock) |
| **A08** (applicable), restart and the login entry | `m04-a08-login-entry.json` (blocked) | verified | verified | verified | n/a | n/a | verified | n/a | blocked: B2, B3, B12 |
| **A27** (applicable), byte integrity | `m04-a27-byte-integrity.json` (verified) | verified | verified | n/a | verified | n/a | n/a | n/a | — |
| **A31** (applicable), setup and uninstall of every M04 integration | `m04-a31-setup-uninstall.json` (blocked) | verified | verified | verified | verified | verified | verified | n/a | blocked: B12 |
| Honest limits (plan §5 M04) | `m04-honest-limits.json` (verified) | verified | verified | verified | n/a | n/a | n/a | n/a | — |
| All of the above | `m04-exit-claims.json` (blocked) | verified | verified | verified | verified | verified | verified | blocked | blocked: B1, B2, B3, B4, B5, B8, B9, B11, B12, the owner's idle window (A03 Mode B lock) |

"n/a" means the record declares no row on that platform. **What proves each claim:** the case index
(`tests/native/m04/case-index.json`) is authoritative; the platform rows name every required test, and each
record lists them with their results and the `m04 observation:` lines of the passed tests (the A12 interrupt,
the A15 engines, user-namespace maps and refused users).

## 2. Native runs at the exit build

Observed in the run's artifacts (`tests/evidence/artifacts/m04/exit-50dbc86b/`):
- **macOS arm64** (the build host): `tests/native/m04/run-macos.sh` exit 0. `check.sh`: all 13 steps exit
  0; 3470 passed, 0 failed, 199 ignored. The observation pass (`e2e_platform_m04`, `e2e_route_m04`): 17
  passed, 0 failed (no M04 test prints an observation line on macOS; M04's come from the Windows and WSL
  rows). Canary count 0. macOS 27.2.1, OpenSSH 10.5p1, Apple Git 2.54.0.
- **Linux x86-64, the devbox** (cross-built with zig): `tests/native/m04/run-linux.sh` in five batches
  covering 112 test binaries (every binary in one batch), each batch exit 0: 3440 passed, 0 failed, 204
  ignored; each batch's scratch directory removed and checked absent; canary count 0. Linux 6.8.0-147,
  glibc 2.39, OpenSSH 9.6p1, git 2.43.0.
- **Windows 11 x64, the full harness** (the PC, 10.0.26300.9974, Medium integrity, BelowNormal; built and run
  natively at the exit commit): `tests/native/m04/run-windows-local.ps1` (the M02 runner, `-Milestone m04`) exit 0
  in 1967 s: 111 test binaries, 2907 passed, 0 failed, 38 ignored; the console-window and issuer-hello rows pass;
  canary count 0. In-box `ssh.exe` OpenSSH_for_Windows 9.5p2, Git for Windows 2.55.0. Imported as `windows/`.
- **WSL Mode B harness, the default plan** (`tests/native/m04/run-mode-b-windows.ps1 -Scenario mode-b`, two
  disposable distributions, WSL 3.0.5.0), at `06784973`: exit 0 in 1055 s; `a13-mode-b` 12 passed, `a12-mode-a` 2,
  `a12-flow` 1 (with its interrupt observation), the helper session, `a31-uninstall` and `a13-unregister` passed;
  every recorded command exit 0; the harness sshd reached on its first try; the sshd logs read on the WSL file
  system; nothing left alive at the end; canary and leak counts 0; the registered set unchanged. Imported as
  `windows-modeb/`. Two earlier attempts are kept on record, not counted:
  at `50dbc86b` four rows read an empty sshd log (`windows-modeb-50dbc86b-failed/`: the harness still exported the
  drvfs log path after M05 W4 moved the fixture logs onto the WSL file system; fixed at `088f6789`), and at
  `088f6789` every row passed but the harness recorded its recovered sshd retry as a failed command
  (`windows-modeb-088f6789-superseded/`; fixed at `06784973`, harness files only).
- **Containers** (`-Scenario containers`, one disposable distribution): exit 0. Podman 4.9.3 rootless and Docker
  Engine 29.1.3 rootful, each 2 passed, 0 failed (`a15_container_mounted_flow`,
  `a31_uninstall_with_a_live_container_binding`); the fixture image built from `alpine:3.21` by digest; only the
  recorded containers and images removed, the recorded `dockerd` stopped; canary count 0. Imported as
  `wsl-containers/`. At the original deadline the refused login now reads "Can't open user config file
  /run/heimdall/ssh_config" (it read "Permission denied (publickey)" before the main merge): M05 W4's ruling I-26
  ends a grant at its deadline at once, so the binding's files are withdrawn by deadline + 3 s and the client
  refuses before reaching the server; the binding ends, then its files go, as intended.
- **systemd login** (`-Scenario systemd-login`, one disposable distribution with systemd): exit 0, `systemd=running`,
  1 passed, 0 failed. Imported as `wsl-login/`.
- **The A03 Mode B lock row** (`-Scenario lock`): not run at the exit commit. Blocked on its exact input:
  the owner away, so the PC's console sits idle for 15 minutes, then the owner unlocks it (ADR-0004 §2).
  A later records commit adds the row, as M03's macOS lock row was added.

## 3. Rows this exit closes for M05 (m05-plan Q9)

M05's records keep four rows `deferred_with_decision` to M04's exit. The shared evidence generator has no
cross-record row (a case-index row is copied verbatim and the referenced record's status is not read), so
M05's records are unchanged and the mapping is recorded here, in `docs/architecture/m05-exit.md` §6 and in
the matrix (the M03 claims precedent):

| M05 row | Closed by (M04 record and row) |
|---|---|
| A16, the WSL pair | `m04-a13-wsl-mode-b.json`, the windows-modeb row (the Mode B environment beside the native one in the real runtime) |
| A16, the container pair | `m04-a15-containers-bastion.json`, the wsl-containers row; and M05's A16 tests adapted at M04's MC5 (one binding per container environment, ADR-0010 §4 item 3) |
| A28, the forwarding row (M04-T06) | `m04-a15-containers-bastion.json`, the route rows `a15_forwarded_endpoint_bounded_to_binding`, `a15_user_dash_a_refused_without_capability`, `a15_non_jump_pair_cannot_open_forwarding` |
| A28, the container row (M04-T05, owner functions) | `m04-a15-containers-bastion.json`, the wsl-containers row: `container::a15_container_mounted_flow` (the endpoint lists only the binding's identity; a control-protocol hello on `agent.sock` fails) |

## 4. Known limitations and residuals

- **Mode B and ordinary `ssh`:** plain `ssh <alias>` inside a Mode B distribution needs `ssh -F` or
  `GIT_SSH_COMMAND`; there is no `~/.ssh/config` projection inside the distribution (ruling I-11).
- **Mode B run base:** a base with a group-writable ancestor or a non-root symlink is refused (W2 R01,
  RC01): set `XDG_RUNTIME_DIR`. WSLg's `XDG_RUNTIME_DIR` (`/mnt/wslg/runtime-dir`, 0777, not sticky) makes
  Mode B use the home base (platform fact at `56ec9a9e`). A missing home base's deepest existing directory
  must be the account's own (MC3 R02).
- **Mode B residuals:** the background relaunch can still start a distribution that stops between its final
  pre-launch listing and `wsl.exe`'s start (W2 R03 ruling); in-distribution leftovers of a stopped
  distribution are kept only for the runtime's lifetime (ADR-0010 §10); a re-issue at a higher generation
  fails closed; the helper does not enforce the deadline (the Windows-side signer does);
  `Bridge::drop` waits up to 2 s; the `wsl.exe -u` residual (a Linux user who can use interop can become
  the endpoint's owner, ADR-0010 §3 non-claims).
- **Mode A:** the A12 flow row gives `ssh.exe` the test world's scratch configuration with `-F` (Windows
  paths only, ADR-0010 §2 item 3); ordinary `ssh.exe` without `-F` needs the disposable second Windows
  account (B2). `scp.exe`/`sftp.exe` with Linux local paths are reported unsupported.
- **Containers:** one binding per container environment (ADR-0010 §4 item 3); a container environment's
  stable directory is removed by `uninstall --purge-state`, not by a plain uninstall. Docker Desktop,
  devcontainers and WSL-nested containers stay `not-tested` by decision; the native Linux product container
  host row is blocked (B11).
- **Routes:** routed enrollment evidence lapses at `fresh_until` unless verified while reached directly
  (M06-T03); an existing-access jump has no approved key (ruling I-12, M06-T03); no per-pair route status
  (M07-T03); the macOS forwarded-agent row needs an sshd below 10.1 or a scratch account (B3); the PC's
  harness sshd has no forwarding settings, so the Windows route rows other than the rule row are not run.
- **Login entry:** the WSL systemd row uses the test-configured build with the debug-build home guard's
  opt-in inside the disposable account (ruling I-15); real logout, reboot and sleep stay blocked (B12); the
  Windows login entry may flash a console at login (residual).
- **Windows:** a sandboxed Windows profile makes a pre-M04 state directory `state_dir_unsafe` (platform
  fact); the PC is not a clean install (recorded as such).
- **Test fixture under WSL NAT:** WSL's localhost relay sometimes never forwards the harness sshd's port to
  Windows (the sshd alive and listening inside the distribution, every attempt from Windows refused; seen in four
  Mode B runs, two of them in a row at the exit). Not a product issue. The Mode B harness's bounded mitigation
  restarts the sshd once on a new port in exactly that case and records both tries as facts
  (`fixture-sshd-tries`, `fixture-sshd-try1*`).

## 5. Open after the exit

- The A03 Mode B lock row (the owner's idle window), added by a later records commit.
- The claims update (ruling I-28), a separate commit after this one: **no new claim entries.** No M04
  record runs a claimed field's tests on a new platform, OS release, client or build, and M04's WSL rows
  are `wsl` hosts. The update fixes an over-claim instead: the claim table's entries hold only for
  bindings with a native endpoint, the kind their records ran, so a WSL Mode B or container binding reads
  every claim-table field `unknown`, with an `endpoint_kind_not_covered` reason naming its kind
  (ADR-0008 D12 item 2).
