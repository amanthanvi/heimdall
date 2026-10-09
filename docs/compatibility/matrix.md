# Compatibility matrix

**Matrix version:** 1 · **Updated:** 2026-10-09 (M00-T02-fix2) · v0: M00-T06, commit 18bb8df, 2026-10-02

This file is the baseline/support-matrix output of M00-T02 (plan.md M00-T02: "construct the baseline/support
matrix") and the matrix deliverable of G01 (plan §3). M00-T06 created v0. M00-T02-fix2 refreshed it to v1: every row
now names the pins it relies on and the evidence records that now exist, including the native Windows 11 and WSL2 runs
of 2026-10-06. The delegation is recorded in ADR-0003 ("Support matrix") and `docs/sources/README.md`.

Each row carries three separate statuses:

- **Label**: the spec §3.3 product-support label (`verified`, `supported-with-limitations`, `experimental`,
  `unsupported`, `not-tested`). Every row is `not-tested`. No Heimdall build exists, and ADR-0001 §9 keeps every
  platform at `not-tested` until ADR-0001 §5 (floors) and §6 (baseline worksheet) close. A row changes from
  `not-tested` only with a cited evidence record in `tests/evidence/` that tests Heimdall itself. Compilation,
  detection of an executable, container emulation, a gate probe and a prototype run never upgrade a label.
- **Gate evidence**: the plan §1.4 status (`not_started`, `in_progress`, `blocked`, `implemented_unverified`,
  `verified`, `deferred_with_decision`) of the gate and fixture records that exercise the row's mechanism. It
  describes the evidence, not product support, and follows the gate-probe convention in `tests/evidence/README.md`:
  `verified` means the probe ran as designed and its output is preserved, whatever the verdict. Each record keeps
  its own top-level status. The multi-row rule says that status is the record's lowest row status (order in
  `tests/evidence/README.md`); `m00-t03-fixtures.json` is coarser: it is `in_progress` by design. A row takes the lowest-standing status among the records and
  sub-rows it relies on:
  - `blocked` if any cited record or needed sub-row is `blocked`, or cannot run without a missing platform, host,
    operator or authorization; the missing input is named;
  - otherwise `in_progress` if any cited record is `in_progress`;
  - `verified` only if every cited record is `verified`;
  - with no record: `blocked` when a documented input is missing, `not_started` otherwise.
- **G01 floor**: the supported OS and SSH/provider version floor. Every floor is `blocked` until G01 clean-machine
  tests choose it (ADR-0001 §5). Versions listed below are observations with a date, never floors.

Pin references:
- `Sxx` and `Axx` are in `docs/sources/pins.json` (spec section 19 sources and auxiliary sources).
- `G03-Sxx` are in `tests/evidence/artifacts/g03/sources/source-pins.json`.
- `cand.<name>` is `pins.json` `candidates.<name>`.
- `tag:` is `pins.json` `tag_pins`, where each tag is resolved to a commit.

## Provider × client × environment × mechanism

| # | Environment | Client | Provider / signer | Mechanism | Label | Gate evidence | G01 floor | Pins |
|---|---|---|---|---|---|---|---|---|
| 1 | macOS arm64 | OpenSSH ssh / git / scp / sftp | native ssh-agent | existing identity, ordinary alias | not-tested | blocked | blocked | S01, S02, S10, S30 |
| 2 | macOS arm64 | OpenSSH | 1Password SSH agent | existing external signer | not-tested | blocked | blocked | S06, S07, S09, S01 |
| 3 | macOS arm64 | OpenSSH | Heimdall managed recipe (G04) | managed execution credential | not-tested | blocked | blocked | S03, S04, S05, S10, S11, S30; cand.smallstep; tag: step-ca v0.30.2, step CLI v0.31.0 |
| 4 | Linux x86-64 / arm64 | OpenSSH | native ssh-agent | existing identity | not-tested | blocked | blocked | S01, S02, S30 |
| 5 | Linux x86-64 / arm64 | OpenSSH | 1Password SSH agent | existing external signer | not-tested | blocked | blocked | S06, S07 |
| 6 | Linux x86-64 / arm64 | OpenSSH | Heimdall managed recipe | managed execution credential | not-tested | blocked | blocked | S03, S04, S05, S10, S11, S30; cand.smallstep |
| 7 | Windows x86-64 | Win32-OpenSSH ssh.exe (inbox build; GitHub MSI) | Windows OpenSSH agent service | existing identity, named pipe | not-tested | blocked | blocked | S13, S01, S30; G03-S01, G03-S02, G03-S03, G03-S05, G03-S07, G03-S08, G03-S09, G03-S10; cand.win32_openssh; tag: 10.0.0.0p2-Preview, openssh-portable v10.0.0.0 |
| 8 | Windows x86-64 | Win32-OpenSSH | 1Password SSH agent (pipe) | existing external signer | not-tested | blocked | blocked | S06, S07; G03-S12 |
| 9 | Windows x86-64 | Win32-OpenSSH | Heimdall managed recipe | managed execution credential | not-tested | blocked | blocked | S04, S05, S10, S13; G03-S07; cand.smallstep |
| 10 | WSL2 Mode A | Windows ssh.exe from WSL, Git | Windows-side provider | Windows SSH authority | not-tested | blocked | blocked | S12, S13; G03-S12, G03-S13, G03-S15, G03-S16; cand.win32_openssh |
| 11 | WSL2 Mode B | Linux OpenSSH in WSL | scoped bridge to selected upstream | Linux-native scoped endpoint | not-tested | blocked | blocked | S03, S30; G03-S15, G03-S16, G03-S17, G03-S18 |
| 12 | Local Linux container | OpenSSH in container | scoped bound endpoint | container binding | not-tested | not_started | blocked | none pinned for this row |
| 13 | Remote Linux runner | OpenSSH | runner-held managed credential | controller-independent runner | not-tested | blocked | blocked | S16, S17, S18, S34 |
| 14 | any | OpenSSH via ProxyJump | any | bastion route | not-tested | blocked | blocked | S01, S02 |
| 15 | any | OpenSSH via ProxyCommand | Iroh/Pigeons | optional transport | not-tested | not_started | blocked | S14, S15, S19, S20, S21, S22, A01, A02, A03, A04; cand.iroh, cand.pigeons; tag: iroh v1.3.0, iroh-ffi v1.1.0, pigeons v0.2.1 |
| 16 | Windows x86-64 | Git for Windows (bundled MSYS ssh, or `core.sshCommand` to Win32-OpenSSH) | Windows named-pipe agent | existing identity | not-tested | blocked | blocked | G03-S06, G03-S12, G03-S13, G03-S14 |

Row 16 is new in v1. In v0, row 7 covered "Win32-OpenSSH ssh.exe / Git for Windows". The G03 runs showed that Git's
bundled MSYS ssh behaves differently from Win32-OpenSSH (observations W2, W3), so it has its own row.

### Row notes

Records are in `tests/evidence/`; the observation ids (W, L, M) refer to the tables below.

1. **Evidence:** `m00-t03-fixtures.json` (`in_progress`; its rows 1–5 are `verified` per fixture; fixture readiness
   only). It ran the macOS host client against containerized `sshd` fixtures with identity files, aliases from a
   fixture `ssh_config`, and `IdentityAgent none`, so it does not exercise ssh-agent. The macOS ssh-agent mechanics
   with a disposable key and certificate are in M2 (row 3). No record exercises the native agent with an existing
   identity. **Blocked on:** the G01 baseline with the owner's real configuration (ADR-0001 §6, `blocked` on the
   owner's pain-point list and baseline machine set). **Observed:** macOS 27.0 (26A428) arm64, client OpenSSH_10.3p1
   with LibreSSL 3.3.6; fixture server OpenSSH_10.0p2 Debian 13; 2026-10-03.
2. **Evidence:** none. **Blocked on:** an owner-authorized disposable 1Password account and vault with disposable keys
   (ADR-0001 §5). Provider lock and approval behavior governs (spec §7.1; S06, S07).
3. **Evidence:** `g04-exp-*` E1–E6 and the enroll-marker record (`verified`/pass, mechanism level, M2). G09-prelim
   multiplexing records (M3). macOS lock-probe smoke records (5 `verified`/pass, 2 `in_progress`; not
   human-driven, M4). **Blocked on:**
   - an owner-driven screen lock, logout, reboot and sleep
     (`g04-macos-{screen-lock,logout,reboot-headless,sleep}-probe.json`);
   - an Apple Developer signing identity and provisioning profile for a test bundle, plus an owner-driven screen
     lock/unlock cycle (`g04-macos-data-protection-keychain-probe.json`);
   - for `g04-macos-secure-enclave-ctk-probe.json` (commit 34ffe3e): `blocked`, verdict `fail`. One unlocked run on
     2026-10-09 under owner decision G04 D4. The identity loaded only through `ssh-add -K -S` and signed. Its fixture
     login was not measured (probe v1 defect), and `KEYCHAIN_CERTIFICATES` did not limit which identities that path
     loads (the clause that fails). Blocked on an owner-driven screen lock/unlock cycle; the fixed probe v3 has not
     yet run on the real store.

   The recipe is not selected (G04 B1 pending).
4. **Evidence:** none on a native Linux host. **Blocked on:** native Linux x86-64 and arm64 desktop/user-session and
   headless hosts (ADR-0001 §5). WSL2 Ubuntu (rows 10, 11) and the Docker Desktop linux/arm64 VM (fixtures, G02
   linux-arm64) are not Linux hosts for this row.
5. **Evidence:** none. **Blocked on:** a native Linux host plus a disposable 1Password account and vault (ADR-0001 §5).
6. **Evidence:** the G04 experiments exercised Linux `sshd` only as containerized servers (M2). **Blocked on:** a Linux
   desktop host with a graphical session and an owner to lock and unlock it (`g04-linux-desktop-lock-probe.json`), and
   Linux desktop and headless hosts where the owner can log out and reboot
   (`g04-linux-logout-reboot-headless-probe.json`).
7. **Evidence:** native Windows 11 run of 2026-10-06 (W1–W12; W4 belongs to row 16 and W11 to row 8). `verified`:
   W1, W2, W3, W7, W8, W9. `blocked`: W5 (its same-user rows are verified; the cross-user pre-squat sub-row needs
   a second account), W6 (Ctrl-C/resize need an interactive console operator), W10 (a second disposable non-admin
   Windows account), W12 (a disposable host whose agent store may be mutated, with
   `-AllowSystemAgentMutation -IAmOnADisposableHost`). The owner's agent on `\\.\pipe\openssh-ssh-agent` was never
   contacted; every probe used fixture pipes. **Observed:** Windows 11 Pro build 26300.9550 x86-64, non-elevated.
   Inbox `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` (file 9.5.6.3); GitHub MSI
   `OpenSSH_for_Windows_10.0p2 Win32-OpenSSH-GitHub, LibreSSL 3.8.2` (file 10.0.0.0, first on PATH, runs the
   ssh-agent and sshd services). The G04 Windows lock records (`g04-windows-desktop-lock-probe.json`,
   `g04-windows-signout-reboot-probe.json`) stay `blocked`. **Open owner item:** E6 (ADR-0003): whether the
   Preview-only Win32-OpenSSH release line, alongside the inbox build, can be a supported baseline.
8. **Evidence:** `g03-win-1password-coexistence.json` (`blocked`). **Blocked on:** 1Password for Windows signed in to
   a disposable account with a disposable key, on a disposable host, plus owner authorization
   (`-AllowProviderContact`); admin for the service sub-probe. On the owner PC a 1Password process runs under the
   owner account. Which process serves `\\.\pipe\openssh-ssh-agent` was not determined.
9. **Evidence:** G02 X4 Windows spike: named-pipe checks pass. DPAPI, CNG and TPM are blocked on owner authorization
   or a disposable account or host (`tests/evidence/artifacts/g02-r4/x1/RESULTS.md` §3; no evidence record).
   **Blocked on:** `g04-windows-desktop-lock-probe.json` and `g04-windows-signout-reboot-probe.json`, both `blocked`.
   Their `blocked_on` text says no Windows host is available; that text predates 2026-10-06, and an owner-driven
   lock, sign-out and reboot is still needed. The recipe is not selected.
10. **Evidence:** WSL run of 2026-10-06 (L1–L7). `verified`: L1–L6. `in_progress`: L7. **Blocked on:**
    - an operator watching the Windows console for the UAC-prompt attestation of P-A06 (L7; progress.md lists
      "P-A06 UAC" among the inputs that need an operator at the console);
    - a host where `\\.\pipe\openssh-ssh-agent` is absent, for the P-A01 unset-variable sub-row. That sub-row was
      skipped by design because the owner's default pipe exists.

    The Windows-side provider was a fixture agent served by pwsh; the 1Password (row 8) and agent-service (row 7)
    providers were not exercised from WSL. **Observed:** WSL 3.0.1.0, Ubuntu 24.04.5, kernel 6.18.40.1, NAT
    networking, `appendWindowsPath = false`; Windows `ssh.exe` 9.5p2 (run r2, all probes). 10.0p2 was used in run
    r3-msi10 for the five Mode A probes P-A01–P-A05, with the same status and criteria. Linux git 2.43.0.
11. **Evidence:** WSL run of 2026-10-06 (L8–L13). `verified`: L9–L12. `in_progress`: L8 (other-Linux-user rows need
    a second Linux account with `sudo -n`). `blocked` (L13): P-B07 host lock (an operator to lock and unlock the
    Windows session); P-B08, P-B09 and P-B10 (a disposable second WSL2 distribution, plus owner authorization to
    create it and run `wsl --terminate`); P-B11 (a second Windows account and a disposable distribution).
    **Observed:** Linux `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19`; the relay used Windows PowerShell 5.1 (L11).
12. **Evidence:** none. M00-T03 fixture row 17 (local container bound to scoped access) is `not_started`. Docker
    Desktop variants are labelled separately (spec §8.5).
13. **Evidence:** none. **Blocked on:** a native headless Linux host (ADR-0001 §5;
    `g04-linux-logout-reboot-headless-probe.json` is `blocked` on Linux desktop and headless hosts). The runner
    itself is not built: M00-T03 fixture row 15 (paired runner) is `not_started`, and the runner belongs to G07.
14. **Evidence:** `m00-t03-fixtures.json` row 4, the ProxyJump portion only (`verified` per fixture; record
    `in_progress`): ProxyJump works with ForwardAgent off and the target sees no agent. That was a macOS client
    only. Bastion-hop host-key substitution and the forwarding recipe were not tested. **Blocked on:** native Linux
    hosts (ADR-0001 §5). ProxyJump from Windows and WSL clients was not run. **Observed:** macOS client 10.3p1
    against container `sshd` 10.0p2, 2026-10-03.
15. **Evidence:** none. M00-T03 fixture row 18 (Iroh) is `not_started`. G06-gated and opt-in. Vendor platform
    statements: A01–A04. ProxyCommand integration and Pigeons behaviors: S19.
16. **Evidence:** W2 and W3 (`verified`). Git's bundled MSYS `ssh` reached no Windows named pipe in any form.
    MSYS `ssh-add` opened the pipe as a file (the fixture logged a connection) but sent no agent request, so it
    cannot use the pipe as an agent. W4 (`blocked`): `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH`, and
    System32 `ssh.exe` through `core.sshCommand` reached the fixture pipe; the live default-ssh row needs a declared disposable Windows host
    whose `%USERPROFILE%\.ssh` is empty. **Observed:** Git for Windows 2.55.0.windows.3, bundled
    `OpenSSH_10.3p1, OpenSSL 3.5.7`.

## Mechanism observations (not product support)

These rows record OpenSSH and platform mechanism behavior observed on fixtures during the gate experiments. They inform
design and do **not** label Heimdall support. Status and verdict are copied from each record; the full criteria and
raw rows are in the record and its artifacts.

### Native Windows 11 (G03, 2026-10-06T06:31Z run)

Host and clients as in row 7. Fixture `sshd`: non-root OpenSSH 9.6p1 in WSL scratch, reached over NAT localhost
forwarding. Artifacts: `tests/evidence/artifacts/g03/native-win/`. Summary in `docs/research/g03-windows-wsl.md` §0.1.

| Id | Observation | Record | Status / verdict | Pins |
|---|---|---|---|---|
| W1 | Three ssh clients present. The MSI is first on PATH. The ssh-agent service is Running/Automatic from the MSI. The default agent pipe exists. `SSH_AUTH_SOCK` unset; no `core.sshCommand` in any scope. Inventory is passive: no pipe was opened. | `g03-win-env-inventory.json` | verified / pass | S13; G03-S08 |
| W2 | `SSH_AUTH_SOCK` in backslash or forward-slash form selects a fixture pipe on both Win32-OpenSSH builds. A non-existent pipe gives exit 2 with no fallback. Any non-ASCII character in the pipe name makes selection fail; spaces work. Git's MSYS `ssh-add` cannot use Windows named pipes: it opened the pipe as a file and sent no request. | `g03-win-sshauthsock-selection.json` | verified / pass | S01, S30; G03-S02 |
| W3 | `IdentityAgent \\.\pipe\x` (single backslashes) is unescaped and reaches nothing. Doubled backslashes, forward slashes, `$VAR` and `${VAR}` select the target exclusively. Both Win32-OpenSSH builds behave the same; MSYS ssh reaches no pipe in any form. | `g03-win-identityagent-forms.json` | verified / pass | S01; G03-S03, G03-S04, G03-S05 |
| W4 | Git precedence `GIT_SSH_COMMAND` > `core.sshCommand` > `GIT_SSH`. System32 ssh through `core.sshCommand` reached the fixture pipe. The live default row was not run. | `g03-win-git-ssh-selection.json` | blocked / inconclusive | G03-S13, G03-S14 |
| W5 | A pipe server with `FILE_FLAG_FIRST_PIPE_INSTANCE` refuses a duplicate server. The pipe vanishes when its server dies, and the client then exits 2. The cross-user pre-squat row is blocked (second account). | `g03-win-stale-squat-pipe.json` | blocked / inconclusive | G03-S09, G03-S10 |
| W6 | Exit 42 preserved, stderr separate, UTF-8 exact, 1 MiB binary round trip exact. `ssh true` took 151–190 ms over loopback (pwsh 7 record). Ctrl-C and resize not run. | `g03-win-process-io.json` | blocked / inconclusive | — |
| W7 | `-F` works under a spaced, non-ASCII directory. In a directory containing `%`, only the `%%`-escaped known_hosts path works. Process-API argv exact for 17 cases; `cmd.exe` altered the `%` case. | `g03-win-path-quoting.json` | verified / pass | S01 |
| W8 | Service DACL grants Authenticated Users start only (not stop or reconfigure). An owner-only fixture pipe needed no elevation. | `g03-win-service-elevation.json` | verified / pass | S13; G03-S08 |
| W9 | Inbox 9.5p2 rejects a private key readable by Authenticated Users ("bad permissions"); restoring the owner-only DACL restores acceptance. | `g03-win-key-file-permissions.json` | verified / pass | S13; G03-S02 |
| W10 | Pipe ACL against another Windows user | `g03-win-pipe-acl-other-user.json` | blocked (second disposable non-admin account) | G03-S09 |
| W11 | 1Password coexistence | `g03-win-1password-coexistence.json` | blocked (disposable 1Password on a disposable host, owner authorization) | S06, S07; G03-S12 |
| W12 | Agent constraints in the Windows agent service | `g03-win-agent-constraints.json` | blocked (disposable host, agent-store mutation authorization) | G03-S07 |

### WSL2 on the same PC (G03, 2026-10-06T06:53Z run)

Host as in row 10. Fixture `sshd`: two non-root 9.6p1 instances in WSL scratch. Windows agents were fixture pipes
served by pwsh 7.6.6, plus a decoy that logged no connection. Artifacts: `tests/evidence/artifacts/g03/native-wsl/`.
Summary in `docs/research/g03-windows-wsl.md` §0.2.

| Id | Observation | Record | Status / verdict | Pins |
|---|---|---|---|---|
| L1 | Inventory: Ubuntu 24.04.5, systemd, NAT, interop on, `appendWindowsPath = false`, so `ssh.exe` is not on PATH | `g03-wsl-env-inventory.json` | verified / pass | G03-S15, G03-S16 |
| L2 | `-o IdentityAgent=//./pipe/<fixture>` and a config `IdentityAgent $VAR` with `WSLENV=…/w` each select the target pipe exclusively. A Linux variable without a WSLENV entry is invisible to `cmd.exe`. | `g03-wsl-a-executable-selection.json` | verified / pass | G03-S15 |
| L3 | Through interop: exit codes, stderr separation, UTF-8, 1 MiB binary exact. Stdin EOF propagates. `timeout -s INT` leaves no `ssh.exe` behind. | `g03-wsl-a-process-io.json` | verified / pass | G03-S15 |
| L4 | 17 remote-argument cases byte-exact. `-F` works with Windows, `\\wsl.localhost\…` and Linux paths; the Linux-path case is probably working-directory-relative [I]. | `g03-wsl-a-path-quoting.json` | verified / pass | G03-S15 |
| L5 | `git` in WSL with `core.sshCommand=<ssh.exe>`: ls-remote, clone (Linux and `/mnt/c` paths), push. `GIT_SSH_COMMAND` beats `core.sshCommand`. | `g03-wsl-a-git.json` | verified / pass | S12; G03-S12, G03-S13 |
| L6 | `ssh.exe` rereads the certificate file on every run: wrong principal rejected, restore accepted | `g03-wsl-a-cert-change.json` | verified / pass | S10 |
| L7 | Interop child token not elevated (Medium integrity). The UAC-prompt attestation needs an operator. | `g03-wsl-a-elevation.json` | in_progress / inconclusive | G03-S16 |
| L8 | Endpoint under `XDG_RUNTIME_DIR`, directory 0700, socket 0600 (same-user rows). Other-Linux-user rows not run. | `g03-wsl-b-endpoint-perms.json` | in_progress / inconclusive | S30 |
| L9 | Only the allowed key is listed. Signing with another key, add, remove-all, lock and a foreign extension are refused. Oversize frame closes the connection. | `g03-wsl-b-unauthorized-key.json` | verified / pass | S03, S30 |
| L10 | Deleted socket recreated with a new inode, or proxy exit 7. A live endpoint is not replaced. A stale socket after SIGKILL fails cleanly and is replaced only with `--replace-stale`. | `g03-wsl-b-socket-deletion.json`, `g03-wsl-b-stale-socket.json` | verified / pass (both) | S30 |
| L11 | Per-connection Windows PowerShell 5.1 relay to the fixture pipe. The filtered key is refused by the proxy. The Windows agent attributes connections to `powershell`, not the Linux caller. About 220 ms per list request. | `g03-wsl-b-relay-attribution.json` | verified / pass | G03-S17, G03-S18 |
| L12 | Deadline enforced; teardown removes only the proxy's own socket | `g03-wsl-b-teardown-deadline.json` | verified / pass | — |
| L13 | Host lock, multi-distribution exposure, distribution restart, idle timeout, another Windows user | `g03-wsl-b-{host-lock,multi-distro-exposure,distro-restart,idle-timeout,other-windows-user}.json` | blocked (5; inputs in row 11 notes) | G03-S15, G03-S16 |

### macOS host with containerized fixtures (2026-10-03)

macOS 27.0 (26A428) arm64; client OpenSSH_10.3p1, LibreSSL 3.3.6; fixture server `openssh-server 1:10.0p1-7+deb13u4`
(banner OpenSSH_10.0p2 Debian) in Docker Desktop (Engine 29.8.1). Fixture servers run in containers only; no native Linux host.

| Id | Observation | Record | Status / verdict | Pins |
|---|---|---|---|---|
| M1 | Fixture inventory: fixed-auth, account-enrollable, two CA hosts, ProxyJump half of the bastion, host-key substitution (loopback + HostKeyAlias) | `m00-t03-fixtures.json` | in_progress (rows 1–5 verified per fixture) | S01, S02, S04, S05, S10 |
| M2 | Dedicated agent, certificate expiry, principal scope, account CA principals, issuer separation, fresh-login verification, enroll marker key | `g04-exp-{e1-dedicated-agent,e2-cert-expiry,e3-principal-scope,e4-account-ca-principals,e5-issuer-separation,e6-fresh-login-verification}.json`, `g04-exp-enroll-marker-key.json` | verified / pass (7) | S04, S05, S10, S30 |
| M3 | Multiplexing (G09 preliminary). After-expiry: certificate expiry did not stop new sessions through an existing master; after `ssh -O stop`, new clients were not admitted and the open session continued (criterion H2 held). Stop race: 0 of 25 clients that started after `-O stop` returned were admitted. Preconnected: the criterion that control connections accepted before `-O stop` are refused afterwards did not hold. | `g04-exp-g09-prelim-mux-{after-expiry,stop-race,preconnected-after-stop}.json` | verified / pass, pass, **fail** | S01, S02 |
| M4 | macOS lock-probe smoke runs (harness smoke; no human-driven lock) | `g04-macos-lock-probe-smoke-*.json` (7) | 5 verified / pass, 2 in_progress / inconclusive | — |
| M5 | Screen lock, logout, reboot, sleep, data-protection keychain, Secure Enclave CTK. CTK (one unlocked run): loads only through `ssh-add -K -S` and signs; `KEYCHAIN_CERTIFICATES` does not limit that path | `g04-macos-*-probe.json` (6) | blocked (owner-driven cycles, signing identity); CTK: blocked / **fail** | — |

## G02 prototype platform runs (not product support)

These are runs of the disposable `heimdall-proto` prototypes (G02), not of Heimdall. They show which platforms the
candidate stacks were executed on. Records are in `tests/evidence/`; the summary is
`tests/evidence/artifacts/g02-r4/x1/RESULTS.md`.

| Platform | Host | Go | Rust | TypeScript |
|---|---|---|---|---|
| darwin-arm64 | macOS 27.0 native | `g02-go-conformance.json` verified / pass (139/139) | `g02-rust-conformance.json` verified / pass | `g02-ts-conformance.json` in_progress / fail |
| linux-arm64 | Docker Desktop VM container (not a Linux host) | `g02-go-conformance-linux.json` verified / pass | `g02-rust-conformance-linux.json` verified / pass | `g02-ts-conformance-linux.json` in_progress / fail |
| linux-x64 | WSL2 Ubuntu 24.04.5 on the Windows 11 PC, native x86_64 (not a Linux desktop host), 2026-10-06 | `g02-go-conformance-linux-x64.json` verified / pass (139/139) | `g02-rust-conformance-linux-x64.json` verified / pass (139/139) | not run |
| windows-x64 | native Windows 11 Pro 26300, non-elevated, 2026-10-06 | `g02-go-x1-windows.json` verified / **fail** (§9.6 baseline, 67/71 gating; `.bat`/`.cmd` argument injection) | `g02-rust-x1-windows.json` verified / **fail** (68/71; named pipe as `--file`, regular file as `--socket` modified) | not run |

The windows-x64 records hold the §9.6 baseline of the frozen artifacts. progress.md reports later fix rounds: Go 71/71
at 84c7665, Rust 71/71 at 001a791 (artifacts in `tests/evidence/artifacts/g02-r4/x1b/`). Those results have no
evidence record and do not change any status here.

## Version floors (ADR-0001 §5)

| Target | Floor | Status | Blocked on | Observed so far (not a floor) |
|---|---|---|---|---|
| macOS arm64 | TBD | blocked | G01 clean-machine install test of a selected-stack build | macOS 27.0 (26A428), OpenSSH_10.3p1 (dev host, 2026-10-03) |
| Linux x86-64 / arm64 | TBD | blocked | native Linux desktop/user-session and headless hosts; G01 clean-machine tests | none on a native Linux host |
| Windows x86-64 | TBD (Windows build + Win32-OpenSSH version) | blocked | G01 clean-machine tests; owner item E6 for the Win32-OpenSSH baseline. The owner PC is not a clean machine. | Windows 11 Pro 26300.9550; inbox 9.5p2 (9.5.6.3); MSI 10.0p2 (10.0.0.0); Git for Windows 2.55.0.windows.3 with MSYS 10.3p1 (2026-10-06) |
| WSL2 x86-64 | TBD (WSL version + distributions) | blocked | G01 clean-machine tests; a disposable distribution | WSL 3.0.1.0, Ubuntu 24.04.5, kernel 6.18.40.1, Linux OpenSSH 9.6p1 (2026-10-06) |
| 1Password SSH agent | TBD | blocked | owner-authorized disposable account and vault with disposable keys on each OS | none |

ADR-0001 §5 (since commit 9b3f665) gives the same reason for Windows and WSL2: the floors stay `blocked` until G01
clean-machine tests. The owner's Windows 11 PC has been available for gate probes since 2026-10-06, but it is not a clean
machine.

## Changes from v0

- Every row names its pins. The evidence-status, G01-floor and row-note sections are new. All labels are still
  `not-tested`. Gate evidence: 14 rows `blocked` (each names its missing platform, host, operator or authorization)
  and 2 `not_started` (rows 12 and 15); no row is `verified` or `in_progress`, because every row with records also
  depends on a blocked record, sub-row or baseline input.
- Rows 7–11: replaced v0's "blocked: no native Windows host / no WSL2 host" with the 2026-10-06 native Windows 11 and
  WSL2 records and their remaining blocked inputs.
- Row 16 is new. Row 7's client is now Win32-OpenSSH only.
- The mechanism-observation tables, the G02 prototype platform table and the floor table replace v0's placeholder.
