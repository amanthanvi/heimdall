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
  `tests/evidence/README.md`); three records are coarser:
  - `m00-t03-fixtures.json` is `in_progress` by design;
  - `g03-wsl-a-process-io.json` (L3) is `verified` although interactive Ctrl-C, PTY resize and console behaviour are
    manual steps it did not run (its Windows twin `g03-win-process-io.json` is `blocked` on the same manual steps);
  - `g03-wsl-a-executable-selection.json` (L2) is `verified` although its P-A01 unset-variable sub-row
    (`unset_var_identityagent`) was deliberately not run. Neither WSL record has a per-row status map
    (`sub_probe_status`), so the matrix cells copy their top-level status.

  A row takes the lowest-standing status among the records and sub-rows it relies on:
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
   - for `g04-macos-secure-enclave-ctk-probe.json` (commit b5a528cb): `blocked`, verdict `fail`. Two unlocked runs
     (v1 2026-10-09, v3 2026-10-31). The identity loads only through `ssh-add -K -S`, signs, and (v3) logs in to the
     fixture with the controls refused; `KEYCHAIN_CERTIFICATES` does not limit which identities that path loads (the
     clause that fails, in both runs). Unlocked row `verified`; blocked on an owner-driven screen lock/unlock cycle,
     and on the owner confirming that D4 covers further real-store runs.

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
   Their `blocked_on` names two inputs: an owner at the console of the native Windows 11 host to lock, or to sign out
   and reboot, and the probe harness, which is not yet implemented (g04 §8.2, P-W1 and P-W2:
   `docs/research/g04-managed-credentials.md`). The owner cannot unblock the row alone. The recipe is not selected.
10. **Evidence:** WSL run of 2026-10-06 (L1–L7). `verified`: L1–L6. `in_progress`: L7. **Blocked on:**
    - an operator watching the Windows console for the UAC-prompt attestation of P-A06 (L7; progress.md lists
      "P-A06 UAC" among the inputs that need an operator at the console);
    - a host where `\\.\pipe\openssh-ssh-agent` is absent, for the P-A01 unset-variable sub-row. That sub-row was
      skipped by design because the owner's default pipe exists;
    - an operator for interactive Ctrl-C and PTY resize from a WSL terminal (L3: `g03-wsl-a-process-io.json` lists them
      as manual steps not run).

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
    **Source note (2026-10-31):** S34 on `main` now says the default pairing grant includes access and relay
    management (its pin says ordinary pairing does not), and that a shell or full-access-agent scope can mint a fully
    scoped session. The pin stays the baseline, main's defaults are not a Heimdall contract, and G07's authority-boundary
    investigation is retained on this point. S17 and S18 also changed on `main` with qualifications. See
    `docs/sources/drift-2026-10-31.md`.
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

## M02 existing-access rows (Heimdall build `e4f43f84`, M02 exit, 2026-11-10)

These rows test Heimdall itself.
- **Build:** commit `e4f43f847af1b3a7396298f5a39af6d859b080d1`. Its `crates/` and `tests/` `*.rs` sources digest is
  `63ad245b…20baa5` (`tests/native/m02/required-inventory.json`).
- **Records:** `tests/evidence/m02-*.json`.
- **Artifacts:** `tests/evidence/artifacts/m02/exit-e4f43f84/`. `runs.json` holds the configuration, and
  `digests.txt` lists every artifact file.
- **Exit record:** `docs/architecture/m02-exit.md`.

- **Label.** Every row stays `not-tested`. ADR-0001 §9 keeps every platform at `not-tested` until ADR-0001 §5 (floors)
  and §6 (baseline worksheet) close, and both are still `blocked`. A row passing at M02 does not change that.
- **M02 evidence.** This column gives the row status of the cited record on that platform (plan §1.4 statuses;
  the lowest-row rule is in `tests/evidence/README.md`).
  - **What `verified` means.** Every required test that applies on that platform ran and passed in this run. A
    test excluded on a platform carries a case-index rationale, and a planned test that does not exist reads as
    not run (ADR-0007 §12.47 item 1). It is not an independent review of the units (`runs.json`
    `common_limitations`).
  - **macOS arm64:** every required test passed. `check.sh` passed 1780, failed 0 and ignored 8, with all 9 steps
    at exit 0; the observation pass passed 197.
  - **Linux x86-64 (devbox):** every required test passed: 1776 passed, 0 failed, 8 ignored over 49 binaries. The
    one build-host-path test, `heimdall_testkit-unit repo::tests::unset_or_empty_is_the_compile_time_root`, is
    classified neutral and runs on the build host only.
  - **Windows 11 x64:** every required test that applies on Windows passed: 1655 passed, 0 failed, 1 ignored over 49
    binaries, and `windows_launch` 4 of 4. The run was native, in local mode (an agent on the PC). See "Windows
    scope" below.
  - **WSL2 disposable distribution:** the ordinary-ssh scenario passed (`wsl_ordinary_ssh` 11 of 11).
- **Windows scope** (read this before M02-9 to M02-13).
  - **The server.** Every Windows transport test connects to a loopback fixture sshd: Linux OpenSSH 9.6p1, non-root,
    in WSL scratch, reached from Windows on 127.0.0.1.
    - It authenticates the WSL account, not the Windows user (`windows/host.txt`, `fixture-sshd-account`).
    - The strict variant (`MaxAuthTries 3`) is separate.
    - No Windows sshd is tested.
  - **The provider.** It is the fixture pipe agent: the testkit `FakeAgent` on a per-run `\\.\pipe\heimdall-hmtest-…`
    name. The harness never opens the system agent's pipe (B4).
  - **Which tests connect the in-box clients** (`windows/tests.txt`, all `ok`):
    - **`ssh.exe`, `scp.exe` and `sftp.exe`:** `e2e_cli_m02 ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound`.
      Its log line shows `ssh`, `scp` and `sftp` resolved to `C:\WINDOWS\System32\OpenSSH\` and `git` to Git for
      Windows' `mingw64\bin\git.exe`. The test asserts that:
      - the copied bytes are identical;
      - only the adopted key was accepted;
      - the decoy agent was never contacted.
    - **`ssh.exe` alone:** the other `e2e_cli_m02 ssh::` tests. 12 `ssh::` tests ran in all, and 8 of them start the
      fixture sshd. Among them are `a01_cli_adopt_observed_and_managed_aliases_then_ordinary_ssh_with_scratch_f`,
      `a01_no_remote_change`, `a35_wrong_key_exclusive_selection_fails_without_fallback`,
      `a35_too_many_keys_succeeds_for_managed_alias_only` and
      `host_key_substitution_fails_closed_and_nothing_written_to_known_hosts`.
    - **`scp.exe` and `sftp.exe` under `heimdall run`:** `e2e_run_m02 a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths`.
    - **`ssh.exe` under `heimdall run` and `connect`:** `a11::a27_binary_stdin_stdout_roundtrip_through_ssh` and
      `a11::connect_reaches_the_fixture_sshd_through_the_verified_client`.
    - **Git:** `a11::a27_git_clone_and_push_over_ssh_with_binary_blob`.
    - **A note on resolution.** The `e2e_run_m02` tests resolve their clients from `PATH` and do not print the path.
      That they used the System32 clients is inferred from `ssh-V-tests=OpenSSH_for_Windows_9.5p2`.
  - **Still missing on Windows:**
    - **Ordinary ssh without `-F`** against a real `%USERPROFILE%\.ssh\config` (B2). Every test above uses a scratch
      configuration.
    - **The Windows system agent** (B4) and **1Password** (B1).
    - **An interactive `connect`** after provider approval, the TUI pty cases and the personal profile without a
      repository. These are deferred to M04's pseudoconsole driver (ADR-0007 §12.47 D2 and D3, §12.49 item 4).
    - **The interactive console Ctrl-C and resize** (B5).
    - **Git for Windows choosing its own client during a transport.** Every Windows Git transport test sets
      `GIT_SSH_COMMAND` explicitly. No test relies on Git reading `core.sshCommand` from the Q7 include, or on the
      run-time `GIT_CONFIG_COUNT` injection, to carry a transport. The bundled MSYS `ssh` carries none.
- **Unattended.** M02 claims nothing unattended. A managed unattended minimum is `capability_unavailable` until M03
  (`m02-exit-no-unattended-claim.json`, `verified` with 2 tests each on macOS, Linux and Windows).

| # | Environment | Client | Provider / signer | Mechanism | Label | M02 evidence | Record |
|---|---|---|---|---|---|---|---|
| M02-1 | macOS 27.2 (26B123) arm64 | OpenSSH ssh 10.5p1 (system) | native ssh-agent (disposable, scratch `HOME`) | existing identity: managed alias with a scratch `-F`, and `heimdall run` | not-tested | verified (A35 39 of 39, A01 13 of 13) | `m02-a35-reference-matrix.json`, `m02-a01-existing-access.json` |
| M02-2 | macOS 27.2 arm64 | Apple Git 2.54.0 over ssh 10.5p1 | native ssh-agent (disposable) | existing identity | not-tested | verified (A35 39, A27 97) | `m02-a35-reference-matrix.json`, `m02-a27-child-integrity.json` |
| M02-3 | macOS 27.2 arm64 | scp (10.5p1) | native ssh-agent (disposable) | existing identity | not-tested | verified (A35, A27) | as M02-2 |
| M02-4 | macOS 27.2 arm64 | sftp (10.5p1) | native ssh-agent (disposable) | existing identity | not-tested | verified (A35, A27) | as M02-2 |
| M02-5 | Linux x86-64 (devbox, Ubuntu, kernel 6.8, glibc 2.39) | OpenSSH ssh 9.6p1 (Ubuntu-3ubuntu13.20) | native ssh-agent (disposable) | existing identity: managed alias with a scratch `-F`, and `heimdall run` | not-tested | verified (A35 39 of 39, A01 13 of 13) | `m02-a35-reference-matrix.json`, `m02-a01-existing-access.json` |
| M02-6 | Linux x86-64 (devbox) | git 2.43.0 over ssh 9.6p1 | native ssh-agent (disposable) | existing identity | not-tested | verified (A35 39, A27 97) | `m02-a35-reference-matrix.json`, `m02-a27-child-integrity.json` |
| M02-7 | Linux x86-64 (devbox) | scp (9.6p1) | native ssh-agent (disposable) | existing identity | not-tested | verified (A35, A27) | as M02-6 |
| M02-8 | Linux x86-64 (devbox) | sftp (9.6p1) | native ssh-agent (disposable) | existing identity | not-tested | verified (A35, A27) | as M02-6 |
| M02-9 | Windows 11 x64 (10.0.26300.9818, Medium integrity) | in-box `ssh.exe` OpenSSH_for_Windows_9.5p2 (LibreSSL 3.8.2), System32; the PATH-first OpenSSH 10.3p1 was a candidate, not selected | fixture pipe agent; the server is the WSL fixture sshd 9.6p1 on 127.0.0.1 | existing identity: managed alias with a scratch configuration, `heimdall run` and `connect` | not-tested | verified (A35 38, A01 12, A11 29, A27 80, R-SE-04 8). Connects: `ssh::a35_matrix_…`, `ssh::a01_…`, `ssh::a35_…`, `ssh::host_key_substitution_…`, `a11::connect_reaches_the_fixture_sshd_…`, `a11::a27_binary_stdin_stdout_roundtrip_through_ssh` | `m02-a35-reference-matrix.json`, `m02-a01-existing-access.json`, `m02-a11-provider-interaction.json`, `m02-a27-child-integrity.json`, `m02-r-se-04-host-trust.json` |
| M02-10 | Windows 11 x64 | Git for Windows 2.55.0.windows.3 (`mingw64\bin\git.exe`); its bundled MSYS `ssh.exe` is present (`git_bundles_msys_ssh="true"`) | fixture pipe agent | existing identity: Git observation; transport through the in-box client and through P_git's rendered command | not-tested | verified (A35 38, A22 463, A27 80). Transport: `ssh::a35_matrix_…` (`git ls-remote`), `a11::a27_git_clone_and_push_over_ssh_with_binary_blob`, `integration_projection_git git_spaced_client_path_is_quoted_and_runs` (authenticated `ls-remote` through a spaced copy of the in-box client). Each sets `GIT_SSH_COMMAND`. The `core.sshCommand` injection's precedence is tested with stub clients only | `m02-a35-reference-matrix.json`, `m02-a22-configuration-precedence.json`, `m02-a27-child-integrity.json` |
| M02-11 | Windows 11 x64 | `scp.exe` (in-box 9.5p2, System32) | fixture pipe agent | existing identity | not-tested | verified (A35 38, A27 80). Connects: `ssh::a35_matrix_…` (upload, byte-identical), `a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths` (up and down under `heimdall run`) | `m02-a35-reference-matrix.json`, `m02-a27-child-integrity.json` |
| M02-12 | Windows 11 x64 | `sftp.exe` (in-box 9.5p2, System32) | fixture pipe agent | existing identity | not-tested | verified (A35 38, A27 80). Connects: `ssh::a35_matrix_…` (batch `get`, byte-identical), `a11::a27_scp_and_sftp_binary_with_unicode_and_spaced_paths` (batch put and get) | as M02-11 |
| M02-13 | Windows 11 x64 | ssh / Git / scp / sftp | Windows OpenSSH agent service (`\\.\pipe\openssh-ssh-agent`), incl. its confirm-constrained row | existing identity | not-tested | blocked: B4, a disposable Windows host whose system agent may hold test keys. The harness never opens this pipe | `m02-a35-reference-matrix.json`, `m02-a11-provider-interaction.json` |
| M02-14 | macOS 27.2 arm64 | ssh / Git / scp / sftp | 1Password SSH agent | existing external signer | not-tested | blocked: B1, a disposable 1Password account with disposable SSH keys | `m02-a35-reference-matrix.json`, `m02-a11-provider-interaction.json` |
| M02-15 | Linux x86-64 | ssh / Git / scp / sftp | 1Password SSH agent | existing external signer | not-tested | blocked: B1 | as M02-14 |
| M02-16 | Windows 11 x64 | ssh / Git / scp / sftp | 1Password SSH agent (pipe) | existing external signer | not-tested | blocked: B1 | as M02-14 |
| M02-17 | macOS arm64, a real `~/.ssh/config` | ordinary ssh / Git / scp / sftp **without `-F`** | native ssh-agent | ordinary alias after `setup apply` | not-tested | blocked: B3, a disposable macOS standard user account | `m02-a01-existing-access.json` |
| M02-18 | Windows 11, a real `%USERPROFILE%\.ssh\config` | ordinary ssh **without `-F`** | fixture pipe agent | ordinary alias after `setup apply` | not-tested | blocked: B2, the disposable second Windows account | `m02-a01-existing-access.json` |
| M02-19 | WSL2 disposable distribution (Ubuntu 24.04.5 image, imported and unregistered by the run; ext4 home, non-root user) | ordinary ssh / git / scp / sftp **without `-F`**: OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, git 2.43.0 | disposable ssh-agent holding the disposable key; loopback fixture sshd 9.6p1 (6 accepted logins) | ordinary alias after `setup apply`, then `uninstall` (T06) | not-tested | verified (A01 7 of 7, A35 4 of 4, A22 1 of 1 plus the birth-time `platform_required` test, T06 2 of 2, no mandatory wrapper 5 of 5) | `m02-a01-existing-access.json`, `m02-a35-reference-matrix.json`, `m02-a22-configuration-precedence.json`, `m02-t06-clean-uninstall.json`, `m02-exit-no-mandatory-wrapper.json` |
| M02-20 | Linux arm64 | OpenSSH | any | existing identity | not-tested | blocked: B9, a native Linux arm64 host | `m02-a01-existing-access.json`, `m02-a35-reference-matrix.json` |
| M02-21 | any | any | hardware security key (FIDO2), touch required | existing identity | not-tested | blocked: B6, a hardware key owned for testing (the synthetic `sk-` key covers only the non-interactive refusal) | `m02-a11-provider-interaction.json` |

### M02 per-configuration facts, unsupported cases and residuals

**Where the values come from.** Observed values come from this build's `observation` lines, under the artifacts
directory:
- `macos/observations.txt`;
- `linux/tests.txt`;
- `windows/tests.txt`;
- `wsl-distro/host.txt` and `wsl-distro/tests.txt`.

"Not observed" means this run's artifacts do not show the fact. A fact that has not been observed stays `[I]` for
that target.

1. **Identity selection is a fact of each configuration, not of a platform.**
   - A selection is exclusive only when `IdentitiesOnly yes` is determined and the adopted identity is the only
     candidate (ADR-0007 F9, §3). Anything else is reported as non-exclusive.
   - Non-interactive use refuses uncleared fallback identities before any agent contact (ADR-0007 §7, §12.5 item 5).
     A file-backed fallback is never cleared.
   - The default agent is the `SSH_AUTH_SOCK` of whatever session runs `ssh`. Consent to a state that uses it covers
     "the session's agent", not a particular endpoint (§12.16, §13).
2. **Default identity files per client** (§12.17, amended by §12.32 item 12).
   - **Heimdall's list.** It is the union of the pinned manuals' six names and every observed client's list. That
     makes eight names, in this order: `id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`,
     `id_mldsa44_ed25519`, `id_xmss`, `id_dsa` (`crates/sshconf/src/client.rs` `DEFAULT_IDENTITIES`).
   - **What `ssh -G` printed** with no `IdentityFile`:
     - macOS OpenSSH_10.5p1: six names, `id_rsa` to `id_mldsa44_ed25519`.
     - Linux OpenSSH_9.6p1: seven, `id_rsa`, `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`, `id_xmss`,
       `id_dsa`.
     - Windows in-box OpenSSH_for_Windows_9.5p2: the same seven as 9.6p1. Its row in the observed-clients table now
       records those seven (`recorded_for_this_client`; §12.47 item 5, D5).
   - **The superset holds** for these three clients. On all three the observation reports no printed name outside
     Heimdall's union (`not_in_heimdall_union=""`).
3. **Client differences, gated per client** (§12.32 items 11–13; §12.47 item 5). `integration_sshconf_vs_ssh_g`
   passes on all three platforms. An unobserved client takes the strictest reading.
   - **Linux 9.6p1 refuses six constructs:** `Match command`, `Match sessiontype` and `Match version`, and the
     keywords `RefuseConnection`, `VersionAddendum` and `WarnWeakCrypto`.
     - `ssh -G` exits 255 for each, and Heimdall marks the file `invalid` for that client
       (`gated_match_criteria_and_keywords_follow_the_client`).
     - The same keywords exit 0 when they are listed as ignored.
     - macOS 10.5p1 accepts all six (exit 0), and Windows 9.5p2 refuses all six, as 9.6p1 does.
   - **`Match sessiontype` with `none` or `subsystem`,** with or without `-s`, is refused by 9.6p1 and by 9.5p2 (exit
     255, `heimdall_stricter="false"`). 10.5p1 accepts it.
   - **Environment expansion** (`s01_env_expansion_keywords_match_the_client`):
     - 10.5p1 expands `User`, `SetEnv` and an `Include` path.
     - 9.6p1 leaves all three literal, and Heimdall follows it (`heimdall_expands_env="false"`).
     - 9.5p2 expands `User`, `RevokedHostKeys`, `LocalForward`, `RemoteForward`, `ControlPath` and `IdentityAgent`,
       but leaves `SetEnv` literal and an `Include` path unexpanded. For those two, Heimdall reads the expanding form
       (`heimdall_expands_env="true"`, `heimdall_stricter="true"`), which is the strict, unknown-client reading.
   - **`%` tokens in `Include`** (`include_tokens_follow_the_client`):
     - 10.5p1 expands them;
     - 9.6p1 does not, and Heimdall follows it (port 2965 on both sides);
     - 9.5p2 does not, and Heimdall's reading differs: port 22 against the client's 2965
       (`heimdall_expands_include_tokens="true"`). That is the strict reading again.
   - **BOM and CRLF user configurations** (`bom_and_crlf_acceptance`):
     - **Windows 9.5p2:** it loads a BOM file and a CRLF file. Its encoding-table rows are present, and the planner
       accepts both (`table_row="true"`, `planner_accepts="true"`; §12.47 item 5, D5).
       `a22_crlf_bom_no_trailing_newline_preserved` passed on Windows, with a BOM, CRLF and no trailing newline
       (§12.51 item 5).
     - **macOS 10.5p1 and Linux 9.6p1:** a BOM file does not load, and a CRLF file does. Neither client has a table
       row (`table_row="false"`), so the planner does not accept either encoding (manual mode, which fails closed).
   - **An LF-only rendered P loads** on all three clients (`rendered_file_loads_on_target_client`, `loads=true`;
     §12.48 item 6).
   - **Git 2.43.0 behaves like 2.54.0.** The devbox's umask 0002 makes a fixture's Git directory group-writable, and
     the writer refuses it. An account with umask 0002 therefore gets the Git item as `not_applicable`
     (`unmanageable_file`), named at preview, while SSH still applies (§12.34).
4. **Atomic exchange per filesystem** (ADR-0007 §5.9 item 3). Where it is absent, manual mode applies.
   - APFS (macOS): supported (`exchange_supported_on_target_fs os=macos supported=true`).
   - ext4 (Linux devbox): supported (`os=linux supported=true`).
   - ext4 in the WSL disposable distribution: supported (`rename-exchange=supported (renameat2 RENAME_EXCHANGE)`).
   - Windows: supported (`os=windows supported=true`). The line names the OS, not the file system. `windows/host.txt`
     does not record the scratch file system, so that it was NTFS is an inference, not an observation.
   - The container overlay filesystem: not observed.
5. **Birth time per filesystem** (F25).
   - APFS: birth time recorded; no inode reuse observed.
   - ext4 (devbox): birth time recorded; inode reuse observed.
   - ext4 in the WSL distribution: birth time recorded (`birth-time=recorded (statx STATX_BTIME)`; A22's
     `platform_required` test `a22_birth_time_recorded_on_the_home_fs` passed).
   - **Windows: not observed.**
     - The line reads `birth_recorded=false inode_reused=false`.
     - Windows identity is the `FILE_ID_INFO` form (volume serial number and a 128-bit file ID,
       `FileIdentity::Windows`), which has no birth-time field.
     - The test inspects birth time and inode reuse only on the Unix identity form
       (`tests/integration/projection_replace.rs`).
     - So the line does not show that NTFS lacks a birth time or never reuses file IDs.
   - **Without birth time.** On a filesystem without birth time, a Git lock left after a crash is never claimed at
     recovery and is the owner's to remove (§5.6, §13). K is the only lock holder Heimdall ever places at Git's lock
     name (§5.9 item 5). `git_apply_releases_k_with_and_without_birth_time` passed on Windows.
6. **Git observations.** These hold on Apple Git 2.54.0, git 2.43.0 and Git for Windows 2.55.0.windows.3:
   - `git config --global` reads `~/.gitconfig` alone when it exists (`global_query_reads_xdg_when_home_file_exists="false"`);
   - the unscoped read order is XDG, then home;
   - values through includes need `--includes` (exit 0 with it, 1 without);
   - a conditional include is not applied outside a repository (the query exits 1).

   Git for Windows only:
   - **Bundled MSYS default.** `git_bundles_msys_ssh="true"`: a bundled `usr/bin/ssh.exe` is present beside the Git
     installation, so with nothing set, Git's default SSH is classified as the bundled MSYS client
     (`GitSshClassification::BundledMsys`, F16). On macOS and Linux the same test prints `false`.
   - **Git name transitions through `ReplaceFileW`** ran natively. `integration_projection_git` passed 44 tests on
     Windows, including `git_name_transitions_crash_at_every_point_reconciles`,
     `git_lock_occupied_by_holder_until_settlement` and `git_lock_held_by_git_is_git_config_locked_nothing_written`.
   - **A spaced client path.** A spaced configured client is quoted in P_git, executed by Git's MSYS shell, and used
     for an authenticated `ls-remote` (`git_spaced_client_path_is_quoted_and_runs`,
     `spaced_client_local_quoting=passed`).
   - **Bundled OpenSSH version.** A Windows PATH-first OpenSSH 10.3p1 was recorded as a candidate and not selected.
     Git for Windows' own bundled OpenSSH version is not recorded in this run's artifacts. The earlier G03 gate run
     recorded `OpenSSH_10.3p1`; see the row 16 notes above.

   The `git_user_value_shadowed` residual stands (§5.6). It needs `git config --show-origin`, so with
   `--no-local-exec` the doctor reports nothing about shadowing (§12.39 item 5).
7. **Git run-time limits** (§8).
   - The selection is resolved only in the child's starting directory. Git commands run in other repositories may
     select differently.
   - Unix: nothing is set for Git; the selection is only reported.
   - Windows: Heimdall injects `core.sshCommand` only for the bundled-MSYS default. That value is command scope, so
     it also overrides a repository-local value. The Q7 global include has neither limit.
   - Windows tests: the injection's precedence (it yields to `-c` and `GIT_SSH_COMMAND`) is tested with stub clients
     (`e2e_run_m02 git_run_injection_yields_to_dash_c_and_env`, passed on Windows). No Windows transport test relies
     on the injection or on the Q7 include to pick its client (see "Windows scope").
8. **Launch classification.**
   - A `launching` record with nothing after it is `indeterminate` on Unix and on Windows, never "launched" (§8).
   - On Windows a run is recorded as `launching, spawned, exited` (§12.43 item 4;
     `a27_windows_spawned_record_is_positive_launch_proof`).
   - A SIGPIPE disposition ignored by the caller is reset, a recorded limitation (Unix).
9. **Unsupported concurrency** (§5.9; not counted toward A22):
   - item 1: a writer that writes through a descriptor it opened before the commit point, after the final content
     check;
   - item 2: on Windows, a replacement inside `ReplaceFileW` between its own open and its rename. This window stays
     `[U]`; no test injects one;
   - item 3: filesystems without exchange (manual mode);
   - item 4: a same-user process writing into a Heimdall quarantine directory. These are private directories (mode
     0700 on Unix; on Windows the protected owner-only DACL, §12.48 item 4). Entries are removed only through a
     validated directory handle, with the expected digest re-read (§5.3);
   - item 5: identity reuse without a birth time.
10. **Held operations** (§5.7). A held setup operation blocks every other setup except its own repair. Repair is
    retry, which continues the operation, or keep, which closes it without moving any file.
    `unix::a22_cli_held_operation_status_retry_and_keep` passed on macOS and Linux. It is a pty case and has a
    case-index rationale on Windows.
11. **`config_tree_changed`** compares two observed snapshots. A change reverted before the second snapshot is not
    detected. `executed_config_commands` lists "constructs found before execution" and is never complete (§6).
12. **Other residuals:**
    - an endpoint `stat` on a hung network filesystem cannot be interrupted (§12.23);
    - a holder with no start-time token reads as exited when the same query succeeds for the runtime's own process
      (§12.24 item 5, §13);
    - the Git residuals of §12.41 and §13:
      - a rollback after the owner moved B_git leaves the moved block;
      - an intact-shaped B_git whose include target was edited is not detected by the update arm;
      - a user value only in a conditional include is read conservatively.
13. **Windows facts.**
    - **Observed natively in this build (the tests passed):**
      - **The account-name lookup** (§12.28 item 4). `sys::account_name` has a Windows implementation.
        `account_name_matches_inbox_ssh_g` shows that the token lookup equals the in-box client's `user`, with
        `USER` and `USERNAME` set to a wrong value. `doctor_reads_localuser_from_the_account_database` passed too.
      - **The DACLs.** A `~/.ssh` that Heimdall creates gets `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<sid>)`,
        and the user file it creates gets `D:P(A;;FA;;;<sid>)` (§12.48 item 4, §12.49 item 6).
        `windows_replace_preserves_dacl` and `windows_replace_retains_displaced_identity_without_race` passed.
      - **The reparse-point refusals.** `a22_windows_reparse_point_user_config_is_manual_mode` (the junction) and
        `a22_windows_file_symlink_user_config_is_manual_mode` (Developer Mode on, read only; §12.47 item 7) passed.
      - **The quarantine pins and the snapshot DACL check** (`sys::quarantine::windows_tests`). The pipe listener
        identifies a client after its first write (ADR-0006 §13.21).
      - **The pseudoconsole drivers** (`windows_launch`, 4 of 4):
        - `ctrlc.event`, `ctrlc.keystroke` and `ctrlc.break` each delivered one interrupt to the child
          (`heimdall_ctrl_c="processed"`, `child_interrupts=1`, heimdall exit 42);
        - `resize` delivered `100x30`, then `132x40`;
        - the agent's environment starts processes with Ctrl-C ignored (`ctrl-c-inherited=ignored`), and the driver
          enables Ctrl-C processing for the heimdall it creates (§12.44 item 2).
    - **Not observed:**
      - **The Windows owner rule** of §5.3 with a foreign owner SID. It cannot be set at Medium integrity (§12.51
        item 5, a stated limitation).
      - **The interactive console Ctrl-C and resize rows** (B5).
      - **The interactive TUI and `connect` pty cases, and the typed-yes purge refusal (exit 6).** These are deferred
        to M04 (§12.47 D2 and D3, §12.49 items 2 and 4).
14. **Evidence partials** (§12.30 item 13). This build's artifacts still do not capture:
    - the A35 matrix's fingerprints and counts. The resolved executables appear only in the Windows log;
    - the offered-key check through `HM_FIXTURE_SSHD_LOG`;
    - the TUI's first-frame latency.

    `check.sh` discards the output of passing tests, and `e2e_cli_m02` and `e2e_tui_m02` are not observation targets.
    These remain open.
15. **The WSL disposable distribution.**
    - **The image.** The run imported the pinned Ubuntu 24.04.5 WSL image, downloaded over https; its sha256 matches
      the pin.
    - **The run:**
      - it installed the OpenSSH server and `sftp-server` in the distribution only;
      - it ran the scenario as a non-root user with a disposable home;
      - it then terminated the distribution and unregistered it.
    - **The user's SSH configuration.** Its sha256 was `99344213…ef9b` before the run, `3bceec60…f85b` after
      `setup apply`, and `99344213…ef9b` again after `uninstall`.
    - **The registered set** had one distribution before and one after, and it was equal.
    - **Listening sockets.** The distribution had 3 non-loopback listening TCP sockets and 0 loopback ones, both
      before and after the scenario. `runs.json` describes them as the distribution's own, unchanged by heimdall. The
      artifacts do not say what they are.
    - **The WSL version** is not recorded: `wsl-distro/host.txt` reads `wsl-version=WSL version: <addr>`.

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
| M5 | Screen lock, logout, reboot, sleep, data-protection keychain, Secure Enclave CTK. CTK (two unlocked runs): loads only through `ssh-add -K -S` and signs; fixture login in v3 only (v1 left it unmeasured); `KEYCHAIN_CERTIFICATES` does not limit that path | `g04-macos-*-probe.json` (6) | blocked (owner-driven cycles, signing identity); CTK: blocked / **fail** | — |

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
