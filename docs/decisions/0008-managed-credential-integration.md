# ADR-0008 — Managed credential integration (M03): the B1 signer and issuer, scoped enrollment, deadline and connection control, lock behaviour

**Status:** proposed, revision 6 · **Date:** 2026-11-06 · **Tasks:** M03-T00-design (revision 1),
M03-T00-design-fix (revisions 2–6)
**Revision 6**, the last design fix, applies the round-5 final check
(`tests/evidence/artifacts/review-m03-design/round5-final-codex.md`, findings M03-R5-01 and R5-02)
under the orchestrator's rulings in §17.13, with §17.12's ruling on Q29. Text it changed is marked
**⟨r6⟩**, and §24 maps each finding to the sections that changed. It raises no new question. Under
§17.13 item 3, the design gate closes on the orchestrator's check of these edits.
**Revision 4** applies the round-3 targeted re-check
(`tests/evidence/artifacts/review-m03-design/round3-recheck-codex.md`, findings M03-R3-01–R3-05) under
the orchestrator's rulings in §17.7. Text it changed is marked **⟨r4⟩**, and §22 maps each R3 finding to
the sections that changed. Where a ruling could not be applied exactly as written, the ruling is kept
and §17.8 asks the question (Q26–Q28).
**Revision 3** applies the two independent round-2 reviews
(`tests/evidence/artifacts/review-m03-design/round2-a-codex.md`, findings A R2-01–R2-09;
`round2-b-opus.md`, findings B M03-R2-01–R2-18) under the orchestrator's rulings in §17.4, and
§17.3's rulings on Q18–Q21. Text it changed is marked **⟨r3⟩**, and §21 maps each R2 finding to the
sections that changed. Where a ruling could not be applied as written, or conflicts with an earlier
ADR, the ruling is kept and §17.5 asks the question (Q22–Q25).
**Revision 2** applies the two independent round-1 reviews
(`tests/evidence/artifacts/review-m03-design/round1-a-codex.md`, findings M03-R01–R15;
`round1-b-opus.md`, findings F01–F27) under the orchestrator's rulings in §17.1. Text changed by it is
marked **⟨r2⟩**, and §20 maps each finding to the sections that changed. Where a ruling could not be
applied as written, or conflicts with an earlier ADR, the ruling is kept and §17.2 asks the
question.
**Gates:** G04 (implementing the accepted recipe), G09 (expiry, multiplexing, clocks, revocation), and
the credential parts of G08.
**Implements:** ADR-0005 (recipe B1, accepted 2026-10-31). Its authority semantics do not change,
except where a §17.1 ruling amends ADR-0005 explicitly (⟨r2⟩ the destination-clock measurement of
item 10, which amends ADR-0005 §3.6 "Heimdall does not measure destination clocks"; the per-pair
runtime evidence of item 13, which amends ADR-0005 §7.4 row 1). Where ADR-0005 leaves a point open
(its §9.3 list and some mechanics), this ADR either decides it (D1–D13) or asks about it (§17).
**Affects:** the eleven requirements M03 owns (plan §13): R-UX-03, R-AU-04, R-AU-05, R-AU-08,
R-CR-02, R-CR-03, R-CR-04, R-CR-05, R-CR-06, R-CR-07 and R-SE-07. It also contributes to R-AU-06,
R-AU-07, R-RT-02, R-RT-07, R-SE-03, R-SE-04, R-SE-06, R-SE-08, R-DI-04 and R-EN-04. Exit cases: A03,
A07, A09, A10, A23 and A33.
**Companion:** `docs/architecture/m03-plan.md`, which gives the units, the tests, the evidence plan, and
the contract deltas in their final form (its §5).
* This ADR edits neither ADR-0005, ADR-0006 nor ADR-0007.
* The integrator applies the deltas as ADR-0006 revision 4 and as the ADR-0007 §2 directive-set
  revision.

**Basis:** the M02 code as committed at `1f5b8156`.
* M02's exit is not closed: its Windows native fixes are in progress elsewhere.
* Every dependency on an M02 internal that may still change is marked **⟨M02?⟩** and listed in
  m03-plan §0.4.

**Evidence labels.** As in ADR-0005:
* `[O:key]` resolves in ADR-0005 §9.1;
* `[S:key]` and `[Snn]` are pinned sources (the research register and spec §19);
* `[I]` is inference;
* `[U]` is unknown, and names the test that settles it.

`[M-Fn]` refers to this ADR's facts table (§1.2). Sentences such as "the issuer refuses" are decisions,
not observations. Nothing here is implemented.

Notation follows ADR-0005:
* **K_env** is a grant's working key, **K_ca** the issuer key, **C** a user certificate, **G** a grant
  with deadline **D**;
* a **pair** is one destination/account pair of a grant's resolved scope;
* **K_verify** (new) is the verification-only key of one enrollment;
* **P** is the managed OpenSSH file of ADR-0007 §2;
* the **registry** is the account's authorized-keys file.

---

## 1. Context

### 1.1 What M03 must deliver

Plan §5 M03 maps onto ADR-0005 §12 ("M03 mapping"). The table below adds what already exists and what
this ADR adds.

| Task | Plan wording | Exists (M01/M02) | Added here |
|---|---|---|---|
| T01 | protected managed execution-key/signer path and secret lifecycle; issuer authority separate | The signing endpoint framer and allow-list (`ipc::signing`). `EndpointKind::Issuer`. The issuance records, predicate and residual (`domain::issuance`). The reserve, publish and void operations (`Operations::{reserve_issuance, publish_issuance}`). The shared time gate | **D1** custody, **D2** signer, **D3** issuer, **D4** issuer lifecycle and the D5 backup |
| T02 | scoped enrollment with independent fresh-login verification, preserved fallback, reconciliation after uncertainty | Journaled operations, effect tokens, stage receipts and recovery intents. Attended decision records. `EffectClass::RemoteMutation` (declared, unused) | **D5** enrollment transaction |
| T03 | certificate acquisition and renewal; report actual offline coverage and refresh dependencies | `PrepareOutcome.{usable_until, offline_until, refresh_dependency}`. `CredentialAvailability` | **D6** acquisition, re-issue and coverage. **D12** reports |
| T04 | grant deadlines, locally immediate revocation, remote pending state, parent cascade | Tombstones, generation, cascade, child-owned parent references, remote-revocation obligations, release semantics (ADR-0006 §13.1 item 2, §13.3 item 1) | **D7**: managed revocation and time-bounded remote obligations |
| T05 | ordinary and strict connection policies; verify multiplex admission stopping | `ExistingConnectionsPolicy`. Holders (`ProcessHolder`, `BindForm::Launch`) | **D8** connection policies and owned masters |
| T06 | fresh connections after desktop/vault lock on actual targets; rotation; wrong-host principals; source-provider failure | ADR-0005 recovery rule §3.7. The lock probes P1 and P-W1, which are still blocked | **D9** lock behaviour, **D10** consumer integration, **D11** rotation and failure handling, **D13** test environments |

### 1.2 Facts this design depends on

| # | Fact | Source / status |
|---|---|---|
| M-F1 | The client signs only after the server accepts the offered key at the query stage. In E1, one login produced one agent sign request. A principal mismatch was refused at the query stage | [I]; [O:E1]; [O:P5]. Settled per client by `verify_negative_records_zero_signatures` (m03-plan U5) |
| M-F2 | OpenSSH clients send `session-bind@openssh.com` to the agent before signing in a key-exchange-bound authentication. It carries the server host key, the session identifier, the host's signature and an `is_forwarding` flag | [S03]; which clients send it is `[U]`, settled by `session_bind_observed_per_client` (U2) |
| M-F3 | `IdentityAgent` overrides `SSH_AUTH_SOCK`. So a per-binding `SSH_AUTH_SOCK` never reaches an alias whose section in P sets `IdentityAgent` | [S01]; ADR-0007 F8 |
| M-F4 | `IdentityFile` and `CertificateFile` accumulate. P cannot remove a user's inherited entries for a managed alias | [S01]; ADR-0007 F2, §3 item 3 |
| M-F5 | `ControlMaster no` with a `ControlPath` uses an existing master on that path if one exists, and otherwise connects normally. `ControlPath none` disables multiplexing | [S01] ("Additional sessions can connect to this socket using the same ControlPath with ControlMaster set to no") |
| M-F6 | `ssh -O exit` ended the master, its sessions and pre-accepted control connections. `-O stop` left pre-accepted connections admitting sessions and forwards | [O:E7][O:E7P]; F-7 triggered |
| M-F7 | Win32-OpenSSH does not support connection multiplexing (`ControlMaster`) | [I]; settled by `windows_owned_multiplexing_reported_unavailable` (U7) |
| M-F8 | `cert-authority,principals="…"` on a registry line restricts the accepted principals ("most restrictive union") | [S:sshd.8]; [O:E4] |
| M-F9 | sshd refuses new authentication outside `[valid_after, valid_before)`. The destination clock error is unmeasured by Heimdall | [O:E2]; ADR-0005 §3.6 |
| M-F10 | POSIX `sh`: `>>` opens with `O_APPEND`; `set -C` makes `>` refuse an existing file; `mv` within one directory is `rename(2)`; `cmp`, `od`, `ls -ldn`, `id -u`, `tail -c`, `grep -F` and `awk` are POSIX utilities | [I] (POSIX.1-2017, not pinned). Settled per remote shell by `registry_protocol_on_target_shell` (U5: dash on Debian 13 and Ubuntu 24.04, macOS `/bin/sh`) |
| M-F11 | sshd `StrictModes` refuses a registry in a group- or world-writable directory or file | [S05] |
| M-F12 | macOS: `CGSessionCopyCurrentDictionary()` reports `CGSSessionScreenIsLocked`; the distributed notifications `com.apple.screenIsLocked` and `com.apple.screenIsUnlocked` signal changes | [I]; settled by `macos_lock_signal_observed` (U9, during the P1 run) |
| M-F13 | Windows: `WTSRegisterSessionNotification` delivers `WTS_SESSION_LOCK` and `WTS_SESSION_UNLOCK`; `WTSQuerySessionInformationW(WTSSessionInfoEx)` reports the session's lock state | [I]; settled by `windows_lock_signal_observed` (U9, during the P-W1 run) |
| M-F14 | Linux: systemd-logind exposes `LockedHint` and emits `Lock`/`Unlock` for a graphical session | [I]; blocked on B11 (no Linux desktop host) |
| M-F15 | DPAPI CurrentUser unprotects across processes. Under lock it is `[U]` | [O:WSS]; P-W1 |
| M-F16 | `ssh-key` 0.6.7 builds and signs OpenSSH user certificates with Ed25519 (`certificate::Builder`), and writes OpenSSH private keys encrypted with bcrypt-pbkdf and aes256-ctr (`encryption` feature) | [I]; settled by `certificate_accepted_by_fixture_sshd` (U1) and `d5_backup_restores_with_stock_ssh_keygen` (U4) |
| M-F17 | An `IdentityFile` naming a `.pub` whose private file is absent selects the agent's matching key | [S01]; ADR-0007 F9 |
| M-F18 | Win32-OpenSSH uses an agent-held certificate through a named pipe given as `IdentityAgent //./pipe/<name>` together with `CertificateFile` | [I]; settled by `windows_ssh_certificate_through_heimdall_pipe` (U8) |
| M-F19 | A Unix process with `PR_SET_DUMPABLE` 0 (Linux) cannot be ptrace-attached by another process of the same user without `CAP_SYS_PTRACE`, and dumps no core | [I]; Yama's `ptrace_scope` changes the default. Settled by `linux_signer_not_ptraceable_by_same_user` (U1; `ptrace_scope` recorded), ⟨r2⟩ with a dumpable positive control attached the same way (F22) |
| ⟨r2⟩ M-F20 | ssh_config(5) documents `none` for `IdentityFile` ("no identity files should be loaded") but **not** for `CertificateFile`: "Multiple CertificateFile directives will add to the list of certificates used for authentication". `IdentityAgent` takes the first value obtained, and the command line is read first | [S01] (pinned snapshot `docs/sources/snapshots/S01.txt.gz`); what each client does with `-o CertificateFile=none` is `[U]`, settled by `certificate_file_none_behaviour_recorded_per_client` (U5). See Q19 |
| ⟨r2⟩ M-F21 | ADR-0007 §8 and §11 rejected a kill-on-close job object for Windows `run`: it "kills grandchildren left running on purpose after a normal exit; not exec-equivalent". M02's probes already use a kill-on-close job with assignment after spawn (`localenv::local_query`, `localenv::sys::JobObject::assign_child`) | Observed in the code at `7f6f1c05`. See D8 item 2 and Q18 |
| ⟨r2⟩ M-F22 | `ssh -v` writes the remote software version, the host-key match, each public key or certificate offered, the server's acceptance or "Authentications that can continue", and the final authentication result to stderr. The exact wording is client-version-specific | [I]; the per-client patterns are recorded and tested by `verify_trace_patterns_per_client` (U5); an unrecorded client is `verification_inconclusive` (D5 §6.5) |
| ⟨r2⟩ M-F23 | POSIX `mkdir` fails if the directory exists (an atomic test-and-create, usable as a lock); ⟨r7⟩ the remote clock is read as POSIX `date -u '+%Y %m %d %H %M %S'`, converted to seconds since the Epoch in `awk` by civil-from-days, and used only within 2000–3000 UTC (otherwise unmeasured); POSIX `date` has no `%s` (§17.17 item 7) | [I] (POSIX.1-2017, not pinned). ⟨r7⟩ Observed: Debian 13's mawk 1.3.4 prints **nanoseconds** from `srand()`, so revision 2's `awk 'BEGIN { srand(); print srand() }'` reading is not used (U5S-Q1, INT-Q3). Settled per remote shell by `registry_protocol_on_target_shell` and `remote_clock_reading_per_target` (U5) |
| ⟨r2⟩ M-F24 | `rusqlite` transactions release the store's connection mutex when they return (`crates/store/src/lib.rs` `transaction`), so an authorization read cannot by itself hold anything across the signature | Observed (R01) |
| ⟨r3⟩ M-F25 | The host-trust sources of the pinned ssh_config(5): `UserKnownHostsFile` (`none` documented); `GlobalKnownHostsFile` (no `none` documented); `KnownHostsCommand`, which supplies "a list of host keys, in addition to those listed in UserKnownHostsFile and GlobalKnownHostsFile" (no `none` documented); `VerifyHostKeyDNS yes`, under which "the client will implicitly trust keys that match a secure fingerprint from DNS"; `UpdateHostKeys`, which adds server-sent keys to `UserKnownHostsFile`; `CheckHostIP yes`, which adds addresses "regardless of the setting of StrictHostKeyChecking"; `NoHostAuthenticationForLocalhost`, which can "disable host authentication for localhost". Command-line options are read first, and the first value obtained wins. `IgnoreUnknown` "will not be applied to unknown options that appear before it" | [S01], [S02] (pinned snapshots). Observed by reviewer A (OpenSSH 10.5p1, loopback): key A was approved in the generated file, the server's key was B, and an inherited `KnownHostsCommand` printed B. ssh accepted B (exit 0). With `-o KnownHostsCommand=none` it failed host verification (exit 255). Whether `none` is a keyword or a command name is Q22 |
| ⟨r3⟩ M-F26 | `sh -s` executes each complete line of its input as it arrives, so a truncated script runs its prefix and can exit 0 | Observed by reviewer B with `/bin/sh` and `dash`: the prefix created the lock and the token. Settled by `truncated_script_does_nothing_at_every_truncation_point` (U5) |
| ⟨r3⟩ M-F27 | A `cert-authority` line **without** `principals=` accepts only certificates whose principals include the account name, so it refuses **both** verification certificates. With `principals="hm:dst1:acct"`, the positive is accepted and the negative refused | Observed by reviewer B (OpenSSH 10.5p1, loopback, scratch CA). The `principals_not_enforced` fixture is rebuilt on this (D13 item 2) |
| ⟨r3⟩ M-F28 | `ssh -G` with D8's dedicated options kept an inherited `ForkAfterAuthentication yes`. `-f` sets the same option from the command line | Observed by reviewer A. D8 item 2 pins it |
| ⟨r3⟩ M-F29 | With revision 2's maintenance pins, `SSH_AUTH_SOCK` pointing at a fixture managed agent and the managed `IdentityFile` and `CertificateFile` inherited, ssh authenticated with the managed certificate (exit 0) despite `CertificateFile=none`. M02's launcher sets `SSH_AUTH_SOCK` to the binding endpoint for a managed `run` (`launch/src/env.rs`) | Observed by reviewer A (loopback), and in the code at `95603af6`. D5 §6.3 now resolves the endpoint without `SSH_AUTH_SOCK` |
| ⟨r3⟩ M-F30 | **Process identity on a target.** POSIX `ps -o` names `pid`, `ppid`, `pgid`, `etime`, `comm` and `args`, but no start time: `lstart` is a BSD and procps extension, and BusyBox `ps` lacks it. Linux `/proc/<pid>/stat` field 22 is the start time in clock ticks since boot, and `/proc/sys/kernel/random/boot_id` names the boot. POSIX `kill` with a negative PID signals a process group, and a process ID is not reused while a process group with that ID exists. sshd runs a non-pty session's command in a new session, so the `$$` of `exec /bin/sh -s` is its process-group leader | [I] (POSIX.1-2017 and OpenSSH `session.c`; neither is pinned). Settled per target by `start_identity_per_target_shell` and `holder_is_process_group_leader_per_target` (U5) |
| ⟨r3⟩ M-F31 | POSIX `ln -s <contents> <name>` creates a symbolic link in one `symlink()` call and fails if `<name>` exists. The exception is an existing **directory** at `<name>`: `ln` then creates the link inside it. `ls -l` prints a link as `<name> -> <contents>` | [I] (POSIX.1-2017, not pinned). Settled by `lock_symlink_is_exclusive_per_target` (U5) |
| ⟨r3⟩ M-F32 | `awk`'s `printf "%c"` depends on the locale. bwk awk 20200816 writes one byte for a code of 128 or more; gawk in a UTF-8 locale is reported to write a multibyte sequence | Observed for bwk awk by reviewer B; gawk is [I]. The scripts set `LC_ALL=C` (D5 §6.3). Settled by `non_ascii_registry_bytes_per_target_shell` (U5) |
| ⟨r4⟩ M-F33 | dash's built-in `kill` rejects `kill -0 -- -PGID` ("Illegal number: -", exit 2), and accepts `kill -s 0 -- -PGID` (exit 0 on a live group); `/bin/kill -0 -- -PGID` exits 0. POSIX `kill` recognizes the symbolic name `0` for `-s`, and POSIX `ps` has `-A` and the `pgid` field. Today's signing transport awaits `write_all` and then `flush` on the socket inside the request path (`ipc/src/signing.rs`) | Observed by the round-3 re-check (scratch model) and in the code at `3d335e7d`; the POSIX statements are [I] (POSIX.1-2017, not pinned). Settled per shell by `group_probe_and_listing_per_target_shell` (U5) |
| ⟨r5⟩ M-F34 | **The per-shell group proof, as observed.** dash 0.5.12-12, bash 5.2.37 as `sh` and macOS `sh` (bash 3.2.57) classify a live child `live` (C/K/L 0/0/0), an empty group `empty` (0/1/0), and invalid syntax and injected disagreements `unproven`. BusyBox 1.37.0 `ash` rejects `--` in `kill` ("invalid number '--'"), so every case is `unproven`. BusyBox `ps` rejects `-p` (exit 1). bash as `sh` printed argument errors for a malformed option and still returned 0. A genuine same-user `EPERM` could not be produced | Observed by the round-4 re-check (`round4-recheck-codex.md`), in containers from pinned official images and on native macOS. D5 §6.3's shell table records it; Q29 |
| ⟨r6⟩ M-F35 | `/proc/<pid>/stat` field 2 (`comm`) is written in parentheses and may contain spaces, `(` and `)`; the state, ppid and pgrp follow it (Linux v6.12 `fs/proc/array.c`). A whitespace count misreads the process group as soon as `comm` holds a space or a `)` | Observed by the round-5 check (`round5-final-codex.md`): in a container where only `comm` changed and the real process group was 1, `$5` gave 1, 0 and `(` for `plain`, `has space` and `a ) b ( c`; the suffix rule gave 1 each time. D5 §6.3's shared parser |

### 1.3 ADR-0005 §9.3: where each open item goes

| ADR-0005 §9.3 item | Disposition in M03 |
|---|---|
| P1 screen lock, Heimdall signer (macOS) | A03 macOS lock row (D9, D13; m03-plan U13). Runnable under the ADR-0004 §2 lock rule; the harness checks idle time and lock state itself |
| P1 extension, ephemeral Secure Enclave K_env | Not in M03: hardware K_env goes to M04 (D1; §16) |
| P5 lock row (CTK) | M04 (it concerns K_A or hardware candidates; no CTK key is used in M03) |
| X4 Windows stores | Done for mechanics [O:WSS]. Cross-user is blocked on B2. The DPAPI rows run as product custody (D1) |
| P-W1 Win+L: DPAPI, CNG, TPM, Heimdall signer | A03 Windows lock row covers the DPAPI unprotect plus the Heimdall signer. CNG and TPM go to M04 with Recipe A and hardware K_env |
| P-L1 Linux desktop lock | Blocked on B11 (no Linux desktop host) |
| P2, P3, P-W2, P-L2 logout, reboot, headless | Blocked on B12 (an operator for logout and reboot cycles); M04-T04 owns their closure. M03 runs the same-boot process-restart row natively |
| P4 sleep across a deadline | Blocked on B12. Covered by virtual-clock tests and the per-signature wake check (D2) |
| P6 data-protection keychain | Blocked on B13 (Apple Developer membership, G04 D3) |
| Login keychain item for an ad-hoc-signed issuer, across updates | Blocked on B3 (a disposable macOS account; tests never touch the owner's keychain). M03 tests the code path against a disposable file keychain, labelled "mechanism, not the product item" |
| Restricted extension profile, including forwards through a live master without `permit-port-forwarding` | U1 and U7 tests; A23 |
| Key destruction makes outstanding certificates unusable; issuer refusal property tests; D5 restore with stock `ssh-keygen`; DH Secret Service session on a real desktop | U2, U3 and U4. The desktop Secret Service part is blocked on B11 |
| Registry interleaving (R1) | U5 with U11's pause hooks; A09 |
| Production verification on an account that cannot read the sshd log (R5) | U5 against the Docker `enrollable` account (macOS build host) and the WSL disposable distribution's non-root account |
| Issue/revoke linearization (R2, R12) | U3 (the model, `tests/model/issuer_linearization.rs`) and U6 (fixture). ⟨r2⟩ The model also covers re-issue racing revocation and a lock revocation (F24), and the signing gate (D2 item 3a). The runner delivery rows go to M06 |
| Time A08 cases (R3, R9) | M01 has the model. M03 adds signer and issuer wiring tests on the virtual clock (U2, U3, U6) |
| Synchronized-time signals (R9) | Observation only in M03 (D12 item 5; Q13). Trust stays off until M04/G09 evidence |
| Runner deadline (R10) | M06 (G07) |
| Recovery per lifecycle event (R4) | Process restart runs natively in M03 (U6, U13). Logout and reboot are blocked on B12 |
| Key-only restore (R6, R11) | U4 fixture test |
| A03, A07, A09, A10, A23, A33 with Heimdall code | This ADR. A24 goes to M06 and A28 to M05 |

---

## 2. D1 — Key custody per platform

**Decision.** Five key classes, with custody as follows. "Memory" means the `KeyVault` of D2.

| Class | Generation | macOS | Windows | Linux desktop | Linux headless, WSL, container, runner | Destruction |
|---|---|---|---|---|---|---|
| **K_env** (one per grant and per delegated child) | Signer, at activation or re-issue, from the OS CSPRNG through `ssh-key`'s Ed25519 generation | Memory | Memory | Memory | Memory, but only where an issuer can certify it. M03 has no remote issuer, so these environments have no product K_env yet | Zeroized at grant end (expiry, cutoff, revocation, release of the last reference), at `TIME_UNCERTAIN` closure, and at process exit |
| **K_verify** (one per enrollment verification) | Verification signer (D5 §6.5) | Memory | Memory | Memory | Memory (WSL distribution only, for mechanism tests) | Zeroized when the verification ends (pass, fail, timeout or drop), and at process exit |
| **K_ca** (one per owner per issuing device) | The issuer module, in the owner-present CLI ceremony (D4) | Login-keychain generic-password item; its access list (SecAccess) trusts only the `heimdall` executable; the issuer never allows user interaction on reads (pre-D3, ADR-0005 §5.2). After D3: the data-protection keychain | DPAPI CurrentUser blob with Heimdall entropy, `CRYPTPROTECT_UI_FORBIDDEN`, in a Heimdall file under the local, non-roaming application-data directory with an owner-only protected DACL | Secret Service item in the login collection, read over a DH-encrypted session | **None.** The issuer is unavailable: `CAPABILITY_UNAVAILABLE`, reason `issuer_store_unavailable`. K_ca never reaches these environments (spec §6.5, §7.3) | Store item deleted by exact identity, memory zeroized, lines removed (D4) |
| **D5 backup of K_ca** | The CLI ceremony | A file at an owner-chosen path; OpenSSH private-key format encrypted with bcrypt-pbkdf and aes256-ctr; generated passphrase shown once on the TTY | Same | Same | Not applicable | The owner destroys it |
| **Test K_ca** | The ceremony, under the test configuration only | `ScratchSecretStore`: the D5 format, encrypted with a per-run passphrase, under the scratch state directory. Compiled only into test-configured builds, never into release builds (the M01 `testcfg` pattern). ⟨r2⟩ It lives in `heimdall-testkit` (feature `managed`), implements the `SecretStore` trait U0 freezes in `heimdall-issuer::store`, and its store kind is not in the public schema (F23). Evidence produced on it never satisfies a product-store claim (D12) | Same, or real DPAPI on a scratch path, which ADR-0004 §3 authorizes. ⟨r2⟩ A **release-profile** build run with `HEIMDALL_HOME` pointing into scratch uses the product DPAPI store kind at a scratch path; that is product-store evidence (D12, §4.4 of the plan) | Same | Same | Scratch removal |

**The `KeyVault`** (`heimdall_credential::vault`). Secret keys live in a `SecretKey` type with these
properties:
* it has no `Clone`, `Debug`, `Display`, `Serialize` or `Deserialize`;
* its only operation is `sign(&self, data) -> Signature`;
* it zeroizes on drop (`zeroize`).

Its pages are locked against swap where the platform allows: `mlock` on Unix, `VirtualLock` on Windows.
A lock that fails is recorded as a degraded mitigation and does not refuse the key.

Process-wide mitigations are applied at runtime start and in the issuer child:
* Linux: `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0)`;
* macOS: `setrlimit(RLIMIT_CORE, 0)`;
* Windows: no additional mitigation (disclosed).

These are **mitigations, not a boundary** (ADR-0005 §3.6). The same OS user is still the boundary
(`workload_isolation: shared_os_user`, `issuer_isolation: same_user_process`).

**Store availability.** Each store reports one of `available`, `locked`, `interaction_not_allowed`,
`missing`, `corrupt` or `unsupported`.
* Anything but `available` makes the issuer unavailable: new activations and re-issue fail with
  `CAPABILITY_UNAVAILABLE`, reason `issuer_store_locked` or `issuer_store_unavailable`.
* There is never a fallback: no plaintext file and no other key (spec §7.3, §15.2).
* The issuer never triggers a store prompt. On macOS it disallows user interaction for the read, and
  `errSecInteractionNotAllowed` maps to `interaction_not_allowed`.
* A prompt, if one is needed, happens only in the owner-present `heimdall issuer unlock` flow (D4).

**What each platform must prove** is listed in m03-plan §4.2. Lock continuity is claimed per platform
only through the claim table (D12).

**Rationale.**
* ADR-0005 §5 fixes these stores.
* K_verify is a new private-key class, and spec §7.3 requires custody rules for every class.
* `ScratchSecretStore` lets every platform run the signer and issuer mechanism without touching an owner
  store (AGENTS.md). Its rows are labelled fixture custody and never count as product-store evidence.

**Rejected:**
* **A hardware K_env in M03** (Secure Enclave, TPM). The P1 and P-W1 hardware rows need runs that M03
  does not have; ADR-0005 §13 lists it as a reopen path. It goes to M04.
* **Persistent K_env on any platform.** It adds an at-rest copy for no local gain (ADR-0005 §3.7).
* **K_ca regenerated at each start.** Every boot would need re-enrollment.
* **A K_ca file encrypted with a passphrase asked at start.** It needs a prompt per login, which defeats
  unattended work.
* **K_ca in the state database.** The database holds references, not secrets (spec §13.3).
* **Kernel keyrings** (ADR-0005 §5.2).

---

## 3. D2 — The signer: in-process, per-signature authorization, three endpoint kinds

**Decision.**

1. **In-process.** The signer runs inside the per-user runtime process (`heimdall service run`), with
   its keys in the `KeyVault`. There is no separate signer process.

2. **Endpoints.** All three kinds use M01's transport and peer check (owner-only Unix socket in a 0700
   directory with a peer-UID check; owner-only named pipe with a client-SID check; ADR-0006 §2.1).

   | Endpoint | Unix path | Windows pipe | Lists | Created / removed |
   |---|---|---|---|---|
   | **Environment** | the existing `<runtime_dir>/signing.sock` | `\\.\pipe\heimdall-<installation token>-signing` (stable; D10 item 1) | K_env public key and per-pair certificates of each **materialized** managed binding (D10). At most one binding per pair | At runtime start / at stop |
   | **Per binding** | `<runtime_dir>/b/<16 hex>/agent.sock`, its directory 0700 | `\\.\pipe\heimdall-<token>-b<16 hex>` | The binding's grant only: its K_env and its certificates | At the binding's preparation / at the grant's end. A generation-tagged `ManagedResource` (`Endpoint`) removed by the cleanup executor |
   | **Verification** | `<runtime_dir>/v/<16 hex>/agent.sock` | `\\.\pipe\heimdall-<token>-v<16 hex>` | K_verify and the verification certificate currently in use | At the verification's start / at its end |

   The 16 hex characters are random and never derived from IDs or labels (g03 §3.1 N2). No endpoint ever
   lists K_ca. No endpoint answers anything but list, sign and `session-bind@openssh.com` (ADR-0006 §2.6
   allow-list).

3. **Per-signature authorization.** Every sign request, on every endpoint, runs through
   `SignatureAuthority`, which the application's `Operations` implements. Nothing is cached, and
   authorization runs **after** the request has been parsed and **before** the key signs. ⟨r2⟩ It is
   bound to the signature by the signing gate of item 3a: the check that admits a signature is the
   fresh read taken **under** the gate. It checks, in one read transaction plus the ⟨r2⟩ read-only time
   assessment (`TimeGate::assess_read_only`, which writes no high-water mark; F21):
   * the key belongs to a grant served by this endpoint, or for a verification endpoint, to its
     enrollment operation;
   * for a grant, ADR-0005 §3.6 in full:
     * state `active`, or `degraded` for a reason that permits use. `mechanism_unavailable` refuses;
       `credential_reissue_pending` has no key to sign with;
     * the last validated generation is current, re-validated automatically under ADR-0006 §13.5
       ruling 2;
     * no tombstone on the grant or an ancestor;
     * the admission deadline: the wall-clock bound and the continuous budget (`TimeGate` plus
       `time::admission`);
     * time `Safe`;
     * the mechanism is configured;
     * if the grant's lock behaviour is `revoke_on_lock`, the session-lock source reports `unlocked`
       (D9, a backstop for a lock event still in flight);
   * for verification, the D5 §6.5 predicate.

   The result is ⟨r2⟩ `Admit(SignPermit)` or `Refuse(reason)`. A refusal returns `SSH_AGENT_FAILURE`,
   and no reason is sent to the client. The audit event records the reason as a nonsecret code, and the
   `CredentialLifecycle` events are rate-limited per grant to 1 per second. Authorization is bounded by
   `signature_authorization_timeout` (2 s); a timeout refuses.

3a. ⟨r2⟩ **The signing gate: one linearization point for signing and narrowing** (§17.1 item 1;
   M03-R01, F12). The store releases its transaction and its connection mutex when an authorization
   read returns (M-F24), so a read alone cannot keep a revocation from committing between it and the
   signature. Each grant therefore has a **signing gate**, an async reader-writer lock held by the
   application (`app::managed::SigningGates`, one per grant, created with the grant's first credential
   instance and dropped with its last).
   * **A sign request** goes through these steps:
     1. parse and purpose-check (item 4);
     2. a **pre-check** authorization (an unlocked read, used only to refuse early). ⟨r4⟩ It also
        refuses at once when a narrowing has marked the grant pending (below). ⟨r5⟩ It is an
        optimization only: it never admits, and passing it proves nothing (§17.10 item 1; M03-R4-01);
     3. take the grant's gate **shared**, waiting at most `signing_gate_wait` (1 s), else refuse;
     4. a **fresh** authorization read under the gate. This is the check that admits.
        * ⟨r5⟩ **Its first check is pending** (§17.10 item 1). It runs right after the awaited gate
          acquisition, before any store read: if the grant **or any ancestor** is marked
          `narrowing_pending`, the request is refused and the gate released at once. The check is an
          in-memory lookup that never awaits, so a request that took the gate after a mark holds it
          only for that lookup;
        * ⟨r3⟩ It returns a `SignPermit` that carries an **absolute expiry**: the earliest of the
          grant's wall-clock deadline, the end of its continuous budget, every applicable admission
          limit, and the holder bound (this step's start + `signing_holder_max`) (§17.4 item 6;
          A R2-06, B R2-01);
     5. `KeyVault::sign`.
        * ⟨r3⟩ It runs on the blocking pool under `signing_budget` (1 s). The async task that holds
          the gate awaits it with that timeout.
        * On overrun the task drops the permit and the gate. When the late signature arrives, it finds
          no permit and is discarded;
     6. ⟨r4⟩ **reserve outbound capacity** for the complete response frame (§17.7 item 2; M03-R3-02).
        * The connection's outbound queue is bounded, and one reservation holds room for one whole
          frame.
        * The wait is bounded by `signing_enqueue_timeout` (2 s), and **the permit's expiry cancels it**,
          whichever comes first.
        * On timeout the signature is discarded and the connection is closed without a reply.
        * On expiry the signature is discarded, and the reply becomes `SSH_AGENT_FAILURE`, sent once
          capacity frees within the same 2 s, or the connection is closed;
     7. ⟨r3⟩ **the release check**, ⟨r4⟩ immediately before the enqueue, with the capacity already held.
        ⟨r5⟩ Three things must hold:
        * the permit has not expired, on both clocks;
        * the read-only time assessment is still `Safe`;
        * ⟨r5⟩ neither the grant nor any ancestor is marked `narrowing_pending` (§17.10 item 1). So a
          request admitted before a mark is not released after it;

        If either fails, the reserved room carries `SSH_AGENT_FAILURE` instead of the signature;
     8. ⟨r4⟩ **the enqueue**: the complete frame goes into the reserved room. It **cannot wait**: the
        capacity was taken at step 6, and nothing between step 7 and this step blocks. A writer task
        drains the queue to the socket afterwards, outside the gate;
     9. release the gate.

     The `SignPermit` returned at step 4 is the shared guard.
     * ⟨r3⟩ It crosses into `ipc` as an opaque `ipc::signing::PermitGuard`, a boxed `ReleaseCheck`
       trait object defined in `ipc` (§18). `ipc` therefore needs no edge to `app`. ⟨r4⟩ The trait
       gives both `may_release()` and the expiry instant that cancels step 6's wait.
     * `ipc::signing::serve` runs steps 6–8 through it, and drops it only after step 8. ⟨r4⟩ It no longer
       awaits `write_all` and `flush` on the socket inside the signing path (today's
       `ipc/src/signing.rs`; M-F33).
     * **The enqueue at step 8 is the linearized effect.**
     * ⟨r3⟩ So a request admitted just before D is never released after D, even when no state changes
       in between. ⟨r4⟩ Expiry is checked at the moment of release, because the only wait (for
       capacity) happens before the check, and the expiry cancels it.
   * **Narrowing commits:**
     * a revocation (explicit, cascade, `revoke_on_lock`, and authority withdrawn at re-validation);
     * a cutoff that is set or moved earlier;
     * an environment-permission removal;
     * an enrollment hold or removal that degrades a pair (D5 §6.8);
     * every other change that narrows a grant.

     Each takes the gate **exclusively**, for every grant it affects (the cascade included), **before**
     its store commit. ⟨r3⟩ The rest of the order is §17.4 item 6's (B R2-03), ⟨r4⟩ as amended by §17.7
     item 3 (M03-R3-03):
     * **Lock order.** Gates are always acquired in one global order: **ancestors first, then by grant
       ID** (sorted by delegation depth, then ID). ⟨r4⟩ **Every gate a narrowing holds was acquired in
       that order**: a narrowing never acquires a gate that sorts before one it already holds.
       * A signer holds one gate and waits for nothing else.
       * ⟨r4⟩ A delegation holds the gates of the parent **and of every ancestor**, taken shared in global
         order (root first), until the child's first install (Q26).
       * So no wait cycle can form between two narrowings, between a narrowing and a delegation, or
         between a narrowing and a signer.
     * ⟨r4⟩ **The pending mark.** Before it waits for any gate, a narrowing marks every grant of the set
       it read as `narrowing_pending`, in memory. ⟨r5⟩ The mark is **authoritative** (§17.10 item 1;
       M03-R4-01). Revision 4 checked it only in the unlocked pre-check, so a request that passed the
       pre-check before the mark could still take a gate and sign after it, and descendants found in
       round 1 stayed unmarked (the re-check's executable model reached a commit at 24.6 s):
       * **Coverage.** A grant is pending when it **or any ancestor** is marked. Each gate records its
         grant's ancestor chain when it is created (bounded by M01's ancestor-chain limit), so the check
         walks that chain in memory. A descendant created or found later is covered from the moment it
         exists.
       * **Signers.** The mark is checked in the pre-check (an optimization), **first in the fresh read
         under the gate** (step 4, after the awaited acquisition), and **again in the release check**
         (step 7).
       * **Delegations.** A delegation from a pending grant refuses to start. It checks the mark again
         after **each** awaited ancestor-gate acquisition, and once more just before the child's first
         install. A mark found at any of these points aborts it fail-closed: the child's instance is
         destroyed, and its entries stay counted.
       * So a holder that acquires a gate after the mark releases it at once, and only holders admitted
         before the mark can make a narrowing wait.
       * Marks are counted per narrowing, so overlapping narrowings do not clear each other's marks. A
         narrowing clears its own marks when it releases its gates, or when it aborts.
     * ⟨r4⟩ **The set is re-validated under the gates; if it grew, everything is released and
       reacquired once** (§17.7 item 3):
       1. **Round 0.** Read the set; acquire its gates in global order; re-read the set in a
          transaction. Unchanged: continue.
       2. **Round 1**, only if the re-read found new descendants:
          * ⟨r5⟩ **first** mark every newly found descendant `narrowing_pending`, **before any gate is
            released** (§17.10 item 1). The ancestor check already covers them; the explicit mark keeps
            them covered even when their marked ancestor is outside the narrowing's own set;
          * release **every** gate;
          * reacquire in global order;
          * as soon as the gate of each **root** of the set is held (a member whose parent is not in
            the set), read that root's subtree again and add any new member (each is deeper than the
            root, so it sorts after every gate already held);
          * when all are held, re-validate: the re-read must equal the set.

       **Why one round suffices.** Every delegation holds its whole ancestor chain shared, the root
       included. So once the narrowing holds a root exclusively, no member can be added anywhere in
       that root's subtree. Every subtree is therefore frozen from the moment its root is held, and the
       round-1 re-validation cannot grow the set. ⟨§17.14⟩ A re-validation that nevertheless differs
       is a defect. It is reported (`narrowing_set_grew`), and the narrowing runs a further round
       under the same rules: mark the new members, release every gate, reacquire in global order,
       re-validate. A revocation is never left uncommitted. The pending marks already stop new
       signatures and delegations, so an extra round costs only time, which is reported.
     * **Order within a narrowing:**
       1. acquire the gates (rounds 0 and, if needed, 1);
       2. commit;
       3. ⟨r6⟩ zeroize the keys and unlist the identities **while the gates are held**. This is in-memory
          work, bounded per grant by `ε` (§17.4 item 6: keys are destroyed and identities unlisted under
          the gate);
       4. release the gates, ⟨r4⟩ and clear the pending marks;
       5. ⟨r6⟩ **then the cleanup**, outside every gate (§17.13 item 1; §17.4 item 6): remove the slot and
          binding files, and close processes, both owned masters and owned dedicated connections (D7
          item 2, D8). Revision 5 removed the files under the gates, so another narrowing waiting for
          those gates also waited for file I/O (M03-R5-01).

       Neither file removal nor process closing ever happens under a gate. So a 5 s master close, or a
       slow file system, cannot lengthen a signer's or another narrowing's wait.
     * ⟨r6⟩ **Earlier marks go first** (M03-R5-01, overlapping narrowings). Each narrowing gets a
       sequence number when it sets its marks. Before it queues for a gate, it checks whether that grant
       is covered (itself or an ancestor) by the mark of a still-running narrowing with a **smaller**
       sequence number. If so, it waits for that narrowing to finish instead of queuing.
       * So a later narrowing never holds a gate that an earlier one still needs, and an earlier
         narrowing never waits for a later one. Without this rule, a later narrowing could take a gate
         during an earlier one's round-1 release and hold it through its own wait.
       * Deadlock cannot arise. A narrowing that defers holds only gates the earlier narrowing does not
         cover; if the earlier one covered any of them, it would have deferred there first.
     * **No gate, no narrowing.** A narrowing never commits without every gate it needs. ⟨r6⟩ **It is
       never aborted for time** (§17.13 item 1). It waits until it holds its gates, because every holder
       of a gate is individually bounded. Its commit time, `committed_at − requested_at`, is
       **reported**, together with the derived bound below and the terms it used.
       * **The holders, all counted** (⟨r6⟩ revision 5 omitted the last two):
         * a signer: `signing_holder_max` (5 s: a 2 s fresh read, a 1 s signature and at most 2 s
           waiting for capacity), enforced by the permit's expiry and the cancellations above;
         * a delegation: `delegation_gate_hold_max` (10 s), aborted fail-closed on overrun;
         * ⟨r6⟩ a **connection registration** (D8 item 2, Windows): one store transaction under the gate
           taken shared, at most `connection_registration_txn_max` (2 s). It checks the mark first, and
           a registration that finds it refuses (`connection_registration_refused`, reason
           `narrowing_pending`; the launcher kills the still-suspended child), so only registrations
           admitted before the mark can make a narrowing wait;
         * ⟨r6⟩ **another narrowing**: under "earlier marks go first", only narrowings with a smaller
           sequence number can make this one wait. Each holds its gates through its acquisition, its
           commit and its in-memory key destruction, and never through cleanup.
       * `H` = `signing_gate_max_wait` = 10 s, the largest of the first three bounds.

       ⟨r4⟩ Revision 4 stated the bound as `(rounds + 1) × signing_gate_max_wait` = 20 s, and ⟨r5⟩ revision
       5 re-derived it as `signing_gate_max_wait + 2·n·ε + 3·t_read`. ⟨r6⟩ That undercounted the round-1
       reads: with `r` roots, round 1 reads `r` subtrees and then re-validates, `(r + 1)·t_read`. The
       re-check's forest (8 roots, 9 grants, a pre-mark delegation ending at 9.9 s, 2 s reads)
       committed at 29.9 s, against 16.0 s predicted, and enforcing a 20 s ceiling would have aborted a
       valid narrowing. Revision 6 restates the bound (§17.13 item 1).

       ⟨r6⟩ **The derived bound.**
       * **Notation**, for a narrowing N:
         * `n` is the number of grants in its set;
         * `r` is the number of roots of its set (members whose parent is not in the set);
         * `t₀` is the moment it sets its marks;
         * `E(N)` is the set of still-running narrowings with a smaller sequence number whose marks
           cover a grant in N's set.
       * **Assumptions:**
         * A1. Every gate holder admitted **before** its covering mark ends within its own bound, so
           within `H` of that mark.
         * A2. Every holder that acquires a gate **after** a covering mark finds it at its first check,
           and releases the gate after an in-memory lookup that never awaits (`ε`).
         * A3. Gates are fair: once a narrowing queues for a gate exclusively, no later shared request is
           granted ahead of it (`gate_is_fair_writer_not_starved`).
         * A4. No delegation or registration can start under a covered grant, so a set grows only
           through holders admitted before `t₀`.
         * A5. Each store read of a set or a subtree takes at most `t_read`, and the tombstone
           transaction at most `t_commit`.
       * **Reads.**
         * Before the mark: one read of the set.
         * After the mark: round 0's re-read (1), then, only if the set grew, round 1's `r` subtree
           reads and its re-validation (`r + 1`).
         * At most `r + 3` reads in all.
       * **Work.** For any narrowing X, define `R(X) = (r_X + 3)·t_read + 4·n_X·ε + t_commit`. That
         covers its reads, its marking, two acquisition rounds and its key destruction (each `ε` per
         grant), and its tombstone transaction.
       * **The bound:**

         ```
         committed_at(N) − requested_at(N)  ≤  H + R(N) + Σ_{X ∈ E(N)} R(X)
         ```

       * **Why it holds:**
         * Every pre-mark holder of N's gates has ended by `t₀ + H` (A1).
         * Every later holder costs `ε` (A2, A3).
         * An earlier narrowing X in `E(N)` was marked no later than `t₀`, so its own pre-mark holders
           had also ended by `t₀ + H`, and it finishes after at most `R(X)` more.
         * By induction over the sequence numbers, the earliest narrowing in any chain waits for no
           other narrowing, so `H` is counted **once**.
         * Round 1 meets no pre-mark holder: every growth came from holders admitted before `t₀`, and
           all of them had ended before round 0 completed (A4).
       * **Budgets** (plan §5 item 17; the values at which the target is tested, not limits that abort
         anything):
         * `t_read` = `narrowing_read_budget` = 150 ms;
         * `n_max` = `narrowing_set_budget` = 256 grants;
         * `r_max` = `narrowing_root_budget` = 16 roots;
         * `t_commit` = `narrowing_commit_budget` = 200 ms;
         * `ε` = `pending_check_budget` = 1 ms.

         At these budgets, `R ≤ 19 × 0.15 + 4 × 256 × 0.001 + 0.2 ≈ 4.07 s`.
       * **The 20 s target** (§17.13 item 1). It is **a target, not a guarantee**, and deterministic
         tests check it at the budgets:
         * a narrowing with no earlier overlapping narrowing commits within `H + R ≈ 14.1 s`;
         * a narrowing behind one earlier overlapping narrowing commits within `H + 2R ≈ 18.2 s`.

         Beyond the budgets, or with more overlap, the derived bound is still computed and reported.
         A narrowing past 20 s is reported (`narrowing_over_target`, with its terms), and is **never
         aborted**. `narrowing_gate_wait_max` is no longer an enforced ceiling; it is the 20 s target.
       * **The re-check's traces**, as deterministic tests:
         * the round-4 flood (24.6 s under revision 4, 9.6 s under revision 5) commits within its derived
           bound (`post_mark_flood_and_round_one_descendants_commit_within_bound`);
         * ⟨r6⟩ the **multi-root countermodel**: 8 roots, 9 grants, a pre-mark delegation ending at 9.9 s,
           2 s reads, no post-mark holder. It committed at 29.9 s; its derived bound is
           `H + (8 + 3) × 2 s + ε terms ≈ 32 s`;
         * ⟨r6⟩ the **overlapping-narrowing countermodel**: an earlier narrowing whose file cleanup is held
           at 5 s and whose reads are at the budget, and a later one sharing some of its grants. The
           later one commits within `H + R(earlier) + R(later)`, without waiting for the earlier one's
           cleanup.

         Each of them also asserts that nothing is enqueued after the mark.
   * ⟨r3⟩ **Who writes the bodies.** `app::managed::SigningGates` and its exclusive acquisition are
     written by **U0b phase 1** (wave 0), and U10 only wires them (§17.4 item 6; B R2-01). U0b phase 1
     needs them because the narrowing paths of its rows 5 and 20 call them, and revocation is reachable
     by request.
   * **Result:** every signature is either enqueued before the narrowing's commit, while its permit is
     unexpired, or refused. None is enqueued after a revocation has been acknowledged, or after the
     grant's deadline.
   * **Tests (U2, and U0b rows 1 and 20):**
     * `sign_paused_after_precheck_then_revoke_is_refused`. Deterministic: the signer is paused right
       after the pre-check authorization; the revocation commits; the signer is resumed; its fresh read
       under the gate refuses (§17.3 item 4);
     * `sign_paused_inside_gate_delays_revoke_and_is_enqueued_before_commit` (§17.3 item 4);
     * `no_signature_enqueued_after_revocation_acknowledged`;
     * ⟨r3⟩ `sign_crossing_deadline_after_fresh_read_not_released`. The signer is paused after the
       fresh read; the virtual clock crosses D with no edit to any state; the signer is resumed; and
       the release check refuses;
     * ⟨r4⟩ `deadline_crossed_while_enqueue_blocked_nothing_released` (§17.7 item 2). Deterministic: the
       outbound queue is held full; the deadline passes after the release check would have run in
       revision 3's order, while the enqueue is blocked; the capacity wait is cancelled by the expiry,
       and nothing is released;
     * ⟨r4⟩ `deadline_crossed_between_capacity_and_release_check_refused`;
     * ⟨r4⟩ `enqueue_after_release_check_never_waits` (U0b row 1);
     * ⟨r3⟩ `sign_budget_overrun_expires_permit_nothing_released`;
     * ⟨r3⟩ `delegation_during_revocation_child_never_signs_after_ack` (U0b row 20);
     * ⟨r3⟩ `two_concurrent_cascades_no_deadlock_no_late_signature` (U0b row 20);
     * ⟨r4⟩ `gate_set_growth_hl_interleaving_releases_and_reacquires_no_deadlock` (U0b row 20): the
       re-check's interleaving. The cascade holds R and H; L (sorting before H) finished delegating
       before R was taken; another narrowing holds L and waits for H. The cascade releases everything,
       reacquires in global order, and both narrowings complete;
     * ⟨r4⟩ `reacquisition_round_never_grows_set` (U0b row 20: delegations at every depth race the
       round-1 reacquisition);
     * ⟨r4⟩ `narrowing_wait_bounded_by_rounds_plus_one_times_gate_max_wait` (U0b row 20). ⟨r6⟩ Replaced by
       `narrowing_commit_within_derived_bound_and_reported`: the formula it checked undercounted the
       reads, and the bound is now reported, not enforced;
     * ⟨r6⟩ `multi_root_countermodel_within_derived_bound` (U0b row 20; §17.13 item 1). The round-5
       check's forest: 8 roots, 9 grants, a pre-mark delegation ending at 9.9 s, 2 s reads, no post-mark
       holder. The commit must come within `H + R(N)` (about 32 s at these reads), and nothing may be
       enqueued after the mark;
     * ⟨r6⟩ `overlapping_narrowings_countermodel_within_derived_bound` (U0b row 20). An earlier narrowing
       whose cleanup is held at 5 s, and a later one sharing grants with it. The later one commits within
       `H + R(earlier) + R(later)`, without waiting for the cleanup, and nothing is enqueued after either
       mark;
     * ⟨r6⟩ `signer_multi_root_countermodel_within_derived_bound` and
       `signer_overlapping_narrowings_countermodel_within_derived_bound` (U2: the same two countermodels,
       through real signer endpoints and outbound queues);
     * ⟨r6⟩ `narrowing_commit_target_20s_at_budgets` (U0b row 20: with no earlier overlap, and with one,
       at the §5 item 17 budgets);
     * ⟨r6⟩ `narrowing_never_aborts_for_time_reports_over_target` (U0b row 20);
     * ⟨r6⟩ `later_narrowing_defers_to_earlier_mark_no_deadlock` (U0b row 20);
     * ⟨r6⟩ `slot_files_removed_only_after_gates_released` (U0b row 20);
     * ⟨r6⟩ `registration_refused_while_pending` (U0b row 26);
     * ⟨r5⟩ `post_mark_flood_and_round_one_descendants_commit_within_bound` (U0b row 20; §17.10 item 1).
       Deterministic replay of the re-check's first trace, which committed at 24.6 s under revision 4.
       Pre-mark holders are present, post-mark signers keep arriving, and a pre-mark delegation adds
       descendants found in round 0's re-read. The commit must come within `narrowing_gate_wait_max`,
       and within `signing_gate_max_wait` plus the measured `ε` and `t_read` terms;
     * ⟨r5⟩ `precheck_before_mark_then_gate_after_mark_refused` (U2; §17.10 item 1). Deterministic replay
       of the re-check's second trace: the pre-check passes at t = −0.1 s, the mark is set at t = 0, and
       the gate is taken at t = 9 s. Revision 4 admitted and signed. The fresh read must refuse, and no
       signature is released;
     * ⟨r5⟩ `release_check_refuses_when_mark_set_after_admission` (U2);
     * ⟨r5⟩ `ancestor_pending_covers_descendant_created_after_mark` (U0b row 20);
     * ⟨r5⟩ `round_one_marks_new_descendants_before_releasing_gates` (U0b row 20);
     * ⟨r5⟩ `delegation_rechecks_pending_after_each_awaited_acquisition_and_before_install` (U0b row 20);
     * ⟨r5⟩ `gate_is_fair_writer_not_starved` (U0b row 24);
     * ⟨r3⟩ `revoke_closes_processes_only_after_gates_released` (U0b row 20);
     * the uncontrolled-interleaving test, added on top, never instead.

     The linearization model (U3) covers activation, re-issue, lock revocation, ⟨r3⟩ delegation and
     concurrent cascades against the gate (F24; B R2-03), ⟨r4⟩ the capacity-then-release order, and the
     release-and-reacquire round, ⟨r5⟩ with the mark checked where step 4, the delegation path and the
     release check now check it, and both re-check traces as fixed cases. ⟨r6⟩ It also replays the round-5
     multi-root and overlapping-narrowing countermodels, each asserting commit within its derived bound
     and nothing enqueued after the mark (§17.13 item 1; `model_multi_root_countermodel_within_derived_bound`,
     `model_overlapping_narrowings_countermodel_within_derived_bound`).

4. **Purpose (spec §7.2).** The signed data must parse, with the established `ssh-encoding` reader, as
   an SSH user-authentication request (RFC 4252 §7):
   * `string session_id`;
   * byte 50;
   * `string user`;
   * `string "ssh-connection"`;
   * method `publickey` or `publickey-hostbound-v00@openssh.com`;
   * `boolean TRUE`;
   * `string algorithm`;
   * `string key_blob`;
   * for the host-bound method, `string server_host_key`;
   * no trailing bytes.

   In addition:
   * ⟨r2⟩ `key_blob` must be one of this grant's **certificates**, matched byte for byte. The plain
     K_env public blob is refused (F17): every managed authentication presents a certificate;
   * ⟨r2⟩ `user` must be the account of **the pair whose principal the presented certificate names**
     (F17), not merely any pair of the grant;
   * the algorithm must match the key, and the signature flags must be the ones Ed25519 permits.

   Anything else is refused. That includes `SSHSIG` (Git signing), arbitrary data, another account
   name, and an RSA SHA-1 flag set on an Ed25519 key.

5. **`session-bind@openssh.com`.** Per connection, the signer parses the extension with
   `ssh-agent-lib`'s types and verifies the host's signature over the session identifier with
   `ssh-key`.
   * A failed verification makes that connection refuse every later sign.
   * `is_forwarding = true` makes the connection refuse every sign unless the grant's scope has the
     `agent-forwarding` capability.
   * Once a session is bound, a sign request's `session_id` must equal the bound one, and a host-bound
     request's `server_host_key` must equal the bound host key.
   * A client that sends no session-bind is admitted and recorded as `session_bind: absent`.

   **No destination-restriction claim is made from this.** `authenticated_agent_restriction` is never
   reported (ADR-0005 §7.3). Destination scope stays the server's principal check.

6. **Install.** A certificate reaches the signer only after its issuance entry is `published`. The
   signer then checks its own view in a read transaction: the generation, the tombstones, a safe
   deadline, and that the certificate's subject key equals the grant's K_env (ADR-0005 §3.5 step 4). It
   also validates the certificate's structure (D6 item 2). Any failure discards the certificate, and the
   entry stays counted in the residual.

7. **Destruction.** At grant end the signer ⟨r2⟩ (holding the grant's gate exclusively when the end
   is a revocation; item 3a):
   * removes the grant's identities from every endpoint;
   * drops its certificates;
   * zeroizes K_env (ADR-0005 §3.6).

   The endpoint keeps no copy. A per-binding endpoint is torn down by the generation-bound cleanup
   (R-RT-04). With no key left, outstanding certificates cannot be used from this environment [I]
   (settled by `destroyed_key_makes_installed_certificate_unusable`, U2).

**Credential-instance state machine** (extends `domain::issuance::CredentialState`):

| From | Event | To | Notes |
|---|---|---|---|
| — | K_env generated, fingerprint registered (`subject_registered`) | `pending` | Persisted: instance row, key handle reference = an opaque vault slot ID, public fingerprint. Never the secret |
| `pending` | ⟨r2⟩ process exit before every pair is installed (found at the next start) | `destroyed` | F18: marked at start, in the U0b row 8 transaction. Its `reserved` and `published` entries stay counted in the residual; a fresh activation or re-issue makes a new instance |
| `pending` | every pair's certificate published and installed | `installed` | `Prepared` stage receipt |
| `pending` | any reservation refused or voided | `destroyed` | The key is zeroized. A fresh `prepare` makes a new instance |
| `installed` | grant ends | `destroyed` | |
| `installed` | process exit (crash, stop, logout) | **`lost`** (new) | Detected at the next start: an `installed` row whose vault slot does not exist in this process |
| `lost` | the ADR-0005 §3.7 recovery rule holds | `destroyed`, plus a new instance `pending` | Re-issue: a new K_env and fresh reservations. The old entries stay counted |
| `lost` | the rule fails (expired, revoked, `revoke_on_lock`, time not accepted) | `destroyed` | The grant ends, or stays `degraded` (`credential_reissue_pending`) while only time is unaccepted |

**Rationale.** The checks of ADR-0005 §3.6 need the transactional state, which lives in the runtime.
* An in-process signer reads it under the same serializable store that revocation writes. ⟨r2⟩ The
  signing gate (item 3a) turns that read into a linearization point with the signature's enqueue, so
  "a revocation commits, then no later signature is released" holds without a cache-invalidation
  protocol.
* A separate process would not change the disclosed same-user boundary. It would need a pushed
  authorization table, which brings staleness windows during revocation.
* `KeyVault` keeps the key material in one module that has no serialization at all.

**Rejected:**
* **A separate signer process** with a pushed authorization table. It adds a revocation staleness
  window and moves no boundary.
* **Stock `ssh-agent`** as the signer: it cannot check the grant (ADR-0005 §8).
* **A cached allow-list per binding.** It is stale across revocation, cutoff and lock.
* **Listing all keys on every endpoint.** Per-binding listing keeps a bound context from enumerating
  other grants' identities. That is a convenience, not isolation (same-user).
* **Destination restriction from session-bind in M03.** It needs host-key binding to the catalog and
  tests that M03 does not have. It is a later candidate (§19).

---

## 4. D3 — The issuer: a child process with no listener, signing by reservation

**Decision.**

1. **Process.** The issuer is `heimdall internal issuer`, a hidden subcommand of the same binary. The
   runtime spawns it as a foreground child.
   * Its **only channel is its stdin and stdout pipes**, created by the runtime (`Stdio::piped()`); its
     stderr goes to the runtime's log, redacted.
   * It refuses to run when stdin is a terminal.
   * It exits, zeroizing K_ca, on EOF from stdin (the parent died) and on `Shutdown`.

2. **No listening endpoint.** `EndpointKind::Issuer` and its path stay in the contract as **reserved
   and never bound**. A test asserts the path never exists. This revises ADR-0006 §2.1, which says the
   path is fixed (Q1).
   * No same-user process can reach the issuer by connecting to a path. E5's same-user minting through
     the issuer socket [O:E5] is not possible through a path any more.
   * The same-user boundary remains: such a process can still ptrace or read memory where the OS allows
     (M-F19), or read the store item.
   * `issuer_isolation: same_user_process` is still reported.

3. **Wire protocol `heimdall-issuer/1`.** Frames are a `u32` big-endian length followed by one UTF-8
   JSON object, at most 64 KiB, checked before allocation. The issuer handles one request at a time.

   | Runtime → issuer | Issuer → runtime |
   |---|---|
   | `{"t":"hello","protocol":"heimdall-issuer/1","nonce":"<32 hex>"}` | `{"t":"hello_ack","nonce":"<same>","pid":<n>}` |
   | `{"t":"load"}` | `{"t":"loaded","cas":[{"fingerprint":"SHA256:…","state":"active"}]}` or `{"t":"store_unavailable","reason":"locked"}` |
   | `{"t":"sign","request_id":"<32 hex>","reservation":{"table":"grant","id":"iss_…"},"subject_public_key":"ssh-ed25519 AAAA…"}` | `{"t":"signed","request_id":"…","certificate":"ssh-ed25519-cert-v01@openssh.com AAAA…"}` or `{"t":"refused","request_id":"…","reason":"<IssuerRefusal>"}` |
   | `{"t":"status"}` | `{"t":"status","cas":[…],"signed_total":<n>,"refused_total":<n>}` |
   | `{"t":"shutdown"}` | (exits) |

   `table` is `grant` or `verification` (D5 §6.5). The request carries **no bounds**: the issuer reads
   them from the store.

   ⟨r2⟩ The store item is read through the `SecretStore` trait, which U0 freezes in
   `heimdall-issuer::store` (F23). The trait's implementations are in D1's table, and the test
   implementation lives in `heimdall-testkit`.

4. **Signing by reservation.** The issuer opens the state database **read-only**
   (`Store::open_read_only`; WAL readers do not block the writer). For each `sign`:
   1. load the entry by ID from `issuance_log` or `verification_issuance`. It must be `reserved`, must
      have been reserved no more than 60 s ago, and its `subject_fingerprint` must equal the fingerprint
      of `subject_public_key`;
   2. re-run the **pure** predicate (`issuance::check`, or `verification::check`) against a read-only
      snapshot taken in one read transaction, with the issuer's own clock observation. ⟨r2⟩ The
      snapshot is assembled by the **read-only issuance check** `app::issuance_ro::assess(&Store /*
      read-only */, IssuanceRef, &TimeAnchor) -> Result<CertificateBounds, IssuerRefusal>`. It is owned
      by U3 and shares the assembly code of the runtime's reserve and publish transactions (ancestry,
      merged policy, validated generation), so the two can never disagree about what the predicate
      sees. The time verdict comes from `TimeGate::assess_read_only`, which persists nothing and is
      tested on a store opened with `Store::open_read_only` (§17.1 item 12; F21);
   3. apply the format ceilings:
      * exactly one principal, matching `hm:<[A-Za-z0-9._-]+>:<[A-Za-z0-9._-]+>` or
        `hm:verify-negative:<32 hex>`;
      * no critical option;
      * extensions ⊆ {`permit-pty`, `permit-agent-forwarding`, `permit-port-forwarding`,
        `permit-user-rc`}, with `permit-X11-forwarding` never allowed;
      * `valid_before − valid_after` ≤ the grant's window bound plus 60 s, or 300 s plus 60 s for
        verification;
      * key ID matching `heimdall:<env>:<grant|op>:<serial>` with opaque IDs only;
      * a subject key that is not a CA key the issuer holds;
   4. select the CA named by the entry's `ca_fingerprint`. It must be loaded and `active` (or `pending`
      for a verification entry of its own enrollment, D4);
   5. sign exactly those bounds and return the certificate.

   The issuer **never publishes, never installs and never writes the store.** Publication stays the
   runtime's publish transaction (ADR-0005 §3.5 step 3; ADR-0006 §13.8 item 1, with its re-reservation
   round trips). Installation stays the signer's check (D2 item 6). A refusal at any step returns
   `refused` with an `IssuerRefusal` reason:
   * an `IssuanceRefusal` variant;
   * `entry_not_reserved`, `entry_stale` or `subject_mismatch`;
   * `ceiling_exceeded`, `ca_not_loaded` or `rate_limited`.

   An unrelated generation move between reserve and sign shows up as an issuer refusal of only
   `StaleGeneration` or `StaleAncestor`. The runtime handles it exactly as ADR-0006 §13.6 item 11
   handles a publish voided only by the generation:
   1. void the entry;
   2. re-validate;
   3. re-reserve with a fresh serial;
   4. ask again.

   These round trips count toward the same bound of 3 (§13.8 item 1). Any other refusal ends the
   attempt.

5. **Rate limit.** At most 600 signatures per minute, and at most 64 certificates per grant per
   activation or re-issue. A limited request is refused with `rate_limited`, which the runtime maps to
   `BACKPRESSURE`. This bounds a runaway loop. It is not a security boundary.

6. **Late replies.** Each request has a 10 s bound inside the 30 s adapter-call bound. When the
   runtime's adapter future is dropped, a reply that arrives later matches no pending `request_id`. It
   is zeroized and discarded.
   * Nothing is released without the runtime's publish transaction, and the reservation is already
     counted in the residual (ADR-0005 §3.5).
   * **So a signature that lands after the drop releases no authority.** This answers the ADR-0007 §14
     reopen condition "an adapter's effect can land after its call was dropped" for B1.

7. **Supervision.** The runtime's supervisor owns the child: exact PID plus its start-time token.

   | State | Meaning | Next |
   |---|---|---|
   | `not_initialized` | No CA registered (D4) | `starting` after registration |
   | `starting` | Spawned; hello pending (5 s bound) | `loading` / `crashed` |
   | `loading` | Reading store items | `ready` / `store_unavailable` |
   | `ready{cas}` | Signs | `crashed`, `stopping`, `store_unavailable` (on a reload) |
   | `store_unavailable{reason}` | Store locked or missing; K_ca not in memory | `loading` on the owner's `issuer unlock`, or on the next demand after the jittered backoff |
   | `crashed` | Exited or broke the protocol | `starting` with bounded, jittered backoff (base 1 s, cap 60 s, max 8 attempts, then `unavailable` until the next demand or `issuer unlock`) |
   | `stopping` | Shutdown sent, EOF on stdin | exited (`stopped`) |

   While the issuer is not `ready`:
   * new activations and re-issues fail with `CAPABILITY_UNAVAILABLE`, reason `issuer_unavailable` (or
     the store reason);
   * existing grants keep signing with their installed keys;
   * a grant whose K_env is lost becomes `degraded` with `credential_reissue_pending`.

   No fallback key is ever used (spec §15.2).

**The authority boundary.**

| | Issuer process | Runtime process (signer, control plane) | Signing endpoints | Bound consumers (`run`, `connect`, containers later) |
|---|---|---|---|---|
| K_ca bytes | memory (zeroized at exit) | **never** | never | never |
| K_env bytes | never | `KeyVault` | never (sign results only) | never |
| Can mint a certificate | only for a `reserved` entry whose pure predicate passes | can reserve (predicate) and publish; cannot sign | no | no |
| Reaches the store | read-only | read-write | no | no |
| Reachable by | its parent's pipes only | the control endpoint (owner-only, same user) | same user, through the endpoint path | the endpoint they were given |

A same-user process can still use any signing endpoint it can reach, use the control endpoint, read
the store item, or attach to processes where the OS allows. All of this is disclosed (spec §7.3, §14.1).
A K_ca compromise means rotation (D4).

**Rationale.**
* ADR-0005 §3.1 requires a separate issuer process that is reachable only by the local supervisor.
  Inherited pipes are the narrowest channel that achieves this, with no path, no peer authentication and
  no name to find.
* Signing by reservation implements ADR-0005 §3.5 "the issuer trusts none of the request's claims".
  The issuer signs only bounds that the store holds as `reserved` and that the store's current state
  authorizes at that moment. A runtime bug or a corrupted message cannot widen what is signed.
* A writer of the store is still inside the same-user boundary. This narrows confused-deputy errors;
  it is not a defence against a compromised account.

**Rejected:**
* **An issuer listening on `issuer.sock` with a UID check.** E5 showed same-user minting by path.
* **The issuer inside the runtime process.** K_ca would then sit in the memory that parses every control
  and agent message.
* **An issuer that signs the bounds in the request.** It would be a blind oracle for whatever its parent
  sends.
* **An issuer with write access to the store.** It does not need it, and two writers would complicate
  the linearization.
* **A separate-OS-account issuer.** It is stronger, but it is ADR-0005 §13's reopen path and needs
  service installation.

---

## 5. D4 — Issuer initialization, the D5 backup, rotation, retirement, restore and the recovery bundle

**Decision.**

1. **Initialization (`heimdall issuer init --backup-out <path>`)** happens only in an owner-present CLI
   process on a TTY, never under `--non-interactive`, an agent or a paired client (ADR-0005 §5.3). The
   steps:
   1. **Generate.** In the CLI process memory: K_ca (Ed25519 from the OS CSPRNG), and a passphrase of
      26 symbols from the RFC 4648 base32 alphabet (130 bits), shown in groups of five.
   2. ⟨r2⟩ **Prepare the backup bytes** (§17.1 item 11; M03-R11). Encrypt K_ca in memory into the
      **exact** D5 file bytes B: the OpenSSH format with bcrypt-pbkdf and aes256-ctr, salt and rounds
      fixed in B. Decrypt B in memory and compare the public key with K_ca's. Compute `backup_sha256 =
      SHA-256(B)`. Nothing is written yet.
   3. **Disclose and decide.** On an attended session (`Attend` first, ADR-0006 §13.6 item 7) the CLI
      sends `Issuer::Register` with K_ca's **public** key, the store kind and ⟨r2⟩ the
      `backup_sha256` of B. The runtime answers `APPROVAL_REQUIRED` with decision `RegisterIssuer`,
      which names the CA fingerprint and the backup digest and carries the disclosure:
      * the same-user issuer boundary;
      * the blast radius: every account that will trust the CA;
      * lock continuity, shown once and conditionally (R-UX-03, D9 item 1);
      * the backup instructions.

      The CLI shows it, and the owner types `yes`. Anything else sends nothing more, zeroizes K_ca and
      B, and exits 3.
   4. **Write the backup** ⟨r2⟩ **exactly**: write B to `--backup-out` with `O_EXCL`, mode 0600 or an
      owner-only DACL, `fsync`. Read it back and compare SHA-256 with `backup_sha256`, then decrypt
      the read-back bytes in memory and compare the public key. A mismatch, or a path that already
      exists, stops here and sends nothing more.
      * There is no default path: Heimdall never proposes a location, and never a synchronized folder.
   5. **Show the passphrase once.** Write it on the controlling terminal (`/dev/tty`; on Windows
      `CONOUT$`), never on stdout or stderr when they are not that terminal. Then wait until the owner
      types `written`, and clear the screen region.
   6. **Store.** Write K_ca to the platform store (D1). Read it back by identity and compare
      fingerprints.
   7. **Register.** Send `Decide approve` for the `RegisterIssuer` record. In one transaction the
      runtime:
      * records the CA (`issuers` row: fingerprint, public key, `active`, store kind, `backup_sha256`,
        backup time);
      * sets the native environment's `managed_signing` and `issuer_access` permissions, which moves the
        generation (ADR-0006 §13.7 item 5).

      Then it starts the issuer child.
   8. **Zeroize** K_ca, B and the passphrase in the CLI process.

   **Crash points:**
   * before step 4: nothing is written. A pending `RegisterIssuer` record expires (`DECISION_STALE`).
   * between 4 and 6: a backup file whose CA nothing trusts. The owner discards it; no store item
     exists.
   * between 6 and 7: an **orphan** store item that is not registered. `issuer status` reports it.
     ⟨r2⟩ `issuer init --replace-orphan <fingerprint>` (F08):
     * **warns** that deleting a K_ca is irreversible;
     * **cross-checks a recovery bundle** given with `--bundle <file>`: if the bundle lists live
       enrollments trusting that fingerprint, it refuses to delete, and **offers restore** instead
       (registration with `restored_without_log: true`, item 4);
     * otherwise it deletes by exact identity after a typed confirmation;
     * without a bundle it warns that remote lines may still trust the key, and requires
       `--no-bundle-available` plus the typed confirmation.
   * after 7: registered.

   The decision record carries only public values (fingerprint and digest), so a stale or denied record
   leaves nothing behind but those.

2. **Unlock (`heimdall issuer unlock`)**, owner-present. It reloads a store that was `locked`. This is
   the only path in which a store prompt may appear, such as a keychain unlock dialog.

3. **Rotation.**
   * `issuer rotate begin --backup-out <path>` is the same ceremony. It produces K_ca′ in state
     `pending`.
   * Per account, `enroll <destination>` with `--ca <K_ca′ fingerprint>` appends a second line and
     verifies it (D5). A `pending` CA signs only verification certificates for its own enrollments.
   * When the first account verifies K_ca′, the CA becomes `active`.
   * Issuance for a pair uses the **newest `active` CA that the pair has a `verified` enrollment for**.
     So issuance moves account by account as each verifies (ADR-0005 §6.4 steps 2–4, per pair).
   * ⟨r2⟩ The pair's preference keeps the **set of issuing CAs** with verified enrollments (F05). E5
     of a rotation does not touch the preference's mechanism or the projection when the pair is
     already managed and applied (D5 §6.6), so `ensure` keeps working on every account throughout
     (`rotation_keeps_ensure_working_per_account`).
   * The old line is removed with `enroll remove <old enrollment>` (compare-then-rename, D5 §6.8).
     ⟨r2⟩ **Early removal is allowed**, before the old CA's latest `reserved`/`published`
     `valid_before` **for that pair** has passed. The removal preview then warns which live grants
     hold a certificate under the old CA for that pair. Which of those grants are degraded is §17.1
     item 15's rule. ⟨r3⟩ §17.3 item 3 ruled the case where another verified enrollment remains (Q20
     (a)): every grant under the old CA for that pair is degraded (D5 §6.8).
   * ⟨r2⟩ **Retirement** (`issuer retire <fingerprint>`, attended decision `RetireIssuer`; §17.1
     item 11) is a **durable transition**. It is allowed only when every enrollment of that CA is final
     or `abandoned` (§17.1 item 7). The CA moves through these states, each persisted before the
     next action:

     | State | Entered when | Effect | Next |
     |---|---|---|---|
     | `active` / `pending` | — | — | `retiring` on `Decide approve` |
     | `retiring` | the decision is applied, in the same transaction that refuses new reservations for this CA (`IssuanceRefusal::CaRetiring`) | issuance disabled; existing certificates stay counted | `unloaded` once the issuer child confirms it zeroized the key (`unload` message) |
     | `unloaded` | the child's confirmation | no process holds the key | `deleted` once the store item is deleted by exact identity and a re-read finds it absent |
     | `deleted` | the store re-read | — | `retired` |
     | `retired` | final | the bundle and `issuer status` show it | — |

     * At restart, a CA in `retiring` or `unloaded` resumes at its next step: the issuer child is
       told not to load a `retiring` CA, and a store item already absent counts as deleted. Each step
       is idempotent.
     * A failure between any two steps is tested (U4: `retire_resumes_after_crash_at_each_step`).
     * Abandoned enrollments keep their lines, reported `pending_until_line_removed`.
   * There is no calendar rotation (ADR-0005 §6.4).

4. **Restore (`heimdall issuer restore --backup <file>`)**, owner-present. The passphrase is typed with
   echo off and never taken from an argument or environment variable.
   * **The issuance log is intact** (the CA is registered and only the store item was lost). Decrypt,
     compare the fingerprint with the registered CA, write it to the store, then `loaded`.
   * **The log is lost** (no registration matches). Registration goes through the full decision, with
     `restored_without_log: true`. Every residual for that CA's scopes is then `unknown` and
     `revocation.remote: unbounded_unknown`, never derived from policy (ADR-0005 §5.3). The preview
     recommends rotation.
   * Restore after theft is the owner's judgment. The CLI shows ADR-0005 §5.3's guidance ("do not
     restore; rotate") and requires an explicit `--not-stolen`.

5. **Recovery bundle (`heimdall issuer bundle --out <path> [--redact hostnames]`)**, read-only. A
   versioned JSON file of **public metadata only**:
   * CA public keys and fingerprints, and backup digests and dates;
   * per enrollment:
     * marker, destination ID, account, form, state;
     * ⟨r2⟩ the alias, hostname and port, when not redacted;
     * ⟨r3⟩ the **canonical registry** `{path, resolved_by: explicit | remote_home}`: the path
       validated by D5 §6.1, never its display form, which M3 forbids parsing back (B R2-07);
     * the full public CA line's SHA-256 (`line_sha256`);
   * the removal instructions.

   It is refreshed automatically: `issuer status` and every enrollment change report its staleness.

   ⟨r2⟩ **Foreign removal** (§17.1 item 11; M03-R12, F07) is run from another device that has existing
   access:

   ```
   heimdall enroll remove --from-bundle <file> --marker <marker> --alias <local alias>
   ```

   * **The target** is the full public removal descriptor `ForeignRemovalTarget`:
     * the **local alias** on this device;
     * the bundle's destination ID (as a label: destination IDs are per installation);
     * ⟨r3⟩ the bundle's hostname and port;
     * account, marker;
     * the CA **public key**;
     * `line_sha256`;
     * ⟨r3⟩ the canonical registry `{path, resolved_by}`, and the form.

     The decision `RemoveEnrollment` and the request hash cover all of it.
   * **Before connecting**, the line is rebuilt from the CA public key, the principal and the marker,
     and its SHA-256 is checked against `line_sha256`. A mismatch refuses.
   * **A redacted bundle is refused clearly** (`bundle_redacted`): without hostnames, the local
     alias's evaluated host cannot be cross-checked against the bundle's host.
   * ⟨r3⟩ **The host cross-check is exact equality** (§17.4 item 10; B R2-07).
     * The local alias's evaluated `HostName` and `Port` (from the `TargetEvaluator`, as for any
       approved target) must equal the bundle's hostname and port, byte for byte.
     * Anything else refuses with `CAPABILITY_UNAVAILABLE`, reason `bundle_host_mismatch`, before any
       connection.
     * No resolution, alias matching or "same address" reasoning is attempted.
   * **The route and host key** are this device's: its catalog's alias, approved for the removal
     like any remote step (D5 §6.3).
   * ⟨r3⟩ **The state machine is the enrollment removal sub-machine, keyed by marker** (§17.4 item 10),
     ⟨r4⟩ with its admission in the **frozen** transition contract (§17.7 item 4; M03-R3-04):
     * ⟨r4⟩ **Admission.** A foreign record is created `planned`. Its admission events are part of
       `domain::enrollment::transition` and of `enrollment_transition_table_golden` (D5 §6.2, `planned`
       row):
       * account form: `RemoveEnrollment` approved → `removing`; denied, cancelled or stale →
         `withdrawn` (nothing remote);
       * system form: the owner's typed confirmation → `manual_removal_pending`, origin `planned`
         (below).
     * account form, after admission: `removing → removed | remove_unknown | held`, then
       `remove_unknown → removed | removing | abandoned`, and ⟨r4⟩ `held → removing` (a new
       `RemoveEnrollment`, with a freshly evaluated target for a host-key hold) or `held → abandoned`;
     * these are exactly D5 §6.2's events, with the D5 §6.3 fence;
     * a lost reply is reconciled by D5 §6.7, with the marker as the key ("marker absent" means
       applied);
     * `ForeignRemovalRecord.state` is a subset of `EnrollmentState`, checked by the same `transition`
       function (plan §5 item 16). ⟨r4⟩ The subset is `planned`, `removing`, `remove_unknown`,
       `removed`, `held`, `abandoned` and `withdrawn`, plus `manual_removal_pending` and
       `removal_verifying` for the system form.
   * **Records.** Foreign removals live in their own table `foreign_removals`, with **no foreign key**
     to `issuers`, because the CA is not registered here.
   * **System form.** A system-form entry in a bundle is never removed by Heimdall. It gets the manual
     instructions of D5 §6.9. ⟨r4⟩ Its record uses the §6.9 manual removal states (§17.7 item 4):
     * `planned → manual_removal_pending`, origin `planned`, on the owner's typed confirmation;
     * `manual_removal_pending → removal_verifying` when the owner reports the lines removed;
     * a cancel **before any absence check** returns to `planned`, which can then be `withdrawn`:
       this device stops its attempt, and the bundle's entry is unaffected.

     **The absence check cannot pass here** (Q28, ruled in §17.9 item 3). §6.9's check issues a
     verification certificate under the removed CA, and expects it to be refused. A foreign removal
     runs on a device that does not hold that CA's key (the CA is not registered here). So
     `removal_verifying` ends `verification_inconclusive`, reason `ca_not_held`, and returns to
     `manual_removal_pending`.
     * The record is never reported `removed`, and stays listed with `pending_until_line_removed`.
     * ⟨r5⟩ **Abandoning** (§17.10 item 2; M03-R4-02). For a foreign record, `manual_removal_pending →
       abandoned` is an explicit event, the owner's `enroll abandon`. The abandoned record keeps
       `pending_until_line_removed`, and is still listed by uninstall and the bundle.
     * ⟨r5⟩ **Cancelling after `ca_not_held`.** Once a `ca_not_held` result exists, the record's
       `removal_origin` is pinned. A cancel then leaves it in `manual_removal_pending`, or returns it to
       `held` when a held foreign record began the removal. It never reaches `planned` or `withdrawn`:
       a residual that is known and unresolved is never discarded. Revision 4 allowed `removal_verifying
       → manual_removal_pending → planned → withdrawn`, which is final with no absence proof.
   * **Tests (U10):**
     * `foreign_removal_from_second_installation_with_different_catalog`;
     * ⟨r3⟩ `foreign_removal_lost_reply_reconciled_by_marker`;
     * ⟨r3⟩ `foreign_removal_refuses_bundle_host_mismatch`;
     * ⟨r4⟩ `foreign_removal_approved_planned_to_removing`;
     * ⟨r4⟩ `foreign_removal_denied_withdrawn_nothing_remote`;
     * ⟨r4⟩ `foreign_removal_held_recovery_by_new_decision_or_abandon`;
     * ⟨r4⟩ `foreign_removal_system_form_manual_route_never_reported_removed`;
     * ⟨r5⟩ `foreign_system_form_abandon_keeps_pending_until_line_removed` (§17.10 item 2);
     * ⟨r5⟩ `foreign_system_form_cancel_after_ca_not_held_never_planned_or_withdrawn`.

     ⟨r4⟩ Before the freeze, U0's `foreign_removal_paths_golden` drives the same five routes through
     the pure `transition`: approval, denial, a lost reply, held recovery, and the system form. ⟨r5⟩ It
     also drives the two paths of §17.10 item 2: `manual_removal_pending → abandoned` with
     `pending_until_line_removed` kept, and a cancel after `ca_not_held` that stays in
     `manual_removal_pending` (or returns to `held`), never `planned` or `withdrawn`.

   This is the ADR-0005 §6.3 lost-issuing-device primitive; the guided flow is M07 (§8).

6. ⟨r2⟩ **Uninstall and the K_ca store item** (§17.1 item 11; F08). Uninstall (M02 U9, extended by
   M03 U12):
   * It lists every enrollment that is not final, with its marker, and offers `enroll remove` first.
   * **A purge that keeps remote enrollments** (`--purge-state --keep-remote-enrollments`) requires a
     **fresh** recovery bundle first: one written after the last enrollment change, whose path the
     command records. Without it, the purge is refused (`bundle_required`). The state database is the
     only other inventory.
   * **The K_ca store item:**
     * while any enrollment under that CA is not final, uninstall **keeps** the store item and says so,
       naming the item and the reason;
     * when every enrollment under it is final, or there are none, uninstall offers deleting it (the
       retirement steps of item 3, run to `retired`) behind a typed confirmation, and reminds the owner
       to destroy the offline backup;
     * a kept store item found by a later `issuer init` is an orphan, handled by item 1's
       `--replace-orphan` rules (restore preferred).

**Rationale.**
* Generating the key in the CLI keeps the passphrase and the unencrypted backup bytes in exactly one
  owner-present process, and they never cross IPC.
* ⟨r2⟩ Registering the digest of bytes prepared in memory, then writing exactly those bytes, makes the
  decision cover the backup the owner keeps (M03-R11).
* The issuer child only ever loads K_ca from the store.
* Per-pair CA selection turns rotation into a sequence of independent per-account steps. Each step is
  verified before issuance relies on it, so an unreachable account never blocks the others.

**Rejected:**
* **Generating K_ca in the issuer child and passing the passphrase to the CLI over IPC.** The secret
  would cross a process boundary for display.
* **A default backup location.** Spec §7.7 and ADR-0005 §5.3 forbid proposing one.
* **A global switch of issuance at rotation.** Accounts not yet verified would fail at once.
* **Retire before the old lines are removed or abandoned.** Live grants on those accounts would stop.
* ⟨r2⟩ **Retirement as one call** (delete from the store and memory at once). A crash in the middle
  leaves no durable record of what is left (M03-R11).
* ⟨r2⟩ **A foreign-removal target of marker only.** Without the CA line and the registry path, the
  removal cannot be checked or recorded (M03-R12, F07).

---

## 6. D5 — The enrollment transaction

### 6.1 Scope and preconditions

`heimdall enroll <destination> [--account <a>] [--registry-path <p>] [--ca <fingerprint>]` enrolls one
pair with **account-level control** (spec §7.4 capability 2): one
`cert-authority,principals="hm:<destination-id>:<account>" <K_ca public> heimdall:<enrollment-id>` line
in the account's registry (ADR-0005 §3.3). The system form is §6.9.

⟨r2⟩ **The approved target** (§17.1 item 2; M03-R02). The preview evaluates the destination's route
statically through the `TargetEvaluator` port (§18; implemented by `heimdall-localenv` over the M02
evaluator and the known-hosts reader, with raw host keys). The result is the **approved target**:
* `HostName`, `Port` and `User`;
* the proxy chain. In M03 it must be empty: `ProxyJump` and `ProxyCommand` are refused,
  `route_unsupported`;
* the **approved host key**: the raw public key, its type and its fingerprint.

The decision, the plan digest and every remote step are bound to it (§6.3).

The preview refuses, writing nothing, unless all of these hold:

| Precondition | Refusal reason (`CAPABILITY_UNAVAILABLE` unless stated) |
|---|---|
| A CA is registered and the issuer is `ready` | `issuer_not_initialized`, `issuer_unavailable` |
| The destination is **managed** in the catalog (rendered in P), not observed | `observed_alias_unmanaged` |
| The destination ID and account fit `[A-Za-z0-9._-]` (ADR-0005 §3.3 principal form) | `principal_charset`, with the remedy |
| ⟨r2⟩ The route is direct and **every** target field is determined statically. ProxyJump, ProxyCommand and canonicalization are M04; `Match exec` or an unset `${VAR}` affecting the alias makes the target undetermined | `route_unsupported`, `route_undetermined` |
| Exactly one non-revoked known host key for (HostName, Port) is found in the user's known-hosts files, hashed entries included, and its raw key is available | `host_trust_undetermined` |
| ⟨r2⟩ `--account`, when given, equals the catalog's account for the destination (§17.1 item 2) | `USAGE_ERROR`, reason `account_override_refused` |
| ⟨r2⟩ An existing-access identity is adopted for the alias, and its kind can drive the steps: an agent-held key (native agent, 1Password) or a key file used through an agent or loaded from a file (ADR-0007 §7) (§17.1 item 14; F13) | `pair_not_adopted`; `existing_access_kind_unsupported` for a password-only or keyboard-interactive account, which the catalog cannot represent in M03 (disclosed; §8 of the plan) |
| ⟨r3⟩ The existing-access **endpoint** is concrete and is not Heimdall's (§6.3; §17.4 item 4; Q24) | `existing_access_endpoint_unrecorded` (the identity's record names no endpoint, and the alias's own `IdentityAgent` does not determine one); `existing_access_endpoint_is_heimdall` (it is, or resolves to, a Heimdall endpoint) |
| No enrollment for this (pair, CA) is in a non-final state other than ⟨r3⟩ `abandoned` (§17.4 item 5: re-enrolling an abandoned pair uses a new marker, and the old residual stays listed; Q25) | `CONFIG_CONFLICT`, `already_enrolled` |
| `--registry-path`, when given, is absolute POSIX, ≤ 255 bytes, from `[A-Za-z0-9._/-]`, with no `..` component | `USAGE_ERROR` |

The preview is **local and passive**. It contacts nothing; reading the remote registry is a step of
`apply`. Its plan names:
* destination and account;
* ⟨r2⟩ the approved target (HostName, Port, User, empty proxy chain, host key);
* ⟨r2⟩ the **existing-access invocation** every remote step will use (§6.3), with the identity and
  ⟨r3⟩ its **concrete endpoint**, resolved as §6.3 says and never from `SSH_AUTH_SOCK` (§17.4 item 4);
* ⟨r3⟩ the **host-trust pins** of §6.3, which make the approved host key the only trust source
  (§17.4 item 1);
* ⟨r3⟩ the **conditional bootstrap step**: "if the registry's directory is absent, create it, mode
  0700" (§6.3; §17.4 item 3). It is part of the approved plan, so `apply` never creates a directory
  the owner did not see;
* ⟨r3⟩ that `reconcile` may stop **Heimdall's own** stale script on the destination: TERM, then KILL,
  of the exact process group its lock recorded (§6.3, §6.7). Nothing else is ever signalled;
* the registry path: given, or `$HOME/.ssh/authorized_keys` resolved by the remote shell;
* the exact line;
* the CA fingerprint;
* the verification plan;
* rollback;
* the disclosures, ⟨r2⟩ reported **separately from the target identity**:
  * this connects with your configuration for `<alias>` for everything that is not pinned, so its
    `Match exec` and similar entries run as in ordinary use (ADR-0007 D5);
  * the CA trust on this account lets this device's issuer mint certificates for this principal;
  * lock continuity, if not yet acknowledged.

`plan_digest` covers all of it.

### 6.2 The enrollment record and its states

`EnrollmentRecord`:
* identity: `{ id: enr_…, destination, account, ca_fingerprint, form: account | system, marker }`;
* `registry: { path_display, resolved_by: explicit | remote_home }`;
* `line_sha256`;
* ⟨r2⟩ `target: ApprovedTarget { hostname, port, user, host_key }`, the approved target;
* ⟨r3⟩ `existing_access: { identity, endpoint, public_key_file }`, with the concrete endpoint approved
  with the plan (§6.3);
* ⟨r3⟩ `hold: Option<{ reason, evidence_based: bool }>`;
* ⟨r3⟩ `removal_origin: Option<{ state, evidence }>`: the state and evidence a manual removal began
  from, persisted so that cancelling returns there (§17.4 item 5);
* ⟨r3⟩ `late_write: Option<{ step_token, not_after_remote }>`: the "possible late write" residual of
  an uncertain append that was left for `withdrawn` or `abandoned` (§6.7);
* `state`, `verified_at`, `evidence: { client, server, verified_by_operation, ⟨r2⟩ clock:
  ClockMeasurement | unmeasured }`;
* `created_at`, `updated_at`.

The marker is `heimdall:<enrollment-id>`. It is opaque and is the add's idempotency key.

⟨r2⟩ The table is reconciled with the stage receipts and outcomes before it is frozen (§17.1 item 7;
M03-R07, F06). It has 20 states. **Every** documented recovery path has a test, not only every pair of
the table (plan U0 `enrollment_recovery_paths_each_tested`).

⟨r3⟩ Revision 3 changes transitions, not states (§17.4 item 5; A R2-05, B R2-05, B R2-06):
* cancelling a manual removal returns to the state it began from;
* system trust the owner may have installed stays listed until its absence is verified;
* `held` has owner-driven exits;
* a retry of the initial verification runs under the still-open `enrollment.apply`;
* a lock holder that cannot be proven gone ends in `held`, for manual recovery, never in a redispatch
  (§17.4 item 2).

⟨r4⟩ Revision 4 adds two things (§17.7 items 4 and 5): the foreign-removal admission (the `planned`
row), and the rule that a target change replaces the approved target only on a pass (`held` and
`reverifying` rows).

| State | Form | Meaning | Allowed transitions (event) |
|---|---|---|---|
| `planned` | both | Operation admitted, awaiting the owner decision | `applying` (account: `EnrollAccount` approved); `manual_pending` (system: `EnrollSystemForm` approved); `withdrawn` (denied, cancelled, or the decision is stale; nothing written); ⟨r4⟩ for a **foreign record** (D4 item 5; §17.7 item 4): `removing` (account form: `RemoveEnrollment` approved), `manual_removal_pending` (system form: the owner's typed confirmation; origin `planned`) |
| `applying` | account | The approved operation is running; nothing remote is known written | `applied_unverified` (append confirmed, or `already_present` with the exact line); `outcome_unknown` (the result of an append, ⟨r3⟩ or of a bootstrap, was lost or timed out); `failed_unwritten` (refused before any write: not manageable, provider locked, host trust, route changed, ⟨r3⟩ not-after passed, parent directory absent, endpoint changed); `held` (post-write check failed); stays `applying` on `busy` (bounded retries, §6.3) and ⟨r3⟩ after a confirmed bootstrap |
| `outcome_unknown` | account | The append may or may not have applied | `applied_unverified` (reconcile: exactly one exact line); `applying` (reconcile: marker absent, ⟨r3⟩ **the old holder proven gone**, and the other conditions of §6.7, within the approval's validity, on an attended session); `held` (damaged line or two marker lines; ⟨r3⟩ or `lock_holder_unresolved` after `holder_termination_attempts` reconciles); ⟨r2⟩ `withdrawn` (marker absent after fencing and the approval lapsed: `DECISION_STALE`, `approval_lapsed`; ⟨r3⟩ it keeps the `late_write` residual until that clears); ⟨r2⟩ `abandoned` (owner; ⟨r3⟩ with the `late_write` residual); stays while unreachable, or while the old holder may still be alive |
| `held` | both | Our marker or trust is present but wrong, or a check failed in a way that needs the owner. Nothing automatic happens. ⟨r3⟩ `hold.reason` says which | `removing` (account: `RemoveEnrollment`, ⟨r3⟩ which carries a **freshly evaluated target** when the hold is a host-key change); `manual_removal_pending` (system; origin `held`); `abandoned`; ⟨r3⟩ `reverifying` (owner, `enroll verify`, for an **evidence-based** hold only: `principals_not_enforced`, positive refused, or verification failed after the approval lapsed); ⟨r3⟩ `reverifying` (decision `ApproveTargetChange` approved, for a `host_key_changed` hold: the new host key is shown as a diff against the approved one. ⟨r4⟩ The `enrollment.verify` operation carries it as the **proposed target**, and the approved target is unchanged until a pass; §6.5 item 3, §17.7 item 5); ⟨r3⟩ `applied_unverified` or `withdrawn` (the manual-recovery reconcile of a `lock_holder_unresolved` hold, §6.7: one exact line, or none; never a redispatch) |
| `applied_unverified` | account | The exact line is present; no positive and negative verification has passed | `verifying` (⟨r3⟩ through `reconcile` while the `enrollment.apply` approval is valid; through `enroll verify` after it has lapsed); `removing` (`RemoveEnrollment`); `abandoned` |
| `manual_pending` | system | Approved; waiting for the owner to apply the sshd lines (§6.9) | `verifying` (owner confirms applied); ⟨r3⟩ `manual_removal_pending` (owner cancels: the owner may already have installed the lines, so the entry stays until their absence is verified; origin `manual_pending`); ⟨r3⟩ `abandoned` |
| `verifying` | both | The **initial** verification (§6.5) is running | `verified` (pass); `rollback_pending` (account: failure with refusal evidence, or principals not enforced, ⟨r3⟩ **while the approval is valid**); ⟨r3⟩ `held` (account: the same failure after the approval lapsed; removal needs `RemoveEnrollment`); `manual_pending` (system: failure or inconclusive, with the finding); `applied_unverified` (account: inconclusive or unreachable); ⟨r2⟩ `held` (host-key mismatch: no rollback over an untrusted host; or the system form with principals not enforced) |
| `verified` | both | Positive passed with exactly one signature and the negative was refused with full refusal evidence (§6.5). `destination_scope: verified_server_principals` may be claimed for the pair | ⟨r2⟩ `reverifying`; `removing` (account: `RemoveEnrollment`); `manual_removal_pending` (system; origin `verified`) |
| ⟨r2⟩ `reverifying` | both | A **later** verification (§6.5, owner or supervisor). Never removes anything (§17.1 item 5) | `verified` (pass: freshness renewed; **or**, when it started from `verified`, unreachable or inconclusive: unchanged freshness and a doctor finding); `held` (failure: `principals_not_enforced`, or positive refused with refusal evidence; grants under that CA for that pair degraded). ⟨r3⟩ When it started from `held`, an unreachable or inconclusive result returns to `held` with its reason unchanged. ⟨r4⟩ **A target-change attempt** (from a `host_key_changed` hold; §17.7 item 5) takes its pins from the operation's proposed target. A pass replaces the approved target with it, atomically with the move to `verified`. A failure or an inconclusive result leaves the approved target unchanged, and the record returns to `held`, reason unchanged |
| `rollback_pending` | account | The initial verification failed; removing our line under the enrollment decision | `verification_failed` (removed); ⟨r2⟩ `rollback_unknown` (the remove step's result was lost); `held` (`registry_changed` three times, or not rewritable: manual instructions; ⟨r3⟩ or `lock_holder_unresolved`); ⟨r2⟩ `abandoned` |
| ⟨r2⟩ `rollback_unknown` | account | The rollback's removal may or may not have applied. It keeps the **rollback** purpose | `verification_failed` (reconcile: marker absent); `rollback_pending` (reconcile: present, ⟨r3⟩ the old holder proven gone); ⟨r3⟩ `held` (`lock_holder_unresolved`); `abandoned`; stays while unreachable |
| `removing` | account | **Explicit** owner-decided removal running (`RemoveEnrollment`) | `removed`; `remove_unknown`; `held` |
| `remove_unknown` | account | The explicit removal may or may not have applied. It keeps the **explicit removal** purpose | `removed` (reconcile: marker absent); `removing` (reconcile: present, ⟨r3⟩ the old holder proven gone); ⟨r3⟩ `held` (`lock_holder_unresolved`); ⟨r2⟩ `abandoned`; stays while unreachable |
| ⟨r2⟩ `manual_removal_pending` | system | The owner is to remove the sshd lines; Heimdall shows them. ⟨r3⟩ `removal_origin` holds the state and evidence it began from | `removal_verifying` (owner confirms removed); ⟨r3⟩ **the origin state, with its evidence restored** (owner cancels: `verified`, `held`, `abandoned` or `manual_pending`, ⟨r4⟩ or `planned` for a foreign record). ⟨r5⟩ **For a foreign record** (§17.10 item 2): `abandoned` (the owner abandons; `pending_until_line_removed` is kept); and once a `ca_not_held` result exists, a cancel leaves it in `manual_removal_pending`, or returns it to `held` when a held foreign record began the removal. It never reaches `planned` or `withdrawn` |
| ⟨r2⟩ `removal_verifying` | system | The absence check runs (§6.9) | `removed` (absence verified); ⟨r3⟩ `withdrawn` (absence verified, and the origin was `manual_pending`, so no verification ever passed); `manual_removal_pending` (still accepted, or inconclusive; origin kept). ⟨r4⟩ A foreign record's check always ends inconclusive, `ca_not_held` (D4 item 5; Q28) |
| `verification_failed`, `removed`, `withdrawn`, `failed_unwritten` | — | Final; no trust of ours remains, as last observed. `removed` for the system form means **absence verified**, never "removed by Heimdall". ⟨r3⟩ A `withdrawn` record may still carry the `late_write` residual (§6.7), listed until an inspect after its not-after shows absence | none |
| `abandoned` | both | The owner gave the account up while unreachable, held or uncertain. Trust may remain. Reported `pending_until_line_removed`; listed by uninstall and the bundle. ⟨r3⟩ It is **outside** the uniqueness rule: a new enrollment of the pair uses a new marker, and this record stays listed (Q25) | `removing` (account: a new `RemoveEnrollment`, whose reconcile may break this enrollment's own stale lock once its holder is proven gone, §6.7); `manual_removal_pending` (system; origin `abandoned`) |

A pair is usable for managed issuance only through a `verified` enrollment (`reverifying` counts as
`verified` while it runs, ⟨r3⟩ when it started from `verified`, never from `held`). Those are the
only states that add the CA to the pair's issuable set. ⟨r2⟩ **CA retirement** requires every
enrollment of that CA to be final or `abandoned` (D4 item 3).

### 6.3 The remote registry protocol

**Who runs a remote step: client-executed steps.** The remote steps run in the **owner's CLI process**
that drives the operation, not in the runtime. Existing access may need the owner's terminal (a key
passphrase, a hardware touch, a provider dialog attributed to that terminal), and the background
runtime has none. ⟨r2⟩ A password-only account is not enrollable in M03 (§6.1). The runtime keeps the
journal:

1. `Enrollment::Step { operation_id }`.
   * ⟨r2⟩ It is accepted from the **owner role** only (F20).
   * ⟨r2⟩ It re-evaluates the route (below) and refuses with `route_changed` on any difference.
   * ⟨r2⟩ At most **one step is outstanding** per enrollment (§17.1 item 6).
   * It writes the stage receipt first: `Attempted` (effect token = the marker) for `append` and
     `remove`, ⟨r3⟩ `Attempted` (effect token = the marker plus `:dir`) for `bootstrap`, and `started`
     for `inspect`. Only then does it return the step: `{stage, step_token, script, client, pins,
     alias, remote_command, timeout_ms, hard_deadline, ⟨r3⟩ not_after_remote}`, where `step_token` is
     128 random bits.
   * ⟨r3⟩ A mutating step needs a fresh remote clock reading: an `inspect` of the same operation less
     than `enrollment_inspect_max_age` (10 min) old. Otherwise `Step` returns an `inspect` first.
2. The CLI runs the invocation below on its own terminal. It then sends `Enrollment::StepResult {
   operation_id, step_token, exit_status, stdout, stderr_excerpt }`.
   * ⟨r2⟩ It is accepted from the owner role only.
   * stdout is bounded to ⟨r2⟩ 512 KiB (F25; it must fit one 1 MiB control frame with its envelope);
     the stderr excerpt is bounded to 4 KiB and redacted.
3. The runtime parses and checks the result (HM1 and the post-write check below) and records
   `Confirmed`, `NotApplied` or `Uncertain`. A result whose `step_token` is not the outstanding one is
   refused with `REQUEST_CONFLICT`, and nothing is recorded.

If the CLI dies, or no result arrives within the step's `timeout_ms`, a mutating step is `Uncertain`
(`outcome_unknown`) and a read step can be retried. **The runtime never runs the existing-access `ssh`
itself.**

The CLI's report is **not** what the security claim rests on:
* `verified_server_principals` comes only from the verification the runtime runs itself (§6.5);
* every mutating result is re-checked by a later `inspect`.

A same-user caller that forges results is inside the disclosed boundary. It can make an enrollment fail
or stay held; it cannot make one verify.

⟨r2⟩ **Route re-evaluation before every dispatch** (§17.1 item 2). `Enrollment::Step` re-runs the
`TargetEvaluator` for the alias and compares the result with the approved target. A difference in
HostName, Port, User, proxy chain or the known host key, or a target that is no longer determined,
refuses the step with `CAPABILITY_UNAVAILABLE`, reason `route_changed`. A new enrollment decision is
needed. The step's stage receipt is not written in that case. ⟨r3⟩ It also re-validates the approved
existing-access endpoint (below); a change refuses with `existing_access_changed`.

**Invocation.** Every remote step is **one** `ssh` process:
* the verified client from M02's client inventory, named in the step;
* the user's ordinary configuration for everything not pinned (P included);
* ⟨r2⟩ the **pins**, all passed with `-o`. Command-line values are read first and win (F1). ⟨r3⟩ They
  are also parsed before any configuration file, so a configured `IgnoreUnknown` cannot hide one, and a
  pin a client does not know fails the step before it connects (M-F25). The M02 client floor (9.5) knows
  every pin below.
  * **target** (§17.1 item 2): `HostName=<approved>`, `Port=<approved>`, `User=<approved>`,
    `ProxyCommand=none`, `ProxyJump=none`, ⟨r3⟩ `CanonicalizeHostname=no`;
  * ⟨r3⟩ **host trust** (§17.4 item 1; A R2-01). The approved host key is the **only** trust source.
    The pins, and the reason each one is needed, are in the table below;
  * **existing access** (§17.1 item 4; M03-R04), for **every** remote step, the initial append
    included (§17.3 item 5):
    * ⟨r3⟩ `IdentityAgent=<the approved concrete endpoint>`;
    * `IdentityFile=<the adopted public key file>`, `IdentitiesOnly=yes`;
    * `CertificateFile=none` (§17.3 item 2; M-F20);
    * `ControlMaster=no`, `ControlPath=none`;
  * **narrowing:** `BatchMode=<yes when non-interactive>`, `ForwardAgent=no`,
    `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `RequestTTY=no`, ⟨r3⟩
    `ForkAfterAuthentication=no` (§17.4 item 7);
* `-T`, then the alias, then ⟨r3⟩ the fixed remote command `printf 'HM1 ready\n'; exec /bin/sh -s`.

⟨r3⟩ **The ready handshake** (B R2-04). The CLI writes the script to ssh's stdin only **after** it has
read the line `HM1 ready` from ssh's stdout.
* The line proves three things at that moment: authentication finished, the remote session is
  running, and the CLI is alive.
* A CLI that dies while ssh waits on a provider approval or a passphrase has written nothing. So a
  stale approval can never deliver an old script later.
* Any output before `HM1 ready` (a noisy login rc) is a `registry_unsupported` refusal, and the script
  is never sent.

⟨r3⟩ **The host-trust pins, and why each is needed** (§17.4 item 1). The list was checked against the
pinned ssh_config(5) and ssh(1) that ADR-0003 points to (`docs/sources/snapshots/S01.txt.gz` and
`S02.txt.gz`; M-F25):

| Option | Pin | What it would otherwise do | Why the pin covers it |
|---|---|---|---|
| `UserKnownHostsFile` | the generated `<runtime_dir>/e/<16 hex>/known_hosts`. It is owner-only and holds exactly one plain line: the alias and the approved key, with no marker, no pattern and no hashed name | The default `~/.ssh/known_hosts` and `~/.ssh/known_hosts2`, or any configured list. Any of them may trust another key | One file, written and digest-checked by the runtime before it returns the step. The first value wins, and the directive takes the whole list |
| `GlobalKnownHostsFile` | an empty generated file | `/etc/ssh/ssh_known_hosts` and `ssh_known_hosts2`, or any configured list | ssh_config(5) documents no `none` for it, so an empty file is used (§17.3 item 5) |
| `KnownHostsCommand` | `none` | Runs a command whose output adds host keys "in addition to" the files: reviewer A's reproduction | `none` is not documented for this option in the pinned page: **Q22**. Each client's handling is recorded, and the wrong-key test refuses before any mutation |
| `VerifyHostKeyDNS` | `no` | With `yes`, trusts a key matching a DNSSEC-secured SSHFP record | `no` is documented |
| `HostKeyAlgorithms` | exactly the approved key's algorithms: its key type, or for RSA `rsa-sha2-512,rsa-sha2-256`. Never a `-cert-v01@openssh.com` type | Lets the server present another key type, or a host certificate | No other key and no certificate can be negotiated, so `@cert-authority` lines and `CASignatureAlgorithms` never come into play |
| `HostKeyAlias` | `hm-target-<16 hex>` | The lookup uses the host name and port as configured, so how the user's files spell them would matter | The lookup name is the generated one, present only in the generated file |
| `StrictHostKeyChecking` | `yes` | `ask`, `accept-new`, `no` or `off` add unknown keys or accept changed ones | Documented: it never adds a key and refuses a changed one. An unknown key is refused without a prompt |
| `CheckHostIP` | `no` | With `yes`, it checks and **adds** address entries "regardless of the setting of StrictHostKeyChecking", and runs `KnownHostsCommand` once more | `no` is documented, and nothing is written |
| `UpdateHostKeys` | `no` | Adds server-sent keys to the user file after authentication | `no` is documented. The generated file is also re-checked by digest before each step |
| `NoHostAuthenticationForLocalhost` | `no` | With `yes`, it **disables host authentication** for a loopback destination, and every M03 fixture is one | **Not in §17.4 item 1's list.** The check added it, because the ruling asks for every option that affects host trust. Its wrong-key fixture test runs on loopback |
| `ControlMaster`, `ControlPath` | `no`, `none` | A mux client reuses an existing master, whose host was authenticated under **its own** options, so this invocation's check is skipped | `none` is documented to disable sharing |
| `ProxyCommand`, `ProxyJump`, `CanonicalizeHostname` | `none`, `none`, `no` | They change which server is reached; canonicalization also re-parses the configuration under a new name | Route pins. Trust still rests on the key; the route is pinned so that the approved destination is the one reached (§17.1 item 2) |

* **Not pinned, because they can only refuse.** The user's values apply: `RevokedHostKeys` (a missing
  file refuses every host), `RequiredRSASize`, and `CASignatureAlgorithms` (host certificates are
  excluded anyway).
* **Not pinned, because they write or display only.** `HashKnownHosts`, `VisualHostKey` and
  `FingerprintHash` change how keys are written or shown, and nothing is written.
* **Options outside the pinned sources** are Q23 (a vendor patch's GSSAPI key exchange).
* **The effective configuration is checked.** Before the first step of an operation, the runtime runs
  the client's `ssh -G` with exactly the step's pins and alias. Unless every option in the table has its
  pinned value, it refuses with `host_trust_unpinnable`.

⟨r3⟩ **The existing-access endpoint** (§17.4 item 4; A R2-04).
* **It is resolved from the catalog identity record**, never from any process's `SSH_AUTH_SOCK`:
  * `native_agent`: the record's endpoint;
  * `onepassword`: the record's endpoint, when it names one;
  * a record that names none (1Password at its default, or a public-key-file identity used through an
    agent) is **Q24**. Default until ruled: the alias's own `IdentityAgent`, statically evaluated from
    the user's configuration **with P's managed block excluded**. When that is unset, `none` or
    undetermined, the preview refuses with `existing_access_endpoint_unrecorded`; the remedy is to
    record the endpoint on the catalog identity (M02's catalog update).
* **It is shown and approved.** The plan names the endpoint, and the decision and the request hash
  cover it.
* **It is refused** (`existing_access_endpoint_is_heimdall`) if it is, or resolves to, a Heimdall
  managed endpoint:
  * any path under the runtime directory;
  * any name in the signer's endpoint registry (environment, binding and verification endpoints,
    Windows pipe names included);
  * any symlink resolving to one of those.
* **It is re-validated before every step**: unchanged, present, owned by the user, and still not
  Heimdall's. Otherwise the step is refused with `existing_access_changed`, which needs a new
  decision.
* **Why it holds.**
  * The pinned `IdentityAgent` is read first, so neither P nor a managed `run`'s `SSH_AUTH_SOCK` can
    select Heimdall's signer.
  * `IdentitiesOnly` with the adopted public key keeps the managed key file from being offered.
  * `maintenance_inside_managed_run_context_zero_managed_signatures` runs maintenance from inside a
    managed `run`, whose `SSH_AUTH_SOCK` is the binding endpoint, and asserts zero signatures on every
    Heimdall endpoint.

The script is written to the child's stdin, ⟨r3⟩ after the ready line.

* **Why the managed credential is never used.** The pinned `IdentityAgent` replaces P's environment
  endpoint, and K_env lives only in Heimdall's signer, which that agent cannot reach. So a maintenance
  step never depends on the credential it repairs. Its tests run with every managed binding released
  and the issuer unavailable (plan U5, U10).
* ⟨r2⟩ **ADR-0007 §9 item 1** keeps tests from adding `IdentityFile`, `HostName` and similar options,
  so that the configuration under test is what decides. These pins are product behaviour, pinning the
  approved target and identity, and are tested as product output.
* The remote login shell interprets only ⟨r3⟩ the fixed remote command. Every value is a validated
  literal inside the script, in single quotes:
  * the line's character set (`[A-Za-z0-9+/=,:" ._@-]`) contains no `'`;
  * paths are validated (§6.1).
* Host trust is never weakened. A host-key failure (exit 255 with "Host key verification failed")
  maps to `HOST_TRUST_CHANGED`.

⟨r3⟩ **The step runner's lifetime** (§17.4 item 2; B R2-04). `SshStepRunner` ties ssh to the CLI:
* **Unix:**
  * ssh runs in its own process group, and the CLI kills the group on drop and on every signal it
    handles;
  * on Linux the child also gets `PR_SET_PDEATHSIG(SIGKILL)`;
  * macOS has no parent-death signal. The ready handshake covers that case: a dead CLI never writes the
    script, and its closed pipe ends ssh's input.
* **Windows:** ssh runs in a kill-on-close job object owned by the CLI (M02's `JobObject` primitive),
  so the CLI's death ends it.

Bounds:
* stdout ≤ 512 KiB and stderr ≤ 64 KiB (excerpt 4 KiB), read concurrently;
* connect 30 s;
* total 120 s, or 300 s for an interactive step that may wait on a provider approval;
* ⟨r2⟩ the step's **hard deadline** is its issue time + `timeout_ms` + 60 s + 30 s, on the runtime's
  continuous clock.
  * ⟨r3⟩ It is persisted together with the wall-clock deadline and the boot ID (B R2-11).
  * After a local reboot the continuous value is void. The deadline then counts as passed only once
    **safe** wall time has passed the wall deadline, which means after `time confirm` (Q13);
* ⟨r3⟩ the step's **remote not-after** (B R2-04):

  ```
  not_after_remote = T + (c_issue − c_read) + timeout_ms + 60 s
  ```

  * `T` is the remote clock reading of the operation's latest `inspect`;
  * `c_read` is the local continuous time at which that reading arrived;
  * the remote clock has passed `not_after_remote` by the hard deadline, with 30 s to spare for the
    reading's resolution and drift.

**Output.** Line-oriented: `HM1 <key>=<value>`. Values are decimal, a fixed token, or lowercase hex
produced by `od -An -v -tx1`, never raw bytes. ⟨r3⟩ The first line is the ready line, and the first line
of the script's own output must be `HM1 v=1`. Otherwise the remote shell is not POSIX, or something
printed before the script ran, and the step fails with `registry_unsupported`, writing nothing.

**Utilities** (M-F10, M-F23, ⟨r3⟩ M-F30, M-F31): `sh`, `id`, `ls`, `test`, `cat`, `cmp`, `od`, `tail`,
`grep`, `awk`, `mkdir`, `chmod`, `mv`, `rm`, `printf`, ⟨r3⟩ `ln`, `kill`, `ps` and `uname`, ⟨r7⟩ `date`
(POSIX fields only, for the remote clock) and `sleep` (the fence's waits after a signal; §17.17 item 7),
plus the start-identity sources below. No `stat`, `sha256sum`, `base64`, `xxd`, `readlink` or `date +%s`,
because none of them is POSIX.1-2017.

⟨r3⟩ **Script hardening** (§17.4 item 2; B R2-10, B R2-14).
* **A truncated script does nothing.** Every script is one function, `hm_main() { … }`, called on its
  **last** line (`hm_main`). A stream cut anywhere before that line leaves either an incomplete
  definition, which is a syntax error so nothing runs, or a complete one that is never called (M-F26). A
  golden test cuts every script at every byte offset and runs each prefix on every target shell.
* **One locale.** The function's first statement is `export LC_ALL=C` (M-F32).
* **One umask.** `umask 077` follows it.

⟨r3⟩ **Fencing: a per-registry lock that records its holder, broken only on proven termination**
(§17.4 item 2; A R2-02, B R2-04). This replaces revision 2's `mkdir` lock and rename-aside, which let a
paused writer append after its lock was taken away (reviewer A's model produced two marker lines).

1. **The holder record is the lock.** Every mutating script (`append`, `remove`) takes the lock with one
   atomic call (M-F31):

   ```sh
   ln -s "hm1-$TOKEN-$$-$START-$BOOT-$NOT_AFTER" "$DIR/.hm-lock.$NAME"
   ```

   * `$$` is the script's shell, the session's process-group leader (M-F30). The script first checks
     that its own process group equals `$$`, ⟨r5⟩ read as the shell table below says (⟨r6⟩ on Linux,
     token 3 after the last `)` of `/proc/$$/stat`, through the shared parser below; `ps -o pgid= -p $$`
     on macOS and the BSDs; Q29). If not, it exits **33**
     (`no_process_group`) before taking the lock;
   * `$START` and `$BOOT` are the start identity and boot identity from the table below, as lowercase
     hex (`od`), so the link's contents use only `[0-9a-f-]`;
   * before `ln`, a **directory** at the lock name (which would make `ln` create the link inside it)
     exits 30;
   * after `ln`, `ls -ld` must show a link whose contents are exactly the script's own. Otherwise the
     script exits 30, after removing only a link it created inside a foreign directory.
2. **Before the lock**, the script checks two more things:
   * that the registry's directory exists. If it is absent, the script exits **32**
     (`registry_dir_absent`), distinct from `busy`, with nothing changed (§17.4 item 3; A R2-03);
   * the remote clock against `NOT_AFTER`. If that has passed, it exits **41** (`not_after_passed`).
3. **A lock that already exists** makes the script exit **40 `busy`**, with nothing changed, whoever
   holds it.
   * A lock carrying another enrollment's token is `busy` for every other enrollment. No enrollment ever
     breaks another's lock (§17.4 item 2).
   * The runtime retries a busy step with bounded, jittered backoff (3 attempts). It then reports
     `CONFIG_CONFLICT`, reason `registry_busy`, and shows the lock's holder record.
4. **Immediately before the write**, the script re-checks two things:
   * the link still holds its own contents, else **42 `lock_lost`**;
   * the remote clock has not passed `NOT_AFTER`, else **41**.
5. It then mutates, reads back, and **releases** the lock by removing the link after checking its
   contents.

**Breaking a lock** is done only by `reconcile` of the **same** enrollment (§6.7), and only once the
holder is **proven gone**. Age alone never proves it. The `fence` script runs under the same pins,
reads the holder record (`PID`, `START`, `BOOT`), and decides `gone`, `alive` or ⟨r4⟩ `unproven`.

⟨r4⟩ **The group-gone proof: two methods that must agree, after a control** (§17.7 item 1; M03-R3-01).
Revision 3 read a failing `kill -0 -- -PID` as "no process in the group". dash rejects that syntax
("Illegal number: -", exit 2), so a syntax error was read as proof, and the reviewer's reproduction lost
a write. Now no failure is ever read as proof:
1. **The control.** The probing shell is its own group leader: the script checks that its process
   group (⟨r5⟩ read as for the lock, per the shell table) is `$$`, else it exits 33. It then runs
   `kill -s 0 -- -$$` against its **own** group, which must exit 0. This proves that this shell accepts exactly this syntax and can signal a live group.
2. **The probe.** `kill -s 0 -- -PID`, the POSIX form (`-s 0` is the null signal, and `--` ends the
   options). Its exit status is recorded.
3. **The listing.** `ps -A -o pgid=` must exit 0 **and** list the probing shell's own group (`$$`); that
   is the listing's own control. The target is "listed" when any line, with spaces trimmed, equals
   `PID`.

| Control | Probe | Listing | Group |
|---|---|---|---|
| exit 0 | exit ≠ 0 | own group present, target **absent** | **empty** (the two methods agree) |
| exit 0 | exit 0 | own group present, target **present** | **live** (the two methods agree) |
| exit ≠ 0 (a syntax error, an unknown option) | — | — | unproven |
| exit 0 | exit ≠ 0 | target present (a permission failure, or a disagreement) | unproven |
| exit 0 | exit 0 | target absent (a disagreement) | unproven |
| exit 0 | — | listing failed, or lacks the shell's own group, or is unparseable | unproven |

Every combination not in the first two rows is **unproven**.

**The decision.**
* **gone** when:
  * the boot identity differs (every process of that boot has ended), ⟨r7⟩ **only on a row whose boot
    identity is stable** (Linux `boot_id`, macOS `kern.bootsessionuuid`). On a row whose boot identity
    is a timestamp (the BSDs' `kern.boottime`, which a clock step moves), a difference alone never
    proves `gone`: the group proof below is still required (§17.17 item 2); or
  * the group is **empty** by agreement, **and** `PID` either does not exist or exists with a
    different start identity. ⟨r4⟩ A different start identity alone no longer decides: revision 3
    inferred "gone" from the PID-reuse rule (M-F30); now the group proof must agree.
* **alive** when the group is **live** by agreement, and either:
  * `PID` exists with the same start identity (a zombie included); or
  * `PID` does not exist. This is the **leader-absent** case: the shell was killed or exited, but one
    of its children (for example a `mv` stopped just before its write) is still in the group. Because a
    PID is not reused while a group with that ID has members (M-F30), these members are the holder's,
    except in the disclosed process-group reuse window (§17.6 item 5).
* **unproven** otherwise. That includes a live group while `PID` exists with a different start
  identity: that group may not be the holder's, so it is never signalled.

An **alive** holder whose `NOT_AFTER` has passed on the remote clock may be **terminated**:
1. `kill -s TERM -- -PID`, then wait up to 5 s;
2. `kill -s KILL -- -PID`, which also ends a stopped process, then wait up to 5 s;
3. prove again, with the control, the probe and the listing.

* **Re-checks.** The decision is re-made before each signal.
* **Only `gone` removes the link.** `unproven` never removes the link, and counts as a failed attempt.
* ⟨r5⟩ **Exit 44 means "no unlock"** (§17.10 item 4; M03-R4-04). An `unproven` decision authorizes **no
  further signal**. It is never read as "nothing was signalled". When `--terminate` found `alive`, sent
  TERM (or TERM and then KILL), and the proof then came back `unproven`:
  * the script stops signalling;
  * it reports what it sent, as `HM1 fence_signals=TERM` or `TERM,KILL`;
  * the runtime keeps that list in the step result and in the audit event (`enrollment.fence`, with the
    lock path, the holder record, the decisions in order and the signals sent).
* **When the proof keeps failing** (a process in uninterruptible sleep, a shell that rejects the
  syntax, a listing that disagrees), nothing is removed, and the step stays `busy` or uncertain.
* **Bounded attempts.** After `holder_termination_attempts` (3) reconciles, the record is `held`
  (`lock_holder_unresolved`), with manual instructions. **It is never redispatched** (§6.7).

⟨r3⟩ **The start identity and the group proof per target shell** (§17.4 item 2; M-F30; ⟨r4⟩ §17.7
item 1; ⟨r5⟩ §17.10 item 5). The start identity depends on the target's userland. The group proof
depends on the shell's `kill` built-in and on the userland's `ps`. ⟨r5⟩ The "Observed" column is the
round-4 re-check's per-shell probe (`tests/evidence/artifacts/review-m03-design/round4-recheck-codex.md`).
Its exit codes are C/K/L, where C is the control `kill -s 0 -- -$$`, K the probe `kill -s 0 -- -PGID`,
and L the listing `ps -A -o pgid=`. The probes ran in containers from
`debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` and
`alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`, and on native macOS.

| Target (shell) | Start identity | Resolution | Boot identity | ⟨r5⟩ Process group of `$$` | ⟨r4⟩ Group probe and control | ⟨r4⟩ Listing | ⟨r5⟩ Observed (round-4 re-check) | ⟨r5⟩ Fence outcome | POSIX status |
|---|---|---|---|---|---|---|---|---|---|
| dash **0.5.12-12** (Debian 13, Ubuntu 24.04) | ⟨r6⟩ token 20 after the last `)` of `/proc/$$/stat` (field 22, `starttime`), through the shared parser | clock ticks since boot | `/proc/sys/kernel/random/boot_id` | ⟨r6⟩ token 3 after the last `)` of `/proc/$$/stat` (field 5), the same parser (Q29); `ps -o pgid= -p $$` also works | built-in `kill -s 0 -- -PGID`. `kill -0 -- -PGID` is rejected (round 3), so it is not used | procps `ps -A -o pgid=` | live child 0/0/0 → live; empty group 0/1/0 → empty; invalid syntax 2/2/0 → unproven; injected disagreements (3 branches) → unproven | **automatic recovery** (gone by agreement) | start, boot identity and process group **not POSIX** (Linux procfs; read with POSIX `awk` and `cat`); probe and listing **POSIX** |
| bash **5.2.37** as `sh` (Linux) | as for dash | as for dash | as for dash | as for dash | built-in `kill -s 0 -- -PGID` | procps `ps -A -o pgid=` | live child 0/0/0 → live; empty 0/1/0 → empty; invalid syntax 1/1/0 → unproven; disagreements → unproven | **automatic recovery** | as for dash |
| BusyBox **1.37.0** `ash` (Alpine) | as for dash | as for dash | as for dash | ⟨r6⟩ token 3 after the last `)` of `/proc/$$/stat` (field 5), the shared parser (Q29). **`ps -p` is unsupported** (exit 1), so a literal `ps -o pgid= -p $$` stops the script with exit 33 | built-in `kill` **rejects `--`** ("invalid number '--'") | BusyBox `ps -A -o pgid=` (exit 0) | live child 1/1/0 → unproven; empty group 1/2/0 → unproven; invalid syntax 1/1/0 → unproven; disagreements → unproven | **always `unproven`: manual recovery only.** Automatic recovery is never claimed for BusyBox (§17.10 item 5) | as for dash |
| macOS `/bin/sh` (**bash 3.2.57** in POSIX mode) | `ps -o lstart= -p $$` | 1 s | ⟨r7⟩ `sysctl -n kern.bootsessionuuid` (stable across clock steps; §17.17 item 2) | `ps -o pgid= -p $$` (works) | built-in `kill -s 0 -- -PGID` | BSD `ps -A -o pgid=` | live child 0/0/0 → live; empty 0/1/0 → empty; invalid syntax 1/1/0 → unproven; disagreements → unproven | **automatic recovery** | start and boot identity **not POSIX** (`lstart` is a BSD `ps` field; `sysctl` is not POSIX); process group, probe and listing **POSIX** |
| FreeBSD, NetBSD and OpenBSD `sh` | `ps -o lstart= -p $$` | 1 s | `sysctl -n kern.boottime` (up to its first `}`): ⟨r7⟩ a **timestamp**, so a difference alone never proves `gone` and the group proof is still required (§17.17 item 2) [I] | `ps -o pgid= -p $$` [I] | built-in `kill -s 0 -- -PGID` [I] | BSD `ps -A -o pgid=` [I] | not run | [I]: no M03 target runs them | as for macOS |
| Anything else (`uname -s` not recognized) | — | — | — | — | — | — | — | The mutating scripts exit 30 (`start_identity_unavailable`) before the lock; `inspect` still runs | — |

* **Why not POSIX `ps -o etime=`.** It gives the elapsed time, but "now minus elapsed" moves with
  rounding between two reads, so any tolerance would accept a reused PID. It is rejected.
* **The 1 s resolution** leaves a PID reused **within the same second** indistinguishable on macOS and
  the BSDs. With the group check and the boot identity this window is small, and it is disclosed.
* ⟨r5⟩ **Exit statuses only.** The re-check saw bash as `sh` print argument errors for a malformed
  option and still return 0. The decision therefore rests on exit statuses, the shell's own-group
  controls and the agreement of the two methods, never on diagnostics.
* ⟨r5⟩ **Permission failures.** The re-check could not produce a genuine same-user `EPERM`. The
  permission-failure test therefore uses a group owned by another account inside a disposable
  container (U11), or an injected fault, and records which.
* **Evidence.** `start_identity_per_target_shell` records each target's values. ⟨r4⟩
  `group_probe_and_listing_per_target_shell` records each shell's control, probe and listing results.
  `leader_absent_live_mutation_child_never_gone_per_shell` runs on dash, bash as `sh`, BusyBox `ash` and
  the macOS `sh` (§17.7 item 1). The BSD row has no M03 target, and is reported as such. ⟨r5⟩ For
  BusyBox, the expected result of every fencing row is `unproven` and manual recovery, as observed.

⟨r6⟩ **The shared `/proc/<pid>/stat` parser** (§17.13 item 2; M03-R5-02). On Linux, the process group
and the start time both come from one line, read by **one rule**, in the scripts and in Rust alike:
1. Read the whole file. A command name may contain a newline, so a line-based read is not enough.
2. Find the **last** `)`. Field 2 (`comm`) is written in parentheses, and it may itself contain spaces,
   `(` and `)`; the kernel emits the state, ppid and pgrp after it (Linux v6.12 `fs/proc/array.c`).
3. Split the suffix after it on whitespace. **Token 3 is the process group** (field 5), and **token 20
   is the start time** (field 22, clock ticks since boot).
4. Validate. There must be at least 20 tokens, and token 1 must be a single state letter. Token 3 must
   be decimal and at least 1, and token 20 must be decimal. Anything else is invalid:
   * a mutating script then exits 30 (`start_identity_unavailable`);
   * `fence` reports `unproven`;
   * the Rust caller returns no identity.

Why it is needed: a whitespace field count (`awk '{print $5}'`) reads the wrong token as soon as `comm`
holds a space or a `)`. The round-5 check observed this in a container where only `comm` changed and
the real process group was 1:
* `plain` gave 1;
* `has space` gave 0;
* `a ) b ( c` gave `(`.

The suffix rule gave 1 in all three cases.

* **In the scripts** (`heimdall_registry::script`), one POSIX `awk` program:

  ```sh
  awk '{ b = b $0 "\n" } END { i = length(b); while (i > 0 && substr(b, i, 1) != ")") i--;
        if (i == 0) exit 2; n = split(substr(b, i + 1), f, " ");
        if (n < 20 || f[1] !~ /^[A-Za-z]$/ || f[3] !~ /^[0-9]+$/ || f[3] + 0 < 1 ||
            f[20] !~ /^[0-9]+$/) exit 2; print f[3], f[20] }' "/proc/$P/stat"
  ```

  `$P` is `$$` for the script's own shell, or the holder's `PID` in `fence`.
* **In Rust**, the pure function is `heimdall_domain::procstat::parse(&str) -> Result<ProcStat { state,
  pgid, start_ticks }, ProcStatError>`.
  * M01's `runtime::platform::process_start_time` already cuts at the last `)`. It moves onto this
    function, and keeps its rule that `Z` and `X` are not alive.
  * The supervisor's owned-connection checks (D8) use it too.
* **One rule, checked twice.** The same fixtures go through both, and they must agree: synthetic lines,
  and live processes whose `comm` is `plain`, `has space`, `a ) b ( c`, `)(` and a name with a newline.
  The tests are `procstat_fixtures_rust_and_awk_agree` and `procstat_live_comm_fixtures_per_linux_shell`
  (plan U5, U11).

**Scripts** (generated by `heimdall_registry::script`; release builds byte-compare them against
goldens, and the test configuration adds pause points):

| Script | Does | Exit codes |
|---|---|---|
| `inspect` | Resolves the registry path. Reports: the directory (present or absent; its mode string from `ls -ldn`; whether it is owned by `id -u`); the file kind (`regular`, `absent`, `symlink`, `other`); link count, mode string, owner and size; whether the last byte is `0a`; the number of lines containing the marker; the content as hex (≤ 128 KiB); ⟨r3⟩ the lock state (`none`, or `held` with its holder record); and the remote clock reading | 0 ok; 30 not manageable (reports why); 31 too large |
| ⟨r3⟩ `bootstrap` | Creates the registry's directory with `mkdir -m 0700 <dir>` (never `-p`) when it is absent (§17.4 item 3). Before: the **parent** must exist, be a directory and not a symlink, be owned by `id -u` or by root, and not be group- or world-writable. After: `ls -ldn` must show a directory, not a symlink, owned by `id -u`, with mode `drwx------`. A single `mkdir` is atomic and needs no lock; run twice, it reports already present | 0 created; 11 already present (checked as above); 30 not manageable; **33 parent absent** |
| `append` | ⟨r3⟩ Under the lock: (1) Directory: present (else 32); refuse when not owned by `id -u`, or group- or world-writable (M-F11). (2) File: when present, it must be regular, not a symlink, have link count 1, be owned by `id -u`, and carry no ACL, xattr or label indicator (a character after the 10-character mode string). (3) **If any line already contains the marker, exit 10 without writing** (idempotent). (4) The link and not-after re-check. (5) If the file is non-empty and its last byte, read **now** with `tail -c 1`, is not a newline, write one first. (6) Append the line with `>>`; when the file is absent, create it with `set -C` and `>` and then `chmod 600`. (7) Emit the new content as hex. (8) Release the lock | 0 written; 10 already present (nothing written); 30 not manageable; 31 too large; ⟨r3⟩ 32 directory absent; 33 no process group; 40 busy; 41 not-after passed; 42 lock lost |
| `remove` | ⟨r2⟩ Under the lock. It gets the expected preimage and post-image as hex in quoted here-documents, decoded by `awk` `printf "%c"` ⟨r3⟩ under `LC_ALL=C` (registry files are text without NUL; a NUL in the preimage refuses with 30). (1) The checks of `append` step (2), with the directory present. (2) Decode both into `.hm-pre.<nonce>` and `.hm-post.<nonce>` in the registry's directory, with umask 077, then `chmod` the post-image to the registry's permission bits read from `ls -ldn` (only `rw-`/`r--` bit patterns; anything else refuses with 30). (3) `cmp -s <registry> .hm-pre.<nonce>`, or **exit 20 without renaming**. (4) The link and not-after re-check. (5) `mv -f .hm-post.<nonce> <registry>`. (6) Remove `.hm-pre.<nonce>` and emit the new content as hex. (7) Release the lock. A trap removes both temporary files on every exit path | 0 renamed; 20 changed since read (nothing renamed); 30 not manageable; 31 too large; ⟨r3⟩ 32, 33, 40, 41 and 42 as for `append` |
| ⟨r3⟩ `fence` | Reads the lock's holder record and reports `gone`, `alive`, ⟨r4⟩ `unproven`, or `none`, using the control, the probe and the listing, which must agree (above). With `--terminate`, allowed only once the holder's `NOT_AFTER` has passed on the remote clock and only for `alive`, it sends TERM and then KILL to the exact process group, proves again, and removes the link only on `gone` | 0 `gone` (link removed) or `none`; **43 `alive`** (nothing removed); ⟨r4⟩ **44 `unproven`**: ⟨r5⟩ no unlock, and no further signal authorized; any signal already sent is reported in `fence_signals` and kept in the result and the audit record (§17.10 item 4); 30 not manageable |

**Disclosed windows** (stated in every preview and confirmation; ADR-0005 §3.3):
* an administrator write between `append` step (5) and its write can join the administrator's line to
  ours. The post-write check detects it (`held`, reason `registry_line_damaged`), and nothing rewrites
  it automatically;
* an administrator write between `remove` step (3) and (5) is lost, and cannot be detected afterwards.
  It is a few system calls in one remote command;
* ⟨r3⟩ revision 2's window **is closed**: a script suspended between its re-check and its write, which
  could write after its lock was broken. A lock is now broken only once its holder's whole process group
  is proven gone, so a paused writer is either terminated first or keeps its lock
  (`writer_paused_just_before_write_no_duplicate_no_loss`);
* ⟨r3⟩ a PID reused within the same second, on a target whose start identity has 1 s resolution
  (above), and a group emptied and its number reused between `fence`'s check and its signal;
* administrators do not take Heimdall's lock, so the lock fences only Heimdall's own steps;
* on a network file system, `O_APPEND`, `symlink` and `mkdir` may not be atomic [I].

**The post-write check** (after `append`, from its own output, with no extra round trip). Pass requires
both:
* exactly one line contains the marker, and it equals the expected line byte for byte;
* the content with that line removed equals the inspected preimage, or starts with it, because an
  administrator append landing after ours is allowed.

Anything else is `held`, with reason `registry_line_damaged` or `registry_changed_concurrently`; the
owner gets the exact bytes to check.

**After `remove`**: the new content must contain no marker line, and must equal the post-image, or start
with it after a later administrator append. Otherwise `held`.

### 6.4 Stages, commit points and recovery

The operation kind is `enrollment.apply`, effect class `RemoteMutation`. Its request hash covers
destination, account, form, registry path, CA fingerprint, ⟨r2⟩ the approved target, the
existing-access invocation and `plan_digest`.

| Stage | Durable before | Remote effect | Durable after | Crash or lost reply → recovery |
|---|---|---|---|---|
| E0 admit | operation row and intent (the plan); record `planned`; decision `EnrollAccount` (or `EnrollSystemForm`, §6.9) | — | — | Retry with the same key returns it (ADR-0006 §7) |
| E1 approve | decision consumed; approval basis in the intent; record `applying` | — | — | Re-driven on owner reconcile |
| E2 inspect | stage receipt `enroll.inspect.started` | read only | `enroll.inspect.observed {preimage_sha256, size, tail_newline, marker_lines, file_kind, dir_state, lock, remote_clock}` | Re-run: reads are safe |
| ⟨r3⟩ E2b bootstrap (only when E2 found the registry's directory absent; §17.4 item 3) | stage receipt **`Attempted`, effect token = marker + `:dir`** | **`mkdir -m 0700`** of the registry's directory (§6.3 `bootstrap`), with no lock | `Confirmed` (created, or 11 already present and checked), then E3; `NotApplied {parent_absent \| refused}` with record `failed_unwritten`; or `Uncertain` | Re-inspect: present and checked → continue at E3; absent → the bootstrap may run again. A second `mkdir` creates at most the same empty directory, so a late first one does no harm |
| E3 append | ⟨r2⟩ route re-evaluated; stage receipt **`Attempted`, effect token = marker**, with the step token and hard deadline | **append**, under the lock | `Confirmed {post_sha256}` with record `applied_unverified`; or `NotApplied {busy \| ⟨r3⟩ not_after_passed \| lock_lost \| dir_absent \| refused}`; or `Uncertain` with record and operation `outcome_unknown` (`registry_outcome_unknown`) | Unresolved; reconcile per §6.7. **Never re-run blindly**; the script itself refuses a second line (exit 10) |
| E4 verify | `enroll.verify.started`; verification issuance entries reserved and published (§6.5) | independent logins (no mutation) | `enroll.verify.passed {client, server, signatures: 1, negative_evidence, clock}` or `enroll.verify.failed {reason, evidence}` or `enroll.verify.inconclusive {reason}` | Re-run verification with fresh certificates. The old entries stay counted until their `valid_before` |
| E5 record | — | — | **One transaction:** record `verified` with its evidence; ⟨r2⟩ add the CA to the pair preference's issuing-CA set; **only if the pair is not already managed with its projection applied**, set the preference to `managed_certificate` with `projection: pending` (§6.6; F05); operation `succeeded`, next `setup_apply` only in that case | If E4 passed and E5 did not commit: re-verify, then record |
| E5′ rollback (E4 failed) | record `rollback_pending`; `Attempted` (token = marker plus `:rm`) | **remove**, through the pinned existing access, under the lock | record `verification_failed` (removed), or ⟨r2⟩ `rollback_unknown` | As E3, through reconcile |

**At restart**, enrollment operations are never driven automatically. Their remote steps are
client-executed (§6.3) and need the owner. An open enrollment operation is reported in the
`runtime_lifecycle` event as `{phase: unresolved, kind: "enrollment.apply", reason: owner_reconcile}`,
the M02 setup pattern (ADR-0006 §15.2 item 6), and `inspect enrollments` lists it. `heimdall enroll
reconcile <operation>` resumes it.

**Cancellation** is allowed until the E3 `Attempted` receipt exists. After that it is refused with
`CAPABILITY_UNAVAILABLE`, reason `remote_step_in_progress`: a remote effect may exist. The owner then
uses `reconcile` or `remove` (spec §11.4: cancellation reports whether an uncertain external step may
have occurred).

### 6.5 Production verification (independent fresh login)

ADR-0005 §3.3, as implemented:

1. **A verification signer endpoint** (D2) with a fresh K_verify. The endpoint counts sign requests and
   session-binds per key.
2. **Two certificates** through the **verification issuance table**. It is separate from the grant
   issuance log, because these certificates have no grant. It uses the same reserve, sign and publish
   protocol with its own predicate, `verification::check`:
   * the operation is an approved `enrollment.apply` (rotation is one too, D4 item 3) or an
     `enrollment.verify`, at stage E4 or ⟨r2⟩ the re-verification stage;
   * the entry's pair and CA equal the plan's;
   * the principal is exactly `hm:<destination-id>:<account>` (positive) or
     `hm:verify-negative:<32 hex nonce>` (negative);
   * there are **no extensions** (`clear`): `ssh -T …` needs none;
   * validity: `valid_after` = now − 60 s and `valid_before` ≤ now + 300 s;
   * the subject is K_verify, registered by this operation's verification endpoint;
   * time is `Safe`;
   * at most 4 entries per verification attempt and 3 attempts per operation.

   Entries count toward a **per-pair residual** (D7 item 4) until their `valid_before`.
3. **A generated configuration** in `<runtime_dir>/v/<16 hex>/ssh_config`, never the user's
   configuration (it avoids the inherited `IdentityFile` entries of M-F4). Its directives:
   * `Host hm-verify`;
   * ⟨r2⟩ `HostName`, `Port` and `User` from the enrollment's **approved target** (§6.1), not
     re-read from the catalog;
   * `HostKeyAlias hm-verify-<16 hex>`, and `UserKnownHostsFile` = a generated file holding exactly
     one line: that alias with the approved host key. The check therefore does not depend on how the
     user's known-hosts files write the host and port;
   * ⟨r4⟩ for a **target-change** verification (`VerifyMode::TargetChange`; §17.7 item 5), `HostName`,
     `Port`, `User` and the host key in that generated file all come from the **proposed target** the
     `enrollment.verify` operation carries. The attempt never touches the enrollment's approved
     target. A pass replaces it atomically with the record's move to `verified` (§6.2). A failure or an
     inconclusive result leaves it unchanged, and the record stays `held`;
   * `GlobalKnownHostsFile` = an empty generated file, `CheckHostIP no`;
   * `StrictHostKeyChecking yes`, `UpdateHostKeys no`, `CanonicalizeHostname no`;
   * ⟨r3⟩ the rest of §6.3's host-trust pins: `KnownHostsCommand none`, `VerifyHostKeyDNS no`,
     `HostKeyAlgorithms` limited to the approved key's algorithms, and `NoHostAuthenticationForLocalhost
     no` (§17.4 item 1). `-F` already drops every user and system configuration file, so these state
     the defaults explicitly and keep one tested pin set;
   * ⟨r3⟩ `ForkAfterAuthentication no` (§17.4 item 7);
   * `IdentityAgent` = the verification endpoint, `IdentitiesOnly yes`, `IdentityFile <K_verify.pub>`,
     `CertificateFile <the positive or negative certificate>`;
   * `PreferredAuthentications publickey`, `PasswordAuthentication no`, `KbdInteractiveAuthentication
     no`;
   * `BatchMode yes`, `ControlMaster no`, `ControlPath none`;
   * `ProxyCommand none`, `ProxyJump none`;
   * `ForwardAgent no`, `ClearAllForwardings yes`, `RequestTTY no`, `ConnectTimeout 20`.

   The client is invoked as `ssh -F <generated> -v -T hm-verify <command>`. Stderr is bounded (64 KiB)
   and ⟨r2⟩ parsed for the trace events of item 5.
4. ⟨r2⟩ **The destination clock is measured** in the positive login (§17.1 item 10; M03-R10).
   * **The command** is ⟨r7⟩ the scripts' POSIX
     `date -u '+%Y %m %d %H %M %S'` reading converted in `awk` (M-F23 as revised; §17.17 item 7), printed
     as `HM1 now=<seconds>`, without a stderr redirection because the account's login shell runs it. A
     reading outside 2000–3000 UTC is discarded, and the clock is then `unmeasured`. It is a fixed
     literal and needs no extension. It replaces revision 2's `awk 'BEGIN { srand(); print "HM1 now="
     srand() }'`.
   * **The bound.** With local wall times t₁ (just before the process starts) and t₂ (when the output
     line is read), and the remote reading T, the destination's clock lags local time by at most
     `behind_upper = max(0, t₂ − T + 1 s)`. The 1 s is the reading's resolution.
   * **The record:** `ClockMeasurement { behind_upper_ms, rtt_ms = t₂ − t₁, measured_at }`, stored
     with the enrollment evidence.
   * **Only lag matters.** A destination clock ahead of local time ends acceptance earlier, never
     later.
   * **Freshness.** A measurement older than the verification freshness (Q11) counts as `unmeasured`.
5. ⟨r2⟩ **Evidence from the `-v` trace** (§17.1 item 3; M03-R03, F01).
   * ⟨r3⟩ The trace patterns are keyed by **upstream release family** (§17.4 item 11; B R2-09):
     * `portable`, for OpenSSH portable and the distribution builds of it;
     * `win32`, for Win32-OpenSSH.

     Each family carries the version ranges recorded from real runs (`verify_trace_patterns`, plan U5;
     M-F22).
   * A client outside every recorded range makes every result `verification_inconclusive`. The doctor
     then reports `client_trace_family_unrecorded`, naming the family and the version.

   For each attempt the Verifier extracts:

   | Event | Meaning |
   |---|---|
   | `server_version` | the remote software version line |
   | `host_key_matched` | the approved host key matched under the generated `HostKeyAlias` |
   | `offered_certificate` | the certificate being verified was offered (matched by K_verify's fingerprint and the certificate type) |
   | `accepted` | the server accepted the offered key or certificate |
   | `not_accepted` | after the offer, the server answered "Authentications that can continue" with `publickey` and no acceptance |
   | `publickey_failure_final` | the run ended with a public-key authentication failure ("Permission denied (publickey)" or the client's equivalent) |

**Outcome classification.** All three of the run's exit status, the signature count and the trace
events are needed.

| Attempt | Required for **pass** | Required for **refused** | Everything else |
|---|---|---|---|
| Positive | exit 0; `server_version`; `host_key_matched`; `offered_certificate`; `accepted`; **exactly 1** signature; the `HM1 now=` line | exit ≠ 0 with `server_version`, `host_key_matched`, `offered_certificate`, `not_accepted`, `publickey_failure_final`, and 0 signatures | inconclusive |
| Negative | — | exit ≠ 0; `server_version`; `host_key_matched`; `offered_certificate`; `not_accepted`; `publickey_failure_final`; **0** signatures | inconclusive. ⟨r2⟩ This includes a connection refused, a reset, a timeout, `MaxStartups` or penalty drops, a host-trust error, and a client startup error. **A transport failure is never a refusal** |

| Positive | Negative | Initial verification (`verifying`) | Re-verification (`reverifying`; §17.1 item 5) |
|---|---|---|---|
| pass | refused | `verified` (`verified_server_principals` may be claimed) | `verified`, freshness renewed |
| pass | accepted, or any signature recorded | `principals_not_enforced`: a high-severity finding. Account: rollback (`rollback_pending`); system: `held` | `held` (`principals_not_enforced`); grants under that CA for that pair degraded (`pair_unenrolled`); removal needs `RemoveEnrollment` |
| refused | — | `verification_failed`: the registry is probably not the server's authoritative one (spec §7.4), or certificates are unsupported. Account: rollback; system: back to `manual_pending` with the finding. No Recipe A in M03 (Q4) | `held` (positive refused); grants degraded as above; removal needs its decision |
| host key mismatch | — | `HOST_TRUST_CHANGED`. **No rollback attempt**: existing access would fail host verification too. Record `held`, remedy `review_host_trust` | `held`, remedy `review_host_trust` |
| inconclusive, either attempt | | Account: back to `applied_unverified`. The line stays, and no grant uses it. ⟨r3⟩ The retry runs through `enroll reconcile`, under the still-open `enrollment.apply`, while its approval is valid. After the approval has lapsed it runs through `enroll verify`, and a failure then goes to `held`, with removal needing `RemoveEnrollment` (§17.4 item 5; B R2-06). System: `manual_pending` | `verified` with **unchanged** freshness, and a doctor finding `reverification_inconclusive`. ⟨r3⟩ From a hold: `held`, reason unchanged |
| ⟨r3⟩ positive refused while the destination's clock is skewed beyond the validity allowance | — | `verification_inconclusive`, reason `destination_clock_skew`, and **no rollback** (§17.4 item 11; B R2-13). The finding names the measured offset; ADR-0005 §3.6 diagnoses a server clock error separately | the same: inconclusive, nothing changed |

⟨r3⟩ **The skew rule.** The known offset is the remote clock reading of the operation's E2 `inspect` (the
initial verification) or the enrollment's last fresh `ClockMeasurement` (re-verification), with its
uncertainty (1 s plus the round trip).
* The clock is **skewed beyond the allowance** when that interval reaches a lag of 60 s or more (the
  certificate is not yet valid there; `valid_after` = now − 60 s), or a lead of 300 s or more (already
  expired there).
* Without a known offset, a refused positive is classified as refused.
* A refusal that a clock fault could explain is therefore never rolled back as a failure.

`log_attestation` is reported `unavailable` (ADR-0005 §3.3). The server log is only the test oracle, in
the fixtures.

**Tests (plan U5).**
* `verify_negative_inconclusive_when_sshd_stopped_between_attempts`;
* `verify_negative_inconclusive_when_port_closed_between_attempts`;
* `verify_negative_inconclusive_on_maxstartups_between_attempts` and `…_during_negative`;
* `verify_negative_inconclusive_on_reset`;
* `verify_unrecorded_client_trace_is_inconclusive`;
* `verify_trace_patterns_per_client`;
* `remote_clock_measurement_bounds_lag`.

⟨r2⟩ **Freshness and re-verification** (Q11 as amended; F27).
* **The window:** evidence is fresh for at most **90 days**.
* **Invalidated earlier**, at once, by any of:
  * a change of destination, account or approved host key (the `TargetEvaluator` comparison, run when
    `inspect` or `ensure` touches the pair);
  * a change of the CA;
  * a change of the verified client's version;
  * **contrary evidence**: any later verification attempt for the pair (owner, supervisor, or the
    doctor's explicit `managed` probe, which runs the §6.5 positive attempt) ending refused with
    refusal evidence. A transport failure is not contrary evidence.

  Invalidated evidence reports `destination_scope: unknown` for the pair until re-verified.

  ⟨r3⟩ **A client or CA change is not contrary evidence** (§17.4 item 11; B R2-09). The supervisor then
  re-verifies the pair **promptly**: within `reverify_prompt_delay` (10 min), with bounded, jittered
  retries. So a routine OpenSSH update does not leave the pair unverified until day 80. A host-key change
  is never re-verified automatically: it needs `ApproveTargetChange` (§6.2).
* **The supervisor re-verifies** each `verified` pair before its window lapses: after 80 days, with
  bounded jittered retries. Re-verification is non-interactive, uses the managed credential path only
  for the verification certificates (D5 item 2), and **changes nothing remotely**.

### 6.6 Preserved fallback and the preference switch

* The existing identity and its remote access are never touched. Heimdall did not create them and does
  not remove them (spec §7.5 "retire older access only through the approved policy"). M03 has no
  retirement policy.
* ⟨r2⟩ E5 sets the pair's preference to `managed_certificate` with `projection: pending` **only when
  the pair is not already managed with an applied projection** (F05). A rotation's new enrollment, or
  any re-verification, only adds the CA to the preference's issuing-CA set and leaves the projection
  alone. Then P keeps rendering the existing identity until the owner applies the projection change
  through M02's setup (preview, `ApplyProjection` decision, journaled apply). The diff shows the alias
  moving to the environment endpoint and the slot files (D10).
* ⟨r2⟩ **While the projection is pending** (§17.1 item 15; F04):
  * `ensure` **resolves to the existing mechanism**, as if the pair were not enrolled. The result
    carries the warning `managed_projection_pending` and `next: setup_apply`. `ensure`, `run` and
    `connect` keep working;
  * only a request whose `required_capabilities` the existing mechanism cannot meet fails with
    `CAPABILITY_UNAVAILABLE`, reason `projection_pending`, next `setup_apply`. Examples are `unattended`,
    `destination_scope_at_least: verified_server_principals`, or an `offline_until` the existing
    mechanism cannot cover.

  So no result ever claims managed access that an ordinary alias does not use.
* **Switching back** (`heimdall destination prefer <alias> existing`) is local: a catalog change plus a
  projection change. The enrollment stays until `enroll remove`.

### 6.7 Reconciliation after uncertainty

`heimdall enroll reconcile <operation>`, owner role (F20). For a step that is `Uncertain`, it runs
`inspect` through the pinned existing access (§6.3) and classifies.

⟨r3⟩ **Fencing first: proven termination, never a lock taken away from a live writer** (§17.4 item 2;
A R2-02). Reconcile reads the lock state in the inspect result before it reads the marker:
* **No lock**, or a lock with **another enrollment's** token (which is `busy` for this one): classify
  directly. The other enrollment's lock is never touched.
* **A lock with this enrollment's step token:** reconcile runs `fence` (§6.3):
  * `gone`: the link is removed, `inspect` runs again, and that second read is classified;
  * `alive`, with the step's `NOT_AFTER` not yet passed on the remote clock: nothing is decided. The
    operation stays uncertain, with next `reconcile` after the hard deadline;
  * `alive` after it: `fence --terminate` (TERM, then KILL, of the exact process group, then the proof
    again). A `gone` result continues as above; still `alive` stays uncertain;
  * ⟨r4⟩ `unproven` (the control failed, the two methods disagree, or a live group's leader PID has
    another start identity): nothing is removed, and ⟨r5⟩ no further signal is sent. Any signal this
    attempt already sent is kept in the step result and the audit record (§17.10 item 4). The
    operation stays uncertain, and the attempt counts toward `holder_termination_attempts` (§17.7
    item 1);
  * after `holder_termination_attempts` (3) reconciles without a proof, the record is `held`
    (`lock_holder_unresolved`).
    * The owner gets the lock path, its holder record, and the commands to check the process and
      remove the link by hand.
    * `enroll reconcile <op> --after-manual-recovery` then re-inspects and classifies **without** any
      redispatch: one exact line gives `applied_unverified`, and none gives `withdrawn` with the
      `late_write` residual.

| Observation (after fencing) | Meaning | Action |
|---|---|---|
| Exactly one marker line, equal to the expected line | Applied | `Confirmed`, then `applied_unverified`, then continue at E4 |
| No marker line | Not applied | A redispatch of E3 is allowed **only** when all of these hold (Q7 as amended): the same approved target, endpoint and effect, re-checked by the route re-evaluation; ⟨r3⟩ the old step's holder **proven gone**, meaning its lock was removed by `fence`, or was never taken and its `NOT_AFTER` has passed on the remote clock, so it can no longer pass its own checks; the approval within its validity (24 h after `Decide approve`, measured on safe time); and an **attended** session (F20). Then back to `applying`: E3 runs again with the same marker and line, and a new not-after. ⟨r2⟩ **An absence read alone never authorizes a redispatch.** If the approval lapsed: `DECISION_STALE`, reason `approval_lapsed`, and the record goes `withdrawn`, ⟨r3⟩ with the `late_write` residual |
| Marker present but the line differs, or more than one marker line | Damaged | `held` (`registry_line_damaged`). The owner gets the exact line numbers and bytes |
| Unreachable, authentication failed, `busy` | Unknown | Stays `outcome_unknown`. `DESTINATION_UNREACHABLE`, the provider's code, or `registry_busy`. No retry loop: the owner retries |

For a removal or rollback step, the same table applies with "marker absent" meaning applied, and the
record keeps its purpose (`remove_unknown` or `rollback_unknown`, §6.2).

⟨r3⟩ **The `late_write` residual** (§17.4 item 2). A record that leaves an uncertain append for
`withdrawn` or `abandoned` keeps `{step_token, not_after_remote}`, and reports `possible_late_write`.
* It clears when an `inspect` whose remote clock reading is past `not_after_remote` shows no marker
  line and no lock with that token. By then, a script that had not taken the lock fails its own
  not-after check, and one that had would still hold the lock.
* Until it clears, it is listed with the enrollment, in uninstall and in the bundle.

**Nothing is ever appended blindly:** the script refuses a second line by marker, whatever the local
state says (spec §7.5). **Tests** (plan U5):
* `first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss`. The first script is
  paused after taking its lock, and its step times out. Reconcile waits out the hard deadline,
  terminates the holder, proves it gone, removes the lock and redispatches. The first script never
  resumes, and the registry holds exactly one line;
* ⟨r3⟩ `writer_paused_just_before_write_no_duplicate_no_loss` (§17.4 item 2). The first script is
  stopped (SIGSTOP) **between its final re-check and its write**. After the not-after, reconcile
  terminates its group (KILL ends the stopped process), proves it gone and redispatches. Exactly one
  line results, and nothing else is lost;
* ⟨r3⟩ `script_started_after_not_after_writes_nothing_exit_41` (B R2-04);
* ⟨r3⟩ `unprovable_holder_held_for_manual_recovery_never_redispatched`;
* ⟨r3⟩ `other_enrollments_lock_is_busy_never_broken`;
* ⟨r3⟩ `late_write_residual_cleared_only_by_inspect_after_not_after`;
* ⟨r4⟩ `leader_absent_live_mutation_child_never_gone_per_shell` (§17.7 item 1), on dash, bash as `sh`,
  BusyBox `ash` and the macOS `sh`. The holder shell is killed and reaped, and its mutation child is
  stopped just before its write. The group proof must report `alive`, never `gone`. After the
  not-after, termination ends the child, the proof agrees on `gone`, and the redispatch's write is
  the only one (the reviewer's reproduction, no longer losing a write);
* ⟨r4⟩ `group_probe_syntax_error_is_unproven` (a shell that rejects the probe's syntax fails the
  control);
* ⟨r4⟩ `group_probe_and_listing_disagreement_is_unproven` (probe and listing disagree, in both
  directions);
* ⟨r4⟩ `listing_without_own_group_is_unproven`;
* ⟨r4⟩ `reused_pid_with_live_foreign_group_is_unproven_never_signalled`.

### 6.8 Removal and rollback (compare-then-rename)

`enroll remove <enrollment>` creates operation `enrollment.remove` with decision `RemoveEnrollment`. ⟨r2⟩
The decision shows:
* the pinned existing-access invocation;
* the approved target;
* every live grant that holds a certificate **under this enrollment's CA** for the pair, with the
  pair residual;
* ⟨r3⟩ for a `held` record whose hold is a host-key change, the **freshly evaluated target**. The
  removal then runs against the newly found key, shown as a diff against the approved one (§17.4
  item 5; B R2-05). Without it, every removal step would be refused `route_changed`.

Then:
1. `inspect`;
2. build the post-image locally: the preimage minus exactly the lines equal to our line (the marker
   lines must all equal it, or the result is `held`);
3. `remove`;
4. on exit 20, start again from `inspect`, at most 3 times, then `CONFIG_CONFLICT`, reason
   `registry_changed`, record `held`;
5. on exit 30 (a symlink, more than one link, an ACL or label, a foreign owner, an unsupported mode),
   `CONFIG_CONFLICT`, reason `registry_not_rewritable`, with **manual instructions**: the file, the exact
   line to delete, and how to re-verify absence (`enroll reconcile`).

⟨r2⟩ **Which live grants are degraded** (§17.1 item 15; F05):
* only grants holding a certificate **under the removed CA** for that pair are affected; grants under
  another CA are not;
* **early removal** is allowed, with the preview's warning;
* ⟨r3⟩ **every** grant holding a certificate under the removed CA for that pair is degraded, whether or
  not another verified enrollment remains. §17.3 item 3 ruled Q20 (a). The "no verified enrollment
  remains" clause governs only the pair's **preference**, which stays `managed_certificate` while
  another verified CA remains; new grants use that CA.

Degraded grants get `pair_unenrolled`. They are not revoked locally; the owner may revoke them. Rollback
after a failed verification (E5′) is the same procedure, under the original decision, with the
`rollback_*` states.

### 6.9 The system form

⟨r2⟩ The system form (`TrustedUserCAKeys` plus `AuthorizedPrincipalsFile`) has **its own path and
decision** (§17.1 items 7 and 11; F06a, M03-R12). It is **manual** in M03: Heimdall never edits
`sshd_config`, never runs `sudo`, and never installs a service (spec §7.4 capability 3 automation;
plan §1.2).

* **Enroll.**
  1. `heimdall enroll <destination> --form system` previews the same approved target and shows the
     owner:
     * the CA public line for `TrustedUserCAKeys`;
     * the principals-file line `hm:<destination-id>:<account>` for the account;
     * the `sshd_config` directives.
  2. Decision `EnrollSystemForm`. It authorizes Heimdall to issue verification certificates for the
     pair and to record the trust once verified. The record goes to `manual_pending`.
  3. When the owner confirms the lines are applied (`enroll verify <enrollment>`), the §6.5
     verification runs (`verifying`). Only its pass records `form: system, state: verified`.
  4. A failure or an inconclusive result returns to `manual_pending` with the finding. Heimdall wrote
     nothing, so there is nothing to roll back.
  5. ⟨r3⟩ **Cancelling** from `manual_pending` (§17.4 item 5; A R2-05). The owner may already have
     installed the lines, so the record does **not** become `withdrawn`.
     * It goes to `manual_removal_pending`, with origin `manual_pending`, and shows the lines to
       delete if they were applied.
     * It becomes `withdrawn` only after the absence check passes.
     * The owner may instead `abandon` it, and it stays listed.
* **Remove.**
  1. `heimdall enroll remove <enrollment>` on a system-form enrollment changes nothing remote. It
     shows the exact lines to delete and moves the record to `manual_removal_pending`. That is
     narrowing, so no decision is needed; a typed confirmation is.
  2. When the owner confirms (`enroll verify <enrollment> --absence`), an **absence check** runs
     (`removal_verifying`): a positive verification certificate for the pair must be **refused**, with
     the full refusal evidence of §6.5.
  3. Only then is the record `removed` (or `withdrawn`, when the origin was `manual_pending`). An
     accepted or inconclusive result returns to `manual_removal_pending`, with its origin kept.
  4. ⟨r3⟩ **Cancelling** a manual removal returns the record to `removal_origin`: the state **and the
     evidence** it began from (§17.4 item 5). Those are persisted when the removal begins: `verified`
     with its verification evidence and freshness, `held` with its reason, `abandoned`, or
     `manual_pending`. The record never moves to `verified` without that evidence.

  A system-form enrollment is **never reported as removed automatically**.
  ⟨r4⟩ **A foreign system-form record** (D4 item 5; §17.7 item 4) follows the same states, with origin
  `planned`. Its absence check cannot pass, because this device holds no key of the removed CA, so it
  ends `verification_inconclusive` (`ca_not_held`) and returns to `manual_removal_pending` (Q28). ⟨r5⟩ It
  can then be abandoned, keeping `pending_until_line_removed`, and a cancel after `ca_not_held` never
  takes it to `planned` or `withdrawn` (§17.10 item 2).
* **Re-verification** behaves as in §6.5's re-verification column.

### 6.10 Interaction and roles

* `enrollment.apply` is admitted on any session. It always needs the attended `Decide` for
  `EnrollAccount` or `EnrollSystemForm`.
* ⟨r2⟩ `Enrollment::{Step, StepResult, Reconcile}` are accepted from the **owner role only**. A
  reconcile that redispatches an append needs an **attended** session (F20).
* After approval, the existing-access steps run in the driving CLI process, in the request's
  interaction mode (§6.3).
  * In `--non-interactive` mode the CLI runs ssh with `BatchMode=yes`. A provider or server that needs
    interaction (a 1Password approval, a locked agent, a touch, a key passphrase) fails the step before
    any write. The provider's code is returned (`PROVIDER_LOCKED`, `INTERACTION_REQUIRED`), and the
    record is `failed_unwritten`.
  * In interactive mode, the prompt appears on the owner's terminal, or as the provider's own dialog
    (ADR-0007 §7 interaction states). Heimdall never reads, relays or stores what the owner types.
* ⟨r2⟩ The existing-access kinds that can drive the steps are those the catalog represents (agent-held,
  or a key file); a password-only account is `existing_access_kind_unsupported` (§6.1; §17.1 item 14).
* Verification needs no interaction. The runtime runs it in `BatchMode`.

---

## 7. D6 — Certificate acquisition, re-issue and offline coverage

0. ⟨r2⟩ **The preparation contract, extended explicitly** (§17.1 item 12; M03-R13). M02's contract
   stays as it is for every existing-access adapter:
   * `read_sources` reads on the blocking pool, outside the bound;
   * `prepare_from` evaluates only over its request and the snapshot, inside the bound, with no store,
     file or live reads (`ports.rs`, `IntegrationSnapshot`; `prepare_from`).

   A managed preparation needs store transactions (reserve, publish, slot claims), issuer calls and
   file writes **between** bounded steps, which `prepare_from` forbids. So the contract gains a
   **managed effect driver**:
   * **`ManagedEffects`** is a port in `app::ports`, implemented by `heimdall-adapters::managed`:
     * `generate_key`, `install` and `destroy`, each bounded by `adapter_call_timeout`;
     * `materialize` and `clear`, which are synchronous file work on the blocking pool, like
       `ProjectionWriter`.
   * **`IssuerPort::sign`** is bounded by its own request bound (D3 item 6).
   * **`app::managed::drive_preparation`** runs the stage sequence of item 1. It does every store
     transaction itself, outside any adapter bound, and writes a stage receipt between each effect.
   * **`IntegrationSnapshot`** gains `managed: Option<ManagedSources>`: the pairs' verified enrollments
     and issuing-CA sets, the slots, the applicable claim entries, the issuer status and the driver's
     own `ManagedPrepared` results. `read_sources` fills it.
   * **`prepare_from`** for `managed_certificate` then only **computes** the `PrepareOutcome` (the
     report of item 6 and D12) from that snapshot. It reads nothing and causes nothing. Called without
     driver results, it returns `AdapterError::Protocol("managed preparation runs through the effect
     driver")`.

   M02's rule "nothing that can block runs inside the bound" therefore holds for every managed step.

1. **Activation.** The managed effect driver for a `managed_certificate` grant (m03-plan U6, U10).
   Every pair must have a `verified` enrollment and an applied projection (D5 §6.6). The steps, each a
   stage receipt under the operation's effect token:
   1. **key:** the signer generates K_env and registers its fingerprint (instance `pending`, D2);
   2. **reserve:** one reservation per pair through `Operations::reserve_issuance`, with the bounds of
      ADR-0005 §3.4 and the CA chosen per D4 item 3 (`CertificateBounds.ca_fingerprint`). Extensions come
      from `issuance::extension_profile(grant, pair)`, which replaces M01's `permitted_extensions`:
      * `permit-pty` for every pair;
      * `permit-agent-forwarding` only with the `agent-forwarding` capability;
      * `permit-port-forwarding` never in M03: there is no route data until M04;
      * `permit-user-rc` never;
      * `permit-X11-forwarding` never;
   3. **sign:** `IssuerPort::sign(reservation, K_env public)`;
   4. **publish:** `Operations::publish_issuance`, with up to 3 re-reservation round trips (ADR-0006
      §13.8 item 1);
   5. **install:** the signer's check (D2 item 6);
   6. **materialize:** the per-binding files `<runtime_dir>/b/<16 hex>/{key.pub, cert-<destination-id>.pub}`,
      and the environment slot when the binding is materialized (D10);
   7. **prepared:** usable.

   A refusal at reserve or publish zeroizes K_env and destroys the instance. The grant then follows the
   M01 rule for that refusal: it ends for withdrawn authority or expiry, and otherwise the operation
   fails.

2. **Certificate profile and structure check** (`heimdall_credential::cert`). The validator, used at
   install and in tests, refuses:
   * a type other than user;
   * a principal count ≠ 1, or a principal ≠ the pair's;
   * any critical option;
   * an extension outside the reserved set;
   * `valid_after`/`valid_before` ≠ the reserved bounds;
   * a key ID or serial ≠ the reserved ones;
   * a signature key ≠ the reserved CA;
   * a subject ≠ K_env.

   This is spec §7.6: "unknown critical options, mismatched certificate/key pairs, invalid validity
   intervals, unexpected principals, and unrecognized issuers must fail closed".

3. **One certificate per pair covers the whole grant.** No chunked renewal in V1 (ADR-0005 §3.5,
   §8).

4. **Re-issue (`renew`)** happens only under the ADR-0005 §3.7 recovery rule. It is triggered by the
   supervisor's `managed_reissue_pass`, never by a caller:
   * at runtime start for each `lost` instance;
   * after the issuer returns to `ready`;
   * after an attended `ConfirmTime`.

   It never extends anything: same pairs, same D. It goes through the same reserve, sign, publish and
   install. It never runs for:
   * an expired, revoked or released grant;
   * a grant past a cutoff;
   * a `revoke_on_lock` grant (it ends instead, ADR-0005 §3.7 rule 5);
   * a grant read from anything but the store.

   If time is not accepted, the grant stays `degraded` (`credential_reissue_pending`) until it is
   accepted or the grant ends.

5. **Delegated children** (ADR-0005 §3.10). `delegate` on a managed parent prepares:
   * the child's own K_env on its own per-binding endpoint;
   * certificates for its subset of pairs, with `valid_before` ≤ the parent's (the predicate refuses
     more).

   The parent's end destroys the child's keys in the same revocation or expiry step (D7). The child
   endpoint cannot request issuance. Full A28 attenuation evidence is M05.

6. **Coverage reporting** (spec §6.5). For a `managed_certificate` binding in a local environment,
   with the issuer `ready` at activation:
   * `usable_until = offline_until = min(D, cutoff, parent deadline)`;
   * `availability: through_deadline`;
   * `refresh_dependency: local_issuer`, with the new `refresh_condition: {needed_only_after:
     signer_restart, source: local_issuer}` and `conditions: [signer_running]`;
   * ⟨r2⟩ `conditions` also carries:
     * `time_confirmation_after_reboot`, because synchronized time is not trusted in M03 (Q13), so
       after any reboot managed issuance waits for an attended `heimdall time confirm` (F14);
     * on macOS, `issuer_store_unlocked_at_start` (F03);
   * `lock_continuity` from the claim table (D12).

   ⟨r2⟩ **"Allow background work once" holds within one boot** (§17.1 item 17; F14). After a reboot,
   the runtime must be started (on demand in M03; at login in M04-T04) and time confirmed once,
   attended. That confirmation is a counted chore in the exit evidence, and the TUI shows it (plan
   U12).

   While an instance is `lost`, or re-issue is pending:
   * `availability: refresh_dependent`;
   * `usable_until` = the time of the observation (not currently usable);
   * the grant is `degraded`.

   A `required_capabilities.offline_until` later than the admission bound gives `CAPABILITY_UNAVAILABLE`.
   **A fifteen-minute or otherwise short certificate is never reported as covering longer work**
   (plan G04): the only certificate lifetime is the grant's.

7. **The `unattended` minimum** (`RequiredCapabilities.unattended`, M02) is met only when all hold:
   * the mechanism is `managed_certificate`;
   * the claim table holds `lock_continuity: verified` for this platform and these versions;
   * the grant's lock behaviour is `continue`;
   * the binding needs no interaction.

   Otherwise `CAPABILITY_UNAVAILABLE`, with reason `lock_continuity_unverified`, `lock_revokes_chosen`
   or `interaction_required`.

8. **The prepare drop contract** (M02 §5 item 15), ⟨r2⟩ applied to each effect-driver step. A dropped
   step future stops between steps and
   leaves behind only durable reservations, which stay counted, and possibly a `pending` instance. Its
   K_env is zeroized when the vault slot drops. `reconcile(token)` reports `Applied` when every pair is
   published and installed, `NotApplied` when nothing is published, and otherwise `Unknown`. On
   `Unknown`, the cleanup intent destroys whatever is installed, and a fresh `prepare` starts over. No
   certificate published by the dropped attempt is ever installed after the drop: installation needs the
   live `prepare` and its matching key.

---

## 8. D7 — Deadlines, revocation, remote pending state, cascade and release

1. **Enforcement points.**

   | Point | Mechanism | When |
   |---|---|---|
   | Signer | per-signature authorization (D2 item 3) | every signature |
   | Issuer (runtime reserve and publish) | `issuance::check` | every reservation and publication |
   | Issuer (child) | the read-only re-check (D3 item 4) | every signature by the issuer |
   | Server | `valid_before` [O:E2] | every new authentication |
   | Supervisor | owned masters closed; strict owned connections closed (D8) | at the admission deadline, `TIME_UNCERTAIN`, revocation, release |
   | Cleanup executor | key destruction, endpoint and slot removal, by generation | after any end, bounded |

2. **Revocation order** (spec §6.7; R-AU-04). M01's revoke path, with M03's managed step. ⟨r3⟩ The order
   is D2 item 3a's (§17.4 item 6; B R2-03):
   0. ⟨r2⟩ Take the **signing gate exclusively** for the grant and every descendant in the cascade (D2
      item 3a). ⟨r3⟩ The gates are taken ancestors first, then by grant ID. ⟨r4⟩ The pending mark is
      set first. The set is re-read under the gates; if it grew, every gate is released and the whole
      set is reacquired once in global order, then re-validated (D2 item 3a; §17.7 item 3).
      * ⟨r5⟩ **The mark is authoritative** (§17.10 item 1). It is checked in the fresh read under the
        gate, after every awaited acquisition, and in the release check. It covers every descendant
        through the ancestor check, and new descendants are marked before round 1 releases any gate.
      * ⟨r6⟩ **The revocation is never aborted for time** (§17.13 item 1). It waits until it holds its
        gates. Its commit time, `committed_at − requested_at`, is reported, with the derived bound of
        D2 item 3a: `H + R(N) + Σ_{X ∈ E(N)} R(X)`. Earlier marks go first. 20 s is a target, tested at
        the budgets, not a guarantee.
      * The revocation never proceeds without the gates.
      * ⟨r5⟩ **Timestamps** (§17.10 item 3; M03-R4-03). `requested_at` is captured when the revoke
        operation is first admitted, before step 0's wait, and stored with the operation.
        `committed_at` is read **inside** step 1's tombstone transaction, and stored with it, separately
        from any later cleanup. Both are reported in `RevokeData`, and a replay of the same
        `request_id` returns the original values.
   1. Tombstone, cascade and generation in one transaction. From this commit, every signature on every
      endpoint is refused, and none was enqueued after it (D2 item 3a). `local_applied: true` is
      acknowledged only after this commit (M01).
   2. In the same call, **while the gates are held**, the managed adapter's `revoke(grant)` runs for
      the grant and every descendant in the cascade. It zeroizes K_env and drops it from every endpoint.
      ⟨r6⟩ That is in-memory work, bounded per grant by `ε`. The slot and binding files are no longer
      removed here (step 4; §17.13 item 1).
   3. ⟨r3⟩ Release the gates.
   4. ⟨r3⟩ **Then**, still before returning, ⟨r6⟩ the cleanup runs, outside every gate (§17.4 item 6,
      §17.13 item 1):
      * remove the slot and binding files, by generation;
      * close the owned masters (`-O exit`, then the exact PID) and the **owned dedicated connections,
        under either policy** (ADR-0005 §6.1, Q4 b).

      Cleanup runs after the gates are released, so it never lengthens a signer's or another
      narrowing's wait.
   5. **Residual** (spec §6.7). `latest_possible_credential_expiry` is the maximum `valid_before` over
      every `reserved` or `published` entry for the cascade, delivered or not. Only `voided` entries are
      excluded (ADR-0005 §3.5).
      * `remote_effects` lists one row per (destination, account) with an unexpired entry:
        `latest_valid_before`, ⟨r2⟩ `destination_clock` (the enrollment's `ClockMeasurement`, or
        `unmeasured`), and `status` from item 3.
      * After a key-only restore (D4 item 4) the status is `unbounded_unknown` and no bound exists.
   6. ⟨r2⟩ **Owned connections** (F15). The revoke result lists every owned connection of the cascade,
      each `{id, kind, state: closing | closed | unverified}`. It also carries the fixed note
      `ordinary_connections_not_closed`: connections that ordinary `ssh` opened through P, and any
      unmanaged connection, are not closed (D8 item 2).

   If any part of step 2 or step 4 fails, a cleanup intent is written in the settling transaction (M01
   §13.19 item 2). Denial already holds from step 1.

3. ⟨r2⟩ **Remote residuals after expiry** (§17.1 item 10, which replaces Q12; M03-R10). B1 has no
   remote revocation action at capability 2 (no KRL), so its remote part never needs adapter rounds.
   Two different things are tracked:
   * **Nominal certificate expiry** is accounted for automatically, at local safe time (the time gate
     `Safe`, wall ≥ `latest_valid_before`).
   * **Bounded remote completion** is a separate fact. It needs the destination's clock measurement
     (D5 §6.5 item 4). With a measurement, the obligation completes at

     ```
     latest_valid_before + behind_upper + rtt + 100 ppm × (now − measured_at)
     ```

     on safe time, which is ADR-0005 §6.2's "plus destination clock error", now bounded.

   A `RemoteObligation` of kind **`bounded_by_expiry { latest_valid_before, clock }`** therefore moves
   through these statuses, in the supervisor's revocation pass, with no adapter call and no attempt
   counted:

   | Status | When | Reported |
   |---|---|---|
   | `pending_until` | before the completion bound (or, unmeasured, before `latest_valid_before`) | `remote_pending`, with the bound |
   | `bounded_complete` | a measurement exists and the bound passed on safe time | the residual is closed, with the measurement it relied on |
   | `nominally_expired` | **no measurement** (or a stale one), and `latest_valid_before` passed on safe time | `nominally_expired`, `destination_clock: unmeasured`. **It never shows as cleared.** The record is kept and listed |

   * **The grant** moves `revoking → revoked` once every obligation of its cascade is
     `bounded_complete` or `nominally_expired`. A `nominally_expired` residual **blocks nothing
     else**, but stays visible in `inspect grants` and in the revoke result.
   * **While time is uncertain**, nothing moves: it fails closed.
   * **The cap and backoff** of ADR-0006 §13.12–§13.19 apply only to obligations of kind
     `needs_remote_action`. M03 has none.
   * **Test** (plan U6): `slow_server_clock_residual_bounded_by_measurement`, a fixture whose clock lags
     by a known amount; and `unmeasured_residual_reported_nominally_expired_never_cleared`.
   * **This amends ADR-0005 §3.6** ("Heimdall does not measure destination clocks") as §17.1 item 10
     rules. The measurement bounds only the lag observed at verification, plus the drift allowance. A
     destination clock that is reset later is an accidental fault outside the bound, and is disclosed.

4. **Per-pair residual** (`inspect enrollments`, `inspect grants`). It is the maximum `valid_before` over
   grant entries and verification entries for the pair, issued under a given CA, ⟨r2⟩ with the
   pair's clock measurement and the status of item 3. Rotation's old-line removal (D4 item 3) and the
   `RemoveEnrollment` decision read it.

5. **The QR17 binding requirement** (ADR-0007 §12.13). The managed adapter has remote-effect semantics:
   its published certificates are authority usable remotely. So:
   * a timed-out immediate `revoke` (the M01 best-effort call for an uncovered grant) **keeps its
     cleanup intent**. It is retried by the supervisor with bounded, jittered backoff (ADR-0006 §13.6
     item 4), and never counts as made;
   * in revocation rounds, a timed-out call is unconfirmed, as in M02.

6. **Parent cascade.** M01's tombstone cascade, plus key destruction for every descendant (item 2).
   * A parent's expiry ends its children no later than the parent, because their bound is ≤ the
     parent's. Their keys are destroyed by the same expiry path.
   * A parent's `released` state is blocked while a child holds its owned reference (ADR-0006 §13.5
     ruling 1, §13.6 item 3).

7. **Release of the last reference** (ADR-0006 §13.3 item 1). Release writes no tombstone and does not
   cascade. It destroys K_env, removes the binding and slot files, and closes owned masters. Owned
   dedicated connections follow the policy, as at expiry. Issued certificates stay in the residual
   until their `valid_before`.

8. **Expiry and cutoff.** At the admission deadline the scheduler's `tick` expires the grant (M01). The
   signer has already been refusing since the deadline, so destruction and closure by the supervisor
   pass come at most one pass later. A cutoff ends affected grants like expiry at the cutoff (ADR-0005
   §6.1). A certificate issued before the cutoff was set stays valid to its own `valid_before` and is
   counted.

9. **Pause.** No effect on running grants; it blocks new activations (M01 §13.6 item 1). Re-issue
   within a grant continues under a pause (ADR-0005 §3.7).

10. **`TIME_UNCERTAIN`.** No signature, reservation, publication or re-issue. Owned masters are closed
    (ADR-0005 §3.6). Dedicated connections follow the policy, as at expiry: their authentication is
    already done.

---

## 9. D8 — Connection policies, owned masters and stopping multiplex admission

1. **Policy.** `ConnectionPolicy { existing: graceful | strict, multiplexing: disabled |
   owned_masters }`.
   * The defaults are `graceful` and `disabled` (spec §6.6).
   * Sources: the standing policy's `connection` field, or for an owner-decision grant the decision's
     recorded value. A request may **narrow** `existing` to `strict` (`EnsureRequest.connection`).
   * The **effective** policy of a grant is the strictest of:
     * the value recorded in its `GrantOrigin` at activation (add-only);
     * every current applicable policy (a fail-closed merge evaluated at the deadline);
     * the request.
   * Widening needs a decision record and an attended `Decide`: `strict → graceful` and `disabled →
     owned_masters` on a policy (ADR-0006 §13.6 item 6 pattern). Narrowing is immediate and moves the
     generation.

2. **Owned dedicated connections.** A connection is owned when its process is the verified `ssh` client
   of M02's client inventory, launched by:
   * `heimdall connect`; or
   * `heimdall run` whose resolved program is that client.

   ⟨r3⟩ **Owned connections stay in the foreground** (§17.4 item 7; A R2-07; M-F28). Ownership names the
   process the launcher started, and a client that forks after authentication would leave it.
   * Every product-generated invocation pins `-o ForkAfterAuthentication=no`: `connect`, the owned
     masters (item 3), the remote steps (D5 §6.3) and the verification (D5 §6.5).
   * For `run` of the verified client, the launcher inserts `-o ForkAfterAuthentication=no -o
     ControlMaster=no -o ControlPath=none` right after the program name. They are then read before the
     user's arguments and before every configuration file.
   * Arguments that would still move the connection out of the launched process are **refused before
     launch** for an owned connection: `CONFIG_CONFLICT`, reason `owned_connection_option_conflict`,
     writing `prelaunch_failed`. They are:
     * `-f`, alone or bundled (as in `-fN`);
     * `-M`, `-S` and `-O`;
     * any `-o` form of `ForkAfterAuthentication`, `ControlMaster`, `ControlPath` or `ControlPersist`.
   * Tests (U8 for `connect` and `run`; U7 for the masters' `owned_master_pins_fork_after_authentication_no`):
     `owned_launch_pins_fork_after_authentication_no`;
     `inherited_fork_after_authentication_yes_stays_in_foreground`;
     `run_ssh_with_f_refused_for_owned_connection`; `run_ssh_conflicting_control_options_refused`.

   ⟨r2⟩ **The binding holder and the controlled connection process are separate records** (§17.1
   item 8; M03-R08, F02). The binding's `Launch` holder (M02: the launcher's own PID and start token)
   stays the reference that keeps the binding. The **owned connection** is a separate
   `owned_connections` row naming the process that carries the connection: its PID, its start or
   creation time, and its verified executable.
   * **Unix.** `run` and `connect` `exec` the client, so the connection process **is** the holder
     process (same PID, same start time).
     * ⟨r3⟩ The row is written **at bind**, in the binding's own transaction, before the launcher execs.
       It has kind `dedicated` and the **expected image**, the verified client's path (§17.4 item 8;
       B R2-12). So a revocation in the interval between bind and exec already finds it.
     * **Before every signal**, the supervisor re-verifies the start time **and** that the process image
       is the expected one (`/proc/<pid>/exe` on Linux, `proc_pidpath` on macOS).
     * ⟨r3⟩ A process still running `heimdall` (the exec not yet done, or failed) is not signalled. It
       cannot authenticate after the narrowing, because the signer refuses. The next supervisor pass
       checks it again once the exec has happened. An exec that failed clears the row together with the
       holder.
   * **Windows.** The launcher spawns the client and waits, so the two are different processes. ⟨r2⟩ A
     managed launch whose program is the verified client:
     1. creates the child **suspended**, and assigns it to a new job object with
        `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and without breakaway
        (`localenv::sys::JobObject::spawn_contained`);
     2. ⟨r3⟩ registers it **while it is still suspended** (§17.4 item 8; A R2-08), through
        `Request::Connections(Register { binding_id, pid, created_at, image })` (owner role).
        * The runtime commits the row **under the grant's signing gate, taken shared**, in a
          transaction that re-checks the grant: not ended, no tombstone on it or an ancestor, deadline
          not passed, time `Safe`, generation current.
        * A grant that fails any check refuses the registration (`connection_registration_refused`).
        * A narrowing takes the gate exclusively before its commit, so every registration is ordered
          with every revocation. Either the row exists before the revocation commits, and the
          revocation closes it, or the registration is refused;
     3. resumes the child's main thread **only after** a successful registration reply. A refusal, or
        any failure, closes the job, which kills the still-suspended client, and writes
        `prelaunch_failed` with reason `connection_registration_failed`;
     4. ⟨r3⟩ a revocation that commits **between** registration and resume finds the row and terminates
        the registered process; the job holds any child it might have started. Resuming a terminated
        process does nothing.

     The launcher's death then ends the client too: the job closes with the launcher's last handle.
     Revocation and a strict deadline end the exact `ssh.exe` through a handle opened on the
     registered PID, with its creation time checked.
   * ⟨r3⟩ Tests (U7; U0b rows 19 and 26): `windows_register_while_suspended_under_gate`;
     `windows_register_refused_for_ended_grant_child_never_resumed`;
     `windows_revoke_between_register_and_resume_kills_child`;
     `windows_pause_before_register_then_revoke_refuses_registration`;
     `unix_connection_row_written_at_bind_with_expected_image`;
     `unix_revoke_between_bind_and_exec_not_signalled_then_closed_after_exec`.
   * ⟨r2⟩ **The M02 "no job object" rule** (`launch/windows.rs`; ADR-0007 §8 and §11) was checked, as
     §17.1 item 8 requires. Its reason is that kill-on-close "kills grandchildren left running on
     purpose after a normal exit; not exec-equivalent" (M-F21).
     * ⟨r3⟩ **§17.3 item 1 ruled Q18 (a).** The job object applies only to launches whose program is
       the verified `ssh`. ADR-0007 §8 is amended for those launches alone, and the narrow residual is
       disclosed: ssh's own `ProxyCommand` or `LocalCommand` helpers end with it.
     * `run` of any other program keeps M02's semantics, and reports `not_controlled`.
     * The predicate `launch_uses_kill_on_close_job(binding, program)` stays, now fixed to that ruling.

   | Event | graceful | strict |
   |---|---|---|
   | Admission deadline, cutoff | kept: the wording of item 6 | closed: "Connections Heimdall started are closed at the deadline." |
   | Revocation, `revoke_on_lock` | **closed** | **closed** |
   | Release of the last reference | as at the deadline | as at the deadline |
   | `TIME_UNCERTAIN` | kept | closed |

   **Closing.**
   * **Linux:** `pidfd_open` on the exact PID, the start time and the executable re-verified through
     `/proc`, then `pidfd_send_signal(SIGTERM)`, and `SIGKILL` after 5 s. A pidfd pins the process, so
     there is no PID-reuse race.
   * **macOS:** `kill` after re-verifying PID, start time and executable with `proc_pidinfo` and
     `proc_pidpath`. A small reuse window remains between the check and the signal; it is disclosed.
   * **Windows:** `OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)` on the
     registered PID, the creation time verified on that handle, then `TerminateProcess`. The handle
     pins the process. The job additionally guarantees the client dies with its launcher.

   A process whose identity cannot be verified is never signalled. It is reported `unverified` and
   treated as unmanaged.

   ⟨r2⟩ **`connect`'s flow** (§17.1 item 8). M02's `connect` binds nothing (`connect_cmd.rs`). In M03,
   `connect <alias>` for a pair whose preference is `managed_certificate` and whose projection is
   applied:
   1. **Resolve the pair** from the catalog.
   2. **`ensure`** for the single-pair scope under the environment's default profile that contains the
      destination. If no profile covers it: `CAPABILITY_UNAVAILABLE`, reason
      `no_profile_covers_destination`. The request ID is derived from the alias and a fresh nonce, so
      it is never a replay.
   3. **`bind`** with `BindForm::Launch { executable, holder }`, the launcher's own PID and start token
      as M02 does for `run`.
   4. **Launch** the verified client with the binding's endpoint and files on the command line (D10
      item 4), ⟨r3⟩ in the foreground: `ForkAfterAuthentication=no`, and the option refusals above. On
      Windows this goes through the contained spawn, registered while still suspended; on Unix through
      `exec`, the connection row having been written at bind.
   5. **On exit:** the holder release (M02 `holder_pass`) drops the reference, and the
      owned-connection row is cleared on the observed exit.

   For an existing-access pair, `connect` keeps M02's flow unchanged.

   **`run` of any other program** (a shell or an agent CLI that starts its own `ssh`): its children are
   **not owned** for closing. Their new authentications are still refused by the signer after the
   deadline. The result reports `existing_connections: not_controlled` for such a binding, never
   `strict_disconnect`. Closing a user program at the deadline is not a connection policy (spec §6.6
   "Detached remote processes are not automatically terminated").

3. **Owned masters** (`multiplexing: owned_masters`, materialized bindings only).
   * ⟨r2⟩ **A stable path per pair slot** (§17.1 item 16; M03-R15, F16). Each pair slot has one
     multiplex path, `<runtime_dir>/mux/<destination-id>`, fixed for the slot's life and **rendered in
     P** by the approved projection. It is never a per-master random path, which would need a new
     projection transaction for every master.
     * **Enabling masters is widening** (a decision record, D8 item 1). It takes effect only through a
       `setup apply` that renders the path into P. While masters are disabled, P renders `ControlPath
       none`.
     * **The path** must fit the platform's socket-path limit (`SUN_LEN`; the M02 lesson). A runtime
       directory whose mux path would exceed it refuses `owned_masters`, with reason
       `mux_path_too_long`.
   * **Start.** The supervisor starts `ssh -M -N` as a **foreground child**, never with `-f`, with
     these options:
     * `-o ControlMaster=yes`, `-o ControlPersist=no`, `-o ControlPath=<the slot's path>`;
     * `-o IdentityAgent=<binding endpoint>`, `-o IdentitiesOnly=yes`,
       `-o IdentityFile=<binding key.pub>`, `-o CertificateFile=<binding cert>`;
     * `-o ClearAllForwardings=yes`, `-o ExitOnForwardFailure=yes`, `-o BatchMode=yes`, ⟨r3⟩
       `-o ForkAfterAuthentication=no` (item 2);
     * `-- <alias>`.

     It is recorded as a `ManagedResource` (`Process`, generation-tagged), and in `owned_connections`
     (kind `master`: PID, start token, control path, generation).
   * ⟨r2⟩ **Generation protection.** The path is stable, but each master is one generation. Before
     starting master N+1, the supervisor closes master N (below) and removes the socket only if it is
     still N's inode. A cleanup of N never removes N+1's socket. Ordinary clients use whichever master
     is live at the path, which is always the slot holder's (M-F5).
   * **Close** at the admission deadline, at `TIME_UNCERTAIN`, at revocation and at release, **under
     both policies**: `ssh -O exit -o ControlPath=<path> <alias>`, bounded to 5 s; then SIGTERM, and
     SIGKILL after 5 s, to the verified PID; then removal of the socket only if it is still the same
     inode.

     Sessions through a master therefore end at the deadline even under `graceful`. The disclosure
     says: "Sessions shared through a Heimdall connection end at the deadline." No other mechanism stops
     admissions gracefully: `-O stop` does not (M-F6, F-7).
   * **Restart.** Before anything else, the supervisor closes the owned masters of grants that have
     ended, identified by persisted PID, start token and control path. A master of a still-valid grant is
     kept; it needs no key for sessions, and it is closed at its deadline. A master whose identity cannot
     be verified is left alone and reported unmanaged. ⟨r2⟩ A slot whose holder changed while the
     runtime was down gets its new master only after the old one is closed or found gone.
   * ⟨r2⟩ **Replacement.** When the slot passes to another binding (D10 item 2), the old master is
     closed first, then the new holder's master starts at the same path. Test:
     `two_successive_bindings_share_the_slot_mux_path_through_ordinary_ssh` (plan U7).
   * **Failure to start** (unreachable, auth failure): bounded, jittered retries by the supervisor. No
     master is needed for correctness: clients connect directly.
   * **Windows:** `multiplexing: owned_masters` is refused with `CAPABILITY_UNAVAILABLE`, reason
     `multiplexing_unsupported` (M-F7). It is reported `owned_multiplexing: unavailable`.

4. **User-configured multiplexing for managed aliases.** P renders `ControlMaster no` and `ControlPath
   none`, or the owned path, for every `managed_certificate` alias. P is read first, so a user `Host *
   ControlMaster auto` cannot create an unmanaged master for a managed alias (F1). For unmanaged aliases
   nothing changes, and their masters are reported `unmanaged_connections: not_controlled`.

5. **Remote processes** are never claimed to stop (`remote_processes: not_terminated`). U7's E7 rerun
   records a remote process still alive after `-O exit` [O:E7].

6. ⟨r2⟩ **The deadline wording depends on identity selection** (§17.1 item 18; F15). For an alias
   whose selection is `exclusive` (D10 item 6), the graceful text is "New connections stop at the
   deadline; existing sessions may stay connected." (spec §6.6). For a `not_exclusive` or
   `undetermined` selection, it is "New connections through Heimdall's key stop at the deadline. Your
   other configured identities for this host are not controlled; existing sessions may stay
   connected." The revoke result and the TUI use the same rule.

---

## 10. D9 — Lock and unlock

1. **Default `continue`.** A desktop lock and a personal-vault lock do not end managed grants (spec
   §6.4). The signer and issuer hold their keys in memory.
   * Heimdall does not observe the personal vault, and does not need to. That independence is the
     point of the recipe.
   * **The disclosure is shown once** (R-UX-03), in the `RegisterIssuer` and first `EnrollAccount`
     decisions and in `inspect capabilities`. ⟨r2⟩ It is **conditional**, and it states the saved
     limits (§17.1 item 18; F19):
     > Approved work is designed to keep working while your screen or password manager is locked,
     > until its end time: at most <max window> after approval, under your saved policy
     > "<policy name>". On this computer that has <been verified | not been verified yet>. To stop it
     > when you lock the screen, set lock behaviour to "revoke on lock".

     The verified/not-verified clause comes from the claim table (D12). The saved limits come from the
     applicable policies' `max_window` and cutoffs.
   * Acknowledgement is recorded once (`meta: lock_disclosure_acknowledged_at`) and not repeated. The
     help text and the TUI detail always show the current behaviour.

2. **`revoke_on_lock`.** It is set on a standing policy (`PolicyAction::SetLockBehavior`). For an
   owner-decision grant, the approval prompt offers it, and the choice is recorded in `GrantOrigin`.
   * The effective behaviour is the strictest of the recorded value and the current applicable
     policies.
   * Setting `revoke_on_lock` is narrowing and immediate. Setting it back to `continue` is widening: a
     decision record and an attended `Decide`, effective for later locks only.
   * **On a lock event**, the supervisor revokes every grant whose effective behaviour is
     `revoke_on_lock`. This is a real revocation, with tombstone and cascade, and cause `session_locked`
     (new `RevocationCause`). Owned connections close (D8).
   * **Unlock reactivates nothing** (terminal grants stay terminal). New work needs a new activation.
   * Re-issue after any restart never runs for these grants (ADR-0005 §3.7 rule 5), so a lock missed
     while the runtime was down cannot leave them alive.

3. **The lock source** (`app::ports::SessionLockSource`). States: `unlocked`, `locked`, `unknown`,
   `unavailable`.

   ⟨r2⟩ **Lock events latch** (§17.1 item 9; M03-R09). A `watch` channel keeps only its last value, so
   a lock followed by an unlock before the consumer reads could erase the lock that must revoke. The
   source therefore exposes two things:
   * **the current state**, carried separately;
   * **a monotonic lock epoch** with a latched "lock observed" flag. Every transition into `locked`
     increments the epoch and sets the flag. The flag clears **only** when the revocation pass calls
     `acknowledge(epoch)` for that epoch, after its revocations have committed.

   So a lock that is over before the supervisor looks still revokes. Test (plan U9):
   `lock_then_unlock_while_consumer_paused_still_revokes`.

   | Platform | Query | Events | Status in M03 |
   |---|---|---|---|
   | macOS | `CGSessionCopyCurrentDictionary`, `CGSSessionScreenIsLocked` | ⟨r7⟩ a poll of `CGSessionCopyCurrentDictionary` every 250 ms on a thread the source owns: distributed notifications are delivered only on the main thread's run loop, which is tokio's, so no observer is registered (§17.17 item 10, U9-Q4) | implemented; native evidence through P1 (M-F12) |
   | Windows | `WTSQuerySessionInformationW(WTSSessionInfoEx)` for the current session | `WTSRegisterSessionNotification` on a hidden message-only window thread | implemented; native evidence through P-W1 (M-F13) |
   | Linux desktop | logind `LockedHint` (D-Bus system bus) | `Lock`/`Unlock` signals | implemented; **native evidence blocked on B11**. ⟨r2⟩ `revoke_on_lock` is accepted there but labelled `signal_unverified` in every result and in the disclosure until B11's evidence exists (F19) |
   | Linux headless, WSL, containers | — | — | `unavailable` |

   * Setting `revoke_on_lock` where the source is `unavailable` is refused with `CAPABILITY_UNAVAILABLE`,
     reason `lock_signal_unavailable`. It is never accepted silently.
   * At start, and whenever the source reports `unknown`, every `revoke_on_lock` grant is treated as
     locked, failing closed.
   * The signer's per-signature check (D2 item 3) also refuses for these grants unless the state is
     `unlocked`, so a signature cannot slip through between a lock and its event.

4. **Logout and reboot.** The runtime is a user process.
   * At logout it may be terminated. Keys are lost, and re-issue at the next start follows ADR-0005
     §3.7: a same-boot anchor, or after a reboot accepted time or an owner confirmation.
   * Start at login (a login item, launchd agent, systemd user unit or Windows Run key) is M04-T04. In
     M03 the runtime starts on demand, and `conditions: [signer_running]` says so.
   * Logout-revokes is not in V1.
   * Native logout and reboot rows are blocked on B12.

5. **Sleep.** The continuous clock counts sleep; the deadline is not suspended. On wake, the
   per-signature gate is the first check before any signature (ADR-0005 §3.6). The native sleep row is
   blocked on B12. Virtual-clock tests cover the wake path (`advance_continuous_only`).

---

## 11. D10 — Consumer integration for managed pairs

1. **The ADR-0007 §2 directive-set revision.** For an alias whose pair preference is
   `managed_certificate`, with the projection applied, P renders, in this order:
   * `HostName`, `Port`, `User`;
   * `IdentityAgent "<environment endpoint>"`: a Unix path, or `//./pipe/heimdall-<token>-signing` on
     Windows (F14);
   * `IdentitiesOnly yes`;
   * `IdentityFile "<data_dir>/managed/<destination-id>/key.pub"`;
   * `CertificateFile "<data_dir>/managed/<destination-id>/cert.pub"`;
   * `ControlMaster no`;
   * `ControlPath none`, or, ⟨r2⟩ once owned masters are enabled and applied, the slot's **stable**
     mux path `<runtime_dir>/mux/<destination-id>` (D8 item 3).

   Existing-access aliases render exactly as in M02; no new directive is added to them, so M02 consent
   and behaviour are unchanged. Paths follow ADR-0007 §4.

   **The Windows environment pipe name** must be stable, because P names it. It uses a **per-installation
   random token**, persisted in the state store (`meta: windows_environment_pipe_token`), not the
   per-instance token of the control pipe. Pipe names are visible to other users (g03 §3.1 N2), so a
   squatter can create the name first:
   * the runtime's first-instance creation then fails, the environment endpoint is reported
     `unavailable`, and every managed result says so (fail closed);
   * Windows `ssh.exe` performs no owner check on the pipe, but a squatting agent still cannot use
     Heimdall's key or certificate: `IdentitiesOnly` with Heimdall's `IdentityFile` makes ssh offer only
     a key the squatter does not hold. So the squatter can deny service, and nothing more. This is
     disclosed. The cross-user test is blocked on B2;
   * if the token ever changes (state reset), P is stale: the setup preview shows an update, and
     `ensure` refuses with `projection_pending`.

   ⟨M02?⟩ This relies on M02's Windows `RenderPath` and replace fixes.

2. **Slots.** One slot per (environment, destination, account): `managed_slots(environment, destination,
   account) → (binding, generation)`. The slot files are public. They are written atomically by
   generation (temporary file plus rename; on Windows the M02 replace primitive), and absent when the
   slot is free. An absent `IdentityFile` makes ssh fail closed for that alias. It warns and offers
   nothing from P, though inherited user entries may still be offered (M-F4; identity selection below).

   ⟨r3⟩ **Ordinary `ssh <alias>` works only while a binding holds the slot** (§17.4 item 12; B R2-18).
   After `setup apply`, a managed alias whose slot is `free` fails closed, and automatic activation on
   first use is M05. This is disclosed wherever the owner meets it:
   * `EnrollmentResult.next` after a pass, and the `ApplyProjection` preview, say that ordinary
     `ssh <alias>` needs a held slot, and give the command that holds one (`heimdall run …` or
     `heimdall bind materialize …`);
   * the doctor and the TUI report `slot_free` for such an alias, with the same command.

   | Slot state | Event | Next |
   |---|---|---|
   | `free` | `bind materialize` of a managed binding for this pair, or `run` auto-materialize | `held(binding, g+1)`: files written, then the endpoint lists the key |
   | `held(b, g)` | another binding asks | refused with `CONFIG_CONFLICT`, reason `managed_slot_held`, next `release_binding` |
   | `held(b, g)` | b's grant ends, or b is released | `clearing(g)`: the key is unlisted at once, then the files are removed by generation |
   | `clearing(g)` | files removed | `free` |
   | any | crash | at restart, the files at generation g are reconciled with the slot row: a missing key (lost instance) is `held` and `degraded` until re-issue; a row for an ended grant is `clearing` |

3. **The environment endpoint** lists exactly the slot holders' keys and certificates.

4. **`connect`** launches ssh for a managed binding with command-line options pointing at the
   **binding's** endpoint and files:
   * `-o IdentityAgent=…`, `-o IdentityFile=…`, `-o CertificateFile=…`;
   * `-o IdentitiesOnly=yes`, `-o ControlMaster=no`, `-o ControlPath=none`, ⟨r3⟩
     `-o ForkAfterAuthentication=no` (D8 item 2).

   Command-line values win (F1), so `connect` works for any managed binding, materialized or not, and
   its connection is an owned dedicated connection (D8). ⟨r2⟩ Its ensure, bind and ownership flow is
   D8 item 2's.

5. **`run`** with a managed binding requires the binding to hold the slot of every managed pair.
   * When the slots are free, it materializes them.
   * Otherwise it refuses before launch with `CONFIG_CONFLICT`, reason `managed_slot_held`, writing
     `prelaunch_failed`.
   * It sets nothing beyond M02's rules. The child's ordinary `ssh`, `git`, `scp` and `sftp` reach the
     key through P, because `IdentityAgent` in P beats `SSH_AUTH_SOCK` (M-F3).
   * **Several concurrent, distinct managed bindings for the same pair in one environment** are
     available only through `connect` and per-binding endpoints in M03. Ordinary aliases and `run` serve
     one binding per pair: the environment default. The general bound-context strategy is G05/M05
     (§8).

6. **Identity selection** for a managed alias is ADR-0007 §3 item 3's classification. `exclusive` means
   only the slot key and slot certificate. Inherited user entries make it `not_exclusive`, and on the
   no-interaction path M02's fallback clearance applies. `identity_selection:
   client_configuration_and_signer` is reported only when `exclusive`. ⟨r2⟩ The deadline wording
   follows the selection (D8 item 6; F15).

---

## 12. D11 — Rotation, wrong-host principals and source-provider failure

1. **Rotation.**
   * K_env rotates by construction: a new key per grant.
   * K_ca: D4 item 3.
   * Registry lines: a new enrollment per (pair, CA) and removal of the old one (D5).
   * The A09 "rotate" exercise is a full K_ca rotation on two accounts, with one account made
     unreachable mid-way.

2. **Wrong-host principals** (spec §7.6, R-CR-07).
   * Each certificate carries exactly one `hm:<destination-id>:<account>` principal.
   * The predicate refuses a pair outside the grant (`PairOutsideSnapshot`) and a principal that is not
     the pair's (`WrongPrincipal`).
   * The issuer child refuses more than one principal (ceiling).
   * No API produces a multi-principal certificate. The destination scope claim is per pair and needs
     that pair's `verified` enrollment.
   * A10 uses two hosts that trust the same CA, in both forms.

3. **Source-provider failure.**
   * **During enrollment:** a locked, denying or unreachable provider fails the step with its own code
     before any write (`failed_unwritten`), or leaves an `Uncertain` step for reconcile (§6.7). Nothing
     falls back to another identity: existing access is used through the alias's own configuration.
   * **After enrollment:** the managed path does not depend on the source provider. A03 locks or stops
     it, and managed access continues.
   * ⟨r2⟩ **Maintenance after enrollment** (rotation, removal, rollback, reconcile) depends only on the
     source provider, never on the managed credential (D5 §6.3, §17.1 item 4). Its tests run with every
     managed binding released and the issuer unavailable.
   * **Issuer or store failure:** no new activation or re-issue, `CAPABILITY_UNAVAILABLE` and no
     fallback. A `managed_certificate` grant never switches to the existing identity, and an
     existing-access grant never switches to managed (spec §15.2). A11 and A35 stay as M02 delivered
     them.

---

## 13. D12 — Capability reports and the claim table

1. **Fields.** ADR-0005 §7.1 maps onto the contract as additive fields; m03-plan §5 gives the shapes.
   * `EnsureData`: `lock_continuity`, `conditions`, `refresh_condition`, `revocation`, `evidence`,
     `connection_policy`.
   * `Enforcement`: `identity_selection`, `new_signing_expiry`, `owned_multiplexing`, `remote_processes`,
     `unmanaged_connections`, `issuer_isolation`.
   * `RevokeData`: `remote_effects`, ⟨r2⟩ `owned_connections`, `notes`, ⟨r5⟩ `requested_at`, `committed_at`
     (D7 item 2; §17.10 item 3).
   * Spelling: ADR-0005's `not_enforced` is the existing `none` of `NewAuthenticationExpiry`, which the
     G08 naming freeze may rename. ADR-0005's `available_through_deadline` is the existing
     `CredentialAvailability::ThroughDeadline`.

2. **Per-field rule:** a value whose test has not passed **for this platform and these versions** is
   `unknown` (or `not_verified` for `lock_continuity`). An unmet or unknown minimum is
   `CAPABILITY_UNAVAILABLE` (R-AU-08).

3. **Three kinds of value:**
   * **Runtime evidence**, produced by the product itself and recorded with the enrollment. The
     enrollment's positive and negative verification (D5 §6.5) gives `destination_scope:
     verified_server_principals` **for that pair**, labelled with its time and its client and server
     versions.
     * Freshness and invalidation follow Q11 as amended (D5 §6.5).
     * ⟨r2⟩ This **amends ADR-0005 §7.4 row 1**, which asked for A10 on two hosts per form before the
       value could be reported. §17.1 item 13 rules that per-pair runtime evidence, labelled with its
       time, suffices. A10 remains the test of the mechanism that produces it (F11).
   * **The claim table** (`heimdall_domain::claims::CLAIMS`). It is the **only** source of
     platform-mechanism claims:
     * `lock_continuity: verified`;
     * `new_signing_expiry: signer`;
     * `owned_multiplexing: closed_at_deadline`;
     * the `existing_connections` behaviour;
     * `new_authentication_expiry: credential_and_signer`;
     * the summary `enforcement.revocation`, and ⟨r2⟩ **`revocation.remote`, gated exactly the same
       way**, so it reads `unknown` until a claim exists (§17.1 item 13; F11).

     It is a static list compiled into the binary. ⟨r2⟩ Each entry holds:
     * field, value, platform and architecture;
     * OS release floor, client version range and signer build range;
     * **the build profile** (`release` or `debug`) **and the store kind** of the run;
     * a record path and the record's commit.

     `check.sh` (`claims-table` step) fails unless every entry's record exists, validates, is `verified`
     for that platform row, and names a commit that is an ancestor of HEAD.
     * ⟨r2⟩ It also fails an entry whose **build profile is not `release`**, or whose **store kind is
       not the platform's product store**, for any field that depends on custody (`lock_continuity`).
       **Test-store evidence never satisfies a product-store claim** (F03).
     * **macOS `lock_continuity` stays `not_verified`** until a release-profile run on the login
       keychain (B3).
     * On Windows a release-profile run with `HEIMDALL_HOME` in scratch uses the product DPAPI store
       kind (D1), and is eligible.
     * **The M03 baseline table is empty.** Entries are added only by a reviewed commit after the
       native record is `verified` (m03-plan §3, "claim update"), and the claim tests then re-run on the
       build that contains them.
   * **Limitations and the binding's own configuration** are always reported. They claim nothing:
     `owned_multiplexing: disabled`, `remote_processes: not_terminated`, `unmanaged_connections:
     not_controlled`, `workload_isolation: shared_os_user`, `issuer_isolation: same_user_process`, and
     ⟨r2⟩ the per-destination facts of `RevokeData.remote_effects`: the latest `valid_before` from the
     issuance log, the clock measurement, the status of D7 item 3.

4. **Never reported by M03:** `isolated_execution_boundary`, `authenticated_agent_restriction`, universal
   immediate revocation, remote process termination, `verified_server_key_enrollment` (Recipe A is not in
   M03), `log_attestation: available`.

5. **Time synchronization.** The `TimeSync` readers report observations: Linux `timedatectl show -p
   NTPSynchronized`, the macOS time daemon's state, Windows `w32tm /query /status`. **They are not
   trusted in M03:** the gate still receives `Unknown` until M04/G09 evidence (ADR-0006 §13.3 item 4;
   Q13). So after a reboot managed issuance waits for an attended `heimdall time confirm`; that is
   disclosed in `conditions` as `time_confirmation_after_reboot`.

6. ⟨r2⟩ **The issuer-reachability evidence of A10** (§17.1 item 13; F10). The test formerly named
   `a10_worker_cannot_reach_issuer_material` claimed more than any same-user test can show. It is renamed
   `a10_bound_consumer_issuer_reachability_recorded`, and it records per platform what a same-user worker
   process **can** do, each with a positive control:
   * **Windows:** a same-user worker can unprotect a DPAPI blob. The positive control unprotects a
     scratch test blob from the worker.
   * **macOS:** reading the keychain item prompts or is refused for a different executable.
   * **Linux:** a same-user worker can read an unlocked Secret Service item (blocked on B11; the
     private-session mechanism row where available).
   * **Every platform:**
     * no issuer listening path exists;
     * no signing endpoint lists K_ca;
     * no process the runtime spawned holds the issuer's pipe descriptors (Unix, checked on exact
       PIDs);
     * the scanned files, argv and environments hold no K_ca bytes.

   `issuer_isolation: same_user_process` stays, and the record says plainly that the boundary is the OS
   user.

---

## 14. D13 — Test environments

1. **The disposable CA.** Each run has its own K_ca, created through the real `issuer init` ceremony on a
   pty, in `ScratchSecretStore`, or, on Windows, in real DPAPI on a scratch path (ADR-0004 §3). The
   key's comment carries a canary. Nothing is committed. The D5 backup goes to scratch, and the
   passphrase is captured only from the pty transcript, which A33 scans as the one allowed location.

   ⟨r2⟩ **The interop check drives stock `ssh-keygen` through a pty** (§17.1 item 17; M03-R14). It runs
   `ssh-keygen -y -f <backup>` and types the passphrase at its prompt, so the passphrase never appears
   in argv. The transcript capture is restricted to that pty, removed with the scratch, and scanned
   like the ceremony's.

2. **Disposable sshd targets** (all on loopback; AGENTS.md). Two families: loopback sshd on every host,
   and the Docker containers on the build host.

   | Target | Form | How | Proves |
   |---|---|---|---|
   | `LoopbackSshd` ×2 (non-root, scratch `AuthorizedKeysFile`, two destination IDs) | account | Enrollment with an explicit `--registry-path <scratch file>`. The **registry guard** (item 4) refuses any other path | the add, remove and verify protocol; A10 wrong host; interleavings |
   | `LoopbackSshd` with `TrustedUserCAKeys <scratch>` and `AuthorizedPrincipalsFile <scratch>/%u` | system | The test writes the CA and principals files as the owner-administrator would | A10 system form |
   | Docker `enrollable` and a new `enrollable2` (M00-T03 image; account `enroll`, account-owned registry seeded with unrelated lines including a foreign `cert-authority`; the sshd log not readable by the account) | account, **default registry path** | Build host only; `up.sh` and `down.sh` | the default-path production verification on an account that cannot read the sshd log (ADR-0005 §9.3 R5); A10 on two hosts |
   | Docker `ca1`/`ca2` | system | The harness adds the run's test CA to the container's `TrustedUserCAKeys` (container-internal, disposable) | A10 system form on two hosts |
   | WSL disposable distribution (`wsl --import`; ADR-0004 §3): sshd as the distribution's root on `127.0.0.1`, a disposable non-root user with a real home | account (default path) and system | Inside the disposable distribution only | the real `~/.ssh/authorized_keys` and `StrictModes`; ordinary `ssh` without `-F` for a managed alias |
   | ⟨r2⟩ `LoopbackSshd` fault modes (`testkit::sshd::Faults`): stop between attempts, close the port, `MaxStartups 1:100:1` with a held connection, reset after the version exchange | account | U11 helpers driven by U5 | the negative verification's inconclusive cases (§17.1 item 3) |
   | ⟨r2⟩ A clock-lagging destination: a fixture sshd whose own `sshd_config` sets `PATH` for its sessions (`SetEnv`) to a scratch directory whose `awk` wrapper reports the time minus a fixed lag. No system clock is changed | account | U11; never a system clock change | the destination-clock measurement and the residual bound computed from it (§17.1 item 10). A server that really accepts certificates late is not reproduced: the fixture's sshd validates with the real clock, and containers share the host kernel's clock |
   | ⟨r2⟩ A second Heimdall installation (`HEIMDALL_HOME` in a second scratch, its own catalog and destination IDs) | account | U10 e2e | foreign removal from a bundle (§17.1 item 11; F07) |
   | ⟨r3⟩ Wrong-key destinations: a `LoopbackSshd` whose host key is **not** the approved one, with each of: an inherited `KnownHostsCommand` that prints that key; an inherited user or global known-hosts file that lists it; an inherited `NoHostAuthenticationForLocalhost yes` | account | U11 fixtures, driven by U5 | every remote step refuses before any mutation (§17.4 item 1) |
   | ⟨r3⟩ The `principals_not_enforced` fixtures (M-F27). Account form: a line listing **both** principals, `principals="hm:<dest>:<acct>,hm:verify-negative:<nonce>"`, written at a pause hook once the verification's nonce is known. System form: an `AuthorizedPrincipalsCommand` (with `%k`) that prints the presented certificate's principals. The bare `cert-authority` line without `principals=` is a separate `verification_failed` case | account, system | U11, driven by U5 | `principals_not_enforced` is actually produced (§17.4 item 11; B R2-08) |
   | ⟨r4⟩ Disposable shell containers on the build host: `debian:13` with `/bin/sh` pointed at bash, and `alpine` with BusyBox `ash` and `ps`. The generated scripts run directly under each shell, in a `setsid` session | — | U11 (`ShellContainers`), driven by U5 | the per-shell group proof and the leader-absent fencing test, where no sshd target runs that shell (§17.7 item 1) |

3. **Concurrent writers.** In the test configuration only, the scripts carry pause points (`HM_PAUSE
   <name>` lines). Each blocks on a FIFO named in the test's scratch until the test releases it. The test
   injects administrator edits at each point, before and after the final check, for add, remove and
   rotation (ADR-0005 §9.3 R1). A golden test proves that release scripts contain no pause point.
   ⟨r3⟩ The points include `before_write` (after the final re-check) and `nonce_known` (once a
   verification's negative nonce exists). A truncation harness cuts each script at every byte offset
   (§17.4 items 2 and 11).

4. **The registry guard** (`testkit::registry::RegistryGuard`). Every enrollment a test runs must target
   a registry under its scratch directory, inside a disposable container, or inside the disposable WSL
   distribution. Anything else is `FixtureUnsafe` before any ssh runs. Each harness also records the
   SHA-256 of the owner's `~/.ssh` tree, Git configuration and (macOS) keychain list before and after,
   as M02's harnesses do, and fails on any change.

5. **Keys.** Per-run keys only. In the test configuration K_env generation may take a seed
   (`HEIMDALL_TEST_KEY_SEED`), so A33 can scan every output for the exact private bytes: raw, hex and
   base64. ⟨r3⟩ Release builds **refuse** the
   variable with exit 2, as M01 and M02 do (`testcfg.rs`), which `release_build_refuses_m03_test_gates`
   proves (§17.4 item 12; B R2-15). Fixture public keys are committed
   only where a file header says so.

6. **Oracles.**
   * The verification endpoint's signature count, and the counting proxy of M02;
   * the loopback sshd log oracle (accepted lines by key ID), test-only;
   * `ssh -O check` for masters;
   * process tables by exact PID.

7. **Lock.**
   * `FakeSessionLockSource` in the test configuration. ⟨r2⟩ It can pause its consumer, to test the
     latched epoch (D9 item 3);
   * ⟨r2⟩ the lock procedure gives **each grant its own pairs** (§17.1 item 17; F09). The authenticating
     grant is confirmed from the certificate key ID in the loopback sshd log, and the post-unlock checks
     depend on each grant's remaining deadline (m03-plan §4.4);
   * native locks under the ADR-0004 §2 rule only: the harness requires console idle ≥ 15 min (macOS
     `HIDIdleTime`, Windows `GetLastInputInfo`), triggers the lock (macOS `pmset displaysleepnow` where
     that locks; Windows `LockWorkStation` from the interactive session), **verifies the lock state
     through the product's own query**, and records it. If the trigger does not produce a verified lock
     on that host, the row is `blocked` with that observation.

8. ⟨r2⟩ **The ptrace mitigation test has a positive control** (§17.1 item 17; F22). The same harness
   attaches, in the same way, to a dumpable scratch control process, and records both results with
   `ptrace_scope`. The non-dumpable result counts only when the control attach succeeded.

9. **Never touched:** the owner's keychain, Secret Service collections, Credential Manager, DPAPI blobs
   other than scratch ones, agents, 1Password, `~/.ssh`, and real servers.

---

## 15. Contract additions (summary)

ADR-0006 revision 4. The exact shapes are in m03-plan §5. Everything is additive (schema major stays
`"1"`), and every new enum is `#[non_exhaustive]` and `snake_case`.
* **Requests:**
  * `Request::Issuer`: status, register (which covers init, rotate-begin and restore), unlock, retire,
    bundle;
  * `Request::Enrollment`: preview, apply, verify (⟨r2⟩ presence or absence, ⟨r3⟩ or a target change
    approved through `ApproveTargetChange`), remove, reconcile (⟨r3⟩ with `after_manual_recovery`),
    abandon, and the client-executed `step` and `step_result` (D5 §6.3; owner role);
  * `Request::Connections`: close (owner role, narrowing), ⟨r2⟩ and `register` for a Windows owned
    connection (D8 item 2);
  * the catalog action `SetPreference`.
* **New fields:** `EnsureRequest.connection`; `PolicyAction::{SetLockBehavior, SetConnectionPolicy}`;
  `InspectSubject::{Enrollments, Issuer, Connections}`.
* **Operation kinds:** `enrollment.apply`, `enrollment.verify`, `enrollment.remove`.
* **Decision kinds:** `RegisterIssuer`, `RetireIssuer`, `EnrollAccount`, ⟨r2⟩ `EnrollSystemForm`,
  `RemoveEnrollment` (⟨r3⟩ optionally carrying a freshly evaluated target), ⟨r3⟩ `ApproveTargetChange`
  (D5 §6.2).
* **Capabilities:** `issuer/1`, `enrollment/1`, `managed-credentials/1`, `connections/1`, offered only
  when their drivers land.
* **Fields on existing types:**
  * in `EnsureData`, `Enforcement` and `RevokeData` (D12; ⟨r2⟩ `RevokeData.owned_connections` and
    `notes`, D7 item 2; ⟨r5⟩ `requested_at` and `committed_at`, §17.10 item 3);
  * `CertificateBounds.ca_fingerprint`;
  * `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`;
  * `RevocationCause::SessionLocked`;
  * `RemoteObligation.kind`, with ⟨r2⟩ the statuses `pending_until`, `bounded_complete` and
    `nominally_expired` (D7 item 3);
  * ⟨r2⟩ `IssuanceRefusal::CaRetiring`; the CA states `retiring`, `unloaded`, `deleted`, `retired`
    (D4 item 3).
* ⟨r2⟩ **New ports** (§18): `ManagedEffects`, `TargetEvaluator`, and the signing gate's `SignPermit`
  in `SignatureAuthority`; ⟨r3⟩ `VerificationEndpoints`, and `ipc::signing::{PermitGuard, ReleaseCheck}`.
* **Events:** `EventType::{Enrollment, Connection, SessionLock}`.
* **Codes:** no new code. The new stable sub-reasons go in `data.error.reason`.
* **Store:** migration `0006_managed_credentials`, `SCHEMA_VERSION` 6. ⟨r2⟩ It adds the
  `foreign_removals` table (no foreign key to `issuers`), the CA retirement states and the clock
  measurement in the enrollment evidence.

---

## 16. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Separate signer process | No boundary gain against the same user; a pushed authorization table adds revocation staleness (D2) |
| Issuer on a listening socket with a UID check | E5: same-user minting by path [O:E5] (D3) |
| Issuer that signs the bounds it is sent | A blind oracle; ADR-0005 §3.5 "trusts none of the request's claims" (D3) |
| Issuer inside the runtime | K_ca in the memory that parses every control and agent message (D3) |
| Recipe A (K_A) in M03 | F-5's inventory has not been taken; three more persistent-store rows with their own lock evidence; one complete recipe is the V1 requirement (spec §7.1, plan §11.1). Goes to M04 (Q4) |
| Hardware K_env (SE, TPM) in M03 | Their lock rows need native runs not available in M03; it is ADR-0005 §13's reopen path (D1) |
| Automating the system form (editing `sshd_config` through `sudo`) | Changes live server authentication and needs administration; capability 3 automation is optional (spec §7.4) (D5 §6.9) |
| Whole-file rewrite to add a line | Loses a concurrent administrator edit (ADR-0005 §8) |
| A non-idempotent append (locally decided "not yet written") | A lost reply plus a retry duplicates the line; the script checks the marker remotely (D5 §6.3) |
| Remote enrollment steps run by the runtime | The background runtime has no terminal, so password, passphrase and touch prompts of existing access fail. Relaying them through IPC would carry secrets over the control channel (spec §7.3) (D5 §6.3) |
| Server log as the production oracle | Capability 2 has no log access (ADR-0005 §3.3) |
| Verification through the user's configuration | Inherited `IdentityFile` entries could make it pass for the wrong reason (M-F4) |
| Per-binding `SSH_AUTH_SOCK` for managed aliases | P's `IdentityAgent` wins (M-F3); the binding would not be the one used |
| Rendering per-grant paths into P | Every activation would be a projection transaction |
| `${VAR}` paths in P | ADR-0007 §4 refuses `${`; an unset variable makes the setting ignored (F7), so it would fall through to the user's agent |
| `ssh -O stop` at the deadline | Pre-accepted control connections keep admitting (M-F6) |
| Killing the program `run` launched at a strict deadline | Not a connection; spec §6.6 limits strict to owned connections |
| Lock-revokes by polling an unavailable signal, or accepting the setting without a signal | Silent non-enforcement (D9) |
| Trusting `Synchronized` time reports in M03 | ADR-0006 §13.3 item 4: an assumption until native evidence (D12) |
| Claims computed from documentation or from a test run on another platform | Spec §4.3; R-AU-08 (D12) |
| One combined decision for enrollment and the projection change | Two distinct effects (remote write, local configuration); M02's consent model is per effect. A combined UX is M07 |
| Mixed existing/managed mechanisms in one grant in M03 | M01 records one responsible adapter per grant; per-pair adapters touch revocation obligations and readiness. Goes to M05 (Q5) |
| ⟨r2⟩ Signing that relies on a store read alone for its admission | The store releases its transaction when the read returns (M-F24), so a revocation can commit between the read and the signature (M03-R01, F12). Replaced by the signing gate (D2 item 3a) |
| ⟨r2⟩ Remote steps that trust the ordinary alias for host, port, user and key | A configuration change after approval could redirect the append (M03-R02). Every target field is pinned (D5 §6.3) |
| ⟨r2⟩ Maintenance through P | After the projection switch, P selects the managed agent, key and certificate, so rotation, removal and reconcile would depend on the credential they repair (M03-R04). The existing identity is pinned instead |
| ⟨r2⟩ A negative verification passing on exit status and zero signatures | A closed port, a reset or `MaxStartups` would yield `verified` (M03-R03, F01). Refusal evidence from the `-v` trace is required (D5 §6.5) |
| ⟨r2⟩ Re-verification that rolls back on failure | A later verification is decision-free and must change nothing remotely (M03-R05, F06b; §17.1 item 5) |
| ⟨r2⟩ An unfenced append after a timeout | A first script that survives its timeout can append after a redispatch, giving two lines (M03-R06). A remote lock and a mutation window fence it (D5 §6.3). ⟨r3⟩ Revised: the lock now records its holder and is broken only on proven termination (rows below) |
| ⟨r2⟩ A `watch` channel for lock events | It keeps only the last value, so a quick unlock erases the lock (M03-R09). A latched epoch is used (D9 item 3) |
| ⟨r2⟩ Clearing a residual at local `valid_before` | The destination's clock may lag (M03-R10). Bounded completion needs a measurement; without one the residual is `nominally_expired`, never cleared (D7 item 3) |
| ⟨r2⟩ A per-master random `ControlPath` rendered into P | P changes only through approved setup transactions (M03-R15, F16). A stable per-slot path is used (D8 item 3) |
| ⟨r2⟩ An `app` → `enroll` call while `enroll` implements an `app` port | A crate cycle (M03-R13). The pure protocol code moved to `heimdall-registry`, below `app` (§18) |
| ⟨r3⟩ Breaking a stale lock by renaming it aside after the hard deadline | A paused writer that has already passed its checks still appends (A R2-02; reviewer A's model). Replaced by proven termination of the recorded process group (D5 §6.3) |
| ⟨r3⟩ A mutation window measured from the script's own start | A script delivered late (a stale approval releasing buffered stdin) gets a fresh window (B R2-04). Replaced by an absolute remote not-after and the ready handshake (D5 §6.3) |
| ⟨r3⟩ `IdentityAgent=SSH_AUTH_SOCK` for maintenance | A managed `run` sets `SSH_AUTH_SOCK` to the binding endpoint, so maintenance authenticated with the managed certificate (A R2-04; M-F29). Replaced by the approved concrete endpoint |
| ⟨r3⟩ Relying on the known-hosts file pins alone | An inherited `KnownHostsCommand` supplied an unapproved key (A R2-01; M-F25). Every trust source is pinned, and the effective configuration is checked (D5 §6.3) |
| ⟨r3⟩ The start identity from POSIX `ps -o etime` | "Now minus elapsed" moves with rounding between reads, so any tolerance would accept a reused PID (D5 §6.3) |
| ⟨r3⟩ Breaking another enrollment's lock once its holder is proven gone | Ruled out by §17.4 item 2: such a lock is `busy`. Only that enrollment's own reconcile, or a `RemoveEnrollment` of it, may break it |

---

## 17. Questions for the orchestrator (authority semantics; recommended answers)

Units build against the recommended answers. The integrator changes the affected unit if a ruling
differs.

⟨r2⟩ The orchestrator's rulings are in §17.1: Q6, Q7, Q11, Q12, Q14 and Q17 are amended there, and the
D sections carry the amended rules. The text of Q1–Q17 below is revision 1's, kept for the record.
Questions raised by revision 2 are in §17.2.

⟨r3⟩ §17.3 rules Q18–Q21 (each default accepted), and §17.4 rules the round-2 findings; the D sections
apply both. Questions raised by revision 3 are in §17.5. ⟨r3⟩ Q8 below is refined by §17.4 item 3: the
directory is created by a separate, journaled `bootstrap` step (D5 §6.3, §6.4 E2b), not inside the
append.

⟨r4⟩ §17.6 rules Q22–Q25 (each default accepted), and §17.7 rules the round-3 findings; the D sections
apply both. Questions raised by revision 4 are in §17.8.

⟨r5⟩ §17.9 rules Q26–Q28 (each default accepted), and §17.10 rules the round-4 findings; the D
sections apply both. Questions raised by revision 5 are in §17.11.

⟨r6⟩ §17.12 rules Q29 (the default accepted), and §17.13 rules the round-5 findings and closes the design
gate on the check of revision 6. Revision 6 raises no question.

* **Q1. The issuer has no listening endpoint** (D3 item 2). ADR-0006 §2.1 says the issuer path is "fixed
  now". **Recommended:** keep `EndpointKind::Issuer` and its path reserved and never bound. The issuer is
  a child reached only through inherited pipes, and a test asserts the path never exists. *Why:* it
  removes the same-user-by-path minting that E5 observed, at no cost. *Alternative:* a socket with a UID
  check, as E5 measured.
* **Q2. Signing by reservation, with a read-only store re-check in the issuer** (D3 item 4).
  **Recommended:** yes. *Why:* ADR-0005 §3.5 says the issuer trusts no request claim. *Cost:* one
  read-only connection and a duplicate of the pure predicate in the child.
* **Q3. The signer runs in the runtime process** (D2). **Recommended:** yes. *Why:* per-signature checks
  read the transactional store directly, and a separate process moves no boundary.
* **Q4. Recipe A is deferred to M04** (`deferred_with_decision`). A failed B1 verification rolls the line
  back and reports `verification_failed`, with no K_A. **Recommended:** yes. *Why:* spec §7.1 requires
  one complete recipe, and F-5 is open. *Effect:* destinations without certificate support stay
  existing-access-only in M03, labelled so.
* **Q5. One mechanism per grant in M03** (P6 carried from M02). A profile that mixes enrolled and
  unenrolled pairs is refused with `mixed_mechanisms`, next `narrow_request`. **Recommended:** yes. Mixed
  grants, with per-pair adapters and a weakest-value summary, go to M05, where quiet trusted work needs
  them.
* **Q6. Enrollment decisions.** One attended `EnrollAccount` per (pair, CA), and one `RemoveEnrollment`
  per removal. Re-verification needs none: it makes no remote mutation, and its certificates are ≤ 5
  min under the original enrollment. **Recommended:** yes.
* **Q7. Re-applying an approved append after a "not applied" reconcile** is allowed within 24 h of
  approval, with the same CA and host key; otherwise `DECISION_STALE` (D5 §6.7). **Recommended:** yes.
  *Why:* the same approved effect, not a new one. The script's marker check makes it idempotent.
* **Q8. The registry directory may be created** (`mkdir -m 0700 ~/.ssh` when absent) as part of the
  append. **Recommended:** yes, refining ADR-0005 §3.3 ("inside an existing owner-only directory").
  `mkdir` is exclusive by nature, and refusing would block accounts whose existing access is a password.
* **Q9. Lock behaviour** (D9).
  * **Recommended:** `revoke_on_lock` lives on the standing policy and in the owner decision, merged
    fail-closed.
  * A lock fires a real revocation (cause `session_locked`), and unlock restores nothing.
  * `unknown` lock state means locked for these grants.
  * Setting it is refused where no signal exists.
  * Moving back to `continue` is widening.
* **Q10. Connection policies** (D8).
  * **Recommended:** `graceful` and `disabled` by default; `strict` may be requested per request
    (narrowing).
  * `strict` closes owned dedicated connections only (the holder is the verified `ssh`). `run` of other
    programs is reported `existing_connections: not_controlled`.
  * Owned masters close at the deadline under both policies.
  * `owned_masters` is widening, and unsupported on Windows.
* **Q11. Evidence freshness for `verified_server_principals`:** 90 days, after which scope reports
  `unknown` until `enroll verify`. **Recommended:** 90 days, as a proposal. *Why:* a server's
  configuration can change silently. Re-verification is cheap and makes no remote mutation.
* **Q12. Time-bounded remote obligations** (D7 item 3). B1's revocation residual clears itself at
  `valid_before` on safe time, with no adapter rounds and no attempt cap. **Recommended:** yes. It
  changes M01's obligation semantics only by adding a kind; `needs_remote_action` obligations keep
  ADR-0006 §13.12–§13.19 unchanged.
* **Q13. Synchronized-time trust stays off in M03** (D12 item 5). After a reboot, managed issuance waits
  for an attended `time confirm`. **Recommended:** yes, until M04/G09 native evidence of how each signal
  fails.
* **Q14. The claim table is the only source of platform `verified` capability values** (D12 item 3). It
  is static, validated by `check.sh`, and populated only after a verified native record.
  **Recommended:** yes.
* **Q15. One materialized managed binding per pair per environment** (D10). Ordinary aliases and `run`
  use it. A second binding is served only through `connect` and per-binding endpoints until G05/M05.
  **Recommended:** yes. *Why:* `IdentityAgent` in P cannot be redirected per process (M-F3), and the
  alternatives (`-F` shims, `${VAR}` paths) are worse.
* **Q16. Restore of K_ca after loss** requires `--not-stolen`. A key-only restore reports every residual
  of that CA `unbounded_unknown` and recommends rotation (D4 item 4). **Recommended:** yes (ADR-0005
  §5.3).
* **Q17. Client-executed enrollment steps** (D5 §6.3). The existing-access `ssh` of each remote step
  runs in the owner's CLI process. The runtime journals each step before handing it out, and it
  classifies the reported result. **Recommended:** yes.
  * *Why:* password, passphrase and touch prompts need the owner's terminal, which the background
    runtime lacks, and relaying them would carry secrets over IPC. The security claim rests only on the
    runtime's own verification.
  * *Alternatives:* restrict enrollment to existing access that needs no terminal, which excludes
    password-only accounts, a primary capability-2 case (spec §7.2, §7.4); or an askpass relay, which
    carries secrets over IPC.

---

### 17.1 Orchestrator rulings on the recommended answers and design review round 1 (2026-11-06)

Under the owner's delegation (ADR-0004). Sources:
- reviewer A (Codex GPT-6.1 Sol): `tests/evidence/artifacts/review-m03-design/round1-a-codex.md`, findings M03-R01–R15;
- reviewer B (Opus 5.5): `round1-b-opus.md`, findings F01–F27.

Both say "proceed after fixes". Every finding below is accepted, and the design fix (revision 2) applies each one. Where the reviewers proposed different fixes, the ruling chooses one.

**Recommended answers.** Q1–Q5, Q8–Q10, Q13, Q15 and Q16 are accepted as recommended, with the amendments below. Q6, Q7, Q11, Q12, Q14 and Q17 are amended as follows:

- **Q6:** per item 5.
- **Q7:** only for the same approved target and effect, with safe elapsed time and the item 6 fencing.
- **Q11:** 90 days at most. The verification becomes invalid earlier on a change of destination, account, host key, CA or client, or on contrary evidence. The supervisor re-verifies before the window lapses (F27); re-verification uses the managed credential and changes nothing remotely.
- **Q12:** replaced by item 10.
- **Q14:** per item 13.
- **Q17:** per item 14.

The plan-level questions are accepted with amendments:

- **P1 and P2:** accepted, conditional on item 12.
- **P3:** accepted. Linux evidence stays blocked until measured.
- **P4:** authorized. The download is pinned by digest into scratch, and the cleanup is exact.
- **P5 and P6:** accepted.
- **P7:** accepted with F25: `remote_stdout_max` is 512 KiB. Every limit is derived with its serialization overhead.
- **P8 and P9:** accepted. Round 2 re-reviews the fixed design.

1. **One linearization point for signing and revocation (R01, F12; blocker).** Every grant has a signing gate.
   - **Sign request:** it holds the gate shared from a fresh authorization read, through the signature, to the moment the response bytes enter the connection's outbound buffer. That enqueue is the linearized effect.
   - **Revocation, cutoff and every authority change that narrows a grant:** each takes the gate exclusively before its tombstone or record commit. It holds the gate until the keys are destroyed.
   - **Bound:** signing is bounded (P7), so a narrowing waits at most that bound. An in-flight signature either is enqueued before the commit, or is refused.
   - **Tests:** a deterministic test pauses a signer right after authorization, revokes, resumes, and asserts the refusal. A second test asserts that no signature is enqueued after the revocation is acknowledged. Uncontrolled interleavings are added on top, never instead.
   - **Scope:** re-issue racing revocation and a lock is in the linearization model too (F24).
2. **Remote steps are bound to the approved target (R02; blocker).**
   - **Approval:** the decision covers the destination's approved route, as Heimdall's evaluator determines it: HostName, Port, User and the proxy chain. It also covers the approved host key.
   - **Each step:** before it is dispatched, the route is evaluated again, and any difference refuses the step (`route_changed`, a decision needed). The step pins `HostName`, `Port` and `User` with `-o`. It sets `HostKeyAlias` and `UserKnownHostsFile` to a Heimdall-written file that holds exactly the approved key, with `StrictHostKeyChecking=yes`.
   - **Account overrides:** an override that differs from the catalog account is refused.
   - **Disclosures:** the configuration-execution disclosures (ADR-0007 D5) stay, and are reported separately from target identity.
   - **Test context:** ADR-0007 §9 item 1 is about tests isolating the configuration under test. A product step pinning its approved target is a different matter, and is not affected.
3. **The negative verification proves refusal by the pinned server (R03, F01; blocker).** It passes only when the same run shows all of the following:
   - the server version line;
   - the approved host key matched;
   - the negative certificate offered and not accepted, in the `-v` trace;
   - a publickey authentication failure at the end.

   Anything else is `verification_inconclusive`: transport errors, host-trust errors, startup errors, `MaxStartups` and resets. Tests stop sshd, close the port, and hit `MaxStartups` between the positive and negative attempts and during the negative one. Each must end inconclusive, never verified.
4. **Maintenance uses an explicit existing-access invocation (R04).** Rotation, removal, rollback and reconcile run with the catalog's existing-access identity pinned on the command line, plus the item 2 pins:
   - `IdentityAgent` or `IdentityFile`, and `IdentitiesOnly=yes`;
   - `CertificateFile=none`;
   - `ControlMaster=no` and `ControlPath=none`.

   This invocation is shown in the preview and covered by the decision. Tests rotate and remove with every managed binding released and the issuer unavailable.
5. **Re-verification never removes anything (R05, F06b).** The first verification's rollback stays under the enrollment decision. A later re-verification behaves as follows:
   - **unreachable or inconclusive:** the record stays `verified` with its existing freshness, and a doctor finding is reported;
   - **failure:** the record goes to `held` (`principals_not_enforced`). Grants under that CA for that pair are degraded. Removal needs its own `RemoveEnrollment` decision.
6. **Remote mutations are fenced (R06).**
   - **Lock:** each remote mutation takes an atomic per-account lock beside the registry, with the step's token. The marker check, the mutation, the read-back and the release all happen under it.
   - **Busy:** a script that cannot take the lock reports `busy` and changes nothing.
   - **Stale lock:** a stale lock is broken only by reconcile, after the old step's hard deadline, by an atomic rename aside and a re-read.
   - **Locally:** each enrollment has one outstanding step at a time.
   - **After a timeout:** a read that finds the marker absent never, by itself, authorizes a redispatch.
   - **Test:** a first script survives its timeout and resumes after reconcile. It must not produce a duplicate or a lost line.
7. **The enrollment state table is reconciled before it is frozen (R07, F06).**
   - add `verifying → held` and `outcome_unknown → withdrawn`;
   - `remove_unknown` keeps the removal's purpose: explicit removal versus a failed enrollment's rollback;
   - add `→ abandoned` from `outcome_unknown`, `remove_unknown` and `rollback_pending`;
   - give the system form its own path and decision (item 11);
   - CA retirement requires every enrollment of that CA to be final or abandoned;
   - every documented recovery path gets a test, not only every pair in the table.
8. **Windows connection control (R08, F02).**
   - **Process ownership:** the binding's holder and the controlled connection process are separate records. On Windows, a managed launch puts the child in a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. It records the child's PID and creation time durably as the owned connection, before strict control is advertised; registration failure fails closed.
   - **Earlier "no job object" note:** the design fix checks the rationale for the M02 "no job object" note (`launch/windows.rs:5`, ADR-0007 §8). If it conflicts, it escalates rather than overriding.
   - **`connect`:** its ensure/bind/ownership flow is designed explicitly.
   - **Native test:** revoking makes the exact `ssh.exe` PID exit, and the launcher's death with ssh still alive is tested too.
9. **Lock events latch (R09).** The lock source carries a monotonic lock epoch and a latched "lock observed" flag. The flag clears only when the revocation pass acknowledges that epoch. The current state is carried separately. A test locks and unlocks while the consumer is paused.
10. **Remote residuals after expiry (R10; replaces Q12).** Nominal certificate expiry is accounted for automatically, at local safe time. Bounded remote completion is a separate thing. The verification step measures the destination's clock, records the offset, the round trip and the time, and the obligation clears at `valid_before` plus that offset, the round trip and a drift allowance of 100 ppm of the age.

    Without a measurement, the residual is reported as `nominally_expired` with `destination_clock: unmeasured`. It never shows as cleared. It blocks nothing else. A slow-server-clock case is tested.
11. **Ceremonies, retirement, foreign removal, uninstall (R11, R12, F07, F08).**
    - **Ceremony:** it prepares the exact encrypted backup bytes before their digest is registered. It then writes and verifies those bytes exclusively.
    - **Retirement:** it is a durable transition. Issuance is disabled first, then the key is unloaded, then deleted. Restart completes it idempotently, and a failure between any two steps is tested.
    - **Foreign removal:** the target carries the full public removal descriptor: local alias, bundle destination ID, account, marker, CA public key, `line_sha256` and registry path and form. The decision and the request hash cover it. The line is rebuilt and hash-checked before connecting. Foreign removals live in their own table, with no foreign key to `issuers`. A redacted bundle is refused clearly. A test runs from a second installation with a different catalog.
    - **System form:** it gets a separate manual removal and re-verification workflow, and is never reported as removed automatically.
    - **Uninstall:** a purge that keeps remote enrollments needs a fresh bundle first. The fate of the K_ca store item is specified. `--replace-orphan` warns and cross-checks a bundle, and offers restore (`restored_without_log`).
12. **The dependency graph and the preparation contract (R13).**
    - **Crate graph:** the design fix draws the production crate graph and checks it against the Cargo manifests. Shared pure enrollment types go below `app`, or are injected through ports; no cycle is allowed.
    - **Preparation contract:** the M02 preparation contract (`ports.rs:185`, `:298`) is extended explicitly. Its inputs gain what U6 needs. A managed effect driver is defined for reserve/publish and materialization. M02's contract is not weakened silently.
    - **New pieces with owners:** raw host-key support (known-host observations keep fingerprints today) and a read-only issuance check.
    - **Time assessment:** a read-only time assessment that does not write the high-water mark (F21), tested on `open_read_only`.
    - **Interface ownership:** the `SecretStore` trait is U0's (F23). `StoreKind::ScratchTest` stays out of the public schema.
13. **Claims and capability reports (F03, F10, F11; Q14).**
    - **Claim content:** a claim records the build profile and the store kind, and test-store evidence never satisfies a product-store claim. macOS lock continuity stays `not_verified` until a release-profile run on the login keychain (B3).
    - **Remote revocation:** `revocation.remote` is gated exactly like `enforcement.revocation`, so it reads `unknown` until a claim exists.
    - **`verified_server_principals`:** it may come from the pair's own runtime verification. That is per-pair runtime evidence, labelled with its time, and amends ADR-0005 §7.4 row 1.
    - **The A10 worker test:** it is renamed to what it checks. Each platform records what a same-user worker can actually do, with a positive control. `issuer_isolation: same_user_process` stays.
14. **Existing access that cannot enroll in M03 (F13; Q17).** The catalog's existing access stays agent-held or key-file. A password-only account cannot enroll in M03; this is disclosed (`existing_access_kind_unsupported`) and handed to a later milestone if the spec requires it.
    - Q17's mechanism stands for provider interaction, passphrase prompts and hardware keys, and the test is renamed.
    - `Enrollment::{Step, StepResult, Reconcile}` need the owner role, and a re-append needs an attended session (F20).
15. **Behaviour while the projection is pending, and rotation (F04, F05).**
    - **Pending projection:** `ensure` resolves to the existing mechanism, says so and advises `setup_apply`. Only a request that requires managed capabilities fails with `projection_pending`.
    - **E5:** the preference and the projection are touched only when the pair is not already managed and applied.
    - **Removal:** only grants under the removed CA are degraded, and only when no verified enrollment remains for the pair. The preference records a set of issuing CAs. Early removal is allowed, with the preview's warning.
    - **Test:** `rotation_keeps_ensure_working_per_account`.
16. **Owned masters (R15, F16).** Each pair slot gets a stable, generation-protected multiplex path inside the approved projection. Enabling masters is widening and needs an apply. Restart, replacement and cleanup are defined. A test runs two successive bindings through ordinary ssh.
17. **Evidence and the lock procedure (F09, F14, F26, R14, F22).**
    - **Disjoint pairs:** each grant in the lock procedure has its own pairs.
    - **Which grant authenticated:** confirmed by the certificate key ID in the sshd log.
    - **Post-unlock checks:** they depend on the remaining deadline.
    - **Background work:** "allow background work once" is scoped to one boot. The attended time confirmation after a reboot is counted as a chore and shown in the TUI. Reboot and logout rows stay blocked on B12.
    - **Lowest-row rule:** the exit mapping states which records are `blocked` under it (A03 and A09 at least) and what that makes M03's exit status.
    - **Backup interop test:** it drives `ssh-keygen` through a PTY, so the passphrase is never in argv.
    - **ptrace test:** `PR_SET_DUMPABLE` gets a dumpable positive control.
18. **Minor rulings (F15, F17–F19, F25).**
    - **F15:** revoke results list the owned connections, each with a `closing` state, and say that ordinary-ssh connections through P are not closed. The deadline wording depends on exclusive identity selection.
    - **F17:** the purpose check uses the account of the pair named by the presented certificate, and refuses the plain K_env key.
    - **F18:** a `pending` credential instance is marked `destroyed` at start, and its reservations stay counted.
    - **F19:** the lock disclosure is conditional, and states R-UX-03's saved limits. Linux `revoke_on_lock` is labelled unverified until B11.
    - **F25:** `StepResult.stdout` is at most 512 KiB.

### 17.2 ⟨r2⟩ Questions raised by revision 2 (rulings kept; evidence and options)

Each question below concerns a §17.1 ruling that could not be applied exactly as written, or that
conflicts with an earlier ADR. In each case the ruling is kept in the D sections. Units build against
the recommended answer, behind one switch the integrator can flip.

⟨r3⟩ All four are ruled in §17.3, each with its default accepted. The text is kept for the record, and
the D sections now state the rulings.

* **Q18. Which launches get the kill-on-close job object** (§17.1 item 8; D8 item 2)?
  * **The check the ruling asked for.** M02's "no job object" note (`crates/launch/src/windows.rs`
    module doc: "No job object") rests on ADR-0007 §8, which says "kill-on-close would kill
    grandchildren the tool left running on purpose after a normal exit, which `exec` on Unix would not
    do". ADR-0007 §11 lists "Windows job object with kill-on-close for `run`" as rejected for the same
    reason (M-F21).
  * **The conflict.** §17.1 item 8 says "a managed launch puts the child in a job object". For a
    launch whose program is the verified `ssh` (an owned connection), there is no conflict with
    ADR-0007's purpose: killing ssh's own helper processes at exit is a narrow, disclosable residual,
    and ending the connection is the ruling's goal. For `run` of any **other** program on a managed
    binding (a shell, `git`, an agent CLI), the ADR-0007 rationale applies in full, and D8 does not own
    those children anyway.
  * **Options:**
    * (a) the job object only for owned-connection launches; ADR-0007 §8 amended for those alone.
      **Recommended**;
    * (b) the job object for every launch on a managed binding, amending ADR-0007 §8 and §11 for all
      managed `run`, with the background-child breakage disclosed;
    * (c) no job object, with Windows strict and revocation closing only the registered `ssh.exe` PID.
      This does not meet the ruling's "launcher death" goal.
  * **Default until ruled:** (a), behind `launch_uses_kill_on_close_job(binding, program)`.
* **Q19. `CertificateFile=none` in the maintenance invocation** (§17.1 item 4; D5 §6.3).
  * **Evidence.** The pinned ssh_config(5) (`docs/sources/snapshots/S01.txt.gz`) documents `none` for
    `IdentityFile` only. For `CertificateFile` it says "Multiple CertificateFile directives will add to
    the list of certificates used for authentication" (M-F20). So `-o CertificateFile=none` is not
    documented to remove P's slot certificate. A client may read `none` as a file name (missing, with
    a warning) or refuse it.
  * **What does hold.** The pinned `IdentityAgent` (read first, so it wins) sends every signature to
    the existing agent, which never holds K_env. So the managed certificate cannot authenticate the
    step, whatever `CertificateFile` does. U5's `maintenance_invocation_never_contacts_heimdall_signer`
    (signature count 0 on every Heimdall endpoint) shows it.
  * **Options:**
    * (a) keep `-o CertificateFile=none` as written, record each client's behaviour
      (`certificate_file_none_behaviour_recorded_per_client`), and rest the guarantee on the
      `IdentityAgent` pin and that test. **Recommended**;
    * (b) drop the option where a client refuses it, and keep (a) elsewhere;
    * (c) run maintenance with a generated `-F` configuration, as verification does. That drops the
      user's configuration entirely; it is possible in M03 because routes are direct and pinned.
  * **Default until ruled:** (a). If a target client refuses `none`, (b) applies to that client, and
    the integrator records it.
* **Q20. Removing one of two verified enrollments of a pair** (§17.1 item 15; D5 §6.8; D4 item 3).
  * **The ruling:** "Only grants under the removed CA are degraded, and only when no verified
    enrollment remains for the pair."
  * **The conflict.** A grant's certificate for the pair was signed by one CA. Once that CA's line is
    removed, the server refuses that certificate, whether or not a newer verified enrollment exists. The
    grant gets no replacement certificate, because ADR-0005 §3.5 "re-issues only after a K_env is lost
    (signer restart) or for a delegated child". Applied literally, the ruling would leave such a grant
    `active` for a pair on which it can no longer authenticate. That is a false report (spec §4.3,
    R-AU-08).
  * **Options:**
    * (a) degrade every grant whose pair certificate is under the removed CA, whatever other
      enrollments remain. The "only when no verified enrollment remains" clause then governs only the
      **preference** (the pair stays `managed_certificate` while another verified CA remains), and new
      grants use the remaining CA. **Recommended:** honest and consistent with ADR-0005 §3.5;
    * (b) re-issue the pair's certificate under the remaining verified CA within the grant: a new
      reservation with the same bounds and the same D. This amends ADR-0005 §3.5's re-issue list;
    * (c) apply the clause literally, with the preview warning naming the grants that lose the pair.
  * **Default until ruled:** (a). The removal preview names the affected grants in every option.
* **Q21. The pause point of the signing-gate test** (§17.1 item 1; D2 item 3a).
  * **The conflict.** The ruling's deterministic test "pauses a signer right after authorization,
    revokes, resumes, and asserts the refusal". The same ruling has the signer hold the gate from its
    **fresh** authorization read onward. A signer paused right after that read holds the gate. The
    revocation then waits, and the signature completes and is enqueued **before** the commit, which is
    a correct order under the ruling's own definition, but not a refusal.
  * **Options:**
    * (a) the design's two-phase signer: a pre-check authorization **outside** the gate (the test's
      pause point, after which the revocation commits and the fresh read under the gate refuses), plus
      a second test that pauses inside the gate and asserts enqueue-before-commit. **Recommended**;
    * (b) a single authorization inside the gate. The ruling's test is then rewritten to assert that
      the revocation waits and the signature precedes the commit.
  * **Default until ruled:** (a).

---

### 17.3 Orchestrator rulings on revision 2's questions (2026-11-06)

1. **Q18:** the default is accepted. The kill-on-close job object applies only to launches whose program is the verified `ssh`, the connections Heimdall owns. `run` of any other program keeps M02's semantics (ADR-0007 §8 and §11) and reports `not_controlled`. ADR-0007 §8 is amended for owned ssh launches only, and the narrow residual is disclosed.
2. **Q19:** the default is accepted. `-o CertificateFile=none` stays. The guarantee rests on the pinned `IdentityAgent` and on `maintenance_invocation_never_contacts_heimdall_signer`, and each client's actual behaviour is recorded as an observation.
3. **Q20:** the default is accepted. Removing a CA degrades every grant whose certificate is under it. The "no verified enrollment remains" clause governs only the pair's preference.
4. **Q21:** the default is accepted, with two tests:
   - one pauses after the early pre-check, outside the gate, and must be refused;
   - one pauses inside the gate, and its signature must be sent before the commit.
5. **Decisions revision 2 asked to confirm, all accepted:**
   - the existing-access pins also apply to the initial append, so one invocation is shown and approved;
   - `GlobalKnownHostsFile` is pinned with the target;
   - a Windows lock-continuity claim can be earned by a release build on DPAPI with `HEIMDALL_HOME` in scratch. The claim records the product store (`dpapi`) and the release profile.
6. **The exit status under the lowest-row rule.** M03 may exit as M01 did. Every record must be `verified`, except rows blocked only on named owner inputs, which stay `blocked` with `blocked_on`. The exit record lists each such row, and no claim is widened to cover it.

### 17.4 Orchestrator rulings on design review round 2 (2026-11-06)

Sources:
- reviewer A (Codex Sol): `review-m03-design/round2-a-codex.md`, R2-01–R2-09, verdict "another design round";
- reviewer B (Opus): `round2-b-opus.md`, M03-R2-01–R2-18, verdict "ready after fixes".

Below, "A" refers to reviewer A's IDs and "B" to reviewer B's. Every finding is accepted, and revision 3 applies each one. Only the fixed findings are re-checked afterwards.

1. **The approved host key is the only trust source (A R2-01; blocker).** Every remote step pins:
   - `KnownHostsCommand=none`, `VerifyHostKeyDNS=no`, `UpdateHostKeys=no` and `CheckHostIP=no`;
   - `HostKeyAlgorithms`, limited to the approved key's algorithm;
   - `GlobalKnownHostsFile`, set to an empty Heimdall file;
   - `UserKnownHostsFile` (the approved key only), `HostKeyAlias` and `StrictHostKeyChecking=yes`.

   The design lists every ssh option that can affect host trust, and states why each pin covers it. A wrong-key fixture with an inherited `KnownHostsCommand` (and, separately, an inherited known-hosts file) must be refused before any remote mutation.
2. **Fencing is proven termination, never a lock taken away from a live writer (A R2-02 blocker; B R2-04, R2-10, R2-11).**
   - **Lock records the holder:** the lock records the holding shell's PID and its start identity (`ps -o lstart= -p $$`, or the platform equivalent named per target shell).
   - **Breaking a lock:** a lock is broken only after the holder is proven gone: the PID is absent, or present with a different start identity. Age alone is never enough.
   - **Terminating the holder:** after the step's not-after, reconcile may stop the exact holder (TERM, then KILL, which also ends a stopped process). It proves the holder is gone, then breaks the lock. If it cannot prove that, the step stays `busy` or uncertain. After a bounded number of attempts this needs manual recovery, and is never redispatched.
   - **Other enrollments' locks:** a lock that carries another enrollment's token is `busy` for every other enrollment.
   - **Not-after:** each mutating script carries an absolute remote not-after (B R2-04), and checks it when taking the lock and immediately before the write.
   - **Holder alive past its not-after:** it can still be paused between that check and the write. The termination rule above, not the clock check, is what fences it.
   - **Local process lifetime:**
     - `SshStepRunner` ties ssh's lifetime to the CLI: a process group plus a parent-death signal where available, and a job object on Windows.
     - A record that leaves an uncertain append for `withdrawn` or `abandoned` keeps a "possible late write" residual until an inspect after the not-after shows absence.
   - **Script hardening:**
     - each script is wrapped in a function called on its last line, so a truncated script does nothing (B R2-10);
     - each script runs `export LC_ALL=C` (B R2-14).
   - **Deadlines across a reboot (B R2-11):** they persist wall time and boot ID, and after a reboot they pass on safe wall time.
   - **Test:** a writer paused just before its write must pass the no-duplicate, no-loss test.
3. **Bootstrapping the registry directory (A R2-03).**
   - When the registry's directory is absent, a journaled bootstrap step creates it first: mode 0700, owner checked, no reparse point or symlink.
   - That step is shown in the approved plan, and the lock is taken afterwards.
   - A missing parent has its own exit code, distinct from `busy`.
4. **Maintenance uses a concrete existing-access endpoint (A R2-04).**
   - The endpoint (agent socket or pipe path, or key file) is resolved from the catalog identity record, never from the current process's `SSH_AUTH_SOCK`.
   - It is shown and approved.
   - It is refused if it is, or resolves to, any Heimdall managed endpoint (runtime directory prefix plus the signer's endpoint registry).
   - A test runs maintenance from inside a managed `run` context and asserts zero managed signatures.
5. **Enrollment state recovery (A R2-05; B R2-05, R2-06).**
   - **Cancelling manual removal:** it returns to the state and evidence the removal began from, which are persisted.
   - **System trust:** once the owner may have installed system trust, the inventory entry stays (uncertain, held or abandoned) until absence is verified.
   - **Leaving `held`:**
     - an evidence-based hold can move to `reverifying`, driven by the owner;
     - a host-key change needs a decision that re-approves the target, with the new key shown as a diff;
     - alternatively, a `RemoveEnrollment` that carries a freshly evaluated target.
   - **Re-enrollment:** `abandoned` is outside the uniqueness rule. Re-enrollment uses a new marker, and the old residual stays listed.
   - **Retrying the initial verification:** it runs under the still-open `enrollment.apply`, through reconcile. Once that approval has lapsed, a failure goes to `held`, and removal needs `RemoveEnrollment`.
   - **Tests:** every path above is in `enrollment_recovery_paths_each_tested`.
6. **The signing gate, completed (A R2-06; B R2-01, R2-03).**
   - **Permit expiry:** the permit carries an absolute expiry: the earliest of the wall deadline, the continuous budget and the admission limits. Release is refused at enqueue once the expiry, or the safe-time predicate, fails.
   - **Signing bound:** `KeyVault::sign` runs under a budget. Overrunning it expires the permit, so nothing is released.
   - **Wave 0:** the gate bodies are written by U0b phase 1, and U10 only wires them.
   - **Lock order:** gates are acquired ancestor-first, then by grant ID. Creating a delegation holds the parent's gate shared until the child's first install, and the revoker re-reads the descendants after taking the gates, until the set is stable.
   - **Order within a narrowing:** keys are destroyed and identities unlisted while the gate is held. Processes are closed after it is released.
   - **No gate, no narrowing:** a narrowing never proceeds without its gates. Bounded holders bound its wait.
   - **Deterministic tests:**
     - a request crossing D after the fresh read, with no edit to state;
     - delegation during revocation;
     - two concurrent cascades.
7. **Connections Heimdall owns stay in the foreground (A R2-07).**
   - Product-generated invocations pin `ForkAfterAuthentication=no`.
   - `run ssh` with `-f` (or a conflicting option) is refused for an owned connection.
   - Tests cover inherited configuration and an explicit `-f`.
8. **Ordering registration against revocation (A R2-08; B R2-12).**
   - **Windows:** the child is registered while still suspended, under the gate or a transaction ordered with grant ending. Registration for an ended or unsafe grant is refused. A revocation that falls between registration and resume kills the child, through the job object.
   - **Unix:** the owned-connection row is written at bind, with the expected image, and the image is verified before any signal.
   - **Tests:** pauses on both sides of registration and resume.
9. **Interfaces and the crate graph (A R2-09; B R2-02, R2-17).**
   - **Verification lifecycle:** each operation's verification key gets its full lifecycle through a factory/effect port: create, register the public key, install the certificate, and clean up on drop.
   - **Permit guard:** `ipc` defines an opaque permit guard, which `app` fills.
   - **Enrollment plan:** its preconditions and digest move into `heimdall-registry` (or `domain`), and `enroll` keeps only I/O.
   - **The `crate-graph` check:** it resolves package names, and includes optional and target-specific dependencies. Its mutant fixtures are a cycle and an `ipc → app` edge.
   - **U9:** it gets one port signature, the operations bodies go to U0b, and the wave is fixed.
10. **Foreign removal (B R2-07).**
    - It reuses the removal sub-machine and the §6.7 reconcile, keyed by marker.
    - It requires exact equality of the evaluated HostName and Port, otherwise it fails with `bundle_host_mismatch`.
    - The bundle carries a canonical `registry {path, resolved_by}`.
    - A lost-reply test is added.
11. **Verification evidence (B R2-08, R2-09, R2-13).**
    - **`principals_not_enforced` fixture:** an account-form line that lists both principals, written at a pause hook once the nonce is known. The system form uses an echoing `AuthorizedPrincipalsCommand`, and the bare line stays a separate `verification_failed` test.
    - **Trace patterns:** keyed by upstream release family (portable and Win32), each with its recorded version ranges.
    - **Re-verification:** a client or CA change that is not contrary evidence triggers a prompt re-verify. An unrecorded family gives a doctor finding that names it.
    - **Destination clock skew:** a skew beyond the validity allowance, known from E2's offset, is `verification_inconclusive` (`destination_clock_skew`), with no rollback.
12. **Minor rulings (B R2-15, R2-16, R2-18).**
    - **R2-15:** release builds refuse the M03 test variables with exit 2, and the test is renamed.
    - **R2-16:** the text is synced with §17.3, and every blocked record is listed: B3, B11 and B12 included.
    - **R2-18:** the enrollment result, the apply preview, the doctor and the TUI all disclose that ordinary `ssh <alias>` works only while a binding holds the slot (`slot_free`, with the command to fix it). Auto-activation stays M05.

### 17.5 ⟨r3⟩ Questions raised by revision 3 (rulings kept; evidence and options)

As in §17.2: each question concerns a §17.4 ruling that could not be applied exactly as written, or that
conflicts with an earlier ADR. The ruling is kept in the D sections, and units build against the
recommended default, behind one switch.

* **Q22. `KnownHostsCommand=none`** (§17.4 item 1; D5 §6.3).
  * **Evidence.** The pinned ssh_config(5) (`S01`) says the command supplies keys "in addition to those
    listed in UserKnownHostsFile and GlobalKnownHostsFile", and that "if the command exits abnormally or
    returns a non-zero exit status then the connection is terminated". It documents `none` for
    `UserKnownHostsFile`, `IdentityAgent`, `IdentityFile`, `ControlPath`, `ProxyCommand`, `ProxyJump`
    and `PKCS11Provider`, but **not** for `KnownHostsCommand` (M-F25).
  * **Why the review's run does not settle it.** Reviewer A's run shows only that the wrong-key case was
    refused (exit 255). A client that ran a command named `none` would refuse that case too. It would
    also run a program named `none`, if one were on `PATH`.
  * **Options:**
    * (a) keep `KnownHostsCommand=none` as ruled, and prove per client that it is a keyword.
      `known_hosts_command_none_is_a_keyword_per_client` connects with the **approved** key (exit 0)
      while `PATH` holds a fixture program named `none`, which would print a wrong key and records any
      invocation. The client passes only if that program never ran; a client that fails is refused for
      remote steps (`host_trust_unpinnable`). **Recommended**;
    * (b) pin `KnownHostsCommand=<absolute path of the running heimdall> internal known-hosts-empty`, a
      documented use (a command that prints nothing and exits 0), at the cost of one process per
      connection;
    * (c) both: (a) where the keyword is proven, (b) elsewhere.
  * **Default until ruled:** (a).
* **Q23. Host-trust options outside the pinned sources** (§17.4 item 1).
  * **Evidence.** The ruling asks for every ssh option that can affect host trust, and the pinned
    sources are upstream OpenSSH's pages.
    * Distribution builds (Debian, Ubuntu, Fedora) carry a GSSAPI key-exchange patch. Its
      `GSSAPIKeyExchange` lets Kerberos authenticate the server, so the host-key check can be bypassed
      [I].
    * The option appears nowhere in S01 or S02, and an upstream client rejects it as a bad option. So
      it cannot be pinned unconditionally.
  * **Options:**
    * (a) the effective-configuration check of D5 §6.3 also reads `gssapikeyexchange` when the
      client's `ssh -G` prints it. If it is present, the step adds `-o GSSAPIKeyExchange=no` (that
      client knows the option), and the check requires `no`. If it is absent, nothing is added.
      **Recommended**;
    * (b) refuse remote steps on any client whose `ssh -G` prints an option this design does not know;
    * (c) leave vendor options out of scope, disclosed.
  * **Default until ruled:** (a).
* **Q24. The existing-access endpoint when the catalog record names none** (§17.4 item 4).
  * **Evidence.** M02's catalog (`crates/domain/src/catalog.rs`, `IdentitySource`) records:
    * an endpoint for `native_agent`;
    * an optional one for `onepassword`, present "when not the documented default";
    * only a `.pub` path for `public_key_file`, whose private key "is used through an agent" (ADR-0007
      F9).

    M02 recognizes 1Password only through configured `IdentityAgent` references
    (`localenv/src/agents.rs`). So for those two kinds, "resolved from the catalog identity record"
    yields no endpoint.
  * **Options:**
    * (a) take the alias's own `IdentityAgent`, statically evaluated from the user's configuration with
      P's managed block excluded. When it is unset, `none` or undetermined, refuse with
      `existing_access_endpoint_unrecorded`, and ask the owner to record the endpoint on the identity.
      Never `SSH_AUTH_SOCK`. **Recommended**;
    * (b) as (a), but fall back to the runtime's start-time environment snapshot of `SSH_AUTH_SOCK`,
      when that is not a Heimdall endpoint;
    * (c) refuse enrollment for every identity whose record names no endpoint.
  * **Default until ruled:** (a).
* **Q25. Re-enrolling an abandoned pair can leave two lines of the same CA** (§17.4 item 5).
  * **Evidence.** The ruling puts `abandoned` outside the uniqueness rule, with a new marker. An
    abandoned line usually stays on the account. So after a re-enrollment under the same CA, the account
    holds two Heimdall lines, while ADR-0005 §3.3 says "each enrolled account gets one line".
  * **Options:**
    * (a) allow it. The new enrollment's E2 `inspect` reports the abandoned marker's line, the result's
      `next` offers `enroll remove <abandoned>`, and both lines are listed until then. Both trust only
      the same principal under the same CA, so no access widens. **Recommended**;
    * (b) the re-enrollment's approved plan also removes the abandoned line, in the same operation and
      under the same decision;
    * (c) refuse re-enrollment while the abandoned line is observed (`abandoned_line_present`).
  * **Default until ruled:** (a).

---

### 17.6 Orchestrator rulings on revision 3's questions (2026-11-06)

1. **Q22:** the default is accepted. `KnownHostsCommand=none` stays. Each recorded client family proves that a fixture program named `none` on `PATH` never runs, and a client that fails that proof is refused for remote steps.
2. **Q23:** the default is accepted. `GSSAPIKeyExchange=no` is pinned wherever the client's `ssh -G` lists the option. Upstream clients that reject the option are recorded as not having it.
3. **Q24:** the default is accepted. When the catalog records no agent endpoint, the agent is the alias's own `IdentityAgent`, evaluated with P's managed block excluded. It is refused if it resolves to a Heimdall-managed endpoint, or to nothing usable. It is never taken from `SSH_AUTH_SOCK`.
4. **Q25:** the default is accepted. Re-enrolling an abandoned pair is allowed. The preview reports the old line under the same CA and offers its removal, and the old line stays listed as a residual until removed. This amends ADR-0005 §3.3 ("one line") for the abandoned case only.
5. **Revision 3's design choices, all accepted:**
   - the atomic `ln -s` lock that encodes its holder;
   - the `HM1 ready` handshake;
   - the "gone" test applied to the holder's whole process group, with no enrollment ever breaking another's lock;
   - the `run ssh` argument insertion and refusals;
   - the `ApproveTargetChange` decision;
   - the `NoHostAuthenticationForLocalhost=no` pin.

   The windows revision 3 discloses as residuals stay disclosed: PID reuse within 1 s on BSD/macOS, process-group reuse between check and signal, and lock atomicity on network file systems. Each is reported, and none is claimed closed.

### 17.7 Orchestrator rulings on the round-3 re-check (2026-11-06)

Source: `tests/evidence/artifacts/review-m03-design/round3-recheck-codex.md`. Every finding is accepted, and revision 4 applies each one. Afterwards only these findings are re-checked, with the fencing probes run again on each target shell.

1. **R3-01, blocker: a gone group must be proven by agreement, never inferred from a failure.**
   - **The probe itself:** the group probe uses the POSIX form `kill -s 0 -- -PGID`.
   - **A control:** before the target is probed, the same command runs against the probing shell's own group (`kill -s 0 -- -$$`), which must exit 0.
   - **When the target counts as gone:** only when the control succeeds, the target probe fails, **and** `ps -A -o pgid=` lists no process with that group ID. Two independent methods must agree.
   - **Unproven:** a syntax error, a permission failure, any disagreement between the two methods, or any unrecognized result means `unproven`, never gone.
   - **Tests:** the leader-absent case with a live mutation child is a required fencing test, run on every target shell (dash, bash as `sh`, BusyBox ash, and the macOS/BSD `sh`).
2. **R3-02: expiry is checked at the moment of release.**
   - **Capacity first:** outbound capacity for the complete frame is reserved first. Expiry cancels the wait for capacity.
   - **Then the check:** `may_release()` runs immediately before an enqueue that cannot wait. That enqueue is the linearized effect.
   - **Test:** a deterministic test crosses the deadline after the release check, while the enqueue is blocked, and asserts nothing is released.
3. **R3-03: gates are always held in global order.**
   - When re-reading the descendants grows the set, the narrowing releases every gate and reacquires the whole set in global order, then re-validates.
   - Delegation needs the parent's gate held shared, so once the root is held exclusively the set cannot grow again. One reacquisition round therefore suffices, and the design states this.
   - The overall wait bound is `(rounds + 1) × signing_gate_max_wait`.
   - **Test:** the H/L interleaving from the re-check.
4. **R3-04: foreign removal in the frozen state table.**
   - **Admission:** `RemoveEnrollment` on a foreign record (`planned → removing`) is part of the frozen transition contract and its golden.
   - **System form:** foreign records in the system form use the §6.9 manual removal states.
   - **Before freezing:** approval, denial, a lost reply, held recovery and the system-form route are each tested.
5. **R3-05: the proposed target belongs to the verification operation.**
   - The verification operation carries the proposed target, and that attempt's pins come from it.
   - The approved target is replaced atomically only on a verification pass.
   - On failure or an inconclusive result, the approved target is unchanged and the record stays `held`. The table says so.

### 17.8 ⟨r4⟩ Questions raised by revision 4 (rulings kept; evidence and options)

As in §17.2 and §17.5: each question concerns a §17.7 ruling that could not be applied exactly as
written. The ruling is kept in the D sections, and units build against the recommended default, behind
one switch.

* **Q26. Which gates a delegation holds** (§17.7 item 3; D2 item 3a).
  * **Evidence.** The ruling's argument is: "Delegation needs the parent's gate held shared, so once
    the root is held exclusively the set cannot grow again." With revision 3's rule (the parent's gate
    only), that holds for the root's **direct** children only.
    * A delegation from a deeper member D needs only D's gate.
    * During the reacquisition round, the narrowing holds the root but not yet D, so D can still gain a
      child.
    * The round-1 re-validation would then find the set grown again, and one round would not suffice.
  * **Options:**
    * (a) a delegation holds the gates of the parent **and every ancestor**, shared, in global order
      (root first), until the child's first install. Holding a root then freezes its whole subtree,
      and the ruling's one-round argument holds at any depth. The cost is a few more shared
      acquisitions per delegation, bounded by the ancestor-chain limit M01 already enforces.
      **Recommended**;
    * (b) keep the parent-only rule, and allow up to "depth" reacquisition rounds, with the bound
      scaled to match;
    * (c) acquire incrementally: right after a member's gate is held, read its children. They are
      deeper, so they sort after every gate held, and no release is ever needed. This departs from the
      ruling's release-and-reacquire.
  * **Default until ruled:** (a). D2 item 3a is written to it.
* **Q27. The constant in the wait bound** (§17.7 item 3).
  * **Evidence.** The ruling sets the overall wait bound at `(rounds + 1) × signing_gate_max_wait`.
    For that to hold, two things must be true:
    * one round's wait is at most `signing_gate_max_wait`. Gate holders include delegations, bounded
      by `delegation_gate_hold_max` (10 s), and revision 3 set `signing_gate_max_wait` to 5 s, the
      signer's bound. A delegation needs an issuer signature, whose timeout is 10 s, so its hold
      cannot be cut to 5 s;
    * no new holder starts during a round. With in-order acquisition, a signer can take a later gate
      shared while the narrowing still waits on an earlier one, so the per-round wait could approach
      "number of gates × holder bound".
  * **Options:**
    * (a) set `signing_gate_max_wait` to the longest holder bound, 10 s, so `narrowing_gate_wait_max`
      is 20 s. Add the in-memory **pending mark**: before waiting, the narrowing marks its set, and
      signers and delegations on marked grants refuse. **Recommended**;
    * (b) shorten delegation holds with a two-phase delegation: create the child record in one short
      transaction under the gates, and issue its certificate afterwards, guarded by the child's own
      gate and the ancestors' tombstone check. `signing_gate_max_wait` could then stay at 5 s (10 s
      overall);
    * (c) keep 5 s, and accept a bound that the formula does not cover.
  * **Default until ruled:** (a). §5 item 17 of the plan carries the values. In the worst case a
    revocation's commit now waits 20 s. Revisions 2 and 3 allowed 5 s and 10 s. A signer that meets a
    marked grant refuses at once.
* **Q28. The absence check of a foreign system-form removal** (§17.7 item 4; D4 item 5; D5 §6.9).
  * **Evidence.** The ruling sends foreign system-form records through the §6.9 manual removal states.
    §6.9's absence check needs a positive verification certificate signed by the removed CA, which is
    then refused. A foreign removal runs on a device that does not hold that CA's key: the CA is not
    registered there (D4 item 5, `foreign_removals` has no foreign key to `issuers`). So the check can
    never pass, and the record can never reach `removed`.
  * **Options:**
    * (a) apply the ruling literally. `removal_verifying` ends `verification_inconclusive`
      (`ca_not_held`) and returns to `manual_removal_pending`. The record is never reported removed,
      stays listed (`pending_until_line_removed`), and may be abandoned. **Recommended**;
    * (b) let the owner restore the CA's D5 backup on this device first (D4 item 4, `--not-stolen`), so
      the absence check can sign. The record then stops being foreign;
    * (c) a separate final state, `owner_reported_removed`, which is never reported as absence verified.
  * **Default until ruled:** (a).

---

### 17.9 Orchestrator rulings on revision 4's questions (2026-11-06)

1. **Q26: accepted as recommended.** A delegation holds the gates of its parent and of every ancestor, shared and in global order, until the child's first install. That makes the "the set cannot grow once the root is held exclusively" argument true, so one reacquisition round suffices.
2. **Q27: accepted as recommended.**
   - `signing_gate_max_wait` is 10 s, and the worst-case wait before a revocation commits is 20 s.
   - When a narrowing starts waiting, it sets an in-memory pending mark on the grants it covers. From then on, every new signature and every new delegation for those grants is refused at once, so revocation stops new signatures immediately at the request ("locally immediate"). Only the in-flight holders finish.
   - The revocation result reports the time it was requested and the time it was committed.
3. **Q28: accepted as recommended.** For a foreign removal in the system form, the absence check ends inconclusive (`ca_not_held`). Such a record is never reported as removed, and it can be abandoned with its residual listed.
4. **Residuals that stay disclosed, not closed:**
   - a group ID reused just after the group empties;
   - shell rows whose behaviour is only inferred from documentation. These are settled by the per-shell tests; a shell that fails them leaves the fence `unproven`, which means manual recovery. That is safe.
5. **Fixtures:** the bash-as-`sh` and BusyBox `ash` shell containers each get a MANIFEST row, built from pinned images by digest on the build host.

### 17.10 Orchestrator rulings on the round-4 re-check (2026-11-06)

**Source:** `tests/evidence/artifacts/review-m03-design/round4-recheck-codex.md`. The re-check found no blocker. Every finding is accepted, and revision 5 applies each one.

**Gate:** once revision 5 is in, the design gate closes after one last targeted check of R4-01 and R4-02 only.

1. **R4-01: pending admission is authoritative.**
   - **Where it is checked:** the pending check moves into the fresh authorization read, under the gate. It is repeated after any awaited gate acquisition, and again in the release check, so a request that passed only the early pre-check is refused.
   - **Coverage:** pending covers descendants through an ancestor-pending check. A grant is pending when it, or any ancestor, is marked.
   - **Round 1:** coverage is extended to newly discovered descendants before round 1 releases any gate.
   - **The bound:** it is re-derived from these rules and stated with its assumptions.
   - **Tests:** deterministic tests for both traces in the re-check.
2. **R4-02: foreign system-form removals keep their residual.**
   - **Abandoning:** `manual_removal_pending` for a foreign record gains an explicit `→ abandoned` event, which keeps `pending_until_line_removed`.
   - **Cancelling:** a cancel after `ca_not_held` returns to `manual_removal_pending`, or to the held foreign record, and never to `planned` or `withdrawn`. A residual that is known and unresolved is never discarded.
   - **Golden:** both paths go in `foreign_removal_paths_golden`.
3. **R4-03: revocation timestamps.**
   - **Where:** `RevokeData` gains `requested_at` and `committed_at` in the frozen contract and its golden.
   - **When each is taken:** `committed_at` is taken in the tombstone transaction, separately from any later cleanup.
   - **Replay:** a replay returns the original values.
4. **R4-04: exit 44 means "no unlock".** An unproven decision authorizes no further signal. Any termination signal already sent is kept in the result and in the audit record, so exit 44 is never read as "nothing was signalled".
5. **BusyBox `ash`:** its fence stays `unproven`, so recovery is manual. The shell table records the observed reason: `ps -p` is unsupported, and `kill` rejects `--`. Automatic recovery is never claimed for BusyBox.

### 17.11 ⟨r5⟩ Questions raised by revision 5 (rulings kept; evidence and options)

* **Q29. BusyBox's missing `ps -p` also stops the mutating scripts** (§17.10 item 5; D5 §6.3).
  * **Evidence.** The ruling records that BusyBox `ps` does not support `-p`, and keeps the fence there
    `unproven`, with manual recovery. But the same `ps -o pgid= -p $$` is the group-leader check that
    `append` and `remove` run before they take the lock (D5 §6.3 fence step 1), not only the fence's
    prerequisite.
    * The re-check observed that a literal script stops there with exit 33 (`no_process_group`).
    * As written, then, no append or removal could run on a BusyBox target at all. Enrollment there
      would fail `failed_unwritten`, which is more than "recovery is manual".
  * **Options:**
    * (a) on Linux, read the process group from field 5 of `/proc/$$/stat`, the same source as the start
      identity (⟨r6⟩ through the shared parser of D5 §6.3: token 3 after the last `)`, never a whitespace
      field count; §17.13 item 2). Every Linux shell then uses it, and `ps -o pgid= -p $$` remains for
      macOS and the BSDs. BusyBox targets can enroll and remove; only their fence stays `unproven` (its control
      fails, because `kill` rejects `--`), so recovery there is manual, as the ruling says.
      **Recommended**;
    * (b) keep `ps -o pgid= -p $$` everywhere, and disclose that BusyBox targets cannot run any remote
      mutation (`no_process_group`);
    * (c) as (a), and also look for a BusyBox-compatible group probe. That would contradict the
      ruling's "automatic recovery is never claimed for BusyBox", so it is listed only for completeness.
  * **Default until ruled:** (a). The shell table and the scripts are written to it.

---

### 17.12 Orchestrator rulings on revision 5's question (2026-11-06)

1. **Q29: accepted as recommended.**
   - **Process group on Linux:** the enrollment scripts read it from field 5 of `/proc/$$/stat`, the file that already gives the start identity.
   - **Process group on macOS and the BSDs:** the scripts keep using `ps -o pgid= -p $$`.
   - **BusyBox:** BusyBox targets enroll and remove normally. Only their fence stays `unproven`, because their `kill` rejects `--`, so stale-lock recovery there is manual (§17.10 item 5).
   - **Tests:** a BusyBox enrollment test and a BusyBox removal test, both in a disposable container.
2. **Revision 5's decisions that asked for confirmation, both accepted:**
   - **Cancelling before any absence check:** a foreign system-form record cancelled before any absence check may return to `planned`. From there it can reach `withdrawn`, because no unresolved residual is yet known. The bundle's entry is unaffected.
   - **`requested_at` and `committed_at`:** both are optional on the wire, so M01 and M02 documents still decode. M03 always fills them.

### 17.13 Orchestrator rulings on the round-5 check; the design gate (2026-11-06)

Source: `tests/evidence/artifacts/review-m03-design/round5-final-codex.md`. It found no blocker. R4-02, R4-03 and R4-04 are closed. R4-01's admission holes are closed, and a replay of the round-4 traces bears this out: the 24.6 s flood now commits at 9.6 s, and the early pre-check trace is refused.

1. **R5-01: the narrowing's commit time is a derived, reported bound, never an abort.**
   - **Safety:** the property that matters is that new signatures and delegations stop at the pending mark. That is unchanged. Every gate holder is individually bounded, so a narrowing waits until it holds its gates. It is never aborted for time. Its commit time is reported (`committed_at − requested_at`).
   - **The formula:** the design states the bound with every holder counted, including signers, delegations, connection registration and other narrowings, and with the actual number of subtree reads: `(r + 1) × t_read` for `r` roots. It gives the budgets: `t_read`, and the maximum set size and root count per narrowing.
   - **Cleanup:** a narrowing's cleanup, which includes closing processes, runs **after** its gates are released, per §17.4 item 6. Text that implies otherwise is corrected.
   - **20 s:** this is no longer a guarantee. It is a target, checked by deterministic tests at the stated budgets.
   - **Tests:** the multi-root countermodel and the overlapping-narrowing countermodel become deterministic tests. Each asserts commit within its derived bound, and that nothing is enqueued after the mark.
2. **R5-02: one shared `/proc/<pid>/stat` parser for both fields.**
   - The parser finds the last `)`. In the suffix after it, the process group is token 3 and the start time is token 20, and both are validated.
   - The scripts and the Rust side use the same rule. Fixtures cover `comm` values with spaces and with parentheses.
3. **The design gate.** Once revision 6 applies items 1 and 2, the M03 design gate closes on the orchestrator's check of those edits, and there is no further review round. The rationale:
   - five review rounds have run, each narrower than the last;
   - the remaining items are a bound derivation and a parsing rule, not safety defects;
   - the implementation units must carry the countermodel tests above, and the code review of wave 0 re-checks the gate protocol against the code.

### 17.14 Orchestrator rulings on revision 6; the M03 design gate closes (2026-11-06)

1. **Revision 6's choices, all accepted:**
   - only in-memory key destruction and identity unlisting stay under the gates, which reconciles §17.4 item 6 with §17.13 item 1;
   - the new "earlier marks go first" rule;
   - the proposed budgets: `t_read` 150 ms, at most 256 grants and 16 roots per narrowing, `t_commit` 200 ms, `ε` 1 ms;
   - beyond two overlapping earlier narrowings, the 20 s target is exceeded and reported, never enforced.
2. **A revocation always commits.** The "set grew again" defect no longer stops the commit. The narrowing reports `narrowing_set_grew` and runs a further round, as amended in D2 item 3a above. A test injects that defect and asserts that the commit happens and that nothing is enqueued after the mark.
3. **The M03 design gate is closed.** This follows the §17.13 item 3 rule, on the orchestrator's check of revision 6:
   - R5-01 is closed: D2 item 3a, D7 item 2 and plan U0b row 20 carry the derived bound, its budgets, the countermodel tests, and cleanup after release.
   - R5-02 is closed: the shared `procstat` parser, plan U0 and U0b row 28, and the U5 cross-checks.

   Wave 0 of M03 may start. Its code review re-checks the gate protocol and the fencing scripts against the code.

### 17.15 Orchestrator rulings on the wave-0 escalations (2026-11-08)

Source: the wave-0 integrator's escalation index (109 rows). Wave 0 was integrated with `check.sh` exiting 0 on two consecutive runs (2010 passed). Rulings made during the wave:

- **S1 and its follow-up.** The uniqueness index covers only states on the enrollment path, including `manual_pending`. A `held` row that a removal reached, which has `removal_origin` set, is outside it. A cancel that names the wrong origin is refused.
- **G-Q1.** A narrowing with no gated grant commits in a single transaction. Any gated member puts the whole set through the full protocol.
- **O-Q4.** No `interaction_required` reason in wave 0.

The rulings below are applied in wave 0 before its review.

1. **G-Q13.** A gate entry is never dropped while it has a holder or a pending mark. In addition, the release of a grant's last instance takes that grant's gate exclusively (U10 does the same).
2. **B2-Q3.** A signature frame without a permit is sent only when its grant has no signing gate, the same condition as G-Q1. For a gated grant it is refused and recorded.
3. **R4.** A `nominally_expired` obligation keeps its record, because it never shows as cleared (§17.1 item 10).
   - The grant may still become `revoked`: the obligation blocks nothing else.
   - A record with only `bounded_complete` obligations may be removed.
4. **X-Q1.** System-form records refuse the manual-recovery events. The system form uses only the §6.9 manual removal and verification states.
5. **X-Q2.** §6.7 wins. A damaged line found while reconciling a removal or a rollback moves to `held`, and keeps its `removal_origin`.
6. **X-Q3.** Manual recovery of a removal keeps the removal's purpose:
   - line absent: `removed`;
   - line present: `held`, with `removal_origin` kept, never `applied_unverified`.
7. **X-Q4.** `plan_digest` is bare 64-character lowercase hex.

Accepted without change:

8. **G-Q2 and G-Q3**, on one condition. `TimeGate::peek` is replaced by U3's `assess_read_only` before the U2 signer lands; that is a wave-2 acceptance criterion.
9. **A1-Q1/Q2, C-Q1/V-E4 and V-E2.**
10. **D-Q2.** The three informational zbus 5 advisories are accepted. M08's cargo-deny carries the ignore, to be revisited at secret-service 6.

Decided now, implemented in later waves:

11. **D-Q3.** Key generation uses only the operating system's CSPRNG, through `getrandom`.
12. **R3.** The M01 `[session] lock_behavior` key stays, as a floor. It is merged fail-closed with the standing policy: `revoke` wins from either side. U9 implements it.

**The other open rows.** The integrator's recorded readings stand as provisional defaults. Each later unit's brief lists the rows in its scope, to confirm or escalate.

### 17.16 Orchestrator rulings on the wave-0 code review (2026-11-08)

**Source:** M03-W0-code-review (Codex Sol, independent), `tests/evidence/artifacts/review-m03-code/wave0.md`. Verdict: fix first, with five findings, each reproduced by a probe. Each is accepted, and wave 0 merges into main only after all five are fixed with regressions and the review is re-checked.

1. **R1: changing the lock policy narrows authority.**
   - A change of `lock_behavior` from `continue` to `revoke_on_lock` narrows authority. It runs the full narrowing protocol for the affected grants and their descendants, before its commit.
   - Every other authority-reducing policy change does the same.
   - The provisional reading G-Q10 is overturned.
2. **R2: removing an environment permission is itself the narrowing.**
   - The removal transaction runs under the narrowing protocol for the affected grants and their descendants.
   - The later revalidation is kept as recovery, but is not the protection.
   - The provisional reading V-E6(a) is overturned.
3. **R3: never wait while holding gates.**
   - **Deferring to an earlier narrowing:** a narrowing first releases every exclusive hold it has, keeps its pending marks, and then restarts acquisition in global order.
   - **Regression tests:** a growing multi-root set with an overlapping narrowing. Both narrowings commit.
4. **R4: the continuous budget expiry comes from paired clock readings of one observation.**
   - The permit's continuous expiry is an absolute instant, computed from the continuous anchor and the wall reading taken together in the same observation. It is never `now()` plus the remaining budget after an await.
   - A budget already expired at that point refuses.
   - **Regression test:** the delayed-commit trace.
5. **R5: a foreign cancellation is checked against the persisted facts.**
   - `transition_foreign_removal` validates a cancellation's `origin` and `ca_not_held_seen` against the persisted `removal_origin`, as `transition_enrollment` does.
   - The persisted absence-history flag is never downgraded.
   - **Regression test:** the reviewer's probe trace.
6. **Follow-up: neither a pause nor a stricter connection policy is a signing narrowing.** The code cites this item as "§17.16 follow-up".
   - **What triggered it:** while fixing R1, the integrator also routed a pause and a stricter connection policy through the narrowing protocol.
   - **Why that is wrong:**
     - A pause never narrowed the signing check. Spec §5.6, ADR-0006 §13.6 item 1 and M01's pause-free `continuing_policy` agree on this.
     - The integrator probed the code as it stood: after a pause committed, an existing permit still released.
     - New activations are refused `POLICY_PAUSED` in their own store transaction, so a pause needs no gates.
     - Connection policy governs owned connections (D8 item 1). Neither admission nor the release check reads it.
   - **The ruling:**
     - Both take the zero-gate commit.
     - These stay in the narrowing set, because each lowers what the signing check allows: a cutoff that is set or moved earlier, `revoke_on_lock`, and an environment-permission removal.
   - **Regression tests:**
     - `pause_leaves_active_grant_permit_releasable_and_refuses_new_activation`;
     - `strict_connection_policy_does_not_narrow_signing_authority`;
     - M01's `r137_3_a_narrowing_inside_the_approved_delta_and_a_pause_keep_the_grant`, which still passes.
7. **The re-check.** An independent re-check (Codex Sol, `tests/evidence/artifacts/review-m03-code/wave0-recheck.md`) found R1–R5 resolved at `6c6b5e06`, with no new defect in the touched code. Its verdict was merge.
   - **Mutation evidence:** with its fix reverted, each regression test exits 101.
   - **Limit:** R2's regression exercises only the removal of `automatic_activation`.

### 17.17 Orchestrator rulings on the wave-1 escalations (2026-11-10)

**Source:** the wave-1 integrator's questions file, archived as `tests/evidence/artifacts/review-m03-code/wave1-notes/m03-wave1-questions.md`. The integrator's fail-closed readings stand unless an item below changes them. Items 1 to 6 are **changes**, made before wave 1 merges. Items 7 to 12 **confirm** a reading. Items 13 and 14 **schedule** contract work for a later wave.

1. **INT-Q2: `__CF_USER_TEXT_ENCODING` is a documented macOS platform addition.**
   - **The finding:** linking CoreFoundation, Security or CoreGraphics (U4's keychain store, U9's lock source) makes CoreFoundation's load-time initializer set `__CF_USER_TEXT_ENCODING` in the process environment, before `main`, when it is absent. A child that `heimdall run` or `connect` starts from such an environment inherits it.
   - **The ruling:** the variable is a documented addition to ADR-0007's "exactly the caller's environment" (§8), on macOS only, and only when it was absent from the caller's environment:
     - when present with the current user's uid, it passes through unchanged, like every other variable;
     - ⟨INT-Q9⟩ when present with another uid, or malformed, CoreFoundation rewrites it before `main`, as it does in every process that links CoreFoundation. The child receives the rewritten value. The rewrite is the operating system's, not Heimdall's, and is disclosed with the addition;
     - its value is the user's default text encoding (the form `0x<uid>:0x<n>:0x<n>`), neither a secret nor a Heimdall value;
     - an ordinary macOS session already carries it, so nothing changes there.
   - **Why not the alternatives:**
     - loading the frameworks lazily through `dlopen` would widen the `unsafe` surface;
     - restoring the exec-time environment would need a new `unsafe` call, `KERN_PROCARGS2`;
     - splitting the executable would change ADR-0002's distribution shape.

     None buys anything a user can observe.
   - **The regression:** `a27_cwd_and_env_preserved_plus_only_documented_additions` accepts exactly this pair on macOS, in exactly that form, only when the input environment lacks it, and fails on any other addition. `a27_cf_text_encoding_form_is_exact` pins the form.
2. **INT-Q5: on Darwin, the boot identity is `kern.bootsessionuuid`.**
   - **Why `kern.boottime` cannot serve:** XNU adjusts it when the wall clock is stepped. A fence could then read a different boot identity for a live holder and decide `gone` without the group proof.
   - **What replaces it:** on macOS, `sysctl -n kern.bootsessionuuid`, which does not move with the clock, is the boot identity in the start-identity record.
   - **A boot-identity difference alone never proves `gone`** on a target whose boot identity is a timestamp: on such a row, the group proof is still required.
   - **The BSD rows** stay `[I]`, with that rule.
   - **D5 §6.3's shell table** is amended accordingly.
3. **INT-Q7: retirement deletes exactly the store item this installation recorded.**
   - `put` returns the `StoreItemRef`. The issuer records it, and retirement deletes only that locator, after the absence check. It never deletes everything `list()` reports for a fingerprint.
   - So a second installation of the same OS user, holding the same restored CA, never loses its item.
   - A missing recorded locator refuses the deletion, with nothing deleted, and leaves an orphan to report.
4. **U9-Q2: a grant records the session-lock floor at creation.**
   - The integrator passes `session_lock_floor()` into `with_lock_and_connection` and into the `no_mechanism` and unattended-refusal lock arguments. The grant's recorded origin is then `lock::origin_behavior(&policies, floor)`.
   - So a later configuration edit plus a restart cannot turn a grant created under `revoke` into `continue` without an attended decision.
   - **The regression:** a grant created under the `revoke` floor stays `revoke_on_lock` after the configuration changes to `continue` and the runtime restarts.
5. **U5IO-Q1: Linux steps get `PR_SET_PDEATHSIG(SIGKILL)`, as §17.4 item 2 requires.**
   - **A fourth `unsafe` module,** `crates/enroll/src/sys.rs`, holds exactly one `CommandExt::pre_exec` closure. It calls rustix's `set_parent_process_death_signal(Some(Signal::Kill))` and nothing else that is not async-signal-safe.
   - Its invariant table goes into overview §9, and `remote::PARENT_DEATH_SIGNAL_APPLIED` becomes `true` on Linux.
   - **The regression** (Linux-native, on the devbox): `cli_death_ends_ssh_step_process` ends the step's child when the CLI is SIGKILLed.
6. **U5S-Q5: a failed write after the decision to write is `Uncertain`.** `classify_step` reads an append or remove exit 30 with `reason=write_failed` as `Uncertain`, never as `NotApplied`.
7. **Clock and boot-identity readings.**
   - **M-F23 is revised (U5S-Q1, INT-Q3).** Debian 13's mawk prints nanoseconds from `srand()`. The remote clock is therefore read as POSIX `date -u '+%Y %m %d %H %M %S'`, converted in awk by civil-from-days, with a plausibility range (2000 to 3000 UTC, otherwise unmeasured). The verifier uses the same reading. The utility list gains `date` and `sleep` (U5S-Q3).
   - **U5S-Q8 and U5S-Q9 are confirmed:** the `TZ` normalization, the `lstart` blank collapsing, and `kill -s 0 -x` as the invalid-syntax input.
8. **Confirmed readings of the pure enrollment plan:** U5P-Q1 (a), the plan context in `CaView`; U5P-Q2 (a); U5P-Q4 (a); U5P-Q5 (a), §6.7 wins; U5P-Q6 (a); U5P-Q7 (a).
9. **Confirmed readings of the credential core:**
   - U1-Q1 (a): the type name is public, with private fields and no constructor;
   - U1-Q2: each stricter validator is kept, behind its named refusal;
   - U1-Q3 (a): a decimal serial in the key ID;
   - U1-Q4 (a): the `/proc/<pid>/mem` attach probe;
   - U1-Q5 (a): it is re-run against `heimdall service run` once U10 calls `harden_process`.
10. **Confirmed readings of the stores and the lock source:**
    - U4-Q2 (b): Heimdall never triggers a store prompt. `issuer unlock` reports the locked store and how to unlock it, which is stricter than D4 item 2 allows.
    - U9-Q1 (a): `unknown` is treated as a lock, revocation included. The disclosed cost is that a transient `unknown` revokes `revoke_on_lock` grants.
    - U9-Q3 (a): U10 and U12 apply the `signal_unverified` labels.
    - U9-Q4 (a): macOS polls `CGSessionCopyCurrentDictionary` every 250 ms on a thread the source owns. D9 item 3's notification rows and overview §9 item 6 are amended.
    - U9-Q5 (b): `meta.session_lock_last` is dropped, and each lock pass's `session_lock` event is the record.
11. **Confirmed readings of enrollment I/O:**
    - U5IO-Q2 (a): on Windows, the CLI injects the job object through `StepContainment`, and a step without one is refused;
    - U5IO-Q3 (c): an interactive `/dev/tty` prompt stops ssh until the step's bound ends it, failing closed. U12 prefers agent-held identities for interactive steps, and rules the terminal handoff with its own escalation;
    - U5IO-Q5 (a): the Verifier installs each certificate;
    - U5IO-Q6 (a): `known_hosts_incomplete` is an undetermined reason, which the plan maps to `host_trust_undetermined`;
    - U5IO-W0: the confirmations are accepted.
12. **Confirmed readings, and what is left as built:**
    - U5S-Q2 (a): the test form exists in debug builds only;
    - U5S-Q4 (a): exit 40 `busy`;
    - U5S-Q6 and U5S-Q7: as listed;
    - INT-Q1 (a): pinned workspace crates may be added as dependencies of new crates; `Cargo.lock` changes only within the `heimdall-*` arrays;
    - INT-Q4 (a): the `m03 observation:` prefix, which U13 captures;
    - INT-Q6 (a): a removal or rollback redispatch narrows trust, so it needs neither approval validity nor an attended session;
    - INT-Q8 (b): as built. A bootstrap that created the directory and then refused leaves an empty private directory, which the next `inspect` reports. This is recorded as a limitation;
    - U11-Q1 and U11-Q2: resolved by the units.
13. **Contract additions, scheduled for the integration that first needs them.**
    - The reasons `registry_path_invalid` (U5P-Q3) and `account_override_refused` (U5P-Q6) are registered, as `USAGE_ERROR`, in the M03 reason golden. Until then no wire result carries either one.
    - **U4-Q1 (b), the test store:** a `#[doc(hidden)]` test store kind, omitted from the wire unless set and absent from the public schema golden.
      - It is accepted only by a test-configured runtime. A release build refuses any request that carries it.
      - A record or claim never reads it as a product store (D12 item 3).
      - It lands with U3 or U10, whichever first registers a CA through the wire.
14. **U5IO-Q4 (a): the verification classification moves into `domain::verification::classify` with U10** (wave 4). `TraceEvents` gains `host_key_failure`, `VerificationOutcome` gains an `unrecorded` flag, and `classify` takes the known clock offset. Until then, classification stays inconclusive, failing closed.

### 17.18 Orchestrator rulings on the wave-1 review and the first native runs (2026-11-10)

**Sources:**
- **The review:** M03-W1-code-review (Codex, independent), `tests/evidence/artifacts/review-m03-code/wave1.md`. Verdict: fix first, with three findings, W1-R01 to W1-R03.
- **The native runs:** the first development-check runs of the wave on the devbox (OpenSSH 9.6p1, dash 0.5.12-6ubuntu5) and on the Windows PC (in-box OpenSSH_for_Windows_9.5p2).
- **The integrator's round-3 escalations:** INT-Q10 to INT-Q12, archived in `wave1-notes/`.

1. **W1-R01 and W1-R02: every secret store is scoped to the installation.**
   - `put`, `get`, `delete` and `list` all select by `heimdall_environment_id`. The shared logic is `store/attributes.rs`, and the Linux Secret Service store is that logic over the Secret Service.
   - On Windows, the DPAPI blob directory is per environment: `%LOCALAPPDATA%\Heimdall\issuer\<environment ID>\` (INT-Q11). Without it, two installations of one user shared one directory. This **replaces the plan's path text** in m03-plan U4.
   - A restore adopts exactly one installation-scoped item. Zero items, or more than one, refuses; nothing is guessed. The frozen trait's `list` is documented as "this installation's items", with its signature unchanged (INT-Q12).
2. **W1-R03: the native lock rows need a real `Locked` reading.**
   - The source keeps a latched count of `Locked` readings, separate from the epoch. An `Unknown` still advances the epoch and still revokes `revoke_on_lock` grants (§17.17 item 10), but it never satisfies a lock-evidence row.
   - **The regression** is `unknown_never_counts_as_a_real_lock_observation`.
3. **INT-Q10: OpenSSH 9.5 and 9.6 never ask the agent for the certificate in the managed-alias shape.**
   - **Observed** in a container with the devbox's exact 9.6p1 build, and then natively on the devbox at `5b36b3d8` (the `identity_file_selection` observation lines):
     - with `IdentityFile` set to K_env's `.pub`, and an agent listing only the certificate, 9.6p1 tries the file's missing private key, exits 255, and asks the agent for nothing;
     - when the agent also lists the plain key, 9.6p1 asks it to sign the plain key;
     - 10.5p1 always asks for the certificate.
   - **The ruling:**
     - D2 item 4 and F17 stand. The signer never lists or signs the plain K_env key; this is not weakened for older clients.
     - **U2 and U8 (wave 2)** must find a projection and signer form that 9.5p2 and 9.6p1 complete through the certificate alone. Candidates are `IdentityFile` naming the certificate file, `IdentitiesOnly` with `CertificateFile`, or the agent's key ordering. Each candidate's evidence must come from the real clients: Windows in-box 9.5p2 natively, and the devbox's 9.6p1.
     - If no form works, U2 and U8 escalate with that evidence. The managed alias on those clients is then `capability_unavailable` (`client_unsupported`), reported per client and never silently degraded.
   - The observation test that records this behaviour per client stays in the suite.
4. **Development-check native runs are not exit evidence.** They locate defects before the M03 exit build. U13's exit runs are the evidence. U13 must run the Linux harness in batches, or strip debug information: the devbox has about 12 GB free, and 72 debug test binaries no longer fit, as the first wave-1 run showed with ENOSPC.
5. **The re-check** (Codex, independent; `tests/evidence/artifacts/review-m03-code/wave1-recheck.md`) found W1-R01 to W1-R03 resolved at `5b36b3d8`, with verdict merge. Its notes are ruled as follows:
   - **W1-C01, low:** for a staged CLI, `m03_test_gates_are_validated_before_anything_else` infers the expected build profile from the behaviour under test. This is accepted for wave 1, because `release-gate.sh` builds and probes the release CLI on its own. U13 passes the staged CLI's profile to the test from the harness, and the test then checks that it agrees.
   - **Pre-release DPAPI blobs:** the per-environment default directory (item 1) has no migration from the old shared path. No product caller of `default_dir` exists yet, and no release has written a blob. U10 wires the directory and refuses any blob outside it, never adopting one.
   - **The debug-only trace dump** writes raw client diagnostics. It exists only in debug builds and is never a support-log exporter or a secret sanitizer. Live accounts never use it.

### 17.19 Orchestrator rulings on wave 2: the reviews, the native checks and the escalations (2026-11-10)

**Sources:**
- **The code review** (Codex, independent): `tests/evidence/artifacts/review-m03-code/wave2.md`. Verdict: fix first, with W2-R01 to W2-R03.
- **The security review** (Codex, independent; plan §6.7): `wave2-security.md`. Verdict: fix first, with W2-S01. That is W2-R01, reproduced by a probe.
- **The integrator's escalations:** `wave2-notes/m03-wave2-questions.md`.
- **The native development checks:** at `0478f6cd` and again at `5adb67da`, after the fixes, on the devbox (OpenSSH 9.6p1) and on Windows (in-box OpenSSH_for_Windows_9.5p2).
  - At `5adb67da`, the devbox passed all 18 binaries it ran and Windows passed all 78 (2183 passed, 0 failed, 5 ignored; canary count 0).
  - Windows' first run at `5adb67da` never reached the fixture sshd. WSL's localhost forwarding did not answer from Windows. The repeated run reached it with the harness unchanged, so this is recorded as transient.

1. **W2-R01 and W2-S01: authorization uses the observation the time gate assessed.**
   - **The defect:** the `ReadOnly` default kept only the verdict of `assess_read_only`, then built `SafeNow` from a second, unassessed `clock.observe()`. A wall-clock step between the two was never judged. The security review reproduced a release after a one-hour rollback, where the `Peek` control refused.
   - **The ruling:** the observation and its verdict travel together. Authorization runs `TimeGate::assess_read_only_in` inside its own transaction and builds `SafeNow` from the observation that call returns. No later `observe()` replaces it.
   - **The regression:** the rollback interleaving, through the real signer and enqueue path. It must refuse, and fail with the fix reverted.
2. **W2-R02: the issuer knows a continuing re-issue from a new activation by a persisted fact.**
   - **The defect:** `ISSUER_FACTS.new_activation` was always true. A re-issue for continuing work, which publication allows under a pause (spec §5.6; ADR-0006 §13.6 item 1), was refused by the issuer, so its verdict differed from the publish transaction's (D3 item 4).
   - **The ruling:** the issuer reads the distinction from state the reserve transaction persisted, never from a field of the request.
     - Existing persisted facts are preferred: a prior published issuance of the same grant at its current generation.
     - If none fits, an additive migration is authorized. Any row written before it reads as a new activation, which fails closed.
   - **The regression:** a continuing re-issue under a paused policy passes both the issuer and publication, and a new activation under the same pause is refused by both. The predicate-equivalence property must stop forcing `new_activation = true` on both sides.
   - This closes U3-Q2.
3. **W2-R03: `stop()` fences restarts.**
   - The issuer client gets a lifecycle generation, or a cancellation token. `stop()` invalidates every restart or reload belonging to the stopped lifecycle, and waits for it.
   - No child is spawned, and no CA reloaded, after `stop()` without a new explicit start.
   - **The regression:** `stop()` during the restart backoff.
4. **INT-Q10: the managed alias names the certificate as its identity file.**
   - **What was observed:** D10's identity lines (`IdentityFile <key.pub>` with `CertificateFile <cert.pub>`) fail on every client tested: ssh exits 255 and never asks the agent. `IdentitiesOnly yes` with `IdentityFile <cert.pub>` (`CertificateAsIdentityFile`) signs once, through the certificate:
     - on macOS 10.5p1, at both reviews;
     - natively on the devbox's 9.6p1 (`managed_identity_form … form=certificate_as_identity_file`, and the rendered-P row);
     - natively on Windows' in-box `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` at `5adb67da`: `form=certificate_as_identity_file exit=Some(0) signed=cert sign_requests=1 accepted_cert_logins=1`, and the rendered-P row likewise.
       - `d10_as_written` exited 255 with no sign request, as on the other clients. The client refused `key.pub` as an unprotected private key file.
       - At `0478f6cd`, the test had failed on a Windows fixture refusal before it reached the client.
   - **No tested client needs `client_unsupported`:** 10.5p1, 9.6p1 and 9.5p2 all complete the managed alias through the certificate alone.
   - **The ruling:** D10 items 1 and 4 are amended to that form. F17 and D2 item 4 are unchanged: the signer never lists or signs the plain K_env key.
   - **A client where the form fails** reports the managed alias as `capability_unavailable` with `client_unsupported`, per client.
   - **`IdentitiesOnly yes` does not remove inherited `IdentityFile` or `CertificateFile` entries**, so D10 item 6's `not_exclusive` and `undetermined` classification still applies.
   - **The verification endpoint** may accept a plain K_verify handle only when the signed data carries the operation's current positive certificate, which is the reviewed behaviour.
5. **INT-Q13: verification signatures get a per-operation gate**, the integrator's option (a).
   - Installing a verification certificate also checks it against the plan's CA and pair, and the verification factory receives the plan.
   - This lands with U0b phase 2 and U10 (wave 4). Until then, every verification signature is refused, failing closed (`VERIFICATION_UNGATED_SIGNING = false`).
6. **Confirmed readings and schedule:**
   - U2-Q1: U10 persists `credential_instances`;
   - U2-Q2: U6 and U10 wire the install view. Until then installs are refused;
   - U3-Q3: the serial format check stands, and the install validator compares the serial;
   - U3-Q4: U10 adds the `managed` feature for `internal issuer`;
   - U8-Q1: the runtime uses `LocalProjection::writing`;
   - U8-Q2, U8-Q3, U8-Q4 and U8-Q5: as the integrator read them;
   - U8-Q6: an additive `preference` field on `inspect destinations` is authorized for U10 and U12. Until then, managed `connect` keeps M02's flow and fails closed.

### 17.20 Orchestrator rulings on wave 3: the reviews, the native checks and the escalations (2026-11-11)

**Sources:**
- **The code review** (Codex, independent): `tests/evidence/artifacts/review-m03-code/wave3.md`. Verdict: fix first, with W3-R01 to W3-R11.
- **The security review** (Codex, independent; plan §6.7): `wave3-security.md`. Verdict: fix first, with W3-S01 to W3-S05. Four were reproduced by probes against the unchanged libraries.
- **The integrator's escalations:** `wave3-notes/m03-wave3-questions.md`.
- **The native development checks at `3f7a582e`:**
  - **devbox** (OpenSSH 9.6p1): 17 of the 18 selected binaries passed (654 passed, 1 failed); canary count 0. The failure is W3-N01 below;
  - **Windows** (in-box 9.5p2): all 81 binaries passed (2239 passed, 0 failed, 6 ignored); canary count 0. All 11 `platform_only` Windows tests of U7 passed.

Several findings overlap: W3-S01 is W3-R04, W3-S05 is W3-R01, and W3-S03 is part of W3-R03. Each item names every finding it covers.

1. **The slot and binding files are fenced by generation and holder: W3-R01, W3-S05.**
   - **The defect:** `files::write_generation` replaced the marker unconditionally. A delayed write for generation N, run after N+1 was claimed and written, rolled the slot back. A probe reproduced it.
   - **The ruling:**
     - a write refuses a generation older than the directory's marker, or a holder that differs at the same generation;
     - a claim, its materialization and a clear of one slot are serialized, and the write re-validates the store's current holder and generation before it publishes;
     - individual atomic renames stay, but they are not the protocol.
   - **The regression:** a generation-1 write delayed past a release and a generation-2 claim leaves generation 2's marker and bytes unchanged.
2. **A stale clear never unlists the current binding: W3-R02.**
   - The signer's listing is withdrawn per binding, pair and generation. A clear for an older generation is a no-op in the signer as well as on disk. Clearing one pair withdraws only that pair.
   - **The regression:** a binding re-materialized at generation N+1 keeps its listing after a clear for N. A second pair keeps its listing after a clear of the first.
3. **The master lifecycle of a slot is serialized and proven: W3-R03, W3-S03, W3-N01.**
   - **The defects:**
     - two concurrent `start_master` calls could both take the same generation and claim one socket;
     - `close_master` sent `-O exit` to the stable path without proving who listened there. A probe killed an unrelated replacement master;
     - **W3-N01:** the socket identity was `(dev, ino)` alone. ext4 reused the inode number at once on the devbox (`master_socket_removed_only_if_same_inode`: left == right), so a stale cleanup could unlink generation N+1's socket.
   - **The ruling:**
     - start, replace and close of one slot run under one per-slot lock, and the generation is reserved inside it;
     - **readiness is proven to belong to the spawned child.** Before a row is recorded, the listener's process must be the child: `ssh -S <path> -O check` reports `pid=<child>`, or peer credentials do. A socket that is not proven is never recorded;
     - **a control command goes only to a proven listener.** Before `-O exit`, the path's inode and the `-O check` PID must match the row being closed. Otherwise no control command is sent, and only the verified-process signal is used;
     - a socket is removed only under the slot's lock, while no newer generation owns the path. An inode number alone never proves identity;
     - the test asserts the protocol, never that inode numbers differ.
4. **Restart judges each recovered master by fresh admission facts: W3-R04, W3-S01.**
   - **The defect:** `connection_restart_pass` kept a master whose deadline passed while the runtime was down, because the stored grant was still `Active`. A probe ran a new session over it after the deadline.
   - **The ruling:** a recovered master is kept only if the grant is usable now under the existing time gate and admission: the absolute deadline, the cutoff, the continuous budget and the parent's bound, with time accepted. Uncertain time closes masters, as in `time_uncertain_close`.
   - **The regression:** the deadline passes while the runtime is absent and the stored state is still `Active`. The pass closes the master, and no session is admitted after the deadline.
5. **Only the slot holder's master serves the stable path: W3-R05.**
   - `start_master(binding, pair)` requires:
     - the pair is in the binding's scope;
     - the binding holds that pair's environment slot at the slot's current generation;
     - owned multiplexing is enabled and applied for the grant.
   - After the spawn's awaited work, the slot holder, its generation and the policy are read again. If any changed, the new child is closed and nothing is recorded.
   - **The regression:** a binding that does not hold the slot is refused, and a slot transfer during the spawn leaves no recorded master.
6. **An unproven listener on the stable path never serves a managed alias: W3-S02.**
   - **The defect:** `mux_path_occupied` refused to start a master, but ordinary `ssh` still reused the foreign listener, also after revocation. A probe reproduced it.
   - **The ruling:**
     - **the mux directory** `<runtime_dir>/mux/` is created and re-verified owner-only: owner, mode 0700 and no symlink component;
     - **the stable path's entry is Heimdall's namespace.** A socket there that is not proven to be the slot holder's current master is never trusted, never recorded and never signalled;
     - **its path entry is removed, by a same-inode check under the slot's lock,** before Heimdall starts its own master, and whenever the slot's grant ends;
     - **the result is reported** as `mux_path_foreign_listener_removed`. The residual is disclosed: sessions already open through that listener are `not_controlled`.
   - **The regression:** the probe's scenario. A foreign master at the path, then the grant is revoked, then an ordinary `ssh <alias>` makes no session through it.
7. **Managed files never follow a planted directory: W3-S04.**
   - **D10 item 2 stands: the slot files are public,** and mode 0644 is correct. The integrity requirement is on the directories.
   - Every write, clear and enumeration under `<state_dir>/managed/` and `<runtime_dir>/b/` follows these rules:
     - it is anchored to verified directory handles, using the repository's existing handle-relative, identity-checked patterns;
     - it rejects a symlink or reparse point in any component;
     - it refuses an existing directory that is not owner-only (0700, or an owner-only DACL on Windows), reporting `managed_dir_unsafe`. Nothing is repaired silently;
     - it never deletes through a directory it has not verified.
   - **The regression:** the probe's three cases: a parent symlink, a leaf symlink on clear, and a pre-existing 0777 directory. Also restart enumeration over a planted entry.
8. **Coverage never exceeds the shortest certificate: W3-R06.**
   - `check_prepared` refuses an expired or not-yet-valid certificate.
   - `usable_until` and `offline_until` are bounded by the minimum `valid_before` across the pairs.
   - An offline minimum beyond that bound is `capability_unavailable`.
9. **The deadline wording follows the selection and multiplexing: W3-R07.**
   - The policy wording is computed from the identity selection and the policy by U8's existing `plan::deadline_wording`, with no retyped text.
   - When owned masters are applied, it adds D8 item 3's disclosure that sessions shared through Heimdall's connection end at the deadline.
   - With today's `Undetermined` selection, the qualified D8 item 6 wording applies.
10. **The aggregate clock is the weakest one now: W3-R08.**
    - The revocation report chooses the pair with the largest completion allowance at the report's observation time: `behind_upper + rtt + drift × age`.
    - An unknown measurement, or an overflow, is the weakest.
11. **Every signal re-verifies the image: W3-R09.** The Linux pidfd stays. Before the second signal (SIGKILL), the executable and start identity are re-read, as on macOS (D8 item 2).
12. **The Windows tests prove what they name: W3-R10.**
    - **`windows_register_while_suspended_under_gate`** uses a managed fixture whose grant has a real registered signing gate, and contends on that gate.
    - **`windows_non_ssh_run_has_no_job_object_by_default`** launches through `run`'s launch path. It asserts that the child is not in a job (`IsProcessInJob` false), and that a deliberately surviving grandchild outlives the launcher's normal exit.
    - A test that cannot be built that way is renamed to what it checks.
13. **A pass reports a discovery failure: W3-R11.**
    - A store failure while enumerating rows, in any pass, is returned as an explicit failure, never as an empty `PassReport`.
    - U10 then keeps the cleanup intent and retries (D7 item 2).
14. **The escalations:**
    - **W3-Q1:** option (a) is accepted.
      - The master uses `OWNED_LAUNCH_PINS[0..2]` (`ForkAfterAuthentication=no`), then its own `-M -N -o ControlMaster=yes -o ControlPersist=no -o ControlPath=<mux>`, then §17.19 item 4's identity options.
      - A unit test pins that slice to exactly `["-o", "ForkAfterAuthentication=no"]`.
      - D8 item 3's `key.pub` and `CertificateFile` lines are superseded by §17.19 item 4.
    - **U7-Q1:** the production edge `heimdall-runtime → heimdall-sshconf` is accepted. It adds no package and no cycle. m03-plan §0.6 is amended to list it.
    - **U6-Q1 and U6-Q2:** accepted. `GrantScopes` must read the grant's stored scope (U10), never a request or a process file.
    - **U6-Q3:** accepted. The selection is `unknown` until U0b phase 2, with item 9's wording.
    - **U6-Q4:** accepted. U10 clears each slot by its own store generation. Items 1 and 2 supply the fencing.
    - **U6-Q5: amended.** Missing grant terms refuse the computation, `grant_terms_unavailable`, instead of defaulting to `continue`. A default could report `verified` for a `revoke_on_lock` grant once a claim exists.
      - **The regression:** a `revoke_on_lock` grant whose terms are absent never reports `verified`, even with a matching claim.
    - **U6-Q6:** the binding endpoint is right (D10 item 4; `connect`'s derivation).
      - The example `schemas/examples/ensure-data.managed.json` changes its `consumer.signing_endpoint` to the binding endpoint, in the locator form of item 15.
      - The contract tests that read the example follow, and `report_for_local_managed_binding_with_empty_claim_table` compares `consumer` too.
      - That example change is authorized. The schema is unchanged.
    - **U7-Q2:** option (a), the reap pass, is accepted. Option (b) is optional for U0b phase 2.
    - **U7-Q3:** accepted. Emitting the `Connection` events, with the close reason, is part of U10's delivery.
    - **U7-Q4:** accepted. The invariant behind it is checked where rows are inserted, with a test: a dedicated row only for a launch binding with a holder, and a master only with a resource.
    - **U7-Q5: recorded,** with the devbox row. On 9.6p1 the behaviour is the same as on 10.5p1:
      - `-O stop` leaves the master and its sessions alive and removes the socket;
      - a later `-O exit` fails with 255;
      - `-O exit` alone ends the master and its sessions.

      The close uses `-O exit` (item 3), then the verified-process signal, and never `-O stop`.

15. **The round-2 questions** (`wave3-notes/m03-wave3-r2-questions.md`):
    - **W3-R2-Q1:** option (a). The contract carries the **locator** the product emits and `connect` parses:
      - `\\.\pipe\heimdall-<token>-b<tag>` on Windows, and the socket path on Unix;
      - P's rendered spelling, `//./pipe/…`, stays a property of the configuration file (ADR-0007 §4).

      The example names the locator, and the golden test compares it with no mapping. Item 14's original wording named the rendered spelling by mistake.
    - **W3-R2-Q2:** option (b) is accepted for now.
      - `valid_after` is read from the signer's install record, and a missing or mismatched record refuses (`prepared_certificate_not_yet_valid`).
      - Adding `valid_after` to `PreparedCertificate` is left for U10, if the driver needs it. It would be a recorded frozen-port change.
    - **W3-R2-Q3:** option (a) is accepted. On Windows the slot and binding files carry an owner-only DACL.
      - "Public" in D10 item 2 means the files hold no secret. It does not require them to be readable by others.
      - The same user's `ssh.exe` must read them, and the Windows-native run confirms this.
    - **The disclosed residuals are accepted:**
      - **A directory that is not owner-only, planted under `<runtime_dir>/b/`,** makes binding clears refuse `managed_dir_unsafe` until it is removed. That fails closed, and the doctor (U12) reports it.
      - **A failed `-O check` during a close removes the path entry** of a master that is being closed anyway. Clients then connect directly, through the gated signer.
16. **Round 3: the re-check and the second native runs.**
    - **The re-check** (`wave3-recheck.md`, Codex, independent) of `3f7a582e..5ee3e143` was **fix first**:
      - it confirmed W3-R01 to R11, W3-S01 to S05 and W3-N01 as resolved, with its own revert runs;
      - **W3-C01:** the connection fixture leaked server-side command processes on green runs, and a recorded master when its store read failed;
      - **W3-C02:** the symlink regressions were masked by the permission check.
    - **The devbox at `5ee3e143`** failed 33 managed-file tests, for one reason:
      - `tempfile` anchors take the user's umask, which is 002 on the devbox, so they came out 0775, and `open_root` correctly refused them;
      - the test anchors are now created owner-only, and `open_root`'s check is unchanged.
    - **Windows at `5ee3e143`:** all 81 binaries passed (2252 passed, 0 failed).
    - **The fixes:**
      - **W3-C01:** the fixture keeps exact receipts (PID, start time, image) independent of the store, the server commands end on their own, and each world audits for survivors;
      - **W3-C02:** the planted targets are owner-only, so only no-follow can refuse them.
    - **Production anchors keep M01's behaviour.**
      - `Paths::ensure` creates Heimdall's directories 0700 whatever the umask, and tightens an existing one the user owns to 0700.
      - A symlink, a non-directory or another owner's directory is refused.
      - A directory loosened after `ensure` is refused by `open_root` with `managed_dir_unsafe`, and is not repaired.
      - Tightening Heimdall's own directory is a safe repair; a refusal is kept for what Heimdall does not own.
      - **The regression:** `production_anchors_are_owner_only_under_umask_002`, which runs in a child process under umask 002.
    - **W3-R10, the gate test:** the registration test is accepted as a test of the real registration gate, using a `fake_agent` grant with a real gate that the test contends on. The full managed-credential workflow is U10's, and the test says so.
    - **W3-R10, the non-ssh test:** when the test runs in no job, the child must not be in a job (`IsProcessInJob == false`). When the test is in an ambient job, the child's immediate job must also hold the launcher. The test stops its grandchild by exact PID and creation time.
17. **Rounds 4 and 5: the connection fixture's process ownership** (test code only; `wave3-recheck3.md`, `wave3-recheck4.md`).
    - **W3-C03:** a server command's shell escaped cleanup before it became `/bin/sleep`. Round 4 fixed it: an exact walk of the fixture's unreaped sshd, receipts with the image actually read, a cancel marker before `exec`, and an audit on a normal drop.
    - **Residual, accepted and disclosed:** a shell stopped **indefinitely** before its pidfile, whose client closes before teardown, is reparented out of the sshd's tree and is not found.
      - It needs an injected `SIGSTOP`. An ordinary delay reaches the cancel marker, or the 40 s self-termination after `exec`.
      - The fixture's doc comment states this limit, and the drop audit claims only what is in the tree or receipted.
      - U13's exit harness counts leftover processes by exact identity at the suite level.
    - **W3-C04: fixed by the orchestrator.**
      - The descendant walk could trust an intermediate parent by PID number alone. If two PIDs were reused within the walk, it could admit, and later signal, an unrelated process of the same user.
      - The frontier now carries each walked parent's start token, and the walk confirms it again after reading the child's parent.
      - **The regression:** `descendant_walk_never_admits_a_child_under_a_reused_parent`, a deterministic model of the reviewer's schedule. It fails with the check removed: the reused child `10002` is admitted.
      - **Checks:** the full `integration_connections` target passed 43 of 43 on three runs, and clippy and the Linux cross-check are clean.
      - **Not re-checked:** this small, test-only change was not independently re-reviewed.
    - **No product code changed in rounds 3 to 5.**

### 17.21 Orchestrator rulings on wave 4, round 1: the activation's escalations (2026-11-11)

**Sources:**
- the integrator's report at the round-1 checkpoint, `d74e35cf`;
- `wave4-notes/m03-wave4-questions.md`, with INT-W4-Q1 to Q6, A-Q1 to Q5, U10B-Q1 to Q5, U10C-Q1 to Q6 and U10-D-Q1 to Q4.

No review has run yet. These rulings complete the wave before its reviews.

1. **INT-W4-Q1 (= U10C-Q1): a managed binding is materialized during preparation, under an ID minted at resolve.** Option (a).
   - **The defect:** the pipeline minted the binding in `stage_commit`, after `prepare_from`. No production caller created a binding endpoint, so an activated managed grant signed for no one, and `consumer.signing_endpoint` was absent.
   - **The ruling:**
     - **The binding ID is minted when the mechanism resolves to `managed_certificate`,** and recorded in the recovery intent. This adds `ResolvedIntent.binding_id: Option<BindingId>`, serde default and omitted when absent, so M01 and M02 intents decode and re-encode byte-identically. That domain change is authorized.
     - **Step 6 (D6 item 1)** calls the existing `ManagedEffects::materialize`. `ManagedEffectsImpl` creates and attaches the binding endpoint through its `BindingEndpoints` (`EndpointRegistry::create_binding`, `SignerTable::attach_binding`) and writes the binding files. No port gains a method.
     - **The result:** `prepare_from` names the binding endpoint in `consumer.signing_endpoint`, and `stage_commit` commits the binding under the pre-minted ID.
     - **A failure before the commit** is cleaned up by the operation's cleanup intent: the endpoint and the files go, and the key is destroyed. A replay of the same `request_id` returns the same binding.
     - **Existing-access ensures are unchanged.** The M01 and M02 suites and request hashes stay as they are.
   - **The regressions:**
     - `enroll_preview_apply_verify_setup_apply_ensure_ssh` exercises its `ensure` and `ssh` legs;
     - a managed `ensure` names the binding endpoint;
     - a crash between materialization and commit leaves no endpoint, file or key after recovery;
     - an existing-access `ensure` is byte-identical to M02.
2. **INT-W4-Q2 (= U10C-Q2): the runtime claims a managed binding's slots in `bind`.** Option (b).
   - `BindForm::Launch` of a managed binding claims each pair's environment slot in the runtime. That covers the store compare-and-swap, the files through `ManagedSlotTable`, and the signer's listing. A slot that cannot be claimed refuses the bind, naming the slot's reason.
   - The CLI's `run_cmd::ManagedSlots` becomes a reader of the bind's outcome, with no claim of its own.
   - If the reply needs a field, an additive one is authorized. No new request.
3. **INT-W4-Q3 (= U10B-Q2) and INT-W4-Q4 (= U10B-Q1): registration and retirement facts are persisted.**
   - **The pending registration:** `DecisionKind::RegisterIssuer` gains additive `ca_public_key` and `backup_created_at` fields (serde default). The pending registration then survives a restart, and approval needs no process memory.
   - **The store item:** `IssuerRecord`'s `record_json` gains an additive `store_locator`, written from whichever component reports the K_ca put: the ceremony's report or the issuer child's.
   - **Retirement** deletes exactly that locator (§17.17 item 3).
   - **Records written before these fields** read as absent:
     - an approval of such a decision refuses with `DECISION_STALE`;
     - retirement stops at `unloaded`, reported as `issuer_store_locator_unrecorded`. Nothing is guessed.
   - These domain and decision-golden changes are authorized. No migration is needed.
4. **INT-W4-Q5 (= A-Q1): journal receipts are accepted, but minimized.**
   - The enrollment journal may live in `enroll.journal` stage receipts.
   - **It never stores the inspected registry's foreign bytes.** Other keys' lines and comments are the server owner's data. Store only:
     - the registry's SHA-256;
     - Heimdall's own marker entries;
     - the parsed facts the stage machine needs.
   - If a later step needs the full bytes, re-inspect.
   - **The regression:** after an enrollment against a registry holding foreign lines with comments, no stored receipt contains those comments.
5. **The verification authorities are extended together: A-Q2 (a) and U10B-Q4 (a).**
   - `verification_m03::operation_facts` and the read-only check authorize three verifications:
     - an `enrollment.apply`'s initial verification;
     - a target change's verification;
     - the system form's absence check.
   - That covers reservation and signing alike. Each has its own predicate: it must be that operation's own verification, at its stage.
   - **The reconcile test:** `enroll_reconcile_applied` then expects `verified`, not "`applied_unverified` or `verified`".
6. **One re-issue rule: U10C-Q5, amended.**
   - The pure `reissue::eligible` moves to a crate that both `app` and `adapters` can call, and both call that one implementation. A second, re-implemented copy in `app` is not kept.
   - **If the crate graph forbids the move,** keep the copy, and add a property test (at least 256 cases) asserting the two agree.
7. **Credential instances are found by a store query: U10C-Q6, option (a).**
   - Add `Txn::credential_instances_for_grant`, a store query with no migration.
   - Do not derive instance IDs from key fingerprints.
8. **The Windows environment pipe token is stable per installation: U10-D-Q1, option (a).**
   - Add `Txn::{windows_pipe_token, set_windows_pipe_token}` over the existing `meta` table, with no migration. D10 item 1 requires a stable name.
   - **The regression:** after a runtime restart on Windows, P still names the live pipe, and `ensure` is not `projection_pending`.
9. **P renders the stable mux path once owned masters are enabled and applied: U10-D-Q4, option (a).**
   - The store-backed `ManagedPairSource` reads the effective connection policy, D8 item 1's merge, and renders the mux path only when `owned_masters` is enabled and that rendering is applied by `setup apply`. Until then it renders `ControlPath none`.
10. **Accepted as built:**
    - **A-Q3:** the clock measurement is taken outside the Verifier, which is conservative;
    - **A-Q4:** a fixed supervisor principal. It is unattended, holds the owner role only for re-verification, and is never accepted for an attended decision;
    - **A-Q5:** the `EnrollmentHost` port;
    - **U10B-Q3 (b):** `bundle_stale` is true while any enrollment exists, and `orphan_store_items` is empty. U12 may refine it with an additive `last_bundle_at` meta key, which is authorized;
    - **U10B-Q5:** no test store kind;
    - **U10C-Q3:** K_env is destroyed under the gates, as now built;
    - **U10C-Q4:** `NarrowingKind::Enrollment`;
    - **U10-D-Q2:** the runtime's own stop has no `CloseReason`;
    - **U10-D-Q3 (= INT-W4-Q6):** `wire_runtime_projection` serves the runtime, and M02's `wire_projection` is kept.
11. **Also owed in round 2:**
    - **The selection classification feeds the report.** The managed adapter passes the actual `SelectionClass` from D10 item 6's classification, now that `MANAGED_SELECTION_CLASSIFIED` is true.
    - **Slot cleanup when a grant ends:** add the store query for the held slots of ended grants (no migration), and run the cleanup from the supervisor.
    - **`inspect connections`:** implement it read-only over the owned-connection rows, matching the existing example.
    - **The plan tests not yet written:**
      - the four fence and terminate tests;
      - `enroll_remove_lists_affected_grants_and_degrades_them`;
      - both `target_change_*` tests that remain;
      - both `held_*` tests that remain;
      - both `initial_verification_*` tests;
      - `e5_rotation_keeps_projection_and_adds_issuing_ca` and `rotation_two_accounts_one_unreachable`;
      - both `a10_narrow_certificate_refused_on_other_host_*` tests;
      - `issuer_crash_blocks_reissue_not_signing`;
      - the host-key half of `evidence_invalidated_on_host_key_or_client_change`;
      - the abandon path of `foreign_removal_held_recovery_by_new_decision_or_abandon`.

### 17.22 Orchestrator rulings on wave 4, round 2: the reviews, the native checks and the round-2 questions (2026-11-11)

**Sources:**
- **The code review** (Codex, independent): `tests/evidence/artifacts/review-m03-code/wave4.md`. Verdict: fix first, with W4-R01 to W4-R09.
- **The security review** (Codex, independent; plan §6.7): `wave4-security.md`. Verdict: fix first, with W4-S01 to W4-S03, all three reproduced by probes.
- **The integrator's round-2 questions:** `wave4-notes/m03-wave4-r2-questions.md`.
- **The native development checks at `e566cc46`:**
  - **devbox** (9.6p1): all 14 selected binaries passed (631 passed, 0 failed); canary count 0;
  - **Windows** (in-box 9.5p2): all 84 binaries passed (2317 passed, 0 failed, 7 ignored); canary count 0. `windows_native_restart_p_still_names_live_pipe_ensure_not_projection_pending` and `reissue_after_runtime_process_restart_same_boot` passed natively.
    - **But `e2e_enroll_m03` ran no tests on Windows.** The whole file is `#[cfg(unix)]`, and the live binding-endpoint tests are Unix-only too, so U10's acceptance on Windows (m03-plan U10) is not met.
    - **The ruling (W4-N01):** port the enrollment e2e flows to Windows. They use the in-box `ssh.exe`, the harness's WSL fixture sshd (`HM_FIXTURE_SSHD_*`), and the binding endpoint's pipe form.
    - A case that truly cannot run on Windows stays gated, with its reason named.

**Findings:**
1. **W4-S01: a held foreign removal executes only the descriptor that was approved.**
   - Reusing a held record requires its descriptor to equal the new request's exactly: destination, account, CA, registry and line hash. A mismatch refuses (`descriptor_mismatch`).
   - The decision's precheck re-checks that equality at approval.
   - **The regression:** the reviewer's probe. Vary principal, CA and registry. Approving B must never remove A.
2. **W4-S02: the journal stores no foreign bytes, even on marker-bearing lines.**
   - Only Heimdall's exact canonical own entry is persisted, and only when it matches.
   - Any other line that carries the marker is recorded as parsed facts: counts, a classification and a SHA-256. Never its bytes.
   - **The regression:** a marker-bearing owner comment and an unrelated key whose comment carries the marker, run through the real inspect and `StepResult` path. No receipt holds their bytes in any encoding.
3. **W4-S03: teardown without `stop` still stops the issuer.**
   - Dropping a started service, or a failed start unwinding, fences and stops the issuer lifecycle and breaks the `Operations` ↔ endpoint ↔ authority cycles, whether or not `run` was entered.
   - **The regression:** drop every public strong handle. The fixture child exits by itself, and the vault is not retained.
4. **W4-R01: expiry destroys the managed key.**
   - When a grant expires, whether found by the scheduler or at use, K_env is destroyed and its instance moves to `destroyed`. The gate is released, and the binding endpoints and files are removed. This holds with or without a held slot (D1 table, D2 table, D7 item 8).
   - **The regression:** a real vault expires with and without a held slot. Afterwards the vault is empty, the instance destroyed, the gate released, and the endpoint and files gone.
5. **W4-R02: a re-issue restores the consumers before it reports the repair.**
   - After a re-issue, every live binding of the grant gets its endpoint attached, its files replaced at a new generation, and its environment listing and slot content restored from the stored bindings and slot generations. Only then does the grant return to `active` (D6 item 4; D10 item 2).
   - **The regression:** restart in the same boot. After the re-issue pass, ordinary `ssh` through the slot and through the binding endpoint succeeds with the new key.
6. **W4-R03: every committed binding is materialized.**
   - A coalesced or decision-joined follower either has its own binding materialized against the existing grant and key, or is refused before success. It never returns `ACCESS_READY` for an unmaterialized binding.
   - **The regression:** two distinct `request_id`s coalesce. Both bindings sign, or the follower is refused.
7. **W4-R04 (with R2A-Q1): evidence is invalidated at the comparison.**
   - When `inspect` or `ensure` finds that the evaluated host key, the client or the CA differs from the evidence, the evidence is invalid **at once**. The report gives `destination_scope: unknown`, and a minimum that needs it fails. This is independent of the enrollment's state and of any later network attempt.
   - **A host-key change** never triggers an automatic login (D5 §6.5). The record is `held` until an attended `ApproveTargetChange` verification passes.
   - **A client or CA change** prompts re-verification (§17.4 item 11). An inconclusive result keeps the evidence invalid; it never restores the old freshness.
   - `pair_evidence` selects evidence for the CA of the certificate being prepared.
   - **The regressions:**
     - an `ensure` before the pass is refused for a scope-needing minimum;
     - an inconclusive attempt after a client change leaves the scope `unknown`.
8. **W4-R05 and W4-R06: a cleanup owner exists from the first effect.**
   - A managed cleanup intent is recorded **before** the first external effect. That is the key generation, the endpoint and the files, not only after a successful `ManagedPrepared`.
   - Recovery of an `Attempted` or uncertain preparation runs that cleanup.
   - A failure inside the driver's own cleanup keeps the intent and is retried; it is never logged and forgotten.
   - **The regressions:**
     - a crash between `materialize` and the ensure confirmation, which is the interval the reviewer named;
     - an injected failure inside the driver's cleanup, which is retried until clean.
9. **W4-R07: an unfinished cleanup stays discoverable.**
   - Freeing a slot never ends the cleanup obligation while binding files or a mux path remain. The obligation stays durable until all the generation-bound work is done.
   - **The regression:** an error after the slot's files are removed is retried on the next pass.
10. **W4-R08: releasing a binding releases its slots.**
    - `held(b, g)` moves to `clearing` when `b` is released, even while the grant lives on through another reference (D10 item 2).
    - K_env is destroyed only with the last reference.
    - **The regression:** a parent binding holding the slot is released while a child keeps the grant live. Another binding can then claim the slot.
11. **W4-R09: real byte identity.**
    - Fixed goldens from the base commit `d6593a7c` cover an existing-access `ensure`: its result, its intent bytes and its request hash.
    - The test compares the current run against them.

**The round-2 questions:**

12. **R2B-Q1 and R2B-Q2: the owner-present CLI deletes the CA's store item.**
    - **The locator:** the ceremony reports the store item's identity in an additive `store_locator` on `issuer.register`, bound to the CA, the installation and the store. That contract change is authorized. The runtime records it with the approval.
    - **Retirement:** after the child unloads, the runtime reports `unloaded`, awaiting deletion of that locator. The owner-present CLI (U12) deletes exactly that item, then confirms through an additive confirmation on `issuer.retire` (authorized). Only then does the record reach `retired`.
    - **Who may write the store:** neither the runtime nor the child ever writes or deletes the platform store; the child only reads (D3).
    - **A restore** that creates a new item records the new locator by compare-and-swap against the expected old one. The displaced item is listed in `orphan_store_items` until resolved.
13. **R2C-Q2: the `bind` result names the binding's endpoint,** read from the runtime registry for that exact live binding. If it is absent, `connect` refuses. Managed `connect` then takes D8 item 2's flow.
14. **R2D-Q1: option (a), documented as a pair-level rendering rule.** P renders the stable mux path only when every standing policy covering the pair has `owned_masters`. Having no applicable policy means disabled. Each master's own grant policy is still checked when it starts.
15. **R2E-Q2: no grant-state change solely because the issuer is unavailable,** reviewer's option (b). The issuer's state is reported on its own. Installed keys keep signing (D3 item 7).
16. **The R2F questions:**
    - **Q1:** record `existing/applied` when its rendering commits. No rows are created for M02 pairs that have no preference.
    - **Q2:** an approved apply with nothing to replace still commits the generation and the preference metadata, so a toggle back to an already-rendered configuration does not stay `pending`.
    - **Q3:** removing a destination from the catalog returns its preference to `pending`, or removes it, in the same transaction.
    - **Q4:** manual mode counts as applied for the journaled P rendering. The manual-include diagnostic and its disclosure stay.
17. **`SetupIntent.managed_pairs` and `ProjectionPlan.managed_pairs` are ratified** as the durable record of what an approved rendering contains (D5 §6.6; U0b row 9). They are serde-default and omitted when empty.
18. **The issuer at start (the security review's readiness caveat) is accepted as built.**
    - The runtime listens after an issuer start *attempt*. A failed start is reported (`issuer_unavailable`), managed issuance and re-issue fail closed, and existing access is unaffected.
    - The guarantee is that the issuer is started before listening, not that it is ready.

### 17.23 Orchestrator rulings on wave 4, round 3: the round-3 questions (2026-11-11)

**Source:** `wave4-notes/m03-wave4-r3-questions.md`. R3A-Q1 was closed by the integrator: `descriptor_mismatch` is registered, as §17.22 item 1 named it.

1. **R3A-Q2: the managed descriptor advertises the server scope as achievable.**
   - The mechanism's descriptor advertises `destination_scope: verified_server_principals` as what it *can* deliver.
   - Each pair's evidence comparison (§17.22 item 7) decides whether the request gets it. Invalid or absent evidence still gives `unknown`, and a minimum that needs the scope is refused.
   - Without this, A10's guarantee could never be offered.
   - **The regression:** with fresh, valid evidence, a `verified_server_principals` minimum is met. With invalidated evidence it is refused.
2. **R3B-Q1:** option (a) is accepted. `CaStatus.store_locator` and `OrphanStoreItem.locator` are additive read fields. A locator identifies a store item and is not a secret.
3. **R3B-Q2:** option (a) is accepted.
   - The second `issuer.register` must repeat the pending registration's facts exactly: the fingerprint, public key, store kind and backup digest.
   - It only attaches the locator, and only once. A mismatch, or a second different locator, refuses.
4. **R3B-Q3:** option (a) is accepted. A log-intact restore that changes the locator goes through an attended `RegisterIssuer` decision.
5. **R3C1-Q1: the per-pair identity selection is fed from the classification.**
   - `PairIntegration.identity_selection` is fed for each pair from D10 item 6's classification of the alias's observed configuration, as §17.21 item 11 required.
   - A fixture whose managed alias classifies `exclusive` then delegates non-interactively. An `undetermined` alias is still refused.
   - §17.22 item 10's regression uses a real child delegation.
6. **R3C2-Q1 and R3C2-Q2: an explicit materialization source.**
   - **No by-reference convention.** No convention may overload the meaning of `MaterializeSpec`.
   - **The spec names its source explicitly:** fresh key material, or the existing installed key of a named grant. This is an additive, typed field in `app::ports`, authorized here.
   - **The locator:** the materialization reports the endpoint locator it actually created, in an additive field of its result. A follower's `consumer.signing_endpoint` is that locator, never one derived by string substitution.
   - **W4-N01's Windows port** covers the follower's and the re-issued binding's pipe forms.

### 17.24 Orchestrator rulings on wave 4, round 5: the re-check, the Windows port's failures and the round-5 questions (2026-11-13)

**Sources:**
- **The independent re-check** of `e566cc46..4866642d` (Codex): `tests/evidence/artifacts/review-m03-code/wave4-recheck.md`. Verdict: fix first, with W4-C01 (medium) and W4-C02 (high). Every round-3/4 finding is resolved except W4-R04, which W4-C02 leaves open on one path.
- **The native Windows run at `4866642d`** (in-box `OpenSSH_for_Windows_9.5p2`, the WSL fixture sshd 9.6p1): the harness exited 1 after 1138 s. W4-N01's port ran, and `e2e_enroll_m03` was the only failing binary (29 passed, 20 failed). Canary count 0.
  - 15 failures were the expected `client_trace_family_unrecorded`: the Win32 row was not yet recorded, so every verification was inconclusive. `windows_client_trace_row_observation` passed and printed the observation lines the row is recorded from (item 5).
  - The other 5 are item 3.
- **The round-5 questions:** `wave4-notes/m03-wave4-r5-questions.md`.
- **The independent re-check of round 5**, `4866642d..a533fc40` (Codex): `tests/evidence/artifacts/review-m03-code/wave4-recheck5.md`. Verdict: merge. W4-C01, W4-C02 and the Windows correction are resolved, five reverts of its own each failed (exit 101) and passed restored, and it found no new actionable defect (item 6).
- **The native development checks at `a533fc40`:**
  - **devbox** (9.6p1): all 20 selected binaries passed (837 passed, 0 failed, 4 ignored), `e2e_enroll_m03` 67 of 67; canary count 0;
  - **Windows** (in-box 9.5p2): the harness exited 1 after 1173 s. `e2e_enroll_m03` was the only failing binary (37 passed, 16 failed), and all 16 were the expected `client_trace_family_unrecorded`. The five tests of item 3 and the item-4 observations passed. Totals over 84 binaries: 2367 passed, 16 failed, 7 ignored; canary count 0.

**Findings:**
1. **W4-C02: a follower's scope claim is its own, computed now.**
   - A joined, coalesced or recovered follower recomputes its managed `destination_scope` from the evidence that holds at its own commit: every pair of the grant, the current client and target, and the CA of the certificate actually installed.
   - A leader's earlier result never satisfies a follower's present minimum. Invalid or stale evidence gives `unknown`, and a minimum that needs the scope is refused.
   - This closes W4-R04 on the last path the re-check found.
   - **The regressions** (`live_tests/follower_scope.rs`): a decision-joined and a coalesced follower are each refused when the verifying client changes after the leader's commit. The refused follower's binding is cleaned up, and the leader stands. A follower with no minimum commits and reports `unknown`, and one with valid evidence meets the minimum.
2. **W4-C01: releasing a re-issued binding clears what it actually owns.**
   - Release clears every generation the binding owned, from `BINDING_GENERATION` up to the highest it reached, not only the first. K_env stays while another reference keeps the grant live.
   - Release records a durable cleanup obligation in the same transaction, with or without a slot. `managed_cleanup_owed` lists it until the binding's directories and endpoint are verified gone.
   - No migration: the obligation is a store meta row, like `cleanup_intent:`.
   - **The regressions** (`live_tests/cleanup.rs`): a re-issued, slotless parent binding is released while a child keeps the grant live. Its endpoint and files go, and the child still signs with K_env. When the release cleanup fails, the next pass retries it until clean.
3. **The Windows failures share one root cause: a foreign removal used the raw catalog locator.**
   - An own enrollment records the plan's rendered endpoint (`plan::build` step 8). A foreign removal has no plan, and its context took the catalog's raw locator instead. On Windows that is `\\.\pipe\<name>`, never the rendered `//./pipe/<name>`.
   - The existing-access re-check before every step correctly refused it (`existing_access_changed`). On Unix the socket path renders to itself, so only Windows saw it.
   - **The fix (Y-W-Q1, accepted):** both the foreign removal and its admission use step 8's rendering (`plan::catalog_endpoint`). The re-check is unchanged.
   - **The regressions:** `foreign_endpoint_is_the_concrete_rendering`, and the two foreign-removal tests that failed on Windows.
   - The three held-setup tests discarded the drive's error, so they reported `Removing` instead of the real failure. The setup now asserts that its damage landed and reports the drive's outcome. The testkit's registry append verifies its write by reading it back.
4. **Y-W-Q2, confirmed: a foreign removal needs a concrete recorded endpoint.**
   - When the recorded endpoint is absent or not concrete (relative, containing `..`, `SSH_AUTH_SOCK`, or an empty pipe name), admission refuses with `existing_access_endpoint_unrecorded`. Step 8 refuses an own enrollment the same way.
   - Before this, such a removal was approved and then failed at its first step. On Windows its disclosed invocation was also empty.
   - **The regression:** `foreign_removal_refuses_non_concrete_recorded_endpoint`, with a relative socket path on Unix and an empty pipe name on Windows. Nothing is written, no operation opens, and the registry is unchanged.
5. **Round 5 item 4: the Windows client's host-key failure is observed, not assumed.**
   - Windows-only tests print the in-box client's changed-host-key and unknown-host lines as `m03 observation: client_trace_row … field=host_key_failure` lines, ungated, so the row can be recorded from them.
   - The ported "a host-key change ends held, with no rollback" test is gated on the recorded row.
   - **The Win32 9.5p2 row is recorded** in `crates/enroll/src/trace.rs` from native lines only:
     - its matched-path fields from `windows_client_trace_row_observation` at `4866642d`, which spell every field exactly as the portable rows do;
     - its `host_key_failure` set from the `a533fc40` observations: `Host key verification failed.`, `REMOTE HOST IDENTIFICATION HAS CHANGED`, ` has changed and you have requested strict checking.` (changed key, through the real verifier, held with `enrollment_host_key_mismatch`), and `No ED25519 host key is known for` (unknown host, exit 255).
     - The ECDSA and RSA unknown-host forms the 10.5p1 row carries were not observed on 9.5p2 and are not recorded.
   - **The regressions:** two unit tests parse the observed lines with the row (the positive accepted, the negative refused, both host-key traces failures with no other event). Each fails when its row string is changed to an unobserved one (exit 101) and passes restored. On Windows the 16 gated tests then run conclusively, and the native rerun is their evidence.
6. **The supervisor's cleanup and re-issue passes stay serial.**
   - The re-check's adversarial probe ran the ended-binding cleanup pass concurrently with a paused re-issue, and resources were recreated after cleanup had acknowledged the obligation.
   - Production awaits those passes one after another in one supervisor loop, and the startup re-issue precedes that loop, so the probe's interleaving is not reachable. It is not a finding.
   - **The constraint:** they must not run concurrently unless a binding-lifecycle fence first orders a re-issue's restoration against the release cleanup of the same binding.

### 17.25 Orchestrator rulings on wave 5, round 1: the U12 questions (2026-11-13)

**Source:** `tests/evidence/artifacts/review-m03-code/wave5-notes/m03-wave5-questions.md` (round 1 of U12, the CLI and TUI surfaces).

**The terminal and the enrollment loop:**
1. **Q-I1 (U5IO-Q3), the terminal handoff: option (c), final for M03.**
   - Interactive steps keep their own process group and fail closed at the step's bound. Before `Apply`, the CLI refuses an interactive enrollment whose existing-access identity is not agent-held (`INTERACTION_REQUIRED`), and it prints the handoff notice before the first interactive step.
   - Every M03 plan pins an agent (`registry::step::access_pins`), so a valid plan never needs a terminal prompt for its key. The residual: a server that falls back to password or keyboard-interactive authentication still stalls until the bound. The handoff notice says so.
   - Option (b), keeping ssh in the CLI's foreground group, is not scheduled. It needs its own ruling if passphrase-only keys must be enrolled directly.
2. **Q-E2** is recorded as built.
3. **Q-E1: option (b).** In debug builds, the runtime inserts the test pause points when it builds a step, from its own test configuration (`ManagedOptions::script_pause_dir`). The CLI only validates. No `heimdall → heimdall-registry` edge is added, and release builds are unchanged.
4. **Q-E3 and Q-T1: option (a).** `EnrollmentView` gains an optional, additive `hold: {reason, next}` (authorized). The app computes `next` from `record.hold`, so `enroll status` and the TUI show the same command.
5. **Q-E4:** the runtime's `ordinary_ssh_needs_held_slot` note uses `slot_free_command(alias)`, the same command as the preview, `status` and the doctor.
6. **Q-I3:** accepted. The target-change and manual-recovery tests live in `e2e_cli_m03`. The TUI shows the same key diff in its decision modal.

**The issuer:**
7. **Q-IS1, the test store: options (b) and (d), both debug-only.**
   - **(b):** a debug-build test selector chooses a disposable store of a **product** kind: on macOS a file keychain created by the test inside its scratch home and never added to the keychain search list; on Windows DPAPI under the scratch home. The CLI and `internal issuer` reach it through `m03_cmd::issuer_store`. It needs no contract change, and U10B-Q5's "no test store kind on the wire" stands.
     - **The selector refuses** a relative path, a path outside the test's scratch home, any path under the user's `Library/Keychains`, and a path that existed before the test created it. A release build ignores it.
     - Claims made through it stay disqualified by the debug profile (F03).
   - **(d):** in debug builds, a scratch test-kind store's item may be deleted by its exact recorded locator. That proves the R2B order on Linux, which has no disposable Secret Service fixture.
   - Together they unblock the passphrase-on-tty assertions, the `register_issuer` typed-yes test, the restore paths after registration, and `test_ca_ceremony_captures_passphrase_only_from_pty`.
8. **Q-IS2 and Q-U1, a bundle's freshness: option (b) for both.**
   - After the bundle file is completely written and fsynced, the CLI confirms it through an additive issuer request carrying the bundle's `created_at` and SHA-256 (authorized). The runtime records `last_bundle_at` and that digest, and never lowers them. `bundle_stale` then uses `last_bundle_at`, as U10B-Q3 (b) allowed.
   - **Uninstall accepts a `--bundle`** only when the file passes the content check and its SHA-256 equals a digest this installation recorded. The content check: an unredacted `heimdall-recovery-bundle/1`, with `created_at` no earlier than the last enrollment or CA change, listing every non-final enrollment in its current state. A file that is hand-made, foreign, stale or partial is refused `bundle_required`.
   - The record never stores the path.
9. **Q-U3: option (b).** Worker I exposes one retire entry: the decision, the typed `yes`, the wait for `unloaded`, the exact-locator deletion and the `deleted_locator` confirmation. Uninstall runs it inline, behind its typed confirmation, before the runtime stops. Until that entry lands, uninstall offers `heimdall issuer retire <fingerprint>`.
10. **Q-T4, the disclosure texts: option (a), with a limit on TUI approvals.**
    - `heimdall_issuer::ceremony::disclosure_text` becomes public and covers every `DisclosureKind`. The CLI preview and the TUI use it, and nothing retypes a disclosure.
    - **The TUI offers Approve only** for decision kinds whose follow-through needs no owner-present CLI step, and only when it can show every disclosure. Enrollment decisions (`enroll_*`, whose steps the CLI runs on the owner's terminal), issuer registration, rotation, restore (passphrase ceremony) and retirement (R2B deletion) are shown read-only, with their CLI command. So the TUI never approves an `enroll_account` without its exact registry line.

**Uninstall, the doctor and chores:**
11. **Q-U2: option (b).**
    - A plain uninstall with live enrollments lists them and requires a typed `yes`. Without a terminal, or under `--non-interactive`, it exits 3 with nothing changed.
    - `--keep-remote-enrollments` may also serve as the explicit acknowledgement for a plain uninstall, so scripted uninstalls stay possible. The state is kept, so nothing is lost.
12. **Q-U4: the chore follows the time gate.** `time_confirmation_after_reboot` is pending exactly when the time gate would now refuse an issuance for lack of a time reference for this boot, and an issuer CA is registered. A never-confirmed store is therefore included when the gate needs a confirmation. A store with no CA shows no chore.
13. **Q-U5: the doctor emits all three findings in U12.** `reverification_inconclusive` and `enrollment_evidence_stale` are read from the store, read-only. `client_trace_family_unrecorded` comes from the local client's version against `heimdall_enroll::trace::RECORDED`, naming the family and version.
14. **Q-I2: option (a).** `doctor::finding::MANAGED_DIR_UNSAFE` is kept as an additive finding code (authorized).
15. **Q-T6: option (a).** When the cause is no time reference for this boot, the runtime's `TIME_UNCERTAIN` warning carries an additive reason `time_confirmation_after_reboot` (authorized). The TUI keys on that reason, not on the code.

**Connections, the managed report and the lock:**
16. **Q-A1: option (a), the exit code follows the envelope code.**
    - ADR-0006 §5 maps each code to one exit. A `connections close` that the runtime answers `OK` exits 0, whatever its `state`.
    - The human output states plainly when the connection was not closed (`unverified`: identity not verified, nothing signalled; `closing`: still pending), and `--json` carries `state`. `INCOMPLETE_CLOSE_IS_NONZERO` is set `false`.
17. **Q-A2:** the ordinary-ssh sentence stays one constant in the `heimdall` crate's output module, and the CLI and TUI share it. The adapters never print it, so it does not move.
18. **Q-R1: option (a).**
    - `PrepareOutcome` gains an additive `managed: Option<ManagedResultFacts>` (a frozen-port change, authorized here as row M2's amendment). `None` for every M01/M02 adapter.
    - The managed adapter fills it from `report::compute`, on both preparation and re-issue. `Facts` carries it, and `ensure_data` copies the six fields for a managed binding.
    - After a restart the commit uses `Facts::conservative`, the fields stay absent, and the CLI and TUI show "unknown" (fail closed).
19. **Q-T2: option (a).** `inspect destinations` items gain `preference.connection_policy` (`ConnectionPolicyReport`, with the runtime's `connection_wording`), authorized as an additive field.
20. **Q-T3: option (c).** The owned-masters sentence reaches the TUI only through the runtime's wording (items 18 and 19). Nothing moves, and nothing is retyped.
21. **Q-T5: option (a), and the "shown once" reading corrected.**
    - `inspect capabilities` gains a read-only `lock: {behavior, disclosure, acknowledged_at?}` from `Operations::lock_disclosure` (authorized).
    - D9 item 1 shows the disclosure "in the `RegisterIssuer` and first `EnrollAccount` decisions… if not yet acknowledged". So approving **any** decision that displayed it, `RegisterIssuer` or `EnrollAccount`, records `lock_disclosure_acknowledged_at` once. Today only `RegisterIssuer` records it. This must be fixed, with a regression.
22. **Q-R2: option (b).** The `SetLockBehavior` and connection-policy results gain `lock_behavior` and `connection {existing, multiplexing}`, recorded as an additive ADR-0006 row. M01 policy results are unchanged.
23. **Q-R3:** the reading is confirmed. The runtime also calls `ops.set_session_lock_signal(p.signal())` explicitly in `service.rs`, so the label never relies on the default.

### 17.26 Orchestrator rulings on wave 5, round 2 (2026-11-13)

**Source:** `tests/evidence/artifacts/review-m03-code/wave5-notes/m03-wave5-r2-questions.md`.

1. **Q-T2-1: Deny is allowed on every read-only decision view,** after the usual typed `yes`. Deny grants no authority and needs no owner-present follow-through. Approve stays CLI-only for the kinds §17.25 item 10 names.
2. **Q-T2-2, confirmed:**
   - `remove_enrollment` (own and foreign) is read-only in the TUI. Its follow-through is the CLI's step loop on the owner's terminal, so the TUI shows its `heimdall enroll remove …` command, with Deny allowed.
   - `approve_target_change` keeps Approve and Deny. On approval the runtime runs the verification itself, the decision carries no disclosure, and the TUI shows the key diff.
   - `register_issuer`'s command is inferred from the record, with placeholder paths.
3. **Q-I-R2-1 (A2-Q1): the managed-activation validity fix is kept, option (a).**
   - `valid_after` = the later of `now` and the grant's `starts_at` rounded up to the second, minus the 60 s skew allowance. The issuer's ceiling check (`deadline − starts_at + 60 s`) is unchanged and stays strict.
   - The defect made the real issuer refuse every first managed activation (`ceiling_exceeded`). It went unseen because every managed test before round 2 used a fixture issuer.
   - **The rule that follows:** U13's exit suite drives at least one managed activation, one re-issue and one revocation through the real `internal issuer` child on each platform, never only through fixture issuers.
4. **Q-I-R2-2 and C-Q1 to C-Q5, confirmed as built:**
   - `hold.next` is a list of commands in order, omitted when empty;
   - `hold.reason` is a string carrying the `HoldReason` wire name;
   - the shared struct literals gain `reason: None` and `hold: None`;
   - the two M03 policy results report that policy's own stored values, while `inspect capabilities` shows the effective behaviour;
   - `preference.connection_policy` appears only when the runtime can compute it.
5. **E2-Q1 and E2-Q2, confirmed:**
   - `hold` is filled only for `held` records;
   - an unresolved lock holder with no open operation leads to the manual step, then `enroll remove`;
   - a non-evidence-based hold never offers `enroll verify`;
   - the note omits `command` when the alias is unknown;
   - an unusable pause directory refuses every step in debug builds.
6. **The issuer:**
   - **Q-IS2-1, option (a):** the owner-only marker created before the store, with its birth order, ownership and content checks, proves that the test created the store. A home that is the account's home or one of its ancestors is refused.
   - **Q-IS2-2, option (a):** Ctrl-C at a ceremony prompt cancels the read and sends nothing (`NotConfirmed`, exit 3). On Windows, the same rule is checked natively by U13 (item 8).
   - **Q-IS2-3, option (a):** a store never confirms a deletion it did not perform. The displaced-item deletion for a genuinely new locator is a Linux-native row.
   - **Q-IS2-4, option (a):** `issuer.bundle_written` records what the owner's CLI confirms, after refusing a malformed digest or a future `created_at`. Uninstall still needs both the file's content check and a recorded digest.
   - **Q-IS2-5, option (b), in round 3:** the registration decision shows the runtime's conditional D9 lock disclosure (`RegisterDecision.lock_text`, filled from `inspect capabilities`), not the general sentence. The integrator may update the `tests/integration/issuer_store.rs` constructor.
7. **Uninstall, doctor and runtime readings, confirmed:**
   - **Q-U2-1, option (a):** `client_trace_family_unrecorded` is reported only while an issuer CA is registered.
   - **Q-U2-2:** a fresh bundle also lists every registered CA in its current state, because CA state changes carry no timestamp.
   - **Q-R2-1, option (a):** the strictest standing policy covering the pair.
   - **Q-R2-2:** an attached managed binding's result omits the six fields ("unknown"). This fails closed, and it never shows another request's narrowed policy.
   - **Q-R2-3:** `LockSignal::None` is not stored.
8. **U12's Windows interactive tests belong to U13.**
   - These tests need a ConPTY or console harness and the harness sshd: the `#[cfg(unix)]` pty tests of `e2e_cli_m03` and `e2e_tui_m03`, and the DPAPI variants of the issuer ceremony tests.
   - U13 owns the native harnesses (m03-plan U13). It builds that harness and runs these tests on Windows, and U12's acceptance on Windows is closed there.
   - Until then they are listed as **blocked: Windows interactive harness (U13)**, never as passed.

## 18. Consequences

* **New crates** (⟨r2⟩ four; §17.1 item 12):
  * ⟨r2⟩ `heimdall-registry` (**pure**, no I/O): the registry line, marker, scripts and their goldens,
    the HM1 parser, post-image construction and the step classification (`classify_step`); ⟨r3⟩ and
    the **enrollment plan**, `plan::build`, with the D5 §6.1 preconditions and `plan_digest` (§17.4
    item 9; B R2-02). `app` calls it directly, through no port;
  * `heimdall-credential`: vault, certificates, purpose parsing, session-bind, the signer, endpoints;
  * `heimdall-issuer`: child, protocol, client, the `SecretStore` trait and its product
    implementations, backup, ceremony, bundle;
  * `heimdall-enroll` (I/O): the CLI-side `SshStepRunner` and the runtime-side `Verifier`. ⟨r3⟩ It holds
    I/O only.

  New modules: `heimdall-adapters::managed`, `heimdall-runtime::{connections, session_lock}`, `heimdall-app::{enrollment, issuer, managed, lock, issuance_ro}`, and ⟨r2⟩
  `heimdall-localenv::target` (the `TargetEvaluator`, with raw host keys in `known_hosts`).
* ⟨r2⟩ **The crate graph, checked against the Cargo manifests** at `7f6f1c05` (§17.1 item 12;
  M03-R13). Production (`[dependencies]`) edges only. Today's manifests:

  ```text
  contract
  domain    → contract
  store     → contract, domain
  app       → contract, domain, store
  ipc       → contract
  sshconf   → contract, domain
  localenv  → contract, domain, app, sshconf, ipc
  launch    → contract, domain, localenv
  adapters  → contract, domain, app, ipc, localenv
  runtime   → contract, domain, store, app, ipc, localenv, adapters
  heimdall  → contract, domain, app, ipc, runtime, launch, localenv, store, sshconf,
              testkit[app] (referenced only under cfg(debug_assertions), testcfg)
  testkit   → contract, domain, [store], [app], [sshconf], [ipc]   (optional, features)
  ```

  **Revision 1's design had a cycle.** `heimdall-enroll` implemented `app::ports::VerificationRunner`
  (enroll → app), while the app driver called `heimdall_enroll::registry::classify_step` (app → enroll).
  It also had a missing edge: the runtime's preview and step re-evaluation need the static evaluator and
  the known-hosts reader, which live in `heimdall-localenv`. `localenv` already depends on `app`, so
  `app` cannot call it directly.

  **Revision 2:**

  ```text
  registry   → contract, domain                          (new, pure)
  app        → contract, domain, store, registry         (+ registry)
  credential → contract, domain, ipc, app                (new; calls SignatureAuthority,
                                                          implements ⟨r3⟩ VerificationEndpoints)
  issuer     → contract, domain, store, app, credential  (new; app::issuance_ro, IssuerPort)
  enroll     → contract, domain, registry, app           (new; implements VerificationRunner)
  localenv   → (unchanged edges)                         (+ implements app::ports::TargetEvaluator)
  adapters   → … + credential                            (implements ManagedEffects)
  runtime    → … + credential, issuer, enroll
  heimdall   → … + issuer, enroll                        (ceremony, `internal issuer`, SshStepRunner)
  testkit    → … + [credential], [issuer]                (optional feature `managed`:
                                                          ScratchSecretStore, FakeSessionLockSource)
  ```

  * **No cycle.** `app` depends on none of `credential`, `issuer`, `enroll`, `adapters`, `localenv`
    or `runtime`. Every new crate depends on `app`, never the reverse. `registry` depends only on
    `contract` and `domain`.
  * **The only cycles are dev-dependency cycles**, which Cargo allows and the workspace already has for
    `ipc`: the new crates dev-depend on `testkit`, and `testkit` optionally depends on `credential`
    and `issuer`.
  * **Ports carry what flows upward:** `TargetEvaluator` (localenv → app), `ManagedEffects`
    (adapters → app), `IssuerPort` (issuer → app), `VerificationRunner` (enroll → app),
    `SignatureAuthority` and ⟨r3⟩ `VerificationEndpoints` (credential ↔ app), `SessionLockSource` and
    `ConnectionControl` (runtime → app).
  * U0 adds `tools/validation/crate_graph.py` to `check.sh` (`crate-graph` step). It parses the
    manifests, fails on any production cycle, and fails if `app` gains an edge to `credential`, `issuer`,
    `enroll`, `adapters`, `localenv` or `runtime`.
  * ⟨r3⟩ **Revision 3** (§17.4 item 9; A R2-09, B R2-02). Two edges that revision 2 would have needed
    are avoided by construction, and the check is tightened:
    * **No `ipc → app` edge.** `ipc::signing` defines the trait `ReleaseCheck { fn may_release(&self)
      -> bool }` and `PermitGuard(Box<dyn ReleaseCheck + Send + Sync>)`. `heimdall-credential` wraps
      `app::managed::SignPermit` in it; credential already depends on both. ⟨r4⟩ The trait also has
      `fn expires_at(&self) -> tokio::time::Instant`, which cancels the capacity wait (D2 item 3a step 6;
      §17.7 item 2).
    * **The enrollment plan is below `app`.** `EnrollmentPlan::build` lives in `heimdall-registry`, and
      its input types (`TargetEvaluation`, `ApprovedTarget`, the catalog view) in `domain`.
    * **The verification lifecycle goes through a factory port**, `app::ports::VerificationEndpoints`,
      implemented by `heimdall-credential`. `create(operation) -> Box<dyn VerificationSession>` returns
      a session that:
      * generates and registers K_verify, returning its public key;
      * installs a certificate line;
      * counts signatures and session-binds, and exposes its locator;
      * on drop, zeroizes the key and removes the endpoint.

      `app::enrollment::run_verification` reserves and publishes through `Operations`, signs through
      `IssuerPort`, and never names `credential`.
    * **The `crate-graph` step** resolves **package names** to crates. It reads `[dependencies]`,
      `[target.'cfg(…)'.dependencies]` and optional dependencies (features included). It fails on any
      production cycle, and on a forbidden edge: `app` to `credential`, `issuer`, `enroll`, `adapters`,
      `localenv` or `runtime`, and `ipc` to anything but `contract`. Its mutant fixtures are a cycle and
      an `ipc → app` edge (`crate_graph_step_rejects_cycle_and_ipc_to_app_edge`).
* **The `unsafe` inventory** gains three modules (overview §9), each with its own invariant table:
  * `crates/credential/src/sys.rs`: `mlock`/`munlock`, `VirtualLock`/`VirtualUnlock`,
    `prctl(PR_SET_DUMPABLE)`, `setrlimit(RLIMIT_CORE)`;
  * `crates/issuer/src/sys.rs`: macOS keychain SecAccess and generic-password calls with interaction
    disallowed; Windows `CryptProtectData`/`CryptUnprotectData` with `LocalFree` exactly once;
  * `crates/runtime/src/session_lock/sys.rs`: `CGSessionCopyCurrentDictionary`, `CFNotificationCenter`,
    `WTSRegisterSessionNotification`, `WTSQuerySessionInformationW`/`WTSFreeMemory`, and the
    message-only window.

  ⟨r2⟩ The existing `crates/localenv/src/sys/mod.rs` gains `JobObject::spawn_contained` (Windows:
  `CREATE_SUSPENDED`, assignment, then `ResumeThread` on the main thread found through
  `CreateToolhelp32Snapshot`/`Thread32First`/`Thread32Next`). ⟨M02?⟩ That module is still receiving
  M02's Windows fixes. `pidfd_open` and `pidfd_send_signal` go through `rustix` (`process` feature) or
  the existing `platform.rs`.
* **New pinned dependencies** (recorded in `dependencies.md` with licence and rejected alternatives):
  * `ssh-key` features `ed25519`, `encryption`, `rand_core`;
  * `zeroize`;
  * on macOS, `security-framework`;
  * on Linux, a Secret Service client (`secret-service` with the tokio runtime feature) and a D-Bus
    client for logind (`zbus`, shared);
  * `windows-sys` features `Win32_Security_Cryptography`, `Win32_System_RemoteDesktop`,
    `Win32_UI_WindowsAndMessaging` and ⟨r2⟩ `Win32_System_Diagnostics_ToolHelp`.

  U0 pins exact versions at least two weeks old.
* **Store:** migration `0006_managed_credentials`, `SCHEMA_VERSION` 6.
* **The ADR-0007 §2 directive set grows** for `managed_certificate` aliases only (D10). ADR-0007 §14's
  reopen condition "M03/M04 need P to carry CertificateFile" is met by that revision. ⟨r2⟩ So is
  "ControlPath" for the stable per-slot mux path (D8 item 3).
* ⟨r2⟩ **ADR-0007 §8 is amended for owned `ssh` connections on Windows** (kill-on-close job; the
  launcher's death ends the client). ⟨r3⟩ §17.3 item 1 ruled Q18: other programs keep M02's semantics.
* ⟨r2⟩ **ADR-0005 is amended** by §17.1 items 10 (destination-clock measurement; §3.6) and 13 (per-pair
  runtime evidence; §7.4 row 1), as the rulings state.
* **M02 residuals handed to M03** (ADR-0007 §13):
  * agent-endpoint discovery's `Include` expansion becomes client-aware (§12.34 item 3);
  * a writing `ProjectionConfig` without `state_dir` is refused (§12.34 item 6);
  * the three Git residuals of §12.41 stay disclosed residuals, re-deferred to M07 with a decision:
    they do not interact with managed credentials;
  * QR17's binding requirement is D7 item 5.
* **Compatibility matrix:** rows for `managed_certificate` × {ssh, Git, scp, sftp} × {macOS, Linux,
  Windows} × {lock continue, lock revoke}, plus the custody rows per store. Every label stays
  `not-tested` until its record is `verified` and its claim-table entry lands.
* **Uninstall (M02)** gains: it lists remaining remote enrollments with their markers and the recovery
  bundle path, offers `enroll remove` first, and ⟨r2⟩ follows D4 item 6: a fresh bundle before a purge
  that keeps enrollments, and the K_ca store item's fate stated (spec §7.7; R-DI-04).

---

## 19. Reopen conditions

* **F-1** on a supported platform: the A03 lock row fails for the in-memory signer or issuer. Change
  custody (hardware, a separate service), not wording (ADR-0005 §13).
* **The issuer child** cannot be kept off a reachable path on some platform, or a same-user process
  reaches K_ca through it in the A10 or A33 tests.
* **The remote protocol** fails on a target server's `/bin/sh` (M-F10), or a target sshd reads a
  registry Heimdall did not write, so that the positive check passes on the wrong file.
* **A client** sends no `session-bind` and the purpose check proves insufficient, or a client signs
  before the server's query acceptance (M-F1), which breaks the zero-signature negative oracle.
* **Windows multiplexing** becomes available (M-F7), or a mechanism that stops admissions on a live
  master gracefully is tested (ADR-0005 §13).
* **G05** changes how bound contexts select an agent (Q15).
* **The owner or orchestrator rules differently** on Q1–Q17, or reopens an ADR-0005 or ADR-0004 item.
* **M02's exit** changes an interface marked ⟨M02?⟩ (m03-plan §0.4).
* ⟨r2⟩ A target client's `-v` trace cannot distinguish a public-key refusal from a transport failure
  (M-F22), so the negative verification can never pass on it.
* ⟨r2⟩ A target remote shell lacks an atomic `mkdir` or `awk srand()` (M-F23), so the fence or the
  clock measurement cannot run there.
* ⟨r2⟩ A client accepts `-o CertificateFile=none` in a way that lets P's certificate reach Heimdall's
  signer during maintenance (Q19), or `maintenance_invocation_never_contacts_heimdall_signer` fails.
* ⟨r3⟩ A target client runs `KnownHostsCommand=none` as a command, or accepts a key outside the
  generated file in any wrong-key fixture (Q22, Q23).
* ⟨r3⟩ A target's sshd does not make the session's shell a process-group leader, or the target's start
  identity cannot be read (M-F30), so the fence cannot run there.
* ⟨r3⟩ `maintenance_inside_managed_run_context_zero_managed_signatures` fails on any client.
* ⟨r3⟩ The orchestrator rules Q22–Q25 differently from their defaults.
* ⟨r4⟩ A target shell's group-proof control or listing fails routinely (for example a BusyBox build
  without `ps -A`), so every stale lock there ends in manual recovery (M-F33).
* ⟨r4⟩ The orchestrator rules Q26–Q28 differently from their defaults.
* ⟨r5⟩ A BusyBox release accepts `--` in `kill` and `-p` in `ps`, so its fence could become automatic.
  That needs a new ruling, because §17.10 item 5 claims manual recovery only.
* ⟨r5⟩ The orchestrator rules Q29 differently from its default.
* ⟨r6⟩ Deterministic tests or field reports show a narrowing's reported commit time routinely above the
  20 s target at the stated budgets, or above its derived bound. Above the bound means an assumption
  (A1–A5) is wrong.

---

## 20. ⟨r2⟩ Change log (revision 2, task M03-T00-design-fix)

Every round-1 finding, with the §17.1 ruling that decided it and where this ADR closes it. The plan's
change log (m03-plan §9) lists the plan-side changes.

| Finding | Ruling | Closed in this ADR |
|---|---|---|
| M03-R01 sign and revoke unlinearized | 1 | D2 item 3a; D7 item 2 steps 0 and 5; M-F24; §17.2 Q21 (the test's pause point) |
| M03-R02 remote steps not bound to the approved target | 2 | D5 §6.1 (approved target, account override refused); §6.3 (route re-evaluation, target pins); §6.5 item 3 (verification from the approved target) |
| M03-R03 negative accepts transport failure | 3 | D5 §6.5 item 5 and the classification tables; M-F22; D13 item 2 (fault fixtures) |
| M03-R04 maintenance through P | 4 | D5 §6.3 (existing-access pins); D11 item 3; M-F20; §17.2 Q19 |
| M03-R05 re-verification rolls back | 5 | D5 §6.2 (`reverifying`), §6.5 (re-verification column) |
| M03-R06 unfenced mutation after timeout | 6 | D5 §6.3 (lock, window, token, exit codes 40–42, hard deadline), §6.7 (fencing before classification) |
| M03-R07 state table gaps | 7 | D5 §6.2 (20-state table; `verifying → held`, `outcome_unknown → withdrawn`, `rollback_unknown` versus `remove_unknown`, `→ abandoned`) |
| M03-R08 Windows holder ≠ connection; `connect` binds nothing | 8 | D8 item 2 (separate records, job object, registration, `connect` flow); M-F21; §17.2 Q18 |
| M03-R09 lock events lost by `watch` | 9 | D9 item 3 (latched epoch) |
| M03-R10 residual cleared at local expiry | 10 | D5 §6.5 item 4 (clock measurement); D7 item 3 (statuses) |
| M03-R11 backup digest before backup; retirement not durable | 11 | D4 item 1 (prepared bytes), item 3 (retirement states) |
| M03-R12 foreign target incomplete; system-form removal | 11 | D4 item 5 (`ForeignRemovalTarget`, separate table); D5 §6.9 (manual removal and absence check) |
| M03-R13 crate cycle; preparation contract; raw host keys; read-only check | 12 | §18 (graph and `crate-graph` step); D6 item 0 (`ManagedEffects`, `IntegrationSnapshot.managed`); D3 item 4 (`app::issuance_ro`, `assess_read_only`); D5 §6.1 (`TargetEvaluator` with raw host keys) |
| M03-R14 passphrase in argv | 17 | D13 item 1 |
| M03-R15 master ControlPath against P | 16 | D8 item 3 (stable per-slot path); D10 item 1 |
| F01 negative passes on any failure | 3 | as M03-R03 |
| F02 Windows strict hits the launcher | 8 | as M03-R08 |
| F03 test store claims macOS lock continuity | 13 | D12 item 3 (build profile and store kind); D1 test K_ca row; D6 item 6 (`issuer_store_unlocked_at_start`) |
| F04 `ensure` broken while the projection is pending | 15 | D5 §6.6 |
| F05 E5 resets the projection; removal degrades too much | 15 | D5 §6.4 E5, §6.6, §6.8; D4 item 3; §17.2 Q20 |
| F06 system-form path; re-verify; `abandoned`; retirement | 5, 7 | D5 §6.2, §6.5, §6.9; D4 item 3 |
| F07 foreign removal across installations | 11 | D4 item 5 |
| F08 uninstall; `--replace-orphan` | 11 | D4 item 1 (crash points), item 6 |
| F09 lock procedure shares a slot | 17 | D13 item 7 (and m03-plan §4.4) |
| F10 A10 worker test overclaims | 13 | D12 item 6 |
| F11 `revocation.remote` ungated; ADR-0005 §7.4 departure | 13 | D12 item 3 |
| F12 signature after the tombstone | 1 | as M03-R01 |
| F13 password-only accounts | 14 | D5 §6.1, §6.3, §6.10 |
| F14 "background work once" ignores reboot | 17 | D6 item 6 |
| F15 revoke results and deadline wording | 18 | D7 item 2 step 4; D8 item 6; D10 item 6 |
| F16 master ControlPath contradiction | 16 | as M03-R15 |
| F17 purpose check accepts any pair's account | 18 | D2 item 4 |
| F18 `pending` instances at restart | 18 | D2 credential-instance table |
| F19 unconditional disclosure; Linux unverified | 18 | D9 items 1 and 3 |
| F20 roles of Step, StepResult, Reconcile | 14 | D5 §6.3, §6.7, §6.10 |
| F21 time assessment writes | 12 | D2 item 3; D3 item 4 |
| F22 ptrace test without a control | 17 | M-F19; D13 item 8 |
| F23 `SecretStore` ownership; `ScratchTest` in the schema | 12 | D1 test K_ca row; D3 item 4 |
| F24 linearization model lacks re-issue | 1 | §1.3; D2 item 3a |
| F25 `StepResult.stdout` too large | 18, P7 | D5 §6.3 |
| F26 the lowest-row rule in the exit mapping | 17 | m03-plan §3 (plan-side) |
| F27 freshness becomes a chore | Q11 | D5 §6.5 (supervisor re-verification) |

---

## 21. ⟨r3⟩ Change log (revision 3, task M03-T00-design-fix)

Every round-2 finding, with the §17.4 ruling that decided it and where this ADR closes it. "A" is
reviewer A (`round2-a-codex.md`), "B" is reviewer B (`round2-b-opus.md`). The plan's change log
(m03-plan §10) lists the plan-side changes. §17.3's rulings on Q18–Q21 are applied in D2 item 3a, D5
§6.3 and §6.8, D8 item 2, §18 and §19.

| Finding | Ruling | Closed in this ADR |
|---|---|---|
| A R2-01 inherited `KnownHostsCommand` defeats the key pin (blocker) | 1 | D5 §6.3 (host-trust pin table, `NoHostAuthenticationForLocalhost` added by the check, the effective-configuration check); §6.5 item 3; M-F25; D13 item 2 (wrong-key fixtures); §17.5 Q22, Q23 |
| A R2-02 stale writer appends after its lock is broken (blocker) | 2 | D5 §6.3 (holder-recording lock, proven termination, not-after, start identity per target shell); §6.7 (fencing first, `late_write`, the paused-writer test); §6.2 (`lock_holder_unresolved`); M-F30, M-F31; §16 |
| A R2-03 lock acquisition fails when the registry directory is absent | 3 | D5 §6.3 (`bootstrap` script, exits 32 and 33); §6.4 (E2b); §6.1 (shown in the plan) |
| A R2-04 maintenance reaches the managed signer through `SSH_AUTH_SOCK` | 4 | D5 §6.1 (endpoint precondition); §6.3 (existing-access endpoint); M-F29; §17.5 Q24 |
| A R2-05 system-form cancel paths unsafe | 5 | D5 §6.2 (`removal_origin`; `manual_pending` cancel); §6.9 (enroll item 5, remove item 4) |
| A R2-06 no expiry check at the enqueue; unbounded `sign` | 6 | D2 item 3a (permit expiry, `signing_budget`, release check); §18 (`PermitGuard`) |
| A R2-07 owned connections may fork | 7 | D8 item 2 (foreground; option refusals); D5 §6.3 and §6.5 item 3; D8 item 3; D10 item 4; M-F28 |
| A R2-08 Windows resume before registration; registration not ordered with revocation | 8 | D8 item 2 (Windows steps 2–4) |
| A R2-09 verification lifecycle has no port; `ipc → app` edge | 9 | §18 (`VerificationEndpoints`, `PermitGuard`, the plan in `heimdall-registry`, the tightened check) |
| B M03-R2-01 gate bodies land after their callers | 6 | D2 item 3a ("Who writes the bodies") |
| B M03-R2-02 `SignPermit` crate; `EnrollmentPlan::build` above `app` | 9 | §18 |
| B M03-R2-03 cascade set, lock order, closing under the gate | 6 | D2 item 3a (lock order, re-read, delegation hold, order within a narrowing, bounds); D7 item 2 |
| B M03-R2-04 script start unbounded; stale stdin | 2 | D5 §6.3 (not-after, ready handshake, step-runner lifetime); §6.7 (`late_write`, `script_started_after_not_after_writes_nothing_exit_41`) |
| B M03-R2-05 `held` has no owner exit; re-enrollment blocked | 5 | D5 §6.2 (`held` exits, `ApproveTargetChange`, `abandoned` outside the uniqueness rule); §6.8 (fresh target); §6.1 (uniqueness row); §17.5 Q25 |
| B M03-R2-06 initial-verification retry under a lapsed approval | 5 | D5 §6.2 (`verifying`, `applied_unverified`); §6.5 (classification) |
| B M03-R2-07 foreign removal state and host cross-check | 10 | D4 item 5 |
| B M03-R2-08 `principals_not_enforced` fixture cannot produce it | 11 | M-F27; D13 item 2 |
| B M03-R2-09 client updates strand verification | 11 | D5 §6.5 item 5 (release families, doctor finding); freshness (prompt re-verification) |
| B M03-R2-10 truncated script runs a prefix | 2 | D5 §6.3 (script hardening); M-F26 |
| B M03-R2-11 hard deadline void after a reboot | 2 | D5 §6.3 (bounds: wall deadline and boot ID) |
| B M03-R2-12 Unix row written after bind | 8 | D8 item 2 (Unix) |
| B M03-R2-13 destination lag classified as failure | 11 | D5 §6.5 (`destination_clock_skew`, the skew rule) |
| B M03-R2-14 `awk %c` locale | 2 | D5 §6.3 (`LC_ALL=C`); M-F32 |
| B M03-R2-15 release builds "ignore" the test variables | 12 | D13 item 5 |
| B M03-R2-16 Q18–Q21 read as open; blocked list incomplete | 12 | header; §17 intro; §17.2 note; D2 item 3a (Q21); D5 §6.3 (Q19), §6.8 (Q20); D8 item 2 (Q18); §18; §19. The blocked records are listed in m03-plan §3 and §7 |
| B M03-R2-17 U9 wave, port signature, operations body | 9 | plan-side (m03-plan U9, U0b, §2) |
| B M03-R2-18 ordinary `ssh` needs a held slot, undisclosed | 12 | D10 item 2 |

---

## 22. ⟨r4⟩ Change log (revision 4, task M03-T00-design-fix)

Each round-3 finding, with the §17.7 ruling that decided it and where this ADR closes it. The plan's
change log (m03-plan §11) lists the plan-side changes. §17.6's rulings on Q22–Q25 are already the D
sections' defaults.

| Finding | Ruling | Closed in this ADR |
|---|---|---|
| M03-R3-01 (blocker): a failing group probe read as "gone" | 1 | D5 §6.3: the group-gone proof (control, POSIX probe, listing, agreement table), the decision (`gone`, `alive`, `unproven`), termination only for `alive`, the per-shell table, and the `fence` row with exit 44. §6.7: `unproven` handling and the leader-absent tests. M-F33 |
| M03-R3-02: expiry during the enqueue wait | 2 | D2 item 3a, steps 6–8 (capacity reserved first, expiry cancels the wait, release check, non-waiting enqueue), and its tests; M-F33 (transport) |
| M03-R3-03: out-of-order acquisition when the set grows | 3 | D2 item 3a (global order always; the pending mark; release and reacquire once; the one-round argument; the bound `(rounds + 1) × signing_gate_max_wait`); D7 item 2 step 0; §17.8 Q26, Q27 |
| M03-R3-04: foreign removal missing from the frozen table | 4 | D4 item 5 (admission events, the subset, the system-form route, the tests); D5 §6.2 (`planned`, `manual_removal_pending` and `removal_verifying` rows); §6.9; §17.8 Q28 |
| M03-R3-05: the approved target replaced before a pass | 5 | D5 §6.2 (`held` and `reverifying` rows); §6.5 item 3 (the proposed target on the operation) |

---

## 23. ⟨r5⟩ Change log (revision 5, task M03-T00-design-fix)

Each round-4 finding, with the §17.10 ruling that decided it and where this ADR closes it. The plan's
change log (m03-plan §12) lists the plan-side changes. §17.9's rulings on Q26–Q28 are the D sections'
defaults, now marked ruled.

| Finding | Ruling | Closed in this ADR |
|---|---|---|
| M03-R4-01: pending checked only by the pre-check; round-1 descendants unmarked; a 24.6 s commit | 1 | D2 item 3a: the pre-check is only an optimization; step 4's first check is the mark; step 7's release check adds it; ancestor coverage; delegation re-checks; round 1 marks before releasing; the bound re-derived with assumptions A1–A5; tests for both re-check traces. D7 item 2 step 0 |
| M03-R4-02: a foreign system-form record could be cancelled to `withdrawn` after `ca_not_held` | 2 | D5 §6.2 `manual_removal_pending` row; D4 item 5 (abandon, pinned origin, the golden's two paths, the tests); §6.9 |
| M03-R4-03: no request and commit times in the revocation result | 3 | D7 item 2 step 0 (capture points, replay); D12 item 1; §15 |
| M03-R4-04: exit 44 read as "nothing signalled" | 4 | D5 §6.3 (exit 44 means no unlock, and no further signal; the signals sent are reported and audited), the `fence` row; §6.7 |
| Per-shell probe table (ruling 5) | 5 | D5 §6.3 shell table (observed rows for dash 0.5.12, bash 5.2 as `sh`, BusyBox 1.37.0 and macOS `sh`; BusyBox always `unproven`, manual recovery); M-F34; §17.11 Q29 |

---

## 24. ⟨r6⟩ Change log (revision 6, the last design fix; task M03-T00-design-fix)

The two round-5 findings, with the §17.13 ruling that decided each and where this ADR closes it. The
plan's change log (m03-plan §13) lists the plan-side changes. §17.12's ruling on Q29 is the D sections'
default. Revision 6 raises no new question.

| Finding | Ruling | Closed in this ADR |
|---|---|---|
| M03-R5-01: the bound undercounted round 1's reads and omitted holders; a 20 s ceiling would abort a valid narrowing | 1 | D2 item 3a: the order within a narrowing (key destruction only under the gates; file removal and process closing after release); "earlier marks go first"; never aborted for time; every holder counted (signers, delegations, connection registration, other narrowings); reads `r + 3` in all, of which round 1 is `(r + 1)·t_read`; the bound `H + R(N) + Σ R(X)`; the budgets; 20 s as a target; the two countermodel tests. D7 item 2 steps 0, 2 and 4 |
| M03-R5-02: a field-5 lookup without the last-`)` rule | 2 | D5 §6.3: the shared `/proc/<pid>/stat` parser (the last `)`, token 3 for the process group, token 20 for the start time, validation, the awk text, `domain::procstat::parse`, fixtures with spaces, parentheses and a newline); the lock's process-group check; the shell table's start-identity and process-group cells; M-F35; §17.11 Q29 note |
