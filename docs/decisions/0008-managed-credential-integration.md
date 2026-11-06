# ADR-0008 — Managed credential integration (M03): the B1 signer and issuer, scoped enrollment, deadline and connection control, lock behaviour

**Status:** proposed, revision 2 · **Date:** 2026-11-06 · **Tasks:** M03-T00-design (revision 1),
M03-T00-design-fix (revision 2)
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
| ⟨r2⟩ M-F23 | POSIX `mkdir` fails if the directory exists (an atomic test-and-create, usable as a lock); POSIX `awk 'BEGIN { srand(); print srand() }'` prints the current time in seconds since the Epoch (POSIX `date` has no `%s`) | [I] (POSIX.1-2017, not pinned). Settled per remote shell by `registry_protocol_on_target_shell` and `remote_clock_reading_per_target` (U5) |
| ⟨r2⟩ M-F24 | `rusqlite` transactions release the store's connection mutex when they return (`crates/store/src/lib.rs` `transaction`), so an authorization read cannot by itself hold anything across the signature | Observed (R01) |

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
     2. a **pre-check** authorization (an unlocked read, used only to refuse early);
     3. take the grant's gate **shared**, waiting at most `signing_gate_wait` (1 s), else refuse;
     4. a **fresh** authorization read under the gate. This is the check that admits;
     5. `KeyVault::sign`;
     6. hand the response frame to the connection's outbound buffer, bounded by
        `signing_enqueue_timeout` (2 s). A response that cannot be enqueued in time is dropped, and the
        connection is closed without it;
     7. release the gate.

     The `SignPermit` returned at step 4 is the shared guard: `ipc::signing::serve` drops it only after
     step 6. **The enqueue at step 6 is the linearized effect.**
   * **Narrowing commits:**
     * a revocation (explicit, cascade, `revoke_on_lock`, and authority withdrawn at re-validation);
     * a cutoff that is set or moved earlier;
     * an environment-permission removal;
     * an enrollment hold or removal that degrades a pair (D5 §6.8);
     * every other change that narrows a grant.

     Each takes the gate **exclusively**, for every grant it affects (the cascade included), **before**
     its store commit. A revocation holds the gate until the grant's keys are destroyed (D7 item 2), and
     other narrowings hold it until their commit.
   * **Bound.** A shared holder is bounded: 2 s of authorization, the signature, and 2 s of enqueue.
     So a narrowing waits at most `signing_gate_max_wait` (5 s). A holder that exceeds its bound is
     cancelled (its response dropped and its connection closed), so the bound holds.
   * **Result:** every signature is either enqueued before the narrowing's commit or refused. None is
     enqueued after a revocation has been acknowledged.
   * **Tests (U2):**
     * `sign_paused_after_precheck_then_revoke_is_refused`: deterministic. The signer is paused right
       after the pre-check authorization; the revocation commits; the signer is resumed; its fresh read
       under the gate refuses;
     * `sign_paused_inside_gate_delays_revoke_and_is_enqueued_before_commit`;
     * `no_signature_enqueued_after_revocation_acknowledged`;
     * the uncontrolled-interleaving test, added on top, never instead.

     The linearization model (U3) covers activation, re-issue and lock revocation against the gate
     (F24).

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
     item 15's rule, held by Q20 for the case where another verified enrollment remains.
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
   * per enrollment: marker, destination ID, ⟨r2⟩ the alias, hostname and port when not redacted,
     account, registry path, form, state, the full public CA line's SHA-256 (`line_sha256`);
   * the removal instructions.

   It is refreshed automatically: `issuer status` and every enrollment change report its staleness.

   ⟨r2⟩ **Foreign removal** (§17.1 item 11; M03-R12, F07) goes from another device with existing
   access:

   ```
   heimdall enroll remove --from-bundle <file> --marker <marker> --alias <local alias>
   ```

   * **The target** is the full public removal descriptor `ForeignRemovalTarget`:
     * the **local alias** on this device;
     * the bundle's destination ID (as a label: destination IDs are per installation);
     * account, marker;
     * the CA **public key**;
     * `line_sha256`;
     * registry path and form.

     The decision `RemoveEnrollment` and the request hash cover all of it.
   * **Before connecting**, the line is rebuilt from the CA public key, the principal and the marker,
     and its SHA-256 is checked against `line_sha256`. A mismatch refuses.
   * **A redacted bundle is refused clearly** (`bundle_redacted`): without hostnames, the local
     alias's evaluated host cannot be cross-checked against the bundle's host.
   * **The route and host key** are this device's: its catalog's alias, approved for the removal
     like any remote step (D5 §6.3).
   * **Records.** Foreign removals live in their own table `foreign_removals`, with **no foreign key**
     to `issuers`, because the CA is not registered here.
   * **System form.** A system-form entry in a bundle is never removed by Heimdall. It gets the manual
     instructions of D5 §6.9.
   * **Test:** `foreign_removal_from_second_installation_with_different_catalog` (U10).

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
| No enrollment for this (pair, CA) is in a non-final state | `CONFIG_CONFLICT`, `already_enrolled` |
| `--registry-path`, when given, is absolute POSIX, ≤ 255 bytes, from `[A-Za-z0-9._/-]`, with no `..` component | `USAGE_ERROR` |

The preview is **local and passive**. It contacts nothing; reading the remote registry is a step of
`apply`. Its plan names:
* destination and account;
* ⟨r2⟩ the approved target (HostName, Port, User, empty proxy chain, host key);
* ⟨r2⟩ the **existing-access invocation** every remote step will use (§6.3), with the identity and
  its endpoint;
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
* `state`, `verified_at`, `evidence: { client, server, verified_by_operation, ⟨r2⟩ clock:
  ClockMeasurement | unmeasured }`;
* `created_at`, `updated_at`.

The marker is `heimdall:<enrollment-id>`. It is opaque and is the add's idempotency key.

⟨r2⟩ The table is reconciled with the stage receipts and outcomes before it is frozen (§17.1 item 7;
M03-R07, F06). It has 20 states. **Every** documented recovery path has a test, not only every pair of
the table (plan U0 `enrollment_recovery_paths_each_tested`).

| State | Form | Meaning | Allowed transitions (event) |
|---|---|---|---|
| `planned` | both | Operation admitted, awaiting the owner decision | `applying` (account: `EnrollAccount` approved); `manual_pending` (system: `EnrollSystemForm` approved); `withdrawn` (denied, cancelled, or the decision is stale; nothing written) |
| `applying` | account | The approved operation is running; nothing remote is known written | `applied_unverified` (append confirmed, or `already_present` with the exact line); `outcome_unknown` (the step's result was lost or timed out); `failed_unwritten` (refused before any write: not manageable, provider locked, host trust, route changed, window expired); `held` (post-write check failed); stays `applying` on `busy` (bounded retries, §6.3) |
| `outcome_unknown` | account | The append may or may not have applied | `applied_unverified` (reconcile: exactly one exact line); `applying` (reconcile: marker absent **and** the fencing conditions of §6.7 hold, within the approval's validity, on an attended session); `held` (damaged line or two marker lines); ⟨r2⟩ `withdrawn` (marker absent after fencing and the approval lapsed: `DECISION_STALE`, `approval_lapsed`); ⟨r2⟩ `abandoned` (owner); stays while unreachable or while the old step's lock may still be live |
| `held` | both | Our marker or trust is present but wrong, or a check failed in a way that needs the owner. Nothing automatic happens | `removing` (account: `RemoveEnrollment`); `manual_removal_pending` (system); `abandoned` |
| `applied_unverified` | account | The exact line is present; no positive and negative verification has passed | `verifying`; `removing` (`RemoveEnrollment`); `abandoned` |
| `manual_pending` | system | Approved; waiting for the owner to apply the sshd lines (§6.9) | `verifying` (owner confirms applied); `withdrawn` (owner cancels: Heimdall wrote nothing) |
| `verifying` | both | The **initial** verification (§6.5) is running | `verified` (pass); `rollback_pending` (account: failure with refusal evidence, or principals not enforced); `manual_pending` (system: failure or inconclusive, with the finding); `applied_unverified` (account: inconclusive or unreachable); ⟨r2⟩ `held` (host-key mismatch: no rollback over an untrusted host; or system form with principals not enforced) |
| `verified` | both | Positive passed with exactly one signature and the negative was refused with full refusal evidence (§6.5). `destination_scope: verified_server_principals` may be claimed for the pair | ⟨r2⟩ `reverifying`; `removing` (account: `RemoveEnrollment`); `manual_removal_pending` (system) |
| ⟨r2⟩ `reverifying` | both | A **later** verification (§6.5, owner or supervisor). Never removes anything (§17.1 item 5) | `verified` (pass: freshness renewed; **or** unreachable or inconclusive: unchanged freshness and a doctor finding); `held` (failure: `principals_not_enforced`, or positive refused with refusal evidence; grants under that CA for that pair degraded) |
| `rollback_pending` | account | The initial verification failed; removing our line under the enrollment decision | `verification_failed` (removed); ⟨r2⟩ `rollback_unknown` (the remove step's result was lost); `held` (`registry_changed` three times, or not rewritable: manual instructions); ⟨r2⟩ `abandoned` |
| ⟨r2⟩ `rollback_unknown` | account | The rollback's removal may or may not have applied. It keeps the **rollback** purpose | `verification_failed` (reconcile: marker absent); `rollback_pending` (reconcile: present); `abandoned`; stays while unreachable |
| `removing` | account | **Explicit** owner-decided removal running (`RemoveEnrollment`) | `removed`; `remove_unknown`; `held` |
| `remove_unknown` | account | The explicit removal may or may not have applied. It keeps the **explicit removal** purpose | `removed` (reconcile: marker absent); `removing` (reconcile: present); ⟨r2⟩ `abandoned`; stays while unreachable |
| ⟨r2⟩ `manual_removal_pending` | system | The owner is to remove the sshd lines; Heimdall shows them | `removal_verifying` (owner confirms removed); `verified` (owner cancels) |
| ⟨r2⟩ `removal_verifying` | system | The absence check runs (§6.9) | `removed` (absence verified); `manual_removal_pending` (still accepted, or inconclusive) |
| `verification_failed`, `removed`, `withdrawn`, `failed_unwritten` | — | Final; no trust of ours remains, as last observed. `removed` for the system form means **absence verified**, never "removed by Heimdall" | none |
| `abandoned` | both | The owner gave the account up while unreachable, held or uncertain. Trust may remain. Reported `pending_until_line_removed`; listed by uninstall and the bundle | `removing` (account, a new `RemoveEnrollment`); `manual_removal_pending` (system) |

A pair is usable for managed issuance only through a `verified` enrollment (`reverifying` counts as
`verified` while it runs). Those are the only states that add the CA to the pair's issuable set. ⟨r2⟩
**CA retirement** requires every enrollment of that CA to be final or `abandoned` (D4 item 3).

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
     `remove`, `started` for `inspect`. Only then does it return the step: `{stage, step_token,
     script, client, pins, alias, remote_command, timeout_ms, hard_deadline}`, where `step_token` is
     128 random bits.
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
needed. The step's stage receipt is not written in that case.

**Invocation.** Every remote step is **one** `ssh` process:
* the verified client from M02's client inventory, named in the step;
* the user's ordinary configuration for everything not pinned (P included);
* ⟨r2⟩ the **pins**, all passed with `-o` (command-line values are read first and win, F1):
  * **target** (§17.1 item 2): `HostName=<approved>`, `Port=<approved>`, `User=<approved>`,
    `ProxyCommand=none`, `ProxyJump=none`, `HostKeyAlias=hm-target-<16 hex>`,
    `UserKnownHostsFile=<runtime_dir>/e/<16 hex>/known_hosts`, `GlobalKnownHostsFile=<runtime_dir>/e/<16
    hex>/empty`, `StrictHostKeyChecking=yes`, `CheckHostIP=no`, `UpdateHostKeys=no`. The known_hosts
    file is written by the runtime before it returns the step, owner-only, and holds exactly one line:
    the alias with the approved host key;
  * **existing access** (§17.1 item 4; M03-R04), for **every** remote step, the initial append
    included. The maintenance steps (rotation, removal, rollback, reconcile) are what the ruling names;
    the initial append gets the same pins so that one invocation is shown and approved:
    * `IdentityAgent=<the identity's endpoint, or SSH_AUTH_SOCK for an identity used through the
      session's agent>`;
    * `IdentityFile=<the adopted public key file>`, `IdentitiesOnly=yes`;
    * `CertificateFile=none`, held by Q19 (M-F20);
    * `ControlMaster=no`, `ControlPath=none`;
  * **narrowing:** `BatchMode=<yes when non-interactive>`, `ForwardAgent=no`,
    `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `RequestTTY=no`;
* `-T`, then the alias, then the remote command `exec /bin/sh -s`.

The script is written to the child's stdin.

* **Why the managed credential is never used.** The pinned `IdentityAgent` replaces P's environment
  endpoint, and K_env lives only in Heimdall's signer, which that agent cannot reach. So a maintenance
  step never depends on the credential it repairs. Its tests run with every managed binding released
  and the issuer unavailable (plan U5, U10).
* ⟨r2⟩ **ADR-0007 §9 item 1** keeps tests from adding `IdentityFile`, `HostName` and similar options,
  so that the configuration under test is what decides. These pins are product behaviour, pinning the
  approved target and identity, and are tested as product output.
* The remote login shell interprets only `exec /bin/sh -s`. Every value is a validated literal inside
  the script, in single quotes:
  * the line's character set (`[A-Za-z0-9+/=,:" ._@-]`) contains no `'`;
  * paths are validated (§6.1).
* Host trust is never weakened. A host-key failure (exit 255 with "Host key verification failed")
  maps to `HOST_TRUST_CHANGED`.

Bounds:
* stdout ≤ 512 KiB and stderr ≤ 64 KiB (excerpt 4 KiB), read concurrently;
* connect 30 s;
* total 120 s, or 300 s for an interactive step that may wait on a provider approval;
* ⟨r2⟩ the step's **hard deadline** is its issue time + `timeout_ms` + the script's mutation window
  (60 s) + 30 s, on the runtime's continuous clock.

**Output.** Line-oriented: `HM1 <key>=<value>`. Values are decimal, a fixed token, or lowercase hex
produced by `od -An -v -tx1`, never raw bytes. The first line must be `HM1 v=1`. Otherwise the remote
shell is not POSIX, or something printed before the script ran, and the step fails with
`registry_unsupported`, writing nothing.

**Utilities** (M-F10, M-F23): `sh`, `id`, `ls`, `test`, `cat`, `cmp`, `od`, `tail`, `grep`, `awk`,
`mkdir`, `chmod`, `mv`, `rm`, `printf`. No `stat`, `sha256sum`, `base64`, `xxd` or `date +%s`, because
none is POSIX.

⟨r2⟩ **Fencing: a per-account lock** (§17.1 item 6; M03-R06). Every mutating script (`append`,
`remove`) runs its critical section under a lock beside the registry:
1. **Take the lock:** `mkdir <registry dir>/.hm-lock.<registry name>` (atomic; M-F23). Write the step's
   token into `token` inside it, and record the script's start time from `awk` (M-F23).
2. A lock that already exists, with another token, makes the script exit **40 `busy`** with nothing
   changed. The runtime retries a busy step with bounded, jittered backoff (3 attempts), then reports
   `CONFIG_CONFLICT`, reason `registry_busy`.
3. **Just before the mutation**, the script re-checks two things:
   * the elapsed time since its start is within the **mutation window** (60 s), else it exits **41
     `window_expired`** with nothing changed;
   * the lock still holds its own token, else it exits **42 `lock_lost`** with nothing changed.
4. It then mutates, reads back, and **releases** the lock by removing exactly its own lock directory
   (the token is checked first).

A lock whose step's **hard deadline** has passed is **stale**. Only `reconcile` breaks it (§6.7): it
renames it aside (`mv <lock> <lock>.stale.<16 hex>`), re-reads the registry, and then removes the
renamed directory. A script that resumes after its lock was broken therefore exits 41 or 42 without
writing.

**Scripts** (generated by `heimdall_registry::script`; release builds byte-compare them against
goldens, and the test configuration adds pause points):

| Script | Does | Exit codes |
|---|---|---|
| `inspect` | Resolves the registry path. Reports the directory (present/absent; mode string from `ls -ldn`; owned by `id -u`), the file kind (`regular`, `absent`, `symlink`, `other`), link count, mode string, owner, size, whether the last byte is `0a`, the number of lines containing the marker, the content as hex (≤ 128 KiB), ⟨r2⟩ the lock state (`none`, or `held` with its token and age from the remote clock), and the remote clock reading | 0 ok; 30 not manageable (reports why); 31 too large |
| `append` | ⟨r2⟩ Under the lock. (1) Directory: `mkdir -m 0700` when absent; refuse when not owned by `id -u` or group/world-writable (M-F11). (2) File: when present, it must be regular, not a symlink, have link count 1, be owned by `id -u`, and carry no ACL, xattr or label indicator (a character after the 10-character mode string). (3) **If any line already contains the marker, exit 10 without writing** (idempotent). (4) The window and token re-check. (5) If the file is non-empty and its last byte, read **now** with `tail -c 1`, is not a newline, write one first. (6) Append the line with `>>`, or, when absent, create it with `set -C` and `>` and then `chmod 600`. (7) Emit the new content as hex. (8) Release the lock | 0 written; 10 already present (nothing written); 30 not manageable; 31 too large; ⟨r2⟩ 40 busy; 41 window expired; 42 lock lost |
| `remove` | ⟨r2⟩ Under the lock. Gets the expected preimage and post-image as hex in quoted here-documents, decoded by `awk` `printf "%c"` (registry files are text without NUL; a NUL in the preimage refuses with 30). (1) The checks of `append` step (2), with the directory present. (2) Decode both into `.hm-pre.<nonce>` and `.hm-post.<nonce>` in the registry's directory, with umask 077, then `chmod` the post-image to the registry's permission bits read from `ls -ldn` (only `rw-`/`r--` bit patterns; anything else refuses with 30). (3) `cmp -s <registry> .hm-pre.<nonce>` or **exit 20 without renaming**. (4) The window and token re-check. (5) `mv -f .hm-post.<nonce> <registry>`. (6) Remove `.hm-pre.<nonce>` and emit the new content as hex. (7) Release the lock. A trap removes both temporary files on every exit path | 0 renamed; 20 changed since read (nothing renamed); 30 not manageable; 31 too large; ⟨r2⟩ 40 busy; 41 window expired; 42 lock lost |

**Disclosed windows** (stated in every preview and confirmation; ADR-0005 §3.3):
* an administrator write between `append` step (5) and its write can join the administrator's line to
  ours. The post-write check detects it (`held`, reason `registry_line_damaged`), and nothing rewrites
  it automatically;
* an administrator write between `remove` step (3) and (5) is lost, and cannot be detected afterwards.
  It is a few system calls in one remote command;
* ⟨r2⟩ a script suspended **between** its window and token re-check (step 4) and its write, beyond
  its hard deadline, could still write after reconcile broke its lock. The post-write and reconcile
  checks then see two marker lines (`held`) or a missing line, and nothing rewrites automatically.
  Administrators do not take Heimdall's lock, so the lock fences Heimdall's own steps only;
* on a network file system, `O_APPEND` and `mkdir` may not be atomic [I].

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
| E3 append | ⟨r2⟩ route re-evaluated; stage receipt **`Attempted`, effect token = marker**, with the step token and hard deadline | **append**, under the lock | `Confirmed {post_sha256}` with record `applied_unverified`; or `NotApplied {busy \| window_expired \| lock_lost \| refused}`; or `Uncertain` with record and operation `outcome_unknown` (`registry_outcome_unknown`) | Unresolved; reconcile per §6.7. **Never re-run blindly**; the script itself refuses a second line (exit 10) |
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
   * `GlobalKnownHostsFile` = an empty generated file, `CheckHostIP no`;
   * `StrictHostKeyChecking yes`, `UpdateHostKeys no`, `CanonicalizeHostname no`;
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
   * **The command** is `awk 'BEGIN { srand(); print "HM1 now=" srand() }'` (M-F23). It is a fixed
     literal and needs no extension.
   * **The bound.** With local wall times t₁ (just before the process starts) and t₂ (when the output
     line is read), and the remote reading T, the destination's clock lags local time by at most
     `behind_upper = max(0, t₂ − T + 1 s)`. The 1 s is the reading's resolution.
   * **The record:** `ClockMeasurement { behind_upper_ms, rtt_ms = t₂ − t₁, measured_at }`, stored
     with the enrollment evidence.
   * **Only lag matters.** A destination clock ahead of local time ends acceptance earlier, never
     later.
   * **Freshness.** A measurement older than the verification freshness (Q11) counts as `unmeasured`.
5. ⟨r2⟩ **Evidence from the `-v` trace** (§17.1 item 3; M03-R03, F01). The trace patterns are
   recorded per client version (`verify_trace_patterns`, plan U5; M-F22). A client whose patterns are
   not recorded makes every result `verification_inconclusive`. For each attempt the Verifier extracts:

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
| inconclusive, either attempt | | account: back to `applied_unverified`, so `enroll verify` retries (the line stays, and no grant uses it); system: `manual_pending` | `verified` with **unchanged** freshness, and a doctor finding `reverification_inconclusive` |

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

⟨r2⟩ **Fencing first** (§17.1 item 6). Reconcile looks at the lock state in the inspect result before
the marker:
* **Lock held with the old step's token, before that step's hard deadline:** the old script may
  still be running. Nothing is decided, and the operation stays `outcome_unknown`, with next
  `reconcile` after the deadline.
* **Lock held after the hard deadline:** it is stale. Reconcile breaks it by renaming it aside
  (`mv … .stale.<16 hex>`), runs `inspect` again, then removes the renamed directory, and classifies
  that second read.
* **No lock:** classify directly.

| Observation (after fencing) | Meaning | Action |
|---|---|---|
| Exactly one marker line, equal to the expected line | Applied | `Confirmed`, then `applied_unverified`, then continue at E4 |
| No marker line | Not applied | A redispatch of E3 is allowed **only** when all hold (Q7 as amended): the same approved target and effect, re-checked by the route re-evaluation; the old step's hard deadline has passed and its lock is gone or was broken (so the old script can no longer write: it exits 41 or 42); the approval is within its validity (24 h after `Decide approve`, measured on safe time); and an **attended** session (F20). Then back to `applying`, and E3 runs again with the same marker and line. ⟨r2⟩ **An absence read alone never authorizes a redispatch.** If the approval lapsed: `DECISION_STALE`, reason `approval_lapsed`, and the record goes `withdrawn` |
| Marker present but the line differs, or more than one marker line | Damaged | `held` (`registry_line_damaged`). The owner gets the exact line numbers and bytes |
| Unreachable, authentication failed, `busy` | Unknown | Stays `outcome_unknown`. `DESTINATION_UNREACHABLE`, the provider's code, or `registry_busy`. No retry loop: the owner retries |

For a removal or rollback step, the same table applies with "marker absent" meaning applied, and the
record keeps its purpose (`remove_unknown` or `rollback_unknown`, §6.2).

**Nothing is ever appended blindly:** the script refuses a second line by marker, whatever the local
state says (spec §7.5). **Test** (plan U5):
`first_script_survives_timeout_resumes_after_reconcile_no_duplicate_no_loss`. The first script is
paused after taking its lock; its step times out; reconcile waits out the hard deadline, breaks the
lock and redispatches; then the first script is resumed. It exits 41 or 42 and writes nothing, and the
registry holds exactly one line. A companion test pauses the first script at the disclosed window and
records the limitation.

### 6.8 Removal and rollback (compare-then-rename)

`enroll remove <enrollment>` creates operation `enrollment.remove` with decision `RemoveEnrollment`. ⟨r2⟩
The decision shows:
* the pinned existing-access invocation;
* the approved target;
* every live grant that holds a certificate **under this enrollment's CA** for the pair, with the
  pair residual.

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
* the ruling says these grants are degraded "only when no verified enrollment remains for the pair".
  Its case where another verified enrollment does remain is held by **Q20**: the affected grants' old
  certificates stop authenticating on that pair, and ADR-0005 §3.5 re-issues only after key loss or for
  a delegated child.

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
* **Remove.**
  1. `heimdall enroll remove <enrollment>` on a system-form enrollment changes nothing remote. It
     shows the exact lines to delete and moves the record to `manual_removal_pending`. That is
     narrowing, so no decision is needed; a typed confirmation is.
  2. When the owner confirms (`enroll verify <enrollment> --absence`), an **absence check** runs
     (`removal_verifying`): a positive verification certificate for the pair must be **refused**, with
     the full refusal evidence of §6.5.
  3. Only then is the record `removed`. An accepted or inconclusive result returns to
     `manual_removal_pending`.

  A system-form enrollment is **never reported as removed automatically**.
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

2. **Revocation order** (spec §6.7; R-AU-04). M01's revoke path, with M03's managed step:
   0. ⟨r2⟩ Take the **signing gate exclusively** for the grant and every descendant in the cascade (D2
      item 3a), waiting at most `signing_gate_max_wait`.
   1. Tombstone, cascade and generation in one transaction. From this commit, every signature on every
      endpoint is refused, and none was enqueued after it (D2 item 3a). `local_applied: true` is
      acknowledged only after this commit (M01).
   2. In the same call, before returning **and before releasing the gates**, the managed adapter's
      `revoke(grant)`:
      * for the grant and every descendant in the cascade: zeroize K_env and drop it from every
        endpoint, and remove the slot and binding files;
      * close owned masters (`-O exit`, then the exact PID) and **owned dedicated connections, under
        either policy** (ADR-0005 §6.1, Q4 b);
      * compute the residual.
   3. **Residual** (spec §6.7). `latest_possible_credential_expiry` is the maximum `valid_before` over
      every `reserved` or `published` entry for the cascade, delivered or not. Only `voided` entries are
      excluded (ADR-0005 §3.5).
      * `remote_effects` lists one row per (destination, account) with an unexpired entry:
        `latest_valid_before`, ⟨r2⟩ `destination_clock` (the enrollment's `ClockMeasurement`, or
        `unmeasured`), and `status` from item 3.
      * After a key-only restore (D4 item 4) the status is `unbounded_unknown` and no bound exists.
   4. ⟨r2⟩ **Owned connections** (F15). The revoke result lists every owned connection of the cascade,
      each `{id, kind, state: closing | closed | unverified}`. It also carries the fixed note
      `ordinary_connections_not_closed`: connections that ordinary `ssh` opened through P, and any
      unmanaged connection, are not closed (D8 item 2).
   5. Release the gates.

   If any part of step 2 fails, a cleanup intent is written in the settling transaction (M01 §13.19
   item 2). Denial already holds from step 1.

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

   ⟨r2⟩ **The binding holder and the controlled connection process are separate records** (§17.1
   item 8; M03-R08, F02). The binding's `Launch` holder (M02: the launcher's own PID and start token)
   stays the reference that keeps the binding. The **owned connection** is a separate
   `owned_connections` row naming the process that carries the connection: its PID, its start or
   creation time, and its verified executable.
   * **Unix.** `run` and `connect` `exec` the client, so the connection process **is** the holder
     process (same PID, same start time). The row is written in the transaction that records the
     holder (U0b row 19), with kind `dedicated`. **Before signalling**, the supervisor re-verifies the
     start time **and** that the process image is the verified client (`/proc/<pid>/exe` on Linux,
     `proc_pidpath` on macOS). A process still running `heimdall` (an exec that failed) is not an
     owned connection.
   * **Windows.** The launcher spawns the client and waits, so the two are different processes. ⟨r2⟩ A
     managed launch whose program is the verified client:
     1. creates the child **suspended**, assigns it to a new job object with
        `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and without breakaway, then resumes it (the suspended
        start keeps any grandchild inside the job; `localenv::sys::JobObject::spawn_contained`);
     2. registers the child's PID and creation time durably as the owned connection, through
        `Request::Connections(Register { binding_id, pid, created_at })` (owner role), **before** the
        binding reports strict control for it;
     3. if registration fails, it fails closed: it closes the job, which kills the client before or
        just after it connects, and writes `prelaunch_failed` with reason
        `connection_registration_failed`.

     The launcher's death then ends the client too: the job closes with the launcher's last handle.
     Revocation and a strict deadline end the exact `ssh.exe` through a handle opened on the
     registered PID with its creation time checked.
   * ⟨r2⟩ **The M02 "no job object" rule** (`launch/windows.rs`; ADR-0007 §8 and §11) was checked, as
     §17.1 item 8 requires. Its reason is that kill-on-close "kills grandchildren left running on
     purpose after a normal exit; not exec-equivalent" (M-F21).
     * **For an owned connection** (the child is the verified `ssh`), the ruling applies without
       conflict. Ending the connection is its purpose. The grandchildren killed at a normal exit are
       ssh's own (a `ProxyCommand` or `LocalCommand` helper), and that narrow residual is disclosed.
       ADR-0007 §8's "if the launcher is terminated, the child keeps running" no longer holds for
       managed `ssh` launches, and the disclosure is amended.
     * **For `run` of any other program on a managed binding**, the M02 rationale applies in full.
       §17.1 item 8's wording, "a managed launch", could be read to include it. That conflict is
       **Q18**. Until it is ruled, units build the job object behind one predicate,
       `launch_uses_kill_on_close_job(binding, program)`, so the integrator can flip it.

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
      item 4). On Windows this goes through the contained, registered spawn above; on Unix through
      `exec`, which makes the connection row the holder's process.
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
     * `-o ClearAllForwardings=yes`, `-o ExitOnForwardFailure=yes`, `-o BatchMode=yes`;
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
   | macOS | `CGSessionCopyCurrentDictionary`, `CGSSessionScreenIsLocked` | distributed notifications on a dedicated run-loop thread | implemented; native evidence through P1 (M-F12) |
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
   * `-o IdentitiesOnly=yes`, `-o ControlMaster=no`, `-o ControlPath=none`.

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
   * `RevokeData`: `remote_effects`, ⟨r2⟩ `owned_connections`, `notes`.
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

3. **Concurrent writers.** In the test configuration only, the scripts carry pause points (`HM_PAUSE
   <name>` lines). Each blocks on a FIFO named in the test's scratch until the test releases it. The test
   injects administrator edits at each point, before and after the final check, for add, remove and
   rotation (ADR-0005 §9.3 R1). A golden test proves that release scripts contain no pause point.

4. **The registry guard** (`testkit::registry::RegistryGuard`). Every enrollment a test runs must target
   a registry under its scratch directory, inside a disposable container, or inside the disposable WSL
   distribution. Anything else is `FixtureUnsafe` before any ssh runs. Each harness also records the
   SHA-256 of the owner's `~/.ssh` tree, Git configuration and (macOS) keychain list before and after,
   as M02's harnesses do, and fails on any change.

5. **Keys.** Per-run keys only. In the test configuration K_env generation may take a seed
   (`HEIMDALL_TEST_KEY_SEED`), so A33 can scan every output for the exact private bytes: raw, hex and
   base64. Release builds ignore the variable, which a test proves. Fixture public keys are committed
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
  * `Request::Enrollment`: preview, apply, verify (⟨r2⟩ presence or absence), remove, reconcile,
    abandon, and the client-executed `step` and `step_result` (D5 §6.3; owner role);
  * `Request::Connections`: close (owner role, narrowing), ⟨r2⟩ and `register` for a Windows owned
    connection (D8 item 2);
  * the catalog action `SetPreference`.
* **New fields:** `EnsureRequest.connection`; `PolicyAction::{SetLockBehavior, SetConnectionPolicy}`;
  `InspectSubject::{Enrollments, Issuer, Connections}`.
* **Operation kinds:** `enrollment.apply`, `enrollment.verify`, `enrollment.remove`.
* **Decision kinds:** `RegisterIssuer`, `RetireIssuer`, `EnrollAccount`, ⟨r2⟩ `EnrollSystemForm`,
  `RemoveEnrollment`.
* **Capabilities:** `issuer/1`, `enrollment/1`, `managed-credentials/1`, `connections/1`, offered only
  when their drivers land.
* **Fields on existing types:**
  * in `EnsureData`, `Enforcement` and `RevokeData` (D12; ⟨r2⟩ `RevokeData.owned_connections` and
    `notes`, D7 item 2);
  * `CertificateBounds.ca_fingerprint`;
  * `DegradedReason::{CredentialReissuePending, IssuerUnavailable, PairUnenrolled}`;
  * `RevocationCause::SessionLocked`;
  * `RemoteObligation.kind`, with ⟨r2⟩ the statuses `pending_until`, `bounded_complete` and
    `nominally_expired` (D7 item 3);
  * ⟨r2⟩ `IssuanceRefusal::CaRetiring`; the CA states `retiring`, `unloaded`, `deleted`, `retired`
    (D4 item 3).
* ⟨r2⟩ **New ports** (§18): `ManagedEffects`, `TargetEvaluator`, and the signing gate's `SignPermit`
  in `SignatureAuthority`.
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
| ⟨r2⟩ An unfenced append after a timeout | A first script that survives its timeout can append after a redispatch, giving two lines (M03-R06). A remote lock and a mutation window fence it (D5 §6.3) |
| ⟨r2⟩ A `watch` channel for lock events | It keeps only the last value, so a quick unlock erases the lock (M03-R09). A latched epoch is used (D9 item 3) |
| ⟨r2⟩ Clearing a residual at local `valid_before` | The destination's clock may lag (M03-R10). Bounded completion needs a measurement; without one the residual is `nominally_expired`, never cleared (D7 item 3) |
| ⟨r2⟩ A per-master random `ControlPath` rendered into P | P changes only through approved setup transactions (M03-R15, F16). A stable per-slot path is used (D8 item 3) |
| ⟨r2⟩ An `app` → `enroll` call while `enroll` implements an `app` port | A crate cycle (M03-R13). The pure protocol code moved to `heimdall-registry`, below `app` (§18) |

---

## 17. Questions for the orchestrator (authority semantics; recommended answers)

Units build against the recommended answers. The integrator changes the affected unit if a ruling
differs.

⟨r2⟩ The orchestrator's rulings are in §17.1: Q6, Q7, Q11, Q12, Q14 and Q17 are amended there, and the
D sections carry the amended rules. The text of Q1–Q17 below is revision 1's, kept for the record.
Questions raised by revision 2 are in §17.2.

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

## 18. Consequences

* **New crates** (⟨r2⟩ four; §17.1 item 12):
  * ⟨r2⟩ `heimdall-registry` (**pure**, no I/O): the registry line, marker, scripts and their goldens,
    the HM1 parser, post-image construction and the step classification (`classify_step`);
  * `heimdall-credential`: vault, certificates, purpose parsing, session-bind, the signer, endpoints;
  * `heimdall-issuer`: child, protocol, client, the `SecretStore` trait and its product
    implementations, backup, ceremony, bundle;
  * `heimdall-enroll` (I/O): the CLI-side `SshStepRunner` and the runtime-side `Verifier`.

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
                                                          implements VerificationEndpoint)
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
    `SignatureAuthority` and `VerificationEndpoint` (credential ↔ app), `SessionLockSource` and
    `ConnectionControl` (runtime → app).
  * U0 adds `tools/validation/crate_graph.py` to `check.sh` (`crate-graph` step). It parses the
    manifests, fails on any production cycle, and fails if `app` gains an edge to `credential`, `issuer`,
    `enroll`, `adapters`, `localenv` or `runtime`.
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
  launcher's death ends the client), pending Q18 for other programs.
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
* ⟨r2⟩ The orchestrator rules Q18–Q21 differently from their defaults.

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
