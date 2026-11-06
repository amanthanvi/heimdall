# ADR-0008 — Managed credential integration (M03): the B1 signer and issuer, scoped enrollment, deadline and connection control, lock behaviour

**Status:** proposed, revision 1 · **Date:** 2026-11-06 · **Task:** M03-T00-design
**Gates:** G04 (implementing the accepted recipe), G09 (expiry, multiplexing, clocks, revocation), and
the credential parts of G08.
**Implements:** ADR-0005 (recipe B1, accepted 2026-10-31). Its authority semantics do not change.
Where ADR-0005 leaves a point open (its §9.3 list and some mechanics), this ADR either decides it
(D1–D13) or asks about it (§17).
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
| M-F19 | A Unix process with `PR_SET_DUMPABLE` 0 (Linux) cannot be ptrace-attached by another process of the same user without `CAP_SYS_PTRACE`, and dumps no core | [I]; Yama's `ptrace_scope` changes the default. Settled by `linux_signer_not_ptraceable_by_same_user` (U1; `ptrace_scope` recorded) |

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
| Issue/revoke linearization (R2, R12) | U3 (the model, `tests/model/issuer_linearization.rs`) and U6 (fixture). The runner delivery rows go to M06 |
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
| **Test K_ca** | The ceremony, under the test configuration only | `ScratchSecretStore`: the D5 format, encrypted with a per-run passphrase, under the scratch state directory. Compiled only into test-configured builds, never into release builds (the M01 `testcfg` pattern) | Same, or real DPAPI on a scratch path, which ADR-0004 §3 authorizes | Same | Same | Scratch removal |

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
   `SignatureAuthority::authorize`, which the application's `Operations` implements. Nothing is cached,
   and authorization runs **after** the request has been parsed and **before** the key signs. It checks,
   in one read transaction plus the shared time gate:
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

   The result is `Admit` or `Refuse(reason)`. A refusal returns `SSH_AGENT_FAILURE`, and no reason is
   sent to the client. The audit event records the reason as a nonsecret code, and the
   `CredentialLifecycle` events are rate-limited per grant to 1 per second. Authorization is bounded by
   `signature_authorization_timeout` (2 s); a timeout refuses.

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
   * `key_blob` must be the K_env public blob, or one of this grant's certificates, matched byte for
     byte;
   * `user` must be the account of one of the grant's pairs;
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

7. **Destruction.** At grant end the signer:
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
| `pending` | every pair's certificate published and installed | `installed` | `Prepared` stage receipt |
| `pending` | any reservation refused or voided | `destroyed` | The key is zeroized. A fresh `prepare` makes a new instance |
| `installed` | grant ends | `destroyed` | |
| `installed` | process exit (crash, stop, logout) | **`lost`** (new) | Detected at the next start: an `installed` row whose vault slot does not exist in this process |
| `lost` | the ADR-0005 §3.7 recovery rule holds | `destroyed`, plus a new instance `pending` | Re-issue: a new K_env and fresh reservations. The old entries stay counted |
| `lost` | the rule fails (expired, revoked, `revoke_on_lock`, time not accepted) | `destroyed` | The grant ends, or stays `degraded` (`credential_reissue_pending`) while only time is unaccepted |

**Rationale.** The checks of ADR-0005 §3.6 need the transactional state, which lives in the runtime.
* An in-process signer reads it under the same serializable store that revocation writes. "Revocation
  commits, then every later signature refuses" therefore holds without a cache-invalidation protocol.
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

4. **Signing by reservation.** The issuer opens the state database **read-only**
   (`Store::open_read_only`; WAL readers do not block the writer). For each `sign`:
   1. load the entry by ID from `issuance_log` or `verification_issuance`. It must be `reserved`, must
      have been reserved no more than 60 s ago, and its `subject_fingerprint` must equal the fingerprint
      of `subject_public_key`;
   2. re-run the **pure** predicate (`issuance::check`, or `verification::check`) against a read-only
      snapshot taken in one read transaction, with the issuer's own clock observation. The gate runs in
      `assess` mode, which persists nothing;
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
   2. **Disclose and decide.** On an attended session (`Attend` first, ADR-0006 §13.6 item 7) the CLI
      sends `Issuer::Register` with K_ca's **public** key and store kind. The runtime answers
      `APPROVAL_REQUIRED` with decision `RegisterIssuer`, which names the CA fingerprint and carries the
      disclosure:
      * the same-user issuer boundary;
      * the blast radius: every account that will trust the CA;
      * lock continuity, shown once (R-UX-03, D9);
      * the backup instructions.

      The CLI shows it, and the owner types `yes`. Anything else sends nothing more, zeroizes K_ca and
      exits 3.
   3. **Back up.** Write the D5 file to `--backup-out` with `O_EXCL`, mode 0600 or an owner-only DACL.
      There is no default path: Heimdall never proposes a location, and never a synchronized folder.
   4. **Verify.** Decrypt the written file in memory and compare its public key with K_ca's.
   5. **Show the passphrase once.** Write it on the controlling terminal (`/dev/tty`; on Windows `CONOUT$`),
      never on stdout or stderr when they are not that terminal. Then wait until the owner types
      `written`, and clear the screen region.
   6. **Store.** Write K_ca to the platform store (D1). Read it back by identity and compare
      fingerprints.
   7. **Register.** Send `Decide approve` for the `RegisterIssuer` record. In one transaction the
      runtime:
      * records the CA (`issuers` row: fingerprint, public key, `active`, store kind, backup fingerprint =
        SHA-256 of the backup file bytes, backup time);
      * sets the native environment's `managed_signing` and `issuer_access` permissions, which moves the
        generation (ADR-0006 §13.7 item 5).

      Then it starts the issuer child.
   8. **Zeroize** K_ca and the passphrase in the CLI process.

   **Crash points:**
   * before step 6: nothing is stored or registered. A pending `RegisterIssuer` record expires
     (`DECISION_STALE`), and the owner discards the backup file;
   * between 6 and 7: an **orphan** store item that is not registered. `issuer status` reports it.
     `issuer init --replace-orphan <fingerprint>` deletes it by exact identity: no line can trust it,
     because enrollment needs a registered CA;
   * after 7: registered.

   The decision record carries only the public fingerprint, so a stale or denied record leaves nothing
   behind but that public value.

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
   * The old line is removed with `enroll remove <old enrollment>` (compare-then-rename, D5 §6.8). It
     becomes eligible once the old CA's latest `reserved`/`published` `valid_before` **for that pair** has
     passed. Before that, the removal preview warns that live certificates would stop working.
   * `issuer retire <fingerprint>` (attended decision `RetireIssuer`) deletes the store item and
     zeroizes the key in the issuer. It is allowed once no enrollment under that CA is `verified` or
     `applied_unverified`. Enrollments the owner abandons (state `abandoned`, unreachable accounts) keep
     their line, reported `pending_until_line_removed`.
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
   * CA public keys and fingerprints, and backup fingerprints and dates;
   * per enrollment: marker, destination ID, account, registry path, form, state;
   * optionally, hostnames;
   * the removal instructions.

   It is refreshed automatically: `issuer status` and every enrollment change report its staleness.
   **Foreign removal** goes from another device with existing access:
   `heimdall enroll remove --from-bundle <file> --marker <marker>`. It runs the D5 §6.8 removal by
   marker and needs an attended decision `RemoveEnrollment`. That device's own catalog needs the
   destination's host trust. This is the ADR-0005 §6.3 lost-issuing-device primitive; the guided flow
   is M07 (§8).

**Rationale.**
* Generating the key in the CLI keeps the passphrase and the unencrypted backup bytes in exactly one
  owner-present process, and they never cross IPC.
* The issuer child only ever loads K_ca from the store.
* Per-pair CA selection turns rotation into a sequence of independent per-account steps. Each step is
  verified before issuance relies on it, so an unreachable account never blocks the others.

**Rejected:**
* **Generating K_ca in the issuer child and passing the passphrase to the CLI over IPC.** The secret
  would cross a process boundary for display.
* **A default backup location.** Spec §7.7 and ADR-0005 §5.3 forbid proposing one.
* **A global switch of issuance at rotation.** Accounts not yet verified would fail at once.
* **Retire before the old lines are removed or abandoned.** Live grants on those accounts would stop.

---

## 6. D5 — The enrollment transaction

### 6.1 Scope and preconditions

`heimdall enroll <destination> [--account <a>] [--registry-path <p>] [--ca <fingerprint>]` enrolls one
pair with **account-level control** (spec §7.4 capability 2): one
`cert-authority,principals="hm:<destination-id>:<account>" <K_ca public> heimdall:<enrollment-id>` line
in the account's registry (ADR-0005 §3.3).

The preview refuses, writing nothing, unless all of these hold:

| Precondition | Refusal reason (`CAPABILITY_UNAVAILABLE` unless stated) |
|---|---|
| A CA is registered and the issuer is `ready` | `issuer_not_initialized`, `issuer_unavailable` |
| The destination is **managed** in the catalog (rendered in P), not observed | `observed_alias_unmanaged` |
| The destination ID and account fit `[A-Za-z0-9._-]` (ADR-0005 §3.3 principal form) | `principal_charset`, with the remedy |
| Its route is direct. ProxyJump, ProxyCommand and canonicalization are M04 | `route_unsupported` |
| Static evaluation determines the alias's HostName, Port and User, and one non-revoked known host key for (HostName, Port) is found in the user's known-hosts files, including hashed entries | `host_trust_undetermined` |
| An existing-access identity is adopted for the alias (M02 catalog), so the known-working path exists | `pair_not_adopted` |
| No enrollment for this (pair, CA) is in a non-final state | `CONFIG_CONFLICT`, `already_enrolled` |
| `--registry-path`, when given, is absolute POSIX, ≤ 255 bytes, from `[A-Za-z0-9._/-]`, with no `..` component | `USAGE_ERROR` |

The preview is **local and passive**. It contacts nothing; reading the remote registry is a step of
`apply`. Its plan names:
* destination and account;
* the existing identity and endpoint that will authenticate the change;
* the registry path: given, or `$HOME/.ssh/authorized_keys` resolved by the remote shell;
* the exact line;
* the CA fingerprint;
* the verification plan;
* rollback;
* the disclosures:
  * this connects with your configuration for `<alias>`, so its `Match exec`, `ProxyCommand` and
    similar entries run as in ordinary use;
  * the CA trust on this account lets this device's issuer mint certificates for this principal;
  * lock continuity, if not yet acknowledged.

`plan_digest` covers all of it.

### 6.2 The enrollment record and its states

`EnrollmentRecord`:
* identity: `{ id: enr_…, destination, account, ca_fingerprint, form: account | system, marker }`;
* `registry: { path_display, resolved_by: explicit | remote_home }`;
* `line_sha256`;
* `state`, `verified_at`, `evidence: { client, server, verified_by_operation }`;
* `created_at`, `updated_at`.

The marker is `heimdall:<enrollment-id>`. It is opaque and is the add's idempotency key.

| State | Meaning | Allowed transitions |
|---|---|---|
| `planned` | Operation admitted, awaiting the owner decision `EnrollAccount` | `applying` (approved); `withdrawn` (denied, cancelled, or the decision is stale and nothing was written) |
| `applying` | The approved operation is running; nothing remote is known written | `outcome_unknown` (the add's result was lost); `applied_unverified` (add confirmed); `failed_unwritten` (refused before any write: registry not manageable, provider locked, host trust) |
| `outcome_unknown` | The add may or may not have applied | `applied_unverified` (reconcile found the exact line once); `applying` (reconcile found the marker absent, within the approval's validity; §6.7); `held` (reconcile found a damaged line); stays while unreachable |
| `held` | Our marker is present but the line is not exactly ours, or there is more than one marker line. Nothing automatic happens | `removing` (owner-decided removal); `abandoned` |
| `applied_unverified` | The exact line is present; no positive and negative verification has passed | `verifying`; `removing` (rollback); `abandoned` |
| `verifying` | Verification certificates issued, independent logins running | `verified`; `rollback_pending` (failed or principals not enforced); `applied_unverified` (destination unreachable; retry `enroll verify`) |
| `verified` | Positive passed with exactly one signature, negative refused with zero. `destination_scope: verified_server_principals` may be claimed for the pair | `verifying` (re-verify); `removing` |
| `rollback_pending` | Verification failed; removing our line | `verification_failed` (removed); `remove_unknown`; `held` (removal refused: `registry_changed` three times, or not rewritable, so the owner gets manual instructions) |
| `removing` | Owner-decided removal running | `removed`, `remove_unknown`, `held` |
| `remove_unknown` | The removal may or may not have applied | `removed` (reconcile found the marker absent); `removing` (found present); stays while unreachable |
| `verification_failed`, `removed`, `withdrawn`, `failed_unwritten` | Final; no line of ours remains (as last observed) | none |
| `abandoned` | The owner gave the account up while unreachable or held. The line may remain. Reported `pending_until_line_removed`; listed by uninstall and the bundle | `removing` (when reachable again; a new decision) |

A pair is usable for managed issuance only through a `verified` enrollment. `verified` is the only state
that adds the CA to that pair's issuable set.

### 6.3 The remote registry protocol

**Who runs a remote step: client-executed steps.** The remote steps run in the **owner's CLI process**
that drives the operation, not in the runtime. Existing access may need the owner's terminal (a
password, a key passphrase, a touch, a provider dialog attributed to that terminal), and the background
runtime has none. The runtime keeps the journal:

1. `Enrollment::Step { operation_id }`. The runtime first writes the stage receipt: `Attempted` (effect
   token = the marker) for `append` and `remove`, `started` for `inspect`. Only then does it return the
   step: `{stage, step_token, script, alias, options, timeout}`, where `step_token` is 128 random bits.
2. The CLI runs the invocation below on its own terminal. It then sends `Enrollment::StepResult {
   operation_id, step_token, exit_status, stdout, stderr_excerpt }`, with stdout bounded and the stderr
   excerpt bounded and redacted.
3. The runtime parses and checks the result (HM1 and the post-write check below) and records
   `Confirmed`, `NotApplied` or `Uncertain`. A result whose `step_token` is not the outstanding one is
   refused with `REQUEST_CONFLICT`, and nothing is recorded.

If the CLI dies, or no result arrives within `enrollment_step_timeout`, a mutating step is `Uncertain`
(`outcome_unknown`) and a read step can be retried. **The runtime never runs the existing-access `ssh`
itself.**

The CLI's report is **not** what the security claim rests on:
* `verified_server_principals` comes only from the verification the runtime runs itself (§6.5);
* every mutating result is re-checked by a later `inspect`.

A same-user caller that forges results is inside the disclosed boundary. It can make an enrollment fail
or stay held; it cannot make one verify.

**Invocation.** Every remote step is **one** `ssh` process run through the pair's **existing access**:
* the verified client from M02's client inventory;
* the user's ordinary configuration (P included);
* command-line options that only narrow: `-T -o BatchMode=<yes when non-interactive> -o
  StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -o ForwardAgent=no -o
  ClearAllForwardings=yes -o PermitLocalCommand=no -o RequestTTY=no -o UpdateHostKeys=no`;
* the alias; and the remote command `exec /bin/sh -s`.

The script is written to the child's stdin.

The remote login shell therefore interprets only `exec /bin/sh -s`. Every value is a validated literal
inside the script, in single quotes:
* the line's character set (`[A-Za-z0-9+/=,:" ._@-]`) contains no `'`;
* paths are validated (§6.1).

Host trust is never weakened: `StrictHostKeyChecking=yes` beats a user `accept-new` (R-SE-04). A host-key
failure (exit 255 with "Host key verification failed") maps to `HOST_TRUST_CHANGED`.

Bounds:
* stdout ≤ 1 MiB and stderr ≤ 64 KiB, read concurrently;
* connect 30 s;
* total 120 s, or 300 s for an interactive step that may wait on a provider approval.

**Output.** Line-oriented: `HM1 <key>=<value>`. Values are decimal, a fixed token, or lowercase hex
produced by `od -An -v -tx1`, never raw bytes. The first line must be `HM1 v=1`. Otherwise the remote
shell is not POSIX, or something printed before the script ran, and the step fails with
`registry_unsupported`, writing nothing.

**Utilities** (M-F10): `sh`, `id`, `ls`, `test`, `cat`, `cmp`, `od`, `tail`, `grep`, `awk`, `mkdir`,
`chmod`, `mv`, `rm`, `printf`. No `stat`, `sha256sum`, `base64` or `xxd`, because none is POSIX.

**Scripts** (generated by `heimdall_enroll::script`; release builds byte-compare them against goldens,
and the test configuration adds pause points):

| Script | Does | Exit codes |
|---|---|---|
| `inspect` | Resolves the registry path. Reports the directory (present/absent; mode string from `ls -ldn`; owned by `id -u`), the file kind (`regular`, `absent`, `symlink`, `other`), link count, mode string, owner, size, whether the last byte is `0a`, the number of lines containing the marker, and the content as hex (≤ 128 KiB) | 0 ok; 30 not manageable (reports why); 31 too large |
| `append` | (1) Directory: `mkdir -m 0700` when absent; refuse when not owned by `id -u` or group/world-writable (M-F11). (2) File: when present, it must be regular, not a symlink, have link count 1, be owned by `id -u`, and carry no ACL, xattr or label indicator (a character after the 10-character mode string). (3) **If any line already contains the marker, exit 10 without writing** (idempotent). (4) If the file is non-empty and its last byte, read **now** with `tail -c 1`, is not a newline, write one first. (5) Append the line with `>>`, or, when absent, create it with `set -C` and `>` and then `chmod 600`. (6) Emit the new content as hex | 0 written; 10 already present (nothing written); 30 not manageable; 31 too large |
| `remove` | Gets the expected preimage and post-image as hex in quoted here-documents, decoded by `awk` `printf "%c"` (registry files are text without NUL; a NUL in the preimage refuses with 30). (1) The checks of `append` step (2), with the directory present. (2) Decode both into `.hm-pre.<nonce>` and `.hm-post.<nonce>` in the registry's directory, with umask 077, then `chmod` the post-image to the registry's permission bits read from `ls -ldn` (only `rw-`/`r--` bit patterns; anything else refuses with 30). (3) `cmp -s <registry> .hm-pre.<nonce>` or **exit 20 without renaming**. (4) `mv -f .hm-post.<nonce> <registry>`. (5) Remove `.hm-pre.<nonce>` and emit the new content as hex. A trap removes both temporary files on every exit path | 0 renamed; 20 changed since read (nothing renamed); 30 not manageable; 31 too large |

**Disclosed windows** (stated in every preview and confirmation; ADR-0005 §3.3):
* an administrator write between `append` step (4) and its write can join the administrator's line to
  ours. The post-write check detects it (`held`, reason `registry_line_damaged`), and nothing rewrites
  it automatically;
* an administrator write between `remove` step (3) and (4) is lost, and cannot be detected afterwards.
  It is a two-system-call window in one remote command;
* on a network file system, `O_APPEND` may not be atomic [I].

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
destination, account, form, registry path, CA fingerprint and `plan_digest`.

| Stage | Durable before | Remote effect | Durable after | Crash or lost reply → recovery |
|---|---|---|---|---|
| E0 admit | operation row and intent (the plan); record `planned`; decision `EnrollAccount` | — | — | Retry with the same key returns it (ADR-0006 §7) |
| E1 approve | decision consumed; approval basis in the intent; record `applying` | — | — | Re-driven on owner reconcile |
| E2 inspect | stage receipt `enroll.inspect.started` | read only | `enroll.inspect.observed {preimage_sha256, size, tail_newline, marker_lines, file_kind, dir_state}` | Re-run: reads are safe |
| E3 append | stage receipt **`Attempted`, effect token = marker** | **append** | `Confirmed {post_sha256}` with record `applied_unverified`, or `Uncertain` with record and operation `outcome_unknown` (`registry_outcome_unknown`) | Unresolved; reconcile per §6.7. **Never re-run blindly**; the script itself refuses a second line (exit 10) |
| E4 verify | `enroll.verify.started`; verification issuance entries reserved and published (§6.5) | independent logins (no mutation) | `enroll.verify.passed {client, server, signatures: 1, negative_signatures: 0}` or `enroll.verify.failed {reason}` | Re-run verification with fresh certificates. The old entries stay counted until their `valid_before` |
| E5 record | — | — | **One transaction:** record `verified` with its evidence; catalog pair preference `managed_certificate` with `projection: pending`; operation `succeeded`, next `setup_apply` | If E4 passed and E5 did not commit: re-verify, then record |
| E5′ rollback (E4 failed) | record `rollback_pending`; `Attempted` (token = marker plus `:rm`) | **remove**, through existing access | record `verification_failed` (removed) or `remove_unknown` | As E3, through reconcile |

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
     `enrollment.verify`, at stage E4;
   * the entry's pair and CA equal the plan's;
   * the principal is exactly `hm:<destination-id>:<account>` (positive) or
     `hm:verify-negative:<32 hex nonce>` (negative);
   * there are **no extensions** (`clear`): `ssh -T … true` needs none;
   * validity: `valid_after` = now − 60 s and `valid_before` ≤ now + 300 s;
   * the subject is K_verify, registered by this operation's verification endpoint;
   * time is `Safe`;
   * at most 4 entries per verification attempt and 3 attempts per operation.

   Entries count toward a **per-pair residual** (D7 item 4) until their `valid_before`.
3. **A generated configuration** in `<runtime_dir>/v/<16 hex>/ssh_config`, never the user's
   configuration (it avoids the inherited `IdentityFile` entries of M-F4). Its directives:
   * `Host hm-verify`;
   * `HostName`, `Port` and `User` from the catalog's managed definition;
   * `HostKeyAlias hm-verify-<16 hex>`, and `UserKnownHostsFile` = a generated file holding exactly
     one line: that alias with the known host key found in §6.1. The check therefore does not depend
     on how the user's known-hosts files write the host and port;
   * `GlobalKnownHostsFile` = an empty generated file, `CheckHostIP no`;
   * `StrictHostKeyChecking yes`, `UpdateHostKeys no`, `CanonicalizeHostname no`;
   * `IdentityAgent` = the verification endpoint, `IdentitiesOnly yes`, `IdentityFile <K_verify.pub>`,
     `CertificateFile <the positive or negative certificate>`;
   * `PreferredAuthentications publickey`, `PasswordAuthentication no`, `KbdInteractiveAuthentication
     no`;
   * `BatchMode yes`, `ControlMaster no`, `ControlPath none`;
   * `ProxyCommand none`, `ProxyJump none`;
   * `ForwardAgent no`, `ClearAllForwardings yes`, `RequestTTY no`, `ConnectTimeout 20`.

   The client is invoked as `ssh -F <generated> -v -T hm-verify true`. Stderr is bounded, and only the
   remote software version line is parsed from it.

**Outcome classification:**

| Positive | Negative | Result |
|---|---|---|
| exit 0, exactly 1 signature | refused (exit ≠ 0), 0 signatures | **verified**: `verified_server_principals` may be claimed for this pair |
| exit 0 | accepted, **or** any signature recorded | **`principals_not_enforced`**: a high-severity finding. The line is rolled back (E5′) |
| refused | — | **`verification_failed`**: the registry is probably not the server's authoritative one (spec §7.4), or certificates are unsupported. Rolled back. No Recipe A in M03 (Q4) |
| exit 0 with 0 or ≥ 2 signatures | — | `verification_inconclusive`: retried once, then treated as failed and rolled back |
| host key mismatch | — | `HOST_TRUST_CHANGED`. **No rollback attempt**: existing access would fail host verification too. The record goes `held` with remedy `review_host_trust` |
| unreachable or timeout | — | Record back to `applied_unverified`; `enroll verify` retries. The line stays and no grant uses it |

`log_attestation` is reported `unavailable` (ADR-0005 §3.3). The server log is only the test oracle, in
the fixtures.

### 6.6 Preserved fallback and the preference switch

* The existing identity and its remote access are never touched. Heimdall did not create them and does
  not remove them (spec §7.5 "retire older access only through the approved policy"). M03 has no
  retirement policy.
* E5 records the pair's preference as `managed_certificate` with `projection: pending`. P keeps
  rendering the existing identity until the owner applies the projection change through M02's setup
  (preview, `ApplyProjection` decision, journaled apply). The diff shows the alias moving to the
  environment endpoint and the slot files (D10).
* Until then, an `ensure` that would use the managed mechanism for the pair is refused with
  `CAPABILITY_UNAVAILABLE`, reason `projection_pending`, next `setup_apply`. So no result ever claims
  managed access that an ordinary alias does not use.
* **Switching back** (`heimdall destination prefer <alias> existing`) is local: a catalog change plus a
  projection change. The enrollment stays until `enroll remove`.

### 6.7 Reconciliation after uncertainty

`heimdall enroll reconcile <operation>` (owner-present). For a step that is `Uncertain`, it runs
`inspect` through existing access and classifies:

| Observation | Meaning | Action |
|---|---|---|
| Exactly one marker line, equal to the expected line | Applied | `Confirmed`, then `applied_unverified`, then continue at E4 |
| No marker line | Not applied | **Only within the approval's validity** (24 h after `Decide approve`), with the same CA `active` and the host key unchanged: back to `applying`, and E3 runs again with the same marker and line. Otherwise the operation fails with `DECISION_STALE`, reason `approval_lapsed`, and the record is `withdrawn`. A new enrollment needs a new decision |
| Marker present but the line differs, or more than one marker line | Damaged | `held` (`registry_line_damaged`). The owner gets the exact line numbers and bytes |
| Unreachable, or authentication failed | Unknown | Stays `outcome_unknown`. `DESTINATION_UNREACHABLE` or the provider's code. No retry loop: the owner retries |

For a removal step, the same table applies with "marker absent" meaning applied.

**Nothing is ever appended blindly:** the script refuses a second line by marker, whatever the local
state says (spec §7.5).

### 6.8 Removal and rollback (compare-then-rename)

`enroll remove <enrollment>` creates operation `enrollment.remove` with decision `RemoveEnrollment`. The
decision lists every live grant that uses the pair; they stop authenticating there once the line is
gone. Then:
1. `inspect`;
2. build the post-image locally: the preimage minus exactly the lines equal to our line (the marker
   lines must all equal it, or the result is `held`);
3. `remove`;
4. on exit 20, start again from `inspect`, at most 3 times, then `CONFIG_CONFLICT`, reason
   `registry_changed`, record `held`;
5. on exit 30 (a symlink, more than one link, an ACL or label, a foreign owner, an unsupported mode),
   `CONFIG_CONFLICT`, reason `registry_not_rewritable`, with **manual instructions**: the file, the exact
   line to delete, and how to re-verify absence (`enroll reconcile`).

Live grants on a removed pair become `degraded`, reason `pair_unenrolled`. They are not revoked locally;
the owner may revoke them. Rollback after a failed verification (E5′) is the same procedure, under the
original decision.

### 6.9 The system form

The system form (`TrustedUserCAKeys` plus `AuthorizedPrincipalsFile`) is **manual** in M03.
`heimdall enroll <destination> --form system` writes nothing remote. It shows the owner:
* the CA public line to add to `TrustedUserCAKeys`;
* the principals-file line `hm:<destination-id>:<account>` for the account;
* the `sshd_config` directives.

Once the owner confirms they are applied, the same verification as §6.5 runs (operation
`enrollment.verify`). Only its pass records `form: system, state: verified`.

Heimdall never edits `sshd_config`, never runs `sudo`, and never installs a service (spec §7.4
capability 3 automation; plan §1.2).

### 6.10 Interaction

* `enrollment.apply` is admitted on any session. It always needs the attended `Decide` for
  `EnrollAccount`.
* After approval, the existing-access steps run in the driving CLI process, in the request's
  interaction mode (§6.3).
  * In `--non-interactive` mode the CLI runs ssh with `BatchMode=yes`. A provider or server that needs
    interaction (a 1Password approval, a locked agent, a touch, a password) fails the step before any
    write. The provider's code is returned (`PROVIDER_LOCKED`, `INTERACTION_REQUIRED`), and the record
    is `failed_unwritten`.
  * In interactive mode, the prompt appears on the owner's terminal, or as the provider's own dialog
    (ADR-0007 §7 interaction states). Heimdall never reads, relays or stores what the owner types.
* Verification needs no interaction. The runtime runs it in `BatchMode`.

---

## 7. D6 — Certificate acquisition, re-issue and offline coverage

1. **Activation.** `prepare` for a `managed_certificate` grant (m03-plan U6). Every pair must have a
   `verified` enrollment and an applied projection (D5 §6.6). The steps, each a stage receipt under the
   operation's effect token:
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
   * `lock_continuity` from the claim table (D12).

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

8. **The prepare drop contract** (M02 §5 item 15). A dropped `prepare` future stops between steps and
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
   1. Tombstone, cascade and generation in one transaction. From this commit, every signature on every
      endpoint is refused. `local_applied: true` is acknowledged only after this commit (M01).
   2. In the same call, before returning, the managed adapter's `revoke(grant)`:
      * for the grant and every descendant in the cascade: zeroize K_env and drop it from every
        endpoint, and remove the slot and binding files;
      * close owned masters (`-O exit`, then the exact PID) and **owned dedicated connections, under
        either policy** (ADR-0005 §6.1, Q4 b);
      * compute the residual.
   3. **Residual** (spec §6.7). `latest_possible_credential_expiry` is the maximum `valid_before` over
      every `reserved` or `published` entry for the cascade, delivered or not. Only `voided` entries are
      excluded (ADR-0005 §3.5). `remote_effects` lists one row per (destination, account) with an
      unexpired entry: `status: bounded_by_credential_expiry`, `until` = that pair's maximum
      `valid_before`, and `destination_clock_error: "unmeasured"`. After a key-only restore (D4 item 4)
      the status is `unbounded_unknown` and `until` is absent.

   If any part of step 2 fails, a cleanup intent is written in the settling transaction (M01 §13.19
   item 2). Denial already holds from step 1.

3. **Time-bounded remote obligations** (a change to M01 semantics; Q12). B1 has no remote revocation
   action at capability 2 (no KRL). Its remote part therefore never needs adapter rounds.
   * A `RemoteObligation` of kind **`bounded_by_expiry {until}`** clears itself in the supervisor's
     revocation pass. The condition is that the time gate is `Safe` with wall time ≥ `until`. There is
     no adapter call and no attempt is counted.
   * The grant stays `revoking`, with `remote_pending` visible, until every obligation of the cascade
     has cleared. Then it becomes `revoked`.
   * The cap and backoff of ADR-0006 §13.12 to §13.19 apply only to obligations of kind
     `needs_remote_action`. M03 has none; later KRL work or Recipe A would add them.
   * While time is uncertain, a `bounded_by_expiry` obligation never clears: it fails closed and stays
     pending.

4. **Per-pair residual** (`inspect enrollments`, `inspect grants`). It is the maximum `valid_before` over
   grant entries and verification entries for the pair, issued under a given CA. Rotation's old-line
   removal (D4 item 3) and the `RemoveEnrollment` decision read it.

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

2. **Owned dedicated connections.** A connection is owned when its holder process is the verified `ssh`
   client of M02's client inventory, launched by:
   * `heimdall connect`; or
   * `heimdall run` whose resolved program is that client.

   The binding's `Launch` holder (exact PID plus start-time token, M02) is recorded in
   `owned_connections` with kind `dedicated`.

   | Event | graceful | strict |
   |---|---|---|
   | Admission deadline, cutoff | kept: "New connections stop at the deadline; existing sessions may stay connected." | closed: "Connections Heimdall started are closed at the deadline." |
   | Revocation, `revoke_on_lock` | **closed** | **closed** |
   | Release of the last reference | as at the deadline | as at the deadline |
   | `TIME_UNCERTAIN` | kept | closed |

   **Closing.**
   * **Linux:** `pidfd_open` on the exact PID, the start time re-verified through `/proc`, then
     `pidfd_send_signal(SIGTERM)`, and `SIGKILL` after 5 s. A pidfd pins the process, so there is no
     PID-reuse race.
   * **macOS:** `kill` after re-verifying PID and start time with `proc_pidinfo`. A small reuse window
     remains between the check and the signal; it is disclosed.
   * **Windows:** `OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)`, the creation time
     verified on that handle, then `TerminateProcess`. The handle pins the process.

   A holder whose identity cannot be verified is never signalled. It is reported `unverified` and
   treated as unmanaged.

   **`run` of any other program** (a shell or an agent CLI that starts its own `ssh`): its children are
   **not owned** for closing. Their new authentications are still refused by the signer after the
   deadline. The result reports `existing_connections: not_controlled` for such a binding, never
   `strict_disconnect`. Closing a user program at the deadline is not a connection policy (spec §6.6
   "Detached remote processes are not automatically terminated").

3. **Owned masters** (`multiplexing: owned_masters`, materialized bindings only).
   * **Start.** The supervisor starts `ssh -M -N` as a **foreground child**, never with `-f`, with
     these options:
     * `-o ControlMaster=yes`, `-o ControlPersist=no`, `-o ControlPath=<runtime_dir>/mux/<16 hex>`;
     * `-o IdentityAgent=<binding endpoint>`, `-o IdentitiesOnly=yes`,
       `-o IdentityFile=<binding key.pub>`, `-o CertificateFile=<binding cert>`;
     * `-o ClearAllForwardings=yes`, `-o ExitOnForwardFailure=yes`, `-o BatchMode=yes`;
     * `-- <alias>`.

     It is recorded as a `ManagedResource` (`Process`, generation-tagged) and in `owned_connections`
     (kind `master`: PID, start token, control path).
   * **P.** The pair's section in P names `ControlPath "<runtime_dir>/mux/<16 hex>"` with `ControlMaster
     no`. Ordinary clients use the master when it exists, and connect directly otherwise (M-F5).
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
     be verified is left alone and reported unmanaged.
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

---

## 10. D9 — Lock and unlock

1. **Default `continue`.** A desktop lock and a personal-vault lock do not end managed grants (spec
   §6.4). The signer and issuer hold their keys in memory.
   * Heimdall does not observe the personal vault, and does not need to. That independence is the
     point of the recipe.
   * **The disclosure is shown once** (R-UX-03), in the `RegisterIssuer` and first `EnrollAccount`
     decisions and in `inspect capabilities`:
     > Approved work keeps working while your screen or password manager is locked, until its end
     > time. To stop it when you lock the screen, set lock behaviour to "revoke on lock".
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

   | Platform | Query | Events | Status in M03 |
   |---|---|---|---|
   | macOS | `CGSessionCopyCurrentDictionary`, `CGSSessionScreenIsLocked` | distributed notifications on a dedicated run-loop thread | implemented; native evidence through P1 (M-F12) |
   | Windows | `WTSQuerySessionInformationW(WTSSessionInfoEx)` for the current session | `WTSRegisterSessionNotification` on a hidden message-only window thread | implemented; native evidence through P-W1 (M-F13) |
   | Linux desktop | logind `LockedHint` (D-Bus system bus) | `Lock`/`Unlock` signals | implemented; **native evidence blocked on B11** |
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
   * `ControlPath none`, or the owned master path.

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
   its connection is an owned dedicated connection (D8).

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
   client_configuration_and_signer` is reported only when `exclusive`.

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
   * `RevokeData`: `remote_effects`, `destination_clock_error`.
   * Spelling: ADR-0005's `not_enforced` is the existing `none` of `NewAuthenticationExpiry`, which the
     G08 naming freeze may rename. ADR-0005's `available_through_deadline` is the existing
     `CredentialAvailability::ThroughDeadline`.

2. **Per-field rule:** a value whose test has not passed **for this platform and these versions** is
   `unknown` (or `not_verified` for `lock_continuity`). An unmet or unknown minimum is
   `CAPABILITY_UNAVAILABLE` (R-AU-08).

3. **Two evidence sources:**
   * **Runtime evidence**, produced by the product itself and recorded with the grant or enrollment:
     the enrollment's positive and negative verification for `destination_scope`, with client and server
     versions and time. Its freshness is 90 days; a proposal, Q11. After that the pair's scope reports
     `unknown` until `enroll verify` runs.
   * **The claim table** (`heimdall_domain::claims::CLAIMS`). It is the **only** source of
     platform-mechanism claims: `lock_continuity: verified`, `new_signing_expiry: signer`,
     `owned_multiplexing: closed_at_deadline`, `existing_connections` behaviour,
     `new_authentication_expiry: credential_and_signer`, and the summary `revocation`.
   * Limitations and the binding's own configuration (`owned_multiplexing: disabled`,
     `remote_processes: not_terminated`, `unmanaged_connections: not_controlled`, `workload_isolation:
     shared_os_user`, `issuer_isolation: same_user_process`) are always reported. They claim nothing. It is a
     static list compiled into the binary. Each entry holds:
     * field, value, platform and architecture;
     * OS release floor, client version range and signer build range;
     * a record path and the record's commit.

     `check.sh` (`claims-table` step) fails unless every entry's record exists, validates, is `verified`
     for that platform row, and names a commit that is an ancestor of HEAD. **The M03 baseline table is
     empty.** Entries are added only by a reviewed commit after the native record is `verified`
     (m03-plan §3, "claim update"), and the claim tests then re-run on the build that contains them.

4. **Never reported by M03:** `isolated_execution_boundary`, `authenticated_agent_restriction`, universal
   immediate revocation, remote process termination, `verified_server_key_enrollment` (Recipe A is not in
   M03), `log_attestation: available`.

5. **Time synchronization.** The `TimeSync` readers report observations: Linux `timedatectl show -p
   NTPSynchronized`, the macOS time daemon's state, Windows `w32tm /query /status`. **They are not
   trusted in M03:** the gate still receives `Unknown` until M04/G09 evidence (ADR-0006 §13.3 item 4;
   Q13). So after a reboot managed issuance waits for an attended `heimdall time confirm`; that is
   disclosed in `conditions` as `time_confirmation_after_reboot`.

---

## 14. D13 — Test environments

1. **The disposable CA.** Each run has its own K_ca, created through the real `issuer init` ceremony on a
   pty, in `ScratchSecretStore`, or, on Windows, in real DPAPI on a scratch path (ADR-0004 §3). The
   key's comment carries a canary. Nothing is committed. The D5 backup goes to scratch, and the
   passphrase is captured only from the pty transcript, which A33 scans as the one allowed location.

2. **Disposable sshd targets** (all on loopback; AGENTS.md). Two families: loopback sshd on every host,
   and the Docker containers on the build host.

   | Target | Form | How | Proves |
   |---|---|---|---|
   | `LoopbackSshd` ×2 (non-root, scratch `AuthorizedKeysFile`, two destination IDs) | account | Enrollment with an explicit `--registry-path <scratch file>`. The **registry guard** (item 4) refuses any other path | the add, remove and verify protocol; A10 wrong host; interleavings |
   | `LoopbackSshd` with `TrustedUserCAKeys <scratch>` and `AuthorizedPrincipalsFile <scratch>/%u` | system | The test writes the CA and principals files as the owner-administrator would | A10 system form |
   | Docker `enrollable` and a new `enrollable2` (M00-T03 image; account `enroll`, account-owned registry seeded with unrelated lines including a foreign `cert-authority`; the sshd log not readable by the account) | account, **default registry path** | Build host only; `up.sh` and `down.sh` | the default-path production verification on an account that cannot read the sshd log (ADR-0005 §9.3 R5); A10 on two hosts |
   | Docker `ca1`/`ca2` | system | The harness adds the run's test CA to the container's `TrustedUserCAKeys` (container-internal, disposable) | A10 system form on two hosts |
   | WSL disposable distribution (`wsl --import`; ADR-0004 §3): sshd as the distribution's root on `127.0.0.1`, a disposable non-root user with a real home | account (default path) and system | Inside the disposable distribution only | the real `~/.ssh/authorized_keys` and `StrictModes`; ordinary `ssh` without `-F` for a managed alias |

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
   * `FakeSessionLockSource` in the test configuration;
   * native locks under the ADR-0004 §2 rule only: the harness requires console idle ≥ 15 min (macOS
     `HIDIdleTime`, Windows `GetLastInputInfo`), triggers the lock (macOS `pmset displaysleepnow` where
     that locks; Windows `LockWorkStation` from the interactive session), **verifies the lock state
     through the product's own query**, and records it. If the trigger does not produce a verified lock
     on that host, the row is `blocked` with that observation.

8. **Never touched:** the owner's keychain, Secret Service collections, Credential Manager, DPAPI blobs
   other than scratch ones, agents, 1Password, `~/.ssh`, and real servers.

---

## 15. Contract additions (summary)

ADR-0006 revision 4. The exact shapes are in m03-plan §5. Everything is additive (schema major stays
`"1"`), and every new enum is `#[non_exhaustive]` and `snake_case`.
* **Requests:**
  * `Request::Issuer`: status, register (which covers init, rotate-begin and restore), unlock, retire,
    bundle;
  * `Request::Enrollment`: preview, apply, verify, remove, reconcile, abandon, and the
    client-executed `step` and `step_result` (D5 §6.3);
  * `Request::Connections`: close (owner role, narrowing);
  * the catalog action `SetPreference`.
* **New fields:** `EnsureRequest.connection`; `PolicyAction::{SetLockBehavior, SetConnectionPolicy}`;
  `InspectSubject::{Enrollments, Issuer, Connections}`.
* **Operation kinds:** `enrollment.apply`, `enrollment.verify`, `enrollment.remove`.
* **Decision kinds:** `RegisterIssuer`, `RetireIssuer`, `EnrollAccount`, `RemoveEnrollment`.
* **Capabilities:** `issuer/1`, `enrollment/1`, `managed-credentials/1`, `connections/1`, offered only
  when their drivers land.
* **Fields on existing types:** in `EnsureData`, `Enforcement` and `RevokeData` (D12);
  `CertificateBounds.ca_fingerprint`; `DegradedReason::{CredentialReissuePending, IssuerUnavailable,
  PairUnenrolled}`; `RevocationCause::SessionLocked`; `RemoteObligation.kind`.
* **Events:** `EventType::{Enrollment, Connection, SessionLock}`.
* **Codes:** no new code. The new stable sub-reasons go in `data.error.reason`.
* **Store:** migration `0006_managed_credentials`, `SCHEMA_VERSION` 6.

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

---

## 17. Questions for the orchestrator (authority semantics; recommended answers)

Units build against the recommended answers. The integrator changes the affected unit if a ruling
differs.

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

## 18. Consequences

* **New crates:**
  * `heimdall-credential`: vault, certificates, purpose parsing, session-bind, the signer, endpoints;
  * `heimdall-issuer`: child, protocol, client, stores, backup, ceremony, bundle;
  * `heimdall-enroll`: scripts, remote, registry, verification.

  New modules: `heimdall-adapters::managed`, `heimdall-runtime::{connections, session_lock}`, and the app
  drivers `heimdall-app::{enrollment, issuer, managed}`.
* **The `unsafe` inventory** gains three modules (overview §9), each with its own invariant table:
  * `crates/credential/src/sys.rs`: `mlock`/`munlock`, `VirtualLock`/`VirtualUnlock`,
    `prctl(PR_SET_DUMPABLE)`, `setrlimit(RLIMIT_CORE)`;
  * `crates/issuer/src/sys.rs`: macOS keychain SecAccess and generic-password calls with interaction
    disallowed; Windows `CryptProtectData`/`CryptUnprotectData` with `LocalFree` exactly once;
  * `crates/runtime/src/session_lock/sys.rs`: `CGSessionCopyCurrentDictionary`, `CFNotificationCenter`,
    `WTSRegisterSessionNotification`, `WTSQuerySessionInformationW`/`WTSFreeMemory`, and the
    message-only window.

  `pidfd_open` and `pidfd_send_signal` go through `rustix` (`process` feature) or the existing
  `platform.rs`.
* **New pinned dependencies** (recorded in `dependencies.md` with licence and rejected alternatives):
  * `ssh-key` features `ed25519`, `encryption`, `rand_core`;
  * `zeroize`;
  * on macOS, `security-framework`;
  * on Linux, a Secret Service client (`secret-service` with the tokio runtime feature) and a D-Bus
    client for logind (`zbus`, shared);
  * `windows-sys` features `Win32_Security_Cryptography`, `Win32_System_RemoteDesktop` and
    `Win32_UI_WindowsAndMessaging`.

  U0 pins exact versions at least two weeks old.
* **Store:** migration `0006_managed_credentials`, `SCHEMA_VERSION` 6.
* **The ADR-0007 §2 directive set grows** for `managed_certificate` aliases only (D10). ADR-0007 §14's
  reopen condition "M03/M04 need P to carry CertificateFile" is met by that revision.
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
  bundle path, offers `enroll remove` first, and refuses to purge state while any enrollment is not
  final without `--keep-remote-enrollments` (spec §7.7; R-DI-04).

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
