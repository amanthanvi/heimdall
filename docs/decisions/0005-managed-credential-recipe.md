# ADR-0005: Managed execution-credential recipe B1 (G04)

**Status:** accepted 2026-10-31. The recipe was selected in ADR-0004 §2 under the owner's
delegation; this ADR is its specification, the G04 deliverable of plan §3 ("chosen minimal recipe
ADR, storage/custody specification ... capability reports"). Nothing in it is implemented.
**Review:**
- Round 1 (`tests/evidence/artifacts/review-adr-0005/review.json`): 0 blockers, 5 major R1–R5, 3
  minor R6–R8. Revision 2 applied them and the orchestrator's rulings on the points revision 1 left
  open (§14).
- Round 2 (`…/review-adr-0005/round2/review.json`): R1, R2, R4, R5, R7 and R8 resolved; R3 and R6
  partly resolved; new major R9–R11 and minor R12.
- Revision 3 applies the round-2 findings under the orchestrator's rulings.
- Round 3 (`…/review-adr-0005/round3/review.json`): **accept**; R3, R6 and R9–R12 resolved, no
  new blocker or major. Acceptance covers the design; the §9.3 tests are still to run.

**Date:** 2026-10-31 (revision 3) · **Gate:** G04, with the credential parts of G07 and the
preliminary G09 · **Task:** M00-T04-G04-adr
**Inputs:** spec.md §4.3, §6–§8, §11.3, §13–§15; plan.md §3 G04/G07/G09, §11.3;
`docs/research/g04-managed-credentials.md` (below: "the research"), in particular its §7
recommendation and the §9.1 decisions D1–D5 and Q4; ADR-0004 §2–§4; the evidence in §9.
**Affects:** the requirements and acceptance cases in §11.

## How to read this ADR

| Label | Meaning |
|---|---|
| `[O:key]` | Observed in a recorded run. The key resolves in §9.1 to a record or artifact. |
| `[S:key]` | Pinned primary source from the research's register (research §1.1). |
| `[I]` | Inference. Not observed. |

Sentences such as "the issuer refuses" or "Heimdall closes" are decisions of this ADR, not
observations. No Heimdall code exists. Every `[O]` below is OpenSSH, platform or harness mechanism
evidence; none of it shows that Heimdall behaves so (tests/evidence/README.md). "Unknown" marks an
open measurement and names the probe that closes it.

Notation follows research §3: **K_env** working key, **K_ca** issuer key, **C** user certificate,
**G** grant with deadline **D**. **K_A** is the Recipe A fallback key. A **pair** is one
destination/account pair of a grant's resolved scope.

## 1. Context

- Spec §7.1 and §3.1 require one complete managed execution-credential recipe whose approved work
  continues through desktop and vault lock. Spec §6.5 requires the recipe to state its maximum
  residual remote-access window. Spec §7.3 requires custody rules for every private-key class.
- G04 asks which minimal recipe opens new SSH connections while the desktop and personal vault are
  locked, without exporting the personal key or handing out unrestricted issuer authority.
- The fixed-provider baseline does not survive lock: 1Password does not hold private keys while it
  is locked [S:1P-Security]. A relay cannot change that (plan G04 failure action).
- The research compared three recipes and recommended B1. The owner answered D1–D5 on 2026-10-06;
  Q4 was decided under delegation (research §9.1). ADR-0004 §2 selected B1 on 2026-10-31.
- The OpenSSH mechanism experiments E1–E7 ran on disposable fixtures and are `verified`. A native
  Windows secure-store spike is `verified` for store mechanics only [O:WSS]. Every lock, logout,
  reboot and sleep probe, and every other platform's store probe, is `blocked` (§9).

## 2. Alternatives

| Alternative | Shape | Outcome |
|---|---|---|
| **A** | Per-environment key written directly into each account's key registry; only the local signer knows the deadline | Ships only as a labelled fallback (§3.11) |
| **B1** | Working key in a supervised signer; separate issuer with K_ca; account-level `cert-authority,principals=` line; short certificates | **Selected** |
| **B, system form** | Same, with `TrustedUserCAKeys` + `AuthorizedPrincipalsFile` | Used only where the owner administers the host |
| **C** | Integrate an existing issuer (step-ca) | Rejected (§8) |

Design choices inside B1 (key lifetime, certificate length, custody per platform, connection
closing, backup format) are listed with their rejected options in §8.

## 3. Selected choice: the recipe

### 3.1 Components and endpoints

| Component | Runs where | Holds | Endpoint | Reachable by |
|---|---|---|---|---|
| **Signer** | Every execution environment, supervised by that environment's Heimdall runtime | One K_env per active grant and per delegated child; the matching certificates (public) | Agent protocol [S:RFC9987] on an owner-only Unix socket in a 0700 directory with a peer-credential check, or a named pipe with a protected single-ACE DACL and a client-SID check. One endpoint per binding, plus the environment endpoint for ordinary tools (spec P03) | `ssh`/`git` through `IdentityAgent`; a container or WSL relay of one binding endpoint |
| **Issuer** | A separate process on an owner device that has a desktop session (macOS, Windows, Linux desktop) | K_ca in memory; the serial counter; the issuance log | Its own owner-only endpoint, distinct from the control and signing interfaces (spec §13.2) | The local Heimdall supervisor only |
| **Supervisor** | Every environment | Grants, generations, tombstones, enrollment inventory, owned connections | Management interface (spec §13.2) | Owner CLI/TUI and authenticated callers |

- The issuer endpoint is never bound into a container, bridged into WSL, forwarded, listed on a
  signing endpoint or offered to a paired limited client. Signing endpoints never accept issuance
  or management requests (R-SE-06).
- The signer answers list and sign requests and the `session-bind@openssh.com` extension only. It
  refuses add, remove, lock, unlock, smart-card and every other extension (the filter of the G03 B2
  design, g03 research §3.3).
- A WSL distribution's K_env is held by the Windows-side signer and reached through the Mode B
  relay (G03 B2; ADR-0004 §3). A Linux-side signer inside the distribution (G03 B3) is not used. A
  container binding mounts one binding endpoint (spec §8.5).
- **Same-user boundary.** Any process running as the owner that reaches an endpoint can use it
  [S:RFC9987 §10][S:ssh-agent.1]. E5 showed this for an issuer socket: a same-user process that
  knew the path obtained a certificate [O:E5]. Results disclose it (`workload_isolation:
  shared_os_user`, `issuer_isolation: same_user_process`, §7). Stronger isolation needs a separate
  OS account, host, or external issuer (spec §7.3) and is a reopen path (§13).

### 3.2 Keys

- **K_ca:** Ed25519, software, one per owner **per issuing device**. D1 requires the issuer to sign
  while the desktop is locked, from memory (ADR-0004 §2). D5 requires an exportable backup. Hardware
  keys are non-exportable [S:Apple-SEKeys][S:MS-TPM], and an sk-type key as CA was not tested
  [O:P5]. The fixture CA (Ed25519, generated by `tests/fixtures/ssh/up.sh`) signed both Ed25519
  and P-256 sk-ecdsa user certificates that sshd accepted [O:E1][O:E3][O:P5]. A destination account enrolled from two issuing devices carries
  two lines, one per CA. K_ca is never copied between live devices.
- **K_env:** generated inside the environment's signer and never leaving it. The signer holds
  **one K_env per active grant** (and one per delegated child). Ed25519 in signer memory by
  default; P-256 in hardware where a platform probe has verified signing under lock (§5.2). Reasons
  in §3.7.
- **Certificates:** one per pair (§3.4).

### 3.3 Enrollment

Enrollment uses spec §7.4 capability 2 and the spec §7.5 transaction. Each enrolled account gets
one line in its actual key registry:

```text
cert-authority,principals="hm:<destination-id>:<account>" <K_ca public key> heimdall:<enrollment-id>
```

- **No other options on the line.** Certificate restrictions and line options combine as "the most
  restrictive union" [S:sshd.8], so the certificate profile (§3.4) carries the restrictions. A
  `restrict` or forwarding ceiling on the line would turn every change of a grant's permissions
  into a remote write. An `expiry-time` on the CA line would make CA rotation a periodic remote
  write; K_ca compromise is handled by removing the line (§6.3).
- **Marker:** `heimdall:<enrollment-id>`, an opaque ID with no host name, account or path.
- **Transaction (spec §7.5).** Heimdall records the intent durably before any remote write and the
  observed outcome afterwards. A broken connection after a write leaves the operation
  `outcome_unknown` until a re-read reconciles it by marker; Heimdall never appends a second line
  blindly. `authorized_keys` has no portable conditional write [I], so the two directions use
  different mechanisms:
  - **Add (enrollment, the add step of rotation):** append the one line to the existing file in a
    single write through a descriptor opened with `O_APPEND` (a POSIX `>>` redirection in a remote
    command [I]). The file is never rewritten, so no stale copy can replace an administrator's
    edit. A leading newline is written only if the preimage did not end with one; empty lines are
    ignored in this file [S:sshd.8]. If no file exists, it is created exclusively (`O_CREAT|O_EXCL`,
    mode 0600) inside an existing owner-only directory. On a network file system `O_APPEND` may not
    be atomic [I]; the post-write re-read below catches a corrupted line.
  - **Remove (unenrollment, the retire step of rotation):** compare, then rename. Heimdall builds
    the post-image from a preimage it has read. Immediately before the rename, in the same remote
    command, it re-checks the preimage's hash, size and mtime. If any differ it does not rename and
    starts again. A registry that is a symlink, has more than one link, or carries ACLs or labels
    Heimdall cannot reproduce is not rewritten; the owner gets exact manual instructions instead.
  - **Disclosed limitation:** an administrator write that lands between the final check and the
    rename is lost. The window is the gap between two system calls in one remote command [I], not
    zero. Removal cannot detect such a loss afterwards.
  - **After every write:** re-read the file. If it differs from the expected post-image (the
    preimage plus exactly the one added line, or minus exactly the one removed line), report
    `outcome_unknown` and reconcile; never retry blindly.
  - **Evidence scope:** E4 measured one add by check-then-rename and one removal by marker, with no
    concurrent writer; the seed bytes were restored [O:E4]. ENR measured an administrator append
    landing *between* enrollment and removal, which removal preserved; it did not race the rename
    [O:ENR]. Neither measured the append path or an edit inside the window. §9.3 requires an
    interleaving test.
- **Verification (production).** The proof needs no access to server logs. Heimdall launches an
  independent `ssh` process with:
  - a generated configuration file (`-F`), never the user's configuration;
  - only the new credential: a verification-only key in a dedicated signer endpoint,
    `IdentitiesOnly yes` and `CertificateFile`;
  - `PreferredAuthentications publickey`, with password and keyboard-interactive off;
  - `ControlMaster no`, `ControlPath none`, `BatchMode yes`;
  - `StrictHostKeyChecking yes` against the destination's already verified host key;
  - a trivial remote command.

  It uses two certificates valid for at most 5 minutes:
  - **positive** (`hm:<destination-id>:<account>`): must exit 0, and the verification signer must
    record exactly one signature for the key during that process. The client signs only after the
    server accepts the offered key [I]; in E1 one login produced one agent sign request [O:E1];
  - **negative**, from the same CA with the principal `hm:verify-negative:<nonce>`: must be refused,
    with no signature recorded. A principal mismatch was refused at the query stage in P5 [O:P5].

  Only an account that passed both reports `verified_server_principals`. This proves the server
  reads this registry and enforces `principals=` there; a guessed `authorized_keys` may not be the
  authoritative registry (spec §7.4), and a scope claim needs a tested mechanism (spec §7.6).
- **Server-log attestation is optional.** It is an extra enrollment capability,
  `log_attestation`, reported `unavailable` when the account cannot read the sshd log. The
  fixture's log oracle (exactly one new accepted line with the expected key ID [O:E6]) remains the
  test oracle; it is not the production criterion.
- **Principal form:** `destination-id` is Heimdall's durable opaque ID (spec §4.2); `account` is
  the remote account name. Both are limited to `[A-Za-z0-9._-]`. The issuer refuses any other
  principal. Principals are comma-separated lists in both certificates and `principals="..."`
  [S:sshd.8], so no quoting, comma, colon inside a component, whitespace or pattern character may
  appear. Accounts with other names use the system form or Recipe A.
- **System form:** only where the owner administers the host: `TrustedUserCAKeys` plus an
  `AuthorizedPrincipalsFile` that maps the account to its `hm:` principal. Shown on fixture ca1/ca2
  [O:E3]. `AuthorizedPrincipalsFile` is not consulted for CAs trusted through `authorized_keys`
  [S:sshd_config.5], so the two forms do not interact.

### 3.4 Certificate profile

| Field | Value | Reason |
|---|---|---|
| Type | OpenSSH user certificate | spec §7.2 |
| Subject key | The grant's K_env (or the child's key) | §3.7 |
| Principals | **Exactly one:** `hm:<destination-id>:<account>` | A wrong-host attempt fails on the principal alone [O:E3][O:E4]. A two-principal certificate is usable on both hosts [O:E3], so one per certificate keeps the scope exact and lets extensions differ per pair |
| Key ID | `heimdall:<environment-id>:<grant-id>:<serial>` (opaque IDs only) | sshd logs it on every authentication [S:ssh-keygen.1]; the fixture test oracle counts accepted lines by key ID [O:E6] |
| Serial | Random 64 bits from the OS CSPRNG, reserved in the issuance log before signing (§3.5) | Attribution; a later KRL by serial where capability 3 exists [I]. Collisions are negligible in practice (birthday bound about n²/2⁶⁵ for n certificates [I]), so no high-water mark is needed and a key-only restore cannot reuse a serial by counting from a lost value |
| `valid_after` | Issuance time − 60 s | Tolerates a destination clock up to 60 s behind at the start only; the end is never widened. The skew bound itself belongs to G09 |
| `valid_before` | min(grant deadline D, policy cutoff, parent deadline) as known at issuance, rounded down to the second | spec §6.5. sshd refuses new authentication outside the window [O:E2]. Always set: without `-V` a certificate is valid "from the Unix Epoch to the distant future" [S:ssh-keygen.1] |
| Critical options | **None in V1** | Unknown critical options make a certificate be refused [S:ssh-keygen.1]. `force-command` breaks ordinary use. `verify-required` belongs to presence-required hardware, which is not unattended (spec §7.2). `source-address` is a later candidate |
| Extensions | Start from `clear` [S:ssh-keygen.1], then per pair as below | ssh-keygen otherwise permits agent, port and X11 forwarding, PTY and `~/.ssh/rc` [S:ssh-keygen.1] |

Extensions per pair:

| Extension | Set when |
|---|---|
| `permit-pty` | The pair is used for shells or commands (the default for an ordinary destination) |
| `permit-port-forwarding` | The grant's route uses the pair as a jump host (`ProxyJump` opens a forwarding channel on it [I]), or the grant explicitly asks for forwarding |
| `permit-agent-forwarding` | Only on an explicit grant request; agent forwarding is a separate capability, off by default (spec §8.5) |
| `permit-user-rc` | Only on an explicit grant request |
| `permit-X11-forwarding` | Never in V1 |
| `no-touch-required` | Never by default. A CTK key with `-t none` logged in without it [O:P5]; whether it is needed under lock is unknown (P5 lock row) |

The experiments used certificates with default extensions [O:E7P][O:P5]. The restricted profile
is untested. sshd applies certificate restrictions to the authenticated connection ("Forbids TCP
forwarding when this key is used for authentication" [S:sshd.8]). So a certificate without
`permit-port-forwarding` should also deny the forwards that E7P obtained through a live master
[I]. M03 must test this (§9.3).

### 3.5 Issuance rules

The issuer signs only on a request from the local supervisor. The request names a grant (ID and
generation), the subject public key and the pairs. The issuer trusts none of the request's claims.

**Issue and revoke are linearized** through the transactional store that holds grants,
generations, cutoffs and tombstones (spec §13.3). The issuer runs the protocol against that store:

1. **Reserve**, in one store transaction. Check the refusal list below against the current store:
   grant state and generation, the revisions of every ancestor and of the policy, tombstones,
   cutoff and time. If every check passes, draw the random serial and write the issuance-log entry
   in state `reserved` with its complete bounds: serial, key ID, principal, `valid_after`,
   `valid_before`, extensions and subject-key fingerprint. Commit. Nothing is signed before this
   commit.
2. **Sign** exactly the reserved certificate, outside the transaction.
3. **Publish**, in a second transaction. Re-apply **every** predicate of the refusal list below
   against the current store and current time, not only the revisions. That covers:
   - grant state;
   - the effective deadline, cutoff and parent deadline, which must not have passed under the
     §3.6 time rule;
   - pause, where it applies to a new activation;
   - time confidence (no `TIME_UNCERTAIN`);
   - unchanged generation, ancestor and policy revisions, and no tombstone.

   If all hold, mark the entry `published`; only then release the certificate to the local signer
   or, over the paired channel, to a runner. If any fails, mark it `voided`, zeroize the
   certificate and release nothing. A deadline or cutoff that passes between reserve and publish
   advances no revision, so this re-check, not the generation check, is what catches it.
4. **Install** at the receiver. The receiving signer, local or on a runner, checks its own view of
   the grant before installing the certificate or admitting anything with it: generation,
   tombstones, and a safe deadline under §3.6 (on a runner, the deadline derived in §3.6 from the
   time exchange). If its view is stale or unsafe it discards the certificate. Discarding does not
   remove the entry from the residual: a published entry stays counted.

Revocation and cutoff changes are single transactions that write the tombstone or cutoff and
advance the generation. They therefore serialize with the reserve and publish steps (1 and 3):
- a revocation that commits before a reservation makes the reservation fail;
- a reservation that commits first is visible to the revocation, which counts it;
- a publication after the revocation sees the new generation and voids.

`latest_possible_credential_expiry` (spec §6.7) is the latest `valid_before` among every entry
for the revoked scope that is `reserved` or `published`, whether or not delivery succeeded or was
acknowledged. Only `voided` entries, which were never released, are excluded. Crash recovery treats
a `reserved` entry as possibly issued: it stays counted until its `valid_before` passes and is
never published after a restart; recovery makes a fresh reservation instead.

The issuer refuses, writes no certificate and records an audit event when:

1. the grant is not `preparing`, `active` or `degraded`; its generation, an ancestor's revision or
   the policy revision is stale; or a tombstone exists for it or an ancestor (R-SE-07);
2. a pair lies outside the grant's resolved snapshot; a child's pairs are not a subset of its
   parent's; or a principal breaks §3.3;
3. the requested `valid_before` is later than min(D, cutoff, parent deadline), or that minimum has
   passed;
4. the request would activate a new grant under a paused policy or after a cutoff (R-AU-02).
   Re-issue for an existing grant follows the §3.7 recovery rule; a pause blocks new activations
   only (spec §5.6);
5. the subject key is not one this environment's signer registered for this grant. This stops the
   supervisor API certifying an arbitrary key; it is still inside the same-user boundary;
6. any critical option, or an extension outside the grant's permissions, is requested;
7. time is uncertain (§3.6): `TIME_UNCERTAIN` (spec §6.4).

The only other certificates are the enrollment verification pair (§3.3): valid for at most 5
minutes, issued under an enrollment operation the owner approved, and reserved and published like
any other.

**Coverage.** At activation the issuer issues one certificate per pair that covers the whole grant.
It re-issues only after a K_env is lost (signer restart) or for a delegated child. Shorter renewed
certificates are not used in V1 (§8).

### 3.6 Signer rules

Per signature request, the signer checks:

- the key belongs to a binding served by this endpoint;
- the grant is `active` or `degraded`, its generation is current, and no tombstone exists for it or
  an ancestor;
- the grant's admission deadline has not passed and time is not uncertain (time rules below);
- **purpose:** the data is an SSH public-key user-authentication request whose embedded key is this
  grant's K_env or one of its certificates. Anything else, such as an `SSHSIG` request for Git
  signing, is refused (spec §7.2). Parsing uses an established library, never ad hoc code (spec
  §7.2); the host-bound variant of the request must be accepted [I].

A policy pause blocks new activations only; running grants continue (spec §5.6). An immediate
stop is a revocation (§6.1).

**Time (spec §6.4, R-AU-06).** The signer, the issuer and the supervisor's owned-connection timers
use one rule.

**Threat model.** A deliberate clock change by an administrator is outside it: spec §6.4 makes no
claim against "a fully compromised root/admin controlling both the clock and enforcement".
Accidental faults are covered: a wrong real-time clock after a reboot, a failed or absent time
sync, a manual mistake by the owner.

**Clocks:**

- **Continuous clock:** a per-boot clock that keeps counting during sleep: `CLOCK_BOOTTIME` on
  Linux, `mach_continuous_time` on macOS, interrupt time including suspend on Windows [I]. macOS
  `CLOCK_MONOTONIC` also keeps counting during sleep [S:clock_gettime.3].
- **Boot ID:** the platform's per-boot identifier: Linux `/proc/sys/kernel/random/boot_id`, macOS
  `kern.bootsessionuuid` [I]. The Windows source is to be selected and evidenced in M04.

**Rules:**

- **Grant anchor.** When a grant is activated, or first validated in the current boot, the runtime
  persists, in the transactional store, the boot ID, the continuous-clock reading and the trusted
  wall time at that moment. The grant's budget end on the continuous clock is the anchor reading
  plus (min(D, cutoff, parent deadline) − anchor wall time). An earlier cutoff set later shortens
  it; nothing lengthens it.
- **Admission deadline:** the earlier of
  - (a) the immutable absolute min(D, cutoff, parent deadline), compared with the wall clock; and
  - (b) the budget end on the continuous clock.

  A backward wall-clock step cannot extend authority, because (b) still runs out.
- **Same-boot restart** (process restart, logout and login): the runtime reloads each grant's
  anchor when the boot ID is unchanged and resumes the budget from it. It **never rebuilds a budget
  from the current wall clock.** It also compares the wall clock with the anchor's prediction
  (anchor wall time + elapsed continuous clock). A disagreement beyond the tolerance means
  `TIME_UNCERTAIN`.
- **After a reboot** (boot ID changed) the anchors are void. The runtime accepts the operating
  system's wall clock only if **both**:
  - it is at or above the persisted high-water mark; and
  - the OS reports synchronized time. Candidates: Linux `timedatectl show -p NTPSynchronized`
    (systemd-timesyncd and compatible daemons); macOS the time daemon's synchronization state;
    Windows `w32tm /query /status` (last successful sync, source) [I]. Which signal is
    trustworthy on each platform is to be evidenced in M03 and M04.

  Only then are new anchors created, from that accepted wall time. Otherwise time is uncertain.
- **High-water mark:** the runtime persists the latest wall-clock time it has accepted under these
  rules, at least at every issuance and periodically while grants are active. Consistency with the
  mark alone is not enough after a reboot. A clock rolled back after downtime can stay above the
  mark (stopped at 10:00, real time 12:00, clock reset to 10:01), which is why synchronization is
  also required.
- **`TIME_UNCERTAIN`** applies when:
  - the wall clock is below the high-water mark by more than the tolerance;
  - within a boot, it disagrees with the anchor's or the process's continuous-clock prediction by
    more than the tolerance in either direction (an implausible forward jump included); or
  - after a reboot, it is not accepted as above.

  While it holds:
  - no re-issue, no signature and no admission happen, and owned masters are closed;
  - results report `TIME_UNCERTAIN`;
  - it is resolved by the conditions above becoming true, or interactively by an explicit owner
    confirmation of the current time in the owner-present CLI/TUI (never `--non-interactive`, an
    agent or a paired client);
  - resolving it never extends a grant: absolute deadlines never move, and a surviving budget end
    still applies.

  The tolerance is set by G09.
- **Wake:** time is validated before any signature or admission. Sleep counts against the budget,
  because the continuous clock includes it and sleep does not suspend the deadline (spec §6.4).

**Runner deadline (G07):**

- The runner never starts a budget at receipt from a duration the controller states. It derives its
  deadline from the absolute D through an **authenticated time exchange** with the controller over
  the pairing channel:
  1. it records its continuous clock at t₁ and sends a nonce;
  2. the controller answers with its wall time T_c, bound to the nonce;
  3. the runner records t₂.
- The controller's time at t₂ lies in [T_c, T_c + (t₂ − t₁)]. The runner takes the upper bound
  (the estimate plus the RTT/2 uncertainty), so its deadline on its own continuous clock is
  t₂ + (min(D, cutoff, parent) − (T_c + (t₂ − t₁))). It may stop early, never late [I].
- The runner applies the earlier of that and its own wall-clock branch. It retains the deadline as
  the grant's runner anchor. A certificate's receipt or re-issue does not restart it; a later
  exchange may only move it earlier.
- After a runner reboot, a fresh exchange is required before any admission.
- **Without a bounded offset** (no exchange, an RTT above the bound G09 sets, or a replayed or
  unauthenticated answer) the runner reports `TIME_UNCERTAIN` for the grant and
  `CAPABILITY_UNAVAILABLE` for owned-connection deadline admission: no owned masters, no deadline
  claim. New authentication stays bounded only by the server's `valid_before`, reported as
  `credential_only` (§7.1).

**Destination clocks.** The issuer's clock sets the certificate bounds. A destination whose clock is
behind by s accepts new authentication for up to s after `valid_before`. Heimdall does not
measure destination clocks, so this component has no finite bound in Heimdall's evidence. It is
diagnosed separately as a server clock error (spec §6.4), and residual reports carry
`destination_clock_error: unmeasured`.

**At grant end** (expiry, cutoff, revocation, release of the last reference) the signer destroys the
grant's K_env (zeroized; a hardware key deleted by exact handle) and drops its certificates from
every endpoint. Outstanding certificates then cannot be used from this environment, because no key
remains [I]. For a deleted CTK key the agent still listed the key but could not sign [O:P5]. The
signer and issuer disable core dumps and keep key memory locked and zeroized where the platform
allows. These are mitigations, not a boundary.

### 3.7 Why one working key per grant, and recovery

- **Ending access by destruction.** Expiry and revocation remove the only copy of the key, so the
  certificate becomes useless locally without parsing or filtering. Certificates on separate keys
  also make per-grant signer checks key-based.
- **No at-rest copy is needed for local environments.** In B1 a lost K_env costs one re-issue and
  no remote write (research §4). An at-rest copy would buy nothing locally and would add a store
  item readable by same-user code [I].
- **Recovery rule.** After a key is lost, the issuer may certify a new key for a grant only when
  all of these hold:
  1. the grant is unexpired, not revoked, not released, and no cutoff covering it has passed;
  2. its scope and absolute deadline are unchanged: the same pairs and the same D. Re-issue never
     widens or extends a grant;
  3. time has been validated under §3.6: in the same boot from the grant's persisted anchor; after
     a reboot only from an accepted, synchronized wall clock or an owner confirmation; on a runner
     from a fresh authenticated time exchange;
  4. the grant was read from the transactional store with its generation and tombstones, never
     from a PID, socket or other process file (spec §6.4, §13.3);
  5. the owner has not chosen lock-revokes (or a future logout-revokes) for it. Under those,
     recovery issues nothing and the grant ends.

  This is renewal within an existing grant (spec §5.5, R-RT-07), not a new activation, so a pause
  does not block it. It goes through the §3.5 protocol like any issuance.
- **Lifecycle events.** Each is listed and tested separately (§9.3):

  | Event | Working key | Time basis (§3.6) | Recovery | New approval |
  |---|---|---|---|---|
  | Signer or supervisor process restart, same login session | Lost | Same boot: resume the persisted anchor | The local issuer re-issues under the rule | No |
  | Logout, then login | Lost | Same boot: resume the persisted anchor | Re-issue at login under the rule | No |
  | Reboot, then login | Lost | New boot: wall clock at or above the high-water mark **and** synchronized, or an owner confirmation; else `TIME_UNCERTAIN` | Re-issue only once time is accepted | No |
  | Runner process restart, same boot | Lost | Resume the runner anchor | Re-issue once the controller's issuer is reachable; `degraded` until then | No |
  | Runner reboot | Lost | Fresh authenticated time exchange | As above, after the exchange | No |
  | Any of the above with lock-revokes or logout-revokes chosen | Lost | — | None; the grant has ended | A new activation is needed |

- **This supersedes D2's cost note.** D2 accepted memory-only custody with the cost "loss at logout
  or reboot needs a new approval" (research §9.1). Re-issue after logout and reboot under the rule
  above is an orchestrator decision under the owner's delegation, recorded in ADR-0004 §2. D2's
  acceptance of memory-only custody stands.
- **Remote runners are different.** There an at-rest K_env would let the runner survive its own
  restart without the issuer. B1 adopts one only after a headless store is verified (§5.2,
  P-L2). Until then D2 applies.
- This refines the research's "software key in the platform store" (research §7). Under D2, memory
  is acceptable where no store has been verified under lock or after restart, which today is every
  platform (§9.2).

### 3.8 Connections at the deadline

- **Bounded contexts default to no multiplexing** (`ControlMaster no`, `ControlPath none`). Spec §6.6
  asks for this when graceful channel-level enforcement cannot be established. None can: `ssh -O
  stop` leaves control connections accepted before the stop still admitting sessions and forwards
  [O:E7P], and certificate expiry does not stop multiplexed admissions [O:E7].
- **Where the owner enables multiplexing**, masters are Heimdall-owned. They start as foreground
  children of the supervisor (no `-f`). At the admission deadline of §3.6 (the earlier of the
  absolute and continuous-clock limits), on `TIME_UNCERTAIN` and on revocation they are closed with `ssh -O exit`,
  then SIGTERM to the exact PID checked by PID, start time and control path. `-O exit` ended the
  master, its sessions and pre-accepted control connections; exact-PID SIGTERM also closed the
  forward listeners [O:E7][O:E7P]. `ControlPersist` is not a grant
  timer (spec §6.6). A supervisor that restarts closes owned masters of ended grants before doing
  anything else.
- **On a runner**, owned masters are started only while its time offset is bounded (§3.6).
- **Owned dedicated connections** (started by `heimdall connect`/`run`): kept at expiry under the
  graceful default; closed under strict; closed on revocation (Q4 b).
- **Unmanaged connections.** Masters created by the user's own configuration, and ordinary `ssh`
  processes that authenticated through the environment endpoint but were not started by Heimdall,
  are unmanaged. Heimdall controls their new authentications, not their live connections (spec
  §6.6).
- **Remote processes** are never claimed to stop: the remote no-tty shell of a session closed by `-O
  exit` was still running 20 s later [O:E7].

### 3.9 Certificates and projections

Public keys and certificates live in Heimdall's materialized data directory at stable per-binding
paths that are replaced atomically by generation. The managed OpenSSH projection sets
`IdentityAgent` to the binding endpoint, `IdentitiesOnly yes`, `IdentityFile` to the grant key's
public half and `CertificateFile` to the pair's certificate. This is the configuration the
experiments used [O:E1][O:E2]. Certificates are public but name destination IDs and accounts, so
exports redact them (spec §7.3, §13.6).

### 3.10 Delegation (A28)

A child gets its own key in the signer, on its own binding endpoint, and one certificate per pair
of a subset of the parent's pairs, with `valid_before` no later than the parent's. Servers enforce
both: E5's child was refused on the other host and expired before its parent [O:E5]. Parent expiry
or revocation destroys the child keys. The child endpoint cannot request issuance; only the
supervisor issues, on an authorized delegation (spec §8.7). The credential is attenuated at the
server. The workload is not isolated: a same-user child can reach the parent's endpoint, so the
result says so (§7).

### 3.11 Recipe A as a labelled fallback

- **When:** chosen per pair at enrollment, when the server lacks OpenSSH user-certificate support or
  B1 verification fails and the owner opts in. It is **never** a runtime fallback when the issuer
  is unavailable (spec §15.2).
- **Key:** one K_A per pair, generated in the environment, never imported from the personal vault.
  Ed25519, or P-256 where hardware-backed or where the server lacks Ed25519. The algorithm is taken
  from what the server offers. sk-type keys are not used, since such servers are unlikely to
  support them [I].
- **Line:** `restrict,<enabled permissions>,expiry-time="<UTC>Z" <K_A public key>
  heimdall:<enrollment-id>`. `pty` is the default permission; `port-forwarding` only for a jump
  host. The line is written with the §3.3 add procedure (append) and verified with the §3.3
  production procedure. Options are written only where the server documents them (pinned at
  enrollment). `expiry-time` defaults to enrollment + 90 days. That is an implementer-selected
  proposal, accepted as a proposal by the orchestrator; the owner may change it or set none, and
  "none" is reported as an unbounded residual.
- **Not offered on headless runners in V1:** it needs a persistent key store, and none is verified
  there (§5.2).
- Custody is in §5.1. Capability reports name it `managed_key`, never `managed_certificate` (§7).

## 4. Authority flows

### 4.1 Local environment

```text
owner (present) ── approves ──▶ standing policy ──▶ grant G {pairs, D, generation}
                                                         │ supervisor (control plane)
                                                         ▼
issuer: K_ca in memory ◀── issuance request {grant id+gen, K_env.pub, pairs} ── signer registers K_env.pub
   │ rules §3.5; one C per pair; valid_before = min(D, cutoff, parent)
   ▼
signer: K_env per grant (memory) ── binding endpoint ──▶ ssh / git (IdentityAgent, IdentitiesOnly, CertificateFile)
   │ rules §3.6 on every signature                                   │ fresh authentication
   ▼                                                                 ▼
supervisor: closes owned masters at D          destination account: cert-authority,principals="hm:<d>:<a>" K_ca.pub
            and on revocation                  sshd checks validity, principal and extensions on every new authentication
```

### 4.2 Remote runner (G07)

```text
runner (own Heimdall runtime)                                 controller device (owner)
  signer generates K_env per grant ── K_env.pub over the ──▶  supervisor checks the runner's paired identity
                                      paired channel (G07)    and its role; issuer signs C per pair,
  ◀──────────────── certificates (public) ───────────────────  valid_before = min(D, cutoff)
  ◀────── authenticated time exchange (nonce, T_c) ──────────  bounds the runner's offset (§3.6)
  runner supervisor enforces D, cutoff, tombstones locally; closes its own owned connections
  K_ca never leaves the controller device (spec §6.5, §7.3)
```

The pairing mechanism is G07's choice. This ADR requires only that the channel authenticates the
runner's environment identity before its key is certified, and that a paired limited client cannot
obtain issuance for any other environment (spec §8.6).

### 4.3 Authority table

| Question | Local environment | Remote runner |
|---|---|---|
| Who can issue | The issuer, for a request from the local supervisor that passes §3.5. Inside the boundary also: any same-user process that reaches the issuer endpoint [O:E5], or reads the K_ca store item [I] | The controller's issuer only. Nothing on the runner can issue |
| Who can sign | The signer, for keys of active grants, for any same-user process that reaches a binding or environment endpoint [S:RFC9987 §10] | The runner's signer, likewise, on the runner |
| What can be exported | Certificates (public). K_env: nothing (memory only, or non-exportable hardware). K_ca: once, into the D5 encrypted backup (§5.3) | Certificates; K_env nothing. K_ca never reaches the runner |
| What persists, and where | Owner device: K_ca encrypted in the platform store (§5.2); issuance log, grants, tombstones, enrollment inventory in transactional state. Destination: one CA line per account. Owner offline: D5 backup | Runner: certificates, grants, tombstones; no private key at rest in V1. Controller: as local |
| Where D is enforced | **Signer**: every signature (§3.6). **Issuer**: no certificate past min(D, cutoff), checked at reserve and at publish. **Server**: `valid_before` on every new authentication [O:E2]. **Supervisor**: closes owned masters at the admission deadline | The same, locally on the runner (spec §8.1), against a deadline derived from D through the authenticated time exchange. Without a bounded offset: no owned masters, and only the server's `valid_before` bounds new authentication |
| Controller (CLI/TUI) exits | Nothing changes; the runtime continues | The runner continues to `valid_before` (spec §8.1) |
| Issuer disappears | Certificates stay valid to `valid_before`; running grants continue. New grants and re-issues fail with `CAPABILITY_UNAVAILABLE`; no fallback key (spec §15.2) | Same; a runner restart cannot be repaired until the issuer is reachable |
| Signer or supervisor stops (crash, logout, reboot) | Memory keys are gone, so no new authentication, although certificates stay valid at servers. Owned masters stay open until the supervisor recovers [I]. On recovery: validate time, close stale masters, then re-issue under the §3.7 rule | Same, but re-issue needs the controller's issuer: the binding is `degraded`, reported as `refresh_dependency` |
| Issuance races revocation | §3.5: whichever transaction commits first wins; a reserved or published certificate is counted in the residual even if never delivered | Same; a certificate published before the revocation reached the controller counts until its `valid_before` |
| Revoked while unreachable | Not applicable | `remote_pending` until the runner reconnects; it can authenticate until `latest_possible_credential_expiry` |

## 5. Custody specification (spec §7.3)

### 5.1 Per key class

| Step | K_env (B1) | K_ca | K_A (Recipe A) |
|---|---|---|---|
| **Generation** | By the signer at grant activation (and per child), from the OS CSPRNG through an established library | By the issuer at first use on that device, after the owner confirms; written to the D5 backup and verified before any enrollment uses it | By the signer at enrollment of its pair |
| **Storage at rest** | None (memory) by default. Hardware-backed where verified (§5.2) | Encrypted platform store item (§5.2); never a plain file | Persistent platform store or hardware (§5.2) |
| **Unlocking** | Not applicable | The store unlocks with the user session at login; the issuer reads the item once at start. A locked or missing store gives `CAPABILITY_UNAVAILABLE` and an owner interaction, never a fallback | Read by the signer at start in the user session |
| **Use while locked** | Signer memory or hardware handle; checks per signature (§3.6). Claimed only after the platform's lock probe passes (§9.3) | Issuer signs from memory, so new grants work while locked (D1, ADR-0004 §2) | As K_env, from the copy loaded at start |
| **Loss** (process ends) | Re-issue a new key and certificates under the §3.7 recovery rule; on a runner this needs the issuer | Store item lost or corrupt without compromise, issuance log intact: restore from D5 (§5.3). Log lost too: rotate (recommended; a key-only restore leaves the residual unknown, §5.3). Device lost: treat as compromise (§6.3) | Remove its line on that account, then re-enroll (one remote write) |
| **Rotation** | By construction: a new key per grant | On compromise, owner request or algorithm change; no calendar rotation (§6.4) | New key, new line, verify, retire the old line; on compromise and before `expiry-time` |
| **Backup** | None | **D5:** encrypted offline backup (§5.3) | None; re-enroll |
| **Destruction** | At grant end (§3.6) | Delete the store item, zeroize memory, remove its lines (§6.5); the owner destroys the backup | Delete the store item or hardware key; remove its line. A software copy taken earlier cannot be recalled [I] |
| **Recovery** | Re-issue | D5 restore after non-compromise loss with the issuance log intact; otherwise, and after compromise, a new CA and re-enrollment through existing access | New key and enrollment through existing access |

Certificates are public: they need no backup, expire by themselves and are re-issued.

### 5.2 Platform stores

**macOS** (tested floor macOS 27 arm64, ADR-0004 §4). D3 decided that Heimdall will ship a
provisioning-profile-signed bundle, but it needs the owner's Apple Developer membership, so until
then the binary is ad-hoc signed (ADR-0004 Q-F).

| Class | Ad-hoc-signed CLI (now) | Signed bundle (after D3) | Evidence and limits |
|---|---|---|---|
| K_env | Signer memory, Ed25519 | Same. Optional: an ephemeral Secure Enclave P-256 key per grant | An ad-hoc-signed CLI with no entitlement created an ephemeral SE key, signed with it, and export was refused [O:X4-mac]. That spike used `WhenUnlockedThisDeviceOnly`, so its behavior under lock is unknown (P1 extension). Signing by a dedicated agent was measured only unlocked [O:SMOKE] |
| K_ca | A generic-password item in the login keychain, which is the default keychain in a user context [S:TN3137], with its access-control list (SecAccess) limited to the Heimdall issuer executable [S:TN3137]. Read once at issuer start, then held in memory | A data-protection keychain item in a Heimdall access group, accessibility `AfterFirstUnlockThisDeviceOnly`: available after first unlock until restart [S:Apple-AfterFirstUnlock], not migrated to another device's restore [S:Apple-RestrictAccess] | Not validated for this design: no login-keychain run exists, and tests never touch the owner's login keychain (AGENTS.md). X4-mac measured a disposable file keychain outside the search list, not this item [O:X4-mac]. Unknown: availability at login after logout and reboot (P2, P3), and how the ACL of an ad-hoc-signed binary behaves across updates (it may prompt once per update [I]). Before this row is claimed it must be validated on a disposable macOS account (§9.3); until then availability and ACL behavior stay unverified. The file-based keychain is "on the road to deprecation" [S:TN3137]; a system backup may hold an encrypted copy of the login keychain beyond Heimdall's control [I]. The data-protection keychain needs the profile-signed bundle [S:TN3137] (P6 blocked) |
| K_A | Login keychain item, as K_ca | A persistent SE P-256 key through the data-protection keychain (non-exportable, P-256 only, no import [S:Apple-SEKeys]) | A CTK identity is persistent and non-exportable, but through `ssh-keychain.dylib` it loads only as `sk-ecdsa`, and `KEYCHAIN_CERTIFICATES` did not select identities [O:P5]. Whether Heimdall can sign with it as plain ECDSA is unknown. It is a candidate, not the default |

Rejected on macOS:
- **A custom file keychain** for K_ca. Its password must come from another store [I]; new
  keychains default to lock on sleep and a 300 s timeout [O:K1]; `SecKeychainCreate` is deprecated
  [S:TN3137]. P1 still measures one as a data point.
- **CTK identities for K_env.** They write the real user token store for every key, load only
  through the FIDO-style path, and are not selectable by `KEYCHAIN_CERTIFICATES` [O:P5]. Per-grant
  keys need no persistence.

**Windows** (Windows 11 26H2 x64 with the in-box OpenSSH, ADR-0004 §4). The native store spike
ran on 2026-10-31 under the ADR-0004 §3 authorization: **verified / pass** for the Rust rows
[O:WSS]. It ran non-elevated on one host and one user (Windows 11 Pro 26H2, build 26300.9711, an AMD
firmware TPM 2.0). It is mechanism evidence for the stores, not for Heimdall custody, and it makes
no lock-continuity claim:
- lock, sign-out, sleep and reboot were out of scope, so P-W1 and P-W2 stay blocked;
- with no second account, cross-user isolation is untested;
- the export refusals have no positive control;
- that console prompts were absent is inferred, not observed;
- the run was self-reviewed only [O:WSS].

The earlier X4 artifacts were cross-built only, plus a native named-pipe subset [O:X4-win].

| Option | Properties | Use in B1 |
|---|---|---|
| **DPAPI, CurrentUser** (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN`, Heimdall entropy) | Protect in one process and unprotect in another worked; wrong entropy and a tampered blob were rejected; medians 187 µs and 147 µs [O:WSS]. Decryptable by the same logon credential, usually only on the same computer; a roaming profile allows decryption elsewhere [S:MS-CryptProtectData]. The plaintext is in process memory after unprotect, and any process of the user can unprotect [I]. `LOCAL_MACHINE` scope lets any local user decrypt [S:MS-CryptProtectData], so it is never used | **K_ca at rest:** a blob in a Heimdall-owned file under the local, non-roaming application-data directory with an owner-only DACL. K_ca must be exportable once for D5 and is used from memory (ADR-0004 §2) |
| **CNG Microsoft Software KSP**, persisted P-256, export policy none | Create, reopen in a new process, sign (median 114 µs), verify by public key and delete worked; export policy 0 read back; private export refused (`0x80090029`) [O:WSS]. Export is forbidden by provider policy [S:MS-KSP-Props]; the key material stays in the user profile under the user's DPAPI protection, so same-user code with profile access is a residual risk [I] (untested, per the record's limitations) | **K_A** default where no TPM key is verified for that use |
| **CNG Platform Crypto Provider (TPM 2.0)** | Without elevation: provider opened, `Impl Type` HARDWARE; P-256 create 85 ms, reopen in a new process, sign (median 12.5 ms), verify, delete; private export refused (`NTE_BAD_TYPE`) [O:WSS]. That key material never leaves the TPM in clear comes from vendor documentation [S:MS-TPM], not from a test. A global anti-hammering lockout exists [S:MS-TPM]. Discrete TPMs and Pluton are untested [O:WSS] | **K_A** preferred where present, and an optional per-grant **K_env**. Both need P-W1 (lock) and P-W2 (sign-out, reboot) before any availability claim |

K_env is held in signer memory (Ed25519) by default; a per-grant TPM key is the hardening
candidate (create about 85 ms per grant [O:WSS]). Credential Manager is not used: network logon sessions
have no credential set [S:MS-CredWrite], and it adds nothing over DPAPI here [I].

**Linux desktop** (Ubuntu 24.04, Debian 13 x86-64).
- K_env: signer memory.
- K_ca and K_A: a Secret Service item in the login collection, read over a DH-encrypted session.
  The Rust `secret-service` crate opened such a session in X4 [O:X4-lin]. A locked item "cannot be
  accessed" [S:FDO-SS-Locking]; gnome-keyring's PAM module unlocks the login keyring at login
  [S:GNOME-Keyring-PAM]. The issuer reads the item at start.
- Kernel keyrings are not used in V1: keys live in kernel memory [S:keyrings.7] and are lost at
  reboot [I], and Docker's default seccomp profile rejects `add_key` [O:X4-lin].
- Behavior under lock is open (P-L1), as are logout and reboot (P-L2).

**Linux headless runner.**
- No issuer: K_ca never reaches a runner.
- K_env: signer memory only (D2). Secret Service failed with a session bus but no initialised
  keyring, and without a session bus [O:X4-lin]; a locked item cannot be accessed
  [S:FDO-SS-Locking].
- Candidate persistent stores, adopted only after P-L2 shows decryption from a lingering user
  service after reboot without a desktop session: `systemd-creds --user` (binds UID, user name and
  machine ID; since systemd 256) [S:systemd-creds.1], or a TPM2 key through tpm2-pkcs11
  [S:tpm2-pkcs11-SSH].
- Recipe A is not offered on runners (§3.11).

**No class has a plaintext fallback on any platform** (spec §7.3). An unavailable store makes the
dependent capability unavailable and reports it.

### 5.3 K_ca backup (D5)

- **Format:** OpenSSH private-key format encrypted with a passphrase, using bcrypt_pbkdf and
  aes256-ctr, ssh-keygen's mechanisms for that format [S:ssh-keygen.1 `-a`, `-Z`]. Stock
  ssh-keygen can restore it, and no custom cryptography is involved (spec §7.2).
- **Passphrase:** generated by Heimdall with at least 128 bits of entropy and shown once on the
  owner's terminal for transcription. It never appears in JSON, logs, arguments, the environment
  or the clipboard (spec §7.3). The KDF round count is recorded in the file; with a random
  passphrase the round count is not the security margin [I].
- **When:** at K_ca generation, before the CA is enrolled anywhere, so no destination trusts a CA
  without a backup; again at every CA rotation. Only an owner-present CLI/TUI action on a TTY can
  create it: never `--non-interactive`, an agent, a project endpoint or a paired client (spec §8.6).
- **Check:** Heimdall decrypts the written file in memory and compares the public key before it
  reports success. It records the backup's fingerprint and date (public metadata) in state and in
  the recovery bundle.
- **Where the owner keeps it:** the file on offline removable media or on paper, under the owner's
  physical control; the passphrase in a separate place, for example the personal password manager
  or paper, never with the file. Heimdall never uploads it and never proposes a cloud-synced
  folder.
- **Restore only after non-compromise loss** (store corruption, reinstall, disk replacement) onto a
  device under the owner's control, as a deliberate owner action. This restores the issuer
  identity, not the lost device's identity (spec §4.2, §7.7). After theft or suspected compromise
  the backup is not restored: the CA is rotated (§6.3) and the owner destroys the old backup.
- **Restore with the issuance log intact** (only the store item was lost): residuals are computed
  from the log as usual (§3.5).
- **Key-only restore** (the issuance log is lost too). The backup holds the key, not the log (spec
  §13.3 keeps runtime state separate).
  - Serials stay safe, because they are random (§3.4).
  - `latest_possible_credential_expiry` for every scope the old issuer served is reported as
    **unknown and unbounded**. The only exception is a verified, durable historical maximum
    covering every possibly outstanding certificate, recovered from a verified copy. V1 defines no
    such record.
  - The value is **never** derived from current policies, saved maximum durations or defaults.
    Policies change and outlive grants (spec §6.1), so a restored shorter policy says nothing about
    a longer certificate issued under an older one.
  - **Recommended recovery: rotate K_ca instead of relying on the restored key.**
    1. Generate a new CA and its backup.
    2. Enroll each account with the §3.3 add procedure.
    3. Remove the old CA's line through the §3.3 removal procedure.

    Once the old line is removed on an account, the old CA's certificates no longer authenticate
    there and that account's residual closes. Accounts that cannot be reached stay
    `remote_pending`, with an unbounded residual, until their line is removed.

  §9.3 requires a test: an old long-validity certificate, a shorter restored policy, and no issuance
  log.

## 6. Ending access

### 6.1 Events and their effects

| Event | Signer | Issuer | Server | Owned masters | Owned dedicated connections | Reported |
|---|---|---|---|---|---|---|
| **Expiry** at the admission deadline (§3.6) | Refuses; destroys the grant's keys | Refuses certificates for G | Refuses new authentication after `valid_before` [O:E2] | Closed | Kept (graceful default); closed under strict | "New connections stop at the deadline; existing sessions may stay connected." (spec §6.6) |
| **Cutoff** reached | Ends every affected grant like expiry: new Heimdall-mediated authentication stops at the cutoff; keys destroyed | Refuses new grants until the cutoff is cleared (R-AU-02) | Certificates issued after the cutoff was set end at it; earlier ones at their `valid_before`, which the residual counts | Closed | Follow the connection policy (graceful keeps them, strict closes them) | As expiry, with the cutoff time. An immediate stop is a revocation |
| **Pause** | Running grants continue (spec §5.6) | Refuses new activations only | — | — | — | Paused state |
| **Revocation**, stop, or lock-revokes (when chosen) | A tombstone is persisted before acknowledgment (R-AU-04); refuses at once; destroys the keys of G and its descendants | Refuses for G and descendants; stale approvals and renewals fail on generation (R-SE-07) | Accepts until `valid_before`; nothing removes it remotely (no KRL at capability 2) | Closed at once | **Closed at once**; the confirmation lists them first (Q4 b) | `local_applied`, `remote_pending`, `latest_possible_credential_expiry` (spec §6.7) |
| **Release** of the last reference | Destroys the keys | — | As expiry | Closed | As expiry | Released |

Expiry is graceful because the user did not act; revocation is "stop now" because a user who
revokes expects access to end (research §9.1 Q4 b).

### 6.2 Residual remote-access window (spec §6.5, Q4)

Stated per component, for a destination or runner that cannot be reached:

| Component | Maximum residual after revocation | Mechanism | Evidence |
|---|---|---|---|
| **Credential (new authentication)** | Until `latest_possible_credential_expiry`: the latest `valid_before` among unexpired certificates `reserved` or `published` for the revoked scope (§3.5), delivered or not. Never later than the grant deadline (default window 12 h, spec P04), plus destination clock error, which Heimdall does not measure (`destination_clock_error: unmeasured`, §3.6). After a key-only restore without a verified issuance history: unknown and unbounded until the old CA line is removed (§5.3) | Server-side `valid_before` | [O:E2] |
| … key not copied, environment reachable | None once the signer has destroyed the key [I] | Key destruction (§3.6) | Untested (§9.3) |
| **Heimdall-owned multiplexed masters** | Until the owning supervisor closes them: at once when it runs; on a disconnected runner, at its own admission deadline (§3.6) or when the revocation arrives | `-O exit`, then exact PID | [O:E7][O:E7P] |
| **Heimdall-owned dedicated connections** | Expiry: kept unless strict. Revocation: closed at once by the owning supervisor | Close | M03, A23 |
| **Unmanaged connections**, including ordinary `ssh` not started by Heimdall | **Unbounded**, disclosed | None (spec §6.6) | — |
| **Remote processes**, including those started over owned connections | **Unbounded**, disclosed | None | [O:E7] |

The live-connection bounds hold only while the owning supervisor runs. On a stolen, running device
nothing Heimdall controls bounds them [I]. Certificate validity is never quoted as the whole
window.

### 6.3 Lost device

- **A lost environment device that is not the issuer.** From a device the owner controls, tombstone
  the environment: the issuer refuses all its grants and re-issues. No remote write is needed.
  Residual as in §6.2. If the device held K_A keys, remove their lines through the inventory.
- **A lost issuing device:** **K_ca is treated as compromised**, because it is a software key in
  memory and in the store (D1). From another device, using existing access:
  1. remove every line of that CA (the enrollment inventory and recovery bundle list them);
  2. generate a new K_ca and its D5 backup;
  3. enroll the new CA's lines.

  The blast radius is every account trusting that CA. Until its line is removed, a holder of K_ca
  can mint certificates for that account's principal [I]. Unreachable accounts stay
  `remote_pending`.
- A replacement device gets a new identity (spec §7.7). K_env lives in memory and K_ca in
  non-migrating stores where available, so copying a state directory does not impersonate it.

### 6.4 Rotation

- **K_env:** a new key for every grant.
- **K_ca:**
  1. generate K_ca′ and its backup;
  2. per account, append a second line with the same principal beside the old one (the §3.3 add
     procedure);
  3. verify with the §3.3 production procedure using a K_ca′ certificate;
  4. switch issuance;
  5. once the old CA's latest reserved or published `valid_before` has passed, remove the old line
     (the §3.3 compare-then-rename procedure, with its disclosed window).

  Accounts that cannot be reached keep both lines and stay `remote_pending`. There is no calendar
  rotation by default, because each rotation is one remote write per account.
- **K_A:** the A09 flow (new key, new line appended, verification, then retirement of the old line
  by compare-then-rename).

### 6.5 Unenrollment, uninstall, recovery

- Lines are removed by marker with the §3.3 compare-then-rename procedure. It preserves unrelated
  bytes, and it detects administrator edits that land before its final check and starts again.
  An edit that lands inside the window between that check and the rename is lost; this is
  disclosed in the unenrollment confirmation. E4 and ENR measured removal without a racing writer
  (ENR's administrator append landed before removal began) [O:E4][O:ENR]. Offline accounts stay
  `remote_pending` in the retained inventory.
- Uninstall offers unenrollment first and lists the remaining remote lines (spec §7.7, R-DI-04).
- The recovery bundle holds public metadata only, with redaction options: CA public keys and
  fingerprints, markers, destinations and accounts, the D5 backup fingerprint, and instructions.
  It never holds private keys.
- K_ca is destroyed once all its lines are removed; the owner destroys its backup.

## 7. Capability reports

### 7.1 Fields

Field names are proposals for the G08 naming freeze; the meanings are fixed here. Spec §11.3's
example names (`destination_scope`, `new_authentication_expiry`, `workload_isolation`,
`existing_connections`) are kept.

| Spec §4.3 dimension | Field | Values |
|---|---|---|
| Identity selection | `enforcement.identity_selection` | `client_configuration_and_signer` (B1, A); `signer_filtering` (filtered upstream); `client_configuration` |
| Destination/account restriction | `enforcement.destination_scope` | `verified_server_principals` (B1); `verified_server_key_enrollment` (A, new value: the key is accepted only where its line is); `client_routing`; `unenforced_intent` |
| Credential availability | `availability`, `lock_continuity`, `usable_until`, `offline_until`, `refresh_dependency`, `conditions` | `available_through_deadline`, `refresh_dependent`, `current_only`, `interaction_required`; `lock_continuity`: `verified`, `not_verified`, `lock_revokes` |
| Expiry | `enforcement.new_signing_expiry`, `new_authentication_expiry`, `owned_multiplexing`, `existing_connections`, `remote_processes`, `unmanaged_connections` | `signer`; `credential_and_signer`, `credential_only` (a runner without a bounded time offset, §3.6), `signer_only`, `static_key_expiry`, `not_enforced`; `disabled`, `closed_at_deadline`, `unavailable`; `graceful_dedicated_connections`, `strict_disconnect`; `not_terminated`; `not_controlled` |
| Revocation | `revocation.local`, `revocation.remote`, `latest_possible_credential_expiry`, `destination_clock_error` | `immediate`; `bounded_by_credential_expiry`, `pending_until_line_removed`, `unbounded_unknown` (key-only restore, §5.3), `not_applicable`; a timestamp or `unknown`; `unmeasured` |
| Isolation | `enforcement.workload_isolation`, `enforcement.issuer_isolation` | `shared_os_user`; `same_user_process` |

- Every claimed value carries `evidence` entries (test ID, record, client/server versions; spec
  §4.3).
- A value whose test has not passed for the platform and versions in use is reported as `unknown`.
  A caller's minimum capability that is unknown or unmet gives `CAPABILITY_UNAVAILABLE`, never
  silently weaker access (spec §4.3, R-AU-08).
- A binding that mixes mechanisms carries per-pair entries, and its summary shows the weakest value
  of each field.

### 7.2 Shapes

Managed certificate, local environment, once its tests have passed:

```json
{
  "credential_mechanism": "managed_certificate",
  "expires_at": "2026-11-01T06:00:00Z",
  "usable_until": "2026-11-01T06:00:00Z",
  "offline_until": "2026-11-01T06:00:00Z",
  "availability": "available_through_deadline",
  "lock_continuity": "verified",
  "refresh_dependency": {"needed_only_after": "signer_restart", "source": "local_issuer"},
  "conditions": ["signer_running"],
  "enforcement": {
    "identity_selection": "client_configuration_and_signer",
    "destination_scope": "verified_server_principals",
    "new_signing_expiry": "signer",
    "new_authentication_expiry": "credential_and_signer",
    "owned_multiplexing": "disabled",
    "existing_connections": "graceful_dedicated_connections",
    "remote_processes": "not_terminated",
    "unmanaged_connections": "not_controlled",
    "workload_isolation": "shared_os_user",
    "issuer_isolation": "same_user_process"
  },
  "revocation": {"local": "immediate", "remote": "bounded_by_credential_expiry",
                 "latest_possible_credential_expiry": "2026-11-01T06:00:00Z",
                 "destination_clock_error": "unmeasured"},
  "evidence": [{"field": "destination_scope", "test": "A10", "record": "<record path>",
                "client": "<ssh -V>", "server": "<sshd version>"}]
}
```

On a remote runner the differences are:
- `refresh_dependency` names the controller's environment and issuer;
- `conditions` is `["runner_signer_running", "time_offset_bounded"]` (a restart loses the memory
  key; the time exchange of §3.6 must have bounded the offset);
- `usable_until` and `offline_until` are the runner's derived deadline, which may fall before the
  certificates' `valid_before` by the exchange uncertainty.

Without a bounded offset the runner reports `TIME_UNCERTAIN`, `owned_multiplexing: unavailable`
and `new_authentication_expiry: credential_only`, and a caller requiring deadline admission gets
`CAPABILITY_UNAVAILABLE`.

Fixed provider (1Password) while it is locked, requested unattended:

```json
{
  "state": "failed",
  "code": "CAPABILITY_UNAVAILABLE",
  "data": {
    "credential_mechanism": "external_agent",
    "availability": "interaction_required",
    "lock_continuity": "not_verified",
    "enforcement": {
      "identity_selection": "signer_filtering",
      "destination_scope": "client_routing",
      "new_authentication_expiry": "not_enforced",
      "existing_connections": "not_controlled",
      "workload_isolation": "shared_os_user"
    },
    "revocation": {"local": "immediate", "remote": "not_applicable"}
  }
}
```

### 7.3 Cases compared

| Field | B1 local | B1 runner | Recipe A | Fixed provider: 1Password | Fixed provider: native agent, file key |
|---|---|---|---|---|---|
| `credential_mechanism` | `managed_certificate` | `managed_certificate` | `managed_key` | `external_agent` | `external_agent` |
| `availability` | `available_through_deadline` | `available_through_deadline` (`refresh_dependent` after a restart) | `available_through_deadline` | `interaction_required` while locked [S:1P-Security]; `current_only` while unlocked | `current_only` |
| `lock_continuity` | Per platform, after P1 / P-W1 / P-L1 | After the runner lock/headless probes | Per platform and store | `not_verified`; the provider does not keep keys while locked [S:1P-Security] | `not_verified` |
| `destination_scope` | `verified_server_principals` | `verified_server_principals` | `verified_server_key_enrollment` | `client_routing` (filtered convenience, ADR-0004 §3) | `client_routing` |
| `new_authentication_expiry` | `credential_and_signer` | `credential_and_signer` | `signer_only`, or `static_key_expiry` with `expiry-time` | `not_enforced` | `not_enforced` |
| `revocation.remote` | `bounded_by_credential_expiry` | `bounded_by_credential_expiry` | `pending_until_line_removed` | `not_applicable`: the key stays valid wherever it is enrolled; Heimdall only stops routing to it | `not_applicable` |
| `workload_isolation` | `shared_os_user` | `shared_os_user` | `shared_os_user` | `shared_os_user` | `shared_os_user` |

Never reported by this recipe: `isolated_execution_boundary`, `authenticated_agent_restriction`
(unless session-bind restriction is implemented and tested), universal immediate revocation,
remote process termination.

### 7.4 What may be reported, on what evidence

| Value | Mechanism evidence now | Heimdall test that must pass first | Today |
|---|---|---|---|
| `destination_scope: verified_server_principals` | [O:E3][O:E4] (one client/server pair) | Production verification with positive and negative checks (§3.3), including on an account that cannot read the sshd log; A10 on two hosts per form | `unknown` |
| Enrollment `log_attestation` (optional) | [O:E6] (fixture with administrator log access) | Reported `unavailable` unless the account can read the sshd log | `unavailable` by default |
| `new_authentication_expiry: credential_and_signer` | [O:E2] server side | Signer refusal after D; A23 | `unknown` |
| `owned_multiplexing: closed_at_deadline` | [O:E7][O:E7P] | A23 with owned masters, including pre-accepted connections | `unknown` |
| `existing_connections` | — | A23 graceful and strict; revocation closes them | `unknown` |
| `revocation.remote: bounded_by_credential_expiry` with a correct time | [O:E2] | A07, including a disconnected runner | `unknown` |
| `lock_continuity: verified` | None; all lock probes blocked | P1 / P-W1 / P-L1 against the Heimdall signer, then A03 | `not_verified` |
| `issuer_isolation: same_user_process` (a limitation) | [O:E5] | A10 issuer-material inspection; A33 | Disclosure, always reported |

## 8. Rejected choices

| Option | Why rejected |
|---|---|
| Recipe A as the primary recipe | No server-side deadline without static `expiry-time`; residual unbounded until a remote removal; a remote write for every new environment, rotation or child (research §4) |
| Recipe C (step-ca) | An always-on service every refreshing environment depends on; unattended refresh puts provisioner credentials on workers (escalation Q1); principals default to the identity [S:Step-SSH-Login]; optional per spec §7.6 |
| `ssh -O stop` as the deadline mechanism | Control connections accepted before the stop still received sessions and forwards [O:E7P] (F-7) |
| Short renewed certificates (for example 1 h) in V1 | They narrow only the new-authentication residual (research §6); lock continuity would then depend on the issuer working under lock instead of the signer alone; runner offline coverage would shrink to one chunk (plan G04's fifteen-minute example) |
| A hardware or presence-gated K_ca | Conflicts with D1 (signing under lock without presence) and D5 (exportable backup); sk-type CA untested [O:P5] |
| K_ca on a runner or worker | Prohibited (spec §6.5, §7.3, R-CR-04) |
| A persistent per-environment software K_env | An at-rest copy readable by same-user code, for no gain locally (§3.7) |
| Options on the CA line (`restrict`, `expiry-time`) | Remote writes for every permission change or on a calendar (§3.3) |
| Adding a line by whole-file check-then-rename (as the E4 harness did) | Replaces the file from a possibly stale copy; an administrator edit in the window is lost (spec §7.5 "Do not rewrite a shared account file from a stale snapshot"). An append cannot lose it (§3.3) |
| The server log as the production verification oracle | Capability 2 does not include log access; the oracle stays a test oracle, and log attestation is optional (§3.3) |
| Counter serials with a persisted high-water mark | A key-only restore could reuse serials; random 64-bit serials need no counter (§3.4) |
| Wall-clock-only deadlines | A backward clock step would extend local signing; the continuous-clock budget prevents it (§3.6) |
| Rebuilding a budget from the wall clock at restart, or accepting a post-reboot clock because it is above the high-water mark alone | A rollback after downtime can stay above the mark and revive elapsed authority (§3.6 example) |
| A runner budget started at receipt from a controller-stated remaining duration | Adds the delivery time to the runner's authority (§3.6) |
| A residual bound taken from current policies or defaults after a key-only restore | An older, longer certificate may be outstanding; the residual is unknown (§5.3) |
| Default-extension certificates | ssh-keygen's defaults permit every forwarding [S:ssh-keygen.1] |
| A stock `ssh-agent` as the signer | It cannot check the grant per signature; it remains only the stand-in used by the experiments |
| A custom file keychain, CTK as K_env, kernel keyrings, Credential Manager | §5.2 |
| `age` or a platform-specific export for the D5 backup | Adds a format and dependency; the OpenSSH format restores with tools any owner already has |
| A plaintext fallback of any kind | Prohibited (spec §7.3, §14.4, plan G04) |

## 9. Evidence

### 9.1 Evidence keys

All E-records ran in run `20261003T192323Z`: client OpenSSH_10.3p1 on macOS 27.0 arm64, server
OpenSSH_10.0p2 (Debian 13) in disposable containers, offset 0.007–0.015 s. Their limitations
apply: one client/server pair, no Heimdall code, not lock or store evidence.

| Key | Record or artifact | Status / verdict |
|---|---|---|
| E1 | `tests/evidence/g04-exp-e1-dedicated-agent.json` | verified / pass |
| E2 | `tests/evidence/g04-exp-e2-cert-expiry.json` | verified / pass (153 logins at the boundary; none accepted starting after `valid_before`) |
| E3 | `tests/evidence/g04-exp-e3-principal-scope.json` | verified / pass |
| E4 | `tests/evidence/g04-exp-e4-account-ca-principals.json` | verified / pass (one check-then-rename add and one removal by marker, no racing writer) |
| ENR | `tests/evidence/g04-exp-enroll-marker-key.json` | verified / pass (an administrator append made between enrollment and removal was preserved; the rename itself was not raced) |
| E5 | `tests/evidence/g04-exp-e5-issuer-separation.json` | verified / pass; findings: same-user minting through the issuer socket, same-user-readable CA file |
| E6 | `tests/evidence/g04-exp-e6-fresh-login-verification.json` | verified / pass |
| E7 | `tests/evidence/g04-exp-g09-prelim-mux-after-expiry.json` | verified / pass (criterion scoped to new control connections) |
| E7P | `tests/evidence/g04-exp-g09-prelim-mux-preconnected-after-stop.json` | verified / **fail** |
| E7R | `tests/evidence/g04-exp-g09-prelim-mux-stop-race.json` | verified / pass |
| P5 | `tests/evidence/g04-macos-secure-enclave-ctk-probe.json` | blocked (lock row); unlocked row verified / fail (the `KEYCHAIN_CERTIFICATES` limit fails; create, export refusal, delete, signing and fixture login pass) |
| SMOKE | `tests/evidence/g04-macos-lock-probe-smoke-*.json` | 5 verified / pass, 2 in_progress / inconclusive; harness evidence, unlocked only |
| K1 | `tests/evidence/artifacts/g04/research/k1-keychain-mechanics/` | research observation O:K1 |
| P1, P2, P3, P4, P6 | `tests/evidence/g04-macos-{screen-lock,logout,reboot-headless,sleep,data-protection-keychain}-probe.json` | blocked |
| P-W1, P-W2 | `tests/evidence/g04-windows-{desktop-lock,signout-reboot}-probe.json` | blocked |
| P-L1, P-L2 | `tests/evidence/g04-linux-{desktop-lock,logout-reboot-headless}-probe.json` | blocked |
| X4-mac | `tests/evidence/artifacts/g02-r4/x4/macos/RESULTS.md` | verified as scoped (file keychain, ephemeral SE key, bundle signing); the provisioned bundle is blocked |
| X4-lin | `tests/evidence/artifacts/g02-r4/x4/linux/RESULTS.md` | verified, linux-arm64 container only |
| X4-win | `tests/evidence/artifacts/g02-r4/x4/windows/RESULTS.md`, `…/g02-r4/x1/x4-windows-run/RESULTS.md` | the spike as cross-built; native pipe subset 10 pass. Its DPAPI, CNG and TPM checks were run later as WSS |
| WSS | `tests/evidence/g04-windows-secure-store-spike.json` (artifacts `tests/evidence/artifacts/g02-r4/x4/windows-stores-run/`) | verified / pass for the Rust rows (2026-10-31): DPAPI CurrentUser across processes, Software KSP and TPM P-256 create/reopen/sign/verify/delete, private export refused, key inventory unchanged. Go TPM delete row verified / fail (a spike flag defect). Limitations: one host and user, AMD firmware TPM only, no lock/sign-out/sleep/reboot, no cross-user test, no positive control for export refusal, self-reviewed only |

### 9.2 Falsifiers (research §7)

| ID | Status | Basis |
|---|---|---|
| **F-1** signer cannot sign under lock, no store or hardware restores it | **Open** | P1, P-W1, P-L1 blocked. A reopen condition, not a reason to defer |
| **F-2** sshd accepts outside the validity window | **Not triggered** | [O:E2] |
| **F-3** principal scope fails at capability 2 | **Not triggered** | [O:E3][O:E4] |
| **F-4** K_ca reachable from the worker path, or a wider or later certificate mintable through it | **Not triggered on its criterion** | [O:E5]; the same-user boundary is confirmed and disclosed (§3.1) |
| **F-5** a material share of destinations lacks certificate support | **Open** | The G01 destination inventory has not been taken (the ADR-0001 §6 baseline worksheet is `not_started`). Recipe A ships as a fallback either way |
| **F-6** new grants must be created while locked, **and** K_ca cannot be used under lock without weakening its protection | **First clause triggered** (D1: yes). The second is met in part | K_ca signs from memory under lock (ADR-0004 §2). That is weaker than a presence-gated or hardware CA key, but it adds little against the boundary already disclosed: a same-user process can use the issuer endpoint whether or not the screen is locked [O:E5]. The added exposure is a K_ca in memory on a locked device (physical memory attacks [I]). ADR-0004 kept B1 knowingly instead of moving unattended new work to Recipe A, whose standing key lines have an unbounded residual; the orchestrator confirmed this in revision 2 (ruling c). A separate-account issuer is the reopen path (§13) |
| **F-7** `-O stop` does not stop admissions | **Triggered** | [O:E7P]. Applied: owned masters are closed (§3.8); the recipe choice is unchanged |

### 9.3 What M03 and M04 must still measure

| Item | Platform | Closes | State and authority |
|---|---|---|---|
| **P1** screen lock: signer signing and fresh logins during lock; extended to the Heimdall signer and to an ephemeral SE key | macOS | F-1 (macOS), A03 | Runnable: ADR-0004 §2 lets the orchestrator lock after at least 15 min of console idle; the owner unlocks on return |
| **P5 lock row** (CTK) | macOS | K_A candidate | Runnable: D4 covers further runs (ADR-0004 §2); same lock rule |
| **X4 Windows store run** | Windows 11 | §5.2 Windows rows (mechanism only) | **Done**: verified / pass for the Rust rows [O:WSS]. Still open from its limitations: a second account (cross-user isolation), discrete TPM or Pluton, a positive export control, independent review |
| **P-W1** Win+L: DPAPI unprotect, CNG and TPM signing, Heimdall signer | Windows 11 | F-1 (Windows), A03 | Blocked: probe script not implemented; lock rule as P1. WSS makes no lock claim |
| **P-L1** session lock: Secret Service read for a disposable user, signer signing | Linux desktop | F-1 (Linux) | Blocked: no Linux desktop host |
| **P2, P3, P-W2, P-L2** logout, reboot, headless | all | Store availability at login; runner persistence (§5.2) | Blocked on the owner (ADR-0004 §2) |
| **P4** sleep across a deadline | macOS | Wake check (spec §6.4) | Blocked; G09 |
| **P6** data-protection keychain | macOS | Post-D3 rows | Blocked: Apple Developer membership |
| Login keychain item for an ad-hoc-signed issuer, across updates | macOS | Pre-D3 K_ca row | Needs a disposable macOS account (never the owner's keychain) |
| Restricted extension profile, including forwards through a live master with no `permit-port-forwarding` | fixture | §3.4, A23 | Not started |
| Key destruction makes outstanding certificates unusable; issuer refusal rules (property tests); D5 restore with stock ssh-keygen; DH Secret Service session on a real desktop | fixture / native | §3.5, §3.6, §5.3 | Not started |
| **Registry interleaving** (R1): an administrator edit injected before the final check and after it, for add, remove and rotation. Pass: add always preserves the edit. Remove and rotation refuse or restart when the edit precedes the final check; an edit forced inside the window is lost and is recorded as the disclosed limitation, not a pass. Also: no trailing newline, an absent file (exclusive create), a symlinked registry (refused), a lost response (`outcome_unknown`, then reconciled) | fixture | §3.3, §6.4, §6.5; A09 | Not started |
| **Production verification** (R5): the §3.3 procedure on an account that cannot read the sshd log; the positive certificate passes, the negative one is refused with no signature recorded; `log_attestation` reported `unavailable` | fixture (non-admin account) | §3.3, §7.4; A09, A10 | Not started |
| **Issue/revoke linearization** (R2, R12): deterministic interleavings against reserve, sign, publish, delivery, installation and acknowledgment:<br>• of revocation, cutoff change and delegation change;<br>• of **deadline and cutoff passage with no edit**;<br>• of **`TIME_UNCERTAIN` arising** between reserve and sign, sign and publish, and publish and delivery.<br>Also: runner delivery lost, acknowledgment lost; re-issue racing revocation; crash at each step.<br>Pass: no certificate is published once any predicate fails; a receiver with a stale generation, a tombstone or an unsafe deadline discards it; every `reserved`/`published` entry counts in `latest_possible_credential_expiry`; a `reserved` entry is never published after a crash | model + fixture | §3.5, §6.2; A07 | Not started |
| **Time, A08 cases** (R3, R9):<br>• rollback with a live key and the issuer unavailable (signing stops at the budget end);<br>• rollback below the high-water mark at restart (`TIME_UNCERTAIN`);<br>• **downtime spanning D, then a rollback that stays above the high-water mark** (e.g. stopped at 10:00 with D = 11:00, real 12:00, clock reset to 10:01): same boot, the anchor detects it; after a reboot without synchronized time, `TIME_UNCERTAIN` and no re-issue;<br>• a same-boot restart resumes the anchor and never rebuilds a budget from the wall clock;<br>• owner confirmation resolves `TIME_UNCERTAIN` without moving any deadline;<br>• forward jump; sleep crossing D (no signature after wake, P4); wake validation before signing.<br>Pass: no signature, admission or re-issue after the true deadline in any case | virtual clock + native | §3.6, §3.7; A08 | Not started (G09) |
| **Synchronized-time signals** (R9): what `timedatectl` `NTPSynchronized`, the macOS time daemon state and `w32tm /query /status` report when sync is healthy, absent and failed, and after a reboot with a wrong real-time clock | Linux, macOS, Windows | §3.6 post-reboot rule | Not started (M03/M04); reboot runs blocked on the owner |
| **Runner deadline** (R10):<br>• authenticated time exchange with a delayed delivery and with a replayed certificate message or time answer (replay rejected; deadline unchanged);<br>• runner clock behind the controller within the tolerance (deadline still at or before the true D);<br>• RTT above the bound (`TIME_UNCERTAIN`, `owned_multiplexing: unavailable`);<br>• an owned master on the runner stops admitting at or before the true D;<br>• re-issue does not restart the deadline | fixture (two clocks) | §3.6 runner rules; A24 | Not started (G07) |
| **Recovery per lifecycle event** (R4): process restart, logout and login, reboot and login, runner restart, runner reboot, each separately, each with its §3.7 time basis; each also with lock-revokes chosen (no re-issue). Pass: re-issue only under the §3.7 rule, never from a process file, and never for an expired, revoked or cut-off grant | native per platform | §3.7; A08, A17 | Not started; logout and reboot runs blocked on the owner (ADR-0004 §2) |
| **Key-only restore** (R6, R11): an old certificate with long validity issued under an earlier policy, the database lost, K_ca restored with a shorter policy and no issuance log. Pass: `latest_possible_credential_expiry` is `unknown` and `revocation.remote` is `unbounded_unknown`, never the restored policy's maximum; rotation closes each account's residual when its old line is removed; unreachable accounts stay `remote_pending`; no serial reuse | fixture | §3.4, §5.3, §6.2; A07 | Not started |
| **A03, A07, A09, A10, A23, A24, A28, A33** with Heimdall code | declared matrix | R-CR-02 and the rest of §11 | Not started (M03, M04, M06) |

## 10. Tradeoffs

- **Offline coverage against revocation speed.** Whole-grant certificates give a runner offline
  coverage equal to its grant. The cost is a new-authentication residual up to D after revocation
  while it is unreachable (spec §6.5).
- **Issuing under lock (D1)** makes unattended new work possible. K_ca is then exposed to same-user
  compromise while the issuer runs, and its blast radius is every enrolled account.
- **Memory-only working keys** remove at-rest copies. They cost a re-issue after any restart, and a
  runner restart needs its controller's issuer.
- **One certificate per pair** means more objects in exchange for exact scope and per-pair
  extensions.
- **No multiplexing by default** means more fresh authentications (latency) in exchange for exact
  deadline behavior.
- **No KRL at capability 2:** no immediate remote revocation, disclosed instead.
- **Registry writes:** an append cannot lose an administrator's edit. Removal and rotation keep a
  small, disclosed window in which one can be lost, because `authorized_keys` has no portable
  conditional write.
- **Conservative time:** the earlier-of rule and `TIME_UNCERTAIN` can end or pause access early
  after a clock problem. After a reboot without synchronized time, managed access waits for sync
  or an owner confirmation. A runner may stop early by the exchange uncertainty. These are the safe
  direction; nothing extends access.
- **Key-only restore** leaves the residual unknown until the old CA lines are removed. Rotation,
  not restore, is the recommended recovery.
- **The pre-D3 macOS store** is a file-based keychain on a deprecation path with unmeasured ACL
  behavior across updates. The alternative was to wait for D3.

## 11. Affected requirements and acceptance cases

| Requirement | Fixed here | Acceptance |
|---|---|---|
| R-CR-02 complete recipe, verified lock continuity | §3, §5; lock continuity still open (F-1) | A03, A09 |
| R-CR-03 protected secrets, no plaintext, no leakage | §5, §5.3 | A33 |
| R-CR-04 issuer authority out of project endpoints and worker exports | §3.1, §3.5, §4 | A10, A28, A33 |
| R-CR-05 enrollment preserves access, fresh verification, reconciliation | §3.3 (append; production verification; `outcome_unknown`) | A09 |
| R-CR-06 rotation and unenrollment touch only owned records | §3.3, §6.4, §6.5 (compare-then-rename with its disclosed window) | A09, A31 |
| R-CR-07 verified destination/account principal scope | §3.3, §3.4, §7.4 | A10 |
| R-CR-08 provider lock, touch, purpose restrictions | §3.6 purpose check; §7.3 fixed provider | A11, A35 |
| R-CR-01 reference providers without key export | §7.3 fixed-provider reports | A11, A35 |
| R-AU-04 local revocation first, tombstones, pending remote | §3.5 (linearization), §6.1, §6.2 | A07 |
| R-AU-05 expiry controls new authentication and owned multiplexing | §3.4, §3.8, §6.1 | A23 |
| R-AU-06 sleep, restart, rollback and skew without extending authority | §3.6 time rule, §3.7 recovery | A08 |
| R-AU-07 delegation no broader or longer | §3.10 | A28 |
| R-AU-08 report actual enforcement and coverage | §7 | A10, A11, A24 |
| R-EN-04 lock, logout, sleep, reboot distinguished | §5.2, §9.3 | A03, A08, A31 |
| R-EN-05 runner independent of controller | §4.2, §4.3, §3.6 runner deadline | A24 |
| R-SE-03 named mechanisms; same-user labelled | §3.1, §7 | A28, A29 |
| R-SE-06 signing/control purpose separation | §3.1, §3.6 | A25, A29 |
| R-SE-07 policy generation checked before issuance | §3.5 (at reservation and again at publication) | A07 |
| R-SE-08 no private keys in diagnostics | §3.6 (core dumps), §5.3 | A33 |
| R-SE-04 host trust during enrollment | §3.3 (spec §7.5 transaction) | A09 |
| R-SE-01, R-SE-02, R-SE-05 | Unchanged; issuance trusts no request claim (§3.5) | A29 |
| R-UX-03, R-RT-07, R-RT-03 | Lock disclosure; recovery rule per lifecycle event (§3.7); separate endpoints | A03, A08, A17 |

## 12. Migration consequences

- **No code or data migrates**: nothing is implemented. M01 must provide a third local interface
  for issuance, distinct from control and signing (spec §13.2). The domain model needs:
  - a credential instance made of a key handle plus per-pair certificates;
  - an issuance log with `reserved`/`published`/`voided` states, sharing a transactional store
    with grants and tombstones;
  - a persisted wall-clock high-water mark, per-grant boot-scoped anchors (boot ID,
    continuous-clock reading, wall time) and, on runners, the derived deadline from the time
    exchange;
  - an enrollment inventory keyed by CA fingerprint.
- **M01-T02** (virtual-clock tests) must cover the §3.6 time rule.
- **M03 mapping:** T01 signer and custody (§3.6, §5); T02 enrollment with append, compare-then-rename
  and the production verification (§3.3); T03 issuance and the reserve/publish protocol (§3.5); T04
  revocation by destruction and the residual (§6.1, §6.2); T05 connection policy (§3.8); T06 lock
  demonstration and the lifecycle recovery tests (§3.7, §9.3).
- **ADR-0004 §2** records the orchestrator's supersession of D2's cost note (§3.7).
- **G07** must carry the authenticated time exchange (nonce, controller wall time) on the pairing
  channel (§3.6).
- **Destinations:** one remote write per account at enrollment; afterwards only for CA rotation,
  unenrollment or a further issuing device.
- **When D3 ships:** move K_ca from the login keychain item to the data-protection keychain. This is
  a local re-store: verify, then delete the old item, with no remote write. K_A items move the same
  way or rotate.
- **When a hardware K_env is verified on a platform:** new grants use it; nothing migrates, because
  keys are per grant.
- **A later capability-3 KRL** can revoke by serial; random serials work for that as well as
  counters do [I] (§3.4).
- **Fixture:** M03 adds a second account-enrollable host so that A10 covers the account-level form
  on two hosts. ca1/ca2 cover the system form.
- **Spec:** no normative change. The new report value and fields (§7.1) go to G08 for naming.
- **Stale records to update** (orchestrator): the P5 record's `blocked_on`, research §5.1/§8.2 and
  `progress.md` still list the D4 coverage question that ADR-0004 §2 answered. The P1 and P-W1
  `blocked_on` texts predate ADR-0004 §2's lock rule.

## 13. Reopen conditions

- **F-1** on any supported platform (no custody signs under lock). Change custody (hardware or a
  separate service), not wording.
- **F-2 or F-3** on a supported server version, or a destination class where the account registry
  is not read (`AuthorizedKeysCommand`, `AuthorizedKeysFile` elsewhere). Use the system form or A.
- **F-4** in Heimdall's own A10/A33 tests (issuer material reachable from a worker path).
- **F-5:** the G01 inventory shows a material share of destinations without certificate support.
  Recipe A then becomes a first-class recipe with its own lock evidence.
- **F-6, strengthened:** evidence that the in-memory K_ca is materially more exposed than the
  signer, or the owner asks for a presence-gated K_ca or a separate-account issuer.
- **Hardware:** the P5 lock row passes, P6 passes, or P-W1 and P-W2 pass for the TPM (the store
  mechanics already passed [O:WSS]). Hardware keys then become the default for K_env or K_A on
  that platform.
- **Registry:** a destination offers a registry API with conditional writes, or a serialization
  that every writer honors. Removal then uses it and the disclosed window closes.
- **P-L2** verifies a headless store: runners persist K_env and Recipe A may be offered on runners.
- **Time signals:** a platform's synchronized-time signal proves unreliable (it reports synchronized
  while wrong) under the accidental faults in scope. The post-reboot rule then needs another
  trustworthy time bound, such as the authenticated controller exchange, on that platform.
- A tested mechanism that stops admissions on a live master gracefully (spec §6.6), or a change in
  OpenSSH's `-O stop` behavior.
- The owner reopens any ADR-0004 §2 item, or rejects a decision listed in §14.

## 14. Decisions added by this ADR

The sources fixed the recipe, D1–D5 and Q4. Revision 1 left four points open. The orchestrator
ruled on them for revision 2:

- (a) a policy cutoff ends affected grants like expiry; an immediate stop is a revocation (§6.1);
- (b) a pause blocks new activations only (§3.5, §3.6, §6.1);
- (c) B1 stays, with K_ca in issuer memory under lock, disclosed; a separate-account issuer is the
  reopen path (§9.2, §13);
- (d) Recipe A's 90-day `expiry-time` is accepted as a proposal (§3.11).

It also superseded D2's cost note (§3.7; recorded in ADR-0004 §2). For revision 3 it ruled on the
round-2 findings:
- R9: same-boot restarts resume a persisted boot-scoped anchor; after a reboot, the wall clock must
  be at or above the high-water mark and synchronized, or the owner confirms;
- R10: the runner derives its deadline from D through an authenticated time exchange;
- R11: a key-only restore leaves the residual unknown, and rotation is the recommended recovery;
- R12: publication re-applies every predicate, and the receiver checks before installing.

This ADR adds the following, each open to review:

1. One K_env per grant and per child inside an environment, memory-only by default, destroyed at
   grant end. Re-issue without new approval only under the §3.7 recovery rule, per lifecycle
   event.
2. One certificate per pair; the extension profile; key ID; random 64-bit serials; the 60 s
   `valid_after` backdate (§3.4).
3. No options but `principals=` on the CA line; append to add, compare-then-rename to remove, with
   the disclosed window; production verification by a constrained client plus the negative check,
   with log attestation optional; the principal character set (§3.3).
4. K_ca: Ed25519, one per issuing device, no calendar rotation (§3.2, §6.4).
5. Platform stores: macOS login keychain before D3, then the data-protection keychain with
   `AfterFirstUnlockThisDeviceOnly`; DPAPI CurrentUser for K_ca on Windows; CNG/TPM for K_A; Secret
   Service over DH on Linux; memory only on runners (§5.2).
6. D5 format, generated passphrase, owner-present creation before first enrollment, and no restore
   after theft (§5.3).
7. Whole-grant certificates and no chunking in V1. Issuance reserves, signs, publishes (every
   predicate re-applied), then installs after the receiver's own check; reserved and published
   entries count in the residual (§3.5).
8. The time rule (§3.6):
   - the earlier of absolute and continuous-clock limits;
   - per-grant boot-scoped anchors;
   - a persisted high-water mark plus a synchronized-time requirement after a reboot;
   - `TIME_UNCERTAIN` stopping re-issue, signing and admission, resolvable by owner confirmation;
   - the runner time exchange with an upper-bound offset;
   - destination clock error reported as unmeasured.
9. Bounded contexts without multiplexing; owned masters as foreground children (§3.8).
10. Recipe A: a key per pair, `restrict` plus chosen permissions, not offered on runners, never a
    runtime fallback (§3.11).
11. Report fields `lock_continuity`, `conditions`, `issuer_isolation`; the value
    `verified_server_key_enrollment`; per-pair entries with a weakest-value summary (§7.1); the
    enrollment capability `log_attestation` (§3.3).
12. Ordinary `ssh` processes not started by Heimdall are unmanaged connections for closing (§3.8).
13. After a key-only restore the residual is reported `unknown`/`unbounded_unknown`, never derived
    from policies, and rotation is the recommended recovery (§5.3).
