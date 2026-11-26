# ADR-0012: Environments, pairing, runners, routes and the Iroh transport (M06)

**Status:** accepted, revision 3 · **Date:** 2026-11-20 · **Gates:** G06, G07 (both open; they close on the rows in m06-plan §3) · **Milestone:** M06 (T01–T06)
**Decided by:** proposal of the M06 design unit. The orchestrator's rulings on the §12 questions (2026-11-19) are recorded as decided. The §2.7 option was ruled not adopted in V1 (2026-11-20). The independent review (FIX FIRST) and the scoped re-check (FIX FIRST) were applied in revisions 2 and 3; the orchestrator checked revision 3 against the re-check and accepted it on 2026-11-20 (ADR-0009 §2.1: no third independent review). The ADR-0006 revision 6 in §9 is applied by the implementing waves.
**Revision 3 (2026-11-20):**
- **Applies:** the scoped re-check (Codex, FIX FIRST) at `tests/evidence/artifacts/review-m06-design/round2-recheck-codex.md`: residuals of M06-D-R01…R06, R07, R08, R10 and R13, and new findings M06-RC-R01…R05. It also applies the orchestrator's rulings on them (2026-11-20).
- **Markers:** rules changed by this revision carry **⟨r3⟩**. §16 maps each item to its section.
- **No RemoteDecide in V1:** revision 2's remote decision path is withdrawn (§3.10).

**Dated amendments after revision 3 (the orchestrator's rulings of 2026-11-21, marked ⟨2026-11-21⟩):**
- §5.5 item 5: the client's identification line on an Iroh leg (M06-W1-R04), and which of its failures end the whole connect;
- §2.1 and §2.5: a stable serve port;
- §2.3 item 1, §3.9 item 5 and §3.11: where a paired client's Iroh endpoint ID comes from (`remote_client_endpoints`), and its rotation;
- §3.2: which several-file `authorizedkeysfile` values verify;
- §3.4 (and §2.4): the encrypted-local-backup residual of K_mgmt and K_iroh;
- §3.5: one shared authorized_keys safety module;
- §3.9 item 5: the join's commit-time time check;
- §4.5: the refresh dependency's contract value.
The contract side is ADR-0006 §18.7 (revision 6.3).

**Revision 2 (2026-11-19):**
- **Applies:** the independent design review (Codex, verdict FIX FIRST), M06-D-R01…R13, at `tests/evidence/artifacts/review-m06-design/round1-codex.md`. It is archived there.
- **Also applies:** the orchestrator's rulings on §12, and the Windows W1 facts.
- **Markers:** rules changed by this revision carry **⟨r2⟩**. §15 maps each finding to its section.
**Basis:**
- `main` at `144fa477`;
- `origin/m04/w2` at `31aadbea`, for ADR-0010;
- `origin/m03/wave6` at `7b75c4c1`;
- `origin/m05/w4` at `50180ec2`.
**Gate reports:** `docs/research/g06-iroh-pigeons.md` and `docs/research/g07-runner-pairing.md`.
**Plan:** `docs/architecture/m06-plan.md`.
**Requirements:** R-EN-05, R-EN-08, R-SS-05, R-SS-07, R-SS-08 and R-SE-06 (primary), with R-AU-08, R-SE-04 and R-DI-07.
**Acceptance:** A24, A25, A26, and the runner rows of A07.

## 0. Rules this ADR keeps

- **Identities stay distinct** (spec §4.2):
  - the management key K_mgmt;
  - the Iroh endpoint key K_iroh;
  - SSH host keys;
  - SSH user keys and K_env;
  - the CA key K_ca;
  - the Unix account.
  Each binding between them is recorded by an authenticated step; none is implicit.
- **Three separate layers:**
  - **Reachability authentication:** Iroh endpoint identity and the serving allowlist.
  - **SSH authentication:** host key and user authentication.
  - **Management authorization:** the role table and decision records.
  None substitutes for another.
- **No custom cryptographic handshake.** No address, ticket or endpoint ID grants anything (spec §8.6).
- **ADR-0005's runner model stands:**
  - K_env is held only in the runner's memory;
  - only a controller's issuer signs, and K_ca stays on its issuing controller;
  - the time anchor comes from an authenticated exchange;
  - a runner cannot repair a restart without the issuer.
- **Spec authority semantics are unchanged.** ⟨r2⟩ The contract changes this needs are explicit in §9; nothing is "unchanged" by implication.

## 1. The integration boundary (G06)

1. **Embed iroh `=1.4.2` in the `heimdall` binary, behind the cargo feature `iroh`.**
   - **On by default:** in the Linux and macOS release builds.
   - **Windows:** per path (§2.6).
   - **Process roles:** the transport runs in separate processes of the same binary:
     - `heimdall transport connect`, the ProxyCommand leg;
     - `heimdall transport serve`, a supervised child of the runtime on a serving host.
2. **The wire protocol is Pigeons' `/pigeons/0`:** one bidirectional stream of raw SSH bytes.
   - **Interop scope** (the ruling on Q6): Heimdall's client to a stock Pigeons roost is supported, as explicitly adopted external infrastructure (§2.8).
   - **Unsupported:** a stock Pigeons client to Heimdall's serve. Rotating client identities cannot satisfy the allowlist (G06 I02a/I02b).
   - **No Pigeons dependency:** Heimdall does not ship or supervise `iroh-pigeons`.
3. **netdev's default-route probe is removed by a scoped patch** (the ruling on Q8).
   - **How:** a `[patch.crates-io]` of netdev 0.47.0, behind a feature.
   - **Where the code lives:** the patched source is vendored under `third_party/netdev-0.47.0/` with the patch file beside it, and its MIT notice goes into the license bundle.
   - **Upstream:** a request is filed, and per-platform bind evidence is kept.
4. **Dependency pins:**
   - rustls is pinned by `Cargo.lock` (0.23.46: no advisory in RustSec `472a4c9a`).
   - `cargo audit` runs in `check.sh` for builds with the `iroh` feature, and a vulnerability fails it.
5. **Bounded process lifecycles,** each with one regression test:
   - endpoint close bounded at 1 s;
   - the ProxyCommand leg never blocks exit on its stdin reader.
   - ⟨r2⟩ (R08) **Helper exit codes are internal** and are not public results. ssh reports a ProxyCommand failure with its own exit. Callers who need the cause read the structured `route.failed_over` and route-health results (§9 item 7), which use the existing code table.

## 2. Exposure, infrastructure and privacy (R-SS-08, R-DI-07)

### 2.1 ⟨r2⟩ One effective exposure policy per endpoint (R05)

**What the policy is:**
- **Who gets one:** every endpoint, dialer and server alike, runs under a single **effective exposure policy** derived from the approved route record and the user's recorded consents.
- **What is built from it alone:**
  - the bind;
  - the relay map;
  - every **peer relay hint**;
  - every direct address;
  - the address lookup;
  - ancillary DNS and net-report targets.
- **Fail closed:** a hint, address or relay outside the policy is refused (`relay_unapproved`, `route_unapproved`), and so is a policy the endpoint cannot apply (`transport_unavailable`).
- **No learned exceptions:** an address learned by lookup or hole punching is usable only if the policy holds a direct-fallback consent.

**The default policy:**
- `presets::Minimal`;
- no relays and no lookup or publishing;
- portmapper not compiled;
- a loopback bind (or none, relay-only);
- direct paths only to the route record's own addresses.

Passive inspection binds nothing (spec §9.2).

**⟨r3⟩ Each of these needs its own recorded consent, and granting one is a widening action (§3.10, RC-R03):**
- a non-loopback listener;
- a wildcard bind;
- direct fallback to learned or public addresses (which reveals public IPs);
- each relay set;
- public infrastructure.

⟨r3⟩ **The decision is bound to the exact delta.** It names each added relay URL and the bind scope before and after, along with the direct-fallback, public-infrastructure and external-roost changes. It is confirmed by an attended session local to the runtime whose endpoint widens (§3.10). A **pure preference change**, such as reordering routes whose exposure is already consented, needs that existing recorded consent and no new decision. Anything not covered by a recorded consent is refused (`exposure_unconsented`).

⟨2026-11-21⟩ **The serve port** (ruling 5, U56-Q5):
- **Named:** the policy may name a `port` (`heimdall transport enable --port <n>`).
- **Not named:** the first successful bind's port is recorded durably and reused at every later start, so the routes' direct addresses stay valid across restarts.
- **Unbindable:** a port that cannot be bound fails closed (`transport_unavailable`), with a doctor finding naming the port. No other port is tried.
- **Changing it** is `disable` then `enable` (§2.5).

### 2.2 Infrastructure profiles (the ruling on Q4)

- **`none`:** direct only.
- **`custom`:** the user's relay URLs. ⟨r3⟩ An IP-literal URL is *expected* to avoid the resolver's sockets. That control was **not run**: G06 S11 used a host name and observed the DNS sockets (G06 §3).
- **`n0-public`:** n0's relays plus lookup. **Off by default**, and **outside V1** unless one bounded capture row runs first (⟨r3⟩ the ruling on Q6).
  - **Where it runs:** in m06-plan U56.
  - **The capture's limits:** in a container, at most 5 minutes, ephemeral keys, an allowlist, and an echo target. **No sshd, and nothing that serves the host.**
  - **What it records:** the profile's exact traffic, which becomes the disclosure text.
  - G06's I01 capture used iroh's stock preset with the portmapper, so it does not qualify the profile.
- **Fallback:** a route never falls back to a profile it does not name (G06 S12). Repair cannot add a profile.

### 2.3 ⟨r2⟩ ⟨r3⟩ The serving side, and admission authority (R05, RC-R02; Windows W1 note)

1. **The allowlist** is required and nonempty, and checked before any byte is forwarded. It holds only the endpoint IDs of clients enrolled for that environment.
   - ⟨2026-11-21⟩ **Where the IDs come from** (ruling 4, U56-Q2): the table `remote_client_endpoints`, one row per client (client ID, endpoint ID, recorded time).
     - **Recorded at join:** the client sends its own endpoint ID in `join` over its K_mgmt session. The runner records it in the join's commit transaction only when the invitation admits Iroh (`iroh_admission`, part of the invitation's runner-local decision, §3.9 item 2); otherwise the join is refused. The owner never types an endpoint ID.
     - **Rotation:** the client's rotation form sets or atomically replaces its own row, and a replacement bumps `remote_authority_generation` in the same transaction.
     - **Revocation** deletes the row in the tombstone's transaction (§3.11).
2. **The target** is `127.0.0.1:<sshd port>` only, checked before forwarding (⟨2026-11-22⟩ the host is fixed; `::1` is refused).
   - **The outbound connect** to it is bound explicitly to `127.0.0.1` before `connect()`, so no wildcard local state can exist (W1 run 1's unexplained `0.0.0.0` reading).
   - ⟨2026-11-22⟩ **The port is product configuration:** `transport enable --serve --sshd-port <n>` (1–65535; the default is 22). The host is fixed at `127.0.0.1` and is never configurable. ⟨corrected 2026-11-23, M06-W5-R03⟩ Changing the port of an enabled serving endpoint is `transport disable`, then `transport enable --serve --sshd-port <n>` (a new attended serve decision); `transport enable` with any configuration other than the enabled one is refused `CONFIG_CONFLICT` and changes nothing.
3. ⟨r3⟩ **The runner's durable tombstones and enrollment records are the only admission authority.** The serve child holds no authority of its own.
   - **The lease:** it admits and forwards only while it holds a lease for the runtime's **current authority generation**. The lease is granted over its supervision channel and renewed as that channel stays open.
   - **Lease loss** stops all admission and closes every stream at once. The lease is lost on channel EOF, on a generation change the child has not acknowledged, or on runtime exit. A surviving orphan child therefore cannot keep admitting; it exits.
4. ⟨r3⟩ **Revocation order:**
   1. commit the tombstone (generation g+1);
   2. tell the child to suspend admission for the affected endpoint IDs and close their streams;
   3. receive the child's acknowledgement. Without it within a bound, stop the child by its exact supervised PID and confirm it is gone;
   4. only then report Iroh revocation as **applied**.
   - Until then the report is `remote_pending`, with reason `iroh_admission_closing`.
5. ⟨r3⟩ **Recovery:** after any runtime restart, closure is **replayed before service resumes.**
   1. the allowlist is rebuilt from durable state, excluding every tombstone;
   2. a new child starts under the new generation;
   3. only then does admission resume.
   - **Fail closed:** if authority cannot be read (a corrupt or unavailable state), the child is not started (`transport_authority_lost`).
6. **Disclosure:** an allowlisted peer gets reachability to sshd only.

### 2.4 ⟨r2⟩ K_iroh custody (the ruling on Q2; R07)

1. **The class:** K_iroh is a reachability key, distinct from every SSH and management credential.
2. **Storage:**
   - **Where a verified platform store exists**, it lives there: macOS Keychain (a non-synchronizable, this-device-only item), Windows DPAPI CurrentUser (local, non-roaming application data, as K_ca), or Secret Service.
   - **Never in a plaintext or owner-only file** (spec §7.3).
3. **Where no verified store exists**, a persistent Iroh endpoint is **unavailable** in V1 for both serving and dialing.
   - It fails closed, with `CAPABILITY_UNAVAILABLE`, reason `transport_key_store_unavailable`, and a doctor finding.
   - Direct and bastion routes are unaffected (M03's K_ca precedent). That includes headless Linux today (G07 readout: no Secret Service; systemd 255).
4. **Lifecycle:**
   - **Generated** at enable.
   - **Rotation** is on demand and gives a new endpoint ID. The new ID reaches clients' allowlists and routes through the management channel.
   - **Destroyed** at disable.
   - **Loss:** treated as a rotation. ⟨r3⟩ (R07) **The recovery path is named.** If Iroh was the only route to the serving host, a rotation notice cannot travel over it. The owner then re-pairs the new endpoint ID through **independently host-verified access**:
     - a direct or bastion route with the pinned host key;
     - or the owner at the serving host.
     This uses §3.3's bootstrap path. Never an unauthenticated announcement.
   - **Locked store:** the endpoint is unavailable while locked, and reported.
5. ⟨2026-11-21⟩ **Backups:** the encrypted-local-backup residual of §3.4 applies to K_iroh in the same stores; its recovery is rotation (item 4).
6. **Disclosure:** K_iroh proves reachability only. Theft of it would let an attacker impersonate that endpoint to its allowlisted peers; SSH host and user authentication still hold (G06 S04/S09).

### 2.5 Uninstall

`heimdall transport disable`:
- stops serve;
- destroys K_iroh;
- removes every route that names it, along with their projections and allowlist entries.

A26 verifies removal. G06 made no uninstall claim.

⟨2026-11-21; M06-W3-R01 (`tests/evidence/artifacts/review-m06/w3.md`) and the ruling on it⟩ **`disable` forgets endpoints; it does not revoke clients.**
- **What it clears:** every `remote_client_endpoints` row, in the narrowing write, with the generation bump.
- **What it keeps:** each client's Iroh admission. A later `enable` is the runner-local approved widening that resumes serving to clients still enrolled and admitted; they record an endpoint again as a first set.
- **To remove one client's Iroh access permanently, revoke that client.**

### 2.6 ⟨r2⟩ Windows, decided per path (the ruling on Q5; R12)

**A path with no evidence gets no support label.** The firewall is never touched.

| Path | Qualifies on | State (2026-11-19) |
|---|---|---|
| Loopback bind behaviour | **W1:** a native bind trace | Two sampled runs (50 ms IP Helper tables) saw only loopback. Run 1 had one unexplained `0.0.0.0` TCP reading, and its IPv6 TCP was not covered. No ETW or Procmon trace without an install or admin rights. **Not qualified** |
| Relay-only | **W3:** an IP-literal TLS relay with certificate validation intact; no UDP socket | Not run |
| LAN direct | **W4:** observer coverage, otherwise a recorded transport-specific deferral | Not run; the owner must be at the console |
| Any support label | Each qualifying path **plus the in-box OpenSSH journey** | Not run |

⟨2026-11-22; the owner's scope decision, through the orchestrator⟩ **A Windows controller of runners is in this release.**
- **What it needs:** a K_mgmt session agent on a named pipe for the in-box OpenSSH, wired into the management-session opener on Windows and reading K_mgmt from the DPAPI store.
- **Its rules** (the named-pipe hygiene of M04 and M07):
  - the pipe name carries only a random token after the `heimdall-` prefix;
  - an owner-only DACL, and the client's SID is checked on connect;
  - no reparse following; bounded frames and reads;
  - the agent exists only for the session's lifetime;
  - it answers list and sign for K_mgmt only, never anything else, and never forwards;
  - nothing in output or logs.
- **Evidence:** a Windows controller driving a Linux runner through the product CLI, with the runner as a fixture in a WSL scratch distribution on the PC (management sshd on 127.0.0.1). The cross-machine runner rows are the Mac-to-devbox journey.
- **A stated limit of this release:** a Windows device can be an owner controller, not a limited client. The confirming probes do not run on Windows, so a limited-role join and a policy recheck from Windows refuse, and the refusal says why.
- **The first `environment add` against a new runner** (every platform): the bootstrap offers to start the runner's runtime in the same attended TTY session, with a typed yes, and says plainly if it is not running. There is no silent second pass.
- (An earlier ruling of the same day deferred this; the owner reversed it before any commit.)

### 2.7 ⟨r2⟩ Not adopted in V1: an encrypted headless K_iroh store

**Does plan.md require headless serving?** Not explicitly. Spec §9.2 requires "explicit remote installation" of a serving endpoint, and a desktop host with a verified store meets the letter of that. The useful serving host, though, is usually headless. This option was offered for a ruling, and **is not adopted** (below).

**The option: user-scoped systemd credentials** (`systemd-creds --user`, systemd ≥ 256):
- **Encryption:** K_iroh is sealed with a key derived from the host's credential secret and/or TPM2, scoped to the user's UID. It is decrypted through the `io.systemd.Credentials` service, which authorizes by peer UID.
- **Availability:**
  - **Ubuntu 24.04:** observed **unavailable**: systemd 255, `systemd-creds --help` lists no `--user`.
  - **Debian 13:** *inferred* available (systemd 257). This needs a probe on such a host.
- **Properties:**
  - **The file:** an owner-only file holding ciphertext only.
  - **Host-bound:** a copied state directory is useless elsewhere. That gives backup exclusion by construction.
  - **The same-user boundary** is as for every other store.
  - **Rotation and loss** work as in §2.4.
- **Decision requested:** adopt the option for hosts where it is probed and verified, or keep headless serving unavailable in V1.

**Ruling (orchestrator, 2026-11-20): not adopted in V1.** No host with `systemd-creds --user` is available to verify it, and an unverified store cannot carry a custody claim (spec §7.3; AGENTS.md evidence discipline). Headless persistent Iroh endpoints are unavailable in V1, failing closed as in §2.4. The option is kept as a post-V1 candidate, to be reopened with a verified probe on a systemd ≥ 256 host and an independent review.

### 2.8 A stock roost is external infrastructure (the ruling on Q6)

**When a user adopts an existing `pigeons roost` as a route target, setup discloses its broader exposure:**
- it has no allowlist, so any holder of its ID reaches sshd;
- it publishes to n0;
- it uses its own relay set.

⟨r3⟩ **Adopting a roost is a widening action** (§2.1, §3.10). The decision is bound to the roost's endpoint ID and its disclosed exposure, and is recorded as that route's consent.

## 3. Pairing and roles (G07; M06-T01)

### 3.1 The channel

**OpenSSH, run under an isolated configuration** (§5.2), over any approved route.

### 3.2 ⟨r3⟩ Activation prerequisites: verified sshd policy for limited roles (R01; the ruling of 2026-11-20)

**Limited (non-owner) roles are available only on runners whose effective sshd policy for that account has been verified.**

**The verification is authoritative.** It is one of:
1. **`sshd -T`:** `sshd -T -h <a readable scratch host key> -C user=<account>,host=…,addr=…,laddr=…,lport=…`, run unprivileged as the account.
   - **Without `-h`:** an unprivileged run fails with "no hostkeys available" on Ubuntu 24.04 / OpenSSH 9.6p1.
   - **With it:** exit 0, and the account's full effective policy is printed [O: `tests/evidence/artifacts/g07/sshd-T-readout.txt`].
   - **The scratch key:** generated for the check and destroyed after it.
2. **A documented drop-in.** The operator installs a Heimdall-provided `sshd_config.d` drop-in with a `Match User <account>` block. It is checked the same way, by the same `sshd -T` invocation.

**The effective policy for that Match context must show all of these:**
- `authorizedkeyscommand none` and `authorizedprincipalscommand none`;
- `authorizedkeysfile` naming only files Heimdall checks. The key must appear in none of them except its own line;
  - ⟨2026-11-21⟩ (ruling 1) `sshd -T` prints the list without its quoting, so only a single file, or exactly sshd's default pair (`.ssh/authorized_keys .ssh/authorized_keys2`), verifies. Any other list leaves the runner owner-only (`management_sshd_unverified`);
- `forcecommand none`;
- `permituserenvironment no`;
- `acceptenv` ⊆ {`LANG`, `LC_*`}, with a POSIX login shell;
- `authenticationmethods` that allow publickey alone;
- an OpenSSH version that supports `restrict` and `expiry-time`.

**On every other runner, only `owner`-role clients may enroll.**
- **Why that fails closed without root:** they are owner-equivalent anyway (§3.12, the ruling on Q3). An unverified configuration cannot raise them above owner.
- **The refusal for a limited role:** `CAPABILITY_UNAVAILABLE`, reason `management_sshd_unverified`.

**Behaviour probes confirm the result; they never establish it.** Before activation reports success, the enrolled key's probe must:
- reach the bridge, which echoes the client ID from its argv and the pending record's nonce;
- be refused a PTY, a `-W` forward, and agent forwarding with a disposable agent (against the bootstrap positive control);
- not deliver a canary `SetEnv`.

A probe that disagrees with the verified policy fails closed (`management_sshd_unsupported`).

**Rendering:** the forced command is `exec "<abs heimdall>" remote serve --client <cid> --home "<abs>"`, built from a validated character set: absolute paths, no shell metacharacters.

**Limits:**
- `sshd -T` reflects the on-disk configuration the account can read.
- A daemon not reloaded since an edit, or one started with another `-f`, can differ. The confirming probes catch the differences that matter, and fail closed.
- ⟨2026-11-21⟩ The check at runner start uses a loopback `Match` context. A `Match Address` or `LocalPort` block can give a real connection a different policy. The backstop is the confirming probe on the real connection path: if it shows the session is not restricted as the policy claimed, the runner downgrades to owner-only and reports the policy as unverifiable.
  - **How the runner learns it:** the joining device reports what its four probes observed in `join`, and the runner checks that before the commit. A limited-role join without an observation is refused. The report is self-made by the joining device, so it catches misconfiguration, not a hostile joiner; the static `sshd -T` verification is the only check that holds against one.
  - **What the runner sees for itself:** at the start of every management session the bridge refuses a session in which sshd allocated a PTY or forwarded an agent. A management session never requests either. The runner then goes owner-only, permanently, with a doctor finding.
  - ⟨2026-11-21⟩ **How the downgrade is kept** (rulings on follow-ups D and E):
    - **Stored** as the authority-bearing `meta` row `runner_owner_only`, compared in recovery.
    - **The one exception to the single-writer rule:** the bridge, which holds no instance lock, sets this row itself. The write is set-only and idempotent, in one `BEGIN IMMEDIATE` transaction with a bounded busy timeout; this path can never clear the row or write anything else. If the write fails, the session is still refused, the failure is logged, and doctor reports it. The bridge then leaves a marker in an owner-only directory, which is a pending-write queue that fails closed: while it exists the runtime treats the runner as owner-only, and at start and at each limited-role admission the runtime records the row under the lock and then removes the marker. Neither the marker's absence nor its removal can lift anything.
    - **The runtime re-reads the row** at each limited-role admission or decision; it does not cache it from startup.
    - **A restore carries it forward:** if the current database has the row set, the row and its epoch are written into the restored database in the restore's transaction. A restored database that has the row when the current one lacks it is accepted. Both directions converge on owner-only if either side says so.
    - **A join refused on a disagreeing probe** commits its refusal and the row in one transaction; the join's own changes do not commit.
    - **Lifting** needs fresh evidence from the real path and an attended runner-local confirmation (ADR-0006 §18.7 item 19); `sshd -T` alone never lifts it.

### 3.3 Bootstrap

**The channel:** the owner's existing, independently host-verified SSH access to the runner account. It is adopted as existing access with its verified known_hosts entry, never via `ssh-keyscan`.

**What it does:**
1. explicitly installs or verifies the runner binary, checksum-checked;
2. runs `heimdall remote init`, which creates the environment ID and state;
3. enrolls the controller's K_mgmt as `owner`. ⟨r3⟩ That is a widening action, confirmed in the bootstrap's **interactive ssh session with a TTY**, which is runner-local and owner-equivalent (§3.10);
4. passes §3.2. ⟨r3⟩ If the sshd policy is not verified, only owner roles are enrolled.

The same path repairs a lost host pin or a lost K_mgmt.

### 3.4 ⟨r2⟩ K_mgmt custody (the ruling on Q1; R07)

- **Store:** one key per controller device, in the verified persistent platform store. It is non-synchronizable or device-local, as for K_iroh in §2.4.
- **Who can hold one in V1:** desktop controllers only.
- **Use:** management only (R-SE-06). It never authenticates onward access and is never signed by K_ca.
- **Locked store:** management connections are unavailable (`mgmt_key_store_locked`), and the runner's work continues.
- **Loss:** another `owner` client revokes the old client and invites a new key, or the owner re-bootstraps through independently host-verified access (§3.3).
- ⟨r3⟩ (R07) **Rotation:**
  - **When:** on compromise, owner request or algorithm change, with no calendar rotation (as K_ca, ADR-0005 §5.1).
  - **How:** a new K_mgmt is invited on each runner (a widening action, §3.10). Then the old client is revoked there.
- ⟨r3⟩ **No backup.** The key is never exported, and Heimdall makes no backup of it. Loss is recovered as below, never by restoring a copy.
- ⟨2026-11-21⟩ **Residual: encrypted local backups** (ruling 7; U2-Q8; the same class of limit as K_ca's row in ADR-0005 §5.2). The key is never synchronized, but it can be present in encrypted local backups:
  - on macOS, Time Machine backups of the login keychain, until the data-protection keychain item (D3) is available (P6 blocked);
  - account backups that include Secret Service collections or DPAPI blobs.
  - **Recovery on another device** is never a restore: run `heimdall device retire` and revoke the old client on each runner.
- **Device retirement is a separate operation** (`heimdall device retire`). It needs an attended local decision (§3.10).
  - **What it does:** revokes this device's client on every runner where it is enrolled, then destroys K_mgmt.
  - **Revoking one runner is narrower:** it removes that runner's record and line only, and never destroys K_mgmt, which may serve other runners.

### 3.5 The enrollment line

⟨2026-11-21⟩ (ruling 8 (c)) The authorized_keys safety steps (symlink and hard-link refusal, compare-then-rename, append-only add, the re-read check after every write) live in one module that both the enrollment writer (ADR-0005 §3.3) and the runner's management-line writer use.

- **Format:** `restrict,command="<§3.2 item 5>"[,expiry-time="…"] <K_mgmt.pub> heimdall-mgmt:<cid>`.
- **Writer:** the runner's own Heimdall, using ADR-0005 §3.3's add/remove procedure. It is a local edit that preserves the user's own lines.
- **Uniqueness:** a key already present under any other line is refused (`key_already_authorized`).

### 3.6 ⟨r2⟩ The bridge originates the only local hello (R01)

- **Identity and home:** `heimdall remote serve` reads the client ID and home from argv only. It never reads them from the environment or from `SSH_ORIGINAL_COMMAND`.
- **The local hello:** the bridge itself sends the only hello to the runner runtime, `ClientHello{…, remote_client: <cid>}`.
  - **The remote side's own hello is consumed by the bridge.** It is used only for version and capability negotiation, and is never forwarded.
  - **Any later frame that carries a hello, or asserts a caller identity, closes the session** (`USAGE_ERROR`).
- **Session binding:** the session is bound to that client ID for its whole lifetime.
- **Same-account processes:** they can also connect to the runtime, but only as the owner principal or as a declared, lower-authority remote client (§3.12). Declaring a client is a downgrade only.

### 3.7 ⟨r2⟩ Caller namespaces include the client (R01)

**The caller context** is `{principal, role, remote_client}`.

**Every namespace keyed by caller includes `remote_client`:**
- **Idempotency keys:** two requesters' identical `request_id`s are different keys.
- **Operation ownership and visibility:** a client sees its own operations, plus the environment-level views its role permits.
- **Event cursors and subscriptions.**

**Revocation:** it is rechecked on every request. Revoking a client closes its existing sessions and subscriptions (§9 item 2).

### 3.8 Roles and permissions

- **Permissions:** `view`, `request`, `approve`, `issuer_trust`, `enroll`, `service`, and ⟨r2⟩ `time_source` (§4.4).
- **Roles:**
  - `owner` holds all of them;
  - `requester` holds `view` and `request`;
  - `viewer` holds `view`.
- **Denial:** `CAPABILITY_UNAVAILABLE`, reason `role_insufficient`.
- **No execution:** limited roles never include execution on the runner.

### 3.9 ⟨r2⟩ ⟨r3⟩ Invitations: authenticated pins, one durable consumption, non-extending expiry (R03, RC-R01)

1. **Pins, both confirmed by explicit fingerprint comparison:**
   - **The receiving key:** the new device shows the fingerprint of its key, and the owner confirms it. The confirmation is bound into the invitation.
   - **The runner's identity:** the new device shows the runner's host-key fingerprint and environment ID from the public bundle, and the user confirms they match the owner's controller.
2. **Creating an invitation is a widening action** (§3.10), confirmed **runner-locally**. The pending record is {invitation ID, cid, role, receiving key fingerprint, created_wall, created_boot_id, created_elapsed, expires_wall ≤ created + 15 min, generation} and ⟨2026-11-21⟩ `iroh_admission` (whether the client may reach the runner over Iroh, §2.3 item 1).
   - **The line** carries `expiry-time = expires_wall`, as an sshd-enforced backstop.
3. ⟨r3⟩ **Pre-dispatch rule.**
   - **A session whose cid is `pending`** may send only the activation probe (§3.2) and `join`. Anything else is refused **before dispatch** with `CAPABILITY_UNAVAILABLE`, reason `invitation_pending`.
   - **On a retried `join`,** the identity is checked first: the cid from argv, the invitation ID and the key fingerprint on the cid's line. Only then is a recorded result returned. A mismatch returns nothing about the record.
4. ⟨r3⟩ **Expiry never extends** (RC-R01). An invitation is live only while **both** of these hold:
   - **The wall-clock deadline:** the runner's wall clock, checked under ADR-0006 §10 (not `TIME_UNCERTAIN`), is before `expires_wall`;
   - **The elapsed bound:** the continuous clock, measured from the **boot anchor** it was created under (the same `boot_id`), shows less than `expires_wall − created_wall` elapsed.
   - **When it is refused:** if time is uncertain, if the boot anchor is lost (a reboot, or the anchor unreadable), or if either bound has passed. The reason is `invitation_expired`.
   - **A rollback cannot help:** rolling the wall clock back cannot extend an invitation, because the elapsed bound still runs out.
5. **`join` is a compare-and-set:** `pending → active` only if the invitation ID, the cid, the line's key fingerprint, the role and the generation all match, and item 4 holds **at join time**.
   - **A session that authenticated before expiry but joins after it is refused.**
   - ⟨2026-11-21⟩ **At the commit** (ruling 2): the runner projects the **upper bound** of now from the time the gate checked, by the elapsed reading of a continuous, suspend-inclusive clock taken in the same process. An unavailable or backwards reading refuses (`invitation_expired`).
     - ⟨2026-11-21, M06-W2-R01 (blocking; `tests/evidence/artifacts/review-m06/w2.md`)⟩ **The projection is a floor.** The commit-time instant is the later of the projected upper bound and the wall clock read then, so a later wall reading can only bring expiry earlier. A backward wall step beyond the gate's step tolerance, measured against the projection, refuses with `TIME_UNCERTAIN`. The instant is sampled inside the committing transaction, after the line files are read.
   - ⟨2026-11-21⟩ **Iroh admission:** a join that carries an endpoint ID records it in the same transaction only when the invitation has `iroh_admission` (§2.3 item 1).
6. **Ordering and recovery:**
   - **The transition is persisted first.** Only then is the line rewritten, without the pending expiry. A reconciler makes the line match the database idempotently.
   - **A lost reply:** a retried `join` returns the recorded result after item 3's identity check.
   - **A crash between the commit and the rewrite:** the pending `expiry-time` stays until reconciled. That fails closed.
7. **After activation:**
   - **Ordinary connections** authenticate as active and consume nothing.
   - **Consumed, expired or revoked records stay refused,** even if a line rewrite fails.
8. **The focused fault test** (U1) covers all three:
   - a delayed `join` past expiry;
   - a **wall-clock rollback between SSH authentication and `join`**;
   - an interruption between the database write and the file write.

### 3.10 ⟨r3⟩ No remote widening in V1: widening is confirmed runner-locally (R02; the ruling of 2026-11-20)

**Revision 2's `RemoteDecide` path is withdrawn.** The re-check found that an unattended paired owner client could complete it on its own, over its authenticated channel.

1. **Paired remote sessions are never attended.** ADR-0006 §13.3 item 2 stands unchanged, and `Attend` and `Decide` on a remote session are refused before dispatch (`INTERACTION_REQUIRED`).
2. **A widening action on a runner executes only after an attended confirmation local to that runner.** That means an owner at the runner's own CLI or TUI, which includes an **interactive ssh session with a TTY** into the runner account. That session is owner-equivalent (§3.12).
   - **It uses ADR-0006 §3.1's decision record unchanged:** server-issued, bound to the action and its canonical parameters, with action-specific confirmation, and consumed once.
3. **What remote paired clients may do:**
   - **submit** a widening request. It creates a pending runner-local decision record (`APPROVAL_REQUIRED` with `next.decision_ref`), which grants nothing;
   - **deliver narrowing effects** (§7).
   - **They cannot decide.**
4. **The same rule applies on the controller** to its own widening actions: local attended decisions only. Examples are widening the controller's own dialer exposure (§2.1) and `device retire`.

**Widening actions on a runner:**
- a grant beyond standing policy, and creating or widening a standing policy;
- creating an invitation, and raising a role;
- `issuer_trust` changes, and designating a time source (§4.4);
- `resume` and `clear_cutoff`;
- ⟨r3⟩ **new or expanded exposure**, including adopting a roost (§2.1, §2.8; RC-R03).

**Narrowing actions, which need no decision:** revoke, pause, cutoff, client revocation, and remove.

**Threat-model rows:**

| Row | Threat | Result |
|---|---|---|
| T-RA1 | An unattended paired owner client submits a widening request | A pending record only; nothing executes |
| T-RA2 | A paired client sends `Decide` or `Attend` | Refused before dispatch (`INTERACTION_REQUIRED`) |
| T-RA3 | A widening request is replayed after it was decided runner-locally | The **recorded terminal result** is returned, with no new record and no re-execution (ADR-0006 §7.3) |
| T-RA4 | A limited client submits a widening request | `role_insufficient` |
| T-RA5 | A compromised owner controller | Can submit requests and narrow; **cannot widen** without runner-local attendance |
| T-RA6 | A shell on the runner account | Is owner (§3.12). Not defended, and disclosed |

**The runner-side denial test** (U1, A25) covers:
- T-RA1, T-RA2 and T-RA4;
- T-RA3's terminal result replay;
- the unattended exposure-widening negative case (RC-R03).

### 3.11 ⟨r3⟩ Client revocation and device retirement

**Revocation order:**
1. the runner commits the tombstone, which is the admission authority;
2. Iroh admission is closed by §2.3 item 4: suspend, close streams, acknowledge or kill, then report applied;
3. the line is removed (R8).
- ⟨2026-11-21⟩ The client's `remote_client_endpoints` row is deleted in step 1's transaction.

**Timing:** it needs no network, and applies to live sessions and subscriptions at once (§3.7).

**Retirement:** §3.4.

### 3.12 Shell access is owner access (the ruling on Q3)

- **The fact:** any principal with a shell on the runner account is owner of that runner.
- **Disclosure:** setup and the limitations statement disclose it, and recommend a **separate account** where operators must be isolated.
- **No in-account boundary** is attempted.

## 4. The runner model (M06-T02)

1. **The kind:** `remote_runner`, a Heimdall runtime on headless Linux under the runner account.
   - **What it owns:** its signer (K_env in memory), supervisor, grants, tombstones, readiness and onward projection.
   - **What it cannot do:** issue (ADR-0005 §4.3).
2. ⟨r2⟩ **Issuance** (R06):
   - **Pinned to its issuer:** each grant is pinned to the controller and CA that issued it. In V1 a different issuer needs a separately approved grant.
   - **The order:**
     1. ⟨r3⟩ a standing policy that covers the request, or a decision confirmed **runner-locally** (§3.10). A remote client may submit the request;
     2. the runner generates K_env and returns K_env.pub bound to the grant and its generation;
     3. the issuer runs ADR-0005 §3.5's reserve and publish;
     4. the runner installs under §3.5 step 4, checking the certificate's key, issuer (it must be in `issuer_trust`), principals, generation, scope and `valid_before`.
   - ⟨2026-11-21⟩ **How a grant comes to exist on a runner** (ruling on the W3 `host` unit's questions; ADR-0005 §3.5 "Remote reservations"):
     - **It starts as an `ensure`** naming the runner's environment. The controller's runtime forwards it over the management session and records exactly what it asked. An `ensure` made locally on the runner goes through the same admission.
     - **A runner never issues locally.** An admitted grant waits for its issuer (refresh dependency `controller`). The runner prepares K_env, the controller's host issues, and the runner installs.
     - **The host issues only for scope a controller-held record authorizes:** an `ensure` it forwarded, or a standing policy held on the controller that names that runner. A runner-originated pending grant outside both stays pending, and readiness reports `controller_dependency`.
     - **Work on the runner** binds through the runner's binding endpoints. A local `ensure` covered by a live issued grant attaches to it.
     - **Certificate length:** a remote certificate runs to the grant's bound (ADR-0005 rejects short renewed certificates). There is no routine renewal. A re-issue happens only after a lifted cutoff, through the controller's `resume-issuance`, and replaces the certificate the cutoff removed.
     - **Who may name the issuing CA:** the forwarding controller, or the runner's local owner for a CA already in the runner's `issuer_trust`. The second creates a pending grant only.
     - **Attach:** same profile; the forwarding client or the runner's local owner; an attached binding's endpoint lists only its own subset of pairs.
     - **The host's session:** one per owned runner, a 30 s pass, with exponential backoff up to about 5 minutes while a runner is unreachable, reset on success.
3. ⟨r2⟩ **Lifetime** (the ruling on Q7; R09):
   - **Preferred:** a verified `systemd --user` unit where the owner has enabled linger. Heimdall never enables linger; setup offers it.
   - **Otherwise:** readiness reports the narrower lifetime: `session_scope`, which survives logout only while `KillUserProcesses=no`.
   - **Evidence is kept apart:** detached-session evidence (G07) is distinct from user-service, restart and reboot evidence.
4. ⟨r2⟩ **Time samples** (the ruling on Q-T; R02):
   - **Who may answer:** only an `owner` client the owner has explicitly designated as this runner's trusted time source. ⟨r3⟩ The designation (`time_source`) is a widening action, confirmed runner-locally (§3.10). It answers `TimeResponse{nonce, T_c}`, fresh and nonce-bound, on its authenticated session.
   - **When it counts:** only within the RTT bound G09 sets.
   - **What it never does:**
     - extend a deadline or an anchor; a sample may only move the anchor earlier (ADR-0005 §3.6);
     - act as `confirm_time` (manual time confirmation);
     - reset a deadline.
   - **Without a qualifying sample:** `TIME_UNCERTAIN`.
5. ⟨r2⟩ **Readiness** (R06, R09; the ruling on Q9):
   - **`offline_until`** is the **earliest** of:
     - the runner's derived continuous-clock anchor;
     - the inherited or parent deadline;
     - the cutoff;
     - the certificate's `valid_before`, which carries a stated destination-clock uncertainty.
   - **No new cap.** Each revocation residual is reported separately (§7.3).
   - **Dependencies by construction:**
     - **Clean launch:** runner work starts from a clean environment holding only an explicit inventory of runner-owned sources: its own signer, runner-local key files adopted as existing access, and verified local signers.
     - **Unattended readiness** is claimed only for runner-managed or independently managed local custody.
     - **Any other agent** has provenance `unknown`, with no unattended claim. That includes an ordinary local path that may relay to the controller.
     - **Path patterns** are diagnostics only.
     - **Reported:** the conditions (lifetime, time bound, process not restarted).
   - ⟨2026-11-22⟩ **The declared pass-list.** Work launched on a runner (`run`, `run --parent-binding`, `connect`) receives exactly these variables from its parent environment and nothing else:
     - the installation locators: `HEIMDALL_HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`;
     - `TERM`, `TZ`, `LANG`, `LC_ALL`.
     None carries authority. `SSH_AUTH_SOCK` never reaches runner work. Adding a variable is an explicit change to this list, and a test asserts the exact set.
   - ⟨2026-11-22⟩ **Launcher-set values**, separate from the pass-list: the launcher sets `PATH`, and sets `HOME`, `USER`, `LOGNAME` and `SHELL` from the account database, never from the parent. When the parent has no `LANG`, the launcher sets `LANG=C.UTF-8`. The exact-set test asserts these come from the account database even when the parent sets something else.
   - ⟨2026-11-22⟩ **An undetermined `IdentityAgent`:** when the static pass cannot determine an existing-access alias's `IdentityAgent` (`~`, `%` tokens, a `Match`-dependent value), an unattended launch on a runner is refused, naming the alias and why. Attended launches behave as before.
   - **Refusal:** `CAPABILITY_UNAVAILABLE`, reason `controller_dependency`, for inherited controller sockets, and reason `dependency_provenance_unknown`.
   - ⟨2026-11-21⟩ **The refresh dependency** of a runner's managed binding is the contract value `refresh_dependency: controller`: the controller's issuer. The G07 report calls it `controller_issuer`.
6. **Fixed-auth onward targets** use runner-local existing access only. The controller's agent is never used.
   - ⟨2026-11-22; found by the A25 real-binary journey, revert proof in the W5 `w5j` unit⟩ **A request from a paired client that is not an owner always waits for an owner controller's record, fixed pairs included.** The runner's standing policy is its owner's, for the owner's work; nothing in it extends to requesters. Before this rule, a requester's `ensure` naming no CA was resolved by the runner's own catalog and came back with an active grant. Letting a runner policy cover requesters is later design, not V1.

## 5. Stable destination identity with several approved routes (M06-T03)

### 5.1 The model

- **What a destination holds:** an ID, its approved host-key set (catalog-pinned), its accounts, and an ordered list of approved routes:
  - `direct{host, port}`;
  - `jump{via: destination-id}` (single hop);
  - `iroh{endpoint ID, exposure policy}`.
- **What a route is:** reachability data only.

### 5.2 ⟨r2⟩ Host pins hold at every hop (R04)

**Management connections run under an isolated configuration.**
- **How:** `ssh -F <heimdall-mgmt.conf>`, so neither the user's configuration nor the system's is read.
- **What it renders, for every hop:**
  - `StrictHostKeyChecking yes`, `UserKnownHostsFile <pins>`, `GlobalKnownHostsFile none`;
  - `KnownHostsCommand none`, `VerifyHostKeyDNS no`, `UpdateHostKeys no`, `CheckHostIP no`;
  - `HostKeyAlgorithms <the pinned key's algorithm>`, `HostKeyAlias hm-dest-<id>` / `hm-env-<id>`;
  - `ControlMaster no`, `ControlPath none`, `ControlPersist no`;
  - `ForwardAgent no`, `ClearAllForwardings yes`, `IdentitiesOnly yes`;
  - `PermitLocalCommand no`, `SetEnv`/`SendEnv` none.
- **The jump hop** is defined in the same file with its own pin.
- **Multiplexing:** no management connection reuses a multiplexed master.

**⟨r3⟩ Projected ordinary clients** (the user's ssh through Heimdall's include; R04):
- **What Heimdall verifies:** with `ssh -G <alias>`, and for the jump alias too, at projection time and in doctor.
- **Each of these must hold effectively, at both hops:**
  - **`StrictHostKeyChecking yes`,** exactly. `no`, `off`, `accept-new` and `ask` are refused even when the pin file is in use, because a changed key must never be accepted;
  - **`HostKeyAlias`** is the expected `hm-dest-<id>` (or the jump's own);
  - **catalog-only trust:**
    - the effective `UserKnownHostsFile` is the pin file only;
    - `GlobalKnownHostsFile` is `none` or `/dev/null`;
    - there is no `KnownHostsCommand`;
    - `VerifyHostKeyDNS no` and `UpdateHostKeys no`;
  - **multiplexing:** `ControlMaster no` with `ControlPath none`, **or** a `ControlPath` that is the path owned by the active context's binding (M03/M05).
- **Anything else is refused:** `CAPABILITY_UNAVAILABLE`, reason `host_pin_defeated`, naming the setting. That includes an alias override from an earlier `Host` or `Match` block.
- This extends M04-D03.

### 5.3 ⟨r2⟩ Rendering, and ADR-0010 §5(b) revised explicitly (R04)

**ADR-0010 §5(b) is revised as follows:**
- ProxyCommand **remains rejected** for every route, with exactly one exception.
- **The exception:** Heimdall's own fixed helper, `"<abs heimdall>" route connect --destination <id> --account <a>`.
- **When it is rendered:** only for a destination with more than one approved route, or with any Iroh route.
- **Its inputs are typed:** a destination ID and an account. The helper looks the approved route list up from the catalog, and takes no host, command or route text from configuration or arguments.
- **Destinations with one direct or jump route** keep their native rendering (`HostName`/`Port`, or ADR-0010's single-hop `ProxyJump`).

This text replaces nothing else in ADR-0010 §5.

⟨Amendment, 2026-11-26, M08 W4 SEC-2, S4-01, orchestrator ruling⟩ The
catalog-only host-trust directives also apply to the native sections covered
by ADR-0010 §5. The helper's execution exception continues to apply only to the
helper described above. A defeated required pin makes its alias unready and
excludes it from the projection.

### 5.4 ⟨r2⟩ ⟨r3⟩ The helper's jump leg keeps ADR-0010 §5's authority (R04)

**A jump route inside the helper is the single-hop `ProxyJump` semantics of ADR-0010 §5 items 1–4, unchanged.**
- **How it runs:** the helper runs `ssh -F <isolated> -W <final host>:<port> <jump alias>`, and the jump alias has its own pin.
- **Its own approved dependency:** the jump authenticates with either:
  - a managed pair in **the same grant as the final pair**, whose certificate carries `permit-port-forwarding`;
  - existing access.
- **Anything else:** `route_dependency_out_of_scope`.

⟨r3⟩ **How the helper finds the active binding:**
- **The alias renders both** `IdentityAgent <binding endpoint>` and the helper's `--endpoint "<that same path>"`. The helper's arguments are destination ID, account and endpoint, and nothing else.
- **The helper asks the runtime** `ResolveRouteBinding{destination, account, endpoint}`. The runtime returns the one binding (and its grant) served at that endpoint for the caller's context.
- **It refuses** when it finds zero or several bindings (`route_binding_ambiguous`), or a grant that does not cover the destination.
- **Concurrent grants** on different endpoints therefore never borrow each other's jump dependency, and the helper never picks a binding by destination alone.

**What carries over:** readiness, the weaker-hop lock continuity, and the forwarding rules.

**The test:** M04-D03's two-hop substitution test is extended to helper aliases. Also, two concurrent grants: the second grant's jump pair is refused for the first grant's final pair.

⟨2026-11-22; rulings on the W5 `w5n` unit⟩ **Routes in the product.**
- **Projection:** a managed-certificate alias whose destination has several routes renders the route helper and the catalog pin, only through `setup apply`, shown in its diff first. Aliases Heimdall does not own and the user's own `Host` blocks stay byte-identical. **Existing-access aliases with several routes keep their native rendering;** a preview and doctor finding says their routes are not used by ordinary ssh.
- **The pin check:** `setup apply` uses the static check, and runs `ssh -G` only with `--allow-config-commands`. Where the static check cannot decide (a `Match exec`, for example), the diff shows the pin status as `undetermined`, and the helper's own `ssh -G` check before any route attempt is the backstop.
- **Route health** (`route.record_health`): only the binding holding the pair's slot may report; the report is typed (a stored route ID, an outcome code, a bounded duration); it can only reorder among stored, owner-approved, pinned routes; it is bounded per binding and kept in memory only.
- **A certificate-content change:** the bastion of a stored, owner-approved jump route under the same grant gets `permit-port-forwarding` in its certificate. The destination's certificate never gains it, and no other extension or restriction changes.
- **A jump hop that cannot be built is skipped; a jump pin that differs from the catalog refuses the whole connect.**
- **Outside V1:** a runner dialing onward over Iroh through a projected alias. The specification does not require it (A24 and R-EN-05 need a runner that continues without its controller; A26, R-SS-05 and R-SS-07 are about routes to a destination). A runner has no catalog pin and no alias projection of its grants.

### 5.5 ⟨r2⟩ ⟨r3⟩ Failover (R08)

1. **The establishment point** is the receipt, through the candidate route, of the server's SSH identification line (`SSH-2.0-…`).
   - **Before it,** the helper holds the client's bytes.
   - ⟨r3⟩ **Pre-identification lines:** lines the server sends before its identification are buffered and forwarded unchanged once it arrives (RFC 4253 §4.2). The buffer is bounded at 8 KiB and 32 lines; past that the attempt fails.
   - ⟨r3⟩ **A bounded wait:** a 10 s default, configurable per route. (⟨2026-11-22⟩ Failover from a route with nothing behind it therefore takes about 10 s; the default is unchanged.) A peer that waits for the client to identify first times out at that bound.
     - **That timeout is an establishment failure,** so the next approved route may be tried.
     - **On a direct or jump leg, a route whose server needs client-first identification is incompatible with the helper** (on an Iroh leg, item 5 applies). It is reported as such, and stays reachable through a single-route native rendering.
2. **The forwarding boundary** is the first byte forwarded in either direction.
   - **Failover is allowed only before it:** a connect refusal or timeout; a jump leg exiting before identification; an Iroh connection refused or closed before identification.
   - **After it, every failure is terminal for the attempt.** That includes a late Iroh refusal and a downstream failure.
3. **Never:**
   - **retried:** a host-key or authentication failure, which ssh detects on every route;
   - **used:** an unapproved route, profile or relay.
4. ⟨r3⟩ **A structured route-health result** (§9 item 8):
   - **When it is written:** for every attempt, failed-over or not.
   - **What it records:** each tried route, its failure class (`refused`, `timeout`, `identification_timeout`, `admission_refused`, `terminal_after_forwarding`), and the route finally used, or none.
   - **Where it can be read:** through `inspect` and the `route.health` event.
   - **What it is not:** the helper's exit codes stay internal.

5. ⟨Amendment, 2026-11-21; M06-W1-R04, Gemini W1 review (`tests/evidence/artifacts/review-m06/w1.md`); orchestrator ruling⟩ **The client's identification line on an Iroh leg.** A QUIC stream is invisible to the serving side until the dialer writes, so holding every client byte until the server's identification would deadlock against `/pigeons/0` serving (which accepts the stream before connecting its target). On an Iroh leg the helper therefore forwards exactly one thing before the server's identification: the client's own SSH identification line. A preamble is not used, because a stock Pigeons roost would forward it to sshd and break raw `/pigeons/0` interop (§1.2).
   - **Bounded and validated before anything is forwarded:** the first line from the client must start with `SSH-2.0-`, end in CRLF, and be at most 255 bytes including the CRLF (RFC 4253 §4.2). Anything else, no CRLF within 255 bytes, or no line before `identification_timeout` fails closed, and nothing is forwarded.
   - ⟨2026-11-21⟩ **Which failures end what** (ruling 3):
     - **A malformed or overlong client line** is terminal for the whole connect, with a precise error. No other route is tried: the client's bytes would be the same on every route.
     - **A timeout waiting for the client's line** stays route-local. The next approved route may be tried.
     - **Neither counts against the Iroh route's health.**
   - ⟨2026-11-21⟩ **Validated before the dial, and waited for once** (M06-W2-R06; ruling on the two windows): the client's line is read and validated before any Iroh leg is dialed. The client window applies once per connect: later routes replay the held line and wait only for the server's identification. The worst case is one client window plus one server window per Iroh route tried.
   - **Nothing past the line** goes out until the server's `SSH-` arrives; the hold-and-replay rule of items 1–2 covers it.
   - **Replay on failover:** the line is stateless; on failover the next approved route receives the same bytes exactly once, and the pre-`SSH-` replay guarantee holds.
   - **Admission order is unchanged:** the serving side checks the allowlist and the authority generation before any target connect; the identification line never bypasses either check.
   - The line's contents are not logged.

### 5.6 No session migration

- **A lost interactive session** is reported lost (G06 S05).
- **Uncertain commands** are never replayed.
- **No claim is made** that live sessions survive a route change.

### 5.7 The M04 deferrals land here

- **Catalog-pinned host identity** applies to every route.
- **Enrollment and verification through a jump** use the final-key rule; a changed final key through any route is `held`.
- **Multi-hop chains** stay `route_chain_unsupported`.

## 6. Version and capability negotiation

1. **The hello** follows ADR-0006 §2.3. A protocol or schema-major mismatch is `SCHEMA_UNSUPPORTED`, naming both versions.
2. ⟨r2⟩ **Capability-required negotiation for remote sessions** (§9 item 4):
   - **The rule:** `required ⊆ offer ∩ server ∩ role`.
   - **A required capability the server lacks:** `SCHEMA_UNSUPPORTED`.
   - **A required capability the role lacks:** `CAPABILITY_UNAVAILABLE`, reason `role_insufficient`.
   - **Optional capabilities:** used only when they are in the intersection.
3. **New capabilities:** `remote-control/1`, `runner/1`, `routes/1`, `transport-iroh/1`.
4. **Runner binary updates are explicit:** a checksum-verified copy, drain, then restart. The environment ID and table are preserved.

## 7. Disconnected status, revocation and resynchronization (M06-T05)

1. **The controller's view:**
   - **Connectivity:** `connected`, `disconnected{last_seen_at}` or `unreachable{reason}`.
   - **Also shown:** the last-known readiness, computed forward, and the `remote_pending` effects.
2. ⟨r3⟩ **Effects are typed and keyed** by (authenticated producing controller, effect ID, **typed target**, **target generation**) (R06, RC-R04):
   - **`grant_revoke{grant, grant_generation}`:** applied as a **durable grant tombstone** (ADR-0005 §6.1 "Revocation"), and acknowledged with its enforcement state: K_env zeroized, owned masters and owned dedicated sessions **closed at once**, admissions refused.
   - **`policy_pause{policy, revision}`:** applied as a **durable policy revision**. Running grants continue and new activations are refused (§6.1 "Pause"). It is not a tombstone.
   - **`policy_cutoff{scope, revision}`:** applied as a durable policy revision. It also ends every affected grant like expiry, and refuses new grants until the cutoff is cleared (§6.1 "Cutoff").
   - **Acknowledgement:** an effect is acknowledged only after the durable record it names exists.
3. ⟨r3⟩ **Residuals keep ADR-0005 §3.5 and §6.1–§6.2.** They are per component:
   - **New authentication:**
     - **Its bound:** `latest_possible_credential_expiry`, taken from the **counted issuance history**. Reserved and published certificates count until their `valid_before`.
     - **Plus destination-clock error.** Where that error is **unmeasured**, the residual is reported as "until `valid_before` plus an unmeasured destination-clock error". It is **never a bare D**.
   - **Owned dedicated sessions:** closed at once on an applied revoke.
   - **Owned admissions:** closed.
   - **Other live sessions:** per the G09 table.
   - **Detached remote processes:** not ended.
   - **Where history is missing:** a controller without the grant's counted history reports `unknown`.
4. ⟨r3⟩ **Reconnect order:**
   1. hello;
   2. **narrowing effects from either controller are pushed and applied, even with uncertain time;**
   3. **the runner's authority report:** tombstones, policy revisions with their generations, and installed certificates;
   4. ⟨r3⟩ **the issuer's reconciliation barrier.** The issuing controller's issuer reads the runner's report before any new `reserve` or `publish`.
      - **A grant another controller tombstoned** is marked revoked in the issuer's ledger, and its counted certificates enter the residual.
      - **A paused or cut-off policy** blocks issuance for that scope.
   5. the time sample (§4.4).
   - **Gating:** issuance, approval of new work, and owned-connection admission stay **gated until both grant tombstones and policy revisions are reconciled**, the outbox is drained, and time is bounded.
   - **Stale grants:** a tombstoned grant is never reactivated. A fresh work ID cannot pass a reconciled pause or cutoff.
   - ⟨2026-11-21⟩ **Rulings on U4's questions:**
     - **Both ends gate.** The controller's barrier and a per-session gate on the runner refuse issuance until the report and resync are complete (`resync_pending`). The runner is the authority: it refuses prepare and install from a session that skipped the report.
     - **A revoke always wins over a stale view.** It revokes the named grant at its current generation and everything older. The generation it carries is for idempotency and audit only, never a precondition. Re-issuing after a revoke needs a new widening.
     - **A cutoff under unbounded uncertain time** fires at once, since it only narrows. Once fired it stays fired even after time becomes certain; only a runner-local attended action lifts it. `environment status` and `doctor` say it fired early because time was uncertain.
     - **Lifting:** a runner-local attended `resume` or `clear_cutoff` lifts a delivered pause or cutoff. The revision rows stay as the record.
       - ⟨2026-11-22⟩ **The in-force flag:** the runner's report states, per delivered revision, whether that effect is still in force. Only a runner-local attended lift clears it. On a runner with no policy in the effect's scope, the attended `policy clear-cutoff` and `resume` succeed for an empty set while a delivered revision of that scope is in force, and clear that revision's flag. More generally, the runner's local owner lifts a delivered effect by clearing its scope: a targeted, attended `resume` or `clear-cutoff` lifts the in-force delivered revisions of exactly its scope, whatever policies exist now. The approval names the effect being lifted (its scope, the delivering controller, and when). ⟨2026-11-23, rulings on M06-W5-R01⟩ An untargeted `resume` or `clear-cutoff --policy P` on a held policy whose widening lifts a delivered effect is recorded in the targeted form, so the approval shows exactly what it lifts. A paired session's request that would lift a delivered effect is refused at request time (`CAPABILITY_UNAVAILABLE`, `role_insufficient`; only the runner's local owner lifts a delivered effect) and leaves no decision record. An approval whose re-check finds a lift its decision does not name (an effect delivered after the decision was issued) is `DECISION_STALE`, and nothing is lifted.
       - ⟨2026-11-22⟩ **Two keys, per controller:** the delivering controller resumes only when the runner reports that effect no longer in force and its own owner has acknowledged it.
       - ⟨2026-11-23, M06-W5-RC01, RC02⟩ **A delivered effect stays in force until a lift that names it is approved; removing or narrowing a policy never lifts it.** The flag clears when the runner's attended owner approves the decision that names the effect, at that approval; the report only reads it. A pause or cutoff the runner's owner makes after that is the runner's own: the delivered effect reads lifted, and the standing policy in the report keeps every controller blocked for that policy (`PolicyPaused` / `PolicyCutoff`).
       - ⟨2026-11-22⟩ **Two owner controllers:** a controller is blocked by the effects it delivered itself, until its two keys clear, and by anything the runner reports as in force. Another controller's effect that the runner reports as lifted does not block it.
     - **Coverage:** a cutoff covers the policies that exist when it is delivered. A policy the runner-local owner creates later is that owner's own attended widening.
   - ⟨2026-11-21; M06-W3-R02 and the ruling on it⟩ **The controller's own delivered effects gate issuance, whatever the runner says.**
     - A cutoff with scope `all` that this controller delivered blocks all issuance for that runner.
     - While the runner's report, or any undrained or unlifted effect this controller delivered, holds a pause or cutoff, a prepare answer that names no policy, or one the report does not list as active, is refused.
     - **This is sticky until a lift is acknowledged on the controller** (W4): issuance resumes only when the runner's report shows the lift and the owner confirms it on the controller, recorded as a controller-held row. Neither alone reopens issuance.
     - **Residual:** a runner that lies in both its report and its answer passes the report-side checks; only this controller's own delivered effects are independent of it.
5. **Identity is not reset.**
   - **A changed host key,** or an environment ID that does not match the pin, gives `held`, with `environment_identity_mismatch`.
   - **Repair** goes through independently host-verified access (§3.3).

## 8. A second controller (M06-T06)

1. **Enrolment:** a second `owner` is enrolled by invitation (§3.9), with its own K_mgmt and K_ca.
2. ⟨r2⟩ ⟨r3⟩ **Narrowing:** either owner may deliver any typed narrowing effect (§7.2): a grant revoke, or a policy pause or cutoff.
3. ⟨r2⟩ ⟨r3⟩ **Issuance and renewal** for a grant come only from its issuing controller (§4.2), after the reconciliation barrier (§7.4). If the first controller is gone, its grants run to their bounds. A separate grant for the second controller is a widening action confirmed **runner-locally** (§3.10), only on destinations that trust its CA, and only after a runner-local `issuer_trust` change.
4. **What T06 exercises:** wrong role, invitation replay, route substitution, an untrusted issuer, and renewal without an issuer.

## 9. ⟨r2⟩ ⟨r3⟩ Proposed ADR-0006 revision 6 (not applied; explicit, per R01, R02, R06)

The contract owner applies these at M06 wave 0 (m06-plan U0). Each item names the ADR-0006 rule it changes. Additive shape changes need no schema-major bump, and earlier supported forms keep their behaviour.

1. **§2.1 (caller identity).** `CallerContext` gains `remote_client: Option<ClientId>`. It is set only by a runner runtime, from a bridge hello on a same-uid connection (§3.6), and never from request fields.
2. **§7.1 (idempotency identity)** becomes `(CallerContext{principal, role, remote_client}, operation kind, request_id)`. The same applies to:
   - **operation ownership and visibility** (§4.1);
   - **§8 cursors and subscriptions.**
   Revoking a client closes its sessions and subscriptions with a terminal `client_revoked` event.
3. ⟨r3⟩ **§2.3, §3.1 and §13.3 item 2 (attendance): unchanged.**
   - **Remote sessions:** a paired remote session is never attended. `Attend`, `Decide` and `confirm_time` on it are refused before dispatch (`INTERACTION_REQUIRED`).
   - **Widening:** it executes only through §3.1's decision record on an attended session local to the runtime whose authority or exposure widens (§3.10).
   - **What a remote client can do:** submit a widening request, which creates a pending record.
   - **Replay:** a replayed request returns the recorded terminal result (§7.3).
   - **Revision 2's `RemoteDecide` and its named amendment are withdrawn.**
4. **§2.3 (negotiation).** `required ⊆ offer ∩ server ∩ role`, with the two refusal codes of §6.2. `ServerHello` gains `role`. New capabilities: `remote-control/1`, `runner/1`, `routes/1`, `transport-iroh/1`.
5. **Environment view.**
   - `EnvironmentKindView::RemoteRunner`.
   - `EnvironmentView` gains `connectivity`, `last_seen_at`, `runner_lifetime`, `remote_pending[]`, `pinned_host_key` and ⟨r3⟩ `management_policy: verified | owner_only`.
6. **New requests:**
   - `env add`, `invite`, `join`, `revoke-client`, `remove`, `update` and `status`; `device retire`;
   - `route add`, `remove` and `prefer`;
   - `transport enable` and `disable`, and `roost adopt`;
   - runner-internal:
     - `prepare_remote_grant`, `install_certificate`;
     - `TimeChallenge`/`TimeResponse`;
     - `deliver_effect` with typed targets per §7.2;
     - `authority_report` (§7.4);
     - ⟨r3⟩ `ResolveRouteBinding` (§5.4);
     - ⟨r3⟩ the serve child's lease and suspend messages (§2.3), which stay internal to the supervision channel.
   - **No `RemoteDecide`.**
7. **New reasons** under `CAPABILITY_UNAVAILABLE`:
   - **roles, invitations and decisions:** `role_insufficient`, `client_revoked`, `invitation_expired`, `invitation_consumed`, ⟨r3⟩ `invitation_pending`, `decision_binding_mismatch`;
   - **management and stores:** ⟨r3⟩ `management_sshd_unverified`, `management_sshd_unsupported`, `mgmt_key_store_locked`, `transport_key_store_unavailable`;
   - **runner dependencies and identity:** `controller_dependency`, `dependency_provenance_unknown`, `issuer_untrusted`, `environment_identity_mismatch`;
   - **routes and transport:** `host_pin_defeated`, ⟨r3⟩ `route_binding_ambiguous`, `route_unapproved`, `relay_unapproved`, ⟨r3⟩ `exposure_unconsented`, `transport_unavailable`, `transport_refused`, ⟨r3⟩ `transport_authority_lost`, `route_dependency_out_of_scope` (existing);
   - **keys:** `key_already_authorized`.
   - **And one pending reason:** `iroh_admission_closing`, under `remote_pending`.
   - No new top-level code, and no exit-code change.
8. **New events:**
   - `environment.connectivity_changed`;
   - `client.enrolled`, `client.revoked`, `device.retired`;
   - `remote_effect.pending` and `remote_effect.acknowledged` (producing controller, effect ID, ⟨r3⟩ typed target and generation);
   - ⟨r3⟩ `route.health`, the structured attempt result of §5.5 item 4, emitted for every attempt;
   - `route.failed_over`, kept as a subtype.
   Each is an audit event.
9. **The destination object** gains `routes[]` (each with its exposure policy and consent references) and `host_keys[]`. The existing single route and jump fields become the one-element case.
10. **Readiness** adds `conditions[]` and the per-component residuals of §7.3 to the existing `usable_until`, `refresh_dependency` and `offline_until`.
    - **⟨r3⟩ The authentication residual** carries `latest_possible_credential_expiry` and `destination_clock_error: measured{bound} | unmeasured`.
11. **Store migration `000N_remote`:**
    - the role table; invitations with their generation, wall deadline, boot ID and elapsed bound; decision records;
    - the typed effect outbox, keyed per §7.2, with acknowledgements;
    - policy revisions received;
    - remote environment pins and grant-to-issuer pins;
    - routes with their exposure policies and consents;
    - the authority generation;
    - transport key references.

## 10. Claims and non-claims

**Claims (once A24–A26 pass):**
- A runner continues approved onward SSH without its controller, until the stated earliest bound.
- An inherited controller dependency, or a source of unknown provenance, is refused before any unattended readiness promise.
- Limited clients cannot widen authority or execute.
- Widening, including new exposure, is decided only by an attended session local to the runtime whose authority or exposure widens. No paired remote client can widen.
- Invitations are consumed once.
- Routes cannot grant authority or change host identity.
- Iroh uses only the infrastructure the user consented to.
- Revocation closes Iroh admission before it is reported applied, and admission fails closed when authority is lost.

**Non-claims:**
- No in-account isolation on the runner.
- No live session migration.
- A revoked runner credential remains usable at destinations within the reported residuals while the runner is unreachable.
- No support label on a Windows path that has no evidence.
- Headless persistent Iroh endpoints are unavailable in V1 (§2.7 not adopted).
- ⟨2026-11-21, §5.5 item 5⟩ A client that sends nothing until it sees the server's banner fails on an Iroh route with `identification_timeout`. OpenSSH, Win32-OpenSSH included, sends its identification first, so the product's own path is unaffected.
- ⟨2026-11-21, §3.4⟩ K_mgmt and K_iroh are never synchronized, but they can be present in encrypted local backups (Time Machine for the macOS login keychain until D3; account backups of Secret Service collections and DPAPI blobs). Recovery on another device is `device retire` and revocation, never a restore.

## 11. Rejected

| Rejected option | Reason |
|---|---|
| A supervised Pigeons helper | G06 §2 |
| Iroh or mutual TLS as the management channel, and management certificates from K_ca | G07 §2.1 |
| Bearer pairing tokens | They need replay and log controls the key-bound invitation avoids |
| Copying an issuer to the runner | spec §6.5 |
| Persisting K_env on runners | No verified headless store |
| A tunnel back to the controller | plan §3 G07 failure action |
| Port mapping | Exposure, and no need |
| n0 publishing by default | spec §9.2 |
| An owner-only plaintext file for K_iroh | spec §7.3; the ruling on Q2 |
| Accepting the owner role, or a client flag, as attendance | R02 |
| ⟨r3⟩ `RemoteDecide` from paired clients (revision 2) | An unattended paired owner could complete it (re-check R02) |
| ⟨r3⟩ Limited roles on an unverified sshd | Behaviour probes cannot establish the effective policy (re-check R01) |
| A generic ProxyCommand | ADR-0010 §5(b), kept apart from §5.3's narrow exception |

## 12. ⟨r2⟩ Questions: the rulings, recorded as decided (orchestrator, 2026-11-19)

- **Q1. K_mgmt** is held in the verified persistent platform store, by desktop controllers only in V1. Device retirement is separate from revoking a runner (§3.4).
- **Q2. K_iroh:**
  - **Where a platform store exists:** it is used (Keychain, DPAPI or Secret Service).
  - **Where none exists:** a persistent Iroh endpoint is unavailable. It fails closed with a doctor finding, and direct and bastion routes are unaffected.
  - **Plaintext is never used.**
  - **The encrypted headless option** is §2.7, ruled not adopted in V1. K_iroh is disclosed as reachability-only (§2.4).
- **Q3.** A shell on the runner account is accepted and disclosed as owner-equivalent, and a separate account is recommended where operators must be isolated (§3.12).
- **Q4.** `n0-public` is off by default. It is an explicit opt-in with disclosure, offered only once that profile's exact traffic has been captured (§2.2).
- **Q5.** Windows is decided per path, from W1, W3 and W4 plus the in-box OpenSSH journey. A path with no evidence gets no label (§2.6).
- **Q6.** ⟨r3⟩ The wording is scoped as follows.
  - **What "no public-relay test" covers:** the design-unit probes and Pigeons interoperability.
  - **Supported:** Heimdall's client to a stock roost, as adopted external infrastructure with its exposure disclosed. Adoption is a widening action (§2.8).
  - **Unsupported:** a stock Pigeons client to Heimdall's serve (§1.2).
  - **The `n0-public` profile** stays outside V1 unless its one bounded capture row runs, in U56. That row is authorized: a container, at most 5 minutes, ephemeral keys, an allowlist and an echo target, with no sshd and nothing that serves the host (§2.2).
- **Q7.** Linger is never enabled automatically. Setup offers it, a user service is used where verified, and readiness reports a narrower lifetime otherwise (§4.3).
- **Q8.** The netdev patch is vendored, pinned and feature-scoped, with an upstream request and per-platform bind evidence (§1.3).
- **Q9.** No new cap. Readiness reports the earliest safe runner deadline and each revocation residual separately (§4.5, §7.3).
- **Q-T.**
  - **What counts:** only fresh, nonce-bound, RTT-bounded answers from an owner client explicitly designated as this runner's trusted time source.
  - **What it never does:** extend anything, or act as a manual time confirmation.
  - **Not enough on its own:** the `approve` permission (§4.4).

**⟨r3⟩ Rulings of 2026-11-20 on the re-check, recorded as decided:**
- **R01:** limited roles only with a verified effective sshd policy (§3.2); otherwise owner-only.
- **R02:** no `RemoteDecide` in V1. Widening is confirmed runner-locally, remote clients may submit requests and narrow, and the denial test includes terminal result replay (§3.10).
- **R03 and RC-R01:** the pre-dispatch rule, and expiry as the earlier of the checked wall deadline and the non-extending elapsed bound, refused under uncertain time or a lost anchor (§3.9).
- **R04:** effectively strict, catalog-only trust at both hops, context-owned or no multiplexing, and helper binding resolution (§5.2, §5.4).
- **R05, RC-R02 and RC-R03:** the tombstone is the admission authority, under a generation lease, with suspend and close before reporting; widening exposure is a widening action (§2.1, §2.3, §2.8).
- **R06 and RC-R04:** typed effects, reconciliation before issuance or approval, the issuer barrier, and ADR-0005's residuals (§7).
- **Q6:** as above.

**Still open, for a ruling:** none. §2.7 (encrypted headless K_iroh store) was ruled not adopted in V1 (2026-11-20).

## 13. Consequences

- **New crates:**
  - `heimdall-remote`: roles, invitations, decisions, the bridge, outbox and resync;
  - `heimdall-transport-iroh`: feature `iroh`; `connect`, `serve` and the exposure policy.
- **Vendored source:** `third_party/netdev-0.47.0/`.
- **Contract:** revision 6 (§9).
- **ADR-0010:** the narrow §5(b) exception (§5.3).
- **Validation:** `check.sh` gains `cargo audit` for builds with the `iroh` feature.

## 14. Reopen conditions

- iroh changes the default-route probe or the `/pigeons/0` semantics.
- A RustSec advisory hits the pinned tree.
- A Windows path's evidence contradicts §2.6.
- A verified headless store appears, which would cover §2.7 and K_env persistence.
- OpenSSH changes how it handles `restrict`, `expiry-time`, `-F` or `ssh -G`.
- A requirement appears for multi-hop chains or live migration.

## 15. ⟨r2⟩ Revision 2 change map

| Finding | Where |
|---|---|
| R01 restricted session end to end | §3.2, §3.6, §3.7, §9 items 1–2 |
| R02 attendance | §3.10, §4.4, §9 item 3 |
| R03 invitation consumption and pins | §3.9 |
| R04 host pins and bastion authority on every route; ADR-0010 §5(b) | §5.2–§5.4 |
| R05 exposure per endpoint and route; revocation closes admission | §2.1–§2.3, §2.8, §3.11 |
| R06 time, issuance and revocation across controllers | §4.2, §4.5, §7.2–§7.4, §8, §9 items 4, 6–8 |
| R07 custody | §2.4, §2.7, §3.4 |
| R08 failover on raw streams | §1.5, §5.5 |
| R09 dependencies by construction | §4.3, §4.5 |
| R10/R11 evidence | g06 §1–§9, g07 §1–§8, the records |
| R12 Windows per path | §2.6; g06 §8 |
| R13 plan | m06-plan |

## 16. ⟨r3⟩ Revision 3 change map

| Item | Where |
|---|---|
| R01 verified sshd policy for limited roles | §3.2, §9 items 5 and 7, §11 |
| R02 no remote widening; runner-local confirmation; denial test | §3.10, §4.4, §8 item 3, §9 items 3 and 6, §11 |
| R03 pre-dispatch rule; identity before a recorded result | §3.9 items 3 and 6 |
| RC-R01 non-extending invitation expiry; rollback fault case | §3.9 items 4, 5 and 8, §9 item 11 |
| R04 effective strict catalog-only trust at both hops; helper binding resolution | §5.2, §5.4, §9 items 6–7 |
| R05 and RC-R02 admission authority, lease, suspend and close before applied, replay on recovery | §2.3, §3.11, §9 items 6–7 |
| RC-R03 exposure widening is widening, bound to the delta; preference changes need recorded consent | §2.1, §2.8, §3.10, §9 items 6–7 |
| R06 and RC-R04 typed effects, policy revisions, reconciliation barrier, ADR-0005 residuals | §7.2–§7.4, §8, §9 items 8, 10 and 11 |
| R07 K_mgmt rotation and backup; K_iroh loss recovery path | §2.4, §3.4 |
| R08 pre-identification buffering, bounded wait, route-health result | §5.5, §9 item 8 |
| R10 S11 is a host-name run; the IP-literal control is not run | §2.2 (and g06 §1, §5) |
| Q6 wording and the n0-public capture row | §2.2, §12 |
| R13 and RC-R05 | m06-plan |
