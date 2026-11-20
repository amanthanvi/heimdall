# G07 — Remote runner independence and pairing (M06 design unit)

**Status:** **open.** The design choices are supported for implementation: OpenSSH as the
management channel, and ADR-0005's memory-only runner credential model. The two records so far are
**mechanism probes** of OpenSSH and logind behaviour on one fixture host, not gate closure. G07 closes
only on the rows listed in §1.1, each with its exact blocking input named there. Revision 2
(2026-11-19) applies the independent design review (M06-D-R01, R03, R06, R09, R11).
· **Date:** 2026-11-19
**Plan:** §3 G07; spec §6.5, §8.1, §8.6, §14.2, §15.2 · **Decision record:** ADR-0012 (proposed)
**Evidence (mechanism probes):**
- `tests/evidence/g07-mechanism-management-roles.json`
- `tests/evidence/g07-mechanism-runner-departure.json`
- the artifacts under `tests/evidence/artifacts/g07/`
**Probe:** `prototypes/g07-runner-ssh/`, which is disposable.

Observed results are marked [O], inferences [I], and what the sources say [S].

## 1. Gate question and what the probes show

> Can a remote environment hold the required bounded access and enforce its own state after the
> controlling device departs, without turning pairing into unlimited owner authority?

**The design answer is yes, with SSH as the established authenticated channel and ADR-0005's
credential model.** The probes support the mechanisms that answer relies on.

**The runner keeps working after the controller leaves** [O, one fixture host]:
- **Survival:** a runner started with `setsid` from the controller's SSH session kept running after that session ended. This is detached-session evidence on a host with `KillUserProcesses=false` and linger already on. It is not user-service, restart or reboot evidence.
- **Its own credential:** 35 of 45 managed attempts succeeded, from 12 s before departure to 136 s after it. The runner used a K_env that existed only in its own agent, with a certificate from the controller's fixture CA. The first failure came at +141 s, after the recorded `valid_before` (+137 s). The server's expiry reason was not retained.
- **Fixed access:** all 45 fixed-key attempts succeeded, through 180 s after departure. That shows operation through the observation window, not that arbitrary fixed access lasts indefinitely.
- **The negative control:** a forwarded fixture agent on the runner host, tied to a nested SSH session, stopped working 1 s after that session ended. This demonstrates the session dependency. A path-pattern classification flagged it, but that cannot detect an arbitrary controller-dependent socket (§4).

**sshd's per-key controls hold on the fixture configuration** [O]:
- **The bound:** each management key is tied to a forced command naming its client ID, under `restrict`.
- **On that configuration a limited client could not:**
  - get a shell or a PTY;
  - use TCP forwarding (`-W`, `-R`);
  - stream-local forward to a control socket (the unrestricted positive control could);
  - change the client ID the bridge saw, by `SetEnv` or by the command text. sshd's `AcceptEnv` filtered the variables.
- **Not tested: agent forwarding.** The client had `IdentityAgent=none`, which disables forwarding, so no forwarding request reached the server. The positive and server-refused controls move to A25.
- **Invitation keys** with an `expiry-time` in the past were refused; unexpired ones were accepted.
- **A removed line** was refused on its next connection.
- **These results cover the fixture's sshd configuration only.** An adopted sshd can differ, which is why ADR-0012 §3.2 verifies the effective configuration before activation (R01).

**The authority boundary still to build** [I]:
- **What remains:**
  - the bridge, which originates the sole local hello;
  - per-client caller namespaces;
  - the role table, the sshd-policy verifier, runner-local widening confirmations (no remote decisions in V1), and the invitation state machine.
  All are in Heimdall's application layer (ADR-0012 §3).
- **Why same-account processes are not a further boundary:** a principal with a shell on the runner account is already its owner (ADR-0006 §2.1; T3 S34 lesson, `docs/sources/drift-2026-10-31.md` §S34). Limited roles therefore never include execution.

### 1.1 What closes G07 (each row names what it waits on)

| Row | Closes on | Blocked on |
|---|---|---|
| A24 | The m06-plan A24 journey with product code: devbox runner, macOS and Windows controllers | M06 waves W1–W3 |
| A25 | The m06-plan A25 journey, including the agent-forwarding positive and server-refused controls | M06 waves W1–W2 |
| A07 runner rows | Revoke while disconnected, reconnect and acknowledge, no stale reactivation | M06 wave W3 |
| Incompatibility negotiation | One real old-client/new-runner run with `SCHEMA_UNSUPPORTED` and a capability-required refusal | A previous release-candidate binary, or a `testcfg` protocol-major build (W4) |
| Native K_mgmt store availability | macOS Keychain and Windows DPAPI product stores, each with a locked-store row | W2. macOS locked-store rows follow the ADR-0004 §2 idle-console rule |
| Declared runner lifecycle | A `systemd --user` unit with linger, plus process-restart rows; **a no-linger / `KillUserProcesses=yes` host and a reboot cycle** | The last two need **a disposable Linux lifecycle environment the owner provides** (a VM or account where linger and logind settings can be changed, and which can be rebooted). The devbox's linger is the account owner's setting and is not changed |

## 2. Pairing and role protocol choice

### 2.1 Options considered

| Option | Verdict | Reason |
|---|---|---|
| **A. SSH as the management channel:** a per-client management key, enrolled on the runner account as `restrict,command="<heimdall> remote serve --client <id>"`; the ADR-0006 framing and hello over the forced command's stdio | **Chosen** | No new cryptography. Mutual authentication is host-key pinning plus per-client public-key authentication. sshd enforces per-key restriction and `expiry-time` (R2–R8). It reuses the ADR-0005 §3.3 authorized_keys add/remove procedure, and it works over every route (direct, jump, Iroh `ProxyCommand`) |
| B. Iroh/QUIC with raw-public-key TLS, roles bound to endpoint IDs | Rejected | Makes the optional transport mandatory for management. It conflates reachability identity with management authority (spec §4.2, §8.6), and there is no per-key restriction layer |
| C. Mutual TLS with a Heimdall PKI | Rejected | A second PKI and certificate lifecycle beside SSH's, and a listener to expose. It amounts to the "custom cryptographic handshake" plan §3 G07 rules out |
| D. Management certificates from the owner's issuer K_ca | Rejected | Signing and control purposes would share one key (R-SE-06). A destination trusting K_ca would also accept management certificates as login certificates if principals were ever misconfigured |
| E. Bearer invitation tokens (T3-style pairing URL) | Rejected for V1 | A bearer secret is what spec §8.6 asks to make one-use, short-lived and unlogged. Option A needs no bearer secret, because the invitation is bound to the receiving client's public key, so there is nothing to replay |

### 2.2 The protocol (normative text in ADR-0012 §3, revision 3)

In brief, revisions 2 and 3 being the review's and the re-check's corrections:
1. **Bootstrap** runs over the owner's existing host-verified access. It installs or verifies the runner binary, then runs `heimdall remote init` and enrolls the controller's K_mgmt as `owner`.
2. **Limited roles need a verified effective sshd policy** (R01; revision 3, ADR-0012 §3.2):
   - **How it is verified:** `sshd -T -h <scratch key> -C user=…` runs unprivileged and prints the account's effective policy [O: `artifacts/g07/sshd-T-readout.txt`; without `-h` it exits 1]. Alternatively, an operator-installed drop-in checked the same way.
   - **Without verification:** only owner-role clients enroll.
   - **Behaviour probes** (bridge reached, PTY, forward and agent refused, `SetEnv` canary) confirm the result. They never establish it.
3. **The bridge originates the only local hello.**
   - **Identity:** the client ID comes from the fixed arguments. Any identity assertion from the client is rejected.
   - **Session:** it stays bound to that ID.
   - **Namespaces:** caller context, idempotency, operation ownership and cursors all include the client ID.
   - **Revocation** is rechecked on every request and on existing subscriptions.
4. **Remote sessions are never attended, and cannot widen** (R02; revision 3, ADR-0012 §3.10).
   - **Widening actions,** including new exposure, are confirmed **runner-locally**: at the runner's CLI or TUI, or over an interactive ssh session with a TTY. That is owner-equivalent.
   - **Remote clients** may submit requests (a pending record) and deliver narrowing effects.
5. **Invitations** (R03):
   - **Pins:** both are checked by explicit fingerprint confirmation. The owner confirms the receiving key; the receiver confirms the runner's host key and environment ID.
   - **Pending keys** reach only the activation probe and `join`. Identity is checked before any recorded result is returned.
   - **Joining** is a distinct `join` operation over the forced command. A runner-side compare-and-set checks the invitation ID, the receiving key, the role and the live generation.
   - **The deadline** is checked at join time as the earlier of the checked wall deadline and a non-extending elapsed bound from the boot anchor. Uncertain time or a lost anchor refuses (RC-R01).
   - **Ordering:** the database transition is persisted before the line changes, and the line is reconciled idempotently. A lost reply returns the recorded result.
   - **Later connections** authenticate as an active client without consuming anything.
6. **Revocation** persists the tombstone before removing the line. The tombstone is authoritative even if the line rewrite fails.

## 3. Selected remote transport

**The design:**
- **Management and onward access are both OpenSSH.**
- **Reachability is a route:** direct, a single-hop jump (ADR-0010 §5), or the optional Iroh route (G06). It never authorizes anything.
- **The management channel and the runner's onward SSH share no socket, key or agent.**
- **No listener:** the runner needs no new one. It uses the existing sshd and, on the Iroh route only, the outbound-only iroh endpoint with an allowlist (G06 §5).

## 4. The runner's credentials and dependencies

```text
 controller device (owner)                         runner (Linux, own Heimdall runtime, same OS account)
 ───────────────────────────                        ─────────────────────────────────────────────────────
 K_mgmt (persistent, platform store) ── ssh ──▶ sshd ─▶ forced command: heimdall remote serve --client cid
   (management only; R-SE-06)          (host key pinned)      │ hello{remote_client: cid} ─▶ runtime control endpoint
                                                              ▼
 issuer: K_ca (never leaves) ◀── K_env.pub, grant ref ── runtime/supervisor: role table, grants, tombstones,
   signs C: principal hm:<d>:<a>,                           runner time anchor (ADR-0005 §3.6)
   valid_before = min(D, cutoff)  ── C (public) ──────▶ signer: K_env per grant, memory only
   time exchange (nonce, T_c)  ─────────────────────▶          │ binding endpoint (runner-local socket)
                                                              ▼
                                         onward ssh/git ─▶ managed destination (cert-authority line, B1)
                                         onward ssh/git ─▶ fixed-auth destination (runner-local existing
                                                           key or agent ON THE RUNNER; adopted as existing access)
 Dependencies after the controller departs:
   needed:      runner process, its memory K_env + C, destination reachability, runner clock (anchored)
   NOT needed:  the controller's sockets, agent, issuer, network presence, any forwarded agent
   needed only to: renew/re-issue (after expiry, restart or reboot), approve new scope, change roles
```

**Dependencies by construction** (revised for M06-D-R09):
- **Clean launch:** runner work starts from a clean environment, holding only an explicit inventory of runner-owned sources. That inventory lists:
  - the runner's own signer endpoint (Heimdall's K_env);
  - runner-local key files adopted as existing access;
  - verified local signers.
  Nothing else is inherited: no `SSH_AUTH_SOCK`, and no socket path from the starting session.
- **Unattended readiness** is claimed only for sources whose custody is runner-managed or independently managed local custody.
- **Any other agent** has provenance `unknown`, so no unattended claim. That includes an agent at an ordinary local path, which may still relay to the controller.
- **Path patterns** like sshd's `/tmp/ssh-*/agent.*` stay a diagnostic, never proof of independence.
- **Planned test (A24):** a controller-dependent signer behind an ordinary local path (a local socket relayed back to the controller) must be reported as `unknown` provenance, not as runner-owned.
- **What readiness reports:**
  - `offline_until`: the earliest of the runner's derived continuous-clock anchor, the inherited or parent deadline, the cutoff, and the certificate's `valid_before`. The last one carries a stated server-clock uncertainty.
  - `refresh_dependency: controller_issuer`.
  - The verified lifetime condition and dependency conditions (§4, process lifetime).

**Process lifetime on the runner** [O on the devbox: detached-session evidence only]:
- **The host:** `KillUserProcesses=false` (the Ubuntu default), with linger already enabled by the account's owner.
- **What survived:** a process started with `setsid` in the controller's session outlived it, staying in the departed session's scope.
- **The product** (ADR-0012 §4.3, the ruling on Q7):
  - **Uses a `systemd --user` unit** where the owner has enabled linger and the unit is verified.
  - **Otherwise reports the narrower lifetime:** `session_scope`, which survives logout only while `KillUserProcesses=no`. A session-scope runner under active logind cleanup loses its signer at logout.
  - **Never enables linger itself.** Setup offers it.

## 5. Offline coverage and revocation

Residuals are per component, as ADR-0005 §4.3 and ADR-0008 accepted (revised for M06-D-R06):
- **New authentication with an issued certificate** lasts until `valid_before`, plus the destination's clock error.
- **Owned admissions** close at the runner's anchored deadline.
- **Dedicated live sessions** follow the G09 table.
- **Detached remote processes** are not ended by any of these.

**Grants are pinned to their issuing controller and CA in V1.** A controller that does not hold a grant's issuance history reports `unknown` for it, or the grant deadline D as a conservative bound.

| Event while the controller is away | What continues | What stops | Residual and evidence |
|---|---|---|---|
| Controller closes its session, sleeps or leaves the network | All approved runner work: new onward SSH for managed pairs until `valid_before`, and fixed pairs indefinitely | Nothing | [O] managed ok to +136 s, fixed through +180 s |
| A certificate reaches `valid_before` | Fixed pairs | New authentication for that managed pair: the server refuses it [O, +141 s] | None for new authentication. Live sessions follow ADR-0005 §3.6 and the G09 table |
| Grant deadline or cutoff known to the runner | Fixed pairs | Runner signer and supervisor at D on the anchored clock (ADR-0005 §3.6) | The runner may stop early, never late |
| Runner process restarts or the runner reboots | Fixed pairs (on-disk existing access) | Managed pairs: K_env is lost; `degraded`, `refresh_dependency: controller_issuer` | ADR-0005 §3.7 rows; not run here |
| Issuer or controller unreachable when renewal is due | Until `valid_before` | Re-issue: `CAPABILITY_UNAVAILABLE`, no fallback key | Disclosed in readiness before departure |
| Owner revokes a grant while the runner is unreachable | The runner, until `latest_possible_credential_expiry` | Controller-side: immediately; no new issuance | `remote_pending`. **Maximum residual = the remaining validity of the issued certificate** (≤ the grant). On reconnect: tombstones are pushed first, then acknowledged |
| Owner revokes a grant while the runner is reachable | — | Runner tombstone, K_env zeroized, owned masters closed; acknowledged | Remaining validity at destinations of a certificate already issued; only that runner held its key |
| Owner revokes a *client* (management) | Runner work | That client's next connection: tombstone plus line removal (R8) | None; local to the runner |
| Owner unenrolls the CA from a destination (emergency) | Other destinations | Every certificate from that CA on that account | Remote write through existing access (ADR-0005 §3.3) |
| Destination down | Other pairs | That pair | Not a revocation event |

## 6. How A24, A25 and the A07 runner rows will be shown

The detail is in the m06-plan exit mapping. The boundary cases of these probes fold into the three
journeys and are not rerun separately.

### A24: a paired Linux runner (the devbox) with a managed target and a fixed-auth target

1. **Prepare:** pair with the product, approve a grant, and let readiness report `offline_until` (the earliest bound, §4), `refresh_dependency` and the lifetime conditions.
2. **Controller departs:** close every controller connection, and on the macOS controller drop off the network (or stop the runtime).
3. **Continue:** the runner keeps doing new SSH work for both pairs.
4. **Interrupt the issuer and network:**
   - stop the controller's issuer;
   - block the runner from the controller.
   Work continues to the predicted bound.
5. **Expected failures:**
   - managed authentication fails at `valid_before`, and readiness had predicted it;
   - a forwarded agent is never inherited (clean launch);
   - a controller-dependent signer at an ordinary local path is reported as `unknown` provenance, with no unattended claim.
6. **Proof that no controller socket was used:** the runner's launch inventory and open sockets list nothing from the controller, and the controller host shows no connection during the window.

### A25: owner, limited consumer, expired and replayed invitation, untrusted route peer, old client

1. **A limited client is refused:**
   - `approve`, `issuer_trust` and `enroll` are refused with `role_insufficient`;
   - a shell, a PTY or forwarding is refused by sshd;
   - agent forwarding is tested with a disposable agent, against an unrestricted positive control.
2. **Activation and roles:**
   - **Limited roles** are refused on a runner without a verified sshd policy (`management_sshd_unverified`).
   - **Activation fails closed** where a confirming probe disagrees with the verified policy: a client-settable environment, or an account-level `ForceCommand`.
   - **Widening:** a paired owner client's widening request stays pending, its `Decide` is refused, and a replay after the runner-local decision returns the recorded terminal result.
3. **Invitations:**
   - a consumed invitation is refused;
   - an expired one is refused by sshd and by the table, including a session authenticated before expiry whose `join` arrives after it, and a wall-clock rollback between authentication and `join`;
   - an invitation bound to another key cannot be presented;
   - a crash between the database commit and the line rewrite recovers with the recorded result.
4. **Collisions:** two requesters using the same request ID get separate operations.
5. **The route:**
   - an Iroh peer not on the allowlist is refused;
   - a replaced endpoint key fails TLS;
   - a replaced host key fails ssh.
   None grants anything.
6. **An old client version** is refused with `SCHEMA_UNSUPPORTED`. A client missing a required capability is refused explicitly.
7. **Endpoint identity replaced:** an environment ID presented over a different pinned host key is refused, and the existing binding is not reset.

### A07 runner rows

1. Revoke while the runner is disconnected: `remote_pending`, with the per-component residuals.
2. Reconnect with uncertain time: narrowing effects still apply.
3. The runner acknowledges, and the acknowledgement names the producing controller, the effect ID and the grant generation.
4. A stale issuance cannot reactivate the grant.

## 7. Rulings (from the orchestrator, 2026-11-19; recorded in ADR-0012 §12)

- **Shell access on the runner account is owner access.**
  - **Ruling:** accepted and disclosed.
  - **Where isolation matters:** a separate account is recommended where operators must be isolated (Q3).
- **K_mgmt custody** (Q1):
  - **Store:** the verified persistent platform store.
  - **Who can hold one in V1:** desktop controllers only.
  - **Device retirement is separate from revoking a runner,** because one device key serves several runners.

## 8. Limits of this evidence

- **The probes:**
  - The bridge, the role table and the runner are shell stand-ins. They show OpenSSH and logind behaviour on Ubuntu 24.04 / OpenSSH 9.6p1, with the fixture's own sshd configuration, not Heimdall code.
  - The host readout describes the fixture host only. It does not establish product secret-store availability.
- **The issuer:** a fixture `ssh-keygen` CA on the Mac. The ADR-0005 §3.6 time exchange was not exercised.
- **Not exercised at all:**
  - the management channel itself;
  - application-level invitation consumption;
  - offline tombstone and reconnect;
  - an issuer outage;
  - old-client negotiation;
  - native management key stores;
  - the trusted time exchange;
  - production user-service behaviour.
  §1.1 lists what closes each.
- **Not run:**
  - the restart and reboot rows;
  - a host with `KillUserProcesses=yes`;
  - a host without linger.
- **The expiry reason** is inferred from timing; the sshd log line was not kept.
- **R5 did not test agent forwarding:** `IdentityAgent=none` on the client disabled the request (§1).
- **The cleanup** was observed in the session but has no standalone retained transcript:
  - exact-PID kills;
  - the scratch directory removed;
  - a final process listing that was empty.
  It also found two orphaned forwarding clients and their sshd children, caused by `$!` naming a function subshell. They were removed by exact PID, and the probe now kills the child too.
- **An OpenSSH behaviour that matters for rendering:** with OpenSSH 9.6p1, `IdentityAgent none` disables agent forwarding even when `ForwardAgent` names a socket path [O]. A rendered alias must not combine the two. This is a regression item for M06 wave W2.
