# M06 plan: connect environments without making the controller essential

**Status:** accepted, revision 3 (2026-11-20), with ADR-0012. It applies the scoped re-check (`tests/evidence/artifacts/review-m06-design/round2-recheck-codex.md`) and the orchestrator's rulings of 2026-11-20, as folded into ADR-0012 revision 3. Under ADR-0009 there is no further independent re-check: the orchestrator reviewed this revision and accepted it. Earlier history:

**Revision 2 (2026-11-19).**
- **What changed:** it applies the independent design review (M06-D-R01…R13) and the orchestrator's rulings, as folded into ADR-0012 revision 2.
- **What it waits on:**
  - one scoped re-check (the ADR-0012 §2.7 option was ruled not adopted in V1, 2026-11-20).
- **When implementation starts:** after the commit.

**Design ADR:** ADR-0012 (proposed, revision 2).
**Gate reports:** `docs/research/g06-iroh-pigeons.md` and `docs/research/g07-runner-pairing.md`. Both gates stay open and close on §3.
**Delivery rules:** ADR-0009.

**Basis and exact prerequisites (R13):**
- **The base:** `main` at `144fa477`.
- **When W0 starts:** after these merge to `main`:
  - **`origin/m03/wave6`** (`7b75c4c1`): the issuer's reserve, publish and install path (ADR-0005 §3.5), and the issue/revoke model that U3 and U4 extend;
  - **`origin/m04/w2`** (`31aadbea`): ADR-0010 §5's single-hop jump, M04-D03's two-hop substitution proof, and M04-D04's route-aware verification, which U5 extends;
  - **`origin/m05/w4`** (`50180ec2`): decision records, bindings and the attended-session machinery that the runner-local widening confirmations reuse.
- **Merged earlier:** U0 may start on a branch that merges all three.

**Inputs:**
- plan §5 M06 (T01–T06 and the exit evidence), §3 G06 and G07, §6.2 fixtures, §6.5 platform rules, §9 Iroh risk;
- spec §3, §4.2, §6.5, §7.3, §8.1, §8.6, §9.1–§9.3, §14.2 and §15.2;
- the six requirements M06 owns: R-EN-05, R-EN-08, R-SS-05, R-SS-07, R-SS-08 and R-SE-06. It also supports R-AU-08, R-SE-04 and R-DI-07.

**Exit evidence** (plan §5 M06):
- **A24, A25 and A26** pass within the declared scope.
- **A runner's onward SSH never silently uses a live socket back to the departed laptop.**
- **Remote access and owner control stay distinct.**
- **Any transport preview or deferral is documented,** not hidden.

**Declared versions:**

| Component | Version, and where it was observed |
|---|---|
| iroh | `=1.4.2`, with netdev 0.47.0 patched and rustls 0.23.46 |
| OpenSSH on macOS | 10.5p1 (the controller) |
| OpenSSH on the devbox runner | Ubuntu 24.04 9.6p1 |
| OpenSSH on Debian 13 | 10.0p2 (the container fixtures) |
| OpenSSH on Windows | The in-box 9.5p2 (ADR-0004 E6) |
| Linux arm64 | **No native host** (§7) |

## 0. Rules

1. **One contract owner.** The integrator holds ADR-0006 revision 6 (ADR-0012 §9) and merges every change to contract types. The integrator also owns:
   - the shared registrations (CLI subcommand table, capability registry, store migration list);
   - `tests/native/m06/case-index.json`.
   Units do not edit these after W0.
2. **Fixtures only:**
   - **Never** the owner's `~/.ssh`, the system sshd, or real agents or keychains as targets.
   - **The runner host's management sshd in tests** is an unprivileged fixture sshd on the devbox loopback, with a scratch `AuthorizedKeysFile`.
   - **Every fixture ssh:** `SSH_AUTH_SOCK` unset, and the AGENTS.md option set.
   - **Agent-forwarding cases** use a disposable agent, named explicitly.
3. **No public listeners:**
   - **Iroh tests** use internal Docker networks and a private `iroh-relay --dev`.
   - **The `n0-public` profile** stays outside V1 unless U56's one bounded capture row runs. That row is authorized: a container, at most 5 minutes, ephemeral keys, an allowlist and an echo target, with **no sshd and nothing that serves the host** (ADR-0012 §2.2, the ruling on Q6). The A26 `n0-public` row may follow only after it.
4. **Gates and native runs** (ADR-0009 §2.2–§2.4), for **every** wave including W0:
   - **While iterating:** focused crate tests, plus targeted platform checks (`HM_ONLY`).
   - **At each commit that goes to a branch** (ADR-0009 §2.4): `tools/validation/check.sh`, `tools/validation/linux-xcheck.sh --workspace`, and the umask-002 targets, each once.
   - **At each merge candidate:** Windows and the devbox once.
   - **macOS:** at each merge candidate that touches the controller or its key store.
   - **At M06 exit:** one combined exit suite.
5. **No blanket reruns.** The G06 cases S01–S12 and the G07 cases R1–R8 are not rerun as separate suites. Their boundary cases fold into the A24–A26 journeys (§3), and the existing host-pin, expiry and revocation checks are reused, not duplicated.

## 1. Units

### U0: Contract revision 6, migration, skeleton (the integrator, as contract owner)

- **Owns:**
  - `crates/contract/**`, `schemas/public-api/**`;
  - the store migration `000N_remote`;
  - ADR-0006 §18 (revision 6);
  - the workspace `Cargo.toml` (feature `iroh`, `[patch.crates-io] netdev`);
  - `third_party/netdev-0.47.0/**`;
  - the shared registrations.
- **Builds:**
  - ADR-0012 §9 items 1–11, applied explicitly;
  - skeleton crates `heimdall-remote` and `heimdall-transport-iroh` that fail closed, plus their crate-graph rule;
  - `cargo audit` in `check.sh` for builds with the `iroh` feature.
- **Tests:**
  - schema goldens;
  - migration up and down;
  - negotiation: `required ⊆ offer ∩ server ∩ role`, with both refusal codes;
  - `remote_client` is refused outside a runner runtime;
  - idempotency: two clients with the same `request_id` get different keys.
- **Native:** Windows and the devbox at the merge candidate (rule 4).

### U1: Roles, invitations, runner-local widening and the bridge (`heimdall-remote`; ADR-0012 §3; T01)

- **Owns:** `crates/remote/**`, `tests/model/remote_roles.rs`.
- **Depends:** U0.
- **Builds:**
  - **the bridge** (it originates the sole hello, binds the session and rejects identity frames);
  - **the effective-policy verifier** (`sshd -T -h <scratch key> -C …`, or the documented drop-in) and the `management_policy: verified | owner_only` gate for limited roles;
  - **the confirming activation probe** (ADR-0012 §3.2);
  - **the role table and permission checks**, with revocation rechecked per request and on subscriptions;
  - **the invitation state machine:**
    - the pre-dispatch rule for pending keys;
    - non-extending expiry (wall deadline plus elapsed bound from the boot anchor);
    - compare-and-set at join;
    - persist-then-rewrite, with an idempotent reconciler;
  - **runner-local widening:** remote requests create pending records only, and confirmation happens at the runner's CLI or TUI, or in an interactive ssh TTY session. There is **no `RemoteDecide`**;
  - **the management line writer**, through `crates/enroll`'s port.
- **Tests:**
  - **proptest:** no sequence of {invite, join, expire, revoke, re-invite, crash, clock rollback, reboot} reaches `active` for an expired, consumed or revoked record;
  - **one focused fault test** (R03, RC-R01):
    - a delayed `join` past expiry;
    - a **wall-clock rollback between SSH authentication and `join`**;
    - a crash between the database commit and the line rewrite;
  - **unit:** a pending key's session is refused everything except activation and `join` (`invitation_pending`); a retried `join` checks identity before it returns a recorded result;
  - **unit:** the bridge ignores `HEIMDALL_*` and `SSH_ORIGINAL_COMMAND`, and closes on a second hello or an identity frame;
  - **unit:** the verifier accepts a fixture `sshd -T` output and refuses each failing field; with no verification, a limited-role invitation gives `management_sshd_unverified`;
  - **runner-side denial test** (T-RA1–T-RA4):
    - a paired owner's widening request stays pending;
    - its `Decide` and `Attend` are refused before dispatch;
    - a viewer's request gives `role_insufficient`;
    - **terminal result replay:** after a runner-local decision, the replayed request returns the recorded result, with no new record and no re-execution;
    - **the unattended exposure-widening negative case:** a new relay set, a broader bind, or roost adoption submitted remotely stays pending (RC-R03).
- **Native:** the devbox fixture sshd.
  - **Limited roles** are enrolled only after verification.
  - **Confirming probes must fail closed** on:
    - a client-settable environment (`AcceptEnv *` in the fixture);
    - an account `ForceCommand`;
    - an alternate authentication source.
  - **Agent forwarding** is tested with a disposable agent, against an unrestricted positive control.
  These are the A25 rows.

### U2: Controller environment management (T01, T06; ADR-0012 §3, §5.2, §8)

- **Owns:**
  - `crates/app/src/remote_env*.rs`;
  - `crates/sshconf/src/mgmt*.rs` (the isolated management configuration);
  - `crates/credential` (the K_mgmt class);
  - the CLI `env` and `device` modules registered by U0.
- **Depends:** U0 and U1.
- **Builds:**
  - `env add`: bootstrap in an interactive ssh TTY session, where the runner-local confirmation happens, and pin repair through independently verified access;
  - `env invite`, `join`, `revoke-client`, `remove`, `status` and `update`. `invite` opens the runner-local confirmation;
  - `device retire`, with a local attended decision;
  - K_mgmt rotation by invite-then-revoke, with no backup;
  - the isolated `-F` configuration with every ADR-0012 §5.2 setting, at both hops.
  - The second-controller flow is **U4b** (W3), not here.
- **Tests:**
  - **golden:** the isolated configuration;
  - **regression:** a rendered alias never combines `IdentityAgent none` with `ForwardAgent <path>` (G07 §8);
  - **adapter:** bootstrap refuses an unverified host key, and no `ssh-keyscan` is ever run;
  - **unit:** K_mgmt in a locked store gives `mgmt_key_store_locked`, and runner work is unaffected;
  - **unit:** device retirement is separate from revoking one runner;
  - **unit:** the controller never sends `Decide` over a management session; a widening request returns `APPROVAL_REQUIRED` with the runner's `decision_ref`.
- **Native:**
  - **macOS:** the real Keychain item, non-synchronizable; a locked-store row under the ADR-0004 §2 idle-console rule.
  - **Windows:** the in-box OpenSSH; a DPAPI K_mgmt.
  - Both against the devbox runner.

### U3: The runner runtime (T02; ADR-0012 §4)

- **Owns:**
  - `crates/runtime/src/runner*.rs`;
  - `crates/app/src/readiness*.rs` (the runner fields, conditions, provenance);
  - `crates/issuer`: the paired-environment request path and the grant-to-issuer pin.
- **Depends:** U0 and U1, on `origin/m03/wave6`'s issuer.
- **Builds:**
  - the `remote_runner` environment;
  - issuance pinned to its issuer, with ADR-0005 §3.5 install checks;
  - the designated time source (Q-T), designated runner-locally;
  - a clean-environment launch with an inventory of runner-owned sources;
  - readiness with the earliest-bound `offline_until`, conditions and per-component residuals;
  - lifetime: a verified `systemd --user` unit, otherwise `session_scope` reporting.
- **Tests:**
  - **virtual clock:** a sample from a non-designated client is refused; a sample never extends anything; a sample cannot act as `confirm_time`; `TIME_UNCERTAIN` without a bound;
  - **unit:** the earliest of anchor, parent deadline, cutoff and `valid_before`; the authentication residual carries `destination_clock_error: unmeasured` when no measurement exists, and is never a bare D;
  - **model:** issue and revoke linearization for runner delivery;
  - **A24 row:** a controller-dependent signer behind an ordinary local path is reported as `dependency_provenance_unknown`.
- **Native:**
  - the devbox A24 rows;
  - a user-service row (linger already on there);
  - a process-restart row.
  The no-linger, `KillUserProcesses=yes` and reboot rows are `blocked` (§7).

### U4: Disconnected status, revocation and resync (T05; ADR-0012 §7)

- **Owns:** `crates/remote/src/sync*.rs`, `crates/app/src/remote_status*.rs`.
- **Depends:** U2 and U3.
- **Builds:**
  - connectivity;
  - **typed effects** keyed by (controller, effect ID, typed target, target generation):
    - `grant_revoke` becomes a durable grant tombstone, with owned dedicated sessions closed at once;
    - `policy_pause` and `policy_cutoff` become durable policy revisions;
  - acknowledgements only after the named durable record exists;
  - narrowing effects applied even with uncertain time;
  - the runner's `authority_report`;
  - **the issuer's reconciliation barrier** after reconnect: no reserve or publish until the report is read;
  - issuance, approval and admission gated until tombstones and policy revisions are reconciled;
  - `held` on an identity mismatch.
- **Tests (A07's runner rows):**
  - **model:**
    - two controllers' typed effects interleave with no collision;
    - a lost acknowledgement converges idempotently;
    - a stale issuance cannot reactivate a tombstoned grant;
    - **a pause preserves running grants;**
    - **a cutoff delivered while disconnected refuses a fresh work ID after reconnect** (RC-R04);
  - **adapter:** reconnect with uncertain time still applies tombstones and policy revisions;
  - **adapter:** the issuing controller reconnects after the other controller revoked its grant, and its issuer marks the grant revoked and counts the residual before any reserve;
  - **adapter:** a changed host key gives `held`, with no reset.
- **Native:** the devbox (A07's runner rows, A24 step 4).

### U4b: The second controller (T06; ADR-0012 §8) — W3, owner: the U4 implementer

- **Owns:** `crates/app/src/remote_env_second*.rs` and the `t06_*` cases in U7's index, registered by the integrator.
- **Depends:** U2 and U4.
- **Builds:**
  - enrolment of a second owner;
  - typed narrowing from either owner;
  - issuance only for the issuing controller's own grants;
  - a separate grant for the second controller, confirmed runner-locally after a runner-local `issuer_trust` change.
- **Tests:** the T06 set: wrong role, invitation replay, route substitution, an untrusted issuer, and renewal without an issuer.
- **Native:** the runner, macOS and Windows.

### U5a: Routes, independent of Iroh (T03; ADR-0012 §5) — W1

- **Owns:**
  - `crates/registry` (routes and host-key sets);
  - `crates/sshconf/src/routes*.rs`;
  - `crates/app/src/routes*.rs`;
  - `heimdall route connect` (the direct and jump legs).
- **Depends:** U0.
- **Builds:**
  - the ordered route model;
  - the ADR-0010 §5(b) exception, with typed inputs;
  - a jump leg that keeps ADR-0010 §5 items 1–4;
  - failover only before the forwarding boundary:
    - the server's identification string is the establishment point;
    - pre-identification lines are buffered, within 8 KiB and 32 lines;
    - the identification wait is bounded, 10 s by default;
  - **the route-health result** for every attempt;
  - **binding resolution** through `ResolveRouteBinding` on the alias's rendered endpoint;
  - `ssh -G` verification of projected aliases at both hops: effective `StrictHostKeyChecking yes`, the expected `HostKeyAlias`, catalog-only trust, and context-owned or no multiplexing (`host_pin_defeated`);
  - enrollment and verification through a jump.
- **Tests:**
  - **golden:** rendering for one route and for several;
  - **property:** failover never selects an unapproved route, and never fires after the first byte;
  - **adapter:** M04-D03's two-hop substitution test extended to helper aliases;
  - **adapter:** each `host_pin_defeated` combination is refused, **including `StrictHostKeyChecking no` with the pin file effective**, a global known-hosts source, an alias override, and a foreign `ControlPath`;
  - **adapter:** two concurrent grants: the second grant's jump pair is refused for the first grant's final pair; an ambiguous endpoint gives `route_binding_ambiguous`;
  - **adapter:** a server that sends pre-identification lines works; a server that waits for client-first identification times out at the bound and is reported `identification_timeout`; a late refusal after the forwarding boundary is terminal, recorded in `route.health`;
  - **adapter:** a jump enrollment with a changed final key is held.
- **Native:** macOS and the devbox. Windows: the helper through the in-box OpenSSH.
- **WSL regressions** for the shared rendering:
  - **Mode A:** Windows `ssh.exe` path and quoting of the helper command;
  - **Mode B:** Linux alias, projection and agent regressions.
  WSL is scoped as a **consumer** only. No management or Iroh endpoint in WSL is claimed.

### U6a: The Iroh transport (T04; ADR-0012 §1–§2) — W1

- **Owns:** `crates/transport-iroh/**`.
- **Depends:** U0.
- **Builds:**
  - `transport connect` and `serve` on `/pigeons/0`;
  - the effective exposure policy, with every address and hint built from it;
  - an allowlist checked before forwarding;
  - a loopback target whose outbound connect is **bound explicitly to `127.0.0.1` (or `::1`)**;
  - bounded close;
  - stdin that never blocks exit.
- **Tests:**
  - **unit:** a hint, address or relay outside the policy is refused;
  - **unit:** an empty allowlist is refused;
  - **unit:** a target other than loopback is refused, and the target socket binds loopback;
  - **regression:** the S03 hang (stdin), and bounded close.
- **Native:** containers only, at this stage.

### U56: Route and transport integration (the integrator) — W2

- **Owns:**
  - `crates/runtime/src/supervise_transport.rs`;
  - the Iroh leg of `route connect`;
  - `transport enable` and `disable`, and `roost adopt`;
  - K_iroh custody (platform stores; §2.7 not adopted in V1), with the K_iroh loss and recovery path;
  - **the admission authority** (ADR-0012 §2.3):
    - the serve child's generation lease;
    - suspend, close and acknowledge (or exact-PID stop) before revocation is reported applied;
    - fail-closed on lost authority;
    - closure replayed before service resumes;
  - **exposure widening** as runner-local (or controller-local) decisions bound to the exact delta. Pure preference changes need recorded consent;
  - adoption of a stock roost as a widening action, with disclosure.
- **Depends:** U5a, U6a, and U1's revocation hook and widening confirmation.
- **Tests:**
  - **adapter:** revocation reports `applied` only after the child has closed the revoked endpoint's existing Iroh connection;
  - **fault:** the runtime is killed between the tombstone commit and the child's acknowledgement. The orphan child loses its lease and exits, and after restart closure is replayed before admission;
  - **fault:** with a corrupt or unavailable authority state, the child is not started (`transport_authority_lost`);
  - **unit:** a remote or unattended request for a new relay set, a broader bind, direct fallback, public infrastructure or roost adoption stays pending (`exposure_unconsented` if executed without a decision);
  - **adapter:** with no verified store, `transport_key_store_unavailable` and a doctor finding;
  - **interop:** the product client against a stock roost, inside the container network only.
- **The `n0-public` capture row** (the ruling on Q6; the only authorized public-relay run):
  - **Where and how long:** one container, at most 5 minutes.
  - **What runs:** ephemeral K_iroh keys on both ends, an allowlist, and an **echo target**. **No sshd, and nothing that serves the host.**
  - **What is kept:** the exact traffic (destinations, ports, protocols), recorded in `tests/evidence/m06-n0-public-capture.json`.
  - **What it gates:** `n0-public` stays outside V1 unless this row runs and its disclosure text is written from it.
- **Native** (RC-R05: product persistence only with verified stores):
  - **The endpoint persistence and restart journey:**
    - **dialer:** the macOS controller (Keychain);
    - **server:** a host with a verified store, which is macOS or, on qualified paths, Windows DPAPI;
    - **the devbox:** the SSH target and the private relay host only.
  - **The devbox as an Iroh endpoint** is used **only to verify the expected no-store refusal** (`transport_key_store_unavailable`).
  - **Container runs** use a fixture store and are labelled **mechanism evidence**, never product persistence.

### U7: Exit suite and evidence (the integrator)

- **Owns:** `tests/native/m06/**`, `tests/evidence/m06-*.json`.
- **Builds:**
  - the A24, A25, A26 and A07 runner journeys of §3;
  - the fixtures of §4;
  - the combined exit suite and its records.

## 2. Waves

```text
W0  U0 contract rev 6 + migration + skeletons + vendored netdev + audit gate
W1  U1 roles/bridge/invitations/runner-local widening │ U5a routes (no Iroh) │ U6a iroh transport
W2  U2 controller env mgmt (U1) │ U3 runner runtime (U1) │ U56 route+transport integration (U5a, U6a)
W3  U4 disconnected/revocation/resync (U2, U3) │ U4b second controller + T06 set (U2, U4; owner: the U4 implementer)
W4  U7 combined exit suite, native runs, records
```

- **Ownership:** W1's units own disjoint crates. The shared files are the integrator's (rule 1).
- **The Iroh/route split:** U5a and U6a have no dependency on each other. Their integration is U56 in W2. This fixes the W1 cycle the review found.
- **Review:** each wave gets one review and one re-check. The plan §6.7 security review covers:
  - W1: pairing, roles, sshd-policy verification and runner-local widening;
  - W2: the runner's issuance, the Iroh exposure and the admission authority;
  - W3: resync races.

## 3. Exit mapping

**The records:**
- **Where they live:** `tests/evidence/m06-*.json`.
- **The lowest-row rule** applies.
- **Platform names:**
  - **"Runner"** is the devbox.
  - **"Controller"** means macOS arm64 and Windows 11.
  - **"Containers"** means Docker on the Mac (linux-arm64).

| Claim or case | Proven by | Platforms |
|---|---|---|
| **A24** (R-EN-05, R-AU-08) | `a24_runner_without_controller`: pair, approve, readiness (earliest bound, conditions, residuals); the controller leaves; new onward SSH to a managed pair and a fixed pair; the issuer is stopped and the route blocked; managed fails at the predicted bound; a forwarded agent is never inherited; a controller-dependent signer at an ordinary path is reported `unknown` | Runner + each controller |
| "No silent controller socket" | Part of A24: the launch inventory and open sockets show nothing from the controller; the controller host shows no connection during the window | Runner |
| **A25** (R-EN-08, R-SE-06) | `a25_roles_invitations_decisions`: <br>• **limited client:** widening refused (`role_insufficient`); shell, PTY and forwarding refused, with agent forwarding against a positive control <br>• **sshd policy:** limited roles only after verification (`management_sshd_unverified` otherwise); confirming probes fail closed on the three unsupported configurations <br>• **invitations:** pending keys reach only activation and `join`; expired, consumed and wrong-key refused; a delayed join refused; a wall-clock rollback between authentication and `join` refused; a crash between commit and rewrite recovers <br>• **collisions:** two clients with the same request ID stay separate <br>• **runner-local widening:** T-RA1–T-RA4, terminal result replay, and the unattended exposure-widening negative case <br>• **route and identity:** a replaced endpoint key and a replaced host key are refused with no reset <br>• **versions:** an old client gives `SCHEMA_UNSUPPORTED`; a missing required capability is refused explicitly | Runner + macOS + containers; Windows for the version and capability rows |
| "Remote access and owner control distinct" | Part of A25: K_mgmt never authenticates onward access; a limited client cannot obtain issuance; no paired remote client can widen; widening is confirmed runner-locally | Runner |
| **A26** (R-SS-05, R-SS-07, R-SS-08, R-SE-04, R-DI-07) | `a26_iroh_routes_trust`: <br>• **routes:** direct, jump and Iroh routes to one destination <br>• **Iroh paths:** direct, and relay through the private relay <br>• **serve:** restart; persistent endpoint identity <br>• **failover:** only before the identification string; a late refusal is terminal <br>• **exposure:** an unapproved hint or relay is refused; widening exposure without a local decision stays pending; revocation is reported applied only after the live Iroh connection closes; a crash mid-revocation replays closure before admission <br>• **host pins:** `host_pin_defeated` combinations refused; the helper's two-hop substitution refused; a wrong-host fixture fails on every route <br>• **removal:** leaves no key, route, allowlist entry or projection <br>• **sessions:** one killed mid-route is reported lost <br>• **the profile's own traffic capture** for the selected profiles <br>• **persistence:** the endpoint persistence and restart journey uses verified stores only (macOS Keychain dialer, and a verified-store server); the devbox is the SSH target, the relay host, and the expected no-store refusal; container fixture-store runs are mechanism evidence | macOS + runner (as SSH target, relay host and no-store refusal); containers for mechanism rows; Windows on the qualified paths |
| `n0-public` capture row (U56) | The one authorized bounded capture: a container, ≤ 5 min, ephemeral keys, an allowlist and an echo target, with no sshd; exact traffic recorded | Containers (internet) |
| A26 `n0-public` row | Only after the capture row, and only if the profile enters V1: the same journey, with the capture listing only the disclosed infrastructure | Containers (internet) |
| T06 second controller (U4b) | `t06_second_controller`: the first controller is gone; the second delivers any typed narrowing effect; issuance only for its own grants, on destinations that trust its CA; renewal without an issuer gives `CAPABILITY_UNAVAILABLE` | Runner + macOS + Windows |
| A07 runner rows | U4 model + `a07_runner_disconnected`: revoke, pause and cutoff while disconnected (typed effects; per-component residuals with the counted history); reconnect with uncertain time, where narrowing still applies; the issuer's barrier; namespaced acknowledgements; no stale reactivation; a fresh work ID refused after a reconciled cutoff | Runner |
| G07 closure rows | g07 §1.1 (A24, A25, A07 runner rows, one real incompatibility run, native K_mgmt stores, the declared runner lifecycle) | As g07 §1.1 |
| G06 closure rows and transport scope | A26 + ADR-0012 §2.6 per-path Windows outcomes + the §2.7 ruling (not adopted in V1); claims-table rows per platform | — |

## 4. Fixtures (plan §6.2)

| Fixture | What | Reset and cleanup |
|---|---|---|
| **Paired remote Linux runner** | The devbox account, with the product runtime under a scratch `HEIMDALL_HOME`. The management sshd is an unprivileged fixture sshd on loopback with a scratch `AuthorizedKeysFile`, reached through an SSH forward over the owner's transport. Limited-role verification runs `sshd -T -f <fixture config> -h <scratch key> -C …` against the fixture's own configuration. Confirming-probe failure variants are the same fixture with `AcceptEnv *`, a `ForceCommand`, or an `AuthorizedKeysCommand`. Onward destinations: a fixture sshd with B1's CA line (managed) and one with a fixed key | Scratch per run; processes killed by exact PID, **including the children of backgrounded functions**; `rm -rf` of the scratch only |
| **Limited management client** | A Linux container on the Mac running the product client with its own K_mgmt (fixture store), invited as `viewer` or `requester` | Container and image removed by name |
| **Iroh direct and relay** | Internal Docker networks with a private `iroh-relay --dev`. **When the devbox reaches the relay through an SSH local forward,** only TCP crosses it: the relay's HTTPS and WebSocket path works, and its UDP QUIC address discovery does not. Those cases are relay-only by construction. Direct-path cases use the container networks | Networks, containers and images removed by name |
| **Wrong-host fixture** | A second destination sshd presenting a different host key behind each route | With the destination |
| **Old client version** | The previous release-candidate binary, or a `testcfg` build with the protocol major decremented | Scratch |

## 5. Deferred, each with a reason

| Item | Reason |
|---|---|
| Multi-hop jump chains | No requirement needs more than one hop. It stays `route_chain_unsupported` |
| Live session migration | Not demonstrable for arbitrary SSH (spec §9.3) |
| A managed Windows remote runner | Spec §3: later |
| K_env persisted on runners | No verified headless store |
| A headless persistent Iroh endpoint | Unavailable in V1: ADR-0012 §2.7 not adopted (the rulings on Q2 and §2.7) |
| Port mapping | Exposure with no V1 need |
| Bearer pairing links and QR | Key-bound invitations need no bearer secret |
| Remote widening (`RemoteDecide`) | Withdrawn for V1: an unattended paired owner could complete it. Widening is runner-local (ADR-0012 §3.10) |
| Limited roles on runners without a verified sshd policy | Owner-only there (ADR-0012 §3.2) |
| A stock Pigeons client against Heimdall's serve | Rotating identities (the ruling on Q6) |
| A native linux-arm64 runner row | No host (§7) |
| An Iroh direct path across real NATs | Needs an authorized public UDP endpoint (§7) |

## 6. Questions for the orchestrator

ADR-0012 §12 records the rulings. **ADR-0012 §2.7** (an encrypted headless K_iroh store) was ruled not adopted in V1 (2026-11-20); it is a post-V1 candidate that needs a verified probe on a systemd ≥ 256 host and an independent review. No questions are open.

## 7. Owner inputs and handoffs

- **Windows (G06 §8):**
  - **W1's event trace** needs a capture tool install or admin rights on the PC: the owner's decision.
  - **W4, and any step that may bind a non-loopback address,** needs **the owner at the Windows console** to watch for, and decline, a firewall prompt.
  - **W3** with an IP-literal relay and **the in-box OpenSSH journey** need no owner at the console.
- **A disposable Linux lifecycle environment:** a VM or account where linger and logind settings can be changed, and which can be rebooted. It is needed for the no-linger, `KillUserProcesses=yes` and reboot rows. **Without it those rows stay `blocked`.**
- **Limited management roles on a runner** need a verified effective sshd policy (ADR-0012 §3.2).
  - **On the devbox,** unprivileged `sshd -T -h <scratch key>` works [O].
  - **Where the account's default policy fails a check,** an operator-installed drop-in is needed, which needs root: the owner's input for that host.
  - **Without it,** that runner is owner-only.
- **A native linux-arm64 host** for the arm64 runner row. Without it, `blocked`.
- **Authorization for one public UDP endpoint with an allowlist** (for example on vps1-edge) for the Iroh direct path across real NATs. Without it, deferred (§5).
- **macOS lock, logout, sleep and reboot rows** are tracked separately, only where M06 changes a claim. Logout and reboot need the operator, as in ADR-0004 §2.
