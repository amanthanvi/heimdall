# ADR-0010: Platform realization (M04)

**Status:** accepted with the §9 rulings (2026-11-15; proposed the same day) · **Date:** 2026-11-15 · **Gate:** G03 and the platform parts of G09
**Plan:** `docs/architecture/m04-plan.md` · **Affects:** R-EN-01, R-EN-02, R-EN-03, R-EN-04, R-EN-06,
R-SS-03, R-SS-06, R-SE-03, R-DI-02, R-QU-02, R-RT-07
**Builds on, unchanged:** ADR-0004 §3 (WSL, Windows stores, E6 client baseline), ADR-0005 §3.4 (certificate
extensions), ADR-0006 §2 (endpoints and peer checks), ADR-0008 D1 (custody), D9 (lock), D10 (consumer
integration). Evidence labels: **[O]** observed in the G03 runs (`docs/research/g03-windows-wsl.md` §0,
probe IDs P-…), **[I]** inference to be proved by the M04 tests named in the plan.

## 0. Rules common to every decision

1. **The environment that runs `ssh` owns the realization** (spec §8.1). A binding names one environment.
   Heimdall creates endpoints and files only in that environment, and only for that binding.
2. **Exported endpoints are signing-only.** WSL, containers and forwarded agents receive one binding's
   signing endpoint, the SSH agent protocol and its allow-list (ADR-0006 §2.6). They never receive a
   control or issuer endpoint, a private key or a personal agent.
3. **Setup is attended, previewed, reversible and never elevated** (spec §5.2, R-DI-02).
   - Each M04 setup action goes through the M02 setup confirmation. An action that adds an environment
     able to hold authority also gets a decision record.
   - Its artifacts are owned resources that uninstall removes by identity.
4. **Same-user code is not isolated** (spec §14.1, ADR-0009 §2.1). Every claim below names its mechanism
   and states what a same-user process can still do. Isolation labels stay `shared_os_user`.

## 1. Native Windows: per-user runtime, login start, pipes, no takeover (M04-T01)

**Options for starting the runtime without a command:**
- **(a) A Windows service (SCM).** Rejected. Installing it needs elevation. A service running as
  LocalSystem or a virtual account cannot unprotect the user's DPAPI CurrentUser blob (ADR-0008 D1).
  Running it as the user needs a stored password. Both widen custody.
- **(b) A Task Scheduler logon task.** Rejected for M04. Whether a standard user may create a logon
  trigger depends on version and policy [U], and the task adds a COM surface. Reopened if (c) proves
  unreliable.
- **(c) A value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.** Chosen.
- **(d) A shortcut in the Startup folder.** Equivalent to (c), but a less conventional artifact for
  the same effect.

**Decision.**
1. **The runtime:** one runtime per user, at Medium integrity. Heimdall never requests elevation, in
   setup or in routine use.
2. **The login entry:** the value `Heimdall-<installation token>` holds `"<absolute heimdall.exe>"
   service run --login`. `--login` exits 0 without side effects when another instance holds the lock.
   - The value is written only by the attended setup step.
   - It is recorded as an owned resource, compared by exact data.
   - It is removed by `service autostart disable` and by uninstall.
3. **The pipes:** unchanged from ADR-0006 §2.1 and ADR-0008 D10: per-binding pipes, a protected
   owner-only DACL, a client SID check, `PIPE_REJECT_REMOTE_CLIENTS` and the first-instance flag.
4. **No takeover:** Heimdall never does any of the following:
   - creates, serves or opens `\\.\pipe\openssh-ssh-agent` unless an adopted catalog identity names it;
   - starts, stops or reconfigures the `ssh-agent` service;
   - writes `SSH_AUTH_SOCK` into the persistent user environment (`HKCU\Environment`);
   - changes anything under `%PROGRAMDATA%\ssh`.

   Existing-access aliases keep the user's own agent (N1, g03 §3.1). N3 (serving the global pipe) stays
   rejected.
5. **Git:** Git for Windows' bundled MSYS `ssh` cannot reach named pipes in any form (P-W03 [O]). The
   M02 Git item points `core.sshCommand` at the in-box `ssh.exe`. When Git's effective client is the
   bundled one, the doctor reports `git_client_cannot_reach_pipe`, and no Git claim is made for that
   configuration.
6. **Child processes:** every child the runtime starts (the issuer child, the WSL helper of §3) inherits
   only an explicit handle list (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).
   - This closes the inheritable-handle residual (ADR-0006 §13.9).
   - It is also what makes the §3 channel private.
7. **The state directory** must have a protected owner-only DACL, checked at start. Anything else is
   refused as `state_dir_unsafe` and never repaired. This closes ADR-0006 §13.12 item 4.

**Claims:**
- no elevation at any point;
- scoped access selects the binding pipe exclusively (P-W02, P-W03 [O]; product test in the plan);
- other standard users are refused [I; B2];
- no takeover: the before/after inventory is identical.

**Non-claims:**
- administrators and SYSTEM;
- same-user processes, which can open the binding pipe.

## 2. WSL Mode A: Windows SSH authority (M04-T02)

**Decision.**
1. **The executable:** WSL consumers run the Windows in-box `ssh.exe` (ADR-0004 E6). The binding,
   endpoint and credential belong to the native Windows environment, so a distribution used only in
   Mode A has **no environment record**. It has a distribution record that holds its owned items.
2. **Setup:** opt-in per distribution, previewed and reversible. The Git item in the distribution
   user's global Git configuration sets `core.sshCommand` to the distribution-visible path of the
   in-box `ssh.exe`.
   - The §3 helper writes it inside the distribution, with M02's Git transaction.
   - It is recorded as an owned projection resource and removed by `wsl disable` and by uninstall.
   - Heimdall installs no `ssh` shim and no alias, and sets no `WSLENV`. Linux `ssh` stays Linux.
3. **Paths:** Heimdall never hands a Linux path to `ssh.exe`.
   - `ssh.exe` reads the Windows user's configuration and the Windows managed include, whose paths are
     Windows paths.
   - A Linux-path `-F` worked in P-A03 only through the inherited `\\wsl.localhost` working directory
     [O], so nothing may rely on it.
   - `scp.exe` and `sftp.exe` with Linux local paths are reported unsupported.

**Claims:** identical to §1, because the distribution adds nothing:
- argv, exit status, stdin EOF and binary bytes are preserved through interop (P-A02, P-A03 [O]);
- `ssh.exe` rereads certificate files on every run, so a re-issue needs no WSL action (P-A05 [O]);
- the interop child runs at Medium integrity (P-A06 [O]). That no UAC prompt appears needs an operator
  (B5).

**Non-claims:** every process of the same Windows user, in any distribution, can run `ssh.exe` against
the same endpoints [S16].

## 3. WSL Mode B: Linux-native scoped endpoint (M04-T03)

**Options:**
- **(a)** `socat` plus `npiperelay` to the global pipe (G03 B1). Rejected: it exposes the broad
  personal agent.
- **(b)** A Heimdall runtime inside each distribution, with its own store and keys (G03 B3). Rejected:
  it duplicates authority, and same-Windows-user processes can read distribution files and become root
  there, so custody is weaker than the Windows store.
- **(c)** A Linux listener that spawns one Windows relay per connection through interop (the P-B04
  shape). Rejected:
  - each connection spawns a Windows process (about 220 ms per listing through the PowerShell relay
    [O]);
  - the Linux side must locate and launch a Windows executable;
  - no supervisor owns the listener.
- **(d)** Loopback TCP, `/mnt/wsl` or abstract sockets. Rejected: all three are reachable from other
  distributions, and TCP from Windows (P-B08 [O]; spec §13.2).
- **(e)** A helper that the Windows runtime supervises, relaying over its own stdio. **Chosen.**

**Identity and keys:**
1. **Environment identity:** each Mode B distribution is an environment of kind `wsl_distribution`. Its
   identity is the distribution's registration GUID under `HKCU\...\Lxss`, read without changes, plus
   the Linux account chosen at enable.
   - A renamed distribution keeps its environment.
   - A re-imported or re-registered one is a new environment and inherits nothing.
2. **Keys:** K_env stays in the Windows runtime's memory (G03 B2; ADR-0008 D1 Windows column). The
   certificates and the server-side principals provide the destination scope.

**The helper and its channel:**
3. **The helper:** the Linux x86-64 build of `heimdall` (`heimdall internal wsl-helper`), shipped with
   the Windows install and run in place through interop. The Windows runtime spawns
   `wsl.exe -d <name> -u <account> --exec <helper> internal wsl-helper` with the §1 item 6 handle list.
4. **The channel** is `heimdall-wsl/1`, over the helper's stdin and stdout. stderr carries bounded
   diagnostics.
   - **The hello** negotiates the version and reports the helper's uid, account and distribution name.
     Any mismatch with the environment record ends the helper.
   - **Frames:** `Realize` and `Withdraw` (binding tag, generation, public material, deadline), and
     `Open`, `Data` and `Close` per stream.
   - **Limits:** the ADR-0006 signing limits: 64 streams per binding, 256 KiB messages, a 30 s idle
     timeout.
   - **No listener:** neither side opens one, apart from the per-binding Linux endpoint.
5. **The Linux side:**
   - **The endpoint** is `$XDG_RUNTIME_DIR/heimdall/b/<tag>/agent.sock`, or
     `~/.local/state/heimdall/run/b/<tag>/agent.sock` when that variable is unset. Each binding
     directory is 0700 and each socket 0600, created through `ManagedDir`.
   - **Admission:** a connection is admitted only when its `SO_PEERCRED` uid equals the helper's uid.
   - **Allow-list:** `ipc::signing::classify` is applied again as defense in depth.
   - **In-distribution files:** the helper writes the binding's certificate `.pub` files and the managed
     include into the distribution user's files with the existing Linux materialization and projection
     code.
6. **The Windows side** serves each stream with that binding's `ManagedSigner`, through the same
   `serve_with_limits` path as the binding pipe. Every signature therefore re-checks grant state,
   deadline, pause, cutoff, generation and time (R-SE-07).
   - The Windows side admits a stream on the strength of the parent/child pipe.
   - The Linux peer check is the endpoint's access control.
   - A Mode B binding has no Windows pipe.

**Ownership:**
7. **The Windows runtime owns** the environment, its bindings, grants, keys and signer, the helper
   (a generation-tagged `Process` resource), the desired endpoint set and the distribution's projection
   record.
8. **The helper owns nothing durable.** It removes only entries of a generation the runtime names, and
   all of its own entries when it exits.

**Lifecycle and teardown:**
9. **When the helper runs:** the helper runs while the environment has at least one active binding and
   the distribution is running. It exits when the last binding ends.
   - "Running" is read with `wsl.exe --list --running --quiet`, which starts nothing.
   - **Background repair never starts a stopped distribution.** Only an explicit `ensure` naming the
     environment may start it.
10. **The distribution stops** (`wsl --terminate`, idle shutdown, shutdown): the helper dies, and the
    runtime reports `wsl_distribution_not_running`. While bindings remain, it re-checks every 10 s with
    the same listing and respawns the helper when the distribution runs again.
11. **The runtime stops:** the helper sees EOF, removes its endpoints and exits. A stale socket on the
    non-tmpfs fallback path is removed by the next helper, but only when it is owned by the helper's uid,
    refuses connections, and sits in Heimdall's own directory (P-B05 rule).
12. **A binding ends** (expiry, release, revocation, cutoff, pause where it applies): the signer refuses
    at once, then `Withdraw` removes that endpoint and its files. A newer generation is never removed
    (R-RT-04).
13. **`wsl disable`** releases the environment's bindings, withdraws the endpoints, rolls back the
    distribution's projection and ends the helper. The environment record stays as a removed identity.
    **The distribution's GUID disappears** (unregistered): the same steps run, without the rollback.
14. **Distribution uptime:** an active Mode B binding keeps its distribution running (P-B10 [O]). This
    is disclosed in setup.

**Upstreams:**
15. **Mode B carries managed bindings only.** Existing access inside WSL uses Mode A.
    - A filtered existing-access upstream is allowed as convenience (ADR-0004 E-3), but it is not
      built in M04 (plan Q1).
    - It would move provider attribution to the relay (P-B04 [O]), and it can be verified only with
      B1 or B4.
16. **Lock:** the signer runs on Windows, so lock continuity follows the managed recipe, and lock-revokes
    uses the Windows session's lock signal (ADR-0008 D9).

**Claims:**
- the endpoint lists and signs only the binding's identities, and refuses other keys and every
  non-allow-listed message;
- new signatures stop when the binding ends;
- destination scope comes from server principals;
- a distribution without its own enabled environment and binding has no endpoint, and none is reachable
  through `/mnt/wsl`, the abstract namespace or TCP;
- other Linux users are refused by file mode and the peer check;
- other Windows users cannot enter the distribution [I; B2].

**Non-claims:**
- the distribution's root, and any process of the same Windows user (`wsl.exe -d <name>`, interop), can
  use the endpoint;
- a Linux user who can use interop can become the owner (`wsl.exe -u`);
- WSL is not a boundary from the same Windows user [S16].

## 4. The local Linux-container binding recipe (M04-T05)

**Options:**
- **(a)** Mount the user's agent socket. Rejected by spec §8.5.
- **(b)** Heimdall runs or wraps the container engine. Rejected:
  - it means parsing each engine's argv;
  - it requires engine access, which is host-root-equivalent for a rootful engine;
  - devcontainer and compose variants multiply.
- **(c)** Mount M03's per-binding directory (`b/<tag>/`). Rejected: every binding gets a new tag, so a
  running container never sees a re-issued or replacement binding.
- **(d)** One stable directory per container environment. **Chosen.**
- **(e)** An agent proxy inside the container. Rejected: it means Heimdall code inside an untrusted
  image.

**The container environment:**
1. **The record:** `container add <label>`, an attended decision, creates an environment of kind
   `container` and its directory `<runtime_dir>/c/<16 hex>/` (0700, through `ManagedDir`). The
   directory lives until `container remove`.
2. **The directory holds exactly:**
   - `agent.sock`, the signing endpoint of the environment's current binding;
   - `ssh_config`, `known_hosts` and the certificate `.pub` files for that binding's pairs, rendered
     with in-container paths under `/run/heimdall/`.

   Never a control or issuer endpoint, a private key, or the host's `SSH_AUTH_SOCK`.
3. **One active binding** per container environment. A second distinct binding is `environment_busy`,
   and an equivalent `ensure` reuses the existing one. Because the directory is stable, a replacement
   binding appears at the same in-container path.

**Mounting and admission:**
4. **The mount instruction** (the `ensure` result and `container mount-args`) has three parts:
   - a read-only bind of the directory at `/run/heimdall`;
   - `SSH_AUTH_SOCK=/run/heimdall/agent.sock`;
   - an optional `GIT_SSH_COMMAND="ssh -F /run/heimdall/ssh_config"`.

   Heimdall never invokes or contacts the engine.
5. **The UID rule:** the endpoint admits a peer only when its `SO_PEERCRED` uid, as read in the
   runtime's user namespace, equals the runtime's uid. In practice:
   - **rootful engine:** run as `--user <uid>:<gid>`;
   - **rootless engine:** container root maps to the user, and so does Podman's `--userns=keep-id`;
   - **refused:** rootful root, unmapped sub-uids, and other users [I; the plan's tests].

**Teardown and hosts:**
6. **A binding ends:** the signer refuses at once, then the socket and files of that generation are
   removed. A running container sees `ENOENT` or `ECONNREFUSED`.
   **`container remove`:** releases the binding and removes the directory through quarantine.
7. **Hosts:** a Linux-native runtime only.
   - Separately labelled `not-tested`: Docker Desktop (macOS, Windows), devcontainers, and containers
     inside a WSL distribution.
   - On headless Linux there is no product issuer store (ADR-0008 D1), so there is no managed binding to
     export there. The product recipe needs a Linux desktop host (B11).
   - The recipe's exposure properties do not depend on the store kind, so test-store runs prove them as
     mechanism evidence.

**Claims:**
- a container gets one binding's signing endpoint and public files, and nothing else;
- the endpoint lists and signs only that binding's identities;
- peers whose uid is not mapped to the owner are refused;
- new signatures stop when the binding ends;
- cleanup removes only Heimdall's own generation;
- destination scope comes from server principals.

**Non-claims:**
- this is not a sandbox (`workload_isolation: shared_os_user`);
- any same-uid host process can use the endpoint;
- anyone who can drive the container engine has host-root-equivalent power over the user's sockets;
- untested engines and variants make no claim.

## 5. Bastion routes and forwarding semantics (M04-T06)

**Options:**
- **(a)** Forward the agent to the bastion, then run `ssh` there. Rejected as a default: the bastion's
  root and processes can use the forwarded agent while the connection lasts.
- **(b)** `ProxyCommand` or a custom transport. Rejected: it executes commands, and `ProxyJump`
  suffices.
- **(c)** Multi-hop chains and alternative routes. Left to M06-T03.
- **(d)** Restricting the next hop with `permitopen` options on the bastion's registry line. A later
  candidate: the bastion's own `PermitOpen` is the operative limit, and it is reported.
- **(e)** A single-hop `ProxyJump` through a catalog destination. **Chosen.**

**The route:**
1. **The definition:** a managed destination may name one jump destination, by ID. The jump must be a
   catalog destination with one approved host key and no route of its own (`route_chain_unsupported`).
   P renders `ProxyJump <jump alias>`.
   - Each hop authenticates from the client, with that hop's own access.
   - Each hop's host key comes from the catalog, so the final host's identity is verified end to end
     (R-SS-05, R-SE-04).
2. **Access to the jump hop** is one of two kinds:
   - **a managed pair in the same grant's scope:** its certificate then carries
     `permit-port-forwarding` (ADR-0005 §3.4, now with route data), and no other pair's does;
   - **existing access:** a fixed identity, outside the grant.

   Anything else is `route_dependency_out_of_scope`. Readiness reports the route dependency, and the
   pair's lock continuity is the weaker of the two hops.

**Forwarding:**
3. **Agent forwarding is off by default.** P never renders `ForwardAgent`. A managed certificate lacks
   `permit-agent-forwarding`, so a user's own `ssh -A` on a managed alias is refused by the destination.
4. **With the grant's existing `agent-forwarding` capability:**
   - the pair's alias renders `ForwardAgent <that binding's endpoint>`, never `SSH_AUTH_SOCK` or a
     personal agent;
   - the destination's certificate carries `permit-agent-forwarding`;
   - the forwarded endpoint lists and signs only the binding's identities, until the binding ends;
   - the forwarded identity can log in only where server principals map it.
5. **Enrollment and verification through a jump route** stay `route_unsupported` in M04 and move to
   M06-T03 (plan Q2). The workaround is documented: enroll while the destination is directly reachable.

**Claims:**
- no credential reaches the bastion by default;
- a non-jump pair cannot open forwarding channels;
- forwarded use is bounded to the binding's identities, its deadline and the server principals.

**Non-claims:**
- while forwarding is on, the intermediate host's root can use the forwarded agent within those bounds;
- the bastion's forwarding reach is whatever its `sshd` allows.

## 6. Login start and restart time on Linux and macOS (M04-T04)

1. **The login entry, by host:**

   | Host | Entry | Started by |
   |---|---|---|
   | macOS | LaunchAgent `~/Library/LaunchAgents/<label>.plist`, `KeepAlive` on unsuccessful exit only | `launchctl bootstrap gui/<uid>` |
   | Linux with a user manager | systemd user unit `~/.config/systemd/user/heimdall.service` | `systemctl --user enable` |
   | Windows | §1 | — |

   Hosts without a user manager get no entry, and the runtime is reported `on_demand`. Heimdall never
   enables lingering.
   - **Same entry point everywhere:** `service run --login`, which exits 0 when another instance holds
     the lock.
   - **Same lifecycle everywhere:** an owned resource, removed by uninstall.
   - **Setup offers it** when managed credentials are configured. It is never silent.
2. **Headless Linux** is reported plainly: `issuer_store_unavailable`, `lock_signal_unavailable` and no
   boot persistence of managed credentials (ADR-0008 D1).
3. **Time after a restart** (ADR-0006 §10): a source counts as `synchronized` only when it is a
   documented, locale-independent kernel or OS interface whose behaviour native evidence has shown.
   - **Linux** uses `adjtimex` read-only, with the rule systemd uses for `NTPSynchronized` (`maxerror`
     below 16 s). The native observation confirms it against `timedatectl` [I].
   - **macOS and Windows** stay `unknown` unless the M04 probe finds such an interface. `w32tm` text is
     localized and does not qualify (plan Q4).
   - **Cost:** where the source reads `unknown`, the first issuance after each reboot waits for one
     attended time confirmation. This is disclosed.

## 7. Consequences

- **Contract:** ADR-0006 revision 5 adds environment kinds to the views, realization descriptors, route
  fields and reason codes. The deltas are additive (plan §5).
- **Claims table:** M04 rows are written only from `verified` native records. Every non-claim above is
  carried to the limitation statement (plan.md §10.2).
- **New `unsafe`:**
  - the Windows handle list and the Lxss read, in `localenv::sys`;
  - `adjtimex`, in `runtime::platform`.

  Each is added to the overview §9 inventory.

## 8. Reopen conditions

This ADR is reopened when any of these happens:
- the Run value proves unreliable at login (back to §1 option b);
- a Mode B evidence row shows exposure across distributions or users;
- a container engine reports peer credentials other than §4 item 5 says;
- a client cannot express `ProxyJump` or `ForwardAgent <path>`; that client is then labelled
  `unsupported`, and the ADR is not widened;
- the owner rules otherwise on a plan §7 question.

## 9. Orchestrator rulings (2026-11-15)

**Source:** the independent design review (Codex `gpt-6.1-sol`): `tests/evidence/artifacts/review-design/m04-design-review.md`. Verdict: revise first, with M04-D01 to D04 blocking.
- **This is the single ruling pass** (ADR-0009 §2.8).
- **Where `docs/architecture/m04-plan.md` differs from these rulings, the rulings win.** The track integrator folds them into the plan when its wave starts.
- **Joint wave 0 with M05:** item 9 governs, and replaces the plan's U0.

1. **M04-D01: one runtime manages a set of environments.** An endpoint target is not enough. The managed-environment seam is joint-wave-0 work (item 9), owned by that integrator:
   - **The set:** the runtime manages a set of environment identities (native, each enabled WSL distribution, each container binding).
   - **Each request:** a request names its target environment, which must be in the set and owned by this runtime. The authenticated controller principal stays distinct from the execution environment.
   - **Per environment:** slots and projection namespaces are separate, issuer validation checks the target environment, and recovery and cleanup run separately.
   - **Removing the existing equality checks without that replacement is not allowed.**
   - **The proof:** the real ensure → issue → bind → sign → restart path, run across two environments. An unmanaged or removed environment is refused, and one environment's cleanup leaves the other usable. These extend the existing authority tests rather than adding a parallel suite.
2. **M04-D02: the projection transaction crosses the WSL channel.**
   - **The record stays on Windows.** The helper owns nothing durable.
   - **The `heimdall-wsl/1` protocol** gets file-operation requests with durable acknowledgments of each receipt and each item commit, bounds and cancellation rules, and reconciliation after a lost reply.
   - **A stopped distribution is never started in the background.** Its cleanup is a retained, reported obligation, done at the next explicit start or `ensure`, or by an explicit authorized start (`heimdall wsl disable --start`). Ownership is never dropped, and a rollback is never claimed without being done.
   - **The proof:** one existing projection fault scenario run over the real helper channel. It is interrupted after the exchange and before the durable receipt or commit, then restarted and reconciled. A later user edit must be preserved, and only the recorded generation removed.
3. **M04-D03: host-key trust at both hops is narrowed.**
   - **The claim** (spec §8.4 and the §14.2 route row) is consistent host-key lookup at each hop under OpenSSH's user-controlled trust. The rendered aliases bind lookup consistently.
   - **What Heimdall never does:** set `StrictHostKeyChecking no` or `accept-new`, or weaken `UpdateHostKeys` or the known-hosts settings.
   - **The proof:** with the configuration the product generates, the bastion's key and the final host's key are substituted separately, plus once with an inherited `KnownHostsCommand` source. Each must fail before authenticating to the substituted hop.
   - **Deferred:** catalog-pinned host identity goes to M06-T03 (stable destination and host identity).
4. **M04-D04: verified evidence is aware of routes.**
   - **What survives:** verified-scope evidence holds through an approved single-hop route while the final host identity, the account and the CA are unchanged.
   - **What doesn't:** an unapproved, changed or dynamic route invalidates the evidence, which fails closed.
   - **`connect`:** uses the approved jump dependency inside the selected profile, or refuses with a stated limitation. It never adds scope silently.
   - **Deferred:** remote enrollment mutations through a jump go to M06-T03. The `route_unsupported` refusal stays until then.
   - **The proof**, through the product's own operations, with no pre-verified record seeded: direct enroll and verify → configure the jump → `ensure`/`inspect` requiring verified scope → `connect` through a managed bastion and an existing-access bastion. Also an unauthorized dependency, and a later change of jump or key.
5. **M04-D05:** one permitted login, an unauthorized-key and destination refusal, a refusal at the original deadline, and a working replacement generation are folded into the existing mounted container case. The UID-negative rows keep an admitted positive control. WSL and test-store results are mechanism evidence, and the native Linux product row stays blocked on B11.
6. **M04-D06: trust in the Linux clock-sync signal is gated.** The mapper is built, including its error, unit and threshold cases. Trust stays off until native negative evidence exists: synchronization absent or failed, on a disposable host, and the wrong-clock reboot (B12). Until then every platform keeps `unknown` and the attended confirmation. Owner services are never disturbed to manufacture a negative control.
7. **M04-D07:** the joint-wave-0 integrator owns:
   - the integration files the review lists (`operations.rs` authority, issuer validation and recovery; `managed/driver.rs`; `store/src/migrations.rs`; `heimdall/src/main.rs`; `localenv/src/sys/mod.rs`; `localenv/src/projection/mod.rs`; `runtime/src/managed_store.rs`; the managed slot and file sources);
   - the crate `lib.rs`, `mod.rs` and `Cargo.toml` registrations.

   Registration edits are serialized. Implementations stay in modules each track owns.
8. **M04-D08: no placeholder tests.**
   - A suite is registered when its first meaningful case lands.
   - New command and request refusals get one table-driven test.
   - A graph mutant is added only for a new forbidden rule (`app` → `wsl`).
   - The container rendering checks fold into the mounted-flow case.
   - **Kept:** the review's coverage notes, which are the positive start-up case for a freshly created protected state directory, `helper_unavailable` when no Linux-visible helper path resolves, an explicitly defined WSL user session, and Windows `ForwardAgent` to a pipe staying `unsupported`. Also the `LoopbackSshd` forwarding settings, so the positive control isn't prohibited by its fixture.
9. **Joint wave 0, shared with M05, replacing U0.** One integrator lands a single coordinated change:
   - **ADR-0006 revision 5,** with both tracks' additive deltas and ADR-0011 §10 item 1's policy-resolution change. The orchestrator owns it.
   - **Migrations:** `0007` (M04) and `0008` (M05).
   - **The two seams:** the managed-environment seam (item 1) and the policy-resolution rewrite (ADR-0011 §10 item 1).
   - **The rest:** both tracks' new crate skeletons (`crates/wsl`, `crates/project`) and the shared registrations.

   After it merges, the M04 and M05 tracks run in parallel in files each track owns.
10. **The plan's questions:**
    - **Q1:** yes. Mode B is for managed bindings only.
    - **Q2:** as item 4.
    - **Q3:** yes. ADR-0004 §3 is extended: up to two disposable distributions at once, created and unregistered by name, with Podman and Docker Engine installed only inside them.
    - **Q4:** as item 6.
    - **Q5:** as item 9.
    - **Q6:** yes. Recipe A and hardware working keys are deferred again, to be reopened only for an observed target without certificate support.

## 10. Wave 1: the integrator's decisions (2026-11-18; review fixes M04-W1-R01, R02 in items 5 and 6)

**Source:** M04 wave 1 (U1, U2, U3a/U3b, U5, U6), committed as `806ab489`. The readings below
were put to the contract owner as I-1 to I-10. **Ruled on 2026-11-18:** I-1 to I-8 and I-10
are confirmed as built. I-9 is answered: the M04 doctor finding codes become a `finding::M04`
list with a golden, an additive revision-5 delta in ADR-0006 §17 (the review-fix round).

**The provisional readings built on:**
- **I-1, the decision kind:** adding a container (or, in wave 2, a Mode B distribution) is
  decision-recorded as `AddEnvironment {environment, realization, disclosures}`.
- **I-2, removals:** `container remove` and `wsl disable` take authority away and execute for
  the owner, with no decision.
- **I-3, non-Linux hosts:** a host that is not Linux refuses `container add` as
  `driver_unavailable`.
- **I-4, I-5, routes:** the jump must be a managed-definition destination with no route of its
  own. Verified-scope evidence holds through exactly the catalog's current single-hop jump.
- **I-6, Mode A listing:** a Mode A distribution's items are recorded under a projection
  namespace that is never in the managed set. `inspect environments` lists it under that
  namespace.
- **I-7, results:** a completed environment request answers `{"environment": <EnvironmentView>}`.
- **I-8, the login entry:** it is attended but not journaled. Ownership is the byte-for-byte
  re-render of its data, so a missing journal can never make a foreign entry look owned: a crash
  during install leaves at worst an **owned** entry with no resource row, which `service
  autostart disable` and uninstall find by its data and remove.
- **I-10, container bindings:** in a container environment, a same-work `ensure` takes the stable
  directory over.

**Authority decisions:**
1. **The store admits a commit into a WSL namespace only from its own environment.** A projection
   item may be committed into a namespace other than the operation's environment only when a WSL
   distribution record of the same store holds that namespace, and the operation belongs to the
   store's own environment (`Txn::commit_projection_item`). Every other cross-environment commit
   is refused, as before.
   - **Test:** the existing store commit test was extended with the refusals.
   - **Mutation check:** dropping the own-environment condition fails it (exit 101); restored, it
     passes (exit 0).
2. **Only the owner's own request may start a stopped distribution.** A setup operation's driver
   may start a stopped distribution only while the owner's own setup request, or the attended
   approval of its `ApplyProjection` decision, leads it.
   - Restart recovery, the supervisor and the cleanup executor never start one.
   - A distribution operation they cannot reach stays unresolved: a retained obligation, driven
     again when the host is wired and at the owner's next `wsl enable` or `wsl disable` (§9
     item 2).
3. **Uninstall never starts a distribution.** A stopped Mode A distribution keeps its rollback as
   an obligation, and uninstall then stays incomplete, so the state store that holds the
   obligation is kept.
4. **What OpenSSH for Windows needs to start is filled from the OS** (the M03 exit suite's
   Windows diagnosis).
   - Every product launch of `ssh.exe` gets `ProgramData`, `ALLUSERSPROFILE`, `windir` and
     `SystemDrive`, from the known-folder APIs, but only when the child would lack them.
   - Nothing else is added, and a present value is never changed.

5. **The Windows state directory has one upgrade path** (the review-fix round, on the
   orchestrator's instruction that an upgrade is never silently refused). A state directory a
   build before M04 created has the profile's inherited list: owned by the user, not
   protected, granting only the user, `SYSTEM` and `BUILTIN\Administrators` (`Verdict::
   LegacyInherited`).
   - At the first start of an M04 build it is narrowed, once, to the protected owner-only DACL
     `D:P(A;OICI;GA;;;<user>)`. The narrowing goes through one `READ_CONTROL | WRITE_DAC`
     handle whose own descriptor must judge `LegacyInherited` again. It only removes access
     (`SYSTEM`, Administrators and the inheritance, all outside §1's claims) and keeps the
     content. Files already inside keep what they inherited, which names no other principal.
   - Every other shape stays refused as `state_dir_unsafe` and is never changed: a foreign
     owner, a deny ACE, any other principal, inherited or protected. The refusal now says how
     to fix it without losing the state, and the CLI's on-demand start names it as such
     instead of a generic start failure.
   - §1 item 7's "never repaired" is narrowed to exactly this: no widening, and no rewrite of
     a list that grants someone else.
   - **Proof:** `windows_state_dir_not_owner_only_is_refused` (Windows native: legacy narrowed
     and started twice, an inherited Everyone grant and a protected Everyone grant refused
     unchanged), and the pure table in `platform::state_dir_acl_tests`.
   - **Undo on such a directory (review finding M04-W1-R02):** the CLI's own start
     (`client::connect_as`) narrows it the same way, so `setup rollback` and `uninstall` run
     on an installation from before M04. A directory that stays refused answers
     `STATE_UNAVAILABLE`, reason `state_dir_unsafe`, with the same message as `service run`,
     instead of a reasonless `SERVICE_UNAVAILABLE`. The owner fixes the list as the message
     says, keeping the state, and runs the command again; Heimdall does not run rollback or
     uninstall around the runtime. **Proof:** `inherited_state_dir_then_setup_rollback_and_uninstall`
     (Windows native: `setup apply` and the login entry, the state directory given the
     pre-M04 inherited list, then `setup rollback` removes the managed include and
     `uninstall` the login entry).

6. **Verification never leaves the direct route; a changed final key is a host-key change
   through any route** (review finding M04-W1-R01, blocking).
   - **The defect:** the supervisor's re-verification pass and `enroll verify` compared only a
     direct evaluation. For a routed enrollment whose final host's key changed, the pass did
     nothing (the record stayed `verified`, its grants active), and `enroll verify` minted the
     verification certificates and ran a **direct** `ssh` to the approved host, around the
     approved jump.
   - **A changed final key** (`app::enrollment::host_key_changed`): a determined evaluation
     of the pair's alias that names the approved `HostName`, `Port` and `User` but not exactly
     the approved key is a host-key change **whatever the route**: direct, the catalog's
     jump, or any other. Both paths use it, so the record is `held` (`host_key_changed`) from
     the evaluation alone, with no session or certificate, and the pair's grants under its CA
     are degraded, as in the direct case. A route change alone (another `HostName`, `Port` or
     `User`) is still not one: the next remote step refuses it as `route_changed`, and the
     evidence is invalidated at once.
   - **No session outside the direct route; chosen: end `inconclusive`.** A verification's
     `ssh` pins the approved host directly. So a verification opens a session only when the
     alias evaluates direct, or, with no evaluator wired, when the catalog names no jump
     (`verification_may_connect`). Otherwise it mints nothing, opens nothing and ends
     `inconclusive`. **Not chosen:** verification through the approved hop, because §5 item 5
     and §9 item 4 keep verification through a jump `route_unsupported` until M06-T03.
     **Consequence:** a routed enrollment's evidence isn't renewed while it is routed. It
     lapses at `fresh_until`, and the workaround of §5 item 5 applies: verify while the
     destination is reached directly.
   - **The jump hop's key** (reading I-12, ruled 2026-11-18 as built): a managed jump's pair is enrolled with
     direct evidence of its own (§5 item 2). A change of its key holds **that** enrollment
     and degrades every grant whose scope holds the jump pair, which is every grant that
     reaches a final host through it. The final enrollment is not held for it: its own key is
     unchanged, so `--approve-target-change` would have nothing to approve. A jump on existing
     access has no approved key before catalog-pinned host identity (M06-T03, §9 item 3). The
     use-time rule (reading I-4) then withholds the evidence while the hop has no single key.
   - **Releasing a held routed enrollment** goes through the direct route too: remove the
     jump, `enroll verify --approve-target-change` while the destination is reached directly,
     then route it again; or `enroll remove`.
   - **Proof:** `routed_enrollment_held_on_a_changed_final_key_and_never_verified_around_its_route`
     (`e2e_enroll_m03`: no session, certificate or login, the pass holds it, the grant is
     degraded) and `a15_routed_enrollment_never_verified_around_the_jump_and_held_on_a_changed_final_key`
     (`e2e_route_m04`, the real binary: neither hop sees a login, `ex2` is held and the grant
     degraded). Both are the review's probes. **Revert proof:** with the fix reverted, both
     fail (exit 101): the first verification ran a direct session (fake ports: a host-key
     mismatch observed through a login; the real binary: `verified` through a direct login).
     Restored, both pass (exit 0). The pure rule is `enrollment::tests::route_matches_via_table`.
   - **Two route tests changed with it** (found by the devbox run). The supervisor now holds a
     routed enrollment within one pass of a final-key change, and a hold outlasts the key
     coming back.
     - `a15_proxyjump_through_managed_bastion` now expects the restored key to stay refused.
       The test waits for the `host_key_changed` hold.
     - `a15_proxyjump_substituted_host_keys_fail_before_authentication` (D03) puts its
       substitutions in the **client's** copies of the configuration and known-hosts file. The
       runtime keeps evaluating the originals, so the client's own lookup at each hop is still
       what's tested, without racing the pass. That race already existed for the jump hop's
       direct enrollment. The test also checks that nothing was held.

**Residuals (ADR-0009 §2.1; probes named):**
- **The spawn-lock window.** A concurrent std `Command::spawn` can inherit a listed spawn's
  three child-side pipe ends during one `CreateProcessW`. It stays open until the remaining
  spawn sites are converted: the owned `ssh` master and its `-O` calls, enrollment
  verification, and the CLI-side children.
  - **Probe:** `runtime_child_inherits_only_listed_handles`.
- **The sub-uid row's container user can't traverse the 0700 directory,** so the peer-uid check
  is exercised alone only by rootful root.
  - **Probe:** `a15_container_mounted_flow`'s errno record.
- **The forwarded-agent case runs only where the sshd keeps the socket outside the account's
  `~/.ssh`.** OpenSSH 10.1 and later put a forwarded agent's listener under the account's
  `~/.ssh/agent/`, and the fixture sshd runs as the owner. So `a15_forwarded_endpoint_bounded_to_binding`
  runs where the sshd uses `/tmp` (the devbox's 9.6p1), or with an explicit scratch-account
  opt-in.
- **Known gap: no per-pair route status.** A routed pair's unsatisfied route dependency shows
  only as a lost `destination_scope`, not as a status with its reason. A per-pair route-status
  field is deferred to M07-T03 (stable JSON and codes), unless an exit claim needs it first.
- **The login entry shows a console window briefly.** `service run --login` detaches from the
  console the Run value opens (`FreeConsole`), so a window may still flash at login.
