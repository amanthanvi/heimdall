# G06 — Iroh/Pigeons reuse (M06 design unit)

**Status:** the integration-boundary choice is supported for implementation (embed iroh, speak the
Pigeons wire protocol, private defaults, infrastructure by explicit opt-in). **The gate stays open:**
it closes with A26 and the per-path Windows outcomes (§8). Revision 2 (2026-11-19) applies the
independent design review (M06-D-R05, R08, R10, R12) and corrects the evidence statements. · **Date:** 2026-11-19 · **Task:** M06 design unit
**Plan:** §3 G06; spec §3, §4.2, §9.1–§9.3; ADR-0004 Q-A, Q-G · **Decision record:** ADR-0012 (proposed)
**Evidence:**
- `tests/evidence/g06-iroh-ssh-linux-containers.json`
- `tests/evidence/g06-iroh-infrastructure-and-pigeons.json`
- `tests/evidence/g06-windows-bind.json` (`blocked`)
- the artifacts under `tests/evidence/artifacts/g06/`
- **Provenance:** both probe records map each row to the binary digest it ran
  (`artifacts/g06/build/digests-sizes.txt`) and give the current source hashes. The probe
  sources were uncommitted at run time.
**Probe:** `prototypes/g06-iroh-ssh/`, which is disposable and never imported by production.

Observed results are marked [O], inferences [I], and what the sources say [S].

## 1. Questions and answers

| G06 question (plan §3) | Answer |
|---|---|
| Does embedding materially simplify lifecycle and packaging compared with a supervised helper? | **Yes: embed iroh in the `heimdall` binary, and run the transport in separate process roles of that same binary** (§2). |
| What does the pinned release support? | **iroh `=1.4.2`** (tag commit `2131f266`, published 2026-11-19T00:56Z, MIT OR Apache-2.0, MSRV 1.91), with netwatch 0.20.2, netdev 0.47.0 and rustls 0.23.46. |
| Which infrastructure is used, and what permission does it need? | **None by default in Heimdall's configuration.** iroh's own defaults use n0's public relays, n0's DNS/pkarr service, port mapping and direct UDP to public addresses [O] (§4). Each piece is an explicit opt-in that Heimdall discloses (§5). |
| What are the exposure and privacy settings? | See §5 and ADR-0012 §2. |
| What is in the package inventory? | §6. |
| What does the licensing review find? | §7. All the code involved is MIT/Apache-2.0. |
| Are reachability authentication and SSH host trust kept separate? | **Yes, for those two:** endpoint admission (S03), endpoint identity (S04) and SSH host-key rejection behind an unchanged endpoint (S09). **Management authorization is outside these cases.** It is covered by the G07 mechanism probes and, for the product, by A25. |
| What happens on Windows (Q-G)? | The wildcard bind has no configuration switch. **A scoped patch removes it** on Linux [O] (§3, S08). The Windows confirmation is a task for the orchestrator (§8). |

**Embedding, in more detail:**
- **What it avoids:**
  - a second artifact for each platform;
  - a second update channel and a version-skew surface between the runtime and a helper;
  - a second supervisor protocol.
- **Why crash isolation is still there:** the transport runs in separate processes, so it does not come from the helper model.
- **Two process roles:**
  - `heimdall transport connect` is the `ProxyCommand`. Each `ssh` invocation gets one short-lived process, and ssh owns its lifetime.
  - `heimdall transport serve` is a supervised child of the runtime on a runner or destination.
- **What a crash affects:** a crash in either role affects only that role, as the S05 and S06 cases show.
- **Size:** the cost is about 3.8–6 MB per platform (X5: `tests/evidence/artifacts/g02-r4/x5/RESULTS.md` §1 item 3). This probe's linux-arm64 build is 4,921,304 B with `tls-ring` only [O].

**The pinned release, in more detail:**
- **Platforms [S21]:** the published list is macOS arm64/x86_64, Linux x86_64/aarch64/armv7 (glibc and musl), and Windows x86_64/aarch64.
- **Support policy:** neither the README nor the repository root states one; there is no `SECURITY.md` [O, via the GitHub API on 2026-11-19]. The only commitment is semver 1.x patch releases with security fixes, as in 1.4.2's notes ("Upgrade deps to get security fixes", RUSTSEC-2026-0385/0386).
- **What Heimdall supports:** only what it tests, which is §3 on linux-arm64 containers. The X5 runs cover darwin-arm64 and linux-x64 for iroh 1.3.0. Windows is §8.

## 2. Embedding versus a supervised helper (Pigeons)

**What Pigeons does** (iroh-pigeons 0.2.3 on crates.io, and the repository at commit `a94fb5f`):
- **Protocol:** ALPN `/pigeons/0`. The dialer opens one bidirectional stream, and the roost proxies raw bytes to `127.0.0.1:<ssh_port>` [O: `src/protocol.rs`].
- **Client:** `pigeons add` writes a `Host` block with `ProxyCommand pigeons fly --stdio <id>` into `~/.ssh/config`.

**What rules it out as Heimdall's helper:**

| Pigeons behaviour [O] | Conflict |
|---|---|
| Always uses `Endpoint::builder(presets::N0)`: it publishes a pkarr record to `dns.iroh.link` and resolves through n0 DNS | Spec §9.2 says passive setup must publish no discovery advertisement. R-DI-07 |
| Relays are always on: n0's dedicated set on `*.relay.iroh-svc.com`, or `--relay-url` | Infrastructure must be an opt-in with disclosure (R-SS-08) |
| No peer allowlist. Its README says "anyone holding the endpoint ID can reach your SSH port" | Exposure of sshd to every holder of the ID |
| `fly` uses a **new endpoint key on every run.** I02a was refused by the allowlist. I02b then **ran** with I02a's refused ID added (the allowlist stayed active): `fly` presented yet another ID, the two serving logs name different refused peers, and ssh ended with exit 124 at 60,086 ms. No allowlist-free attempt was made | A server cannot admit Pigeons clients by identity |
| `fly` without n0 lookup cannot reach a roost even with `--relay-url` (P02, exit 255: "All address lookup services failed") | It cannot run with n0's infrastructure switched off |
| `fly` did not exit when the server refused it; ssh waited until the harness's 60 s timeout (I02a and I02b, exit 124) | Leaves ssh hanging |
| Writes `~/.ssh/config` on `add`; `~/.ssh/pigeons_ed25519`; `/etc/pigeons/endpoint_id` when run as root (P00 `docker diff`) | Spec §10: Heimdall owns its projections and never edits the user's `~/.ssh` behind its back |
| Telemetry prompt (iroh-services) and privileged service install | The opt-in model and the no-privilege rule |

**What Heimdall does instead:**
- It **reuses the protocol, not the binary.** Heimdall speaks `/pigeons/0` byte for byte: one bidirectional stream carrying raw SSH bytes.
- The probe's client reached a stock `pigeons roost` end to end (P01, exit 0, using only a relay inside the container network). So Heimdall is not a competing transport (spec §9.2, R-SS-07), and a user's existing roost can be a Heimdall route.
- This is Q-A's "integration boundary" decision: **embed** rather than supervise, with Pigeons as the wire protocol and a reference implementation.

## 3. What was tested (ordinary OpenSSH 10.0p2 client and sshd on debian:trixie-slim, linux-arm64 containers)

**The fixture:**
- **sshd:** listens on `127.0.0.1:22` inside the server container, with a host key generated for the run and key-only authentication.
- **The client's trust:** it pins the host key under `HostKeyAlias hm-dest-1`.
- **The route:** `ProxyCommand=g06-iroh-ssh connect …`.
- **Networks:** `--internal` Docker networks, so there is no route off the Docker host.
- **Isolation:** every ssh runs with `SSH_AUTH_SOCK` unset and `IdentityAgent=none`, inside the container.

**The results** (`artifacts/g06/local/results.tsv`; exit codes are ssh's, and the times run from ssh's start):

| Case | What | Exit | Observed |
|---|---|---|---|
| S01 | Direct path, relays and lookup disabled, the client allowlisted | 0 | `ok-direct` in 84 ms; path `ip`, selected |
| S02 | Serving helper restarted with the same key file | 0 | Endpoint ID unchanged; ssh works in 88 ms (**stable endpoint ID across restart and reconnection**) |
| S03 | A client endpoint not on the allowlist | 255 | Refused in 51 ms; the server logs `refused`; sshd never sees a connection |
| S04 | Endpoint key replaced at the same address; the client dials the old ID | 255 | `invalid peer certificate: UnknownIssuer` in 58 ms. **Reachability identity is authenticated** |
| S05 | Serving helper killed mid-session (`sleep 30`) | 255 | Session lost 4.6 s after the kill. **No migration.** S05b: a new ssh after the restart is 0 |
| S06 | ProxyCommand process killed mid-session | 255 | ssh ends 125 ms after the kill (**cancellation**) |
| S07 | Unreachable address, 3 s connect timeout | 255 | The helper exits with code 3; ssh ends 4.1 s after starting (bounded) |
| S08 | strace of the wildcard bind: stock | 0 | serve 2, connect 2 (`bind 0.0.0.0:0`, `bind [::]:0`), plus `connect 10.254.254.254:1` / `fdff:…:1` |
| S08 | strace of the wildcard bind: netdev patch | 0 | serve 0, connect 0; the probe never connects; ssh still works |
| S09 | SSH host key replaced behind an unchanged endpoint ID | 255 | 63 ms. `REMOTE HOST IDENTIFICATION HAS CHANGED` / `Host key verification failed`. **SSH host trust is independent of Iroh** |
| S10 | Relay path: server and client on different internal networks, private `iroh-relay --dev` on both | 0 | Path `relay`, selected; 3.1 s to the first byte (includes the relay handshake) |
| S11 | Relay-only client, `--bind none` (no IP transport), traced | 0 | Works (129 ms). The trace (`local/cli-strace-relayonly.net.txt`) shows two IPv4 UDP sockets bound `0.0.0.0:0` whose only sends go to `127.0.0.11:53`: iroh's own resolver looking up the relay host name. The TSV's `udp_sockets=8 udp_binds=7` also count netlink sockets and are not DNS-specific |
| S12 | Relay stopped | 255 | Fails in 9.1 s. The capture shows only the relay's address (TCP 3340, UDP 7842, TCP 80) and Docker DNS; **no n0 name or address; no fallback** |

**Two probe defects, found and fixed.** Product guidance follows from both:
- **Endpoint close must be bounded.** The probe now limits it to 1 s.
- **tokio's `stdin` reader.** It blocks runtime shutdown while ssh holds the pipe open, so a refused connection held ssh until its 30 s `ConnectTimeout` (the first S03 runs).
  - **The fix:** `Runtime::shutdown_background`.
  - **Where it belongs:** the product's `transport connect` needs the same, with a regression test, which belongs to wave W3.

**The netdev patch** (`patches/netdev-0.47.0-hm-no-route-probe.patch`):
- **Size:** 7 lines, behind a cargo feature.
- **What it does:** `get_local_ipaddr()` returns `None` without creating a socket. Its callers already handle `None`.
- **Its cost:** netdev no longer marks a "default" interface, and netwatch's `my_ip` is `None`.
- **Effect seen so far:** none on direct, relay or relay-only paths (S08 patched, S10, S11 used the patched build).
- **Untested:** whether the missing default route degrades NAT traversal on real networks. That is an M06-T04 test.
- **Why it is needed:** iroh 1.4.2 calls `netmon::Monitor::new()` unconditionally (`src/socket.rs:1033`) → netwatch `interfaces::State::new()` → `netdev_impl::local_ip()` → `netdev::net::ip::get_local_ipaddr()`, so no builder setting avoids the bind [O, by reading the source].

## 4. Infrastructure inventory: iroh's defaults versus Heimdall's

**The I01 run** used the probe's `portmapper` build with iroh's n0 preset. It is disclosure evidence for that preset only. A Heimdall `n0-public` profile would differ (no portmapper), so its exact traffic must be captured before it is offered (ADR-0012 Q4).

**I01 details:**
- **Setup:** two containers on an ordinary Docker bridge with outbound internet, each with iroh's n0 defaults (`RelayMode::Default`, pkarr publish and resolve, n0 DNS lookup, portmapper on).
- **Admission:** the serving side admitted only the client's endpoint ID.
- **Result:** ssh succeeded. The first selected path was `Relay(https://use1-1.relay.n0.iroh.link./)`, 278 ms to connect [O].
- **What the packet capture shows** (`artifacts/g06/inet/*-outbound-summary.txt`; the IPs were mapped to names with `dig` on 2026-11-19):

| Destination | Protocol | Purpose |
|---|---|---|
| use1-1 / usw1-1 / euc1-1 / aps1-1 `.relay.n0.iroh.link` (87.99.151.110, 5.78.69.43, 91.99.237.97, 5.223.65.62) | TCP 443; UDP 7842; TCP 80 once | Relay connections; QUIC address discovery; captive-portal check |
| `dns.iroh.link` (49.13.207.244) | TCP 443 | pkarr publish and resolve (signed record: endpoint ID → home relay) |
| 239.255.255.250:1900 | UDP multicast | Portmapper (UPnP SSDP) on the local network |
| The peer's public IP (redacted `<owner-public-ip>`) | UDP | Hole punching. **Reveals each side's public IP to the other** [S20] |
| Pigeons' own default relays `*.relay.iroh-svc.com` (5.161.85.51, 5.78.78.66, 91.98.21.219, 5.223.60.50) | TCP 443, UDP 7842 | Seen from the client container while `pigeons fly` ran |

**What the operators can see** [S20]:
- Relay operators see the endpoint IDs, which pairs talk, when, and how much was relayed. They cannot see payloads.
- `dns.iroh.link` receives each published endpoint's ID and home relay.

**Heimdall's default** (§5) contacts none of these. S12 shows that with a private relay saved, an outage does not fall back to n0.

## 5. Exposure and privacy settings: the proposal (ADR-0012 §2, revised for M06-D-R05)

**Every endpoint, dialer and server alike, runs under one effective exposure policy** taken from
the approved route record. Everything the endpoint may contact is built from that policy alone:
its bind, its relay map, the peer relay hint, the direct addresses and its lookup. The probe took
its peer relay hint separately from its relay map; the product does not. A hint, address or
relay outside the policy, or a policy the endpoint cannot apply, fails closed
(`relay_unapproved`, `route_unapproved`, `transport_unavailable`).

| Policy element | Heimdall default | Needs its own consent | Evidence |
|---|---|---|---|
| Preset | `presets::Minimal` (crypto provider only) | — | Probe source |
| Relays (endpoint relay map **and** peer relay hints) | None | `custom` relay URLs; `n0-public` (only after its exact traffic is captured, Q4) | S10, S12, I01 |
| Address lookup and publishing | None. Addresses travel in Heimdall's own route record | Part of `n0-public` only | S01, S10 |
| Direct UDP paths | Only to the route record's addresses | **Direct fallback** to lookup-learned or hole-punched public addresses (reveals public IPs, S20) | I01 |
| Bind | Loopback, or relay-only (`--bind none`) | **A non-loopback listener;** separately, **a wildcard bind** | S01, S08, S11 |
| Port mapping (UPnP/PCP/NAT-PMP) | Feature not compiled | Not offered in V1 | I01 shows SSDP with the stock preset |
| Ancillary traffic (DNS for relay names, net report, captive-portal check) | Only toward approved relays. An IP-literal relay URL is *expected* to avoid DNS; **that control was not run** (S11 used a host name) | Part of the relay consent | S11 (host name), S12 |
| Serving allowlist | **Required and nonempty,** enforced before any byte is forwarded | — | S03 |
| Serving target | `127.0.0.1:<sshd port>` only, enforced before forwarding | — | Probe refuses a non-loopback target |

- **The allowlist follows enrollment.** Enrollment, rotation and revocation update it through the authenticated management channel. Revoking a client closes that endpoint's existing Iroh connections, not just future ones. Revocation is reported applied only after that closure (ADR-0012 §2.3, revision 3).
- **What an allowlisted peer gets:** reachability to sshd and nothing more. That is disclosed.
- **A stock `pigeons roost`** is adopted only as external infrastructure, with its broader exposure disclosed at adoption: no allowlist, and n0 publishing. Adoption is a widening action, confirmed locally (ADR-0012 §2.8).

## 6. Package inventory (the probe's lockfile, `prototypes/g06-iroh-ssh/Cargo.lock`)

- **Size:** 358 resolved packages, with iroh `=1.4.2` (`tls-ring`), tokio `=1.54.1`, rustls **0.23.46**, netwatch 0.20.2 and netdev 0.47.0 (patched).
- **`cargo audit`** (cargo-audit 0.22.1, advisory database `472a4c9a`, 1,533 advisories, 2026-11-19):
  - **0 vulnerabilities.**
  - 1 "unmaintained" warning: `chrono`, RUSTSEC-2026-0543.
- **Pigeons' lockfile** (at `a94fb5f`, 472 packages): 0 vulnerabilities, 3 unmaintained (atomic-polyfill, chrono, paste) [O: `artifacts/g06/build/cargo-audit-*.json`].
- **The progress.md rustls note:** an Iroh embedding "must pin a patched rustls".
  - 0.23.46 carries no advisory today.
  - The product pins rustls through `Cargo.lock`, and the M08 dependency gate (`cargo audit`/`cargo deny`) blocks a release on a new advisory.
- **Native code** (the X5 finding, unchanged): `ring` ships prebuilt assembly objects for windows-gnu. This is a supply-chain note for the M08 inventory.

## 7. Licensing review

- **Crates:** iroh, iroh-base, iroh-relay, netwatch and iroh-pigeons are `MIT OR Apache-2.0`; netdev is `MIT` [O: crates.io metadata].
- **The Heimdall-owned files** (the netdev patch, and a compatible `/pigeons/0` implementation of about 30 lines, which copies no Pigeons code):
  - need only the MIT notice of the patched crate in the license bundle (M08 required artifacts, plan §10.2);
  - require no source disclosure.
- **The rest of the dependency tree:** M08's `cargo deny` license allowlist covers it.
- **Status of this review:** recorded here, and not a legal opinion.

## 8. Windows (ADR-0004 Q-G): per-path outcomes (revised for M06-D-R12)

**What is established on Linux only:**
- The wildcard bind is netdev's default-route probe, and no iroh setting removes it (§3).
- The patch removes it in the traced direct fixture (S08).
- Relay mode with a host-name relay URL still opens DNS sockets on `0.0.0.0:0` (S11).

**Each Windows path is qualified on its own.** A path with no evidence gets no support label, and
the firewall is never touched. Every step stops at the first firewall prompt; the agent never
answers one. Every process is stopped by its exact PID, and the scratch directory is removed.

| Step | Path | What it must show | Owner at the console? | Outcome rule |
|---|---|---|---|---|
| **W1** | Patched build, loopback direct (`serve` on `127.0.0.1:7000`, `connect` from `127.0.0.1:0`, a fixture echo target) | A **native event trace** (ETW: `Microsoft-Windows-Kernel-Network`/WFP, or Process Monitor), not polling, showing every bind by both PIDs is `127.0.0.1` | No | Qualifies only the loopback bind behaviour |
| **W3** | Patched build, relay-only (`--bind none`) to a private TLS relay given by an **IP literal**, with relay certificate validation intact (an IP-SAN certificate from a fixture CA trusted only by the test client's configuration; never a "skip verification" switch) | No UDP socket at all; the relay's TLS validates | No (with the IP literal); yes if a host-name variant is tried | Qualifies Windows relay-only routes, or records that the path is unsupported |
| **W4** | Patched build, LAN direct (`--bind <LAN IP>:0`) | Behaviour under observer coverage | **Yes** | Qualifies Windows direct paths, or produces a **recorded transport-specific deferral** |
| **W2** (optional) | Stock build, loopback | Whether the transient wildcard bind prompts | Yes | Diagnosis only, once the shipping paths are resolved |
| **Journey** | The in-box Windows OpenSSH client through `heimdall route connect`, then Git | ssh and Git work, host pins hold | As the path requires | Required before any support label |

**The private relay for W3** runs on the devbox loopback and is reached through an SSH local forward. That forward carries only TCP: the relay's HTTPS and WebSocket path works, but its QUIC address discovery (UDP 7842) does not cross it. W3 tests relay-only, which is exactly that TCP path.

**Build:** on the Mac, `prototypes/g06-iroh-ssh/build.sh --features no-route-probe --target x86_64-pc-windows-gnu`, using the X5 zig cross-linker setup (`tests/evidence/artifacts/g02-r4/x5/RESULTS.md` §8). Copy the binary with its SHA-256 to a scratch directory on the PC.

**W1 result (reported by the orchestrator, 2026-11-19; patched build only, native rustc 1.99.1, loopback direct, a pwsh echo target):**

- **Run 1** (exe `55f32f0b…6cb9d`):
  - **Echo:** 23 bytes each way, client exit 0.
  - **Sampler:** the IP Helper tables (`GetExtendedUdpTable`/`GetExtendedTcpTable`), every 50 ms: 55 samples over 2,762 ms, longest gap 63 ms. It saw only loopback sockets.
  - **One unexplained reading:** a cmdlet cross-check once showed the server's TCP socket as `0.0.0.0:59023`. That is the same port as its outbound connect to the target, with its state not recorded.
  - **A sampler bug** meant IPv6 TCP was not covered.
- **Run 2** (W1b, exe `bbd314a3…38e`):
  - **Why the hash differs:** the exe embeds the build-root path about 442 times and the root name changed. This is unverified, because run 1's exe was deleted.
  - **Echo:** three connects, 30 bytes each, exits 0, 0, 0.
  - **Sampler:** the corrected sampler took 95 samples over 4,762 ms, longest gap 64 ms, with state and remote. UDP sockets were only `127.0.0.1`. The server's outbound TCP connects to the target went SynSent, then Established, always from `127.0.0.1`. There was no `0.0.0.0` entry in any state, no IPv6, and no TCP Listen by the probe.
- **Limits, as they are:**
  - 50 ms sampling can miss a transient socket.
  - No ETW or Process Monitor trace was possible without an install or admin rights, so W1's event-trace requirement is **not met**.
  - Firewall prompts were not observable.
  - Run 1's `0.0.0.0` reading fits an outbound socket caught before its connect completed, but that is not proven.
- **Design response:** the product binds its outbound connect to the loopback SSH target explicitly to `127.0.0.1` (or `::1`) before connecting, so no wildcard state can exist (ADR-0012 §2.3).

**Current state:** W1 has loopback sampling evidence but no event trace. W2–W4 and the journey have not run. `g06-windows-bind.json` stays `blocked`, with each missing input named.

## 9. Limits of this evidence

- **The probe stands in for the reference flow.** It is a single binary playing `heimdall transport connect|serve`. Installation, removal, supervision, policy storage and health reporting are M06-T04 work.
- **Platforms:** linux-arm64 containers only, on Docker Desktop's VM kernel.
  - linux-x64 and macOS are covered by X5 (iroh 1.3.0) only for the endpoint mechanics.
  - The pinned full ssh suite on macOS, linux-x64 and native arm64 stays unverified until those exact runs.
- **Direct paths across real NATs:** not tested. The Docker bridge is one L2 segment, and the only public-internet run (I01) used n0's relays with the stock preset. Public NAT direct stays deferred until an authorized endpoint and independent NAT paths exist.
- **Pigeons interop over n0's public relay:**
  - I02a and I02b both ran with the allowlist active, and both were refused, because `fly` rotates its identity.
  - No allowlist-free attempt was made: it would have served sshd to any holder of the endpoint ID through a public relay.
  - Proven: the probe client to a stock roost, through a private relay inside the container network (P01). The reverse direction is unsupported (ADR-0012 Q6).
- **Uninstall:** no claim.
  - The local suite's `docker diff` transcripts were not retained.
  - The retained diff (`interop/docker-diff-srv3.txt`, fixture account path redacted) is Pigeons' roost footprint, not Heimdall's.
  - Product removal is tested in A26 (M06-T04).
- **Not yet captured:** the product's default and selected-profile traffic, failures on allowed paths, restart, ordinary cancellation and clean removal. These belong to the A26 boundary test (m06-plan §3).
