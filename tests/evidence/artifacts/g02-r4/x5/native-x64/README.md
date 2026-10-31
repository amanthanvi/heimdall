# X5 native x64 runs (task `M00-T05-r5-x5`, 2026-10-31)

X5 (`../RESULTS.md`) built the iroh 1.3.0 probe `x5-iroh` and the Go supervisor `x5-gosup` for
linux-x64 and windows-x64, but ran linux-x64 only under Rosetta and never ran anything on
Windows. This run rebuilt them with X5's pinned toolchain. It then ran them natively on the
owner's PC: Windows 11 Pro x64 (build 26300) and its WSL2 Ubuntu 24.04 (x86_64, kernel
6.18.54.1-microsoft-standard-WSL2, NAT networking).

## 1. Result

| platform | selftest | supervisor + 2 helpers | supervisor death | status |
|---|---|---|---|---|
| linux-x64, WSL2 | **pass**: 14/14 exit 0 (7 per variant: 3 timed, 3 held for inspection, 1 under strace) | **pass**: 14/14 exit 0, message received from B's endpoint ID, `bye`, both helpers exit 0 | **pass**: 6/6. SIGKILL of the exact supervisor PID returned 137, and both helpers were gone 2–4 ms later | `verified` |
| windows-x64 | **not run** | **not run** with iroh helpers | **not run** with iroh helpers | `blocked` (see §2) |
| windows-x64, no-endpoint subset | load check: 9/9 exit 64 (usage) | baseline helpers: 3/3 supervisor exit 1 by design, both helpers exit 0 | baseline helpers: 3/3. After TerminateProcess the helpers exited in 2–4 ms with exit 0 | partial evidence only |

Both variants (`iroh-ring-min`, `iroh-default`) were run on Linux.

**Socket evidence, linux-x64.** These are snapshots of the exact PIDs: inodes matched against
`/proc/PID/net/*`, plus `lsof -i` and `ss -p`.
- Selftest process: 2 UDP sockets on `127.0.0.1:<port>` and 2 NETLINK_ROUTE sockets.
- Each helper: 1 UDP socket on `127.0.0.1:<port>` and 1 NETLINK_ROUTE socket.
- Supervisor: no sockets.
- No TCP, UDP6 or wildcard socket was present at inspection time.

The full-lifetime strace (§5.2) found one more socket per endpoint: a short-lived UDP socket
bound to the wildcard address.

## 2. Finding: each iroh endpoint briefly binds a wildcard UDP socket (why Windows is blocked)

The owner's rule for Windows is: confirm from the X5 source that nothing binds a non-loopback
address before running; otherwise stop and report. That confirmation failed.

**Code path.** Every `x5-iroh` endpoint starts netwatch's network monitor; there is no
relay, address-lookup, portmapper or net-report setting that skips it. The path is:
- `iroh-1.3.0/src/socket.rs:1030` calls `netmon::Monitor::new()`.
- `netwatch-0.19.3/src/netmon/actor.rs:59` calls `interfaces::State::new()`.
- `netwatch-0.19.3/src/interfaces/netdev_impl.rs:76` calls `netdev::interface::get_interfaces()`.
- From there, by platform:
  - Windows: netdev 0.45.1, `src/os/windows/interface.rs:93-97`.
  - Linux: netdev 0.46.3, `src/os/linux/interface.rs:157`.
  - darwin: netdev 0.46.3, `src/os/macos/interface.rs:63`.
- Each of these calls `netdev::net::ip::get_local_ipaddr()` (`src/net/ip.rs:7-26`, the same in
  0.45.1 and 0.46.3).
- That function does `UdpSocket::bind(<unspecified IPv4>:0)` followed by `connect()` to a fixed
  private address hard-coded in netdev, port 1. It uses the result to learn which local address
  the default route would use.
- The code sits behind netdev's `gateway` feature. netwatch enables netdev's default features,
  so `gateway` is on for both variants and both targets (`builds/reproducibility.txt` §5).
- On a network change, netwatch calls `State::new()` again (`actor.rs:140`). *Inference:* the
  bind repeats then.

**Observed on Linux** (strace of the whole run, `runs/strace-*.txt`):
- Each endpoint makes exactly one `bind(<any4>:0)` and one `connect(<netdev-probe4>:1)`.
- Nothing is sent or received on that socket. All 22–26 `sendmsg`/`recvmmsg` calls per run use
  the `127.0.0.1`-bound iroh socket and a `127.0.0.1` peer.
- The process makes no TCP calls, no `listen`, and no IPv6 sockets.
- The netdev socket is closed within the same function. Hence the `lsof`/`ss` snapshots, here
  and in X5, never show it.

**Windows decision.** Windows Defender Firewall can prompt when an unknown executable binds a
non-loopback address. Such a prompt would need the owner, so no iroh endpoint was started on
Windows. The Windows selftest, the supervisor with iroh helpers, and the supervisor-death check
with iroh helpers are **`blocked`**. They wait on an owner decision, for example one of:
1. The owner is present at the PC to watch for, and decline, any firewall prompt. The agent
   never answers a prompt.
2. The owner authorises a deviation from X5's configuration: a probe built with
   netwatch/netdev patched so that `get_local_ipaddr` is not called.
3. The owner confirms that this bind pattern (explicit wildcard bind to port 0, then an immediate
   connect) does not prompt on that PC.

It was not tested whether this bind pattern prompts on Windows. Option 1 would answer that
too, and G06 needs the answer for any product that embeds iroh.

## 3. Method

**Hosts.**
- Builds ran on the Mac (darwin-arm64), in a scratch directory outside the repository.
- Remote steps used only `ssh`/`scp -F <ssh_config> <winhost>` with SSH_AUTH_SOCK unset. They
  landed in WSL as the non-root user.
- Windows was reached only through WSL interop (`powershell.exe`), as the non-admin user. Its
  token was not elevated (`IsInRole(Administrator)=False`).
- Scratch directories were `~/hm-m00/M00-T05-r5-x5/` in WSL and
  `%LOCALAPPDATA%\hm-m00\M00-T05-r5-x5\` on Windows. Both are now removed (§9).
- Nothing touched `~/.ssh`, agents, the registry, the firewall, services, persistent
  environment variables or Docker.

**Children and identity checks.**
- On Linux, every probe process started under `env -i PATH=/usr/bin:/bin`.
- On Windows, every probe process started with an environment holding only `SystemRoot`.
- Before inspection or kill, each PID's identity was checked:
  - Linux: `/proc/PID/exe` basename plus PPid. The helpers' parent must be the supervisor; the
    supervisor's parent must be the script shell.
  - Windows: the `Process` object we created (StartTime and Path), with the helpers'
    `ParentProcessId` and names from `Win32_Process`.
- The kill went only to the exact supervisor:
  - Linux: `kill -KILL <pid>`.
  - Windows: `Process.Kill()` on our handle, which is TerminateProcess.

**Linux runs** (`scripts/linux-runs.sh`, per variant):
- 3× `selftest`, timed.
- 3× `selftest --hold-ms 2500`, inspected at 1.2 s.
- 3× `x5-gosup -helper x5-iroh`, timed.
- 3× `x5-gosup ... -hold-ms 3000`, inspecting all 3 PIDs at 1.5 s.
- 3× supervisor death: `-hold-ms 8000`, SIGKILL at 2 s, then polling both helper PIDs every
  50 ms for up to 10 s.
- Separately, `scripts/linux-strace.sh` ran one selftest and one supervisor run each under
  `strace -ff -yy -e trace=%network`. The summary is by `scripts/strace_summary.py`.

**Windows subset** (`scripts/windows-runs.ps1`). No iroh endpoint is created:
- **W1, load check.** `x5-iroh.exe` with no arguments, 3× each for ring-min, default and the
  no-iroh baseline. `main()` builds the tokio runtime and prints usage before any endpoint
  exists. mio creates its AFD socket-poll handle lazily (`mio-1.2.4/src/sys/windows/selector.rs:39-44`).
  This proves that the PE files load on Windows 11, with their UCRT imports resolved, and run.
- **W3, supervisor with baseline helpers.** `x5-gosup.exe` with two baseline (`none`)
  `x5-iroh.exe` helpers, 3×. The baseline never sends `ready`. The supervisor times out after
  15 s, sends `shutdown`, gets `bye`, and exits 1 by design. Sockets of all 3 PIDs were listed
  at about 2 s.
- **W4, supervisor death with baseline helpers.** Same setup, 3×. TerminateProcess hit the
  exact supervisor during its ready wait. Helper handles were opened beforehand, so their real
  exit codes were captured.
- What W4 shows: on Windows, the helpers notice that the supervisor is gone and exit 0 within
  milliseconds. They run the same `read_frame` code as the iroh helper. *Inferred mechanism:*
  Rust std reports ERROR_BROKEN_PIPE on the stdin pipe as EOF. Iroh's endpoint shutdown on
  Windows is not covered.

**Redaction.** All remote output passed through `scripts/redact.sh`:
- Non-loopback IPv4/IPv6 addresses become `<nonloop4>`/`<nonloop6>`; the unspecified addresses
  become `<any4>`/`<any6>`; netdev's fixed probe address becomes `<netdev-probe4>`.
- MAC addresses, the home path, the user name and the host name are replaced too.
- Only 127.0.0.1 and ::1 are kept.
- strace's decoded netlink payloads (the kernel's interface and route dumps) are counted, not
  printed.
- Raw traces stayed in WSL scratch and were deleted.

An earlier ring-min strace pass (selftest exit 0, supervisor exit 0) wrote one interleaved
trace file. Its address summary mixed in the netlink-dump addresses. It was replaced by the
`-ff` per-thread pass recorded here; its raw file was deleted with the scratch.

## 4. Builds and digests

**Toolchain.** All of it was installed into the scratch directory, and every cache was
redirected there: CARGO_HOME, RUSTUP_HOME, CARGO_ZIGBUILD_CACHE_DIR, ZIG_*_CACHE_DIR, GOPATH,
GOMODCACHE and GOCACHE. The host's own rustc 1.99.1, zig 0.17.0 and Go 1.27.3 were not used.
- **rustc 1.99.0** (b940084d7 2026-09-28): `rustup toolchain install 1.99.0 --profile minimal`,
  plus the musl and windows-gnu std.
- **zig 0.16.0**: the official `zig-aarch64-macos-0.16.0.tar.xz`. Its sha256 `b23d70de…1489`
  matched ziglang.org's `index.json`.
- **cargo-zigbuild 0.23.4**: `cargo install --locked --version 0.23.4`. The old copy under
  `prototypes/rust/target/tools` no longer exists.
- **Go 1.27.1**: `GOTOOLCHAIN=go1.27.1`, downloaded through the module proxy and checked by the
  checksum database.
- Network used during the builds: static.rust-lang.org, ziglang.org, crates.io,
  proxy.golang.org and sum.golang.org.

**Build changes.** `rust-embed/build.sh` was run from a scratch copy with only `TARGETS`
narrowed to the two x64 triples (`builds/build-sh-scratch.diff`). All builds exited 0 with 0
warnings (`builds/rust-build.tsv`, `builds/logs/`). Build times:
- ring-min: 69 s (linux), 52 s (windows).
- default: 59 s (linux), 47 s (windows).
- Rebuild of ring-min: 56 s (linux), 42 s (windows).
- no-iroh baseline: 2 s per target.

**Go supervisor.**
- The first build, from the plain scratch copy, differed from X5 only in its missing VCS stamp.
  The scratch copy is not inside a git checkout (`builds/reproducibility.txt` §4).
- It was then rebuilt in a `git clone --shared` of this repository, sparse-checked-out at X5's
  commit `772a6b1`, with the X5 `go-helper/` copied in as uncommitted files. That reproduces
  X5's `vcs.revision`, `vcs.time` and `vcs.modified=true`.
- **All four Go digests then matched X5 exactly.** The binaries run on WSL and Windows were
  these, bit-identical to X5's.

| artifact | target | X5 bytes / sha256 | this run | equal |
|---|---|---|---|---|
| x5-iroh ring-min | linux-musl | 5,633,896 / `850dec9f…` | 5,633,880 / `c8b8da35…` | no (−16 B) |
| x5-iroh ring-min | windows-gnu | 4,336,640 / `b030873d…` | 4,336,640 / `278ef7d2…` | size only |
| x5-iroh default | linux-musl | 6,400,880 / `210bebb2…` | 6,400,864 / `390f8350…` | no (−16 B) |
| x5-iroh default | windows-gnu | 5,044,736 / `69868d98…` | 5,044,736 / `76c4b11c…` | size only |
| x5-iroh none | linux-musl | 325,752 / `7d282afa…` | 325,736 / `b193f9b1…` | no (−16 B) |
| x5-iroh none | windows-gnu | 327,168 / `0be3ecb2…` | 327,168 / `dd0bb520…` | size only |
| x5-gosup | linux-amd64 | 3,367,036 / `2e3d4878…` | same | **yes** |
| x5-gosup | windows-amd64 | 3,505,664 / `84a77e87…` | same | **yes** |
| x5-gosup | darwin-arm64, linux-arm64 | `e76f5ba6…`, `b5a0edc7…` | same | **yes** |

Full digests are in `builds/digest-comparison.tsv`.

**Why the Rust digests differ.**
- **windows-gnu.** The PE `TimeDateStamp` holds the link wall-clock time, and X5's `build.sh`
  passes no `/Brepro`. Two builds made here differ in exactly those 4 bytes: zero them and the
  two binaries are byte-identical (`reproducibility.txt` §1). So X5's Windows digests cannot be
  reproduced. The sizes match exactly.
- **linux-musl.**
  - The builds made here are self-reproducible: the ring-min rebuild is identical (§3).
  - All three variants are exactly 16 bytes smaller than X5's. That includes the no-iroh
    baseline, which compiles no C crates.
  - So the difference sits in something every variant shares: zig's output, meaning its
    musl CRT and libc objects, LLD, or the `.comment` strings (`clang version 21.1.0`,
    `Linker: LLD 21.1.0`).
  - X5 used "zig 0.16.0 (already installed)" on the host. Where that copy came from was not
    recorded; Homebrew now ships 0.17.0. This run used the official ziglang.org 0.16.0 build.
  - *Inferred, not proven:* different zig 0.16.0 builds explain the 16 bytes. X5's binaries
    were deleted at X5's cleanup, so they cannot be compared.

## 5. linux-x64 results (WSL2)

### 5.1 Runs (`runs/linux-ring-min.txt`, `runs/linux-default.txt`)

| check | ring-min | default |
|---|---|---|
| selftest, no hold (exit, wall ms) | 0/0/0; 21, 18, 24 | 0/0/0; 17, 17, 17 |
| selftest `--hold-ms 2500` (exit, wall ms) | 0/0/0; 2519, 2520, 2517 | 0/0/0; 2518, 2522, 2521 |
| gosup, no hold (exit; supervisor `elapsed_ms`) | 0/0/0; 11, 12, 11 | 0/0/0; 12, 13, 12 |
| gosup `-hold-ms 3000` (exit; `elapsed_ms`) | 0/0/0; 3014, 3015, 3011 | 0/0/0; 3014, 3013, 3021 |
| every gosup run | `ok:true`, message intact, `from_matches_sender:true`, `exit_a:0`, `exit_b:0` | same |
| supervisor SIGKILL (wait status; helper A/B gone after ms) | 137; 3/3, 3/4, 2/3 | 137; 2/3, 3/4, 3/4 |
| under strace (selftest exit; gosup exit, `elapsed_ms`) | 0; 0, 145 | 0; 0, 136 |

- After the SIGKILL, the helpers' stderr (shared with the supervisor's file) held no error lines.
- Their exit codes cannot be observed on Linux once they are reparented. Only their
  disappearance was timed.

### 5.2 Sockets

All 6 held runs per variant (12 exact-PID inspections) showed the same pattern:

| process | sockets (exact PID) |
|---|---|
| selftest | UDP `127.0.0.1:<port>` ×2 (one per endpoint), NETLINK_ROUTE ×2 |
| x5-gosup | none (0 socket fds) |
| x5-iroh helper | UDP `127.0.0.1:<port>` ×1, NETLINK_ROUTE ×1 |

`ss` listed each UDP socket as `UNCONN 127.0.0.1:<port>` with peer `<any4>:*`; that peer is
`ss`'s notation for "no peer".

Whole lifetime, per endpoint (strace, `runs/strace-*.txt`, both variants identical):
- 1 UDP `bind 127.0.0.1:0`: the iroh transport. It carried all traffic, `127.0.0.1` ↔ `127.0.0.1`.
- 4 short-lived NETLINK_ROUTE sockets, which dump the kernel's interfaces and routes.
- 1 persistent NETLINK_ROUTE socket with `nl_groups=0x0405d0` (netmon change notifications).
  This is the "second Linux socket fd" that X5 §3/§7 left unidentified. Its darwin counterpart
  is the `rte` (PF_ROUTE) socket.
- 1 transient UDP socket, `bind <any4>:0` then `connect <netdev-probe4>:1`, with no data (§2).
- No TCP, no `listen`, no IPv6.

## 6. windows-x64 results (`runs/windows-subset.txt`)

| check | result |
|---|---|
| W1 `x5-iroh.exe` (no args), ring-min / default / none | exit 64 ×3 each; wall 9/9/9, 12/8/8, 5/4/4 ms; stderr = usage line |
| W3 `x5-gosup.exe` + 2 baseline helpers | exit 1 ×3 (by design: `A: timeout waiting for "ready "`), wall 15,018–15,020 ms. Every run: `exit_a:0`, `exit_b:0`, and both helper processes exit 0 |
| W4 TerminateProcess of the supervisor | identity_ok ×3; supervisor exit −1 (`Process.Kill`); helpers exited 4/4, 2/3, 3/3 ms later, **exit 0** each |
| sockets of all 18 PIDs (W3 + W4, during the run) | `Get-NetUDPEndpoint -OwningProcess` 0, `Get-NetTCPConnection -OwningProcess` 0, `netstat -ano` rows 0 |

The same queries return rows system-wide for this non-admin user: 118 UDP, 468 TCP and 527
netstat lines, counts only (`runs/windows-socket-query-control.txt`). So the zeros are not an
empty-query artefact.

None of the code paths these runs reached opens a socket:
- W1 exits before any endpoint exists.
- The baseline helper and the Go supervisor contain no networking at all.

None of the processes held a socket when inspected. Whether any prompt appeared on the desktop
was not observable from here.

## 7. Differences from X5's darwin, linux-arm64 and Rosetta runs

- **Speed.** Here, a full supervisor run (spawn, iroh handshake, message, shutdown) took
  11–13 ms natively on x86_64.
  - X5's measurements, with the hold subtracted: darwin about 17–25 ms (4017/4025 ms with a
    4000 ms hold); linux-arm64 in a container about 13 ms (2513/2500); Rosetta about 300 ms
    (2798/2500).
  - Rosetta was therefore about 25× slower than native x64.
- **Network namespace.**
  - X5's Linux runs used `--network none` (only `lo`), where the netdev `connect()` would fail
    with no route (inferred).
  - WSL2 has `eth0` with a default route, so here the `connect()` succeeded and
    `getsockname` returned the eth0 address (redacted). Still no datagram was sent.
- **Inspection.**
  - X5 read namespace-wide `/proc/net/udp` (containers) and used `lsof` (darwin), all as
    snapshots.
  - This run matched inodes per exact PID and added a full-lifetime strace. That trace is
    what revealed the transient wildcard socket.
  - Darwin runs the same netdev call (`os/macos/interface.rs:63`). *Inferred:* X5's darwin
    snapshot also missed it. Darwin was not traced.
- **Supervisor death.**
  - X5 made one check at 1.5 s on darwin. This run polled every 50 ms: 2–4 ms on Linux, and
    2–4 ms on Windows with the baseline helpers.
  - Windows also yielded the helpers' real exit codes (0).
- **Binaries.** The Go binaries are bit-identical to X5's. The Rust binaries come from the same
  source, lock and toolchain versions, but are not bit-identical (§4).

## 8. Limitations

- **Windows iroh checks are `blocked`** (§2): selftest, supervisor with iroh helpers, and death
  with iroh helpers. What ran on Windows is a load check and a baseline-helper lifecycle check.
  It does not close X5's Windows execution gap.
- **WSL2 is not bare metal.** It is a Hyper-V VM running the Microsoft WSL2 kernel, in NAT
  mode. The code ran as native x86_64 on an AMD Ryzen 9 9900X; no emulation was involved.
- **Partial visibility on Windows.** No packet capture was possible (no root or admin), and
  strace covers only network syscalls. Windows has no syscall trace without admin, so a
  transient socket there would be invisible to these listings.
- **Small samples.** The timings come from small samples on one host, which other agents were
  also using.
- **Rust digest difference.** The cause of the 16-byte linux-musl difference is inferred,
  not proven (§4).
- **Third-party code read, not audited.** The analysis of iroh, netwatch, netdev and mio read
  their published crate sources for the pinned versions. Those crates were not audited.

## 9. Commands, exit codes and cleanup

| # | where | command (abridged; scripts in `scripts/`) | exit |
|---|---|---|---|
| 1 | Mac | `curl` ziglang.org `index.json` and `zig-aarch64-macos-0.16.0.tar.xz`; `shasum -a 256 -c` | 0, 0, OK |
| 2 | Mac | `RUSTUP_HOME=<scratch> rustup toolchain install 1.99.0 --profile minimal --target x86_64-unknown-linux-musl --target x86_64-pc-windows-gnu` | 0 |
| 3 | Mac | `cargo install --locked cargo-zigbuild --version 0.23.4 --root <scratch>/tools` | 0 |
| 4 | Mac | `GOTOOLCHAIN=go1.27.1 go version` (downloads into scratch GOMODCACHE) | 0 |
| 5 | Mac | `go-helper/build.sh <scratch>/go-out` (plain copy) | 0 (4/4 builds 0) |
| 6 | Mac | `git clone --shared --no-checkout <repo>`, `git sparse-checkout set --cone tests/evidence/artifacts/g02-r4`, `git checkout 772a6b1`, then `go-helper/build.sh` | 0 (4/4 builds 0) |
| 7 | Mac | `scripts/mac-run-rust-build.sh iroh-ring-min iroh-default` | 0 (4/4 builds 0) |
| 8 | Mac | same, with a second target dir: `iroh-ring-min none` | 0 (4/4 builds 0) |
| 9 | Mac | `scripts/repro.py`, `go version -m`, `cargo tree -e features -i netdev` (`builds/reproducibility.txt`) | 0 |
| 10 | WSL | `scripts/linux-strace.sh {ring-min,default} …` | 0, 0 |
| 11 | WSL | `scripts/linux-runs.sh {ring-min,default} …` | 0, 0 |
| 12 | Windows | `powershell.exe` `Parser::ParseFile(windows-runs.ps1)` | 0 parse errors |
| 13 | Windows | `powershell.exe -NoProfile -NonInteractive -File windows-runs.ps1` (execution policy RemoteSigned, unchanged) | 0 |
| 14 | Windows | socket-query control (counts only) | 0 |
| 15 | WSL, Windows | leftover check (`pgrep -x`, `Get-Process -Name`) | 0 probe processes on either |
| 16 | WSL, Windows | `rm -rf` of both remote scratch dirs (13 MB on Windows, 28 MB in WSL) | 0, 0 |
| 17 | Mac | `chmod -R u+w` and `rm -rf` of the Mac scratch dir | 0 |

**Cleanup.**
- **Remote.** Both remote scratch directories are gone. The parent `hm-m00` directories exist
  and are empty on both sides, which is how they were found.
- **Mac scratch.** The directory was 5.4 GB before deletion: target 2.1 G, target-rebuild
  1.0 G, rustup 808 M, zig 403 M, cargo 363 M, gopath 313 M, gocache 209 M, zig-cache 83 M.
  After deletion it is gone, and `r4-scratch` is back to its pre-task 3.4 MB. Free space rose by
  5,585,152 KiB, about 5.3 GiB.
- **Mac host state.** No zig or cargo-zigbuild cache was created outside scratch. The user's
  rustup default is unchanged (`stable`).

## 10. Files

- `runs/`: `linux-{ring-min,default}.txt`, `strace-{ring-min,default}.txt`,
  `windows-subset.txt`, `windows-socket-query-control.txt` (all redacted).
- `builds/`:
  - `rust-build.tsv`, `go-build.tsv`, `digest-comparison.tsv`, `toolchain.txt`;
  - `reproducibility.txt`, `build-sh-scratch.diff`;
  - `logs/` (cargo output, home path redacted).
- `scripts/`: the scripts exactly as run, plus `mac-ssh-wrappers.txt` (host alias and config
  path redacted).
- `record-linux-x64.json`, `record-windows-x64.json`: evidence records (plan.md §6.6 schema).
