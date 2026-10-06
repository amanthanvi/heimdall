# G02 round 4 — X5: Iroh integration paths (Go vs Rust)

Task `M00-T05-r4-x5`. Run 2026-10-06 05:46–06:10 UTC on darwin-arm64 (macOS 27.0), repo
HEAD `772a6b1` (x5 files uncommitted). Frozen prototypes Go `38b6b72` / Rust `d8f0cbe` were
not edited; a copy of the Rust prototype was patched in scratch (`/tmp`) for one size probe.

**Status: `verified`** for everything the task asked to build and run. Windows execution is
`blocked` (no native Windows host); the Windows binaries were built, not run.

The X5 question was whether a single toolchain is realistic once Iroh is added. ADR-0002 §8
inferred several answers without compiling anything. This run compiled, cross-compiled and
ran them.

## 1. Findings

1. **ring and aws-lc compile under zig for every cross target.** iroh 1.3.0 was built with
   cargo-zigbuild 0.23.4 and zig 0.16.0 for x86_64-unknown-linux-musl,
   aarch64-unknown-linux-musl and x86_64-pc-windows-gnu, and natively for
   aarch64-apple-darwin. That is 4 targets × 3 crypto/feature variants = **12 builds, 12 exit
   0, 0 warnings**. ADR §8's "cross-compiling ring under zig is untested" risk is closed for
   building (`results/rust-build-matrix.tsv`).
   - aws-lc-sys 0.45.0 built with its cc builder ("Building with: CC"), not CMake.
   - On windows-x64, both ring (`pregenerated/*nasm.o`) and aws-lc-sys
     (`builder/prebuilt-nasm/*.obj`, used because `nasm` is not installed) link **prebuilt
     assembly objects shipped inside the crates**. This is a supply-chain note, not a build
     failure.
2. **The binaries ran, loopback only.**
   - Native darwin: the single-process selftest and the Go supervisor with two helpers
     both exited 0.
   - linux-arm64 in a `--network none` container (alpine 3.22): the selftest and the
     supervisor exited 0.
   - linux-x64 under Rosetta emulation (same container setup): both exited 0. This is
     emulated, not native.
   - lsof on the exact PIDs (darwin) found only one `UDP 127.0.0.1:<port>` socket per
     endpoint. There was no TCP socket, no IPv6 socket and no non-loopback address. Each
     helper also held one `rte` (PF_ROUTE) socket.
   - Relays, address lookup (discovery), portmapper and net-report probes were disabled.
     The only IP transport was `127.0.0.1:0`.
3. **Size.** Embedding iroh in the Rust prototype grows it about 6–8×. The prototype was
   built in scratch under the same conditions, with iroh's default features:

   | target | prototype d8f0cbe | + iroh 1.3.0 | delta |
   |---|---:|---:|---:|
   | darwin-arm64 | 722,144 | 4,504,064 | +3,781,920 (×6.2) |
   | linux-x64 (musl) | 879,464 | 6,836,288 | +5,956,824 (×7.8) |
   | linux-arm64 (musl) | 816,528 | 5,761,880 | +4,945,352 (×7.1) |
   | windows-x64 (gnu) | 844,288 | 5,451,776 | +4,607,488 (×6.5) |

   The frozen manifest records 718,080 for the darwin-arm64 prototype. The 4 KB difference
   comes from build.sh's remap, oso_prefix and codesign steps, which this scratch build
   omitted. The patched copy still ran `version` and the embedded selftest. The darwin build
   ran natively and the linux-arm64 build ran in a `--network none` container
   (`results/runs/linux-arm64-proto-plus-container.txt`).
4. **Standalone probe sizes in bytes** (`x5-iroh`, same release profile as the prototype,
   `results/rust-build-matrix.tsv`):

   | variant | darwin-arm64 | linux-x64 | linux-arm64 | windows-x64 |
   |---|---:|---:|---:|---:|
   | none (frame code only, no iroh/tokio) | 302,960 | 325,752 | 302,024 | 327,168 |
   | iroh-ring-min (`tls-ring` only) | 3,586,496 | 5,633,896 | 4,711,776 | 4,336,640 |
   | iroh-awslc-min (`tls-aws-lc-rs` only) | 4,043,648 | 6,326,832 | 5,218,920 | 4,648,448 |
   | iroh-default (metrics, portmapper, fast-apple-datapath, tls-ring) | 4,186,096 | 6,400,880 | 5,367,144 | 5,044,736 |

5. **Go path: it works, but the product ships two binaries built with two toolchains.**
   - Mechanism: a 226-line stdlib-only Go supervisor (CGO_ENABLED=0) starts two Rust helper
     processes. It talks to them over stdio using u32-length-prefixed frames. It asks helper
     B to send one message to helper A across the loopback iroh link, checks that A received
     it from B's endpoint ID, sends `shutdown`, and gets `bye` and exit 0 from both.
   - Supervisor death: after a SIGKILL of the supervisor (exact PID), both helpers exited
     within 1.5 s on stdin EOF (`results/runs/darwin-orphan.txt`).
   - Per-target payload for a Go product is the Go binary plus a Rust helper:
     - darwin: 5,212,000 (Go prototype manifest) + 3,586,496 (ring-min helper) =
       **8,798,496 B in two files**. Rust with iroh embedded is 4,504,064 B in one file.
     - linux-x64: 11,085,832 vs 6,836,288.
     - linux-arm64: 9,889,280 vs 5,761,880.
     - windows-x64: 9,436,672 vs 5,451,776.
     - *Inference:* a real helper carries more protocol code than this probe, so the real
       gap is at least this large.
6. **Build cost.** Wall times are noisy (host shared with other agents) and not scored.
   - Rust with iroh: 39–84 s per target, cold per-variant target dir, registry already
     downloaded. All four targets: iroh-default 228 s, ring-min 173 s, aws-lc-min 206 s.
   - Rust prototype without iroh: about 5–9 s per target.
   - Prototype + iroh: 46–52 s per target.
   - Go supervisor stub: 0–1 s per target.
   - Disk: the 16-build scratch target tree took 5.6 GB.
7. **No maintained, adoptable pure-Go iroh path was found.** One pure-Go port exists; it is
   young and experimental (§5).

## 2. What was built

### Rust embedding (`rust-embed/`)

- `Cargo.toml` pins `iroh =1.3.0` (MSRV 1.91, latest on crates.io at run time, published
  2026-09-28) and `tokio =1.53.2`.
- `Cargo.lock` has 369 resolved entries across all platforms and features. ADR §8's scratch
  resolve found 363.
- Features select the variant:
  - `iroh-default`: iroh's own default features;
  - `iroh-ring-min`: `tls-ring` only;
  - `iroh-awslc-min`: `tls-aws-lc-rs` only;
  - `--no-default-features`: no iroh. This is the size baseline, with the same frame code.
- Release profile is identical to `prototypes/rust` (`opt-level=z`, LTO, 1 CGU, strip,
  unwind).
- `src/main.rs` (275 lines) has two modes:
  - `selftest`: two endpoints in one process, one message on ALPN `heimdall/x5/0`;
  - `helper`: the stdio frame protocol documented at the top of the file.
- Every endpoint is built the same way: `Endpoint::builder(presets::Minimal)` with
  `.relay_mode(Disabled)`, `.clear_address_lookup()`, `.clear_ip_transports()`,
  `.bind_addr(127.0.0.1:0)`, `.portmapper_config(Disabled)` and
  `.net_report_config(NetReportConfig::minimal())`.
- The binary refuses non-loopback bound sockets and peer addresses.
- `build.sh` runs the 4 variants × 4 targets matrix. It uses `--remap-path-prefix`, and no
  built binary contains the builder's home path (checked by grep).

### Go supervisor (`go-helper/`)

- `main.go` is a stdlib-only supervisor (no `go.sum`; `go 1.27`).
- Each child gets an **empty environment**, so SSH_AUTH_SOCK, proxies and the rest are not
  inherited.
- Timeouts are 15 s per step and 10 s for exit. On timeout the supervisor kills only its own
  child's PID.
- `build.sh` builds all four targets with `CGO_ENABLED=0 -trimpath`. The four builds succeeded
  (`results/go-build.tsv`).
- Go's default `-buildvcs` embeds `vcs.revision` and `vcs.modified=true` in the binary. A
  release build would set `-buildvcs` deliberately.

## 3. Network and loopback verification (observed)

| run | where | exit | sockets observed |
|---|---|---|---|
| selftest, iroh-default | darwin-arm64 native | 0 | lsof -i on exact PID: 2× `IPv4 UDP 127.0.0.1:<port>`, nothing else (`runs/darwin-selftest.*`) |
| selftest, ring-min / awslc-min | darwin-arm64 native | 0 / 0 | not inspected |
| `selftest` on the no-iroh baseline | darwin-arm64 native | 64 | usage exit by design: the baseline has no network mode (`runs/darwin-selftest-none.*`) |
| Go sup + 2 helpers, iroh-default | darwin-arm64 native | 0 | supervisor: no inet sockets. Each helper: 1× `UDP 127.0.0.1:<port>` + 1 `rte` (PF_ROUTE) + pipes and kqueues (`runs/darwin-gosup.lsof`) |
| Go sup + 2 helpers, ring-min | darwin-arm64 native | 0 | same (`runs/darwin-gosup-ringmin.lsof`) |
| selftest + Go sup, iroh-default | linux-arm64, alpine:3.22, `--network none --read-only --cap-drop ALL` | 0 / 0 | `/proc/net/udp`: only `0100007F` (127.0.0.1) entries. udp6 and tcp empty. 2 socket fds per helper (`runs/linux-arm64-container.txt`) |
| same | linux-amd64 binaries under Rosetta, same container flags | 0 / 0 | same (`runs/linux-amd64-emulated-container.txt`). **Emulated, not native** |
| prototype + iroh selftest and `version` | linux-arm64 container `--network none` | 0 / 0 | not inspected (`runs/linux-arm64-proto-plus-container.txt`) |
| supervisor SIGKILL | darwin-arm64 | 137 (supervisor) | both helper PIDs gone 1.5 s later (`runs/darwin-orphan.txt`) |

The second Linux socket fd per helper was not identified. *Inferred:* it is netwatch's
netlink socket, the Linux counterpart of the darwin `rte` socket. With `--network none` it
cannot reach anything off-host.

Network use during builds was limited to crates.io (index, crate downloads and the version
API) and proxy.golang.org (go-iroh / xk6-iroh source and metadata, read only). The Go
supervisor has no dependencies. Docker images were already local; nothing was pulled.

## 4. What a Go product would need to ship Iroh

Observed in this run:

- **Two toolchains and four build tools.**
  - Go 1.27.1 for the product.
  - Rust 1.99.0 with the musl and windows-gnu targets, zig 0.16.0 and cargo-zigbuild
    0.23.4 for the helper.
  - A C toolchain for ring/blake3, plus aws-lc if chosen. On cross targets this comes from
    zig. On darwin it is Apple's `cc`.
  - The Rust prototype path already needed rustc, zig and cargo-zigbuild. Iroh adds
    C/asm compilation through the same tools, but no new toolchain.
- **Two artifacts per target.**
  - `x5-gosup` + `x5-iroh`: about 8.8–11.1 MB per target with the prototype-sized Go binary.
  - A single Rust binary with iroh embedded is about 4.5–6.8 MB.
- **Native code in the helper.** Every variant builds ring 0.17.14 (107 C/asm source
  files) and blake3 1.8.7 (24) through `cc`. The aws-lc variant replaces ring with
  aws-lc-sys 0.45.0 (1,548 files) (`results/native-code-crates.txt`).
- **Resolved dependency packages per target** (normal + build edges, excluding the root):
  - iroh-default: 242–250;
  - ring-min: 232–243;
  - aws-lc-min: 237–248;
  - no-iroh: 0 (`results/dep-census.tsv`).
  - Go supervisor: 0 modules.
- **Platform linkage.**
  - darwin: iroh adds SystemConfiguration, Security, CoreFoundation, Foundation and
    libobjc. The prototype links only libSystem and libiconv.
  - windows-gnu: imports are system DLLs plus UCRT api-sets (Windows 10+). The Go
    supervisor imports only kernel32.

*Inferred,* not exercised here:

- Two of everything per release: lockfiles, license/notice sets, SBOMs, vulnerability
  feeds, and signing/notarization operations (both executables need signing on macOS and
  Windows).
- A versioned Go↔Rust frame protocol, to survive version skew between the two binaries.
- Helper resolution from the Go binary's real directory, as K11 requires for sidecars (the
  probe takes `-helper <path>`).
- Supervision code: restart, cancellation and shutdown. G06 must test these anyway.

## 5. Pure-Go / iroh-compatible paths (sources read, nothing adopted)

- **`github.com/tmc/go-iroh`** (proxy.golang.org; latest v0.3.0, 2026-10-01; first tag
  v0.0.1, 2026-08-15; 9 tags).
  - The README calls it a "clean-room Go port targeting wire compatibility with upstream
    Rust iroh. It is not affiliated with the n0 team". It says the "Go API is not stable
    before v1".
  - It is pure Go: no `import "C"` and no `.s`/`.c` files in the v0.3.0 module zip.
  - It achieves compatibility through forks. `internal/itls/tls` is a vendored, patched
    copy of Go's `crypto/tls` that adds RFC 7250 raw public keys, which stdlib
    `crypto/tls` lacks. `internal/qng` is a fork of quic-go v0.59.1 extended with QUIC
    multipath, QAD and QNT.
  - Together the forks are about 51k non-test lines that must be re-synced by hand with Go
    and quic-go security releases.
  - Its `COMPATIBILITY.md` (its own harness, generated 2026-10-01) claims passes against
    pinned Rust iroh 1.2.0/1.3.0 peers, including rust↔go handshakes and relays. **Not
    independently verified here.**
  - Verdict: experimental, under 2 months old, a single unaffiliated project carrying
    security-critical forks. Not adoptable for Heimdall now. G06 could revisit it with a
    live interop test against this `x5-iroh` helper if a Go stack is chosen.
- **`git.coopcloud.tech/decentral1se/iroh-go`**: iroh's Go docs page points to these
  community FFI bindings over iroh-ffi. They require cgo, support only linux-musl
  x86_64/aarch64, and are labelled experimental. This matches ADR §8 (docs.iroh.computer,
  read 2026-10-06).
- **`github.com/n0-computer/iroh-ffi`** v1.1.0 (2026-07-16) is upstream's "tier 2" FFI
  repository; Go is "Community" there. Stock **quic-go** v0.63.0 alone is not
  iroh-compatible: iroh 1.3.0 requires RFC 7250 raw-public-key TLS (`iroh/src/tls.rs`) and
  enables QUIC multipath (`endpoint/quic.rs`: `max_concurrent_multipath_paths`, minimum
  enforced).

## 6. Effect on ADR-0002 (input for the re-score; not decided here)

- §8 row "Rust": the ring/zig risk is **resolved for building**. All three cross targets
  plus darwin built with ring or aws-lc. Linux binaries ran; Windows did not run.
- §8 row "Go": this run confirmed what the ADR inferred. A Go product needs a Rust helper,
  a second toolchain and a second artifact. The ring/zig build risk is the same and now
  closed for building. A pure-Go port exists but is experimental (§5).
- §7 rows "release simplicity" and "cross-platform": with Iroh, Rust ships one file per
  target, about 6–8× its current size. Go ships two files totalling about 1.6–2× the Rust
  single file. Without Iroh, nothing changes.

## 7. Limitations

- **Windows (`blocked`, missing a native Windows x64 host):** the windows-gnu `.exe` files
  (x5-iroh in four variants, x5-gosup, and the prototype with and without iroh) were built
  and their PE imports listed. None was executed.
- **linux-x64 ran only under Rosetta emulation.** Native x86_64 Linux execution was not
  done.
- **Loopback only.** No relay, holepunching, discovery, IPv6, restart or real network path
  was exercised; G06 owns those. Disabling net-report probes and portmapper is a
  configuration choice that G06 must revisit for real connectivity.
- **Helper sockets.** The darwin `rte` socket and the unidentified second Linux socket per
  helper are not network endpoints in the inet sense. They were not traced further.
- **Unobserved activity.** No packet capture was taken (no sudo). Loopback-only status
  rests on lsof and `/proc/net` socket tables, plus `--network none` on Linux. Short-lived
  sockets opened and closed between inspections would not be seen.
- **Build times** are single cold runs on a shared host and are noisy.
- **Proto+iroh sizes** come from a scratch copy built without build.sh's remap, codesign and
  `/Brepro` flags. Baselines were rebuilt under the same conditions, so the deltas are
  like-for-like.
- **cargo-zigbuild cache.** cargo-zigbuild writes compiler wrappers into
  `<home>/Library/Caches/cargo-zigbuild/0.23.4/`, outside the task scratch. This is tool
  behaviour, unchanged from the prototype builds. Build-script outputs in the scratch
  target dir also embed that cache path. The logs copied here were sanitized.
- **Third-party claims.** Statements about go-iroh, iroh-go and iroh-ffi come from their
  published sources and docs. Only module metadata and the go-iroh v0.3.0 source zip were
  inspected; none were built or run.

## 8. Reproduce

```sh
# Rust matrix (scratch outputs; needs rustc 1.99.0, zig 0.16.0, cargo-zigbuild 0.23.4)
CARGO_ZIGBUILD=/tmp/hm-r4/tools/cargo-zigbuild-0.23.4/bin/cargo-zigbuild \
  CARGO_TARGET_DIR=/tmp/hm-r4/M00-T05-r4-x5/target \
  tests/evidence/artifacts/g02-r4/x5/rust-embed/build.sh /tmp/hm-r4/M00-T05-r4-x5/out
tests/evidence/artifacts/g02-r4/x5/go-helper/build.sh /tmp/hm-r4/M00-T05-r4-x5/go-out
scripts/run-gosup-inspect.sh <gosup> <x5-iroh> <out-prefix>      # darwin, lsof on exact PIDs
scripts/orphan-check.sh <gosup> <x5-iroh> <out-prefix>           # supervisor SIGKILL
docker run --rm --network none --platform linux/arm64 --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges -v <dir-with-binaries+in-container.sh>:/x5:ro \
  alpine:3.22 /bin/sh /x5/in-container.sh
scripts/dep-census.sh; scripts/native-census.sh <scratch>; python3 -I scripts/pe_imports.py <exe>
```

The prototype + iroh patch is in `results/proto-plus/scratch-patch.diff`. It was applied to
`git archive d8f0cbe prototypes/rust` in scratch; the lock gained 296 packages and no
existing pin changed. The sizes are in `results/proto-plus/sizes.tsv`.

## 9. Files

- `rust-embed/`: `Cargo.toml`, `Cargo.lock`, `src/main.rs`, `build.sh`.
- `go-helper/`: `go.mod`, `main.go`, `build.sh`.
- `scripts/`: run, inspect and census helpers.
- `results/`:
  - `rust-build-matrix.tsv`, `go-build.tsv`, `dep-census.tsv`, `native-code-crates.txt`;
  - `logs/rust-matrix/*.log` (sanitized);
  - `runs/*` (sanitized run outputs);
  - `proto-plus/*`.
- `record.json`: evidence record (plan.md §6.6 schema).
- Binaries were not committed. Their SHA-256 values are in the TSVs, and the binaries remain
  in `/tmp/hm-r4/M00-T05-r4-x5/` until cleanup.
