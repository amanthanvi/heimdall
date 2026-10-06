# X4 Linux: Secret Service and kernel keyring spikes (Go vs Rust)

**Task:** M00-T05-r4-x4-linux. **Date:** 2026-10-06 (UTC, container clock). **Status:** verified for the
claims below (native linux/arm64 container run); `implemented_unverified` for anything marked "not run".
Linux **arm64 only**: linux-x64 was not run (blocked on X1; no x64 execution environment used here).

## What was built

Same small CLI in both languages: `spike secret-service | keyctl | keyctl-user`. It generates a random
fixture secret, stores it, reads it back, compares (constant time), deletes it, checks it is gone, and prints one
JSON line that never contains the secret. Exit 0 only if all five steps succeed. A 20 s watchdog exits 124 if a
Secret Service prompt blocks.

- Go: `go/` (`main.go` skeleton, `backends_real.go`, `backends_stub.go` for the baseline via `-tags nobackends`).
- Rust: `rust/` (`src/main.rs` skeleton, `src/backends.rs`, baseline via `--no-default-features`), plus a second
  binary `x4spike-keyring` through the keyring 4.x facade (Secret Service only).
- Runtime: `Dockerfile.run` (debian bookworm-slim pinned by digest, `dbus`, `gnome-keyring` 42.1; image built with
  network, **every run uses `--network none`**, `--cap-drop ALL`, `--security-opt no-new-privileges`, uid 1000,
  private session bus from `dbus-run-session`, `SSH_AUTH_SOCK` unset, fixture keyring password `x4fixture`).
- Drivers: `run-matrix.sh` (host), `run-in-container.sh`, `inner.sh` (in container), `build-rust.sh`,
  `build-go.sh`, `metrics-go.sh`, `metrics-rust.sh`.
- Raw run output: `run-A-default-seccomp.txt`, `run-B-seccomp-unconfined.txt`, `run-C-no-provider.txt`,
  `run-D-no-bus.txt`, `metrics-go.txt`, `metrics-rust.txt`.

Toolchains: Go 1.27.1 (host darwin/arm64 cross-compile and `golang:1.27.1-bookworm` linux/arm64), Rust 1.98.1
(`rust:1.98.1-bookworm` linux/arm64; host has 1.99.0, not used for the artifacts), Docker 29.8.1, container kernel
`7.0.14-linuxkit` (Docker Desktop VM).

## Libraries

| | Go | Rust |
|---|---|---|
| Secret Service | `github.com/zalando/go-keyring` v0.2.8 over `github.com/godbus/dbus/v5` v5.2.2 (pure Go) | `secret-service` 5.2.0 (blocking API, `rt-async-io-crypto-rust`) over `zbus` 5.19.0, RustCrypto AES/HKDF/SHA2 |
| Kernel keyring | `golang.org/x/sys/unix` v0.48.0 (`AddKey`, `KeyctlSearch`, `KeyctlBuffer`, `KeyctlInt`); no keyctl wrapper library used | `linux-keyutils` 0.2.5 (safe API over raw syscalls, depends on `libc`) |
| All-in-one facade | not evaluated (`99designs/keyring`, `gsterjov/go-libsecret` not built) | `keyring` 4.2.0 `v1` facade: Secret Service only on Linux (zbus store). It has no kernel-keyring path; that needs `keyring-core` plus `linux-keyutils-keyring-store` directly (not run) |

## Results (go | rust)

All numbers are observed from the files named; inference is marked.

| Item | Go | Rust |
|---|---|---|
| Secret Service store/read/match/delete/gone, run A (Docker default seccomp) | exit 0, all ok | exit 0, all ok (gnu and musl builds, and keyring facade gnu and musl) |
| Kernel keyring `keyctl-session`, run A (default seccomp) | exit 1, `operation not permitted` at store | exit 1, `PermissionDenied` at store (gnu and musl) |
| Kernel keyring `keyctl-user`, run A (default seccomp) | exit 1, same | exit 1, same |
| Kernel keyring both scopes, run B (`seccomp=unconfined`) | exit 0, all ok | exit 0, all ok (gnu and musl) |
| Secret Service, run C (bus up, no initialised keyring) | exit 1, `failed to unlock correct collection '/org/freedesktop/secrets/aliases/default'` | exit 1, `SS error: result not returned from SS API` (facade: `Couldn't access platform storage: ...`) |
| Secret Service, run D (no session bus) | exit 1, `exec: "dbus-launch": executable file not found in $PATH` | exit 1, `zbus error: Failed to connect to address unix:path=/run/user/1000/bus: No such file or directory` (facade: `No default store has been set`) |
| Library surface that needs C / cgo | None. `CgoFiles` is 0 for every non-std package. **But** std `net` and `os/user` (pulled in by godbus) switch to cgo when `CGO_ENABLED=1` | None. No `cc`, `pkg-config`, `bindgen`, `openssl-sys` or `libdbus-sys` in the graph (the keyring facade's `dbus-secret-service` store, which would pull libdbus, is not enabled) |
| Default build on Linux with gcc present | `go build` (CGO_ENABLED=1 by default) produced a **dynamically linked** binary (`ldd` first line lists `linux-vdso.so.1`, i.e. a dynamic executable); size 3,735,815 | gnu target: dynamically linked (glibc). musl target: static |
| Fully static build | `CGO_ENABLED=0` (or `-tags netgo,osusergo`): `ldd` says "not a dynamic executable"; the binary ran in the container | `aarch64-unknown-linux-musl`: `ldd` says "not a dynamic executable"; ran in the container, all runs above |
| `unsafe` in our own source | 0 lines | 0 lines |
| `unsafe` in dependencies (crude, not comparable across languages) | compiled files only: godbus 2 lines, x/sys/unix 543 lines in 22 files, go-keyring 0 (`metrics-go.txt`) | grep over every crate linked into the binary: 10,833 `unsafe` lines in 80 crates, dominated by `linux-raw-sys` (6,931, generated bindings), `rustix` 1,588, `libc` 800, `hashbrown` 450; `linux-keyutils` 10, `secret-service` 0, `zbus` 54 (`metrics-rust.txt`). cfg is not applied, so this overstates what is compiled |
| Where the kernel-keyring FFI lives | inside `x/sys/unix` (hand-written syscall wrappers using `unsafe.Pointer`) | inside `linux-keyutils` (10 `unsafe` lines, calls `libc::syscall`) |
| Secret Service transport encryption | `go-keyring` opens the session with algorithm `plain` (source: `secret_service.go` `OpenSession`). The secret crosses the session-bus socket unencrypted; a DH session would need our own godbus code | `EncryptionType::Dh` selected explicitly, works with the pure-Rust crypto feature |
| Secret handling in the API | `Set(string)` / `Get() string`: Go strings are immutable and cannot be zeroed | `create_item(&[u8])`, `get_secret() -> Vec<u8>`: can be zeroized (not done in the spike) |
| Binary size, baseline skeleton (no backends) | 2,687,136 B | gnu 332,496 B; musl 397,456 B |
| Binary size, spike with both backends | 3,735,712 B (static) | gnu 1,513,552 B; musl 1,578,520 B |
| **Size delta from the backends** | **+1,048,576 B** | **+1,181,056 B (gnu), +1,181,064 B (musl)** |
| Binary size, keyring facade variant | n/a | gnu 1,579,216 B; musl 1,644,184 B |
| LOC (`wc -l`) | `main.go` 94 + `backends_real.go` 109 + `backends_stub.go` 6 = 209; `go.mod` 13 | `main.rs` 103 + `backends.rs` 124 = 227; `main_keyring.rs` 40; `Cargo.toml` 36 (the Rust skeleton hand-writes JSON and a urandom reader, so skeleton LOC is not comparable; backend-only LOC 109 vs 124) |
| Dependencies | 3 direct-or-needed modules for linux (`go-keyring`, `godbus`, `x/sys`); `go.mod` also lists `wincred` (Windows-only, not linked); `go.sum` 18 lines | 2 direct crates; 80 crates linked into the binary, 98 including proc-macro/build-time, 130 `[[package]]` entries in `Cargo.lock` (all features, all targets, incl. the facade) |
| Cold build time (observed) | 1.7 s in `golang:1.27.1` (empty GOCACHE, modules cached); 2.15 s host cross-compile | 21.1 s gnu in `rust:1.98.1` (empty target dir, registry cached, `--offline`); first online gnu+facade build 22.8 s |
| Build steps | 1: `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w'` from the macOS host; no extra target install | gnu: `cargo build --locked --release --target aarch64-unknown-linux-gnu` in a Linux container. musl: `rustup target add aarch64-unknown-linux-musl` first, then the same cargo command; it linked using the container's `cc` (gcc) as the driver, no C was compiled. Cross-building from macOS was **not run** (host has the musl target and `zig`, untested) |
| Reproducibility | not measured here (X3) | not measured here (X3) |

## Observations that matter for the decision

1. **Both languages handle Secret Service and keyutils without cgo or a C compiler.** Neither needed an `unsafe`
   block or `import "C"` in our own code.
2. **The Go static build is opt-in, not default, once godbus is linked.** godbus imports `net` and `os/user`;
   on a Linux host with gcc, the unflagged build is dynamic. The release recipe must pin `CGO_ENABLED=0` (or
   `netgo,osusergo`). Rust's equivalent switch is the target triple (musl).
3. **The kernel keyring is not usable in a default Docker container.** Docker's default seccomp profile rejects
   `add_key` (observed: both languages fail at store with EPERM-class errors). With `seccomp=unconfined`, both
   work. This affects any CI or container deployment, in either language.
4. **Possession pitfall (both languages, same result):** a first version of the spike stored into the bare user
   keyring and failed at read/delete in both languages (`permission denied` / `AccessDenied`; that intermediate
   output was not kept). Default key permissions give the owner only `view`, and inside runc the anonymous session
   keyring does not link the user keyring. The kept version links the user keyring into the session keyring
   (`keyctl-user`) or uses the session keyring directly (`keyctl-session`); both pass. Kernel keyrings are
   volatile (lost on reboot or session end); this spike does not test persistence or cross-process reads.
5. **Go's Secret Service library sends the secret in plaintext over the session bus (`plain` session).**
   The Rust crate uses a DH-negotiated session. The bus is a per-user socket, so the practical exposure is small,
   but it is a real difference in default security posture; fixing it in Go means writing the session handshake on
   godbus ourselves.
6. **Error messages from the Rust path are somewhat more diagnostic in the no-bus case; both are opaque when the
   keyring is uninitialised** (runs C and D).
7. **Size:** Rust's absolute binary is smaller (1.5 MB vs 3.7 MB) with `opt-level="z"`, LTO and strip (same profile as
   the frozen prototype); the delta added by the backends is similar (about 1.0 to 1.2 MB). The Rust build is about
   10x slower cold.

## Limits

- linux-arm64 in Docker Desktop's VM only. No linux-x64, no real desktop session, no KWallet/KeePassXC provider, no
  macOS/Windows paths (separate X4 tasks).
- gnome-keyring was the only Secret Service provider. The first attempt used an empty fixture password and both
  languages failed at store (`failed to unlock correct collection` / `result not returned from SS API`; output not
  kept). With a non-empty fixture password the same binaries passed. Cause not investigated further.
- The `unsafe` counts are textual and not comparable between languages (Go counts compiled files only; Rust counts
  all cfgs). `cargo geiger` was not installed.
- Reproducible-build and vulnerability-scan comparisons belong to X3.
- Docker image `hm-x4-run:bookworm-arm64` (label `heimdall.x4`) and scratch under `/tmp/hm-r4/M00-T05-r4-x4-linux/`
  are left in place; nothing labeled `heimdall.fixture` was touched.

## Reproduce

```
# build Go (host)         : see go build line above
# build Rust (container)  : docker run --rm --platform linux/arm64 -v <rust copy>:/src -v <out>:/out \
#                           -v build-rust.sh:/build-rust.sh:ro rust:1.98.1-bookworm bash /build-rust.sh
# run                     : ./run-matrix.sh <dir containing go-spike rust-gnu rust-musl rust-keyring-gnu rust-keyring-musl>
```
