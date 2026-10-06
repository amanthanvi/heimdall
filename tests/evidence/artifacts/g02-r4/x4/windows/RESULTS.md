# X4 Windows spike: DPAPI, CNG, named pipe with client-SID check (Go vs Rust)

Task `M00-T05-r4-x4-windows`. Date 2026-10-06 (UTC, from `date -u` at build time).
Scope now: **compile-only** cross-builds from darwin/arm64. Native execution is X1.

## Status (CLAUDE.md statuses)

| Item | Status | Basis |
|---|---|---|
| Go spike source (DPAPI, CNG, pipe server, pipe client) | `implemented_unverified` | compiles and vets clean for windows/amd64; never executed |
| Rust spike source (same four) | `implemented_unverified` | clippy `-D warnings` clean, release build links; never executed |
| Cross-compile to x86_64 Windows, both languages | `verified` (build fact only) | exit codes below; rebuild in a second directory gave identical SHA-256 |
| Every runtime behaviour (DPAPI, CNG, TPM, DACL, SID check, SQOS level, first-instance, reject-remote) | `blocked` | needs native Windows 11 x64 (X1). No Windows host was available to this task. Cross-compiles and code review do not close these claims (CLAUDE.md). |
| `run-x4-windows.ps1` | `implemented_unverified` | PowerShell parser reports 0 syntax errors (`pwsh` on darwin, parse only, script not run) |

Nothing in "Observed at runtime" exists in this document. All runtime items are listed under "Blocked until X1".

## Layout

```
x4/windows/
  build.sh               cross-build both (host: any unix with go, rust, zig, cargo-zigbuild)
  build.log              sanitized log of the build run recorded below
  run-x4-windows.ps1     native runner for X1 (PowerShell 5.1 and 7 compatible)
  go/    go.mod go.sum main_windows.go dpapi_windows.go cng_windows.go pipe_windows.go other.go (non-windows stub)
  rust/  Cargo.toml Cargo.lock src/{main,dpapi,cng,pipe}.rs
```

Both binaries expose the same CLI and print one JSON object per line (no secrets, SIDs redacted to
`S-1-5-21-<redacted>-<RID>`): `dpapi`, `cng --op probe|create|sign|delete|all [--provider software|platform] [--name N]`,
`pipe-server [--name N] [--count N] [--timeout S] [--expect-sid SID]`, `pipe-client [--name N] [--level identification|anonymous|impersonation]`.

## What each spike does and which APIs it uses

| # | Feature | Go | Rust |
|---|---|---|---|
| 1 | DPAPI | `windows.CryptProtectData/CryptUnprotectData` (x/sys has typed wrappers and `DataBlob`); user scope, `CRYPTPROTECT_UI_FORBIDDEN`, optional entropy; round trip, wrong-entropy and tampered-ciphertext rejection; `LocalFree` of outputs | `windows-sys` `CryptProtectData/CryptUnprotectData`, same checks |
| 2 | CNG persisted P-256 key | **no NCrypt bindings in x/sys or go-winio**: 10 `ncrypt.dll` entry points bound by hand with `windows.NewLazySystemDLL(...).NewProc(...).Call(...)`. `NCryptOpenStorageProvider("Microsoft Software Key Storage Provider")`, `CreatePersistedKey("ECDSA_P256", name)` without `NCRYPT_OVERWRITE_KEY_FLAG`, explicit non-exportable policy, `FinalizeKey`, `ExportKey("ECCPUBLICBLOB")` (checks magic `ECS1` and 32-byte coordinates), `SignHash` (SHA-256 digest, raw r\|\|s expected, 64 bytes), `VerifySignature` plus a tampered signature that must fail, `OpenKey` in a fresh process, `DeleteKey`, then `OpenKey` must return `NTE_BAD_KEYSET`. `--provider platform` selects "Microsoft Platform Crypto Provider" (TPM 2.0); `--op probe` reports which KSPs open | `windows-sys` ships all NCrypt functions and constants (`MS_KEY_STORAGE_PROVIDER`, `MS_PLATFORM_CRYPTO_PROVIDER`, `BCRYPT_ECDSA_P256_ALGORITHM`, `BCRYPT_ECCPUBLIC_BLOB`, `NTE_BAD_KEYSET`). Same sequence. Digest is a fixed 32-byte constant (no hashing crate), so it differs from Go's `sha256.Sum256` input; it does not change what is exercised |
| 3 | Named-pipe server, current-user-only DACL, client SID check | `go-winio` `ListenPipe` with SDDL `D:P(A;;GA;;;<current-user-SID>)` (protected DACL, one ACE, so SYSTEM/Administrators/Everyone get nothing). go-winio source (v0.6.2, read) creates the first instance with `FILE_CREATE` (exclusive) and `FILE_PIPE_REJECT_REMOTE_CLIENTS`. Per connection: `Fd()` handle, `ImpersonateNamedPipeClient` (bound by hand; not in x/sys) on a `LockOSThread`-pinned goroutine, `OpenThreadToken`, read `TokenImpersonationLevel` and `TokenUser`, `RevertToSelf` (panic if it fails), compare SID to the expected SID. `GetNamedPipeClientProcessId` + `OpenProcessToken` is run as a cross-check only (PID reuse race, so it never decides). Server speaks first (`ok` / `denied`), then waits for the client to close so the verdict is not lost | `CreateNamedPipeW` with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, SDDL via `ConvertStringSecurityDescriptorToSecurityDescriptorW`, same SID rule. One thread per connection (impersonation is per thread; plain `std::thread`, no pinning concept needed). `Drop` guard calls `RevertToSelf` and `abort()`s on failure. The next pipe instance is created while the connected one still holds the name |
| 4 | Client with `SECURITY_IDENTIFICATION` | `winio.DialPipeAccessImpLevel(..., winio.PipeImpLevelIdentification)` (go-winio sets `SECURITY_SQOS_PRESENT`; the level constants exist, read in source) | `std::fs::OpenOptions::security_qos_flags(SECURITY_IDENTIFICATION)`: std only, no unsafe, no FFI for the whole client |

The server logs, per connection: redacted client SID, token impersonation level (expected 1 for Identification,
2 for Impersonation), whether the PID-derived SID agrees, and `decision`. Refusal is fail-closed: any error in
impersonation or token reads is a refuse.

## Build record (observed)

Host: darwin/arm64. Go go1.27.1. rustc 1.99.0, zig 0.16.0, cargo-zigbuild taken from the frozen
prototype's `target/tools/bin` (read and executed only; prototype not modified). All builds offline from caches
(`GOPROXY=off`, `CARGO_NET_OFFLINE=true`); no downloads were needed, so module and crate availability from the
network was not exercised.

| | Go | Rust |
|---|---|---|
| Target | `GOOS=windows GOARCH=amd64` | `x86_64-pc-windows-gnu` (zig as mingw linker via cargo-zigbuild) |
| Build command | `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w'` | `cargo zigbuild --release --locked` with `--remap-path-prefix` and `-C link-arg=-Wl,/Brepro` (same flags as the prototype `build.sh`); profile `opt-level=z, lto, codegen-units=1, strip, panic=abort` |
| Lint/vet exit | `go vet` windows/amd64: **0**; host `go vet` (stub): 0 | `cargo clippy --locked -- -D warnings`: **0** |
| Build exit | **0** | **0** (release compile 7.82 s; Go build time not measured) |
| Warnings | 0 | 0 (rustc and clippy) |
| Binary | `x4-go.exe` PE32+ x86-64 console, **3,279,360 B** | `x4-rust.exe` PE32+ x86-64 console, **361,984 B** |
| SHA-256 | `d058981a8cebe848a36cd1e39c7258fddec4c62efad19196c709634b0a079442` | `ad77730697ed2040790f063d7ca6ce76dd5f96e0e2e78879168193d165a6ddf7` |
| Reproducible | second build in another output dir: identical SHA-256 | identical SHA-256 |
| Host path leak | 0 `/Users/` hits in binary | 0 hits |
| Libraries | `golang.org/x/sys v0.46.0`, `github.com/Microsoft/go-winio v0.6.2` (both already in the Go prototype). Packages compiled in: go-winio + 4 internal pkgs, `x/sys/windows`. `go.sum` has 4 lines. `go list -m all` also lists logrus, x/mod, x/tools from go-winio's own go.mod; none are compiled in | `windows-sys =0.61.2` (+ `windows-link 0.2.1`), already in the Rust prototype's lock via `ctrlc`. `cargo tree`: 2 crates below the root. No `windows` crate, no serde |
| cgo | **not required**. `CGO_ENABLED=0` builds; every compiled package reports `CgoFiles=[]` | no C code, no `build.rs`; FFI is `raw-dylib` through windows-link |
| unsafe | `unsafe.Pointer`/`unsafe.Slice` at 30 sites in 3 files (`cng` 24, `dpapi` 5, `pipe` 1), required for every hand-bound NCrypt call and for DPAPI blobs; none in the client or in go-winio use | `unsafe {` at 20 sites: `cng.rs` 7, `pipe.rs` 11, `dpapi.rs` 2; none in `main.rs` or in the client (`std` only) |
| LOC (non-blank, non-comment) | 504 total: dpapi 66, cng 189, pipe 188, main 52, non-windows stub 9 | 698 total: dpapi 105, cng 202, pipe 302, main 89 (includes a ~45-line JSON line builder that Go gets from `encoding/json`) |
| External toolchain for the cross build | none | zig + cargo-zigbuild. Plain `cargo build --target x86_64-pc-windows-gnu` fails here: `error calling dlltool 'x86_64-w64-mingw32-dlltool': No such file or directory` (observed). The MSVC target was not attempted |
| PE imports (read with `debug/pe`) | static imports: `kernel32.dll` only (48 symbols). advapi32, crypt32, ncrypt, ntdll are bound at run time by `LazyDLL` | static imports: advapi32 (7), crypt32 (2), ncrypt (10), ntdll (3), kernel32 (75), plus UCRT api sets `api-ms-win-crt-*` (26 symbols) and `api-ms-win-core-synch` (3); Windows 10 and later ship these |

LOC and unsafe counts are mechanical (awk/grep) and the two styles differ (rustfmt expands more lines than gofmt);
read them as order of magnitude, not as a ranking.

## Observations that bear on the decision (inference from code and build, not runtime)

- **CNG coverage differs.** Rust's `windows-sys` covers NCrypt, DPAPI, pipes and tokens with typed signatures and the
  compiler checks argument counts and types. In Go the 10 NCrypt calls are untyped `uintptr` varargs through
  `LazyProc.Call`: a wrong argument count or width compiles and is only caught at run time (X1). `ImpersonateNamedPipeClient`
  is also hand-bound in Go. `go vet` passes, but it does not check these calls.
- **Pointer lifetime in Go.** The `uintptr(unsafe.Pointer(&x))` conversions must stay inline in the `Call(...)` argument list
  (`LazyProc.Call` is marked `uintptrescapes`). My first draft used a `ptr()` helper, which would have been a latent
  stack-move bug; I replaced it before building. `go vet` did not flag the helper form, so this class of bug depends on review.
- **Thread-affine impersonation.** Go needs `runtime.LockOSThread`, and a failed `RevertToSelf` must never return the thread
  to the scheduler (the spike panics). Rust uses an ordinary OS thread plus a `Drop` guard that aborts. Both fail closed. Both are untested.
- **Pipe I/O model.** go-winio gives an overlapped-I/O `net.Listener` with deadlines (used for the 3 s read deadlines). The Rust
  server is blocking with thread-per-connection and no read deadline (a stuck same-user client occupies a thread until the
  watchdog exit). A product server would need overlapped I/O or timeouts in Rust; that cost is not in the LOC above.
- **Client simplicity.** Rust std exposes `security_qos_flags`, so the SECURITY_IDENTIFICATION client is safe code. Go needs go-winio
  (or `windows.CreateFile` with `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`).
- **go-winio internals.** It creates the pipe through `NtCreateNamedPipeFile` (ntdll) rather than `CreateNamedPipeW`. Its behaviours
  (exclusive first instance, reject-remote, SDDL to descriptor) were read from v0.6.2 source, not observed.
- **Loader surface.** Rust statically imports ncrypt/crypt32/advapi32/ntdll plus UCRT api sets; Go imports kernel32 only and loads the
  rest by name at run time. What this means for AV heuristics or DLL search behaviour is not evaluated here.
- **Binary size.** 3.28 MB vs 0.36 MB. Profiles differ (Go `-s -w`; Rust `opt-level=z`, LTO, `panic=abort`), and `panic=abort` differs from the
  prototype's `panic=unwind`, so these sizes are not comparable with the prototype binaries.
- **TPM option.** Both spikes try the Platform Crypto Provider via `--provider platform`. Whether the owner's TPM accepts `ECDSA_P256`
  persisted keys through that KSP is unknown until X1. A TPM-backed key would be a different security level from the Software KSP
  (Software KSP keys live in the user profile key store, not in hardware; the TPM option is the hardware-backed one). The spikes make no claim either way.

## Blocked until X1 (native Windows 11 x64; exact missing platform: Windows 11 x64 host)

Run: `build.sh <outdir>` on the dev host, copy `x4-go.exe` and `x4-rust.exe` to the PC, then
`powershell -ExecutionPolicy Bypass -File run-x4-windows.ps1 -BinDir <dir with exes> [-Lang go|rust|both]`.
Needs no elevation, no network, no admin, and starts no listener outside `\\.\pipe\`. Before running, confirm `SSH_AUTH_SOCK` is
unset (the script records it). It writes raw stdout/stderr and `results.json` to `-OutDir` (host OS/build/TPM, binary hashes, one record
per check, real exit codes). Copy redacted output into `tests/evidence/artifacts/` per plan §6.6.

| Check id (per language) | Expectation | Status |
|---|---|---|
| `dpapi.roundtrip` | exit 0; round trip, wrong entropy and tampered blob rejected | blocked |
| `cng.probe` | info: which KSPs open | blocked |
| `cng.create` | key created; ECCPUBLICBLOB magic `ECS1`, 32-byte coordinates | blocked |
| `cng.create.duplicate_fails` | second create fails `NTE_EXISTS 0x8009000F` | blocked |
| `cng.sign.new_process` | key persists across processes; sig 64 bytes; verifies; tampered sig rejected | blocked |
| `cng.delete` | deleted; reopen gives `NTE_BAD_KEYSET 0x80090016` (key removed from the profile store) | blocked |
| `cng.platform_tpm` | info only: TPM-backed P-256 create/sign/delete | blocked |
| `pipe.accept_same_user` | accept; token level 1 (Identification) seen server side; PID cross-check agrees | blocked |
| `pipe.refuse_foreign_sid` | server expecting `S-1-5-32-545` denies the real user | blocked |
| `pipe.refuse_anonymous_level` | anonymous-level client refused (fail closed) | blocked |
| `pipe.control_impersonation_level` | info: accepted, level 2 | blocked |
| `pipe.first_instance_exclusive` | second server on the same name fails to start | blocked |
| `pipe.dacl_refuses_other_user` | other local user cannot open the pipe (`ERROR_ACCESS_DENIED`); needs `-OtherUserCredential` and `-OtherUserBinDir` (second disposable non-admin account) | blocked (second account) |
| `pipe.reject_remote_clients` | SMB client rejected | blocked (second Windows machine); code review only |

Open questions X1 should answer: does `ImpersonateNamedPipeClient` + `OpenThreadToken(openAsSelf=TRUE)` succeed at Identification
level on Windows 11 for both languages; what does an Anonymous-level client produce (error path or anonymous SID); does the
protected single-ACE DACL block the same user's other-integrity or elevated processes in ways the product cannot accept;
whether the Platform Crypto Provider accepts P-256 on this TPM; whether Defender/SmartScreen quarantines either unsigned binary.

## Limits

- Not executed on any Windows host. No runtime claim is made. API semantics (SDDL parsing, level constants, error codes)
  come from vendor headers as vendored in `windows-sys`/`x/sys` and from library source, not from observation.
- `ECDSA_P256` signatures from NCrypt are expected as raw `r||s` (64 bytes); converting to an SSH or DER encoding is outside the spike and equal work in both languages.
- Both spikes verify signatures with the same CNG key handle only; no independent verifier was used.
- Builds used warm local caches; cold-cache build times and network fetch behaviour were not measured. Build wall times are not scored.
- One Rust target (`x86_64-pc-windows-gnu`) and one Go target (`windows/amd64`) only; no arm64 Windows, no MSVC target.
