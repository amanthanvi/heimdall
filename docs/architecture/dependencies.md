# Third-party dependencies (M01 and M02 workspace)

**Policy (plan §7.4):** every third-party crate is pinned to an exact version in
`[workspace.dependencies]`, `Cargo.lock` is committed and CI builds `--locked`,
features are minimal and explicit, and each crate has a recorded reason, licence
and rejected alternatives. Bumps are recorded here. `cargo-deny`, `cargo auditable`
and OSV/GHSA scanning are M08 obligations (ADR-0002 §11); this file does not claim
them.

**Observed on 2026-10-31:** versions were checked against crates.io (`cargo search`,
`cargo info`, the sparse index for patch lines) and the licence column below is the
`license` field reported by `cargo metadata --locked` for the resolved graph (185
packages). The whole graph resolves to permissive licences only (MIT, Apache-2.0,
BSD-2/3-Clause, Zlib, Unicode-3.0, Unlicense, ISC-style); nothing copyleft except
`r-efi`'s *optional* `LGPL-2.1-or-later` alternative in an `OR` expression. The
project's own licence is still an unmade release decision (ADR-0001 §8).

Toolchain: `rust-toolchain.toml` pins **1.99.1** (rustc 1.99.1 58cf8f9c3 2026-10-13),
edition 2024, resolver 3. Highest MSRV in the direct set is rusqlite's 1.89.

## 1. Direct dependencies

| Crate | Pinned | Licence | Used by | Purpose | Rejected alternatives |
|---|---|---|---|---|---|
| serde | 1.0.229 | MIT OR Apache-2.0 | all | (de)serialization of every wire and stored type | hand-written JSON (rejected: contract drift); `miniserde` (no derive breadth) |
| serde_json | 1.0.154 (`float_roundtrip`, design-fix E3) | MIT OR Apache-2.0 | all | JSON for envelopes, events, stored documents; `Value` for canonicalization (`preserve_order` deliberately **off**; `float_roundtrip` so a parsed float canonicalizes back to the same text) | `simd-json` (unsafe-heavy, no need) |
| schemars | 1.2.3 (features `derive`, `jiff02`) | MIT | contract, runtime | JSON Schema generated from the canonical Rust model (spec P10, plan §4.5) | hand-written schemas (rejected: two sources of truth); `typify` (inverse direction) |
| toml | 1.1.8 (`parse`, `serde`, `std`; no `display` yet) | MIT OR Apache-2.0 | runtime | `config.toml` parsing (spec P10) | `toml_edit` (needed only when setup writes config, M02) |
| jiff | 0.2.38 (`std`, `serde`, `tz-system`, `tzdb-zoneinfo`, `tzdb-bundle-platform`) | Unlicense OR MIT | contract, domain, app, runtime | `Timestamp` (UTC instant, RFC 3339 with offset), spans, time-zone disambiguation for human input (spec §6.2; `tzdb-zoneinfo` reads the system zoneinfo on Unix so named-zone input is diagnosed as ambiguous/nonexistent, design-fix E9–E11; bundled database on Windows), schemars integration | `time` 0.3.55 (no tz database or disambiguation API); `chrono` + `chrono-tz` (two crates, weaker ambiguity semantics) |
| tokio | 1.54.1 (`rt`, `net`, `io-util`, `time`, `sync`, `macros`, `signal`, ⟨M02⟩ `process`; **no** `rt-multi-thread`) | MIT | app, ipc, runtime, bin, ⟨M02⟩ launch (U8 Windows console guard, `tokio::signal::windows`), adapters; `process` is for the U3 probes and local queries, and `heimdall-localenv` takes the tokio dependency with U3 | current-thread async runtime; `UnixStream::peer_cred`; Windows named-pipe `ServerOptions`/`ClientOptions`; timers; `broadcast`/`watch` | std threads + mpsc (rejected: no peer_cred/named-pipe flags without unsafe, Iroh is tokio-native); `smol`/`async-std` (no named-pipe security options) |
| tokio-util | 0.7.20 (`codec`) | MIT | ipc, runtime, bin | `LengthDelimitedCodec` with `max_frame_length`; `CancellationToken` | hand-rolled framing (kept only as the pure test helper) |
| futures-util | 0.3.34 (`std`, `sink`, no default) | MIT OR Apache-2.0 | ipc | `StreamExt`/`SinkExt` for framed streams | `tokio-stream` (no sink side) |
| async-trait | 0.1.92 | MIT OR Apache-2.0 | app, ipc, testkit | dyn-compatible async adapter/dispatcher ports | native `async fn` in traits (not dyn-compatible), manual boxed futures (noise) |
| rusqlite | 0.41.1 (`bundled`) | MIT (SQLite: public domain) | store | transactional local state (spec P08); bundled engine pins the SQLite version per build and needs no system library | `sqlx` (async + larger, pool semantics unneeded); `redb`/`sled` (no SQL migrations, less crash evidence); JSON journal files (no transactions) |
| ssh-agent-lib | 0.6.0 (**no default features**: `proto` types only) | MIT OR Apache-2.0 | ipc | SSH agent message types and (M03) codec for the signing endpoint; its `agent` listener helpers are not used because they cannot apply the DACL/peer checks | hand-parsing agent frames (spec §7.2 forbids guessed parsing); `russh-keys` agent (pulls a full SSH stack) |
| ssh-key | 0.6.7 (`std`) | Apache-2.0 OR MIT | ipc (M03: credentials) | public key / certificate types (RustCrypto); 0.6 line chosen because ssh-agent-lib 0.6 depends on it; 0.7 is still release-candidate | `openssh-keys` (unmaintained), shelling out to `ssh-keygen` for parsing (fine for issuance, not for in-process validation) |
| ssh-encoding | 0.2.0 (`alloc`) | Apache-2.0 OR MIT | ipc | RFC 4251 encodings shared with ssh-key 0.6 | 0.3.0 (incompatible with ssh-key 0.6/ssh-agent-lib 0.6; revisit when ssh-key 0.7 is stable) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | contract, domain | SHA-256 for request hashes and cursor reader tags; 0.10 line to share one copy with ssh-key 0.6 | `blake3` (second hash family for no gain); sha2 0.11 (would duplicate sha2 in the graph) |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | app | OS CSPRNG for IDs and pipe-name tokens | `rand` 0.10 (API churn; not needed for IDs); `uuid` (v4 only wraps getrandom, v7 leaks time) |
| libc | 0.2.191 (`std`, no default; Unix only) | MIT OR Apache-2.0 | runtime (`platform.rs`, design-fix round) | boot-scoped continuous clock and boot ID: `clock_gettime(CLOCK_BOOTTIME)`, `mach_continuous_time`/`mach_timebase_info`, `sysctlbyname("kern.bootsessionuuid")` (ADR-0005 §3.6); same version the lock already carried through tokio | `rustix` 1.1.6 (has `ClockId::Boottime` but no `mach_continuous_time`/`sysctl`; arrives with M02 `run` anyway); `nix` (larger; the prototype used it only for `pthread_sigmask`) |
| base64ct | 1.8.3 (`alloc`) | Apache-2.0 OR MIT | app, domain | base64url cursors; already in the graph through ssh-encoding | `base64` 0.23 (second base64 crate) |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | all | error enums | `anyhow` in libraries (rejected: codes must stay classified) |
| tracing | 0.1.44 (`std`) | MIT | store, app, ipc, runtime, bin | structured local diagnostics (spec §13.6) | `log` (no spans/fields) |
| tracing-subscriber | 0.3.23 (`fmt`, `std`; no `ansi`, no `env-filter`) | MIT | runtime | stderr/file sinks without ANSI (NO_COLOR semantics) | `env_logger` |
| clap | 4.6.7 (`std`, `derive`, `help`, `usage`, `error-context`, `env`; no `color`) | MIT OR Apache-2.0 | bin | command tree, usage errors exit 2 | hand-written parser (prototype did this; production needs help/discovery breadth); `argh`/`lexopt` (no subcommand help depth) |
| ratatui | 0.30.2 (`crossterm`, no default) | MIT | bin (M02-T05) | TUI (decided, ADR-0002/0004); declared now, enters the lock when the TUI crate consumes it | — (decision not reopened) |
| crossterm | 0.29.0 | MIT | bin (M02-T05) | terminal backend; **watch item**: hang on terminal hang-up and `ESC[6n` query (REPORT.md §5) must be mitigated in the TUI unit | `termion` (no Windows); `termwiz` (heavier) |
| etcetera | 0.11.0 | MIT OR Apache-2.0 | runtime | XDG dirs on every Unix (so the include path is `~/.config/heimdall/...` as in spec §10.1) and Known Folders on Windows | `directories` 6.0.0 (forces macOS `~/Library/...`, conflicting with the spec's proposed path) |
| windows-sys | 0.61.2 (`Win32_Foundation`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_System_IO`, `Win32_System_Pipes`, `Win32_System_Registry`, `Win32_System_Threading`, `Win32_System_WindowsProgramming`; ⟨M02⟩ `Win32_System_JobObjects`, `Win32_System_Console`, `Win32_UI_Shell`) | MIT OR Apache-2.0 | ipc, runtime (Windows only; runtime: `QueryInterruptTime` and the Session Manager `BootId` registry value, ADR-0005 §3.6); ⟨M02⟩ localenv `sys.rs` (Windows only): kill-on-close job objects for probes, the profile folder (account home, ADR-0007 F19), and, through the existing `Win32_Storage_FileSystem`, `ReplaceFileW`, `GetFileInformationByHandleEx`, `SetFileInformationByHandle`. `Win32_System_Console` is the dependency note's feature for the Windows launcher's console guard; U8 plans tokio's `ctrl_c`/`ctrl_break` (`crates/launch/Cargo.toml`), and any direct console call would go through `localenv::sys` (the only M02 `unsafe` module) | DACL/SDDL, impersonation, token query, `GetFileType`; same version tokio already carries; feature set is the one the prototype verified natively (REPORT.md §16) | `windows` crate (larger), `winapi` (unmaintained since 2020) |
| ⟨M02⟩ glob | 0.3.4 | MIT OR Apache-2.0 | localenv (U1/U3 `Include` expansion) | expands an OpenSSH `Include` pattern against the filesystem; the caller sorts the results bytewise and bounds them (`Limits::glob_results`, m02-plan U1), as OpenSSH's `glob(3)` use does. The rust-lang-maintained crate, no dependencies | `globset` (matching only, no directory walk; pulls `regex`); `wax` (larger graph); hand-written `fnmatch` + `read_dir` (another parser to get wrong for one call site) |
| ⟨M02⟩ rustix | 1.1.6 (`std`, `fs`; no default) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | localenv (Unix only, U4 `projection::replace`) | the atomic exchange and the no-replace rename through the reviewed safe wrapper `fs::renameat_with`: Linux `renameat2` with `RENAME_EXCHANGE`/`RENAME_NOREPLACE`, macOS `renameatx_np` with `RENAME_SWAP`/`RENAME_EXCL` (checked in the 1.1.6 source: on Linux the default `linux_raw` backend issues `renameat2` directly, `backend/linux_raw/fs/{types,syscalls}.rs`; on macOS `backend/libc/fs/syscalls.rs` resolves `renameatx_np` as a weak symbol and, where it is missing, returns `ENOSYS` for any flagged call rather than falling back to a plain `rename`); also `statx` (`STATX_BTIME`) and `fstat` for birth time (ADR-0007 F25). Already in the lock through `tempfile`, so no new package. m02-plan §6 P5: a safe wrapper exists at the pinned version, so it is a normal dependency and these calls stay out of `sys.rs` | FFI to `renameat2`/`renameatx_np` through `libc` in `sys.rs` (more `unsafe` for no gain; P5's fallback); `nix` (no `renameatx_np` wrapper) |
| proptest | 1.12.0 (dev) | MIT OR Apache-2.0 | all (dev) | property tests with reproducible seeds and committed regressions (plan §6.3) | `quickcheck` (no shrinking persistence) |
| tempfile | 3.27.0 (dev) | MIT OR Apache-2.0 | store, ipc, runtime, testkit (dev) | temp dirs for store and socket tests | manual temp paths |

## 2. Not used, and why

* `nix`: not used (tokio supplies peer credentials; std supplies file locks since
  Rust 1.89 and permission bits; `libc` covers the clock/boot-ID syscalls; M02 uses
  `rustix`, above).
* ⟨M02⟩ **Planned by the U0 dependency note, not yet in the lock** (each enters with
  the unit that first uses it, under this entry, with no new version decision):
  * `rustix` dev-only features `pty`, `termios`, `process` for the pty tests of U8
    and U10 (same pinned 1.1.6; rejected: `portable-pty`, a second pty stack, and
    `nix`);
  * `ratatui` 0.30.2 and `crossterm` 0.29.0 (already pinned above) enter the lock
    when the TUI module (U10) consumes them.
* Dev-only feature changes of the design-fix round: `heimdall-testkit` gained
  features `store` (ScriptedFaults) and `app` (FakeCredentialAdapter,
  ScriptedStageHook), both default-on; `heimdall-ipc`'s dev-dependency uses
  `default-features = false` so the IPC test build and the Windows cross-check do
  not pull rusqlite (E2); `heimdall-ipc` dev-dependencies enable tokio `test-util`
  (paused virtual time for timeout tests). No new package entered the lock.
* ⟨M02, wave 1⟩ Dependency-list changes, no new package and no version change
  (`Cargo.lock` gains only edges between packages it already held):
  * `heimdall-testkit` feature `fixtures` (default-on; U7's process fixtures)
    enables, all optional and already pinned: `heimdall-sshconf` (the
    default-identity guard's static evaluator), `tokio`, `ssh-key` 0.6.7 with feature
    `ed25519` (`FakeAgent` signing; rejected: shelling out to `ssh-keygen -Y sign`
    inside the fake, which would make the fake depend on the client under test;
    `ed25519-dalek` was already in the lock), `ssh-encoding`, `glob`, `getrandom`
    0.4.3, `rustix` (Unix; feature `process` for `setsid` and SIGTERM by exact PID)
    and `heimdall-ipc` (Windows; the owner-only pipe listener). `heimdall-ipc`'s
    dev-dependency keeps `default-features = false`, so its own test build leaves
    `fixtures` off.
  * `heimdall-sshconf` dev-dependencies `proptest` and `glob` (U1/U2 test targets;
    `glob` is the differential oracle for the test-only in-memory matcher).
* `zeroize` / `secrecy`: arrive with M03 key handling (already in the graph through
  ssh-key).
* `anyhow`: never in libraries; the CLI maps every failure to a `Code`.
* `interprocess`, `named_pipe`: tokio's named-pipe API plus `windows-sys` cover the
  required flags; a third abstraction would hide the DACL.
* `iroh` 1.3.0: M06 (G06 decides embedding vs helper; ADR-0002 §8).
* `cargo-zigbuild`, `zig`: build tooling (M08 packaging), not a dependency.

## 3. Duplicate-version watch

⟨M02, wave 0⟩ The new packages are `glob` 0.3.4 and the four workspace crates;
`rustix` 1.1.6 was already in the graph. `cargo metadata` shows two `getrandom` lines (0.2.17 via proptest's `rand` 0.8, dev
only; 0.4.3 ours) and `sha2` deliberately on 0.10 (see above). No other duplicate of
a crate we pin. Re-check after any bump (`cargo tree -d`).

## 4. Bump procedure

1. Change the exact pin in the root `Cargo.toml`; run `cargo update -p <crate>
   --precise <version>`.
2. Run `tools/validation/check.sh`; for `windows-sys`, `tokio`, `ssh-*` also
   `cargo check --target x86_64-pc-windows-gnu -p heimdall-ipc`.
3. Record the reason and date in this file; licence changes reopen ADR-0002 §12.
