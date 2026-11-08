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
| ratatui | 0.30.2 (`crossterm`, no default) | MIT | bin (M02-T05) | TUI (decided, ADR-0002/0004); in the lock since M02 wave 4, consumed by `crates/heimdall/src/tui` (U10) | — (decision not reopened) |
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
* ⟨M02, wave 4⟩ `ratatui` 0.30.2 and `crossterm` 0.29.0 (pinned above) entered the
  lock with the TUI module (U10), at the pinned versions, with their transitive
  packages.
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

## 5. ⟨M03⟩ Dependencies (U0, wave 0; ADR-0008 §18)

**Observed on 2026-11-08.** Selection rule (m03-plan U0): the newest release published
**on or before 2026-10-25** (at least two weeks before this record), not yanked, with a
`rust_version` of at most 1.99.1. Versions, publish dates, MSRVs and licences are the
crates.io sparse index and `crates.io/api/v1` values for the exact version; advisories are
the RustSec advisory-db at commit `309392b1` (2026-11-06). The resolution check was a
copy of the workspace manifests and the committed `Cargo.lock` with a scratch member
carrying the new dependencies under their target cfgs (`cargo metadata` and `cargo tree`
only, no build; no existing package moved). `cargo-deny`/`cargo audit` remain M08.

| Crate | Pinned | Licence | Used by | Purpose | Rejected alternatives |
|---|---|---|---|---|---|
| ssh-key | 0.6.7 (published 2024-10-15, MSRV 1.65; features `std` + ⟨M03⟩ `ed25519`, `encryption`, `rand_core`) | Apache-2.0 OR MIT | credential, issuer (ipc, testkit as before) | Ed25519 key generation for K_env, K_verify and K_ca; OpenSSH private-key and certificate encoding; the D5 backup (`encryption` = bcrypt-pbkdf with aes256-ctr, ADR-0008 §6.3). `ed25519` and `rand_core` add no package (`ed25519-dalek` 2.2.0 and `rand_core` 0.6.4 are already in the lock through ssh-agent-lib's `ssh-key/crypto`); `encryption` adds 15 (aead, aes 0.8.4, aes-gcm, bcrypt-pbkdf, blowfish, cbc 0.1.2, chacha20 0.9.1, ctr, ghash, opaque-debug, pbkdf2, poly1305, polyval, universal-hash, block-padding 0.3.3). No advisory. Kept at 0.6.7, the last 0.6 release: 0.7.0-rc.11 (2026-06-29) is still a release candidate and ssh-agent-lib 0.6 needs 0.6 | `ed25519-dalek` directly (would hand-roll OpenSSH key and certificate encoding, which spec §7.2 forbids guessing); shelling out to `ssh-keygen` (no in-memory key, no zeroize); `ssh-key` 0.7 rc (see above) |
| zeroize | 1.9.1 (2026-10-06, MSRV 1.85; `alloc`, no default, no `derive`) | Apache-2.0 OR MIT | credential, issuer | `Zeroizing<_>` and `Zeroize` for the `SecretKey` vault type, passphrases and the issuer's K_ca buffer (ADR-0008 D2, D4). Already in the lock at 1.9.1 through ssh-key and the RustCrypto crates: **no new package**. `derive` is left off (it adds `zeroize_derive`, one more proc-macro crate); the vault type implements `Drop` explicitly. No advisory | `secrecy` (a second wrapper; the vault type's no-`Clone`/`Debug` rules are the ADR's own); volatile writes by hand (needs `unsafe`) |
| security-framework | 3.7.0 (2026-02-20, MSRV 1.85; **no default features**, no features) | MIT OR Apache-2.0 | issuer (macOS only) | login-keychain generic-password items, `SecKeychain` (a disposable file keychain under the test configuration) and `SecKeychain::disable_user_interaction()` (ADR-0008 D1, D3). Adds 4 packages: security-framework, security-framework-sys 2.17.0 (2026-02-20), core-foundation 0.10.1, core-foundation-sys 0.8.7. Only advisory: RUSTSEC-2017-0003 (patched at 0.1.12, not applicable). **Gap:** neither this crate nor `security-framework-sys` 2.17.0 declares `SecAccessCreate` or `SecTrustedApplicationCreateFromPath` (the crate has the `SecAccess` type only), so the "trust only the `heimdall` executable" access list is declared in `crates/issuer/src/sys.rs` (already in the `unsafe` inventory, ADR-0008 §18). `OSX_10_15` (`PasswordOptions::use_protected_keychain`) is added with D3's data-protection keychain, with no new package | `keyring` 4.2.0 (a facade over per-OS store crates: no SecAccess list, no interaction control, and its Windows store is Credential Manager where D1 specifies a DPAPI file); hand-written FFI for everything (a far larger `unsafe` surface); feature `sync-keychain` (iCloud sync is never wanted) |
| secret-service | 5.2.0 (2026-08-29, MSRV 1.87; **no default features**, `rt-tokio-crypto-rust`) | MIT OR Apache-2.0 | issuer (Linux only) | Secret Service client for the login collection over a DH-encrypted session (ADR-0008 D1, `LinuxSecretService`). `rt-tokio` = `zbus/tokio`; `crypto-rust` is the pure-Rust DH/AES-CBC path. 5.2.0 over 5.1.0: its notes list a check of the initialization-vector length and an error instead of a panic when a prompt fails (GitHub release notes, read 2026-11-08). No advisory. **Cost:** `crypto-rust` pulls the RustCrypto 0.11 generation (sha2 0.11.1, hkdf 0.13, hmac 0.13, digest 0.11, aes 0.9, cbc 0.2, cipher 0.5), a Linux-only duplicate of the 0.10 generation ssh-key uses (§3 below) | `secret-service` 5.1.0 (2025-09-03; zero duplicate crypto crates because it uses the 0.10 generation, but no IV check; the fallback if the duplicates are refused); `crypto-openssl` (links the system libssl); `rt-async-io` (a second async runtime); 6.0.0-rc.1 (2026-11-06, a release candidate on zbus 6; younger than two weeks); `oo7` 0.7.0 (2026-11-05, MSRV 1.95, carries a portal and file backend that this design must not have, D1 "no plaintext fallback"); `keyring` (see above); libsecret bindings (glib, a C dependency); shelling out to `secret-tool` (m03-plan P3: no DH control) |
| zbus | 5.19.0 (2026-08-09, MSRV 1.87; **no default features**, `tokio`) | MIT | issuer (through secret-service), runtime (Linux only; logind `LockedHint` and `Lock`/`Unlock`) | the one D-Bus client in the tree (m03-plan P3). Shared with secret-service by pinning the major it requires (`zbus ^5`), so there is exactly one zbus. The Linux additions are zbus 5.19.0, zbus_macros, zbus_names 4.3.5, zvariant 5.15.1, zvariant_derive, zvariant_utils 4.2.0 and their small dependencies (async-broadcast, event-listener, futures-lite, enumflags2, serde_repr, winnow, uuid, ordered-stream and similar; the Linux total is under "Weight" below). **Advisories:** RUSTSEC-2026-0370, -0371 and -0372 (2026-10-16, informational `unmaintained`, no patched version) cover zvariant, zbus_names and zvariant_derive, which zbus 6.0.0 merged into itself; zbus 5.19.0 (the last 5.x) has none of its own. Accepted until secret-service 6.0.0 is released stable on zbus 6; then bump both together (record it here). **Feature unification:** zbus's `tokio` feature turns on tokio's `rt-multi-thread`, `fs` and `tracing` in Linux builds (it adds no package; the runtime stays `current_thread`; measured with `cargo tree -e features`: Linux gains `rt-multi-thread` and `fs`, macOS and Windows builds do not) | `dbus` crate (needs libdbus-1 and pkg-config, a C dependency that breaks the zig cross-build); zbus 6.x (6.0.0 on 2026-10-16 to 6.2.1 on 2026-11-01: secret-service 5.2.0 cannot use it, and a hand-written Secret Service DH client would be custody code we do not want to own); `rustbus`; shelling out to `busctl monitor` (polling, stdout parsing) |
| windows-sys | 0.61.2 (unchanged; ⟨M03⟩ adds `Win32_Security_Cryptography`, `Win32_System_RemoteDesktop`, `Win32_UI_WindowsAndMessaging`, `Win32_System_Diagnostics_ToolHelp`, plus `Win32_System_Memory` and `Win32_System_LibraryLoader` below) | MIT OR Apache-2.0 | issuer (`Win32_Security_Cryptography`: `CryptProtectData`, `CryptUnprotectData`, `CRYPTPROTECT_UI_FORBIDDEN`, `CRYPT_INTEGER_BLOB`; `LocalFree` and the blob's DACL use the existing `Win32_Foundation` and `Win32_Security_Authorization`); runtime session lock (`Win32_System_RemoteDesktop`: `WTSRegisterSessionNotification`, `WTSUnRegisterSessionNotification`, `WTSQuerySessionInformationW`, `WTSFreeMemory`, `WTSINFOEXW`, `NOTIFY_FOR_THIS_SESSION`; `Win32_UI_WindowsAndMessaging`: `CreateWindowExW`, `RegisterClassW`, `HWND_MESSAGE`, `GetMessageW`, `DispatchMessageW`, `DefWindowProcW`, `PostMessageW`, `DestroyWindow`, `WM_WTSSESSION_CHANGE` and the constants `WTS_SESSION_LOCK`/`WTS_SESSION_UNLOCK`, which live in this module, not in RemoteDesktop; `Win32_System_LibraryLoader`: `GetModuleHandleW` for the window class); localenv (`Win32_System_Diagnostics_ToolHelp`: `CreateToolhelp32Snapshot`, `Thread32First`, `Thread32Next`, `THREADENTRY32`; `ResumeThread`, `OpenThread`, `CREATE_SUSPENDED` are already in `Win32_System_Threading`); credential (`Win32_System_Memory`: `VirtualLock`, `VirtualUnlock`) | each feature name and each symbol above was found in the 0.61.2 source (checked 2026-11-08). The four ADR-0008 §18 features exist at 0.61.2. `Win32_System_Memory` and `Win32_System_LibraryLoader` are **not in ADR-0008 §18's list** but the named `sys.rs` modules need them (see the notes file). **No new package** | `windows` crate (larger); `winapi` (unmaintained since 2020) |
| core-foundation | 0.10.1 (2025-05-26, MSRV 1.65; default `link`) | MIT OR Apache-2.0 | runtime (macOS only) | `CFDictionary`, `CFString`, `CFBoolean`, `CFRunLoop` wrappers for the session-lock source (`CGSSessionScreenIsLocked`, the run-loop thread). Already in the graph through security-framework: **no new package** once that is in | `objc2-core-foundation` (a new family for the same wrappers) |
| core-foundation-sys | 0.8.7 (2024-08-11; default `link`) | MIT OR Apache-2.0 | runtime (macOS only) | `CFNotificationCenterGetDistributedCenter`, `CFNotificationCenterAddObserver`, `CFNotificationCenterRemoveObserver` for `com.apple.screenIsLocked`/`com.apple.screenIsUnlocked` (present in 0.8.7 `notification_center`; core-foundation 0.10.1 has no wrapper). Already in the graph. `CGSessionCopyCurrentDictionary` is in neither crate: `crates/runtime/src/session_lock/sys.rs` declares it with `#[link(name = "CoreGraphics", kind = "framework")]` (already in the `unsafe` inventory) | `core-graphics` (bindings for one function, plus its own dependencies) |

**Existing pins that M03 starts using (no change):** `libc` 0.2.191 for `mlock`,
`munlock`, `prctl(PR_SET_DUMPABLE)` and `setrlimit(RLIMIT_CORE)` in
`crates/credential/src/sys.rs` (Unix); `rustix` 1.1.6 feature `process` for
`pidfd_open`/`pidfd_send_signal` where the using crate declares it (the feature is
already on in the lock's feature set through testkit); `getrandom` 0.4.3, which
secret-service 5.2.0 also requires (`^0.4`), so one copy serves both.

**Transitive versions held back to the two-week rule.** After adding the dependencies
the resolver picked six packages published after 2026-10-25. They are held at the newest
release on or before that date (`cargo update -p <name> --precise <version>`, checked
to resolve): aes 0.9.4 to **0.9.3** (2026-08-28), ctutils 0.4.8 to **0.4.6**
(2026-10-25; RUSTSEC-2026-0385 is patched from 0.4.4), inout 0.2.6 to **0.2.5**
(2026-10-19), uuid 1.29.1 to **1.29.0** (2026-10-23), zcheapstr 1.2.0 to **1.1.0**
(2026-08-10), and js-sys 0.3.107 with wasm-bindgen 0.2.130 (and its macro,
macro-support and shared crates) to **0.3.106 / 0.2.129** (2026-09-25; these five are
wasm32-only lock entries pulled by uuid and are never compiled here). With these, every
package the M03 dependencies add was published on or before 2026-10-25 and none is
yanked. Every added package is MIT, MIT OR Apache-2.0 or Apache-2.0 OR MIT; the highest
MSRV among them is 1.89 (uuid 1.29.0, aes 0.9.3), which rusqlite's direct 1.89 already
sets.

**Weight, measured with the check above (unique normal-edge crates, then lock
packages).** All targets: 204 to 272; Cargo.lock 245 to 316 (71 added). Per target:
Linux x86_64 186 to 248 (+62: 15 ssh-key `encryption`, 47 secret-service and zbus), macOS
arm64 183 to 202 (+19: 15 and 4 security-framework), Windows msvc 184 to 199 and gnu 185
to 200 (+15, all ssh-key `encryption`; windows-sys features add no package). The Linux
cost is the one the m03-plan P3 asks to record; the devbox build time is measured by the
unit that first builds it, not here. No new package has a C build step (no
`openssl-sys`, no `libdbus-sys`).

**Duplicate versions this adds (against §3):** Linux only, from secret-service
`crypto-rust`: aes 0.8/0.9, block-buffer 0.10/0.12, block-padding 0.3/0.4, cbc 0.1/0.2,
cipher 0.4/0.5, const-oid 0.9/0.10, crypto-common 0.1/0.2, digest 0.10/0.11, hmac
0.12/0.13, inout 0.1/0.2, sha2 0.10/0.11. All targets, from ssh-key `encryption`:
chacha20 0.9.1 beside the 0.10.2 already present. No second zbus, getrandom 0.4,
rand_core or windows-sys. The earlier note that sha2 0.11 "would duplicate sha2" now
holds on Linux, accepted for the pure-Rust Secret Service path (see secret-service
above; 5.1.0 is the zero-duplicate fallback).

**Known gap in what this records:** the compile-level behaviour of zbus on a
`current_thread` tokio runtime and of the macOS `SecAccess` declarations is verified by
the units that first call them (m03-plan U4, U8), on their native hosts; this section
checks resolution, versions, features and source symbols only.
