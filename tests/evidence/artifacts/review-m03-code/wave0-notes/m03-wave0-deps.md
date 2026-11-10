# M03 wave 0: dependency pins (subagent D; untracked notes for the integrator)

Observed 2026-11-08. Record: `docs/architecture/dependencies.md` section 5. Nothing in any `Cargo.toml` or
`Cargo.lock` was edited by D. Selection rule: newest release published on or before 2026-10-25, not yanked,
MSRV <= 1.99.1. RustSec advisory-db at commit 309392b1 (2026-11-06).

## 1. Root `Cargo.toml`, `[workspace.dependencies]`

Replace the `ssh-key` line and add the rest (a comment per line in the file's existing style):

```toml
# M03 (ADR-0008 §18): ed25519 (K_env/K_verify/K_ca generation), encryption (D5 backup:
# bcrypt-pbkdf + aes256-ctr), rand_core (key generation takes a rand_core 0.6 RNG).
ssh-key = { version = "=0.6.7", default-features = false, features = ["std", "ed25519", "encryption", "rand_core"] }

# --- secret handling and custody stores (M03) --------------------------------------
zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }
# macOS only (issuer): login keychain. No default features (the OSX_* defaults are no-op markers).
security-framework = { version = "=3.7.0", default-features = false }
# macOS only (runtime session lock): CFDictionary/CFString/CFRunLoop and the CFNotificationCenter externs.
core-foundation = { version = "=0.10.1" }
core-foundation-sys = { version = "=0.8.7" }
# Linux only: the Secret Service client and the one zbus (logind). secret-service 5.2.0 requires zbus ^5.
secret-service = { version = "=5.2.0", default-features = false, features = ["rt-tokio-crypto-rust"] }
zbus = { version = "=5.19.0", default-features = false, features = ["tokio"] }
```

`windows-sys` stays `=0.61.2`; append to its existing `features` list (M02's pattern: one root list):

```toml
    # M03 (ADR-0008 §18): DPAPI (issuer), WTS session lock + message-only window (runtime),
    # thread enumeration for CREATE_SUSPENDED/ResumeThread (localenv).
    "Win32_Security_Cryptography",
    "Win32_System_RemoteDesktop",
    "Win32_UI_WindowsAndMessaging",
    "Win32_System_Diagnostics_ToolHelp",
    # Not in ADR-0008 §18's list, but the named sys.rs modules need them (see question Q4):
    "Win32_System_Memory",        # credential: VirtualLock / VirtualUnlock
    "Win32_System_LibraryLoader", # runtime: GetModuleHandleW for the window class
```

All four ADR features, and every symbol in the crate table of dependencies.md, were found in the
windows-sys 0.61.2 source. Note `WTS_SESSION_LOCK`/`WTS_SESSION_UNLOCK` live in `Win32_UI_WindowsAndMessaging`,
not `Win32_System_RemoteDesktop`.

## 2. Per-crate dependency lines

heimdall-credential (ssh-key, zeroize; sys.rs memory FFI needs the OS crate too, see Q4):

```toml
[dependencies]
ssh-key.workspace = true
zeroize.workspace = true

[target.'cfg(unix)'.dependencies]
libc.workspace = true            # mlock/munlock, prctl(PR_SET_DUMPABLE), setrlimit(RLIMIT_CORE)

[target.'cfg(windows)'.dependencies]
windows-sys.workspace = true     # VirtualLock/VirtualUnlock (Win32_System_Memory, root list)
```

heimdall-issuer:

```toml
[dependencies]
ssh-key.workspace = true
zeroize.workspace = true

[target.'cfg(target_os = "macos")'.dependencies]
security-framework.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
secret-service.workspace = true

[target.'cfg(windows)'.dependencies]
windows-sys.workspace = true     # CryptProtectData/CryptUnprotectData (Win32_Security_Cryptography, root list)
```

heimdall-runtime (add to its existing target tables; `windows-sys` is already a Windows dependency, and the
root list carries the new features):

```toml
[target.'cfg(target_os = "linux")'.dependencies]
zbus.workspace = true            # logind LockedHint + Lock/Unlock

[target.'cfg(target_os = "macos")'.dependencies]
core-foundation.workspace = true
core-foundation-sys.workspace = true
```

heimdall-localenv: no new line (Windows `windows-sys` is already a dependency; `Win32_System_Diagnostics_ToolHelp`
comes from the root list). `rustix` feature `process` (pidfd) is declared on the crate that uses it
(`rustix = { workspace = true, features = ["process"] }`), no new package.

Because `secret-service` and `zbus` are Linux-only target dependencies of two different crates, the single
`zbus` entry in the root is shared; there is one zbus in the tree.

## 3. Lock edits to apply after the manifests change (the two-week rule for transitive packages)

After `cargo metadata`/`cargo check` resolves the new packages, run (each is verified to resolve; the order
matters only for js-sys, which carries the wasm-bindgen family with it):

```
cargo update -p aes@0.9.4        --precise 0.9.3
cargo update -p ctutils@0.4.8    --precise 0.4.6
cargo update -p inout@0.2.6      --precise 0.2.5
cargo update -p uuid@1.29.1      --precise 1.29.0
cargo update -p zcheapstr@1.2.0  --precise 1.1.0
cargo update -p js-sys@0.3.107   --precise 0.3.106   # also moves wasm-bindgen, -macro, -macro-support, -shared to 0.2.129
```

(If a later resolver run picks different "newest" versions than the ones above because crates.io moved, the
rule is the same: newest published on or before 2026-10-25. The version numbers above are what resolved on
2026-11-08.) After these, all 71 added lock packages were published on or before 2026-10-25, none yanked, all
licences MIT / MIT OR Apache-2.0 / Apache-2.0 OR MIT. In the check, no existing package in `Cargo.lock` changed
version; the lock only gained entries. The lock also gains wasm32-only entries (js-sys, 4 wasm-bindgen crates,
bumpalo) through uuid: they are never compiled here, but a future `cargo-deny`/`cargo audit` (M08) scans them.

## 4. Resolution check, real output (nothing was built; toolchain 1.99.1 via rust-toolchain; no CARGO_TARGET_DIR)

### 4a. Copy of the real workspace (manifests + committed `Cargo.lock`) plus one scratch member with the new deps

Commands: `cargo metadata --format-version 1` (resolves and updates the copied lock; exit 0; `--locked` re-run
after the precise downgrades also exit 0), `cargo tree --workspace --target <t> -e normal --prefix none | sed
's/ (.*//' | grep -v '^heimdall-' | sort -u | wc -l`, `cargo tree --workspace --target all -d -e normal`.

| Target | Unique crates before | after | delta |
|---|---|---|---|
| all targets | 204 | 272 | +68 |
| x86_64-unknown-linux-gnu | 186 | 248 | +62 (15 ssh-key `encryption`, 47 secret-service + zbus) |
| aarch64-apple-darwin | 183 | 202 | +19 (15 + security-framework, -sys, core-foundation, -sys) |
| x86_64-pc-windows-msvc | 184 | 199 | +15 (all ssh-key `encryption`) |
| x86_64-pc-windows-gnu | 185 | 200 | +15 |

`Cargo.lock`: 245 packages before; 316 after (71 added, not counting the scratch member). With `secret-service`
5.1.0 instead of 5.2.0 (the fallback): 301 packages (+56 added), Linux 233 unique crates (+47), and no new
duplicate crypto pairs.

ssh-key `encryption` adds 15: aead, aes 0.8.4, aes-gcm, bcrypt-pbkdf, blowfish, cbc 0.1.2, chacha20 0.9.1, ctr,
ghash, opaque-debug, pbkdf2, poly1305, polyval, universal-hash, block-padding 0.3.3. `ed25519` and `rand_core`
add none.

Duplicate versions already present before (unchanged): cpufeatures 0.2/0.3, getrandom 0.2/0.4, jiff-core,
rand 0.8/0.10, rand_core 0.6/0.10, syn 2/3.

Duplicate versions this adds (distinct versions only):
- Linux only, from secret-service `crypto-rust` (the RustCrypto 0.11 generation next to ssh-key's 0.10
  generation): aes 0.8/0.9, block-buffer 0.10/0.12, block-padding 0.3/0.4, cbc 0.1/0.2, cipher 0.4/0.5,
  const-oid 0.9/0.10, crypto-common 0.1/0.2, digest 0.10/0.11, hmac 0.12/0.13, inout 0.1/0.2, sha2 0.10/0.11.
- All targets, from ssh-key `encryption`: chacha20 0.9.1 next to the 0.10.2 already present.
- None for zbus, getrandom 0.4, rand_core, windows-sys, libc, rustix, tokio.

tokio feature unification (`cargo tree -e features -i tokio`): on Linux builds zbus's `tokio` feature enables
`rt-multi-thread`, `fs` and `tracing` (not enabled before). macOS and Windows builds do not gain them. No package
is added by it; the runtime selection stays in our code (`current_thread`).

### 4b. The throwaway minimal workspace the brief asked for (4 empty member crates, existing relevant pins + new)

Literal command `cargo tree --target all -e normal --prefix none | sort -u | wc -l` (this counts lines including
member crates and `(*)` markers):

| Workspace | `cargo generate-lockfile` | `cargo tree` lines, sorted unique | lock packages |
|---|---|---|---|
| base (existing pins only: serde, tokio, ssh-agent-lib, ssh-key `std`, ssh-encoding, sha2, getrandom, base64ct, libc, rustix, windows-sys) | exit 0, "Locking 88 packages" | 118 | 92 |
| new, secret-service 5.2.0 + zbus 5.19.0 | exit 0, "Locking 183 packages" | 228 | 187 |
| new, secret-service 5.1.0 + zbus 5.19.0 | exit 0 | 210 | 171 |

Distinct crates only (members excluded): base 85, new/5.2.0 172 (+87 against that small base), new/5.1.0 156.
`cargo tree --target all -d`: base lists getrandom 0.2/0.4 and syn 2/3. new/5.2.0 adds the eleven pairs above
plus cpufeatures 0.2/0.3 (already present in the real workspace); chacha20 does not show there because the
minimal workspace lacks the `rand` 0.10 package that carries 0.10.2. new/5.1.0: only getrandom
and syn (the same as base).

The scratch directories were removed (see the report).

## 5. Per-dependency facts (selected version, publish date, MSRV, licence, advisories)

| Crate | Version | Published | MSRV | Licence | Advisories for that version |
|---|---|---|---|---|---|
| ssh-key | 0.6.7 | 2024-10-15 | 1.65 | Apache-2.0 OR MIT | none (no advisory-db directory) |
| zeroize | 1.9.1 | 2026-10-06 | 1.85 | Apache-2.0 OR MIT | none |
| security-framework | 3.7.0 | 2026-02-20 | 1.85 | MIT OR Apache-2.0 | RUSTSEC-2017-0003, patched 0.1.12 (n/a) |
| security-framework-sys | 2.17.0 | 2026-02-20 | 1.70 | MIT OR Apache-2.0 | none |
| core-foundation | 0.10.1 | 2025-05-26 | 1.65 | MIT OR Apache-2.0 | none |
| core-foundation-sys | 0.8.7 | 2024-08-11 | none declared | MIT OR Apache-2.0 | none |
| secret-service | 5.2.0 | 2026-08-29 | 1.87 | MIT OR Apache-2.0 | none |
| zbus | 5.19.0 | 2026-08-09 | 1.87 | MIT | none for zbus; zvariant 5.15.1 RUSTSEC-2026-0370, zbus_names 4.3.5 -0371, zvariant_derive 5.15.1 -0372: informational `unmaintained`, 2026-10-16, no patch (merged into zbus 6) |
| windows-sys | 0.61.2 | 2025-10-06 | 1.71 | MIT OR Apache-2.0 | none |

Other advisories seen on added packages, all patched in the resolved versions: aes-gcm 0.10.3 (RUSTSEC-2023-0096,
patched 0.10.3), chacha20 0.9.1 (2019-0029), cmov 0.5.4 (2026-0003), ctutils 0.4.6 (2026-0385, patched 0.4.4),
sha2 0.11.1 (2021-0100), enumflags2 0.7.12 (2023-0035), event-listener 5.4.2 (2026-0221, patched 5.4.2),
memoffset 0.9.1 (2019-0011, 2023-0045), bumpalo 3.20.3. Existing: tokio 1.54.1 is exactly the patched version of
RUSTSEC-2026-0384.

zbus alternatives considered: 6.x (6.0.0 2026-10-16, 6.1.0 2026-10-23, 6.2.0 2026-10-29, 6.2.1 2026-11-01).
secret-service 6.0.0-rc.1 (2026-11-06) is on zbus 6 but is a release candidate younger than two weeks.

## 6. Risks and findings the integrator should know

1. **zbus 5 carries three informational "unmaintained" advisories** (zvariant, zvariant_derive, zbus_names) with no
   patched version. A future `cargo-deny` run (M08) needs a recorded ignore with a revisit trigger:
   secret-service 6.0.0 stable. (Q2.)
2. **secret-service 5.2.0 `crypto-rust` adds 11 duplicate crypto crate pairs on Linux, including sha2 0.11**, which
   dependencies.md section 1 said it wanted to avoid. 5.1.0 has zero but lacks the IV-length check. (Q1.)
3. **RNG for key generation.** `ssh-key` 0.6.7 `PrivateKey::random`/`Ed25519Keypair::random` take a `rand_core` 0.6
   `CryptoRngCore`. `rand_core::OsRng` needs `rand_core`'s `getrandom` feature, which is on in today's graph only
   because p521's `getrandom` feature is enabled through ssh-agent-lib's `ssh-key/crypto`. That is feature
   unification by accident, not a declared dependency. (Q3.)
4. **ADR-0008 §18's dependency list is incomplete for the named `sys.rs` modules:** `Win32_System_Memory`
   (VirtualLock), `Win32_System_LibraryLoader` (GetModuleHandleW), a `libc` edge and a `windows-sys` edge for
   `heimdall-credential`, and the macOS externs (`SecAccessCreate`, `SecTrustedApplicationCreateFromPath`, and
   `CGSessionCopyCurrentDictionary` with `#[link(name = "CoreGraphics", kind = "framework")]`) which are in no
   pinned crate. All are covered by the existing `unsafe` inventory entries except that the credential module's
   Windows/Unix dependency edges are new. (Q4.)
5. **tokio feature unification on Linux** (`rt-multi-thread`, `fs`, `tracing`), described above. zbus on a
   `current_thread` runtime and `block_in_place` interactions are not verified here (nothing was compiled); the
   first unit that calls zbus (U8) must test it on the devbox.
6. The root `ssh-key` pin keeps `default-features = false`; testkit's `ed25519` feature line (M02) is now redundant
   but harmless.
7. `secret-service` 5.2.0 declares `getrandom ^0.4`, the same line as the workspace's 0.4.3; no second getrandom
   0.4.

## 7. dependencies.md edits left for the integrator (not made: they rewrite existing sections)

- The file title still says "(M01 and M02 workspace)".
- Section 2's line "`zeroize` / `secrecy`: arrive with M03 key handling (already in the graph through ssh-key)":
  zeroize arrives as pinned in section 5; `secrecy` is not adopted.
- Section 3 ("Duplicate-version watch") could point to section 5's list.
- Section 1's `ssh-key` row ("ipc (M03: credentials)") and `windows-sys` row are superseded by section 5 for the
  M03 features.
