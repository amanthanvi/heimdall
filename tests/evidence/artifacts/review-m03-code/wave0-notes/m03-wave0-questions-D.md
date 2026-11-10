# Questions from subagent D (dependency pins), M03 wave 0

Each question has a default D took (recorded in dependencies.md section 5). Evidence is in
`.m03-wave0-deps.md`.

## Q1. secret-service 5.2.0 (Linux duplicates) or 5.1.0 (none)?

- ADR-0008 §18 / m03-plan U0: "pins exact versions at least two weeks old" and P3 "the dependency weight is
  recorded". dependencies.md section 1 (sha2 row) says sha2 0.11 "would duplicate sha2 in the graph".
- 5.2.0 (2026-08-29, newest eligible): GitHub release notes list "check initialization vector length" and
  "error instead of panicking in exec_prompt". Its `crypto-rust` feature uses the RustCrypto 0.11 generation:
  Linux-only duplicate pairs aes, block-buffer, block-padding, cbc, cipher, const-oid, crypto-common, digest, hmac,
  inout, sha2; +15 lock packages over 5.1.0.
- 5.1.0 (2025-09-03): uses the 0.10 generation ssh-key already has: no new duplicates; lacks the IV check and
  panics instead of erroring on a failed prompt.
- **Default taken:** 5.2.0 (custody-critical decrypt path; duplicates are Linux-only and pure Rust). Switching is
  one line in the root `Cargo.toml` plus the table row.

## Q2. Accept the three informational "unmaintained" advisories that zbus 5 brings?

- RUSTSEC-2026-0370 (zvariant), -0371 (zbus_names), -0372 (zvariant_derive), all 2026-10-16, no patched
  version. They apply to the zbus 5 line because zbus 6.0.0 merged those crates.
- Options: (a) zbus 5.19.0 + secret-service 5.2.0 now, revisit at secret-service 6.0.0 stable (rc.1 published
  2026-11-06); (b) zbus 6.x for logind plus our own Secret Service client (rejected: custody crypto we would own);
  (c) wait for secret-service 6.0.0 before pinning (blocks Linux K_ca work only; the Linux product row is already
  blocked on B11).
- **Default taken:** (a). M08's `cargo-deny` will need a recorded ignore with that revisit trigger.

## Q3. Which RNG does key generation use?

- `ssh-key` 0.6.7 key generation takes a `rand_core` 0.6 RNG. `rand_core::OsRng` exists in this graph only because
  p521's `getrandom` feature is switched on through ssh-agent-lib's `ssh-key/crypto` (feature unification by
  accident). ADR-0008 §18 names only the `rand_core` feature.
- Options: (a) add `getrandom` to the ssh-key feature list (declares it; adds no package; uses getrandom 0.2 for
  key generation while IDs use 0.4); (b) a small adapter in `heimdall-credential` implementing rand_core 0.6
  `RngCore + CryptoRng` over the pinned getrandom 0.4.3, which needs a direct `rand_core = "=0.6.4"` dependency
  (package already in the lock); (c) rely on the accident (fragile).
- **Default taken:** none applied to the manifests; the root `ssh-key` line carries exactly the ADR's three
  features. The unit that writes key generation (U2/U3) decides between (a) and (b). (b) keeps one OS-entropy path.

## Q4. ADR-0008 §18's dependency list is missing items its own `sys.rs` modules need

- `crates/credential/src/sys.rs` (mlock/VirtualLock/prctl/setrlimit) needs `libc` (Unix) and `windows-sys` with
  `Win32_System_Memory` (Windows) as `heimdall-credential` dependencies; the ADR lists neither.
- `crates/runtime/src/session_lock/sys.rs` (message-only window) needs `Win32_System_LibraryLoader`
  (`GetModuleHandleW`).
- macOS externs that exist in no pinned crate (checked in security-framework 3.7.0, security-framework-sys 2.17.0,
  core-foundation 0.10.1, core-foundation-sys 0.8.7): `SecAccessCreate`, `SecTrustedApplicationCreateFromPath` (issuer
  `sys.rs`), `CGSessionCopyCurrentDictionary` (runtime `sys.rs`, `#[link(name = "CoreGraphics", kind = "framework")]`).
  The `unsafe` inventory already names these modules, but the inventory text does not say these three functions are
  hand-declared.
- **Default taken:** D recorded all of them in dependencies.md section 5 and put `Win32_System_Memory` and
  `Win32_System_LibraryLoader` in the proposed root windows-sys list. Request to the integrator: have ADR-0008 §18
  and m03-plan U0's unsafe-inventory rows say so (D does not own those files).
