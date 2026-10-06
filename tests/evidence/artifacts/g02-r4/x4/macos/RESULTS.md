# G02 round 4, X4 (macOS): native secure storage, Secure Enclave and signed bundle, Go vs Rust

Task `M00-T05-r4-x4-macos`. Status: **verified** for the three spikes as scoped. Provisioned
(profile-signed) bundle: **blocked** (see §5). Host: macOS 27.0 (26A428), arm64, Apple M5 Max.
Toolchains: go1.27.1, rustc/cargo 1.99.0, Apple clang 21.0.0, macOS SDK 27.0. Final harness run
2026-10-06T06:02:09Z to 06:02:19Z (`transcript.log`); Linux cross-build run 05:58:45Z to 05:59:13Z
(`cross-linux.log`). `run.sh` ran three times while the harness was developed, with the same
results each time. These are disposable G02 spikes, not production code.

Labels: **[O]** observed in the named log; **[S]** Apple source in `sources/`; **[I]** inference;
**[U]** unknown or untested.

Three implementations were built, because Go has two realistic routes:

- **go**: cgo calling Security.framework directly (C helpers in the cgo preamble). keybase/go-keychain
  could not be used. Its only published version, v0.0.1, exposes no way to target a file keychain
  and no SecKey API (`library-survey.log`, grep exit 1), so it can only reach the default search
  list (the login keychain) or the data-protection keychain.
- **go-purego**: no cgo. Security.framework is called through `github.com/ebitengine/purego` v0.11.1
  (dlopen/dlsym), built with `CGO_ENABLED=0`.
- **rust**: `security-framework` 3.7.0, `security-framework-sys` 2.17.0 and `core-foundation`
  0.10.1. The security-framework crate carries the maintenance badge `looking-for-maintainer`
  (`library-survey.log`).

## 1. Functional results (exit codes are real; see `transcript.log`)

| Item | go (cgo) | go-purego (no cgo) | rust |
|---|---|---|---|
| (1) Generic password in a disposable file keychain (`security create-keychain` via `security -i`; never in the search list) | open/add/read 0; delete 0; read after delete −25300; **exit 0**. Independent `security find-generic-password` afterwards exit 44 (not found) [O] | same, **exit 0**, find exit 44 [O] | same, **exit 0**, find exit 44 [O] |
| Keychain API used | `SecKeychainOpen`, `SecKeychainAddGenericPassword`, `SecKeychainFindGenericPassword`, `SecKeychainItemDelete` (all deprecated, so the build needs `-Wno-deprecated-declarations`) | same functions, called through dlsym | `SecKeychain::open`, `add_generic_password`, `find_generic_password` (the same deprecated C functions underneath). Delete goes through `ItemSearchOptions…keychains(&[kc]).delete()` (SecItemDelete) because the crate's `SecKeychainItem::delete()` throws away its OSStatus (`library-survey.log`) |
| (2) Ephemeral Secure Enclave P-256 key (`kSecAttrIsPermanent=false`, `privateKeyUsage`, `WhenUnlockedThisDeviceOnly`) | created; token = Secure Enclave; private key export refused; public key 65 bytes; ECDSA-SHA256 sign OK; verify true; tampered verify false; **exit 0** [O] | same, **exit 0** [O] | same, **exit 0** [O] (the crate sets `kSecAttrIsPermanent=false` when no location is given) |
| … from the plain CLI binary | works. The binary is only **linker ad-hoc signed** (`flags=0x20002(adhoc,linker-signed)`), with no entitlements [O] | same [O] | same [O] |
| … with the signature removed (`codesign --remove-signature`) | killed, **exit 137** [O] | **exit 137** [O] | **exit 137** [O] |
| Data-protection keychain, read-only probe (`SecItemCopyMatching`, `kSecUseDataProtectionKeychain`) | no access group: −25300 (not found). Explicit unentitled group: **−34018** (errSecMissingEntitlement); exit 1 by design [O] | same [O] | same [O] |
| (3) App-like bundle, `Info.plist` + empty entitlements, ad hoc with hardened runtime | codesign 0; `--verify --strict --deep` 0; `spctl --assess` **3 (rejected)**; SE probe 0; keychain round trip 0 [O] | same [O] | same [O] |
| Same bundle with restricted entitlements (`keychain-access-groups`, `com.apple.application-identifier`, `com.apple.developer.team-identifier`; placeholder team) | codesign 0; verify 0; spctl 3; **exec killed, exit 137**. amfid: `Code=-424 "The file is adhoc signed but contains restricted entitlements"` [O] | same, exit 137; kernel: `Code has restricted entitlements, but the validation of its code signature failed.` [O] | same, exit 137, amfid −424 [O] |

Platform findings (the same for all three implementations):

- On Apple silicon, "unsigned CLI" in practice means *linker ad-hoc signed*. Both linkers add
  that signature by default, and a binary with no signature at all is killed at exec [O].
- An **ephemeral** Secure Enclave key needs no entitlement, profile or bundle [O]. TN3137 lists
  "Protecting a key with the Secure Enclave" among the features that require the data-protection
  keychain [S]. The [I] is that this requirement applies to *storing* the key (permanent keys),
  not to an in-memory SE key. An ephemeral key is gone when the process exits, so on its own it
  cannot be a persistent K_env [I].
- A persistent hardware-backed key without the data-protection keychain is [U]. CryptoKit exposes
  `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation` ("A data representation of the private
  key") [S], but it is a Swift API, and storing and restoring that blob from Go or Rust was not tested.
- A read-only data-protection query with no access group returns −25300 for an unentitled process,
  so it does **not** reveal a missing entitlement. A query naming a group does (−34018) [O].
- The amfid "−423 adhoc signed" lines for the unrestricted bundles are logged, but the
  processes ran [O].

## 2. Cost per language

Sizes come from `transcript.log` §1. The "hello" baselines are built the same way and live in
`go/baseline-hello`, `rust/baseline-hello`.

| Metric | go (cgo) | go-purego | rust |
|---|---|---|---|
| Library | none usable (go-keychain v0.0.1 lacks file-keychain and SecKey). Hand-written cgo | `ebitengine/purego` v0.11.1, plus hand-written CF/Sec bindings | `security-framework` 3.7.0 (+ `-sys` 2.17.0, `core-foundation` 0.10.1, `libc`, `bitflags`) |
| cgo / unsafe / FFI | **cgo required**: 97 lines of C in the preamble, 28 `C.*` references, 9 `unsafe.Pointer`. `CGO_ENABLED=1` is recorded in the build info [O] | **No cgo** (`CGO_ENABLED=0` in the build info [O]). Still FFI: 22 functions plus 21 constant/data symbols resolved by dlsym, 5 `unsafe.*` uses, hand-maintained C signatures with no compiler type checking | FFI is wrapped by the crate. The spike has **2 `unsafe` blocks**, used only to read the extern statics `kSecAttrTokenID`/`…SecureEnclave` for the token check. The crate is unsafe internally |
| Linked libraries (`otool -L`) | + Security, CoreFoundation (and libSystem, libresolv) [O] | libSystem and libresolv only. Frameworks are dlopened at run time [O] | + Security, CoreFoundation, libiconv (and libSystem) [O] |
| Size, default build (spike − hello) | 2,902,402 − 2,396,642 = **+505,760 B** | 3,091,698 − 2,396,642 = **+695,056 B** | 511,664 − 435,088 = **+76,576 B** |
| Size, stripped (`-s -w` / `strip=symbols`) | 1,813,874 − 1,571,202 = **+242,672 B** | 2,045,762 − 1,571,202 = **+474,560 B** | 393,792 − 342,720 = **+51,072 B** |
| Lines of code (non-blank, non-comment) | 208 (main.go 57 + native_darwin.go 151, of which 97 are C) | 228 (one file) | 134 |
| Build steps (macOS host) | Xcode CLT (clang + SDK); `go build -trimpath` (exit 0) | `CGO_ENABLED=0 go build -trimpath` (exit 0); module pinned by go.sum | `cargo build --release --locked` (exit 0); clippy `-D warnings` 0; fmt 0 |
| Cross: darwin/arm64 host → darwin/amd64 | `GOARCH=amd64 CGO_ENABLED=1` exit 0 (Apple clang) [O] | `CGO_ENABLED=0 GOARCH=amd64` exit 0 [O] | not tested (target not installed; installing it writes outside the granted paths) [U] |
| Cross: **Linux container with no macOS SDK** → darwin/arm64 | `CGO_ENABLED=0`: **exit 1** (the cgo file is excluded, so its symbols are undefined). `CGO_ENABLED=1 CC="zig cc -target aarch64-macos"`: **exit 1** (`CoreFoundation/CoreFoundation.h` not found) [O] | **exit 0**. The Linux-built binary (Go linker ad-hoc signed) ran `se` on this Mac with **exit 0**, without re-signing [O] | Rust code compiles. **Link fails**: system `cc` exit 101; `cargo zigbuild` exit 101 (`unable to find framework 'Security'` / `'CoreFoundation'`). Baseline hello: cc 101, zigbuild **0** [O] |
| Effect on the cgo-free / static story | Loses `CGO_ENABLED=0` and SDK-free cross builds for darwin. On darwin, Go binaries are dynamic (libSystem) whatever the setting [O] | Keeps `CGO_ENABLED=0` and Linux-hosted darwin builds; still dynamic on libSystem [O] | Never static on darwin. Linking frameworks makes a darwin build need a macOS SDK (or a macOS runner). A dlopen-based Rust variant (e.g. libloading) would avoid that, but it is untested [U] |

## 3. What a provisioning profile would add (sources, not observed)

- `keychain-access-groups` and the App ID entitlement (`com.apple.application-identifier`) are
  **restricted** entitlements: "restricted entitlements must be authorized by a provisioning profile",
  so that "other developers can't impersonate your app in order to steal its keychain items" [S:TN3125].
  The ad-hoc restricted bundle above was killed with amfid −424, which matches this [O].
- "macOS builds the list of data protection keychain access groups available to your program from its
  code signing entitlements … These entitlements must be authorized by a provisioning profile. Your
  program needs an app-like bundle structure in which to embed that profile" [S:TN3137]. The profile
  goes at `X.app/Contents/embedded.provisionprofile` [S:TN3125]. "A standalone executable can't claim
  a restricted entitlement" [S:TN3125]. Apple's wrapper recipe: *Signing a daemon with a restricted
  entitlement* [S].
- With a profile, the bundle could use the data-protection keychain, persistent (keychain-stored)
  Secure Enclave keys, and biometric access control [S:TN3137]. It works only in a user login
  context, not from a launchd daemon [S:TN3137].
- Developer ID profiles have `ProvisionsAllDevices` and an expiry "far in the future"; other profiles
  are typically valid for no more than a year and list devices [S:TN3125]. "Some entitlements are not
  supported by Developer ID profiles". Whether `keychain-access-groups` is one of them was not
  established here [U].
- Gatekeeper rejected every ad-hoc bundle (`spctl --assess` exit 3) [O]. Developer ID signing (and,
  [I], notarization) is needed for distribution. Both are owner-held (G04 D3).
- None of this depends on the language. The profile, signature and bundle wrap whatever Mach-O the
  Go or Rust build produces. Both languages produced bundles that codesign and verify identically [O].

## 4. Reading for ADR-0002 (inference, for the re-scoring reviewers)

- **Functional parity [O].** All three implementations did every probe with the same results. X4
  does not separate the languages on capability.
- **Rust** has a safe high-level wrapper: fewest lines (134), smallest size delta (+77 KB), 2 small
  `unsafe` blocks. Costs: a crate flagged as needing a maintainer, one API that silently drops an
  error status, and darwin builds that need the macOS SDK at link time (no SDK-free Linux cross build
  observed).
- **Go** has no maintained high-level library that covers file keychains and SecKey. It needs either
  cgo (C in the repo, a C toolchain and SDK, loses `CGO_ENABLED=0`) or purego (keeps a cgo-free,
  Linux-buildable darwin binary that was shown working on the Mac, but needs hand-written untyped
  bindings: 228 LOC, +695 KB).
- D3 will in any case put a macOS signing step (Developer ID, provisioning profile) into releases
  [I]. That narrows purego's cross-build advantage. Signing from Linux (e.g. `rcodesign`) was not
  examined [U].

## 5. Blocked or not tested

- **Blocked:** provisioned bundle, data-protection keychain writes, and persistent Secure Enclave
  keys. These need an Apple Developer membership, team ID, App ID and provisioning profile (G04 D3),
  plus a disposable macOS user or VM, because a successful write would land in the owner's real
  data-protection keychain. See `records/g02-r4-x4-macos-provisioned-bundle.json`.
- Not tested [U]: the CryptoKit `dataRepresentation` persistence route; Rust dlopen variant; Rust
  x86_64-apple-darwin; Linux cross builds with a supplied MacOSX.sdk (SDK licence terms not
  checked); lock, sleep and logout behaviour (G04 P-probes); wall-clock times.
- The `go spike GOOS=linux` exit 1 in `transcript.log` §6 is expected by construction (the spike is
  darwin-only, with no stub file). It is not a finding.

## 6. Files

- `run.sh` → `transcript.log`: builds, sizes, keychain, SE, data-protection probe, unsigned,
  bundles, host cross builds, LOC. `cross-linux.sh` → `cross-linux.log`: Linux container builds,
  plus a run of the Linux-built purego binary. `library-survey.sh` → `library-survey.log`.
- `go/` (cgo spike + baseline), `go-purego/`, `rust/` (Cargo.lock pinned; `baseline-hello/`),
  `bundle/` (Info.plist template, entitlement plists).
- `sources/`: Apple JSON docs as extracted text, with `MANIFEST.tsv` (URL, HTTP code, sha256, fetch
  time). The TN3137 sha256 equals the copy retained for G04 on 2026-10-03.
- `records/`: record-shaped JSON (`tests/evidence/record.schema.json`, all required keys present)
  for the orchestrator to place under `tests/evidence/`.
- Cleanup [O]: no disposable keychain directory left; the user keychain search list and default
  keychain digests are unchanged; containers ran with `--rm` (0 left with label
  `heimdall.x4.scratch`); scratch build output is under `/tmp/hm-r4/M00-T05-r4-x4-macos/`.
