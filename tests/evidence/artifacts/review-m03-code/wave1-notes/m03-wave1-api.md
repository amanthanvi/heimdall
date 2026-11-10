# M03 wave 1: shared readings and landed interfaces (untracked; integrator + units)

Read the code for exact signatures. Each unit appends what it lands to **its own section**, as
soon as it compiles. Requests to another unit go under "Requests".

## 0. Landed by the integrator before the units started

**Module declarations (reserved files):**
- `crates/app/src/lib.rs`: `pub mod lock;` → `crates/app/src/lock.rs` (U9; placeholder doc only).
- `crates/runtime/src/lib.rs`: `pub mod session_lock;` → `crates/runtime/src/session_lock/mod.rs`
  (U9; placeholder). U9 adds `mod macos; mod windows; mod linux; mod sys;` inside its own `mod.rs`.
- `crates/testkit/src/lib.rs` (U11; placeholders): `ca` (features fixtures+managed),
  `installation` (fixtures), `lock` (managed), `managed` (fixtures+managed), `owner_digest`
  (fixtures), `procstat` (fixtures), `registry` (fixtures), `shells` (fixtures). `sshd.rs`
  (fixtures) and `session_lock.rs` (managed, wave 0's full `FakeSessionLockSource`) already exist;
  `scratch_store.rs` (managed) is U4's.
- Crate-internal module declarations of the new crates already exist (`credential::{cert, vault,
  purpose, session_bind, …}`, `issuer::{backup, bundle, ceremony, retire, store, …}`,
  `registry::{line, script, step, hm1, post_image, classify, fence, plan}`, `enroll::{remote,
  verify, trace}`). **Adding a new module inside your own crate's `lib.rs`** (e.g. `credential::sys`,
  `issuer::sys`, `issuer::store::{macos,windows,linux}` in `store/mod.rs`, `localenv::target`):
  `crates/credential/src/lib.rs`, `crates/issuer/src/lib.rs`, `crates/issuer/src/store/mod.rs`,
  `crates/localenv/src/lib.rs`, `crates/enroll/src/lib.rs`, `crates/registry/src/lib.rs` are **not**
  reserved, but they are shared by several units: change **only** the one `mod` line (plus its
  `#[cfg]` and one comment line) you need, re-read the file right before editing, and record it.

**Test targets (`[[test]]`, path `../../tests/<layer>/<name>.rs`; placeholder files exist):**

| Target | File | Host crate | Unit |
|---|---|---|---|
| `integration_credential_cert` | `tests/integration/credential_cert.rs` | heimdall-credential | U1 |
| `integration_credential_memory` | `tests/integration/credential_memory.rs` | heimdall-credential | U1 |
| `adversarial_signer_requests` | `tests/adversarial/signer_requests.rs` | heimdall-credential | U1 |
| `integration_issuer_store` | `tests/integration/issuer_store.rs` | heimdall-issuer | U4 |
| `e2e_issuer_ceremony` | `tests/e2e/issuer_ceremony.rs` | heimdall | U4 |
| `model_registry_pure` | `tests/model/registry_pure.rs` | heimdall-registry | U5-pure |
| `integration_enroll_registry` | `tests/integration/enroll_registry.rs` | heimdall-enroll | U5-scripts |
| `integration_enroll_verify` | `tests/integration/enroll_verify.rs` | heimdall-enroll | U5-io |
| `integration_session_lock` | `tests/integration/session_lock.rs` | heimdall-runtime | U9 |
| `model_lock_behavior` | `tests/model/lock_behavior.rs` | heimdall-app | U9 |
| `integration_testkit_m03` | `tests/integration/testkit_m03.rs` | heimdall-testkit (req. fixtures+managed) | U11 |

**Dev-dependencies added:** credential: testkit[fixtures], proptest, tempfile, tokio. issuer:
testkit features `managed`,`fixtures` (was none), tempfile. registry: proptest, testkit (no
default features; `repo::repo_root`), serde_json. enroll: testkit[fixtures, managed],
credential, localenv, proptest, tempfile, tokio[test-util]. runtime and app: testkit now with
`managed`. **Production deps added:** credential: `getrandom`, `thiserror` (both already pinned;
D-Q3 ruling). Cargo.lock changed only in `heimdall-*` dependency arrays.

**`heimdall_credential::vault::SystemRng`** (landed; U1 owns the file from now on):
- `SystemRng::fill(&mut [u8]) -> Result<(), RandomnessUnavailable>`: the OS CSPRNG via getrandom
  0.4 (ADR-0008 §17.15 item 11, D-Q3). **Use it for every random value** (keys, serials, vault
  slots, backup salt, passphrases).
- implements `ssh_key::rand_core::{RngCore, CryptoRng}` (rand_core 0.6, re-exported by ssh-key);
  `fill_bytes` aborts the process on CSPRNG failure (fail closed), `try_fill_bytes` returns an error.
  Never use `rand_core::OsRng` (enabled only by accidental feature unification).

**`heimdall_credential::cert::SecretCaKey`** (landed; U1 owns the file from now on; U4 builds on it):
- `generate() -> Result<SecretCaKey, CaKeyError>` (Ed25519, seed from `SystemRng`, empty comment);
- `from_private_key(PrivateKey)`, `public_key() -> &PublicKey`,
  `public_openssh() -> Result<String, CaKeyError>` (`ssh-ed25519 AAAA…`, no comment),
  `fingerprint() -> Result<CaFingerprint, CaKeyError>` (`SHA256:…`);
- `to_secret_bytes() -> Result<Zeroizing<Vec<u8>>, CaKeyError>` (unencrypted OpenSSH PEM, LF; for a
  platform store to protect) and `from_secret_bytes(&[u8]) -> Result<SecretCaKey, CaKeyError>`
  (refuses encrypted / non-Ed25519);
- `encrypt_openssh(passphrase: &[u8]) -> Result<Vec<u8>, CaKeyError>` (the D5 form: OpenSSH,
  bcrypt-pbkdf + aes256-ctr, LF) and `decrypt_openssh(bytes, passphrase) -> Result<SecretCaKey,
  CaKeyError>` (`Malformed` if not an encrypted key, `WrongPassphrase` otherwise);
- `same_key(&SecretCaKey) -> bool`; `pub(crate) private_key()` for `build_and_sign`.
- No `Clone`/`Debug`/`Display`/serde. `CaKeyError { RandomnessUnavailable, Malformed,
  WrongPassphrase, Encoding }`.

**Cross-target helper:** `bash .m03-wave1-xcheck.sh linux|windows -p <pkg> …` (clippy
`--all-targets -D warnings` for the cross triple, zig shims in a removed mktemp dir).

## 1. Readings for all units (integrator)
- **Docker-gated tests:** `#[ignore = "docker: …"]` + body asserts `HM_DOCKER_TESTS=1` (brief §4).
- **Owner-input-blocked tests:** `#[ignore = "blocked: Bn (…)"]`, platform-cfg'd where relevant.
- **Later-unit dependencies:** fake the frozen port in the test, or report "not done: needs Uxx".
- **Wave-0 provisional readings in scope** stay unless you escalate them (brief §6).

## U1 (credential core): landed interfaces
(U1 appends here.)

**`heimdall_credential::cert` (landed, compiles; `cargo clippy -p heimdall-credential -- -D warnings` exit 0):**
```rust
pub const VALID_AFTER_SKEW_SECONDS: i64 = 60;
pub const NONCE_BYTES: usize = 32;
pub fn key_id(environment: &EnvironmentId, grant: &GrantId, serial: u64) -> String; // "heimdall:<env>:<grant>:<serial decimal>"
pub fn valid_after_for(issued_at: Timestamp) -> Option<Timestamp>;                  // issued_at − 60 s, whole seconds
pub fn unix_seconds(t: Timestamp) -> i64;                                           // truncation used by sign and validate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateProfile { pub serial: u64, pub key_id: String, pub principal: String,
    pub valid_after: i64, pub valid_before: i64, pub extensions: BTreeSet<String>,
    pub subject_fingerprint: String, pub ca_fingerprint: Option<CaFingerprint> }
impl CertificateProfile { pub fn from_bounds(bounds: &CertificateBounds) -> CertificateProfile; }
pub fn build_and_sign(profile: &CertificateProfile, subject: &PublicKey, ca: &SecretCaKey)
    -> Result<ssh_key::Certificate, CertError>;
pub enum CertError { InvalidProfile(&'static str), SubjectMismatch, CaMismatch,
    RandomnessUnavailable, Signing, SelfCheck(CertRefusal) }            // #[non_exhaustive], Copy
pub fn validate_installed(cert: &Certificate, reserved: &CertificateBounds,
    subject_fp: &str /* SHA256:… of K_env/K_verify */, ca_fp: &CaFingerprint) -> Result<(), CertRefusal>;
pub enum CertRefusal { NoReservedCa, WrongCa, BadSignature, WrongSubject, NotUserCertificate,
    PrincipalCount { count: usize }, WrongPrincipal, CriticalOption, ExtensionOutsideReserved,
    ExtensionMissing, ExtensionData, ValidAfterMismatch, ValidBeforeMismatch, KeyIdMismatch,
    SerialMismatch }                                                    // #[non_exhaustive], Copy; .code() -> &'static str
```
Notes for test authors (U4, U5, U11): `build_and_sign` signs **exactly** the profile: the
subject's `SHA256:` fingerprint must equal `profile.subject_fingerprint`, and `ca.fingerprint()`
must equal `profile.ca_fingerprint` (`Some`), else `SubjectMismatch`/`CaMismatch`.
`valid_before > valid_after >= 0` (Unix seconds). To sign a test certificate: build a
`CertificateBounds` (or a `CertificateProfile` directly) with
`subject_fingerprint: subject.fingerprint(HashAlg::Sha256).to_string()` and
`ca_fingerprint: Some(ca.fingerprint()?)`; extensions are flag names (`permit-pty`, …). The
`SecretCaKey` API above is unchanged.

**`heimdall_credential::vault` (landed; U2, U6, U10 build on it):**
```rust
pub struct VaultSlot([u8; 16]);  // Copy, Eq, Hash, Ord, Debug, Display(hex)
impl VaultSlot { pub fn to_hex(&self) -> String /* 32 lowercase hex = key_handle_ref */;
                 pub fn from_hex(&str) -> Option<VaultSlot>; }
pub struct PublicKeyInfo { pub openssh_line: String /* "ssh-ed25519 AAAA…", no comment */,
                           pub blob: Vec<u8>, pub fingerprint: String /* SHA256:… */ }
impl PublicKeyInfo { pub fn public_key(&self) -> Result<ssh_key::PublicKey, VaultError>; }
pub enum VaultError { RandomnessUnavailable, NoSuchSlot, Unavailable, InvalidSeed, Signing, Encoding } // non_exhaustive, Copy
pub struct SecretKey { /* private; no Clone/Debug/Display/serde; never handed out */ }
pub struct KeyVault;  // Send + Sync; Debug shows only the key count; Drop zeroizes every key
impl KeyVault {
    pub fn new() -> KeyVault;
    pub fn generate_ed25519(&self) -> Result<(VaultSlot, PublicKeyInfo), VaultError>;
    pub fn sign(&self, slot: &VaultSlot, data: &[u8]) -> Result<Vec<u8>, VaultError>; // SSH signature blob (string "ssh-ed25519", string sig[64]) = SIGN_RESPONSE's field
    pub fn destroy(&self, slot: &VaultSlot);          // idempotent, works on a poisoned lock
    pub fn destroy_all(&self);
    pub fn contains(&self, slot: &VaultSlot) -> bool; // restart recovery: installed + !contains => lost
    pub fn public_key(&self, slot: &VaultSlot) -> Option<PublicKeyInfo>;
    pub fn pages_locked(&self, slot: &VaultSlot) -> Option<bool>; // Some(false) = degraded mitigation (D1)
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    #[cfg(debug_assertions)] pub fn with_test_seed(seed: &[u8] /* 1..=64 bytes */) -> Result<KeyVault, VaultError>;
}
#[cfg(debug_assertions)]
pub fn seeded_private_key(seed: &[u8], index: u64) -> Option<Zeroizing<[u8; 32]>>;
// = SHA-256(b"heimdall-test-key-seed/k_env/v1\0" || u64_be(index) || seed), U11's rule (Requests).
```
`sign` is synchronous CPU work: U2 runs it on the blocking pool under `signing_budget`. The
test-seed gate is `cfg(debug_assertions)` (the project's test configuration, `testcfg::AVAILABLE`),
so U10's wiring of `HEIMDALL_TEST_KEY_SEED` must be `cfg(debug_assertions)` too.

**`heimdall_credential::purpose` (landed; U2's signer calls it before authorization):**
```rust
pub fn parse_userauth(data: &[u8]) -> Result<UserAuthRequest, PurposeRefusal>;
pub struct UserAuthRequest { pub session_id: Vec<u8>, pub user: String, pub method: UserAuthMethod,
                             pub algorithm: String, pub key_blob: Vec<u8> }
pub enum UserAuthMethod { Publickey, PublickeyHostbound { server_host_key: Vec<u8> } }
pub struct GrantCertificates;   // Clone; one certificate per pair + the plain key (always refused)
impl GrantCertificates {
    pub fn new(grant_key: &PublicKey) -> Result<Self, GrantCertificateError>;
    pub fn add(&mut self, pair: AccessPair, cert: &Certificate) -> Result<(), GrantCertificateError>; // subject = grant key, principals == [principal_for(pair)], one per pair
    pub fn remove(&mut self, pair: &AccessPair) -> bool;
    pub fn blobs(&self) -> impl Iterator<Item = &[u8]>;   // what the endpoint lists
    pub fn plain_key(&self) -> &[u8]; pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
}
pub enum GrantCertificateError { SubjectNotGrantKey, PrincipalNotPair, DuplicatePair, Encoding }
pub fn check(request: &UserAuthRequest, grant_certs: &GrantCertificates, flags: u32) -> Result<PairRef, PurposeRefusal>;
pub struct PairRef { pub pair: AccessPair, pub serial: u64 }
pub fn check_bound(request: &UserAuthRequest, bind: &ipc::signing::SessionBindRecord) -> Result<(), PurposeRefusal>; // D2 item 5
pub enum PurposeRefusal { Oversize, Sshsig, Malformed, SessionIdLength, NotUserAuth, NotUtf8, WrongService,
    UnsupportedMethod, NotSigned, EmptyKey, TrailingBytes, PlainKeyRefused, KeyNotInGrant,
    AlgorithmMismatch, FlagsNotPermitted, WrongUser, SessionMismatch, HostKeyMismatch } // .code()
pub const MAX_USERAUTH_BYTES: usize = 32 * 1024; pub const MAX_SESSION_ID_BYTES: usize = 128;
```

**`heimdall_credential::session_bind` (landed; U2's `Signer::session_bind`):**
```rust
pub use ssh_agent_lib::proto::extension::SessionBind; // { host_key: KeyData, session_id, signature, is_forwarding }
pub fn parse(payload: &[u8] /* contents after the extension name */) -> Result<SessionBind, SessionBindError>;
pub fn verify(bind: &SessionBind) -> bool;            // Ed25519, ECDSA P-256/384/521, RSA (rsa-sha2-256/512)
pub fn accept(payload: &[u8]) -> Result<(SessionBind, SessionBindRecord), SessionBindError>; // parse + verify; store the record in SigningSession::bind
pub enum SessionBindError { Malformed, SessionIdLength, UnsupportedHostKey, BadSignature } // .code()
```

**`heimdall_credential::sys` (landed; the crate's only `unsafe`):**
```rust
pub fn lock_pages(buf: &mut [u8]) -> MemLock;          // never fails; unlocked MemLock = degraded
pub struct MemLock; impl MemLock { pub fn none() -> MemLock; pub fn is_locked(&self) -> bool;
                                   pub fn os_error(&self) -> Option<i32>; pub fn len(&self) -> usize; }
pub fn page_size() -> usize;
pub fn harden_process() -> HardeningReport;            // U10: at runtime start; U3: in the issuer child; before any key
pub struct HardeningReport { pub dumpable: Option<bool> /* Linux */, pub core_limit: Option<u64> /* soft, read back */, pub mlock_ok: bool }
```
Manifest (credential): `ssh-key` now names feature `crypto`; new deps `ssh-encoding`,
`ssh-agent-lib`, `sha2` (workspace pins); dev-dep `serde`. Cargo.lock: only the
heimdall-credential dependency array (+ `serde`, `sha2 0.10.9`, `ssh-agent-lib`, `ssh-encoding`).

## U4 (issuer stores, backup, ceremonies, retire, bundle): landed interfaces
(U4 appends here.)

**Landed 2026-11-10 (compiles; `cargo clippy -p heimdall-issuer --lib -- -D warnings` 0 on host,
linux and windows cross).** Read the module docs for details.

`store` (the frozen trait unchanged; mod lines + re-exports only): `MacosLoginKeychain`
(macOS) `::login(account_home: &Path, &EnvironmentId)` (`<home>/Library/Keychains/login.keychain-db`;
pass localenv's account home, never `$HOME`); test configuration only (`cfg(debug_assertions)`):
`::disposable_file_keychain(path, &EnvironmentId)`, `::create_disposable_file_keychain(path,
password)`, `::lock_disposable_file_keychain(path)`, `::delete_disposable_file_keychain(path)`.
Kind `Product(MacosLoginKeychain)`; item = generic password, service = label =
`heimdall-issuer/<fp>`, account = environment ID, SecAccess trusting only this executable; reads
with interaction disabled; `errSecInteractionNotAllowed` **and `errSecAuthFailed`** (what a locked
keychain returns here, observed) → `Unavailable(InteractionNotAllowed)`; `availability()` reads
`SecKeychainGetStatus` (locked → `Locked`, absent → `Missing`). Locator
`service=<label>;account=<env>`. `WindowsDpapi` (Windows) `::default_dir()`
(`%LOCALAPPDATA%\Heimdall\issuer`), `::in_dir(dir, &EnvironmentId)` (product kind also for a
scratch dir under `HEIMDALL_HOME`), `blob_path(&fp)`, `::dacl_sddl(path)`, `::expected_blob_dacl()`;
blob `<dir>\sha256-<64 hex>.dpapi`, CurrentUser, entropy `heimdall-issuer/1 K_ca dpapi entropy\0`‖fp,
`CRYPTPROTECT_UI_FORBIDDEN`, created `CREATE_NEW` with `D:P(A;;FA;;;<user>)` (dir `OICI`).
`LinuxSecretService` (Linux) `::new(&EnvironmentId)`: login collection
(`/org/freedesktop/secrets/collection/login`), DH session, attributes `heimdall_application=
heimdall-issuer`, `heimdall_ca_fingerprint`, `heimdall_environment_id`; each call on its own
current-thread runtime on a scoped thread under `OPERATION_BOUND` (5 s); never unlocks (no prompt).
`store::StoredCaKey` = re-export of `heimdall_credential::cert::SecretCaKey` (for implementors
without that dependency). `delete` → `Err(NotFound)` when the item is absent.

`heimdall_testkit::scratch_store::ScratchSecretStore` (managed): `new(dir)` (frozen),
`with_availability(dir, StoreAvailability)` (reports it and refuses all with it, writes nothing),
`dir()`, `item_path(&fp)`. Kind `Test("scratch_test")`. Items `<dir>/sha256-<hex>.key` in the D5
form under a per-run passphrase in `<dir>/scratch-store.passphrase` (0600, created on first put;
another process of the run reads it).

`backup`: `Passphrase::{new, from_utf8(Vec<u8>) -> Option, generate() -> Result, expose, grouped()
-> Zeroizing<String>, normalized_generated()}`; `PASSPHRASE_SYMBOLS = 26`; `sha256_hex(&[u8])`;
`fingerprint_file_stem(&CaFingerprint) -> String` / `fingerprint_from_file_stem(&str) ->
Option<CaFingerprint>` (case-insensitive-safe names); `prepare(&SecretCaKey, &Passphrase) ->
Result<PreparedBackup { pub bytes, pub sha256, .. }, BackupError>` (+ `public_key()`);
`write_exact(path, &PreparedBackup) -> Result<BackupInfo { sha256, created_at }, BackupError>`
(O_EXCL 0600 / owner-only DACL, fsync file + dir, read back, digest + decrypt compared);
`write_exact_probed(path, &PreparedBackup, &mut dyn WriteProbe)`; `read(path) -> BackupFile { bytes,
sha256 }` (+ `decrypt(&Passphrase)`, also tries the normalized generated form); `restore(path,
&Passphrase) -> Result<SecretCaKey, BackupError>`. `BackupError` gains `RandomnessUnavailable,
Malformed, Encoding, Interrupted`. Test seams: `WriteProbe { partial(path, written) -> Result<(),
Interrupted>, before_read_back(path) }`, `NoProbe`.

`ceremony` (U12 implements `Tty` for nothing: use `ControllingTerminal`; U12 implements
`OwnerSession` over IPC):
```rust
pub trait Tty { fn write_text(&mut self, &str) -> io::Result<()>; fn read_line(&mut self) -> io::Result<Option<Zeroizing<String>>>;
                fn read_hidden(&mut self) -> io::Result<Option<Zeroizing<String>>>; fn clear_lines(&mut self, usize) -> io::Result<()>; }
pub struct ControllingTerminal; ControllingTerminal::open() -> Result<Self, CeremonyError /*NotATerminal*/> // /dev/tty; CONIN$/CONOUT$
pub trait OwnerSession { fn attend(&mut self) -> Result<(), SessionError>; fn status(&mut self) -> Result<IssuerStatus, SessionError>;
    fn register(&mut self, &RegisterRequest) -> Result<RegisterDecision, SessionError>;   // wire: request.to_issuer_request()?
    fn approve(&mut self, &DecisionId) -> Result<(), SessionError>;                      // Decide approve
    fn unlock(&mut self) -> Result<IssuerStatus, SessionError>; }                        // issuer.unlock
pub struct RegisterRequest { ca_public_key, store: SecretStoreKind, backup_sha256, backup_created_at, rotation_of, restored_without_log }
RegisterRequest::to_issuer_request(&self) -> Result<IssuerRequest, CeremonyError>  // Test kind → TestStoreNotRegistrable (S3, U4-Q1)
pub struct RegisterDecision { decision_id: DecisionId, ca_fingerprint, backup_sha256, disclosures: Vec<DisclosureKind> }
pub enum SessionError { Refused { code: Code, reason: Option<String> }, Unavailable }
pub fn init(tty, client, store: &dyn SecretStore, &InitOptions { backup_out, non_interactive }) -> Result<Registered, CeremonyError>;
pub fn rotate_begin(tty, client, store, &InitOptions) -> Result<Registered, CeremonyError>;   // rotation_of = newest active CA
pub fn restore(tty, client, store, &RestoreOptions { backup, not_stolen, non_interactive }) -> Result<Restored, CeremonyError>;
pub fn unlock(tty, client, store, non_interactive: bool) -> Result<IssuerStatus, CeremonyError>; // never prompts; locked → StoreUnavailable
pub fn replace_orphan(tty, client, store, &ReplaceOrphanOptions { fingerprint, bundle: Option<&RecoveryBundle>,
    no_bundle_available, non_interactive }) -> Result<StoreItemRef, CeremonyError>;          // CLI runs init afterwards
pub fn orphans(store, &IssuerStatus) -> Result<Vec<StoreItemRef>, StoreError>;
pub fn public_key_fingerprint(openssh: &str) -> Option<CaFingerprint>;   // what RegisterIssuer must name (U10)
// *_probed variants take &mut dyn CeremonyProbe (CrashPoint::{Registered, BackupWritten, PassphraseShown, Stored}).
pub struct Registered { fingerprint, item: StoreItemRef, backup: Option<BackupInfo>, decision: DecisionId }
pub enum Restored { StoreItemRewritten { fingerprint, item }, RegisteredWithoutLog(Registered) }
CeremonyError::{code() -> Code, reason() -> Option<String>}  // e.g. StoreUnavailable(a) → CAPABILITY_UNAVAILABLE + issuer_store_*
```
`ceremony::Zeroizing` re-exports `zeroize::Zeroizing` (the `Tty` line type) for implementors
without a zeroize dependency.
Order inside init/rotate: preflight (non-interactive, store available), `status` (init: refuses
`AlreadyInitialized` / `OrphansPresent`), backup path must not exist, generate, prepare, `attend`,
`register` (decision must name the CA and digest, else `DecisionMismatch`), disclosure, typed
`yes` (else `NotConfirmed`, exit 3, nothing more sent), write exactly, passphrase on the tty until
`written`, clear, `put` + `get` compare, `approve`.

`retire`: `step(&CaFingerprint, CaState, &mut dyn RetireEffects) -> Result<Step { event: CaEvent,
next: CaState }, RetireError>` (performs the effect; the caller persists `set_issuer_state`);
`RetireEffects { unload(&fp), delete_store_item(&fp) }`; `StoreEffects::new(&dyn SecretStore, unload
closure)`; `delete_confirmed_absent(&dyn SecretStore, &fp) -> Result<(), StoreError>` (absent = ok);
`StoreItemDeletion::new(&dyn SecretStore)` implements `app::operations::CaStoreItemDeletion` (refuses
a `StoreKind` that is not the store's product kind); `admissible(&fp, &[EnrollmentView]) ->
Result<Vec<EnrollmentId> /*abandoned*/, RetireRefusal { open }>`; `uninstall_store_plan(&[EnrollmentView],
&StoreItemRef) -> StoreFate::{Keep(KeepReason::LiveEnrollments(markers)), OfferDelete}`.

`bundle`: `export(&StoreView { created_at, cas: &[IssuerRecord], enrollments: &[EnrollmentEntry {
record: &EnrollmentRecord, alias: &str }] }, Redaction::{None, Hostnames}) -> Result<RecoveryBundle,
BundleError::UnknownCa>`; hostname/port from `record.target` (omitted when redacted), sorted by
marker, every enrollment included.

## U5-pure (registry: line, step, hm1, post_image, classify, fence, plan): landed interfaces
(U5-pure appends here.)

**Landed (compiles; `cargo test -p heimdall-registry --lib` green), 2026-11-10:**
- `hm1::parse(&[u8]) -> Result<Hm1Record, ParseError>`: ≤ 512 KiB (`TooLarge`); line 1 exactly
  `HM1 ready\n` (`NoReadyLine`), line 2 exactly `HM1 v=1\n` (`NoVersionLine`); then `HM1 <key>=<value>\n`
  only, known key, value of its shape, `content_hex` ≤ 2×128 KiB chars, **`v` never again**, **every line
  ends `\n`** (a cut last line is `Malformed{line}`), no `\r`. `Hm1Record.fields` = pairs after `v=1`.
  Helpers: `hm1::handshake(&[u8]) -> Handshake { NoReady, Ready, Versioned }` (first two lines only),
  `hm1::decode_hex(&str) -> Option<Vec<u8>>`, `hm1::encode_hex(&[u8]) -> String`,
  `Hm1Record::single(key) -> Result<Option<&str>, hm1::DuplicateKey>`.
- `classify::classify_step(RemoteStage, &StepResult, &Expected) -> StepClass` (frozen signature).
  `NotAppliedReason` gains (non_exhaustive, additive; U5P-Q2) `ChangedSinceRead` (remove exit 20) and
  `TooLarge` (exit 31). Rules: no `HM1 ready` → `NotApplied(Refused)` every stage (exit 255 + stderr
  "Host key verification failed" → `HostTrustChanged`; "agent refused operation" → `ProviderLocked`;
  "read_passphrase: can't open /dev/tty"/"Confirm user presence" → `InteractionRequired`); ready w/o
  `v=1` → inspect/fence `NotApplied(Refused)`, bootstrap/append/remove `Uncertain` unless exit 0..=127
  (then `NotApplied(Refused)`); after `v=1`: unparseable, exit 255 or unknown code → mutating and fence
  `Uncertain`, inspect `NotApplied(Refused)`. append 0 → post-write check on its `content_hex` vs
  `Expected{preimage,line}` → `Confirmed`|`Held`; append 10 + `content_hex` with exactly one marker line
  equal to the line → `AlreadyPresent` (damaged → `Held`; no content → `Uncertain`); remove 0 →
  `check_post_remove(Expected.post_image, content_hex, Expected.marker)`; 30/31/32/33/40/41/42 →
  `NotApplied(..)`; bootstrap 0/11 need `dir=present` (and `dir_mode=drwx------`, `dir_owner_self=yes` when
  printed); fence: last `fence=` value is the decision; 0+gone|none → `Confirmed`; 43 alive / 44 unproven /
  40 → `NotApplied(Busy)`, **but any non-empty `fence_signals` (or a repeated one) without `gone` →
  `Uncertain`** (§17.10 item 4).
- **To U5-io (runner):** report a killed / timed-out / signal-ended ssh with an `exit_status` outside
  0..=255 (e.g. -1) or 255; never 0..=127. Send the script only when the **first** stdout line is exactly
  `HM1 ready`.
- `classify::Inspection::from_record(&Hm1Record, marker: &str) -> Result<Inspection, ReadingError>`
  (required `path_hex`, `dir`, `file`, `lock`, `remote_now`; regular file: `size`, `content_hex`,
  `marker_lines`, re-counted against `marker` when non-empty; each key once), fields `path, dir: DirState,
  dir_mode, dir_owner_self, file: FileKind, links, mode, owner_self, content: Option<Vec<u8>>,
  last_byte_newline, marker_lines: u64, lock: LockReading { None, Held(HolderRecord), HeldForeign },
  remote_now: i64`; `preimage() -> Option<&[u8]>` (absent file = empty), `holder()`.
  `classify::HolderRecord { token, pid: u32, start_hex, boot_hex, not_after: i64 }::{parse, render}`,
  `classify::token_ok(&str)` (32 lowercase hex).
- `line::{expected_line (frozen), principal(&DestinationId, &AccountName) -> Result<String, LineError>,
  marker, marker_of(&str) -> Option<&str>, marker_ok, ca_public_ok, principal_part_ok, in_charset,
  lines(&[u8]), contains, marker_lines(&[u8], &str) -> usize}`. Marker lines = substring (`grep -c -F`).
- `post_image::{post_image_without(&[u8], line: &str) -> Result<Vec<u8>, PostImageError>,
  check_post_append(pre, post, line) -> Result<(), PostWriteError>, check_post_remove(post_image, post,
  marker: &str) -> Result<(), PostWriteError>}`; `PostWriteError::hold_reason() -> HoldReason`.
  (`check_post_remove` takes the marker: the plan sketch had two arguments.)
- **`step` (landed, clippy clean):**
  ```rust
  pub const REMOTE_COMMAND: &str = "printf 'HM1 ready\\n'; exec /bin/sh -s";
  pub struct TrustPaths { pub tag: String /*16 lc hex*/, pub user_known_hosts: String, pub global_known_hosts: String }
  pub fn trust_pins(&ApprovedTarget, &TrustPaths) -> Result<Vec<(String, String)>, StepError>; // the 10 table rows, in order
  pub fn target_pins(&ApprovedTarget) -> Result<Vec<(String,String)>, StepError>;
  pub fn access_pins(endpoint: &str, identity_file: &str) -> Result<Vec<(String,String)>, StepError>;
  pub fn narrowing_pins(interactive: bool) -> Vec<(String,String)>;   // BatchMode=yes|no first
  pub struct StepTarget<'a> { alias, target: &ApprovedTarget, host_trust: &[String], invocation: &[String],
                              registry: &RegistryCanonical, line: &str }   // StepTarget::from_plan(&plan, &registry)
  pub enum StageInput<'a> { Inspect, Bootstrap, Append, Remove { preimage: &[u8], post_image: &[u8] }, Fence { terminate: bool } }
  pub struct StepEnv<'a> { pub client: &str, pub timeout_ms: u64, pub interactive: bool, pub gssapi_key_exchange: bool }
  pub fn remote_step(StageInput, &EnrollmentPlan, &RegistryCanonical, token: &str, hard_deadline_ms: u64,
                     not_after_remote: Option<i64>, &StepEnv) -> Result<RemoteStep, StepError>;
  pub fn remote_step_for(StageInput, &StepTarget, token, hard_deadline_ms, not_after_remote, &StepEnv) -> Result<RemoteStep, StepError>;
  pub fn pin_args(&StepPins) -> Vec<String>;            // ["-o","K=V",...] target, trust, access, narrowing
  pub fn ssh_args(&RemoteStep) -> Vec<String>;          // pin_args + "-T", alias, remote_command  (U5-io: run exactly this after `client`)
  pub fn effective_config_args(&RemoteStep) -> Vec<String>; // "-G", pin_args, alias
  pub fn check_effective(ssh_g_output: &str, &StepPins) -> Result<(), HostTrustUnpinnable { option, kind: UnpinnableKind }>;
  pub fn client_lists_gssapi_kex(ssh_g_output: &str) -> bool;
  ```
  The step re-checks the plan's `host_trust` and `existing_access.invocation` against the documented set
  (keys, order, fixed values, HostKeyAlgorithms of the approved key) and refuses otherwise; the script comes
  from `registry::script::{inspect,bootstrap,append,remove,fence}` (release form; the test form is applied
  CLI-side by `script::test_form`). `not_after_remote` is required for append/remove, refused for others.
  Values with a space are double-quoted (`ssh -o` strips them; observed with OpenSSH_10.5p1 `ssh -G`);
  `%`, `$`, `"`, `'`, `\`, `#`, backtick and control characters are refused; Windows paths use `/`.
  Q23 flow for U10/U5-io: run `ssh -G` (effective_config_args) once; if `client_lists_gssapi_kex(out)`,
  rebuild the step with `gssapi_key_exchange: true` and run `-G` again; then `check_effective` must pass
  (`GssapiPinRequired` otherwise). Observed on this host (OpenSSH_10.5p1): `proxycommand`, `proxyjump`,
  `knownhostscommand`, `controlpath` are **absent** when pinned `none`; `stricthostkeychecking true`;
  `verifyhostkeydns`/`updatehostkeys`/`controlmaster`/`canonicalizehostname false`; no `gssapikeyexchange`.
- **`fence` (landed):**
  ```rust
  pub const HOLDER_TERMINATION_ATTEMPTS: u32 = 3; INSPECT_MAX_AGE (10 min); NOT_AFTER_ALLOWANCE (60 s); HARD_DEADLINE_MARGIN (30 s)
  pub struct FenceReading { decisions: Vec<FenceDecision{Gone,Alive,Unproven,None}>, signals: FenceSignals{None,Term,TermKill},
                            holder: Option<HolderRecord>, remote_now: Option<i64>, exit: Option<ExitCode> }
  FenceReading::from_record(&Hm1Record, exit_status) -> Result<_, ReadingError>; .decision() (last); .lock_view(terminate: bool) -> LockView
  pub enum OurLock { Unfenced, Gone, Alive { not_after_passed: bool, terminated: bool }, Unproven { signals } }
  pub enum LockView { None, Other, Ours(OurLock) }     pub struct FenceView { lock: LockView, attempts: u32 }
  FenceView::shown(&Inspection, step_token) -> LockView
  pub enum ReconcilePurpose { Append, Rollback, Removal, Bootstrap }
  pub struct ReconcileExpected<'a> { purpose, line: &str, step_token: &str, not_after_remote: Option<i64>,
                                     approval_valid, attended, route_unchanged, after_manual_recovery: bool }
  pub enum Observation { Unavailable, Inspected(Box<Inspection>) }
  pub enum ReconcileClass { Applied, Redispatch, Damaged, ApprovalLapsed, Fence, Terminate, HolderUnresolved,
                            ManualRecoveryLinePresent, ManualRecoveryLineAbsent, Unresolved(UnresolvedReason) }
  //   .redispatches(), .counts_attempt();  UnresolvedReason { Unreachable, Unreadable, Inconsistent, HolderAlive,
  //   StillAlive, Unproven, HolderNotProvenGone, RouteChanged, NotAttended, LockStillHeld, NotManageable }
  pub fn classify_reconcile(&Observation, &ReconcileExpected, FenceView) -> ReconcileClass;
  pub fn not_after_remote(inspect_reading: i64, c_read: Duration, c_issue: Duration, timeout: Duration) -> Result<i64, NotAfterError>;
  pub fn step_hard_deadline(c_issue: Duration, timeout: Duration) -> Option<Duration>;
  pub fn late_write_cleared(&Inspection, &LateWrite, marker: &str) -> bool;   // takes the marker (LateWrite has none)
  ```
  Reconcile loop for U10: inspect → `classify_reconcile(obs, exp, FenceView{lock: LockView::None, attempts})`;
  `Fence` → run fence (no terminate) → `reading.lock_view(false)` → classify again with the same inspect;
  `Terminate` → fence --terminate → `lock_view(true)`; `Ours(Gone)` → **inspect again** and classify that
  read with `lock: Ours(Gone)`. `counts_attempt()` → +1 to the operation's attempts. "Proven gone" =
  fence removed our lock, or no lock of ours and `remote_now > not_after_remote` (strict). A fence that saw
  ours alive/unproven and a later read without it → `Unresolved(Inconsistent)`, never a redispatch.
- **`plan` (landed):** `build(&CatalogView, &TargetEvaluation, &CaView, EnrollmentSpec)` and `plan_digest`
  (frozen signatures). **`CaView` gains `issuer: Option<IssuerState>` and `context: Option<PlanContext>`**
  (U5P-Q1): `PlanContext { enrollment_id: EnrollmentId, trust_files: step::TrustPaths, identity_file:
  Option<String> /* generated .pub for agent identities */, alias_identity_agent: AgentReading {
  Determined(String), Unset, Undetermined } /* Q24 */, pair_enrollments: Vec<PairEnrollment { ca_fingerprint,
  state, removal_origin_set }>, lock_continuity_acknowledged: bool }`. `context: None` → `DriverUnavailable`.
  `plan::trust_tag(&EnrollmentId) -> String` (16 hex for `<runtime_dir>/e/<tag>/` and `hm-target-<tag>`).
  `PlanRefusal` gains `IssuerNotInitialized, IssuerUnavailable, CaRetiring, ObservedAliasUnmanaged,
  PrincipalCharset, RouteUnsupported, HostTrustUndetermined, PairNotAdopted, AlreadyEnrolled` (registered
  reasons) and `RegistryPathInvalid` (USAGE_ERROR, provisional reason `registry_path_invalid`, U5P-Q3).
  Digest = `canonical::request_hash("heimdall-enrollment-plan-digest/1", plan JSON without plan_digest)`,
  bare 64 hex. U10: mint the enrollment ID at preview and remember it with the digest (as M02 setup does).
- **Also landed:** `fence::{HardDeadline { continuous, wall: Timestamp, boot_id }, DeadlineNow { boot_id,
  continuous, safe_wall: Option<Timestamp> }, hard_deadline_passed(&HardDeadline, &DeadlineNow) -> bool}`
  (same boot: continuous `>`; after a reboot: only safe wall time `>` the wall deadline; no safe time → not
  passed). Tests: `tests/model/registry_pure.rs` (target `model_registry_pure`, 17 tests, 256-case fixed-seed
  properties) — `cargo test -p heimdall-registry` exit 0.

## U5-scripts (registry::script, goldens, shell tests): landed interfaces
(U5-scripts appends here.)

**`heimdall_registry::script` (landed, compiles; `cargo test -p heimdall-registry --lib script` 5 passed):**
```rust
// Validated literals (constructors refuse anything that could leave its single quotes):
pub struct RegistryPath;  RegistryPath::parse(&str) -> Result<_, ScriptError>   // abs POSIX, <=255, [A-Za-z0-9._/-],
                                                                             // no empty/./.. component, file name last
pub enum RegistryLocation { RemoteHome, Explicit(RegistryPath) }  RegistryLocation::from_plan(Option<&str>)
pub struct Marker;        Marker::parse(&str)          // "heimdall:" + [A-Za-z0-9._:-]+, <=256
pub struct RegistryLine;  RegistryLine::parse(&str, &Marker)  // LINE_CHARSET only, <=8 KiB, must contain the marker
pub struct StepToken;     StepToken::parse(&str)       // exactly 32 lowercase hex (also names remove's temp files)
pub struct NotAfter;      NotAfter::new(i64)           // >= 0, remote epoch seconds
pub struct Payload;       Payload::new(&[u8])          // <= 128 KiB (remove's preimage / post-image; NUL refused remotely, exit 30)
pub struct InspectParams   { pub registry: RegistryLocation, pub marker: Marker }
pub struct BootstrapParams { pub registry: RegistryLocation }
pub struct AppendParams    { pub registry, pub marker, pub line: RegistryLine, pub token: StepToken, pub not_after_remote: NotAfter }
pub struct RemoveParams    { pub registry, pub marker, pub token, pub not_after_remote, pub preimage: Payload, pub post_image: Payload }
pub struct FenceParams     { pub registry, pub token: StepToken /* the uncertain step's */, pub terminate: bool }
pub struct RemoteScript;   .stage() -> RemoteStage, .text() -> &str, .into_text() -> String   // ends "}\nhm_main\n"
pub fn inspect(&InspectParams) -> RemoteScript;   pub fn bootstrap(&BootstrapParams) -> RemoteScript;
pub fn append(&AppendParams) -> RemoteScript;     pub fn remove(&RemoveParams) -> RemoteScript;
pub fn fence(&FenceParams) -> RemoteScript;       // all infallible (release form, no pause points)
pub const PROCSTAT_AWK: &str;          // the shared /proc/<pid>/stat awk program (ADR text verbatim)
pub const REMOTE_CLOCK_COMMAND: &str;  // how remote_now is read (U5S-Q1: POSIX date -u + awk, not srand)
pub fn pause_points(RemoteStage) -> &'static [&'static str];
#[cfg(debug_assertions)] pub mod test_form {
    pub struct PauseDir; PauseDir::parse(&str)   // abs, [A-Za-z0-9._/-], <=1024
    pub fn insert_pause_points(release_text: &str, &PauseDir) -> Result<String, ScriptError>; // for the CLI (RemoteStep.script)
    pub fn with_pause_points(&RemoteScript, &PauseDir) -> Result<RemoteScript, ScriptError>;
}
pub enum ScriptError { RegistryPath, Marker, Line, Token, NotAfter, Payload, PauseDir, NotAReleaseScript } // non_exhaustive
```
**What the scripts emit (for U5-pure's parser/classify, U10):** first line `HM1 v=1`; last
lines `HM1 status=<word>` and, for a refusal, `HM1 reason=<word>`; then the exit code.
* `status` words: `ok` (inspect 0), `created` (bootstrap 0), `already_present` (10/11),
  `written` (append 0), `renamed` (remove 0), `changed_since_read` (20), `refused` (30, with
  `reason`), `too_large` (31), `dir_absent` (32), `parent_absent` / `no_process_group` (33),
  `busy` (40), `not_after_passed` (41), `lock_lost` (42), `alive` (43), `unproven` (44), `gone` /
  `none` (fence 0).
* 30 `reason` words: `home_unset`, `clock_unavailable`, `uid_unavailable`,
  `start_identity_unavailable`, `dir_unreadable`, `dir_not_directory`, `dir_owner_foreign`,
  `dir_writable_by_others`, `dir_acl`, `registry_symlink`, `registry_not_regular`,
  `registry_hardlinked`, `registry_owner_foreign`, `registry_acl_or_label`,
  `registry_unreadable`, `registry_mode_unsupported`, `lock_is_directory`, `lock_not_created`,
  `lock_not_verified`, `temp_create_failed`, `decode_failed` (incl. a NUL), `write_failed`,
  bootstrap: `dir_symlink`, `dir_not_private`, `parent_symlink`, `parent_not_directory`,
  `parent_owner_foreign`, `parent_writable_by_others`, `mkdir_failed`; fence:
  `lock_not_symlink`, `lock_not_removed`. Fence 40 reasons: `lock_foreign`, `lock_other_token`,
  `lock_replaced`; fence 43 `not_after_not_passed` (terminate asked too early); fence 44
  `start_identity_unavailable` (an invalid identity read is unproven, never 30).
* **`append` exit 30 `write_failed` means a write was attempted** (the line may be partly
  there; `content_hex` follows when readable): classify it **Uncertain**, not NotApplied.
* Order: `path_hex`, `remote_now` (every script, epoch seconds), then for append/remove
  `pgid` (= `$$`), `start_identity`, `boot_identity` (the holder record's), `dir`, `dir_mode`,
  `dir_owner_self`; lock busy → `lock=held` (+ `lock_holder` when the record is well formed);
  `file`, `links`, `mode`, `owner_self`, `size` (**before** the write); `last_byte_newline`,
  `marker_lines`, `content_hex` (**after** the write; for 10 the current content). inspect: dir,
  file, content (regular, readable, <= 128 KiB), `lock` (+`lock_holder`); an empty file has
  `last_byte_newline=no`. inspect exits 30 **after** reporting everything readable (so absence
  can be checked on a registry Heimdall cannot rewrite).
* fence: `lock=none` + `fence=none` (0), or `lock=held`, `lock_holder`, then per decision round
  `pgid`(holder PID) `boot_identity`(now) [`group_control` `group_probe` [`group_listed`]
  [`start_identity`(holder PID now)]] `fence`; rounds repeat while waiting after TERM/KILL; the
  **last** `fence` is the decision; `fence_signals` (``, `TERM`, `TERM,KILL`) always last before
  `status`. A boot-identity change prints `fence=gone` without the group fields.
* Not-after: a script refuses (41) when the remote clock reads `>= not_after`; fence
  `--terminate` signals only when the clock reads `> ` the record's not-after.

**Pause protocol (test form; for U11 `PauseHooks`):** points `before_ln`, `after_lock`,
`before_write` (append: after the newline decision, immediately before the single append
write; remove: immediately before `mv -f`), bootstrap `before_mkdir`, fence `after_term`,
`after_kill`. At a point, **if `<dir>/<name>` is a FIFO**, the script writes `$$` to
`<dir>/<name>.pid` (`>|`) and then runs `cat <dir>/<name> > /dev/null` (a child in its process
group). So: `wait_at(name)` = open the FIFO for writing (returns once the script is there) and
hold it; `release(name)` = close it. No FIFO = no pause. The pid file gives the group for
`stop_holder()` / `continue_holder()`. `nonce_known` is not a script point (the verifier's).

**Later changes (2026-11-10):** the scripts also `export TZ=UTC0` (third statement), collapse blanks
in `ps -o lstart=`, and keep `sysctl -n kern.boottime` up to its first `}` (U5S-Q8); `remote_now`
comes from `REMOTE_CLOCK_COMMAND` (POSIX `date -u` + awk; U5S-Q1). Goldens regenerated.
**Suite:** `tests/integration/enroll_registry.rs` (target `integration_enroll_registry`): modules
`golden`, `native_sh` (host `/bin/sh`, own group), `native_sshd` (LoopbackSshd + the fixed remote
command, explicit scratch registries only), and `#[ignore]` Docker modules `docker_dash` (M00
`enrollable`, needs `up.sh`), `docker_debian_dash` (own acl image), `docker_bash_sh`,
`docker_busybox` (U11 `ShellContainer`s). `HM_DOCKER_TESTS=1 cargo test -p heimdall-enroll --test
integration_enroll_registry -- --ignored`. Every registry passes U11's `RegistryGuard`; host targets
assert U11's `OwnerDigest` unchanged on drop. `HM_UPDATE_GOLDENS=1` rewrites the five goldens.

## U5-io (enroll remote/verify/trace, localenv target/known_hosts): landed interfaces
(U5-io appends here.)

**Landed (compiles, clippy clean, lib tests green), 2026-11-10:**
- `heimdall_localenv::known_hosts` (additive): `RawHostKeyObservation { key_type, key_b64 /*padded,
  re-encoded*/, fingerprint, origin_display, revoked }` (`.observation()`), `RawKnownHostsLookup { keys,
  complete }`, `lookup_raw_in(files, home, host, port, LocalQueries, keygen) `, `lookup_raw_detailed(&SshPaths,
  …)`, `base64_encode_padded`. A matching line that is not a usable host key (type ≠ blob type, a cert type,
  bad blob, unknown marker) makes it `complete: false`. M02 functions unchanged.
- `heimdall_localenv::target`:
  ```rust
  pub struct LocalTargetEvaluator;  // impl app::ports::TargetEvaluator (evaluate = evaluate_alias)
  LocalTargetEvaluator::new(SshPaths, Env, Platform)            // keygen off, local user from the account db
      .with_managed_file(p) .with_client_version(OpenSshVersion) .with_keygen(path) .with_limits(l) .with_local_user(Option<String>)
  fn evaluate_alias(&self, alias) -> TargetEvaluation            // passive; Exec(Some(STEP_REMOTE_COMMAND)) invocation
  fn evaluate_identity_agent(&self, alias, exclude_managed_block: bool) -> IdentityAgentEvaluation
  pub enum IdentityAgentEvaluation { Determined(EndpointRef), Unset /* unset or none */, Undetermined { reason: &'static str } }
  fn check_endpoint(&self, &EndpointRef) -> EndpointCheck { presence: agents::Presence, resolved: Option<String> } // stat + canonicalize, never connects
  pub mod undetermined_reason { ALIAS_INVALID, HOSTNAME, HOSTNAME_INVALID, PORT, PORT_INVALID, USER,
      LOCAL_ACCOUNT_UNKNOWN, PROXY, CANONICALIZATION, CONFIG_INVALID, KNOWN_HOSTS_INCOMPLETE, ALL }
  pub mod identity_agent_reason { ALIAS_INVALID, UNDETERMINED, SSH_AUTH_SOCK, ENVIRONMENT_REFERENCE, TOKEN, NOT_AN_ENDPOINT }
  ```
  **To U5-pure (plan):** `Determinism::Undetermined{reason}` carries these strings; `known_hosts_incomplete`
  is a host-trust fact (maps naturally to `host_trust_undetermined`), the others to `route_undetermined`.
  Proxy `Jump`/`Command` with `Determined` is `route_unsupported`. Host keys are the user+system **default**
  known-hosts files (M02's reader), for (HostName, Port); revoked keys are listed with `revoked: true`.
  **To U10:** `check_endpoint` is the "re-validated before every step" read (present + owned + resolved);
  compare `resolved` with the approved endpoint's and with `CatalogView.heimdall_endpoints`.
- `heimdall_enroll::remote` (CLI side; U12 wires it):
  ```rust
  pub const READY_LINE = "HM1 ready"; STEP_REMOTE_COMMAND; KILLED_EXIT_STATUS: i32 = -1; CONNECT_TIMEOUT = 30 s;
  pub const PARENT_DEATH_SIGNAL_APPLIED: bool = false; INTERACTIVE_FOREGROUND_HANDOFF: bool = false; // U5IO-Q1/Q3
  SshStepRunner::new() .with_containment(Box<dyn StepContainment>) .abort_handle() -> StepAbort (abort(): sticky)
  fn run(&self, &RemoteStep, TtyMode) -> Result<StepReport, StepRunError>
  fn effective_config(&self, &RemoteStep) -> Result<String /* ssh -G stdout */, StepRunError> // -G + pins + -T alias cmd
  pub fn step_argv(&RemoteStep, TtyMode) -> Result<Vec<String>, StepRunError>  // == registry::step::ssh_args
  pub struct StepReport { exit_status, stdout, stderr_excerpt, ready_seen, script_sent, ended: StepEnd, lifetime: LifetimeTie }
  pub enum StepEnd { Exited, Signalled, Killed(KillCause{ConnectTimeout,Timeout,StdoutBound,Aborted}) }
  pub enum StepRunError { Unavailable, InvalidStep(&'static str), ContainmentUnavailable, Aborted, Spawn(String), EffectiveConfig(i32) }
  pub trait StepContainment: Send + Sync { fn spawn_contained(&self, &mut Command) -> io::Result<Contained>; fn ends_with_parent(&self) -> bool; }
  pub struct Contained { pub child: std::process::Child, pub guard: Box<dyn Send> }   // drop guard = kill
  pub fn redact_excerpt(&[u8], max) -> String
  ```
  A Batch step must carry `BatchMode=yes` (`InvalidStep("batch_mode_pin")`); killed/timed-out/signalled
  runs report `-1` (U5-pure's request honoured). **Windows: `run` refuses without a containment** (the CLI
  supplies one over `heimdall_localenv::sys::JobObject`; the test file has one). **To U5-pure:**
  `effective_config` passes `-T <alias> <remote command>` after the pins (so `Match command` is evaluated as in
  the step); your `effective_config_args` stops at the alias. Either works with `check_effective`.
- `heimdall_enroll::trace`: `ClientFamily { Portable, Win32 }`, `ClientVersion::parse(ssh -V text)`,
  `patterns_for(family, version) -> Result<&'static TracePatterns, UnrecordedClient>`, `RECORDED`
  (portable 10.5p1 only, observed here), `UNRECORDED_FINDING = "client_trace_family_unrecorded"`,
  `UnrecordedClient { version }::{finding, detail}`, `parse(&TracePatterns, trace, &TraceContext) -> ParsedTrace
  { events: TraceEvents, host_key_failure }`.
- `heimdall_enroll::verify`:
  ```rust
  Verifier::new()  // unavailable; Verifier::with_client(VerifierClient { path, version: ClientVersion }, runtime_dir)
  impl app::ports::VerificationRunner for Verifier       // run = run_detailed(..).outcome
  async fn run_detailed(&self, plan, positive, negative, &dyn VerificationSession) -> VerifierReport
  pub struct VerifierReport { outcome, positive: AttemptEvidence, negative, clock: Option<ClockMeasurement>,
      unrecorded: Option<UnrecordedClient>, refused: Option<VerifierRefusal>, session_binds, log_attestation }
  pub fn classify_evidence(&VerifierReport, Option<KnownOffset>, skew_lag_ms, skew_lead_ms) -> VerificationVerdict // proposed domain body (U5IO-Q4)
  pub fn generated_config(&GeneratedConfig) -> Option<String>; pub fn measurement(t1, t2, remote_secs) -> Option<ClockMeasurement>
  ```
  **To U2/U10:** the Verifier calls `session.install(cert)` **itself, just before each attempt** (positive,
  then negative), and counts `session.signatures(K_verify fingerprint)` before/after each attempt; the
  app must not install them again (or `install` must be idempotent). The generated files live in
  `<runtime_dir>/v/<16 hex>/` and are removed at the end and on drop.

## U9 (session lock): landed interfaces
(U9 appends here.)

**`heimdall_runtime::session_lock`** (compiles on macOS, Linux, Windows):
- `PlatformSessionLockSource::start() -> Arc<Self>` (spawns its one thread, waits **blocking** at most
  `INITIAL_STATE_WAIT` 3 s for the first reading: call from `spawn_blocking`; never panics);
  `unavailable() -> Arc<Self>`; `signal() -> LockSignal`; `snapshot() -> SourceSnapshot`;
  `thread_running()`; `shutdown()` (idempotent, joins; also on drop). Implements the frozen
  `SessionLockSource` exactly. Fail-closed latch: every transition into `locked` **or `unknown`**, and
  an initial `locked`/`unknown`, latches the epoch (`app::lock::UNKNOWN_IS_LOCK`).
- macOS: a dedicated thread **polling** `CGSessionCopyCurrentDictionary` every
  `MACOS_POLL_INTERVAL` 250 ms (the distributed notifications only reach a main-thread run loop:
  U9-Q4). Windows: message-only window thread (WTS). Linux: logind via zbus on its own thread
  (this PID's session, else `GetSession("auto")`; only a graphical session counts, else
  `unavailable`).
- `lock_floor(&SessionConfig) -> contract LockBehavior` (R3: `revoke` → `RevokeOnLock`).

**`heimdall_app::lock`**:
- `effective_behavior(&GrantOrigin, &[StandingPolicy]) -> LockBehavior`,
  `effective_behavior_with_floor(Option<&GrantOrigin>, &[StandingPolicy], floor)`,
  `origin_behavior(&[StandingPolicy], floor) -> Option<LockBehavior>`, `treated_as_locked(LockState)`,
  `signs_while(behavior, state)`, `reissue_allowed(behavior)`, `floor_refusal(floor, state) ->
  Option<OpError>` (`lock_signal_unavailable`).
- `LockSignal { MacosScreenLock, WindowsSession, LinuxLogind, None }`, `lock_warnings(behavior,
  signal) -> Vec<Warning>` (`signal_unverified` for Linux `revoke_on_lock`, `LINUX_LOGIND_SIGNAL_VERIFIED
  = false`), `label_completed(&mut Completed<T>, behavior, signal)`.
- Disclosure: `disclosure(&[StandingPolicy], floor, continuity_verified, signal) -> LockDisclosure
  { behavior, floor, continuity_verified, signal, limits: Vec<SavedLimit>, warnings, text,
  acknowledged_at }`; `Operations::{lock_disclosure(verified, signal), pending_lock_disclosure(verified,
  signal) -> Option<LockDisclosure>, acknowledge_lock_disclosure() -> Timestamp}` (once, meta
  `lock_disclosure_acknowledged_at`).
- Driver (U10 runs it from the supervisor): `run_lock_passes(ops: Operations, source: Arc<dyn
  SessionLockSource>, LockPassConfig { min_interval (1 s), retry_after (1 s) }, shutdown: impl Future)
  -> LockPassReport { passes, failures, revoked, epochs }`; `lock_pass_now(&Operations, &dyn
  SessionLockSource) -> Result<LockRevocation, OpError>`.
- `Operations::{effective_lock_behavior_of(&GrantId) -> Option<LockBehavior>,
  lock_blocks_reissue(&GrantId) -> bool}` (U6/U10's re-issue pass must ask this).

**U0b child-module edits (R3 floor, recorded):** `Operations::{set_session_lock_floor(LockBehavior),
session_lock_floor()}` (`operations/lock.rs`; state field `NarrowingState::lock_floor` in
`operations/narrowing.rs`); `effective_lock_behavior(.., floor)` used by the lock pass and the
per-signature check (`authorize.rs`); each lock pass now emits one `session_lock` event
`{state, revoked}` in its commit. U10 at start: `ops.set_session_lock_floor(lock_floor(&cfg.session))`,
`ops.set_session_lock_source(PlatformSessionLockSource::start())`, report `lock::floor_refusal`.

## U11 (testkit, Docker fixtures): landed interfaces
(U11 appends here.)

**Landed 2026-11-10 (all compile: `cargo check -p heimdall-testkit --features fixtures,managed`).**
Module paths are `heimdall_testkit::<mod>`. Read the module docs for details.

`ca::ceremony` (fixtures+managed): `run(&CeremonyRun { binary, env, cwd, backup_out, timeout }) ->
Result<CeremonyCa { fingerprint, passphrase: Passphrase, backup, status, .. }, CeremonyError>`
(`issuer init` over a pty via `script`; answers `yes`/`written`; passphrase only from the
transcript, `CeremonyCa::transcript()`), `find_passphrase`, `find_fingerprint`. Unverified: needs
U12's handler.
`ca` (features fixtures+managed): `TestCa::generate(&Scratch) -> io::Result<TestCa>` (K_ca from
`SecretCaKey::generate`; pub file `<scratch>/ca<n>/test_ca.pub`); `public_line() -> &str`
(`ssh-ed25519 AAAA…`, no comment); `public_key() -> &PublicKey`; `fingerprint() -> &CaFingerprint`;
`pub_file() -> &Path`; `secret() -> &SecretCaKey`; `cert_authority_line(&[&str], Option<&str>) ->
String`; `sign_user(&PublicKey, &UserCertSpec) -> io::Result<ssh_key::Certificate>` (through U1's
`cert::build_and_sign`: exactly one principal, flag extensions, no critical options);
`sign_user_raw(&PublicKey, &UserCertSpec)` (ssh-key builder, for deviating certificates);
`issue_files(&FixtureKey, &UserCertSpec, dir, name) ->
io::Result<CertFiles { identity, certificate, key_id }>` (private key + `<name>-cert.pub` in scratch,
for a scratch config's IdentityFile/CertificateFile). `UserCertSpec { key_id, principals,
valid_after, valid_before, serial, extensions, critical_options }`, `UserCertSpec::for_principal(&str)`
(now−60 s .. now+300 s, no extensions). `ca::unix_now() -> u64`.

`sshd` (fixtures): `SshdConfig` gains `trusted_user_ca_keys: Option<PathBuf>`,
`authorized_principals: Option<BTreeMap<String, Vec<String>>>` (→ `AuthorizedPrincipalsFile
<scratch>/principals/%u`), `registry_seed: Option<Vec<u8>>` (starts the scratch AuthorizedKeysFile =
the explicit registry), `authorized_principals_command: Option<PathBuf>` (→ `AuthorizedPrincipalsCommand
/bin/sh <script> %t %k` + `…CommandUser <current account>`), `max_startups: Option<String>`,
`session_path: Option<PathBuf>` (→ `SetEnv PATH=<dir>:/usr/bin:/bin:/usr/sbin:/sbin`). Use
`..SshdConfig::default()`. A harness (Windows/WSL) server refuses every one of these except
`registry_seed` with `SshdUnavailable` (never ignored). `current_account() -> Option<String>`;
`enrollable_like_seed() -> Vec<u8>`; `REMOTE_CLOCK_COMMAND`; `negative_principal(nonce) -> String`.
`LoopbackSshd` new: `accepted_certificates() -> Vec<AcceptedCert { key_type, fingerprint, key_id,
serial, ca_fingerprint }>`, `accepted_key_ids() -> Vec<String>`, `log_lines_containing(&str)`,
`destination_id() -> Option<&str>`, `set_destination_id(&str)`, `login_account() -> Option<String>`,
`managed_principal() -> Option<String>` (`hm:<dest>:<account>`), `registry_path() -> Option<&Path>`,
`trusted_ca_keys_path()`, `principals_path(account) -> Option<PathBuf>`, `trust_user_ca(line)`,
`set_principals(account, &[&str])`, `append_registry_line(line)`.
`TwoHosts::start(&Scratch, EnrollmentForm) -> Result<(LoopbackSshd, LoopbackSshd), SshdUnavailable>`
(distinct destination IDs `hm-fx-<hex>-<n>`; account form: registry seeded like `enrollable`; system
form: empty TrustedUserCAKeys file + principals file listing the host's own `hm:<dest>:<acct>`).
`ThreeHosts::start(&Scratch, EnrollmentForm) -> Result<ThreeHosts { hosts: [LoopbackSshd; 3] }, _>`,
`ThreeHosts::accepted_key_ids() -> [Vec<String>; 3]`.
`Faults::{stop_between_attempts, close_port_between_attempts, reset_after_version_exchange}(&Scratch,
SshdConfig)`, `Faults::max_startups(&Scratch, SshdConfig, during_negative: bool)`,
`Faults::start(&Scratch, SshdConfig, FaultKind)` → `Result<Faults, SshdUnavailable>`; a loopback
proxy: connection 1 forwarded, the fault applied before its close reaches the client; clients use
`port()` / `host_key_line()`; `sshd() -> MutexGuard<LoopbackSshd>`, `connections()`, `applied()`.
`LaggingClock::new(&Scratch, Duration) -> io::Result<LaggingClock>`, `.start_sshd(&Scratch,
SshdConfig) -> Result<LoopbackSshd, _>`, `.path_dir()`, pub `lag`. Its PATH dir lags both the
verifier's `awk … srand()` reading (`HM1 now=` lines) and the scripts' `date -u +<fmt>` reading
(U5-scripts' `REMOTE_CLOCK_COMMAND`).
`WrongKey::start(&Scratch, SshdConfig) -> Result<WrongKey, _>` (pub `sshd`), `approved_host_key_line()`
(never served), `approved_public_key()`, `served_host_key_line()`, `inherit(WrongKeyVariant,
&ScratchHome) -> io::Result<Vec<String>>` (config lines for the alias block; the file variants write
the served key into the scratch known-hosts files), `none_program_dir()`, `none_invocations() ->
usize`. `WrongKeyVariant::{KnownHostsCommand, UserKnownHostsFile, GlobalKnownHostsFile,
NoHostAuthenticationForLocalhost}`.
`PrincipalsNotEnforced::account_line(ca_line, positive, nonce) -> String`,
`::write_at_nonce_known(&PauseHooks, registry, ca_line, positive) -> io::Result<String /*nonce*/>`,
`::echo_principals_command(&Scratch) -> io::Result<PathBuf>` (for
`SshdConfig.authorized_principals_command`).

`registry` (fixtures): `RegistryGuard::new(&Scratch) -> io::Result<RegistryGuard>`,
`check(&RegistryTarget) -> Result<(), registry::FixtureUnsafe>` (`RegistryTarget::{Path(&Path),
Container { name, path }, Wsl { distribution, path }}`; containers: running + label
`heimdall.fixture`; WSL: `hm-m0N-…` named by `HM_FIXTURE_WSL_DISTRO` or `WSL_DISTRO_NAME`).
`registry::FixtureUnsafe` is its own enum (not `home::FixtureUnsafe`).
**Pause protocol: U11 adopted U5-scripts' test form as published above** (single FIFO `D/N`;
the script writes `$$` to `D/N.pid` with `>|`, then `cat D/N > /dev/null`). `PauseHooks::wait_at`
opens the FIFO's write end once the reader is there (non-blocking open retried, bounded), holds it,
and reads the report files `D/N.pid` and `D/N.nonce` into `Reached.fields`; `release` closes it
(and waits up to 2 s until the reader has gone). **The verifier's `nonce_known` (U5-io) uses the same
form:** write the 32-hex nonce to `D/nonce_known.nonce`, then read the FIFO `D/nonce_known` to EOF.
`registry::pause_snippet(dir, name)` is an equivalent POSIX `sh` point for non-U5 fixture scripts.
Names: `registry::hook::{AFTER_LOCK, BEFORE_WRITE, BEFORE_LN, NONCE_KNOWN, BEFORE_MKDIR, AFTER_TERM,
AFTER_KILL, ALL}`.
`PauseHooks::new(&Scratch)`, `PauseHooks::in_container(name, dir)`, `dir()`, `env() -> (&str,
OsString)`, `snippet(name)`, `arm(name)`, `arm_all()`, `disarm(name)`, `wait_at(name) /
wait_at_for(name, Duration) -> io::Result<Reached { name, fields, pid, process_group }>`,
`release(name) / release_for(name, Duration)`, `holder() -> Option<HolderGroup { pid, process_group
}>`, `stop_holder()`, `continue_holder()` (SIGSTOP/SIGCONT of the last arrival's exact group; never
group 0/1 or our own). `LocalScript::spawn(shell, script, env, cwd)` (own process group), `.pid()`,
`.wait(Duration) -> io::Result<Finished { status, stdout, stderr }>`.
`Truncation::new(script)`, `cut_points() -> 0..=len`, `prefix(len)`, `run_with(FnMut(usize, &[u8]) ->
io::Result<Finished>)`, `run_local(shell, env, cwd, each) -> io::Result<Vec<PrefixRun { len, status,
stdout, stderr }>>`.

`shells` (fixtures; docker): `ShellContainers::start() -> Result<ShellContainers { bash, busybox },
ShellsUnavailable>`, `each()`; `ShellContainer::{kind, name, exec(args, t), exec_as(user, args, t),
run_script(script, env, t)` (`setsid /bin/sh -s`, exit status kept), `spawn_script(script, env, user)
-> RunningScript`, `write_file(path, bytes, mode)`, `read_file(path)`, `signal_group(pgid, sig)`,
`pause_hooks(dir)`, `run_prefixes(script, env, t) -> Vec<PrefixRun>` (the loop runs in-container)}.
`ShellKind::{BashAsSh, BusyBoxAsh}`. `ProbeShim::local(&Scratch)` / `ProbeShim::in_container(&c, dir)`,
`shell()` (a wrapper sh whose `kill` rejects `kill -s 0 -- -N`), `ps_dir()`, `path_env()`,
`set_listing(Listing::{PassThrough, Hide(pgid), Add(pgid)})`. Images: `DEBIAN_BASE`, `ALPINE_BASE`,
`DEBIAN_IMAGE`; label `heimdall.fixture=m03-shells`; containers `hm-m03-shell-<kind>-<hex>`.

`procstat` (fixtures): `Fixtures::synthetic() -> Vec<SyntheticStat { label, text, expected:
Result<ProcStat, ProcStatError> }>`, `Fixtures::committed() -> io::Result<Vec<CommittedStat { file,
text, expected: Result<ProcStat, String /*golden code*/> }>>` (wave 0's `tests/fixtures/procstat/`),
`error_code(&ProcStatError) -> &str`, `Fixtures::naive_field5(text)`, `COMM_NAMES`,
`LiveComm::spawn_in_container(container, user: Option<&str>) -> io::Result<LiveComm>`, `procs() ->
&[LiveProc { requested, expected_comm, pid, expected_process_group, expected_start_time }]`,
`read_stat(pid)`.

`lock` (managed): `pub use session_lock::{FakeSessionLockSource, ENV}`; new methods on it:
`pause_consumer()`, `resume_consumer()`, `consumer_paused() -> bool` (wake-ups withheld while
paused, transitions still latch; one wake-up on resume if anything changed).

`managed` (fixtures+managed): `seeded_k_env(seed: &[u8]) -> [u8; 32]`, `seeded_k_env_nth(seed, n)`
(= SHA-256(`K_ENV_SEED_LABEL` ‖ u64_be(n) ‖ seed); see Request U11 → U1), `scan_forms(secret) ->
Vec<Vec<u8>>` (raw, hex lower/upper, base64 ±padding), `contains_secret(haystack, secret)`.
`ManagedRunContext::new(&ScratchHome, alias, binding: &Endpoint, environment: &Endpoint,
slot_public: &PublicKey, slot_cert_line: Option<&str>) -> io::Result<_>`, `env()` (SSH_AUTH_SOCK =
binding, HOME), `apply(&mut Command)`, `managed_block()`, `write_user_config(&ScratchHome, rest)`,
`binding_endpoint()`, `environment_endpoint()`, `slot_public()`, `slot_certificate()`.

`installation` (fixtures): `SecondInstallation::new(&Scratch)`, `heimdall_home()`, `state_dir()`,
`runtime_dir()`, `ssh_home()`, `destination_id()` (`hm-fx2-<hex>-<n>`), `env()` (HEIMDALL_HOME,
HEIMDALL_TEST_SSH_HOME, HEIMDALL_TEST_SECRET_STORE=scratch), `destination_add_args(…)`.

`owner_digest` (fixtures): `OwnerDigest::capture() -> io::Result<_>` (`$HOME/.ssh` tree, Git global
files, macOS `security list-keychains -d user` names; read-only, digests only),
`OwnerDigest::capture_tree(root)`, `components()`, `changes() -> Vec<DigestChanged>`,
`assert_unchanged()`.

## Requests (unit → unit)
(Append `- <from> → <to>: <what, exact signature>`; the owner answers inline.)
- U5-pure → U5-scripts: `cargo fmt -p heimdall-registry --check` reports diffs only in `crates/registry/src/script.rs`
  (lines ~472, 479, 490, 499, 1388, 1603); `cargo fmt` would fix them (check.sh's `fmt` step runs `--all --check`).
  - **U5-scripts answer (2026-11-10): done** (`rustfmt --edition 2024` on `script.rs` and
    `tests/integration/enroll_registry.rs` only; `--check` clean; rendered scripts unchanged).
- U5-pure → U5-io: the runner reports a killed/timed-out ssh with an `exit_status` outside 0..=127 (255 or -1):
  `classify_step` reads 0..=127 as "the remote shell completed" (ready without `HM1 v=1` → nothing ran).
- U11 → U1: the seeded K_env derivation must be ONE rule. Either (a) `KeyVault::with_test_seed(seed)`
  derives the n-th generated K_env's Ed25519 seed as `SHA-256(b"heimdall-test-key-seed/k_env/v1\0" ‖
  u64_be(n) ‖ seed)` (what `heimdall_testkit::managed::seeded_k_env_nth` computes now), or (b) U1
  exposes `pub fn heimdall_credential::vault::test_seed_material(seed: &[u8], n: u64) -> [u8; 32]`
  and testkit calls it (the integrator then switches `managed::seeded_k_env_nth` to it).
  - **U1 answer (2026-11-10): (a) adopted, and (b) exists.** `KeyVault::with_test_seed` now derives
    the n-th key's seed as exactly `SHA-256(b"heimdall-test-key-seed/k_env/v1\0" ‖ u64_be(n) ‖ seed)`,
    and U1 exposes it as `#[cfg(debug_assertions)] pub fn
    heimdall_credential::vault::seeded_private_key(seed: &[u8], n: u64) -> Option<Zeroizing<[u8; 32]>>`
    (`None` for a seed outside 1..=64 bytes). `integration_credential_memory::
    seeded_vault_is_deterministic_and_published` is a known-answer test of the formula. Note the gate:
    the U1 function exists only under `debug_assertions`, so testkit may call it only from code that
    is itself debug-only; otherwise keep testkit's copy (both now agree).
- U1 → U11 (not blocking; U1 has in-file stand-ins in `tests/integration/credential_cert.rs`):
  (1) a **capturing agent** in testkit, e.g. `FakeAgent::signed_requests() -> Vec<(Vec<u8> /*key
  blob*/, Vec<u8> /*data*/, u32 /*flags*/)>` and `FakeAgent::session_binds() -> Vec<Vec<u8>>`
  (contents after the extension name), with an `AgentMode` that answers `session-bind@openssh.com`
  `SSH_AGENT_SUCCESS` and signs with a caller-supplied signer (U1 signs with a `KeyVault` key, so
  certificates' subjects match); the M02 `FakeAgent`/`CountingProxy` record message types only.
  (2) **host key types** for `LoopbackSshd`: `SshdConfig.host_keys: Vec<HostKeyKind { Ed25519,
  EcdsaP256, Rsa }>` (default `[Ed25519]`) and `LoopbackSshd::host_key_lines() -> Vec<String>`
  (U1's `HostKeySshd` uses `ssh-keygen -A -f <scratch prefix>`, no passphrase anywhere).
- U11 → U5-io: the verifier's `nonce_known` pause (test configuration only): if
  `<HEIMDALL_TEST_SCRIPT_PAUSE_DIR>/nonce_known` is a FIFO, write the negative nonce (32 lowercase
  hex + `\n`) to `<dir>/nonce_known.nonce`, then open the FIFO for reading and read to EOF; else
  no-op (U5-scripts' protocol; `sshd::PrincipalsNotEnforced::write_at_nonce_known` drives it).
- U4 → U11 (2026-11-10): `crates/testkit/src/shells.rs:462` (`text.len() % 2 != 0`) fails
  `clippy::manual_is_multiple_of` under `-D warnings`, which stops `cargo clippy --all-targets`
  for every crate that dev-depends on testkit with `fixtures` (issuer, heimdall, …). Suggested:
  `!text.len().is_multiple_of(2)`.
- U4 → U11 (2026-11-10, later): `crates/testkit/src/registry.rs:721` `fn local_reports` is dead code
  on `x86_64-pc-windows-gnu`, so `.m03-wave1-xcheck.sh windows -p heimdall-issuer -p
  heimdall-testkit` exits 101 (`dead_code` under `-D warnings`). (The shells.rs item above is fixed.)
- U9 → U11 (2026-11-10): `crates/testkit/src/registry.rs:721` `fn local_reports` is unused on
  Windows (its callers are `cfg(unix)`), so `.m03-wave1-xcheck.sh windows -p heimdall-runtime -p
  heimdall-app` fails `dead_code` under `-D warnings` in testkit before reaching the U9 targets.
  Suggested: `#[cfg(unix)]` on `local_reports` (or its caller's cfg). U9's own `--lib` windows clippy
  passes meanwhile.
- U5-io → U5-scripts (2026-11-10): `cargo clippy -p heimdall-enroll --all-targets -- -D warnings` (host and
  `.m03-wave1-xcheck.sh linux`) currently fails only in `tests/integration/enroll_registry.rs`
  (`manual_is_multiple_of` at ~104, `collapsible_if` at ~363 and ~1197, `match_like_matches_macro` at
  ~468). The enroll lib and `integration_enroll_verify` are clean.
- U5-io → U11 (answer to the `nonce_known` request): landed as an explicit opt-in,
  `heimdall_enroll::verify::Verifier::with_test_pause_dir(dir)` (the library never reads
  `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`; the test gate that constructs the Verifier passes it). Before the
  negative attempt, if `<dir>/nonce_known` is a FIFO: write `<32 hex>\n` to `<dir>/nonce_known.nonce`,
  then read the FIFO to EOF. Used by `integration_enroll_verify::principals_not_enforced_detected_and_rolled_back`
  with `PauseHooks` + `PrincipalsNotEnforced::write_at_nonce_known` (passes here).
- U5-scripts → U5-pure (2026-11-10): `append` (and `remove`) **exit 30 with `reason=write_failed`**
  means a write was attempted and failed (the line may be partly there; `content_hex` follows when
  readable): please classify it `Uncertain`, not `NotApplied(Refused)` (U5S-Q5). Fence exit 40 now
  also covers a lock it must not break (`reason` `lock_other_token` | `lock_foreign` |
  `lock_replaced`; U5S-Q4); fence 43 with `reason=not_after_not_passed` = `--terminate` asked
  before the record's not-after (nothing signalled).
- U5-scripts → U5-io (2026-11-10): (1) the verifier's clock command `awk 'BEGIN { srand(); print
  "HM1 now=" srand() }'` reads **nanoseconds** on Debian 13's mawk 1.3.4 (U5S-Q1); the scripts use
  `script::REMOTE_CLOCK_COMMAND` (POSIX `date -u` + awk). (2) CLI test form: in a debug build with
  `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` set, write `script::test_form::insert_pause_points(&step.script,
  &PauseDir::parse(dir)?)` instead of `step.script` (U5S-Q2); close ssh's stdin right after writing.
- U5-scripts → U11 (2026-11-10): (1) please add `acl` to `shells::DEBIAN_DOCKERFILE` (so `setfacl`
  exists); until then `integration_enroll_registry` builds its own `heimdall-u5s-debian-acl:local`
  (DEBIAN_BASE + procps + acl, label `heimdall.fixture=u5-scripts`, network only at build) for the
  Docker `acl_indicator_refused` row, and a MANIFEST row may be wanted for it. (2) `LaggingClock`: the
  scripts' `remote_now` comes from `date -u` (U5S-Q1), so a lag there needs a `date` wrapper too.
