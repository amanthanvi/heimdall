# M03 wave 2: shared readings and landed interfaces (untracked; integrator + units)

Read the code for exact signatures. Each unit appends what it lands to **its own section**, as
soon as it compiles. Requests to another unit go under "Requests".

## 0. Landed by the integrator before the units started

**Test targets (`[[test]]`, path `../../tests/<layer>/<name>.rs`; placeholder files exist, the
owner fills them; a target must run ≥ 1 test on the host):**

| Target | File | Host crate | Owner |
|---|---|---|---|
| `integration_managed_signer` | `tests/integration/managed_signer.rs` | heimdall-credential | U2 |
| `integration_managed_identity_forms` | `tests/integration/managed_identity_forms.rs` | heimdall-credential | integrator (INT-Q10) |
| `integration_issuer_child` | `tests/integration/issuer_child.rs` | heimdall-issuer | U3 |
| `model_issuer_linearization` | `tests/model/issuer_linearization.rs` | heimdall-issuer | U3 |
| `integration_projection_managed` | `tests/integration/projection_managed.rs` | heimdall-localenv | U8 |
| `e2e_consumer_m03` | `tests/e2e/consumer_m03.rs` | heimdall | U8 |

**Dev-dependencies added:** heimdall-credential: testkit now `["fixtures", "managed"]`, tokio
`test-util`, `heimdall-store`. heimdall-issuer: tokio `test-util`, `heimdall-store`.
Cargo.lock: only `heimdall-credential`'s dependency array (+ `heimdall-store`).

**Cross-target helper:** `bash .m03-wave2-xcheck-windows.sh -p <pkg> …` (clippy `--all-targets
-D warnings` for `x86_64-pc-windows-gnu`, zig shims in a removed mktemp dir). Linux:
`bash tools/validation/linux-xcheck.sh -p <pkg> …`.

## 1. Readings for all units (integrator)

- **R1. Docker / owner-blocked / later-unit gating:** as wave 1 (brief §4).
- **R2. `TimeGate::assess_read_only` (§17.15 item 8, wave-2 acceptance).** U3 writes the body
  (`crates/app/src/timegate.rs`, the `assess_read_only` addition only) and
  `crates/app/src/issuance_ro.rs`. Once it lands, the **integrator** switches the authorization
  seam's default (`app::operations::narrowing::AuthorizationTime`, today `Peek`) to `ReadOnly`
  in `operations/narrowing.rs` (U0b's file). U2's tests must pass under `ReadOnly`; build them
  so they do not depend on the default (call `Operations::set_authorization_time` explicitly if
  a test needs one mode).
- **R3. Verification signatures (INT-Q13, escalated by the integrator).**
  `Operations::admit`/`precheck` refuse every `SignatureSubject::Verification` with
  `SignRefusal::Unavailable` (`crates/app/src/operations/authorize.rs:277`, `:343`), and a
  `SignPermit` can only be built from a grant's gate (`app::managed::SigningGates::permit`). So
  in production **every verification-endpoint signature is refused** until the orchestrator
  rules. U2: the verification endpoint goes through `precheck` → `admit` like a grant endpoint
  and sends a signature **only with a permit**; no ungated path for verification (named switch
  `signer::VERIFICATION_UNGATED_SIGNING: bool = false`, documented). U2's verification-endpoint
  tests (listing, counters, install of two certificates, session-bind counting) use a fixture
  `SignatureAuthority` in the test file. K_verify: per ADR-0008 D2's table the verification
  endpoint lists **K_verify and the certificate currently in use** (unlike K_env, which is never
  listed, F17); the verification purpose check is U2's design (userauth `key_blob` must be the
  installed certificate; the agent request may name the plain K_verify blob, as 9.6p1 asks for
  it when `IdentityFile` is K_verify's `.pub`, the D5 §6.5 item 3 generated configuration).
- **R4. INT-Q10 (§17.18 item 3).** The integrator investigates the managed-alias identity forms
  per client in `integration_managed_identity_forms` and writes the outcome under §INT-Q10
  below. **U8:** implement the managed section's identity directives behind a named switch
  `ManagedIdentityForm` (at least: `D10AsWritten` = `IdentitiesOnly yes`, `IdentityFile
  key.pub`, `CertificateFile cert.pub`; `CertificateAsIdentityFile` = `IdentitiesOnly yes`,
  `IdentityFile cert.pub`, no `CertificateFile`; `CertificateAsIdentityFileAndCertificateFile`
  = both lines naming the certificate), one place that selects the default, used by P and by
  `connect`'s command-line options alike. **U2:** the environment and binding endpoints list
  certificates only (F17, D2 item 4); never the plain K_env blob, in any form.
- **R5. The test store kind (§17.17 item 13).** Lands only if U3 registers a CA **through the
  wire** (a `RegisterIssuer` request). U3's tests seed issuer/CA records through the store
  directly (test-only writes), so by default it does **not** land in wave 2; U3 reports.
- **R6. Endpoint names (D2 item 2, D10 item 1).** Unix: environment `<runtime_dir>/signing.sock`;
  binding `<runtime_dir>/b/<16 hex>/agent.sock` (dir 0700, socket 0600); verification
  `<runtime_dir>/v/<16 hex>/agent.sock`. Windows: `\\.\pipe\heimdall-<installation token>-signing`
  (stable; `meta: windows_environment_pipe_token`), `\\.\pipe\heimdall-<token>-b<16 hex>`,
  `\\.\pipe\heimdall-<token>-v<16 hex>`; P renders the environment pipe as
  `//./pipe/heimdall-<token>-signing`. The 16 hex are random (never derived from IDs/labels).
  U2 lands these as pure path/name functions first; U8 renders from them.
- **R7. Slot files (D10 items 1–2).** `<data_dir>/managed/<destination-id>/key.pub` and
  `cert.pub`, public, written atomically by generation (U6's `ManagedEffects::materialize`,
  wave 3). U8 renders the paths from one function (land it in U8's section) that U6 will reuse.

## U2 (signer, endpoints, table): landed interfaces
(U2 appends here.)

**Landed 2026-11-10 (compiles; `cargo check -p heimdall-credential --lib` 0). Bodies are real;
tests follow.** Manifest: credential `[dependencies]` + `tokio`, `tokio-util`, `async-trait`
(all pinned; Cargo.lock: only `heimdall-credential`'s array, + `async-trait`, + `tokio-util`).

**R6 endpoint names (pure; `heimdall_credential::endpoints`) — U8 renders from these:**
```rust
pub const ENDPOINT_TAG_HEX: usize = 16; ENVIRONMENT_SOCKET = "signing.sock"; BINDING_DIR = "b";
pub const VERIFICATION_DIR = "v"; AGENT_SOCKET = "agent.sock"; PIPE_PREFIX = r"\\.\pipe\heimdall-";
pub const RENDERED_PIPE_PREFIX = "//./pipe/heimdall-"; MAX_PIPE_TOKEN = 64;
pub struct EndpointTag;  EndpointTag::generate() -> Result<_, RandomnessUnavailable> /* OS CSPRNG */,
                         ::parse(&str) -> Option<_> /* 16 lowercase hex */, .as_str()
pub fn pipe_token_ok(&str) -> bool;                                    // 1..=64 ASCII alnum
pub fn environment_socket(runtime_dir: &Path) -> PathBuf;              // <rd>/signing.sock
pub fn binding_dir(rd, &EndpointTag) -> PathBuf;                       // <rd>/b/<tag>      (0700)
pub fn binding_socket(rd, &EndpointTag) -> PathBuf;                    // <rd>/b/<tag>/agent.sock (0600)
pub fn verification_dir(rd, &EndpointTag) / verification_socket(rd, &EndpointTag)   // <rd>/v/<tag>[/agent.sock]
pub fn environment_pipe(token) -> Option<String>;                      // \\.\pipe\heimdall-<token>-signing
pub fn binding_pipe(token, &EndpointTag) / verification_pipe(token, &EndpointTag)   // ...-b<tag> / ...-v<tag>
pub fn rendered_environment_pipe(token) -> Option<String>;             // //./pipe/heimdall-<token>-signing (P)
pub enum EndpointLayout { Unix { runtime_dir }, Windows { token } }
  EndpointLayout::unix(&Path) -> Option<_> /* UTF-8 only */, ::windows(&str) -> Option<_>,
  .environment() / .binding(&tag) / .verification(&tag) -> contract::provider::EndpointRef,
  .rendered_environment() -> String   // what P writes after IdentityAgent (Unix path | //./pipe/…)
pub fn endpoint_resource(id: ResourceId, &BindingId, ResourceGeneration, &EndpointRef, updated_at) -> ManagedResource // kind Endpoint
```
**`EndpointRegistry`** (`Clone`; M01 `ipc::{unix,windows}::Listener` + `verify_peer`; per-connection
`serve_with_limits`; ≤ 64 connections per endpoint):
```rust
EndpointRegistry::new(EndpointLayout, ExpectedOwner, SignerTable, Arc<dyn SignatureAuthority>, SignerLimits, CancellationToken)
  .with_hook(Arc<dyn SignHook>)              // test-only pause points, on every signer created afterwards
  .table() / .layout() / .environment() -> EndpointRef
  .start_environment() -> Result<EndpointRef, EndpointError>
  .create_binding(&BindingId, ResourceGeneration) -> Result<EndpointRef, EndpointError>  // random <tag>; lists the grant attached in the table
  .binding_endpoint(&BindingId) -> Option<(EndpointRef, ResourceGeneration)>             // newest generation
  .remove(&ManagedResource) -> Result<(), AdapterError>  // generation- and locator-bound; others Ok, untouched
  .create_verification(&OperationId) -> Result<VerificationEndpoint, EndpointError>
  .signer(&SignerEndpoint) -> Option<Arc<ManagedSigner>>; .stop_all()
impl VerificationEndpoints for EndpointRegistry; impl ResourceCleaner for EndpointRegistry (delete = remove)
pub struct VerificationEndpoint;  // impl VerificationSession: install(line) accepts 2 certs (positive, then negative);
                                  // .key_fingerprint(); Drop = K_verify zeroized + endpoint removed
pub async fn serve_connection(stream, PeerIdentity, EndpointRef, Arc<dyn Signer>, &ExpectedOwner, ServeLimits, CancellationToken) -> io::Result<()>
pub fn peer_admitted(&PeerIdentity, &ExpectedOwner) -> bool
```
**`SignerTable`** (`heimdall_credential::table`; in-memory only, see U2-Q1/Q2):
```rust
SignerTable::new(Arc<KeyVault>); .vault(); .set_install_view(Arc<dyn InstallView>)
.register(&GrantId, VaultSlot, PublicKeyInfo, &[AccessPair]) -> Result<KeyRegistration, RegisterRefusal>  // instance pending
.generate(&GrantId, &[AccessPair]) -> Result<KeyRegistration, RegisterRefusal>
.install(&GrantId, &AccessPair, &Certificate, &IssuanceEntry /* published */) -> Result<(), InstallRefusal>  // async
.attach_binding(&BindingId, &GrantId); .detach_binding(&BindingId); .binding_grant(&BindingId)
.materialize(&BindingId, &[AccessPair]) -> Result<(), MaterializeRefusal>; .unmaterialize(&BindingId)   // ≤ 1 binding per pair
.destroy_grant(&GrantId) -> bool          // unlist everywhere, drop certs, KeyVault::destroy
.list(&SignerEndpoint) -> Vec<(Vec<u8>, String)>   // ≤ 64; comments heimdall:<12 chars of the ID's random part>
.resolve(&SignerEndpoint, key_blob) -> Option<SignTarget>; .instance_state(&GrantId) -> Option<CredentialState>
.register_verification(&OperationId) / .install_verification(&OperationId, &Certificate) / .destroy_verification
#[async_trait] pub trait InstallView { async fn check(&self, &GrantId, &IssuanceEntry) -> Result<(), InstallRefusal>; }
pub const INSTALL_STORE_VIEW_WIRED: bool = false;  // no view → every install refused (StoreViewUnavailable)
pub fn instance_transition(CredentialState, InstanceEvent) -> Result<CredentialState, InvalidInstanceTransition> // D2 table
```
Listing (F17/R4/R3): environment = installed **certificates** of materialized bindings' pairs; binding
= its grant's installed **certificates**; verification = plain K_verify + the current certificate.
The plain K_env blob is never listed and never resolves (refused before authorization).
**`ManagedSigner`** (`heimdall_credential::signer`): `new(SignerEndpoint, SignerTable, Arc<dyn
SignatureAuthority>, SignerLimits)`, `.with_hook`, `.refusals() -> Vec<&'static str>`, `.counters()`;
`SignerLimits::from_limits(&Limits)`; `SignStep::{Purpose, Prechecked, Admitted, Signing, Signed}`;
`trait SignHook { fn at(&self, &SignerEndpoint, SignStep) -> HookFuture<'_>; }`;
`VERIFICATION_UNGATED_SIGNING = false` (INT-Q13).

## U3 (issuer child, protocol, client, ca, check; issuance_ro; assess_read_only): landed interfaces
(U3 appends here.)

**Landed 2026-11-10 (compile; `cargo check -p heimdall-app -p heimdall-issuer` 0).**
```rust
// heimdall_issuer::ca
pub struct CaSet;            // K_ca by fingerprint; Debug shows fingerprints/states only; drop zeroizes
pub enum CaSetError { NotLoadable, WrongKey }
impl CaSet {
    pub fn new() -> Self;
    pub fn insert(&mut self, fp: &CaFingerprint, key: SecretCaKey, state: CaState) -> Result<(), CaSetError>; // active|pending only
    pub fn loaded(&self) -> Vec<protocol::LoadedCa>;
    pub fn state(&self, fp: &CaFingerprint) -> Option<CaState>;
    pub fn holds_public(&self, subject: &ssh_key::PublicKey) -> bool;
    pub fn unload(&mut self, fp: &CaFingerprint) -> bool;   // zeroizes
    pub fn clear(&mut self);
    pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
    /// steps 3 (subject is a held CA key → ceiling_exceeded), 4 (grant: active only;
    /// verification: active|pending; else ca_not_loaded) and 5 (build_and_sign)
    pub fn sign(&self, table: IssuanceTable, bounds: &CertificateBounds, subject: &ssh_key::PublicKey)
        -> Result<ssh_key::Certificate, IssuerRefusal>;
}
// heimdall_issuer::check (one read transaction over the read-only store)
pub fn verify_reservation(ro_store: &Store, time: &heimdall_app::timegate::TimeGate,
    entry: &IssuanceRef, subject: &str /* OpenSSH line */) -> Result<CertificateBounds, IssuerRefusal>;
pub const ALLOWED_EXTENSIONS: [&str; 4]; pub const VALIDITY_SLACK: Duration; pub const VERIFICATION_VALIDITY: Duration;
pub fn principal_within_ceiling(&str) -> bool; pub fn extensions_within_ceiling(..) -> bool;
pub fn validity_within_ceiling(&CertificateBounds, window: Duration) -> bool;
pub fn key_id_within_ceiling(key_id: &str, environment: &str, id: &str) -> bool;
// heimdall_app::timegate (the assess_read_only addition)
impl TimeGate {
    pub fn assess_read_only(&self, store: &Store) -> TimeStatus;            // persists nothing
    pub fn assess_read_only_in(&self, txn: &mut Txn<'_>) -> heimdall_store::Result<(TimeAnchor, TimeStatus)>;
}
// heimdall_app::issuance_ro
pub const MAX_RESERVATION_AGE: Duration;      // 60 s
pub const ISSUER_FACTS: IssuanceFacts;        // new_activation: true (U3-Q2), subject_registered: true, critical_option: false
pub enum StoredEntry { Grant(IssuanceEntry), Verification(VerificationEntry) }
pub fn stored_entry(txn, &IssuanceRef) -> heimdall_store::Result<Option<StoredEntry>>;   // interim scan (U3-Q1)
pub fn subject_fingerprint(openssh_line: &str) -> Option<String>;                       // "SHA256:…"
pub fn assess(txn, &IssuanceRef, subject: &str, now: &TimeAnchor, time: &TimeStatus)
    -> heimdall_store::Result<Result<CertificateBounds, IssuerRefusal>>;               // frozen signature
```
**`assess_read_only` semantics (§17.15 item 8):** the gate's rules over a read transaction,
persisting nothing; **fails closed without an anchor**: an observation with no same-boot
reference (no runtime anchor, no attended confirmation of this boot) is `Uncertain
(Unsynchronized{sync})` even on synchronized time; a store read error is `Uncertain
(Unsynchronized{Unknown})`. Under `AuthorizationTime::ReadOnly`, a world needs a runtime anchor
(any Safe `TimeGate::check`, e.g. the activation's) before a signature is admitted.

**Landed 2026-11-10, bodies (tests green here):**
```rust
// heimdall_issuer::child — run(stdin, stdout, Box<dyn SecretStore>, db, Arc<dyn Clock>) -> i32 (frozen)
pub const EXIT_UNAVAILABLE: i32 = 69; pub const EXIT_USAGE: i32 = 2 /* tty stdin */; pub const EXIT_PROTOCOL: i32 = 76;
pub const SIGNATURES_PER_MINUTE: usize = 600; pub const CERTIFICATES_PER_SUBJECT: u32 = 64; // per K_env = per activation/re-issue
// heimdall_issuer::client
pub const REQUEST_TIMEOUT /*10 s*/, HELLO_TIMEOUT /*5 s*/, BACKOFF_BASE /*1 s*/, BACKOFF_CAP /*60 s*/, STOP_TIMEOUT /*5 s*/: Duration;
pub const MAX_RESTART_ATTEMPTS: u32 = 8; pub fn backoff_ceiling(attempt: u32) -> Duration;
pub trait Jitter: Send + Sync { fn delay(&self, ceiling: Duration) -> Duration; } pub struct SystemJitter;
pub type StartToken = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>; // U10: heimdall_runtime::platform::process_start_time
pub struct ChildIdentity { pub pid: u32, pub start_token: Option<String> }
pub struct ChildCommand { pub program: PathBuf, pub args: Vec<OsString>, pub env: Vec<(OsString, OsString)> }
impl ChildCommand { pub fn internal_issuer() -> io::Result<Self>; } // current_exe + ["internal","issuer"]
pub struct ClientConfig { pub command, pub jitter, pub start_token, pub request_timeout, pub hello_timeout }
impl ClientConfig { pub fn new(command: ChildCommand, start_token: StartToken) -> Self; }
pub struct ChildIssuer; // Clone; implements app::ports::IssuerPort (status/sign/unload)
impl ChildIssuer { pub fn new(ClientConfig) -> Self; pub async fn start(&self) -> Result<(), IssuerError>;
    pub async fn reload(&self) -> Result<(), IssuerError> /* issuer unlock */; pub async fn stop(&self);
    pub fn identity(&self) -> Option<ChildIdentity>; pub fn loaded_cas(&self) -> Vec<LoadedCa>; pub fn state(&self) -> IssuerState;
    pub async fn child_status(&self) -> Result<(Vec<LoadedCa>, u64, u64), IssuerError>; }
```
`IssuerPort::status()` leaves `cas` empty (the registered CA records are the store's; U10 fills them),
`issuer_isolation: same_user_process`. Errors: `Unavailable("issuer_not_initialized" | "issuer_unavailable" |
"issuer_restarting" | "issuer_store_locked" | "issuer_store_unavailable")`, `Timeout`, `Refused(IssuerRefusal)`.
**`heimdall internal issuer`** (`m03_cmd::internal` → `internal_issuer`): tty → the envelope (exit 2); a pipe →
`child::run(stdin, stdout, store, <state>/state.db, clock)`, nothing else on stdout; release build + any
`HEIMDALL_TEST_*` → exit 2; store = `m03_cmd::issuer_store(ctx, paths, env, scratch)` (macOS login keychain via
`localenv::sys::account_home`; Windows DPAPI `<state>/issuer/<env>` under an explicit home else
`%LOCALAPPDATA%\Heimdall\issuer\<env>`; Linux Secret Service); scratch → `None` until U3-Q4. Clock: system,
shifted by `HEIMDALL_TEST_CLOCK_OFFSET_S` in a test build. `m03_cmd::SCRATCH_STORE_DIR = "scratch-secret-store"`.
**Test store kind (§17.17 item 13; R5): not landed** — U3 registers no CA through the wire; tests seed
`issuers` rows through the store.
**For the integrator (R2 flip):** `tests/model/narrowing_m03.rs:754-757` (`authorize_refuses_each_predicate`,
U0b's) asserts `ReadOnly` refuses `TimeUncertain` (the wave-0 stub). With the body it admits (the world has a
runtime anchor), so that test now fails at :757. Suggested replacement: under `ReadOnly`, `assert!(admit.is_ok())`,
then set `wall_back = 3600 s` and assert `TimeUncertain`, then reset.

**Reserved-file hunks (integrator authorization; behaviour-preserving):**
`crates/app/src/operations.rs`: `run_issuance_check` split into the shared
`issuance_predicate(tx, env, &IssuanceSnapshot, pair, bounds, facts, time, admission, now)`
(the snapshot assembly: ancestry copies, merged/continuing policy, expected revision,
tombstone, CA facts, `issuance::check`) plus the new `pub(crate) fn issuance_check_read_only(tx,
entry, facts, now, time)` (no re-validation recorded: a stale grant/ancestor/entry generation
refuses `stale_generation`/`stale_ancestor` after the predicate passes; the mechanism judged
from the store's degraded rule only); `pub(crate) use verification_m03::verification_check_read_only;`.
`crates/app/src/operations/verification_m03.rs`: new `pub(crate) fn verification_check_read_only(tx,
entry, subject_registered, time, now, max_validity)` (the publish predicate; the enrollment from the
operation's stored `enrollment.verify` request, else `operation_not_verifying`).

## U8 (projection, consumer integration, M02 residuals): landed interfaces
(U8 appends here.)

**Landed 2026-11-10 (compiles; clippy `-D warnings` clean for sshconf, localenv, heimdall,
testkit+managed).** No manifest change.

`heimdall_sshconf::render` (the directive-set revision; reading R4, INT-Q10):
```rust
pub enum ManagedIdentityForm { D10AsWritten, CertificateAsIdentityFile, CertificateAsIdentityFileAndCertificateFile }
pub const DEFAULT_MANAGED_IDENTITY_FORM = ManagedIdentityForm::CertificateAsIdentityFile; // INT-Q10 (set)
ManagedIdentityForm::select(Option<OpenSshVersion>) -> Self   // THE selector (P and connect); ::ALL; .as_str()
pub enum Section { ExistingAccess(ManagedAlias),            // M02 bytes, unchanged
    ManagedCertificate { alias, hostname, port, user, endpoint: RenderPath, key_pub: RenderPath,
                         cert: RenderPath, control_path: Option<RenderPath> } }
pub fn render_sections(&[Section], PathStyle, ManagedIdentityForm) -> Result<Vec<u8>, RenderError>; rendered_sections(..) -> Rendered
// order: HostName, Port, User, IdentityAgent "<env endpoint>", IdentitiesOnly yes, <form's lines>,
//        ControlMaster no, ControlPath none | "<mux>" (Some refused in a Windows file)
pub fn render_managed(..)  // unchanged signature and bytes (= render_sections over ExistingAccess)
pub fn managed_identity_options(endpoint, key_pub, cert, PathStyle, form) -> Result<Vec<String>, RenderError>
    // ["-o","IdentityAgent=\"…\"","-o","IdentitiesOnly=yes", form's "-o IdentityFile=…"/"-o CertificateFile=…"]
pub const OWNED_LAUNCH_PINS: [&str; 6]  // -o ForkAfterAuthentication=no -o ControlMaster=no -o ControlPath=none
pub enum OwnedOptionConflict { Fork{index}, Master{index}, ControlSocket{index}, ControlCommand{index}, Option{index, keyword} }
pub fn check_owned_ssh_arguments(&[OsString]) -> Result<(), OwnedOptionConflict>  // ssh's BSD getopt, both passes
pub fn owned_ssh_arguments(&[OsString]) -> Result<Vec<OsString>, OwnedOptionConflict>  // pins + args
```
`heimdall_localenv::projection::content` (**R7: the one slot path function; U6 reuses it**):
```rust
pub struct SlotPaths { dir, key_pub, cert_pub }           // <data_dir>/managed/<dest>/{key.pub,cert.pub}
pub fn managed_slot_paths(data_dir: &Path, &DestinationId) -> Result<SlotPaths, SlotPathRefused>
pub fn slot_component(&DestinationId) -> Result<&str, SlotPathRefused>   // U8-Q3: lower-case [a-z0-9._-] only
pub fn managed_mux_path(runtime_dir, &DestinationId) -> Result<PathBuf, SlotPathRefused>  // <rd>/mux/<dest>
pub fn checked_mux_path(runtime_dir, &DestinationId) -> Result<PathBuf, &'static str /* mux_path_too_long */>
pub const SOCKET_PATH_MAX: usize   // 103 macOS, 107 elsewhere
```
`data_dir` is the caller's (U8-Q2; provisional reading `Paths.state_dir`).
`heimdall_localenv::projection` (preview input; the runtime wires it, U10):
```rust
pub struct ManagedSectionSpec { environment_endpoint: EndpointRef, key_pub: PathBuf, cert_pub: PathBuf, control_path: Option<PathBuf> }
pub trait ManagedPairSource: Send + Sync {   // None = existing access; Err refuses the preview
    fn managed_section(&self, &ManagedAliasSpec) -> Result<Option<ManagedSectionSpec>, String>; }
ProjectionConfig.managed: Option<Arc<dyn ManagedPairSource>>   // None: every alias is M02's
ProjectionTestConfig.managed_identity_form: Option<ManagedIdentityForm>   // test override only
LocalProjection::writing(ProjectionConfig) -> Result<LocalProjection, StateDirMissing>  // ADR-0007 §12.34 item 6
```
A managed alias renders the slot files (no M02 key file step) and adds one `slot_free` finding
to the preview (`plan::slot_free_disclosure`).
`heimdall_localenv::projection::plan`: `slot_free_command(alias) -> String` (`heimdall run
--profile <profile> -- ssh <alias>`), `slot_free_disclosure(alias, &DestinationId) -> Finding`
(code `slot_free`, Info; **the doctor reuses it**), `deadline_wording(IdentitySelection,
ExistingConnectionsMode) -> &'static str` + `DEADLINE_{GRACEFUL,STRICT}_{EXCLUSIVE,NOT_EXCLUSIVE}`.
`heimdall_localenv::agents`: `detect_agents_for_client(env, paths, platform,
Option<OpenSshVersion>)`, `identity_agent_references_for_client(..)` (ADR-0007 §12.34 item 3;
the M02 functions are unchanged).
`heimdall` (bin): `run` with a managed binding → `run_cmd::require_slots(&mut dyn ManagedSlots,
&BindingId, &[PairIntegration])` (production `UnavailableSlots`: `driver_unavailable`), an owned
launch (program = verified ssh) gets the pins / refusals (`owned_connection_option_conflict`),
Windows owned launch refused `driver_unavailable` (U7). `connect`: D8 item 2's flow when the
listing names `preference` managed+applied (see Requests); binding files read as
`consumer.signing_endpoint` = `<rd>/b/<tag>/agent.sock` (Windows `\\.\pipe\heimdall-<token>-b<tag>`)
→ `<rd>/b/<tag>/key.pub`, `cert-<destination-id>.pub` (D6 item 1 step 6). **To U6/U10:** fill
`signing_endpoint` with the binding endpoint for a managed binding.
`heimdall_testkit::managed::ManagedRunContext` (integrator grant): the block is now the
renderer's `Section::ManagedCertificate` output in `CONTEXT_IDENTITY_FORM`
(`CertificateAsIdentityFileAndCertificateFile`), route lines left to the caller's section.

## INT-Q10 (integrator): managed-alias identity forms per client
Test: `integration_managed_identity_forms::managed_identity_forms_observed_per_client` (real
`ssh`, `LoopbackSshd` account form, an `ipc::signing::serve` agent over M01's owner-only
listener that **lists only the certificate**, D10 item 1's block shape with each form's
identity lines; one `m03 observation: managed_identity_form` row per form).

Observed (2026-11-10), exit / blob the agent was asked to sign / server accepted the cert:

| form | macOS OpenSSH_10.5p1 (host) | OpenSSH_9.6p1 Ubuntu-3ubuntu13.20 (disposable container; validation, not evidence) |
|---|---|---|
| control (decoy `IdentityFile`, no `IdentitiesOnly`) | 0 / cert / yes | 0 / cert / yes |
| `d10_as_written` (`IdentitiesOnly yes`, `IdentityFile key.pub`, `CertificateFile cert.pub`) | **255 / none / no** | **255 / none / no** |
| `certificate_as_identity_file` (`IdentitiesOnly yes`, `IdentityFile cert.pub`) | 0 / cert / yes | 0 / cert / yes |
| `certificate_as_identity_file_and_certificate_file` | 0 / cert / yes | 0 / cert / yes |
| `key_stem_with_certificate_only` (`IdentityFile <dir>/key`, only `key-cert.pub` on disk) | 0 / cert / yes | 0 / cert / yes |
| `decoy_identity_file_and_certificate_file` | 255 / none / no | 255 / none / no |
| context: D10 as written, slot files 0600 | 255 / none / no | 255 / none / no |
| context: verification shape (agent lists K_verify plain **and** cert; D10 lines) | 0 / **plain** / yes | 0 / **plain** / yes |

Findings: **D10 item 1 as written fails on both clients**, not only on 9.5/9.6: ssh pairs the
`CertificateFile` certificate with the `key.pub` file identity and tries to load a private key
from the public file ("Load key …key.pub: bad permissions"; with 0600 files it still fails),
never asking the agent. Naming the **certificate** as the `IdentityFile` works on both: ssh
matches the agent's certificate to the file identity and asks the agent to sign the
certificate blob.

**Decision (integrator; ADR text change escalated as INT-Q10 in the questions file):** the
default `ManagedIdentityForm` is **`CertificateAsIdentityFile`**: `IdentitiesOnly yes` +
`IdentityFile "<slot>/cert.pub"`, no `CertificateFile`, no `key.pub` line; the same for
`connect`'s command line (`-o IdentitiesOnly=yes -o IdentityFile=<binding cert>`). **U8:** set
this default now. Windows in-box 9.5p2 is observed natively by the orchestrator; if it fails
there, U8 reports the managed alias on that client as `capability_unavailable`
(`client_unsupported`), per client (§17.18 item 3).

**For U2 (verification endpoint, reading R3):** with K_verify's `.pub` as `IdentityFile`,
its certificate as `CertificateFile`, and an endpoint listing both, 10.5p1 asks the agent to
sign the **plain K_verify blob** while the userauth request carries the certificate
(10.5p1 and 9.6p1 alike). The
verification purpose check must accept that (request blob = plain K_verify, userauth
`key_blob` = the installed certificate), and must never extend it to K_env.

## Requests (unit → unit)
(Append `- <from> → <to>: <what, exact signature>`; the owner answers inline.)
- U3 → integrator: U3-Q1 — make `heimdall_store::Txn::issuance_entry(&mut self, &IssuanceId) -> Result<Option<IssuanceEntry>>` (`ext.rs:1474`) and `Txn::verification_entry(&mut self, &IssuanceId) -> Result<Option<VerificationEntry>>` (`ext_m03.rs:638`) `pub` (doc line each). U3 then swaps the scan in `issuance_ro::stored_entry`.
- U3 → integrator: U3-Q4 — `crates/heimdall/Cargo.toml` `[dependencies] heimdall-testkit` features `["app", "managed"]`, so the debug-build `internal issuer` can name `ScratchSecretStore` (branch ready in `m03_cmd::issuer_store`).
- integrator → U2 (2026-11-10): U2 and the integrator both added `async-trait`, `tokio`,
  `tokio-util` to `crates/credential/Cargo.toml` at the same moment (duplicate keys); the
  integrator removed its own copy, U2's block stays. No action needed.
- U8 → integrator (reserved `crates/app/src/operations.rs` `destination_view`, ~line 5093): add
  `"preference": {"mechanism": <PreferredMechanism>, "projection": <ProjectionStatus>}` (the
  stored `pair_preferences` row of the managed definition's (destination, account)) to each
  listed destination. `connect` takes ADR-0008 D8 item 2's flow only when it reads
  `managed_certificate` + `{"state":"applied"}`; without the field it keeps M02's flow.
- U8 → integrator/U10 (`crates/runtime/src/service.rs` `account_projection`/the writer wiring;
  reserved `crates/heimdall/src/testcfg.rs` ~824): build every runtime writer with
  `LocalProjection::writing(config)` (U8-Q1), and wire `ProjectionConfig.managed` with a
  store-backed `ManagedPairSource` (pair preference `managed_certificate` → `ManagedSectionSpec`
  from `EndpointLayout::environment()` and `content::managed_slot_paths(<data_dir>, dest)`; the
  mux path once owned masters are applied).
- U8 → integrator (doctor; `crates/localenv/src/doctor.rs:447`, `crates/heimdall/src/catalog_cmd.rs:408`):
  call `agents::detect_agents_for_client(&ctx.env, &ctx.paths, ctx.platform, ssh_version)`
  (the selected client's version is already at doctor.rs:443), and report
  `projection::plan::slot_free_disclosure(alias, destination)` for every managed alias whose slot
  is `free` (needs U6's slot table read; plan test `doctor_reports_slot_free_with_command`).
- U8 → U6/U0b (classification; `crates/localenv/src/projection/observe.rs`,
  `crates/sshconf/src/relevant.rs`, neither U8's): D10 item 6's `exclusive` for a managed alias
  (only the slot certificate, in the selected form). Today `observe` finds no adopted key file
  for a managed alias, so its selection is `None` → undetermined → refused on the
  no-interaction path (fail closed); `inherited_identityfile_makes_selection_not_exclusive_and_noninteractive_refused`
  waits on it.
- U8 → U6/U10: a runtime request for the slot table that `run` needs (`run_cmd::ManagedSlots`:
  read a pair's `SlotState`, claim a free slot for the binding); until then `run` with a managed
  binding refuses `driver_unavailable`.
- U2 → integrator (2026-11-10): `bash .m03-wave2-xcheck-windows.sh -p heimdall-credential` exits 101 only in
  `tests/integration/managed_identity_forms.rs:114` (`unused variable: home` on Windows: it is used only under
  `cfg(unix)`). Every other credential target is clean on `x86_64-pc-windows-gnu` (the helper's command with
  `--lib --test integration_managed_signer --test integration_credential_cert --test
  integration_credential_memory --test adversarial_signer_requests`, and `--lib --profile test`: exit 0).
