# M03 wave 3: shared readings and landed interfaces (untracked; integrator + units)

Read the code for exact signatures. Each unit appends what it lands to **its own section** as soon
as it compiles. Requests to another unit or to the integrator go under "Requests".

## 0. Landed by the integrator before the units started

| Target | File | Host crate | Owner |
|---|---|---|---|
| `integration_managed_adapter` | `tests/integration/managed_adapter.rs` | heimdall-adapters | U6 |
| `integration_connections` | `tests/integration/connections.rs` | heimdall-runtime | U7 |
| `e2e_deadline_m03` | `tests/e2e/deadline_m03.rs` | heimdall | U7 |

- `pub mod managed;` in `crates/adapters/src/lib.rs` (stub `managed/mod.rs`); `pub mod connections;` in
  `crates/runtime/src/lib.rs` (stub `connections.rs`).
- Root `Cargo.toml`: rustix features `["std", "fs", "process"]` (authorized; `Cargo.lock` gains no
  package). adapters dev-deps: `heimdall-testkit[fixtures,managed]`, `heimdall-issuer`,
  `heimdall-store`, tokio `test-util`, `proptest`, `tempfile` (Cargo.lock: only adapters' array).
- Helpers: `bash .m03-wave3-xcheck-windows.sh -p <pkg> --all-targets` (Windows clippy per
  package); `bash tools/validation/linux-xcheck.sh -p <pkg>`.

## 1. Readings for both units (integrator)

- **R1. Paths (wave-2 R7, U8-Q2/Q3, §17.19 item 6).** `<data_dir>` = `Paths.state_dir`. Every slot path
  comes from `heimdall_localenv::projection::content::managed_slot_paths(data_dir, &DestinationId)`;
  every path component from a destination from `content::slot_component` (an unsafe ID refuses).
  The mux path from `content::checked_mux_path(runtime_dir, &DestinationId)` (`mux_path_too_long`).
  Duplicating these elsewhere is a defect.
- **R2. Binding files (D6 item 1 step 6; wave-2 R6).** `<runtime_dir>/b/<16 hex>/key.pub` and
  `cert-<slot_component(dest)>.pub`, beside the binding endpoint `<runtime_dir>/b/<tag>/agent.sock`
  (Windows: pipe `\\.\pipe\heimdall-<token>-b<tag>`, files under the same `<runtime_dir>/b/<tag>/`).
  The directory comes from `heimdall_credential::endpoints::binding_dir(runtime_dir, &EndpointTag)`.
  `heimdall/src/connect_cmd.rs::binding_files` (U8) derives the same paths from the endpoint string;
  U6's `files` is the producer, and must agree with it byte for byte (U6 adds a test that asserts
  agreement through its own public function; connect_cmd is not edited this wave).
- **R3. The managed identity form (§17.19 item 4; INT-Q10).** Never `key.pub` + `CertificateFile`.
  The alias and every product command line name the **certificate** as the identity file:
  `heimdall_sshconf::render::managed_identity_options(endpoint, key_pub, cert, style,
  ManagedIdentityForm::select(None))` (= `DEFAULT_MANAGED_IDENTITY_FORM`,
  `CertificateAsIdentityFile`) gives `-o IdentityAgent=… -o IdentitiesOnly=yes -o IdentityFile=<cert>`.
  U6's files must provide exactly the `cert-<dest>.pub` and slot `cert.pub` this reads (one OpenSSH
  certificate line + `\n`). `key.pub` is still written (D6 step 6, slot table), but nothing names it
  as an identity.
- **R4. The owned master's argv (U7; D8 item 3 as amended by §17.19 item 4 and §17.4 item 7).** D8
  item 3's identity options (`IdentityFile=<key.pub>`, `CertificateFile=<cert>`) are superseded by
  R3. `OWNED_LAUNCH_PINS` is `[-o ForkAfterAuthentication=no, -o ControlMaster=no, -o
  ControlPath=none]`; its `ControlMaster`/`ControlPath` pins contradict a master, and ssh takes the
  first value obtained, so the master uses **only its first pin pair** (`OWNED_LAUNCH_PINS[0..2]`,
  asserted equal in a test, never retyped) and then its own: `-M -N -o ControlMaster=yes -o
  ControlPersist=no -o ControlPath=<checked_mux_path>`, the R3 identity options for the **binding's**
  endpoint and cert, `-o ClearAllForwardings=yes -o ExitOnForwardFailure=yes -o BatchMode=yes`, then
  `-- <alias>`. Foreground child, never `-f`. (Recorded as W3-Q1 for the orchestrator to confirm.)
- **R5. Seams that stay closed until U10 (wave 4); do not open them.** U2-Q1 (`credential_instances`
  rows persisted by U10 from `SignerTable::register`'s `KeyRegistration`); U2-Q2
  (`SignerTable::install` refuses without an `InstallView`, `table::INSTALL_STORE_VIEW_WIRED = false`;
  `ManagedEffectsImpl::install` goes through it, tests set a fixture view); INT-Q13 (every
  verification signature refused, `VERIFICATION_UNGATED_SIGNING = false`); U8-Q6 (no `preference`
  on `inspect destinations`: managed `connect` keeps M02's flow); `app::managed::drive_preparation`
  stays U10's (fails closed `MANAGED_DRIVER_NOT_WIRED`); `dispatch.rs` keeps refusing
  `Request::Connections(_)` with `driver_unavailable` (so the CLI's registration request fails →
  fail closed); `service.rs`/`supervisor.rs` untouched. U6 computes and performs effects only when
  asked (D6 item 0). Tests that need the stage sequence use a **test-local driver** in the test file
  that calls U6's effects and the real `Operations` store transactions in the documented order — it
  is a fixture, never production code, and its results are labelled "fixture driver" in the report.
- **R6. No new production crate edges** (m03-plan §0.6; `tools/validation/crate_graph.py`).
  `heimdall-adapters` may depend only on contract, domain, app, ipc, localenv, credential. So U6's
  `read_sources` reads through a **source trait** defined in `heimdall_adapters::managed` (the M02
  `integration::IntegrationSources` pattern: every default claims nothing, fail closed), which U10
  implements over the store. The test file implements it over a real `heimdall_store::Store`
  (dev-dependency). `heimdall-runtime` already has store, app, localenv, adapters, credential.
- **R7. Q20 (§17.3 item 3).** Removing a CA degrades **every grant whose certificate is under it**;
  "no verified enrollment remains" governs only the pair's **preference**. U6's
  `removal_degrades_only_grants_under_removed_ca` asserts that; there is no switch to flip.
- **R8. Process identity and signalling (U7; D8 item 2 "Closing").** New FFI lives **only** in
  `crates/localenv/src/sys/mod.rs` (its module-doc table and overview §9 item 3 updated). Start-time
  tokens compared for equality must come from the same source that wrote them:
  Unix rows are written at bind by U0b row 19 with `heimdall_runtime::platform::process_start_time`'s
  token; Windows rows are written by `Operations::register_owned_connection`
  (`crates/app/src/operations/connections.rs`) with `start_token = created_at.to_string()` (a
  `Timestamp` of the creation time the launcher read). Linux: `pidfd_open` (rustix, safe) **first**,
  then verify start time and `/proc/<pid>/exe`, then signal through the pidfd only (open-then-verify
  is sound: a matching start time proves the pidfd names that process). macOS: verify start time
  (platform.rs) and `proc_pidpath` image, then `kill` (window disclosed). Windows:
  `OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)`, creation time and image read
  **on that handle**, then `TerminateProcess` on it. An identity that does not verify is reported
  `unverified` and never signalled.
- **R9. Windows owned launch (§17.3 item 1, §17.4 item 8; wave-2 request).** `run`'s Windows owned
  launch is refused `driver_unavailable` today (`crates/heimdall/src/run_cmd.rs` `managed_checks`,
  `owned && cfg!(windows)`). U7 replaces that refusal with the contained path behind
  `launch_uses_kill_on_close_job(binding, program)` (true only for a managed binding whose program is
  the verified `ssh`): `JobObject::spawn_suspended(command) -> SuspendedChild { pid, created_at, job }`,
  registration while suspended through a caller-supplied registrar (production: `Request::Connections
  (Register)`, refused by dispatch until U10 → the job closes, the child dies never resumed,
  `prelaunch_failed` with `connection_registration_failed`), `SuspendedChild::resume()` only after a
  successful reply. `run` of any other program keeps M02's semantics (no job; `not_controlled`).
  The integrator authorizes U7 to edit exactly that refusal in `run_cmd.rs` (U8's file) and to add
  the contained call in `crates/launch/src/windows.rs`; `connect_cmd.rs`'s Windows refusal stays (its
  managed flow is closed by U8-Q6) unless trivially shared — note it either way.

## U6 (the managed credential adapter): owner paths and the interface U7 builds on

Owner paths: `crates/adapters/src/managed/{mod,effects,prepare,reissue,report,files}.rs`;
`tests/integration/managed_adapter.rs`.

**Declared now (U6 must land these names first, then the bodies; U7 builds against them):**
```rust
// heimdall_adapters::managed::files
pub const BINDING_KEY_FILE: &str = "key.pub";
pub fn binding_cert_name(dest: &DestinationId) -> Result<String, SlotPathRefused>;      // "cert-<component>.pub"
pub struct BindingFiles { pub directory: PathBuf, pub key_pub: PathBuf,
                          pub certificates: Vec<(DestinationId, PathBuf)> }            // what is (to be) on disk
pub fn binding_files(runtime_dir: &Path, tag: &EndpointTag, dests: &[DestinationId])
    -> Result<BindingFiles, SlotPathRefused>;                                          // pure paths, R2
pub fn binding_files_for_endpoint(runtime_dir: &Path, endpoint: &EndpointRef, dests: &[DestinationId])
    -> Option<BindingFiles>;                                                           // Unix socket / Windows pipe → dir; None = not a binding endpoint
// heimdall_adapters::managed::report
pub fn owned_connection_reports(rows: &[OwnedConnection]) -> Vec<OwnedConnectionReport>; // F15: closing|closed|unverified
pub fn revoke_notes() -> Vec<RevokeNote>;                                                // always [ordinary_connections_not_closed]
pub fn owned_multiplexing(policy: &ConnectionPolicy, platform: Platform, claims: &[Claim]) -> OwnedMultiplexing;
```
(U6 may refine argument types; record any change here before U7 relies on it.)

U6 landed interfaces:
**Step 1, landed 2026-11-11 (compiles: `cargo check -p heimdall-adapters` 0; real bodies).** Refinements vs the
declaration: `binding_files_for_endpoint` takes `&EndpointRef` (kind `UnixSocket` | `NamedPipe`, other kinds
→ `None`); `owned_multiplexing`'s `Platform` is `heimdall_domain::claims::Platform`; `SlotPathRefused` is
`heimdall_localenv::projection::content::SlotPathRefused` (re-exported from `files`).
```rust
// heimdall_adapters::managed::files
pub const BINDING_KEY_FILE: &str = "key.pub";
pub const GENERATION_FILE: &str = ".generation";             // "<generation> <binding-id>\n", written first, removed last
pub fn binding_cert_name(dest: &DestinationId) -> Result<String, SlotPathRefused>;   // "cert-<slot_component>.pub"
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindingFiles { pub directory: PathBuf, pub key_pub: PathBuf,
                          pub certificates: Vec<(DestinationId, PathBuf)> }   // + fn certificate(&self, &DestinationId) -> Option<&Path>
pub fn binding_files(runtime_dir: &Path, tag: &EndpointTag, dests: &[DestinationId])
    -> Result<BindingFiles, SlotPathRefused>;          // endpoints::binding_dir(runtime_dir, tag)
pub fn binding_files_for_endpoint(runtime_dir: &Path, endpoint: &EndpointRef, dests: &[DestinationId])
    -> Option<BindingFiles>;                            // = connect_cmd::binding_files' derivation (R2)
pub fn write_binding_files(files: &BindingFiles, binding: &BindingId, generation: u64, key_pub: &str,
    certs: &[(DestinationId, String)]) -> Result<Vec<PathBuf>, FilesError>;
pub fn clear_binding_files(files: &BindingFiles, binding: &BindingId, generation: u64) -> Result<ClearOutcome, FilesError>;
pub fn binding_directories_of(runtime_dir: &Path, binding: &BindingId) -> Vec<(PathBuf, u64)>;
pub struct SlotRoot { pub data_dir: PathBuf /* Paths.state_dir */, pub environment: EnvironmentId }
pub fn slot_paths(data_dir: &Path, pair: &AccessPair) -> Result<SlotPaths, SlotPathRefused>;   // managed_slot_paths
pub fn write_slot(root: &SlotRoot, env: &EnvironmentId, pair: &AccessPair, binding: &BindingId, generation: u64,
    key_pub: &str, cert: &str) -> Result<Vec<PathBuf>, FilesError>;
pub fn clear_slot(root: &SlotRoot, env: &EnvironmentId, pair: &AccessPair, generation: u64) -> Result<ClearOutcome, FilesError>;
pub fn slot_generation(root: &SlotRoot, pair: &AccessPair) -> Result<Option<u64>, FilesError>;
pub enum ClearOutcome { Removed, Absent, OtherGeneration(u64), Unmarked }
// heimdall_adapters::managed::report
pub fn owned_connection_reports(rows: &[OwnedConnection]) -> Vec<OwnedConnectionReport>; // up|closing→closing, closed, unverified
pub fn revoke_notes() -> Vec<RevokeNote>;                                                // [ordinary_connections_not_closed]
pub fn owned_multiplexing(policy: &ConnectionPolicy, platform: Platform, claims: &[Claim]) -> OwnedMultiplexing;
    // policy disabled → disabled (every platform; the golden is a Windows result); owned_masters: windows → unavailable,
    // else closed_at_deadline only with its claim, else unknown
pub fn current_platform() -> Platform;                   // std::env::consts::{OS, ARCH}
```

**Step 2, landed 2026-11-11 (compiles, clippy `-D warnings` host + Windows + Linux clean; tests green here).**
```rust
// heimdall_adapters::managed (mod.rs)
pub const RENEW_THROUGH_DRIVER: &str;                         // renew() through the port fails closed (R5)
pub fn managed_capabilities() -> BTreeSet<Capability>;        // ssh_authentication, agent_forwarding
pub fn lock_continuity_from(&[Claim], &Platform) -> LockContinuity;   // Verified only with its claim, else Unknown
pub fn baseline_enforcement() -> Enforcement;                  // empty-claim-table values
pub struct ReissueInput<'a> { stored, origin, time, admission, lock_behavior, read: &StoreRead }
pub struct ManagedCertificateAdapter;   // impl CredentialAdapter (mechanism managed_certificate,
    // external_side_effects + remote_credential_effect true, interaction None)
impl ManagedCertificateAdapter {
    pub fn new(instance: &str, sources: Arc<dyn ManagedSourceRead>, effects: Option<ManagedEffectsImpl>,
               layout: Option<EndpointLayout>) -> Self;            // platform = report::current_platform()
    pub fn for_platform(.., platform: Platform) -> Self;
    pub fn effects(&self) -> Option<&ManagedEffectsImpl>;
    pub fn reissue_from(&self, req: PrepareRequest<'_>, sources: &IntegrationSnapshot, input: &ReissueInput<'_>)
        -> Result<PrepareOutcome, AdapterError>;                   // U10's managed_reissue_pass computes with this
}
// revoke(grant, now): destroys K_env of sources.cascade(grant) through effects; RevokeOutcome
//   { remote_pending: dests pending, latest_possible_credential_expiry: max valid_before reserved|published,
//     remote_effects: per (dest, account), statuses as at revocation (never moved on the caller's `now`) }.
// reconcile: NotApplied (nothing published) | Applied(sources.recorded_outcome) (all published+installed under
//   this token) | Unknown.
// heimdall_adapters::managed::prepare
pub struct GrantTerms { pub lock_behavior: LockBehavior, pub policy: ConnectionPolicy }
pub trait ManagedSourceRead: Send + Sync {   // R6; U10 implements over the store; every default claims nothing
    fn enrollments(&self, &[AccessPair]) -> Vec<EnrollmentRecord>;  fn issuing_cas(..) -> BTreeMap<AccessPair, BTreeSet<CaFingerprint>>;
    fn slots(..) -> Vec<ManagedSlot>;  fn claims(&self) -> Vec<Claim> /* default: CLAIMS for the running platform */;
    fn issuer(&self) -> Option<IssuerStatusSnapshot>;  fn prepared(&self, &[AccessPair]) -> Option<ManagedPrepared>;
    fn terms(&self, &GrantId) -> GrantTerms /* in-memory, U6-Q5 */;  fn cascade(&self, &GrantId) -> Vec<GrantId>;
    fn issuance_entries(&self, &[GrantId]) -> Vec<IssuanceEntry>;  fn key_only_restore(&self) -> bool;
    fn recorded_outcome(&self, &GrantId, token: &str) -> Option<PrepareOutcome>;
    fn owned_connections(&self, &[GrantId]) -> Vec<OwnedConnection>; }
pub struct NoManagedSources;
pub fn snapshot(&dyn ManagedSourceRead, &[PreparePair]) -> IntegrationSnapshot;   // read_sources
pub struct ManagedRefusal { pub reason: &'static str }   // → AdapterError::CapabilityUnavailable
pub const OFFLINE_UNTIL_BEYOND_BOUND: &str; pub const MINIMUM_NOT_MET: &str;
pub fn pair_enrolled / check_enrolled / issuer_ready / check_prepared / check_minimums / binding_endpoint /
       pair_integrations / pair_evidence / outcome(...)
// heimdall_adapters::managed::reissue (pure, ADR-0005 §3.7)
pub enum GrantSource { Store, ProcessFile }
pub struct StoreRead { pub source: GrantSource, pub tombstoned: bool, pub cutoff_at: Option<Timestamp>, pub now: Timestamp }
pub enum ReissueRefusal { NotFromStore, GrantEnded(GrantState), Tombstoned, DeadlinePassed, CutoffPassed,
                          TimeNotAccepted, RevokeOnLock, ScopeChanged, DeadlineChanged, NotThisGrant }
pub fn eligible(&GrantSnapshot, &GrantOrigin, &TimeStatus, &Admission, LockBehavior, &StoreRead) -> Result<(), ReissueRefusal>;
pub struct ReissuePlan { pub grant, pub pairs, pub valid_before }
pub fn same_grant(stored: &GrantSnapshot, requested: &GrantSnapshot) -> Result<ReissuePlan, ReissueRefusal>;
// heimdall_adapters::managed::report (beyond step 1)
pub const FIELD_*: &str; pub const DRIFT_PPM: u64 = 100; pub const MANAGED_SELECTION_CLASSIFIED: bool = false;
pub fn claimed / claim; pub fn completion_bound(lvb, &ClockMeasurement, now) -> Option<Timestamp>;
pub fn residual_status(lvb, &DestinationClock, bound_at, safe_now: Option<Timestamp>, unbounded) -> (ResidualStatus, Option<Timestamp>);
pub fn latest_possible_credential_expiry(&[IssuanceEntry]) -> Option<Timestamp>;
pub fn remote_effects(&[IssuanceEntry], &[PairClock], bound_at, safe_now, unbounded) -> Vec<RemoteEffectReport>;
pub fn grants_under_ca(&CaFingerprint, &[IssuanceEntry]) -> BTreeSet<GrantId>;          // Q20 / R7 degrade + preview set
pub fn preference_after_removal(&BTreeSet<CaFingerprint>) -> PreferredMechanism;
pub enum SelectionClass { Exclusive, NotExclusive, Undetermined }
pub struct ReportContext { platform, lock_behavior, policy, issuer_ready, reissue_pending, now, selection }
pub struct ManagedReport { usable_until, offline_until, refresh_dependency, refresh_condition, conditions, availability,
                           lock_continuity, lock_claim_verified, enforcement, revocation, evidence, connection_policy }
pub fn connection_wording(ExistingConnectionsMode) -> &'static str;  pub fn weakest_clock(&[Option<ClockMeasurement>]) -> DestinationClock;
pub fn compute(&GrantSnapshot, &ManagedPrepared, &[Claim], &ReportContext, &[PairEvidence]) -> ManagedReport;
// heimdall_adapters::managed::effects
pub trait GrantScopes { fn pairs(&self, &GrantId) -> Option<Vec<AccessPair>> }  pub struct NoGrantScopes;   // U6-Q2
pub trait BindingEndpoints { fn binding_endpoint(&self, &BindingId) -> Option<EndpointRef> }  // impl for EndpointRegistry
pub struct ManagedEffectsImpl;   // impl ManagedEffects; Clone
impl ManagedEffectsImpl {
    pub fn new(SignerTable, Arc<dyn BindingEndpoints>, Arc<dyn GrantScopes>, runtime_dir: PathBuf, SlotRoot) -> Self;
    pub fn with_call_timeout(self, Duration) -> Self; pub fn table(&self) -> &SignerTable; pub fn slot_root(&self) -> &SlotRoot;
    pub fn certificate(&self, &GrantId, &AccessPair) -> Option<String>; pub fn grant_pairs(..); pub fn generated_under(..);
    pub fn materialize_slot(&self, &BindingId, &AccessPair, generation: u64) -> Result<Vec<PathBuf>, AdapterError>;
    pub fn clear_slot(&self, &BindingId, &AccessPair, generation: u64) -> Result<ClearOutcome, AdapterError>; }
pub trait SlotStore { fn slot(&self, &EnvironmentId, &AccessPair) -> Result<SlotState, AdapterError>;
                      fn claim(&self, &EnvironmentId, &AccessPair, &BindingId) -> Result<Result<SlotState, SlotRefusal>, AdapterError>; }
pub struct NoSlotStore;  pub const SLOT_STORE_UNAVAILABLE: &str = "driver_unavailable";
pub enum SlotClaimError { Refused(SlotRefusal), Failed(AdapterError) }
pub struct ManagedSlotTable<S: SlotStore>;  // new(store, effects); state(&AccessPair); claim(&BindingId, &AccessPair)
                                             // = what run_cmd::ManagedSlots needs (U10 wires the request)
```

## U7 (connection control): owner paths

Owner paths: `crates/runtime/src/connections.rs`; `JobObject::spawn_suspended`/`SuspendedChild` (and
the process pin/verify/signal primitives of R8) in `crates/localenv/src/sys/mod.rs` with its
invariant table + `docs/architecture/overview.md` §9 (authorized); the Windows managed-launch path in
`crates/launch/src/windows.rs` behind `launch_uses_kill_on_close_job`; the R9 edit in
`crates/heimdall/src/run_cmd.rs`; `tests/integration/connections.rs`, `tests/e2e/deadline_m03.rs`.

U7 landed interfaces:
**Landed 2026-11-11** (compiles once U7-Q1's one line is applied; until then only with the sshconf call stubbed).
```rust
// heimdall_localenv::sys (the R8 primitives; the only new FFI)
pub struct ProcessPin;                         // Linux pidfd | macOS PID | Windows handle(TERMINATE|QUERY_LIMITED)
impl ProcessPin {
    pub fn open(pid: u32) -> Result<Option<ProcessPin>, SysError>;   // None: no such process; refuses 0, 1, self
    pub fn pid(&self) -> u32;
    pub fn image(&self) -> Option<PathBuf>;                          // /proc/<pid>/exe | proc_pidpath | QueryFullProcessImageNameW
    #[cfg(windows)] pub fn created_at(&self) -> Option<Timestamp>;   // GetProcessTimes on the handle; None once exited
    pub fn verify(self, start_token_matches: bool, expected_image: &Path) -> Option<VerifiedProcess>;
}
pub struct VerifiedProcess;                    // the only signallable value
impl VerifiedProcess { pub fn pid(&self) -> u32; pub fn signal(&self, ProcessSignal) -> Result<(), SysError>;
                       #[cfg(windows)] pub fn exited(&self) -> bool; }
pub enum ProcessSignal { Terminate, Kill }     // SIGTERM/SIGKILL | TerminateProcess
#[cfg(windows)] impl JobObject {
    pub fn spawn_suspended(command: std::process::Command) -> Result<SuspendedChild, SysError>;
    pub fn contains_pid(&self, pid: u32) -> Result<bool, SysError>;  // IsProcessInJob
}
#[cfg(windows)] pub struct SuspendedChild { pub pid: u32, pub created_at: Timestamp, pub job: JobObject, /* child */ }
#[cfg(windows)] impl SuspendedChild { pub fn resume(self) -> Result<ContainedChild, SysError>; pub fn close(self); }
#[cfg(windows)] pub struct ContainedChild { pub job: JobObject, pub child: std::process::Child }

// heimdall_launch::windows
pub fn launch_uses_kill_on_close_job(managed_binding: bool, program_is_verified_ssh: bool) -> bool; // Q18
pub enum Registration { Registered, Refused, Failed }
pub enum ContainedFailure { Launch(LaunchFailure), Registration { refused: bool, meta: Option<SideChannel> } }
impl ContainedFailure { pub fn reason(&self) -> Option<&'static str>; } // connection_registration_{refused,failed}
pub fn spawn_contained_and_wait(program, args, delta, meta,
    register: &mut dyn FnMut(u32, Timestamp, &Path) -> Registration) -> Result<u32, ContainedFailure>;

// heimdall_runtime::connections
pub trait BindingEndpoints: Send + Sync { fn endpoint(&self, binding: &BindingId) -> Option<EndpointRef>; }
pub struct ConnectionConfig { pub runtime_dir, pub verified_ssh, pub platform, pub endpoints, pub jitter,
    pub start_backoff, pub close_grace, pub ready_wait, pub client_args, pub client_env }  // ::new(runtime_dir, ssh, endpoints, jitter)
pub struct ConnectionSupervisor;               // impl ConnectionControl (start_master, close, register)
impl ConnectionSupervisor {
    pub fn new(store: Arc<Store>, ops: Option<Operations>, config: ConnectionConfig) -> Self; // ops: register only
    pub async fn effective_policy(&self, grant: &GrantId) -> ConnectionPolicy;       // D8 item 1, FAIL_CLOSED_POLICY
    pub async fn connection_deadline_pass(&self, ended: &[GrantId]) -> PassReport;   // deadline/cutoff
    pub async fn revocation_close(&self, cascade: &[GrantId]) -> PassReport;         // D7 item 2 step 4, after gates
    pub async fn release_close(&self, grants: &[GrantId]) -> PassReport;
    pub async fn time_uncertain_close(&self) -> PassReport;
    pub async fn connection_restart_pass(&self) -> PassReport;                       // first at start
    pub async fn reap_pass(&self) -> PassReport;      // masters that exited; Windows dedicated rows whose ssh.exe is gone
    pub async fn shutdown(&self) -> PassReport;       // runtime exit: close this process's masters
    pub async fn close_for(&self, grants: &[GrantId], event: ConnectionEnd) -> PassReport;
    pub async fn close_one(&self, c: &OwnedConnection) -> CloseOutcome;  // Closed | Unverified | Pending | Failed
}
pub fn effective_policy_in(tx, grant, request) -> heimdall_store::Result<ConnectionPolicy>;
pub fn master_argv(control_path, alias, endpoint, key_pub, cert, client_args) -> Result<Vec<OsString>, ConnError>;
pub fn exit_argv(control_path, alias, client_args) -> Result<Vec<OsString>, ConnError>;
pub struct PassReport { pub closed, pub unverified, pub pending, pub kept, pub failed }
pub struct MasterLocator { connection, pid, start_token, control_path, alias, inode }   // resource locator JSON
pub mod refusal { /* fixed words carried by ConnError */ }
```
For U10: build one `ConnectionSupervisor` in `Service::start` (store, `Some(ops)`, `ConnectionConfig::new(paths
runtime dir, the client inventory's verified ssh, a `BindingEndpoints` over the signer's endpoint table,
`RandomJitter`)`); call `connection_restart_pass` before anything else, `connection_deadline_pass` with the grants
each `tick` ended (deadline or cutoff), `revocation_close` with the cascade after the revoke's gates are released
(and `release_close` on release), `time_uncertain_close` when the gate leaves `Safe`, `reap_pass` each supervisor
pass, `shutdown` at exit; route `Connections::{Close, Register}` to `close`/`register`; emit the `Connection` events
(U7-Q3). `start_master` returns `Unavailable` for every refusal (Windows `multiplexing_unsupported`,
`owned_masters_disabled`, `mux_path_too_long`, `binding_endpoint_unavailable`, `mux_path_occupied`) and
`Failed("master_start_failed")` after the bounded retries: clients connect directly, nothing else to do.

## Requests (unit → unit / integrator)
(Append `- <from> → <to>: <what, exact text/signature>`; the owner answers inline.)
- U7 → integrator (blocking for the master argv, R4): `heimdall-runtime` has no edge to
  `heimdall-sshconf`, so `connections.rs` cannot use `OWNED_LAUNCH_PINS` /
  `managed_identity_options` (R3/R4 forbid retyping them). Please add to
  `crates/runtime/Cargo.toml` `[dependencies]`, after `heimdall-adapters`:
  ```toml
  # M03 wave 3 (U7, reading R4): the owned master's argv uses the command-line half of P's
  # directive set (`heimdall_sshconf::render::{OWNED_LAUNCH_PINS, managed_identity_options}`),
  # never retyped. sshconf is already in runtime's graph through localenv (contract, domain
  # only), so no package enters the lock and no cycle forms.
  heimdall-sshconf = { workspace = true }
  ```
  (`tools/validation/crate_graph.py` allows it; m03-plan §0.6 lists runtime's edges without
  it, so this is a new direct edge to a crate already in its graph; Cargo.lock: only
  heimdall-runtime's dependency array.) Recorded as U7-Q1.
- U6 → integrator (2026-11-11): ~~`ssh-key` in adapters `[dependencies]`~~ **withdrawn, no change needed**:
  `ManagedEffectsImpl::install` gets its `ssh_key::Certificate` by type inference (`line.parse()` into
  `SignerTable::install`'s parameter; `Certificate: FromStr`), with no direct dependency.
- U6 → integrator (2026-11-11): `.m03-wave3-xcheck-windows.sh` at the worktree root does `cd "$(dirname "$0")/../.."`
  (copied from `tools/validation/`), so `bash .m03-wave3-xcheck-windows.sh …` exits 101 ("could not find
  `Cargo.toml` in the worktrees parent directory"). U6 ran it unchanged as
  `bash -c "$(cat .m03-wave3-xcheck-windows.sh)" tools/validation/xcheck-windows-via-u6.sh -p heimdall-adapters --all-targets`
  (`$0` two levels below the root; no file created). Suggested fix: `cd "$(dirname "$0")" || exit 2` in the copy.
