//! M07 U8a and A27: load the shipped integration in a real PowerShell host. The
//! serving cases use the runtime's real control and signing endpoints, with a
//! per-run CA held only in memory. No SSH client, server or account store is used.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ports::{
    AdapterDescriptor, InteractionRequirement, IssuanceRef, IssuerError, IssuerPort,
    IssuerStatusSnapshot, LockContinuity, PrepareOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnrollmentId, IdentityId, OperationId, PolicyId,
    ProfileId, WorkId,
};
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
use heimdall_contract::managed::{
    ConnectionPolicy, IssuerIsolation, LockBehavior, PreferredMechanism,
};
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy, NewAuthenticationExpiry,
    RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload};
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::table::SignerTable;
use heimdall_domain::binding::BindingState;
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource, InteractionProfile,
};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus,
    RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::managed::SlotState;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::SyncStatus;
use heimdall_runtime::config::Config;
use heimdall_runtime::instance::{INSTANCE_FILE, InstanceInfo};
use heimdall_runtime::paths::Paths;
use heimdall_runtime::service::{ManagedOptions, Service, ServiceOptions, SessionLockWiring};
use heimdall_store::{IssuerRecord, Store};
use heimdall_testkit::{
    FakeCredentialAdapter, FakeStep, ScriptedTimeSync, assert_no_canary, home::find_program,
    session_lock::FakeSessionLockSource,
};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;

const PROMPT: &str = " fixture prompt > ";
const LOCATION: &str = if cfg!(windows) {
    "work $([1]) ' [u8a]"
} else {
    "work $([1]) '\" [u8a]"
};
const LOAD: &str = r#"
$ErrorActionPreference = 'Stop'
function global:prompt { ' fixture prompt > ' }
Invoke-Expression ((& heimdall shell init powershell) -join "`n")
if ($LASTEXITCODE -ne 0) { throw 'shell init failed' }
'loaded'
"#;
const RENDER: &str = r#"
Set-Location -LiteralPath $env:FIXTURE_LOCATION
$global:LASTEXITCODE = 42
prompt
if ($LASTEXITCODE -ne 42) { throw 'hook changed the last exit code' }
'rendered'
"#;
const AFTER_ACTIVATION: &str = r#"
if ($global:__heimdall_state -cne 'active' -or [long]$global:__heimdall_due -le 0) {
    throw 'hook did not retain its active state and recheck deadline'
}
[void][Console]::ReadLine()
$global:__heimdall_seq = '1'
$global:__heimdall_due = '1'
prompt
if ($global:__heimdall_state -cne 'paused') { throw 'hook did not recheck when due' }
$global:__heimdall_due = '1'
prompt
'rechecked'
"#;
const PAUSED: &str = "heimdall: access here is paused, stopped or past its cutoff; nothing was activated. To resume: heimdall access resume";
const HOST_TIMEOUT: Duration = Duration::from_secs(30);

fn hosts() -> Vec<PathBuf> {
    let pwsh = find_program("pwsh");
    #[cfg(windows)]
    {
        let system = std::env::var_os("SystemRoot").expect("SystemRoot");
        let legacy = PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        assert!(legacy.is_file(), "Windows PowerShell 5.1 is required");
        let pwsh = pwsh.or_else(|| {
            let path =
                PathBuf::from(std::env::var_os("ProgramFiles")?).join("PowerShell/7/pwsh.exe");
            path.is_file().then_some(path)
        });
        std::iter::once(legacy).chain(pwsh).collect()
    }
    #[cfg(not(windows))]
    {
        if pwsh.is_none() {
            eprintln!("skipped PowerShell hook: pwsh was not found on the test runner's PATH");
        }
        pwsh.into_iter().collect()
    }
}

struct Fixture {
    _scratch: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    paths: Paths,
}

impl Fixture {
    fn new() -> Self {
        // Unix signing sockets need a short absolute path.
        let scratch = if cfg!(unix) {
            tempfile::Builder::new().prefix("hm-ps-").tempdir_in("/tmp")
        } else {
            tempfile::Builder::new().prefix("hm-ps-").tempdir()
        }
        .unwrap();
        let root = scratch.path().to_path_buf();
        let home = root.join("hm");
        for dir in ["account", "ssh/etc-ssh", LOCATION] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        Self {
            _scratch: scratch,
            root,
            paths: Paths::under(&home),
            home,
        }
    }

    fn command(&self, host: &Path, body: &str) -> Command {
        let script = self.root.join("fixture.ps1");
        std::fs::write(&script, format!("{LOAD}{body}")).unwrap();
        // A native run copies the binary elsewhere and names it (`HEIMDALL_E2E_BIN`).
        let bin = std::env::var("HEIMDALL_E2E_BIN")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
        let bin = Path::new(&bin);
        let mut path = vec![bin.parent().unwrap().to_owned()];
        let mut cmd = Command::new(host);
        cmd.env_clear()
            .env("HEIMDALL_HOME", &self.home)
            .env("HOME", self.root.join("account"))
            .env("HEIMDALL_TEST_SSH_HOME", self.root.join("ssh"))
            .env("FIXTURE_LOCATION", self.root.join(LOCATION))
            .env("PSModulePath", host.parent().unwrap().join("Modules"))
            .env("XDG_CACHE_HOME", self.root.join("account"))
            .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(&self.root)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive"])
            .kill_on_drop(true);
        if cfg!(windows) {
            let system = std::env::var_os("SystemRoot").expect("SystemRoot");
            path.push(PathBuf::from(&system).join("System32"));
            cmd.env("SystemRoot", system)
                .args(["-ExecutionPolicy", "Bypass"])
                .env("USERPROFILE", self.root.join("account"))
                .env("APPDATA", self.root.join("account"))
                .env("LOCALAPPDATA", self.root.join("account"))
                .env("TEMP", &self.root)
                .env("TMP", &self.root);
        } else {
            path.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        }
        cmd.env("PATH", std::env::join_paths(path).unwrap())
            .arg("-File")
            .arg(script);
        cmd
    }

    async fn run(&self, host: &Path, body: &str, stdout: &[&str]) {
        let out = timeout(
            HOST_TIMEOUT,
            self.command(host, body).stdin(Stdio::null()).output(),
        )
        .await
        .expect("PowerShell exited")
        .unwrap();
        assert_output(&out, stdout, &[]);
    }
}

fn assert_output(out: &Output, expected_stdout: &[&str], expected_stderr: &[&str]) {
    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let stderr = std::str::from_utf8(&out.stderr).unwrap();
    assert_no_canary(stdout);
    assert_no_canary(stderr);
    assert!(out.status.success(), "PowerShell exit: {}", out.status);
    assert_eq!(stdout.lines().collect::<Vec<_>>(), expected_stdout);
    assert_eq!(stderr.lines().collect::<Vec<_>>(), expected_stderr);
}

#[tokio::test]
async fn powershell_hook_writes_nothing_to_stdout() {
    for host in hosts() {
        let fixture = Fixture::new();
        fixture
            .run(&host, RENDER, &["loaded", PROMPT, "rendered"])
            .await;
        assert!(!fixture.home.exists(), "the hook started no runtime");
    }
}

#[tokio::test]
async fn powershell_hook_startup_with_an_unreachable_runtime() {
    for host in hosts() {
        let fixture = Fixture::new();
        fixture.paths.ensure().unwrap();
        let token = format!("hmtest-{}", heimdall_testkit::agent::random_hex(16));
        let endpoints =
            heimdall_ipc::EndpointPaths::for_runtime(&fixture.paths.runtime_dir, &token);
        let info = InstanceInfo {
            pid: std::process::id(),
            started_at: InstanceInfo::current_started_at().unwrap(),
            version: "0.0.0".into(),
            control_endpoint: endpoints.control.to_str().unwrap().into(),
            signing_endpoint: endpoints.signing.to_str().unwrap().into(),
        };
        let runtime_dir = &fixture.paths.runtime_dir;
        info.write(runtime_dir).unwrap();
        fixture
            .run(&host, RENDER, &["loaded", PROMPT, "rendered"])
            .await;
        assert_eq!(InstanceInfo::read_file(runtime_dir).unwrap(), Some(info));
        assert!(!fixture.paths.state_dir.join("state.db").exists());
    }
}

// Stand in only for the issuer child. Sign the production driver's reservation with
// the ephemeral CA and the registered subject. No CA secret is put on disk.
struct MemoryIssuer {
    ca: SecretCaKey,
    store: Arc<Store>,
    table: SignerTable,
}

#[async_trait::async_trait]
impl IssuerPort for MemoryIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: IssuerState::Ready,
                reason: None,
                cas: Vec::new(),
                orphan_store_items: Vec::new(),
                issuer_isolation: IssuerIsolation::SameUserProcess,
                bundle_stale: false,
            },
        }
    }

    async fn sign(&self, reservation: IssuanceRef, _: &str) -> Result<String, IssuerError> {
        let refused =
            || IssuerError::Protocol("test issuance could not sign the reservation".into());
        let entry = self
            .store
            .transaction(|tx| tx.issuance_entry(&reservation.id))
            .map_err(|_| refused())?
            .ok_or_else(refused)?;
        let key = self
            .table
            .public_key(&entry.grant)
            .ok_or_else(refused)?
            .public_key()
            .map_err(|_| refused())?;
        build_and_sign(
            &CertificateProfile::from_bounds(&entry.bounds),
            &key,
            &self.ca,
        )
        .map_err(|_| refused())?
        .to_openssh()
        .map_err(|_| refused())
    }

    async fn unload(&self, _: &heimdall_contract::ids::CaFingerprint) -> Result<(), IssuerError> {
        Ok(())
    }
}

// Give the context hook an observed destination independent of the managed default.
// Its fixture adapter does not need a projected SSH configuration or a live agent.
fn context_adapter() -> Arc<FakeCredentialAdapter> {
    let enforcement = EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::ClientRouting,
            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
            revocation: RevocationStatus::LocalApplied,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
            ordinary_aliases: None,
            owner_functions: None,
        },
        evidence: Vec::new(),
    };
    let end = Timestamp::now()
        .checked_add(Duration::from_secs(7200))
        .unwrap();
    FakeCredentialAdapter::new(
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "hook-fixture".into(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement.clone(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        },
        vec![FakeStep::Prepare(PrepareOutcome {
            usable_until: end,
            offline_until: end,
            refresh_dependency: RefreshDependency::None,
            enforcement,
            credential_ref: "fixture-context".into(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
            managed: None,
        })],
    )
}

fn seed(service: &Service, ca: &SecretCaKey) -> (AccessPair, PolicyId) {
    let environment = service.environment();
    let pair = AccessPair {
        destination: DestinationId::parse("hook-fixture").unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    };
    let policy = PolicyId::parse("hook-policy").unwrap();
    let profile = ProfileId::parse("hook-profile").unwrap();
    let now = Timestamp::now();
    let scope = Scope {
        pairs: [pair.clone()].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    };
    let identity = IdentityId::from_random_bytes([12; 16]);
    let enrollment = EnrollmentId::from_random_bytes([13; 16]);
    let fingerprint = ca.fingerprint().unwrap();
    let public = ca.public_openssh().unwrap();
    service
        .store()
        .transaction(|tx| {
            tx.upsert_environment(&EnvironmentRecord {
                id: environment.clone(),
                device: DeviceId::from_random_bytes([11; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: fingerprint.clone(),
                public_key: public.clone(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: now,
                restored_without_log: false,
                created_at: now,
                retired_at: None,
            })?;
            tx.upsert_identity(&IdentityRecord {
                id: identity.clone(),
                revision: 1,
                source: IdentitySource::PublicKeyFile {
                    path: "fixture.pub".into(),
                },
                public_key: public.clone(),
                fingerprint: fingerprint.to_string(),
                interaction: InteractionProfile {
                    interaction: heimdall_contract::provider::InteractionKind::Unknown,
                    basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                },
                label: None,
                adopted_at: now,
                updated_at: now,
            })?;
            tx.upsert_destination(&DestinationRecord {
                id: pair.destination.clone(),
                alias: pair.destination.to_string(),
                revision: 1,
                definition: DestinationDefinition::Managed {
                    hostname: "hook-fixture.invalid".into(),
                    port: None,
                    account: pair.account.clone(),
                    identity: identity.clone(),
                    jump: None,
                },
                label: None,
                updated_at: now,
            })?;
            tx.seed_enrollment(&EnrollmentRecord {
                marker: marker_for(&enrollment),
                id: enrollment,
                destination: pair.destination.clone(),
                account: pair.account.clone(),
                ca_fingerprint: fingerprint.clone(),
                form: EnrollmentForm::Account,
                registry: RegistryRef {
                    path_display: "fixture/authorized_keys".into(),
                    resolved_by: RegistryResolvedBy::RemoteHome,
                },
                registry_canonical: RegistryCanonical {
                    path: None,
                    resolved_by: RegistryResolvedBy::RemoteHome,
                },
                line_sha256: "cd".repeat(32),
                target: ApprovedTarget {
                    hostname: "hook-fixture.invalid".into(),
                    port: 22,
                    user: pair.account.clone(),
                    proxy: NoProxy::None,
                    host_key: ApprovedHostKey {
                        algorithm: "ssh-ed25519".into(),
                        key: public.split_whitespace().nth(1).unwrap().into(),
                        fingerprint: fingerprint.to_string(),
                    },
                },
                existing_access: ExistingAccessRecord {
                    identity,
                    endpoint: None,
                    public_key_file: None,
                },
                hold: None,
                removal_origin: None,
                late_write: None,
                state: EnrollmentState::Verified,
                verified_at: Some(now),
                evidence: Some(EnrollmentEvidence {
                    client: "OpenSSH_9.9".into(),
                    server: "OpenSSH_fixture".into(),
                    operation: OperationId::from_random_bytes([14; 16]),
                    verified_at: now,
                    fresh_until: now.checked_add(Duration::from_secs(3600)).unwrap(),
                    clock: None,
                }),
                created_at: now,
                updated_at: now,
            })?;
            tx.set_pair_preference(
                &PairPreference {
                    destination: pair.destination.clone(),
                    account: pair.account.clone(),
                    mechanism: PreferredMechanism::ManagedCertificate,
                    projection: ProjectionStatus::Applied { generation: 1 },
                    issuing_cas: [fingerprint].into_iter().collect(),
                },
                now,
            )?;
            tx.upsert_profile(&ProfileDefinition {
                id: profile.clone(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: policy.clone(),
                    revision: PolicyRevision(1),
                    profile: profile.clone(),
                    workspace: None,
                    scope,
                    environments: [environment.clone()].into_iter().collect(),
                    max_window: Duration::from_secs(3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: true,
                },
                false,
            )?;
            let context_profile = ProfileId::parse("hook-context").unwrap();
            let context = DestinationId::parse("hook-context").unwrap();
            tx.upsert_destination(&DestinationRecord {
                id: context.clone(),
                alias: context.to_string(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: now,
            })?;
            let scope = Scope {
                pairs: [AccessPair {
                    destination: context,
                    account: pair.account.clone(),
                }]
                .into_iter()
                .collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: context_profile.clone(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("hook-context-policy").unwrap(),
                    revision: PolicyRevision(1),
                    profile: context_profile.clone(),
                    workspace: None,
                    scope,
                    environments: [environment.clone()].into_iter().collect(),
                    max_window: Duration::from_secs(3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: false,
                },
                false,
            )?;
            tx.set_default_profile(environment, &context_profile)
        })
        .unwrap();
    (pair, policy)
}

async fn activation_journey(host: &Path, hostile_state: bool) {
    let fixture = Fixture::new();
    let stop = CancellationToken::new();
    let _cancel_on_unwind = stop.clone().drop_guard();
    let mut options = ServiceOptions::with_clock(
        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
        ScriptedTimeSync::new(SyncStatus::Synchronized),
    );
    options.endpoint_prefix = "hmtest-".into();
    options.adapters.push(context_adapter());
    options.managed = Some(ManagedOptions {
        session_lock: SessionLockWiring::Source(Arc::new(FakeSessionLockSource::default())),
        ..ManagedOptions::default()
    });
    let service = Service::start_with(
        fixture.paths.clone(),
        Config::default(),
        options,
        stop.clone(),
    )
    .await
    .expect("start fixture runtime");
    let ca = SecretCaKey::generate().unwrap();
    let (pair, policy) = seed(&service, &ca);
    let store = service.store().clone();
    let environment = service.environment().clone();
    let table = service.endpoint_registry().unwrap().table().clone();
    let mut wiring = service
        .operations()
        .managed_wiring()
        .unwrap()
        .as_ref()
        .clone();
    wiring.issuer = Some(Arc::new(MemoryIssuer {
        ca,
        store: store.clone(),
        table,
    }));
    wiring.issuer_lifecycle = None;
    service.operations().set_managed_wiring(wiring);
    let server = tokio::spawn(service.run());
    let stats = || store.transaction(|tx| tx.table_counts()).unwrap();

    fixture
        .run(host, "'no prompt'\n", &["loaded", "no prompt"])
        .await;
    assert_eq!(stats().grants, 0, "loading the profile does not activate");
    assert_eq!(
        stats().decisions,
        0,
        "non-interactive startup makes no decision"
    );

    let junk = if hostile_state {
        r#"
$global:__heimdall_seq = '1; throw "junk"'
$global:__heimdall_state = @('active', 'not a state')
$global:__heimdall_due = '9999999999999999999999999'
$global:__heimdall_pwd = $env:FIXTURE_LOCATION
"#
    } else {
        ""
    };
    let body = format!("{junk}{RENDER}{AFTER_ACTIVATION}");
    let mut shell = fixture
        .command(host, &body)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = shell.id().unwrap();
    let start = heimdall_runtime::platform::process_start_time(pid).unwrap();
    let work = WorkId::parse(&format!("shell:{pid}.{start}.0")).unwrap();
    let mut stdout = BufReader::new(shell.stdout.take().unwrap());
    let mut observed = String::new();
    for _ in 0..3 {
        assert_ne!(
            timeout(HOST_TIMEOUT, stdout.read_line(&mut observed))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    assert_no_canary(&observed);
    assert_eq!(
        observed.lines().collect::<Vec<_>>(),
        ["loaded", PROMPT, "rendered"]
    );

    // The shell is still alive. Its binding and the default's slot reference are
    // separate. The warm-up can finish in the runtime after the hook returns.
    let env_default = heimdall_app::operations::default_work_id(&environment, 1).unwrap();
    let filter = EventFilter {
        operation_id: None,
        types: vec![EventType::Activation],
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (holders, defaults, events, slot) = store
            .transaction(|tx| {
                let holders = tx
                    .bindings_for_work(&environment, &work)?
                    .into_iter()
                    .filter(|b| b.state == BindingState::Active)
                    .map(|b| tx.binding_holder(&b.id))
                    .collect::<heimdall_store::Result<Vec<_>>>()?;
                Ok((
                    holders,
                    tx.bindings_for_work(&environment, &env_default)?,
                    tx.events_after(&environment, 0, &filter, 20)?.events,
                    tx.slot(&environment, &pair)?,
                ))
            })
            .unwrap();
        if let ([Some(holder)], [default], [event], SlotState::Held { .. }) = (
            holders.as_slice(),
            defaults.as_slice(),
            events.as_slice(),
            slot,
        ) {
            assert_eq!(holder.pid, pid);
            assert_eq!(holder.started_at, start);
            assert_eq!(default.state, BindingState::Active);
            let payload: ActivationEventPayload =
                serde_json::from_value(event.payload.clone()).unwrap();
            assert_eq!(payload.kind, ActivationEventKind::Activated);
            assert_eq!(payload.policy_id.as_ref(), Some(&policy));
            assert_eq!(payload.workspace_id, None);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "expected shell holder, warmed slot and activation event (holders {}, default bindings {}, activation outcomes {:?})",
            holders.len(),
            defaults.len(),
            events
                .iter()
                .map(|e| (&e.payload["kind"], &e.payload["reason"]))
                .collect::<Vec<_>>()
        );
        sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(stats().decisions, 0);

    store
        .transaction(|tx| {
            let id = PolicyId::parse("hook-context-policy").unwrap();
            let mut context = tx.policy(&id)?.unwrap();
            context.revision = PolicyRevision(context.revision.0 + 1);
            context.pause = PauseState::Paused {
                since: Timestamp::now(),
            };
            tx.upsert_policy(&context, false).map(drop)
        })
        .unwrap();
    drop(shell.stdin.take());
    shell.stdout = Some(stdout.into_inner());
    let out = timeout(HOST_TIMEOUT, shell.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_output(&out, &[PROMPT, PROMPT, "rechecked"], &[PAUSED]);
    assert_eq!(stats().decisions, 0);
    stop.cancel();
    timeout(HOST_TIMEOUT, server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!fixture.paths.runtime_dir.join(INSTANCE_FILE).exists());
}

#[tokio::test]
async fn powershell_hook_activates_and_warms_the_default() {
    for host in hosts() {
        activation_journey(&host, false).await;
    }
}

#[tokio::test]
async fn powershell_hook_recovers_from_hostile_state() {
    for host in hosts() {
        activation_journey(&host, true).await;
    }
}
