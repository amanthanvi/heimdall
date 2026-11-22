//! ⟨M05⟩ U6, live: shared ordinary-alias slots (ADR-0011 §5.2 as ruled in §10 item 6) and
//! the default-profile preference (ADR-0011 §5.1), through the real `Operations`, managed
//! adapter, [`StoreCleanup`] (with the handover, `crate::slot_handover`),
//! `ManagedEffectsImpl`, signer table, vault and `EndpointRegistry` of [`super::Live`],
//! the supervisor's ended-slot pass, and **real `ssh`** (the system client) through the
//! environment endpoint and the slot's files against a disposable [`LoopbackSshd`]
//! trusting this run's fixture CA.
//!
//! * [`two_jobs_share_a_pair_and_hand_over`]: the join, the handover to the
//!   later-deadline job under a new generation, the old generation's cleanup fenced, and
//!   the slot ending with its last referencer.
//! * [`a16_concurrent_environments_defaults_and_cleanup`]: A16 in its **two
//!   environments, one OS user** realization (the native session and a second managed
//!   environment through the joint wave-0 seam; the WSL and container rows are M04's).
//! * [`a04_default_and_profile_change_never_redirects_bindings`]: A04's default and
//!   profile-definition change while two bindings run.
//!
//! Every key and the CA are generated per run in scratch directories; the client runs with
//! the scratch home's isolation (its own configuration, known hosts, `HOME`, a decoy
//! agent); nothing of the owner's is read, contacted or changed.

use super::*;
use crate::supervisor::{FixedJitter, ManagedConnections, Supervisor, SupervisorConfig};
use heimdall_adapters::managed::files::ClearOutcome;
use heimdall_app::error::Completed;
use heimdall_app::ports::SignerEndpoint;
use heimdall_contract::catalog::{CatalogRequest, ProfileSpec};
use heimdall_contract::envelope::m05_warning::SLOT_SHARED;
use heimdall_contract::request::{
    BindForm, BindRequest, DeadlineIntent, LaunchBinding, ReleaseRequest,
};
use heimdall_contract::trust::OrdinaryAliases;
use heimdall_domain::binding::BindingRecord;
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use std::path::Path;

/// The current account as a pair of destination `dest` (a non-root fixture sshd
/// authenticates only its own account).
fn own_pair(dest: &str) -> AccessPair {
    pair(dest, &current_account().expect("the current account"))
}

/// A managed `ensure` of profile `dev` over `scope`, in `environment` (the runtime's own
/// when `None`), ending `until` from now: one job.
async fn job(
    ops: &Operations,
    tag: &str,
    scope: &[AccessPair],
    environment: Option<&EnvironmentId>,
    until: &str,
) -> EnsureData {
    try_job(ops, tag, scope, environment, until)
        .await
        .unwrap_or_else(|e| panic!("ensure {tag}: {} {}", e.code, e.message))
}

/// [`job`], with its refusal.
async fn try_job(
    ops: &Operations,
    tag: &str,
    scope: &[AccessPair],
    environment: Option<&EnvironmentId>,
    until: &str,
) -> Result<EnsureData, heimdall_app::OpError> {
    ops.ensure(
        &caller(),
        EnsureRequest {
            profile: Some(ProfileId::parse("dev").unwrap()),
            profile_revision: None,
            scope: scope.iter().cloned().collect(),
            environment: environment.cloned(),
            work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
            until: Some(DeadlineIntent::Duration(until.to_owned())),
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
            interaction: InteractionMode::Interactive,
            wait: WaitMode::Sync { timeout_ms: 30_000 },
            connection: None,
            context: None,
            covered_only: false,
            pair_issuers: Vec::new(),
        },
    )
    .await
    .map(|c| c.data)
}

/// The launch bind of `binding` (`run`'s), with its warnings.
async fn launch(p: &Process, binding: &BindingId, tag: &str) -> Completed<EnsureData> {
    p.ops
        .bind(
            &caller(),
            BindRequest {
                binding_id: binding.clone(),
                form: BindForm::Launch(LaunchBinding {
                    executable: "/usr/bin/true".into(),
                    holder: None,
                }),
                request_id: RequestId::parse(&format!("bind-{tag}")).unwrap(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("bind {tag}: {} {}", e.code, e.message))
}

/// Whether `bound` is labelled as joining a shared slot (ADR-0011 §5.2).
fn shared(bound: &Completed<EnsureData>) -> bool {
    let labelled =
        bound.data.enforcement.ordinary_aliases == Some(OrdinaryAliases::SharedEnvironmentDefault);
    let warned = bound.warnings.iter().any(|w| w.code == SLOT_SHARED);
    assert_eq!(labelled, warned, "the label and the warning go together");
    labelled
}

async fn release(p: &Process, binding: &BindingId) {
    p.ops
        .release(
            &caller(),
            ReleaseRequest {
                binding_id: binding.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("release: {} {}", e.code, e.message));
}

/// The supervisor of process `p` with the M03 passes and the production end cleanup
/// ([`StoreCleanup`] over `p`'s effects, which hands slots over), as the cleanup live
/// tests build it.
fn supervisor(w: &Live, p: &Process) -> Supervisor {
    struct NoEndpoints;
    impl crate::connections::BindingEndpoints for NoEndpoints {
        fn endpoint(&self, _: &BindingId) -> Option<EndpointRef> {
            None
        }
    }
    let config = crate::connections::ConnectionConfig::new(
        w.run_dir(),
        std::path::PathBuf::from("/nonexistent/fixture-ssh"),
        Arc::new(NoEndpoints),
        Arc::new(FixedJitter(1.0)),
    );
    let connections = Arc::new(crate::connections::ConnectionSupervisor::new(
        w.store.clone(),
        Some(p.ops.clone()),
        config,
    ));
    let clock: Arc<dyn heimdall_domain::time::Clock> = w.clock.clone();
    Supervisor::new(p.ops.clone(), SupervisorConfig::default())
        .with_state(w.store.clone(), clock)
        .with_connections(Arc::new(ManagedConnections::new(
            connections,
            w.store.clone(),
            p.ops.clone(),
        )))
        .with_end_cleanup(Arc::new(StoreCleanup::new(
            StoreSources::new(w.store.clone(), env()),
            p.effects.clone(),
            None,
        )))
}

fn slot_in(w: &Live, environment: &EnvironmentId, pr: &AccessPair) -> SlotState {
    w.store.transaction(|tx| tx.slot(environment, pr)).unwrap()
}

/// The bindings referencing `pr`'s slot in `environment`, by ID.
fn references(w: &Live, environment: &EnvironmentId, pr: &AccessPair) -> Vec<BindingId> {
    w.store
        .transaction(|tx| tx.slot_references(environment, &pr.destination, &pr.account))
        .unwrap()
        .into_iter()
        .map(|r| r.binding)
        .collect()
}

fn sorted(mut ids: Vec<BindingId>) -> Vec<BindingId> {
    ids.sort();
    ids
}

/// What a binding pins (ADR-0011 §5.1): its stored row (environment, profile and
/// revision, scope, mechanism, grant) and its context.
fn pins(
    w: &Live,
    binding: &BindingId,
) -> (
    BindingRecord,
    Option<heimdall_domain::workspace::BindingContext>,
) {
    w.store
        .transaction(|tx| Ok((tx.binding(binding)?.unwrap(), tx.binding_context(binding)?)))
        .unwrap()
}

/// The pins compared: every field but the state (a release changes only that).
fn same_pins(
    before: &(
        BindingRecord,
        Option<heimdall_domain::workspace::BindingContext>,
    ),
    after: &(
        BindingRecord,
        Option<heimdall_domain::workspace::BindingContext>,
    ),
) -> bool {
    let (b, c) = before;
    let (a, d) = after;
    b.environment == a.environment
        && b.grant == a.grant
        && b.profile == a.profile
        && b.profile_revision == a.profile_revision
        && b.scope == a.scope
        && b.mechanism == a.mechanism
        && b.work_id == a.work_id
        && c == d
}

fn key_of(p: &Process, grant: &GrantId) -> String {
    p.table
        .public_key(grant)
        .expect("the grant's key")
        .fingerprint
}

/// A disposable sshd trusting this world's CA for `pr`'s principal, and a scratch client
/// home whose configuration names an alias → that server as the current account.
struct Ssh {
    home: ScratchHome,
    sshd: LoopbackSshd,
    alias: String,
}

fn ssh_world(w: &Live, pr: &AccessPair) -> Ssh {
    let home = ScratchHome::new();
    let account = pr.account.as_str().to_owned();
    let sshd = LoopbackSshd::start(
        home.scratch(),
        SshdConfig {
            trusted_user_ca_keys: Some(home.root.join("trusted_ca.pub")),
            authorized_principals: Some(
                [(
                    account.clone(),
                    vec![heimdall_domain::issuance::principal_for(pr)],
                )]
                .into(),
            ),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("a local fixture sshd is needed: {e}"));
    sshd.trust_user_ca(&w.ca.public_openssh().unwrap()).unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();
    let alias = "hm-u6-fixture".to_owned();
    home.write_user_config(&format!(
        "Host {alias}\n  HostName 127.0.0.1\n  Port {}\n  User {account}\n",
        sshd.port
    ))
    .unwrap();
    Ssh { home, sshd, alias }
}

impl Ssh {
    /// The system `ssh` to the fixture alias with the managed identity options the
    /// projection renders for an ordinary alias (`IdentityAgent=<environment endpoint>`,
    /// `IdentitiesOnly=yes`, the slot's certificate as the identity file), running
    /// `echo <marker>`. Returns whether it succeeded and the fingerprint of the
    /// certified key the server accepted (if any).
    async fn run(
        &self,
        endpoint: &str,
        key_pub: &Path,
        cert: &Path,
        marker: &str,
    ) -> (bool, Option<String>) {
        use heimdall_sshconf::render::{
            ManagedIdentityForm, PathStyle, RenderPath, managed_identity_options,
        };
        let before = self.sshd.accepted_certificates().len();
        let options = managed_identity_options(
            &RenderPath::unix(Path::new(endpoint)).unwrap(),
            &RenderPath::unix(key_pub).unwrap(),
            &RenderPath::unix(cert).unwrap(),
            PathStyle::Unix,
            ManagedIdentityForm::select(None),
        )
        .unwrap();
        let mut cmd = std::process::Command::new(find_program("ssh").expect("ssh"));
        cmd.args(self.home.isolation_args())
            .args(&options)
            .args(["-o", "PreferredAuthentications=publickey"])
            .arg(&self.alias)
            .arg(format!("echo {marker}"))
            .env(
                "SSH_AUTH_SOCK",
                self.home.decoy_agent().endpoint().locator(),
            )
            .env("HOME", &self.home.git_home)
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("SSH_AGENT_PID")
            .env_remove("DISPLAY")
            .stdin(std::process::Stdio::null());
        let out = tokio::task::spawn_blocking(move || cmd.output())
            .await
            .unwrap()
            .unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        let ok = out.status.success() && String::from_utf8_lossy(&out.stdout).contains(marker);
        let accepted = self.sshd.accepted_certificates();
        let fingerprint = (accepted.len() > before)
            .then(|| accepted.last().map(|a| a.fingerprint.clone()))
            .flatten();
        (ok, fingerprint)
    }

    /// `ssh` through `pr`'s ordinary-alias slot in `p`'s native environment.
    async fn through_slot(
        &self,
        p: &Process,
        pr: &AccessPair,
        marker: &str,
    ) -> (bool, Option<String>) {
        let slot = files::slot_paths(&p.effects.slot_root().data_dir, pr).unwrap();
        self.run(
            &p.registry.environment().locator,
            &slot.key_pub,
            &slot.cert_pub,
            marker,
        )
        .await
    }
}

/// The slot's certificate file, trimmed.
fn slot_certificate(root: &SlotRoot, pr: &AccessPair) -> Option<String> {
    let paths = files::slot_paths(&root.data_dir, pr).unwrap();
    std::fs::read_to_string(paths.cert_pub)
        .ok()
        .map(|c| c.trim().to_owned())
}

/// The certificate `grant` installed for `pr` (its principals and `valid_before` are that
/// grant's: the issuer bounds them by its deadline).
fn certificate_of(p: &Process, grant: &GrantId, pr: &AccessPair) -> String {
    p.effects
        .certificate(grant, pr)
        .expect("the grant's installed certificate")
        .trim()
        .to_owned()
}

/// ADR-0011 §5.2 (ruling D06), live: job A binds pair P (it materializes the slot); job B,
/// with a later deadline, binds P too and **joins** (`slot_shared`,
/// `shared_environment_default`): one slot, A's grant's certificate, A's generation, and
/// `ssh` through the ordinary alias signs with A's key. A is released: the cleanup pass
/// removes A's generation and hands the slot to B under a **new generation**, re-
/// materialized from **B's own grant** (B's certificate, B's key; `ssh` still works). A's
/// old generation's slot cleanup, replayed after the handover (what a stale pass's
/// `begin_slot` does), removes nothing of B's: its files and listing stay and `ssh` still
/// works. B, the last referencer, ends: the slot clears, no reference stays, and the alias
/// fails closed. No pin of either binding changes.
#[tokio::test]
async fn two_jobs_share_a_pair_and_hand_over() {
    let pr = own_pair("u6-share");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let ssh = ssh_world(&w, &pr);
    let p = w.process(Arc::new(NoStageHook)).await;
    p.registry.start_environment().unwrap();
    let root = p.effects.slot_root().clone();
    let a = job(&p.ops, "a", std::slice::from_ref(&pr), None, "1h").await;
    let b = job(&p.ops, "b", std::slice::from_ref(&pr), None, "2h").await;
    assert_ne!(a.grant_id, b.grant_id, "two jobs, two grants");
    assert!(b.expires_at > a.expires_at, "B's deadline is the later one");
    let pins_before = [pins(&w, &a.binding_id), pins(&w, &b.binding_id)];

    // A materializes; B joins.
    assert!(
        !shared(&launch(&p, &a.binding_id, "a").await),
        "A materializes"
    );
    assert!(shared(&launch(&p, &b.binding_id, "b").await), "B joins");
    let held_a = SlotState::Held {
        binding: a.binding_id.clone(),
        generation: 1,
    };
    assert_eq!(slot_in(&w, &env(), &pr), held_a, "the join moves nothing");
    assert_eq!(
        references(&w, &env(), &pr),
        sorted(vec![a.binding_id.clone(), b.binding_id.clone()])
    );
    assert_eq!(p.table.materialized_generation(&a.binding_id, &pr), Some(1));
    assert_eq!(p.table.materialized_generation(&b.binding_id, &pr), None);
    assert_eq!(
        slot_certificate(&root, &pr),
        Some(certificate_of(&p, &a.grant_id, &pr)),
        "the slot carries A's grant's certificate only"
    );
    let (ok, fp) = ssh.through_slot(&p, &pr, "shared-a").await;
    assert!(ok, "ssh through the shared alias");
    assert_eq!(fp, Some(key_of(&p, &a.grant_id)), "with A's key");
    let key_b = key_of(&p, &b.grant_id);

    // A ends: the slot passes to B under a new generation, from B's own grant. A's was
    // its grant's last reference, so the release's own end cleanup (the adapter's
    // `StoreCleanup`) may already have handed it over; the supervisor's pass otherwise.
    release(&p, &a.binding_id).await;
    assert!(matches!(
        slot_in(&w, &env(), &pr),
        SlotState::Clearing { generation: 1 } | SlotState::Held { generation: 2, .. }
    ));
    supervisor(&w, &p).ended_slot_pass().await.unwrap();
    assert_eq!(
        slot_in(&w, &env(), &pr),
        SlotState::Held {
            binding: b.binding_id.clone(),
            generation: 2
        },
        "handed over to B at a new generation"
    );
    assert_eq!(references(&w, &env(), &pr), vec![b.binding_id.clone()]);
    assert_eq!(files::slot_generation(&root, &pr).unwrap(), Some(2));
    assert_eq!(p.table.materialized_generation(&b.binding_id, &pr), Some(2));
    assert_eq!(p.table.materialized_generation(&a.binding_id, &pr), None);
    assert_eq!(
        slot_certificate(&root, &pr),
        Some(certificate_of(&p, &b.grant_id, &pr)),
        "re-materialized from B's own grant"
    );
    let (ok, fp) = ssh.through_slot(&p, &pr, "handed-over").await;
    assert!(ok, "ssh still works after the handover");
    assert_eq!(fp.as_deref(), Some(key_b.as_str()), "with B's key");

    // A's old generation's cleanup, replayed: fenced by its generation.
    let replay = p.effects.clear_slot(&a.binding_id, &env(), &pr, 1).unwrap();
    let (ok, fp) = ssh.through_slot(&p, &pr, "after-stale-cleanup").await;
    assert!(
        ok,
        "generation 1's cleanup never removed generation 2's files"
    );
    assert_eq!(fp.as_deref(), Some(key_b.as_str()));
    assert_eq!(files::slot_generation(&root, &pr).unwrap(), Some(2));
    assert_eq!(p.table.materialized_generation(&b.binding_id, &pr), Some(2));
    assert_eq!(replay, ClearOutcome::OtherGeneration(2));
    for (before, binding) in pins_before.iter().zip([&a.binding_id, &b.binding_id]) {
        assert!(same_pins(before, &pins(&w, binding)), "no pin changed");
    }

    // B, the last referencer, ends: the slot clears and the alias fails closed.
    release(&p, &b.binding_id).await;
    supervisor(&w, &p).ended_slot_pass().await.unwrap();
    assert_eq!(slot_in(&w, &env(), &pr), SlotState::Free { generation: 2 });
    assert!(references(&w, &env(), &pr).is_empty(), "no reference stays");
    assert_eq!(
        slot_certificate(&root, &pr),
        None,
        "the slot's files are gone"
    );
    assert!(p.table.list(&SignerEndpoint::Environment).is_empty());
    let (ok, _) = ssh.through_slot(&p, &pr, "after-last").await;
    assert!(!ok, "the alias fails closed with no referencer");
    p.shutdown.cancel();
}

/// A second environment `e2` in the managed set of `w`'s runtime (the joint wave-0
/// seam, as the pipeline's two-environment test adds it): its environment record, its
/// `managed_environments` row (controller: the runtime's own environment), and the
/// standing policy extended to it. Its slots live under `<dir>/state-e2`.
fn add_managed_environment(w: &Live, e2: &EnvironmentId) -> SlotRoot {
    use heimdall_domain::environment::{EnvironmentRealization, ManagedEnvironment, ManagedState};
    let data_dir = w.dir.path().join("state-e2");
    owner_only(&data_dir);
    w.store
        .transaction(|tx| {
            tx.upsert_environment(&EnvironmentRecord {
                id: e2.clone(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::Container,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.insert_managed_environment(&ManagedEnvironment {
                environment: e2.clone(),
                controller: env(),
                realization: EnvironmentRealization::Container {
                    label: "u6".to_owned(),
                    dir_tag: "00000000000000e2".to_owned(),
                },
                state: ManagedState::Active,
                created_at: t0(),
                updated_at: t0(),
            })?;
            let mut p = tx.policy(&PolicyId::parse("pol").unwrap())?.unwrap();
            p.environments.insert(e2.clone());
            p.revision = PolicyRevision(p.revision.0 + 1);
            tx.upsert_policy(&p, false)
        })
        .unwrap();
    SlotRoot {
        data_dir,
        environment: e2.clone(),
    }
}

fn set_mode(dir: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// An owner catalog upsert of profile `id` over `pairs`.
async fn upsert_profile(p: &Process, id: &str, pairs: &[AccessPair], tag: &str) {
    p.ops
        .catalog(
            &caller(),
            CatalogRequest::UpsertProfile {
                profile: ProfileSpec {
                    id: ProfileId::parse(id).unwrap(),
                    pairs: pairs.iter().cloned().collect(),
                    label: None,
                },
                request_id: RequestId::parse(&format!("cat-{tag}")).unwrap(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("upsert {id}: {} {}", e.code, e.message));
}

async fn set_default(p: &Process, environment: Option<&EnvironmentId>, profile: &str) {
    p.ops
        .set_default_profile(
            &caller(),
            environment,
            Some(ProfileId::parse(profile).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("default {profile}: {} {}", e.code, e.message));
}

async fn default_of(p: &Process, environment: Option<&EnvironmentId>) -> Option<String> {
    p.ops
        .default_profile(environment)
        .await
        .unwrap()
        .map(|id| id.as_str().to_owned())
}

/// A16 (R-AU-03), **two environments, one OS user** (the native session and a second
/// managed environment `e2` through the joint wave-0 managed-environment seam; the WSL
/// and container realizations are M04's rows): jobs prepare and bind **concurrently** in
/// both environments on the same pair, with a slot and its references per environment,
/// none crossing. Natively two jobs share the slot (one materializes, one joins).
/// ⟨M04 MC5 merge⟩ `e2` is a container environment, which serves **one** binding
/// (ADR-0010 §4 item 3, M04's container row): its second job is refused
/// `environment_busy`, so `e2` holds one job. The global default changes mid-run (the
/// native default moves `dev` → `ops`; `e2`'s stays `dev`): no binding pin changes. Then
/// each environment's cleanup runs during the other's jobs, through the supervisor's pass
/// over the managed set: `e2`'s job ends (its release's own cleanup fails, so the pass
/// completes it) and its slot clears in `e2` only, while the native slot, listing, files,
/// bindings and `ssh` are untouched; the native materializer ends and its slot is handed
/// over while `e2`'s stays as it was. Finally every job ends and both slots clear, each
/// in its own namespace.
#[tokio::test]
async fn a16_concurrent_environments_defaults_and_cleanup() {
    let pr = own_pair("u6-a16");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let e2 = EnvironmentId::from_random_bytes([0xe2; 16]);
    let root2 = add_managed_environment(&w, &e2);
    let ssh = ssh_world(&w, &pr);
    let p = w
        .process_opts(
            Arc::new(NoStageHook),
            Opts {
                slot_roots: vec![root2.clone()],
                ..Opts::default()
            },
        )
        .await;
    p.registry.start_environment().unwrap();
    let root1 = p.effects.slot_root().clone();
    let scope = std::slice::from_ref(&pr);
    upsert_profile(&p, "ops", scope, "ops").await;
    set_default(&p, None, "dev").await;
    set_default(&p, Some(&e2), "dev").await;

    // Concurrent jobs in both environments.
    let (a, c) = tokio::join!(
        job(&p.ops, "a16-a", scope, None, "1h"),
        job(&p.ops, "a16-c", scope, Some(&e2), "1h"),
    );
    let (b, d) = tokio::join!(
        job(&p.ops, "a16-b", scope, None, "2h"),
        try_job(&p.ops, "a16-d", scope, Some(&e2), "2h"),
    );
    let busy = d.expect_err("a container environment serves one binding");
    assert_eq!(
        (busy.code, busy.reason.as_deref()),
        (Code::ConfigConflict, Some("environment_busy")),
        "{}",
        busy.message
    );
    assert_eq!(
        (a.environment_id.clone(), c.environment_id.clone()),
        (env(), e2.clone())
    );
    let (ba, bc) = tokio::join!(
        launch(&p, &a.binding_id, "a16-a"),
        launch(&p, &c.binding_id, "a16-c")
    );
    let bb = launch(&p, &b.binding_id, "a16-b").await;
    assert!(
        !shared(&ba) && !shared(&bc),
        "one materializer per environment"
    );
    assert!(shared(&bb), "the native joiner");
    let all = [&a, &b, &c];
    let pins_before: Vec<_> = all.iter().map(|j| pins(&w, &j.binding_id)).collect();
    assert_eq!(
        slot_in(&w, &env(), &pr),
        SlotState::Held {
            binding: a.binding_id.clone(),
            generation: 1
        }
    );
    assert_eq!(
        slot_in(&w, &e2, &pr),
        SlotState::Held {
            binding: c.binding_id.clone(),
            generation: 1
        }
    );
    assert_eq!(
        references(&w, &env(), &pr),
        sorted(vec![a.binding_id.clone(), b.binding_id.clone()])
    );
    assert_eq!(
        references(&w, &e2, &pr),
        vec![c.binding_id.clone()],
        "environments never share a slot or a reference"
    );
    assert_ne!(
        files::slot_paths(&root1.data_dir, &pr).unwrap().dir,
        files::slot_paths(&root2.data_dir, &pr).unwrap().dir,
        "separate slot namespaces"
    );
    let e2_listing = SignerEndpoint::ManagedEnvironment(e2.clone());
    assert_eq!(p.table.list(&SignerEndpoint::Environment).len(), 1);
    assert_eq!(p.table.list(&e2_listing).len(), 1);
    let (ok, fp) = ssh.through_slot(&p, &pr, "a16-native").await;
    assert!(ok);
    assert_eq!(fp, Some(key_of(&p, &a.grant_id)));

    // The global default changes mid-run: per environment, and no pin moves.
    set_default(&p, None, "ops").await;
    assert_eq!(default_of(&p, None).await.as_deref(), Some("ops"));
    assert_eq!(
        default_of(&p, Some(&e2)).await.as_deref(),
        Some("dev"),
        "e2's default is its own"
    );
    for (before, j) in pins_before.iter().zip(all) {
        assert!(
            same_pins(before, &pins(&w, &j.binding_id)),
            "the default redirects no binding"
        );
    }

    // e2's cleanup during the native jobs: e2's job ends. Its release's own cleanup cannot
    // finish (its binding files cannot be removed), so the slot stays `clearing` in e2; the
    // supervisor's pass over the managed set completes it, in e2 only (no other job
    // references it there, so it clears).
    let dirs = w.binding_dirs(&c.binding_id);
    assert_eq!(dirs.len(), 1);
    set_mode(&dirs[0].0, 0o500);
    release(&p, &c.binding_id).await;
    assert_eq!(
        slot_in(&w, &e2, &pr),
        SlotState::Clearing { generation: 1 },
        "the release's own cleanup did not complete"
    );
    set_mode(&dirs[0].0, 0o700);
    supervisor(&w, &p).ended_slot_pass().await.unwrap();
    assert_eq!(
        slot_in(&w, &e2, &pr),
        SlotState::Free { generation: 1 },
        "e2's slot cleared in e2"
    );
    assert!(references(&w, &e2, &pr).is_empty());
    assert_eq!(slot_certificate(&root2, &pr), None);
    assert!(p.table.list(&e2_listing).is_empty());
    assert_eq!(
        slot_in(&w, &env(), &pr),
        SlotState::Held {
            binding: a.binding_id.clone(),
            generation: 1
        },
        "the native slot is untouched"
    );
    assert_eq!(p.table.materialized_generation(&a.binding_id, &pr), Some(1));
    assert_eq!(files::slot_generation(&root1, &pr).unwrap(), Some(1));
    assert_eq!(
        references(&w, &env(), &pr),
        sorted(vec![a.binding_id.clone(), b.binding_id.clone()])
    );
    let (ok, fp) = ssh.through_slot(&p, &pr, "a16-native-after-e2").await;
    assert!(ok, "the native alias still works");
    assert_eq!(fp, Some(key_of(&p, &a.grant_id)));

    // The native cleanup during e2's job: the native slot hands over; e2's stays.
    release(&p, &a.binding_id).await;
    supervisor(&w, &p).ended_slot_pass().await.unwrap();
    assert_eq!(
        slot_in(&w, &env(), &pr),
        SlotState::Held {
            binding: b.binding_id.clone(),
            generation: 2
        }
    );
    let (ok, fp) = ssh.through_slot(&p, &pr, "a16-native-handed").await;
    assert!(ok);
    assert_eq!(fp, Some(key_of(&p, &b.grant_id)));
    assert_eq!(
        slot_in(&w, &e2, &pr),
        SlotState::Free { generation: 1 },
        "e2's slot is untouched by the native cleanup"
    );
    for (before, j) in pins_before.iter().zip(all) {
        assert!(
            same_pins(before, &pins(&w, &j.binding_id)),
            "no pin changed"
        );
    }

    // Every job ends: both slots clear, each in its own namespace.
    release(&p, &b.binding_id).await;
    supervisor(&w, &p).ended_slot_pass().await.unwrap();
    for (environment, root, generation) in [(env(), &root1, 2), (e2.clone(), &root2, 1)] {
        assert_eq!(
            slot_in(&w, &environment, &pr),
            SlotState::Free { generation }
        );
        assert!(references(&w, &environment, &pr).is_empty());
        assert_eq!(slot_certificate(root, &pr), None);
    }
    assert!(p.table.list(&SignerEndpoint::Environment).is_empty());
    assert!(p.table.list(&e2_listing).is_empty());
    p.shutdown.cancel();
}

/// A04 (R-UX-06, R-AU-03): two bindings run on pair P of profile `dev` (one materializes
/// P's alias, the other joins it). The default profile changes (`dev` → `ops`) and a new
/// revision of `dev` is published that no longer has P. Neither binding's pins change
/// (environment, profile and revision 1, scope, mechanism, grant, context), their grants
/// keep their scope, and the alias keeps its authority: `ssh` through it still signs with
/// the materializer's key. Only new requests see the change: the default reads `ops`, a
/// new `dev` request pins revision 2 (its scope, P2), and a new request for P under `dev`
/// is refused (P is no longer in it).
#[tokio::test]
async fn a04_default_and_profile_change_never_redirects_bindings() {
    let pr = own_pair("u6-a04");
    let pr2 = own_pair("u6-a04b");
    let w = Live::seeded(&[pr.clone(), pr2.clone()], Timestamp::now());
    let ssh = ssh_world(&w, &pr);
    let p = w.process(Arc::new(NoStageHook)).await;
    p.registry.start_environment().unwrap();
    let only_p = std::slice::from_ref(&pr);
    upsert_profile(&p, "ops", std::slice::from_ref(&pr2), "ops").await;
    set_default(&p, None, "dev").await;
    let a = job(&p.ops, "a04-a", only_p, None, "1h").await;
    let b = job(&p.ops, "a04-b", only_p, None, "2h").await;
    assert!(!shared(&launch(&p, &a.binding_id, "a04-a").await));
    assert!(shared(&launch(&p, &b.binding_id, "a04-b").await));
    let before = [pins(&w, &a.binding_id), pins(&w, &b.binding_id)];
    assert!(before.iter().all(|(r, _)| r.profile_revision == 1));
    let scopes = |w: &Live| {
        w.store
            .transaction(|tx| {
                Ok((
                    tx.grant(&a.grant_id)?.unwrap().scope,
                    tx.grant(&b.grant_id)?.unwrap().scope,
                ))
            })
            .unwrap()
    };
    let scopes_before = scopes(&w);
    let (ok, fp) = ssh.through_slot(&p, &pr, "a04-before").await;
    assert!(ok);
    assert_eq!(fp, Some(key_of(&p, &a.grant_id)));

    // The default and the profile definition change while both run.
    set_default(&p, None, "ops").await;
    upsert_profile(&p, "dev", std::slice::from_ref(&pr2), "dev-r2").await;
    let revision = w
        .store
        .transaction(|tx| tx.profile(&ProfileId::parse("dev").unwrap()))
        .unwrap()
        .unwrap()
        .revision;
    assert_eq!(revision, 2, "a new revision of dev");

    // Existing work: no pin, scope or authority moves.
    for (old, binding) in before.iter().zip([&a.binding_id, &b.binding_id]) {
        assert!(
            same_pins(old, &pins(&w, binding)),
            "the binding keeps its pins"
        );
    }
    assert_eq!(scopes(&w), scopes_before, "the grants keep their scope");
    assert_eq!(
        slot_in(&w, &env(), &pr),
        SlotState::Held {
            binding: a.binding_id.clone(),
            generation: 1
        }
    );
    let (ok, fp) = ssh.through_slot(&p, &pr, "a04-after").await;
    assert!(ok, "the alias keeps its authority");
    assert_eq!(fp, Some(key_of(&p, &a.grant_id)));

    // New requests only.
    assert_eq!(default_of(&p, None).await.as_deref(), Some("ops"));
    let fresh = job(&p.ops, "a04-new", &[], None, "1h").await;
    assert_eq!(
        fresh.profile_revision, 2,
        "a new request pins the new revision"
    );
    let fresh_scope = pins(&w, &fresh.binding_id).0.scope.pairs;
    assert_eq!(fresh_scope, [pr2.clone()].into_iter().collect());
    let refused = p
        .ops
        .ensure(
            &caller(),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: [pr.clone()].into_iter().collect(),
                environment: None,
                work_id: WorkId::parse("w-a04-p").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-a04-p").unwrap(),
                interaction: InteractionMode::Interactive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
                context: None,
                covered_only: false,
                pair_issuers: Vec::new(),
            },
        )
        .await;
    assert!(refused.is_err(), "P is not in dev's new revision");
    p.shutdown.cancel();
}
