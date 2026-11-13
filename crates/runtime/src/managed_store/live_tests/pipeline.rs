//! ⟨M03 wave 4, round 3 (R3-C2)⟩ ADR-0008 §17.22 items 5, 6 and 8, live: the managed
//! pipeline through the real `Operations`, managed adapter, [`StoreCleanup`],
//! `ManagedEffectsImpl`, signer table, vault and `EndpointRegistry` of [`super::Live`].
//!
//! * Item 8 (W4-R05, W4-R06): a crash between `materialize` and the ensure
//!   confirmation, and a failure inside the driver's own cleanup.
//! * Item 5 (W4-R02): a restart in the same boot, the re-issue pass, then **real
//!   `ssh`** (the system client) through the binding endpoint and through the slot,
//!   against a disposable [`LoopbackSshd`] trusting this run's fixture CA
//!   (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`): the certificate path of
//!   `tests/integration/credential_cert.rs`'s fixture-sshd case, with the managed
//!   identity options `connect` renders.
//! * Item 6 (W4-R03): two distinct `request_id`s coalesce; both bindings sign through
//!   real `ssh`.
//!
//! Every key and the CA are generated per run in scratch directories; the client runs
//! with the scratch home's isolation (its own configuration, known hosts, `HOME`, a
//! decoy agent); nothing of the owner's is read, contacted or changed.

use super::*;
use heimdall_adapters::managed::files::binding_files_for_endpoint;
use heimdall_app::ports::{KeyRegistration, MaterializeSpec, MaterializedFiles};
use heimdall_contract::provider::EndpointKind;
use heimdall_domain::operation::EffectReceipt;
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// A managed `ensure` of profile `dev` over `scope` (interactive, as
/// [`Live::ensure`]), on `ops`.
async fn ensure_on(
    ops: &Operations,
    tag: &str,
    scope: &[AccessPair],
) -> Result<EnsureData, heimdall_app::OpError> {
    ops.ensure(
        &caller(),
        EnsureRequest {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: None,
            scope: scope.iter().cloned().collect(),
            environment: None,
            work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
            until: None,
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
            interaction: InteractionMode::Interactive,
            wait: WaitMode::Sync { timeout_ms: 30_000 },
            connection: None,
        },
    )
    .await
    .map(|c| c.data)
}

/// The one open operation of the store (the in-flight ensure).
fn open_operation(w: &Live) -> OperationId {
    let open = w.store.transaction(|tx| tx.open_operations()).unwrap();
    assert_eq!(open.len(), 1, "one operation in flight");
    open[0].id.clone()
}

fn stages(w: &Live, op: &OperationId) -> Vec<(String, EffectReceipt)> {
    w.store
        .transaction(|tx| tx.stage_receipts(op))
        .unwrap()
        .into_iter()
        .map(|r| (r.stage, r.effect))
        .collect()
}

fn intents(w: &Live) -> Vec<(GrantId, OperationId)> {
    w.store
        .transaction(|tx| tx.cleanup_intents())
        .unwrap()
        .into_iter()
        .map(|i| (i.grant, i.operation))
        .collect()
}

fn op_and_grant_state(
    w: &Live,
    op: &OperationId,
    grant: &GrantId,
) -> (
    Option<heimdall_contract::OperationState>,
    Option<GrantState>,
    bool,
) {
    w.store
        .transaction(|tx| {
            let minted = w_minted(tx, op)?;
            Ok((
                tx.operation(op)?.map(|o| o.state),
                tx.grant(grant)?.map(|g| g.state),
                tx.binding(&minted)?.is_some(),
            ))
        })
        .unwrap()
}

fn w_minted(
    tx: &mut heimdall_store::Txn<'_>,
    op: &OperationId,
) -> heimdall_store::Result<BindingId> {
    Ok(tx
        .recovery_intent(op)?
        .and_then(|i| i.resolved)
        .and_then(|r| r.binding_id)
        .expect("a binding ID minted at resolve"))
}

/// §17.22 item 8 (W4-R05), the reviewer's exact interval: the runtime dies **after**
/// `effects.materialize` wrote the binding files (and the binding endpoint lists the
/// grant's certificates) but **before** the ensure confirmation (the last `Reconcile`
/// receipt is still `Attempted`). The process runs on its own tokio runtime, held in
/// `prepare_from` (after the driver's step 6 and its `managed.prepared` receipt), and
/// that runtime is dropped there: no cleanup of that process runs. The cleanup intent
/// was recorded with the attempt, before the first effect. After the restart (same
/// store, a new signer, the effects wired late as in production) the recovery fails
/// the operation and the cleanup pass leaves no endpoint, no binding file, no key and
/// no live instance; nothing is committed and no intent is left.
#[tokio::test]
async fn crash_between_materialize_and_confirmation_leaves_no_endpoint_file_or_key() {
    let w = Live::new();
    let (op, binding, grant, endpoint) = std::thread::scope(|s| {
        s.spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let out = rt.block_on(async {
                let hold = Arc::new(Hold::default());
                hold.armed.store(true, Ordering::SeqCst);
                let p = w
                    .process_opts(
                        Arc::new(NoStageHook),
                        Opts {
                            hold: hold.clone(),
                            ..Opts::default()
                        },
                    )
                    .await;
                let ops = p.ops.clone();
                tokio::spawn(async move {
                    let _ = ensure_on(&ops, "crash-mc", &pairs()).await;
                });
                hold.reached.notified().await;
                let op = open_operation(&w);
                let binding = w.minted_binding(&op);
                let grant = w.grant_of(&op);
                // The interval: materialized, prepared, not confirmed.
                let receipts = stages(&w, &op);
                assert!(
                    receipts.iter().any(|(s, _)| s == "managed.materialize"),
                    "{receipts:?}"
                );
                let last_reconcile = receipts
                    .iter()
                    .rev()
                    .find(|(s, _)| s == "reconcile")
                    .map(|(_, e)| e.clone());
                assert!(
                    matches!(last_reconcile, Some(EffectReceipt::Attempted { .. })),
                    "not confirmed: {last_reconcile:?}"
                );
                let (endpoint, _) = p
                    .registry
                    .binding_endpoint(&binding)
                    .expect("materialized before the crash");
                assert_eq!(listed(&endpoint.locator).await.unwrap(), 2);
                assert_eq!(w.binding_dirs(&binding).len(), 1, "the files were written");
                assert_eq!(p.table.vault().len(), 1, "K_env lives in this process");
                assert!(
                    intents(&w).contains(&(grant.clone(), op.clone())),
                    "the cleanup intent exists from the attempt on"
                );
                (op, binding, grant, endpoint.locator)
            });
            // The crash: every task of the process stops where it is.
            rt.shutdown_background();
            out
        })
        .join()
        .unwrap()
    });
    assert!(gone(&endpoint).await, "the dead process's endpoint stopped");
    assert_eq!(w.binding_dirs(&binding).len(), 1, "the files outlived it");
    // The restart: recovery, then the late wiring, then the supervisor's cleanup pass.
    let q = w.process(Arc::new(NoStageHook)).await;
    q.ops.process_cleanup_intents().await.unwrap();
    assert!(w.binding_dirs(&binding).is_empty(), "no binding file");
    assert!(
        q.registry.binding_endpoint(&binding).is_none(),
        "no endpoint"
    );
    assert!(listed(&endpoint).await.is_err());
    assert_eq!(q.table.vault().len(), 0, "no key");
    assert_eq!(w.live_instances(&grant), 0);
    assert!(intents(&w).is_empty(), "the cleanup intent was processed");
    let (state, grant_state, committed) = op_and_grant_state(&w, &op, &grant);
    assert!(!committed, "no binding committed");
    assert_eq!(state, Some(heimdall_contract::OperationState::Failed));
    assert_eq!(grant_state, Some(GrantState::Failed));
}

/// The injected transient filesystem error of
/// [`driver_cleanup_failure_is_retried_until_clean`]: once armed, the driver's
/// `materialize` writes the files, makes the binding directory read-only (so removing
/// its files fails, `EACCES`) and fails; `release` makes it writable again.
#[derive(Default)]
struct Injected {
    armed: AtomicBool,
    dir: Mutex<Option<PathBuf>>,
}

impl Injected {
    fn release(&self) {
        if let Some(d) = self.dir.lock().unwrap().as_ref() {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}

impl Drop for Injected {
    fn drop(&mut self) {
        // Never leave the scratch directory undeletable.
        if let Some(d) = self.dir.get_mut().unwrap().as_ref() {
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
    }
}

/// The driver's effects with [`Injected`] (every other call delegates).
struct FailingMaterialize {
    inner: ManagedEffectsImpl,
    injected: Arc<Injected>,
}

impl ManagedEffects for FailingMaterialize {
    fn generate_key<'a, 'b, 'c, 'd>(
        &'a self,
        grant: &'b GrantId,
        token: &'c str,
    ) -> BoxFuture<'d, Result<KeyRegistration, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        self.inner.generate_key(grant, token)
    }
    fn install<'a, 'b, 'c, 'd, 'e>(
        &'a self,
        grant: &'b GrantId,
        entry: &'c IssuanceEntry,
        cert: &'d str,
    ) -> BoxFuture<'e, Result<(), AdapterError>>
    where
        'a: 'e,
        'b: 'e,
        'c: 'e,
        'd: 'e,
        Self: 'e,
    {
        self.inner.install(grant, entry, cert)
    }
    fn destroy<'a, 'b, 'c>(
        &'a self,
        grants: &'b [GrantId],
    ) -> BoxFuture<'c, Result<(), AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        self.inner.destroy(grants)
    }
    fn materialize(
        &self,
        binding: &BindingId,
        spec: &MaterializeSpec,
    ) -> Result<MaterializedFiles, AdapterError> {
        let files = self.inner.materialize(binding, spec)?;
        if self.injected.armed.swap(false, Ordering::SeqCst) {
            std::fs::set_permissions(&files.directory, std::fs::Permissions::from_mode(0o500))
                .unwrap();
            *self.injected.dir.lock().unwrap() = Some(files.directory.clone());
            return Err(AdapterError::Unavailable(
                "injected_materialize_failure".into(),
            ));
        }
        Ok(files)
    }
    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError> {
        self.inner.clear(binding, generation)
    }
}

/// §17.22 item 8 (W4-R06): the materialization fails after writing the files, and the
/// driver's own cleanup (`abandon`) then meets a transient filesystem error (the
/// binding directory is read-only). The key is destroyed and the operation fails, but
/// the cleanup intent is **kept**, not logged and forgotten: a supervisor pass while
/// the error lasts keeps it again, and the first pass after it ends removes the
/// endpoint and the files and clears the intent.
#[tokio::test]
async fn driver_cleanup_failure_is_retried_until_clean() {
    let w = Live::new();
    let injected = Arc::new(Injected::default());
    injected.armed.store(true, Ordering::SeqCst);
    let inj = injected.clone();
    let p = w
        .process_opts(
            Arc::new(NoStageHook),
            Opts {
                wrap: Some(Arc::new(move |inner| {
                    Arc::new(FailingMaterialize {
                        inner,
                        injected: inj.clone(),
                    }) as Arc<dyn ManagedEffects>
                })),
                ..Opts::default()
            },
        )
        .await;
    let e = w
        .ensure(&p, "r06", RequiredCapabilities::default())
        .await
        .unwrap_err();
    let op = e.operation_id.clone().expect("the operation");
    let binding = w.minted_binding(&op);
    let grant = w.grant_of(&op);
    assert!(
        injected.dir.lock().unwrap().is_some(),
        "the failure was injected inside the driver"
    );
    // The driver's cleanup could not remove the files: the intent is kept.
    assert_eq!(
        w.binding_dirs(&binding).len(),
        1,
        "the files are still there"
    );
    assert_eq!(intents(&w), vec![(grant.clone(), op.clone())], "kept");
    assert_eq!(p.table.vault().len(), 0, "the key was destroyed anyway");
    assert_eq!(w.live_instances(&grant), 0);
    // A pass while the error lasts: kept again.
    p.ops.process_cleanup_intents().await.unwrap();
    assert_eq!(w.binding_dirs(&binding).len(), 1);
    assert_eq!(intents(&w), vec![(grant.clone(), op.clone())], "still kept");
    // The error ends: the next pass completes the cleanup.
    injected.release();
    p.ops.process_cleanup_intents().await.unwrap();
    assert!(w.binding_dirs(&binding).is_empty(), "no binding file");
    assert!(
        p.registry.binding_endpoint(&binding).is_none(),
        "no endpoint"
    );
    assert!(intents(&w).is_empty(), "the intent was cleared once clean");
    let (state, grant_state, committed) = op_and_grant_state(&w, &op, &grant);
    assert!(!committed);
    assert_eq!(state, Some(heimdall_contract::OperationState::Failed));
    assert_eq!(grant_state, Some(GrantState::Failed));
}

// --- real ssh (items 5 and 6) ---------------------------------------------------------

/// A disposable sshd trusting this world's CA for `pair`'s principal, and a scratch
/// client home whose configuration names `alias` → that server as the current
/// account.
struct Ssh {
    home: ScratchHome,
    sshd: LoopbackSshd,
    alias: String,
}

fn ssh_world(w: &Live, pair: &AccessPair) -> Ssh {
    let home = ScratchHome::new();
    let account = pair.account.as_str().to_owned();
    let sshd = LoopbackSshd::start(
        home.scratch(),
        SshdConfig {
            trusted_user_ca_keys: Some(home.root.join("trusted_ca.pub")),
            authorized_principals: Some(
                [(
                    account.clone(),
                    vec![heimdall_domain::issuance::principal_for(pair)],
                )]
                .into(),
            ),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("a local fixture sshd is needed: {e}"));
    sshd.trust_user_ca(&w.ca.public_openssh().unwrap()).unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();
    let alias = "hm-c2-fixture".to_owned();
    home.write_user_config(&format!(
        "Host {alias}\n  HostName 127.0.0.1\n  Port {}\n  User {account}\n",
        sshd.port
    ))
    .unwrap();
    Ssh { home, sshd, alias }
}

/// The current account as a pair of destination `dest` (a non-root fixture sshd
/// authenticates only its own account).
fn own_pair(dest: &str) -> AccessPair {
    let account = current_account().expect("the current account");
    pair(dest, &account)
}

impl Ssh {
    /// The system `ssh` to the fixture alias with the managed identity options
    /// `connect` renders (`IdentityAgent=<endpoint>`, `IdentitiesOnly=yes`, the
    /// certificate as the identity file), running `echo <marker>`. Returns the exit
    /// status and the fingerprint of the certified key the server accepted (if any).
    async fn run(
        &self,
        endpoint: &str,
        key_pub: &Path,
        cert: &Path,
        marker: &str,
    ) -> (Option<i32>, Option<String>) {
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
        (
            if ok {
                Some(0)
            } else {
                out.status.code().or(Some(-1))
            },
            fingerprint,
        )
    }
}

/// The binding endpoint of `binding` in `p` and its files for `pair`: `(locator,
/// key.pub, cert-<dest>.pub, generation)`.
fn binding_files(
    w: &Live,
    p: &Process,
    binding: &BindingId,
    pair: &AccessPair,
) -> (String, PathBuf, PathBuf, u64) {
    let (endpoint, generation) = p
        .registry
        .binding_endpoint(binding)
        .expect("the binding endpoint runs");
    assert_eq!(endpoint.kind, EndpointKind::UnixSocket);
    let files = binding_files_for_endpoint(
        &w.run_dir(),
        &endpoint,
        std::slice::from_ref(&pair.destination),
    )
    .expect("the binding files beside the endpoint");
    let cert = files.certificate(&pair.destination).unwrap().to_path_buf();
    (endpoint.locator, files.key_pub, cert, generation.0)
}

/// §17.22 item 5 (W4-R02; D6 item 4; D10 item 2): an active managed binding holds its
/// environment slot; the runtime restarts in the same boot (a new process: an empty
/// signer, no in-memory record of the materialization). The grant is degraded
/// `credential_reissue_pending` and the slot path no longer signs. After the re-issue
/// pass the grant is `active` again, and **ordinary `ssh` succeeds with the new key**
/// both through the binding's endpoint (attached again, its files replaced at a new
/// generation, the old generation's removed) and through the slot (its files rewritten
/// at their store generation, listed again by the environment endpoint).
#[tokio::test]
async fn reissue_restores_binding_endpoint_files_and_slot_so_ssh_signs_with_the_new_key() {
    let pr = own_pair("c2-reissue");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let ssh = ssh_world(&w, &pr);
    // Process 1: the ensure, the launch bind (the slot held), ssh through both paths.
    let p = w.process(Arc::new(NoStageHook)).await;
    p.registry.start_environment().unwrap();
    let data = ensure_on(&p.ops, "reissue", std::slice::from_ref(&pr))
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    super::launch_bind(&p, &data.binding_id, "reissue", None)
        .await
        .unwrap_or_else(|e| panic!("bind: {} {}", e.code, e.message));
    let old_key = p.table.public_key(&data.grant_id).unwrap().fingerprint;
    let (ep1, key1, cert1, gen1) = binding_files(&w, &p, &data.binding_id, &pr);
    assert_eq!(gen1, 1);
    let (code, fp) = ssh.run(&ep1, &key1, &cert1, "before-binding").await;
    assert_eq!(
        code,
        Some(0),
        "ssh through the binding endpoint before the restart"
    );
    assert_eq!(fp.as_deref(), Some(old_key.as_str()));
    let slot = files::slot_paths(&p.effects.slot_root().data_dir, &pr).unwrap();
    let env_endpoint = p.registry.environment().locator;
    let (code, _) = ssh
        .run(&env_endpoint, &slot.key_pub, &slot.cert_pub, "before-slot")
        .await;
    assert_eq!(code, Some(0), "ssh through the slot before the restart");
    // The restart in the same boot.
    p.shutdown.cancel();
    drop(p);
    let q = w.process(Arc::new(NoStageHook)).await;
    q.registry.start_environment().unwrap();
    let degradation = w
        .store
        .transaction(|tx| {
            Ok((
                tx.grant(&data.grant_id)?.unwrap().state,
                tx.grant_degradation(&data.grant_id)?,
            ))
        })
        .unwrap();
    assert_eq!(
        degradation,
        (
            GrantState::Degraded,
            Some(heimdall_domain::grant::DegradedReason::CredentialReissuePending)
        )
    );
    let (code, _) = ssh
        .run(
            &q.registry.environment().locator,
            &slot.key_pub,
            &slot.cert_pub,
            "degraded",
        )
        .await;
    assert_ne!(
        code,
        Some(0),
        "degraded until the re-issue: the slot does not sign"
    );
    // The re-issue pass.
    assert_eq!(
        q.ops.managed_reissue_pass().await.unwrap(),
        vec![data.grant_id.clone()]
    );
    let state = w
        .store
        .transaction(|tx| tx.grant(&data.grant_id))
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state, GrantState::Active);
    let new_key = q.table.public_key(&data.grant_id).unwrap().fingerprint;
    assert_ne!(new_key, old_key);
    // The binding endpoint: attached again, files at a new generation, the old ones gone.
    let (ep2, key2, cert2, gen2) = binding_files(&w, &q, &data.binding_id, &pr);
    assert!(gen2 > gen1, "a new generation: {gen2}");
    assert_eq!(
        w.binding_dirs(&data.binding_id)
            .into_iter()
            .map(|(_, g)| g)
            .collect::<Vec<_>>(),
        vec![gen2],
        "only the new generation's files remain"
    );
    assert_eq!(listed(&ep2).await.unwrap(), 1);
    let (code, fp) = ssh.run(&ep2, &key2, &cert2, "after-binding").await;
    assert_eq!(
        code,
        Some(0),
        "ssh through the binding endpoint after the re-issue"
    );
    assert_eq!(fp.as_deref(), Some(new_key.as_str()), "with the new key");
    // The slot: rewritten at its store generation and listed again.
    assert_eq!(
        q.table.materialized_generation(&data.binding_id, &pr),
        Some(1)
    );
    let (code, fp) = ssh
        .run(
            &q.registry.environment().locator,
            &slot.key_pub,
            &slot.cert_pub,
            "after-slot",
        )
        .await;
    assert_eq!(code, Some(0), "ssh through the slot after the re-issue");
    assert_eq!(fp.as_deref(), Some(new_key.as_str()), "with the new key");
    q.shutdown.cancel();
}

/// §17.22 item 6 (W4-R03): two equivalent managed ensures with **distinct**
/// `request_id`s coalesce in flight (the leader is held in its preparation while the
/// follower resolves and joins it). The follower attaches to the leader's grant and
/// key (it prepares nothing: its `Reconcile` is `NotAttempted`), but its own binding
/// is materialized under its own ID before its commit: its own endpoint (named in its
/// result) and files. Both bindings sign through real `ssh`, with the one shared key.
#[tokio::test]
async fn coalesced_follower_gets_its_own_materialized_binding_and_both_sign() {
    let pr = own_pair("c2-coalesce");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let ssh = ssh_world(&w, &pr);
    let hold = Arc::new(Hold::default());
    hold.armed.store(true, Ordering::SeqCst);
    let p = w
        .process_opts(
            Arc::new(NoStageHook),
            Opts {
                hold: hold.clone(),
                ..Opts::default()
            },
        )
        .await;
    let ops = p.ops.clone();
    let scope = vec![pr.clone()];
    let s1 = scope.clone();
    let leader = tokio::spawn(async move { ensure_on(&ops, "lead", &s1).await });
    hold.reached.notified().await;
    let ops = p.ops.clone();
    let s2 = scope.clone();
    let follower = tokio::spawn(async move { ensure_on(&ops, "follow", &s2).await });
    // The follower resolves, then joins the leader's flight at `Coalesce`.
    let mut joined = false;
    for _ in 0..500 {
        let resolved = w
            .store
            .transaction(|tx| {
                for o in tx.open_operations()? {
                    let rs = tx.stage_receipts(&o.id)?;
                    if rs.iter().any(|r| r.stage == "resolve_mechanism")
                        && !rs.iter().any(|r| r.stage == "reconcile")
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .unwrap();
        if resolved {
            joined = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(joined, "the follower resolved while the leader prepares");
    tokio::time::sleep(Duration::from_millis(300)).await;
    hold.release.notify_one();
    let lead = leader
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("leader: {} {}", e.code, e.message));
    let follow = follower
        .await
        .unwrap()
        .unwrap_or_else(|e| panic!("follower: {} {}", e.code, e.message));
    assert_eq!(follow.grant_id, lead.grant_id, "coalesced onto one grant");
    assert_ne!(follow.binding_id, lead.binding_id, "each its own binding");
    let follow_op = w
        .store
        .transaction(|tx| {
            let key = heimdall_domain::idempotency::IdempotencyKey {
                caller: caller().context.clone(),
                kind: heimdall_domain::operation::OperationKind::Ensure,
                request_id: RequestId::parse("r-follow").unwrap(),
            };
            Ok(tx.idempotency_record(&key)?.unwrap().operation_id)
        })
        .unwrap();
    let last = stages(&w, &follow_op)
        .into_iter()
        .rev()
        .find(|(s, _)| s == "reconcile")
        .map(|(_, e)| e);
    assert_eq!(
        last,
        Some(EffectReceipt::NotAttempted),
        "the follower prepared nothing"
    );
    assert_eq!(p.table.vault().len(), 1, "one shared K_env");
    let key = p.table.public_key(&lead.grant_id).unwrap().fingerprint;
    // Each binding: its own endpoint, named in its own result, and its files.
    let (lep, lkey, lcert, _) = binding_files(&w, &p, &lead.binding_id, &pr);
    let (fep, fkey, fcert, fgen) = binding_files(&w, &p, &follow.binding_id, &pr);
    assert_ne!(lep, fep);
    assert_eq!(
        lead.consumer.signing_endpoint.as_deref(),
        Some(lep.as_str())
    );
    assert_eq!(
        follow.consumer.signing_endpoint.as_deref(),
        Some(fep.as_str())
    );
    assert!(
        follow
            .consumer
            .pairs
            .iter()
            .all(|pi| pi.endpoint.as_ref().is_none_or(|e| e.locator == fep)),
        "the follower's pairs name its own endpoint"
    );
    assert_eq!(fgen, 1);
    assert!(intents(&w).is_empty(), "both commits retired their intents");
    let (code, fp) = ssh.run(&lep, &lkey, &lcert, "leader").await;
    assert_eq!(code, Some(0), "the leader's binding signs");
    assert_eq!(fp.as_deref(), Some(key.as_str()));
    let (code, fp) = ssh.run(&fep, &fkey, &fcert, "follower").await;
    assert_eq!(code, Some(0), "the follower's binding signs");
    assert_eq!(fp.as_deref(), Some(key.as_str()));
    p.shutdown.cancel();
}

/// §17.22 item 6 (W4-R03), the decision-joined case (code review A07): two equivalent
/// managed ensures that need an approval (a window beyond the standing policy's) with
/// **distinct** `request_id`s share one decision record; once it is approved the
/// owner prepares the grant, and the joined request attaches to it. The joined
/// request's own binding is materialized under its own ID (its own endpoint, named in
/// its result, and its files), and both bindings sign through real `ssh`.
#[tokio::test]
async fn decision_joined_follower_gets_its_own_materialized_binding_and_both_sign() {
    use heimdall_app::context::Attendance;
    use heimdall_contract::ids::DecisionId;
    use heimdall_contract::request::{DecideRequest, Verdict};
    let pr = own_pair("c2-joined");
    let start = Timestamp::now();
    let w = Live::seeded(std::slice::from_ref(&pr), start);
    let ssh = ssh_world(&w, &pr);
    let p = w.process(Arc::new(NoStageHook)).await;
    // Beyond the policy's two-hour window: added authority, an owner decision.
    let until = heimdall_contract::request::DeadlineIntent::Absolute(
        Timestamp::from_second(start.as_second() + 3 * 3600)
            .unwrap()
            .to_string(),
    );
    let ensure = |tag: &'static str| {
        let ops = p.ops.clone();
        let scope = vec![pr.clone()];
        let until = until.clone();
        async move {
            ops.ensure(
                &caller(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: scope.into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse("w-joined").unwrap(),
                    until: Some(until.clone()),
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(tag).unwrap(),
                    interaction: InteractionMode::Interactive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            )
            .await
        }
    };
    let a = ensure("r-joined-1").await.unwrap_err();
    let b = ensure("r-joined-2").await.unwrap_err();
    assert_eq!(a.code, Code::InteractionRequired, "{}", a.message);
    let decision = |e: &heimdall_app::OpError| {
        DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
    };
    assert_eq!(decision(&a), decision(&b), "one decision record, joined");
    assert_ne!(a.operation_id, b.operation_id);
    let attended = Caller {
        attendance: Attendance::Attended { since: start },
        interaction: InteractionMode::Interactive,
        ..caller()
    };
    p.ops
        .decide(
            &attended,
            DecideRequest {
                decision_id: decision(&a),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
    let ra = ensure("r-joined-1")
        .await
        .unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message))
        .data;
    let rb = ensure("r-joined-2")
        .await
        .unwrap_or_else(|e| panic!("joined: {} {}", e.code, e.message))
        .data;
    assert_eq!(ra.grant_id, rb.grant_id, "one grant");
    assert_ne!(ra.binding_id, rb.binding_id, "separate bindings");
    assert_eq!(p.table.vault().len(), 1, "one K_env, prepared once");
    let joined_op = b.operation_id.clone().unwrap();
    let last = stages(&w, &joined_op)
        .into_iter()
        .rev()
        .find(|(s, _)| s == "reconcile")
        .map(|(_, e)| e);
    assert_eq!(
        last,
        Some(EffectReceipt::NotAttempted),
        "the joined request prepared nothing"
    );
    let key = p.table.public_key(&ra.grant_id).unwrap().fingerprint;
    let (aep, akey, acert, _) = binding_files(&w, &p, &ra.binding_id, &pr);
    let (bep, bkey, bcert, _) = binding_files(&w, &p, &rb.binding_id, &pr);
    assert_ne!(aep, bep);
    assert_eq!(ra.consumer.signing_endpoint.as_deref(), Some(aep.as_str()));
    assert_eq!(rb.consumer.signing_endpoint.as_deref(), Some(bep.as_str()));
    assert!(intents(&w).is_empty(), "both commits retired their intents");
    let (code, fp) = ssh.run(&aep, &akey, &acert, "owner").await;
    assert_eq!(code, Some(0), "the owner's binding signs");
    assert_eq!(fp.as_deref(), Some(key.as_str()));
    let (code, fp) = ssh.run(&bep, &bkey, &bcert, "joined").await;
    assert_eq!(code, Some(0), "the joined request's binding signs");
    assert_eq!(fp.as_deref(), Some(key.as_str()));
    p.shutdown.cancel();
}

// --- ⟨M03 wave 4, round 3b (X-M); ADR-0008 §17.23 item 6⟩ the typed source and locator ---

/// One `materialize` the driver's effects answered: the binding, the spec, and the
/// endpoint the result reported as created.
type Answered = (BindingId, MaterializeSpec, Option<EndpointRef>);

/// The driver's effects, recording each `materialize` answer; while
/// `drop_installed_endpoint` is set, an [`heimdall_app::ports::MaterializeSource::InstalledKeyOf`]
/// answer reports **no** created endpoint (the files and the endpoint still exist).
struct RecordingEffects {
    inner: ManagedEffectsImpl,
    answered: Arc<Mutex<Vec<Answered>>>,
    drop_installed_endpoint: Arc<AtomicBool>,
}

impl ManagedEffects for RecordingEffects {
    fn generate_key<'a, 'b, 'c, 'd>(
        &'a self,
        grant: &'b GrantId,
        token: &'c str,
    ) -> BoxFuture<'d, Result<KeyRegistration, AdapterError>>
    where
        'a: 'd,
        'b: 'd,
        'c: 'd,
        Self: 'd,
    {
        self.inner.generate_key(grant, token)
    }
    fn install<'a, 'b, 'c, 'd, 'e>(
        &'a self,
        grant: &'b GrantId,
        entry: &'c IssuanceEntry,
        cert: &'d str,
    ) -> BoxFuture<'e, Result<(), AdapterError>>
    where
        'a: 'e,
        'b: 'e,
        'c: 'e,
        'd: 'e,
        Self: 'e,
    {
        self.inner.install(grant, entry, cert)
    }
    fn destroy<'a, 'b, 'c>(
        &'a self,
        grants: &'b [GrantId],
    ) -> BoxFuture<'c, Result<(), AdapterError>>
    where
        'a: 'c,
        'b: 'c,
        Self: 'c,
    {
        self.inner.destroy(grants)
    }
    fn materialize(
        &self,
        binding: &BindingId,
        spec: &MaterializeSpec,
    ) -> Result<MaterializedFiles, AdapterError> {
        let mut files = self.inner.materialize(binding, spec)?;
        if self.drop_installed_endpoint.load(Ordering::SeqCst)
            && matches!(
                spec.source,
                heimdall_app::ports::MaterializeSource::InstalledKeyOf { .. }
            )
        {
            files.endpoint = None;
        }
        self.answered
            .lock()
            .unwrap()
            .push((binding.clone(), spec.clone(), files.endpoint.clone()));
        Ok(files)
    }
    fn clear(&self, binding: &BindingId, generation: u64) -> Result<(), AdapterError> {
        self.inner.clear(binding, generation)
    }
}

/// A process whose driver effects are [`RecordingEffects`].
async fn recording_process(
    w: &Live,
    drop_installed_endpoint: bool,
) -> (Process, Arc<Mutex<Vec<Answered>>>) {
    let answered = Arc::new(Mutex::new(Vec::new()));
    let drop_endpoint = Arc::new(AtomicBool::new(drop_installed_endpoint));
    let (a, d) = (answered.clone(), drop_endpoint.clone());
    let p = w
        .process_opts(
            Arc::new(NoStageHook),
            Opts {
                wrap: Some(Arc::new(move |inner| {
                    Arc::new(RecordingEffects {
                        inner,
                        answered: a.clone(),
                        drop_installed_endpoint: d.clone(),
                    }) as Arc<dyn ManagedEffects>
                })),
                ..Opts::default()
            },
        )
        .await;
    (p, answered)
}

/// Two equivalent managed ensures needing one owner decision (a window beyond the
/// policy's), joined on it; approved; then the owner's ensure (it prepares the grant)
/// and the joined one (a decision-joined follower). Returns both results and the
/// joined request's operation.
async fn decision_joined(
    p: &Process,
    pr: &AccessPair,
    start: Timestamp,
    tag: &str,
) -> (
    Result<EnsureData, heimdall_app::OpError>,
    Result<EnsureData, heimdall_app::OpError>,
    OperationId,
) {
    use heimdall_app::context::Attendance;
    use heimdall_contract::ids::DecisionId;
    use heimdall_contract::request::{DecideRequest, Verdict};
    let until = heimdall_contract::request::DeadlineIntent::Absolute(
        Timestamp::from_second(start.as_second() + 3 * 3600)
            .unwrap()
            .to_string(),
    );
    let ensure = |request: String| {
        let ops = p.ops.clone();
        let scope = vec![pr.clone()];
        let until = until.clone();
        let work = format!("w-{tag}");
        async move {
            ops.ensure(
                &caller(),
                EnsureRequest {
                    profile: ProfileId::parse("dev").unwrap(),
                    profile_revision: None,
                    scope: scope.into_iter().collect(),
                    environment: None,
                    work_id: WorkId::parse(&work).unwrap(),
                    until: Some(until),
                    required_capabilities: RequiredCapabilities::default(),
                    request_id: RequestId::parse(&request).unwrap(),
                    interaction: InteractionMode::Interactive,
                    wait: WaitMode::Sync { timeout_ms: 30_000 },
                    connection: None,
                },
            )
            .await
        }
    };
    let (r1, r2) = (format!("r-{tag}-1"), format!("r-{tag}-2"));
    let a = ensure(r1.clone()).await.unwrap_err();
    let b = ensure(r2.clone()).await.unwrap_err();
    assert_eq!(a.code, Code::InteractionRequired, "{}", a.message);
    let decision = |e: &heimdall_app::OpError| {
        DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
    };
    assert_eq!(decision(&a), decision(&b), "one decision record, joined");
    let attended = Caller {
        attendance: Attendance::Attended { since: start },
        interaction: InteractionMode::Interactive,
        ..caller()
    };
    p.ops
        .decide(
            &attended,
            DecideRequest {
                decision_id: decision(&a),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
    let ra = ensure(r1).await.map(|c| c.data);
    let rb = ensure(r2).await.map(|c| c.data);
    (ra, rb, b.operation_id.clone().unwrap())
}

/// §17.23 item 6 (R3C2-Q1/Q2): a decision-joined follower's own binding is
/// materialized with the explicit source `InstalledKeyOf` its grant (the new
/// activation's with `Fresh` key material), and **each result names exactly the
/// endpoint its materialization reported as created**: the follower's
/// `consumer.signing_endpoint` and every pair's endpoint are that locator, which is the
/// endpoint the registry runs for the follower's binding; nothing is derived from the
/// leader's locator.
#[tokio::test]
async fn follower_names_exactly_the_endpoint_its_materialization_created() {
    use heimdall_app::ports::MaterializeSource;
    let pr = own_pair("xm-named");
    let start = Timestamp::now();
    let w = Live::seeded(std::slice::from_ref(&pr), start);
    let (p, answered) = recording_process(&w, false).await;
    let (ra, rb, _) = decision_joined(&p, &pr, start, "named").await;
    let ra = ra.unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message));
    let rb = rb.unwrap_or_else(|e| panic!("joined: {} {}", e.code, e.message));
    assert_eq!(ra.grant_id, rb.grant_id, "one grant");
    let answered = answered.lock().unwrap().clone();
    let of = |b: &BindingId| {
        let found: Vec<&Answered> = answered.iter().filter(|(x, _, _)| x == b).collect();
        assert_eq!(found.len(), 1, "one materialization of {b}: {answered:?}");
        found[0].clone()
    };
    let (_, lspec, lcreated) = of(&ra.binding_id);
    let (_, fspec, fcreated) = of(&rb.binding_id);
    assert!(
        matches!(lspec.source, MaterializeSource::Fresh { .. }),
        "{lspec:?}"
    );
    assert_eq!(
        fspec.source,
        MaterializeSource::InstalledKeyOf {
            grant: ra.grant_id.clone()
        },
        "the follower names its source explicitly"
    );
    let lcreated = lcreated.expect("the owner's materialization created its endpoint");
    let fcreated = fcreated.expect("the follower's materialization created its endpoint");
    assert_ne!(lcreated, fcreated);
    for (data, created) in [(&ra, &lcreated), (&rb, &fcreated)] {
        assert_eq!(
            data.consumer.signing_endpoint.as_deref(),
            Some(created.locator.as_str())
        );
        assert!(!data.consumer.pairs.is_empty());
        assert!(
            data.consumer
                .pairs
                .iter()
                .all(|pi| pi.endpoint.as_ref() == Some(created)),
            "every pair names the created endpoint: {:?}",
            data.consumer.pairs
        );
        let (running, _) = p
            .registry
            .binding_endpoint(&data.binding_id)
            .expect("the binding endpoint runs");
        assert_eq!(&running, created, "the registry runs exactly that endpoint");
    }
    p.shutdown.cancel();
}

/// §17.23 item 6: a follower whose materialization reports **no** created endpoint is
/// refused at its commit (`SERVICE_UNAVAILABLE`, effect `none`), never `ACCESS_READY`
/// naming a derived locator; its binding is not committed and its cleanup intent is
/// processed (its endpoint and files are gone), while the owner's binding is
/// unaffected.
#[tokio::test]
async fn follower_refused_when_its_materialization_created_no_endpoint() {
    let pr = own_pair("xm-none");
    let start = Timestamp::now();
    let w = Live::seeded(std::slice::from_ref(&pr), start);
    let (p, _) = recording_process(&w, true).await;
    let (ra, rb, joined) = decision_joined(&p, &pr, start, "none").await;
    let ra = ra.unwrap_or_else(|e| panic!("owner: {} {}", e.code, e.message));
    let e = rb.expect_err("the follower must be refused");
    assert_eq!(e.code, Code::ServiceUnavailable, "{}", e.message);
    assert_eq!(e.effect_status, heimdall_contract::EffectStatus::None);
    let minted = w.minted_binding(&joined);
    let committed = w
        .store
        .transaction(|tx| tx.binding(&minted))
        .unwrap()
        .is_some();
    assert!(!committed, "no binding committed for the refused follower");
    assert!(
        p.registry.binding_endpoint(&minted).is_none(),
        "the refused follower's endpoint was removed"
    );
    assert!(w.binding_dirs(&minted).is_empty(), "and its files");
    assert!(intents(&w).is_empty(), "its intent was processed");
    assert!(p.registry.binding_endpoint(&ra.binding_id).is_some());
    p.shutdown.cancel();
}

/// §17.23 item 6: a spec whose source is inconsistent with the binding or the grant
/// is refused by the effects, and creates nothing (no endpoint, no files, nothing
/// attached): R3-C2's by-reference convention (a fingerprint for the key line, empty
/// certificates) is no longer a form; a `Fresh` source without certificates; an
/// `InstalledKeyOf` a grant with no live key here; an `InstalledKeyOf` another live
/// grant than the one the binding is attached to; `SlotsOnly` without the slots.
#[tokio::test]
async fn materialize_refuses_a_spec_with_an_inconsistent_source() {
    use heimdall_app::ports::{MaterializeSource, MaterializedCertificate};
    let (pr, pr2) = (own_pair("xm-src"), own_pair("xm-src2"));
    let w = Live::seeded(&[pr.clone(), pr2.clone()], Timestamp::now());
    let p = w.process(Arc::new(NoStageHook)).await;
    let data = ensure_on(&p.ops, "src", std::slice::from_ref(&pr))
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    // Another live grant, its key and certificate installed here.
    let live_other = ensure_on(&p.ops, "src2", std::slice::from_ref(&pr2))
        .await
        .unwrap_or_else(|e| panic!("ensure 2: {} {}", e.code, e.message))
        .grant_id;
    assert_ne!(live_other, data.grant_id);
    let key = p.table.public_key(&data.grant_id).unwrap();
    let fresh = BindingId::from_random_bytes([0x5a; 16]);
    let spec = |source| MaterializeSpec {
        generation: 1,
        source,
        environment_slots: false,
    };
    let other_grant = GrantId::from_random_bytes([0x6b; 16]);
    let cases: Vec<(&str, &BindingId, MaterializeSpec, &str)> = vec![
        (
            "by-reference convention",
            &fresh,
            spec(MaterializeSource::Fresh {
                public_key: key.fingerprint.clone(),
                certificates: vec![MaterializedCertificate {
                    pair: pr.clone(),
                    certificate: String::new(),
                }],
            }),
            "binding_not_attached",
        ),
        (
            "fresh without certificates",
            &fresh,
            spec(MaterializeSource::Fresh {
                public_key: key.openssh_line.clone(),
                certificates: Vec::new(),
            }),
            "no_certificates",
        ),
        (
            "installed key of a grant without a live key",
            &fresh,
            spec(MaterializeSource::InstalledKeyOf {
                grant: other_grant.clone(),
            }),
            heimdall_adapters::managed::effects::NO_LIVE_KEY,
        ),
        (
            "installed key of another live grant than the attached one",
            &data.binding_id,
            spec(MaterializeSource::InstalledKeyOf {
                grant: live_other.clone(),
            }),
            heimdall_adapters::managed::effects::BINDING_GRANT_MISMATCH,
        ),
        (
            "slots-only without the slots",
            &data.binding_id,
            spec(MaterializeSource::SlotsOnly),
            "empty_materialize_spec",
        ),
    ];
    let leader_endpoint = p.registry.binding_endpoint(&data.binding_id);
    for (what, binding, spec, reason) in cases {
        let r = p.effects.materialize(binding, &spec);
        assert!(
            matches!(&r, Err(AdapterError::Protocol(t)) if t == reason),
            "{what}: {r:?}"
        );
        assert!(
            p.registry.binding_endpoint(&fresh).is_none(),
            "{what}: no endpoint created"
        );
        assert!(w.binding_dirs(&fresh).is_empty(), "{what}: no files");
        assert!(
            p.table.binding_grant(&fresh).is_none(),
            "{what}: nothing attached"
        );
        assert_eq!(
            p.table.binding_grant(&data.binding_id).as_ref(),
            Some(&data.grant_id),
            "{what}: the attached binding is untouched"
        );
        assert_eq!(
            p.registry.binding_endpoint(&data.binding_id),
            leader_endpoint
        );
    }
    // The consistent source for the same fresh binding succeeds and reports the
    // endpoint it created.
    let ok = p
        .effects
        .materialize(
            &fresh,
            &spec(MaterializeSource::InstalledKeyOf {
                grant: data.grant_id.clone(),
            }),
        )
        .expect("the consistent source");
    let created = ok.endpoint.expect("created");
    assert_eq!(
        p.registry.binding_endpoint(&fresh).map(|(e, _)| e),
        Some(created)
    );
    p.shutdown.cancel();
}
