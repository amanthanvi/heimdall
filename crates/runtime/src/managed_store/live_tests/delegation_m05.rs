//! ⟨M05, U8⟩ A28 on real loopback `sshd`s: delegation and the narrower binding
//! (ADR-0011 §6; spec §14.3, §14.4; m05-plan U8), live: through the real `Operations`, managed
//! adapter, driver, `ManagedEffectsImpl`, signer table, vault and `EndpointRegistry` of
//! [`super::Live`], and the system `ssh` against two disposable [`LoopbackSshd`]s that trust
//! this run's one fixture CA under **different principal mappings** (`TrustedUserCAKeys`,
//! `AuthorizedPrincipalsFile`): the first admits only `hm:<d1>:<account>`, the second only
//! `hm:<d2>:<account>`.
//!
//! * `a28_child_subset_server_enforced`: the child delegated over one of the parent's two pairs
//!   logs in where its principal is admitted and is refused by the server that trusts the same
//!   CA under the other mapping (spec §14.3 "a worker trying another destination that trusts
//!   the same CA"); the parent's certificate is admitted there (the positive control).
//! * `a28_broader_or_longer_child_refused`: a wider scope and a later deadline are each
//!   `DELEGATION_EXCEEDS_PARENT`, and no child key, certificate or binding is created.
//! * `a28_child_handle_has_no_owner_functions`: what a child's binding ID and endpoint reach.
//! * `a28_parent_end_cascades_child_login_fails`: the parent's revoke, expiry and cutoff each
//!   destroy the child's key, and its next login fails at the server that admitted it before.
//! * `a28_existing_access_child_labelled_convenience`: an existing-access parent's child carries
//!   the convenience labels (`shared_os_user`, `owner_functions: not_delegated`).
//!
//! Every key and the CA are generated per run in scratch directories; the client runs with the
//! scratch home's isolation (its own configuration and known hosts, `HOME`, a decoy agent);
//! nothing of the owner's is read, contacted or changed. A non-root fixture `sshd`
//! authenticates only the current account, so every pair's account is the current account.
//! These tests need a local `sshd` and Unix sockets: Windows has no sshd fixture (the harness's
//! WSL one serves the exit suite, not this in-process harness), so they are `blocked` there.

use super::*;
use heimdall_adapters::managed::files::binding_files_for_endpoint;
use heimdall_contract::request::{
    DeadlineIntent, DelegateRequest, DestinationScopeEnforcement as Scope_, PolicyAction,
    WorkloadIsolation,
};
use heimdall_contract::trust::OwnerFunctions;
use heimdall_domain::issuance::principal_for;
use heimdall_domain::time::Clock as _;
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A pair of destination `dest` for the current account (a non-root fixture `sshd`
/// authenticates only its own account).
fn mine(dest: &str) -> AccessPair {
    pair(dest, &current_account().expect("the current account"))
}

/// One fixture server: its `sshd`, and the alias the scratch client configuration gives it.
struct Host {
    sshd: LoopbackSshd,
    alias: String,
}

/// A certificate, its public key and the endpoint that signs for it, as copied out of a
/// binding's directory while it lives (so a login after the binding ended still names real
/// files: its failure is then the signer's absence, not a missing path).
#[derive(Clone)]
struct Creds {
    locator: String,
    key_pub: std::path::PathBuf,
    cert: std::path::PathBuf,
}

/// The world: a managed runtime process over two own-account pairs and the two servers.
struct World {
    live: Live,
    p: Process,
    home: ScratchHome,
    pairs: [AccessPair; 2],
    hosts: [Host; 2],
    copies: std::cell::Cell<u32>,
}

/// One login attempt's outcome.
struct Login {
    /// The client ran `echo <marker>` on the server.
    ok: bool,
    /// The certified key the server accepted, if it accepted one.
    accepted: Option<String>,
}

impl World {
    async fn new() -> World {
        let pairs = [mine("a28-d1"), mine("a28-d2")];
        let live = Live::seeded(&pairs, Timestamp::now());
        for pr in &pairs {
            // A delegation is never interactive: the aliases are observed `exclusive`.
            live.feed.observe(
                pr.destination.as_str(),
                heimdall_contract::provider::IdentitySelection::Exclusive,
            );
        }
        live.feed.evidence_holds(&pairs);
        let home = ScratchHome::new();
        let mut config = String::new();
        let mut hosts = Vec::new();
        for (i, pr) in pairs.iter().enumerate() {
            let sshd = LoopbackSshd::start(
                home.scratch(),
                SshdConfig {
                    trusted_user_ca_keys: Some(home.root.join(format!("trusted_ca{i}.pub"))),
                    authorized_principals: Some(
                        [(pr.account.as_str().to_owned(), vec![principal_for(pr)])].into(),
                    ),
                    ..SshdConfig::default()
                },
            )
            .unwrap_or_else(|e| panic!("a local fixture sshd is needed: {e}"));
            sshd.trust_user_ca(&live.ca.public_openssh().unwrap())
                .unwrap();
            home.trust_host_key(&sshd.host_key_line).unwrap();
            let alias = format!("hm-a28-host{i}");
            config.push_str(&format!(
                "Host {alias}\n  HostName 127.0.0.1\n  Port {}\n  User {}\n",
                sshd.port,
                pr.account.as_str()
            ));
            hosts.push(Host { sshd, alias });
        }
        home.write_user_config(&config).unwrap();
        let p = live.process(Arc::new(NoStageHook)).await;
        World {
            live,
            p,
            home,
            pairs,
            hosts: <[Host; 2]>::try_from(hosts).ok().unwrap(),
            copies: std::cell::Cell::new(0),
        }
    }

    /// A managed `ensure` of profile `dev` over `scope`.
    async fn ensure(&self, tag: &str, scope: &[AccessPair]) -> EnsureData {
        self.p
            .ops
            .ensure(
                &caller(),
                EnsureRequest {
                    profile: Some(ProfileId::parse("dev").unwrap()),
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
                    context: None,
                    covered_only: false,
                    pair_issuers: Vec::new(),
                },
            )
            .await
            .map(|c| c.data)
            .unwrap_or_else(|e| panic!("ensure {tag}: {} {}", e.code, e.message))
    }

    /// A `delegate` of `parent` over `scope` until `until`, as `who`.
    async fn delegate_as(
        &self,
        who: &Caller,
        tag: &str,
        parent: &BindingId,
        scope: &[AccessPair],
        until: Option<DeadlineIntent>,
    ) -> Result<EnsureData, heimdall_app::OpError> {
        self.p
            .ops
            .delegate(
                who,
                DelegateRequest {
                    parent_binding_id: parent.clone(),
                    scope: scope.iter().cloned().collect(),
                    until,
                    work_id: WorkId::parse(&format!("w-{tag}")).unwrap(),
                    request_id: RequestId::parse(&format!("r-{tag}")).unwrap(),
                    required_capabilities: RequiredCapabilities::default(),
                },
            )
            .await
            .map(|c| c.data)
    }

    async fn delegate(
        &self,
        tag: &str,
        parent: &BindingId,
        scope: &[AccessPair],
    ) -> Result<EnsureData, heimdall_app::OpError> {
        self.delegate_as(&caller(), tag, parent, scope, None).await
    }

    /// The binding endpoint of `binding` and its files for `pr`, copied to scratch.
    fn creds(&self, binding: &BindingId, pr: &AccessPair) -> Creds {
        let (endpoint, _) = self
            .p
            .registry
            .binding_endpoint(binding)
            .expect("the binding endpoint runs");
        let files = binding_files_for_endpoint(
            &self.live.run_dir(),
            &endpoint,
            std::slice::from_ref(&pr.destination),
        )
        .expect("the binding files beside the endpoint");
        let n = self.copies.get();
        self.copies.set(n + 1);
        let dir = self.home.scratch().subdir(&format!("creds{n}-")).unwrap();
        let key_pub = dir.join("key.pub");
        let cert = dir.join("cert.pub");
        std::fs::copy(&files.key_pub, &key_pub).unwrap();
        std::fs::copy(files.certificate(&pr.destination).unwrap(), &cert).unwrap();
        Creds {
            locator: endpoint.locator,
            key_pub,
            cert,
        }
    }

    /// The system `ssh` to host `host` through `creds` (the managed identity options
    /// `connect` renders: `IdentityAgent=<endpoint>`, `IdentitiesOnly=yes`, the certificate
    /// as the identity file), running `echo <marker>`.
    async fn login(&self, host: usize, creds: &Creds, marker: &str) -> Login {
        use heimdall_sshconf::render::{
            ManagedIdentityForm, PathStyle, RenderPath, managed_identity_options,
        };
        let h = &self.hosts[host];
        let before = h.sshd.accepted_certificates().len();
        let options = managed_identity_options(
            &RenderPath::unix(std::path::Path::new(&creds.locator)).unwrap(),
            &RenderPath::unix(&creds.key_pub).unwrap(),
            &RenderPath::unix(&creds.cert).unwrap(),
            PathStyle::Unix,
            ManagedIdentityForm::select(None),
        )
        .unwrap();
        let mut cmd = std::process::Command::new(find_program("ssh").expect("ssh"));
        cmd.args(self.home.isolation_args())
            .args(&options)
            .args(["-o", "PreferredAuthentications=publickey"])
            .arg(&h.alias)
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
        let accepted = h.sshd.accepted_certificates();
        Login {
            ok: out.status.success() && String::from_utf8_lossy(&out.stdout).contains(marker),
            accepted: (accepted.len() > before)
                .then(|| accepted.last().map(|a| a.fingerprint.clone()))
                .flatten(),
        }
    }

    fn state(&self, grant: &GrantId) -> GrantState {
        self.live
            .store
            .transaction(|tx| tx.grant(grant))
            .unwrap()
            .unwrap()
            .state
    }

    /// The grant's key is gone and its endpoint no longer answers.
    async fn assert_destroyed(&self, grant: &GrantId, locator: &str) {
        assert!(self.p.table.public_key(grant).is_none(), "K_env destroyed");
        assert!(gone(locator).await, "the endpoint stopped answering");
    }

    /// A parent over both pairs and a child over the first, with the copied credentials of
    /// the parent's pair 1 and the child's: logged in once each, before anything ends.
    async fn parent_and_child(&self, tag: &str) -> (EnsureData, EnsureData, Creds, Creds) {
        let parent = self.ensure(tag, &self.pairs).await;
        let child = self
            .delegate(
                &format!("{tag}-child"),
                &parent.binding_id,
                &self.pairs[..1],
            )
            .await
            .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason));
        let parent_creds = self.creds(&parent.binding_id, &self.pairs[0]);
        let child_creds = self.creds(&child.binding_id, &self.pairs[0]);
        let login = self.login(0, &child_creds, "child-before").await;
        assert!(login.ok, "the child logs in before the parent ends");
        assert_eq!(
            login.accepted,
            Some(
                self.p
                    .table
                    .public_key(&child.grant_id)
                    .unwrap()
                    .fingerprint
            )
        );
        (parent, child, parent_creds, child_creds)
    }
}

/// §14.3 / ADR-0011 §6.1: the child's certificate is refused by a second server that trusts
/// the same CA under a different principal mapping; the parent's is admitted there.
#[tokio::test]
async fn a28_child_subset_server_enforced() {
    let w = World::new().await;
    let parent = w.ensure("sub", &w.pairs).await;
    let child = w
        .delegate("sub-child", &parent.binding_id, &w.pairs[..1])
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason));
    assert_ne!(child.grant_id, parent.grant_id, "the child's own grant");
    assert_ne!(
        w.p.table.public_key(&child.grant_id).unwrap().fingerprint,
        w.p.table.public_key(&parent.grant_id).unwrap().fingerprint,
        "its own key"
    );
    // The child's endpoint lists exactly its one pair's certificate; the parent's both.
    let (child_ep, _) = w.p.registry.binding_endpoint(&child.binding_id).unwrap();
    let (parent_ep, _) = w.p.registry.binding_endpoint(&parent.binding_id).unwrap();
    assert_eq!(listed(&child_ep.locator).await.unwrap(), 1);
    assert_eq!(listed(&parent_ep.locator).await.unwrap(), 2);
    // ADR-0011 §6.3: the child of a managed parent with verified pairs.
    assert_eq!(
        parent.enforcement.destination_scope,
        Scope_::VerifiedServerPrincipals
    );
    assert_eq!(
        parent.enforcement.owner_functions, None,
        "a parent result is unlabelled"
    );
    assert_eq!(
        child.enforcement.destination_scope,
        Scope_::VerifiedServerPrincipals
    );
    assert_eq!(
        child.enforcement.workload_isolation,
        WorkloadIsolation::SharedOsUser
    );
    assert_eq!(
        child.enforcement.owner_functions,
        Some(OwnerFunctions::NotDelegated)
    );

    let child_creds = w.creds(&child.binding_id, &w.pairs[0]);
    let parent_first = w.creds(&parent.binding_id, &w.pairs[0]);
    let parent_second = w.creds(&parent.binding_id, &w.pairs[1]);
    let child_key = w.p.table.public_key(&child.grant_id).unwrap().fingerprint;
    let parent_key = w.p.table.public_key(&parent.grant_id).unwrap().fingerprint;

    // Positive controls: each certificate is admitted where its principal is mapped, so a
    // refusal below is the server's principal mapping and nothing else (same CA, same
    // account, same client).
    let login = w.login(0, &child_creds, "child-first").await;
    assert!(login.ok, "the child logs in at the first server");
    assert_eq!(login.accepted.as_deref(), Some(child_key.as_str()));
    let login = w.login(1, &parent_second, "parent-second").await;
    assert!(
        login.ok,
        "the parent's certificate is admitted at the second server"
    );
    assert_eq!(login.accepted.as_deref(), Some(parent_key.as_str()));
    let login = w.login(0, &parent_first, "parent-first").await;
    assert!(login.ok, "and at the first");

    // The scope proof: the child's only certificate (its pair's principal) is refused by
    // the server that trusts the same CA under the other mapping.
    let accepted_before = w.hosts[1].sshd.accepted_certificates().len();
    let login = w.login(1, &child_creds, "child-second").await;
    assert!(!login.ok, "the child is refused at the second server");
    assert_eq!(login.accepted, None);
    assert_eq!(
        w.hosts[1].sshd.accepted_certificates().len(),
        accepted_before,
        "the second server accepted nothing of the child's"
    );
    w.p.shutdown.cancel();
}

/// ADR-0011 §6.1, spec §14.3 "a child asking for a later deadline": a wider scope and a later
/// deadline are each `DELEGATION_EXCEEDS_PARENT`, and nothing of a child is created; the
/// boundary itself (a subset, an earlier deadline) is admitted.
#[tokio::test]
async fn a28_broader_or_longer_child_refused() {
    let w = World::new().await;
    // The parent holds the first pair only; the second is in the profile, so the child's
    // request for it is wider than the parent, not outside the profile.
    let parent = w.ensure("wide", &w.pairs[..1]).await;
    let refs_before = w
        .live
        .store
        .transaction(|tx| tx.grant_references(&parent.grant_id))
        .unwrap();
    assert_eq!(refs_before.len(), 1, "only the parent's own reference");
    let keys_before = w.p.table.vault().len();
    let dirs_before = std::fs::read_dir(w.live.run_dir()).unwrap().count();

    let wider = w
        .delegate("wide-scope", &parent.binding_id, &w.pairs)
        .await
        .expect_err("a pair the parent does not hold");
    assert_eq!(
        wider.code,
        Code::DelegationExceedsParent,
        "{}",
        wider.message
    );
    let later = Timestamp::from_second(parent.expires_at.as_second() + 3600).unwrap();
    let longer = w
        .delegate_as(
            &caller(),
            "wide-until",
            &parent.binding_id,
            &w.pairs[..1],
            Some(DeadlineIntent::Absolute(later.to_string())),
        )
        .await
        .expect_err("a deadline later than the parent's");
    assert_eq!(
        longer.code,
        Code::DelegationExceedsParent,
        "{}",
        longer.message
    );

    // Nothing was created: no key, no endpoint or file, no reference on the parent's grant,
    // no binding under either refused operation.
    assert_eq!(w.p.table.vault().len(), keys_before, "no child key");
    assert_eq!(
        std::fs::read_dir(w.live.run_dir()).unwrap().count(),
        dirs_before,
        "no child endpoint or binding directory"
    );
    assert_eq!(
        w.live
            .store
            .transaction(|tx| tx.grant_references(&parent.grant_id))
            .unwrap(),
        refs_before,
        "no child reference"
    );
    let live_grants: Vec<GrantId> = w
        .live
        .store
        .transaction(|tx| tx.grants_due(Timestamp::MAX))
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(
        &live_grants,
        std::slice::from_ref(&parent.grant_id),
        "no child grant"
    );
    for refused in [&wider, &longer] {
        let op = refused.operation_id.clone().expect("a journaled refusal");
        let state = w
            .live
            .store
            .transaction(|tx| tx.operation(&op))
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, heimdall_contract::OperationState::Failed);
    }

    // The boundary: the same pair and an earlier deadline are admitted, and the child ends
    // no later than the parent.
    let earlier = Timestamp::from_second(parent.expires_at.as_second() - 600).unwrap();
    let child = w
        .delegate_as(
            &caller(),
            "wide-ok",
            &parent.binding_id,
            &w.pairs[..1],
            Some(DeadlineIntent::Absolute(earlier.to_string())),
        )
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason));
    assert!(child.expires_at <= parent.expires_at);
    assert_eq!(child.expires_at, earlier);
    w.p.shutdown.cancel();
}

/// ADR-0011 §6.2 (R-RT-03; spec §11.2): what a child's binding ID and signing endpoint reach.
///
/// * The endpoint answers the agent protocol's identity listing and signing only. A control
///   frame (a real control `hello`), an agent `add identity` and an agent extension are each
///   answered `SSH_AGENT_FAILURE`, the connection stays usable, and the store gains no
///   operation, decision or binding.
/// * A binding ID is a reference, not a bearer credential: a foreign limited caller that
///   names the child's binding gets `NOT_FOUND` from `delegate`, and neither `decide` nor a
///   policy action is open to it. A pending widening decision stays pending.
/// * The child's own `delegate` can only narrow further: wider is
///   `DELEGATION_EXCEEDS_PARENT`, narrower is admitted.
#[tokio::test]
async fn a28_child_handle_has_no_owner_functions() {
    let w = World::new().await;
    let parent = w.ensure("own", &w.pairs).await;
    let child = w
        .delegate("own-child", &parent.binding_id, &w.pairs[..1])
        .await
        .unwrap();
    let (endpoint, _) = w.p.registry.binding_endpoint(&child.binding_id).unwrap();
    let ledger = |w: &World| {
        w.live
            .store
            .transaction(|tx| {
                Ok((
                    tx.pending_decisions()?.len(),
                    tx.grant_references(&parent.grant_id)?.len(),
                    tx.cleanup_intents()?.len(),
                ))
            })
            .unwrap()
    };
    let before = ledger(&w);

    // 1. Frames the endpoint must refuse, on one connection, then a listing on the same one.
    let hello = heimdall_contract::ipc::ClientMessage::Hello(heimdall_contract::ipc::ClientHello {
        protocol: heimdall_contract::PROTOCOL_VERSION,
        schema_version: heimdall_contract::SchemaVersion::current(),
        client: heimdall_contract::ipc::PeerInfo {
            name: "child".into(),
            version: "0".into(),
        },
        capabilities: heimdall_ipc::session::server_capabilities(),
        required: Default::default(),
        interaction: InteractionMode::NonInteractive,
        remote_client: None,
    });
    let control =
        heimdall_ipc::frame::encode_frame(&hello, heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES)
            .unwrap();
    let framed = |body: &[u8]| {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    };
    let mut input = control;
    // Add identity (17): an issuance request in agent clothing; never parsed as a key.
    input.extend(framed(&[
        17, 0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a',
    ]));
    // An agent extension (27) naming a Heimdall-looking operation.
    let mut extension = vec![27, 0, 0, 0, 8];
    extension.extend_from_slice(b"issue@hm");
    input.extend(framed(&extension));
    input.extend(framed(&[11]));
    let mut stream = tokio::net::UnixStream::connect(&endpoint.locator)
        .await
        .unwrap();
    stream.write_all(&input).await.unwrap();
    // Three `SSH_AGENT_FAILURE`s (one-byte bodies), then the identities answer (type 12)
    // listing exactly the child's one identity.
    let mut next_frame = async || {
        let mut len = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len))
            .await
            .expect("the endpoint answers")
            .expect("the connection stayed usable");
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).await.unwrap();
        body
    };
    for f in 0..3 {
        assert_eq!(next_frame().await, [5], "frame {f} is SSH_AGENT_FAILURE");
    }
    let listing = next_frame().await;
    assert_eq!(listing[0], 12, "then the identities answer");
    assert_eq!(
        u32::from_be_bytes(listing[1..5].try_into().unwrap()),
        1,
        "exactly the child's one identity"
    );
    drop(stream);
    assert_eq!(ledger(&w), before, "the frames created and changed nothing");

    // 2. A binding ID is a reference. A foreign limited caller (another principal) naming
    // the child's binding has nothing from `delegate`, `policy` or `decide`.
    let foreign = Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 777 },
            role: ClientRole::LimitedConsumer,
            remote_client: None,
        },
        attendance: heimdall_app::Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    };
    let e = w
        .delegate_as(
            &foreign,
            "own-foreign",
            &child.binding_id,
            &w.pairs[..1],
            None,
        )
        .await
        .expect_err("a foreign caller cannot delegate from the child's binding");
    assert_eq!(e.code, Code::NotFound, "{}", e.message);
    let policy_id = PolicyId::parse("pol").unwrap();
    let e =
        w.p.ops
            .policy(
                &foreign,
                PolicyAction::Pause {
                    policy_id: Some(policy_id.clone()),
                    target: None,
                },
            )
            .await
            .expect_err("no policy change by a limited caller");
    assert_eq!(e.code, Code::CapabilityUnavailable, "{}", e.message);
    // A real pending decision (a widening the owner has not approved) that the limited
    // caller tries to approve, attended or not.
    // A first cutoff narrows (applied); a later one widens (a decision).
    w.p.ops
        .policy(
            &caller(),
            PolicyAction::Cutoff {
                policy_id: Some(policy_id.clone()),
                at: Timestamp::from_second(Timestamp::now().as_second() + 86_400).unwrap(),
                target: None,
            },
        )
        .await
        .unwrap();
    let widening =
        w.p.ops
            .policy(
                &caller(),
                PolicyAction::Cutoff {
                    policy_id: Some(policy_id.clone()),
                    at: Timestamp::from_second(Timestamp::now().as_second() + 2 * 86_400).unwrap(),
                    target: None,
                },
            )
            .await
            .expect_err("moving a cutoff later is widening: a decision, never executed");
    let decision = widening
        .next
        .decision_ref
        .clone()
        .expect("a pending decision");
    let decision = heimdall_contract::ids::DecisionId::parse(&decision).unwrap();
    for who in [&foreign, &caller()] {
        let e =
            w.p.ops
                .decide(
                    who,
                    heimdall_contract::request::DecideRequest {
                        decision_id: decision.clone(),
                        verdict: heimdall_contract::request::Verdict::Approve,
                    },
                )
                .await
                .expect_err("no decision is approved by a child-side caller");
        assert!(
            matches!(
                e.code,
                Code::CapabilityUnavailable | Code::InteractionRequired
            ),
            "{} {}",
            e.code,
            e.message
        );
    }
    let state = w
        .live
        .store
        .transaction(|tx| tx.decision(&decision))
        .unwrap()
        .unwrap()
        .state;
    assert_eq!(state, heimdall_domain::decision::DecisionState::Pending);

    // 3. The child's own `delegate` can only narrow further (as the child's owner principal
    // with a limited role, the strongest thing holding the child's handle gives).
    let child_side = Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::LimitedConsumer,
        remote_client: None,
    });
    let e = w
        .delegate_as(&child_side, "own-wider", &child.binding_id, &w.pairs, None)
        .await
        .expect_err("a grandchild cannot be wider than the child");
    assert_eq!(e.code, Code::DelegationExceedsParent, "{}", e.message);
    let grandchild = w
        .delegate_as(
            &child_side,
            "own-same",
            &child.binding_id,
            &w.pairs[..1],
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason));
    assert!(grandchild.expires_at <= child.expires_at);
    assert_eq!(
        grandchild.enforcement.owner_functions,
        Some(OwnerFunctions::NotDelegated)
    );
    w.p.shutdown.cancel();
}

/// ADR-0011 §6.1 (the expiry proof), §7: the parent's end destroys the child's key, after
/// which the child's next login fails at the server that admitted it before. By revoke, by
/// expiry and by a cutoff on the parent's policy.
#[tokio::test]
async fn a28_parent_end_cascades_child_login_fails() {
    for how in ["revoke", "expiry", "cutoff"] {
        let w = World::new().await;
        let (parent, child, parent_creds, child_creds) = w.parent_and_child(how).await;
        let login = w.login(0, &parent_creds, "parent-before").await;
        assert!(login.ok, "{how}: the parent logs in before it ends");
        match how {
            "revoke" => {
                w.p.ops
                    .revoke(
                        &caller(),
                        RevokeRequest {
                            grant_id: Some(parent.grant_id.clone()),
                            request_id: RequestId::parse("rv-cascade").unwrap(),
                            target: None,
                        },
                    )
                    .await
                    .unwrap_or_else(|e| panic!("revoke: {} {}", e.code, e.message));
                // `revoking` until the certificates' own expiry bounds the remote side
                // (the tombstone and the destroyed key are immediate).
                for (who, grant) in [("parent", &parent.grant_id), ("child", &child.grant_id)] {
                    assert!(
                        matches!(w.state(grant), GrantState::Revoking | GrantState::Revoked),
                        "{who}: the revoke cascades"
                    );
                }
            }
            "expiry" => {
                w.live.clock.advance(3 * HOUR);
                w.p.ops.tick().await.unwrap();
                assert_eq!(w.state(&parent.grant_id), GrantState::Expired);
                assert_eq!(w.state(&child.grant_id), GrantState::Expired);
            }
            _ => {
                let at = Timestamp::from_second(w.live.clock.wall().as_second() + 600).unwrap();
                w.p.ops
                    .policy(
                        &caller(),
                        PolicyAction::Cutoff {
                            policy_id: Some(PolicyId::parse("pol").unwrap()),
                            at,
                            target: None,
                        },
                    )
                    .await
                    .unwrap_or_else(|e| panic!("cutoff: {} {}", e.code, e.message));
                w.live.clock.advance(Duration::from_secs(660));
                w.p.ops.tick().await.unwrap();
                assert_eq!(w.state(&parent.grant_id), GrantState::Expired);
                assert_eq!(w.state(&child.grant_id), GrantState::Expired);
            }
        }
        w.assert_destroyed(&child.grant_id, &child_creds.locator)
            .await;
        w.assert_destroyed(&parent.grant_id, &parent_creds.locator)
            .await;
        assert_eq!(w.p.table.vault().len(), 0, "{how}: no key is left");
        // The certificate and key files are still as the child had them, and still inside
        // their validity at the server's clock: only the signer is missing.
        let accepted_before = w.hosts[0].sshd.accepted_certificates().len();
        let login = w.login(0, &child_creds, "child-after").await;
        assert!(!login.ok, "{how}: the child's next login fails");
        assert_eq!(login.accepted, None, "{how}");
        assert_eq!(
            w.hosts[0].sshd.accepted_certificates().len(),
            accepted_before,
            "{how}: the server that admitted it before accepts nothing now"
        );
        let login = w.login(0, &parent_creds, "parent-after").await;
        assert!(!login.ok, "{how}: nor does the parent's");
        w.p.shutdown.cancel();
    }
}

/// The native-agent adapter's integration sources for [`a28_existing_access_child_labelled_convenience`]:
/// the one alias's observation, its identity and the identity's live declaration.
struct ExistingSources {
    feed: Arc<LiveFeed>,
    identity: heimdall_domain::catalog::IdentityRecord,
    declaration: heimdall_domain::catalog::InteractionDeclaration,
}

impl heimdall_adapters::integration::IntegrationSources for ExistingSources {
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
        let observed = self.feed.observations.lock().unwrap();
        aliases
            .iter()
            .filter_map(|a| observed.get(a).cloned())
            .collect()
    }

    fn catalog_identities(&self) -> Vec<heimdall_domain::catalog::IdentityRecord> {
        vec![self.identity.clone()]
    }

    fn declaration(
        &self,
        identity: &IdentityId,
    ) -> Option<heimdall_domain::catalog::InteractionDeclaration> {
        (*identity == self.identity.id).then(|| self.declaration.clone())
    }
}

/// ADR-0011 §6.3 row 3, spec §14.4: a child of an **existing-access** parent is labelled what
/// it is: a convenience (client routing, `shared_os_user`), never isolation, and
/// `owner_functions: not_delegated`. The parent's own result stays unlabelled.
#[tokio::test]
async fn a28_existing_access_child_labelled_convenience() {
    use heimdall_adapters::native_agent::NativeAgentAdapter;
    use heimdall_domain::catalog::{
        DeclarationState, IdentityRecord, IdentitySource, InteractionDeclaration,
        InteractionProfile,
    };
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};

    // A disposable fake agent in scratch: the adapter only stats its endpoint.
    let key = FixtureKey::generate();
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    let at = Endpoint::in_scratch(&scratch, "agent").unwrap();
    let _agent = FakeAgent::start(
        at.clone(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    );
    let endpoint = EndpointRef {
        kind: heimdall_contract::provider::EndpointKind::UnixSocket,
        locator: at.locator().to_str().unwrap().to_owned(),
    };
    let pr = pair("a28-ea", "deploy");
    let w = Live::seeded(std::slice::from_ref(&pr), Timestamp::now());
    let now = w.clock.wall();
    // Existing access: an adopted native-agent identity with a live `none` declaration (so
    // a delegation, which is never interactive, is eligible), its alias observed
    // `exclusive`, the pair's preference `existing`; the native-agent adapter is the only
    // one configured.
    let source = IdentitySource::NativeAgent {
        endpoint: endpoint.clone(),
    };
    let public_key = key.public_line_without_comment();
    let identity = IdentityRecord {
        id: IdentityId::from_random_bytes([2; 16]),
        revision: 1,
        interaction: InteractionProfile::default_for(&source, &public_key),
        source,
        public_key,
        fingerprint: key.fingerprint(),
        label: None,
        adopted_at: now,
        updated_at: now,
    };
    let declaration = InteractionDeclaration {
        revision: 1,
        state: DeclarationState::Live,
        interaction: heimdall_contract::catalog::DeclaredInteraction::None,
        fingerprint: identity.fingerprint.clone(),
        endpoint: endpoint.clone(),
        declared_at: Timestamp::from_second(now.as_second() - 60).unwrap(),
        expires_at: Timestamp::from_second(now.as_second() + 3600).unwrap(),
        decision: heimdall_contract::ids::DecisionId::from_random_bytes([3; 16]),
        ended_at: None,
        end_reason: None,
    };
    w.feed.observe(
        pr.destination.as_str(),
        heimdall_contract::provider::IdentitySelection::Exclusive,
    );
    w.store
        .transaction(|tx| {
            tx.upsert_identity(&identity)?;
            tx.upsert_destination(&DestinationRecord {
                id: pr.destination.clone(),
                alias: pr.destination.as_str().into(),
                revision: 2,
                definition: DestinationDefinition::Managed {
                    hostname: "a28-ea.example.invalid".into(),
                    port: None,
                    account: pr.account.clone(),
                    identity: identity.id.clone(),
                    jump: None,
                },
                label: None,
                updated_at: now,
            })?;
            tx.put_interaction_declaration(&identity.id, 0, &declaration)?;
            tx.set_pair_preference(
                &PairPreference {
                    destination: pr.destination.clone(),
                    account: pr.account.clone(),
                    mechanism: PreferredMechanism::Existing,
                    projection: ProjectionStatus::Applied { generation: 1 },
                    issuing_cas: Default::default(),
                },
                now,
            )
        })
        .unwrap();
    let sources = Arc::new(ExistingSources {
        feed: w.feed.clone(),
        identity: identity.clone(),
        declaration,
    });
    let ops = Operations::start(OperationsConfig {
        store: w.store.clone(),
        clock: w.clock.clone(),
        time_sync: w.sync.clone(),
        time_policy: TimePolicy::default(),
        environment: env(),
        adapters: vec![Arc::new(
            NativeAgentAdapter::new("m05-ea".into(), Some(endpoint)).with_sources(sources),
        ) as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    let interactive = Caller {
        interaction: InteractionMode::Interactive,
        ..caller()
    };
    let parent = ops
        .ensure(
            &interactive,
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: [pr.clone()].into_iter().collect(),
                environment: None,
                work_id: WorkId::parse("w-ea").unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse("r-ea").unwrap(),
                interaction: InteractionMode::Interactive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
                context: None,
                covered_only: false,
                pair_issuers: Vec::new(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {} {:?}", e.code, e.message, e.reason))
        .data;
    assert_eq!(parent.credential_mechanism, "native_agent");
    assert_eq!(
        parent.enforcement.owner_functions, None,
        "a parent result is unlabelled"
    );
    let child = ops
        .delegate(
            &caller(),
            DelegateRequest {
                parent_binding_id: parent.binding_id.clone(),
                scope: [pr.clone()].into_iter().collect(),
                until: None,
                work_id: WorkId::parse("w-ea-child").unwrap(),
                request_id: RequestId::parse("r-ea-child").unwrap(),
                required_capabilities: RequiredCapabilities::default(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("delegate: {} {} {:?}", e.code, e.message, e.reason))
        .data;
    assert_eq!(child.credential_mechanism, "native_agent");
    let report = &child.enforcement;
    assert!(
        matches!(
            report.destination_scope,
            Scope_::ClientRouting | Scope_::UnenforcedIntent
        ),
        "convenience, not server enforcement: {:?}",
        report.destination_scope
    );
    assert_eq!(report.workload_isolation, WorkloadIsolation::SharedOsUser);
    assert_eq!(report.owner_functions, Some(OwnerFunctions::NotDelegated));
    // The stored report (what `inspect` and a restart read) carries the same labels.
    let stored = w
        .store
        .transaction(|tx| tx.grant(&child.grant_id))
        .unwrap()
        .unwrap()
        .enforcement
        .report;
    assert_eq!(stored.workload_isolation, WorkloadIsolation::SharedOsUser);
    assert_eq!(stored.owner_functions, Some(OwnerFunctions::NotDelegated));
    let stored_parent = w
        .store
        .transaction(|tx| tx.grant(&parent.grant_id))
        .unwrap()
        .unwrap()
        .enforcement
        .report;
    assert_eq!(stored_parent.owner_functions, None);
}
