//! Existing-access adapters at fixture level (m02-plan U6 "Tests"; A11, A35;
//! ADR-0007 §7).
//!
//! Cargo test target `integration_adapters` hosted by `heimdall-adapters` (review F09
//! convention). Every agent is a disposable fixture from `heimdall-testkit` (U7): the
//! in-process `FakeAgent` (keys generated in memory per run, comments are per-run
//! `HEIMDALL_CANARY_*` strings) and, on Unix, a real `DisposableSshAgent`
//! (`ssh-agent -D -a <scratch>/agent.sock` with a scratch `HOME`, stopped by exact
//! PID). Every endpoint is in a scratch directory this test creates; the owner's
//! `~/.ssh`, agents, keychains and configuration are never read or contacted, and no
//! test reads `SSH_AUTH_SOCK` from the process environment.
//!
//! Static identity selections are given through a test `IntegrationSources` (the
//! projection writer's `observe` is U4's; the selection rules are U2's): these tests
//! check what the adapters do with a selection, not how one is computed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use heimdall_adapters::integration::{
    IntegrationSources, Prepared, SSH_AUTH_SOCK, descriptor_enforcement,
};
use heimdall_adapters::native_agent::NativeAgentAdapter;
use heimdall_adapters::onepassword::OnePasswordAdapter;
use heimdall_adapters::state::{self, PROVIDER_RESOURCE, PairReadiness, Refusal};
use heimdall_app::OpError;
use heimdall_app::ports::{
    AdapterError, CredentialAdapter, DetectContext, IdentityListing, InteractionRequirement,
    LockContinuity, PreparePair, PrepareRequest, ProbeBounds, ProviderProbe, ReconcileOutcome,
};
use heimdall_contract::catalog::DeclaredInteraction;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{
    AliasDefinition, AliasObservation, ConfigProvenance, DirectiveCertainty, DirectiveObservation,
};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, EnvironmentId, GrantId, IdentityId,
};
use heimdall_contract::provider::{
    Certainty, CredentialAvailability, EndpointKind, EndpointRef, EvidenceBasis, IdentitiesOnly,
    IdentityBacking, IdentityEntry, IdentityEntryKind, IdentityEntrySource, IdentitySelection,
    IdentitySelectionReport, InteractionKind, ProviderAvailability, ProviderInteractionRef,
    ProviderKind,
};
use heimdall_contract::request::{
    ConsumerKind, ConsumerOverride, DeadlineIntent, DestinationScopeEnforcement,
    ExistingConnectionsPolicy, NewAuthenticationExpiry, OverrideSource, RefreshDependency,
    RequiredCapabilities, RevocationStatus, WorkloadIsolation,
};
use heimdall_contract::{GrantState, Timestamp};
use heimdall_domain::catalog::{
    DeclarationEndReason, DeclarationState, IdentityRecord, IdentitySource, InteractionDeclaration,
    InteractionProfile, PreparedFacts,
};
use heimdall_domain::evidence::{EnforcementEvidence, SupportLabel};
use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
use heimdall_domain::policy::{AuthorityGeneration, PolicyRevision};
use heimdall_domain::scope::Scope;
use heimdall_domain::time::Deadline;
use heimdall_testkit::agent::{
    AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey, StallPoint, msg,
};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::home::Scratch;

// --- fixtures -------------------------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-01T12:00:00Z".parse().unwrap()
}

fn at(seconds: i64) -> Timestamp {
    let d = Duration::from_secs(seconds.unsigned_abs());
    if seconds >= 0 {
        t0().checked_add(d).unwrap()
    } else {
        t0().checked_sub(d).unwrap()
    }
}

fn grant() -> GrantSnapshot {
    GrantSnapshot {
        id: GrantId::from_random_bytes([1; 16]),
        environment: EnvironmentId::from_random_bytes([2; 16]),
        scope: Scope::empty(),
        starts_at: t0(),
        deadline: Deadline {
            intent: DeadlineIntent::Duration("PT1H".into()),
            resolved_at: t0(),
            effective: at(3600),
        },
        parent: None,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(1),
        state: GrantState::Preparing,
        enforcement: EnforcementEvidence::unknown(),
    }
}

fn required(unattended: bool) -> RequiredCapabilities {
    RequiredCapabilities {
        unattended,
        ..RequiredCapabilities::default()
    }
}

fn endpoint_ref(e: &Endpoint) -> EndpointRef {
    match e {
        Endpoint::UnixSocket(p) => EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: p.to_str().unwrap().to_owned(),
        },
        Endpoint::NamedPipe(n) => EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: n.clone(),
        },
    }
}

/// A scratch directory and a fake agent in it holding `keys`.
struct Fixture {
    _scratch: Scratch,
    agent: FakeAgent,
    endpoint: EndpointRef,
}

fn fake(mode: AgentMode, keys: Vec<FixtureKey>) -> Fixture {
    let scratch = Scratch::new().unwrap();
    let endpoint = Endpoint::in_scratch(&scratch, "agent").unwrap();
    let agent = FakeAgent::start(endpoint.clone(), FakeAgentConfig { keys, mode });
    Fixture {
        endpoint: endpoint_ref(&endpoint),
        _scratch: scratch,
        agent,
    }
}

fn identity(
    n: u8,
    source: IdentitySource,
    public_key: String,
    fingerprint: String,
) -> IdentityRecord {
    IdentityRecord {
        id: IdentityId::from_random_bytes([n; 16]),
        revision: 1,
        interaction: InteractionProfile::default_for(&source, &public_key),
        source,
        public_key,
        fingerprint,
        label: None,
        adopted_at: at(-86_400),
        updated_at: at(-86_400),
    }
}

fn native_identity(n: u8, key: &FixtureKey, endpoint: &EndpointRef) -> IdentityRecord {
    identity(
        n,
        IdentitySource::NativeAgent {
            endpoint: endpoint.clone(),
        },
        key.public_line_without_comment(),
        key.fingerprint(),
    )
}

fn op_identity(n: u8, key: &FixtureKey, endpoint: &EndpointRef) -> IdentityRecord {
    identity(
        n,
        IdentitySource::OnePassword {
            endpoint: Some(endpoint.clone()),
        },
        key.public_line_without_comment(),
        key.fingerprint(),
    )
}

fn declaration(
    id: &IdentityRecord,
    endpoint: &EndpointRef,
    expires_at: Timestamp,
) -> InteractionDeclaration {
    InteractionDeclaration {
        revision: 3,
        state: DeclarationState::Live,
        interaction: DeclaredInteraction::None,
        fingerprint: id.fingerprint.clone(),
        endpoint: endpoint.clone(),
        declared_at: at(-3600),
        expires_at,
        decision: DecisionId::from_random_bytes([9; 16]),
        ended_at: None,
        end_reason: None,
    }
}

fn pair(destination: &str, identity: &IdentityRecord, alias: Option<&str>) -> PreparePair {
    PreparePair {
        destination: DestinationId::parse(destination).unwrap(),
        account: AccountName::parse("deploy").unwrap(),
        identity: identity.clone(),
        alias: alias.map(str::to_owned),
    }
}

fn provenance(file: &str, line: u32) -> ConfigProvenance {
    ConfigProvenance {
        path_display: file.to_owned(),
        line,
    }
}

fn entry(
    source: IdentityEntrySource,
    fingerprint: Option<String>,
    backing: IdentityBacking,
) -> IdentityEntry {
    IdentityEntry {
        kind: IdentityEntryKind::IdentityFile,
        source,
        provenance: Some(provenance(
            if source == IdentityEntrySource::Managed {
                "~/.config/heimdall/ssh/heimdall.conf"
            } else {
                "~/.ssh/config"
            },
            4,
        )),
        certainty: Certainty::Determined,
        fingerprint,
        backing,
        cleared: None,
    }
}

fn exclusive(fingerprint: &str) -> IdentitySelectionReport {
    IdentitySelectionReport {
        selection: IdentitySelection::Exclusive,
        entries: vec![entry(
            IdentityEntrySource::Managed,
            Some(fingerprint.to_owned()),
            IdentityBacking::Agent,
        )],
        identities_only: IdentitiesOnly::DeterminedYes,
    }
}

fn observation(alias: &str, report: IdentitySelectionReport) -> AliasObservation {
    AliasObservation {
        alias: alias.to_owned(),
        definition: AliasDefinition::Managed,
        behavior: Vec::new(),
        identity_selection: Some(report),
    }
}

/// The test's `IntegrationSources`: fixed observations, catalog and declarations.
#[derive(Default)]
struct Sources {
    observations: Vec<AliasObservation>,
    identities: Vec<IdentityRecord>,
    declarations: BTreeMap<IdentityId, InteractionDeclaration>,
    asked: Mutex<Vec<Vec<String>>>,
}

impl IntegrationSources for Sources {
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
        self.asked.lock().unwrap().push(aliases.to_vec());
        self.observations
            .iter()
            .filter(|o| aliases.contains(&o.alias))
            .cloned()
            .collect()
    }

    fn catalog_identities(&self) -> Vec<IdentityRecord> {
        self.identities.clone()
    }

    fn declaration(&self, identity: &IdentityId) -> Option<InteractionDeclaration> {
        self.declarations.get(identity).cloned()
    }
}

fn native(endpoint: &EndpointRef, sources: Sources) -> NativeAgentAdapter {
    NativeAgentAdapter::new("u6".into(), Some(endpoint.clone())).with_sources(Arc::new(sources))
}

fn onepassword(endpoint: &EndpointRef, sources: Sources) -> OnePasswordAdapter {
    OnePasswordAdapter::new("u6".into(), Some(endpoint.clone())).with_sources(Arc::new(sources))
}

/// Prepare through the detailed entry point, with `now` = t0.
fn prepare_native(
    adapter: &NativeAgentAdapter,
    pairs: &[PreparePair],
    interactive: bool,
    now: Timestamp,
) -> Result<Prepared, AdapterError> {
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    adapter.prepare_detailed(&PrepareRequest {
        grant: &g,
        scope: &scope,
        required: &req,
        interactive,
        effect_token: "tok-1",
        now,
        pairs,
    })
}

fn request<'a>(
    g: &'a GrantSnapshot,
    scope: &'a Scope,
    req: &'a RequiredCapabilities,
    interactive: bool,
    token: &'a str,
    pairs: &'a [PreparePair],
) -> PrepareRequest<'a> {
    PrepareRequest {
        grant: g,
        scope,
        required: req,
        interactive,
        effect_token: token,
        now: t0(),
        pairs,
    }
}

fn bounds() -> ProbeBounds {
    ProbeBounds::default()
}

/// Every message type the fake agent received.
fn received(agent: &FakeAgent) -> Vec<u8> {
    agent.log().iter().map(|c| c.msg_type).collect()
}

// --- A11 ------------------------------------------------------------------------------

#[tokio::test]
async fn a11_noninteractive_ensure_never_contacts_provider() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let declared = Sources {
        observations: vec![observation("h1", exclusive(&id.fingerprint))],
        declarations: BTreeMap::from([(id.id.clone(), declaration(&id, &f.endpoint, at(1800)))]),
        ..Sources::default()
    };
    let native_declared = native(&f.endpoint, declared);
    let native_undeclared = native(&f.endpoint, Sources::default());
    let op_id = op_identity(2, &key, &f.endpoint);
    let op = onepassword(&f.endpoint, Sources::default());
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    let native_pairs = [pair("h1", &id, Some("h1"))];
    let op_pairs = [pair("h1", &op_id, Some("h1"))];

    // The declared native key is ready without interaction; the others are refused
    // before anything is contacted.
    let ready = native_declared
        .prepare(request(&g, &scope, &req, false, "t1", &native_pairs))
        .await
        .unwrap();
    assert_eq!(ready.availability, CredentialAvailability::CurrentOnly);
    assert!(matches!(
        native_undeclared
            .prepare(request(&g, &scope, &req, false, "t2", &native_pairs))
            .await,
        Err(AdapterError::InteractionRequired(_))
    ));
    assert!(matches!(
        op.prepare(request(&g, &scope, &req, false, "t3", &op_pairs))
            .await,
        Err(AdapterError::InteractionRequired(_))
    ));
    let adapters: [&dyn CredentialAdapter; 3] = [&native_declared, &native_undeclared, &op];
    for a in adapters {
        let _ = a
            .renew(request(&g, &scope, &req, false, "t4", &native_pairs))
            .await;
        let _ = a.reconcile(&g.id, "t1").await.unwrap();
        let _ = a.revoke(&g.id, t0()).await.unwrap();
    }
    for p in [&native_declared as &dyn ProviderProbe, &op] {
        let _ = p.detect(&DetectContext {
            now: t0(),
            endpoint: Some(f.endpoint.clone()),
        });
    }
    assert_eq!(
        f.agent.contact_count(),
        0,
        "no message reached the provider"
    );
    // Opens, not identified connections: on Windows a client that opens the pipe and
    // sends nothing is never identified, so only `opens` would see it (W6W-R02).
    assert_eq!(f.agent.opens(), 0, "no connection was even opened");
}

#[tokio::test]
async fn a11_unattended_minimum_is_capability_unavailable_for_both_mechanisms() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let op_id = op_identity(2, &key, &f.endpoint);
    // Even a declared, exclusive native key: lock continuity is not verified.
    let sources = Sources {
        observations: vec![observation("h1", exclusive(&id.fingerprint))],
        declarations: BTreeMap::from([(id.id.clone(), declaration(&id, &f.endpoint, at(1800)))]),
        ..Sources::default()
    };
    let n = native(&f.endpoint, sources);
    let op = onepassword(&f.endpoint, Sources::default());
    let g = grant();
    let scope = Scope::empty();
    let req = required(true);
    for interactive in [true, false] {
        let np = [pair("h1", &id, Some("h1"))];
        let opp = [pair("h1", &op_id, Some("h1"))];
        assert_eq!(
            n.prepare(request(&g, &scope, &req, interactive, "t", &np))
                .await,
            Err(AdapterError::CapabilityUnavailable)
        );
        assert_eq!(
            op.prepare(request(&g, &scope, &req, interactive, "t", &opp))
                .await,
            Err(AdapterError::CapabilityUnavailable)
        );
    }
    for (d, lock) in [
        (n.descriptor(), LockContinuity::Unknown),
        (op.descriptor(), LockContinuity::StopsOnLock),
    ] {
        assert_eq!(d.lock_continuity, lock);
        assert!(!state::unattended_met(
            d.lock_continuity,
            [InteractionKind::None]
        ));
    }
    let e = Refusal::UnattendedUnavailable {
        provider: ProviderKind::OnePassword,
    }
    .op_error();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.code.exit_code().as_i32(), 4);
    assert_eq!(f.agent.contact_count(), 0);
}

/// Settles ADR-0007 §7's `[I]` for OpenSSH's agent: locked with `ssh-add -x`, it lists
/// nothing; unlocked again, it lists the key (the control).
#[cfg(unix)]
#[tokio::test]
async fn a11_locked_native_agent_lists_nothing() {
    use heimdall_contract::provider::ProbeLevel;
    use heimdall_testkit::agent::{AgentOptions, DisposableSshAgent, KeyConstraints};
    use heimdall_testkit::hook::HookBinary;
    let scratch = Scratch::new().unwrap();
    // No askpass is configured, so the hook program is never run.
    let hook = HookBinary::locate().unwrap_or_else(|_| HookBinary::at("hm-fixture-hook"));
    let mut agent =
        DisposableSshAgent::start_with_hook(&scratch, AgentOptions::default(), &hook).unwrap();
    let key = FixtureKey::generate();
    agent.add_key(&key, KeyConstraints::default()).unwrap();
    let endpoint = endpoint_ref(&agent.endpoint());
    let adapter = NativeAgentAdapter::new("u6".into(), Some(endpoint.clone()));

    let unlocked = adapter.list_identities(&bounds()).await;
    let fps: Vec<_> = unlocked
        .as_ref()
        .unwrap()
        .identities
        .iter()
        .map(|i| i.fingerprint.clone())
        .collect();
    assert_eq!(fps, vec![key.fingerprint()], "the control lists the key");
    let s = state::status_from_listing(ProviderKind::NativeAgent, &unlocked, t0());
    assert_eq!(s.availability, ProviderAvailability::Available);

    agent.lock().unwrap();
    let locked = adapter.list_identities(&bounds()).await;
    assert_eq!(
        locked.as_ref().unwrap().identities,
        Vec::new(),
        "a locked ssh-agent lists nothing"
    );
    let s = state::status_from_listing(ProviderKind::NativeAgent, &locked, t0());
    assert_eq!(s.availability, ProviderAvailability::Locked);
    assert_eq!(s.interaction, InteractionKind::ProviderUnlock);
    assert_eq!(s.observed_level, ProbeLevel::Agent);
    assert_eq!(s.basis, EvidenceBasis::Inferred);
    let refusal = state::readiness(&s, &[], true, false, LockContinuity::Unknown).unwrap_err();
    let e = refusal.op_error();
    assert_eq!(e.code, Code::ProviderLocked);
    assert_eq!(e.code.exit_code().as_i32(), 3);
    assert_eq!(e.next.action, "interact");
    assert_eq!(
        e.next.provider_interaction,
        Some(ProviderInteractionRef {
            provider: ProviderKind::NativeAgent,
            kind: InteractionKind::ProviderUnlock,
        })
    );
    assert!(e.next.decision_ref.is_none());

    agent.unlock().unwrap();
    let again = adapter.list_identities(&bounds()).await.unwrap();
    assert_eq!(
        again.identities.len(),
        1,
        "unlocked again, the key is listed"
    );
    agent.stop();
}

#[tokio::test]
async fn a11_fake_onepassword_states() {
    for mode in [
        AgentMode::Normal,
        AgentMode::ApprovalPending,
        AgentMode::Deny,
        AgentMode::Locked,
    ] {
        let key = FixtureKey::generate();
        let f = fake(mode.clone(), vec![key.clone()]);
        let op_id = op_identity(2, &key, &f.endpoint);
        let adapter = onepassword(&f.endpoint, Sources::default());
        let listing = adapter.list_identities(&bounds()).await;
        let status = state::status_from_listing(ProviderKind::OnePassword, &listing, t0());
        let pairs = [PairReadiness {
            eligibility: state::pair_eligibility(&op_id, None, &f.endpoint, t0()),
            selection: IdentitySelection::Exclusive,
            clearance: None,
        }];
        let interactive =
            state::readiness(&status, &pairs, true, false, LockContinuity::StopsOnLock);
        let noninteractive =
            state::readiness(&status, &pairs, false, false, LockContinuity::StopsOnLock);
        if mode == AgentMode::Locked {
            assert_eq!(
                status.availability,
                ProviderAvailability::Locked,
                "{mode:?}"
            );
            assert_eq!(status.interaction, InteractionKind::ProviderUnlock);
            for r in [interactive, noninteractive] {
                let e = r.unwrap_err().op_error();
                assert_eq!(e.code, Code::ProviderLocked);
                assert_eq!(
                    e.next.provider_interaction,
                    Some(ProviderInteractionRef {
                        provider: ProviderKind::OnePassword,
                        kind: InteractionKind::ProviderUnlock,
                    })
                );
            }
        } else {
            // Approval is per signature, and Heimdall never signs: the listing is the
            // same whether an approval is pending or would be denied.
            assert_eq!(
                status.availability,
                ProviderAvailability::Available,
                "{mode:?}"
            );
            assert_eq!(status.interaction, InteractionKind::ProviderApproval);
            assert_eq!(status.basis, EvidenceBasis::Observed);
            assert_eq!(interactive, Ok(CredentialAvailability::InteractionRequired));
            let e = noninteractive.unwrap_err().op_error();
            assert_eq!(e.code, Code::InteractionRequired);
            assert_eq!(e.code.exit_code().as_i32(), 3);
            assert_eq!(e.reason.as_deref(), Some(reason::PROVIDER_INTERACTION));
            assert_eq!(e.next.action, "interact");
            assert_eq!(
                e.next.provider_interaction,
                Some(ProviderInteractionRef {
                    provider: ProviderKind::OnePassword,
                    kind: InteractionKind::ProviderApproval,
                })
            );
            assert!(
                e.next.decision_ref.is_none(),
                "a provider dialog is not a decision"
            );
            assert_eq!(listing.as_ref().unwrap().identities.len(), 1);
        }
        assert_eq!(
            received(&f.agent),
            vec![msg::REQUEST_IDENTITIES],
            "{mode:?}"
        );
        assert_no_canary(&format!("{listing:?} {status:?}"));
    }
}

#[tokio::test]
async fn a11_fido_identity_is_hardware_presence_from_public_key_alone() {
    let f = fake(AgentMode::Normal, Vec::new());
    // A synthetic FIDO public key: its type alone decides (no agent contact).
    let fido = identity(
        5,
        IdentitySource::NativeAgent {
            endpoint: f.endpoint.clone(),
        },
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIFU2Zmlkb2ZpeHR1cmVwdWJsaWNrZXlvbmx5AAAABHNzaDo="
            .to_owned(),
        "SHA256:u6fidofixture".to_owned(),
    );
    assert_eq!(
        fido.interaction.interaction,
        InteractionKind::HardwarePresence
    );
    // A live declaration of `none` does not change a FIDO key.
    let sources = Sources {
        observations: vec![observation("h1", exclusive(&fido.fingerprint))],
        declarations: BTreeMap::from([(
            fido.id.clone(),
            declaration(&fido, &f.endpoint, at(1800)),
        )]),
        ..Sources::default()
    };
    let adapter = native(&f.endpoint, sources);
    let pairs = [pair("h1", &fido, Some("h1"))];
    let p = prepare_native(&adapter, &pairs, true, t0()).unwrap();
    assert_eq!(
        p.pairs[0].pair.interaction,
        InteractionKind::HardwarePresence
    );
    assert_eq!(p.pairs[0].pair.interaction_basis, EvidenceBasis::Documented);
    assert!(!p.pairs[0].pair.noninteractive.eligible);
    assert_eq!(
        prepare_native(&adapter, &pairs, false, t0()),
        Err(AdapterError::InteractionRequired(
            InteractionRequirement::HardwarePresence
        ))
    );
    assert_eq!(f.agent.contact_count(), 0);
}

#[tokio::test]
async fn a11_native_agent_identity_defaults_to_interaction_unknown() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    assert_eq!(id.interaction.interaction, InteractionKind::Unknown);
    assert_eq!(id.interaction.basis, EvidenceBasis::Inferred);
    let adapter = native(
        &f.endpoint,
        Sources {
            observations: vec![observation("h1", exclusive(&id.fingerprint))],
            ..Sources::default()
        },
    );
    let p = prepare_native(&adapter, &[pair("h1", &id, Some("h1"))], true, t0()).unwrap();
    let pair = &p.pairs[0].pair;
    assert_eq!(pair.interaction, InteractionKind::Unknown);
    assert_eq!(pair.interaction_basis, EvidenceBasis::Inferred);
    assert_eq!(pair.declaration, None);
    assert_eq!(pair.declared_at, None);
    assert!(!pair.noninteractive.eligible);
    assert_eq!(
        pair.noninteractive.reason.as_deref(),
        Some(reason::INTERACTION_UNKNOWN)
    );
    assert_eq!(
        p.outcome.availability,
        CredentialAvailability::InteractionRequired
    );
    let provider = p.outcome.provider.unwrap();
    assert_eq!(provider.interaction, InteractionKind::Unknown);
    assert_eq!(provider.basis, EvidenceBasis::Inferred);
    assert_eq!(
        state::interaction_profile(
            &id,
            None,
            &state::EndpointObservation {
                endpoint: f.endpoint.clone(),
                present: true,
                observed_at: t0(),
            },
            t0(),
        ),
        (InteractionKind::Unknown, EvidenceBasis::Inferred)
    );
    assert_eq!(f.agent.contact_count(), 0);
}

#[tokio::test]
async fn a11_declared_none_reported_declared_and_lapses() {
    let key = FixtureKey::generate();
    let other_key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let moved = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let expires = at(1800);
    let live = declaration(&id, &f.endpoint, expires);
    let sources = |decl: InteractionDeclaration| Sources {
        observations: vec![observation("h1", exclusive(&id.fingerprint))],
        declarations: BTreeMap::from([(id.id.clone(), decl)]),
        ..Sources::default()
    };

    // Declared: `none`, basis `declared`, with the declaration it relied on.
    let adapter = native(&f.endpoint, sources(live.clone()));
    let pairs = [pair("h1", &id, Some("h1"))];
    let p = prepare_native(&adapter, &pairs, false, t0()).unwrap();
    let pr = &p.pairs[0].pair;
    assert_eq!(pr.interaction, InteractionKind::None);
    assert_eq!(pr.interaction_basis, EvidenceBasis::Declared);
    assert_eq!(pr.declared_at, Some(live.declared_at));
    assert_eq!(pr.declaration.as_ref().unwrap().revision, live.revision);
    assert_eq!(pr.declaration.as_ref().unwrap().expires_at, expires);
    assert!(pr.noninteractive.eligible);
    assert_eq!(p.outcome.availability, CredentialAvailability::CurrentOnly);

    let lapsed = |p: &Prepared| {
        let pr = &p.pairs[0].pair;
        pr.interaction == InteractionKind::Unknown
            && pr.interaction_basis == EvidenceBasis::Inferred
            && pr.declaration.is_none()
            && pr.declared_at.is_none()
            && !pr.noninteractive.eligible
    };

    // 1. The endpoint changed: the identity now lives at another agent.
    let moved_id = native_identity(1, &key, &moved.endpoint);
    let a = native(&moved.endpoint, sources(live.clone()));
    let p = prepare_native(&a, &[pair("h1", &moved_id, Some("h1"))], true, t0()).unwrap();
    assert!(lapsed(&p), "endpoint change");

    // 2. An explicit listing at the endpoint lacks the fingerprint; the CLI records
    //    the lapse (`WithdrawDeclaration { reason: listing_missing }`), after which
    //    the row is no longer live.
    let without = fake(AgentMode::Normal, vec![other_key.clone()]);
    let listing = NativeAgentAdapter::new("u6".into(), Some(without.endpoint.clone()))
        .list_identities(&bounds())
        .await
        .unwrap();
    assert!(
        listing
            .identities
            .iter()
            .all(|i| i.fingerprint != id.fingerprint)
    );
    let recorded = InteractionDeclaration {
        revision: live.revision + 1,
        state: DeclarationState::Lapsed,
        ended_at: Some(t0()),
        end_reason: Some(DeclarationEndReason::ListingMissing),
        ..live.clone()
    };
    let a = native(&f.endpoint, sources(recorded));
    assert!(
        lapsed(&prepare_native(&a, &pairs, true, t0()).unwrap()),
        "listing missing"
    );

    // 3. Expiry: counted at every read; `expires_at == now` no longer counts.
    let a = native(&f.endpoint, sources(live.clone()));
    let before = prepare_native(&a, &pairs, true, at(1799)).unwrap();
    assert_eq!(before.pairs[0].pair.interaction, InteractionKind::None);
    assert!(
        lapsed(&prepare_native(&a, &pairs, true, expires).unwrap()),
        "expiry"
    );
    assert_eq!(
        prepare_native(&a, &pairs, false, expires),
        Err(AdapterError::InteractionRequired(
            InteractionRequirement::ProviderDialog
        ))
    );
    assert_eq!(f.agent.contact_count(), 0);
    assert_eq!(moved.agent.contact_count(), 0);
    assert_eq!(received(&without.agent), vec![msg::REQUEST_IDENTITIES]);
}

#[tokio::test]
async fn prepare_marks_uncleared_fallback_entries() {
    let adopted = FixtureKey::generate();
    let inherited_undeclared = FixtureKey::generate();
    let inherited_declared = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![adopted.clone()]);
    let a = native_identity(1, &adopted, &f.endpoint);
    let b = native_identity(2, &inherited_undeclared, &f.endpoint);
    let c = native_identity(3, &inherited_declared, &f.endpoint);
    let report = |alternatives: &[&IdentityRecord]| {
        let mut entries = vec![entry(
            IdentityEntrySource::Managed,
            Some(a.fingerprint.clone()),
            IdentityBacking::Agent,
        )];
        for alt in alternatives {
            entries.push(entry(
                IdentityEntrySource::User,
                Some(alt.fingerprint.clone()),
                IdentityBacking::Agent,
            ));
        }
        IdentitySelectionReport {
            selection: IdentitySelection::NotExclusive,
            entries,
            identities_only: IdentitiesOnly::DeterminedYes,
        }
    };
    let sources = |alternatives: &[&IdentityRecord]| Sources {
        observations: vec![observation("h1", report(alternatives))],
        identities: vec![a.clone(), b.clone(), c.clone()],
        declarations: BTreeMap::from([
            (a.id.clone(), declaration(&a, &f.endpoint, at(1800))),
            (c.id.clone(), declaration(&c, &f.endpoint, at(1800))),
        ]),
        ..Sources::default()
    };
    let pairs = [pair("h1", &a, Some("h1"))];

    // The undeclared inherited key is uncleared; the declared one is cleared.
    let adapter = native(&f.endpoint, sources(&[&b, &c]));
    let p = prepare_native(&adapter, &pairs, true, t0()).unwrap();
    let d = &p.pairs[0];
    assert_eq!(d.pair.identity_selection, IdentitySelection::NotExclusive);
    let cleared: Vec<_> = d.selection.entries.iter().map(|e| e.cleared).collect();
    assert_eq!(cleared, vec![None, Some(false), Some(true)]);
    assert_eq!(d.clearance.as_ref().unwrap().uncleared, vec![1]);
    assert!(!d.pair.noninteractive.eligible);
    assert_eq!(
        d.pair.noninteractive.reason.as_deref(),
        Some(reason::FALLBACK_IDENTITY_INTERACTION)
    );
    assert_eq!(
        prepare_native(&adapter, &pairs, false, t0()),
        Err(AdapterError::InteractionRequired(
            InteractionRequirement::ProviderDialog
        ))
    );

    // With only the declared alternative, every alternative is cleared.
    let adapter = native(&f.endpoint, sources(&[&c]));
    let p = prepare_native(&adapter, &pairs, false, t0()).unwrap();
    let d = &p.pairs[0];
    let cleared: Vec<_> = d.selection.entries.iter().map(|e| e.cleared).collect();
    assert_eq!(cleared, vec![None, Some(true)]);
    assert!(d.clearance.as_ref().unwrap().cleared);
    assert!(d.pair.noninteractive.eligible);
    assert_eq!(f.agent.contact_count(), 0);
}

/// ⟨M02⟩ ADR-0007 §12.15 items 3(c) and 3(d) (U0b phase 2). The pair the port
/// reports carries the full selection (`PairIntegration.identity_selection_report`,
/// with every `cleared` mark), and the one domain clearance rule, which takes the
/// adopted identity's fingerprint, never clears a managed entry naming another key
/// (a stale projection), even beside a cleared alternative.
#[tokio::test]
async fn prepare_reports_the_full_selection_and_never_clears_a_stale_managed_entry() {
    let adopted = FixtureKey::generate();
    let declared_alt = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![adopted.clone()]);
    let a = native_identity(1, &adopted, &f.endpoint);
    let c = native_identity(3, &declared_alt, &f.endpoint);
    let report = |stale: bool| {
        let mut entries = vec![entry(
            IdentityEntrySource::Managed,
            Some(a.fingerprint.clone()),
            IdentityBacking::Agent,
        )];
        if stale {
            entries.push(entry(
                IdentityEntrySource::Managed,
                Some("SHA256:u0bstaleprojectionAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
                IdentityBacking::Agent,
            ));
        }
        entries.push(entry(
            IdentityEntrySource::User,
            Some(c.fingerprint.clone()),
            IdentityBacking::Agent,
        ));
        IdentitySelectionReport {
            selection: IdentitySelection::NotExclusive,
            entries,
            identities_only: IdentitiesOnly::DeterminedYes,
        }
    };
    let sources = |stale: bool| Sources {
        observations: vec![observation("h1", report(stale))],
        identities: vec![a.clone(), c.clone()],
        declarations: BTreeMap::from([
            (a.id.clone(), declaration(&a, &f.endpoint, at(1800))),
            (c.id.clone(), declaration(&c, &f.endpoint, at(1800))),
        ]),
        ..Sources::default()
    };
    let pairs = [pair("h1", &a, Some("h1"))];
    // Without the stale entry: cleared, and the port carries the marked report.
    let adapter = native(&f.endpoint, sources(false));
    let p = prepare_native(&adapter, &pairs, false, t0()).unwrap();
    let d = &p.pairs[0];
    assert!(d.pair.noninteractive.eligible);
    assert_eq!(
        d.pair.identity_selection_report.as_ref(),
        Some(&d.selection)
    );
    let marks: Vec<_> = d.selection.entries.iter().map(|e| e.cleared).collect();
    assert_eq!(marks, vec![None, Some(true)]);
    let reported = &p.outcome.integration.pairs[0];
    assert_eq!(
        reported.identity_selection_report.as_ref(),
        Some(&d.selection)
    );
    // With it: the stale managed entry is an uncleared alternative.
    let adapter = native(&f.endpoint, sources(true));
    let p = prepare_native(&adapter, &pairs, true, t0()).unwrap();
    let d = &p.pairs[0];
    let marks: Vec<_> = d.selection.entries.iter().map(|e| e.cleared).collect();
    assert_eq!(marks, vec![None, Some(false), Some(true)]);
    assert_eq!(d.clearance.as_ref().unwrap().uncleared, vec![1]);
    assert!(!d.clearance.as_ref().unwrap().cleared);
    assert_eq!(
        d.pair.noninteractive.reason.as_deref(),
        Some(reason::FALLBACK_IDENTITY_INTERACTION)
    );
    assert_eq!(
        prepare_native(&adapter, &pairs, false, t0()),
        Err(AdapterError::InteractionRequired(
            InteractionRequirement::ProviderDialog
        ))
    );
    // The rule itself: only the adopted fingerprint names the adopted entry.
    let eligibility_of = |id: &IdentityId| {
        let record = [&a, &c].into_iter().find(|r| r.id == *id).unwrap();
        state::pair_eligibility(
            record,
            Some(&declaration(record, &f.endpoint, at(1800))),
            &f.endpoint,
            t0(),
        )
    };
    let catalog = [a.clone(), c.clone()];
    let by = |fp: &str| {
        state::fallback_clearance(&report(false), &catalog, &eligibility_of, &f.endpoint, fp)
    };
    assert!(by(&a.fingerprint).cleared);
    assert_eq!(
        by(&c.fingerprint).uncleared,
        vec![0],
        "another key's managed entry"
    );
    assert_eq!(f.agent.contact_count(), 0);
}

#[tokio::test]
async fn prepared_facts_from_outcome_drop_interaction_fields() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let report = exclusive(&id.fingerprint);
    let declared = native(
        &f.endpoint,
        Sources {
            observations: vec![observation("h1", report.clone())],
            declarations: BTreeMap::from([(
                id.id.clone(),
                declaration(&id, &f.endpoint, at(1800)),
            )]),
            ..Sources::default()
        },
    );
    let undeclared = native(
        &f.endpoint,
        Sources {
            observations: vec![observation("h1", report.clone())],
            ..Sources::default()
        },
    );
    let pairs = [pair("h1", &id, Some("h1"))];
    let a = prepare_native(&declared, &pairs, true, t0()).unwrap();
    let b = prepare_native(&undeclared, &pairs, true, t0()).unwrap();
    // The outcomes differ in their fresh fields ...
    assert_ne!(a.outcome.integration.pairs, b.outcome.integration.pairs);
    assert_ne!(a.outcome.availability, b.outcome.availability);
    // ... and their history is identical: nothing interaction-related survives.
    let facts = |p: &Prepared| PreparedFacts {
        provider: p.outcome.provider.clone(),
        executables: p.outcome.integration.executables.clone(),
        overrides: p.outcome.integration.overrides.clone(),
        environment: p.outcome.integration.environment.clone(),
        pairs: p.prepared_pairs(),
        recorded_at: t0(),
    };
    assert_eq!(facts(&a), facts(&b));
    // The history carries the full selection (ADR-0007 §12.14 item 6).
    let history = &facts(&a).pairs[0];
    assert_eq!(history.identity_selection, report);
    assert_eq!(
        history.identity_selection.identities_only,
        IdentitiesOnly::DeterminedYes
    );
    assert_eq!(history.selection_observed_at, t0());
    assert_eq!(history.endpoint.as_ref(), Some(&f.endpoint));
}

// --- A35 and identity selection -------------------------------------------------------

#[tokio::test]
async fn a35_identity_selected_by_public_key_with_identities_only() {
    let key = FixtureKey::generate();
    // Ten other keys are listed first: an agent offering every key would exhaust a
    // server's tries; the selection must name the adopted key alone.
    let f = fake(AgentMode::ManyKeys(10), vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let decl = BTreeMap::from([(id.id.clone(), declaration(&id, &f.endpoint, at(1800)))]);
    let adapter = native(
        &f.endpoint,
        Sources {
            observations: vec![observation("h1", exclusive(&id.fingerprint))],
            declarations: decl.clone(),
            ..Sources::default()
        },
    );
    let pairs = [pair("h1", &id, Some("h1"))];
    let p = prepare_native(&adapter, &pairs, false, t0()).unwrap();
    let d = &p.pairs[0];
    assert_eq!(d.pair.identity_selection, IdentitySelection::Exclusive);
    assert_eq!(d.selection.identities_only, IdentitiesOnly::DeterminedYes);
    assert_eq!(d.selection.entries.len(), 1);
    assert_eq!(
        d.selection.entries[0].fingerprint.as_deref(),
        Some(id.fingerprint.as_str())
    );
    assert!(
        d.clearance.is_none(),
        "no fallback for an exclusive selection"
    );
    assert!(d.pair.noninteractive.eligible);
    assert_eq!(f.agent.contact_count(), 0, "selection is static");

    // The explicit probe finds the adopted key among the eleven by public key.
    let listing = adapter.list_identities(&bounds()).await.unwrap();
    assert_eq!(listing.identities.len(), 11);
    assert!(
        listing
            .identities
            .iter()
            .any(|i| i.fingerprint == id.fingerprint)
    );

    // Control: an `exclusive` verdict whose managed entry names another key does not
    // select the adopted key, so it is not trusted.
    let wrong = native(
        &f.endpoint,
        Sources {
            observations: vec![observation(
                "h1",
                exclusive(&FixtureKey::generate().fingerprint()),
            )],
            declarations: decl,
            ..Sources::default()
        },
    );
    let p = prepare_native(&wrong, &pairs, true, t0()).unwrap();
    assert_eq!(
        p.pairs[0].pair.identity_selection,
        IdentitySelection::Undetermined
    );
    // The managed entry that names another key is an alternative, never cleared.
    assert_eq!(p.pairs[0].selection.entries[0].cleared, Some(false));
    assert_eq!(
        p.pairs[0].pair.noninteractive.reason.as_deref(),
        Some(reason::FALLBACK_IDENTITY_INTERACTION)
    );
    assert_eq!(
        prepare_native(&wrong, &pairs, false, t0()),
        Err(AdapterError::InteractionRequired(
            InteractionRequirement::ProviderDialog
        ))
    );
}

#[tokio::test]
async fn prepare_reports_not_exclusive_for_inherited_identityfile() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let report = IdentitySelectionReport {
        selection: IdentitySelection::NotExclusive,
        entries: vec![
            entry(
                IdentityEntrySource::Managed,
                Some(id.fingerprint.clone()),
                IdentityBacking::Agent,
            ),
            // `Host *` IdentityFile with its private key file present.
            entry(IdentityEntrySource::User, None, IdentityBacking::File),
        ],
        identities_only: IdentitiesOnly::DeterminedYes,
    };
    let adapter = native(
        &f.endpoint,
        Sources {
            observations: vec![observation("h1", report)],
            declarations: BTreeMap::from([(
                id.id.clone(),
                declaration(&id, &f.endpoint, at(1800)),
            )]),
            ..Sources::default()
        },
    );
    let pairs = [pair("h1", &id, Some("h1"))];
    let p = prepare_native(&adapter, &pairs, true, t0()).unwrap();
    assert_eq!(
        p.pairs[0].pair.identity_selection,
        IdentitySelection::NotExclusive
    );
    assert_eq!(
        p.outcome.integration.pairs[0].identity_selection,
        IdentitySelection::NotExclusive
    );
    assert_eq!(
        p.pairs[0].selection.entries[1].cleared,
        Some(false),
        "file-backed"
    );
    assert!(prepare_native(&adapter, &pairs, false, t0()).is_err());
}

// --- integration, enforcement, endpoints -----------------------------------------------

#[tokio::test]
async fn integration_sets_ssh_auth_sock_only_for_one_endpoint() {
    let k1 = FixtureKey::generate();
    let k2 = FixtureKey::generate();
    let f1 = fake(AgentMode::Normal, vec![k1.clone()]);
    let f2 = fake(AgentMode::Normal, vec![k2.clone()]);
    let i1 = native_identity(1, &k1, &f1.endpoint);
    let i2 = native_identity(2, &k2, &f2.endpoint);
    let adapter = native(&f1.endpoint, Sources::default());
    let one = prepare_native(&adapter, &[pair("h1", &i1, Some("h1"))], true, t0()).unwrap();
    assert_eq!(
        one.outcome.integration.environment,
        vec![(SSH_AUTH_SOCK.to_owned(), f1.endpoint.locator.clone())]
    );
    let two = prepare_native(
        &adapter,
        &[pair("h1", &i1, Some("h1")), pair("h2", &i2, Some("h2"))],
        true,
        t0(),
    )
    .unwrap();
    assert!(two.outcome.integration.environment.is_empty());
    assert!(
        two.outcome
            .integration
            .overrides
            .contains(&ConsumerOverride {
                consumer: ConsumerKind::Ssh,
                setting: SSH_AUTH_SOCK.to_owned(),
                source: OverrideSource::Environment,
            })
    );
    // An observed alias whose configuration sets IdentityAgent: that wins (F8).
    let observed = AliasObservation {
        alias: "h1".into(),
        definition: AliasDefinition::Observed,
        behavior: vec![DirectiveObservation {
            directive: "IdentityAgent".into(),
            values: vec!["~/.ssh/other.sock".into()],
            certainty: DirectiveCertainty::Determined,
            provenance: vec![provenance("~/.ssh/config", 7)],
        }],
        identity_selection: None,
    };
    let a = native(
        &f1.endpoint,
        Sources {
            observations: vec![observed],
            ..Sources::default()
        },
    );
    let p = prepare_native(&a, &[pair("h1", &i1, Some("h1"))], true, t0()).unwrap();
    assert!(p.outcome.integration.overrides.contains(&ConsumerOverride {
        consumer: ConsumerKind::Ssh,
        setting: "IdentityAgent".into(),
        source: OverrideSource::SshConfig(provenance("~/.ssh/config", 7)),
    }));
    assert_eq!(
        p.pairs[0].pair.identity_selection,
        IdentitySelection::Undetermined
    );
    let ids: BTreeSet<_> = two
        .outcome
        .integration
        .pairs
        .iter()
        .map(|p| p.identity.clone())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_eq!(f1.agent.contact_count() + f2.agent.contact_count(), 0);
}

#[tokio::test]
async fn enforcement_report_is_exact_for_existing_access() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let op_id = op_identity(2, &key, &f.endpoint);
    let check = |e: &EnforcementEvidence, scope: DestinationScopeEnforcement| {
        assert_eq!(e.report.destination_scope, scope);
        assert_eq!(
            e.report.new_authentication_expiry,
            NewAuthenticationExpiry::None
        );
        assert_eq!(e.report.workload_isolation, WorkloadIsolation::SharedOsUser);
        assert_eq!(
            e.report.existing_connections,
            ExistingConnectionsPolicy::Unknown
        );
        assert_eq!(e.report.revocation, RevocationStatus::Unknown);
    };
    let adapter = native(&f.endpoint, Sources::default());
    let managed = prepare_native(&adapter, &[pair("h1", &id, Some("h1"))], true, t0()).unwrap();
    check(
        &managed.outcome.enforcement,
        DestinationScopeEnforcement::ClientRouting,
    );
    assert!(
        managed
            .outcome
            .enforcement
            .evidence
            .iter()
            .all(|r| r.label == SupportLabel::NotTested && r.test_id.as_deref() == Some("A35"))
    );
    let observed = prepare_native(&adapter, &[pair("h1", &id, None)], true, t0()).unwrap();
    check(
        &observed.outcome.enforcement,
        DestinationScopeEnforcement::UnenforcedIntent,
    );
    assert!(observed.outcome.enforcement.evidence.is_empty());
    let mixed = prepare_native(
        &adapter,
        &[pair("h1", &id, Some("h1")), pair("h2", &id, None)],
        true,
        t0(),
    )
    .unwrap();
    check(
        &mixed.outcome.enforcement,
        DestinationScopeEnforcement::UnenforcedIntent,
    );
    check(
        &descriptor_enforcement(),
        DestinationScopeEnforcement::ClientRouting,
    );
    assert_eq!(managed.outcome.refresh_dependency, RefreshDependency::None);
    assert!(managed.outcome.usable_until <= t0(), "no claim beyond now");

    let op = onepassword(&f.endpoint, Sources::default());
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    let opp = [pair("h1", &op_id, Some("h1"))];
    let o = op
        .prepare(request(&g, &scope, &req, true, "t", &opp))
        .await
        .unwrap();
    check(&o.enforcement, DestinationScopeEnforcement::ClientRouting);
    assert_eq!(o.refresh_dependency, RefreshDependency::ProviderInteraction);
    assert_eq!(o.availability, CredentialAvailability::InteractionRequired);
    assert!(o.credential_ref.starts_with("onepassword/"));
    assert!(o.credential_ref.ends_with(&op_id.fingerprint));
    assert_no_canary(&format!("{o:?}"));
    for d in [adapter.descriptor(), op.descriptor()] {
        assert!(!d.external_side_effects);
        assert_eq!(d.interaction, InteractionRequirement::ProviderDialog);
    }
}

#[tokio::test]
async fn endpoint_absent_is_service_unavailable_resource_provider() {
    let scratch = Scratch::new().unwrap();
    let absent = endpoint_ref(&Endpoint::in_scratch(&scratch, "absent").unwrap());
    let key = FixtureKey::generate();
    let id = native_identity(1, &key, &absent);
    let op_id = op_identity(2, &key, &absent);
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    let np = [pair("h1", &id, Some("h1"))];
    let opp = [pair("h1", &op_id, Some("h1"))];
    let n = native(&absent, Sources::default());
    let op = onepassword(&absent, Sources::default());
    for r in [
        n.prepare(request(&g, &scope, &req, true, "t", &np)).await,
        op.prepare(request(&g, &scope, &req, true, "t", &opp)).await,
    ] {
        let e = r.unwrap_err();
        assert!(matches!(e, AdapterError::Unavailable(_)), "{e:?}");
        let mapped = OpError::from_adapter_for(&e, PROVIDER_RESOURCE);
        assert_eq!(mapped.code, Code::ServiceUnavailable);
        assert_eq!(mapped.resource.unwrap().kind, "provider");
    }
    let e = Refusal::EndpointAbsent {
        provider: ProviderKind::NativeAgent,
    }
    .op_error();
    assert_eq!(e.code, Code::ServiceUnavailable);
    assert_eq!(e.resource.as_ref().unwrap().kind, PROVIDER_RESOURCE);
    assert_eq!(e.reason.as_deref(), Some(reason::ENDPOINT_ABSENT));
    // Passive detection says the same, and the probe refuses without contact.
    for p in [&n as &dyn ProviderProbe, &op] {
        let s = p.detect(&DetectContext {
            now: t0(),
            endpoint: None,
        });
        assert_eq!(s.availability, ProviderAvailability::Unavailable);
        assert!(matches!(
            p.list_identities(&bounds()).await,
            Err(AdapterError::Unavailable(_))
        ));
    }
    // No endpoint at all, and no hardcoded 1Password path to fall back to.
    let nowhere = OnePasswordAdapter::new("u6".into(), None);
    let op_default = identity(
        3,
        IdentitySource::OnePassword { endpoint: None },
        key.public_line_without_comment(),
        key.fingerprint(),
    );
    let pp = [pair("h1", &op_default, Some("h1"))];
    assert!(matches!(
        nowhere
            .prepare(request(&g, &scope, &req, true, "t", &pp))
            .await,
        Err(AdapterError::Unavailable(_))
    ));
}

#[tokio::test]
async fn reconcile_answers_from_what_prepare_returned() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let adapter = native(&f.endpoint, Sources::default());
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    let pairs = [pair("h1", &id, Some("h1"))];
    let o = adapter
        .prepare(request(&g, &scope, &req, true, "tok-a", &pairs))
        .await
        .unwrap();
    assert_eq!(
        adapter.reconcile(&g.id, "tok-a").await,
        Ok(ReconcileOutcome::Applied(o))
    );
    assert_eq!(
        adapter.reconcile(&g.id, "tok-other").await,
        Ok(ReconcileOutcome::NotApplied)
    );
    let r = adapter.revoke(&g.id, t0()).await.unwrap();
    assert!(r.remote_pending.is_empty() && r.latest_possible_credential_expiry.is_none());
    assert_eq!(
        adapter.reconcile(&g.id, "tok-a").await,
        Ok(ReconcileOutcome::NotApplied)
    );
    assert_eq!(f.agent.contact_count(), 0);
}

// --- what is never sent, and the drop contract -----------------------------------------

/// The test sources behind a counter of every read (ADR-0007 §12.23 item 2).
struct Counted {
    inner: Sources,
    reads: std::sync::atomic::AtomicUsize,
}

impl Counted {
    fn read(&self) {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn reads(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl IntegrationSources for Counted {
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
        self.read();
        self.inner.observe_aliases(aliases)
    }
    fn catalog_identities(&self) -> Vec<IdentityRecord> {
        self.read();
        self.inner.catalog_identities()
    }
    fn declaration(&self, identity: &IdentityId) -> Option<InteractionDeclaration> {
        self.read();
        self.inner.declaration(identity)
    }
    fn executables(&self) -> Vec<heimdall_contract::request::ConsumerExecutable> {
        self.read();
        self.inner.executables()
    }
}

/// ADR-0007 §12.23 item 2 (U02), both adapters: `read_sources` makes every source
/// read (the observation, the catalog, the declarations, the executables) into an
/// in-memory snapshot; `prepare_from` over it reads no source at all and answers
/// exactly what the self-reading `prepare` answers. An empty snapshot claims nothing
/// (fail closed): the declared, exclusive key that is ready without interaction over
/// its snapshot is refused on the no-interaction path over an empty one.
#[tokio::test]
async fn prepare_from_reads_nothing_but_its_snapshot() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let op_id = op_identity(2, &key, &f.endpoint);
    let g = grant();
    let scope = Scope::empty();
    let req = required(false);
    for (onepassword_adapter, identity) in [(false, &id), (true, &op_id)] {
        let sources = Arc::new(Counted {
            inner: Sources {
                observations: vec![observation("h1", exclusive(&identity.fingerprint))],
                identities: vec![id.clone(), op_id.clone()],
                declarations: BTreeMap::from([(
                    identity.id.clone(),
                    declaration(identity, &f.endpoint, at(1800)),
                )]),
                ..Sources::default()
            },
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let adapter: Box<dyn CredentialAdapter> = if onepassword_adapter {
            Box::new(
                OnePasswordAdapter::new("u6".into(), Some(f.endpoint.clone()))
                    .with_sources(sources.clone()),
            )
        } else {
            Box::new(
                NativeAgentAdapter::new("u6".into(), Some(f.endpoint.clone()))
                    .with_sources(sources.clone()),
            )
        };
        let pairs = [pair("h1", identity, Some("h1"))];
        let snapshot = adapter.read_sources(&pairs);
        let reads = sources.reads();
        assert!(reads >= 4, "every source was read: {reads}");
        assert_eq!(snapshot.observations.len(), 1);
        assert_eq!(snapshot.identities.len(), 2);
        assert!(snapshot.declarations.contains_key(&identity.id));
        for interactive in [true, false] {
            let before = sources.reads();
            let from = adapter
                .prepare_from(
                    request(&g, &scope, &req, interactive, "t-from", &pairs),
                    &snapshot,
                )
                .await;
            assert_eq!(sources.reads(), before, "no source read inside the bound");
            let direct = adapter
                .prepare(request(&g, &scope, &req, interactive, "t-direct", &pairs))
                .await;
            assert!(sources.reads() > before, "prepare reads its own sources");
            let reads_now = sources.reads();
            assert_eq!(from, direct, "onepassword={onepassword_adapter}");
            // The empty snapshot claims nothing.
            let empty = adapter
                .prepare_from(
                    request(&g, &scope, &req, interactive, "t-empty", &pairs),
                    &heimdall_app::ports::IntegrationSnapshot::default(),
                )
                .await;
            assert_eq!(sources.reads(), reads_now);
            match (onepassword_adapter, interactive) {
                (false, false) => {
                    assert_eq!(
                        from.unwrap().availability,
                        CredentialAvailability::CurrentOnly
                    );
                    assert!(matches!(empty, Err(AdapterError::InteractionRequired(_))));
                }
                (_, true) => {
                    assert!(from.is_ok());
                    let e = empty.unwrap();
                    assert_eq!(e.integration.pairs[0].declaration, None);
                    assert_eq!(
                        e.integration.pairs[0].identity_selection,
                        IdentitySelection::Undetermined
                    );
                }
                (true, false) => {
                    assert!(matches!(from, Err(AdapterError::InteractionRequired(_))));
                    assert!(matches!(empty, Err(AdapterError::InteractionRequired(_))));
                }
            }
        }
    }
    assert_eq!(f.agent.contact_count(), 0, "the agent is never contacted");
}

#[tokio::test]
async fn adapters_never_send_sign_add_remove_lock_or_extension() {
    let key = FixtureKey::generate();
    let f = fake(AgentMode::Normal, vec![key.clone()]);
    let id = native_identity(1, &key, &f.endpoint);
    let op_id = op_identity(2, &key, &f.endpoint);
    let n = native(&f.endpoint, Sources::default());
    let op = onepassword(&f.endpoint, Sources::default());
    let g = grant();
    let scope = Scope::empty();
    for unattended in [false, true] {
        let req = required(unattended);
        for interactive in [true, false] {
            let np = [pair("h1", &id, Some("h1"))];
            let opp = [pair("h1", &op_id, Some("h1"))];
            let _ = n
                .prepare(request(&g, &scope, &req, interactive, "t", &np))
                .await;
            let _ = n
                .renew(request(&g, &scope, &req, interactive, "t", &np))
                .await;
            let _ = op
                .prepare(request(&g, &scope, &req, interactive, "t", &opp))
                .await;
            let _ = op
                .renew(request(&g, &scope, &req, interactive, "t", &opp))
                .await;
        }
    }
    let mut listings = 0;
    for a in [&n as &dyn CredentialAdapter, &op] {
        let _ = a.reconcile(&g.id, "t").await;
        let _ = a.revoke(&g.id, t0()).await;
    }
    for p in [&n as &dyn ProviderProbe, &op] {
        let _ = p.detect(&DetectContext {
            now: t0(),
            endpoint: Some(f.endpoint.clone()),
        });
        for _ in 0..3 {
            let l: Result<IdentityListing, _> = p.list_identities(&bounds()).await;
            assert_eq!(l.unwrap().identities.len(), 1);
            listings += 1;
        }
    }
    let types = received(&f.agent);
    assert_eq!(types, vec![msg::REQUEST_IDENTITIES; listings]);
    for forbidden in [
        msg::SIGN_REQUEST,
        msg::ADD_IDENTITY,
        msg::REMOVE_IDENTITY,
        msg::LOCK,
        msg::EXTENSION,
    ] {
        assert!(!types.contains(&forbidden), "type {forbidden}");
    }
    assert!(
        f.agent.log().iter().all(|c| c.key_fp.is_none()),
        "no key named"
    );
    // The only bytes the agent client can write are the one request frame.
    let source = include_str!("../../crates/ipc/src/agent_client.rs");
    let writes: Vec<_> = source.match_indices(".write_all(").collect();
    assert_eq!(writes.len(), 1);
    assert!(source.contains(".write_all(&REQUEST_IDENTITIES_FRAME)"));
}

/// Poll `fut` until the fake agent has logged one more message, then drop it.
async fn drop_after_request<F: std::future::Future>(agent: &FakeAgent, fut: F) {
    let before = agent.contact_count();
    let mut fut = Box::pin(fut);
    let reached = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                _ = &mut fut => panic!("a stalled agent cannot complete the call"),
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    if agent.contact_count() > before {
                        return;
                    }
                }
            }
        }
    })
    .await;
    reached.expect("the request reached the agent");
    // Let any partial reply arrive before the drop.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(fut);
}

#[tokio::test]
async fn adapters_stop_all_work_when_dropped() {
    let alive = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let baseline = alive();
    for point in [StallPoint::BeforeReply, StallPoint::MidReply] {
        let key = FixtureKey::generate();
        let f = fake(AgentMode::Stall(point), vec![key.clone()]);
        let id = native_identity(1, &key, &f.endpoint);
        let op_id = op_identity(2, &key, &f.endpoint);
        let n = native(&f.endpoint, Sources::default());
        let op = onepassword(&f.endpoint, Sources::default());
        let g = grant();
        let scope = Scope::empty();
        let req = required(false);
        let np = [pair("h1", &id, Some("h1"))];
        let opp = [pair("h1", &op_id, Some("h1"))];

        // prepare, renew, reconcile and revoke: dropped unpolled and after one poll.
        // They contact nothing, so there is no protocol step to stall at.
        for a in [&n as &dyn CredentialAdapter, &op] {
            let pairs: &[PreparePair] = if a.descriptor().mechanism() == "native_agent" {
                &np
            } else {
                &opp
            };
            drop(a.prepare(request(&g, &scope, &req, true, "d", pairs)));
            drop(a.reconcile(&g.id, "d"));
            drop(a.revoke(&g.id, t0()));
            let _ = tokio::time::timeout(
                Duration::ZERO,
                a.prepare(request(&g, &scope, &req, false, "d", pairs)),
            )
            .await;
            let _ = tokio::time::timeout(
                Duration::ZERO,
                a.renew(request(&g, &scope, &req, true, "d", pairs)),
            )
            .await;
            let _ = tokio::time::timeout(Duration::ZERO, a.reconcile(&g.id, "d")).await;
            let _ = tokio::time::timeout(Duration::ZERO, a.revoke(&g.id, t0())).await;
        }
        // Nothing even opened the endpoint (W6W-R02: `opens` sees a silent open,
        // which Windows identification refuses and `connections` never counts).
        assert_eq!(f.agent.opens(), 0, "{point:?}");

        // list_identities, dropped at the stall point, for both adapters.
        for p in [&n as &dyn ProviderProbe, &op] {
            let opened = f.agent.connections();
            let logged = f.agent.contact_count();
            drop_after_request(&f.agent, p.list_identities(&bounds())).await;
            assert_eq!(f.agent.connections(), opened + 1, "{point:?}");
            // Wait on the runtime, not by blocking its thread: a dropped Windows pipe
            // client is closed once the reactor reaps its cancelled read, which a
            // blocked thread never lets happen (a Unix socket closes at the drop).
            let closed = tokio::time::timeout(Duration::from_secs(2), async {
                while f.agent.open_connections() != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            assert!(
                closed.is_ok(),
                "{point:?}: the connection is closed after the drop"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                f.agent.contact_count(),
                logged + 1,
                "{point:?}: no message after the drop"
            );
        }
        assert_eq!(received(&f.agent), vec![msg::REQUEST_IDENTITIES; 2]);
        assert_eq!(alive(), baseline, "{point:?}: no task the adapters spawned");
    }
    // Nothing in the crate or the agent client spawns a task or a thread.
    for (name, source) in [
        (
            "integration",
            include_str!("../../crates/adapters/src/integration.rs"),
        ),
        (
            "native_agent",
            include_str!("../../crates/adapters/src/native_agent.rs"),
        ),
        (
            "onepassword",
            include_str!("../../crates/adapters/src/onepassword.rs"),
        ),
        (
            "detect",
            include_str!("../../crates/adapters/src/detect.rs"),
        ),
        ("state", include_str!("../../crates/adapters/src/state.rs")),
        (
            "agent_client",
            include_str!("../../crates/ipc/src/agent_client.rs"),
        ),
    ] {
        for spawn in ["spawn(", "spawn_blocking", "thread::", "Command::new"] {
            assert!(!source.contains(spawn), "{name} contains {spawn}");
        }
    }
}

#[test]
fn onepassword_paths_are_never_hardcoded() {
    for (name, source) in [
        (
            "onepassword",
            include_str!("../../crates/adapters/src/onepassword.rs"),
        ),
        (
            "detect",
            include_str!("../../crates/adapters/src/detect.rs"),
        ),
        (
            "integration",
            include_str!("../../crates/adapters/src/integration.rs"),
        ),
        ("state", include_str!("../../crates/adapters/src/state.rs")),
        (
            "native_agent",
            include_str!("../../crates/adapters/src/native_agent.rs"),
        ),
    ] {
        let lower = source.to_ascii_lowercase();
        for path in [
            ".1password",
            "1password/agent",
            "group containers",
            "agent.toml\"",
            "2bua8c4s2c",
        ] {
            assert!(!lower.contains(path), "{name} hardcodes {path}");
        }
    }
}
