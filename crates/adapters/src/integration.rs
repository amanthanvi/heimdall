//! The consumer integration `prepare` materializes (m02-plan U6; ADR-0007 §7, §8), and
//! the core both existing-access adapters share.
//!
//! **`prepare` is local and passive.** It stats the agent endpoints (it never connects
//! to them), takes the static identity selection of the managed aliases from its
//! sources (the runtime's [`IntegrationSources::observe_aliases`] is the
//! `ProjectionWriter::observe` handle, U5), applies the one eligibility and clearance
//! rule ([`crate::state`]), and returns the integration.
//!
//! ⟨M02⟩ **Two steps, one bound** (ADR-0007 §12.23 item 2, U02). The runtime first
//! calls `CredentialAdapter::read_sources` outside `bounded_adapter_call`: every
//! store and file read (`observe_aliases`, `catalog_identities`, `declarations`,
//! `executables`) happens there, into an in-memory
//! [`IntegrationSnapshot`](heimdall_app::ports::IntegrationSnapshot), which is itself
//! an [`IntegrationSources`]. The bounded `prepare_from` then does only evaluation
//! over that snapshot and one metadata call (`stat`) per endpoint; it waits on no lock
//! and no other I/O, and nothing is detached past the bound. Residual: an endpoint
//! `stat` on a hung network file system is not interruptible. `prepare` and
//! `prepare_detailed` read their own sources first (the same two steps in one call,
//! for direct callers; the runtime never bounds them). The integration is:
//! * `environment`: `SSH_AUTH_SOCK` set to the endpoint only when every pair uses that
//!   one endpoint; otherwise nothing is set and an `SSH_AUTH_SOCK` override from the
//!   environment is reported (ADR-0007 §8);
//! * `executables` (the verified clients the sources name) and `overrides` (an
//!   `IdentityAgent` the user's configuration sets for a pair's alias, which wins over
//!   `SSH_AUTH_SOCK`, F8);
//! * `pairs`: one per destination/account pair, with its endpoint, alias, fresh
//!   interaction and eligibility, and the static selection verdict.
//!
//! **The full selection crosses the port** (ADR-0007 §12.14 item 6). Each pair's
//! whole `IdentitySelectionReport` (entries, `identities_only`, and each
//! alternative's `cleared` from the domain clearance rule) travels in
//! `PairIntegration.identity_selection_report` (§12.15 item 3(c)), which the runtime
//! stores in the prepared facts; [`Prepared`] carries it too. A missing report clears
//! nothing.
//!
//! **No effect outlives the call.** The integration is a returned value; nothing is
//! written anywhere. `reconcile` answers from the integrations this instance returned
//! (a bounded in-memory record, keyed by grant and effect token): `applied` with the
//! same outcome when it has one, else `not_applied`, which is true (nothing exists
//! outside the runtime's own records, so a fresh `prepare` is safe); never `unknown`.
//! A restart empties that record, so for a **confirmed** effect the runtime answers
//! `not_applied` from the `PreparedFacts` it recorded with the confirmation, never
//! from this memory (ADR-0007 §12.15 item 7, E-U6-6; the descriptor's
//! `external_side_effects: false` is what allows it).
//! `revoke` removes the record and reports no remote effect and no expiry: the key
//! stays usable outside Heimdall, and the enforcement report already says so.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use heimdall_app::ports::{
    AdapterDescriptor, AdapterError, DetectContext, IdentityListing, IntegrationSnapshot,
    InteractionRequirement, ListedIdentity, LockContinuity, PrepareOutcome, PreparePair,
    PrepareRequest, ProbeBounds, ReconcileOutcome, RevokeOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::doctor::{AliasDefinition, AliasObservation, DirectiveCertainty};
use heimdall_contract::ids::{GrantId, IdentityId};
use heimdall_contract::provider::{
    EndpointKind, EndpointRef, EvidenceBasis, IdentitiesOnly, IdentityEntrySource,
    IdentitySelection, IdentitySelectionReport, InteractionKind, NoninteractiveEligibility,
    ProviderKind, ProviderStatus, noninteractive_reason,
};
use heimdall_contract::request::{
    Capability, ConsumerExecutable, ConsumerIntegration, ConsumerKind, ConsumerOverride,
    DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy, NewAuthenticationExpiry,
    OverrideSource, PairIntegration, RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_domain::catalog::{
    FallbackClearance, IdentityRecord, InteractionDeclaration, PairEligibility, PreparedPair,
};
use heimdall_domain::evidence::{EnforcementEvidence, EvidenceRef, SupportLabel};
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::time::Clock;
use heimdall_ipc::agent_client::{self, AgentClientError, ClientBounds};

use crate::detect::{self, EndpointPresence};
use crate::state::{self, PairReadiness};

/// The environment variable a launcher sets for the agent.
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// The `IdentityAgent` directive (canonical case).
pub const IDENTITY_AGENT: &str = "IdentityAgent";

/// The evidence mechanism behind a `client_routing` claim: the managed alias renders
/// `HostName`, `User`, `Port`, `IdentityAgent`, `IdentityFile` and `IdentitiesOnly`
/// (ADR-0007 §7 "Identity selection"); its end-to-end evidence is A35.
pub const CLIENT_ROUTING_MECHANISM: &str = "managed_alias_client_routing";

/// How many prepared integrations one adapter instance remembers for `reconcile`.
const MEMO_CAPACITY: usize = 256;

/// What `prepare` reads besides its request. The runtime wiring (U5) implements it
/// over the projection writer, the store and the client discovery. Every method is
/// passive, and its default claims nothing, which fails closed: no observation leaves
/// the selection `undetermined`, no declaration leaves a native key `unknown`, no
/// catalog identity clears no fallback.
///
/// ⟨M02⟩ ADR-0007 §12.23 item 2: a live implementation (the runtime's) may wait on the
/// store or the file system, so it is read only in `read_sources`, outside the
/// adapter bound. The bounded call evaluates over the in-memory
/// [`IntegrationSnapshot`] built from it, which implements this trait too.
pub trait IntegrationSources: Send + Sync {
    /// The static observation of `aliases` (`ProjectionWriter::observe` over the
    /// current projection record).
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
        let _ = aliases;
        Vec::new()
    }

    /// Every catalog identity (fallback clearance looks alternatives up here).
    fn catalog_identities(&self) -> Vec<IdentityRecord> {
        Vec::new()
    }

    /// The identity's declaration row, when one exists.
    fn declaration(&self, identity: &IdentityId) -> Option<InteractionDeclaration> {
        let _ = identity;
        None
    }

    /// ⟨M02⟩ The declaration rows of `identities` that have one, in one read where
    /// the source can (default: [`Self::declaration`] for each).
    fn declarations(
        &self,
        identities: &[IdentityId],
    ) -> BTreeMap<IdentityId, InteractionDeclaration> {
        identities
            .iter()
            .filter_map(|id| self.declaration(id).map(|d| (id.clone(), d)))
            .collect()
    }

    /// The verified client executables the integration relies on.
    fn executables(&self) -> Vec<ConsumerExecutable> {
        Vec::new()
    }
}

/// Sources that claim nothing (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSources;

impl IntegrationSources for NoSources {}

/// ⟨M02⟩ ADR-0007 §12.23 item 2: the in-memory snapshot as sources. Every method is a
/// read of memory; nothing here waits on a lock or does I/O.
impl IntegrationSources for IntegrationSnapshot {
    fn observe_aliases(&self, aliases: &[String]) -> Vec<AliasObservation> {
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

    fn executables(&self) -> Vec<ConsumerExecutable> {
        self.executables.clone()
    }
}

/// The managed aliases of `pairs`, sorted and without duplicates.
fn aliases_of(pairs: &[PreparePair]) -> Vec<String> {
    pairs
        .iter()
        .filter_map(|p| p.alias.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// ⟨M02⟩ ADR-0007 §12.23 item 2: read everything `prepare` needs for `pairs` from
/// `sources`, once: the aliases' observation (only when a pair has an alias), the
/// catalog identities and the declaration rows of the pairs' and the catalog's
/// identities (only when there is a pair), and the executables.
#[must_use]
pub fn snapshot_of(sources: &dyn IntegrationSources, pairs: &[PreparePair]) -> IntegrationSnapshot {
    let aliases = aliases_of(pairs);
    let observations = if aliases.is_empty() {
        Vec::new()
    } else {
        sources.observe_aliases(&aliases)
    };
    let (identities, declarations) = if pairs.is_empty() {
        (Vec::new(), BTreeMap::new())
    } else {
        let identities = sources.catalog_identities();
        let ids: Vec<IdentityId> = pairs
            .iter()
            .map(|p| p.identity.id.clone())
            .chain(identities.iter().map(|r| r.id.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let declarations = sources.declarations(&ids);
        (identities, declarations)
    };
    IntegrationSnapshot {
        observations,
        identities,
        declarations,
        executables: sources.executables(),
        managed: None, // M03 wave 0 (A2)
    }
}

/// One pair as `prepare` established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairDetail {
    /// The pair as the port reports it.
    pub pair: PairIntegration,
    /// The full static selection, with `cleared` filled on every alternative when a
    /// clearance was evaluated.
    pub selection: IdentitySelectionReport,
    /// The identity's fresh eligibility.
    pub eligibility: PairEligibility,
    /// The fallback clearance (absent for an `exclusive` selection).
    pub clearance: Option<FallbackClearance>,
}

/// What `prepare` established: the port outcome and each pair's detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The outcome `prepare` returns.
    pub outcome: PrepareOutcome,
    /// Per pair, in the request's order.
    pub pairs: Vec<PairDetail>,
}

impl Prepared {
    /// The history part of each pair (`PreparedFacts.pairs`), with the full
    /// selection report: no interaction, availability or eligibility field
    /// (M2-R04).
    #[must_use]
    pub fn prepared_pairs(&self) -> Vec<PreparedPair> {
        self.pairs
            .iter()
            .map(|d| PreparedPair {
                destination: d.pair.destination.clone(),
                account: d.pair.account.clone(),
                identity: d.pair.identity.clone(),
                mechanism: d.pair.mechanism.clone(),
                endpoint: d.pair.endpoint.clone(),
                alias: d.pair.alias.clone(),
                identity_selection: d.selection.clone(),
                selection_observed_at: d.pair.selection_observed_at,
            })
            .collect()
    }
}

/// The enforcement an existing-access adapter can claim at best, for its descriptor:
/// `client_routing` (for managed aliases), no expiry of new authentication, a shared
/// OS user, and nothing known about existing connections or revocation (ADR-0007 §7;
/// F12: never isolation or destination enforcement beyond routing). The evidence is a
/// capability statement, not an observation: it is never fresh.
#[must_use]
pub fn descriptor_enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: report(DestinationScopeEnforcement::ClientRouting),
        evidence: vec![routing_evidence(Timestamp::UNIX_EPOCH, Duration::ZERO)],
    }
}

/// The enforcement of one prepared integration (ADR-0007 §7 `prepare`):
/// `destination_scope` is `client_routing` when every pair goes through a managed
/// alias, else `unenforced_intent`; `new_authentication_expiry` `none`;
/// `workload_isolation` `shared_os_user`; `existing_connections` and `revocation`
/// `unknown`.
#[must_use]
pub fn enforcement(all_managed: bool, now: Timestamp, until: Timestamp) -> EnforcementEvidence {
    if all_managed {
        let fresh = Duration::try_from(now.duration_until(until)).unwrap_or(Duration::ZERO);
        EnforcementEvidence {
            report: report(DestinationScopeEnforcement::ClientRouting),
            evidence: vec![routing_evidence(now, fresh)],
        }
    } else {
        // Every field at its weakest label: no evidence is needed.
        EnforcementEvidence {
            report: report(DestinationScopeEnforcement::UnenforcedIntent),
            evidence: Vec::new(),
        }
    }
}

fn report(destination_scope: DestinationScopeEnforcement) -> Enforcement {
    Enforcement {
        destination_scope,
        new_authentication_expiry: NewAuthenticationExpiry::None,
        workload_isolation: WorkloadIsolation::SharedOsUser,
        existing_connections: ExistingConnectionsPolicy::Unknown,
        revocation: RevocationStatus::Unknown,
        // M03 wave 0 (A1): fail closed until U0b
        identity_selection: None,
        new_signing_expiry: None,
        owned_multiplexing: None,
        remote_processes: None,
        unmanaged_connections: None,
        issuer_isolation: None,
    }
}

fn routing_evidence(observed_at: Timestamp, freshness: Duration) -> EvidenceRef {
    EvidenceRef {
        mechanism: CLIENT_ROUTING_MECHANISM.to_owned(),
        test_id: Some("A35".to_owned()),
        versions: Vec::new(),
        observed_at,
        freshness,
        // M02 stays implemented_unverified until U11's evidence exists.
        label: SupportLabel::NotTested,
    }
}

/// An agent-client failure as an adapter error. Nonsecret: only static text and
/// counts.
#[must_use]
pub fn adapter_error(e: &AgentClientError) -> AdapterError {
    match e {
        AgentClientError::AgentFailure => AdapterError::ProviderLocked,
        AgentClientError::NotFound
        | AgentClientError::Refused(_)
        | AgentClientError::ForeignPeer
        | AgentClientError::Timeout
        | AgentClientError::Io(_) => AdapterError::Unavailable(e.to_string()),
        other => AdapterError::Protocol(other.to_string()),
    }
}

/// The `SSH_AUTH_SOCK` value for an endpoint, when one can carry it: a socket path,
/// or a pipe path whose name is ASCII (a non-ASCII pipe name fails in
/// `SSH_AUTH_SOCK`, ADR-0007 F14).
#[must_use]
pub fn auth_sock_value(endpoint: &EndpointRef) -> Option<String> {
    match endpoint.kind {
        EndpointKind::UnixSocket => Some(endpoint.locator.clone()),
        EndpointKind::NamedPipe => {
            agent_client::pipe_path(&endpoint.locator).filter(|p| p.is_ascii())
        }
        _ => None,
    }
}

fn endpoint_key(endpoint: &EndpointRef) -> String {
    let kind = match endpoint.kind {
        EndpointKind::UnixSocket => "unix_socket",
        EndpointKind::NamedPipe => "named_pipe",
        _ => "unknown",
    };
    format!("{kind}:{}", endpoint.locator)
}

/// The undetermined selection: what is reported when no observation exists.
#[must_use]
pub fn undetermined_selection() -> IdentitySelectionReport {
    IdentitySelectionReport {
        selection: IdentitySelection::Undetermined,
        entries: Vec::new(),
        identities_only: IdentitiesOnly::Undetermined,
    }
}

/// The selection reported for `identity` from its alias's observation. An
/// `exclusive` verdict stands only when a managed entry carries the identity's own
/// fingerprint; otherwise the projection does not select the adopted key and the
/// verdict is `undetermined` (fail closed). Any `cleared` the observation carried is
/// dropped: `prepare` evaluates clearance itself.
#[must_use]
pub fn selection_for(
    identity: &IdentityRecord,
    observation: Option<&AliasObservation>,
) -> IdentitySelectionReport {
    let Some(mut report) = observation.and_then(|o| o.identity_selection.clone()) else {
        return undetermined_selection();
    };
    for entry in &mut report.entries {
        entry.cleared = None;
    }
    let adopted = report.entries.iter().any(|e| {
        e.source == IdentityEntrySource::Managed
            && e.fingerprint.as_deref() == Some(identity.fingerprint.as_str())
    });
    if report.selection == IdentitySelection::Exclusive && !adopted {
        report.selection = IdentitySelection::Undetermined;
    }
    report
}

/// Fill `cleared` on every alternative from the clearance: each entry not from the
/// managed projection, and each managed entry the clearance did not clear (a managed
/// entry that is not the adopted key, ADR-0007 §12.15 item 3(d)). The adopted
/// identity's own managed entry stays unmarked.
pub fn mark_cleared(report: &mut IdentitySelectionReport, clearance: &FallbackClearance) {
    for (i, entry) in report.entries.iter_mut().enumerate() {
        let uncleared = clearance.uncleared.contains(&i);
        entry.cleared = if entry.source != IdentityEntrySource::Managed {
            Some(!uncleared)
        } else if uncleared {
            Some(false)
        } else {
            None
        };
    }
}

/// The `IdentityAgent` overrides an observation shows for an alias the user defines:
/// an effective `IdentityAgent` wins over `SSH_AUTH_SOCK` (F8).
fn identity_agent_overrides(observation: &AliasObservation, out: &mut Vec<ConsumerOverride>) {
    if observation.definition == AliasDefinition::Managed {
        return;
    }
    for directive in &observation.behavior {
        if directive.directive != IDENTITY_AGENT || directive.certainty == DirectiveCertainty::Unset
        {
            continue;
        }
        for provenance in &directive.provenance {
            let o = ConsumerOverride {
                consumer: ConsumerKind::Ssh,
                setting: IDENTITY_AGENT.to_owned(),
                source: OverrideSource::SshConfig(provenance.clone()),
            };
            if !out.contains(&o) {
                out.push(o);
            }
        }
    }
}

/// The eligibility of an identity that is not in the catalog: `unknown`, never
/// eligible (nothing is known about it).
fn uncatalogued() -> PairEligibility {
    PairEligibility {
        interaction: InteractionKind::Unknown,
        basis: EvidenceBasis::Inferred,
        declaration: None,
        noninteractive: NoninteractiveEligibility {
            eligible: false,
            reason: Some(noninteractive_reason::INTERACTION_UNKNOWN.to_owned()),
        },
    }
}

type MemoKey = (GrantId, String);

/// The integrations this instance returned, for `reconcile` (bounded, oldest first
/// out).
#[derive(Debug, Default)]
struct Memo {
    order: VecDeque<MemoKey>,
    outcomes: BTreeMap<MemoKey, PrepareOutcome>,
}

impl Memo {
    fn put(&mut self, key: MemoKey, outcome: PrepareOutcome) {
        if self.outcomes.insert(key.clone(), outcome).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > MEMO_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.outcomes.remove(&old);
            }
        }
    }

    fn forget_grant(&mut self, grant: &GrantId) {
        self.order.retain(|(g, _)| g != grant);
        self.outcomes.retain(|(g, _), _| g != grant);
    }
}

/// The part both adapters share.
#[derive(Clone)]
pub(crate) struct Core {
    pub(crate) provider: ProviderKind,
    pub(crate) mechanism: &'static str,
    pub(crate) descriptor: AdapterDescriptor,
    pub(crate) endpoint: Option<EndpointRef>,
    refresh: RefreshDependency,
    sources: Arc<dyn IntegrationSources>,
    clock: Option<Arc<dyn Clock>>,
    memo: Arc<Mutex<Memo>>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("provider", &self.provider)
            .field("descriptor", &self.descriptor)
            .field("endpoint", &self.endpoint)
            .field("refresh", &self.refresh)
            .finish_non_exhaustive()
    }
}

impl Core {
    pub(crate) fn new(
        provider: ProviderKind,
        mechanism: &'static str,
        lock_continuity: LockContinuity,
        refresh: RefreshDependency,
        instance: String,
        endpoint: Option<EndpointRef>,
    ) -> Self {
        Self {
            provider,
            mechanism,
            descriptor: AdapterDescriptor {
                identity: AdapterIdentity {
                    mechanism: mechanism.to_owned(),
                    instance,
                },
                capabilities: BTreeSet::from([Capability::SshAuthentication]),
                external_side_effects: false,
                // A native key may carry a confirmation constraint (ADR-0007 F23);
                // 1Password asks for approval.
                interaction: InteractionRequirement::ProviderDialog,
                enforcement: descriptor_enforcement(),
                lock_continuity,
                remote_credential_effect: false, // M03 wave 0 (A2)
            },
            endpoint,
            refresh,
            sources: Arc::new(NoSources),
            clock: None,
            memo: Arc::new(Mutex::new(Memo::default())),
        }
    }

    pub(crate) fn set_sources(&mut self, sources: Arc<dyn IntegrationSources>) {
        self.sources = sources;
    }

    pub(crate) fn set_clock(&mut self, clock: Arc<dyn Clock>) {
        self.clock = Some(clock);
    }

    fn now(&self) -> Timestamp {
        self.clock
            .as_ref()
            .map_or_else(Timestamp::now, |c| c.wall())
    }

    fn memo(&self) -> MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// ⟨M02⟩ ADR-0007 §12.23 item 2: this instance's sources read once for `pairs`
    /// (store and file reads; never inside the adapter bound).
    pub(crate) fn read_sources(&self, pairs: &[PreparePair]) -> IntegrationSnapshot {
        snapshot_of(self.sources.as_ref(), pairs)
    }

    /// `prepare` (and `renew`) over `sources`: local, passive, synchronous, with no
    /// read but `sources` and one endpoint `stat`. Remembers the outcome for
    /// `reconcile`.
    pub(crate) fn prepare(
        &self,
        req: &PrepareRequest<'_>,
        sources: &dyn IntegrationSources,
    ) -> Result<Prepared, AdapterError> {
        let prepared = self.establish(req, sources)?;
        self.memo().put(
            (req.grant.id.clone(), req.effect_token.to_owned()),
            prepared.outcome.clone(),
        );
        Ok(prepared)
    }

    /// `prepare` that reads this instance's sources first (both steps in one call,
    /// for direct callers; the runtime bounds only [`Self::prepare`] over a snapshot).
    pub(crate) fn prepare_reading(
        &self,
        req: &PrepareRequest<'_>,
    ) -> Result<Prepared, AdapterError> {
        let sources = self.read_sources(req.pairs);
        self.prepare(req, &sources)
    }

    fn establish(
        &self,
        req: &PrepareRequest<'_>,
        sources: &dyn IntegrationSources,
    ) -> Result<Prepared, AdapterError> {
        let now = req.now;
        // One mechanism per grant (ADR-0007 §7): a pair of another mechanism never
        // reaches this adapter through the runtime; refuse it if it does.
        if req
            .pairs
            .iter()
            .any(|p| p.identity.source.mechanism() != self.mechanism)
        {
            return Err(AdapterError::CapabilityUnavailable);
        }

        // Endpoints: the identity's own, else this instance's.
        let endpoints: Vec<Option<EndpointRef>> = req
            .pairs
            .iter()
            .map(|p| {
                p.identity
                    .source
                    .endpoint()
                    .or(self.endpoint.as_ref())
                    .cloned()
            })
            .collect();
        let used: BTreeSet<EndpointRef> = if req.pairs.is_empty() {
            self.endpoint.iter().cloned().collect()
        } else {
            endpoints.iter().flatten().cloned().collect()
        };
        let all_known = endpoints.iter().all(Option::is_some) && !used.is_empty();
        let presence = all_known.then(|| {
            used.iter()
                .map(detect::observe_endpoint)
                .find(|p| *p != EndpointPresence::Present)
                .unwrap_or(EndpointPresence::Present)
        });
        let status = detect::passive_status(self.provider, presence, now);
        if presence != Some(EndpointPresence::Present) {
            // Row 1 of the table; nothing else is evaluated.
            return Err(state::Refusal::EndpointAbsent {
                provider: self.provider,
            }
            .adapter_error());
        }

        // Static selection of the managed aliases, from the sources.
        let aliases = aliases_of(req.pairs);
        let observations = if aliases.is_empty() {
            Vec::new()
        } else {
            sources.observe_aliases(&aliases)
        };
        let by_alias: BTreeMap<&str, &AliasObservation> =
            observations.iter().map(|o| (o.alias.as_str(), o)).collect();
        let mut catalog: Option<Vec<IdentityRecord>> = None;

        let mut details = Vec::with_capacity(req.pairs.len());
        let mut readiness = Vec::with_capacity(req.pairs.len());
        let mut overrides = Vec::new();
        for (p, endpoint) in req.pairs.iter().zip(endpoints.into_iter().flatten()) {
            let declaration = sources.declaration(&p.identity.id);
            let eligibility =
                state::pair_eligibility(&p.identity, declaration.as_ref(), &endpoint, now);
            let observation = p.alias.as_deref().and_then(|a| by_alias.get(a).copied());
            if let Some(o) = observation {
                identity_agent_overrides(o, &mut overrides);
            }
            let mut selection = selection_for(&p.identity, observation);
            let clearance = if selection.selection == IdentitySelection::Exclusive {
                None
            } else {
                let catalog = catalog.get_or_insert_with(|| sources.catalog_identities());
                let eligibility_of = |id: &IdentityId| -> PairEligibility {
                    match catalog.iter().find(|r| &r.id == id) {
                        Some(r) => state::pair_eligibility(
                            r,
                            sources.declaration(id).as_ref(),
                            r.source.endpoint().unwrap_or(&endpoint),
                            now,
                        ),
                        None => uncatalogued(),
                    }
                };
                // ⟨M02⟩ ADR-0007 §12.15 item 3(d): the one domain rule, which takes
                // the adopted identity's fingerprint.
                let c = state::fallback_clearance(
                    &selection,
                    catalog,
                    &eligibility_of,
                    &endpoint,
                    &p.identity.fingerprint,
                );
                mark_cleared(&mut selection, &c);
                Some(c)
            };
            let judged = PairReadiness {
                eligibility: eligibility.clone(),
                selection: selection.selection,
                clearance: clearance.clone(),
            };
            let declared_at = eligibility
                .declaration
                .as_ref()
                .and(declaration.as_ref())
                .map(|d| d.declared_at);
            let pair = PairIntegration {
                destination: p.destination.clone(),
                account: p.account.clone(),
                identity: p.identity.id.clone(),
                mechanism: self.mechanism.to_owned(),
                endpoint: Some(endpoint.clone()),
                alias: p.alias.clone(),
                interaction: eligibility.interaction,
                interaction_basis: eligibility.basis,
                declared_at,
                identity_selection: selection.selection,
                selection_observed_at: now,
                declaration: eligibility.declaration.clone(),
                noninteractive: judged.noninteractive(),
                eligibility_checked_at: now,
                // ⟨M02⟩ ADR-0007 §12.15 item 3(c): the full selection crosses the
                // port (§12.14 item 6), with each alternative's `cleared`.
                identity_selection_report: Some(selection.clone()),
            };
            readiness.push(judged);
            details.push(PairDetail {
                pair,
                selection,
                eligibility,
                clearance,
            });
        }

        let availability = state::readiness(
            &status,
            &readiness,
            req.interactive,
            req.required.unattended,
            self.descriptor.lock_continuity,
        )
        .map_err(|r| r.adapter_error())?;

        // SSH_AUTH_SOCK only when every pair uses one endpoint (ADR-0007 §8).
        let mut environment = Vec::new();
        let single = if used.len() == 1 {
            used.iter().next().and_then(auth_sock_value)
        } else {
            None
        };
        match single {
            Some(value) => environment.push((SSH_AUTH_SOCK.to_owned(), value)),
            None => overrides.push(ConsumerOverride {
                consumer: ConsumerKind::Ssh,
                setting: SSH_AUTH_SOCK.to_owned(),
                source: OverrideSource::Environment,
            }),
        }

        let credential_ref = {
            let parts: BTreeSet<String> = if details.is_empty() {
                used.iter().map(endpoint_key).collect()
            } else {
                req.pairs
                    .iter()
                    .zip(&details)
                    .map(|(p, d)| {
                        let ep = d
                            .pair
                            .endpoint
                            .as_ref()
                            .map(endpoint_key)
                            .unwrap_or_default();
                        format!("{ep}#{}", p.identity.fingerprint)
                    })
                    .collect()
            };
            format!(
                "{}/{}",
                self.mechanism,
                parts.into_iter().collect::<Vec<_>>().join(";")
            )
        };
        let until = now.min(req.grant.deadline.effective);
        let all_managed = !req.pairs.is_empty() && req.pairs.iter().all(|p| p.alias.is_some());
        let outcome = PrepareOutcome {
            // No claim beyond now: an existing key's later availability is unknown.
            usable_until: until,
            offline_until: until,
            refresh_dependency: self.refresh,
            enforcement: enforcement(all_managed, now, req.grant.deadline.effective),
            credential_ref,
            availability,
            provider: Some(status),
            integration: ConsumerIntegration {
                signing_endpoint: None,
                ssh_config_include: None,
                environment,
                executables: sources.executables(),
                overrides,
                pairs: details.iter().map(|d| d.pair.clone()).collect(),
            },
            managed: None,
        };
        Ok(Prepared {
            outcome,
            pairs: details,
        })
    }

    /// `reconcile`: the outcome this instance returned for the token, else
    /// `not_applied`. Never performs the effect, never `unknown`.
    pub(crate) fn reconcile(&self, grant: &GrantId, effect_token: &str) -> ReconcileOutcome {
        let key = (grant.clone(), effect_token.to_owned());
        match self.memo().outcomes.get(&key) {
            Some(outcome) => ReconcileOutcome::Applied(outcome.clone()),
            None => ReconcileOutcome::NotApplied,
        }
    }

    /// `revoke`: forget the grant's integrations; nothing remote, no expiry.
    pub(crate) fn revoke(&self, grant: &GrantId) -> RevokeOutcome {
        self.memo().forget_grant(grant);
        RevokeOutcome {
            remote_pending: Vec::new(),
            latest_possible_credential_expiry: None,
            remote_effects: Vec::new(), // M03 wave 0 (A2)
        }
    }

    /// Passive status at the context's endpoint, else this instance's.
    pub(crate) fn detect(&self, ctx: &DetectContext) -> ProviderStatus {
        let endpoint = ctx.endpoint.as_ref().or(self.endpoint.as_ref());
        detect::passive_status(
            self.provider,
            endpoint.map(detect::observe_endpoint),
            ctx.now,
        )
    }

    /// The explicit `agent` probe at this instance's endpoint: a passive look first
    /// (a socket owned by another user is never connected to), then one bounded
    /// listing.
    pub(crate) async fn list_identities(
        &self,
        bounds: &ProbeBounds,
    ) -> Result<IdentityListing, AdapterError> {
        let Some(endpoint) = self.endpoint.clone() else {
            return Err(AdapterError::Unavailable(
                "no agent endpoint is known".to_owned(),
            ));
        };
        let presence = detect::observe_endpoint(&endpoint);
        if presence != EndpointPresence::Present {
            return Err(AdapterError::Unavailable(presence.describe().to_owned()));
        }
        let Some(locator) = detect::locator(&endpoint) else {
            return Err(AdapterError::Unavailable(
                "agent endpoint transport not supported".to_owned(),
            ));
        };
        let client = ClientBounds {
            timeout: bounds.timeout,
            max_reply_bytes: bounds.max_reply_bytes,
            max_identities: bounds.max_identities,
        };
        let listing = agent_client::list_identities(&locator, &client)
            .await
            .map_err(|e| adapter_error(&e))?;
        Ok(IdentityListing {
            endpoint,
            identities: listing
                .identities
                .into_iter()
                .map(|i| ListedIdentity {
                    key_type: i.key_type,
                    fingerprint: i.fingerprint,
                })
                .collect(),
            observed_at: self.now(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn auth_sock_values() {
        let sock = EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: "/scratch/a.sock".into(),
        };
        assert_eq!(auth_sock_value(&sock).as_deref(), Some("/scratch/a.sock"));
        let pipe = EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: "//./pipe/agent".into(),
        };
        assert_eq!(auth_sock_value(&pipe).as_deref(), Some(r"\\.\pipe\agent"));
        let non_ascii = EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: "agent-\u{e9}".into(),
        };
        assert_eq!(auth_sock_value(&non_ascii), None);
    }

    #[test]
    fn adapter_errors_are_classified() {
        assert_eq!(
            adapter_error(&AgentClientError::AgentFailure),
            AdapterError::ProviderLocked
        );
        assert!(matches!(
            adapter_error(&AgentClientError::Timeout),
            AdapterError::Unavailable(_)
        ));
        assert!(matches!(
            adapter_error(&AgentClientError::TooManyIdentities { declared: 2000 }),
            AdapterError::Protocol(_)
        ));
    }

    #[test]
    fn descriptor_enforcement_is_never_fresh() {
        let e = descriptor_enforcement();
        assert_eq!(
            e.report.destination_scope,
            DestinationScopeEnforcement::ClientRouting
        );
        assert!(
            e.evidence
                .iter()
                .all(|r| !r.is_fresh_at(Timestamp::UNIX_EPOCH))
        );
    }
}
