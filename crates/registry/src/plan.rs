//! The enrollment plan (ADR-0008 D5 §6.1; §17.4 item 9; m03-plan U5 "Interfaces"),
//! moved below `app` so that `app` calls it directly, through no port (§0.6).
//!
//! The signatures of [`build`] and [`plan_digest`] are frozen in wave 0 (U0); their
//! bodies are U5's.
//!
//! **Inputs.** The frozen signature has no slot for the facts that are neither
//! catalog, target nor CA facts: the new enrollment's ID (the marker), the generated
//! host-trust files, the Q24 alias `IdentityAgent` reading, the pair's other
//! enrollments (the uniqueness rule) and the lock-continuity acknowledgement. They
//! travel in the registry-owned [`CaView`] as [`CaView::context`] (with the issuer
//! state in [`CaView::issuer`]); a view without a context refuses with
//! [`PlanRefusal::DriverUnavailable`] (U5P-Q1).
//!
//! **Preconditions** (the D5 §6.1 table, checked in its order; the first that fails
//! is the refusal): a CA registered and the issuer `ready`; the destination managed;
//! the principal charset; a statically determined, direct route; exactly one
//! non-revoked, pinnable host key; no account override (`--account`, or a
//! configuration whose evaluated `User` is not the catalog's account); an adopted
//! identity of a kind that can drive the steps; a concrete existing-access endpoint
//! that is not Heimdall's (from the catalog record, or the Q24 default; never
//! `SSH_AUTH_SOCK`); no live enrollment for the (pair, CA) (the store's partial-index
//! rule: `abandoned`, removal states and finals are outside it); a valid
//! `--registry-path`.
//!
//! **The plan** names the approved target, the existing-access invocation with its
//! concrete endpoint, the host-trust pins, the conditional bootstrap step (account
//! form), the registry, the exact line and its SHA-256, the CA, the verification and
//! rollback, and the disclosures. [`plan_digest`] covers every field but itself: the
//! canonical JSON (sorted keys) of the plan without `plan_digest`, SHA-256
//! domain-separated by [`DIGEST_CONTEXT`], as bare 64-character lowercase hex
//! (§17.15 X-Q4).

use heimdall_contract::Code;
use heimdall_contract::enrollment::{
    ApprovedTarget, BootstrapPlan, DisclosureKind, EndpointSource, EnrollmentForm, EnrollmentPlan,
    EnrollmentSpec, EnrollmentState, ExistingAccessPlan, NoProxy, RegistryRef, RegistryResolvedBy,
    RollbackPlan, VerificationPlan,
};
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{AccountName, CaFingerprint, EnrollmentId};
use heimdall_contract::issuer::{CaState, IssuerState};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::setup::PlanDigest;
use heimdall_domain::catalog::{DestinationDefinition, IdentitySource};
use heimdall_domain::enrollment::{
    CatalogView, Determinism, ProxyRoute, RawHostKey, TargetEvaluation,
};
use heimdall_domain::projection::Sha256Hex;

use crate::line;
use crate::step::{self, TrustPaths};

/// The `plan_digest` domain separation (with `heimdall-request-hash/1` of
/// `heimdall_contract::canonical::request_hash`).
pub const DIGEST_CONTEXT: &str = "heimdall-enrollment-plan-digest/1";

/// The display form of the default registry.
pub const REMOTE_HOME_DISPLAY: &str = "$HOME/.ssh/authorized_keys";

/// The verification certificates' validity ceiling (`verification_max_validity`).
pub const VERIFICATION_MAX_VALIDITY_SECONDS: u64 = 300;

/// ⟨U5⟩ The `USAGE_ERROR` reason of an invalid `--registry-path` (U5P-Q3; registered in
/// `contract::envelope::reason::M03` by wave 5 per ADR-0008 §17.20 item 13).
pub const REGISTRY_PATH_INVALID: &str = heimdall_contract::envelope::reason::REGISTRY_PATH_INVALID;

/// One registered CA as the plan sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaViewEntry {
    /// Fingerprint.
    pub fingerprint: CaFingerprint,
    /// State (`active` CAs are eligible; `pending` only for rotation's enrollments).
    pub state: CaState,
    /// The CA's OpenSSH public key line (the registry line's key).
    pub public_key: String,
}

/// The Q24 reading: the alias's own `IdentityAgent`, statically evaluated with P's
/// managed block excluded (`localenv::target::evaluate_identity_agent`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AgentReading {
    /// A value (a socket path or a pipe), as the configuration names it.
    Determined(String),
    /// Unset, or `none`.
    Unset,
    /// Not statically determined.
    #[default]
    Undetermined,
}

/// Another enrollment of the same pair, for the uniqueness rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PairEnrollment {
    /// Its CA.
    pub ca_fingerprint: CaFingerprint,
    /// Its state.
    pub state: EnrollmentState,
    /// Its `removal_origin` is set (a `held` row a removal reached is a residual).
    pub removal_origin_set: bool,
}

impl PairEnrollment {
    /// Whether it is live for the uniqueness rule: exactly the store's partial index
    /// `enrollments_open_pair_ca` (S1 rulings).
    #[must_use]
    pub fn live(&self) -> bool {
        use EnrollmentState as S;
        matches!(
            self.state,
            S::Planned
                | S::Applying
                | S::OutcomeUnknown
                | S::AppliedUnverified
                | S::ManualPending
                | S::Verifying
                | S::Verified
                | S::Reverifying
                | S::Held
        ) && !(self.state == S::Held && self.removal_origin_set)
    }
}

/// ⟨U5⟩ The preview facts the frozen [`build`] signature has no other slot for
/// (module docs; U5P-Q1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanContext {
    /// The new enrollment's ID (its marker is `heimdall:<id>`). Minted at preview and
    /// remembered with the digest, as M02's setup previews are.
    pub enrollment_id: EnrollmentId,
    /// The generated host-trust files (`<runtime_dir>/e/<tag>/`; [`trust_tag`]).
    pub trust_files: TrustPaths,
    /// The generated copy of the adopted public key, pinned with `IdentityFile` for
    /// an agent-held identity (one with no public key file of its own).
    pub identity_file: Option<String>,
    /// The Q24 reading, used when the identity's record names no endpoint.
    pub alias_identity_agent: AgentReading,
    /// The pair's other enrollments.
    pub pair_enrollments: Vec<PairEnrollment>,
    /// Lock continuity was acknowledged (else `lock_continuity_once` is disclosed).
    pub lock_continuity_acknowledged: bool,
}

/// The CAs the plan may choose from (`EnrollmentSpec.ca_fingerprint`, default the
/// newest active CA), the issuer's state, and the preview context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaView {
    /// Registered CAs, newest last.
    pub cas: Vec<CaViewEntry>,
    /// ⟨U5⟩ The issuer's state; `None` (unknown) refuses `issuer_unavailable`.
    pub issuer: Option<IssuerState>,
    /// ⟨U5⟩ The preview context; `None` refuses `driver_unavailable`.
    pub context: Option<PlanContext>,
}

/// Why no plan was built (ADR-0008 D5 §6.1 preconditions). Each maps to a stable
/// reason of `contract::envelope::reason::M03` (or `driver_unavailable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PlanRefusal {
    /// The plan builder lacks its context (no [`CaView::context`], an unusable
    /// generated path).
    #[error("the enrollment plan is not available in this build")]
    DriverUnavailable,
    /// An account other than the managed definition's (`USAGE_ERROR`).
    #[error("the account override is refused")]
    AccountOverrideRefused,
    /// The route is not statically determined.
    #[error("the route is undetermined")]
    RouteUndetermined,
    /// The existing access is of a kind M03 cannot use.
    #[error("the existing-access kind is unsupported")]
    ExistingAccessKindUnsupported,
    /// The existing-access endpoint is neither recorded nor statically determined.
    #[error("the existing-access endpoint is unrecorded")]
    ExistingAccessEndpointUnrecorded,
    /// The existing-access endpoint is (or resolves to) a Heimdall endpoint.
    #[error("the existing-access endpoint is Heimdall's")]
    ExistingAccessEndpointIsHeimdall,
    /// ⟨U5⟩ No CA is registered (or the named one is not).
    #[error("the issuer is not initialized")]
    IssuerNotInitialized,
    /// ⟨U5⟩ The issuer is not `ready`.
    #[error("the issuer is unavailable")]
    IssuerUnavailable,
    /// ⟨U5⟩ The named CA is retiring or retired.
    #[error("the CA is retiring")]
    CaRetiring,
    /// ⟨U5⟩ The destination is observed, not managed.
    #[error("the alias is not managed")]
    ObservedAliasUnmanaged,
    /// ⟨U5⟩ The destination ID or account is outside `[A-Za-z0-9._-]`.
    #[error("the principal is outside the permitted character set")]
    PrincipalCharset,
    /// ⟨U5⟩ The route uses a proxy (M04), or the alias is not a literal host name.
    #[error("the route is unsupported")]
    RouteUnsupported,
    /// ⟨U5⟩ Not exactly one non-revoked, pinnable known host key.
    #[error("the host trust is undetermined")]
    HostTrustUndetermined,
    /// ⟨U5⟩ No identity is adopted for the alias.
    #[error("the pair is not adopted")]
    PairNotAdopted,
    /// ⟨U5⟩ A live enrollment exists for the (pair, CA) (`CONFIG_CONFLICT`).
    #[error("the pair is already enrolled under this CA")]
    AlreadyEnrolled,
    /// ⟨U5⟩ `--registry-path` is invalid (`USAGE_ERROR`; U5P-Q3).
    #[error("the registry path is invalid")]
    RegistryPathInvalid,
}

impl PlanRefusal {
    /// The stable sub-reason (`data.error.reason`).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            PlanRefusal::DriverUnavailable => reason::DRIVER_UNAVAILABLE,
            PlanRefusal::AccountOverrideRefused => reason::ACCOUNT_OVERRIDE_REFUSED,
            PlanRefusal::RouteUndetermined => reason::ROUTE_UNDETERMINED,
            PlanRefusal::ExistingAccessKindUnsupported => reason::EXISTING_ACCESS_KIND_UNSUPPORTED,
            PlanRefusal::ExistingAccessEndpointUnrecorded => {
                reason::EXISTING_ACCESS_ENDPOINT_UNRECORDED
            }
            PlanRefusal::ExistingAccessEndpointIsHeimdall => {
                reason::EXISTING_ACCESS_ENDPOINT_IS_HEIMDALL
            }
            PlanRefusal::IssuerNotInitialized => reason::ISSUER_NOT_INITIALIZED,
            PlanRefusal::IssuerUnavailable => reason::ISSUER_UNAVAILABLE,
            PlanRefusal::CaRetiring => reason::CA_RETIRING,
            PlanRefusal::ObservedAliasUnmanaged => reason::OBSERVED_ALIAS_UNMANAGED,
            PlanRefusal::PrincipalCharset => reason::PRINCIPAL_CHARSET,
            PlanRefusal::RouteUnsupported => reason::ROUTE_UNSUPPORTED,
            PlanRefusal::HostTrustUndetermined => reason::HOST_TRUST_UNDETERMINED,
            PlanRefusal::PairNotAdopted => reason::PAIR_NOT_ADOPTED,
            PlanRefusal::AlreadyEnrolled => reason::ALREADY_ENROLLED,
            PlanRefusal::RegistryPathInvalid => REGISTRY_PATH_INVALID,
        }
    }

    /// The public code.
    #[must_use]
    pub fn code(self) -> Code {
        match self {
            PlanRefusal::AccountOverrideRefused | PlanRefusal::RegistryPathInvalid => {
                Code::UsageError
            }
            PlanRefusal::AlreadyEnrolled => Code::ConfigConflict,
            PlanRefusal::DriverUnavailable
            | PlanRefusal::RouteUndetermined
            | PlanRefusal::ExistingAccessKindUnsupported
            | PlanRefusal::ExistingAccessEndpointUnrecorded
            | PlanRefusal::ExistingAccessEndpointIsHeimdall
            | PlanRefusal::IssuerNotInitialized
            | PlanRefusal::IssuerUnavailable
            | PlanRefusal::CaRetiring
            | PlanRefusal::ObservedAliasUnmanaged
            | PlanRefusal::PrincipalCharset
            | PlanRefusal::RouteUnsupported
            | PlanRefusal::HostTrustUndetermined
            | PlanRefusal::PairNotAdopted => Code::CapabilityUnavailable,
        }
    }
}

/// The 16-hex tag of an enrollment's generated host-trust files and `HostKeyAlias`
/// (`<runtime_dir>/e/<tag>/`, `hm-target-<tag>`).
#[must_use]
pub fn trust_tag(enrollment: &EnrollmentId) -> String {
    let digest =
        Sha256Hex::of(format!("heimdall-target-tag/1\0{}", enrollment.as_str()).as_bytes());
    digest.as_str()[..16].to_owned()
}

/// The CA the plan uses.
fn choose_ca<'a>(cas: &'a CaView, spec: &EnrollmentSpec) -> Result<&'a CaViewEntry, PlanRefusal> {
    match cas.issuer {
        Some(IssuerState::Ready) => {}
        Some(IssuerState::NotInitialized) => return Err(PlanRefusal::IssuerNotInitialized),
        _ if cas.cas.is_empty() => return Err(PlanRefusal::IssuerNotInitialized),
        _ => return Err(PlanRefusal::IssuerUnavailable),
    }
    let entry = match &spec.ca_fingerprint {
        Some(fp) => {
            let entry = cas
                .cas
                .iter()
                .find(|c| &c.fingerprint == fp)
                .ok_or(PlanRefusal::IssuerNotInitialized)?;
            match entry.state {
                CaState::Active | CaState::Pending => entry,
                _ => return Err(PlanRefusal::CaRetiring),
            }
        }
        None => cas
            .cas
            .iter()
            .rev()
            .find(|c| c.state == CaState::Active)
            .ok_or(PlanRefusal::IssuerNotInitialized)?,
    };
    if line::ca_public_ok(&entry.public_key) {
        Ok(entry)
    } else {
        Err(PlanRefusal::IssuerUnavailable)
    }
}

/// The one non-revoked, pinnable host key.
fn approved_key(keys: &[RawHostKey]) -> Result<&RawHostKey, PlanRefusal> {
    let blob_ok = |k: &RawHostKey| {
        !k.key_b64.is_empty()
            && k.key_b64
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    };
    let same = |a: &RawHostKey, b: &RawHostKey| a.key_type == b.key_type && a.key_b64 == b.key_b64;
    let mut candidates: Vec<&RawHostKey> = Vec::new();
    for key in keys.iter().filter(|k| !k.revoked) {
        if keys.iter().any(|r| r.revoked && same(r, key)) {
            continue;
        }
        if !candidates.iter().any(|c| same(c, key)) {
            candidates.push(key);
        }
    }
    match candidates.as_slice() {
        [key] if blob_ok(key) && step::host_key_algorithms(&key.key_type).is_some() => Ok(key),
        _ => Err(PlanRefusal::HostTrustUndetermined),
    }
}

/// A drive-absolute Windows path is written with `/` separators (as M02 renders it);
/// anything else is kept as it is.
fn normalized_path(path: &str) -> String {
    let b = path.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/') {
        path.replace('\\', "/")
    } else {
        path.to_owned()
    }
}

/// The pipe prefixes (any ASCII case of `pipe`).
fn pipe_name(value: &str) -> Option<&str> {
    let lower = value.to_ascii_lowercase();
    ["//./pipe/", "\\\\.\\pipe\\"]
        .into_iter()
        .find(|p| lower.starts_with(p))
        .map(|p| &value[p.len()..])
}

/// A concrete endpoint, rendered: an absolute, normalized socket path, or a pipe as
/// `//./pipe/<name>`. `None` for anything that is not concrete.
fn concrete_endpoint(kind: Option<EndpointKind>, locator: &str) -> Option<String> {
    let as_pipe = |name: &str| {
        (!name.is_empty() && !name.contains(['/', '\\'])).then(|| format!("//./pipe/{name}"))
    };
    let rendered = match (kind, pipe_name(locator)) {
        (Some(EndpointKind::NamedPipe), Some(name)) | (None, Some(name)) => as_pipe(name)?,
        (Some(EndpointKind::NamedPipe), None) => as_pipe(locator)?,
        (Some(EndpointKind::UnixSocket) | None, None) => {
            let rest = locator.strip_prefix('/')?;
            if rest
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return None;
            }
            locator.to_owned()
        }
        _ => return None,
    };
    let lower = rendered.to_ascii_lowercase();
    if lower.contains("ssh_auth_sock") || step::literal(&rendered).is_err() {
        return None;
    }
    Some(rendered)
}

/// The concrete endpoint a catalog-recorded existing-access endpoint renders to (step
/// 8's rule: an absolute, normalized socket path, or a pipe as `//./pipe/<name>`):
/// what a plan approves, a record stores and the host re-validates before each step.
/// ⟨round 5, Y-W⟩ A foreign removal names its endpoint through this too, never the
/// catalog's raw locator (on Windows `\\.\pipe\<name>`, which no step can pin).
/// `None` for anything that is not concrete.
#[must_use]
pub fn catalog_endpoint(endpoint: &EndpointRef) -> Option<String> {
    concrete_endpoint(Some(endpoint.kind), &normalized_path(&endpoint.locator))
}

/// Whether `endpoint` (rendered) is, or is under, one of Heimdall's endpoints.
fn is_heimdall(endpoint: &str, heimdall: &[String]) -> bool {
    let ours = |entry: &String| {
        let entry = normalized_path(entry);
        let entry = match pipe_name(&entry) {
            Some(name) => format!("//./pipe/{name}"),
            None => entry,
        };
        let entry = entry.trim_end_matches('/');
        if entry.is_empty() {
            return false;
        }
        let pipe = entry.starts_with("//./pipe/");
        let (e, p) = if pipe {
            (endpoint.to_ascii_lowercase(), entry.to_ascii_lowercase())
        } else {
            (endpoint.to_owned(), entry.to_owned())
        };
        e == p || e.starts_with(&format!("{p}/"))
    };
    heimdall.iter().any(ours)
}

/// Build the enrollment plan (module docs): the D5 §6.1 preconditions, the approved
/// target, the existing-access invocation, the conditional bootstrap step, the
/// disclosures and the digest.
///
/// # Errors
/// [`PlanRefusal`]: the first precondition that does not hold.
pub fn build(
    catalog: &CatalogView,
    target: &TargetEvaluation,
    cas: &CaView,
    spec: EnrollmentSpec,
) -> Result<EnrollmentPlan, PlanRefusal> {
    let context = cas.context.as_ref().ok_or(PlanRefusal::DriverUnavailable)?;
    let destination = &catalog.destination;
    if destination.id != spec.destination {
        return Err(PlanRefusal::DriverUnavailable);
    }
    // 1. A CA registered and the issuer ready.
    let ca = choose_ca(cas, &spec)?;
    // 2. Managed.
    let DestinationDefinition::Managed {
        account, identity, ..
    } = &destination.definition
    else {
        return Err(PlanRefusal::ObservedAliasUnmanaged);
    };
    // 3. The principal charset.
    let principal =
        line::principal(&destination.id, account).map_err(|_| PlanRefusal::PrincipalCharset)?;
    // 4. A determined, direct route.
    if target.determinism != Determinism::Determined || target.port == 0 {
        return Err(PlanRefusal::RouteUndetermined);
    }
    if target.proxy != ProxyRoute::None || !step::alias_ok(&destination.alias) {
        return Err(PlanRefusal::RouteUnsupported);
    }
    if !step::hostname_ok(&target.hostname) {
        return Err(PlanRefusal::RouteUndetermined);
    }
    // 5. Exactly one non-revoked host key.
    let host_key = approved_key(&target.host_keys)?;
    // 6. No account override.
    if spec.account.as_ref().is_some_and(|a| a != account) || target.user != account.as_str() {
        return Err(PlanRefusal::AccountOverrideRefused);
    }
    // 7. An adopted identity of a kind that can drive the steps.
    let record = catalog
        .identity
        .as_ref()
        .filter(|r| &r.id == identity)
        .ok_or(PlanRefusal::PairNotAdopted)?;
    let key_ok = matches!(
        record.key_type(),
        "ssh-ed25519"
            | "ssh-rsa"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    );
    if !key_ok {
        return Err(PlanRefusal::ExistingAccessKindUnsupported);
    }
    let identity_file = match &record.source {
        IdentitySource::PublicKeyFile { path } => normalized_path(path),
        _ => context
            .identity_file
            .clone()
            .ok_or(PlanRefusal::DriverUnavailable)?,
    };
    if step::literal(&identity_file).is_err() {
        return Err(PlanRefusal::ExistingAccessKindUnsupported);
    }
    // 8. A concrete endpoint that is not Heimdall's.
    let (endpoint, endpoint_source) = match record.source.endpoint() {
        Some(e) => (catalog_endpoint(e), EndpointSource::CatalogRecord),
        None => match &context.alias_identity_agent {
            AgentReading::Determined(value) => (
                concrete_endpoint(None, &normalized_path(value)),
                EndpointSource::AliasIdentityAgent,
            ),
            _ => (None, EndpointSource::AliasIdentityAgent),
        },
    };
    let endpoint = endpoint.ok_or(PlanRefusal::ExistingAccessEndpointUnrecorded)?;
    if is_heimdall(&endpoint, &catalog.heimdall_endpoints) {
        return Err(PlanRefusal::ExistingAccessEndpointIsHeimdall);
    }
    // 9. No live enrollment for this (pair, CA).
    if context
        .pair_enrollments
        .iter()
        .any(|e| e.ca_fingerprint == ca.fingerprint && e.live())
    {
        return Err(PlanRefusal::AlreadyEnrolled);
    }
    // 10. The registry path.
    let registry = match (&spec.registry_path, spec.form) {
        (None, _) => RegistryRef {
            path_display: REMOTE_HOME_DISPLAY.to_owned(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        (Some(path), EnrollmentForm::Account) => {
            crate::script::RegistryPath::parse(path)
                .map_err(|_| PlanRefusal::RegistryPathInvalid)?;
            RegistryRef {
                path_display: path.clone(),
                resolved_by: RegistryResolvedBy::Explicit,
            }
        }
        (Some(_), _) => return Err(PlanRefusal::RegistryPathInvalid),
    };

    let user = AccountName::parse(&target.user).map_err(|_| PlanRefusal::PrincipalCharset)?;
    let approved_target = ApprovedTarget {
        hostname: target.hostname.clone(),
        port: target.port,
        user,
        proxy: NoProxy::None,
        host_key: host_key.approved(),
    };
    let marker = line::marker(&context.enrollment_id);
    let line = line::expected_line(&ca.public_key, &principal, &marker)
        .map_err(|_| PlanRefusal::PrincipalCharset)?;
    let host_trust =
        step::trust_pins(&approved_target, &context.trust_files).map_err(|e| match e {
            step::StepError::HostKeyType => PlanRefusal::HostTrustUndetermined,
            _ => PlanRefusal::DriverUnavailable,
        })?;
    let access = step::access_pins(&endpoint, &identity_file)
        .map_err(|_| PlanRefusal::ExistingAccessEndpointUnrecorded)?;
    step::target_pins(&approved_target).map_err(|_| PlanRefusal::RouteUndetermined)?;

    let account_form = spec.form == EnrollmentForm::Account;
    let mut disclosures = vec![
        DisclosureKind::ConfigCommandsRunAsOrdinaryUse,
        DisclosureKind::CaTrustBlastRadius,
    ];
    if account_form {
        disclosures.push(DisclosureKind::RemoveWindow);
    }
    if !context.lock_continuity_acknowledged {
        disclosures.push(DisclosureKind::LockContinuityOnce);
    }
    if account_form {
        disclosures.push(DisclosureKind::ReconcileMayStopOwnStaleScript);
    }
    disclosures.push(DisclosureKind::OrdinarySshNeedsHeldSlot);

    let mut plan = EnrollmentPlan {
        plan_digest: PlanDigest::from_sha256([0; 32]),
        destination_id: destination.id.clone(),
        alias: destination.alias.clone(),
        account: account.clone(),
        form: spec.form,
        registry,
        line_sha256: Sha256Hex::of(line.as_bytes()).as_str().to_owned(),
        line,
        ca_fingerprint: ca.fingerprint.clone(),
        existing_access: ExistingAccessPlan {
            identity_id: record.id.clone(),
            mechanism: record.source.mechanism().to_owned(),
            endpoint,
            endpoint_source,
            invocation: step::render_invocation(&access),
        },
        host_trust: step::render_pairs(&host_trust),
        approved_target,
        bootstrap: account_form.then_some(BootstrapPlan::CreateRegistryDir0700IfAbsent),
        verification: VerificationPlan {
            positive_principal: principal,
            negative: true,
            max_validity_seconds: VERIFICATION_MAX_VALIDITY_SECONDS,
        },
        rollback: RollbackPlan::CompareThenRenameByMarker,
        disclosures,
    };
    plan.plan_digest = plan_digest(&plan)?;
    Ok(plan)
}

/// The digest over every field of `plan` except `plan_digest` itself (the decision
/// and the request hash cover it): bare 64 lowercase hex (§17.15 X-Q4).
///
/// # Errors
/// [`PlanRefusal::DriverUnavailable`] when the plan cannot be canonicalized.
pub fn plan_digest(plan: &EnrollmentPlan) -> Result<PlanDigest, PlanRefusal> {
    let mut value = serde_json::to_value(plan).map_err(|_| PlanRefusal::DriverUnavailable)?;
    value
        .as_object_mut()
        .ok_or(PlanRefusal::DriverUnavailable)?
        .remove("plan_digest");
    let hash = heimdall_contract::canonical::request_hash(DIGEST_CONTEXT, &value)
        .map_err(|_| PlanRefusal::DriverUnavailable)?;
    PlanDigest::parse(&hash.to_hex()).map_err(|_| PlanRefusal::DriverUnavailable)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn refusal_reasons_are_registered_with_their_codes() {
        let all = [
            PlanRefusal::DriverUnavailable,
            PlanRefusal::AccountOverrideRefused,
            PlanRefusal::RouteUndetermined,
            PlanRefusal::ExistingAccessKindUnsupported,
            PlanRefusal::ExistingAccessEndpointUnrecorded,
            PlanRefusal::ExistingAccessEndpointIsHeimdall,
            PlanRefusal::IssuerNotInitialized,
            PlanRefusal::IssuerUnavailable,
            PlanRefusal::CaRetiring,
            PlanRefusal::ObservedAliasUnmanaged,
            PlanRefusal::PrincipalCharset,
            PlanRefusal::RouteUnsupported,
            PlanRefusal::HostTrustUndetermined,
            PlanRefusal::PairNotAdopted,
            PlanRefusal::AlreadyEnrolled,
            PlanRefusal::RegistryPathInvalid,
        ];
        for r in all {
            match r {
                PlanRefusal::DriverUnavailable => {
                    assert_eq!(r.code(), Code::CapabilityUnavailable);
                    assert!(reason::ALL.contains(&r.reason()));
                }
                // Escalated (U5P-Q3): no registered reason.
                PlanRefusal::RegistryPathInvalid => assert_eq!(r.code(), Code::UsageError),
                _ => assert!(
                    reason::M03
                        .iter()
                        .any(|(name, code)| *name == r.reason() && *code == r.code()),
                    "{}",
                    r.reason()
                ),
            }
        }
    }

    #[test]
    fn endpoints_are_concrete_or_refused() {
        assert_eq!(
            concrete_endpoint(Some(EndpointKind::UnixSocket), "/run/a.sock").as_deref(),
            Some("/run/a.sock")
        );
        assert_eq!(
            concrete_endpoint(
                Some(EndpointKind::NamedPipe),
                "\\\\.\\pipe\\openssh-ssh-agent"
            )
            .as_deref(),
            Some("//./pipe/openssh-ssh-agent")
        );
        for bad in [
            "SSH_AUTH_SOCK",
            "none",
            "~/a.sock",
            "$SSH_AUTH_SOCK",
            "/a/../b",
            "rel",
        ] {
            assert_eq!(concrete_endpoint(None, bad), None, "{bad}");
        }
        let heimdall = vec![
            "/run/user/1/heimdall/".to_owned(),
            "\\\\.\\pipe\\hm-env".to_owned(),
        ];
        assert!(is_heimdall("/run/user/1/heimdall/signing.sock", &heimdall));
        assert!(is_heimdall("//./pipe/HM-ENV", &heimdall));
        assert!(!is_heimdall("/run/user/1/heimdallx", &heimdall));
    }
}
