//! Roles, permissions and the per-request check (ADR-0012 §3.7, §3.8, §3.9 item 3, §3.10,
//! §3.11; M06 U1).
//!
//! **Roles** are the contract's ([`Role`], [`Permission`]): `owner` holds every permission,
//! `requester` holds `view` and `request`, `viewer` holds `view`. Limited roles never
//! include execution on the runner. A denial is `CAPABILITY_UNAVAILABLE`, reason
//! `role_insufficient`.
//!
//! **The check** ([`check`]) is total and runs for **every** frame of a paired session,
//! before dispatch, against the client's row read for that frame (so revocation is
//! rechecked per request, §3.7):
//! 1. no row, or a tombstone → `client_revoked` (`invitation_expired` for a client whose
//!    invitation expired before its join);
//! 2. a **pending** client may send only the activation probe and `join`; anything else is
//!    `invitation_pending` (§3.9 item 3);
//! 3. `join` and the probe go to the invitation service ([`Verdict::Join`],
//!    [`Verdict::Probe`]);
//! 4. `Attend`, `Decide`, `confirm_time`, an issuer unlock and `device retire` are refused
//!    `INTERACTION_REQUIRED`: a paired remote session is never attended (§3.10 item 1);
//! 5. the request's permission ([`classify`]) must be in the role, else `role_insufficient`;
//! 6. by effect: reads, actions and narrowing are dispatched ([`Verdict::Dispatch`]); a
//!    widening that the application already holds for an attended decision record
//!    (ADR-0006 §3.1) is dispatched and creates only that pending record; a widening
//!    with no such record (the revision-6 widening forms) becomes a pending runner-local
//!    record ([`Verdict::PendingRunnerLocal`], [`crate::widening`]) and is never
//!    dispatched; a form this build has not classified is refused (`driver_unavailable`).
//!
//! **Subscriptions** are rechecked with [`subscription_verdict`]: a revoked client's
//! subscriptions end with the terminal `client_revoked` event (§3.7, §3.11).

use heimdall_app::OpError;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ErrorData, reason};
use heimdall_contract::ids::{ClientId, DestinationId, RouteId};
use heimdall_contract::ipc::ClientHello;
use heimdall_contract::issuer::IssuerRequest;
use heimdall_contract::remote::{
    DeviceRequest, Permission, RemoteEnvironmentRequest, Role, RunnerRequest,
};
use heimdall_contract::request::Request;
use heimdall_contract::route::{ExposurePolicy, RouteRequest, TransportRequest};
use heimdall_domain::principal::ClientRole;
use heimdall_store::ext_m06::{ClientState, RemoteClientRecord, RevocationCause};

/// A refusal this crate produces, with its code and reason (ADR-0012 §9 item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The role lacks the request's permission (`role_insufficient`).
    #[error("the client's role does not permit this request")]
    RoleInsufficient,
    /// The client is unknown or revoked (`client_revoked`).
    #[error("the client is revoked")]
    ClientRevoked,
    /// A pending client sent something other than the probe or `join`
    /// (`invitation_pending`).
    #[error("the client's invitation is pending: only the activation probe and join are accepted")]
    InvitationPending,
    /// The invitation is not live (`invitation_expired`). Also the uniform answer of a
    /// `join` whose identity does not match: it says nothing about the record.
    #[error("the invitation is not live")]
    InvitationExpired,
    /// The invitation was consumed by another join (`invitation_consumed`).
    #[error("the invitation was already consumed")]
    InvitationConsumed,
    /// A `join` or a confirmed key does not match the invitation's binding
    /// (`decision_binding_mismatch`).
    #[error("the request does not match the invitation's binding")]
    BindingMismatch,
    /// A limited role on a runner whose sshd policy is not verified
    /// (`management_sshd_unverified`).
    #[error("limited roles need a verified sshd policy on this runner")]
    ManagementSshdUnverified,
    /// A confirming probe disagreed with the verified policy
    /// (`management_sshd_unsupported`).
    #[error("the runner's sshd behaviour disagrees with its verified policy")]
    ManagementSshdUnsupported,
    /// The key is already authorized under another line (`key_already_authorized`).
    #[error("the key is already authorized under another line")]
    KeyAlreadyAuthorized,
    /// A paired remote session is never attended (`INTERACTION_REQUIRED`).
    #[error("this request needs an owner attending at the runner")]
    InteractionRequired,
    /// ⟨rev 6.3; ADR-0006 §18.7 items 9, 10 and 15⟩ A local-only form from a paired session
    /// (`runner_local.*`, `decide`, `confirm_time`, issuer unlock, `device retire`,
    /// `transport.rotate`, and `Attend`): `INTERACTION_REQUIRED` with reason
    /// `local_owner_required`. A retry from the paired session can never succeed.
    #[error("this request is decided by the owner at the runner, never by a paired session")]
    LocalOwnerRequired,
    /// Time is uncertain (`TIME_UNCERTAIN`).
    #[error("the runner's time is uncertain")]
    TimeUncertain,
    /// The form is not served to a paired session by this build (`driver_unavailable`).
    #[error("this request is not available to a paired session")]
    NotAvailableRemotely,
    /// The authorized_keys port is unavailable (`driver_unavailable`).
    #[error("the authorized_keys writer is not available")]
    LinesUnavailable,
    /// The state store failed (`STATE_UNAVAILABLE`).
    #[error("the state store is unavailable")]
    State,
    /// The same request ID with different content (`REQUEST_CONFLICT`).
    #[error("the request ID was used for a different request")]
    RequestConflict,
    /// The runner-local record is no longer pending, expired, or stale
    /// (`DECISION_STALE`).
    #[error("the decision is no longer pending")]
    DecisionStale,
    /// The recorded outcome is unknown (`OUTCOME_UNKNOWN`); never retried by itself.
    #[error("the outcome of the approved request is unknown")]
    OutcomeUnknown,
    /// A hello naming a paired client reached a runtime that is not a runner
    /// (`SCHEMA_UNSUPPORTED`, as `heimdall_ipc::session::negotiate_for_role` answers it).
    #[error("this runtime does not accept a paired client")]
    NotARunner,
    /// ⟨M06 W3; ADR-0006 §18.7 items 3–4⟩ The request carries what its invitation did not
    /// admit: an Iroh endpoint ID without `iroh_admission`, another client's endpoint ID, or
    /// another environment. ADR-0006 §18.7 item 3 names `INVALID_REQUEST`, which the code
    /// table does not have: the nearest existing code, `USAGE_ERROR` (`fix_request`), with
    /// effect `none`, until the contract owner rules (DONE question M06-W3-runner-Q1).
    #[error("the request is not admitted by the client's invitation")]
    InvalidRequest,
}

impl Refusal {
    /// The code.
    #[must_use]
    pub fn code(self) -> Code {
        match self {
            Self::InteractionRequired | Self::LocalOwnerRequired => Code::InteractionRequired,
            Self::TimeUncertain => Code::TimeUncertain,
            Self::State => Code::StateUnavailable,
            Self::RequestConflict => Code::RequestConflict,
            Self::DecisionStale => Code::DecisionStale,
            Self::OutcomeUnknown => Code::OutcomeUnknown,
            Self::NotARunner => Code::SchemaUnsupported,
            Self::InvalidRequest => Code::UsageError,
            _ => Code::CapabilityUnavailable,
        }
    }

    /// The reason: of a `CAPABILITY_UNAVAILABLE` refusal, and `local_owner_required`.
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        Some(match self {
            Self::RoleInsufficient => reason::ROLE_INSUFFICIENT,
            Self::ClientRevoked => reason::CLIENT_REVOKED,
            Self::InvitationPending => reason::INVITATION_PENDING,
            Self::InvitationExpired => reason::INVITATION_EXPIRED,
            Self::InvitationConsumed => reason::INVITATION_CONSUMED,
            Self::BindingMismatch => reason::DECISION_BINDING_MISMATCH,
            Self::ManagementSshdUnverified => reason::MANAGEMENT_SSHD_UNVERIFIED,
            Self::ManagementSshdUnsupported => reason::MANAGEMENT_SSHD_UNSUPPORTED,
            Self::KeyAlreadyAuthorized => reason::KEY_ALREADY_AUTHORIZED,
            Self::NotAvailableRemotely | Self::LinesUnavailable => reason::DRIVER_UNAVAILABLE,
            Self::LocalOwnerRequired => reason::LOCAL_OWNER_REQUIRED,
            Self::InteractionRequired
            | Self::TimeUncertain
            | Self::State
            | Self::RequestConflict
            | Self::DecisionStale
            | Self::OutcomeUnknown
            | Self::NotARunner
            | Self::InvalidRequest => return None,
        })
    }

    /// As an application error (effect `none`: every refusal here happens before any
    /// effect, except `OUTCOME_UNKNOWN`, whose effect is `unknown`).
    #[must_use]
    pub fn to_op_error(self) -> OpError {
        let mut e = OpError::new(self.code(), self.to_string());
        if let Some(r) = self.reason() {
            e = e.with_reason(r);
        }
        let effect = if self == Self::OutcomeUnknown {
            EffectStatus::Unknown
        } else {
            EffectStatus::None
        };
        e.with_effect(effect)
    }

    /// As an error envelope.
    #[must_use]
    pub fn envelope(self) -> Envelope<ErrorData> {
        self.to_op_error().into_envelope()
    }
}

/// The domain's caller role for a paired client: `owner` stays owner, a limited role is a
/// `LimitedConsumer` (for ownership and visibility checks, ADR-0006 §18.2 item 17).
#[must_use]
pub fn client_role(role: Role) -> ClientRole {
    match role {
        Role::Owner => ClientRole::Owner,
        _ => ClientRole::LimitedConsumer,
    }
}

/// What a request does, for the remote check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Read-only.
    Read,
    /// An action within the role, gated by the application as for a local caller.
    Act,
    /// Narrowing (needs no decision, §3.10).
    Narrow,
    /// A widening for which the application always creates an ADR-0006 §3.1 decision
    /// record and never executes on dispatch (added authority, the widening policy
    /// actions, issuer registration, enrollment, environment addition).
    WidenViaDecision,
    /// A widening with no application decision record: a pending runner-local record
    /// only, never dispatched (§3.10 items 2–3).
    WidenRunnerLocal,
    /// Refused before dispatch on every paired session (`INTERACTION_REQUIRED`).
    AttendedOnly,
    /// Not classified by this build: refused (fail closed).
    Unclassified,
}

/// A request's permission and effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestClass {
    /// The permission the role must hold.
    pub permission: Permission,
    /// The effect.
    pub effect: Effect,
}

const fn class(permission: Permission, effect: Effect) -> RequestClass {
    RequestClass { permission, effect }
}

/// Whether a route's exposure is already covered by recorded consents (ADR-0012 §2.1: a
/// pure preference change needs the existing consent and no new decision). U5a's route
/// store implements it; the default answer is "not covered", so a preference change
/// stays a widening (fail closed).
pub trait ConsentLookup {
    /// Whether making `route` the most preferred route of `destination` is a pure
    /// preference change over already-consented exposure.
    fn preference_consented(&self, destination: &DestinationId, route: &RouteId) -> bool;
}

/// No recorded consents (fail closed).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoConsents;

impl ConsentLookup for NoConsents {
    fn preference_consented(&self, _: &DestinationId, _: &RouteId) -> bool {
        false
    }
}

fn exposure_widens(exposure: Option<&ExposurePolicy>) -> bool {
    exposure.is_some_and(|p| *p != ExposurePolicy::default())
}

/// The permission and effect of `request` from a paired session (module docs, step 5–6).
/// Exhaustive over the variants this build knows; any other variant is
/// [`Effect::Unclassified`].
#[must_use]
pub fn classify(request: &Request, consents: &dyn ConsentLookup) -> RequestClass {
    use Effect::{
        Act, AttendedOnly, Narrow, Read, Unclassified, WidenRunnerLocal, WidenViaDecision,
    };
    use Permission as P;
    match request {
        Request::Inspect(_) | Request::Observe(_) => class(P::View, Read),
        Request::Ensure(_)
        | Request::Bind(_)
        | Request::Delegate(_)
        | Request::Cancel(_)
        | Request::Release(_) => class(P::Request, Act),
        Request::Revoke(_) => class(P::Request, Narrow),
        Request::Policy(a) if a.is_widening() => class(P::Approve, WidenViaDecision),
        Request::Policy(_) => class(P::Approve, Narrow),
        Request::Decide(_) | Request::ConfirmTime(_) => class(P::Approve, AttendedOnly),
        Request::Shutdown(_) | Request::UninstallFence(_) => class(P::Service, Act),
        Request::Setup(_) | Request::Catalog(_) | Request::Connections(_) => class(P::Service, Act),
        Request::Issuer(IssuerRequest::Unlock) => class(P::IssuerTrust, AttendedOnly),
        Request::Issuer(IssuerRequest::Status | IssuerRequest::Bundle { .. }) => {
            class(P::IssuerTrust, Read)
        }
        Request::Issuer(IssuerRequest::Register { .. } | IssuerRequest::Retire { .. }) => {
            class(P::IssuerTrust, WidenViaDecision)
        }
        Request::Issuer(IssuerRequest::BundleWritten { .. }) => class(P::IssuerTrust, Act),
        Request::Issuer(_) => class(P::IssuerTrust, Unclassified),
        Request::Enrollment(e) => {
            use heimdall_contract::enrollment::EnrollmentRequest as E;
            match e {
                E::Preview { .. } => class(P::Enroll, Read),
                E::Apply { .. } => class(P::Enroll, WidenViaDecision),
                E::Remove { .. } => class(P::Enroll, Narrow),
                E::Verify { .. }
                | E::Reconcile { .. }
                | E::Abandon { .. }
                | E::Step { .. }
                | E::StepResult { .. } => class(P::Enroll, Act),
                _ => class(P::Enroll, Unclassified),
            }
        }
        Request::Environment(e) => {
            use heimdall_contract::environment::EnvironmentRequest as E;
            match e {
                E::WslEnable { .. } | E::ContainerAdd { .. } => class(P::Service, WidenViaDecision),
                E::WslDisable { .. } | E::ContainerRemove { .. } => class(P::Service, Narrow),
                _ => class(P::Service, Unclassified),
            }
        }
        Request::RemoteEnvironment(r) => match r {
            RemoteEnvironmentRequest::Status { .. } => class(P::View, Read),
            // §3.9 item 2: creating an invitation is a widening confirmed runner-locally.
            RemoteEnvironmentRequest::Invite { .. } => class(P::Enroll, WidenRunnerLocal),
            RemoteEnvironmentRequest::RevokeClient { .. } => class(P::Enroll, Narrow),
            // Routed to the invitation service before classification ([`check`]).
            RemoteEnvironmentRequest::Join { .. } => class(P::View, Act),
            // ⟨Gemini R03⟩ Also routed there first; read-only (an echo).
            RemoteEnvironmentRequest::ActivationProbe { .. } => class(P::View, Read),
            // ⟨M06 W3; §18.7 item 4⟩ Any role, its own client only, within what its
            // runner-locally confirmed invitation admitted (served by the runner).
            RemoteEnvironmentRequest::RotateEndpoint { .. } => class(P::View, Act),
            // ⟨§18.7 item 19⟩ Owner only: it records evidence and lifts nothing (the lift
            // is the attended `runner_local.policy_recheck`).
            RemoteEnvironmentRequest::RunnerPolicyRecheck { .. } => class(P::Enroll, Act),
            RemoteEnvironmentRequest::Remove { .. } => class(P::Service, Narrow),
            RemoteEnvironmentRequest::Add { .. } | RemoteEnvironmentRequest::Update { .. } => {
                class(P::Service, Act)
            }
            _ => class(P::Service, Unclassified),
        },
        // §3.4, §3.10 item 4: retirement needs an attended decision local to the device.
        Request::Device(DeviceRequest::Retire) => class(P::Enroll, AttendedOnly),
        Request::Device(_) => class(P::Enroll, Unclassified),
        Request::Route(r) => match r {
            RouteRequest::ResolveBinding { .. } => class(P::Request, Read),
            RouteRequest::Remove { .. } => class(P::Service, Narrow),
            // Approving a route is a widening (§2.1, §3.10, RC-R03).
            RouteRequest::Add { .. } => class(P::Service, WidenRunnerLocal),
            RouteRequest::Prefer {
                destination, route, ..
            } => {
                if consents.preference_consented(destination, route) {
                    class(P::Service, Act)
                } else {
                    class(P::Service, WidenRunnerLocal)
                }
            }
            _ => class(P::Service, Unclassified),
        },
        Request::Transport(t) => match t {
            TransportRequest::Disable => class(P::Service, Narrow),
            // Serving, or any exposure beyond the minimal policy, is new exposure.
            TransportRequest::Enable {
                serve, exposure, ..
            } => {
                if *serve || exposure_widens(exposure.as_ref()) {
                    class(P::Service, WidenRunnerLocal)
                } else {
                    class(P::Service, Act)
                }
            }
            // §2.8: adopting a roost is always a widening.
            TransportRequest::AdoptRoost { .. } => class(P::Service, WidenRunnerLocal),
            // ⟨rev 6.3; §18.7 item 10⟩ Rotating this device's K_iroh is the local owner's
            // alone: no remote decision path, as the runner-local forms.
            TransportRequest::Rotate => class(P::Service, AttendedOnly),
            _ => class(P::Service, Unclassified),
        },
        // ⟨M06 W3; ADR-0006 §18.7 item 7⟩ Runner-local decisions: never from a paired session
        // (§3.10 item 1: a paired session is never attended; the narrowing forms are the local
        // owner's too).
        Request::RunnerLocal(r) => {
            use heimdall_contract::remote::RunnerLocalRequest as L;
            match r {
                L::TrustIssuer { .. } | L::DistrustIssuer { .. } => {
                    class(P::IssuerTrust, AttendedOnly)
                }
                L::DesignateTimeSource { .. } | L::ClearTimeSource => {
                    class(P::TimeSource, AttendedOnly)
                }
                // ⟨M06-W2-R02⟩ `remote init`'s form: an owner enrollment.
                L::EnrollOwner { .. } => class(P::Enroll, AttendedOnly),
                // ⟨§18.7 item 19⟩ Lifting the owner-only downgrade re-admits limited roles.
                L::PolicyRecheck { .. } => class(P::Enroll, AttendedOnly),
                _ => class(P::IssuerTrust, Unclassified),
            }
        }
        Request::Runner(r) => match r {
            RunnerRequest::PrepareRemoteGrant { .. } | RunnerRequest::InstallCertificate { .. } => {
                class(P::IssuerTrust, Act)
            }
            RunnerRequest::AuthorityReport => class(P::IssuerTrust, Read),
            RunnerRequest::TimeChallenge => class(P::TimeSource, Read),
            RunnerRequest::TimeResponse { .. } => class(P::TimeSource, Act),
            RunnerRequest::DeliverEffect { .. } => class(P::Approve, Narrow),
            _ => class(P::Approve, Unclassified),
        },
        _ => class(P::Approve, Unclassified),
    }
}

/// One frame of a paired session, as the check sees it.
#[derive(Debug, Clone, Copy)]
pub enum SessionFrame<'a> {
    /// A request.
    Request(&'a Request),
    /// A subscription.
    Subscribe,
    /// The end of a subscription.
    Unsubscribe,
    /// An attendance claim.
    Attend,
}

/// What to do with a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Dispatch to the application as this caller.
    Dispatch {
        /// The client's role.
        role: Role,
        /// How the request was classified (`None` for a subscription frame).
        class: Option<RequestClass>,
    },
    /// Create (or replay) a pending runner-local record; never dispatch.
    PendingRunnerLocal {
        /// The client's role (always `owner` here).
        role: Role,
    },
    /// Hand the `join` to the invitation service.
    Join,
    /// Answer the activation probe.
    Probe,
    /// Refuse before dispatch.
    Refuse(Refusal),
}

/// ⟨ADR-0006 §18.2 reading 1, amended⟩ Who a session is, settled once from its hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionIdentity {
    /// No paired client in the hello: the local same-uid caller (the owner, ADR-0006 §2.1).
    Local,
    /// A paired client: named by a runner's bridge hello, with its role read from this
    /// runner's role table.
    Paired {
        /// The client.
        client: ClientId,
        /// Its role, from the role table (never from the hello or a capability).
        role: Role,
        /// Its state now (the per-frame [`check`] rereads it).
        state: ClientState,
    },
}

/// ⟨Reading 1, amended⟩ Resolve a session's identity: a client ID is accepted only from a
/// hello's `remote_client` (which only the bridge originates, from its argv,
/// [`crate::bridge`]) on a **runner** runtime, **and** only once the role table resolves
/// it to a live client with a role. The capabilities a hello advertises never establish an
/// identity: a hello without `remote_client` is the local caller whatever it advertises.
/// `lookup` reads the client's row.
///
/// # Errors
///
/// `SCHEMA_UNSUPPORTED` ([`Refusal::NotARunner`]) for a hello naming a client on a runtime
/// that is not a runner; `client_revoked` (`invitation_expired`) for a client the role
/// table does not resolve or has tombstoned.
pub fn resolve_session(
    runner: bool,
    hello: &ClientHello,
    lookup: impl FnOnce(&ClientId) -> Option<RemoteClientRecord>,
) -> Result<SessionIdentity, Refusal> {
    let Some(client) = &hello.remote_client else {
        return Ok(SessionIdentity::Local);
    };
    if !runner {
        return Err(Refusal::NotARunner);
    }
    let record = lookup(client).filter(|r| &r.client == client);
    if let Some(r) = row_refusal(record.as_ref()) {
        return Err(r);
    }
    let Some(record) = record else {
        return Err(Refusal::ClientRevoked);
    };
    Ok(SessionIdentity::Paired {
        client: client.clone(),
        role: record.role,
        state: record.state,
    })
}

/// Recheck a client's row for one frame: unknown or revoked → refused.
fn row_refusal(record: Option<&RemoteClientRecord>) -> Option<Refusal> {
    match record {
        None => Some(Refusal::ClientRevoked),
        Some(r) if r.state == ClientState::Revoked => Some(match r.revocation {
            Some(RevocationCause::InvitationExpired) => Refusal::InvitationExpired,
            _ => Refusal::ClientRevoked,
        }),
        Some(_) => None,
    }
}

/// The total per-frame check (module docs). `record` is the client's row read for this
/// frame.
#[must_use]
pub fn check(
    record: Option<&RemoteClientRecord>,
    frame: SessionFrame<'_>,
    consents: &dyn ConsentLookup,
) -> Verdict {
    if let Some(r) = row_refusal(record) {
        return Verdict::Refuse(r);
    }
    let Some(record) = record else {
        return Verdict::Refuse(Refusal::ClientRevoked);
    };
    let is_join = matches!(
        frame,
        SessionFrame::Request(Request::RemoteEnvironment(
            RemoteEnvironmentRequest::Join { .. }
        ))
    );
    // ⟨Gemini R03⟩ The wire activation probe (`remote_environment.activation_probe`).
    let is_probe = matches!(
        frame,
        SessionFrame::Request(Request::RemoteEnvironment(
            RemoteEnvironmentRequest::ActivationProbe { .. }
        ))
    );
    match frame {
        _ if is_probe => return Verdict::Probe,
        _ if is_join => return Verdict::Join,
        _ if record.state == ClientState::Pending => {
            return Verdict::Refuse(Refusal::InvitationPending);
        }
        // ⟨rev 6.3; §18.7 item 15⟩ A paired session is never attended: the refusal names
        // its reason, so a wrapper does not ask the user and retry.
        SessionFrame::Attend => return Verdict::Refuse(Refusal::LocalOwnerRequired),
        SessionFrame::Subscribe | SessionFrame::Unsubscribe => {
            return if record.role.has(Permission::View) {
                Verdict::Dispatch {
                    role: record.role,
                    class: None,
                }
            } else {
                Verdict::Refuse(Refusal::RoleInsufficient)
            };
        }
        SessionFrame::Request(_) => {}
    }
    let SessionFrame::Request(request) = frame else {
        return Verdict::Refuse(Refusal::NotAvailableRemotely);
    };
    let c = classify(request, consents);
    // ⟨rev 6.3; §18.7 items 9, 10 and 15⟩ One rule: a form with no remote decision path
    // (every attended-only form: `runner_local.*`, `decide`, `confirm_time`, issuer unlock,
    // `device retire`, `transport.rotate`) names its reason, whatever the client's role. A
    // retry from the paired session can never succeed.
    if c.effect == Effect::AttendedOnly
        || request.requires_attended_session()
        || matches!(request, Request::RunnerLocal(_))
    {
        return Verdict::Refuse(Refusal::LocalOwnerRequired);
    }
    if !record.role.has(c.permission) {
        return Verdict::Refuse(Refusal::RoleInsufficient);
    }
    match c.effect {
        Effect::Read | Effect::Act | Effect::Narrow | Effect::WidenViaDecision => {
            Verdict::Dispatch {
                role: record.role,
                class: Some(c),
            }
        }
        Effect::WidenRunnerLocal => Verdict::PendingRunnerLocal { role: record.role },
        Effect::AttendedOnly => Verdict::Refuse(Refusal::LocalOwnerRequired),
        Effect::Unclassified => Verdict::Refuse(Refusal::NotAvailableRemotely),
    }
}

/// What the application does when its pipeline finds that a paired client's request needs
/// added authority beyond standing policy (a widening, §3.10): an owner's request becomes
/// a pending record only; a limited client's is refused `role_insufficient` (T-RA4).
///
/// # Errors
///
/// [`Refusal::RoleInsufficient`] for a limited role.
pub fn approval_needed(role: Role) -> Result<(), Refusal> {
    if role.has(Permission::Approve) {
        Ok(())
    } else {
        Err(Refusal::RoleInsufficient)
    }
}

/// A live subscription's recheck (§3.7, §3.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionVerdict {
    /// The client is still active.
    Continue,
    /// End it with the terminal `client_revoked` event.
    Close,
}

/// Recheck a paired client's subscription against its row.
#[must_use]
pub fn subscription_verdict(record: Option<&RemoteClientRecord>) -> SubscriptionVerdict {
    match record {
        Some(r) if r.state == ClientState::Active && r.role.has(Permission::View) => {
            SubscriptionVerdict::Continue
        }
        _ => SubscriptionVerdict::Close,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::ids::{ClientId, InvitationId, KeyFingerprint};
    use heimdall_store::ext_m06::AppliedLine;

    pub(crate) fn record(role: Role, state: ClientState) -> RemoteClientRecord {
        let at = "2026-11-20T10:00:00Z".parse().unwrap();
        RemoteClientRecord {
            client: ClientId::from_random_bytes([1; 16]),
            role,
            key_fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "B".repeat(43))).unwrap(),
            public_key: "ssh-ed25519 AAAA".into(),
            state,
            invitation: Some(InvitationId::from_random_bytes([1; 16])),
            revoked_generation: None,
            revocation: None,
            created_at: at,
            updated_at: at,
            line: AppliedLine::Absent,
        }
    }

    fn req(json: &str) -> Request {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn refusals_carry_their_codes_and_reasons() {
        for (r, code, why) in [
            (
                Refusal::RoleInsufficient,
                Code::CapabilityUnavailable,
                Some("role_insufficient"),
            ),
            (
                Refusal::InvitationPending,
                Code::CapabilityUnavailable,
                Some("invitation_pending"),
            ),
            (
                Refusal::InteractionRequired,
                Code::InteractionRequired,
                None,
            ),
            (
                Refusal::LocalOwnerRequired,
                Code::InteractionRequired,
                Some(reason::LOCAL_OWNER_REQUIRED),
            ),
            (
                Refusal::ManagementSshdUnverified,
                Code::CapabilityUnavailable,
                Some("management_sshd_unverified"),
            ),
        ] {
            let env = r.envelope();
            assert_eq!(env.code, code);
            assert_eq!(env.data.error.reason.as_deref(), why);
            assert_eq!(env.data.error.effect_status, EffectStatus::None);
        }
    }

    /// ⟨ADR-0006 §18.7 item 19⟩ The recheck forms in the role table: the controller's
    /// `runner_policy_recheck` is dispatched for an active owner only (`role_insufficient`
    /// for a limited role, `invitation_pending` for a pending client); the runner-local
    /// `policy_recheck` is refused for every paired client (`local_owner_required`).
    #[test]
    fn the_policy_recheck_is_the_owners_and_its_lift_is_never_a_paired_clients() {
        let recheck = req(
            r#"{"op":"remote_environment","action":"runner_policy_recheck",
                "environment":"env_01010101010101010101010101010101",
                "probe":{"pty_refused":true,"forward_refused":true,
                         "agent_forward_refused":true,"setenv_canary_delivered":false}}"#,
        );
        assert_eq!(recheck.kind(), "remote_environment.runner_policy_recheck");
        let lift = req(r#"{"op":"runner_local","action":"policy_recheck","request_id":"r-1"}"#);
        assert_eq!(lift.kind(), "runner_local.policy_recheck");
        let verdict = |role, state, request: &Request| {
            check(
                Some(&record(role, state)),
                SessionFrame::Request(request),
                &NoConsents,
            )
        };
        assert!(matches!(
            verdict(Role::Owner, ClientState::Active, &recheck),
            Verdict::Dispatch {
                role: Role::Owner,
                ..
            }
        ));
        for role in [Role::Requester, Role::Viewer] {
            assert_eq!(
                verdict(role, ClientState::Active, &recheck),
                Verdict::Refuse(Refusal::RoleInsufficient),
                "{role:?}"
            );
        }
        assert_eq!(
            verdict(Role::Owner, ClientState::Pending, &recheck),
            Verdict::Refuse(Refusal::InvitationPending)
        );
        for role in [Role::Owner, Role::Requester, Role::Viewer] {
            assert_eq!(
                verdict(role, ClientState::Active, &lift),
                Verdict::Refuse(Refusal::LocalOwnerRequired),
                "{role:?}"
            );
        }
    }

    /// ⟨Gemini R03⟩ The wire activation probe, deserialized from the rev-6.1 golden.
    pub(crate) fn wire_probe() -> Request {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/contracts/golden/rev6-requests.golden.json"
        ))
        .unwrap();
        let form = golden
            .as_array()
            .or_else(|| golden["requests"].as_array())
            .unwrap()
            .iter()
            .find(|f| f["kind"] == "remote_environment.activation_probe")
            .expect("the golden lists the activation probe");
        serde_json::from_value(form["json"].clone()).unwrap()
    }

    /// ⟨Gemini R03⟩ The wire probe reaches `Probe` for a pending and an active client, is
    /// classified a read needing `view`, and gives a tombstoned client nothing.
    #[test]
    fn the_wire_activation_probe_reaches_the_probe() {
        let probe = wire_probe();
        assert_eq!(probe.kind(), "remote_environment.activation_probe");
        for state in [ClientState::Pending, ClientState::Active] {
            for role in [Role::Owner, Role::Requester, Role::Viewer] {
                assert_eq!(
                    check(
                        Some(&record(role, state)),
                        SessionFrame::Request(&probe),
                        &NoConsents
                    ),
                    Verdict::Probe,
                    "{role:?} {state:?}"
                );
            }
        }
        assert_eq!(
            classify(&probe, &NoConsents),
            RequestClass {
                permission: Permission::View,
                effect: Effect::Read,
            }
        );
        let mut tomb = record(Role::Owner, ClientState::Revoked);
        tomb.revocation = Some(RevocationCause::Revoked);
        assert_eq!(
            check(Some(&tomb), SessionFrame::Request(&probe), &NoConsents),
            Verdict::Refuse(Refusal::ClientRevoked)
        );
        assert_eq!(
            check(None, SessionFrame::Request(&probe), &NoConsents),
            Verdict::Refuse(Refusal::ClientRevoked)
        );
    }

    /// A pending client: only the probe and join; everything else `invitation_pending`.
    #[test]
    fn pending_client_reaches_only_probe_and_join() {
        let pending = record(Role::Owner, ClientState::Pending);
        let join = req(&format!(
            r#"{{"op":"remote_environment","action":"join","environment":"env_00","invitation":"{}","role":"owner","generation":1}}"#,
            InvitationId::from_random_bytes([1; 16])
        ));
        assert_eq!(
            check(Some(&pending), SessionFrame::Request(&join), &NoConsents),
            Verdict::Join
        );
        assert_eq!(
            check(
                Some(&pending),
                SessionFrame::Request(&wire_probe()),
                &NoConsents
            ),
            Verdict::Probe
        );
        for frame in [
            SessionFrame::Request(&req(r#"{"op":"inspect","subject":"capabilities"}"#)),
            SessionFrame::Subscribe,
            SessionFrame::Unsubscribe,
            SessionFrame::Attend,
            SessionFrame::Request(&req(
                r#"{"op":"decide","decision_id":"dec_00","verdict":"approve"}"#,
            )),
        ] {
            assert_eq!(
                check(Some(&pending), frame, &NoConsents),
                Verdict::Refuse(Refusal::InvitationPending)
            );
        }
    }

    /// Unknown and revoked clients are refused everything, rechecked per frame; a revoked
    /// client's subscriptions close.
    #[test]
    fn revocation_is_rechecked_per_frame_and_on_subscriptions() {
        let inspect = req(r#"{"op":"inspect","subject":"capabilities"}"#);
        assert_eq!(
            check(None, SessionFrame::Request(&inspect), &NoConsents),
            Verdict::Refuse(Refusal::ClientRevoked)
        );
        let mut r = record(Role::Owner, ClientState::Active);
        assert_eq!(
            subscription_verdict(Some(&r)),
            SubscriptionVerdict::Continue
        );
        r.state = ClientState::Revoked;
        r.revocation = Some(RevocationCause::Revoked);
        assert_eq!(
            check(Some(&r), SessionFrame::Request(&wire_probe()), &NoConsents),
            Verdict::Refuse(Refusal::ClientRevoked)
        );
        assert_eq!(subscription_verdict(Some(&r)), SubscriptionVerdict::Close);
        assert_eq!(subscription_verdict(None), SubscriptionVerdict::Close);
        r.revocation = Some(RevocationCause::InvitationExpired);
        assert_eq!(
            check(Some(&r), SessionFrame::Request(&inspect), &NoConsents),
            Verdict::Refuse(Refusal::InvitationExpired)
        );
    }

    /// ⟨Reading 1, amended⟩ A client ID comes only from a runner's bridge hello resolved by
    /// the role table; advertising `remote-control/1` alone is the local caller; a hello
    /// naming a client on another runtime, or an unknown or tombstoned client, is refused;
    /// the role is the table's.
    #[test]
    fn a_client_identity_needs_a_runner_hello_and_the_role_table() {
        use heimdall_contract::ipc::{PeerInfo, capability};
        let rec = record(Role::Viewer, ClientState::Active);
        let mut hello = ClientHello {
            protocol: heimdall_contract::PROTOCOL_VERSION,
            schema_version: heimdall_contract::version::SchemaVersion::current(),
            client: PeerInfo {
                name: "x".into(),
                version: "0".into(),
            },
            capabilities: [capability::REMOTE_CONTROL_V1, capability::RUNNER_V1]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            required: [capability::REMOTE_CONTROL_V1.to_owned()]
                .into_iter()
                .collect(),
            interaction: heimdall_contract::request::InteractionMode::NonInteractive,
            remote_client: None,
        };
        let found = |r: &RemoteClientRecord| {
            let r = r.clone();
            move |_: &ClientId| Some(r)
        };
        // Capabilities alone: the local caller, on a runner or not.
        for runner in [true, false] {
            assert_eq!(
                resolve_session(runner, &hello, found(&rec)),
                Ok(SessionIdentity::Local)
            );
        }
        hello.remote_client = Some(rec.client.clone());
        assert_eq!(
            resolve_session(false, &hello, found(&rec)),
            Err(Refusal::NotARunner)
        );
        assert_eq!(Refusal::NotARunner.code(), Code::SchemaUnsupported);
        assert_eq!(
            resolve_session(true, &hello, |_| None),
            Err(Refusal::ClientRevoked)
        );
        let mut other = rec.clone();
        other.client = ClientId::from_random_bytes([9; 16]);
        assert_eq!(
            resolve_session(true, &hello, found(&other)),
            Err(Refusal::ClientRevoked),
            "a row for another client resolves nothing"
        );
        let mut tomb = rec.clone();
        tomb.state = ClientState::Revoked;
        assert_eq!(
            resolve_session(true, &hello, found(&tomb)),
            Err(Refusal::ClientRevoked)
        );
        assert_eq!(
            resolve_session(true, &hello, found(&rec)),
            Ok(SessionIdentity::Paired {
                client: rec.client.clone(),
                role: Role::Viewer,
                state: ClientState::Active,
            })
        );
    }

    #[test]
    fn roles_hold_only_their_permissions_through_the_check() {
        let viewer = record(Role::Viewer, ClientState::Active);
        let requester = record(Role::Requester, ClientState::Active);
        let inspect = req(r#"{"op":"inspect","subject":"capabilities"}"#);
        let pause = req(r#"{"op":"policy","action":"pause","policy_id":"p"}"#);
        assert!(matches!(
            check(Some(&viewer), SessionFrame::Request(&inspect), &NoConsents),
            Verdict::Dispatch {
                role: Role::Viewer,
                ..
            }
        ));
        assert_eq!(
            check(Some(&viewer), SessionFrame::Request(&pause), &NoConsents),
            Verdict::Refuse(Refusal::RoleInsufficient)
        );
        assert_eq!(
            check(Some(&requester), SessionFrame::Request(&pause), &NoConsents),
            Verdict::Refuse(Refusal::RoleInsufficient)
        );
        assert!(matches!(
            check(Some(&viewer), SessionFrame::Subscribe, &NoConsents),
            Verdict::Dispatch { .. }
        ));
        assert_eq!(
            approval_needed(Role::Requester),
            Err(Refusal::RoleInsufficient)
        );
        assert_eq!(approval_needed(Role::Owner), Ok(()));
        assert_eq!(client_role(Role::Viewer), ClientRole::LimitedConsumer);
    }

    /// ⟨rev6.5; ADR-0006 §18.9 item 5⟩ `rotate_endpoint` is on the base capability, so
    /// a limited role's session (which negotiates no `remote-control/1`) can send it, and
    /// the per-request check dispatches it for every active role. The form names an
    /// environment and an endpoint and no client: the runner serves it for the session's
    /// own client only. Every other `remote_environment` form still needs
    /// `remote-control/1`, and a pending or revoked client still cannot send this one.
    #[test]
    fn any_role_announces_its_own_endpoint_on_the_base_capability() {
        use heimdall_contract::ipc::capability;
        let rotate = req(&format!(
            r#"{{"op":"remote_environment","action":"rotate_endpoint",
                "environment":"env_0123456789abcdef0123456789abcdef","endpoint":"{}"}}"#,
            "ab".repeat(32)
        ));
        assert_eq!(rotate.required_capability(), None);
        // No field of the form names a client.
        let sent = serde_json::to_value(&rotate).unwrap();
        let fields: Vec<&str> = sent
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            ["action", "endpoint", "environment", "op"],
            "{sent}"
        );
        for role in [Role::Viewer, Role::Requester, Role::Owner] {
            let active = record(role, ClientState::Active);
            assert!(
                matches!(
                    check(Some(&active), SessionFrame::Request(&rotate), &NoConsents),
                    Verdict::Dispatch { role: r, .. } if r == role
                ),
                "{role:?}"
            );
            let pending = record(role, ClientState::Pending);
            assert_eq!(
                check(Some(&pending), SessionFrame::Request(&rotate), &NoConsents),
                Verdict::Refuse(Refusal::InvitationPending),
                "{role:?}"
            );
        }
        assert_eq!(
            check(None, SessionFrame::Request(&rotate), &NoConsents),
            Verdict::Refuse(Refusal::ClientRevoked)
        );
        // The limited roles' capability sets are what made it unreachable before.
        for role in [Role::Viewer, Role::Requester] {
            assert!(!role.capabilities().contains(&capability::REMOTE_CONTROL_V1));
        }
        // Another client is touched only through the owner's forms, which keep their
        // capability and their permission.
        let revoke = req(r#"{"op":"remote_environment","action":"revoke_client",
                "environment":"env_0123456789abcdef0123456789abcdef",
                "client":"cl_0123456789abcdef0123456789abcdef"}"#);
        assert_eq!(
            revoke.required_capability(),
            Some(capability::REMOTE_CONTROL_V1)
        );
        for role in [Role::Viewer, Role::Requester] {
            assert_eq!(
                check(
                    Some(&record(role, ClientState::Active)),
                    SessionFrame::Request(&revoke),
                    &NoConsents
                ),
                Verdict::Refuse(Refusal::RoleInsufficient),
                "{role:?}"
            );
        }
    }
}
