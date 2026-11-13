//! ⟨M02⟩ The catalog driver (m02-plan U5; ADR-0007 §7): destinations, adopted
//! identities, profiles and owner interaction declarations.
//!
//! **Entry point.** [`Operations::catalog`] answers every `CatalogRequest`. A caller
//! that is not the owner (a `LimitedConsumer`) gets `CAPABILITY_UNAVAILABLE`. Every
//! action is journaled under kind `catalog`, effect class `local`; its idempotency hash
//! is the action and its canonical spec (m02-plan §5 item 16), so a replay returns the
//! first result and a changed spec under the same request ID is `REQUEST_CONFLICT`.
//! The operation's `CatalogIntent` is the request's canonical action; the driver
//! stores it in `RecoveryIntent.local` (add-only) in its first transaction.
//!
//! **Actions.** Each is one store transaction that writes the catalog row and settles
//! the operation together, so a crash leaves either nothing or the whole action:
//! * `UpsertDestination`: the alias is a literal OpenSSH `Host` name; its
//!   `DestinationId` survives an alias change (spec §4.2); an alias another
//!   destination holds is `CONFIG_CONFLICT`, reason `alias_collision`; a managed
//!   destination names an adopted identity;
//! * `RemoveDestination` changes no file: the projection is stale until the next
//!   `setup apply`, whose plan shows the removal (ADR-0007 §5.5); ⟨M03⟩ its pair
//!   preferences return to `projection: pending` in the same transaction (ADR-0008
//!   §17.22 item 16, R2F-Q3);
//! * `AdoptIdentity` parses the OpenSSH one-line **public** key and records its
//!   `SHA256:` fingerprint; its interaction profile is ADR-0007 §7's default, never
//!   the request's. Adopting a key already adopted updates that identity (its
//!   source, so its endpoint), and an endpoint change ends its live declaration with
//!   `endpoint_changed` in the same transaction;
//! * `RemoveIdentity` is refused while a managed destination names the identity;
//! * `UpsertProfile` goes through `Txn::upsert_profile` and its snapshots: a changed
//!   scope bumps the revision, so a grant pinned to the earlier snapshot is never
//!   widened (R-AU-03). A profile defined again after a removal continues after the
//!   highest revision ever pinned (`Txn::profile_latest_revision`), so no revision is
//!   reused with other content;
//! * `RemoveProfile` (ADR-0007 §12.22 item 10) narrows and needs no decision:
//!   `Txn::remove_profile` deletes the current definition and keeps every pinned
//!   snapshot. New work that names the profile is refused (`NOT_FOUND`, there is no
//!   definition to resolve); a grant or binding already resolved keeps exactly its
//!   pinned revision and is never widened. The result is `{ profile_id, removed }`;
//! * `DeclareInteraction` always creates a `DeclareInteraction` decision (QR1),
//!   completed only by an attended `Decide`. After approval U0b's `decide` copies the
//!   record's fields into `CatalogIntent.approval`, and the driver builds the
//!   `InteractionDeclaration` **only** from it, written with
//!   `Txn::put_interaction_declaration` at revision + 1. If the identity's current
//!   fingerprint or endpoint differs from the approval, it answers `DECISION_STALE`
//!   and writes nothing (M2-R07). The approved declaration lasts
//!   `Limits::declaration_validity` (`[setup] declaration_validity_days`, default 30);
//! * `WithdrawDeclaration` narrows and needs no decision: `Txn::
//!   end_interaction_declaration`, a compare-and-swap when `revision` is given (a
//!   newer declaration stays live and the result says `withdrawn: false`).
//!
//! **Expiry** (ADR-0007 §12.22 item 9). A declaration waiting in `awaiting_approval`
//! whose decision passed its deadline expires (`CREDENTIAL_EXPIRED`, `next:
//! new_work`; `crate::operations::expire_awaiting_local_in`): when the driver or a
//! replay finds it, at a `decide` of the expired record, or at the supervisor's tick.
//! A new request is new work; no fresh decision is issued for an expired one.
//!
//! **Stale decision** (⟨M02⟩ ADR-0007 §12.24 item 8). A declaration still in
//! `awaiting_approval` whose record left `pending` without its deadline passing (stale
//! after a generation move) is reissued as the setup driver does: when the driver or
//! a replay finds no live record, it creates a fresh pending `DeclareInteraction`
//! record bound to the identity's **current** fingerprint and endpoint, at the current
//! generation, and the replay answers with it. An identity that is gone or names no
//! endpoint settles the operation failed instead, as a first declaration would.

use std::collections::BTreeSet;

use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, IdentitySourceSpec,
    WithdrawDeclarationData,
};
use heimdall_contract::envelope::{EffectStatus, ResourceRef};
use heimdall_contract::event::EventType;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DecisionId, DestinationId, IdentityId, OperationId,
};
use heimdall_contract::managed::PreferredMechanism;
use heimdall_contract::request::{Capability, RequiredCapabilities};
use heimdall_contract::setup::ConflictKind;
use heimdall_contract::{Code, OperationState, Timestamp};
use heimdall_domain::catalog::{
    CatalogAction, CatalogIntent, DeclarationEndReason, DeclarationState, DestinationDefinition,
    DestinationRecord, IdentityRecord, IdentitySource, InteractionDeclaration, InteractionProfile,
};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::enrollment::{PairPreference, ProjectionStatus};
use heimdall_domain::idempotency::{HashInput, IdempotencyKey, IdempotencyOutcome, compute_hash};
use heimdall_domain::lifecycle::OperationEvent;
use heimdall_domain::operation::{EffectClass, LocalIntent, OperationKind, OperationRecord};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::projection::Sha256Hex;
use heimdall_domain::scope::AccessPair;
use heimdall_domain::scope::Scope;
use heimdall_store::Txn;

use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::operations::{
    LocalDriver, LocalEmit, Operations, local_approval_needed, local_expire_awaiting, local_op_to,
    local_refuse_outcome, local_settle_failed, local_settle_succeeded,
};

/// How long an approved interaction declaration stays in force by default: the
/// default of `[setup] declaration_validity_days` (m02-plan §5 item 19; QR1), 30 days.
/// The runtime wires the configured value into `Limits::declaration_validity`
/// (ADR-0007 §12.22 item 10), which the driver reads.
pub const DECLARATION_VALIDITY: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 60 * 60);

/// Longest alias accepted (a literal OpenSSH `Host` name).
const MAX_ALIAS_BYTES: usize = 255;

/// Longest hostname accepted.
const MAX_HOSTNAME_BYTES: usize = 255;

/// The plain OpenSSH public-key types an identity may be (ADR-0007 §2; certificates
/// join in M03). The same set the materializer accepts.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn internal(msg: &str) -> OpError {
    OpError::new(Code::InternalError, msg.to_owned())
}

fn usage(msg: &str) -> OpError {
    OpError::new(Code::UsageError, msg.to_owned()).with_effect(EffectStatus::None)
}

/// A literal OpenSSH `Host` name: no pattern, negation, whitespace, quote or comment
/// character, and no leading `-` or `.`.
fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= MAX_ALIAS_BYTES
        && !alias.starts_with(['-', '.'])
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A hostname or address a managed alias renders as `HostName`: no whitespace, quote,
/// `%` token, pattern or control character.
fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOSTNAME_BYTES
        && !host.starts_with('-')
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'[' | b']')
        })
}

/// A parsed OpenSSH one-line public key: its canonical line (type and blob, no
/// comment) and its OpenSSH `SHA256:` fingerprint. Never private material.
struct PublicKey {
    line: String,
    fingerprint: String,
}

fn parse_public_key(text: &str) -> Option<PublicKey> {
    use base64ct::Encoding as _;
    if text.contains("PRIVATE KEY") || text.contains("-----BEGIN") {
        return None;
    }
    let body = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if body.contains(['\n', '\r', '\0']) {
        return None;
    }
    let mut fields = body.split([' ', '\t']).filter(|f| !f.is_empty());
    let (kind, blob) = (fields.next()?, fields.next()?);
    if !KEY_TYPES.contains(&kind) {
        return None;
    }
    let decoded = base64ct::Base64::decode_vec(blob).ok()?;
    let len = usize::try_from(u32::from_be_bytes(decoded.get(..4)?.try_into().ok()?)).ok()?;
    if decoded.get(4..4usize.checked_add(len)?)? != kind.as_bytes() {
        return None;
    }
    let hex = Sha256Hex::of(&decoded);
    let digest: Vec<u8> = (0..hex.as_str().len() / 2)
        .filter_map(|i| u8::from_str_radix(hex.as_str().get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    Some(PublicKey {
        line: format!("{kind} {blob}"),
        fingerprint: format!(
            "SHA256:{}",
            base64ct::Base64Unpadded::encode_string(&digest)
        ),
    })
}

fn source_of(spec: &IdentitySourceSpec) -> Option<IdentitySource> {
    match spec {
        IdentitySourceSpec::NativeAgent { endpoint } => Some(IdentitySource::NativeAgent {
            endpoint: endpoint.clone(),
        }),
        IdentitySourceSpec::OnePassword { endpoint } => Some(IdentitySource::OnePassword {
            endpoint: endpoint.clone(),
        }),
        IdentitySourceSpec::PublicKeyFile { path } => {
            Some(IdentitySource::PublicKeyFile { path: path.clone() })
        }
        _ => None,
    }
}

/// The boundary rules the wire types cannot express (beyond
/// `CatalogRequest::validate`).
fn check_request(req: &CatalogRequest) -> Result<(), OpError> {
    req.validate().map_err(|e| usage(&e.to_string()))?;
    match req {
        CatalogRequest::UpsertDestination { destination, .. } => {
            if !valid_alias(&destination.alias) {
                return Err(usage(
                    "an alias is a literal OpenSSH Host name of letters, digits, '.', '_' and '-'",
                ));
            }
            match &destination.definition {
                DestinationDefinitionSpec::Managed { hostname, port, .. } => {
                    if !valid_hostname(hostname) {
                        return Err(usage("the hostname is not a plain host name or address"));
                    }
                    if *port == Some(0) {
                        return Err(usage("the port is 1-65535"));
                    }
                }
                DestinationDefinitionSpec::Observed => {}
                _ => return Err(usage("this destination definition is not supported")),
            }
        }
        CatalogRequest::AdoptIdentity { identity, .. } => {
            if parse_public_key(&identity.public_key).is_none() {
                return Err(usage("the public key must be one OpenSSH public-key line"));
            }
            if source_of(&identity.source).is_none() {
                return Err(usage("this identity source is not supported"));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether the action narrows only (it never waits for safe time).
fn narrowing(action: &CatalogAction) -> bool {
    matches!(
        action,
        CatalogAction::RemoveDestination { .. }
            | CatalogAction::RemoveIdentity { .. }
            | CatalogAction::RemoveProfile { .. }
            | CatalogAction::WithdrawDeclaration { .. }
            | CatalogAction::SetPreference {
                mechanism: PreferredMechanism::Existing,
                ..
            }
    )
}

/// The idempotency hash: the action and its canonical spec (m02-plan §5 item 16).
fn catalog_hash(
    environment: &heimdall_contract::ids::EnvironmentId,
    req: &CatalogRequest,
    action: &CatalogAction,
) -> Result<heimdall_contract::canonical::RequestHash, OpError> {
    let scope = BTreeSet::new();
    let required = RequiredCapabilities::default();
    let spec = serde_json::to_value(action).map_err(|_| internal("the action cannot be hashed"))?;
    compute_hash(
        OperationKind::Catalog,
        &HashInput {
            environment,
            profile: None,
            profile_revision: None,
            scope: &scope,
            deadline_intent: None,
            work_id: None,
            required_capabilities: &required,
            parent_binding: None,
            extra: serde_json::json!({ "action": req.action(), "spec": spec }),
        },
    )
    .map_err(|_| internal("the request cannot be hashed"))
}

fn plus(t: Timestamp, d: std::time::Duration) -> Timestamp {
    jiff::SignedDuration::try_from(d)
        .ok()
        .and_then(|s| t.checked_add(s).ok())
        .unwrap_or(Timestamp::MAX)
}

impl Operations {
    /// `Request::Catalog` (every action); see the module docs.
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE` for a caller that is not the owner; `USAGE_ERROR` for a
    /// request that breaks a boundary rule; `REQUEST_CONFLICT`, `CONFIG_CONFLICT`
    /// (`alias_collision` …), `NOT_FOUND`, `DECISION_STALE`; and
    /// `APPROVAL_REQUIRED`/`INTERACTION_REQUIRED` with `next.decision_ref` for a
    /// declaration awaiting the owner.
    pub async fn catalog(
        &self,
        caller: &Caller,
        req: CatalogRequest,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "the catalog needs the owner role",
            )
            .with_effect(EffectStatus::None));
        }
        check_request(&req)?;
        let Some(action) = CatalogAction::from_request(&req) else {
            return Err(usage(
                "this catalog action is not supported by this runtime",
            ));
        };
        let now = if narrowing(&action) {
            self.local_narrowing_now().await
        } else {
            self.timegate().check().await?.wall()
        };
        let hash = catalog_hash(self.environment(), &req, &action)?;
        let key = IdempotencyKey {
            caller: caller.context.clone(),
            kind: OperationKind::Catalog,
            request_id: req.request_id().clone(),
        };
        let request_json =
            serde_json::to_value(&req).map_err(|_| internal("request is not serializable"))?;
        let outcome = self
            .local_admit(
                key,
                hash,
                OperationKind::Catalog,
                EffectClass::Local,
                request_json,
                now,
                None,
            )
            .await?;
        if let Some(e) = local_refuse_outcome(&outcome) {
            return Err(e);
        }
        let IdempotencyOutcome::Replay(id) = outcome else {
            return Err(internal("unexpected idempotency outcome"));
        };
        if let Some(Err(e)) = self
            .local_lead_bounded(&id, LocalDriver::Catalog, self.limits().max_wait)
            .await
        {
            return Err(e);
        }
        self.catalog_respond(&id, caller).await
    }

    /// The caller's view of a catalog operation.
    async fn catalog_respond(
        &self,
        id: &OperationId,
        caller: &Caller,
    ) -> OpResult<serde_json::Value> {
        let id2 = id.clone();
        let now = self.local_narrowing_now().await;
        let (op, pending) = self
            .local_write(move |tx, _| {
                let op = tx.operation(&id2)?;
                let pending = pending_declaration(tx, &id2, now)?;
                Ok((op, pending))
            })
            .await?;
        let Some(op) = op else {
            return Err(OpError::new(Code::NotFound, "unknown operation"));
        };
        match op.state {
            OperationState::Succeeded => Ok(Completed {
                operation_id: Some(op.id.clone()),
                state: op.state,
                code: op.code.clone().unwrap_or(Code::Ok),
                data: op.result.clone().unwrap_or(serde_json::Value::Null),
                warnings: Vec::new(),
                next: None,
            }),
            OperationState::AwaitingApproval => match pending {
                Some(d) => Err(local_approval_needed(
                    caller.is_attended(),
                    d.as_str(),
                    "the interaction declaration needs the owner's attended decision",
                )
                .with_resource("decision", Some(d.to_string()))
                .with_operation(op.id.clone())),
                None => {
                    // ADR-0007 §12.22 item 9: no live decision. The driver expires the
                    // operation when its decision passed its deadline, and ⟨M02⟩
                    // §12.24 item 8 issues a fresh one for a stale record; answer from
                    // the state it leaves.
                    if let Some(Err(e)) = self
                        .local_lead_bounded(id, LocalDriver::Catalog, self.limits().max_wait)
                        .await
                    {
                        return Err(e);
                    }
                    let id2 = id.clone();
                    let now = self.local_narrowing_now().await;
                    let (state, fresh) = self
                        .local_write(move |tx, _| {
                            let state = tx.operation(&id2)?.map(|o| o.state);
                            Ok((state, pending_declaration(tx, &id2, now)?))
                        })
                        .await?;
                    if state.is_some_and(|s| s != OperationState::AwaitingApproval) {
                        return Box::pin(self.catalog_respond(id, caller)).await;
                    }
                    match fresh {
                        Some(d) => Err(local_approval_needed(
                            caller.is_attended(),
                            d.as_str(),
                            "the interaction declaration needs the owner's attended decision",
                        )
                        .with_resource("decision", Some(d.to_string()))
                        .with_operation(op.id.clone())),
                        None => Err(OpError::new(
                            Code::Accepted,
                            "the declaration awaits a fresh decision; observe it",
                        )
                        .with_operation(op.id.clone())),
                    }
                }
            },
            OperationState::Failed | OperationState::Cancelled | OperationState::OutcomeUnknown => {
                let detail = op
                    .result
                    .as_ref()
                    .and_then(|v| v.get("error"))
                    .and_then(|e| serde_json::from_value(e.clone()).ok());
                Err(match detail {
                    Some(d) => OpError::from_detail(d, Some(op.id.clone())),
                    None => OpError::new(
                        op.code.clone().unwrap_or(Code::InternalError),
                        "the catalog operation failed",
                    )
                    .with_operation(op.id.clone()),
                })
            }
            OperationState::Queued | OperationState::Running => Err(OpError::new(
                Code::Accepted,
                "the operation is still in progress; observe it",
            )
            .with_operation(op.id.clone())),
        }
    }
}

/// What one action's transaction decided.
enum Step {
    /// Settle succeeded with this result.
    Done(serde_json::Value),
    /// Settle failed with this error; nothing of the action was written.
    Refused(Box<OpError>),
    /// A decision was created; the operation awaits it.
    Waiting,
}

/// Drive catalog operation `id` (module docs). Restart recovery and a decision's
/// resume reach it through `Operations::drive`; requests through the same flight.
///
/// # Errors
/// A store failure (the operation stays where it is).
pub(crate) async fn drive(ops: &Operations, id: &OperationId) -> Result<(), OpError> {
    let decision = crate::ids::new_decision_id()?;
    let fresh = new_identity_id()?;
    let retention = ops.local_retention();
    let lifetime = ops.limits().decision_lifetime;
    let validity = ops.limits().declaration_validity;
    let now = ops.local_narrowing_now().await;
    let id = id.clone();
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state == OperationState::AwaitingApproval {
            // ADR-0007 §12.22 item 9: waiting past its decision's deadline expires it;
            // with a live decision it keeps waiting for the owner. ⟨M02⟩ §12.24 item 8:
            // a declaration whose decision left `pending` without its deadline passing
            // (stale after a generation move) gets a fresh one below, as the setup
            // driver does, bound to the identity's current fingerprint and endpoint.
            if local_expire_awaiting(tx, emit, &mut op, now, retention)?
                || pending_declaration(tx, &op.id, now)?.is_some()
            {
                return Ok(());
            }
            let reissuable = matches!(
                tx.recovery_intent(&id)?.and_then(|r| r.local),
                Some(LocalIntent::Catalog(CatalogIntent {
                    action: CatalogAction::DeclareInteraction { .. },
                    approval: None,
                }))
            );
            if !reissuable {
                return Ok(());
            }
        }
        if op.state.is_settled() {
            return Ok(());
        }
        let Some(mut recovery) = tx.recovery_intent(&id)? else {
            return refuse(
                tx,
                emit,
                &mut op,
                internal("the catalog operation has no intent"),
                now,
                retention,
            );
        };
        let intent = match recovery.local.clone() {
            Some(LocalIntent::Catalog(i)) => i,
            Some(_) => {
                return refuse(
                    tx,
                    emit,
                    &mut op,
                    internal("the operation's intent is not a catalog intent"),
                    now,
                    retention,
                );
            }
            None => {
                let action = serde_json::from_value::<CatalogRequest>(recovery.request.clone())
                    .ok()
                    .and_then(|r| CatalogAction::from_request(&r));
                let Some(action) = action else {
                    return refuse(
                        tx,
                        emit,
                        &mut op,
                        internal("the catalog request cannot be read"),
                        now,
                        retention,
                    );
                };
                let intent = CatalogIntent {
                    action,
                    approval: None,
                };
                recovery.local = Some(LocalIntent::Catalog(intent.clone()));
                tx.set_recovery_intent(&id, &recovery)?;
                intent
            }
        };
        if intent.validate().is_err() {
            return refuse(
                tx,
                emit,
                &mut op,
                internal("the catalog intent is invalid"),
                now,
                retention,
            );
        }
        let ctx = ActionCtx {
            now,
            decision: &decision,
            lifetime,
            validity,
            fresh,
        };
        match apply_action(tx, emit, &op, &intent, &ctx)? {
            Step::Done(data) => {
                local_settle_succeeded(tx, emit, &mut op, Code::Ok, data, now, retention)
            }
            Step::Refused(e) => refuse(tx, emit, &mut op, *e, now, retention),
            Step::Waiting => {
                if op.state == OperationState::Queued {
                    local_op_to(&mut op, OperationEvent::ApprovalNeeded, now)?;
                    tx.update_operation(&op)?;
                    emit.op(tx, &op)?;
                }
                Ok(())
            }
        }
    })
    .await
}

/// The pending, unexpired `DeclareInteraction` record that names `op`, if any.
fn pending_declaration(
    tx: &mut Txn<'_>,
    op: &OperationId,
    now: Timestamp,
) -> heimdall_store::Result<Option<DecisionId>> {
    Ok(tx
        .pending_decisions()?
        .into_iter()
        .rev()
        .find(|d| {
            matches!(&d.kind, DecisionKind::DeclareInteraction { operation, .. } if operation == op)
                && now < d.expires_at
        })
        .map(|d| d.id))
}

fn refuse(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &mut OperationRecord,
    e: OpError,
    now: Timestamp,
    retention: std::time::Duration,
) -> heimdall_store::Result<()> {
    local_settle_failed(
        tx,
        emit,
        op,
        &e.with_effect(EffectStatus::None),
        now,
        retention,
    )
}

fn new_identity_id() -> Result<IdentityId, OpError> {
    let a = crate::ids::random_u64()?;
    let b = crate::ids::random_u64()?;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    Ok(IdentityId::from_random_bytes(bytes))
}

fn conflict_with(kind: ConflictKind, message: &str) -> OpError {
    let mut e = OpError::new(Code::ConfigConflict, message.to_owned());
    if let Some(name) = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
    {
        e = e.with_reason(&name);
    }
    e
}

fn not_found(kind: &str, id: &impl ToString) -> OpError {
    OpError::new(Code::NotFound, format!("unknown {kind}"))
        .with_resource(kind, Some(id.to_string()))
}

fn json<T: serde::Serialize>(v: &T) -> heimdall_store::Result<serde_json::Value> {
    serde_json::to_value(v).map_err(|_| {
        heimdall_store::StoreError::Corrupt("a catalog result cannot be rendered".into())
    })
}

/// What an action's transaction needs besides the store.
struct ActionCtx<'a> {
    now: Timestamp,
    decision: &'a DecisionId,
    lifetime: std::time::Duration,
    /// How long an approved declaration lasts (`Limits::declaration_validity`).
    validity: std::time::Duration,
    fresh: IdentityId,
}

/// One action inside the driver's transaction.
#[allow(clippy::too_many_lines)]
fn apply_action(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &OperationRecord,
    intent: &CatalogIntent,
    ctx: &ActionCtx<'_>,
) -> heimdall_store::Result<Step> {
    let now = ctx.now;
    Ok(match &intent.action {
        CatalogAction::UpsertDestination { destination } => {
            let definition = match &destination.definition {
                DestinationDefinitionSpec::Managed {
                    hostname,
                    port,
                    account,
                    identity,
                } => {
                    if tx.identity(identity)?.is_none() {
                        return Ok(Step::Refused(Box::new(not_found("identity", identity))));
                    }
                    DestinationDefinition::Managed {
                        hostname: hostname.clone(),
                        port: *port,
                        account: account.clone(),
                        identity: identity.clone(),
                    }
                }
                _ => DestinationDefinition::Observed,
            };
            if let Some(other) = tx.destination_by_alias(&destination.alias)?
                && other.id != destination.id
            {
                return Ok(Step::Refused(Box::new(
                    conflict_with(
                        ConflictKind::AliasCollision,
                        "another destination already uses this alias",
                    )
                    .with_resource("destination", Some(other.id.to_string())),
                )));
            }
            let stored = tx.destination(&destination.id)?;
            let unchanged = stored.as_ref().is_some_and(|s| {
                s.alias == destination.alias
                    && s.definition == definition
                    && s.label == destination.label
            });
            let record = match stored {
                Some(s) if unchanged => s,
                other => {
                    let record = DestinationRecord {
                        id: destination.id.clone(),
                        alias: destination.alias.clone(),
                        revision: other.map_or(1, |s| s.revision.saturating_add(1)),
                        definition,
                        label: destination.label.clone(),
                        updated_at: now,
                    };
                    tx.upsert_destination(&record)?;
                    record
                }
            };
            Step::Done(serde_json::json!({ "destination": json(&record)? }))
        }
        CatalogAction::RemoveDestination { id } => {
            // ⟨§17.22 item 16 (R2F-Q3)⟩ The destination's pair preferences return to
            // `pending` in this transaction (read before the row goes).
            let preferences = preferences_of_destination(tx, id)?;
            let removed = tx.remove_destination(id)?;
            if removed {
                for mut p in preferences {
                    if p.projection != ProjectionStatus::Pending {
                        p.projection = ProjectionStatus::Pending;
                        tx.set_pair_preference(&p, now)?;
                    }
                }
            }
            Step::Done(serde_json::json!({ "destination_id": id, "removed": removed }))
        }
        CatalogAction::AdoptIdentity { identity } => {
            let (Some(key), Some(source)) = (
                parse_public_key(&identity.public_key),
                source_of(&identity.source),
            ) else {
                return Ok(Step::Refused(Box::new(usage(
                    "the public key must be one OpenSSH public-key line",
                ))));
            };
            let interaction = InteractionProfile::default_for(&source, &key.line);
            let record = match tx.identity_by_fingerprint(&key.fingerprint)? {
                Some(stored)
                    if stored.source == source
                        && stored.label == identity.label
                        && stored.public_key == key.line =>
                {
                    stored
                }
                Some(stored) => {
                    let endpoint_changed = stored.source.endpoint() != source.endpoint();
                    let record = IdentityRecord {
                        revision: stored.revision.saturating_add(1),
                        source,
                        public_key: key.line,
                        interaction,
                        label: identity.label.clone(),
                        updated_at: now,
                        ..stored.clone()
                    };
                    tx.upsert_identity(&record)?;
                    if endpoint_changed
                        && tx
                            .interaction_declaration(&record.id)?
                            .is_some_and(|d| d.state == DeclarationState::Live)
                    {
                        tx.end_interaction_declaration(
                            &record.id,
                            None,
                            DeclarationEndReason::EndpointChanged,
                            now,
                        )?;
                    }
                    record
                }
                None => {
                    let record = IdentityRecord {
                        id: ctx.fresh.clone(),
                        revision: 1,
                        source,
                        public_key: key.line,
                        fingerprint: key.fingerprint,
                        interaction,
                        label: identity.label.clone(),
                        adopted_at: now,
                        updated_at: now,
                    };
                    tx.upsert_identity(&record)?;
                    record
                }
            };
            Step::Done(serde_json::json!({
                "identity_id": record.id,
                "fingerprint": record.fingerprint,
                "revision": record.revision,
                "interaction": record.interaction.interaction,
                "interaction_basis": record.interaction.basis,
            }))
        }
        CatalogAction::RemoveIdentity { id } => {
            let used = tx.destinations()?.into_iter().any(|d| {
                matches!(&d.definition, DestinationDefinition::Managed { identity, .. } if identity == id)
            });
            if used {
                return Ok(Step::Refused(Box::new(
                    OpError::new(
                        Code::ConfigConflict,
                        "a managed destination still uses this identity; change or remove it first",
                    )
                    .with_resource("identity", Some(id.to_string())),
                )));
            }
            let removed = tx.remove_identity(id)?;
            Step::Done(serde_json::json!({ "identity_id": id, "removed": removed }))
        }
        CatalogAction::UpsertProfile { profile } => {
            let stored = tx.profile(&profile.id)?;
            let capabilities = stored.as_ref().map_or_else(
                || [Capability::SshAuthentication].into_iter().collect(),
                |s| s.scope.capabilities.clone(),
            );
            let scope = Scope {
                pairs: profile.pairs.clone(),
                capabilities,
            };
            let definition = match stored {
                Some(s) if s.scope == scope && s.label == profile.label => s,
                other => {
                    // After the highest revision ever pinned, the stored definition's
                    // or, once removed, its snapshots' (never a reused revision).
                    let latest = match &other {
                        Some(s) => s.revision,
                        None => tx.profile_latest_revision(&profile.id)?.unwrap_or(0),
                    };
                    let definition = ProfileDefinition {
                        id: profile.id.clone(),
                        revision: latest.saturating_add(1),
                        scope,
                        label: profile.label.clone(),
                    };
                    tx.upsert_profile(&definition)?;
                    definition
                }
            };
            Step::Done(serde_json::json!({
                "profile_id": definition.id,
                "revision": definition.revision,
            }))
        }
        CatalogAction::RemoveProfile { id } => {
            let removed = tx.remove_profile(id)?;
            Step::Done(serde_json::json!({ "profile_id": id, "removed": removed }))
        }
        CatalogAction::DeclareInteraction {
            identity,
            interaction,
        } => declare(tx, emit, op, intent, identity, *interaction, ctx)?,
        CatalogAction::WithdrawDeclaration {
            identity,
            revision,
            reason,
        } => {
            let ended =
                tx.end_interaction_declaration(identity, *revision, (*reason).into(), now)?;
            Step::Done(json(&WithdrawDeclarationData {
                withdrawn: ended.ended,
                revision: ended.revision,
            })?)
        }
        CatalogAction::SetPreference {
            destination,
            account,
            mechanism,
        } => set_preference(tx, destination, account, *mechanism, now)?,
    })
}

// --- ⟨M03⟩ U0b row 22: pair preferences (m03-plan §5 item 4b; ADR-0008 D5 §6.6) -------

/// ⟨ADR-0008 §17.22 item 16 (R2F-Q3)⟩ Every stored pair preference of destination `id`.
/// A preference is created only for a pair with an enrollment (`SetPreference`,
/// `add_issuing_ca`), and enrollment records are never deleted, so the pair's accounts
/// are those of its enrollments (under every CA, in every state) and its managed
/// definition's account. A `RemoveDestination` returns each to `projection: pending` in
/// its own transaction (the preference and its issuing CAs are kept: the mechanism the
/// owner chose survives, and P renders nothing for the removed alias, so nothing is
/// applied for it until a later apply renders it again). Pending, a removed pair never
/// resolves to `managed_certificate`.
fn preferences_of_destination(
    tx: &mut Txn<'_>,
    id: &DestinationId,
) -> heimdall_store::Result<Vec<PairPreference>> {
    let mut accounts: BTreeSet<AccountName> = BTreeSet::new();
    if let Some(d) = tx.destination(id)?
        && let DestinationDefinition::Managed { account, .. } = d.definition
    {
        accounts.insert(account);
    }
    for issuer in tx.issuers()? {
        for e in tx.enrollments_for_ca(&issuer.ca_fingerprint)? {
            if &e.destination == id {
                accounts.insert(e.account);
            }
        }
    }
    let mut out = Vec::new();
    for account in accounts {
        if let Some(p) = tx.pair_preference(&AccessPair {
            destination: id.clone(),
            account,
        })? {
            out.push(p);
        }
    }
    Ok(out)
}

fn pair_not_enrolled(pair: &AccessPair) -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "managed certificates need a verified enrollment for the pair",
    )
    .with_reason(heimdall_contract::envelope::reason::PAIR_NOT_ENROLLED)
    .with_resource("destination", Some(pair.destination.to_string()))
}

/// `SetPreference`: local only, nothing outside the store changes; P follows only
/// through `setup apply`, so a changed preference is stored with `projection:
/// pending` (D5 §6.6).
/// * `managed_certificate` needs a `verified` enrollment for the pair
///   (`CAPABILITY_UNAVAILABLE`, `pair_not_enrolled`); a new record's issuing-CA set
///   is the pair's verified CAs, an existing one keeps its set and gains them;
/// * `existing` on a pair with no stored preference, or one already `existing`,
///   changes nothing (no record means `existing`).
fn set_preference(
    tx: &mut Txn<'_>,
    destination: &DestinationId,
    account: &AccountName,
    mechanism: PreferredMechanism,
    now: Timestamp,
) -> heimdall_store::Result<Step> {
    let pair = AccessPair {
        destination: destination.clone(),
        account: account.clone(),
    };
    if tx.destination(destination)?.is_none() {
        return Ok(Step::Refused(Box::new(not_found(
            "destination",
            destination,
        ))));
    }
    let stored = tx.pair_preference(&pair)?;
    let next = match mechanism {
        PreferredMechanism::ManagedCertificate => {
            let verified = tx.verified_cas_for_pair(&pair)?;
            if verified.is_empty() {
                return Ok(Step::Refused(Box::new(pair_not_enrolled(&pair))));
            }
            match stored.clone() {
                Some(p) if p.mechanism == PreferredMechanism::ManagedCertificate => None,
                Some(mut p) => {
                    p.mechanism = PreferredMechanism::ManagedCertificate;
                    p.projection = ProjectionStatus::Pending;
                    p.issuing_cas.extend(verified);
                    Some(p)
                }
                None => Some(PairPreference {
                    destination: destination.clone(),
                    account: account.clone(),
                    mechanism: PreferredMechanism::ManagedCertificate,
                    projection: ProjectionStatus::Pending,
                    issuing_cas: verified,
                }),
            }
        }
        PreferredMechanism::Existing => match stored.clone() {
            Some(mut p) if p.mechanism != PreferredMechanism::Existing => {
                p.mechanism = PreferredMechanism::Existing;
                p.projection = ProjectionStatus::Pending;
                Some(p)
            }
            _ => None,
        },
        _ => {
            return Ok(Step::Refused(Box::new(usage(
                "this preferred mechanism is not supported",
            ))));
        }
    };
    let changed = next.is_some();
    let current = match next {
        Some(p) => {
            tx.set_pair_preference(&p, now)?;
            Some(p)
        }
        None => stored,
    };
    Ok(Step::Done(serde_json::json!({
        "destination_id": destination,
        "account": account,
        "mechanism": mechanism,
        "projection": current.map(|p| p.projection),
        "changed": changed,
    })))
}

impl Operations {
    /// ⟨M03⟩ U0b row 22 (ADR-0008 D5 §6.4 E5, §6.6; F05): the hook the enrollment
    /// driver calls when an enrollment of `ca` for `pair` is recorded `verified`: `ca`
    /// joins the pair preference's issuing-CA set. `e5` is an initial enrollment's E5:
    /// then, **only if** the pair is not already managed with its projection applied,
    /// the preference becomes `managed_certificate` with `projection: pending`. A
    /// rotation's enrollment or a re-verification (`e5` false) only adds the CA. A pair
    /// without a stored preference gets one (`existing` unless `e5`). One transaction.
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE`, reason `pair_not_enrolled`, when `ca` has no `verified`
    /// enrollment for the pair (nothing written); `STATE_UNAVAILABLE` (store).
    pub async fn add_issuing_ca(
        &self,
        pair: &AccessPair,
        ca: &CaFingerprint,
        e5: bool,
    ) -> Result<PairPreference, OpError> {
        let now = self.local_narrowing_now().await;
        let (pair, ca) = (pair.clone(), ca.clone());
        self.local_write(move |tx, _| {
            if !tx.verified_cas_for_pair(&pair)?.contains(&ca) {
                return Ok(Err(pair_not_enrolled(&pair)));
            }
            let mut p = tx
                .pair_preference(&pair)?
                .unwrap_or_else(|| PairPreference {
                    destination: pair.destination.clone(),
                    account: pair.account.clone(),
                    mechanism: PreferredMechanism::Existing,
                    projection: ProjectionStatus::Pending,
                    issuing_cas: BTreeSet::new(),
                });
            let managed_applied = p.mechanism == PreferredMechanism::ManagedCertificate
                && matches!(p.projection, ProjectionStatus::Applied { .. });
            if e5 && !managed_applied {
                p.mechanism = PreferredMechanism::ManagedCertificate;
                p.projection = ProjectionStatus::Pending;
            }
            p.issuing_cas.insert(ca);
            tx.set_pair_preference(&p, now)?;
            Ok(Ok(p))
        })
        .await?
    }

    /// ⟨M03⟩ U0b row 22 (ADR-0008 D5 §6.8; §17.1 item 15, §17.3 item 3): the hook the
    /// removal driver calls when an enrollment of `ca` for `pair` is removed: `ca`
    /// leaves the issuing-CA set. The preference stays `managed_certificate` while
    /// another `verified` CA remains for the pair; when none remains it becomes
    /// `existing` with `projection: pending` (P follows through `setup apply`). A pair
    /// without a stored preference is unchanged (`None`). One transaction.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store).
    pub async fn remove_issuing_ca(
        &self,
        pair: &AccessPair,
        ca: &CaFingerprint,
    ) -> Result<Option<PairPreference>, OpError> {
        let now = self.local_narrowing_now().await;
        let (pair, ca) = (pair.clone(), ca.clone());
        self.local_write(move |tx, _| {
            let Some(mut p) = tx.pair_preference(&pair)? else {
                return Ok(None);
            };
            p.issuing_cas.remove(&ca);
            let mut remaining = tx.verified_cas_for_pair(&pair)?;
            remaining.remove(&ca);
            if remaining.is_empty() && p.mechanism == PreferredMechanism::ManagedCertificate {
                p.mechanism = PreferredMechanism::Existing;
                p.projection = ProjectionStatus::Pending;
            }
            tx.set_pair_preference(&p, now)?;
            Ok(Some(p))
        })
        .await
    }
}

/// `DeclareInteraction`: without an approval, create the decision; with one, build the
/// declaration from the approval alone, or answer `DECISION_STALE`.
fn declare(
    tx: &mut Txn<'_>,
    emit: &mut LocalEmit<'_>,
    op: &OperationRecord,
    intent: &CatalogIntent,
    identity: &IdentityId,
    interaction: DeclaredInteraction,
    ctx: &ActionCtx<'_>,
) -> heimdall_store::Result<Step> {
    let now = ctx.now;
    let Some(record) = tx.identity(identity)? else {
        return Ok(Step::Refused(Box::new(not_found("identity", identity))));
    };
    let Some(endpoint) = record.source.endpoint().cloned() else {
        return Ok(Step::Refused(Box::new(
            OpError::new(
                Code::CapabilityUnavailable,
                "the identity names no agent endpoint a declaration could cover",
            )
            .with_resource("identity", Some(identity.to_string())),
        )));
    };
    let Some(approval) = &intent.approval else {
        // A first decision (`queued`), or ⟨M02⟩ ADR-0007 §12.24 item 8 a fresh one for
        // a declaration still `awaiting_approval` whose record went stale (the driver
        // reaches this only when no live record names it): either way bound to the
        // identity as it is now.
        if !matches!(
            op.state,
            OperationState::Queued | OperationState::AwaitingApproval
        ) {
            return Ok(Step::Refused(Box::new(OpError::new(
                Code::DecisionStale,
                "the declaration has no approval",
            ))));
        }
        let d = DecisionRecord {
            id: ctx.decision.clone(),
            kind: DecisionKind::DeclareInteraction {
                operation: op.id.clone(),
                identity: identity.clone(),
                fingerprint: record.fingerprint.clone(),
                endpoint,
                interaction,
                valid_until: plus(now, ctx.validity),
            },
            generation: tx.authority_generation()?,
            created_at: now,
            expires_at: plus(now, ctx.lifetime),
            state: DecisionState::Pending,
            decided_at: None,
        };
        tx.insert_decision(&d)?;
        emit.decision(tx, &d, Some(&op.id))?;
        return Ok(Step::Waiting);
    };
    // M2-R07: the declaration is the approval's, and only while the identity is still
    // the one the owner was shown.
    if approval.identity != *identity
        || approval.fingerprint != record.fingerprint
        || approval.endpoint != endpoint
        || approval.interaction != interaction
    {
        return Ok(Step::Refused(Box::new(
            OpError::new(
                Code::DecisionStale,
                "the identity's key or endpoint changed after the decision; declare again",
            )
            .with_resource("identity", Some(identity.to_string())),
        )));
    }
    if approval.valid_until <= now {
        return Ok(Step::Refused(Box::new(OpError::new(
            Code::DecisionStale,
            "the approved declaration has already lapsed; declare again",
        ))));
    }
    let expected = tx
        .interaction_declaration(identity)?
        .map_or(0, |d| d.revision);
    let declaration = InteractionDeclaration {
        revision: expected.saturating_add(1),
        state: DeclarationState::Live,
        interaction: approval.interaction,
        fingerprint: approval.fingerprint.clone(),
        endpoint: approval.endpoint.clone(),
        declared_at: now,
        expires_at: approval.valid_until,
        decision: approval.decision.clone(),
        ended_at: None,
        end_reason: None,
    };
    tx.put_interaction_declaration(identity, expected, &declaration)?;
    emit.event(
        tx,
        EventType::ResourceChanged,
        Some(op.id.clone()),
        Some(ResourceRef {
            kind: "identity".to_owned(),
            id: Some(identity.to_string()),
        }),
        serde_json::json!({ "declaration_revision": declaration.revision, "change": "declared" }),
    )?;
    Ok(Step::Done(serde_json::json!({
        "identity_id": identity,
        "revision": declaration.revision,
        "expires_at": declaration.expires_at,
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn blob() -> Vec<u8> {
        // A synthetic ed25519 wire blob over 32 zero bytes (no private key exists).
        let mut blob = Vec::new();
        blob.extend(11u32.to_be_bytes());
        blob.extend(b"ssh-ed25519");
        blob.extend(32u32.to_be_bytes());
        blob.extend([0u8; 32]);
        blob
    }

    #[test]
    fn public_keys_parse_to_openssh_fingerprints_and_refuse_armor() {
        use base64ct::Encoding as _;
        let b64 = base64ct::Base64::encode_string(&blob());
        let key = parse_public_key(&format!("ssh-ed25519 {b64} comment")).unwrap();
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert!(!key.fingerprint.ends_with('='));
        assert_eq!(key.line, format!("ssh-ed25519 {b64}"));
        assert!(parse_public_key("-----BEGIN OPENSSH PRIVATE KEY-----").is_none());
        assert!(parse_public_key(&format!("ssh-rsa {b64}")).is_none());
        assert!(parse_public_key("ssh-ed25519 !!!").is_none());
        assert!(parse_public_key(&format!("ssh-ed25519 {b64}\nssh-ed25519 {b64}")).is_none());
    }

    #[test]
    fn aliases_are_literal_host_names() {
        for ok in ["work", "devbox-1", "a.b_c"] {
            assert!(valid_alias(ok), "{ok}");
        }
        for bad in ["", "*", "a b", "!x", "-o", "a?b", "a,b", "\"q\"", ".x"] {
            assert!(!valid_alias(bad), "{bad}");
        }
    }
}
