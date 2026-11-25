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
//! * ⟨M05⟩ `ApplyImport` (U7; ADR-0011 §2.4 I4) writes the destinations and profiles a
//!   portable bundle names that the catalog lacks, in this one transaction, and answers
//!   the plan as applied (`crate::operations::portable_m05`); it needs no decision and
//!   changes no authority; with `dry_run` (§17.9) it answers the plan and writes nothing
//!   (a read: no operation, idempotency, event or journal record);
//! * ⟨M05⟩ `SetDefaultProfile` (ADR-0006 §17.9) sets or clears an environment's
//!   default-profile preference: no decision, no authority generation, no safe-time wait.
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
    RouteCatalogView, RouteRefusal, jump_pairs_in_scope,
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

// --- ⟨rev7⟩ D20: write-time item bounds (ADR-0013 §6.4; PC11) ---------------------------

/// ⟨rev7⟩ `USAGE_ERROR` / `item_too_large`, effect `none`, next `fix_request` (ADR-0013 §6.4,
/// D20): `field` is over `bound` (bytes or entries), carried as the typed detail
/// (`data.error.field`, `bound`, `unit`; PC11) and named in the message, with the item in
/// `resource` when it has an ID. Nothing is written. The value itself is never quoted.
pub(crate) fn item_too_large(
    field: &str,
    bound: usize,
    unit: heimdall_contract::envelope::BoundUnit,
    resource: Option<(&str, String)>,
) -> OpError {
    let words = match unit {
        heimdall_contract::envelope::BoundUnit::Entries => "entries",
        _ => "bytes",
    };
    let e = OpError::new(
        Code::UsageError,
        format!("{field} is over its bound of {bound} {words}; nothing was changed"),
    )
    .with_reason(heimdall_contract::envelope::reason::ITEM_TOO_LARGE)
    .with_effect(EffectStatus::None)
    .with_item_bound(field, u64::try_from(bound).unwrap_or(u64::MAX), unit);
    match resource {
        Some((kind, id)) => e.with_resource(kind, Some(id)),
        None => e,
    }
}

/// ⟨rev7⟩ `field` holds at most `bound` entries ([`item_too_large`] otherwise).
pub(crate) fn bounded_entries(
    field: &str,
    n: usize,
    bound: usize,
    resource: Option<(&str, String)>,
) -> Result<(), OpError> {
    if n > bound {
        return Err(item_too_large(
            field,
            bound,
            heimdall_contract::envelope::BoundUnit::Entries,
            resource,
        ));
    }
    Ok(())
}

/// ⟨rev7⟩ `field` is at most `bound` bytes ([`item_too_large`] otherwise).
pub(crate) fn bounded_bytes(
    field: &str,
    len: usize,
    bound: usize,
    resource: Option<(&str, String)>,
) -> Result<(), OpError> {
    if len > bound {
        return Err(item_too_large(
            field,
            bound,
            heimdall_contract::envelope::BoundUnit::Bytes,
            resource,
        ));
    }
    Ok(())
}

/// ⟨rev7⟩ Every list item's serialized form is at most
/// [`MAX_ITEM_BYTES`](heimdall_contract::bounds::MAX_ITEM_BYTES) (field `item`). The per-field
/// bounds keep a maximal item well under it (the maximal-record tests); this is the backstop
/// for the fields with no bound of their own (an identity's endpoint, a key file's path).
pub(crate) fn bounded_item<T: serde::Serialize>(
    item: &T,
    resource: Option<(&str, String)>,
) -> Result<(), OpError> {
    let n = serde_json::to_vec(item).map_or(usize::MAX, |b| b.len());
    bounded_bytes(
        "item",
        n,
        heimdall_contract::bounds::MAX_ITEM_BYTES,
        resource,
    )
}

/// A label's byte bound ([`MAX_LABEL_BYTES`](heimdall_contract::catalog::MAX_LABEL_BYTES)).
fn bounded_label(label: Option<&String>, resource: (&str, String)) -> Result<(), OpError> {
    bounded_bytes(
        "label",
        label.map_or(0, String::len),
        heimdall_contract::catalog::MAX_LABEL_BYTES,
        Some(resource),
    )
}

/// ⟨rev7; D20⟩ The byte and entry bounds of a catalog request, checked before anything else
/// so an over-bound field is `item_too_large` (not the generic shape refusal) and nothing is
/// admitted: an alias and a host name 255 bytes, a label
/// [`MAX_LABEL_BYTES`](heimdall_contract::catalog::MAX_LABEL_BYTES), a public key
/// [`MAX_PUBLIC_KEY_BYTES`](heimdall_contract::catalog::MAX_PUBLIC_KEY_BYTES), a profile's
/// pairs [`MAX_PROFILE_PAIRS`](heimdall_contract::bounds::MAX_PROFILE_PAIRS), and an import's
/// items the same ([`crate::operations::portable_m05::check_bounds`]).
fn check_bounds(req: &CatalogRequest) -> Result<(), OpError> {
    match req {
        CatalogRequest::UpsertDestination { destination, .. } => {
            let at = || Some(("destination", destination.id.to_string()));
            bounded_bytes("alias", destination.alias.len(), MAX_ALIAS_BYTES, at())?;
            bounded_label(
                destination.label.as_ref(),
                ("destination", destination.id.to_string()),
            )?;
            if let DestinationDefinitionSpec::Managed { hostname, .. } = &destination.definition {
                bounded_bytes("hostname", hostname.len(), MAX_HOSTNAME_BYTES, at())?;
            }
        }
        CatalogRequest::AdoptIdentity { identity, .. } => {
            bounded_bytes(
                "public_key",
                identity.public_key.len(),
                heimdall_contract::catalog::MAX_PUBLIC_KEY_BYTES,
                None,
            )?;
            bounded_bytes(
                "label",
                identity.label.as_ref().map_or(0, String::len),
                heimdall_contract::catalog::MAX_LABEL_BYTES,
                None,
            )?;
        }
        CatalogRequest::UpsertProfile { profile, .. } => {
            let at = || Some(("profile", profile.id.to_string()));
            bounded_entries(
                "pairs",
                profile.pairs.len(),
                heimdall_contract::bounds::MAX_PROFILE_PAIRS,
                at(),
            )?;
            bounded_label(profile.label.as_ref(), ("profile", profile.id.to_string()))?;
        }
        CatalogRequest::ApplyImport { bundle, .. } => {
            crate::operations::portable_m05::check_bounds(bundle)?;
        }
        _ => {}
    }
    Ok(())
}

/// The boundary rules the wire types cannot express (beyond
/// `CatalogRequest::validate`).
fn check_request(req: &CatalogRequest) -> Result<(), OpError> {
    // ⟨rev7; D20⟩ The item bounds first: an over-bound field is `item_too_large`.
    check_bounds(req)?;
    req.validate().map_err(|e| usage(&e.to_string()))?;
    // ⟨M04, M05⟩ Revision 5 (ADR-0006 §17): ⟨M04 U6⟩ a route's `jump` is checked in the
    // upsert's own transaction (`route_checks`); ⟨M05⟩ U7: a bundle is checked as a file's
    // bytes are (bounds, schema name, every value) before anything is admitted; a refusal
    // writes nothing.
    if let CatalogRequest::ApplyImport { bundle, .. } = req {
        crate::operations::portable_m05::validate_bundle(bundle)
            .map_err(|e| usage(&e.to_string()))?;
    }
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
            // ⟨M05⟩ A preference creates no authority, so it never waits for safe time.
            | CatalogAction::SetDefaultProfile { .. }
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
        // ⟨M05⟩ Revision 5.1 (§17.9): a dry-run import is a read. It has been validated as a
        // real one; it creates no operation, idempotency, event or journal record.
        if let CatalogRequest::ApplyImport {
            bundle,
            dry_run: true,
            ..
        } = &req
        {
            let bundle = bundle.clone();
            let plan = self
                .local_write(move |tx, _| crate::operations::portable_m05::dry_run(tx, &bundle))
                .await?;
            return Ok(Completed::ok(Code::Ok, plan));
        }
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
    let own = ops.environment().clone();
    let id = id.clone();
    // ⟨rev7, review U0-R01⟩ A store conflict inside the action rolls its transaction back
    // whole; it is remembered here and settled below as a terminal `CONFIG_CONFLICT`, never
    // passed up as an unavailable store with the operation left queued.
    let conflict: std::sync::Arc<std::sync::Mutex<Option<StoreConflict>>> =
        std::sync::Arc::default();
    let seen = conflict.clone();
    let settle_id = id.clone();
    let result = ops
        .local_write(move |tx, emit| {
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
                own: &own,
            };
            let step = match apply_action(tx, emit, &op, &intent, &ctx) {
                Err(e @ heimdall_store::StoreError::DestinationAliasTaken) => {
                    if let Ok(mut slot) = seen.lock() {
                        *slot = Some(StoreConflict::AliasTaken);
                    }
                    return Err(e);
                }
                Err(e @ heimdall_store::StoreError::GenerationConflict(_)) => {
                    if let Ok(mut slot) = seen.lock() {
                        *slot = Some(StoreConflict::Other);
                    }
                    return Err(e);
                }
                other => other?,
            };
            match step {
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
        .await;
    let what = conflict.lock().ok().and_then(|mut slot| slot.take());
    match (result, what) {
        (Err(_), Some(what)) => settle_store_conflict(ops, &settle_id, what).await,
        (result, _) => result,
    }
}

/// ⟨rev7, review U0-R01⟩ The store conflict a catalog action met, by its typed kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreConflict {
    /// `StoreError::DestinationAliasTaken`.
    AliasTaken,
    /// Any `StoreError::GenerationConflict`.
    Other,
}

/// ⟨rev7, review U0-R01⟩ Settle catalog operation `id` as a terminal `CONFIG_CONFLICT` after
/// its action's transaction met a store conflict (and rolled back whole): `alias_collision`
/// for a taken alias (the store's typed `DestinationAliasTaken`), otherwise no reason. Nothing of the action was written, and nothing is
/// left queued to be driven again.
async fn settle_store_conflict(
    ops: &Operations,
    id: &OperationId,
    what: StoreConflict,
) -> Result<(), OpError> {
    let retention = ops.local_retention();
    let now = ops.local_narrowing_now().await;
    let id = id.clone();
    let alias = what == StoreConflict::AliasTaken;
    ops.local_write(move |tx, emit| {
        let Some(mut op) = tx.operation(&id)? else {
            return Ok(());
        };
        if op.state.is_settled() {
            return Ok(());
        }
        let refusal = if alias {
            conflict_with(
                ConflictKind::AliasCollision,
                "another destination already uses this alias (aliases compare without case)",
            )
        } else {
            OpError::new(
                Code::ConfigConflict,
                "the catalog changed under this request; nothing was written".to_owned(),
            )
        };
        refuse(tx, emit, &mut op, refusal, now, retention)
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

/// ⟨M04 U6⟩ The catalog facts a route decision reads (every destination and each
/// managed pair's stored preference), inside the caller's transaction.
pub(crate) fn route_view(tx: &mut Txn<'_>) -> heimdall_store::Result<RouteCatalogView> {
    let mut view = RouteCatalogView::default();
    for d in tx.destinations()? {
        if let DestinationDefinition::Managed { account, .. } = &d.definition {
            let pair = AccessPair {
                destination: d.id.clone(),
                account: account.clone(),
            };
            if let Some(p) = tx.pair_preference(&pair)? {
                view.mechanisms.insert(pair, p.mechanism);
            }
        }
        view.destinations.insert(d.id.clone(), d);
    }
    Ok(view)
}

/// ⟨rev7; ruled 2026-11-25 (U3-1b's Q2)⟩ The route facts of `destinations` alone, read by key
/// in the caller's transaction, never by enumerating the catalog: each destination with its
/// stored route list and its managed pair's preference, then each hop its approved routes
/// jump through (the same facts), and the destinations that jump through it
/// ([`Txn::destinations_jumping_through`], the reverse lookup `check_jump`'s chain rule
/// reads; two suffice, since the rule asks whether one other exists). Every decision
/// [`RouteCatalogView`] makes for these destinations' pairs reads the same facts as over the
/// whole catalog. The reads stay within D20's bounds: per destination, at most
/// [`MAX_ROUTES_PER_DESTINATION`](heimdall_contract::bounds::MAX_ROUTES_PER_DESTINATION) hops
/// and two jumpers.
pub(crate) fn route_view_of<'a>(
    tx: &mut Txn<'_>,
    destinations: impl IntoIterator<Item = &'a DestinationId>,
) -> heimdall_store::Result<RouteCatalogView> {
    fn load(
        tx: &mut Txn<'_>,
        view: &mut RouteCatalogView,
        id: &DestinationId,
    ) -> heimdall_store::Result<()> {
        if view.destinations.contains_key(id) {
            return Ok(());
        }
        let Some(d) = tx.destination(id)? else {
            return Ok(());
        };
        if let DestinationDefinition::Managed { account, .. } = &d.definition {
            let pair = AccessPair {
                destination: d.id.clone(),
                account: account.clone(),
            };
            if let Some(p) = tx.pair_preference(&pair)? {
                view.mechanisms.insert(pair, p.mechanism);
            }
        }
        let routes = tx.destination_routes(id)?;
        if !routes.is_empty() {
            view.routes.insert(id.clone(), routes);
        }
        view.destinations.insert(id.clone(), d);
        Ok(())
    }
    let mut view = RouteCatalogView::default();
    for id in destinations {
        load(tx, &mut view, id)?;
        let hops: Vec<DestinationId> = view
            .approved_routes(id)
            .into_iter()
            .filter_map(|r| match r.route {
                heimdall_contract::route::RouteSpec::Jump { via } => Some(via),
                _ => None,
            })
            .collect();
        for hop in &hops {
            load(tx, &mut view, hop)?;
        }
        for jumper in tx.destinations_jumping_through(id, 2)? {
            load(tx, &mut view, &jumper)?;
        }
    }
    Ok(view)
}

/// ⟨M04 U6⟩ The in-scope pairs another in-scope pair uses as its managed jump
/// (`heimdall_domain::catalog::jump_pairs_in_scope`), read in the caller's transaction:
/// the one input of `extension_profile` that request creation and the independent
/// issuance check both compute from the store.
pub(crate) fn jump_pairs_of(
    tx: &mut Txn<'_>,
    scope: &BTreeSet<AccessPair>,
) -> heimdall_store::Result<BTreeSet<AccessPair>> {
    if scope.is_empty() {
        return Ok(BTreeSet::new());
    }
    // ⟨M06 W5 `w5n`; ADR-0012 §5.4⟩ With the stored route lists: a helper alias's jump leg
    // is the same single-hop dependency as M04's native jump, so the jump pair of every
    // approved jump route in scope carries `permit-port-forwarding`
    // (`jump_pairs_in_scope`). Without them only a definition's own jump was seen, and a
    // jump route approved by `route add` could authenticate at its bastion and never
    // forward.
    let mut view = route_view(tx)?;
    view.routes = tx.all_destination_routes()?;
    Ok(jump_pairs_in_scope(scope, &view))
}

/// A route refusal as the operation error: `route_chain_unsupported` and
/// `route_dependency_out_of_scope` are `CAPABILITY_UNAVAILABLE`, an unknown jump
/// `NOT_FOUND`.
pub(crate) fn route_refused(r: RouteRefusal, destination: &DestinationId, why: &str) -> OpError {
    match r.reason() {
        Some(reason) => OpError::new(Code::CapabilityUnavailable, why.to_owned())
            .with_reason(reason)
            .with_effect(EffectStatus::None)
            .with_resource("destination", Some(destination.to_string())),
        None => not_found("destination", destination),
    }
}

/// ⟨M04 U6; reading I-4⟩ The route rules of an upsert, over the stored catalog: a
/// jump is a managed destination other than the destination, with no jump of its own
/// (`route_chain_unsupported`; an observed or self jump is
/// `route_dependency_out_of_scope`; an unknown one `NOT_FOUND`), and a destination
/// another uses as its jump cannot become route-bearing or observed.
fn route_checks(
    tx: &mut Txn<'_>,
    id: &DestinationId,
    definition: &DestinationDefinition,
) -> heimdall_store::Result<Option<OpError>> {
    let jump = match definition {
        DestinationDefinition::Managed { jump, .. } => jump.as_ref(),
        DestinationDefinition::Observed => None,
    };
    let needs_view = jump.is_some()
        || matches!(definition, DestinationDefinition::Observed)
        || tx.destination(id)?.is_some();
    if !needs_view {
        return Ok(None);
    }
    let view = route_view(tx)?;
    if !view.used_as_jump_by(id).is_empty() {
        let refusal = match definition {
            DestinationDefinition::Managed { jump: None, .. } => None,
            DestinationDefinition::Managed { .. } => Some(RouteRefusal::ChainUnsupported),
            DestinationDefinition::Observed => Some(RouteRefusal::OutOfScope),
        };
        if let Some(r) = refusal {
            return Ok(Some(route_refused(
                r,
                id,
                "another destination uses this destination as its jump",
            )));
        }
    }
    if let Some(j) = jump
        && let Err(r) = view.check_jump(id, j)
    {
        return Ok(Some(route_refused(
            r,
            j,
            "a jump is a managed destination with no jump of its own, other than the destination itself",
        )));
    }
    Ok(None)
}

/// What an action's transaction needs besides the store.
struct ActionCtx<'a> {
    now: Timestamp,
    decision: &'a DecisionId,
    lifetime: std::time::Duration,
    /// How long an approved declaration lasts (`Limits::declaration_validity`).
    validity: std::time::Duration,
    fresh: IdentityId,
    /// The runtime's own environment (⟨M05⟩ the default of `set_default_profile`).
    own: &'a heimdall_contract::ids::EnvironmentId,
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
                    jump,
                } => {
                    if tx.identity(identity)?.is_none() {
                        return Ok(Step::Refused(Box::new(not_found("identity", identity))));
                    }
                    DestinationDefinition::Managed {
                        hostname: hostname.clone(),
                        port: *port,
                        account: account.clone(),
                        identity: identity.clone(),
                        jump: jump.clone(),
                    }
                }
                _ => DestinationDefinition::Observed,
            };
            // ⟨M04 U6; ADR-0010 §5 item 1, reading I-4⟩ The route rules, in this
            // transaction.
            if let Some(refused) = route_checks(tx, &destination.id, &definition)? {
                return Ok(Step::Refused(Box::new(refused)));
            }
            // ⟨rev7, U0-Q9⟩ Aliases are unique without case: Heimdall's renderer refuses
            // case-variant aliases (`sshconf::render`, `DuplicateAlias`), so the catalog stays
            // renderable. (OpenSSH folds case only in canonicalization, `Match final` and
            // `Match host`.)
            // A write that keeps this destination's own stored alias byte for byte is not
            // refused, so a legacy case-variant pair stays editable (`doctor` reports it).
            let keeps_own_alias = tx
                .destination(&destination.id)?
                .is_some_and(|s| s.alias == destination.alias);
            if let Some(other) = tx
                .destinations_by_alias_ignoring_case(&destination.alias)?
                .into_iter()
                .find(|other| other.id != destination.id)
                && (!keeps_own_alias || other.alias == destination.alias)
            {
                return Ok(Step::Refused(Box::new(
                    conflict_with(
                        ConflictKind::AliasCollision,
                        "another destination already uses this alias (aliases compare without case)",
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
                    // ⟨rev7; D20⟩ The record's serialized form (the backstop).
                    if let Err(e) =
                        bounded_item(&record, Some(("destination", record.id.to_string())))
                    {
                        return Ok(Step::Refused(Box::new(e)));
                    }
                    #[cfg(test)]
                    if tests::alias_taken_by_another_writer(&record.alias) {
                        return Err(heimdall_store::StoreError::DestinationAliasTaken);
                    }
                    tx.upsert_destination(&record)?;
                    record
                }
            };
            Step::Done(serde_json::json!({ "destination": json(&record)? }))
        }
        CatalogAction::RemoveDestination { id } => {
            // ⟨§17.22 item 16 (R2F-Q3)⟩ The destination's pair preferences return to
            // `pending` in this transaction (read before the row goes).
            // ⟨M04 U6⟩ A destination another destination uses as its jump stays.
            let view = route_view(tx)?;
            if !view.used_as_jump_by(id).is_empty() {
                return Ok(Step::Refused(Box::new(route_refused(
                    RouteRefusal::ChainUnsupported,
                    id,
                    "another destination uses this destination as its jump",
                ))));
            }
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
                    if let Err(e) = bounded_item(&record, Some(("identity", record.id.to_string())))
                    {
                        return Ok(Step::Refused(Box::new(e)));
                    }
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
                    if let Err(e) = bounded_item(&record, None) {
                        return Ok(Step::Refused(Box::new(e)));
                    }
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
                    if let Err(e) =
                        bounded_item(&definition, Some(("profile", definition.id.to_string())))
                    {
                        return Ok(Step::Refused(Box::new(e)));
                    }
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
        // ⟨M05⟩ U7 (ADR-0011 §2.4 I4): catalog intent only, one transaction with the
        // operation's settlement.
        CatalogAction::ApplyImport { bundle } => Step::Done(
            crate::operations::portable_m05::apply_import(tx, bundle, now)?,
        ),
        // ⟨M05⟩ Revision 5.1 (§17.9): a preference, never authority.
        CatalogAction::SetDefaultProfile {
            environment,
            profile,
        } => match set_default_profile_in(
            tx,
            ctx.own,
            environment.as_ref().unwrap_or(ctx.own),
            profile.as_ref(),
        )? {
            Ok(set) => Step::Done(json(&set)?),
            Err(e) => Step::Refused(Box::new(e)),
        },
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

// --- ⟨M05⟩ U6: the default-profile catalog preference (ADR-0011 §5.1) -------------------

/// ⟨M05⟩ U6: an environment's default-profile preference (ADR-0011 §5.1; spec §8.2), as
/// [`Operations::set_default_profile`] answers it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefaultProfile {
    /// The environment the preference belongs to (defaults are per environment).
    pub environment_id: heimdall_contract::ids::EnvironmentId,
    /// The default profile, `None` when none is set.
    pub profile_id: Option<heimdall_contract::ids::ProfileId>,
}

/// ⟨M05⟩ U6/U7 (ADR-0011 §5.1): set (`Some`) or clear (`None`) `env`'s default-profile
/// preference inside the caller's transaction, after admitting `env` against the managed
/// set of `own`. The one body behind [`Operations::set_default_profile`] and the journaled
/// `catalog set_default_profile` (ADR-0006 §17.9). Writes nothing on a refusal (inner).
fn set_default_profile_in(
    tx: &mut Txn<'_>,
    own: &heimdall_contract::ids::EnvironmentId,
    env: &heimdall_contract::ids::EnvironmentId,
    profile: Option<&heimdall_contract::ids::ProfileId>,
) -> heimdall_store::Result<Result<DefaultProfile, OpError>> {
    if let Err(e) = crate::environments::admit(tx, own, env)? {
        return Ok(Err(e));
    }
    match profile {
        Some(p) => {
            if tx.profile(p)?.is_none() {
                return Ok(Err(OpError::new(Code::NotFound, "unknown profile")
                    .with_resource("profile", Some(p.to_string()))));
            }
            tx.set_default_profile(env, p)?;
        }
        None => {
            tx.clear_default_profile(env)?;
        }
    }
    Ok(Ok(DefaultProfile {
        environment_id: env.clone(),
        profile_id: profile.cloned(),
    }))
}

impl Operations {
    /// ⟨M05⟩ U6 (ADR-0011 §5.1): set (`Some`) or clear (`None`) the default profile of
    /// `environment` (the runtime's own when `None`), an owner-channel catalog
    /// preference. **Not authority** (no decision, no authority generation): only a
    /// **new** request that omits its profile reads it ([`Self::default_profile`]);
    /// an existing binding pinned its environment, profile revision, scope, mechanism,
    /// grant and context at activation and never reads it (R-AU-03), so changing it
    /// redirects no running work. The profile must exist in the catalog; the
    /// environment must be in the managed set. One transaction.
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE` for a caller without the owner role; `NOT_FOUND` for an
    /// unknown profile or an environment outside the managed set (reason
    /// `environment_removed` for a removed one); nothing is written then.
    pub async fn set_default_profile(
        &self,
        caller: &Caller,
        environment: Option<&heimdall_contract::ids::EnvironmentId>,
        profile: Option<heimdall_contract::ids::ProfileId>,
    ) -> OpResult<DefaultProfile> {
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "the catalog needs the owner role",
            )
            .with_effect(EffectStatus::None));
        }
        let own = self.environment().clone();
        let env = environment.cloned().unwrap_or_else(|| own.clone());
        let set = self
            .local_write(move |tx, _| set_default_profile_in(tx, &own, &env, profile.as_ref()))
            .await??;
        Ok(Completed::ok(Code::Ok, set))
    }

    /// ⟨M05⟩ U6 (ADR-0011 §5.1): the default profile of `environment` (the runtime's own
    /// when `None`), the preference a new request reads **only** when it omits its
    /// profile (`run` without `--profile`, after the workspace context). `None` when
    /// none is set. A binding never reads it.
    ///
    /// # Errors
    /// `STATE_UNAVAILABLE` (store).
    pub async fn default_profile(
        &self,
        environment: Option<&heimdall_contract::ids::EnvironmentId>,
    ) -> Result<Option<heimdall_contract::ids::ProfileId>, OpError> {
        let env = environment
            .cloned()
            .unwrap_or_else(|| self.environment().clone());
        self.local_write(move |tx, _| tx.default_profile(&env))
            .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// ⟨rev7; review U0-RC03⟩ The aliases a test marks as taken by another writer: the store's
    /// `DestinationAliasTaken` at the write, after the catalog's own check passed. Keyed by
    /// alias, so tests running at the same time are not touched.
    static TAKEN_BY_ANOTHER_WRITER: std::sync::Mutex<Vec<String>> =
        std::sync::Mutex::new(Vec::new());

    pub(super) fn alias_taken_by_another_writer(alias: &str) -> bool {
        TAKEN_BY_ANOTHER_WRITER
            .lock()
            .is_ok_and(|taken| taken.iter().any(|a| a == alias))
    }

    /// ⟨rev7; review U0-RC03⟩ The driver's own defence, without the plan's: a store alias
    /// conflict that reaches the catalog driver settles the operation terminal as
    /// `CONFIG_CONFLICT` / `alias_collision`, writes nothing and leaves nothing open, through
    /// a retry with the same request ID and a restart.
    #[tokio::test]
    async fn a_store_alias_conflict_in_the_driver_settles_terminal_and_leaves_nothing_open() {
        use heimdall_contract::catalog::{DestinationDefinitionSpec, DestinationSpec};
        use heimdall_contract::ids::{EnvironmentId, RequestId};
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        use heimdall_domain::time::{SyncStatus, TimePolicy};
        use heimdall_store::Store;
        use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

        use crate::ensure::NoStageHook;
        use crate::operations::{Limits, OperationsConfig};

        const ALIAS: &str = "rc03-taken-by-another-writer";
        TAKEN_BY_ANOTHER_WRITER
            .lock()
            .unwrap()
            .push(ALIAS.to_owned());
        let env = EnvironmentId::from_random_bytes([0x33; 16]);
        let store = std::sync::Arc::new(
            Store::open_in_memory(std::sync::Arc::new(heimdall_store::NoFaults)).unwrap(),
        );
        store
            .transaction(|tx| tx.init_self_environment(&env))
            .unwrap();
        let start = |store: std::sync::Arc<Store>| {
            let env = env.clone();
            async move {
                Operations::start(OperationsConfig {
                    store,
                    clock: VirtualClock::at("2026-11-24T09:00:00Z".parse().unwrap()),
                    time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                    time_policy: TimePolicy::default(),
                    environment: env,
                    adapters: Vec::new(),
                    stage_hook: std::sync::Arc::new(NoStageHook),
                    limits: Limits::default(),
                    default_window: std::time::Duration::from_secs(3600),
                    projection: None,
                })
                .await
                .unwrap()
            }
        };
        let owner = Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
            remote_client: None,
        });
        let request = || CatalogRequest::UpsertDestination {
            destination: DestinationSpec {
                id: DestinationId::parse("dst-late").unwrap(),
                alias: ALIAS.to_owned(),
                definition: DestinationDefinitionSpec::Observed,
                label: None,
            },
            request_id: RequestId::parse("r-rc03").unwrap(),
        };
        let open = |store: &Store| store.transaction(|tx| tx.open_operations()).unwrap();
        let written = |store: &Store| {
            store
                .transaction(|tx| tx.destination(&DestinationId::parse("dst-late").unwrap()))
                .unwrap()
                .is_some()
        };
        let ops = start(store.clone()).await;
        for attempt in ["first", "retry"] {
            let e = ops.catalog(&owner, request()).await.unwrap_err();
            assert_eq!(e.code, Code::ConfigConflict, "{attempt}: {e:?}");
            assert_eq!(e.reason.as_deref(), Some("alias_collision"), "{attempt}");
            assert!(open(&store).is_empty(), "{attempt}: nothing is left open");
            assert!(!written(&store), "{attempt}: nothing was written");
        }
        drop(ops);
        let _restarted = start(store.clone()).await;
        assert!(open(&store).is_empty(), "nothing is open after a restart");
        assert!(!written(&store));
        TAKEN_BY_ANOTHER_WRITER
            .lock()
            .unwrap()
            .retain(|a| a != ALIAS);
    }

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

    // --- ⟨rev7; D20⟩ write-time item bounds through the catalog's IPC entry point ---------

    mod bounds {
        use std::sync::Arc;

        use heimdall_contract::catalog::{
            DestinationDefinitionSpec, DestinationSpec, IdentitySourceSpec, IdentitySpec,
            ProfileSpec,
        };
        use heimdall_contract::ids::{AccountName, EnvironmentId, ProfileId, RequestId};
        use heimdall_contract::project::{
            PORTABLE_BUNDLE_SCHEMA, PortableBundle, PortableDestination, PortableProfile,
        };
        use heimdall_contract::request::AccessPairRef;
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        use heimdall_domain::time::{SyncStatus, TimePolicy};
        use heimdall_store::Store;
        use heimdall_testkit::{ScriptedTimeSync, VirtualClock};

        use super::super::*;
        use crate::ensure::NoStageHook;
        use crate::operations::{Limits, OperationsConfig};

        fn env() -> EnvironmentId {
            EnvironmentId::from_random_bytes([0x44; 16])
        }

        async fn start() -> (Operations, Arc<Store>) {
            let store =
                Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
            store
                .transaction(|tx| tx.init_self_environment(&env()))
                .unwrap();
            let ops = Operations::start(OperationsConfig {
                store: store.clone(),
                clock: VirtualClock::at("2026-11-25T09:00:00Z".parse().unwrap()),
                time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                time_policy: TimePolicy::default(),
                environment: env(),
                adapters: Vec::new(),
                stage_hook: Arc::new(NoStageHook),
                limits: Limits::default(),
                default_window: std::time::Duration::from_secs(3600),
                projection: None,
            })
            .await
            .unwrap();
            (ops, store)
        }

        fn owner() -> Caller {
            Caller::unattended(CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
                remote_client: None,
            })
        }

        /// Everything an ingress could write: the catalog's rows and every operation.
        fn state(store: &Store) -> String {
            store
                .transaction(|tx| {
                    Ok(format!(
                        "{:?}|{:?}|{:?}|{:?}|{:?}",
                        tx.destinations()?,
                        tx.identities()?,
                        tx.profiles()?,
                        tx.open_operations()?,
                        tx.operation_counts()?,
                    ))
                })
                .unwrap()
        }

        fn assert_item_too_large(e: &OpError, field: &str, what: &str) {
            assert_eq!(e.code, Code::UsageError, "{what}: {e:?}");
            assert_eq!(
                e.reason.as_deref(),
                Some(heimdall_contract::envelope::reason::ITEM_TOO_LARGE),
                "{what}: {e:?}"
            );
            assert_eq!(e.effect_status, EffectStatus::None, "{what}");
            assert_eq!(e.next.action, "fix_request", "{what}");
            assert!(e.message.starts_with(field), "{what}: {}", e.message);
            // ⟨PC11⟩ The typed detail: the field and its bound, on the wire.
            let d = e.detail();
            assert_eq!(d.field.as_deref(), Some(field), "{what}");
            let Some(typed) = d.item_too_large() else {
                panic!("{what}: no typed detail");
            };
            assert!(e.message.contains(&format!("{} ", typed.bound)), "{what}");
        }

        fn pairs(n: usize) -> std::collections::BTreeSet<AccessPairRef> {
            (0..n)
                .map(|i| AccessPairRef {
                    destination: DestinationId::parse(&format!("dst-{i:04}")).unwrap(),
                    account: AccountName::parse("deploy").unwrap(),
                })
                .collect()
        }

        fn rid(s: &str) -> RequestId {
            RequestId::parse(s).unwrap()
        }

        /// ⟨D20⟩ Each catalog write over a bound (a profile's pairs, an alias, a host name, a
        /// label, a public key) is `USAGE_ERROR` / `item_too_large` naming its field, before
        /// anything is admitted: the store is unchanged and no operation exists. A profile at
        /// its bound is accepted.
        #[tokio::test]
        async fn over_bound_catalog_writes_are_refused_and_change_nothing() {
            use heimdall_contract::bounds::MAX_PROFILE_PAIRS;
            let (ops, store) = start().await;
            let before = state(&store);
            let profile =
                |n: usize, label: Option<String>, r: &str| CatalogRequest::UpsertProfile {
                    profile: ProfileSpec {
                        id: ProfileId::parse("big").unwrap(),
                        pairs: pairs(n),
                        label,
                    },
                    request_id: rid(r),
                };
            let destination = |alias: String, hostname: String, label: Option<String>, r: &str| {
                CatalogRequest::UpsertDestination {
                    destination: DestinationSpec {
                        id: DestinationId::parse("dst-big").unwrap(),
                        alias,
                        definition: DestinationDefinitionSpec::Managed {
                            hostname,
                            port: None,
                            account: AccountName::parse("deploy").unwrap(),
                            identity: heimdall_contract::ids::IdentityId::from_random_bytes(
                                [1; 16],
                            ),
                            jump: None,
                        },
                        label,
                    },
                    request_id: rid(r),
                }
            };
            let cases: Vec<(&str, &str, CatalogRequest)> = vec![
                (
                    "pairs",
                    "201 pairs",
                    profile(MAX_PROFILE_PAIRS + 1, None, "r1"),
                ),
                (
                    "label",
                    "a 257-byte profile label",
                    profile(1, Some("\"".repeat(257)), "r2"),
                ),
                (
                    "alias",
                    "a 256-byte alias",
                    destination("a".repeat(256), "h".into(), None, "r3"),
                ),
                (
                    "hostname",
                    "a 256-byte host name",
                    destination("a".into(), "h".repeat(256), None, "r4"),
                ),
                (
                    "label",
                    "a 257-byte destination label",
                    destination("a".into(), "h".into(), Some("l".repeat(257)), "r5"),
                ),
                (
                    "public_key",
                    "a public key over 16 KiB",
                    CatalogRequest::AdoptIdentity {
                        identity: IdentitySpec {
                            source: IdentitySourceSpec::PublicKeyFile {
                                path: "/fixture/id.pub".to_owned(),
                            },
                            public_key: format!(
                                "ssh-ed25519 {}",
                                "A".repeat(heimdall_contract::catalog::MAX_PUBLIC_KEY_BYTES)
                            ),
                            label: None,
                        },
                        request_id: rid("r6"),
                    },
                ),
            ];
            for (field, what, req) in cases {
                let e = ops.catalog(&owner(), req).await.unwrap_err();
                assert_item_too_large(&e, field, what);
                assert_eq!(state(&store), before, "{what}: nothing was written");
            }
            // The profile names its item.
            let e = ops
                .catalog(&owner(), profile(MAX_PROFILE_PAIRS + 1, None, "r7"))
                .await
                .unwrap_err();
            assert_eq!(
                e.resource
                    .as_deref()
                    .map(|r| (r.kind.as_str(), r.id.as_deref())),
                Some(("profile", Some("big")))
            );
            // At its bound, accepted.
            ops.catalog(&owner(), profile(MAX_PROFILE_PAIRS, None, "r8"))
                .await
                .unwrap();
            let stored = store
                .transaction(|tx| tx.profile(&ProfileId::parse("big").unwrap()))
                .unwrap()
                .unwrap();
            assert_eq!(stored.scope.pairs.len(), MAX_PROFILE_PAIRS);
        }

        fn bundle(profile_pairs: usize) -> PortableBundle {
            PortableBundle {
                schema: PORTABLE_BUNDLE_SCHEMA.to_owned(),
                created_at: "2026-11-25T09:00:00Z".parse().unwrap(),
                redacted: false,
                destinations: vec![PortableDestination {
                    id: DestinationId::parse("dst-imported").unwrap(),
                    alias: "imported".to_owned(),
                    hostname: Some("imported.example.invalid".to_owned()),
                    port: None,
                    account: Some(AccountName::parse("deploy").unwrap()),
                    host_key_fingerprints: Vec::new(),
                    jump: None,
                }],
                identities: Vec::new(),
                profiles: vec![PortableProfile {
                    id: ProfileId::parse("imported").unwrap(),
                    pairs: (0..profile_pairs)
                        .map(|i| format!("dst-{i:04}:deploy"))
                        .collect(),
                }],
                reestablish: Vec::new(),
            }
        }

        /// ⟨m07-plan U3 "Bounds and refusals"; D20⟩ An import with one item over a bound (a
        /// profile of 201 pairs, within the bundle's own entry bound) is refused
        /// `item_too_large` naming the profile, through the IPC entry point (a dry run and a
        /// real import) and the CLI's file parse, and nothing is written: not the profile, and
        /// not the bundle's valid destination either.
        #[tokio::test]
        async fn over_limit_import_is_refused() {
            use heimdall_contract::bounds::MAX_PROFILE_PAIRS;
            let (ops, store) = start().await;
            let before = state(&store);
            for (dry_run, r) in [(true, "i1"), (false, "i2")] {
                let e = ops
                    .catalog(
                        &owner(),
                        CatalogRequest::ApplyImport {
                            bundle: bundle(MAX_PROFILE_PAIRS + 1),
                            dry_run,
                            request_id: rid(r),
                        },
                    )
                    .await
                    .unwrap_err();
                assert_item_too_large(&e, "pairs", "an over-limit import");
                assert_eq!(
                    e.resource
                        .as_deref()
                        .map(|r| (r.kind.as_str(), r.id.as_deref())),
                    Some(("profile", Some("imported")))
                );
                assert_eq!(
                    state(&store),
                    before,
                    "dry run {dry_run}: nothing was written"
                );
            }
            // The CLI's path: the file's bytes are refused the same way before anything is sent.
            let bytes = serde_json::to_vec(&bundle(MAX_PROFILE_PAIRS + 1)).unwrap();
            let e = crate::operations::portable_m05::parse_import_bundle(&bytes).unwrap_err();
            assert_item_too_large(&e, "pairs", "the CLI's file parse");
            // An alias over its bound is the bundle's shape refusal there, and named so.
            let mut long = bundle(1);
            long.destinations[0].alias = "a".repeat(256);
            let bytes = serde_json::to_vec(&long).unwrap();
            let e = crate::operations::portable_m05::parse_import_bundle(&bytes).unwrap_err();
            assert_item_too_large(&e, "alias", "a 256-byte alias in a file");
            // At the bound the same bundle imports.
            ops.catalog(
                &owner(),
                CatalogRequest::ApplyImport {
                    bundle: bundle(MAX_PROFILE_PAIRS),
                    dry_run: false,
                    request_id: rid("i3"),
                },
            )
            .await
            .unwrap();
            assert!(
                store
                    .transaction(|tx| tx.profile(&ProfileId::parse("imported").unwrap()))
                    .unwrap()
                    .is_some()
            );
        }
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
