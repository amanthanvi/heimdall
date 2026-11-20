//! ⟨M04⟩ U1: the login entry as a setup item (ADR-0010 §1 item 2, §6 item 1; m04-plan U1).
//!
//! **The item.** `PreviewIntent::Apply {items: {login_entry}}` previews writing the
//! runtime's login entry, and `PreviewIntent::Rollback {items: {login_entry}}` previews
//! removing it. Both are previewed, applied and rolled back through
//! [`Operations::setup`] with the plan's digest, like the projection items, and neither is
//! mixed with them: an intent that names the login entry **and** another item is a usage
//! error (preview the entry on its own). `distribution_*` items stay refused
//! (`driver_unavailable`, U3 and U4).
//!
//! **What the plan holds.** No file change and no alias; one finding (`login_entry`) that
//! names the entry's kind, its location, what is there now (`absent`, `owned`,
//! `conflict`) and, for an apply, the **exact data** to be written. The digest covers the
//! intent, the kind, the location, the observed state and that data, so a plan is stale
//! (`CONFIG_CONFLICT`) when any of them changed. No decision is created: the entry carries
//! no authority (ADR-0010 §0 item 3 asks a decision record only for an action that adds
//! an environment able to hold authority); its confirmation is the attended setup step.
//!
//! **Attended only.** An apply or a rollback is accepted from an **attended** session of
//! the owner (the session's attendance, never a request field) and is otherwise
//! `INTERACTION_REQUIRED`, so the entry is never written by an unattended or scripted
//! client. A preview is read-only and needs no attendance.
//!
//! **Effects.** An apply writes and activates the entry through the port, and a
//! non-owned entry at Heimdall's name is `CONFIG_CONFLICT` with reason
//! `login_entry_conflict`, untouched. The result is the item's outcome plus a
//! `login_entry` object (`kind`, `location`, `effect`). An apply or a rollback is
//! idempotent by the entry's exact data: repeating one is `unchanged` or `absent`. It is
//! **not** a journaled operation (no operation row or stage receipt): the entry is one
//! atomic write that the next preview reads back, so a crash between the write and the
//! reply is repaired by repeating the request. The effect is recorded as an owned
//! resource (`ResourceKind::LoginEntry`, owner `runtime`, locator = the entry's
//! location) after it, best effort.
//!
//! **`inspect capabilities`** carries `login_start {kind, installed}`
//! (`contract::environment::LoginStartView`); with no port wired it reads `none`.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use heimdall_contract::Code;
use heimdall_contract::canonical::canonical_json;
use heimdall_contract::doctor::{Finding, FindingSeverity};
use heimdall_contract::envelope::{EffectStatus, NextAction, ResourceRef, reason};
use heimdall_contract::environment::{LoginStartKind, LoginStartView};
use heimdall_contract::ids::ResourceId;
use heimdall_contract::provider::ProbeLevel;
use heimdall_contract::setup::{
    ConsentNeed, ItemOutcome, ItemOutcomeKind, PlanDigest, PreviewIntent, ProjectionItem,
    SetupMode, SetupPlan, SetupRequest,
};
use heimdall_domain::projection::Sha256Hex;
use heimdall_domain::resource::{
    ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
};

use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::operations::Operations;
use crate::ports::{LoginEntryEffect, LoginEntryFailure, LoginEntryPort, LoginEntryState};

/// How many previewed login-entry plans a runtime remembers (by digest).
const PREVIEW_MEMORY: usize = 16;

/// The domain tag of a plan digest.
const DIGEST_TAG: &str = "heimdall.login_entry_plan.v1";

/// The wired port and the remembered previews (`Inner.login_entry`).
#[derive(Default)]
pub(crate) struct LoginEntryWiring {
    port: RwLock<Option<Arc<dyn LoginEntryPort>>>,
    previews: Mutex<VecDeque<(PlanDigest, PreviewIntent)>>,
}

/// Which login-entry action an intent is, if it is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Install,
    Remove,
}

/// What an intent is, as far as this module is concerned.
enum Class {
    /// Not the login entry: the existing setup path answers.
    Other,
    /// The login entry on its own.
    Entry(Action),
    /// The login entry together with another item.
    Mixed,
}

fn classify(intent: &PreviewIntent) -> Class {
    use std::collections::BTreeSet;
    let only = |items: &BTreeSet<ProjectionItem>| {
        items.len() == 1 && items.contains(&ProjectionItem::LoginEntry)
    };
    match intent {
        PreviewIntent::Apply {
            include_git,
            items,
            distribution,
        } => {
            if !items.contains(&ProjectionItem::LoginEntry) {
                Class::Other
            } else if only(items) && !include_git && distribution.is_none() {
                Class::Entry(Action::Install)
            } else if items.iter().any(|i| {
                matches!(
                    i,
                    ProjectionItem::DistributionGit | ProjectionItem::DistributionProjection
                )
            }) || distribution.is_some()
            {
                // A distribution item is still refused as a whole (U3, U4).
                Class::Other
            } else {
                Class::Mixed
            }
        }
        PreviewIntent::Rollback {
            items,
            distribution,
            ..
        } => {
            if !items.contains(&ProjectionItem::LoginEntry) {
                Class::Other
            } else if only(items) && distribution.is_none() {
                Class::Entry(Action::Remove)
            } else if items.iter().any(|i| {
                matches!(
                    i,
                    ProjectionItem::DistributionGit | ProjectionItem::DistributionProjection
                )
            }) || distribution.is_some()
            {
                Class::Other
            } else {
                Class::Mixed
            }
        }
        _ => Class::Other,
    }
}

fn state_word(state: LoginEntryState) -> &'static str {
    match state {
        LoginEntryState::Absent => "absent",
        LoginEntryState::Owned => "owned",
        LoginEntryState::Foreign => "conflict",
    }
}

fn kind_word(kind: LoginStartKind) -> &'static str {
    match kind {
        LoginStartKind::RunValue => "run_value",
        LoginStartKind::LaunchAgent => "launch_agent",
        LoginStartKind::SystemdUser => "systemd_user",
        _ => "none",
    }
}

fn effect_word(effect: LoginEntryEffect) -> &'static str {
    match effect {
        LoginEntryEffect::Created => "created",
        LoginEntryEffect::Updated => "updated",
        LoginEntryEffect::Unchanged => "unchanged",
        LoginEntryEffect::Removed => "removed",
        LoginEntryEffect::Absent => "absent",
    }
}

fn internal(msg: &str) -> OpError {
    OpError::new(Code::InternalError, msg.to_owned())
}

/// `CONFIG_CONFLICT`, reason `login_entry_conflict`: a non-owned entry at Heimdall's name.
fn conflict() -> OpError {
    OpError::new(
        Code::ConfigConflict,
        "another entry is at Heimdall's login entry name; it was left untouched",
    )
    .with_reason(reason::LOGIN_ENTRY_CONFLICT)
    .with_effect(EffectStatus::None)
}

fn failure(f: LoginEntryFailure) -> OpError {
    match f {
        LoginEntryFailure::Conflict => conflict(),
        LoginEntryFailure::NoUserManager => OpError::driver_unavailable(
            "this host has no user session manager: there is no login entry, and the runtime starts on demand",
        ),
        LoginEntryFailure::Failed(msg) => {
            OpError::new(Code::StateUnavailable, msg).with_effect(EffectStatus::Unknown)
        }
    }
}

/// `CONFIG_CONFLICT` ("preview is stale"), effect `none`.
fn stale() -> OpError {
    OpError::new(
        Code::ConfigConflict,
        "preview is stale: the login entry changed since the plan was shown; preview again",
    )
    .with_effect(EffectStatus::None)
}

/// What a plan was computed from.
struct Observed {
    kind: LoginStartKind,
    location: String,
    state: LoginEntryState,
    /// The exact data an install writes (`None` for a removal, or when none can be
    /// rendered).
    data: Option<String>,
}

fn digest_of(intent: &PreviewIntent, o: &Observed) -> Result<PlanDigest, OpError> {
    let value = serde_json::json!({
        "tag": DIGEST_TAG,
        "intent": intent,
        "kind": kind_word(o.kind),
        "location": o.location,
        "state": state_word(o.state),
        "data": o.data,
    });
    let bytes = canonical_json(&value).map_err(|_| internal("the plan cannot be hashed"))?;
    PlanDigest::parse(Sha256Hex::of(&bytes).as_str())
        .map_err(|_| internal("the plan digest is malformed"))
}

impl Operations {
    /// ⟨M04⟩ Wire the runtime's login entry ([`LoginEntryPort`]). Without it the setup item
    /// answers `driver_unavailable` and `inspect capabilities` reports `login_start`
    /// `none`.
    pub fn set_login_entry(&self, port: Arc<dyn LoginEntryPort>) {
        *self
            .inner
            .login_entry
            .port
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(port);
    }

    fn login_port(&self) -> Option<Arc<dyn LoginEntryPort>> {
        self.inner
            .login_entry
            .port
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// ⟨M04⟩ `inspect capabilities` → `login_start {kind, installed}` (m04-plan §5 item 7).
    pub(crate) async fn add_capabilities_login(&self, data: &mut serde_json::Value) {
        let view = match self.login_port() {
            None => LoginStartView {
                kind: LoginStartKind::None,
                installed: false,
            },
            Some(port) => {
                let read = tokio::task::spawn_blocking(move || (port.kind(), port.observe())).await;
                match read {
                    Ok((kind, state)) => LoginStartView {
                        kind,
                        installed: matches!(state, Ok(LoginEntryState::Owned)),
                    },
                    Err(_) => return,
                }
            }
        };
        if let (serde_json::Value::Object(map), Ok(v)) = (data, serde_json::to_value(view)) {
            map.insert("login_start".to_owned(), v);
        }
    }

    /// ⟨M04⟩ The login-entry part of [`Operations::setup`]: `Some` when `req` is a
    /// login-entry preview, or an apply or rollback of a remembered login-entry plan;
    /// `None` leaves the request to the projection items (module docs). The caller is the
    /// owner.
    pub(crate) async fn login_entry_setup(
        &self,
        caller: &Caller,
        req: &SetupRequest,
    ) -> Option<OpResult<serde_json::Value>> {
        match req {
            SetupRequest::Preview { intent } => match classify(intent) {
                Class::Other => None,
                Class::Mixed => Some(Err(OpError::new(
                    heimdall_contract::Code::UsageError,
                    "the login entry is set up on its own: preview it without other items",
                )
                .with_effect(EffectStatus::None))),
                Class::Entry(action) => Some(self.login_preview(intent, action).await),
            },
            SetupRequest::Apply { plan_digest, .. }
            | SetupRequest::Rollback { plan_digest, .. } => {
                let intent = self.recall_login(plan_digest)?;
                let Class::Entry(action) = classify(&intent) else {
                    return None;
                };
                // The request kind must match the plan's action.
                let rollback = matches!(req, SetupRequest::Rollback { .. });
                if rollback != (action == Action::Remove) {
                    return Some(Err(stale()));
                }
                Some(
                    self.login_effect(caller, &intent, action, plan_digest)
                        .await,
                )
            }
            _ => None,
        }
    }

    fn recall_login(&self, digest: &PlanDigest) -> Option<PreviewIntent> {
        self.inner
            .login_entry
            .previews
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(d, _)| d == digest)
            .map(|(_, i)| i.clone())
    }

    fn remember_login(&self, digest: &PlanDigest, intent: &PreviewIntent) {
        let mut p = self
            .inner
            .login_entry
            .previews
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        p.retain(|(d, _)| d != digest);
        p.push_back((digest.clone(), intent.clone()));
        while p.len() > PREVIEW_MEMORY {
            p.pop_front();
        }
    }

    /// Observe the entry (on the blocking pool; a registry or file read).
    async fn observe_entry(
        port: &Arc<dyn LoginEntryPort>,
        action: Action,
    ) -> Result<Observed, OpError> {
        let port = Arc::clone(port);
        tokio::task::spawn_blocking(move || {
            let kind = port.kind();
            let state = port.observe().map_err(failure)?;
            let data = match action {
                Action::Install => port.render().ok(),
                Action::Remove => None,
            };
            Ok::<_, OpError>(Observed {
                kind,
                location: port.location(),
                state,
                data,
            })
        })
        .await
        .map_err(|_| internal("the login entry could not be read"))?
    }

    async fn login_preview(
        &self,
        intent: &PreviewIntent,
        action: Action,
    ) -> OpResult<serde_json::Value> {
        let Some(port) = self.login_port() else {
            return Err(OpError::driver_unavailable(
                "the login entry is not available in this runtime",
            ));
        };
        let observed = Self::observe_entry(&port, action).await?;
        let digest = digest_of(intent, &observed)?;
        let (severity, message, reason_code) = describe(action, &observed);
        let plan = SetupPlan {
            plan_digest: digest.clone(),
            intent: intent.clone(),
            mode: SetupMode::Automatic,
            manual_reasons: Vec::new(),
            files: Vec::new(),
            git: None,
            aliases: Vec::new(),
            consent: ConsentNeed {
                decision_required: false,
                reasons: Vec::new(),
            },
            unaffected_names_checked: 0,
            findings: vec![Finding {
                code: heimdall_contract::doctor::finding::LOGIN_ENTRY.to_owned(),
                severity,
                subject: ResourceRef {
                    kind: "login_entry".to_owned(),
                    id: Some(observed.location.clone()),
                },
                level: ProbeLevel::Static,
                provenance: None,
                message,
                next: NextAction::for_code(Code::Ok),
                reason: reason_code.map(str::to_owned),
            }],
        };
        self.remember_login(&digest, intent);
        let data =
            serde_json::to_value(&plan).map_err(|_| internal("the plan cannot be rendered"))?;
        Ok(Completed::ok(Code::Ok, data))
    }

    async fn login_effect(
        &self,
        caller: &Caller,
        intent: &PreviewIntent,
        action: Action,
        digest: &PlanDigest,
    ) -> OpResult<serde_json::Value> {
        if !caller.is_attended() {
            return Err(OpError::new(
                Code::InteractionRequired,
                "the login entry is written and removed only from an attended session",
            )
            .with_effect(EffectStatus::None));
        }
        let Some(port) = self.login_port() else {
            return Err(OpError::driver_unavailable(
                "the login entry is not available in this runtime",
            ));
        };
        let observed = Self::observe_entry(&port, action).await?;
        if digest_of(intent, &observed)? != *digest {
            return Err(stale());
        }
        if observed.state == LoginEntryState::Foreign {
            return Err(conflict());
        }
        let kind = observed.kind;
        let location = observed.location.clone();
        let p = Arc::clone(&port);
        let effect = tokio::task::spawn_blocking(move || match action {
            Action::Install => p.install(),
            Action::Remove => p.remove(),
        })
        .await
        .map_err(|_| internal("the login entry operation stopped"))?
        .map_err(failure)?;
        self.record_login_resource(&location, action).await;
        let outcome = match (action, effect) {
            (Action::Remove, LoginEntryEffect::Absent) => ItemOutcomeKind::NotApplied,
            _ => ItemOutcomeKind::Applied,
        };
        let item = ItemOutcome {
            item: ProjectionItem::LoginEntry,
            outcome,
            files: Vec::new(),
        };
        let data = serde_json::json!({
            "generation": 0,
            "items": [item],
            "remaining": [],
            "login_entry": {
                "kind": kind_word(kind),
                "location": location,
                "effect": effect_word(effect),
            },
        });
        Ok(Completed::ok(Code::Ok, data))
    }

    /// Record (or retire) the entry as an owned resource, best effort: the entry's own
    /// data, not this row, is what ownership rests on.
    async fn record_login_resource(&self, location: &str, action: Action) {
        let environment = self.environment().clone();
        let id = login_resource_id(&environment, location);
        let now = self.local_clock_wall();
        let locator = location.to_owned();
        let state = match action {
            Action::Install => ResourceState::Present,
            Action::Remove => ResourceState::Absent,
        };
        let written = self
            .local_write(move |tx, _| {
                let (generation, expected) = match tx.resource(&id)? {
                    Some(old) => (
                        ResourceGeneration(old.generation.0 + 1),
                        Some(old.generation),
                    ),
                    None => (ResourceGeneration(1), None),
                };
                tx.upsert_resource(
                    &ManagedResource {
                        id: id.clone(),
                        kind: ResourceKind::LoginEntry,
                        owner: OwnerRef::Runtime,
                        generation,
                        desired: state,
                        observed: state,
                        last_operation: None,
                        locator,
                        updated_at: now,
                    },
                    expected,
                )
            })
            .await;
        if written.is_err() {
            tracing::warn!("the login entry's resource record could not be written");
        }
    }
}

/// The owned resource record of the entry at `location` in `environment`
/// (`ResourceKind::LoginEntry`): a stable ID derived from both, so a repeated install
/// updates one row.
#[must_use]
pub fn login_resource_id(
    environment: &heimdall_contract::ids::EnvironmentId,
    location: &str,
) -> ResourceId {
    let mut input = b"heimdall login entry resource\0".to_vec();
    input.extend_from_slice(environment.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(location.as_bytes());
    let digest = Sha256Hex::of(&input);
    let mut bytes = [0u8; 16];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&digest.as_str()[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    ResourceId::from_random_bytes(bytes)
}

/// The finding's severity, message and sub-reason for a plan.
fn describe(action: Action, o: &Observed) -> (FindingSeverity, String, Option<&'static str>) {
    let kind = kind_word(o.kind);
    if o.kind == LoginStartKind::None {
        return (
            FindingSeverity::Warning,
            "this host has no user session manager: no login entry is possible, and the runtime starts on demand".to_owned(),
            Some(heimdall_contract::doctor::finding::LOGIN_ENTRY_ON_DEMAND),
        );
    }
    match (action, o.state) {
        (_, LoginEntryState::Foreign) => (
            FindingSeverity::Problem,
            format!(
                "{kind} at {}: another entry is at Heimdall's name; it is left untouched and nothing is written",
                o.location
            ),
            Some(reason::LOGIN_ENTRY_CONFLICT),
        ),
        (Action::Install, state) => {
            let what = match state {
                LoginEntryState::Owned => "replace Heimdall's own entry (the same data is a no-op)",
                _ => "create the entry",
            };
            (
                FindingSeverity::Info,
                format!(
                    "{kind} at {}: {what}. Data written:\n{}\nThe runtime then starts at your next login (`service run --login`, which yields to a running instance); it never enables lingering",
                    o.location,
                    o.data.as_deref().unwrap_or_default()
                ),
                None,
            )
        }
        (Action::Remove, LoginEntryState::Owned) => (
            FindingSeverity::Info,
            format!("{kind} at {}: remove Heimdall's own entry", o.location),
            None,
        ),
        (Action::Remove, _) => (
            FindingSeverity::Info,
            format!(
                "{kind} at {}: there is no Heimdall entry to remove",
                o.location
            ),
            None,
        ),
    }
}
