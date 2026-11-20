//! ⟨M04⟩ U5: the local Linux-container binding recipe's operations (ADR-0010 §4; revision 5
//! §17.2; the integrator's design, `design-u5.md`).
//!
//! * **`container_add {label}`** (host first, then the label rules) creates an
//!   [`DecisionKind::AddEnvironment`] decision, as `issuer.register` creates its decision: an
//!   equal pending one is joined, never duplicated; the answer is `INTERACTION_REQUIRED` /
//!   `APPROVAL_REQUIRED` with `next.decision_ref`. Approval ([`decision_apply`], inside
//!   `Operations::decide`'s transaction) inserts the `managed_environments` row, the
//!   environment's record (`managed_signing` only) and moves the authority generation; after
//!   the commit ([`Operations::container_after_decision`]) the stable directory is created
//!   through the effects port. A crash between the two is repaired by the next `ensure` in
//!   that environment (the endpoint listener creates the directory).
//! * **`container_remove {environment_id}`** executes on dispatch (owner role; it removes,
//!   it adds no authority): the environment leaves the set through
//!   [`Operations::retire_managed_environment`] (its grants end through the withdrawal path,
//!   so each grant's own cleanup runs), then the effects stop what serves the directory and
//!   remove the entries Heimdall wrote, through the quarantine. Idempotent.
//! * **[`admit_binding`]** is the one call the admission transaction makes for `ensure`
//!   (ADR-0010 §4 item 3): one active binding per container environment.
//! * **[`realization_descriptor`]** is the mount instruction (§4 item 4), shared by the
//!   `ensure` result and `heimdall container mount-args`.
//!
//! Every environment request that completes answers `OK` with `{"environment":
//! <EnvironmentView>}` (the view `inspect environments` lists, [`environment_view`]).

use std::path::PathBuf;

use heimdall_contract::envelope::reason;
use heimdall_contract::environment::{
    EnvironmentKindView, EnvironmentState, EnvironmentView, EnvironmentsView,
    MAX_ENVIRONMENT_LABEL_BYTES, MountSpec, RealizationDescriptor, RealizationView, WslMode,
};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{ConsumerIntegration, Request, Verdict};
use heimdall_contract::{Code, EffectStatus, Timestamp};
use heimdall_domain::decision::{DecisionKind, DecisionRecord, DecisionState};
use heimdall_domain::environment::{
    EnvironmentDisclosure, EnvironmentKind, EnvironmentPermissions, EnvironmentRealization,
    ManagedEnvironment, ManagedState,
};
use heimdall_domain::operation::OperationRecord;
use heimdall_store::{StoreError, Txn};

use super::{Emit, Operations, approval_needed, internal, plus};
use crate::context::Caller;
use crate::environments::{
    CONTAINER_AGENT_SOCKET, CONTAINER_CONFIG, CONTAINER_MOUNT_TARGET, unmanaged,
};
use crate::error::{Completed, OpError, OpResult};
use crate::timegate::uncertain;

/// The message of the non-Linux refusal (ADR-0010 §4 item 7).
pub const HOST_REFUSAL: &str =
    "container environments need a Linux-native runtime (ADR-0010 §4 item 7)";

fn owner_only() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "this request needs the owner role",
    )
    .with_effect(EffectStatus::None)
}

fn host_refused() -> OpError {
    OpError::driver_unavailable(HOST_REFUSAL)
}

fn usage(msg: &str) -> OpError {
    OpError::new(Code::UsageError, msg.to_owned()).with_effect(EffectStatus::None)
}

/// The label rules: 1 to [`MAX_ENVIRONMENT_LABEL_BYTES`] bytes, no control characters.
fn label_ok(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_ENVIRONMENT_LABEL_BYTES
        && !label.chars().any(char::is_control)
}

/// Whether `tag` is a directory tag this module accepts (16 lowercase hex characters).
fn tag_ok(tag: &str) -> bool {
    tag.len() == 16 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 16 random lowercase hex characters from the OS CSPRNG; never derived from the label.
fn new_dir_tag() -> Result<String, OpError> {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| internal("operating system randomness unavailable"))?;
    let mut tag = String::with_capacity(16);
    for b in bytes {
        let _ = write!(tag, "{b:02x}");
    }
    Ok(tag)
}

/// The mount instruction of a container environment whose host directory is `directory`
/// (ADR-0010 §4 item 4): a read-only bind of the directory at `/run/heimdall`,
/// `SSH_AUTH_SOCK`, and `GIT_SSH_COMMAND`. Paths inside the container are fixed; the host
/// path is the only variable part.
#[must_use]
pub fn realization_descriptor(directory: &str) -> RealizationDescriptor {
    RealizationDescriptor {
        environment_kind: EnvironmentKindView::Container,
        endpoint: Some(CONTAINER_AGENT_SOCKET.to_owned()),
        config: Some(CONTAINER_CONFIG.to_owned()),
        mount: Some(MountSpec {
            source: directory.to_owned(),
            target: CONTAINER_MOUNT_TARGET.to_owned(),
            read_only: true,
        }),
        environment: vec![
            (
                "SSH_AUTH_SOCK".to_owned(),
                CONTAINER_AGENT_SOCKET.to_owned(),
            ),
            (
                "GIT_SSH_COMMAND".to_owned(),
                format!("ssh -F {}", sh_word(CONTAINER_CONFIG)),
            ),
        ],
    }
}

/// ⟨M04 W2 review, M04-W2-R04⟩ `text` as one POSIX shell word, for the command lines the
/// descriptor gives (Git runs `GIT_SSH_COMMAND` through `sh`): as it is when it holds only
/// `[A-Za-z0-9/._-]`, otherwise single-quoted with each `'` written `'\''`. The raw path
/// fields of the descriptor stay as they are.
#[must_use]
pub fn sh_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

fn state_view(s: ManagedState) -> EnvironmentState {
    match s {
        ManagedState::Active => EnvironmentState::Active,
        ManagedState::NotRunning => EnvironmentState::NotRunning,
        ManagedState::Removed => EnvironmentState::Removed,
        _ => EnvironmentState::Gone,
    }
}

/// One managed row as `inspect environments` and every environment answer show it.
/// `directory` is the host path of a container's stable directory (from the effects; empty
/// where the runtime realizes none).
///
/// # Errors
/// A store error (the WSL distribution record lookup).
pub fn environment_view(
    tx: &mut Txn<'_>,
    row: &ManagedEnvironment,
    directory: Option<&std::path::Path>,
) -> heimdall_store::Result<EnvironmentView> {
    let label = tx.environment(&row.environment)?.and_then(|e| e.label);
    let (kind, label, realization) = match &row.realization {
        EnvironmentRealization::Container { label, dir_tag } => {
            let directory = directory.map_or_else(
                || format!("c/{dir_tag}"),
                |d| d.to_string_lossy().into_owned(),
            );
            (
                EnvironmentKindView::Container,
                Some(label.clone()),
                RealizationView::Container {
                    label: label.clone(),
                    directory,
                    in_container_path: CONTAINER_MOUNT_TARGET.to_owned(),
                },
            )
        }
        EnvironmentRealization::Wsl {
            guid,
            name,
            account,
        } => {
            let mut modes = vec![WslMode::B];
            if tx.wsl_distribution(guid)?.is_some_and(|d| d.mode_a) {
                modes.insert(0, WslMode::A);
            }
            (
                EnvironmentKindView::WslDistribution,
                label,
                RealizationView::Wsl {
                    name: name.clone(),
                    guid: guid.clone(),
                    account: account.clone(),
                    modes,
                    helper: None,
                },
            )
        }
        // A future realization is shown as what it is not: nothing claimed.
        _ => (
            EnvironmentKindView::Container,
            label,
            RealizationView::Native,
        ),
    };
    Ok(EnvironmentView {
        environment_id: row.environment.clone(),
        kind,
        label,
        state: state_view(row.state),
        realization,
    })
}

/// `inspect environments` for the owner (design §3): the native entry first, then every
/// managed row of this runtime in any state, by ID.
///
/// # Errors
/// A store error.
pub fn environments_view(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    directory_of: &dyn Fn(&str) -> Option<PathBuf>,
) -> heimdall_store::Result<EnvironmentsView> {
    let label = tx.environment(own)?.and_then(|e| e.label);
    let mut items = vec![EnvironmentView {
        environment_id: own.clone(),
        kind: EnvironmentKindView::NativeSession,
        label,
        state: EnvironmentState::Active,
        realization: RealizationView::Native,
    }];
    for row in tx.managed_environments()? {
        if row.controller != *own {
            continue;
        }
        let dir = match &row.realization {
            EnvironmentRealization::Container { dir_tag, .. } => directory_of(dir_tag),
            _ => None,
        };
        items.push(environment_view(tx, &row, dir.as_deref())?);
    }
    // ⟨M04 U3b; reading I-6⟩ A distribution served in Mode A only has no environment record:
    // it is listed with its projection namespace as the ID (never an `ensure` target), its
    // state read as not running until the caller asks the WSL host. A Mode B distribution is
    // its environment's row above, which carries both modes.
    for rec in tx.wsl_distributions()? {
        if rec.mode_b.is_none()
            && (rec.mode_a || rec.cleanup_pending)
            && let Some(view) = crate::operations::wsl_m04::distribution_view(
                &rec,
                crate::ports::RunningState::Unknown,
            )
        {
            items.push(view);
        }
    }
    Ok(EnvironmentsView { items })
}

impl Operations {
    /// The wired managed effects, which also realize container directories (`None`: no
    /// effects are wired, so this runtime realizes no container).
    pub(super) fn container_effects(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::ports::ManagedEffects>> {
        self.managed_wiring().and_then(|w| w.effects.clone())
    }

    /// The owner's `container_add` (module docs).
    pub(crate) async fn container_add(
        &self,
        caller: &Caller,
        label: String,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(owner_only());
        }
        // Host first (design §1, I-3): before anything is read or written. The test
        // switch lives in the effects (`container_host_supported`).
        let effects = self.container_effects();
        if !effects
            .as_ref()
            .is_some_and(|e| e.container_host_supported())
        {
            return Err(host_refused());
        }
        if !label_ok(&label) {
            return Err(usage(
                "a container label is 1 to 64 bytes with no control characters",
            ));
        }
        let dir_tag = new_dir_tag()?;
        self.request_add_environment(
            caller,
            EnvironmentRealization::Container { label, dir_tag },
            EnvironmentDisclosure::CONTAINER.to_vec(),
            "adding a container environment needs an attended owner decision (AddEnvironment)",
        )
        .await
    }

    /// ⟨M04 U4b⟩ The `AddEnvironment` decision of any realization (the container's and WSL
    /// Mode B's share it, generalized by kind): an equal pending one is joined, never
    /// duplicated; the answer is `INTERACTION_REQUIRED` / `APPROVAL_REQUIRED` with
    /// `next.decision_ref`. The caller checked the host and the request's own fields;
    /// the realization-specific in-use rule runs inside the transaction.
    pub(super) async fn request_add_environment(
        &self,
        caller: &Caller,
        realization: EnvironmentRealization,
        disclosures: Vec<EnvironmentDisclosure>,
        message: &'static str,
    ) -> OpResult<serde_json::Value> {
        let gate = self.inner.timegate.in_txn();
        let decision_id = crate::ids::new_decision_id()?;
        let environment = crate::ids::new_environment_id()?;
        let lifetime = self.inner.config.limits.decision_lifetime;
        let own = self.environment().clone();
        let decided = self
            .write(move |tx, emit| {
                // A decision's lifetime is measured on accepted time only (G10).
                let now = match gate.check(tx)? {
                    Ok(s) => s.wall(),
                    Err(u) => return Ok(Err(uncertain(&u))),
                };
                if let Some(refusal) = in_use_refusal(tx, &own, &realization)? {
                    return Ok(Err(refusal));
                }
                let current = tx.authority_generation()?;
                let live: Vec<DecisionRecord> = tx
                    .pending_decisions()?
                    .into_iter()
                    .filter(|d| now < d.expires_at && d.generation == current)
                    .collect();
                // An equal pending request is joined, never duplicated.
                if let Some(existing) = live.iter().find(|d| {
                    matches!(&d.kind, DecisionKind::AddEnvironment {
                        realization: other, ..
                    } if same_request(other, &realization))
                }) {
                    return Ok(Ok(existing.id.clone()));
                }
                let d = DecisionRecord {
                    id: decision_id,
                    kind: DecisionKind::AddEnvironment {
                        environment,
                        realization,
                        disclosures,
                    },
                    generation: current,
                    created_at: now,
                    expires_at: plus(now, lifetime),
                    state: DecisionState::Pending,
                    decided_at: None,
                };
                tx.insert_decision(&d)?;
                emit.decision(tx, &d, None)?;
                Ok(Ok(d.id))
            })
            .await??;
        Err(
            approval_needed(caller.is_attended(), decided.as_str(), message)
                .with_resource("decision", Some(decided.to_string())),
        )
    }

    /// After `Operations::decide` committed an `AddEnvironment`: a container's stable
    /// directory is created; a WSL Mode B environment's row takes its running state
    /// ([`Operations::wsl_after_decision`]). Answers the environment's view. Never fails the
    /// decide (the record is durable); a failure to create the directory is repaired by the
    /// next `ensure`.
    pub(super) async fn container_after_decision(
        &self,
        record: &DecisionRecord,
        verdict: Verdict,
    ) -> Option<serde_json::Value> {
        let DecisionKind::AddEnvironment {
            environment,
            realization,
            ..
        } = &record.kind
        else {
            return None;
        };
        if verdict != Verdict::Approve {
            return None;
        }
        match realization {
            EnvironmentRealization::Container { dir_tag, .. } => {
                if let Some(effects) = self.container_effects() {
                    let tag = dir_tag.clone();
                    let made = tokio::task::spawn_blocking(move || {
                        effects.container_directory_create(&tag)
                    })
                    .await;
                    if !matches!(made, Ok(Ok(_))) {
                        tracing::warn!(
                            "the container directory could not be created; the next ensure repairs it"
                        );
                    }
                }
                self.container_environment_view(environment).await
            }
            EnvironmentRealization::Wsl { guid, .. } => {
                self.wsl_after_decision(environment, guid).await
            }
            _ => None,
        }
    }

    /// The view of one managed environment, `None` when it has no row.
    pub(super) async fn container_environment_view(
        &self,
        id: &EnvironmentId,
    ) -> Option<serde_json::Value> {
        let id = id.clone();
        let dirs = self.container_effects();
        self.write(move |tx, _| {
            let Some(row) = tx.managed_environment(&id)? else {
                return Ok(None);
            };
            let dir = match (&row.realization, &dirs) {
                (EnvironmentRealization::Container { dir_tag, .. }, Some(e)) => {
                    e.container_directory(dir_tag)
                }
                _ => None,
            };
            let view = environment_view(tx, &row, dir.as_deref())?;
            Ok(serde_json::to_value(view).ok())
        })
        .await
        .ok()
        .flatten()
    }

    /// The owner's `container_remove` (module docs).
    pub(crate) async fn container_remove(
        &self,
        caller: &Caller,
        environment: EnvironmentId,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(owner_only());
        }
        let own = self.environment().clone();
        let id = environment.clone();
        // The environment must be a container row this runtime controls (never its own).
        let row = self
            .write(move |tx, _| {
                Ok(tx
                    .managed_environment(&id)?
                    .filter(|r| r.controller == own && r.environment != own))
            })
            .await?;
        let Some(row) =
            row.filter(|r| matches!(r.realization, EnvironmentRealization::Container { .. }))
        else {
            return Err(unmanaged());
        };
        let EnvironmentRealization::Container { dir_tag, .. } = &row.realization else {
            return Err(unmanaged());
        };
        if row.state.in_set() {
            self.retire_managed_environment(&environment, ManagedState::Removed)
                .await?;
        }
        // Then the directory: what serves it is stopped, the entries Heimdall wrote go
        // through the quarantine, a foreign entry is left and reported.
        let mut left = Vec::new();
        if tag_ok(dir_tag)
            && let Some(effects) = self.container_effects()
        {
            let tag = dir_tag.clone();
            let report =
                tokio::task::spawn_blocking(move || effects.container_directory_remove(&tag))
                    .await
                    .map_err(|_| internal("the directory removal did not finish"))?
                    .map_err(|_| {
                        OpError::new(
                            Code::StateUnavailable,
                            "the container directory could not be removed; run the removal again",
                        )
                        .with_effect(EffectStatus::Partial)
                    })?;
            left = report.left;
        }
        let view = self.container_environment_view(&environment).await;
        let mut data = serde_json::json!({ "environment": view });
        if !left.is_empty()
            && let Some(map) = data.as_object_mut()
        {
            // Names only, bounded and printable: a foreign entry Heimdall did not write.
            let names: Vec<String> = left
                .iter()
                .take(32)
                .map(|n| n.chars().filter(|c| !c.is_control()).take(255).collect())
                .collect();
            map.insert("left_in_place".to_owned(), serde_json::json!(names));
        }
        Ok(Completed::ok(Code::Ok, data))
    }
}

/// Whether a container environment of this runtime's managed set already uses `label`.
fn container_label_in_use(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    label: &str,
) -> heimdall_store::Result<bool> {
    Ok(tx.managed_environments()?.iter().any(|r| {
        r.controller == *own
            && r.state.in_set()
            && matches!(&r.realization, EnvironmentRealization::Container { label: l, .. } if l == label)
    }))
}

// --- the decision (precheck and apply) ------------------------------------------------

/// Before completion (`decisions_m03::precheck`'s contract): refuse with nothing written.
/// A denial is never refused here.
pub(super) fn decision_precheck(
    tx: &mut Txn<'_>,
    d: &DecisionRecord,
    verdict: Verdict,
    own: &EnvironmentId,
) -> heimdall_store::Result<Result<Option<OperationRecord>, OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(None));
    }
    let DecisionKind::AddEnvironment {
        environment,
        realization,
        ..
    } = &d.kind
    else {
        return Ok(Err(OpError::driver_unavailable(
            "this decision kind is not available in this build",
        )));
    };
    match realization {
        EnvironmentRealization::Container { label, dir_tag } => {
            if !label_ok(label) || !tag_ok(dir_tag) {
                return Ok(Err(stale("the recorded environment is malformed")));
            }
            if tx.managed_environment(environment)?.is_some() {
                return Ok(Err(stale("this environment already exists")));
            }
            if container_label_in_use(tx, own, label)? {
                return Ok(Err(stale(
                    "a container environment now uses this label; add it again",
                )));
            }
            Ok(Ok(None))
        }
        EnvironmentRealization::Wsl {
            guid,
            name,
            account,
        } => crate::operations::wsl_m04::decision_precheck_wsl(
            tx,
            own,
            environment,
            guid,
            name,
            account,
        ),
        _ => Ok(Err(OpError::driver_unavailable(
            "this environment realization is not available in this build",
        ))),
    }
}

/// The refusal of a request whose realization is already in use inside the transaction, or
/// `None` (the realization-specific rule of [`Operations::request_add_environment`]).
fn in_use_refusal(
    tx: &mut Txn<'_>,
    own: &EnvironmentId,
    realization: &EnvironmentRealization,
) -> heimdall_store::Result<Option<OpError>> {
    match realization {
        EnvironmentRealization::Container { label, .. } => {
            Ok(container_label_in_use(tx, own, label)?
                .then(|| usage("a container environment already uses this label")))
        }
        EnvironmentRealization::Wsl { guid, .. } => {
            crate::operations::wsl_m04::mode_b_in_use(tx, own, guid)
        }
        _ => Ok(None),
    }
}

/// Whether two pending requests ask for the same environment: the same container label, or
/// the same distribution and account.
fn same_request(a: &EnvironmentRealization, b: &EnvironmentRealization) -> bool {
    match (a, b) {
        (
            EnvironmentRealization::Container { label: x, .. },
            EnvironmentRealization::Container { label: y, .. },
        ) => x == y,
        (
            EnvironmentRealization::Wsl {
                guid: g1,
                account: a1,
                ..
            },
            EnvironmentRealization::Wsl {
                guid: g2,
                account: a2,
                ..
            },
        ) => g1 == g2 && a1 == a2,
        _ => false,
    }
}

fn stale(msg: &str) -> OpError {
    OpError::new(Code::DecisionStale, msg.to_owned())
}

/// After the store completed `record` (same transaction): approval inserts the row and the
/// environment's record (and a Mode B distribution's `mode_b`). A denial changes nothing. An inner `Err` rolls the decide
/// transaction back.
pub(super) fn decision_apply(
    tx: &mut Txn<'_>,
    _emit: &mut Emit,
    record: &DecisionRecord,
    verdict: Verdict,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    if verdict != Verdict::Approve {
        return Ok(Ok(()));
    }
    let DecisionKind::AddEnvironment {
        environment,
        realization,
        ..
    } = &record.kind
    else {
        return Ok(Ok(()));
    };
    let (kind, label) = match realization {
        EnvironmentRealization::Container { label, .. } => {
            (EnvironmentKind::Container, Some(label.clone()))
        }
        EnvironmentRealization::Wsl { name, .. } => (
            EnvironmentKind::WslDistribution,
            Some(name.clone()).filter(|n| label_ok(n)),
        ),
        _ => {
            return Ok(Err(internal(
                "an AddEnvironment record names an unknown realization",
            )));
        }
    };
    let Some(own) = tx.self_environment()? else {
        return Ok(Err(internal("this installation has no environment")));
    };
    let device = match tx.environment(&own)? {
        Some(e) => e.device,
        None => heimdall_contract::ids::DeviceId::from_random_bytes([0; 16]),
    };
    // One transaction: the row (moves the generation), the environment's record (kind,
    // label, `managed_signing` and nothing else).
    let row = ManagedEnvironment {
        environment: environment.clone(),
        controller: own,
        realization: realization.clone(),
        state: ManagedState::Active,
        created_at: now,
        updated_at: now,
    };
    match tx.insert_managed_environment(&row) {
        Ok(()) => {}
        Err(StoreError::GenerationConflict(_)) => {
            return Ok(Err(stale("this environment already exists")));
        }
        Err(e) => return Err(e),
    }
    tx.upsert_environment(&heimdall_domain::environment::EnvironmentRecord {
        id: environment.clone(),
        device,
        kind,
        label,
        permissions: EnvironmentPermissions {
            automatic_activation: false,
            managed_signing: true,
            issuer_access: false,
        },
    })?;
    // ⟨M04 U4b⟩ A Mode B environment is also its distribution's `mode_b`.
    if let EnvironmentRealization::Wsl { guid, name, .. } = realization {
        crate::operations::wsl_m04::record_mode_b(tx, guid, name, environment, now)?;
    }
    Ok(Ok(()))
}

// --- one active binding per container environment -----------------------------------

/// ADR-0010 §4 item 3, in the `ensure` admission transaction, before anything is written:
/// a container environment serves **one** binding. Another, non-equivalent work with a live
/// binding (or an `ensure` already running) in it is `environment_busy`; the same work
/// (same work ID, same profile, same scope: the existing equivalence rule, whose follower
/// shares the grant) continues, and its binding takes the directory over. A binding that has
/// ended (released, expired, revoked) does not count, and the replacement appears at the
/// same in-container path. A delegation always adds a second binding, so it is busy.
/// Every environment that is not a container is `Ok`.
///
/// # Errors
/// A store error (outer); `environment_busy` (inner, `CONFIG_CONFLICT`).
pub(crate) fn admit_binding(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    request: &serde_json::Value,
    now: Timestamp,
) -> heimdall_store::Result<Result<(), OpError>> {
    let is_container = tx
        .managed_environment(environment)?
        .is_some_and(|r| matches!(r.realization, EnvironmentRealization::Container { .. }));
    if !is_container {
        return Ok(Ok(()));
    }
    let busy = || {
        Err(OpError::new(
            Code::ConfigConflict,
            "this container environment already serves another binding (one active binding per container environment)",
        )
        .with_reason(reason::ENVIRONMENT_BUSY)
        .with_effect(EffectStatus::None)
        .with_resource("environment", Some(environment.to_string())))
    };
    let ask = match serde_json::from_value::<Request>(request.clone()) {
        Ok(Request::Ensure(r)) => r,
        // A delegation (or any other work request) in a container environment is a second
        // binding.
        _ => return Ok(busy()),
    };
    let same_pairs = |pairs: &std::collections::BTreeSet<heimdall_domain::scope::AccessPair>| {
        ask.scope.is_empty()
            || (ask.scope.len() == pairs.len()
                && ask.scope.iter().all(|r| {
                    pairs
                        .iter()
                        .any(|p| p.destination == r.destination && p.account == r.account)
                }))
    };
    // Live bindings: the active bindings of this environment's live grants.
    for g in tx.grants_due(Timestamp::MAX)? {
        if g.environment != *environment || !g.state.permits_use() || g.deadline.effective <= now {
            continue;
        }
        for b in tx.bindings_of_grant(&g.id)? {
            let Some(b) = tx.binding(&b)? else { continue };
            if b.state != heimdall_domain::binding::BindingState::Active {
                continue;
            }
            let equivalent = b.work_id == ask.work_id
                && ask.profile.as_ref() == Some(&b.profile)
                && ask.profile_revision.is_none_or(|r| r == b.profile_revision)
                && same_pairs(&b.scope.pairs);
            if !equivalent {
                return Ok(busy());
            }
        }
    }
    // Operations already running in it, not yet bound (a concurrent ensure).
    for op in tx.open_operations()? {
        if op.environment != *environment
            || op.state == heimdall_contract::OperationState::AwaitingApproval
        {
            continue;
        }
        let other = tx
            .recovery_intent(&op.id)?
            .and_then(|i| serde_json::from_value::<Request>(i.request).ok());
        let equivalent = match other {
            Some(Request::Ensure(o)) => o.work_id == ask.work_id && o.profile == ask.profile,
            _ => false,
        };
        if !equivalent {
            return Ok(busy());
        }
    }
    Ok(Ok(()))
}

// --- the result's realization -----------------------------------------------------------

/// A container or WSL Mode B binding's `ensure` result (design §7): the native
/// `signing_endpoint` and `ssh_config_include` carry no host path; the in-environment
/// endpoint and the realization descriptor are the answer. A container's is the mount
/// instruction; a Mode B distribution's names the socket and `ssh_config` inside the
/// distribution (no mount). Other environments are untouched.
pub(crate) fn finish_integration(
    tx: &mut Txn<'_>,
    environment: &EnvironmentId,
    consumer: &mut ConsumerIntegration,
    directory_of: &dyn Fn(&str) -> Option<PathBuf>,
) -> heimdall_store::Result<()> {
    let Some(row) = tx.managed_environment(environment)? else {
        return Ok(());
    };
    let EnvironmentRealization::Container { dir_tag, .. } = &row.realization else {
        if matches!(row.realization, EnvironmentRealization::Wsl { .. }) {
            finish_wsl_integration(consumer);
        }
        return Ok(());
    };
    let directory = directory_of(dir_tag).map_or_else(
        || format!("c/{dir_tag}"),
        |d| d.to_string_lossy().into_owned(),
    );
    consumer.signing_endpoint = None;
    consumer.ssh_config_include = None;
    for p in &mut consumer.pairs {
        if p.endpoint.is_some() {
            p.endpoint = Some(EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: CONTAINER_AGENT_SOCKET.to_owned(),
            });
        }
    }
    let descriptor = realization_descriptor(&directory);
    consumer.environment.clone_from(&descriptor.environment);
    consumer.realization = Some(descriptor);
    Ok(())
}

/// ⟨M04 U4b⟩ The mode B descriptor (design §1): `endpoint` is the binding's socket inside
/// the distribution, `config` the `ssh_config` beside it (`<run>/b/<tag>/ssh_config`),
/// `environment` is `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND=ssh -F <config>` (the path one shell
/// word, [`sh_word`]), and there is no
/// mount. The native fields carry no path: Linux `ssh` and Git use the descriptor directly,
/// and nothing is written into the distribution user's `~/.ssh`.
fn finish_wsl_integration(consumer: &mut ConsumerIntegration) {
    let socket = consumer.signing_endpoint.take().or_else(|| {
        consumer
            .pairs
            .iter()
            .find_map(|p| p.endpoint.as_ref().map(|e| e.locator.clone()))
    });
    consumer.ssh_config_include = None;
    let Some(socket) = socket else { return };
    let Some((directory, _)) = socket.rsplit_once('/') else {
        return;
    };
    let config = format!("{directory}/ssh_config");
    let descriptor = wsl_realization_descriptor(&socket, &config);
    consumer.environment.clone_from(&descriptor.environment);
    consumer.realization = Some(descriptor);
}

/// ⟨M04 U4b⟩ The realization descriptor of a Mode B binding whose endpoint is `socket` and
/// whose OpenSSH configuration is `config`, both Linux paths inside the distribution.
#[must_use]
pub fn wsl_realization_descriptor(socket: &str, config: &str) -> RealizationDescriptor {
    RealizationDescriptor {
        environment_kind: EnvironmentKindView::WslDistribution,
        endpoint: Some(socket.to_owned()),
        config: Some(config.to_owned()),
        mount: None,
        environment: vec![
            ("SSH_AUTH_SOCK".to_owned(), socket.to_owned()),
            (
                "GIT_SSH_COMMAND".to_owned(),
                format!("ssh -F {}", sh_word(config)),
            ),
        ],
    }
}
