//! ⟨M04 U3b⟩ WSL distributions: `wsl_enable` and `wsl_disable` (ADR-0010 §2, §3 item 13,
//! §9 item 2; m04-plan U3; ADR-0006 revision 5 §17.1 item 2).
//!
//! **Mode A** (ADR-0010 §2) gives a distribution no environment record. `wsl_enable
//! {mode_a}` writes only its [`WslDistributionRecord`]: the Linux account its helper runs as,
//! and the **projection namespace** its items are recorded under (minted once). It changes
//! nothing inside the distribution. The distribution's Git item is then applied through the
//! M02 setup flow, a preview and apply of `distribution_git` naming the distribution. The
//! setup driver routes that intent to the distribution's writer
//! ([`crate::ports::DistributionHost::writer`], the helper over `heimdall-wsl/1`), so the
//! receipts and item commits are durable here, on the Windows side (ADR-0010 §9 item 2).
//! Mode A alone is setup-confirmed, not decision-recorded (revision 5 §17.1 item 2).
//!
//! **`wsl_disable`** ends Mode A once its Git item is rolled back. The CLI previews and
//! applies that rollback first. A distribution that is stopped, when the request does not
//! carry the explicit authorized `start`, is never started: its rollback stays a retained,
//! reported obligation (`cleanup_pending`), and the record keeps its namespace and every
//! owned resource. A rollback is never claimed without being done.
//!
//! **Mode B** is wave 2's (U4). Until then a `mode_b` request answers `driver_unavailable`,
//! before anything is read or written.
//!
//! Both requests are owner-only: the dispatcher refuses any other role first, and so does
//! [`Operations::wsl_request`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use heimdall_contract::Code;
use heimdall_contract::envelope::{EffectStatus, reason};
use heimdall_contract::environment::{
    DistributionGuid, EnvironmentKindView, EnvironmentRequest, EnvironmentState, EnvironmentView,
    MAX_ENVIRONMENT_LABEL_BYTES, RealizationView, WslMode,
};
use heimdall_contract::ids::OperationId;
use heimdall_contract::setup::ProjectionItem;
use heimdall_domain::environment::WslDistributionRecord;

use crate::Operations;
use crate::context::Caller;
use crate::error::{Completed, OpError, OpResult};
use crate::ports::{DiscoveredDistribution, DistributionHost, DistributionTarget, RunningState};

/// The per-instance WSL state: the host, when the runtime wired one, and the setup
/// operations whose driver may start a stopped distribution right now.
#[derive(Default)]
pub(crate) struct WslState {
    host: RwLock<Option<Arc<dyn DistributionHost>>>,
    /// Operation → how many owner requests are leading it now
    /// ([`Operations::allow_distribution_start`]).
    start_allowed: Arc<Mutex<BTreeMap<OperationId, usize>>>,
}

/// While alive, the setup driver of each named operation may start a stopped WSL
/// distribution its intent names: the owner's own request or decision leads it
/// (ADR-0010 §3 item 9, §9 item 2). Dropped when that request stops leading, so a
/// restart's or the supervisor's later drive of the same operation may not.
pub(crate) struct StartAllowed {
    set: Arc<Mutex<BTreeMap<OperationId, usize>>>,
    ops: Vec<OperationId>,
}

impl Drop for StartAllowed {
    fn drop(&mut self) {
        let mut set = self.set.lock().unwrap_or_else(PoisonError::into_inner);
        for id in &self.ops {
            if let Some(n) = set.get_mut(id) {
                *n -= 1;
                if *n == 0 {
                    set.remove(id);
                }
            }
        }
    }
}

impl std::fmt::Debug for WslState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wired = self
            .host
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        f.debug_struct("WslState").field("host", &wired).finish()
    }
}

/// Whether `account` is an acceptable Linux account name for `wsl.exe -u`: 1 to 32
/// bytes (and within the revision-5 label bound), starting with a letter or `_`, then
/// letters, digits, `_`, `-` or `.`, with an optional final `$`. Conservative on purpose:
/// it is passed as one argument, but it also names an identity.
#[must_use]
pub fn account_ok(account: &str) -> bool {
    let body = account.strip_suffix('$').unwrap_or(account);
    let mut bytes = body.bytes();
    account.len() <= 32.min(MAX_ENVIRONMENT_LABEL_BYTES)
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// The modes a record has enabled.
fn modes(rec: &WslDistributionRecord) -> Vec<WslMode> {
    let mut m = Vec::new();
    if rec.mode_a {
        m.push(WslMode::A);
    }
    if rec.mode_b.is_some() {
        m.push(WslMode::B);
    }
    m
}

/// ⟨I-6⟩ A Mode A distribution's `EnvironmentView`: its projection namespace as the ID,
/// state from the running set (`Unknown` reads as not running), no helper (Mode B's).
/// `None` for a record without a namespace (Mode A never enabled).
#[must_use]
pub fn distribution_view(
    rec: &WslDistributionRecord,
    running: RunningState,
) -> Option<EnvironmentView> {
    let namespace = rec.namespace.clone()?;
    Some(EnvironmentView {
        environment_id: namespace,
        kind: EnvironmentKindView::WslDistribution,
        label: None,
        state: if running == RunningState::Running {
            EnvironmentState::Active
        } else {
            EnvironmentState::NotRunning
        },
        realization: RealizationView::Wsl {
            name: rec.name.clone(),
            guid: rec.guid.clone(),
            account: rec.account.clone().unwrap_or_default(),
            modes: modes(rec),
            helper: None,
        },
    })
}

/// The target for a distribution's Mode A items, from its record: `None` while Mode A
/// was never enabled for an account (no account or no namespace).
#[must_use]
pub fn mode_a_target(rec: &WslDistributionRecord) -> Option<DistributionTarget> {
    Some(DistributionTarget {
        guid: rec.guid.clone(),
        name: rec.name.clone(),
        account: rec.account.clone()?,
        namespace: rec.namespace.clone()?,
    })
}

fn unavailable() -> OpError {
    OpError::new(
        Code::CapabilityUnavailable,
        "WSL is not available to this runtime",
    )
    .with_reason(reason::WSL_UNAVAILABLE)
    .with_effect(EffectStatus::None)
}

fn unknown_distribution() -> OpError {
    OpError::new(
        Code::NotFound,
        "no registered WSL distribution has this GUID",
    )
    .with_reason(reason::WSL_DISTRIBUTION_UNKNOWN)
    .with_resource("distribution", None)
    .with_effect(EffectStatus::None)
}

fn usage(msg: &str) -> OpError {
    OpError::new(Code::UsageError, msg).with_effect(EffectStatus::None)
}

fn conflict(msg: &str) -> OpError {
    OpError::new(Code::ConfigConflict, msg).with_effect(EffectStatus::None)
}

fn view_data(view: Option<EnvironmentView>) -> Result<serde_json::Value, OpError> {
    let view =
        view.ok_or_else(|| OpError::new(Code::InternalError, "the distribution has no namespace"))?;
    Ok(serde_json::json!({ "environment": view }))
}

impl Operations {
    /// ⟨M04 U3b⟩ Wire the WSL host (the runtime's `heimdall_wsl` host, or a test's).
    /// Without it every WSL request answers `wsl_unavailable`, and every
    /// distribution setup intent answers `driver_unavailable`.
    pub fn set_distribution_host(&self, host: Arc<dyn DistributionHost>) {
        *self
            .inner
            .wsl
            .host
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(host);
    }

    /// The WSL host, when wired.
    pub(crate) fn distribution_host(&self) -> Option<Arc<dyn DistributionHost>> {
        self.inner
            .wsl
            .host
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// ⟨M04 U3b⟩ Mark `ops` as led by the owner's own request or decision while the
    /// returned guard lives ([`StartAllowed`]).
    pub(crate) fn allow_distribution_start(&self, ops: &[OperationId]) -> StartAllowed {
        let set = Arc::clone(&self.inner.wsl.start_allowed);
        {
            let mut s = set.lock().unwrap_or_else(PoisonError::into_inner);
            for id in ops {
                *s.entry(id.clone()).or_default() += 1;
            }
        }
        StartAllowed {
            set,
            ops: ops.to_vec(),
        }
    }

    /// Whether the driver of `op` may start a stopped distribution now.
    pub(crate) fn distribution_start_allowed(&self, op: &OperationId) -> bool {
        self.inner
            .wsl
            .start_allowed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(op)
    }

    /// ⟨M04 U3b⟩ Drive again every open or unresolved setup operation whose intent names
    /// a WSL distribution (`distribution` given: only that one's), from its durable state:
    /// a reconcile through a fresh helper, never a second `apply`. The runtime calls it once
    /// the host is wired (restart recovery ran before it, so such an operation was left
    /// unresolved there), and `wsl enable`/`wsl disable` call it for their distribution,
    /// as the owner's explicit action on it, which may start it ([`StartAllowed`]). A
    /// distribution still not reachable leaves its operation where it is: a retained
    /// obligation (ADR-0010 §9 item 2). Failures are logged, never raised.
    pub async fn redrive_distribution_setups(
        &self,
        distribution: Option<&DistributionGuid>,
        explicit: bool,
    ) {
        let only = distribution.cloned();
        let ids = self
            .local_write(move |tx, _| {
                let mut ids = Vec::new();
                for op in tx
                    .open_operations()?
                    .into_iter()
                    .chain(tx.unresolved_operations()?)
                {
                    if !op.kind.is_setup() || ids.contains(&op.id) {
                        continue;
                    }
                    let Some(intent) = tx.recovery_intent(&op.id)? else {
                        continue;
                    };
                    let Some(heimdall_domain::operation::LocalIntent::Setup(setup)) = intent.local
                    else {
                        continue;
                    };
                    let named = match crate::setup::distribution_form(&setup.intent) {
                        Ok(Some(g)) => g,
                        _ => continue,
                    };
                    if only.as_ref().is_none_or(|o| *o == named) {
                        ids.push(op.id);
                    }
                }
                Ok(ids)
            })
            .await;
        let ids = match ids {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(code = %e.code, "distribution setup operations could not be listed");
                return;
            }
        };
        let allowed = explicit.then(|| self.allow_distribution_start(&ids));
        for id in &ids {
            if let Err(e) = self.lead_local_setup(id).await {
                tracing::warn!(code = %e.code, "a distribution setup operation is still unfinished");
            }
        }
        drop(allowed);
    }

    /// Lead one setup operation's driver, bounded by the request bound (it continues
    /// past it, observable).
    async fn lead_local_setup(&self, id: &OperationId) -> Result<(), OpError> {
        self.local_lead_bounded(
            id,
            crate::operations::LocalDriver::Setup,
            self.limits().max_wait,
        )
        .await
        .unwrap_or(Ok(()))
    }

    /// ⟨M04 U3b⟩ `inspect environments`' WSL rows with their state from the host's running
    /// listing (`active` when listed, `not_running` otherwise, as `Unknown` reads); a
    /// removed or gone row keeps its state. Without a host, the data is returned as it is.
    pub(crate) async fn wsl_running_states(
        &self,
        mut data: serde_json::Value,
    ) -> serde_json::Value {
        let Some(host) = self.distribution_host() else {
            return data;
        };
        let Some(items) = data.get_mut("items").and_then(|i| i.as_array_mut()) else {
            return data;
        };
        let guids: Vec<(usize, DistributionGuid)> = items
            .iter()
            .enumerate()
            .filter(|(_, v)| {
                v["kind"] == "wsl_distribution"
                    && matches!(v["state"].as_str(), Some("active" | "not_running"))
            })
            .filter_map(|(i, v)| {
                serde_json::from_value(v["realization"]["guid"].clone())
                    .ok()
                    .map(|g| (i, g))
            })
            .collect();
        if guids.is_empty() {
            return data;
        }
        let states = tokio::task::spawn_blocking(move || {
            guids
                .into_iter()
                .map(|(i, g)| (i, host.running(&g)))
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        for (i, running) in states {
            if let Some(item) = items.get_mut(i) {
                item["state"] = serde_json::json!(if running == RunningState::Running {
                    "active"
                } else {
                    "not_running"
                });
            }
        }
        data
    }

    /// ⟨M04 U3b⟩ `wsl_enable` and `wsl_disable` (module docs). Owner only; synchronous;
    /// no operation row or request ID (revision 5 §17.1 item 2).
    ///
    /// # Errors
    /// `CAPABILITY_UNAVAILABLE` for a non-owner, `wsl_unavailable` without a host and
    /// `driver_unavailable` for Mode B; `NOT_FOUND` (`wsl_distribution_unknown`);
    /// `USAGE_ERROR` and `CONFIG_CONFLICT` before anything is written.
    pub async fn wsl_request(
        &self,
        caller: &Caller,
        req: EnvironmentRequest,
    ) -> OpResult<serde_json::Value> {
        if !caller.context.is_owner() {
            return Err(OpError::new(
                Code::CapabilityUnavailable,
                "this request needs the owner role",
            )
            .with_effect(EffectStatus::None));
        }
        match req {
            EnvironmentRequest::WslEnable {
                distribution_guid,
                account,
                mode_a,
                mode_b,
            } => {
                self.wsl_enable(distribution_guid, account, mode_a, mode_b)
                    .await
            }
            EnvironmentRequest::WslDisable {
                distribution_guid,
                start,
            } => self.wsl_disable(distribution_guid, start).await,
            _ => Err(usage("not a WSL request")),
        }
    }

    async fn wsl_discover(
        &self,
        guid: &DistributionGuid,
    ) -> Result<
        (
            Arc<dyn DistributionHost>,
            DiscoveredDistribution,
            RunningState,
        ),
        OpError,
    > {
        let host = self.distribution_host().ok_or_else(unavailable)?;
        let h = Arc::clone(&host);
        let g = guid.clone();
        let (found, running) = tokio::task::spawn_blocking(move || {
            let listed = h.discover();
            let running = h.running(&g);
            (listed, running)
        })
        .await
        .map_err(|_| OpError::new(Code::InternalError, "the WSL discovery task failed"))?;
        let found = found.map_err(|_| unavailable())?;
        let d = found
            .into_iter()
            .find(|d| d.guid == *guid)
            .ok_or_else(unknown_distribution)?;
        Ok((host, d, running))
    }

    async fn wsl_enable(
        &self,
        guid: DistributionGuid,
        account: String,
        mode_a: bool,
        mode_b: bool,
    ) -> OpResult<serde_json::Value> {
        if mode_b {
            return Err(OpError::driver_unavailable(
                "WSL Mode B is not available in this build",
            ));
        }
        if !mode_a {
            return Err(usage("name at least one mode (--mode-a or --mode-b)"));
        }
        if !account_ok(&account) {
            return Err(usage("the Linux account name is not acceptable"));
        }
        let (_host, found, running) = self.wsl_discover(&guid).await?;
        // The owner's explicit action on this distribution: finish what it left first.
        self.redrive_distribution_setups(Some(&guid), true).await;
        let fresh = crate::ids::new_environment_id()?;
        let at = self.local_clock_wall();
        let rec = self
            .local_write(move |tx, _| {
                let existing = tx.wsl_distribution(&guid)?;
                if let Some(r) = &existing {
                    if r.cleanup_pending {
                        return Ok(Err(conflict(
                            "the distribution has a retained cleanup: run `heimdall wsl disable \
                             <name> --start` first",
                        )));
                    }
                    if r.mode_a && r.account.as_deref() != Some(account.as_str()) {
                        return Ok(Err(conflict(
                            "Mode A is enabled for another account: disable it first",
                        )));
                    }
                }
                let mut rec = existing.unwrap_or(WslDistributionRecord {
                    guid: guid.clone(),
                    name: found.name.clone(),
                    mode_a: false,
                    mode_b: None,
                    cleanup_pending: false,
                    account: None,
                    namespace: None,
                    updated_at: at,
                });
                rec.name = found.name.clone();
                rec.mode_a = true;
                rec.account = Some(account);
                if rec.namespace.is_none() {
                    rec.namespace = Some(fresh);
                }
                rec.updated_at = at;
                tx.put_wsl_distribution(&rec)?;
                Ok(Ok(rec))
            })
            .await??;
        Ok(Completed::ok(
            Code::Ok,
            view_data(distribution_view(&rec, running))?,
        ))
    }

    async fn wsl_disable(
        &self,
        guid: DistributionGuid,
        start: bool,
    ) -> OpResult<serde_json::Value> {
        let host = self.distribution_host().ok_or_else(unavailable)?;
        // A setup operation it left unfinished is driven again first: it may start the
        // distribution only with the explicit `start`.
        self.redrive_distribution_setups(Some(&guid), start).await;
        let h = Arc::clone(&host);
        let g = guid.clone();
        let running = tokio::task::spawn_blocking(move || h.running(&g))
            .await
            .map_err(|_| OpError::new(Code::InternalError, "the WSL listing task failed"))?;
        let at = self.local_clock_wall();
        let (rec, retained) = self
            .local_write(move |tx, _| {
                let Some(mut rec) = tx.wsl_distribution(&guid)? else {
                    return Ok(Err(unknown_distribution()));
                };
                if rec.mode_b.is_some() {
                    return Ok(Err(OpError::driver_unavailable(
                        "WSL Mode B is not available in this build",
                    )));
                }
                let live = match &rec.namespace {
                    Some(ns) => tx.projection_record(ns)?.is_some_and(|r| {
                        r.items
                            .get(&ProjectionItem::Git)
                            .is_some_and(|i| !(i.files.is_empty() && i.aliases.is_empty()))
                    }),
                    None => false,
                };
                let reachable = start || running == RunningState::Running;
                if live && reachable {
                    return Ok(Err(conflict(
                        "the distribution's Git item is still applied: roll it back first \
                         (`heimdall wsl disable` previews and applies the rollback)",
                    )));
                }
                rec.mode_a = false;
                rec.cleanup_pending = live;
                rec.updated_at = at;
                tx.put_wsl_distribution(&rec)?;
                Ok(Ok((rec, live)))
            })
            .await??;
        // A retained cleanup is reported in the data (I-7): the distribution was not
        // running and the request did not carry `start`, so its Git item was not rolled
        // back, and the record keeps its namespace and owned resources until `wsl disable
        // --start`, or a `wsl disable` while it runs, rolls it back.
        let mut data = view_data(distribution_view(&rec, running))?;
        data["cleanup_pending"] = serde_json::Value::Bool(retained);
        Ok(Completed::ok(Code::Ok, data))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn account_names_are_conservative() {
        for ok in ["ubuntu", "_svc", "a.b-c_d", "build$", "U1"] {
            assert!(account_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "-root",
            "1abc",
            "a b",
            "a/b",
            "a\u{0}",
            "é",
            &"a".repeat(33),
            "$",
        ] {
            assert!(!account_ok(bad), "{bad:?}");
        }
    }
}
