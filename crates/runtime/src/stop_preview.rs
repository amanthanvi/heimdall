//! ⟨M08 U2b-4; ADR-0014 §3.2 item 2, §3.3, §3.4, H2⟩ Read-only collector for
//! `heimdall service stop --preview`.
//!
//! Collects everything stopping the runtime would interrupt without starting a runtime,
//! without touching `state_dir` or `runtime_dir`, and without writing a single byte
//! (not even a SQLite `-wal` or `-shm` companion file) inside the installation's directories.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use heimdall_contract::ids::OperationId;
use heimdall_contract::issuer::CaState;
use heimdall_contract::lifecycle::{IssuerKeyAccessNote, StopPreview, StopPreviewItem};
use heimdall_contract::managed::ConnectionKind;
use heimdall_domain::environment::{EnvironmentRealization, ManagedState};
use heimdall_domain::issuance::CredentialState;
use heimdall_domain::managed::OwnedConnectionState;
use heimdall_store::ext_m03::IssuerRecord;
use heimdall_store::layout::stategen::{RealFs, StateDir};
use heimdall_store::{NoFaults, Store, StoreError};

use crate::Paths;
use crate::instance::InstanceInfo;

/// Why collecting the stop preview could not trust the installation's runtime state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StopPreviewError {
    /// The runtime advertisement failed its trust check.
    #[error("the runtime advertisement is not trusted: {0:?}")]
    UntrustedAdvertisement(std::io::ErrorKind),
}

/// Collect a complete, read-only [`StopPreview`] for `paths`.
///
/// Writes nothing under `paths` (never calls `paths.ensure()`, never starts a runtime,
/// never opens SQLite in a mode that creates `-wal` or `-shm` inside `state_dir`).
///
/// # Errors
/// [`StopPreviewError::UntrustedAdvertisement`] when `instance.json` is present but fails
/// the owner/format trust check.
pub fn collect(paths: &Paths) -> Result<StopPreview, StopPreviewError> {
    let running = match InstanceInfo::read_valid(&paths.runtime_dir) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => return Err(StopPreviewError::UntrustedAdvertisement(e.kind())),
    };
    let migration_backups = count_migration_backups(&paths.state_dir);
    let mut preview = StopPreview {
        running,
        open_operations: 0,
        held_bindings: 0,
        in_memory_keys: 0,
        owned_connections: Vec::new(),
        environment_endpoints: Vec::new(),
        remote: Vec::new(),
        migration_backups,
        issuer_key_access: None,
    };
    if !paths.state_dir.is_dir() {
        return Ok(preview);
    }
    let Ok(db) = heimdall_store::layout::db_path(&paths.state_dir) else {
        return Ok(preview);
    };
    if std::fs::symlink_metadata(&db).is_err() {
        return Ok(preview);
    }
    read_family_no_write(&db, |opened| {
        let Ok(store) = opened else {
            return;
        };
        let _ = store.transaction(|tx| populate_from_txn(tx, running, &mut preview));
    });
    Ok(preview)
}

/// Populate `preview` inside one read-only store transaction.
fn populate_from_txn(
    tx: &mut heimdall_store::Txn<'_>,
    running: bool,
    preview: &mut StopPreview,
) -> heimdall_store::Result<()> {
    let issuers = tx.issuers()?;
    preview.issuer_key_access = issuer_key_access_note(cfg!(target_os = "macos"), false, &issuers);
    if !running {
        return Ok(());
    }

    // 1. Open and unresolved operations (deduplicated by ID).
    let mut open_ops: BTreeSet<OperationId> = BTreeSet::new();
    for op in tx.open_operations()? {
        open_ops.insert(op.id);
    }
    for op in tx.unresolved_operations()? {
        open_ops.insert(op.id);
    }
    preview.open_operations = open_ops.len() as u64;

    // 2. Bindings with a live holder process (verified by PID + OS start time).
    let active_bindings: BTreeSet<_> = tx.active_bindings()?.into_iter().map(|b| b.id).collect();
    let mut held_bindings = 0u64;
    for (binding_id, holder) in tx.binding_holders()? {
        if active_bindings.contains(&binding_id)
            && crate::platform::process_start_time(holder.pid)
                .is_some_and(|started| started == holder.started_at)
        {
            held_bindings = held_bindings.saturating_add(1);
        }
    }
    preview.held_bindings = held_bindings;

    // 3. Working keys held only in memory (installed/pending credential instances on live grants).
    let mut live_key_handles: BTreeSet<String> = BTreeSet::new();
    for grant in tx.live_grants()? {
        for inst in tx.credential_instances_for_grant(&grant.id)? {
            if matches!(
                inst.state,
                CredentialState::Installed | CredentialState::Pending
            ) {
                live_key_handles.insert(inst.key_handle_ref);
            }
        }
    }
    preview.in_memory_keys = live_key_handles.len() as u64;

    // 4. Owned multiplexing masters (closed on stop) and dedicated connections (left to client).
    for conn in tx.owned_connections()? {
        if !matches!(
            conn.state,
            OwnedConnectionState::Up | OwnedConnectionState::Closing
        ) {
            continue;
        }
        let (kind, effect) = match conn.kind {
            ConnectionKind::Master => ("master", "closed"),
            ConnectionKind::Dedicated => ("connection", "left_to_client"),
            _ => ("connection", "left_to_client"),
        };
        preview.owned_connections.push(StopPreviewItem {
            kind: kind.to_owned(),
            id: conn.id.as_str().to_owned(),
            effect: effect.to_owned(),
        });
    }
    preview
        .owned_connections
        .sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));

    // 5. Active WSL bridges and container endpoints (unavailable until restart).
    for env in tx.managed_environments()? {
        if env.state != ManagedState::Active {
            continue;
        }
        let kind = match env.realization {
            EnvironmentRealization::Wsl { .. } => "wsl_bridge",
            EnvironmentRealization::Container { .. } => "container_endpoint",
            _ => continue,
        };
        preview.environment_endpoints.push(StopPreviewItem {
            kind: kind.to_owned(),
            id: env.environment.as_str().to_owned(),
            effect: "unavailable_until_restart".to_owned(),
        });
    }
    preview
        .environment_endpoints
        .sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));

    // 6. Remote transport (served Iroh endpoint) and runner state.
    if let Ok(state) = heimdall_app::transport::endpoint_state(tx)
        && state.serve
        && let Some(key) = state.key
    {
        preview.remote.push(StopPreviewItem {
            kind: "iroh_endpoint".to_owned(),
            id: key.endpoint.as_str().to_owned(),
            effect: "closed".to_owned(),
        });
    }
    if crate::paired::is_runner(tx).unwrap_or(false) {
        let id = tx
            .self_environment()?
            .map_or_else(|| "runner".to_owned(), |e| e.as_str().to_owned());
        preview.remote.push(StopPreviewItem {
            kind: "runner".to_owned(),
            id,
            effect: "unavailable_until_restart".to_owned(),
        });
    }
    preview
        .remote
        .sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));

    Ok(())
}

/// The macOS CA-key access note: shown on macOS when at least one non-retired, non-deleted
/// issuer CA is registered.
#[must_use]
pub(crate) fn issuer_key_access_note(
    is_macos: bool,
    developer_id_signed: bool,
    issuers: &[IssuerRecord],
) -> Option<IssuerKeyAccessNote> {
    if !is_macos {
        return None;
    }
    let active: Vec<&IssuerRecord> = issuers
        .iter()
        .filter(|i| !matches!(i.state, CaState::Deleted | CaState::Retired))
        .collect();
    if active.is_empty() {
        return None;
    }
    Some(IssuerKeyAccessNote {
        may_lose_access: !developer_id_signed,
        offline_backup_recorded: active.iter().all(|ca| !ca.backup_sha256.is_empty()),
    })
}

/// Count pre-migration backups belonging to `state_dir`, across `state_dir`, the current
/// generation directory, and earlier generation directories (read-only).
#[must_use]
pub fn count_migration_backups(state_dir: &Path) -> u64 {
    use heimdall_store::layout::stategen::generations::Startup;
    if !state_dir.is_dir() {
        return 0;
    }
    let dir = StateDir::new(RealFs, state_dir);
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    dirs.insert(state_dir.to_path_buf());
    if let Ok(Startup::Serving(current)) = dir.inspect() {
        dirs.insert(current.dir);
    }
    for residue in dir.residue().unwrap_or_default() {
        dirs.insert(state_dir.join("generations").join(&residue.name));
    }
    let mut count = 0u64;
    for d in dirs {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            if heimdall_store::restore::is_own_backup(state_dir, &entry.path()) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// Open the SQLite database family at `db` strictly without writing any file in `db`'s
/// directory (not even `-wal` or `-shm`).
///
/// * Both `-wal` and `-shm` present: `Store::open_read_only_no_write` in place
///   (`mode=ro&readonly_shm=1`).
/// * No `-wal`: `Store::open_read_only_quiescent` in place (`mode=ro&immutable=1`).
/// * `-wal` present without `-shm`: copies `db` and `db-wal` into a private owner-only
///   scratch directory in `std::env::temp_dir()`, opens the copy read-only, and removes
///   the scratch directory before returning.
fn read_family_no_write<T>(db: &Path, read: impl FnOnce(Result<Store, StoreError>) -> T) -> T {
    let with = |sfx: &str| {
        let mut p = db.as_os_str().to_owned();
        p.push(sfx);
        PathBuf::from(p)
    };
    let has_wal = std::fs::symlink_metadata(with("-wal")).is_ok();
    let has_shm = std::fs::symlink_metadata(with("-shm")).is_ok();
    if has_wal && has_shm {
        return read(Store::open_read_only_no_write(db, Arc::new(NoFaults)));
    }
    if !has_wal {
        return read(Store::open_read_only_quiescent(db, Arc::new(NoFaults)));
    }
    let scratch = scratch_dir();
    let copied = scratch.as_ref().map_err(|_| ()).and_then(|dir| {
        let copy = dir.join("state.db");
        std::fs::copy(db, &copy).map_err(|_| ())?;
        std::fs::copy(with("-wal"), dir.join("state.db-wal")).map_err(|_| ())?;
        Ok(copy)
    });
    let out = match copied {
        Ok(copy) => read(Store::open_read_only(&copy, Arc::new(NoFaults))),
        Err(()) => read(Err(StoreError::Corrupt(
            "the state database could not be copied for its read".to_owned(),
        ))),
    };
    if let Ok(dir) = scratch {
        let _ = std::fs::remove_dir_all(dir);
    }
    out
}

fn scratch_dir() -> std::io::Result<PathBuf> {
    use std::hash::BuildHasher as _;
    let tag = std::hash::RandomState::new().hash_one((std::process::id(), Instant::now()));
    let dir =
        std::env::temp_dir().join(format!("hm-stop-preview-{}-{tag:016x}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use heimdall_contract::canonical::RequestHash;
    use heimdall_contract::ids::{
        AccountName, BindingId, CaFingerprint, ConnectionId, ConsentId, CredentialInstanceId,
        DecisionId, DestinationId, EnvironmentId, GrantId, IrohEndpointId, OperationId, ProfileId,
        RequestId, WorkId,
    };
    use heimdall_contract::issuer::StoreKind;
    use heimdall_contract::request::{DeadlineIntent, ProcessHolder};
    use heimdall_contract::route::{BindScope, ExposurePolicy, InfrastructureProfile};
    use heimdall_contract::{GrantState, OperationState, Timestamp};
    use heimdall_domain::binding::{BindingRecord, BindingState};
    use heimdall_domain::environment::{EnvironmentRealization, ManagedEnvironment, ManagedState};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::grant::{AuthorizationSource, GrantSnapshot};
    use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
    use heimdall_domain::issuance::{CredentialInstance, CredentialState};
    use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};
    use heimdall_domain::operation::{
        EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
    };
    use heimdall_domain::policy::AuthorityGeneration;
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::scope::{AccessPair, Scope};
    use heimdall_domain::time::Deadline;

    use super::*;

    fn snapshot_dir(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.is_dir() {
                    out.insert(format!("{rel}/"), Vec::new());
                    walk(base, &path, out);
                } else {
                    out.insert(rel, std::fs::read(&path).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        if dir.is_dir() {
            walk(dir, dir, &mut out);
        }
        out
    }

    fn t0() -> Timestamp {
        "2026-11-27T00:00:00Z".parse().unwrap()
    }

    fn t1() -> Timestamp {
        "2026-11-27T01:00:00Z".parse().unwrap()
    }

    fn caller() -> CallerContext {
        CallerContext::local(PrincipalRef::UnixUser { uid: 501 }, ClientRole::Owner)
    }

    /// Populates a store with every category ADR-0014 §3.3 lists and verifies that
    /// `populate_from_txn` reports all of them accurately when `running = true` and reports
    /// zero active interruptions when `running = false`.
    #[test]
    fn populate_reports_every_interrupted_category_and_nothing_when_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("state.db");
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap();

        let self_env = crate::paired::init_runner(&store).unwrap();
        let container_env = EnvironmentId::from_random_bytes([2; 16]);
        let wsl_env = EnvironmentId::from_random_bytes([3; 16]);
        let removed_env = EnvironmentId::from_random_bytes([4; 16]);
        let grant_id = GrantId::from_random_bytes([10; 16]);
        let binding_live = BindingId::from_random_bytes([11; 16]);
        let binding_dead = BindingId::from_random_bytes([12; 16]);
        let op_running = OperationId::from_random_bytes([20; 16]);
        let op_unknown = OperationId::from_random_bytes([21; 16]);
        let master_id = ConnectionId::from_random_bytes([30; 16]);
        let dedicated_id = ConnectionId::from_random_bytes([31; 16]);
        let closed_id = ConnectionId::from_random_bytes([32; 16]);
        let endpoint = IrohEndpointId::parse(&"ab".repeat(32)).unwrap();

        let my_pid = std::process::id();
        let my_start = crate::platform::process_start_time(my_pid).unwrap();

        store
            .transaction(|tx| {
                // 1. Open and unresolved operations.
                for (idx, (id, state)) in [
                    (op_running.clone(), OperationState::Running),
                    (op_unknown.clone(), OperationState::OutcomeUnknown),
                ]
                .into_iter()
                .enumerate()
                {
                    let key = IdempotencyKey {
                        caller: caller(),
                        kind: OperationKind::Ensure,
                        request_id: RequestId::parse(&format!("req-{idx}")).unwrap(),
                    };
                    let request_hash = RequestHash([idx as u8; 32]);
                    tx.insert_operation(
                        &OperationRecord {
                            id: id.clone(),
                            kind: OperationKind::Ensure,
                            environment: self_env.clone(),
                            key: key.clone(),
                            request_hash,
                            effect_class: EffectClass::Local,
                            state,
                            code: None,
                            effect_status: heimdall_contract::envelope::EffectStatus::Unknown,
                            result: None,
                            created_at: t0(),
                            updated_at: t0(),
                            cancellation: None,
                            recovery: RecoveryMetadata::default(),
                        },
                        &IdempotencyRecord {
                            key,
                            request_hash,
                            operation_id: id,
                            created_at: t0(),
                            expires_at: None,
                        },
                    )?;
                }

                // 2. Grant + live binding + dead-holder binding + in-memory working key.
                let pair = AccessPair {
                    destination: DestinationId::parse("lab").unwrap(),
                    account: AccountName::parse("deploy").unwrap(),
                };
                let scope = Scope {
                    pairs: BTreeSet::from([pair]),
                    capabilities: BTreeSet::new(),
                };
                let profile = ProfileId::parse("dev").unwrap();
                tx.insert_grant(&GrantSnapshot {
                    id: grant_id.clone(),
                    environment: self_env.clone(),
                    scope: scope.clone(),
                    starts_at: t0(),
                    deadline: Deadline {
                        intent: DeadlineIntent::Duration("1h".into()),
                        resolved_at: t0(),
                        effective: t1(),
                    },
                    parent: None,
                    source: AuthorizationSource::OwnerDecision {
                        operation_id: op_running.clone(),
                    },
                    generation: AuthorityGeneration(1),
                    state: GrantState::Active,
                    enforcement: EnforcementEvidence::unknown(),
                })?;

                for (bid, work, holder) in [
                    (
                        binding_live.clone(),
                        "w-live",
                        ProcessHolder {
                            pid: my_pid,
                            started_at: my_start.clone(),
                        },
                    ),
                    (
                        binding_dead.clone(),
                        "w-dead",
                        ProcessHolder {
                            pid: my_pid,
                            started_at: "not-my-start-time".to_owned(),
                        },
                    ),
                ] {
                    tx.insert_binding(&BindingRecord {
                        id: bid.clone(),
                        environment: self_env.clone(),
                        grant: grant_id.clone(),
                        work_id: WorkId::parse(work).unwrap(),
                        owner: caller(),
                        profile: profile.clone(),
                        profile_revision: 1,
                        scope: scope.clone(),
                        mechanism: "managed_certificate".into(),
                        parent: None,
                        created_at: t0(),
                        released_at: None,
                        state: BindingState::Active,
                    })?;
                    tx.set_binding_holder(&bid, &holder)?;
                }

                tx.insert_credential_instance(&CredentialInstance {
                    id: CredentialInstanceId::from_random_bytes([40; 16]),
                    grant: grant_id.clone(),
                    key_handle_ref: "0123456789abcdef0123456789abcdef".to_owned(),
                    certificates: Vec::new(),
                    state: CredentialState::Installed,
                })?;

                // 3. Owned connections: 1 master (up), 1 dedicated (up), 1 closed (ignored).
                for (cid, kind) in [
                    (master_id.clone(), ConnectionKind::Master),
                    (dedicated_id.clone(), ConnectionKind::Dedicated),
                    (closed_id.clone(), ConnectionKind::Master),
                ] {
                    tx.insert_owned_connection(&OwnedConnection {
                        id: cid,
                        kind,
                        binding: binding_live.clone(),
                        grant: grant_id.clone(),
                        pid: my_pid,
                        start_token: my_start.clone(),
                        image: "/usr/bin/ssh".into(),
                        control_path: None,
                        generation: 1,
                        state: OwnedConnectionState::Up,
                        started_at: t0(),
                    })?;
                }
                tx.close_owned_connection(&closed_id, 1, OwnedConnectionState::Closed)?;

                // 4. Environment endpoints: 1 active container, 1 active WSL bridge, 1 removed.
                tx.insert_managed_environment(&ManagedEnvironment {
                    environment: container_env.clone(),
                    controller: self_env.clone(),
                    realization: EnvironmentRealization::Container {
                        label: "devbox".into(),
                        dir_tag: "0123456789abcdef".into(),
                    },
                    state: ManagedState::Active,
                    created_at: t0(),
                    updated_at: t0(),
                })?;
                tx.insert_managed_environment(&ManagedEnvironment {
                    environment: wsl_env.clone(),
                    controller: self_env.clone(),
                    realization: EnvironmentRealization::Wsl {
                        guid: heimdall_contract::environment::DistributionGuid::parse(
                            "11111111-2222-3333-4444-555555555555",
                        )
                        .unwrap(),
                        name: "Ubuntu".into(),
                        account: "dev".into(),
                    },
                    state: ManagedState::Active,
                    created_at: t0(),
                    updated_at: t0(),
                })?;
                tx.insert_managed_environment(&ManagedEnvironment {
                    environment: removed_env.clone(),
                    controller: self_env.clone(),
                    realization: EnvironmentRealization::Container {
                        label: "old".into(),
                        dir_tag: "fedcba9876543210".into(),
                    },
                    state: ManagedState::Removed,
                    created_at: t0(),
                    updated_at: t0(),
                })?;

                // 5. Remote: served Iroh endpoint (runner marker already set via init_runner).
                tx.insert_transport_key(&heimdall_app::transport::TransportKeyRecord {
                    endpoint: endpoint.clone(),
                    store_kind: "fixture_store".into(),
                    store_ref: "ref-1".into(),
                    state: heimdall_app::transport::TransportKeyState::Active,
                    created_at: t0(),
                    destroyed_at: None,
                })?;
                let policy = ExposurePolicy {
                    bind: BindScope::Loopback,
                    infrastructure: InfrastructureProfile::None,
                    direct_fallback: false,
                    port: None,
                    sshd_port: 22,
                };
                tx.insert_route_consent(&heimdall_app::transport::RouteConsentRecord {
                    consent: ConsentId::from_random_bytes([50; 16]),
                    route: None,
                    decision: DecisionId::from_random_bytes([51; 16]),
                    delta: heimdall_app::transport::exposure_delta(
                        Some(&endpoint),
                        &ExposurePolicy::default(),
                        false,
                        &policy,
                        true,
                        None,
                    ),
                    recorded_at: t0(),
                })?;
                Ok(())
            })
            .unwrap();

        let mut active = StopPreview {
            running: true,
            open_operations: 0,
            held_bindings: 0,
            in_memory_keys: 0,
            owned_connections: Vec::new(),
            environment_endpoints: Vec::new(),
            remote: Vec::new(),
            migration_backups: 0,
            issuer_key_access: None,
        };
        store
            .transaction(|tx| populate_from_txn(tx, true, &mut active))
            .unwrap();
        assert_eq!(active.open_operations, 2);
        assert_eq!(active.held_bindings, 1, "only live holder counts");
        assert_eq!(active.in_memory_keys, 1);
        assert_eq!(
            active.owned_connections,
            vec![
                StopPreviewItem {
                    kind: "connection".into(),
                    id: dedicated_id.as_str().into(),
                    effect: "left_to_client".into(),
                },
                StopPreviewItem {
                    kind: "master".into(),
                    id: master_id.as_str().into(),
                    effect: "closed".into(),
                },
            ]
        );
        assert_eq!(
            active.environment_endpoints,
            vec![
                StopPreviewItem {
                    kind: "container_endpoint".into(),
                    id: container_env.as_str().into(),
                    effect: "unavailable_until_restart".into(),
                },
                StopPreviewItem {
                    kind: "wsl_bridge".into(),
                    id: wsl_env.as_str().into(),
                    effect: "unavailable_until_restart".into(),
                },
            ]
        );
        assert_eq!(
            active.remote,
            vec![
                StopPreviewItem {
                    kind: "iroh_endpoint".into(),
                    id: endpoint.as_str().into(),
                    effect: "closed".into(),
                },
                StopPreviewItem {
                    kind: "runner".into(),
                    id: self_env.as_str().into(),
                    effect: "unavailable_until_restart".into(),
                },
            ]
        );

        let mut stopped = StopPreview {
            running: false,
            open_operations: 0,
            held_bindings: 0,
            in_memory_keys: 0,
            owned_connections: Vec::new(),
            environment_endpoints: Vec::new(),
            remote: Vec::new(),
            migration_backups: 0,
            issuer_key_access: None,
        };
        store
            .transaction(|tx| populate_from_txn(tx, false, &mut stopped))
            .unwrap();
        assert_eq!(stopped.open_operations, 0);
        assert_eq!(stopped.held_bindings, 0);
        assert_eq!(stopped.in_memory_keys, 0);
        assert!(stopped.owned_connections.is_empty());
        assert!(stopped.environment_endpoints.is_empty());
        assert!(stopped.remote.is_empty());
    }

    /// `collect` writes zero bytes in `state_dir` (even when no `-wal`/`-shm` exists, and
    /// when a migration backup sits beside the store).
    #[test]
    fn collect_leaves_state_dir_byte_identical_and_counts_migration_backups() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(&dir.path().join("home"));
        paths.ensure().unwrap();
        let db = heimdall_store::layout::db_path(&paths.state_dir).unwrap();
        drop(Store::open(&db, Arc::new(NoFaults)).unwrap());
        std::fs::write(paths.state_dir.join("state.db.v12.backup"), b"backup").unwrap();

        let before = snapshot_dir(&paths.state_dir);
        let preview = collect(&paths).unwrap();
        let after = snapshot_dir(&paths.state_dir);

        assert_eq!(
            before, after,
            "stop preview must leave state_dir byte-identical"
        );
        assert!(!preview.running);
        assert_eq!(preview.migration_backups, 1);
    }

    #[test]
    fn issuer_key_access_note_only_on_macos_with_active_ca() {
        let ca = |state: CaState, sha: &str| IssuerRecord {
            ca_fingerprint: CaFingerprint::parse(
                "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            public_key: "ssh-ed25519 AAAA test".into(),
            state,
            store_kind: StoreKind::MacosLoginKeychain,
            backup_sha256: sha.into(),
            backup_created_at: t0(),
            restored_without_log: false,
            created_at: t0(),
            retired_at: None,
        };
        assert_eq!(
            issuer_key_access_note(false, false, &[ca(CaState::Active, "ab")]),
            None
        );
        assert_eq!(issuer_key_access_note(true, false, &[]), None);
        assert_eq!(
            issuer_key_access_note(true, false, &[ca(CaState::Retired, "ab")]),
            None
        );
        assert_eq!(
            issuer_key_access_note(true, false, &[ca(CaState::Active, "ab")]),
            Some(IssuerKeyAccessNote {
                may_lose_access: true,
                offline_backup_recorded: true,
            })
        );
        assert_eq!(
            issuer_key_access_note(true, false, &[ca(CaState::Active, "")]),
            Some(IssuerKeyAccessNote {
                may_lose_access: true,
                offline_backup_recorded: false,
            })
        );
        assert_eq!(
            issuer_key_access_note(true, true, &[ca(CaState::Active, "ab")]),
            Some(IssuerKeyAccessNote {
                may_lose_access: false,
                offline_backup_recorded: true,
            })
        );
    }
}
