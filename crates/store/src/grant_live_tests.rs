#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use heimdall_contract::GrantState::{self, *};
use heimdall_contract::request::DeadlineIntent;
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::grant::AuthorizationSource;
use heimdall_domain::policy::PolicyRevision;
use heimdall_domain::scope::Scope;
use heimdall_domain::time::Deadline;
use rusqlite::StatementStatus::{Run, VmStep};

use super::*;
use layout::stategen::{GenerationName, Operation, Plan, RealFs, StateDir};

#[derive(Debug, PartialEq, Eq)]
struct DocReads {
    rows: usize,
    vm_steps: i32,
}

fn now() -> Timestamp {
    "2026-11-25T00:00:00Z".parse().unwrap()
}

fn environment() -> EnvironmentId {
    EnvironmentId::from_random_bytes([1; 16])
}

fn snapshot(n: u128, state: GrantState, deadline: Timestamp) -> GrantSnapshot {
    let starts_at = "2026-11-24T00:00:00Z".parse().unwrap();
    GrantSnapshot {
        id: GrantId::from_random_bytes(n.to_be_bytes()),
        environment: environment(),
        scope: Scope::empty(),
        starts_at,
        deadline: Deadline {
            intent: DeadlineIntent::Absolute(deadline.to_string()),
            resolved_at: starts_at,
            effective: deadline,
        },
        parent: None,
        source: AuthorizationSource::StandingPolicy {
            revision: PolicyRevision(1),
        },
        generation: AuthorityGeneration(0),
        state,
        enforcement: EnforcementEvidence::unknown(),
    }
}

fn seed_v14(db: &Path) -> Result<Vec<GrantSnapshot>> {
    let store = Store::open_at_schema_version(db, Arc::new(NoFaults), 14)?;
    let states = [
        Requested,
        AwaitingApproval,
        Preparing,
        Active,
        Degraded,
        Revoking,
        Revoked,
        Expired,
        Released,
        Denied,
        Cancelled,
        Failed,
    ];
    let grants: Vec<_> = states
        .into_iter()
        .enumerate()
        .map(|(i, state)| snapshot(i as u128, state, now()))
        .collect();
    store.transaction(|tx| {
        tx.init_self_environment(&environment())?;
        for grant in &grants {
            tx.insert_grant(grant)?;
        }
        Ok(())
    })?;
    Ok(grants)
}

fn assert_backfill(root: &Path, opened: &layout::Opened, grants: &[GrantSnapshot]) {
    assert_eq!(opened.store.schema_version().unwrap(), 15);
    let state = StateDir::new(RealFs, root);
    let notes = state.migrations(&opened.current).unwrap();
    assert_eq!(
        notes.last().map(|note| (note.from, note.to)),
        Some((14, 15))
    );
    opened
        .store
        .transaction(|tx| {
            let mut live: Vec<_> = grants
                .iter()
                .filter(|grant| !grant.state.is_terminal())
                .cloned()
                .collect();
            live.sort_by(|a, b| a.id.cmp(&b.id));
            assert_eq!(tx.live_grants()?, live);
            assert_eq!(tx.grants_due(now())?, live);
            for grant in grants {
                let generated: bool = tx.tx.query_row(
                    "SELECT is_live FROM grants WHERE id = ?1",
                    [grant.id.as_str()],
                    |row| row.get(0),
                )?;
                assert_eq!(generated, !grant.state.is_terminal(), "{:?}", grant.state);
                assert_eq!(tx.grant(&grant.id)?.as_ref(), Some(grant));
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn schema_15_backfills_grants_after_adopting_a_flat_v14_store() {
    let root = tempfile::tempdir().unwrap();
    let flat = layout::db_path(root.path()).unwrap();
    let grants = seed_v14(&flat).unwrap();
    let opened =
        layout::open_locked(root.path(), &RealFs, Arc::new(NoFaults), &|| None, now()).unwrap();
    assert_eq!(opened.began, layout::Began::Adopted { schema_version: 14 });
    assert_ne!(opened.db, flat);
    assert_backfill(root.path(), &opened, &grants);
}

#[test]
fn schema_15_backfills_grants_in_an_existing_v14_generation() {
    let root = tempfile::tempdir().unwrap();
    let state = StateDir::new(RealFs, root.path());
    let mut grants = Vec::new();
    let current = state
        .publish(
            Plan {
                name: GenerationName::parse("g-v14").unwrap(),
                operation: Operation::Install,
                created_at: now(),
                backup_sha256: None,
                environment_id: environment().as_str().to_owned(),
                restore_epoch: 0,
            },
            |dir| -> Result<Vec<String>> {
                grants = seed_v14(&dir.join(layout::DB_FILE))?;
                Ok(vec![layout::DB_FILE.to_owned()])
            },
        )
        .unwrap();
    let opened =
        layout::open_locked(root.path(), &RealFs, Arc::new(NoFaults), &|| None, now()).unwrap();
    assert_eq!(opened.began, layout::Began::Served);
    assert_eq!(opened.current.name, current.name);
    assert_backfill(root.path(), &opened, &grants);
}

#[test]
fn ending_a_grant_updates_both_live_reads_in_the_same_transaction() {
    let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
    let mut grant = snapshot(1, Active, now());
    store
        .transaction(|tx| {
            tx.insert_grant(&grant)?;
            for state in [Active, Revoking, Revoked] {
                if state != grant.state {
                    grant.state = state;
                    tx.update_grant_state(&grant)?;
                }
                let expected = if state.is_terminal() {
                    &[][..]
                } else {
                    std::slice::from_ref(&grant)
                };
                assert_eq!(tx.live_grants()?, expected);
                assert_eq!(tx.grants_due(now())?, expected);
                assert_eq!(tx.grant(&grant.id)?.as_ref(), Some(&grant));
            }
            Ok(())
        })
        .unwrap();
}

fn seed_live(store: &Store) -> Vec<GrantSnapshot> {
    let grants = vec![
        snapshot(3, Revoking, "2026-11-24T23:00:00Z".parse().unwrap()),
        snapshot(2, Preparing, now()),
        snapshot(1, Active, "2026-11-26T00:00:00Z".parse().unwrap()),
    ];
    store
        .transaction(|tx| {
            for grant in grants.iter().rev() {
                tx.insert_grant(grant)?;
            }
            Ok(())
        })
        .unwrap();
    grants
}

fn seed_history(store: &Store, from: u128, to: u128) {
    store
        .transaction(|tx| {
            for i in from..to {
                tx.insert_grant(&snapshot(10 + i, Expired, now()))?;
            }
            Ok(())
        })
        .unwrap();
}

fn counted_read(
    store: &Store,
    sql: &str,
    params: impl rusqlite::Params,
    read: impl FnOnce(&mut Txn<'_>) -> Result<Vec<GrantSnapshot>>,
    expected: &[GrantSnapshot],
) -> DocReads {
    store
        .transaction(|tx| {
            {
                let stmt = tx.tx.prepare_cached(sql)?;
                stmt.reset_status(Run);
                stmt.reset_status(VmStep);
            }
            assert_eq!(read(tx)?, expected);
            let mut stmt = tx.tx.prepare_cached(sql)?;
            // Check the accessor ran this statement and capture its actual VM work.
            // Counting only its returned rows would miss a SQL scan of history.
            assert_eq!(stmt.get_status(Run), 1);
            let vm_steps = stmt.get_status(VmStep);
            assert!(vm_steps > 0);
            // Count raw rows crossing into Rust with the same SQL and parameters,
            // independently of any decoding or filtering the accessor might do.
            let mut query = stmt.query(params)?;
            let mut rows = 0;
            while query.next()?.is_some() {
                rows += 1;
            }
            assert_eq!(rows, expected.len());
            Ok(DocReads { rows, vm_steps })
        })
        .unwrap()
}

fn counted_live(store: &Store, expected: &[GrantSnapshot]) -> DocReads {
    counted_read(store, LIVE_GRANTS_SQL, [], |tx| tx.live_grants(), expected)
}

fn counted_due(store: &Store, deadline: Timestamp, expected: &[GrantSnapshot]) -> DocReads {
    counted_read(
        store,
        GRANTS_DUE_SQL,
        [codec::ts(deadline)],
        |tx| tx.grants_due(deadline),
        expected,
    )
}

#[test]
fn live_and_due_grant_read_work_ignores_terminal_history_and_future_deadlines() {
    let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
    let live = seed_live(&store);
    let live_baseline = counted_live(&store, &live);
    let due_baseline = counted_due(&store, now(), &live[..2]);
    seed_history(&store, 0, 5_000);
    assert_eq!(counted_live(&store, &live), live_baseline);
    assert_eq!(counted_due(&store, now(), &live[..2]), due_baseline);
    store
        .transaction(|tx| {
            for i in 10_000..12_000 {
                tx.insert_grant(&snapshot(i, Requested, live[2].deadline.effective))?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(counted_due(&store, now(), &live[..2]), due_baseline);
}

#[test]
#[ignore = "run with tools/benchmarks/m08/run-soak.sh --grant-history-growth"]
#[allow(clippy::print_stdout)] // One JSON sample per operation and history size.
fn grant_history_growth() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("grants.sqlite"), Arc::new(NoFaults)).unwrap();
    let live = seed_live(&store);
    let deadline = now();
    let due = |tx: &mut Txn<'_>| tx.grants_due(deadline);
    let baseline = [
        counted_live(&store, &live),
        counted_due(&store, deadline, &live[..2]),
    ];
    let mut history = 0;
    for terminal_rows in [0, 1_000, 10_000, 100_000] {
        seed_history(&store, history, terminal_rows);
        history = terminal_rows;
        let reads = [
            counted_live(&store, &live),
            counted_due(&store, deadline, &live[..2]),
        ];
        assert_eq!(reads, baseline);
        let mut live_ns = Vec::new();
        let mut due_ns = Vec::new();
        for _ in 0..1_000 {
            let start = Instant::now();
            let result = store.transaction(|tx| tx.live_grants()).unwrap();
            live_ns.push(start.elapsed().as_nanos());
            assert_eq!(result.len(), live.len());

            let start = Instant::now();
            let result = store.transaction(due).unwrap();
            due_ns.push(start.elapsed().as_nanos());
            assert_eq!(result.len(), 2);
        }
        for ((operation, mut times), reads) in [("live_grants", live_ns), ("grants_due", due_ns)]
            .into_iter()
            .zip(reads)
        {
            times.sort_unstable();
            println!(
                "{}",
                serde_json::json!({
                    "workload": "grant_history_growth",
                    "operation": operation,
                    "terminal_rows": terminal_rows,
                    "samples": times.len(),
                    "document_rows_per_operation": reads.rows,
                    "sqlite_vm_steps_per_operation": reads.vm_steps,
                    "p50_ns": times[(times.len() - 1) / 2],
                    "p95_ns": times[(times.len() * 95).div_ceil(100) - 1],
                })
            );
        }
    }
}
