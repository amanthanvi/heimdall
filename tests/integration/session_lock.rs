//! M03 U9: the platform session-lock sources (ADR-0008 D9 item 3; m03-plan U9, §4.4).
//! Hosted by heimdall-runtime (target `integration_session_lock`).
//!
//! **Nothing here locks a screen.** The runnable tests start the real source, read the
//! current state, exercise the delivery mechanism with test-only notification names
//! (macOS: `dev.heimdall.test.*`, never a system name), and join the thread. The native
//! signal rows (`macos_lock_signal_observed`, `windows_lock_signal_observed`,
//! `linux_logind_lock_signal_observed`) need a real lock event: they only **wait for**
//! and record one, run only under the ADR-0004 §2 lock rule through U13's §4.4 harness
//! (`tests/native/m03/lock-macos.sh`, `lock-windows.ps1`), and are `#[ignore]`d
//! otherwise. The harness passes `HM_LOCK_WAIT_SECS` (default 1800), optionally
//! `HM_LOCK_TRIGGERED_AT_MS` (Unix ms when it triggered the lock, for the latency) and
//! `HM_LOCK_RECORD` (a scratch path for the JSON observation).

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_app::lock::{self, LockSignal};
use heimdall_app::operations::Limits;
use heimdall_app::ports::{
    AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity, LockState,
    PrepareOutcome, SessionLockSource,
};
use heimdall_app::{Attendance, Caller, Operations, OperationsConfig};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId,
};
use heimdall_contract::managed::LockBehavior;
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy, InteractionMode,
    NewAuthenticationExpiry, PolicyAction, RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::{SyncStatus, TimePolicy};
use heimdall_runtime::session_lock::PlatformSessionLockSource;
use heimdall_store::Store;
use heimdall_testkit::{FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock};

// =================================================================================
// Harness
// =================================================================================

const HOUR: Duration = Duration::from_secs(3600);

fn t0() -> Timestamp {
    "2026-11-03T09:00:00Z".parse().unwrap()
}

fn env_id() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn attended() -> Caller {
    Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

fn h1() -> AccessPair {
    AccessPair {
        destination: DestinationId::parse("h1").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
    }
}

fn ssh_only() -> BTreeSet<Capability> {
    [Capability::SshAuthentication].into_iter().collect()
}

fn pol() -> PolicyId {
    PolicyId::parse("pol").unwrap()
}

fn enforcement() -> EnforcementEvidence {
    EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::ClientRouting,
            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
            revocation: RevocationStatus::LocalApplied,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
        },
        evidence: Vec::new(),
    }
}

/// Operations over an in-memory store with one `continue` policy, and `source` wired.
async fn operations(source: Arc<dyn SessionLockSource>) -> (Operations, Arc<Store>) {
    let store = Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap());
    store
        .transaction(|tx| {
            tx.init_self_environment(&env_id())?;
            tx.upsert_environment(&EnvironmentRecord {
                id: env_id(),
                device: DeviceId::from_random_bytes([8; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            let scope = Scope {
                pairs: [h1()].into_iter().collect(),
                capabilities: ssh_only(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse("dev").unwrap(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: pol(),
                    revision: PolicyRevision(1),
                    profile: ProfileId::parse("dev").unwrap(),
                    workspace: None,
                    scope,
                    environments: [env_id()].into_iter().collect(),
                    max_window: 2 * HOUR,
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: Default::default(),
                },
                false,
            )
        })
        .unwrap();
    let outcome = PrepareOutcome {
        usable_until: t0(),
        offline_until: t0(),
        refresh_dependency: RefreshDependency::None,
        enforcement: enforcement(),
        credential_ref: "fixture-ref".into(),
        availability: Default::default(),
        provider: None,
        integration: Default::default(),
    };
    let fake = FakeCredentialAdapter::new(
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            capabilities: ssh_only(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        },
        vec![FakeStep::Prepare(outcome)],
    );
    let ops = Operations::start(OperationsConfig {
        store: store.clone(),
        clock: VirtualClock::at(t0()),
        time_sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
        time_policy: TimePolicy::default(),
        environment: env_id(),
        adapters: vec![fake as Arc<dyn CredentialAdapter>],
        stage_hook: Arc::new(heimdall_app::ensure::NoStageHook),
        limits: Limits::default(),
        default_window: 12 * HOUR,
        projection: None,
    })
    .await
    .unwrap();
    ops.set_session_lock_source(source);
    (ops, store)
}

fn stored_lock(store: &Store) -> LockBehavior {
    store
        .transaction(|tx| tx.policy(&pol()))
        .unwrap()
        .unwrap()
        .lock_behavior
}

/// Shut a source down and return how long the join took.
fn timed_shutdown(src: &PlatformSessionLockSource) -> Duration {
    let started = Instant::now();
    src.shutdown();
    started.elapsed()
}

// =================================================================================
// Runnable on every platform
// =================================================================================

/// The platform source's thread is spawned once, joined at shutdown (bounded), and a
/// second shutdown or the drop is harmless. The port reads never block.
#[test]
fn source_thread_spawned_once_and_joined_at_shutdown() {
    for _ in 0..3 {
        let src = PlatformSessionLockSource::start();
        let t = Instant::now();
        let _ = (src.state(), src.lock_epoch());
        src.acknowledge(src.lock_epoch().epoch);
        assert!(
            t.elapsed() < Duration::from_millis(50),
            "the port never blocks"
        );
        let took = timed_shutdown(&src);
        assert!(took < Duration::from_secs(3), "joined in {took:?}");
        assert!(!src.thread_running());
        src.shutdown();
    }
    let src = PlatformSessionLockSource::start();
    drop(src);
}

/// `revoke_on_lock` is refused where the source is `unavailable`
/// (`CAPABILITY_UNAVAILABLE`, `lock_signal_unavailable`, nothing written), through the
/// runtime's own sources: the no-signal source everywhere, and this host's real source
/// where it reads `unavailable` (the devbox over SSH and the WSL distribution natively;
/// m03-plan U9). Where the real source has a signal the change is accepted, labelled
/// `signal_unverified` on Linux; the observation is recorded.
#[tokio::test]
async fn revoke_on_lock_refused_where_signal_unavailable() {
    let set = PolicyAction::SetLockBehavior {
        policy_id: pol(),
        behavior: LockBehavior::RevokeOnLock,
    };
    // The no-signal source.
    let none = PlatformSessionLockSource::unavailable();
    assert_eq!(none.signal(), LockSignal::None);
    let (ops, store) = operations(none).await;
    let e = ops.policy(&attended(), set.clone()).await.unwrap_err();
    assert_eq!(e.code, heimdall_contract::Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
    assert_eq!(
        stored_lock(&store),
        LockBehavior::Continue,
        "nothing written"
    );
    // This host's real source.
    let real = tokio::task::spawn_blocking(PlatformSessionLockSource::start)
        .await
        .unwrap();
    let state = real.state();
    let signal = real.signal();
    let (ops, store) = operations(real.clone()).await;
    let r = ops.policy(&attended(), set).await;
    #[allow(clippy::print_stderr)] // an observation for the evidence record
    {
        eprintln!(
            "m03 observation: os={} session_lock_state={state:?} signal={signal:?} revoke_on_lock={}",
            std::env::consts::OS,
            match &r {
                Ok(_) => "accepted".to_owned(),
                Err(e) => format!("refused {}", e.reason.as_deref().unwrap_or("-")),
            }
        );
    }
    if state == LockState::Unavailable {
        let e = r.unwrap_err();
        assert_eq!(e.code, heimdall_contract::Code::CapabilityUnavailable);
        assert_eq!(e.reason.as_deref(), Some("lock_signal_unavailable"));
        assert_eq!(stored_lock(&store), LockBehavior::Continue);
        assert_eq!(signal, LockSignal::None);
    } else {
        let mut done = r.unwrap();
        assert_eq!(stored_lock(&store), LockBehavior::RevokeOnLock);
        lock::label_completed(&mut done, LockBehavior::RevokeOnLock, signal);
        let labelled = done.warnings.iter().any(|w| w.code == "signal_unverified");
        assert_eq!(labelled, cfg!(target_os = "linux"));
    }
    real.shutdown();
}

// =================================================================================
// Runnable on macOS (no lock)
// =================================================================================

/// The real macOS source starts its run-loop thread, reads the current state from
/// `CGSessionCopyCurrentDictionary` without locking anything (an attended GUI session
/// reads `unlocked`; whatever it reads is recorded), latches nothing for an initial
/// `unlocked`, and joins its thread cleanly.
#[cfg(target_os = "macos")]
#[test]
fn macos_source_reads_current_state_and_joins() {
    let started = Instant::now();
    let src = PlatformSessionLockSource::start();
    let first_reading = started.elapsed();
    let snap = src.snapshot();
    let running = src.thread_running();
    let took = timed_shutdown(&src);
    #[allow(clippy::print_stderr)] // an observation for the evidence record
    {
        eprintln!(
            "m03 observation: macos session_lock_state={:?} signal={:?} epoch={} observed={} \
             thread_running_before_shutdown={running} first_reading_ms={} join_ms={}",
            snap.state,
            snap.signal,
            snap.epoch.epoch,
            snap.epoch.observed,
            first_reading.as_millis(),
            took.as_millis()
        );
    }
    assert_ne!(
        snap.state,
        LockState::Unknown,
        "the first reading arrived within the bound"
    );
    if snap.state == LockState::Unlocked {
        assert!(running, "a session with a lock signal keeps its thread");
        assert_eq!(snap.signal, LockSignal::MacosScreenLock);
        assert!(!snap.epoch.observed, "an initial unlocked latches nothing");
    }
    assert!(took < Duration::from_secs(2), "joined in {took:?}");
    assert!(!src.thread_running());
    assert_eq!(src.state(), snap.state, "the state stays as last read");
}

/// The macOS polling mechanism, without locking anything: the source's own thread
/// reads the session dictionary on every interval (counted as events, all on that
/// thread), an `unlocked` session stays `unlocked` with nothing latched, and the thread
/// joins within one stop slice. Skipped with a recorded observation when this process
/// has no GUI session (`unavailable`). (The distributed notifications are not used:
/// `session_lock/macos.rs`, questions file U9-Q4.)
#[cfg(target_os = "macos")]
#[test]
fn macos_polling_thread_reads_on_its_own_thread() {
    use heimdall_runtime::session_lock::SourceOptions;
    let src = PlatformSessionLockSource::start_with(&SourceOptions {
        poll_interval: Duration::from_millis(50),
        ..SourceOptions::default()
    });
    let initial = src.snapshot();
    if initial.state == LockState::Unavailable {
        #[allow(clippy::print_stderr)] // an observation for the evidence record
        {
            eprintln!("m03 observation: macos no GUI session (unavailable); polling not exercised");
        }
        assert!(!src.thread_running(), "no session: the thread ends at once");
        return;
    }
    let watched = Instant::now();
    std::thread::sleep(Duration::from_millis(1000));
    let snap = src.snapshot();
    let elapsed = watched.elapsed();
    let took = timed_shutdown(&src);
    #[allow(clippy::print_stderr)] // an observation for the evidence record
    {
        eprintln!(
            "m03 observation: macos polls={} in {}ms off_thread={} state={:?} transitions={} join_ms={}",
            snap.events,
            elapsed.as_millis(),
            snap.events_off_thread,
            snap.state,
            snap.transitions,
            took.as_millis()
        );
    }
    assert!(snap.events >= 5, "the thread polls: {}", snap.events);
    assert_eq!(
        snap.events_off_thread, 0,
        "every read on the source's own thread"
    );
    if initial.state == LockState::Unlocked && snap.transitions == 0 {
        assert_eq!(snap.state, LockState::Unlocked);
        assert!(!snap.epoch.observed, "nothing latched while unlocked");
    }
    assert!(took < Duration::from_secs(1), "joined in {took:?}");
    assert!(!src.thread_running());
}

// =================================================================================
// Native signal rows (m03-plan §4.4; never run without the ADR-0004 §2 lock rule)
// =================================================================================

/// Wait for a real transition into `locked` and record it (the native rows).
#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
fn wait_for_real_lock(row: &str, expected: LockSignal) {
    let env_u64 = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let wait = Duration::from_secs(env_u64("HM_LOCK_WAIT_SECS").unwrap_or(1800));
    let src = PlatformSessionLockSource::start();
    let initial = src.snapshot();
    assert_eq!(initial.signal, expected, "{row}: the platform signal");
    assert_eq!(
        initial.state,
        LockState::Unlocked,
        "{row}: start unlocked (the harness locks after the source starts)"
    );
    let started = Instant::now();
    while src.lock_epoch().epoch == initial.epoch.epoch && started.elapsed() < wait {
        std::thread::sleep(Duration::from_millis(10));
    }
    let snap = src.snapshot();
    let observed_wall_ms = {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let since_change = snap.last_change.map_or(0, |t| t.elapsed().as_millis());
        now_ms.saturating_sub(since_change)
    };
    let latency_ms = env_u64("HM_LOCK_TRIGGERED_AT_MS")
        .map(|t| i128::try_from(observed_wall_ms).unwrap() - i128::from(t));
    let record = serde_json::json!({
        "row": row,
        "os": std::env::consts::OS,
        "signal": format!("{:?}", snap.signal),
        "initial_state": format!("{:?}", initial.state),
        "observed_state": format!("{:?}", snap.state),
        "epoch": snap.epoch.epoch,
        "observed": snap.epoch.observed,
        "events": snap.events,
        "events_off_thread": snap.events_off_thread,
        "waited_ms": started.elapsed().as_millis(),
        "observed_at_unix_ms": observed_wall_ms,
        "latency_from_trigger_ms": latency_ms,
    });
    if let Ok(path) = std::env::var("HM_LOCK_RECORD") {
        std::fs::write(path, record.to_string()).unwrap();
    }
    #[allow(clippy::print_stderr)] // an observation for the evidence record
    {
        eprintln!("m03 observation: {record}");
    }
    assert_eq!(
        snap.epoch.epoch,
        initial.epoch.epoch + 1,
        "{row}: a real lock was observed within {wait:?}"
    );
    assert!(snap.epoch.observed, "{row}: latched until acknowledged");
    assert_eq!(snap.events_off_thread, 0);
    src.shutdown();
}

/// P1 (M-F12): the macOS screen-lock signal, observed and timed during a real lock.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "native lock procedure: m03-plan §4.4 (U13 lock-macos.sh / lock-windows.ps1)"]
fn macos_lock_signal_observed() {
    wait_for_real_lock("macos_lock_signal_observed", LockSignal::MacosScreenLock);
}

/// P-W1 (M-F13): the Windows WTS lock signal, observed and timed during a real lock.
#[cfg(windows)]
#[test]
#[ignore = "native lock procedure: m03-plan §4.4 (U13 lock-macos.sh / lock-windows.ps1)"]
fn windows_lock_signal_observed() {
    wait_for_real_lock("windows_lock_signal_observed", LockSignal::WindowsSession);
}

/// The logind lock signal on a Linux desktop (blocked on B11).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "blocked: B11 (a Linux desktop host: GNOME, gnome-keyring, systemd-logind, a disposable account)"]
fn linux_logind_lock_signal_observed() {
    wait_for_real_lock("linux_logind_lock_signal_observed", LockSignal::LinuxLogind);
}
