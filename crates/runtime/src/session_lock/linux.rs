//! The Linux session-lock source (ADR-0008 D9 item 3): logind over the D-Bus system bus
//! (`zbus`, no `unsafe`), on a dedicated thread running a current-thread tokio runtime.
//!
//! * **The session** is the caller's own (`GetSessionByPID` of this process), or, when
//!   this process belongs to no session (a GNOME application or a user unit runs in a
//!   systemd user scope, outside the login session), logind's `GetSession("auto")`: the
//!   caller's session, else the same user's graphical session. No system bus, no logind,
//!   no such session, or a session that is not graphical (`Type` other than `x11`,
//!   `wayland`, `mir`: an SSH or console login on a headless host, WSL, a container)
//!   reads `unavailable`, and `revoke_on_lock` is refused there
//!   (`lock_signal_unavailable`).
//! * **The state** is the session's `LockedHint`. The thread subscribes before its first
//!   read to the session's `Lock` signal (recorded `locked` at once), its `Unlock` signal
//!   (re-read), and `PropertiesChanged` for `org.freedesktop.login1.Session`
//!   (`LockedHint`; an invalidation re-reads). Every stream is a proxy signal stream,
//!   which accepts only messages from logind's unique name. A failed read is `unknown`.
//!   The backstop re-query applies definite readings only.
//! * **A lost connection** (any stream ends) reads `unknown`, and the thread reconnects
//!   after [`RECONNECT_AFTER`].
//!
//! Native evidence is blocked on B11 (a Linux desktop host); until then
//! `revoke_on_lock` here carries `signal_unverified` (`heimdall_app::lock`).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use zbus::export::futures_core::Stream;
use zbus::proxy::{Builder, CacheProperties};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, Message, Proxy, proxy::SignalStream};

use super::{LockSignal, LockState, Shared, SourceOptions};

/// This platform's signal.
pub(super) const SIGNAL: LockSignal = LockSignal::LinuxLogind;

/// The source thread's name.
const THREAD_NAME: &str = "heimdall-session-lock";

/// The delay before a lost connection is re-established.
pub(super) const RECONNECT_AFTER: Duration = Duration::from_secs(5);

const LOGIND: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";
const LOCKED_HINT: &str = "LockedHint";
/// logind session types that have a screen to lock.
const GRAPHICAL: &[&str] = &["x11", "wayland", "mir"];

type Signals = Pin<Box<SignalStream<'static>>>;

struct Session {
    proxy: Proxy<'static>,
    lock: Signals,
    unlock: Signals,
    properties: Signals,
}

/// Why no session can be watched.
enum NoSession {
    /// No signal here: `unavailable`.
    Unavailable(&'static str),
    /// A failure after the session was found: `unknown`.
    Failed(&'static str),
}

async fn next(s: &mut Signals) -> Option<Message> {
    std::future::poll_fn(|cx| s.as_mut().poll_next(cx)).await
}

fn state_of(locked: Option<bool>) -> LockState {
    match locked {
        Some(true) => LockState::Locked,
        Some(false) => LockState::Unlocked,
        None => LockState::Unknown,
    }
}

async fn locked_hint(session: &Proxy<'_>) -> Option<bool> {
    session.get_property::<bool>(LOCKED_HINT).await.ok()
}

async fn proxy(
    conn: &Connection,
    path: &OwnedObjectPath,
    interface: &'static str,
) -> zbus::Result<Proxy<'static>> {
    Builder::<Proxy<'static>>::new(conn)
        .destination(LOGIND)?
        .path(path.clone().into_inner())?
        .interface(interface)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

/// Find and subscribe to this process's graphical session; returns it with its first
/// reading.
async fn connect() -> Result<(Session, LockState), NoSession> {
    use NoSession::{Failed, Unavailable};
    let conn = Connection::system()
        .await
        .map_err(|_| Unavailable("no system bus"))?;
    let manager = Proxy::new(&conn, LOGIND, MANAGER_PATH, MANAGER_IFACE)
        .await
        .map_err(|_| Unavailable("no logind"))?;
    let path: OwnedObjectPath = match manager
        .call("GetSessionByPID", &(std::process::id(),))
        .await
    {
        Ok(p) => p,
        Err(_) => manager
            .call("GetSession", &("auto",))
            .await
            .map_err(|_| Unavailable("no logind session for this process or user"))?,
    };
    let session = proxy(&conn, &path, SESSION_IFACE)
        .await
        .map_err(|_| Unavailable("the session cannot be addressed"))?;
    let kind: String = session
        .get_property("Type")
        .await
        .map_err(|_| Unavailable("the session type cannot be read"))?;
    if !GRAPHICAL.contains(&kind.as_str()) {
        return Err(Unavailable("the session is not graphical"));
    }
    let properties = proxy(&conn, &path, PROPERTIES_IFACE)
        .await
        .map_err(|_| Failed("the session properties cannot be addressed"))?;
    // Subscribe before the first read, so no transition falls between the two.
    let lock = session
        .receive_signal("Lock")
        .await
        .map_err(|_| Failed("cannot subscribe to Lock"))?;
    let unlock = session
        .receive_signal("Unlock")
        .await
        .map_err(|_| Failed("cannot subscribe to Unlock"))?;
    let changed = properties
        .receive_signal_with_args("PropertiesChanged", &[(0, SESSION_IFACE)])
        .await
        .map_err(|_| Failed("cannot subscribe to PropertiesChanged"))?;
    let first = state_of(locked_hint(&session).await);
    Ok((
        Session {
            proxy: session,
            lock: Box::pin(lock),
            unlock: Box::pin(unlock),
            properties: Box::pin(changed),
        },
        first,
    ))
}

async fn on_properties(shared: &Shared, session: &Proxy<'_>, msg: &Message) {
    type Changed = (String, HashMap<String, OwnedValue>, Vec<String>);
    let Ok((interface, changed, invalidated)) = msg.body().deserialize::<Changed>() else {
        shared.record(LockState::Unknown);
        return;
    };
    if interface != SESSION_IFACE {
        return;
    }
    if let Some(v) = changed.get(LOCKED_HINT) {
        shared.event_delivered();
        shared.record(state_of(bool::try_from(v).ok()));
    } else if invalidated.iter().any(|p| p == LOCKED_HINT) {
        shared.event_delivered();
        shared.record(state_of(locked_hint(session).await));
    }
}

/// Watch `s` until shutdown (`true`) or until a stream ends (`false`).
async fn watch(shared: &Shared, s: &mut Session, poll: Duration) -> bool {
    let mut tick = tokio::time::interval(poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            () = shared.stopped() => return true,
            m = next(&mut s.lock) => {
                if m.is_none() {
                    return false;
                }
                shared.event_delivered();
                shared.record(LockState::Locked);
            }
            m = next(&mut s.unlock) => {
                if m.is_none() {
                    return false;
                }
                shared.event_delivered();
                shared.record(state_of(locked_hint(&s.proxy).await));
            }
            m = next(&mut s.properties) => {
                let Some(msg) = m else {
                    return false;
                };
                on_properties(shared, &s.proxy, &msg).await;
            }
            _ = tick.tick() => {
                shared.record_definite(locked_hint(&s.proxy).await.map(|b| state_of(Some(b))));
            }
        }
    }
}

async fn run(shared: &Shared, poll: Duration) {
    let mut first = true;
    loop {
        if shared.stopping() {
            return;
        }
        match connect().await {
            Ok((mut session, reading)) => {
                shared.record(reading);
                if watch(shared, &mut session, poll).await {
                    return;
                }
                tracing::warn!("the logind connection was lost; unknown until it is back");
                shared.record(LockState::Unknown);
            }
            Err(NoSession::Unavailable(why)) if first => {
                tracing::info!(why, "no logind lock signal here; unavailable");
                shared.record(LockState::Unavailable);
                return;
            }
            Err(NoSession::Unavailable(why) | NoSession::Failed(why)) => {
                tracing::warn!(why, "the logind session cannot be watched; unknown");
                shared.record(LockState::Unknown);
            }
        }
        first = false;
        tokio::select! {
            () = shared.stopped() => return,
            () = tokio::time::sleep(RECONNECT_AFTER) => {}
        }
    }
}

/// Spawn the source thread.
pub(super) fn spawn(
    shared: Arc<Shared>,
    options: &SourceOptions,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let poll = options.poll_interval;
    std::thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || {
            shared.bind_thread();
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(error = %e, "the session-lock runtime could not start; unknown");
                    shared.record(LockState::Unknown);
                    return;
                }
            };
            rt.block_on(run(&shared, poll));
        })
}

/// Nothing extra: `shutdown` notifies [`Shared::stopped`], which the worker awaits.
pub(super) fn wake(_shared: &Shared) {}
