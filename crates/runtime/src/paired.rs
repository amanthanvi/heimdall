//! ⟨M06⟩ W2: the runner runtime's paired sessions (ADR-0012 §3.6–§3.11; m06-plan U1's W2
//! items M06-W0-R03 and M06-W0-R06; ADR-0006 §18.5 readings 1, 5, 7 and 17).
//!
//! * **Runner mode** ([`init_runner`], [`is_runner`]). The runner-init marker is this
//!   installation's own environment record with kind `remote_runner` (ADR-0012 §4 item 1):
//!   `heimdall remote init`'s library half writes it once (creating the environment ID at
//!   first use), and the runtime reads it at start. Only a runner offers `remote-control/1`
//!   and accepts a hello naming a paired client; every other runtime keeps wave 0's refusal
//!   (`SCHEMA_UNSUPPORTED`). The marker is not a boundary against same-account code, which
//!   is owner anyway (§3.12): a hello's client is still accepted only once the role table
//!   resolves it.
//! * **Acceptance** ([`PairedRunner::bind`]). A hello's `remote_client` (which only the
//!   bridge originates, from its argv, §3.6) is resolved by `heimdall_remote::roles::
//!   resolve_session` against the role table: an unknown or tombstoned client is refused
//!   (`client_revoked`, `invitation_expired`). The session's caller is then `{principal,
//!   role, remote_client}` with the table's role; capabilities never establish an identity
//!   (reading 1). The session is bound to that client for its lifetime.
//! * **Per-frame checks** ([`PairedRunner::frame`]). Every request of a paired session runs
//!   `heimdall_remote::roles::check` against the client's row read for that frame:
//!   revocation is rechecked per request; a pending client is refused everything but the
//!   activation probe and `join` (`invitation_pending`); `Attend` and `Decide` never reach
//!   the application (`INTERACTION_REQUIRED`: the session is non-interactive, §3.10 item 1);
//!   a permission outside the role is `role_insufficient`. ⟨M08 U2b-2 follow-up A⟩ The check
//!   runs nothing: a request it passes is run afterwards ([`PairedRunner::answer`], or the
//!   application), so a request it refuses never reaches the request fence and its ledger.
//! * **Pending sessions** (R06). A client pending at its hello negotiates only
//!   `remote-control/1` (`heimdall_ipc::session::PENDING_CAPABILITIES`), and that session
//!   is served only the activation probe and `join`, with the invitation and identity
//!   checks (`Invitations::join`) ahead of any recorded result, for its whole lifetime:
//!   after a successful join the client reconnects for an ordinary session. A limited role's
//!   ordinary negotiation never includes `remote-control/1`.
//! * **Runner-local widening** (§3.10). A paired owner's widening request becomes a pending
//!   ADR-0006 §3.1 decision record (`heimdall_remote::widening::StoreWidening`) and answers
//!   `APPROVAL_REQUIRED` with `next.decision_ref`; only an attended session local to the
//!   runner decides it ([`PairedRunner::decide_local`]), running the exact recorded request
//!   once; a replay returns the recorded terminal result.
//! * **Live events** (R03, blocking). A paired session's live events pass
//!   [`PairedRunner::live_visibility`]: its client still not revoked **and**
//!   `heimdall_app::events::event_visible_in` for its caller (client scope plus the views its
//!   role permits). The local owner keeps everything.
//! * **Revocation** (§3.7, §3.11). [`PairedRunner::revoke_client`] commits the tombstone
//!   first, then the line, then wakes every session of the client
//!   ([`PairedRunner::session_end`]): each of its subscriptions gets the terminal
//!   `client.revoked` event and the session closes.
//! * ⟨M06 W3⟩ **Runner requests** ([`PairedRunner::runner_request`]): a paired controller's
//!   `runner/1` forms that passed the role table and the pre-dispatch rules reach the runner
//!   runtime (`crate::runner::RunnerRuntime::handle`) on the blocking pool; a runner without
//!   one, and every other runtime, refuse them as before (`driver_unavailable`).
//! * ⟨M06 W3⟩ **Endpoints** ([`PairedRunner::rotate_endpoint`]): the session's own client
//!   sets or replaces its Iroh endpoint ID (ADR-0006 §18.7 item 4); a replacement moves the
//!   admission generation and then narrows the serve child's admission as a revocation does.
//! * ⟨M06 W3⟩ **Runner-local decisions** ([`PairedRunner::runner_local`]): `issuer_trust` and
//!   the time-source designation, for the local owner only (widening forms attended); a
//!   paired session never reaches them (`heimdall_remote::roles` refuses them first).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::events::LiveVisibility;
use heimdall_app::transport::{
    AdmissionReport, ApprovedWidening, ExposureDelta, PeerEnrollments, ServeControl, TransportKeys,
    TransportOps,
};
use heimdall_app::{Attendance, Caller, OpError};
use heimdall_contract::code::Code;
use heimdall_contract::envelope::{EffectStatus, Envelope, ResourceRef};
use heimdall_contract::event::{Cursor, Event, EventType};
use heimdall_contract::ids::{ClientId, EnvironmentId, IrohEndpointId};
use heimdall_contract::ipc::{ClientHello, PrincipalInfo};
use heimdall_contract::remote::{
    ClientEventKind, ClientEventPayload, ManagementPolicy, ProbeObservation,
    RemoteEnvironmentRequest, Role,
};
use heimdall_contract::request::{DecideRequest, InteractionMode, Request, Verdict};
use heimdall_contract::{SchemaVersion, Timestamp};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::principal::CallerContext;
use heimdall_domain::time::Clock;
use heimdall_ipc::session::{SessionEnd, SessionEndFuture};
use heimdall_remote::Refusal;
use heimdall_remote::invitations::{BootReading, Invitations, JoinRequest, TimeReading};
use heimdall_remote::line::{ManagementLine, ManagementLines, PublicKeyText, ServeCommand};
use heimdall_remote::roles::{self, NoConsents, SessionFrame, SessionIdentity, Verdict as Check};
use heimdall_remote::sshd_policy;
use heimdall_remote::widening::{self, DecidingSession, StoreWidening, WideningRecords as _};
use heimdall_store::ext_m06::{
    AppliedLine, ClientState, OwnerEndpoint, RemoteClientRecord, RevocationCause,
};
use heimdall_store::{Store, Txn};
use tokio::sync::watch;

/// `heimdall remote serve`'s library half (ADR-0012 §3.6), re-exported for the CLI wiring:
/// [`ServeArgs::parse`] reads exactly `--client <cid> --home <abs>` from argv, and
/// [`serve_bridge`] runs one bridged session between the remote side (stdin, stdout) and
/// the home's runtime control endpoint (`connect`).
pub use heimdall_remote::bridge::{
    ArgsError as ServeArgsError, BridgeEnd, ServeArgs, serve as serve_bridge,
};
/// The ports [`RunnerOptions`] takes, re-exported for the wiring.
pub use heimdall_remote::line::{
    ManagementLines as ManagementLinesPort, ServeCommand as RunnerServeCommand,
};

/// The ports a runner's paired sessions use besides the state store. The integrator's
/// `heimdall remote serve` / `service run` wiring supplies them
/// (`crate::service::ServiceOptions::runner`).
#[derive(Clone)]
pub struct RunnerOptions {
    /// The authorized_keys writer (`heimdall_remote::line::ManagementLines`). `None`: an
    /// approved invitation, a `join` and the activation probe answer `driver_unavailable`;
    /// a revocation still commits its tombstone (the admission authority), and the
    /// reconciler removes the line once a writer exists.
    pub lines: Option<Arc<dyn ManagementLines>>,
    /// The forced command's paths (`exec "<heimdall>" remote serve --client <cid> --home
    /// "<home>"`). Needed with [`Self::lines`].
    pub command: Option<ServeCommand>,
    /// Whether limited roles may enroll (ADR-0012 §3.2): the verified effective sshd
    /// policy, or `owner_only` (the default, fail closed).
    pub management_policy: ManagementPolicy,
    /// ⟨M06 W2⟩ The serve child's supervision (`crate::supervise_transport::
    /// TransportSupervisor`): a client revocation applies its narrowing there (ADR-0012
    /// §3.11 step 2: suspend, close streams, acknowledge or kill, then report). `None`: no
    /// serve child (the supervisor's watchdog, when wired, still applies it).
    pub admission: Option<Arc<dyn ServeControl>>,
    /// ⟨M06 W2, U56-Q6⟩ The transport executor's ports: with them an approved transport
    /// widening record runs `heimdall_app::transport::TransportOps::execute`, bound to its
    /// exact exposure delta; without them such a record stays pending on approval.
    pub transport: Option<RunnerTransport>,
    /// ⟨M06-W2-R02⟩ The effective sshd policy check the runtime runs at start when it builds
    /// its own line writer ([`runner_lines`]). `None`: under the account's own SSH files the
    /// runtime uses [`RunnerSshd::account`]; under a test configuration's scratch home, no
    /// check (sshd's default files, `owner_only`).
    pub sshd: Option<RunnerSshd>,
}

/// ⟨M06 W2⟩ The ports `heimdall_app::transport::TransportOps` runs over on a runner.
#[derive(Clone)]
pub struct RunnerTransport {
    /// K_iroh custody (`crate::supervise_transport::CredentialKeys`).
    pub keys: Arc<dyn TransportKeys>,
    /// The serve child's supervision.
    pub serve: Arc<dyn ServeControl>,
    /// The serve allowlist's enrollments.
    pub peers: Arc<dyn PeerEnrollments>,
}

impl Default for RunnerOptions {
    fn default() -> Self {
        Self {
            lines: None,
            command: None,
            management_policy: ManagementPolicy::OwnerOnly,
            admission: None,
            transport: None,
            sshd: None,
        }
    }
}

impl std::fmt::Debug for RunnerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerOptions")
            .field("lines", &self.lines.is_some())
            .field("command", &self.command.is_some())
            .field("management_policy", &self.management_policy)
            .field("admission", &self.admission.is_some())
            .field("transport", &self.transport.is_some())
            .field("sshd", &self.sshd.is_some())
            .finish()
    }
}

/// Whether this installation is a remote runner (module docs, "Runner mode"): its own
/// environment record's kind is `remote_runner`.
///
/// # Errors
///
/// The store's.
pub fn is_runner(tx: &mut Txn<'_>) -> heimdall_store::Result<bool> {
    let Some(id) = tx.self_environment()? else {
        return Ok(false);
    };
    Ok(tx
        .environment(&id)?
        .is_some_and(|e| e.kind == EnvironmentKind::RemoteRunner))
}

/// `heimdall remote init`'s library half (ADR-0012 §3.3 step 2; module docs, "Runner
/// mode"): record this installation's environment ID at first use and mark its own
/// environment record `remote_runner`, keeping any recorded permissions, device and label.
/// Idempotent. The caller holds the instance lock (no runtime is running on this home), or
/// runs inside the runtime; the runtime reads the marker at its next start.
///
/// # Errors
///
/// `STATE_UNAVAILABLE` from the store; `INTERNAL_ERROR` when randomness is unavailable.
pub fn init_runner(store: &Store) -> Result<EnvironmentId, OpError> {
    let fresh = heimdall_app::ids::new_environment_id().map_err(OpError::from)?;
    let id = store.transaction(|tx| {
        let id = match tx.self_environment()? {
            Some(id) => id,
            None => {
                tx.init_self_environment(&fresh)?;
                fresh.clone()
            }
        };
        let record = match tx.environment(&id)? {
            Some(mut e) => {
                e.kind = EnvironmentKind::RemoteRunner;
                e
            }
            None => EnvironmentRecord {
                id: id.clone(),
                device: heimdall_contract::ids::DeviceId::from_random_bytes([0; 16]),
                kind: EnvironmentKind::RemoteRunner,
                label: None,
                permissions: EnvironmentPermissions::default(),
            },
        };
        tx.upsert_environment(&record)?;
        Ok(id)
    })?;
    Ok(id)
}

// --- ⟨M06-W2-R02⟩ the runner's sshd policy, key files and owner enrollment ------------------

/// How a runner checks its account's effective sshd policy (ADR-0012 §3.2;
/// `heimdall_remote::sshd_policy::check_effective_policy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerSshd {
    /// The sshd binary (absolute).
    pub sshd: PathBuf,
    /// `-f`; `None` checks the system's default configuration.
    pub config: Option<PathBuf>,
    /// The runner account.
    pub user: String,
    /// Its home directory (absolute).
    pub home: PathBuf,
    /// Its login shell; `None` reads the account database (`getent passwd`, Linux).
    pub login_shell: Option<String>,
    /// Where the check's scratch directory is created (it must exist).
    pub scratch_parent: PathBuf,
    /// The bound on each sshd run.
    pub timeout: Duration,
}

impl RunnerSshd {
    /// The current account against the system sshd's default configuration: the account's
    /// name and home from the account database (never `$USER` or `$HOME`). `None` when
    /// either cannot be resolved (then: sshd's default files, `owner_only`).
    #[must_use]
    pub fn account(scratch_parent: &Path) -> Option<Self> {
        let paths = heimdall_localenv::paths::SshPaths::resolve().ok()?;
        let user = heimdall_localenv::sys::account_name().ok()?;
        Some(Self {
            sshd: PathBuf::from(sshd_policy::DEFAULT_SSHD),
            config: None,
            user,
            home: paths.account_home,
            login_shell: None,
            scratch_parent: scratch_parent.to_owned(),
            timeout: sshd_policy::DEFAULT_TIMEOUT,
        })
    }
}

/// ⟨M06-W2-R02; ADR-0012 §3.2⟩ A runner's authorized_keys files and management policy, from
/// its effective sshd policy: **verified** gives the policy's own file list (with the file
/// Heimdall writes, `<user_dir>/authorized_keys`, first) and `verified`; a refused policy, a
/// check that did not complete, a list that does not hold that file, or no check at all
/// gives sshd's default pair under `user_dir` and `owner_only` (fail closed).
///
/// The Match context is the loopback one (`host=localhost`, `addr` and `laddr` 127.0.0.1,
/// `lport` 22): the runner has no connection to take a context from at start. The
/// confirming probes of each activation (§3.2) catch a policy that differs for the
/// connection actually used.
pub async fn runner_lines(
    sshd: Option<&RunnerSshd>,
    user_dir: &Path,
) -> (crate::paired_lines::AuthorizedKeysFiles, ManagementPolicy) {
    use crate::paired_lines::AuthorizedKeysFiles;
    let fallback = || {
        (
            AuthorizedKeysFiles::sshd_default(user_dir),
            ManagementPolicy::OwnerOnly,
        )
    };
    let Some(s) = sshd else {
        return fallback();
    };
    let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let (Some(home), Ok(context)) = (
        s.home.to_str(),
        sshd_policy::MatchContext::new(&s.user, "localhost", loopback, loopback, 22),
    ) else {
        return fallback();
    };
    let shell = match &s.login_shell {
        Some(shell) => Some(shell.clone()),
        None => sshd_policy::login_shell(&s.user, s.timeout).await,
    };
    let check = sshd_policy::SshdCheck {
        sshd: &s.sshd,
        config: s.config.as_deref(),
        scratch_parent: &s.scratch_parent,
        context: &context,
        home,
        login_shell: shell.as_deref(),
        timeout: s.timeout,
    };
    let Ok(sshd_policy::PolicyVerdict::Verified(verified)) =
        sshd_policy::check_effective_policy(&check).await
    else {
        return fallback();
    };
    let own = user_dir.join("authorized_keys");
    let listed: Vec<PathBuf> = verified
        .authorized_keys_files
        .iter()
        .map(PathBuf::from)
        .collect();
    if !listed.contains(&own) {
        return fallback();
    }
    let mut files = vec![own.clone()];
    files.extend(listed.into_iter().filter(|f| f != &own));
    match AuthorizedKeysFiles::new(files) {
        Some(files) => (files, ManagementPolicy::Verified),
        None => fallback(),
    }
}

/// ⟨ADR-0012 §3.2 "Limits", ⟨2026-11-21⟩; ADR-0006 §18.7 items 16–19⟩ A runner's management
/// policy: the start check's result ([`runner_lines`]), which a confirming probe on a real
/// connection, or the bridge's own session check, can only lower. The start check evaluates
/// a loopback `Match` context, so a `Match Address` or `LocalPort` block can give a real
/// connection another policy; when an activation's probe shows the session is **not**
/// restricted as the verified policy claimed ([`sshd_policy::confirm_probe`] disagrees), the
/// runner is `owner_only` from then on and the policy is reported unverifiable: every later
/// limited-role invitation is refused `management_sshd_unverified`.
///
/// The downgrade is the store's authority-bearing `meta` row
/// (`heimdall_store::ext_runner::RunnerDowngrade`), read on every use: it holds across
/// runtime starts, and a new start check never raises it. Only the attended lift
/// ([`lift_downgrade`]) removes it, on fresh evidence from the real path. Probes confirm;
/// they never establish: an agreeing probe leaves an `owner_only` runner `owner_only`.
#[derive(Debug)]
pub struct RunnerPolicy {
    checked: ManagementPolicy,
    /// Lowered in this process without a durable row: a policy with no store, or a row that
    /// could not be written (fail closed until the next start).
    unverifiable: std::sync::atomic::AtomicBool,
    /// The store holding the downgrade row, when known.
    store: Option<Arc<Store>>,
    /// Where the bridge leaves its marker of a downgrade it could not record
    /// ([`UNRECORDED_DOWNGRADE_LOG`]): the log directory of the store's home. While a
    /// marker is pending there, this runner is `owner_only`.
    markers: Option<PathBuf>,
    /// A pending marker was recorded but could not be removed: owner-only for this
    /// process's life, and not recorded again until the next start.
    marker_stuck: std::sync::atomic::AtomicBool,
}

/// Why a runner went owner-only (the downgrade row's cause token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OwnerOnlyCause {
    /// A joining device's confirming probes disagreed with the verified policy (item 16).
    Probe,
    /// sshd allocated a PTY for a management session (item 17).
    SessionPty,
    /// sshd forwarded an agent into a management session (item 17).
    SessionAgent,
    /// The row cannot be read or names no known cause (still owner-only: fail closed).
    Unreadable,
}

impl OwnerOnlyCause {
    /// The token kept in the downgrade row.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Probe => "probe_disagreed",
            Self::SessionPty => "session_pty",
            Self::SessionAgent => "session_agent_forwarded",
            Self::Unreadable => "unreadable",
        }
    }

    /// The cause a row's token names ([`Self::Unreadable`] for any other).
    #[must_use]
    pub fn of_token(token: &str) -> Self {
        [Self::Probe, Self::SessionPty, Self::SessionAgent]
            .into_iter()
            .find(|c| c.token() == token)
            .unwrap_or(Self::Unreadable)
    }

    /// A fixed statement of the cause (`doctor`'s finding).
    #[must_use]
    pub fn statement(self) -> &'static str {
        match self {
            Self::Probe => {
                "a device's probes showed its management session was not restricted as the \
                 verified sshd policy claimed"
            }
            Self::SessionPty => "sshd allocated a terminal for a management session",
            Self::SessionAgent => "sshd forwarded an agent into a management session",
            Self::Unreadable => "the record cannot be read or names no known cause",
        }
    }
}

/// Record a downgrade event in `store` (a narrowing: no confirmation). The first cause
/// stands; a later event moves the epoch, so evidence recorded before it lifts nothing.
///
/// # Errors
///
/// The store's.
pub fn record_owner_only(
    store: &Store,
    cause: OwnerOnlyCause,
    now: Timestamp,
) -> heimdall_store::Result<heimdall_store::ext_runner::RunnerDowngrade> {
    store.transaction(|tx| tx.record_runner_downgrade(cause.token(), now))
}

/// The downgrade recorded in `store`: `None` only when the row is read and absent. A row or
/// a store that cannot be read is a downgrade ([`OwnerOnlyCause::Unreadable`]).
#[must_use]
pub fn recorded_owner_only(store: &Store) -> Option<OwnerOnlyCause> {
    match store.transaction(|tx| tx.runner_downgrade()) {
        Ok(None) => None,
        Ok(Some(d)) => Some(OwnerOnlyCause::of_token(&d.cause)),
        Err(_) => Some(OwnerOnlyCause::Unreadable),
    }
}

/// The state database of the home a forced command names (`remote serve --home`), following
/// the pointer (⟨M08 U2b-1⟩ `heimdall_store::layout::db_path`).
///
/// # Errors
/// The home's layout is corrupt (`state_corrupt`): no database is named.
pub fn state_db_of_home(home: &Path) -> heimdall_store::Result<PathBuf> {
    heimdall_store::layout::db_path(&crate::Paths::under(home).state_dir)
}

/// ⟨ADR-0006 §18.7 items 17–18; ADR-0012 §3.2 "How the downgrade is kept"⟩ The bridge's
/// write: record a downgrade event in the state database of `home`, from a process that
/// holds no instance lock (the runtime it would have bridged to may be running). It is the
/// store's one write outside the lock holder
/// (`heimdall_store::ext_runner::bridge_record_runner_downgrade`): set-only, idempotent, one
/// `BEGIN IMMEDIATE` transaction with a bounded busy timeout, on an existing runner's
/// database at this build's schema only (never created, migrated or repaired). ⟨review
/// W3-R01⟩ The schema is read again inside that transaction, so a flat family that a
/// runtime's start fenced for adoption after this function found it is refused, not
/// written; the caller then queues the event, and the runtime records it in the generation
/// it serves.
///
/// # Errors
///
/// No such database, another schema (a family fenced for adoption included), not a
/// runner's, the write lock not obtained in time, or the store's failure: nothing was
/// recorded. The caller refuses its session all the same and notes the failure
/// ([`note_unrecorded_downgrade`]).
///
/// ⟨M08 W4 U2b-3b; W3-R01's W4 half⟩ **The pointer is checked again after the write.** A
/// restore or a reset makes another generation current by the pointer switch, under the
/// instance lock the bridge does not hold. The restore reads the replaced generation inside
/// a `BEGIN IMMEDIATE` transaction it holds until after the switch
/// (`heimdall_store::restore`), so the bridge's transaction commits either before that read
/// (the row is in the replaced generation before it is read, and is carried forward) or after
/// the switch. In the second case the pointer no longer names the generation the bridge opened,
/// and this fails ([`StoreError::Corrupt`]), so the caller queues the event in the fail-closed
/// marker and the runtime records it in the generation it serves. A reset is the same switch.
/// **Stated limit:** that late write lands in the replaced generation, which is residue; the
/// refusal inside the bridge's own transaction, before it writes, is the store's
/// (`ext_runner::bridge_record_with`, SEC-3b's file), not made here.
pub fn record_owner_only_in_home(
    home: &Path,
    cause: OwnerOnlyCause,
    now: Timestamp,
) -> heimdall_store::Result<()> {
    record_owner_only_in_home_with(home, cause, now, None)
}

/// Test support (`restore_window_tests`): [`record_owner_only_in_home`] with `faults` as the
/// hook of the bridge's store (its `BeforeTransaction` fires after the bridge opened the
/// database and before its transaction: the window a restore can switch in). Never used by
/// production code.
///
/// # Errors
/// As [`record_owner_only_in_home`].
#[doc(hidden)]
pub fn record_owner_only_in_home_with_faults(
    home: &Path,
    cause: OwnerOnlyCause,
    now: Timestamp,
    faults: Arc<dyn heimdall_store::FaultHook>,
) -> heimdall_store::Result<()> {
    record_owner_only_in_home_with(home, cause, now, Some(faults))
}

fn record_owner_only_in_home_with(
    home: &Path,
    cause: OwnerOnlyCause,
    now: Timestamp,
    faults: Option<Arc<dyn heimdall_store::FaultHook>>,
) -> heimdall_store::Result<()> {
    let state_dir = crate::Paths::under(home).state_dir;
    let opened = heimdall_store::layout::pointed_generation(&state_dir)?;
    let db = state_db_of_home(home)?;
    let written = match faults {
        None => heimdall_store::ext_runner::bridge_record_runner_downgrade(&db, cause.token(), now),
        Some(faults) => heimdall_store::ext_runner::bridge_record_runner_downgrade_with_faults(
            &db,
            cause.token(),
            now,
            faults,
        ),
    };
    if heimdall_store::layout::pointed_generation(&state_dir)? != opened {
        return Err(heimdall_store::StoreError::Corrupt(
            "a restore or a reset made another store generation current during the bridge's write"
                .to_owned(),
        ));
    }
    written.map(drop)
}

/// ⟨M08 W4 U2b-3b; ADR-0014 §3.6 step 6⟩ **Reauthorize** a paired management client a restore
/// quarantined: the owner's decision, attended at this machine (the caller confirms it). It
/// removes the client's hold (`heimdall_store::restore`), so a hello the client sends after it
/// is admitted again. It reopens nothing else: the client's pre-restore request IDs stay
/// refused by their epoch and answered by their fences, and its decision references stay
/// stale. A revoked client is never reauthorized (its tombstone stands). Returns whether a
/// hold was removed.
///
/// # Errors
/// The store's.
pub fn reauthorize_client(store: &Store, client: &ClientId) -> heimdall_store::Result<bool> {
    store.transaction(|tx| {
        if tx
            .remote_client(client)?
            .is_some_and(|c| c.state == ClientState::Revoked)
        {
            return Ok(false);
        }
        tx.lift_client_hold(client)
    })
}

/// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The marker, in a home's log directory, of a
/// downgrade event the bridge could **not** record: a **pending-write queue that fails
/// closed**. One line per event (the cause token and the time), appended by the bridge
/// ([`note_unrecorded_downgrade`]) in an owner-only directory. While it exists the runtime
/// treats the runner as owner-only, before the row exists ([`RunnerPolicy::unverifiable`]);
/// at start and at each limited-role admission the runtime records the row under its
/// instance lock and then removes the marker ([`RunnerPolicy::drain_pending`]). The marker
/// only ever lowers: its absence or removal lifts nothing (the row then stands, and only
/// the attended lift removes that).
pub const UNRECORDED_DOWNGRADE_LOG: &str = "runner-downgrade-unrecorded.log";

/// The marker while the runtime records it: [`UNRECORDED_DOWNGRADE_LOG`] is renamed to
/// this first, so an event the bridge appends meanwhile lands in a new marker and is never
/// removed unrecorded. It counts as the marker wherever that is read.
const UNRECORDED_DOWNGRADE_DRAINING: &str = "runner-downgrade-unrecorded.draining";

/// The most [`UNRECORDED_DOWNGRADE_LOG`] holds; further events are not appended (the
/// marker already stands, which is all it says).
const UNRECORDED_DOWNGRADE_LOG_MAX: u64 = 4096;

/// One noted event: its cause, and its time when the line states one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnrecordedDowngrade {
    /// The cause the bridge saw.
    pub cause: OwnerOnlyCause,
    /// When (the bridge's wall clock).
    pub at: Option<Timestamp>,
}

/// What a marker directory is, as it is on disk now (never through a link).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerDir {
    /// No such directory: it holds no marker.
    Missing,
    /// A real directory of this account that no one else can write.
    Private,
    /// A link, not a directory, another account's or open to others: nothing in it is
    /// read, written or removed, and its state counts as a pending marker (fail closed).
    Refused,
}

fn marker_dir(dir: &Path) -> MarkerDir {
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return MarkerDir::Missing,
        Err(_) => return MarkerDir::Refused,
    };
    if !meta.file_type().is_dir() {
        return MarkerDir::Refused;
    }
    #[cfg(unix)]
    {
        use heimdall_ipc::unix::{PathFacts, check_private_dir, current_uid};
        if check_private_dir(&PathFacts::of(&meta), current_uid()).is_err() {
            return MarkerDir::Refused;
        }
    }
    MarkerDir::Private
}

/// A file of the marker directory, opened without following a link.
fn open_marker(path: &Path, options: &mut std::fs::OpenOptions) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Queue, in `log_dir`, a downgrade event that could not be recorded: one appended line of
/// fixed tokens (no path, no environment value, no key material) in the marker
/// ([`UNRECORDED_DOWNGRADE_LOG`]). The directory is created owner-only (0700) when the home
/// has none, and is otherwise used only as it is: a link, another account's directory or
/// one others can write is refused, and so is a marker that is a link or not a regular
/// file. The file is owner-only and never followed through a link. A full marker is left
/// as it is (it already stands).
///
/// # Errors
///
/// The directory or the marker is refused, or cannot be created or written.
pub fn note_unrecorded_downgrade(
    log_dir: &Path,
    cause: OwnerOnlyCause,
    now: Timestamp,
) -> std::io::Result<()> {
    use std::io::Write as _;
    if marker_dir(log_dir) == MarkerDir::Missing {
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        // One level only: the home itself is never created here.
        match builder.create(log_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    if marker_dir(log_dir) != MarkerDir::Private {
        return Err(std::io::Error::other(
            "the marker's directory is not an owner-only directory",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = open_marker(&log_dir.join(UNRECORDED_DOWNGRADE_LOG), &mut options)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("the marker is not a regular file"));
    }
    if meta.len() >= UNRECORDED_DOWNGRADE_LOG_MAX {
        return Ok(());
    }
    file.write_all(format!("{} {now}\n", cause.token()).as_bytes())?;
    file.sync_all()
}

/// The last event one marker file states; `None` without the file. A file that is a link,
/// is not regular, cannot be read, or whose last line names no known cause, is still an
/// event ([`OwnerOnlyCause::Unreadable`]). Read-only, bounded, never through a link.
fn marker_event(path: &Path) -> Option<UnrecordedDowngrade> {
    use std::io::Read as _;
    let unreadable = UnrecordedDowngrade {
        cause: OwnerOnlyCause::Unreadable,
        at: None,
    };
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(unreadable),
    };
    if !meta.is_file() {
        return Some(unreadable);
    }
    let mut text = String::new();
    let read = open_marker(path, std::fs::OpenOptions::new().read(true)).and_then(|f| {
        f.take(UNRECORDED_DOWNGRADE_LOG_MAX)
            .read_to_string(&mut text)
    });
    if read.is_err() {
        return Some(unreadable);
    }
    let Some(line) = text.lines().rev().find(|l| !l.trim().is_empty()) else {
        return Some(unreadable);
    };
    let mut words = line.split_ascii_whitespace();
    let cause = words
        .next()
        .map_or(OwnerOnlyCause::Unreadable, OwnerOnlyCause::of_token);
    let at = words.next().and_then(|w| w.parse().ok());
    Some(UnrecordedDowngrade { cause, at })
}

/// The downgrade event pending in `log_dir` (the marker, or the one the runtime was
/// recording when it stopped); `None` when the directory is missing or holds neither. A
/// directory that is refused (a link, another account's, open to others) is a pending
/// event too ([`OwnerOnlyCause::Unreadable`]): nothing in it is read, and nothing says the
/// marker was not removed from it. Read-only.
#[must_use]
pub fn unrecorded_downgrade(log_dir: &Path) -> Option<UnrecordedDowngrade> {
    match marker_dir(log_dir) {
        MarkerDir::Missing => None,
        MarkerDir::Refused => Some(UnrecordedDowngrade {
            cause: OwnerOnlyCause::Unreadable,
            at: None,
        }),
        MarkerDir::Private => marker_event(&log_dir.join(UNRECORDED_DOWNGRADE_LOG))
            .or_else(|| marker_event(&log_dir.join(UNRECORDED_DOWNGRADE_DRAINING))),
    }
}

/// Step one of recording the marker in `log_dir`: move it aside
/// ([`UNRECORDED_DOWNGRADE_DRAINING`]), so what the bridge appends from now on is a new
/// marker. `false` when the directory is refused (nothing in it is touched).
fn set_marker_aside(log_dir: &Path) -> bool {
    if marker_dir(log_dir) != MarkerDir::Private {
        return false;
    }
    let marker = log_dir.join(UNRECORDED_DOWNGRADE_LOG);
    if std::fs::symlink_metadata(&marker).is_ok() {
        // A rename moves a link itself, never its target. If it fails the marker stays,
        // and so does the downgrade ([`marker_cleared`] then says so).
        let _ = std::fs::rename(&marker, log_dir.join(UNRECORDED_DOWNGRADE_DRAINING));
    }
    true
}

/// Step three, after the row committed: remove what was set aside. `true` only when the
/// set-aside marker is gone (a marker the bridge wrote meanwhile is the next one).
fn marker_cleared(log_dir: &Path) -> bool {
    let aside = log_dir.join(UNRECORDED_DOWNGRADE_DRAINING);
    match std::fs::remove_file(&aside) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// What one attempt to record the pending marker did ([`drain_marker`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drained {
    /// No marker is pending.
    Nothing,
    /// The row is recorded with the marker's cause and the marker is gone.
    Recorded(OwnerOnlyCause),
    /// The row could not be written: the marker stays.
    RowFailed,
    /// The row is recorded; the marker could not be removed (or its directory is refused).
    MarkerStuck(OwnerOnlyCause),
}

impl Drained {
    /// Whether no marker is left pending.
    fn cleared(self) -> bool {
        matches!(self, Drained::Nothing | Drained::Recorded(_))
    }
}

/// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ Record the pending marker of `dir`, if any,
/// as a downgrade row of `store` (the marker's cause), and remove the marker only once the
/// row committed. The caller holds the instance lock. Never call it inside a transaction of
/// the same store.
fn drain_marker(dir: &Path, store: &Store, now: Timestamp) -> Drained {
    let Some(pending) = unrecorded_downgrade(dir) else {
        return Drained::Nothing;
    };
    let aside = set_marker_aside(dir);
    if record_owner_only(store, pending.cause, now).is_err() {
        return Drained::RowFailed;
    }
    if aside && marker_cleared(dir) {
        Drained::Recorded(pending.cause)
    } else {
        Drained::MarkerStuck(pending.cause)
    }
}

/// The marker directory of the home whose state database is `db` (the bridge's own rule,
/// [`state_db_of_home`], read backwards); `None` for a database that is not a home's.
/// ⟨M08 U2b-1⟩ The database is `<state>/state.db` in the flat layout, or
/// `<state>/generations/<generation>/state.db`: either names the home.
fn marker_dir_of_db(db: &Path) -> Option<PathBuf> {
    use heimdall_store::layout::stategen::{GenerationName, generations::GENERATIONS};
    if db.file_name()? != std::ffi::OsStr::new(crate::service::STATE_DB_FILE) {
        return None;
    }
    let parent = db.parent()?;
    let state_dir = match parent.parent() {
        Some(generations)
            if generations.file_name() == Some(std::ffi::OsStr::new(GENERATIONS))
                && GenerationName::parse(parent.file_name()?.to_str()?).is_some() =>
        {
            generations.parent()?
        }
        _ => parent,
    };
    let paths = crate::Paths::under(state_dir.parent()?);
    (paths.state_dir == state_dir).then_some(paths.log_dir)
}

impl RunnerPolicy {
    /// The policy the start check produced, with no durable downgrade.
    #[must_use]
    pub fn new(checked: ManagementPolicy) -> Self {
        Self {
            checked,
            unverifiable: std::sync::atomic::AtomicBool::new(false),
            store: None,
            markers: None,
            marker_stuck: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// [`Self::new`], over the store holding the downgrade row: a row there, whoever wrote
    /// it and whenever, makes this runner `owner_only`, and a disagreeing probe writes one.
    ///
    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ So does the bridge's pending marker in
    /// the log directory of the store's home (the home whose state database the store is;
    /// none for an in-memory store): [`Self::drain_pending`].
    #[must_use]
    pub fn with_store(checked: ManagementPolicy, store: Arc<Store>) -> Self {
        let markers = store.database_path().as_deref().and_then(marker_dir_of_db);
        Self {
            store: Some(store),
            markers,
            ..Self::new(checked)
        }
    }

    /// Whether a marker is pending or stuck (no I/O beyond reading the directory; usable
    /// inside a store transaction).
    fn marker_pending(&self) -> bool {
        self.marker_stuck.load(std::sync::atomic::Ordering::SeqCst)
            || self
                .markers
                .as_deref()
                .is_some_and(|dir| unrecorded_downgrade(dir).is_some())
    }

    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ Record the bridge's pending marker, if
    /// one exists: the runtime (the instance lock's holder) writes the downgrade row with
    /// the marker's cause, and only once that committed removes the marker. Run at start
    /// ([`PairedRunner::new`]) and at each limited-role admission or decision
    /// ([`Self::unverifiable`], and before a join's transaction).
    ///
    /// It fails closed at every step: the marker lowers this runner while it exists
    /// ([`Self::marker_pending`]); a row that cannot be written leaves the marker and
    /// lowers the process; a marker that cannot be removed (or a marker directory that is
    /// a link, another account's or open to others) leaves this process owner-only until
    /// its next start, with the row recorded. Removing the marker lifts nothing: the row
    /// stands then.
    ///
    /// Never call it inside a transaction of the same store.
    pub fn drain_pending(&self, now: Timestamp) {
        use std::sync::atomic::Ordering::SeqCst;
        let (Some(dir), Some(store)) = (self.markers.as_deref(), self.store.as_deref()) else {
            return;
        };
        if self.marker_stuck.load(SeqCst) {
            return;
        }
        let outcome = drain_marker(dir, store, now);
        match outcome {
            Drained::Nothing => {}
            Drained::RowFailed => {
                tracing::warn!("a pending owner-only downgrade could not be recorded");
                self.lower_in_process();
            }
            Drained::Recorded(cause) | Drained::MarkerStuck(cause) => {
                tracing::warn!(
                    cause = cause.token(),
                    "a downgrade the bridge could not record is recorded now: this runner is \
                     owner-only"
                );
                if outcome == Drained::MarkerStuck(cause) {
                    tracing::warn!("the pending-downgrade marker could not be removed");
                    self.marker_stuck.store(true, SeqCst);
                }
            }
        }
    }

    /// The policy in force now: `owner_only` while a downgrade stands.
    #[must_use]
    pub fn current(&self) -> ManagementPolicy {
        if self.unverifiable() {
            ManagementPolicy::OwnerOnly
        } else {
            self.checked
        }
    }

    /// The policy the start check produced, whatever happened since.
    #[must_use]
    pub fn checked(&self) -> ManagementPolicy {
        self.checked
    }

    /// Whether the checked policy is unverifiable: a downgrade row stands (read on every
    /// call, so the bridge's write takes effect without a restart and a lift without one
    /// too), the bridge's marker is pending (it is recorded first:
    /// [`Self::drain_pending`]), or this process lowered it without one.
    ///
    /// Never call it inside a transaction of the same store (the store has one connection).
    #[must_use]
    pub fn unverifiable(&self) -> bool {
        self.drain_pending(Timestamp::now());
        self.unverifiable.load(std::sync::atomic::Ordering::SeqCst)
            || self.marker_pending()
            || self
                .store
                .as_deref()
                .is_some_and(|s| recorded_owner_only(s).is_some())
    }

    /// Lower the runner to `owner_only` for this process at once, without touching the store
    /// (usable inside a store transaction). [`Self::lower`] makes it durable.
    fn lower_in_process(&self) {
        self.unverifiable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Record a downgrade event: durably when there is a store (the row is then the only
    /// record, so an attended lift takes effect without a restart), otherwise, or when the
    /// row cannot be written, for this process's life.
    pub fn lower(&self, cause: OwnerOnlyCause, now: Timestamp) {
        let durable = self
            .store
            .as_deref()
            .is_some_and(|s| record_owner_only(s, cause, now).is_ok());
        if self.store.is_some() && !durable {
            tracing::warn!("the owner-only downgrade could not be recorded");
        }
        self.unverifiable
            .store(!durable, std::sync::atomic::Ordering::SeqCst);
        tracing::warn!(
            cause = cause.token(),
            "the verified sshd policy is unverifiable: this runner is owner-only"
        );
    }

    /// Confirm the policy with what an activation's probes observed on the real connection.
    ///
    /// # Errors
    ///
    /// [`Refusal::ManagementSshdUnsupported`] when the probe disagrees; the runner is then
    /// `owner_only` ([`Self::current`]), durably when it has a store.
    pub fn confirm(
        &self,
        client: &ClientId,
        nonce: &str,
        report: &sshd_policy::ProbeReport,
    ) -> Result<(), Refusal> {
        sshd_policy::confirm_probe(client, nonce, report)
            .inspect_err(|_| self.lower(OwnerOnlyCause::Probe, Timestamp::now()))
    }

    /// Whether a device's own observation (`Join.probe`, a recheck's `probe`) agrees with a
    /// restricted management session. The echoes are the runner's own (it answered this
    /// session itself), so only the four observed behaviours are compared.
    ///
    /// # Errors
    ///
    /// [`Refusal::ManagementSshdUnsupported`] when it disagrees. Nothing is recorded.
    pub fn observation_agrees(
        client: &ClientId,
        observed: &ProbeObservation,
    ) -> Result<(), Refusal> {
        let report = sshd_policy::ProbeReport {
            echoed_client: Some(client.clone()),
            echoed_nonce: Some(String::new()),
            pty_refused: observed.pty_refused,
            forward_refused: observed.forward_refused,
            agent_forward_refused: observed.agent_forward_refused,
            setenv_canary_delivered: observed.setenv_canary_delivered,
        };
        sshd_policy::confirm_probe(client, "", &report)
    }

    /// ⟨ADR-0006 §18.7 item 16⟩ [`Self::confirm`] with a joining device's own observation.
    ///
    /// # Errors
    ///
    /// As [`Self::confirm`].
    pub fn confirm_observation(
        &self,
        client: &ClientId,
        observed: &ProbeObservation,
    ) -> Result<(), Refusal> {
        Self::observation_agrees(client, observed)
            .inspect_err(|_| self.lower(OwnerOnlyCause::Probe, Timestamp::now()))
    }

    /// ⟨ADR-0006 §18.7 item 16⟩ The judgement of a `join` that would activate, given the
    /// policy in force (`current`), with no I/O: the refusal if any, and whether the runner
    /// must be lowered. An owner join is exempt; a disagreeing observation it carries still
    /// lowers the runner (it never refuses the owner). A limited role needs a verified
    /// policy now (`management_sshd_unverified`), an observation (`USAGE_ERROR` without one)
    /// and their agreement (`management_sshd_unsupported`, and the runner is lowered).
    pub fn judge_join(
        current: ManagementPolicy,
        client: &ClientId,
        role: Role,
        observed: Option<&ProbeObservation>,
    ) -> (Result<(), Refusal>, bool) {
        let disagrees = |o: &ProbeObservation| Self::observation_agrees(client, o).is_err();
        if role == Role::Owner {
            let lower = current == ManagementPolicy::Verified && observed.is_some_and(disagrees);
            return (Ok(()), lower);
        }
        if current != ManagementPolicy::Verified {
            return (Err(Refusal::ManagementSshdUnverified), false);
        }
        match observed {
            None => (Err(Refusal::InvalidRequest), false),
            Some(o) if disagrees(o) => (Err(Refusal::ManagementSshdUnsupported), true),
            Some(_) => (Ok(()), false),
        }
    }

    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ [`Self::judge_join`] inside the join's
    /// commit transaction `tx` (`Invitations::join_confirmed`): the downgrade row is read
    /// there (so a write of the bridge's that landed just before is seen by this join, and a
    /// row that cannot be read is a downgrade), and a disagreeing probe's downgrade is
    /// written there, so the refusal's row commits in the join's transaction while the
    /// join's own changes do not. The second value is whether the runner was lowered: the
    /// caller lowers the process too if that transaction does not commit
    /// ([`Self::lower_in_process`]). A policy with no store is lowered in process only.
    ///
    /// # Errors
    ///
    /// The store's, writing the row (the caller's transaction rolls back).
    pub fn check_join_in(
        &self,
        tx: &mut heimdall_store::Txn<'_>,
        client: &ClientId,
        role: Role,
        observed: Option<&ProbeObservation>,
        now: Timestamp,
    ) -> heimdall_store::Result<(Result<(), Refusal>, bool)> {
        // A pending marker lowers this join too (the caller recorded it before this
        // transaction when it could: `Self::drain_pending`).
        let lowered = self.unverifiable.load(std::sync::atomic::Ordering::SeqCst)
            || self.marker_pending()
            || (self.store.is_some() && !matches!(tx.runner_downgrade(), Ok(None)));
        let current = if lowered {
            ManagementPolicy::OwnerOnly
        } else {
            self.checked
        };
        let (judged, lower) = Self::judge_join(current, client, role, observed);
        if lower {
            if self.store.is_some() {
                tx.record_runner_downgrade(OwnerOnlyCause::Probe.token(), now)?;
            } else {
                self.lower_in_process();
            }
            tracing::warn!(
                cause = OwnerOnlyCause::Probe.token(),
                "the verified sshd policy is unverifiable: this runner is owner-only"
            );
        }
        Ok((judged, lower))
    }

    /// [`Self::judge_join`] against the policy in force now, lowering the runner when it
    /// says so. Not for use inside a store transaction ([`Self::unverifiable`]).
    ///
    /// # Errors
    ///
    /// The refusals of [`Self::judge_join`].
    pub fn check_join(
        &self,
        client: &ClientId,
        role: Role,
        observed: Option<&ProbeObservation>,
    ) -> Result<(), Refusal> {
        let (judged, lower) = Self::judge_join(self.current(), client, role, observed);
        if lower {
            self.lower(OwnerOnlyCause::Probe, Timestamp::now());
        }
        judged
    }
}

// --- ⟨ADR-0006 §18.7 item 19⟩ lifting the owner-only downgrade ------------------------------

/// How old recheck evidence may be when the attended lift judges it.
pub const RECHECK_EVIDENCE_MAX_AGE: Duration = Duration::from_secs(15 * 60);

/// One reading of the clocks the evidence's age is judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockReading {
    /// The wall clock.
    pub wall: Timestamp,
    /// The current boot.
    pub boot_id: String,
    /// The continuous (suspend-inclusive) clock; `None` when its source is unavailable now.
    pub continuous: Option<Duration>,
}

impl ClockReading {
    /// A reading of `clock`, now.
    #[must_use]
    pub fn of(clock: &dyn Clock) -> Self {
        Self {
            wall: clock.wall(),
            boot_id: clock.boot_id().0,
            continuous: clock.try_continuous(),
        }
    }
}

/// Why recorded evidence does not lift the downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftRefusal {
    /// No owner controller's recheck is recorded.
    NoEvidence,
    /// The evidence was recorded before a later downgrade event.
    BeforeLaterDowngrade,
    /// The evidence is older than [`RECHECK_EVIDENCE_MAX_AGE`].
    Stale,
    /// Its age cannot be established (another boot, a clock that went backwards, or a
    /// continuous clock available at only one of the two readings).
    AgeUncertain,
    /// ⟨M06-W3-R03⟩ A downgrade the bridge could not record is still pending in the home's
    /// log directory and could not be recorded and removed now: lifting would be undone at
    /// once.
    MarkerPending,
}

impl LiftRefusal {
    /// A fixed statement, for the refusal's message.
    #[must_use]
    pub fn statement(self) -> &'static str {
        match self {
            Self::NoEvidence => {
                "no recheck from an owner's controller is recorded (run `heimdall environment \
                 recheck` on the owner's controller first)"
            }
            Self::BeforeLaterDowngrade => {
                "the recorded recheck is from before a later downgrade (run `heimdall \
                 environment recheck` on the owner's controller again)"
            }
            Self::Stale => {
                "the recorded recheck is older than 15 minutes (run `heimdall environment \
                 recheck` on the owner's controller again)"
            }
            Self::AgeUncertain => {
                "the age of the recorded recheck cannot be established (run `heimdall \
                 environment recheck` on the owner's controller again)"
            }
            Self::MarkerPending => {
                "a downgrade that could not be recorded is still pending in this home's log \
                 directory and cannot be recorded now (see `heimdall doctor`, then run \
                 `heimdall environment recheck` on the owner's controller again)"
            }
        }
    }

    /// The refusal as an error (`CAPABILITY_UNAVAILABLE`, `management_sshd_unverified`,
    /// effect `none`).
    #[must_use]
    pub fn to_error(self) -> OpError {
        OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "{}: the runner stays owner-only and nothing was changed",
                self.statement()
            ),
        )
        .with_reason(heimdall_contract::envelope::reason::MANAGEMENT_SSHD_UNVERIFIED)
        .with_effect(EffectStatus::None)
    }
}

/// Whether `evidence` lifts `downgrade` at `now`: recorded at the downgrade's own epoch, and
/// no older than [`RECHECK_EVIDENCE_MAX_AGE`] by the wall clock and, where both readings
/// have one, by the continuous clock of the same boot. Any uncertainty refuses.
///
/// # Errors
///
/// The [`LiftRefusal`].
pub fn judge_evidence(
    downgrade: &heimdall_store::ext_runner::RunnerDowngrade,
    evidence: Option<&heimdall_store::ext_runner::PolicyRecheckEvidence>,
    now: &ClockReading,
) -> Result<(), LiftRefusal> {
    let Some(e) = evidence else {
        return Err(LiftRefusal::NoEvidence);
    };
    if e.epoch != downgrade.epoch {
        return Err(LiftRefusal::BeforeLaterDowngrade);
    }
    if e.boot_id != now.boot_id {
        return Err(LiftRefusal::AgeUncertain);
    }
    let within = |elapsed: Option<Duration>| match elapsed {
        None => Err(LiftRefusal::AgeUncertain),
        Some(d) if d > RECHECK_EVIDENCE_MAX_AGE => Err(LiftRefusal::Stale),
        Some(_) => Ok(()),
    };
    // The wall clock: a reading before the evidence's is a clock that went backwards.
    within(Duration::try_from(now.wall.duration_since(e.recorded_at)).ok())?;
    match (e.continuous_ms, now.continuous) {
        (Some(then), Some(at)) => within(at.checked_sub(Duration::from_millis(then))),
        (None, None) => Ok(()),
        _ => Err(LiftRefusal::AgeUncertain),
    }
}

/// What `heimdall remote policy recheck` shows before it asks: the downgrade, the recorded
/// evidence with the probing controller's row, and whether the evidence would lift it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecheckView {
    /// The standing downgrade (`None`: the runner is not downgraded).
    pub downgrade: Option<heimdall_store::ext_runner::RunnerDowngrade>,
    /// The recorded evidence, if any.
    pub evidence: Option<heimdall_store::ext_runner::PolicyRecheckEvidence>,
    /// The probing controller's row in the role table, when it still has one.
    pub controller: Option<RemoteClientRecord>,
    /// Whether the evidence lifts the downgrade at the reading given.
    pub verdict: Result<(), LiftRefusal>,
}

/// Read the [`RecheckView`] in one transaction (read-only).
///
/// # Errors
///
/// The store's.
pub fn recheck_view(tx: &mut Txn<'_>, now: &ClockReading) -> heimdall_store::Result<RecheckView> {
    let downgrade = tx.runner_downgrade()?;
    let evidence = tx.policy_recheck()?;
    let controller = match &evidence {
        Some(e) => tx.remote_client(&e.controller)?,
        None => None,
    };
    let verdict = match &downgrade {
        Some(d) => judge_evidence(d, evidence.as_ref(), now).and_then(|()| {
            // The probing client must still be an active owner of this runner.
            if controller
                .as_ref()
                .is_some_and(|c| c.state == ClientState::Active && c.role == Role::Owner)
            {
                Ok(())
            } else {
                Err(LiftRefusal::NoEvidence)
            }
        }),
        None => Ok(()),
    };
    Ok(RecheckView {
        downgrade,
        evidence,
        controller,
        verdict,
    })
}

/// ⟨ADR-0006 §18.7 item 19⟩ `runner_local.policy_recheck`: lift the owner-only downgrade.
/// A local, attended widening: the caller is the local owner in an attended session (the CLI
/// asked for the typed `yes` on the evidence shown), in the runtime or, with no runtime,
/// under the instance lock. The evidence is judged again here, in the lift's own
/// transaction ([`recheck_view`]), and the rows are removed only at the epoch judged. A
/// runner that is not downgraded answers `lifted: false` (idempotent by convergence).
///
/// The CLI uses this path when the runtime is offline, after terminal confirmation. The
/// runtime checks attendance for `runner_local.policy_recheck` before the request fence.
///
/// # Errors
///
/// `INTERACTION_REQUIRED` when unattended; `driver_unavailable` on a store that is not a runner's;
/// `CAPABILITY_UNAVAILABLE` /
/// `management_sshd_unverified` with the [`LiftRefusal`]'s statement; `STATE_UNAVAILABLE`.
pub fn lift_downgrade(
    store: &Store,
    now: &ClockReading,
    attended: bool,
) -> heimdall_app::error::OpResult<serde_json::Value> {
    if !attended {
        return Err(OpError::new(
            Code::InteractionRequired,
            "lifting the owner-only downgrade needs the owner attending at this runner's terminal",
        )
        .with_effect(EffectStatus::None));
    }
    apply_downgrade_lift(store, now)
}

fn apply_downgrade_lift(
    store: &Store,
    now: &ClockReading,
) -> heimdall_app::error::OpResult<serde_json::Value> {
    // ⟨M06-W3-R03⟩ A pending marker is a downgrade event not yet in the store: record it
    // first (its row moves the epoch, so evidence from before it lifts nothing below). A
    // marker that cannot be recorded and removed refuses the lift: the runner would be
    // lowered again at once.
    if let Some(dir) = store.database_path().as_deref().and_then(marker_dir_of_db)
        && unrecorded_downgrade(&dir).is_some()
        && store.transaction(is_runner)?
        && !drain_marker(&dir, store, now.wall).cleared()
    {
        return Err(LiftRefusal::MarkerPending.to_error());
    }
    store
        .transaction(|tx| {
            if !is_runner(tx)? {
                return Ok(Err(OpError::driver_unavailable(
                    "this installation is not a remote runner",
                )
                .with_effect(EffectStatus::None)));
            }
            let view = recheck_view(tx, now)?;
            let Some(downgrade) = view.downgrade else {
                return Ok(Ok(
                    serde_json::json!({ "downgraded": false, "lifted": false }),
                ));
            };
            if let Err(refusal) = view.verdict {
                return Ok(Err(refusal.to_error()));
            }
            if !tx.lift_runner_downgrade(downgrade.epoch)? {
                return Ok(Err(LiftRefusal::BeforeLaterDowngrade.to_error()));
            }
            Ok(Ok(serde_json::json!({
                "downgraded": false,
                "lifted": true,
                "cause": downgrade.cause,
                "epoch": downgrade.epoch,
                "controller": view.evidence.as_ref().map(|e| e.controller.as_str().to_owned()),
                "evidence_recorded_at": view.evidence.as_ref().map(|e| e.recorded_at),
            })))
        })?
        .map(|data| heimdall_app::error::Completed::ok(Code::Ok, data))
}

/// Whether `id` is an endpoint ID the Iroh library accepts: with feature `iroh`, Iroh's own
/// parser (the 32 bytes must be an Ed25519 public key); without it this build has no Iroh
/// library, and the contract's parser (64 lowercase hex, already applied to `id`) is all
/// there is.
#[must_use]
pub fn iroh_endpoint_ok(id: &IrohEndpointId) -> bool {
    #[cfg(feature = "iroh")]
    {
        heimdall_transport_iroh::endpoint::iroh_id(id).is_some()
    }
    #[cfg(not(feature = "iroh"))]
    {
        let _ = id;
        true
    }
}

/// What `heimdall remote init` enrolls (ADR-0012 §3.3 step 3; ADR-0006 §18.7 item 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEnrollment {
    /// The client ID the controller records for itself.
    pub client: ClientId,
    /// The controller's management key (`ssh-ed25519 <base64>`).
    pub public_key: String,
    /// The controller device's Iroh endpoint ID, when it has K_iroh.
    pub iroh_endpoint: Option<IrohEndpointId>,
}

/// A committed owner enrollment ([`enroll_owner`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEnrolled {
    /// This runner's environment.
    pub environment: EnvironmentId,
    /// The effective owner client (an earlier enrollment of the same key stands).
    pub owner: RemoteClientRecord,
    /// Whether the client was created now.
    pub created: bool,
    /// What happened to the endpoint, when the enrollment carried one.
    pub endpoint: Option<OwnerEndpoint>,
}

impl OwnerEnrolled {
    /// The owner's management line under `command` (`None` when its recorded key or the
    /// command does not render: no line, fail closed).
    #[must_use]
    pub fn line(&self, command: &ServeCommand) -> Option<String> {
        let key = PublicKeyText::parse(&self.owner.public_key).ok()?;
        ManagementLine {
            client: self.owner.client.clone(),
            command: command.clone(),
            key,
            expiry: None,
        }
        .render()
        .ok()
    }

    /// The answer's data (`remote init`'s, and the `runner_local.enroll_owner` form's).
    #[must_use]
    pub fn data(&self, line: Option<&str>, line_written: bool) -> serde_json::Value {
        let mut data = serde_json::json!({
            "environment": self.environment.as_str(),
            "client": self.owner.client.as_str(),
            "created": self.created,
            "key_fingerprint": self.owner.key_fingerprint.as_str(),
            "management_line": line,
            "line_written": line_written,
        });
        if let (Some(change), Some(map)) = (&self.endpoint, data.as_object_mut()) {
            let (change, kept) = match change {
                OwnerEndpoint::Recorded => ("recorded", None),
                OwnerEndpoint::Unchanged => ("unchanged", None),
                OwnerEndpoint::Kept(current) => ("kept", Some(current.as_str())),
            };
            map.insert(
                "iroh_admission".to_owned(),
                serde_json::json!({ "endpoint": change, "kept_endpoint": kept }),
            );
        }
        data
    }
}

/// ⟨M06-W2-R02; ADR-0012 §3.3; ADR-0006 §18.7 item 8⟩ `remote init`'s records, after the
/// owner's confirmation on the runner's terminal: the runner marker ([`init_runner`]), then
/// in **one transaction** the owner client (`Txn::enroll_bootstrap_owner`: idempotent for a
/// retried bootstrap of the same key) and, when the enrollment carries an endpoint ID, the
/// owner's Iroh admission and first endpoint (`Txn::admit_bootstrap_owner_iroh`: it adds,
/// and never replaces an existing endpoint). The caller holds the instance lock, or is the
/// runtime serving the attended local owner's `runner_local.enroll_owner`.
///
/// # Errors
///
/// `USAGE_ERROR` for a key that is not one Ed25519 public key, an endpoint ID the Iroh
/// library refuses, or an endpoint that cannot be recorded for the effective client (another
/// client's, or a client that joined by invitation); `key_already_authorized`;
/// `STATE_UNAVAILABLE`. Nothing is written on a refusal (the marker aside).
pub fn enroll_owner(
    store: &Store,
    now: Timestamp,
    enrollment: &OwnerEnrollment,
) -> Result<OwnerEnrolled, OpError> {
    let usage = |m: &str| OpError::new(Code::UsageError, m).with_effect(EffectStatus::None);
    let key = PublicKeyText::parse(&enrollment.public_key)
        .map_err(|_| usage("the owner key is not one ssh-ed25519 public key"))?;
    if enrollment
        .iroh_endpoint
        .as_ref()
        .is_some_and(|e| !iroh_endpoint_ok(e))
    {
        return Err(usage("the Iroh endpoint ID is not a valid endpoint ID"));
    }
    let environment = init_runner(store)?;
    let record = RemoteClientRecord {
        client: enrollment.client.clone(),
        role: Role::Owner,
        key_fingerprint: key.fingerprint(),
        public_key: key.openssh(),
        state: ClientState::Active,
        invitation: None,
        revoked_generation: None,
        revocation: None,
        created_at: now,
        updated_at: now,
        line: AppliedLine::Absent,
    };
    // Which step refused, for the answer: the transaction rolls back whole either way.
    let endpoint_refused = std::cell::Cell::new(false);
    let committed = store.transaction(|tx| {
        let (owner, created) = tx.enroll_bootstrap_owner(&record, now)?;
        let endpoint = match &enrollment.iroh_endpoint {
            Some(e) => Some(
                tx.admit_bootstrap_owner_iroh(&owner.client, e, now)
                    .inspect_err(|_| endpoint_refused.set(true))?,
            ),
            None => None,
        };
        Ok((owner, created, endpoint))
    });
    match committed {
        Ok((owner, created, endpoint)) => Ok(OwnerEnrolled {
            environment,
            owner,
            created,
            endpoint,
        }),
        Err(heimdall_store::StoreError::GenerationConflict(_)) if endpoint_refused.get() => {
            Err(usage(
                "the Iroh endpoint cannot be recorded for this client (it is another client's, \
                 or the client joined by invitation): nothing was written",
            ))
        }
        Err(heimdall_store::StoreError::GenerationConflict(_)) => Err(OpError::new(
            Code::CapabilityUnavailable,
            "this key is already authorized for another client of this runner",
        )
        .with_reason(heimdall_contract::envelope::reason::KEY_ALREADY_AUTHORIZED)
        .with_effect(EffectStatus::None)),
        Err(_) => Err(OpError::new(
            Code::StateUnavailable,
            "the owner enrollment cannot be written",
        )
        .with_effect(EffectStatus::None)),
    }
}

/// `remote init`'s line write when **no runtime runs** (the caller holds the instance lock,
/// so no reconciler races it): make the files hold exactly `line` for the owner through the
/// port (`crate::paired_lines`' ADR-0005 §3.3 procedure), then record it. `false` when the
/// port refused; the runtime's reconciler writes the line at its next start.
pub fn write_owner_line(
    store: &Store,
    lines: &dyn ManagementLines,
    owner: &ClientId,
    line: &str,
) -> bool {
    let desired = heimdall_remote::line::DesiredLine::Present(line.to_owned());
    if heimdall_remote::line::reconcile_line(lines, owner, &desired).is_err() {
        return false;
    }
    // Bookkeeping only; the reconciler repeats it idempotently.
    let _ = store.transaction(|tx| tx.set_remote_client_line(owner, AppliedLine::Active));
    true
}

/// ⟨M06 W2; the orchestrator's ruling on M06-W0-R03⟩ Strip every decision handle from an
/// event a paired caller receives: a decision event reaches a paired owner as a read-only
/// owner-role view (V1 has no `RemoteDecide`), so its payload loses `decision_id` and a
/// `decision` resource reference loses its ID. Applied on every paired delivery path: live
/// events (the relay's paired channel, `crate::dispatch::EventRelay`), resumed backlogs,
/// snapshots, event pages and `inspect decisions` ([`redact_value`]).
pub fn redact_event(event: &mut Event) {
    redact_value(&mut event.payload);
    if let Some(r) = &mut event.resource
        && r.kind == "decision"
    {
        r.id = None;
    }
}

/// [`redact_event`] over a document (an event page, a snapshot, a decision listing): every
/// `decision_id` member is removed, and every object naming `kind: "decision"` loses its
/// `id`, at any depth.
pub fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.remove("decision_id");
            if map.get("kind").and_then(serde_json::Value::as_str) == Some("decision") {
                map.remove("id");
            }
            for child in map.values_mut() {
                redact_value(child);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_value),
        _ => {}
    }
}

/// One paired session's binding (module docs, "Acceptance")./// One paired session's binding (module docs, "Acceptance").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedSession {
    /// The client, from the bridge's hello, resolved by the role table.
    pub client: ClientId,
    /// Its role, from the role table.
    pub role: Role,
    /// Whether it was pending at the hello (module docs, "Pending sessions").
    pub pending: bool,
}

/// What a paired session's request becomes ([`PairedRunner::frame`]).
#[derive(Debug)]
pub enum Frame {
    /// Refused by the row check: nothing was run.
    Answer(Envelope<serde_json::Value>),
    /// ⟨M08 U2b-2 follow-up A⟩ Passed the row check and answered by this runner, not the
    /// application (the probe, `join`, a pending widening record, a client revocation, an
    /// endpoint rotation, a policy recheck): nothing has run yet. [`PairedRunner::answer`]
    /// runs it, after the request fence (`crate::dispatch`).
    Runner(RunnerFrame),
    /// Passed every check: dispatch to the application as this caller.
    Route(Box<Caller>, Request),
}

/// ⟨M08 U2b-2 follow-up A⟩ A paired request that passed its row check and that this runner
/// answers itself ([`Frame::Runner`]).
#[derive(Debug)]
pub struct RunnerFrame {
    client: ClientId,
    answer: RunnerAnswer,
    request: Request,
}

impl RunnerFrame {
    /// The request.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.request
    }
}

/// Which of this runner's own answers a [`RunnerFrame`] gets.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunnerAnswer {
    Probe,
    Join,
    Widening,
    RevokeClient {
        environment: EnvironmentId,
        client: ClientId,
    },
    RotateEndpoint,
    PolicyRecheck {
        environment: EnvironmentId,
        probe: ProbeObservation,
    },
}

fn value_of(e: Envelope<impl serde::Serialize>) -> Envelope<serde_json::Value> {
    e.map(|d| serde_json::to_value(d).unwrap_or_default())
}

fn refused(r: Refusal) -> Envelope<serde_json::Value> {
    value_of(r.envelope())
}

fn ok(data: serde_json::Value) -> Envelope<serde_json::Value> {
    Envelope::ok(data)
}

/// The runner runtime's paired-session service (module docs). One per runtime, shared by
/// every connection's dispatcher.
pub struct PairedRunner {
    store: Arc<Store>,
    operations: heimdall_app::Operations,
    clock: Arc<dyn Clock>,
    options: RunnerOptions,
    /// Moves on every client revocation this runtime commits; each paired session's
    /// [`Self::session_end`] rereads its client's row then.
    revocations: watch::Sender<u64>,
    /// ⟨M06 W1 review⟩ The one line-write lock of this runner: every invitation service over
    /// it shares it, so a revocation's line removal always wins over an in-flight reconcile.
    serial: heimdall_remote::invitations::LineSerial,
    /// ⟨M06 W3⟩ The runner runtime that serves `runner/1` forms ([`Self::with_runtime`]).
    runtime: Option<Arc<crate::runner::RunnerRuntime>>,
    /// The management policy in force (`RunnerOptions::management_policy`, which a
    /// disagreeing confirming probe lowers to `owner_only`).
    policy: RunnerPolicy,
    /// ⟨§18.7 item 19⟩ "`sshd -T` verifies now", when given ([`Self::with_sshd_recheck`]);
    /// otherwise the effective policy check is run again ([`Self::sshd_verifies_now`]).
    sshd_recheck: Option<SshdRecheck>,
}

/// The port behind a recheck's "`sshd -T` verifies now" ([`PairedRunner::with_sshd_recheck`]).
pub type SshdRecheck = Arc<dyn Fn() -> bool + Send + Sync>;

impl std::fmt::Debug for PairedRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedRunner")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PairedRunner {
    /// The service over this runtime's store and operations.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        operations: heimdall_app::Operations,
        clock: Arc<dyn Clock>,
        options: RunnerOptions,
    ) -> Self {
        let (revocations, _) = watch::channel(0);
        // The downgrade is a row of this runner's own store: the database of the home
        // `remote serve --home` gives the bridge. A downgrade the bridge could not record
        // there (its pending marker) is recorded now, at start.
        let policy = RunnerPolicy::with_store(options.management_policy, Arc::clone(&store));
        policy.drain_pending(clock.wall());
        Self {
            operations,
            clock,
            policy,
            sshd_recheck: None,
            store,
            options,
            revocations,
            serial: heimdall_remote::invitations::LineSerial::default(),
            runtime: None,
        }
    }

    /// ⟨M06 W3⟩ Serve paired controllers' `runner/1` forms with `runtime` (module docs,
    /// "Runner requests").
    #[must_use]
    pub fn with_runtime(mut self, runtime: Arc<crate::runner::RunnerRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// ⟨§18.7 item 19⟩ Answer a recheck's "`sshd -T` verifies now" with `port` instead of
    /// running the effective policy check (a runner whose sshd is not the account's).
    #[must_use]
    pub fn with_sshd_recheck(mut self, port: SshdRecheck) -> Self {
        self.sshd_recheck = Some(port);
        self
    }

    /// The management policy in force and whether a confirming probe made it unverifiable
    /// ([`RunnerPolicy`]): what limited-role invitations are gated by.
    #[must_use]
    pub fn policy(&self) -> &RunnerPolicy {
        &self.policy
    }

    /// ⟨M06 W3⟩ The runner runtime, when wired.
    #[must_use]
    pub fn runtime(&self) -> Option<&Arc<crate::runner::RunnerRuntime>> {
        self.runtime.as_ref()
    }

    /// This runner's environment.
    #[must_use]
    pub fn environment(&self) -> &EnvironmentId {
        self.operations.environment()
    }

    /// The client's row now (`None`: unknown).
    fn row(&self, client: &ClientId) -> Result<Option<RemoteClientRecord>, Refusal> {
        self.store
            .transaction(|tx| tx.remote_client(client))
            .map_err(|_| Refusal::State)
    }

    /// Resolve a hello (module docs, "Acceptance"): `None` for a hello naming no client
    /// (the local same-uid owner), else the bound session.
    ///
    /// # Errors
    ///
    /// The resolution's refusal: `client_revoked`, `invitation_expired`, or
    /// `STATE_UNAVAILABLE` (the role table could not be read: refused, never accepted).
    pub fn bind(&self, hello: &ClientHello) -> Result<Option<PairedSession>, Refusal> {
        let mut read_failed = false;
        let identity = roles::resolve_session(true, hello, |client| match self.row(client) {
            Ok(row) => row,
            Err(_) => {
                read_failed = true;
                None
            }
        });
        if read_failed {
            return Err(Refusal::State);
        }
        match identity? {
            SessionIdentity::Local => Ok(None),
            SessionIdentity::Paired {
                client,
                role,
                state,
            } => Ok(Some(PairedSession {
                client,
                role,
                pending: state == ClientState::Pending,
            })),
        }
    }

    /// ⟨M08 W4 U2b-3b; ADR-0014 §3.6's table, H10⟩ The refusal of a bound session whose client
    /// or invitation a restore put on hold, or `None`. A management client quarantined by a
    /// restore is not admitted until reauthorized at this machine (`CAPABILITY_UNAVAILABLE` /
    /// `client_quarantined_after_restore`, next `owner_decision`); a pending client whose
    /// invitation the restore voided cannot join it (`invitation_void_after_restore`). A hold
    /// that cannot be read refuses too (`STATE_UNAVAILABLE`): never admitted on a failed read.
    /// The dispatcher asks this at the hello, before the session is bound.
    #[must_use]
    pub fn hold_refusal(
        &self,
        session: &PairedSession,
    ) -> Option<Envelope<heimdall_contract::envelope::ErrorData>> {
        use heimdall_contract::envelope::{NextAction, reason};
        use heimdall_store::restore::HoldKind;
        let held = self.store.transaction(|tx| {
            let invitation = tx
                .remote_client(&session.client)?
                .and_then(|c| c.invitation)
                .map(|i| i.as_str().to_owned());
            let void = match &invitation {
                Some(id) if session.pending => tx.restore_hold(HoldKind::Invitation, id)?.is_some(),
                _ => false,
            };
            let quarantined = tx
                .restore_hold(HoldKind::Client, session.client.as_str())?
                .is_some();
            Ok((void, quarantined))
        });
        let refuse = |reason: &str, message: &str| {
            OpError::new(Code::CapabilityUnavailable, message.to_owned())
                .with_reason(reason)
                .with_effect(EffectStatus::None)
                .with_next(NextAction {
                    action: "owner_decision".to_owned(),
                    ..NextAction::default()
                })
                .into_envelope()
        };
        match held {
            Ok((true, _)) => Some(refuse(
                reason::INVITATION_VOID_AFTER_RESTORE,
                "this invitation was voided when the runner's state was restored: it cannot be \
                 joined. Ask the runner's owner for a new invitation",
            )),
            Ok((false, true)) => Some(refuse(
                reason::CLIENT_QUARANTINED_AFTER_RESTORE,
                "this client was quarantined when the runner's state was restored: it is not \
                 admitted until the runner's owner reauthorizes it at the runner",
            )),
            Ok((false, false)) => None,
            Err(_) => Some(
                OpError::new(
                    Code::StateUnavailable,
                    "the runner's state store could not be read".to_owned(),
                )
                .with_effect(EffectStatus::None)
                .into_envelope(),
            ),
        }
    }

    /// The caller of a paired session (ADR-0012 §3.7): `{principal, role, remote_client}`,
    /// never attended, non-interactive.
    #[must_use]
    pub fn caller(&self, principal: &PrincipalInfo, session: &PairedSession) -> Caller {
        let principal = crate::dispatch::principal_ref(principal);
        Caller {
            context: CallerContext {
                principal,
                role: roles::client_role(session.role),
                remote_client: Some(session.client.clone()),
            },
            attendance: Attendance::Unattended,
            interaction: InteractionMode::NonInteractive,
        }
    }

    /// The check of one paired request (module docs, "Per-frame checks"; "Pending
    /// sessions"): refused here, passed to this runner's own answer ([`Self::answer`]), or
    /// routed to the application as the client's caller. ⟨M08 U2b-2 follow-up A⟩ It reads
    /// the client's row and runs nothing, so the request fence can come between it and the
    /// request (`crate::dispatch`).
    pub fn frame(
        &self,
        principal: &PrincipalInfo,
        session: &PairedSession,
        request: Request,
    ) -> Frame {
        let record = match self.row(&session.client) {
            Ok(r) => r,
            Err(r) => return Frame::Answer(refused(r)),
        };
        // ⟨Gemini R03⟩ The wire activation probe goes through `roles::check` as it is.
        let verdict = roles::check(
            record.as_ref(),
            SessionFrame::Request(&request),
            &NoConsents,
        );
        // R06: a session that started pending is served only the probe and `join`, whatever
        // the row says now.
        if session.pending && !matches!(verdict, Check::Probe | Check::Join | Check::Refuse(_)) {
            return Frame::Answer(refused(Refusal::InvitationPending));
        }
        let answer = match verdict {
            Check::Refuse(r) => {
                if matches!(r, Refusal::ClientRevoked | Refusal::InvitationExpired) {
                    // Whatever revoked it, forget any cached time sample from it and end its
                    // other sessions too.
                    if let Some(rt) = &self.runtime {
                        rt.time().invalidate_client(&session.client);
                    }
                    self.revocations.send_modify(|n| *n = n.wrapping_add(1));
                }
                return Frame::Answer(refused(r));
            }
            Check::Probe => RunnerAnswer::Probe,
            Check::Join => RunnerAnswer::Join,
            Check::PendingRunnerLocal { .. } => RunnerAnswer::Widening,
            Check::Dispatch { .. } => match &request {
                Request::RemoteEnvironment(RemoteEnvironmentRequest::RevokeClient {
                    environment,
                    client,
                }) => RunnerAnswer::RevokeClient {
                    environment: environment.clone(),
                    client: client.clone(),
                },
                // ⟨M06 W3⟩ The session's own client only (never a field). ⟨W5; ADR-0006
                // §18.9 item 5⟩ The form is on the base capability, so a limited role's
                // session reaches this arm too; the check above and the invitation's own
                // admission (`rotate_endpoint`) are what decide, per request, as before.
                Request::RemoteEnvironment(RemoteEnvironmentRequest::RotateEndpoint { .. }) => {
                    RunnerAnswer::RotateEndpoint
                }
                // ⟨§18.7 item 19⟩ The session's own client is the probing controller.
                Request::RemoteEnvironment(RemoteEnvironmentRequest::RunnerPolicyRecheck {
                    environment,
                    probe,
                }) => RunnerAnswer::PolicyRecheck {
                    environment: environment.clone(),
                    probe: *probe,
                },
                _ => return Frame::Route(Box::new(self.caller(principal, session)), request),
            },
        };
        Frame::Runner(RunnerFrame {
            client: session.client.clone(),
            answer,
            request,
        })
    }

    /// ⟨M08 U2b-2 follow-up A⟩ Run a paired request that [`Self::frame`] passed to this
    /// runner ([`Frame::Runner`]), as the session's client.
    pub async fn answer(&self, frame: RunnerFrame) -> Envelope<serde_json::Value> {
        let RunnerFrame {
            client,
            answer,
            request,
        } = frame;
        match answer {
            RunnerAnswer::Probe => self.probe(&client, &request).await,
            RunnerAnswer::Join => self.join(&client, &request).await,
            RunnerAnswer::Widening => self.submit_widening(&client, &request),
            RunnerAnswer::RevokeClient {
                environment,
                client: revoked,
            } => self.revoke_client(&environment, &revoked).await,
            RunnerAnswer::RotateEndpoint => self.rotate_endpoint(&client, &request).await,
            RunnerAnswer::PolicyRecheck { environment, probe } => {
                self.policy_recheck(&client, &environment, &probe).await
            }
        }
    }

    /// The subscription check of a paired session (module docs): the row reread now; a
    /// pending session subscribes to nothing.
    ///
    /// # Errors
    ///
    /// The check's refusal.
    pub fn subscribe_check(&self, session: &PairedSession) -> Result<(), Refusal> {
        if session.pending {
            return Err(Refusal::InvitationPending);
        }
        let record = self.row(&session.client)?;
        match roles::check(record.as_ref(), SessionFrame::Subscribe, &NoConsents) {
            Check::Dispatch { .. } => Ok(()),
            Check::Refuse(r) => Err(r),
            _ => Err(Refusal::NotAvailableRemotely),
        }
    }

    /// ⟨M06-W0-R03⟩ A paired session's live-event visibility (module docs, "Live events"):
    /// its client still not revoked (reread per event, a store failure hides the event), and
    /// the application's per-reader scope for its caller.
    #[must_use]
    pub fn live_visibility(&self, caller: &CallerContext, client: &ClientId) -> LiveVisibility {
        let scope = self.operations.events().live_visibility(caller);
        let store = Arc::clone(&self.store);
        let client = client.clone();
        Arc::new(move |event: &Event| {
            let live = store
                .transaction(|tx| tx.remote_client(&client))
                .ok()
                .flatten()
                .is_some_and(|r| r.state != ClientState::Revoked);
            live && scope(event)
        })
    }

    /// The terminal `client.revoked` event of a client's own subscriptions.
    fn revoked_event(&self, client: &ClientId, role: Option<Role>) -> Event {
        let payload = ClientEventPayload {
            kind: ClientEventKind::Revoked,
            environment: self.environment().clone(),
            client: client.clone(),
            role,
        };
        Event {
            schema_version: SchemaVersion::current(),
            event_id: heimdall_app::ids::new_event_id()
                .unwrap_or_else(|_| heimdall_contract::ids::EventId::from_random_bytes([0; 16])),
            event_type: EventType::Client,
            environment_id: self.environment().clone(),
            operation_id: None,
            resource: Some(ResourceRef {
                kind: "client".to_owned(),
                id: Some(client.as_str().to_owned()),
            }),
            timestamp: self.clock.wall(),
            cursor: Cursor(String::new()),
            payload: serde_json::to_value(payload).unwrap_or_default(),
        }
    }

    /// The future that ends a paired session once its client is revoked (module docs,
    /// "Revocation"): it wakes on every revocation this runtime commits and rereads the
    /// row; a missing or tombstoned row, or a row that cannot be read, ends it.
    pub fn session_end(&self, session: &PairedSession) -> SessionEndFuture {
        let mut rx = self.revocations.subscribe();
        let store = Arc::clone(&self.store);
        let terminal = self.revoked_event(&session.client, Some(session.role));
        let client = session.client.clone();
        Box::pin(async move {
            loop {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                let gone = store
                    .transaction(|tx| tx.remote_client(&client))
                    .map_or(true, |r| r.is_none_or(|r| r.state == ClientState::Revoked));
                if gone {
                    let mut event = terminal;
                    event.timestamp = Timestamp::now();
                    return SessionEnd {
                        event,
                        code: Code::CapabilityUnavailable,
                        message: "the client was revoked on this runner".to_owned(),
                    };
                }
            }
        })
    }

    /// The time reading of the invitation rules: the shared gate's `Safe` observation, or
    /// an uncertain wall clock with the boot anchor.
    async fn time_reading(&self) -> TimeReading {
        match self.operations.timegate().check().await {
            // ⟨2026-11-21, ruling 2⟩ With the tolerance the gate accepted it with, so the
            // invitation rules judge deadlines on the upper bound of now.
            Ok(safe) => TimeReading::safe_within(&safe.anchor, safe.tolerance_used),
            Err(_) => TimeReading::uncertain(Some(BootReading {
                boot_id: self.clock.boot_id(),
                continuous: self.clock.continuous(),
            })),
        }
    }

    fn invitations(&self) -> Result<Invitations<'_>, Refusal> {
        match (&self.options.lines, &self.options.command) {
            (Some(lines), Some(command)) => Ok(Invitations {
                store: &self.store,
                lines: lines.as_ref(),
                environment: self.operations.environment(),
                command,
                clock: self.clock.as_ref(),
                serial: &self.serial,
            }),
            _ => Err(Refusal::LinesUnavailable),
        }
    }

    /// The activation probe (ADR-0012 §3.2): the client from the bridge's argv and the
    /// pending record's nonce, for a probe naming this runner and that nonce, while a pending
    /// client's invitation is live (`Invitations::probe` checks all three).
    async fn probe(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        let Some(probe) = heimdall_remote::invitations::ProbeRequest::from_request(request) else {
            return refused(Refusal::NotAvailableRemotely);
        };
        let now = self.time_reading().await;
        let echo = match self
            .invitations()
            .and_then(|i| i.probe(client, &probe, &now))
        {
            Ok(e) => e,
            Err(r) => return refused(r),
        };
        ok(serde_json::json!({
            "environment": self.environment(),
            "client": echo.client,
            "nonce": echo.nonce,
        }))
    }

    /// `join` (ADR-0012 §3.9 items 3–6): identity first, the compare-and-set at join time,
    /// then the line; a retried join returns the recorded result after the same check.
    async fn join(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        let Some(join) = JoinRequest::from_request(request) else {
            return refused(Refusal::NotAvailableRemotely);
        };
        let now = self.time_reading().await;
        // ⟨§18.7 item 16; ADR-0012 §3.2 "How the downgrade is kept"⟩ The policy check runs
        // before the commit, for an activation only, inside the commit's transaction: the
        // downgrade row is read there, and a disagreeing probe's row is written there, so
        // the refusal and the row commit together and the join's own changes do not.
        let (joined, unobserved) = {
            let unobserved = std::cell::Cell::new(false);
            let lowered = std::cell::Cell::new(false);
            let wall = self.clock.wall();
            // A downgrade the bridge could not record is recorded first, under the lock.
            self.policy.drain_pending(wall);
            let confirm = |tx: &mut heimdall_store::Txn<'_>,
                           j: &heimdall_store::ext_m06::JoinRecord| {
                let (judged, lowers) =
                    self.policy
                        .check_join_in(tx, &j.client, j.role, join.probe.as_ref(), wall)?;
                lowered.set(lowers);
                Ok(judged.inspect_err(|r| unobserved.set(*r == Refusal::InvalidRequest)))
            };
            let joined = self
                .invitations()
                .and_then(|i| i.join_confirmed(client, &join, &now, &confirm));
            // The row did not commit (the store failed under a disagreeing probe): this
            // process stays owner-only all the same, until its next start.
            if lowered.get() && matches!(joined, Err(Refusal::State)) {
                self.policy.lower_in_process();
            }
            (joined, unobserved.get())
        };
        if unobserved {
            return value_of(
                OpError::new(
                    Code::UsageError,
                    "a limited role's join must report what its confirming probes observed \
                     (`probe`): nothing was joined",
                )
                .with_effect(EffectStatus::None)
                .into_envelope(),
            );
        }
        match joined {
            Ok(joined) => {
                let mut data = serde_json::json!({
                    "environment": joined.join.environment,
                    "invitation": joined.join.invitation,
                    "client": joined.join.client,
                    "role": joined.join.role,
                    "generation": joined.join.generation,
                    "joined_at": joined.join.joined_at,
                    "replayed": joined.replayed,
                });
                // ⟨M06 W3⟩ An endpoint recorded in the join's commit reaches the serve child
                // by its replacement (U56-Q10).
                if let (Some(endpoint), false) = (&join.iroh_endpoint, joined.replayed) {
                    let report = self.reconcile_serve().await;
                    if let Some(map) = data.as_object_mut() {
                        map.insert("iroh_endpoint".to_owned(), serde_json::json!(endpoint));
                        map.insert(
                            "iroh_admission".to_owned(),
                            serde_json::to_value(report).unwrap_or_default(),
                        );
                    }
                }
                ok(data)
            }
            Err(r) => refused(r),
        }
    }

    /// The transport executor over the configured ports (`None`: not configured).
    fn transport_ops(&self) -> Option<TransportOps<'_>> {
        self.options.transport.as_ref().map(|t| TransportOps {
            store: &self.store,
            keys: t.keys.as_ref(),
            serve: t.serve.as_ref(),
            peers: t.peers.as_ref(),
        })
    }

    /// ⟨U56-Q6⟩ The exact exposure delta a transport request applies now, as the record's
    /// document; `None` for any other request, a narrowing form, or without the transport
    /// ports (then an approval leaves the record pending).
    fn exposure_of(&self, request: &Request) -> Result<Option<serde_json::Value>, OpError> {
        let (Request::Transport(t), Some(ops)) = (request, self.transport_ops()) else {
            return Ok(None);
        };
        ops.delta_of(t)?
            .map(|d| {
                serde_json::to_value(d)
                    .map_err(|_| OpError::new(Code::InternalError, "a delta cannot be recorded"))
            })
            .transpose()
    }

    /// A paired owner's widening request (§3.10 item 3): a pending runner-local record bound
    /// to its exact request (and, for an exposure widening, its exact delta), or the
    /// recorded answer of the same key.
    fn submit_widening(&self, client: &ClientId, request: &Request) -> Envelope<serde_json::Value> {
        // ⟨rev6.5; ADR-0006 §18.9 item 9⟩ A `route add`'s relay URLs are validated, and put
        // in their one spelling, before any record is made of the request.
        let normal;
        let request = match request {
            Request::Route(r) => match heimdall_app::routes::ops::normalized(r) {
                Ok(std::borrow::Cow::Borrowed(_)) => request,
                Ok(std::borrow::Cow::Owned(r)) => {
                    normal = Request::Route(r);
                    &normal
                }
                Err(e) => return value_of(e.into_envelope()),
            },
            _ => request,
        };
        let generation = match self.store.transaction(|tx| tx.authority_generation()) {
            Ok(g) => g,
            Err(_) => return refused(Refusal::State),
        };
        let exposure = match self.exposure_of(request) {
            Ok(e) => e,
            Err(e) => return value_of(e.into_envelope()),
        };
        let records = StoreWidening::new(Arc::clone(&self.store));
        match widening::submit_bound(
            &records,
            client,
            request,
            exposure,
            generation,
            self.clock.wall(),
        ) {
            Ok((_, answer)) => answer,
            Err(r) => refused(r),
        }
    }

    /// Whether this build can run an approved record now (checked before the record is
    /// claimed, so a refusal leaves it pending): an invite needs the line writer; a transport
    /// widening needs the transport ports and a recorded delta that is still exactly the one
    /// its request applies (⟨U56-Q6⟩; otherwise `decision_binding_mismatch`).
    fn executable(
        &self,
        record: &widening::WideningRecord,
    ) -> Result<(), Envelope<serde_json::Value>> {
        let unavailable = || {
            value_of(
                OpError::driver_unavailable(
                    "this runner cannot run the recorded request in this build; the record stays pending",
                )
                .with_resource("decision", Some(record.decision.to_string()))
                .into_envelope(),
            )
        };
        match &record.request {
            Request::RemoteEnvironment(RemoteEnvironmentRequest::Invite { .. }) => {
                self.invitations().map(drop).map_err(|_| unavailable())
            }
            Request::Transport(_) => {
                let Some(recorded) = &record.exposure else {
                    return Err(unavailable());
                };
                match self.exposure_of(&record.request) {
                    Ok(Some(now)) if &now == recorded => Ok(()),
                    Ok(Some(_)) => Err(refused(Refusal::BindingMismatch)),
                    Ok(None) => Err(unavailable()),
                    Err(e) => Err(value_of(e.into_envelope())),
                }
            }
            _ => Err(unavailable()),
        }
    }

    /// ⟨§3.10 item 2⟩ `Decide` on a runner-local widening record, from a session local to
    /// the runner (never a paired one: that never reaches here). `None` when the decision
    /// is not a runner-local widening record (the application decides it). Approval needs
    /// an attended session and checked time; the record must still be bound to exactly its
    /// decided request (`heimdall_remote::widening::verify_binding`) and executable now
    /// ([`Self::executable`]), else it is refused before it is claimed and stays pending;
    /// then the exact request runs once. A denial records the owner's refusal.
    pub async fn decide_local(
        &self,
        attended: bool,
        decide: &DecideRequest,
    ) -> Option<Envelope<serde_json::Value>> {
        let records = StoreWidening::new(Arc::clone(&self.store));
        let record = match records.by_decision(&decide.decision_id) {
            // ⟨M06 W5; ADR-0006 §18.9 item 8⟩ A local owner's record is not this path's: its
            // executor is on every installation (`crate::local_widening`).
            Ok(Some(r)) if !r.key.submitter.is_local() => r,
            Ok(_) => return None,
            Err(_) => return Some(refused(Refusal::State)),
        };
        if !attended {
            return Some(refused(Refusal::InteractionRequired));
        }
        let time = self.time_reading().await;
        if decide.verdict == Verdict::Approve
            && record.state == heimdall_domain::decision::DecisionState::Pending
        {
            if time.checked_wall.is_none() {
                return Some(refused(Refusal::TimeUncertain));
            }
            if let Err(r) = widening::verify_binding(&record) {
                return Some(refused(r));
            }
            if let Err(env) = self.executable(&record) {
                return Some(env);
            }
        }
        let current = match self.store.transaction(|tx| tx.authority_generation()) {
            Ok(g) => g,
            Err(_) => return Some(refused(Refusal::State)),
        };
        let now = time.checked_wall.unwrap_or_else(|| self.clock.wall());
        let policy = self.policy.current();
        let decided = widening::decide_async(
            &records,
            DecidingSession {
                remote_client: None,
                attended,
            },
            &decide.decision_id,
            decide.verdict,
            current,
            now,
            async |claimed: &widening::WideningRecord| {
                self.execute(claimed, policy, &time, now).await
            },
        )
        .await;
        Some(decided.unwrap_or_else(refused))
    }

    /// Run an approved record's exact request once (the claimed record): its binding is
    /// checked again first (a mismatch runs nothing); an invite enrolls exactly the bound key
    /// and role; a transport widening runs with exactly the recorded delta as its approval,
    /// which `TransportOps::execute` compares with the delta it reads (a different one runs
    /// nothing: `exposure_unconsented`).
    async fn execute(
        &self,
        record: &widening::WideningRecord,
        policy: ManagementPolicy,
        time: &TimeReading,
        now: Timestamp,
    ) -> Envelope<serde_json::Value> {
        if let Err(r) = widening::verify_binding(record) {
            return refused(r);
        }
        if let Some(binding) = &record.invite {
            let invited = self
                .invitations()
                .and_then(|i| i.invite_bound(binding, policy, time));
            return match invited {
                Ok(done) => ok(serde_json::json!({
                    "environment": self.environment(),
                    "invitation": done.invitation.invitation,
                    "client": done.invitation.client,
                    "role": done.invitation.role,
                    "key_fingerprint": done.invitation.key_fingerprint,
                    "generation": done.invitation.generation,
                    "expires_wall": done.invitation.expires_wall,
                    "probe_nonce": done.invitation.probe_nonce,
                })),
                Err(r) => refused(r),
            };
        }
        if let (Request::Transport(t), Some(ops), Some(recorded)) =
            (&record.request, self.transport_ops(), &record.exposure)
        {
            let Ok(delta) = serde_json::from_value::<ExposureDelta>(recorded.clone()) else {
                return refused(Refusal::BindingMismatch);
            };
            let approved = ApprovedWidening {
                decision: record.decision.clone(),
                delta,
            };
            return match ops.execute(t, Some(&approved), now).await {
                Ok(data) => ok(data),
                Err(e) => value_of(e.into_envelope()),
            };
        }
        value_of(
            OpError::driver_unavailable("no executor for this request in this build")
                .into_envelope(),
        )
    }

    /// ⟨M06 W3; ADR-0006 §18.7 item 4⟩ The session's client sets or replaces its own Iroh
    /// endpoint ID (`heimdall_remote::invitations::rotate_endpoint`: active client, consumed
    /// invitation with `iroh_admission`, an endpoint no other client holds), after the
    /// per-request role check and revocation recheck of [`Self::frame`]. A first set is
    /// insert-if-absent and reaches the serve child by its replacement (U56-Q10); a
    /// replacement moved the admission authority generation in its transaction and the
    /// serve child's admission is narrowed as for a revocation (the old endpoint's streams
    /// close). The answer reports the child's state (`iroh_admission`).
    pub async fn rotate_endpoint(
        &self,
        client: &ClientId,
        request: &Request,
    ) -> Envelope<serde_json::Value> {
        let Some(rotate) = heimdall_remote::invitations::RotateRequest::from_request(request)
        else {
            return refused(Refusal::NotAvailableRemotely);
        };
        let rotated = match heimdall_remote::invitations::rotate_endpoint(
            &self.store,
            self.environment(),
            client,
            &rotate,
            self.clock.wall(),
        ) {
            Ok(r) => r,
            Err(r) => return refused(r),
        };
        let change = match rotated.change {
            heimdall_store::ext_m06::EndpointChange::Recorded => "recorded",
            heimdall_store::ext_m06::EndpointChange::Unchanged => "unchanged",
            heimdall_store::ext_m06::EndpointChange::Replaced(_) => "replaced",
        };
        // A replacement (generation moved) narrows; a first set reaches the serve child by its
        // replacement (U56-Q10: the allowlist is fixed per child). The supervisor's one
        // reconcile does both.
        let iroh = match rotated.change {
            heimdall_store::ext_m06::EndpointChange::Unchanged => None,
            _ => Some(self.reconcile_serve().await),
        };
        let mut data = serde_json::json!({
            "environment": self.environment(),
            "client": rotated.client,
            "endpoint": rotated.endpoint,
            "change": change,
        });
        if let (Some(report), Some(map)) = (iroh, data.as_object_mut()) {
            map.insert(
                "iroh_admission".to_owned(),
                serde_json::to_value(report).unwrap_or_default(),
            );
        }
        ok(data)
    }

    /// Reconcile the serve child with durable admission state (the supervisor's one entry:
    /// a moved generation suspends the withdrawn endpoints; a new endpoint replaces the
    /// child, U56-Q10).
    async fn reconcile_serve(&self) -> AdmissionReport {
        match self.serve_control() {
            Some(serve) => serve.apply_narrowing().await,
            None => AdmissionReport::NotServing,
        }
    }

    /// The serve child's supervision, when wired (the admission port, else the transport's).
    fn serve_control(&self) -> Option<Arc<dyn ServeControl>> {
        self.options.admission.clone().or_else(|| {
            self.options
                .transport
                .as_ref()
                .map(|t| Arc::clone(&t.serve))
        })
    }

    /// ⟨M06 W3⟩ A paired controller's `runner/1` form (module docs, "Runner requests"), after
    /// the role table and the pre-dispatch rules passed it: served by the runner runtime on
    /// the blocking pool, with this connection's serial (the time challenge binds its nonce
    /// to the session). `driver_unavailable` without a runner runtime.
    pub async fn runner_request(
        &self,
        caller: &Caller,
        connection: u64,
        request: heimdall_contract::remote::RunnerRequest,
    ) -> Envelope<serde_json::Value> {
        let Some(runtime) = self.runtime.clone() else {
            return value_of(
                OpError::driver_unavailable("this runner has no runner runtime in this build")
                    .with_effect(EffectStatus::None)
                    .into_envelope(),
            );
        };
        // ⟨M06 U4⟩ Typed narrowing effects and the authority report go through this runner's
        // own narrowing machinery (`heimdall_remote::sync` over its operations).
        if crate::runner::RunnerRuntime::is_sync_request(&request) {
            let sync = heimdall_remote::sync::RunnerSync::new(
                Arc::clone(&self.store),
                self.operations.clone(),
                Arc::clone(&self.clock),
            );
            return crate::dispatch::render(
                runtime
                    .serve_sync(&sync, caller, connection, &request)
                    .await,
            );
        }
        let context = caller.context.clone();
        let handled =
            tokio::task::spawn_blocking(move || runtime.handle(&context, connection, &request))
                .await;
        match handled {
            Ok(result) => crate::dispatch::render(result),
            Err(_) => value_of(
                OpError::new(Code::InternalError, "the runner request did not complete")
                    .with_effect(EffectStatus::Unknown)
                    .into_envelope(),
            ),
        }
    }

    /// ⟨M06 W3; ADR-0006 §18.7 item 7; M08 W4 SEC-3a⟩ A runner-local decision (`issuer_trust`,
    /// the time source, owner enrollment, downgrade lift): caller identity and attendance for
    /// widening forms were enforced once before the request fence in `dispatch::pre_fence_refusal`.
    /// Source changes invalidate the runner's cached time sample and outstanding challenges.
    pub(crate) async fn runner_local(
        &self,
        request: heimdall_contract::remote::RunnerLocalRequest,
    ) -> Envelope<serde_json::Value> {
        if let heimdall_contract::remote::RunnerLocalRequest::EnrollOwner {
            client,
            public_key,
            iroh_endpoint,
            ..
        } = &request
        {
            let enrollment = OwnerEnrollment {
                client: client.clone(),
                public_key: public_key.clone(),
                iroh_endpoint: iroh_endpoint.clone(),
            };
            return self.enroll_owner(enrollment).await;
        }
        let store = Arc::clone(&self.store);
        let runtime = self.runtime.clone();
        let now = self.clock.wall();
        // ⟨§18.7 item 19⟩ The attended lift, judged on this runtime's own clock.
        let reading = ClockReading::of(self.clock.as_ref());
        let applied = tokio::task::spawn_blocking(move || {
            use heimdall_contract::remote::RunnerLocalRequest;
            let apply = || crate::runner::apply_runner_local(&store, now, &request);
            match (&request, runtime) {
                (RunnerLocalRequest::PolicyRecheck { .. }, _) => {
                    apply_downgrade_lift(&store, &reading)
                }
                (
                    RunnerLocalRequest::DesignateTimeSource { .. }
                    | RunnerLocalRequest::ClearTimeSource,
                    Some(rt),
                ) => rt.time().change_source(apply),
                _ => apply(),
            }
        })
        .await;
        match applied {
            Ok(result) => crate::dispatch::render(result),
            Err(_) => value_of(
                OpError::new(
                    Code::InternalError,
                    "the runner-local request did not complete",
                )
                .with_effect(EffectStatus::Unknown)
                .into_envelope(),
            ),
        }
    }

    /// ⟨M06-W2-R02⟩ `runner_local.enroll_owner`: `remote init` while this runtime runs. The
    /// attended local owner only (enforced before the fence in `dispatch::pre_fence_refusal`).
    /// The records commit ([`enroll_owner`]); the line is then written by the runtime's own
    /// reconciler, under the line lock and from the row as it is then (so a revocation still
    /// wins); a first endpoint reaches the serve child by its replacement (U56-Q10).
    async fn enroll_owner(&self, enrollment: OwnerEnrollment) -> Envelope<serde_json::Value> {
        let Some(command) = self.options.command.clone() else {
            return refused(Refusal::LinesUnavailable);
        };
        let store = Arc::clone(&self.store);
        let now = self.clock.wall();
        let enrolled =
            tokio::task::spawn_blocking(move || enroll_owner(&store, now, &enrollment)).await;
        let enrolled = match enrolled {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => return value_of(e.into_envelope()),
            Err(_) => {
                return value_of(
                    OpError::new(Code::InternalError, "the owner enrollment did not complete")
                        .with_effect(EffectStatus::Unknown)
                        .into_envelope(),
                );
            }
        };
        self.reconcile_lines().await;
        let line_written = self
            .row(&enrolled.owner.client)
            .ok()
            .flatten()
            .is_some_and(|r| r.line == AppliedLine::Active);
        if enrolled.endpoint == Some(OwnerEndpoint::Recorded) {
            let _ = self.reconcile_serve().await;
        }
        ok(enrolled.data(enrolled.line(&command).as_deref(), line_written))
    }

    /// ⟨§18.7 item 19⟩ Whether the runner's effective sshd policy verifies **now**: the
    /// port when one was given, else the start check run again ([`runner_lines`]) with the
    /// options' check or, for a runner whose start check verified without one, the
    /// account's. A runner with no check to run does not verify.
    async fn sshd_verifies_now(&self) -> bool {
        if let Some(port) = &self.sshd_recheck {
            return port();
        }
        let sshd = self.options.sshd.clone().or_else(|| {
            let command = self.options.command.as_ref()?;
            (self.policy.checked() == ManagementPolicy::Verified)
                .then(|| {
                    RunnerSshd::account(&crate::Paths::under(Path::new(command.home())).state_dir)
                })
                .flatten()
        });
        let Some(sshd) = sshd else {
            return false;
        };
        let user_dir = sshd.home.join(".ssh");
        runner_lines(Some(&sshd), &user_dir).await.1 == ManagementPolicy::Verified
    }

    /// ⟨ADR-0006 §18.7 item 19⟩ An owner controller's recheck
    /// (`remote_environment.runner_policy_recheck`), after the per-request role check of
    /// [`Self::frame`] (owner only): `client` is the session's own. The observation is
    /// recorded as evidence, for the downgrade's epoch read before the checks, only when
    /// the runner's own `sshd -T` check verifies now **and** the observation agrees. It
    /// lifts nothing ([`lift_downgrade`] does, attended, at the runner).
    ///
    /// A disagreeing observation is `management_sshd_unsupported` and a downgrade event
    /// (evidence recorded before it lifts nothing; a runner that was verified is lowered); a
    /// check that does not verify is `management_sshd_unverified`. A runner with no
    /// downgrade records no evidence.
    pub async fn policy_recheck(
        &self,
        client: &ClientId,
        environment: &EnvironmentId,
        probe: &ProbeObservation,
    ) -> Envelope<serde_json::Value> {
        if environment != self.environment() {
            return value_of(
                OpError::new(Code::NotFound, "unknown environment")
                    .with_resource("environment", None)
                    .with_effect(EffectStatus::None)
                    .into_envelope(),
            );
        }
        // ⟨M06-W3-R03⟩ A pending marker is recorded first, so the evidence below is for the
        // epoch that includes it (and never for one a marker is about to move).
        self.policy.drain_pending(self.clock.wall());
        let standing = match self.store.transaction(|tx| tx.runner_downgrade()) {
            Ok(d) => d,
            Err(_) => return refused(Refusal::State),
        };
        let refusal = |r: Refusal, why: &str| {
            let mut e = r.to_op_error();
            e.message = format!("{why}: nothing was recorded and the runner is owner-only");
            value_of(e.into_envelope())
        };
        // A fresh observation of an unrestricted session is a downgrade event whenever it
        // contradicts something: a standing downgrade's epoch moves, and a runner whose
        // policy is verified now is lowered (as an owner's disagreeing join lowers it).
        if RunnerPolicy::observation_agrees(client, probe).is_err() {
            if standing.is_some() || self.policy.current() == ManagementPolicy::Verified {
                self.policy.lower(OwnerOnlyCause::Probe, self.clock.wall());
            }
            return refusal(
                Refusal::ManagementSshdUnsupported,
                "the probes show this management session is not restricted as the sshd \
                 policy claims",
            );
        }
        let Some(standing) = standing else {
            return ok(serde_json::json!({
                "environment": self.environment(),
                "downgraded": false,
                "recorded": false,
                "management_policy": self.policy.current(),
            }));
        };
        if !self.sshd_verifies_now().await {
            return refusal(
                Refusal::ManagementSshdUnverified,
                "this runner's effective sshd policy does not verify now (`sshd -T`); \
                 correct it, restart the runner's runtime, then recheck",
            );
        }
        let evidence = heimdall_store::ext_runner::PolicyRecheckEvidence {
            controller: client.clone(),
            epoch: standing.epoch,
            recorded_at: self.clock.wall(),
            boot_id: self.clock.boot_id().0,
            continuous_ms: self
                .clock
                .try_continuous()
                .and_then(|d| u64::try_from(d.as_millis()).ok()),
            probe: *probe,
        };
        match self
            .store
            .transaction(|tx| tx.record_policy_recheck(&evidence))
        {
            Ok(true) => ok(serde_json::json!({
                "environment": self.environment(),
                "downgraded": true,
                "recorded": true,
                "cause": standing.cause,
                "epoch": evidence.epoch,
                "controller": evidence.controller,
                "recorded_at": evidence.recorded_at,
                "valid_for_seconds": RECHECK_EVIDENCE_MAX_AGE.as_secs(),
            })),
            // The downgrade moved while the checks ran: this observation is from before it.
            Ok(false) => refusal(
                Refusal::ManagementSshdUnverified,
                "the runner was downgraded again while the recheck ran",
            ),
            Err(_) => refused(Refusal::State),
        }
    }

    /// Revoke a client on this runner (ADR-0012 §3.11; narrowing, no decision), in the
    /// ADR's order: (1) the tombstone, the admission authority (it also moves the admission
    /// generation), and every session of the client ends ([`Self::session_end`]); (2) Iroh
    /// admission closed through the serve child's supervision (suspend, close streams,
    /// acknowledge or kill, then report: `iroh_admission`); (3) the line removed (or left to
    /// the reconciler when no writer is wired); then the `client.revoked` event.
    pub async fn revoke_client(
        &self,
        environment: &EnvironmentId,
        client: &ClientId,
    ) -> Envelope<serde_json::Value> {
        if environment != self.environment() {
            return value_of(
                OpError::new(Code::NotFound, "unknown environment")
                    .with_resource("environment", None)
                    .with_effect(EffectStatus::None)
                    .into_envelope(),
            );
        }
        let now = self.clock.wall();
        let tomb = self
            .store
            .transaction(|tx| {
                if tx.remote_client(client)?.is_none() {
                    return Ok(None);
                }
                tx.revoke_remote_client(client, RevocationCause::Revoked, now)
                    .map(Some)
            })
            .map_err(|_| Refusal::State)
            .and_then(|r| r.ok_or(Refusal::ClientRevoked));
        let tomb = match tomb {
            Ok(t) => t,
            Err(r) => return refused(r),
        };
        // ⟨M08 W4 SEC-3a, S2-02⟩ Forget any cached time sample from the revoked client at once.
        if let Some(rt) = &self.runtime {
            rt.time().invalidate_client(client);
        }
        self.revocations.send_modify(|n| *n = n.wrapping_add(1));
        let iroh = match self.serve_control() {
            Some(serve) => serve.apply_narrowing().await,
            None => AdmissionReport::NotServing,
        };
        // Idempotent on the tombstone (already revoked: nothing moves); it removes the line.
        let line_removed = self
            .invitations()
            .and_then(|i| i.revoke(client, now))
            .is_ok_and(|r| r.line_removed);
        let payload = ClientEventPayload {
            kind: ClientEventKind::Revoked,
            environment: self.environment().clone(),
            client: client.clone(),
            role: Some(tomb.role),
        };
        // The tombstone is committed: a lost event costs only the report.
        let _ = self.operations.events().publish(
            EventType::Client,
            None,
            serde_json::to_value(payload).unwrap_or_default(),
        );
        ok(serde_json::json!({
            "environment": self.environment(),
            "client": client,
            "state": "revoked",
            "iroh_admission": iroh,
            "line_removed": line_removed,
        }))
    }

    /// Bring every client's line in line with the role table (the invitation service's
    /// idempotent reconciler, after tombstoning invitations that definitely expired); run at
    /// the runtime's start. Without a line writer it does nothing.
    pub async fn reconcile_lines(&self) {
        let now = self.time_reading().await;
        if let Ok(i) = self.invitations() {
            if let Ok(expired) = i.expire_due(&now)
                && !expired.is_empty()
            {
                self.revocations.send_modify(|n| *n = n.wrapping_add(1));
            }
            if let Ok(report) = i.reconcile(&now)
                && report.failed > 0
            {
                tracing::warn!(
                    failed = report.failed,
                    "a management line could not be reconciled"
                );
            }
        }
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const RESTRICTED: &str = "AuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n\
                              PermitUserEnvironment no\nAcceptEnv LANG LC_*\n\
                              AuthenticationMethods any\nPubkeyAuthentication yes\n";

    /// ⟨M06-W2-R02; ADR-0012 §3.2⟩ The runner's files and management policy come from its
    /// effective sshd policy, through the real `sshd -T` over a fixture configuration (no
    /// daemon, nothing listens): a verified **non-default** policy (one keys file instead of
    /// sshd's default pair) gives exactly that file and `verified`; a policy that is not
    /// verified (an `AuthorizedKeysCommand`), a check that cannot run, and no check at all
    /// give sshd's default pair and `owner_only`.
    #[tokio::test]
    async fn the_runners_files_and_policy_follow_its_effective_sshd_policy() {
        let scratch = tempfile::tempdir().unwrap();
        let home = scratch.path().join("home");
        let user_dir = home.join(".ssh");
        std::fs::create_dir_all(&user_dir).unwrap();
        let default_pair = crate::paired_lines::AuthorizedKeysFiles::sshd_default(&user_dir);
        let owner_only = (default_pair.clone(), ManagementPolicy::OwnerOnly);
        assert_eq!(runner_lines(None, &user_dir).await, owner_only);
        let check = |config: Option<&str>, sshd: &str| {
            let path = scratch.path().join("sshd_config");
            if let Some(text) = config {
                std::fs::write(&path, text).unwrap();
            }
            RunnerSshd {
                sshd: PathBuf::from(sshd),
                config: Some(path),
                user: "hmfixture".to_owned(),
                home: home.clone(),
                login_shell: Some("/bin/sh".to_owned()),
                scratch_parent: scratch.path().to_owned(),
                timeout: sshd_policy::DEFAULT_TIMEOUT,
            }
        };
        // A check that cannot run (no such sshd): fail closed.
        let missing = check(None, "/nonexistent/hm-sshd");
        assert_eq!(runner_lines(Some(&missing), &user_dir).await, owner_only);
        if !Path::new(sshd_policy::DEFAULT_SSHD).exists() {
            #[allow(clippy::print_stderr)] // the skipped row's reason
            {
                eprintln!(
                    "skipped: {} is absent on this host",
                    sshd_policy::DEFAULT_SSHD
                );
            }
            return;
        }
        let single = check(
            Some(&format!(
                "AuthorizedKeysFile .ssh/authorized_keys\n{RESTRICTED}"
            )),
            sshd_policy::DEFAULT_SSHD,
        );
        let (files, policy) = runner_lines(Some(&single), &user_dir).await;
        assert_eq!(policy, ManagementPolicy::Verified);
        assert_eq!(files.files(), [user_dir.join("authorized_keys")]);
        assert_ne!(files, default_pair);
        // The verified list is for the account's own `~/.ssh`: another directory's writer
        // does not take it.
        let elsewhere = scratch.path().join("elsewhere");
        assert_eq!(
            runner_lines(Some(&single), &elsewhere).await.1,
            ManagementPolicy::OwnerOnly
        );
        let command = check(
            Some(&format!(
                "AuthorizedKeysFile .ssh/authorized_keys\n{}",
                RESTRICTED.replace(
                    "AuthorizedKeysCommand none",
                    "AuthorizedKeysCommand /usr/bin/false\nAuthorizedKeysCommandUser nobody"
                )
            )),
            sshd_policy::DEFAULT_SSHD,
        );
        assert_eq!(runner_lines(Some(&command), &user_dir).await, owner_only);
        // Nothing of the check is left behind.
        let left: Vec<_> = std::fs::read_dir(scratch.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with("hm-sshd-policy-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// ⟨ADR-0012 §3.2 "Limits", ⟨2026-11-21⟩⟩ A confirming probe that shows the session is not
    /// restricted as the verified policy claimed (here: a PTY was granted) fails closed
    /// (`management_sshd_unsupported`) and leaves the runner owner-only with the policy
    /// unverifiable: limited roles are refused from then on, and a later agreeing probe does
    /// not raise it again. An agreeing probe never establishes a policy the check did not.
    #[test]
    fn a_disagreeing_probe_downgrades_the_runner_to_owner_only() {
        use heimdall_contract::remote::Role;
        let user_dir = Path::new("/nonexistent/hm-fixture/.ssh");
        let client = ClientId::from_random_bytes([5; 16]);
        let agrees = sshd_policy::ProbeReport {
            echoed_client: Some(client.clone()),
            echoed_nonce: Some("n-1".to_owned()),
            pty_refused: true,
            forward_refused: true,
            agent_forward_refused: true,
            setenv_canary_delivered: false,
        };
        // No check (as `runner_lines` answers it): owner-only, and a probe cannot raise it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let unchecked = RunnerPolicy::new(rt.block_on(runner_lines(None, user_dir)).1);
        assert_eq!(unchecked.confirm(&client, "n-1", &agrees), Ok(()));
        assert_eq!(unchecked.current(), ManagementPolicy::OwnerOnly);
        // A verified policy: confirmed, then contradicted on the real connection.
        let policy = RunnerPolicy::new(ManagementPolicy::Verified);
        assert_eq!(policy.confirm(&client, "n-1", &agrees), Ok(()));
        assert_eq!(policy.current(), ManagementPolicy::Verified);
        assert!(sshd_policy::limited_role_gate(Role::Viewer, policy.current()).is_ok());
        let unrestricted = sshd_policy::ProbeReport {
            pty_refused: false,
            ..agrees.clone()
        };
        assert_eq!(
            policy.confirm(&client, "n-1", &unrestricted),
            Err(Refusal::ManagementSshdUnsupported)
        );
        assert!(policy.unverifiable());
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(policy.confirm(&client, "n-1", &agrees), Ok(()));
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
        for role in [Role::Requester, Role::Viewer] {
            assert_eq!(
                sshd_policy::limited_role_gate(role, policy.current()),
                Err(Refusal::ManagementSshdUnverified)
            );
        }
        assert!(sshd_policy::limited_role_gate(Role::Owner, policy.current()).is_ok());
    }

    fn memory_store() -> Arc<Store> {
        Arc::new(Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap())
    }

    const AGREES: ProbeObservation = ProbeObservation {
        pty_refused: true,
        forward_refused: true,
        agent_forward_refused: true,
        setenv_canary_delivered: false,
    };

    /// ⟨ADR-0006 §18.7 items 16–18⟩ The owner-only downgrade is a row of the runner's store,
    /// durable and one-way: a disagreeing observation writes it; a row another connection
    /// wrote (the bridge) lowers a running runner without a restart; a new policy over the
    /// same store starts owner-only whatever its start check says; a row that cannot be read
    /// is a downgrade too. The join check: an owner is exempt, a limited role needs a
    /// verified policy, an observation and their agreement.
    #[test]
    fn the_owner_only_downgrade_is_durable_and_the_join_check_reads_it() {
        use heimdall_contract::remote::Role;
        let client = ClientId::from_random_bytes([6; 16]);
        let agrees = AGREES;
        let now: Timestamp = "2026-11-21T09:00:00Z".parse().unwrap();
        let store = memory_store();
        let verified = || RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
        let policy = verified();
        assert_eq!(recorded_owner_only(&store), None);
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&agrees)),
            Ok(())
        );
        assert_eq!(
            policy.check_join(&client, Role::Requester, None),
            Err(Refusal::InvalidRequest)
        );
        assert_eq!(policy.check_join(&client, Role::Owner, None), Ok(()));
        assert_eq!(policy.current(), ManagementPolicy::Verified);
        // Each of the four behaviours disagrees on its own.
        for disagrees in [
            ProbeObservation {
                pty_refused: false,
                ..agrees
            },
            ProbeObservation {
                forward_refused: false,
                ..agrees
            },
            ProbeObservation {
                agent_forward_refused: false,
                ..agrees
            },
            ProbeObservation {
                setenv_canary_delivered: true,
                ..agrees
            },
        ] {
            let fresh = RunnerPolicy::new(ManagementPolicy::Verified);
            assert_eq!(
                fresh.check_join(&client, Role::Viewer, Some(&disagrees)),
                Err(Refusal::ManagementSshdUnsupported)
            );
            assert_eq!(fresh.current(), ManagementPolicy::OwnerOnly);
        }
        let disagrees = ProbeObservation {
            forward_refused: false,
            ..agrees
        };
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&disagrees)),
            Err(Refusal::ManagementSshdUnsupported)
        );
        assert_eq!(recorded_owner_only(&store), Some(OwnerOnlyCause::Probe));
        // Sticky: an agreeing limited join is refused from then on; an owner's is not.
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&agrees)),
            Err(Refusal::ManagementSshdUnverified)
        );
        assert_eq!(
            policy.check_join(&client, Role::Owner, Some(&agrees)),
            Ok(())
        );
        // Durable: the next start over the same store is owner-only though its start check
        // verified; the first cause stands and a later event moves the epoch.
        let later = record_owner_only(&store, OwnerOnlyCause::SessionPty, now).unwrap();
        assert_eq!((later.cause.as_str(), later.epoch), ("probe_disagreed", 2));
        assert_eq!(verified().current(), ManagementPolicy::OwnerOnly);

        // Another writer's row reaches a running runner; an owner's disagreeing observation
        // lowers the runner and is not refused.
        let other = memory_store();
        let running = RunnerPolicy::with_store(ManagementPolicy::Verified, other.clone());
        assert_eq!(running.current(), ManagementPolicy::Verified);
        record_owner_only(&other, OwnerOnlyCause::SessionAgent, now).unwrap();
        assert_eq!(running.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(
            recorded_owner_only(&other),
            Some(OwnerOnlyCause::SessionAgent)
        );
        let third = memory_store();
        let owner_seen = RunnerPolicy::with_store(ManagementPolicy::Verified, third.clone());
        assert_eq!(
            owner_seen.check_join(&client, Role::Owner, Some(&disagrees)),
            Ok(())
        );
        assert_eq!(owner_seen.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(recorded_owner_only(&third), Some(OwnerOnlyCause::Probe));
        // An unknown token is still a downgrade.
        assert_eq!(
            OwnerOnlyCause::of_token("other"),
            OwnerOnlyCause::Unreadable
        );
    }

    /// ⟨ADR-0006 §18.7 item 19⟩ The evidence's age: at most 15 minutes by the wall clock
    /// and, where both readings have one, by the continuous clock of the same boot. Another
    /// boot, a clock that went backwards, a continuous clock at only one reading, evidence
    /// of another epoch and no evidence all refuse.
    #[test]
    fn recheck_evidence_is_judged_by_epoch_and_by_both_clocks() {
        use heimdall_store::ext_runner::{PolicyRecheckEvidence, RunnerDowngrade};
        let t = |s: &str| -> Timestamp { s.parse().unwrap() };
        let downgrade = RunnerDowngrade {
            cause: "session_pty".to_owned(),
            epoch: 3,
            recorded_at: t("2026-11-21T08:00:00Z"),
            last_event_at: t("2026-11-21T08:30:00Z"),
        };
        let evidence = PolicyRecheckEvidence {
            controller: ClientId::from_random_bytes([7; 16]),
            epoch: 3,
            recorded_at: t("2026-11-21T09:00:00Z"),
            boot_id: "boot-a".to_owned(),
            continuous_ms: Some(1_000_000),
            probe: AGREES,
        };
        let at = |wall: &str, boot: &str, continuous_s: Option<u64>| ClockReading {
            wall: t(wall),
            boot_id: boot.to_owned(),
            continuous: continuous_s.map(Duration::from_secs),
        };
        let judge = |e: Option<&PolicyRecheckEvidence>, now: &ClockReading| {
            judge_evidence(&downgrade, e, now)
        };
        let fresh = at("2026-11-21T09:15:00Z", "boot-a", Some(1_000 + 900));
        assert_eq!(judge(Some(&evidence), &fresh), Ok(()));
        assert_eq!(judge(None, &fresh), Err(LiftRefusal::NoEvidence));
        let earlier_epoch = PolicyRecheckEvidence {
            epoch: 2,
            ..evidence.clone()
        };
        assert_eq!(
            judge(Some(&earlier_epoch), &fresh),
            Err(LiftRefusal::BeforeLaterDowngrade)
        );
        for (now, why) in [
            // One second past the bound, on either clock alone.
            (
                at("2026-11-21T09:15:01Z", "boot-a", Some(1_900)),
                LiftRefusal::Stale,
            ),
            (
                at("2026-11-21T09:15:00Z", "boot-a", Some(1_901)),
                LiftRefusal::Stale,
            ),
            // A wall clock stepped back hides nothing: the continuous clock still counts.
            (
                at("2026-11-21T09:01:00Z", "boot-a", Some(5_000)),
                LiftRefusal::Stale,
            ),
            (
                at("2026-11-21T08:59:59Z", "boot-a", Some(1_010)),
                LiftRefusal::AgeUncertain,
            ),
            (
                at("2026-11-21T09:05:00Z", "boot-a", Some(999)),
                LiftRefusal::AgeUncertain,
            ),
            (
                at("2026-11-21T09:05:00Z", "boot-b", Some(1_300)),
                LiftRefusal::AgeUncertain,
            ),
            (
                at("2026-11-21T09:05:00Z", "boot-a", None),
                LiftRefusal::AgeUncertain,
            ),
        ] {
            assert_eq!(judge(Some(&evidence), &now), Err(why), "{now:?}");
        }
        // No continuous clock at either reading: the wall clock alone.
        let wall_only = PolicyRecheckEvidence {
            continuous_ms: None,
            ..evidence.clone()
        };
        assert_eq!(
            judge(
                Some(&wall_only),
                &at("2026-11-21T09:10:00Z", "boot-a", None)
            ),
            Ok(())
        );
        assert_eq!(
            judge(
                Some(&wall_only),
                &at("2026-11-21T09:16:00Z", "boot-a", None)
            ),
            Err(LiftRefusal::Stale)
        );
    }

    /// A scratch home in the bridge's layout: its state database and its log directory.
    fn scratch_home() -> (tempfile::TempDir, Arc<Store>, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        // The database reports its real path; the marker directory is found from it.
        let home = dir.path().canonicalize().unwrap();
        let paths = crate::Paths::under(&home);
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        let store = Arc::new(
            Store::open(
                &state_db_of_home(&home).unwrap(),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap(),
        );
        (dir, store, paths.log_dir)
    }

    fn standing(store: &Store) -> Option<(String, u64)> {
        store
            .transaction(|tx| tx.runner_downgrade())
            .unwrap()
            .map(|d| (d.cause, d.epoch))
    }

    /// ⟨ADR-0012 §3.2 "How the downgrade is kept"⟩ The bridge's marker is a pending write
    /// that fails closed. While it exists a verified runner is owner-only before any row
    /// exists (inside a join's transaction too); the next limited-role admission is
    /// refused, records the row with the marker's cause and removes the marker; the
    /// runner stays owner-only after the removal (the row stands), across a restart. A
    /// marker left by a runtime that stopped while recording it counts the same, and a
    /// start records it. When the row cannot be written the marker stays.
    #[test]
    fn a_pending_downgrade_marker_lowers_the_runner_until_the_row_is_recorded() {
        use heimdall_contract::remote::Role;
        let (_dir, store, log_dir) = scratch_home();
        let at: Timestamp = "2026-11-21T09:00:00Z".parse().unwrap();
        let client = ClientId::from_random_bytes([5; 16]);
        let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
        assert_eq!(policy.markers.as_deref(), Some(log_dir.as_path()));
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&AGREES)),
            Ok(())
        );

        // The bridge creates the directory owner-only and queues the event.
        note_unrecorded_downgrade(&log_dir, OwnerOnlyCause::SessionPty, at).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&log_dir), 0o700);
            assert_eq!(mode(&log_dir.join(UNRECORDED_DOWNGRADE_LOG)), 0o600);
        }
        let marker = log_dir.join(UNRECORDED_DOWNGRADE_LOG);
        let aside = log_dir.join(UNRECORDED_DOWNGRADE_DRAINING);
        assert_eq!(standing(&store), None);
        // Inside a transaction: lowered by the marker alone, nothing written or removed.
        let judged = store
            .transaction(|tx| policy.check_join_in(tx, &client, Role::Viewer, Some(&AGREES), at))
            .unwrap();
        assert_eq!(judged, (Err(Refusal::ManagementSshdUnverified), false));
        assert!(marker.exists() && standing(&store).is_none());

        // The next limited-role admission: refused, the row recorded, the marker gone.
        assert_eq!(
            policy.check_join(&client, Role::Viewer, Some(&AGREES)),
            Err(Refusal::ManagementSshdUnverified)
        );
        assert_eq!(standing(&store), Some(("session_pty".to_owned(), 1)));
        assert!(
            !marker.exists() && !aside.exists(),
            "the marker was not removed"
        );
        // Its removal lifts nothing, here or after a restart; nor is it recorded twice.
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
        let restarted = RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
        restarted.drain_pending(at);
        assert_eq!(restarted.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(standing(&store), Some(("session_pty".to_owned(), 1)));

        // A marker set aside by a runtime that stopped before recording it: still pending,
        // and the start's drain records it (a later event: the epoch moves).
        std::fs::write(&aside, "session_agent_forwarded 2026-11-21T09:01:00Z\n").unwrap();
        assert_eq!(
            unrecorded_downgrade(&log_dir).map(|n| n.cause),
            Some(OwnerOnlyCause::SessionAgent)
        );
        restarted.drain_pending(at);
        assert_eq!(standing(&store), Some(("session_pty".to_owned(), 2)));
        assert!(!aside.exists());

        // The row cannot be written: owner-only all the same, and the marker stays queued.
        let (_dir2, store2, log2) = scratch_home();
        note_unrecorded_downgrade(&log2, OwnerOnlyCause::SessionAgent, at).unwrap();
        let read_only = Arc::new(
            Store::open_read_only(
                &store2.database_path().unwrap(),
                Arc::new(heimdall_store::NoFaults),
            )
            .unwrap(),
        );
        let failing = RunnerPolicy::with_store(ManagementPolicy::Verified, read_only);
        assert_eq!(failing.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(standing(&store2), None);
        assert_eq!(
            unrecorded_downgrade(&log2).map(|n| n.cause),
            Some(OwnerOnlyCause::SessionAgent)
        );
    }

    /// ⟨M06-W3-R03⟩ The attended lift records a pending marker before it judges anything:
    /// evidence from before the marker's event lifts nothing (never `lifted: true` while a
    /// marker would lower the runner again), the marker's row stands, and fresh evidence for
    /// that row's epoch then lifts for good.
    #[test]
    fn a_pending_marker_is_recorded_before_a_lift_and_never_lifted_over() {
        use heimdall_store::ext_runner::PolicyRecheckEvidence;
        let (_dir, store, log_dir) = scratch_home();
        init_runner(&store).unwrap();
        let at: Timestamp = "2026-11-21T09:00:00Z".parse().unwrap();
        let owner = ClientId::from_random_bytes([6; 16]);
        let record = RemoteClientRecord {
            client: owner.clone(),
            role: heimdall_contract::remote::Role::Owner,
            key_fingerprint: heimdall_contract::ids::KeyFingerprint::parse(&format!(
                "SHA256:{}",
                "L".repeat(43)
            ))
            .unwrap(),
            public_key: "ssh-ed25519 AAAA".into(),
            state: ClientState::Active,
            invitation: None,
            revoked_generation: None,
            revocation: None,
            created_at: at,
            updated_at: at,
            line: AppliedLine::Absent,
        };
        store
            .transaction(|tx| tx.enroll_bootstrap_owner(&record, at).map(drop))
            .unwrap();
        let now = ClockReading {
            wall: at,
            boot_id: "boot-a".into(),
            continuous: Some(Duration::from_secs(1)),
        };
        let recheck = |epoch: u64| {
            let evidence = PolicyRecheckEvidence {
                controller: owner.clone(),
                epoch,
                recorded_at: at,
                boot_id: "boot-a".into(),
                continuous_ms: Some(1_000),
                probe: AGREES,
            };
            store
                .transaction(|tx| tx.record_policy_recheck(&evidence))
                .unwrap()
        };
        record_owner_only(&store, OwnerOnlyCause::Probe, at).unwrap();
        assert!(recheck(1), "evidence that would lift epoch 1");

        // The bridge queues an event it could not record.
        note_unrecorded_downgrade(&log_dir, OwnerOnlyCause::SessionPty, at).unwrap();
        let refused = lift_downgrade(&store, &now, true).unwrap_err();
        assert_eq!(
            refused.reason.as_deref(),
            Some(heimdall_contract::envelope::reason::MANAGEMENT_SSHD_UNVERIFIED)
        );
        // The standing row keeps its first cause; the marker's event moved its epoch.
        assert_eq!(standing(&store).map(|(_, epoch)| epoch), Some(2));
        assert!(
            unrecorded_downgrade(&log_dir).is_none(),
            "the marker is recorded"
        );
        assert_eq!(
            RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone()).current(),
            ManagementPolicy::OwnerOnly
        );

        // Fresh evidence for the marker's epoch: lifted, and nothing lowers it again.
        assert!(recheck(2));
        let lifted = lift_downgrade(&store, &now, true).unwrap();
        assert_eq!(lifted.data["lifted"], true);
        assert_eq!(standing(&store), None);
        assert_eq!(
            RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone()).current(),
            ManagementPolicy::Verified
        );
    }

    /// A marker or marker directory that is a link is refused. The bridge writes through
    /// neither. The runtime reads through neither and fails closed: a linked marker is a
    /// pending event (recorded, the link itself removed, its target untouched); a linked
    /// directory, or one open to other accounts, is one too, and since nothing in it is
    /// touched the process stays owner-only with the row recorded once.
    #[cfg(unix)]
    #[test]
    fn a_linked_marker_or_marker_directory_is_refused_and_fails_closed() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let at: Timestamp = "2026-11-21T09:00:00Z".parse().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let target = elsewhere.path().join("target");
        std::fs::write(&target, "kept").unwrap();

        // The marker is a link.
        let (_dir, store, log_dir) = scratch_home();
        std::fs::create_dir(&log_dir).unwrap();
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = log_dir.join(UNRECORDED_DOWNGRADE_LOG);
        symlink(&target, &marker).unwrap();
        assert!(note_unrecorded_downgrade(&log_dir, OwnerOnlyCause::SessionPty, at).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");
        let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
        assert_eq!(standing(&store), Some(("unreadable".to_owned(), 1)));
        assert!(
            std::fs::symlink_metadata(&marker).is_err(),
            "the link stayed"
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept");

        // The directory is a link, then a directory other accounts can write.
        for linked in [true, false] {
            let (_dir, store, log_dir) = scratch_home();
            if linked {
                symlink(elsewhere.path(), &log_dir).unwrap();
            } else {
                std::fs::create_dir(&log_dir).unwrap();
                std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
            }
            assert!(
                note_unrecorded_downgrade(&log_dir, OwnerOnlyCause::SessionPty, at).is_err(),
                "linked: {linked}"
            );
            assert!(!elsewhere.path().join(UNRECORDED_DOWNGRADE_LOG).exists());
            assert!(!log_dir.join(UNRECORDED_DOWNGRADE_LOG).exists());
            let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, store.clone());
            for _ in 0..3 {
                assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
            }
            assert_eq!(standing(&store), Some(("unreadable".to_owned(), 1)));
        }
    }
}

/// ⟨review W3-R01⟩ The bridge's write against a concurrent adoption (ADR-0012 §3.2 "How the
/// downgrade is kept"; ADR-0014 §3.6 adoption). Outside the Unix-only module above, so it
/// runs on every platform.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod adoption_window_tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use heimdall_store::layout::{self, Began, Located, Opened};
    use heimdall_store::{FaultAction, FaultHook, FaultPoint, NoFaults, StoreError};

    use super::*;

    /// The family's data files as they are on disk: the database, its write-ahead log and
    /// its rollback journal, where they exist. The log's index (`-shm`) is shared memory that
    /// every reader updates, not data, so it is not compared.
    fn family_bytes(db: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for suffix in ["", "-wal", "-journal"] {
            let mut name = db.as_os_str().to_owned();
            name.push(suffix);
            if let Ok(bytes) = std::fs::read(PathBuf::from(name)) {
                out.insert(suffix.to_owned(), bytes);
            }
        }
        out
    }

    /// The hook of the bridge's store. At `BeforeTransaction` (the bridge has opened the
    /// database and checked its schema; its `BEGIN IMMEDIATE` has not begun) the runtime's
    /// start adopts the home's flat store through its own open and the production file
    /// system (`crate::state_store::open_locked`): intent, fence, copy, publication,
    /// completion. The hook keeps the served store and the flat family's bytes as the
    /// adoption left them.
    struct AdoptionInTheWindow {
        state_dir: PathBuf,
        flat: PathBuf,
        now: Timestamp,
        adopted: Mutex<Option<Opened>>,
        fenced: Mutex<Option<BTreeMap<String, Vec<u8>>>>,
    }

    impl FaultHook for AdoptionInTheWindow {
        fn at(&self, point: FaultPoint) -> FaultAction {
            let mut adopted = self.adopted.lock().unwrap();
            if point == FaultPoint::BeforeTransaction && adopted.is_none() {
                let opened =
                    crate::state_store::open_locked(&self.state_dir, Arc::new(NoFaults), self.now)
                        .unwrap_or_else(|e| panic!("the adoption: {e}"));
                *self.fenced.lock().unwrap() = Some(family_bytes(&self.flat));
                *adopted = Some(opened);
            }
            FaultAction::Continue
        }
    }

    fn downgrade(store: &Store) -> Option<(String, u64)> {
        store
            .transaction(|tx| tx.runner_downgrade())
            .unwrap()
            .map(|d| (d.cause, d.epoch))
    }

    /// ⟨review W3-R01⟩ The runtime's start adopts the flat store of a runner home (from a
    /// build before generations) between the bridge's open and schema check and its
    /// transaction. The store's fault hook runs the adoption there.
    /// - **The write is refused.** The bridge's `BEGIN IMMEDIATE` transaction reads the
    ///   schema again and finds the fence (`AdoptionFenced`).
    /// - **The marker is queued.** The caller's one fallback for a write that fails
    ///   (`m06_cmd::refuse_session`; its rule is tested there, by
    ///   `a_downgrade_the_bridge_cannot_write_is_queued_and_the_next_admission_records_it`)
    ///   is made here as it makes it: `note_unrecorded_downgrade` in the home's log
    ///   directory.
    /// - **The fenced flat family is byte-identical** to what the adoption left. A reader
    ///   of it stays open throughout, as a runtime's connection would, so closing the
    ///   bridge's connection checkpoints nothing into it.
    /// - **The served generation carries the downgrade once the marker is applied**, as the
    ///   design says. The runner's policy over the served store finds the marker from that
    ///   generation's database (`marker_dir_of_db`). Until the marker is applied, it alone
    ///   keeps the runner owner-only (`RunnerPolicy::marker_pending`). The runtime applies it
    ///   at start (`PairedRunner::new`) and at each limited-role admission
    ///   (`RunnerPolicy::drain_pending`). The row then stands in the served generation, the
    ///   marker is gone, and the runner stays owner-only, after a restart too.
    #[test]
    fn a_bridge_write_after_the_adoption_fence_is_refused_and_reaches_the_served_generation_by_the_marker()
     {
        let at: Timestamp = "2026-11-25T09:00:00Z".parse().unwrap();
        let cause = OwnerOnlyCause::SessionPty;
        let dir = tempfile::tempdir().unwrap();
        // The database reports its real path; the marker directory is found from it.
        let home = dir.path().canonicalize().unwrap();
        let paths = crate::Paths::under(&home);
        paths.ensure().unwrap();
        let flat = paths.state_dir.join(layout::DB_FILE);
        init_runner(&Store::open(&flat, Arc::new(NoFaults)).unwrap()).unwrap();
        // No pointer yet: the bridge resolves the flat family (`record_owner_only_in_home`).
        assert_eq!(state_db_of_home(&home).unwrap(), flat);
        let reader = Store::open_read_only(&flat, Arc::new(NoFaults)).unwrap();
        let hook = Arc::new(AdoptionInTheWindow {
            state_dir: paths.state_dir.clone(),
            flat: flat.clone(),
            now: at,
            adopted: Mutex::new(None),
            fenced: Mutex::new(None),
        });

        // `record_owner_only_in_home`'s write, with the hook.
        let recorded = heimdall_store::ext_runner::bridge_record_runner_downgrade_with_faults(
            &state_db_of_home(&home).unwrap(),
            cause.token(),
            at,
            hook.clone(),
        );
        let opened = hook
            .adopted
            .lock()
            .unwrap()
            .take()
            .expect("the adoption ran in the window");
        assert!(
            matches!(opened.began, Began::Adopted { .. }),
            "{:?}",
            opened.began
        );
        assert!(matches!(
            layout::locate(&paths.state_dir).unwrap(),
            Located::Generation { .. }
        ));
        assert_eq!(layout::db_path(&paths.state_dir).unwrap(), opened.db);
        assert!(
            matches!(recorded, Err(StoreError::AdoptionFenced)),
            "the bridge's write was not refused: {recorded:?}"
        );
        let fenced = hook.fenced.lock().unwrap().take().unwrap();
        assert!(fenced.contains_key(""), "{:?}", fenced.keys());
        let after = family_bytes(&flat);
        let sizes = |f: &BTreeMap<String, Vec<u8>>| -> Vec<(String, usize)> {
            f.iter().map(|(k, v)| (k.clone(), v.len())).collect()
        };
        assert!(
            after == fenced,
            "the bridge wrote into the fenced flat family: sizes {:?} became {:?}",
            sizes(&fenced),
            sizes(&after)
        );
        drop(reader);

        // The caller's fallback (`m06_cmd::refuse_session`): the event is queued.
        note_unrecorded_downgrade(&paths.log_dir, cause, at).unwrap();
        assert_eq!(
            unrecorded_downgrade(&paths.log_dir).map(|n| n.cause),
            Some(cause),
            "the marker is not queued"
        );

        let served = Arc::new(opened.store);
        assert_eq!(downgrade(&served), None);
        // The policy finds the marker from the served generation's database, which lives in
        // `generations/<name>/` (`marker_dir_of_db`): pending, it lowers the runner.
        let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, served.clone());
        assert!(
            policy.marker_pending(),
            "the marker does not lower the runner"
        );
        policy.drain_pending(at);
        assert_eq!(
            downgrade(&served),
            Some((cause.token().to_owned(), 1)),
            "the served generation does not carry the downgrade"
        );
        assert_eq!(unrecorded_downgrade(&paths.log_dir), None);
        assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
        drop(policy);
        let restarted = RunnerPolicy::with_store(ManagementPolicy::Verified, served.clone());
        assert_eq!(restarted.current(), ManagementPolicy::OwnerOnly);
    }
}

/// ⟨M08 W4 U2b-3b; W3-R01's W4 half⟩ A restore or a reset committed between the bridge's open
/// of the database and its write.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod restore_window_tests {
    use std::sync::Mutex;

    use heimdall_store::layout;
    use heimdall_store::{FaultAction, FaultHook, FaultPoint, NoFaults};

    use super::*;

    /// What runs in the window: a restore of `backup`, or a reset.
    enum Switch {
        Restore(PathBuf),
        Reset,
    }

    /// The hook of the bridge's store: at `BeforeTransaction` (the bridge has opened the
    /// database the pointer named and checked its schema; its transaction has not begun) the
    /// switch runs to completion, under the instance lock this test holds for it.
    struct SwitchInTheWindow {
        state_dir: PathBuf,
        switch: Switch,
        now: Timestamp,
        done: Mutex<Option<String>>,
    }

    impl FaultHook for SwitchInTheWindow {
        fn at(&self, point: FaultPoint) -> FaultAction {
            let mut done = self.done.lock().unwrap();
            if point == FaultPoint::BeforeTransaction && done.is_none() {
                let name = match &self.switch {
                    Switch::Restore(backup) => {
                        crate::state_store::restore_locked(
                            &self.state_dir,
                            backup,
                            self.now,
                            false,
                            std::time::Duration::from_secs(7 * 24 * 3600),
                        )
                        .unwrap_or_else(|e| panic!("the restore: {e}"))
                        .current
                        .name
                    }
                    Switch::Reset => {
                        crate::state_store::reset_locked(&self.state_dir, self.now, false)
                            .unwrap_or_else(|e| panic!("the reset: {e}"))
                            .current
                            .name
                    }
                };
                *done = Some(name.as_str().to_owned());
            }
            FaultAction::Continue
        }
    }

    fn downgrade(store: &Store) -> Option<String> {
        store
            .transaction(|tx| tx.runner_downgrade())
            .unwrap()
            .map(|d| d.cause)
    }

    /// `the_bridge_write_after_a_restore_or_reset_switch_fails_to_the_marker`: the pointer
    /// no longer names the generation the bridge opened, so its write fails and the caller's
    /// fallback queues the event in the marker; the generation now served carries the
    /// downgrade once the marker is applied (for the restore, whose store is a runner's: the
    /// carry-forward read the replaced generation before the bridge's write committed, so the
    /// marker is the only way the event reaches it).
    #[test]
    fn the_bridge_write_after_a_restore_or_reset_switch_fails_to_the_marker() {
        let at: Timestamp = "2026-11-27T09:00:00Z".parse().unwrap();
        let cause = OwnerOnlyCause::SessionAgent;
        for reset in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().canonicalize().unwrap();
            let paths = crate::Paths::under(&home);
            paths.ensure().unwrap();
            let opened =
                crate::state_store::open_locked(&paths.state_dir, Arc::new(NoFaults), at).unwrap();
            init_runner(&opened.store).unwrap();
            let before = opened.current.name.as_str().to_owned();
            drop(opened);
            let backup = dir.path().join("backup.db");
            Store::open_read_only(
                &layout::db_path(&paths.state_dir).unwrap(),
                Arc::new(NoFaults),
            )
            .unwrap()
            .vacuum_into(&backup)
            .unwrap();
            let _lock = crate::InstanceLock::try_acquire(&paths.state_dir).unwrap();
            let hook = Arc::new(SwitchInTheWindow {
                state_dir: paths.state_dir.clone(),
                switch: if reset {
                    Switch::Reset
                } else {
                    Switch::Restore(backup)
                },
                now: at,
                done: Mutex::new(None),
            });
            let recorded = record_owner_only_in_home_with_faults(&home, cause, at, hook.clone());
            let switched = hook
                .done
                .lock()
                .unwrap()
                .take()
                .expect("the switch ran in the window");
            assert_ne!(switched, before);
            assert_eq!(
                layout::pointed_generation(&paths.state_dir)
                    .unwrap()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy(),
                switched.as_str(),
                "reset {reset}: the switch is in place"
            );
            assert!(
                matches!(recorded, Err(heimdall_store::StoreError::Corrupt(_))),
                "reset {reset}: the bridge's write after the switch did not fail: {recorded:?}"
            );
            // The caller's fallback: the event is queued in the marker.
            note_unrecorded_downgrade(&paths.log_dir, cause, at).unwrap();
            assert_eq!(
                unrecorded_downgrade(&paths.log_dir).map(|n| n.cause),
                Some(cause)
            );
            if !reset {
                let served = Arc::new(
                    Store::open(
                        &layout::db_path(&paths.state_dir).unwrap(),
                        Arc::new(NoFaults),
                    )
                    .unwrap(),
                );
                assert_eq!(
                    downgrade(&served),
                    None,
                    "not carried: written after the read"
                );
                let policy = RunnerPolicy::with_store(ManagementPolicy::Verified, served.clone());
                assert!(policy.marker_pending(), "the marker lowers the runner");
                policy.drain_pending(at);
                assert_eq!(
                    downgrade(&served).as_deref(),
                    Some(cause.token()),
                    "the served generation carries the downgrade"
                );
                assert_eq!(policy.current(), ManagementPolicy::OwnerOnly);
            }
        }
    }
}
