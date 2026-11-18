//! The in-distribution helper (`heimdall internal wsl-helper`; ADR-0010 §3 items 3–4, 8,
//! §9 item 2; design U3 §2–§3).
//!
//! It is the Linux build of `heimdall`, run in place through interop. It owns nothing
//! durable apart from the user-file snapshots next to the files they protect
//! (`<state_dir>/backups`, ADR-0007 §5.5) and its instance lock. It serves the Windows
//! runtime's file-operation requests one at a time over stdin and stdout, running
//! `LocalProjection` with a **proxy sink** whose two calls cross the channel and block until
//! Windows has made the receipt or the item commit durable and said so:
//!
//! * `append` returns `Ok` only on the matching `sink_ack`; `sink_failed`, EOF, a protocol
//!   error or [`proto::SINK_ACK_TIMEOUT`] without the ack is a `SinkError`, and the writer
//!   stops (row T1). A lost channel at any point is therefore exactly a crash of the native
//!   writer at the same point, which ADR-0007 §5.7's recovery table already handles: a later
//!   `reconcile` through a fresh helper, never a second `apply`.
//! * It never starts a new file step after a sink call failed (`LocalProjection` guarantees
//!   it) and ends at EOF on stdin.
//!
//! Nothing but protocol frames is written to stdout.

pub mod identity;
pub mod lock;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use heimdall_app::ports::{PreviewError, ReconcileError, SinkError, StageSink};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::setup::ProjectionItem;
use heimdall_domain::operation::LocalReceipt;
use heimdall_domain::projection::{ItemCommit, ProjectionLocator};
use heimdall_localenv::clients::{ClientsConfig, resolve_clients};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::{LocalProjection, ProjectionConfig, ReplaceHook};

use self::identity::Identity;
use crate::proto::{
    self, DistContext, EXIT_PROTOCOL, ErrorKind, Hello, HelperFrame, Inbound, SinkCalls, VERSION,
    WindowsFrame, WireHeldStep, WireItemOutcome,
};

/// The helper's exit status for a refused configuration or a terminal on stdin.
pub const EXIT_USAGE: i32 = 2;
/// The helper's exit status when it cannot establish what it needs to run.
pub const EXIT_UNAVAILABLE: i32 = 5;

/// How the helper turns the Windows path of the in-box `ssh.exe` into a path it can run.
#[derive(Debug, Clone)]
pub enum SshExe {
    /// `/usr/bin/wslpath -u <windows path>`, then an existence and executable check
    /// (production).
    WslPath,
    /// A fixed distribution-visible path (the test configuration, where no `wslpath`
    /// exists).
    Fixed(PathBuf),
}

/// Everything the helper takes from its process and account.
#[derive(Clone)]
pub struct HelperEnv {
    /// What the hello reports.
    pub identity: Identity,
    /// The SSH locations of the account (the home is the account's; Mode A never writes
    /// below `~/.ssh`).
    pub ssh_paths: SshPaths,
    /// `$XDG_CONFIG_HOME` (default `~/.config`): its `heimdall` child is `config_dir`.
    pub config_base: PathBuf,
    /// `$XDG_STATE_HOME` (default `~/.local/state`): its `heimdall` child is `state_dir`.
    pub state_base: PathBuf,
    /// The process environment (Git's global-file resolution reads it).
    pub env: Env,
    /// The `ssh.exe` translation.
    pub ssh_exe: SshExe,
    /// A test-only hook inside the file transaction (`None` in production).
    pub hook: Option<Arc<dyn ReplaceHook>>,
    /// How long the instance lock is awaited.
    pub lock_wait: Duration,
}

impl std::fmt::Debug for HelperEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperEnv")
            .field("identity", &self.identity)
            .field("ssh_exe", &self.ssh_exe)
            .field("hook", &self.hook.is_some())
            .finish_non_exhaustive()
    }
}

impl HelperEnv {
    /// The production environment: the account database's name and home, the process uid,
    /// `$WSL_DISTRO_NAME`, and the XDG directories of the account.
    ///
    /// # Errors
    /// A fixed message when the account cannot be established.
    pub fn production() -> Result<Self, &'static str> {
        let home = heimdall_localenv::sys::account_home().map_err(|_| "no account home")?;
        let account = heimdall_localenv::sys::account_name().map_err(|_| "no account name")?;
        let env = Env::capture();
        let xdg = |name: &str, default: &[&str]| {
            env.get(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| default.iter().fold(home.clone(), |p, c| p.join(c)))
        };
        Ok(Self {
            identity: Identity {
                uid: identity::effective_uid(),
                account,
                distribution: std::env::var("WSL_DISTRO_NAME")
                    .ok()
                    .filter(|s| !s.is_empty()),
                interop: identity::interop_enabled(),
                append_windows_path: identity::read_append_windows_path(),
            },
            ssh_paths: SshPaths::resolve().map_err(|_| "no account home")?,
            config_base: xdg("XDG_CONFIG_HOME", &[".config"]),
            state_base: xdg("XDG_STATE_HOME", &[".local", "state"]),
            env,
            ssh_exe: SshExe::WslPath,
            hook: None,
            lock_wait: lock::LOCK_WAIT,
        })
    }

    fn hello(&self) -> Hello {
        Hello {
            version: VERSION.to_owned(),
            uid: self.identity.uid,
            account: self.identity.account.clone(),
            distribution: self.identity.distribution.clone(),
            interop: self.identity.interop,
            append_windows_path: self.identity.append_windows_path,
            arch: std::env::consts::ARCH.to_owned(),
            helper_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

/// A request failure: what `error {kind, message}` carries.
type Failure = (ErrorKind, String);

fn fail(kind: ErrorKind, message: &str) -> Failure {
    (kind, message.to_owned())
}

fn from_reconcile(e: &ReconcileError) -> Failure {
    let kind = match e {
        ReconcileError::UnreadableReceipt(_) => ErrorKind::UnreadableReceipt,
        ReconcileError::IntentInvalid(_) => ErrorKind::IntentInvalid,
        ReconcileError::Sink(_) => ErrorKind::Sink,
        _ => ErrorKind::Unavailable,
    };
    (kind, e.to_string())
}

fn from_preview(e: &PreviewError) -> Failure {
    match e {
        PreviewError::TooLarge => (ErrorKind::TooLarge, e.to_string()),
        _ => (ErrorKind::Unavailable, e.to_string()),
    }
}

/// What the helper has taken so far: the directories and the lock.
#[derive(Default)]
struct Ready {
    dirs: Option<(PathBuf, PathBuf)>,
    lock: Option<lock::InstanceLock>,
}

/// The `heimdall` directory under an XDG base: created `0700` when missing (and any missing
/// ancestor too, never changing one that exists), then opened through `ManagedDir` (a symlink,
/// another owner or a group or world writable directory is refused) and required to be
/// owner-only. An unsafe directory is refused and never repaired.
///
/// The ancestors are not the helper's to judge: an account's `~/.config` is whatever its
/// umask made it (often group-writable under `umask 002`), so the anchor is Heimdall's own
/// directory, not the XDG base.
#[cfg(unix)]
fn heimdall_dir(base: &Path) -> Result<PathBuf, Failure> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    use heimdall_localenv::sys::ManagedDir;
    let unsafe_dir = || fail(ErrorKind::Unavailable, "wsl_helper_state_unsafe");
    let dir = base.join("heimdall");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(base).map_err(|_| unsafe_dir())?;
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(unsafe_dir()),
    }
    ManagedDir::open_root(&dir)
        .map_err(|_| unsafe_dir())?
        .ok_or_else(unsafe_dir)?;
    let meta = std::fs::symlink_metadata(&dir).map_err(|_| unsafe_dir())?;
    if !meta.is_dir()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
    {
        return Err(unsafe_dir());
    }
    Ok(dir)
}

#[cfg(not(unix))]
fn heimdall_dir(_base: &Path) -> Result<PathBuf, Failure> {
    Err(fail(
        ErrorKind::Unavailable,
        "the helper runs on Linux only",
    ))
}

impl Ready {
    /// The directories and the instance lock, taken before the first file operation.
    fn take(&mut self, env: &HelperEnv) -> Result<(PathBuf, PathBuf), Failure> {
        if let (Some(dirs), Some(_)) = (&self.dirs, &self.lock) {
            return Ok(dirs.clone());
        }
        let config_dir = heimdall_dir(&env.config_base)?;
        let state_dir = heimdall_dir(&env.state_base)?;
        let held =
            lock::acquire(&state_dir.join(lock::LOCK_FILE), env.lock_wait).map_err(
                |e| match e {
                    lock::LockError::Busy => fail(ErrorKind::Busy, "another helper is running"),
                    _ => fail(ErrorKind::Unavailable, "wsl_helper_lock_unavailable"),
                },
            )?;
        self.lock = Some(held);
        self.dirs = Some((config_dir.clone(), state_dir.clone()));
        Ok((config_dir, state_dir))
    }
}

/// The distribution-visible path of the in-box `ssh.exe`: translated, absolute, an existing
/// executable regular file.
fn resolve_ssh_exe(env: &HelperEnv, windows_path: &str) -> Result<PathBuf, Failure> {
    let unavailable = || fail(ErrorKind::Unavailable, "wsl_ssh_exe_unavailable");
    let path = match &env.ssh_exe {
        SshExe::Fixed(p) => p.clone(),
        SshExe::WslPath => {
            let out = std::process::Command::new("/usr/bin/wslpath")
                .arg("-u")
                .arg(windows_path)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .map_err(|_| unavailable())?;
            if !out.status.success() {
                return Err(unavailable());
            }
            PathBuf::from(
                String::from_utf8(out.stdout)
                    .map_err(|_| unavailable())?
                    .trim(),
            )
        }
    };
    if !path.is_absolute() {
        return Err(unavailable());
    }
    let meta = std::fs::metadata(&path).map_err(|_| unavailable())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            return Err(unavailable());
        }
    }
    #[cfg(not(unix))]
    if !meta.is_file() {
        return Err(unavailable());
    }
    Ok(path)
}

/// The writer's configuration for one request. Only a `preview` needs the in-box `ssh.exe`
/// (the Git item points Git at it); the other requests read every path from the intent.
fn projection_config(
    env: &HelperEnv,
    dirs: &(PathBuf, PathBuf),
    ctx: &DistContext,
    for_preview: bool,
) -> Result<ProjectionConfig, Failure> {
    if !ctx.items.contains(&ProjectionItem::DistributionGit) {
        return Err(fail(
            ErrorKind::IntentInvalid,
            "the context grants no distribution item",
        ));
    }
    let clients = if for_preview {
        let ssh = resolve_ssh_exe(env, &ctx.ssh_exe_windows)?;
        resolve_clients(
            &env.env,
            &env.ssh_paths,
            &ClientsConfig {
                ssh: Some(ssh),
                ..ClientsConfig::default()
            },
            LocalQueries::Enabled,
        )
    } else {
        resolve_clients(
            &env.env,
            &env.ssh_paths,
            &ClientsConfig::default(),
            LocalQueries::Disabled,
        )
    };
    let mut config =
        ProjectionConfig::new(env.ssh_paths.clone(), Platform::current(), dirs.0.clone())
            .with_state_dir(dirs.1.clone())
            .for_distribution(ctx.guid.clone());
    config.env = env.env.clone();
    config.clients = clients;
    config.queries = LocalQueries::Enabled;
    config.hook = env.hook.clone();
    Ok(config)
}

// --- the proxy sink ---------------------------------------------------------------------

/// Why the proxy sink's exchange broke the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Broken {
    /// Windows went away (EOF, a write failure): exit quietly.
    Gone,
    /// A protocol violation: exit with [`EXIT_PROTOCOL`].
    Protocol,
}

struct ProxySink<'a, W: Write> {
    writer: &'a mut W,
    rx: &'a mut Receiver<Inbound<WindowsFrame>>,
    id: u64,
    calls: SinkCalls,
    namespace: EnvironmentId,
    ack_timeout: Duration,
    /// Set once an exchange failed: no further call is made.
    failed: bool,
    broken: Option<Broken>,
}

impl<W: Write> ProxySink<'_, W> {
    fn exchange(&mut self, frame: impl FnOnce(u64, u64) -> HelperFrame) -> Result<(), SinkError> {
        let stop = |m: &str| SinkError(m.to_owned());
        if self.failed {
            return Err(stop("an earlier sink call failed"));
        }
        let seq = self.calls.next_seq();
        if self.calls.accept(self.id, seq).is_err() {
            self.failed = true;
            self.broken = Some(Broken::Protocol);
            return Err(stop("too many sink calls"));
        }
        if proto::write_frame(self.writer, &frame(self.id, seq)).is_err() {
            self.failed = true;
            self.broken = Some(Broken::Gone);
            return Err(stop("the channel is gone"));
        }
        let verdict = match self.rx.recv_timeout(self.ack_timeout) {
            Ok(Inbound::Frame(WindowsFrame::SinkAck { id, seq: s }))
                if id == self.id && s == seq =>
            {
                Ok(())
            }
            Ok(Inbound::Frame(WindowsFrame::SinkFailed { id, seq: s }))
                if id == self.id && s == seq =>
            {
                Err("windows could not make the call durable")
            }
            Ok(Inbound::Frame(_) | Inbound::Broken(_)) => {
                self.broken = Some(Broken::Protocol);
                Err("an unexpected frame during a sink call")
            }
            Ok(Inbound::Eof) | Err(RecvTimeoutError::Disconnected) => {
                self.broken = Some(Broken::Gone);
                Err("the channel ended")
            }
            Err(RecvTimeoutError::Timeout) => Err("no acknowledgment in time"),
        };
        verdict.map_err(|m| {
            self.failed = true;
            stop(m)
        })
    }
}

impl<W: Write + Send> StageSink for ProxySink<'_, W> {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        let receipt = receipt.clone();
        self.exchange(|id, seq| HelperFrame::SinkAppend { id, seq, receipt })
    }

    fn commit_item(&mut self, mut commit: ItemCommit) -> Result<(), SinkError> {
        // The writer knows no environment: the request's namespace is stamped here, and
        // Windows checks it equals the one the request was sent for.
        commit.record.environment = self.namespace.clone();
        self.exchange(|id, seq| HelperFrame::SinkCommit {
            id,
            seq,
            commit: Box::new(commit),
        })
    }
}

// --- the session ---------------------------------------------------------------------------

enum Next {
    Continue,
    Exit(i32),
}

/// Serve one session: hello, wait for `welcome`, then requests until `shutdown`, EOF or a
/// protocol error. Returns the helper's exit status (0, or [`EXIT_PROTOCOL`]).
pub fn serve<R, W>(env: &HelperEnv, reader: R, mut writer: W) -> i32
where
    R: Read + Send + 'static,
    W: Write + Send,
{
    let mut rx = proto::spawn_reader::<WindowsFrame, _>(reader);
    if proto::write_frame(&mut writer, &HelperFrame::Hello(env.hello())).is_err() {
        return 0;
    }
    match rx.recv_timeout(proto::HELLO_TIMEOUT) {
        Ok(Inbound::Frame(WindowsFrame::Welcome { version })) if version == VERSION => {}
        Ok(Inbound::Frame(WindowsFrame::Bye { .. }) | Inbound::Eof) => return 0,
        _ => return protocol_exit(&mut writer),
    }
    let mut ready = Ready::default();
    loop {
        let frame = match rx.recv() {
            Ok(Inbound::Frame(f)) => f,
            Ok(Inbound::Eof) | Err(_) => return 0,
            Ok(Inbound::Broken(_)) => return protocol_exit(&mut writer),
        };
        match handle(env, &mut ready, &mut rx, &mut writer, frame) {
            Next::Continue => {}
            Next::Exit(code) => return code,
        }
    }
}

/// Tell Windows (best effort) and exit with [`EXIT_PROTOCOL`].
fn protocol_exit<W: Write>(writer: &mut W) -> i32 {
    let _ = proto::write_frame(
        writer,
        &HelperFrame::Error {
            id: 0,
            kind: ErrorKind::Protocol,
            message: "protocol error".to_owned(),
        },
    );
    EXIT_PROTOCOL
}

fn reply<W: Write>(writer: &mut W, frame: &HelperFrame) -> Next {
    match proto::write_frame(writer, frame) {
        Ok(()) => Next::Continue,
        Err(_) => Next::Exit(0),
    }
}

fn error_frame(id: u64, (kind, message): Failure) -> HelperFrame {
    HelperFrame::Error {
        id,
        kind,
        message: proto::bounded_message(&message),
    }
}

fn handle<W: Write + Send>(
    env: &HelperEnv,
    ready: &mut Ready,
    rx: &mut Receiver<Inbound<WindowsFrame>>,
    writer: &mut W,
    frame: WindowsFrame,
) -> Next {
    match frame {
        WindowsFrame::Shutdown {} => Next::Exit(0),
        // Mode B is U4's: defined, answered `unsupported`, and the session continues.
        f if f.is_mode_b() => reply(
            writer,
            &error_frame(
                f.mode_b_id(),
                fail(ErrorKind::Unsupported, "mode b is not served by this build"),
            ),
        ),
        WindowsFrame::Welcome { .. }
        | WindowsFrame::Bye { .. }
        | WindowsFrame::SinkAck { .. }
        | WindowsFrame::SinkFailed { .. } => Next::Exit(protocol_exit(writer)),
        WindowsFrame::Preview {
            id,
            spec,
            intent,
            ctx,
        } => {
            let result = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, true))
                .and_then(|c| {
                    LocalProjection::writing(c)
                        .map_err(|e| fail(ErrorKind::Unavailable, &e.to_string()))
                })
                .and_then(|w| {
                    heimdall_app::ports::ProjectionWriter::preview(&w, &spec, &intent)
                        .map_err(|e| from_preview(&e))
                });
            match result {
                Ok(plan) => reply(
                    writer,
                    &HelperFrame::PreviewOk {
                        id,
                        plan: Box::new(plan),
                    },
                ),
                Err(f) => reply(writer, &error_frame(id, f)),
            }
        }
        WindowsFrame::Apply { id, intent, ctx } => {
            let config = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, false));
            run_with_sink(
                rx,
                writer,
                id,
                &ctx,
                config,
                |w, sink| {
                    heimdall_app::ports::ProjectionWriter::apply(w, &intent, sink).map(|r| r.items)
                },
                |items| HelperFrame::ApplyOk {
                    id,
                    items: items.iter().map(WireItemOutcome::from).collect(),
                },
            )
        }
        WindowsFrame::Reconcile {
            id,
            intent,
            receipts,
            ctx,
        } => {
            let config = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, false));
            run_with_sink(
                rx,
                writer,
                id,
                &ctx,
                config,
                |w, sink| {
                    heimdall_app::ports::ProjectionWriter::reconcile(w, &intent, &receipts, sink)
                        .map(|r| r.items)
                },
                |items| HelperFrame::ReconcileOk {
                    id,
                    items: items.iter().map(WireItemOutcome::from).collect(),
                },
            )
        }
        WindowsFrame::Observe {
            id,
            record,
            aliases,
            ctx,
        } => {
            let result = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, false))
                .map(|c| {
                    heimdall_app::ports::ProjectionWriter::observe(
                        &LocalProjection::new(c),
                        &record,
                        &aliases,
                    )
                });
            match result {
                Ok(observations) => reply(writer, &HelperFrame::ObserveOk { id, observations }),
                Err(f) => reply(writer, &error_frame(id, f)),
            }
        }
        WindowsFrame::ObserveHeld {
            id,
            intent,
            receipts,
            ctx,
        } => {
            let result = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, false))
                .and_then(|c| {
                    heimdall_app::ports::ProjectionWriter::observe_held(
                        &LocalProjection::new(c),
                        &intent,
                        &receipts,
                    )
                    .map_err(|e| from_reconcile(&e))
                });
            match result {
                Ok(steps) => reply(
                    writer,
                    &HelperFrame::ObserveHeldOk {
                        id,
                        steps: steps.iter().map(WireHeldStep::from).collect(),
                    },
                ),
                Err(f) => reply(writer, &error_frame(id, f)),
            }
        }
        WindowsFrame::Clean { id, resource, ctx } => {
            let result = ready
                .take(env)
                .and_then(|dirs| projection_config(env, &dirs, &ctx, false))
                .and_then(|c| {
                    let locator: ProjectionLocator = serde_json::from_str(&resource.locator)
                        .map_err(|_| fail(ErrorKind::Adapter, "unreadable projection locator"))?;
                    heimdall_localenv::projection::cleaner::delete_locator(
                        &c,
                        &locator,
                        resource.generation.0,
                    )
                    .map_err(|e| match e {
                        heimdall_app::ports::AdapterError::Unavailable(m) => {
                            (ErrorKind::Unavailable, m)
                        }
                        other => (ErrorKind::Adapter, other.to_string()),
                    })
                });
            match result {
                Ok(()) => reply(writer, &HelperFrame::CleanOk { id }),
                Err(f) => reply(writer, &error_frame(id, f)),
            }
        }
        // Handled above; the guard arm keeps the match total without a wildcard that
        // would hide a new frame.
        WindowsFrame::Realize { .. }
        | WindowsFrame::Withdraw { .. }
        | WindowsFrame::Open { .. }
        | WindowsFrame::Data { .. }
        | WindowsFrame::Close { .. } => Next::Continue,
    }
}

/// Run `apply` or `reconcile` over a [`ProxySink`] and answer: `done` builds the success
/// frame; a failure is answered `error`; a broken channel ends the session.
fn run_with_sink<W, T>(
    rx: &mut Receiver<Inbound<WindowsFrame>>,
    writer: &mut W,
    id: u64,
    ctx: &DistContext,
    config: Result<ProjectionConfig, Failure>,
    run: impl FnOnce(&LocalProjection, &mut dyn StageSink) -> Result<Vec<T>, ReconcileError>,
    done: impl FnOnce(Vec<T>) -> HelperFrame,
) -> Next
where
    W: Write + Send,
{
    let projection = config.and_then(|c| {
        LocalProjection::writing(c).map_err(|e| fail(ErrorKind::Unavailable, &e.to_string()))
    });
    let projection = match projection {
        Ok(p) => p,
        Err(f) => return reply(writer, &error_frame(id, f)),
    };
    let mut sink = ProxySink {
        writer,
        rx,
        id,
        calls: SinkCalls::new(id),
        namespace: ctx.namespace.clone(),
        ack_timeout: proto::SINK_ACK_TIMEOUT,
        failed: false,
        broken: None,
    };
    let result = run(&projection, &mut sink);
    let broken = sink.broken;
    drop(sink);
    match (result, broken) {
        (_, Some(Broken::Protocol)) => Next::Exit(protocol_exit(writer)),
        (_, Some(Broken::Gone)) => Next::Exit(0),
        (Ok(items), None) => reply(writer, &done(items)),
        (Err(e), None) => reply(writer, &error_frame(id, from_reconcile(&e))),
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// The helper's directory is created `0700` below an XDG base whatever its umask made the
    /// base (a group-writable `~/.config` under `umask 002` is the account's, not unsafe: found
    /// on the Linux devbox); an existing `heimdall` directory that is not owner-only, or is a
    /// symlink, is refused and never repaired.
    #[test]
    fn heimdall_dir_is_owner_only_whatever_the_base_is() {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("config");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o775)).unwrap();
        let dir = heimdall_dir(&base).unwrap();
        assert_eq!(dir, base.join("heimdall"));
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A missing base chain is created owner-only too.
        let deep = heimdall_dir(&root.path().join("a").join("b")).unwrap();
        assert_eq!(
            std::fs::metadata(deep.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            heimdall_dir(&base).unwrap_err().1,
            "wsl_helper_state_unsafe"
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "never repaired"
        );
        let other = root.path().join("other");
        std::fs::create_dir(&other).unwrap();
        let linked = root.path().join("linked");
        std::fs::create_dir(&linked).unwrap();
        std::os::unix::fs::symlink(&other, linked.join("heimdall")).unwrap();
        assert!(heimdall_dir(&linked).is_err());
    }
}
