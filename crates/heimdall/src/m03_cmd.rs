//! M03 command surface, wave 0 (m03-plan U0, §5 item 24).
//!
//! The clap tree of every M03 command is in `cli.rs`; this module holds what they
//! share until their units land (U10, U12): the envelope a command answers while its
//! body is not built, and the handlers of the commands that extend M02's `access` and
//! `destination` trees and of the hidden `internal` commands. `issuer_cmd`,
//! `enroll_cmd` and `connections_cmd` hold the per-group handlers.
//!
//! **The wave-0 envelope** is M01's: `USAGE_ERROR` (exit 2), effect `none`, next
//! `fix_request`, the message "this command is not available in this build (planned
//! for M03)". M02 retired that text for its own commands and `cli.rs` guards the M02
//! sources against it, so it is built here at run time, and only here (this module is
//! not one of the guarded sources). No handler in this wave opens the store, builds an
//! async executor or contacts the runtime: the Heimdall home is never created.

use heimdall_contract::envelope::Envelope;
use heimdall_contract::{Code, ExitCode};

use crate::cli::{ConnectionPolicyArgs, DestinationPreferArgs, InternalCommand, LockBehaviorArgs};
use crate::client::{Ctx, error};
use crate::output;
use crate::setup_cmd::Outcome;

/// The message of the wave-0 envelope, assembled at run time (module docs).
pub(crate) fn not_available_message() -> String {
    [
        "this command is not available",
        "in this build (planned for M03)",
    ]
    .join(" ")
}

/// The envelope an M03 command answers until its unit lands: `USAGE_ERROR`, effect
/// `none`, next `fix_request` (exit 2).
pub(crate) fn not_available_envelope() -> Envelope<serde_json::Value> {
    output::error_value(error(Code::UsageError, &not_available_message()))
}

/// [`not_available_envelope`] as a printable outcome (the `Outcome` handlers).
pub(crate) fn not_available_outcome() -> Outcome {
    Outcome::of(not_available_envelope())
}

/// Print [`not_available_envelope`] and return its exit code. Builds no executor,
/// opens no store and never contacts the runtime.
pub(crate) fn not_available(ctx: &Ctx) -> ExitCode {
    let env = not_available_envelope();
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

/// `destination prefer <alias> managed|existing` (catalog `SetPreference`; U12).
pub(crate) fn destination_prefer(ctx: &Ctx, _args: DestinationPreferArgs) -> ExitCode {
    not_available(ctx)
}

/// `access lock-behavior --policy P continue|revoke-on-lock` (U10, U12).
pub(crate) fn lock_behavior(ctx: &Ctx, _args: LockBehaviorArgs) -> ExitCode {
    not_available(ctx)
}

/// `access connection-policy --policy P [--existing ..] [--multiplexing ..]` (U10, U12).
pub(crate) fn connection_policy(ctx: &Ctx, _args: ConnectionPolicyArgs) -> ExitCode {
    not_available(ctx)
}

/// `access ensure ... --strict`: the request field exists (`EnsureRequest.connection`),
/// but the managed path that honours it is U10's, so it is answered here, whole,
/// before any request is built. Without `--strict` an `ensure` is M01's, unchanged.
pub(crate) fn ensure_strict(ctx: &Ctx) -> ExitCode {
    not_available(ctx)
}

/// The refusal of `internal issuer` run with a terminal on stdin: the issuer child is
/// started by the runtime on a pipe, never by a person (ADR-0008 D3).
pub(crate) fn internal_issuer_envelope(stdin_tty: bool) -> Envelope<serde_json::Value> {
    if stdin_tty {
        output::error_value(error(
            Code::UsageError,
            "internal issuer is started by the runtime and refuses a terminal on stdin",
        ))
    } else {
        not_available_envelope()
    }
}

/// The hidden `internal` commands. `issuer` refuses a terminal on stdin first (the
/// envelope); on a pipe it **is** the issuer child (M03-U3, [`internal_issuer`]),
/// which writes nothing on stdout but protocol frames. The session-lock state answers
/// the wave-0 envelope.
pub(crate) fn internal(ctx: &Ctx, command: InternalCommand) -> ExitCode {
    let env = match command {
        InternalCommand::Issuer if !ctx.stdin_tty => return internal_issuer(ctx),
        InternalCommand::Issuer => internal_issuer_envelope(true),
        InternalCommand::SessionLockState => not_available_envelope(),
    };
    output::emit(&env, ctx.json);
    output::exit_code_for(env.code, false)
}

/// ⟨M03-U3⟩ The directory of the scratch test store under the state directory (D1
/// "Test K_ca": under the scratch state directory). U10's runtime wiring and U12's
/// ceremony select the same directory.
pub(crate) const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

/// ⟨M03-U3⟩ `heimdall internal issuer` on a pipe (ADR-0008 D3 item 1): the child the
/// runtime spawns. Its stdout is the `heimdall-issuer/1` channel, so it never prints
/// an envelope; the status is the child's ([`heimdall_issuer::child::run`]): 0 →
/// success, a refused configuration → usage (2), anything else → unavailable (5),
/// which the supervisor reads as `crashed`.
fn internal_issuer(ctx: &Ctx) -> ExitCode {
    match issuer_child_status(ctx) {
        0 => ExitCode::Success,
        heimdall_issuer::child::EXIT_USAGE => ExitCode::Usage,
        _ => ExitCode::Unavailable,
    }
}

/// The issuer child's status (see [`internal_issuer`]).
fn issuer_child_status(ctx: &Ctx) -> i32 {
    use heimdall_issuer::child::{EXIT_UNAVAILABLE, EXIT_USAGE};
    let env = |name: &str| std::env::var_os(name);
    // A release build refuses every test variable before anything is read (U0b's
    // `release_build_refuses_m03_test_gates`); the M03 values are validated here.
    if crate::testcfg::refusal(
        crate::testcfg::AVAILABLE,
        crate::testcfg::requested_by(&env),
    )
    .is_some()
    {
        return EXIT_USAGE;
    }
    let Ok(m03) = crate::testcfg::m03_config(&env) else {
        return EXIT_USAGE;
    };
    let Ok(paths) = ctx.paths() else {
        return EXIT_UNAVAILABLE;
    };
    let db = paths
        .state_dir
        .join(heimdall_runtime::service::STATE_DB_FILE);
    // The installation's environment, which scopes the product store's items.
    let environment =
        heimdall_store::Store::open_read_only(&db, std::sync::Arc::new(heimdall_store::NoFaults))
            .and_then(|s| s.transaction(|tx| tx.self_environment()));
    let Ok(Some(environment)) = environment else {
        return EXIT_UNAVAILABLE;
    };
    let Some(store) = issuer_store(ctx, &paths, &environment, m03.scratch_secret_store) else {
        return EXIT_UNAVAILABLE;
    };
    heimdall_issuer::child::run(
        std::io::stdin(),
        std::io::stdout(),
        store,
        &db,
        issuer_clock(&env),
    )
}

/// ⟨M03-U3⟩ The issuer child's K_ca store (ADR-0008 D1): the platform's product
/// store, scoped to `environment` (§17.18 item 1). `None` where there is none
/// (headless Linux answers through the Secret Service's own availability; other
/// platforms have no store), and for the scratch test store, which a test-configured
/// build selects with `HEIMDALL_TEST_SECRET_STORE=scratch` but which this crate's
/// production graph cannot name yet (questions file U3-Q4): fail closed, never a
/// plaintext fallback. On Windows an explicit Heimdall home keeps the DPAPI blobs
/// under `<state>/issuer/<environment>` (D1: a scratch `HEIMDALL_HOME` is the product
/// kind at a scratch path); otherwise `%LOCALAPPDATA%\Heimdall\issuer\<environment>`.
pub(crate) fn issuer_store(
    ctx: &Ctx,
    paths: &heimdall_runtime::paths::Paths,
    environment: &heimdall_contract::ids::EnvironmentId,
    scratch: bool,
) -> Option<Box<dyn heimdall_issuer::store::SecretStore>> {
    if scratch {
        let _ = paths.state_dir.join(SCRATCH_STORE_DIR);
        return None;
    }
    let _ = (ctx, paths, environment);
    #[cfg(target_os = "macos")]
    {
        let home = heimdall_localenv::sys::account_home().ok()?;
        Some(Box::new(heimdall_issuer::store::MacosLoginKeychain::login(
            &home,
            environment,
        )))
    }
    #[cfg(windows)]
    {
        let dir = if ctx.home.is_some() {
            paths.state_dir.join("issuer").join(environment.as_str())
        } else {
            heimdall_issuer::store::WindowsDpapi::default_dir(environment).ok()?
        };
        Some(Box::new(heimdall_issuer::store::WindowsDpapi::in_dir(
            dir,
            environment,
        )))
    }
    #[cfg(target_os = "linux")]
    {
        Some(Box::new(heimdall_issuer::store::LinuxSecretService::new(
            environment,
        )))
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    {
        None
    }
}

/// ⟨M03-U3⟩ The issuer child's clock: the system clock, shifted like the runtime's
/// by `HEIMDALL_TEST_CLOCK_OFFSET_S` in a test-configured build, so the child's
/// read-only time gate sees the wall time the runtime anchored.
fn issuer_clock(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> std::sync::Arc<dyn heimdall_domain::time::Clock> {
    use heimdall_domain::time::Clock;
    struct Shifted(crate::testcfg::ClockOffset);
    impl Clock for Shifted {
        fn wall(&self) -> heimdall_contract::Timestamp {
            self.0.shift(heimdall_runtime::platform::SystemClock.wall())
        }
        fn continuous(&self) -> std::time::Duration {
            heimdall_runtime::platform::SystemClock.continuous()
        }
        fn boot_id(&self) -> heimdall_domain::time::BootId {
            heimdall_runtime::platform::SystemClock.boot_id()
        }
    }
    match env(crate::testcfg::CLOCK_OFFSET_ENV)
        .filter(|_| crate::testcfg::AVAILABLE)
        .and_then(|v| crate::testcfg::ClockOffset::parse(&v).ok())
    {
        Some(offset) => std::sync::Arc::new(Shifted(offset)),
        None => std::sync::Arc::new(heimdall_runtime::platform::SystemClock),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(env: &Envelope<serde_json::Value>) -> String {
        env.data
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(str::to_owned)
            .unwrap_or_default()
    }

    /// M01's envelope, reproduced: `USAGE_ERROR`, exit 2, the fixed message.
    #[test]
    fn the_wave_0_envelope_is_m01s() {
        let env = not_available_envelope();
        assert_eq!(env.code, Code::UsageError);
        assert_eq!(
            output::exit_code_for(env.code.clone(), false),
            ExitCode::Usage
        );
        assert_eq!(
            message(&env),
            "this command is not available in this build (planned for M03)"
        );
    }

    /// `internal issuer_refuses_tty_stdin`: a terminal on stdin is refused first, with
    /// its own message; a pipe gets the wave-0 envelope.
    #[test]
    fn internal_issuer_refuses_tty_stdin() {
        let tty = internal_issuer_envelope(true);
        assert_eq!(tty.code, Code::UsageError);
        assert!(message(&tty).contains("refuses a terminal on stdin"));
        assert!(!message(&tty).contains("not available"));
        let pipe = internal_issuer_envelope(false);
        assert_eq!(message(&pipe), message(&not_available_envelope()));
    }

    /// Every M03 command line of m03-plan §5 item 24, as a list of arguments.
    pub(crate) const M03_LINES: &[&[&str]] = &[
        &["issuer", "init", "--backup-out", "b.enc"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--bundle",
            "f",
        ],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--no-bundle-available",
        ],
        &["issuer", "status"],
        &["issuer", "unlock"],
        &["issuer", "rotate", "begin", "--backup-out", "b.enc"],
        &["issuer", "retire", "SHA256:abc"],
        &["issuer", "restore", "--backup", "b.enc"],
        &["issuer", "restore", "--backup", "b.enc", "--not-stolen"],
        &["issuer", "bundle", "--out", "o.json"],
        &[
            "issuer",
            "bundle",
            "--out",
            "o.json",
            "--redact",
            "hostnames",
        ],
        &["enroll", "lab"],
        &[
            "enroll",
            "lab",
            "--account",
            "deploy",
            "--form",
            "system",
            "--registry-path",
            "p",
            "--ca",
            "fp",
        ],
        &["enroll", "status"],
        &["enroll", "verify", "enr-1"],
        &["enroll", "verify", "enr-1", "--absence"],
        &["enroll", "verify", "enr-1", "--approve-target-change"],
        &["enroll", "remove", "enr-1"],
        &[
            "enroll",
            "remove",
            "--from-bundle",
            "f",
            "--marker",
            "m",
            "--alias",
            "a",
        ],
        &["enroll", "reconcile", "op-1"],
        &["enroll", "reconcile", "op-1", "--after-manual-recovery"],
        &["enroll", "abandon", "enr-1"],
        &["destination", "prefer", "lab", "managed"],
        &["destination", "prefer", "lab", "existing"],
        &[
            "access",
            "ensure",
            "--profile",
            "p",
            "--work-id",
            "w",
            "--request-id",
            "r",
            "--strict",
        ],
        &["access", "lock-behavior", "--policy", "pol", "continue"],
        &[
            "access",
            "lock-behavior",
            "--policy",
            "pol",
            "revoke-on-lock",
        ],
        &["access", "connection-policy", "--policy", "pol"],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--existing",
            "strict",
            "--multiplexing",
            "owned",
        ],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--existing",
            "graceful",
            "--multiplexing",
            "disabled",
        ],
        &["connections"],
        &["connections", "close", "conn-1"],
        &["internal", "issuer"],
        &["internal", "session-lock-state"],
    ];

    /// Lines the tree must refuse at parse time (exit 2 `USAGE_ERROR`).
    const REFUSED_LINES: &[&[&str]] = &[
        &["issuer", "init"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
        ],
        &["issuer", "init", "--backup-out", "b", "--bundle", "f"],
        &[
            "issuer",
            "init",
            "--backup-out",
            "b",
            "--replace-orphan",
            "fp",
            "--bundle",
            "f",
            "--no-bundle-available",
        ],
        &["issuer", "rotate"],
        &["issuer", "restore"],
        &["issuer", "bundle", "--out", "o", "--redact", "everything"],
        &["enroll"],
        &["enroll", "lab", "status"],
        &[
            "enroll",
            "verify",
            "enr-1",
            "--absence",
            "--approve-target-change",
        ],
        &["enroll", "remove"],
        &["enroll", "remove", "--from-bundle", "f"],
        &[
            "enroll",
            "remove",
            "enr-1",
            "--from-bundle",
            "f",
            "--marker",
            "m",
            "--alias",
            "a",
        ],
        &["destination", "prefer", "lab", "other"],
        &["access", "lock-behavior", "continue"],
        &["access", "lock-behavior", "--policy", "pol", "sometimes"],
        &["access", "connection-policy"],
        &[
            "access",
            "connection-policy",
            "--policy",
            "pol",
            "--multiplexing",
            "owned_masters",
        ],
        &["connections", "close"],
        &["uninstall", "--keep-remote-enrollments"],
        &["uninstall", "--purge-state", "--bundle", "f"],
    ];

    /// The tree takes exactly the commands of the plan's table and refuses the rest,
    /// and every accepted line is an M03 command that no M02 handler owns.
    #[test]
    fn the_m03_command_tree_matches_the_plan_table() {
        use clap::Parser as _;
        for line in M03_LINES {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            if let Err(e) = crate::cli::Cli::try_parse_from(&argv) {
                panic!("{line:?} must parse: {:?}", e.kind());
            }
        }
        for line in REFUSED_LINES {
            let argv: Vec<&str> = std::iter::once("heimdall")
                .chain(line.iter().copied())
                .collect();
            assert!(
                crate::cli::Cli::try_parse_from(&argv).is_err(),
                "{line:?} must be refused"
            );
        }
        let uninstall = crate::cli::Cli::try_parse_from([
            "heimdall",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
            "--bundle",
            "f",
        ]);
        assert!(uninstall.is_ok());
    }

    /// `internal` is hidden from help; the user commands are not.
    #[test]
    fn internal_is_hidden_and_the_rest_are_listed() {
        use clap::CommandFactory as _;
        let cmd = crate::cli::Cli::command();
        for (name, hidden) in [
            ("internal", true),
            ("issuer", false),
            ("enroll", false),
            ("connections", false),
        ] {
            let Some(sub) = cmd.get_subcommands().find(|c| c.get_name() == name) else {
                panic!("no {name} command");
            };
            assert_eq!(sub.is_hide_set(), hidden, "{name}");
        }
    }

    /// Every M03 line, dispatched in-process, answers the wave-0 envelope's exit code
    /// and creates nothing under the Heimdall home it names (no runtime contact).
    #[test]
    fn m03_lines_answer_without_touching_the_home() {
        use clap::Parser as _;
        let scratch = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        for (i, line) in M03_LINES.iter().enumerate() {
            let home = scratch.path().join(format!("home-{i}"));
            let home_arg = home.to_string_lossy().into_owned();
            let argv: Vec<&str> = ["heimdall", "--json", "--non-interactive", "--home"]
                .into_iter()
                .chain(std::iter::once(home_arg.as_str()))
                .chain(line.iter().copied())
                .collect();
            let cli = crate::cli::Cli::try_parse_from(&argv)
                .unwrap_or_else(|e| panic!("{line:?} must parse: {:?}", e.kind()));
            // ⟨M03-U3⟩ `internal issuer` on a pipe is the issuer child: with no state
            // database in the home it cannot open one read-only and exits unavailable
            // (a terminal stdin is still the usage refusal). Neither touches the home.
            let expected = if *line == ["internal", "issuer"]
                && !std::io::IsTerminal::is_terminal(&std::io::stdin())
            {
                ExitCode::Unavailable
            } else {
                ExitCode::Usage
            };
            assert_eq!(crate::cli::dispatch(cli), expected, "{line:?}");
            assert!(!home.exists(), "{line:?} touched the home");
        }
    }
}
