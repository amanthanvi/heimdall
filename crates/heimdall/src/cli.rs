//! Command surface (spec §11.1; names are v0.1 proposals, semantics normative).
//! Only the M01 subset is wired in M01-T06: `access ensure|release|revoke`,
//! `operation show|wait|cancel|events`, `service run|status|stop`, `inspect`,
//! `schema export|show`, `status`. The rest are declared so help is complete and
//! return `USAGE_ERROR` with a "not yet available" message until their milestone.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use heimdall_contract::ExitCode;

/// Heimdall: set up access once; your terminals, tools, and agents work across
/// environments.
#[derive(Debug, Parser)]
#[command(name = "heimdall", version, disable_colored_help = true)]
pub struct Cli {
    /// Machine output: one JSON envelope on stdout (NDJSON for event streams).
    #[arg(long, global = true)]
    pub json: bool,
    /// Never open a browser, dialog, or terminal prompt (spec §11.3).
    #[arg(long, global = true)]
    pub non_interactive: bool,
    /// Override the Heimdall home directory (fixtures and tests).
    #[arg(long, global = true, env = "HEIMDALL_HOME", value_name = "DIR")]
    pub home: Option<PathBuf>,
    /// Subcommand; with none, the TUI on a TTY or status without one.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Adopt supported local access (M02).
    Setup,
    /// Convenience connect; ordinary ssh also works (M02).
    Connect {
        /// Destination alias.
        destination: String,
    },
    /// Ensure access then launch argv without a shell (spec §10.4) (M02).
    Run(RunArgs),
    /// Summary of machines, work, and attention items.
    Status,
    /// Passive diagnostics by default (spec §10.2) (M02).
    Doctor {
        /// Explicit probe level; never default.
        #[arg(long, value_name = "LEVEL")]
        active_probe: Option<String>,
    },
    /// Terminal UI (M02).
    Tui,
    /// Read-only inspection of runtime state.
    Inspect {
        /// Subject: capabilities|environments|profiles|destinations|bindings|grants|operations|decisions.
        subject: String,
    },
    /// Access primitives.
    #[command(subcommand)]
    Access(AccessCommand),
    /// Operation observation and control.
    #[command(subcommand)]
    Operation(OperationCommand),
    /// Per-user runtime control.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Public schemas and code table (R-AP-08).
    #[command(subcommand)]
    Schema(SchemaCommand),
}

/// `run` arguments.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Profile to ensure.
    #[arg(long)]
    pub profile: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: Option<String>,
    /// Argument vector after `--`, passed byte-exact.
    #[arg(last = true, required = true, value_name = "ARGV")]
    pub argv: Vec<OsString>,
}

/// `access` subcommands.
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Idempotent access preparation (spec §11.3).
    Ensure(EnsureArgs),
    /// Drop this consumer's reference to a binding.
    Release {
        /// Binding ID.
        binding_id: String,
    },
    /// Revoke a grant and its descendants (spec §6.7).
    Revoke {
        /// Grant ID.
        grant_id: String,
        /// Idempotency request ID.
        #[arg(long)]
        request_id: Option<String>,
    },
    /// Narrower child binding (M05 demo; model in M01).
    Delegate(DelegateArgs),
    /// Pause automatic activation for a policy (owner channel).
    Pause {
        /// Policy ID.
        policy_id: String,
    },
    /// Resume automatic activation.
    Resume {
        /// Policy ID.
        policy_id: String,
    },
    /// Schedule a hard stop for a policy (spec §6.1).
    Cutoff {
        /// Policy ID.
        policy_id: String,
        /// RFC 3339 instant with explicit offset.
        #[arg(long)]
        at: String,
    },
}

/// `access ensure` arguments (spec §11.3 example).
#[derive(Debug, Args)]
pub struct EnsureArgs {
    /// Profile.
    #[arg(long)]
    pub profile: String,
    /// Environment; default the caller's.
    #[arg(long)]
    pub environment: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: String,
    /// Absolute RFC 3339 deadline with offset.
    #[arg(long, conflicts_with = "for_duration")]
    pub until: Option<String>,
    /// Duration deadline (`2h`, `PT2H`).
    #[arg(long = "for", conflicts_with = "until")]
    pub for_duration: Option<String>,
    /// Idempotency request ID.
    #[arg(long)]
    pub request_id: String,
    /// Return immediately with the operation to observe.
    #[arg(long, name = "async")]
    pub r#async: bool,
    /// Bounded synchronous wait in milliseconds (timeout is not cancel).
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,
}

/// `access delegate` arguments.
#[derive(Debug, Args)]
pub struct DelegateArgs {
    /// Parent binding.
    #[arg(long)]
    pub parent: String,
    /// `destination:account` pairs (subset of the parent).
    #[arg(long = "pair", value_name = "DEST:ACCOUNT")]
    pub pairs: Vec<String>,
    /// Deadline (≤ parent).
    #[arg(long)]
    pub until: Option<String>,
    /// Work ID.
    #[arg(long)]
    pub work_id: String,
    /// Request ID.
    #[arg(long)]
    pub request_id: String,
}

/// `operation` subcommands.
#[derive(Debug, Subcommand)]
pub enum OperationCommand {
    /// Show an operation.
    Show {
        /// Operation ID.
        operation_id: String,
    },
    /// Wait (bounded) for a terminal state; timeout returns current state.
    Wait {
        /// Operation ID.
        operation_id: String,
        /// Timeout in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Explicit, idempotent cancellation.
    Cancel {
        /// Operation ID.
        operation_id: String,
    },
    /// NDJSON event stream (resumable with --cursor).
    Events {
        /// Resume cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Follow live events.
        #[arg(long)]
        follow: bool,
    },
}

/// `service` subcommands.
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Run the per-user runtime in the foreground (or detached).
    Run {
        /// Detach from the terminal (used by on-demand start).
        #[arg(long)]
        detach: bool,
    },
    /// Report whether a runtime is serving and its endpoints.
    Status,
    /// Ask the runtime to drain and stop.
    Stop,
}

/// `schema` subcommands.
#[derive(Debug, Subcommand)]
pub enum SchemaCommand {
    /// Write every public schema into a directory.
    Export {
        /// Output directory (default `schemas/public-api`).
        #[arg(long, default_value = "schemas/public-api")]
        out: PathBuf,
    },
    /// Print one schema or the code table to stdout.
    Show {
        /// Schema name, or `codes`.
        name: String,
    },
}

/// Dispatch a parsed command and return the process exit code.
///
/// M01-T00 wires only `schema show|export` (pure, no runtime needed). Every other
/// command returns a `USAGE_ERROR` envelope until M01-T06 connects the control
/// endpoint; nothing here ever authorizes access locally.
pub fn dispatch(cli: Cli) -> ExitCode {
    let json = cli.json;
    match cli.command {
        Some(Command::Schema(SchemaCommand::Show { name })) => schema_show(&name),
        Some(Command::Schema(SchemaCommand::Export { out })) => schema_export(&out, json),
        Some(_) | None => {
            let env = heimdall_app::OpError::new(
                heimdall_contract::Code::UsageError,
                "this command is not available in this build (M01-T06 wires the runtime client)",
            )
            .into_envelope();
            crate::output::emit(&env, json);
            crate::output::exit_code_for(env.code, false)
        }
    }
}

fn schema_show(name: &str) -> ExitCode {
    let doc = if name == "codes" {
        Some(heimdall_contract::schema::code_table())
    } else {
        heimdall_contract::schema::public_schemas()
            .into_iter()
            .find(|s| s.name == name)
            .and_then(|s| serde_json::to_value(&s.schema).ok())
    };
    match doc {
        Some(v) => {
            let env = heimdall_contract::Envelope::ok(v);
            crate::output::emit(&env, true);
            ExitCode::Success
        }
        None => {
            let env = heimdall_app::OpError::new(
                heimdall_contract::Code::NotFound,
                "unknown schema name",
            )
            .with_resource("schema", Some(name.to_owned()))
            .into_envelope();
            crate::output::emit(&env, true);
            crate::output::exit_code_for(env.code, false)
        }
    }
}

fn schema_export(out: &std::path::Path, json: bool) -> ExitCode {
    let result = (|| -> std::io::Result<Vec<String>> {
        std::fs::create_dir_all(out)?;
        let mut written = Vec::new();
        for s in heimdall_contract::schema::public_schemas() {
            let path = out.join(format!("{}.schema.json", s.name));
            let mut text =
                serde_json::to_string_pretty(&s.schema).map_err(std::io::Error::other)?;
            text.push('\n');
            std::fs::write(&path, text)?;
            written.push(path.display().to_string());
        }
        let codes = out.join("codes.json");
        let mut text = serde_json::to_string_pretty(&heimdall_contract::schema::code_table())
            .map_err(std::io::Error::other)?;
        text.push('\n');
        std::fs::write(&codes, text)?;
        written.push(codes.display().to_string());
        Ok(written)
    })();
    match result {
        Ok(written) => {
            let env = heimdall_contract::Envelope::ok(serde_json::json!({ "written": written }));
            crate::output::emit(&env, json);
            ExitCode::Success
        }
        Err(e) => {
            let env = heimdall_app::OpError::new(
                heimdall_contract::Code::InternalError,
                format!("schema export failed: {}", e.kind()),
            )
            .into_envelope();
            crate::output::emit(&env, json);
            crate::output::exit_code_for(env.code, false)
        }
    }
}
