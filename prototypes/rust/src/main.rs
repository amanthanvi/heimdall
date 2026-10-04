//! heimdall-proto: G02 prototype entry point. Thin adapter over the library's
//! shared domain operations (see lib.rs).
#![forbid(unsafe_code)]

mod cli;
mod tui;

use std::ffi::OsString;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use cli::Cmd;
use heimdall_proto::agent::{self, ProbeOutcome};
use heimdall_proto::envelope::{Code, Envelope};
use heimdall_proto::{profile, runner};
use serde_json::json;

fn emit(e: &Envelope) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(e.to_line().as_bytes());
    let _ = out.flush();
}

fn exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

fn main() {
    // Round 2: block the handled signals first; each command restores the mask once
    // its own handling is installed (see heimdall_proto::sigdisp).
    #[cfg(unix)]
    heimdall_proto::sigdisp::block_early();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let json = cli::wants_json(&args);
    let code = match std::panic::catch_unwind(|| dispatch(args)) {
        Ok(c) => c,
        Err(_) => {
            if json {
                emit(&Envelope::failure(Code::Internal, None, "internal error"));
            }
            1
        }
    };
    exit(code)
}

/// Restore the signal mask saved at startup (commands without their own handling).
fn default_signals() {
    #[cfg(unix)]
    heimdall_proto::sigdisp::restore_mask();
}

/// Write the `--meta-file` result. Opened non-blocking so a FIFO without a reader
/// fails at once (ENXIO) instead of hanging after the child exited; a pipe or FIFO
/// that has a reader is then written in blocking mode.
fn write_meta(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NONBLOCK);
    }
    let mut f = o.open(path)?;
    #[cfg(unix)]
    rustix::io::ioctl_fionbio(&f, false)?;
    f.write_all(line.as_bytes())
}

fn dispatch(args: Vec<OsString>) -> i32 {
    let cmd = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            default_signals();
            eprintln!("heimdall-proto: {}\n{}", e.message, cli::USAGE);
            if e.json {
                emit(&Envelope::failure(Code::UsageError, None, e.message));
            }
            return 2;
        }
    };
    if matches!(
        cmd,
        Cmd::Help | Cmd::Version { .. } | Cmd::ProfileShow { .. }
    ) {
        default_signals();
    }
    match cmd {
        Cmd::Help => {
            println!("{}", cli::USAGE);
            0
        }
        Cmd::Version { json } => {
            let data = json!({
                "name": "heimdall-proto",
                "version": heimdall_proto::VERSION,
                "candidate": heimdall_proto::CANDIDATE,
                "runtime": heimdall_proto::RUSTC_VERSION,
                "tui_framework": heimdall_proto::TUI_FRAMEWORK,
                "tui_framework_version": heimdall_proto::TUI_FRAMEWORK_VERSION,
            });
            if json {
                emit(&Envelope::success(Code::VersionOk, data));
            } else {
                println!(
                    "heimdall-proto {} (rust; {}; ratatui {}; crossterm {})",
                    heimdall_proto::VERSION,
                    heimdall_proto::RUSTC_VERSION,
                    heimdall_proto::TUI_FRAMEWORK_VERSION,
                    heimdall_proto::CROSSTERM_VERSION
                );
            }
            0
        }
        Cmd::ProfileShow { file, json } => match profile::load_file(&file) {
            Ok(p) => {
                if json {
                    emit(&p.to_envelope());
                } else {
                    println!("{} (revision {})", p.name, p.revision);
                    for d in &p.destinations {
                        println!("{}  {}@{}:{}", d.alias, d.account, d.host, d.port);
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("heimdall-proto: {}: {}", e.code.as_str(), e.message);
                if json {
                    emit(&e.to_envelope());
                }
                e.code.exit_code()
            }
        },
        Cmd::AgentList {
            socket,
            timeout_ms,
            json,
        } => {
            let cancel = Arc::new(AtomicBool::new(false));
            #[cfg(unix)]
            {
                if let Err(e) =
                    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&cancel))
                {
                    eprintln!(
                        "heimdall-proto: cannot install SIGINT handler: {:?}",
                        e.kind()
                    );
                }
                // A SIGINT that arrived since main() started is delivered now and
                // sets `cancel` before the agent is contacted.
                default_signals();
            }
            #[cfg(windows)]
            {
                let c = Arc::clone(&cancel);
                if ctrlc::set_handler(move || c.store(true, std::sync::atomic::Ordering::SeqCst))
                    .is_err()
                {
                    eprintln!("heimdall-proto: cannot install console control handler");
                }
            }
            let env = match agent::probe(&socket, Duration::from_millis(timeout_ms), &cancel) {
                ProbeOutcome::Cancelled => Envelope::cancelled(),
                ProbeOutcome::Done(Ok(ids)) => {
                    if !json {
                        for i in &ids {
                            println!("{} {} {}", i.key_type, i.fingerprint, i.comment);
                        }
                    }
                    agent::identities_envelope(&ids)
                }
                ProbeOutcome::Done(Err(e)) => e.to_envelope(),
            };
            if env.code != Code::AgentOk {
                eprintln!("heimdall-proto: {}", env.code.as_str());
            }
            if json {
                emit(&env);
            }
            env.exit_code()
        }
        Cmd::Run { meta_file, argv } => {
            let outcome = runner::run(&argv);
            if let Some(d) = &outcome.diagnostic {
                eprintln!("{d}");
            }
            if let Some(path) = meta_file
                && let Err(e) = write_meta(&path, &outcome.meta_envelope().to_line())
            {
                eprintln!("heimdall-proto: cannot write meta file: {:?}", e.kind());
            }
            outcome.process_exit
        }
        Cmd::Tui { file } => tui::main(&file),
    }
}
