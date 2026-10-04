//! Argument parsing (contract §1–§6 command surface). Hand-written to avoid a
//! CLI-framework dependency; paths are kept as OsString so non-UTF-8 and
//! non-ASCII paths pass through unchanged.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub const USAGE: &str = "\
usage:
  heimdall-proto profile show --file <path> [--json]
  heimdall-proto agent list --socket <path> [--timeout-ms N] [--json]
  heimdall-proto run [--meta-file <path>] -- <argv...>
  heimdall-proto tui --file <path>
  heimdall-proto version [--json]";

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    ProfileShow {
        file: PathBuf,
        json: bool,
    },
    AgentList {
        socket: PathBuf,
        timeout_ms: u64,
        json: bool,
    },
    Run {
        meta_file: Option<PathBuf>,
        argv: Vec<OsString>,
    },
    Tui {
        file: PathBuf,
    },
    Version {
        json: bool,
    },
    Help,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UsageError {
    pub message: String,
    /// `--json` was present, so the error is also emitted as a JSON result.
    pub json: bool,
}

/// `--json` anywhere before a `--` separator.
pub fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .take_while(|a| a.as_os_str() != "--")
        .any(|a| a == "--json")
}

pub const DEFAULT_TIMEOUT_MS: u64 = 5000;
const MAX_TIMEOUT_MS: u64 = 3_600_000;

struct Opts {
    values: Vec<(&'static str, OsString)>,
    json: bool,
}

/// Parse `--flag value` pairs and `--json`. `value_flags` take one value each.
fn parse_opts(
    rest: &[OsString],
    value_flags: &[&'static str],
    allow_json: bool,
) -> Result<Opts, String> {
    let mut values: Vec<(&'static str, OsString)> = Vec::new();
    let mut json = false;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_os_str();
        if allow_json && a == "--json" {
            if json {
                return Err("--json given more than once".into());
            }
            json = true;
            i += 1;
            continue;
        }
        let Some(flag) = value_flags.iter().find(|f| a == OsStr::new(f)) else {
            return Err(format!("unexpected argument {}", display_arg(a)));
        };
        if values.iter().any(|(f, _)| f == flag) {
            return Err(format!("{flag} given more than once"));
        }
        let Some(v) = rest.get(i + 1).filter(|v| {
            *v != "--json" && *v != "--" && !value_flags.iter().any(|f| *v == OsStr::new(f))
        }) else {
            return Err(format!("{flag} requires a value"));
        };
        values.push((flag, v.clone()));
        i += 2;
    }
    Ok(Opts { values, json })
}

/// Arguments in diagnostics: flags are echoed (lossy, control characters escaped);
/// they are user-typed, not file content.
fn display_arg(a: &OsStr) -> String {
    format!("{:?}", a.to_string_lossy())
}

impl Opts {
    fn get(&self, flag: &str) -> Option<&OsString> {
        self.values.iter().find(|(f, _)| *f == flag).map(|(_, v)| v)
    }
    fn require(&self, flag: &str) -> Result<PathBuf, String> {
        self.get(flag)
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing required {flag} <path>"))
    }
}

pub fn parse(args: &[OsString]) -> Result<Cmd, UsageError> {
    let json = wants_json(args);
    parse_inner(args).map_err(|message| UsageError { message, json })
}

fn parse_inner(args: &[OsString]) -> Result<Cmd, String> {
    let words: Vec<Option<&str>> = args.iter().map(|a| a.to_str()).collect();
    match words.as_slice() {
        [] => Err("missing subcommand".into()),
        [Some("--help" | "-h" | "help")] => Ok(Cmd::Help),
        [Some("profile"), Some("show"), ..] => {
            let o = parse_opts(&args[2..], &["--file"], true)?;
            Ok(Cmd::ProfileShow {
                file: o.require("--file")?,
                json: o.json,
            })
        }
        [Some("agent"), Some("list"), ..] => {
            let o = parse_opts(&args[2..], &["--socket", "--timeout-ms"], true)?;
            let timeout_ms = match o.get("--timeout-ms") {
                None => DEFAULT_TIMEOUT_MS,
                Some(v) => v
                    .to_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .filter(|n| (1..=MAX_TIMEOUT_MS).contains(n))
                    .ok_or_else(|| {
                        format!("--timeout-ms must be an integer in 1..={MAX_TIMEOUT_MS}")
                    })?,
            };
            Ok(Cmd::AgentList {
                socket: o.require("--socket")?,
                timeout_ms,
                json: o.json,
            })
        }
        [Some("run"), ..] => {
            let rest = &args[1..];
            let Some(sep) = rest.iter().position(|a| a == "--") else {
                return Err("run requires -- before the command".into());
            };
            let o = parse_opts(&rest[..sep], &["--meta-file"], false)?;
            let argv = rest[sep + 1..].to_vec();
            if argv.is_empty() {
                return Err("run requires a command after --".into());
            }
            Ok(Cmd::Run {
                meta_file: o.get("--meta-file").map(PathBuf::from),
                argv,
            })
        }
        [Some("tui"), ..] => {
            let o = parse_opts(&args[1..], &["--file"], false)?;
            Ok(Cmd::Tui {
                file: o.require("--file")?,
            })
        }
        [Some("version"), ..] => {
            let o = parse_opts(&args[1..], &[], true)?;
            Ok(Cmd::Version { json: o.json })
        }
        [Some("profile" | "agent"), ..] => Err("unknown or missing sub-subcommand".into()),
        [first, ..] => Err(format!(
            "unknown subcommand {}",
            first
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| display_arg(&args[0]))
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_commands() {
        assert_eq!(
            parse(&a(&["profile", "show", "--file", "x y/ü.toml", "--json"])).unwrap(),
            Cmd::ProfileShow {
                file: "x y/ü.toml".into(),
                json: true
            }
        );
        assert_eq!(
            parse(&a(&[
                "agent",
                "list",
                "--json",
                "--socket",
                "s",
                "--timeout-ms",
                "250"
            ]))
            .unwrap(),
            Cmd::AgentList {
                socket: "s".into(),
                timeout_ms: 250,
                json: true
            }
        );
        assert_eq!(
            parse(&a(&["agent", "list", "--socket", "s"])).unwrap(),
            Cmd::AgentList {
                socket: "s".into(),
                timeout_ms: 5000,
                json: false
            }
        );
        assert_eq!(
            parse(&a(&["version", "--json"])).unwrap(),
            Cmd::Version { json: true }
        );
        assert_eq!(
            parse(&a(&["tui", "--file", "f"])).unwrap(),
            Cmd::Tui { file: "f".into() }
        );
    }

    #[test]
    fn run_argv_passthrough() {
        let args = a(&[
            "run",
            "--meta-file",
            "m ü.json",
            "--",
            "printf",
            "%s",
            "--json",
            "--",
            "a b",
            "$X;*",
            "\n",
            "ü",
        ]);
        assert_eq!(
            parse(&args).unwrap(),
            Cmd::Run {
                meta_file: Some("m ü.json".into()),
                argv: a(&["printf", "%s", "--json", "--", "a b", "$X;*", "\n", "ü"])
            }
        );
        assert!(!wants_json(&args), "--json after -- belongs to the child");
        assert_eq!(
            parse(&a(&["run", "--", "x"])).unwrap(),
            Cmd::Run {
                meta_file: None,
                argv: a(&["x"])
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_argv_non_utf8() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0x66, 0xff, 0xfe]);
        let args = vec!["run".into(), "--".into(), "printf".into(), bad.clone()];
        match parse(&args).unwrap() {
            Cmd::Run { argv, .. } => assert_eq!(argv[1], bad),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn usage_errors() {
        for (args, json) in [
            (vec![], false),
            (vec!["bogus", "--json"], true),
            (vec!["profile", "show", "--json"], true),
            (vec!["profile", "show", "--file"], false),
            (vec!["profile", "show", "--file", "--json"], true),
            (vec!["profile", "show", "--file", "a", "--file", "b"], false),
            (
                vec!["profile", "show", "--file", "a", "--bogus", "--json"],
                true,
            ),
            (vec!["profile", "list", "--json"], true),
            (
                vec![
                    "agent",
                    "list",
                    "--socket",
                    "s",
                    "--timeout-ms",
                    "0",
                    "--json",
                ],
                true,
            ),
            (
                vec!["agent", "list", "--socket", "s", "--timeout-ms", "x"],
                false,
            ),
            (vec!["run", "x"], false),
            (vec!["run", "--"], false),
            (vec!["run", "--bogus", "--", "x"], false),
            (vec!["tui"], false),
            (vec!["tui", "--file", "f", "--json"], true),
            (vec!["version", "extra"], false),
        ] {
            let e = parse(&a(&args)).unwrap_err();
            assert_eq!(e.json, json, "{args:?}");
        }
    }
}
