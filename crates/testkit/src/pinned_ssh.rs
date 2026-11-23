//! ⟨M07 W7b; ADR-0007 §12.52⟩ `hm-pinned-ssh`: the scratch wrapper that the debug
//! pinned-client redirect (`HEIMDALL_TEST_PINNED_CLIENT`, `crates/heimdall/src/testcfg.rs`)
//! names in place of the verified client `heimdall connect` launches. The program body is
//! [`main`]; `src/bin/hm-pinned-ssh.rs` only calls it.
//!
//! **Why it exists.** On Windows `connect` launches only the in-box
//! `%SystemRoot%\System32\OpenSSH\ssh.exe` (ADR-0004 E6). That client finds the account's
//! profile from its token, so no scratch home can stand in for it, and without `-F` it reads
//! the owner's real `%USERPROFILE%\.ssh\config` (ADR-0007 §9 item 5, §12.49 item 4). In a
//! debug build the redirect points `connect` at a copy of this program in the test's scratch
//! directory instead; this program adds the scratch isolation and starts the **real** in-box
//! client, so the client a test row exercises is still the in-box one.
//!
//! **What it adds, and nothing else.** It reads its sidecar file, `<this program's path with
//! the extension .json>` (written by [`WrapperConfig::install`]), and starts
//!
//! ```text
//! <client> -F <config> -o ControlMaster=no -o ControlPath=none [-o <option>]… <its own arguments>… [<trailing>]…
//! ```
//!
//! * `<client>`: on Windows always `%SystemRoot%\System32\OpenSSH\ssh.exe` (`windir` when
//!   `SystemRoot` is unset), from this process's environment, which `connect` passes on
//!   unchanged; a sidecar that names another client is refused there. On other platforms
//!   the sidecar's `client`, an absolute path (the build host's demonstration runs).
//! * `-F <config>`: the sidecar's `config`, an absolute path of an existing regular file
//!   (the scratch user configuration). Without it the program refuses: it never starts a
//!   client that would read the account's real configuration.
//! * the isolated option set: the sidecar's `options` (each passed as `-o <option>`), which
//!   must name `UserKnownHostsFile` and `GlobalKnownHostsFile` and must not name
//!   `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `HostName`, `User` or `Port`
//!   (ADR-0007 §9 item 1: a command-line value wins over the configuration under test), nor
//!   `ControlMaster` or `ControlPath`, which the program sets itself (no control socket);
//! * its own arguments, exactly as `connect` gave them (the alias, or a managed pair's
//!   options and alias), then the sidecar's `trailing` words (the remote command the Unix
//!   twins' wrappers append, e.g. `true`).
//!
//! The client inherits this program's standard handles, console and environment (as
//! `connect`'s own launch passes them to the client); this program waits and exits with the
//! client's exit code (a Unix signal reads as `128 + signal`). A refusal writes one line
//! `hm-pinned-ssh: refused: <reason>` to stderr (never a value from the sidecar) and exits
//! [`REFUSED`] without starting anything. Ctrl-C is not handled here: a case that types
//! Ctrl-C at the console must not use this wrapper (none does).

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The program name.
pub const NAME: &str = "hm-pinned-ssh";

/// The exit status of a refusal (the program started nothing): the conventional "the
/// wrapper itself failed" status, which `ssh` never uses.
pub const REFUSED: i32 = 125;

/// An environment variable naming the built program explicitly (a native harness that
/// copies the binaries elsewhere; [`locate`]).
pub const ENV_OVERRIDE: &str = "HM_PINNED_SSH";

/// Option names the sidecar must not set (module docs).
const FORBIDDEN: [&str; 8] = [
    "identityagent",
    "identityfile",
    "identitiesonly",
    "hostname",
    "user",
    "port",
    "controlmaster",
    "controlpath",
];

/// Option names the sidecar must set (module docs).
const REQUIRED: [&str; 2] = ["userknownhostsfile", "globalknownhostsfile"];

/// The sidecar's content: what the wrapper adds (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperConfig {
    /// The scratch user configuration, passed as `-F`.
    pub config: PathBuf,
    /// The isolated option set, each passed as `-o <option>` (`Name=value`).
    pub options: Vec<String>,
    /// Words appended after the caller's arguments (a remote command).
    pub trailing: Vec<String>,
    /// The client on platforms other than Windows (absolute); `None` on Windows.
    pub client: Option<PathBuf>,
}

impl WrapperConfig {
    /// The sidecar of the wrapper at `exe`: the same path with the extension `json`.
    #[must_use]
    pub fn sidecar(exe: &Path) -> PathBuf {
        exe.with_extension("json")
    }

    /// The sidecar's JSON text.
    #[must_use]
    pub fn to_json(&self) -> String {
        let text = |p: &Path| serde_json::Value::String(p.to_string_lossy().into_owned());
        let mut v = serde_json::json!({
            "config": text(&self.config),
            "options": self.options,
            "trailing": self.trailing,
        });
        if let Some(client) = &self.client {
            v["client"] = text(client);
        }
        v.to_string()
    }

    /// Parse a sidecar.
    ///
    /// # Errors
    /// Malformed JSON, or a field of the wrong shape (the reason names the field only).
    pub fn parse(text: &str) -> Result<WrapperConfig, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "the sidecar is not JSON".to_owned())?;
        let strings = |name: &str| -> Result<Vec<String>, String> {
            match v.get(name) {
                None => Ok(Vec::new()),
                Some(serde_json::Value::Array(items)) => items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| format!("{name}: expected strings"))
                    })
                    .collect(),
                Some(_) => Err(format!("{name}: expected a list")),
            }
        };
        let path = |name: &str| -> Result<Option<PathBuf>, String> {
            match v.get(name) {
                None => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(PathBuf::from(s))),
                Some(_) => Err(format!("{name}: expected a path")),
            }
        };
        Ok(WrapperConfig {
            config: path("config")?.ok_or_else(|| "no scratch config (-F) named".to_owned())?,
            options: strings("options")?,
            trailing: strings("trailing")?,
            client: path("client")?,
        })
    }

    /// Copy the built wrapper ([`locate`]) into `dir` and write its sidecar there: the
    /// scratch wrapper path the redirect names.
    ///
    /// # Errors
    /// The program is not built, or a copy or write failed.
    pub fn install(&self, dir: &Path) -> io::Result<PathBuf> {
        let built = locate()?;
        let exe = dir.join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&built, &exe)?;
        std::fs::write(WrapperConfig::sidecar(&exe), self.to_json())?;
        Ok(exe)
    }
}

/// The built program: [`ENV_OVERRIDE`] when set, else next to the running test executable
/// (`target/<profile>/`, the parent of `deps/`), as `hook::HookBinary::locate` finds
/// `hm-fixture-hook`.
///
/// # Errors
/// `NotFound`, naming the build command, when it was not built.
pub fn locate() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os(ENV_OVERRIDE).filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "HM_PINNED_SSH does not name a file",
            ))
        };
    }
    let file = format!("{NAME}{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe()?;
    exe.ancestors()
        .skip(1)
        .take(3)
        .map(|d| d.join(&file))
        .find(|c| c.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "hm-pinned-ssh is not built: run `cargo build -p heimdall-testkit --bin hm-pinned-ssh`",
            )
        })
}

/// The option's name in lower case (`Name=value` or `Name value`).
fn option_name(option: &str) -> String {
    option
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// The client this platform's wrapper starts (module docs).
fn client_of(
    config: &WrapperConfig,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, String> {
    if cfg!(windows) {
        if config.client.is_some() {
            return Err("on Windows the client is always the in-box ssh.exe".to_owned());
        }
        let root = env("SystemRoot")
            .or_else(|| env("windir"))
            .ok_or_else(|| "SystemRoot is not set".to_owned())?;
        let client = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        if !client.is_absolute() || !client.is_file() {
            return Err("the in-box ssh.exe is not there".to_owned());
        }
        Ok(client)
    } else {
        let client = config
            .client
            .clone()
            .ok_or_else(|| "no client named".to_owned())?;
        if !client.is_absolute() || !client.is_file() {
            return Err("the client is not an absolute path of a file".to_owned());
        }
        Ok(client)
    }
}

/// What the wrapper at `exe` would start for `args` (its own arguments, after the program
/// name), with `env` as its environment: the client and the client's arguments. Starts
/// nothing.
///
/// # Errors
/// The refusal's reason (module docs); it names no path or value.
pub fn plan(
    exe: &Path,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<(PathBuf, Vec<OsString>), String> {
    let sidecar = WrapperConfig::sidecar(exe);
    let text = std::fs::read_to_string(&sidecar)
        .map_err(|_| "no sidecar: the scratch config (-F) is not named".to_owned())?;
    let config = WrapperConfig::parse(&text)?;
    if !config.config.is_absolute() || !config.config.is_file() {
        return Err("the scratch config (-F) is not an absolute path of a file".to_owned());
    }
    let names: Vec<String> = config.options.iter().map(|o| option_name(o)).collect();
    if let Some(bad) = names.iter().find(|n| FORBIDDEN.contains(&n.as_str())) {
        return Err(format!(
            "the option {bad} would override the configuration under test"
        ));
    }
    if let Some(missing) = REQUIRED.iter().find(|r| !names.iter().any(|n| n == *r)) {
        return Err(format!("the isolated option set lacks {missing}"));
    }
    if config.options.iter().any(|o| !o.contains('=')) {
        return Err("an option is not of the form Name=value".to_owned());
    }
    let client = client_of(&config, env)?;
    let mut argv: Vec<OsString> = vec!["-F".into(), config.config.clone().into_os_string()];
    for fixed in ["ControlMaster=no", "ControlPath=none"] {
        argv.push("-o".into());
        argv.push(fixed.into());
    }
    for option in &config.options {
        argv.push("-o".into());
        argv.push(option.into());
    }
    argv.extend(args.iter().cloned());
    argv.extend(config.trailing.iter().map(OsString::from));
    Ok((client, argv))
}

/// The `hm-pinned-ssh` program (module docs): its exit status.
#[must_use]
pub fn main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Ok(exe) = std::env::current_exe() else {
        return refuse("its own path is unknown");
    };
    match plan(&exe, &args, &|n| std::env::var_os(n)) {
        Err(reason) => refuse(&reason),
        Ok((client, argv)) => match Command::new(client).args(argv).status() {
            Ok(status) => exit_code(status),
            Err(_) => refuse("the client did not start"),
        },
    }
}

fn refuse(reason: &str) -> i32 {
    let mut err = io::stderr();
    let _ = writeln!(err, "{NAME}: refused: {reason}").and_then(|()| err.flush());
    REFUSED
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(REFUSED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// A client file that exists (its content is never run by [`plan`]).
    fn fake_client(dir: &Path) -> PathBuf {
        let p = dir.join(format!("client{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&p, b"not run").unwrap();
        p
    }

    /// An environment whose `SystemRoot` holds a fake in-box client (Windows), else empty.
    fn env_with_inbox(dir: &Path) -> impl Fn(&str) -> Option<OsString> + use<> {
        let root = dir.join("sysroot");
        let openssh = root.join("System32").join("OpenSSH");
        std::fs::create_dir_all(&openssh).unwrap();
        std::fs::write(openssh.join("ssh.exe"), b"not run").unwrap();
        move |n: &str| (n == "SystemRoot").then(|| root.clone().into_os_string())
    }

    fn good(dir: &Path) -> WrapperConfig {
        let config = dir.join("config");
        std::fs::write(&config, b"Host x\n").unwrap();
        WrapperConfig {
            config,
            options: vec![
                format!("UserKnownHostsFile={}", dir.join("kh").display()),
                "GlobalKnownHostsFile=/dev/null".to_owned(),
            ],
            trailing: vec!["true".to_owned()],
            client: (!cfg!(windows)).then(|| fake_client(dir)),
        }
    }

    fn write(dir: &Path, config: &WrapperConfig) -> PathBuf {
        let exe = dir.join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        std::fs::write(WrapperConfig::sidecar(&exe), config.to_json()).unwrap();
        exe
    }

    /// The selftest's first half (ADR-0007 §12.52): the wrapper refuses to start anything
    /// without its scratch config. No sidecar, a sidecar naming no `-F` file, a relative
    /// or missing one, a forbidden or missing isolation option: each is a refusal, and
    /// [`plan`] returns no client to start.
    #[test]
    fn refuses_without_the_scratch_config_or_the_isolated_option_set() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
        assert!(err.contains("scratch config"), "{err}");

        let base = good(d.path());
        let cases: Vec<(&str, WrapperConfig)> = vec![
            (
                "relative -F",
                WrapperConfig {
                    config: PathBuf::from("config"),
                    ..base.clone()
                },
            ),
            (
                "missing -F file",
                WrapperConfig {
                    config: d.path().join("absent"),
                    ..base.clone()
                },
            ),
            (
                "forbidden option",
                WrapperConfig {
                    options: [base.options.clone(), vec!["IdentityAgent=none".into()]].concat(),
                    ..base.clone()
                },
            ),
            (
                "forbidden ControlPath",
                WrapperConfig {
                    options: [base.options.clone(), vec!["controlpath=/x".into()]].concat(),
                    ..base.clone()
                },
            ),
            (
                "no known-hosts isolation",
                WrapperConfig {
                    options: vec!["GlobalKnownHostsFile=/dev/null".into()],
                    ..base.clone()
                },
            ),
        ];
        for (what, config) in cases {
            let exe = write(d.path(), &config);
            assert!(plan(&exe, &["alpha".into()], &env).is_err(), "{what}");
        }
        // A sidecar without a `config` field at all.
        std::fs::write(WrapperConfig::sidecar(&exe), r#"{"options": []}"#).unwrap();
        let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
        assert!(err.contains("-F"), "{err}");
        // Windows: never a client other than the in-box one; elsewhere one is required.
        let other = WrapperConfig {
            client: if cfg!(windows) {
                Some(fake_client(d.path()))
            } else {
                None
            },
            ..base
        };
        let exe = write(d.path(), &other);
        assert!(plan(&exe, &["alpha".into()], &env).is_err());
    }

    /// With the scratch config, the client gets `-F`, the fixed and the isolated options,
    /// the caller's arguments unchanged and then the trailing words; on Windows the
    /// client is `%SystemRoot%\System32\OpenSSH\ssh.exe`.
    #[test]
    fn adds_only_the_isolation_then_the_callers_arguments() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let config = good(d.path());
        let exe = write(d.path(), &config);
        let (client, argv) = plan(&exe, &["-o".into(), "X=y".into(), "alpha".into()], &env)
            .unwrap_or_else(|e| panic!("{e}"));
        if cfg!(windows) {
            assert!(client.ends_with(Path::new("System32/OpenSSH/ssh.exe")));
        } else {
            assert_eq!(Some(client), config.client.clone());
        }
        let text: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut want = vec![
            "-F".to_owned(),
            config.config.display().to_string(),
            "-o".to_owned(),
            "ControlMaster=no".to_owned(),
            "-o".to_owned(),
            "ControlPath=none".to_owned(),
        ];
        for o in &config.options {
            want.push("-o".to_owned());
            want.push(o.clone());
        }
        want.extend(["-o", "X=y", "alpha", "true"].map(str::to_owned));
        assert_eq!(text, want);
        assert_eq!(WrapperConfig::parse(&config.to_json()).unwrap(), config);
    }

    /// The selftest's second half, through the **built** program (`cargo test -p
    /// heimdall-testkit` builds it): installed in a scratch directory without its sidecar,
    /// and again with a sidecar whose `-F` file is gone, it refuses with [`REFUSED`] and
    /// the refusal line, and starts nothing (on Unix the client is a script that leaves a
    /// marker; it stays absent). With the `-F` file back, the same wrapper starts the client:
    /// on Unix the script (the marker appears), on Windows the in-box `ssh.exe -V`
    /// (its version line, never [`REFUSED`]).
    #[test]
    fn the_built_wrapper_refuses_to_run_without_the_scratch_config() {
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        let d = scratch();
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&built, &exe).unwrap();
        let marker = d.path().join("started");
        #[cfg(not(unix))]
        let config = good(d.path());
        #[cfg(unix)]
        let config = {
            use std::os::unix::fs::PermissionsExt as _;
            let script = d.path().join("client.sh");
            std::fs::write(
                &script,
                format!("#!/bin/sh\necho \"$*\" > '{}'\n", marker.display()),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            WrapperConfig {
                client: Some(script),
                ..good(d.path())
            }
        };
        let program_data = d.path().join("programdata");
        std::fs::create_dir_all(&program_data).unwrap();
        let run = |args: &[&str]| {
            let mut cmd = Command::new(&exe);
            cmd.args(args)
                .env_clear()
                .env("ProgramData", &program_data)
                .stdin(std::process::Stdio::null());
            for k in ["SystemRoot", "windir"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
            cmd.output().unwrap()
        };
        let refused = |out: &std::process::Output| {
            let stderr = String::from_utf8_lossy(&out.stderr);
            out.status.code() == Some(REFUSED)
                && stderr.starts_with("hm-pinned-ssh: refused: ")
                && out.stdout.is_empty()
        };
        let out = run(&["alpha"]);
        assert!(refused(&out), "no sidecar: {out:?}");
        std::fs::write(WrapperConfig::sidecar(&exe), config.to_json()).unwrap();
        let bytes = std::fs::read(&config.config).unwrap();
        std::fs::remove_file(&config.config).unwrap();
        let out = run(&["alpha"]);
        assert!(refused(&out), "no -F file: {out:?}");
        assert!(!marker.exists(), "a refusal starts nothing");
        // The control: with the scratch config back, the client starts.
        std::fs::write(&config.config, bytes).unwrap();
        if cfg!(windows) {
            let out = run(&["-V"]);
            assert_ne!(out.status.code(), Some(REFUSED), "{out:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("OpenSSH"),
                "{out:?}"
            );
        } else {
            let out = run(&["alpha"]);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            let seen = std::fs::read_to_string(&marker).unwrap();
            assert!(
                seen.starts_with("-F ") && seen.trim_end().ends_with("alpha true"),
                "{seen}"
            );
        }
    }
}
