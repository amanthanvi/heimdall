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
//! the extension .json>` (written by [`WrapperConfig::install`]), checks the client's
//! effective identity configuration (the identity guard, below), and starts
//!
//! ```text
//! <client> -F <config> -o IdentityAgent=<checked> -o ControlMaster=no -o ControlPath=none [-o <option>]… <its own arguments>… [<trailing>]…
//! ```
//!
//! * `<client>`: on Windows always `%SystemRoot%\System32\OpenSSH\ssh.exe` (`windir` when
//!   `SystemRoot` is unset), from this process's environment, which `connect` passes on
//!   unchanged; a sidecar that names another client is refused there. On other platforms
//!   the sidecar's `client`, an absolute path (the build host's demonstration runs).
//! * `-F <config>`: the sidecar's `config`, an absolute path of an existing regular file
//!   (the scratch user configuration) inside the scratch root. Without it the program
//!   refuses: it never starts a client that would read the account's real configuration.
//! * `-o IdentityAgent=<checked>`: ⟨M07 W7.1⟩ the `identityagent` value the guard accepted,
//!   on the command line ahead of everything else the client reads (the first obtained
//!   value wins), whatever the projected block says. So a configuration that changes between
//!   the check and the start cannot send the client to another agent, and never to the
//!   system pipe. `none` is passed as `none`; a path or pipe name is passed double-quoted
//!   with `\` and `"` escaped (OpenSSH argument splitting), so it reaches the client as
//!   checked.
//! * the isolated option set: the sidecar's `options` (each passed as `-o <option>`), which
//!   must name `UserKnownHostsFile` and `GlobalKnownHostsFile` and must not name
//!   `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`, `HostName`, `User` or `Port`
//!   (ADR-0007 §9 item 1: a command-line value wins over the configuration under test), nor
//!   `ControlMaster` or `ControlPath`, which the program sets itself (no control socket);
//! * its own arguments, exactly as `connect` gave them (the alias, or a managed pair's
//!   options and alias), then the sidecar's `trailing` words (the remote command the Unix
//!   twins' wrappers append, e.g. `true`).
//!
//! **The scratch root.** ⟨M07 W7.1⟩ The sidecar's `scratch_root`: an absolute path of an
//! existing directory that is not a filesystem root and that holds, once resolved, both this
//! program and the `-F` file. The tests name their `ScratchHome::root`: the wrapper sits in
//! `<root>/pinned`, the user configuration in `<root>/home/.ssh`, Heimdall's projection and
//! key files under `<root>/config` and `<root>/state`, Unix fixture sockets in
//! `<root>/s<n>`. A value is *inside the scratch root* when it has no `%`, `$`, leading `~`
//! or control character (nothing the client would expand again), is absolute, does not start
//! with two separators (a UNC or device name; never opened), has no `..` component, lies
//! lexically under the root (as named, resolved, or resolved without Windows' `\\?\`
//! prefix), and its deepest existing ancestor resolves under the resolved root (no symbolic
//! link out). Nothing outside the root is touched while deciding. On Windows a value
//! `/X:/…` (a drive path with a leading slash) is read as `X:/…`.
//!
//! **The identity guard.** ⟨M07 W7.1; ADR-0007 §12.52⟩ On Windows an in-box `ssh.exe` with
//! no `IdentityAgent` uses the system agent pipe `\\.\pipe\openssh-ssh-agent`, which may hold
//! the owner's real keys, and with no `IdentityFile` it loads the account's default identity
//! files. So before it starts the client, the program runs the **same** client once with
//! `-G` (print the effective configuration and exit; it connects to nothing and opens no
//! agent):
//!
//! ```text
//! <client> -G -F <config> -o ControlMaster=no -o ControlPath=none [-o <option>]… <its own arguments>…
//! ```
//!
//! with this program's environment unchanged, as the client gets it (nothing is added, no
//! `SSH_AUTH_SOCK` either), stdin empty, stderr discarded, at most [`CHECK_TIMEOUT`] (then
//! that child, by its handle, is killed) and [`CHECK_OUTPUT_MAX`] bytes. It refuses, starting
//! nothing, unless the run exits 0, prints UTF-8 `<lowercase key> <value>` lines, and they
//! show all of:
//!
//! * exactly one `identitiesonly` line, `yes`;
//! * exactly one `identityagent` line, whose value is `none`, a path inside the scratch root
//!   (a Unix fixture socket), or, on Windows only, a **fixture pipe**:
//!   `\\.\pipe\heimdall-hmtest-<name>` or `//./pipe/heimdall-hmtest-<name>` (ASCII case
//!   ignored), `<name>` one or more ASCII letters, digits, `-`, `_` or `.` (no separator).
//!   That is the form `heimdall_testkit::agent::Endpoint::in_scratch` gives every fixture
//!   agent, proxy and decoy pipe (`\\.\pipe\heimdall-hmtest-<random hex>-agent`), each
//!   created owner-only by the test; it is the agent the A01 and A11 rows' projected block
//!   names. The system pipe, any other pipe, `SSH_AUTH_SOCK` in any spelling, a `%` token
//!   and a path outside the root are refused. No line at all is refused: the client would
//!   fall back to the system pipe;
//! * at least one `identityfile` line, and every one inside the scratch root (so none of the
//!   defaults `~/.ssh/id_*` that `-G` prints when the configuration names none);
//! * a `userknownhostsfile` line whose every (space-separated) entry is inside the scratch
//!   root.
//!
//! A passed check writes one line to stderr, `hm-pinned-ssh: checked: identity agent
//! <kind>`, `<kind>` being `none`, `scratch path` or `fixture pipe` (never the value), then
//! starts the client.
//!
//! The client inherits this program's standard handles, console and environment (as
//! `connect`'s own launch passes them to the client); this program waits and exits with the
//! client's exit code (a Unix signal reads as `128 + signal`). A refusal writes one line
//! `hm-pinned-ssh: refused: <reason>` to stderr (never a value from the sidecar or from the
//! `-G` output) and exits [`REFUSED`] without starting the client. Ctrl-C is not handled
//! here: a case that types Ctrl-C at the console must not use this wrapper (none does).
//!
//! **The test seam.** The guard's `-G` run goes through a function argument (`prepare_with`,
//! private to this module): [`main`] passes the real bounded run of the client; the module's
//! own unit tests pass a closure that returns a chosen `-G` output and records the arguments,
//! so they run on every platform without any `ssh`. No product binary links this crate, and
//! the closure is not reachable from outside the module.

use std::ffi::OsString;
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The program name.
pub const NAME: &str = "hm-pinned-ssh";

/// The exit status of a refusal (the program started nothing): the conventional "the
/// wrapper itself failed" status, which `ssh` never uses.
pub const REFUSED: i32 = 125;

/// An environment variable naming the built program explicitly (a native harness that
/// copies the binaries elsewhere; [`locate`]).
pub const ENV_OVERRIDE: &str = "HM_PINNED_SSH";

/// ⟨M07 W7.1⟩ The longest the guard's `-G` run may take (module docs).
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// ⟨M07 W7.1⟩ The most the guard reads from the `-G` run; more is a refusal.
pub const CHECK_OUTPUT_MAX: usize = 256 * 1024;

/// The fixture pipe prefix the guard accepts on Windows (module docs). The same text as
/// `agent::FIXTURE_PIPE_PREFIX`, which needs the `fixtures` feature this module does not.
const FIXTURE_PIPE_PREFIX: &str = "heimdall-hmtest-";

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
    /// ⟨M07 W7.1⟩ The scratch root (module docs): every identity, agent and known-hosts
    /// path the client may use lies inside it.
    pub scratch_root: PathBuf,
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
            "scratch_root": text(&self.scratch_root),
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
            scratch_root: path("scratch_root")?
                .ok_or_else(|| "no scratch root named".to_owned())?,
            options: strings("options")?,
            trailing: strings("trailing")?,
            client: path("client")?,
        })
    }

    /// Copy the built wrapper ([`locate`]) into `dir` and write its sidecar there: the
    /// scratch wrapper path the redirect names. `dir` must be inside `scratch_root`, or the
    /// installed program refuses.
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

/// ⟨M07 W7.1⟩ The scratch root, resolved (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Root {
    /// The resolved root.
    canonical: PathBuf,
    /// The forms a value may lie lexically under: as named, resolved, and resolved without
    /// Windows' `\\?\` prefix.
    forms: Vec<PathBuf>,
}

impl Root {
    fn new(named: &Path) -> Result<Root, String> {
        if !named.is_absolute() {
            return Err("the scratch root is not an absolute path".to_owned());
        }
        let canonical = std::fs::canonicalize(named)
            .ok()
            .filter(|c| c.is_dir())
            .ok_or_else(|| "the scratch root is not a directory".to_owned())?;
        if canonical.parent().is_none() {
            return Err("the scratch root is a filesystem root".to_owned());
        }
        let mut forms = vec![named.to_path_buf(), canonical.clone()];
        let text = canonical.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\")
            && rest.as_bytes().get(1) == Some(&b':')
        {
            forms.push(PathBuf::from(rest));
        }
        forms.dedup();
        Ok(Root { canonical, forms })
    }

    /// Whether an existing file resolves under the root.
    fn holds_file(&self, path: &Path) -> bool {
        std::fs::canonicalize(path).is_ok_and(|c| c.starts_with(&self.canonical))
    }

    /// Whether a value from the `-G` output is inside the root (module docs).
    fn holds(&self, value: &str, windows: bool) -> bool {
        if value.is_empty()
            || value.contains(['%', '$'])
            || value.starts_with('~')
            || value.chars().any(char::is_control)
        {
            return false;
        }
        let mut text = value;
        if windows
            && let Some(rest) = text.strip_prefix('/')
            && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && rest.as_bytes().get(1) == Some(&b':')
        {
            text = rest;
        }
        let separator = |c: char| c == '/' || c == '\\';
        let mut chars = text.chars();
        if chars.next().is_some_and(separator) && chars.next().is_some_and(separator) {
            return false;
        }
        let path = Path::new(text);
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || !self.forms.iter().any(|r| path.starts_with(r))
        {
            return false;
        }
        // Lexically inside: resolve the deepest existing ancestor.
        let mut probe = path;
        loop {
            match std::fs::canonicalize(probe) {
                Ok(c) => return c.starts_with(&self.canonical),
                Err(_) => match probe.parent() {
                    Some(parent) => probe = parent,
                    None => return false,
                },
            }
        }
    }
}

/// ⟨M07 W7.1⟩ Whether `value` is a fixture pipe (module docs).
fn fixture_pipe(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower
        .strip_prefix(r"\\.\pipe\")
        .or_else(|| lower.strip_prefix("//./pipe/"))
        .and_then(|name| name.strip_prefix(FIXTURE_PIPE_PREFIX))
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

/// ⟨M07 W7.1⟩ The agent the guard accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Agent {
    None,
    ScratchPath(String),
    FixturePipe(String),
}

impl Agent {
    /// What the passed-check line names (never the value).
    fn kind(&self) -> &'static str {
        match self {
            Agent::None => "none",
            Agent::ScratchPath(_) => "scratch path",
            Agent::FixturePipe(_) => "fixture pipe",
        }
    }

    /// The `IdentityAgent=<value>` option the client gets (module docs).
    fn option(&self) -> String {
        match self {
            Agent::None => "IdentityAgent=none".to_owned(),
            Agent::ScratchPath(v) | Agent::FixturePipe(v) => {
                format!(
                    "IdentityAgent=\"{}\"",
                    v.replace('\\', r"\\").replace('"', "\\\"")
                )
            }
        }
    }
}

/// ⟨M07 W7.1⟩ The guard over the `-G` output `text` (module docs): the accepted agent.
///
/// # Errors
/// The refusal's reason; it names no value.
fn check_effective(text: &str, root: &Root, windows: bool) -> Result<Agent, String> {
    let mut only = Vec::new();
    let mut agents = Vec::new();
    let mut files = Vec::new();
    let mut known = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        let value = unquote(value.trim());
        match key {
            "identitiesonly" => only.push(value),
            "identityagent" => agents.push(value),
            "identityfile" => files.push(value),
            "userknownhostsfile" => known.push(value),
            _ => {}
        }
    }
    let refuse = |reason: &str| Err(format!("the effective configuration: {reason}"));
    if only.as_slice() != ["yes"] {
        return refuse("IdentitiesOnly is not yes");
    }
    let [agent] = agents.as_slice() else {
        return refuse("IdentityAgent is not set once (the client would use the system agent)");
    };
    let agent = if *agent == "none" {
        Agent::None
    } else if windows && fixture_pipe(agent) {
        Agent::FixturePipe((*agent).to_owned())
    } else if root.holds(agent, windows) {
        Agent::ScratchPath((*agent).to_owned())
    } else if agent.to_ascii_lowercase().contains("pipe") {
        return refuse("IdentityAgent names a pipe that is not a fixture's");
    } else {
        return refuse("IdentityAgent is not none, a fixture pipe or inside the scratch root");
    };
    if files.is_empty() {
        return refuse("no IdentityFile is set");
    }
    for file in &files {
        if file.starts_with("~/.ssh/id_") || file.starts_with(r"~\.ssh\id_") {
            return refuse("an IdentityFile is a default identity (~/.ssh/id_*)");
        }
        if !root.holds(file, windows) {
            return refuse("an IdentityFile is outside the scratch root");
        }
    }
    let [known] = known.as_slice() else {
        return refuse("UserKnownHostsFile is not set once");
    };
    let entries: Vec<&str> = known.split_whitespace().map(unquote).collect();
    if entries.is_empty() || !entries.iter().all(|e| root.holds(e, windows)) {
        return refuse("a UserKnownHostsFile is outside the scratch root");
    }
    Ok(agent)
}

/// A value without one pair of surrounding double quotes.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// What the wrapper at `exe` would do for `args` (its own arguments, after the program name),
/// with `env` as its environment, before the guard: the client and its arguments (module
/// docs). Starts nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The client.
    pub client: PathBuf,
    config: OsString,
    /// `-o` and an option, in pairs: the fixed options, then the sidecar's.
    options: Vec<OsString>,
    args: Vec<OsString>,
    trailing: Vec<OsString>,
    root: Root,
}

impl Launch {
    /// The guard's `-G` run's arguments (module docs).
    #[must_use]
    pub fn check_argv(&self) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec!["-G".into(), "-F".into(), self.config.clone()];
        argv.extend(self.options.iter().cloned());
        argv.extend(self.args.iter().cloned());
        argv
    }

    /// The client's arguments once the guard accepted `agent` (module docs).
    fn client_argv(&self, agent: &Agent) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec![
            "-F".into(),
            self.config.clone(),
            "-o".into(),
            agent.option().into(),
        ];
        argv.extend(self.options.iter().cloned());
        argv.extend(self.args.iter().cloned());
        argv.extend(self.trailing.iter().cloned());
        argv
    }
}

/// What the wrapper at `exe` would start for `args`, before the identity guard ([`Launch`]).
/// Starts nothing.
///
/// # Errors
/// The refusal's reason (module docs); it names no path or value.
pub fn plan(
    exe: &Path,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Launch, String> {
    let sidecar = WrapperConfig::sidecar(exe);
    let text = std::fs::read_to_string(&sidecar)
        .map_err(|_| "no sidecar: the scratch config (-F) is not named".to_owned())?;
    let config = WrapperConfig::parse(&text)?;
    if !config.config.is_absolute() || !config.config.is_file() {
        return Err("the scratch config (-F) is not an absolute path of a file".to_owned());
    }
    let root = Root::new(&config.scratch_root)?;
    if !root.holds_file(exe) {
        return Err("the program is not inside the scratch root".to_owned());
    }
    if !root.holds_file(&config.config) {
        return Err("the scratch config (-F) is not inside the scratch root".to_owned());
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
    let mut options: Vec<OsString> = Vec::new();
    for option in ["ControlMaster=no", "ControlPath=none"]
        .into_iter()
        .chain(config.options.iter().map(String::as_str))
    {
        options.push("-o".into());
        options.push(option.into());
    }
    Ok(Launch {
        client,
        config: config.config.into_os_string(),
        options,
        args: args.to_vec(),
        trailing: config.trailing.iter().map(OsString::from).collect(),
        root,
    })
}

/// The guard's `-G` run: the client's standard output, or the refusal's reason.
type CheckRun<'a> = &'a dyn Fn(&Path, &[OsString]) -> Result<Vec<u8>, String>;

/// [`plan`], then the identity guard through `run` (module docs, "The test seam"): the client,
/// its arguments, and the accepted agent's kind.
fn prepare_with(
    exe: &Path,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    run: CheckRun<'_>,
) -> Result<(PathBuf, Vec<OsString>, &'static str), String> {
    let launch = plan(exe, args, env)?;
    let out = run(&launch.client, &launch.check_argv())?;
    let text = String::from_utf8(out)
        .map_err(|_| "ssh -G printed something that is not text".to_owned())?;
    let agent = check_effective(&text, &launch.root, cfg!(windows))?;
    let argv = launch.client_argv(&agent);
    Ok((launch.client, argv, agent.kind()))
}

/// The guard's real `-G` run (module docs): the client with `argv`, this process's
/// environment, stdin empty, stderr discarded, bounded by `timeout` and
/// [`CHECK_OUTPUT_MAX`]. A run past `timeout` is killed (that child only, by its handle).
fn run_check(client: &Path, argv: &[OsString], timeout: Duration) -> Result<Vec<u8>, String> {
    let mut child = Command::new(client)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "ssh -G did not start".to_owned())?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("ssh -G has no output".to_owned());
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let read = stdout
            .take(CHECK_OUTPUT_MAX as u64 + 1)
            .read_to_end(&mut buf);
        let _ = tx.send(read.map(|_| buf));
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ssh -G did not finish in time".to_owned());
            }
        }
    };
    // The output's reader ends at the client's exit (or a grandchild holding the pipe: the
    // same deadline bounds it).
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(100));
    let buf = match rx.recv_timeout(left) {
        Ok(Ok(buf)) => buf,
        Ok(Err(_)) => return Err("ssh -G output could not be read".to_owned()),
        Err(_) => return Err("ssh -G did not finish in time".to_owned()),
    };
    if !status.success() {
        return Err("ssh -G failed".to_owned());
    }
    if buf.len() > CHECK_OUTPUT_MAX {
        return Err("ssh -G printed too much".to_owned());
    }
    Ok(buf)
}

/// The `hm-pinned-ssh` program (module docs): its exit status.
#[must_use]
pub fn main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Ok(exe) = std::env::current_exe() else {
        return refuse("its own path is unknown");
    };
    let run = |client: &Path, argv: &[OsString]| run_check(client, argv, CHECK_TIMEOUT);
    match prepare_with(&exe, &args, &|n| std::env::var_os(n), &run) {
        Err(reason) => refuse(&reason),
        Ok((client, argv, kind)) => {
            let mut err = io::stderr();
            let _ =
                writeln!(err, "{NAME}: checked: identity agent {kind}").and_then(|()| err.flush());
            match Command::new(client).args(argv).status() {
                Ok(status) => exit_code(status),
                Err(_) => refuse("the client did not start"),
            }
        }
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
    use std::cell::RefCell;

    use super::*;

    const SYSTEM_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// An `ssh_config` argument: double-quoted, `\` and `"` escaped.
    fn q(path: &Path) -> String {
        format!(
            "\"{}\"",
            path.display()
                .to_string()
                .replace('\\', r"\\")
                .replace('"', "\\\"")
        )
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

    /// A sidecar whose scratch configuration names only scratch identities (`IdentityAgent
    /// none`, `IdentityFile <dir>/k`, `IdentitiesOnly yes`): the real in-box client's `-G`
    /// passes the guard with it.
    fn good(dir: &Path) -> WrapperConfig {
        let config = dir.join("config");
        std::fs::write(
            &config,
            format!(
                "Host *\n    IdentityAgent none\n    IdentityFile {}\n    IdentitiesOnly yes\n",
                q(&dir.join("k"))
            ),
        )
        .unwrap();
        WrapperConfig {
            config,
            scratch_root: dir.to_path_buf(),
            options: vec![
                format!("UserKnownHostsFile={}", q(&dir.join("kh"))),
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

    /// A `-G` output that passes the guard, with `agent` as the `identityagent` value.
    fn g_output(root: &Path, agent: &str) -> String {
        format!(
            "user x\nidentitiesonly yes\nidentityagent {agent}\nidentityfile {}\nuserknownhostsfile {}\n",
            root.join("k").display(),
            root.join("kh").display()
        )
    }

    /// `g_output` with every line whose key is `key` replaced by `line` (or removed when
    /// `line` is empty).
    fn with_line(text: &str, key: &str, line: &str) -> String {
        let mut out: Vec<&str> = text
            .lines()
            .filter(|l| l.split(' ').next() != Some(key))
            .collect();
        if !line.is_empty() {
            out.push(line);
        }
        out.join("\n") + "\n"
    }

    fn check(root: &Path, text: &str, windows: bool) -> Result<Agent, String> {
        check_effective(text, &Root::new(root).unwrap(), windows)
    }

    /// The selftest's first half (ADR-0007 §12.52): the wrapper refuses to start anything
    /// without its scratch config. No sidecar, a sidecar naming no `-F` file, a relative
    /// or missing one, a forbidden or missing isolation option, ⟨M07 W7.1⟩ no scratch root,
    /// a relative one, a filesystem root, one that does not hold the `-F` file or the
    /// program: each is a refusal, and [`plan`] returns no client to start.
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
        let elsewhere = scratch();
        let other_config = elsewhere.path().join("config");
        std::fs::write(&other_config, b"Host x\n").unwrap();
        let fs_root = d.path().ancestors().last().unwrap().to_path_buf();
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
            (
                "relative scratch root",
                WrapperConfig {
                    scratch_root: PathBuf::from("scratch"),
                    ..base.clone()
                },
            ),
            (
                "missing scratch root",
                WrapperConfig {
                    scratch_root: d.path().join("absent"),
                    ..base.clone()
                },
            ),
            (
                "a filesystem root as the scratch root",
                WrapperConfig {
                    scratch_root: fs_root,
                    ..base.clone()
                },
            ),
            (
                "-F outside the scratch root",
                WrapperConfig {
                    config: other_config,
                    ..base.clone()
                },
            ),
            (
                "the program outside the scratch root",
                WrapperConfig {
                    scratch_root: elsewhere.path().to_path_buf(),
                    config: elsewhere.path().join("config"),
                    ..base.clone()
                },
            ),
        ];
        for (what, config) in cases {
            let exe = write(d.path(), &config);
            assert!(plan(&exe, &["alpha".into()], &env).is_err(), "{what}");
        }
        // A sidecar without a `config` field at all, or without a `scratch_root`.
        std::fs::write(WrapperConfig::sidecar(&exe), r#"{"options": []}"#).unwrap();
        let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
        assert!(err.contains("-F"), "{err}");
        let mut v: serde_json::Value = serde_json::from_str(&base.to_json()).unwrap();
        v.as_object_mut().unwrap().remove("scratch_root");
        std::fs::write(WrapperConfig::sidecar(&exe), v.to_string()).unwrap();
        let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
        assert!(err.contains("scratch root"), "{err}");
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

    /// With the scratch config, the guard's `-G` run gets `-G`, `-F`, the fixed and the
    /// isolated options and the caller's arguments (no trailing words); once it passes, the
    /// client gets `-F`, ⟨M07 W7.1⟩ the checked `-o IdentityAgent=…`, the fixed and the
    /// isolated options, the caller's arguments unchanged and then the trailing words; on
    /// Windows the client is `%SystemRoot%\System32\OpenSSH\ssh.exe`.
    #[test]
    fn adds_only_the_isolation_then_the_callers_arguments() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let config = good(d.path());
        let exe = write(d.path(), &config);
        let seen = RefCell::new(Vec::new());
        let run = |client: &Path, argv: &[OsString]| {
            seen.borrow_mut()
                .push((client.to_path_buf(), argv.to_vec()));
            Ok(g_output(d.path(), "none").into_bytes())
        };
        let (client, argv, kind) = prepare_with(
            &exe,
            &["-o".into(), "X=y".into(), "alpha".into()],
            &env,
            &run,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(kind, "none");
        if cfg!(windows) {
            assert!(client.ends_with(Path::new("System32/OpenSSH/ssh.exe")));
        } else {
            assert_eq!(Some(client.clone()), config.client.clone());
        }
        let text = |argv: &[OsString]| -> Vec<String> {
            argv.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let mut options = vec![
            "-o".to_owned(),
            "ControlMaster=no".to_owned(),
            "-o".to_owned(),
            "ControlPath=none".to_owned(),
        ];
        for o in &config.options {
            options.push("-o".to_owned());
            options.push(o.clone());
        }
        let caller = ["-o", "X=y", "alpha"].map(str::to_owned);
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 1, "one -G run");
        assert_eq!(seen[0].0, client, "the -G run uses the same client");
        let mut want_check = vec![
            "-G".to_owned(),
            "-F".to_owned(),
            config.config.display().to_string(),
        ];
        want_check.extend(options.iter().cloned());
        want_check.extend(caller.iter().cloned());
        assert_eq!(text(&seen[0].1), want_check);
        let mut want = vec![
            "-F".to_owned(),
            config.config.display().to_string(),
            "-o".to_owned(),
            "IdentityAgent=none".to_owned(),
        ];
        want.extend(options);
        want.extend(caller);
        want.push("true".to_owned());
        assert_eq!(text(&argv), want);
        assert_eq!(WrapperConfig::parse(&config.to_json()).unwrap(), config);
    }

    /// ⟨M07 W7.1⟩ The guard refuses unless `-G` shows `identitiesonly yes` exactly once:
    /// `no`, a missing line and a doubled line are refusals.
    #[test]
    fn guard_refuses_unless_identities_only_is_yes() {
        let d = scratch();
        let good = g_output(d.path(), "none");
        assert_eq!(check(d.path(), &good, false), Ok(Agent::None));
        for (what, text) in [
            (
                "no",
                with_line(&good, "identitiesonly", "identitiesonly no"),
            ),
            ("missing", with_line(&good, "identitiesonly", "")),
            ("twice", format!("{good}identitiesonly yes\n")),
        ] {
            let err = check(d.path(), &text, false).unwrap_err();
            assert!(err.contains("IdentitiesOnly"), "{what}: {err}");
        }
    }

    /// ⟨M07 W7.1⟩ The guard refuses an `identityagent` that is missing (the client would use
    /// the system agent), doubled, `SSH_AUTH_SOCK` in any spelling, a `%` token, relative,
    /// a path outside the scratch root, a `..` way out of it, or (Unix) a symbolic link out.
    #[test]
    fn guard_refuses_an_identity_agent_that_is_missing_or_outside_scratch() {
        let d = scratch();
        let outside = scratch();
        let good = g_output(d.path(), "none");
        let agent_line = |v: &str| with_line(&good, "identityagent", &format!("identityagent {v}"));
        let mut cases = vec![
            ("missing", with_line(&good, "identityagent", "")),
            ("twice", format!("{good}identityagent none\n")),
            ("SSH_AUTH_SOCK", agent_line("SSH_AUTH_SOCK")),
            ("$SSH_AUTH_SOCK", agent_line("$SSH_AUTH_SOCK")),
            ("${SSH_AUTH_SOCK}", agent_line("${SSH_AUTH_SOCK}")),
            (
                "token",
                agent_line(&format!("{}/%d.sock", d.path().display())),
            ),
            ("tilde", agent_line("~/agent.sock")),
            ("relative", agent_line("agent.sock")),
            (
                "outside",
                agent_line(&outside.path().join("agent.sock").display().to_string()),
            ),
            (
                "dot-dot",
                agent_line(&format!(
                    "{}/../{}/agent.sock",
                    d.path().display(),
                    outside.path().file_name().unwrap().to_string_lossy()
                )),
            ),
            ("NONE is not none", agent_line("NONE")),
        ];
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), d.path().join("out")).unwrap();
        if cfg!(unix) {
            cases.push((
                "symlink out",
                agent_line(
                    &d.path()
                        .join("out")
                        .join("agent.sock")
                        .display()
                        .to_string(),
                ),
            ));
        }
        for windows in [false, true] {
            for (what, text) in &cases {
                let err = check(d.path(), text, windows).unwrap_err();
                assert!(err.contains("IdentityAgent"), "{what} ({windows}): {err}");
            }
        }
        // A path inside the root is accepted, on either platform's reading.
        let inside = d.path().join("s0").join("agent.sock").display().to_string();
        assert_eq!(
            check(d.path(), &agent_line(&inside), false),
            Ok(Agent::ScratchPath(inside))
        );
    }

    /// ⟨M07 W7.1⟩ The guard refuses when `-G` reports the system agent pipe
    /// `\\.\pipe\openssh-ssh-agent` (in either spelling, any case, on either platform's
    /// reading), any pipe that is not a fixture's, or a fixture name with a separator; and
    /// through the wrapper's steps the client is then never started: only the `-G` run ran.
    #[test]
    fn guard_refuses_the_system_agent_pipe() {
        let d = scratch();
        let good = g_output(d.path(), "none");
        let agent_line = |v: &str| with_line(&good, "identityagent", &format!("identityagent {v}"));
        for value in [
            SYSTEM_PIPE,
            "//./pipe/openssh-ssh-agent",
            r"\\.\PIPE\OpenSSH-SSH-Agent",
            r"\\.\pipe\heimdall-hmtest-",
            r"\\.\pipe\heimdall-hmtest-x\..\openssh-ssh-agent",
            "//./pipe/heimdall-hmtest-x/../openssh-ssh-agent",
            r"\\.\pipe\heimdall-1234-binding",
            r"\\?\pipe\heimdall-hmtest-x",
            r"\\server\pipe\heimdall-hmtest-x",
        ] {
            for windows in [false, true] {
                let err = check(d.path(), &agent_line(value), windows).unwrap_err();
                assert!(err.contains("IdentityAgent"), "{value} ({windows}): {err}");
            }
        }
        // Through `prepare_with`: the refusal comes before the client.
        let env = env_with_inbox(d.path());
        let exe = write(d.path(), &self::good(d.path()));
        let runs = RefCell::new(0);
        let run = |_: &Path, argv: &[OsString]| {
            *runs.borrow_mut() += 1;
            assert_eq!(argv.first().map(OsString::as_os_str), Some("-G".as_ref()));
            Ok(agent_line(SYSTEM_PIPE).into_bytes())
        };
        let err = prepare_with(&exe, &["alpha".into()], &env, &run).unwrap_err();
        assert!(err.contains("IdentityAgent"), "{err}");
        assert!(!err.contains("openssh"), "the reason names no value: {err}");
        assert_eq!(runs.into_inner(), 1, "only the -G run");
    }

    /// ⟨M07 W7.1⟩ The guard refuses an `identityfile` outside the scratch root, a default
    /// `~/.ssh/id_*` one (as `-G` prints them when the configuration names none), one that
    /// leaves the root through `..`, a UNC name, and an output with no `identityfile` at
    /// all; one bad entry among good ones is enough.
    #[test]
    fn guard_refuses_identity_files_outside_scratch_or_default() {
        let d = scratch();
        let outside = scratch();
        let good = g_output(d.path(), "none");
        let inside = format!("identityfile {}", d.path().join("k").display());
        let file = |v: &str| {
            with_line(
                &good,
                "identityfile",
                &format!("{inside}\nidentityfile {v}"),
            )
        };
        let cases = [
            ("none", with_line(&good, "identityfile", "")),
            (
                "outside",
                file(&outside.path().join("id_ed25519").display().to_string()),
            ),
            ("default", file("~/.ssh/id_ed25519")),
            (
                "default only",
                with_line(&good, "identityfile", "identityfile ~/.ssh/id_rsa"),
            ),
            (
                "dot-dot",
                file(&format!("{}/../x/id_ed25519", d.path().display())),
            ),
            ("unc", file(r"\\server\share\id_ed25519")),
            ("token", file(&format!("{}/%u", d.path().display()))),
        ];
        for windows in [false, true] {
            for (what, text) in &cases {
                let err = check(d.path(), text, windows).unwrap_err();
                assert!(err.contains("IdentityFile"), "{what} ({windows}): {err}");
            }
        }
        let err = check(d.path(), &cases[2].1, false).unwrap_err();
        assert!(err.contains("default identity"), "{err}");
    }

    /// ⟨M07 W7.1⟩ The guard refuses a `userknownhostsfile` entry outside the scratch root
    /// (the only one, or the second of two), and an output with none.
    #[test]
    fn guard_refuses_known_hosts_outside_scratch() {
        let d = scratch();
        let outside = scratch();
        let good = g_output(d.path(), "none");
        let kh = d.path().join("kh").display().to_string();
        let far = outside.path().join("known_hosts").display().to_string();
        for (what, line) in [
            ("outside", format!("userknownhostsfile {far}")),
            ("second outside", format!("userknownhostsfile {kh} {far}")),
            (
                "default",
                "userknownhostsfile ~/.ssh/known_hosts".to_owned(),
            ),
            ("missing", String::new()),
        ] {
            let text = with_line(&good, "userknownhostsfile", &line);
            let err = check(d.path(), &text, false).unwrap_err();
            assert!(err.contains("UserKnownHostsFile"), "{what}: {err}");
        }
    }

    /// ⟨M07 W7.1⟩ The guard refuses when its `-G` run fails (the run's error is the
    /// refusal), prints something that is not UTF-8, or prints nothing; the client is never
    /// started.
    #[test]
    fn guard_refuses_when_the_check_fails() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let exe = write(d.path(), &good(d.path()));
        let failing = |_: &Path, _: &[OsString]| Err("ssh -G failed".to_owned());
        assert_eq!(
            prepare_with(&exe, &["alpha".into()], &env, &failing),
            Err("ssh -G failed".to_owned())
        );
        let binary = |_: &Path, _: &[OsString]| Ok(vec![0xff, 0xfe, b'\n']);
        assert!(prepare_with(&exe, &["alpha".into()], &env, &binary).is_err());
        let empty = |_: &Path, _: &[OsString]| Ok(Vec::new());
        let err = prepare_with(&exe, &["alpha".into()], &env, &empty).unwrap_err();
        assert!(err.contains("IdentitiesOnly"), "{err}");
    }

    /// ⟨M07 W7.1⟩ The accepted agents, and the client's explicit `-o IdentityAgent=<value>`:
    /// `none` as `none`; a scratch path, and on Windows a fixture pipe in either spelling,
    /// double-quoted with `\` escaped, right after `-F <config>`, whatever else follows.
    /// On the non-Windows reading a fixture pipe name is not accepted.
    #[test]
    fn guard_accepts_fixture_agents_and_passes_the_checked_identity_agent() {
        let d = scratch();
        let socket = d.path().join("s0").join("agent.sock").display().to_string();
        let pipe = r"\\.\pipe\heimdall-hmtest-0a1b2c3d4e5f6a7b-agent";
        let slashes = "//./pipe/Heimdall-HMTEST-0a1b2c3d4e5f6a7b-proxy";
        assert_eq!(
            check(d.path(), &g_output(d.path(), "none"), true),
            Ok(Agent::None)
        );
        assert_eq!(
            check(d.path(), &g_output(d.path(), &socket), false),
            Ok(Agent::ScratchPath(socket.clone()))
        );
        assert_eq!(
            check(d.path(), &g_output(d.path(), pipe), true),
            Ok(Agent::FixturePipe(pipe.to_owned()))
        );
        assert_eq!(
            check(d.path(), &g_output(d.path(), slashes), true),
            Ok(Agent::FixturePipe(slashes.to_owned()))
        );
        assert!(check(d.path(), &g_output(d.path(), pipe), false).is_err());
        assert_eq!(
            Agent::FixturePipe(pipe.to_owned()).option(),
            r#"IdentityAgent="\\\\.\\pipe\\heimdall-hmtest-0a1b2c3d4e5f6a7b-agent""#
        );
        assert_eq!(
            Agent::ScratchPath(r#"/s/a"b"#.to_owned()).option(),
            r#"IdentityAgent="/s/a\"b""#
        );
        // Through `prepare_with`: the platform's accepted value reaches the client.
        let env = env_with_inbox(d.path());
        let exe = write(d.path(), &good(d.path()));
        let value = if cfg!(windows) { pipe } else { socket.as_str() };
        let run = |_: &Path, _: &[OsString]| Ok(g_output(d.path(), value).into_bytes());
        let (_, argv, kind) =
            prepare_with(&exe, &["alpha".into()], &env, &run).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            kind,
            if cfg!(windows) {
                "fixture pipe"
            } else {
                "scratch path"
            }
        );
        let want = format!(
            "IdentityAgent=\"{}\"",
            value.replace('\\', r"\\").replace('"', "\\\"")
        );
        assert_eq!(argv[2], OsString::from("-o"));
        assert_eq!(argv[3], OsString::from(want));
    }

    /// The fixture pipe prefix is the fixtures' own.
    #[cfg(feature = "fixtures")]
    #[test]
    fn fixture_pipe_prefix_is_the_fixtures() {
        assert_eq!(FIXTURE_PIPE_PREFIX, crate::agent::FIXTURE_PIPE_PREFIX);
    }

    /// ⟨M07 W7.1⟩ The real `-G` run (Unix: a script client): a run past its time is killed
    /// and refused, a non-zero exit is refused, and the output comes back otherwise; the
    /// run gets this process's environment unchanged (no `SSH_AUTH_SOCK` added).
    #[cfg(unix)]
    #[test]
    fn the_check_run_is_bounded() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = scratch();
        let script = |name: &str, body: &str| {
            let p = d.path().join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let slow = script("slow", "exec sleep 30");
        let started = Instant::now();
        assert_eq!(
            run_check(&slow, &[], Duration::from_millis(300)),
            Err("ssh -G did not finish in time".to_owned())
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let failing = script("failing", "echo identitiesonly yes; exit 3");
        assert_eq!(
            run_check(&failing, &[], CHECK_TIMEOUT),
            Err("ssh -G failed".to_owned())
        );
        let echo = script("echo", "printf '%s|%s\\n' \"$*\" \"${SSH_AUTH_SOCK+set}\"");
        let want = format!(
            "-G x|{}\n",
            if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                "set"
            } else {
                ""
            }
        );
        assert_eq!(
            run_check(&echo, &["-G".into(), "x".into()], CHECK_TIMEOUT),
            Ok(want.into_bytes())
        );
    }

    /// The selftest's second half, through the **built** program (`cargo test -p
    /// heimdall-testkit` builds it): installed in a scratch directory without its sidecar,
    /// and again with a sidecar whose `-F` file is gone, it refuses with [`REFUSED`] and
    /// the refusal line, and starts nothing (on Unix the client is a script that leaves a
    /// marker; it stays absent). ⟨M07 W7.1⟩ On Unix the script also answers `-G` with a
    /// chosen output: reporting the system pipe, or failing, is a refusal and the marker
    /// stays absent. With all of it back, the same wrapper writes the passed-check line and
    /// starts the client with `-o IdentityAgent=none` right after `-F`: on Unix the script
    /// (the marker appears), on Windows the real in-box `ssh.exe` (the guard's `-G` and the
    /// client's own `-G alpha` print the effective configuration; no connection), whose
    /// output shows `identityagent none`, never [`REFUSED`].
    #[test]
    fn the_built_wrapper_refuses_to_run_without_the_scratch_config() {
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        let d = scratch();
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&built, &exe).unwrap();
        let marker = d.path().join("started");
        let g_file = d.path().join("g.out");
        #[cfg(not(unix))]
        let config = good(d.path());
        #[cfg(unix)]
        let config = {
            use std::os::unix::fs::PermissionsExt as _;
            let script = d.path().join("client.sh");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = -G ]; then cat '{}' || exit 3; exit 0; fi\necho \"$*\" > '{}'\n",
                    g_file.display(),
                    marker.display()
                ),
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
                && stderr.lines().count() == 1
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
        std::fs::write(&config.config, bytes).unwrap();
        if cfg!(windows) {
            // The control: the real in-box client, its effective configuration twice.
            let out = run(&["-G", "alpha"]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr)
                    .contains("hm-pinned-ssh: checked: identity agent none"),
                "{out:?}"
            );
            assert!(stdout.lines().any(|l| l == "identityagent none"), "{out:?}");
        } else {
            // `-G` reports the system pipe: refused, nothing started.
            std::fs::write(&g_file, g_output(d.path(), SYSTEM_PIPE)).unwrap();
            let out = run(&["alpha"]);
            assert!(refused(&out), "the system pipe: {out:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("IdentityAgent"),
                "{out:?}"
            );
            assert!(!marker.exists(), "a refusal starts nothing");
            // `-G` fails: refused, nothing started.
            std::fs::remove_file(&g_file).unwrap();
            let out = run(&["alpha"]);
            assert!(refused(&out), "-G failed: {out:?}");
            assert!(!marker.exists(), "a refusal starts nothing");
            // The control: the client starts with the checked agent.
            std::fs::write(&g_file, g_output(d.path(), "none")).unwrap();
            let out = run(&["alpha"]);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert_eq!(
                String::from_utf8_lossy(&out.stderr),
                "hm-pinned-ssh: checked: identity agent none\n"
            );
            let seen = std::fs::read_to_string(&marker).unwrap();
            let want_head = format!("-F {} -o IdentityAgent=none ", config.config.display());
            assert!(
                seen.starts_with(&want_head) && seen.trim_end().ends_with("alpha true"),
                "{seen}"
            );
        }
    }
}
