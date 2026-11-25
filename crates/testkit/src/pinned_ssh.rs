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
//!   `ControlMaster` or `ControlPath`, which the program sets itself (no control socket),
//!   nor ⟨M07 W7.3⟩ `ProxyCommand` or `ProxyJump` ("No hop", below). ⟨M07 W7.3;
//!   M07-W7-R06⟩ An option is named as the client reads its keyword: its double quotes
//!   removed, leading whitespace skipped, in any case (`" User=other"` and
//!   `"\"User\"=other"` both name `User`);
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
//!   fall back to the system pipe. ⟨M07 W9e⟩ With a declared agent pipe (below) the line
//!   must name exactly that pipe instead, and nothing else is accepted;
//! * at least one `identityfile` line, and every one inside the scratch root (so none of the
//!   defaults `~/.ssh/id_*` that `-G` prints when the configuration names none);
//! * a `userknownhostsfile` line whose every (space-separated) entry is inside the scratch
//!   root;
//! * ⟨M07 W7.3; M07-W7-R01⟩ no `proxycommand` or `proxyjump` line other than `none`, and no
//!   `localcommand` line other than `none` unless there is exactly one `permitlocalcommand`
//!   line, `no`.
//!
//! **No hop.** ⟨M07 W7.3; M07-W7-R01⟩ The guard checks the client this program starts, and a
//! `ProxyCommand` or `ProxyJump` hop is another client it never sees: OpenSSH builds a jump's
//! client with only `-F <config>` (and `-l`, `-p`, `-J`, `-v` and the host), so none of the
//! options above reach it, and it falls back to `SSH_AUTH_SOCK`, the default identities and
//! the account's `known_hosts`. Win32-OpenSSH also sets `SSH_AUTH_SOCK` to the system pipe
//! whenever it is unset, before the client applies its own `IdentityAgent`, so a
//! `ProxyCommand`, `ProxyJump` or `LocalCommand` child inherits that pipe. So the guard
//! refuses an effective hop or a permitted local command (above), and before any run the
//! program refuses a hop that the sidecar's `options` name, or that the words it passes on
//! (its own arguments, then the sidecar's `trailing`) give: `-J` in any form (`-J x`, `-Jx`,
//! `-vJ x`), or `-o` naming `ProxyCommand` or `ProxyJump` in any spelling the client
//! accepts. Each word is read as the client's `getopt` reads options, wherever it stands
//! (the client reads options after the destination too), so more words are read as options
//! than the client reads, never fewer. A routed row needs another design: each hop checked
//! with its own `-G`.
//!
//! **The argument record.** ⟨M07 W9d⟩ The sidecar may name `record` (written by
//! [`WrapperConfig::install_recording`]): an absolute path inside the scratch root (as
//! above), whose parent directory exists, and which is not a directory, not the program,
//! its sidecar or the `-F` file; anything else is a refusal before any run. Once the guard
//! passed, and before the client starts, the program appends one JSON line to it:
//!
//! ```text
//! {"caller":[<its own arguments>…],"added":[<the words it puts ahead of them>…],"trailing":[<the sidecar's trailing words>…]}
//! ```
//!
//! `added` is `-F <config> -o IdentityAgent=<checked> -o ControlMaster=no -o
//! ControlPath=none [-o <option>]…`, so `added`, then `caller`, then `trailing` are exactly
//! the client's arguments. Only those words: never key material, never an environment
//! value. A refusal records nothing; a record that cannot be written is a refusal (the
//! client does not start). A test reads it to show what its caller (`connect`, the TUI)
//! passed, for example only the alias.
//!
//! ⟨M07 W9e⟩ With a declared agent pipe (below) the line also has a fourth field,
//! `"agent_pipe":"<the declared pipe name>"`, and `added` holds `-o IdentityAgent=//./pipe/<name>`.
//!
//! **The declared agent pipe.** ⟨M07 W9e; ADR-0007 §12.52, the contract owner's ruling of
//! 2026-11-24⟩ `heimdall run` hands its child the binding's signing endpoint as
//! `SSH_AUTH_SOCK`. The wrapper accepts that variable as the client's agent only when the
//! sidecar declares it ([`WrapperConfig::install_declaring`], [`DeclaredAgentPipe`]): the
//! fields `allowed_agent_pipe` (the pipe name), `runtime_pid` and `runtime_started` (the
//! runtime process's creation time, `GetProcessTimes`, 100 ns units since 1601), all three or
//! none. Then, in this order, and any failure is a refusal that starts nothing (not even the
//! `-G` run):
//!
//! 1. **The name rule.** The declared name is `\\.\pipe\heimdall-<token>-<kind>` byte for
//!    byte: the `\\.\pipe\` namespace and the `heimdall-` prefix in that case, then one
//!    pipe-name component of ASCII letters, digits, `-`, `_` and `.` (no separator, so
//!    nothing for Windows' path normalization to resolve), not ending in `.`, at most 256
//!    characters, whose `<token>` (up to the last `-`) holds a letter or digit and whose
//!    `<kind>` (after it) is not empty and is neither `control` nor `issuer` in any case.
//!    That is the Windows endpoint name of ADR-0006 §2.1 (`\\.\pipe\heimdall-<token>-<kind>`,
//!    as `heimdall_ipc::EndpointPaths::for_runtime` builds it), which ADR-0013 §8 adopts, read
//!    for a consumer endpoint: ADR-0013 §8 keeps the control, signing and issuer endpoints
//!    apart ("never merged"), gives signing endpoints only through a binding's `consumer`,
//!    and never publishes the issuer endpoint (ADR-0006 §2.1 rev2: never materialized into
//!    a binding), so a consumer's agent is never the `-control` or `-issuer` pipe. The
//!    fixtures' `\\.\pipe\heimdall-hmtest-<hex>-<name>` and ADR-0008's per-binding
//!    `\\.\pipe\heimdall-<token>-b<hex>` both have this form; the system pipe
//!    `\\.\pipe\openssh-ssh-agent`, a `//./pipe/` spelling and a `\\?\` one do not.
//! 2. **The variable.** `SSH_AUTH_SOCK` in this program's environment equals the declared
//!    name exactly, code unit for code unit: no prefix match, no case folding, no other
//!    spelling. Unset is a refusal.
//! 3. **The server.** The program opens the pipe (`CreateFileW`, `SECURITY_SQOS_PRESENT |
//!    SECURITY_IDENTIFICATION`, so its server cannot impersonate it beyond identification;
//!    the handle must be `FILE_TYPE_PIPE`), reads the server's PID with
//!    `GetNamedPipeServerProcessId`, closes the pipe without writing a byte, and opens that
//!    process to read its creation time (`GetProcessTimes`; `heimdall_testkit::win`). The PID
//!    must equal `runtime_pid` and the creation time `runtime_started`, so neither a pipe
//!    another process serves nor a reused PID passes. Only Windows builds with the
//!    `fixtures` feature can read a server; every other build refuses here.
//! 4. **The `-G` run** gets `-o IdentityAgent=//./pipe/<name>` right after `-F <config>`, as
//!    the client will (ADR-0007 F14: in `IdentityAgent` only the `//./pipe/` form reaches the
//!    pipe; `SSH_AUTH_SOCK` takes `\\.\pipe\`). So the guard checks the effective
//!    configuration of the client it is about to start, agent included: the first obtained
//!    value wins, and its `identityagent` line must name the declared pipe (either separator,
//!    ASCII case ignored: the same pipe object), which shows that nothing ahead of it chose
//!    another agent. Every other check of the guard is unchanged. Without the option the
//!    `-G` run would check the configuration's own `IdentityAgent`, which the client never
//!    uses.
//!
//! The client then gets the same `-o IdentityAgent=//./pipe/<name>`. Without a declaration
//! nothing changes: the guard still refuses `SSH_AUTH_SOCK` in every spelling, the system
//! pipe and every pipe that is not a fixture's. The residual: the pipe is checked before the
//! client opens it, so a server that replaced the runtime's pipe in between would not be
//! seen; the runtime is the test's own process and outlives the client.
//!
//! **A stated test limit (M07 W9 review):** a declared runtime must be the test's own; the
//! wrapper trusts the declaration. A real Heimdall runtime's `-signing` endpoint passes the
//! name rule, and the wrapper cannot tell a scratch runtime from a real one: it checks only
//! that the pipe's server is the process the sidecar names. The test that writes the
//! declaration makes the difference (A32's driver requires the binding's `SSH_AUTH_SOCK` to
//! be the lab agent's endpoint and `service status`'s PID to be the test process's own
//! before it declares anything).
//!
//! A passed check writes one line to stderr, `hm-pinned-ssh: checked: identity agent
//! <kind>`, `<kind>` being `none`, `scratch path`, `fixture pipe` or ⟨M07 W9e⟩ `declared
//! pipe` (never the value), then starts the client.
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
//! so they run on every platform without any `ssh`. ⟨M07 W9e⟩ The declared pipe's server is
//! read the same way: [`main`] passes the real read, the unit tests a chosen answer; the
//! Windows tests also run the built program against real pipes. No product binary links
//! this crate, and the closures are not reachable from outside the module.

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

/// ⟨M07 W7.3; M07-W7-R01⟩ Option names that make the client start another client, a hop
/// (module docs, "No hop").
const HOPS: [&str; 2] = ["proxycommand", "proxyjump"];

/// ⟨M07 W7.3⟩ The `ssh` options that take an argument (its `getopt` string, the same in
/// OpenSSH and Win32-OpenSSH): `-oX`, `-o X`.
const WITH_ARGUMENT: &str = "BDEFIJLOPQRSWbceilmopw";

/// ⟨M07 W9e⟩ The variable `heimdall run` names the binding's signing endpoint in.
const AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// ⟨M07 W9e⟩ The pipe namespace a declared agent pipe is named in, byte for byte (module
/// docs, "The declared agent pipe").
const PIPE_NAMESPACE: &str = r"\\.\pipe\";

/// ⟨M07 W9e⟩ The prefix of every Heimdall endpoint pipe (ADR-0006 §2.1).
const ENDPOINT_PREFIX: &str = "heimdall-";

/// ⟨M07 W9e⟩ The endpoint kinds that are never a consumer's agent (ADR-0013 §8).
const NOT_A_CONSUMER: [&str; 2] = ["control", "issuer"];

/// ⟨M07 W9e⟩ The longest pipe-name component Windows accepts.
const PIPE_NAME_MAX: usize = 256;

/// ⟨M07 W9e⟩ The agent pipe a sidecar declares (module docs, "The declared agent pipe"):
/// the only `SSH_AUTH_SOCK` the wrapper accepts, and the process that must serve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredAgentPipe {
    /// The pipe name, `\\.\pipe\heimdall-<token>-<kind>`, as `heimdall run` sets
    /// `SSH_AUTH_SOCK` (the binding's `consumer.environment`).
    pub name: String,
    /// The PID of the runtime process that must serve it.
    pub runtime_pid: u32,
    /// That process's creation time (`GetProcessTimes`, 100 ns units since 1601).
    pub runtime_started: u64,
}

impl DeclaredAgentPipe {
    /// The `IdentityAgent=//./pipe/<name>` option the `-G` run and the client get (module
    /// docs, step 4; ADR-0007 F14).
    #[must_use]
    pub fn identity_agent_option(&self) -> String {
        pipe_option(&self.name)
    }
}

/// `IdentityAgent=//./pipe/<component>` for the pipe `name` (`\\.\pipe\<component>`).
fn pipe_option(name: &str) -> String {
    let component = name.strip_prefix(PIPE_NAMESPACE).unwrap_or(name);
    format!("IdentityAgent=//./pipe/{component}")
}

/// ⟨M07 W9e⟩ The name rule (module docs, step 1).
///
/// # Errors
/// The rule the name breaks; the reason names no value.
fn check_pipe_name(name: &str) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("the declared agent pipe {why}"));
    let Some(component) = name.strip_prefix(PIPE_NAMESPACE) else {
        return refuse("is not named \\\\.\\pipe\\<name>");
    };
    if component.is_empty() || component.len() > PIPE_NAME_MAX {
        return refuse("has an empty or overlong name");
    }
    if !component
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || component.ends_with('.')
    {
        return refuse("has a character outside A-Z, a-z, 0-9, -, _ and . (or ends in .)");
    }
    let Some(rest) = component.strip_prefix(ENDPOINT_PREFIX) else {
        return refuse("has no heimdall- prefix");
    };
    let Some((token, kind)) = rest.rsplit_once('-') else {
        return refuse("has no <token>-<kind> after heimdall-");
    };
    if !token.bytes().any(|b| b.is_ascii_alphanumeric()) || kind.is_empty() {
        return refuse("has an empty token or kind");
    }
    if NOT_A_CONSUMER.contains(&kind.to_ascii_lowercase().as_str()) {
        return refuse("is a control or issuer endpoint, never a consumer's agent");
    }
    Ok(())
}

/// ⟨M07 W9e⟩ Whether a `-G` `identityagent` value names the pipe `name`: the same text with
/// either separator, ASCII case ignored (the same pipe object).
fn names_pipe(value: &str, name: &str) -> bool {
    value
        .replace('\\', "/")
        .eq_ignore_ascii_case(&name.replace('\\', "/"))
}

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
        self.sidecar_json(None)
    }

    /// ⟨M07 W9d⟩ The sidecar's JSON text, naming `record` as the argument record (module
    /// docs) when given.
    #[must_use]
    pub fn sidecar_json(&self, record: Option<&Path>) -> String {
        self.sidecar_json_declaring(record, None)
    }

    /// ⟨M07 W9e⟩ [`sidecar_json`](Self::sidecar_json), also declaring `pipe` (module docs,
    /// "The declared agent pipe") when given.
    #[must_use]
    pub fn sidecar_json_declaring(
        &self,
        record: Option<&Path>,
        pipe: Option<&DeclaredAgentPipe>,
    ) -> String {
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
        if let Some(record) = record {
            v["record"] = text(record);
        }
        if let Some(pipe) = pipe {
            v["allowed_agent_pipe"] = serde_json::Value::String(pipe.name.clone());
            v["runtime_pid"] = pipe.runtime_pid.into();
            v["runtime_started"] = pipe.runtime_started.into();
        }
        v.to_string()
    }

    /// Parse a sidecar (an argument record or ⟨M07 W9e⟩ a declared agent pipe it names is
    /// not part of the result; the program reads them with the rest).
    ///
    /// # Errors
    /// Malformed JSON, or a field of the wrong shape (the reason names the field only).
    pub fn parse(text: &str) -> Result<WrapperConfig, String> {
        parse_sidecar(text).map(|s| s.config)
    }

    /// Copy the built wrapper ([`locate`]) into `dir` and write its sidecar there: the
    /// scratch wrapper path the redirect names. `dir` must be inside `scratch_root`, or the
    /// installed program refuses.
    ///
    /// # Errors
    /// The program is not built, or a copy or write failed.
    pub fn install(&self, dir: &Path) -> io::Result<PathBuf> {
        self.install_declaring(dir, None, None)
    }

    /// ⟨M07 W9d⟩ [`install`](Self::install), with the sidecar naming `record` as the
    /// argument record (module docs): an absolute path inside `scratch_root`, or the
    /// installed program refuses.
    ///
    /// # Errors
    /// As [`install`](Self::install).
    pub fn install_recording(&self, dir: &Path, record: &Path) -> io::Result<PathBuf> {
        self.install_declaring(dir, Some(record), None)
    }

    /// ⟨M07 W9e⟩ [`install`](Self::install), with the sidecar naming `record` as the
    /// argument record and declaring `pipe` (module docs, "The declared agent pipe"), each
    /// when given.
    ///
    /// # Errors
    /// As [`install`](Self::install).
    pub fn install_declaring(
        &self,
        dir: &Path,
        record: Option<&Path>,
        pipe: Option<&DeclaredAgentPipe>,
    ) -> io::Result<PathBuf> {
        let built = locate()?;
        let exe = dir.join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&built, &exe)?;
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            self.sidecar_json_declaring(record, pipe),
        )?;
        Ok(exe)
    }
}

/// ⟨M07 W9d⟩ One argument record line (module docs, "The argument record"), parsed: what a
/// test reads back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentRecord {
    /// The wrapper's own arguments, as its caller gave them.
    pub caller: Vec<String>,
    /// The words it put ahead of them.
    pub added: Vec<String>,
    /// The sidecar's trailing words, after them.
    pub trailing: Vec<String>,
    /// ⟨M07 W9e⟩ The declared agent pipe the client was given, when the sidecar declared
    /// one.
    pub agent_pipe: Option<String>,
}

impl ArgumentRecord {
    /// Every line of the record file's `text`, in order.
    ///
    /// # Errors
    /// A line that is not a record (the reason names the line's number only).
    pub fn parse_all(text: &str) -> Result<Vec<ArgumentRecord>, String> {
        text.lines()
            .enumerate()
            .map(|(n, line)| {
                let v: serde_json::Value = serde_json::from_str(line)
                    .map_err(|_| format!("record line {}: not JSON", n + 1))?;
                let words = |name: &str| -> Result<Vec<String>, String> {
                    v.get(name)
                        .and_then(serde_json::Value::as_array)
                        .and_then(|items| {
                            items
                                .iter()
                                .map(|i| i.as_str().map(str::to_owned))
                                .collect::<Option<Vec<String>>>()
                        })
                        .ok_or_else(|| format!("record line {}: {name}: expected strings", n + 1))
                };
                let agent_pipe = match v.get("agent_pipe") {
                    None => None,
                    Some(serde_json::Value::String(s)) => Some(s.clone()),
                    Some(_) => {
                        return Err(format!("record line {}: agent_pipe: expected text", n + 1));
                    }
                };
                let fields = v.as_object().map_or(0, serde_json::Map::len);
                if fields != 3 + usize::from(agent_pipe.is_some()) {
                    return Err(format!(
                        "record line {}: expected three fields (four with agent_pipe)",
                        n + 1
                    ));
                }
                Ok(ArgumentRecord {
                    caller: words("caller")?,
                    added: words("added")?,
                    trailing: words("trailing")?,
                    agent_pipe,
                })
            })
            .collect()
    }
}

/// A sidecar, parsed: its configuration, the argument record it names and ⟨M07 W9e⟩ the
/// agent pipe it declares, if any (module docs).
struct Sidecar {
    config: WrapperConfig,
    record: Option<PathBuf>,
    pipe: Option<DeclaredAgentPipe>,
}

/// ⟨M07 W9e⟩ The declared agent pipe's three fields: all or none (module docs).
fn parse_pipe(v: &serde_json::Value) -> Result<Option<DeclaredAgentPipe>, String> {
    let name = v.get("allowed_agent_pipe");
    let pid = v.get("runtime_pid");
    let started = v.get("runtime_started");
    match (name, pid, started) {
        (None, None, None) => Ok(None),
        (Some(name), Some(pid), Some(started)) => Ok(Some(DeclaredAgentPipe {
            name: name
                .as_str()
                .ok_or_else(|| "allowed_agent_pipe: expected text".to_owned())?
                .to_owned(),
            runtime_pid: pid
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or_else(|| "runtime_pid: expected a process ID".to_owned())?,
            runtime_started: started
                .as_u64()
                .ok_or_else(|| "runtime_started: expected a creation time".to_owned())?,
        })),
        _ => Err(
            "the declared agent pipe needs allowed_agent_pipe, runtime_pid and runtime_started"
                .to_owned(),
        ),
    }
}

/// A sidecar and the argument record it names, if any (module docs).
fn parse_sidecar(text: &str) -> Result<Sidecar, String> {
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
    let config = WrapperConfig {
        config: path("config")?.ok_or_else(|| "no scratch config (-F) named".to_owned())?,
        scratch_root: path("scratch_root")?.ok_or_else(|| "no scratch root named".to_owned())?,
        options: strings("options")?,
        trailing: strings("trailing")?,
        client: path("client")?,
    };
    Ok(Sidecar {
        config,
        record: path("record")?,
        pipe: parse_pipe(&v)?,
    })
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

/// The option's name in lower case (`Name=value` or `Name value`). ⟨M07 W7.3; M07-W7-R06⟩
/// As the client reads a keyword: its double quotes removed (the client accepts a quoted
/// keyword, even `Proxy"Jump"`) and leading whitespace skipped, so `" User=other"` and
/// `"\"User\"=other"` are named `user`.
fn option_name(option: &str) -> String {
    let unquoted: String = option.chars().filter(|&c| c != '"').collect();
    unquoted
        .trim_start()
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// ⟨M07 W7.3; M07-W7-R01⟩ The hop `words` would give the client, if any (module docs, "No
/// hop"): `-J` in any form (`-J x`, `-Jx`, `-vJ x`), or `-o` naming `ProxyCommand` or
/// `ProxyJump` in any spelling the client accepts ([`option_name`]). Every word is read
/// the way the client's `getopt` reads an option, wherever it stands: the client also reads
/// options after the destination, so a word that is not an option is skipped, not an end.
/// That reads more words as options than the client does, never fewer.
fn hop_in(words: &[OsString]) -> Option<&'static str> {
    let mut words = words.iter().map(|w| w.to_string_lossy());
    while let Some(word) = words.next() {
        let Some(cluster) = word.strip_prefix('-') else {
            continue;
        };
        for (at, letter) in cluster.char_indices() {
            if letter == 'J' {
                return Some("-J");
            }
            if WITH_ARGUMENT.contains(letter) {
                let rest = &cluster[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    words.next().map(std::borrow::Cow::into_owned)
                } else {
                    Some(rest.to_owned())
                };
                if letter == 'o' && value.is_some_and(|v| HOPS.contains(&option_name(&v).as_str()))
                {
                    return Some("-o ProxyCommand or ProxyJump");
                }
                break;
            }
        }
    }
    None
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
    /// ⟨M07 W9e⟩ The declared agent pipe (its name), checked (module docs).
    DeclaredPipe(String),
}

impl Agent {
    /// What the passed-check line names (never the value).
    fn kind(&self) -> &'static str {
        match self {
            Agent::None => "none",
            Agent::ScratchPath(_) => "scratch path",
            Agent::FixturePipe(_) => "fixture pipe",
            Agent::DeclaredPipe(_) => "declared pipe",
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
            Agent::DeclaredPipe(name) => pipe_option(name),
        }
    }
}

/// ⟨M07 W7.1⟩ The guard over the `-G` output `text` (module docs): the accepted agent.
///
/// # Errors
/// The refusal's reason; it names no value.
fn check_effective(
    text: &str,
    root: &Root,
    windows: bool,
    declared: Option<&DeclaredAgentPipe>,
) -> Result<Agent, String> {
    let mut only = Vec::new();
    let mut agents = Vec::new();
    let mut files = Vec::new();
    let mut known = Vec::new();
    let mut hops = Vec::new();
    let mut local = Vec::new();
    let mut permit = Vec::new();
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        let value = unquote(value.trim());
        match key {
            "identitiesonly" => only.push(value),
            "identityagent" => agents.push(value),
            "identityfile" => files.push(value),
            "userknownhostsfile" => known.push(value),
            "proxycommand" | "proxyjump" => hops.push(value),
            "localcommand" => local.push(value),
            "permitlocalcommand" => permit.push(value),
            _ => {}
        }
    }
    let refuse = |reason: &str| Err(format!("the effective configuration: {reason}"));
    // ⟨M07 W7.3; M07-W7-R01⟩ No hop, and no local command (module docs, "No hop").
    if hops.iter().any(|v| *v != "none") {
        return refuse("a ProxyCommand or ProxyJump hop is set (its client is not checked)");
    }
    if local.iter().any(|v| *v != "none") && permit.as_slice() != ["no"] {
        return refuse("a LocalCommand is set and PermitLocalCommand is not no");
    }
    if only.as_slice() != ["yes"] {
        return refuse("IdentitiesOnly is not yes");
    }
    let [agent] = agents.as_slice() else {
        return refuse("IdentityAgent is not set once (the client would use the system agent)");
    };
    let agent = if let Some(pipe) = declared {
        // ⟨M07 W9e⟩ The `-G` run got the declared pipe first: nothing else is accepted.
        if names_pipe(agent, &pipe.name) {
            Agent::DeclaredPipe(pipe.name.clone())
        } else {
            return refuse("IdentityAgent is not the declared agent pipe");
        }
    } else if *agent == "none" {
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
    /// ⟨M07 W9d⟩ The argument record (module docs), checked.
    record: Option<PathBuf>,
    /// ⟨M07 W9e⟩ The declared agent pipe (module docs), its name and `SSH_AUTH_SOCK`
    /// checked; its server is checked by [`prepare_with`].
    pipe: Option<DeclaredAgentPipe>,
}

impl Launch {
    /// The guard's `-G` run's arguments (module docs). ⟨M07 W9e⟩ With a declared agent pipe,
    /// `-o IdentityAgent=//./pipe/<name>` follows `-F <config>`, as for the client.
    #[must_use]
    pub fn check_argv(&self) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec!["-G".into(), "-F".into(), self.config.clone()];
        if let Some(pipe) = &self.pipe {
            argv.push("-o".into());
            argv.push(pipe.identity_agent_option().into());
        }
        argv.extend(self.options.iter().cloned());
        argv.extend(self.args.iter().cloned());
        argv
    }

    /// The words the client gets ahead of the caller's arguments once the guard accepted
    /// `agent` (module docs).
    fn added(&self, agent: &Agent) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec![
            "-F".into(),
            self.config.clone(),
            "-o".into(),
            agent.option().into(),
        ];
        argv.extend(self.options.iter().cloned());
        argv
    }

    /// The client's arguments once the guard accepted `agent` (module docs).
    fn client_argv(&self, agent: &Agent) -> Vec<OsString> {
        let mut argv = self.added(agent);
        argv.extend(self.args.iter().cloned());
        argv.extend(self.trailing.iter().cloned());
        argv
    }

    /// ⟨M07 W9d⟩ The argument record's line for this start (module docs), without its
    /// newline: only the caller's arguments, the added words and the trailing words, and
    /// ⟨M07 W9e⟩ the declared agent pipe's name when the client got it.
    fn record_line(&self, agent: &Agent) -> String {
        let words = |w: &[OsString]| -> Vec<String> {
            w.iter().map(|a| a.to_string_lossy().into_owned()).collect()
        };
        let mut line = serde_json::json!({
            "caller": words(&self.args),
            "added": words(&self.added(agent)),
            "trailing": words(&self.trailing),
        });
        if let Agent::DeclaredPipe(name) = agent {
            line["agent_pipe"] = serde_json::Value::String(name.clone());
        }
        line.to_string()
    }
}

/// ⟨M07 W9d⟩ The argument record `record` names, checked (module docs): an absolute path
/// inside the root whose parent is a directory, and not a directory, a symbolic link, the
/// program, its sidecar or the `-F` file.
fn check_record(record: &Path, root: &Root, exe: &Path, config: &Path) -> Result<PathBuf, String> {
    let text = record
        .to_str()
        .ok_or_else(|| "the argument record is not a text path".to_owned())?;
    if !record.is_absolute() || !root.holds(text, cfg!(windows)) {
        return Err("the argument record is not inside the scratch root".to_owned());
    }
    if !record.parent().is_some_and(Path::is_dir) {
        return Err("the argument record's directory does not exist".to_owned());
    }
    if let Ok(meta) = std::fs::symlink_metadata(record) {
        if !meta.file_type().is_file() {
            return Err("the argument record is not a regular file".to_owned());
        }
        let same = |other: &Path| {
            std::fs::canonicalize(other)
                .ok()
                .is_some_and(|o| std::fs::canonicalize(record).ok() == Some(o))
        };
        if same(exe) || same(&WrapperConfig::sidecar(exe)) || same(config) {
            return Err("the argument record names one of the wrapper's own files".to_owned());
        }
    }
    Ok(record.to_path_buf())
}

/// ⟨M07 W9d⟩ Append `line` and a newline to the argument record.
fn append_record(record: &Path, line: &str) -> io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(record)?;
    f.write_all(format!("{line}\n").as_bytes())?;
    f.flush()
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
    let Sidecar {
        config,
        record,
        pipe,
    } = parse_sidecar(&text)?;
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
    // ⟨M07 W7.3; M07-W7-R01⟩ No hop, from the sidecar or the caller (module docs).
    if let Some(hop) = names.iter().find(|n| HOPS.contains(&n.as_str())) {
        return Err(format!(
            "the option {hop} would start a hop the guard does not check"
        ));
    }
    let words: Vec<OsString> = args
        .iter()
        .cloned()
        .chain(config.trailing.iter().map(OsString::from))
        .collect();
    if let Some(hop) = hop_in(&words) {
        return Err(format!(
            "the arguments name a hop ({hop}) the guard does not check"
        ));
    }
    if config.options.iter().any(|o| !o.contains('=')) {
        return Err("an option is not of the form Name=value".to_owned());
    }
    // ⟨M07 W7.3⟩ The trailing words are the remote command, never options: the guard's `-G`
    // run does not see them, and ssh reads an option placed after the destination.
    if config.trailing.iter().any(|w| w.starts_with('-')) {
        return Err("a trailing word is an option the guard does not check".to_owned());
    }
    // ⟨M07 W7.3⟩ ssh uses the last `-F` it is given: a caller's own would replace the scratch
    // configuration the wrapper names.
    if args.iter().any(|a| a.to_string_lossy().starts_with("-F")) {
        return Err("the arguments name a configuration file (-F)".to_owned());
    }
    let record = record
        .map(|r| check_record(&r, &root, exe, &config.config))
        .transpose()?;
    // ⟨M07 W9e⟩ The declared agent pipe: the name rule, then `SSH_AUTH_SOCK` byte for byte
    // (module docs, steps 1 and 2).
    if let Some(pipe) = &pipe {
        check_pipe_name(&pipe.name)?;
        if env(AUTH_SOCK).as_deref() != Some(std::ffi::OsStr::new(&pipe.name)) {
            return Err("SSH_AUTH_SOCK does not name the declared agent pipe exactly".to_owned());
        }
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
        record,
        pipe,
    })
}

/// The guard's `-G` run: the client's standard output, or the refusal's reason.
type CheckRun<'a> = &'a dyn Fn(&Path, &[OsString]) -> Result<Vec<u8>, String>;

/// ⟨M07 W9e⟩ The read of a pipe's server (module docs, step 3): its PID and that process's
/// creation time, or the refusal's reason.
type PipeServer<'a> = &'a dyn Fn(&str) -> Result<(u32, u64), String>;

/// What [`prepare_with`] decided: the client, its arguments, the accepted agent's kind, and
/// ⟨M07 W9d⟩ the argument record with its line for this start, when the sidecar names one.
type Prepared = (
    PathBuf,
    Vec<OsString>,
    &'static str,
    Option<(PathBuf, String)>,
);

/// [`plan`], then ⟨M07 W9e⟩ the declared agent pipe's server through `server`, then the
/// identity guard through `run` (module docs, "The test seam"): the client, its arguments,
/// the accepted agent's kind, and the argument record's line ([`Prepared`]). Writes nothing.
fn prepare_with(
    exe: &Path,
    args: &[OsString],
    env: &dyn Fn(&str) -> Option<OsString>,
    run: CheckRun<'_>,
    server: PipeServer<'_>,
) -> Result<Prepared, String> {
    let launch = plan(exe, args, env)?;
    if let Some(pipe) = &launch.pipe {
        let (pid, started) = server(&pipe.name)?;
        if pid != pipe.runtime_pid {
            return Err(
                "the declared agent pipe's server is not the declared runtime process".to_owned(),
            );
        }
        if started != pipe.runtime_started {
            return Err(
                "the declared agent pipe's server started at another time than the declared runtime (a reused PID)"
                    .to_owned(),
            );
        }
    }
    let out = run(&launch.client, &launch.check_argv())?;
    let text = String::from_utf8(out)
        .map_err(|_| "ssh -G printed something that is not text".to_owned())?;
    let agent = check_effective(&text, &launch.root, cfg!(windows), launch.pipe.as_ref())?;
    let argv = launch.client_argv(&agent);
    let record = launch
        .record
        .clone()
        .map(|r| (r, launch.record_line(&agent)));
    Ok((launch.client, argv, agent.kind(), record))
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
    match prepare_with(&exe, &args, &|n| std::env::var_os(n), &run, &pipe_server) {
        Err(reason) => refuse(&reason),
        Ok((client, argv, kind, record)) => {
            // ⟨M07 W9d⟩ The record first: one that cannot be written starts nothing.
            if let Some((path, line)) = record
                && append_record(&path, &line).is_err()
            {
                return refuse("the argument record could not be written");
            }
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

/// ⟨M07 W9e⟩ The real read of the declared agent pipe's server (module docs, step 3):
/// `heimdall_testkit::win`'s `GetNamedPipeServerProcessId` and `GetProcessTimes`.
#[cfg(all(windows, feature = "fixtures"))]
fn pipe_server(name: &str) -> Result<(u32, u64), String> {
    let pid = crate::win::pipe_server_process(name)
        .map_err(|_| "the declared agent pipe could not be opened or its server read".to_owned())?;
    let started = crate::win::process_creation_time(pid)
        .map_err(|_| "the declared agent pipe's server process could not be read".to_owned())?;
    Ok((pid, started))
}

/// ⟨M07 W9e⟩ Without Windows and the `fixtures` feature no pipe's server can be read: a
/// declared agent pipe is refused (module docs, step 3).
#[cfg(not(all(windows, feature = "fixtures")))]
fn pipe_server(_: &str) -> Result<(u32, u64), String> {
    Err(
        "this build cannot read a pipe's server (Windows with the fixtures feature only)"
            .to_owned(),
    )
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
        check_effective(text, &Root::new(root).unwrap(), windows, None)
    }

    /// A pipe-server read for a sidecar that declares no pipe: never called.
    fn no_pipe(_: &str) -> Result<(u32, u64), String> {
        panic!("no agent pipe is declared, so no server is read")
    }

    /// [`prepare_with`] for a sidecar that declares no agent pipe.
    fn prepare(
        exe: &Path,
        args: &[OsString],
        env: &dyn Fn(&str) -> Option<OsString>,
        run: CheckRun<'_>,
    ) -> Result<Prepared, String> {
        prepare_with(exe, args, env, run, &no_pipe)
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
        let (client, argv, kind, record) = prepare(
            &exe,
            &["-o".into(), "X=y".into(), "alpha".into()],
            &env,
            &run,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(kind, "none");
        assert_eq!(record, None, "the sidecar names no argument record");
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

    /// ⟨M07 W9d⟩ The argument record (module docs): with a sidecar naming one inside the
    /// scratch root, the wrapper's steps give its line, and the line holds exactly the
    /// caller's words (here only the alias), the words added ahead of them and the trailing
    /// words, which together are the client's arguments, and nothing else (three fields).
    /// Deciding writes nothing; the sidecar still parses to the same configuration.
    #[test]
    fn the_argument_record_holds_only_the_callers_and_the_added_words() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let config = good(d.path());
        std::fs::create_dir(d.path().join("rec")).unwrap();
        let record = d.path().join("rec").join("args.ndjson");
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json(Some(&record)),
        )
        .unwrap();
        let run = |_: &Path, _: &[OsString]| Ok(g_output(d.path(), "none").into_bytes());
        let (_, argv, _, named) =
            prepare(&exe, &["alpha".into()], &env, &run).unwrap_or_else(|e| panic!("{e}"));
        let (path, line) = named.expect("the sidecar names an argument record");
        assert_eq!(path, record);
        assert!(!record.exists(), "deciding writes nothing");
        let argv: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let parsed = ArgumentRecord::parse_all(&line).unwrap_or_else(|e| panic!("{e}"));
        let [one] = parsed.as_slice() else {
            panic!("one line: {line}");
        };
        assert_eq!(one.caller, ["alpha"], "the caller passed only the alias");
        assert_eq!(one.trailing, ["true"]);
        assert_eq!(one.added, argv[..argv.len() - 2]);
        assert_eq!(
            [one.added.clone(), one.caller.clone(), one.trailing.clone()].concat(),
            argv,
            "the record's words are exactly the client's arguments"
        );
        assert_eq!(
            one.added[..4],
            [
                "-F".to_owned(),
                config.config.display().to_string(),
                "-o".to_owned(),
                "IdentityAgent=none".to_owned()
            ]
        );
        assert_eq!(
            WrapperConfig::parse(&config.sidecar_json(Some(&record))).unwrap(),
            config
        );
        // A line with another field, or not JSON, is not a record.
        assert!(
            ArgumentRecord::parse_all(r#"{"caller":[],"added":[],"trailing":[],"env":[]}"#)
                .is_err()
        );
        assert!(ArgumentRecord::parse_all("alpha").is_err());
    }

    /// ⟨M07 W9d⟩ An argument record the sidecar names is refused before any run unless it is
    /// an absolute path inside the scratch root whose directory exists: outside the root, a
    /// `..` way out, relative, a `%` token, in a missing directory, a directory, the `-F`
    /// file, the program or its sidecar, (Unix) a symbolic link, and a field that is not a
    /// path are each a refusal, and nothing is written outside the root.
    #[test]
    fn refuses_an_argument_record_outside_the_scratch_root() {
        let d = scratch();
        let outside = scratch();
        let env = env_with_inbox(d.path());
        let config = good(d.path());
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        let far = outside.path().join("args.ndjson");
        let base: Vec<(&str, PathBuf)> = vec![
            ("outside", far.clone()),
            (
                "dot-dot",
                d.path()
                    .join("..")
                    .join(outside.path().file_name().unwrap())
                    .join("args.ndjson"),
            ),
            ("relative", PathBuf::from("args.ndjson")),
            ("token", d.path().join("%d.ndjson")),
            ("missing directory", d.path().join("absent").join("args")),
            ("a directory", d.path().to_path_buf()),
            ("the -F file", config.config.clone()),
            ("the program", exe.clone()),
            ("its sidecar", WrapperConfig::sidecar(&exe)),
        ];
        #[cfg(unix)]
        let links: Vec<(&str, PathBuf)> = {
            std::fs::write(outside.path().join("target"), b"").unwrap();
            std::os::unix::fs::symlink(outside.path().join("target"), d.path().join("link"))
                .unwrap();
            std::fs::write(d.path().join("rec-file"), b"").unwrap();
            std::os::unix::fs::symlink(d.path().join("rec-file"), d.path().join("link-in"))
                .unwrap();
            vec![
                ("a symbolic link out", d.path().join("link")),
                ("a symbolic link in", d.path().join("link-in")),
            ]
        };
        #[cfg(not(unix))]
        let links: Vec<(&str, PathBuf)> = Vec::new();
        let cases = [base, links].concat();
        for (what, record) in &cases {
            std::fs::write(
                WrapperConfig::sidecar(&exe),
                config.sidecar_json(Some(record)),
            )
            .unwrap();
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(err.contains("argument record"), "{what}: {err}");
            assert!(
                !err.contains(&*d.path().to_string_lossy()),
                "the reason names no path: {err}"
            );
        }
        assert!(!far.exists(), "nothing written outside the root");
        let mut v: serde_json::Value = serde_json::from_str(&config.to_json()).unwrap();
        v["record"] = serde_json::json!(3);
        std::fs::write(WrapperConfig::sidecar(&exe), v.to_string()).unwrap();
        let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
        assert!(err.contains("record"), "{err}");
        // The control: inside the root, in an existing directory.
        let inside = d.path().join("args.ndjson");
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json(Some(&inside)),
        )
        .unwrap();
        assert!(plan(&exe, &["alpha".into()], &env).is_ok());
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
        let err = prepare(&exe, &["alpha".into()], &env, &run).unwrap_err();
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
            prepare(&exe, &["alpha".into()], &env, &failing),
            Err("ssh -G failed".to_owned())
        );
        let binary = |_: &Path, _: &[OsString]| Ok(vec![0xff, 0xfe, b'\n']);
        assert!(prepare(&exe, &["alpha".into()], &env, &binary).is_err());
        let empty = |_: &Path, _: &[OsString]| Ok(Vec::new());
        let err = prepare(&exe, &["alpha".into()], &env, &empty).unwrap_err();
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
        let (_, argv, kind, _) =
            prepare(&exe, &["alpha".into()], &env, &run).unwrap_or_else(|e| panic!("{e}"));
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

    /// ⟨M07 W7.3; M07-W7-R01⟩ The guard refuses an effective `proxyjump` or `proxycommand`
    /// whose value is not `none` (so `NONE` too: the client compares case-sensitively), and a
    /// `localcommand` unless `permitlocalcommand` is `no`, once; `none` values, a local
    /// command that may not run, and keys that merely start alike pass. The reason names no
    /// value.
    #[test]
    fn guard_refuses_a_hop_or_a_local_command_that_may_run() {
        let d = scratch();
        let good = g_output(d.path(), "none");
        let permit_no = format!("{good}permitlocalcommand no\n");
        for (what, text) in [
            ("proxyjump", format!("{good}proxyjump bastion\n")),
            ("proxyjump chain", format!("{good}proxyjump a,bastion\n")),
            ("proxycommand", format!("{good}proxycommand nc %h %p\n")),
            ("proxycommand NONE", format!("{good}proxycommand NONE\n")),
            (
                "none, then a hop",
                format!("{good}proxyjump none\nproxyjump bastion\n"),
            ),
        ] {
            for windows in [false, true] {
                let err = check(d.path(), &text, windows).unwrap_err();
                assert!(err.contains("hop"), "{what} ({windows}): {err}");
                assert!(
                    !err.contains("bastion") && !err.contains("nc "),
                    "the reason names no value: {err}"
                );
            }
        }
        for (what, text) in [
            (
                "permitted",
                format!("{good}permitlocalcommand yes\nlocalcommand true\n"),
            ),
            ("no permit line", format!("{good}localcommand true\n")),
            (
                "two permit lines",
                format!("{permit_no}permitlocalcommand no\nlocalcommand true\n"),
            ),
        ] {
            let err = check(d.path(), &text, false).unwrap_err();
            assert!(err.contains("LocalCommand"), "{what}: {err}");
        }
        for text in [
            format!("{good}proxyjump none\nproxycommand none\n"),
            format!("{permit_no}localcommand true\n"),
            format!("{good}localcommand none\n"),
            format!("{good}proxyusefdpass no\n"),
        ] {
            assert_eq!(check(d.path(), &text, false), Ok(Agent::None), "{text}");
        }
    }

    /// The scratch configuration of the W7 review's reproduction (M07-W7-R01): `Host alpha`
    /// passes every identity check and, with `jump`, goes through `ProxyJump bastion`; the
    /// bare `Host bastion` sets nothing, so the hop's client would use the default agent,
    /// identities and `known_hosts`.
    fn reviewers_proxy_jump(dir: &Path, jump: bool) -> WrapperConfig {
        let config = good(dir);
        std::fs::write(
            &config.config,
            format!(
                "Host alpha\n{}    IdentityAgent none\n    IdentityFile {}\n    IdentitiesOnly yes\nHost bastion\n",
                if jump { "    ProxyJump bastion\n" } else { "" },
                q(&dir.join("k"))
            ),
        )
        .unwrap();
        config
    }

    /// ⟨M07 W7.3; M07-W7-R01⟩ The review's reproduction through the stubbed `-G`: the guard's
    /// run prints what the review's real `ssh -G` printed for `alpha` (every identity check
    /// passes, and `proxyjump bastion`). Refused after the `-G` run only, so the client never
    /// starts; without the `proxyjump` line the same check passes.
    #[test]
    fn the_reviewers_proxy_jump_reproduction_is_refused() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let exe = write(d.path(), &reviewers_proxy_jump(d.path(), true));
        let runs = RefCell::new(0);
        let run = |_: &Path, argv: &[OsString]| {
            *runs.borrow_mut() += 1;
            assert_eq!(argv.first().map(OsString::as_os_str), Some("-G".as_ref()));
            Ok(format!("{}proxyjump bastion\n", g_output(d.path(), "none")).into_bytes())
        };
        let err = prepare(&exe, &["alpha".into()], &env, &run).unwrap_err();
        assert!(err.contains("ProxyCommand or ProxyJump hop"), "{err}");
        assert!(!err.contains("bastion"), "the reason names no value: {err}");
        assert_eq!(runs.into_inner(), 1, "only the -G run");
        let run = |_: &Path, _: &[OsString]| Ok(g_output(d.path(), "none").into_bytes());
        assert!(prepare(&exe, &["alpha".into()], &env, &run).is_ok());
    }

    /// ⟨M07 W7.3; M07-W7-R01⟩ The review's reproduction through the **built** program, on Unix.
    /// Its client is a script that answers `-G` from a stub file when there is one, else runs
    /// the real `/usr/bin/ssh -G` (when that exists: the effective configuration only, no
    /// connection, the scratch `-F` file only), and otherwise leaves a marker. With the hop,
    /// the stubbed and the real `-G` are each refused (exit [`REFUSED`], the marker absent);
    /// the control without the hop starts the client through the real `-G`.
    #[cfg(unix)]
    #[test]
    fn the_built_wrapper_refuses_the_reviewers_proxy_jump() {
        use std::os::unix::fs::PermissionsExt as _;
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        let d = scratch();
        let exe = d.path().join(NAME);
        std::fs::copy(&built, &exe).unwrap();
        let marker = d.path().join("started");
        let g_file = d.path().join("g.out");
        let real_ssh = Path::new("/usr/bin/ssh");
        let script = d.path().join("client.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nif [ \"$1\" = -G ]; then\n  if [ -f '{g}' ]; then cat '{g}' || exit 3; exit 0; fi\n  exec {ssh} \"$@\"\nfi\necho \"$*\" > '{m}'\n",
                g = g_file.display(),
                ssh = real_ssh.display(),
                m = marker.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let install = |jump: bool| {
            let config = WrapperConfig {
                client: Some(script.clone()),
                ..reviewers_proxy_jump(d.path(), jump)
            };
            std::fs::write(WrapperConfig::sidecar(&exe), config.to_json()).unwrap();
        };
        let run = || {
            Command::new(&exe)
                .arg("alpha")
                .env_clear()
                .stdin(Stdio::null())
                .output()
                .unwrap()
        };
        let refused_for_the_hop = |out: &std::process::Output| {
            let stderr = String::from_utf8_lossy(&out.stderr);
            out.status.code() == Some(REFUSED)
                && stderr.starts_with("hm-pinned-ssh: refused: ")
                && stderr.contains("ProxyCommand or ProxyJump hop")
                && stderr.lines().count() == 1
        };
        install(true);
        std::fs::write(
            &g_file,
            format!("{}proxyjump bastion\n", g_output(d.path(), "none")),
        )
        .unwrap();
        let out = run();
        assert!(refused_for_the_hop(&out), "the stubbed -G: {out:?}");
        assert!(!marker.exists(), "a refusal starts nothing");
        std::fs::remove_file(&g_file).unwrap();
        if !real_ssh.is_file() {
            #[allow(clippy::print_stdout)] // the skipped half, named in the test's output
            {
                println!("the real-ssh variant not run: /usr/bin/ssh is missing");
            }
            return;
        }
        let out = run();
        assert!(refused_for_the_hop(&out), "the real -G: {out:?}");
        assert!(!marker.exists(), "a refusal starts nothing");
        install(false);
        let out = run();
        assert_eq!(out.status.code(), Some(0), "the control: {out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "hm-pinned-ssh: checked: identity agent none\n"
        );
        let seen = std::fs::read_to_string(&marker).unwrap();
        assert!(seen.trim_end().ends_with("alpha true"), "{seen}");
    }

    /// ⟨M07 W7.3; M07-W7-R01⟩ Before any run, the program refuses a hop in the words it passes
    /// on, read as the client's `getopt` reads them wherever they stand: `-J` in any form,
    /// `-o` naming `ProxyJump` or `ProxyCommand` in any spelling the client accepts, after
    /// the destination too, and in the sidecar's `trailing`; and a sidecar option naming
    /// either. An option's own argument that looks like a hop is not one.
    #[test]
    fn refuses_a_hop_in_the_callers_arguments_or_the_sidecar() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let base = good(d.path());
        let exe = write(d.path(), &base);
        let words = |w: &[&str]| -> Vec<OsString> { w.iter().map(OsString::from).collect() };
        for args in [
            &["-J", "bastion", "alpha"][..],
            &["-Jbastion", "alpha"],
            &["-vJ", "bastion", "alpha"],
            &["-TvJbastion", "alpha"],
            &["-oProxyJump=bastion", "alpha"],
            &["-o", "ProxyJump=bastion", "alpha"],
            &["-o", "proxyjump bastion", "alpha"],
            &["-o", " PROXYJUMP=bastion", "alpha"],
            &["-o", "\"ProxyJump\"=bastion", "alpha"],
            &["-o", "Proxy\"Jump\"=bastion", "alpha"],
            &["-oProxyCommand=nc %h %p", "alpha"],
            &["-o", "ProxyCommand nc %h %p", "alpha"],
            &["-4", "-o", "X=y", "alpha", "-J", "bastion"],
            &["alpha", "true", "-oProxyJump=bastion"],
        ] {
            let err = plan(&exe, &words(args), &env).unwrap_err();
            assert!(err.contains("hop"), "{args:?}: {err}");
            assert!(!err.contains("bastion"), "the reason names no value: {err}");
        }
        for args in [
            &["-l", "-J", "alpha"][..],
            &["-E", "-oProxyJump=x", "alpha"],
            &["-oProxyUseFdpass=no", "-p", "22", "alpha"],
            &["-o", "X=y", "alpha"],
        ] {
            assert!(plan(&exe, &words(args), &env).is_ok(), "{args:?}");
        }
        let with_option = |option: &str| WrapperConfig {
            options: [base.options.clone(), vec![option.to_owned()]].concat(),
            ..base.clone()
        };
        for (what, config) in [
            ("ProxyJump option", with_option("ProxyJump=bastion")),
            (
                "quoted ProxyCommand option",
                with_option("\"proxycommand\"=nc"),
            ),
            (
                "trailing -J",
                WrapperConfig {
                    trailing: vec!["-J".into(), "bastion".into()],
                    ..base.clone()
                },
            ),
        ] {
            let exe = write(d.path(), &config);
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(err.contains("hop"), "{what}: {err}");
        }
    }

    /// ⟨M07 W7.3⟩ A trailing word that is an option (the guard's `-G` run never sees the
    /// trailing words, and ssh reads options after the destination) and a caller's own `-F`
    /// (ssh uses the last one) are refused before anything starts.
    #[test]
    fn trailing_options_and_a_callers_own_config_are_refused() {
        let d = scratch();
        let env = |_: &str| None;
        let base = good(d.path());
        for trailing in [
            vec!["-oIdentityFile=elsewhere".to_owned()],
            vec!["true".to_owned(), "-i".to_owned(), "key".to_owned()],
        ] {
            let exe = write(
                d.path(),
                &WrapperConfig {
                    trailing: trailing.clone(),
                    ..base.clone()
                },
            );
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(err.contains("trailing word"), "{trailing:?}: {err}");
        }
        let words = |w: &[&str]| -> Vec<OsString> { w.iter().map(OsString::from).collect() };
        let exe = write(d.path(), &base);
        for args in [&["-F", "other", "alpha"][..], &["-Fother", "alpha"]] {
            let err = plan(&exe, &words(args), &env).unwrap_err();
            assert!(err.contains("(-F)"), "{args:?}: {err}");
        }
        // The accepted case needs an in-box client to find (Windows reads `SystemRoot`).
        assert!(plan(&exe, &words(&["alpha"]), &env_with_inbox(d.path())).is_ok());
    }

    /// The sidecar's options with `option` added.
    fn with_sidecar_option(dir: &Path, option: &str) -> WrapperConfig {
        let base = good(dir);
        WrapperConfig {
            options: [base.options.clone(), vec![option.to_owned()]].concat(),
            ..base
        }
    }

    /// ⟨M07 W7.3; M07-W7-R06 (a)⟩ A forbidden option with leading whitespace is refused: the
    /// client skips it (`ssh -G -o " User=other"` prints `user other`).
    #[test]
    fn a_forbidden_option_with_leading_whitespace_is_refused() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        for (option, name) in [
            (" User=other", "user"),
            ("\t HostName=elsewhere", "hostname"),
        ] {
            assert_eq!(option_name(option), name);
            let exe = write(d.path(), &with_sidecar_option(d.path(), option));
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(
                err.contains(&format!(
                    "the option {name} would override the configuration under test"
                )),
                "{option:?}: {err}"
            );
        }
    }

    /// ⟨M07 W7.3; M07-W7-R06 (a)⟩ A forbidden option with a quoted keyword is refused: the
    /// client removes the quotes (`"User"=other`, and `Us"er"=other` too). A required option
    /// spelled that way still counts as set.
    #[test]
    fn a_forbidden_option_with_a_quoted_keyword_is_refused() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        for option in ["\"User\"=other", "Us\"er\"=other", "\" User\" other"] {
            assert_eq!(option_name(option), "user", "{option:?}");
            let exe = write(d.path(), &with_sidecar_option(d.path(), option));
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(
                err.contains("the option user would override the configuration under test"),
                "{option:?}: {err}"
            );
        }
        let base = good(d.path());
        let quoted = WrapperConfig {
            options: vec![
                format!("\"UserKnownHostsFile\"={}", q(&d.path().join("kh"))),
                " GlobalKnownHostsFile=/dev/null".to_owned(),
            ],
            ..base
        };
        let exe = write(d.path(), &quoted);
        assert!(plan(&exe, &["alpha".into()], &env).is_ok());
    }

    /// ⟨M07 W9e⟩ A fixture's agent pipe name, as `heimdall run` sets it in `SSH_AUTH_SOCK`.
    const DECLARED: &str = r"\\.\pipe\heimdall-hmtest-0a1b2c3d4e5f6a7b-access";

    /// ⟨M07 W9e⟩ The runtime a test sidecar declares.
    fn declared() -> DeclaredAgentPipe {
        DeclaredAgentPipe {
            name: DECLARED.to_owned(),
            runtime_pid: 4242,
            runtime_started: 133_000_000_000_000_000,
        }
    }

    /// ⟨M07 W9e⟩ The name rule (module docs, "The declared agent pipe", step 1): a consumer
    /// endpoint `\\.\pipe\heimdall-<token>-<kind>` byte for byte, never the control or issuer
    /// endpoint, never the system pipe, another spelling or a name Windows would resolve.
    #[test]
    fn the_declared_agent_pipe_name_rule() {
        for good in [
            DECLARED,
            r"\\.\pipe\heimdall-0123abcd-signing",
            r"\\.\pipe\heimdall-0123abcd-b0123456789abcdef",
            r"\\.\pipe\heimdall-a_b.c-x",
        ] {
            assert_eq!(check_pipe_name(good), Ok(()), "{good}");
        }
        let long = format!(r"\\.\pipe\heimdall-x-{}", "a".repeat(PIPE_NAME_MAX));
        for (bad, why) in [
            (r"\\.\pipe\openssh-ssh-agent", "heimdall- prefix"),
            ("//./pipe/heimdall-x-signing", "is not named"),
            (r"\\?\pipe\heimdall-x-signing", "is not named"),
            (r"\\.\PIPE\heimdall-x-signing", "is not named"),
            (r"\\server\pipe\heimdall-x-signing", "is not named"),
            ("heimdall-x-signing", "is not named"),
            ("", "is not named"),
            (r"\\.\pipe\", "empty or overlong"),
            (long.as_str(), "empty or overlong"),
            (r"\\.\pipe\Heimdall-x-signing", "heimdall- prefix"),
            (r"\\.\pipe\heimdall-x-control", "control or issuer"),
            (r"\\.\pipe\heimdall-x-CONTROL", "control or issuer"),
            (r"\\.\pipe\heimdall-x-issuer", "control or issuer"),
            (r"\\.\pipe\heimdall-x-Issuer", "control or issuer"),
            (r"\\.\pipe\heimdall-signing", "<token>-<kind>"),
            (r"\\.\pipe\heimdall--signing", "empty token or kind"),
            (r"\\.\pipe\heimdall---signing", "empty token or kind"),
            (r"\\.\pipe\heimdall-x-", "empty token or kind"),
            (r"\\.\pipe\heimdall-x-a\..\openssh-ssh-agent", "character"),
            (r"\\.\pipe\heimdall-x-a/../openssh-ssh-agent", "character"),
            (r"\\.\pipe\heimdall-x-%u", "character"),
            (r"\\.\pipe\heimdall-x-a b", "character"),
            (r"\\.\pipe\heimdall-x-a.", "character"),
            ("\\\\.\\pipe\\heimdall-x-\u{e9}", "character"),
        ] {
            let err = check_pipe_name(bad).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
            assert!(
                !err.contains("heimdall-x"),
                "the reason names no value: {err}"
            );
        }
        assert_eq!(
            declared().identity_agent_option(),
            "IdentityAgent=//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-access"
        );
        assert!(names_pipe(
            "//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-access",
            DECLARED
        ));
        assert!(names_pipe(
            r"\\.\PIPE\HEIMDALL-hmtest-0A1B2C3D4E5F6A7B-access",
            DECLARED
        ));
        assert!(!names_pipe(
            "//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-acces",
            DECLARED
        ));
        assert!(!names_pipe(
            "//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-accessx",
            DECLARED
        ));
    }

    /// ⟨M07 W9e⟩ A sidecar declares all three fields of the agent pipe or none, each of its
    /// type; it parses back to the same configuration.
    #[test]
    fn a_declared_agent_pipe_needs_all_three_fields() {
        let d = scratch();
        let env = env_with_inbox(d.path());
        let config = good(d.path());
        let exe = write(d.path(), &config);
        let full: serde_json::Value =
            serde_json::from_str(&config.sidecar_json_declaring(None, Some(&declared()))).unwrap();
        assert_eq!(full["allowed_agent_pipe"], DECLARED);
        assert_eq!(full["runtime_pid"], 4242);
        assert_eq!(full["runtime_started"], 133_000_000_000_000_000_u64);
        assert_eq!(WrapperConfig::parse(&full.to_string()).unwrap(), config);
        for (what, edit) in [
            ("no name", ("allowed_agent_pipe", None)),
            ("no PID", ("runtime_pid", None)),
            ("no start time", ("runtime_started", None)),
            (
                "a PID as text",
                ("runtime_pid", Some(serde_json::json!("4242"))),
            ),
            (
                "a PID past u32",
                (
                    "runtime_pid",
                    Some(serde_json::json!(u64::from(u32::MAX) + 1)),
                ),
            ),
            (
                "a negative start",
                ("runtime_started", Some(serde_json::json!(-1))),
            ),
            (
                "a name that is no text",
                ("allowed_agent_pipe", Some(serde_json::json!(7))),
            ),
        ] {
            let mut v = full.clone();
            match edit {
                (field, None) => {
                    v.as_object_mut().unwrap().remove(field);
                }
                (field, Some(value)) => v[field] = value,
            }
            std::fs::write(WrapperConfig::sidecar(&exe), v.to_string()).unwrap();
            let err = plan(&exe, &["alpha".into()], &env).unwrap_err();
            assert!(
                err.contains("allowed_agent_pipe")
                    || err.contains("runtime_pid")
                    || err.contains("runtime_started"),
                "{what}: {err}"
            );
        }
    }

    /// ⟨M07 W9e⟩ The declared agent pipe through the wrapper's steps (module docs, "The
    /// declared agent pipe"), with a chosen server and a chosen `-G` output. Accepted only
    /// when `SSH_AUTH_SOCK` equals the declared name byte for byte, the pipe's server is the
    /// declared runtime (PID and start time), and `-G`, which gets the declared pipe first,
    /// reports it; the client then gets `-o IdentityAgent=//./pipe/<name>` and the record
    /// names the pipe. Each refusal before the server read reads no server and runs no `-G`;
    /// each server refusal runs no `-G`; a `-G` that reports another agent starts no client.
    /// No reason names a value.
    #[test]
    fn a_declared_agent_pipe_is_accepted_only_from_its_runtime() {
        let d = scratch();
        let inbox = env_with_inbox(d.path());
        let inbox = &inbox;
        let config = good(d.path());
        let record = d.path().join("args.ndjson");
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"").unwrap();
        let install = |pipe: &DeclaredAgentPipe| {
            std::fs::write(
                WrapperConfig::sidecar(&exe),
                config.sidecar_json_declaring(Some(&record), Some(pipe)),
            )
            .unwrap();
        };
        let env_with = |sock: Option<&str>| {
            let sock = sock.map(OsString::from);
            move |n: &str| {
                if n == AUTH_SOCK {
                    sock.clone()
                } else {
                    inbox(n)
                }
            }
        };
        let runs = RefCell::new(Vec::<Vec<OsString>>::new());
        let echo = RefCell::new("//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-access".to_owned());
        let run = |_: &Path, argv: &[OsString]| {
            runs.borrow_mut().push(argv.to_vec());
            Ok(g_output(d.path(), &echo.borrow()).into_bytes())
        };
        let servers = RefCell::new(Vec::<String>::new());
        let answer = RefCell::new(Ok((4242_u32, 133_000_000_000_000_000_u64)));
        let server = |name: &str| {
            servers.borrow_mut().push(name.to_owned());
            answer.borrow().clone()
        };
        let caller: Vec<OsString> = vec!["-T".into(), "lab".into()];
        let reset = || {
            runs.borrow_mut().clear();
            servers.borrow_mut().clear();
        };
        install(&declared());

        // Accepted: the variable, the server and the `-G` echo all name the declared pipe.
        let (_, argv, kind, named) =
            prepare_with(&exe, &caller, &env_with(Some(DECLARED)), &run, &server)
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(kind, "declared pipe");
        assert_eq!(*servers.borrow(), [DECLARED], "the server is read once");
        let option = OsString::from(declared().identity_agent_option());
        let seen = runs.borrow().clone();
        assert_eq!(seen.len(), 1, "one -G run");
        assert_eq!(
            seen[0][..5],
            [
                OsString::from("-G"),
                "-F".into(),
                config.config.clone().into_os_string(),
                "-o".into(),
                option.clone()
            ],
            "the -G run gets the declared pipe right after -F"
        );
        assert_eq!(
            argv[..4],
            [
                OsString::from("-F"),
                config.config.clone().into_os_string(),
                "-o".into(),
                option.clone()
            ],
            "the client gets the declared pipe right after -F"
        );
        assert_eq!(
            argv[argv.len() - 3..],
            [caller[0].clone(), caller[1].clone(), "true".into()]
        );
        let (path, line) = named.expect("the sidecar names an argument record");
        assert_eq!(path, record);
        let parsed = ArgumentRecord::parse_all(&line).unwrap_or_else(|e| panic!("{e}"));
        let [one] = parsed.as_slice() else {
            panic!("one line: {line}");
        };
        assert_eq!(
            one.agent_pipe.as_deref(),
            Some(DECLARED),
            "the record names it"
        );
        assert_eq!(one.added[3], option.to_string_lossy());
        assert_eq!(one.caller, ["-T", "lab"]);
        // The `-G` echo in the other spelling, any case: the same pipe object.
        for spelling in [DECLARED.to_owned(), DECLARED.to_ascii_uppercase()] {
            *echo.borrow_mut() = spelling;
            assert!(prepare_with(&exe, &caller, &env_with(Some(DECLARED)), &run, &server).is_ok());
        }

        // `SSH_AUTH_SOCK` is not the declared name, byte for byte: nothing read, nothing run.
        let prefix = format!("{DECLARED}x");
        let slashes = DECLARED.replace('\\', "/");
        let upper = DECLARED.to_ascii_uppercase();
        for (what, sock) in [
            ("unset", None),
            ("empty", Some("")),
            ("a longer name", Some(prefix.as_str())),
            ("a shorter name", Some(&DECLARED[..DECLARED.len() - 1])),
            ("another case", Some(upper.as_str())),
            ("the //./pipe/ spelling", Some(slashes.as_str())),
            ("the system pipe", Some(SYSTEM_PIPE)),
            (
                "an undeclared heimdall- pipe",
                Some(r"\\.\pipe\heimdall-hmtest-ffffffffffffffff-decoy"),
            ),
        ] {
            reset();
            let err = prepare_with(&exe, &caller, &env_with(sock), &run, &server).unwrap_err();
            assert!(err.contains("SSH_AUTH_SOCK"), "{what}: {err}");
            assert!(
                !err.contains("heimdall-hmtest"),
                "the reason names no value: {err}"
            );
            assert!(
                servers.borrow().is_empty() && runs.borrow().is_empty(),
                "{what}"
            );
        }

        // The pipe's server is not the declared runtime: no -G run.
        for (what, server_answer, why) in [
            (
                "another process",
                Ok((4343, 133_000_000_000_000_000)),
                "not the declared runtime",
            ),
            (
                "a reused PID",
                Ok((4242, 133_000_000_000_000_001)),
                "another time",
            ),
            (
                "no server read",
                Err("the declared agent pipe could not be opened".to_owned()),
                "could not be opened",
            ),
        ] {
            reset();
            *answer.borrow_mut() = server_answer;
            let err =
                prepare_with(&exe, &caller, &env_with(Some(DECLARED)), &run, &server).unwrap_err();
            assert!(err.contains(why), "{what}: {err}");
            assert_eq!(*servers.borrow(), [DECLARED], "{what}");
            assert!(runs.borrow().is_empty(), "{what}: no -G run");
        }
        *answer.borrow_mut() = Ok((4242, 133_000_000_000_000_000));

        // `-G` reports another agent than the declared pipe: refused after the -G run.
        for other in [
            "none",
            SYSTEM_PIPE,
            "//./pipe/heimdall-hmtest-ffffffffffffffff-decoy",
            "//./pipe/heimdall-hmtest-0a1b2c3d4e5f6a7b-accessx",
        ] {
            reset();
            *echo.borrow_mut() = other.to_owned();
            let err =
                prepare_with(&exe, &caller, &env_with(Some(DECLARED)), &run, &server).unwrap_err();
            assert!(
                err.contains("not the declared agent pipe"),
                "{other}: {err}"
            );
            assert_eq!(runs.borrow().len(), 1, "{other}");
        }

        // A declared name the rule refuses is refused before the variable or the server,
        // even when the variable matches it.
        for bad in [SYSTEM_PIPE, r"\\.\pipe\heimdall-0123abcd-control"] {
            reset();
            install(&DeclaredAgentPipe {
                name: bad.to_owned(),
                ..declared()
            });
            let err = prepare_with(&exe, &caller, &env_with(Some(bad)), &run, &server).unwrap_err();
            assert!(err.contains("the declared agent pipe"), "{bad}: {err}");
            assert!(
                servers.borrow().is_empty() && runs.borrow().is_empty(),
                "{bad}"
            );
        }

        // Without a declaration nothing changes: an `SSH_AUTH_SOCK` naming a heimdall- pipe
        // is not used, and the guard still refuses that pipe or the variable as the agent.
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json(Some(&record)),
        )
        .unwrap();
        let binding = r"\\.\pipe\heimdall-0123abcd-signing";
        for value in [binding, "SSH_AUTH_SOCK"] {
            reset();
            *echo.borrow_mut() = value.to_owned();
            let err = prepare(&exe, &caller, &env_with(Some(binding)), &run).unwrap_err();
            assert!(err.contains("IdentityAgent"), "{value}: {err}");
            assert_eq!(
                runs.borrow()[0][..3],
                [
                    OsString::from("-G"),
                    "-F".into(),
                    config.config.clone().into_os_string()
                ],
                "no IdentityAgent is added without a declaration"
            );
        }
    }

    /// ⟨M07 W9e⟩ Through the **built** program on Windows, with real pipes (module docs, "The
    /// declared agent pipe"): two fixture agents served by this test process, `runtime` and
    /// `decoy`, and another process (`cmd.exe` waiting on its input). Each case is refused
    /// with exit [`REFUSED`] and one refusal line, prints nothing, writes no record and
    /// starts no client (no agent is contacted): a declared pipe whose server is not the
    /// declared runtime (the decoy, declared with the other process as its runtime; the
    /// wrapper opened it), the start-time mismatch (the wrapper opened the runtime's pipe), an
    /// undeclared `heimdall-` pipe in `SSH_AUTH_SOCK`, the system agent pipe in
    /// `SSH_AUTH_SOCK` and declared (never opened: the variable and the name rule come
    /// first), and the `//./pipe/` spelling in `SSH_AUTH_SOCK`. The control: the declared
    /// pipe served by this process, with its PID and creation time, passes, and the real
    /// in-box `ssh.exe` prints an effective configuration whose `identityagent` is that pipe
    /// (`-G`: no connection); the record's one line names the pipe.
    #[cfg(all(windows, feature = "fixtures"))]
    #[test]
    fn the_built_wrapper_checks_the_declared_agent_pipe_on_real_pipes() {
        use crate::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        let d = scratch();
        let exe = d
            .path()
            .join(format!("{NAME}{}", std::env::consts::EXE_SUFFIX));
        std::fs::copy(&built, &exe).unwrap();
        let config = good(d.path());
        let record = d.path().join("args.ndjson");
        let pipes = crate::home::Scratch::new().unwrap();
        let agent = |name: &str| {
            FakeAgent::start(
                Endpoint::in_scratch(&pipes, name).unwrap(),
                FakeAgentConfig {
                    keys: vec![FixtureKey::generate()],
                    mode: AgentMode::Normal,
                },
            )
        };
        let runtime = agent("runtime");
        let decoy = agent("decoy");
        let name_of = |a: &FakeAgent| a.endpoint().locator().into_string().unwrap();
        let (ours_name, decoy_name) = (name_of(&runtime), name_of(&decoy));
        let me = std::process::id();
        let me_started = crate::win::process_creation_time(me).unwrap();
        let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
        let mut other = Command::new(system_root.join("System32").join("cmd.exe"))
            .args(["/d", "/q", "/k"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let other_started = crate::win::process_creation_time(other.id()).unwrap();
        let program_data = d.path().join("programdata");
        std::fs::create_dir_all(&program_data).unwrap();
        let run = |pipe: &DeclaredAgentPipe, sock: &str| {
            std::fs::write(
                WrapperConfig::sidecar(&exe),
                config.sidecar_json_declaring(Some(&record), Some(pipe)),
            )
            .unwrap();
            let mut cmd = Command::new(&exe);
            cmd.args(["-G", "alpha"])
                .env_clear()
                .env("ProgramData", &program_data)
                .env(AUTH_SOCK, sock)
                .stdin(Stdio::null());
            for k in ["SystemRoot", "windir"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
            cmd.output().unwrap()
        };
        let declare = |name: &str, runtime_pid: u32, runtime_started: u64| DeclaredAgentPipe {
            name: name.to_owned(),
            runtime_pid,
            runtime_started,
        };
        let ours = declare(&ours_name, me, me_started);
        let wait = Duration::from_secs(5);
        let cases: Vec<(&str, DeclaredAgentPipe, String, &str)> = vec![
            (
                "a declared pipe whose server is not the runtime",
                declare(&decoy_name, other.id(), other_started),
                decoy_name.clone(),
                "is not the declared runtime process",
            ),
            (
                "the start-time mismatch",
                declare(&ours_name, me, me_started + 1),
                ours_name.clone(),
                "another time",
            ),
            (
                "an undeclared heimdall- pipe",
                ours.clone(),
                decoy_name.clone(),
                "SSH_AUTH_SOCK",
            ),
            (
                "the system agent pipe in SSH_AUTH_SOCK",
                ours.clone(),
                SYSTEM_PIPE.to_owned(),
                "SSH_AUTH_SOCK",
            ),
            (
                "the system agent pipe declared",
                declare(SYSTEM_PIPE, me, me_started),
                SYSTEM_PIPE.to_owned(),
                "heimdall- prefix",
            ),
            (
                "the //./pipe/ spelling in SSH_AUTH_SOCK",
                ours.clone(),
                ours_name.replace('\\', "/"),
                "SSH_AUTH_SOCK",
            ),
        ];
        for (at, (what, pipe, sock, why)) in cases.iter().enumerate() {
            let out = run(pipe, sock);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.code() == Some(REFUSED)
                    && stderr.starts_with("hm-pinned-ssh: refused: ")
                    && stderr.contains(why)
                    && stderr.lines().count() == 1
                    && out.stdout.is_empty(),
                "{what}: {out:?}"
            );
            assert!(!record.exists(), "{what}: a refusal records nothing");
            // The first two were refused on the server the wrapper read: it opened that pipe.
            match at {
                0 => assert!(decoy.wait_until(wait, |a| a.opens() == 1), "{what}"),
                1 => assert!(runtime.wait_until(wait, |a| a.opens() == 1), "{what}"),
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            (runtime.opens(), decoy.opens()),
            (1, 1),
            "the later refusals opened no pipe"
        );
        assert_eq!(
            (runtime.contact_count(), decoy.contact_count()),
            (0, 0),
            "no client asked either agent"
        );
        // The control.
        let out = run(&ours, &ours_name);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("hm-pinned-ssh: checked: identity agent declared pipe"),
            "{out:?}"
        );
        assert!(
            stdout.lines().any(|l| l
                .strip_prefix("identityagent ")
                .is_some_and(|v| names_pipe(unquote(v), &ours_name))),
            "the client's effective agent is the declared pipe: {out:?}"
        );
        let lines = std::fs::read_to_string(&record).unwrap();
        let parsed = ArgumentRecord::parse_all(&lines).unwrap_or_else(|e| panic!("{e}"));
        let [one] = parsed.as_slice() else {
            panic!("one start, one line: {lines}");
        };
        assert_eq!(
            one.agent_pipe.as_deref(),
            Some(ours_name.as_str()),
            "{lines}"
        );
        assert_eq!(
            one.added[2..4],
            ["-o".to_owned(), ours.identity_agent_option()]
        );
        assert_eq!(one.caller, ["-G", "alpha"], "{lines}");
        assert!(
            runtime.wait_until(wait, |a| a.opens() == 2),
            "the control's server read"
        );
        assert_eq!(runtime.contact_count(), 0, "-G contacts no agent");
        #[allow(clippy::print_stdout)] // a fact for the native run's report
        {
            println!(
                "w9e wrapper: declared pipe accepted from its runtime; refused: {} cases",
                cases.len()
            );
        }
        other.kill().unwrap();
        other.wait().unwrap();
    }

    /// ⟨M07 W9e⟩ Through the **built** program on Unix: no build but a Windows one with the
    /// `fixtures` feature can read a pipe's server, so a declared agent pipe is refused even
    /// when `SSH_AUTH_SOCK` names it exactly, before any `-G` run: the script client's marker
    /// and the record stay absent.
    #[cfg(unix)]
    #[test]
    fn the_built_wrapper_refuses_a_declared_pipe_it_cannot_check() {
        use std::os::unix::fs::PermissionsExt as _;
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        let d = scratch();
        let exe = d.path().join(NAME);
        std::fs::copy(&built, &exe).unwrap();
        let marker = d.path().join("started");
        let script = d.path().join("client.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\necho \"$*\" > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = WrapperConfig {
            client: Some(script),
            ..good(d.path())
        };
        let record = d.path().join("args.ndjson");
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json_declaring(Some(&record), Some(&declared())),
        )
        .unwrap();
        let out = Command::new(&exe)
            .arg("alpha")
            .env_clear()
            .env(AUTH_SOCK, DECLARED)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(REFUSED), "{out:?}");
        assert_eq!(
            stderr,
            "hm-pinned-ssh: refused: this build cannot read a pipe's server (Windows with the fixtures feature only)\n"
        );
        assert!(
            !marker.exists() && !record.exists(),
            "a refusal starts nothing"
        );
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
    /// output shows `identityagent none`, never [`REFUSED`]. ⟨M07 W9d⟩ The argument record:
    /// a sidecar naming one outside the scratch root is refused and nothing is written
    /// there; named inside, the refusals record nothing and each start appends one line
    /// holding exactly the caller's words, the added ones and the trailing ones (on Unix,
    /// the words the script client was given).
    #[test]
    fn the_built_wrapper_refuses_to_run_without_the_scratch_config() {
        let built = locate().unwrap_or_else(|e| panic!("{e}"));
        // The program's own digest, for the native run's build facts (PC job 46: the
        // harness removes `target` before it records them).
        #[cfg(feature = "fixtures")]
        #[allow(clippy::print_stdout)] // a build fact for the native run's report
        {
            println!(
                "{NAME}{} sha256: {}",
                std::env::consts::EXE_SUFFIX,
                crate::owner_digest::sha256_hex(&std::fs::read(&built).unwrap())
            );
        }
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
        // ⟨M07 W9d⟩ An argument record outside the scratch root: refused, nothing written.
        let elsewhere = scratch();
        let far = elsewhere.path().join("args.ndjson");
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json(Some(&far)),
        )
        .unwrap();
        let out = run(&["alpha"]);
        assert!(refused(&out), "a record outside the root: {out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("argument record"),
            "{out:?}"
        );
        assert!(
            !far.exists() && !marker.exists(),
            "a refusal starts nothing"
        );
        // From here the sidecar names the argument record inside the root.
        let record = d.path().join("args.ndjson");
        std::fs::write(
            WrapperConfig::sidecar(&exe),
            config.sidecar_json(Some(&record)),
        )
        .unwrap();
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
            let lines = std::fs::read_to_string(&record).unwrap();
            let parsed = ArgumentRecord::parse_all(&lines).unwrap_or_else(|e| panic!("{e}"));
            let [one] = parsed.as_slice() else {
                panic!("one start, one line: {lines}");
            };
            assert_eq!(one.caller, ["-G", "alpha"], "{lines}");
            assert_eq!(one.trailing, ["true"], "{lines}");
            assert_eq!(
                one.added[..4],
                [
                    "-F".to_owned(),
                    config.config.display().to_string(),
                    "-o".to_owned(),
                    "IdentityAgent=none".to_owned()
                ],
                "{lines}"
            );
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
            assert!(!record.exists(), "a refusal records nothing");
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
            // ⟨M07 W9d⟩ The refusals recorded nothing; the start recorded one line, whose
            // words are exactly what the client was given.
            let lines = std::fs::read_to_string(&record).unwrap();
            let parsed = ArgumentRecord::parse_all(&lines).unwrap_or_else(|e| panic!("{e}"));
            let [one] = parsed.as_slice() else {
                panic!("one start, one line: {lines}");
            };
            assert_eq!(one.caller, ["alpha"], "{lines}");
            assert_eq!(one.trailing, ["true"], "{lines}");
            assert_eq!(
                [one.added.clone(), one.caller.clone(), one.trailing.clone()]
                    .concat()
                    .join(" "),
                seen.trim_end(),
                "the record holds exactly the client's words"
            );
            // A second start appends a second line.
            let out = run(&["alpha"]);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            let lines = std::fs::read_to_string(&record).unwrap();
            assert_eq!(
                ArgumentRecord::parse_all(&lines).unwrap(),
                [one.clone(), one.clone()],
                "{lines}"
            );
        }
    }
}
