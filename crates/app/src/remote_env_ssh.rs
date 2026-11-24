//! ⟨M06 U2⟩ The `ssh` legs of the controller's environment management (ADR-0012 §3.1, §3.3,
//! §5.2). Argument vectors only: no shell string is built here except the one remote
//! command of the bootstrap session, assembled from validated tokens (absolute paths and
//! IDs from a closed character set, the key as type and base64), never escaped.
//!
//! * **Bootstrap** ([`BootstrapSsh`], [`bootstrap_args`]): the owner's existing access
//!   alias, run by the verified `ssh` client with the catalog pin forced on the command line
//!   (`-o` options win over every configuration file): `StrictHostKeyChecking yes`, the pin
//!   file as the only known-hosts source under `HostKeyAlias hm-dest-<id>`, no DNS, no
//!   host-key updates, no multiplexing, no forwarding, no local command. First a
//!   **host-key preflight** ([`preflight_args`]: `PreferredAuthentications none`,
//!   `BatchMode yes`, no command) proves the runner presents a pinned key before anything
//!   authenticates: a mismatch is `HOST_TRUST_CHANGED` (`enrollment_host_key_mismatch`) and
//!   nothing else runs. Then one interactive session with a TTY (`-t`) runs `heimdall remote
//!   init` on the runner, where the owner confirms the enrollment. It shares the user's
//!   terminal, so it is not a `no_window!` child. **No key is ever scanned**: nothing here
//!   runs `ssh-keyscan` or accepts a key it was not given.
//! * **Management sessions** ([`management_args`], [`spawn_management`]): `ssh -F <isolated
//!   configuration> -T -o BatchMode=yes -- hm-env-<id>`, a non-interactive child
//!   (`no_window!`, ruling I-24) with `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `SSH_ASKPASS` and
//!   `SSH_ASKPASS_REQUIRE` removed, standard streams piped, killed on drop. The forced
//!   command on the runner is the bridge; the controller speaks the IPC protocol over the
//!   child's standard streams.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use heimdall_contract::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::IrohEndpointId;
use tokio::io::AsyncReadExt as _;

use super::{BootstrapPlan, BootstrapRunner, ManagementHop};
use crate::error::OpError;

/// The `HostKeyAlias` prefix of a catalog destination's pin (as `heimdall_sshconf::routes`).
pub const DEST_ALIAS_PREFIX: &str = "hm-dest-";

/// How long the host-key preflight may take.
pub const PREFLIGHT_BOUND: Duration = Duration::from_secs(30);

/// The bound on a child's kept standard error.
pub const STDERR_MAX: usize = 64 * 1024;

/// The words `heimdall remote init` is invoked with on the runner (wired by the
/// integrator; its argument shape is DONE question U2-Q4).
pub const REMOTE_INIT: [&str; 2] = ["remote", "init"];

/// ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The flag the bootstrap session appends to
/// the runner's `remote init` ([`bootstrap_args_for`]): after the enrollment the runner says
/// plainly whether its runtime is running and, when it is not, offers to start it in the
/// same attended terminal session with a typed `yes`. A `remote init` the runner's owner
/// runs by hand does not carry it.
pub const OFFER_RUNTIME_START: &str = "--offer-runtime-start";

/// Key types that can be the only trust source of a pin.
const PINNABLE: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

fn usage(message: &str) -> OpError {
    OpError::new(Code::UsageError, message)
}

/// `[A-Za-z0-9._-]`, not starting with `-`, at most 247 bytes (a pin name's suffix).
fn name_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 247
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An absolute POSIX path from a closed character set (`[A-Za-z0-9._/+@-]`, no `..`
/// component), safe as one word of a remote shell command without quoting.
fn remote_path_ok(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && !path.split('/').any(|c| c == "..")
        && path.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'+' | b'@' | b'-')
        })
}

/// A pinned key line's type and base64 blob, validated.
fn pin_parts(line: &str) -> Option<(&str, &str)> {
    if line.chars().any(char::is_control) {
        return None;
    }
    let mut words = line.split_ascii_whitespace();
    let (kind, blob) = (words.next()?, words.next()?);
    let blob_ok = !blob.is_empty()
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    (PINNABLE.contains(&kind) && blob_ok).then_some((kind, blob))
}

/// The host-key signature algorithms of the pinned keys (RSA only through SHA-2).
fn host_key_algorithms(hop: &ManagementHop) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    for line in &hop.host_keys {
        let (kind, _) = pin_parts(line)?;
        let algs: &[&str] = if kind == "ssh-rsa" {
            &["rsa-sha2-512", "rsa-sha2-256"]
        } else {
            std::slice::from_ref(PINNABLE.iter().find(|k| **k == kind)?)
        };
        for a in algs {
            if !out.contains(a) {
                out.push(a);
            }
        }
    }
    (!out.is_empty()).then(|| out.join(","))
}

/// The pin file for `destination`'s hop: `hm-dest-<id> <type> <base64>` lines, sorted.
///
/// # Errors
/// `USAGE_ERROR` for a destination that cannot be a pin name or a key that cannot be a pin;
/// `host_trust_undetermined` when there is no key.
pub fn pin_file_text(destination: &str, hop: &ManagementHop) -> Result<String, OpError> {
    if !name_ok(destination) {
        return Err(usage("the destination ID cannot name a host-key pin"));
    }
    if hop.host_keys.is_empty() {
        return Err(OpError::new(
            Code::CapabilityUnavailable,
            "the destination has no catalog-pinned host key",
        )
        .with_reason(reason::HOST_TRUST_UNDETERMINED));
    }
    let mut lines = Vec::new();
    for key in &hop.host_keys {
        let (kind, blob) =
            pin_parts(key).ok_or_else(|| usage("a pinned host key is not a plain key"))?;
        lines.push(format!("{DEST_ALIAS_PREFIX}{destination} {kind} {blob}\n"));
    }
    lines.sort();
    lines.dedup();
    Ok(lines.concat())
}

/// The trust options every bootstrap invocation forces (module docs).
fn pinned_options(
    destination: &str,
    hop: &ManagementHop,
    pin_file: &Path,
) -> Result<Vec<String>, OpError> {
    let pin_file = pin_file
        .to_str()
        .filter(|p| !p.contains(['"', '\'', '%']) && !p.chars().any(char::is_control))
        .ok_or_else(|| usage("the pin file path cannot be passed to ssh"))?;
    let algorithms =
        host_key_algorithms(hop).ok_or_else(|| usage("a pinned host key is not a plain key"))?;
    Ok(vec![
        "StrictHostKeyChecking=yes".into(),
        format!("UserKnownHostsFile=\"{pin_file}\""),
        "GlobalKnownHostsFile=none".into(),
        "KnownHostsCommand=none".into(),
        format!("HostKeyAlias={DEST_ALIAS_PREFIX}{destination}"),
        format!("HostKeyAlgorithms={algorithms}"),
        "VerifyHostKeyDNS=no".into(),
        "UpdateHostKeys=no".into(),
        "CheckHostIP=no".into(),
        "ControlMaster=no".into(),
        "ControlPath=none".into(),
        "ControlPersist=no".into(),
        "ForwardAgent=no".into(),
        "ForwardX11=no".into(),
        "ClearAllForwardings=yes".into(),
        "PermitLocalCommand=no".into(),
    ])
}

fn push_options(args: &mut Vec<OsString>, options: &[String]) {
    for o in options {
        args.push("-o".into());
        args.push(o.into());
    }
}

/// The ssh configuration selection: `-F <file>` when one is named (tests: a scratch
/// configuration), otherwise the user's own (the existing access).
fn config_args(args: &mut Vec<OsString>, config: Option<&Path>) {
    if let Some(config) = config {
        args.push("-F".into());
        args.push(config.as_os_str().to_owned());
    }
}

/// The host-key preflight's arguments (module docs): no authentication, no command.
///
/// # Errors
/// As [`pin_file_text`], and a pin file path ssh cannot take.
pub fn preflight_args(
    plan: &BootstrapPlan,
    pin_file: &Path,
    config: Option<&Path>,
    extra_options: &[String],
) -> Result<Vec<OsString>, OpError> {
    let destination = plan.access.destination.as_str();
    let mut args = Vec::new();
    config_args(&mut args, config);
    args.push("-T".into());
    let mut options = pinned_options(destination, &plan.access.route.runner, pin_file)?;
    options.extend([
        "BatchMode=yes".to_owned(),
        "PreferredAuthentications=none".to_owned(),
        "ConnectTimeout=15".to_owned(),
    ]);
    options.extend(extra_options.iter().cloned());
    push_options(&mut args, &options);
    args.push("-l".into());
    args.push(plan.access.route.runner.account.as_str().into());
    args.push("--".into());
    args.push(plan.access.alias.as_str().into());
    Ok(args)
}

/// The runner's `remote init` command line (one remote shell command from validated
/// tokens): `"<program>" remote init [--home <abs>] [--expect-sha256 <hex>] --owner-client
/// <cid> --owner-key '<type> <base64>'`.
///
/// # Errors
/// `USAGE_ERROR` for a program or home outside the closed character set, or a key that is
/// not one plain Ed25519 key.
pub fn remote_init_command(plan: &BootstrapPlan) -> Result<String, OpError> {
    remote_init_command_with(plan, None)
}

/// ⟨M06 W3; ADR-0006 §18.7 item 7⟩ [`remote_init_command`] with the controller's CA public key
/// (`issuer_ca`, the active issuer's key when this controller has one): it appends
/// ` --issuer-ca '<type> <base64>'`, so the runner trusts that CA for the owner client being
/// enrolled and designates that client its time source, both confirmed in the same TTY
/// confirmation as the enrollment. `None` (no issuer) omits both. Validated tokens only: the
/// CA key must be one plain Ed25519 key.
///
/// # Errors
/// As [`remote_init_command`], and `USAGE_ERROR` for a CA key that is not one plain Ed25519
/// key.
pub fn remote_init_command_with(
    plan: &BootstrapPlan,
    issuer_ca: Option<&str>,
) -> Result<String, OpError> {
    remote_init_command_for(plan, issuer_ca, None)
}

/// ⟨ADR-0006 §18.7 item 8⟩ [`remote_init_command_with`] with this device's Iroh endpoint ID
/// (`iroh_endpoint`, present when its verified store holds K_iroh): it appends
/// ` --iroh-endpoint <64 lowercase hex>`, so the runner admits the owner client over Iroh
/// and records the endpoint, confirmed in the same TTY confirmation. The ID is a validated
/// token (the contract type admits only 64 lowercase hex characters). `None` omits it.
///
/// # Errors
/// As [`remote_init_command_with`].
pub fn remote_init_command_for(
    plan: &BootstrapPlan,
    issuer_ca: Option<&str>,
    iroh_endpoint: Option<&IrohEndpointId>,
) -> Result<String, OpError> {
    if !remote_path_ok(&plan.runner_program) {
        return Err(usage(
            "the runner program must be an absolute path of letters, digits and ._/+@-",
        ));
    }
    let mut command = format!(
        "{} {} {}",
        plan.runner_program, REMOTE_INIT[0], REMOTE_INIT[1]
    );
    if let Some(home) = &plan.runner_home {
        if !remote_path_ok(home) {
            return Err(usage(
                "the runner home must be an absolute path of letters, digits and ._/+@-",
            ));
        }
        command.push_str(" --home ");
        command.push_str(home);
    }
    if let Some(sha) = &plan.runner_sha256 {
        let ok = sha.len() == 64 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !ok {
            return Err(usage(
                "the runner checksum must be 64 lowercase hexadecimal characters",
            ));
        }
        command.push_str(" --expect-sha256 ");
        command.push_str(sha);
    }
    let (kind, blob) = pin_parts(&plan.owner_key.openssh_line)
        .filter(|(k, _)| *k == "ssh-ed25519")
        .ok_or_else(|| usage("the management key is not one Ed25519 public key"))?;
    let client = plan.owner_client.as_str();
    if !name_ok(client) {
        return Err(usage("the client ID cannot be passed"));
    }
    command.push_str(&format!(
        " --owner-client {client} --owner-key '{kind} {blob}'"
    ));
    if let Some(ca) = issuer_ca {
        let (kind, blob) = pin_parts(ca)
            .filter(|(k, _)| *k == "ssh-ed25519")
            .ok_or_else(|| usage("the controller's CA key is not one Ed25519 public key"))?;
        command.push_str(&format!(" --issuer-ca '{kind} {blob}'"));
    }
    if let Some(endpoint) = iroh_endpoint {
        // Checked again here: the token goes into a remote shell command.
        let id = endpoint.as_str();
        if id.len() != IrohEndpointId::HEX_CHARS
            || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(usage("the Iroh endpoint ID cannot be passed"));
        }
        command.push_str(" --iroh-endpoint ");
        command.push_str(id);
    }
    Ok(command)
}

/// The interactive bootstrap session's arguments (module docs): `-t`, the forced pin, the
/// account, the existing access alias, then the remote `init` command.
///
/// # Errors
/// As [`preflight_args`] and [`remote_init_command`].
pub fn bootstrap_args(
    plan: &BootstrapPlan,
    pin_file: &Path,
    config: Option<&Path>,
    extra_options: &[String],
) -> Result<Vec<OsString>, OpError> {
    bootstrap_args_with(plan, pin_file, config, extra_options, None)
}

/// ⟨M06 W3⟩ [`bootstrap_args`] whose remote command carries the controller's CA key
/// ([`remote_init_command_with`]).
///
/// # Errors
/// As [`bootstrap_args`] and [`remote_init_command_with`].
pub fn bootstrap_args_with(
    plan: &BootstrapPlan,
    pin_file: &Path,
    config: Option<&Path>,
    extra_options: &[String],
    issuer_ca: Option<&str>,
) -> Result<Vec<OsString>, OpError> {
    bootstrap_args_for(plan, pin_file, config, extra_options, issuer_ca, None)
}

/// ⟨ADR-0006 §18.7 item 8⟩ [`bootstrap_args_with`] whose remote command also carries this
/// device's Iroh endpoint ID ([`remote_init_command_for`]).
///
/// # Errors
/// As [`bootstrap_args_with`].
pub fn bootstrap_args_for(
    plan: &BootstrapPlan,
    pin_file: &Path,
    config: Option<&Path>,
    extra_options: &[String],
    issuer_ca: Option<&str>,
    iroh_endpoint: Option<&IrohEndpointId>,
) -> Result<Vec<OsString>, OpError> {
    let destination = plan.access.destination.as_str();
    let mut args = Vec::new();
    config_args(&mut args, config);
    args.push("-t".into());
    let mut options = pinned_options(destination, &plan.access.route.runner, pin_file)?;
    options.extend(extra_options.iter().cloned());
    push_options(&mut args, &options);
    args.push("-l".into());
    args.push(plan.access.route.runner.account.as_str().into());
    args.push("--".into());
    args.push(plan.access.alias.as_str().into());
    // ⟨M06 W5; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The bootstrap is attended on this
    // terminal: the runner says whether its runtime runs and offers to start it there.
    let mut command = remote_init_command_for(plan, issuer_ca, iroh_endpoint)?;
    command.push(' ');
    command.push_str(OFFER_RUNTIME_START);
    args.push(command.into());
    Ok(args)
}

/// What a finished preflight's standard error says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightVerdict {
    /// The runner presented a pinned key (authentication was then refused, as intended).
    HostVerified,
    /// The runner's key is not pinned (changed, or a different host).
    HostKeyMismatch,
    /// The runner was not reached, and why ([`UnreachableCause`]).
    Unreachable(UnreachableCause),
}

/// ⟨M06 W5 `w5v`; ADR-0006 §18.9⟩ Why an `ssh` this controller ran did not reach the runner,
/// from what that `ssh` actually did ([`unreachable_cause`]). Each is one reason
/// ([`UnreachableCause::reason`]) under the code the placement rule gives it
/// ([`UnreachableCause::code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreachableCause {
    /// The client did not start (it could not be spawned, or it ended with a status no
    /// OpenSSH client uses and said nothing).
    ClientNotStarted,
    /// The client refused its own options or configuration before connecting.
    ClientRejected,
    /// The connection was refused.
    ConnectionRefused,
    /// The connection, or its banner exchange, timed out.
    ConnectionTimedOut,
    /// The host name did not resolve.
    NameNotResolved,
    /// Anything else (or nothing said).
    Other,
}

impl UnreachableCause {
    /// Its reason (`heimdall_contract::envelope::reason`).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::ClientNotStarted => reason::SSH_CLIENT_NOT_STARTED,
            Self::ClientRejected => reason::SSH_CLIENT_CONFIG_REJECTED,
            Self::ConnectionRefused => reason::SSH_CONNECTION_REFUSED,
            Self::ConnectionTimedOut => reason::SSH_CONNECTION_TIMED_OUT,
            Self::NameNotResolved => reason::SSH_NAME_NOT_RESOLVED,
            Self::Other => reason::SSH_UNREACHABLE_OTHER,
        }
    }

    /// Its code: the client's own failures, which an unchanged retry cannot fix, are
    /// `CAPABILITY_UNAVAILABLE`; the network outcomes stay `DESTINATION_UNREACHABLE`.
    #[must_use]
    pub fn code(self) -> Code {
        match self {
            Self::ClientNotStarted | Self::ClientRejected => Code::CapabilityUnavailable,
            Self::ConnectionRefused
            | Self::ConnectionTimedOut
            | Self::NameNotResolved
            | Self::Other => Code::DestinationUnreachable,
        }
    }

    /// The error for this cause; `leg` says which `ssh` it was ("over the existing access",
    /// "for a management session"). No path and no address. `Other` keeps the message an
    /// unreached runner always had.
    #[must_use]
    pub fn error(self, leg: &str) -> OpError {
        let message = match self {
            Self::ClientNotStarted => format!(
                "this controller's OpenSSH client did not start, so the runner was not \
                 reached {leg}: nothing was sent"
            ),
            Self::ClientRejected => format!(
                "this controller's OpenSSH client refused its own options or configuration \
                 (a bad option, or a configuration file it could not open or whose owner or \
                 permissions it does not accept), so the runner was not reached {leg}: \
                 nothing was sent"
            ),
            Self::ConnectionRefused => {
                format!("the runner's address refused the connection {leg}")
            }
            Self::ConnectionTimedOut => format!("the connection to the runner timed out {leg}"),
            Self::NameNotResolved => {
                format!("the runner's host name could not be resolved {leg}")
            }
            Self::Other => format!("the runner could not be reached {leg}"),
        };
        OpError::new(self.code(), message).with_reason(self.reason())
    }
}

/// ⟨`w5v`⟩ What the client prints when it refuses its own options or configuration before
/// connecting. The same text in POSIX OpenSSH and Win32-OpenSSH (PowerShell/openssh-portable
/// v9.5.0.0 shares the portable sources): `readconf.c` `"%s: line %d: Bad configuration
/// option: %s"` and `"%s line %d: …"` with the file name `command-line` for a `-o` option
/// (`ssh.c` case `'o'`: then `exit(255)`); `"%s: terminating, %d bad configuration options"`;
/// `"Bad owner or permissions on %s"` (both builds; on Windows
/// `check_secure_file_permission`); `ssh.c` `"Can't open user config file %.100s: %.100s"`;
/// the usage text `"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] …"`; `log.c` `"Couldn't open
/// logfile %s: %s"` (`-E`).
const CLIENT_REJECTED: &[&str] = &[
    "command-line line 0:",
    "command-line: line 0:",
    "Bad configuration option",
    "bad configuration options",
    "Bad owner or permissions on",
    "Can't open user config file",
    "usage: ssh",
    "Couldn't open logfile",
];

/// `ssh.c` `resolve_host`: `"%s: Could not resolve hostname %.100s: %s"`; `"Could not resolve
/// host \"%s\""` (both builds).
const NAME_NOT_RESOLVED: &[&str] = &["Could not resolve host"];

/// `sshconnect.c` `"ssh: connect to host %s port %s: %s"` with `strerror(ECONNREFUSED)`:
/// glibc, macOS and Win32-OpenSSH's `_sys_errlist_ext` (`contrib/win32/win32compat/misc.c`)
/// all say "Connection refused".
const CONNECTION_REFUSED: &[&str] = &["Connection refused"];

/// `strerror(ETIMEDOUT)`: "Connection timed out" (glibc; Win32-OpenSSH's `_sys_errlist_ext`),
/// "Operation timed out" (macOS and the BSDs); `kex.c` "Connection timed out during banner
/// exchange".
const CONNECTION_TIMED_OUT: &[&str] = &["Connection timed out", "Operation timed out"];

/// Why an `ssh` that did not reach the runner failed, read from its standard error (module
/// docs of [`UnreachableCause`]; the markers above, in that order: the client's own refusal
/// first, since a client that refused its configuration never connected).
#[must_use]
pub fn unreachable_cause(stderr: &[u8]) -> UnreachableCause {
    let text = String::from_utf8_lossy(stderr);
    let any = |markers: &[&str]| markers.iter().any(|m| text.contains(m));
    if any(CLIENT_REJECTED) {
        UnreachableCause::ClientRejected
    } else if any(NAME_NOT_RESOLVED) {
        UnreachableCause::NameNotResolved
    } else if any(CONNECTION_REFUSED) {
        UnreachableCause::ConnectionRefused
    } else if any(CONNECTION_TIMED_OUT) {
        UnreachableCause::ConnectionTimedOut
    } else {
        UnreachableCause::Other
    }
}

/// Classify the preflight's standard error. Only OpenSSH's own markers are read. The
/// authentication refusal that proves the pinned key is `"%s@%s: Permission denied (%s)."`
/// (`sshconnect2.c`, both builds): the parenthesis keeps a `strerror(EACCES)` ("Permission
/// denied" after a file name the client could not open) from reading as a verified host.
#[must_use]
pub fn classify_preflight(stderr: &[u8]) -> PreflightVerdict {
    let text = String::from_utf8_lossy(stderr);
    let mismatch = [
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
        "No matching host key type found",
        "host key is known for",
    ];
    if mismatch.iter().any(|m| text.contains(m)) {
        PreflightVerdict::HostKeyMismatch
    } else if text.contains("Permission denied (") {
        PreflightVerdict::HostVerified
    } else {
        PreflightVerdict::Unreachable(unreachable_cause(stderr))
    }
}

/// ⟨M06 W5 `w5v`, PC job 44⟩ The variable Win32-OpenSSH needs before it can start or say
/// anything: `w32posix_initialize` (contrib/win32/win32compat/w32fd.c, PowerShell/openssh-portable
/// v9.5.0.0) calls `init_prog_paths` first, which does `fatal("couldn't find ProgramData
/// environment variable")` when it is unset. That runs before `fd_table_initialize`, so the
/// message is written to an fd that does not exist yet (`w32_write`: `EBADF`) and the client
/// exits 255 having printed nothing. That was job 44: the journey's driver started
/// `heimdall` with an explicit environment that had no `ProgramData`, and the preflight's
/// `ssh.exe` inherited it.
pub const WINDOWS_CLIENT_REQUIRED_ENV: &str = "ProgramData";

/// ⟨`w5v`⟩ The refusal when the environment an `ssh` child would inherit lacks
/// [`WINDOWS_CLIENT_REQUIRED_ENV`] (`env` looks a name up; the product passes the process
/// environment). `None` when it is set and not empty. Checked before every non-interactive
/// `ssh` this controller starts on Windows ([`BootstrapSsh::preflight`],
/// [`spawn_management`]); elsewhere the check is never made. The OpenSSH client would not start
/// properly and would not say why, so nothing is started: `CAPABILITY_UNAVAILABLE`,
/// `ssh_client_not_started`, and the message names the variable. No path.
#[must_use]
pub fn windows_client_environment_refusal(
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Option<OpError> {
    let set = env(WINDOWS_CLIENT_REQUIRED_ENV).is_some_and(|v| !v.is_empty());
    (!set).then(|| {
        OpError::new(
            Code::CapabilityUnavailable,
            format!(
                "this controller's environment has no {WINDOWS_CLIENT_REQUIRED_ENV} variable, \
                 which the Windows OpenSSH client needs before it can start or report an error, \
                 so no ssh was started and nothing was sent; run Heimdall from an ordinary \
                 Windows session (or set {WINDOWS_CLIENT_REQUIRED_ENV}), then try again"
            ),
        )
        .with_reason(reason::SSH_CLIENT_NOT_STARTED)
    })
}

/// [`windows_client_environment_refusal`] for this process, on Windows only.
fn client_environment_refusal() -> Option<OpError> {
    if cfg!(windows) {
        windows_client_environment_refusal(&|n| std::env::var_os(n))
    } else {
        None
    }
}

/// ⟨`w5v`⟩ A finished preflight: [`classify_preflight`], except that a client that said
/// nothing and ended with a status no OpenSSH client uses (`ssh` exits 0–255; a Windows
/// loader failure such as a missing DLL ends with an NTSTATUS, a negative `i32`) did not
/// start.
#[must_use]
pub fn classify_preflight_run(exit: Option<i32>, stderr: &[u8]) -> PreflightVerdict {
    let silent = stderr.iter().all(u8::is_ascii_whitespace);
    if silent && exit.is_some_and(|c| !(0..=255).contains(&c)) {
        PreflightVerdict::Unreachable(UnreachableCause::ClientNotStarted)
    } else {
        classify_preflight(stderr)
    }
}

/// ⟨`w5v`; debug builds only, `HEIMDALL_TEST_SSH_STDERR_FILE`⟩ Append one `ssh` run's
/// standard error to the diagnostic file, under a header naming the leg and its exit. Best
/// effort: a failure to write it changes nothing else.
pub fn append_stderr_record(file: &Path, leg: &str, exit: Option<i32>, stderr: &[u8]) {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    if let Ok(mut f) = options.open(file) {
        let exit = exit.map_or_else(|| "none".to_owned(), |c| c.to_string());
        let _ = writeln!(f, "### {leg} exit={exit}");
        let _ = f.write_all(&stderr[..stderr.len().min(STDERR_MAX)]);
        let _ = writeln!(f);
    }
}

/// The production [`BootstrapRunner`]: the verified `ssh` client over the existing access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSsh {
    /// The verified `ssh` client (absolute).
    pub ssh_client: PathBuf,
    /// A private directory (owner-only) for the pin file of this bootstrap.
    pub scratch_dir: PathBuf,
    /// `-F <file>`: tests only (a scratch configuration); production reads the user's own.
    pub config: Option<PathBuf>,
    /// Extra `-o` options: tests only (the fixture isolation options).
    pub extra_options: Vec<String>,
    /// ⟨`w5v`⟩ Debug builds only (`HEIMDALL_TEST_SSH_STDERR_FILE`, an absolute scratch
    /// path): the preflight's standard error is appended there, and the interactive
    /// session gets `-E <file>` so its client's own messages go there too. `None` in
    /// production.
    pub stderr_file: Option<PathBuf>,
    /// ⟨M06 W3⟩ The controller's CA public key line (its active issuer's), passed to the
    /// runner's `remote init` ([`remote_init_command_with`]); `None` when this controller has
    /// no issuer.
    pub issuer_ca: Option<String>,
    /// ⟨ADR-0006 §18.7 item 8⟩ This device's Iroh endpoint ID, when its verified store holds
    /// K_iroh: passed to the runner's `remote init` ([`remote_init_command_for`]), which
    /// admits the owner client over Iroh with it. `None`: no Iroh key, nothing is passed.
    pub iroh_endpoint: Option<IrohEndpointId>,
}

impl BootstrapSsh {
    /// The client is an absolute path (the verified client's selection): never a `PATH`
    /// lookup at spawn time.
    fn check_client(&self) -> Result<(), OpError> {
        if self.ssh_client.is_absolute() {
            Ok(())
        } else {
            Err(OpError::new(
                Code::LaunchFailed,
                "no OpenSSH client was found (the verified client's selection)",
            ))
        }
    }

    fn write_pin_file(&self, plan: &BootstrapPlan) -> Result<PathBuf, OpError> {
        let text = pin_file_text(plan.access.destination.as_str(), &plan.access.route.runner)?;
        // ⟨M06 W5⟩ The directory may not exist yet: on a new installation the bootstrap runs
        // before any management session has made it (found by the Windows journey's driver:
        // the first `environment add` failed here, after K_mgmt had been created).
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.scratch_dir).map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "the bootstrap pin file could not be written",
            )
        })?;
        let path = self.scratch_dir.join("bootstrap_known_hosts");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|_| {
            OpError::new(
                Code::StateUnavailable,
                "the bootstrap pin file could not be written",
            )
        })?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| {
                OpError::new(
                    Code::StateUnavailable,
                    "the bootstrap pin file could not be written",
                )
            })?;
        Ok(path)
    }

    /// Run the host-key preflight (module docs).
    ///
    /// # Errors
    /// `HOST_TRUST_CHANGED` (`enrollment_host_key_mismatch`) when the runner's key is not
    /// pinned; `DESTINATION_UNREACHABLE` otherwise.
    pub async fn preflight(&self, plan: &BootstrapPlan, pin_file: &Path) -> Result<(), OpError> {
        self.check_client()?;
        let args = preflight_args(plan, pin_file, self.config.as_deref(), &self.extra_options)?;
        // ⟨`w5v`, PC job 44⟩ A Windows client that cannot start says nothing: refuse first.
        if let Some(refusal) = client_environment_refusal() {
            if let Some(file) = &self.stderr_file {
                append_stderr_record(file, "preflight (not started: no ProgramData)", None, b"");
            }
            return Err(refusal);
        }
        let mut command = crate::no_window!(tokio::process::Command::new(&self.ssh_client));
        command
            .args(&args)
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        const LEG: &str = "over the existing access";
        let Ok(child) = command.spawn() else {
            if let Some(file) = &self.stderr_file {
                append_stderr_record(file, "preflight (not started)", None, b"");
            }
            return Err(UnreachableCause::ClientNotStarted.error(LEG));
        };
        let output = match tokio::time::timeout(PREFLIGHT_BOUND, child.wait_with_output()).await {
            Ok(Ok(output)) => output,
            Ok(Err(_)) => return Err(UnreachableCause::Other.error(LEG)),
            Err(_) => return Err(UnreachableCause::ConnectionTimedOut.error(LEG)),
        };
        let stderr = &output.stderr[..output.stderr.len().min(STDERR_MAX)];
        let exit = output.status.code();
        if let Some(file) = &self.stderr_file {
            append_stderr_record(file, "preflight", exit, stderr);
        }
        match classify_preflight_run(exit, stderr) {
            PreflightVerdict::HostVerified => Ok(()),
            PreflightVerdict::HostKeyMismatch => Err(OpError::new(
                Code::HostTrustChanged,
                "the runner's host key is not the catalog-pinned key: nothing was run (repair \
                 the pin through independently verified access; a key is never scanned)",
            )
            .with_reason(reason::ENROLLMENT_HOST_KEY_MISMATCH)),
            PreflightVerdict::Unreachable(cause) => Err(cause.error(LEG)),
        }
    }
}

#[async_trait::async_trait]
impl BootstrapRunner for BootstrapSsh {
    async fn run(&self, plan: &BootstrapPlan) -> Result<(), OpError> {
        self.check_client()?;
        let pin_file = self.write_pin_file(plan)?;
        let result = async {
            self.preflight(plan, &pin_file).await?;
            let mut args = bootstrap_args_for(
                plan,
                &pin_file,
                self.config.as_deref(),
                &self.extra_options,
                self.issuer_ca.as_deref(),
                self.iroh_endpoint.as_ref(),
            )?;
            // ⟨`w5v`, debug builds only⟩ The client's own messages to the diagnostic file
            // (`-E`, first: before every other argument).
            if let Some(file) = &self.stderr_file {
                append_stderr_record(file, "bootstrap session (its -E log follows)", None, b"");
                args.splice(0..0, [OsString::from("-E"), file.as_os_str().to_owned()]);
            }
            // The interactive session shares the user's terminal: not a `no_window!` child.
            let status = tokio::process::Command::new(&self.ssh_client)
                .args(&args)
                .env_remove("SSH_ASKPASS")
                .env_remove("SSH_ASKPASS_REQUIRE")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .await
                .map_err(|_| {
                    OpError::new(Code::LaunchFailed, "the ssh client could not be started")
                })?;
            if status.success() {
                Ok(())
            } else {
                Err(OpError::new(
                    Code::OutcomeUnknown,
                    "the bootstrap session did not complete: nothing was recorded on this \
                     controller; run `environment add` again to repair",
                ))
            }
        }
        .await;
        let _ = std::fs::remove_file(&pin_file);
        result
    }
}

/// The management session's arguments: `-F <isolated configuration> -T -o BatchMode=yes
/// -o ConnectTimeout=15 -- <alias>` (no command: the runner's forced command is the
/// bridge).
#[must_use]
pub fn management_args(config: &Path, alias: &str) -> Vec<OsString> {
    vec![
        "-F".into(),
        config.as_os_str().to_owned(),
        "-T".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "--".into(),
        alias.into(),
    ]
}

/// A running management `ssh` child: its standard streams and its kept standard error.
#[derive(Debug)]
pub struct ManagementChild {
    /// The child (killed on drop).
    pub child: tokio::process::Child,
    /// Its standard input (frames to the runner).
    pub stdin: tokio::process::ChildStdin,
    /// Its standard output (frames from the runner).
    pub stdout: tokio::process::ChildStdout,
    /// Its standard error, kept up to [`STDERR_MAX`].
    pub stderr: Arc<Mutex<Vec<u8>>>,
}

/// Spawn the management `ssh` (module docs).
///
/// # Errors
/// `LAUNCH_FAILED` when the client cannot be started; on Windows `CAPABILITY_UNAVAILABLE`
/// (`ssh_client_not_started`) when the environment lacks `ProgramData`
/// ([`windows_client_environment_refusal`]).
pub fn spawn_management(ssh_client: &Path, args: &[OsString]) -> Result<ManagementChild, OpError> {
    // ⟨`w5v`⟩ As the preflight: a Windows client that cannot start says nothing.
    if let Some(refusal) = client_environment_refusal() {
        return Err(refusal);
    }
    let mut command = crate::no_window!(tokio::process::Command::new(ssh_client));
    command
        .args(args)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let failed = || OpError::new(Code::LaunchFailed, "the ssh client could not be started");
    let mut child = command.spawn().map_err(|_| failed())?;
    let (Some(stdin), Some(stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(failed());
    };
    let kept = Arc::new(Mutex::new(Vec::new()));
    let sink = kept.clone();
    tokio::spawn(async move {
        let mut chunk = [0u8; 4096];
        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut kept = sink.lock().unwrap_or_else(PoisonError::into_inner);
                    let room = STDERR_MAX.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
    });
    Ok(ManagementChild {
        child,
        stdin,
        stdout,
        stderr: kept,
    })
}

// --- the confirming probes (ADR-0012 §3.2; ADR-0006 §18.7 items 16–17) ---------------------

/// The bridge's closing message when sshd allocated a terminal for its session (its own
/// check at start, item 17). The PTY probe looks for it on standard output.
pub const SESSION_REFUSED_PTY: &str = "management session refused: sshd allocated a terminal";
/// The bridge's closing message when sshd forwarded an agent into its session (item 17).
pub const SESSION_REFUSED_AGENT: &str = "management session refused: sshd forwarded an agent";
/// The bridge's closing message when the probe's `SetEnv` variable reached it.
pub const SESSION_REFUSED_SETENV: &str =
    "management session refused: sshd delivered a client variable";
/// The variable the `SetEnv` probe offers. A verified policy accepts only `LANG` and `LC_*`,
/// so it never arrives there. Its value is fixed and means nothing.
pub const SETENV_PROBE_NAME: &str = "HEIMDALL_SETENV_PROBE";

/// How long one confirming probe may take.
pub const PROBE_BOUND: Duration = Duration::from_secs(30);

/// The OpenSSH client's statement that the server refused its PTY request.
const PTY_REQUEST_FAILED: &str = "PTY allocation request failed";

/// Where the `-W` probe asks the runner to connect: loopback's port 1, so a runner that
/// (wrongly) permits the forward reaches nothing.
const FORWARD_PROBE_TARGET: &str = "127.0.0.1:1";

/// One of the four confirming probes, each its own `ssh` run with the enrolled key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// Ask for a PTY (`-tt`).
    Pty,
    /// Ask for a `-W` forward.
    Forward,
    /// Offer agent forwarding, with a disposable agent that holds nothing.
    AgentForward,
    /// Offer a `SetEnv` variable ([`SETENV_PROBE_NAME`]).
    SetEnv,
}

/// What one probe showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The runner refused it: the session is restricted in this respect.
    Refused,
    /// The runner granted it.
    Granted,
    /// Neither was shown (the run failed, timed out, or said nothing recognizable).
    Inconclusive,
}

/// What one probe's `ssh` run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeRun {
    /// The exit status, when the child exited by itself.
    pub exit: Option<i32>,
    /// Its standard output, up to [`STDERR_MAX`].
    pub stdout: Vec<u8>,
    /// Its standard error, up to [`STDERR_MAX`].
    pub stderr: Vec<u8>,
}

/// A probe's arguments: the management session's ([`management_args`]: the same isolated
/// `-F` configuration and alias, so the same key, pins and route), with the one request
/// under test given on the command line, where it wins over the configuration.
/// `disposable_agent` is the socket of an agent that holds nothing, used by
/// [`ProbeKind::AgentForward`] only: K_mgmt's own agent is never offered for forwarding.
/// `None` when that socket's path cannot be written as an option value.
#[must_use]
pub fn probe_args(
    config: &Path,
    alias: &str,
    kind: ProbeKind,
    disposable_agent: &Path,
) -> Option<Vec<OsString>> {
    let mut args: Vec<OsString> = vec![
        "-F".into(),
        config.as_os_str().to_owned(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=15".into(),
    ];
    match kind {
        ProbeKind::Pty => args.push("-tt".into()),
        ProbeKind::Forward => {
            args.push("-W".into());
            args.push(FORWARD_PROBE_TARGET.into());
        }
        ProbeKind::AgentForward => {
            let socket = disposable_agent.to_str()?;
            if !disposable_agent.is_absolute()
                || socket.bytes().any(|b| b == b'"' || b.is_ascii_control())
            {
                return None;
            }
            args.push("-T".into());
            args.push("-o".into());
            // An explicit socket, never `yes`: with `IdentityAgent` set, `yes` would offer
            // the agent that holds K_mgmt.
            args.push(format!("ForwardAgent=\"{socket}\"").into());
        }
        ProbeKind::SetEnv => {
            args.push("-T".into());
            args.push("-o".into());
            args.push(format!("SetEnv={SETENV_PROBE_NAME}=1").into());
        }
    }
    args.push("--".into());
    args.push(alias.into());
    Some(args)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// Read a probe's run. Only positive evidence counts, either way:
/// * a session probe (PTY, agent, `SetEnv`) was **granted** when the bridge's own refusal
///   for exactly that is on standard output, and **refused** when the bridge ran and ended
///   normally (exit 0: it saw no terminal, no agent and no probe variable);
/// * the PTY was also **refused** when the client itself says the request failed (observed
///   with OpenSSH 10: a refused `-tt` request ends the run with status 255 and that line);
/// * the forward was **refused** when the client reports the channel administratively
///   prohibited, and **granted** when the runner tried the connection or opened it.
///
/// Anything else is inconclusive.
#[must_use]
pub fn classify_probe(kind: ProbeKind, run: &ProbeRun) -> ProbeVerdict {
    let own = match kind {
        ProbeKind::Pty => SESSION_REFUSED_PTY,
        ProbeKind::AgentForward => SESSION_REFUSED_AGENT,
        ProbeKind::SetEnv => SESSION_REFUSED_SETENV,
        ProbeKind::Forward => {
            return if contains(&run.stderr, "administratively prohibited") {
                ProbeVerdict::Refused
            } else if run.exit == Some(0) || contains(&run.stderr, "connect failed") {
                ProbeVerdict::Granted
            } else {
                ProbeVerdict::Inconclusive
            };
        }
    };
    if contains(&run.stdout, own) {
        ProbeVerdict::Granted
    } else if run.exit == Some(0)
        || (kind == ProbeKind::Pty && contains(&run.stderr, PTY_REQUEST_FAILED))
    {
        ProbeVerdict::Refused
    } else {
        ProbeVerdict::Inconclusive
    }
}

/// The observation four verdicts make (`Join.probe`): `None` when any is inconclusive, so
/// a failed run is never reported as a grant or a refusal.
#[must_use]
pub fn observation(
    pty: ProbeVerdict,
    forward: ProbeVerdict,
    agent: ProbeVerdict,
    setenv: ProbeVerdict,
) -> Option<heimdall_contract::remote::ProbeObservation> {
    let refused = |v: ProbeVerdict| match v {
        ProbeVerdict::Refused => Some(true),
        ProbeVerdict::Granted => Some(false),
        ProbeVerdict::Inconclusive => None,
    };
    Some(heimdall_contract::remote::ProbeObservation {
        pty_refused: refused(pty)?,
        forward_refused: refused(forward)?,
        agent_forward_refused: refused(agent)?,
        setenv_canary_delivered: !refused(setenv)?,
    })
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(mut from: R) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match from.read(&mut chunk).await {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                let room = STDERR_MAX.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
}

/// Run one probe: a non-interactive `ssh` child (`no_window!`) with the same environment
/// removals as a management session, no standard input, bounded by [`PROBE_BOUND`]. A
/// child that cannot be started or does not end in time is an empty run (inconclusive).
pub async fn run_probe(ssh_client: &Path, args: &[OsString]) -> ProbeRun {
    let mut command = crate::no_window!(tokio::process::Command::new(ssh_client));
    command
        .args(args)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return ProbeRun::default();
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return ProbeRun::default();
    };
    let run = async {
        let (stdout, stderr, status) =
            tokio::join!(read_bounded(stdout), read_bounded(stderr), child.wait());
        ProbeRun {
            exit: status.ok().and_then(|s| s.code()),
            stdout,
            stderr,
        }
    };
    tokio::time::timeout(PROBE_BOUND, run)
        .await
        .unwrap_or_default()
}

/// A disposable agent for the agent-forwarding probe: a socket that accepts a connection
/// and closes it. It holds no key and answers nothing; it exists so the client has an
/// agent to offer. Stops when dropped.
#[cfg(unix)]
#[derive(Debug)]
pub struct DisposableAgent {
    socket: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl DisposableAgent {
    /// Listen at `socket` (inside the session's own owner-only directory).
    ///
    /// # Errors
    /// The socket could not be bound.
    pub fn start(socket: &Path) -> std::io::Result<Self> {
        let listener = tokio::net::UnixListener::bind(socket)?;
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Ok(Self {
            socket: socket.to_path_buf(),
            task,
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

#[cfg(unix)]
impl Drop for DisposableAgent {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Run the four confirming probes through the management session's configuration
/// ([`probe_args`]), one after another, and report what they observed. `None` when any
/// was inconclusive (nothing is guessed).
#[cfg(unix)]
pub async fn run_probes(
    ssh_client: &Path,
    config: &Path,
    alias: &str,
    disposable_agent: &DisposableAgent,
) -> Option<heimdall_contract::remote::ProbeObservation> {
    let mut verdicts = [ProbeVerdict::Inconclusive; 4];
    let kinds = [
        ProbeKind::Pty,
        ProbeKind::Forward,
        ProbeKind::AgentForward,
        ProbeKind::SetEnv,
    ];
    for (verdict, kind) in verdicts.iter_mut().zip(kinds) {
        let args = probe_args(config, alias, kind, disposable_agent.socket())?;
        *verdict = classify_probe(kind, &run_probe(ssh_client, &args).await);
        if *verdict == ProbeVerdict::Inconclusive {
            return None;
        }
    }
    let [pty, forward, agent, setenv] = verdicts;
    observation(pty, forward, agent, setenv)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use heimdall_contract::ids::{AccountName, ClientId, DestinationId, KeyFingerprint};

    use super::super::{ManagementRoute, MgmtKeyInfo, VerifiedAccess};
    use super::*;

    const ED: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn";

    pub(crate) fn plan() -> BootstrapPlan {
        BootstrapPlan {
            access: VerifiedAccess {
                destination: DestinationId::parse("lab").unwrap(),
                alias: "lab".into(),
                route: ManagementRoute {
                    runner: ManagementHop {
                        hostname: "10.0.0.7".into(),
                        port: None,
                        account: AccountName::parse("runner").unwrap(),
                        host_keys: vec![format!("{ED} host")],
                    },
                    jump: None,
                },
            },
            runner_program: "/opt/heimdall/bin/heimdall".into(),
            runner_home: None,
            runner_sha256: None,
            owner_key: MgmtKeyInfo {
                openssh_line: format!("{ED} heimdall-mgmt"),
                fingerprint: KeyFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap(),
            },
            owner_client: ClientId::from_random_bytes([1; 16]),
        }
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// m06-plan U2 "adapter: bootstrap refuses an unverified host key, and no `ssh-keyscan`
    /// is ever run" (the argument half; the fixture-sshd half is
    /// `integration_remote_env_m06`): every bootstrap invocation forces the catalog pin as
    /// the only trust source, strict checking, no multiplexing and no forwarding, and no
    /// argument anywhere names a key scan or accepts a new key.
    #[test]
    fn bootstrap_forces_the_pin_and_never_scans() {
        let pin = Path::new("/home/u/.local/state/heimdall/mgmt/bootstrap_known_hosts");
        let preflight = strings(&preflight_args(&plan(), pin, None, &[]).unwrap());
        let session = strings(&bootstrap_args(&plan(), pin, None, &[]).unwrap());
        for args in [&preflight, &session] {
            for required in [
                "StrictHostKeyChecking=yes",
                "UserKnownHostsFile=\"/home/u/.local/state/heimdall/mgmt/bootstrap_known_hosts\"",
                "GlobalKnownHostsFile=none",
                "KnownHostsCommand=none",
                "HostKeyAlias=hm-dest-lab",
                "HostKeyAlgorithms=ssh-ed25519",
                "UpdateHostKeys=no",
                "VerifyHostKeyDNS=no",
                "ControlMaster=no",
                "ControlPath=none",
                "ForwardAgent=no",
                "ClearAllForwardings=yes",
                "PermitLocalCommand=no",
            ] {
                assert!(
                    args.iter().any(|a| a == required),
                    "{required} missing in {args:?}"
                );
            }
            let joined = args.join(" ").to_ascii_lowercase();
            for forbidden in [
                "keyscan",
                "accept-new",
                "stricthostkeychecking=no",
                "stricthostkeychecking=ask",
            ] {
                assert!(!joined.contains(forbidden), "{forbidden} in {args:?}");
            }
        }
        assert!(preflight.contains(&"PreferredAuthentications=none".to_owned()));
        assert!(preflight.contains(&"BatchMode=yes".to_owned()));
        assert_eq!(
            preflight.last().unwrap(),
            "lab",
            "no remote command in the preflight"
        );
        assert!(session.contains(&"-t".to_owned()));
        let command = session.last().unwrap();
        assert!(command.starts_with("/opt/heimdall/bin/heimdall remote init --owner-client cl_"));
        // ⟨M06 W5⟩ The attended bootstrap session, and only it, asks the runner to state
        // whether its runtime runs and to offer its start.
        assert!(command.ends_with(&format!(" --owner-key '{ED}' {OFFER_RUNTIME_START}")));
        assert!(
            !remote_init_command(&plan())
                .unwrap()
                .contains(OFFER_RUNTIME_START)
        );
        assert_eq!(
            pin_file_text("lab", &plan().access.route.runner).unwrap(),
            format!("hm-dest-lab {ED}\n")
        );
    }

    #[test]
    fn refused_inputs_and_preflight_classification() {
        let mut p = plan();
        p.access.route.runner.host_keys.clear();
        assert_eq!(
            pin_file_text("lab", &p.access.route.runner)
                .unwrap_err()
                .reason
                .as_deref(),
            Some(reason::HOST_TRUST_UNDETERMINED)
        );
        for bad in [
            "relative/heimdall",
            "/opt/heim dall",
            "/opt/$(x)",
            "/opt/../bin/x",
            "/opt/a;b",
        ] {
            let mut p = plan();
            p.runner_program = bad.into();
            assert!(remote_init_command(&p).is_err(), "{bad}");
        }
        let mut p = plan();
        p.runner_home = Some("/home/r/.heimdall'x".into());
        assert!(remote_init_command(&p).is_err());
        let mut p = plan();
        p.runner_sha256 = Some("AB".repeat(32));
        assert!(remote_init_command(&p).is_err(), "uppercase");
        p.runner_sha256 = Some("ab".repeat(32));
        p.runner_home = Some("/srv/runner/heimdall".into());
        let cmd = remote_init_command(&p).unwrap();
        assert!(cmd.contains(" remote init --home /srv/runner/heimdall --expect-sha256 abab"));
        let mut p = plan();
        p.owner_key.openssh_line = "ssh-rsa AAAA".into();
        assert!(remote_init_command(&p).is_err());
        // ⟨M06 W3⟩ The controller's CA key: appended as one validated token pair; omitted
        // without an issuer; anything but one plain Ed25519 key refused.
        let with_ca =
            remote_init_command_with(&plan(), Some(&format!("{ED} ca@controller"))).unwrap();
        assert!(with_ca.ends_with(&format!(" --owner-key '{ED}' --issuer-ca '{ED}'")));
        assert_eq!(
            remote_init_command_with(&plan(), None).unwrap(),
            remote_init_command(&plan()).unwrap()
        );
        // ⟨§18.7 item 8⟩ This device's endpoint ID: one validated token, last; omitted
        // without K_iroh.
        let endpoint = IrohEndpointId::parse(&"ab".repeat(32)).unwrap();
        let with_iroh = remote_init_command_for(&plan(), None, Some(&endpoint)).unwrap();
        assert!(
            with_iroh.ends_with(&format!(
                " --owner-key '{ED}' --iroh-endpoint {}",
                "ab".repeat(32)
            )),
            "{with_iroh}"
        );
        assert_eq!(
            remote_init_command_for(&plan(), None, None).unwrap(),
            remote_init_command(&plan()).unwrap()
        );
        for bad in [
            "ssh-rsa AAAA",
            "ssh-ed25519 AA'A",
            "ssh-ed25519 AAAA; rm -rf /",
        ] {
            assert!(
                remote_init_command_with(&plan(), Some(bad)).is_err(),
                "{bad}"
            );
        }
        for bad in [
            "ssh-dss AAAA",
            "ssh-ed25519-cert-v01@openssh.com AAAA",
            "ssh-ed25519 AA'A",
        ] {
            let mut p = plan();
            p.access.route.runner.host_keys = vec![bad.into()];
            assert!(
                preflight_args(&p, Path::new("/k"), None, &[]).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            classify_preflight(b"Host key verification failed.\r\n"),
            PreflightVerdict::HostKeyMismatch
        );
        assert_eq!(
            classify_preflight(b"user@127.0.0.1: Permission denied (publickey).\r\n"),
            PreflightVerdict::HostVerified
        );
        assert_eq!(
            classify_preflight(b"ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n"),
            PreflightVerdict::Unreachable(UnreachableCause::ConnectionRefused)
        );
        assert_eq!(
            strings(&management_args(Path::new("/s/mgmt.conf"), "hm-env-env_aa")),
            [
                "-F",
                "/s/mgmt.conf",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                "--",
                "hm-env-env_aa"
            ]
        );
    }

    /// ⟨M06 W5 `w5v`; ADR-0006 §18.9⟩ An unreached runner says why, from what the client
    /// printed. Every line below is a client's real message: the POSIX ones as OpenSSH
    /// 9.x/10.x prints them (glibc and macOS `strerror` texts), the Win32 ones from
    /// PowerShell/openssh-portable v9.5.0.0 (`ssh.c`, `readconf.c`, `sshconnect.c`,
    /// `kex.c`, `log.c`, `contrib/win32/win32compat/misc.c` `_sys_errlist_ext`), the
    /// sources of the in-box `OpenSSH_for_Windows_9.5p2`. Paths and addresses are fixture
    /// values.
    #[test]
    fn an_unreached_runner_is_classified_from_the_clients_own_words() {
        use UnreachableCause as C;
        let cases: &[(&str, &[u8], UnreachableCause)] = &[
            // ssh.c case 'o' -> readconf.c parse_token (both builds), then exit(255).
            (
                "posix/win32 -o unknown keyword",
                b"command-line: line 0: Bad configuration option: knownhostscommandx\r\n",
                C::ClientRejected,
            ),
            (
                "posix/win32 -o bad value",
                b"command-line line 0: unsupported option \"maybe\".\r\n",
                C::ClientRejected,
            ),
            // readconf.c read_config_file_depth (a -F file with a bad line).
            (
                "posix/win32 config file",
                b"C:\\hm\\acct\\.ssh\\config: line 3: Bad configuration option: identityagnet\r\n\
                  C:\\hm\\acct\\.ssh\\config: terminating, 1 bad configuration options\r\n",
                C::ClientRejected,
            ),
            // readconf.c (SSHCONF_CHECKPERM): POSIX st_mode, Windows check_secure_file_permission.
            (
                "posix/win32 bad owner",
                b"Bad owner or permissions on C:\\Users\\u/.ssh/config\r\n",
                C::ClientRejected,
            ),
            // ssh.c process_config_files (-F names a file that cannot be opened).
            (
                "posix/win32 -F unreadable",
                b"Can't open user config file C:\\hm\\acct\\.ssh\\config: No such file or directory\r\n",
                C::ClientRejected,
            ),
            // ssh.c usage() after getopt refused a flag.
            (
                "posix usage",
                b"ssh: illegal option -- J\nusage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n",
                C::ClientRejected,
            ),
            // log.c log_redirect_stderr_to (-E).
            (
                "posix/win32 -E",
                b"Couldn't open logfile C:\\hm\\x\\ssh.log: Permission denied\r\n",
                C::ClientRejected,
            ),
            // ssh.c resolve_host.
            (
                "posix name",
                b"ssh: Could not resolve hostname runner.invalid: Name or service not known\r\n",
                C::NameNotResolved,
            ),
            (
                "win32 name",
                b"ssh: Could not resolve hostname runner.invalid: No such host is known. \r\n",
                C::NameNotResolved,
            ),
            // sshconnect.c ssh_connect_direct, strerror(ECONNREFUSED).
            (
                "posix refused",
                b"ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n",
                C::ConnectionRefused,
            ),
            (
                "win32 refused",
                b"ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n",
                C::ConnectionRefused,
            ),
            // strerror(ETIMEDOUT): glibc / Win32 _sys_errlist_ext, macOS; kex.c banner.
            (
                "linux/win32 timeout",
                b"ssh: connect to host 192.0.2.1 port 22: Connection timed out\r\n",
                C::ConnectionTimedOut,
            ),
            (
                "macos timeout",
                b"ssh: connect to host 192.0.2.1 port 22: Operation timed out\r\n",
                C::ConnectionTimedOut,
            ),
            (
                "banner timeout",
                b"Connection timed out during banner exchange\r\n",
                C::ConnectionTimedOut,
            ),
            // kex.c / sshconnect.c: anything else.
            (
                "closed",
                b"kex_exchange_identification: Connection closed by remote host\r\n\
                  Connection closed by 127.0.0.1 port 2222\r\n",
                C::Other,
            ),
            ("silent", b"", C::Other),
        ];
        for (name, stderr, want) in cases {
            assert_eq!(
                classify_preflight(stderr),
                PreflightVerdict::Unreachable(*want),
                "{name}"
            );
        }
        // A file the client could not open says "Permission denied" without the
        // authentication refusal's parenthesis: not a verified host.
        assert_eq!(
            classify_preflight(b"Couldn't open logfile /s/x.log: Permission denied\n"),
            PreflightVerdict::Unreachable(C::ClientRejected)
        );
        assert_eq!(
            classify_preflight(b"runner@127.0.0.1: Permission denied (publickey,password).\r\n"),
            PreflightVerdict::HostVerified
        );
        // A client that ended with a status no OpenSSH uses and said nothing did not start
        // (Windows: STATUS_DLL_NOT_FOUND); with words, its words decide.
        let dll_not_found = i32::from_ne_bytes(0xC000_0135_u32.to_ne_bytes());
        assert_eq!(
            classify_preflight_run(Some(dll_not_found), b""),
            PreflightVerdict::Unreachable(C::ClientNotStarted)
        );
        assert_eq!(
            classify_preflight_run(Some(255), b""),
            PreflightVerdict::Unreachable(C::Other)
        );
        assert_eq!(
            classify_preflight_run(Some(dll_not_found), b"x: Connection refused\n"),
            PreflightVerdict::Unreachable(C::ConnectionRefused)
        );
        // Codes by the placement rule; reasons as the contract names them; no path.
        for (cause, code, why) in [
            (
                C::ClientNotStarted,
                Code::CapabilityUnavailable,
                reason::SSH_CLIENT_NOT_STARTED,
            ),
            (
                C::ClientRejected,
                Code::CapabilityUnavailable,
                reason::SSH_CLIENT_CONFIG_REJECTED,
            ),
            (
                C::ConnectionRefused,
                Code::DestinationUnreachable,
                reason::SSH_CONNECTION_REFUSED,
            ),
            (
                C::ConnectionTimedOut,
                Code::DestinationUnreachable,
                reason::SSH_CONNECTION_TIMED_OUT,
            ),
            (
                C::NameNotResolved,
                Code::DestinationUnreachable,
                reason::SSH_NAME_NOT_RESOLVED,
            ),
            (
                C::Other,
                Code::DestinationUnreachable,
                reason::SSH_UNREACHABLE_OTHER,
            ),
        ] {
            let e = cause.error("over the existing access");
            assert_eq!(e.code, code, "{cause:?}");
            assert_eq!(e.reason.as_deref(), Some(why), "{cause:?}");
            assert!(reason::M06.contains(&(why, code)), "{cause:?}");
            assert!(
                e.message.ends_with("over the existing access")
                    || e.message.ends_with("nothing was sent"),
                "{}",
                e.message
            );
            assert!(!e.message.contains(['/', '\\']), "{}", e.message);
        }
        assert_eq!(
            C::Other.error("over the existing access").message,
            "the runner could not be reached over the existing access"
        );
    }

    /// ⟨`w5v`⟩ The debug-only diagnostic file: each run appended under its own header.
    #[test]
    fn the_stderr_record_appends_each_run_under_its_header() {
        let dir =
            std::env::temp_dir().join(format!("hm-w5v-stderr-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ssh-stderr.txt");
        append_stderr_record(&file, "preflight", Some(255), b"first\n");
        append_stderr_record(&file, "preflight", None, b"second");
        let text = std::fs::read_to_string(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            text,
            "### preflight exit=255\nfirst\n\n### preflight exit=none\nsecond\n"
        );
    }

    /// ⟨`w5v`⟩ A scratch directory of its own (removed by the caller), a `-F` configuration
    /// that sends the plan's alias to loopback port 1 (nothing listens there), and the
    /// fixture isolation options. Nothing of the account's is read: `-F`, no agent, no key.
    fn real_client_fixture(tag: &str) -> (PathBuf, PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("hm-w5v-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config");
        std::fs::write(
            &config,
            "Host lab\n    HostName 127.0.0.1\n    Port 1\n    IdentitiesOnly yes\n    \
             IdentityAgent none\n    CertificateFile none\n",
        )
        .unwrap();
        let isolation = vec![
            "IdentityFile=none".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "IdentityAgent=none".to_owned(),
            "CertificateFile=none".to_owned(),
        ];
        (dir, config, isolation)
    }

    /// ⟨`w5v`⟩ The real client against the preflight's exact arguments: `ssh -G` (parse and
    /// print the evaluated configuration, no connection) must accept every pinned option
    /// and read the pin file's path back exactly, and a real preflight to a closed loopback
    /// port must say "connection refused", never "rejected its options". This is the
    /// check that tells a client that refuses the bootstrap's options (or mangles the
    /// quoted pin path) from an unreachable runner.
    async fn the_real_client_accepts_the_preflight_options(ssh: &Path, tag: &str) {
        let (dir, config, isolation) = real_client_fixture(tag);
        let scratch = dir.join("mgmt");
        let adapter = BootstrapSsh {
            ssh_client: ssh.to_path_buf(),
            scratch_dir: scratch.clone(),
            config: Some(config.clone()),
            extra_options: isolation.clone(),
            stderr_file: Some(dir.join("ssh-stderr.txt")),
            issuer_ca: None,
            iroh_endpoint: None,
        };
        let plan = plan();
        let pin = adapter.write_pin_file(&plan).unwrap();
        let redact = |text: &str| text.replace(dir.to_string_lossy().as_ref(), "<scratch>");
        let mut g = vec![OsString::from("-G")];
        g.extend(preflight_args(&plan, &pin, Some(&config), &isolation).unwrap());
        let out = std::process::Command::new(ssh)
            .args(&g)
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let dump = String::from_utf8_lossy(&out.stdout).into_owned();
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "ssh -G refused the preflight's options: exit {:?}: {}",
            out.status.code(),
            redact(&said)
        );
        // Win32 may print a path with either separator; a dropped or doubled separator, or a
        // kept quote, still fails.
        let norm = |l: &str| l.trim_end().replace('\\', "/").to_ascii_lowercase();
        let want = norm(&format!("userknownhostsfile {}", pin.to_string_lossy()));
        assert!(
            dump.lines().any(|l| norm(l) == want),
            "the pin file's path did not come back as given: {}",
            redact(
                dump.lines()
                    .find(|l| l.starts_with("userknownhostsfile"))
                    .unwrap_or("(none)")
            )
        );
        assert!(
            dump.lines()
                .any(|l| l.trim_end() == "hostkeyalias hm-dest-lab"),
            "{}",
            redact(&dump)
        );
        let e = adapter.preflight(&plan, &pin).await.unwrap_err();
        let record = std::fs::read_to_string(dir.join("ssh-stderr.txt")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            e.reason.as_deref(),
            Some(reason::SSH_CONNECTION_REFUSED),
            "{e:?}; the client said: {}",
            redact(&record)
        );
        assert_eq!(e.code, Code::DestinationUnreachable);
        assert!(
            record.starts_with("### preflight exit="),
            "{}",
            redact(&record)
        );
    }

    /// ⟨`w5v`, PC job 44⟩ An environment without `ProgramData` (what the journey's driver
    /// gave `heimdall`) is refused before any Windows `ssh` starts, with the variable named;
    /// an empty value counts as unset; a set one passes.
    #[test]
    fn a_windows_client_without_program_data_is_never_started() {
        let refused = windows_client_environment_refusal(&|_| None).unwrap();
        assert_eq!(refused.code, Code::CapabilityUnavailable);
        assert_eq!(
            refused.reason.as_deref(),
            Some(reason::SSH_CLIENT_NOT_STARTED)
        );
        assert!(
            refused.message.contains("no ProgramData variable"),
            "{}",
            refused.message
        );
        assert!(
            !refused.message.contains(['/', '\\']),
            "{}",
            refused.message
        );
        assert!(
            windows_client_environment_refusal(&|n| (n == "ProgramData").then(OsString::new))
                .is_some()
        );
        assert!(
            windows_client_environment_refusal(&|n| {
                (n == "ProgramData").then(|| OsString::from("C:\\ProgramData"))
            })
            .is_none()
        );
        // Off Windows nothing is checked.
        #[cfg(not(windows))]
        assert!(client_environment_refusal().is_none());
    }

    /// ⟨`w5v`, PC job 44⟩ The child half of
    /// [`the_windows_inbox_client_preflight_from_a_pseudoconsole`]: a real preflight to a
    /// closed loopback port, run inside that test's pseudoconsole, printing what it got.
    /// Does nothing unless the parent set `HM_W5V_CHILD`.
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "the child of the_windows_inbox_client_preflight_from_a_pseudoconsole"]
    #[allow(clippy::print_stdout)]
    async fn conpty_preflight_child() {
        if std::env::var_os("HM_W5V_CHILD").is_none() {
            return;
        }
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let ssh = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        let (dir, config, isolation) = real_client_fixture("conpty");
        let adapter = BootstrapSsh {
            ssh_client: ssh,
            scratch_dir: dir.join("mgmt"),
            config: Some(config),
            extra_options: isolation,
            stderr_file: None,
            issuer_ca: None,
            iroh_endpoint: None,
        };
        let plan = plan();
        let pin = adapter.write_pin_file(&plan).unwrap();
        let got = adapter.preflight(&plan, &pin).await;
        let _ = std::fs::remove_dir_all(&dir);
        let reason = got
            .err()
            .and_then(|e| e.reason)
            .unwrap_or_else(|| "none".to_owned());
        // The parent reads this line from the pseudoconsole.
        println!("w5v-child reason={reason} end");
    }

    /// ⟨`w5v`, PC job 44; the orchestrator's test (c)⟩ The journey's conditions for the
    /// preflight: this test binary re-run on a pseudoconsole (`TerminalCommand`, as the
    /// journey's driver runs `heimdall environment add`) with the driver's explicit
    /// environment, its preflight's in-box `ssh.exe` started windowless from there, against
    /// 127.0.0.1:1.
    /// * With `ProgramData` (what the driver now passes): "connection refused", exactly as
    ///   without a pseudoconsole (so the pseudoconsole loses no standard error).
    /// * Without it (what the driver passed in job 44): refused before any ssh starts,
    ///   `ssh_client_not_started`. Before the fix the client exited 255 silently, which read
    ///   `ssh_unreachable_other`: job 44's result.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs the in-box OpenSSH client: run on the Windows PC by exact name"]
    fn the_windows_inbox_client_preflight_from_a_pseudoconsole() {
        let me = std::env::current_exe().unwrap();
        for (with_program_data, want) in [
            (true, reason::SSH_CONNECTION_REFUSED),
            (false, reason::SSH_CLIENT_NOT_STARTED),
        ] {
            let mut command = heimdall_testkit::console::TerminalCommand::new(&me)
                .args([
                    "--ignored",
                    "--exact",
                    "remote_env::ssh::tests::conpty_preflight_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .size(400, 50)
                .env("HM_W5V_CHILD", "1");
            // The driver's list (tests/e2e/windows_controller_m06.rs `environment_add`).
            let mut names = vec![
                "PATH",
                "USERPROFILE",
                "LOCALAPPDATA",
                "APPDATA",
                "TEMP",
                "TMP",
                "USERNAME",
            ];
            if with_program_data {
                names.push("ProgramData");
            }
            for name in names {
                if let Some(value) = std::env::var_os(name) {
                    command = command.env(name, value);
                }
            }
            let mut terminal = command.spawn().expect("a pseudoconsole");
            let shown = terminal.expect("w5v-child reason=", Duration::from_secs(120));
            let _ = terminal.wait(Duration::from_secs(60));
            let text = terminal.text();
            assert!(
                shown.is_ok(),
                "ProgramData={with_program_data}: the child said nothing"
            );
            let line = text
                .lines()
                .find(|l| l.contains("w5v-child reason="))
                .unwrap_or_default()
                .to_owned();
            assert!(
                line.contains(&format!("w5v-child reason={want} end")),
                "ProgramData={with_program_data}: {line}"
            );
        }
    }

    /// ⟨`w5v`⟩ POSIX OpenSSH (the system client, as the macOS rehearsal and the devbox use).
    #[cfg(unix)]
    #[tokio::test]
    async fn the_posix_client_accepts_the_preflight_options() {
        let ssh = Path::new("/usr/bin/ssh");
        assert!(ssh.exists(), "blocked: this host has no /usr/bin/ssh");
        the_real_client_accepts_the_preflight_options(ssh, "posix").await;
    }

    /// ⟨`w5v`; the Windows bootstrap failure of PC job 42⟩ The in-box Win32-OpenSSH client
    /// with the preflight's exact arguments, a Windows pin path (backslashes, quoted in
    /// `UserKnownHostsFile="…"`) and a Windows `-F` path. Ignored: it needs the in-box
    /// client, so it runs on the PC (target/m06-w5/w5v/PC-DIAG.md), by exact name with
    /// `--ignored`.
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "needs the in-box OpenSSH client: run on the Windows PC by exact name"]
    async fn the_windows_inbox_client_accepts_the_preflight_options() {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        let ssh = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        assert!(
            ssh.exists(),
            "blocked: the in-box OpenSSH client is not installed"
        );
        the_real_client_accepts_the_preflight_options(&ssh, "win32").await;
    }

    /// ⟨ADR-0006 §18.7 item 16; ADR-0012 §3.2⟩ The four probes' arguments and how a run is
    /// read. Each probe is the management session's own configuration and alias plus the one
    /// request under test; the agent offered is an explicit disposable socket, never `yes`
    /// (which would offer K_mgmt's agent). Only positive evidence counts: the bridge's own
    /// refusal is a grant, a normal end a refusal, and a failed run is neither.
    #[test]
    fn the_confirming_probes_ask_one_thing_each_and_guess_nothing() {
        // ⟨Windows job 23⟩ Paths absolute on the platform the test runs on: the disposable
        // agent's socket must be absolute, and a rooted path without a drive (`/s/...`)
        // is not absolute on Windows.
        #[cfg(windows)]
        let root = Path::new("C:\\s");
        #[cfg(not(windows))]
        let root = Path::new("/s");
        let (config, agent) = (root.join("mgmt.conf"), root.join("probe-agent.sock"));
        let (config, agent) = (config.as_path(), agent.as_path());
        let (config_text, agent_text) = (config.to_str().unwrap(), agent.to_str().unwrap());
        let args = |kind| strings(&probe_args(config, "hm-env-env_aa", kind, agent).unwrap());
        let head = [
            "-F",
            config_text,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=15",
        ];
        let tail = ["--", "hm-env-env_aa"];
        let middle = |kind| {
            let all = args(kind);
            assert_eq!(all[..head.len()], head, "{kind:?}");
            assert_eq!(all[all.len() - 2..], tail, "{kind:?}");
            all[head.len()..all.len() - 2].to_vec()
        };
        assert_eq!(middle(ProbeKind::Pty), ["-tt"]);
        assert_eq!(middle(ProbeKind::Forward), ["-W", "127.0.0.1:1"]);
        assert_eq!(
            middle(ProbeKind::AgentForward),
            [
                "-T".to_owned(),
                "-o".to_owned(),
                format!("ForwardAgent=\"{agent_text}\"")
            ]
        );
        assert_eq!(
            middle(ProbeKind::SetEnv),
            ["-T", "-o", "SetEnv=HEIMDALL_SETENV_PROBE=1"]
        );
        // A socket path that cannot be written as an option value is refused, and only the
        // agent probe needs one: a relative path, a quote, a control character.
        for bad in [
            PathBuf::from("relative.sock"),
            root.join("a\"b.sock"),
            root.join("a\nb.sock"),
        ] {
            assert!(
                probe_args(config, "x", ProbeKind::AgentForward, &bad).is_none(),
                "{bad:?}"
            );
            assert!(probe_args(config, "x", ProbeKind::Pty, &bad).is_some());
        }
        // On Windows a rooted path without a drive is not absolute, so it is refused too.
        // No agent-forward probe is ever built there in the product: the disposable agent
        // and the probe runner exist on Unix only, and no management session opens on
        // Windows (U2-Q6).
        #[cfg(windows)]
        assert!(
            probe_args(
                config,
                "x",
                ProbeKind::AgentForward,
                Path::new("/s/probe-agent.sock")
            )
            .is_none()
        );

        let run = |exit, stdout: &str, stderr: &str| ProbeRun {
            exit,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        use ProbeVerdict::{Granted, Inconclusive, Refused};
        for (kind, own, other) in [
            (ProbeKind::Pty, SESSION_REFUSED_PTY, SESSION_REFUSED_AGENT),
            (
                ProbeKind::AgentForward,
                SESSION_REFUSED_AGENT,
                SESSION_REFUSED_SETENV,
            ),
            (
                ProbeKind::SetEnv,
                SESSION_REFUSED_SETENV,
                SESSION_REFUSED_PTY,
            ),
        ] {
            // The bridge ran and ended normally: it saw nothing it refuses.
            assert_eq!(classify_probe(kind, &run(Some(0), "", "")), Refused);
            // The client's own statement counts for the PTY probe only.
            let said = "PTY allocation request failed on channel 0\r\n";
            assert_eq!(
                classify_probe(kind, &run(Some(255), "", said)),
                if kind == ProbeKind::Pty {
                    Refused
                } else {
                    Inconclusive
                }
            );
            // The bridge's own refusal, framed (and through a terminal, with noise around).
            let framed = format!("\0\0\0\x60{{\"type\":\"goodbye\",\"message\":\"{own}\"}}\r\n");
            assert_eq!(
                classify_probe(kind, &run(Some(69), &framed, "")),
                Granted,
                "{kind:?}"
            );
            // Another refusal, a failed connection, a timeout: nothing is shown.
            let theirs = format!("{{\"message\":\"{other}\"}}");
            assert_eq!(
                classify_probe(kind, &run(Some(69), &theirs, "")),
                Inconclusive
            );
            assert_eq!(
                classify_probe(kind, &run(Some(255), "", "Connection refused")),
                Inconclusive
            );
            assert_eq!(classify_probe(kind, &ProbeRun::default()), Inconclusive);
        }
        assert_eq!(
            classify_probe(
                ProbeKind::Forward,
                &run(
                    Some(255),
                    "",
                    "channel 0: open failed: administratively prohibited: open failed\r\n\
                     stdio forwarding failed\r\n"
                )
            ),
            Refused
        );
        assert_eq!(
            classify_probe(
                ProbeKind::Forward,
                &run(
                    Some(255),
                    "",
                    "channel 0: open failed: connect failed: Connection refused\r\n"
                )
            ),
            Granted
        );
        assert_eq!(
            classify_probe(ProbeKind::Forward, &run(Some(0), "", "")),
            Granted
        );
        assert_eq!(
            classify_probe(
                ProbeKind::Forward,
                &run(
                    Some(255),
                    "",
                    "ssh: connect to host 127.0.0.1 port 1: Connection refused"
                )
            ),
            Inconclusive
        );

        let observed = observation(Refused, Refused, Refused, Refused).unwrap();
        assert!(observed.pty_refused && observed.forward_refused);
        assert!(observed.agent_forward_refused && !observed.setenv_canary_delivered);
        let observed = observation(Granted, Refused, Granted, Granted).unwrap();
        assert!(!observed.pty_refused && observed.forward_refused);
        assert!(!observed.agent_forward_refused && observed.setenv_canary_delivered);
        for i in 0..4 {
            let mut v = [Refused; 4];
            v[i] = Inconclusive;
            assert_eq!(observation(v[0], v[1], v[2], v[3]), None);
        }
    }
}
