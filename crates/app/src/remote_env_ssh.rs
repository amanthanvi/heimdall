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
    args.push(remote_init_command(plan)?.into());
    Ok(args)
}

/// What a finished preflight's standard error says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightVerdict {
    /// The runner presented a pinned key (authentication was then refused, as intended).
    HostVerified,
    /// The runner's key is not pinned (changed, or a different host).
    HostKeyMismatch,
    /// Anything else (no connection, a refused name, a timeout).
    Unreachable,
}

/// Classify the preflight's standard error. Only OpenSSH's own markers are read.
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
    } else if text.contains("Permission denied") {
        PreflightVerdict::HostVerified
    } else {
        PreflightVerdict::Unreachable
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
        let unreachable = || {
            OpError::new(
                Code::DestinationUnreachable,
                "the runner could not be reached over the existing access",
            )
        };
        let child = command.spawn().map_err(|_| unreachable())?;
        let output = tokio::time::timeout(PREFLIGHT_BOUND, child.wait_with_output())
            .await
            .map_err(|_| unreachable())?
            .map_err(|_| unreachable())?;
        let stderr = &output.stderr[..output.stderr.len().min(STDERR_MAX)];
        match classify_preflight(stderr) {
            PreflightVerdict::HostVerified => Ok(()),
            PreflightVerdict::HostKeyMismatch => Err(OpError::new(
                Code::HostTrustChanged,
                "the runner's host key is not the catalog-pinned key: nothing was run (repair \
                 the pin through independently verified access; a key is never scanned)",
            )
            .with_reason(reason::ENROLLMENT_HOST_KEY_MISMATCH)),
            PreflightVerdict::Unreachable => Err(unreachable()),
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
            let args =
                bootstrap_args(plan, &pin_file, self.config.as_deref(), &self.extra_options)?;
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
/// `LAUNCH_FAILED` when the client cannot be started.
pub fn spawn_management(ssh_client: &Path, args: &[OsString]) -> Result<ManagementChild, OpError> {
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
        assert!(command.ends_with(&format!(" --owner-key '{ED}'")));
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
            PreflightVerdict::Unreachable
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
}
