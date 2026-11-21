//! Verified sshd policy for limited roles (ADR-0012 §3.2; M06 U1).
//!
//! **What is verified.** Limited (non-owner) roles are available only on a runner whose
//! effective sshd policy for the account was verified. The verification is `sshd -T -h
//! <scratch host key> -C user=…,host=…,addr=…,laddr=…,lport=…`, run unprivileged as the
//! account ([`check_effective_policy`]); a documented drop-in is checked by the same
//! invocation. Its output is untrusted text, checked by the pure [`verify`]:
//! * `authorizedkeyscommand none` and `authorizedprincipalscommand none`;
//! * `authorizedkeysfile` naming only files Heimdall checks: every entry is expanded
//!   (`%%`, `%h`, `%u`; any other token is refused), resolved against the account's home
//!   and must be a normalized absolute path, and the list must include
//!   `<home>/.ssh/authorized_keys`, the file Heimdall writes. The verified list is every
//!   file the uniqueness check reads ([`VerifiedPolicy::authorized_keys_files`]): there
//!   may be two or more;
//! * `forcecommand none`; `permituserenvironment no`;
//! * `acceptenv` ⊆ {`LANG`, `LC_*`} (each value is `LANG`, `LC_*` or a literal `LC_<NAME>`),
//!   with a POSIX login shell;
//! * `authenticationmethods` that allow publickey alone (`any`, or one list that is exactly
//!   `publickey`), and `pubkeyauthentication` not `no`;
//! * OpenSSH 8.7 or later: `restrict` (7.2) and `expiry-time` (7.7) with the UTC `Z` form
//!   the line uses (8.7).
//!
//! Each single-valued field must appear exactly once; a missing or repeated one is refused
//! by name. A refusal names the failing field ([`PolicyRefusal::field`]) and never echoes
//! the text.
//!
//! **The result** gates limited roles: [`PolicyVerdict::management_policy`] is `verified`
//! or `owner_only`, and a limited-role invitation on an `owner_only` runner is refused
//! `management_sshd_unverified` ([`limited_role_gate`]). Behaviour probes confirm the
//! result and never establish it: a probe that disagrees fails closed
//! (`management_sshd_unsupported`, [`confirm_probe`]).
//!
//! **The run.** The scratch Ed25519 host key is generated in process with `ssh-key` (no
//! `ssh-keygen`), written into a fresh owner-only directory, and destroyed after the run,
//! pass or fail. sshd runs with an empty environment, no stdin, a bounded timeout and
//! bounded output, and is killed if the timeout passes; `-T` never listens. Every child is
//! spawned through `heimdall_app::no_window!` (ADR-0008 §17.43, ruling I-24).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use heimdall_contract::ids::ClientId;
use heimdall_contract::remote::{ManagementPolicy, Role};
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use crate::roles::Refusal;

/// Where sshd usually is.
pub const DEFAULT_SSHD: &str = "/usr/sbin/sshd";

/// The oldest OpenSSH whose `expiry-time` reads the UTC `Z` form the line uses.
pub const MIN_VERSION: OpensshVersion = OpensshVersion { major: 8, minor: 7 };

/// The most output read from one sshd run, per stream.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// The most lines `verify` reads.
pub const MAX_LINES: usize = 8192;

/// The default bound on one sshd run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// The login shells accepted as POSIX (by file name, at an absolute path).
pub const POSIX_SHELLS: &[&str] = &[
    "sh", "bash", "dash", "ksh", "ksh93", "mksh", "zsh", "ash", "yash",
];

/// An OpenSSH release, `major.minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpensshVersion {
    /// Major.
    pub major: u16,
    /// Minor.
    pub minor: u16,
}

impl OpensshVersion {
    /// The first `OpenSSH_<major>.<minor>` in `text` (sshd's banner, from `sshd -V` or its
    /// usage text).
    #[must_use]
    pub fn parse_banner(text: &str) -> Option<Self> {
        let at = text.find("OpenSSH_")?;
        let rest = &text[at + "OpenSSH_".len()..];
        let (major, rest) = rest.split_once('.')?;
        let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if major.is_empty() || major.len() > 4 || minor.is_empty() || minor.len() > 4 {
            return None;
        }
        Some(Self {
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
        })
    }
}

/// The field a refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyField {
    /// The output itself (too large, not text, malformed).
    Output,
    /// The account or its home (outside the accepted forms).
    Account,
    /// The OpenSSH version.
    Version,
    /// `authorizedkeyscommand`.
    AuthorizedKeysCommand,
    /// `authorizedprincipalscommand`.
    AuthorizedPrincipalsCommand,
    /// `authorizedkeysfile`.
    AuthorizedKeysFile,
    /// `forcecommand`.
    ForceCommand,
    /// `permituserenvironment`.
    PermitUserEnvironment,
    /// `acceptenv`.
    AcceptEnv,
    /// The account's login shell.
    LoginShell,
    /// `authenticationmethods`.
    AuthenticationMethods,
    /// `pubkeyauthentication`.
    PubkeyAuthentication,
}

impl PolicyField {
    /// The field's name (the `sshd -T` keyword where it has one).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Output => "output",
            Self::Account => "account",
            Self::Version => "version",
            Self::AuthorizedKeysCommand => "authorizedkeyscommand",
            Self::AuthorizedPrincipalsCommand => "authorizedprincipalscommand",
            Self::AuthorizedKeysFile => "authorizedkeysfile",
            Self::ForceCommand => "forcecommand",
            Self::PermitUserEnvironment => "permituserenvironment",
            Self::AcceptEnv => "acceptenv",
            Self::LoginShell => "login_shell",
            Self::AuthenticationMethods => "authenticationmethods",
            Self::PubkeyAuthentication => "pubkeyauthentication",
        }
    }
}

/// Why the policy was not verified: the failing field and a fixed description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRefusal {
    /// The failing field.
    pub field: PolicyField,
    /// What is wrong with it (fixed text, never the value).
    pub detail: &'static str,
}

fn refuse(field: PolicyField, detail: &'static str) -> PolicyRefusal {
    PolicyRefusal { field, detail }
}

/// A verified policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPolicy {
    /// The OpenSSH release.
    pub version: OpensshVersion,
    /// Every authorized_keys file sshd consults for the account, resolved, in order. The
    /// uniqueness check reads all of them.
    pub authorized_keys_files: Vec<String>,
}

/// The verifier's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Every field holds: limited roles may enroll.
    Verified(VerifiedPolicy),
    /// A field fails: only owners may enroll.
    Refused(PolicyRefusal),
}

impl PolicyVerdict {
    /// `verified` or `owner_only` (ADR-0012 §9 item 5).
    #[must_use]
    pub fn management_policy(&self) -> ManagementPolicy {
        match self {
            Self::Verified(_) => ManagementPolicy::Verified,
            Self::Refused(_) => ManagementPolicy::OwnerOnly,
        }
    }
}

/// The management policy a check produced: `owner_only` for a refusal **and** for a run
/// that did not complete (fail closed).
#[must_use]
pub fn management_policy_of(result: &Result<PolicyVerdict, RunError>) -> ManagementPolicy {
    match result {
        Ok(v) => v.management_policy(),
        Err(_) => ManagementPolicy::OwnerOnly,
    }
}

/// A limited role needs a verified policy (ADR-0012 §3.2): on an `owner_only` runner its
/// invitation is refused `management_sshd_unverified`. Owners always pass.
///
/// # Errors
///
/// [`Refusal::ManagementSshdUnverified`].
pub fn limited_role_gate(role: Role, policy: ManagementPolicy) -> Result<(), Refusal> {
    match (role, policy) {
        (Role::Owner, _) | (_, ManagementPolicy::Verified) => Ok(()),
        _ => Err(Refusal::ManagementSshdUnverified),
    }
}

/// The account the policy is checked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account<'a> {
    /// The account name.
    pub user: &'a str,
    /// Its home directory (absolute).
    pub home: &'a str,
    /// Its login shell, when known.
    pub login_shell: Option<&'a str>,
}

fn user_ok(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with('-')
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parse the output into `(keyword, value)` pairs, bounded. Keywords are case-folded:
/// OpenSSH 9.x prints them in lower case, 10.x in their configuration spelling.
fn parse_pairs(text: &str) -> Result<Vec<(String, &str)>, PolicyRefusal> {
    if text.len() > MAX_OUTPUT_BYTES {
        return Err(refuse(PolicyField::Output, "the output is too large"));
    }
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if out.len() >= MAX_LINES {
            return Err(refuse(PolicyField::Output, "the output has too many lines"));
        }
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err(refuse(
                PolicyField::Output,
                "the output has a control character",
            ));
        }
        let (key, value) = line.split_once([' ', '\t']).unwrap_or((line, ""));
        if key.is_empty() || key.len() > 64 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(refuse(
                PolicyField::Output,
                "the output has a malformed keyword",
            ));
        }
        out.push((key.to_ascii_lowercase(), value.trim()));
    }
    Ok(out)
}

fn single<'a>(
    pairs: &[(String, &'a str)],
    key: &str,
    field: PolicyField,
) -> Result<&'a str, PolicyRefusal> {
    let mut found = pairs.iter().filter(|(k, _)| *k == key).map(|(_, v)| *v);
    match (found.next(), found.next()) {
        (Some(v), None) => Ok(v),
        (None, _) => Err(refuse(
            field,
            "the field is missing from the effective policy",
        )),
        (Some(_), Some(_)) => Err(refuse(field, "the field appears more than once")),
    }
}

fn require(
    pairs: &[(String, &str)],
    key: &str,
    field: PolicyField,
    want: &str,
    detail: &'static str,
) -> Result<(), PolicyRefusal> {
    if single(pairs, key, field)? == want {
        Ok(())
    } else {
        Err(refuse(field, detail))
    }
}

fn accept_env_value_ok(v: &str) -> bool {
    v == "LANG"
        || v == "LC_*"
        || v.strip_prefix("LC_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn login_shell_ok(shell: Option<&str>) -> bool {
    let Some(s) = shell else { return false };
    crate::line::check_abs_path(s).is_ok()
        && s.rsplit('/')
            .next()
            .is_some_and(|name| POSIX_SHELLS.contains(&name))
}

fn methods_allow_publickey_alone(v: &str) -> bool {
    v == "any" || v.split_ascii_whitespace().any(|list| list == "publickey")
}

fn expand_keys_file(entry: &str, account: &Account<'_>) -> Result<String, PolicyRefusal> {
    let mut out = String::new();
    let mut chars = entry.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('h') => out.push_str(account.home),
            Some('u') => out.push_str(account.user),
            _ => {
                return Err(refuse(
                    PolicyField::AuthorizedKeysFile,
                    "a file names a token other than %%, %h or %u",
                ));
            }
        }
    }
    let path = if out.starts_with('/') {
        out
    } else {
        format!("{}/{out}", account.home)
    };
    if crate::line::check_abs_path(&path).is_err() {
        return Err(refuse(
            PolicyField::AuthorizedKeysFile,
            "a file is not a normalized absolute path from the permitted set",
        ));
    }
    Ok(path)
}

/// Verify `sshd -T` output for one Match context (module docs). `version_banner` is the
/// text sshd printed for `-V` (or its usage text); `account` names the account the
/// context was evaluated for.
#[must_use]
pub fn verify(effective: &str, version_banner: &str, account: &Account<'_>) -> PolicyVerdict {
    match verify_inner(effective, version_banner, account) {
        Ok(v) => PolicyVerdict::Verified(v),
        Err(r) => PolicyVerdict::Refused(r),
    }
}

fn verify_inner(
    effective: &str,
    version_banner: &str,
    account: &Account<'_>,
) -> Result<VerifiedPolicy, PolicyRefusal> {
    if !user_ok(account.user) || crate::line::check_abs_path(account.home).is_err() {
        return Err(refuse(
            PolicyField::Account,
            "the account name or home is outside the accepted forms",
        ));
    }
    let pairs = parse_pairs(effective)?;
    let version = OpensshVersion::parse_banner(version_banner)
        .ok_or_else(|| refuse(PolicyField::Version, "the OpenSSH version is unknown"))?;
    if version < MIN_VERSION {
        return Err(refuse(
            PolicyField::Version,
            "the OpenSSH version predates the UTC expiry-time form",
        ));
    }
    require(
        &pairs,
        "authorizedkeyscommand",
        PolicyField::AuthorizedKeysCommand,
        "none",
        "an authorized keys command is configured",
    )?;
    require(
        &pairs,
        "authorizedprincipalscommand",
        PolicyField::AuthorizedPrincipalsCommand,
        "none",
        "an authorized principals command is configured",
    )?;
    require(
        &pairs,
        "forcecommand",
        PolicyField::ForceCommand,
        "none",
        "a ForceCommand applies to the account",
    )?;
    require(
        &pairs,
        "permituserenvironment",
        PolicyField::PermitUserEnvironment,
        "no",
        "user environment files are permitted",
    )?;
    for (_, value) in pairs.iter().filter(|(k, _)| *k == "acceptenv") {
        if !value.split_ascii_whitespace().all(accept_env_value_ok) {
            return Err(refuse(
                PolicyField::AcceptEnv,
                "a client-settable variable outside LANG and LC_* is accepted",
            ));
        }
    }
    if !login_shell_ok(account.login_shell) {
        return Err(refuse(
            PolicyField::LoginShell,
            "the account's login shell is not a known POSIX shell",
        ));
    }
    if !methods_allow_publickey_alone(single(
        &pairs,
        "authenticationmethods",
        PolicyField::AuthenticationMethods,
    )?) {
        return Err(refuse(
            PolicyField::AuthenticationMethods,
            "publickey alone does not complete authentication",
        ));
    }
    let mut pubkey = pairs
        .iter()
        .filter(|(k, _)| *k == "pubkeyauthentication")
        .map(|(_, v)| *v);
    match (pubkey.next(), pubkey.next()) {
        (Some(_), Some(_)) => {
            return Err(refuse(
                PolicyField::PubkeyAuthentication,
                "the field appears more than once",
            ));
        }
        (Some("no"), None) => {
            return Err(refuse(
                PolicyField::PubkeyAuthentication,
                "public key authentication is disabled",
            ));
        }
        _ => {}
    }
    let files_value = single(
        &pairs,
        "authorizedkeysfile",
        PolicyField::AuthorizedKeysFile,
    )?;
    let entries: Vec<&str> = files_value.split_ascii_whitespace().collect();
    if entries.is_empty() || entries.contains(&"none") {
        return Err(refuse(
            PolicyField::AuthorizedKeysFile,
            "no authorized keys file is consulted",
        ));
    }
    let mut files: Vec<String> = Vec::with_capacity(entries.len());
    for e in entries {
        let p = expand_keys_file(e, account)?;
        if !files.contains(&p) {
            files.push(p);
        }
    }
    let written = format!("{}/.ssh/authorized_keys", account.home);
    if !files.contains(&written) {
        return Err(refuse(
            PolicyField::AuthorizedKeysFile,
            "the file Heimdall writes is not consulted",
        ));
    }
    Ok(VerifiedPolicy {
        version,
        authorized_keys_files: files,
    })
}

// --- the confirming probe (ADR-0012 §3.2 "Behaviour probes confirm the result") ----------

/// What the controller's activation probes observed through the enrolled key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// The client ID the bridge echoed from its argv.
    pub echoed_client: Option<ClientId>,
    /// The pending record's nonce the bridge echoed.
    pub echoed_nonce: Option<String>,
    /// A PTY request was refused.
    pub pty_refused: bool,
    /// A `-W` forward was refused.
    pub forward_refused: bool,
    /// Agent forwarding (with a disposable agent) was refused.
    pub agent_forward_refused: bool,
    /// A canary `SetEnv` reached the bridge.
    pub setenv_canary_delivered: bool,
}

/// Confirm a verified policy with the probes: the bridge echoed exactly the client and
/// nonce, a PTY, a forward and agent forwarding were refused, and the `SetEnv` canary was
/// not delivered. Any disagreement fails closed.
///
/// # Errors
///
/// [`Refusal::ManagementSshdUnsupported`].
pub fn confirm_probe(client: &ClientId, nonce: &str, report: &ProbeReport) -> Result<(), Refusal> {
    let agrees = report.echoed_client.as_ref() == Some(client)
        && report.echoed_nonce.as_deref() == Some(nonce)
        && report.pty_refused
        && report.forward_refused
        && report.agent_forward_refused
        && !report.setenv_canary_delivered;
    if agrees {
        Ok(())
    } else {
        Err(Refusal::ManagementSshdUnsupported)
    }
}

// --- the run -------------------------------------------------------------------------------

/// The Match context `sshd -T -C` evaluates: each value validated, so no value can add a
/// criterion (no `,` or `=`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchContext {
    user: String,
    host: String,
    addr: IpAddr,
    laddr: IpAddr,
    lport: u16,
}

impl MatchContext {
    /// Validate a context: `user` from `[A-Za-z0-9._-]`, `host` a host name or address
    /// from `[A-Za-z0-9.:-]`.
    ///
    /// # Errors
    ///
    /// [`RunError::Context`].
    pub fn new(
        user: &str,
        host: &str,
        addr: IpAddr,
        laddr: IpAddr,
        lport: u16,
    ) -> Result<Self, RunError> {
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with('-')
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'));
        if !user_ok(user) || !host_ok {
            return Err(RunError::Context);
        }
        Ok(Self {
            user: user.to_owned(),
            host: host.to_owned(),
            addr,
            laddr,
            lport,
        })
    }

    /// The account name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The `-C` argument.
    #[must_use]
    pub fn spec(&self) -> String {
        format!(
            "user={},host={},addr={},laddr={},lport={}",
            self.user, self.host, self.addr, self.laddr, self.lport
        )
    }
}

/// One effective-policy check.
#[derive(Debug, Clone, Copy)]
pub struct SshdCheck<'a> {
    /// The sshd binary (absolute).
    pub sshd: &'a Path,
    /// `-f` (a drop-in check uses the default configuration: `None`).
    pub config: Option<&'a Path>,
    /// The directory the scratch directory is created in (it must exist).
    pub scratch_parent: &'a Path,
    /// The Match context.
    pub context: &'a MatchContext,
    /// The account's home directory (absolute).
    pub home: &'a str,
    /// The account's login shell, when known ([`login_shell`]).
    pub login_shell: Option<&'a str>,
    /// The bound on each sshd run.
    pub timeout: Duration,
}

/// Why a check did not complete. The management policy is then `owner_only`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    /// A Match context value is outside its accepted form.
    #[error("a Match context value is outside its accepted form")]
    Context,
    /// The sshd path is not absolute.
    #[error("the sshd path is not absolute")]
    SshdPath,
    /// The scratch directory or key file could not be created.
    #[error("the scratch directory could not be created")]
    Scratch,
    /// The operating system's randomness or the key encoding failed.
    #[error("the scratch host key could not be generated")]
    KeyGeneration,
    /// sshd could not be started.
    #[error("sshd could not be started")]
    Spawn,
    /// sshd did not finish within the bound (it was killed).
    #[error("sshd did not finish within the bound")]
    Timeout,
    /// `sshd -T` exited unsuccessfully.
    #[error("sshd -T exited unsuccessfully (exit {exit:?})")]
    Failed {
        /// The exit code, when there is one.
        exit: Option<i32>,
    },
    /// The output exceeded [`MAX_OUTPUT_BYTES`] or was not UTF-8.
    #[error("sshd's output was too large or not text")]
    Output,
    /// The scratch directory could not be removed.
    #[error("the scratch directory could not be removed")]
    Cleanup,
    /// This platform has no unprivileged effective-policy check.
    #[error("the effective-policy check is not available on this platform")]
    Unsupported,
}

/// The scratch directory; removed on drop as a backstop for [`ScratchDir::destroy`].
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn create(parent: &Path) -> Result<Self, RunError> {
        let mut rnd = [0u8; 16];
        getrandom::fill(&mut rnd).map_err(|_| RunError::KeyGeneration)?;
        let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let path = parent.join(format!("hm-sshd-policy-{hex}"));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut b = std::fs::DirBuilder::new();
            b.mode(0o700);
            b
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        // `create` (not `create_all`) fails if the name exists: the directory is fresh.
        builder.create(&path).map_err(|_| RunError::Scratch)?;
        Ok(Self { path })
    }

    fn destroy(mut self) -> Result<(), RunError> {
        let path = std::mem::take(&mut self.path);
        let removed = std::fs::remove_dir_all(&path);
        if removed.is_ok() || !path.exists() {
            Ok(())
        } else {
            Err(RunError::Cleanup)
        }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Generate the scratch Ed25519 host key (OpenSSH private-key text, zeroized on drop).
fn scratch_host_key() -> Result<Zeroizing<String>, RunError> {
    use ssh_key::private::{Ed25519Keypair, KeypairData};
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| RunError::KeyGeneration)?;
    let pair = Ed25519Keypair::from_seed(&seed);
    let key = ssh_key::PrivateKey::new(KeypairData::Ed25519(pair), "hm-sshd-policy")
        .map_err(|_| RunError::KeyGeneration)?;
    key.to_openssh(ssh_key::LineEnding::LF)
        .map_err(|_| RunError::KeyGeneration)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), RunError> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|_| RunError::Scratch)?;
    f.write_all(bytes).map_err(|_| RunError::Scratch)?;
    f.sync_all().map_err(|_| RunError::Scratch)
}

/// Read at most `cap` bytes, draining (and discarding) the rest so the child never blocks
/// on a full pipe. Returns the bytes and whether more were discarded.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    reader: Option<R>,
    cap: usize,
) -> (Vec<u8>, bool) {
    let Some(mut r) = reader else {
        return (Vec::new(), false);
    };
    let mut out = Vec::new();
    let mut over = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
                over |= n > room;
            }
        }
    }
    (out, over)
}

/// The result of one bounded sshd run.
struct RunOutput {
    exit: Option<i32>,
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    over: bool,
}

async fn run_sshd(
    sshd: &Path,
    args: &[&std::ffi::OsStr],
    timeout: Duration,
) -> Result<RunOutput, RunError> {
    let mut cmd = tokio::process::Command::new(sshd);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut cmd = heimdall_app::no_window!(cmd);
    let run = async move {
        let mut child = cmd.spawn().map_err(|_| RunError::Spawn)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (out, err, status) = tokio::join!(
            read_capped(stdout, MAX_OUTPUT_BYTES),
            read_capped(stderr, MAX_OUTPUT_BYTES),
            child.wait()
        );
        let status = status.map_err(|_| RunError::Spawn)?;
        Ok(RunOutput {
            exit: status.code(),
            success: status.success(),
            stdout: out.0,
            stderr: err.0,
            over: out.1 || err.1,
        })
    };
    // On timeout the future (and with it the child, `kill_on_drop`) is dropped.
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| RunError::Timeout)?
}

/// Run the check (module docs): create the owner-only scratch directory and key, run
/// `sshd -T -h <key> -C <context> [-f <config>]` and `sshd -V`, destroy the scratch
/// directory, then [`verify`] the output. The scratch directory is removed whatever the
/// outcome.
///
/// # Errors
///
/// [`RunError`]: the management policy is then `owner_only` ([`management_policy_of`]).
pub async fn check_effective_policy(check: &SshdCheck<'_>) -> Result<PolicyVerdict, RunError> {
    if !cfg!(unix) {
        return Err(RunError::Unsupported);
    }
    if !check.sshd.is_absolute() {
        return Err(RunError::SshdPath);
    }
    let scratch = ScratchDir::create(check.scratch_parent)?;
    let key_path = scratch.path.join("host_key");
    let outcome = async {
        let pem = scratch_host_key()?;
        write_owner_only(&key_path, pem.as_bytes())?;
        drop(pem);
        let spec = check.context.spec();
        let mut args: Vec<&std::ffi::OsStr> = vec!["-T".as_ref()];
        if let Some(f) = check.config {
            args.push("-f".as_ref());
            args.push(f.as_os_str());
        }
        args.extend([
            "-h".as_ref(),
            key_path.as_os_str(),
            "-C".as_ref(),
            spec.as_ref(),
        ]);
        let effective = run_sshd(check.sshd, &args, check.timeout).await?;
        if !effective.success {
            return Err(RunError::Failed {
                exit: effective.exit,
            });
        }
        if effective.over {
            return Err(RunError::Output);
        }
        let banner = run_sshd(check.sshd, &["-V".as_ref()], check.timeout).await?;
        let mut banner_text = String::from_utf8_lossy(&banner.stdout).into_owned();
        banner_text.push('\n');
        banner_text.push_str(&String::from_utf8_lossy(&banner.stderr));
        let text = String::from_utf8(effective.stdout).map_err(|_| RunError::Output)?;
        Ok((text, banner_text))
    }
    .await;
    // Destroyed before the result is looked at: pass or fail.
    let cleaned = scratch.destroy();
    let (text, banner) = outcome?;
    cleaned?;
    Ok(verify(
        &text,
        &banner,
        &Account {
            user: check.context.user(),
            home: check.home,
            login_shell: check.login_shell,
        },
    ))
}

/// The account's login shell from the system's account database (`getent passwd`, Linux
/// runners). `None` where it cannot be read, which the verifier refuses.
pub async fn login_shell(user: &str, timeout: Duration) -> Option<String> {
    if !cfg!(target_os = "linux") || !user_ok(user) {
        return None;
    }
    let mut cmd = tokio::process::Command::new("/usr/bin/getent");
    cmd.arg("passwd")
        .arg(user)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut cmd = heimdall_app::no_window!(cmd);
    let run = async move {
        let mut child = cmd.spawn().ok()?;
        let (out, status) = tokio::join!(read_capped(child.stdout.take(), 4096), child.wait());
        if !status.ok()?.success() || out.1 {
            return None;
        }
        let text = String::from_utf8(out.0).ok()?;
        let line = text.lines().next()?;
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() == 7 && fields[0] == user).then(|| fields[6].to_owned())
    };
    tokio::time::timeout(timeout, run).await.ok().flatten()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The devbox readout's shape (`tests/evidence/artifacts/g07/sshd-T-readout.txt`, Ubuntu
    /// 24.04 / OpenSSH 9.6p1), its 14 recorded lines verbatim.
    pub(crate) const DEVBOX: &str = "usepam yes
permittty yes
allowtcpforwarding yes
allowagentforwarding yes
disableforwarding no
allowstreamlocalforwarding yes
forcecommand none
authorizedkeyscommand none
authorizedprincipalscommand none
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
acceptenv LANG
acceptenv LC_*
authenticationmethods any
permituserenvironment no
";
    pub(crate) const BANNER: &str = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024";

    fn account() -> Account<'static> {
        Account {
            user: "runner",
            home: "/home/runner",
            login_shell: Some("/bin/bash"),
        }
    }

    #[test]
    fn devbox_shaped_output_is_verified_with_both_files() {
        let PolicyVerdict::Verified(v) = verify(DEVBOX, BANNER, &account()) else {
            panic!("the devbox shape verifies");
        };
        assert_eq!(v.version, OpensshVersion { major: 9, minor: 6 });
        assert_eq!(
            v.authorized_keys_files,
            vec![
                "/home/runner/.ssh/authorized_keys".to_owned(),
                "/home/runner/.ssh/authorized_keys2".to_owned()
            ]
        );
        assert_eq!(
            verify(DEVBOX, BANNER, &account()).management_policy(),
            ManagementPolicy::Verified
        );
    }

    fn with(line_from: &str, line_to: &str) -> String {
        assert!(DEVBOX.contains(line_from), "{line_from}");
        DEVBOX.replace(line_from, line_to)
    }

    fn refused(text: &str, banner: &str, acct: &Account<'_>) -> PolicyField {
        match verify(text, banner, acct) {
            PolicyVerdict::Refused(r) => {
                assert_eq!(
                    verify(text, banner, acct).management_policy(),
                    ManagementPolicy::OwnerOnly
                );
                r.field
            }
            PolicyVerdict::Verified(_) => panic!("refusal expected"),
        }
    }

    /// Each failing field is refused by name.
    #[test]
    fn each_failing_field_is_refused_by_name() {
        let a = account();
        let cases: Vec<(String, PolicyField)> = vec![
            (
                with(
                    "authorizedkeyscommand none",
                    "authorizedkeyscommand /usr/bin/lookup %u",
                ),
                PolicyField::AuthorizedKeysCommand,
            ),
            (
                with(
                    "authorizedprincipalscommand none",
                    "authorizedprincipalscommand /usr/bin/p",
                ),
                PolicyField::AuthorizedPrincipalsCommand,
            ),
            (
                with("forcecommand none", "forcecommand /usr/bin/menu"),
                PolicyField::ForceCommand,
            ),
            (
                with("permituserenvironment no", "permituserenvironment yes"),
                PolicyField::PermitUserEnvironment,
            ),
            (
                with("acceptenv LC_*", "acceptenv *"),
                PolicyField::AcceptEnv,
            ),
            (
                with("acceptenv LANG", "acceptenv LANG HEIMDALL_X"),
                PolicyField::AcceptEnv,
            ),
            (
                with(
                    "authenticationmethods any",
                    "authenticationmethods publickey,password",
                ),
                PolicyField::AuthenticationMethods,
            ),
            (
                with(
                    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                    "authorizedkeysfile /etc/ssh/keys/%u .ssh/authorized_keys2",
                ),
                PolicyField::AuthorizedKeysFile,
            ),
            (
                with(
                    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                    "authorizedkeysfile .ssh/authorized_keys %i",
                ),
                PolicyField::AuthorizedKeysFile,
            ),
            (
                with(
                    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                    "authorizedkeysfile none",
                ),
                PolicyField::AuthorizedKeysFile,
            ),
            (
                with(
                    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                    "authorizedkeysfile .ssh/authorized_keys ../shared/keys",
                ),
                PolicyField::AuthorizedKeysFile,
            ),
            (with("forcecommand none\n", ""), PolicyField::ForceCommand),
            (
                format!("{DEVBOX}forcecommand none\n"),
                PolicyField::ForceCommand,
            ),
            (
                format!("{DEVBOX}pubkeyauthentication no\n"),
                PolicyField::PubkeyAuthentication,
            ),
            (format!("{DEVBOX}bad-keyword x\n"), PolicyField::Output),
            (format!("{DEVBOX}x\u{1b}[2J\n"), PolicyField::Output),
        ];
        for (text, field) in cases {
            assert_eq!(refused(&text, BANNER, &a), field, "{text}");
        }
        assert_eq!(
            refused(DEVBOX, "OpenSSH_8.6p1, OpenSSL", &a),
            PolicyField::Version
        );
        assert_eq!(refused(DEVBOX, "usage: sshd", &a), PolicyField::Version);
        for shell in [
            None,
            Some("/usr/bin/fish"),
            Some("bash"),
            Some("/sbin/nologin"),
        ] {
            let acct = Account {
                login_shell: shell,
                ..account()
            };
            assert_eq!(
                refused(DEVBOX, BANNER, &acct),
                PolicyField::LoginShell,
                "{shell:?}"
            );
        }
        let acct = Account {
            home: "relative",
            ..account()
        };
        assert_eq!(refused(DEVBOX, BANNER, &acct), PolicyField::Account);
    }

    #[test]
    fn accepted_variants() {
        let a = account();
        for (from, to) in [
            (
                "authenticationmethods any",
                "authenticationmethods publickey,password publickey",
            ),
            ("acceptenv LC_*", "acceptenv LC_ALL LC_CTYPE"),
            (
                "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",
                "authorizedkeysfile %h/.ssh/authorized_keys /home/%u/.ssh/extra_keys",
            ),
        ] {
            assert!(
                matches!(
                    verify(&with(from, to), BANNER, &a),
                    PolicyVerdict::Verified(_)
                ),
                "{to}"
            );
        }
        // OpenSSH 10.x prints the keywords in their configuration spelling (observed on
        // macOS 10.5p1): the same policy verifies.
        let camel = DEVBOX
            .replace("forcecommand", "ForceCommand")
            .replace("authorizedkeyscommand", "AuthorizedKeysCommand")
            .replace("authorizedprincipalscommand", "AuthorizedPrincipalsCommand")
            .replace("authorizedkeysfile", "AuthorizedKeysFile")
            .replace("acceptenv", "AcceptEnv")
            .replace("authenticationmethods", "AuthenticationMethods")
            .replace("permituserenvironment", "PermitUserEnvironment");
        assert!(matches!(
            verify(&camel, "OpenSSH_10.5p1, LibreSSL 3.3.6", &a),
            PolicyVerdict::Verified(_)
        ));
        assert_eq!(
            OpensshVersion::parse_banner("unknown option -- V\nOpenSSH_10.0p2 Debian"),
            Some(OpensshVersion {
                major: 10,
                minor: 0
            })
        );
    }

    #[test]
    fn limited_roles_need_verification_and_probes_confirm() {
        assert_eq!(
            limited_role_gate(Role::Requester, ManagementPolicy::OwnerOnly),
            Err(Refusal::ManagementSshdUnverified)
        );
        assert_eq!(
            limited_role_gate(Role::Viewer, ManagementPolicy::OwnerOnly),
            Err(Refusal::ManagementSshdUnverified)
        );
        assert!(limited_role_gate(Role::Owner, ManagementPolicy::OwnerOnly).is_ok());
        assert!(limited_role_gate(Role::Viewer, ManagementPolicy::Verified).is_ok());
        assert_eq!(
            management_policy_of(&Err(RunError::Timeout)),
            ManagementPolicy::OwnerOnly
        );

        let c = ClientId::from_random_bytes([3; 16]);
        let good = ProbeReport {
            echoed_client: Some(c.clone()),
            echoed_nonce: Some("ab".into()),
            pty_refused: true,
            forward_refused: true,
            agent_forward_refused: true,
            setenv_canary_delivered: false,
        };
        assert!(confirm_probe(&c, "ab", &good).is_ok());
        for bad in [
            ProbeReport {
                setenv_canary_delivered: true,
                ..good.clone()
            },
            ProbeReport {
                agent_forward_refused: false,
                ..good.clone()
            },
            ProbeReport {
                echoed_nonce: Some("cd".into()),
                ..good.clone()
            },
            ProbeReport {
                echoed_client: Some(ClientId::from_random_bytes([4; 16])),
                ..good.clone()
            },
        ] {
            assert_eq!(
                confirm_probe(&c, "ab", &bad),
                Err(Refusal::ManagementSshdUnsupported)
            );
        }
    }

    /// The real `sshd -T` (skipped where `/usr/sbin/sshd` is absent): against scratch
    /// configurations only (`-f`), so neither `~/.ssh` nor the system configuration is
    /// read; `-T` never listens. A clean configuration verifies (on an sshd new enough), a
    /// client-settable environment and an account `ForceCommand` in a `Match User` block are
    /// refused by name, and the scratch host key directory is gone after every run.
    #[tokio::test]
    #[allow(clippy::print_stderr)] // the skip reason is printed, as the plan requires
    async fn real_sshd_t_with_scratch_configurations() {
        let sshd = Path::new(DEFAULT_SSHD);
        if !sshd.exists() {
            eprintln!("skipped: {DEFAULT_SSHD} is absent on this host");
            return;
        }
        let scratch = tempfile::tempdir().unwrap();
        let parent = scratch.path().join("runs");
        std::fs::create_dir(&parent).unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let ctx = MatchContext::new("hmfixture", "localhost", lo, lo, 22).unwrap();
        let base = "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n\
                    AuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n\
                    PermitUserEnvironment no\nAcceptEnv LANG LC_*\n\
                    AuthenticationMethods any\nPubkeyAuthentication yes\n";
        let cases = [
            ("clean", base.to_owned(), None),
            (
                "acceptenv",
                base.replace("AcceptEnv LANG LC_*", "AcceptEnv *"),
                Some(PolicyField::AcceptEnv),
            ),
            (
                "forcecommand",
                format!("{base}Match User hmfixture\n    ForceCommand /usr/bin/false\n"),
                Some(PolicyField::ForceCommand),
            ),
        ];
        for (name, text, want) in cases {
            let config = scratch.path().join(format!("{name}.conf"));
            std::fs::write(&config, text).unwrap();
            let check = SshdCheck {
                sshd,
                config: Some(&config),
                scratch_parent: &parent,
                context: &ctx,
                home: "/home/hmfixture",
                login_shell: Some("/bin/sh"),
                timeout: DEFAULT_TIMEOUT,
            };
            let result = check_effective_policy(&check).await;
            assert_eq!(
                std::fs::read_dir(&parent).unwrap().count(),
                0,
                "{name}: the scratch host key directory was destroyed"
            );
            let verdict = match result {
                Ok(v) => v,
                Err(e) => panic!("{name}: the run did not complete: {e}"),
            };
            match (want, &verdict) {
                (None, PolicyVerdict::Verified(v)) => {
                    assert_eq!(v.authorized_keys_files.len(), 2, "{name}");
                }
                (None, PolicyVerdict::Refused(r)) if r.field == PolicyField::Version => {
                    eprintln!("{name}: this sshd predates {MIN_VERSION:?}; refused by version");
                }
                (Some(f), PolicyVerdict::Refused(r)) => assert_eq!(r.field, f, "{name}"),
                _ => panic!("{name}: unexpected verdict {verdict:?}"),
            }
        }
    }

    #[test]
    fn match_context_values_cannot_add_criteria() {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(MatchContext::new("runner,user=root", "h", lo, lo, 22).is_err());
        assert!(MatchContext::new("runner", "h,addr=1.2.3.4", lo, lo, 22).is_err());
        assert!(MatchContext::new("-oX", "h", lo, lo, 22).is_err());
        let ctx = MatchContext::new("runner", "localhost", lo, lo, 22).unwrap();
        assert_eq!(
            ctx.spec(),
            "user=runner,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22"
        );
    }
}
