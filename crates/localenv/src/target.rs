//! ⟨M03⟩ The passive target evaluation of a managed alias (m03-plan U5
//! `localenv::target::LocalTargetEvaluator`; ADR-0008 D5 §6.1, §6.3, §17.1 items 2 and
//! 12, §17.6 item 3 (Q24); §0.4 M10, M11, M17, M19).
//!
//! [`LocalTargetEvaluator`] implements `app::ports::TargetEvaluator`: the source of the
//! **approved target** at preview, and of the re-evaluation before every remote step.
//! It reads the configuration through M02's static evaluator (`heimdall-sshconf`, which
//! executes nothing) and the known-hosts files through M02's reader with the raw-key
//! addition ([`crate::known_hosts::lookup_raw_in`]). It **contacts nothing**: no agent,
//! no network, no configuration command. The only process it may start is the M02
//! local query `ssh-keygen -F <name> -f <file>` for hashed known-hosts entries, and
//! only when built with [`LocalTargetEvaluator::with_keygen`].
//!
//! **What it determines** for the alias, under the invocation every remote step makes
//! (`ssh … -T <alias> "printf 'HM1 ready\n'; exec /bin/sh -s"`):
//! * `HostName` (`%h` and `%%` expanded; the alias when unset), `Port` (22 when unset)
//!   and `User` (the local account when unset);
//! * the proxy: `ProxyJump`/`ProxyCommand` (one first-wins slot), `none` being direct;
//! * the host keys for (`HostName`, `Port`) in the user's and the system's default
//!   known-hosts files, hashed entries included, each with its raw blob.
//!
//! **Undetermined** (`Determinism::Undetermined { reason }`, a stable reason) when any of
//! those depends on something not evaluated statically (`Match exec`, an environment
//! reference, an unreadable include, a token), when canonicalization is not `no`, when
//! ssh would refuse the configuration (`config_invalid`), when the local account is not
//! known (`local_account_unknown`), or when the known-hosts lookup could not be
//! completed (`known_hosts_incomplete`: a hashed entry left unchecked, an unreadable
//! file, or a matching line that is not a usable host key). The reasons are the
//! constants of [`undetermined_reason`]. The plan (`heimdall_registry::plan::build`)
//! decides which refusal each becomes.
//!
//! **The existing-access endpoint** ([`LocalTargetEvaluator::evaluate_identity_agent`],
//! Q24 as ruled in §17.6 item 3): the alias's own `IdentityAgent`, statically evaluated,
//! with P's managed block excluded when asked. `none` or unset is
//! [`IdentityAgentEvaluation::Unset`]; `SSH_AUTH_SOCK` in any spelling, an environment
//! reference, a token other than `~`, `%d`, `%u` and `%%`, or anything that is not an
//! endpoint on this platform is [`IdentityAgentEvaluation::Undetermined`]. It is
//! **never** taken from `SSH_AUTH_SOCK` (§17.4 item 4; M-F29).
//! [`LocalTargetEvaluator::check_endpoint`] is the passive re-validation of an endpoint
//! before a step (present, owned by this user, and its resolved path), which the caller
//! compares with the approved one and with Heimdall's endpoints.

use std::path::{Path, PathBuf};

use heimdall_app::ports::TargetEvaluator;
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_domain::enrollment::{Determinism, ProxyRoute, RawHostKey, TargetEvaluation};
use heimdall_sshconf::directive::KnownKeyword;
use heimdall_sshconf::eval::{Evaluation, Invocation, OpenSshVersion, Query, Resolved, evaluate};
use heimdall_sshconf::include::{self, ConfigSet, ConfigSource, Roots, SourceBytes, SourceError};
use heimdall_sshconf::limits::Limits;

use crate::agents::{EndpointLocator, Presence, locator_for, roots_for};
use crate::env::{Env, Platform};
use crate::fs::BoundedSource;
use crate::known_hosts::{RawHostKeyObservation, lookup_raw_in};
use crate::local_query::LocalQueries;
use crate::paths::SshPaths;

/// The fixed remote command of every remote step (ADR-0008 D5 §6.3), which is the
/// invocation the alias is evaluated under (`Match command`).
pub const STEP_REMOTE_COMMAND: &str = "printf 'HM1 ready\\n'; exec /bin/sh -s";

/// The stable reasons of `Determinism::Undetermined` this evaluator reports.
pub mod undetermined_reason {
    /// The alias is not a host token (empty, a leading `-`, whitespace or a control
    /// character).
    pub const ALIAS_INVALID: &str = "alias_invalid";
    /// `HostName` depends on something not evaluated statically.
    pub const HOSTNAME: &str = "hostname_undetermined";
    /// `HostName` holds a token other than `%h` and `%%`, or is empty.
    pub const HOSTNAME_INVALID: &str = "hostname_invalid";
    /// `Port` depends on something not evaluated statically.
    pub const PORT: &str = "port_undetermined";
    /// `Port` is not a port number.
    pub const PORT_INVALID: &str = "port_invalid";
    /// `User` depends on something not evaluated statically, or holds a token or an
    /// environment reference.
    pub const USER: &str = "user_undetermined";
    /// `User` is unset and the local account cannot be established.
    pub const LOCAL_ACCOUNT_UNKNOWN: &str = "local_account_unknown";
    /// `ProxyJump` or `ProxyCommand` depends on something not evaluated statically.
    pub const PROXY: &str = "proxy_undetermined";
    /// `CanonicalizeHostname` is not `no` (or is undetermined): the name ssh connects
    /// to needs DNS (M04).
    pub const CANONICALIZATION: &str = "canonicalization";
    /// ssh would refuse the configuration (an invalid line): the step cannot run as
    /// evaluated.
    pub const CONFIG_INVALID: &str = "config_invalid";
    /// The known-hosts lookup could not be completed, so the key set is not known.
    pub const KNOWN_HOSTS_INCOMPLETE: &str = "known_hosts_incomplete";
    /// Every reason, in documentation order.
    pub const ALL: &[&str] = &[
        ALIAS_INVALID,
        HOSTNAME,
        HOSTNAME_INVALID,
        PORT,
        PORT_INVALID,
        USER,
        LOCAL_ACCOUNT_UNKNOWN,
        PROXY,
        CANONICALIZATION,
        CONFIG_INVALID,
        KNOWN_HOSTS_INCOMPLETE,
    ];
}

/// The stable reasons of [`IdentityAgentEvaluation::Undetermined`].
pub mod identity_agent_reason {
    /// The alias is not a host token.
    pub const ALIAS_INVALID: &str = "alias_invalid";
    /// The value depends on something not evaluated statically (`Match exec`, an
    /// unreadable include, an undetermined condition).
    pub const UNDETERMINED: &str = "identity_agent_undetermined";
    /// `SSH_AUTH_SOCK` in any spelling: the environment's agent, never concrete
    /// (ADR-0008 §17.4 item 4).
    pub const SSH_AUTH_SOCK: &str = "ssh_auth_sock";
    /// An environment reference (`$NAME`, `${NAME}`).
    pub const ENVIRONMENT_REFERENCE: &str = "environment_reference";
    /// A `%` token whose value is not known statically.
    pub const TOKEN: &str = "token_unavailable";
    /// The value names no endpoint on this platform (a relative path, not a pipe,
    /// another account's `~user`).
    pub const NOT_AN_ENDPOINT: &str = "not_an_endpoint";
}

/// The alias's own `IdentityAgent` (Q24 default as ruled, ADR-0008 §17.6 item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAgentEvaluation {
    /// A concrete endpoint.
    Determined(EndpointRef),
    /// Unset, or `none`.
    Unset,
    /// Not concrete (a stable reason of [`identity_agent_reason`]).
    Undetermined {
        /// Why.
        reason: &'static str,
    },
}

/// The passive re-validation of an agent endpoint
/// ([`LocalTargetEvaluator::check_endpoint`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCheck {
    /// Present and owned by this user ([`Presence::Present`]), absent, owned by another
    /// user, or not checkable.
    pub presence: Presence,
    /// The endpoint's path with every symlink resolved (Unix sockets; `None` when it
    /// cannot be resolved, and for a Windows pipe, which has no links).
    pub resolved: Option<String>,
}

/// The production `TargetEvaluator` (module documentation).
#[derive(Debug, Clone)]
pub struct LocalTargetEvaluator {
    paths: SshPaths,
    env: Env,
    platform: Platform,
    limits: Limits,
    managed_file: Option<PathBuf>,
    client_version: Option<OpenSshVersion>,
    local_user: Option<String>,
    queries: LocalQueries,
    keygen: Option<PathBuf>,
}

impl LocalTargetEvaluator {
    /// An evaluator over `paths` with the environment snapshot `env` (never the live
    /// environment), for `platform`. The local account is read from the account
    /// database; hashed known-hosts entries are left unchecked (so a file holding one
    /// makes the lookup incomplete) until [`with_keygen`](Self::with_keygen).
    #[must_use]
    pub fn new(paths: SshPaths, env: Env, platform: Platform) -> Self {
        Self {
            paths,
            env,
            platform,
            limits: Limits::default(),
            managed_file: None,
            client_version: None,
            local_user: crate::doctor::local_account(),
            queries: LocalQueries::Disabled,
            keygen: None,
        }
    }

    /// P's path, so its values carry the managed role and
    /// [`evaluate_identity_agent`](Self::evaluate_identity_agent) can exclude it.
    #[must_use]
    pub fn with_managed_file(mut self, managed: impl Into<PathBuf>) -> Self {
        self.managed_file = Some(managed.into());
        self
    }

    /// The verified client's version (its version gates; strictest when unknown).
    #[must_use]
    pub fn with_client_version(mut self, version: OpenSshVersion) -> Self {
        self.client_version = Some(version);
        self
    }

    /// Match hashed known-hosts entries with `keygen` (the M02 local query).
    #[must_use]
    pub fn with_keygen(mut self, keygen: impl Into<PathBuf>) -> Self {
        self.queries = LocalQueries::Enabled;
        self.keygen = Some(keygen.into());
        self
    }

    /// Read bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The local account name used for an unset `User`, `%u` and `Match localuser`
    /// (`None`: not established, which fails those closed). For callers and tests that
    /// must not depend on the account database.
    #[must_use]
    pub fn with_local_user(mut self, user: Option<String>) -> Self {
        self.local_user = user;
        self
    }

    fn query(&self, alias: &str) -> Query {
        Query {
            host: alias.to_owned(),
            user: None,
            local_user: self.local_user.clone(),
            client_version: self.client_version.unwrap_or(OpenSshVersion::MINIMUM),
            invocation: Invocation::Exec(Some(STEP_REMOTE_COMMAND.to_owned())),
        }
    }

    fn roots(&self) -> Roots {
        let roots = roots_for(&self.paths, true);
        match &self.managed_file {
            Some(p) => roots.with_managed(p.clone()),
            None => roots,
        }
    }

    fn evaluation(&self, alias: &str, exclude_managed: bool) -> Evaluation {
        let inner = BoundedSource::new(self.paths.clone(), self.env.clone(), self.limits);
        let roots = self.roots();
        let query = self.query(alias);
        let mut set = ConfigSet::new();
        match (&self.managed_file, exclude_managed) {
            (Some(managed), true) => {
                let source = WithoutManaged {
                    inner: &inner,
                    managed,
                    managed_canonical: std::fs::canonicalize(managed).ok(),
                };
                evaluate(&mut set, &source, &roots, &query, &self.limits)
            }
            _ => evaluate(&mut set, &inner, &roots, &query, &self.limits),
        }
    }

    /// The evaluation of `alias` (module documentation). Contacts nothing.
    #[must_use]
    pub fn evaluate_alias(&self, alias: &str) -> TargetEvaluation {
        if !alias_is_host_token(alias) {
            return TargetEvaluation {
                hostname: String::new(),
                port: 22,
                user: String::new(),
                proxy: ProxyRoute::None,
                determinism: undetermined(undetermined_reason::ALIAS_INVALID),
                host_keys: Vec::new(),
            };
        }
        let evaluation = self.evaluation(alias, false);
        let mut reasons: Vec<&'static str> = Vec::new();
        let hostname = match evaluation.values.get(&KnownKeyword::Hostname) {
            None | Some(Resolved::Unset) => alias.to_owned(),
            Some(Resolved::Determined(v)) => {
                match v.args.first().and_then(|h| expand_h(h, alias)) {
                    Some(h) if !h.is_empty() && is_plain_token(&h) => h,
                    _ => {
                        reasons.push(undetermined_reason::HOSTNAME_INVALID);
                        alias.to_owned()
                    }
                }
            }
            Some(Resolved::Undetermined(_)) => {
                reasons.push(undetermined_reason::HOSTNAME);
                alias.to_owned()
            }
        };
        let port = match evaluation.values.get(&KnownKeyword::Port) {
            None | Some(Resolved::Unset) => 22,
            Some(Resolved::Determined(v)) => {
                match v.args.first().and_then(|p| p.parse::<u16>().ok()) {
                    Some(p) if p != 0 => p,
                    _ => {
                        reasons.push(undetermined_reason::PORT_INVALID);
                        22
                    }
                }
            }
            Some(Resolved::Undetermined(_)) => {
                reasons.push(undetermined_reason::PORT);
                22
            }
        };
        let user = match evaluation.values.get(&KnownKeyword::User) {
            None | Some(Resolved::Unset) => match &self.local_user {
                Some(u) => u.clone(),
                None => {
                    reasons.push(undetermined_reason::LOCAL_ACCOUNT_UNKNOWN);
                    String::new()
                }
            },
            Some(Resolved::Determined(v)) => match v.args.first() {
                Some(u) if !u.is_empty() && !u.contains(['%', '$']) && is_plain_token(u) => {
                    u.clone()
                }
                _ => {
                    reasons.push(undetermined_reason::USER);
                    String::new()
                }
            },
            Some(Resolved::Undetermined(_)) => {
                reasons.push(undetermined_reason::USER);
                String::new()
            }
        };
        let proxy = proxy_route(&evaluation, &mut reasons);
        match evaluation.values.get(&KnownKeyword::CanonicalizeHostname) {
            None | Some(Resolved::Unset) => {}
            Some(Resolved::Determined(v))
                if v.args.first().is_some_and(|a| {
                    a.eq_ignore_ascii_case("no") || a.eq_ignore_ascii_case("false")
                }) => {}
            Some(_) => reasons.push(undetermined_reason::CANONICALIZATION),
        }
        if !evaluation.invalid.is_empty() {
            reasons.push(undetermined_reason::CONFIG_INVALID);
        }
        let lookup = lookup_raw_in(
            &crate::known_hosts::default_files(&self.paths),
            &self.paths.account_home,
            &hostname,
            port,
            self.queries,
            self.keygen.as_deref(),
        );
        if !lookup.complete {
            reasons.push(undetermined_reason::KNOWN_HOSTS_INCOMPLETE);
        }
        let determinism = match reasons.first() {
            None => Determinism::Determined,
            Some(r) => undetermined(r),
        };
        TargetEvaluation {
            hostname,
            port,
            user,
            proxy,
            determinism,
            host_keys: lookup.keys.into_iter().map(raw_host_key).collect(),
        }
    }

    /// The alias's own `IdentityAgent`, statically evaluated, with P's managed block
    /// excluded when `exclude_managed_block` (and P's path is known). Never
    /// `SSH_AUTH_SOCK` (module documentation). Contacts nothing.
    #[must_use]
    pub fn evaluate_identity_agent(
        &self,
        alias: &str,
        exclude_managed_block: bool,
    ) -> IdentityAgentEvaluation {
        if !alias_is_host_token(alias) {
            return IdentityAgentEvaluation::Undetermined {
                reason: identity_agent_reason::ALIAS_INVALID,
            };
        }
        let evaluation = self.evaluation(alias, exclude_managed_block);
        let value = match evaluation.values.get(&KnownKeyword::IdentityAgent) {
            None | Some(Resolved::Unset) => return IdentityAgentEvaluation::Unset,
            Some(Resolved::Undetermined(_)) => {
                return IdentityAgentEvaluation::Undetermined {
                    reason: identity_agent_reason::UNDETERMINED,
                };
            }
            Some(Resolved::Determined(v)) => match v.args.first() {
                Some(a) => a.clone(),
                None => {
                    return IdentityAgentEvaluation::Undetermined {
                        reason: identity_agent_reason::UNDETERMINED,
                    };
                }
            },
        };
        self.identity_agent_value(&value)
    }

    fn identity_agent_value(&self, value: &str) -> IdentityAgentEvaluation {
        use identity_agent_reason as r;
        let undetermined = |reason| IdentityAgentEvaluation::Undetermined { reason };
        if value.eq_ignore_ascii_case("none") {
            return IdentityAgentEvaluation::Unset;
        }
        if matches!(
            value,
            "SSH_AUTH_SOCK" | "$SSH_AUTH_SOCK" | "${SSH_AUTH_SOCK}"
        ) {
            return undetermined(r::SSH_AUTH_SOCK);
        }
        if value.contains('$') {
            return undetermined(r::ENVIRONMENT_REFERENCE);
        }
        let source = BoundedSource::new(self.paths.clone(), self.env.clone(), self.limits);
        let local_user = self.local_user.clone();
        let tokens = move |c: char| match c {
            'u' => local_user.clone(),
            _ => None,
        };
        let Ok(expanded) = include::expand(value, KnownKeyword::IdentityAgent, &source, &tokens)
        else {
            return undetermined(r::TOKEN);
        };
        let expanded = match expanded.strip_prefix('~') {
            None => expanded,
            Some("") => source.account_home().to_string_lossy().into_owned(),
            Some(rest) => match rest.strip_prefix(['/', '\\']) {
                Some(rest) => source
                    .account_home()
                    .join(rest)
                    .to_string_lossy()
                    .into_owned(),
                // `~user` names another account's home.
                None => return undetermined(r::NOT_AN_ENDPOINT),
            },
        };
        match locator_for(&expanded, self.platform) {
            Some(EndpointLocator::UnixSocket(p)) => {
                IdentityAgentEvaluation::Determined(EndpointRef {
                    kind: EndpointKind::UnixSocket,
                    locator: p.to_string_lossy().into_owned(),
                })
            }
            Some(EndpointLocator::NamedPipe(n)) => {
                IdentityAgentEvaluation::Determined(EndpointRef {
                    kind: EndpointKind::NamedPipe,
                    locator: n,
                })
            }
            None => undetermined(r::NOT_AN_ENDPOINT),
        }
    }

    /// Re-validate `endpoint` passively before a step (ADR-0008 D5 §6.3 "It is
    /// re-validated before every step"): a Unix socket is `stat`ed (following links, as
    /// `connect` would) and its path resolved; a pipe is never opened, so its presence
    /// is [`Presence::Unknown`] here. Nothing is connected to.
    #[must_use]
    pub fn check_endpoint(&self, endpoint: &EndpointRef) -> EndpointCheck {
        match endpoint.kind {
            EndpointKind::UnixSocket if !self.platform.is_windows() => {
                let path = Path::new(&endpoint.locator);
                EndpointCheck {
                    presence: socket_presence(path),
                    resolved: std::fs::canonicalize(path)
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned()),
                }
            }
            _ => EndpointCheck {
                presence: Presence::Unknown,
                resolved: None,
            },
        }
    }
}

impl TargetEvaluator for LocalTargetEvaluator {
    fn evaluate(&self, alias: &str) -> TargetEvaluation {
        self.evaluate_alias(alias)
    }
}

fn undetermined(reason: &str) -> Determinism {
    Determinism::Undetermined {
        reason: reason.to_owned(),
    }
}

fn raw_host_key(k: RawHostKeyObservation) -> RawHostKey {
    RawHostKey {
        key_type: k.key_type,
        key_b64: k.key_b64,
        fingerprint: k.fingerprint,
        origin_display: k.origin_display,
        revoked: k.revoked,
    }
}

/// No whitespace and no control character.
fn is_plain_token(s: &str) -> bool {
    !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// A host token: non-empty, no leading `-`, no whitespace or control character.
fn alias_is_host_token(alias: &str) -> bool {
    !alias.is_empty() && !alias.starts_with('-') && is_plain_token(alias)
}

/// `HostName`'s `%h` and `%%` (the only tokens it accepts); `None` for any other.
fn expand_h(hostname: &str, alias: &str) -> Option<String> {
    let mut out = String::with_capacity(hostname.len());
    let mut chars = hostname.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('%') => out.push('%'),
                Some('h') => out.push_str(alias),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn proxy_route(evaluation: &Evaluation, reasons: &mut Vec<&'static str>) -> ProxyRoute {
    let mut route = ProxyRoute::None;
    for (keyword, kind) in [
        (KnownKeyword::ProxyJump, ProxyRoute::Jump),
        (KnownKeyword::ProxyCommand, ProxyRoute::Command),
    ] {
        match evaluation.values.get(&keyword) {
            None | Some(Resolved::Unset) => {}
            Some(Resolved::Determined(v)) => {
                let direct = v.args.len() == 1
                    && v.args
                        .first()
                        .is_some_and(|a| a.eq_ignore_ascii_case("none"));
                if !direct {
                    route = kind;
                }
            }
            Some(Resolved::Undetermined(_)) => {
                reasons.push(undetermined_reason::PROXY);
                route = kind;
            }
        }
    }
    route
}

#[cfg(unix)]
fn socket_presence(path: &Path) -> Presence {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Presence::Absent,
        Err(_) => Presence::Unknown,
        Ok(m) if !m.file_type().is_socket() => Presence::Unknown,
        Ok(m) if m.uid() != crate::sys::current_uid() => Presence::ForeignOwner,
        Ok(_) => Presence::Present,
    }
}

#[cfg(not(unix))]
fn socket_presence(_path: &Path) -> Presence {
    Presence::Unknown
}

/// A source that reads P (the managed include file) as empty: the evaluation with
/// "P's managed block excluded" (Q24). Every other read goes to `inner`.
struct WithoutManaged<'a> {
    inner: &'a BoundedSource,
    managed: &'a Path,
    managed_canonical: Option<PathBuf>,
}

impl WithoutManaged<'_> {
    fn is_managed(&self, path: &Path) -> Option<PathBuf> {
        if path == self.managed {
            return Some(
                self.managed_canonical
                    .clone()
                    .unwrap_or_else(|| self.managed.to_path_buf()),
            );
        }
        let canonical = std::fs::canonicalize(path).ok()?;
        (Some(&canonical) == self.managed_canonical.as_ref()).then_some(canonical)
    }
}

impl ConfigSource for WithoutManaged<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        match self.is_managed(path) {
            Some(canonical) => Ok(SourceBytes {
                canonical,
                bytes: Vec::new(),
            }),
            None => self.inner.read(path),
        }
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        self.inner.glob(pattern)
    }

    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }

    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }

    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }

    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }

    fn include_home(&self) -> Option<&Path> {
        self.inner.include_home()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::known_hosts::{base64_encode_padded, base64_encode_unpadded};

    /// A synthetic public key blob (not a real key) with `fill` as its key bytes.
    fn blob(fill: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&11u32.to_be_bytes());
        b.extend_from_slice(b"ssh-ed25519");
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(&[fill; 32]);
        b
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        etc: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("home");
            let etc = dir.path().join("etc");
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            std::fs::create_dir_all(&etc).unwrap();
            Fixture {
                _dir: dir,
                home,
                etc,
            }
        }

        fn config(&self, text: &str) {
            std::fs::write(self.home.join(".ssh").join("config"), text).unwrap();
        }

        fn known_hosts(&self, text: &str) {
            std::fs::write(self.home.join(".ssh").join("known_hosts"), text).unwrap();
        }

        fn evaluator(&self) -> LocalTargetEvaluator {
            LocalTargetEvaluator::new(
                SshPaths::with_test_override(self.home.clone(), self.etc.clone()),
                Env::from_vars([
                    ("SSH_AUTH_SOCK", "/tmp/hm-not-used.sock"),
                    ("HM_T_AGENT", "/tmp/hm-env.sock"),
                ]),
                Platform::current(),
            )
            .with_local_user(Some("localacct".into()))
        }
    }

    #[test]
    fn direct_alias_is_determined_with_its_raw_key() {
        let f = Fixture::new();
        f.config("Host lab\n  HostName %h.example.internal\n  Port 2222\n  User deploy\n");
        let key = base64_encode_unpadded(&blob(1));
        f.known_hosts(&format!(
            "[lab.example.internal]:2222 ssh-ed25519 {key}\nother ssh-ed25519 {key}\n"
        ));
        let t = f.evaluator().evaluate("lab");
        assert_eq!(t.determinism, Determinism::Determined);
        assert_eq!(t.hostname, "lab.example.internal");
        assert_eq!(t.port, 2222);
        assert_eq!(t.user, "deploy");
        assert_eq!(t.proxy, ProxyRoute::None);
        assert_eq!(t.host_keys.len(), 1);
        assert_eq!(t.host_keys[0].key_b64, base64_encode_padded(&blob(1)));
        assert_eq!(t.host_keys[0].key_type, "ssh-ed25519");
        assert!(!t.host_keys[0].revoked);
        assert!(t.host_keys[0].origin_display.ends_with("known_hosts:1"));
    }

    #[test]
    fn defaults_apply_when_unset() {
        let f = Fixture::new();
        f.config("");
        let t = f.evaluator().evaluate("bare");
        assert_eq!(t.determinism, Determinism::Determined);
        assert_eq!(
            (t.hostname.as_str(), t.port, t.user.as_str()),
            ("bare", 22, "localacct")
        );
        assert!(t.host_keys.is_empty());
        let t = f.evaluator().with_local_user(None).evaluate("bare");
        assert_eq!(
            t.determinism,
            undetermined(undetermined_reason::LOCAL_ACCOUNT_UNKNOWN)
        );
    }

    #[test]
    fn proxies_canonicalization_exec_and_tokens_are_reported() {
        let f = Fixture::new();
        f.config(
            "Host jump\n  ProxyJump bastion\n\
             Host cmd\n  ProxyCommand nc %h %p\n\
             Host direct\n  ProxyCommand none\n\
             Host canon\n  CanonicalizeHostname yes\n\
             Match host exec exec \"false\"\n  HostName other\n\
             Host envuser\n  User ${HM_T_USER}\n",
        );
        let e = f.evaluator();
        assert_eq!(e.evaluate("jump").proxy, ProxyRoute::Jump);
        assert_eq!(e.evaluate("jump").determinism, Determinism::Determined);
        assert_eq!(e.evaluate("cmd").proxy, ProxyRoute::Command);
        assert_eq!(e.evaluate("direct").proxy, ProxyRoute::None);
        // Canonicalization re-reads every `Host` line under an unknown name, so the
        // first reason may be another directive's.
        assert!(matches!(
            e.evaluate("canon").determinism,
            Determinism::Undetermined { .. }
        ));
        assert_eq!(
            e.evaluate("exec").determinism,
            undetermined(undetermined_reason::HOSTNAME)
        );
        assert!(matches!(
            e.evaluate("envuser").determinism,
            Determinism::Undetermined { .. }
        ));
        assert_eq!(
            e.evaluate("-oProxyCommand=x").determinism,
            undetermined(undetermined_reason::ALIAS_INVALID)
        );
        f.config("Host canon\n  CanonicalizeHostname yes\n");
        assert_eq!(
            e.evaluate("canon").determinism,
            undetermined(undetermined_reason::CANONICALIZATION)
        );
        // A line ssh would refuse makes every alias of the file undetermined (fail
        // closed: the step could not run as evaluated).
        f.config("Host tok\n  HostName %r.example\nHost other\n  Port 22\n");
        assert!(matches!(
            e.evaluate("tok").determinism,
            Determinism::Undetermined { .. }
        ));
        assert_eq!(
            e.evaluate("other").determinism,
            undetermined(undetermined_reason::CONFIG_INVALID)
        );
    }

    #[test]
    fn hashed_known_hosts_without_the_query_is_incomplete() {
        let f = Fixture::new();
        f.config("Host lab\n  HostName lab.example\n");
        let key = base64_encode_unpadded(&blob(2));
        f.known_hosts(&format!("|1|c2FsdA==|aGFzaA== ssh-ed25519 {key}\n"));
        let t = f.evaluator().evaluate("lab");
        assert_eq!(
            t.determinism,
            undetermined(undetermined_reason::KNOWN_HOSTS_INCOMPLETE)
        );
    }

    #[test]
    fn identity_agent_is_the_alias_own_and_never_ssh_auth_sock() {
        let f = Fixture::new();
        // The endpoint forms of this platform (native Windows run, wave-1 item B7): a
        // Unix socket path, or on Windows a named pipe (only pipes are endpoints there).
        let windows = cfg!(windows);
        let socket = |unix: &str, pipe: &str| -> (String, EndpointRef) {
            if windows {
                (
                    format!("//./pipe/{pipe}"),
                    EndpointRef {
                        kind: EndpointKind::NamedPipe,
                        locator: format!(r"\\.\pipe\{pipe}"),
                    },
                )
            } else {
                (
                    unix.to_owned(),
                    EndpointRef {
                        kind: EndpointKind::UnixSocket,
                        locator: unix.to_owned(),
                    },
                )
            }
        };
        let own_home = f.home.join("agent.sock").to_string_lossy().into_owned();
        let (managed_value, managed_ep) = socket("/tmp/hm-managed.sock", "hm-managed");
        let (own_value, own_ep) = if windows {
            socket("", "hm-own")
        } else {
            (
                "~/agent.sock".to_owned(),
                EndpointRef {
                    kind: EndpointKind::UnixSocket,
                    locator: own_home,
                },
            )
        };
        let (user_value, user_ep) = socket("/tmp/%u.sock", "%u");
        let user_ep = EndpointRef {
            locator: user_ep.locator.replace("%u", "localacct"),
            ..user_ep
        };
        let (host_value, _) = socket("/tmp/%h.sock", "%h");
        let managed = f.home.join("heimdall-p.conf");
        std::fs::write(
            &managed,
            format!("Host lab\n  IdentityAgent {managed_value}\n"),
        )
        .unwrap();
        f.config(&format!(
            "Include {}\n\
             Host lab\n  IdentityAgent {own_value}\n\
             Host env\n  IdentityAgent $HM_T_AGENT\n\
             Host sock\n  IdentityAgent SSH_AUTH_SOCK\n\
             Host none\n  IdentityAgent none\n\
             Host user\n  IdentityAgent {user_value}\n\
             Host host\n  IdentityAgent {host_value}\n\
             Host rel\n  IdentityAgent relative.sock\n",
            managed.display()
        ));
        let e = f.evaluator().with_managed_file(&managed);
        // P is first, so it wins unless excluded.
        assert_eq!(
            e.evaluate_identity_agent("lab", false),
            IdentityAgentEvaluation::Determined(managed_ep)
        );
        assert_eq!(
            e.evaluate_identity_agent("lab", true),
            IdentityAgentEvaluation::Determined(own_ep)
        );
        let u = |reason| IdentityAgentEvaluation::Undetermined { reason };
        assert!(matches!(
            e.evaluate_identity_agent("env", true),
            IdentityAgentEvaluation::Undetermined { .. }
        ));
        assert_eq!(
            e.evaluate_identity_agent("sock", true),
            u(identity_agent_reason::SSH_AUTH_SOCK)
        );
        assert_eq!(
            e.evaluate_identity_agent("none", true),
            IdentityAgentEvaluation::Unset
        );
        // Unset: the environment's SSH_AUTH_SOCK is never taken.
        assert_eq!(
            e.evaluate_identity_agent("unset", true),
            IdentityAgentEvaluation::Unset
        );
        assert_eq!(
            e.evaluate_identity_agent("user", true),
            IdentityAgentEvaluation::Determined(user_ep)
        );
        assert_eq!(
            e.evaluate_identity_agent("host", true),
            u(identity_agent_reason::TOKEN)
        );
        assert_eq!(
            e.evaluate_identity_agent("rel", true),
            u(identity_agent_reason::NOT_AN_ENDPOINT)
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_endpoint_resolves_links_and_connects_to_nothing() {
        use std::os::unix::net::UnixListener;
        let f = Fixture::new();
        let sock = f.home.join("a.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let link = f.home.join("link.sock");
        std::os::unix::fs::symlink(&sock, &link).unwrap();
        let e = f.evaluator();
        let check = e.check_endpoint(&EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: link.to_string_lossy().into_owned(),
        });
        assert_eq!(check.presence, Presence::Present);
        assert_eq!(
            check.resolved,
            Some(
                std::fs::canonicalize(&sock)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            )
        );
        assert!(listener.accept().is_err(), "nothing connected");
        let gone = e.check_endpoint(&EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: f.home.join("gone.sock").to_string_lossy().into_owned(),
        });
        assert_eq!(gone.presence, Presence::Absent);
        assert_eq!(gone.resolved, None);
    }
}
