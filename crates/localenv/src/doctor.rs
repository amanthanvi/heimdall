//! The doctor (m02-plan U3; ADR-0007 §6; spec §10.2).
//!
//! The default run is **passive**: the `static` level only, plus local queries unless
//! `--no-local-exec`. It runs no configuration command, contacts no agent, provider or
//! network, and changes nothing. Every other level is explicit and recorded in a
//! `ProbeRecord`. `evaluate`, `host_verification` and `authentication` run the real
//! configuration tree, so without `allow_config_commands` they are always declined
//! (`config_commands_not_authorized`) before anything runs, and a tree the static pass
//! could not fully read declines them even with it (`config_not_fully_readable`).
//!
//! **What the static level reads:** the user and system configuration trees (through
//! `fs::BoundedSource`), `known_hosts` files, `.pub` files and private-key presence by
//! `stat` (identity selection), agent sockets by `stat` and `\\.\pipe\` by listing, the
//! Git files of §5.6, and the catalog facts the caller read from the store read-only
//! ([`LocalContext::catalog`]). With local queries: `<ssh> -V`, `ssh-keygen -F` and the
//! `git config`/`git var` queries, each contained and bounded at 2 s.
//!
//! **Reporting rules:** paths are shown with `~` for the account home; command
//! directives (`ProxyCommand`, `LocalCommand`, `KnownHostsCommand`) are shown as
//! `<command>` with their file:line, never their text; a Git value never appears
//! (digest only). `--redact` replaces aliases with `alias-<n>` and host and user names
//! with `<redacted>`. The `executed_config_commands` of a probe record are the
//! constructs the static pass found **before** the run; they are never described as
//! complete, and [`INVENTORY_WORDING`] is the text every rendering uses.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{
    AliasDefinition, AliasObservation, ClientObservation, ClientSource as WireSource,
    ConfigFileObservation, ConfigFileRole, ConfigProvenance, Containment, DirectiveCertainty,
    DirectiveObservation, DoctorReport, Finding, FindingSeverity, GitObservation, GitScope,
    GitValueObservation, ProbeOutcome, ProbeRecord, ProjectionObservation, ProjectionState,
    finding,
};
use heimdall_contract::envelope::{NextAction, ResourceRef};
use heimdall_contract::provider::{
    EvidenceBasis, IdentityBacking, IdentitySelection, InteractionKind, ProbeLevel,
    ProviderAvailability, ProviderStatus,
};
use heimdall_contract::request::ConsumerKind;
use heimdall_contract::setup::ConflictKind;
use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::edit::{BlockPosition, find_blocks};
use heimdall_sshconf::eval::{
    Evaluation, Invocation, OpenSshVersion, Resolved, UnresolvedReason, Value, evaluate,
};
use heimdall_sshconf::include::{self, ConfigSet, Roots};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::Line;
use heimdall_sshconf::relevant::{
    Proxy, ProxyResolution, RelevantBehavior, executing_constructs, identity_selection_with_spans,
    relevant,
};

use crate::agents::{AgentEndpoint, EndpointLocator, EndpointSource, Presence, detect_agents};
use crate::clients::{ClientInventory, ClientKind, ClientSource, ClientsConfig, resolve_clients};
use crate::env::{Env, Platform};
use crate::fs::BoundedSource;
use crate::git::{
    DefaultGitSsh, MANAGED_GIT_FILE, managed_include_present, observe_global, observe_global_for,
    resolve_run_selection, winning_origin,
};
use crate::known_hosts::lookup_detailed;
use crate::local_query::{LocalQueries, version_text};
use crate::paths::SshPaths;
use crate::probe::{self, ProbeContext, ProbeHook, provenance};

/// The wording every rendering of `executed_config_commands` uses (ADR-0007 §6; the
/// list is never complete).
pub const INVENTORY_WORDING: &str =
    "configuration commands found before the run; the run may have executed others";

/// The lowest client version M02 supports (in-box Windows 9.5p2; ADR-0004 E6).
pub const CLIENT_FLOOR: OpenSshVersion = OpenSshVersion {
    major: 9,
    minor: 5,
    portable: None,
};

/// More identity entries than this may exhaust the server's `MaxAuthTries` (default 6)
/// before the adopted key is offered.
pub const MAX_IDENTITY_ENTRIES: usize = 5;

/// Most aliases one doctor run evaluates from the configuration.
pub const MAX_ALIASES: usize = 256;

/// What the doctor runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorRequest {
    /// Levels requested; `static` is always performed.
    pub levels: BTreeSet<ProbeLevel>,
    /// `--allow-config-commands`: the owner's authorization for the real-tree levels.
    pub allow_config_commands: bool,
    /// `--alias`, or every alias when `None`.
    pub aliases: Option<Vec<String>>,
    /// Whether prompts are allowed.
    pub interactive: bool,
    /// `--no-local-exec` turns local queries off.
    pub local_queries: LocalQueries,
    /// `--redact`: display paths and names are redacted in the report.
    pub redact: bool,
}

impl DoctorRequest {
    /// The default passive run: `static` only, local queries on, non-interactive.
    #[must_use]
    pub fn passive() -> Self {
        Self {
            levels: BTreeSet::from([ProbeLevel::Static]),
            allow_config_commands: false,
            aliases: None,
            interactive: false,
            local_queries: LocalQueries::Enabled,
            redact: false,
        }
    }
}

/// An identity of the catalog, as the caller read it from the store read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogIdentity {
    /// The adopted public key's path (identity selection's `adopted`).
    pub public_key_path: PathBuf,
    /// Its fingerprint (`SHA256:…`), when recorded.
    pub fingerprint: Option<String>,
    /// Its current interaction: `none` only while a live declaration covers it.
    pub interaction: InteractionKind,
    /// The provider endpoint it is used through, when recorded.
    pub endpoint: Option<EndpointLocator>,
}

/// An alias of the catalog (managed or observed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogAlias {
    /// The alias.
    pub alias: String,
    /// `managed` or `observed`.
    pub definition: AliasDefinition,
    /// Its identity, when one is adopted for it.
    pub identity: Option<CatalogIdentity>,
}

/// The local facts a doctor run reads.
#[derive(Clone)]
pub struct LocalContext {
    /// SSH configuration locations.
    pub paths: SshPaths,
    /// The environment snapshot.
    pub env: Env,
    /// The platform.
    pub platform: Platform,
    /// `config.toml` `[clients]`.
    pub clients: ClientsConfig,
    /// Read bounds.
    pub limits: Limits,
    /// Test-only probe hook (env-gated through the test configuration; `None` in
    /// production).
    pub probe_hook: Option<Arc<dyn ProbeHook>>,
    /// Test configuration only (ADR-0007 §9): the isolation arguments put on every
    /// client a probe runs (`-F <scratch config>`, the scratch known-hosts files,
    /// `BatchMode`). When set, the system file is not read, as `-F` drops it (F6).
    /// `None` in production, where ssh reads the real tree.
    pub client_isolation: Option<Vec<OsString>>,
    /// The catalog's aliases and identities, read by the caller from the store
    /// read-only; empty when the store could not be read.
    pub catalog: Vec<CatalogAlias>,
    /// The Heimdall-managed include file P, when known (its role is `managed`).
    pub managed_file: Option<PathBuf>,
}

impl std::fmt::Debug for LocalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalContext")
            .field("platform", &self.platform)
            .field("probe_hook", &self.probe_hook.is_some())
            .finish_non_exhaustive()
    }
}

impl LocalContext {
    /// A context with no hook, no test isolation, an empty catalog and no managed
    /// file.
    #[must_use]
    pub fn new(
        paths: SshPaths,
        env: Env,
        platform: Platform,
        clients: ClientsConfig,
        limits: Limits,
    ) -> Self {
        Self {
            paths,
            env,
            platform,
            clients,
            limits,
            probe_hook: None,
            client_isolation: None,
            catalog: Vec::new(),
            managed_file: None,
        }
    }

    /// The local account name for `%u` and `Match localuser` ([`local_account`]):
    /// `None` when the account cannot be established.
    #[must_use]
    pub fn local_user(&self) -> Option<String> {
        local_account()
    }

    /// The roots ssh reads: the user file, and the system file unless the test
    /// isolation passes `-F`; P's path, when known, gives its values the `managed`
    /// role (ADR-0007 §12.15 item 3a).
    #[must_use]
    pub fn roots(&self) -> Roots {
        let roots = crate::agents::roots_for(&self.paths, self.client_isolation.is_none());
        match &self.managed_file {
            Some(p) => roots.with_managed(p.clone()),
            None => roots,
        }
    }

    /// P_git, Heimdall's managed Git file: `gitconfig` beside P in Heimdall's
    /// configuration directory (ADR-0007 §5.6). `None` when P's path is not known.
    #[must_use]
    pub fn managed_git_file(&self) -> Option<PathBuf> {
        self.managed_file
            .as_deref()
            .and_then(Path::parent)
            .map(|dir| dir.join(MANAGED_GIT_FILE))
    }

    /// The catalog alias `alias`, if any.
    #[must_use]
    pub fn catalog_alias(&self, alias: &str) -> Option<&CatalogAlias> {
        self.catalog.iter().find(|c| c.alias == alias)
    }

    /// The catalog identity adopted for `alias`, if any.
    #[must_use]
    pub fn catalog_identity(&self, alias: &str) -> Option<&CatalogIdentity> {
        self.catalog_alias(alias).and_then(|c| c.identity.as_ref())
    }

    fn source(&self) -> BoundedSource {
        BoundedSource::new(self.paths.clone(), self.env.clone(), self.limits)
    }
}

/// ADR-0007 §12.25 item 2 (T02): the local account name for `%u` and `Match
/// localuser`, from the OS account database as OpenSSH computes it
/// (`sys::account_name`, `getpwuid_r(getuid())`), never from `USER`, `USERNAME` or
/// `LOGNAME`. `None` when the account cannot be established: a failed lookup, an empty
/// name, or an unsupported platform. Every query
/// builder (projection observe and preview, the pre-launch check, the probes and the
/// doctor) then evaluates with `Query::local_user` `None`, never an empty name: only
/// the conditions that read the account (`Match localuser`, `Match user` on the local
/// account, `%u`, `%r`) are undetermined (ADR-0007 §12.28 item 3).
#[must_use]
pub fn local_account() -> Option<String> {
    #[cfg(any(unix, windows))]
    {
        crate::sys::account_name().ok().filter(|n| !n.is_empty())
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Whether the configuration `evaluation` read can depend on the local account name
/// (ADR-0007 §12.25 item 2): a `Match` line with a `localuser` or `user` criterion
/// (`Match user` compares with the local account when no `User` is in force), or an
/// `Include` argument with a `%u` or `%r` token. Read over every file the evaluation
/// visited, whatever its sections' conditions, so a line in a section that does not
/// apply still counts (the conservative reading). It decides nothing (the evaluator
/// leaves only the affected conditions undetermined, §12.28 item 3); the doctor uses it
/// to say why a selection is undetermined.
#[must_use]
pub fn reads_local_account(set: &ConfigSet, evaluation: &Evaluation) -> bool {
    evaluation.files.keys().any(|id| {
        set.file(*id).is_some_and(|file| {
            file.lines.iter().any(|line| match line {
                Line::Directive(d) => match &d.keyword {
                    Keyword::Known(KnownKeyword::Match) => d.args.iter().any(|a| {
                        let a = a.trim_start_matches('!').to_ascii_lowercase();
                        let criterion = a.split('=').next().unwrap_or_default();
                        criterion == "localuser" || criterion == "user"
                    }),
                    Keyword::Known(KnownKeyword::Include) => {
                        d.args.iter().any(|a| a.contains("%u") || a.contains("%r"))
                    }
                    _ => false,
                },
                _ => false,
            })
        })
    })
}

/// ADR-0007 §12.26 item 7: `path` for display, `~/…` when it lies under the account
/// `home`. Both are canonicalized before the comparison, so a home reached through a
/// symlink (`/var` against `/private/var`, as on macOS) still shows as `~/…`; the
/// written forms are compared too. A path outside the home is shown as given. `/`
/// separators. The account home's absolute path, and so the account name it holds,
/// never appears for a path under it.
#[must_use]
pub fn path_display(path: &Path, home: &Path) -> String {
    let text = |p: &Path| p.to_string_lossy().replace('\\', "/");
    if home.as_os_str().is_empty() {
        return text(path);
    }
    let tilde = |rest: &Path| {
        if rest.as_os_str().is_empty() {
            "~".to_owned()
        } else {
            format!("~/{}", text(rest))
        }
    };
    let canonical_home = std::fs::canonicalize(home).ok();
    let canonical_path = std::fs::canonicalize(path).ok();
    let candidates = [
        (Some(path), Some(home)),
        (Some(path), canonical_home.as_deref()),
        (canonical_path.as_deref(), Some(home)),
        (canonical_path.as_deref(), canonical_home.as_deref()),
    ];
    for (p, h) in candidates {
        if let (Some(p), Some(h)) = (p, h)
            && let Ok(rest) = p.strip_prefix(h)
        {
            return tilde(rest);
        }
    }
    text(path)
}

/// ADR-0007 §12.30 item 10: `path` (a path as the configuration names it) for display:
/// `~/…` under the account home, the home's canonical form included; anything else as
/// given.
fn written_display(ctx: &LocalContext, path: &Path) -> String {
    let plain = ctx.paths.display(path);
    if plain.starts_with('~') {
        plain
    } else {
        path_display(path, &ctx.paths.account_home)
    }
}

/// ADR-0007 §12.30 item 10: `span` as file:line with its file as written
/// ([`ConfigSet::written_path_of`]), never in its canonical form; a root's span keeps
/// [`provenance`]'s root path.
fn written_provenance(
    ctx: &LocalContext,
    set: &ConfigSet,
    roots: &Roots,
    span: heimdall_sshconf::parse::Span,
) -> ConfigProvenance {
    match set.written_path_of(span.source) {
        Some(path) => ConfigProvenance {
            path_display: written_display(ctx, path),
            line: span.line,
        },
        None => provenance(ctx, set, roots, span),
    }
}

/// ADR-0007 §12.26 item 7: `provenance` shown through [`path_display`]. A display
/// that already starts at `~` is kept; any other is read as the path it shows (the
/// evaluator's display of a file it could not place under the home it was given) and
/// shown again, so a home behind a symlink is still `~/…`.
pub fn redisplay(provenance: &mut ConfigProvenance, home: &Path) {
    if !provenance.path_display.starts_with('~') {
        provenance.path_display = path_display(Path::new(&provenance.path_display), home);
    }
}

/// [`redisplay`] over every provenance of `observation` (its directives and its
/// identity selection's entries).
pub fn redisplay_observation(observation: &mut AliasObservation, home: &Path) {
    for d in &mut observation.behavior {
        for p in &mut d.provenance {
            redisplay(p, home);
        }
    }
    if let Some(report) = observation.identity_selection.as_mut() {
        for p in report
            .entries
            .iter_mut()
            .filter_map(|e| e.provenance.as_mut())
        {
            redisplay(p, home);
        }
    }
}

/// ADR-0007 §12.25 item 1 (T01): `alias`'s static observation under each invocation
/// profile a launch can use, `Shell`, `Exec(None)` and `Subsystem("sftp")` (the
/// consent profile set, `Invocation::consent_profiles`), each named by
/// `Invocation::profile_name`, in that order. The doctor's static level for the alias
/// alone: passive, no local query and no client version query (the floor version), no
/// finding kept. With the local account unknown (T02) a profile whose configuration
/// reads it is undetermined; every provenance is shown through [`path_display`].
#[must_use]
pub fn alias_profiles(ctx: &LocalContext, alias: &str) -> Vec<(String, AliasObservation)> {
    let mut request = DoctorRequest::passive();
    request.aliases = Some(vec![alias.to_owned()]);
    request.local_queries = LocalQueries::Disabled;
    let mut d = Doctor {
        ctx,
        request: &request,
        findings: Vec::new(),
        probes: Vec::new(),
    };
    Invocation::consent_profiles()
        .into_iter()
        .map(|invocation| {
            let name = invocation.profile_name();
            let (observation, _) = d.alias(alias, None, invocation);
            (name, observation)
        })
        .collect()
}

/// Run the doctor.
#[must_use]
pub fn run(ctx: &LocalContext, request: &DoctorRequest) -> DoctorReport {
    let started_at = Timestamp::now();
    let t0 = std::time::Instant::now();
    let mut d = Doctor {
        ctx,
        request,
        findings: Vec::new(),
        probes: Vec::new(),
    };
    let inventory = resolve_clients(&ctx.env, &ctx.paths, &ctx.clients, request.local_queries);
    let clients = d.clients(&inventory);
    let ssh_version = inventory.selected(ClientKind::Ssh).and_then(|c| c.version);
    let (config_files, config_aliases) = d.config_files();
    d.home_mismatch();
    let projection = d.projection();
    let agents = detect_agents(&ctx.env, &ctx.paths, ctx.platform);
    let providers = d.providers(&agents);
    let aliases_to_check = d.alias_list(&config_aliases);
    let mut aliases = Vec::new();
    let mut evaluations: BTreeMap<String, Evaluation> = BTreeMap::new();
    for alias in &aliases_to_check {
        let (obs, evaluation) = d.alias(alias, ssh_version, Invocation::Shell);
        aliases.push(obs);
        evaluations.insert(alias.clone(), evaluation);
    }
    let git = d.git(&inventory, &agents);
    // The static level's own record: nothing configured ran, nothing was contacted
    // or changed; local queries ran contained.
    let mut static_record = probe::record(ProbeLevel::Static, "*", started_at);
    static_record.duration_ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
    static_record.containment =
        if request.local_queries == LocalQueries::Enabled && !inventory.candidates.is_empty() {
            if cfg!(windows) {
                Containment::JobObject
            } else {
                Containment::ProcessGroup
            }
        } else {
            Containment::None
        };
    d.probes.push(static_record);
    d.explicit_levels(&aliases_to_check, &evaluations, &agents, &inventory);
    let mut levels_performed = BTreeSet::new();
    let mut levels_declined = BTreeSet::new();
    for r in &d.probes {
        if r.outcome == ProbeOutcome::Declined {
            levels_declined.insert(r.level);
        } else {
            levels_performed.insert(r.level);
        }
    }
    let mut report = DoctorReport {
        levels_performed,
        levels_declined,
        clients,
        config_files,
        aliases,
        providers,
        projection,
        git,
        findings: d.findings,
        probes: d.probes,
    };
    if request.redact {
        redact(&mut report);
    }
    report
}

struct Doctor<'a> {
    ctx: &'a LocalContext,
    request: &'a DoctorRequest,
    findings: Vec<Finding>,
    probes: Vec<ProbeRecord>,
}

fn subject(kind: &str, id: Option<&str>) -> ResourceRef {
    ResourceRef {
        kind: kind.to_owned(),
        id: id.map(str::to_owned),
    }
}

fn next(action: &str) -> NextAction {
    NextAction {
        action: action.to_owned(),
        ..NextAction::default()
    }
}

impl Doctor<'_> {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        code: &str,
        severity: FindingSeverity,
        subject: ResourceRef,
        level: ProbeLevel,
        provenance: Option<ConfigProvenance>,
        message: impl Into<String>,
        action: &str,
        reason: Option<&str>,
    ) {
        self.findings.push(Finding {
            code: code.to_owned(),
            severity,
            subject,
            level,
            provenance,
            message: message.into(),
            next: next(action),
            reason: reason.map(str::to_owned),
        });
    }

    fn clients(&mut self, inventory: &ClientInventory) -> Vec<ClientObservation> {
        let home = &self.ctx.paths.account_home;
        let out: Vec<ClientObservation> = inventory
            .candidates
            .iter()
            .map(|c| ClientObservation {
                consumer: match c.kind {
                    ClientKind::Ssh => ConsumerKind::Ssh,
                    ClientKind::Scp => ConsumerKind::Scp,
                    ClientKind::Sftp => ConsumerKind::Sftp,
                    ClientKind::Git => ConsumerKind::Git,
                    ClientKind::SshKeygen => ConsumerKind::SshKeygen,
                },
                path_display: crate::paths::display_path(home, &c.path),
                source: match c.source {
                    ClientSource::Path => WireSource::Path,
                    ClientSource::System32 => WireSource::System32,
                    ClientSource::GitBundled => WireSource::GitBundled,
                    ClientSource::Configured => WireSource::Configured,
                },
                version: c
                    .version
                    .as_ref()
                    .map(|v| format!("OpenSSH_{}", version_text(v))),
                sha256: c.sha256.clone(),
                selected: c.selected,
            })
            .collect();
        match inventory.selected(ClientKind::Ssh) {
            None => self.add(
                finding::CLIENT_NOT_FOUND,
                FindingSeverity::Problem,
                subject("executable", Some("ssh")),
                ProbeLevel::Static,
                None,
                "no ssh client was found on PATH or in config.toml [clients]",
                "change_client",
                None,
            ),
            Some(ssh) => {
                if let Some(v) = ssh.version
                    && v < CLIENT_FLOOR
                {
                    self.add(
                        finding::CLIENT_UNSUPPORTED_VERSION,
                        FindingSeverity::Problem,
                        subject("executable", Some("ssh")),
                        ProbeLevel::Static,
                        None,
                        format!(
                            "the selected ssh is OpenSSH {}, below the supported floor 9.5",
                            version_text(&v)
                        ),
                        "change_client",
                        None,
                    );
                }
            }
        }
        out
    }

    /// Read both trees once: the file inventory (role, readability, digest, size),
    /// the encoding, permission, missing-include and bound findings, and the literal
    /// `Host` aliases.
    fn config_files(&mut self) -> (Vec<ConfigFileObservation>, Vec<String>) {
        let ctx = self.ctx;
        let source = ctx.source();
        let digesting = probe::snapshot::Digesting::new(&source);
        let roots = ctx.roots();
        let mut set = ConfigSet::new();
        let record = include::record(&mut set, &digesting, &roots, &ctx.limits, &|_| None);
        let digests = digesting.into_digests();
        let managed = ctx
            .managed_file
            .as_ref()
            .and_then(|p| crate::fs::canonical_path(p).ok());
        let mut files: Vec<ConfigFileObservation> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut aliases: Vec<String> = Vec::new();
        for visit in &record.visits {
            if !seen.insert(visit.canonical.clone()) {
                continue;
            }
            let role = if managed.as_ref() == Some(&visit.canonical) {
                ConfigFileRole::Managed
            } else if visit.depth > 0 {
                ConfigFileRole::Included
            } else if visit.origin == include::Origin::System {
                ConfigFileRole::System
            } else {
                ConfigFileRole::User
            };
            // ADR-0007 §12.30 item 10: the path as the configuration names it (the
            // written path), never its canonical form.
            let display = written_display(
                ctx,
                set.written_path_of(visit.source)
                    .unwrap_or(visit.canonical.as_path()),
            );
            let (sha, bytes) = digests
                .get(&visit.canonical)
                .map_or((None, None), |(d, n)| (Some(d.clone()), Some(*n)));
            files.push(ConfigFileObservation {
                path_display: display.clone(),
                role,
                readable: true,
                sha256: sha,
                bytes,
            });
            if let Some(file) = set.file(visit.source) {
                if file.had_bom {
                    self.add(
                        finding::UNSUPPORTED_ENCODING,
                        FindingSeverity::Warning,
                        subject("config", Some(&display)),
                        ProbeLevel::Static,
                        Some(ConfigProvenance {
                            path_display: display.clone(),
                            line: 1,
                        }),
                        "the file starts with a UTF-8 byte-order mark, which OpenSSH reads as part of the first keyword",
                        "review_config",
                        Some("byte_order_mark"),
                    );
                }
                if role != ConfigFileRole::Managed {
                    for line in &file.lines {
                        if let Line::Directive(dir) = line
                            && matches!(dir.keyword, Keyword::Known(KnownKeyword::Host))
                        {
                            for pat in &dir.args {
                                if !pat.contains(['*', '?', '!', '%'])
                                    && probe::alias_is_usable(pat)
                                    && !aliases.contains(pat)
                                    && aliases.len() < MAX_ALIASES
                                {
                                    aliases.push(pat.clone());
                                }
                            }
                        }
                    }
                }
            }
            self.permissions(&visit.canonical, &display, visit.origin);
        }
        for failure in &record.failures {
            let display = written_display(ctx, &failure.path);
            if seen.insert(failure.path.clone()) {
                files.push(ConfigFileObservation {
                    path_display: display.clone(),
                    role: if failure.at.is_none() {
                        if failure.origin == include::Origin::System {
                            ConfigFileRole::System
                        } else {
                            ConfigFileRole::User
                        }
                    } else {
                        ConfigFileRole::Included
                    },
                    readable: false,
                    sha256: None,
                    bytes: None,
                });
            }
            let prov = failure
                .at
                .map(|span| written_provenance(ctx, &set, &roots, span));
            let (code, reason) = if failure.error.is_bound() {
                (finding::BOUND_EXCEEDED, None)
            } else {
                (finding::INCLUDE_MISSING, Some("unreadable"))
            };
            self.add(
                code,
                FindingSeverity::Problem,
                subject("config", Some(&display)),
                ProbeLevel::Static,
                prov,
                "a configuration file could not be read within the bounds; probes that run the real tree are declined",
                "review_config",
                reason,
            );
        }
        for inc in &record.includes {
            let literal = inc
                .arg
                .pattern
                .as_ref()
                .is_some_and(|p| !p.to_string_lossy().contains(['*', '?', '[']));
            let prov = written_provenance(ctx, &set, &roots, inc.span);
            match &inc.arg.matches {
                Ok(m) if m.is_empty() && literal => self.add(
                    finding::INCLUDE_MISSING,
                    FindingSeverity::Warning,
                    subject("config", Some(&prov.path_display)),
                    ProbeLevel::Static,
                    Some(prov),
                    "an Include names a file that does not exist; ssh skips it",
                    "review_config",
                    None,
                ),
                Err(e) => {
                    let bound = matches!(e, include::ArgError::Glob(g) if g.is_bound());
                    self.add(
                        if bound {
                            finding::BOUND_EXCEEDED
                        } else {
                            finding::INCLUDE_MISSING
                        },
                        FindingSeverity::Problem,
                        subject("config", Some(&prov.path_display)),
                        ProbeLevel::Static,
                        Some(prov),
                        "an Include path could not be expanded statically",
                        "review_config",
                        Some("unresolved"),
                    );
                }
                Ok(_) => {}
            }
        }
        (files, aliases)
    }

    #[cfg(unix)]
    fn permissions(&mut self, path: &Path, display: &str, origin: include::Origin) {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let foreign_owner = meta.uid() != crate::sys::current_uid() && meta.uid() != 0;
        if origin == include::Origin::User && (meta.mode() & 0o022 != 0 || foreign_owner) {
            self.add(
                finding::CONFIG_PERMISSIONS_UNSAFE,
                FindingSeverity::Problem,
                subject("config", Some(display)),
                ProbeLevel::Static,
                None,
                "the file is writable by another user or not owned by you; ssh refuses such a user configuration",
                "review_config",
                None,
            );
        }
    }

    #[cfg(not(unix))]
    fn permissions(&mut self, _path: &Path, _display: &str, _origin: include::Origin) {}

    /// ADR-0007 §12.17 item 9: reported exactly when an `Include`'s `~` (and a relative
    /// user `Include`) would follow a `HOME` other than the account home, which makes
    /// those includes undetermined (`crate::fs::include_home_for`).
    fn home_mismatch(&mut self) {
        if crate::fs::include_home_for(&self.ctx.env, &self.ctx.paths.account_home).is_none() {
            self.add(
                finding::HOME_MISMATCH,
                FindingSeverity::Warning,
                subject("environment", Some("HOME")),
                ProbeLevel::Static,
                None,
                "HOME differs from the account's home: ssh reads ~/.ssh/config and expands %d from the account's home, but an Include's ~ and a relative Include follow HOME, so those includes are undetermined",
                "review_config",
                None,
            );
        }
    }

    fn projection(&mut self) -> Option<ProjectionObservation> {
        let ctx = self.ctx;
        let bytes = crate::fs::read_bounded(&ctx.paths.user_config, ctx.limits.file_bytes)
            .ok()
            .map(|r| r.bytes);
        let blocks = bytes.as_deref().map(find_blocks).unwrap_or_default();
        if blocks.is_empty() && ctx.managed_file.is_none() {
            return None;
        }
        let display = ctx.paths.display(&ctx.paths.user_config);
        let state = match blocks.as_slice() {
            [] => ProjectionState::Absent,
            [one] if !one.intact => {
                self.add(
                    finding::MARKER_EDITED,
                    FindingSeverity::Problem,
                    subject("projection", None),
                    ProbeLevel::Static,
                    None,
                    "the Heimdall include block was edited",
                    "review_config",
                    None,
                );
                ProjectionState::Conflict
            }
            [one] => match one.position {
                BlockPosition::BeforeFirstSection => ProjectionState::Healthy,
                BlockPosition::Conditional(span) => {
                    self.add(
                        finding::INCLUDE_CONDITIONAL,
                        FindingSeverity::Problem,
                        subject("projection", None),
                        ProbeLevel::Static,
                        Some(ConfigProvenance {
                            path_display: display.clone(),
                            line: span.line,
                        }),
                        "the Heimdall include block is inside a Host or Match section, so it applies conditionally",
                        "review_config",
                        None,
                    );
                    ProjectionState::Conditional
                }
            },
            _ => {
                self.add(
                    finding::MARKER_EDITED,
                    FindingSeverity::Problem,
                    subject("projection", None),
                    ProbeLevel::Static,
                    None,
                    "the Heimdall include block appears more than once",
                    "review_config",
                    Some("marker_duplicated"),
                );
                ProjectionState::Conflict
            }
        };
        let conflict = match (state, blocks.len()) {
            (ProjectionState::Conflict, 1) => Some(ConflictKind::MarkerEdited),
            (ProjectionState::Conflict, _) => Some(ConflictKind::MarkerDuplicated),
            (ProjectionState::Conditional, _) => Some(ConflictKind::IncludeConditional),
            _ => None,
        };
        Some(ProjectionObservation {
            state,
            generation: None,
            conflict,
        })
    }

    fn providers(&mut self, agents: &[AgentEndpoint]) -> Vec<ProviderStatus> {
        let now = Timestamp::now();
        let home = self.ctx.paths.account_home.clone();
        let mut out = Vec::new();
        for a in agents {
            let availability = match a.presence {
                Presence::Present | Presence::Unknown => ProviderAvailability::Unknown,
                Presence::Absent | Presence::ForeignOwner => ProviderAvailability::Unavailable,
            };
            out.push(ProviderStatus {
                provider: a.provider,
                availability,
                interaction: InteractionKind::Unknown,
                observed_level: ProbeLevel::Static,
                observed_at: now,
                basis: EvidenceBasis::Inferred,
            });
            let display = a.locator.display(&home);
            let prov = match &a.source {
                EndpointSource::IdentityAgent(p) => Some(p.clone()),
                _ => None,
            };
            match a.presence {
                Presence::Absent => self.add(
                    finding::AGENT_ENDPOINT_MISSING,
                    FindingSeverity::Warning,
                    subject("endpoint", Some(&display)),
                    ProbeLevel::Static,
                    prov,
                    "an agent endpoint is named but nothing is there",
                    "review_config",
                    None,
                ),
                Presence::ForeignOwner => self.add(
                    finding::AGENT_ENDPOINT_FOREIGN_OWNER,
                    FindingSeverity::Problem,
                    subject("endpoint", Some(&display)),
                    ProbeLevel::Static,
                    prov,
                    "the agent socket is owned by another user; it is never contacted",
                    "review_config",
                    None,
                ),
                Presence::Present | Presence::Unknown => {}
            }
        }
        out
    }

    fn alias_list(&self, config_aliases: &[String]) -> Vec<String> {
        if let Some(list) = &self.request.aliases {
            return list.clone();
        }
        let mut out: Vec<String> = self.ctx.catalog.iter().map(|c| c.alias.clone()).collect();
        for a in config_aliases {
            if !out.contains(a) && out.len() < MAX_ALIASES {
                out.push(a.clone());
            }
        }
        out
    }

    fn observe(
        &self,
        set: &ConfigSet,
        evaluation: &Evaluation,
        roots: &Roots,
        name: &str,
        r: &Resolved,
    ) -> DirectiveObservation {
        let command = matches!(name, "ProxyCommand" | "LocalCommand" | "KnownHostsCommand");
        let shown = |v: &Value| -> String {
            if v.args.is_empty() {
                "<unreadable>".to_owned()
            } else if command {
                "<command>".to_owned()
            } else {
                v.args.join(" ")
            }
        };
        // ADR-0007 §12.28 item 6: each file as the configuration names it.
        let prov = |v: &Value| probe::provenance_in(self.ctx, set, evaluation, roots, v.span);
        match r {
            Resolved::Unset => DirectiveObservation {
                directive: name.to_owned(),
                values: Vec::new(),
                certainty: DirectiveCertainty::Unset,
                provenance: Vec::new(),
            },
            Resolved::Determined(v) => DirectiveObservation {
                directive: name.to_owned(),
                values: vec![shown(v)],
                certainty: DirectiveCertainty::Determined,
                provenance: vec![prov(v)],
            },
            Resolved::Undetermined(vs) => DirectiveObservation {
                directive: name.to_owned(),
                values: vs.iter().map(shown).collect(),
                certainty: DirectiveCertainty::Undetermined,
                provenance: vs.iter().map(prov).collect(),
            },
        }
    }

    fn behavior(
        &self,
        set: &ConfigSet,
        evaluation: &Evaluation,
        roots: &Roots,
        b: &RelevantBehavior,
    ) -> Vec<DirectiveObservation> {
        let mut out = Vec::new();
        let first: [(&str, &Resolved); 4] = [
            ("HostName", &b.hostname),
            ("Port", &b.port),
            ("User", &b.user),
            ("IdentityAgent", &b.identity_agent),
        ];
        for (n, r) in first {
            out.push(self.observe(set, evaluation, roots, n, r));
        }
        for (name, list) in [
            ("IdentityFile", &b.identity_files),
            ("CertificateFile", &b.certificate_files),
        ] {
            let certain = list.iter().all(|c| c.determined);
            out.push(DirectiveObservation {
                directive: name.to_owned(),
                values: list
                    .iter()
                    .map(|c| {
                        if c.value.args.is_empty() {
                            "<unreadable>".to_owned()
                        } else {
                            c.value.args.join(" ")
                        }
                    })
                    .collect(),
                certainty: if list.is_empty() {
                    DirectiveCertainty::Unset
                } else if certain {
                    DirectiveCertainty::Determined
                } else {
                    DirectiveCertainty::Undetermined
                },
                provenance: list
                    .iter()
                    .map(|c| probe::provenance_in(self.ctx, set, evaluation, roots, c.value.span))
                    .collect(),
            });
        }
        out.push(self.observe(set, evaluation, roots, "IdentitiesOnly", &b.identities_only));
        fn proxy_values(p: &Proxy) -> Option<(String, &Value)> {
            match p {
                Proxy::None => None,
                Proxy::Jump(v) => Some((format!("ProxyJump {}", v.args.join(" ")), v)),
                Proxy::Command(v) => Some(("ProxyCommand <command>".to_owned(), v)),
            }
        }
        let (values, provs, certainty) = match &b.proxy {
            ProxyResolution::Determined(p) => match proxy_values(p) {
                Some((s, v)) => (
                    vec![s],
                    vec![probe::provenance_in(
                        self.ctx, set, evaluation, roots, v.span,
                    )],
                    DirectiveCertainty::Determined,
                ),
                None => (Vec::new(), Vec::new(), DirectiveCertainty::Unset),
            },
            ProxyResolution::Undetermined(ps) => {
                let mut vals = Vec::new();
                let mut provs = Vec::new();
                for p in ps {
                    match proxy_values(p) {
                        Some((s, v)) => {
                            vals.push(s);
                            provs.push(probe::provenance_in(
                                self.ctx, set, evaluation, roots, v.span,
                            ));
                        }
                        None => vals.push("none".to_owned()),
                    }
                }
                (vals, provs, DirectiveCertainty::Undetermined)
            }
        };
        out.push(DirectiveObservation {
            directive: "Proxy".to_owned(),
            values,
            certainty,
            provenance: provs,
        });
        let rest: [(&str, &Resolved); 14] = [
            ("ControlMaster", &b.control_master),
            ("ControlPath", &b.control_path),
            ("ControlPersist", &b.control_persist),
            ("ForwardAgent", &b.forward_agent),
            ("StrictHostKeyChecking", &b.strict_host_key_checking),
            ("UserKnownHostsFile", &b.user_known_hosts_file),
            ("GlobalKnownHostsFile", &b.global_known_hosts_file),
            ("HostKeyAlias", &b.host_key_alias),
            ("CanonicalizeHostname", &b.canonicalize_hostname),
            ("PermitLocalCommand", &b.permit_local_command),
            ("LocalCommand", &b.local_command),
            ("KnownHostsCommand", &b.known_hosts_command),
            ("AddKeysToAgent", &b.add_keys_to_agent),
            ("PKCS11Provider", &b.pkcs11_provider),
        ];
        for (n, r) in rest {
            out.push(self.observe(set, evaluation, roots, n, r));
        }
        out.push(self.observe(
            set,
            evaluation,
            roots,
            "SecurityKeyProvider",
            &b.security_key_provider,
        ));
        out
    }

    /// Statically evaluate one alias under `invocation`, with its findings. The local
    /// account comes from the account database (ADR-0007 §12.25 item 2): when it cannot
    /// be established, only the conditions that read it are undetermined (§12.28 item
    /// 3), and an undetermined selection of a configuration that reads it says so in
    /// its `identity_selection_undetermined` finding.
    fn alias(
        &mut self,
        alias: &str,
        version: Option<OpenSshVersion>,
        invocation: Invocation,
    ) -> (AliasObservation, Evaluation) {
        let ctx = self.ctx;
        let source = ctx.source();
        let roots = ctx.roots();
        let query = probe::query_with(ctx, alias, version, invocation);
        let mut set = ConfigSet::new();
        let evaluation = evaluate(&mut set, &source, &roots, &query, &ctx.limits);
        let account_unknown = query.local_user.is_none() && reads_local_account(&set, &evaluation);
        let behavior = relevant(&evaluation);
        let catalog = ctx.catalog_alias(alias).cloned();
        let subj = || subject("destination", Some(alias));
        for u in &evaluation.unresolved {
            let prov = probe::provenance_in(ctx, &set, &evaluation, &roots, u.span);
            match &u.reason {
                UnresolvedReason::MatchExec | UnresolvedReason::MatchLocalNetwork => self.add(
                    finding::DYNAMIC_MATCH_UNRESOLVED,
                    FindingSeverity::Warning,
                    subj(),
                    ProbeLevel::Static,
                    Some(prov),
                    "a Match condition cannot be decided without running something; the values it guards are undetermined",
                    "review_config",
                    Some(if u.reason == UnresolvedReason::MatchExec {
                        "match_exec"
                    } else {
                        "match_localnetwork"
                    }),
                ),
                UnresolvedReason::BoundExceeded => self.add(
                    finding::BOUND_EXCEEDED,
                    FindingSeverity::Problem,
                    subj(),
                    ProbeLevel::Static,
                    Some(prov),
                    "a read bound was exceeded; the tree is not fully readable",
                    "review_config",
                    None,
                ),
                _ => {}
            }
        }
        let match_exec: BTreeSet<_> = evaluation
            .unresolved
            .iter()
            .filter(|u| u.reason == UnresolvedReason::MatchExec)
            .map(|u| u.span)
            .collect();
        for span in executing_constructs(&evaluation) {
            if match_exec.contains(&span) {
                continue;
            }
            let prov = probe::provenance_in(ctx, &set, &evaluation, &roots, span);
            self.add(
                finding::EXECUTABLE_DIRECTIVE_PRESENT,
                FindingSeverity::Info,
                subj(),
                ProbeLevel::Static,
                Some(prov),
                "a directive runs a command when ssh uses this alias; it was not run",
                "none",
                None,
            );
        }
        for inv in &evaluation.invalid {
            let prov = probe::provenance_in(ctx, &set, &evaluation, &roots, inv.span);
            let code = if inv.reason == "byte_order_mark" {
                finding::UNSUPPORTED_ENCODING
            } else {
                finding::CONFIG_INVALID
            };
            self.add(
                code,
                FindingSeverity::Problem,
                subj(),
                ProbeLevel::Static,
                Some(prov),
                "ssh would refuse this line",
                "review_config",
                Some(&inv.reason),
            );
        }
        if let Resolved::Determined(v) = &behavior.strict_host_key_checking
            && v.args.first().is_some_and(|a| {
                matches!(a.to_ascii_lowercase().as_str(), "no" | "off" | "accept-new")
            })
        {
            let prov = probe::provenance_in(ctx, &set, &evaluation, &roots, v.span);
            self.add(
                finding::STRICT_HOST_KEY_CHECKING_WEAK,
                FindingSeverity::Warning,
                subj(),
                ProbeLevel::Static,
                Some(prov),
                "StrictHostKeyChecking accepts unknown host keys for this alias",
                "review_host_trust",
                None,
            );
        }
        let mut identity_report = None;
        if let Some(identity) = catalog.as_ref().and_then(|c| c.identity.as_ref()) {
            let (mut report, spans) =
                identity_selection_with_spans(&evaluation, &identity.public_key_path, &source);
            for (entry, span) in report.entries.iter_mut().zip(spans) {
                if entry.provenance.is_none()
                    && let Some(span) = span
                {
                    entry.provenance =
                        Some(probe::provenance_in(ctx, &set, &evaluation, &roots, span));
                }
            }
            match report.selection {
                IdentitySelection::Exclusive => {}
                IdentitySelection::NotExclusive => self.add(
                    finding::IDENTITY_SELECTION_NOT_EXCLUSIVE,
                    FindingSeverity::Warning,
                    subj(),
                    ProbeLevel::Static,
                    report
                        .entries
                        .iter()
                        .find_map(|e| e.provenance.clone()),
                    "ssh may offer other identities than the adopted key for this alias: an inherited IdentityFile or CertificateFile, a default identity, or every key in the agent without IdentitiesOnly yes. Remedy: set IdentitiesOnly yes for the alias and remove or scope the inherited IdentityFile and CertificateFile lines listed in identity_selection",
                    "review_config",
                    None,
                ),
                IdentitySelection::Undetermined => self.add(
                    finding::IDENTITY_SELECTION_UNDETERMINED,
                    FindingSeverity::Warning,
                    subj(),
                    ProbeLevel::Static,
                    None,
                    if account_unknown {
                        "the configuration reads the local account name, which cannot be established from the account database, so the identities ssh offers for this alias are undetermined"
                    } else {
                        "which identities ssh offers for this alias depends on something static evaluation cannot decide"
                    },
                    "review_config",
                    None,
                ),
                _ => {}
            }
            if report.entries.len() > MAX_IDENTITY_ENTRIES {
                self.add(
                    finding::TOO_MANY_IDENTITIES,
                    FindingSeverity::Warning,
                    subj(),
                    ProbeLevel::Static,
                    None,
                    "more identities than a server's default MaxAuthTries allows may be offered before the adopted key",
                    "review_config",
                    None,
                );
            }
            for e in &report.entries {
                if e.fingerprint.is_none() && e.backing == IdentityBacking::Unknown {
                    self.add(
                        finding::IDENTITY_PUBLIC_KEY_UNKNOWN,
                        FindingSeverity::Warning,
                        subj(),
                        ProbeLevel::Static,
                        e.provenance.clone(),
                        "an identity's public key is unknown (no .pub file); it is never read from the private key",
                        "review_config",
                        None,
                    );
                }
            }
            if let (Some(endpoint), Resolved::Determined(v)) =
                (&identity.endpoint, &behavior.identity_agent)
            {
                let expanded = v
                    .args
                    .first()
                    .and_then(|a| crate::agents::expand_agent_value(a, &source, &ctx.env))
                    .and_then(|s| crate::agents::locator_for(&s, ctx.platform));
                if expanded.as_ref() != Some(endpoint) {
                    let prov = probe::provenance_in(ctx, &set, &evaluation, &roots, v.span);
                    self.add(
                        finding::IDENTITY_AGENT_OVERRIDDEN,
                        FindingSeverity::Warning,
                        subj(),
                        ProbeLevel::Static,
                        Some(prov),
                        "the effective IdentityAgent for this alias is not the identity's provider endpoint",
                        "review_config",
                        None,
                    );
                }
            }
            identity_report = Some(report);
        }
        self.known_host_static(alias, &behavior);
        let mut obs = AliasObservation {
            alias: alias.to_owned(),
            definition: catalog.map_or(AliasDefinition::UserOnly, |c| c.definition),
            behavior: self.behavior(&set, &evaluation, &roots, &behavior),
            identity_selection: identity_report,
        };
        redisplay_observation(&mut obs, &ctx.paths.account_home);
        (obs, evaluation)
    }

    fn known_host_static(&mut self, alias: &str, b: &RelevantBehavior) {
        // Only the default files are looked up; a configured file is the probe's.
        if !matches!(b.user_known_hosts_file, Resolved::Unset)
            || !matches!(b.global_known_hosts_file, Resolved::Unset)
        {
            return;
        }
        let Some((host, port)) = destination(alias, b) else {
            return;
        };
        let name = match &b.host_key_alias {
            Resolved::Determined(v) => v.args.first().cloned().unwrap_or(host),
            Resolved::Unset => host,
            Resolved::Undetermined(_) => return,
        };
        let keygen =
            crate::clients::selected_path(&self.ctx.env, &self.ctx.clients, ClientKind::SshKeygen);
        let look = lookup_detailed(
            &self.ctx.paths,
            &name,
            port,
            self.request.local_queries,
            keygen.as_deref(),
        );
        if look.complete && look.keys.iter().all(|k| k.revoked) {
            self.add(
                finding::KNOWN_HOST_MISSING,
                FindingSeverity::Info,
                subject("destination", Some(alias)),
                ProbeLevel::Static,
                None,
                "no known_hosts entry was found for this destination in the default files",
                "review_host_trust",
                None,
            );
        }
    }

    fn git(
        &mut self,
        inventory: &ClientInventory,
        agents: &[AgentEndpoint],
    ) -> Option<GitObservation> {
        inventory.selected(ClientKind::Git)?;
        let ctx = self.ctx;
        let q = self.request.local_queries;
        // ADR-0007 §12.37 item 1: Heimdall's own P_git is not a user's value. A value
        // reached once through an intact B_git is the projection's Git selection (the
        // run-time selection below reports it); every other value is a user's and is
        // reported with its origin.
        let p_git = ctx.managed_git_file();
        let mut obs = match &p_git {
            Some(p) => observe_global_for(&ctx.env, inventory, q, p),
            None => observe_global(&ctx.env, inventory, q),
        };
        let own = std::mem::take(&mut obs.own_values);
        let own = match &p_git {
            Some(p)
                if !own.is_empty()
                    && managed_include_present(&ctx.env, p, ctx.platform.is_windows()) =>
            {
                own
            }
            // No intact B_git links the file in: whatever it holds is present like any
            // other value (fail closed, as the setup preview takes it).
            _ => {
                obs.values.extend(own);
                Vec::new()
            }
        };
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\")
        } else {
            PathBuf::from("/")
        };
        let selection = resolve_run_selection(&root, &ctx.env, inventory, q);
        if !obs.values.is_empty() {
            self.add(
                finding::GIT_SSH_COMMAND_PRESENT,
                FindingSeverity::Info,
                subject("config", Some("core.sshCommand")),
                ProbeLevel::Static,
                None,
                "core.sshCommand is set in the system or global Git configuration (values are never shown)",
                "none",
                None,
            );
        }
        if let [own] = own.as_slice() {
            self.git_user_value_shadowed(inventory, own, &obs.values);
        }
        if obs.file.is_none() && ctx.env.get("GIT_CONFIG_GLOBAL").is_some() {
            self.add(
                finding::GIT_GLOBAL_REDIRECTED,
                FindingSeverity::Info,
                subject("environment", Some("GIT_CONFIG_GLOBAL")),
                ProbeLevel::Static,
                None,
                "GIT_CONFIG_GLOBAL redirects the global Git configuration",
                "none",
                None,
            );
        }
        if !obs.unreadable.is_empty() {
            self.add(
                finding::GIT_CONFIG_UNREADABLE,
                FindingSeverity::Warning,
                subject("config", Some("git")),
                ProbeLevel::Static,
                None,
                format!(
                    "{} Git configuration file(s) or include(s) could not be read within the bounds",
                    obs.unreadable.len()
                ),
                "review_config",
                None,
            );
        }
        if matches!(obs.default_ssh, DefaultGitSsh::BundledMsys(_))
            && agents
                .iter()
                .any(|a| matches!(a.locator, EndpointLocator::NamedPipe(_)))
        {
            self.add(
                finding::GIT_SSH_UNREACHABLE_AGENT,
                FindingSeverity::Warning,
                subject("executable", Some("git")),
                ProbeLevel::Static,
                None,
                "Git's bundled ssh cannot reach a named-pipe agent",
                "change_client",
                None,
            );
        }
        Some(GitObservation {
            selection,
            values: obs.values,
        })
    }

    /// ADR-0007 §12.37 item 2, §5.6 "Residual, disclosed": `git_user_value_shadowed`.
    /// B_git sits in the first-read global file at the time of the apply. A user
    /// `core.sshCommand` in the *other* global file that Git reads earlier (an XDG file
    /// created after the apply, while B_git is in `~/.gitconfig`) loses to Heimdall's value,
    /// because Git's last occurrence wins. It is reported when Heimdall's own value is the
    /// effective one (`git config --show-origin --get-all`, whose last entry is Git's
    /// choice) and a user value is global; when the user's value wins there is nothing to
    /// report, and without a local query nobody can say who wins. Origins and value
    /// digests only: a value is never shown.
    fn git_user_value_shadowed(
        &mut self,
        inventory: &ClientInventory,
        own: &GitValueObservation,
        user: &[GitValueObservation],
    ) {
        let shadowed: Vec<String> = user
            .iter()
            .filter(|v| v.scope == GitScope::Global && v.origin_display != own.origin_display)
            .map(|v| {
                format!(
                    "{} (sha256 {}{})",
                    v.origin_display.as_deref().unwrap_or("an unknown file"),
                    v.value_sha256,
                    if v.conditional { ", conditional" } else { "" }
                )
            })
            .collect();
        let Some(own_origin) = own.origin_display.as_deref() else {
            return;
        };
        if shadowed.is_empty()
            || winning_origin(&self.ctx.env, inventory, self.request.local_queries).as_deref()
                != Some(own_origin)
        {
            return;
        }
        self.add(
            finding::GIT_USER_VALUE_SHADOWED,
            FindingSeverity::Warning,
            subject("config", Some("core.sshCommand")),
            ProbeLevel::Static,
            None,
            format!(
                "Heimdall's core.sshCommand in {own_origin} (sha256 {}) takes effect over a user \
                 value in {} (values are never shown); move the value into the file that holds \
                 Heimdall's include, or roll back the Git item",
                own.value_sha256,
                shadowed.join("; ")
            ),
            "review_config",
            None,
        );
    }

    fn explicit_levels(
        &mut self,
        aliases: &[String],
        evaluations: &BTreeMap<String, Evaluation>,
        agents: &[AgentEndpoint],
        inventory: &ClientInventory,
    ) {
        let ctx = self.ctx;
        let mut pctx = ProbeContext::new(
            ctx,
            self.request.allow_config_commands,
            self.request.interactive,
        );
        pctx.inventory = Some(inventory);
        let levels: Vec<ProbeLevel> = self
            .request
            .levels
            .iter()
            .copied()
            .filter(|l| *l != ProbeLevel::Static)
            .collect();
        for level in levels {
            let before = self.probes.len();
            match level {
                ProbeLevel::Evaluate => {
                    for alias in aliases {
                        self.probes.push(probe::evaluate::ssh_g(&pctx, alias));
                    }
                }
                ProbeLevel::HostVerification => {
                    for alias in aliases {
                        let (r, class) = probe::host::verify_observed(&pctx, alias);
                        self.probes.push(r);
                        self.host_findings(alias, class);
                    }
                }
                ProbeLevel::Authentication => {
                    for alias in aliases {
                        let (r, refusal) = probe::auth::authenticate_observed(&pctx, alias);
                        self.probes.push(r);
                        if let Some(why) = refusal {
                            self.add(
                                finding::INTERACTION_UNKNOWN,
                                FindingSeverity::Warning,
                                subject("destination", Some(alias)),
                                ProbeLevel::Authentication,
                                None,
                                "a non-interactive authentication was refused before anything ran",
                                "interact",
                                Some(why.as_str()),
                            );
                        }
                    }
                }
                ProbeLevel::Network => {
                    for alias in aliases {
                        let Some(eval) = evaluations.get(alias) else {
                            continue;
                        };
                        let b = relevant(eval);
                        let direct = matches!(b.proxy, ProxyResolution::Determined(Proxy::None));
                        match (direct, destination(alias, &b)) {
                            (true, Some((host, port))) => {
                                self.probes.push(probe::network::banner(&pctx, &host, port));
                            }
                            _ => {
                                // Routed through a proxy, or not decided statically:
                                // reported undetermined, never probed.
                                self.probes.push(probe::refused(
                                    ProbeLevel::Network,
                                    alias,
                                    Code::CapabilityUnavailable,
                                ));
                            }
                        }
                    }
                }
                ProbeLevel::Agent => {
                    let mut targets: Vec<EndpointLocator> = Vec::new();
                    for a in agents {
                        if a.presence == Presence::Present && !targets.contains(&a.locator) {
                            targets.push(a.locator.clone());
                        }
                    }
                    for c in &ctx.catalog {
                        if let Some(e) = c.identity.as_ref().and_then(|i| i.endpoint.clone())
                            && !targets.contains(&e)
                        {
                            targets.push(e);
                        }
                    }
                    for t in targets {
                        let (r, listing) = probe::agent::list_identities_observed(&pctx, &t);
                        self.probes.push(r);
                        if let Ok(listing) = listing {
                            self.listing_findings(&t, &listing);
                        }
                    }
                }
                _ => {}
            }
            if self.probes.len() == before {
                self.probes.push(probe::refused(level, "*", Code::NotFound));
            }
        }
    }

    fn host_findings(&mut self, alias: &str, class: Option<probe::host::HostVerification>) {
        use probe::host::HostVerification as H;
        match class {
            Some(H::Missing) => self.add(
                finding::KNOWN_HOST_MISSING,
                FindingSeverity::Warning,
                subject("destination", Some(alias)),
                ProbeLevel::HostVerification,
                None,
                "the host presented a key that no known_hosts entry vouches for",
                "review_host_trust",
                None,
            ),
            Some(H::Mismatch) => self.add(
                finding::KNOWN_HOST_MISMATCH,
                FindingSeverity::Problem,
                subject("destination", Some(alias)),
                ProbeLevel::HostVerification,
                None,
                "the host presented a key that differs from the known_hosts entry",
                "review_host_trust",
                None,
            ),
            _ => {}
        }
    }

    fn listing_findings(
        &mut self,
        endpoint: &EndpointLocator,
        listing: &heimdall_ipc::agent_client::AgentListing,
    ) {
        let listed: BTreeSet<&str> = listing
            .identities
            .iter()
            .map(|i| i.fingerprint.as_str())
            .collect();
        let missing: Vec<String> = self
            .ctx
            .catalog
            .iter()
            .filter_map(|c| {
                let id = c.identity.as_ref()?;
                (id.endpoint.as_ref() == Some(endpoint)
                    && id
                        .fingerprint
                        .as_deref()
                        .is_some_and(|f| !listed.contains(f)))
                .then(|| c.alias.clone())
            })
            .collect();
        for alias in missing {
            self.add(
                finding::IDENTITY_NOT_LISTED,
                FindingSeverity::Warning,
                subject("destination", Some(&alias)),
                ProbeLevel::Agent,
                None,
                "the agent does not list the adopted identity",
                "interact",
                None,
            );
        }
    }
}

/// The statically known destination of an alias: its determined `HostName` (or the
/// alias when unset; `%h` is the alias) and its determined `Port` (22 when unset).
fn destination(alias: &str, b: &RelevantBehavior) -> Option<(String, u16)> {
    let host = match &b.hostname {
        Resolved::Unset => alias.to_owned(),
        Resolved::Determined(v) => {
            let h = v.args.first()?;
            if h.contains('%') {
                h.replace("%h", alias).replace("%%", "%")
            } else {
                h.clone()
            }
        }
        Resolved::Undetermined(_) => return None,
    };
    if host.contains('%') {
        return None;
    }
    let port = match &b.port {
        Resolved::Unset => 22,
        Resolved::Determined(v) => v.args.first()?.parse().ok()?,
        Resolved::Undetermined(_) => return None,
    };
    Some((host, port))
}

/// `--redact`: aliases become `alias-<n>`; host names, user names and host key aliases
/// become `<redacted>`.
fn redact(report: &mut DoctorReport) {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (i, a) in report.aliases.iter().enumerate() {
        names.insert(a.alias.clone(), format!("alias-{}", i + 1));
    }
    let swap = |s: &str| names.get(s).cloned();
    for a in &mut report.aliases {
        if let Some(n) = swap(&a.alias) {
            a.alias = n;
        }
        for d in &mut a.behavior {
            if matches!(
                d.directive.as_str(),
                "HostName" | "User" | "HostKeyAlias" | "Proxy"
            ) {
                for v in &mut d.values {
                    *v = "<redacted>".to_owned();
                }
            }
        }
    }
    for f in &mut report.findings {
        if let Some(id) = f.subject.id.as_deref().and_then(swap) {
            f.subject.id = Some(id);
        }
    }
    for p in &mut report.probes {
        if let Some(n) = swap(&p.target) {
            p.target = n;
        } else if p.level == ProbeLevel::Network
            && let Some((_, port)) = p.target.rsplit_once(':')
        {
            p.target = format!("<redacted>:{port}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn destination_uses_the_alias_and_default_port_when_unset() {
        let unset = RelevantBehavior {
            hostname: Resolved::Unset,
            port: Resolved::Unset,
            ..relevant(&Evaluation::default())
        };
        assert_eq!(
            destination("a.example", &unset),
            Some(("a.example".to_owned(), 22))
        );
    }

    #[test]
    fn passive_request_is_static_only() {
        let r = DoctorRequest::passive();
        assert_eq!(r.levels, BTreeSet::from([ProbeLevel::Static]));
        assert!(!r.allow_config_commands);
        assert_eq!(r.local_queries, LocalQueries::Enabled);
    }

    /// A scratch home whose user file is `text`, evaluated for `alias` with no local
    /// account (as a builder does when the account cannot be established).
    #[cfg(unix)]
    fn reads(text: &str) -> bool {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh").join("config"), text).unwrap();
        std::fs::write(home.join("other.conf"), "Host x\n  Match localuser a\n").unwrap();
        let paths = SshPaths::with_test_override(home.clone(), dir.path().join("etc-ssh"));
        let source = BoundedSource::new(paths.clone(), Env::default(), Limits::default());
        let roots = Roots::new(Some(paths.user_config.clone()), None);
        let query = heimdall_sshconf::eval::Query {
            host: "alias".to_owned(),
            user: None,
            local_user: None,
            client_version: OpenSshVersion::MINIMUM,
            invocation: Invocation::Shell,
        };
        let mut set = ConfigSet::new();
        let evaluation = evaluate(&mut set, &source, &roots, &query, &Limits::default());
        reads_local_account(&set, &evaluation)
    }

    /// ADR-0007 §12.25 item 2 (T02): with the local account not established, a
    /// configuration reads it through `Match localuser` (negated or not, any case, in
    /// a section that does not apply too), `Match user` (compared with the local
    /// account when no `User` is in force), or an `Include` argument with `%u` or
    /// `%r`; through a file it includes as well. Anything else does not.
    #[cfg(unix)]
    #[test]
    fn a_configuration_reads_the_local_account_only_through_its_tokens_and_criteria() {
        for text in [
            "Match localuser someone\n  IdentityFile ~/k\n",
            "Match !LocalUser someone\n  IdentityFile ~/k\n",
            "Host nothing-applies\nMatch user someone\n  IdentityFile ~/k\n",
            "Match host x user someone\n  Port 2\n",
            "Include ~/%u.conf\n",
            "Include ~/conf.d/%r\n",
            "Include ~/other.conf\n",
        ] {
            assert!(reads(text), "{text:?}");
        }
        for text in [
            "",
            "Host alias\n  User someone\n  IdentityFile ~/k\n",
            "Match host alias\n  Port 2\n",
            "Include ~/conf.d/%h\n",
            "Host alias\n  IdentityFile ~/.ssh/%u\n",
        ] {
            assert!(!reads(text), "{text:?}");
        }
    }

    /// ADR-0007 §12.26 item 7: a home reached through a symlink (the configured home is
    /// the link; the evaluator reports canonical file paths) still shows as `~/…`, from
    /// either side; the home itself is `~`; a path outside it is shown as given, and so
    /// is a sibling that only shares the home's name as a prefix.
    #[cfg(unix)]
    #[test]
    fn path_display_canonicalizes_the_home_and_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real").join("hm-fixture-account-name");
        std::fs::create_dir_all(real.join(".ssh")).unwrap();
        std::fs::write(real.join(".ssh").join("config"), "").unwrap();
        let link = dir.path().join("home");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        let file = canonical.join(".ssh").join("config");
        assert_eq!(path_display(&file, &link), "~/.ssh/config");
        assert_eq!(
            path_display(&link.join(".ssh").join("config"), &link),
            "~/.ssh/config"
        );
        assert_eq!(
            path_display(&link.join(".ssh").join("config"), &canonical),
            "~/.ssh/config"
        );
        assert_eq!(path_display(&canonical, &link), "~");
        assert_eq!(
            path_display(Path::new("/hm-fixture-outside/x"), &link),
            "/hm-fixture-outside/x"
        );
        let sibling = dir.path().join("homework");
        assert_eq!(path_display(&sibling, &link), sibling.display().to_string());
        let mut p = ConfigProvenance {
            path_display: file.display().to_string(),
            line: 3,
        };
        redisplay(&mut p, &link);
        assert_eq!(p.path_display, "~/.ssh/config");
        let mut kept = ConfigProvenance {
            path_display: "~/x".to_owned(),
            line: 1,
        };
        redisplay(&mut kept, &link);
        assert_eq!(kept.path_display, "~/x");
    }
}
