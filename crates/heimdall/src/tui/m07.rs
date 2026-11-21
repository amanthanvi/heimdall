//! ⟨M07⟩ The TUI's information architecture (m07-plan U1 and U2's TUI half; spec §5.1,
//! §5.6, §12.1–§12.3): the Environments, Identities, Projects and Settings views, the
//! overview's environment, access, lock and stop lines, and the everyday words the default
//! surfaces use.
//!
//! **Only what current views carry** (m07-plan U1 "Depends"). Each view reads the listings
//! one refresh already brings (`inspect environments`, `identities`, `policies`,
//! `workspace`, `destinations`, `capabilities`); nothing here asks for a new field.
//!
//! **Settings change only through the CLI's requests** ([`SettingAction::request`]): the
//! default profile (`access default-profile`), a policy's pause, resume and cutoff
//! (`access pause|resume|cutoff --clear`), its lock behaviour (`access lock-behavior`) and
//! its connection policy (`access connection-policy`). A narrowing applies at once; a
//! widening is answered with a decision, which the existing decision modal shows (the
//! worker's `Done` carries its `decision_ref`). Every change is confirmed with a typed
//! `yes` first, default No, as the stop menu's are. A setting with no CLI-equivalent
//! request is shown read-only with its CLI command.
//!
//! **Everyday words** (spec §5.1): grant, lease, certificate, issuer, generation, epoch,
//! principal and raw snake_case codes stay in detail views; the overview, first trust and
//! the stop menu say what happens in plain words ([`kind_words`], [`state_words`]).

use heimdall_contract::Timestamp;
use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::ids::{PolicyId, ProfileId, RequestId};
use heimdall_contract::managed::{ExistingConnectionsMode, LockBehavior, MultiplexingMode};
use heimdall_contract::request::{PolicyAction, Request};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use serde_json::Value;

use super::data::{Catalog, clean, items, text};
use super::keys::Key;

fn bold(s: impl Into<String>) -> Line<'static> {
    Line::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

fn plain(s: impl Into<String>) -> Line<'static> {
    Line::from(s.into())
}

fn hms(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ---- everyday words ------------------------------------------------------------------

/// A code as words: underscores and dots become spaces (never the raw code on a default
/// surface).
#[must_use]
pub(crate) fn spaced(code: &str) -> String {
    clean(code).replace(['_', '.'], " ")
}

/// What a decision of this kind is about, in everyday words (spec §5.1). The kind's wire
/// name stays in the decision's own detail.
#[must_use]
pub(crate) fn kind_words(kind: &str) -> String {
    match kind {
        "apply_projection" => "a change to your SSH configuration".to_owned(),
        "declare_interaction" => "how a key asks for confirmation".to_owned(),
        "approve_authority" => "more access for a request".to_owned(),
        "trust_workspace" => "using access automatically for a project".to_owned(),
        "widen_policy" => "more standing access".to_owned(),
        "reconcile_workspace" => "a moved or re-cloned project".to_owned(),
        "enroll_account" | "enroll_system_form" => {
            "setting up managed access on a machine".to_owned()
        }
        "approve_target_change" => "a changed machine address".to_owned(),
        "remove_enrollment" => "removing managed access from a machine".to_owned(),
        "register_issuer" | "retire_issuer" => "Heimdall's managed signing setup".to_owned(),
        other => spaced(other),
    }
}

/// An operation's kind in words.
#[must_use]
pub(crate) fn operation_words(kind: &str) -> String {
    match kind {
        "ensure" => "access request".to_owned(),
        "setup.apply" => "setup".to_owned(),
        other => spaced(other),
    }
}

/// A state in words (`outcome_unknown` reads "outcome unknown").
#[must_use]
pub(crate) fn state_words(state: &str) -> String {
    spaced(state)
}

/// A capability in words.
#[must_use]
pub(crate) fn capability_words(capability: &str) -> String {
    match capability {
        "ssh-authentication" | "ssh_authentication" => "SSH sign-in".to_owned(),
        "git-signing" | "git_signing" => "Git signing".to_owned(),
        other => spaced(other).replace('-', " "),
    }
}

/// A key's mechanism in words.
fn mechanism_words(mechanism: &str) -> String {
    match mechanism {
        "native_agent" => "SSH agent".to_owned(),
        "onepassword" => "1Password".to_owned(),
        other => spaced(other),
    }
}

// ---- environments --------------------------------------------------------------------

/// One environment of `inspect environments` (`EnvironmentView`, read tolerantly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Environment {
    /// Environment ID.
    pub id: String,
    /// `native_session`, `wsl_distribution` or `container`.
    pub kind: String,
    /// The owner's label.
    pub label: Option<String>,
    /// `active`, `not_running`, `removed` or `gone`.
    pub state: String,
    /// How it is realized, one (field, value) per published field.
    pub realization: Vec<(String, String)>,
}

impl Environment {
    fn of(v: &Value) -> Option<Self> {
        let r = v.get("realization").unwrap_or(&Value::Null);
        let mut realization = Vec::new();
        if let Some(kind) = text(r, "kind") {
            realization.push(("realized as".to_owned(), spaced(&kind)));
        }
        for key in [
            "name",
            "account",
            "label",
            "directory",
            "in_container_path",
            "helper",
        ] {
            if let Some(t) = text(r, key) {
                realization.push((spaced(key), t));
            }
        }
        let modes: Vec<String> = items(r, &["modes"])
            .iter()
            .filter_map(|m| m.as_str().map(clean))
            .collect();
        if !modes.is_empty() {
            realization.push(("modes".to_owned(), modes.join(", ")));
        }
        Some(Self {
            id: text(v, "environment_id")?,
            kind: text(v, "kind").unwrap_or_else(|| "?".to_owned()),
            label: text(v, "label"),
            state: text(v, "state").unwrap_or_else(|| "?".to_owned()),
            realization,
        })
    }

    /// Its name in words: the owner's label, else what it is.
    #[must_use]
    pub(crate) fn name(&self, own: bool) -> String {
        if let Some(l) = &self.label {
            return l.clone();
        }
        let named = |key: &str| {
            self.realization
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };
        match self.kind.as_str() {
            "native_session" if own => "this computer".to_owned(),
            "native_session" => "a native session".to_owned(),
            "wsl_distribution" => format!("WSL {}", named("name").unwrap_or_default()),
            "container" => format!("container {}", named("label").unwrap_or_default()),
            other => spaced(other),
        }
    }

    /// Its state's text marker and words.
    #[must_use]
    pub(crate) fn state_class(&self) -> (&'static str, String) {
        match self.state.as_str() {
            "active" => ("[OK]", "active".to_owned()),
            "not_running" => ("[ !]", "not running".to_owned()),
            "removed" | "gone" => ("[--]", state_words(&self.state)),
            other => ("[??]", state_words(other)),
        }
    }
}

/// `inspect environments` (the owner's view: every environment, the runtime's own first).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Environments {
    /// The runtime's own environment ID (`environment_id`).
    pub own: Option<String>,
    /// Every environment the runtime knows.
    pub items: Vec<Environment>,
}

impl Environments {
    /// From the `data` of `inspect environments` (`Null` when not read).
    #[must_use]
    pub(crate) fn of(v: &Value) -> Self {
        Self {
            own: text(v, "environment_id"),
            items: items(v, &["items"])
                .iter()
                .filter_map(Environment::of)
                .collect(),
        }
    }

    /// The runtime's own environment, when listed.
    #[must_use]
    pub(crate) fn own_environment(&self) -> Option<&Environment> {
        let own = self.own.as_deref()?;
        self.items.iter().find(|e| e.id == own)
    }

    /// The name of environment `id` in words (`this computer` for the runtime's own
    /// native session), or the ID.
    #[must_use]
    pub(crate) fn name_of(&self, id: &str) -> String {
        let own = self.own.as_deref() == Some(id);
        self.items.iter().find(|e| e.id == id).map_or_else(
            || {
                if own {
                    "this environment".to_owned()
                } else {
                    clean(id)
                }
            },
            |e| e.name(own),
        )
    }
}

/// The Environments view's row for `e`.
#[must_use]
pub(crate) fn environment_row(envs: &Environments, e: &Environment) -> (&'static str, String) {
    let own = envs.own.as_deref() == Some(e.id.as_str());
    let (marker, words) = e.state_class();
    (
        marker,
        format!(
            "{:<28} {words}{}  {}",
            e.name(own),
            if own { " · this runtime's own" } else { "" },
            e.id
        ),
    )
}

/// The detail of environment `id`: every published field with where it came from and
/// when it was read.
#[must_use]
pub(crate) fn environment_lines(catalog: &Catalog, id: &str, read: &str) -> Vec<Line<'static>> {
    let envs = &catalog.environments;
    let Some(e) = envs.items.iter().find(|e| e.id == id) else {
        return vec![plain(format!("{id}: not in the latest listing"))];
    };
    let own = envs.own.as_deref() == Some(id);
    let (marker, words) = e.state_class();
    let mut lines = vec![bold(format!(
        "{}{}",
        e.name(own),
        if own {
            " (this runtime's own environment)"
        } else {
            ""
        }
    ))];
    lines.push(plain(format!(
        "Source: the runtime's environment list (inspect environments), read {read}"
    )));
    lines.push(plain(format!("  [runtime] ID {}", e.id)));
    lines.push(plain(format!("  [runtime] kind {}", spaced(&e.kind))));
    lines.push(plain(format!("  [runtime] state {marker} {words}")));
    lines.push(plain(match &e.label {
        Some(l) => format!("  [yours]   label {l} (set by you)"),
        None => "  [runtime] label none".to_owned(),
    }));
    for (k, v) in &e.realization {
        lines.push(plain(format!("  [runtime] {k} {v}")));
    }
    let policies: Vec<&super::m05::Policy> = catalog
        .m05
        .policies
        .iter()
        .flatten()
        .filter(|p| p.environments.iter().any(|x| x == id))
        .collect();
    lines.push(plain(""));
    lines.push(bold("Standing access that covers it (inspect policies):"));
    if catalog.m05.policies.is_none() {
        lines.push(plain("  not listed by this runtime"));
    } else if policies.is_empty() {
        lines.push(plain("  none: requests from it ask you each time"));
    }
    for p in policies {
        lines.push(plain(format!(
            "  {} · profile {} · {}",
            p.id,
            p.profile,
            policy_state_words(p)
        )));
    }
    if let Some((_, profile)) = catalog.m05.default_profiles.iter().find(|(e, _)| e == id) {
        lines.push(plain(format!(
            "Default profile: {profile} (a preference, never authority)"
        )));
    }
    lines
}

// ---- identities ----------------------------------------------------------------------

/// The Identities view's row for identity `i`.
#[must_use]
pub(crate) fn identity_row(i: &super::data::Identity) -> (&'static str, String) {
    let (marker, eligible) = match i.noninteractive {
        Some(true) => ("[OK]", "background use: allowed"),
        Some(false) => ("[ !]", "background use: asks first"),
        None => ("[??]", "background use: unknown"),
    };
    (
        marker,
        format!(
            "{:<12} {} {} via {} · {eligible}",
            i.id,
            i.fingerprint,
            i.key_type.as_deref().unwrap_or("?"),
            i.mechanism
                .as_deref()
                .map_or_else(|| "?".to_owned(), mechanism_words),
        ),
    )
}

/// The detail of identity `id`: each value with where it came from and how fresh it is.
#[must_use]
pub(crate) fn identity_lines(
    catalog: &Catalog,
    id: &str,
    read: &str,
    checked: &str,
    declared: &dyn Fn(Option<Timestamp>) -> String,
) -> Vec<Line<'static>> {
    let Some(i) = catalog.identity(id) else {
        return vec![plain(format!("{id}: not in the latest listing"))];
    };
    let mut lines = vec![bold(format!("Identity {}", i.id))];
    lines.push(plain(format!(
        "Source: the runtime's identity list (inspect identities), read {read}"
    )));
    lines.push(plain(format!("  [adopted]  fingerprint {}", i.fingerprint)));
    lines.push(plain(format!(
        "  [adopted]  key type {}",
        i.key_type.as_deref().unwrap_or("unknown")
    )));
    lines.push(plain(format!(
        "  [adopted]  held by {} at {}",
        i.mechanism
            .as_deref()
            .map_or_else(|| "unknown".to_owned(), mechanism_words),
        i.endpoint.as_deref().unwrap_or("unknown")
    )));
    let basis = i.basis.as_deref().unwrap_or("unknown");
    let class = match basis {
        "declared" => "[declared]",
        "documented" => "[documented]",
        "inferred" => "[inferred]",
        "observed" => "[observed]",
        _ => "[unknown]",
    };
    lines.push(plain(format!(
        "  {class:<10} asks for confirmation: {} (basis {basis})",
        spaced(&i.interaction)
    )));
    if basis == "declared" {
        lines.push(plain(format!(
            "  [declared] declared {} · expires {}",
            declared(i.declared_at),
            declared(i.declaration_expires_at)
        )));
    }
    lines.push(plain(format!(
        "  [runtime]  background use: {} (checked {checked})",
        match i.noninteractive {
            Some(true) => "allowed",
            Some(false) => "not allowed (it may ask for confirmation)",
            None => "unknown",
        }
    )));
    let using: Vec<&str> = catalog
        .destinations
        .iter()
        .filter(|d| d.identity_id.as_deref() == Some(id))
        .map(|d| d.alias.as_str())
        .collect();
    lines.push(plain(format!(
        "  [catalog]  destinations using it: {}",
        if using.is_empty() {
            "none listed".to_owned()
        } else {
            using.join(", ")
        }
    )));
    lines
}

// ---- projects ------------------------------------------------------------------------

/// The Projects view: the working directory's workspace status and every standing
/// policy, with where they came from (`w` and `h` open the same screens in full).
#[must_use]
pub(crate) fn projects_lines(catalog: &Catalog, now: Timestamp, read: &str) -> Vec<Line<'static>> {
    let mut lines = super::m05::workspace_lines(catalog, now);
    // The workspace view's own key line is replaced by this view's footer.
    if lines
        .last()
        .is_some_and(|l| l.to_string().starts_with("s pause"))
    {
        lines.pop();
        lines.pop();
    }
    lines.push(plain(""));
    lines.push(bold("Standing access"));
    match &catalog.m05.policies {
        None => lines.push(plain("  not listed by this runtime")),
        Some(ps) if ps.is_empty() => lines.push(plain("  none")),
        Some(ps) => {
            for p in ps {
                lines.push(plain(format!(
                    "  {} · profile {} · {} · {}",
                    p.id,
                    p.profile,
                    match &p.workspace_id {
                        Some(w) => format!("project {w}"),
                        None => "personal".to_owned(),
                    },
                    policy_state_words(p)
                )));
            }
        }
    }
    lines.push(plain(""));
    lines.push(plain(format!(
        "Source: inspect workspace (this directory) and inspect policies, read {read}"
    )));
    lines
}

// ---- the overview's lines ------------------------------------------------------------

fn policy_paused(p: &super::m05::Policy, now: Timestamp) -> bool {
    p.paused_since.is_some() || p.cutoff_at.is_some_and(|c| c <= now)
}

fn policy_state_words(p: &super::m05::Policy) -> String {
    match (p.paused_since, p.cutoff_at) {
        (Some(_), _) => "[!!] paused".to_owned(),
        (None, Some(at)) => format!("[ i] cutoff {}", hms(at)),
        (None, None) => "[OK] automatic".to_owned(),
    }
}

/// The overview's environment line: the runtime's own environment and the active work
/// the listings carry (open operations, owned connections that are up).
#[must_use]
pub(crate) fn environment_line(catalog: &Catalog, narrow: bool) -> String {
    let envs = &catalog.environments;
    let name = envs.own_environment().map_or_else(
        || "this environment".to_owned(),
        |e| match e.kind.as_str() {
            "native_session" if !narrow => format!("{} (native session)", e.name(true)),
            _ => e.name(true),
        },
    );
    let running = catalog.operations.iter().filter(|o| o.is_active()).count();
    let connections = catalog.m03.connections.len();
    let work = match (running, connections) {
        (0, 0) => "no work running".to_owned(),
        (r, 0) => format!("{r} running"),
        (0, c) => format!("{c} connection(s) open"),
        (r, c) => format!("{r} running, {c} connection(s) open"),
    };
    if narrow {
        format!("Here: {name} · {work}")
    } else {
        format!("Environment: {name} · {work}")
    }
}

/// The overview's access line: which profiles this environment uses automatically, and
/// which are paused (from `inspect policies`).
#[must_use]
pub(crate) fn access_line(catalog: &Catalog, now: Timestamp, narrow: bool) -> String {
    let envs = &catalog.environments;
    let who = envs
        .own_environment()
        .map_or_else(|| "this environment".to_owned(), |e| e.name(true));
    let Some(policies) = &catalog.m05.policies else {
        return if narrow {
            "Access: not listed".to_owned()
        } else {
            format!("Access: {who}'s standing access is not listed by this runtime")
        };
    };
    let covering: Vec<&super::m05::Policy> = policies
        .iter()
        .filter(|p| {
            envs.own
                .as_deref()
                .is_none_or(|own| p.environments.iter().any(|e| e == own))
        })
        .collect();
    let mut automatic: Vec<&str> = Vec::new();
    let mut paused: Vec<&str> = Vec::new();
    for p in &covering {
        let list = if policy_paused(p, now) {
            &mut paused
        } else {
            &mut automatic
        };
        if !list.contains(&p.profile.as_str()) {
            list.push(&p.profile);
        }
    }
    paused.retain(|p| !automatic.contains(p));
    let paused_words = if paused.is_empty() {
        String::new()
    } else {
        format!("; paused: {}", paused.join(", "))
    };
    match (automatic.is_empty(), narrow) {
        (false, false) => format!(
            "Access: {who} uses {} automatically{paused_words}",
            automatic.join(", ")
        ),
        (false, true) => format!("Access: {} auto{paused_words}", automatic.join(", ")),
        (true, false) if covering.is_empty() => {
            format!("Access: {who} has no standing access; each request asks you")
        }
        (true, false) => format!("Access: {who} has no automatic access now{paused_words}"),
        (true, true) => format!("Access: none automatic{paused_words}"),
    }
}

/// The overview's lock line: whether work continues while the desktop is locked (the
/// capabilities' lock report). Narrow, it also names the stop key (one row less).
#[must_use]
pub(crate) fn lock_line(catalog: &Catalog, narrow: bool) -> String {
    let behavior = catalog.m03.lock.as_ref().map(|l| l.behavior.as_str());
    match (behavior, narrow) {
        (Some("continue"), false) => {
            "Desktop lock: work continues while your desktop is locked".to_owned()
        }
        (Some("continue"), true) => "Lock: work continues · s stop".to_owned(),
        (Some("revoke_on_lock"), false) => {
            "Desktop lock: locking your desktop ends managed access".to_owned()
        }
        (Some("revoke_on_lock"), true) => "Lock: locking ends access · s stop".to_owned(),
        (Some(other), false) => format!("Desktop lock: {}", spaced(other)),
        (Some(other), true) => format!("Lock: {} · s stop", spaced(other)),
        (None, false) => "Desktop lock: not reported by the runtime".to_owned(),
        (None, true) => "Lock: not reported · s stop".to_owned(),
    }
}

/// The overview's line on how to pause or stop (wide; narrow, the lock line names `s`,
/// or this line does while the runtime is not connected).
#[must_use]
pub(crate) fn stop_line(narrow: bool) -> &'static str {
    if narrow {
        "s: pause or stop access"
    } else {
        "Pause or stop access: press s (pause automatic access, stop work, a cutoff) · 8 Settings"
    }
}

// ---- settings ------------------------------------------------------------------------

/// One row of the Settings view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettingRow {
    /// An environment's default profile (`inspect policies` `default_profiles`).
    DefaultProfile {
        /// The environment (its ID, or "this environment" when the runtime's own is not
        /// listed).
        environment: String,
        /// The runtime's own (the only one `access default-profile` changes).
        own: bool,
        /// The current default.
        profile: Option<String>,
    },
    /// A standing policy's pause and cutoff state, and its lock and connection settings.
    Policy {
        /// Policy ID.
        id: String,
    },
    /// The current lock behaviour (the capabilities' lock report).
    Lock,
    /// A managed destination's connection policy (`inspect destinations` preference).
    Connection {
        /// Alias.
        alias: String,
    },
}

/// The Settings view's rows, in order: default profiles, standing access, the lock
/// behaviour, each managed destination's connection policy.
#[must_use]
pub(crate) fn settings_rows(catalog: &Catalog) -> Vec<SettingRow> {
    let own = catalog.environments.own.clone();
    let defaults = &catalog.m05.default_profiles;
    let mut rows = vec![SettingRow::DefaultProfile {
        environment: own.clone().unwrap_or_else(|| "this environment".to_owned()),
        own: true,
        profile: own
            .as_deref()
            .and_then(|o| defaults.iter().find(|(e, _)| e == o))
            .map(|(_, p)| p.clone()),
    }];
    for (e, p) in defaults {
        if Some(e) != own.as_ref() {
            rows.push(SettingRow::DefaultProfile {
                environment: e.clone(),
                own: false,
                profile: Some(p.clone()),
            });
        }
    }
    for p in catalog.m05.policies.iter().flatten() {
        rows.push(SettingRow::Policy { id: p.id.clone() });
    }
    rows.push(SettingRow::Lock);
    for d in catalog.destinations.iter().filter(|d| d.is_managed()) {
        rows.push(SettingRow::Connection {
            alias: d.alias.clone(),
        });
    }
    rows
}

/// A change Settings can make: exactly the request the CLI sends for the same command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettingAction {
    /// `access default-profile <profile>` (or `--clear`): `catalog set_default_profile`
    /// for the runtime's own environment. A preference, never authority.
    DefaultProfile {
        /// The profile, `None` to clear.
        profile: Option<ProfileId>,
    },
    /// `access pause <policy>` (narrowing).
    Pause {
        /// The policy.
        policy: PolicyId,
    },
    /// `access resume <policy>` (widening: a decision).
    Resume {
        /// The policy.
        policy: PolicyId,
    },
    /// `access cutoff <policy> --clear` (widening: a decision).
    ClearCutoff {
        /// The policy.
        policy: PolicyId,
    },
    /// `access lock-behavior --policy <policy> continue|revoke-on-lock`.
    LockBehavior {
        /// The policy.
        policy: PolicyId,
        /// The behaviour.
        behavior: LockBehavior,
    },
    /// `access connection-policy --policy <policy> [--existing ..] [--multiplexing ..]`.
    ConnectionPolicy {
        /// The policy.
        policy: PolicyId,
        /// `--existing`.
        existing: Option<ExistingConnectionsMode>,
        /// `--multiplexing`.
        multiplexing: Option<MultiplexingMode>,
    },
}

impl SettingAction {
    /// The request it sends (the CLI's for the same command; `request_id` is used where
    /// the request carries one).
    #[must_use]
    pub(crate) fn request(&self, request_id: RequestId) -> Request {
        Request::Policy(match self {
            SettingAction::DefaultProfile { profile } => {
                return Request::Catalog(CatalogRequest::SetDefaultProfile {
                    environment: None,
                    profile: profile.clone(),
                    request_id,
                });
            }
            SettingAction::Pause { policy } => PolicyAction::Pause {
                policy_id: Some(policy.clone()),
                target: None,
            },
            SettingAction::Resume { policy } => PolicyAction::Resume {
                policy_id: Some(policy.clone()),
                target: None,
            },
            SettingAction::ClearCutoff { policy } => PolicyAction::ClearCutoff {
                policy_id: Some(policy.clone()),
                target: None,
            },
            SettingAction::LockBehavior { policy, behavior } => PolicyAction::SetLockBehavior {
                policy_id: policy.clone(),
                behavior: *behavior,
            },
            SettingAction::ConnectionPolicy {
                policy,
                existing,
                multiplexing,
            } => PolicyAction::SetConnectionPolicy {
                policy_id: policy.clone(),
                existing: *existing,
                multiplexing: *multiplexing,
            },
        })
    }

    /// Whether it widens (the runtime answers with a decision for the owner).
    #[must_use]
    pub(crate) fn widening(&self) -> bool {
        match self {
            SettingAction::DefaultProfile { .. } => false,
            SettingAction::Resume { .. } | SettingAction::ClearCutoff { .. } => true,
            SettingAction::Pause { .. } => false,
            SettingAction::LockBehavior { behavior, .. } => *behavior == LockBehavior::Continue,
            SettingAction::ConnectionPolicy {
                existing,
                multiplexing,
                ..
            } => {
                *existing == Some(ExistingConnectionsMode::Graceful)
                    || *multiplexing == Some(MultiplexingMode::OwnedMasters)
            }
        }
    }

    /// Whether the CLI sends `Attend` first for it (`cli::policy_flow`, `m05_cmd::
    /// owner_request`): a widening, never a narrowing or the default profile.
    #[must_use]
    pub(crate) fn attends(&self) -> bool {
        self.widening()
    }

    /// The CLI command that sends the same request.
    #[must_use]
    pub(crate) fn cli(&self) -> String {
        match self {
            SettingAction::DefaultProfile { profile: Some(p) } => {
                format!("heimdall access default-profile {p}")
            }
            SettingAction::DefaultProfile { profile: None } => {
                "heimdall access default-profile --clear".to_owned()
            }
            SettingAction::Pause { policy } => format!("heimdall access pause {policy}"),
            SettingAction::Resume { policy } => format!("heimdall access resume {policy}"),
            SettingAction::ClearCutoff { policy } => {
                format!("heimdall access cutoff {policy} --clear")
            }
            SettingAction::LockBehavior { policy, behavior } => format!(
                "heimdall access lock-behavior --policy {policy} {}",
                match behavior {
                    LockBehavior::RevokeOnLock => "revoke-on-lock",
                    _ => "continue",
                }
            ),
            SettingAction::ConnectionPolicy {
                policy,
                existing,
                multiplexing,
            } => {
                let mut s = format!("heimdall access connection-policy --policy {policy}");
                match existing {
                    Some(ExistingConnectionsMode::Strict) => s.push_str(" --existing strict"),
                    Some(_) => s.push_str(" --existing graceful"),
                    None => {}
                }
                match multiplexing {
                    Some(MultiplexingMode::OwnedMasters) => s.push_str(" --multiplexing owned"),
                    Some(_) => s.push_str(" --multiplexing disabled"),
                    None => {}
                }
                s
            }
        }
    }

    /// What it does, in one sentence the confirmation shows.
    #[must_use]
    pub(crate) fn sentence(&self) -> String {
        let then = if self.widening() {
            " This widens access: the runtime asks for your decision next, and nothing changes until you approve it."
        } else {
            " It applies at once."
        };
        let what = match self {
            SettingAction::DefaultProfile { profile: Some(p) } => format!(
                "Make {p} this environment's default profile: only new requests that name no profile use it."
            ),
            SettingAction::DefaultProfile { profile: None } => {
                "Clear this environment's default profile: new requests must name a profile."
                    .to_owned()
            }
            SettingAction::Pause { policy } => format!(
                "Pause {policy}: no new work starts automatically under it; running work continues."
            ),
            SettingAction::Resume { policy } => {
                format!("Resume {policy}: new work under it starts automatically again.")
            }
            SettingAction::ClearCutoff { policy } => {
                format!(
                    "Clear the cutoff of {policy}: work under it is no longer stopped at that time."
                )
            }
            SettingAction::LockBehavior { policy, behavior } => match behavior {
                LockBehavior::RevokeOnLock => {
                    format!("Under {policy}, locking your desktop ends managed access.")
                }
                _ => format!("Under {policy}, work continues while your desktop is locked."),
            },
            SettingAction::ConnectionPolicy {
                policy,
                existing,
                multiplexing,
            } => {
                let mut parts = Vec::new();
                match existing {
                    Some(ExistingConnectionsMode::Strict) => {
                        parts.push("connections Heimdall owns close at the deadline".to_owned());
                    }
                    Some(_) => parts
                        .push("existing sessions may stay connected after the deadline".to_owned()),
                    None => {}
                }
                match multiplexing {
                    Some(MultiplexingMode::OwnedMasters) => parts
                        .push("Heimdall keeps one shared connection per destination".to_owned()),
                    Some(_) => parts.push("no shared connection is kept".to_owned()),
                    None => {}
                }
                format!("Under {policy}, {}.", parts.join("; "))
            }
        };
        format!("{what}{then}")
    }

    /// A short name for the status line.
    #[must_use]
    pub(crate) fn what(&self) -> String {
        match self {
            SettingAction::DefaultProfile { .. } => "default profile".to_owned(),
            SettingAction::Pause { policy } => format!("pause {policy}"),
            SettingAction::Resume { policy } => format!("resume {policy}"),
            SettingAction::ClearCutoff { policy } => format!("clear the cutoff of {policy}"),
            SettingAction::LockBehavior { policy, .. } => format!("lock behaviour of {policy}"),
            SettingAction::ConnectionPolicy { policy, .. } => {
                format!("connection policy of {policy}")
            }
        }
    }
}

/// One change a Settings row offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    /// Type a profile ID, then set it as the default.
    SetDefault,
    /// Clear the default.
    ClearDefault,
    /// Pause the policy.
    Pause,
    /// Resume the policy.
    Resume,
    /// Clear the policy's cutoff.
    ClearCutoff,
    /// Set the lock behaviour.
    Lock(LockBehavior),
    /// Set what happens to existing connections at the deadline.
    Existing(ExistingConnectionsMode),
    /// Set the multiplexing.
    Multiplexing(MultiplexingMode),
}

impl Choice {
    fn label(self) -> &'static str {
        match self {
            Choice::SetDefault => "Set the default profile (type its ID)",
            Choice::ClearDefault => "Clear the default profile",
            Choice::Pause => "Pause automatic access",
            Choice::Resume => "Resume automatic access",
            Choice::ClearCutoff => "Clear the cutoff",
            Choice::Lock(LockBehavior::RevokeOnLock) => "Locking the desktop ends managed access",
            Choice::Lock(_) => "Work continues while the desktop is locked",
            Choice::Existing(ExistingConnectionsMode::Strict) => {
                "Close connections Heimdall owns at the deadline"
            }
            Choice::Existing(_) => "Let existing sessions stay connected at the deadline",
            Choice::Multiplexing(MultiplexingMode::OwnedMasters) => {
                "Keep one shared connection per destination"
            }
            Choice::Multiplexing(_) => "Keep no shared connection",
        }
    }

    /// The action, for a choice that needs no typed value.
    fn action(self, row: &SettingRow) -> Option<SettingAction> {
        let policy = match row {
            SettingRow::Policy { id } => PolicyId::parse(id).ok(),
            _ => None,
        };
        Some(match self {
            Choice::SetDefault => return None,
            Choice::ClearDefault => SettingAction::DefaultProfile { profile: None },
            Choice::Pause => SettingAction::Pause { policy: policy? },
            Choice::Resume => SettingAction::Resume { policy: policy? },
            Choice::ClearCutoff => SettingAction::ClearCutoff { policy: policy? },
            Choice::Lock(behavior) => SettingAction::LockBehavior {
                policy: policy?,
                behavior,
            },
            Choice::Existing(e) => SettingAction::ConnectionPolicy {
                policy: policy?,
                existing: Some(e),
                multiplexing: None,
            },
            Choice::Multiplexing(m) => SettingAction::ConnectionPolicy {
                policy: policy?,
                existing: None,
                multiplexing: Some(m),
            },
        })
    }

    /// Whether choosing it widens (shown beside it).
    fn widens(self) -> bool {
        matches!(
            self,
            Choice::Resume
                | Choice::ClearCutoff
                | Choice::Lock(LockBehavior::Continue)
                | Choice::Existing(ExistingConnectionsMode::Graceful)
                | Choice::Multiplexing(MultiplexingMode::OwnedMasters)
        )
    }
}

/// What `row` offers: the changes with a CLI-equivalent request, or `Err` with the CLI
/// command when it is read-only here.
pub(crate) fn choices(catalog: &Catalog, row: &SettingRow) -> Result<Vec<Choice>, String> {
    match row {
        SettingRow::DefaultProfile { own: true, profile, .. } => {
            let mut out = vec![Choice::SetDefault];
            if profile.is_some() {
                out.push(Choice::ClearDefault);
            }
            Ok(out)
        }
        SettingRow::DefaultProfile {
            own: false,
            profile,
            ..
        } => Err(format!(
            "read-only here: another environment's default; in that environment run `heimdall access default-profile {}`",
            profile.as_deref().unwrap_or("<profile>")
        )),
        SettingRow::Policy { id } => {
            let Some(p) = catalog.m05.policy(id) else {
                return Err(format!("{id} is not in the latest listing"));
            };
            if PolicyId::parse(id).is_err() {
                return Err(format!("{id} is not a valid policy ID"));
            }
            let mut out = Vec::new();
            out.push(if p.paused_since.is_some() {
                Choice::Resume
            } else {
                Choice::Pause
            });
            if p.cutoff_at.is_some() {
                out.push(Choice::ClearCutoff);
            }
            out.extend([
                Choice::Lock(LockBehavior::RevokeOnLock),
                Choice::Lock(LockBehavior::Continue),
                Choice::Existing(ExistingConnectionsMode::Strict),
                Choice::Existing(ExistingConnectionsMode::Graceful),
                Choice::Multiplexing(MultiplexingMode::Disabled),
                Choice::Multiplexing(MultiplexingMode::OwnedMasters),
            ]);
            Ok(out)
        }
        SettingRow::Lock => Err(
            "set per standing access entry above (Enter on one), or run `heimdall access lock-behavior --policy <policy> continue|revoke-on-lock`"
                .to_owned(),
        ),
        SettingRow::Connection { .. } => Err(
            "set per standing access entry above (Enter on one), or run `heimdall access connection-policy --policy <policy> --existing strict|graceful`"
                .to_owned(),
        ),
    }
}

/// The longest value typed into a Settings prompt.
const MAX_VALUE: usize = 64;

/// Where a Settings prompt stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettingPhase {
    /// Choosing one of the row's changes.
    Choose,
    /// Typing the value the chosen change needs (a profile ID).
    Value,
    /// Confirming the exact action with a typed yes.
    Confirm(SettingAction),
}

/// The change prompt of a Settings row (drawn inside the Settings view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SettingPrompt {
    /// The row it changes.
    pub row: SettingRow,
    /// What the row offers.
    pub choices: Vec<Choice>,
    /// The chosen change.
    pub selected: usize,
    /// The phase.
    pub phase: SettingPhase,
    /// What was typed (a value, then the confirmation).
    pub input: String,
    /// Why the last step was refused.
    pub notice: Option<String>,
}

/// What a key did to a Settings prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettingStep {
    /// The prompt stays open.
    Stay,
    /// The prompt closes; the text is the status line.
    Close(String),
    /// The prompt closes and the action is sent.
    Send(SettingAction),
}

impl SettingPrompt {
    /// A prompt for `row` offering `choices`.
    #[must_use]
    pub(crate) fn new(row: SettingRow, choices: Vec<Choice>) -> Self {
        Self {
            row,
            choices,
            selected: 0,
            phase: SettingPhase::Choose,
            input: String::new(),
            notice: None,
        }
    }

    fn choice(&self) -> Option<Choice> {
        self.choices
            .get(self.selected.min(self.choices.len().saturating_sub(1)))
            .copied()
    }

    fn pick(&mut self) {
        let Some(choice) = self.choice() else {
            return;
        };
        self.input.clear();
        self.notice = None;
        match choice.action(&self.row) {
            Some(action) => self.phase = SettingPhase::Confirm(action),
            None => {
                if let SettingRow::DefaultProfile {
                    profile: Some(p), ..
                } = &self.row
                {
                    self.input = p.chars().take(MAX_VALUE).collect();
                }
                self.phase = SettingPhase::Value;
            }
        }
    }

    /// Fold one key in.
    pub(crate) fn key(&mut self, key: Key) -> SettingStep {
        let cancel = |what: &str| SettingStep::Close(format!("{what}: nothing was sent"));
        if matches!(key, Key::Esc | Key::CtrlC) {
            return cancel("cancelled");
        }
        match self.phase.clone() {
            SettingPhase::Choose => match key {
                Key::Up => self.selected = self.selected.saturating_sub(1),
                Key::Down => {
                    self.selected = (self.selected + 1).min(self.choices.len().saturating_sub(1));
                }
                Key::Char(c @ '1'..='9') => {
                    let i = usize::from(u8::try_from(c).unwrap_or(b'1') - b'1');
                    if i < self.choices.len() {
                        self.selected = i;
                    }
                }
                Key::Enter => self.pick(),
                Key::Char('q') => return cancel("closed"),
                _ => {}
            },
            SettingPhase::Value => match key {
                Key::Enter => match ProfileId::parse(self.input.trim()) {
                    Ok(profile) => {
                        self.input.clear();
                        self.notice = None;
                        self.phase = SettingPhase::Confirm(SettingAction::DefaultProfile {
                            profile: Some(profile),
                        });
                    }
                    Err(_) => self.notice = Some("that is not a valid profile ID".to_owned()),
                },
                Key::Backspace => {
                    self.input.pop();
                }
                Key::Char(c) if self.input.chars().count() < MAX_VALUE => self.input.push(c),
                _ => {}
            },
            SettingPhase::Confirm(action) => match key {
                Key::Enter => {
                    return if super::model::typed_yes(&self.input) {
                        SettingStep::Send(action)
                    } else {
                        cancel("not confirmed")
                    };
                }
                Key::Backspace => {
                    self.input.pop();
                }
                Key::Char(c) if self.input.chars().count() < super::model::MAX_TYPED => {
                    self.input.push(c);
                }
                _ => {}
            },
        }
        SettingStep::Stay
    }
}

/// The prompt's lines.
#[must_use]
pub(crate) fn prompt_lines(p: &SettingPrompt) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &p.phase {
        SettingPhase::Choose => {
            lines.push(bold(
                "Change (each is what the CLI sends for the same command):",
            ));
            for (i, c) in p.choices.iter().enumerate() {
                let sel = i == p.selected;
                let text = format!(
                    "{} {}. {}{}",
                    if sel { ">" } else { " " },
                    i + 1,
                    c.label(),
                    if c.widens() {
                        " (needs your decision)"
                    } else {
                        " (applies at once)"
                    }
                );
                lines.push(if sel { bold(text) } else { plain(text) });
            }
        }
        SettingPhase::Value => {
            lines.push(bold("Set the default profile"));
            lines.push(plain(format!("Profile ID: {}_", p.input)));
        }
        SettingPhase::Confirm(action) => {
            lines.push(bold(action.sentence()));
            lines.push(plain(format!("Same as: {}", action.cli())));
            lines.push(plain(format!("Type yes to confirm [y/N]: {}_", p.input)));
        }
    }
    if let Some(n) = &p.notice {
        lines.push(bold(format!("[!!] {n}")));
    }
    lines
}

/// One Settings row as a line: its marker and words.
#[must_use]
pub(crate) fn setting_row(
    catalog: &Catalog,
    now: Timestamp,
    row: &SettingRow,
) -> (&'static str, String) {
    let envs = &catalog.environments;
    match row {
        SettingRow::DefaultProfile {
            environment,
            own,
            profile,
        } => (
            if profile.is_some() { "[OK]" } else { "[ i]" },
            format!(
                "Default profile of {}{}: {}",
                envs.name_of(environment),
                if *own { "" } else { " (read-only here)" },
                profile.as_deref().unwrap_or("none set")
            ),
        ),
        SettingRow::Policy { id } => match catalog.m05.policy(id) {
            Some(p) => {
                let marker = if policy_paused(p, now) {
                    "[!!]"
                } else if p.cutoff_at.is_some() {
                    "[ i]"
                } else {
                    "[OK]"
                };
                let state = match (p.paused_since, p.cutoff_at) {
                    (Some(since), _) => format!("paused since {}", hms(since)),
                    (None, Some(at)) if at <= now => format!("stopped by a cutoff at {}", hms(at)),
                    (None, Some(at)) => format!("automatic until a cutoff at {}", hms(at)),
                    (None, None) => "automatic".to_owned(),
                };
                (
                    marker,
                    format!(
                        "{} · profile {} · {} · {state}",
                        p.id,
                        p.profile,
                        match &p.workspace_id {
                            Some(_) => "project",
                            None => "personal",
                        }
                    ),
                )
            }
            None => ("[??]", format!("{id}: not listed")),
        },
        SettingRow::Lock => {
            let line = lock_line(catalog, false);
            let words = line.trim_start_matches("Desktop lock: ").to_owned();
            ("[ i]", format!("Now: {words} (read-only here)"))
        }
        SettingRow::Connection { alias } => {
            let wording = catalog
                .destination(alias)
                .and_then(|d| d.preference.as_ref())
                .and_then(|p| p.policy.as_ref())
                .and_then(|p| p.wording.clone());
            (
                if wording.is_some() { "[ i]" } else { "[??]" },
                format!(
                    "{alias}: {} (read-only here)",
                    wording.map_or_else(|| "not reported by the runtime".to_owned(), |w| clean(&w))
                ),
            )
        }
    }
}

/// The selected Settings row's detail: where each value came from and how fresh it is.
#[must_use]
pub(crate) fn setting_detail(
    catalog: &Catalog,
    row: &SettingRow,
    read: &str,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match row {
        SettingRow::DefaultProfile { own, .. } => {
            lines.push(plain(format!(
                "Source: inspect policies (default_profiles), read {read}. A preference, never authority: only new requests that name no profile read it."
            )));
            lines.push(plain(if *own {
                "Change: Enter (the same request as `heimdall access default-profile`)"
            } else {
                "Change: only from that environment"
            }));
        }
        SettingRow::Policy { id } => {
            lines.push(plain(format!(
                "Source: inspect policies (the runtime's record of {id}), read {read}"
            )));
            if let Some(p) = catalog.m05.policy(id) {
                lines.push(plain(format!(
                    "  Environments: {}",
                    p.environments
                        .iter()
                        .map(|e| catalog.environments.name_of(e))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
                lines.push(plain(format!(
                    "  Revision {} · {}",
                    p.revision,
                    policy_state_words(p)
                )));
            }
            lines.push(plain(
                "Change: Enter (pause, resume, lock behaviour, connections; narrowing applies at once, widening asks for your decision)",
            ));
        }
        SettingRow::Lock => {
            lines.push(plain(format!(
                "Source: inspect capabilities (the runtime's lock report), read {read}"
            )));
            if let Some(l) = &catalog.m03.lock {
                lines.push(plain(match l.acknowledged_at {
                    Some(at) => format!("  Its disclosure was acknowledged {}", hms(at)),
                    None => "  Its disclosure has not been acknowledged yet".to_owned(),
                }));
            }
        }
        SettingRow::Connection { alias } => {
            lines.push(plain(format!(
                "Source: inspect destinations (the pair's effective connection policy, as the runtime words it), read {read}"
            )));
            lines.push(plain(format!("  Destination {alias}")));
        }
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod fixtures {
    use heimdall_contract::environment::{
        DistributionGuid, EnvironmentKindView, EnvironmentState, EnvironmentView, EnvironmentsView,
        HelperState, RealizationView, WslMode,
    };
    use heimdall_contract::ids::EnvironmentId;

    use crate::tui::data::Identity;
    use crate::tui::m03::{LockReport, PolicyReport, Preference, Projection};
    use crate::tui::m05::fixtures::{ENV, extend_decision, trust_decision, trusted_listings};
    use crate::tui::model::App;
    use crate::tui::model::tests::{populated, t};

    /// The working directory of the fixture workspace.
    pub(crate) const CWD: &str = "/work/example";
    /// A WSL distribution's and a container's environment IDs.
    pub(crate) const WSL: &str = "env_33333333333333333333333333333333";
    pub(crate) const CONTAINER: &str = "env_44444444444444444444444444444444";

    /// `inspect environments` as the runtime serializes it (`EnvironmentsView` plus the
    /// own-environment keys): this computer first, a stopped WSL distribution, a removed
    /// container.
    pub(crate) fn environments_data() -> serde_json::Value {
        let view = EnvironmentsView {
            items: vec![
                EnvironmentView {
                    environment_id: EnvironmentId::parse(ENV).unwrap(),
                    kind: EnvironmentKindView::NativeSession,
                    label: None,
                    state: EnvironmentState::Active,
                    realization: RealizationView::Native,
                },
                EnvironmentView {
                    environment_id: EnvironmentId::parse(WSL).unwrap(),
                    kind: EnvironmentKindView::WslDistribution,
                    label: None,
                    state: EnvironmentState::NotRunning,
                    realization: RealizationView::Wsl {
                        name: "Ubuntu".to_owned(),
                        guid: DistributionGuid::parse("0a1b2c3d-0000-4000-8000-00000000abcd")
                            .unwrap(),
                        account: "dev".to_owned(),
                        modes: vec![WslMode::A, WslMode::B],
                        helper: Some(HelperState::Stopped),
                    },
                },
                EnvironmentView {
                    environment_id: EnvironmentId::parse(CONTAINER).unwrap(),
                    kind: EnvironmentKindView::Container,
                    label: Some("builder".to_owned()),
                    state: EnvironmentState::Removed,
                    realization: RealizationView::Container {
                        label: "builder".to_owned(),
                        directory: "/scratch/rt/c/0123456789abcdef/".to_owned(),
                        in_container_path: "/run/heimdall".to_owned(),
                    },
                },
            ],
        };
        let mut data = serde_json::to_value(view).unwrap();
        data["environment_id"] = serde_json::json!(ENV);
        data["enrolled"] = serde_json::json!(true);
        data
    }

    fn identity(n: u8, noninteractive: Option<bool>) -> Identity {
        Identity {
            id: format!("idn_k{n}"),
            fingerprint: format!("SHA256:fixtureKey{n}"),
            key_type: Some("ssh-ed25519".to_owned()),
            mechanism: Some("native_agent".to_owned()),
            endpoint: Some("/scratch/agent.sock".to_owned()),
            interaction: "unknown".to_owned(),
            basis: Some("inferred".to_owned()),
            declared_at: None,
            declaration_expires_at: None,
            noninteractive,
            checked_at: Some(t("2026-11-03T09:00:25Z")),
        }
    }

    /// The populated state plus what the M07 views read: the environments, a trusted
    /// workspace with two policies (one paused, the personal default), the lock report
    /// (`continue`), a pending first trust and scope extension for the workspace, three
    /// identities, and the managed destination's connection policy.
    pub(crate) fn app() -> App {
        let mut app = populated();
        let c = app.catalog_mut();
        c.environments = super::Environments::of(&environments_data());
        c.m05 = trusted_listings(CWD);
        c.m03.lock = Some(LockReport {
            behavior: "continue".to_owned(),
            disclosure: Some(
                "Locking your desktop does not end access that Heimdall already issued.".to_owned(),
            ),
            acknowledged_at: None,
        });
        c.decisions = vec![
            trust_decision("dec_trust1", CWD, Some("Example project"), true, true),
            extend_decision("dec_ext1", "pol-ws1"),
        ];
        c.identities.push(identity(2, Some(false)));
        c.identities.push(identity(3, None));
        if let Some(d) = c.destinations.iter_mut().find(|d| d.alias == "alpha") {
            d.preference = Some(Preference {
                mechanism: "managed_certificate".to_owned(),
                projection: Some(Projection::Applied(Some(3))),
                policy: Some(PolicyReport {
                    existing: None,
                    multiplexing: None,
                    wording: Some(
                        "existing sessions may stay connected after the deadline".to_owned(),
                    ),
                }),
            });
        }
        app
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::fixtures::{CWD, WSL};
    use super::*;
    use crate::tui::keys::Key;
    use crate::tui::m05::fixtures::ENV;
    use crate::tui::model::tests::{press, read, type_text};
    use crate::tui::model::{Command, Effect, Modal, Outcome, Screen, Tab, Update};
    use heimdall_contract::request::Verdict;

    fn worker(effects: &[Effect]) -> Vec<Command> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Worker(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    fn rid() -> RequestId {
        RequestId::parse("req-1").unwrap()
    }

    fn wire(r: &Request) -> serde_json::Value {
        serde_json::to_value(r).unwrap()
    }

    /// `inspect environments` reads back from the runtime's own serialization: the own
    /// environment first and named "this computer", every published field kept.
    #[test]
    fn environments_read_back_from_the_published_view() {
        let envs = Environments::of(&fixtures::environments_data());
        assert_eq!(envs.own.as_deref(), Some(ENV));
        assert_eq!(envs.items.len(), 3);
        assert_eq!(envs.own_environment().unwrap().name(true), "this computer");
        assert_eq!(envs.name_of(WSL), "WSL Ubuntu");
        let wsl = &envs.items[1];
        assert_eq!(wsl.state_class(), ("[ !]", "not running".to_owned()));
        let fields: Vec<String> = wsl
            .realization
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        for expected in [
            "realized as=wsl",
            "name=Ubuntu",
            "account=dev",
            "helper=stopped",
            "modes=a, b",
        ] {
            assert!(
                fields.iter().any(|f| f == expected),
                "{expected}: {fields:?}"
            );
        }
        assert_eq!(envs.items[2].state_class().0, "[--]");
        // Not read (an older runtime, or before the first refresh): nothing invented.
        assert_eq!(
            Environments::of(&serde_json::Value::Null),
            Environments::default()
        );
    }

    /// m07-plan U1 `tui_actions_send_the_cli_requests`: every TUI action that sends a
    /// request builds exactly the request the CLI builds for the same command. Each
    /// command is produced by real key sequences in the model, turned into its request
    /// by the worker's own functions, and compared with the CLI's builder where the TUI
    /// can reach it (`m03_cmd::lock_behavior_action`, `m03_cmd::connection_policy_action`,
    /// `setup_cmd::repair_intent`); where the CLI builds the request inline (`access
    /// pause|resume|cutoff --clear`, `access default-profile`, `decision approve|deny`,
    /// `operation cancel`, `setup repair`'s submission), with the request its documented
    /// semantics name, field by field on the wire.
    #[test]
    fn tui_actions_send_the_cli_requests() {
        use crate::cli::{
            ConnectionPolicyArgs, ExistingArg, LockBehaviorArg, LockBehaviorArgs, MultiplexingArg,
            RepairArgs,
        };
        use crate::tui::worker::{
            cancel_request, decide_request, preview_repair_request, submit_repair_request,
        };

        // ---- Settings, from the keys ----
        // Settings rows of the fixture: own default, pol-ws1, pol-per1 (paused), lock, alpha.
        let base = fixtures::app();
        let setting = |row: usize, choice: usize, value: Option<&str>| -> SettingAction {
            let mut app = base.clone();
            press(&mut app, &[Key::Char('8')]);
            app.selected[Tab::Settings.index()] = row;
            press(&mut app, &[Key::Enter]);
            assert!(app.settings.is_some(), "row {row} opens a prompt");
            for _ in 0..choice {
                press(&mut app, &[Key::Down]);
            }
            press(&mut app, &[Key::Enter]);
            if let Some(v) = value {
                for _ in 0..16 {
                    press(&mut app, &[Key::Backspace]);
                }
                type_text(&mut app, v);
                press(&mut app, &[Key::Enter]);
            }
            type_text(&mut app, "yes");
            let sent = worker(&press(&mut app, &[Key::Enter]));
            match sent.as_slice() {
                [Command::Setting(a)] => a.clone(),
                other => panic!("row {row} choice {choice}: {other:?}"),
            }
        };
        let policy = PolicyId::parse("pol-ws1").unwrap();
        // Lock behaviour (choices 1 and 2 of an active policy: after Pause).
        for (choice, arg) in [
            (1, LockBehaviorArg::RevokeOnLock),
            (2, LockBehaviorArg::Continue),
        ] {
            let action = setting(1, choice, None);
            let cli = crate::m03_cmd::lock_behavior_action(&LockBehaviorArgs {
                policy: "pol-ws1".to_owned(),
                behavior: arg,
            })
            .ok()
            .unwrap();
            assert_eq!(
                action.request(rid()),
                Request::Policy(cli.clone()),
                "{arg:?}"
            );
            assert_eq!(action.attends(), cli.is_widening(), "{arg:?}");
            assert_eq!(
                action.cli().split_whitespace().nth(2),
                Some("lock-behavior")
            );
        }
        // Connection policy (choices 3–6).
        for (choice, existing, multiplexing) in [
            (3, Some(ExistingArg::Strict), None),
            (4, Some(ExistingArg::Graceful), None),
            (5, None, Some(MultiplexingArg::Disabled)),
            (6, None, Some(MultiplexingArg::Owned)),
        ] {
            let action = setting(1, choice, None);
            let cli = crate::m03_cmd::connection_policy_action(&ConnectionPolicyArgs {
                policy: "pol-ws1".to_owned(),
                existing,
                multiplexing,
            })
            .ok()
            .unwrap();
            assert_eq!(
                action.request(rid()),
                Request::Policy(cli.clone()),
                "{choice}"
            );
            assert_eq!(action.attends(), cli.is_widening(), "{choice}");
        }
        // Pause (an active policy) and resume (the paused one): `access pause|resume
        // <policy>`, the policy-ID form (`cli::access`); pause never attends, resume does
        // (`cli::policy_flow`).
        let pause = setting(1, 0, None);
        assert_eq!(
            pause,
            SettingAction::Pause {
                policy: policy.clone()
            }
        );
        assert_eq!(
            wire(&pause.request(rid())),
            serde_json::json!({"op": "policy", "action": "pause", "policy_id": "pol-ws1"})
        );
        assert!(!pause.attends());
        let resume = setting(2, 0, None);
        assert_eq!(
            wire(&resume.request(rid())),
            serde_json::json!({"op": "policy", "action": "resume", "policy_id": "pol-per1"})
        );
        assert!(resume.attends());
        // `access cutoff <policy> --clear`.
        let clear = SettingAction::ClearCutoff {
            policy: policy.clone(),
        };
        assert_eq!(
            wire(&clear.request(rid())),
            serde_json::json!({"op": "policy", "action": "clear_cutoff", "policy_id": "pol-ws1"})
        );
        assert!(clear.attends());
        // `access default-profile <profile>` and `--clear` (`m05_cmd::default_profile_flow`:
        // the runtime's own environment, the request ID, never attended).
        let set = setting(0, 0, Some("ops"));
        assert_eq!(
            wire(&set.request(rid())),
            serde_json::json!({"op": "catalog", "action": "set_default_profile", "profile": "ops", "request_id": "req-1"})
        );
        assert!(!set.attends());
        let cleared = setting(0, 1, None);
        assert_eq!(
            wire(&cleared.request(rid())),
            serde_json::json!({"op": "catalog", "action": "set_default_profile", "profile": null, "request_id": "req-1"})
        );

        // ---- Decide, from the decision modal (`decision approve|deny <id>`) ----
        let mut app = base.clone();
        press(&mut app, &[Key::Char('4'), Key::Enter]);
        read(&app);
        press(&mut app, &[Key::End]);
        read(&app);
        type_text(&mut app, "yes");
        let sent = worker(&press(&mut app, &[Key::Enter]));
        let Some(Command::Decide { id, verdict }) = sent.first() else {
            panic!("{sent:?}");
        };
        assert_eq!(
            wire(&decide_request(id, *verdict).unwrap()),
            serde_json::json!({"op": "decide", "decision_id": "dec_trust1", "verdict": "approve"})
        );
        assert_eq!(decide_request("not an id", Verdict::Deny), None);

        // ---- Cancel, from the operation detail (`operation cancel <id>`) ----
        let mut app = base.clone();
        press(&mut app, &[Key::Char('1')]);
        let at = app
            .overview_items()
            .iter()
            .position(|i| matches!(i, crate::tui::model::Item::Working { .. }))
            .unwrap();
        app.selected[0] = at;
        press(&mut app, &[Key::Enter]);
        let sent = worker(&press(&mut app, &[Key::Char('x')]));
        let Some(Command::Cancel { id }) = sent.first() else {
            panic!("{sent:?}");
        };
        assert_eq!(
            wire(&cancel_request(id).unwrap()),
            serde_json::json!({"op": "cancel", "operation_id": "op_run1"})
        );

        // ---- A held repair: the preview is `setup repair --operation <id> retry|keep`
        // (the CLI's own `repair_intent`), the submission `setup repair`'s effect request.
        let mut app = base.clone();
        press(&mut app, &[Key::Char('1')]);
        app.selected[0] = 0;
        for (key, word, resolution) in [
            (
                'r',
                "retry",
                heimdall_contract::setup::RepairResolution::RetryHeld,
            ),
            (
                'k',
                "keep",
                heimdall_contract::setup::RepairResolution::KeepHeld,
            ),
        ] {
            let mut a = app.clone();
            let sent = worker(&press(&mut a, &[Key::Char(key)]));
            let Some(Command::PreviewRepair { operation, .. }) = sent.first() else {
                panic!("{sent:?}");
            };
            let cli = crate::setup_cmd::repair_intent(&RepairArgs {
                operation: Some(operation.clone()),
                args: vec![word.to_owned()],
                request_id: None,
            })
            .ok()
            .unwrap();
            let tui = preview_repair_request(
                heimdall_contract::ids::OperationId::parse(operation).unwrap(),
                resolution,
            );
            assert_eq!(
                tui,
                Request::Setup(heimdall_contract::setup::SetupRequest::Preview { intent: cli })
            );
        }
        let digest = heimdall_contract::setup::PlanDigest::parse(&"a".repeat(64)).unwrap();
        assert_eq!(
            wire(&submit_repair_request(digest, rid())),
            serde_json::json!({"op": "setup", "action": "repair", "plan_digest": "a".repeat(64), "request_id": "req-1"})
        );
        // The stop menu's four actions are `StopAction::request`, compared with the CLI's
        // requests in `m05::tests::each_stop_action_is_the_cli_request`.
    }

    /// Settings change only through those requests: a narrowing is sent after a typed yes
    /// and applies at once; a widening is sent the same way, and the decision the runtime
    /// answers with opens in the existing decision modal. Anything but yes sends nothing;
    /// a read-only row names its CLI command.
    #[test]
    fn settings_narrow_at_once_and_widen_through_the_decision_modal() {
        let mut app = fixtures::app();
        press(&mut app, &[Key::Char('8')]);
        assert_eq!(app.screen, Screen::Tab(Tab::Settings));
        // A narrowing: pause pol-ws1.
        app.selected[Tab::Settings.index()] = 1;
        press(&mut app, &[Key::Enter, Key::Enter]);
        type_text(&mut app, "no");
        assert!(
            worker(&press(&mut app, &[Key::Enter])).is_empty(),
            "no is No"
        );
        assert!(app.settings.is_none());
        press(&mut app, &[Key::Enter, Key::Enter]);
        type_text(&mut app, "yes");
        let sent = worker(&press(&mut app, &[Key::Enter]));
        assert!(matches!(
            sent.as_slice(),
            [Command::Setting(SettingAction::Pause { .. })]
        ));
        // A widening: resume pol-per1; the runtime answers with a decision, which opens
        // in the decision modal once listed.
        app.selected[Tab::Settings.index()] = 2;
        press(&mut app, &[Key::Enter, Key::Enter]);
        type_text(&mut app, "yes");
        let sent = worker(&press(&mut app, &[Key::Enter]));
        assert!(matches!(
            sent.as_slice(),
            [Command::Setting(SettingAction::Resume { .. })]
        ));
        app.apply(Update::Done {
            what: "resume pol-per1".to_owned(),
            outcome: Outcome {
                ok: false,
                code: "DECISION_REQUIRED".to_owned(),
                message: "needs your decision".to_owned(),
                decision_ref: Some("dec_resume1".to_owned()),
            },
        });
        let mut listed = app.catalog().clone();
        let mut d = crate::tui::m05::fixtures::decision(
            "dec_resume1",
            "widen_policy",
            serde_json::json!({"action": {"action": "resume", "policy_id": "pol-per1"}}),
        );
        d.expires_at = Some(crate::tui::model::tests::t("2026-11-03T09:30:00Z"));
        listed.decisions.push(d);
        app.apply(Update::Catalog(Box::new(listed)));
        assert!(
            matches!(&app.modal, Some(Modal::Decision(p)) if p.id == "dec_resume1"),
            "{:?}",
            app.modal
        );
        // A read-only row: no prompt, its CLI command on the status line.
        let mut app = fixtures::app();
        press(&mut app, &[Key::Char('8')]);
        let lock = app
            .setting_rows()
            .iter()
            .position(|r| *r == SettingRow::Lock)
            .unwrap();
        app.selected[Tab::Settings.index()] = lock;
        assert!(press(&mut app, &[Key::Enter]).is_empty());
        assert!(app.settings.is_none());
        assert!(
            app.status
                .as_deref()
                .is_some_and(|s| s.contains("heimdall access lock-behavior")),
            "{:?}",
            app.status
        );
        // The overview's environment and access lines read the same listings.
        let c = app.catalog();
        assert_eq!(
            environment_line(c, false),
            "Environment: this computer (native session) · 1 running"
        );
        assert_eq!(
            access_line(c, app.now(), false),
            "Access: this computer uses dev automatically"
        );
        let _ = CWD;
    }
}
