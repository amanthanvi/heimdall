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
//! worker's `Sent` carries its `decision_ref`). Every change is confirmed with a typed
//! `yes` first, default No. A setting with no CLI-equivalent request is shown read-only
//! with its CLI command.
//!
//! **A change is sent only when the owner saw it** (M07-W0-R01). The confirmation names
//! the action, its exact effect and its target ([`confirm_lines`]) and sits behind the
//! reading guard of the decision modal: the view reports what each frame drew
//! ([`SettingPrompt::seen`], the marker the stop menu's confirmation shares:
//! [`super::model::Seen`]), and a typed `yes` counts only when the latest frame drew the
//! prompt with a window of that content and the frames so far have drawn every row of it
//! ([`SettingPrompt::unseen`]). Keys handled before any frame, a frame a modal covered,
//! and a terminal too small for the confirmation confirm nothing, and the status line
//! says why.
//!
//! **A value is stated only for a listing that was read** (M07-W0-R03, `Catalog::known`):
//! otherwise the lines here say what is not known, or mark the last good value stale.
//!
//! **Lock wording states only what the runtime attests** (M07-W0-R04): a saved setting of
//! personal access ([`lock_line`]), never an outcome, and the runtime's own qualified
//! statement in its words ([`lock_screen_lines`]).
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

use super::data::{Catalog, Known, clean, items, subject, text};
use super::keys::Key;
use super::model::Seen;

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
    let known = catalog.known(&[subject::POLICIES]);
    if let Some(why) = unread_note(catalog, subject::POLICIES) {
        lines.push(plain(format!("  {why}")));
    } else if catalog.m05.policies.is_none() {
        lines.push(plain("  not listed by this runtime"));
    } else if policies.is_empty() {
        lines.push(plain(format!(
            "  none{}: requests from it ask you each time",
            known.suffix()
        )));
    }
    for p in policies {
        lines.push(plain(format!(
            "  {} · profile {} · {}{}",
            p.id,
            p.profile,
            policy_state_words(p),
            known.suffix()
        )));
    }
    if let Some((_, profile)) = catalog.m05.default_profiles.iter().find(|(e, _)| e == id) {
        lines.push(plain(format!(
            "Default profile: {profile}{} (a preference, never authority)",
            known.suffix()
        )));
    }
    lines
}

/// ⟨M07⟩ M07-W0-R03: what to say in place of a value from listing `subject` when it has
/// never been read (its read failed with nothing read before): what is not known and
/// why. `None` when it was read (its value, fresh or stale, can be shown).
#[must_use]
pub(crate) fn unread_note(catalog: &Catalog, subject: &str) -> Option<String> {
    let f = catalog
        .failure(subject)
        .filter(|f| f.stale_from.is_none())?;
    Some(format!(
        "not known: the {} could not be read ({})",
        subject_words(subject),
        f.code
    ))
}

/// ⟨M07⟩ A listing in words, for the lines that say it could not be read.
#[must_use]
pub(crate) fn subject_words(name: &str) -> String {
    match name {
        subject::DESTINATIONS => "destination list".to_owned(),
        subject::PROFILES => "profile list".to_owned(),
        subject::IDENTITIES => "identity list".to_owned(),
        subject::OPERATIONS => "operation list".to_owned(),
        subject::DECISIONS => "decision list".to_owned(),
        subject::ENROLLMENTS => "enrollment list".to_owned(),
        subject::CONNECTIONS => "connection list".to_owned(),
        subject::CAPABILITIES => "lock setting".to_owned(),
        subject::ENVIRONMENTS => "environment list".to_owned(),
        subject::POLICIES => "standing access list".to_owned(),
        subject::WORKSPACE => "project status".to_owned(),
        "projections" => "setup state".to_owned(),
        other => format!("{} list", spaced(other)),
    }
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
    // ⟨M07⟩ M07-W0-R03: a project status or a policy list that could not be read is said
    // so, above what the last good read (if any) showed.
    for name in [subject::WORKSPACE, subject::POLICIES] {
        if let Some(f) = catalog.failure(name) {
            lines.insert(
                0,
                bold(format!(
                    "[!!] The {} could not be read ({}): {}",
                    subject_words(name),
                    f.code,
                    if f.stale_from.is_some() {
                        "what follows is the last good read and may have changed"
                    } else {
                        "nothing is known about it yet"
                    }
                )),
            );
        }
    }
    let known = catalog.known(&[subject::POLICIES]);
    lines.push(plain(""));
    lines.push(bold(format!("Standing access{}", known.suffix())));
    match &catalog.m05.policies {
        None => lines.push(plain(match unread_note(catalog, subject::POLICIES) {
            Some(why) => format!("  {why}"),
            None => "  not listed by this runtime".to_owned(),
        })),
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
///
/// ⟨M07⟩ M07-W0-R03: "no work running" and the counts are claims of the operation and
/// connection lists. When one of them was never read the line says the work is not known;
/// when its latest read failed the counts are marked stale.
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
    let known = catalog.known(&[subject::OPERATIONS, subject::CONNECTIONS]);
    let work = match (known, running, connections) {
        (Known::Unread, _, _) if narrow => "work not known".to_owned(),
        (Known::Unread, _, _) => {
            "what is running is not known (the lists could not be read)".to_owned()
        }
        (_, 0, 0) => "no work running".to_owned(),
        (_, r, 0) => format!("{r} running"),
        (_, 0, c) => format!("{c} connection(s) open"),
        (_, r, c) => format!("{r} running, {c} connection(s) open"),
    };
    let label = if narrow { "Here" } else { "Environment" };
    let line = format!("{label}: {name} · {work}{}", known.suffix());
    if narrow && line.chars().count() > 40 {
        // The stale mark is never the part that is cut.
        return format!("{label}: {name} · work stale");
    }
    line
}

/// The overview's configured access, with project policies scoped to their projects.
/// Unread and stale listings are disclosed separately from the access summary.
#[must_use]
pub(crate) fn access_line(catalog: &Catalog, now: Timestamp, narrow: bool) -> String {
    let envs = &catalog.environments;
    let who = envs
        .own_environment()
        .map_or_else(|| "this environment".to_owned(), |e| e.name(true));
    let known = catalog.known(&[subject::POLICIES]);
    let Some(policies) = &catalog.m05.policies else {
        return match (known, narrow) {
            (Known::Unread, true) => "Access: not known (not read)".to_owned(),
            (Known::Unread, false) => {
                format!("Access: {who}'s standing access is not known (it could not be read)")
            }
            (_, true) => "Access: not listed".to_owned(),
            (_, false) => {
                format!("Access: {who}'s standing access is not listed by this runtime")
            }
        };
    };
    let current_project = catalog
        .m05
        .workspace
        .as_ref()
        .filter(|w| {
            matches!(
                w.matched,
                super::m05::Match::Trusted | super::m05::Match::Member
            )
        })
        .and_then(|w| w.workspace_id.as_deref());
    let scope = |project: Option<&str>| match project {
        Some(id) if Some(id) == current_project => " in this project".to_owned(),
        Some(id) => format!(" in project {id}"),
        None => String::new(),
    };
    let mut automatic = Vec::new();
    let mut paused = Vec::new();
    for p in policies.iter().filter(|p| {
        envs.own
            .as_deref()
            .is_none_or(|own| p.environments.iter().any(|e| e == own))
    }) {
        let list = if policy_paused(p, now) {
            &mut paused
        } else {
            &mut automatic
        };
        let entry = (p.profile.as_str(), p.workspace_id.as_deref());
        if !list.contains(&entry) {
            list.push(entry);
        }
    }
    paused.retain(|p| !automatic.contains(p));
    let paused_words = if paused.is_empty() {
        String::new()
    } else {
        let names: Vec<_> = paused
            .iter()
            .map(|(profile, project)| format!("{profile}{}", scope(*project)))
            .collect();
        format!("; paused: {}", names.join(", "))
    };
    let auto = if narrow { "auto" } else { "automatically" };
    let configured: Vec<_> = automatic
        .iter()
        .map(|(profile, project)| format!("{profile} {auto}{}", scope(*project)))
        .collect();
    let line = match (automatic.is_empty(), narrow) {
        (false, false) => format!("Access: {who} uses {}", configured.join(", ")),
        (false, true) => format!("Access: {}", configured.join(", ")),
        (true, false) if paused.is_empty() => {
            format!("Access: {who} has no standing access; each request asks you")
        }
        (true, false) => format!("Access: {who} has no automatic access now"),
        (true, true) => "Access: none automatic".to_owned(),
    };
    let full = format!("{line}{paused_words}{}", known.suffix());
    if !narrow || Line::raw(full.as_str()).width() <= 40 {
        return full;
    }
    if known == Known::Stale {
        return "Access: stale (not read again)".to_owned();
    }
    if !automatic.is_empty() && Line::raw(line.as_str()).width() <= 40 {
        return line;
    }
    let personal = automatic
        .iter()
        .chain(&paused)
        .filter(|(_, project)| project.is_none())
        .count();
    let projects = automatic.len() + paused.len() - personal;
    format!("Access: {personal} personal, {projects} project")
}

/// ⟨M07⟩ The saved lock setting's name as the runtime's own disclosure writes it
/// (`continue`, `revoke on lock`).
fn lock_setting_name(behavior: &str) -> String {
    spaced(behavior)
}

/// The overview's lock line (narrow, it also names the stop key: one row less).
///
/// ⟨M07⟩ M07-W0-R04: it states **only what the runtime attests**, and that is a saved
/// setting: `capabilities.lock.behavior` is the strictest of the configuration and the
/// **personal** standing access of this environment (`Operations::applicable_policies`).
/// It is not an outcome. No listing this view reads carries a project policy's lock
/// setting, a verification of the lock signal or of continuity, or what a lock did to
/// running work, so the line says those are not known here and points at Settings, where
/// the runtime's own qualified statement is shown in its words ([`lock_screen_lines`]).
/// It never says that work continues or that locking ends access.
#[must_use]
pub(crate) fn lock_line(catalog: &Catalog, narrow: bool) -> String {
    let known = catalog.known(&[subject::CAPABILITIES]);
    let saved = catalog
        .m03
        .lock
        .as_ref()
        .map(|l| lock_setting_name(&l.behavior));
    match (known, saved, narrow) {
        (Known::Unread, _, false) => {
            "Desktop lock: not known (the lock setting could not be read)".to_owned()
        }
        (Known::Unread, _, true) => "Lock setting: not known · s stop".to_owned(),
        (_, None, false) => "Desktop lock: not reported by the runtime".to_owned(),
        (_, None, true) => "Lock setting: not reported · s stop".to_owned(),
        (Known::Stale, Some(s), false) => format!(
            "Desktop lock: saved personal setting \"{s}\" (stale: it could not be read again) · 8 Settings"
        ),
        (Known::Stale, Some(_), true) => "Lock setting: stale · s stop".to_owned(),
        (Known::Fresh, Some(s), false) => format!(
            "Desktop lock: saved personal setting \"{s}\" · project settings, observed effect: not known here · 8 Settings"
        ),
        (Known::Fresh, Some(s), true) => format!("Lock setting: {s} · s stop"),
    }
}

/// ⟨M07⟩ M07-W0-R04: the lock detail (Enter on the Settings lock row), readable in full at
/// any size (it wraps and scrolls). The saved setting and what is observed are separate
/// sections, and the runtime's qualified statement is `capabilities.lock.disclosure`,
/// shown in its own words and never retyped (as tui/m03.rs requires of every wording): it
/// is where the runtime says whether continuity and the lock signal are verified on this
/// computer.
#[must_use]
pub(crate) fn lock_screen_lines(catalog: &Catalog, read: &str) -> Vec<Line<'static>> {
    let known = catalog.known(&[subject::CAPABILITIES]);
    let mut lines = vec![bold("Desktop lock")];
    lines.push(plain(format!(
        "Source: the runtime's lock report (inspect capabilities), read {read}"
    )));
    if let Some(f) = catalog.failure(subject::CAPABILITIES) {
        lines.push(bold(format!(
            "[!!] It could not be read ({}): {}",
            f.code,
            if f.stale_from.is_some() {
                "what follows is the last good read and may have changed"
            } else {
                "nothing is known about it yet"
            }
        )));
    }
    let lock = catalog.m03.lock.as_ref();
    lines.push(plain(""));
    lines.push(bold(format!("Saved setting{}", known.suffix())));
    match (known, lock) {
        (Known::Unread, _) => lines.push(plain("  not known")),
        (_, None) => lines.push(plain("  not reported by the runtime")),
        (_, Some(l)) => {
            lines.push(plain(format!(
                "  \"{}\": the strictest of your configuration and your personal standing access in this environment.",
                lock_setting_name(&l.behavior)
            )));
            lines.push(plain(
                "  A project's standing access has its own setting. No listing this view reads reports it: not known here.",
            ));
            lines.push(plain(
                "  For one piece of work, the strictest setting that applies to it decides.",
            ));
        }
    }
    lines.push(plain(""));
    lines.push(bold("Observed"));
    lines.push(plain(
        "  This view has no report of what a lock did, or will do, to work that is running: not known here.",
    ));
    lines.push(plain(""));
    lines.push(bold("The runtime's statement (its own words)"));
    match lock.and_then(|l| l.disclosure.as_deref()) {
        Some(text) if known != Known::Unread => lines.push(plain(format!("  {}", clean(text)))),
        _ => lines.push(plain(
            "  The runtime sent no statement: whether work keeps going at a lock is unverified here.",
        )),
    }
    if let Some(l) = lock {
        lines.push(plain(match l.acknowledged_at {
            Some(at) => format!("  You acknowledged its disclosure {}", hms(at)),
            None => "  You have not acknowledged its disclosure yet".to_owned(),
        }));
    }
    lines.push(plain(""));
    lines.push(bold("Change it"));
    lines.push(plain(
        "  Per standing access entry: Enter on one in Settings (8), or run",
    ));
    lines.push(plain(format!("  `{LOCK_COMMAND}`")));
    lines
}

/// The CLI command that sets a policy's lock behaviour.
pub(crate) const LOCK_COMMAND: &str =
    "heimdall access lock-behavior --policy <policy> continue|revoke-on-lock";

/// ⟨M07⟩ M07-W0-R04: what a Settings confirmation of a lock change adds to its sentence:
/// that it is a saved setting of this one entry, and the runtime's own statement about
/// locking as it stands now (its words), or that it sent none.
fn lock_confirm_lines(catalog: &Catalog) -> Vec<Line<'static>> {
    let mut lines = vec![plain(
        "This saves a setting of this entry only. For one piece of work, the strictest setting that applies to it decides, and this view has no report of what a lock does to work that is running.",
    )];
    match catalog
        .m03
        .lock
        .as_ref()
        .and_then(|l| l.disclosure.as_deref())
        .filter(|_| catalog.known(&[subject::CAPABILITIES]) != Known::Unread)
    {
        Some(text) => lines.push(plain(format!(
            "The runtime's statement now (its own words): {}",
            clean(text)
        ))),
        None => lines.push(plain(
            "The runtime sent no statement: whether work keeps going at a lock is unverified here.",
        )),
    }
    lines
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
        /// ⟨M07⟩ Its index in the destinations listing (M07-W0-R06: the row is found
        /// without a search; the rows are built again whenever the listing changes).
        at: usize,
    },
}

/// The Settings view's rows, in order: default profiles, standing access, the lock
/// behaviour, each managed destination's connection policy. ⟨M07⟩ Built once per change of
/// the listings (`App::setting_rows`), never per key or per frame (M07-W0-R06).
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
    rows.extend(
        catalog
            .destinations
            .iter()
            .enumerate()
            .filter(|(_, d)| d.is_managed())
            .map(|(at, _)| SettingRow::Connection { at }),
    );
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
            // ⟨M07⟩ M07-W0-R04: a saved setting and what it is meant to do, never a
            // promise of what a lock does ([`lock_confirm_lines`] follows it).
            SettingAction::LockBehavior { policy, behavior } => match behavior {
                LockBehavior::RevokeOnLock => format!(
                    "Set the saved lock setting of {policy} to \"revoke on lock\": work under it is meant to end when you lock your desktop."
                ),
                _ => format!(
                    "Set the saved lock setting of {policy} to \"continue\": work under it is meant to keep going while your desktop is locked."
                ),
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
            Choice::Lock(LockBehavior::RevokeOnLock) => "Lock setting: revoke on lock",
            Choice::Lock(_) => "Lock setting: continue",
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
        SettingRow::Lock => Err(format!(
            "set per standing access entry above (Enter on one), or run `{LOCK_COMMAND}`"
        )),
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
    /// ⟨M07⟩ What the frames have shown of the confirmation: which of its rows they have
    /// drawn, and what the latest one showed (a fresh one for every confirmation; the
    /// marker the stop menu's confirmation shares, [`Seen`]).
    pub seen: Seen,
}

/// What a key did to a Settings prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettingStep {
    /// The prompt stays open.
    Stay,
    /// The prompt closes; the text is the status line.
    Close(String),
    /// ⟨M07⟩ A typed yes was refused because the change was not on screen: the prompt
    /// stays open and the text is the status line.
    Refused(&'static str),
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
            seen: Seen::default(),
        }
    }

    /// ⟨M07⟩ Ask for the confirmation of `action`: nothing typed, and nothing of it shown
    /// yet (what an earlier confirmation showed never counts for this one).
    fn confirm(&mut self, action: SettingAction) {
        self.input.clear();
        self.notice = None;
        self.seen = Seen::default();
        self.phase = SettingPhase::Confirm(action);
    }

    /// ⟨M07⟩ M07-W0-R01: why a typed yes cannot be accepted now, if it cannot; `frame` is
    /// the number of the latest frame. A change is sent only when the owner saw it: the
    /// latest frame drew the confirmation (its prompt and a window of its content, with
    /// no modal over it), and the frames so far have drawn every row of the content,
    /// which names the action, its target and its exact effect ([`confirm_lines`]). Keys
    /// handled before any frame (a batch) showed nothing, so they cannot confirm; a
    /// terminal too small for the confirmation cannot either ([`Seen::unseen`]).
    #[must_use]
    pub(crate) fn unseen(&self, frame: u64) -> Option<&'static str> {
        self.seen.unseen(frame)
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
            Some(action) => self.confirm(action),
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

    /// Fold one key in; `frame` is the number of the latest frame drawn.
    pub(crate) fn key(&mut self, key: Key, frame: u64) -> SettingStep {
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
                    Ok(profile) => self.confirm(SettingAction::DefaultProfile {
                        profile: Some(profile),
                    }),
                    Err(_) => self.notice = Some("that is not a valid profile ID".to_owned()),
                },
                Key::Backspace => {
                    self.input.pop();
                }
                Key::Char(c) if self.input.chars().count() < MAX_VALUE => self.input.push(c),
                _ => {}
            },
            SettingPhase::Confirm(action) => match key {
                // The content scrolls above the fixed prompt, as a decision's does.
                Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                    self.seen.reading.scroll_key(key);
                }
                Key::Enter => {
                    if !super::model::typed_yes(&self.input) {
                        return cancel("not confirmed");
                    }
                    // M07-W0-R01: never a change the owner has not seen.
                    if let Some(why) = self.unseen(frame) {
                        return SettingStep::Refused(self.seen.refuse(why, &mut self.input));
                    }
                    return SettingStep::Send(action);
                }
                Key::Backspace => {
                    self.input.pop();
                    self.seen.reading.refused = false;
                }
                Key::Char(c) if self.input.chars().count() < super::model::MAX_TYPED => {
                    self.input.push(c);
                    self.seen.reading.refused = false;
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
        // The confirmation is laid out by the view ([`confirm_lines`], [`confirm_ask`]):
        // its content scrolls above the prompt and what each frame drew is recorded.
        SettingPhase::Confirm(_) => {}
    }
    if let Some(n) = &p.notice {
        lines.push(bold(format!("[!!] {n}")));
    }
    lines
}

/// ⟨M07⟩ What a Settings confirmation asks the owner to confirm (M07-W0-R01): the action
/// and its exact effect, then its target as the latest listings describe it (which
/// standing access entry: its profile, whether it is personal or a project's, the
/// environments it covers and its state now; or which environment's default profile, and
/// whether the catalog lists the profile), then the CLI command that sends the same
/// request. The view wraps and scrolls these lines; a typed `yes` counts only once every
/// row of them has been drawn.
#[must_use]
pub(crate) fn confirm_lines(
    catalog: &Catalog,
    now: Timestamp,
    action: &SettingAction,
) -> Vec<Line<'static>> {
    let mut lines = vec![bold(action.sentence())];
    let envs = &catalog.environments;
    match action {
        SettingAction::DefaultProfile { profile } => {
            let own = envs.own.as_deref();
            lines.push(plain(format!(
                "Environment: {}{}",
                own.map_or_else(|| "this environment".to_owned(), |id| envs.name_of(id)),
                own.map_or_else(String::new, |id| format!(" ({})", clean(id)))
            )));
            let current = own.and_then(|o| {
                catalog
                    .m05
                    .default_profiles
                    .iter()
                    .find(|(e, _)| e == o)
                    .map(|(_, p)| p.as_str())
            });
            lines.push(plain(format!(
                "Default profile now: {}",
                current.unwrap_or("none listed")
            )));
            if let Some(p) = profile {
                lines.push(plain(
                    if catalog.profiles.iter().any(|q| q.id == p.as_str()) {
                        format!("Profile {p}: in your catalog")
                    } else {
                        format!("Profile {p}: not in the latest profile listing")
                    },
                ));
            }
        }
        SettingAction::Pause { policy }
        | SettingAction::Resume { policy }
        | SettingAction::ClearCutoff { policy }
        | SettingAction::LockBehavior { policy, .. }
        | SettingAction::ConnectionPolicy { policy, .. } => {
            match catalog.m05.policy(policy.as_str()) {
                Some(p) => {
                    lines.push(plain(format!(
                        "Standing access {}: profile {} · {}",
                        p.id,
                        p.profile,
                        match &p.workspace_id {
                            Some(w) => format!("project {w}"),
                            None => "personal".to_owned(),
                        }
                    )));
                    lines.push(plain(format!(
                        "Covers: {}",
                        if p.environments.is_empty() {
                            "no environment listed".to_owned()
                        } else {
                            p.environments
                                .iter()
                                .map(|e| envs.name_of(e))
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    )));
                    lines.push(plain(format!("Now: {}", policy_state(p, now))));
                }
                None => lines.push(plain(format!(
                    "Standing access {policy}: not in the latest listing"
                ))),
            }
            if matches!(action, SettingAction::LockBehavior { .. }) {
                lines.extend(lock_confirm_lines(catalog));
            }
        }
    }
    lines.push(plain(format!("Same as: {}", action.cli())));
    lines
}

/// ⟨M07⟩ The Settings confirmation's fixed prompt line, with what was typed.
#[must_use]
pub(crate) fn confirm_ask(input: &str) -> Line<'static> {
    bold(format!("Type yes to confirm [y/N]: {input}_"))
}

/// A policy's state in words, with its times.
fn policy_state(p: &super::m05::Policy, now: Timestamp) -> String {
    match (p.paused_since, p.cutoff_at) {
        (Some(since), _) => format!("paused since {}", hms(since)),
        (None, Some(at)) if at <= now => format!("stopped by a cutoff at {}", hms(at)),
        (None, Some(at)) => format!("automatic until a cutoff at {}", hms(at)),
        (None, None) => "automatic".to_owned(),
    }
}

/// One Settings row as a line: its marker and words.
///
/// ⟨M07⟩ M07-W0-R03: a value is stated only for a listing that was read. A default
/// profile whose list was never read is "not known", never "none set"; a value from a
/// read that has since failed is marked stale. M07-W0-R04: the lock row names the saved
/// setting and says what is not known, as [`lock_line`] does.
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
        } => {
            let known = catalog.known(&[subject::POLICIES]);
            // The value first, so a narrow row never cuts it off.
            let whose = format!(
                "{}{}",
                envs.name_of(environment),
                if *own { "" } else { " (read-only here)" }
            );
            match (known, profile) {
                (Known::Unread, _) => (
                    "[??]",
                    format!("Default profile: not known (not read) · {whose}"),
                ),
                (k, Some(p)) => (
                    if k == Known::Stale { "[??]" } else { "[OK]" },
                    format!("Default profile: {p}{} · {whose}", k.suffix()),
                ),
                (Known::Stale, None) => (
                    "[??]",
                    format!("Default profile: none set when last read (stale) · {whose}"),
                ),
                (Known::Fresh, None) => ("[ i]", format!("Default profile: none set · {whose}")),
            }
        }
        SettingRow::Policy { id } => match catalog.m05.policy(id) {
            Some(p) => {
                let known = catalog.known(&[subject::POLICIES]);
                let marker = if known == Known::Stale {
                    "[??]"
                } else if policy_paused(p, now) {
                    "[!!]"
                } else if p.cutoff_at.is_some() {
                    "[ i]"
                } else {
                    "[OK]"
                };
                let state = policy_state(p, now);
                (
                    marker,
                    format!(
                        "{} · profile {} · {} · {state}{}",
                        p.id,
                        p.profile,
                        match &p.workspace_id {
                            Some(_) => "project",
                            None => "personal",
                        },
                        known.suffix()
                    ),
                )
            }
            None => ("[??]", format!("{id}: not listed")),
        },
        SettingRow::Lock => {
            let known = catalog.known(&[subject::CAPABILITIES]);
            let saved = catalog
                .m03
                .lock
                .as_ref()
                .map(|l| lock_setting_name(&l.behavior));
            match (known, saved) {
                (Known::Unread, _) => (
                    "[??]",
                    "Saved: not known (it could not be read) · Enter for detail".to_owned(),
                ),
                (_, None) => (
                    "[??]",
                    "Saved: not reported by the runtime · Enter for detail".to_owned(),
                ),
                (k, Some(s)) => (
                    if k == Known::Stale { "[??]" } else { "[ i]" },
                    // The value first, so a narrow row never cuts it off.
                    format!(
                        "Saved: {s}{} (personal access) · projects, observed effect: not known here · Enter",
                        k.suffix()
                    ),
                ),
            }
        }
        SettingRow::Connection { at } => {
            let known = catalog.known(&[subject::DESTINATIONS]);
            let d = catalog.destinations.get(*at);
            let wording = d
                .and_then(|d| d.preference.as_ref())
                .and_then(|p| p.policy.as_ref())
                .and_then(|p| p.wording.as_deref());
            (
                if wording.is_some() && known == Known::Fresh {
                    "[ i]"
                } else {
                    "[??]"
                },
                format!(
                    "{}: {}{} (read-only here)",
                    d.map_or("?", |d| d.alias.as_str()),
                    wording.map_or_else(|| "not reported by the runtime".to_owned(), clean),
                    known.suffix()
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
    // ⟨M07⟩ M07-W0-R03: a source whose latest read failed says so first.
    let source_failed = |lines: &mut Vec<Line<'static>>, name: &str| {
        if let Some(f) = catalog.failure(name) {
            lines.push(bold(format!(
                "[!!] The {} could not be read ({}): {}",
                subject_words(name),
                f.code,
                if f.stale_from.is_some() {
                    "this is the last good read and may have changed"
                } else {
                    "nothing is known about it yet"
                }
            )));
        }
    };
    match row {
        SettingRow::DefaultProfile { own, .. } => {
            source_failed(&mut lines, subject::POLICIES);
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
            source_failed(&mut lines, subject::POLICIES);
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
            // ⟨M07⟩ M07-W0-R04: this listing carries no lock or connection setting.
            lines.push(plain(
                "  Its own lock and connection settings are not in this listing: not known here.",
            ));
            lines.push(plain(
                "Change: Enter (pause, resume, lock behaviour, connections; narrowing applies at once, widening asks for your decision)",
            ));
        }
        SettingRow::Lock => {
            source_failed(&mut lines, subject::CAPABILITIES);
            lines.push(plain(format!(
                "Source: inspect capabilities (the runtime's lock report), read {read}"
            )));
            lines.push(plain(
                "  A saved setting, not an observation of what a lock does. Enter: the detail, with the runtime's own statement.",
            ));
        }
        SettingRow::Connection { at } => {
            source_failed(&mut lines, subject::DESTINATIONS);
            lines.push(plain(format!(
                "Source: inspect destinations (the pair's effective connection policy, as the runtime words it), read {read}"
            )));
            lines.push(plain(format!(
                "  Destination {}",
                catalog
                    .destinations
                    .get(*at)
                    .map_or("?", |d| d.alias.as_str())
            )));
        }
    }
    lines
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod fixtures {
    use heimdall_app::lock::LockSignal;
    use heimdall_contract::environment::{
        DistributionGuid, EnvironmentKindView, EnvironmentState, EnvironmentView, EnvironmentsView,
        HelperState, RealizationView, WslMode,
    };
    use heimdall_contract::ids::EnvironmentId;
    use heimdall_contract::managed::LockBehavior;

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

    /// `capabilities.lock` as the runtime builds it: the behaviour and the disclosure
    /// text of `heimdall_app::lock::disclosure` itself (never retyped here) for a
    /// configuration floor of `floor`, no saved personal policy, continuity not verified,
    /// over `signal`.
    pub(crate) fn lock_report(floor: LockBehavior, signal: LockSignal) -> LockReport {
        let d = heimdall_app::lock::disclosure(&[], floor, false, signal);
        LockReport {
            behavior: serde_json::to_value(d.behavior)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
            disclosure: Some(d.text),
            acknowledged_at: None,
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
        c.m03.lock = Some(lock_report(
            LockBehavior::Continue,
            LockSignal::MacosScreenLock,
        ));
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
    use crate::tui::model::{
        Command, Effect, Modal, Outcome, REFUSED_NOT_DRAWN, REFUSED_TOO_SMALL, REFUSED_UNREAD,
        Screen, Tab, Update,
    };
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
            // The confirmation is drawn before it is answered (M07-W0-R01).
            read(&app);
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
        // `x` cancels what a frame has shown (m07-plan U1c).
        read(&app);
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

    /// The open Settings prompt of `app`.
    fn prompt(app: &crate::tui::model::App) -> &SettingPrompt {
        app.settings.as_ref().expect("a Settings prompt is open")
    }

    /// Settings on row `row` (of the fixture: 0 the own default profile, 1 pol-ws1,
    /// 2 pol-per1), with no frame drawn.
    fn settings_on(row: usize) -> crate::tui::model::App {
        let mut app = fixtures::app();
        press(&mut app, &[Key::Char('8')]);
        app.selected[Tab::Settings.index()] = row;
        app
    }

    /// M07-W0-R01 `settings_batched_input_cannot_confirm_before_a_frame_is_drawn`: the
    /// input loop handles a whole batch of keys before it draws, so a batch that opens a
    /// Settings prompt, picks a change and types `yes` has shown the owner nothing. It
    /// sends nothing: the prompt stays open with the answer discarded and the status line
    /// says why. The same holds for a confirmation another one's frame preceded, for a
    /// jump to the end before the first frame (the action and its target were never
    /// drawn), for a frame a modal covered, and for a target that changed after it was
    /// read. Once a frame has drawn every row, a typed yes sends exactly that change.
    #[test]
    fn settings_batched_input_cannot_confirm_before_a_frame_is_drawn() {
        use crate::tui::view::draw_once;
        let pause = || {
            [Command::Setting(SettingAction::Pause {
                policy: PolicyId::parse("pol-ws1").unwrap(),
            })]
        };
        // One batch, no frame: open, pick "Pause", yes, Enter.
        let mut app = settings_on(1);
        let batch = [
            Key::Enter,
            Key::Enter,
            Key::Char('y'),
            Key::Char('e'),
            Key::Char('s'),
            Key::Enter,
        ];
        assert_eq!(worker(&press(&mut app, &batch)), [], "nothing was drawn");
        let p = prompt(&app);
        assert!(matches!(p.phase, SettingPhase::Confirm(_)), "{p:?}");
        assert!(p.input.is_empty(), "the answer is discarded");
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));
        // The frame that follows shows the change and that the yes was refused.
        let screen = draw_once(&app, 120, 40).join(
            "
",
        );
        for shown in [
            "Pause pol-ws1",
            "Standing access pol-ws1: profile dev · project",
            "Covers: this computer",
            "Now: automatic",
            "Same as: heimdall access pause pol-ws1",
            "yes refused",
            "Type yes to confirm [y/N]: _",
            REFUSED_NOT_DRAWN,
        ] {
            assert!(screen.contains(shown), "{shown}:\n{screen}");
        }
        // Now it has been on screen: the same keys confirm it.
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), pause());
        assert!(app.settings.is_none());

        // A confirmation that was drawn does not vouch for the next one: Esc, reopen,
        // pick the second change, yes, all in one batch.
        let mut app = settings_on(1);
        press(&mut app, &[Key::Enter, Key::Enter]);
        draw_once(&app, 120, 40);
        assert_eq!(
            prompt(&app).unseen(app.frame()),
            None,
            "the first one was read"
        );
        let batch = [
            Key::Esc,
            Key::Enter,
            Key::Down,
            Key::Enter,
            Key::Char('y'),
            Key::Enter,
        ];
        assert_eq!(worker(&press(&mut app, &batch)), []);
        assert!(matches!(
            &prompt(&app).phase,
            SettingPhase::Confirm(SettingAction::LockBehavior { .. })
        ));
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));

        // At 40×12 the confirmation does not fit. A jump to the end before the first
        // frame draws its last rows only: the action and its target were never on
        // screen, so the yes is refused; so is one after the first window alone.
        let mut app = settings_on(1);
        press(&mut app, &[Key::Enter, Key::Enter, Key::End]);
        let screen = draw_once(&app, 40, 12).join("\n");
        assert!(prompt(&app).seen.reading.scrollable(), "{screen}");
        assert!(prompt(&app).seen.reading.end_shown(), "{screen}");
        assert!(!screen.contains("Pause pol-ws1"), "{screen}");
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), []);
        assert_eq!(app.status.as_deref(), Some(REFUSED_UNREAD));
        let screen = draw_once(&app, 40, 12).join("\n");
        assert!(screen.contains("yes refused"), "{screen}");
        // Read from the top, frame by frame: then it is accepted.
        press(&mut app, &[Key::Home]);
        let screen = draw_once(&app, 40, 12).join("\n");
        assert!(screen.contains("Pause pol-ws1"), "{screen}");
        assert!(screen.contains("below (PgDn)"), "{screen}");
        type_text(&mut app, "yes");
        assert_eq!(
            worker(&press(&mut app, &[Key::Enter])),
            [],
            "the first window alone"
        );
        let mut guard = 0;
        while prompt(&app).unseen(app.frame()).is_some() {
            press(&mut app, &[Key::PageDown]);
            draw_once(&app, 40, 12);
            guard += 1;
            assert!(guard < 20);
        }
        // A page key with no frame after it shows nothing new, and a resize re-wraps the
        // text: both must be drawn again.
        let screen = draw_once(&app, 44, 12).join("\n");
        assert_eq!(
            prompt(&app).unseen(app.frame()),
            Some(REFUSED_UNREAD),
            "re-wrapped"
        );
        assert!(screen.contains("read from the top (Home)"), "{screen}");
        press(&mut app, &[Key::Home]);
        draw_once(&app, 44, 12);
        let mut guard = 0;
        while prompt(&app).unseen(app.frame()).is_some() {
            press(&mut app, &[Key::PageDown]);
            draw_once(&app, 44, 12);
            guard += 1;
            assert!(guard < 20);
        }
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), pause());

        // A frame that drew a modal over the confirmation showed none of it.
        let mut app = settings_on(1);
        press(&mut app, &[Key::Enter, Key::Enter]);
        app.modal = Some(Modal::Help);
        let screen = draw_once(&app, 120, 40).join("\n");
        assert!(screen.contains("Keys"), "{screen}");
        assert_eq!(prompt(&app).unseen(app.frame()), Some(REFUSED_NOT_DRAWN));
        press(&mut app, &[Key::Esc]);
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), []);
        // And a decision the runtime just issued never opens over an open prompt.
        app.open_when_listed = Some("dec_trust1".to_owned());
        let listed = app.catalog().clone();
        app.apply(Update::Catalog(Box::new(listed)));
        assert!(app.modal.is_none(), "{:?}", app.modal);
        assert!(app.settings.is_some());

        // The target changed after it was read (the policy was paused elsewhere): what
        // the confirmation says is different now, so it is read again.
        let mut app = settings_on(1);
        press(&mut app, &[Key::Enter, Key::Enter]);
        draw_once(&app, 120, 40);
        assert_eq!(prompt(&app).unseen(app.frame()), None);
        let mut changed = app.catalog().clone();
        changed.m05.policies.as_mut().unwrap()[0].paused_since =
            Some(crate::tui::model::tests::t("2026-11-03T09:00:00Z"));
        app.apply(Update::Catalog(Box::new(changed)));
        let screen = draw_once(&app, 120, 40).join("\n");
        assert!(screen.contains("Now: paused since"), "{screen}");
        assert_eq!(
            prompt(&app).unseen(app.frame()),
            None,
            "drawn again in full"
        );
    }

    /// M07-W0-R01 `settings_short_terminal_refuses_to_submit`: at 40×5 and smaller the
    /// confirmation cannot be shown (the review saw neither the policy nor the command
    /// there). The frame says so instead of drawing a cut confirmation, a typed yes sends
    /// nothing and the status line says why; the prompt stays, and on a terminal large
    /// enough the same change is confirmed after it has been drawn.
    #[test]
    fn settings_short_terminal_refuses_to_submit() {
        use crate::tui::view::draw_once;
        for (w, h) in [
            (40, 5),
            (40, 4),
            (40, 3),
            (120, 5),
            (20, 5),
            (12, 6),
            (9, 2),
        ] {
            let mut app = settings_on(1);
            press(&mut app, &[Key::Enter, Key::Enter]);
            let screen = draw_once(&app, w, h).join("\n");
            assert!(
                !screen.contains("Type yes") && !screen.contains("[y/N]"),
                "{w}x{h}: no prompt is offered:\n{screen}"
            );
            if w >= 40 {
                assert!(
                    screen.contains("Too small to show this change"),
                    "{w}x{h}:\n{screen}"
                );
            }
            type_text(&mut app, "yes");
            // Drawn again with the answer typed, as the loop would.
            draw_once(&app, w, h);
            assert_eq!(
                worker(&press(&mut app, &[Key::Enter])),
                [],
                "{w}x{h}: nothing is sent"
            );
            let p = prompt(&app);
            assert!(matches!(p.phase, SettingPhase::Confirm(_)), "{w}x{h}");
            assert!(p.input.is_empty(), "{w}x{h}");
            // Why: the status line (the footer, wherever the frame has one).
            let why = if w < 10 || h < 3 {
                REFUSED_NOT_DRAWN
            } else {
                REFUSED_TOO_SMALL
            };
            assert_eq!(app.status.as_deref(), Some(why), "{w}x{h}");
            let screen = draw_once(&app, w, h).join("\n");
            if w >= 40 && h >= 3 {
                assert!(screen.ends_with(REFUSED_TOO_SMALL), "{w}x{h}:\n{screen}");
            }
            // Larger: drawn, then confirmed.
            let screen = draw_once(&app, 120, 40).join("\n");
            assert!(
                screen.contains("Same as: heimdall access pause pol-ws1"),
                "{screen}"
            );
            type_text(&mut app, "yes");
            assert!(
                matches!(
                    worker(&press(&mut app, &[Key::Enter])).as_slice(),
                    [Command::Setting(SettingAction::Pause { .. })]
                ),
                "{w}x{h}"
            );
        }
        // Having been drawn large does not carry to a frame that is too small: the last
        // frame is the one the owner is looking at.
        let mut app = settings_on(1);
        press(&mut app, &[Key::Enter, Key::Enter]);
        draw_once(&app, 120, 40);
        assert_eq!(prompt(&app).unseen(app.frame()), None);
        draw_once(&app, 40, 5);
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), []);
        assert_eq!(app.status.as_deref(), Some(REFUSED_TOO_SMALL));
        // Nor to a frame with no room for any view ("terminal too small"), which draws
        // no confirmation and so reports nothing: every frame is counted, and only the
        // latest one's report stands (W1s; before it the marker of the large frame
        // stayed, and this yes was sent).
        draw_once(&app, 120, 40);
        assert_eq!(prompt(&app).unseen(app.frame()), None);
        let screen = draw_once(&app, 9, 2).join("\n");
        assert!(!screen.contains("yes"), "{screen}");
        type_text(&mut app, "yes");
        assert_eq!(worker(&press(&mut app, &[Key::Enter])), []);
        assert_eq!(app.status.as_deref(), Some(REFUSED_NOT_DRAWN));
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
        read(&app);
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
        read(&app);
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
        // ⟨M07⟩ M07-W0-R04: and its detail opens (the runtime's statement in full).
        assert_eq!(app.screen, Screen::Lock);
        press(&mut app, &[Key::Esc]);
        assert_eq!(app.screen, Screen::Tab(Tab::Settings));
        // The overview's environment and access lines read the same listings.
        let c = app.catalog();
        assert_eq!(
            environment_line(c, false),
            "Environment: this computer (native session) · 1 running"
        );
        assert_eq!(
            access_line(c, app.now(), false),
            "Access: this computer uses dev automatically in this project; paused: dev"
        );
        let _ = CWD;
    }

    #[test]
    fn overview_scopes_project_access_and_summarizes_long_fresh_listings() {
        use crate::tui::view::draw_once;

        let mut app = fixtures::app();
        let now = app.now();
        let catalog = app.catalog_mut();
        catalog.m05.workspace = None;
        let workspace = crate::tui::m05::fixtures::WS;
        let policies = catalog.m05.policies.as_mut().unwrap();
        policies[1].paused_since = None;
        assert_eq!(
            access_line(catalog, now, false),
            format!(
                "Access: this computer uses dev automatically in project {workspace}, dev automatically"
            )
        );

        let policies = catalog.m05.policies.as_mut().unwrap();
        policies.truncate(1);
        assert_eq!(
            access_line(catalog, now, false),
            format!("Access: this computer uses dev automatically in project {workspace}")
        );
        assert_eq!(
            access_line(catalog, now, true),
            "Access: 0 personal, 1 project"
        );

        let policies = catalog.m05.policies.as_mut().unwrap();
        for i in 0..5 {
            let mut policy = policies[0].clone();
            policy.profile = format!("a-long-profile-name-{i}");
            policy.workspace_id = None;
            policies.push(policy);
        }
        let text = draw_once(&app, 40, 12).join("\n");
        assert!(text.contains("Access: 5 personal, 1 project"), "{text}");
    }
}
