//! ⟨M05⟩ The TUI's trusted-work views (m05-plan U9; spec §5.2, §12.3; ADR-0011 I1, I5).
//!
//! What the runtime's read-only `inspect workspace` and `inspect policies` answer carry,
//! parsed tolerantly (a field the runtime does not send reads as absent, never as a guess;
//! a runtime that does not offer `trusted-work/1` reads as "not available"), and the lines
//! the views draw from it:
//! * **workspace status** of the TUI's working directory: trusted, member, untrusted,
//!   ambiguous or none, its policy, and its pause and cutoff state ([`workspace_lines`]);
//! * **the first-trust view** (`trust_workspace`): the spec §5.2 question, then a detail view
//!   of the pairs, the environments, lock continuity and the limits ([`decision_lines`]);
//! * **the delta review** (`widen_policy{extend_scope}`): only the added authority, never
//!   the whole scope ([`decision_lines`]);
//! * **reconcile** (`reconcile_workspace`), a personal policy's creation (`create`: the
//!   scope the runtime recorded for the decision, ADR-0006 §17.10 item 22, and no Approve
//!   without it, [`approve_block`]) and a longer window (`set_max_window`), in the same
//!   readable form;
//! * **the stop menu**: pause, stop this work, stop all for a profile, and a cutoff at a
//!   time, four distinct actions with their own sentence ([`StopMenu`]);
//! * **policy history** (`inspect policies`): each revision's cause and decision
//!   ([`policy_history_lines`]).
//!
//! **Nothing here authorizes anything** (ADR-0011 I1). An approval is the existing attended
//! `decide` of the record shown (the decision modal; the typed `yes` after the last row has
//! been on screen), so the TUI never builds a widening. The stop menu only narrows: each of
//! its actions is the request the CLI sends for the same command ([`StopAction::request`]).
//! ⟨M07⟩ Its actions are persistent changes all the same, so each is sent only after a
//! typed `yes` to a confirmation the frames have drawn in full and the latest frame drew
//! ([`StopMenu::unseen`]; M07-W0-R01's rule for a Settings change).
//!
//! **Repository text is quoted, bounded data** (ADR-0011 I5): the manifest's project label
//! appears in the first-trust view as one quoted line of its own ([`quoted`]); it is never a
//! title, never part of the question and never an action. Every string of the runtime passes
//! through [`safe`], which also drops the bidirectional and invisible formatting characters
//! that [`clean`] leaves, so a label can neither run a control sequence nor reorder the text
//! around it.

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{ProfileId, RequestId, WorkId, WorkspaceId};
use heimdall_contract::request::{PolicyAction, Request, RevokeRequest};
use heimdall_contract::trust::{PolicyTarget, RevokeTarget};
use heimdall_domain::policy::DEFAULT_MAX_WINDOW;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use serde_json::Value;

use super::data::{Catalog, Decision, clean, items, text, time};
use super::keys::Key;
use super::model::Seen;

/// The first-trust question's opening, with the profile's ID (spec §5.2's `<profile>`; ruling
/// I-21: never its label, which any same-user program can set).
fn first_trust_question(profile: &str) -> String {
    format!("Use {profile} access automatically for this project?")
}

/// The first-trust message's middle sentence when the project asks for background work
/// (spec §5.2, verbatim).
const WORK_WHILE_LOCKED: &str = "Work can continue while your desktop and password manager are locked, using your saved session limits.";

/// The middle sentence when it does not: the lock behavior then follows the owner's existing
/// setting for the profile, and the default lets work continue (spec §6.4;
/// `trust_m05::workspace_lock_behavior`).
const LOCK_FOLLOWS_SETTING: &str = "Whether work continues while your desktop and password manager are locked follows your existing lock setting for this profile (work continues unless you chose otherwise), using your saved session limits.";

/// The first-trust message's last sentence (spec §5.2, verbatim).
const PAUSE_OR_REMOVE: &str = "You can pause or remove access at any time.";

/// The longest label shown, in characters (ADR-0011 I5: bounded).
pub(crate) const LABEL_MAX_CHARS: usize = 64;

/// The longest value typed into the stop menu.
const MAX_VALUE: usize = 64;

fn bold(s: impl Into<String>) -> Line<'static> {
    Line::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

fn plain(s: impl Into<String>) -> Line<'static> {
    Line::from(s.into())
}

fn hms(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ---- inert text ----------------------------------------------------------------------

/// A character that can reorder or hide the text around it: the bidirectional controls
/// (marks, embeddings, overrides, isolates), the zero-width and invisible formatting
/// characters (Unicode category Cf), the soft hyphen, and the line and paragraph separators.
/// ⟨M05⟩ Review M05-W3-R03: the CLI's data fields use the same class
/// ([`crate::output::is_invisible_format`]).
fn is_breaker(c: char) -> bool {
    crate::output::is_invisible_format(c)
}

/// `s` as one safe row of cells: [`clean`] (controls and escape sequences gone, newlines
/// and tabs spaces) and without a bidirectional or invisible formatting character.
#[must_use]
pub(crate) fn safe(s: &str) -> String {
    clean(s).chars().filter(|c| !is_breaker(*c)).collect()
}

/// A repository-supplied label as inert quoted data (ADR-0011 I5): at most
/// [`LABEL_MAX_CHARS`] characters between double quotes, with `"` and `\` escaped, every
/// control and formatting character dropped and every line break a space; a note says when
/// anything was changed or cut, so the owner never reads the label as the program's own
/// words. `$(...)`, backticks and markup stay visible and mean nothing here: this text is
/// drawn, never run, and never an action.
#[must_use]
pub(crate) fn quoted(label: &str) -> String {
    let mut body = String::new();
    let mut shown = 0usize;
    let mut changed = false;
    let mut cut = false;
    for c in label.chars() {
        let c = if matches!(c, '\n' | '\r' | '\t') {
            changed = true;
            ' '
        } else {
            c
        };
        if c.is_control() || is_breaker(c) {
            changed = true;
            continue;
        }
        if shown == LABEL_MAX_CHARS {
            cut = true;
            break;
        }
        shown += 1;
        if matches!(c, '"' | '\\') {
            body.push('\\');
        }
        body.push(c);
    }
    let mut out = format!("\"{body}\"");
    if changed {
        out.push_str(" (control characters removed)");
    }
    if cut {
        out.push_str(" (cut at 64 characters)");
    }
    out
}

fn t(v: &Value, key: &str) -> Option<String> {
    text(v, key).map(|s| safe(&s))
}

fn names(v: &Value, key: &str) -> Vec<String> {
    items(v, &[key])
        .iter()
        .map(|x| safe(x.as_str().unwrap_or("?")))
        .collect()
}

// ---- data ----------------------------------------------------------------------------

/// How the workspace matched (`inspect workspace` `match`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Match {
    /// Equal path and identity.
    Trusted,
    /// A verified linked worktree.
    Member,
    /// No record matches.
    Untrusted,
    /// One reconcile decision away.
    Ambiguous,
    /// No workspace root above the working directory.
    None,
    /// A match this build does not know.
    Other(String),
}

impl Match {
    fn of(s: &str) -> Self {
        match s {
            "trusted" => Match::Trusted,
            "member" => Match::Member,
            "untrusted" => Match::Untrusted,
            "ambiguous" => Match::Ambiguous,
            "none" => Match::None,
            other => Match::Other(safe(other)),
        }
    }
}

/// `inspect workspace` data (`WorkspaceView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Workspace {
    /// The working directory asked about.
    pub cwd: String,
    /// The discovered root.
    pub root: Option<String>,
    /// The match.
    pub matched: Match,
    /// The workspace record (trusted, member, ambiguous).
    pub workspace_id: Option<String>,
    /// The workspace policy, when one exists.
    pub policy_id: Option<String>,
    /// The manifest's access digest.
    pub access_digest: Option<String>,
}

impl Workspace {
    fn of(v: &Value) -> Option<Self> {
        Some(Self {
            cwd: t(v, "cwd")?,
            root: t(v, "root"),
            matched: Match::of(&text(v, "match")?),
            workspace_id: t(v, "workspace_id"),
            policy_id: t(v, "policy_id"),
            access_digest: t(v, "access_digest"),
        })
    }
}

/// One applied revision of a policy (`PolicyRevisionView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revision {
    /// Revision number.
    pub revision: String,
    /// `decision` or `narrowing`.
    pub cause: String,
    /// The decision, for `decision`.
    pub decision_id: Option<String>,
    /// When.
    pub at: Option<Timestamp>,
}

/// One standing policy (`PolicyView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Policy {
    /// Policy ID.
    pub id: String,
    /// Current revision.
    pub revision: String,
    /// Profile ID.
    pub profile: String,
    /// The workspace, for a workspace policy.
    pub workspace_id: Option<String>,
    /// Environments.
    pub environments: Vec<String>,
    /// The personal default.
    pub default: bool,
    /// Paused since.
    pub paused_since: Option<Timestamp>,
    /// Hard cutoff.
    pub cutoff_at: Option<Timestamp>,
    /// Applied revisions, oldest first.
    pub history: Vec<Revision>,
}

impl Policy {
    fn of(v: &Value) -> Option<Self> {
        Some(Self {
            id: t(v, "policy_id")?,
            revision: t(v, "revision").unwrap_or_else(|| "?".to_owned()),
            profile: t(v, "profile").unwrap_or_else(|| "?".to_owned()),
            workspace_id: t(v, "workspace_id"),
            environments: names(v, "environments"),
            default: v.get("default").and_then(Value::as_bool) == Some(true),
            paused_since: time(v, "paused_since"),
            cutoff_at: time(v, "cutoff_at"),
            history: items(v, &["history"])
                .iter()
                .map(|r| Revision {
                    revision: t(r, "revision").unwrap_or_else(|| "?".to_owned()),
                    cause: t(r, "cause").unwrap_or_else(|| "?".to_owned()),
                    decision_id: t(r, "decision_id"),
                    at: time(r, "at"),
                })
                .collect(),
        })
    }
}

/// The M05 part of one refresh.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Listings {
    /// `inspect workspace` for the TUI's working directory; `None` when the runtime does not
    /// serve it (it does not offer `trusted-work/1`) or the directory is not readable.
    pub workspace: Option<Workspace>,
    /// `inspect policies`; `None` when the runtime does not serve it.
    pub policies: Option<Vec<Policy>>,
    /// Each environment's default profile (environment, profile).
    pub default_profiles: Vec<(String, String)>,
}

impl Listings {
    /// From the `data` of `inspect policies` and `inspect workspace` (either may be `Null`).
    #[must_use]
    pub(crate) fn of(policies: &Value, workspace: &Value) -> Self {
        Self {
            workspace: Workspace::of(workspace),
            policies: policies
                .get("items")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Policy::of).collect()),
            default_profiles: items(policies, &["default_profiles"])
                .iter()
                .filter_map(|d| Some((t(d, "environment_id")?, t(d, "profile_id")?)))
                .collect(),
        }
    }

    /// The policy with this ID, when listed.
    #[must_use]
    pub(crate) fn policy(&self, id: &str) -> Option<&Policy> {
        self.policies.as_ref()?.iter().find(|p| p.id == id)
    }

    /// What the stop menu acts on: the trusted (or member) workspace of the working
    /// directory, and its policy's profile as the profile to offer.
    #[must_use]
    pub(crate) fn stop_context(&self) -> StopContext {
        let workspace = self
            .workspace
            .as_ref()
            .filter(|w| matches!(w.matched, Match::Trusted | Match::Member))
            .and_then(|w| WorkspaceId::parse(w.workspace_id.as_deref()?).ok());
        let profile = self
            .workspace
            .as_ref()
            .and_then(|w| self.policy(w.policy_id.as_deref()?))
            .map(|p| p.profile.clone());
        StopContext { workspace, profile }
    }
}

/// ⟨M05; ruling I-21⟩ A profile in a decision's text: its ID, which the record names, and the
/// owner's label only as quoted data after it (`dev (label "Development")`). A label is catalog
/// text any same-user program can set without a decision (`profile create --label`), so it is
/// never part of a question or a title (ADR-0011 I5), as in the CLI.
fn profile_detail(catalog: &Catalog, id: &str) -> String {
    match catalog
        .profiles
        .iter()
        .find(|p| p.id == id)
        .and_then(|p| p.label.clone())
    {
        Some(label) => format!("{} (label {})", safe(id), quoted(&label)),
        None => safe(id),
    }
}

fn profile_name(catalog: &Catalog, id: &str) -> String {
    catalog
        .profiles
        .iter()
        .find(|p| p.id == id)
        .and_then(|p| p.label.clone())
        .map_or_else(|| safe(id), |l| safe(&l))
}

fn pair_label(catalog: &Catalog, p: &Value) -> String {
    let dest = text(p, "destination").unwrap_or_else(|| "?".to_owned());
    let alias = catalog
        .destinations
        .iter()
        .find(|d| d.id == dest)
        .map_or_else(|| dest.clone(), |d| d.alias.clone());
    format!(
        "{}:{}",
        safe(&alias),
        t(p, "account").unwrap_or_else(|| "?".to_owned())
    )
}

// ---- workspace status ----------------------------------------------------------------

/// The pending M05 decision that concerns the workspace, if any: a first trust for this
/// directory, a reconcile of this record, or a scope review of this policy.
#[must_use]
pub(crate) fn pending_decision(catalog: &Catalog, now: Timestamp) -> Option<String> {
    let w = catalog.m05.workspace.as_ref()?;
    catalog
        .decisions
        .iter()
        .filter(|d| !d.expired && d.expires_at.is_none_or(|e| e > now))
        .find(|d| {
            let a = d.request.get("action").unwrap_or(&Value::Null);
            match (d.kind.as_str(), text(a, "action").as_deref()) {
                ("trust_workspace", _) => text(a, "cwd").is_some_and(|c| safe(&c) == w.cwd),
                ("reconcile_workspace", _) => {
                    w.workspace_id.is_some() && t(a, "workspace") == w.workspace_id
                }
                ("widen_policy", Some("extend_scope")) => {
                    w.policy_id.is_some() && t(a, "policy_id") == w.policy_id
                }
                _ => false,
            }
        })
        .map(|d| d.id.clone())
}

/// A policy's pause and cutoff state, one marker and sentence each.
fn access_state(p: &Policy, now: Timestamp) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(since) = p.paused_since {
        out.push(format!(
            "[!!] paused since {}: no new work starts automatically; resuming needs your decision",
            hms(since)
        ));
    }
    match p.cutoff_at {
        Some(at) if at <= now => out.push(format!(
            "[!!] cutoff in effect since {}: no new work starts until you clear it (clearing needs your decision)",
            hms(at)
        )),
        Some(at) => out.push(format!(
            "[ i] a cutoff is scheduled for {}: no new work starts after it and existing access ends at it, until you clear it",
            hms(at)
        )),
        None => {}
    }
    if out.is_empty() {
        out.push(
            "[OK] active: new work under this policy starts automatically within your saved limits"
                .to_owned(),
        );
    }
    out
}

/// The workspace status view of the working directory.
#[must_use]
pub(crate) fn workspace_lines(catalog: &Catalog, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = vec![bold("Workspace status")];
    let Some(w) = &catalog.m05.workspace else {
        lines.push(plain(
            "Not available: this runtime does not serve workspace status (trusted work is not offered by it yet), or the directory could not be read.",
        ));
        return lines;
    };
    lines.push(plain(format!("Directory: {}", w.cwd)));
    lines.push(plain(match &w.root {
        Some(r) => format!("Workspace root: {r}"),
        None => "Workspace root: none found above this directory".to_owned(),
    }));
    let (marker, words, next) = match &w.matched {
        Match::Trusted => (
            "[OK]",
            "trusted: this checkout is the one you approved (same path, same directory identity)",
            None,
        ),
        Match::Member => (
            "[OK]",
            "member: a linked worktree of a trusted checkout (its back-link was verified)",
            None,
        ),
        Match::Untrusted => (
            "[ !]",
            "untrusted: no trust record matches this checkout; only your personal access applies here and nothing in the repository is trusted",
            Some(
                "To trust it, run `heimdall project trust` in this directory: you review the exact scope first.",
            ),
        ),
        Match::Ambiguous => (
            "[!!]",
            "ambiguous: this checkout only partly matches a trusted workspace (moved, or re-cloned at the same path); no workspace access is used until you reconcile it",
            Some("Run `heimdall project reconcile` in this directory to review it."),
        ),
        Match::None => (
            "[ i]",
            "none: no workspace root above this directory; this is personal context",
            None,
        ),
        Match::Other(m) => ("[??]", m.as_str(), None),
    };
    lines.push(bold(format!("{marker} {words}")));
    if let Some(n) = next {
        lines.push(plain(n));
    }
    if let Some(d) = &w.access_digest {
        let short: String = d.chars().take(16).collect();
        lines.push(plain(format!(
            "Manifest access digest: {short}... (what a review is checked against)"
        )));
    }
    lines.push(plain(
        "The directory is a same-user claim: any program you run can name any directory.",
    ));
    lines.push(plain(""));
    lines.push(bold("Policy"));
    match w.policy_id.as_deref().and_then(|id| catalog.m05.policy(id)) {
        Some(p) => {
            lines.push(plain(format!(
                "{} revision {} · profile {} ({})",
                p.id,
                p.revision,
                profile_name(catalog, &p.profile),
                p.profile
            )));
            lines.push(plain(format!(
                "Environments: {}",
                p.environments.join(", ")
            )));
            for s in access_state(p, now) {
                lines.push(plain(s));
            }
        }
        None => lines.push(plain(match &w.policy_id {
            Some(id) => format!("{id}: not listed by the runtime"),
            None => "none: this workspace has no policy of its own".to_owned(),
        })),
    }
    if let Some(id) = pending_decision(catalog, now) {
        lines.push(plain(""));
        lines.push(bold(format!(
            "[!!] A decision is waiting for this workspace: {id} (Enter to review it)"
        )));
    }
    lines.push(plain(""));
    lines.push(plain(
        "s pause or stop access · h policy history · Esc back",
    ));
    lines
}

/// The overview's one line about the working directory's workspace (only when the runtime
/// served it).
#[must_use]
pub(crate) fn overview_line(catalog: &Catalog, narrow: bool) -> Option<String> {
    let w = catalog.m05.workspace.as_ref()?;
    let state = match &w.matched {
        Match::Trusted => "trusted",
        Match::Member => "member of a trusted workspace",
        Match::Untrusted => "untrusted",
        Match::Ambiguous => "ambiguous (needs reconcile)",
        Match::None => "no workspace here",
        Match::Other(_) => "unknown",
    };
    // ⟨M07⟩ Narrow: the state and the key that shows it.
    Some(if narrow {
        format!("Workspace: {state} (w)")
    } else {
        format!("Workspace: {state} (w details · s stop · h history)")
    })
}

// ---- policy history ------------------------------------------------------------------

/// The policy history view (`inspect policies`): each policy, its state and every applied
/// revision with its cause and decision.
#[must_use]
pub(crate) fn policy_history_lines(catalog: &Catalog, now: Timestamp) -> Vec<Line<'static>> {
    let mut lines = vec![bold("Policy history")];
    let Some(policies) = &catalog.m05.policies else {
        lines.push(plain(
            "Not available: this runtime does not serve policies (trusted work is not offered by it yet).",
        ));
        return lines;
    };
    if policies.is_empty() {
        lines.push(plain("No standing policies."));
    }
    for p in policies {
        lines.push(plain(""));
        lines.push(bold(format!(
            "{} · revision {} · profile {} ({}) · {}{}",
            p.id,
            p.revision,
            profile_name(catalog, &p.profile),
            p.profile,
            match &p.workspace_id {
                Some(w) => format!("workspace {w}"),
                None => "personal".to_owned(),
            },
            if p.default { " · default" } else { "" }
        )));
        lines.push(plain(format!(
            "  Environments: {}",
            p.environments.join(", ")
        )));
        for s in access_state(p, now) {
            lines.push(plain(format!("  {s}")));
        }
        lines.push(plain("  Applied revisions, oldest first:"));
        if p.history.is_empty() {
            lines.push(plain("    none recorded"));
        }
        for r in &p.history {
            let cause = match (r.cause.as_str(), &r.decision_id) {
                ("decision", Some(d)) => format!("approved by decision {d}"),
                ("decision", None) => "approved by a decision".to_owned(),
                ("narrowing", _) => "narrowing (it only removes authority: no decision)".to_owned(),
                (other, _) => other.to_owned(),
            };
            lines.push(plain(format!(
                "    revision {} · {cause} · {}",
                r.revision,
                r.at.map_or_else(|| "unknown".to_owned(), hms)
            )));
        }
    }
    if !catalog.m05.default_profiles.is_empty() {
        lines.push(plain(""));
        lines.push(bold("Default profiles (a preference, never authority)"));
        for (e, p) in &catalog.m05.default_profiles {
            lines.push(plain(format!("  {e}: {}", profile_name(catalog, p))));
        }
    }
    lines
}

// ---- decisions -----------------------------------------------------------------------

fn pair_lines(catalog: &Catalog, a: &Value, key: &str, mark: &str) -> Vec<Line<'static>> {
    items(a, &[key])
        .iter()
        .map(|p| plain(format!("    {mark} {}", pair_label(catalog, p))))
        .collect()
}

fn list_lines(a: &Value, key: &str, mark: &str) -> Vec<Line<'static>> {
    names(a, key)
        .into_iter()
        .map(|n| plain(format!("    {mark} {n}")))
        .collect()
}

/// The runtime's own lock disclosure, shown once (D9 item 1; the M03 pattern): its text is
/// `capabilities.lock.disclosure`, never retyped here.
fn lock_disclosure_lines(catalog: &Catalog) -> Vec<Line<'static>> {
    let lock = catalog.m03.lock.as_ref();
    if let Some(at) = lock.and_then(|l| l.acknowledged_at) {
        return vec![plain(format!(
            "Lock disclosure: acknowledged {}; not shown again",
            hms(at)
        ))];
    }
    let mut lines = vec![bold(
        "Lock disclosure (shown once; recorded when the decision is approved):",
    )];
    lines.push(plain(format!(
        "  {}",
        lock.and_then(|l| l.disclosure.as_deref())
            .map_or_else(|| "(the runtime did not send its text)".to_owned(), safe)
    )));
    lines
}

/// The first-trust view of a `TrustWorkspace` record: the spec §5.2 message, then the
/// detail view (the project label only as quoted data).
fn trust_lines(catalog: &Catalog, d: &Decision) -> Vec<Line<'static>> {
    let r = &d.request;
    let a = r.get("action").unwrap_or(&Value::Null);
    let p = a.get("proposal").unwrap_or(&Value::Null);
    let profile = t(p, "profile").unwrap_or_else(|| "?".to_owned());
    let background = p.get("background_work").and_then(Value::as_bool) == Some(true);
    let mut lines = vec![
        bold(first_trust_question(&safe(&profile))),
        plain(if background {
            WORK_WHILE_LOCKED
        } else {
            LOCK_FOLLOWS_SETTING
        }),
        plain(PAUSE_OR_REMOVE),
        plain(""),
    ];
    if let Some(label) = text_raw(r, "project_label") {
        lines.push(plain(
            "Project label (written by the repository; quoted text only, it decides nothing):",
        ));
        lines.push(plain(format!("  {}", quoted(&label))));
        lines.push(plain(""));
    }
    lines.push(bold("Detail: what approving allows"));
    lines.push(plain(format!(
        "  Profile: {}",
        profile_detail(catalog, &profile)
    )));
    lines.push(plain(format!(
        "  Workspace: {}",
        t(a, "cwd").unwrap_or_else(|| "?".to_owned())
    )));
    if items(p, &["pairs"]).is_empty() {
        lines.push(plain(
            "  Pairs (destination and account): every pair of the profile, as it reads now:",
        ));
        let all: Vec<Line<'static>> = catalog
            .profiles
            .iter()
            .find(|x| x.id == profile)
            .map(|x| {
                x.pairs
                    .iter()
                    .map(|q| {
                        let alias = catalog
                            .destinations
                            .iter()
                            .find(|d| d.id == q.destination)
                            .map_or_else(|| q.destination.clone(), |d| d.alias.clone());
                        plain(format!("    - {}:{}", safe(&alias), safe(&q.account)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if all.is_empty() {
            lines.push(plain("    - (the profile is not listed here)"));
        }
        lines.extend(all);
    } else {
        lines.push(plain("  Pairs (destination and account):"));
        lines.extend(pair_lines(catalog, p, "pairs", "-"));
    }
    if items(p, &["environments"]).is_empty() {
        lines.push(plain("  Environments: this environment"));
    } else {
        lines.push(plain("  Environments:"));
        lines.extend(list_lines(p, "environments", "-"));
    }
    if items(p, &["capabilities"]).is_empty() {
        lines.push(plain("  Capabilities: those the profile holds"));
    } else {
        lines.push(plain("  Capabilities:"));
        // ⟨M07⟩ U2: first trust is a default surface: each capability in words.
        lines.extend(
            names(p, "capabilities")
                .iter()
                .map(|n| plain(format!("    - {}", super::m07::capability_words(n)))),
        );
    }
    lines.push(plain(if background {
        "  Lock continuity: the project asks for background work: access continues while your desktop is locked"
    } else {
        "  Lock continuity: the project does not ask for background work; your existing lock setting for this profile applies"
    }));
    lines.push(plain(format!(
        "  Limits: each work session lasts at most {} h by default (also shown in settings); a session never extends its own deadline",
        DEFAULT_MAX_WINDOW.as_secs() / 3600
    )));
    lines.push(plain(
        "  Approving records this workspace and its policy and lets this environment start work automatically under it. Denying records nothing.",
    ));
    if r.get("lock_disclosure").and_then(Value::as_bool) == Some(true) {
        lines.push(plain(""));
        lines.extend(lock_disclosure_lines(catalog));
    }
    lines
}

/// A string field without the `clean` of [`text`]: [`quoted`] does its own, stricter, work.
fn text_raw(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

/// The delta review of an `extend_scope` record: only the added authority.
fn delta_lines(catalog: &Catalog, a: &Value) -> Vec<Line<'static>> {
    let policy = t(a, "policy_id").unwrap_or_else(|| "?".to_owned());
    let mut lines = vec![
        bold("Review: more access for a workspace you already trust"),
        plain(format!("Policy {policy}")),
        plain(
            "Only what would be ADDED is listed. Access the policy already allows stays as it is and is not repeated here.",
        ),
        plain(""),
    ];
    let before = lines.len();
    let pairs = pair_lines(catalog, a, "pairs", "+");
    if !pairs.is_empty() {
        lines.push(bold("  Added pairs (destination and account):"));
        lines.extend(pairs);
    }
    let caps = list_lines(a, "capabilities", "+");
    if !caps.is_empty() {
        lines.push(bold("  Added capabilities:"));
        lines.extend(caps);
    }
    let envs = list_lines(a, "environments", "+");
    if !envs.is_empty() {
        lines.push(bold("  Added environments:"));
        lines.extend(envs);
    }
    match a.get("background_work").and_then(Value::as_bool) {
        Some(true) => {
            lines.push(bold("  Added lock behavior:"));
            lines.push(plain(
                "    + work continues while your desktop and password manager are locked",
            ));
        }
        Some(false) => {
            lines.push(bold("  Lock behavior:"));
            lines.push(plain("    work ends when the session locks (narrowing)"));
        }
        None => {}
    }
    if lines.len() == before {
        lines.push(plain("  (no added authority is recorded in this decision)"));
    }
    lines.push(plain(""));
    lines.push(plain(
        "Approving applies exactly this addition. Denying changes nothing.",
    ));
    lines
}

/// A personal policy's creation (`create`): the question, then the scope **the runtime
/// recorded for this decision** (`Decision::scope`, ADR-0006 §17.10 item 22; review
/// M05-W3-R01), which is exactly what approval gives the new policy: the pinned profile
/// revision's pairs and capabilities, the environments and the lock behaviour. Never the
/// catalog's current definition, which an edit can move past the pinned revision. Without
/// a recorded scope the view says so and Approve is not offered ([`approve_block`]).
fn create_lines(catalog: &Catalog, a: &Value, d: &Decision) -> Vec<Line<'static>> {
    let profile = t(a, "profile").unwrap_or_else(|| "?".to_owned());
    let mut lines = vec![
        bold(first_trust_question(&safe(&profile)).replace("this project", "your personal work")),
        plain(PAUSE_OR_REMOVE),
        plain(""),
        bold("Detail: a personal standing policy, as the runtime recorded this decision"),
    ];
    let Some(scope) = &d.scope else {
        lines.push(plain(format!(
            "  Profile: {}",
            profile_detail(catalog, &profile)
        )));
        lines.push(bold(format!(
            "[!!] Approve is not offered here: {}",
            crate::setup_cmd::SCOPE_NOT_RECORDED
        )));
        return lines;
    };
    lines.push(plain(format!(
        "  Profile: {} at revision {}",
        profile_detail(catalog, &profile),
        scope.profile_revision
    )));
    let recorded = serde_json::json!({
        "pairs": scope.pairs,
        "capabilities": scope.capabilities,
        "environments": scope.environments,
    });
    for (title, key) in [
        ("  Pairs (destination and account):", "pairs"),
        ("  Capabilities:", "capabilities"),
        ("  Environments:", "environments"),
    ] {
        lines.push(plain(title));
        let rows = if key == "pairs" {
            pair_lines(catalog, &recorded, key, "-")
        } else {
            list_lines(&recorded, key, "-")
        };
        if rows.is_empty() {
            lines.push(plain("    - none"));
        } else {
            lines.extend(rows);
        }
    }
    lines.push(plain(match scope.lock_behavior {
        heimdall_contract::managed::LockBehavior::Continue => {
            "  Lock behavior: work continues while your desktop and password manager are locked"
        }
        _ => "  Lock behavior: work ends when the session locks",
    }));
    lines.push(plain(format!(
        "  Limits: each work session lasts at most {}",
        t(a, "max_window").map_or_else(
            || format!(
                "{} h by default (also shown in settings)",
                DEFAULT_MAX_WINDOW.as_secs() / 3600
            ),
            |w| format!("{w} (also shown in settings)")
        )
    )));
    if a.get("default").and_then(Value::as_bool) == Some(true) {
        lines.push(plain(
            "  Default: it also covers ordinary ssh to your managed aliases in those environments",
        ));
    }
    lines
}

/// ⟨M05⟩ Review M05-W3-R01: why Approve is not offered for `d` (the decision modal sends
/// nothing): a `create` without a recorded scope, whose destinations cannot be shown.
/// `None` for every other decision.
#[must_use]
pub(crate) fn approve_block(d: &Decision) -> Option<String> {
    (d.kind == "widen_policy"
        && text(d.request.get("action").unwrap_or(&Value::Null), "action").as_deref()
            == Some("create")
        && d.scope.is_none())
    .then(|| crate::setup_cmd::SCOPE_NOT_RECORDED.to_owned())
}

fn reconcile_lines(r: &Value) -> Vec<Line<'static>> {
    let a = r.get("action").unwrap_or(&Value::Null);
    let why = match text(r, "why").as_deref() {
        Some("same_path_other_identity") => {
            "same path, different directory identity: a re-clone or a restore from backup"
        }
        Some("same_identity_other_path") => {
            "same directory identity at a different path: the checkout was moved"
        }
        _ => "an observation this build does not know",
    };
    vec![
        bold("Review: this checkout only partly matches a workspace you trust"),
        plain(format!("Why: {why}")),
        plain(format!(
            "Workspace record: {}",
            t(a, "workspace").unwrap_or_else(|| "?".to_owned())
        )),
        plain(format!(
            "This checkout: {}",
            t(a, "cwd").unwrap_or_else(|| "?".to_owned())
        )),
        plain(
            "Approving moves the trust to this checkout: the old record is retired and its policy follows. Denying leaves this checkout untrusted.",
        ),
    ]
}

/// The readable lines of an M05 decision's recorded request, or `None` for any other kind
/// (the caller keeps its own rendering). Reads only the record: the action fixed at its
/// creation (ADR-0011 I5).
#[must_use]
pub(crate) fn decision_lines(catalog: &Catalog, d: &Decision) -> Option<Vec<Line<'static>>> {
    let r = &d.request;
    let a = r.get("action").unwrap_or(&Value::Null);
    Some(match (d.kind.as_str(), text(a, "action").as_deref()) {
        ("trust_workspace", _) => trust_lines(catalog, d),
        ("reconcile_workspace", _) => reconcile_lines(r),
        ("widen_policy", Some("extend_scope")) => delta_lines(catalog, a),
        ("widen_policy", Some("create")) => create_lines(catalog, a, d),
        // ⟨W3 integration⟩ A targeted `resume`, `clear_cutoff` or later `cutoff` (ADR-0011
        // §7.3): one decision for every affected policy, listed as the record fixed them
        // (ADR-0006 §17.9 C1).
        ("widen_policy", Some(act @ ("resume" | "clear_cutoff" | "cutoff")))
            if a.get("target").is_some() =>
        {
            targeted_lines(act, a, &d.policies)
        }
        ("widen_policy", Some("set_max_window")) => vec![
            bold("Review: a longer session window"),
            plain(format!(
                "Policy {}: each work session may last up to {}",
                t(a, "policy_id").unwrap_or_else(|| "?".to_owned()),
                t(a, "max_window").unwrap_or_else(|| "?".to_owned())
            )),
        ],
        _ => return None,
    })
}

/// A targeted widening's review: what approval does, and exactly the policies (with the
/// revisions the record was created against) it changes.
fn targeted_lines(action: &str, a: &Value, policies: &[(String, u64)]) -> Vec<Line<'static>> {
    let what = match action {
        "resume" => "Review: resume automatic access".to_owned(),
        "clear_cutoff" => "Review: clear the hard stop".to_owned(),
        _ => format!(
            "Review: move the hard stop later, to {}",
            t(a, "at").unwrap_or_else(|| "?".to_owned())
        ),
    };
    let mut out = vec![
        bold(what),
        plain(format!(
            "Approving changes exactly these {} policies, as they were when this was asked:",
            policies.len()
        )),
    ];
    for (id, revision) in policies {
        out.push(plain(format!("  {id} (revision {revision})")));
    }
    out
}

// ---- the stop menu -------------------------------------------------------------------

/// What the stop menu acts on (from [`Listings::stop_context`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct StopContext {
    /// The trusted workspace of the working directory.
    pub workspace: Option<WorkspaceId>,
    /// Its policy's profile, offered for "stop all for a profile".
    pub profile: Option<String>,
}

/// One of the four actions of the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopKind {
    /// Stop future automatic activation for the workspace; running work continues.
    Pause,
    /// End one piece of work.
    Work,
    /// Pause every policy of a profile and end its active access.
    Profile,
    /// A hard stop at a time.
    Cutoff,
}

/// The four actions, in menu order.
pub(crate) const STOP_KINDS: [StopKind; 4] = [
    StopKind::Pause,
    StopKind::Work,
    StopKind::Profile,
    StopKind::Cutoff,
];

impl StopKind {
    fn name(self) -> &'static str {
        match self {
            StopKind::Pause => "Pause automatic access",
            StopKind::Work => "Stop this work",
            StopKind::Profile => "Stop all for a profile",
            StopKind::Cutoff => "Cutoff at a time",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            StopKind::Pause => {
                "No new work starts automatically for this workspace. Work already running continues. Resuming needs your decision."
            }
            StopKind::Work => {
                "Ends one piece of work, named by its work ID: access only it uses ends now and the work ID cannot start again. Other work, and access it shares with other work, stay."
            }
            StopKind::Profile => {
                "Pauses every policy of a profile and ends its active access now, including work already running. Starting again needs your decision."
            }
            StopKind::Cutoff => {
                "A hard stop at a time you choose (RFC 3339 with an offset): after it no new work starts and existing access ends, until you clear the cutoff (clearing needs your decision)."
            }
        }
    }

    fn needs_workspace(self) -> bool {
        matches!(self, StopKind::Pause | StopKind::Cutoff)
    }

    fn value_prompt(self) -> &'static str {
        match self {
            StopKind::Pause => "",
            StopKind::Work => "Work ID",
            StopKind::Profile => "Profile ID",
            StopKind::Cutoff => "Cutoff time (for example 2026-12-01T02:00:00-05:00)",
        }
    }
}

/// A narrowing action the menu can send: exactly the request the CLI sends for the same
/// command (`access pause --workspace`, `access stop --work`, `access stop --profile`,
/// `access cutoff --workspace --at`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopAction {
    /// `pause` with the workspace target.
    Pause {
        /// The trusted workspace.
        workspace: WorkspaceId,
    },
    /// `revoke` with the work target.
    Work {
        /// The work ID.
        work_id: WorkId,
    },
    /// `stop` with the profile target.
    Profile {
        /// The profile.
        profile: ProfileId,
    },
    /// `cutoff` with the workspace target.
    Cutoff {
        /// The trusted workspace.
        workspace: WorkspaceId,
        /// The instant.
        at: Timestamp,
    },
}

impl StopAction {
    /// What this does, in one sentence the confirmation shows.
    #[must_use]
    pub(crate) fn sentence(&self) -> String {
        match self {
            StopAction::Pause { workspace } => format!(
                "Pause automatic access for workspace {workspace}: no new work starts automatically; running work continues."
            ),
            StopAction::Work { work_id } => format!(
                "Stop work {work_id}: access only it uses ends now and the work ID cannot start again; other work and shared access stay."
            ),
            StopAction::Profile { profile } => format!(
                "Stop everything for profile {profile}: every policy of it is paused and its active access ends now."
            ),
            StopAction::Cutoff { workspace, at } => format!(
                "Cut off workspace {workspace} at {}: after it no new work starts and existing access ends, until you clear the cutoff.",
                hms(*at)
            ),
        }
    }

    /// A short name for the status line.
    #[must_use]
    pub(crate) fn what(&self) -> String {
        match self {
            StopAction::Pause { .. } => "pause".to_owned(),
            StopAction::Work { work_id } => format!("stop work {work_id}"),
            StopAction::Profile { profile } => format!("stop profile {profile}"),
            StopAction::Cutoff { .. } => "cutoff".to_owned(),
        }
    }

    /// Whether the CLI sends `Attend` first for it: a cutoff may become a widening record
    /// (a later cutoff than the current one), which only an attended session can be asked
    /// about; `pause`, `stop` and a work stop never create a decision.
    #[must_use]
    pub(crate) fn attends(&self) -> bool {
        matches!(self, StopAction::Cutoff { .. })
    }

    /// The request it sends.
    #[must_use]
    pub(crate) fn request(&self, request_id: RequestId) -> Request {
        match self {
            StopAction::Pause { workspace } => Request::Policy(PolicyAction::Pause {
                policy_id: None,
                target: Some(PolicyTarget::Workspace {
                    workspace: workspace.clone(),
                }),
            }),
            StopAction::Work { work_id } => Request::Revoke(RevokeRequest {
                grant_id: None,
                request_id,
                target: Some(RevokeTarget::Work {
                    environment: None,
                    work_id: work_id.clone(),
                }),
            }),
            StopAction::Profile { profile } => Request::Policy(PolicyAction::Stop {
                target: PolicyTarget::Profile {
                    profile: profile.clone(),
                },
            }),
            StopAction::Cutoff { workspace, at } => Request::Policy(PolicyAction::Cutoff {
                policy_id: None,
                at: *at,
                target: Some(PolicyTarget::Workspace {
                    workspace: workspace.clone(),
                }),
            }),
        }
    }
}

/// Where the menu stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopPhase {
    /// Choosing one of the four.
    Choose,
    /// Typing the value the chosen action needs.
    Value,
    /// Confirming the exact action with a typed yes.
    Confirm(StopAction),
}

/// The stop menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StopMenu {
    /// The chosen row of [`STOP_KINDS`].
    pub selected: usize,
    /// The phase.
    pub phase: StopPhase,
    /// What was typed (a value, then the confirmation).
    pub input: String,
    /// Why the last step was refused.
    pub notice: Option<String>,
    /// ⟨M07⟩ What the frames have shown of the confirmation: which of its rows they have
    /// drawn, and what the latest one showed (a fresh one for every confirmation; the
    /// marker a Settings confirmation uses, [`Seen`]).
    pub seen: Seen,
}

/// What a key did to the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopStep {
    /// The menu stays open.
    Stay,
    /// The menu closes; the text is the status line.
    Close(String),
    /// ⟨M07⟩ A typed yes was refused because the action was not on screen: the menu
    /// stays open on its confirmation and the text says why.
    Refused(&'static str),
    /// The menu closes and the action is sent.
    Send(StopAction),
}

impl Default for StopMenu {
    fn default() -> Self {
        Self {
            selected: 0,
            phase: StopPhase::Choose,
            input: String::new(),
            notice: None,
            seen: Seen::default(),
        }
    }
}

impl StopMenu {
    fn kind(&self) -> StopKind {
        STOP_KINDS[self.selected.min(STOP_KINDS.len() - 1)]
    }

    fn pick(&mut self, ctx: &StopContext) {
        let kind = self.kind();
        if kind.needs_workspace() && ctx.workspace.is_none() {
            self.notice = Some(
                "needs a trusted workspace in this directory (w shows its status); to act without one, use `heimdall access pause --profile <profile>` or `--all`"
                    .to_owned(),
            );
            return;
        }
        self.input.clear();
        self.notice = None;
        match (kind, &ctx.workspace) {
            (StopKind::Pause, Some(workspace)) => {
                self.confirm(StopAction::Pause {
                    workspace: workspace.clone(),
                });
            }
            (StopKind::Profile, _) => {
                if let Some(p) = &ctx.profile {
                    self.input = p.chars().take(MAX_VALUE).collect();
                }
                self.phase = StopPhase::Value;
            }
            _ => self.phase = StopPhase::Value,
        }
    }

    fn build(&mut self, ctx: &StopContext) {
        let value = self.input.trim().to_owned();
        let built = match (self.kind(), &ctx.workspace) {
            (StopKind::Work, _) => WorkId::parse(&value)
                .map(|work_id| StopAction::Work { work_id })
                .map_err(|_| "that is not a valid work ID"),
            (StopKind::Profile, _) => ProfileId::parse(&value)
                .map(|profile| StopAction::Profile { profile })
                .map_err(|_| "that is not a valid profile ID"),
            (StopKind::Cutoff, Some(workspace)) => value
                .parse::<Timestamp>()
                .map(|at| StopAction::Cutoff {
                    workspace: workspace.clone(),
                    at,
                })
                .map_err(|_| "not an RFC 3339 time with an offset (for example 2026-12-01T02:00:00-05:00)"),
            _ => Err("needs a trusted workspace in this directory"),
        };
        match built {
            Ok(action) => self.confirm(action),
            Err(why) => self.notice = Some(why.to_owned()),
        }
    }

    /// ⟨M07⟩ Ask for the confirmation of `action`: nothing typed, and nothing of it shown
    /// yet (what a frame showed of anything else never counts for it).
    fn confirm(&mut self, action: StopAction) {
        self.input.clear();
        self.notice = None;
        self.seen = Seen::default();
        self.phase = StopPhase::Confirm(action);
    }

    /// ⟨M07⟩ Why a typed yes cannot be accepted now, if it cannot; `frame` is the number
    /// of the latest frame. The stop menu only narrows, but a pause, a stop and a cutoff
    /// are persistent changes, so the rule of a Settings change holds (M07-W0-R01): the
    /// action and its target ([`stop_confirm_lines`]) must have been drawn in full, and
    /// the latest frame must have drawn the confirmation ([`Seen::unseen`]). Keys handled
    /// before any frame (a batch such as `s`, Enter, `yes`, Enter) confirm nothing, and
    /// neither does a terminal too small to show it.
    #[must_use]
    pub(crate) fn unseen(&self, frame: u64) -> Option<&'static str> {
        self.seen.unseen(frame)
    }

    /// Fold one key in; ⟨M07⟩ `frame` is the number of the latest frame drawn.
    pub(crate) fn key(&mut self, key: Key, ctx: &StopContext, frame: u64) -> StopStep {
        let cancel = |what: &str| StopStep::Close(format!("{what}: nothing was sent"));
        if matches!(key, Key::Esc | Key::CtrlC) {
            return cancel("cancelled");
        }
        match self.phase.clone() {
            StopPhase::Choose => match key {
                Key::Up => self.selected = self.selected.saturating_sub(1),
                Key::Down => self.selected = (self.selected + 1).min(STOP_KINDS.len() - 1),
                Key::Char(c @ '1'..='4') => {
                    self.selected = usize::from(u8::try_from(c).unwrap_or(b'1') - b'1');
                }
                Key::Enter => self.pick(ctx),
                Key::Char('q') => return cancel("closed"),
                _ => {}
            },
            StopPhase::Value => match key {
                Key::Enter => self.build(ctx),
                Key::Backspace => {
                    self.input.pop();
                }
                Key::Char(c) if self.input.chars().count() < MAX_VALUE => self.input.push(c),
                _ => {}
            },
            StopPhase::Confirm(action) => match key {
                // ⟨M07⟩ The content scrolls above the fixed prompt, as a decision's does.
                Key::Up | Key::Down | Key::PageUp | Key::PageDown | Key::Home | Key::End => {
                    self.seen.reading.scroll_key(key);
                }
                Key::Enter => {
                    if !super::model::typed_yes(&self.input) {
                        return cancel("not confirmed");
                    }
                    // ⟨M07⟩ Never a pause, a stop or a cutoff the owner has not seen.
                    if let Some(why) = self.unseen(frame) {
                        return StopStep::Refused(self.seen.refuse(why, &mut self.input));
                    }
                    return StopStep::Send(action);
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
        StopStep::Stay
    }
}

/// The menu's lines, and the index of the first line of the selected action (for keeping
/// it on screen when the terminal is short).
#[must_use]
pub(crate) fn stop_menu_lines(menu: &StopMenu, ctx: &StopContext) -> (Vec<Line<'static>>, usize) {
    let mut lines = Vec::new();
    let mut at = 0;
    match &menu.phase {
        StopPhase::Choose => {
            lines.push(plain("Four different actions; pick one:"));
            lines.push(plain(""));
            for (i, kind) in STOP_KINDS.iter().enumerate() {
                if i == menu.selected {
                    at = lines.len();
                }
                let sel = i == menu.selected;
                let unavailable = kind.needs_workspace() && ctx.workspace.is_none();
                let head = format!(
                    "{} {}. {}{}",
                    if sel { ">" } else { " " },
                    i + 1,
                    kind.name(),
                    if unavailable {
                        " (needs a trusted workspace here)"
                    } else {
                        ""
                    }
                );
                lines.push(if sel { bold(head) } else { plain(head) });
                lines.push(plain(format!("     {}", kind.describe())));
            }
        }
        StopPhase::Value => {
            let kind = menu.kind();
            lines.push(bold(kind.name()));
            lines.push(plain(kind.describe()));
            lines.push(plain(""));
            lines.push(plain(format!("{}: {}_", kind.value_prompt(), menu.input)));
        }
        // ⟨M07⟩ The view draws the confirmation itself, behind the reading guard
        // ([`stop_confirm_lines`], [`stop_confirm_ask`]); these are the same lines.
        StopPhase::Confirm(action) => {
            lines.extend(stop_confirm_lines(menu, action));
            lines.push(plain(""));
            lines.push(stop_confirm_ask(&menu.input));
        }
    }
    if let Some(n) = &menu.notice {
        lines.push(plain(""));
        lines.push(bold(format!("[!!] {n}")));
    }
    (lines, at)
}

/// ⟨M07⟩ What a stop-menu confirmation asks the owner to confirm: which of the four
/// actions, and its sentence, which names the target (the workspace, the work ID or the
/// profile) and, for a cutoff, the instant (date and time). The view wraps and scrolls these
/// lines; a typed `yes` counts only once every row of them has been drawn
/// ([`StopMenu::unseen`]).
#[must_use]
pub(crate) fn stop_confirm_lines(menu: &StopMenu, action: &StopAction) -> Vec<Line<'static>> {
    vec![bold(menu.kind().name()), plain(action.sentence())]
}

/// ⟨M07⟩ The confirmation's fixed prompt line, with what was typed.
#[must_use]
pub(crate) fn stop_confirm_ask(input: &str) -> Line<'static> {
    plain(format!("Type yes to confirm [y/N]: {input}_"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod fixtures {
    /// The fixture workspace and environment IDs.
    pub(crate) const WS: &str = "ws_11111111111111111111111111111111";
    pub(crate) const ENV: &str = "env_22222222222222222222222222222222";

    use heimdall_contract::ids::{
        AccountName, DestinationId, EnvironmentId, PolicyId, ProfileId, WorkspaceId,
    };
    use heimdall_contract::request::AccessPairRef;
    use heimdall_contract::request::PolicyAction;
    use heimdall_contract::trust::TrustProposal;
    use heimdall_domain::decision::DecisionKind;
    use heimdall_domain::workspace::AmbiguityReason;

    use crate::tui::data::Decision;
    use crate::tui::model::tests::t;

    pub(crate) fn pair(dest: &str, account: &str) -> AccessPairRef {
        AccessPairRef {
            destination: DestinationId::parse(dest).unwrap(),
            account: AccountName::parse(account).unwrap(),
        }
    }

    pub(crate) fn decision(id: &str, kind: &str, request: serde_json::Value) -> Decision {
        Decision {
            id: id.to_owned(),
            kind: kind.to_owned(),
            created_at: Some(t("2026-11-03T09:00:00Z")),
            expires_at: Some(t("2026-11-03T09:15:00Z")),
            expired: false,
            policies: Vec::new(),
            scope: None,
            request,
        }
    }

    /// A pending first-trust decision for `cwd`, serialized the way the runtime lists it
    /// (`decision_view`: the decision kind as stored).
    pub(crate) fn trust_decision(
        id: &str,
        cwd: &str,
        label: Option<&str>,
        background_work: bool,
        lock_disclosure: bool,
    ) -> Decision {
        let kind = DecisionKind::TrustWorkspace {
            action: PolicyAction::TrustWorkspace {
                cwd: cwd.to_owned(),
                access_digest: "ab".repeat(32),
                proposal: TrustProposal {
                    profile: ProfileId::parse("dev").unwrap(),
                    pairs: [pair("dst-alpha", "fixture")].into_iter().collect(),
                    environments: [EnvironmentId::parse(ENV).unwrap()].into_iter().collect(),
                    capabilities: [heimdall_contract::request::Capability::SshAuthentication]
                        .into_iter()
                        .collect(),
                    background_work,
                },
            },
            project_label: label.map(str::to_owned),
            lock_disclosure,
        };
        decision(id, "trust_workspace", serde_json::to_value(kind).unwrap())
    }

    /// A pending `extend_scope` decision (`decision_view`: `{ "action": … }`).
    pub(crate) fn extend_decision(id: &str, policy: &str) -> Decision {
        let action = PolicyAction::ExtendScope {
            policy_id: PolicyId::parse(policy).unwrap(),
            pairs: [pair("dst-beta", "deploy")].into_iter().collect(),
            capabilities: [heimdall_contract::request::Capability::GitSigning]
                .into_iter()
                .collect(),
            environments: Default::default(),
            background_work: Some(true),
        };
        decision(id, "widen_policy", serde_json::json!({ "action": action }))
    }

    /// A pending reconcile decision.
    pub(crate) fn reconcile_decision(id: &str, workspace: &str, cwd: &str) -> Decision {
        let kind = DecisionKind::ReconcileWorkspace {
            action: PolicyAction::ReconcileWorkspace {
                workspace: WorkspaceId::parse(workspace).unwrap(),
                cwd: cwd.to_owned(),
            },
            why: AmbiguityReason::SameIdentityOtherPath,
        };
        decision(
            id,
            "reconcile_workspace",
            serde_json::to_value(kind).unwrap(),
        )
    }

    /// The M05 listings of a trusted workspace with one workspace policy (revision 2, from
    /// a first-trust decision and a scope extension) and one personal policy.
    pub(crate) fn trusted_listings(cwd: &str) -> super::Listings {
        super::Listings::of(
            &serde_json::json!({
                "items": [
                    {
                        "policy_id": "pol-ws1", "revision": 2, "profile": "dev",
                        "workspace_id": WS, "environments": [ENV],
                        "history": [
                            {"revision": 1, "cause": "decision", "decision_id": "dec_trust0", "at": "2026-11-02T08:00:00Z"},
                            {"revision": 2, "cause": "decision", "decision_id": "dec_ext0", "at": "2026-11-02T09:30:00Z"},
                        ],
                    },
                    {
                        "policy_id": "pol-per1", "revision": 3, "profile": "dev",
                        "environments": [ENV], "default": true,
                        "paused_since": "2026-11-03T08:00:00Z",
                        "history": [
                            {"revision": 1, "cause": "decision", "decision_id": "dec_per0", "at": "2026-11-01T08:00:00Z"},
                            {"revision": 3, "cause": "narrowing", "at": "2026-11-03T08:00:00Z"},
                        ],
                    },
                ],
                "default_profiles": [{"environment_id": ENV, "profile_id": "dev"}],
            }),
            &serde_json::json!({
                "cwd": cwd, "root": cwd, "match": "trusted", "workspace_id": WS,
                "policy_id": "pol-ws1", "access_digest": "ab".repeat(32),
                "provenance": "same_user_context",
            }),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::tui::model::tests::{now, populated};

    /// A targeted widening's review lists every policy it changes, with the revision the
    /// record was created against (W3 integration; ADR-0006 §17.9 C1).
    #[test]
    fn a_targeted_widening_lists_its_policies() {
        let mut d = decision(
            "dec-t",
            "widen_policy",
            serde_json::json!({ "action": {
                "action": "resume", "target": { "kind": "profile", "profile": "dev" }
            }}),
        );
        d.policies = vec![("pol-a".to_owned(), 3), ("pol-b".to_owned(), 1)];
        let text = flat(&decision_lines(&Catalog::default(), &d).expect("rendered"));
        assert!(text.contains("resume automatic access"), "{text}");
        assert!(text.contains("pol-a (revision 3)"), "{text}");
        assert!(text.contains("pol-b (revision 1)"), "{text}");
        // A single-policy (M01) resume keeps its existing rendering.
        let single = decision(
            "dec-s",
            "widen_policy",
            serde_json::json!({ "action": { "action": "resume", "policy_id": "pol-a" } }),
        );
        assert!(decision_lines(&Catalog::default(), &single).is_none());
    }

    fn flat(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// ADR-0011 I5: a label is quoted, bounded, and drops every control, escape and
    /// bidirectional character; it can neither end its quote nor add a line.
    #[test]
    fn quoted_label_is_inert() {
        let hostile = "ok $(touch /tmp/x) `id` \u{1b}[31mred\u{1b}[0m\nline2\r\u{202e}evil\u{2066}\u{200b}\"; rm -rf \\";
        let q = quoted(hostile);
        assert!(q.starts_with('"'), "{q}");
        assert!(q.contains("$(touch /tmp/x)") && q.contains("`id`"), "{q}");
        assert!(q.contains("(control characters removed)"), "{q}");
        assert!(
            q.contains("\\\"; rm -rf \\\\"),
            "quote and backslash escaped: {q}"
        );
        for c in q.chars() {
            assert!(!c.is_control() && !is_breaker(c), "{c:?} in {q}");
        }
        assert!(!q.contains('\n'));
        let long = quoted(&"a".repeat(500));
        assert!(long.contains("(cut at 64 characters)"), "{long}");
        let inner = long.split('"').nth(1).unwrap();
        assert_eq!(inner.len(), LABEL_MAX_CHARS, "{long}");
        assert_eq!(quoted("plain label"), "\"plain label\"");
    }

    /// The runtime's own wire forms parse: a record built from the domain types, serialized
    /// the way `decision_view` lists it, reads back into its fields.
    #[test]
    fn decisions_read_back_from_their_wire_forms() {
        let catalog = populated().catalog;
        let d = trust_decision("dec_t1", "/work/a", Some("lab"), true, true);
        let text = flat(&decision_lines(&catalog, &d).unwrap());
        assert!(
            text.contains("Use dev access automatically for this project?"),
            "{text}"
        );
        assert!(
            text.contains(WORK_WHILE_LOCKED) && text.contains(PAUSE_OR_REMOVE),
            "{text}"
        );
        assert!(
            text.contains("alpha:fixture") && text.contains(ENV),
            "{text}"
        );
        // ⟨M07⟩ U2: the first-trust view names the capability in words.
        assert!(text.contains("SSH sign-in"), "{text}");
        assert!(text.contains("Lock disclosure"), "{text}");
        let d = extend_decision("dec_e1", "pol-ws1");
        let text = flat(&decision_lines(&catalog, &d).unwrap());
        assert!(
            text.contains("+ beta:deploy") && text.contains("+ git-signing"),
            "{text}"
        );
        let d = reconcile_decision("dec_r1", WS, "/work/moved");
        let text = flat(&decision_lines(&catalog, &d).unwrap());
        assert!(text.contains("the checkout was moved"), "{text}");
        // Any other decision keeps its own rendering.
        let mut other = extend_decision("dec_o", "pol-ws1");
        other.request = serde_json::json!({"action": {"action": "resume", "policy_id": "pol-ws1"}});
        assert!(decision_lines(&catalog, &other).is_none());
    }

    /// ⟨M05⟩ Review M05-W3-R01 (ADR-0006 §17.10 item 22): a `create` record read from its
    /// wire form shows the scope the runtime recorded for it (every pair of the pinned
    /// revision, its capabilities, environments and lock behavior), and nothing from the
    /// catalog's profile listing; one without a recorded scope (or a malformed one) says so
    /// and Approve is not offered.
    #[test]
    fn a_create_shows_its_recorded_scope_or_offers_no_approval() {
        let record = |scope: Option<serde_json::Value>| {
            let mut d = serde_json::json!({
                "decision_id": "dec_c1", "kind": "widen_policy", "state": "pending",
                "expires_at": "2026-11-03T09:15:00Z",
                "request": {"action": {"action": "create", "profile": "dev",
                    "environments": [ENV], "default": true}},
            });
            if let Some(scope) = scope {
                d["scope"] = scope;
            }
            let listing = serde_json::json!({ "decisions": [d] });
            let empty = serde_json::json!({});
            Catalog::from_answers(&empty, &empty, &empty, &empty, &listing, &empty, now())
                .decisions
                .remove(0)
        };
        let scope = serde_json::json!({
            "profile_id": "dev", "profile_revision": 4,
            "pairs": [{"destination": "h1", "account": "deploy"},
                {"destination": "h3", "account": "deploy"}],
            "environments": [ENV], "capabilities": ["ssh-authentication"],
            "lock_behavior": "continue",
        });
        let d = record(Some(scope));
        assert!(d.scope.is_some());
        let text = flat(&decision_lines(&Catalog::default(), &d).unwrap());
        for needle in [
            "Use dev access automatically for your personal work?",
            "at revision 4",
            "- h1:deploy",
            "- h3:deploy",
            "- ssh-authentication",
            ENV,
            "work continues while your desktop and password manager are locked",
            "ordinary ssh",
        ] {
            assert!(text.contains(needle), "missing {needle:?}: {text}");
        }
        assert_eq!(approve_block(&d), None);
        for scope in [
            None,
            Some(serde_json::json!({"profile_id": "dev", "pairs": []})),
        ] {
            let d = record(scope);
            assert!(d.scope.is_none());
            let text = flat(&decision_lines(&Catalog::default(), &d).unwrap());
            assert!(text.contains("Approve is not offered here"), "{text}");
            assert!(!text.contains("deploy"), "no pair is guessed: {text}");
            assert!(approve_block(&d).is_some());
        }
        // Any other decision is never blocked here.
        assert_eq!(approve_block(&extend_decision("dec_e1", "pol-ws1")), None);
    }

    /// Every stop action is the request the CLI sends for the same command, and only a
    /// cutoff attends first.
    #[test]
    fn each_stop_action_is_the_cli_request() {
        let ws = WorkspaceId::parse(WS).unwrap();
        let rid = || RequestId::parse("req-1").unwrap();
        let at: Timestamp = "2026-12-01T02:00:00-05:00".parse().unwrap();
        let cases = [
            (
                StopAction::Pause {
                    workspace: ws.clone(),
                },
                serde_json::json!({"action": "pause", "target": {"kind": "workspace", "workspace": WS}}),
            ),
            (
                StopAction::Profile {
                    profile: ProfileId::parse("dev").unwrap(),
                },
                serde_json::json!({"action": "stop", "target": {"kind": "profile", "profile": "dev"}}),
            ),
            (
                StopAction::Cutoff {
                    workspace: ws.clone(),
                    at,
                },
                serde_json::json!({"action": "cutoff", "at": "2026-12-01T07:00:00Z", "target": {"kind": "workspace", "workspace": WS}}),
            ),
        ];
        for (action, wire) in cases {
            let Request::Policy(p) = action.request(rid()) else {
                panic!("{action:?}");
            };
            assert_eq!(serde_json::to_value(&p).unwrap(), wire, "{action:?}");
            assert_eq!(action.attends(), wire["action"] == "cutoff");
        }
        let work = StopAction::Work {
            work_id: WorkId::parse("job-7").unwrap(),
        };
        let Request::Revoke(r) = work.request(rid()) else {
            panic!();
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({"request_id": "req-1", "target": {"kind": "work", "work_id": "job-7"}})
        );
        assert!(!work.attends());
    }

    /// The menu sends nothing until a valid value has been typed and `yes` confirmed; a
    /// pause and a cutoff need a trusted workspace; Esc and anything but yes send nothing.
    #[test]
    fn the_menu_confirms_before_it_sends() {
        let ctx = trusted_listings("/work/a").stop_context();
        assert_eq!(ctx.workspace, Some(WorkspaceId::parse(WS).unwrap()));
        assert_eq!(ctx.profile.as_deref(), Some("dev"));
        let type_all = |m: &mut StopMenu, s: &str| {
            for c in s.chars() {
                m.key(Key::Char(c), &ctx, 0);
            }
        };
        // Pause: choose, confirm.
        let mut m = StopMenu::default();
        assert_eq!(m.key(Key::Enter, &ctx, 0), StopStep::Stay);
        assert!(matches!(
            m.phase,
            StopPhase::Confirm(StopAction::Pause { .. })
        ));
        assert!(
            matches!(m.key(Key::Enter, &ctx, 0), StopStep::Close(_)),
            "default No"
        );
        // ⟨M07⟩ A yes before any frame has drawn the confirmation sends nothing; the menu
        // stays on it with the answer discarded (the frames themselves:
        // `view::tests::stop_menu_batched_input_cannot_confirm_before_a_frame_is_drawn`).
        let mut m = StopMenu::default();
        m.key(Key::Enter, &ctx, 0);
        type_all(&mut m, "yes");
        assert_eq!(
            m.key(Key::Enter, &ctx, 0),
            StopStep::Refused(crate::tui::model::REFUSED_NOT_DRAWN)
        );
        assert!(m.input.is_empty() && matches!(m.phase, StopPhase::Confirm(_)));
        // Frame 1 drew the prompt and both content rows: then the yes is accepted, but
        // not once a later frame (2) has drawn something else.
        m.seen.reading.record(7, 2, 2, 0);
        m.seen.report(1, crate::tui::model::Shown::Drawn);
        type_all(&mut m, "yes");
        assert_eq!(
            m.clone().key(Key::Enter, &ctx, 2),
            StopStep::Refused(crate::tui::model::REFUSED_NOT_DRAWN)
        );
        assert!(matches!(
            m.key(Key::Enter, &ctx, 1),
            StopStep::Send(StopAction::Pause { .. })
        ));
        // Stop this work: a bad value is refused in place, a good one is confirmed.
        let mut m = StopMenu::default();
        m.key(Key::Char('2'), &ctx, 0);
        m.key(Key::Enter, &ctx, 0);
        type_all(&mut m, "bad id");
        m.key(Key::Enter, &ctx, 0);
        assert_eq!(m.phase, StopPhase::Value);
        assert!(m.notice.is_some());
        for _ in 0..6 {
            m.key(Key::Backspace, &ctx, 0);
        }
        type_all(&mut m, "job-7");
        m.key(Key::Enter, &ctx, 0);
        assert!(
            matches!(&m.phase, StopPhase::Confirm(StopAction::Work { work_id }) if work_id.as_str() == "job-7")
        );
        // The profile is offered, not forced.
        let mut m = StopMenu::default();
        m.key(Key::Char('3'), &ctx, 0);
        m.key(Key::Enter, &ctx, 0);
        assert_eq!(m.input, "dev");
        // Esc sends nothing, from any phase.
        assert!(
            matches!(m.key(Key::Esc, &ctx, 0), StopStep::Close(s) if s.contains("nothing was sent"))
        );
        // Without a trusted workspace, pause and cutoff are refused with the way out.
        let none = StopContext::default();
        for key in ['1', '4'] {
            let mut m = StopMenu::default();
            m.key(Key::Char(key), &none, 0);
            assert_eq!(m.key(Key::Enter, &none, 0), StopStep::Stay);
            assert_eq!(m.phase, StopPhase::Choose);
            assert!(m.notice.as_deref().unwrap().contains("trusted workspace"));
        }
    }

    /// A runtime that does not offer trusted work reads as "not available", never as an
    /// empty or invented state.
    #[test]
    fn an_unserved_runtime_reads_as_unavailable() {
        let catalog = populated().catalog;
        assert!(catalog.m05.workspace.is_none() && catalog.m05.policies.is_none());
        assert!(flat(&workspace_lines(&catalog, now())).contains("Not available"));
        assert!(flat(&policy_history_lines(&catalog, now())).contains("Not available"));
        assert!(overview_line(&catalog, false).is_none());
        let l = Listings::of(&Value::Null, &Value::Null);
        assert_eq!(l, Listings::default());
    }
}
