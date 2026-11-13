//! ⟨M03⟩ The TUI's M03 views (m03-plan U12; ADR-0008 D8, D9, D10 item 2; F04, F14).
//!
//! What the runtime's read-only `inspect` answers carry, parsed tolerantly (a field the
//! runtime does not send reads as absent, never as a guess), and the lines the views
//! draw from it:
//! * **enrollments** (`inspect enrollments`): every state, a held record's reason and
//!   next step, the `late_write` residual (`possible_late_write`);
//! * **managed readiness** of a managed destination: its pair preference and
//!   projection (`inspect destinations` `preference`; pending is F04's warning with the
//!   `setup apply` hint), the D8 deadline wording, the live owned connections
//!   (`inspect connections`) and the current lock behaviour (D9: "the TUI detail always
//!   shows the current behaviour");
//! * **`slot_free`** (D10 item 2): the doctor's finding, with the command that holds a
//!   slot ([`slot_free_command`], the doctor's own);
//! * **the time-confirmation chore** after a reboot (F14), from the runtime's
//!   `TIME_UNCERTAIN` warning whose reason is `time_confirmation_after_reboot`
//!   (§17.25 item 15: keyed on the reason, never on the code alone);
//! * **the M03 decision kinds' recorded requests**, readably: the target change as a
//!   key diff, the enrollment plan with its disclosures, the lock disclosure where the
//!   record carries it (shown once: until `capabilities.lock.acknowledged_at`).
//!
//! **Wording is never retyped** (ADR-0008 §17.20 item 9, §17.25 items 10, 17, 19, 20):
//! the deadline text is the runtime's own (`preference.connection_policy.wording`) or
//! "unknown"; a disclosure's text is `heimdall_issuer::ceremony::disclosure_text`'s; the
//! lock disclosure is `capabilities.lock.disclosure`; the ordinary-ssh sentence is
//! `output::ORDINARY_CONNECTIONS_NOTE`.
//!
//! **Approve in the TUI** (§17.25 item 10): only for a decision kind whose follow-through
//! needs no owner-present CLI step, and only when every disclosure can be shown. Every
//! other M03 kind is shown read-only with its CLI command ([`cli_only`]). No fail-closed
//! switch remains in this module.

use heimdall_contract::Timestamp;
use heimdall_contract::envelope::Warning;
use heimdall_contract::managed::{ExistingConnectionsMode, MultiplexingMode};
use heimdall_localenv::projection::plan::slot_free_command;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use serde_json::Value;

use super::data::{Catalog, Decision, clean, items, text, time};

/// The time warning every `inspect` answer carries while safe time is not established
/// (`Operations::inspect`).
pub(crate) const TIME_UNCERTAIN: &str = "TIME_UNCERTAIN";

/// The chore's code, and the `TIME_UNCERTAIN` warning's reason when its cause is no
/// time reference for this boot (ADR-0008 D2 item 6, F14; §17.25 items 12, 15).
pub(crate) const TIME_CHORE: &str =
    heimdall_contract::envelope::m03_warning::TIME_CONFIRMATION_AFTER_REBOOT;

/// The chore's one command.
pub(crate) const TIME_CONFIRM_COMMAND: &str = "heimdall time confirm";

/// F04's warning code (`heimdall_contract::envelope::m03_warning`).
pub(crate) const PROJECTION_PENDING: &str =
    heimdall_contract::envelope::m03_warning::MANAGED_PROJECTION_PENDING;

/// F04's hint.
pub(crate) const SETUP_APPLY_COMMAND: &str = "heimdall setup apply";

/// The doctor's `slot_free` finding code.
pub(crate) const SLOT_FREE: &str = heimdall_contract::doctor::finding::SLOT_FREE;

/// The disclosure that is shown once (D9 item 1, R-UX-03).
pub(crate) const LOCK_DISCLOSURE: &str = "lock_continuity_once";

fn bold(s: impl Into<String>) -> Line<'static> {
    Line::styled(s.into(), Style::new().add_modifier(Modifier::BOLD))
}

fn plain(s: impl Into<String>) -> Line<'static> {
    Line::from(s.into())
}

fn hms(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn when(ts: Option<Timestamp>) -> String {
    ts.map_or_else(|| "unknown".to_owned(), hms)
}

fn s(v: &Value, key: &str) -> String {
    text(v, key).unwrap_or_else(|| "?".to_owned())
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().map_or_else(|| clean(&x.to_string()), clean))
                .collect()
        })
        .unwrap_or_default()
}

fn wire<T: serde::de::DeserializeOwned>(v: Option<&Value>) -> Option<T> {
    serde_json::from_value(v?.clone()).ok()
}

// ---- data ----------------------------------------------------------------------------

/// A managed pair's projection status (`ProjectionStatus`, tagged `state`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Projection {
    /// Not applied yet: `setup apply` renders it (F04).
    Pending,
    /// Applied at this generation.
    Applied(Option<u64>),
    /// A state this build does not know.
    Other(String),
}

/// The effective connection policy of a pair, as the runtime reports it
/// (`inspect destinations` `preference.connection_policy`, the serde form of
/// `ConnectionPolicyReport`; §17.25 item 19).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PolicyReport {
    /// `existing`.
    pub existing: Option<ExistingConnectionsMode>,
    /// `multiplexing`.
    pub multiplexing: Option<MultiplexingMode>,
    /// The runtime's exact D8 wording.
    pub wording: Option<String>,
}

impl PolicyReport {
    fn of(v: &Value) -> Option<Self> {
        v.is_object().then(|| Self {
            existing: wire(v.get("existing")),
            multiplexing: wire(v.get("multiplexing")),
            wording: text(v, "wording"),
        })
    }
}

/// A managed destination's pair preference (`inspect destinations` `preference`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Preference {
    /// `managed_certificate` or `existing`.
    pub mechanism: String,
    /// The projection status, when sent.
    pub projection: Option<Projection>,
    /// The pair's effective connection policy, when sent (§17.25 item 19).
    pub policy: Option<PolicyReport>,
}

impl Preference {
    pub(crate) fn of(v: &Value) -> Option<Self> {
        let mechanism = text(v, "mechanism")?;
        let projection = v
            .get("projection")
            .map(|p| match text(p, "state").as_deref() {
                Some("pending") => Projection::Pending,
                Some("applied") => Projection::Applied(p.get("generation").and_then(Value::as_u64)),
                other => Projection::Other(other.unwrap_or("?").to_owned()),
            });
        Some(Self {
            mechanism,
            projection,
            policy: v.get("connection_policy").and_then(PolicyReport::of),
        })
    }

    /// A managed-certificate pair.
    #[must_use]
    pub(crate) fn is_managed_certificate(&self) -> bool {
        self.mechanism == "managed_certificate"
    }

    /// F04: its projection is pending.
    #[must_use]
    pub(crate) fn projection_pending(&self) -> bool {
        self.is_managed_certificate() && self.projection == Some(Projection::Pending)
    }
}

/// A held record's reason and next steps (`EnrollmentView.hold {reason, next}`,
/// §17.25 item 4): the app computes `next`, so `enroll status` and the TUI show the
/// same commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hold {
    /// `HoldReason` wire name.
    pub reason: String,
    /// The runtime's next steps in order (commands or a manual instruction); empty when
    /// it names none.
    pub next: Vec<String>,
}

/// One enrollment record (`inspect enrollments`, `EnrollmentView`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Enrollment {
    /// Enrollment ID.
    pub id: String,
    /// Destination ID.
    pub destination: String,
    /// Account.
    pub account: String,
    /// `account` or `system`.
    pub form: String,
    /// CA fingerprint.
    pub ca: String,
    /// Marker.
    pub marker: String,
    /// State (`EnrollmentState` wire name).
    pub state: String,
    /// Registry path (display) and how it was resolved.
    pub registry: String,
    /// When verified.
    pub verified_at: Option<Timestamp>,
    /// Evidence fresh until.
    pub evidence_fresh_until: Option<Timestamp>,
    /// Per-pair residual.
    pub pair_residual_until: Option<Timestamp>,
    /// The approved target, `host:port as user`.
    pub target: String,
    /// The approved host key's fingerprint.
    pub host_key: String,
    /// `rollback` or `explicit_removal`.
    pub removal_purpose: Option<String>,
    /// Live grants under it.
    pub live_grants: usize,
    /// Its open operation.
    pub open_operation: Option<String>,
    /// The `late_write` residual exists.
    pub possible_late_write: bool,
    /// A held record's reason and next steps (§17.25 item 4).
    pub hold: Option<Hold>,
}

impl Enrollment {
    fn of(v: &Value) -> Option<Self> {
        let t = v.get("approved_target").unwrap_or(&Value::Null);
        let r = v.get("registry").unwrap_or(&Value::Null);
        Some(Self {
            id: text(v, "enrollment_id")?,
            destination: s(v, "destination_id"),
            account: s(v, "account"),
            form: s(v, "form"),
            ca: s(v, "ca_fingerprint"),
            marker: s(v, "marker"),
            state: s(v, "state"),
            registry: format!(
                "{} (resolved by {})",
                s(r, "path_display"),
                s(r, "resolved_by")
            ),
            verified_at: time(v, "verified_at"),
            evidence_fresh_until: time(v, "evidence_fresh_until"),
            pair_residual_until: time(v, "pair_residual_until"),
            target: format!("{}:{} as {}", s(t, "hostname"), s(t, "port"), s(t, "user")),
            host_key: s(t, "host_key_fingerprint"),
            removal_purpose: text(v, "removal_purpose"),
            live_grants: v
                .get("live_grants")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            open_operation: text(v, "open_operation_id"),
            possible_late_write: v.get("possible_late_write").and_then(Value::as_bool)
                == Some(true),
            hold: v.get("hold").and_then(|h| {
                Some(Hold {
                    reason: text(h, "reason")?,
                    next: strings(h, "next"),
                })
            }),
        })
    }

    /// Whether it needs the owner now (held, an unknown outcome, a manual step).
    #[must_use]
    pub(crate) fn needs_attention(&self) -> bool {
        state_class(&self.state).0 == "[!!]"
    }
}

/// One owned connection (`inspect connections`, `ConnectionEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connection {
    /// `dedicated` or `master`.
    pub kind: String,
    /// Destination ID.
    pub destination: String,
    /// Its recorded policy, `existing`.
    pub existing: String,
    /// Its recorded policy, `multiplexing`.
    pub multiplexing: String,
    /// When it closes, if it does.
    pub closes_at: Option<Timestamp>,
    /// `up` or `closing`.
    pub state: String,
}

impl Connection {
    fn of(v: &Value) -> Option<Self> {
        let p = v.get("policy").unwrap_or(&Value::Null);
        Some(Self {
            kind: text(v, "kind")?,
            destination: s(v, "destination_id"),
            existing: s(p, "existing"),
            multiplexing: s(p, "multiplexing"),
            closes_at: time(v, "closes_at"),
            state: s(v, "state"),
        })
    }
}

/// The current lock behaviour and its disclosure (`inspect capabilities` `lock
/// {behavior, disclosure, acknowledged_at?}`, from `Operations::lock_disclosure`;
/// §17.25 item 21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockReport {
    /// `continue` or `revoke_on_lock`.
    pub behavior: String,
    /// The runtime's D9 disclosure text.
    pub disclosure: Option<String>,
    /// When the owner acknowledged it (D9 item 1: shown once, until then).
    pub acknowledged_at: Option<Timestamp>,
}

/// The M03 part of one refresh.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Listings {
    /// Enrollment records.
    pub enrollments: Vec<Enrollment>,
    /// Owned connections that are up or closing.
    pub connections: Vec<Connection>,
    /// The runtime's `TIME_UNCERTAIN` message, while it reports one with the reason
    /// `time_confirmation_after_reboot` (§17.25 item 15).
    pub time_uncertain: Option<String>,
    /// The lock behaviour (§17.25 item 21).
    pub lock: Option<LockReport>,
}

impl Listings {
    /// From the `data` of `inspect enrollments`, `inspect connections` and `inspect
    /// capabilities` (any may be `Null`), and every warning of the refresh.
    #[must_use]
    pub(crate) fn of(
        enrollments: &Value,
        connections: &Value,
        capabilities: &Value,
        warnings: &[Warning],
    ) -> Self {
        Self {
            enrollments: items(enrollments, &["enrollments"])
                .iter()
                .filter_map(Enrollment::of)
                .collect(),
            connections: items(connections, &["connections"])
                .iter()
                .filter_map(Connection::of)
                .collect(),
            time_uncertain: warnings
                .iter()
                .find(|w| w.code == TIME_UNCERTAIN && w.reason.as_deref() == Some(TIME_CHORE))
                .map(|w| clean(&w.message)),
            lock: capabilities.get("lock").and_then(|l| {
                Some(LockReport {
                    behavior: text(l, "behavior")?,
                    disclosure: text(l, "disclosure"),
                    acknowledged_at: time(l, "acknowledged_at"),
                })
            }),
        }
    }
}

// ---- enrollment states ---------------------------------------------------------------

/// Every `EnrollmentState` wire name (ADR-0008 D5 §6.1), in the table's order.
#[cfg(test)]
pub(crate) const ENROLLMENT_STATES: [&str; 20] = [
    "planned",
    "applying",
    "outcome_unknown",
    "held",
    "applied_unverified",
    "manual_pending",
    "verifying",
    "verified",
    "reverifying",
    "rollback_pending",
    "rollback_unknown",
    "removing",
    "remove_unknown",
    "manual_removal_pending",
    "removal_verifying",
    "verification_failed",
    "removed",
    "withdrawn",
    "failed_unwritten",
    "abandoned",
];

/// A state's text marker and words (never color alone).
#[must_use]
pub(crate) fn state_class(state: &str) -> (&'static str, &'static str) {
    match state {
        "verified" => ("[OK]", "verified"),
        "held" | "outcome_unknown" | "rollback_unknown" | "remove_unknown" => ("[!!]", "needs you"),
        "manual_pending" | "manual_removal_pending" => ("[!!]", "waits for your manual step"),
        "planned" | "applying" | "applied_unverified" | "verifying" | "reverifying"
        | "rollback_pending" | "removing" | "removal_verifying" => ("[..]", "in progress"),
        "verification_failed" | "removed" | "withdrawn" | "failed_unwritten" => ("[--]", "final"),
        "abandoned" => ("[--]", "abandoned (not final)"),
        _ => ("[??]", "unknown state"),
    }
}

/// The alias of a destination ID, or the ID.
fn alias_of(catalog: &Catalog, destination: &str) -> String {
    catalog
        .destinations
        .iter()
        .find(|d| d.id == destination)
        .map_or_else(|| destination.to_owned(), |d| d.alias.clone())
}

/// One row of an enrollment list.
#[must_use]
pub(crate) fn enrollment_row(catalog: &Catalog, e: &Enrollment) -> String {
    let (_, words) = state_class(&e.state);
    let words = if words == e.state {
        String::new()
    } else {
        format!(" ({words})")
    };
    format!(
        " {}  {}@{}  {}{words}{}",
        e.id,
        e.account,
        alias_of(catalog, &e.destination),
        e.state,
        if e.possible_late_write {
            " · possible late write"
        } else {
            ""
        }
    )
}

/// A held record's next steps, exactly as the runtime names them (§17.25 item 4): a
/// command is quoted, a manual instruction is shown as it is; none named reads so.
fn held_next_lines(hold: &Hold) -> Vec<Line<'static>> {
    if hold.next.is_empty() {
        return vec![plain("  next: none named by the runtime")];
    }
    let mut lines = vec![plain("  next:")];
    for n in &hold.next {
        lines.push(plain(if n.starts_with("heimdall ") {
            format!("    - `{n}`")
        } else {
            format!("    - {n}")
        }));
    }
    lines
}

/// The `late_write` residual's lines (ADR-0008 D5 §6.7; the runtime's note command).
fn late_write_lines(e: &Enrollment) -> Vec<Line<'static>> {
    vec![
        bold("[ !] Possible late write (the late_write residual):"),
        plain(
            "  an uncertain append may still land on the host until its not-after; it stays listed until an inspect after that shows absence",
        ),
        plain(format!(
            "  remove it with `heimdall enroll remove {}`",
            e.id
        )),
    ]
}

/// The enrollment detail screen.
#[must_use]
pub(crate) fn enrollment_lines(catalog: &Catalog, id: &str) -> Vec<Line<'static>> {
    let Some(e) = catalog.m03.enrollments.iter().find(|e| e.id == id) else {
        return vec![plain(format!("{id}: not in the latest listing"))];
    };
    let (marker, words) = state_class(&e.state);
    let mut lines = vec![bold(format!(
        "{}: {} at {} ({} form)",
        e.id,
        e.account,
        alias_of(catalog, &e.destination),
        e.form
    ))];
    let mut state = format!("{marker} State: {} ({words})", e.state);
    if e.form == "system" && e.state == "removed" {
        state.push_str("; absence verified, not removed by Heimdall");
    }
    lines.push(plain(state));
    lines.push(plain(format!("CA {} · marker {}", e.ca, e.marker)));
    lines.push(plain(format!("Registry {}", e.registry)));
    lines.push(plain(format!(
        "Approved target {} · host key {}",
        e.target, e.host_key
    )));
    lines.push(plain(format!(
        "Verified {} · evidence fresh until {}",
        when(e.verified_at),
        when(e.evidence_fresh_until)
    )));
    if let Some(r) = e.pair_residual_until {
        lines.push(plain(format!("Pair residual until {}", hms(r))));
    }
    if let Some(p) = &e.removal_purpose {
        lines.push(plain(format!("Removal purpose: {p}")));
    }
    lines.push(plain(format!(
        "Live grants: {} · open operation {}",
        e.live_grants,
        e.open_operation.as_deref().unwrap_or("none")
    )));
    if e.state == "held" {
        match &e.hold {
            Some(h) => {
                lines.push(bold(format!("[!!] Held: {}", h.reason)));
                lines.extend(held_next_lines(h));
            }
            None => {
                lines.push(bold(
                    "[!!] Held: reason unknown (not reported by the runtime)",
                ));
                lines.push(plain("  next: unknown"));
            }
        }
    }
    if e.possible_late_write {
        lines.extend(late_write_lines(e));
    }
    lines
}

// ---- managed readiness -----------------------------------------------------------------

/// The D8 deadline wording of a managed pair (ADR-0008 D8 items 3 and 6; §17.25 items
/// 19 and 20): the runtime's own `connection_wording`, verbatim (D8 item 3's
/// owned-masters sentence reaches the TUI only inside it); with no wording reported it
/// is unknown, never derived here.
#[must_use]
pub(crate) fn deadline_line(policy: Option<&PolicyReport>) -> String {
    policy.and_then(|p| p.wording.as_deref()).map_or_else(
        || "unknown: the runtime reports no connection policy for this pair".to_owned(),
        clean,
    )
}

/// The managed block of a destination detail (only for a managed-certificate pair).
#[must_use]
pub(crate) fn managed_lines(
    catalog: &Catalog,
    destination: &super::data::Destination,
) -> Vec<Line<'static>> {
    let Some(p) = destination
        .preference
        .as_ref()
        .filter(|p| p.is_managed_certificate())
    else {
        return Vec::new();
    };
    let mut lines = vec![bold("Managed readiness:")];
    lines.push(plain(format!(
        "  Mechanism {} · projection {}",
        p.mechanism,
        match &p.projection {
            Some(Projection::Pending) => "pending".to_owned(),
            Some(Projection::Applied(g)) => format!(
                "applied (generation {})",
                g.map_or_else(|| "?".to_owned(), |g| g.to_string())
            ),
            Some(Projection::Other(o)) => clean(o),
            None => "unknown".to_owned(),
        }
    )));
    if p.projection_pending() {
        lines.push(plain(format!(
            "  [ !] {PROJECTION_PENDING}: the managed projection for this pair is not applied yet; run `{SETUP_APPLY_COMMAND}`"
        )));
    }
    lines.push(plain("  At the deadline:"));
    lines.push(plain(format!("    {}", deadline_line(p.policy.as_ref()))));
    let live: Vec<_> = catalog
        .m03
        .connections
        .iter()
        .filter(|c| c.destination == destination.id)
        .collect();
    if live.is_empty() {
        lines.push(plain("  Owned connections: none up"));
    }
    for c in live {
        lines.push(plain(format!(
            "  Owned connection: {} {} (policy {}, {}), closes {}",
            c.kind,
            c.state,
            c.existing,
            c.multiplexing,
            when(c.closes_at)
        )));
    }
    // §17.25 item 17: the one ordinary-ssh sentence, shared with the CLI.
    lines.push(plain(format!(
        "  Note: {}",
        crate::output::ORDINARY_CONNECTIONS_NOTE
    )));
    lines.extend(lock_lines(catalog.m03.lock.as_ref()));
    for e in catalog
        .m03
        .enrollments
        .iter()
        .filter(|e| e.destination == destination.id)
    {
        let (marker, _) = state_class(&e.state);
        lines.push(plain(format!(
            "  {marker} Enrollment{}",
            enrollment_row(catalog, e)
        )));
    }
    lines
}

/// The current lock behaviour (D9 item 1: "the TUI detail always shows the current
/// behaviour"), and its disclosure while it is not acknowledged (shown once; §17.25
/// item 21), both from `inspect capabilities` `lock`.
fn lock_lines(lock: Option<&LockReport>) -> Vec<Line<'static>> {
    let Some(l) = lock else {
        return vec![plain(
            "  Lock behaviour: unknown (not reported by the runtime)",
        )];
    };
    let mut lines = vec![plain(format!("  Lock behaviour: {}", clean(&l.behavior)))];
    match (l.acknowledged_at, &l.disclosure) {
        (Some(at), _) => lines.push(plain(format!("  Lock disclosure acknowledged {}", hms(at)))),
        (None, Some(text)) => lines.push(plain(format!(
            "  Lock disclosure (not yet acknowledged): {}",
            clean(text)
        ))),
        (None, None) => lines.push(plain(
            "  Lock disclosure: not acknowledged; its text is not reported by the runtime",
        )),
    }
    lines
}

/// The `slot_free` line for `alias`, its command first (the doctor's, D10 item 2): an
/// overview row is one terminal row, so what to run comes before why.
#[must_use]
pub(crate) fn slot_free_line(alias: &str) -> String {
    format!(
        "{SLOT_FREE} ({alias}): hold the slot with `{}` (ordinary `ssh {alias}` needs a held slot)",
        slot_free_command(alias)
    )
}

/// A chore of the store reader (worker U's `doctor_cmd::PendingChore`) as one overview
/// line, its command first (its message's trailing ": run `<command>`" is not repeated).
#[must_use]
pub(crate) fn chore_line(c: &crate::doctor_cmd::PendingChore) -> String {
    let tail = format!(": run `{}`", c.command);
    let why = c.message.strip_suffix(&tail).unwrap_or(&c.message);
    format!("{}: run `{}` ({})", c.chore, c.command, clean(why))
}

/// The time chore's overview text, its command first.
#[must_use]
pub(crate) fn time_chore_line(message: &str) -> String {
    format!(
        "{TIME_CHORE}: run `{TIME_CONFIRM_COMMAND}` ({message}; after a reboot it needs one attended confirmation)"
    )
}

// ---- decisions -------------------------------------------------------------------------

/// The M03 decision kinds whose records the TUI renders readably.
const M03_KINDS: [&str; 6] = [
    "enroll_account",
    "enroll_system_form",
    "approve_target_change",
    "remove_enrollment",
    "register_issuer",
    "retire_issuer",
];

/// The disclosures a record carries (wire names).
fn disclosures(d: &Decision) -> Vec<String> {
    let r = &d.request;
    let from = r.get("summary").unwrap_or(r);
    strings(from, "disclosures")
}

/// The text of disclosure `kind` (a wire name) for decision `d`: the one shared text,
/// `heimdall_issuer::ceremony::disclosure_text` (§17.25 item 10), with the record's
/// alias and the runtime's own lock disclosure (`capabilities.lock.disclosure`, §17.25
/// item 21) as its context. `None` for a kind this build does not know: the modal then
/// shows the shared `UNKNOWN_DISCLOSURE` text and Approve is not offered. Nothing here
/// retypes a disclosure.
fn disclosure_text(catalog: &Catalog, d: &Decision, kind: &str) -> Option<String> {
    use heimdall_issuer::ceremony::{DisclosureContext, disclosure_text};
    let known: heimdall_contract::enrollment::DisclosureKind =
        serde_json::from_value(Value::String(kind.to_owned())).ok()?;
    let alias = d.request.get("summary").and_then(|p| text(p, "alias"));
    let lock = catalog.m03.lock.as_ref().and_then(|l| l.disclosure.clone());
    let shown = disclosure_text(
        known,
        &DisclosureContext {
            alias: alias.as_deref(),
            lock: lock.as_deref(),
        },
    );
    (shown != heimdall_issuer::ceremony::UNKNOWN_DISCLOSURE).then(|| clean(&shown))
}

/// The CLI command that completes an M03 decision the TUI shows read-only (§17.25 item
/// 10, §17.26): its follow-through needs the owner at a CLI terminal (the enrollment
/// and removal step loop, which runs `ssh` there; the issuer ceremony's passphrase; the
/// retirement's exact-locator deletion), so the TUI never offers or sends Approve for
/// it. Deny (narrowing, nothing to follow through) is its one verdict here, after the
/// usual typed `yes`. `None` for every other kind.
#[must_use]
pub(crate) fn cli_only(d: &Decision) -> Option<String> {
    let r = &d.request;
    let summary = r.get("summary").unwrap_or(&Value::Null);
    let alias = || text(summary, "alias").unwrap_or_else(|| s(summary, "destination_id"));
    Some(match d.kind.as_str() {
        "enroll_account" => format!("heimdall enroll {}", alias()),
        "enroll_system_form" => format!("heimdall enroll {} --form system", alias()),
        "remove_enrollment" => {
            let t = r.get("target").unwrap_or(&Value::Null);
            match text(t, "kind").as_deref() {
                Some("enrollment") => {
                    format!("heimdall enroll remove {}", s(t, "enrollment_id"))
                }
                _ => format!(
                    "heimdall enroll remove --from-bundle <file> --marker {} --alias {}",
                    s(t, "marker"),
                    s(t, "local_alias")
                ),
            }
        }
        "register_issuer" => {
            if text(r, "rotation_of").is_some() {
                "heimdall issuer rotate begin --backup-out <path>".to_owned()
            } else if r.get("restored_without_log").and_then(Value::as_bool) == Some(true)
                || text(r, "expected_store_locator").is_some()
            {
                "heimdall issuer restore --backup <file>".to_owned()
            } else {
                "heimdall issuer init --backup-out <path>".to_owned()
            }
        }
        "retire_issuer" => format!("heimdall issuer retire {}", s(r, "ca_fingerprint")),
        _ => return None,
    })
}

/// The read-only notice of a [`cli_only`] decision: what to run to approve it, and that
/// only Deny can be sent from here.
#[must_use]
pub(crate) fn cli_only_notice(command: &str) -> String {
    format!(
        "Read-only in the TUI: this decision is approved only in the CLI, on the terminal that runs `{command}` (its follow-through needs you there). Approve is not offered here; you can deny it here with a typed yes."
    )
}

/// Why Approve is not offered for `d` in the TUI: a decision decided only in the CLI
/// ([`cli_only`]), or an M03 decision with a disclosure this build cannot show (a kind
/// it does not know).
/// `None` for every other kind.
#[must_use]
pub(crate) fn approve_block(catalog: &Catalog, d: &Decision) -> Option<String> {
    if let Some(command) = cli_only(d) {
        return Some(format!(
            "{} is approved only in the CLI: run `{command}`",
            clean(&d.kind)
        ));
    }
    if !M03_KINDS.contains(&d.kind.as_str()) {
        return None;
    }
    let missing: Vec<String> = disclosures(d)
        .into_iter()
        .filter(|k| disclosure_text(catalog, d, k).is_none())
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "the TUI cannot show the text of {}; decide it where its disclosures are shown (the CLI)",
            missing.join(", ")
        )
    })
}

fn target_lines(label: &str, t: &Value) -> Vec<Line<'static>> {
    let k = t.get("host_key").unwrap_or(&Value::Null);
    vec![
        plain(format!(
            "{label}: {}:{} as {} (proxy {})",
            s(t, "hostname"),
            s(t, "port"),
            s(t, "user"),
            s(t, "proxy")
        )),
        plain(format!(
            "  host key {} {}",
            s(k, "algorithm"),
            s(k, "fingerprint")
        )),
        plain(format!("  key {}", s(k, "key"))),
    ]
}

/// The approved and proposed targets as a diff: unchanged fields once, changed ones
/// as `-` (approved) and `+` (proposed) lines, the host key in full.
fn target_diff(approved: &Value, proposed: &Value) -> Vec<Line<'static>> {
    let mut lines = vec![bold("Target change (- approved, + proposed):")];
    let key = |t: &Value, f: &str| s(t.get("host_key").unwrap_or(&Value::Null), f);
    let field = |t: &Value| {
        [
            ("HostName", s(t, "hostname")),
            ("Port", s(t, "port")),
            ("User", s(t, "user")),
            ("host key type", key(t, "algorithm")),
            ("host key fingerprint", key(t, "fingerprint")),
            ("host key", key(t, "key")),
        ]
    };
    for ((name, a), (_, b)) in field(approved).into_iter().zip(field(proposed)) {
        if a == b {
            lines.push(plain(format!("  {name} {a}")));
        } else {
            lines.push(plain(format!("- {name} {a}")));
            lines.push(plain(format!("+ {name} {b}")));
        }
    }
    lines
}

fn disclosure_lines(catalog: &Catalog, d: &Decision) -> Vec<Line<'static>> {
    let kinds = disclosures(d);
    if kinds.is_empty() {
        return vec![plain("Disclosures: none")];
    }
    let mut lines = vec![bold("Disclosures:")];
    for k in kinds {
        let shown = disclosure_text(catalog, d, &k);
        if k == LOCK_DISCLOSURE {
            // D9 item 1: shown once, until the runtime reports it acknowledged.
            if let Some(at) = catalog.m03.lock.as_ref().and_then(|l| l.acknowledged_at) {
                lines.push(plain(format!(
                    "  * Lock disclosure: acknowledged {}; not shown again",
                    hms(at)
                )));
                continue;
            }
            lines.push(bold(
                "  * Lock disclosure (shown once; recorded when the decision is approved):",
            ));
            lines.push(plain(format!(
                "    {}",
                shown.unwrap_or_else(|| heimdall_issuer::ceremony::UNKNOWN_DISCLOSURE.to_owned())
            )));
        } else {
            lines.push(plain(format!(
                "  * {k}: {}",
                shown.unwrap_or_else(|| heimdall_issuer::ceremony::UNKNOWN_DISCLOSURE.to_owned())
            )));
        }
    }
    lines
}

/// The readable lines of an M03 decision's recorded request, or `None` for any other
/// kind (the caller keeps its own rendering).
#[must_use]
pub(crate) fn decision_lines(catalog: &Catalog, d: &Decision) -> Option<Vec<Line<'static>>> {
    let r = &d.request;
    let mut lines = Vec::new();
    match d.kind.as_str() {
        "enroll_account" | "enroll_system_form" => {
            let p = r.get("summary").unwrap_or(&Value::Null);
            let reg = p.get("registry").unwrap_or(&Value::Null);
            lines.push(plain(format!(
                "Plan: enroll {} at {} ({}), {} form, under CA {}",
                s(p, "account"),
                s(p, "alias"),
                s(p, "destination_id"),
                s(p, "form"),
                s(p, "ca_fingerprint")
            )));
            lines.push(plain(format!(
                "Registry {} (resolved by {}) · line SHA-256 {}",
                s(reg, "path_display"),
                s(reg, "resolved_by"),
                s(p, "line_sha256")
            )));
            lines.push(plain(format!("Plan digest {}", s(r, "plan_digest"))));
            lines.extend(target_lines(
                "Approved target",
                p.get("approved_target").unwrap_or(&Value::Null),
            ));
            lines.push(plain(format!(
                "Existing access: {}",
                strings(p, "invocation").join(" ")
            )));
            for pin in strings(p, "host_trust") {
                lines.push(plain(format!("Host trust: {pin}")));
            }
            lines.push(plain(format!(
                "Bootstrap step: {}",
                if p.get("bootstrap").and_then(Value::as_bool) == Some(true) {
                    "may run"
                } else {
                    "none"
                }
            )));
            if let Some(sys) = r.get("sshd_lines") {
                lines.push(bold("System form lines (you apply them):"));
                lines.push(plain(format!(
                    "  TrustedUserCAKeys line: {}",
                    s(sys, "trusted_user_ca_keys_line")
                )));
                lines.push(plain(format!(
                    "  principals line: {}",
                    s(sys, "principals_line")
                )));
                for dline in strings(sys, "sshd_directives") {
                    lines.push(plain(format!("  sshd_config: {dline}")));
                }
            }
            lines.extend(disclosure_lines(catalog, d));
        }
        "approve_target_change" => {
            lines.push(plain(format!(
                "Enrollment {} · operation {}",
                s(r, "enrollment"),
                s(r, "operation")
            )));
            lines.extend(target_diff(
                r.get("approved").unwrap_or(&Value::Null),
                r.get("proposed").unwrap_or(&Value::Null),
            ));
        }
        "remove_enrollment" => {
            let t = r.get("target").unwrap_or(&Value::Null);
            lines.push(plain(match text(t, "kind").as_deref() {
                Some("enrollment") => format!("Remove enrollment {}", s(t, "enrollment_id")),
                _ => format!("Remove a foreign line: {}", clean(&t.to_string())),
            }));
            lines.push(plain(format!("Operation {}", s(r, "operation"))));
            lines.push(plain(format!(
                "Existing access: {}",
                strings(r, "invocation").join(" ")
            )));
            lines.push(plain(format!(
                "Grants it ends: {}",
                match strings(r, "affected_grants") {
                    g if g.is_empty() => "none".to_owned(),
                    g => g.join(", "),
                }
            )));
            lines.push(plain(format!(
                "Pair residual until {}",
                when(time(r, "pair_residual_until"))
            )));
            if let Some(f) = r.get("fresh_target").filter(|f| !f.is_null()) {
                lines.extend(target_lines("Freshly evaluated target", f));
            }
        }
        "register_issuer" => {
            lines.push(plain(format!("Register CA {}", s(r, "ca_fingerprint"))));
            lines.push(plain(format!("Store {}", s(r, "store"))));
            lines.push(plain(format!(
                "Backup SHA-256 {} (created {})",
                s(r, "backup_sha256"),
                text(r, "backup_created_at").unwrap_or_else(|| "?".to_owned())
            )));
            if let Some(rot) = text(r, "rotation_of") {
                lines.push(plain(format!("Rotation of {rot}")));
            }
            if r.get("restored_without_log").and_then(Value::as_bool) == Some(true) {
                lines.push(plain("Restored without its issuance log"));
            }
            lines.extend(disclosure_lines(catalog, d));
        }
        "retire_issuer" => {
            lines.push(plain(format!("Retire CA {}", s(r, "ca_fingerprint"))));
            let abandoned = strings(r, "abandoned_enrollments");
            lines.push(plain(format!(
                "Enrollments abandoned with it: {}",
                if abandoned.is_empty() {
                    "none".to_owned()
                } else {
                    abandoned.join(", ")
                }
            )));
        }
        _ => return None,
    }
    if let Some(command) = cli_only(d) {
        lines.push(bold(format!("[!!] {}", cli_only_notice(&command))));
    } else if let Some(why) = approve_block(catalog, d) {
        lines.push(bold(format!("[!!] Approve is not offered here: {why}")));
    }
    Some(lines)
}

/// Fixtures of the M03 views' tests: records built from the contract and domain
/// types, serialized the way the runtime serializes them.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod fixtures {
    use heimdall_contract::enrollment::{
        ApprovedHostKey, ApprovedTarget, DisclosureKind, EnrollmentForm, NoProxy, RegistryRef,
        RegistryResolvedBy,
    };
    use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId, OperationId};
    use heimdall_domain::decision::{DecisionKind, EnrollmentPlanSummary};
    use serde_json::Value;

    use crate::tui::data::Decision;
    use crate::tui::model::tests::t;

    /// The fixture CA.
    pub(crate) fn ca() -> CaFingerprint {
        CaFingerprint::parse(&format!("SHA256:{}", "A".repeat(43))).unwrap()
    }

    /// A target with host key `key`.
    pub(crate) fn target(key: &str) -> ApprovedTarget {
        ApprovedTarget {
            hostname: "alpha.example.invalid".to_owned(),
            port: 22,
            user: AccountName::parse("fixture").unwrap(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".to_owned(),
                key: format!("AAAAC3NzaC1lZDI1NTE5AAAAI{key}"),
                fingerprint: format!("SHA256:{key}"),
            },
        }
    }

    fn decision(id: &str, kind: &str, request: &DecisionKind) -> Decision {
        Decision {
            id: id.to_owned(),
            kind: kind.to_owned(),
            created_at: Some(t("2026-11-03T09:00:00Z")),
            expires_at: Some(t("2026-11-03T09:15:00Z")),
            expired: false,
            request: serde_json::to_value(request).unwrap(),
        }
    }

    /// A pending `EnrollAccount` decision for `alpha` with `disclosures`.
    pub(crate) fn enroll_decision(id: &str, disclosures: Vec<DisclosureKind>) -> Decision {
        decision(
            id,
            "enroll_account",
            &DecisionKind::EnrollAccount {
                operation: OperationId::parse("op_enroll1").unwrap(),
                plan_digest: heimdall_contract::setup::PlanDigest::parse(&"b".repeat(64)).unwrap(),
                summary: EnrollmentPlanSummary {
                    destination_id: DestinationId::parse("dst-alpha").unwrap(),
                    alias: "alpha".to_owned(),
                    account: AccountName::parse("fixture").unwrap(),
                    form: EnrollmentForm::Account,
                    registry: RegistryRef {
                        path_display: "~/.ssh/authorized_keys".to_owned(),
                        resolved_by: RegistryResolvedBy::RemoteHome,
                    },
                    line_sha256: "ab".repeat(32),
                    ca_fingerprint: ca(),
                    approved_target: target("hostOld"),
                    invocation: vec!["ssh".to_owned(), "alpha".to_owned()],
                    host_trust: vec!["~/.ssh/known_hosts:3".to_owned()],
                    bootstrap: false,
                    disclosures,
                },
            },
        )
    }

    /// A pending `ApproveTargetChange` decision: the host key changed.
    pub(crate) fn target_change_decision() -> Decision {
        decision(
            "dec_target1",
            "approve_target_change",
            &DecisionKind::ApproveTargetChange {
                operation: OperationId::parse("op_verify1").unwrap(),
                enrollment: heimdall_contract::ids::EnrollmentId::from_random_bytes([7; 16]),
                approved: target("hostOld"),
                proposed: target("hostNew"),
            },
        )
    }

    /// A pending `RegisterIssuer` decision: an init, or a rotation of the fixture CA, or
    /// a key-only restore.
    pub(crate) fn register_decision(id: &str, rotation: bool, restore: bool) -> Decision {
        decision(
            id,
            "register_issuer",
            &DecisionKind::RegisterIssuer {
                ca_fingerprint: CaFingerprint::parse(&format!("SHA256:{}", "B".repeat(43)))
                    .unwrap(),
                store: heimdall_contract::issuer::StoreKind::MacosLoginKeychain,
                backup_sha256: "cd".repeat(32),
                rotation_of: rotation.then(ca),
                restored_without_log: restore,
                disclosures: vec![
                    DisclosureKind::SameUserIssuerBoundary,
                    DisclosureKind::LockContinuityOnce,
                ],
                ca_public_key: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture".to_owned()),
                backup_created_at: Some(t("2026-11-03T08:59:00Z")),
                store_locator: None,
                expected_store_locator: None,
            },
        )
    }

    /// A pending `RetireIssuer` decision for the fixture CA.
    pub(crate) fn retire_decision(id: &str) -> Decision {
        decision(
            id,
            "retire_issuer",
            &DecisionKind::RetireIssuer {
                ca_fingerprint: ca(),
                abandoned_enrollments: Vec::new(),
            },
        )
    }

    /// A pending `RemoveEnrollment` decision for enrollment `[n; 16]`.
    pub(crate) fn remove_decision(id: &str, n: u8) -> Decision {
        decision(
            id,
            "remove_enrollment",
            &DecisionKind::RemoveEnrollment {
                operation: OperationId::parse("op_remove1").unwrap(),
                target: heimdall_contract::enrollment::RemovalTarget::Enrollment {
                    enrollment_id: heimdall_contract::ids::EnrollmentId::from_random_bytes([n; 16]),
                },
                invocation: vec!["ssh".to_owned(), "alpha".to_owned()],
                affected_grants: Vec::new(),
                pair_residual_until: None,
                fresh_target: None,
            },
        )
    }

    /// A pending `EnrollSystemForm` decision for `alpha`.
    pub(crate) fn system_form_decision(id: &str) -> Decision {
        let DecisionKind::EnrollAccount {
            operation,
            plan_digest,
            summary,
        } = serde_json::from_value(enroll_decision(id, Vec::new()).request).unwrap()
        else {
            panic!("an enroll_account fixture")
        };
        decision(
            id,
            "enroll_system_form",
            &DecisionKind::EnrollSystemForm {
                operation,
                plan_digest,
                summary: EnrollmentPlanSummary {
                    form: EnrollmentForm::System,
                    ..summary
                },
                sshd_lines: heimdall_domain::decision::SystemFormLines {
                    trusted_user_ca_keys_line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture"
                        .to_owned(),
                    principals_line: "fixture".to_owned(),
                    sshd_directives: Vec::new(),
                },
            },
        )
    }

    /// The runtime's next steps of a held record (`EnrollmentView.hold.next`), as the
    /// app computes them for a host-key change (`enroll_cmd::render::held_next`).
    pub(crate) fn host_key_next(id: &str) -> Vec<String> {
        vec![
            format!("heimdall enroll verify {id} --approve-target-change"),
            format!("heimdall enroll remove {id}"),
        ]
    }

    /// An `inspect enrollments` entry for `dst-alpha` in `state`; a held one carries
    /// `hold {reason, next}` (§17.25 item 4), `next` the host-key change's two exits for
    /// `host_key_changed` and none for any other reason.
    pub(crate) fn enrollment(n: u8, state: &str, late_write: bool, hold: Option<&str>) -> Value {
        let id = heimdall_contract::ids::EnrollmentId::from_random_bytes([n; 16]);
        let mut v = serde_json::json!({
            "enrollment_id": id.to_string(), "destination_id": "dst-alpha",
            "account": "fixture", "form": "account", "ca_fingerprint": ca().to_string(),
            "marker": format!("hm:m{n}"), "state": state,
            "registry": {"path_display": "~/.ssh/authorized_keys", "resolved_by": "remote_home"},
            "destination_clock": "unmeasured",
            "approved_target": {"hostname": "alpha.example.invalid", "port": 22,
                "user": "fixture", "host_key_fingerprint": "SHA256:hostOld"},
            "live_grants": [],
        });
        if late_write {
            v["possible_late_write"] = Value::Bool(true);
        }
        if let Some(reason) = hold {
            v["hold"] = if reason == "host_key_changed" {
                serde_json::json!({"reason": reason, "next": host_key_next(&id.to_string())})
            } else {
                serde_json::json!({"reason": reason})
            };
        }
        v
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn listings_parse_tolerantly() {
        let l = Listings::of(
            &serde_json::json!({"enrollments": [
                {"enrollment_id": "enr_1", "destination_id": "dst-a", "account": "u",
                 "form": "account", "ca_fingerprint": "SHA256:ca", "marker": "hm:m",
                 "state": "held", "registry": {"path_display": "~/.ssh/authorized_keys",
                 "resolved_by": "remote_home"}, "approved_target": {"hostname": "h",
                 "port": 22, "user": "u", "host_key_fingerprint": "SHA256:hk"},
                 "possible_late_write": true},
                {"state": "verified"}
            ]}),
            &serde_json::json!({"connections": [{"kind": "dedicated", "destination_id": "dst-a",
                "policy": {"existing": "strict", "multiplexing": "disabled"},
                "closes_at": null, "state": "up"}]}),
            &Value::Null,
            &[Warning {
                code: TIME_UNCERTAIN.to_owned(),
                message: "m\u{1b}[2J".to_owned(),
                reason: Some(TIME_CHORE.to_owned()),
            }],
        );
        assert_eq!(l.enrollments.len(), 1, "an entry without an ID is skipped");
        let e = &l.enrollments[0];
        assert!(e.possible_late_write && e.needs_attention());
        assert_eq!(e.target, "h:22 as u");
        assert!(e.hold.is_none());
        assert_eq!(l.connections[0].existing, "strict");
        assert_eq!(l.time_uncertain.as_deref(), Some("m"));
        assert!(l.lock.is_none());
    }

    #[test]
    fn every_enrollment_state_has_a_text_marker() {
        for state in ENROLLMENT_STATES {
            assert_ne!(state_class(state).0, "[??]", "{state}");
        }
        assert_eq!(state_class("something_new").0, "[??]");
    }
}
