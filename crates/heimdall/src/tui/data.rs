//! What the TUI shows, read from the runtime's `inspect` answers and the local passive
//! doctor (m02-plan U10).
//!
//! Every record is parsed tolerantly from the envelope's JSON: a field the runtime
//! does not send reads as absent, never as a guess. Every string that came from the
//! runtime, the configuration or the filesystem passes through [`clean`] before it is
//! drawn, so a label or a path can never carry a terminal escape (spec §14.3).

use heimdall_contract::Timestamp;
use heimdall_contract::doctor::DoctorReport;
use serde_json::Value;

/// `s` with every control character and escape sequence removed and newlines and tabs
/// turned into spaces: safe to place in one terminal cell row.
#[must_use]
pub(crate) fn clean(s: &str) -> String {
    crate::output::sanitize_for_terminal(s)
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .collect()
}

pub(crate) fn text(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(clean(s)),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn text_or(v: &Value, key: &str, default: &str) -> String {
    text(v, key).unwrap_or_else(|| default.to_owned())
}

pub(crate) fn time(v: &Value, key: &str) -> Option<Timestamp> {
    v.get(key)?.as_str()?.parse().ok()
}

pub(crate) fn items<'v>(data: &'v Value, keys: &[&str]) -> &'v [Value] {
    keys.iter()
        .find_map(|k| data.get(*k).and_then(Value::as_array))
        .map_or(&[], Vec::as_slice)
}

/// Where the runtime connection stands.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Runtime {
    /// Not contacted yet.
    #[default]
    Connecting,
    /// Connected; the snapshot below is the runtime's.
    Connected,
    /// No runtime is running; the TUI does not start one by itself.
    NotRunning,
    /// The connection failed (message).
    Failed(String),
}

/// A catalog destination (`inspect destinations`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Destination {
    /// Destination ID.
    pub id: String,
    /// Alias.
    pub alias: String,
    /// `managed` or `observed`.
    pub definition: String,
    /// Label.
    pub label: Option<String>,
    /// Catalog revision.
    pub revision: Option<String>,
    /// Last catalog change.
    pub updated_at: Option<Timestamp>,
    /// Managed: rendered host name.
    pub hostname: Option<String>,
    /// Managed: rendered port.
    pub port: Option<String>,
    /// Managed: rendered account.
    pub account: Option<String>,
    /// Managed: its identity.
    pub identity_id: Option<String>,
    /// ⟨M03⟩ Managed: the pair preference (`inspect destinations` `preference`).
    pub preference: Option<super::m03::Preference>,
}

impl Destination {
    fn of(v: &Value) -> Option<Self> {
        Some(Self {
            id: text(v, "destination_id").unwrap_or_default(),
            alias: text(v, "alias")?,
            definition: text_or(v, "definition", "managed"),
            label: text(v, "label"),
            revision: text(v, "revision"),
            updated_at: time(v, "updated_at"),
            hostname: text(v, "hostname"),
            port: text(v, "port"),
            account: text(v, "account"),
            identity_id: text(v, "identity_id"),
            preference: v.get("preference").and_then(super::m03::Preference::of),
        })
    }

    /// Whether Heimdall renders it into P.
    #[must_use]
    pub(crate) fn is_managed(&self) -> bool {
        self.definition != "observed"
    }
}

/// One pair of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pair {
    /// Destination ID.
    pub destination: String,
    /// Account.
    pub account: String,
}

/// A catalog profile (`inspect profiles`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Profile {
    /// Profile ID.
    pub id: String,
    /// Revision.
    pub revision: Option<String>,
    /// Label.
    pub label: Option<String>,
    /// Pairs.
    pub pairs: Vec<Pair>,
}

impl Profile {
    fn of(v: &Value) -> Option<Self> {
        Some(Self {
            id: text(v, "profile_id")?,
            revision: text(v, "revision"),
            label: text(v, "label"),
            pairs: items(v, &["pairs"])
                .iter()
                .map(|p| Pair {
                    destination: text_or(p, "destination", "?"),
                    account: text_or(p, "account", "?"),
                })
                .collect(),
        })
    }
}

/// An adopted identity (`inspect identities`) with its fresh eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    /// Identity ID.
    pub id: String,
    /// `SHA256:…`.
    pub fingerprint: String,
    /// Key type.
    pub key_type: Option<String>,
    /// Mechanism (`native_agent`, `onepassword`).
    pub mechanism: Option<String>,
    /// Endpoint locator, when recorded.
    pub endpoint: Option<String>,
    /// Interaction kind.
    pub interaction: String,
    /// How it was established (`declared`, `documented`, `inferred`, `observed`).
    pub basis: Option<String>,
    /// When the live declaration was made.
    pub declared_at: Option<Timestamp>,
    /// When the live declaration expires.
    pub declaration_expires_at: Option<Timestamp>,
    /// Whether non-interactive work may use it now.
    pub noninteractive: Option<bool>,
    /// When the runtime computed the eligibility.
    pub checked_at: Option<Timestamp>,
}

impl Identity {
    fn of(v: &Value) -> Option<Self> {
        let endpoint = v.get("endpoint").and_then(|e| {
            e.get("locator")
                .and_then(Value::as_str)
                .map(clean)
                .or_else(|| e.as_str().map(clean))
        });
        let declaration = v.get("declaration").filter(|d| !d.is_null());
        Some(Self {
            id: text(v, "identity_id")?,
            fingerprint: text_or(v, "fingerprint", "?"),
            key_type: text(v, "key_type"),
            mechanism: text(v, "mechanism"),
            endpoint,
            interaction: text_or(v, "interaction", "unknown"),
            basis: text(v, "interaction_basis"),
            declared_at: time(v, "declared_at"),
            declaration_expires_at: declaration.and_then(|d| time(d, "expires_at")),
            // The runtime sends `noninteractive` as the eligibility object
            // (`contract::provider::NoninteractiveEligibility`: `eligible`, and `reason` when
            // not), never a bare boolean (M07 W9; U0's D1 typed-view survey).
            noninteractive: v
                .get("noninteractive")
                .and_then(|n| n.get("eligible"))
                .and_then(Value::as_bool),
            checked_at: time(v, "eligibility_checked_at"),
        })
    }
}

/// An open or unresolved operation (`inspect operations`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Operation {
    /// Operation ID.
    pub id: String,
    /// Kind (`ensure`, `setup.apply`, …).
    pub kind: String,
    /// State (`queued`, `running`, `awaiting_approval`, `outcome_unknown`, …).
    pub state: String,
    /// Result code, once known.
    pub code: Option<String>,
    /// Effect status.
    pub effect: Option<String>,
    /// Created.
    pub created_at: Option<Timestamp>,
    /// Updated.
    pub updated_at: Option<Timestamp>,
    /// The stored result (redacted JSON).
    pub result: Option<Value>,
}

/// The reason the runtime gives a held setup operation (ADR-0007 §5.7 outcome H).
pub(crate) const PROJECTION_HELD: &str = "projection_held";

impl Operation {
    pub(crate) fn of(v: &Value) -> Option<Self> {
        Some(Self {
            id: text(v, "operation_id")?,
            kind: text_or(v, "kind", "?"),
            state: text_or(v, "state", "?"),
            code: text(v, "code"),
            effect: text(v, "effect_status"),
            created_at: time(v, "created_at"),
            updated_at: time(v, "updated_at"),
            result: v.get("result").filter(|r| !r.is_null()).cloned(),
        })
    }

    /// The error reason the stored result names, if any.
    #[must_use]
    pub(crate) fn reason(&self) -> Option<String> {
        let r = self.result.as_ref()?;
        r.get("error")
            .and_then(|e| e.get("reason"))
            .or_else(|| r.get("reason"))
            .and_then(Value::as_str)
            .map(clean)
    }

    /// The message the stored result carries, if any.
    #[must_use]
    pub(crate) fn message(&self) -> Option<String> {
        let r = self.result.as_ref()?;
        r.get("error")
            .and_then(|e| e.get("message"))
            .or_else(|| r.get("message"))
            .and_then(Value::as_str)
            .map(clean)
    }

    /// A setup operation held for the owner (ADR-0007 §5.7): `outcome_unknown` with
    /// the reason `projection_held`. Its two repairs are `retry_held` and `keep_held`.
    #[must_use]
    pub(crate) fn is_held(&self) -> bool {
        self.kind.starts_with("setup")
            && self.state == "outcome_unknown"
            && self.reason().as_deref() == Some(PROJECTION_HELD)
    }

    /// Unresolved: its effect is not known (`outcome_unknown`).
    #[must_use]
    pub(crate) fn is_unresolved(&self) -> bool {
        self.state == "outcome_unknown"
    }

    /// Still in progress (`queued`, `running`, `awaiting_approval`).
    #[must_use]
    pub(crate) fn is_active(&self) -> bool {
        matches!(
            self.state.as_str(),
            "queued" | "running" | "awaiting_approval"
        )
    }
}

/// A pending owner decision (`inspect decisions`), with its exact recorded request.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Decision {
    /// Decision ID.
    pub id: String,
    /// Kind (`approve_authority`, `apply_projection`, `declare_interaction`, …).
    pub kind: String,
    /// Created.
    pub created_at: Option<Timestamp>,
    /// Expires.
    pub expires_at: Option<Timestamp>,
    /// Whether the runtime already considers it expired.
    pub expired: bool,
    /// The exact recorded request.
    pub request: Value,
    /// ⟨M05, ADR-0006 §17.9 C1⟩ For a targeted widening, the policies approval changes,
    /// fixed when the record was created (`policy_id`, `revision`); empty otherwise.
    pub policies: Vec<(String, u64)>,
    /// ⟨M05, ADR-0006 §17.10 item 22⟩ For a `create`, the scope its approval applies, as the
    /// runtime recorded it; `None` otherwise, and for a missing or malformed one (never a
    /// guess: the TUI then refuses to approve it, `tui::m05::approve_block`).
    pub scope: Option<heimdall_contract::trust::DecisionScope>,
}

impl Decision {
    fn of(v: &Value) -> Option<Self> {
        Some(Self {
            id: text(v, "decision_id")?,
            kind: text_or(v, "kind", "?"),
            created_at: time(v, "created_at"),
            expires_at: time(v, "expires_at"),
            expired: v.get("expired").and_then(Value::as_bool) == Some(true),
            request: v.get("request").cloned().unwrap_or(Value::Null),
            policies: v
                .get("policies")
                .and_then(Value::as_array)
                .map(|ps| {
                    ps.iter()
                        .filter_map(|p| {
                            Some((
                                text(p, "policy_id")?,
                                p.get("revision").and_then(Value::as_u64)?,
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default(),
            scope: v
                .get("scope")
                .cloned()
                .and_then(|s| serde_json::from_value(s).ok()),
        })
    }

    /// The operation waiting on it, when the record names one (⟨M03⟩ the M03 kinds'
    /// records name it `operation`).
    #[must_use]
    pub(crate) fn operation(&self) -> Option<String> {
        text(&self.request, "operation_id").or_else(|| text(&self.request, "operation"))
    }
}

/// The runtime's answers of one refresh.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Catalog {
    /// Destinations.
    pub destinations: Vec<Destination>,
    /// Profiles.
    pub profiles: Vec<Profile>,
    /// Identities.
    pub identities: Vec<Identity>,
    /// Open and unresolved operations.
    pub operations: Vec<Operation>,
    /// Pending decisions.
    pub decisions: Vec<Decision>,
    /// The committed projection generation (`inspect projections` record).
    pub projection_generation: Option<u64>,
    /// When it was read.
    pub read_at: Option<Timestamp>,
    /// ⟨M03⟩ The M03 listings and conditions of the same refresh.
    pub m03: super::m03::Listings,
    /// ⟨M05⟩ The trusted-work listings of the same refresh (workspace status, policies).
    pub m05: super::m05::Listings,
    /// ⟨M07⟩ `inspect environments` of the same refresh (the runtime's own first).
    pub environments: super::m07::Environments,
    /// ⟨M07⟩ The listings whose last read failed, by subject wire name
    /// (`destinations`, `profiles`, ...). A failed subject keeps its last good data
    /// above, which is then stale (Q4: a failed listing is never shown as empty).
    pub failures: std::collections::BTreeMap<String, ListingFailure>,
}

/// ⟨M07⟩ Why a listing's last read failed (m07-plan U1; ruling Q4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListingFailure {
    /// The answer's code (for example `INTERNAL_ERROR`).
    pub code: String,
    /// The answer's message, cleaned.
    pub message: String,
    /// Since when the reads have failed with this code and message (the first failed
    /// read; a repeat of the same failure keeps it, so an unchanged failure redraws
    /// nothing).
    pub since: Timestamp,
    /// When the data still shown was read (the last good read), if there was one.
    pub stale_from: Option<Timestamp>,
}

/// ⟨M07⟩ The wire names of the listings the views name in their error state.
pub(crate) mod subject {
    /// `inspect destinations`.
    pub(crate) const DESTINATIONS: &str = "destinations";
    /// `inspect profiles`.
    pub(crate) const PROFILES: &str = "profiles";
    /// `inspect operations`.
    pub(crate) const OPERATIONS: &str = "operations";
    /// `inspect decisions`.
    pub(crate) const DECISIONS: &str = "decisions";
    /// `inspect enrollments`.
    pub(crate) const ENROLLMENTS: &str = "enrollments";
    /// ⟨M07⟩ `inspect environments`.
    pub(crate) const ENVIRONMENTS: &str = "environments";
    /// ⟨M07⟩ `inspect identities`.
    pub(crate) const IDENTITIES: &str = "identities";
    /// ⟨M07⟩ `inspect connections`.
    pub(crate) const CONNECTIONS: &str = "connections";
    /// ⟨M07⟩ `inspect capabilities` (the lock report).
    pub(crate) const CAPABILITIES: &str = "capabilities";
    /// ⟨M07⟩ `inspect policies` (standing access and the default profiles).
    pub(crate) const POLICIES: &str = "policies";
    /// ⟨M07⟩ `inspect workspace` (the working directory's project).
    pub(crate) const WORKSPACE: &str = "workspace";
}

/// ⟨M07⟩ How far a value read from some listings can be claimed (M07-W0-R03): a view
/// states a value, or its absence, only for a listing that was read; otherwise it says
/// what is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    /// Every listing was read in the latest refresh.
    Fresh,
    /// A listing's latest read failed: its last good data is shown and may have changed.
    Stale,
    /// A listing has never been read: nothing can be said from it.
    Unread,
}

impl Known {
    /// ` (stale)` after a value that may have changed, nothing after a fresh one.
    #[must_use]
    pub(crate) fn suffix(self) -> &'static str {
        match self {
            Known::Stale => " (stale)",
            _ => "",
        }
    }
}

impl Catalog {
    /// Parse the `data` of the six `inspect` answers (any may be `Null`).
    #[must_use]
    pub(crate) fn from_answers(
        destinations: &Value,
        profiles: &Value,
        identities: &Value,
        operations: &Value,
        decisions: &Value,
        projections: &Value,
        read_at: Timestamp,
    ) -> Self {
        let generation = projections.get("record").and_then(|r| {
            r.get("items")
                .and_then(Value::as_object)
                .and_then(|items| {
                    items
                        .values()
                        .filter_map(|i| i.get("generation").and_then(Value::as_u64))
                        .max()
                })
                .or_else(|| r.get("generation").and_then(Value::as_u64))
        });
        Self {
            destinations: items(destinations, &["destinations", "items"])
                .iter()
                .filter_map(Destination::of)
                .collect(),
            profiles: items(profiles, &["profiles", "items"])
                .iter()
                .filter_map(Profile::of)
                .collect(),
            identities: items(identities, &["identities"])
                .iter()
                .filter_map(Identity::of)
                .collect(),
            operations: items(operations, &["operations"])
                .iter()
                .filter_map(Operation::of)
                .collect(),
            decisions: items(decisions, &["decisions"])
                .iter()
                .filter_map(Decision::of)
                .collect(),
            projection_generation: generation,
            read_at: Some(read_at),
            m03: super::m03::Listings::default(),
            m05: super::m05::Listings::default(),
            environments: super::m07::Environments::default(),
            failures: std::collections::BTreeMap::new(),
        }
    }

    /// ⟨M07⟩ Whether `other` lists the same things: every field but the read times
    /// (`read_at`, each identity's `checked_at`): a poll whose answers change nothing
    /// draws nothing (m07-plan U1).
    #[must_use]
    pub(crate) fn same_listings(&self, other: &Self) -> bool {
        // Destructured, so a new field cannot be forgotten here.
        let Self {
            destinations,
            profiles,
            identities,
            operations,
            decisions,
            projection_generation,
            read_at: _,
            m03,
            m05,
            environments,
            failures,
        } = self;
        // An identity's `checked_at` is the time of the read (the runtime checks
        // eligibility as it answers), so, like `read_at`, it is not a change.
        let same_identities = identities.len() == other.identities.len()
            && identities.iter().zip(&other.identities).all(|(a, b)| {
                Identity {
                    checked_at: None,
                    ..a.clone()
                } == Identity {
                    checked_at: None,
                    ..b.clone()
                }
            });
        *destinations == other.destinations
            && *profiles == other.profiles
            && same_identities
            && *operations == other.operations
            && *decisions == other.decisions
            && *projection_generation == other.projection_generation
            && *m03 == other.m03
            && *m05 == other.m05
            && *environments == other.environments
            && *failures == other.failures
    }

    /// ⟨M07⟩ How far values read from the listings `subjects` can be claimed: not at
    /// all before the first refresh or when one of them was never read, as stale when one
    /// of their latest reads failed.
    #[must_use]
    pub(crate) fn known(&self, subjects: &[&str]) -> Known {
        let failed = |s: &&str| self.failures.get(*s);
        if self.read_at.is_none()
            || subjects
                .iter()
                .filter_map(failed)
                .any(|f| f.stale_from.is_none())
        {
            Known::Unread
        } else if subjects.iter().any(|s| failed(s).is_some()) {
            Known::Stale
        } else {
            Known::Fresh
        }
    }

    /// ⟨M07⟩ The failure of the listing `subject` ([`subject`]), if its last read failed.
    #[must_use]
    pub(crate) fn failure(&self, subject: &str) -> Option<&ListingFailure> {
        self.failures.get(subject)
    }

    /// The destination with this alias.
    #[must_use]
    pub(crate) fn destination(&self, alias: &str) -> Option<&Destination> {
        self.destinations.iter().find(|d| d.alias == alias)
    }

    /// The identity with this ID.
    #[must_use]
    pub(crate) fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }

    /// The identity with this fingerprint.
    #[must_use]
    pub(crate) fn identity_by_fingerprint(&self, fingerprint: &str) -> Option<&Identity> {
        self.identities
            .iter()
            .find(|i| i.fingerprint == fingerprint)
    }
}

/// The passive doctor's report and when it was taken.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Doctor {
    /// The report (static level only).
    pub report: DoctorReport,
    /// When the static pass ran.
    pub taken_at: Timestamp,
}

/// One event of an operation (`observe events`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EventLine {
    /// Event type.
    pub kind: String,
    /// Runtime time.
    pub at: Option<Timestamp>,
    /// A one-line summary of the payload (state, code).
    pub summary: String,
}

impl EventLine {
    /// From one event of an events page.
    #[must_use]
    pub(crate) fn of(v: &Value) -> Self {
        let payload = v.get("payload").unwrap_or(&Value::Null);
        let mut parts = Vec::new();
        for key in [
            "state",
            "from",
            "to",
            "code",
            "reason",
            "stage",
            "effect_status",
        ] {
            if let Some(t) = text(payload, key) {
                parts.push(format!("{key}={t}"));
            }
        }
        Self {
            kind: text_or(v, "type", "?"),
            at: time(v, "timestamp"),
            summary: parts.join(" "),
        }
    }
}

/// An operation as its detail view shows it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OperationDetail {
    /// The operation (`observe operation`), when it could be read.
    pub operation: Option<Operation>,
    /// Its events so far (oldest first, bounded).
    pub events: Vec<EventLine>,
    /// The last error reading it, if any.
    pub error: Option<String>,
}

/// Most events an operation detail keeps.
pub(crate) const MAX_EVENTS: usize = 256;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ⟨M07 W9⟩ The identity's non-interactive state is read from the object the runtime
    /// emits (`inspect identities`, observed from the real binary in a scratch home:
    /// `{"eligible": false, "reason": "interaction_unknown"}`), built here from the
    /// contract type itself so the test follows the emitter.
    #[test]
    fn an_identitys_noninteractive_state_is_read_from_the_eligibility_object() {
        use heimdall_contract::provider::NoninteractiveEligibility;
        let identity = |eligibility: NoninteractiveEligibility| {
            serde_json::json!({
                "identity_id": "idn_fixture",
                "fingerprint": "SHA256:fixture",
                "noninteractive": eligibility,
            })
        };
        let eligible = NoninteractiveEligibility {
            eligible: true,
            reason: None,
        };
        let refused = NoninteractiveEligibility {
            eligible: false,
            reason: Some("interaction_unknown".to_owned()),
        };
        assert_eq!(
            Identity::of(&identity(eligible)).unwrap().noninteractive,
            Some(true)
        );
        assert_eq!(
            Identity::of(&identity(refused)).unwrap().noninteractive,
            Some(false)
        );
        let absent = serde_json::json!({"identity_id": "idn_fixture"});
        assert_eq!(Identity::of(&absent).unwrap().noninteractive, None);
    }

    #[test]
    fn clean_removes_escapes_and_controls_and_flattens_lines() {
        // The CSI goes whole; an OSC loses its introducer and its BEL, so no byte of it
        // can reach the terminal as a control.
        assert_eq!(
            clean("a\u{1b}[31mb\u{1b}]0;x\u{7}c\nd\te\u{0}"),
            "ab0;xc d e"
        );
        assert_eq!(clean("plain"), "plain");
    }

    #[test]
    fn a_held_setup_operation_is_recognized_by_its_reason() {
        let op = |kind: &str, state: &str, reason: &str| {
            Operation::of(&serde_json::json!({
                "operation_id": "op_1", "kind": kind, "state": state,
                "result": {"error": {"reason": reason, "message": "m"}},
            }))
            .unwrap()
        };
        assert!(op("setup.apply", "outcome_unknown", PROJECTION_HELD).is_held());
        assert!(op("setup.repair", "outcome_unknown", PROJECTION_HELD).is_held());
        assert!(!op("setup.apply", "failed", PROJECTION_HELD).is_held());
        assert!(!op("ensure", "outcome_unknown", PROJECTION_HELD).is_held());
        assert!(!op("setup.apply", "outcome_unknown", "other").is_held());
        assert!(op("setup.apply", "outcome_unknown", "other").is_unresolved());
    }

    #[test]
    fn catalog_listings_parse_tolerantly() {
        let c = Catalog::from_answers(
            &serde_json::json!({"items": [
                {"destination_id": "dst-a", "alias": "alpha", "definition": "managed",
                 "hostname": "a.example.invalid", "port": 22, "account": "u", "identity_id": "idn_1"},
                {"destination_id": "dst-b", "alias": "be\u{1b}[2Jta", "definition": "observed"},
                {"destination_id": "dst-c"}
            ]}),
            &serde_json::json!({"items": [{"profile_id": "dev", "pairs": [{"destination": "dst-a", "account": "u"}]}]}),
            &serde_json::json!({"identities": [{"identity_id": "idn_1", "fingerprint": "SHA256:x",
                "endpoint": {"kind": "unix_socket", "locator": "/s/agent.sock"},
                "interaction": "none", "interaction_basis": "declared",
                "declared_at": "2026-11-01T10:00:00Z",
                "declaration": {"revision": 1, "expires_at": "2026-12-01T10:00:00Z"}}]}),
            &serde_json::json!({"operations": []}),
            &serde_json::json!({"decisions": []}),
            &serde_json::json!({"record": {"items": {"ssh": {"generation": 3}}}}),
            "2026-11-03T09:00:00Z".parse().unwrap(),
        );
        assert_eq!(
            c.destinations.len(),
            2,
            "an item without an alias is skipped"
        );
        assert_eq!(c.destinations[1].alias, "beta");
        assert!(!c.destinations[1].is_managed());
        assert_eq!(c.destinations[0].port.as_deref(), Some("22"));
        assert_eq!(c.profiles[0].pairs[0].destination, "dst-a");
        let id = &c.identities[0];
        assert_eq!(id.endpoint.as_deref(), Some("/s/agent.sock"));
        assert_eq!(id.basis.as_deref(), Some("declared"));
        assert!(id.declared_at.is_some() && id.declaration_expires_at.is_some());
        assert_eq!(c.projection_generation, Some(3));
    }
}
