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

fn text(v: &Value, key: &str) -> Option<String> {
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

fn time(v: &Value, key: &str) -> Option<Timestamp> {
    v.get(key)?.as_str()?.parse().ok()
}

fn items<'v>(data: &'v Value, keys: &[&str]) -> &'v [Value] {
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
            noninteractive: v.get("noninteractive").and_then(Value::as_bool),
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
        })
    }

    /// The operation waiting on it, when the record names one.
    #[must_use]
    pub(crate) fn operation(&self) -> Option<String> {
        text(&self.request, "operation_id")
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
        }
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
