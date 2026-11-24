//! ⟨rev7⟩ The compact primitive set exposed to agents (ADR-0013 §9, D7): what
//! `heimdall --json schema show primitives` prints, offline.
//!
//! Exactly six groups. Each gives its CLI and wire forms, the schemas of its answers, the
//! codes it can answer with each code's exit class and default next action (from the code
//! table, so they cannot drift), whether it takes a `request_id`, and who may call it. The
//! forms are the ones this build serves; a form a later revision adds (`inspect`'s `select`
//! and `page`, ADR-0013 D2) joins its group when it is served.
//!
//! **Excluded** (ADR-0013 §9): pause, resume, cutoff, broader `access stop`, `access allow`,
//! decisions, time confirmation, setup, enrollment, the issuer and uninstall. Consent never
//! comes from the agent surface.

use crate::code::Code;
use crate::ipc::capability;
use crate::remote::Role;

/// Whether a form takes an idempotency `request_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestIdUse {
    /// The form requires one (the CLI mints one when none is given).
    Required,
    /// The form takes none.
    None,
}

impl RequestIdUse {
    fn as_str(self) -> &'static str {
        match self {
            RequestIdUse::Required => "required",
            RequestIdUse::None => "none",
        }
    }
}

/// One form of a primitive.
#[derive(Debug, Clone, Copy)]
pub struct Form {
    /// The wire request kind (`Request::kind`), or the IPC message for a subscription.
    pub wire: &'static str,
    /// The CLI form.
    pub cli: &'static str,
    /// The capabilities a session needs for it.
    pub capabilities: &'static [&'static str],
    /// Whether it takes a `request_id`.
    pub request_id: RequestIdUse,
}

/// One of the six groups.
#[derive(Debug, Clone, Copy)]
pub struct Group {
    /// The group's name.
    pub name: &'static str,
    /// Its forms.
    pub forms: &'static [Form],
    /// The published schemas of its answers (`schema show <name>`).
    pub schemas: &'static [&'static str],
    /// The codes its forms answer with.
    pub codes: &'static [Code],
    /// The roles whose sessions may send it.
    pub roles: &'static [Role],
    /// Which caller of those roles may act, in words.
    pub callers: &'static str,
}

const OPS: &[&str] = &[capability::OPERATIONS_V1];
const OPS_EVENTS: &[&str] = &[capability::OPERATIONS_V1, capability::EVENTS_V1];

/// The codes every form can answer whatever it asks (a refused or failed exchange).
const COMMON: &[Code] = &[
    Code::UsageError,
    Code::SchemaUnsupported,
    Code::ServiceUnavailable,
    Code::StateUnavailable,
    Code::Backpressure,
    Code::InternalError,
];

/// The six groups, in ADR-0013 §9's order.
pub const GROUPS: &[Group] = &[
    Group {
        name: "inspect",
        forms: &[Form {
            wire: "inspect",
            cli: "heimdall --json inspect <subject> [--preview <profile> [--environment E] [--until T | --for D] [--require-* …]]",
            capabilities: OPS,
            request_id: RequestIdUse::None,
        }],
        schemas: &[
            "inspect-environments",
            "inspect-workspace",
            "inspect-policies",
            "issuer-status",
            "envelope.error",
        ],
        codes: &[Code::Ok, Code::NotFound, Code::CapabilityUnavailable],
        roles: &[Role::Owner, Role::Requester, Role::Viewer],
        callers: "every role, within its visibility",
    },
    Group {
        name: "ensure",
        forms: &[Form {
            wire: "ensure",
            cli: "heimdall --json --non-interactive access ensure --profile P --work-id W --request-id R [--pair D:A …] [--environment E] [--until T | --for D] [--async] [--timeout-ms N] [--require-* …]",
            capabilities: OPS,
            request_id: RequestIdUse::Required,
        }],
        schemas: &["envelope.ensure", "envelope.error"],
        codes: &[
            Code::AccessReady,
            Code::Accepted,
            Code::ApprovalRequired,
            Code::InteractionRequired,
            Code::ProviderLocked,
            Code::CapabilityUnavailable,
            Code::PolicyPaused,
            Code::PolicyCutoff,
            Code::CredentialExpired,
            Code::HostTrustChanged,
            Code::OperationCancelled,
            Code::DestinationUnreachable,
            Code::TimeUncertain,
            Code::UnsupportedClient,
            Code::RequestConflict,
            Code::RequestExpired,
            Code::DecisionStale,
            Code::OutcomeUnknown,
            Code::NotFound,
        ],
        roles: &[Role::Owner, Role::Requester],
        callers: "owner, requester",
    },
    Group {
        name: "bind",
        forms: &[
            Form {
                wire: "bind",
                cli: "heimdall run [--profile P] [--work-id W] [--request-id R] [--meta-fd N | --meta-file F] -- <argv>",
                capabilities: OPS,
                request_id: RequestIdUse::Required,
            },
            Form {
                wire: "bind",
                cli: "(wire only: materialize)",
                capabilities: OPS,
                request_id: RequestIdUse::Required,
            },
        ],
        schemas: &["run-record", "envelope.ensure", "envelope.error"],
        codes: &[
            Code::AccessReady,
            Code::ApprovalRequired,
            Code::InteractionRequired,
            Code::ProviderLocked,
            Code::CapabilityUnavailable,
            Code::PolicyPaused,
            Code::PolicyCutoff,
            Code::CredentialExpired,
            Code::DestinationUnreachable,
            Code::TimeUncertain,
            Code::UnsupportedClient,
            Code::RequestConflict,
            Code::RequestExpired,
            Code::OutcomeUnknown,
            Code::NotFound,
            Code::LaunchFailed,
        ],
        roles: &[Role::Owner, Role::Requester],
        callers: "the binding's holder; the owner",
    },
    Group {
        name: "delegate",
        forms: &[
            Form {
                wire: "delegate",
                cli: "heimdall --json access delegate --parent B --work-id W --request-id R [--pair D:A …] [--until T]",
                capabilities: OPS,
                request_id: RequestIdUse::Required,
            },
            Form {
                wire: "delegate",
                cli: "heimdall run --parent-binding B [--scope D:A …] [--until T] -- <argv>",
                capabilities: OPS,
                request_id: RequestIdUse::Required,
            },
        ],
        schemas: &["envelope.ensure", "run-record", "envelope.error"],
        codes: &[
            Code::AccessReady,
            Code::CapabilityUnavailable,
            Code::CredentialExpired,
            Code::DelegationExceedsParent,
            Code::RequestConflict,
            Code::RequestExpired,
            Code::OutcomeUnknown,
            Code::NotFound,
            Code::LaunchFailed,
        ],
        roles: &[Role::Owner, Role::Requester],
        callers: "the parent binding's holder",
    },
    Group {
        name: "observe",
        forms: &[
            Form {
                wire: "observe",
                cli: "heimdall --json operation show|wait [--operation O]",
                capabilities: OPS,
                request_id: RequestIdUse::None,
            },
            Form {
                wire: "observe",
                cli: "heimdall --json operation events [--operation O] [--cursor C] [--limit N]",
                capabilities: OPS_EVENTS,
                request_id: RequestIdUse::None,
            },
            Form {
                wire: "subscribe",
                cli: "heimdall --json operation events --follow [--operation O] [--cursor C] [--max-events N]",
                capabilities: OPS_EVENTS,
                request_id: RequestIdUse::None,
            },
            Form {
                wire: "cancel",
                cli: "heimdall --json operation cancel --operation O",
                capabilities: OPS,
                request_id: RequestIdUse::None,
            },
        ],
        schemas: &["envelope", "event", "snapshot", "envelope.error"],
        codes: &[
            Code::Ok,
            Code::Accepted,
            Code::OperationCancelled,
            Code::ResyncRequired,
            Code::OutcomeUnknown,
            Code::NotFound,
        ],
        roles: &[Role::Owner, Role::Requester, Role::Viewer],
        callers: "the operation's caller; the local owner",
    },
    Group {
        name: "release_revoke",
        forms: &[
            Form {
                wire: "release",
                cli: "heimdall --json access release <binding>",
                capabilities: OPS,
                request_id: RequestIdUse::None,
            },
            Form {
                wire: "revoke",
                cli: "heimdall --json access revoke <grant> --request-id R",
                capabilities: OPS,
                request_id: RequestIdUse::Required,
            },
        ],
        schemas: &["envelope", "envelope.revoke", "envelope.error"],
        codes: &[
            Code::Ok,
            Code::CapabilityUnavailable,
            Code::RequestConflict,
            Code::RequestExpired,
            Code::OutcomeUnknown,
            Code::NotFound,
        ],
        roles: &[Role::Owner, Role::Requester],
        callers: "release: the holder; revoke: the grant's holder, own grant only, or the owner",
    },
];

/// What the agent surface never offers (ADR-0013 §9 "Excluded").
pub const EXCLUDED: &[&str] = &[
    "pause",
    "resume",
    "cutoff",
    "access stop (broader than one work)",
    "access allow",
    "decisions",
    "time confirmation",
    "setup",
    "enrollment",
    "the issuer",
    "uninstall",
];

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Requester => "requester",
        Role::Viewer => "viewer",
    }
}

fn code_row(code: &Code) -> serde_json::Value {
    serde_json::json!({
        "code": code.as_str(),
        "exit_code": code.exit_code().as_i32(),
        "next_action": code.default_next_action(),
    })
}

/// The index as `schema show primitives` prints it (stable key and row order).
#[must_use]
pub fn index() -> serde_json::Value {
    let groups: Vec<serde_json::Value> = GROUPS
        .iter()
        .map(|g| {
            let mut codes: Vec<&Code> = g.codes.iter().chain(COMMON.iter()).collect();
            codes.dedup();
            serde_json::json!({
                "group": g.name,
                "forms": g.forms.iter().map(|f| serde_json::json!({
                    "wire": f.wire,
                    "cli": f.cli,
                    "capabilities": f.capabilities,
                    "request_id": f.request_id.as_str(),
                })).collect::<Vec<_>>(),
                "schemas": g.schemas,
                "codes": codes.into_iter().map(code_row).collect::<Vec<_>>(),
                "roles": g.roles.iter().map(|r| role_name(*r)).collect::<Vec<_>>(),
                "callers": g.callers,
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": crate::SCHEMA_VERSION,
        "groups": groups,
        "excluded": EXCLUDED,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn six_groups_with_unique_names_and_codes() {
        assert_eq!(GROUPS.len(), 6);
        let mut names: Vec<&str> = GROUPS.iter().map(|g| g.name).collect();
        names.dedup();
        assert_eq!(names.len(), 6);
        for g in GROUPS {
            let mut codes: Vec<&str> = g.codes.iter().map(Code::as_str).collect();
            codes.sort_unstable();
            let before = codes.len();
            codes.dedup();
            assert_eq!(codes.len(), before, "{}: a repeated code", g.name);
            for c in g.codes {
                assert!(!COMMON.contains(c), "{}: {c} is common", g.name);
                assert!(!matches!(c, Code::Unknown(_)));
            }
        }
    }
}
