//! JSON Schema generation for the public contract (plan §4.5, §7.4; R-AP-02).
//!
//! `heimdall schema export` writes these to `schemas/public-api/`; the validation
//! script regenerates and diffs them so generated artifacts never drift from the
//! canonical Rust model.

use schemars::{JsonSchema, Schema, schema_for};

/// A named schema document.
#[derive(Debug, Clone)]
pub struct NamedSchema {
    /// File stem, e.g. `envelope.error`.
    pub name: &'static str,
    /// The schema.
    pub schema: Schema,
}

fn named<T: JsonSchema>(name: &'static str) -> NamedSchema {
    NamedSchema {
        name,
        schema: schema_for!(T),
    }
}

/// Every public schema in a stable order.
#[must_use]
pub fn public_schemas() -> Vec<NamedSchema> {
    use crate::envelope::{Envelope, ErrorData};
    use crate::event::{Event, EventSnapshotData, Snapshot};
    use crate::ipc::{ClientMessage, ServerMessage};
    use crate::request::{EnsureData, Request, RevokeData};

    vec![
        named::<Envelope<serde_json::Value>>("envelope"),
        named::<Envelope<ErrorData>>("envelope.error"),
        named::<Envelope<EnsureData>>("envelope.ensure"),
        named::<Envelope<RevokeData>>("envelope.revoke"),
        named::<Request>("request"),
        named::<Event>("event"),
        // ⟨rev7; PC1⟩ A snapshot's `data` is the typed `event-snapshot` (ADR-0013 §5.5).
        named::<Snapshot<EventSnapshotData>>("snapshot"),
        named::<ClientMessage>("ipc.client-message"),
        named::<ServerMessage>("ipc.server-message"),
        named::<crate::code::Code>("code"),
        // ADR-0006 revision 3 (m02-plan §5 items 2, 11, 12).
        named::<crate::doctor::DoctorReport>("doctor-report"),
        named::<crate::run_record::RunRecord>("run-record"),
        named::<crate::setup::SetupPlan>("setup-plan"),
        named::<crate::setup::SetupResult>("setup-result"),
        // ⟨M03⟩ ADR-0006 revision 4 (m03-plan §5 item 23).
        named::<crate::enrollment::EnrollmentPlan>("enrollment-plan"),
        named::<crate::enrollment::EnrollmentResult>("enrollment-result"),
        named::<crate::issuer::IssuerStatus>("issuer-status"),
        named::<crate::issuer::RecoveryBundle>("recovery-bundle"),
        // ⟨rev5⟩ ADR-0006 revision 5 (§17): the result views of the new inspect
        // subjects. (The two trusted-work file formats are [`project_schemas`].)
        named::<crate::environment::EnvironmentsView>("inspect-environments"),
        named::<crate::trust::WorkspaceView>("inspect-workspace"),
        named::<crate::trust::PoliciesView>("inspect-policies"),
        // ⟨rev5.1⟩ ADR-0006 §17.9 C2: the typed result of a targeted policy action.
        named::<crate::trust::PolicyTargetResult>("policy-target-result"),
        // ⟨rev6.5⟩ ADR-0006 §18.9 item 8: the typed parts of a decision document (the
        // `request` of a `remote_widening` decision, with its `origin`; one entry of a
        // `widen_policy` decision's `lifted_effects`).
        named::<crate::decision::RemoteWidening>("decision.remote-widening"),
        named::<crate::decision::LiftedEffect>("decision.lifted-effect"),
    ]
}

/// ⟨rev7⟩ The directory under the public schemas' directory that holds
/// [`declared_schemas`] (`schemas/public-api/declared/`).
pub const DECLARED_DIR: &str = "declared";

/// ⟨rev7⟩ The schemas revision 7 **declares**: the standalone types of ADR-0013 §11 and
/// ADR-0014 §7 that no live document carries yet (the ruling on S0). They are exported to
/// [`DECLARED_DIR`] and answered by `schema show <name>`, but they are not
/// [`public_schemas`]: `inspect capabilities` does not list them, and no published schema
/// of a live document changes. The change that attaches a type to its live document, with
/// its emitters and readers, moves its schema to [`public_schemas`].
#[must_use]
pub fn declared_schemas() -> Vec<NamedSchema> {
    let mut out = vec![
        // ADR-0013 D2: pages and selectors.
        named::<crate::page::PageRequest>("page-request"),
        named::<crate::page::Select>("select"),
        named::<crate::page::Page<serde_json::Value>>("page"),
        named::<crate::page::Selection<serde_json::Value>>("selection"),
        // D4, D6: the typed snapshot (⟨rev7; PC1⟩ emitted as `snapshot`'s `data` now; it
        // is promoted with every typed view in U3-3's one promotion commit, ruled
        // 2026-11-26) and the resync reasons.
        named::<crate::event::EventSnapshotData>("event-snapshot"),
        named::<crate::event::ResyncReason>("resync-reason"),
        // D5: the typed payloads, as emitted.
        named::<crate::event_payload::EventPayload>("event-payload"),
        // D13, D19: typed refusal details.
        named::<crate::envelope::LiveAccessRefusal>("error.destination-has-live-access"),
        named::<crate::envelope::ResponseTooLarge>("error.response-too-large"),
        named::<crate::envelope::ItemTooLarge>("error.item-too-large"),
        // U0-Q4, Q7.
        named::<crate::run_record::LaunchProvenanceEntry>("launch-provenance"),
        named::<crate::request_state::RequestView>("inspect-request"),
        // ADR-0014 H1, H2, H3, H4/H10, H7; U0-Q8.
        named::<crate::lifecycle::SupportBundleManifest>("support-bundle-manifest"),
        named::<crate::lifecycle::StopPreview>("service-stop-preview"),
        named::<crate::lifecycle::StateStatus>("state-status"),
        named::<crate::lifecycle::RestoreReport>("state-restore"),
        named::<crate::lifecycle::ResetReport>("state-reset"),
        named::<crate::lifecycle::RepairReport>("state-repair"),
        named::<crate::lifecycle::StateRestoredPayload>("event.state-restored"),
        named::<crate::lifecycle::BuildProvenance>("build-provenance"),
    ];
    out.extend(crate::views::view_schemas());
    out
}

/// ⟨rev5⟩ ADR-0006 revision 5 (§17; m05-plan §4 item 11): the trusted-work file
/// formats, written to `schemas/project/` (`manifest`, `portable`). Not wire messages:
/// the manifest is a **closed** schema (ADR-0011 §2.2, any unknown key rejects the
/// file), so these documents are outside the public API's unknown-field tolerance
/// (ADR-0006 §9) and its keyword check.
#[must_use]
pub fn project_schemas() -> Vec<NamedSchema> {
    vec![
        named::<crate::project::Manifest>("manifest"),
        named::<crate::project::PortableBundle>("portable"),
    ]
}

/// The stable code table as a JSON document (code, exit, retryable, effect, next).
#[must_use]
pub fn code_table() -> serde_json::Value {
    let rows: Vec<serde_json::Value> = crate::code::Code::all()
        .iter()
        .map(|c| {
            serde_json::json!({
                "code": c.as_str(),
                "exit_code": c.exit_code().as_i32(),
                "retryable": c.retryable(),
                "default_effect_status": c.default_effect_status(),
                "default_next_action": c.default_next_action(),
                "success": c.is_success(),
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": crate::SCHEMA_VERSION,
        "codes": rows,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn schemas_generate_and_are_unique() {
        let all = public_schemas();
        let mut names: Vec<&str> = all.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len());
        for s in &all {
            let v = serde_json::to_value(&s.schema).unwrap();
            assert!(v.is_object(), "{}", s.name);
        }
    }

    #[test]
    fn code_table_lists_every_code() {
        let table = code_table();
        assert_eq!(
            table["codes"].as_array().unwrap().len(),
            crate::code::Code::all().len()
        );
    }
}
