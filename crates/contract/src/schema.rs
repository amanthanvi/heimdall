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
    use crate::event::{Event, Snapshot};
    use crate::ipc::{ClientMessage, ServerMessage};
    use crate::request::{EnsureData, Request, RevokeData};

    vec![
        named::<Envelope<serde_json::Value>>("envelope"),
        named::<Envelope<ErrorData>>("envelope.error"),
        named::<Envelope<EnsureData>>("envelope.ensure"),
        named::<Envelope<RevokeData>>("envelope.revoke"),
        named::<Request>("request"),
        named::<Event>("event"),
        named::<Snapshot<serde_json::Value>>("snapshot"),
        named::<ClientMessage>("ipc.client-message"),
        named::<ServerMessage>("ipc.server-message"),
        named::<crate::code::Code>("code"),
        // ADR-0006 revision 3 (m02-plan §5 items 2, 11, 12).
        named::<crate::doctor::DoctorReport>("doctor-report"),
        named::<crate::run_record::RunRecord>("run-record"),
        named::<crate::setup::SetupPlan>("setup-plan"),
        named::<crate::setup::SetupResult>("setup-result"),
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
