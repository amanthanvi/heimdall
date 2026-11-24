//! ⟨rev7⟩ Typed read views (ADR-0013 §11 D1 and D9; §12 PC2 and PC3).
//!
//! Revision 7 publishes a typed view, with a schema, for every list and read subject of
//! `inspect`, for `status`, `service status`, the operation view, the subscription head of
//! `operation events --follow`, the NDJSON stream line, and `environment status`. The
//! types were inventoried from today's builders field by field
//! (`tests/contracts/golden/views-null-inventory.md`).
//!
//! **Not emitted yet (U0).** No emitter uses these types: today's builders still assemble
//! untyped JSON. U3 switches each builder to its view, in one change with its readers and
//! goldens (ADR-0013 §1.3, RC09).
//!
//! **Keys are kept** (D1), subject metadata included (`inspect operations`' `counts`,
//! `inspect projections`' `record`).
//!
//! **Omitted versus `null`** (D9; ADR-0006 §9). An optional field is omitted when it does
//! not apply; no view field is required-nullable. Every view still *reads* today's
//! documents: a field that today's builder writes as `null` is an `Option` that
//! deserializes `null` as absent, so the revision-7 form (omitted) differs from today's
//! only where the inventory marks a PC3 change. Nested documents that a builder copies
//! verbatim from a persisted record (a decision's `request`, an authority delta) stay
//! [`serde_json::Value`]: persisted payloads are unchanged (D9).
//!
//! Already typed elsewhere, so not repeated here: `inspect workspace`
//! ([`crate::trust::WorkspaceView`]), `inspect policies` ([`crate::trust::PoliciesView`]),
//! `inspect issuer` ([`crate::issuer::IssuerStatus`]), `inspect enrollments`
//! ([`crate::enrollment::EnrollmentsView`]), `inspect connections`
//! ([`crate::managed::ConnectionsView`]), `inspect export`
//! ([`crate::project::PortableBundle`]), and the owner's `items` of `inspect environments`
//! ([`crate::environment::EnvironmentsView`]; the subject's other keys are
//! [`environment::EnvironmentListView`]).

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::Timestamp;
use crate::code::Code;
use crate::ids::ProfileId;
use crate::request::{AccessPairRef, Capability};
use crate::schema::NamedSchema;

pub mod access;
pub mod catalog;
pub mod environment;
pub mod operations;
pub mod status;
pub mod stream;

/// A set of destination/account pairs and the capabilities permitted on them, as views
/// show a scope (the domain `Scope`'s wire form: two arrays, each sorted and unique).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScopeView {
    /// Destination/account pairs.
    pub pairs: Vec<AccessPairRef>,
    /// Capabilities permitted on every pair.
    pub capabilities: Vec<Capability>,
}

/// `inspect --preview`'s `preview` key: resolution without effects, added to the data of
/// any subject but `export` when the request carries `preview`. Tagged by `outcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviewView {
    /// Existing authority covers the request.
    Allowed {
        /// What would be resolved.
        snapshot: PreviewSnapshot,
        /// The effective authority (the domain `EffectiveAuthority`, verbatim).
        effective: serde_json::Value,
    },
    /// Only the delta needs an owner decision.
    ApprovalRequired {
        /// What would be resolved.
        snapshot: PreviewSnapshot,
        /// What existing authority already covers (the domain `EffectiveAuthority`,
        /// verbatim). Omitted when nothing is covered (today: `null`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        covered: Option<serde_json::Value>,
        /// What needs a decision (the domain `AuthorityDelta`, verbatim).
        delta: serde_json::Value,
    },
    /// Refused.
    Denied {
        /// The refusal's code.
        code: Code,
        /// The refusal's message.
        message: String,
    },
}

/// ⟨rev7⟩ A subject's view typed elsewhere, with `inspect --preview`'s `preview` key beside
/// its own keys (the ruling of 2026-11-24 on D1 question 5): the view's keys are flattened, so
/// the document is one flat object, and `preview` is omitted without a preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WithPreview<T> {
    /// The subject's own view.
    #[serde(flatten)]
    pub view: T,
    /// `inspect --preview`'s result. Omitted without a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewView>,
}

/// What a preview would resolve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreviewSnapshot {
    /// The profile.
    pub profile: ProfileId,
    /// Its current revision.
    pub profile_revision: u64,
    /// The requested scope.
    pub requested: ScopeView,
    /// The deadline that would be enforced.
    pub deadline: Timestamp,
    /// The mechanism that would serve it. Omitted when no adapter is resolved (today:
    /// `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mechanism: Option<String>,
}

/// `skip_serializing_if` for a flag omitted when false.
fn is_false(b: &bool) -> bool {
    !*b
}

fn named<T: JsonSchema>(name: &'static str) -> NamedSchema {
    NamedSchema {
        name,
        schema: schema_for!(T),
    }
}

/// ⟨rev7⟩ One schema per typed view (D1), in a stable order. Every name is unique and none
/// is a name of [`crate::schema::public_schemas`].
#[must_use]
pub fn view_schemas() -> Vec<NamedSchema> {
    vec![
        named::<status::CapabilitiesView>("inspect-capabilities"),
        named::<environment::EnvironmentListView>("inspect-environments.full"),
        named::<catalog::ProfileListView>("inspect-profiles"),
        named::<catalog::DestinationListView>("inspect-destinations"),
        named::<access::BindingListView>("inspect-bindings"),
        named::<access::GrantListView>("inspect-grants"),
        named::<operations::OperationListView>("inspect-operations"),
        named::<access::DecisionListView>("inspect-decisions"),
        named::<catalog::IdentityListView>("inspect-identities"),
        named::<catalog::ProjectionListView>("inspect-projections"),
        named::<status::StatusView>("status"),
        named::<status::ServiceStatusView>("service-status"),
        named::<operations::OperationView>("operation"),
        named::<stream::SubscriptionHeadView>("subscription-head"),
        named::<stream::StreamLine>("stream-line"),
        named::<environment::EnvironmentStatusView>("environment-status"),
        named::<environment::GrantResidual>("grant-residual"),
        // The subjects whose view is typed elsewhere, with `preview` beside it. A public name
        // with `.full` is the view U3 swaps in by a rename (ruled 2026-11-24).
        named::<WithPreview<crate::trust::WorkspaceView>>("inspect-workspace.full"),
        named::<WithPreview<crate::trust::PoliciesView>>("inspect-policies.full"),
        named::<WithPreview<crate::issuer::IssuerStatus>>("inspect-issuer"),
        named::<WithPreview<crate::enrollment::EnrollmentsView>>("inspect-enrollments"),
        named::<WithPreview<crate::managed::ConnectionsView>>("inspect-connections"),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The ruling's condition: a flattened view is one flat object, `preview` among its
    /// properties beside the view's own, with no `additionalProperties: false`.
    #[test]
    fn with_preview_is_one_flat_object() {
        let v =
            serde_json::to_value(schema_for!(WithPreview<crate::trust::WorkspaceView>)).unwrap();
        assert_eq!(v["type"], "object", "{v}");
        assert!(v.get("allOf").is_none() && v.get("oneOf").is_none(), "{v}");
        let props = v["properties"].as_object().unwrap();
        assert!(props.contains_key("preview"));
        let own = serde_json::to_value(schema_for!(crate::trust::WorkspaceView)).unwrap();
        for k in own["properties"].as_object().unwrap().keys() {
            assert!(props.contains_key(k), "{k}");
        }
        assert_ne!(v["additionalProperties"], serde_json::json!(false));
        for s in view_schemas().into_iter().filter(|s| {
            s.name.ends_with(".full")
                || s.name.starts_with("inspect-issuer")
                || s.name == "inspect-enrollments"
                || s.name == "inspect-connections"
        }) {
            let v = serde_json::to_value(&s.schema).unwrap();
            assert_eq!(v["type"], "object", "{}", s.name);
            assert!(
                v.get("allOf").is_none() && v.get("oneOf").is_none(),
                "{}",
                s.name
            );
            assert!(v["properties"].get("preview").is_some(), "{}", s.name);
        }
    }

    #[test]
    fn view_schemas_generate_unique_and_disjoint() {
        let views = view_schemas();
        let mut names: Vec<&str> = views.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), views.len());
        let public = crate::schema::public_schemas();
        for s in &views {
            assert!(
                public.iter().all(|p| p.name != s.name),
                "{} is a public schema",
                s.name
            );
            assert!(
                serde_json::to_value(&s.schema).unwrap().is_object(),
                "{}",
                s.name
            );
        }
    }
}
