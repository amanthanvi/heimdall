//! `Request::Catalog`: the destination, identity and profile catalog, and owner
//! interaction declarations (ADR-0007 §7; m02-plan §5 item 3).
//!
//! Every action is effectful and journaled under kind `catalog`; the action name
//! goes into the idempotency hash extras (m02-plan §5 item 16). An identity is
//! adopted by its **public** key only: no request field carries private material.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::ids::{AccountName, DestinationId, IdentityId, ProfileId, RequestId};
use crate::managed::PreferredMechanism;
use crate::provider::EndpointRef;
use crate::request::AccessPairRef;

/// Maximum size of an adopted OpenSSH one-line public key (the 16 KiB key-file
/// bound, m02-plan §5 item 17).
pub const MAX_PUBLIC_KEY_BYTES: usize = 16 << 10;
/// Maximum size of a label.
pub const MAX_LABEL_BYTES: usize = 256;

/// How a managed destination is defined; an observed one stays in the user's file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DestinationDefinitionSpec {
    /// Rendered into the managed file P.
    Managed {
        /// `HostName`.
        hostname: String,
        /// `Port`; ssh's default when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// `User`.
        account: AccountName,
        /// The adopted identity the alias uses.
        identity: IdentityId,
    },
    /// Defined by the user; Heimdall only observes it.
    Observed,
}

/// A destination as the caller specifies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DestinationSpec {
    /// Destination ID.
    pub id: DestinationId,
    /// The OpenSSH alias.
    pub alias: String,
    /// Definition.
    pub definition: DestinationDefinitionSpec,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Where an adopted identity is used from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentitySourceSpec {
    /// A key held by a native agent at this endpoint.
    NativeAgent {
        /// The agent endpoint.
        endpoint: EndpointRef,
    },
    /// A key held by the 1Password agent.
    #[serde(rename = "onepassword")]
    OnePassword {
        /// The endpoint, when not the documented default.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<EndpointRef>,
    },
    /// A public key file (the private key is never opened).
    PublicKeyFile {
        /// Path of the `.pub` file.
        path: String,
    },
}

/// An identity to adopt. Its interaction profile comes from ADR-0007 §7, not from
/// the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentitySpec {
    /// Where it is used from.
    pub source: IdentitySourceSpec,
    /// The OpenSSH one-line public key.
    pub public_key: String,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A profile as the caller specifies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProfileSpec {
    /// Profile ID.
    pub id: ProfileId,
    /// Its destination/account pairs.
    pub pairs: BTreeSet<AccessPairRef>,
    /// Owner label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// The interaction an owner may declare (QR1). Only `none` exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeclaredInteraction {
    /// The key asks for no confirmation.
    None,
}

/// Why a declaration is withdrawn.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WithdrawReason {
    /// The owner withdrew it.
    #[default]
    Owner,
    /// An explicit agent listing lacked the fingerprint (ADR-0007 §7; QR9).
    ListingMissing,
}

/// `Request::Catalog`, tagged by `action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CatalogRequest {
    /// Create or replace a destination.
    UpsertDestination {
        /// The destination.
        destination: DestinationSpec,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Remove a destination.
    RemoveDestination {
        /// Destination ID.
        id: DestinationId,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Adopt an existing identity.
    AdoptIdentity {
        /// The identity.
        identity: IdentitySpec,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Remove an adopted identity.
    RemoveIdentity {
        /// Identity ID.
        id: IdentityId,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Create or replace a profile.
    UpsertProfile {
        /// The profile.
        profile: ProfileSpec,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Remove a profile.
    RemoveProfile {
        /// Profile ID.
        id: ProfileId,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Declare an identity's interaction; always creates a `DeclareInteraction`
    /// decision (QR1), completed only by an attended `decide`.
    DeclareInteraction {
        /// Identity ID.
        identity: IdentityId,
        /// The declared interaction.
        interaction: DeclaredInteraction,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// Withdraw a declaration (narrowing; no decision). Answered with
    /// [`WithdrawDeclarationData`].
    WithdrawDeclaration {
        /// Identity ID.
        identity: IdentityId,
        /// Expected revision: with it the withdrawal is a compare-and-swap, and a
        /// newer declaration stays live (`withdrawn: false`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revision: Option<u64>,
        /// Why.
        #[serde(default)]
        reason: WithdrawReason,
        /// Idempotency request ID.
        request_id: RequestId,
    },
    /// ⟨M03⟩ The ninth action (m03-plan §5 item 4b): a pair's preferred mechanism.
    /// Journaled under `catalog`, local only. `managed_certificate` is refused
    /// (`pair_not_enrolled`) without a `verified` enrollment for the pair; the
    /// preference takes effect for P only through `setup apply`.
    SetPreference {
        /// Destination.
        destination: DestinationId,
        /// Account.
        account: AccountName,
        /// Mechanism.
        mechanism: PreferredMechanism,
        /// Idempotency request ID.
        request_id: RequestId,
    },
}

/// A catalog request that breaks a boundary rule the wire types cannot express.
/// The catalog driver applies the full rules (alias syntax, key parsing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogRequestError {
    /// The public key is empty, longer than [`MAX_PUBLIC_KEY_BYTES`], not one line,
    /// or carries private-key armor.
    #[error("the public key must be one OpenSSH public-key line")]
    PublicKey,
    /// A label is longer than [`MAX_LABEL_BYTES`] or carries control characters.
    #[error("a label is at most 256 bytes without control characters")]
    Label,
}

fn check_label(label: Option<&String>) -> Result<(), CatalogRequestError> {
    match label {
        Some(l) if l.len() > MAX_LABEL_BYTES || l.chars().any(char::is_control) => {
            Err(CatalogRequestError::Label)
        }
        _ => Ok(()),
    }
}

impl CatalogRequest {
    /// The action name, as on the wire (part of the idempotency hash extras).
    #[must_use]
    pub fn action(&self) -> &'static str {
        match self {
            CatalogRequest::UpsertDestination { .. } => "upsert_destination",
            CatalogRequest::RemoveDestination { .. } => "remove_destination",
            CatalogRequest::AdoptIdentity { .. } => "adopt_identity",
            CatalogRequest::RemoveIdentity { .. } => "remove_identity",
            CatalogRequest::UpsertProfile { .. } => "upsert_profile",
            CatalogRequest::RemoveProfile { .. } => "remove_profile",
            CatalogRequest::DeclareInteraction { .. } => "declare_interaction",
            CatalogRequest::WithdrawDeclaration { .. } => "withdraw_declaration",
            CatalogRequest::SetPreference { .. } => "set_preference",
        }
    }

    /// The idempotency request ID.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        match self {
            CatalogRequest::UpsertDestination { request_id, .. }
            | CatalogRequest::RemoveDestination { request_id, .. }
            | CatalogRequest::AdoptIdentity { request_id, .. }
            | CatalogRequest::RemoveIdentity { request_id, .. }
            | CatalogRequest::UpsertProfile { request_id, .. }
            | CatalogRequest::RemoveProfile { request_id, .. }
            | CatalogRequest::DeclareInteraction { request_id, .. }
            | CatalogRequest::WithdrawDeclaration { request_id, .. }
            | CatalogRequest::SetPreference { request_id, .. } => request_id,
        }
    }

    /// Boundary checks: a one-line, bounded public key without private-key armor,
    /// and bounded labels.
    pub fn validate(&self) -> Result<(), CatalogRequestError> {
        match self {
            CatalogRequest::UpsertDestination { destination, .. } => {
                check_label(destination.label.as_ref())
            }
            CatalogRequest::AdoptIdentity { identity, .. } => {
                let key = &identity.public_key;
                if key.is_empty()
                    || key.len() > MAX_PUBLIC_KEY_BYTES
                    || key.chars().any(char::is_control)
                    || key.contains("PRIVATE KEY")
                {
                    return Err(CatalogRequestError::PublicKey);
                }
                check_label(identity.label.as_ref())
            }
            CatalogRequest::UpsertProfile { profile, .. } => check_label(profile.label.as_ref()),
            CatalogRequest::RemoveDestination { .. }
            | CatalogRequest::RemoveIdentity { .. }
            | CatalogRequest::RemoveProfile { .. }
            | CatalogRequest::DeclareInteraction { .. }
            | CatalogRequest::WithdrawDeclaration { .. }
            | CatalogRequest::SetPreference { .. } => Ok(()),
        }
    }
}

/// `WithdrawDeclaration` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WithdrawDeclarationData {
    /// Whether a live declaration was withdrawn (false when a newer one stays live,
    /// or none was live).
    pub withdrawn: bool,
    /// The declaration row's revision after the request.
    pub revision: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn withdraw_reason_defaults_to_owner_and_is_always_written() {
        let r: CatalogRequest = serde_json::from_str(
            r#"{"action":"withdraw_declaration","identity":"idn_00112233445566778899aabbccddeeff","request_id":"r1"}"#,
        )
        .unwrap();
        let CatalogRequest::WithdrawDeclaration {
            revision, reason, ..
        } = &r
        else {
            panic!("withdraw");
        };
        assert_eq!((*revision, *reason), (None, WithdrawReason::Owner));
        let back = serde_json::to_value(&r).unwrap();
        assert_eq!(back["reason"], "owner");
        assert!(back.get("revision").is_none());
        assert_eq!(r.action(), "withdraw_declaration");
    }

    #[test]
    fn public_key_boundary_refuses_armor_and_multiline() {
        let adopt = |key: &str| CatalogRequest::AdoptIdentity {
            identity: IdentitySpec {
                source: IdentitySourceSpec::PublicKeyFile {
                    path: "~/.ssh/id_ed25519.pub".to_owned(),
                },
                public_key: key.to_owned(),
                label: None,
            },
            request_id: RequestId::parse("r1").unwrap(),
        };
        assert_eq!(adopt("ssh-ed25519 AAAA comment").validate(), Ok(()));
        for bad in [
            String::new(),
            "ssh-ed25519 AAAA\nssh-ed25519 BBBB".to_owned(),
            // Built at run time so no armor line sits in the source.
            format!("-----BEGIN OPENSSH {} KEY-----", "PRIVATE"),
            "x".repeat(MAX_PUBLIC_KEY_BYTES + 1),
        ] {
            assert_eq!(adopt(&bad).validate(), Err(CatalogRequestError::PublicKey));
        }
    }
}
