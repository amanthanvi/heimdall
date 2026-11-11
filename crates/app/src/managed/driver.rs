//! ⟨M03⟩ wave 4 (U10): the managed effect driver (ADR-0008 D6 items 0–1; m03-plan U0b
//! row 21): key → reserve → sign → publish → install → materialize → prepared around
//! [`ManagedEffects`] and [`IssuerPort`], with every store transaction outside any
//! adapter bound and a stage receipt between effects.
//!
//! **Order and bounds.** Each store step is one `Operations` transaction
//! (`managed_instance_created`, `reserve_issuance`, `publish_issuance`,
//! `managed_instance_installed`, `managed_stage_receipt`); each effect is one bounded
//! port call (`generate_key`, `install`: the effects' own bound; `sign`: the issuer's
//! request bound, inside the adapter-call bound). No store transaction is open while
//! an effect runs, and no effect runs inside a store transaction
//! (`managed_effect_steps_run_outside_store_transactions`).
//!
//! **Refusals** (D6 item 1). A refusal at reserve or publish (or any later failure)
//! destroys K_env and its credential instance before the error is returned; the grant
//! follows the M01 rule for that refusal (the reserve and publish transactions end it
//! for withdrawn authority or expiry), and the operation fails.
//!
//! **Materialize (step 6; ADR-0008 §17.21 item 1).** The binding ID is minted when
//! the mechanism resolves to `managed_certificate` and recorded in the operation's
//! recovery intent (`ResolvedIntent.binding_id`). The driver reads it from the open
//! operation whose `Attempted` receipt carries the effect token (`PrepareRequest` is
//! unchanged), and calls [`ManagedEffects::materialize`] for it at
//! [`BINDING_GENERATION`]: the effects create and attach the binding endpoint and
//! write the binding's files. `prepare_from` then names that endpoint in
//! `consumer.signing_endpoint`, and the commit creates the binding under the same ID.
//! Without a minted ID (the re-issue pass: no operation) nothing is materialized. A
//! failure after the materialization clears the binding (endpoint and files) with the
//! key; a failure after the driver returned is cleaned up by the operation's cleanup
//! intent (`Operations::cleanup_uncommitted_managed`).

use base64ct::{Base64Unpadded, Encoding as _};
use heimdall_contract::ids::{CredentialInstanceId, GrantId};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::issuance::{IssuanceEntry, extension_profile, principal_for};

use crate::operations::{IssuanceFacts, IssuanceRequest, Operations, Publication};
use crate::ports::{
    AdapterError, IssuanceRef, IssuanceTable, IssuerError, IssuerPort, ManagedEffects,
    ManagedPrepared, MaterializeSpec, MaterializedCertificate, PrepareRequest, PreparedCertificate,
};
use heimdall_contract::ids::BindingId;

use crate::error::OpError;

/// The stage names of the managed effect driver's receipts (ADR-0008 D6 item 1; U0b
/// row 21), written under the operation's effect token between effects. They are not
/// `EnsureStage` names, so the M01 pipeline's stage bookkeeping ignores them.
pub mod stage {
    /// K_env generated and its credential instance recorded `pending`.
    pub const KEY: &str = "managed.key";
    /// A pair's reservation committed.
    pub const RESERVE: &str = "managed.reserve";
    /// A pair's certificate signed by the issuer.
    pub const SIGN: &str = "managed.sign";
    /// A pair's entry published.
    pub const PUBLISH: &str = "managed.publish";
    /// A pair's certificate installed (after the last, the instance is `installed`).
    pub const INSTALL: &str = "managed.install";
    /// ⟨§17.21 item 1⟩ The binding's endpoint created and attached, its files written.
    pub const MATERIALIZE: &str = "managed.materialize";
    /// The driver's results handed to `prepare_from`.
    pub const PREPARED: &str = "managed.prepared";
}

/// The reason a managed preparation failed at the store, for the port: a refusal
/// the predicate names is `CapabilityUnavailable` (no fallback); the rest
/// `Unavailable` with the error's nonsecret code.
#[must_use]
pub(crate) fn adapter_error_of(e: &OpError) -> AdapterError {
    match e.code {
        Code::CapabilityUnavailable => AdapterError::CapabilityUnavailable,
        _ => AdapterError::Unavailable(
            e.reason
                .clone()
                .unwrap_or_else(|| e.code.as_str().to_owned()),
        ),
    }
}

/// The credential instance ID of the K_env whose OpenSSH SHA-256 fingerprint is
/// `fingerprint` (`SHA256:<unpadded base64>`): the digest's first 16 bytes. `None`
/// for any other form (fail closed: no instance is recorded).
#[must_use]
pub fn instance_id_for(fingerprint: &str) -> Option<CredentialInstanceId> {
    let b64 = fingerprint.strip_prefix("SHA256:")?;
    let mut buf = [0u8; 32];
    let digest = Base64Unpadded::decode(b64, &mut buf).ok()?;
    let first: [u8; 16] = digest.get(..16)?.try_into().ok()?;
    Some(CredentialInstanceId::from_random_bytes(first))
}

/// ⟨§17.21 item 1⟩ The resource generation of a binding materialized at preparation
/// (its endpoint and files; one generation per binding in M03).
pub const BINDING_GENERATION: u64 = 1;

/// How far before `now` a certificate's validity starts (ADR-0005 §3.4: clock skew
/// allowance).
pub const VALID_AFTER_SKEW_SECS: i64 = 60;

/// Publication round trips for one entry (the original reservation counts as the
/// first; `Operations::publish_issuance` refuses past `PUBLISH_ATTEMPTS`).
const PUBLISH_ROUNDS: usize = 4;

/// The `AdapterError::Unavailable` text when the issuer refused or could not sign.
/// ⟨R2-F⟩ When the issuer answered one of its store reasons, the text is
/// `issuer_sign_failed:<reason>`; read it with [`issuer_sign_failure_reason`].
pub const ISSUER_SIGN_FAILED: &str = "issuer_sign_failed";
/// The `AdapterError::Unavailable` text when a bounded effect timed out (the key
/// was destroyed: the outcome is known).
pub const EFFECT_TIMED_OUT: &str = "managed_effect_timed_out";

/// The driver body behind [`super::drive_preparation`]: the activation's stages for
/// `req.grant` (`req.grant.deadline.effective` is already the recorded bound), as a
/// new activation.
///
/// # Errors
/// [`AdapterError`]; on any error K_env and its instance are destroyed first.
pub(crate) async fn drive(
    ops: &Operations,
    effects: &dyn ManagedEffects,
    issuer: &dyn IssuerPort,
    req: PrepareRequest<'_>,
) -> Result<ManagedPrepared, AdapterError> {
    run_stages(
        ops,
        effects,
        issuer,
        req.grant,
        req.effect_token,
        req.now,
        true,
    )
    .await
}

/// The stage sequence for `grant` under `token` (activation: `new_activation`;
/// re-issue: continuing work, same pairs and deadline).
///
/// # Errors
/// [`AdapterError`]; on any error K_env and its instance are destroyed first.
pub(crate) async fn run_stages(
    ops: &Operations,
    effects: &dyn ManagedEffects,
    issuer: &dyn IssuerPort,
    grant: &GrantSnapshot,
    token: &str,
    now: Timestamp,
    new_activation: bool,
) -> Result<ManagedPrepared, AdapterError> {
    if grant.scope.pairs.is_empty() {
        return Err(AdapterError::CapabilityUnavailable);
    }
    // The binding minted at resolve (§17.21 item 1), from the operation's intent; a
    // re-issue (continuing work, no operation) materializes nothing new.
    let binding = if new_activation {
        ops.managed_binding_of_token(token)
            .await
            .map_err(|e| adapter_error_of(&e))?
    } else {
        None
    };
    let limit = ops.managed_effect_limit();
    // 1. key (an effect), then its instance `pending` and the gate (a transaction).
    let key = match tokio::time::timeout(limit, effects.generate_key(&grant.id, token)).await {
        Ok(r) => r?,
        Err(_) => return Err(AdapterError::Unavailable(EFFECT_TIMED_OUT.to_owned())),
    };
    let instance = match ops.managed_instance_created(&grant.id, &key).await {
        Ok(i) => i,
        Err(e) => {
            let _ = effects.destroy(std::slice::from_ref(&grant.id)).await;
            return Err(adapter_error_of(&e));
        }
    };
    let staged = stages_after_key(
        ops,
        effects,
        issuer,
        grant,
        token,
        now,
        new_activation,
        &key,
        &instance,
        binding.as_ref(),
    )
    .await;
    match staged {
        Ok(p) => Ok(p),
        Err(e) => {
            abandon(ops, effects, &grant.id, &instance, binding.as_ref()).await;
            Err(e)
        }
    }
}

/// Zeroize K_env and destroy its instance (D6 item 1: a refusal at reserve or
/// publish; D6 item 8 for a failed later step); ⟨§17.21 item 1⟩ a binding the driver
/// materialized loses its endpoint and files first (idempotent: nothing to clear
/// before step 6).
async fn abandon(
    ops: &Operations,
    effects: &dyn ManagedEffects,
    grant: &GrantId,
    instance: &CredentialInstanceId,
    binding: Option<&BindingId>,
) {
    if let Some(b) = binding
        && effects.clear(b, BINDING_GENERATION).is_err()
    {
        tracing::warn!("managed driver: the abandoned binding's files could not be cleared");
    }
    let _ = effects.destroy(std::slice::from_ref(grant)).await;
    if ops.managed_instance_destroyed(instance).await.is_err() {
        tracing::warn!("managed driver: the abandoned credential instance could not be updated");
    }
}

#[allow(clippy::too_many_arguments)]
async fn stages_after_key(
    ops: &Operations,
    effects: &dyn ManagedEffects,
    issuer: &dyn IssuerPort,
    grant: &GrantSnapshot,
    token: &str,
    now: Timestamp,
    new_activation: bool,
    key: &crate::ports::KeyRegistration,
    instance: &CredentialInstanceId,
    binding: Option<&BindingId>,
) -> Result<ManagedPrepared, AdapterError> {
    let receipt = |s: &'static str| async move {
        ops.managed_stage_receipt(token, s)
            .await
            .map_err(|e| adapter_error_of(&e))
    };
    receipt(stage::KEY).await?;
    let facts = IssuanceFacts {
        new_activation,
        subject_registered: true,
        critical_option: false,
    };
    let valid_after = Timestamp::from_second(now.as_second() - VALID_AFTER_SKEW_SECS)
        .map_err(|_| AdapterError::Protocol("validity_start_out_of_range".to_owned()))?;
    let env = ops.environment().clone();
    let mut published: Vec<(IssuanceEntry, String)> = Vec::new();
    for (n, pair) in grant.scope.pairs.iter().enumerate() {
        // 2. reserve (a transaction; the CA is selected inside it, D4 item 3).
        let request = IssuanceRequest {
            grant: grant.id.clone(),
            pair: pair.clone(),
            principal: principal_for(pair),
            key_id: format!(
                "heimdall:{}:{}:{}",
                env.as_str(),
                grant.id.as_str(),
                n.saturating_add(1)
            ),
            valid_after,
            valid_before: grant.deadline.effective,
            extensions: extension_profile(grant, pair),
            subject_fingerprint: key.fingerprint.clone(),
            facts: facts.clone(),
        };
        let mut entry = ops
            .reserve_issuance(request)
            .await
            .map_err(|e| adapter_error_of(&e))?;
        receipt(stage::RESERVE).await?;
        // 3. sign, 4. publish (with the re-reservation round trips).
        let mut done = None;
        for _ in 0..PUBLISH_ROUNDS {
            let cert = sign(issuer, &entry, &key.public_key, limit_of(ops)).await?;
            receipt(stage::SIGN).await?;
            match ops
                .publish_issuance(&entry.id, &facts)
                .await
                .map_err(|e| adapter_error_of(&e))?
            {
                Publication::Published(e) => {
                    done = Some((e, cert));
                    break;
                }
                Publication::Rereserved { reservation } => entry = reservation,
            }
        }
        let Some(done) = done else {
            return Err(AdapterError::Unavailable(
                "publication_rounds_exhausted".to_owned(),
            ));
        };
        receipt(stage::PUBLISH).await?;
        published.push(done);
    }
    // 5. install (each an effect, bounded by the effects; the signer's own check,
    // D2 item 6, reads the store view in its own transaction), a receipt after each.
    for (e, cert) in &published {
        match tokio::time::timeout(limit_of(ops), effects.install(&grant.id, e, cert)).await {
            Ok(Ok(())) => {}
            Ok(Err(AdapterError::OutcomeUnknown(_))) | Err(_) => {
                // The key is destroyed on return: nothing was or will be usable.
                return Err(AdapterError::Unavailable(EFFECT_TIMED_OUT.to_owned()));
            }
            Ok(Err(other)) => return Err(other),
        }
        receipt(stage::INSTALL).await?;
    }
    ops.managed_instance_installed(
        instance,
        published.iter().map(|(e, _)| e.id.clone()).collect(),
    )
    .await
    .map_err(|e| adapter_error_of(&e))?;
    // 6. materialize (§17.21 item 1): the binding's endpoint, attached, and its files
    // (synchronous file work, outside every store transaction).
    let materialized = match binding {
        None => None,
        Some(b) => {
            let spec = MaterializeSpec {
                generation: BINDING_GENERATION,
                public_key: key.public_key.clone(),
                certificates: published
                    .iter()
                    .map(|(e, cert)| MaterializedCertificate {
                        pair: e.pair.clone(),
                        certificate: cert.clone(),
                    })
                    .collect(),
                environment_slots: false,
            };
            let files = effects.materialize(b, &spec)?;
            receipt(stage::MATERIALIZE).await?;
            Some(files)
        }
    };
    // 7. prepared.
    let certificates = published
        .iter()
        .map(|(e, _)| {
            e.bounds
                .ca_fingerprint
                .clone()
                .map(|ca| PreparedCertificate {
                    pair: e.pair.clone(),
                    issuance: e.id.clone(),
                    ca,
                    valid_before: e.bounds.valid_before,
                })
                .ok_or_else(|| AdapterError::Protocol("published_entry_names_no_ca".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    receipt(stage::PREPARED).await?;
    Ok(ManagedPrepared {
        instance: instance.clone(),
        key: key.clone(),
        certificates,
        materialized,
    })
}

fn limit_of(ops: &Operations) -> std::time::Duration {
    ops.managed_effect_limit()
}

/// `IssuerPort::sign` for a grant entry, under the adapter-call bound on top of the
/// issuer's own request bound.
async fn sign(
    issuer: &dyn IssuerPort,
    entry: &IssuanceEntry,
    subject: &str,
    limit: std::time::Duration,
) -> Result<String, AdapterError> {
    let r = tokio::time::timeout(
        limit,
        issuer.sign(
            IssuanceRef {
                table: IssuanceTable::Grant,
                id: entry.id.clone(),
            },
            subject,
        ),
    )
    .await;
    match r {
        Ok(Ok(cert)) => Ok(cert),
        Ok(Err(IssuerError::Refused(_))) => Err(AdapterError::CapabilityUnavailable),
        Ok(Err(IssuerError::Unavailable(why))) => {
            Err(AdapterError::Unavailable(match issuer_store_reason(&why) {
                Some(store) => format!("{ISSUER_SIGN_FAILED}{ISSUER_SIGN_FAILED_SEP}{store}"),
                None => ISSUER_SIGN_FAILED.to_owned(),
            }))
        }
        Ok(Err(_)) | Err(_) => Err(AdapterError::Unavailable(ISSUER_SIGN_FAILED.to_owned())),
    }
}

/// The separator between [`ISSUER_SIGN_FAILED`] and the issuer's store reason.
const ISSUER_SIGN_FAILED_SEP: char = ':';

/// The issuer's store reasons a refused activation reports instead of
/// `issuer_unavailable` (ADR-0008 D3 item 7: "reason `issuer_unavailable` (or the store
/// reason)"). Any other issuer text is not carried.
fn issuer_store_reason(why: &str) -> Option<&'static str> {
    use heimdall_contract::envelope::reason;
    [
        reason::ISSUER_STORE_LOCKED,
        reason::ISSUER_STORE_UNAVAILABLE,
    ]
    .into_iter()
    .find(|r| *r == why)
}

/// ⟨M03 wave 4, round 2 (R2-F)⟩ The contract reason of a driver failure to have a
/// certificate signed, or `None` when `e` is not one: `issuer_store_locked` /
/// `issuer_store_unavailable` when the issuer answered that store reason, else
/// `issuer_unavailable` (a timeout, a restart, a protocol error, any other
/// unavailability; ADR-0008 D3 item 7).
pub fn issuer_sign_failure_reason(e: &AdapterError) -> Option<&'static str> {
    let AdapterError::Unavailable(t) = e else {
        return None;
    };
    if t == ISSUER_SIGN_FAILED {
        return Some(heimdall_contract::envelope::reason::ISSUER_UNAVAILABLE);
    }
    let rest = t.strip_prefix(ISSUER_SIGN_FAILED)?;
    let store = rest.strip_prefix(ISSUER_SIGN_FAILED_SEP)?;
    Some(
        issuer_store_reason(store)
            .unwrap_or(heimdall_contract::envelope::reason::ISSUER_UNAVAILABLE),
    )
}
