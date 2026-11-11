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
//! **Materialize (step 6) is not run at preparation** (question U10-C-Q1): the binding
//! a managed preparation materializes for is minted by the ensure pipeline's commit,
//! **after** `prepare_from`, so no binding (and no binding endpoint) exists yet. The
//! driver's results carry `materialized: None`; `prepare_from` then names no binding
//! endpoint, and nothing lists K_env on any endpoint until a later step materializes
//! a binding (fail closed: the key signs for no one).

use base64ct::{Base64Unpadded, Encoding as _};
use heimdall_contract::ids::{CredentialInstanceId, GrantId};
use heimdall_contract::{Code, Timestamp};
use heimdall_domain::grant::GrantSnapshot;
use heimdall_domain::issuance::{IssuanceEntry, extension_profile, principal_for};

use crate::operations::{IssuanceFacts, IssuanceRequest, Operations, Publication};
use crate::ports::{
    AdapterError, IssuanceRef, IssuanceTable, IssuerError, IssuerPort, ManagedEffects,
    ManagedPrepared, PrepareRequest, PreparedCertificate,
};

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

/// How far before `now` a certificate's validity starts (ADR-0005 §3.4: clock skew
/// allowance).
pub const VALID_AFTER_SKEW_SECS: i64 = 60;

/// Publication round trips for one entry (the original reservation counts as the
/// first; `Operations::publish_issuance` refuses past `PUBLISH_ATTEMPTS`).
const PUBLISH_ROUNDS: usize = 4;

/// The `AdapterError::Unavailable` text when the issuer refused or could not sign.
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
    )
    .await;
    match staged {
        Ok(p) => Ok(p),
        Err(e) => {
            abandon(ops, effects, &grant.id, &instance).await;
            Err(e)
        }
    }
}

/// Zeroize K_env and destroy its instance (D6 item 1: a refusal at reserve or
/// publish; D6 item 8 for a failed later step).
async fn abandon(
    ops: &Operations,
    effects: &dyn ManagedEffects,
    grant: &GrantId,
    instance: &CredentialInstanceId,
) {
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
    // 6. materialize: not at preparation (module docs, U10-C-Q1).
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
        materialized: None,
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
        Ok(Err(_)) | Err(_) => Err(AdapterError::Unavailable(ISSUER_SIGN_FAILED.to_owned())),
    }
}
