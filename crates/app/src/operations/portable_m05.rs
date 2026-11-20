//! ⟨M05⟩ U7: export and import of portable intent (ADR-0011 §2.4 I4; ADR-0006 §17.1 items
//! 4, 5).
//!
//! **Export** ([`export_bundle`]) reads the local catalog (destinations, identity
//! references, profiles) and hands it to `heimdall_project::emit_bundle`, which has no field
//! for a policy, workspace record, environment permission, grant, decision, enrollment,
//! socket or home path, or private material, and which removes host names, addresses, ports
//! and labels when `redact` is set. Nothing of the authority tables is read.
//!
//! **Import** (`catalog apply_import`) is one journaled, owner-only, decision-free
//! reconciliation that applies catalog intent only. It computes a plan ([`plan`], pure over
//! a snapshot of the local catalog) and writes the plan's `add` entries in the caller's
//! single store transaction ([`apply_import`]); the catalog driver settles the operation in
//! that same transaction, so a crash leaves nothing or everything (M05-D07).
//!
//! * **Destinations.** A destination whose ID is not in the catalog is added as an
//!   *observed* destination named by its alias: a bundle has no link from a destination to
//!   an identity (a managed destination needs an adopted one), so the host name, port and
//!   account in the bundle are shown for comparison and never become a definition. An ID
//!   that exists with other content (another alias; for a managed one, another host name,
//!   port or account), or an alias another destination holds, is a **conflict**: reported,
//!   never overwritten. A redacted bundle's placeholder alias (the destination ID) is not
//!   compared.
//! * **Identity references** (public fingerprint and provider kind) cannot be adopted from
//!   a fingerprint alone (adoption needs the public key and endpoint), so nothing is written
//!   for one: it is `unchanged` when the fingerprint is adopted here and `needs_local`
//!   otherwise, for the owner to adopt locally.
//! * **Profiles.** An unknown ID is added with the bundle's pairs and the baseline
//!   `ssh-authentication` capability (the same default as `catalog upsert_profile`); an
//!   existing ID with other pairs is a conflict. A profile is never changed, so no existing
//!   profile, grant, binding or policy can widen (spec §6.2; R-AU-03), and a new one is
//!   covered by no policy until an attended owner decides (I1).
//! * **Host keys.** Exported fingerprints are carried in the plan for the owner's
//!   comparison and then dropped: no known-hosts file and no host-key record is written, and
//!   nothing is trusted (I4).
//!
//! The result lists the plan as applied and the importer's fixed `reestablish` sentences
//! (never the bundle's own, which are untrusted text). A re-import of the same bundle is a
//! no-op: every entry is `unchanged` (or `needs_local`).
//!
//! **Dry run** (`dry_run: true`, ADR-0006 §17.9; [`dry_run`]): the same validation and the
//! same [`plan`] over the same snapshot, answered as `{dry_run: true, would_apply, plan,
//! reestablish}` and written nowhere: a read (no operation, idempotency, event or journal
//! record).

use std::collections::{BTreeMap, BTreeSet};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, DestinationId, ProfileId};
use heimdall_contract::project::{
    PortableBundle, PortableDestination, PortableIdentity, PortableProfile,
};
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord, IdentitySource};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_project::portable::REESTABLISH;
use heimdall_project::{BundleError, BundleInput, emit_bundle, parse_bundle};
use heimdall_store::Txn;
use serde::Serialize;

/// Check a bundle a request carries the way a file's bytes are checked: bounded, the schema
/// name, every ID, alias, host name, fingerprint, provider and pair valid. (A typed request
/// cannot carry an authority section: the type has no field for one. The file path,
/// [`parse_bundle`], refuses such a section before a bundle exists.)
///
/// # Errors
/// [`BundleError`]; nothing is read or written.
pub(crate) fn validate_bundle(bundle: &PortableBundle) -> Result<(), BundleError> {
    let bytes = serde_json::to_vec(bundle).map_err(|_| BundleError::Invalid)?;
    parse_bundle(&bytes).map(|_| ())
}

/// Parse a bundle file's bytes for an import (the CLI's path, and any caller holding bytes):
/// [`parse_bundle`] with its refusals as `USAGE_ERROR`, effect `none`. An unknown top-level
/// key, or an authority section or key at any depth, refuses the whole bundle before one
/// exists to send, so nothing is written.
///
/// # Errors
/// `USAGE_ERROR`.
pub fn parse_import_bundle(bytes: &[u8]) -> Result<PortableBundle, crate::error::OpError> {
    parse_bundle(bytes).map_err(|e| {
        crate::error::OpError::new(heimdall_contract::Code::UsageError, e.to_string())
            .with_effect(heimdall_contract::envelope::EffectStatus::None)
    })
}

// --- export ---------------------------------------------------------------------------

/// The provider kind an identity reference carries (the bundle's `provider` values are
/// `ProviderKind`'s): a key file is not an agent, so it reads `unknown`.
fn provider_kind(source: &IdentitySource) -> &'static str {
    match source {
        IdentitySource::NativeAgent { .. } => "native_agent",
        IdentitySource::OnePassword { .. } => "onepassword",
        _ => "unknown",
    }
}

/// `inspect export`: a [`PortableBundle`] of the local catalog, redacted when `redact`.
///
/// # Errors
/// A store error.
pub(crate) fn export_bundle(
    tx: &mut Txn<'_>,
    redact: bool,
    now: Timestamp,
) -> heimdall_store::Result<PortableBundle> {
    let mut input = BundleInput::default();
    for d in tx.destinations()? {
        let (hostname, port, account) = match &d.definition {
            DestinationDefinition::Managed {
                hostname,
                port,
                account,
                ..
            } => (Some(hostname.clone()), *port, Some(account.clone())),
            _ => (None, None, None),
        };
        input.destinations.push(PortableDestination {
            id: d.id,
            alias: d.alias,
            hostname,
            port,
            account,
            // The catalog holds no host-key record; a host key lives with an enrollment,
            // which never travels.
            host_key_fingerprints: Vec::new(),
        });
    }
    for i in tx.identities()? {
        input.identities.push(PortableIdentity {
            provider: provider_kind(&i.source).to_owned(),
            fingerprint: i.fingerprint,
        });
    }
    for p in tx.profiles()? {
        input.profiles.push(PortableProfile {
            id: p.id,
            pairs: p
                .scope
                .pairs
                .iter()
                .map(|a| format!("{}:{}", a.destination, a.account))
                .collect(),
        });
    }
    Ok(emit_bundle(&input, redact, now))
}

// --- import: the plan -----------------------------------------------------------------

/// What import does with one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    /// Not in the catalog: written.
    Add,
    /// Already here as the bundle says: nothing to do.
    Unchanged,
    /// Here with other content, or a clash: reported, never applied.
    Conflict,
    /// An identity reference with no adopted key here: nothing can be written for it.
    NeedsLocal,
}

/// One plan entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Entry {
    /// `destination`, `identity` (its fingerprint) or `profile`.
    pub kind: &'static str,
    /// The ID (the fingerprint for an identity reference).
    pub id: String,
    /// What import does.
    pub status: Status,
    /// Why, for a conflict, and what an `add` or `needs_local` means.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// A destination's exported host-key fingerprints, shown for the owner's comparison
    /// and then dropped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host_key_fingerprints: Vec<String>,
}

/// A snapshot of the local catalog the plan is computed against.
#[derive(Debug, Default)]
pub(crate) struct Local {
    pub destinations: Vec<DestinationRecord>,
    pub fingerprints: BTreeSet<String>,
    pub profiles: Vec<ProfileDefinition>,
}

impl Local {
    fn read(tx: &mut Txn<'_>) -> heimdall_store::Result<Self> {
        Ok(Self {
            destinations: tx.destinations()?,
            fingerprints: tx
                .identities()?
                .into_iter()
                .map(|i| i.fingerprint)
                .collect(),
            profiles: tx.profiles()?,
        })
    }
}

/// The plan: every entry in the bundle's order, and the writes its `add` entries are.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    pub entries: Vec<Entry>,
    /// `(id, alias)` of each destination to add (as an observed destination).
    pub add_destinations: Vec<(DestinationId, String)>,
    pub add_profiles: Vec<(ProfileId, BTreeSet<AccessPair>)>,
}

fn entry(kind: &'static str, id: String, status: Status, reason: Option<&'static str>) -> Entry {
    Entry {
        kind,
        id,
        status,
        reason,
        host_key_fingerprints: Vec::new(),
    }
}

/// Whether the catalog's record says what the bundle's destination says. Only what the
/// bundle carries is compared: a redacted bundle's alias is a placeholder, and the host
/// name, port and account of a bundle that has them are compared with a managed record
/// (an observed one has none to differ).
fn same_destination(local: &DestinationRecord, d: &PortableDestination, redacted: bool) -> bool {
    if !redacted && local.alias != d.alias {
        return false;
    }
    match &local.definition {
        DestinationDefinition::Managed {
            hostname,
            port,
            account,
            ..
        } => {
            d.hostname.as_ref().is_none_or(|h| h == hostname)
                && d.port.is_none_or(|p| Some(p) == *port)
                && d.account.as_ref().is_none_or(|a| a == account)
        }
        _ => true,
    }
}

fn parse_pairs(pairs: &[String]) -> Option<BTreeSet<AccessPair>> {
    pairs
        .iter()
        .map(|t| {
            let (d, a) = t.split_once(':')?;
            Some(AccessPair {
                destination: DestinationId::parse(d).ok()?,
                account: AccountName::parse(a).ok()?,
            })
        })
        .collect()
}

/// Plan the import of `bundle` against `local`. Pure and total: the same inputs give the
/// same plan, and an entry that repeats an earlier one's ID in the bundle is a conflict.
pub(crate) fn plan(bundle: &PortableBundle, local: &Local) -> Plan {
    let mut out = Plan::default();
    let by_id: BTreeMap<&DestinationId, &DestinationRecord> =
        local.destinations.iter().map(|d| (&d.id, d)).collect();
    let by_alias: BTreeMap<&str, &DestinationId> = local
        .destinations
        .iter()
        .map(|d| (d.alias.as_str(), &d.id))
        .collect();
    let mut seen_ids: BTreeSet<&DestinationId> = BTreeSet::new();
    let mut claimed_aliases: BTreeSet<&str> = BTreeSet::new();
    for d in &bundle.destinations {
        let id = d.id.as_str().to_owned();
        let (status, reason) = if !seen_ids.insert(&d.id) {
            (Status::Conflict, Some("duplicate_in_bundle"))
        } else if let Some(stored) = by_id.get(&d.id) {
            if same_destination(stored, d, bundle.redacted) {
                (Status::Unchanged, None)
            } else {
                (Status::Conflict, Some("differs_locally"))
            }
        } else if by_alias.contains_key(d.alias.as_str())
            || claimed_aliases.contains(d.alias.as_str())
        {
            (Status::Conflict, Some("alias_collision"))
        } else {
            claimed_aliases.insert(d.alias.as_str());
            out.add_destinations.push((d.id.clone(), d.alias.clone()));
            (Status::Add, Some("recorded_as_observed"))
        };
        let mut e = entry("destination", id, status, reason);
        e.host_key_fingerprints = d.host_key_fingerprints.clone();
        out.entries.push(e);
    }
    let mut seen_fingerprints: BTreeSet<&str> = BTreeSet::new();
    for i in &bundle.identities {
        let (status, reason) = if !seen_fingerprints.insert(i.fingerprint.as_str()) {
            (Status::Conflict, Some("duplicate_in_bundle"))
        } else if local.fingerprints.contains(&i.fingerprint) {
            (Status::Unchanged, None)
        } else {
            (Status::NeedsLocal, Some("adopt_locally"))
        };
        out.entries
            .push(entry("identity", i.fingerprint.clone(), status, reason));
    }
    let profiles: BTreeMap<&ProfileId, &ProfileDefinition> =
        local.profiles.iter().map(|p| (&p.id, p)).collect();
    let mut seen_profiles: BTreeSet<&ProfileId> = BTreeSet::new();
    for p in &bundle.profiles {
        let pairs = parse_pairs(&p.pairs);
        let (status, reason) = if !seen_profiles.insert(&p.id) {
            (Status::Conflict, Some("duplicate_in_bundle"))
        } else {
            match (&pairs, profiles.get(&p.id)) {
                (None, _) => (Status::Conflict, Some("invalid")),
                (Some(pairs), Some(stored)) => {
                    if stored.scope.pairs == *pairs {
                        (Status::Unchanged, None)
                    } else {
                        (Status::Conflict, Some("differs_locally"))
                    }
                }
                (Some(pairs), None) => {
                    out.add_profiles.push((p.id.clone(), pairs.clone()));
                    (Status::Add, None)
                }
            }
        };
        out.entries
            .push(entry("profile", p.id.as_str().to_owned(), status, reason));
    }
    out
}

// --- import: the transaction ----------------------------------------------------------

/// Apply `bundle`'s catalog intent in the caller's transaction and answer the plan as
/// applied. Writes only destinations and profiles that are not in the catalog.
///
/// # Errors
/// A store error (the caller's transaction rolls back whole).
pub(crate) fn apply_import(
    tx: &mut Txn<'_>,
    bundle: &PortableBundle,
    now: Timestamp,
) -> heimdall_store::Result<serde_json::Value> {
    let local = Local::read(tx)?;
    let plan = plan(bundle, &local);
    for (id, alias) in &plan.add_destinations {
        tx.upsert_destination(&DestinationRecord {
            id: id.clone(),
            alias: alias.clone(),
            revision: 1,
            definition: DestinationDefinition::Observed,
            label: None,
            updated_at: now,
        })?;
    }
    for (id, pairs) in &plan.add_profiles {
        // After the highest revision ever pinned (a profile removed earlier keeps its
        // snapshots), as `catalog upsert_profile` does.
        let revision = tx
            .profile_latest_revision(id)?
            .unwrap_or(0)
            .saturating_add(1);
        tx.upsert_profile(&ProfileDefinition {
            id: id.clone(),
            revision,
            scope: Scope {
                pairs: pairs.clone(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            },
            label: None,
        })?;
    }
    Ok(result(&plan, false))
}

/// `catalog apply_import` with `dry_run` (ADR-0006 §17.9): the plan a real import of
/// `bundle` would apply, computed over the same snapshot and by the same [`plan`], and
/// nothing written. Run in a read; it needs no operation.
///
/// # Errors
/// A store error.
pub(crate) fn dry_run(
    tx: &mut Txn<'_>,
    bundle: &PortableBundle,
) -> heimdall_store::Result<serde_json::Value> {
    let local = Local::read(tx)?;
    Ok(result(&plan(bundle, &local), true))
}

/// The import's answer. A real import answers `applied` (its counts), the plan and the
/// importer's `reestablish` list; a dry run answers the same plan, `dry_run: true` and the
/// counts as `would_apply`.
fn result(plan: &Plan, dry_run: bool) -> serde_json::Value {
    let count = |s: Status| plan.entries.iter().filter(|e| e.status == s).count();
    let counts = serde_json::json!({
        "added": count(Status::Add),
        "unchanged": count(Status::Unchanged),
        "conflicts": count(Status::Conflict),
        "needs_local": count(Status::NeedsLocal),
    });
    if dry_run {
        return serde_json::json!({
            "dry_run": true,
            "would_apply": counts,
            "plan": plan.entries,
            "reestablish": REESTABLISH,
        });
    }
    serde_json::json!({
        "applied": counts,
        "plan": plan.entries,
        "reestablish": REESTABLISH,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::project::PORTABLE_BUNDLE_SCHEMA;

    fn fp(c: char) -> String {
        format!("SHA256:{}", c.to_string().repeat(43))
    }

    fn bundle() -> PortableBundle {
        PortableBundle {
            schema: PORTABLE_BUNDLE_SCHEMA.to_owned(),
            created_at: "2026-11-18T09:00:00Z".parse().unwrap(),
            redacted: false,
            destinations: vec![PortableDestination {
                id: DestinationId::parse("lab-db").unwrap(),
                alias: "lab-db".into(),
                hostname: Some("db.example.invalid".into()),
                port: None,
                account: Some(AccountName::parse("deploy").unwrap()),
                host_key_fingerprints: vec![fp('A')],
            }],
            identities: vec![PortableIdentity {
                fingerprint: fp('B'),
                provider: "native_agent".into(),
            }],
            profiles: vec![PortableProfile {
                id: ProfileId::parse("dev").unwrap(),
                pairs: vec!["lab-db:deploy".into()],
            }],
            reestablish: vec!["untrusted text".into()],
        }
    }

    /// Entries keep the bundle's order; an entry repeating an ID or fingerprint is a
    /// conflict and never a second write; host-key fingerprints stay on the destination's
    /// entry (for comparison) and nowhere else.
    #[test]
    fn duplicates_in_a_bundle_are_conflicts_and_fingerprints_ride_the_entry() {
        let mut b = bundle();
        b.destinations.push(b.destinations[0].clone());
        b.identities.push(b.identities[0].clone());
        b.profiles.push(b.profiles[0].clone());
        let p = plan(&b, &Local::default());
        let statuses: Vec<_> = p.entries.iter().map(|e| (e.kind, e.status)).collect();
        assert_eq!(
            statuses,
            [
                ("destination", Status::Add),
                ("destination", Status::Conflict),
                ("identity", Status::NeedsLocal),
                ("identity", Status::Conflict),
                ("profile", Status::Add),
                ("profile", Status::Conflict),
            ]
        );
        assert_eq!((p.add_destinations.len(), p.add_profiles.len()), (1, 1));
        assert_eq!(p.entries[0].host_key_fingerprints, vec![fp('A')]);
        assert!(p.entries[2].host_key_fingerprints.is_empty());
    }

    /// Two different IDs claiming one alias: the first is added, the second is a
    /// collision, so the transaction can never hit the store's unique alias.
    #[test]
    fn one_alias_is_claimed_once() {
        let mut b = bundle();
        let mut second = b.destinations[0].clone();
        second.id = DestinationId::parse("lab-db-2").unwrap();
        b.destinations.push(second);
        let p = plan(&b, &Local::default());
        assert_eq!(p.entries[1].status, Status::Conflict);
        assert_eq!(p.entries[1].reason, Some("alias_collision"));
        assert_eq!(p.add_destinations.len(), 1);
    }
}
