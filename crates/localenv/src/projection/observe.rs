//! Passive observation (m02-plan U4): aliases against the projection record, and the
//! held steps of an intent. Moves nothing and writes nothing.
//!
//! `observe` evaluates each alias statically (the U2 evaluator over the bounded,
//! read-only configuration source; nothing executes), with P as the managed root so
//! values read from P carry the managed role, under every invocation profile a launch
//! can use, combined into one observation that no profile is better than (ADR-0007
//! §12.28 item 5): the runtime's no-interaction readiness reads it, so it clears a
//! selection only when the CLI's pre-launch check would clear it in every profile.
//! `observe_held` runs the recovery engine's observation and decision without a sink:
//! it reports the steps a restart would hold, with their classification and content
//! fingerprints (M2-T03).

use std::path::Path;

use heimdall_app::ports::{HeldStep, ReconcileError};
use heimdall_contract::doctor::{
    AliasDefinition, AliasObservation, ConfigProvenance, DirectiveCertainty, DirectiveObservation,
};
use heimdall_contract::provider::{
    Certainty, IdentitiesOnly, IdentityEntry, IdentitySelection, IdentitySelectionReport,
};
use heimdall_contract::setup::ProjectionItem;
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{FileRole, ProjectionRecord, SetupIntent};
use heimdall_sshconf::directive::KnownKeyword;
use heimdall_sshconf::eval::{
    Candidate, Evaluation, Invocation, OpenSshVersion, Query, Resolved, SourceRole, Value, evaluate,
};
use heimdall_sshconf::include::{ConfigSet, ConfigSource, Roots};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::relevant::{identity_selection, managed_identity_selection, relevant};
use heimdall_sshconf::render::ManagedIdentityForm;

use super::ProjectionConfig;
use crate::clients::ClientKind;
use crate::fs::BoundedSource;

/// Re-evaluate `aliases` statically against `record` under every invocation profile
/// a launch can use, `Shell`, `Exec(None)` and `Subsystem("sftp")`, each alias's
/// observations combined by [`combine_profiles`] (ADR-0007 §12.28 item 5). This is what
/// `ProjectionWriter::observe` answers, so the runtime's no-interaction readiness at
/// `ensure` clears a selection under every profile, as the pre-launch check does
/// (§12.25 item 1), for an API caller as for the CLI. The local account is the account
/// database's ([`observe_under`]).
#[must_use]
pub fn observe(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
) -> Vec<AliasObservation> {
    observe_all_as(config, record, aliases, crate::doctor::local_account())
}

/// [`observe`] with the local account given (`None`: it cannot be established).
#[must_use]
pub fn observe_all_as(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
    local_user: Option<String>,
) -> Vec<AliasObservation> {
    let per_profile: Vec<Vec<AliasObservation>> = Invocation::consent_profiles()
        .iter()
        .map(|invocation| observe_as(config, record, aliases, invocation, local_user.clone()))
        .collect();
    (0..aliases.len())
        .filter_map(|i| {
            let observations: Vec<&AliasObservation> =
                per_profile.iter().filter_map(|p| p.get(i)).collect();
            combine_profiles(&observations)
        })
        .collect()
}

/// ADR-0007 §12.28 item 5: one alias's observations under several invocation profiles
/// as one observation that no profile is better than (fail closed). `None` without an
/// observation.
///
/// * **Behaviour:** a directive every profile observes alike is kept; one the profiles
///   observe differently is `undetermined`, with every profile's values and provenance
///   (each once, in profile order), because which applies depends on the invocation.
/// * **Identity selection:** `None` when no profile reports one. Otherwise `exclusive`
///   only when every profile reports `exclusive`; `undetermined` when a profile reports
///   none or `undetermined`; else `not_exclusive`. The entries are every profile's
///   entries, each once (by kind, source, provenance, fingerprint and backing),
///   `undetermined` where any profile has it undetermined, with no stored `cleared`
///   (readiness evaluates clearance itself). `IdentitiesOnly` is kept when every
///   profile reports the same value, else `undetermined`. So the fallback clearance
///   over the combined report clears it only when it would clear every profile's: an
///   exec-only or subsystem-only fallback identity is an alternative to clear.
#[must_use]
pub fn combine_profiles(observations: &[&AliasObservation]) -> Option<AliasObservation> {
    let first = *observations.first()?;
    let behavior = first
        .behavior
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let all: Vec<&DirectiveObservation> = observations
                .iter()
                .filter_map(|o| o.behavior.get(i))
                .filter(|o| o.directive == d.directive)
                .collect();
            if all.len() == observations.len() && all.iter().all(|o| *o == d) {
                return d.clone();
            }
            let mut values = Vec::new();
            let mut provenance = Vec::new();
            for o in observations
                .iter()
                .flat_map(|o| o.behavior.iter().filter(|b| b.directive == d.directive))
            {
                for v in &o.values {
                    if !values.contains(v) {
                        values.push(v.clone());
                    }
                }
                for p in &o.provenance {
                    if !provenance.contains(p) {
                        provenance.push(p.clone());
                    }
                }
            }
            DirectiveObservation {
                directive: d.directive.clone(),
                values,
                certainty: DirectiveCertainty::Undetermined,
                provenance,
            }
        })
        .collect();
    let reports: Vec<Option<&IdentitySelectionReport>> = observations
        .iter()
        .map(|o| o.identity_selection.as_ref())
        .collect();
    let identity_selection = if reports.iter().all(Option::is_none) {
        None
    } else {
        Some(combine_reports(&reports))
    };
    Some(AliasObservation {
        alias: first.alias.clone(),
        definition: first.definition,
        behavior,
        identity_selection,
    })
}

/// The identity selection part of [`combine_profiles`].
fn combine_reports(reports: &[Option<&IdentitySelectionReport>]) -> IdentitySelectionReport {
    let selection = if reports
        .iter()
        .any(|r| r.is_none_or(|r| r.selection == IdentitySelection::Undetermined))
    {
        IdentitySelection::Undetermined
    } else if reports
        .iter()
        .all(|r| r.is_some_and(|r| r.selection == IdentitySelection::Exclusive))
    {
        IdentitySelection::Exclusive
    } else {
        IdentitySelection::NotExclusive
    };
    let present: Vec<&IdentitySelectionReport> = reports.iter().flatten().copied().collect();
    let identities_only = match present.split_first() {
        Some((first, rest))
            if reports.iter().all(Option::is_some)
                && rest
                    .iter()
                    .all(|r| r.identities_only == first.identities_only) =>
        {
            first.identities_only
        }
        _ => IdentitiesOnly::Undetermined,
    };
    let same = |a: &IdentityEntry, b: &IdentityEntry| {
        a.kind == b.kind
            && a.source == b.source
            && a.provenance == b.provenance
            && a.fingerprint == b.fingerprint
            && a.backing == b.backing
    };
    let mut entries: Vec<IdentityEntry> = Vec::new();
    for e in present.iter().flat_map(|r| r.entries.iter()) {
        match entries.iter_mut().find(|x| same(x, e)) {
            Some(x) => {
                if e.certainty == Certainty::Undetermined {
                    x.certainty = Certainty::Undetermined;
                }
            }
            None => entries.push(IdentityEntry {
                cleared: None,
                ..e.clone()
            }),
        }
    }
    IdentitySelectionReport {
        selection,
        entries,
        identities_only,
    }
}

/// The invocation profiles a launch can use, by name (`Invocation::profile_name`), in
/// the order [`observe_profiles`] reports them: `shell`, `exec` (any remote command,
/// so Git over SSH and SCP) and `subsystem:sftp` (ADR-0007 §12.21 item 2, §12.25 item
/// 1).
#[must_use]
pub fn profile_names() -> Vec<String> {
    Invocation::consent_profiles()
        .iter()
        .map(Invocation::profile_name)
        .collect()
}

/// ADR-0007 §12.25 item 1 (T01): `alias` observed under every invocation profile a
/// launch can use, `Shell`, `Exec(None)` and `Subsystem("sftp")`, each with its name
/// ([`profile_names`]), in that order. `None` for a profile the pass reported nothing
/// for.
#[must_use]
pub fn observe_profiles(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    alias: &str,
) -> Vec<(String, Option<AliasObservation>)> {
    Invocation::consent_profiles()
        .iter()
        .map(|invocation| {
            let observation = observe_under(config, record, &[alias.to_owned()], invocation)
                .into_iter()
                .next();
            (invocation.profile_name(), observation)
        })
        .collect()
}

/// `aliases` observed under `invocation` alone. The local account for `%u` and `Match
/// localuser` is the account database's (ADR-0007 §12.25 item 2,
/// `doctor::local_account`), never `USER` or `USERNAME`; when it cannot be
/// established, only the conditions that read it are undetermined (§12.28 item 3).
/// Provenance is shown through `doctor::path_display` (§12.26 item 7), each file as
/// the configuration names it (§12.28 item 6).
#[must_use]
pub fn observe_under(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
    invocation: &Invocation,
) -> Vec<AliasObservation> {
    observe_as(
        config,
        record,
        aliases,
        invocation,
        crate::doctor::local_account(),
    )
}

/// [`observe_under`] with the local account given: `None` is an account that cannot
/// be established, so the conditions that read it are undetermined (ADR-0007 §12.28
/// item 3). [`observe_under`] passes `doctor::local_account`.
#[must_use]
pub fn observe_as(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
    invocation: &Invocation,
    local_user: Option<String>,
) -> Vec<AliasObservation> {
    let managed: Vec<&str> = record
        .items
        .get(&ProjectionItem::Ssh)
        .map(|r| r.aliases.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let key_files: Vec<&str> = record
        .items
        .get(&ProjectionItem::Ssh)
        .map(|r| {
            r.files
                .iter()
                .filter(|l| l.role == FileRole::Key)
                .map(|l| l.path.as_str())
                .collect()
        })
        .unwrap_or_default();
    let limits = Limits::default();
    let source = BoundedSource::new(config.paths.clone(), config.env.clone(), limits);
    let mut roots = Roots::new(
        Some(config.paths.user_config.clone()),
        Some(config.paths.system_config.clone()),
    );
    roots.managed = Some(config.managed_ssh_path());
    let client_version = config
        .clients
        .selected(ClientKind::Ssh)
        .and_then(|c| c.version)
        .unwrap_or(OpenSshVersion::MINIMUM);
    // ADR-0007 §12.25 item 2 (T02): the account database, never the environment
    // (`observe_under`), and never an empty name (§12.28 item 3).
    let local_user = local_user.filter(|n| !n.is_empty());
    aliases
        .iter()
        .map(|alias| {
            let query = Query {
                host: alias.clone(),
                user: None,
                local_user: local_user.clone(),
                client_version,
                invocation: invocation.clone(),
            };
            let mut set = ConfigSet::new();
            let evaluation = evaluate(&mut set, &source, &roots, &query, &limits);
            let is_managed = managed.contains(&alias.as_str());
            let behavior = behavior_of(&evaluation, config);
            let identity_selection = if is_managed {
                match adopted_key(&evaluation, &key_files, config.platform.is_windows()) {
                    Some(adopted) => {
                        Some(identity_selection(&evaluation, Path::new(adopted), &source))
                    }
                    // ⟨M03⟩ A managed-certificate alias names no adopted key file: its
                    // selection is the slot's (ADR-0008 D10 item 6).
                    None => managed_slot_selection(&evaluation, config, &source),
                }
            } else {
                None
            };
            let mut observation = AliasObservation {
                alias: alias.clone(),
                definition: if is_managed {
                    AliasDefinition::Managed
                } else {
                    AliasDefinition::UserOnly
                },
                behavior,
                identity_selection,
            };
            crate::doctor::redisplay_observation(&mut observation, &config.paths.account_home);
            observation
        })
        .collect()
}

/// The managed key file the alias's evaluation names first, among the record's key
/// files. P names a key file in the renderer's form: on Windows with `/` separators
/// (`RenderPath::windows`), while the record keeps the path as written. On Windows a
/// record path is therefore compared with `\` read as `/` (ADR-0007 §12.48 item 1); on
/// Unix `\` is a file-name character and the comparison is exact.
fn adopted_key<'k>(
    evaluation: &Evaluation,
    key_files: &[&'k str],
    windows: bool,
) -> Option<&'k str> {
    let entries = evaluation
        .accumulated
        .iter()
        .find(|(k, _)| k.as_str() == "IdentityFile")
        .map(|(_, v)| v.as_slice())
        .unwrap_or_default();
    entries.iter().find_map(|c| {
        let arg = c.value.args.first()?;
        let arg = arg.trim_matches('"');
        key_files
            .iter()
            .copied()
            .find(|k| key_matches(k, arg, windows))
    })
}

/// ⟨M03⟩ ADR-0008 D10 item 6 (§17.19 item 4, last bullets): the identity selection of a
/// managed-certificate alias. The slot is the one whose file P (the managed role) names
/// as the alias's `IdentityFile`, under `<state_dir>/managed/<destination-id>/`
/// (`content::managed_slot_paths`); the selected `ManagedIdentityForm` (the test
/// override, else `ManagedIdentityForm::select` for the selected client) says which
/// slot files are the alias's own entries. Only those make it `exclusive`; an inherited
/// `IdentityFile` or `CertificateFile` makes it `not_exclusive`, anything undeterminable
/// `undetermined` (`relevant::managed_identity_selection`). `None` when no state
/// directory is configured or P names no slot file for the alias (no selection is
/// claimed, as for an M02 alias whose key file is not found).
fn managed_slot_selection(
    evaluation: &Evaluation,
    config: &ProjectionConfig,
    source: &dyn ConfigSource,
) -> Option<IdentitySelectionReport> {
    let state_dir = config.state_dir.as_ref()?;
    let windows = config.platform.is_windows();
    let slash = |s: &str| {
        if windows {
            s.replace('\\', "/")
        } else {
            s.to_owned()
        }
    };
    let root = format!(
        "{}/",
        slash(&state_dir.join("managed").to_string_lossy()).trim_end_matches('/')
    );
    let entries = evaluation
        .accumulated
        .get(&KnownKeyword::IdentityFile)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let destination = entries
        .iter()
        .filter(|c| c.value.role == SourceRole::Managed)
        .find_map(|c| {
            let arg = c.value.args.first()?.trim_matches('"');
            // P may name the slot under the account home as `~/…`.
            let arg = match arg.strip_prefix("~/") {
                Some(rest) => slash(&source.account_home().join(rest).to_string_lossy()),
                None => slash(arg),
            };
            let rest = arg.strip_prefix(&root)?;
            let (component, file) = rest.split_once('/')?;
            matches!(file, "cert.pub" | "key.pub")
                .then(|| heimdall_contract::ids::DestinationId::parse(component).ok())
                .flatten()
        })?;
    let slot = super::content::managed_slot_paths(state_dir, &destination).ok()?;
    let version = config
        .clients
        .selected(ClientKind::Ssh)
        .and_then(|c| c.version);
    let form = config
        .test
        .managed_identity_form
        .unwrap_or_else(|| ManagedIdentityForm::select(version));
    let (identity, certificate) = match form {
        ManagedIdentityForm::D10AsWritten => (&slot.key_pub, Some(slot.cert_pub.as_path())),
        ManagedIdentityForm::CertificateAsIdentityFile => (&slot.cert_pub, None),
        ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile => {
            (&slot.cert_pub, Some(slot.cert_pub.as_path()))
        }
    };
    Some(managed_identity_selection(
        evaluation,
        identity,
        certificate,
        source,
    ))
}

/// Whether a record's key file `k` is the `IdentityFile` argument `arg` that P names
/// (see [`adopted_key`]).
fn key_matches(k: &str, arg: &str, windows: bool) -> bool {
    let k = if windows {
        k.replace('\\', "/")
    } else {
        k.to_owned()
    };
    k == arg || arg.strip_prefix("~/").is_some_and(|rest| k.ends_with(rest))
}

/// The relevant directives the contract reports (`HostName`, `Port`, `User`,
/// `IdentityAgent`, `IdentityFile`, `IdentitiesOnly`), with certainty and provenance.
fn behavior_of(evaluation: &Evaluation, config: &ProjectionConfig) -> Vec<DirectiveObservation> {
    let r = relevant(evaluation);
    let provenance = |v: &Value| -> Option<ConfigProvenance> {
        let path = evaluation.files.get(&v.span.source)?;
        Some(ConfigProvenance {
            path_display: display_path(path, &config.paths.account_home),
            line: v.span.line,
        })
    };
    let first = |name: &str, res: &Resolved| -> DirectiveObservation {
        match res {
            Resolved::Unset => DirectiveObservation {
                directive: name.to_owned(),
                values: Vec::new(),
                certainty: DirectiveCertainty::Unset,
                provenance: Vec::new(),
            },
            Resolved::Determined(v) => DirectiveObservation {
                directive: name.to_owned(),
                values: vec![v.args.join(" ")],
                certainty: DirectiveCertainty::Determined,
                provenance: provenance(v).into_iter().collect(),
            },
            Resolved::Undetermined(vs) => DirectiveObservation {
                directive: name.to_owned(),
                values: vs.iter().map(|v| v.args.join(" ")).collect(),
                certainty: DirectiveCertainty::Undetermined,
                provenance: vs.iter().filter_map(provenance).collect(),
            },
        }
    };
    let acc = |name: &str, cs: &[Candidate]| -> DirectiveObservation {
        DirectiveObservation {
            directive: name.to_owned(),
            values: cs.iter().map(|c| c.value.args.join(" ")).collect(),
            certainty: if cs.is_empty() {
                DirectiveCertainty::Unset
            } else if cs.iter().all(|c| c.determined) {
                DirectiveCertainty::Determined
            } else {
                DirectiveCertainty::Undetermined
            },
            provenance: cs.iter().filter_map(|c| provenance(&c.value)).collect(),
        }
    };
    vec![
        first("HostName", &r.hostname),
        first("Port", &r.port),
        first("User", &r.user),
        first("IdentityAgent", &r.identity_agent),
        acc("IdentityFile", &r.identity_files),
        first("IdentitiesOnly", &r.identities_only),
    ]
}

/// `~/…` under the account home (both canonicalized, ADR-0007 §12.26 item 7), `/`
/// separators.
fn display_path(path: &Path, home: &Path) -> String {
    crate::doctor::path_display(path, home)
}

/// The held steps of `intent`, with their classification and fingerprints.
///
/// # Errors
/// [`ReconcileError`].
pub fn observe_held(
    config: &ProjectionConfig,
    intent: &SetupIntent,
    receipts: &[StageReceipt],
) -> Result<Vec<HeldStep>, ReconcileError> {
    super::apply::held_steps(config, intent, receipts)
}

#[cfg(test)]
mod tests {
    use super::key_matches;

    #[test]
    fn windows_record_path_matches_the_rendered_identity_file() {
        // ADR-0007 §12.48 item 1: P names the key with `/` on Windows; the record keeps `\`.
        let record = r"C:\Users\fixture\AppData\Local\heimdall\keys\work.pub";
        assert!(key_matches(
            record,
            "C:/Users/fixture/AppData/Local/heimdall/keys/work.pub",
            true
        ));
        assert!(key_matches(
            record,
            "~/AppData/Local/heimdall/keys/work.pub",
            true
        ));
        assert!(!key_matches(
            record,
            "C:/Users/fixture/AppData/Local/heimdall/keys/other.pub",
            true
        ));
    }

    #[test]
    fn unix_comparison_stays_exact_and_backslash_is_a_file_name_character() {
        assert!(key_matches(
            "/home/fixture/.config/heimdall/keys/work.pub",
            "/home/fixture/.config/heimdall/keys/work.pub",
            false
        ));
        assert!(!key_matches(
            r"/home/fixture/a\b.pub",
            "/home/fixture/a/b.pub",
            false
        ));
        assert!(key_matches(
            "/home/fixture/k/work.pub",
            "~/k/work.pub",
            false
        ));
    }
}
