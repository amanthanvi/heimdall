//! Passive observation (m02-plan U4): aliases against the projection record, and the
//! held steps of an intent. Moves nothing and writes nothing.
//!
//! `observe` evaluates each alias statically (the U2 evaluator over the bounded,
//! read-only configuration source; nothing executes), with P as the managed root so
//! values read from P carry the managed role. `observe_held` runs the recovery
//! engine's observation and decision without a sink: it reports the steps a restart
//! would hold, with their classification and content fingerprints (M2-T03).

use std::path::Path;

use heimdall_app::ports::{HeldStep, ReconcileError};
use heimdall_contract::doctor::{
    AliasDefinition, AliasObservation, ConfigProvenance, DirectiveCertainty, DirectiveObservation,
};
use heimdall_contract::setup::ProjectionItem;
use heimdall_domain::operation::StageReceipt;
use heimdall_domain::projection::{FileRole, ProjectionRecord, SetupIntent};
use heimdall_sshconf::eval::{
    Candidate, Evaluation, Invocation, OpenSshVersion, Query, Resolved, Value, evaluate,
};
use heimdall_sshconf::include::{ConfigSet, Roots};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::relevant::{identity_selection, relevant};

use super::ProjectionConfig;
use crate::clients::ClientKind;
use crate::fs::BoundedSource;

/// Re-evaluate `aliases` statically against `record`.
#[must_use]
pub fn observe(
    config: &ProjectionConfig,
    record: &ProjectionRecord,
    aliases: &[String],
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
    let local_user = config
        .env
        .get("USER")
        .or_else(|| config.env.get("USERNAME"))
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_owned();
    aliases
        .iter()
        .map(|alias| {
            let query = Query {
                host: alias.clone(),
                user: None,
                local_user: local_user.clone(),
                client_version,
                invocation: Invocation::Shell,
            };
            let mut set = ConfigSet::new();
            let evaluation = evaluate(&mut set, &source, &roots, &query, &limits);
            let is_managed = managed.contains(&alias.as_str());
            let behavior = behavior_of(&evaluation, config);
            let identity_selection = if is_managed {
                adopted_key(&evaluation, &key_files)
                    .map(|adopted| identity_selection(&evaluation, Path::new(adopted), &source))
            } else {
                None
            };
            AliasObservation {
                alias: alias.clone(),
                definition: if is_managed {
                    AliasDefinition::Managed
                } else {
                    AliasDefinition::UserOnly
                },
                behavior,
                identity_selection,
            }
        })
        .collect()
}

/// The managed key file the alias's evaluation names first, among the record's key
/// files.
fn adopted_key<'k>(evaluation: &Evaluation, key_files: &[&'k str]) -> Option<&'k str> {
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
            .find(|k| *k == arg || arg.strip_prefix("~/").is_some_and(|rest| k.ends_with(rest)))
    })
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

/// `~/…` under the account home, `/` separators.
fn display_path(path: &Path, home: &Path) -> String {
    let shown = match path.strip_prefix(home) {
        Ok(rest) if !home.as_os_str().is_empty() => format!("~/{}", rest.display()),
        _ => path.display().to_string(),
    };
    shown.replace('\\', "/")
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
