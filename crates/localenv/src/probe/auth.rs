//! The `authentication` level: one real authentication through the real tree
//! (m02-plan U3). Needs `allow_config_commands`; refused non-interactively for an
//! unknown or interactive identity, or an uncleared fallback identity (Q2 as
//! qualified).
//!
//! `ssh -T -o BatchMode=yes -o ControlMaster=no -o ControlPath=none <alias> exit 0`
//! (ADR-0007 §6). It offers the identities the configuration selects; how many
//! signatures that causes is not claimed (§6 "Signature counts").
//!
//! **Non-interactive refusal** (`ProbeContext::interactive == false`), decided after
//! the static pass and before anything runs (outcome `refused`, code
//! `INTERACTION_REQUIRED`). The static pass evaluates the invocation the probe runs,
//! the remote command `exit 0` (`Exec(Some("exit 0"))`, ADR-0007 §12.25 item 1), with
//! the local account from the account database (item 2):
//!
//! * `interaction_unknown`: the alias has no catalog identity, or its identity's
//!   current interaction is not `none` (only a live declaration makes it `none`);
//! * `interaction_unknown` (§12.25 item 3, T03), before either success path: the
//!   alias's effective `IdentityAgent` under that invocation (below) is unknown or is
//!   not the endpoint the adopted identity's declaration covers (its recorded
//!   endpoint), or the pass is undetermined for want of the local account;
//! * `fallback_identity_interaction` (M2-R05): the identity selection for the adopted
//!   key is not `exclusive`, **and** the domain's fallback clearance rule
//!   (`heimdall_domain::catalog::fallback_clearance`, ADR-0007 §7; adopted by
//!   §12.17 item 10 now that U0b phase 2 landed it) does not clear the alternatives.
//!   Readiness, the adapters and the pre-launch check apply the same rule.
//!
//! **The rule's inputs here** (the probe has the doctor's `LocalContext`, not the
//! store; every reading fails closed):
//! * `endpoint`, the alias's effective `IdentityAgent` from the same static pass: a
//!   determined literal path, or for the default agent (unset, `SSH_AUTH_SOCK`,
//!   `$SSH_AUTH_SOCK`) the `SSH_AUTH_SOCK` of the environment snapshot the `ssh` child
//!   gets. An undetermined value, `none`, a value with a `%`, `$` or `~` token, or an
//!   unset `SSH_AUTH_SOCK` gives no endpoint, so nothing is cleared;
//! * the catalog identities are the context's catalog aliases' identities. Each enters
//!   the rule only when its `.pub` reads and parses (its key type decides FIDO) and,
//!   when the catalog recorded a fingerprint, the file's fingerprint equals it; its
//!   endpoint is the recorded one, and its fresh eligibility is the context's
//!   `interaction`. An identity that cannot be established this way is absent, so an
//!   entry with its key is never cleared;
//! * the adopted fingerprint is the catalog's, else the adopted `.pub`'s.

use std::cell::Cell;
use std::path::Path;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{ProbeOutcome, ProbeRecord};
use heimdall_contract::ids::IdentityId;
use heimdall_contract::provider::{
    EndpointKind, EndpointRef, EvidenceBasis, IdentitySelection, IdentitySelectionReport,
    InteractionKind, NoninteractiveEligibility, ProbeLevel,
};
use heimdall_domain::catalog::{
    IdentityRecord, IdentitySource, InteractionProfile, PairEligibility, fallback_clearance,
};
use heimdall_sshconf::eval::Resolved;
use heimdall_sshconf::include::ConfigSource as _;
use heimdall_sshconf::relevant::{agent_is_default, identity_selection, relevant};

use super::ProbeContext;
use crate::agents::EndpointLocator;
use crate::doctor::CatalogIdentity;
use crate::fs::BoundedSource;

/// The `ssh` options of the level, in order, before the alias.
pub const AUTHENTICATION_ARGS: &[&str] = &[
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
];

/// The remote command after the alias.
pub const AUTHENTICATION_COMMAND: &[&str] = &["exit", "0"];

/// Why a non-interactive authentication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthRefusal {
    /// The identity is unknown or needs an interaction.
    InteractionUnknown,
    /// An inherited fallback identity is not cleared.
    FallbackIdentityInteraction,
}

impl AuthRefusal {
    /// The stable `snake_case` reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthRefusal::InteractionUnknown => "interaction_unknown",
            AuthRefusal::FallbackIdentityInteraction => "fallback_identity_interaction",
        }
    }
}

/// Authenticate to `alias`.
#[must_use]
pub fn authenticate(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    authenticate_observed(ctx, alias).0
}

/// [`authenticate`], with the non-interactive refusal reason when there was one.
#[must_use]
pub fn authenticate_observed(
    ctx: &ProbeContext<'_>,
    alias: &str,
) -> (ProbeRecord, Option<AuthRefusal>) {
    let refusal: Cell<Option<AuthRefusal>> = Cell::new(None);
    let gate = |pass: &super::StaticPass| -> Option<Code> {
        if ctx.interactive {
            return None;
        }
        let why = noninteractive_refusal(ctx, alias, pass);
        refusal.set(why);
        why.map(|_| Code::InteractionRequired)
    };
    let run = super::run_real_tree(
        ctx,
        ProbeLevel::Authentication,
        alias,
        AUTHENTICATION_ARGS,
        AUTHENTICATION_COMMAND,
        &gate,
    );
    let mut record = run.record;
    if let Some(finished) = run.finished
        && record.outcome == ProbeOutcome::Ok
        && !finished.status.is_some_and(|s| s.success())
    {
        record.outcome = ProbeOutcome::Failed;
        if String::from_utf8_lossy(&finished.stderr).contains("Host key verification failed") {
            record.code = Some(Code::HostTrustChanged);
        }
    }
    (record, refusal.get())
}

fn noninteractive_refusal(
    ctx: &ProbeContext<'_>,
    alias: &str,
    pass: &super::StaticPass,
) -> Option<AuthRefusal> {
    let Some(identity) = ctx.local.catalog_identity(alias) else {
        return Some(AuthRefusal::InteractionUnknown);
    };
    if identity.interaction != InteractionKind::None {
        return Some(AuthRefusal::InteractionUnknown);
    }
    // ADR-0007 §12.25 item 3 (T03): before either success path, the effective
    // `IdentityAgent` of the invocation the probe runs (item 1; the pass evaluated
    // it) is the endpoint the adopted identity's declaration covers. A declaration
    // covers one endpoint only, so an unknown or different one refuses, exclusive
    // selection or not; so does a pass the local account leaves undetermined (item 2).
    let declared = identity.endpoint.as_ref().and_then(endpoint_of);
    let endpoint = match (effective_agent(ctx, pass), declared) {
        (Some(effective), Some(declared)) if effective == declared && !pass.account_unknown => {
            effective
        }
        _ => return Some(AuthRefusal::InteractionUnknown),
    };
    let source = BoundedSource::new(
        ctx.local.paths.clone(),
        ctx.local.env.clone(),
        ctx.local.limits,
    );
    let report = identity_selection(&pass.evaluation, &identity.public_key_path, &source);
    if report.selection == IdentitySelection::Exclusive
        || fallbacks_cleared(ctx, &endpoint, identity, &report, &source)
    {
        return None;
    }
    Some(AuthRefusal::FallbackIdentityInteraction)
}

/// ADR-0007 §12.17 item 10: whether the domain's fallback clearance rule clears every
/// alternative of `report` at the alias's effective agent `endpoint` (module docs for
/// the inputs).
fn fallbacks_cleared(
    ctx: &ProbeContext<'_>,
    endpoint: &EndpointRef,
    adopted: &CatalogIdentity,
    report: &IdentitySelectionReport,
    source: &BoundedSource,
) -> bool {
    let catalog = catalog_identities(ctx, source);
    let records: Vec<IdentityRecord> = catalog.iter().map(|(r, _)| r.clone()).collect();
    let eligibility_of = |id: &IdentityId| -> PairEligibility {
        let interaction = catalog
            .iter()
            .find(|(r, _)| r.id == *id)
            .map_or(InteractionKind::Unknown, |(_, i)| *i);
        PairEligibility {
            interaction,
            basis: if interaction == InteractionKind::None {
                EvidenceBasis::Declared
            } else {
                EvidenceBasis::Inferred
            },
            declaration: None,
            noninteractive: NoninteractiveEligibility {
                eligible: interaction == InteractionKind::None,
                reason: None,
            },
        }
    };
    let adopted_fingerprint = adopted
        .fingerprint
        .clone()
        .or_else(|| public_key(source, &adopted.public_key_path).map(|k| k.fingerprint))
        .unwrap_or_default();
    fallback_clearance(
        report,
        &records,
        &eligibility_of,
        endpoint,
        &adopted_fingerprint,
    )
    .cleared
}

/// The alias's effective `IdentityAgent` as an endpoint, when it is determined.
fn effective_agent(ctx: &ProbeContext<'_>, pass: &super::StaticPass) -> Option<EndpointRef> {
    let agent = relevant(&pass.evaluation).identity_agent;
    let locator = if agent_is_default(&agent) {
        ctx.local
            .env
            .get("SSH_AUTH_SOCK")
            .and_then(|v| v.to_str())
            .map(str::to_owned)?
    } else {
        let Resolved::Determined(v) = agent else {
            return None;
        };
        let [value] = v.args.as_slice() else {
            return None;
        };
        let tokens = value.contains(['%', '$']) || value.starts_with('~');
        if tokens || value.eq_ignore_ascii_case("none") {
            return None;
        }
        value.clone()
    };
    if locator.is_empty() {
        return None;
    }
    Some(EndpointRef {
        kind: if ctx.local.platform.is_windows() {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        },
        locator,
    })
}

/// A catalog endpoint as the rule compares it (`None` for a path that is not Unicode).
fn endpoint_of(locator: &EndpointLocator) -> Option<EndpointRef> {
    Some(match locator {
        EndpointLocator::UnixSocket(p) => EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: p.to_str()?.to_owned(),
        },
        EndpointLocator::NamedPipe(name) => EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: name.clone(),
        },
    })
}

/// A public key read from a `.pub`: its canonical line (type and blob) and
/// fingerprint.
struct PublicKey {
    line: String,
    fingerprint: String,
}

/// The first key line of the `.pub` at `path` (bounded read; public material only).
fn public_key(source: &BoundedSource, path: &Path) -> Option<PublicKey> {
    let bytes = source.read(path).ok()?.bytes;
    let text = std::str::from_utf8(&bytes).ok()?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let mut parts = line.split_ascii_whitespace();
    let (kind, encoded) = (parts.next()?, parts.next()?);
    let blob = crate::known_hosts::base64_decode(encoded)?;
    let len = usize::try_from(u32::from_be_bytes(blob.get(..4)?.try_into().ok()?)).ok()?;
    if blob.get(4..4usize.checked_add(len)?)? != kind.as_bytes() {
        return None;
    }
    Some(PublicKey {
        line: format!("{kind} {encoded}"),
        fingerprint: crate::known_hosts::fingerprint(&blob),
    })
}

/// The context's catalog identities as the rule's records, each with its fresh
/// interaction (module docs). IDs are local to this computation.
fn catalog_identities(
    ctx: &ProbeContext<'_>,
    source: &BoundedSource,
) -> Vec<(IdentityRecord, InteractionKind)> {
    let mut out: Vec<(IdentityRecord, InteractionKind)> = Vec::new();
    for (n, identity) in ctx
        .local
        .catalog
        .iter()
        .filter_map(|a| a.identity.as_ref())
        .enumerate()
    {
        let Some(key) = public_key(source, &identity.public_key_path) else {
            continue;
        };
        if identity
            .fingerprint
            .as_ref()
            .is_some_and(|f| *f != key.fingerprint)
        {
            continue;
        }
        let source = match identity.endpoint.as_ref().and_then(endpoint_of) {
            Some(endpoint) => IdentitySource::NativeAgent { endpoint },
            None => IdentitySource::PublicKeyFile {
                path: identity.public_key_path.display().to_string(),
            },
        };
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
        let record = IdentityRecord {
            id: IdentityId::from_random_bytes(id),
            revision: 1,
            interaction: InteractionProfile::default_for(&source, &key.line),
            source,
            public_key: key.line,
            fingerprint: key.fingerprint,
            label: None,
            adopted_at: Timestamp::UNIX_EPOCH,
            updated_at: Timestamp::UNIX_EPOCH,
        };
        out.push((record, identity.interaction));
    }
    out
}

/// The fixture names Unix-socket endpoints; the named-pipe branch of
/// `effective_agent` needs a native Windows run (blocked here).
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use heimdall_sshconf::limits::Limits;

    use super::*;
    use crate::clients::ClientsConfig;
    use heimdall_contract::doctor::AliasDefinition;

    use crate::doctor::{CatalogAlias, LocalContext};
    use crate::env::{Env, Platform};
    use crate::paths::SshPaths;

    const ALIAS: &str = "hm-auth";

    /// A synthetic public key line of `key_type` over a fixed 32-byte pattern: public
    /// fixture material only (no private key exists for it).
    fn synthetic(key_type: &str, fill: u8) -> String {
        let mut blob = Vec::new();
        blob.extend(u32::try_from(key_type.len()).unwrap().to_be_bytes());
        blob.extend(key_type.as_bytes());
        blob.extend(32u32.to_be_bytes());
        blob.extend([fill; 32]);
        // The fixture types make blobs of a multiple of 3 bytes: no padding needed.
        assert_eq!(blob.len() % 3, 0, "{key_type}");
        format!(
            "{key_type} {}",
            crate::known_hosts::base64_encode_unpadded(&blob)
        )
    }

    struct Fx {
        _dir: tempfile::TempDir,
        root: PathBuf,
        home: PathBuf,
        /// The agent socket path the alias names (never created or opened).
        agent: PathBuf,
    }

    impl Fx {
        fn new() -> Fx {
            let dir = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(dir.path()).unwrap();
            let home = root.join("home");
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            std::fs::create_dir_all(root.join("etc-ssh")).unwrap();
            std::fs::create_dir_all(root.join("keys")).unwrap();
            Fx {
                _dir: dir,
                agent: root.join("agent.sock"),
                root,
                home,
            }
        }

        fn key(&self, name: &str, key_type: &str, fill: u8) -> PathBuf {
            let path = self.root.join("keys").join(format!("{name}.pub"));
            std::fs::write(&path, format!("{} fixture\n", synthetic(key_type, fill))).unwrap();
            path
        }

        fn config(&self, text: &str) {
            std::fs::write(self.home.join(".ssh").join("config"), text).unwrap();
        }

        fn alias_block(&self, agent: Option<&str>, adopted: &Path, only: bool) -> String {
            let mut s = format!("Host {ALIAS}\n  HostName 127.0.0.1\n");
            if let Some(a) = agent {
                s.push_str(&format!("  IdentityAgent \"{a}\"\n"));
            }
            s.push_str(&format!("  IdentityFile \"{}\"\n", adopted.display()));
            if only {
                s.push_str("  IdentitiesOnly yes\n");
            }
            s
        }

        fn ctx(&self, catalog: Vec<CatalogAlias>, sock: Option<&Path>) -> LocalContext {
            let paths = SshPaths::with_test_override(self.home.clone(), self.root.join("etc-ssh"));
            let mut vars: Vec<(&str, OsString)> =
                vec![("HOME", self.home.clone().into_os_string())];
            if let Some(s) = sock {
                vars.push(("SSH_AUTH_SOCK", s.as_os_str().to_owned()));
            }
            let mut c = LocalContext::new(
                paths,
                Env::from_vars(vars),
                Platform::current(),
                ClientsConfig::default(),
                Limits::default(),
            );
            // Read only the scratch user file (as `-F` would): never the system file.
            c.client_isolation = Some(Vec::new());
            c.catalog = catalog;
            c
        }

        /// The refusal of the static pass the probe takes: the invocation it runs,
        /// `exit 0` (ADR-0007 §12.25 item 1).
        fn refusal(&self, ctx: &LocalContext) -> Option<AuthRefusal> {
            let pass = self.pass(ctx);
            noninteractive_refusal(&ProbeContext::new(ctx, true, false), ALIAS, &pass)
        }

        fn pass(&self, ctx: &LocalContext) -> super::super::StaticPass {
            let pass = super::super::static_pass_for(
                ctx,
                ALIAS,
                None,
                super::super::invocation_of(AUTHENTICATION_COMMAND),
            );
            assert!(!pass.not_fully_readable);
            pass
        }
    }

    fn entry(
        alias: &str,
        key: &Path,
        interaction: InteractionKind,
        endpoint: &Path,
    ) -> CatalogAlias {
        CatalogAlias {
            alias: alias.to_owned(),
            definition: AliasDefinition::Managed,
            identity: Some(CatalogIdentity {
                public_key_path: key.to_path_buf(),
                fingerprint: None,
                interaction,
                endpoint: Some(EndpointLocator::UnixSocket(endpoint.to_path_buf())),
            }),
        }
    }

    /// ADR-0007 §12.17 item 10 (W3b-gaps): the non-interactive authentication probe
    /// applies the domain's fallback clearance rule and refuses only a selection the
    /// rule does not clear. A declared-`none`, agent-backed inherited key of the
    /// catalog at the alias's agent, with `IdentitiesOnly yes`, is cleared; every
    /// condition of the rule, broken alone, refuses again.
    #[test]
    fn noninteractive_authentication_refuses_only_what_fallback_clearance_does_not_clear() {
        use AuthRefusal::FallbackIdentityInteraction as Refused;
        use InteractionKind::{None as Declared, Unknown};
        let fx = Fx::new();
        let adopted = fx.key("adopted", "ssh-ed25519", 1);
        let inherited = fx.key("inherited", "ssh-ed25519", 2);
        let agent = fx.agent.display().to_string();
        let other_agent = fx.root.join("other.sock");
        let inherit = format!("Host *\n  IdentityFile \"{}\"\n", inherited.display());
        let full = format!("{}{inherit}", fx.alias_block(Some(&agent), &adopted, true));
        let both = |inherited_interaction, inherited_at: &Path| {
            vec![
                entry(ALIAS, &adopted, Declared, &fx.agent),
                entry("hm-other", &inherited, inherited_interaction, inherited_at),
            ]
        };

        // Control: an exclusive selection is never refused (the rule is not needed).
        fx.config(&fx.alias_block(Some(&agent), &adopted, true));
        assert_eq!(fx.refusal(&fx.ctx(both(Unknown, &fx.agent), None)), None);

        // The rule clears the inherited key: not refused (the strict reading refused).
        fx.config(&full);
        assert_eq!(fx.refusal(&fx.ctx(both(Declared, &fx.agent), None)), None);

        // Each condition broken alone refuses again.
        assert_eq!(
            fx.refusal(&fx.ctx(both(Unknown, &fx.agent), None)),
            Some(Refused),
            "the inherited identity is not declared"
        );
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &other_agent), None)),
            Some(Refused),
            "the inherited identity is recorded at another agent"
        );
        assert_eq!(
            fx.refusal(&fx.ctx(vec![entry(ALIAS, &adopted, Declared, &fx.agent)], None)),
            Some(Refused),
            "the inherited key is not a catalog identity"
        );
        fx.config(&format!(
            "{}{inherit}",
            fx.alias_block(Some(&agent), &adopted, false)
        ));
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &fx.agent), None)),
            Some(Refused),
            "IdentitiesOnly is not a determined yes"
        );
        // Even when the catalog recorded the very same text, a value with a token (or
        // `none`) is not a determined endpoint, so the adopted identity's declared
        // endpoint is not established (ADR-0007 §12.25 item 3).
        for agent_value in ["none", "~/agent.sock", "%d/agent.sock", "$AGENT/agent.sock"] {
            fx.config(&format!(
                "{}{inherit}",
                fx.alias_block(Some(agent_value), &adopted, true)
            ));
            let literal = Path::new(agent_value);
            let ctx = fx.ctx(
                vec![
                    entry(ALIAS, &adopted, Declared, literal),
                    entry("hm-other", &inherited, Declared, literal),
                ],
                Some(&fx.agent),
            );
            assert_eq!(
                fx.refusal(&ctx),
                Some(AuthRefusal::InteractionUnknown),
                "IdentityAgent {agent_value} is not a determined endpoint"
            );
        }
        // A FIDO inherited key is never cleared, whatever interaction is claimed.
        let fido = fx.key("fido", "sk-ssh-ed25519@openssh.com", 3);
        fx.config(&format!(
            "{}Host *\n  IdentityFile \"{}\"\n",
            fx.alias_block(Some(&agent), &adopted, true),
            fido.display()
        ));
        assert_eq!(
            fx.refusal(&fx.ctx(
                vec![
                    entry(ALIAS, &adopted, Declared, &fx.agent),
                    entry("hm-fido", &fido, Declared, &fx.agent),
                ],
                None
            )),
            Some(Refused),
            "a FIDO key"
        );
        // A file-backed inherited key (its private key file exists) is never cleared.
        let private = inherited.with_extension("");
        std::fs::write(
            &private,
            b"placeholder: never opened, only its presence is checked\n",
        )
        .unwrap();
        fx.config(&format!(
            "{}Host *\n  IdentityFile \"{}\"\n",
            fx.alias_block(Some(&agent), &adopted, true),
            private.display()
        ));
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &fx.agent), None)),
            Some(Refused),
            "a file-backed key"
        );
        std::fs::remove_file(&private).unwrap();
        // A catalog fingerprint that its `.pub` does not match is not the identity.
        fx.config(&full);
        let mut wrong = both(Declared, &fx.agent);
        if let Some(i) = wrong[1].identity.as_mut() {
            i.fingerprint = Some("SHA256:not-this-key".to_owned());
        }
        assert_eq!(fx.refusal(&fx.ctx(wrong, None)), Some(Refused));

        // The default agent is the snapshot's SSH_AUTH_SOCK: cleared when it is the
        // catalog's endpoint, refused when it is another or unset (the adopted
        // identity's declared endpoint is not the alias's agent, §12.25 item 3).
        fx.config(&format!(
            "{}{inherit}",
            fx.alias_block(None, &adopted, true)
        ));
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &fx.agent), Some(&fx.agent))),
            None
        );
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &fx.agent), Some(&other_agent))),
            Some(AuthRefusal::InteractionUnknown)
        );
        assert_eq!(
            fx.refusal(&fx.ctx(both(Declared, &fx.agent), None)),
            Some(AuthRefusal::InteractionUnknown)
        );
        // An identity whose interaction is not `none` is still `interaction_unknown`.
        fx.config(&full);
        assert_eq!(
            fx.refusal(&fx.ctx(vec![entry(ALIAS, &adopted, Unknown, &fx.agent)], None)),
            Some(AuthRefusal::InteractionUnknown)
        );
    }

    /// The adopted key read from Heimdall's managed file is the adopted identity, not
    /// an alternative, when its `.pub` matches (the adopted fingerprint is taken from
    /// the `.pub` when the catalog recorded none); another managed key is never
    /// cleared.
    #[test]
    fn managed_adopted_entry_is_not_an_alternative() {
        let fx = Fx::new();
        let adopted = fx.key("adopted", "ssh-ed25519", 4);
        let inherited = fx.key("inherited", "ssh-ed25519", 5);
        let agent = fx.agent.display().to_string();
        let managed = fx.root.join("ssh_config");
        std::fs::write(&managed, fx.alias_block(Some(&agent), &adopted, true)).unwrap();
        fx.config(&format!(
            "Include \"{}\"\nHost *\n  IdentityFile \"{}\"\n",
            managed.display(),
            inherited.display()
        ));
        let catalog = vec![
            CatalogAlias {
                alias: ALIAS.to_owned(),
                definition: AliasDefinition::Managed,
                identity: Some(CatalogIdentity {
                    public_key_path: adopted.clone(),
                    fingerprint: None,
                    interaction: InteractionKind::None,
                    // Its declared endpoint is the alias's agent (ADR-0007 §12.25 item
                    // 3); its own record is not what clears it as an alternative.
                    endpoint: Some(EndpointLocator::UnixSocket(fx.agent.clone())),
                }),
            },
            entry("hm-other", &inherited, InteractionKind::None, &fx.agent),
        ];
        let mut ctx = fx.ctx(catalog, None);
        ctx.managed_file = Some(managed.clone());
        assert_eq!(fx.refusal(&ctx), None);
        // Another key in the managed file is an alternative that is never cleared.
        let stale = fx.key("stale", "ssh-ed25519", 6);
        std::fs::write(
            &managed,
            format!(
                "{}  IdentityFile \"{}\"\n",
                fx.alias_block(Some(&agent), &adopted, true),
                stale.display()
            ),
        )
        .unwrap();
        assert_eq!(
            fx.refusal(&ctx),
            Some(AuthRefusal::FallbackIdentityInteraction)
        );
    }

    /// A stub `ssh` in `<root>/bin` that creates `<root>/<marker>` when it runs, and
    /// a context whose snapshot `PATH` finds it (the probe resolves `ssh` from the
    /// snapshot).
    fn with_stub(fx: &Fx, ctx: &mut LocalContext, marker: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let bin = fx.root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ran = fx.root.join(marker);
        let ssh = bin.join("ssh");
        std::fs::write(&ssh, format!("#!/bin/sh\n: > '{}'\n", ran.display())).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut vars: Vec<(String, OsString)> = vec![
            ("HOME".to_owned(), fx.home.clone().into_os_string()),
            ("PATH".to_owned(), bin.into_os_string()),
        ];
        if let Some(sock) = ctx.env.get("SSH_AUTH_SOCK") {
            vars.push(("SSH_AUTH_SOCK".to_owned(), sock.to_owned()));
        }
        ctx.env = Env::from_vars(vars);
        ran
    }

    /// ADR-0007 §12.25 item 3 (T03), the reviewer's
    /// `review_authentication_probe_ignores_changed_agent_for_exclusive_key`: an
    /// exclusive selection of the adopted key whose configuration changes only
    /// `IdentityAgent` to another endpoint is refused before anything runs, through
    /// `authenticate_observed` with a stub client (its marker is never created). The
    /// control, the same configuration at the declared endpoint, runs the stub.
    #[test]
    fn exclusive_selection_through_another_agent_is_refused_before_anything_runs() {
        let fx = Fx::new();
        let adopted = fx.key("adopted", "ssh-ed25519", 7);
        let other = fx.root.join("other.sock").display().to_string();
        let catalog = || vec![entry(ALIAS, &adopted, InteractionKind::None, &fx.agent)];
        fx.config(&fx.alias_block(Some(&other), &adopted, true));
        let mut ctx = fx.ctx(catalog(), None);
        let pass = fx.pass(&ctx);
        assert_eq!(
            identity_selection(
                &pass.evaluation,
                &adopted,
                &BoundedSource::new(ctx.paths.clone(), ctx.env.clone(), ctx.limits)
            )
            .selection,
            IdentitySelection::Exclusive,
            "only the agent changed"
        );
        assert_eq!(fx.refusal(&ctx), Some(AuthRefusal::InteractionUnknown));
        let ran = with_stub(&fx, &mut ctx, "ran-refused");
        let (record, why) = authenticate_observed(&ProbeContext::new(&ctx, true, false), ALIAS);
        assert_eq!(why, Some(AuthRefusal::InteractionUnknown));
        assert_eq!(record.outcome, ProbeOutcome::Refused);
        assert_eq!(record.code, Some(Code::InteractionRequired));
        assert!(!ran.exists(), "nothing ran");

        // Control: the declared endpoint.
        fx.config(&fx.alias_block(Some(&fx.agent.display().to_string()), &adopted, true));
        let mut ctx = fx.ctx(catalog(), None);
        let ran = with_stub(&fx, &mut ctx, "ran-control");
        let (record, why) = authenticate_observed(&ProbeContext::new(&ctx, true, false), ALIAS);
        assert_eq!(why, None);
        assert_eq!(record.outcome, ProbeOutcome::Ok, "{record:?}");
        assert!(ran.exists(), "the stub ran");
        // An adopted identity with no recorded endpoint is not established either.
        let mut unrecorded = catalog();
        if let Some(i) = unrecorded[0].identity.as_mut() {
            i.endpoint = None;
        }
        assert_eq!(
            fx.refusal(&fx.ctx(unrecorded, None)),
            Some(AuthRefusal::InteractionUnknown)
        );
    }

    /// ADR-0007 §12.25 item 1 (T01): the probe's static pass evaluates the invocation
    /// it runs (`exit 0`, an exec session), not the shell. An `IdentityFile` behind
    /// `Match sessiontype exec` or `Match command "exit 0"` is a fallback the shell
    /// never sees, and an `IdentityAgent` override behind `Match sessiontype exec`
    /// moves the agent; each is refused, and each is invisible to a shell pass.
    #[test]
    fn the_probe_evaluates_the_exec_invocation_it_runs() {
        let fx = Fx::new();
        let adopted = fx.key("adopted", "ssh-ed25519", 8);
        let inherited = fx.key("inherited", "ssh-ed25519", 9);
        let agent = fx.agent.display().to_string();
        let block = fx.alias_block(Some(&agent), &adopted, true);
        let ctx = || {
            fx.ctx(
                vec![entry(ALIAS, &adopted, InteractionKind::None, &fx.agent)],
                None,
            )
        };
        let shell = |ctx: &LocalContext| {
            let pass = super::super::static_pass(ctx, ALIAS, None);
            noninteractive_refusal(&ProbeContext::new(ctx, true, false), ALIAS, &pass)
        };
        assert_eq!(
            super::super::invocation_of(AUTHENTICATION_COMMAND),
            heimdall_sshconf::eval::Invocation::Exec(Some("exit 0".to_owned()))
        );
        for condition in ["Match sessiontype exec", "Match command \"exit 0\""] {
            fx.config(&format!(
                "{block}{condition}\n  IdentityFile \"{}\"\n",
                inherited.display()
            ));
            assert_eq!(
                shell(&ctx()),
                None,
                "{condition}: the shell does not see it"
            );
            assert_eq!(
                fx.refusal(&ctx()),
                Some(AuthRefusal::FallbackIdentityInteraction),
                "{condition}"
            );
        }
        // Through the probe itself (its real-tree run takes the same pass): refused,
        // and the stub client never runs.
        let mut c = ctx();
        let ran = with_stub(&fx, &mut c, "ran-exec-fallback");
        let (record, why) = authenticate_observed(&ProbeContext::new(&c, true, false), ALIAS);
        assert_eq!(why, Some(AuthRefusal::FallbackIdentityInteraction));
        assert_eq!(record.outcome, ProbeOutcome::Refused);
        assert!(!ran.exists(), "nothing ran");
        let other = fx.root.join("other.sock").display().to_string();
        fx.config(&format!(
            "Match sessiontype exec\n  IdentityAgent \"{other}\"\n{block}"
        ));
        assert_eq!(shell(&ctx()), None, "the shell keeps the declared agent");
        assert_eq!(fx.refusal(&ctx()), Some(AuthRefusal::InteractionUnknown));
        let mut c = ctx();
        let ran = with_stub(&fx, &mut c, "ran-exec-agent");
        let (_, why) = authenticate_observed(&ProbeContext::new(&c, true, false), ALIAS);
        assert_eq!(why, Some(AuthRefusal::InteractionUnknown));
        assert!(!ran.exists(), "nothing ran");
    }

    /// ADR-0007 §12.25 item 2 (T02): `Match localuser` reads the account database,
    /// never the snapshot's `USER`. A fallback behind `Match localuser <the account>`
    /// is refused with `USER` unset and with `USER` naming another account; a rule
    /// for that other name never applies. A pass the local account leaves undetermined
    /// is refused.
    #[test]
    fn localuser_comes_from_the_account_database_not_the_environment() {
        let Some(account) = crate::doctor::local_account() else {
            panic!("the account database names this test's account");
        };
        let fx = Fx::new();
        let adopted = fx.key("adopted", "ssh-ed25519", 10);
        let inherited = fx.key("inherited", "ssh-ed25519", 11);
        let agent = fx.agent.display().to_string();
        let block = fx.alias_block(Some(&agent), &adopted, true);
        let ctx = |user: Option<&str>| {
            let mut c = fx.ctx(
                vec![entry(ALIAS, &adopted, InteractionKind::None, &fx.agent)],
                None,
            );
            let mut vars: Vec<(String, OsString)> =
                vec![("HOME".to_owned(), fx.home.clone().into_os_string())];
            if let Some(u) = user {
                vars.push(("USER".to_owned(), u.into()));
                vars.push(("USERNAME".to_owned(), u.into()));
            }
            c.env = Env::from_vars(vars);
            c
        };
        let rule = |name: &str| {
            format!(
                "{block}Match localuser {name}\n  IdentityFile \"{}\"\n",
                inherited.display()
            )
        };
        fx.config(&rule(&account));
        for user in [None, Some("hm-fixture-not-the-account")] {
            assert_eq!(
                fx.refusal(&ctx(user)),
                Some(AuthRefusal::FallbackIdentityInteraction),
                "USER {}",
                if user.is_some() {
                    "set to another name"
                } else {
                    "unset"
                }
            );
        }
        fx.config(&rule("hm-fixture-not-the-account"));
        assert_eq!(fx.refusal(&ctx(Some("hm-fixture-not-the-account"))), None);
        let c = ctx(None);
        let mut pass = fx.pass(&c);
        assert!(!pass.account_unknown);
        pass.account_unknown = true;
        assert_eq!(
            noninteractive_refusal(&ProbeContext::new(&c, true, false), ALIAS, &pass),
            Some(AuthRefusal::InteractionUnknown)
        );
    }
}
