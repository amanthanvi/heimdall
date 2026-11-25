//! Spec §14.3 "host alias collision", the same-name case (m08-plan §7.1, added by W2-2;
//! U0-Q9 and Q10, ruled 2026-11-24): a user `Host` line, in the user's configuration or in a
//! file it includes, that names a managed alias as an exact literal (compared without ASCII
//! case) is **reported as a conflict**:
//!
//! * by the passive doctor, finding `alias_collision` (`warning`), with the line's file:line
//!   and the alias as the subject (never in the message, so `--redact` hides it);
//! * by setup's plan, the conflict `alias_collision` (a `warning` finding whose reason is
//!   `ConflictKind::AliasCollision`'s wire name), bound into the plan digest. The plan keeps its
//!   steps: the conflict is reported, not refused (the consent classification and the identity
//!   selection findings weigh what such a section adds; ruled "report, not refuse" by the M08
//!   track lead on U1b's question). Its apply settles the item `applied`, never
//!   `conflict_preserved` or `not_applied`, and leaves the user's lines as they were.
//!
//! The doctor also reports a legacy catalog pair whose aliases differ only in case
//! (`Txn::destination_alias_case_collisions`, `problem`). Wildcard, negated and `Match` lines
//! are out of scope (the stated limitation), and so are the system tree and Heimdall's own P.
//! Nothing here claims how `ssh` matches `Host` patterns.
//!
//! Cargo test target `adversarial_alias_collision`, hosted by `heimdall-localenv`. Every file
//! lives in a `tempfile` scratch directory; the doctor runs its static level only with local
//! queries off, so no client, agent or network is touched; the apply writes only the scratch
//! home's files and Heimdall's scratch directories (local queries off: it starts nothing), and
//! the public key the plan materializes is synthetic, generated per run.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use heimdall_app::ports::{ItemOutcome, ProjectionWriter as _, SinkError, StageSink};
use heimdall_contract::doctor::{AliasDefinition, Finding, FindingSeverity, finding};
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, IdentityId};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::LocalReceipt;
use heimdall_domain::projection::{
    ConsentRecord, ItemCommit, ManagedAliasSpec, ProjectionPlan, ProjectionSpec,
};
use heimdall_localenv::clients::ClientsConfig;
use heimdall_localenv::doctor::{
    self, CatalogAlias, DoctorRequest, LocalContext, USER_HOST_LINE_MESSAGE,
};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::{LocalProjection, ProjectionConfig, PublicKeySource};
use heimdall_sshconf::limits::Limits;

/// One scratch account: a home with `~/.ssh`, Heimdall's configuration and state
/// directories, and an empty system directory.
struct Scratch {
    _dir: tempfile::TempDir,
    home: PathBuf,
    system: PathBuf,
    config_dir: PathBuf,
    state_dir: PathBuf,
}

impl Scratch {
    fn new(user_config: &str, files: &[(&str, &str)]) -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        // Unix: the canonical root (macOS's `/var` is `/private/var`). Windows: as given, never
        // the `\\?\` form `canonicalize` returns, which an `Include` path cannot extend.
        #[cfg(unix)]
        let root = std::fs::canonicalize(dir.path()).unwrap();
        #[cfg(not(unix))]
        let root = dir.path().to_path_buf();
        let home = root.join("home");
        let system = root.join("etc-ssh");
        let config_dir = root.join("heimdall-config");
        let state_dir = root.join("heimdall-state");
        for d in [
            home.join(".ssh").join("conf.d"),
            system.clone(),
            config_dir.clone(),
            state_dir.clone(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let s = Scratch {
            _dir: dir,
            home,
            system,
            config_dir,
            state_dir,
        };
        std::fs::write(s.user_config(), s.expand(user_config)).unwrap();
        for (rel, text) in files {
            std::fs::write(s.home.join(".ssh").join(rel), s.expand(text)).unwrap();
        }
        // The system file names the managed alias too: it is not the user's, never compared.
        std::fs::write(s.system.join("ssh_config"), "Host alpha\n    Port 2222\n").unwrap();
        s
    }

    /// `text` with `{SSH}` as the scratch `~/.ssh` (absolute, so no `Include` follows `HOME`).
    fn expand(&self, text: &str) -> String {
        text.replace("{SSH}", &self.home.join(".ssh").to_string_lossy())
    }

    fn user_config(&self) -> PathBuf {
        self.home.join(".ssh").join("config")
    }

    fn paths(&self) -> SshPaths {
        SshPaths::with_test_override(self.home.clone(), self.system.clone())
    }

    fn env(&self) -> Env {
        Env::from_vars([
            ("HOME".to_owned(), self.home.clone().into_os_string()),
            ("PATH".to_owned(), "/usr/bin:/bin".into()),
        ])
    }

    /// The doctor's context: the scratch paths, the system file read too (no isolation), the
    /// catalog's managed `alpha` and observed `other`, and P's path.
    fn doctor(&self) -> LocalContext {
        let mut ctx = LocalContext::new(
            self.paths(),
            self.env(),
            Platform::current(),
            ClientsConfig::default(),
            Limits::default(),
        );
        ctx.catalog = vec![
            CatalogAlias {
                alias: "alpha".to_owned(),
                definition: AliasDefinition::Managed,
                identity: None,
            },
            CatalogAlias {
                alias: "other".to_owned(),
                definition: AliasDefinition::Observed,
                identity: None,
            },
        ];
        ctx.managed_file = Some(self.config_dir.join("ssh_config"));
        ctx
    }

    /// The setup preview of a first `apply` that renders the managed `alpha`.
    fn preview(&self) -> ProjectionPlan {
        let (writer, spec) = self.writer();
        writer.preview(&spec, &apply_intent()).unwrap()
    }

    /// A writer over the scratch account (its state directory set, as a runtime wires it)
    /// and the spec of a first `apply` that renders the managed `alpha`.
    fn writer(&self) -> (LocalProjection, ProjectionSpec) {
        let identity = IdentityId::from_random_bytes(random());
        let keys = KeyBook::default();
        keys.0
            .lock()
            .unwrap()
            .insert(identity.as_str().to_owned(), synthetic_public_key());
        let mut config =
            ProjectionConfig::new(self.paths(), Platform::current(), self.config_dir.clone())
                .with_state_dir(self.state_dir.clone());
        config.env = self.env();
        let keys: Arc<dyn PublicKeySource> = Arc::new(keys);
        config.keys = Some(keys);
        let spec = ProjectionSpec {
            environment: EnvironmentId::from_random_bytes(random()),
            aliases: vec![ManagedAliasSpec {
                alias: "alpha".to_owned(),
                destination: DestinationId::parse("dst-alpha").unwrap(),
                hostname: "alpha.example.invalid".to_owned(),
                port: None,
                account: AccountName::parse("fixture").unwrap(),
                identity,
                endpoint: None,
                key_file: self
                    .config_dir
                    .join("keys")
                    .join("alpha.pub")
                    .to_str()
                    .unwrap()
                    .to_owned(),
                jump_alias: None,
            }],
            record: None,
            consent: ConsentRecord::default(),
        };
        (LocalProjection::writing(config).unwrap(), spec)
    }
}

fn apply_intent() -> PreviewIntent {
    PreviewIntent::Apply {
        include_git: false,
        distribution: None,
        items: Default::default(),
    }
}

/// A sink that keeps the commits in memory (the receipts are not inspected).
#[derive(Default)]
struct Sink(Vec<ItemCommit>);

impl StageSink for Sink {
    fn append(&mut self, _receipt: &LocalReceipt) -> Result<(), SinkError> {
        Ok(())
    }
    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), SinkError> {
        self.0.push(commit);
        Ok(())
    }
}

/// Synthetic public keys by identity (preview only).
#[derive(Default)]
struct KeyBook(Mutex<BTreeMap<String, String>>);

impl PublicKeySource for KeyBook {
    fn public_key(&self, identity: &IdentityId) -> Option<String> {
        self.0.lock().unwrap().get(identity.as_str()).cloned()
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

/// Standard base64 with padding.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A synthetic `ssh-ed25519` public key line over 32 random bytes; no private key exists.
fn synthetic_public_key() -> String {
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(random::<32>());
    format!("ssh-ed25519 {}", b64(&blob))
}

fn passive() -> DoctorRequest {
    let mut request = DoctorRequest::passive();
    request.local_queries = LocalQueries::Disabled;
    request
}

fn collisions(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.code == finding::ALIAS_COLLISION)
        .collect()
}

/// `(file as shown, line)` of each collision, sorted.
fn places(found: &[&Finding]) -> Vec<(String, u32)> {
    let mut out: Vec<(String, u32)> = found
        .iter()
        .map(|f| {
            let p = f.provenance.as_ref().unwrap();
            (p.path_display.clone(), p.line)
        })
        .collect();
    out.sort();
    out
}

const USER: &str =
    "Include {SSH}/conf.d/*.conf\n\nHost other\n    User someone\n\nHost ALPHA\n    User someone\n";
const INCLUDED: &str = "Host gamma alpha\n    Port 2200\n";

fn expected_places() -> Vec<(String, u32)> {
    vec![
        ("~/.ssh/conf.d/extra.conf".to_owned(), 1),
        ("~/.ssh/config".to_owned(), 6),
    ]
}

/// The doctor reports both lines (the user file's case variant and the included file's
/// exact literal), each once, with its file:line and the alias as subject; the observed
/// alias, the system file and P are never compared; `--redact` hides the alias.
#[test]
fn doctor_reports_a_same_name_host_line_in_the_user_file_and_an_included_file() {
    let s = Scratch::new(USER, &[("conf.d/extra.conf", INCLUDED)]);
    let report = doctor::run(&s.doctor(), &passive());
    let found = collisions(&report.findings);
    assert_eq!(places(&found), expected_places(), "{found:?}");
    for f in &found {
        assert_eq!(f.severity, FindingSeverity::Warning);
        assert_eq!(f.subject.kind, "destination");
        assert_eq!(f.subject.id.as_deref(), Some("alpha"));
        assert_eq!(f.message, USER_HOST_LINE_MESSAGE);
        assert!(!f.message.to_ascii_lowercase().contains("alpha"));
        assert_eq!(f.next.action, "review_config");
    }
    let mut redacted = passive();
    redacted.redact = true;
    let report = doctor::run(&s.doctor(), &redacted);
    for f in collisions(&report.findings) {
        let id = f.subject.id.as_deref().unwrap();
        assert!(id.starts_with("alias-"), "redacted subject: {id}");
    }
}

/// Setup's plan reports the same two lines as the conflict `alias_collision` and keeps its
/// steps (reported, not refused); without the lines there is no such finding, and the plan
/// digest binds the difference.
#[test]
fn setup_reports_the_conflict_and_keeps_its_steps() {
    let s = Scratch::new(USER, &[("conf.d/extra.conf", INCLUDED)]);
    let plan = s.preview();
    let found = collisions(&plan.view.findings);
    assert_eq!(places(&found), expected_places(), "{found:?}");
    for f in &found {
        assert_eq!(f.severity, FindingSeverity::Warning);
        assert_eq!(f.subject.id.as_deref(), Some("alpha"));
        let kind: ConflictKind =
            serde_json::from_value(serde_json::Value::String(f.reason.clone().unwrap())).unwrap();
        assert_eq!(kind, ConflictKind::AliasCollision);
    }
    assert!(!plan.files.is_empty(), "the plan keeps its steps");

    let clean = Scratch::new("Host other\n    User someone\n", &[]);
    let clean_plan = clean.preview();
    assert!(collisions(&clean_plan.view.findings).is_empty());
    assert!(!clean_plan.files.is_empty());
}

/// Reported, not refused, through the apply as well (the M08 track lead's ruling on U1b's
/// question): the plan with the conflict applies, its one item settles `applied` and is
/// committed once (never `conflict_preserved` or `not_applied`), and the user's own lines are
/// left as they were: the included file byte for byte, and every line of the user file
/// (which gains only Heimdall's include block). No claim is made here about how `ssh` then
/// matches `Host alpha`.
#[test]
fn setup_applies_the_plan_with_the_conflict_and_leaves_the_users_lines() {
    let s = Scratch::new(USER, &[("conf.d/extra.conf", INCLUDED)]);
    let included = s.home.join(".ssh").join("conf.d").join("extra.conf");
    let (user_before, included_before) = (
        std::fs::read_to_string(s.user_config()).unwrap(),
        std::fs::read(&included).unwrap(),
    );
    let (writer, spec) = s.writer();
    let plan = writer.preview(&spec, &apply_intent()).unwrap();
    assert_eq!(
        places(&collisions(&plan.view.findings)),
        expected_places(),
        "the conflict is in the plan applied"
    );
    let mut sink = Sink::default();
    let receipt = writer.apply(&plan.intent(), &mut sink).unwrap();
    assert!(
        matches!(
            receipt.items.as_slice(),
            [ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                ..
            }]
        ),
        "{:?}",
        receipt.items
    );
    assert_eq!(sink.0.len(), 1, "one item committed");
    assert_eq!(std::fs::read(&included).unwrap(), included_before);
    let user_after = std::fs::read_to_string(s.user_config()).unwrap();
    assert!(
        user_after.contains("Include \""),
        "B was inserted: {user_after}"
    );
    let kept: Vec<&str> = user_after.lines().collect();
    for line in user_before.lines() {
        assert!(kept.contains(&line), "kept: {line:?}");
    }
}

/// The stated limitation: wildcard, negated and `Match` lines, and a longer name, are not
/// compared, by the doctor or by setup.
#[test]
fn wildcard_negated_and_match_lines_are_out_of_scope() {
    let s = Scratch::new(
        "Host *\n    User x\nHost alph?\nHost alpha*\nHost !alpha other\nMatch host alpha\n    Port 2\nHost alphabet\n",
        &[],
    );
    assert!(collisions(&doctor::run(&s.doctor(), &passive()).findings).is_empty());
    assert!(collisions(&s.preview().view.findings).is_empty());
}

/// A legacy catalog pair whose aliases differ only in case (as the store lists it for the
/// doctor) is a `problem`: the managed file cannot render both. Named by destination ID only.
#[test]
fn doctor_reports_a_legacy_catalog_case_pair() {
    let s = Scratch::new("", &[]);
    let mut ctx = s.doctor();
    let (a, b) = (
        DestinationId::parse("dst-lab-upper").unwrap(),
        DestinationId::parse("dst-lab-lower").unwrap(),
    );
    ctx.alias_case_collisions = vec![(a.clone(), b.clone())];
    let report = doctor::run(&ctx, &passive());
    let found = collisions(&report.findings);
    assert_eq!(found.len(), 1, "{found:?}");
    let f = found[0];
    assert_eq!(f.severity, FindingSeverity::Problem);
    assert_eq!(f.subject.id.as_deref(), Some(a.as_str()));
    assert!(f.message.contains(a.as_str()) && f.message.contains(b.as_str()));
    assert!(f.provenance.is_none());
}
