//! M03 wave 2 (U8): managed sections in P, the preference, the `state_dir` refusal and the
//! client-aware `Include` expansion (m03-plan U8 "Tests"; ADR-0008 D10, D8 items 3 and 6;
//! ADR-0007 §4, §12.34 items 3 and 6).
//!
//! Cargo test target `integration_projection_managed`, hosted by `heimdall-localenv`.
//!
//! * The renderer's goldens (`heimdall_sshconf::render`): the D10 item 1 order with each
//!   identity form, the Windows pipe form, the owned-master path, and the M02 bytes of an
//!   existing-access alias.
//! * The preview (`LocalProjection::preview`) with a fake `ManagedPairSource`: a pair whose
//!   preference is `managed_certificate` renders its managed section with the slot paths of
//!   the one path function (`content::managed_slot_paths`, reading R7), shows it in the
//!   diff, needs the owner's decision, and discloses `slot_free`; nothing is written until
//!   the apply.
//! * Ordinary `ssh` through P (Unix): a scratch `-F` user configuration that includes the
//!   product's P (written by the product's own preview and apply), a `LoopbackSshd` that
//!   trusts a disposable CA, and a disposable `ssh-agent` standing in for the environment
//!   endpoint with the slot key and its certificate. The decoy agent at `SSH_AUTH_SOCK`
//!   is never contacted (ADR-0007 §9).
//!
//! Every key, CA and agent is generated per run in scratch and removed with it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use heimdall_app::ports::{ProjectionWriter, StageSink};
use heimdall_contract::doctor::{FindingSeverity, finding};
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, IdentityId};
use heimdall_contract::managed::ExistingConnectionsMode;
use heimdall_contract::provider::{EndpointKind, EndpointRef, IdentitySelection};
use heimdall_contract::setup::{PreviewIntent, ProjectionItem};
use heimdall_domain::operation::LocalReceipt;
use heimdall_domain::projection::{
    FileRole, ItemCommit, ManagedAliasSpec, ProjectionPlan, ProjectionSpec, StepContentView,
};
#[cfg(unix)]
use heimdall_localenv::env::Env;
use heimdall_localenv::env::Platform;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::content::{
    SlotPathRefused, checked_mux_path, managed_mux_path, managed_slot_paths, slot_component,
};
use heimdall_localenv::projection::plan::{
    DEADLINE_GRACEFUL_EXCLUSIVE, DEADLINE_GRACEFUL_NOT_EXCLUSIVE, DEADLINE_STRICT_EXCLUSIVE,
    DEADLINE_STRICT_NOT_EXCLUSIVE, deadline_wording, slot_free_command,
};
use heimdall_localenv::projection::{
    LocalProjection, ManagedPairSource, ManagedSectionSpec, ProjectionConfig, PublicKeySource,
    StateDirMissing,
};
use heimdall_sshconf::render::{
    AliasName, DEFAULT_MANAGED_IDENTITY_FORM, HostName, ManagedAlias, ManagedIdentityForm,
    PathStyle, RenderError, RenderPath, Section, render_managed, render_sections,
};
#[cfg(unix)]
use heimdall_testkit::home::ClientKind;
use heimdall_testkit::home::ScratchHome;

// --- fixtures -------------------------------------------------------------------------------

/// Synthetic public keys by identity (preview only).
#[derive(Default)]
struct KeyBook(Mutex<BTreeMap<String, String>>);

impl PublicKeySource for KeyBook {
    fn public_key(&self, identity: &IdentityId) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(identity.as_str())
            .cloned()
    }
}

/// The fake preference source: the managed section of each managed alias.
#[derive(Default)]
struct Managed(Mutex<BTreeMap<String, ManagedSectionSpec>>);

impl ManagedPairSource for Managed {
    fn managed_section(
        &self,
        alias: &ManagedAliasSpec,
    ) -> Result<Option<ManagedSectionSpec>, String> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&alias.alias)
            .cloned())
    }
}

/// A synthetic `ssh-ed25519` public key line over 32 random bytes (no private key).
fn synthetic_public_key() -> String {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).unwrap();
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend(raw);
    format!("ssh-ed25519 {}", b64(&blob))
}

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

/// The scratch world of one preview test.
struct Fx {
    home: ScratchHome,
    keys: Arc<KeyBook>,
    managed: Arc<Managed>,
    env: EnvironmentId,
}

impl Fx {
    fn new() -> Fx {
        let home = ScratchHome::new();
        std::fs::create_dir(home.root.join("etc-ssh")).unwrap();
        Fx {
            home,
            keys: Arc::default(),
            managed: Arc::default(),
            env: EnvironmentId::from_random_bytes([5; 16]),
        }
    }

    /// The writer's configuration; `source` adds the managed preference source.
    fn config(&self, source: bool) -> ProjectionConfig {
        let paths = SshPaths::with_test_override(
            self.home.git_home.clone(),
            self.home.root.join("etc-ssh"),
        );
        let mut c = ProjectionConfig::new(paths, Platform::current(), self.home.config_dir.clone())
            .with_state_dir(self.home.state_dir.clone());
        let keys: Arc<dyn PublicKeySource> = self.keys.clone();
        c.keys = Some(keys);
        if source {
            let managed: Arc<dyn ManagedPairSource> = self.managed.clone();
            c.managed = Some(managed);
        }
        c
    }

    fn writer(&self, source: bool) -> LocalProjection {
        LocalProjection::writing(self.config(source)).unwrap()
    }

    /// An alias's spec (`port` 22 renders no `Port`).
    fn alias(
        &self,
        name: &str,
        hostname: &str,
        port: Option<u16>,
        account: &str,
    ) -> ManagedAliasSpec {
        let identity = IdentityId::from_random_bytes([name.len() as u8; 16]);
        self.keys
            .0
            .lock()
            .unwrap()
            .insert(identity.as_str().to_owned(), synthetic_public_key());
        ManagedAliasSpec {
            alias: name.to_owned(),
            destination: DestinationId::parse(&format!("dst-{name}")).unwrap(),
            hostname: hostname.to_owned(),
            port,
            account: AccountName::parse(account).unwrap(),
            identity,
            endpoint: None,
            key_file: self
                .home
                .config_dir
                .join("keys")
                .join(format!("{name}.pub"))
                .to_str()
                .unwrap()
                .to_owned(),
        }
    }

    /// The environment endpoint of this platform's fixture (a scratch socket path, or a
    /// stable pipe name with the installation token).
    fn environment_endpoint(&self, token: &str) -> EndpointRef {
        if cfg!(windows) {
            EndpointRef {
                kind: EndpointKind::NamedPipe,
                locator: format!(r"\\.\pipe\heimdall-{token}-signing"),
            }
        } else {
            EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: self
                    .home
                    .root
                    .join("run")
                    .join("signing.sock")
                    .to_str()
                    .unwrap()
                    .to_owned(),
            }
        }
    }

    /// Make `spec`'s pair prefer `managed_certificate`, with its slot under the scratch
    /// state directory (the provisional `data_dir`, U8-Q2).
    fn prefer_managed(&self, spec: &ManagedAliasSpec, endpoint: EndpointRef) -> ManagedSectionSpec {
        let slot = managed_slot_paths(&self.home.state_dir, &spec.destination).unwrap();
        let section = ManagedSectionSpec {
            environment_endpoint: endpoint,
            key_pub: slot.key_pub,
            cert_pub: slot.cert_pub,
            control_path: None,
        };
        self.managed
            .0
            .lock()
            .unwrap()
            .insert(spec.alias.clone(), section.clone());
        section
    }

    fn spec(&self, aliases: Vec<ManagedAliasSpec>) -> ProjectionSpec {
        ProjectionSpec {
            environment: self.env.clone(),
            aliases,
            record: None,
            consent: heimdall_domain::projection::ConsentRecord::default(),
        }
    }

    fn p(&self) -> PathBuf {
        self.home.config_dir.join("ssh_config")
    }
}

fn apply_intent() -> PreviewIntent {
    PreviewIntent::Apply { include_git: false }
}

/// P's planned bytes in `plan` (its whole-file step).
fn planned_p(plan: &ProjectionPlan) -> String {
    let step = plan
        .files
        .iter()
        .find(|s| s.role == FileRole::ManagedSsh)
        .expect("a P step");
    match step.content.view() {
        StepContentView::Whole { bytes } => String::from_utf8(bytes.to_vec()).unwrap(),
        other => panic!("P is written whole: {other:?}"),
    }
}

/// The section of `alias` in P's text (from `Host <alias>` to the next section).
fn section_of<'a>(p: &'a str, alias: &str) -> &'a str {
    let start = p.find(&format!("\nHost {alias}\n")).expect("the section") + 1;
    let rest = &p[start..];
    let end = rest[1..].find("\nHost ").map_or(rest.len(), |i| i + 2);
    &rest[..end]
}

/// A test sink: receipts and commits in memory.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<ItemCommit>>>);

impl StageSink for Sink {
    fn append(&mut self, _receipt: &LocalReceipt) -> Result<(), heimdall_app::ports::SinkError> {
        Ok(())
    }
    fn commit_item(&mut self, commit: ItemCommit) -> Result<(), heimdall_app::ports::SinkError> {
        self.0.lock().unwrap().push(commit);
        Ok(())
    }
}

fn unix(path: &str) -> RenderPath {
    RenderPath::unix(Path::new(path)).unwrap()
}

fn managed_section(alias: &str, control_path: Option<RenderPath>) -> Section {
    Section::ManagedCertificate {
        alias: AliasName::parse(alias).unwrap(),
        hostname: HostName::parse("work.example.invalid").unwrap(),
        port: Some(2222),
        user: "deploy".to_owned(),
        endpoint: unix("/run/user/1000/heimdall/signing.sock"),
        key_pub: unix("~/.local/state/heimdall/managed/dst-work/key.pub"),
        cert: unix("~/.local/state/heimdall/managed/dst-work/cert.pub"),
        control_path,
    }
}

// --- the renderer ---------------------------------------------------------------------------

/// m03-plan U8: P renders a managed alias in D10 item 1's order with the slot paths and
/// `ControlPath none`, with each identity form's lines (reading R4), the default being the
/// INT-Q10 form; through the preview, the paths are the one slot path function's.
#[test]
fn p_renders_managed_alias_with_slot_paths_and_control_none() {
    let route = "Host work\n    HostName work.example.invalid\n    Port 2222\n    User deploy\n    \
                 IdentityAgent \"/run/user/1000/heimdall/signing.sock\"\n    IdentitiesOnly yes\n";
    let key = "    IdentityFile \"~/.local/state/heimdall/managed/dst-work/key.pub\"\n";
    let cert_id = "    IdentityFile \"~/.local/state/heimdall/managed/dst-work/cert.pub\"\n";
    let cert_file = "    CertificateFile \"~/.local/state/heimdall/managed/dst-work/cert.pub\"\n";
    let tail = "    ControlMaster no\n    ControlPath none\n";
    let header = "# heimdall managed ssh configuration (generated; do not edit)\n\n";
    for (form, identity) in [
        (
            ManagedIdentityForm::D10AsWritten,
            format!("{key}{cert_file}"),
        ),
        (
            ManagedIdentityForm::CertificateAsIdentityFile,
            cert_id.to_owned(),
        ),
        (
            ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile,
            format!("{cert_id}{cert_file}"),
        ),
    ] {
        let bytes =
            render_sections(&[managed_section("work", None)], PathStyle::Unix, form).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!("{header}{route}{identity}{tail}"),
            "{}",
            form.as_str()
        );
    }
    assert_eq!(
        DEFAULT_MANAGED_IDENTITY_FORM,
        ManagedIdentityForm::CertificateAsIdentityFile,
        "INT-Q10's decision"
    );
    assert_eq!(
        ManagedIdentityForm::select(None),
        DEFAULT_MANAGED_IDENTITY_FORM
    );

    // A Windows file: the environment pipe is written `//./pipe/…`, never `\\.\pipe\`.
    let windows = Section::ManagedCertificate {
        alias: AliasName::parse("work").unwrap(),
        hostname: HostName::parse("work.example.invalid").unwrap(),
        port: None,
        user: "deploy".to_owned(),
        endpoint: RenderPath::pipe(r"\\.\pipe\heimdall-0a1b2c3d-signing").unwrap(),
        key_pub: RenderPath::windows(Path::new(
            r"C:\Users\fx\AppData\Local\heimdall\state\managed\dst-work\key.pub",
        ))
        .unwrap(),
        cert: RenderPath::windows(Path::new(
            r"C:\Users\fx\AppData\Local\heimdall\state\managed\dst-work\cert.pub",
        ))
        .unwrap(),
        control_path: None,
    };
    let text = String::from_utf8(
        render_sections(
            &[windows],
            PathStyle::Windows,
            DEFAULT_MANAGED_IDENTITY_FORM,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        text.contains("    IdentityAgent \"//./pipe/heimdall-0a1b2c3d-signing\"\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "IdentityFile \"C:/Users/fx/AppData/Local/heimdall/state/managed/dst-work/cert.pub\""
        ),
        "{text}"
    );
    assert!(!text.contains('\\'), "{text}");
    // A pipe is never a key or certificate file; a pipe never goes into a Unix file.
    let mut bad = managed_section("work", None);
    if let Section::ManagedCertificate { cert, .. } = &mut bad {
        *cert = RenderPath::pipe("x").unwrap();
    }
    assert!(render_sections(&[bad], PathStyle::Windows, DEFAULT_MANAGED_IDENTITY_FORM).is_err());

    // Through the preview: the slot paths are `managed_slot_paths`'s, home-relative when
    // under the home (here the state directory is outside it, so absolute).
    let fx = Fx::new();
    let spec = fx.alias("work", "work.example.invalid", Some(2222), "deploy");
    let section = fx.prefer_managed(&spec, fx.environment_endpoint("0a1b2c3d"));
    let plan = fx
        .writer(true)
        .preview(&fx.spec(vec![spec.clone()]), &apply_intent())
        .unwrap();
    let p = planned_p(&plan);
    let text = section_of(&p, "work");
    let slot = managed_slot_paths(&fx.home.state_dir, &spec.destination).unwrap();
    assert_eq!(slot.cert_pub, section.cert_pub);
    let shown = |p: &Path| p.to_str().unwrap().replace('\\', "/");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let keyword = |l: &str| l.split(' ').next().unwrap().to_owned();
    assert_eq!(
        lines.iter().map(|l| keyword(l)).collect::<Vec<_>>(),
        [
            "Host",
            "HostName",
            "Port",
            "User",
            "IdentityAgent",
            "IdentitiesOnly",
            "IdentityFile",
            "ControlMaster",
            "ControlPath"
        ],
        "{text}"
    );
    assert!(
        lines.contains(&format!("IdentityFile \"{}\"", shown(&slot.cert_pub)).as_str()),
        "{text}"
    );
    assert!(lines.contains(&"ControlPath none"), "{text}");
    assert!(
        !text.contains(&shown(Path::new(&spec.key_file))),
        "no existing-access key for a managed alias"
    );
    assert!(
        plan.files.iter().all(|s| s.role != FileRole::Key),
        "a managed alias writes no M02 key file"
    );
}

/// ADR-0008 D8 item 3: once owned masters are enabled, P renders the slot's stable mux
/// path (`<runtime_dir>/mux/<destination-id>`); a Windows file refuses it (M-F7), and a
/// path beyond the socket limit is `mux_path_too_long`.
#[test]
fn p_renders_owned_master_control_path_when_enabled() {
    let dest = DestinationId::parse("dst-work").unwrap();
    let mux = managed_mux_path(Path::new("/run/user/1000/heimdall"), &dest).unwrap();
    assert_eq!(mux, Path::new("/run/user/1000/heimdall/mux/dst-work"));
    // ⟨wave-2 Windows native run⟩ The mux path is a Unix runtime path, rendered only into a
    // Unix P: on a Windows host `Path::join` writes `\` into it, which `RenderPath::unix`
    // refuses (owned multiplexing is unavailable on Windows, D8, M-F7; the refusal of a
    // mux path in a Windows file is asserted below on every host).
    if cfg!(unix) {
        let bytes = render_sections(
            &[managed_section(
                "work",
                Some(RenderPath::unix(&mux).unwrap()),
            )],
            PathStyle::Unix,
            DEFAULT_MANAGED_IDENTITY_FORM,
        )
        .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.ends_with(
                "    ControlMaster no\n    ControlPath \"/run/user/1000/heimdall/mux/dst-work\"\n"
            ),
            "{text}"
        );
        assert!(!text.contains("ControlPath none"));
    } else {
        assert!(
            RenderPath::unix(&mux).is_err(),
            "a Windows-built path is never a Unix render path"
        );
    }
    // `%` in the path is escaped like every rendered path.
    let pct = render_sections(
        &[managed_section("work", Some(unix("/run/h%e/mux/dst-work")))],
        PathStyle::Unix,
        DEFAULT_MANAGED_IDENTITY_FORM,
    )
    .unwrap();
    assert!(
        String::from_utf8(pct)
            .unwrap()
            .contains("ControlPath \"/run/h%%e/mux/dst-work\"")
    );
    // Windows: owned masters are unavailable, so a mux path is never rendered there.
    let windows = Section::ManagedCertificate {
        alias: AliasName::parse("work").unwrap(),
        hostname: HostName::parse("h").unwrap(),
        port: None,
        user: "deploy".to_owned(),
        endpoint: RenderPath::pipe("heimdall-t-signing").unwrap(),
        key_pub: RenderPath::windows(Path::new("C:/s/key.pub")).unwrap(),
        cert: RenderPath::windows(Path::new("C:/s/cert.pub")).unwrap(),
        control_path: Some(RenderPath::windows(Path::new("C:/s/mux")).unwrap()),
    };
    assert_eq!(
        render_sections(
            &[windows],
            PathStyle::Windows,
            DEFAULT_MANAGED_IDENTITY_FORM
        ),
        Err(RenderError::RefusedValue("control_path"))
    );
    // The socket-path limit (the M02 SUN_LEN lesson).
    let long = PathBuf::from(format!("/{}", "r".repeat(120)));
    assert_eq!(
        checked_mux_path(&long, &dest),
        Err(heimdall_contract::envelope::reason::MUX_PATH_TOO_LONG)
    );
    assert!(checked_mux_path(Path::new("/run/h"), &dest).is_ok());
    // Through the preview: the source's control path is rendered.
    let fx = Fx::new();
    let spec = fx.alias("work", "work.example.invalid", None, "deploy");
    let mut section = fx.prefer_managed(&spec, fx.environment_endpoint("t"));
    section.control_path =
        Some(managed_mux_path(&fx.home.root.join("run"), &spec.destination).unwrap());
    fx.managed
        .0
        .lock()
        .unwrap()
        .insert("work".to_owned(), section);
    if cfg!(unix) {
        let plan = fx
            .writer(true)
            .preview(&fx.spec(vec![spec]), &apply_intent())
            .unwrap();
        let p = planned_p(&plan);
        assert!(
            section_of(&p, "work").contains("/run/mux/dst-work\"\n"),
            "{p}"
        );
    }
}

/// The slot path function refuses a destination ID that is not one safe path component
/// (U8-Q3): traversal, an NTFS stream, a trailing dot, a device name, upper case.
#[test]
fn slot_paths_refuse_unsafe_destination_ids() {
    let id = |s: &str| DestinationId::parse(s).unwrap();
    for bad in [
        "..", ".hidden", "a:b", "work.", "NUL", "nul.txt", "Work", "com1",
    ] {
        assert_eq!(slot_component(&id(bad)), Err(SlotPathRefused), "{bad}");
        assert!(
            managed_slot_paths(Path::new("/d"), &id(bad)).is_err(),
            "{bad}"
        );
    }
    let ok = managed_slot_paths(Path::new("/d"), &id("dst-work_1.a")).unwrap();
    assert_eq!(ok.dir, Path::new("/d/managed/dst-work_1.a"));
    assert_eq!(ok.key_pub, Path::new("/d/managed/dst-work_1.a/key.pub"));
    assert_eq!(ok.cert_pub, Path::new("/d/managed/dst-work_1.a/cert.pub"));
}

/// m03-plan U8 (golden regression): an existing-access alias renders exactly the M02
/// bytes, alone or beside a managed section, and a preview whose preference source names
/// no managed pair plans the same P and the same plan digest as M02's writer.
#[test]
fn existing_access_aliases_render_byte_identical_to_m02() {
    let alpha = ManagedAlias {
        alias: AliasName::parse("alpha").unwrap(),
        hostname: HostName::parse("10.0.0.1").unwrap(),
        port: Some(2200),
        user: "deploy".to_owned(),
        identity_agent: Some(unix("/run/agent.sock")),
        identity_files: vec![unix("~/.config/heimdall/keys/k.pub")],
        identities_only: true,
    };
    // M02's bytes, as committed at the M02 exit (ADR-0007 §4).
    let golden = "# heimdall managed ssh configuration (generated; do not edit)\n\nHost alpha\n    \
                  HostName 10.0.0.1\n    Port 2200\n    User deploy\n    IdentityAgent \
                  \"/run/agent.sock\"\n    IdentityFile \"~/.config/heimdall/keys/k.pub\"\n    \
                  IdentitiesOnly yes\n";
    let m02 = render_managed(std::slice::from_ref(&alpha), PathStyle::Unix).unwrap();
    assert_eq!(String::from_utf8(m02.clone()).unwrap(), golden);
    for form in ManagedIdentityForm::ALL {
        let sections = render_sections(
            &[Section::ExistingAccess(alpha.clone())],
            PathStyle::Unix,
            form,
        )
        .unwrap();
        assert_eq!(sections, m02, "{}", form.as_str());
        let mixed = render_sections(
            &[
                managed_section("work", None),
                Section::ExistingAccess(alpha.clone()),
            ],
            PathStyle::Unix,
            form,
        )
        .unwrap();
        let mixed = String::from_utf8(mixed).unwrap();
        assert!(
            mixed.starts_with(golden),
            "the existing section's bytes are M02's: {mixed}"
        );
        assert!(
            !section_of(&mixed, "alpha").contains("Control"),
            "no new directive for it"
        );
    }
    // Through the preview: a source that names no managed pair changes nothing.
    let fx = Fx::new();
    let spec = fx.spec(vec![
        fx.alias("alpha", "alpha.example.invalid", None, "deploy"),
        fx.alias("beta", "beta.example.invalid", Some(2222), "deploy"),
    ]);
    let m02_plan = LocalProjection::new(fx.config(false))
        .preview(&spec, &apply_intent())
        .unwrap();
    let m03_plan = fx.writer(true).preview(&spec, &apply_intent()).unwrap();
    assert_eq!(planned_p(&m02_plan), planned_p(&m03_plan));
    assert_eq!(m02_plan.view.plan_digest, m03_plan.view.plan_digest);
    assert_eq!(m02_plan.view.findings, m03_plan.view.findings);
}

/// ADR-0008 D10 item 2, §17.4 item 12: the `ApplyProjection` preview of a managed alias
/// says that ordinary `ssh <alias>` needs a held slot and names the command that holds
/// one; the diff shows the managed section, and the change needs the owner's decision.
#[test]
fn apply_preview_discloses_slot_free_ordinary_ssh() {
    let fx = Fx::new();
    let work = fx.alias("work", "work.example.invalid", None, "deploy");
    let plain = fx.alias("plain", "plain.example.invalid", None, "deploy");
    fx.prefer_managed(&work, fx.environment_endpoint("t"));
    let plan = fx
        .writer(true)
        .preview(&fx.spec(vec![work.clone(), plain]), &apply_intent())
        .unwrap();
    let slot_free: Vec<_> = plan
        .view
        .findings
        .iter()
        .filter(|f| f.code == finding::SLOT_FREE)
        .collect();
    assert_eq!(
        slot_free.len(),
        1,
        "one disclosure, for the managed alias only"
    );
    let f = slot_free[0];
    assert_eq!(f.severity, FindingSeverity::Info);
    assert_eq!(f.subject.id.as_deref(), Some(work.destination.as_str()));
    assert!(f.message.contains("ordinary `ssh work`"), "{}", f.message);
    assert!(
        f.message.contains(&slot_free_command("work")),
        "{}",
        f.message
    );
    assert_eq!(
        slot_free_command("work"),
        "heimdall run --profile <profile> -- ssh work"
    );
    // The decision shows the managed section in its diff.
    let summary = plan.summary.as_ref().expect("a decision is required");
    assert!(plan.view.consent.decision_required);
    assert!(summary.added_aliases.contains(&"work".to_owned()));
    assert!(
        summary.diff_text.contains("+    ControlPath none"),
        "{}",
        summary.diff_text
    );
    assert!(summary.diff_text.contains("+    IdentitiesOnly yes"));
}

/// The managed section is a pending projection until `setup apply`: the preview plans it
/// and writes nothing; the apply (consented through M02's `ApplyProjection`) renders it
/// into P. (`ensure`'s `projection_pending` refusal meanwhile is U0b row 9's.)
#[test]
fn projection_pending_until_setup_apply() {
    let fx = Fx::new();
    let spec = fx.alias("work", "work.example.invalid", None, "deploy");
    fx.prefer_managed(&spec, fx.environment_endpoint("t"));
    let writer = fx.writer(true);
    let plan = writer
        .preview(&fx.spec(vec![spec]), &apply_intent())
        .unwrap();
    assert!(!fx.p().exists(), "the preview writes nothing");
    assert!(planned_p(&plan).contains("Host work\n"));
    let sink = Sink::default();
    let r = writer.apply(&plan.intent(), &mut sink.clone()).unwrap();
    assert!(
        matches!(
            r.items.as_slice(),
            [heimdall_app::ports::ItemOutcome::Applied {
                item: ProjectionItem::Ssh,
                ..
            }]
        ),
        "{:?}",
        r.items
    );
    let p = std::fs::read_to_string(fx.p()).unwrap();
    assert_eq!(p, planned_p(&plan));
    assert!(section_of(&p, "work").contains("ControlPath none"));
    let user = std::fs::read_to_string(&fx.home.user_config).unwrap();
    assert!(user.contains("Include \""), "B was inserted: {user}");
    assert_eq!(sink.0.lock().unwrap().len(), 1, "one item committed");
}

/// ADR-0008 D10 item 1: the Windows environment pipe name carries the installation token;
/// a changed token makes P stale, so the setup preview shows an update (and `ensure`
/// refuses `projection_pending` until it is applied, U0b row 9). The renderer row runs on
/// every platform; the preview row on Windows (the pipe is a Windows endpoint).
#[test]
fn windows_token_change_makes_p_stale_and_ensure_projection_pending() {
    let render = |token: &str| {
        let section = Section::ManagedCertificate {
            alias: AliasName::parse("work").unwrap(),
            hostname: HostName::parse("h").unwrap(),
            port: None,
            user: "deploy".to_owned(),
            endpoint: RenderPath::pipe(&format!(r"\\.\pipe\heimdall-{token}-signing")).unwrap(),
            key_pub: RenderPath::windows(Path::new("C:/s/key.pub")).unwrap(),
            cert: RenderPath::windows(Path::new("C:/s/cert.pub")).unwrap(),
            control_path: None,
        };
        String::from_utf8(
            render_sections(
                &[section],
                PathStyle::Windows,
                DEFAULT_MANAGED_IDENTITY_FORM,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let (a, b) = (render("tokena"), render("tokenb"));
    assert_ne!(a, b, "a new token is a new P");
    assert!(
        a.contains("//./pipe/heimdall-tokena-signing")
            && b.contains("//./pipe/heimdall-tokenb-signing")
    );
    #[cfg(windows)]
    {
        let fx = Fx::new();
        let spec = fx.alias("work", "work.example.invalid", None, "deploy");
        fx.prefer_managed(&spec, fx.environment_endpoint("tokena"));
        let writer = fx.writer(true);
        let plan = writer
            .preview(&fx.spec(vec![spec.clone()]), &apply_intent())
            .unwrap();
        writer.apply(&plan.intent(), &mut Sink::default()).unwrap();
        // The token changes (a state reset): the next preview plans an update of P.
        fx.prefer_managed(&spec, fx.environment_endpoint("tokenb"));
        let record = heimdall_domain::projection::ProjectionRecord {
            environment: fx.env.clone(),
            items: Default::default(),
        };
        let mut next = fx.spec(vec![spec]);
        next.record = Some(record);
        let update = writer.preview(&next, &apply_intent()).unwrap();
        assert!(planned_p(&update).contains("//./pipe/heimdall-tokenb-signing"));
        assert!(
            update.files.iter().any(|s| s.role == FileRole::ManagedSsh),
            "P is stale"
        );
    }
}

/// ADR-0008 D8 item 6 (F15): the deadline wording follows the identity selection: only
/// `exclusive` gets the unqualified text; `not_exclusive` and `undetermined` name the
/// identities Heimdall does not control. Both `existing` modes.
#[test]
fn deadline_wording_follows_identity_selection() {
    use ExistingConnectionsMode::{Graceful, Strict};
    use IdentitySelection::{Exclusive, NotExclusive, Undetermined};
    assert_eq!(
        DEADLINE_GRACEFUL_EXCLUSIVE,
        "New connections stop at the deadline; existing sessions may stay connected."
    );
    assert_eq!(
        DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
        "New connections through Heimdall's key stop at the deadline. Your other configured \
         identities for this host are not controlled; existing sessions may stay connected."
    );
    assert_eq!(
        deadline_wording(Exclusive, Graceful),
        DEADLINE_GRACEFUL_EXCLUSIVE
    );
    assert_eq!(
        deadline_wording(NotExclusive, Graceful),
        DEADLINE_GRACEFUL_NOT_EXCLUSIVE
    );
    assert_eq!(
        deadline_wording(Undetermined, Graceful),
        DEADLINE_GRACEFUL_NOT_EXCLUSIVE
    );
    assert_eq!(
        deadline_wording(Exclusive, Strict),
        DEADLINE_STRICT_EXCLUSIVE
    );
    assert_eq!(
        deadline_wording(NotExclusive, Strict),
        DEADLINE_STRICT_NOT_EXCLUSIVE
    );
    assert_eq!(
        deadline_wording(Undetermined, Strict),
        DEADLINE_STRICT_NOT_EXCLUSIVE
    );
    assert_eq!(
        DEADLINE_STRICT_EXCLUSIVE,
        "Connections Heimdall started are closed at the deadline."
    );
    for text in [
        DEADLINE_GRACEFUL_NOT_EXCLUSIVE,
        DEADLINE_STRICT_NOT_EXCLUSIVE,
    ] {
        assert!(text.contains("not controlled"), "{text}");
    }
}

// --- M02 residuals ---------------------------------------------------------------------------

/// ADR-0007 §12.34 item 6 (m02-exit §7): a writer a runtime wires is refused without a
/// state directory, so no edit of the owner's files can run without the original's
/// snapshot; with one, the first edit copies the original.
#[test]
fn writing_projection_config_without_state_dir_refused() {
    let fx = Fx::new();
    let mut without = fx.config(false);
    without.state_dir = None;
    assert_eq!(
        LocalProjection::writing(without).err(),
        Some(StateDirMissing)
    );
    // With a state directory: the writer exists, and its first edit of the user file
    // takes the snapshot first.
    std::fs::write(&fx.home.user_config, "Host other\n    User x\n").unwrap();
    let writer = LocalProjection::writing(fx.config(false)).unwrap();
    let spec = fx.spec(vec![fx.alias(
        "alpha",
        "alpha.example.invalid",
        None,
        "deploy",
    )]);
    let plan = writer.preview(&spec, &apply_intent()).unwrap();
    writer.apply(&plan.intent(), &mut Sink::default()).unwrap();
    let backups: Vec<_> = std::fs::read_dir(fx.home.state_dir.join("backups"))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(backups.len(), 1, "the original was copied before the edit");
    assert_eq!(
        std::fs::read(backups[0].path()).unwrap(),
        b"Host other\n    User x\n"
    );
}

/// ADR-0007 §12.34 item 3 (m02-exit §7): an `Include` the selected client would not
/// expand adds no candidate endpoint. OpenSSH 9.6p1 takes `${VAR}` in `Include`
/// literally, so the expanded file's `IdentityAgent` is not a candidate for it; 10.5p1
/// expands it; a client whose behaviour is not settled (unknown, or 9.5p2's unrecorded
/// fact) gets both readings, so a candidate is never hidden; M02's function is unchanged.
#[cfg(unix)]
#[test]
fn identity_agent_references_follow_client_include_behaviour() {
    use heimdall_localenv::agents::{
        EndpointLocator, identity_agent_references, identity_agent_references_for_client,
    };
    use heimdall_sshconf::eval::OpenSshVersion;
    let fx = Fx::new();
    let dir = fx.home.root.join("inc");
    std::fs::create_dir(&dir).unwrap();
    let expanded_sock = fx.home.root.join("expanded.sock");
    std::fs::write(
        dir.join("agents.conf"),
        format!("Host *\n  IdentityAgent {}\n", expanded_sock.display()),
    )
    .unwrap();
    // The literal reading names `~/.ssh/${HM_U8_INC}/agents.conf`: make it exist too, with
    // its own candidate, so each reading's candidate is distinguishable.
    let literal_dir = fx.home.ssh_dir.join("${HM_U8_INC}");
    std::fs::create_dir(&literal_dir).unwrap();
    let literal_sock = fx.home.root.join("literal.sock");
    std::fs::write(
        literal_dir.join("agents.conf"),
        format!("Host *\n  IdentityAgent {}\n", literal_sock.display()),
    )
    .unwrap();
    std::fs::write(&fx.home.user_config, "Include ${HM_U8_INC}/agents.conf\n").unwrap();
    let paths =
        SshPaths::with_test_override(fx.home.git_home.clone(), fx.home.root.join("etc-ssh"));
    let env = Env::from_vars([("HM_U8_INC", dir.clone().into_os_string())]);
    let candidates = |client: Option<OpenSshVersion>| -> Vec<EndpointLocator> {
        identity_agent_references_for_client(&env, &paths, Platform::current(), client)
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    };
    let v = |major, minor, p| OpenSshVersion {
        major,
        minor,
        portable: Some(p),
    };
    let expanded = EndpointLocator::UnixSocket(expanded_sock);
    let literal = EndpointLocator::UnixSocket(literal_sock);
    assert_eq!(
        candidates(Some(v(9, 6, 1))),
        std::slice::from_ref(&literal),
        "9.6p1: literal"
    );
    assert_eq!(
        candidates(Some(v(10, 5, 1))),
        std::slice::from_ref(&expanded),
        "10.5p1: expanded"
    );
    for unsettled in [None, Some(v(9, 5, 2)), Some(v(9, 9, 1))] {
        let both = candidates(unsettled);
        assert!(
            both.contains(&expanded) && both.contains(&literal),
            "{unsettled:?}: {both:?}"
        );
    }
    let m02: Vec<_> = identity_agent_references(&env, &paths, Platform::current())
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(m02, [expanded], "M02's reading is unchanged");
}

// --- ordinary ssh through P (Unix fixtures) -------------------------------------------------

/// m03-plan U8, ADR-0007 §9: ordinary `ssh <alias>` through the product's P (applied by the
/// product's own preview and apply into the scratch `-F` user configuration) authenticates
/// with the slot certificate through the environment endpoint P names; the decoy agent at
/// `SSH_AUTH_SOCK` is never contacted. The environment endpoint is a disposable `ssh-agent`
/// holding the slot key and its certificate, standing in for U2's signer.
#[cfg(unix)]
#[test]
fn ordinary_ssh_through_p_uses_environment_endpoint() {
    let fx = Fx::new();
    let world = Ordinary::start(&fx);
    let out = world.client(&fx, ClientKind::Ssh, &["true"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    world.assert_certificate_login(&fx, 1);
}

/// ADR-0008 D10 item 2: while the slot is free its files are absent, and ordinary `ssh
/// <alias>` through P fails closed: P's `IdentityFile` names a missing file under
/// `IdentitiesOnly yes`, so ssh offers nothing from the agent P names (which still holds
/// a certificate here) and the server accepts nothing. The decoy agent is never contacted.
#[cfg(unix)]
#[test]
fn absent_slot_fails_closed() {
    let fx = Fx::new();
    let world = Ordinary::start(&fx);
    let section = fx.managed.0.lock().unwrap().get("work").cloned().unwrap();
    std::fs::remove_file(&section.key_pub).unwrap();
    std::fs::remove_file(&section.cert_pub).unwrap();
    let out = world.client(&fx, ClientKind::Ssh, &["true"]);
    assert!(!out.status.success(), "a free slot must not authenticate");
    assert!(world.sshd.accepted_key_ids().is_empty(), "nothing accepted");
    assert!(
        world.sshd.accepted_log().is_empty(),
        "no key accepted either"
    );
    assert_eq!(
        fx.home.decoy_agent().contact_count(),
        0,
        "SSH_AUTH_SOCK never used"
    );
}

/// m03-plan U8: `git`, `scp` and `sftp` through the managed alias reach the server with
/// the slot certificate through the environment endpoint, never `SSH_AUTH_SOCK`.
#[cfg(unix)]
#[test]
fn git_scp_sftp_through_managed_alias() {
    let fx = Fx::new();
    let world = Ordinary::start(&fx);
    let file = fx.home.root.join("payload.bin");
    std::fs::write(&file, b"hm-u8 payload\n").unwrap();
    let remote = fx.home.root.join("copied.bin");
    let scp = world.client(
        &fx,
        ClientKind::Scp,
        &[
            file.to_str().unwrap(),
            &format!("work:{}", remote.display()),
        ],
    );
    assert!(
        scp.status.success(),
        "{}",
        String::from_utf8_lossy(&scp.stderr)
    );
    assert_eq!(std::fs::read(&remote).unwrap(), b"hm-u8 payload\n");
    let batch = fx.home.root.join("sftp.batch");
    std::fs::write(&batch, format!("ls {}\n", remote.display())).unwrap();
    let sftp = world.client(
        &fx,
        ClientKind::Sftp,
        &["-b", batch.to_str().unwrap(), "work"],
    );
    assert!(
        sftp.status.success(),
        "{}",
        String::from_utf8_lossy(&sftp.stderr)
    );
    let repo = fx.home.root.join("repo.git");
    let git_init = std::process::Command::new(heimdall_testkit::home::find_program("git").unwrap())
        .args(["init", "-q", "--bare"])
        .arg(&repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", fx.home.git_home.join(".gitconfig"))
        .env("HOME", &fx.home.git_home)
        .output()
        .unwrap();
    assert!(git_init.status.success());
    let git = world.client(
        &fx,
        ClientKind::Git,
        &["ls-remote", &format!("work:{}", repo.display())],
    );
    assert!(
        git.status.success(),
        "{}",
        String::from_utf8_lossy(&git.stderr)
    );
    world.assert_certificate_login(&fx, 3);
}

/// The world of the ordinary-client tests: a `LoopbackSshd` trusting a disposable CA, the
/// slot key and its certificate in the slot files, a disposable `ssh-agent` holding them
/// as the environment endpoint, and P applied into the scratch user configuration.
#[cfg(unix)]
struct Ordinary {
    sshd: heimdall_testkit::sshd::LoopbackSshd,
    _agent: heimdall_testkit::agent::DisposableSshAgent,
    key_id: String,
}

#[cfg(unix)]
impl Ordinary {
    fn start(fx: &Fx) -> Ordinary {
        use heimdall_testkit::agent::{AgentOptions, DisposableSshAgent, FixtureKey};
        use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
        use std::process::Command;
        let keygen = heimdall_testkit::home::find_program("ssh-keygen").expect("ssh-keygen");
        let add = heimdall_testkit::home::find_program("ssh-add").expect("ssh-add");
        let dir = fx.home.scratch().subdir("u8ca").unwrap();
        let ca = dir.join("ca");
        let run = |cmd: &mut Command| {
            let out = cmd.output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let tool = |program: &Path| {
            let mut c = Command::new(program);
            c.env_clear().env("PATH", "/usr/bin:/bin");
            c
        };
        run(tool(&keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
            .arg(&ca));
        let sshd = LoopbackSshd::start(
            fx.home.scratch(),
            SshdConfig {
                trusted_user_ca_keys: Some(ca.with_extension("pub")),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let account = sshd
            .login_account()
            .or_else(current_account)
            .expect("account");
        fx.home.trust_host_key(&sshd.host_key_line).unwrap();
        // The slot key and its certificate (principal = the login account).
        let key = FixtureKey::generate();
        let kdir = fx.home.scratch().subdir("u8key").unwrap();
        let private = kdir.join("slot");
        key.write_private(&private).unwrap();
        key.write_public(&kdir.join("slot.pub")).unwrap();
        let key_id = format!("hm-u8-{}", heimdall_testkit::agent::random_hex(8));
        run(tool(&keygen)
            .args(["-q", "-s"])
            .arg(&ca)
            .args(["-I", &key_id, "-n", &account, "-V", "-5m:+10m"])
            .arg(kdir.join("slot.pub")));
        let agent = DisposableSshAgent::start(fx.home.scratch(), AgentOptions::default()).unwrap();
        run(tool(&add)
            .arg(&private)
            .env("SSH_AUTH_SOCK", &agent.socket)
            .env("HOME", agent.home()));
        // The slot files, where the one path function puts them.
        let spec = fx.alias("work", "127.0.0.1", Some(sshd.port), &account);
        let section = fx.prefer_managed(
            &spec,
            EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: agent.socket.to_str().unwrap().to_owned(),
            },
        );
        std::fs::create_dir_all(section.key_pub.parent().unwrap()).unwrap();
        std::fs::copy(kdir.join("slot.pub"), &section.key_pub).unwrap();
        std::fs::copy(kdir.join("slot-cert.pub"), &section.cert_pub).unwrap();
        std::fs::remove_file(&private).unwrap();
        // P, by the product's own preview and apply, into the scratch user configuration.
        let writer = fx.writer(true);
        let plan = writer
            .preview(&fx.spec(vec![spec]), &apply_intent())
            .unwrap();
        writer.apply(&plan.intent(), &mut Sink::default()).unwrap();
        assert!(
            std::fs::read_to_string(&fx.home.user_config)
                .unwrap()
                .contains("Include \"")
        );
        Ordinary {
            sshd,
            _agent: agent,
            key_id,
        }
    }

    /// Run a client for the alias `work` with only the isolation arguments.
    fn client(&self, fx: &Fx, kind: ClientKind, args: &[&str]) -> std::process::Output {
        let git = matches!(kind, ClientKind::Git);
        let mut cmd = fx.home.client_command(kind, "work").unwrap();
        if git {
            cmd.current_dir(&fx.home.root);
        }
        cmd.args(args).stdin(std::process::Stdio::null());
        let out = cmd.output().unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    }

    /// The server accepted exactly the slot certificate (by key ID), `logins` times or
    /// more, and the decoy agent was never contacted.
    fn assert_certificate_login(&self, fx: &Fx, logins: usize) {
        let ids = self.sshd.accepted_key_ids();
        assert!(
            ids.len() >= logins && ids.iter().all(|id| *id == self.key_id),
            "accepted: {ids:?}"
        );
        assert_eq!(
            fx.home.decoy_agent().contact_count(),
            0,
            "SSH_AUTH_SOCK never used"
        );
    }
}
