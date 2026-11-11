//! M03 wave 2, INT-Q10 (ADR-0008 §17.18 item 3): which managed-alias identity form lets
//! each OpenSSH client authenticate **through the certificate alone**.
//!
//! **The finding being answered.** With `IdentityFile` naming K_env's `.pub` and an agent
//! that lists only the certificate, OpenSSH 9.5p2 and 9.6p1 pair the agent's certificate
//! with that file identity and sign with the file's absent private key, so they never ask
//! the agent for the certificate (observed for 9.6p1 natively on the devbox, wave 1;
//! `integration_credential_cert::certificate_identity_file_selection_observed_per_client`).
//! The signer never lists or signs the plain K_env key (ADR-0008 D2 item 4, F17), so the
//! projection must offer a form those clients complete with the certificate alone.
//!
//! **What runs.** For each candidate form, a real `ssh` (the host's; the devbox's 9.6p1
//! and Windows' in-box 9.5p2 in the native runs) logs in to a fixture sshd that trusts a
//! per-run test CA for exactly the pair's principal, through an agent endpoint that
//! **lists only the certificate**, as the real signer's environment and binding endpoints
//! do. The agent is an `ipc::signing::Signer` served by `ipc::signing::serve` over M01's
//! owner-only listener (a Unix socket in a 0700 scratch directory, or an owner-only named
//! pipe), so the transport is the product's. It records which key blob each sign request
//! names; it signs only a listed blob, with the K_env vault key.
//!
//! The alias block is the **product shape** of ADR-0008 D10 item 1 (`HostName`, `Port`,
//! `User`, `IdentityAgent`, the identity lines of the form, `ControlMaster no`,
//! `ControlPath none`), written into the scratch user configuration: the product
//! projection is the thing under test here (m03-plan §0.2's exception); the client itself
//! gets only the isolation arguments and the default-identity guard
//! (`ScratchHome::client_command`).
//!
//! Each row prints one `m03 observation: managed_identity_form` line (INT-Q4): the client
//! version, the form, ssh's exit status, which blob the agent was asked to sign (`cert`,
//! `plain`, `none`, `other`) and whether the server logged the certificate's acceptance.
//! Only the control row is asserted (an agent listing only the certificate with a decoy
//! `IdentityFile` and no `IdentitiesOnly`: every client must log in), plus the fixture's
//! own invariants (the plain K_env blob is never listed, no secret in any output). The
//! rows are observations, recorded per client; the integrator chooses the default form
//! from them (`.m03-wave2-api.md` §INT-Q10).
//!
//! Every key, CA and certificate is generated per run; every file lives in the run's
//! scratch directory and is removed with it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo, VaultSlot};
use heimdall_ipc::signing::{SignOutcome, Signer, SigningSession};
use heimdall_sshconf::render::{
    AliasName, HostName, ManagedIdentityForm, PathStyle, RenderPath, Section, render_sections,
};
use heimdall_testkit::agent::FixtureKey;
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::ca::{TestCa, UserCertSpec};
use heimdall_testkit::home::{ClientKind, ScratchHome, find_program, ssh_config_quote};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account};
use tokio_util::sync::CancellationToken;

// --- the certificate-only agent ----------------------------------------------------------

/// An agent that lists `listed` (certificate blobs of one vault key) and signs a listed
/// blob with that key. Records the key blob of every sign request and counts binds.
struct CertOnlyAgent {
    vault: Arc<KeyVault>,
    slot: VaultSlot,
    listed: Vec<Vec<u8>>,
    asked: Mutex<Vec<Vec<u8>>>,
    binds: AtomicUsize,
}

#[async_trait::async_trait]
impl Signer for CertOnlyAgent {
    async fn identities(&self, _session: &SigningSession) -> Vec<(Vec<u8>, String)> {
        self.listed
            .iter()
            .map(|b| (b.clone(), "heimdall:int-q10".to_owned()))
            .collect()
    }

    async fn sign(
        &self,
        _session: &SigningSession,
        key_blob: &[u8],
        data: &[u8],
        _flags: u32,
    ) -> SignOutcome {
        self.asked.lock().unwrap().push(key_blob.to_vec());
        if !self.listed.iter().any(|b| b == key_blob) {
            return SignOutcome::failure();
        }
        match self.vault.sign(&self.slot, data) {
            // A test agent with no grant and so no signing gate (ADR-0008 §17.15 item 2).
            Ok(sig) => SignOutcome::ungated_signature(&sig),
            Err(_) => SignOutcome::failure(),
        }
    }

    fn session_bind(&self, _session: &mut SigningSession, _payload: &[u8]) -> bool {
        self.binds.fetch_add(1, Ordering::SeqCst);
        true
    }
}

/// The agent served on an owner-only endpoint by a background thread with its own
/// runtime; stopped (and its socket removed by the listener's owner) on drop.
struct ServedAgent {
    agent: Arc<CertOnlyAgent>,
    locator: String,
    stop: CancellationToken,
    thread: Option<JoinHandle<()>>,
}

impl ServedAgent {
    fn start(home: &ScratchHome, name: &str, agent: CertOnlyAgent) -> ServedAgent {
        let agent = Arc::new(agent);
        let stop = CancellationToken::new();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<String>();
        let (a2, s2) = (Arc::clone(&agent), stop.clone());
        // ⟨wave-2 Windows native run⟩ The fixture endpoint testkit names: a socket in
        // the run's scratch directory, or a fixture pipe `\\.\pipe\heimdall-hmtest-<hex>-
        // <name>` (the default-identity guard admits only these; never loosened).
        let fixture = heimdall_testkit::agent::Endpoint::in_scratch(home.scratch(), name).unwrap();
        #[cfg(unix)]
        let heimdall_testkit::agent::Endpoint::UnixSocket(socket) = fixture else {
            panic!("a Unix fixture endpoint is a socket");
        };
        #[cfg(windows)]
        let heimdall_testkit::agent::Endpoint::NamedPipe(pipe) = fixture else {
            panic!("a Windows fixture endpoint is a pipe");
        };
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                #[cfg(unix)]
                let (listener, endpoint) = {
                    let l = heimdall_ipc::unix::Listener::bind(
                        &socket,
                        heimdall_ipc::EndpointKind::Signing,
                    )
                    .unwrap();
                    let locator = socket.to_string_lossy().into_owned();
                    (
                        l,
                        EndpointRef {
                            kind: EndpointKind::UnixSocket,
                            locator,
                        },
                    )
                };
                #[cfg(windows)]
                let (listener, endpoint) = {
                    let sid = heimdall_ipc::windows::current_user_sid().unwrap();
                    let l = heimdall_ipc::windows::Listener::bind(
                        &pipe,
                        heimdall_ipc::EndpointKind::Signing,
                        &sid,
                    )
                    .unwrap();
                    (
                        l,
                        EndpointRef {
                            kind: EndpointKind::NamedPipe,
                            locator: pipe.clone(),
                        },
                    )
                };
                ready_tx.send(endpoint.locator.clone()).unwrap();
                loop {
                    tokio::select! {
                        () = s2.cancelled() => break,
                        accepted = listener.accept() => {
                            let Ok((stream, peer)) = accepted else { continue };
                            let signer: Arc<dyn Signer> = a2.clone();
                            let (ep, tok) = (endpoint.clone(), s2.clone());
                            tokio::spawn(async move {
                                let _ = heimdall_ipc::signing::serve(stream, peer, ep, signer, tok).await;
                            });
                        }
                    }
                }
                #[cfg(unix)]
                let _ = fs::remove_file(listener.path());
            });
        });
        let locator = ready_rx.recv().unwrap();
        ServedAgent {
            agent,
            locator,
            stop,
            thread: Some(thread),
        }
    }

    /// The locator as `IdentityAgent` takes it (`//./pipe/…` on Windows; ADR-0008 D10 item 1).
    fn identity_agent(&self) -> String {
        if cfg!(windows) {
            self.locator.replace('\\', "/")
        } else {
            self.locator.clone()
        }
    }

    fn asked(&self) -> Vec<Vec<u8>> {
        self.agent.asked.lock().unwrap().clone()
    }
}

impl Drop for ServedAgent {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// --- forms --------------------------------------------------------------------------

/// A candidate identity form (`.m03-wave2-api.md` R4; ADR-0008 §17.18 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    /// D10 item 1 as written: `IdentitiesOnly yes`, `IdentityFile key.pub`,
    /// `CertificateFile cert.pub`.
    D10AsWritten,
    /// `IdentitiesOnly yes`, `IdentityFile cert.pub`, no `CertificateFile`.
    CertificateAsIdentityFile,
    /// `IdentitiesOnly yes`, `IdentityFile cert.pub`, `CertificateFile cert.pub`.
    CertificateAsIdentityFileAndCertificateFile,
    /// `IdentitiesOnly yes`, `IdentityFile <dir>/key` with no `key` or `key.pub` on disk,
    /// only `key-cert.pub` (OpenSSH loads `<IdentityFile>-cert.pub` itself).
    KeyStemWithCertificateOnly,
    /// `IdentitiesOnly yes`, `CertificateFile cert.pub`, `IdentityFile` a decoy key that
    /// is not K_env (no plain K_env anywhere in the configuration).
    DecoyIdentityFileAndCertificateFile,
}

impl Form {
    const ALL: [Form; 5] = [
        Form::D10AsWritten,
        Form::CertificateAsIdentityFile,
        Form::CertificateAsIdentityFileAndCertificateFile,
        Form::KeyStemWithCertificateOnly,
        Form::DecoyIdentityFileAndCertificateFile,
    ];

    fn name(self) -> &'static str {
        match self {
            Form::D10AsWritten => "d10_as_written",
            Form::CertificateAsIdentityFile => "certificate_as_identity_file",
            Form::CertificateAsIdentityFileAndCertificateFile => {
                "certificate_as_identity_file_and_certificate_file"
            }
            Form::KeyStemWithCertificateOnly => "key_stem_with_certificate_only",
            Form::DecoyIdentityFileAndCertificateFile => "decoy_identity_file_and_certificate_file",
        }
    }
}

/// The slot files of one run, as `<scratch>/managed/<dest>/…`.
struct SlotFiles {
    key_pub: PathBuf,
    cert_pub: PathBuf,
    stem: PathBuf,
    decoy_pub: PathBuf,
}

impl SlotFiles {
    fn write(dir: &Path, kenv: &PublicKeyInfo, cert_line: &str) -> SlotFiles {
        fs::create_dir_all(dir).unwrap();
        let key_pub = dir.join("key.pub");
        let cert_pub = dir.join("cert.pub");
        fs::write(&key_pub, format!("{}\n", kenv.openssh_line.trim_end())).unwrap();
        fs::write(&cert_pub, format!("{cert_line}\n")).unwrap();
        // The stem form: only `<stem>-cert.pub` exists.
        let stem_dir = dir.join("stem");
        fs::create_dir_all(&stem_dir).unwrap();
        let stem = stem_dir.join("key");
        fs::write(stem_dir.join("key-cert.pub"), format!("{cert_line}\n")).unwrap();
        let decoy_pub = dir.join("decoy.pub");
        let decoy = FixtureKey::generate();
        fs::write(
            &decoy_pub,
            format!("{}\n", decoy.public().to_openssh().unwrap().trim_end()),
        )
        .unwrap();
        SlotFiles {
            key_pub,
            cert_pub,
            stem,
            decoy_pub,
        }
    }

    fn identity_lines(&self, form: Form) -> String {
        let q = |p: &Path| ssh_config_quote(&p.to_string_lossy());
        match form {
            Form::D10AsWritten => format!(
                "  IdentitiesOnly yes\n  IdentityFile {}\n  CertificateFile {}\n",
                q(&self.key_pub),
                q(&self.cert_pub)
            ),
            Form::CertificateAsIdentityFile => format!(
                "  IdentitiesOnly yes\n  IdentityFile {}\n",
                q(&self.cert_pub)
            ),
            Form::CertificateAsIdentityFileAndCertificateFile => format!(
                "  IdentitiesOnly yes\n  IdentityFile {}\n  CertificateFile {}\n",
                q(&self.cert_pub),
                q(&self.cert_pub)
            ),
            Form::KeyStemWithCertificateOnly => {
                format!("  IdentitiesOnly yes\n  IdentityFile {}\n", q(&self.stem))
            }
            Form::DecoyIdentityFileAndCertificateFile => format!(
                "  IdentitiesOnly yes\n  IdentityFile {}\n  CertificateFile {}\n",
                q(&self.decoy_pub),
                q(&self.cert_pub)
            ),
        }
    }
}

/// D10 item 1's block for `alias` with `form`'s identity lines.
fn product_block(
    alias: &str,
    port: u16,
    user: &str,
    agent: &ServedAgent,
    files: &SlotFiles,
    form: Form,
) -> String {
    format!(
        "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  IdentityAgent {}\n{}  ControlMaster no\n  ControlPath none\n",
        ssh_config_quote(&agent.identity_agent()),
        files.identity_lines(form)
    )
}

/// P's managed section for `alias`, rendered by `heimdall_sshconf::render::render_sections`
/// in the selected form (the header comment kept: it is part of P's bytes).
fn rendered_p_block(
    alias: &str,
    port: u16,
    user: &str,
    agent: &ServedAgent,
    files: &SlotFiles,
) -> String {
    #[cfg(windows)]
    let (style, endpoint, key_pub, cert) = (
        PathStyle::Windows,
        RenderPath::pipe(&agent.locator).unwrap(),
        RenderPath::windows(&files.key_pub).unwrap(),
        RenderPath::windows(&files.cert_pub).unwrap(),
    );
    #[cfg(unix)]
    let (style, endpoint, key_pub, cert) = (
        PathStyle::Unix,
        RenderPath::unix(Path::new(&agent.locator)).unwrap(),
        RenderPath::unix(&files.key_pub).unwrap(),
        RenderPath::unix(&files.cert_pub).unwrap(),
    );
    let section = Section::ManagedCertificate {
        alias: AliasName::parse(alias).unwrap(),
        hostname: HostName::parse("127.0.0.1").unwrap(),
        port: Some(port),
        user: user.to_owned(),
        endpoint,
        key_pub,
        cert,
        control_path: None,
    };
    let bytes = render_sections(&[section], style, ManagedIdentityForm::select(None)).unwrap();
    String::from_utf8(bytes).unwrap()
}

/// The control block: a decoy `IdentityFile`, no `IdentitiesOnly`, the same agent.
fn control_block(
    alias: &str,
    port: u16,
    user: &str,
    agent: &ServedAgent,
    files: &SlotFiles,
) -> String {
    format!(
        "Host {alias}\n  HostName 127.0.0.1\n  Port {port}\n  User {user}\n  IdentityAgent {}\n  IdentityFile {}\n",
        ssh_config_quote(&agent.identity_agent()),
        ssh_config_quote(&files.decoy_pub.to_string_lossy())
    )
}

fn login(home: &ScratchHome, alias: &str) -> Output {
    let mut cmd = home.client_command(ClientKind::Ssh, alias).unwrap();
    cmd.arg("true").stdin(Stdio::null());
    let out = cmd.output().unwrap();
    assert_no_canary(&String::from_utf8_lossy(&out.stdout));
    assert_no_canary(&String::from_utf8_lossy(&out.stderr));
    out
}

fn client_version() -> String {
    Command::new(find_program("ssh").unwrap())
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
        .unwrap_or_default()
}

/// The last lines of ssh's stderr with the scratch root and account redacted.
fn stderr_tail(home: &ScratchHome, out: &Output, account: &str) -> String {
    let root = home.root.to_string_lossy().into_owned();
    let text = String::from_utf8_lossy(&out.stderr);
    let tail: Vec<&str> = text.lines().rev().take(12).collect();
    let joined = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    let joined = joined.replace(&root, "<scratch>");
    if account.len() >= 2 {
        joined.replace(account, "<user>")
    } else {
        joined
    }
}

/// INT-Q10: every candidate form, one observation row each, plus the asserted control.
#[test]
fn managed_identity_forms_observed_per_client() {
    let home = ScratchHome::new();
    let ca = TestCa::generate(home.scratch()).unwrap();
    // The account form: an empty explicit registry, then the CA line for exactly the
    // principal of the account the server authenticates (the harness's on Windows).
    let sshd = LoopbackSshd::start(
        home.scratch(),
        SshdConfig {
            registry_seed: Some(Vec::new()),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let account = sshd
        .login_account()
        .or_else(current_account)
        .expect("the fixture login account");
    let destination = "hm-intq10-dest";
    let principal = format!("hm:{destination}:{account}");
    sshd.append_registry_line(&ca.cert_authority_line(&[&principal], None))
        .unwrap();
    home.trust_host_key(&sshd.host_key_line).unwrap();

    let vault = Arc::new(KeyVault::new());
    let (slot, info) = vault.generate_ed25519().unwrap();
    let subject = info.public_key().unwrap();
    let cert = ca
        .sign_user(&subject, &UserCertSpec::for_principal(&principal))
        .unwrap();
    let cert_blob = cert.to_bytes().unwrap();
    let cert_line = cert.to_openssh().unwrap();
    assert_ne!(
        cert_blob, info.blob,
        "the fixture lists a certificate, not the key"
    );

    let files = SlotFiles::write(
        &home.root.join("managed").join(destination),
        &info,
        &cert_line,
    );
    let agent = ServedAgent::start(
        &home,
        "q10",
        CertOnlyAgent {
            vault: Arc::clone(&vault),
            slot,
            listed: vec![cert_blob.clone()],
            asked: Mutex::new(Vec::new()),
            binds: AtomicUsize::new(0),
        },
    );
    assert!(
        !agent.agent.listed.contains(&info.blob),
        "F17: the plain K_env blob is never listed"
    );

    // Context rows (not candidates): (1) D10 as written with **owner-only** slot files,
    // to separate the "public slot files" effect from the form itself (D10 item 2 makes
    // them public); (2) the shape of the D5 §6.5 item 3 verification configuration, whose
    // endpoint lists K_verify **and** its certificate (ADR-0008 D2's table), to show U2
    // which blob each client asks a verification endpoint to sign.
    let private_files = SlotFiles::write(
        &home.root.join("managed-private").join(destination),
        &info,
        &cert_line,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&private_files.key_pub, &private_files.cert_pub] {
            fs::set_permissions(f, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let both = ServedAgent::start(
        &home,
        "q10v",
        CertOnlyAgent {
            vault: Arc::clone(&vault),
            slot,
            listed: vec![cert_blob.clone(), info.blob.clone()],
            asked: Mutex::new(Vec::new()),
            binds: AtomicUsize::new(0),
        },
    );

    let mut config = control_block("q10-control", sshd.port, &account, &agent, &files);
    for (i, form) in Form::ALL.iter().enumerate() {
        config.push_str(&product_block(
            &format!("q10-form-{i}"),
            sshd.port,
            &account,
            &agent,
            &files,
            *form,
        ));
    }
    config.push_str(&product_block(
        "q10-ctx-private",
        sshd.port,
        &account,
        &agent,
        &private_files,
        Form::D10AsWritten,
    ));
    config.push_str(&product_block(
        "q10-ctx-verify",
        sshd.port,
        &account,
        &both,
        &files,
        Form::D10AsWritten,
    ));
    // The product row: P's managed section as the real renderer writes it, in the form
    // `ManagedIdentityForm::select` picks (the default P and `connect` use).
    config.push_str(&rendered_p_block(
        "q10-rendered-p",
        sshd.port,
        &account,
        &agent,
        &files,
    ));
    home.write_user_config(&config).unwrap();

    let client = client_version();
    let which = |blobs: &[Vec<u8>]| -> &'static str {
        match blobs.first() {
            None => "none",
            Some(k) if *k == cert_blob => "cert",
            Some(k) if *k == info.blob => "plain",
            Some(_) => "other",
        }
    };
    let mut rows: Vec<(String, Output, Vec<Vec<u8>>, usize)> = Vec::new();
    let mut aliases: Vec<(String, String, &ServedAgent)> =
        vec![("control".to_owned(), "q10-control".to_owned(), &agent)];
    for (i, form) in Form::ALL.iter().enumerate() {
        aliases.push((form.name().to_owned(), format!("q10-form-{i}"), &agent));
    }
    if cfg!(unix) {
        aliases.push((
            "context_d10_as_written_owner_only_files".to_owned(),
            "q10-ctx-private".to_owned(),
            &agent,
        ));
    }
    aliases.push((
        "context_verification_shape_key_and_certificate_listed".to_owned(),
        "q10-ctx-verify".to_owned(),
        &both,
    ));
    aliases.push((
        format!("rendered_p_{}", ManagedIdentityForm::select(None).as_str()),
        "q10-rendered-p".to_owned(),
        &agent,
    ));
    for (name, alias, served) in aliases {
        let before = served.asked().len();
        let accepted_before = sshd.accepted_certificates().len();
        let out = login(&home, &alias);
        let asked: Vec<Vec<u8>> = served.asked()[before..].to_vec();
        let accepted = sshd
            .accepted_certificates()
            .len()
            .saturating_sub(accepted_before);
        #[allow(clippy::print_stderr)] // an observation row (INT-Q4)
        {
            eprintln!(
                "m03 observation: managed_identity_form client={client:?} form={name} exit={:?} signed={} sign_requests={} accepted_cert_logins={accepted}",
                out.status.code(),
                which(&asked),
                asked.len(),
            );
            if !out.status.success() {
                eprintln!(
                    "m03 observation: managed_identity_form_detail form={name} stderr_tail={:?}",
                    stderr_tail(&home, &out, &account)
                );
            }
        }
        rows.push((name, out, asked, accepted));
    }

    // The certificate-only agent was never asked for the plain K_env blob it does not
    // list (the verification-shaped context row lists both, so it is excluded).
    for (name, _, asked, _) in rows
        .iter()
        .filter(|r| !r.0.starts_with("context_verification"))
    {
        assert!(
            asked.iter().all(|k| *k != info.blob),
            "{name}: a client asked the agent for the unlisted plain K_env blob"
        );
    }
    let (_, control, control_asked, _) = &rows[0];
    assert!(
        control.status.success(),
        "control: ssh exit {:?}: {}",
        control.status.code(),
        stderr_tail(&home, control, &account)
    );
    assert_eq!(
        which(control_asked),
        "cert",
        "control: the certificate signs"
    );
}
