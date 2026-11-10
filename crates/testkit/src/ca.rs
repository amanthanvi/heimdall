//! The run's disposable test CA (m03-plan U11 `ca::TestCa`; ADR-0008 D13 item 1).
//! Features `fixtures` and `managed`.
//!
//! **In-memory form** ([`TestCa::generate`]): a K_ca from
//! [`SecretCaKey::generate`] (the OS CSPRNG), its public line and fingerprint, and the
//! public key written to a scratch file for an sshd's `TrustedUserCAKeys` or an account
//! registry's `cert-authority` line. It signs fixture user certificates
//! ([`TestCa::sign_user`]) through U1's `heimdall_credential::cert::build_and_sign`
//! (one principal, flag extensions, no critical options: the managed profile's shape).
//! Deliberately deviating certificates (several principals, critical options,
//! extension data) go through [`TestCa::sign_user_raw`], `ssh-key`'s certificate
//! builder, where the private key is reached only through
//! [`SecretCaKey::to_secret_bytes`] (zeroizing memory, dropped at once). Nothing private
//! is ever written to disk except a fixture **user** key in scratch
//! ([`TestCa::issue_files`]); the CA's key never is.
//!
//! **Ceremony form** ([`ceremony`]): drives the real `heimdall issuer init` ceremony
//! over a pty and returns the fingerprint and the passphrase captured from the pty
//! transcript, for scanning (A33). It needs U12's CLI handler; until then it fails
//! closed with [`ceremony::CeremonyError::Unavailable`] when the binary does not run
//! the ceremony (see that module).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::BTreeSet;

use heimdall_contract::ids::CaFingerprint;
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Certificate, HashAlg, PrivateKey, PublicKey};

use crate::agent::FixtureKey;
use crate::home::Scratch;

/// A disposable CA for one run (in-memory form). `Debug` shows the fingerprint only.
pub struct TestCa {
    key: SecretCaKey,
    public_line: String,
    fingerprint: CaFingerprint,
    pub_file: PathBuf,
}

impl fmt::Debug for TestCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestCa")
            .field("fingerprint", &self.fingerprint.as_str())
            .finish_non_exhaustive()
    }
}

/// What a fixture user certificate carries (ADR-0005 §3.4's shape, but every field is
/// the test's choice, so fixtures can also build deviating certificates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCertSpec {
    /// The key ID (`heimdall:<env>:<grant>:<serial>` for a managed-profile certificate).
    pub key_id: String,
    /// The principals (never empty: an empty list would be valid for every principal).
    pub principals: Vec<String>,
    /// `valid_after`, Unix seconds.
    pub valid_after: u64,
    /// `valid_before`, Unix seconds.
    pub valid_before: u64,
    /// The serial.
    pub serial: u64,
    /// Extensions (name, data); `permit-pty` and the like have empty data.
    pub extensions: Vec<(String, String)>,
    /// Critical options (name, data).
    pub critical_options: Vec<(String, String)>,
}

impl UserCertSpec {
    /// One principal, key ID `hm-fixture`, valid from 60 s ago for 300 s, serial 1, no
    /// extensions (`ssh -T` needs none), no critical options.
    #[must_use]
    pub fn for_principal(principal: &str) -> UserCertSpec {
        let now = unix_now();
        UserCertSpec {
            key_id: "hm-fixture".to_owned(),
            principals: vec![principal.to_owned()],
            valid_after: now.saturating_sub(60),
            valid_before: now + 300,
            serial: 1,
            extensions: Vec::new(),
            critical_options: Vec::new(),
        }
    }
}

/// A user key and its certificate written to scratch, for a scratch client
/// configuration's `IdentityFile` and `CertificateFile` (never a command line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFiles {
    /// The private key (owner-only).
    pub identity: PathBuf,
    /// `<identity>-cert.pub`.
    pub certificate: PathBuf,
    /// The certificate's key ID.
    pub key_id: String,
}

/// The current Unix time in seconds (0 before the epoch).
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn other(what: &str) -> io::Error {
    io::Error::other(format!("test CA: {what}"))
}

impl TestCa {
    /// Generate a fresh CA and write its public key to `<scratch>/ca<n>/test_ca.pub`.
    ///
    /// # Errors
    /// The CSPRNG failed, or the scratch write failed.
    pub fn generate(scratch: &Scratch) -> io::Result<TestCa> {
        let key = SecretCaKey::generate().map_err(|e| other(&e.to_string()))?;
        let public_line = key
            .public_openssh()
            .map_err(|e| other(&e.to_string()))?
            .trim_end()
            .to_owned();
        let fingerprint = key.fingerprint().map_err(|e| other(&e.to_string()))?;
        let dir = scratch.subdir("ca")?;
        let pub_file = dir.join("test_ca.pub");
        fs::write(&pub_file, format!("{public_line}\n"))?;
        Ok(TestCa {
            key,
            public_line,
            fingerprint,
            pub_file,
        })
    }

    /// `ssh-ed25519 AAAA…`, no comment.
    #[must_use]
    pub fn public_line(&self) -> &str {
        &self.public_line
    }

    /// The CA's public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    /// `SHA256:…`.
    #[must_use]
    pub fn fingerprint(&self) -> &CaFingerprint {
        &self.fingerprint
    }

    /// The scratch file holding [`Self::public_line`] (for `TrustedUserCAKeys`).
    #[must_use]
    pub fn pub_file(&self) -> &Path {
        &self.pub_file
    }

    /// The CA key, for code under test that takes a [`SecretCaKey`] (U1's
    /// `build_and_sign`, U4's stores).
    #[must_use]
    pub fn secret(&self) -> &SecretCaKey {
        &self.key
    }

    /// The account-form registry line for `principals` (ADR-0008 D5 §6.1 shape:
    /// `cert-authority,principals="a,b" <ca>`), with an optional trailing marker comment.
    #[must_use]
    pub fn cert_authority_line(&self, principals: &[&str], marker: Option<&str>) -> String {
        let mut line = format!(
            "cert-authority,principals=\"{}\" {}",
            principals.join(","),
            self.public_line
        );
        if let Some(marker) = marker {
            line.push(' ');
            line.push_str(marker);
        }
        line
    }

    /// Sign a user certificate for `subject` with U1's `build_and_sign`. The spec must
    /// have the managed profile's shape: exactly one principal, flag extensions (empty
    /// data) and no critical options; use [`Self::sign_user_raw`] for deviations.
    ///
    /// # Errors
    /// A spec outside that shape, or `build_and_sign` refused the profile.
    pub fn sign_user(&self, subject: &PublicKey, spec: &UserCertSpec) -> io::Result<Certificate> {
        let [principal] = spec.principals.as_slice() else {
            return Err(other(
                "sign_user takes one principal (sign_user_raw for more)",
            ));
        };
        if !spec.critical_options.is_empty() || spec.extensions.iter().any(|(_, d)| !d.is_empty()) {
            return Err(other(
                "sign_user takes flag extensions only (sign_user_raw)",
            ));
        }
        let to_i64 = |v: u64| i64::try_from(v).map_err(|_| other("validity out of range"));
        let profile = CertificateProfile {
            serial: spec.serial,
            key_id: spec.key_id.clone(),
            principal: principal.clone(),
            valid_after: to_i64(spec.valid_after)?,
            valid_before: to_i64(spec.valid_before)?,
            extensions: spec
                .extensions
                .iter()
                .map(|(n, _)| n.clone())
                .collect::<BTreeSet<String>>(),
            subject_fingerprint: subject.fingerprint(HashAlg::Sha256).to_string(),
            ca_fingerprint: Some(self.fingerprint.clone()),
        };
        build_and_sign(&profile, subject, &self.key)
            .map_err(|e| other(&format!("build_and_sign refused: {e:?}")))
    }

    /// Sign any user certificate for `subject` as `spec` says, with `ssh-key`'s builder
    /// (for deliberately deviating fixtures: several principals, critical options,
    /// extension data).
    ///
    /// # Errors
    /// An empty principal list (refused: it would be valid for every principal), or
    /// `ssh-key` refused a field.
    pub fn sign_user_raw(
        &self,
        subject: &PublicKey,
        spec: &UserCertSpec,
    ) -> io::Result<Certificate> {
        if spec.principals.is_empty() {
            return Err(other("a fixture certificate needs at least one principal"));
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| other("randomness unavailable"))?;
        let bad = |e: ssh_key::Error| other(&format!("certificate field refused: {e}"));
        let mut builder = Builder::new(
            nonce.to_vec(),
            subject.key_data().clone(),
            spec.valid_after,
            spec.valid_before,
        )
        .map_err(bad)?;
        builder
            .serial(spec.serial)
            .map_err(bad)?
            .cert_type(CertType::User)
            .map_err(bad)?
            .key_id(spec.key_id.clone())
            .map_err(bad)?;
        for p in &spec.principals {
            builder.valid_principal(p.clone()).map_err(bad)?;
        }
        for (name, data) in &spec.extensions {
            builder.extension(name.clone(), data.clone()).map_err(bad)?;
        }
        for (name, data) in &spec.critical_options {
            builder
                .critical_option(name.clone(), data.clone())
                .map_err(bad)?;
        }
        // Zeroized on drop (`SecretCaKey::to_secret_bytes` hands out `Zeroizing`).
        let secret = self
            .key
            .to_secret_bytes()
            .map_err(|e| other(&e.to_string()))?;
        let signer = PrivateKey::from_openssh(secret.as_slice()).map_err(|_| other("CA key"))?;
        drop(secret);
        builder.sign(&signer).map_err(bad)
    }

    /// Write `key`'s private half to `<dir>/<name>` (owner-only, scratch only) and a
    /// certificate for it, signed as `spec` says ([`Self::sign_user`] for a one-principal
    /// flag-only spec, [`Self::sign_user_raw`] otherwise), to `<dir>/<name>-cert.pub`.
    ///
    /// # Errors
    /// As the signing call, or a write failed (including an existing file).
    pub fn issue_files(
        &self,
        key: &FixtureKey,
        spec: &UserCertSpec,
        dir: &Path,
        name: &str,
    ) -> io::Result<CertFiles> {
        let profile_shaped = spec.principals.len() == 1
            && spec.critical_options.is_empty()
            && spec.extensions.iter().all(|(_, d)| d.is_empty());
        let cert = if profile_shaped {
            self.sign_user(key.public(), spec)?
        } else {
            self.sign_user_raw(key.public(), spec)?
        };
        let identity = dir.join(name);
        key.write_private(&identity)?;
        let certificate = dir.join(format!("{name}-cert.pub"));
        let line = cert
            .to_openssh()
            .map_err(|_| other("certificate encoding"))?;
        fs::write(&certificate, format!("{}\n", line.trim_end()))?;
        Ok(CertFiles {
            identity,
            certificate,
            key_id: spec.key_id.clone(),
        })
    }
}

pub mod ceremony {
    //! The ceremony form of the test CA (m03-plan U11 `ca::TestCa`; ADR-0008 D13 item 1,
    //! D4 item 1): `heimdall issuer init --backup-out <scratch>` on a pty, with the
    //! disclosure answered `yes` and the passphrase acknowledged `written`, returning
    //! the CA fingerprint and the passphrase **captured from the pty transcript** (the
    //! one place it may appear, A33), for scanning. Nothing is typed but `yes` and
    //! `written`; the passphrase is never in any argv.
    //!
    //! The pty comes from the host's `script` (`script -q /dev/null <cmd>` on macOS and
    //! the BSDs; `script -q -e -c <cmd> /dev/null` with util-linux). **Status:** written
    //! against the CLI as ADR-0008 D4 specifies it; U12's handler does not exist yet, so a
    //! binary that ends without showing a passphrase is
    //! [`CeremonyError::NoPassphrase`] (never a pass). Its self-test
    //! `test_ca_ceremony_captures_passphrase_only_from_pty` waits for U12.

    use std::ffi::OsString;
    use std::fmt;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use heimdall_contract::ids::CaFingerprint;

    use crate::home::{find_program, sh_join};

    /// The passphrase: 26 RFC 4648 base32 symbols (ADR-0008 D4 item 1.1). Overwritten
    /// on drop; its `Debug` shows only its length.
    pub struct Passphrase(Vec<u8>);

    impl Passphrase {
        /// The symbols, for scanning outputs (never print them).
        #[must_use]
        pub fn expose(&self) -> &[u8] {
            &self.0
        }
    }

    impl fmt::Debug for Passphrase {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Passphrase({} symbols)", self.0.len())
        }
    }

    impl Drop for Passphrase {
        fn drop(&mut self) {
            self.0.fill(0);
        }
    }

    /// What one ceremony produced. The transcript holds the passphrase: it is for
    /// scanning, never for printing (`Debug` shows its length only).
    pub struct CeremonyCa {
        /// The CA fingerprint the ceremony reported.
        pub fingerprint: CaFingerprint,
        /// The passphrase captured from the transcript.
        pub passphrase: Passphrase,
        /// The backup file (`--backup-out`).
        pub backup: PathBuf,
        /// The binary's exit status (through `script`).
        pub status: Option<i32>,
        transcript: Vec<u8>,
    }

    impl CeremonyCa {
        /// The whole pty transcript (the one allowed location of the passphrase).
        #[must_use]
        pub fn transcript(&self) -> &[u8] {
            &self.transcript
        }
    }

    impl Drop for CeremonyCa {
        fn drop(&mut self) {
            self.transcript.fill(0);
        }
    }

    impl fmt::Debug for CeremonyCa {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CeremonyCa")
                .field("fingerprint", &self.fingerprint.as_str())
                .field("status", &self.status)
                .field("transcript_bytes", &self.transcript.len())
                .finish_non_exhaustive()
        }
    }

    /// Why a ceremony run produced no CA.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CeremonyError {
        /// No `script` program, or the run could not start.
        Unavailable(String),
        /// The run did not finish within the bound (killed by its exact handle).
        TimedOut,
        /// The run ended without showing a passphrase (for example, a build without
        /// U12's handler).
        NoPassphrase {
            /// The exit status.
            status: Option<i32>,
        },
        /// The run showed no CA fingerprint.
        NoFingerprint {
            /// The exit status.
            status: Option<i32>,
        },
    }

    impl fmt::Display for CeremonyError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                CeremonyError::Unavailable(why) => write!(f, "ceremony unavailable: {why}"),
                CeremonyError::TimedOut => f.write_str("the ceremony did not finish in time"),
                CeremonyError::NoPassphrase { status } => {
                    write!(f, "the ceremony showed no passphrase (exit {status:?})")
                }
                CeremonyError::NoFingerprint { status } => {
                    write!(f, "the ceremony showed no CA fingerprint (exit {status:?})")
                }
            }
        }
    }

    impl std::error::Error for CeremonyError {}

    /// One ceremony run.
    #[derive(Debug, Clone)]
    pub struct CeremonyRun<'a> {
        /// The `heimdall` binary under test.
        pub binary: &'a Path,
        /// Exactly the environment (`HEIMDALL_HOME`, the test configuration, …); `PATH`
        /// and `TERM=dumb` are added.
        pub env: &'a [(OsString, OsString)],
        /// The working directory.
        pub cwd: &'a Path,
        /// `--backup-out` (a scratch path that does not exist yet).
        pub backup_out: &'a Path,
        /// The bound.
        pub timeout: Duration,
    }

    /// `true` for an RFC 4648 base32 symbol.
    fn is_b32(b: u8) -> bool {
        b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)
    }

    /// The first passphrase shown in `transcript`: 26 base32 symbols in groups of five
    /// (the last group shorter), separated by spaces or `-`.
    #[must_use]
    pub fn find_passphrase(transcript: &[u8]) -> Option<Vec<u8>> {
        let text = String::from_utf8_lossy(transcript);
        for line in text.lines() {
            let tokens: Vec<&str> = line
                .split([' ', '-', '\t'])
                .filter(|t| !t.is_empty())
                .collect();
            for start in 0..tokens.len() {
                let mut got = Vec::new();
                for (i, t) in tokens[start..].iter().enumerate() {
                    if !t.bytes().all(is_b32)
                        || t.len() > 5
                        || (t.len() < 5 && got.len() + t.len() != 26)
                    {
                        break;
                    }
                    got.extend_from_slice(t.as_bytes());
                    if got.len() == 26 && i >= 5 {
                        return Some(got);
                    }
                    if got.len() >= 26 {
                        break;
                    }
                }
            }
        }
        None
    }

    /// The first `SHA256:<43 base64>` in `transcript` that is a valid CA fingerprint.
    #[must_use]
    pub fn find_fingerprint(transcript: &[u8]) -> Option<CaFingerprint> {
        let text = String::from_utf8_lossy(transcript);
        let mut rest = text.as_ref();
        while let Some(i) = rest.find(CaFingerprint::PREFIX) {
            let cand: String = rest[i..]
                .chars()
                .take(CaFingerprint::PREFIX.len() + CaFingerprint::DIGEST_CHARS)
                .collect();
            if let Ok(fp) = CaFingerprint::parse(&cand) {
                return Some(fp);
            }
            rest = &rest[i + CaFingerprint::PREFIX.len()..];
        }
        None
    }

    /// Run the ceremony (see the module documentation).
    ///
    /// # Errors
    /// [`CeremonyError`].
    pub fn run(r: &CeremonyRun<'_>) -> Result<CeremonyCa, CeremonyError> {
        let script = find_program("script")
            .ok_or_else(|| CeremonyError::Unavailable("no script program".to_owned()))?;
        let args: Vec<OsString> = vec![
            r.binary.as_os_str().to_owned(),
            "issuer".into(),
            "init".into(),
            "--backup-out".into(),
            r.backup_out.as_os_str().to_owned(),
        ];
        let mut cmd = Command::new(script);
        if cfg!(target_os = "linux") {
            cmd.args(["-q", "-e", "-c"])
                .arg(sh_join(&args))
                .arg("/dev/null");
        } else {
            cmd.args(["-q", "/dev/null"]).args(&args);
        }
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TERM", "dumb")
            .current_dir(r.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in r.env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| CeremonyError::Unavailable(format!("{:?}", e.kind())))?;
        let mut stdin = child.stdin.take();
        let out = Arc::new(Mutex::new(Vec::new()));
        let reader = {
            let out = Arc::clone(&out);
            let mut pipe = child.stdout.take();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Some(p) = pipe.as_mut() {
                    match p.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => out
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extend_from_slice(&buf[..n]),
                    }
                }
            })
        };
        let end = Instant::now() + r.timeout;
        let (mut said_yes, mut said_written) = (false, false);
        let status = loop {
            if let Ok(Some(s)) = child.try_wait() {
                break s.code();
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                out.lock().unwrap_or_else(|e| e.into_inner()).fill(0);
                return Err(CeremonyError::TimedOut);
            }
            let seen = out.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let lower = String::from_utf8_lossy(&seen).to_ascii_lowercase();
            let mut answer = |word: &[u8]| {
                if let Some(pipe) = stdin.as_mut() {
                    let _ = pipe.write_all(word);
                    let _ = pipe.flush();
                }
            };
            if !said_yes && lower.contains("yes") {
                answer(b"yes\n");
                said_yes = true;
            } else if said_yes
                && !said_written
                && find_passphrase(&seen).is_some()
                && lower.contains("written")
            {
                answer(b"written\n");
                said_written = true;
            }
            let mut seen = seen;
            seen.fill(0);
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(stdin.take());
        let _ = reader.join();
        let transcript = std::mem::take(&mut *out.lock().unwrap_or_else(|e| e.into_inner()));
        let Some(passphrase) = find_passphrase(&transcript) else {
            let mut t = transcript;
            t.fill(0);
            return Err(CeremonyError::NoPassphrase { status });
        };
        let Some(fingerprint) = find_fingerprint(&transcript) else {
            let mut t = transcript;
            t.fill(0);
            return Err(CeremonyError::NoFingerprint { status });
        };
        Ok(CeremonyCa {
            fingerprint,
            passphrase: Passphrase(passphrase),
            backup: r.backup_out.to_path_buf(),
            status,
            transcript,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn passphrase_and_fingerprint_are_found_in_a_transcript() {
            let t = b"Backup passphrase (shown once):\r\n  ABCDE FGH23 KLMNO PQRS7 UVWXY Z\r\nType written: ";
            assert_eq!(
                find_passphrase(t).unwrap(),
                b"ABCDEFGH23KLMNOPQRS7UVWXYZ".to_vec()
            );
            assert!(find_passphrase(b"ABCDE FGHIJ").is_none());
            assert!(find_passphrase(b"abcde fghij klmno pqrst uvwxy z").is_none());
            let fp = format!("CA SHA256:{} registered", "A".repeat(43));
            assert_eq!(
                find_fingerprint(fp.as_bytes()).unwrap().as_str(),
                format!("SHA256:{}", "A".repeat(43))
            );
            assert!(find_fingerprint(b"SHA256:short").is_none());
            let p = Passphrase(b"ABC".to_vec());
            assert_eq!(format!("{p:?}"), "Passphrase(3 symbols)");
        }
    }
}
