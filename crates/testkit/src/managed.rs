//! Managed-credential fixtures (m03-plan U11 `managed`; ADR-0008 D13 item 5, D5 §6.3).
//! Features `fixtures` and `managed`.
//!
//! * [`seeded_k_env`]: the exact K_env private seed a test-configuration run with
//!   `HEIMDALL_TEST_KEY_SEED=<hex seed>` generates first, so A33 can scan every output
//!   for it ([`scan_forms`]: raw, hex and base64). **The derivation is shared with U1's
//!   `KeyVault::with_test_seed`** ([`seeded_k_env_nth`]; U1's
//!   `heimdall_credential::vault::seeded_private_key` computes the same bytes, which a
//!   unit test checks).
//! * [`ManagedRunContext`]: a child environment as a managed `run` produces it
//!   (`SSH_AUTH_SOCK` at the binding endpoint, the managed files inherited), for
//!   `maintenance_inside_managed_run_context_zero_managed_signatures`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use heimdall_sshconf::render::ManagedIdentityForm;
use ssh_key::{HashAlg, PublicKey};

use crate::agent::Endpoint;
use crate::home::ScratchHome;

/// The domain-separation label of the seeded K_env derivation (version 1).
pub const K_ENV_SEED_LABEL: &[u8] = b"heimdall-test-key-seed/k_env/v1\0";

/// The Ed25519 private seed of the **first** K_env generated under the test key seed
/// `seed` (the bytes `HEIMDALL_TEST_KEY_SEED` decodes to): [`seeded_k_env_nth`] with
/// `n = 0`.
#[must_use]
pub fn seeded_k_env(seed: &[u8]) -> [u8; 32] {
    seeded_k_env_nth(seed, 0)
}

/// The Ed25519 private seed of the `n`-th (0-based) K_env generated under `seed`:
/// `SHA-256(K_ENV_SEED_LABEL || u64_be(n) || seed)`.
#[must_use]
pub fn seeded_k_env_nth(seed: &[u8], n: u64) -> [u8; 32] {
    let mut msg = Vec::with_capacity(K_ENV_SEED_LABEL.len() + 8 + seed.len());
    msg.extend_from_slice(K_ENV_SEED_LABEL);
    msg.extend_from_slice(&n.to_be_bytes());
    msg.extend_from_slice(seed);
    let digest = HashAlg::Sha256.digest(&msg);
    msg.fill(0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// The forms of secret bytes a canary scan looks for: the raw bytes, lowercase and
/// uppercase hex, and standard base64 with and without padding.
#[must_use]
pub fn scan_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let lower: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_ascii_uppercase();
    let padded = base64(secret);
    let unpadded = padded.trim_end_matches('=').to_owned();
    vec![
        secret.to_vec(),
        lower.into_bytes(),
        upper.into_bytes(),
        padded.into_bytes(),
        unpadded.into_bytes(),
    ]
}

/// Whether `haystack` contains any [`scan_forms`] of `secret`.
#[must_use]
pub fn contains_secret(haystack: &[u8], secret: &[u8]) -> bool {
    scan_forms(secret)
        .iter()
        .any(|needle| !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle))
}

/// Standard base64 with padding (RFC 4648 §4).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The identity form of [`ManagedRunContext`]'s block (a named switch): the
/// certificate as both `IdentityFile` and `CertificateFile`, which INT-Q10 observed to
/// authenticate through an agent that lists only the certificate on macOS 10.5p1 and
/// 9.6p1, like P's default form (`ManagedIdentityForm::select`, the certificate as
/// `IdentityFile` alone). Naming it in both directives keeps the block's
/// `CertificateFile` line, which the context's own test reads from `ssh -G`.
pub const CONTEXT_IDENTITY_FORM: ManagedIdentityForm =
    ManagedIdentityForm::CertificateAsIdentityFileAndCertificateFile;

/// A child environment as a managed `run` produces it (m03-plan U11; ADR-0008 D5 §6.3
/// "Why it holds"; M17): `SSH_AUTH_SOCK` is the **binding** endpoint, `HOME` the scratch
/// home, and the scratch user configuration starts with the managed block for the
/// alias. ⟨M03 wave 2, U8⟩ The block is **the projection renderer's own output**
/// (`heimdall_sshconf::render::render_sections`, one `Section::ManagedCertificate`:
/// `IdentityAgent` = the **environment** endpoint, `IdentitiesOnly yes`, the slot's
/// files in [`CONTEXT_IDENTITY_FORM`], `ControlMaster no`, `ControlPath none`), with its
/// route lines (`HostName`, `User`) left out: the context has no route, and the
/// caller's own section for the alias supplies it, as before. The slot files are real
/// scratch files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRunContext {
    alias: String,
    binding_endpoint: OsString,
    environment_endpoint: OsString,
    slot_public: PathBuf,
    slot_certificate: PathBuf,
    env: Vec<(OsString, OsString)>,
    block: String,
}

impl ManagedRunContext {
    /// Build the context for `alias` in `home`: write the slot's public key (and, when
    /// given, its certificate line) under `<scratch>/slots<n>/`, and compose the
    /// environment and the managed block. Nothing is written to the user configuration
    /// until [`Self::write_user_config`].
    ///
    /// # Errors
    /// A write failed, or the alias is not a plain host token.
    pub fn new(
        home: &ScratchHome,
        alias: &str,
        binding: &Endpoint,
        environment: &Endpoint,
        slot_public_key: &PublicKey,
        slot_certificate_line: Option<&str>,
    ) -> io::Result<ManagedRunContext> {
        if alias.is_empty()
            || alias.starts_with('-')
            || alias.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(io::Error::other("the alias is not a host token"));
        }
        let dir = home.scratch().subdir("slots")?;
        let slot_public = dir.join("slot.pub");
        let mut public = slot_public_key.clone();
        public.set_comment("");
        let line = public
            .to_openssh()
            .map_err(|_| io::Error::other("slot key encoding"))?;
        fs::write(&slot_public, format!("{}\n", line.trim_end()))?;
        let slot_certificate = dir.join("slot-cert.pub");
        fs::write(
            &slot_certificate,
            slot_certificate_line.map_or(String::new(), |l| format!("{}\n", l.trim_end())),
        )?;
        let binding_endpoint = binding.locator();
        let environment_endpoint = environment.locator();
        let block = managed_block(alias, environment, &slot_public, &slot_certificate)?;
        let env = vec![
            (OsString::from("SSH_AUTH_SOCK"), binding_endpoint.clone()),
            (
                OsString::from("HOME"),
                home.git_home.clone().into_os_string(),
            ),
        ];
        Ok(ManagedRunContext {
            alias: alias.to_owned(),
            binding_endpoint,
            environment_endpoint,
            slot_public,
            slot_certificate,
            env,
            block,
        })
    }

    /// The alias.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The binding endpoint's locator (the child's `SSH_AUTH_SOCK`).
    #[must_use]
    pub fn binding_endpoint(&self) -> &OsStr {
        &self.binding_endpoint
    }

    /// The environment endpoint's locator (the managed block's `IdentityAgent`).
    #[must_use]
    pub fn environment_endpoint(&self) -> &OsStr {
        &self.environment_endpoint
    }

    /// The slot's public key file.
    #[must_use]
    pub fn slot_public(&self) -> &Path {
        &self.slot_public
    }

    /// The slot's certificate file.
    #[must_use]
    pub fn slot_certificate(&self) -> &Path {
        &self.slot_certificate
    }

    /// The managed block's text.
    #[must_use]
    pub fn managed_block(&self) -> &str {
        &self.block
    }

    /// The variables a managed `run` child inherits (`SSH_AUTH_SOCK`, `HOME`).
    #[must_use]
    pub fn env(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    /// Write the scratch user configuration: the managed block first (as the
    /// projection places it), then `rest`.
    ///
    /// # Errors
    /// The write failed.
    pub fn write_user_config(&self, home: &ScratchHome, rest: &str) -> io::Result<()> {
        home.write_user_config(&format!("{}{rest}", self.block))
    }

    /// Apply the environment to `cmd` (after whatever the caller set).
    pub fn apply(&self, cmd: &mut Command) {
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
    }
}

/// The renderer's section for `alias` (module docs of [`ManagedRunContext`]), without
/// its route lines.
fn managed_block(
    alias: &str,
    environment: &Endpoint,
    slot_public: &Path,
    slot_certificate: &Path,
) -> io::Result<String> {
    use heimdall_sshconf::render::{
        AliasName, HostName, PathStyle, RenderPath, Section, render_sections,
    };
    let refused = |what: &str| io::Error::other(format!("the managed block cannot render {what}"));
    let (style, file): (PathStyle, fn(&Path) -> Result<RenderPath, _>) = if cfg!(windows) {
        (PathStyle::Windows, RenderPath::windows)
    } else {
        (PathStyle::Unix, RenderPath::unix)
    };
    let endpoint = match environment {
        Endpoint::UnixSocket(p) => file(p),
        Endpoint::NamedPipe(n) => RenderPath::pipe(n),
    }
    .map_err(|_| refused("the environment endpoint"))?;
    // A placeholder route, removed below: the caller's section supplies the real one.
    let section = Section::ManagedCertificate {
        alias: AliasName::parse(alias).map_err(|_| refused("the alias"))?,
        hostname: HostName::parse(ROUTE_PLACEHOLDER).map_err(|_| refused("the route"))?,
        port: None,
        user: ROUTE_PLACEHOLDER.to_owned(),
        endpoint,
        key_pub: file(slot_public).map_err(|_| refused("the slot key"))?,
        cert: file(slot_certificate).map_err(|_| refused("the slot certificate"))?,
        control_path: None,
    };
    let rendered = render_sections(&[section], style, CONTEXT_IDENTITY_FORM)
        .map_err(|_| refused("the section"))?;
    let text = String::from_utf8(rendered).map_err(|_| refused("UTF-8"))?;
    Ok(text
        .lines()
        .filter(|l| !l.ends_with(&format!(" {ROUTE_PLACEHOLDER}")))
        .map(|l| format!("{l}\n"))
        .collect())
}

/// The placeholder `HostName` and `User` of [`managed_block`]'s render (never kept).
const ROUTE_PLACEHOLDER: &str = "hm-route-placeholder";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_k_env_is_deterministic_and_separated() {
        let a = seeded_k_env(b"\x01\x02");
        assert_eq!(a, seeded_k_env(b"\x01\x02"));
        assert_ne!(a, seeded_k_env(b"\x01\x03"));
        assert_ne!(a, seeded_k_env_nth(b"\x01\x02", 1));
    }

    /// One rule on both sides (U11-Q1): U1's vault derives exactly these bytes.
    #[cfg(debug_assertions)]
    #[test]
    fn seeded_k_env_matches_the_vault() {
        for seed in [&b"\x01"[..], b"\x00\x11\x22", &[0xab; 64]] {
            for n in 0..3 {
                let vault = heimdall_credential::vault::seeded_private_key(seed, n).unwrap();
                assert_eq!(seeded_k_env_nth(seed, n), *vault);
            }
        }
        assert!(heimdall_credential::vault::seeded_private_key(&[], 0).is_none());
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input), want);
        }
        assert!(contains_secret(b"xx Zm9vYmFy yy", b"foobar"));
        assert!(contains_secret(b"666f6f", b"foo"));
        assert!(!contains_secret(b"nothing", b"foobar"));
    }
}
