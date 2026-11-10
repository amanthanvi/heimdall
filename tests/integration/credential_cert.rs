//! m03-plan U1 certificate, purpose and session-bind tests (hosted by
//! heimdall-credential; ADR-0008 D2 items 4–5, D6 item 2; ADR-0005 §3.4).
//!
//! Every key, CA and certificate here is generated per run in memory or in a scratch
//! directory (m03-plan §0.2; ADR-0008 D13). The real-client tests (Unix) run the host's
//! `ssh` with only the isolation arguments and the default-identity guard
//! (`ScratchHome::client_command`), against a non-root loopback sshd, with
//! `SSH_AUTH_SOCK` pointed at this file's **capture agent**: a scratch Unix socket that
//! records every signing request's data and every `session-bind@openssh.com` payload,
//! and signs with a `KeyVault` key. The M02 testkit's agents log message types only
//! (`FakeAgent`, `CountingProxy`), so the capture agent lives here (a request to U11 is
//! in `tests/evidence/artifacts/review-m03-code/wave1-notes/m03-wave1-api.md`). The ECDSA and RSA host keys come from this file's own
//! loopback sshd (`HostKeySshd`), because the testkit `LoopbackSshd` has an Ed25519 host
//! key only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId, EnvironmentId, GrantId};
use heimdall_credential::cert::{
    self, CertError, CertRefusal, CertificateProfile, SecretCaKey, build_and_sign,
    validate_installed,
};
use heimdall_credential::purpose::{
    self, GrantCertificates, PurposeRefusal, UserAuthRequest, check, check_bound, parse_userauth,
};
use heimdall_credential::session_bind::{self, SessionBindError};
use heimdall_credential::vault::{KeyVault, PublicKeyInfo, SystemRng, VaultSlot};
use heimdall_domain::issuance::{
    CertificateBounds, EXTENSION_AGENT_FORWARDING, EXTENSION_PTY, principal_for,
};
use heimdall_domain::scope::AccessPair;
use heimdall_ipc::signing::SessionBindRecord;
use ssh_key::certificate::{Builder, CertType, Certificate};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{HashAlg, PrivateKey, PublicKey};

// --- fixtures ---------------------------------------------------------------------------

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_second(secs).unwrap()
}

fn now() -> i64 {
    Timestamp::now().as_second()
}

fn pair(destination: &str, account: &str) -> AccessPair {
    AccessPair {
        destination: DestinationId::parse(destination).unwrap(),
        account: AccountName::parse(account).unwrap(),
    }
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    SystemRng::fill(&mut b).unwrap();
    u64::from_be_bytes(b)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    SystemRng::fill(&mut b).unwrap();
    b
}

/// A test CA: the `SecretCaKey` for `build_and_sign`, and the same key as a plain
/// `PrivateKey` for forging deviating certificates.
struct TestCa {
    secret: SecretCaKey,
    private: PrivateKey,
}

impl TestCa {
    fn new() -> TestCa {
        let pair = Ed25519Keypair::from_seed(&random_bytes::<32>());
        let private = PrivateKey::new(KeypairData::Ed25519(pair), "").unwrap();
        TestCa {
            secret: SecretCaKey::from_private_key(private.clone()),
            private,
        }
    }

    fn fingerprint(&self) -> CaFingerprint {
        self.secret.fingerprint().unwrap()
    }

    #[cfg(unix)]
    fn public_line(&self) -> String {
        self.secret.public_openssh().unwrap().trim_end().to_owned()
    }
}

/// K_env in a vault.
struct Kenv {
    vault: std::sync::Arc<KeyVault>,
    slot: VaultSlot,
    info: PublicKeyInfo,
}

impl Kenv {
    fn new() -> Kenv {
        let vault = std::sync::Arc::new(KeyVault::new());
        let (slot, info) = vault.generate_ed25519().unwrap();
        Kenv { vault, slot, info }
    }

    fn public(&self) -> PublicKey {
        self.info.public_key().unwrap()
    }
}

/// The bounds a reservation records (ADR-0005 §3.4, §3.5 step 1).
fn bounds(
    pair: &AccessPair,
    subject: &PublicKeyInfo,
    ca: &TestCa,
    issued_at: i64,
    valid_before: i64,
    extensions: &[&str],
) -> CertificateBounds {
    let env = EnvironmentId::from_random_bytes(random_bytes());
    let grant = GrantId::from_random_bytes(random_bytes());
    let serial = random_u64();
    CertificateBounds {
        serial,
        key_id: cert::key_id(&env, &grant, serial),
        principal: principal_for(pair),
        valid_after: cert::valid_after_for(ts(issued_at)).unwrap(),
        valid_before: ts(valid_before),
        extensions: extensions.iter().map(|e| (*e).to_owned()).collect(),
        subject_fingerprint: subject.fingerprint.clone(),
        ca_fingerprint: Some(ca.fingerprint()),
    }
}

fn issue(bounds: &CertificateBounds, subject: &PublicKey, ca: &TestCa) -> Certificate {
    build_and_sign(
        &CertificateProfile::from_bounds(bounds),
        subject,
        &ca.secret,
    )
    .unwrap()
}

/// SSH wire helper for synthetic requests.
fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

/// A userauth request (RFC 4252 §7) with every field chosen by the caller.
fn userauth(
    session_id: &[u8],
    user: &str,
    method: &str,
    algorithm: &str,
    key_blob: &[u8],
    host_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, session_id);
    out.push(50);
    put_string(&mut out, user.as_bytes());
    put_string(&mut out, b"ssh-connection");
    put_string(&mut out, method.as_bytes());
    out.push(1);
    put_string(&mut out, algorithm.as_bytes());
    put_string(&mut out, key_blob);
    if let Some(h) = host_key {
        put_string(&mut out, h);
    }
    out
}

const CERT_ALG: &str = "ssh-ed25519-cert-v01@openssh.com";
const HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

/// A grant with two pairs (A: `dest-a`/`alice`, B: `dest-b`/`bob`), each with its
/// certificate under one CA.
struct Grant {
    kenv: Kenv,
    pair_a: AccessPair,
    pair_b: AccessPair,
    cert_a: Certificate,
    cert_b: Certificate,
    certs: GrantCertificates,
}

impl Grant {
    fn new() -> Grant {
        let kenv = Kenv::new();
        let ca = TestCa::new();
        let t = now();
        let pair_a = pair("dest-a", "alice");
        let pair_b = pair("dest-b", "bob");
        let cert_a = issue(
            &bounds(&pair_a, &kenv.info, &ca, t, t + 3600, &[EXTENSION_PTY]),
            &kenv.public(),
            &ca,
        );
        let cert_b = issue(
            &bounds(&pair_b, &kenv.info, &ca, t, t + 3600, &[EXTENSION_PTY]),
            &kenv.public(),
            &ca,
        );
        let mut certs = GrantCertificates::new(&kenv.public()).unwrap();
        certs.add(pair_a.clone(), &cert_a).unwrap();
        certs.add(pair_b.clone(), &cert_b).unwrap();
        Grant {
            kenv,
            pair_a,
            pair_b,
            cert_a,
            cert_b,
            certs,
        }
    }

    fn request(&self, user: &str, cert: &Certificate) -> UserAuthRequest {
        let data = userauth(
            &random_bytes::<32>(),
            user,
            "publickey",
            CERT_ALG,
            &cert.to_bytes().unwrap(),
            None,
        );
        parse_userauth(&data).unwrap()
    }
}

// --- the certificate profile ----------------------------------------------------------

#[test]
fn certificate_profile_matches_adr_0005_3_4() {
    let kenv = Kenv::new();
    let ca = TestCa::new();
    let issued_at = now();
    let deadline = issued_at + 7200;
    let p = pair("dest-a", "alice");
    let env = EnvironmentId::from_random_bytes(random_bytes());
    let grant = GrantId::from_random_bytes(random_bytes());
    let serial = random_u64();
    let reserved = CertificateBounds {
        serial,
        key_id: cert::key_id(&env, &grant, serial),
        principal: principal_for(&p),
        valid_after: cert::valid_after_for(ts(issued_at)).unwrap(),
        valid_before: ts(deadline),
        extensions: [EXTENSION_PTY.to_owned()].into(),
        subject_fingerprint: kenv.info.fingerprint.clone(),
        ca_fingerprint: Some(ca.fingerprint()),
    };
    let profile = CertificateProfile::from_bounds(&reserved);
    let c = build_and_sign(&profile, &kenv.public(), &ca.secret).unwrap();

    // Type, subject and issuer.
    assert_eq!(c.cert_type(), CertType::User);
    assert_eq!(c.algorithm().to_certificate_type(), CERT_ALG);
    assert_eq!(c.public_key(), kenv.public().key_data());
    assert_eq!(
        c.signature_key().fingerprint(HashAlg::Sha256).to_string(),
        ca.fingerprint().as_str()
    );
    c.verify_signature().unwrap();
    // Exactly one principal: hm:<destination>:<account>.
    assert_eq!(c.valid_principals(), ["hm:dest-a:alice".to_owned()]);
    // Extensions start from `clear`: only permit-pty, a flag; no critical option.
    assert!(c.critical_options().is_empty());
    assert_eq!(
        c.extensions().keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([EXTENSION_PTY.to_owned()])
    );
    assert!(c.extensions().values().all(String::is_empty));
    // Key ID heimdall:<env>:<grant>:<serial>; the reserved random serial.
    assert_eq!(
        c.key_id(),
        format!("heimdall:{}:{}:{serial}", env.as_str(), grant.as_str())
    );
    assert!(c.key_id().starts_with("heimdall:env_"));
    assert_eq!(c.serial(), serial);
    // valid_after = issuance − 60 s; valid_before = the reserved bound.
    assert_eq!(c.valid_after(), u64::try_from(issued_at - 60).unwrap());
    assert_eq!(c.valid_before(), u64::try_from(deadline).unwrap());
    // The validator accepts it.
    validate_installed(&c, &reserved, &kenv.info.fingerprint, &ca.fingerprint()).unwrap();

    // Random per certificate: the nonce (and serials drawn from SystemRng).
    let again = build_and_sign(&profile, &kenv.public(), &ca.secret).unwrap();
    assert_ne!(c.nonce(), again.nonce());
    assert_eq!(c.nonce().len(), cert::NONCE_BYTES);
    assert_ne!(random_u64(), random_u64());

    // A sub-second deadline is rounded down to the second.
    let mut fractional = reserved.clone();
    fractional.valid_before = Timestamp::new(deadline, 900_000_000).unwrap();
    let rounded = issue(&fractional, &kenv.public(), &ca);
    assert_eq!(rounded.valid_before(), u64::try_from(deadline).unwrap());

    // Agent forwarding appears only when reserved.
    let mut fwd = reserved.clone();
    fwd.extensions.insert(EXTENSION_AGENT_FORWARDING.to_owned());
    let with_fwd = issue(&fwd, &kenv.public(), &ca);
    assert_eq!(
        with_fwd
            .extensions()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            EXTENSION_PTY.to_owned(),
            EXTENSION_AGENT_FORWARDING.to_owned()
        ])
    );

    // The issuer signs exactly the reservation: another subject or CA is refused.
    let other = Kenv::new();
    assert_eq!(
        build_and_sign(&profile, &other.public(), &ca.secret).err(),
        Some(CertError::SubjectMismatch)
    );
    assert_eq!(
        build_and_sign(&profile, &kenv.public(), &TestCa::new().secret).err(),
        Some(CertError::CaMismatch)
    );
    let mut no_ca = profile.clone();
    no_ca.ca_fingerprint = None;
    assert_eq!(
        build_and_sign(&no_ca, &kenv.public(), &ca.secret).err(),
        Some(CertError::CaMismatch)
    );
    let mut empty = profile.clone();
    empty.valid_before = empty.valid_after;
    assert!(matches!(
        build_and_sign(&empty, &kenv.public(), &ca.secret),
        Err(CertError::InvalidProfile(_))
    ));

    // OpenSSH's own reading of the certificate (ssh-keygen -L), where installed.
    #[cfg(unix)]
    if let Some(keygen) = heimdall_testkit::home::find_program("ssh-keygen") {
        let scratch = heimdall_testkit::home::Scratch::new().unwrap();
        let file = scratch.path().join("k-cert.pub");
        std::fs::write(&file, c.to_openssh().unwrap()).unwrap();
        let out = std::process::Command::new(keygen)
            .arg("-L")
            .arg("-f")
            .arg(&file)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "ssh-keygen -L exit {:?}", out.status);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(&format!("Type: {CERT_ALG} user certificate")));
        assert!(text.contains(&format!("Key ID: \"{}\"", c.key_id())));
        assert!(text.contains(&format!("Serial: {serial}")));
        let section = |start: &str| -> Vec<String> {
            text.lines()
                .skip_while(|l| !l.trim_start().starts_with(start))
                .skip(1)
                .take_while(|l| l.starts_with("                "))
                .map(|l| l.trim().to_owned())
                .collect()
        };
        assert_eq!(section("Principals:"), ["hm:dest-a:alice"]);
        assert!(text.contains("Critical Options: (none)"));
        assert_eq!(section("Extensions:"), [EXTENSION_PTY]);
    }
}

// --- the installed-certificate validator ------------------------------------------------

/// One deviation from the reserved certificate (ADR-0008 D6 item 2).
#[derive(Debug, Clone)]
enum Deviation {
    None,
    PrincipalsNone,
    PrincipalsTwo,
    ForeignPrincipal,
    CriticalOption(&'static str, &'static str),
    ExtraExtension(&'static str),
    MissingExtension,
    ExtensionData,
    ValidAfter(i64),
    ValidBefore(i64),
    Serial(u64),
    KeyId(&'static str),
    HostCertificate,
    WrongCa,
    WrongSubject,
    BadSignature,
}

/// The reserved certificate with exactly one deviation, built with `ssh-key`'s builder
/// directly (`build_and_sign` refuses to make any of them).
fn forge(
    d: &Deviation,
    reserved: &CertificateBounds,
    subject: &PublicKey,
    ca: &TestCa,
) -> Certificate {
    let other_ca = TestCa::new();
    let other_subject = Kenv::new().public();
    let subject = if matches!(d, Deviation::WrongSubject) {
        &other_subject
    } else {
        subject
    };
    let shift = |base: i64, by: i64| u64::try_from(base + by).unwrap();
    let (va, vb) = (
        reserved.valid_after.as_second(),
        reserved.valid_before.as_second(),
    );
    let (va, vb) = match d {
        Deviation::ValidAfter(by) => (shift(va, *by), shift(vb, 0)),
        Deviation::ValidBefore(by) => (shift(va, 0), shift(vb, *by)),
        _ => (shift(va, 0), shift(vb, 0)),
    };
    let mut b = Builder::new(
        random_bytes::<32>().to_vec(),
        subject.key_data().clone(),
        va,
        vb,
    )
    .unwrap();
    b.serial(match d {
        Deviation::Serial(s) => *s,
        _ => reserved.serial,
    })
    .unwrap();
    b.key_id(match d {
        Deviation::KeyId(k) => (*k).to_owned(),
        _ => reserved.key_id.clone(),
    })
    .unwrap();
    b.cert_type(if matches!(d, Deviation::HostCertificate) {
        CertType::Host
    } else {
        CertType::User
    })
    .unwrap();
    match d {
        Deviation::PrincipalsNone => {
            b.all_principals_valid().unwrap();
        }
        Deviation::PrincipalsTwo => {
            b.valid_principal(reserved.principal.clone()).unwrap();
            b.valid_principal("hm:dest-b:alice").unwrap();
        }
        Deviation::ForeignPrincipal => {
            b.valid_principal("hm:dest-z:alice").unwrap();
        }
        _ => {
            b.valid_principal(reserved.principal.clone()).unwrap();
        }
    }
    if let Deviation::CriticalOption(name, value) = d {
        b.critical_option(*name, *value).unwrap();
    }
    for e in &reserved.extensions {
        match d {
            Deviation::MissingExtension => {}
            Deviation::ExtensionData => {
                b.extension(e.clone(), "data").unwrap();
            }
            _ => {
                b.extension(e.clone(), "").unwrap();
            }
        }
    }
    if let Deviation::ExtraExtension(name) = d {
        b.extension(*name, "").unwrap();
    }
    let signer = if matches!(d, Deviation::WrongCa) {
        &other_ca.private
    } else {
        &ca.private
    };
    let c = b.sign(signer).unwrap();
    if matches!(d, Deviation::BadSignature) {
        let mut bytes = c.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        return Certificate::from_bytes(&bytes).unwrap();
    }
    c
}

#[test]
fn cert_validator_refuses_each_deviation() {
    let kenv = Kenv::new();
    let ca = TestCa::new();
    let t = now();
    let p = pair("dest-a", "alice");
    let reserved = bounds(&p, &kenv.info, &ca, t, t + 3600, &[EXTENSION_PTY]);
    let fp = kenv.info.fingerprint.clone();
    let ca_fp = ca.fingerprint();

    // The control: the reserved certificate itself, built the forging way, passes.
    let base = forge(&Deviation::None, &reserved, &kenv.public(), &ca);
    validate_installed(&base, &reserved, &fp, &ca_fp).unwrap();

    // Every field of ADR-0008 D6 item 2, generated: each deviation alone.
    let mut cases: Vec<(Deviation, CertRefusal)> = vec![
        (
            Deviation::PrincipalsNone,
            CertRefusal::PrincipalCount { count: 0 },
        ),
        (
            Deviation::PrincipalsTwo,
            CertRefusal::PrincipalCount { count: 2 },
        ),
        (Deviation::ForeignPrincipal, CertRefusal::WrongPrincipal),
        (Deviation::HostCertificate, CertRefusal::NotUserCertificate),
        (Deviation::MissingExtension, CertRefusal::ExtensionMissing),
        (Deviation::ExtensionData, CertRefusal::ExtensionData),
        (
            Deviation::KeyId("heimdall:env_x:grant_y:1"),
            CertRefusal::KeyIdMismatch,
        ),
        (Deviation::KeyId(""), CertRefusal::KeyIdMismatch),
        (Deviation::WrongCa, CertRefusal::WrongCa),
        (Deviation::WrongSubject, CertRefusal::WrongSubject),
        (Deviation::BadSignature, CertRefusal::BadSignature),
    ];
    for (name, value) in [
        ("force-command", "/bin/true"),
        ("source-address", "127.0.0.1/32"),
        ("verify-required", ""),
        ("hm-unknown@example.org", ""),
    ] {
        cases.push((
            Deviation::CriticalOption(name, value),
            CertRefusal::CriticalOption,
        ));
    }
    for name in [
        "permit-port-forwarding",
        "permit-agent-forwarding",
        "permit-user-rc",
        "permit-X11-forwarding",
        "no-touch-required",
        "hm-unknown@example.org",
    ] {
        cases.push((
            Deviation::ExtraExtension(name),
            CertRefusal::ExtensionOutsideReserved,
        ));
    }
    for by in [-3600, -61, -60, -1, 1, 59, 60] {
        cases.push((Deviation::ValidAfter(by), CertRefusal::ValidAfterMismatch));
        cases.push((Deviation::ValidBefore(by), CertRefusal::ValidBeforeMismatch));
    }
    for delta in [1u64, 2, 1 << 32, u64::MAX] {
        cases.push((
            Deviation::Serial(reserved.serial.wrapping_add(delta)),
            CertRefusal::SerialMismatch,
        ));
    }
    let mut seen = BTreeSet::new();
    for (deviation, want) in &cases {
        let c = forge(deviation, &reserved, &kenv.public(), &ca);
        assert_eq!(
            validate_installed(&c, &reserved, &fp, &ca_fp),
            Err(*want),
            "{deviation:?}"
        );
        seen.insert(want.code());
    }

    // The validator's own inputs: the expected CA and subject, and the reserved CA.
    assert_eq!(
        validate_installed(&base, &reserved, &fp, &TestCa::new().fingerprint()),
        Err(CertRefusal::WrongCa)
    );
    assert_eq!(
        validate_installed(&base, &reserved, &Kenv::new().info.fingerprint, &ca_fp),
        Err(CertRefusal::WrongSubject)
    );
    let mut no_ca = reserved.clone();
    no_ca.ca_fingerprint = None;
    assert_eq!(
        validate_installed(&base, &no_ca, &fp, &ca_fp),
        Err(CertRefusal::NoReservedCa)
    );
    seen.insert(CertRefusal::NoReservedCa.code());
    // A reservation recorded for another subject, or with a wider extension set.
    let mut other_subject = reserved.clone();
    other_subject.subject_fingerprint = Kenv::new().info.fingerprint;
    assert_eq!(
        validate_installed(&base, &other_subject, &fp, &ca_fp),
        Err(CertRefusal::WrongSubject)
    );
    let mut wider = reserved.clone();
    wider
        .extensions
        .insert(EXTENSION_AGENT_FORWARDING.to_owned());
    assert_eq!(
        validate_installed(&base, &wider, &fp, &ca_fp),
        Err(CertRefusal::ExtensionMissing)
    );
    // Every refusal kind was produced.
    assert_eq!(seen.len(), 15, "{seen:?}");
}

// --- purpose -------------------------------------------------------------------------------

#[test]
fn trailing_bytes_refused() {
    let g = Grant::new();
    let blob = g.cert_a.to_bytes().unwrap();
    let sid = random_bytes::<32>();
    let host = Kenv::new().info.blob;
    for (method, host_key) in [("publickey", None), (HOSTBOUND, Some(host.as_slice()))] {
        let good = userauth(&sid, "alice", method, CERT_ALG, &blob, host_key);
        let req = parse_userauth(&good).unwrap();
        assert_eq!(check(&req, &g.certs, 0).unwrap().pair, g.pair_a);
        for extra in [&[0u8][..], &[0, 0, 0, 0], b"x", &[0, 0, 0, 1, 7]] {
            let mut bad = good.clone();
            bad.extend_from_slice(extra);
            assert_eq!(
                parse_userauth(&bad),
                Err(PurposeRefusal::TrailingBytes),
                "{method} + {extra:?}"
            );
        }
    }
    // A publickey request carrying a host key, as if host-bound.
    let bad = userauth(&sid, "alice", "publickey", CERT_ALG, &blob, Some(&host));
    assert_eq!(parse_userauth(&bad), Err(PurposeRefusal::TrailingBytes));
}

#[test]
fn wrong_user_refused() {
    let g = Grant::new();
    for user in ["mallory", "root", "Alice", "alice ", "", "bob"] {
        let req = g.request(user, &g.cert_a);
        assert_eq!(
            check(&req, &g.certs, 0),
            Err(PurposeRefusal::WrongUser),
            "{user:?}"
        );
    }
    assert_eq!(
        check(&g.request("alice", &g.cert_a), &g.certs, 0)
            .unwrap()
            .pair,
        g.pair_a
    );
}

#[test]
fn key_blob_not_grant_key_refused() {
    let g = Grant::new();
    // Another key entirely.
    let stranger = Kenv::new();
    // Another grant's certificate for the same pair (its own K_env).
    let other = Grant::new();
    // This grant's key, certified by another CA (not installed here).
    let ca = TestCa::new();
    let t = now();
    let foreign_ca_cert = issue(
        &bounds(&g.pair_a, &g.kenv.info, &ca, t, t + 3600, &[EXTENSION_PTY]),
        &g.kenv.public(),
        &ca,
    );
    for blob in [
        stranger.info.blob.clone(),
        other.cert_a.to_bytes().unwrap(),
        foreign_ca_cert.to_bytes().unwrap(),
    ] {
        let data = userauth(
            &random_bytes::<32>(),
            "alice",
            "publickey",
            CERT_ALG,
            &blob,
            None,
        );
        let req = parse_userauth(&data).unwrap();
        assert_eq!(check(&req, &g.certs, 0), Err(PurposeRefusal::KeyNotInGrant));
    }
    // A certificate that is not the grant key's, or not the pair's, is never installed.
    let mut certs = GrantCertificates::new(&g.kenv.public()).unwrap();
    assert_eq!(
        certs.add(g.pair_a.clone(), &other.cert_a),
        Err(purpose::GrantCertificateError::SubjectNotGrantKey)
    );
    assert_eq!(
        certs.add(g.pair_b.clone(), &g.cert_a),
        Err(purpose::GrantCertificateError::PrincipalNotPair)
    );
    certs.add(g.pair_a.clone(), &g.cert_a).unwrap();
    assert_eq!(
        certs.add(g.pair_a.clone(), &g.cert_a),
        Err(purpose::GrantCertificateError::DuplicatePair)
    );
}

#[test]
fn plain_k_env_key_refused_certificate_required() {
    let g = Grant::new();
    let plain = g.kenv.info.blob.clone();
    assert_eq!(g.certs.plain_key(), plain.as_slice());
    for (method, alg, host) in [
        ("publickey", "ssh-ed25519", None),
        ("publickey", CERT_ALG, None),
        (HOSTBOUND, "ssh-ed25519", Some(Kenv::new().info.blob)),
    ] {
        let data = userauth(
            &random_bytes::<32>(),
            "alice",
            method,
            alg,
            &plain,
            host.as_deref(),
        );
        let req = parse_userauth(&data).unwrap();
        assert_eq!(
            check(&req, &g.certs, 0),
            Err(PurposeRefusal::PlainKeyRefused),
            "{method} {alg}"
        );
    }
    // Even a grant with no certificate installed refuses its plain key.
    let empty = GrantCertificates::new(&g.kenv.public()).unwrap();
    let data = userauth(
        &random_bytes::<32>(),
        "alice",
        "publickey",
        "ssh-ed25519",
        &plain,
        None,
    );
    assert_eq!(
        check(&parse_userauth(&data).unwrap(), &empty, 0),
        Err(PurposeRefusal::PlainKeyRefused)
    );
}

#[test]
fn user_must_match_presented_certificates_pair() {
    let g = Grant::new();
    // Pair A's account presenting pair B's certificate, and the reverse (F17).
    assert_eq!(
        check(&g.request("alice", &g.cert_b), &g.certs, 0),
        Err(PurposeRefusal::WrongUser)
    );
    assert_eq!(
        check(&g.request("bob", &g.cert_a), &g.certs, 0),
        Err(PurposeRefusal::WrongUser)
    );
    // Each certificate with its own pair's account.
    let a = check(&g.request("alice", &g.cert_a), &g.certs, 0).unwrap();
    assert_eq!((a.pair, a.serial), (g.pair_a.clone(), g.cert_a.serial()));
    let b = check(&g.request("bob", &g.cert_b), &g.certs, 0).unwrap();
    assert_eq!((b.pair, b.serial), (g.pair_b.clone(), g.cert_b.serial()));
    // Once a pair's certificate is removed, its requests are refused.
    let mut certs = g.certs.clone();
    assert!(certs.remove(&g.pair_b));
    assert_eq!(
        check(&g.request("bob", &g.cert_b), &certs, 0),
        Err(PurposeRefusal::KeyNotInGrant)
    );
}

#[test]
fn rsa_sha1_flag_on_ed25519_refused() {
    let g = Grant::new();
    let req = g.request("alice", &g.cert_a);
    // SSH_AGENT_RSA_SHA2_256 (2), SSH_AGENT_RSA_SHA2_512 (4), both, and any other bit.
    for flags in [1u32, 2, 4, 6, 8, 0x8000_0000, u32::MAX] {
        assert_eq!(
            check(&req, &g.certs, flags),
            Err(PurposeRefusal::FlagsNotPermitted),
            "flags {flags:#x}"
        );
    }
    assert!(check(&req, &g.certs, 0).is_ok());
    // An RSA (or plain-key) algorithm name on the Ed25519 certificate.
    let blob = g.cert_a.to_bytes().unwrap();
    for alg in [
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ssh-rsa-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ] {
        let data = userauth(
            &random_bytes::<32>(),
            "alice",
            "publickey",
            alg,
            &blob,
            None,
        );
        let req = parse_userauth(&data).unwrap();
        assert_eq!(
            check(&req, &g.certs, 0),
            Err(PurposeRefusal::AlgorithmMismatch),
            "{alg}"
        );
    }
}

#[test]
fn non_userauth_message_refused() {
    let g = Grant::new();
    let blob = g.cert_a.to_bytes().unwrap();
    let sid = random_bytes::<32>();
    let good = userauth(&sid, "alice", "publickey", CERT_ALG, &blob, None);
    assert!(parse_userauth(&good).is_ok());
    // The message byte after the session identifier: anything but 50.
    let at = 4 + sid.len();
    for byte in [0u8, 1, 5, 20, 21, 30, 51, 52, 53, 60, 80, 90, 94, 255] {
        let mut bad = good.clone();
        bad[at] = byte;
        assert_eq!(
            parse_userauth(&bad),
            Err(PurposeRefusal::NotUserAuth),
            "message {byte}"
        );
    }
    // Another service.
    let mut other_service = Vec::new();
    put_string(&mut other_service, &sid);
    other_service.push(50);
    put_string(&mut other_service, b"alice");
    put_string(&mut other_service, b"ssh-userauth");
    put_string(&mut other_service, b"publickey");
    other_service.push(1);
    put_string(&mut other_service, CERT_ALG.as_bytes());
    put_string(&mut other_service, &blob);
    assert_eq!(
        parse_userauth(&other_service),
        Err(PurposeRefusal::WrongService)
    );
    // Other methods.
    for method in [
        "password",
        "none",
        "hostbased",
        "keyboard-interactive",
        "publickey-hostbound@openssh.com",
        "PUBLICKEY",
    ] {
        let data = userauth(&sid, "alice", method, CERT_ALG, &blob, None);
        assert_eq!(
            parse_userauth(&data),
            Err(PurposeRefusal::UnsupportedMethod),
            "{method}"
        );
    }
    // The query form (boolean FALSE) and any boolean but exactly 1.
    let flag_at = 4 + sid.len() + 1 + (4 + 5) + (4 + 14) + (4 + 9);
    for value in [0u8, 2, 255] {
        let mut bad = good.clone();
        bad[flag_at] = value;
        assert_eq!(parse_userauth(&bad), Err(PurposeRefusal::NotSigned));
    }
    // Session identifiers that no SSH key exchange produces.
    for len in [0usize, 129, 1024] {
        let data = userauth(&vec![7u8; len], "alice", "publickey", CERT_ALG, &blob, None);
        assert_eq!(
            parse_userauth(&data),
            Err(PurposeRefusal::SessionIdLength),
            "{len}"
        );
    }
    // Arbitrary data: an empty buffer, text, a bare agent frame, a run of 50s.
    for data in [&b""[..], b"hello, world", &[0, 0, 0, 1, 11], &[50u8; 64]] {
        assert!(parse_userauth(data).is_err(), "{data:?}");
    }
}

#[test]
fn sshsig_request_refused() {
    // Synthetic: PROTOCOL.sshsig's signed data for a Git commit.
    let mut sig = b"SSHSIG".to_vec();
    put_string(&mut sig, b"git");
    put_string(&mut sig, b"");
    put_string(&mut sig, b"sha512");
    put_string(&mut sig, &[0x5a; 64]);
    assert_eq!(parse_userauth(&sig), Err(PurposeRefusal::Sshsig));
    assert_eq!(parse_userauth(b"SSHSIG"), Err(PurposeRefusal::Sshsig));
    // Real: what ssh-keygen -Y sign sends an agent holding the K_env key.
    #[cfg(unix)]
    {
        let real = capture::sshsig_data();
        assert!(real.starts_with(b"SSHSIG"));
        assert_eq!(parse_userauth(&real), Err(PurposeRefusal::Sshsig));
    }
}

// --- session-bind ---------------------------------------------------------------------------

/// A `session-bind@openssh.com` payload (the contents after the extension name).
fn bind_payload(host_key: &[u8], sid: &[u8], signature: &[u8], forwarding: u8) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, host_key);
    put_string(&mut out, sid);
    put_string(&mut out, signature);
    out.push(forwarding);
    out
}

/// A host key in a vault, and a payload with its signature over `sid`.
fn signed_bind(sid: &[u8], forwarding: u8) -> (Kenv, Vec<u8>) {
    let host = Kenv::new();
    let signature = host.vault.sign(&host.slot, sid).unwrap();
    let payload = bind_payload(&host.info.blob, sid, &signature, forwarding);
    (host, payload)
}

#[test]
fn session_bind_bad_signature_refused() {
    let sid = random_bytes::<32>();
    let (host, good) = signed_bind(&sid, 0);
    let (bind, record) = session_bind::accept(&good).unwrap();
    assert!(session_bind::verify(&bind));
    assert_eq!(record.session_id, sid);
    assert_eq!(record.host_key, host.info.blob);

    // The signature over another session identifier.
    let over_other = host.vault.sign(&host.slot, &random_bytes::<32>()).unwrap();
    // A signature by another key.
    let stranger = Kenv::new();
    let by_other = stranger.vault.sign(&stranger.slot, &sid).unwrap();
    // A flipped bit in the signature bytes.
    let mut flipped = host.vault.sign(&host.slot, &sid).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x80;
    for (name, signature) in [
        ("other sid", over_other),
        ("other key", by_other),
        ("flipped", flipped),
    ] {
        let payload = bind_payload(&host.info.blob, &sid, &signature, 0);
        let bind = session_bind::parse(&payload).unwrap();
        assert!(!session_bind::verify(&bind), "{name}");
        assert_eq!(
            session_bind::accept(&payload).err(),
            Some(SessionBindError::BadSignature),
            "{name}"
        );
    }
    // A signature labelled with another algorithm.
    let mut mislabeled = Vec::new();
    put_string(&mut mislabeled, b"ecdsa-sha2-nistp256");
    put_string(&mut mislabeled, &[1u8; 72]);
    assert!(session_bind::accept(&bind_payload(&host.info.blob, &sid, &mislabeled, 0)).is_err());
    // Session identifiers outside 1..=128 bytes.
    for len in [0usize, 129] {
        let sid = vec![3u8; len];
        let signature = host.vault.sign(&host.slot, &sid).unwrap();
        let payload = bind_payload(&host.info.blob, &sid, &signature, 0);
        assert_eq!(
            session_bind::parse(&payload).err(),
            Some(SessionBindError::SessionIdLength)
        );
    }
    // A host key type outside Ed25519/ECDSA/RSA (a security-key Ed25519 blob).
    let mut sk = Vec::new();
    put_string(&mut sk, b"sk-ssh-ed25519@openssh.com");
    put_string(&mut sk, &[9u8; 32]);
    put_string(&mut sk, b"ssh:");
    let signature = host.vault.sign(&host.slot, &sid).unwrap();
    assert_eq!(
        session_bind::parse(&bind_payload(&sk, &sid, &signature, 0)).err(),
        Some(SessionBindError::UnsupportedHostKey)
    );
    // Structure: truncation, trailing bytes, a field that does not decode completely.
    for cut in 0..good.len() {
        assert!(session_bind::parse(&good[..cut]).is_err(), "cut {cut}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        session_bind::parse(&trailing).err(),
        Some(SessionBindError::Malformed)
    );
    let mut padded_key = host.info.blob.clone();
    padded_key.push(0);
    let payload = bind_payload(
        &padded_key,
        &sid,
        &host.vault.sign(&host.slot, &sid).unwrap(),
        0,
    );
    assert_eq!(
        session_bind::parse(&payload).err(),
        Some(SessionBindError::Malformed)
    );
}

#[test]
fn session_bind_forwarding_flag_reported() {
    let sid = random_bytes::<32>();
    for (flag, forwarding) in [(0u8, false), (1, true)] {
        let (_, payload) = signed_bind(&sid, flag);
        let (bind, record) = session_bind::accept(&payload).unwrap();
        assert_eq!(bind.is_forwarding, forwarding);
        assert_eq!(record.is_forwarding, forwarding);
        assert_eq!(
            session_bind::parse(&payload).unwrap().is_forwarding,
            forwarding
        );
    }
    for flag in [2u8, 0x80, 0xff] {
        let (_, payload) = signed_bind(&sid, flag);
        assert_eq!(
            session_bind::parse(&payload).err(),
            Some(SessionBindError::Malformed),
            "flag {flag}"
        );
    }
}

/// A bound connection's later requests must match the bound session (D2 item 5).
#[test]
fn bound_session_requires_matching_session_and_host_key() {
    let g = Grant::new();
    let sid = random_bytes::<32>();
    let (host, payload) = signed_bind(&sid, 0);
    let (_, record) = session_bind::accept(&payload).unwrap();
    let blob = g.cert_a.to_bytes().unwrap();
    let hostbound = |sid: &[u8], host_key: &[u8]| {
        parse_userauth(&userauth(
            sid,
            "alice",
            HOSTBOUND,
            CERT_ALG,
            &blob,
            Some(host_key),
        ))
        .unwrap()
    };
    assert_eq!(
        check_bound(&hostbound(&sid, &host.info.blob), &record),
        Ok(())
    );
    assert_eq!(
        check_bound(&hostbound(&random_bytes::<32>(), &host.info.blob), &record),
        Err(PurposeRefusal::SessionMismatch)
    );
    assert_eq!(
        check_bound(&hostbound(&sid, &Kenv::new().info.blob), &record),
        Err(PurposeRefusal::HostKeyMismatch)
    );
    let plain =
        parse_userauth(&userauth(&sid, "alice", "publickey", CERT_ALG, &blob, None)).unwrap();
    assert_eq!(check_bound(&plain, &record), Ok(()));
    let record_other = SessionBindRecord {
        session_id: random_bytes::<32>().to_vec(),
        ..record
    };
    assert_eq!(
        check_bound(&plain, &record_other),
        Err(PurposeRefusal::SessionMismatch)
    );
}

// --- real clients and servers (Unix) -------------------------------------------------------

#[cfg(unix)]
#[test]
fn userauth_parsed_for_publickey_and_hostbound() {
    capture::userauth_parsed_for_publickey_and_hostbound();
}

#[cfg(unix)]
#[test]
fn session_bind_verified_for_each_host_key_type() {
    capture::session_bind_verified_for_each_host_key_type();
}

#[cfg(unix)]
#[test]
fn certificate_accepted_by_fixture_sshd() {
    capture::certificate_accepted_by_fixture_sshd();
}

#[cfg(unix)]
#[test]
fn certificate_identity_file_selection_observed_per_client() {
    capture::certificate_identity_file_selection_observed_per_client();
}

#[cfg(unix)]
mod capture {
    //! The capture agent, the host-key sshd and the real-client test bodies.

    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use heimdall_credential::purpose::UserAuthMethod;
    use heimdall_testkit::agent::{FixtureKey, frame};
    use heimdall_testkit::assert_no_canary;
    use heimdall_testkit::home::{
        ClientKind, Scratch, ScratchHome, find_program, ssh_config_quote,
    };
    use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig, current_account, pick_loopback_port};

    use super::*;

    /// One message the capture agent received.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Captured {
        /// `SSH_AGENTC_SIGN_REQUEST`: key blob, data, flags.
        Sign(Vec<u8>, Vec<u8>, u32),
        /// `session-bind@openssh.com` contents.
        SessionBind(Vec<u8>),
        /// Anything else (its type byte).
        Other(u8),
    }

    struct Shared {
        log: Mutex<Vec<Captured>>,
        identities: Vec<Vec<u8>>,
        vault: Arc<KeyVault>,
        slot: VaultSlot,
    }

    /// An agent on a scratch Unix socket that lists `identities` (all of one vault
    /// key: its plain blob or its certificates), signs with that key, accepts every
    /// session-bind, and records each message. Stopped, and its socket removed, on drop.
    struct CaptureAgent {
        socket: PathBuf,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        accept: Option<JoinHandle<()>>,
    }

    fn take_string(c: &mut &[u8]) -> Option<Vec<u8>> {
        let (len, rest) = c.split_first_chunk::<4>()?;
        let n = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        let s = rest.get(..n)?.to_vec();
        *c = &rest[n..];
        Some(s)
    }

    fn handle(shared: &Shared, payload: &[u8]) -> Vec<u8> {
        let Some((&ty, mut rest)) = payload.split_first() else {
            return vec![5];
        };
        match ty {
            11 => {
                let mut out = vec![12];
                let n = u32::try_from(shared.identities.len()).unwrap();
                out.extend_from_slice(&n.to_be_bytes());
                for blob in &shared.identities {
                    put_string(&mut out, blob);
                    put_string(&mut out, b"u1-capture");
                }
                out
            }
            13 => {
                let (Some(key_blob), Some(data)) = (take_string(&mut rest), take_string(&mut rest))
                else {
                    return vec![5];
                };
                let flags = rest
                    .first_chunk::<4>()
                    .map_or(u32::MAX, |b| u32::from_be_bytes(*b));
                let known = shared.identities.contains(&key_blob);
                shared
                    .log
                    .lock()
                    .unwrap()
                    .push(Captured::Sign(key_blob, data.clone(), flags));
                if !known {
                    return vec![5];
                }
                match shared.vault.sign(&shared.slot, &data) {
                    Ok(signature) => {
                        let mut out = vec![14];
                        put_string(&mut out, &signature);
                        out
                    }
                    Err(_) => vec![5],
                }
            }
            27 => {
                let Some(name) = take_string(&mut rest) else {
                    return vec![5];
                };
                if name == b"session-bind@openssh.com" {
                    shared
                        .log
                        .lock()
                        .unwrap()
                        .push(Captured::SessionBind(rest.to_vec()));
                    vec![6]
                } else {
                    shared.log.lock().unwrap().push(Captured::Other(27));
                    vec![5]
                }
            }
            other => {
                shared.log.lock().unwrap().push(Captured::Other(other));
                vec![5]
            }
        }
    }

    fn serve(mut s: UnixStream, shared: Arc<Shared>) {
        let _ = s.set_nonblocking(false);
        let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
        loop {
            let mut len = [0u8; 4];
            if s.read_exact(&mut len).is_err() {
                return;
            }
            let n = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
            if n == 0 || n > 256 * 1024 {
                return;
            }
            let mut payload = vec![0u8; n];
            if s.read_exact(&mut payload).is_err() {
                return;
            }
            if s.write_all(&frame(&handle(&shared, &payload))).is_err() {
                return;
            }
        }
    }

    impl CaptureAgent {
        fn start(scratch: &Scratch, name: &str, kenv: &Kenv, identities: Vec<Vec<u8>>) -> Self {
            let socket = scratch.subdir("c").unwrap().join(format!("{name}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let shared = Arc::new(Shared {
                log: Mutex::new(Vec::new()),
                identities,
                vault: Arc::clone(&kenv.vault),
                slot: kenv.slot,
            });
            let stop = Arc::new(AtomicBool::new(false));
            let (s2, stop2) = (Arc::clone(&shared), Arc::clone(&stop));
            let accept = std::thread::spawn(move || {
                while !stop2.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((conn, _)) => {
                            let s3 = Arc::clone(&s2);
                            std::thread::spawn(move || serve(conn, s3));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            CaptureAgent {
                socket,
                shared,
                stop,
                accept: Some(accept),
            }
        }

        fn log(&self) -> Vec<Captured> {
            self.shared.log.lock().unwrap().clone()
        }

        /// The signing requests (key blob, data, flags), in order.
        fn signed(&self) -> Vec<(Vec<u8>, Vec<u8>, u32)> {
            self.log()
                .into_iter()
                .filter_map(|c| match c {
                    Captured::Sign(k, d, f) => Some((k, d, f)),
                    _ => None,
                })
                .collect()
        }

        /// The session-bind payloads, in order.
        fn binds(&self) -> Vec<Vec<u8>> {
            self.log()
                .into_iter()
                .filter_map(|c| match c {
                    Captured::SessionBind(p) => Some(p),
                    _ => None,
                })
                .collect()
        }
    }

    impl Drop for CaptureAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.accept.take() {
                let _ = t.join();
            }
            let _ = fs::remove_file(&self.socket);
        }
    }

    /// The scratch config block of one alias: the loopback server, a scratch
    /// `IdentityFile` (the K_env public key; the default-identity guard requires a
    /// scratch identity), and the alias's own lines.
    fn alias_block(name: &str, port: u16, identity: &Path, extra: &str) -> String {
        format!(
            "Host {name}\n  HostName 127.0.0.1\n  Port {port}\n  IdentityFile {}\n  LogLevel VERBOSE\n{extra}",
            ssh_config_quote(&identity.to_string_lossy())
        )
    }

    /// Why a login failed, for its assertion message (wave-1 native run, item B2): the
    /// last lines of ssh's stderr and the fixture sshd's refusal lines, with the scratch
    /// root and the account name redacted.
    fn failure_reason(home: &ScratchHome, out: &Output, sshd: Option<&LoopbackSshd>) -> String {
        let root = home.root.to_string_lossy().into_owned();
        let me = account();
        let redact = |text: &str| {
            let t = text.replace(&root, "<scratch>");
            if me.len() >= 2 {
                t.replace(&me, "<user>")
            } else {
                t
            }
        };
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
        let mut text = format!(
            "ssh stderr (last {} lines):\n{}",
            tail.len(),
            redact(&tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
        );
        if let Some(sshd) = sshd {
            let mut lines: Vec<String> = Vec::new();
            for needle in [
                "rror",
                "efus",
                "nvalid",
                "enied",
                "ertificate",
                "uthentication",
                "fatal",
                "Failed",
                "losed",
            ] {
                for l in sshd.log_lines_containing(needle) {
                    if !lines.contains(&l) {
                        lines.push(l);
                    }
                }
            }
            let lines: Vec<String> = lines.into_iter().rev().take(20).rev().collect();
            text.push_str(&format!(
                "\nsshd log (refusal lines):\n{}",
                redact(&lines.join("\n"))
            ));
        }
        text
    }

    /// `ssh <alias> true` with only the isolation arguments, its agent at `agent`.
    fn login(home: &ScratchHome, alias: &str, agent: &CaptureAgent) -> Output {
        let mut cmd = home.client_command(ClientKind::Ssh, alias).unwrap();
        cmd.arg("true")
            .env("SSH_AUTH_SOCK", &agent.socket)
            .stdin(Stdio::null());
        let out = cmd.output().unwrap();
        assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    }

    /// The server key blob of a testkit known-hosts line (`[host]:port type b64`).
    fn host_key_blob(known_hosts_line: &str) -> Vec<u8> {
        let mut f = known_hosts_line.split_whitespace().skip(1);
        let (kind, b64) = (f.next().unwrap(), f.next().unwrap());
        PublicKey::from_openssh(&format!("{kind} {b64}"))
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn account() -> String {
        current_account().expect("the current account name")
    }

    /// The alias's `IdentityFile` (the default-identity guard requires one): an
    /// unrelated decoy public key, never K_env's own. With K_env's `.pub` as the
    /// `IdentityFile` and only its certificate in the agent, OpenSSH 9.6p1 pairs the
    /// agent's certificate with that file identity and signs with the file's (absent)
    /// private key, so the certificate never authenticates (observed on 9.6p1, wave-1
    /// native run item B2; `certificate_identity_file_selection_observed_per_client`
    /// records each client's behaviour). 10.5p1 signs through the agent either way.
    fn write_identity(home: &ScratchHome, _kenv: &Kenv) -> PathBuf {
        let identity = home.root.join("decoy.pub");
        if !identity.exists() {
            let decoy = FixtureKey::generate();
            fs::write(
                &identity,
                format!("{}\n", decoy.public().to_openssh().unwrap().trim_end()),
            )
            .unwrap();
        }
        identity
    }

    /// K_env's own public key as the `IdentityFile` (the managed alias's shape), for the
    /// observation of each client's identity selection.
    fn write_kenv_identity(home: &ScratchHome, kenv: &Kenv) -> PathBuf {
        let identity = home.root.join("kenv.pub");
        fs::write(
            &identity,
            format!("{}\n", kenv.info.openssh_line.trim_end()),
        )
        .unwrap();
        identity
    }

    /// A reservation and its certificate for `p`, valid for an hour.
    fn issued(kenv: &Kenv, ca: &TestCa, p: &AccessPair) -> (CertificateBounds, Certificate) {
        let t = now();
        let b = bounds(p, &kenv.info, ca, t, t + 3600, &[EXTENSION_PTY]);
        let c = issue(&b, &kenv.public(), ca);
        (b, c)
    }

    fn cert_authority_line(p: &AccessPair, ca: &TestCa) -> Vec<u8> {
        format!(
            "cert-authority,principals=\"{}\" {}\n",
            principal_for(p),
            ca.public_line()
        )
        .into_bytes()
    }

    pub(super) fn userauth_parsed_for_publickey_and_hostbound() {
        let home = ScratchHome::new();
        let kenv = Kenv::new();
        let ca = TestCa::new();
        let me = account();
        let p = pair("u1-dest", &me);
        let (_, cert) = issued(&kenv, &ca, &p);
        let cert_blob = cert.to_bytes().unwrap();
        // Two servers: one trusting the CA for exactly this pair's principal (account
        // form), one authorizing the plain K_env key (for the plain-key capture).
        let cert_sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                registry_seed: Some(cert_authority_line(&p, &ca)),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let plain_sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                authorized: vec![kenv.public()],
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        home.trust_host_key(&cert_sshd.host_key_line).unwrap();
        home.trust_host_key(&plain_sshd.host_key_line).unwrap();
        let identity = write_identity(&home, &kenv);
        let unbound = "  PubkeyAuthentication unbound\n";
        home.write_user_config(
            &[
                alias_block("u1-hb", cert_sshd.port, &identity, ""),
                alias_block("u1-pk", cert_sshd.port, &identity, unbound),
                alias_block("u1-hb-plain", plain_sshd.port, &identity, ""),
                alias_block("u1-pk-plain", plain_sshd.port, &identity, unbound),
            ]
            .concat(),
        )
        .unwrap();
        let cert_host_key = host_key_blob(&cert_sshd.host_key_line);
        let plain_host_key = host_key_blob(&plain_sshd.host_key_line);
        let mut certs = GrantCertificates::new(&kenv.public()).unwrap();
        certs.add(p.clone(), &cert).unwrap();

        for (alias, hostbound) in [("u1-hb", true), ("u1-pk", false)] {
            // The certificate: parsed, and accepted by the purpose check.
            let agent = CaptureAgent::start(home.scratch(), alias, &kenv, vec![cert_blob.clone()]);
            let out = login(&home, alias, &agent);
            assert!(
                out.status.success(),
                "{alias}: ssh exit {:?}\n{}",
                out.status.code(),
                failure_reason(&home, &out, Some(&cert_sshd))
            );
            let signed = agent.signed();
            assert_eq!(signed.len(), 1, "{alias}: one signature");
            let (key_blob, data, flags) = &signed[0];
            assert_eq!(key_blob, &cert_blob);
            assert_eq!(*flags, 0, "Ed25519: no flags");
            let req = parse_userauth(data).unwrap();
            assert!(req.user == me, "{alias}: the login account");
            assert_eq!(req.algorithm, CERT_ALG);
            assert_eq!(&req.key_blob, &cert_blob);
            assert!(
                matches!(req.session_id.len(), 20 | 32 | 48 | 64),
                "a hash output"
            );
            match (&req.method, hostbound) {
                (UserAuthMethod::PublickeyHostbound { server_host_key }, true) => {
                    assert_eq!(server_host_key, &cert_host_key);
                }
                (UserAuthMethod::Publickey, false) => {}
                (m, _) => panic!("{alias}: method {m:?}"),
            }
            let got = check(&req, &certs, *flags).unwrap();
            assert_eq!(got.pair, p);
            assert_eq!(got.serial, cert.serial());
            // The same connection's session-bind: verified, and the request matches it.
            let binds = agent.binds();
            assert_eq!(binds.len(), 1, "{alias}: one session-bind");
            let (bind, record) = session_bind::accept(&binds[0]).unwrap();
            assert!(!bind.is_forwarding);
            assert_eq!(record.session_id, req.session_id);
            assert_eq!(record.host_key, cert_host_key);
            check_bound(&req, &record).unwrap();
            let mut trailing = data.clone();
            trailing.push(0);
            assert_eq!(
                parse_userauth(&trailing),
                Err(PurposeRefusal::TrailingBytes)
            );
        }
        for (alias, hostbound) in [("u1-hb-plain", true), ("u1-pk-plain", false)] {
            // The plain K_env key: parsed, and refused by the purpose check (F17).
            let agent =
                CaptureAgent::start(home.scratch(), alias, &kenv, vec![kenv.info.blob.clone()]);
            let out = login(&home, alias, &agent);
            assert!(
                out.status.success(),
                "{alias}: ssh exit {:?}\n{}",
                out.status.code(),
                failure_reason(&home, &out, Some(&plain_sshd))
            );
            let signed = agent.signed();
            assert_eq!(signed.len(), 1, "{alias}: one signature");
            let (key_blob, data, flags) = &signed[0];
            assert_eq!(key_blob, &kenv.info.blob);
            let req = parse_userauth(data).unwrap();
            assert_eq!(req.algorithm, "ssh-ed25519");
            match (&req.method, hostbound) {
                (UserAuthMethod::PublickeyHostbound { server_host_key }, true) => {
                    assert_eq!(server_host_key, &plain_host_key);
                }
                (UserAuthMethod::Publickey, false) => {}
                (m, _) => panic!("{alias}: method {m:?}"),
            }
            assert_eq!(
                check(&req, &certs, *flags),
                Err(PurposeRefusal::PlainKeyRefused)
            );
        }
        // The certificate server accepted exactly our certificate, once per method.
        let accepted = cert_sshd.accepted_certificates();
        assert_eq!(accepted.len(), 2);
        assert!(
            accepted
                .iter()
                .all(|a| a.key_id == cert.key_id() && a.serial == cert.serial())
        );
    }

    /// What `ssh-keygen -Y sign` sends an agent holding the K_env key.
    pub(super) fn sshsig_data() -> Vec<u8> {
        let scratch = Scratch::new().unwrap();
        let kenv = Kenv::new();
        let agent = CaptureAgent::start(&scratch, "sig", &kenv, vec![kenv.info.blob.clone()]);
        let dir = scratch.subdir("sig").unwrap();
        let public = dir.join("k.pub");
        fs::write(&public, format!("{}\n", kenv.info.openssh_line.trim_end())).unwrap();
        let message = dir.join("msg");
        fs::write(&message, b"u1 commit").unwrap();
        let status = Command::new(find_program("ssh-keygen").expect("ssh-keygen"))
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&public)
            .arg(&message)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", scratch.path())
            .env("SSH_AUTH_SOCK", &agent.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "ssh-keygen -Y sign through the capture agent"
        );
        let signed = agent.signed();
        assert_eq!(signed.len(), 1);
        signed[0].1.clone()
    }

    /// A non-root loopback sshd with an Ed25519, an ECDSA and an RSA host key
    /// (`ssh-keygen -A` under a scratch prefix, so no passphrase is involved), a scratch
    /// `AuthorizedKeysFile`, and the testkit fixture's hardening lines. Stopped by exact
    /// PID (its `Child` handle) on drop.
    struct HostKeySshd {
        port: u16,
        /// (`ssh-ed25519` | `ecdsa-sha2-nistp256` | `ssh-rsa`, public blob).
        host_keys: Vec<(String, Vec<u8>)>,
        child: Child,
    }

    impl HostKeySshd {
        fn start(scratch: &Scratch, authorized: &str) -> HostKeySshd {
            let sshd = find_program("sshd").expect("sshd");
            let keygen = find_program("ssh-keygen").expect("ssh-keygen");
            let dir = scratch.subdir("hk").unwrap();
            fs::create_dir_all(dir.join("etc/ssh")).unwrap();
            let status = Command::new(keygen)
                .arg("-A")
                .arg("-f")
                .arg(&dir)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "ssh-keygen -A");
            let mut host_keys = Vec::new();
            let mut lines = String::new();
            for kind in ["ed25519", "ecdsa", "rsa"] {
                let private = dir.join(format!("etc/ssh/ssh_host_{kind}_key"));
                lines.push_str(&format!(
                    "HostKey {}\n",
                    ssh_config_quote(&private.to_string_lossy())
                ));
                let text = fs::read_to_string(format!("{}.pub", private.display())).unwrap();
                let mut key = PublicKey::from_openssh(text.trim()).unwrap();
                key.set_comment("");
                host_keys.push((key.algorithm().as_str().to_owned(), key.to_bytes().unwrap()));
            }
            let auth = dir.join("authorized_keys");
            fs::write(&auth, authorized).unwrap();
            let log = dir.join("sshd.log");
            let config = dir.join("sshd_config");
            for _attempt in 0..5 {
                let port = pick_loopback_port().unwrap();
                let mut accepted = false;
                for penalties in [true, false] {
                    let mut text = format!(
                        "ListenAddress 127.0.0.1\nPort {port}\nAddressFamily inet\n{lines}\
                         AuthorizedKeysFile {}\nPidFile none\nStrictModes no\nUsePAM no\n\
                         PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
                         PubkeyAuthentication yes\nAuthenticationMethods publickey\n\
                         PermitRootLogin no\nPermitUserRC no\nPermitUserEnvironment no\n\
                         AllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\n\
                         UseDNS no\nMaxAuthTries 6\nLogLevel VERBOSE\n",
                        ssh_config_quote(&auth.to_string_lossy())
                    );
                    if penalties {
                        // Servers before OpenSSH 9.8 do not know it.
                        text.push_str("PerSourcePenalties no\n");
                    }
                    fs::write(&config, text).unwrap();
                    let ok = Command::new(&sshd)
                        .arg("-t")
                        .arg("-f")
                        .arg(&config)
                        .env_clear()
                        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success();
                    if ok {
                        accepted = true;
                        break;
                    }
                }
                assert!(accepted, "sshd -t accepted the host-key fixture config");
                let _ = fs::remove_file(&log);
                let mut child = Command::new(&sshd)
                    .arg("-D")
                    .arg("-f")
                    .arg(&config)
                    .arg("-E")
                    .arg(&log)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let ready = format!("Server listening on 127.0.0.1 port {port}.");
                let end = Instant::now() + Duration::from_secs(10);
                loop {
                    if fs::read_to_string(&log).is_ok_and(|t| t.contains(&ready)) {
                        return HostKeySshd {
                            port,
                            host_keys,
                            child,
                        };
                    }
                    if let Ok(Some(_)) = child.try_wait() {
                        break; // the port was taken meanwhile: another one
                    }
                    if Instant::now() >= end {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("the host-key sshd did not listen within 10 s");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            panic!("the host-key sshd could not bind a loopback port");
        }

        fn known_hosts(&self) -> String {
            self.host_keys
                .iter()
                .map(|(alg, blob)| {
                    let line = PublicKey::from_bytes(blob).unwrap().to_openssh().unwrap();
                    let b64 = line.split_whitespace().nth(1).unwrap().to_owned();
                    format!("[127.0.0.1]:{} {alg} {b64}\n", self.port)
                })
                .collect()
        }
    }

    impl Drop for HostKeySshd {
        fn drop(&mut self) {
            // The exact PID, through the handle: SIGKILL, then reap.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    pub(super) fn session_bind_verified_for_each_host_key_type() {
        let home = ScratchHome::new();
        let kenv = Kenv::new();
        let sshd = HostKeySshd::start(
            home.scratch(),
            &format!("restrict {}\n", kenv.info.openssh_line.trim_end()),
        );
        fs::write(&home.known_hosts, sshd.known_hosts()).unwrap();
        let identity = write_identity(&home, &kenv);
        // One alias per host key algorithm; the client negotiates only that one.
        let cases = [
            ("u1-ed25519", "ssh-ed25519", "ssh-ed25519"),
            ("u1-ecdsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
            ("u1-rsa512", "rsa-sha2-512", "ssh-rsa"),
            ("u1-rsa256", "rsa-sha2-256", "ssh-rsa"),
        ];
        let config: String = cases
            .iter()
            .map(|(alias, alg, _)| {
                alias_block(
                    alias,
                    sshd.port,
                    &identity,
                    &format!("  HostKeyAlgorithms {alg}\n"),
                )
            })
            .collect();
        home.write_user_config(&config).unwrap();
        for (alias, alg, key_type) in cases {
            let agent =
                CaptureAgent::start(home.scratch(), alias, &kenv, vec![kenv.info.blob.clone()]);
            let out = login(&home, alias, &agent);
            assert!(
                out.status.success(),
                "{alias}: ssh exit {:?}\n{}",
                out.status.code(),
                failure_reason(&home, &out, None)
            );
            let binds = agent.binds();
            assert_eq!(binds.len(), 1, "{alias}: the client sent one session-bind");
            let bind = session_bind::parse(&binds[0]).unwrap();
            assert!(
                session_bind::verify(&bind),
                "{alias}: the host signature verifies"
            );
            assert!(!bind.is_forwarding);
            assert_eq!(bind.host_key.algorithm().as_str(), key_type);
            assert_eq!(bind.signature.algorithm().as_str(), alg, "{alias}");
            let (_, record) = session_bind::accept(&binds[0]).unwrap();
            let expected = &sshd
                .host_keys
                .iter()
                .find(|(t, _)| t == key_type)
                .unwrap()
                .1;
            assert_eq!(&record.host_key, expected, "{alias}: the server's key");
            // The userauth request on the same connection names the same session.
            let signed = agent.signed();
            let req = parse_userauth(&signed.last().unwrap().1).unwrap();
            assert_eq!(req.session_id, record.session_id);
            check_bound(&req, &record).unwrap();
            // A changed bit in the captured signature breaks it.
            let mut bad = binds[0].clone();
            let at = bad.len() - 2;
            bad[at] ^= 0x01;
            assert!(session_bind::accept(&bad).is_err(), "{alias}: tampered");
        }
    }

    pub(super) fn certificate_accepted_by_fixture_sshd() {
        let me = account();
        let ca = TestCa::new();
        for form in ["account", "system"] {
            let home = ScratchHome::new();
            let kenv = Kenv::new();
            let p = pair("u1-dest", &me);
            let (reserved, cert) = issued(&kenv, &ca, &p);
            validate_installed(&cert, &reserved, &kenv.info.fingerprint, &ca.fingerprint())
                .unwrap();
            let config = if form == "account" {
                // A `cert-authority,principals=…` registry line.
                SshdConfig {
                    registry_seed: Some(cert_authority_line(&p, &ca)),
                    ..SshdConfig::default()
                }
            } else {
                // TrustedUserCAKeys and AuthorizedPrincipalsFile, as an administrator
                // would write them.
                SshdConfig {
                    trusted_user_ca_keys: Some(home.root.join("trusted_ca.pub")),
                    authorized_principals: Some([(me.clone(), vec![principal_for(&p)])].into()),
                    ..SshdConfig::default()
                }
            };
            let sshd =
                LoopbackSshd::start(home.scratch(), config).unwrap_or_else(|e| panic!("{e}"));
            if form == "system" {
                sshd.trust_user_ca(&ca.public_line()).unwrap();
            }
            home.trust_host_key(&sshd.host_key_line).unwrap();
            let identity = write_identity(&home, &kenv);
            home.write_user_config(&alias_block("u1-cert", sshd.port, &identity, ""))
                .unwrap();

            let agent =
                CaptureAgent::start(home.scratch(), form, &kenv, vec![cert.to_bytes().unwrap()]);
            let out = login(&home, "u1-cert", &agent);
            assert!(
                out.status.success(),
                "{form}: ssh exit {:?}\n{}",
                out.status.code(),
                failure_reason(&home, &out, Some(&sshd))
            );
            let accepted = sshd.accepted_certificates();
            assert_eq!(accepted.len(), 1, "{form}");
            assert_eq!(accepted[0].key_id, cert.key_id());
            assert_eq!(accepted[0].serial, cert.serial());
            assert_eq!(accepted[0].ca_fingerprint, ca.fingerprint().as_str());
            assert_eq!(accepted[0].fingerprint, kenv.info.fingerprint);

            // Control: a certificate for another destination's principal is refused.
            let (_, foreign) = issued(&kenv, &ca, &pair("u1-other", &me));
            let agent = CaptureAgent::start(
                home.scratch(),
                &format!("{form}-x"),
                &kenv,
                vec![foreign.to_bytes().unwrap()],
            );
            let out = login(&home, "u1-cert", &agent);
            assert_eq!(
                out.status.code(),
                Some(255),
                "{form}: a foreign principal is refused"
            );
            assert_eq!(sshd.accepted_certificates().len(), 1, "{form}");
        }
    }

    /// ⟨wave-1 native run, item B2⟩ An observation per client, for U2 and U8: the managed
    /// alias's shape (`IdentityFile` K_env's `.pub`) with an agent listing (a) only the
    /// certificate and (b) the certificate and the plain key. Records the login's exit and
    /// which key blob the client asked the agent to sign (`cert`, `plain`, `none`). The
    /// control (a decoy `IdentityFile`, only the certificate) must log in on every
    /// client. Nothing else is asserted: the rows are observations.
    pub(super) fn certificate_identity_file_selection_observed_per_client() {
        let me = account();
        let ca = TestCa::new();
        let home = ScratchHome::new();
        let kenv = Kenv::new();
        let p = pair("u1-dest", &me);
        let (_, cert) = issued(&kenv, &ca, &p);
        let cert_blob = cert.to_bytes().unwrap();
        let sshd = LoopbackSshd::start(
            home.scratch(),
            SshdConfig {
                registry_seed: Some(cert_authority_line(&p, &ca)),
                ..SshdConfig::default()
            },
        )
        .unwrap_or_else(|e| panic!("{e}"));
        home.trust_host_key(&sshd.host_key_line).unwrap();
        let kenv_file = write_kenv_identity(&home, &kenv);
        let decoy_file = write_identity(&home, &kenv);
        home.write_user_config(
            &[
                alias_block("u1-sel-kenv", sshd.port, &kenv_file, ""),
                alias_block("u1-sel-decoy", sshd.port, &decoy_file, ""),
            ]
            .concat(),
        )
        .unwrap();
        let client = Command::new(find_program("ssh").unwrap())
            .arg("-V")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
            .unwrap_or_default();
        let which = |agent: &CaptureAgent| -> &'static str {
            match agent.signed().first() {
                None => "none",
                Some((k, _, _)) if *k == cert_blob => "cert",
                Some((k, _, _)) if *k == kenv.info.blob => "plain",
                Some(_) => "other",
            }
        };
        let cases: [(&str, &str, Vec<Vec<u8>>); 3] = [
            (
                "a_kenv_file_cert_only",
                "u1-sel-kenv",
                vec![cert_blob.clone()],
            ),
            (
                "b_kenv_file_cert_and_plain",
                "u1-sel-kenv",
                vec![cert_blob.clone(), kenv.info.blob.clone()],
            ),
            (
                "control_decoy_file_cert_only",
                "u1-sel-decoy",
                vec![cert_blob.clone()],
            ),
        ];
        for (case, alias, identities) in cases {
            let agent = CaptureAgent::start(home.scratch(), case, &kenv, identities);
            let out = login(&home, alias, &agent);
            #[allow(clippy::print_stderr)] // an observation for U2 and U8
            {
                eprintln!(
                    "m03 observation: identity_file_selection client={client:?} case={case} exit={:?} signed={}",
                    out.status.code(),
                    which(&agent)
                );
            }
            if case.starts_with("control") {
                assert!(
                    out.status.success(),
                    "{case}: ssh exit {:?}\n{}",
                    out.status.code(),
                    failure_reason(&home, &out, Some(&sshd))
                );
                assert_eq!(which(&agent), "cert");
            }
        }
    }
}
