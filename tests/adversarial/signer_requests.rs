//! m03-plan U1 adversarial userauth and session-bind request tests (hosted by
//! heimdall-credential; ADR-0008 D2 items 4–5). Truncated and oversized requests,
//! declared lengths past the end, 1 MiB of random data, and fixed-seed properties
//! (≥ 256 cases): nothing panics, and everything malformed is refused. Every key is
//! generated per run.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{AccountName, DestinationId, EnvironmentId, GrantId};
use heimdall_credential::cert::{self, CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::purpose::{
    GrantCertificates, MAX_USERAUTH_BYTES, PurposeRefusal, check, parse_userauth,
};
use heimdall_credential::session_bind;
use heimdall_credential::vault::{KeyVault, SystemRng};
use heimdall_domain::issuance::{CertificateBounds, EXTENSION_PTY, principal_for};
use heimdall_domain::scope::AccessPair;
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

const CERT_ALG: &str = "ssh-ed25519-cert-v01@openssh.com";
const HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    SystemRng::fill(&mut b).unwrap();
    b
}

/// A grant with one pair and its certificate, and two valid requests (publickey and
/// host-bound) with the offset of each length field in them.
struct Fixture {
    certs: GrantCertificates,
    cert_blob: Vec<u8>,
    requests: Vec<(Vec<u8>, Vec<usize>)>,
    bind: (Vec<u8>, Vec<usize>),
}

fn fixture() -> Fixture {
    let vault = KeyVault::new();
    let (_slot, info) = vault.generate_ed25519().unwrap();
    let ca = SecretCaKey::generate().unwrap();
    let pair = AccessPair {
        destination: DestinationId::parse("dest-a").unwrap(),
        account: AccountName::parse("alice").unwrap(),
    };
    let now = Timestamp::now().as_second();
    let serial = u64::from_be_bytes(random_bytes(8).try_into().unwrap());
    let bounds = CertificateBounds {
        serial,
        key_id: cert::key_id(
            &EnvironmentId::from_random_bytes([1; 16]),
            &GrantId::from_random_bytes([2; 16]),
            serial,
        ),
        principal: principal_for(&pair),
        valid_after: cert::valid_after_for(Timestamp::from_second(now).unwrap()).unwrap(),
        valid_before: Timestamp::from_second(now + 3600).unwrap(),
        extensions: [EXTENSION_PTY.to_owned()].into(),
        subject_fingerprint: info.fingerprint.clone(),
        ca_fingerprint: Some(ca.fingerprint().unwrap()),
    };
    let subject = info.public_key().unwrap();
    let c = build_and_sign(&CertificateProfile::from_bounds(&bounds), &subject, &ca).unwrap();
    let cert_blob = c.to_bytes().unwrap();
    let mut certs = GrantCertificates::new(&subject).unwrap();
    certs.add(pair, &c).unwrap();

    let host = KeyVault::new();
    let (host_slot, host_info) = host.generate_ed25519().unwrap();
    let sid = random_bytes(32);
    let mut requests = Vec::new();
    for hostbound in [false, true] {
        let mut out = Vec::new();
        let mut lengths = Vec::new();
        let mut string = |out: &mut Vec<u8>, s: &[u8]| {
            lengths.push(out.len());
            put_string(out, s);
        };
        string(&mut out, &sid);
        out.push(50);
        string(&mut out, b"alice");
        string(&mut out, b"ssh-connection");
        string(
            &mut out,
            if hostbound { HOSTBOUND } else { "publickey" }.as_bytes(),
        );
        out.push(1);
        string(&mut out, CERT_ALG.as_bytes());
        string(&mut out, &cert_blob);
        if hostbound {
            string(&mut out, &host_info.blob);
        }
        requests.push((out, lengths));
    }
    let signature = host.sign(&host_slot, &sid).unwrap();
    let mut bind = Vec::new();
    let mut bind_lengths = Vec::new();
    for field in [&host_info.blob, &sid, &signature] {
        bind_lengths.push(bind.len());
        put_string(&mut bind, field);
    }
    bind.push(0);
    Fixture {
        certs,
        cert_blob,
        requests,
        bind: (bind, bind_lengths),
    }
}

#[test]
fn valid_fixture_requests_are_accepted() {
    // The control for every refusal below: the unmodified requests pass.
    let f = fixture();
    for (data, _) in &f.requests {
        let req = parse_userauth(data).unwrap();
        assert!(check(&req, &f.certs, 0).is_ok());
    }
    assert!(session_bind::accept(&f.bind.0).is_ok());
}

#[test]
fn truncated_userauth_requests_refused() {
    let f = fixture();
    for (data, _) in &f.requests {
        for cut in 0..data.len() {
            assert!(
                parse_userauth(&data[..cut]).is_err(),
                "prefix of {cut} bytes"
            );
        }
    }
    let bind = &f.bind.0;
    for cut in 0..bind.len() {
        assert!(
            session_bind::parse(&bind[..cut]).is_err(),
            "bind prefix {cut}"
        );
    }
}

#[test]
fn oversized_userauth_requests_refused() {
    let f = fixture();
    // Over the bound by one byte, however it is padded.
    for (data, _) in &f.requests {
        let mut big = data.clone();
        big.resize(MAX_USERAUTH_BYTES + 1, 0);
        assert_eq!(parse_userauth(&big), Err(PurposeRefusal::Oversize));
    }
    // A request whose key blob alone is 1 MiB: refused before any field is read.
    let mut huge = Vec::new();
    put_string(&mut huge, &random_bytes(32));
    huge.push(50);
    put_string(&mut huge, b"alice");
    put_string(&mut huge, b"ssh-connection");
    put_string(&mut huge, b"publickey");
    huge.push(1);
    put_string(&mut huge, CERT_ALG.as_bytes());
    put_string(&mut huge, &vec![0x41; 1 << 20]);
    assert_eq!(parse_userauth(&huge), Err(PurposeRefusal::Oversize));
    // A well-formed request just under the bound parses (the bound is not off by one),
    // and is still refused by the purpose check (its key is not the grant's).
    let mut fits = Vec::new();
    put_string(&mut fits, &random_bytes(32));
    fits.push(50);
    put_string(&mut fits, b"alice");
    put_string(&mut fits, b"ssh-connection");
    put_string(&mut fits, b"publickey");
    fits.push(1);
    put_string(&mut fits, CERT_ALG.as_bytes());
    let room = MAX_USERAUTH_BYTES - fits.len() - 4;
    put_string(&mut fits, &vec![0x42; room]);
    assert_eq!(fits.len(), MAX_USERAUTH_BYTES);
    let req = parse_userauth(&fits).unwrap();
    assert_eq!(check(&req, &f.certs, 0), Err(PurposeRefusal::KeyNotInGrant));
    // An oversized session-bind (a 1 MiB host key) is refused too.
    let mut bind = Vec::new();
    put_string(&mut bind, &vec![0x43; 1 << 20]);
    put_string(&mut bind, &random_bytes(32));
    put_string(&mut bind, &random_bytes(83));
    bind.push(0);
    assert!(session_bind::parse(&bind).is_err());
}

#[test]
fn declared_lengths_past_the_end_refused() {
    let f = fixture();
    for (data, lengths) in &f.requests {
        for &at in lengths {
            let declared = u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
            for bad in [
                declared + 1,
                declared + 4096,
                (1 << 20) - 1,
                1 << 20,
                (1 << 20) + 1,
                u32::MAX - 1,
                u32::MAX,
            ] {
                let mut m = data.clone();
                m[at..at + 4].copy_from_slice(&bad.to_be_bytes());
                assert!(
                    parse_userauth(&m).is_err(),
                    "length at {at} set to {bad} (was {declared})"
                );
            }
        }
    }
    let (bind, lengths) = &f.bind;
    for &at in lengths {
        let declared = u32::from_be_bytes(bind[at..at + 4].try_into().unwrap());
        for bad in [declared + 1, declared + 2, 1 << 20, u32::MAX] {
            let mut m = bind.clone();
            m[at..at + 4].copy_from_slice(&bad.to_be_bytes());
            assert!(
                session_bind::parse(&m).is_err(),
                "bind length at {at} = {bad}"
            );
        }
    }
}

#[test]
fn one_mebibyte_of_random_data_refused() {
    let data = random_bytes(1 << 20);
    assert_eq!(parse_userauth(&data), Err(PurposeRefusal::Oversize));
    assert!(session_bind::parse(&data).is_err());
    // Every 4 KiB window, and every window starting on a byte boundary in the first
    // 4 KiB, is refused as well.
    for window in data.chunks(4096) {
        assert!(parse_userauth(window).is_err());
        assert!(session_bind::parse(window).is_err());
    }
    for start in 0..4096 {
        let w = &data[start..start + 512];
        assert!(parse_userauth(w).is_err());
        assert!(session_bind::parse(w).is_err());
    }
}

fn props_config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 512,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5531_5349_474e_5251);
    }
    c
}

proptest! {
    #![proptest_config(props_config())]

    /// Arbitrary bytes are never a userauth request or a session-bind.
    #[test]
    fn arbitrary_bytes_refused(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert!(parse_userauth(&data).is_err());
        prop_assert!(session_bind::parse(&data).is_err());
    }

    /// One mutated byte, an inserted byte or a deletion anywhere in a valid request
    /// never panics; whatever still parses keeps the purpose binding: the purpose check
    /// admits it only for exactly the grant's certificate, its algorithm and its pair's
    /// account.
    #[test]
    fn mutated_requests_keep_the_purpose_binding(
        which in 0usize..2,
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
        op in 0u8..3,
        flags in prop_oneof![Just(0u32), any::<u32>()],
    ) {
        let f = FIXTURE.with(|f| (f.certs.clone(), f.cert_blob.clone(), f.requests.clone()));
        let (certs, cert_blob, requests) = f;
        let mut data = requests[which].0.clone();
        let i = at.index(data.len());
        match op {
            0 => data[i] ^= byte | 1,
            1 => data.insert(i, byte),
            _ => { data.remove(i); }
        }
        if let Ok(req) = parse_userauth(&data)
            && let Ok(pair) = check(&req, &certs, flags)
        {
            prop_assert_eq!(&req.key_blob, &cert_blob);
            prop_assert_eq!(req.algorithm.as_str(), CERT_ALG);
            prop_assert_eq!(req.user.as_str(), pair.pair.account.as_str());
            prop_assert_eq!(flags, 0);
        }
        // The same mutations of the session-bind never panic; one that still parses
        // verifies only if its signed fields are intact.
        let mut bind = FIXTURE.with(|f| f.bind.0.clone());
        let j = at.index(bind.len());
        match op {
            0 => bind[j] ^= byte | 1,
            1 => bind.insert(j, byte),
            _ => { bind.remove(j); }
        }
        let _ = session_bind::accept(&bind);
    }
}

thread_local! {
    static FIXTURE: Fixture = fixture();
}
