//! ⟨M06 U3⟩ The runner runtime (m06-plan U3 "Tests"; ADR-0012 §4; ADR-0005 §3.5 step 4, §3.6
//! "Runner deadline"): issuance pinned to its issuer with the install checks, the designated
//! time source on a virtual clock, readiness with the earliest bound and the residuals, and the
//! A24 provenance row.
//!
//! Everything is in process over a disposable in-memory runner store and per-run CAs; the A24
//! row uses scratch Unix sockets and `/usr/bin/env` with a cleared environment. No real
//! agent, key, keychain or systemd is touched.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "runner_fixture_m06.rs"]
mod fixture;

use std::time::Duration;

use fixture::*;
use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::managed::DestinationClock;
use heimdall_contract::remote::RunnerRequest;
use heimdall_domain::issuance::IssuanceRefusal;
use heimdall_domain::time::Clock;
use heimdall_runtime::runner::issuance::IssuanceFailure;
use heimdall_runtime::runner::time::TimeRefusal;

fn grant_bound_until(w: &World) -> heimdall_contract::Timestamp {
    deadline().min(plus(w.clock.wall(), HOUR))
}

// --- the designated time source (virtual clock) ------------------------------------------------

/// A sample from a client that is not the designated time source is refused, whoever it is and
/// however it obtained a nonce; the designation is reread for every answer.
#[test]
fn a_sample_from_a_non_designated_client_is_refused() {
    let w = world();
    let tc = w.clock.wall();
    // No designation at all: nobody is answered.
    assert_eq!(
        w.exchange(&controller_a(), 1, Duration::from_millis(10), tc),
        Err(TimeRefusal::NotDesignated)
    );
    w.designate(&controller_a());
    // Another active owner is not the time source.
    assert_eq!(
        w.exchange(&stranger(), 2, Duration::from_millis(10), tc),
        Err(TimeRefusal::NotDesignated)
    );
    let e = TimeRefusal::NotDesignated.to_error();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(e.reason.as_deref(), Some(reason::ROLE_INSUFFICIENT));
    // A's nonce answered on B's session: no such challenge there (TIME_UNCERTAIN).
    let time = w.runner.time();
    let a = heimdall_runtime::runner::time::TimeSession {
        client: controller_a(),
        connection: 3,
    };
    let b = heimdall_runtime::runner::time::TimeSession {
        client: controller_b(),
        connection: 3,
    };
    let nonce = w
        .store
        .transaction(|tx| Ok(time.challenge(tx, &a)))
        .unwrap()
        .unwrap()
        .nonce;
    assert_eq!(nonce.len(), 32);
    assert_eq!(
        w.store
            .transaction(|tx| Ok(time.respond(tx, &b, &nonce, tc)))
            .unwrap(),
        Err(TimeRefusal::UnknownNonce)
    );
    assert_eq!(
        TimeRefusal::UnknownNonce.to_error().code,
        Code::TimeUncertain
    );
    // Re-designated between the challenge and the answer: A's answer no longer counts.
    let nonce = w
        .store
        .transaction(|tx| Ok(time.challenge(tx, &a)))
        .unwrap()
        .unwrap()
        .nonce;
    w.designate(&controller_b());
    assert_eq!(
        w.store
            .transaction(|tx| Ok(time.respond(tx, &a, &nonce, tc)))
            .unwrap(),
        Err(TimeRefusal::NotDesignated)
    );
    // A designated client that is revoked counts for nothing.
    w.store
        .transaction(|tx| {
            tx.revoke_remote_client(
                &controller_b(),
                heimdall_store::ext_m06::RevocationCause::Revoked,
                tc,
            )
            .map(drop)
        })
        .unwrap();
    assert_eq!(
        w.exchange(&controller_b(), 4, Duration::from_millis(10), tc),
        Err(TimeRefusal::NotActiveOwner)
    );
    assert!(!w.runner.time().bounded());
}

/// An answer counts once, on its own session, in its boot and within the RTT bound.
#[test]
fn a_sample_is_fresh_nonce_bound_and_rtt_bounded() {
    let w = world();
    w.designate(&controller_a());
    let tc = w.clock.wall();
    let time = w.runner.time();
    let s = heimdall_runtime::runner::time::TimeSession {
        client: controller_a(),
        connection: 7,
    };
    let other_connection = heimdall_runtime::runner::time::TimeSession {
        client: controller_a(),
        connection: 8,
    };
    let challenge = |s| {
        w.store
            .transaction(|tx| Ok(time.challenge(tx, s)))
            .unwrap()
            .unwrap()
            .nonce
    };
    let respond = |s, n: &str| {
        w.store
            .transaction(|tx| Ok(time.respond(tx, s, n, tc)))
            .unwrap()
    };
    // The same client on another connection: not this session's challenge.
    let n = challenge(&s);
    assert_eq!(
        respond(&other_connection, &n),
        Err(TimeRefusal::UnknownNonce)
    );
    // Once: the replay finds nothing.
    let n = challenge(&s);
    assert!(respond(&s, &n).is_ok());
    assert_eq!(respond(&s, &n), Err(TimeRefusal::UnknownNonce));
    // A forged nonce.
    assert_eq!(respond(&s, &"0".repeat(32)), Err(TimeRefusal::UnknownNonce));
    // Over the RTT bound (2 s): refused, time stays as it was.
    let n = challenge(&s);
    w.clock.advance(Duration::from_millis(2_001));
    assert_eq!(respond(&s, &n), Err(TimeRefusal::RttExceeded));
    // Across a reboot: the challenge belongs to another boot, and the earlier sample no longer
    // bounds anything.
    let n = challenge(&s);
    w.clock.reboot(w.clock.wall());
    assert!(matches!(
        respond(&s, &n),
        Err(TimeRefusal::OtherBoot | TimeRefusal::UnknownNonce)
    ));
    assert!(!w.runner.time().bounded());
    // Two nonces are never equal.
    assert_ne!(challenge(&s), challenge(&s));
}

/// A sample never extends an anchor, a bound or a deadline, and never acts as `confirm_time`:
/// the runtime anchor, the high-water mark and the attended confirmation are untouched.
#[test]
fn a_sample_never_extends_and_never_confirms_time() {
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let p = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, w.generation())
        .unwrap();
    w.good_sample();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), grant_bound_until(&w));
    w.runner
        .issuance()
        .install(&controller_a(), &w.grant, p.grant_generation, &cert)
        .unwrap();
    let anchor = |w: &World| {
        w.store
            .transaction(|tx| tx.grant_anchor(&w.grant))
            .unwrap()
            .unwrap()
    };
    let first = anchor(&w);
    // The derived deadline is at or before D: t₂ + (D − (T_c + rtt)).
    assert!(first.budget_end <= w.clock.continuous() + (2 * HOUR));
    assert_eq!(first.bound, deadline());
    // A controller clock one hour behind would put the deadline later: nothing moves.
    let behind = plus(w.clock.wall(), Duration::ZERO)
        .checked_sub(jiff::SignedDuration::from_hours(1))
        .unwrap();
    let r = w
        .exchange(&controller_a(), 1, Duration::from_millis(50), behind)
        .unwrap();
    assert_eq!(r.anchors_shortened, 0);
    assert_eq!(anchor(&w), first);
    // A controller clock 30 minutes ahead moves it earlier, never the bound.
    let ahead = plus(w.clock.wall(), 30 * 60 * Duration::from_secs(1));
    let r = w
        .exchange(&controller_a(), 1, Duration::from_millis(50), ahead)
        .unwrap();
    assert_eq!(r.anchors_shortened, 1);
    let second = anchor(&w);
    assert!(second.budget_end < first.budget_end);
    assert_eq!(second.bound, first.bound);
    assert_eq!(second.anchor, first.anchor);
    // Never confirm_time.
    w.store
        .transaction(|tx| {
            assert_eq!(tx.time_confirmation()?, None);
            assert_eq!(tx.runtime_anchor()?, None);
            assert_eq!(tx.high_water_mark()?, None);
            Ok(())
        })
        .unwrap();
    // And the grant's deadline is the one it was created with.
    let g = w
        .store
        .transaction(|tx| tx.grant(&w.grant))
        .unwrap()
        .unwrap();
    assert_eq!(g.deadline.effective, deadline());
}

/// Without a qualifying sample the runner's time is uncertain: installation answers
/// `TIME_UNCERTAIN` and readiness has no derived anchor; with one, both proceed.
#[test]
fn time_uncertain_without_a_qualifying_sample() {
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let p = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, w.generation())
        .unwrap();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), grant_bound_until(&w));
    let e = w
        .runner
        .issuance()
        .install(&controller_a(), &w.grant, p.grant_generation, &cert)
        .unwrap_err();
    assert_eq!(e, IssuanceFailure::TimeUncertain);
    assert_eq!(e.to_error().code, Code::TimeUncertain);
    let r = w
        .runner
        .readiness(&w.grant, DestinationClock::Unmeasured, None)
        .unwrap();
    assert_eq!(r.time, heimdall_app::readiness::RunnerTime::Uncertain);
    w.good_sample();
    let ok = w
        .runner
        .issuance()
        .install(&controller_a(), &w.grant, p.grant_generation, &cert)
        .unwrap();
    assert!(!ok.complete);
    let r = w
        .runner
        .readiness(
            &w.grant,
            DestinationClock::Unmeasured,
            Some(ok.valid_before),
        )
        .unwrap();
    assert_eq!(r.time, heimdall_app::readiness::RunnerTime::Bounded);
}

// --- issuance pinned to its issuer, with the install checks ------------------------------------

/// Prepare and install: `issuer_trust`, the pin to the issuing controller and CA, and ADR-0005
/// §3.5 step 4's checks (key, issuer, principals, generation, scope, `valid_before`).
#[test]
fn issuance_is_pinned_to_its_issuer_with_the_install_checks() {
    let w = world();
    let iss = w.runner.issuance();
    let g = w.generation();
    // Untrusted controller: nothing is generated.
    assert_eq!(
        iss.prepare(&controller_a(), &w.grant, g).unwrap_err(),
        IssuanceFailure::IssuerUntrusted
    );
    assert!(iss.keys().public_key(&w.grant).is_none());
    w.trust(&w.ca_a, &controller_a());
    // A stale generation.
    assert_eq!(
        iss.prepare(&controller_a(), &w.grant, g + 1).unwrap_err(),
        IssuanceFailure::Refused(IssuanceRefusal::StaleGeneration)
    );
    let p = iss.prepare(&controller_a(), &w.grant, g).unwrap();
    assert_eq!(p.environment, w.env);
    assert_eq!(p.pairs, vec![pair("h1"), pair("h2")]);
    assert_eq!(p.bound, deadline());
    assert_eq!(p.pinned_issuer, None);
    assert!(p.public_key.starts_with("ssh-ed25519 "));
    // A lost reply: the same key again.
    assert_eq!(iss.prepare(&controller_a(), &w.grant, g).unwrap(), p);
    // The controller accepts it (the issuer's paired-environment path).
    let expected = heimdall_issuer::remote::RemoteExpectation {
        environment: w.env.clone(),
        grant: w.grant.clone(),
        grant_generation: g,
        controller: controller_a(),
        ca_fingerprint: w.ca_a.fingerprint().unwrap(),
    };
    let request = heimdall_issuer::remote::verify_prepared(&expected, &p, w.clock.wall()).unwrap();
    w.good_sample();
    let until = grant_bound_until(&w);
    let install = |cert: &str| iss.install(&controller_a(), &w.grant, g, cert);
    // Issuer: a CA not in issuer_trust.
    let untrusted = w.sign(&w.ca_b, &p, &pair("h1"), until);
    assert_eq!(
        install(&untrusted).unwrap_err(),
        IssuanceFailure::IssuerUntrusted
    );
    assert_eq!(
        IssuanceFailure::IssuerUntrusted
            .to_error()
            .reason
            .as_deref(),
        Some(reason::ISSUER_UNTRUSTED)
    );
    // Key: another subject than K_env.
    let other = w.sign_with(
        &w.ca_a,
        &World::other_key(),
        &p,
        &pair("h1"),
        until,
        &["permit-pty"],
        None,
    );
    assert_eq!(
        install(&other).unwrap_err(),
        IssuanceFailure::Refused(IssuanceRefusal::UnknownSubjectKey)
    );
    // Principals: not one of the grant's pairs.
    let wrong = w.sign_with(
        &w.ca_a,
        &w.k_env(),
        &p,
        &pair("h1"),
        until,
        &["permit-pty"],
        Some("hm:h9:deploy"),
    );
    assert_eq!(
        install(&wrong).unwrap_err(),
        IssuanceFailure::Refused(IssuanceRefusal::WrongPrincipal)
    );
    // Scope: an extension outside the grant's permissions.
    let fwd = w.sign_with(
        &w.ca_a,
        &w.k_env(),
        &p,
        &pair("h1"),
        until,
        &["permit-pty", "permit-agent-forwarding"],
        None,
    );
    assert_eq!(
        install(&fwd).unwrap_err(),
        IssuanceFailure::Refused(IssuanceRefusal::UnpermittedExtension)
    );
    // valid_before: later than the grant's bound.
    let late = w.sign(
        &w.ca_a,
        &p,
        &pair("h1"),
        plus(deadline(), Duration::from_secs(60)),
    );
    assert_eq!(
        install(&late).unwrap_err(),
        IssuanceFailure::Refused(IssuanceRefusal::BoundTooLate)
    );
    // Generation: another generation than the key was prepared for.
    let good = w.sign(&w.ca_a, &p, &pair("h1"), until);
    assert_eq!(
        iss.install(&controller_a(), &w.grant, g + 1, &good)
            .unwrap_err(),
        IssuanceFailure::NoKey
    );
    // Garbage.
    assert_eq!(
        install("ssh-ed25519-cert-v01@openssh.com AAAA").unwrap_err(),
        IssuanceFailure::Certificate
    );
    // The good one installs and pins the grant to A and CA A; a retry returns the same.
    let ok = install(&good).unwrap();
    assert_eq!(ok.pair, pair("h1"));
    assert_eq!(install(&good).unwrap(), ok);
    let pin = w
        .store
        .transaction(|tx| tx.remote_grant_issuer(&w.grant))
        .unwrap()
        .unwrap();
    assert_eq!(pin.issuer_client, controller_a());
    assert_eq!(pin.ca_fingerprint, w.ca_a.fingerprint().unwrap());
    // Another certificate for the installed pair is refused.
    let again = w.sign(&w.ca_a, &p, &pair("h1"), until);
    assert_eq!(
        install(&again).unwrap_err(),
        IssuanceFailure::AlreadyInstalled
    );
    // Pinned: controller B (trusted with its own CA) cannot prepare or install for this grant,
    // and A cannot switch to another CA even if trusted for it.
    w.trust(&w.ca_b, &controller_b());
    assert_eq!(
        iss.prepare(&controller_b(), &w.grant, g).unwrap_err(),
        IssuanceFailure::IssuerUntrusted
    );
    let by_b = w.sign(&w.ca_b, &p, &pair("h2"), until);
    assert_eq!(
        iss.install(&controller_b(), &w.grant, g, &by_b)
            .unwrap_err(),
        IssuanceFailure::IssuerUntrusted
    );
    let ca_c = heimdall_credential::cert::SecretCaKey::generate().unwrap();
    w.trust(&ca_c, &controller_a());
    let other_ca = w.sign(&ca_c, &p, &pair("h2"), until);
    assert_eq!(
        install(&other_ca).unwrap_err(),
        IssuanceFailure::IssuerUntrusted
    );
    // The second pair from A and CA A completes the grant; the prepare now reports the pin.
    let h2 = w.sign(&w.ca_a, &p, &pair("h2"), until);
    assert!(install(&h2).unwrap().complete);
    let again = iss.prepare(&controller_a(), &w.grant, g).unwrap();
    assert_eq!(
        again.pinned_issuer,
        Some(heimdall_issuer::remote::PinnedIssuer {
            controller: controller_a(),
            ca_fingerprint: w.ca_a.fingerprint().unwrap(),
        })
    );
    assert!(heimdall_issuer::remote::install_request(&request, &h2).is_ok());
    assert_eq!(iss.keys().certificates(&w.grant).len(), 2);
}

/// A tombstone on the runner refuses installation; grant end zeroizes K_env.
#[test]
fn a_tombstone_refuses_installation_and_grant_end_destroys_the_key() {
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let p = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, g)
        .unwrap();
    w.good_sample();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), grant_bound_until(&w));
    w.tombstone();
    let e = w
        .runner
        .issuance()
        .install(&controller_a(), &w.grant, g, &cert)
        .unwrap_err();
    assert!(
        matches!(
            e,
            IssuanceFailure::Refused(
                IssuanceRefusal::GrantNotIssuable(_)
                    | IssuanceRefusal::Tombstoned
                    | IssuanceRefusal::StaleGeneration
            )
        ),
        "{e:?}"
    );
    assert!(w.runner.issuance().keys().certificates(&w.grant).is_empty());
    assert!(w.runner.issuance().destroy(&w.grant));
    assert!(w.runner.issuance().keys().public_key(&w.grant).is_none());
    assert!(!w.runner.issuance().destroy(&w.grant));
}

/// A signature authority that admits nothing: the listing test never signs.
struct NoAuthority;

#[async_trait::async_trait]
impl heimdall_app::ports::SignatureAuthority for NoAuthority {
    async fn precheck(
        &self,
        _facts: &heimdall_app::ports::SignatureRequestFacts,
    ) -> Result<(), heimdall_app::ports::SignRefusal> {
        Err(heimdall_app::ports::SignRefusal::Unavailable)
    }
    async fn admit(
        &self,
        _facts: &heimdall_app::ports::SignatureRequestFacts,
    ) -> Result<heimdall_app::managed::SignPermit, heimdall_app::ports::SignRefusal> {
        Err(heimdall_app::ports::SignRefusal::Unavailable)
    }
}

/// ⟨M06 W3; ADR-0012 §4.1, §4.6⟩ The runner's working keys are served by the existing local
/// binding-endpoint machinery over the runner's own signer table: a binding of the runner
/// grant lists exactly the certificates runner issuance accepted, never the plain K_env and
/// never a key the runner did not generate (another grant's, or the controller's CA); a
/// binding of a grant the runner holds no K_env for gets no signer; nothing is listed before
/// an install, and grant end empties the endpoint.
#[test]
fn the_runner_binding_endpoint_serves_only_runner_owned_keys() {
    use heimdall_app::ports::SignerEndpoint;
    use heimdall_contract::ids::{BindingId, GrantId};
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let iss = w.runner.issuance();
    let p = iss.prepare(&controller_a(), &w.grant, g).unwrap();
    let binding = BindingId::from_random_bytes([0x61; 16]);
    let authority: std::sync::Arc<dyn heimdall_app::ports::SignatureAuthority> =
        std::sync::Arc::new(NoAuthority);
    let limits = heimdall_credential::signer::SignerLimits::default();
    let signer = iss
        .keys()
        .binding_signer(&binding, &w.grant, authority.clone(), limits)
        .expect("the runner holds K_env for its grant");
    assert_eq!(signer.endpoint(), &SignerEndpoint::Binding(binding.clone()));
    let table = iss.keys().table();
    let listed = |b: &BindingId| table.list(&SignerEndpoint::Binding(b.clone()));
    assert!(listed(&binding).is_empty(), "nothing before an install");
    w.good_sample();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), grant_bound_until(&w));
    iss.install(&controller_a(), &w.grant, g, &cert).unwrap();
    let ids = listed(&binding);
    assert_eq!(ids.len(), 1, "exactly the installed certificate");
    let installed = ssh_key::Certificate::from_openssh(cert.trim())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(ids[0].0, installed);
    assert!(ids[0].1.starts_with("heimdall:"));
    // Never the plain K_env, never the controller's CA key.
    let k_env = ssh_key::PublicKey::from_openssh(&p.public_key)
        .unwrap()
        .to_bytes()
        .unwrap();
    let ca = w.ca_a.public_key().to_bytes().unwrap();
    assert!(ids.iter().all(|(blob, _)| blob != &k_env && blob != &ca));
    // Another grant: the runner generated no key for it, so no signer and nothing listed.
    let other_grant = GrantId::from_random_bytes([0x62; 16]);
    let other = BindingId::from_random_bytes([0x63; 16]);
    assert!(
        iss.keys()
            .binding_signer(&other, &other_grant, authority, limits)
            .is_none()
    );
    assert!(listed(&other).is_empty());
    // Grant end: the endpoint lists nothing.
    assert!(iss.destroy(&w.grant));
    assert!(listed(&binding).is_empty());
}

/// ⟨M06 W3; runner Q7; ADR-0012 §4.1, §4.6⟩ The managed wiring's route for a runner grant's
/// binding (`service::RunnerBindingEndpoints`, what `LateRegistry` asks first): its endpoint
/// is created over the runner signer's own table, and a real agent client on its socket is
/// listed exactly the grant's K_env certificate (never the plain K_env, never the CA's key);
/// a binding of a grant the runner holds no K_env for, or one the store does not know, is not
/// routed here at all; after `destroy` the endpoint lists nothing and no new one is created.
#[cfg(unix)]
#[tokio::test]
async fn a_runner_grants_binding_endpoint_lists_its_k_env_identity_only() {
    use heimdall_contract::ids::{BindingId, GrantId};
    use heimdall_credential::endpoints::{EndpointLayout, EndpointPlacement};
    use heimdall_runtime::service::RunnerBindingEndpoints;
    use heimdall_testkit::agent::{AgentConnection, Endpoint};
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let p = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, g)
        .unwrap();
    let binding = BindingId::from_random_bytes([0x71; 16]);
    let other = BindingId::from_random_bytes([0x72; 16]);
    let other_grant = GrantId::from_random_bytes([0x73; 16]);
    let unknown = BindingId::from_random_bytes([0x74; 16]);
    let (grant, b, o) = (w.grant.clone(), binding.clone(), other.clone());
    // A short runtime directory: a socket path stays under the platform's limit.
    let dir = tempfile::Builder::new()
        .prefix("hm-rb")
        .tempdir_in("/tmp")
        .unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    let endpoints = RunnerBindingEndpoints::new(
        std::sync::Arc::clone(&w.runner),
        EndpointLayout::unix(dir.path()).unwrap(),
        heimdall_ipc::endpoint::ExpectedOwner::Uid(heimdall_ipc::unix::current_uid()),
        std::sync::Arc::new(NoAuthority),
        heimdall_credential::signer::SignerLimits::default(),
        stop.clone(),
        std::sync::Arc::new(move |id: &BindingId| {
            if id == &b {
                Some(grant.clone())
            } else if id == &o {
                Some(other_grant.clone())
            } else {
                None
            }
        }),
    );
    // Not the runner's: another grant's binding and an unknown binding create nothing here.
    assert!(
        endpoints
            .create(&other, 1, &EndpointPlacement::Native)
            .is_none()
    );
    assert!(
        endpoints
            .create(&unknown, 1, &EndpointPlacement::Native)
            .is_none()
    );
    assert!(endpoints.endpoint(&other).is_none());
    assert_eq!(endpoints.runner_grant(&binding), Some(w.grant.clone()));
    let endpoint = endpoints
        .create(&binding, 1, &EndpointPlacement::Native)
        .expect("a runner grant's binding is routed to the runner signer")
        .unwrap();
    assert_eq!(endpoints.endpoint(&binding), Some(endpoint.clone()));
    let socket = Endpoint::UnixSocket(endpoint.locator.clone().into());
    let list = |socket: Endpoint| async move {
        tokio::task::spawn_blocking(move || {
            AgentConnection::connect(&socket, Duration::from_secs(10))
                .unwrap()
                .list()
                .unwrap()
        })
        .await
        .unwrap()
    };
    assert!(
        list(socket.clone()).await.is_empty(),
        "nothing before an install"
    );
    w.good_sample();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), grant_bound_until(&w));
    w.runner
        .issuance()
        .install(&controller_a(), &w.grant, g, &cert)
        .unwrap();
    let ids = list(socket.clone()).await;
    let installed = ssh_key::Certificate::from_openssh(cert.trim())
        .unwrap()
        .to_bytes()
        .unwrap();
    assert_eq!(ids.len(), 1, "exactly the grant's K_env certificate");
    assert_eq!(ids[0].0, installed);
    let k_env = ssh_key::PublicKey::from_openssh(&p.public_key)
        .unwrap()
        .to_bytes()
        .unwrap();
    let ca = w.ca_a.public_key().to_bytes().unwrap();
    assert!(ids.iter().all(|(blob, _)| blob != &k_env && blob != &ca));
    // Grant end: the same endpoint lists nothing, and the binding is no longer the runner's.
    assert!(w.runner.issuance().destroy(&w.grant));
    assert!(list(socket).await.is_empty(), "nothing after destroy");
    assert_eq!(endpoints.runner_grant(&binding), None);
    assert!(
        endpoints
            .create(&binding, 2, &EndpointPlacement::Native)
            .is_none()
    );
    assert!(endpoints.remove(&binding, 1).unwrap());
    assert!(endpoints.endpoint(&binding).is_none());
    endpoints.stop_all();
    stop.cancel();
}

/// The dispatcher entry: only a paired controller is served, and the forms route.
#[test]
fn only_a_paired_controller_is_served() {
    let w = world();
    let local = heimdall_domain::principal::CallerContext {
        remote_client: None,
        ..World::caller(&controller_a())
    };
    let e = w
        .runner
        .handle(&local, 1, &RunnerRequest::TimeChallenge)
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::DRIVER_UNAVAILABLE));
    w.designate(&controller_a());
    let done = w
        .runner
        .handle(
            &World::caller(&controller_a()),
            1,
            &RunnerRequest::TimeChallenge,
        )
        .unwrap();
    assert_eq!(done.data["nonce"].as_str().unwrap().len(), 32);
    let prepare = RunnerRequest::PrepareRemoteGrant {
        grant: w.grant.clone(),
        grant_generation: w.generation(),
    };
    // ⟨M06 W3; ADR-0006 §18.7 item 11⟩ A session that has not read the authority report is
    // refused before any issuance check (the per-session gate); once it has, the form routes
    // to issuance, which refuses this untrusted controller.
    let e = w
        .runner
        .handle(&World::caller(&controller_a()), 1, &prepare)
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::RESYNC_PENDING));
    w.runner.note_report_served(&controller_a(), 1);
    let e = w
        .runner
        .handle(&World::caller(&controller_a()), 2, &prepare)
        .unwrap_err();
    assert_eq!(
        e.reason.as_deref(),
        Some(reason::RESYNC_PENDING),
        "the gate is per session"
    );
    let e = w
        .runner
        .handle(&World::caller(&controller_a()), 1, &prepare)
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::ISSUER_UNTRUSTED));
    let e = w
        .runner
        .handle(
            &World::caller(&controller_a()),
            1,
            &RunnerRequest::AuthorityReport,
        )
        .unwrap_err();
    assert_eq!(e.reason.as_deref(), Some(reason::DRIVER_UNAVAILABLE));
}

// --- readiness ---------------------------------------------------------------------------------

/// A runner grant's readiness: the earliest bound, the controller dependency, the three runner
/// conditions and the residuals (never a bare D).
#[test]
fn readiness_reports_the_earliest_bound_and_the_residuals() {
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let p = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, g)
        .unwrap();
    w.good_sample();
    // Certificates carry whole seconds.
    let vb = heimdall_contract::Timestamp::from_second(
        plus(w.clock.wall(), 30 * 60 * Duration::from_secs(1)).as_second(),
    )
    .unwrap();
    let cert = w.sign(&w.ca_a, &p, &pair("h1"), vb);
    w.runner
        .issuance()
        .install(&controller_a(), &w.grant, g, &cert)
        .unwrap();
    let r = w
        .runner
        .readiness(&w.grant, DestinationClock::Unmeasured, Some(vb))
        .unwrap();
    assert_eq!(r.offline_until, vb);
    assert_eq!(
        r.bound_by,
        heimdall_app::readiness::OfflineBound::CertificateValidBefore
    );
    assert_eq!(
        r.refresh_dependency,
        heimdall_contract::request::RefreshDependency::Controller
    );
    assert_eq!(
        r.lifetime,
        heimdall_contract::remote::RunnerLifetime::SessionScope
    );
    let auth = r.residuals.new_authentication.unwrap();
    assert_eq!(auth.latest_possible_credential_expiry, Some(vb));
    assert_eq!(auth.destination_clock_error, DestinationClock::Unmeasured);
    // The anchor bounds it once the controller's clock is ahead (it may stop early).
    let ahead = plus(w.clock.wall(), 100 * 60 * Duration::from_secs(1));
    w.exchange(&controller_a(), 1, Duration::from_millis(50), ahead)
        .unwrap();
    let r = w
        .runner
        .readiness(&w.grant, DestinationClock::Unmeasured, Some(vb))
        .unwrap();
    assert_eq!(r.bound_by, heimdall_app::readiness::OfflineBound::Anchor);
    assert!(r.offline_until < vb);
}

// --- A24: dependencies by construction ----------------------------------------------------------

/// The A24 row (m06-plan U3): a controller-dependent signer behind an ordinary local path is
/// reported `dependency_provenance_unknown`, with no unattended claim; the same socket
/// inherited from the management session is a `controller_dependency`; and runner work starts
/// from a clean environment that carries neither.
#[cfg(unix)]
#[test]
fn a24_a_controller_dependent_signer_behind_an_ordinary_local_path_is_unknown() {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    use heimdall_runtime::runner::launch::{
        AgentCandidate, AgentOrigin, DependencyProvenance, RunnerInventory, classify_agent,
        clean_command, inherited_agent, unattended_claim,
    };

    let dir = tempfile::tempdir().unwrap();
    // The "controller's" signer: a fixture socket that answers one byte (not an agent; no key).
    let controller_sock = dir.path().join("controller-agent.sock");
    let controller = UnixListener::bind(&controller_sock).unwrap();
    // An ordinary local path on the runner that relays to it.
    std::fs::create_dir_all(dir.path().join("home/.ssh")).unwrap();
    let relay_sock = dir.path().join("home/.ssh/agent.sock");
    let relay = UnixListener::bind(&relay_sock).unwrap();
    let target = controller_sock.clone();
    let relay_thread = std::thread::spawn(move || {
        let (mut inbound, _) = relay.accept().unwrap();
        let mut outbound = UnixStream::connect(&target).unwrap();
        let mut b = [0u8; 1];
        inbound.read_exact(&mut b).unwrap();
        outbound.write_all(&b).unwrap();
        outbound.read_exact(&mut b).unwrap();
        inbound.write_all(&b).unwrap();
    });
    let controller_thread = std::thread::spawn(move || {
        let (mut s, _) = controller.accept().unwrap();
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
        s.write_all(&[b[0] ^ 0xff]).unwrap();
    });
    // The relay really reaches the controller's socket.
    let mut c = UnixStream::connect(&relay_sock).unwrap();
    c.write_all(&[0x0f]).unwrap();
    let mut b = [0u8; 1];
    c.read_exact(&mut b).unwrap();
    assert_eq!(b[0], 0xf0);
    relay_thread.join().unwrap();
    controller_thread.join().unwrap();

    let own = dir.path().join("runner-signer.sock");
    let inventory = RunnerInventory {
        own_signer: Some(own.clone()),
        ..RunnerInventory::default()
    };
    // Named as an ordinary local path: unknown, no unattended claim.
    let candidate = AgentCandidate {
        socket: relay_sock.clone(),
        origin: AgentOrigin::Configured,
    };
    let provenance = classify_agent(&candidate, &inventory);
    assert_eq!(provenance, DependencyProvenance::Unknown);
    let e = unattended_claim(provenance).unwrap_err();
    assert_eq!(e.code, Code::CapabilityUnavailable);
    assert_eq!(
        e.reason.as_deref(),
        Some(reason::DEPENDENCY_PROVENANCE_UNKNOWN)
    );
    // Inherited by the runner's process from an SSH session: the controller's.
    let relay_str = relay_sock.clone().into_os_string();
    let parent = move |k: &str| match k {
        "SSH_AUTH_SOCK" => Some(relay_str.clone()),
        "SSH_CONNECTION" => Some("192.0.2.1 50000 192.0.2.2 22".into()),
        "HOME" => Some("/home/runner".into()),
        _ => None,
    };
    let inherited = inherited_agent(&parent).unwrap();
    assert_eq!(
        classify_agent(&inherited, &inventory),
        DependencyProvenance::ControllerDependency
    );
    assert_eq!(
        unattended_claim(DependencyProvenance::ControllerDependency)
            .unwrap_err()
            .reason
            .as_deref(),
        Some(reason::CONTROLLER_DEPENDENCY)
    );
    // The runner's own signer is claimed.
    assert_eq!(
        classify_agent(
            &AgentCandidate {
                socket: own.clone(),
                origin: AgentOrigin::Configured
            },
            &inventory
        ),
        DependencyProvenance::RunnerManaged
    );
    // Clean launch: the child sees only the inventory, never the inherited socket.
    // `/usr/bin/env` exists on every Unix this runs on (macOS, the devbox, the containers).
    let env = std::path::Path::new("/usr/bin/env");
    let out = clean_command(env, std::iter::empty::<&str>(), &inventory, &parent)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let mut keys: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
    keys.sort_unstable();
    // ⟨M06 W5⟩ The parent's HOME is not on the declared pass-list (ADR-0012 §4 item 5); the
    // launcher sets HOME, USER, LOGNAME and SHELL from the account database and, with no
    // LANG in the parent, the default LANG ("Launcher-set values" ⟨2026-11-22⟩).
    let keys: Vec<&str> = keys
        .into_iter()
        .filter(|k| *k != "__CF_USER_TEXT_ENCODING")
        .collect();
    assert_eq!(
        keys,
        [
            "HOME",
            "LANG",
            "LOGNAME",
            "PATH",
            "SHELL",
            "SSH_AUTH_SOCK",
            "USER"
        ]
    );
    assert!(!text.contains("HOME=/home/runner"));
    assert!(text.contains(&format!("SSH_AUTH_SOCK={}", own.display())));
    assert!(!text.contains("agent.sock"));
    assert!(!text.contains("SSH_CONNECTION"));
    let none = clean_command(
        env,
        std::iter::empty::<&str>(),
        &RunnerInventory::default(),
        &parent,
    )
    .output()
    .unwrap();
    assert!(
        !String::from_utf8(none.stdout)
            .unwrap()
            .contains("SSH_AUTH_SOCK")
    );
}
