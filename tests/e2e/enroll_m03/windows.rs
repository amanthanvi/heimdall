//! ⟨M03 wave 4, round 3b; W4-N01 (ADR-0008 §17.22 Sources), §17.23 item 6⟩ The binding
//! endpoint's **pipe form**, natively on Windows: the Windows equivalents of the Unix-only
//! live binding-endpoint tests (`heimdall_runtime::managed_store::live_tests`, a Unix
//! socket in a scratch runtime directory).
//!
//! Every test runs the production managed pieces of [`World`] (`ManagedCertificateAdapter`,
//! `ManagedEffectsImpl`, `SignerTable`, `EndpointRegistry` over
//! `EndpointLayout::windows`) on a pair enrolled through the real flow against the
//! harness's WSL fixture sshd, so each binding endpoint is a named pipe
//! `\\.\pipe\heimdall-<token>-b<16 hex>` (owner-only, this user's SID), and a binding
//! signs for the in-box `ssh.exe` through that pipe:
//! * [`windows_binding_endpoint_pipe_lists_and_signs_through_the_agent_protocol`]: a managed
//!   `ensure` names its binding pipe; the pipe lists exactly the grant's certificate and
//!   answers an agent-protocol sign request for a user-authentication payload of the
//!   pair (`SSH_AGENTC_SIGN_REQUEST` → `SSH_AGENT_SIGN_RESPONSE`, admitted with the permit
//!   held), and the server accepts the certificate through it;
//! * [`windows_decision_joined_follower_names_the_pipe_its_materialization_created`]
//!   (§17.23 item 6): a decision-joined follower's result names exactly the pipe its own
//!   materialization created (the registry's endpoint for its binding, reported in
//!   `MaterializedFiles.endpoint`, never derived from the leader's), and both bindings
//!   sign through their own pipes;
//! * [`windows_reissue_restores_the_binding_pipe_and_signs_with_the_new_key`] (§17.22
//!   item 5, §17.23 item 6): after a restart in the same boot the re-issue pass restores
//!   the binding's endpoint as a new pipe (the locator the registry created, read from
//!   it, never derived) whose files are at a new generation, and `ssh.exe` signs through
//!   it with the new K_env.
//!
//!
//! ⟨round 5, item 4⟩ The in-box client's host-key failure paths, for its trace row:
//! [`windows_client_trace_row_host_key_changed_observation`] and
//! [`windows_client_trace_row_host_key_unknown_observation`] (observations, not gated on
//! the row), and [`windows_verification_host_key_mismatch_holds_no_rollback`] (gated on
//! it, as every test needing a conclusive verification).
//!
//! A run without the harness fixture **fails** with that reason (`World::with`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::fx::*;
use super::managed_verified;
use heimdall_app::ports::SignerEndpoint;
use heimdall_contract::ids::{BindingId, ProfileId, RequestId, WorkId};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{EnsureData, EnsureRequest, RequiredCapabilities};
use heimdall_credential::signer::SignStep;
use heimdall_ipc::agent_client::{ClientBounds, list_identities};

/// The certificate type the binding lists (an Ed25519 K_env's certificate).
const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";

/// `\\.\pipe\heimdall-<token>-b<16 hex>`: the binding pipe form of
/// `heimdall_credential::endpoints::binding_pipe` (Unix: `<run>/b/<16 hex>/agent.sock`).
fn assert_binding_form(endpoint: &EndpointRef, why: &str) {
    if cfg!(windows) {
        assert_eq!(endpoint.kind, EndpointKind::NamedPipe, "{why}");
        let name = endpoint
            .locator
            .strip_prefix(r"\\.\pipe\heimdall-")
            .unwrap_or_else(|| panic!("{why}: not a Heimdall pipe"));
        let (token, tag) = name
            .rsplit_once("-b")
            .unwrap_or_else(|| panic!("{why}: not a binding pipe"));
        assert!(
            !token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{why}: the installation token"
        );
        assert!(
            tag.len() == 16 && tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{why}: the binding tag"
        );
    } else {
        assert_eq!(endpoint.kind, EndpointKind::UnixSocket, "{why}");
        assert!(endpoint.locator.ends_with("/agent.sock"), "{why}");
    }
}

/// The identities a binding endpoint lists, through the agent protocol on it.
async fn listed(locator: &str) -> Vec<heimdall_ipc::agent_client::AgentIdentity> {
    list_identities(&agent_locator(locator), &ClientBounds::default())
        .await
        .unwrap_or_else(|e| panic!("the binding endpoint answers a listing: {e:?}"))
        .identities
}

/// The binding's files beside `endpoint` (the locator the registry runs), for this
/// world's destination, as `connect` derives them.
fn files_of(w: &World, endpoint: &EndpointRef) -> (String, std::path::PathBuf, std::path::PathBuf) {
    let files = heimdall_adapters::managed::files::binding_files_for_endpoint(
        &w.managed().run_dir,
        endpoint,
        std::slice::from_ref(&w.destination),
    )
    .expect("the binding endpoint's files are under the runtime dir");
    let cert = files.certificate(&w.destination).unwrap().to_path_buf();
    (endpoint.locator.clone(), files.key_pub, cert)
}

/// `ssh.exe` to this world's alias through `files` (the binding's identity options as
/// `connect` renders them): the server accepts one certificate, the grant's (its key
/// ID), signed by K_env `fingerprint`; the remote command's marker comes back.
async fn ssh_through(
    w: &World,
    files: &(String, std::path::PathBuf, std::path::PathBuf),
    key_id: &str,
    fingerprint: &str,
    why: &str,
) {
    let marker = format!("hm-w4n01-{}", heimdall_testkit::agent::random_hex(6));
    let before = w.sshd.accepted_certificates().len();
    let out = w
        .managed_ssh(ALIAS, &w.sshd.host_key_line, files, &marker)
        .await;
    assert!(out.status.success(), "{why}: {}", w.why(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&marker),
        "{why}: the remote command ran"
    );
    let accepted = w.sshd.accepted_certificates();
    assert_eq!(accepted.len(), before + 1, "{why}: one login");
    let cert = accepted.last().unwrap();
    assert_eq!(cert.key_id, key_id, "{why}: the grant's certificate");
    assert_eq!(cert.fingerprint, fingerprint, "{why}: signed by K_env");
}

/// A user-authentication request of this world's pair for `cert_blob` (the data a
/// client asks the agent to sign; ADR-0008 D2 item 4): session identifier, `50`, the
/// account, `ssh-connection`, `publickey`, `TRUE`, the certificate type and blob.
fn userauth_payload(account: &str, cert_blob: &[u8]) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&u32::try_from(b.len()).unwrap().to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut session = [0u8; 32];
    for (i, b) in heimdall_testkit::agent::random_hex(32)
        .as_bytes()
        .chunks(2)
        .enumerate()
    {
        session[i] = u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap();
    }
    let mut out = Vec::new();
    put(&mut out, &session);
    out.push(50);
    put(&mut out, account.as_bytes());
    put(&mut out, b"ssh-connection");
    put(&mut out, b"publickey");
    out.push(1);
    put(&mut out, CERT_TYPE.as_bytes());
    put(&mut out, cert_blob);
    out
}

/// One agent-protocol sign request on the endpoint (the testkit's blocking client: a
/// pipe opened as a file on Windows, a socket on Unix): `(algorithm, signature)`.
async fn sign_through(locator: &str, blob: Vec<u8>, data: Vec<u8>) -> Option<(String, Vec<u8>)> {
    use heimdall_testkit::agent::{AgentConnection, Endpoint, parse_sign_response, sign_request};
    let endpoint = if cfg!(windows) {
        Endpoint::NamedPipe(locator.to_owned())
    } else {
        Endpoint::UnixSocket(std::path::PathBuf::from(locator))
    };
    tokio::task::spawn_blocking(move || {
        let mut c = AgentConnection::connect(&endpoint, Duration::from_secs(10))
            .expect("the binding endpoint accepts this user");
        let reply = c.request(&sign_request(&blob, &data, 0)).expect("a reply");
        parse_sign_response(&reply)
    })
    .await
    .unwrap()
}

/// The registry's running endpoint of `binding`.
fn running(w: &World, binding: &BindingId) -> EndpointRef {
    w.managed()
        .registry
        .binding_endpoint(binding)
        .expect("the binding endpoint runs")
        .0
}

/// The published entry of `data`'s grant (its key ID and subject).
fn published(w: &World, data: &EnsureData) -> heimdall_domain::issuance::IssuanceEntry {
    let entries = w.tx(|tx| tx.issuance_entries(&data.grant_id));
    let published: Vec<_> = entries
        .into_iter()
        .filter(|e| e.state == heimdall_domain::issuance::IssuanceState::Published)
        .collect();
    assert_eq!(published.len(), 1, "{published:?}");
    published.into_iter().next().unwrap()
}

/// W4-N01 (the Windows pipe form of `managed_ensure_names_binding_endpoint_listing_…` and
/// the binding leg of `reissue_restores_…`): a managed `ensure` over a pair enrolled
/// through the real flow names its binding endpoint, a pipe
/// `\\.\pipe\heimdall-<token>-b<tag>` the registry runs for the binding (generation 1);
/// the pipe lists exactly the grant's certificate; an agent-protocol sign request for
/// the pair's user-authentication payload is answered with an Ed25519 signature, the
/// signer having admitted it with the permit held (one `Admitted`, one `Signed`, no
/// refusal); and `ssh.exe` logs in through the pipe with that certificate.
#[tokio::test]
async fn windows_binding_endpoint_pipe_lists_and_signs_through_the_agent_protocol() {
    let w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    managed_verified(&w, "wpipe").await;
    let data = w
        .ensure_managed("wpipe")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {:?} {}", e.code, e.reason, e.message));
    let m = w.managed();
    let (endpoint, generation) = m
        .registry
        .binding_endpoint(&data.binding_id)
        .expect("the binding endpoint was created during the preparation");
    assert_eq!(generation, heimdall_domain::resource::ResourceGeneration(1));
    assert_binding_form(&endpoint, "the binding endpoint");
    assert_eq!(
        data.consumer.signing_endpoint.as_deref(),
        Some(endpoint.locator.as_str()),
        "the ensure result names the binding pipe"
    );
    let ids = listed(&endpoint.locator).await;
    assert_eq!(ids.len(), 1, "the grant's one certificate");
    assert_eq!(ids[0].key_type, CERT_TYPE);
    let entry = published(&w, &data);
    let binding = SignerEndpoint::Binding(data.binding_id.clone());
    let signed = sign_through(
        &endpoint.locator,
        ids[0].public_blob.clone(),
        userauth_payload(w.account.as_str(), &ids[0].public_blob),
    )
    .await;
    let signer = m.registry.signer(&binding).expect("the binding's signer");
    let (algorithm, signature) =
        signed.unwrap_or_else(|| panic!("a sign response; refusals {:?}", signer.refusals()));
    assert_eq!(algorithm, "ssh-ed25519");
    assert_eq!(signature.len(), 64, "an Ed25519 signature");
    assert_eq!(
        m.signs.count(&binding, SignStep::Admitted),
        1,
        "permit held"
    );
    assert_eq!(
        m.signs.count(&binding, SignStep::Signed),
        1,
        "one signature"
    );
    assert!(signer.refusals().is_empty(), "{:?}", signer.refusals());
    let files = files_of(&w, &endpoint);
    ssh_through(
        &w,
        &files,
        &entry.bounds.key_id,
        &entry.bounds.subject_fingerprint,
        "ssh through the binding pipe",
    )
    .await;
    assert_eq!(m.signs.count(&binding, SignStep::Signed), 2, "and ssh's");
}

/// §17.23 item 6 (R3C2-Q1/Q2) and W4-N01, the follower's pipe form (the Windows form of
/// `live_tests::pipeline::follower_names_exactly_the_endpoint_its_materialization_created`
/// and `decision_joined_follower_gets_its_own_materialized_binding_and_both_sign`): two
/// equivalent managed ensures needing one owner decision (a window beyond the standing
/// policy's two hours) with distinct `request_id`s join one decision; once approved, the
/// owner's ensure prepares the grant and the joined one attaches to it. The follower's
/// `consumer.signing_endpoint` and every pair's endpoint are **exactly** the pipe the
/// registry runs for the follower's own binding (what its materialization created and
/// reported), a pipe of its own (not the leader's, not derived from it); both pipes list
/// the grant's certificate, and `ssh.exe` signs through each with the one K_env.
#[tokio::test]
async fn windows_decision_joined_follower_names_the_pipe_its_materialization_created() {
    use heimdall_contract::ids::DecisionId;
    // A request may ask for up to 12 hours (as the runtime's default); the standing
    // policy covers two, so a three-hour window needs the owner's decision.
    let w = World::with(WorldOptions {
        managed: true,
        default_window: Duration::from_secs(12 * 3600),
        ..WorldOptions::default()
    })
    .await;
    managed_verified(&w, "wjoin").await;
    let start = w.clock.wall();
    let until = heimdall_contract::request::DeadlineIntent::Absolute(
        Timestamp::from_second(start.as_second() + 3 * 3600)
            .unwrap()
            .to_string(),
    );
    let ensure = |request: &'static str| {
        let until = until.clone();
        let w = &w;
        async move {
            w.ops
                .ensure(
                    &unattended(),
                    EnsureRequest {
                        profile: ProfileId::parse("dev").unwrap(),
                        profile_revision: None,
                        scope: [w.pair()].into_iter().collect(),
                        environment: None,
                        work_id: WorkId::parse("w-wjoin").unwrap(),
                        until: Some(until),
                        required_capabilities: RequiredCapabilities::default(),
                        request_id: RequestId::parse(request).unwrap(),
                        interaction: InteractionMode::Interactive,
                        wait: WaitMode::Sync { timeout_ms: 30_000 },
                        connection: None,
                    },
                )
                .await
        }
    };
    // Both requests resolve at one instant (the extra window they ask the owner for is
    // computed from it), as the live test's virtual clock gives them.
    w.clock.hold();
    let a = ensure("r-wjoin-1").await.unwrap_err();
    let b = ensure("r-wjoin-2").await.unwrap_err();
    w.clock.release();
    assert_eq!(a.code, Code::InteractionRequired, "{}", a.message);
    let decision = |e: &OpError| {
        DecisionId::parse(e.next.decision_ref.as_deref().expect("decision_ref")).unwrap()
    };
    assert_eq!(decision(&a), decision(&b), "one decision record, joined");
    w.ops
        .decide(
            &attended(),
            DecideRequest {
                decision_id: decision(&a),
                verdict: Verdict::Approve,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message));
    let ra = ensure("r-wjoin-1")
        .await
        .unwrap_or_else(|e| panic!("owner: {} {:?} {}", e.code, e.reason, e.message))
        .data;
    let rb = ensure("r-wjoin-2")
        .await
        .unwrap_or_else(|e| panic!("joined: {} {:?} {}", e.code, e.reason, e.message))
        .data;
    assert_eq!(ra.grant_id, rb.grant_id, "one grant");
    assert_ne!(ra.binding_id, rb.binding_id, "separate bindings");
    assert_eq!(
        w.managed().table.vault().len(),
        1,
        "one K_env, prepared once"
    );
    let (lead, follow) = (running(&w, &ra.binding_id), running(&w, &rb.binding_id));
    assert_ne!(lead, follow, "the follower's own pipe");
    for (data, created, who) in [(&ra, &lead, "the owner"), (&rb, &follow, "the follower")] {
        assert_binding_form(created, who);
        assert_eq!(
            data.consumer.signing_endpoint.as_deref(),
            Some(created.locator.as_str()),
            "{who}: the result names the pipe its materialization created"
        );
        assert!(!data.consumer.pairs.is_empty(), "{who}");
        assert!(
            data.consumer
                .pairs
                .iter()
                .all(|p| p.endpoint.as_ref() == Some(created)),
            "{who}: every pair names that pipe: {:?}",
            data.consumer.pairs
        );
        let ids = listed(&created.locator).await;
        assert_eq!(ids.len(), 1, "{who}: the grant's certificate");
    }
    let entry = published(&w, &ra);
    for (created, who) in [
        (&lead, "the owner's pipe"),
        (&follow, "the follower's pipe"),
    ] {
        let files = files_of(&w, created);
        ssh_through(
            &w,
            &files,
            &entry.bounds.key_id,
            &entry.bounds.subject_fingerprint,
            who,
        )
        .await;
    }
}

/// §17.22 item 5 (W4-R02), §17.23 item 6 and W4-N01, the re-issued binding's pipe form
/// (the Windows form of `live_tests::pipeline::reissue_restores_binding_endpoint_files_…`,
/// binding leg): the runtime restarts in the same boot ([`World::restart_managed`]: a new
/// vault, signer table and registry); the grant is degraded `credential_reissue_pending`
/// and its binding has no endpoint in the new process. After the re-issue pass the grant
/// is `active` with a **new** K_env, and the binding's endpoint runs again as a new pipe
/// (the locator the registry created for the restoration, read from it, never derived
/// from the old one) at a new generation; it lists the re-issued certificate, and
/// `ssh.exe` signs through it with the new key.
#[tokio::test]
async fn windows_reissue_restores_the_binding_pipe_and_signs_with_the_new_key() {
    let mut w = World::with(WorldOptions {
        managed: true,
        ..WorldOptions::default()
    })
    .await;
    managed_verified(&w, "wreis").await;
    let data = w
        .ensure_managed("wreis")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {:?} {}", e.code, e.reason, e.message));
    let before = running(&w, &data.binding_id);
    let (_, gen1) = w
        .managed()
        .registry
        .binding_endpoint(&data.binding_id)
        .unwrap();
    let old_key = w
        .managed()
        .table
        .public_key(&data.grant_id)
        .unwrap()
        .fingerprint;
    let entry = published(&w, &data);
    ssh_through(
        &w,
        &files_of(&w, &before),
        &entry.bounds.key_id,
        &old_key,
        "before the restart",
    )
    .await;
    // The restart in the same boot.
    w.restart_managed().await;
    let grant = w.tx(|tx| tx.grant(&data.grant_id)).unwrap();
    assert_eq!(grant.state, heimdall_contract::GrantState::Degraded);
    assert_eq!(
        w.tx(|tx| tx.grant_degradation(&data.grant_id)),
        Some(heimdall_domain::grant::DegradedReason::CredentialReissuePending)
    );
    assert!(
        w.managed()
            .registry
            .binding_endpoint(&data.binding_id)
            .is_none(),
        "the new process runs no endpoint for the binding before the re-issue"
    );
    // The re-issue pass.
    assert_eq!(
        w.ops.managed_reissue_pass().await.unwrap(),
        vec![data.grant_id.clone()]
    );
    assert_eq!(
        w.tx(|tx| tx.grant(&data.grant_id)).unwrap().state,
        heimdall_contract::GrantState::Active
    );
    let new_key = w
        .managed()
        .table
        .public_key(&data.grant_id)
        .unwrap()
        .fingerprint;
    assert_ne!(new_key, old_key, "a new K_env");
    let (after, gen2) = w
        .managed()
        .registry
        .binding_endpoint(&data.binding_id)
        .expect("the re-issue restored the binding's endpoint");
    assert!(gen2.0 > gen1.0, "a new generation: {gen2:?} after {gen1:?}");
    assert_binding_form(&after, "the restored binding endpoint");
    assert_ne!(
        after.locator, before.locator,
        "a new pipe, created for the restoration"
    );
    let ids = listed(&after.locator).await;
    assert_eq!(ids.len(), 1, "the re-issued certificate");
    let reissued = w
        .tx(|tx| tx.issuance_entries(&data.grant_id))
        .into_iter()
        .filter(|e| e.state == heimdall_domain::issuance::IssuanceState::Published)
        .find(|e| e.bounds.subject_fingerprint == new_key)
        .expect("a published entry for the new K_env");
    ssh_through(
        &w,
        &files_of(&w, &after),
        &reissued.bounds.key_id,
        &new_key,
        "after the re-issue",
    )
    .await;
}

/// W4-N01: **the observation** the in-box client's trace row is recorded from (as
/// `integration_enroll_verify`'s `observe_unrecorded_trace` for a Unix client). A client
/// with no row in `heimdall_enroll::trace::RECORDED` makes every verification
/// inconclusive by design, and the Windows tests that need a conclusive one fail on
/// `World::require_recorded_client` until its row is recorded from real output (the
/// in-box 9.5p2's row was recorded from this test's lines at `4866642d` and the
/// host-key observations' at `a533fc40`). This test runs one enrollment against the harness's WSL
/// sshd with an observation verifier (it parses under the first recorded row's label
/// and dumps each attempt's raw trace; its report is **no evidence of a
/// verification**), then prints every trace line a row's fields come from, and the
/// server's own log lines of the attempts, redacted, as `m03 observation:
/// client_trace_row` lines. It asserts only that both attempts ran and were dumped.
#[tokio::test]
async fn windows_client_trace_row_observation() {
    let w = World::with(WorldOptions {
        observe_trace: true,
        ..WorldOptions::default()
    })
    .await;
    let dump = w.trace_dump.clone().expect("an observation world");
    let op = w.approved(&w.spec(), "req_wobs").await;
    let result = w.drive(&op).await;
    let root = w.home.root.to_string_lossy().into_owned();
    let account = w.account.as_str().to_owned();
    let redact = |l: &str| {
        let t = l
            .replace(&root, "<scratch>")
            .replace(&root.replace('\\', "/"), "<scratch>");
        if account.len() >= 2 {
            t.replace(&account, "<user>")
        } else {
            t
        }
    };
    const MARKERS: &[&str] = &[
        "remote software version",
        "is known and matches",
        "Offering public key",
        "Server accepts key",
        "Authentications that can continue",
        "Authenticated to",
        "Permission denied",
        "Host key verification failed",
        "REMOTE HOST IDENTIFICATION HAS CHANGED",
        "host key is known for",
    ];
    let v = w.client_version;
    let family = v.family.as_str();
    let state = match &result {
        Ok(r) => format!("{:?}", r.state),
        Err(e) => format!("{} {:?}", e.code, e.reason),
    };
    #[allow(clippy::print_stderr)] // the observed facts for the client's trace row
    {
        eprintln!(
            "m03 observation: client_trace_row family={family} version={v} client={:?} \
             parsed_with={} enrollment={state}",
            w.host.version.lock().unwrap(),
            heimdall_enroll::trace::RECORDED[0].from
        );
        for which in ["positive", "negative"] {
            let text = std::fs::read(dump.join(format!("{which}.trace")))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_else(|_| panic!("the {which} attempt ran and was dumped"));
            assert!(!text.is_empty(), "the {which} attempt's trace is empty");
            for line in text.lines() {
                let line = line.trim_end_matches('\r');
                if MARKERS.iter().any(|m| line.contains(m)) {
                    eprintln!(
                        "m03 observation: client_trace_row family={family} version={v} \
                         attempt={which} line={:?}",
                        redact(line)
                    );
                }
            }
        }
        const SERVER: &[&str] = &[
            "rror",
            "efus",
            "nvalid",
            "ertificate",
            "ccepted",
            "Failed",
            "uthentication",
        ];
        // The server's own account of the attempts (from where this fixture started).
        for line in w.sshd.log_lines_containing("") {
            if SERVER.iter().any(|m| line.contains(m)) {
                eprintln!(
                    "m03 observation: client_trace_row family={family} version={v} sshd_log={:?}",
                    redact(&line)
                );
            }
        }
    }
}

// =====================================================================================
// ⟨round 5, item 4⟩ The in-box client's host-key failure paths, for its trace row
// =====================================================================================

/// The observation redaction of [`windows_client_trace_row_observation`] (the scratch
/// root, in both separator forms, and the account), and a key blob (`AAAA…`, a public
/// key's base64) masked; a canary in a line is a defect (the line is never printed).
fn observation_redactor(w: &World) -> impl Fn(&str) -> String {
    let root = w.home.root.to_string_lossy().into_owned();
    let account = w.account.as_str().to_owned();
    move |l: &str| {
        let t = l
            .replace(&root, "<scratch>")
            .replace(&root.replace('\\', "/"), "<scratch>");
        let t = if account.len() >= 2 {
            t.replace(&account, "<user>")
        } else {
            t
        };
        let t = t
            .split(' ')
            .map(|word| {
                if word.starts_with("AAAA") && word.len() >= 40 {
                    "<key>"
                } else {
                    word
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        heimdall_testkit::assert_no_canary(&t);
        t
    }
}

/// What the in-box client prints about a host key (the markers a row's
/// `host_key_failure` set is taken from; the 10.5p1 and 9.6p1 rows' strings and the
/// lines around them).
const HOST_KEY_MARKERS: &[&str] = &[
    "host key",
    "Host key",
    "HOST IDENTIFICATION",
    "known_hosts",
    "strict checking",
    "fingerprint",
];

/// Whether `line` is printed by a host-key observation: every non-debug line, and every
/// line about a host key.
fn host_key_line(line: &str) -> bool {
    !line.trim().is_empty()
        && (!line.starts_with("debug") || HOST_KEY_MARKERS.iter().any(|m| line.contains(m)))
}

/// A verified record of this world's pair whose approved host key is a fresh fixture key
/// the server does not serve, its registry line present, and the alias evaluating to
/// that approved key (the route matches: only the server's key differs, as for a host
/// whose key changed since the approval). Returns the record and the registry's bytes.
fn host_key_changed_record(w: &World) -> (heimdall_domain::enrollment::EnrollmentRecord, Vec<u8>) {
    let fake = FixtureKey::generate().public_line_without_comment();
    let (kt, kb) = {
        let mut f = fake.split_whitespace();
        (f.next().unwrap().to_owned(), f.next().unwrap().to_owned())
    };
    let mut approved = w.served_target();
    approved.host_key = raw_key(&kt, &kb).approved();
    assert_ne!(approved.host_key, w.served_target().host_key);
    let record = w.seed(
        EnrollmentState::Verified,
        EnrollmentForm::Account,
        approved,
        None,
    );
    w.sshd.append_registry_line(&w.line_of(&record)).unwrap();
    assert_eq!(w.marker_lines(), 1);
    w.target.evaluation.lock().unwrap().host_keys = vec![raw_key(&kt, &kb)];
    (record, std::fs::read(&w.registry).unwrap())
}

/// ⟨round 5, item 4⟩ **The observation** of the in-box client's **changed host key**
/// path, for its trace row's `host_key_failure` set (`heimdall_enroll::trace`'s unit
/// test requires every recorded row to have one; the 9.6p1 row's came from
/// `integration_enroll_verify`'s `verification_host_key_mismatch_holds_no_rollback`,
/// which is not built on Windows). A re-verification of a record whose approved host
/// key the server does not serve runs through the real verifier (its generated
/// known-hosts file pins the approved key) against the harness's WSL sshd, in an
/// observation world (parsed under the first recorded row's label, each attempt's raw
/// trace dumped; its outcome is **no evidence**). Every non-debug line and every
/// host-key line of both attempts is printed, redacted as the matched-path observation
/// redacts, as `m03 observation: client_trace_row … field=host_key_failure …`. It
/// asserts only that both attempts ran and were dumped, and that nothing was removed.
/// Not gated on the row (it produces it).
#[tokio::test]
async fn windows_client_trace_row_host_key_changed_observation() {
    let w = World::with(WorldOptions {
        observe_trace: true,
        ..WorldOptions::default()
    })
    .await;
    let dump = w.trace_dump.clone().expect("an observation world");
    let (record, before) = host_key_changed_record(&w);
    let result = w.verify(&record.id, "req_whk", VerifyMode::Presence).await;
    let redact = observation_redactor(&w);
    let v = w.client_version;
    let family = v.family.as_str();
    let outcome = match &result {
        Ok(c) => format!("ok {}", c.data["state"]),
        Err(e) => format!("{} {:?}", e.code, e.reason),
    };
    #[allow(clippy::print_stderr)] // the observed facts for the client's trace row
    {
        eprintln!(
            "m03 observation: client_trace_row family={family} version={v} \
             field=host_key_failure verification={outcome} state={:?}",
            w.record(&record.id).state
        );
        for which in ["positive", "negative"] {
            let text = std::fs::read(dump.join(format!("{which}.trace")))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_else(|_| panic!("the {which} attempt ran and was dumped"));
            assert!(!text.is_empty(), "the {which} attempt's trace is empty");
            for line in text.lines() {
                let line = line.trim_end_matches('\r');
                if host_key_line(line) {
                    eprintln!(
                        "m03 observation: client_trace_row family={family} version={v} \
                         field=host_key_failure attempt={which} line={:?}",
                        redact(line)
                    );
                }
            }
        }
    }
    assert_eq!(
        std::fs::read(&w.registry).unwrap(),
        before,
        "nothing removed or written"
    );
}

/// ⟨round 5, item 4⟩ **The observation** of the in-box client's **unknown host** path
/// (no key known for the host at all). The 10.5p1 row's `host_key_failure` set carries
/// this path's lines (`No ED25519 host key is known for …`); the 9.6p1 row does not (not
/// observed). The verifier always pins the approved key, so this path is the in-box
/// `ssh.exe` run directly, as an attempt runs it (`-F <scratch config>`, `-v -T`,
/// `BatchMode yes`, `StrictHostKeyChecking yes`, `HostKeyAlgorithms ssh-ed25519`, a
/// `HostKeyAlias` of the verifier's form), with empty scratch known-hosts files, no
/// agent and no public-key, password or keyboard-interactive authentication, against
/// the harness's WSL sshd. Every non-debug line and every host-key line is printed,
/// redacted, as `m03 observation: client_trace_row … field=host_key_unknown …`. It
/// asserts only that the client exited non-zero with some output. Not gated on the row.
#[tokio::test]
async fn windows_client_trace_row_host_key_unknown_observation() {
    let w = World::new().await;
    let dir = w.home.scratch().subdir("unknown-host").unwrap();
    owner_only_dir(&dir);
    let known = dir.join("known_hosts");
    let global = dir.join("global_known_hosts");
    std::fs::write(&known, b"").unwrap();
    std::fs::write(&global, b"").unwrap();
    let opt_path = heimdall_testkit::home::ssh_option_path;
    let mut cmd = tokio::process::Command::new(system_ssh());
    cmd.arg("-F")
        .arg(&w.home.user_config)
        .args(["-o", &format!("UserKnownHostsFile={}", opt_path(&known))])
        .args(["-o", &format!("GlobalKnownHostsFile={}", opt_path(&global))])
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "HostKeyAlias=hm-verify-0000000000000000",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ConnectTimeout=20",
            "-v",
            "-T",
            ALIAS,
            "true",
        ])
        .env("SSH_AUTH_SOCK", w.home.decoy_agent().endpoint().locator())
        .env("HOME", &w.home.git_home)
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .env_remove("SSH_AGENT_PID")
        .env_remove("DISPLAY")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("the client exits within 60 s")
        .expect("the client runs");
    assert!(!out.status.success(), "no host key known: refused");
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!text.is_empty(), "the client printed its trace");
    let redact = observation_redactor(&w);
    let v = w.client_version;
    let family = v.family.as_str();
    #[allow(clippy::print_stderr)] // the observed facts for the client's trace row
    {
        eprintln!(
            "m03 observation: client_trace_row family={family} version={v} \
             field=host_key_unknown exit={:?}",
            out.status.code()
        );
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if host_key_line(line) {
                eprintln!(
                    "m03 observation: client_trace_row family={family} version={v} \
                     field=host_key_unknown line={:?}",
                    redact(line)
                );
            }
        }
    }
    assert_eq!(
        std::fs::read(&known).unwrap(),
        b"",
        "strict checking added no key"
    );
}

/// ⟨round 5, item 4⟩ The Windows port of `integration_enroll_verify`'s
/// `verification_host_key_mismatch_holds_no_rollback` (D5 §6.5; §17.4 item 5): a
/// re-verification whose server host key is not the approved one ends `held`
/// (`host_key_changed`, not evidence-based) with `host_trust_changed` /
/// `enrollment_host_key_mismatch`, and nothing is rolled back: the registry is
/// byte-for-byte unchanged, no login was accepted, no removal opened. Needs the in-box
/// client's recorded trace row: **fails** `client_trace_family_unrecorded` until it is
/// recorded (never a pass, never a skip).
#[tokio::test]
async fn windows_verification_host_key_mismatch_holds_no_rollback() {
    let w = World::new().await;
    w.require_recorded_client();
    let (record, before) = host_key_changed_record(&w);
    let accepted = w.sshd.accepted_certificates().len();
    let e = w
        .verify(&record.id, "req_whm", VerifyMode::Presence)
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::HostTrustChanged, "{e:?}");
    assert_eq!(
        e.reason.as_deref(),
        Some("enrollment_host_key_mismatch"),
        "{e:?}"
    );
    let r = w.record(&record.id);
    assert_eq!(r.state, EnrollmentState::Held);
    assert_eq!(
        r.hold.map(|h| (h.reason, h.evidence_based)),
        Some((
            heimdall_domain::enrollment::HoldReason::HostKeyChanged,
            false
        ))
    );
    assert_eq!(r.target, record.target, "the approved target is kept");
    assert_eq!(
        std::fs::read(&w.registry).unwrap(),
        before,
        "no rollback: the line stays"
    );
    assert_eq!(w.marker_lines(), 1);
    assert_eq!(
        w.sshd.accepted_certificates().len(),
        accepted,
        "no login through a changed host key"
    );
    assert!(
        !w.tx(|tx| tx.open_operations())
            .iter()
            .any(|o| o.kind == OperationKind::EnrollmentRemove),
        "no removal opened"
    );
}
