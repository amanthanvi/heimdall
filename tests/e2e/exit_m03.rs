//! ⟨M03 wave 6, U13⟩ The M03 exit suite through the **real binary** (`HEIMDALL_E2E_BIN`,
//! else `CARGO_BIN_EXE_heimdall`) and its **real** `internal issuer` child, never a
//! fixture issuer (ADR-0008 §17.26 item 3; m03-plan U13 and §3 rows A07, A10, A33).
//!
//! * [`real_issuer_activation_reissue_revocation_with_fresh_logins`]: a managed
//!   activation, a re-issue and a revocation through the real issuer child, each followed
//!   by a fresh ssh login attributed by certificate key ID from the server log;
//! * [`a10_bound_consumer_issuer_reachability_recorded`]: what a same-user worker
//!   started on a managed binding can reach (ADR-0008 D12 item 6; F10), with positive
//!   controls, printed as `m03 observation: a10 <platform> <fact>` lines;
//! * [`a33_secret_bytes_scan_all_artifacts`]: a full managed flow with known secret bytes
//!   and canaries, then every artifact scanned (m03-plan §0.2).
//!
//! The scaffolding is [`world`] (reused by the A03 lock driver: pair count and servers
//! are parameters), the worker that runs under `heimdall run` is [`worker`], the process
//! and descriptor readings are [`procs`], the scan is [`scan`].
//!
//! **Platforms.** Every test is `cfg(any(unix, windows))`. Windows runs need the
//! harness's WSL fixture sshd (`HM_FIXTURE_SSHD_*`, with its enrollment registry), the
//! in-box OpenSSH client and the ConPTY console (`heimdall_testkit::console`); without the
//! fixture sshd a test fails naming it (never a skip).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    missing_docs
)]
#![cfg_attr(not(any(unix, windows)), allow(dead_code, unused_imports))]

#[path = "exit_m03/endpoints.rs"]
mod endpoints;
#[path = "exit_m03/lock.rs"]
mod lock;
#[path = "exit_m03/procs.rs"]
mod procs;
#[path = "exit_m03/scan.rs"]
mod scan;
#[path = "exit_m03/worker.rs"]
mod worker;
#[path = "exit_m03/world.rs"]
mod world;

use std::path::Path;
use std::time::Duration;

use heimdall_testkit::sshd::AcceptedCert;
use world::{World, WorldOptions, platform, take_projection_cleanups};

/// The worker's entry when this binary is re-executed under `heimdall run`
/// ([`world::World::spawn_worker`]); a no-op in the suite itself (no instructions).
#[test]
fn worker_process_entry() {
    if let Some(path) = std::env::var_os(world::WORKER_ENV) {
        worker::run(Path::new(&path));
    }
}

/// A fresh login marker.
fn marker(tag: &str) -> String {
    format!("hm-exit-{tag}-{}", heimdall_testkit::agent::random_hex(6))
}

/// The key-ID prefix of `grant`'s certificates: `heimdall:<environment>:<grant>:`.
fn key_id_prefix(w: &World, grant: &str) -> String {
    format!("heimdall:{}:{grant}:", w.environment.as_str())
}

/// Exactly one accepted certificate, of `grant`, signed by the world's CA.
fn one_cert_of(w: &World, accepted: &[AcceptedCert], grant: &str, what: &str) -> AcceptedCert {
    assert_eq!(
        accepted.len(),
        1,
        "{what}: one accepted login: {accepted:?}"
    );
    let c = accepted[0].clone();
    assert!(
        c.key_id.starts_with(&key_id_prefix(w, grant)),
        "{what}: the key ID names the grant: {} vs {grant}",
        c.key_id
    );
    assert_eq!(
        c.ca_fingerprint,
        w.ca_fingerprint.as_str(),
        "{what}: the world's CA"
    );
    c
}

/// A worker's login result, asserted successful (the remote command's marker came back).
fn assert_login_ok(w: &World, results: &[serde_json::Value], label: &str) {
    let r = worker::result(results, "login", Some(label));
    assert!(
        r["exit"] == 0 && r["marker_seen"] == true,
        "{label}: {}",
        w.redact(&r.to_string())
    );
}

/// The grant a certificate key ID names (`heimdall:<environment>:<grant>:<n>`).
fn grant_of(key_id: &str) -> String {
    key_id.split(':').nth(2).unwrap_or_default().to_owned()
}

/// ADR-0008 §17.26 item 3 (U13): one managed activation, one re-issue and one revocation
/// through the real `internal issuer` child, on this platform (the product binary holds
/// no other issuer):
/// 1. **activations**: `access ensure --profile exit` (grant A), then a worker under
///    `heimdall run` on the same work (its own ensure activates grant B; the launch bind
///    claims the pair's slot). Each grant has exactly one published issuance entry,
///    signed under the world's CA. The worker logs in fresh through the projection: the
///    server accepts exactly one certificate, whose key ID names B and whose serial is
///    B's published entry's;
/// 2. **re-issue**: the runtime process is restarted in the same boot (the trigger the
///    product supports, `World::restart_runtime`: K_env lived only in the old process;
///    the new one starts its issuer child, and its re-issue pass re-issues every
///    continuing grant through it and restores the worker's live binding). A and B are
///    `active`, each with one more published entry (a new serial), and the worker's next
///    fresh login is accepted with B's **new certificate**: the same grant, a new serial,
///    a new K_env;
/// 3. **revocation**: `access revoke B`; the worker's next fresh login is refused, a
///    fresh login through the projection alone is refused, and the server log shows no
///    accepted line for any of B's key IDs (none at all) after the revocation.
#[cfg(any(unix, windows))]
#[test]
fn real_issuer_activation_reissue_revocation_with_fresh_logins() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        ..WorldOptions::default()
    });
    drop(ca);
    let work = "exit-work-lifecycle";
    // 1. The activations.
    let a = w.ensure(work, "exit-ensure-1")["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(w.published(&a).len(), 1, "A's certificate was signed");
    let sig = w.subdir("sig");
    let (s1, g1, s2, g2) = (
        sig.join("s1"),
        sig.join("g1"),
        sig.join("s2"),
        sig.join("g2"),
    );
    let (m1, m2, m3) = (marker("first"), marker("second"), marker("revoked"));
    let mark1 = w.pairs[0].sshd.log_mark();
    let mut wk = w.spawn_worker(
        work,
        "exit-run-1",
        vec![
            worker::login("first", &w.login_command(0, &m1), &m1),
            worker::signal(&s1),
            worker::wait(&g1, Duration::from_secs(180)),
            worker::login("second", &w.login_command(0, &m2), &m2),
            worker::signal(&s2),
            worker::wait(&g2, Duration::from_secs(180)),
            worker::login("after_revoke", &w.login_command(0, &m3), &m3),
        ],
    );
    let results = wk.wait_signal(&s1, Duration::from_secs(120));
    assert_login_ok(&w, &results, "first");
    let accepted = w.accepted_since(0, mark1);
    let b = grant_of(
        &accepted
            .first()
            .map(|c| c.key_id.clone())
            .unwrap_or_default(),
    );
    let first = one_cert_of(&w, &accepted, &b, "the activation's login");
    assert_ne!(b, a, "the worker's ensure activated its own grant");
    assert_eq!(w.grant_state(&b), "active");
    let published_b = w.published(&b);
    assert_eq!(published_b.len(), 1, "B's certificate was signed");
    assert_eq!(
        published_b[0].0, first.serial,
        "the login used B's certificate"
    );
    let prefix = key_id_prefix(&w, &b);

    // 2. The re-issue (a runtime restart in the same boot), then the second fresh login.
    w.restart_runtime();
    // A and B `active` again, each with one more signed certificate.
    w.wait_reissued(&[&a, &b], 2);
    let mark2 = w.pairs[0].sshd.log_mark();
    std::fs::write(&g1, b"").unwrap();
    let results = wk.wait_signal(&s2, Duration::from_secs(120));
    assert_login_ok(&w, &results, "second");
    let second = one_cert_of(&w, &w.accepted_since(0, mark2), &b, "the re-issue's login");
    assert_ne!(second.serial, first.serial, "a new certificate (serial)");
    assert!(
        w.published(&b).iter().any(|e| e.0 == second.serial),
        "the login used B's re-issued certificate"
    );
    assert_ne!(
        second.fingerprint, first.fingerprint,
        "a new K_env (the old one lived only in the stopped runtime)"
    );

    // 3. The revocation, then the refused fresh logins.
    let mark3 = w.pairs[0].sshd.log_mark();
    w.revoke(&b, "exit-revoke-1");
    assert_ne!(w.grant_state(&b), "active", "revoked");
    std::fs::write(&g2, b"").unwrap();
    let out = wk.finish(Duration::from_secs(120));
    w.record_bytes("worker (stdout)", out.stdout.as_bytes());
    w.record_bytes("worker (stderr)", out.stderr.as_bytes());
    let r = worker::result(&out.results, "login", Some("after_revoke"));
    assert!(
        r["exit"] != 0 && r["marker_seen"] == false,
        "the revoked grant's binding logs in no more: {}",
        w.redact(&r.to_string())
    );
    let alone = w.projection_login(0, &marker("alone"));
    assert_ne!(
        alone.code,
        0,
        "the projection alone: {}",
        w.redact(&alone.stderr)
    );
    let after = w.accepted_since(0, mark3);
    assert!(
        after.iter().all(|c| !c.key_id.starts_with(&prefix)),
        "no accepted line for the revoked grant after the revocation: {after:?}"
    );
    assert!(after.is_empty(), "no login at all was accepted: {after:?}");
    // ⟨M03 wave 6; the orchestrator's ruling on I-3⟩ ADR-0005 §3.4: each certificate's key ID
    // is `heimdall:<env>:<grant>:<serial>`, so the re-issue has a new key ID ending in its new
    // serial (the pair ordinal it once carried stayed `…:1` across re-issues).
    for (what, c) in [("activation", &first), ("re-issue", &second)] {
        assert_eq!(
            c.key_id,
            format!("{prefix}{}", c.serial),
            "the {what} certificate's key ID ends in its own serial"
        );
    }
    assert_ne!(second.key_id, first.key_id, "the re-issue has a new key ID");
    let suffix = "serial";
    println!(
        "m03 observation: issuer_child {} activation=signed_and_login_accepted reissue=signed_and_login_accepted revocation=login_refused reissue_trigger=runtime_restart_same_boot key_id_last_field={suffix}",
        platform()
    );
}

/// The policy window of [`managed_revoke_reaches_revoked_once_the_residual_passes`]'s
/// grant, and so its certificate's validity (`valid_before` is the grant's deadline).
const SHORT_WINDOW: Duration = Duration::from_secs(90);

/// E5 (ruling I-12; ADR-0008 D7 items 2–3, §17.15) through the real binary: a managed
/// grant whose certificate is valid for [`SHORT_WINDOW`] is revoked. It reads `revoking`,
/// and its pending record holds one `bounded_by_expiry` obligation for its pair, with the
/// certificate's `valid_before` (the world's enrollment has no clock measurement, so
/// `unmeasured`). Once that has passed, the runtime's supervisor moves the grant to
/// `revoked` with no further adapter round (the record's round count is unchanged), never
/// earlier. The record is kept with the obligation `nominally_expired`: it is never shown
/// as cleared.
#[cfg(any(unix, windows))]
#[test]
fn managed_revoke_reaches_revoked_once_the_residual_passes() {
    use heimdall_contract::managed::{DestinationClock, ResidualStatus};
    use heimdall_domain::revocation::{ObligationKind, PendingRemoteRevocation};
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        per_pair_profiles: true,
        pair_policy_windows: vec![SHORT_WINDOW],
        ..WorldOptions::default()
    });
    drop(ca);
    let g = w.ensure_on(
        &w.profile_of(0),
        "exit-work-residual",
        "exit-ensure-residual",
    )["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let gid = heimdall_contract::ids::GrantId::parse(&g).unwrap();
    let record = || -> Option<PendingRemoteRevocation> {
        w.open_store()
            .transaction(|tx| tx.remote_revocation(&gid))
            .unwrap()
    };
    let lvb = w
        .open_store()
        .transaction(|tx| tx.issuance_entries(&gid))
        .unwrap()
        .into_iter()
        .filter(|e| e.state != heimdall_domain::issuance::IssuanceState::Voided)
        .map(|e| e.bounds.valid_before)
        .max()
        .expect("the grant's certificate was signed");
    w.revoke(&g, "exit-revoke-residual");
    assert!(
        heimdall_contract::Timestamp::now() < lvb,
        "revoked before the certificate's valid_before"
    );
    assert_eq!(w.grant_state(&g), "revoking", "the residual is pending");
    let kinds = |r: &PendingRemoteRevocation| -> Vec<
        Option<(
            heimdall_contract::Timestamp,
            DestinationClock,
            ResidualStatus,
        )>,
    > {
        r.obligations
            .iter()
            .map(|o| match &o.kind {
                ObligationKind::BoundedByExpiry {
                    latest_valid_before,
                    clock,
                    status,
                } => Some((*latest_valid_before, *clock, *status)),
                _ => None,
            })
            .collect()
    };
    let at_revoke = record().expect("a pending record");
    assert_eq!(
        kinds(&at_revoke),
        [Some((
            lvb,
            DestinationClock::Unmeasured,
            ResidualStatus::PendingUntil
        ))],
        "one bounded obligation for the pair"
    );
    let limit = lvb.checked_add(Duration::from_secs(120)).unwrap();
    loop {
        let state = w.grant_state(&g);
        let now = heimdall_contract::Timestamp::now();
        if state == "revoked" {
            assert!(now >= lvb, "revoked before the residual passed");
            break;
        }
        assert_eq!(state, "revoking");
        assert!(
            now < limit,
            "still revoking {} s after the certificate's valid_before",
            now.duration_since(lvb).as_secs()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let kept = record().expect("kept: a nominally expired obligation (§17.15)");
    assert_eq!(
        kinds(&kept),
        [Some((
            lvb,
            DestinationClock::Unmeasured,
            ResidualStatus::NominallyExpired
        ))]
    );
    assert_eq!(
        kept.attempts, at_revoke.attempts,
        "no adapter round after it"
    );
    println!(
        "m03 observation: managed_revoke_residual {} certificate_validity_s={} state_at_revoke=revoking state_after_residual=revoked obligation=bounded_by_expiry clock=unmeasured status=nominally_expired record_kept=true rounds_after_revoke=0",
        platform(),
        SHORT_WINDOW.as_secs()
    );
}

/// ⟨M03 wave 6, W6-R01⟩ A failure injected right after `setup apply` (as a failing or
/// time-limited `time confirm` would) unwinds the preparation, and the world's owned
/// rollback runs as it is dropped: the projection is rolled back and the restoration
/// verified (the scratch home then removed), or, when the rollback fails, the scratch home
/// holding the projection's state and backups is kept and the failure reported, never
/// deleted. (The A03 lock driver's Windows product configuration owns the same rollback.)
#[test]
fn projection_rolled_back_or_recovery_kept_after_a_failure_after_apply() {
    let failing = |fail_rollback: bool| {
        let _ = take_projection_cleanups();
        let unwound = std::panic::catch_unwind(|| {
            World::start(WorldOptions {
                pairs: 1,
                own_projection_rollback: true,
                fail_after_apply: true,
                fail_rollback,
                ..WorldOptions::default()
            })
        });
        assert!(
            unwound.is_err(),
            "the injected failure unwinds the preparation"
        );
        let mut reports = take_projection_cleanups();
        assert_eq!(reports.len(), 1, "one owned rollback ran: {reports:?}");
        reports.remove(0)
    };
    // Rolled back and verified; nothing kept.
    let done = failing(false);
    assert!(
        matches!(&done.result, Ok(t) if t.contains("restoration verified")),
        "{:?}",
        done.result
    );
    assert!(
        !done.root.exists(),
        "the scratch home is removed after a verified rollback"
    );
    // The rollback fails: the recovery state is kept and the failure reported.
    let kept = failing(true);
    assert!(
        matches!(&kept.result, Err(t) if t.contains("kept for recovery")),
        "{:?}",
        kept.result
    );
    assert!(
        kept.root.exists(),
        "the recovery state is kept, never deleted"
    );
    let projected = std::fs::read_to_string(kept.root.join("home").join(".ssh").join("config"))
        .unwrap_or_default();
    assert!(
        projected.to_ascii_lowercase().contains("heimdall")
            || projected.contains(&*kept.root.join("hh").to_string_lossy()),
        "the projection was applied and is still there to recover"
    );
    // This test's own scratch (the kept recovery state), removed by its exact path.
    std::fs::remove_dir_all(&kept.root).unwrap();
}

/// A10, U13 (ADR-0008 D12 item 6; F10): what a same-user worker started on a managed
/// binding can reach, recorded per platform with positive controls. The worker runs under
/// `heimdall run` on the profile's managed binding, logs in once (its grant's
/// certificate, attributed by key ID), reads its own descriptors and lists the endpoints
/// it was given; meanwhile this test reads the runtime's side. Each fact is printed as
/// one `m03 observation: a10 <platform> <fact>` line; a fact this platform cannot show is
/// printed `unobservable: <why>` and asserted nowhere. Asserted:
/// * **no issuer path:** the runtime's endpoints are its control and environment
///   endpoints and the live bindings' endpoints only, never the issuer path the IPC
///   layer reserves (`<run>/issuer.sock`, `\\.\pipe\heimdall-<token>-issuer`) or any other;
///   on Unix the issuer child holds no socket at all (it talks only over its inherited
///   pipes; control: the runtime's sockets are seen by the same reading);
/// * **no CA key listed on any endpoint:** every agent endpoint (the environment
///   endpoint and each binding's), listed from this test and from the worker, lists no
///   identity that is the CA key (control: the worker's binding endpoint lists exactly
///   its grant's certificate, key ID and serial decoded);
/// * **Unix: no issuer pipe descriptor in a runtime-spawned process**, on exact PIDs: the
///   issuer pipes are identified from the issuer child's descriptors 0 and 1 (Linux: the
///   pipe inode; macOS: both ends' addresses); the worker and every other child of the
///   runtime hold none of them (controls: the runtime holds both issuer pipes' other ends;
///   the worker's stdout is identified as the pipe this test gave it);
/// * **no K_ca bytes** in any artifact ([`scan::artifacts`]).
///
/// The platform's store row: Windows, whether the worker can read the CA's DPAPI item
/// through the product store (control: it reads a scratch test item); macOS and Linux
/// record why the row is not observable on this run's store.
#[cfg(any(unix, windows))]
#[test]
fn a10_bound_consumer_issuer_reachability_recorded() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        ..WorldOptions::default()
    });
    let needles = [scan::k_ca(&ca)];
    drop(ca);
    let os = platform();
    let say = |fact: &str| println!("m03 observation: a10 {os} {fact}");
    let signing = w.instance()["signing_endpoint"]
        .as_str()
        .unwrap()
        .to_owned();
    // Windows: a scratch DPAPI test item for the worker's positive control.
    #[cfg(windows)]
    let control_item = {
        use heimdall_issuer::store::SecretStore as _;
        let dir = w.hh.join("control-dpapi");
        std::fs::create_dir(&dir).unwrap();
        let key = heimdall_credential::cert::SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        heimdall_issuer::store::WindowsDpapi::in_dir(&dir, &w.environment)
            .put(&fp, &key)
            .unwrap();
        (dir, fp)
    };
    let sig = w.subdir("sig");
    let (ready, go) = (sig.join("ready"), sig.join("go"));
    let m = marker("a10");
    let mut tasks = vec![
        worker::login("bound", &w.login_command(0, &m), &m),
        worker::fds(),
        worker::agent_list("binding", None),
        worker::agent_list("environment", Some(&signing)),
    ];
    #[cfg(windows)]
    {
        tasks.push(worker::dpapi(
            "ca",
            w.store.dir(),
            w.environment.as_str(),
            w.ca_fingerprint.as_str(),
        ));
        tasks.push(worker::dpapi(
            "control",
            &control_item.0,
            w.environment.as_str(),
            control_item.1.as_str(),
        ));
    }
    tasks.extend([
        worker::signal(&ready),
        worker::wait(&go, Duration::from_secs(180)),
    ]);
    let mark = w.pairs[0].sshd.log_mark();
    let mut wk = w.spawn_worker("exit-work-a10", "exit-a10-run", tasks);
    let results = wk.wait_signal(&ready, Duration::from_secs(120));
    assert_login_ok(&w, &results, "bound");
    let accepted = w.accepted_since(0, mark);
    let grant = grant_of(
        &accepted
            .first()
            .map(|c| c.key_id.clone())
            .unwrap_or_default(),
    );
    let cert = one_cert_of(&w, &accepted, &grant, "the worker's login");

    // 1. No issuer path.
    let eps = endpoints::of(&w);
    let count = |c: endpoints::Class| eps.iter().filter(|e| e.class == c).count();
    assert_eq!(
        count(endpoints::Class::Issuer),
        0,
        "{}",
        endpoints::summary(&eps)
    );
    assert_eq!(
        count(endpoints::Class::Other),
        0,
        "{}",
        endpoints::summary(&eps)
    );
    assert_eq!(
        count(endpoints::Class::Control),
        1,
        "{}",
        endpoints::summary(&eps)
    );
    assert_eq!(
        count(endpoints::Class::Environment),
        1,
        "{}",
        endpoints::summary(&eps)
    );
    assert!(
        count(endpoints::Class::Binding) >= 1,
        "{}",
        endpoints::summary(&eps)
    );
    say(&format!(
        "issuer_path none (endpoints: {}; control: the worker's live binding endpoint is among them)",
        endpoints::summary(&eps)
    ));
    let rt = w.runtime_pid();
    #[cfg(unix)]
    let issuer = procs::issuer_child(rt).expect("the runtime has exactly one issuer child");
    #[cfg(unix)]
    match (procs::fds_of(issuer), procs::fds_of(rt)) {
        (Ok(child), Ok(runtime)) => {
            let sockets =
                |f: &[procs::Fd]| f.iter().filter(|d| d.kind == procs::FdKind::Socket).count();
            assert_eq!(
                sockets(&child),
                0,
                "the issuer child holds no socket: {child:?}"
            );
            assert!(
                sockets(&runtime) >= 2,
                "control: the runtime's listeners are seen: {runtime:?}"
            );
            say(&format!(
                "issuer_child_sockets 0 (control: the runtime holds {} sockets by the same reading)",
                sockets(&runtime)
            ));
        }
        (Err(why), _) | (_, Err(why)) => {
            say(&format!("issuer_child_sockets unobservable: {why}"));
            // Linux: the namespace's bound Unix sockets instead (any user reads them).
            #[cfg(target_os = "linux")]
            {
                let names = procs::unix_socket_names().unwrap();
                let hh = w.hh.to_string_lossy().into_owned();
                let ours: std::collections::BTreeSet<&str> = names
                    .iter()
                    .map(String::as_str)
                    .filter(|n| n.starts_with(&hh))
                    .collect();
                let known: std::collections::BTreeSet<&str> =
                    eps.iter().map(|e| e.locator.as_str()).collect();
                let issuerish = names
                    .iter()
                    .filter(|n| {
                        n.contains("issuer") || (n.starts_with('@') && n.contains("heimdall"))
                    })
                    .count();
                assert_eq!(issuerish, 0, "no bound socket names an issuer");
                assert_eq!(
                    ours, known,
                    "control: the bound sockets under the Heimdall home are exactly its endpoints"
                );
                say(&format!(
                    "bound_unix_sockets_naming_issuer 0 (the namespace's sockets bound under the Heimdall home are exactly its {} endpoints; control: the runtime's listeners are listed)",
                    ours.len()
                ));
            }
        }
    }
    #[cfg(windows)]
    say(
        "issuer_child_sockets unobservable: another process's handles are not listed without privilege",
    );

    // 2. No CA key listed on any endpoint; the binding endpoint lists its grant's
    // certificate.
    let mut listed_eps = 0;
    let mut ca_listed = 0;
    for e in eps.iter().filter(|e| {
        matches!(
            e.class,
            endpoints::Class::Environment | endpoints::Class::Binding
        )
    }) {
        let ids = endpoints::list(&e.locator).unwrap_or_else(|code| {
            panic!(
                "the {} endpoint answers as an agent (ssh-add exit {code})",
                e.class.name()
            )
        });
        listed_eps += 1;
        ca_listed += ids
            .iter()
            .filter(|l| endpoints::is_ca(l, &w.ca_public))
            .count();
    }
    let mut worker_ca = 0;
    let mut binding_certs = Vec::new();
    for label in ["binding", "environment"] {
        let r = worker::result(&results, "agent_list", Some(label));
        let lines: Vec<String> = r["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_owned())
            .collect();
        let ids = endpoints::parse_listing(
            i32::try_from(r["exit"].as_i64().unwrap()).unwrap(),
            &lines.join("\n"),
        )
        .unwrap_or_else(|code| panic!("the worker's {label} endpoint answers (exit {code})"));
        worker_ca += ids
            .iter()
            .filter(|l| endpoints::is_ca(l, &w.ca_public))
            .count();
        if label == "binding" {
            binding_certs = ids.iter().filter_map(endpoints::cert_key_id).collect();
        }
    }
    assert_eq!(ca_listed + worker_ca, 0, "no endpoint lists the CA key");
    assert_eq!(
        binding_certs,
        vec![(cert.key_id.clone(), cert.serial)],
        "control: the binding endpoint lists exactly its grant's certificate"
    );
    say(&format!(
        "ca_key_listed 0 (agent endpoints listed: {listed_eps} from the test, 2 from the worker; control: the worker's binding endpoint lists exactly its grant's certificate, key ID and serial)"
    ));

    // 3. Unix: no issuer pipe descriptor in a runtime-spawned process.
    #[cfg(unix)]
    {
        let r = worker::result(&results, "fds", None);
        let worker_fds: Vec<procs::Fd> = r["fds"]
            .as_array()
            .unwrap_or_else(|| panic!("the worker read its descriptors: {r}"))
            .iter()
            .map(procs::Fd::from_json)
            .collect();
        let given = |fd: i64, id: u64| {
            worker_fds
                .iter()
                .any(|f| f.fd == fd && f.kind == procs::FdKind::Pipe && f.ids.contains(&id))
        };
        assert!(
            given(1, wk.stdout_identity) && given(2, wk.stderr_identity),
            "control: the worker's stdout and stderr are the pipes this test gave it: {worker_fds:?}"
        );
        assert!(
            worker_fds.iter().any(|f| f.fd == 0),
            "control: the worker sees its stdin: {worker_fds:?}"
        );
        let others: Vec<procs::Proc> = procs::processes()
            .into_iter()
            .filter(|p| p.ppid == rt && p.pid != issuer)
            .collect();
        match (procs::fds_of(issuer), procs::fds_of(rt)) {
            (Ok(child), Ok(runtime)) => {
                let issuer_pipes = procs::pipe_ids(
                    &child
                        .iter()
                        .filter(|f| f.fd == 0 || f.fd == 1)
                        .cloned()
                        .collect::<Vec<_>>(),
                );
                assert!(
                    !issuer_pipes.is_empty(),
                    "the issuer's stdin and stdout are pipes: {child:?}"
                );
                let held = runtime
                    .iter()
                    .filter(|f| {
                        f.kind == procs::FdKind::Pipe
                            && f.ids.iter().any(|i| issuer_pipes.contains(i))
                    })
                    .count();
                assert_eq!(
                    held, 2,
                    "control: the runtime holds both issuer pipes' other ends"
                );
                let in_worker = procs::pipe_ids(&worker_fds)
                    .intersection(&issuer_pipes)
                    .count();
                let mut in_others = 0;
                for p in &others {
                    if let Ok(f) = procs::fds_of(p.pid) {
                        in_others += procs::pipe_ids(&f).intersection(&issuer_pipes).count();
                    }
                }
                assert_eq!(in_worker, 0, "the worker holds no issuer pipe");
                assert_eq!(in_others, 0, "no other runtime child holds an issuer pipe");
                say(&format!(
                    "issuer_pipe_descriptors 0 (exact PIDs checked: the bound worker and {} other runtime children; controls: the runtime holds both issuer pipes' other ends, the worker's stdout and stderr are identified as the pipes it was given)",
                    others.len()
                ));
            }
            (Err(why), _) | (_, Err(why)) => {
                // The issuer pipes' identities cannot be read here; the worker holds no
                // pipe but the two this test gave it, so it holds none of the issuer's.
                let unaccounted: Vec<&procs::Fd> = worker_fds
                    .iter()
                    .filter(|f| {
                        f.kind == procs::FdKind::Pipe
                            && !f
                                .ids
                                .iter()
                                .any(|i| *i == wk.stdout_identity || *i == wk.stderr_identity)
                    })
                    .collect();
                assert!(
                    unaccounted.is_empty(),
                    "the worker holds only the pipes this test gave it: {unaccounted:?}"
                );
                say(&format!(
                    "issuer_pipe_descriptors 0 (the bound worker holds no pipe but the stdout and stderr this test gave it, so none of the issuer's; {} other runtime children, not comparable; the issuer pipes' identities are unobservable here: {why})",
                    others.len()
                ));
            }
        }
    }
    #[cfg(windows)]
    say(
        "issuer_pipe_descriptors unobservable: the descriptor check is Unix-only (m03-plan U13); another process's handles are not listed without privilege",
    );

    // 4. The platform's store row.
    #[cfg(windows)]
    {
        let control = worker::result(&results, "dpapi", Some("control"));
        assert!(
            control["read"] == true && control["matches"] == true,
            "control: the worker reads a scratch DPAPI test item: {control}"
        );
        let ca_item = worker::result(&results, "dpapi", Some("ca"));
        let yes = ca_item["read"] == true && ca_item["matches"] == true;
        say(&format!(
            "worker_reads_ca_dpapi_item {} (control: the worker read a scratch DPAPI test item)",
            if yes { "yes" } else { "no" }
        ));
    }
    #[cfg(target_os = "macos")]
    say(
        "keychain_item_reading unobservable: this run's issuer store is the fixture scratch store, not a keychain item (the product keychain row needs a disposable account, B3)",
    );
    #[cfg(target_os = "linux")]
    say("secret_service_item_reading unobservable: no disposable Secret Service on this run (B11)");

    // 5. No K_ca bytes in the artifacts.
    #[cfg(unix)]
    let pids = vec![
        ("runtime", rt),
        ("issuer child", issuer),
        ("worker", wk.pid()),
    ];
    #[cfg(windows)]
    let pids = {
        let mut p = vec![("runtime", rt), ("worker", wk.pid())];
        if let Some(i) = procs::issuer_child(rt) {
            p.push(("issuer child", i));
        }
        p
    };
    let mut hits = Vec::new();
    let scanned = scan::artifacts(&w, &needles, &pids, &[], &mut hits);
    std::fs::write(&go, b"").unwrap();
    let out = wk.finish(Duration::from_secs(120));
    assert_eq!(out.code, 0, "the worker: {}", w.redact(&out.stderr));
    assert!(
        hits.is_empty(),
        "K_ca bytes found: {}",
        scan::describe(&hits)
    );
    // ⟨W6-R04⟩ No unread artifact is counted as scanned.
    assert!(
        scanned.not_scanned.is_empty(),
        "artifacts that exist but could not be read (incomplete coverage): {:?}",
        scanned.not_scanned
    );
    let control = scan::public_control(&w);
    assert!(
        control >= 1,
        "control: the scan finds the CA's public blob in the Heimdall home"
    );
    say(&format!(
        "k_ca_bytes 0 ({}; control: the CA public blob found in {control} Heimdall-home files)",
        scanned.summary()
    ));
    for u in &scanned.unobservable {
        say(&format!("k_ca_bytes unobservable: {u}"));
    }
    say("issuer_isolation same_user_process: the boundary is the OS user");
}

/// The variable the A33 canary is placed in (unrelated to Heimdall; every process the
/// world starts has it, so the runtime and its issuer child inherit it).
const CANARY_VAR: &str = "HM_EXIT_M03_UNRELATED";

/// The seeded index (below [`scan::K_ENV_INDICES`]) of every published certificate's
/// subject key of `grants`, computed by the product's own seeded vault
/// (`KeyVault::with_test_seed`); `None` for a key no seeded index gives.
fn seeded_indices(w: &World, seed: &[u8], grants: &[&str]) -> Vec<Option<u64>> {
    let vault = heimdall_credential::vault::KeyVault::with_test_seed(seed).unwrap();
    let seeded: Vec<String> = (0..scan::K_ENV_INDICES)
        .map(|_| vault.generate_ed25519().unwrap().1.fingerprint)
        .collect();
    grants
        .iter()
        .flat_map(|g| {
            let gid = heimdall_contract::ids::GrantId::parse(g).unwrap();
            w.open_store()
                .transaction(|tx| tx.issuance_entries(&gid))
                .unwrap()
        })
        .filter(|e| e.state == heimdall_domain::issuance::IssuanceState::Published)
        .map(|e| {
            seeded
                .iter()
                .position(|f| *f == e.bounds.subject_fingerprint)
                .map(|i| u64::try_from(i).unwrap())
        })
        .collect()
}

/// A33, U13 (m03-plan §0.2): a full managed flow with known secret bytes, then every
/// artifact scanned at three checkpoints. The secrets: the seeded K_env
/// (`HEIMDALL_TEST_KEY_SEED`, random per run), the test K_ca (its private seed and
/// field, raw, hex and base64, and its OpenSSH encoding) and canaries
/// (`HEIMDALL_CANARY_<random>` in an unrelated variable of every process the world starts,
/// and the fake adapter's own canary credential reference, reached by an existing-access
/// ensure of the fixture profile `ops`). The flow: the activation, an existing-access
/// ensure, a worker's fresh login, the re-issue (a runtime restart) and a second login,
/// a doctor report (JSON and human), the events and operations reads, the revocation and
/// a refused login. At each checkpoint ([`scan::artifacts`]): every output the binary
/// printed (envelopes, errors, the doctor report, events, the worker's streams), every
/// file under the Heimdall home (the state database and journal, the runtime and data
/// directories, the log, the rendered managed configuration), the account's `.ssh`, the
/// worker records, the crash-artifact locations, and the argument vector and environment
/// of every process the run started that is still alive (the runtime, its issuer child,
/// the worker, the servers) as far as the platform shows them; what it cannot show is
/// printed `unobservable`. A hit is reported by kind and offset only, never the bytes.
/// No ceremony runs, so no D5 passphrase exists in this flow. One stated exception: the
/// fake adapter's canary-named credential reference inside an effect receipt's
/// `credential_ref` field of the state database, which records it by design
/// (`scan::neutralize_receipt_refs`; counted and printed, never in an output).
///
/// Controls: the CA's public blob is found in the Heimdall home by the same reading; on
/// Linux the environment reading sees the placed canary in its variable (that one entry
/// is the only place it may be); every published certificate's subject key (the
/// activations' and the re-issues') is one of the seeded K_env the scan looks for
/// ([`seeded_indices`]), so the scanned K_env bytes are the runtime's real keys.
#[cfg(any(unix, windows))]
#[test]
fn a33_secret_bytes_scan_all_artifacts() {
    let canary = format!(
        "{}EXIT_{}",
        heimdall_testkit::CANARY_PREFIX,
        heimdall_testkit::agent::random_hex(12)
    );
    let hex = heimdall_testkit::agent::random_hex(32);
    let seed: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    assert_eq!(seed.len(), 32);
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        key_seed: Some(seed.clone()),
        extra_env: vec![(CANARY_VAR.to_owned(), canary.clone())],
        ..WorldOptions::default()
    });
    let needles = [
        scan::k_env(&seed),
        scan::k_ca(&ca),
        scan::canaries(std::slice::from_ref(&canary)),
    ];
    drop(ca);
    let placed = [format!("{CANARY_VAR}={canary}")];
    let os = platform();
    let mut hits = Vec::new();
    let mut checkpoints = Vec::new();
    let mut unobservable = std::collections::BTreeSet::new();
    let mut placed_seen = 0;
    let mut receipt_refs = 0;
    let servers: Vec<u32> = w.pairs.iter().filter_map(|p| p.sshd.pid()).collect();
    let mut checkpoint = |w: &World, name: &str, worker: Option<u32>, hits: &mut Vec<scan::Hit>| {
        let rt = w.runtime_pid();
        let mut pids = vec![("runtime", rt)];
        if let Some(i) = procs::issuer_child(rt) {
            pids.push(("issuer child", i));
        }
        if let Some(p) = worker {
            pids.push(("worker", p));
        }
        for p in &servers {
            pids.push(("fixture server", *p));
        }
        let before = hits.len();
        let s = scan::artifacts(w, &needles, &pids, &placed, hits);
        for h in &mut hits[before..] {
            h.artifact = format!("{name}: {}", h.artifact);
        }
        placed_seen += s.placed_seen;
        receipt_refs = receipt_refs.max(s.receipt_refs);
        unobservable.extend(s.unobservable.clone());
        // ⟨W6-R04⟩ Every listed artifact was read: an unreadable file or directory is
        // incomplete coverage, never a clean scan.
        assert!(
            s.not_scanned.is_empty(),
            "{name}: artifacts that exist but could not be read (incomplete coverage): {:?}",
            s.not_scanned
        );
        checkpoints.push(format!("{name} [{}]", s.summary()));
    };

    // The activation, and an existing-access ensure through the fake adapter (its
    // credential reference carries the adapter's own canary).
    let work = "exit-work-a33";
    let a = w.ensure(work, "exit-a33-ensure")["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let ops = w.cli(&[
        "--json",
        "access",
        "ensure",
        "--profile",
        "ops",
        "--work-id",
        "exit-a33-ops",
        "--request-id",
        "exit-a33-ops",
    ]);
    assert_eq!(
        ops.code,
        0,
        "the existing-access ensure: {}",
        w.redact(&format!("{ops:?}"))
    );

    let sig = w.subdir("sig");
    let (s1, g1, s2, g2) = (
        sig.join("s1"),
        sig.join("g1"),
        sig.join("s2"),
        sig.join("g2"),
    );
    let (m1, m2, m3) = (marker("a33a"), marker("a33b"), marker("a33c"));
    let mark1 = w.pairs[0].sshd.log_mark();
    let mut wk = w.spawn_worker(
        work,
        "exit-a33-run",
        vec![
            worker::login("first", &w.login_command(0, &m1), &m1),
            worker::signal(&s1),
            worker::wait(&g1, Duration::from_secs(180)),
            worker::login("second", &w.login_command(0, &m2), &m2),
            worker::signal(&s2),
            worker::wait(&g2, Duration::from_secs(180)),
            worker::login("after_revoke", &w.login_command(0, &m3), &m3),
        ],
    );
    let results = wk.wait_signal(&s1, Duration::from_secs(120));
    assert_login_ok(&w, &results, "first");
    let accepted = w.accepted_since(0, mark1);
    let b = grant_of(
        &accepted
            .first()
            .map(|c| c.key_id.clone())
            .unwrap_or_default(),
    );
    let _ = one_cert_of(&w, &accepted, &b, "the activation's login");
    checkpoint(&w, "after the activation", Some(wk.pid()), &mut hits);

    // The re-issue, the second login.
    w.restart_runtime();
    w.wait_reissued(&[&a, &b], 2);
    std::fs::write(&g1, b"").unwrap();
    let results = wk.wait_signal(&s2, Duration::from_secs(120));
    assert_login_ok(&w, &results, "second");
    let indices = seeded_indices(&w, &seed, &[&a, &b]);
    assert_eq!(
        indices.len(),
        4,
        "two activations and two re-issues: {indices:?}"
    );
    assert!(
        indices.iter().all(Option::is_some),
        "control: every K_env is a seeded key the scan looks for: {indices:?}"
    );
    // The doctor report and the events and operations reads.
    for args in [
        &["--json", "doctor"][..],
        &["doctor"][..],
        &["--json", "operation", "events", "--limit", "500"][..],
        &["--json", "inspect", "operations"][..],
        &["--json", "inspect", "grants"][..],
        &["--json", "inspect", "bindings"][..],
        &["--json", "issuer", "status"][..],
        &["--json", "inspect", "capabilities"][..],
    ] {
        let out = w.cli(args);
        assert!(
            out.code == 0 || args[..2] == ["--json", "doctor"] || args[0] == "doctor",
            "{args:?}: {}",
            w.redact(&format!("{out:?}"))
        );
    }
    checkpoint(&w, "after the re-issue", Some(wk.pid()), &mut hits);

    // The revocation and the refused login.
    w.revoke(&b, "exit-a33-revoke");
    std::fs::write(&g2, b"").unwrap();
    let out = wk.finish(Duration::from_secs(120));
    w.record_bytes("worker (stdout)", out.stdout.as_bytes());
    w.record_bytes("worker (stderr)", out.stderr.as_bytes());
    let r = worker::result(&out.results, "login", Some("after_revoke"));
    assert!(
        r["exit"] != 0,
        "refused after the revocation: {}",
        w.redact(&r.to_string())
    );
    let events = w.cli(&["--json", "operation", "events", "--limit", "500"]);
    assert_eq!(events.code, 0, "{}", w.redact(&format!("{events:?}")));
    checkpoint(&w, "after the revocation", None, &mut hits);

    assert!(
        hits.is_empty(),
        "secret bytes found: {}",
        scan::describe(&hits)
    );
    let control = scan::public_control(&w);
    assert!(
        control >= 1,
        "control: the scan finds the CA's public blob in the Heimdall home"
    );
    if cfg!(target_os = "linux") {
        assert!(
            placed_seen >= 1,
            "control: the environment reading sees the placed canary in its variable"
        );
    }
    println!(
        "m03 observation: a33 {os} secret_bytes 0 (kinds: k_env {} forms, k_ca {} forms, canary {} forms; checkpoints: {}; controls: CA public blob in {control} Heimdall-home files, placed canary seen in {placed_seen} environments, all {} K_env seeded (indices {:?}))",
        needles[0].forms.len(),
        needles[1].forms.len(),
        needles[2].forms.len(),
        checkpoints.join("; "),
        indices.len(),
        indices.iter().flatten().collect::<Vec<_>>()
    );
    println!(
        "m03 observation: a33 {os} fake_adapter_credential_ref_in_effect_receipts {receipt_refs} (the test configuration's canary-named credential reference, stored by design in the state database's effect receipts; not counted)"
    );
    for u in &unobservable {
        println!("m03 observation: a33 {os} unobservable: {u}");
    }
}

/// ⟨M03 wave 6, B-L1-2⟩ A verification through the real runtime and its real `internal
/// issuer` child (no fixture issuer, no fixture session): `enroll verify` of the world's
/// `verified` enrollment (a presence re-verification) has the issuer child sign both
/// verification certificates under its format ceilings (ADR-0008 D3 item 4 step 3: key
/// ID `heimdall:<env>:<operation>:<decimal serial>`), the runtime's Verifier logs in
/// with the positive one through the operation's own endpoint, and the record is
/// `verified` again. The server accepted exactly one certificate, of the world's CA,
/// whose key ID names the operation and ends in the certificate's own serial.
#[cfg(any(unix, windows))]
#[test]
fn real_issuer_signs_verification_certificates_enroll_verify_passes() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        ..WorldOptions::default()
    });
    drop(ca);
    let status = w.cli(&["--json", "--non-interactive", "enroll", "status"]);
    assert_eq!(status.code, 0, "{}", w.redact(&status.stdout));
    let listed = status.json()["data"]["enrollments"].clone();
    let id = listed[0]["enrollment_id"].as_str().unwrap().to_owned();
    let mark = w.pairs[0].sshd.log_mark();
    let out = w.cli(&["--json", "--non-interactive", "enroll", "verify", &id]);
    let env = out.json();
    assert!(
        out.code == 0 && env["data"]["state"] == "verified",
        "enroll verify through the real issuer child: exit {}, {}",
        out.code,
        w.redact(&out.stdout)
    );
    let accepted = w.accepted_since(0, mark);
    assert_eq!(
        accepted.len(),
        1,
        "the positive certificate only: {accepted:?}"
    );
    let c = &accepted[0];
    assert_eq!(
        c.ca_fingerprint,
        w.ca_fingerprint.as_str(),
        "the world's CA"
    );
    let fields: Vec<&str> = c.key_id.split(':').collect();
    assert!(
        fields.len() == 4
            && fields[0] == "heimdall"
            && fields[1] == w.environment.as_str()
            && fields[2].starts_with("op_")
            && fields[3] == c.serial.to_string(),
        "key ID heimdall:<env>:<operation>:<serial>: {} (serial {})",
        c.key_id,
        c.serial
    );
}
