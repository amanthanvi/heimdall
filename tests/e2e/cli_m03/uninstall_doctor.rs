//! M03 wave 5 (U12): `e2e_cli_m03` submodule `uninstall_doctor` (owner: see `.m03-wave5-api.md` R1).
//! Shares the parent's `bin()`, `run()` and fixtures through `super::`.
//!
//! * Uninstall (ADR-0008 D4 item 6, §17.25 items 8, 9, 11): the listing of the
//!   enrollments that are not final and the `enroll remove` offer, the plain
//!   uninstall's acknowledgement (a typed `yes`, or `--keep-remote-enrollments`), the
//!   purge refusals (`CONFIG_CONFLICT` exit 6 without the acknowledgement,
//!   `bundle_required`/`bundle_redacted` exit 4 without a fresh bundle whose SHA-256 this
//!   installation recorded), and the K_ca store item's fate. Every case ends **before**
//!   any runtime contact (a runtime the CLI started would wire the account's real
//!   `~/.ssh`): where a case gets past the acknowledgement, the runtime directory is a
//!   regular file, so the CLI cannot prepare it and starts nothing. The state database
//!   is never written by the CLI.
//! * Doctor (m03-plan U12, §5 item 14, §17.25 item 13): `slot_free` with its command,
//!   `managed_dir_unsafe`, `enrollment_evidence_stale`, `reverification_inconclusive`
//!   and `client_trace_family_unrecorded`, read-only and never repaired.
//! * The CLI half of `time_confirmation_after_reboot` (§17.25 item 12): the bare
//!   `heimdall` status without a terminal shows the chore with `heimdall time confirm`
//!   exactly when the time gate lacks a reference for this boot and a CA is registered.
//!
//! Fixtures are synthetic (fixture IDs, `example.invalid`, fake public keys); no owner
//! key, agent, keychain or SSH configuration is read (`HEIMDALL_TEST_SSH_HOME` points
//! the doctor at the scratch account). Every directory the managed checks look at is
//! created owner-only explicitly (the devbox's umask is 002).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::RegistryCanonical;
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, EnvironmentId, IdentityId, OperationId,
};
use heimdall_contract::issuer::{
    BundleCa, BundleEnrollment, RECOVERY_BUNDLE_SCHEMA, RecoveryBundle,
};
use heimdall_contract::managed::PreferredMechanism;
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    EnrollmentEvidence, EnrollmentRecord, EnrollmentState, PairPreference, ProjectionStatus,
};
use heimdall_domain::time::AttendedTimeConfirmation;
use heimdall_store::{NoFaults, Store};

use super::{Out, ca, enrollment, run, seed_state, t0};

/// The fixture's recorded K_ca store locator (a synthetic Secret Service item path).
const LOCATOR: &str = "/org/freedesktop/secrets/collection/fixture/heimdall_ca_1";

/// A scratch account directory (the doctor's and the CLI's `HOME`).
fn account(scratch: &Path) -> std::path::PathBuf {
    let a = scratch.join("account");
    std::fs::create_dir_all(a.join(".ssh")).unwrap();
    a
}

/// Record [`LOCATOR`] as the fixture CA's store item.
fn record_locator(db: &Path) {
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| tx.set_issuer_store_locator(&ca(), LOCATOR))
        .unwrap();
}

fn no_runtime(home: &Path, out: &Out) {
    assert!(
        !home.join("run").exists(),
        "no runtime was contacted: {out:?}"
    );
}

fn markers(out: &Out) -> Vec<String> {
    out.json()["data"]["enrollments"]
        .as_array()
        .unwrap_or_else(|| panic!("no enrollments: {out:?}"))
        .iter()
        .map(|e| e["marker"].as_str().unwrap().to_owned())
        .collect()
}

/// `uninstall_lists_remote_enrollments_and_refuses_purge_without_ack` (D4 item 6): a
/// plain `uninstall` lists every enrollment that is not final, with its marker, and
/// offers `enroll remove` first; without a terminal it cannot be acknowledged (exit 3,
/// nothing changed). `--purge-state` without `--keep-remote-enrollments` is refused
/// (exit 6), and with it but without a bundle `bundle_required` (exit 4).
#[test]
fn uninstall_lists_remote_enrollments_and_refuses_purge_without_ack() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(
        &home,
        &[
            EnrollmentState::AppliedUnverified,
            EnrollmentState::Verified,
            EnrollmentState::Withdrawn,
        ],
    );
    let live = [
        enrollment(1, EnrollmentState::AppliedUnverified),
        enrollment(2, EnrollmentState::Verified),
    ];
    let final_one = enrollment(3, EnrollmentState::Withdrawn);
    let before = std::fs::read(&db).unwrap();

    // A plain uninstall: listed, `enroll remove` offered, no acknowledgement possible.
    let out = run(
        &home,
        &account,
        &["--json", "--non-interactive", "uninstall"],
        &[],
    );
    assert_eq!(out.code, 3, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "INTERACTION_REQUIRED", "{out:?}");
    assert_eq!(env["data"]["error"]["effect_status"], "none", "{out:?}");
    assert!(
        env["next"].get("decision_ref").is_none(),
        "client-side: {out:?}"
    );
    assert_eq!(
        markers(&out),
        live.iter().map(|e| e.marker.clone()).collect::<Vec<_>>()
    );
    let listed = env["data"]["enrollments"].as_array().unwrap();
    assert_eq!(listed[0]["destination_id"], "dst-lab1");
    assert_eq!(listed[0]["state"], "applied_unverified");
    assert_eq!(listed[1]["state"], "verified");
    assert!(!out.stdout.contains(&final_one.marker), "{out:?}");
    let message = out.message();
    assert!(
        message.contains("heimdall enroll remove <enrollment>"),
        "{message}"
    );
    assert!(message.contains("nothing was changed"), "{message}");
    no_runtime(&home, &out);
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");

    // Human mode lists the markers and the offer on stdout.
    let out = run(&home, &account, &["--non-interactive", "uninstall"], &[]);
    assert_eq!(out.code, 3, "{out:?}");
    for e in &live {
        assert!(out.stdout.contains(&e.marker), "{out:?}");
    }
    assert!(out.stdout.contains("dst-lab2 verified"), "{out:?}");
    assert!(out.stderr.contains("heimdall enroll remove"), "{out:?}");

    // A stdin that is not a terminal cannot acknowledge either (no --non-interactive).
    let out = run(&home, &account, &["--json", "uninstall"], &[]);
    assert_eq!(out.code, 3, "{out:?}");
    assert!(out.message().contains("stdin is not a terminal"), "{out:?}");

    // `--purge-state` without the acknowledgement: refused (exit 6), listed.
    let out = run(
        &home,
        &account,
        &["--json", "--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(out.code, 6, "{out:?}");
    assert_eq!(out.json()["code"], "CONFIG_CONFLICT");
    assert_eq!(markers(&out).len(), 2);
    assert!(
        out.message().contains("--keep-remote-enrollments"),
        "{out:?}"
    );

    // With it but without a bundle: `bundle_required` (exit 4).
    let out = run(
        &home,
        &account,
        &[
            "--json",
            "--non-interactive",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
        ],
        &[],
    );
    assert_eq!(out.code, 4, "{out:?}");
    assert_eq!(out.json()["code"], "CAPABILITY_UNAVAILABLE");
    assert_eq!(out.json()["data"]["error"]["reason"], "bundle_required");
    assert_eq!(markers(&out).len(), 2);
    no_runtime(&home, &out);
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
}

/// `uninstall_plain_keep_remote_enrollments_is_the_acknowledgement` (ADR-0008 §17.25
/// item 11): `--keep-remote-enrollments` alone is the explicit acknowledgement of a
/// plain uninstall while enrollments are not final, without a terminal and under
/// `--non-interactive`, so a scripted uninstall goes on (the state is kept). Without it
/// the same invocation stops at exit 3; `--bundle` still needs `--purge-state` and
/// `--keep-remote-enrollments` (usage, exit 2). The runtime directory is a regular file
/// here, so the acknowledged uninstall stops when it would prepare it: nothing is
/// started, and the state database is untouched.
#[test]
fn uninstall_plain_keep_remote_enrollments_is_the_acknowledgement() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(
        &home,
        &[EnrollmentState::Verified, EnrollmentState::Withdrawn],
    );
    std::fs::write(home.join("run"), b"not a directory").unwrap();
    let before = std::fs::read(&db).unwrap();
    let ssh_home = account.to_string_lossy().into_owned();
    let env = [("HEIMDALL_TEST_SSH_HOME", ssh_home.as_str())];
    let not_started = |out: &Out| {
        assert!(home.join("run").is_file(), "nothing was started: {out:?}");
        assert!(!home.join("log").join("runtime.log").exists(), "{out:?}");
    };

    for ni in [true, false] {
        let mut args = vec!["--json"];
        if ni {
            args.push("--non-interactive");
        }
        args.push("uninstall");
        // Not acknowledged: exit 3, nothing changed.
        let out = run(&home, &account, &args, &env);
        assert_eq!(out.code, 3, "{out:?}");
        assert!(
            out.message().contains("--keep-remote-enrollments"),
            "the scripted acknowledgement is named: {out:?}"
        );
        not_started(&out);
        // Acknowledged: past the gate, to the runtime step (which cannot start here).
        args.push("--keep-remote-enrollments");
        let out = run(&home, &account, &args, &env);
        assert_ne!(out.code, 3, "acknowledged: {out:?}");
        let envelope = out.json();
        assert_eq!(envelope["code"], "SERVICE_UNAVAILABLE", "{out:?}");
        assert!(
            out.message()
                .contains("cannot prepare the runtime directories"),
            "{out:?}"
        );
        not_started(&out);
    }

    // `--bundle` without `--purge-state` is a usage error, as is it without the flag.
    let bundle = scratch.path().join("b.json");
    let arg = bundle.to_string_lossy().into_owned();
    for args in [
        &[
            "--json",
            "uninstall",
            "--keep-remote-enrollments",
            "--bundle",
            &arg,
        ][..],
        &["--json", "uninstall", "--purge-state", "--bundle", &arg][..],
    ] {
        let out = run(&home, &account, args, &env);
        assert_eq!(out.code, 2, "{args:?}: {out:?}");
    }
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
}

/// One bundle enrollment for `r` (public metadata only).
fn bundle_entry(r: &EnrollmentRecord) -> BundleEnrollment {
    BundleEnrollment {
        marker: r.marker.clone(),
        destination_id: r.destination.as_str().to_owned(),
        alias: format!("lab-{}", r.destination.as_str()),
        hostname: Some(r.target.hostname.clone()),
        port: Some(r.target.port),
        account: r.account.clone(),
        registry: RegistryCanonical {
            path: None,
            resolved_by: r.registry_canonical.resolved_by,
        },
        registry_path_display: r.registry.path_display.clone(),
        form: r.form,
        state: r.state,
        ca_fingerprint: r.ca_fingerprint.clone(),
        ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
        line_sha256: r.line_sha256.clone(),
        late_write: None,
    }
}

/// Write a recovery bundle at `path`, created at `at`, listing `records`.
fn write_bundle(path: &Path, at: Timestamp, records: &[EnrollmentRecord], redacted: bool) {
    let bundle = RecoveryBundle {
        schema: RECOVERY_BUNDLE_SCHEMA.to_owned(),
        created_at: at,
        redacted,
        cas: vec![BundleCa {
            fingerprint: ca(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
            backup_sha256: "00".repeat(32),
            backup_created_at: t0(),
            state: heimdall_contract::issuer::CaState::Active,
        }],
        enrollments: records
            .iter()
            .map(|r| {
                let mut e = bundle_entry(r);
                if redacted {
                    e.hostname = None;
                    e.port = None;
                }
                e
            })
            .collect(),
        instructions: vec!["Remove the line carrying the marker.".into()],
    };
    std::fs::write(path, serde_json::to_vec(&bundle).unwrap()).unwrap();
}

/// Record `bundle`'s SHA-256 as one this installation confirmed writing, through the
/// store accessor the runtime's `issuer.bundle_written` handler writes
/// (`Txn::record_bundle_digest`; ADR-0008 §17.25 item 8). Seeded directly: the real path
/// (`heimdall issuer bundle`) needs a running runtime, which this suite never starts.
fn record_digest(db: &Path, bundle: &Path) {
    let bytes = std::fs::read(bundle).unwrap();
    let sha = heimdall_issuer::backup::sha256_hex(&bytes);
    let created_at = serde_json::from_slice::<RecoveryBundle>(&bytes)
        .unwrap()
        .created_at;
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| tx.record_bundle_digest(&sha, created_at))
        .unwrap();
}

/// `uninstall_purge_keeping_enrollments_requires_fresh_bundle` (F08; D4 item 6; §17.25
/// item 8): a purge that keeps remote enrollments needs a fresh recovery bundle: by
/// content (unredacted, created no earlier than the last enrollment or CA change, every
/// CA and remaining enrollment in its current state) **and** by origin (its SHA-256 is
/// one this installation recorded). A missing file, a file that is not a bundle, a stale
/// one, a partial one, one with an enrollment in another state (each refused whether or
/// not its digest is recorded), a hand-made one with a fresh content but no record, and
/// a foreign one (the same content in other bytes, so another digest) are each
/// `bundle_required` (exit 4); a redacted one is `bundle_redacted` (exit 4). A fresh,
/// recorded bundle is accepted: the purge goes on to its own confirmation (exit 3 without
/// a terminal), naming the bundle. Nothing is changed and no runtime is contacted.
#[test]
fn uninstall_purge_keeping_enrollments_requires_fresh_bundle() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(
        &home,
        &[EnrollmentState::Verified, EnrollmentState::Removed],
    );
    let live = enrollment(1, EnrollmentState::Verified);
    let removed = enrollment(2, EnrollmentState::Removed);
    // The last change is enrollment 2's (t0 + 2 s).
    let after = t0().checked_add(Duration::from_secs(60)).unwrap();
    let before_change = t0().checked_add(Duration::from_secs(1)).unwrap();

    let bundle = |name: &str, at, records: &[EnrollmentRecord], redacted| {
        let p = scratch.path().join(name);
        write_bundle(&p, at, records, redacted);
        p
    };
    let missing = scratch.path().join("missing.json");
    let garbage = scratch.path().join("garbage.json");
    std::fs::write(&garbage, b"{\"not\": \"a bundle\"}").unwrap();
    let stale = bundle(
        "stale.json",
        before_change,
        &[live.clone(), removed.clone()],
        false,
    );
    let partial = bundle("partial.json", after, std::slice::from_ref(&removed), false);
    let mut changed = live.clone();
    changed.state = EnrollmentState::AppliedUnverified;
    let wrong_state = bundle("wrong-state.json", after, &[changed], false);
    let redacted = bundle(
        "redacted.json",
        after,
        &[live.clone(), removed.clone()],
        true,
    );
    // Fresh and complete by content, but made by hand (another `created_at`, so other
    // bytes than any bundle this installation recorded).
    let hand_made = bundle(
        "hand-made.json",
        after.checked_add(Duration::from_secs(1)).unwrap(),
        &[live.clone(), removed.clone()],
        false,
    );
    let fresh = bundle("fresh.json", after, &[live.clone(), removed.clone()], false);
    // The same content as `fresh`, written by someone else: other bytes, another digest.
    let foreign = scratch.path().join("foreign.json");
    let parsed: RecoveryBundle = serde_json::from_slice(&std::fs::read(&fresh).unwrap()).unwrap();
    std::fs::write(&foreign, serde_json::to_vec_pretty(&parsed).unwrap()).unwrap();
    // Every file below is recorded except `hand_made` and `foreign`: the content check
    // refuses the stale, partial, other-state and redacted ones whatever the record.
    for b in [&stale, &partial, &wrong_state, &redacted, &fresh] {
        record_digest(&db, b);
    }
    let before = std::fs::read(&db).unwrap();

    let attempt = |bundle: &Path| {
        let arg = bundle.to_string_lossy().into_owned();
        run(
            &home,
            &account,
            &[
                "--json",
                "--non-interactive",
                "uninstall",
                "--purge-state",
                "--keep-remote-enrollments",
                "--bundle",
                &arg,
            ],
            &[],
        )
    };
    let refused = |out: &Out, reason: &str, why: &str| {
        assert_eq!(out.code, 4, "{out:?}");
        let env = out.json();
        assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{out:?}");
        assert_eq!(env["data"]["error"]["reason"], reason, "{out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none", "{out:?}");
        assert_eq!(markers(out), vec![live.marker.clone()]);
        let message = out.message();
        assert!(message.contains(why), "{why}: {message}");
        assert!(message.contains("nothing was changed"), "{message}");
        assert!(env["data"].get("bundle").is_none(), "{out:?}");
        no_runtime(&home, out);
    };

    refused(&attempt(&missing), "bundle_required", "cannot be read");
    refused(
        &attempt(&garbage),
        "bundle_required",
        "not a recovery bundle",
    );
    refused(
        &attempt(&stale),
        "bundle_required",
        "predates the last enrollment or CA change",
    );
    refused(
        &attempt(&partial),
        "bundle_required",
        "every remaining enrollment",
    );
    refused(
        &attempt(&wrong_state),
        "bundle_required",
        "every remaining enrollment",
    );
    refused(&attempt(&redacted), "bundle_redacted", "redacted");
    for unrecorded in [&hand_made, &foreign] {
        refused(
            &attempt(unrecorded),
            "bundle_required",
            "recorded no bundle with that SHA-256",
        );
    }

    // Fresh, complete and recorded: accepted; the purge stops at its own typed
    // confirmation (no terminal here), naming the bundle that records what stays.
    let out = attempt(&fresh);
    assert_eq!(out.code, 3, "{out:?}");
    let env = out.json();
    assert_eq!(env["code"], "INTERACTION_REQUIRED", "{out:?}");
    assert!(
        out.message().contains("--purge-state not confirmed"),
        "{out:?}"
    );
    assert!(
        env["data"]["bundle"]["path_display"]
            .as_str()
            .is_some_and(|p| p.ends_with("fresh.json")),
        "{out:?}"
    );
    assert_eq!(markers(&out), vec![live.marker.clone()]);
    assert_eq!(
        env["data"]["store_items"][0]["markers"],
        serde_json::json!([live.marker.clone()]),
        "each live marker once: {out:?}"
    );
    no_runtime(&home, &out);

    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    assert!(
        fresh.exists() && redacted.exists() && foreign.exists(),
        "the bundles are left alone"
    );
}

/// `uninstall_states_store_item_fate` (F08; D4 item 6; §17.25 item 9): the K_ca store
/// item is kept, named with its reason, while an enrollment under its CA is not final;
/// when every one is final, deletion is offered (the retirement steps behind their typed
/// confirmation, which uninstall runs inline before the runtime stops, or
/// `heimdall issuer retire <fingerprint>`) with the reminder to destroy the offline
/// backup; an item whose locator was never recorded is kept (it cannot be deleted by
/// exact identity). Stated in JSON and in the human text. The inline run itself needs a
/// terminal and a runtime, which this suite never starts: its gating and its call of the
/// one retire entry are `uninstall_cmd::tests::offered_store_items_are_retired_inline_only_on_a_terminal`.
#[test]
fn uninstall_states_store_item_fate() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let purge = ["--json", "--non-interactive", "uninstall", "--purge-state"];
    let fp = ca().as_str().to_owned();

    // Live: kept, naming the item, the CA and the reason (the live marker).
    let home = scratch.path().join("live");
    let db = seed_state(
        &home,
        &[EnrollmentState::Verified, EnrollmentState::Withdrawn],
    );
    record_locator(&db);
    let live = enrollment(1, EnrollmentState::Verified);
    let out = run(&home, &account, &purge, &[]);
    assert_eq!(out.code, 6, "{out:?}");
    let items = out.json()["data"]["store_items"].clone();
    assert_eq!(items.as_array().map(Vec::len), Some(1), "{out:?}");
    let item = &items[0];
    assert_eq!(item["ca_fingerprint"], fp.as_str());
    assert_eq!(item["store_kind"], "linux_secret_service");
    assert_eq!(item["locator"], LOCATOR);
    assert_eq!(item["fate"], "kept", "{out:?}");
    assert_eq!(item["reason"], "live_enrollments");
    assert_eq!(item["markers"][0], live.marker.as_str());
    assert!(
        item.get("command").is_none(),
        "no deletion offered: {out:?}"
    );
    let message = item["message"].as_str().unwrap();
    for needle in [LOCATOR, fp.as_str(), live.marker.as_str(), "not final"] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
    let human = run(&home, &account, &purge[1..], &[]);
    assert_eq!(human.code, 6, "{human:?}");
    assert!(
        human.stdout.contains("CA key (K_ca) store items:"),
        "{human:?}"
    );
    assert!(
        human
            .stdout
            .contains(&format!("kept: the linux_secret_service item {LOCATOR}")),
        "{human:?}"
    );
    no_runtime(&home, &out);

    // Every enrollment final: deletion offered, with the command and the reminder. The
    // purge itself then stops at its own confirmation (exit 3), which shows the fate too.
    let home = scratch.path().join("final");
    let db = seed_state(
        &home,
        &[EnrollmentState::Removed, EnrollmentState::Withdrawn],
    );
    record_locator(&db);
    let before = std::fs::read(&db).unwrap();
    let out = run(&home, &account, &purge, &[]);
    assert_eq!(out.code, 3, "{out:?}");
    assert!(out.json()["data"].get("enrollments").is_none(), "{out:?}");
    let item = out.json()["data"]["store_items"][0].clone();
    assert_eq!(item["fate"], "deletion_offered", "{out:?}");
    assert!(item["reason"].is_null(), "{out:?}");
    assert_eq!(item["command"], format!("heimdall issuer retire {fp}"));
    let message = item["message"].as_str().unwrap();
    for needle in [
        "deletion offered",
        LOCATOR,
        "run to `retired`",
        "typed yes",
        "uninstall runs them before the runtime stops",
        "destroy the offline backup",
    ] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
    let human = run(&home, &account, &purge[1..], &[]);
    assert_eq!(human.code, 3, "{human:?}");
    assert!(human.stdout.contains("deletion offered"), "{human:?}");
    assert!(
        human
            .stdout
            .contains(&format!("heimdall issuer retire {fp}")),
        "{human:?}"
    );
    no_runtime(&home, &out);
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");

    // No recorded locator: kept, with that reason (never deleted by fingerprint).
    let home = scratch.path().join("unrecorded");
    seed_state(&home, &[EnrollmentState::Removed]);
    let out = run(&home, &account, &purge, &[]);
    assert_eq!(out.code, 3, "{out:?}");
    let item = out.json()["data"]["store_items"][0].clone();
    assert_eq!(item["fate"], "kept", "{out:?}");
    assert_eq!(item["reason"], "locator_unrecorded");
    assert!(item["locator"].is_null());
    assert!(item.get("command").is_none());
    assert!(
        item["message"].as_str().unwrap().contains("never recorded"),
        "{out:?}"
    );
}

/// Seed `home`'s store for the doctor: this installation's environment, and managed
/// destinations `alias` → `(destination, mechanism, projection)`.
fn seed_managed(home: &Path, aliases: &[(&str, &str, PreferredMechanism, ProjectionStatus)]) {
    let db = seed_state(home, &[]);
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.init_self_environment(&EnvironmentId::from_random_bytes([7; 16]))?;
            for (n, (alias, dst, mechanism, projection)) in (1u8..).zip(aliases) {
                let account = AccountName::parse("deploy").unwrap();
                let destination = DestinationId::parse(dst).unwrap();
                tx.upsert_destination(&DestinationRecord {
                    id: destination.clone(),
                    alias: (*alias).to_owned(),
                    revision: 1,
                    definition: DestinationDefinition::Managed {
                        hostname: "example.invalid".into(),
                        port: None,
                        account: account.clone(),
                        identity: IdentityId::from_random_bytes([n; 16]),
                    },
                    label: None,
                    updated_at: t0(),
                })?;
                tx.set_pair_preference(
                    &PairPreference {
                        destination,
                        account,
                        mechanism: *mechanism,
                        projection: *projection,
                        issuing_cas: std::iter::once(ca()).collect(),
                    },
                    t0(),
                )?;
            }
            Ok(())
        })
        .unwrap();
}

fn doctor(home: &Path, account: &Path) -> Out {
    let ssh_home = account.to_string_lossy().into_owned();
    let out = run(
        home,
        account,
        &["--json", "--non-interactive", "doctor", "--no-local-exec"],
        &[("HEIMDALL_TEST_SSH_HOME", &ssh_home)],
    );
    assert_eq!(out.code, 0, "{out:?}");
    out
}

fn findings(out: &Out, code: &str) -> Vec<serde_json::Value> {
    out.json()["data"]["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("no findings: {out:?}"))
        .iter()
        .filter(|f| f["code"] == code)
        .cloned()
        .collect()
}

/// `doctor_reports_slot_free_with_command` (D10 item 2; §17.4 item 12): a managed alias
/// whose pair prefers managed certificates, whose projection is applied and whose slot
/// no binding holds is reported `slot_free` with the command that holds one
/// (`heimdall run --profile <profile> -- ssh <alias>`, never `bind materialize`); a pair
/// still `pending` or on its existing identity is not. Read-only, no runtime.
#[test]
fn doctor_reports_slot_free_with_command() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    seed_managed(
        &home,
        &[
            (
                "lab-applied",
                "dst-applied",
                PreferredMechanism::ManagedCertificate,
                ProjectionStatus::Applied { generation: 3 },
            ),
            (
                "lab-pending",
                "dst-pending",
                PreferredMechanism::ManagedCertificate,
                ProjectionStatus::Pending,
            ),
            (
                "lab-existing",
                "dst-existing",
                PreferredMechanism::Existing,
                ProjectionStatus::Applied { generation: 3 },
            ),
        ],
    );
    let db = home.join("state").join("state.db");
    let before = std::fs::read(&db).unwrap();
    let out = doctor(&home, &account);
    let free = findings(&out, "slot_free");
    assert_eq!(free.len(), 1, "{out:?}");
    assert_eq!(free[0]["subject"]["kind"], "destination");
    assert_eq!(free[0]["subject"]["id"], "dst-applied");
    let message = free[0]["message"].as_str().unwrap();
    assert!(
        message.contains("`heimdall run --profile <profile> -- ssh lab-applied`"),
        "{message}"
    );
    assert!(message.contains("ordinary `ssh lab-applied`"), "{message}");
    assert!(!out.stdout.contains("bind materialize"), "{out:?}");
    // The human report names the same command.
    let ssh_home = account.to_string_lossy().into_owned();
    let human = run(
        &home,
        &account,
        &["--non-interactive", "doctor", "--no-local-exec"],
        &[("HEIMDALL_TEST_SSH_HOME", &ssh_home)],
    );
    assert_eq!(human.code, 0, "{human:?}");
    assert!(
        human
            .stdout
            .contains("heimdall run --profile <profile> -- ssh lab-applied"),
        "{human:?}"
    );
    assert!(!human.stdout.contains("ssh lab-pending"), "{human:?}");
    no_runtime(&home, &out);
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the doctor wrote nothing"
    );
}

/// Create `path` as a directory with `mode` (set explicitly, whatever the umask).
#[cfg(unix)]
fn dir_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// `doctor_reports_managed_dir_unsafe` (ADR-0008 §17.20 item 15): a binding directory
/// under `<runtime_dir>/b/` that is not owner-only, and a symlink where a slot directory
/// must be, are each reported `managed_dir_unsafe`; owner-only ones are not; nothing is
/// repaired, followed or removed. An installation without the managed levels gets no
/// finding. Unix only: the Windows DACL rule needs the Windows-native run.
#[cfg(unix)]
#[test]
fn doctor_reports_managed_dir_unsafe() {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());

    // No managed level at all: no finding.
    let plain = scratch.path().join("plain");
    dir_mode(&plain.join("run"), 0o700);
    seed_state(&plain, &[]);
    let out = doctor(&plain, &account);
    assert!(findings(&out, "managed_dir_unsafe").is_empty(), "{out:?}");

    let home = scratch.path().join("home");
    seed_state(&home, &[]);
    dir_mode(&home, 0o700);
    dir_mode(&home.join("state"), 0o700);
    dir_mode(&home.join("run"), 0o700);
    dir_mode(&home.join("run").join("b"), 0o700);
    let good = home.join("run").join("b").join("00112233445566aa");
    let loose = home.join("run").join("b").join("00112233445566bb");
    dir_mode(&good, 0o700);
    dir_mode(&loose, 0o755);
    dir_mode(&home.join("state").join("managed"), 0o700);
    dir_mode(&home.join("state").join("managed").join("dst-ok"), 0o700);
    let elsewhere = scratch.path().join("elsewhere");
    dir_mode(&elsewhere, 0o700);
    let link = home.join("state").join("managed").join("dst-link");
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
    std::fs::write(home.join("run").join("b").join("stray-file"), b"x").unwrap();

    let out = doctor(&home, &account);
    let unsafe_dirs = findings(&out, "managed_dir_unsafe");
    let ids: Vec<&str> = unsafe_dirs
        .iter()
        .map(|f| f["subject"]["id"].as_str().unwrap())
        .collect();
    assert_eq!(unsafe_dirs.len(), 2, "{out:?}");
    assert!(
        ids.iter().any(|i| i.ends_with("run/b/00112233445566bb")),
        "{ids:?}"
    );
    assert!(
        ids.iter().any(|i| i.ends_with("state/managed/dst-link")),
        "{ids:?}"
    );
    for f in &unsafe_dirs {
        assert_eq!(f["subject"]["kind"], "directory");
        assert_eq!(f["severity"], "problem");
        assert_eq!(f["reason"], "managed_dir_unsafe");
        let message = f["message"].as_str().unwrap();
        assert!(message.contains("nothing was repaired"), "{message}");
        assert!(message.contains("binding clears refuse"), "{message}");
    }
    let loose_finding = unsafe_dirs
        .iter()
        .find(|f| f["subject"]["id"].as_str().unwrap().ends_with("bb"))
        .unwrap();
    assert!(
        loose_finding["message"]
            .as_str()
            .unwrap()
            .contains("not owner-only"),
        "{loose_finding}"
    );
    // Reported, never repaired, followed or removed.
    let mode = std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "the directory was not repaired");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(good.is_dir());
    assert!(
        !home.join("run").join("instance.json").exists(),
        "no runtime was started"
    );
}

/// Seed an attended time confirmation at `at` (boot, continuous reading, wall time).
fn seed_confirmation(home: &Path, at: &heimdall_domain::time::TimeAnchor) {
    let db = seed_state(home, &[]);
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.set_time_confirmation(&AttendedTimeConfirmation {
                boot_id: at.boot_id.clone(),
                continuous: at.continuous,
                wall: at.wall,
                decision: DecisionId::from_random_bytes([9; 16]),
            })
        })
        .unwrap();
}

fn chores(out: &Out) -> Option<Vec<serde_json::Value>> {
    out.json()["data"]["chores"].as_array().cloned()
}

/// `status_shows_time_confirmation_chore_after_reboot` (ADR-0008 D9 item 5, §17.25 item
/// 12; m03-plan U12; F14): the chore is pending exactly when the time gate would refuse
/// an issuance for lack of a time reference for this boot **and** an issuer CA is
/// registered. After a reboot (the store's confirmation belongs to another boot) and in a
/// never-confirmed store with a CA, the bare `heimdall` without a terminal shows it with
/// its one command, `heimdall time confirm`, with no runtime running (it never starts
/// one). A store with no CA shows none, and so does a store confirmed in this boot now
/// (a same-boot reference the gate accepts).
#[test]
fn status_shows_time_confirmation_chore_after_reboot() {
    use heimdall_domain::time::{BootId, Clock as _, TimeAnchor};
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let now = heimdall_runtime::platform::SystemClock::new().observe();

    let rebooted = scratch.path().join("rebooted");
    seed_confirmation(
        &rebooted,
        &TimeAnchor {
            boot_id: BootId("boot-before-the-reboot".into()),
            ..now.clone()
        },
    );
    let never = scratch.path().join("never-confirmed");
    seed_state(&never, &[]);
    for home in [&rebooted, &never] {
        let db = home.join("state").join("state.db");
        let before = std::fs::read(&db).unwrap();
        for args in [&["--json"][..], &["--json", "--non-interactive"][..]] {
            let out = run(home, &account, args, &[]);
            let chores = chores(&out).unwrap_or_else(|| panic!("no chores: {out:?}"));
            assert_eq!(chores.len(), 1, "{out:?}");
            assert_eq!(chores[0]["chore"], "time_confirmation_after_reboot");
            assert_eq!(chores[0]["command"], "heimdall time confirm");
            assert!(
                chores[0]["message"]
                    .as_str()
                    .unwrap()
                    .contains("`heimdall time confirm`"),
                "{out:?}"
            );
            no_runtime(home, &out);
        }
        assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    }

    // No CA registered (never confirmed): no chore.
    let no_ca = scratch.path().join("no-ca");
    std::fs::create_dir_all(no_ca.join("state")).unwrap();
    drop(Store::open(&no_ca.join("state").join("state.db"), Arc::new(NoFaults)).unwrap());
    let out = run(&no_ca, &account, &["--json"], &[]);
    assert!(chores(&out).is_none(), "{out:?}");
    no_runtime(&no_ca, &out);

    // Confirmed in this boot, now: the gate has its reference, no chore.
    let confirmed = scratch.path().join("confirmed");
    seed_confirmation(&confirmed, &now);
    let out = run(&confirmed, &account, &["--json"], &[]);
    assert!(chores(&out).is_none(), "{out:?}");
}

/// Seed `home`'s store with this installation's environment and the `verified`
/// enrollments `records` (the CA of [`seed_state`] included).
fn seed_verified(home: &Path, records: &[EnrollmentRecord]) -> std::path::PathBuf {
    let db = seed_state(home, &[]);
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.init_self_environment(&environment())?;
            for r in records {
                tx.seed_enrollment(r)?;
            }
            Ok(())
        })
        .unwrap();
    db
}

fn environment() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

/// A `verified` enrollment `n` whose evidence came from `operation`, fresh until
/// `fresh_until` (no evidence when `None`).
fn verified(n: u8, operation: &OperationId, fresh_until: Option<Timestamp>) -> EnrollmentRecord {
    let mut r = enrollment(n, EnrollmentState::Verified);
    r.verified_at = Some(t0());
    r.evidence = fresh_until.map(|fresh_until| EnrollmentEvidence {
        client: "OpenSSH_10.5p1".into(),
        server: "OpenSSH_10.5p1".into(),
        operation: operation.clone(),
        verified_at: t0(),
        fresh_until,
        clock: None,
    });
    r
}

/// A far-future freshness bound.
fn far() -> Timestamp {
    "2100-01-01T00:00:00Z".parse().unwrap()
}

fn doctor_findings(home: &Path, account: &Path, code: &str) -> (Out, Vec<serde_json::Value>) {
    let out = doctor(home, account);
    let found = findings(&out, code);
    (out, found)
}

/// `doctor_reports_enrollment_evidence_stale` (ADR-0008 §17.25 item 13; m03-plan §5
/// item 14): each `verified` enrollment whose evidence is no longer fresh, or has none,
/// is reported with the command that re-verifies it; a fresh one is not, and neither is
/// an enrollment in another state. Read from the store read-only; `--redact` changes
/// nothing in it (no host, user or alias name).
#[test]
fn doctor_reports_enrollment_evidence_stale() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let op = OperationId::from_random_bytes([3; 16]);
    let expired = verified(1, &op, Some(t0()));
    let none = verified(2, &op, None);
    let fresh = verified(3, &op, Some(far()));
    let mut held = verified(4, &op, Some(t0()));
    held.state = EnrollmentState::Held;
    let db = seed_verified(
        &home,
        &[expired.clone(), none.clone(), fresh.clone(), held.clone()],
    );
    let before = std::fs::read(&db).unwrap();
    let (out, stale) = doctor_findings(&home, &account, "enrollment_evidence_stale");
    let ids: Vec<&str> = stale
        .iter()
        .map(|f| f["subject"]["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![expired.id.as_str(), none.id.as_str()], "{out:?}");
    for f in &stale {
        assert_eq!(f["severity"], "warning");
        assert_eq!(f["subject"]["kind"], "enrollment");
        assert_eq!(f["level"], "static");
        assert_eq!(f["next"]["action"], "none");
        let id = f["subject"]["id"].as_str().unwrap();
        let message = f["message"].as_str().unwrap();
        assert!(
            message.contains(&format!("`heimdall enroll verify {id}`")),
            "{message}"
        );
    }
    let first = stale[0]["message"].as_str().unwrap();
    assert!(first.contains(&expired.marker), "{first}");
    assert!(first.contains("dst-lab1"), "{first}");
    assert!(
        first.contains("fresh until 2026-11-01T00:00:00Z"),
        "{first}"
    );
    assert!(
        stale[1]["message"]
            .as_str()
            .unwrap()
            .contains("no verification evidence is recorded"),
        "{out:?}"
    );
    // `--redact` leaves these findings as they are (they carry no name to redact).
    let ssh_home = account.to_string_lossy().into_owned();
    let red = run(
        &home,
        &account,
        &[
            "--json",
            "--non-interactive",
            "doctor",
            "--no-local-exec",
            "--redact",
        ],
        &[("HEIMDALL_TEST_SSH_HOME", &ssh_home)],
    );
    assert_eq!(red.code, 0, "{red:?}");
    assert_eq!(findings(&red, "enrollment_evidence_stale"), stale);
    no_runtime(&home, &out);
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the doctor wrote nothing"
    );
}

/// Append one enrollment event (`state`, by `operation`) for `r`.
fn event(
    tx: &mut heimdall_store::Txn<'_>,
    r: &EnrollmentRecord,
    state: EnrollmentState,
    operation: &OperationId,
) {
    use heimdall_contract::SchemaVersion;
    use heimdall_contract::envelope::ResourceRef;
    use heimdall_contract::event::{Cursor, Event, EventType};
    use heimdall_contract::ids::EventId;
    tx.append_event(&Event {
        schema_version: SchemaVersion::current(),
        event_id: EventId::from_random_bytes([0; 16]),
        event_type: EventType::Enrollment,
        environment_id: environment(),
        operation_id: Some(operation.clone()),
        resource: Some(ResourceRef {
            kind: "enrollment".into(),
            id: Some(r.id.as_str().to_owned()),
        }),
        timestamp: t0(),
        cursor: Cursor(String::new()),
        payload: serde_json::json!({
            "enrollment_id": r.id.as_str(),
            "state": state,
            "operation_id": operation.as_str(),
        }),
    })
    .unwrap();
}

/// Insert a settled `enrollment.verify` operation `id` that failed with `reason`.
fn failed_verify(tx: &mut heimdall_store::Txn<'_>, id: &OperationId, reason: &str) {
    use heimdall_contract::OperationState;
    use heimdall_contract::canonical::RequestHash;
    use heimdall_contract::ids::RequestId;
    use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
    use heimdall_domain::operation::{
        EffectClass, OperationKind, OperationRecord, RecoveryMetadata,
    };
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    let key = IdempotencyKey {
        caller: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        kind: OperationKind::EnrollmentVerify,
        request_id: RequestId::parse(&format!("fixture_{}", id.as_str())).unwrap(),
    };
    let op = OperationRecord {
        id: id.clone(),
        kind: OperationKind::EnrollmentVerify,
        environment: environment(),
        key: key.clone(),
        request_hash: RequestHash([5; 32]),
        effect_class: EffectClass::Local,
        state: OperationState::Failed,
        code: Some(heimdall_contract::Code::CapabilityUnavailable),
        effect_status: heimdall_contract::envelope::EffectStatus::None,
        result: Some(serde_json::json!({"error": {
            "code": "CAPABILITY_UNAVAILABLE",
            "message": "the verification was inconclusive",
            "reason": reason,
        }})),
        created_at: t0(),
        updated_at: t0(),
        cancellation: None,
        recovery: RecoveryMetadata::default(),
    };
    tx.insert_operation(
        &op,
        &IdempotencyRecord {
            key,
            request_hash: op.request_hash,
            operation_id: id.clone(),
            created_at: t0(),
            expires_at: Some(far()),
        },
    )
    .unwrap();
}

/// `doctor_reports_reverification_inconclusive` (ADR-0008 §17.25 item 13; D5 §6.5): a
/// `verified` enrollment whose last re-verification (`reverifying` then `verified`, one
/// operation) kept its earlier evidence is reported, naming the operation, its reason
/// and the command that tries again; one whose re-verification passed (its evidence is
/// that operation's) is not, and neither is one never re-verified. Read from the store
/// (the enrollment events and the operation), read-only.
#[test]
fn doctor_reports_reverification_inconclusive() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let first = OperationId::from_random_bytes([1; 16]);
    let inconclusive_op = OperationId::from_random_bytes([2; 16]);
    let passed_op = OperationId::from_random_bytes([4; 16]);
    let kept = verified(1, &first, Some(far()));
    let passed = verified(2, &passed_op, Some(far()));
    let untouched = verified(3, &first, Some(far()));
    let db = seed_verified(&home, &[kept.clone(), passed.clone(), untouched.clone()]);
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            for r in [&kept, &passed, &untouched] {
                event(tx, r, EnrollmentState::Verifying, &first);
                event(tx, r, EnrollmentState::Verified, &first);
            }
            failed_verify(tx, &inconclusive_op, "destination_clock_skew");
            event(tx, &kept, EnrollmentState::Reverifying, &inconclusive_op);
            event(tx, &kept, EnrollmentState::Verified, &inconclusive_op);
            event(tx, &passed, EnrollmentState::Reverifying, &passed_op);
            event(tx, &passed, EnrollmentState::Verified, &passed_op);
            Ok(())
        })
        .unwrap();
    drop(store);
    let before = std::fs::read(&db).unwrap();
    let (out, found) = doctor_findings(&home, &account, "reverification_inconclusive");
    assert_eq!(found.len(), 1, "{out:?}");
    let f = &found[0];
    assert_eq!(f["subject"]["kind"], "enrollment");
    assert_eq!(f["subject"]["id"], kept.id.as_str());
    assert_eq!(f["severity"], "warning");
    assert_eq!(f["next"]["action"], "none");
    let message = f["message"].as_str().unwrap();
    for needle in [
        kept.marker.as_str(),
        "dst-lab1",
        inconclusive_op.as_str(),
        "(destination_clock_skew)",
        "stays verified",
        "fresh until 2100-01-01T00:00:00Z",
        &format!("`heimdall enroll verify {}`", kept.id.as_str()),
    ] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
    assert!(
        findings(&out, "enrollment_evidence_stale").is_empty(),
        "{out:?}"
    );
    no_runtime(&home, &out);
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the doctor wrote nothing"
    );
}

/// A scratch `PATH` directory whose `ssh` answers `-V` with `OpenSSH_<version>` (and
/// exits 0 for anything else, contacting nothing).
#[cfg(unix)]
fn stub_ssh(dir: &Path, version: &str) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = dir.join("bin");
    dir_mode(&bin, 0o700);
    let ssh = bin.join("ssh");
    std::fs::write(
        &ssh,
        format!("#!/bin/sh\nif [ \"$1\" = \"-V\" ]; then\n  echo 'OpenSSH_{version}, LibreSSL 3.3.6' >&2\nfi\nexit 0\n"),
    )
    .unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    bin.to_string_lossy().into_owned()
}

/// `doctor_reports_client_trace_family_unrecorded` (ADR-0008 §17.25 item 13; D5 §6.5
/// item 5): with an issuer CA registered, a selected `ssh` whose family and version have
/// no row in `heimdall_enroll::trace::RECORDED` is reported, naming both
/// (`portable 9.9p1`); a recorded one (`portable 10.5p1`) is not, nor is an
/// installation with no CA. The version comes from the doctor's own contained `ssh -V`
/// of a scratch stub. Unix only (a shell-script stub; the Windows family is
/// `doctor_cmd::tests::client_trace_finding_names_an_unrecorded_family_and_version`).
#[cfg(unix)]
#[test]
fn doctor_reports_client_trace_family_unrecorded() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let ssh_home = account.to_string_lossy().into_owned();
    let doctor_with = |home: &Path, path: &str| {
        let out = run(
            home,
            &account,
            &["--json", "--non-interactive", "doctor"],
            &[("HEIMDALL_TEST_SSH_HOME", &ssh_home), ("PATH", path)],
        );
        assert_eq!(out.code, 0, "{out:?}");
        out
    };
    let home = scratch.path().join("home");
    let db = seed_state(&home, &[]);
    let before = std::fs::read(&db).unwrap();

    let unrecorded = stub_ssh(&scratch.path().join("old"), "9.9p1");
    let out = doctor_with(&home, &unrecorded);
    let found = findings(&out, "client_trace_family_unrecorded");
    assert_eq!(found.len(), 1, "{out:?}");
    let f = &found[0];
    assert_eq!(f["severity"], "problem");
    assert_eq!(f["subject"]["kind"], "executable");
    assert_eq!(f["subject"]["id"], "ssh");
    assert_eq!(f["next"]["action"], "change_client");
    let message = f["message"].as_str().unwrap();
    assert!(message.contains("portable 9.9p1"), "{message}");
    assert!(message.contains("inconclusive"), "{message}");
    assert!(
        message.contains("portable 10.5p1"),
        "the recorded rows: {message}"
    );
    assert!(!message.contains(&unrecorded), "no path: {message}");

    let recorded = stub_ssh(&scratch.path().join("new"), "10.5p1");
    let out = doctor_with(&home, &recorded);
    assert!(
        findings(&out, "client_trace_family_unrecorded").is_empty(),
        "{out:?}"
    );

    // No CA: managed certificates are not set up, so the trace row does not matter.
    let no_ca = scratch.path().join("no-ca");
    std::fs::create_dir_all(no_ca.join("state")).unwrap();
    drop(Store::open(&no_ca.join("state").join("state.db"), Arc::new(NoFaults)).unwrap());
    let out = doctor_with(&no_ca, &unrecorded);
    assert!(
        findings(&out, "client_trace_family_unrecorded").is_empty(),
        "{out:?}"
    );
    no_runtime(&home, &out);
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the doctor wrote nothing"
    );
}
