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
//! * ⟨ADR-0008 §17.31 item 1⟩ The purge's instance lock excludes a runtime start-up
//!   (`runtime_start_refused_while_the_purge_lock_is_held`: the one case that runs
//!   `service run`, under the test configuration over a scratch account, refused at the
//!   lock before anything is opened).
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
    EnrollmentEvidence, EnrollmentRecord, EnrollmentState, ForeignRemovalRecord, PairPreference,
    ProjectionStatus,
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
        late_write: r
            .late_write
            .as_ref()
            .map(|l| heimdall_contract::issuer::BundleLateWrite {
                not_after_remote: l.not_after_remote,
            }),
    }
}

/// Write a recovery bundle at `path`, created at `at`, listing `records`.
fn write_bundle(path: &Path, at: Timestamp, records: &[EnrollmentRecord], redacted: bool) {
    write_bundle_with(path, at, records, &[], redacted);
}

/// [`write_bundle`] with the foreign removals `foreign` too (descriptor and state).
fn write_bundle_with(
    path: &Path,
    at: Timestamp,
    records: &[EnrollmentRecord],
    foreign: &[ForeignRemovalRecord],
    redacted: bool,
) {
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
        foreign_removals: foreign
            .iter()
            .map(|f| heimdall_contract::issuer::BundleForeignRemoval {
                marker: f.target.marker.clone(),
                local_alias: f.target.local_alias.clone(),
                bundle_destination_id: f.target.bundle_destination_id.clone(),
                hostname: (!redacted).then(|| f.target.bundle_hostname.clone()),
                port: (!redacted).then_some(f.target.bundle_port),
                account: f.target.account.clone(),
                ca_public_key: f.target.ca_public_key.clone(),
                line_sha256: f.target.line_sha256.clone(),
                registry: f.target.registry.clone(),
                form: f.target.form,
                state: f.state,
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

// --- ADR-0008 §17.27 items 1-3 (W5-R01, W5-R02, W5-S01) ---------------------------------

/// A foreign system-form removal (another installation's enrollment, by its public
/// descriptor), moved `planned → manual_removal_pending → abandoned`: the owner gave it up
/// while its line may still trust that CA (`pending_until_line_removed`).
fn abandoned_foreign(db: &Path) -> ForeignRemovalRecord {
    use heimdall_contract::enrollment::{EnrollmentForm, ForeignRemovalTarget};
    use heimdall_contract::ids::ForeignRemovalId;
    use heimdall_domain::enrollment::{EnrollmentEventKind as K, RegistryResolvedBy};
    let planned = ForeignRemovalRecord {
        id: ForeignRemovalId::from_random_bytes([0x5a; 16]),
        target: ForeignRemovalTarget {
            local_alias: "lab-other".into(),
            bundle_destination_id: "dst-elsewhere".into(),
            bundle_hostname: "example.invalid".into(),
            bundle_port: 22,
            account: AccountName::parse("deploy").unwrap(),
            marker: format!("heimdall:enr_{}", "e".repeat(32)),
            ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIforeign0".into(),
            line_sha256: "cd".repeat(32),
            registry: RegistryCanonical {
                path: None,
                resolved_by: RegistryResolvedBy::RemoteHome,
            },
            form: EnrollmentForm::System,
        },
        state: EnrollmentState::Planned,
        operation: OperationId::from_random_bytes([0x5b; 16]),
        created_at: t0(),
        removal_origin: None,
    };
    let store = Store::open(db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.insert_foreign_removal(&planned)?;
            let pending = tx
                .transition_foreign_removal(
                    EnrollmentState::Planned,
                    K::ManualRemovalConfirmed,
                    &planned,
                )?
                .unwrap();
            Ok(tx
                .transition_foreign_removal(pending.state, K::OwnerAbandon, &pending)?
                .unwrap())
        })
        .unwrap()
}

/// The three purge attempts every outstanding obligation must survive without a bundle:
/// a bare purge (`CONFIG_CONFLICT`, exit 6), one keeping the enrollments without a bundle
/// (`bundle_required`, exit 4), and one with a fresh recorded bundle that does not list
/// the obligation (`bundle_required`, exit 4, `why`). Returns the bare purge's output.
fn purge_refusals(home: &Path, account: &Path, partial: &Path, why: &str) -> Out {
    let purge = ["--json", "--non-interactive", "uninstall", "--purge-state"];
    let bare = run(home, account, &purge, &[]);
    assert_eq!(bare.code, 6, "{bare:?}");
    assert_eq!(bare.json()["code"], "CONFIG_CONFLICT", "{bare:?}");
    assert_eq!(bare.json()["data"]["error"]["effect_status"], "none");
    assert!(bare.message().contains("--purge-state refused"), "{bare:?}");
    let mut keep = purge.to_vec();
    keep.push("--keep-remote-enrollments");
    let out = run(home, account, &keep, &[]);
    assert_eq!(out.code, 4, "{out:?}");
    assert_eq!(out.json()["data"]["error"]["reason"], "bundle_required");
    let arg = partial.to_string_lossy().into_owned();
    keep.extend(["--bundle", &arg]);
    let out = run(home, account, &keep, &[]);
    assert_eq!(out.code, 4, "{out:?}");
    assert_eq!(out.json()["data"]["error"]["reason"], "bundle_required");
    assert!(out.message().contains(why), "{why}: {out:?}");
    no_runtime(home, &out);
    bare
}

/// `uninstall_purge_refuses_abandoned_foreign_system_form_removal` (ADR-0008 §17.27
/// item 1, W5-R01, end to end): an abandoned foreign system-form removal, still
/// `pending_until_line_removed`, is listed by its descriptor (`foreign_removals`, also in
/// the human text) and blocks `--purge-state` without the acknowledgement or a bundle,
/// and with a bundle that does not list it; a fresh recorded bundle listing it in its
/// state is accepted (the purge then stops at its own confirmation). Nothing is written
/// and no runtime is contacted.
#[test]
fn uninstall_purge_refuses_abandoned_foreign_system_form_removal() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(&home, &[EnrollmentState::Removed]);
    let foreign = abandoned_foreign(&db);
    assert_eq!(foreign.state, EnrollmentState::Abandoned);
    let at = t0().checked_add(Duration::from_secs(60)).unwrap();
    let removed = enrollment(1, EnrollmentState::Removed);
    let partial = scratch.path().join("partial.json");
    write_bundle(&partial, at, std::slice::from_ref(&removed), false);
    let full = scratch.path().join("full.json");
    write_bundle_with(
        &full,
        at,
        std::slice::from_ref(&removed),
        std::slice::from_ref(&foreign),
        false,
    );
    record_digest(&db, &partial);
    record_digest(&db, &full);
    let before = std::fs::read(&db).unwrap();

    let bare = purge_refusals(
        &home,
        &account,
        &partial,
        "every outstanding foreign removal",
    );
    let listed = &bare.json()["data"]["foreign_removals"][0];
    assert_eq!(listed["marker"], foreign.target.marker.as_str(), "{bare:?}");
    assert_eq!(listed["state"], "abandoned");
    assert_eq!(listed["form"], "system");
    assert_eq!(listed["local_alias"], "lab-other");
    let human = run(
        &home,
        &account,
        &["--non-interactive", "uninstall", "--purge-state"],
        &[],
    );
    assert_eq!(human.code, 6, "{human:?}");
    assert!(
        human.stdout.contains(&foreign.target.marker)
            && human.stdout.contains("pending_until_line_removed"),
        "{human:?}"
    );

    let arg = full.to_string_lossy().into_owned();
    let out = run(
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
    );
    assert_eq!(
        out.code, 3,
        "accepted, then the purge's own confirmation: {out:?}"
    );
    assert!(
        out.message().contains("--purge-state not confirmed"),
        "{out:?}"
    );
    no_runtime(&home, &out);
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
}

/// `uninstall_purge_refuses_withdrawn_late_write` (ADR-0008 §17.27 item 1, W5-R02, end
/// to end): a `withdrawn` record whose `late_write` residual is unresolved (absence not
/// yet observed after its not-after; one not-after still ahead, one passed) is listed
/// with its residual and blocks the purge like a live enrollment; a bundle listing the
/// record without its residual is refused; one with it is accepted.
#[test]
fn uninstall_purge_refuses_withdrawn_late_write() {
    use heimdall_domain::enrollment::LateWrite;
    let now = Timestamp::now().as_second();
    for (n, not_after) in [(1u8, now + 3600), (2, now - 3600)] {
        let scratch = tempfile::tempdir().unwrap();
        let account = account(scratch.path());
        let home = scratch.path().join("home");
        let db = seed_state(&home, &[]);
        let mut late = enrollment(n, EnrollmentState::Withdrawn);
        late.late_write = Some(LateWrite {
            step_token: "ab".repeat(16),
            not_after_remote: not_after,
        });
        let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
        store.transaction(|tx| tx.seed_enrollment(&late)).unwrap();
        drop(store);
        let at = t0().checked_add(Duration::from_secs(60)).unwrap();
        let mut quiet = late.clone();
        quiet.late_write = None;
        let partial = scratch.path().join("partial.json");
        write_bundle(&partial, at, std::slice::from_ref(&quiet), false);
        let full = scratch.path().join("full.json");
        write_bundle(&full, at, std::slice::from_ref(&late), false);
        record_digest(&db, &partial);
        record_digest(&db, &full);
        let before = std::fs::read(&db).unwrap();

        let bare = purge_refusals(&home, &account, &partial, "every remaining enrollment");
        assert_eq!(markers(&bare), vec![late.marker.clone()], "{bare:?}");
        let listed = &bare.json()["data"]["enrollments"][0];
        assert_eq!(listed["state"], "withdrawn");
        assert_eq!(listed["late_write"]["not_after_remote"], not_after);

        let arg = full.to_string_lossy().into_owned();
        let out = run(
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
        );
        assert_eq!(out.code, 3, "{out:?}");
        no_runtime(&home, &out);
        assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    }
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

// --- the owner's terminal for uninstall (ADR-0008 §17.27 items 2 and 3) ------------------

/// A pty whose session leader runs heimdall with stdin and stderr on the terminal and
/// **stdout in a file**, so a `--json` case can check both what the terminal showed
/// before the prompt and that stdout holds exactly one envelope (as `enroll`'s
/// `terminal`, which puts all three on the pty). The test binary re-executes itself in
/// child mode ([`pty::pty_child`]); its own child is stopped through its `Child`
/// handle only.
#[cfg(unix)]
pub(super) mod pty {
    use std::ffi::{OsStr, OsString};
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    use super::super::bin;

    const SLAVE: &str = "HM_U3_PTY_SLAVE";
    const ARGS: &str = "HM_U3_PTY_ARGS";
    const STDOUT: &str = "HM_U3_PTY_STDOUT";

    /// Child-mode entry; does nothing in a normal run.
    #[test]
    #[ignore = "child-mode entry of the uninstall pty tests, started by them"]
    fn pty_child() {
        let (Some(slave), Some(args), Some(stdout)) = (
            std::env::var_os(SLAVE),
            std::env::var(ARGS).ok(),
            std::env::var_os(STDOUT),
        ) else {
            return;
        };
        rustix::process::setsid().unwrap();
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave)
            .unwrap();
        rustix::process::ioctl_tiocsctty(&tty).unwrap();
        let out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stdout)
            .unwrap();
        rustix::stdio::dup2_stdin(&tty).unwrap();
        rustix::stdio::dup2_stdout(&out).unwrap();
        rustix::stdio::dup2_stderr(&tty).unwrap();
        drop(tty);
        drop(out);
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        heimdall_testkit::term::default_terminal_signals_for_exec().unwrap();
        let err = Command::new(bin())
            .args(args)
            .env_remove("HEIMDALL_E2E_BIN")
            .exec();
        panic!("exec failed: {err}");
    }

    /// A pseudo-terminal holding its slave for its life, its output drained.
    pub struct Pty {
        master: OwnedFd,
        slave_fd: Option<OwnedFd>,
        slave: PathBuf,
        output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Pty {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.slave_fd = None;
        }
    }

    impl Pty {
        pub fn open() -> Pty {
            let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
            grantpt(&master).unwrap();
            unlockpt(&master).unwrap();
            let name = ptsname(&master, Vec::new()).unwrap();
            let slave = PathBuf::from(OsStr::from_bytes(name.as_bytes()));
            let slave_fd = rustix::fs::open(
                &slave,
                rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::termios::tcsetwinsize(
                &slave_fd,
                rustix::termios::Winsize {
                    ws_row: 50,
                    ws_col: 250,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                },
            )
            .unwrap();
            let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader = master.try_clone().unwrap();
            let sink = std::sync::Arc::clone(&output);
            let done = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut f = std::fs::File::from(reader);
                let mut buf = [0u8; 4096];
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    match f.read(&mut buf) {
                        Ok(n) if n > 0 => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        _ => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            });
            Pty {
                master,
                slave_fd: Some(slave_fd),
                slave,
                output,
                stop,
            }
        }

        pub fn write(&self, bytes: &[u8]) {
            use std::io::Write as _;
            let mut f = std::fs::File::from(self.master.try_clone().unwrap());
            f.write_all(bytes).unwrap();
        }

        /// `heimdall <args>` on this terminal with exactly `env`, in `cwd`; its stdout
        /// goes to `stdout` (created; it must not exist).
        pub fn start(
            &self,
            env: &[(OsString, OsString)],
            cwd: &Path,
            args: &[&str],
            stdout: &Path,
        ) -> Child {
            let json = serde_json::to_string(&args).unwrap();
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "uninstall_doctor::pty::pty_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .current_dir(cwd);
            for (k, v) in env {
                cmd.env(k, v);
            }
            cmd.env(SLAVE, &self.slave)
                .env(ARGS, &json)
                .env(STDOUT, stdout)
                .env("HEIMDALL_E2E_BIN", bin())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        }

        pub fn transcript(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        /// Wait until the transcript contains `needle` (the child still running).
        pub fn wait_for(&self, needle: &str, child: &mut Child) {
            let deadline = Instant::now() + Duration::from_secs(90);
            while !self.transcript().contains(needle) {
                if child.try_wait().unwrap().is_some() {
                    std::thread::sleep(Duration::from_millis(150));
                    assert!(
                        self.transcript().contains(needle),
                        "the child exited before {needle:?}: {}",
                        self.transcript()
                    );
                    return;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("no {needle:?} on the terminal: {}", self.transcript());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        /// Wait for the child's exit; its code and the transcript (canary-scanned).
        pub fn finish(&self, child: &mut Child) -> (Option<i32>, String) {
            let deadline = Instant::now() + Duration::from_secs(120);
            let code = loop {
                if let Some(s) = child.try_wait().unwrap() {
                    break s.code();
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the pty child did not exit in time: {}", self.transcript());
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            std::thread::sleep(Duration::from_millis(150));
            let t = self.transcript();
            heimdall_testkit::assert_no_canary(&t);
            assert!(!t.contains("panicked"), "{t}");
            (code, t)
        }
    }

    /// Exactly one envelope in the stdout file: one non-empty line, a JSON object.
    pub fn one_envelope(stdout: &Path) -> serde_json::Value {
        let text = std::fs::read_to_string(stdout).unwrap();
        heimdall_testkit::assert_no_canary(&text);
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "exactly one envelope on stdout: {text:?}");
        serde_json::from_str(lines[0]).unwrap()
    }
}

/// `uninstall_json_shows_the_preview_on_the_terminal` (ADR-0008 §17.27 item 3 for
/// uninstall): `--json uninstall --purge-state` on a real terminal writes the complete
/// human preview to the terminal (stderr) before its typed confirmation: the
/// outstanding obligations (a foreign removal `pending_until_line_removed`, a late
/// write), the K_ca store item's fate and the reminder to destroy the offline backup;
/// stdout holds exactly one envelope. Answering no changes nothing (exit 3, no runtime).
#[cfg(unix)]
#[test]
fn uninstall_json_shows_the_preview_on_the_terminal() {
    use heimdall_domain::enrollment::LateWrite;
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = tempfile::tempdir().unwrap();
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(&home, &[]);
    record_locator(&db);
    let foreign = abandoned_foreign(&db);
    let mut late = enrollment(1, EnrollmentState::Withdrawn);
    late.late_write = Some(LateWrite {
        step_token: "ab".repeat(16),
        not_after_remote: Timestamp::now().as_second() + 3600,
    });
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store.transaction(|tx| tx.seed_enrollment(&late)).unwrap();
    drop(store);
    let bundle = scratch.path().join("bundle.json");
    write_bundle_with(
        &bundle,
        t0().checked_add(Duration::from_secs(60)).unwrap(),
        std::slice::from_ref(&late),
        std::slice::from_ref(&foreign),
        false,
    );
    record_digest(&db, &bundle);
    let before = std::fs::read(&db).unwrap();
    let env: Vec<(std::ffi::OsString, std::ffi::OsString)> = vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), account.clone().into_os_string()),
        ("HEIMDALL_HOME".into(), home.clone().into_os_string()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
    ];
    let arg = bundle.to_string_lossy().into_owned();
    let stdout = scratch.path().join("stdout.json");
    let term = pty::Pty::open();
    let mut child = term.start(
        &env,
        scratch.path(),
        &[
            "--json",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
            "--bundle",
            &arg,
        ],
        &stdout,
    );
    term.wait_for("[y/N]", &mut child);
    let shown = term.transcript();
    let prompt_at = shown.find("[y/N]").unwrap();
    let preview = &shown[..prompt_at];
    for needle in [
        "--purge-state permanently deletes Heimdall's state",
        "Outstanding remote obligations",
        foreign.target.marker.as_str(),
        "pending_until_line_removed",
        late.marker.as_str(),
        "late_write",
        "CA key (K_ca) store items:",
        LOCATOR,
        "deletion offered",
        "destroy the offline backup",
    ] {
        assert!(
            preview.contains(needle),
            "{needle} before the prompt: {preview}"
        );
    }
    assert!(
        !preview.contains("\"schema_version\""),
        "no envelope on the terminal: {preview}"
    );
    term.write(b"no\n");
    let (code, _) = term.finish(&mut child);
    assert_eq!(code, Some(3), "{}", term.transcript());
    let v = pty::one_envelope(&stdout);
    assert_eq!(v["code"], "INTERACTION_REQUIRED", "{v}");
    assert!(no_runtime_started(&home), "nothing was started");
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
}

/// No runtime was started under `home` (no advertisement, no log).
#[cfg(unix)]
fn no_runtime_started(home: &Path) -> bool {
    !home.join("run").join("instance.json").exists()
        && !home.join("log").join("runtime.log").exists()
}

/// `uninstall_purge_race_with_concurrent_enrollment_keeps_state` (ADR-0008 §17.27
/// item 2, W5-S01, the reviewer's two-CLI race): `--json uninstall --purge-state` waits
/// at its typed confirmation on one terminal while a second CLI's `enroll`, approved with
/// a typed yes on another, writes its line through the loopback sshd. The purge's `yes`
/// then takes the uninstall fence, re-reads the inventory, finds the new enrollment and
/// refuses `uninstall_inventory_changed` (exit 4, effect `none`, listing it, naming
/// `heimdall uninstall`): the state database, the enrollment record and the runtime are
/// all still there, and the remote line stays recorded. The fence is lifted after the
/// refusal: a new enrollment request is admitted again (refused only for its own reason,
/// never `uninstall_in_progress`).
#[cfg(unix)]
#[test]
fn uninstall_purge_race_with_concurrent_enrollment_keeps_state() {
    use super::enroll::world::{ALIAS, World};
    let w = World::new();
    // The once-only lock disclosure is already acknowledged here, so the enrollment's
    // approval needs nothing but its typed yes.
    w.tx(|tx| tx.set_lock_disclosure_ack(Timestamp::now()).map(drop));
    let db = w.home.root.join("state").join("state.db");
    assert!(db.exists(), "the in-process runtime's store");
    let out_dir = w.home.scratch().subdir("u3-race").unwrap();
    let reg = w.registry_remote.clone();
    let enrollments = || w.tx(|tx| tx.outstanding_obligations()).enrollments;
    assert!(enrollments().is_empty());

    // 1. The purge waits at its confirmation (the inventory it shows is empty).
    let purge_term = pty::Pty::open();
    let purge_out = out_dir.join("purge.json");
    let mut purge = purge_term.start(
        &w.env(),
        &w.home.root,
        &["--json", "uninstall", "--purge-state"],
        &purge_out,
    );
    purge_term.wait_for("[y/N]", &mut purge);

    // 2. Meanwhile a second CLI enrolls, approved with a typed yes.
    let enroll_term = pty::Pty::open();
    let enroll_out = out_dir.join("enroll.json");
    let mut enroll = enroll_term.start(
        &w.env(),
        &w.home.root,
        &["--json", "enroll", ALIAS, "--registry-path", &reg],
        &enroll_out,
    );
    enroll_term.wait_for("[y/N]", &mut enroll);
    enroll_term.write(b"yes\n");
    let (code, t) = enroll_term.finish(&mut enroll);
    assert!(code.is_some(), "{t}");
    assert_eq!(
        w.marker_lines(),
        1,
        "the enrollment was approved and written: {t}"
    );
    let admitted = enrollments();
    assert_eq!(
        admitted.len(),
        1,
        "one outstanding enrollment: {admitted:?}"
    );

    // 3. The purge is confirmed: fenced, revalidated, refused; nothing deleted.
    purge_term.write(b"yes\n");
    let (code, t) = purge_term.finish(&mut purge);
    assert_eq!(code, Some(4), "{t}");
    let v = pty::one_envelope(&purge_out);
    assert_eq!(v["code"], "CAPABILITY_UNAVAILABLE", "{v}");
    assert_eq!(
        v["data"]["error"]["reason"], "uninstall_inventory_changed",
        "{v}"
    );
    assert_eq!(v["data"]["error"]["effect_status"], "none", "{v}");
    assert_eq!(v["data"]["next_command"], "heimdall uninstall", "{v}");
    assert_eq!(
        v["data"]["enrollments"][0]["marker"],
        admitted[0].marker.as_str(),
        "{v}"
    );
    assert!(db.exists(), "the state database was not deleted");
    assert_eq!(enrollments(), admitted, "the enrollment record is kept");
    assert_eq!(w.marker_lines(), 1, "the remote line is still recorded");
    assert!(
        w.home.root.join("run").join("instance.json").exists(),
        "the runtime was not stopped"
    );

    // 4. The fence was lifted: an enrollment request is admitted again (here refused only
    // because the pair is already enrolled under this CA).
    let again = w.cli(&[
        "--json",
        "--non-interactive",
        "enroll",
        ALIAS,
        "--registry-path",
        &reg,
    ]);
    let v: serde_json::Value = serde_json::from_str(again.stdout.trim()).unwrap();
    assert_ne!(
        v["data"]["error"]["reason"], "uninstall_in_progress",
        "the fence outlived the refused uninstall: {again:?}"
    );
    assert_ne!(v["code"], "SERVICE_UNAVAILABLE", "{again:?}");
}

// --- ADR-0008 §17.28 item 1: the fence's scope, and unresolved remote steps -------------

/// A bare control-endpoint client (the wire of ADR-0006 §2: 4-byte big-endian length,
/// then JSON), so a test can hold the fence on one connection and speak for another;
/// the CLI has no command that only holds the fence.
#[cfg(unix)]
mod raw {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use heimdall_contract::envelope::Envelope;
    use heimdall_contract::ipc::{ClientHello, ClientMessage, PeerInfo, ServerMessage, capability};
    use heimdall_contract::request::{InteractionMode, Request};

    pub struct Raw {
        stream: UnixStream,
        seq: u64,
    }

    impl Raw {
        /// An interactive, attended owner session on `root`'s control endpoint.
        pub fn attended(root: &Path) -> Raw {
            let stream = UnixStream::connect(root.join("run").join("control.sock")).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .unwrap();
            let mut raw = Raw { stream, seq: 0 };
            let caps = [
                capability::OPERATIONS_V1,
                capability::SERVICE_CONTROL_V1,
                capability::ISSUER_V1,
                capability::ENROLLMENT_V1,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            raw.send(&ClientMessage::Hello(ClientHello {
                protocol: heimdall_contract::PROTOCOL_VERSION,
                schema_version: heimdall_contract::SchemaVersion::current(),
                client: PeerInfo {
                    name: "u3-raw-test".into(),
                    version: "0".into(),
                },
                capabilities: caps,
                required: [capability::OPERATIONS_V1.to_owned()].into_iter().collect(),
                interaction: InteractionMode::Interactive,
            }));
            assert!(
                matches!(raw.recv(), ServerMessage::Hello(_)),
                "the runtime accepted the hello"
            );
            raw.seq += 1;
            let seq = raw.seq;
            raw.send(&ClientMessage::Attend { seq });
            let attended = raw.reply(seq);
            assert!(attended.code.is_success(), "{attended:?}");
            raw
        }

        fn send(&mut self, m: &ClientMessage) {
            let body = serde_json::to_vec(m).unwrap();
            let len = u32::try_from(body.len()).unwrap().to_be_bytes();
            self.stream.write_all(&len).unwrap();
            self.stream.write_all(&body).unwrap();
        }

        fn recv(&mut self) -> ServerMessage {
            let mut len = [0u8; 4];
            self.stream.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            self.stream.read_exact(&mut body).unwrap();
            serde_json::from_slice(&body).unwrap()
        }

        fn reply(&mut self, seq: u64) -> Envelope<serde_json::Value> {
            loop {
                if let ServerMessage::Response {
                    in_reply_to,
                    envelope,
                } = self.recv()
                    && in_reply_to == seq
                {
                    heimdall_testkit::assert_no_canary(&serde_json::to_string(&envelope).unwrap());
                    return envelope;
                }
            }
        }

        pub fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            self.seq += 1;
            let seq = self.seq;
            self.send(&ClientMessage::Request { seq, request });
            self.reply(seq)
        }
    }
}

#[cfg(unix)]
fn is_fenced(env: &heimdall_contract::envelope::Envelope<serde_json::Value>) -> bool {
    env.code == heimdall_contract::Code::ServiceUnavailable
        && env.data["error"]["reason"] == "uninstall_in_progress"
}

/// A paused enrollment: `enroll` approved on a pty, its append step dispatched and held
/// at the script's `before_write` point (nothing written yet). Returns the pty, the CLI,
/// its stdout file and the hooks.
#[cfg(unix)]
fn paused_enrollment(
    w: &super::enroll::world::World,
    hooks: &heimdall_testkit::registry::PauseHooks,
    out: &Path,
) -> (pty::Pty, std::process::Child) {
    use heimdall_testkit::registry::hook;
    w.tx(|tx| tx.set_lock_disclosure_ack(Timestamp::now()).map(drop));
    hooks.arm(hook::BEFORE_WRITE).unwrap();
    let mut env = w.env();
    let (k, v) = hooks.env();
    env.push((k.into(), v));
    let reg = w.registry_remote.clone();
    let term = pty::Pty::open();
    let mut child = term.start(
        &env,
        &w.home.root,
        &[
            "--json",
            "enroll",
            super::enroll::world::ALIAS,
            "--registry-path",
            &reg,
        ],
        out,
    );
    term.wait_for("[y/N]", &mut child);
    term.write(b"yes\n");
    hooks
        .wait_at_for(hook::BEFORE_WRITE, Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("no pause at before_write ({e}): {}", term.transcript()));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the CLI waits on the step"
    );
    (term, child)
}

/// `uninstall_purge_refuses_unresolved_remote_step` (ADR-0008 §17.28 item 1, end to
/// end): an enrollment's append step is dispatched and paused remotely (no result yet).
/// `uninstall --purge-state --keep-remote-enrollments` with a fresh recorded bundle
/// listing it is confirmed with a typed yes; under the fence it finds the unresolved
/// step and refuses `uninstall_remote_step_unresolved` (exit 4, effect `none`, naming
/// the operation): the state database and the runtime are kept. Released, the step
/// finishes and writes its line.
#[cfg(unix)]
#[test]
fn uninstall_purge_refuses_unresolved_remote_step() {
    use heimdall_testkit::registry::hook;
    let (w, hooks) = super::enroll::world::World::with_pause();
    let dir = w.home.scratch().subdir("u3-step").unwrap();
    let (enroll_term, mut enroll) = paused_enrollment(&w, &hooks, &dir.join("enroll.json"));
    let outstanding = w.tx(|tx| tx.outstanding_obligations());
    assert_eq!(outstanding.enrollments.len(), 1, "{outstanding:?}");
    let op = outstanding.operations[0].id.clone();
    assert_eq!(
        w.tx(heimdall_app::operations::unresolved_remote_steps),
        vec![op.clone()]
    );
    // A fresh bundle listing the CA and the enrollment as they are, recorded.
    let ca = w.tx(|tx| tx.issuer(w.ca.fingerprint())).unwrap();
    let bundle = RecoveryBundle {
        schema: RECOVERY_BUNDLE_SCHEMA.to_owned(),
        created_at: Timestamp::now()
            .checked_add(Duration::from_secs(60))
            .unwrap(),
        redacted: false,
        cas: vec![BundleCa {
            fingerprint: ca.ca_fingerprint.clone(),
            public_key: ca.public_key.clone(),
            backup_sha256: ca.backup_sha256.clone(),
            backup_created_at: ca.backup_created_at,
            state: ca.state,
        }],
        enrollments: outstanding.enrollments.iter().map(bundle_entry).collect(),
        foreign_removals: Vec::new(),
        instructions: Vec::new(),
    };
    let file = dir.join("bundle.json");
    let bytes = serde_json::to_vec(&bundle).unwrap();
    std::fs::write(&file, &bytes).unwrap();
    let sha = heimdall_issuer::backup::sha256_hex(&bytes);
    w.tx(|tx| tx.record_bundle_digest(&sha, bundle.created_at));
    let db = w.home.root.join("state").join("state.db");

    let arg = file.to_string_lossy().into_owned();
    let purge_out = dir.join("purge.json");
    let term = pty::Pty::open();
    let mut purge = term.start(
        &w.env(),
        &w.home.root,
        &[
            "--json",
            "uninstall",
            "--purge-state",
            "--keep-remote-enrollments",
            "--bundle",
            &arg,
        ],
        &purge_out,
    );
    term.wait_for("[y/N]", &mut purge);
    term.write(b"yes\n");
    let (code, t) = term.finish(&mut purge);
    assert_eq!(code, Some(4), "{t}");
    let v = pty::one_envelope(&purge_out);
    assert_eq!(v["code"], "CAPABILITY_UNAVAILABLE", "{v}");
    assert_eq!(
        v["data"]["error"]["reason"], "uninstall_remote_step_unresolved",
        "{v}"
    );
    assert_eq!(v["data"]["error"]["effect_status"], "none", "{v}");
    assert_eq!(v["data"]["unresolved_steps"][0], op.as_str(), "{v}");
    assert!(db.exists(), "the state database was not deleted");
    assert!(
        w.home.root.join("run").join("instance.json").exists(),
        "the runtime was not stopped"
    );
    // Released, the paused step finishes: its result is recorded (the fence was lifted).
    hooks.disarm(hook::BEFORE_WRITE).unwrap();
    hooks.release(hook::BEFORE_WRITE).unwrap();
    let (_, t) = enroll_term.finish(&mut enroll);
    assert_eq!(w.marker_lines(), 1, "the step wrote its line: {t}");
    assert!(
        w.tx(heimdall_app::operations::unresolved_remote_steps)
            .is_empty(),
        "{t}"
    );
}

/// `uninstall_fence_scope_end_to_end` (ADR-0008 §17.28 item 1): with an enrollment's
/// append step dispatched before the fence and paused remotely, one connection takes
/// the fence. From a second connection, `Step`, `abandon` and issuer `retire` are each
/// refused `uninstall_in_progress`, and so is an approval, while a denial is accepted.
/// The holder's own retirement and its approval are not refused. The pre-fence step's
/// result is accepted and recorded when the script is released (its line written, the
/// journal's step resolved); the CLI's next `Step` is then refused. When the holder's
/// connection closes, the fence is lifted.
#[cfg(unix)]
#[test]
fn uninstall_fence_scope_end_to_end() {
    use heimdall_contract::enrollment::EnrollmentRequest;
    use heimdall_contract::ids::{DecisionId, EnrollmentId};
    use heimdall_contract::issuer::IssuerRequest;
    use heimdall_contract::request::{DecideRequest, Request, UninstallFenceRequest, Verdict};
    use heimdall_testkit::registry::hook;
    let (w, hooks) = super::enroll::world::World::with_pause();
    let dir = w.home.scratch().subdir("u3-scope").unwrap();
    let (enroll_term, mut enroll) = paused_enrollment(&w, &hooks, &dir.join("enroll.json"));
    let outstanding = w.tx(|tx| tx.outstanding_obligations());
    let op = outstanding.operations[0].id.clone();
    let enrollment: EnrollmentId = outstanding.enrollments[0].id.clone();
    let state_at_pause = outstanding.enrollments[0].state;
    let spare = w.add_ca();

    let mut holder = raw::Raw::attended(&w.home.root);
    let held = holder.request(Request::UninstallFence(UninstallFenceRequest::Acquire));
    assert_eq!(held.data["fence"], "held", "{held:?}");
    let mut other = raw::Raw::attended(&w.home.root);
    let retire = || {
        Request::Issuer(IssuerRequest::Retire {
            ca_fingerprint: spare.fingerprint().clone(),
            deleted_locator: None,
        })
    };
    let decide = |id: &str, verdict| {
        Request::Decide(DecideRequest {
            decision_id: DecisionId::parse(id).unwrap(),
            verdict,
        })
    };
    for (what, request) in [
        (
            "step",
            Request::Enrollment(EnrollmentRequest::Step {
                operation_id: op.clone(),
            }),
        ),
        (
            "abandon",
            Request::Enrollment(EnrollmentRequest::Abandon {
                enrollment_id: enrollment.clone(),
            }),
        ),
        ("retire", retire()),
    ] {
        let env = other.request(request);
        assert!(is_fenced(&env), "{what} from a second connection: {env:?}");
    }
    // The holder's retirement is not refused; its decision is approved by the holder,
    // and only refused when another connection approves it.
    let first = holder.request(retire());
    assert!(!is_fenced(&first), "{first:?}");
    let decision = first
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .unwrap_or_else(|| panic!("a retirement decision: {first:?}"));
    let approve = other.request(decide(&decision, Verdict::Approve));
    assert!(
        is_fenced(&approve),
        "an approval from a second connection: {approve:?}"
    );
    let deny = other.request(decide(&decision, Verdict::Deny));
    assert!(
        deny.code.is_success(),
        "a denial from a second connection: {deny:?}"
    );
    let second = holder.request(retire());
    let decision = second
        .next
        .as_ref()
        .and_then(|n| n.decision_ref.clone())
        .unwrap_or_else(|| panic!("a retirement decision: {second:?}"));
    let approved = holder.request(decide(&decision, Verdict::Approve));
    assert!(
        approved.code.is_success(),
        "the holder's approval: {approved:?}"
    );
    let after = w.tx(|tx| tx.issuer(spare.fingerprint())).unwrap();
    assert_ne!(
        after.state,
        heimdall_contract::issuer::CaState::Active,
        "the holder's retirement ran"
    );

    // The step dispatched before the fence reports its result: accepted and recorded.
    hooks.disarm(hook::BEFORE_WRITE).unwrap();
    hooks.release(hook::BEFORE_WRITE).unwrap();
    let (_, t) = enroll_term.finish(&mut enroll);
    assert_eq!(
        w.marker_lines(),
        1,
        "the pre-fence step wrote its line: {t}"
    );
    let now = w.tx(|tx| tx.enrollment(&enrollment)).unwrap();
    assert_ne!(now.state, state_at_pause, "its result was recorded: {t}");
    assert!(
        !w.tx(heimdall_app::operations::unresolved_remote_steps)
            .contains(&op),
        "{t}"
    );
    let cli = std::fs::read_to_string(dir.join("enroll.json")).unwrap_or_default();
    assert!(
        cli.contains("uninstall_in_progress") || t.contains("uninstall_in_progress"),
        "the CLI's next step was refused: {cli} {t}"
    );

    // The holder's connection ends: lifted.
    drop(holder);
    std::thread::sleep(Duration::from_millis(300));
    let env = other.request(Request::Enrollment(EnrollmentRequest::Step {
        operation_id: op,
    }));
    assert!(!is_fenced(&env), "{env:?}");
}

/// `runtime_start_refused_while_the_purge_lock_is_held` (ADR-0008 §17.31 item 1,
/// W5-C01, through the real binary): while this test holds the runtime's instance lock
/// (`<state>/service.lock`, `InstanceLock`, as the purge holds it from its final read
/// through its deletion), `heimdall service run` over the same state fails at once
/// (`SERVICE_UNAVAILABLE`, exit 5) before it opens the state database: the database is
/// byte-identical and nothing is advertised. The runtime runs under the test
/// configuration with a scratch account (`HEIMDALL_TEST_SSH_HOME`, a scratch secret
/// store), never the account's `~/.ssh` or keychain; it is this test's own child, waited
/// for, and stopped through its own handle if it ever outlived the bound.
#[test]
fn runtime_start_refused_while_the_purge_lock_is_held() {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());
    let home = scratch.path().join("home");
    let db = seed_state(&home, &[]);
    let state = home.join("state");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for d in [scratch.path(), home.as_path(), state.as_path()] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let before = std::fs::read(&db).unwrap();
    let lock = heimdall_runtime::InstanceLock::try_acquire(&state).unwrap();
    let mut cmd = Command::new(super::bin());
    cmd.args(["--json", "service", "run"])
        .env_clear()
        .env("HEIMDALL_HOME", &home)
        .env("HOME", &account)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HEIMDALL_TEST_ADAPTER", "prepare")
        .env("HEIMDALL_TEST_SSH_HOME", &account)
        .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
    } else {
        cmd.env("PATH", "/usr/bin:/bin");
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            // Our own unreaped child: its handle names exactly this process.
            let _ = child.kill();
            let _ = child.wait();
            panic!("a runtime start-up got past the held instance lock");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().unwrap();
    drop(lock);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    heimdall_testkit::assert_no_canary(&stdout);
    heimdall_testkit::assert_no_canary(&stderr);
    assert_eq!(out.status.code(), Some(5), "{stdout} {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["code"], "SERVICE_UNAVAILABLE", "{v}");
    assert_eq!(
        std::fs::read(&db).unwrap(),
        before,
        "the start-up wrote nothing"
    );
    assert!(
        !home.join("run").join("instance.json").exists(),
        "nothing was advertised"
    );
}
