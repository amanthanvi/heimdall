//! M03 wave 5 (U12): `e2e_cli_m03` submodule `uninstall_doctor` (owner: see `.m03-wave5-api.md` R1).
//! Shares the parent's `bin()`, `run()` and fixtures through `super::`.
//!
//! * Uninstall (ADR-0008 D4 item 6): the listing of the enrollments that are not final
//!   and the `enroll remove` offer, the purge refusals (`CONFIG_CONFLICT` exit 6 without
//!   the acknowledgement, `bundle_required`/`bundle_redacted` exit 4 without a fresh
//!   bundle), and the K_ca store item's fate. Every case ends **before** any runtime
//!   contact (a runtime the CLI started would wire the account's real `~/.ssh`), and
//!   the state database is never written.
//! * Doctor (m03-plan U12, §5 item 14): `slot_free` with its command and
//!   `managed_dir_unsafe`, read-only and never repaired.
//! * The CLI half of `time_confirmation_after_reboot`: the bare `heimdall` status
//!   without a terminal shows the chore with `heimdall time confirm`.
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
use heimdall_contract::ids::{AccountName, DecisionId, DestinationId, EnvironmentId, IdentityId};
use heimdall_contract::issuer::{
    BundleCa, BundleEnrollment, RECOVERY_BUNDLE_SCHEMA, RecoveryBundle,
};
use heimdall_contract::managed::PreferredMechanism;
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    EnrollmentRecord, EnrollmentState, PairPreference, ProjectionStatus,
};
use heimdall_domain::time::{AttendedTimeConfirmation, BootId};
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

/// `uninstall_purge_keeping_enrollments_requires_fresh_bundle` (F08; D4 item 6): a purge
/// that keeps remote enrollments needs a fresh recovery bundle. A missing file, a file
/// that is not a bundle, one that predates the last enrollment change, one that does not
/// list every remaining enrollment as it is now, and (U-Q1, `BUNDLE_WRITE_RECORD_REQUIRED`)
/// even a fresh complete one without this installation's record of writing it: each is
/// `bundle_required` (exit 4); a redacted one is `bundle_redacted` (exit 4). Nothing is
/// changed and no runtime is contacted.
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
        no_runtime(&home, out);
    };

    let missing = scratch.path().join("missing.json");
    refused(&attempt(&missing), "bundle_required", "cannot be read");

    let garbage = scratch.path().join("garbage.json");
    std::fs::write(&garbage, b"{\"not\": \"a bundle\"}").unwrap();
    refused(
        &attempt(&garbage),
        "bundle_required",
        "not a recovery bundle",
    );

    let stale = scratch.path().join("stale.json");
    write_bundle(
        &stale,
        before_change,
        &[live.clone(), removed.clone()],
        false,
    );
    refused(
        &attempt(&stale),
        "bundle_required",
        "predates the last enrollment change",
    );

    let partial = scratch.path().join("partial.json");
    write_bundle(&partial, after, std::slice::from_ref(&removed), false);
    refused(
        &attempt(&partial),
        "bundle_required",
        "every remaining enrollment",
    );

    let mut changed = live.clone();
    changed.state = EnrollmentState::AppliedUnverified;
    let wrong_state = scratch.path().join("wrong-state.json");
    write_bundle(&wrong_state, after, &[changed], false);
    refused(
        &attempt(&wrong_state),
        "bundle_required",
        "every remaining enrollment",
    );

    let redacted = scratch.path().join("redacted.json");
    write_bundle(&redacted, after, &[live.clone(), removed.clone()], true);
    refused(&attempt(&redacted), "bundle_redacted", "redacted");

    // Fresh and complete by content, but nothing records that this installation wrote it
    // (U-Q1): still refused, fail closed.
    let fresh = scratch.path().join("fresh.json");
    write_bundle(&fresh, after, &[live.clone(), removed.clone()], false);
    refused(
        &attempt(&fresh),
        "bundle_required",
        "no record of writing that bundle",
    );

    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");
    assert!(
        fresh.exists() && redacted.exists(),
        "the bundles are left alone"
    );
}

/// `uninstall_states_store_item_fate` (F08; D4 item 6): the K_ca store item is kept,
/// named with its reason, while an enrollment under its CA is not final; when every one
/// is final, deletion is offered (`heimdall issuer retire <fingerprint>`, the retirement
/// steps behind a typed confirmation) with the reminder to destroy the offline backup;
/// an item whose locator was never recorded is kept (it cannot be deleted by exact
/// identity). Stated in JSON and in the human text.
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

/// Seed an attended time confirmation for boot `boot`.
fn seed_confirmation(home: &Path, boot: &str) {
    let db = seed_state(home, &[]);
    let store = Store::open(&db, Arc::new(NoFaults)).unwrap();
    store
        .transaction(|tx| {
            tx.set_time_confirmation(&AttendedTimeConfirmation {
                boot_id: BootId(boot.to_owned()),
                continuous: Duration::from_secs(60),
                wall: t0(),
                decision: DecisionId::from_random_bytes([9; 16]),
            })
        })
        .unwrap();
}

/// The CLI half of `time_confirmation_after_reboot` (ADR-0008 D9 item 5; m03-plan U12;
/// F14): after a reboot (the store's last time confirmation belongs to another boot) the
/// bare `heimdall` without a terminal shows the pending chore with its one command,
/// `heimdall time confirm`, even with no runtime running (it never starts one); in the
/// confirmed boot it shows none.
#[test]
fn status_shows_time_confirmation_chore_after_reboot() {
    let scratch = tempfile::tempdir().unwrap();
    let account = account(scratch.path());

    let home = scratch.path().join("rebooted");
    seed_confirmation(&home, "boot-before-the-reboot");
    let db = home.join("state").join("state.db");
    let before = std::fs::read(&db).unwrap();
    for args in [&["--json"][..], &["--json", "--non-interactive"][..]] {
        let out = run(&home, &account, args, &[]);
        let env = out.json();
        let chores = env["data"]["chores"]
            .as_array()
            .unwrap_or_else(|| panic!("no chores: {out:?}"));
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
        no_runtime(&home, &out);
    }
    assert_eq!(std::fs::read(&db).unwrap(), before, "nothing was written");

    // Confirmed in this boot: no chore.
    let current = heimdall_runtime::platform::read_boot_id_uncached().unwrap();
    let home = scratch.path().join("confirmed");
    seed_confirmation(&home, &current);
    let out = run(&home, &account, &["--json"], &[]);
    assert!(out.json()["data"].get("chores").is_none(), "{out:?}");
}
