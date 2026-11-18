//! ⟨M05⟩ U4: the runtime's workspace observer over real files (ADR-0011 §2.2 "Reading",
//! §2.3; m05-plan U4 "observer integration"; §10 item 9 keeps these cases).
//!
//! Every file is created per run in a scratch directory (`heimdall_testkit::workspace`):
//!
//! * a symlinked path to a root observes the canonical root, with the same identity, and
//!   matches the record made from the real path (`Trusted`);
//! * a manifest that is a symlink, a FIFO (the observation must not hang), a directory,
//!   or a device is refused `manifest_invalid`;
//! * a manifest swapped and rewritten by a concurrent writer is never parsed from bytes
//!   other than those hashed: every observation's access digest equals the digest of the
//!   request it reports;
//! * a root's `FileIdentity` is stable across re-observation and differs for a copy and
//!   for a re-clone at the same path (Unix here; the Windows run covers its
//!   implementation).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use heimdall_app::ports::{ProbeError, ProbedWorkspace, WorkspaceProbe};
use heimdall_contract::Timestamp;
use heimdall_contract::envelope::reason;
use heimdall_contract::ids::{DecisionId, EnvironmentId, ProfileId, WorkspaceId};
use heimdall_contract::project::{Manifest, ManifestAccess, ManifestPreferences};
use heimdall_domain::workspace::{WorkspaceMatch, WorkspaceRecord, WorkspaceState};
use heimdall_project::{FsView, ReadOutcome, access_digest};
use heimdall_runtime::workspace_observe::{RealFs, RealWorkspaceProbe};
use heimdall_testkit::workspace::{Scratch, manifest, write_manifest};

fn env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([7; 16])
}

fn probe(cwd: &Path, records: &[WorkspaceRecord]) -> Result<ProbedWorkspace, ProbeError> {
    RealWorkspaceProbe.probe(&env(), cwd.to_str().unwrap(), records)
}

/// The record an owner's trust of `o` would write.
fn record_of(o: &ProbedWorkspace) -> WorkspaceRecord {
    WorkspaceRecord {
        id: WorkspaceId::from_random_bytes([1; 16]),
        environment: env(),
        root: o.root.clone().unwrap(),
        root_identity: o.root_identity.clone().unwrap(),
        git_common_identity: o.git_common_identity.clone(),
        decision: DecisionId::from_random_bytes([2; 16]),
        created_at: "2026-11-18T09:00:00Z".parse::<Timestamp>().unwrap(),
        state: WorkspaceState::Active,
    }
}

fn manifest_refused(r: Result<ProbedWorkspace, ProbeError>, what: &str) {
    assert_eq!(
        r,
        Err(ProbeError::Manifest {
            reason: reason::MANIFEST_INVALID
        }),
        "{what}"
    );
}

const VALID: &str = "schema_version = 1\n[access]\nprofile = \"dev\"\npairs = [\"h1:deploy\"]\n";

/// A symlinked path to a workspace root is canonicalized: the observation names the real
/// root, with the same identity, and matches the record made through the real path.
#[test]
fn symlinked_root_is_canonicalized() {
    let s = Scratch::new().unwrap();
    let repo = s.init_repo("repo", Some(VALID)).unwrap();
    std::fs::create_dir_all(repo.join("src/deep")).unwrap();
    let real = probe(&repo.join("src/deep"), &[]).unwrap();
    assert_eq!(real.root.as_deref(), repo.to_str());
    assert_eq!(real.matched, Some(WorkspaceMatch::Untrusted));
    let link = s.symlink_dir(&repo, "link-to-repo").unwrap();
    let rec = record_of(&real);
    let via = probe(&link.join("src"), std::slice::from_ref(&rec)).unwrap();
    assert_eq!(via.root, real.root, "the canonical root, not the link");
    assert_eq!(via.root_identity, real.root_identity);
    assert_eq!(
        via.matched,
        Some(WorkspaceMatch::Trusted {
            workspace: rec.id.clone()
        })
    );
    assert_eq!(
        via.manifest.as_ref().map(|m| &m.access_digest),
        real.manifest.as_ref().map(|m| &m.access_digest)
    );
}

/// A manifest that is a symlink (even to a valid manifest), a FIFO, a directory or a
/// device is refused `manifest_invalid`, and observing a FIFO never blocks.
#[test]
fn symlinked_fifo_directory_and_device_manifests_are_refused() {
    let s = Scratch::new().unwrap();
    // A symlink to a valid manifest elsewhere.
    let target = s.path("elsewhere.toml");
    std::fs::write(&target, VALID).unwrap();
    let a = s.init_repo("symlinked", None).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, a.join(".heimdall.toml")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, a.join(".heimdall.toml")).unwrap();
    manifest_refused(probe(&a, &[]), "symlinked manifest");
    // A directory named `.heimdall.toml`.
    let b = s.init_repo("directory", None).unwrap();
    std::fs::create_dir(b.join(".heimdall.toml")).unwrap();
    manifest_refused(probe(&b, &[]), "directory manifest");
    #[cfg(unix)]
    {
        // A FIFO: the observation returns (on another thread, bounded) and refuses it.
        let c = s.init_repo("fifo", None).unwrap();
        heimdall_testkit::workspace::make_fifo(&c.join(".heimdall.toml")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let cwd = c.clone();
        std::thread::spawn(move || {
            let _ = tx.send(probe(&cwd, &[]));
        });
        let r = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("observing a FIFO manifest must not block");
        manifest_refused(r, "FIFO manifest");
        // The reader itself on a FIFO and on a device: not a regular file, no block.
        assert_eq!(
            RealFs
                .read_regular_nofollow(&c.join(".heimdall.toml"), 1024)
                .unwrap(),
            ReadOutcome::NotRegular
        );
        assert_eq!(
            RealFs
                .read_regular_nofollow(Path::new("/dev/null"), 1024)
                .unwrap(),
            ReadOutcome::NotRegular,
            "a device is not a regular file"
        );
        // A symlink as the last component, read directly: never followed.
        assert_eq!(
            RealFs
                .read_regular_nofollow(&a.join(".heimdall.toml"), 1024)
                .unwrap(),
            ReadOutcome::NotRegular
        );
    }
    // The bound: one byte more than allowed is `TooLarge`, read from the same handle.
    let big = s.path("big.toml");
    std::fs::write(&big, vec![b'#'; 65]).unwrap();
    assert_eq!(
        RealFs.read_regular_nofollow(&big, 64).unwrap(),
        ReadOutcome::TooLarge
    );
    assert_eq!(
        RealFs.read_regular_nofollow(&big, 65).unwrap(),
        ReadOutcome::Bytes(vec![b'#'; 65])
    );
}

/// The digest a probed manifest's own request hashes to (the parser's `access_digest`
/// over the reported fields).
fn digest_of_reported(m: &heimdall_app::ports::ProbedManifest) -> String {
    access_digest(&Manifest {
        schema_version: 1,
        project: None,
        access: ManifestAccess {
            profile: ProfileId::parse(m.profile.as_str()).unwrap(),
            pairs: m.pairs.clone(),
            environments: m.environments.clone(),
            required_capabilities: m.capabilities.clone(),
        },
        preferences: ManifestPreferences {
            background_work: Some(m.background_work),
        },
        metadata: Default::default(),
    })
}

/// A manifest swapped (atomic renames) and rewritten in place (truncate and write) by a
/// concurrent writer, observed repeatedly: every observation that parsed reports the
/// digest of exactly the request it parsed, never another version's (the bytes hashed
/// are the bytes parsed).
#[test]
fn a_concurrently_swapped_manifest_is_never_parsed_from_other_bytes_than_hashed() {
    let s = Scratch::new().unwrap();
    let a = manifest("swap", "dev", &["h1:deploy"], false);
    let b = manifest(
        "swap",
        "dev",
        &["h2:deploy", "h3:deploy", "h4:deploy", "h5:deploy"],
        true,
    );
    let repo = s.init_repo("swap", Some(&a)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let (stop, repo) = (Arc::clone(&stop), repo.clone());
        let (a, b) = (a.clone(), b.clone());
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let text = if n.is_multiple_of(2) { &a } else { &b };
                if n.is_multiple_of(3) {
                    // In place: truncate, then write (readers may see a prefix).
                    let _ = write_manifest(&repo, text);
                } else {
                    let tmp = repo.join(".heimdall.toml.tmp");
                    if std::fs::write(&tmp, text).is_ok() {
                        let _ = std::fs::rename(&tmp, repo.join(".heimdall.toml"));
                    }
                }
                n += 1;
            }
        })
    };
    let mut parsed = 0;
    let (mut saw_a, mut saw_b) = (false, false);
    let digest_a = heimdall_project::parse_manifest(a.as_bytes())
        .unwrap()
        .access_digest;
    let digest_b = heimdall_project::parse_manifest(b.as_bytes())
        .unwrap()
        .access_digest;
    for _ in 0..2000 {
        match probe(&repo, &[]) {
            Ok(o) => {
                let Some(m) = o.manifest else {
                    // Between the unlink of a rename and its replacement no manifest is
                    // seen only if discovery raced the swap: then there is nothing parsed.
                    continue;
                };
                parsed += 1;
                assert_eq!(
                    m.access_digest,
                    digest_of_reported(&m),
                    "the digest describes exactly the parsed request: {m:?}"
                );
                saw_a |= m.access_digest == digest_a;
                saw_b |= m.access_digest == digest_b;
            }
            // A torn in-place write parses as invalid: refused, never mixed.
            Err(ProbeError::Manifest { .. } | ProbeError::Io) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    assert!(parsed > 0, "some observations parsed a manifest");
    assert!(
        saw_a && saw_b,
        "both versions were observed: a={saw_a} b={saw_b}"
    );
}

/// A root's identity is stable across re-observation, and differs for a `cp -R` copy and
/// for a re-clone at the same path (Unix in this run).
#[test]
fn file_identity_is_stable_and_differs_for_a_copy_and_a_reclone() {
    let s = Scratch::new().unwrap();
    let repo = s.init_repo("origin", Some(VALID)).unwrap();
    let first = probe(&repo, &[]).unwrap();
    let again = probe(&repo, &[]).unwrap();
    assert!(
        first.root_identity.is_some(),
        "this filesystem has identities"
    );
    assert_eq!(first.root_identity, again.root_identity, "stable");
    assert_eq!(first.git_common_identity, again.git_common_identity);
    let copy = s.copy_tree(&repo, "copy").unwrap();
    let copied = probe(&copy, std::slice::from_ref(&record_of(&first))).unwrap();
    assert_ne!(
        copied.root_identity, first.root_identity,
        "a copy is another file"
    );
    assert_eq!(copied.matched, Some(WorkspaceMatch::Untrusted));
    // A re-clone at the same path: same root, another identity (ambiguous).
    let upstream = s.init_repo("upstream", Some(VALID)).unwrap();
    let target = s.clone_repo(&upstream, "target").unwrap();
    let before = probe(&target, &[]).unwrap();
    let rec = record_of(&before);
    let again = s.reclone_at(&upstream, &target).unwrap();
    let after = probe(&again, std::slice::from_ref(&rec)).unwrap();
    assert_eq!(after.root, before.root);
    assert_ne!(after.root_identity, before.root_identity);
    assert!(
        matches!(after.matched, Some(WorkspaceMatch::Ambiguous { .. })),
        "{:?}",
        after.matched
    );
}

/// ⟨Integrator, W2; the W1 Windows run's follow-up⟩ A working directory written in another
/// letter case names the same workspace on a case-insensitive filesystem (macOS APFS by
/// default, Windows NTFS): the observer's canonicalization returns the on-disk case, so the
/// observed root is the recorded root, byte for byte, with the same identity, and matches
/// the record as `Trusted`, never `Ambiguous{SameIdentityOtherPath}` (which would ask the
/// owner to reconcile a workspace that never moved). On a case-sensitive filesystem the
/// variant is another path, which does not exist here, and the test says so.
#[test]
fn a_case_variant_working_directory_observes_the_recorded_root() {
    let s = Scratch::new().unwrap();
    let repo = s.init_repo("CaseRepo", Some(VALID)).unwrap();
    std::fs::create_dir_all(repo.join("Src")).unwrap();
    let real = probe(&repo.join("Src"), &[]).unwrap();
    let rec = record_of(&real);
    let variant = repo.with_file_name("cASErEPO").join("sRC");
    if !variant.exists() {
        // A case-sensitive filesystem (Linux): the variant is another path, absent here.
        return;
    }
    let via = probe(&variant, std::slice::from_ref(&rec)).unwrap();
    assert_eq!(via.root, real.root, "the on-disk case, as recorded");
    assert_eq!(via.root_identity, real.root_identity);
    assert_eq!(
        via.matched,
        Some(WorkspaceMatch::Trusted {
            workspace: rec.id.clone()
        })
    );
}
