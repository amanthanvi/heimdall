//! m03-plan U4 store, backup, ceremony-logic, retirement, uninstall-plan and bundle
//! tests (hosted by heimdall-issuer; ADR-0008 D1, D4, D13).
//!
//! The ceremonies run here against a scripted terminal ([`ScriptedTty`]) and a fake
//! owner session ([`FakeSession`]) standing in for U12's CLI and U10's runtime (the
//! real CLI → `issuer.register` → `Decide` path needs U10/U12); the pty ceremonies
//! are in `tests/e2e/issuer_ceremony.rs`. Every key, passphrase, keychain and blob is
//! created per run in a scratch directory and removed with it. The macOS keychain
//! rows use a disposable **file** keychain created by path, never on the search list
//! (mechanism evidence only); the search list's digest is compared before and after.

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::enrollment::{
    DisclosureKind, EnrollmentForm, EnrollmentState, EnrollmentView, RegistryRef,
    RegistryResolvedBy, TargetSummary,
};
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DecisionId, DestinationId, EnrollmentId, IdentityId,
};
use heimdall_contract::issuer::{
    BundleEnrollment, CaState, CaStatus, EnrollmentCounts, IssuerState, IssuerStatus,
    RECOVERY_BUNDLE_SCHEMA, RecoveryBundle, StoreKind,
};
use heimdall_contract::managed::IssuerIsolation;
use heimdall_credential::cert::SecretCaKey;
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentRecord, ExistingAccessRecord, LateWrite, NoProxy,
    RegistryCanonical, marker_for,
};
use heimdall_domain::issuance::CaEvent;
use heimdall_issuer::backup::{self, BackupError, Interrupted, Passphrase, WriteProbe, sha256_hex};
use heimdall_issuer::bundle::{self, EnrollmentEntry, Redaction, StoreView};
use heimdall_issuer::ceremony::{
    self, CeremonyError, CeremonyProbe, CrashPoint, InitOptions, OwnerSession, RegisterDecision,
    RegisterRequest, ReplaceOrphanOptions, RestoreOptions, Restored, SessionError, Tty,
};
use heimdall_issuer::retire::{self, RetireError, StoreEffects, StoreFate};
use heimdall_issuer::store::attributes::{
    ATTR_ENVIRONMENT, ATTR_FINGERPRINT, AttrItem, AttributeBackend, AttributeStore,
};
use heimdall_issuer::store::{
    SecretStore, SecretStoreKind, StoreAvailability, StoreError, StoreItemRef,
};
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::scratch_store::{SCRATCH_TEST, ScratchSecretStore};
use ssh_key::{HashAlg, PublicKey};
use zeroize::Zeroizing;

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

fn t0() -> Timestamp {
    "2026-11-01T00:00:00Z".parse().unwrap()
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("hm-u4-store-")
        .tempdir()
        .unwrap()
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Every file under `dir` whose bytes contain `needle`.
fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| {
            std::fs::read(p)
                .map(|b| b.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
        })
        .collect()
}

/// A terminal that answers from a script and records what was written.
#[derive(Default)]
struct ScriptedTty {
    lines: VecDeque<String>,
    hidden: VecDeque<String>,
    transcript: String,
    hidden_reads: usize,
}

impl ScriptedTty {
    fn answering(lines: &[&str]) -> Self {
        Self {
            lines: lines.iter().map(|s| (*s).to_owned()).collect(),
            ..Self::default()
        }
    }

    fn with_hidden(mut self, hidden: &str) -> Self {
        self.hidden.push_back(hidden.to_owned());
        self
    }

    /// The passphrase as the ceremony displayed it (groups of five), joined.
    fn shown_passphrase(&self) -> Option<String> {
        let marker = "without the spaces):\n\n    ";
        let at = self.transcript.find(marker)? + marker.len();
        let line = self.transcript[at..].lines().next()?;
        Some(line.split(' ').collect())
    }
}

impl Tty for ScriptedTty {
    fn write_text(&mut self, text: &str) -> io::Result<()> {
        self.transcript.push_str(text);
        Ok(())
    }

    fn read_line(&mut self) -> io::Result<Option<Zeroizing<String>>> {
        Ok(self.lines.pop_front().map(|l| {
            self.transcript.push_str(&l);
            self.transcript.push('\n');
            Zeroizing::new(l)
        }))
    }

    fn read_hidden(&mut self) -> io::Result<Option<Zeroizing<String>>> {
        self.hidden_reads += 1;
        Ok(self.hidden.pop_front().map(Zeroizing::new))
    }

    fn clear_lines(&mut self, lines: usize) -> io::Result<()> {
        self.transcript.push_str(&format!("<clear {lines}>"));
        Ok(())
    }
}

/// What the fake runtime saw.
#[derive(Default)]
struct SessionLog {
    attended: usize,
    registered: Vec<RegisterRequest>,
    approved: Vec<DecisionId>,
    unlocks: usize,
}

/// The owner session's fake: a runtime that answers `register` with a
/// `RegisterIssuer` decision naming the request's CA and digest, and on `approve`
/// records the CA (`pending` for a rotation, else `active`).
struct FakeSession {
    status: IssuerStatus,
    pending: Vec<(RegisterDecision, RegisterRequest)>,
    log: Rc<RefCell<SessionLog>>,
    next: u8,
}

fn empty_status() -> IssuerStatus {
    IssuerStatus {
        state: IssuerState::NotInitialized,
        reason: None,
        cas: Vec::new(),
        orphan_store_items: Vec::new(),
        issuer_isolation: IssuerIsolation::SameUserProcess,
        bundle_stale: false,
    }
}

fn fingerprint_of(public_openssh: &str) -> CaFingerprint {
    let fp = ceremony::public_key_fingerprint(public_openssh).unwrap();
    let key = PublicKey::from_openssh(public_openssh).unwrap();
    assert_eq!(fp.as_str(), key.fingerprint(HashAlg::Sha256).to_string());
    fp
}

fn ca_status(fp: &CaFingerprint, state: CaState) -> CaStatus {
    CaStatus {
        fingerprint: fp.clone(),
        state,
        // The fake's display value: a test-configuration store has no public kind
        // (S3); the ceremony never reads this field.
        store: StoreKind::WindowsDpapi,
        backup_sha256: "00".repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        enrollments: EnrollmentCounts::default(),
        store_locator: None,
    }
}

impl FakeSession {
    fn new() -> (Self, Rc<RefCell<SessionLog>>) {
        let log = Rc::new(RefCell::new(SessionLog::default()));
        (
            Self {
                status: empty_status(),
                pending: Vec::new(),
                log: Rc::clone(&log),
                next: 1,
            },
            log,
        )
    }

    fn with_ca(mut self, fp: &CaFingerprint, state: CaState) -> Self {
        self.status.cas.push(ca_status(fp, state));
        self
    }
}

impl OwnerSession for FakeSession {
    fn attend(&mut self) -> Result<(), SessionError> {
        self.log.borrow_mut().attended += 1;
        Ok(())
    }

    fn status(&mut self) -> Result<IssuerStatus, SessionError> {
        Ok(self.status.clone())
    }

    fn register(&mut self, request: &RegisterRequest) -> Result<RegisterDecision, SessionError> {
        self.log.borrow_mut().registered.push(request.clone());
        // ⟨§17.22 item 12⟩ As the runtime: the same registration with its store-item
        // report joins the pending decision, which records the locator once.
        let bare = |r: &RegisterRequest| RegisterRequest {
            store_locator: None,
            ..r.clone()
        };
        if let Some((d, pending)) = self.pending.iter_mut().find(|(_, r)| {
            bare(r) == bare(request)
                && (r.store_locator.is_none() || r.store_locator == request.store_locator)
        }) {
            if request.store_locator.is_some() {
                pending.store_locator.clone_from(&request.store_locator);
            }
            return Ok(d.clone());
        }
        let mut disclosures = vec![
            DisclosureKind::SameUserIssuerBoundary,
            DisclosureKind::CaTrustBlastRadius,
            DisclosureKind::BackupInstructions,
        ];
        if request.restored_without_log {
            disclosures.push(DisclosureKind::RestoredWithoutLogResidualsUnknown);
        }
        let decision = RegisterDecision {
            decision_id: DecisionId::from_random_bytes([self.next; 16]),
            ca_fingerprint: fingerprint_of(&request.ca_public_key),
            backup_sha256: request.backup_sha256.clone(),
            disclosures,
        };
        self.next += 1;
        self.pending.push((decision.clone(), request.clone()));
        Ok(decision)
    }

    fn approve(&mut self, decision: &DecisionId) -> Result<(), SessionError> {
        let Some(at) = self
            .pending
            .iter()
            .position(|(d, _)| d.decision_id == *decision)
        else {
            return Err(SessionError::Refused {
                code: Code::DecisionStale,
                reason: None,
            });
        };
        let (d, request) = self.pending.remove(at);
        // ⟨§17.22 item 12⟩ A known CA: the restore's compare-and-swap.
        if let Some(ca) = self
            .status
            .cas
            .iter_mut()
            .find(|c| c.fingerprint == d.ca_fingerprint)
        {
            if ca.store_locator != request.expected_store_locator {
                return Err(SessionError::Refused {
                    code: Code::ConfigConflict,
                    reason: None,
                });
            }
            ca.store_locator.clone_from(&request.store_locator);
            self.log.borrow_mut().approved.push(decision.clone());
            return Ok(());
        }
        let state = if request.rotation_of.is_some() {
            CaState::Pending
        } else {
            CaState::Active
        };
        let mut ca = ca_status(&d.ca_fingerprint, state);
        ca.backup_sha256 = request.backup_sha256.clone();
        ca.backup_created_at = request.backup_created_at;
        ca.restored_without_log = request.restored_without_log;
        ca.store_locator.clone_from(&request.store_locator);
        self.status.cas.push(ca);
        self.status.state = IssuerState::Ready;
        self.log.borrow_mut().approved.push(decision.clone());
        Ok(())
    }

    fn unlock(&mut self) -> Result<IssuerStatus, SessionError> {
        self.log.borrow_mut().unlocks += 1;
        Ok(self.status.clone())
    }
}

/// Stops a ceremony at one crash point.
struct StopAt(CrashPoint);

impl WriteProbe for StopAt {}

impl CeremonyProbe for StopAt {
    fn at(&mut self, point: CrashPoint) -> Result<(), Interrupted> {
        if point == self.0 {
            Err(Interrupted)
        } else {
            Ok(())
        }
    }
}

/// Stops the backup write half way, as a crash would.
struct CrashMidWrite;

impl WriteProbe for CrashMidWrite {
    fn partial(&mut self, _path: &Path, _written: usize) -> Result<(), Interrupted> {
        Err(Interrupted)
    }
}

impl CeremonyProbe for CrashMidWrite {}

/// Corrupts the written backup before it is read back.
struct CorruptBeforeReadBack;

impl WriteProbe for CorruptBeforeReadBack {
    fn before_read_back(&mut self, path: &Path) {
        let mut bytes = std::fs::read(path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(path, bytes).unwrap();
    }
}

impl CeremonyProbe for CorruptBeforeReadBack {}

/// The answers a complete init needs: `yes`, then `written`.
const YES_WRITTEN: &[&str] = &["yes", "written"];

struct Rig {
    dir: tempfile::TempDir,
    store: ScratchSecretStore,
}

impl Rig {
    fn new() -> Self {
        let dir = scratch();
        std::fs::create_dir(dir.path().join("store")).unwrap();
        let store = ScratchSecretStore::new(dir.path().join("store"));
        Self { dir, store }
    }

    fn backup_out(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn options(path: &Path) -> InitOptions<'_> {
    InitOptions {
        backup_out: path,
        non_interactive: false,
    }
}

// -----------------------------------------------------------------------------
// Stores
// -----------------------------------------------------------------------------

#[test]
fn scratch_store_round_trip() {
    let dir = scratch();
    let store = ScratchSecretStore::new(dir.path());
    assert_eq!(store.kind(), SecretStoreKind::Test(SCRATCH_TEST));
    assert_eq!(store.kind().product(), None);
    assert_eq!(store.availability(), StoreAvailability::Available);
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let item = store.put(&fp, &key).unwrap();
    assert_eq!(item.fingerprint, fp);
    assert_eq!(item.kind, store.kind());
    // put never overwrites.
    assert_eq!(store.put(&fp, &key).err(), Some(StoreError::AlreadyExists));
    // A second instance (another process of the run) reads it back.
    let other = ScratchSecretStore::new(dir.path());
    assert!(other.get(&fp).unwrap().same_key(&key));
    assert_eq!(other.list().unwrap(), vec![item.clone()]);
    // No plaintext: the item file is the D5 form, not the store's PEM.
    let secret = key.to_secret_bytes().unwrap();
    assert!(files_containing(dir.path(), &secret).is_empty());
    let item_bytes = std::fs::read(store.item_path(&fp)).unwrap();
    assert!(String::from_utf8_lossy(&item_bytes).contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(
        SecretCaKey::from_secret_bytes(&item_bytes).is_err(),
        "encrypted"
    );
    // Delete is by exact identity only.
    let mut wrong = item.clone();
    wrong.locator.push('x');
    assert_eq!(store.delete(&wrong), Err(StoreError::Failed));
    store.delete(&item).unwrap();
    assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
    assert_eq!(store.list().unwrap(), Vec::new());
    assert_eq!(store.delete(&item), Err(StoreError::NotFound));
}

/// Builds a store under a scratch root.
type MakeStore = Box<dyn Fn(&Path) -> Box<dyn SecretStore>>;

#[test]
fn no_plaintext_when_store_unavailable() {
    let unavailable: Vec<StoreAvailability> = StoreAvailability::ALL
        .into_iter()
        .filter(|a| *a != StoreAvailability::Available)
        .collect();
    // Each store kind this host can build, in each unavailability it can be put in.
    let mut cases: Vec<(String, MakeStore, StoreAvailability)> = Vec::new();
    for a in unavailable.iter().copied() {
        cases.push((
            format!("scratch_test/{}", a.as_str()),
            Box::new(move |root: &Path| {
                Box::new(ScratchSecretStore::with_availability(root.join("store"), a))
                    as Box<dyn SecretStore>
            }),
            a,
        ));
    }
    #[cfg(target_os = "macos")]
    cases.push((
        "macos_login_keychain/missing".into(),
        Box::new(|root: &Path| {
            Box::new(
                heimdall_issuer::store::MacosLoginKeychain::disposable_file_keychain(
                    root.join("absent.keychain-db"),
                    &env_id(),
                ),
            ) as Box<dyn SecretStore>
        }),
        StoreAvailability::Missing,
    ));
    #[cfg(windows)]
    cases.push((
        "windows_dpapi/corrupt".into(),
        Box::new(|root: &Path| {
            let not_a_dir = root.join("issuer");
            std::fs::write(&not_a_dir, b"not a directory").unwrap();
            Box::new(heimdall_issuer::store::WindowsDpapi::in_dir(
                not_a_dir,
                &env_id(),
            )) as Box<dyn SecretStore>
        }),
        StoreAvailability::Corrupt,
    ));
    for (name, make, expected) in &cases {
        let root = scratch();
        let dirs: Vec<PathBuf> = ["state", "data", "config", "runtime"]
            .iter()
            .map(|d| root.path().join(d))
            .collect();
        for d in &dirs {
            std::fs::create_dir(d).unwrap();
        }
        let store = make(root.path());
        let before = files_under(root.path());
        assert_eq!(store.availability(), *expected, "{name}");
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        // The store itself refuses, writing nothing.
        match store.put(&fp, &key) {
            Err(StoreError::Unavailable(a)) => assert_eq!(a, *expected, "{name}"),
            other => panic!("{name}: put gave {:?}", other.map(|i| i.locator)),
        }
        // The ceremony refuses before generating anything.
        let (mut session, log) = FakeSession::new();
        let mut tty = ScriptedTty::answering(YES_WRITTEN);
        let out = root.path().join("backup.key");
        let err = ceremony::init(&mut tty, &mut session, store.as_ref(), &options(&out))
            .err()
            .unwrap();
        assert_eq!(err, CeremonyError::StoreUnavailable(*expected), "{name}");
        assert_eq!(err.code(), Code::CapabilityUnavailable, "{name}");
        assert_eq!(
            err.reason().as_deref(),
            expected.refusal_reason(),
            "{name}: CAPABILITY_UNAVAILABLE carries the reason"
        );
        assert!(err.reason().is_some());
        assert!(log.borrow().registered.is_empty(), "{name}");
        assert!(!out.exists(), "{name}");
        for d in &dirs {
            assert!(
                files_under(d).is_empty(),
                "{name}: a file appeared in {d:?}"
            );
        }
        assert_eq!(files_under(root.path()), before, "{name}: no file appeared");
        let secret = key.to_secret_bytes().unwrap();
        assert!(files_containing(root.path(), &secret).is_empty(), "{name}");
    }
    // macOS: the product keychain code path on a locked disposable file keychain.
    #[cfg(target_os = "macos")]
    macos::locked_keychain_writes_nothing();
    // Linux: the product store with no session bus (the headless devbox's product
    // behaviour), in a child whose bus address is a scratch path, so the owner's
    // session bus and its Secret Service are never contacted.
    #[cfg(target_os = "linux")]
    linux::no_session_bus_writes_nothing();
}

fn env_id() -> heimdall_contract::ids::EnvironmentId {
    heimdall_contract::ids::EnvironmentId::from_random_bytes([7; 16])
}

// -----------------------------------------------------------------------------
// Backup
// -----------------------------------------------------------------------------

#[test]
fn backup_out_existing_file_refused() {
    let rig = Rig::new();
    let out = rig.backup_out("exists.key");
    std::fs::write(&out, b"the owner's file").unwrap();
    // The backup primitive refuses an existing entry and leaves it untouched.
    let key = SecretCaKey::generate().unwrap();
    let pass = Passphrase::generate().unwrap();
    let prepared = backup::prepare(&key, &pass).unwrap();
    assert_eq!(
        backup::write_exact(&out, &prepared).err(),
        Some(BackupError::Exists)
    );
    // A symbolic link at the name is an existing entry too, never followed.
    #[cfg(unix)]
    {
        let target = rig.backup_out("link-target");
        let link = rig.backup_out("link.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            backup::write_exact(&link, &prepared).err(),
            Some(BackupError::Exists)
        );
        assert!(!target.exists());
    }
    // The ceremony refuses it before registering anything.
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let err = ceremony::init(&mut tty, &mut session, &rig.store, &options(&out))
        .err()
        .unwrap();
    assert_eq!(err, CeremonyError::BackupOutExists);
    assert_eq!(err.code(), Code::UsageError);
    assert_eq!(std::fs::read(&out).unwrap(), b"the owner's file");
    assert!(log.borrow().registered.is_empty());
    assert_eq!(rig.store.list().unwrap(), Vec::new());
}

#[test]
fn wrong_passphrase_restore_refused() {
    let rig = Rig::new();
    let key = SecretCaKey::generate().unwrap();
    let pass = Passphrase::generate().unwrap();
    let out = rig.backup_out("ca.key");
    backup::write_exact(&out, &backup::prepare(&key, &pass).unwrap()).unwrap();
    let wrong = Passphrase::generate().unwrap();
    assert_eq!(
        backup::restore(&out, &wrong).err(),
        Some(BackupError::WrongPassphrase)
    );
    // The right one, typed in its groups, restores.
    let typed = Passphrase::new(Zeroizing::new(pass.grouped().to_lowercase()));
    assert!(backup::restore(&out, &typed).unwrap().same_key(&key));
    // The ceremony: a wrong typed passphrase stores and registers nothing.
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(&["yes"]).with_hidden(wrong.expose());
    let err = ceremony::restore(
        &mut tty,
        &mut session,
        &rig.store,
        &RestoreOptions {
            backup: &out,
            not_stolen: true,
            non_interactive: false,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::Backup(BackupError::WrongPassphrase));
    assert_eq!(err.code(), Code::UsageError);
    assert_eq!(tty.hidden_reads, 1, "typed with echo off");
    assert!(log.borrow().registered.is_empty());
    assert_eq!(rig.store.list().unwrap(), Vec::new());
}

#[test]
fn backup_write_mismatch_stops_before_store() {
    let rig = Rig::new();
    let out = rig.backup_out("ca.key");
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let err = ceremony::init_probed(
        &mut tty,
        &mut session,
        &rig.store,
        &options(&out),
        &mut CorruptBeforeReadBack,
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::Backup(BackupError::Mismatch));
    // Registered (step 3) but nothing stored, the passphrase never shown, nothing
    // approved.
    assert_eq!(log.borrow().registered.len(), 1);
    assert!(log.borrow().approved.is_empty());
    assert_eq!(rig.store.list().unwrap(), Vec::new());
    assert!(tty.shown_passphrase().is_none());
}

// -----------------------------------------------------------------------------
// Ceremonies (logic; the pty runs are in e2e_issuer_ceremony)
// -----------------------------------------------------------------------------

#[test]
fn registered_digest_is_the_written_backup() {
    let rig = Rig::new();
    let out = rig.backup_out("ca.key");
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let done = ceremony::init(&mut tty, &mut session, &rig.store, &options(&out)).unwrap();
    let file = std::fs::read(&out).unwrap();
    let log = log.borrow();
    // ⟨§17.22 item 12⟩ Step 3, then the store-item report after the put: the same
    // registration with the put's exact locator (it joined the same decision).
    assert_eq!(log.registered.len(), 2);
    let request = &log.registered[0];
    assert_eq!(request.store_locator, None);
    assert_eq!(
        log.registered[1],
        RegisterRequest {
            store_locator: Some(done.item.locator.clone()),
            ..request.clone()
        }
    );
    assert_eq!(
        session.status.cas[0].store_locator.as_deref(),
        Some(done.item.locator.as_str()),
        "recorded with the approval"
    );
    assert_eq!(request.backup_sha256, sha256_hex(&file));
    assert_eq!(done.backup.as_ref().unwrap().sha256, sha256_hex(&file));
    assert_eq!(log.approved, vec![done.decision.clone()]);
    // The file decrypts, with the passphrase shown on the terminal, to the stored key.
    let shown = tty.shown_passphrase().unwrap();
    let restored = backup::restore(&out, &Passphrase::new(Zeroizing::new(shown))).unwrap();
    assert!(
        rig.store
            .get(&done.fingerprint)
            .unwrap()
            .same_key(&restored)
    );
    assert_eq!(restored.fingerprint().unwrap(), done.fingerprint);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // The wire form of a test store is refused (S3, fail-closed).
    assert_eq!(
        request.to_issuer_request().err(),
        Some(CeremonyError::TestStoreNotRegistrable)
    );
}

#[test]
fn rotate_begin_creates_pending_ca_with_its_backup() {
    let rig = Rig::new();
    let first = rig.backup_out("first.key");
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let old = ceremony::init(&mut tty, &mut session, &rig.store, &options(&first)).unwrap();
    // No rotation without an active CA.
    let (mut empty, _) = FakeSession::new();
    let out = rig.backup_out("second.key");
    assert_eq!(
        ceremony::rotate_begin(
            &mut ScriptedTty::default(),
            &mut empty,
            &rig.store,
            &options(&out)
        )
        .err(),
        Some(CeremonyError::NotInitialized)
    );
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let new = ceremony::rotate_begin(&mut tty, &mut session, &rig.store, &options(&out)).unwrap();
    assert_ne!(new.fingerprint, old.fingerprint);
    let request = log.borrow().registered[2].clone();
    assert_eq!(request.rotation_of.as_ref(), Some(&old.fingerprint));
    assert!(!request.restored_without_log);
    assert_eq!(
        request.backup_sha256,
        sha256_hex(&std::fs::read(&out).unwrap())
    );
    let status = session.status().unwrap();
    let ca = status
        .cas
        .iter()
        .find(|c| c.fingerprint == new.fingerprint)
        .unwrap();
    assert_eq!(ca.state, CaState::Pending);
    // Its own backup, and both keys in the store.
    let shown = tty.shown_passphrase().unwrap();
    let key = backup::restore(&out, &Passphrase::new(Zeroizing::new(shown))).unwrap();
    assert_eq!(key.fingerprint().unwrap(), new.fingerprint);
    let listed: Vec<CaFingerprint> = rig
        .store
        .list()
        .unwrap()
        .into_iter()
        .map(|i| i.fingerprint)
        .collect();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&old.fingerprint) && listed.contains(&new.fingerprint));
}

#[test]
fn init_denied_zeroizes_and_stores_nothing() {
    for answer in ["no", "", "y es"] {
        let rig = Rig::new();
        let out = rig.backup_out("ca.key");
        let (mut session, log) = FakeSession::new();
        let mut tty = ScriptedTty::answering(&[answer, "written"]);
        let err = ceremony::init(&mut tty, &mut session, &rig.store, &options(&out))
            .err()
            .unwrap();
        assert_eq!(err, CeremonyError::NotConfirmed, "{answer:?}");
        assert_eq!(err.code(), Code::InteractionRequired, "exit 3");
        // The decision was asked for; nothing more was sent, written or stored. K_ca,
        // B and the passphrase were dropped (zeroizing types) when init returned.
        assert_eq!(log.borrow().registered.len(), 1);
        assert!(log.borrow().approved.is_empty());
        assert!(!out.exists());
        assert_eq!(rig.store.list().unwrap(), Vec::new());
        assert!(files_under(rig.store.dir()).is_empty());
        assert!(tty.shown_passphrase().is_none());
    }
    // End of input is a refusal too.
    let rig = Rig::new();
    let out = rig.backup_out("ca.key");
    let (mut session, _) = FakeSession::new();
    let err = ceremony::init(
        &mut ScriptedTty::default(),
        &mut session,
        &rig.store,
        &options(&out),
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::NotConfirmed);
    assert!(!out.exists());
}

#[test]
fn restore_requires_not_stolen_flag() {
    let rig = Rig::new();
    let key = SecretCaKey::generate().unwrap();
    let pass = Passphrase::generate().unwrap();
    let out = rig.backup_out("ca.key");
    backup::write_exact(&out, &backup::prepare(&key, &pass).unwrap()).unwrap();
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(&["yes"]).with_hidden(pass.expose());
    let err = ceremony::restore(
        &mut tty,
        &mut session,
        &rig.store,
        &RestoreOptions {
            backup: &out,
            not_stolen: false,
            non_interactive: false,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::NotStolenRequired);
    assert!(tty.transcript.contains("do not restore: rotate"));
    assert_eq!(tty.hidden_reads, 0, "no passphrase asked");
    assert!(log.borrow().registered.is_empty());
    assert_eq!(rig.store.list().unwrap(), Vec::new());
    // Non-interactive is refused before anything.
    let err = ceremony::restore(
        &mut ScriptedTty::default(),
        &mut session,
        &rig.store,
        &RestoreOptions {
            backup: &out,
            not_stolen: true,
            non_interactive: true,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::NonInteractive);
}

/// ADR-0005 §9.3 R6/R11. U4's part: a restore with no matching registration goes
/// through the full decision with `restored_without_log: true`, discloses that every
/// residual under the CA is unknown, and recommends rotation; a restore with the log
/// intact rewrites the store item and reloads. The residual report itself
/// (`latest_possible_credential_expiry: unknown`, `revocation.remote:
/// unbounded_unknown`, per-account closure on rotation, no serial reuse) needs the
/// issuance log and the report paths of U3/U6/U10 (not done here).
#[test]
fn key_only_restore_reports_unbounded_unknown() {
    let rig = Rig::new();
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let pass = Passphrase::generate().unwrap();
    let out = rig.backup_out("ca.key");
    let info = backup::write_exact(&out, &backup::prepare(&key, &pass).unwrap()).unwrap();
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(&["yes"]).with_hidden(pass.expose());
    let restored = ceremony::restore(
        &mut tty,
        &mut session,
        &rig.store,
        &RestoreOptions {
            backup: &out,
            not_stolen: true,
            non_interactive: false,
        },
    )
    .unwrap();
    let Restored::RegisteredWithoutLog(reg) = restored else {
        panic!("expected a key-only registration");
    };
    assert_eq!(reg.fingerprint, fp);
    let request = log.borrow().registered[0].clone();
    assert!(request.restored_without_log);
    assert_eq!(request.backup_sha256, info.sha256);
    assert!(
        tty.transcript
            .contains("every residual under this CA is unknown")
    );
    assert!(tty.transcript.contains("Rotate"));
    let status = session.status().unwrap();
    assert!(
        status
            .cas
            .iter()
            .any(|c| c.fingerprint == fp && c.restored_without_log)
    );
    assert!(rig.store.get(&fp).unwrap().same_key(&key));
    // Log intact: the registered CA's lost store item is rewritten and reloaded,
    // with no new decision.
    let item = rig.store.list().unwrap().remove(0);
    rig.store.delete(&item).unwrap();
    let mut tty = ScriptedTty::default().with_hidden(pass.expose());
    let again = ceremony::restore(
        &mut tty,
        &mut session,
        &rig.store,
        &RestoreOptions {
            backup: &out,
            not_stolen: true,
            non_interactive: false,
        },
    )
    .unwrap();
    assert!(matches!(again, Restored::StoreItemRewritten { .. }));
    // The registration and its store-item report; the rewritten item has the
    // recorded locator, so nothing is registered again.
    assert_eq!(log.borrow().registered.len(), 2);
    assert_eq!(log.borrow().unlocks, 1);
    assert!(rig.store.get(&fp).unwrap().same_key(&key));
}

// -----------------------------------------------------------------------------
// Crash points (D4 item 1)
// -----------------------------------------------------------------------------

#[test]
fn crash_before_store_write_registers_nothing() {
    for point in [
        CrashPoint::Registered,
        CrashPoint::BackupWritten,
        CrashPoint::PassphraseShown,
    ] {
        let rig = Rig::new();
        let out = rig.backup_out("ca.key");
        let (mut session, log) = FakeSession::new();
        let mut tty = ScriptedTty::answering(YES_WRITTEN);
        let err = ceremony::init_probed(
            &mut tty,
            &mut session,
            &rig.store,
            &options(&out),
            &mut StopAt(point),
        )
        .err()
        .unwrap();
        assert_eq!(err, CeremonyError::Interrupted, "{point:?}");
        // The pending decision is never approved (it expires, DECISION_STALE); no
        // store item exists; nothing is registered.
        assert!(log.borrow().approved.is_empty(), "{point:?}");
        assert!(session.status().unwrap().cas.is_empty(), "{point:?}");
        assert_eq!(rig.store.list().unwrap(), Vec::new(), "{point:?}");
        // Before step 4 nothing is written; after it, a backup nothing trusts.
        assert_eq!(out.exists(), point != CrashPoint::Registered, "{point:?}");
    }
}

#[test]
fn crash_during_backup_write_leaves_no_store_item() {
    let rig = Rig::new();
    let out = rig.backup_out("ca.key");
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let err = ceremony::init_probed(
        &mut tty,
        &mut session,
        &rig.store,
        &options(&out),
        &mut CrashMidWrite,
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::Interrupted);
    assert_eq!(rig.store.list().unwrap(), Vec::new());
    assert!(files_under(rig.store.dir()).is_empty());
    assert!(log.borrow().approved.is_empty());
    assert!(tty.shown_passphrase().is_none());
    // A truncated file is left (the owner discards it); it is no usable backup.
    let partial = std::fs::read(&out).unwrap();
    assert!(!partial.is_empty());
    assert!(
        backup::read(&out)
            .unwrap()
            .decrypt(&Passphrase::generate().unwrap())
            .is_err()
    );
}

#[test]
fn crash_between_store_and_register_leaves_orphan_reported() {
    let rig = Rig::new();
    let out = rig.backup_out("ca.key");
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let err = ceremony::init_probed(
        &mut tty,
        &mut session,
        &rig.store,
        &options(&out),
        &mut StopAt(CrashPoint::Stored),
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::Interrupted);
    assert!(log.borrow().approved.is_empty());
    let request = log.borrow().registered[0].clone();
    let fp = fingerprint_of(&request.ca_public_key);
    let status = session.status().unwrap();
    let orphans = ceremony::orphans(&rig.store, &status).unwrap();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].fingerprint, fp);
    // A later init finds it and refuses until it is restored or replaced.
    let out2 = rig.backup_out("again.key");
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let err = ceremony::init(&mut tty, &mut session, &rig.store, &options(&out2))
        .err()
        .unwrap();
    assert_eq!(err, CeremonyError::OrphansPresent(1));
    assert!(tty.transcript.contains("--replace-orphan"));
    assert!(!out2.exists());
}

/// Leave an orphan for `rig` (a ceremony stopped between store and approve).
fn orphan(rig: &Rig, name: &str) -> CaFingerprint {
    let out = rig.backup_out(name);
    let (mut session, log) = FakeSession::new();
    let mut tty = ScriptedTty::answering(YES_WRITTEN);
    let _ = ceremony::init_probed(
        &mut tty,
        &mut session,
        &rig.store,
        &options(&out),
        &mut StopAt(CrashPoint::Stored),
    );
    let request = log.borrow().registered[0].clone();
    fingerprint_of(&request.ca_public_key)
}

#[test]
fn replace_orphan_deletes_exact_item_only() {
    let rig = Rig::new();
    let doomed = orphan(&rig, "a.key");
    // Another item: a registered CA's key, and a second orphan.
    let kept_key = SecretCaKey::generate().unwrap();
    let kept = kept_key.fingerprint().unwrap();
    rig.store.put(&kept, &kept_key).unwrap();
    let other_key = SecretCaKey::generate().unwrap();
    let other = other_key.fingerprint().unwrap();
    rig.store.put(&other, &other_key).unwrap();
    let (session, _) = FakeSession::new();
    let mut session = session.with_ca(&kept, CaState::Active);
    // A registered CA is never an orphan.
    let err = ceremony::replace_orphan(
        &mut ScriptedTty::answering(&["delete"]),
        &mut session,
        &rig.store,
        &ReplaceOrphanOptions {
            fingerprint: &kept,
            bundle: None,
            no_bundle_available: true,
            non_interactive: false,
        },
    )
    .err()
    .unwrap();
    assert_eq!(err, CeremonyError::NotAnOrphan);
    let mut tty = ScriptedTty::answering(&["delete"]);
    let deleted = ceremony::replace_orphan(
        &mut tty,
        &mut session,
        &rig.store,
        &ReplaceOrphanOptions {
            fingerprint: &doomed,
            bundle: None,
            no_bundle_available: true,
            non_interactive: false,
        },
    )
    .unwrap();
    assert_eq!(deleted.fingerprint, doomed);
    assert!(tty.transcript.contains("irreversible"));
    let left: Vec<CaFingerprint> = rig
        .store
        .list()
        .unwrap()
        .into_iter()
        .map(|i| i.fingerprint)
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&kept) && left.contains(&other) && !left.contains(&doomed));
    assert!(rig.store.get(&kept).unwrap().same_key(&kept_key));
    assert!(rig.store.get(&other).unwrap().same_key(&other_key));
}

fn bundle_with(ca: &CaFingerprint, state: EnrollmentState) -> RecoveryBundle {
    let record = enrollment_record(1, ca, state);
    RecoveryBundle {
        schema: RECOVERY_BUNDLE_SCHEMA.into(),
        created_at: t0(),
        redacted: false,
        cas: Vec::new(),
        enrollments: vec![BundleEnrollment {
            marker: record.marker.clone(),
            destination_id: record.destination.as_str().to_owned(),
            alias: "web".into(),
            hostname: Some(record.target.hostname.clone()),
            port: Some(record.target.port),
            account: record.account.clone(),
            registry: record.registry_canonical.clone(),
            registry_path_display: record.registry.path_display.clone(),
            form: record.form,
            state,
            ca_fingerprint: ca.clone(),
            ca_public_key: "ssh-ed25519 AAAA".into(),
            line_sha256: record.line_sha256.clone(),
            late_write: None,
        }],
        instructions: Vec::new(),
    }
}

#[test]
fn replace_orphan_refuses_when_bundle_lists_live_enrollments_and_offers_restore() {
    let rig = Rig::new();
    let fp = orphan(&rig, "a.key");
    for live in [
        EnrollmentState::Verified,
        EnrollmentState::AppliedUnverified,
        EnrollmentState::Abandoned,
        EnrollmentState::Held,
    ] {
        let bundle = bundle_with(&fp, live);
        let (mut session, _) = FakeSession::new();
        let mut tty = ScriptedTty::answering(&["delete"]);
        let err = ceremony::replace_orphan(
            &mut tty,
            &mut session,
            &rig.store,
            &ReplaceOrphanOptions {
                fingerprint: &fp,
                bundle: Some(&bundle),
                no_bundle_available: false,
                non_interactive: false,
            },
        )
        .err()
        .unwrap();
        assert_eq!(err, CeremonyError::OrphanStillTrusted(1), "{live:?}");
        assert!(tty.transcript.contains("Restore it instead"), "{live:?}");
        assert!(
            tty.transcript.contains("heimdall issuer restore"),
            "{live:?}"
        );
        assert!(
            tty.lines.contains(&"delete".to_owned()),
            "never asked to confirm"
        );
        assert_eq!(
            rig.store.list().unwrap().len(),
            1,
            "{live:?}: nothing deleted"
        );
    }
    // A bundle whose enrollments of that CA are all final allows the deletion.
    let bundle = bundle_with(&fp, EnrollmentState::Removed);
    let (mut session, _) = FakeSession::new();
    ceremony::replace_orphan(
        &mut ScriptedTty::answering(&["delete"]),
        &mut session,
        &rig.store,
        &ReplaceOrphanOptions {
            fingerprint: &fp,
            bundle: Some(&bundle),
            no_bundle_available: false,
            non_interactive: false,
        },
    )
    .unwrap();
    assert_eq!(rig.store.list().unwrap(), Vec::new());
}

#[test]
fn replace_orphan_without_bundle_requires_flag_and_typed_confirmation() {
    let rig = Rig::new();
    let fp = orphan(&rig, "a.key");
    let (mut session, _) = FakeSession::new();
    let opts = |no_bundle_available| ReplaceOrphanOptions {
        fingerprint: &fp,
        bundle: None,
        no_bundle_available,
        non_interactive: false,
    };
    // No bundle and no flag: refused.
    let mut tty = ScriptedTty::answering(&["delete"]);
    assert_eq!(
        ceremony::replace_orphan(&mut tty, &mut session, &rig.store, &opts(false)).err(),
        Some(CeremonyError::BundleOrFlagRequired)
    );
    assert_eq!(rig.store.list().unwrap().len(), 1);
    // The flag, but no typed confirmation: refused.
    for answer in ["yes", "", "Delete it"] {
        let mut tty = ScriptedTty::answering(&[answer]);
        assert_eq!(
            ceremony::replace_orphan(&mut tty, &mut session, &rig.store, &opts(true)).err(),
            Some(CeremonyError::NotConfirmed),
            "{answer:?}"
        );
        assert!(tty.transcript.contains("remote lines may still trust"));
        assert_eq!(rig.store.list().unwrap().len(), 1);
    }
    // The flag and `delete`: deleted.
    let mut tty = ScriptedTty::answering(&["delete"]);
    ceremony::replace_orphan(&mut tty, &mut session, &rig.store, &opts(true)).unwrap();
    assert_eq!(rig.store.list().unwrap(), Vec::new());
}

// -----------------------------------------------------------------------------
// Retirement and the uninstall plan
// -----------------------------------------------------------------------------

fn issuer_record(key: &SecretCaKey, state: CaState) -> IssuerRecord {
    IssuerRecord {
        ca_fingerprint: key.fingerprint().unwrap(),
        public_key: key.public_openssh().unwrap(),
        state,
        store_kind: StoreKind::WindowsDpapi,
        backup_sha256: "ab".repeat(32),
        backup_created_at: t0(),
        restored_without_log: false,
        created_at: t0(),
        retired_at: None,
    }
}

/// A scratch state database holding `key`'s CA, moved to `retiring` (the
/// `RetireIssuer` decision's transaction is the runtime's).
fn retiring_db(dir: &Path, key: &SecretCaKey) -> Store {
    let store = Store::open(&dir.join("state.db"), Arc::new(NoFaults)).unwrap();
    let fp = key.fingerprint().unwrap();
    store
        .transaction(|tx| {
            tx.insert_issuer(&issuer_record(key, CaState::Active))?;
            tx.set_issuer_state(&fp, CaState::Active, CaEvent::RetireApproved, t0())?
                .unwrap();
            Ok(())
        })
        .unwrap();
    store
}

fn ca_state(db: &Store, fp: &CaFingerprint) -> CaState {
    db.transaction(|tx| tx.issuer(fp)).unwrap().unwrap().state
}

/// Run the retirement from the durable state until `retired`, persisting each step;
/// `crash_after` stops after that many persisted steps (a process crash), and
/// `crash_before_persist` performs the next effect and stops before persisting it.
fn run_retirement(
    db: &Store,
    store: &dyn SecretStore,
    fp: &CaFingerprint,
    recorded: &dyn retire::RecordedItems,
    unloads: &RefCell<usize>,
    crash_after: Option<usize>,
    crash_before_persist: bool,
) {
    let mut effects = StoreEffects::new(store, recorded, |_ca: &CaFingerprint| {
        *unloads.borrow_mut() += 1;
        Ok(())
    });
    let mut persisted = 0;
    loop {
        if !crash_before_persist && crash_after == Some(persisted) {
            return;
        }
        let state = ca_state(db, fp);
        if state == CaState::Retired {
            return;
        }
        let step = retire::step(fp, state, &mut effects).unwrap();
        if crash_before_persist && crash_after == Some(persisted) {
            return;
        }
        db.transaction(|tx| {
            tx.set_issuer_state(fp, state, step.event, t0())?.unwrap();
            Ok(())
        })
        .unwrap();
        persisted += 1;
    }
}

/// U4's part: the store item is deleted by exact identity and the CA reaches
/// `retired`; the issuer child's zeroization on `unload` is U3's (`ca::CaSet`,
/// `child`), stood in for here by the unload effect (not done here).
#[test]
fn retire_deletes_store_item_and_issuer_zeroizes() {
    let dir = scratch();
    let store = ScratchSecretStore::new(dir.path().join("store"));
    std::fs::create_dir(store.dir()).unwrap();
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let recorded = vec![store.put(&fp, &key).unwrap()];
    let other = SecretCaKey::generate().unwrap();
    store.put(&other.fingerprint().unwrap(), &other).unwrap();
    let db = retiring_db(dir.path(), &key);
    let unloads = RefCell::new(0);
    run_retirement(&db, &store, &fp, &recorded, &unloads, None, false);
    assert_eq!(ca_state(&db, &fp), CaState::Retired);
    let record = db.transaction(|tx| tx.issuer(&fp)).unwrap().unwrap();
    assert_eq!(record.retired_at, Some(t0()));
    assert_eq!(*unloads.borrow(), 1);
    assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
    assert!(!store.item_path(&fp).exists());
    // Only that item.
    assert!(
        store
            .get(&other.fingerprint().unwrap())
            .unwrap()
            .same_key(&other)
    );
    // No step from a final or a not-yet-retiring state.
    let mut effects = StoreEffects::new(&store, &recorded, |_ca: &CaFingerprint| Ok(()));
    for s in [CaState::Active, CaState::Pending, CaState::Retired] {
        assert_eq!(
            retire::step(&fp, s, &mut effects).err(),
            Some(RetireError::NoStep(s))
        );
    }
    // ⟨§17.22 item 12; §17.25 item 7 (d)⟩ The owner-present CLI's deletion over the
    // same scratch store (a test kind). A locator the store lists for another CA is
    // refused in every build, deleting nothing.
    let other_fp = other.fingerprint().unwrap();
    let other_locator = store.list().unwrap()[0].locator.clone();
    assert_eq!(
        retire::delete_awaiting(&store, &fp, StoreKind::WindowsDpapi, &other_locator),
        Err(RetireError::LocatorMismatch)
    );
    assert!(store.get(&other_fp).is_ok());
    // A debug build deletes a scratch test-kind item by its exact recorded locator,
    // whatever product kind the record names (a test kind is never on the wire); a
    // release build refuses a test kind (S3) and deletes nothing.
    let deleted =
        retire::delete_awaiting(&store, &other_fp, StoreKind::WindowsDpapi, &other_locator);
    if retire::TEST_STORE_DELETION {
        assert_eq!(deleted, Ok(()));
        assert_eq!(store.get(&other_fp).err(), Some(StoreError::NotFound));
        assert!(store.list().unwrap().is_empty(), "exactly that item went");
    } else {
        assert_eq!(deleted, Err(RetireError::LocatorMismatch));
        assert!(store.get(&other_fp).is_ok());
    }
}

#[test]
fn retire_resumes_after_crash_at_each_step() {
    // A crash after `retiring` (0 steps), after `unloaded` (1) and after `deleted`
    // (2) persisted, and a crash between each effect and its persist; a restart
    // completes it, idempotently.
    for crash_before_persist in [false, true] {
        for after in 0..3 {
            let dir = scratch();
            let store = ScratchSecretStore::new(dir.path().join("store"));
            std::fs::create_dir(store.dir()).unwrap();
            let key = SecretCaKey::generate().unwrap();
            let fp = key.fingerprint().unwrap();
            let recorded = vec![store.put(&fp, &key).unwrap()];
            let db = retiring_db(dir.path(), &key);
            let unloads = RefCell::new(0);
            run_retirement(
                &db,
                &store,
                &fp,
                &recorded,
                &unloads,
                Some(after),
                crash_before_persist,
            );
            let label = format!("after {after}, before persist {crash_before_persist}");
            assert_ne!(ca_state(&db, &fp), CaState::Retired, "{label}");
            // Restart: a fresh store instance and the durable state.
            let restarted = ScratchSecretStore::new(store.dir());
            run_retirement(&db, &restarted, &fp, &recorded, &unloads, None, false);
            assert_eq!(ca_state(&db, &fp), CaState::Retired, "{label}");
            assert_eq!(restarted.list().unwrap(), Vec::new(), "{label}");
            // Each effect ran once, or twice when the crash fell between it and its
            // persist (an unload and an absent item both succeed again).
            let expected = if crash_before_persist && after == 0 {
                2
            } else {
                1
            };
            assert_eq!(*unloads.borrow(), expected, "{label}");
            // A second restart finds nothing to do.
            run_retirement(&db, &restarted, &fp, &recorded, &unloads, None, false);
            assert_eq!(*unloads.borrow(), expected, "{label}");
        }
    }
}

/// One OS store shared by every installation of the same OS user (like the login
/// Secret Service collection): `list` reports every installation's items, and the
/// locator names the installation (ADR-0008 §17.17 item 3's regression).
#[derive(Default)]
struct SharedOsStore {
    items: std::sync::Mutex<std::collections::BTreeMap<String, (CaFingerprint, Vec<u8>)>>,
}

/// One installation's view of the shared store.
struct Installation<'a> {
    shared: &'a SharedOsStore,
    environment: &'static str,
    /// ⟨§17.21 item 3⟩ Report this product kind (a stand-in for a platform store, to
    /// drive `retire::delete_awaiting`'s product-kind path; no platform store is
    /// touched).
    product: Option<StoreKind>,
}

impl Installation<'_> {
    fn locator(&self, fp: &CaFingerprint) -> String {
        format!("{}/{}", self.environment, fp.as_str())
    }
}

impl SecretStore for Installation<'_> {
    fn kind(&self) -> SecretStoreKind {
        match self.product {
            Some(kind) => SecretStoreKind::Product(kind),
            None => SecretStoreKind::Test("shared_os_store"),
        }
    }
    fn availability(&self) -> StoreAvailability {
        StoreAvailability::Available
    }
    fn put(&self, fp: &CaFingerprint, key: &SecretCaKey) -> Result<StoreItemRef, StoreError> {
        let mut items = self.shared.items.lock().unwrap();
        let locator = self.locator(fp);
        if items.contains_key(&locator) {
            return Err(StoreError::AlreadyExists);
        }
        let bytes = key.to_secret_bytes().unwrap().to_vec();
        items.insert(locator.clone(), (fp.clone(), bytes));
        Ok(StoreItemRef {
            kind: self.kind(),
            fingerprint: fp.clone(),
            locator,
        })
    }
    fn get(&self, fp: &CaFingerprint) -> Result<SecretCaKey, StoreError> {
        let items = self.shared.items.lock().unwrap();
        let (_, bytes) = items.get(&self.locator(fp)).ok_or(StoreError::NotFound)?;
        SecretCaKey::from_secret_bytes(bytes).map_err(|_| StoreError::Corrupt)
    }
    fn delete(&self, item: &StoreItemRef) -> Result<(), StoreError> {
        let mut items = self.shared.items.lock().unwrap();
        // Like the platform stores, an installation deletes only within its own scope.
        if !item.locator.starts_with(&format!("{}/", self.environment)) {
            return Err(StoreError::NotFound);
        }
        items
            .remove(&item.locator)
            .map(drop)
            .ok_or(StoreError::NotFound)
    }
    fn list(&self) -> Result<Vec<StoreItemRef>, StoreError> {
        Ok(self
            .shared
            .items
            .lock()
            .unwrap()
            .iter()
            .map(|(locator, (fp, _))| StoreItemRef {
                kind: self.kind(),
                fingerprint: fp.clone(),
                locator: locator.clone(),
            })
            .collect())
    }
}

/// ADR-0008 §17.17 item 3 (INT-Q7): two installations of the same OS user hold the
/// same (restored) CA in one OS store. Retiring it in installation A deletes exactly
/// the item A recorded at `put`; B's item, which `list()` also reports under the same
/// fingerprint, survives and still reads. Without a recorded item the deletion is
/// refused and deletes nothing, through the step and through the CLI deletion.
#[test]
fn retirement_deletes_only_the_recorded_item_when_two_installations_hold_the_same_ca() {
    let shared = SharedOsStore::default();
    let a = Installation {
        shared: &shared,
        environment: "env_a",
        product: None,
    };
    let b = Installation {
        shared: &shared,
        environment: "env_b",
        product: None,
    };
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let a_item = a.put(&fp, &key).unwrap();
    let b_item = b.put(&fp, &key).unwrap();
    assert_ne!(a_item.locator, b_item.locator);
    assert_eq!(
        a.list()
            .unwrap()
            .iter()
            .filter(|i| i.fingerprint == fp)
            .count(),
        2,
        "the OS store lists both installations' items"
    );

    // No recorded item: refused, nothing deleted (the item stays, an orphan to report).
    assert_eq!(
        retire::delete_recorded(&a, &fp, None),
        Err(RetireError::LocatorNotRecorded)
    );
    let none = retire::NoRecordedItems;
    let mut effects = StoreEffects::new(&a, &none, |_ca: &CaFingerprint| Ok(()));
    assert_eq!(
        retire::step(&fp, CaState::Unloaded, &mut effects).err(),
        Some(RetireError::LocatorNotRecorded)
    );
    assert_eq!(a.list().unwrap().len(), 2, "nothing was deleted");
    // A recorded item of another CA is refused too.
    let other = SecretCaKey::generate().unwrap();
    let other_item = a.put(&other.fingerprint().unwrap(), &other).unwrap();
    assert_eq!(
        retire::delete_recorded(&a, &fp, Some(&other_item)),
        Err(RetireError::LocatorMismatch)
    );
    a.delete(&other_item).unwrap();

    // A retires with the item it recorded at `put`: exactly that one goes.
    let recorded = vec![a_item.clone()];
    let mut effects = StoreEffects::new(&a, &recorded, |_ca: &CaFingerprint| Ok(()));
    let step = retire::step(&fp, CaState::Unloaded, &mut effects).unwrap();
    assert_eq!(step.next, CaState::Deleted);
    assert_eq!(a.get(&fp).err(), Some(StoreError::NotFound));
    assert_eq!(b.list().unwrap(), vec![b_item.clone()]);
    assert!(
        b.get(&fp).unwrap().same_key(&key),
        "B's item survives and reads"
    );
    // Idempotent: the step again (a crash before its persist) succeeds, B untouched.
    retire::step(&fp, CaState::Unloaded, &mut effects).unwrap();
    assert_eq!(b.list().unwrap(), vec![b_item.clone()]);

    // ⟨§17.25 item 7 (d)⟩ The CLI deletion over this test-kind store with A's exact
    // locator (a fresh item of A's): a debug build deletes exactly it, B's item kept; a
    // release build refuses a test kind (S3) and deletes nothing.
    let a_again = a.put(&fp, &key).unwrap();
    let deleted = retire::delete_awaiting(&a, &fp, StoreKind::LinuxSecretService, &a_again.locator);
    if retire::TEST_STORE_DELETION {
        assert_eq!(deleted, Ok(()));
        assert_eq!(
            a.list().unwrap(),
            vec![b_item.clone()],
            "only A's item went"
        );
    } else {
        assert_eq!(deleted, Err(RetireError::LocatorMismatch));
        assert_eq!(a.list().unwrap().len(), 2, "nothing was deleted");
    }
    assert!(b.get(&fp).unwrap().same_key(&key), "B's item survives");
}

/// ⟨ADR-0008 §17.22 item 12; §17.17 item 3⟩ The owner-present CLI's deletion
/// (`retire::delete_awaiting`, run with the locator `issuer.status` names) deletes
/// **exactly that locator**: over a store of the record's product kind, A's recorded
/// item goes, while B's item for the same CA (another locator) and another CA's item
/// in A survive. A store of another kind, another installation's locator, and a
/// locator the store lists for **another CA** delete nothing. Absent counts as
/// deleted. (A product-kinded in-memory stand-in; no platform store is touched, so
/// this closes no native store claim.)
#[test]
fn cli_store_item_deletion_deletes_exactly_the_named_locator() {
    let shared = SharedOsStore::default();
    let a = Installation {
        shared: &shared,
        environment: "env_a",
        product: Some(StoreKind::LinuxSecretService),
    };
    let b = Installation {
        shared: &shared,
        environment: "env_b",
        product: Some(StoreKind::LinuxSecretService),
    };
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let a_item = a.put(&fp, &key).unwrap();
    let b_item = b.put(&fp, &key).unwrap();
    let other = SecretCaKey::generate().unwrap();
    let other_fp = other.fingerprint().unwrap();
    let other_item = a.put(&other_fp, &other).unwrap();
    let delete =
        |ca: &CaFingerprint, kind, locator: &str| retire::delete_awaiting(&a, ca, kind, locator);

    // The record names another store kind: refused, nothing deleted.
    assert_eq!(
        delete(&fp, StoreKind::WindowsDpapi, &a_item.locator),
        Err(RetireError::LocatorMismatch)
    );
    // A locator the store lists for another CA: refused, nothing deleted.
    assert_eq!(
        delete(&fp, StoreKind::LinuxSecretService, &other_item.locator),
        Err(RetireError::LocatorMismatch)
    );
    assert_eq!(
        delete(&fp, StoreKind::LinuxSecretService, ""),
        Err(RetireError::LocatorMismatch)
    );
    // Another installation's locator: B's item is not A's to delete.
    assert!(delete(&fp, StoreKind::LinuxSecretService, &b_item.locator).is_err());
    assert_eq!(a.list().unwrap().len(), 3, "nothing was deleted");

    // The named locator: exactly that item goes.
    delete(&fp, StoreKind::LinuxSecretService, &a_item.locator).unwrap();
    let left: Vec<StoreItemRef> = a.list().unwrap();
    assert!(!left.contains(&a_item));
    assert!(left.contains(&b_item), "B's item for the same CA survives");
    assert!(left.contains(&other_item), "another CA's item survives");
    assert!(b.get(&fp).unwrap().same_key(&key));
    assert!(a.get(&other_fp).unwrap().same_key(&other));
    // Idempotent: already absent counts as deleted; still nothing else touched.
    delete(&fp, StoreKind::LinuxSecretService, &a_item.locator).unwrap();
    assert_eq!(a.list().unwrap().len(), 2);
}

/// ADR-0008 §17.17 item 3 (wave-1 review W1-R01, W1-R02): installations A and B of the
/// same OS user share one store. A holds a CA; B restores the same backup with its log
/// intact (the CA registered and active in B). B gets an item of its own; each lists,
/// reads and deletes only its own (a second item never makes `get` `Corrupt`); a
/// second restore in B, with A's item listed first, adopts B's own item, never A's; and
/// retiring B leaves A's item, which A still reads.
fn two_installations_restore_and_retire(a: &dyn SecretStore, b: &dyn SecretStore) {
    let key = SecretCaKey::generate().unwrap();
    let fp = key.fingerprint().unwrap();
    let a_item = a.put(&fp, &key).unwrap();
    let dir = scratch();
    let pass = Passphrase::generate().unwrap();
    let out = dir.path().join("ca.key");
    backup::write_exact(&out, &backup::prepare(&key, &pass).unwrap()).unwrap();
    let (mut session, log) = FakeSession::new();
    session.status.cas.push(ca_status(&fp, CaState::Active));
    let restore_in_b = |session: &mut FakeSession| {
        let mut tty = ScriptedTty::answering(&["yes"]).with_hidden(pass.expose());
        match ceremony::restore(
            &mut tty,
            session,
            b,
            &RestoreOptions {
                backup: &out,
                not_stolen: true,
                non_interactive: false,
            },
        )
        .unwrap()
        {
            Restored::StoreItemRewritten { item, .. } => item,
            other => panic!("expected the log-intact restore: {other:?}"),
        }
    };
    let b_item = restore_in_b(&mut session);
    assert_ne!(b_item.locator, a_item.locator, "B has an item of its own");
    // ⟨§17.22 item 12⟩ A new item for the registered CA: re-registered with a
    // compare-and-swap against the recorded locator (none here), then recorded.
    let rereg = log.borrow().registered.clone();
    assert_eq!(rereg.len(), 1);
    assert_eq!(
        rereg[0].store_locator.as_deref(),
        Some(b_item.locator.as_str())
    );
    assert_eq!(rereg[0].expected_store_locator, None);
    assert!(rereg[0].rotation_of.is_none() && !rereg[0].restored_without_log);
    assert_eq!(
        session.status.cas[0].store_locator.as_deref(),
        Some(b_item.locator.as_str())
    );
    assert_eq!(
        a.list().unwrap(),
        vec![a_item.clone()],
        "A lists only its own"
    );
    assert_eq!(
        b.list().unwrap(),
        vec![b_item.clone()],
        "B lists only its own"
    );
    assert!(a.get(&fp).unwrap().same_key(&key));
    assert!(
        b.get(&fp).unwrap().same_key(&key),
        "never Corrupt because another installation holds the CA"
    );
    // B restores again: its own existing item is adopted (A's was created first),
    // already recorded: nothing is registered again.
    assert_eq!(restore_in_b(&mut session), b_item, "B adopts its own item");
    assert_eq!(log.borrow().registered.len(), 1);
    // Retiring B deletes B's recorded item only.
    let recorded_b = vec![b_item.clone()];
    let mut effects = StoreEffects::new(b, &recorded_b, |_ca: &CaFingerprint| Ok(()));
    retire::step(&fp, CaState::Unloaded, &mut effects).unwrap();
    assert_eq!(b.get(&fp).err(), Some(StoreError::NotFound));
    assert_eq!(b.list().unwrap(), Vec::new());
    assert_eq!(a.list().unwrap(), vec![a_item.clone()]);
    assert!(
        a.get(&fp).unwrap().same_key(&key),
        "A's item survives B's retirement"
    );
    // B cannot delete A's item, even named by its exact identity.
    assert!(b.delete(&a_item).is_err());
    assert!(a.get(&fp).unwrap().same_key(&key));
    // A retires its own.
    let recorded_a = vec![a_item];
    let mut effects = StoreEffects::new(a, &recorded_a, |_ca: &CaFingerprint| Ok(()));
    retire::step(&fp, CaState::Unloaded, &mut effects).unwrap();
    assert_eq!(a.list().unwrap(), Vec::new());
}

/// An in-memory attribute-addressed store with the Secret Service's search semantics
/// (every attribute must match), shared by several installations.
#[derive(Clone, Default)]
struct MemSecretService {
    inner: Arc<std::sync::Mutex<(u64, Vec<MemItem>)>>,
}

struct MemItem {
    path: String,
    attributes: std::collections::BTreeMap<String, String>,
    secret: Vec<u8>,
}

impl MemItem {
    fn matches(&self, attributes: &[(&str, &str)]) -> bool {
        attributes
            .iter()
            .all(|(k, v)| self.attributes.get(*k).map(String::as_str) == Some(*v))
    }
}

impl AttributeBackend for MemSecretService {
    fn availability(&self) -> StoreAvailability {
        StoreAvailability::Available
    }
    fn search(&self, attributes: &[(&str, &str)]) -> Result<Vec<AttrItem>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.1
            .iter()
            .filter(|i| i.matches(attributes))
            .map(|i| AttrItem {
                path: i.path.clone(),
                fingerprint: i.attributes.get(ATTR_FINGERPRINT).cloned(),
                environment: i.attributes.get(ATTR_ENVIRONMENT).cloned(),
            })
            .collect())
    }
    fn create(
        &self,
        _label: &str,
        attributes: &[(&str, &str)],
        secret: &[u8],
    ) -> Result<String, StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.0 += 1;
        let path = format!("/org/freedesktop/secrets/collection/login/{}", g.0);
        g.1.push(MemItem {
            path: path.clone(),
            attributes: attributes
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            secret: secret.to_vec(),
        });
        Ok(path)
    }
    fn secret(
        &self,
        attributes: &[(&str, &str)],
        path: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let g = self.inner.lock().unwrap();
        g.1.iter()
            .find(|i| i.path == path && i.matches(attributes))
            .map(|i| Zeroizing::new(i.secret.clone()))
            .ok_or(StoreError::NotFound)
    }
    fn delete(&self, attributes: &[(&str, &str)], path: &str) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let at =
            g.1.iter()
                .position(|i| i.path == path && i.matches(attributes))
                .ok_or(StoreError::NotFound)?;
        g.1.remove(at);
        Ok(())
    }
}

/// ADR-0008 §17.17 item 3 (wave-1 review W1-R01): the Linux store's logic
/// (`store::attributes::AttributeStore`, the Secret Service's) over one shared
/// in-memory collection, on every host. The Linux-native row is
/// `linux::linux_secret_service_two_installations_restore_and_retire_in_private_session`.
#[test]
fn two_installations_restore_and_retire_on_a_shared_attribute_store() {
    let shared = MemSecretService::default();
    let kind = SecretStoreKind::Product(StoreKind::LinuxSecretService);
    let env_b = heimdall_contract::ids::EnvironmentId::from_random_bytes([8; 16]);
    let a = AttributeStore::new(shared.clone(), &env_id(), kind);
    let b = AttributeStore::new(shared.clone(), &env_b, kind);
    two_installations_restore_and_retire(&a, &b);
    // Every item carried its environment attribute.
    assert!(shared.inner.lock().unwrap().1.is_empty());
}

fn enrollment_view(n: u8, ca: &CaFingerprint, state: EnrollmentState) -> EnrollmentView {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    EnrollmentView {
        marker: marker_for(&id),
        enrollment_id: id,
        destination_id: DestinationId::parse("web").unwrap(),
        account: AccountName::parse("deploy").unwrap(),
        form: EnrollmentForm::Account,
        ca_fingerprint: ca.clone(),
        state,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        verified_at: None,
        evidence_fresh_until: None,
        pair_residual_until: None,
        destination_clock: Default::default(),
        residual_status: None,
        approved_target: TargetSummary {
            hostname: "web.example.invalid".into(),
            port: 22,
            user: AccountName::parse("deploy").unwrap(),
            host_key_fingerprint: "SHA256:hostfixture".into(),
        },
        removal_purpose: None,
        live_grants: Vec::new(),
        open_operation_id: None,
        possible_late_write: false,
        hold: None,
    }
}

#[test]
fn retire_refused_while_enrollment_not_final_or_abandoned() {
    let key = SecretCaKey::generate().unwrap();
    let ca = key.fingerprint().unwrap();
    let other = SecretCaKey::generate().unwrap().fingerprint().unwrap();
    for open in EnrollmentState::ALL
        .into_iter()
        .filter(|s| !s.is_final() && *s != EnrollmentState::Abandoned)
    {
        let views = vec![
            enrollment_view(1, &ca, EnrollmentState::Removed),
            enrollment_view(2, &ca, open),
            enrollment_view(3, &other, EnrollmentState::Verified),
        ];
        let refusal = retire::admissible(&ca, &views).err().unwrap();
        assert_eq!(
            refusal.open,
            vec![views[1].enrollment_id.clone()],
            "{open:?}"
        );
    }
    // Final and abandoned only: allowed, the abandoned ones listed for the decision.
    let views = vec![
        enrollment_view(1, &ca, EnrollmentState::Removed),
        enrollment_view(2, &ca, EnrollmentState::Abandoned),
        enrollment_view(3, &ca, EnrollmentState::Withdrawn),
        enrollment_view(4, &other, EnrollmentState::Verified),
    ];
    assert_eq!(
        retire::admissible(&ca, &views).unwrap(),
        vec![views[1].enrollment_id.clone()]
    );
    assert_eq!(
        retire::admissible(&ca, &[]).unwrap(),
        Vec::<EnrollmentId>::new()
    );
}

#[test]
fn uninstall_store_plan_keeps_item_while_enrollments_live() {
    let key = SecretCaKey::generate().unwrap();
    let ca = key.fingerprint().unwrap();
    let other = SecretCaKey::generate().unwrap().fingerprint().unwrap();
    let item = StoreItemRef {
        kind: SecretStoreKind::Product(StoreKind::WindowsDpapi),
        fingerprint: ca.clone(),
        locator: "x".into(),
    };
    for live in EnrollmentState::ALL.into_iter().filter(|s| !s.is_final()) {
        let views = vec![
            enrollment_view(1, &ca, EnrollmentState::Removed),
            enrollment_view(2, &ca, live),
        ];
        match retire::uninstall_store_plan(&views, &item) {
            StoreFate::Keep(retire::KeepReason::LiveEnrollments(markers)) => {
                assert_eq!(markers, vec![views[1].marker.clone()], "{live:?}");
            }
            other => panic!("{live:?}: {other:?}"),
        }
    }
    let finals: Vec<EnrollmentView> = EnrollmentState::ALL
        .into_iter()
        .filter(|s| s.is_final())
        .enumerate()
        .map(|(i, s)| enrollment_view(u8::try_from(i).unwrap() + 1, &ca, s))
        .chain([enrollment_view(9, &other, EnrollmentState::Verified)])
        .collect();
    assert_eq!(
        retire::uninstall_store_plan(&finals, &item),
        StoreFate::OfferDelete
    );
    assert_eq!(
        retire::uninstall_store_plan(&[], &item),
        StoreFate::OfferDelete
    );
}

// -----------------------------------------------------------------------------
// The recovery bundle
// -----------------------------------------------------------------------------

fn enrollment_record(n: u8, ca: &CaFingerprint, state: EnrollmentState) -> EnrollmentRecord {
    let id = EnrollmentId::from_random_bytes([n; 16]);
    let account = AccountName::parse("deploy").unwrap();
    EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: DestinationId::parse(&format!("web{n}")).unwrap(),
        account: account.clone(),
        ca_fingerprint: ca.clone(),
        form: if n.is_multiple_of(2) {
            EnrollmentForm::System
        } else {
            EnrollmentForm::Account
        },
        registry: heimdall_domain::enrollment::RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: heimdall_domain::enrollment::RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: heimdall_domain::enrollment::RegistryResolvedBy::RemoteHome,
        },
        line_sha256: format!("{n:02x}").repeat(32),
        target: ApprovedTarget {
            hostname: format!("host{n}.bundle-fixture.invalid"),
            port: 2200 + u16::from(n),
            user: account,
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: "ssh-ed25519".into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture".into(),
                fingerprint: "SHA256:hostfixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes([n; 16]),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: (n == 1).then(|| LateWrite {
            step_token: "tok".into(),
            not_after_remote: 1_800_000_000,
        }),
        state,
        verified_at: None,
        evidence: None,
        created_at: t0(),
        updated_at: t0(),
    }
}

struct BundleFixture {
    keys: Vec<SecretCaKey>,
    cas: Vec<IssuerRecord>,
    records: Vec<EnrollmentRecord>,
}

fn bundle_fixture() -> BundleFixture {
    let keys = vec![
        SecretCaKey::generate().unwrap(),
        SecretCaKey::generate().unwrap(),
    ];
    let cas = vec![
        issuer_record(&keys[0], CaState::Active),
        issuer_record(&keys[1], CaState::Pending),
    ];
    let records = vec![
        enrollment_record(1, &cas[0].ca_fingerprint, EnrollmentState::Verified),
        enrollment_record(
            2,
            &cas[0].ca_fingerprint,
            EnrollmentState::ManualRemovalPending,
        ),
        enrollment_record(
            3,
            &cas[1].ca_fingerprint,
            EnrollmentState::AppliedUnverified,
        ),
    ];
    BundleFixture { keys, cas, records }
}

fn export(f: &BundleFixture, redact: Redaction) -> RecoveryBundle {
    let entries: Vec<EnrollmentEntry<'_>> = f
        .records
        .iter()
        .map(|r| EnrollmentEntry {
            record: r,
            alias: "alias-of-the-destination",
        })
        .collect();
    bundle::export(
        &StoreView {
            created_at: t0(),
            cas: &f.cas,
            enrollments: &entries,
        },
        redact,
    )
    .unwrap()
}

#[test]
fn bundle_lists_cas_enrollments_markers_and_instructions() {
    let f = bundle_fixture();
    let b = export(&f, Redaction::None);
    assert_eq!(b.schema, RECOVERY_BUNDLE_SCHEMA);
    assert!(!b.redacted);
    assert_eq!(b.created_at, t0());
    assert_eq!(b.cas.len(), 2);
    for (ca, rec) in b.cas.iter().zip(&f.cas) {
        assert_eq!(ca.fingerprint, rec.ca_fingerprint);
        assert_eq!(ca.public_key, rec.public_key);
        assert_eq!(ca.backup_sha256, rec.backup_sha256);
        assert_eq!(ca.backup_created_at, rec.backup_created_at);
        assert_eq!(ca.state, rec.state);
    }
    assert_eq!(b.enrollments.len(), 3);
    for r in &f.records {
        let e = b.enrollments.iter().find(|e| e.marker == r.marker).unwrap();
        assert_eq!(e.marker, marker_for(&r.id));
        assert_eq!(e.destination_id, r.destination.as_str());
        assert_eq!(e.alias, "alias-of-the-destination");
        assert_eq!(e.hostname.as_deref(), Some(r.target.hostname.as_str()));
        assert_eq!(e.port, Some(r.target.port));
        assert_eq!(e.account, r.account);
        assert_eq!(e.registry, r.registry_canonical);
        assert_eq!(e.registry_path_display, r.registry.path_display);
        assert_eq!(e.form, r.form);
        assert_eq!(e.state, r.state);
        assert_eq!(e.ca_fingerprint, r.ca_fingerprint);
        let ca = f
            .cas
            .iter()
            .find(|c| c.ca_fingerprint == r.ca_fingerprint)
            .unwrap();
        assert_eq!(e.ca_public_key, ca.public_key);
        assert_eq!(e.line_sha256, r.line_sha256);
        assert_eq!(
            e.late_write.map(|l| l.not_after_remote),
            r.late_write.as_ref().map(|l| l.not_after_remote)
        );
    }
    assert!(
        b.instructions
            .iter()
            .any(|i| i.contains("enroll remove --from-bundle"))
    );
    assert!(b.instructions.iter().any(|i| i.starts_with("System-form")));
    // The wire form round-trips through the contract type.
    let json = serde_json::to_string(&b).unwrap();
    let back: RecoveryBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
    // An enrollment under an unregistered CA is refused, never exported blank.
    let stray = enrollment_record(5, &f.records[0].ca_fingerprint, EnrollmentState::Verified);
    let mut stray = stray;
    stray.ca_fingerprint = SecretCaKey::generate().unwrap().fingerprint().unwrap();
    let entries = [EnrollmentEntry {
        record: &stray,
        alias: "a",
    }];
    assert!(
        bundle::export(
            &StoreView {
                created_at: t0(),
                cas: &f.cas,
                enrollments: &entries,
            },
            Redaction::None
        )
        .is_err()
    );
}

#[test]
fn bundle_contains_no_private_material() {
    let f = bundle_fixture();
    let canary = format!(
        "{}U4_BUNDLE_{}",
        heimdall_testkit::CANARY_PREFIX,
        std::process::id()
    );
    let pass = Passphrase::generate().unwrap();
    for redact in [Redaction::None, Redaction::Hostnames] {
        let b = export(&f, redact);
        let json = serde_json::to_vec_pretty(&b).unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        heimdall_testkit::assert_no_canary(&text);
        assert!(!text.contains(&canary));
        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains(pass.expose()));
        for key in &f.keys {
            // The unencrypted store form, its base64 body lines, and the D5 form.
            let secret = key.to_secret_bytes().unwrap();
            assert!(!json.windows(secret.len()).any(|w| w == secret.as_slice()));
            let pem = String::from_utf8(secret.to_vec()).unwrap();
            for line in pem
                .lines()
                .filter(|l| !l.starts_with("-----") && l.len() > 16)
            {
                assert!(!text.contains(line), "a private-key line leaked");
            }
            let d5 = key.encrypt_openssh(pass.expose().as_bytes()).unwrap();
            let d5 = String::from_utf8(d5).unwrap();
            for line in d5
                .lines()
                .filter(|l| !l.starts_with("-----") && l.len() > 16)
            {
                assert!(!text.contains(line), "a backup line leaked");
            }
        }
        // The only key material is public: each CA's public line.
        for ca in &f.cas {
            assert!(text.contains(&ca.public_key));
        }
    }
}

#[test]
fn bundle_redacts_hostnames() {
    let f = bundle_fixture();
    let b = export(&f, Redaction::Hostnames);
    assert!(b.redacted);
    assert!(
        b.enrollments
            .iter()
            .all(|e| e.hostname.is_none() && e.port.is_none())
    );
    let text = serde_json::to_string(&b).unwrap();
    for r in &f.records {
        assert!(
            !text.contains(&r.target.hostname),
            "hostname in a redacted bundle"
        );
    }
    assert!(!text.contains("bundle-fixture.invalid"));
    assert!(!text.contains("\"hostname\"") && !text.contains("\"port\""));
    assert!(b.instructions.iter().any(|i| i.contains("bundle_redacted")));
    // Everything else foreign removal names is still there.
    assert!(
        b.enrollments
            .iter()
            .all(|e| !e.marker.is_empty() && !e.line_sha256.is_empty())
    );
}

// -----------------------------------------------------------------------------
// macOS: the keychain code path against a disposable file keychain (mechanism only)
// -----------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use heimdall_contract::envelope::reason;
    use heimdall_issuer::store::MacosLoginKeychain;

    /// SHA-256 of `security <args>`'s output (the user search list or default
    /// keychain): compared before and after, never printed.
    fn security_digest(args: &[&str]) -> String {
        let out = std::process::Command::new("/usr/bin/security")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        sha256_hex(&out.stdout)
    }

    fn owner_keychain_digests() -> (String, String) {
        (
            security_digest(&["list-keychains", "-d", "user"]),
            security_digest(&["default-keychain", "-d", "user"]),
        )
    }

    /// A disposable file keychain in scratch, deleted by path on drop.
    struct DisposableKeychain {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl DisposableKeychain {
        fn create() -> Self {
            let dir = scratch();
            let path = dir.path().join("hm-u4.keychain-db");
            // A per-run password, in memory only (never an argument).
            let password = Passphrase::generate().unwrap();
            MacosLoginKeychain::create_disposable_file_keychain(&path, password.expose()).unwrap();
            Self { _dir: dir, path }
        }
    }

    impl Drop for DisposableKeychain {
        fn drop(&mut self) {
            let _ = MacosLoginKeychain::delete_disposable_file_keychain(&self.path);
        }
    }

    /// Mechanism evidence only (a test-configuration file keychain, not the login
    /// keychain): SecAccess trusting this executable, reads without interaction,
    /// put never overwrites, delete by exact identity.
    #[test]
    fn macos_keychain_code_path_against_disposable_file_keychain() {
        let owner = heimdall_testkit::owner_digest::OwnerDigest::capture().unwrap();
        let before = owner_keychain_digests();
        let kc = DisposableKeychain::create();
        let after_create = owner_keychain_digests();
        assert_eq!(
            after_create, before,
            "the keychain joined the search list or default"
        );
        let store = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        assert_eq!(
            store.kind(),
            SecretStoreKind::Product(StoreKind::MacosLoginKeychain)
        );
        assert_eq!(store.availability(), StoreAvailability::Available);
        assert_eq!(store.list().unwrap(), Vec::new());
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
        let item = store.put(&fp, &key).unwrap();
        assert_eq!(store.put(&fp, &key).err(), Some(StoreError::AlreadyExists));
        assert!(store.get(&fp).unwrap().same_key(&key));
        assert_eq!(store.list().unwrap(), vec![item.clone()]);
        // A second key, and a fresh store instance on the same file.
        let key2 = SecretCaKey::generate().unwrap();
        let fp2 = key2.fingerprint().unwrap();
        let item2 = store.put(&fp2, &key2).unwrap();
        let again = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        assert!(again.get(&fp2).unwrap().same_key(&key2));
        assert_eq!(again.list().unwrap().len(), 2);
        // The keychain file holds no plaintext key.
        let secret = key.to_secret_bytes().unwrap();
        let bytes = std::fs::read(&kc.path).unwrap();
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_slice()));
        // Exact identity: a wrong locator deletes nothing.
        let mut wrong = item.clone();
        wrong.locator.push('x');
        assert_eq!(store.delete(&wrong), Err(StoreError::Failed));
        store.delete(&item).unwrap();
        assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
        assert_eq!(store.list().unwrap(), vec![item2.clone()]);
        // The retirement deletion step over this store: exactly the recorded item.
        retire::delete_recorded(&store, &fp2, Some(&item2)).unwrap();
        assert_eq!(store.list().unwrap(), Vec::new());
        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
        assert_eq!(owner_keychain_digests(), before);
        owner.assert_unchanged();
    }

    /// ADR-0008 §17.17 item 3 (INT-Q7), on one disposable file keychain: two
    /// installations (two environment IDs) hold the same CA; retiring it in A deletes
    /// A's item only, and B's still reads. Mechanism evidence (not the login keychain).
    #[test]
    fn retirement_on_a_shared_keychain_deletes_only_this_installations_item() {
        let owner = heimdall_testkit::owner_digest::OwnerDigest::capture().unwrap();
        let before = owner_keychain_digests();
        let kc = DisposableKeychain::create();
        let env_b = heimdall_contract::ids::EnvironmentId::from_random_bytes([8; 16]);
        let a = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        let b = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_b);
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        let a_item = a.put(&fp, &key).unwrap();
        let b_item = b.put(&fp, &key).unwrap();
        assert_ne!(a_item.locator, b_item.locator);
        // Each installation lists only its own item (W1-R02).
        assert_eq!(a.list().unwrap(), vec![a_item.clone()]);
        assert_eq!(b.list().unwrap(), vec![b_item.clone()]);
        assert_eq!(
            retire::delete_recorded(&a, &fp, None),
            Err(RetireError::LocatorNotRecorded)
        );
        assert_eq!(
            a.list().unwrap(),
            vec![a_item.clone()],
            "nothing was deleted"
        );
        assert_eq!(
            b.list().unwrap(),
            vec![b_item.clone()],
            "nothing was deleted"
        );
        let recorded = vec![a_item];
        let mut effects = StoreEffects::new(&a, &recorded, |_ca: &CaFingerprint| Ok(()));
        retire::step(&fp, CaState::Unloaded, &mut effects).unwrap();
        assert_eq!(a.get(&fp).err(), Some(StoreError::NotFound));
        assert_eq!(b.list().unwrap(), vec![b_item]);
        assert!(
            b.get(&fp).unwrap().same_key(&key),
            "B's item survives and reads"
        );
        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
        assert_eq!(owner_keychain_digests(), before);
        owner.assert_unchanged();
    }

    /// ADR-0008 §17.17 item 3 (wave-1 review W1-R02) on one disposable file keychain:
    /// two installations (two environment IDs, two accounts) and the restore that
    /// adopts an existing item with the other account's item listed first.
    #[test]
    fn two_installations_restore_and_retire_on_a_shared_disposable_keychain() {
        let owner = heimdall_testkit::owner_digest::OwnerDigest::capture().unwrap();
        let before = owner_keychain_digests();
        let kc = DisposableKeychain::create();
        let env_b = heimdall_contract::ids::EnvironmentId::from_random_bytes([8; 16]);
        let a = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        let b = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_b);
        two_installations_restore_and_retire(&a, &b);
        let path = kc.path.clone();
        drop(kc);
        assert!(!path.exists(), "the disposable keychain is deleted by path");
        assert_eq!(owner_keychain_digests(), before);
        owner.assert_unchanged();
    }

    /// `no_plaintext_when_store_unavailable`'s macOS row: a locked keychain refuses the
    /// put and the ceremony, and no file appears.
    pub(super) fn locked_keychain_writes_nothing() {
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        MacosLoginKeychain::lock_disposable_file_keychain(&kc.path).unwrap();
        assert_eq!(store.availability(), StoreAvailability::Locked);
        let root = scratch();
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        assert_eq!(
            store.put(&fp, &key).err(),
            Some(StoreError::Unavailable(StoreAvailability::Locked))
        );
        let out = root.path().join("backup.key");
        let (mut session, log) = FakeSession::new();
        let err = ceremony::init(
            &mut ScriptedTty::answering(YES_WRITTEN),
            &mut session,
            &store,
            &options(&out),
        )
        .err()
        .unwrap();
        assert_eq!(
            err,
            CeremonyError::StoreUnavailable(StoreAvailability::Locked)
        );
        assert_eq!(err.reason().as_deref(), Some(reason::ISSUER_STORE_LOCKED));
        assert!(log.borrow().registered.is_empty());
        assert!(files_under(root.path()).is_empty());
    }

    #[test]
    fn macos_interaction_not_allowed_maps_to_store_locked() {
        let owner = heimdall_testkit::owner_digest::OwnerDigest::capture().unwrap();
        let before = owner_keychain_digests();
        let kc = DisposableKeychain::create();
        let store = MacosLoginKeychain::disposable_file_keychain(&kc.path, &env_id());
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        store.put(&fp, &key).unwrap();
        MacosLoginKeychain::lock_disposable_file_keychain(&kc.path).unwrap();
        assert_eq!(store.availability(), StoreAvailability::Locked);
        // The read never prompts: errSecInteractionNotAllowed.
        let err = store.get(&fp).err().unwrap();
        assert_eq!(
            err,
            StoreError::Unavailable(StoreAvailability::InteractionNotAllowed)
        );
        assert_eq!(
            StoreAvailability::InteractionNotAllowed.refusal_reason(),
            Some(reason::ISSUER_STORE_LOCKED)
        );
        // The ceremony on the locked store: CAPABILITY_UNAVAILABLE issuer_store_locked.
        let dir = scratch();
        let out = dir.path().join("ca.key");
        let (mut session, log) = FakeSession::new();
        let err = ceremony::init(
            &mut ScriptedTty::answering(YES_WRITTEN),
            &mut session,
            &store,
            &options(&out),
        )
        .err()
        .unwrap();
        assert_eq!(err.code(), Code::CapabilityUnavailable);
        assert_eq!(err.reason().as_deref(), Some(reason::ISSUER_STORE_LOCKED));
        assert!(log.borrow().registered.is_empty());
        assert!(!out.exists());
        // Unlock is reported, never prompted for.
        let mut tty = ScriptedTty::default();
        let err = ceremony::unlock(&mut tty, &mut session, &store, false)
            .err()
            .unwrap();
        assert_eq!(err.reason().as_deref(), Some(reason::ISSUER_STORE_LOCKED));
        assert!(tty.transcript.contains("Unlock it"));
        assert_eq!(log.borrow().unlocks, 0);
        drop(kc);
        assert_eq!(owner_keychain_digests(), before);
        owner.assert_unchanged();
    }
}

// -----------------------------------------------------------------------------
// Windows: DPAPI on a scratch path (runs natively only)
// -----------------------------------------------------------------------------

#[cfg(windows)]
mod windows {
    use super::*;
    use heimdall_issuer::store::WindowsDpapi;

    const CHILD_DIR: &str = "HM_U4_DPAPI_DIR";
    const CHILD_FP: &str = "HM_U4_DPAPI_FP";

    /// Child-mode entry of `windows_dpapi_round_trip_across_processes`: reads the
    /// blob in a separate process and prints the CA's public key.
    #[test]
    #[ignore = "child-mode entry of windows_dpapi_round_trip_across_processes, started by it"]
    fn windows_dpapi_child_reads_blob() {
        let (Some(dir), Some(fp)) = (std::env::var_os(CHILD_DIR), std::env::var(CHILD_FP).ok())
        else {
            return;
        };
        let store = WindowsDpapi::in_dir(PathBuf::from(dir), &env_id());
        let fp = CaFingerprint::parse(&fp).unwrap();
        let key = store.get(&fp).unwrap();
        let line = format!("PUBLIC {}\n", key.public_openssh().unwrap());
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes()).unwrap();
    }

    #[test]
    fn windows_dpapi_round_trip_across_processes() {
        let dir = scratch();
        let blobs = dir.path().join("Heimdall").join("issuer");
        let store = WindowsDpapi::in_dir(&blobs, &env_id());
        assert_eq!(
            store.kind(),
            SecretStoreKind::Product(StoreKind::WindowsDpapi)
        );
        assert_eq!(store.availability(), StoreAvailability::Available);
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        let item = store.put(&fp, &key).unwrap();
        assert_eq!(store.put(&fp, &key).err(), Some(StoreError::AlreadyExists));
        assert!(store.get(&fp).unwrap().same_key(&key));
        assert_eq!(store.list().unwrap(), vec![item.clone()]);
        // No plaintext on disk.
        let secret = key.to_secret_bytes().unwrap();
        assert!(files_containing(dir.path(), &secret).is_empty());
        // Another process (this test binary in child mode) unprotects it.
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::windows_dpapi_child_reads_blob",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env(CHILD_DIR, &blobs)
            .env(CHILD_FP, fp.as_str())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "child exit {:?}", out.status.code());
        let stdout = String::from_utf8_lossy(&out.stdout);
        let expected = format!("PUBLIC {}", key.public_openssh().unwrap());
        assert!(
            stdout.lines().any(|l| l == expected),
            "the child read the blob"
        );
        // A different entropy (another fingerprint's name) does not unprotect it.
        let other = SecretCaKey::generate().unwrap().fingerprint().unwrap();
        std::fs::copy(store.blob_path(&fp), store.blob_path(&other)).unwrap();
        assert_eq!(store.get(&other).err(), Some(StoreError::Corrupt));
        std::fs::remove_file(store.blob_path(&other)).unwrap();
        store.delete(&item).unwrap();
        assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
        assert_eq!(store.list().unwrap(), Vec::new());
    }

    #[test]
    fn windows_dpapi_blob_dacl_owner_only() {
        let dir = scratch();
        let blobs = dir.path().join("issuer");
        let store = WindowsDpapi::in_dir(&blobs, &env_id());
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        store.put(&fp, &key).unwrap();
        let expected = WindowsDpapi::expected_blob_dacl().unwrap();
        assert!(expected.starts_with("D:P(A;;FA;;;S-1-"), "{expected}");
        assert_eq!(
            WindowsDpapi::dacl_sddl(&store.blob_path(&fp)).unwrap(),
            expected
        );
        let dir_dacl = WindowsDpapi::dacl_sddl(&blobs).unwrap();
        assert_eq!(dir_dacl, expected.replacen("(A;;", "(A;OICI;", 1));
        // The D5 backup written on Windows carries the same owner-only DACL.
        let out = dir.path().join("ca.key");
        let pass = Passphrase::generate().unwrap();
        backup::write_exact(&out, &backup::prepare(&key, &pass).unwrap()).unwrap();
        assert_eq!(WindowsDpapi::dacl_sddl(&out).unwrap(), expected);
    }
}

// -----------------------------------------------------------------------------
// Linux: the Secret Service in a private session (runs natively only)
// -----------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use heimdall_issuer::store::LinuxSecretService;

    const GATE: &str = "HM_SECRET_SERVICE_TESTS";
    const CHILD: &str = "HM_U4_SS_CHILD";

    fn find(program: &str) -> Option<PathBuf> {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|d| d.join(program))
                .find(|p| p.is_file())
        })
    }

    const NO_BUS_CHILD: &str = "HM_U4_NO_BUS_CHILD";

    /// Child-mode entry of `no_plaintext_when_store_unavailable`'s Linux row.
    #[test]
    #[ignore = "child-mode entry of no_plaintext_when_store_unavailable, started by it"]
    fn linux_no_session_bus_child() {
        let Some(root) = std::env::var_os(NO_BUS_CHILD) else {
            return;
        };
        let root = PathBuf::from(root);
        let store = LinuxSecretService::new(&env_id());
        let a = store.availability();
        assert_ne!(a, StoreAvailability::Available);
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        assert_eq!(store.put(&fp, &key).err(), Some(StoreError::Unavailable(a)));
        let out = root.join("backup.key");
        let (mut session, log) = FakeSession::new();
        let err = ceremony::init(
            &mut ScriptedTty::answering(YES_WRITTEN),
            &mut session,
            &store,
            &options(&out),
        )
        .err()
        .unwrap();
        assert_eq!(err.code(), Code::CapabilityUnavailable);
        assert_eq!(err.reason().as_deref(), a.refusal_reason());
        assert!(log.borrow().registered.is_empty());
        let line = format!("NO-BUS-ROW {}\n", a.as_str());
        std::io::Write::write_all(&mut std::io::stdout(), line.as_bytes()).unwrap();
    }

    pub(super) fn no_session_bus_writes_nothing() {
        let root = scratch();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux::linux_no_session_bus_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", root.path())
            .env("XDG_RUNTIME_DIR", root.path())
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", root.path().join("no-bus").display()),
            )
            .env(NO_BUS_CHILD, root.path())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "child exit {:?}", out.status.code());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("NO-BUS-ROW "), "the row ran in the child");
        assert!(files_under(root.path()).is_empty(), "no file appeared");
    }

    /// Child-mode entry, run inside `dbus-run-session` with a scratch `HOME`.
    #[test]
    #[ignore = "child-mode entry of linux_secret_service_round_trip_in_private_session, started by it"]
    fn linux_secret_service_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let store = LinuxSecretService::new(&env_id());
        start_private_keyring(&store);
        let key = SecretCaKey::generate().unwrap();
        let fp = key.fingerprint().unwrap();
        let item = store.put(&fp, &key).unwrap();
        assert_eq!(store.put(&fp, &key).err(), Some(StoreError::AlreadyExists));
        assert!(store.get(&fp).unwrap().same_key(&key));
        assert_eq!(store.list().unwrap(), vec![item.clone()]);
        store.delete(&item).unwrap();
        assert_eq!(store.get(&fp).err(), Some(StoreError::NotFound));
        std::io::Write::write_all(&mut std::io::stdout(), b"SECRET-SERVICE-ROUND-TRIP-OK\n")
            .unwrap();
    }

    /// Start a private gnome-keyring on this child's session bus; its login keyring
    /// password is written to its stdin (never an argument). Waits until `store` is
    /// available.
    fn start_private_keyring(store: &LinuxSecretService) {
        let daemon = find("gnome-keyring-daemon").unwrap();
        let mut child = std::process::Command::new(daemon)
            .args(["--unlock", "--components=secrets"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let password = Passphrase::generate().unwrap();
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), password.expose().as_bytes())
            .unwrap();
        drop(child.stdin.take());
        let _ = child.wait();
        let mut available = store.availability();
        for _ in 0..50 {
            if available == StoreAvailability::Available {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            available = store.availability();
        }
        assert_eq!(available, StoreAvailability::Available);
    }

    /// Child-mode entry of the two-installation row (ADR-0008 §17.17 item 3; wave-1
    /// review W1-R01), run inside `dbus-run-session` with a scratch `HOME`.
    #[test]
    #[ignore = "child-mode entry of linux_secret_service_two_installations_restore_and_retire_in_private_session, started by it"]
    fn linux_secret_service_two_installations_child() {
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let env_b = heimdall_contract::ids::EnvironmentId::from_random_bytes([8; 16]);
        let a = LinuxSecretService::new(&env_id());
        let b = LinuxSecretService::new(&env_b);
        start_private_keyring(&a);
        two_installations_restore_and_retire(&a, &b);
        std::io::Write::write_all(
            &mut std::io::stdout(),
            b"SECRET-SERVICE-TWO-INSTALLATIONS-OK\n",
        )
        .unwrap();
    }

    /// Run `child` (a child-mode entry of this module) inside `dbus-run-session` with a
    /// scratch `HOME`, and require its `marker` line.
    fn run_in_private_session(child: &str, marker: &str) {
        assert_eq!(
            std::env::var(GATE).as_deref(),
            Ok("1"),
            "set {GATE}=1 to run this row"
        );
        let (Some(run_session), Some(_daemon)) =
            (find("dbus-run-session"), find("gnome-keyring-daemon"))
        else {
            panic!(
                "BLOCKED: dbus-run-session or gnome-keyring-daemon is not installed on this host (observation; nothing was installed)"
            );
        };
        let home = scratch();
        for d in [".config", ".local/share", ".cache", "run"] {
            std::fs::create_dir_all(home.path().join(d)).unwrap();
        }
        let out = std::process::Command::new(run_session)
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                child,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env("XDG_DATA_HOME", home.path().join(".local/share"))
            .env("XDG_CACHE_HOME", home.path().join(".cache"))
            .env("XDG_RUNTIME_DIR", home.path().join("run"))
            .env(CHILD, "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "child exit {:?}", out.status.code());
        assert!(stdout.contains(marker));
    }

    #[test]
    #[ignore = "needs dbus-run-session and gnome-keyring-daemon on the host; run with HM_SECRET_SERVICE_TESTS=1 cargo test -p heimdall-issuer --test integration_issuer_store -- --ignored linux::linux_secret_service_round_trip_in_private_session"]
    fn linux_secret_service_round_trip_in_private_session() {
        run_in_private_session(
            "linux::linux_secret_service_child",
            "SECRET-SERVICE-ROUND-TRIP-OK",
        );
    }

    /// ADR-0008 §17.17 item 3 (wave-1 review W1-R01) on the real Secret Service: two
    /// installations of the same OS user, one login collection, the same restored CA.
    #[test]
    #[ignore = "needs dbus-run-session and gnome-keyring-daemon on the host; run with HM_SECRET_SERVICE_TESTS=1 cargo test -p heimdall-issuer --test integration_issuer_store -- --ignored linux::linux_secret_service_two_installations_restore_and_retire_in_private_session"]
    fn linux_secret_service_two_installations_restore_and_retire_in_private_session() {
        run_in_private_session(
            "linux::linux_secret_service_two_installations_child",
            "SECRET-SERVICE-TWO-INSTALLATIONS-OK",
        );
    }
}
