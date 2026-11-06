//! W2-U4a: the replacement primitive, the quarantine and the materializer (m02-plan U4,
//! the primitive half, as split by ADR-0007 §12.15 item 9; ADR-0007 §5.3 and §5.7).
//!
//! Every test works in a fresh scratch directory this process creates (owner-only,
//! removed on drop). No test reads or writes the account's `~/.ssh`, keys, agents or
//! configuration; key material is generated per run in memory (`FixtureKey`). The
//! tests that settle an ADR-0007 `[I]` fact (`exchange_supported_on_target_fs`,
//! `file_identity_birth_recorded_on_target_fs`) print one `observation:` line for the
//! evidence record; they print no content.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use heimdall_domain::operation::{HoldReason, SettleSource, SettledDisposition};
use heimdall_domain::projection::{
    Base, ContentState, EffectivePhase, EntryFileType, EntryFingerprint, EntryObs, FileIdentity,
    FileRole, FileStep, FingerprintContent, ItemState, RecordedRole, RecoveryState, Rendered,
    RestoreCtx, SettleCtx, Sha256Hex, StepContent, Target, bounds, lock_holder_line,
};
#[cfg(unix)]
use heimdall_localenv::materialize::{
    KeyLineError, PublicKeyLine, key_file_path, public_key_bytes,
};
use heimdall_localenv::projection::content::{ContentError, READ_MAX, materialize};
#[cfg(unix)]
use heimdall_localenv::projection::replace::Unmanageable;
use heimdall_localenv::projection::replace::{
    self, DirHandle, Exchanged, Expected, HookAt, IdentitySource, Mode, NameState, PostValidation,
    Quarantine, RemoveVerified, ReplaceError, ReplaceRefusal, RestoreFailure, RestoreOutcome,
    SettleOutcome, Staged, StepNames, StepRecord, Validated,
};
use heimdall_localenv::projection::{ReplaceHook, ReplacePoint};

const OLD: &[u8] = b"Host old\n  HostName old.invalid\n";
const NEW: &[u8] = b"Host new\n  HostName new.invalid\n";
const WRITER: &[u8] = b"# another writer's bytes\nHost theirs\n";

// --- helpers ---------------------------------------------------------------------

fn scratch() -> tempfile::TempDir {
    let d = tempfile::Builder::new()
        .prefix("hm-u4a-")
        .tempdir()
        .unwrap();
    set_mode(d.path(), 0o700);
    d
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}

#[cfg(unix)]
fn mode_of(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn sha(b: &[u8]) -> Sha256Hex {
    Sha256Hex::of(b)
}

/// The ADR-0007 §5.7 staged name of `target` (generation 1).
fn staged_name(target: &str, n: u32) -> String {
    format!(".{target}.hm-1-{n:032x}")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    fs::write(dir.join(name), bytes).unwrap();
    set_mode(&dir.join(name), 0o600);
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap()
}

/// Whether `id` names the inode at `path` (Unix: device and inode).
#[cfg(unix)]
fn is_at(id: &FileIdentity, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path).unwrap();
    matches!(id, FileIdentity::Unix { dev, ino, .. } if *dev == m.dev() && *ino == m.ino())
}

fn rendered(bytes: &[u8]) -> Rendered {
    Rendered::from_renderer(bytes.to_vec())
}

/// A whole-target step (P, P_git or a key file).
fn whole_step(role: FileRole, path: &Path, base: Option<&[u8]>, target: &[u8], n: u32) -> FileStep {
    let name = path.file_name().unwrap().to_str().unwrap();
    let staged = staged_name(name, n);
    FileStep {
        role,
        path: path.to_string_lossy().into_owned(),
        base: base.map_or(Base::Absent, |b| Base::Present { sha256: sha(b) }),
        target: Target::Present {
            sha256: sha(target),
        },
        content: rendered(target).into_whole(),
        commit: false,
        displaced_name: base.map(|_| {
            if cfg!(windows) {
                format!(".{name}.hm-displaced-1")
            } else {
                staged.clone()
            }
        }),
        staged_name: Some(staged),
    }
}

/// A splice step of the user file.
fn splice_step(
    base: Option<&[u8]>,
    offset: u64,
    remove_len: u64,
    removed: Option<Sha256Hex>,
    insert: &[u8],
    target: Sha256Hex,
) -> FileStep {
    FileStep {
        role: FileRole::UserSsh,
        path: "/scratch/.ssh/config".to_owned(),
        base: base.map_or(Base::Absent, |b| Base::Present { sha256: sha(b) }),
        target: Target::Present { sha256: target },
        content: rendered(insert).into_splice(offset, remove_len, removed),
        commit: true,
        staged_name: Some(staged_name("config", 1)),
        displaced_name: base.map(|_| staged_name("config", 1)),
    }
}

/// A scratch directory holding `config` (`OLD`), validated, staged with `NEW` and
/// rechecked: the state just before the exchange (ADR-0007 §5.3 steps 1–4).
struct Forward {
    dir: tempfile::TempDir,
    handle: DirHandle,
    step: FileStep,
    validated: Validated,
    staged: Staged,
    expected_s: Expected,
}

impl Forward {
    fn new() -> Forward {
        let dir = scratch();
        write(dir.path(), "config", OLD);
        let handle = DirHandle::open(dir.path()).unwrap();
        let step = whole_step(
            FileRole::ManagedSsh,
            &dir.path().join("config"),
            Some(OLD),
            NEW,
            1,
        );
        let validated = replace::validate(&handle, "config", &step.base).unwrap();
        let m = materialize(&step, validated.bytes.as_deref()).unwrap();
        handle.learn_step(&step);
        let staged = replace::stage(
            &handle,
            step.staged_name.as_deref().unwrap(),
            &m,
            Mode::OwnerReadWrite,
        )
        .unwrap();
        replace::recheck_at(&handle, "config", &validated).unwrap();
        let expected_s = Expected {
            identity: staged.identity.clone(),
            sha256: m.sha256,
        };
        Forward {
            dir,
            handle,
            step,
            validated,
            staged,
            expected_s,
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn staged_path(&self) -> PathBuf {
        self.path().join(&self.staged.name)
    }

    /// D after a forward exchange (Windows keeps a separate backup name).
    fn displaced_path(&self) -> PathBuf {
        self.path().join(self.step.displaced_name.as_ref().unwrap())
    }

    fn exchange(&self) -> Exchanged {
        replace::exchange_at(
            &self.handle,
            &self.names(),
            &self.staged,
            Some(&self.validated),
        )
        .unwrap()
    }

    fn post_validate(&self, x: &Exchanged) -> PostValidation {
        replace::post_validate_at(
            &self.handle,
            &self.names(),
            x,
            &self.validated,
            &self.staged,
        )
    }

    /// `restore_with` of the step's names in `handle`, with D expected as `aside` and
    /// no receipt callback.
    fn restore_in(&self, handle: &DirHandle, aside: &FileIdentity) -> RestoreOutcome {
        replace::restore_with(
            handle,
            &self.names(),
            &self.expected_s,
            aside,
            HookAt::NONE,
            || Ok::<(), ()>(()),
        )
        .unwrap()
    }

    fn restore(&self, aside: &FileIdentity) -> RestoreOutcome {
        self.restore_in(&self.handle, aside)
    }

    fn v(&self) -> FileIdentity {
        self.validated.identity.clone().unwrap()
    }

    fn names(&self) -> StepNames {
        StepNames::of(&self.step).unwrap()
    }
}

/// A hook that runs `f` once at `point`.
struct At<F: Fn() + Send + Sync> {
    point: ReplacePoint,
    f: F,
    fired: Mutex<Vec<ReplacePoint>>,
}

impl<F: Fn() + Send + Sync> At<F> {
    fn new(point: ReplacePoint, f: F) -> Self {
        Self {
            point,
            f,
            fired: Mutex::new(Vec::new()),
        }
    }
}

impl<F: Fn() + Send + Sync> ReplaceHook for At<F> {
    fn at(&self, point: ReplacePoint, _step: u16) {
        self.fired.lock().unwrap().push(point);
        if point == self.point {
            (self.f)();
        }
    }
}

/// Rename-replace `name` with a new file holding `bytes` (an editor's save by rename).
fn rename_replace(dir: &Path, name: &str, bytes: &[u8]) {
    let tmp = dir.join("writer.tmp");
    fs::write(&tmp, bytes).unwrap();
    set_mode(&tmp, 0o600);
    fs::rename(&tmp, dir.join(name)).unwrap();
}

/// Rewrite `name` in place (same inode).
fn write_in_place(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn slot(n: u32) -> String {
    format!("{n:032x}")
}

// --- materializer (M2-T02) -------------------------------------------------------

/// m02-plan U4 `materialize_checks_both_digests_from_the_step`: the base digest and
/// the target digest are both checked by the materializer itself, before `stage`.
#[test]
fn materialize_checks_both_digests_from_the_step() {
    let p = Path::new("/scratch/hm/ssh_config");
    // Whole target over a present base: the base is still checked.
    let step = whole_step(FileRole::ManagedSsh, p, Some(OLD), NEW, 1);
    let m = materialize(&step, Some(OLD)).unwrap();
    assert_eq!(m.bytes, NEW);
    assert_eq!(m.sha256, sha(NEW));
    assert_eq!(
        materialize(&step, Some(WRITER)),
        Err(ContentError::BaseMismatch)
    );
    assert_eq!(materialize(&step, None), Err(ContentError::BaseMissing));
    // Whole target over an absent base: bytes given for it are refused.
    let create = whole_step(FileRole::ManagedSsh, p, None, NEW, 1);
    assert_eq!(materialize(&create, None).unwrap().bytes, NEW);
    assert_eq!(
        materialize(&create, Some(b"")),
        Err(ContentError::BaseUnexpected)
    );
    // The output must hash to the target digest: whole …
    let mut wrong = step.clone();
    wrong.target = Target::Present { sha256: sha(OLD) };
    assert_eq!(
        materialize(&wrong, Some(OLD)),
        Err(ContentError::TargetMismatch)
    );
    // … and splice.
    let base = b"Host a\n";
    let block = b"# >>> heimdall\nInclude x\n# <<< heimdall\n";
    let mut out = block.to_vec();
    out.extend_from_slice(base);
    let ok = splice_step(Some(base), 0, 0, None, block, sha(&out));
    assert_eq!(materialize(&ok, Some(base)).unwrap().bytes, out);
    let bad_target = splice_step(Some(base), 0, 0, None, block, sha(base));
    assert_eq!(
        materialize(&bad_target, Some(base)),
        Err(ContentError::TargetMismatch)
    );
    // A splice is never applied to a base that is not the validated one.
    assert_eq!(
        materialize(&ok, Some(b"Host b\n")),
        Err(ContentError::BaseMismatch)
    );
    assert_eq!(materialize(&ok, None), Err(ContentError::BaseMissing));
}

/// The variant must fit the role, and the lock holder has its exact one-line form.
#[test]
fn materialize_refuses_shapes_that_do_not_fit_the_role() {
    let p = Path::new("/scratch/hm/ssh_config");
    let mut s = whole_step(FileRole::UserSsh, p, Some(OLD), NEW, 1);
    assert_eq!(materialize(&s, Some(OLD)), Err(ContentError::ShapeMismatch));
    s.role = FileRole::ManagedSsh;
    s.content = StepContent::absent();
    assert_eq!(materialize(&s, Some(OLD)), Err(ContentError::ShapeMismatch));
    s.content = rendered(NEW).into_lock_holder();
    assert_eq!(materialize(&s, Some(OLD)), Err(ContentError::ShapeMismatch));
    // Bounds: a key file over 16 KiB.
    let big = vec![b'a'; bounds::KEY_FILE_MAX + 1];
    let key = whole_step(FileRole::Key, p, None, &big, 1);
    assert_eq!(materialize(&key, None), Err(ContentError::TooLarge));
    // The `git_lock` step: the holder line, base and target absent.
    let line = lock_holder_line(7, [0xab; 16]);
    let lock = FileStep {
        role: FileRole::GitLock,
        path: "/scratch/h/.gitconfig.lock".to_owned(),
        base: Base::Absent,
        target: Target::Absent,
        content: rendered(&line).into_lock_holder(),
        commit: false,
        staged_name: Some(staged_name(".gitconfig.lock", 1)),
        displaced_name: None,
    };
    assert_eq!(materialize(&lock, None).unwrap().bytes, line);
    assert_eq!(
        materialize(&lock, Some(b"")),
        Err(ContentError::BaseUnexpected)
    );
    for bad in [
        b"heimdall setup lock, generation 007, abababababababababababababababab\n".to_vec(),
        b"heimdall setup lock, generation 7, abababababababababababababababab".to_vec(),
        b"heimdall setup lock, generation 7, ABABABABABABABABABABABABABABABAB\n".to_vec(),
        b"something else\n".to_vec(),
    ] {
        let mut l = lock.clone();
        l.content = rendered(&bad).into_lock_holder();
        assert_eq!(
            materialize(&l, None),
            Err(ContentError::ShapeMismatch),
            "{bad:?}"
        );
    }
    let mut not_lock = lock.clone();
    not_lock.role = FileRole::ManagedSsh;
    assert_eq!(
        materialize(&not_lock, None),
        Err(ContentError::ShapeMismatch)
    );
}

/// m02-plan U4 `materialize_absent_base_is_insert_only`.
#[test]
fn materialize_absent_base_is_insert_only() {
    let block = b"# >>> heimdall\nInclude x\n# <<< heimdall\n";
    let ok = splice_step(None, 0, 0, None, block, sha(block));
    assert_eq!(materialize(&ok, None).unwrap().bytes, block);
    let cases = [
        (
            splice_step(None, 1, 0, None, block, sha(block)),
            ContentError::NotInsertOnly,
        ),
        (
            splice_step(None, 0, 1, Some(sha(b"x")), block, sha(block)),
            ContentError::NotInsertOnly,
        ),
        (
            splice_step(None, 0, 1, None, block, sha(block)),
            ContentError::NotInsertOnly,
        ),
        (
            splice_step(None, 0, 0, Some(sha(b"")), block, sha(block)),
            ContentError::NotInsertOnly,
        ),
        (
            splice_step(None, 0, 0, None, b"", sha(b"")),
            ContentError::EmptyInsert,
        ),
    ];
    for (step, want) in cases {
        assert_eq!(materialize(&step, None), Err(want), "{:?}", step.content);
    }
}

mod range {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

    /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::SourceParallel(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x5534_6152_414e_4745);
        }
        c
    }

    fn edge() -> impl Strategy<Value = u64> {
        prop_oneof![
            4 => 0u64..72,
            1 => Just(u64::MAX),
            1 => (1u64..4).prop_map(|k| u64::MAX - k),
            1 => Just(u64::MAX / 2 + 1),
            1 => Just(usize::MAX as u64),
        ]
    }

    /// The reference splice, in `u128` arithmetic (independent of the checked `usize`
    /// arithmetic under test), with the same error order.
    fn reference(
        base: Option<&[u8]>,
        offset: u64,
        len: u64,
        removed: Option<&Sha256Hex>,
        insert: &[u8],
    ) -> Result<Vec<u8>, ContentError> {
        let Some(base) = base else {
            if offset != 0 || len != 0 || removed.is_some() {
                return Err(ContentError::NotInsertOnly);
            }
            if insert.is_empty() {
                return Err(ContentError::EmptyInsert);
            }
            return Ok(insert.to_vec());
        };
        let max = usize::MAX as u128;
        let (o, l) = (u128::from(offset), u128::from(len));
        if o > max || l > max || o + l > max {
            return Err(ContentError::RangeOverflow);
        }
        if o + l > base.len() as u128 {
            return Err(ContentError::RangeOutOfBounds);
        }
        let (start, end) = (offset as usize, (offset + len) as usize);
        match (len > 0, removed) {
            (true, None) => return Err(ContentError::RemovedDigestMissing),
            (false, Some(_)) => return Err(ContentError::RemovedDigestUnexpected),
            (true, Some(d)) if *d != sha(&base[start..end]) => {
                return Err(ContentError::RemovedDigestMismatch);
            }
            _ => {}
        }
        let mut out = base[..start].to_vec();
        out.extend_from_slice(insert);
        out.extend_from_slice(&base[end..]);
        Ok(out)
    }

    proptest! {
        #![proptest_config(config())]

        /// m02-plan U4 `materialize_range_arithmetic_is_checked`: random bases (empty
        /// and absent included), offsets and lengths including `u64::MAX`, overflowing
        /// sums, ends past the input, and offsets past the input with `remove_len` 0.
        /// Every out-of-range case returns its error; none panics or wraps; every
        /// in-range case matches the reference byte for byte.
        #[test]
        fn materialize_range_arithmetic_is_checked(
            absent in proptest::bool::weighted(0.2),
            base in proptest::collection::vec(any::<u8>(), 0..64),
            offset in edge(),
            len in edge(),
            digest in 0u8..3,
            insert in proptest::collection::vec(any::<u8>(), 0..16),
            wrong_target in any::<bool>(),
        ) {
            let base_opt = (!absent).then_some(base.as_slice());
            // The removed range's digest: none, the right one (when the range is in
            // bounds), or a wrong one.
            let in_range = base_opt.and_then(|b| {
                let end = offset.checked_add(len)?;
                b.get(usize::try_from(offset).ok()?..usize::try_from(end).ok()?)
            });
            let removed = match digest {
                0 => None,
                1 => Some(sha(in_range.unwrap_or(b"out of range"))),
                _ => Some(sha(&[b"wrong".as_slice(), in_range.unwrap_or_default()].concat())),
            };
            let want = reference(base_opt, offset, len, removed.as_ref(), &insert);
            let target = match &want {
                Ok(out) if wrong_target => sha(&[out.as_slice(), b"x"].concat()),
                Ok(out) => sha(out),
                Err(_) => sha(b""),
            };
            let step = splice_step(base_opt, offset, len, removed.clone(), &insert, target);
            let got = materialize(&step, base_opt);
            match want {
                Ok(_) if wrong_target => prop_assert_eq!(got, Err(ContentError::TargetMismatch)),
                Ok(out) => prop_assert_eq!(got.map(|m| m.bytes), Ok(out)),
                Err(e) => prop_assert_eq!(got, Err(e)),
            }
        }
    }

    /// The fixed out-of-range corners, each with its own error.
    #[test]
    fn materialize_range_corners() {
        let base = b"0123456789";
        let s = |o, l, d: Option<Sha256Hex>| splice_step(Some(base), o, l, d, b"x", sha(b""));
        assert_eq!(
            materialize(&s(u64::MAX, 1, Some(sha(b"0"))), Some(base)),
            Err(ContentError::RangeOverflow)
        );
        assert_eq!(
            materialize(&s(1, u64::MAX, Some(sha(b"0"))), Some(base)),
            Err(ContentError::RangeOverflow)
        );
        assert_eq!(
            materialize(&s(u64::MAX, 0, None), Some(base)),
            Err(ContentError::RangeOutOfBounds)
        );
        assert_eq!(
            materialize(&s(11, 0, None), Some(base)),
            Err(ContentError::RangeOutOfBounds)
        );
        assert_eq!(
            materialize(&s(5, 6, Some(sha(b"56789"))), Some(base)),
            Err(ContentError::RangeOutOfBounds)
        );
        assert_eq!(
            materialize(&s(2, 3, None), Some(base)),
            Err(ContentError::RemovedDigestMissing)
        );
        assert_eq!(
            materialize(&s(2, 0, Some(sha(b""))), Some(base)),
            Err(ContentError::RemovedDigestUnexpected)
        );
        assert_eq!(
            materialize(&s(2, 3, Some(sha(b"999"))), Some(base)),
            Err(ContentError::RemovedDigestMismatch)
        );
        // Offset at the end with nothing removed is in range (an append).
        let append = splice_step(Some(base), 10, 0, None, b"x", sha(b"0123456789x"));
        assert_eq!(
            materialize(&append, Some(base)).unwrap().bytes,
            b"0123456789x"
        );
        // An output past the read bound is refused.
        let big = vec![b'a'; READ_MAX];
        let over = splice_step(Some(&big), 0, 0, None, b"x", sha(b""));
        assert_eq!(materialize(&over, Some(&big)), Err(ContentError::TooLarge));
        let insert = vec![b'b'; bounds::INSERT_MAX + 1];
        let wide = splice_step(Some(base), 0, 0, None, &insert, sha(b""));
        assert_eq!(materialize(&wide, Some(base)), Err(ContentError::TooLarge));
    }
}

// --- exchange and identity on the target filesystem (F24, F25) ---------------------

/// m02-plan U4 `exchange_supported_on_target_fs` (settles F24 for this harness): the
/// atomic exchange works on the scratch filesystem, S is at the path and the
/// validated base V at the staged name, each with its identity and bytes.
#[test]
fn exchange_supported_on_target_fs() {
    let f = Forward::new();
    let x = f.exchange();
    assert_eq!(
        x.displaced_name.as_deref(),
        f.step.displaced_name.as_deref()
    );
    assert_eq!(read(f.path(), "config"), NEW);
    let displaced = x.displaced_name.clone().unwrap();
    assert_eq!(read(f.path(), &displaced), OLD);
    assert_eq!(f.post_validate(&x), PostValidation::Valid);
    assert_eq!(
        replace::check_name(&f.handle, "config", &f.expected_s),
        NameState::Expected(ContentState::Unchanged)
    );
    #[cfg(unix)]
    {
        assert!(is_at(&f.staged.identity, &f.path().join("config")));
        assert!(is_at(&f.v(), &f.path().join(&displaced)));
    }
    eprintln!(
        "observation: exchange_supported_on_target_fs os={} supported=true",
        std::env::consts::OS
    );
}

/// m02-plan U4 `file_identity_birth_recorded_on_target_fs` (settles F25 for this
/// harness): whether the birth time is filled, and that a file created after another
/// file's removal never compares equal to the removed file's identity when a birth time
/// is present, even if it reuses the inode.
#[test]
fn file_identity_birth_recorded_on_target_fs() {
    let d = scratch();
    let h = DirHandle::open(d.path()).unwrap();
    let stage = |n: u32| {
        let bytes = format!("file {n}\n").into_bytes();
        let m = heimdall_localenv::projection::content::Materialized {
            sha256: sha(&bytes),
            bytes,
        };
        replace::stage(&h, &staged_name("f", n), &m, Mode::OwnerReadWrite).unwrap()
    };
    let first = stage(0);
    let birth = matches!(first.identity, FileIdentity::Unix { birth: Some(_), .. });
    if cfg!(target_os = "macos") {
        assert!(birth, "APFS records a birth time");
    }
    // Remove it (test code; the product never removes a name outside the quarantine)
    // and create files until the inode is reused, or give up after 256 (ext4 reuses a
    // freed inode at once; APFS allocates new inode numbers).
    fs::remove_file(d.path().join(&first.name)).unwrap();
    let mut reused = false;
    for n in 1..256 {
        let s = stage(n);
        let same_inode = matches!(
            (&first.identity, &s.identity),
            (FileIdentity::Unix { dev: a, ino: b, .. }, FileIdentity::Unix { dev: c, ino: e, .. })
                if a == c && b == e
        );
        if same_inode {
            reused = true;
            if birth {
                assert_ne!(
                    first.identity, s.identity,
                    "a reused inode has a new birth time"
                );
                assert!(!first.identity.same_file(&s.identity));
            }
            break;
        }
        fs::remove_file(d.path().join(&s.name)).unwrap();
    }
    // With a birth time, the same (dev, ino) never compares equal across births, and a
    // birth on one side only is unequal in both directions.
    if let FileIdentity::Unix { dev, ino, birth: b } = first.identity.clone() {
        let none = FileIdentity::Unix {
            dev,
            ino,
            birth: None,
        };
        let other = FileIdentity::Unix {
            dev,
            ino,
            birth: Some(b.unwrap_or(0) + 1),
        };
        if b.is_some() {
            assert_ne!(first.identity, none);
            assert_ne!(none, first.identity);
        }
        assert_ne!(other, none);
        assert_ne!(first.identity, other);
    }
    // The test-only identity source drops the birth time.
    let nb = DirHandle::open_with(d.path(), IdentitySource::WithoutBirth).unwrap();
    let m = heimdall_localenv::projection::content::Materialized {
        sha256: sha(b"x"),
        bytes: b"x".to_vec(),
    };
    let s = replace::stage(&nb, &staged_name("nb", 1), &m, Mode::OwnerReadWrite).unwrap();
    assert!(matches!(
        s.identity,
        FileIdentity::Unix { birth: None, .. } | FileIdentity::Windows { .. }
    ));
    eprintln!(
        "observation: file_identity_birth_recorded_on_target_fs os={} birth_recorded={birth} inode_reused={reused}",
        std::env::consts::OS
    );
}

// --- validation (§5.3 steps 1, 2, 4) ---------------------------------------------

/// ADR-0007 §5.3 steps 1–2: what is manual mode and what is a conflict.
#[cfg(unix)]
#[test]
fn validate_refuses_unmanageable_and_changed_bases() {
    let d = scratch();
    let p = d.path();
    let h = DirHandle::open(p).unwrap();
    let present = Base::Present { sha256: sha(OLD) };
    let unmanageable = |name: &str| replace::validate(&h, name, &present).unwrap_err();
    write(p, "target", OLD);
    std::os::unix::fs::symlink(p.join("target"), p.join("link")).unwrap();
    assert_eq!(
        unmanageable("link"),
        ReplaceRefusal::Unmanageable(Unmanageable::Link)
    );
    write(p, "hard", OLD);
    fs::hard_link(p.join("hard"), p.join("hard2")).unwrap();
    assert_eq!(
        unmanageable("hard"),
        ReplaceRefusal::Unmanageable(Unmanageable::HardLinked)
    );
    write(p, "group", OLD);
    set_mode(&p.join("group"), 0o664);
    assert_eq!(
        unmanageable("group"),
        ReplaceRefusal::Unmanageable(Unmanageable::ForeignOwner)
    );
    write(p, "readonly", OLD);
    set_mode(&p.join("readonly"), 0o400);
    assert_eq!(
        unmanageable("readonly"),
        ReplaceRefusal::Unmanageable(Unmanageable::ForeignOwner)
    );
    fs::create_dir(p.join("dir")).unwrap();
    assert!(matches!(
        unmanageable("dir"),
        ReplaceRefusal::Unmanageable(Unmanageable::Io(_))
    ));
    let fifo = std::process::Command::new("mkfifo")
        .arg(p.join("fifo"))
        .status()
        .unwrap();
    assert!(fifo.success());
    assert!(matches!(
        unmanageable("fifo"),
        ReplaceRefusal::Unmanageable(Unmanageable::Io(_))
    ));
    // Conflicts: other content, gone, present where absent was planned, too long.
    write(p, "edited", WRITER);
    assert_eq!(unmanageable("edited"), ReplaceRefusal::BaseChanged);
    assert_eq!(unmanageable("missing"), ReplaceRefusal::BaseChanged);
    assert_eq!(
        replace::validate(&h, "target", &Base::Absent).unwrap_err(),
        ReplaceRefusal::BaseChanged
    );
    let big = vec![b'a'; READ_MAX + 1];
    write(p, "big", &big);
    assert_eq!(
        replace::validate(&h, "big", &Base::Present { sha256: sha(&big) }).unwrap_err(),
        ReplaceRefusal::BaseChanged
    );
    // Not a single name.
    assert!(matches!(
        replace::validate(&h, "../target", &present),
        Err(ReplaceRefusal::Unmanageable(Unmanageable::Io(_)))
    ));
    // The valid base, then a boundary recheck after an in-place edit or a mode change.
    let v = replace::validate(&h, "target", &present).unwrap();
    assert_eq!(v.bytes.as_deref(), Some(OLD));
    replace::recheck_at(&h, "target", &v).unwrap();
    set_mode(&p.join("target"), 0o640);
    assert_eq!(
        replace::recheck_at(&h, "target", &v),
        Err(ReplaceRefusal::BaseChanged)
    );
    set_mode(&p.join("target"), 0o600);
    replace::recheck_at(&h, "target", &v).unwrap();
    write_in_place(&p.join("target"), WRITER);
    assert_eq!(
        replace::recheck_at(&h, "target", &v),
        Err(ReplaceRefusal::BaseChanged)
    );
    // Every file is where it was, with its bytes.
    assert_eq!(read(p, "target"), WRITER);
    assert_eq!(read(p, "hard2"), OLD);
}

/// ADR-0007 §5.3 step 1: the directory itself.
#[cfg(unix)]
#[test]
fn dir_handle_refuses_symlink_foreign_mode_and_files() {
    let d = scratch();
    let p = d.path();
    fs::create_dir(p.join("real")).unwrap();
    set_mode(&p.join("real"), 0o700);
    std::os::unix::fs::symlink(p.join("real"), p.join("alias")).unwrap();
    assert_eq!(
        DirHandle::open(&p.join("alias")).unwrap_err(),
        Unmanageable::Link
    );
    set_mode(&p.join("real"), 0o770);
    assert_eq!(
        DirHandle::open(&p.join("real")).unwrap_err(),
        Unmanageable::ForeignOwner
    );
    set_mode(&p.join("real"), 0o755);
    let h = DirHandle::open(&p.join("real")).unwrap();
    assert_eq!(h.path(), p.join("real"));
    write(p, "file", OLD);
    assert!(matches!(
        DirHandle::open(&p.join("file")),
        Err(Unmanageable::Io(_))
    ));
    // A directory whose mode changes after it was opened no longer validates.
    set_mode(&p.join("real"), 0o775);
    assert!(matches!(
        replace::validate(&h, "x", &Base::Absent),
        Err(ReplaceRefusal::Unmanageable(_))
    ));
}

/// A replace stages with the original's permission bits; a create with the mode.
#[cfg(unix)]
#[test]
fn stage_keeps_the_original_permission_bits() {
    let d = scratch();
    let p = d.path();
    write(p, "config", OLD);
    set_mode(&p.join("config"), 0o640);
    let h = DirHandle::open(p).unwrap();
    let step = whole_step(FileRole::ManagedSsh, &p.join("config"), Some(OLD), NEW, 1);
    let v = replace::validate(&h, "config", &step.base).unwrap();
    let m = materialize(&step, v.bytes.as_deref()).unwrap();
    h.learn_step(&step);
    let s = replace::stage(
        &h,
        step.staged_name.as_deref().unwrap(),
        &m,
        Mode::OwnerReadWrite,
    )
    .unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o640);
    let key = whole_step(
        FileRole::Key,
        &p.join("k.pub"),
        None,
        b"ssh-ed25519 AAAA\n",
        2,
    );
    let m = materialize(&key, None).unwrap();
    let s = replace::stage(
        &h,
        key.staged_name.as_deref().unwrap(),
        &m,
        Mode::PublicRead,
    )
    .unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o644);
    let s = replace::stage(&h, &staged_name("p", 3), &m, Mode::OwnerReadWrite).unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o600);
    // An existing staged name is never replaced.
    assert_eq!(
        replace::stage(&h, &staged_name("p", 3), &m, Mode::OwnerReadWrite),
        Err(ReplaceError::Exists)
    );
}

// --- quarantine (§5.3 "The quarantine") -------------------------------------------

/// m02-plan U4 quarantine validation: mode exactly 0700, no symlink, a directory. The
/// owner and mount-point rules, which need privileges to build, are covered by the
/// unit test `sys::quarantine::tests::quarantine_validation_rules`.
#[cfg(unix)]
#[test]
fn quarantine_validation_owner_mode_symlink_mount() {
    let d = scratch();
    let p = d.path();
    let h = DirHandle::open(p).unwrap();
    // Created lazily at mode 0700 and reopened.
    let q = Quarantine::open_or_create(&h).unwrap();
    assert_eq!(mode_of(&p.join(".hm-quarantine")), 0o700);
    assert!(Quarantine::open_existing(&h).unwrap().is_some());
    assert!(q.rmdir_if_empty().unwrap());
    assert!(!p.join(".hm-quarantine").exists());
    assert!(Quarantine::open_existing(&h).unwrap().is_none());
    // Mode 0755: refused, and never changed.
    fs::create_dir(p.join(".hm-quarantine")).unwrap();
    set_mode(&p.join(".hm-quarantine"), 0o755);
    assert_eq!(
        Quarantine::open_or_create(&h).unwrap_err(),
        Unmanageable::QuarantineInvalid
    );
    assert_eq!(mode_of(&p.join(".hm-quarantine")), 0o755);
    fs::remove_dir(p.join(".hm-quarantine")).unwrap();
    // A symlink to an owner-only directory: refused, and its target untouched.
    fs::create_dir(p.join("elsewhere")).unwrap();
    set_mode(&p.join("elsewhere"), 0o700);
    write(&p.join("elsewhere"), "kept", OLD);
    std::os::unix::fs::symlink(p.join("elsewhere"), p.join(".hm-quarantine")).unwrap();
    assert_eq!(
        Quarantine::open_or_create(&h).unwrap_err(),
        Unmanageable::QuarantineInvalid
    );
    assert_eq!(
        Quarantine::open_existing(&h).unwrap_err(),
        Unmanageable::QuarantineInvalid
    );
    assert_eq!(read(&p.join("elsewhere"), "kept"), OLD);
    fs::remove_file(p.join(".hm-quarantine")).unwrap();
    // A regular file at the name.
    write(p, ".hm-quarantine", OLD);
    assert_eq!(
        Quarantine::open_or_create(&h).unwrap_err(),
        Unmanageable::QuarantineInvalid
    );
    assert_eq!(read(p, ".hm-quarantine"), OLD);
}

/// `remove_verified`: the only removal, of an entry with the expected identity and
/// digest; an identity or content mismatch keeps the entry.
#[test]
fn remove_verified_identity_and_content_mismatch_outcomes() {
    let f = Forward::new();
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    let qdir = f.path().join(".hm-quarantine");
    let s1 = slot(1);
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &s1),
        SettleOutcome::Settled
    );
    assert!(!f.staged_path().exists());
    // Another identity: kept.
    let other = Expected {
        identity: f.v(),
        sha256: f.expected_s.sha256.clone(),
    };
    assert_eq!(
        q.remove_verified(&s1, &other).unwrap(),
        RemoveVerified::Foreign
    );
    // Another digest: kept.
    let wrong = Expected {
        identity: f.staged.identity.clone(),
        sha256: sha(OLD),
    };
    assert_eq!(
        q.remove_verified(&s1, &wrong).unwrap(),
        RemoveVerified::Modified
    );
    // Written into after the settlement check: kept, with the writer's bytes.
    write_in_place(&qdir.join(&s1), WRITER);
    assert_eq!(
        q.remove_verified(&s1, &f.expected_s).unwrap(),
        RemoveVerified::Modified
    );
    assert_eq!(read(&qdir, &s1), WRITER);
    assert_eq!(
        q.check_slot(&s1, &f.expected_s),
        NameState::Expected(ContentState::Modified)
    );
    // A foreign entry in a slot: kept.
    let s2 = slot(2);
    write(&qdir, &s2, NEW);
    assert_eq!(
        q.remove_verified(&s2, &f.expected_s).unwrap(),
        RemoveVerified::Foreign
    );
    assert_eq!(q.check_slot(&s2, &f.expected_s), NameState::Foreign);
    // The expected entry: removed, then missing.
    let s3 = slot(3);
    let m = heimdall_localenv::projection::content::Materialized {
        sha256: sha(NEW),
        bytes: NEW.to_vec(),
    };
    let st = replace::stage(
        &f.handle,
        &staged_name("other", 9),
        &m,
        Mode::OwnerReadWrite,
    )
    .unwrap();
    let exp = Expected {
        identity: st.identity.clone(),
        sha256: sha(NEW),
    };
    assert_eq!(
        replace::settle(&f.handle, &q, &st.name, &exp, &s3),
        SettleOutcome::Settled
    );
    assert_eq!(
        q.check_slot(&s3, &exp),
        NameState::Expected(ContentState::Unchanged)
    );
    assert_eq!(
        q.remove_verified(&s3, &exp).unwrap(),
        RemoveVerified::Removed
    );
    assert!(!qdir.join(&s3).exists());
    assert_eq!(
        q.remove_verified(&s3, &exp).unwrap(),
        RemoveVerified::Missing
    );
    assert_eq!(q.check_slot(&s3, &exp), NameState::Absent);
    // A slot name that is not a single component is refused.
    assert!(q.remove_verified("../config", &exp).is_err());
    // The quarantine with entries is never removed, and its entries survive.
    assert!(!q.rmdir_if_empty().unwrap());
    assert_eq!(read(&qdir, &s1), WRITER);
    assert_eq!(read(&qdir, &s2), NEW);
    assert_eq!(read(f.path(), "config"), OLD);
}

/// The residual window (ADR-0007 §5.9 item 1): `AfterSettleCheck` fires between the
/// final check and the removal. On Unix a write there is lost with the entry; on
/// Windows the checked delete handle denies the writer's open. A write just before
/// the final check is kept (tested by the content-mismatch cases above).
#[test]
fn remove_verified_hook_marks_the_residual_window() {
    let f = Forward::new();
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    let qdir = f.path().join(".hm-quarantine");
    let s1 = slot(1);
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &s1),
        SettleOutcome::Settled
    );
    let target = qdir.join(&s1);
    let hook = At::new(ReplacePoint::AfterSettleCheck, move || {
        #[cfg(unix)]
        write_in_place(&target, WRITER);
        #[cfg(windows)]
        {
            let err = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&target)
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(32), "write sharing is denied");
            assert_eq!(fs::read(&target).unwrap(), NEW, "checked bytes unchanged");
        }
    });
    let out = q
        .remove_verified_with(&s1, &f.expected_s, HookAt::new(Some(&hook), 0))
        .unwrap();
    assert_eq!(out, RemoveVerified::Removed);
    assert_eq!(
        *hook.fired.lock().unwrap(),
        vec![ReplacePoint::AfterSettleCheck]
    );
    assert!(
        !qdir.join(&s1).exists(),
        "the checked entry is removed after the hook"
    );
}

/// A foreign file renamed onto the slot after the final check is not removed: the
/// name is re-checked against the checked inode immediately before the removal.
#[cfg(unix)]
#[test]
fn remove_verified_rechecks_the_name_before_removal() {
    let f = Forward::new();
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    let qdir = f.path().join(".hm-quarantine");
    let s1 = slot(1);
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &s1),
        SettleOutcome::Settled
    );
    let (dir, target) = (f.path().to_path_buf(), qdir.join(&s1));
    let hook = At::new(ReplacePoint::AfterSettleCheck, move || {
        write(&dir, "foreign.tmp", WRITER);
        fs::rename(dir.join("foreign.tmp"), &target).unwrap();
    });
    assert_eq!(
        q.remove_verified_with(&s1, &f.expected_s, HookAt::new(Some(&hook), 0))
            .unwrap(),
        RemoveVerified::Foreign
    );
    assert_eq!(read(&qdir, &s1), WRITER);
}

/// `settle`: missing, foreign at the source (never moved), occupied slot (nothing
/// moved), modified after the move (kept), a foreign entry moved in (put back, or kept
/// under a conflict name).
#[test]
fn settle_outcomes_missing_foreign_occupied_modified() {
    let f = Forward::new();
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    let qdir = f.path().join(".hm-quarantine");
    assert_eq!(
        replace::settle(&f.handle, &q, "nothing-here", &f.expected_s, &slot(1)),
        SettleOutcome::Missing
    );
    // A foreign entry at the source: not moved.
    assert_eq!(
        replace::settle(&f.handle, &q, "config", &f.expected_s, &slot(2)),
        SettleOutcome::ForeignPutBack {
            path: "config".to_owned()
        }
    );
    assert_eq!(read(f.path(), "config"), OLD);
    assert!(!qdir.join(slot(2)).exists());
    // An occupied slot: nothing moved.
    write(&qdir, &slot(3), WRITER);
    assert_eq!(
        replace::settle_with(
            &f.handle,
            &q,
            &f.staged.name,
            &f.expected_s,
            &slot(3),
            HookAt::NONE
        ),
        Err(ReplaceError::Exists)
    );
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &slot(3)),
        SettleOutcome::ForeignPutBack {
            path: f.staged.name.clone()
        }
    );
    assert_eq!(fs::read(f.staged_path()).unwrap(), NEW);
    assert_eq!(read(&qdir, &slot(3)), WRITER);
    // Written into between the move and its check: kept in the quarantine.
    let moved = qdir.join(slot(4));
    let hook = At::new(ReplacePoint::AfterSettleMove, move || {
        write_in_place(&moved, WRITER)
    });
    assert_eq!(
        replace::settle_with(
            &f.handle,
            &q,
            &f.staged.name,
            &f.expected_s,
            &slot(4),
            HookAt::new(Some(&hook), 0)
        ),
        Ok(SettleOutcome::Modified { slot: slot(4) })
    );
    assert_eq!(read(&qdir, &slot(4)), WRITER);
    // A foreign entry replaces the moved one before its check: it is put back at the
    // source name; with the source occupied again, it is kept beside it.
    let g = Forward::new();
    let gq = Quarantine::open_or_create(&g.handle).unwrap();
    let gdir = g.path().to_path_buf();
    let hook = At::new(ReplacePoint::AfterSettleMove, move || {
        write(&gdir, "foreign.tmp", WRITER);
        fs::rename(
            gdir.join("foreign.tmp"),
            gdir.join(".hm-quarantine").join(slot(5)),
        )
        .unwrap();
    });
    assert_eq!(
        replace::settle_with(
            &g.handle,
            &gq,
            &g.staged.name,
            &g.expected_s,
            &slot(5),
            HookAt::new(Some(&hook), 0)
        ),
        Ok(SettleOutcome::ForeignPutBack {
            path: g.staged.name.clone()
        })
    );
    assert_eq!(fs::read(g.staged_path()).unwrap(), WRITER);
    write(&g.path().join(".hm-quarantine"), &slot(6), NEW);
    assert_eq!(
        gq.put_back(&g.handle, &slot(6), &g.staged.name).unwrap(),
        SettleOutcome::ForeignKept {
            path: format!("{}.hm-conflict-{}", g.staged.name, slot(6))
        }
    );
    assert_eq!(
        read(
            g.path(),
            &format!("{}.hm-conflict-{}", g.staged.name, slot(6))
        ),
        NEW
    );
    assert_eq!(fs::read(g.staged_path()).unwrap(), WRITER);
}

// --- races at the boundary (M2-D03; ADR-0007 §5.3 steps 5–7) -----------------------

/// m02-plan U4 race injection at `BeforeExchange`, primitive level: another writer
/// rename-replaces the file after the final check. The displaced entry is not V, so
/// post-validation reports the writer's identity, the restore puts the writer's file
/// back intact, and S is settled. The writer's bytes are never overwritten.
#[test]
fn race_rename_replace_before_exchange_is_restored_never_overwritten() {
    let f = Forward::new();
    let hook = {
        let dir = f.path().to_path_buf();
        At::new(ReplacePoint::BeforeExchange, move || {
            rename_replace(&dir, "config", WRITER)
        })
    };
    hook.at(ReplacePoint::BeforeExchange, 0);
    let x = f.exchange();
    let PostValidation::Mismatch { observed: Some(w) } = f.post_validate(&x) else {
        panic!("the displaced entry is the writer's, not V");
    };
    assert_ne!(w, f.v());
    let displaced = x.displaced_name.clone().unwrap();
    assert_eq!(read(f.path(), &displaced), WRITER);
    assert_eq!(f.restore(&w), RestoreOutcome::Restored);
    assert_eq!(read(f.path(), "config"), WRITER);
    #[cfg(unix)]
    assert!(is_at(&w, &f.path().join("config")));
    assert_eq!(fs::read(f.staged_path()).unwrap(), NEW);
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &slot(1)),
        SettleOutcome::Settled
    );
    assert_eq!(
        q.remove_verified(&slot(1), &f.expected_s).unwrap(),
        RemoveVerified::Removed
    );
    assert!(q.rmdir_if_empty().unwrap());
    let left: Vec<_> = fs::read_dir(f.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from("config")]);
    assert_eq!(read(f.path(), "config"), WRITER);
}

/// The in-place variant: the writer rewrites V after the final check. D is V with
/// other content: a mismatch naming V, then restored with the writer's bytes.
#[test]
fn race_in_place_write_before_exchange_is_restored() {
    let f = Forward::new();
    write_in_place(&f.path().join("config"), WRITER);
    let x = f.exchange();
    let PostValidation::Mismatch { observed: Some(d) } = f.post_validate(&x) else {
        panic!("V with other content is a mismatch");
    };
    assert_eq!(d, f.v());
    assert_eq!(f.restore(&d), RestoreOutcome::Restored);
    assert_eq!(read(f.path(), "config"), WRITER);
    assert_eq!(fs::read(f.staged_path()).unwrap(), NEW);
}

/// The symlink variant (Unix), primitive level (ADR-0007 §12.17 item 5): a symlink
/// substituted at the boundary is X whatever its identity (normalization rule 1), so
/// the restore holds (`third_writer`) and nothing moves: S stays active, the symlink
/// stays at the staged name, and its target is untouched.
#[cfg(unix)]
#[test]
fn race_symlink_substitution_at_boundary_is_held() {
    let f = Forward::new();
    let p = f.path();
    write(p, "elsewhere", WRITER);
    std::os::unix::fs::symlink(p.join("elsewhere"), p.join("link.tmp")).unwrap();
    fs::rename(p.join("link.tmp"), p.join("config")).unwrap();
    let x = f.exchange();
    let PostValidation::Mismatch { observed: Some(d) } = f.post_validate(&x) else {
        panic!("a symlink is not V");
    };
    match f.restore(&d) {
        RestoreOutcome::Held(HoldReason::ThirdWriter, obs) => {
            assert_eq!(obs.aside(), EntryObs::Foreign, "a symlink is X");
        }
        other => panic!("expected third_writer, got {other:?}"),
    }
    assert_eq!(read(p, "config"), NEW);
    assert!(
        fs::symlink_metadata(f.staged_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(f.staged_path()).unwrap(), p.join("elsewhere"));
    assert_eq!(read(p, "elsewhere"), WRITER);
    // A hard link to D is X too: nothing moves.
    let g = Forward::new();
    let x = g.exchange();
    assert_eq!(g.post_validate(&x), PostValidation::Valid);
    fs::hard_link(g.staged_path(), g.path().join("extra")).unwrap();
    assert!(matches!(
        g.restore(&g.v()),
        RestoreOutcome::Held(HoldReason::ThirdWriter, _)
    ));
    assert_eq!(read(g.path(), "config"), NEW);
    assert_eq!(fs::read(g.displaced_path()).unwrap(), OLD);
}

/// A create is a no-replace rename: a writer that creates the file first wins, and
/// its bytes are never overwritten.
#[test]
fn create_is_no_replace_and_never_overwrites() {
    let d = scratch();
    let p = d.path();
    let h = DirHandle::open(p).unwrap();
    let step = whole_step(FileRole::ManagedSsh, &p.join("config"), None, NEW, 1);
    let v = replace::validate(&h, "config", &Base::Absent).unwrap();
    let m = materialize(&step, None).unwrap();
    let s = replace::stage(
        &h,
        step.staged_name.as_deref().unwrap(),
        &m,
        Mode::OwnerReadWrite,
    )
    .unwrap();
    let names = StepNames::of(&step).unwrap();
    replace::recheck_at(&h, "config", &v).unwrap();
    write(p, "config", WRITER);
    assert_eq!(
        replace::recheck_at(&h, "config", &v),
        Err(ReplaceRefusal::BaseChanged)
    );
    assert_eq!(
        replace::exchange_at(&h, &names, &s, None),
        Err(ReplaceError::Exists)
    );
    assert_eq!(read(p, "config"), WRITER);
    assert_eq!(read(p, &s.name), NEW);
    // Without the writer the create succeeds and post-validates.
    fs::remove_file(p.join("config")).unwrap();
    let x = replace::exchange_at(&h, &names, &s, None).unwrap();
    assert_eq!(x.displaced_name, None);
    assert_eq!(
        replace::post_validate_at(&h, &names, &x, &v, &s),
        PostValidation::Valid
    );
    assert_eq!(read(p, "config"), NEW);
    assert!(!p.join(&s.name).exists());
}

/// ADR-0007 §5.3 step 7 and QR13: before anything moves, the path must be S with the
/// target digest and the aside D. An in-place edit of S holds (`active_entry_modified`);
/// a third writer at either name holds (`third_writer`); nothing moves.
#[test]
fn restore_holds_on_modified_active_entry_or_third_writer_and_moves_nothing() {
    // The active S edited in place after a valid forward exchange.
    let f = Forward::new();
    let x = f.exchange();
    assert_eq!(f.post_validate(&x), PostValidation::Valid);
    write_in_place(&f.path().join("config"), WRITER);
    match f.restore(&f.v()) {
        RestoreOutcome::Held(HoldReason::ActiveEntryModified, obs) => {
            assert_eq!(
                obs.path(),
                EntryObs::Recorded {
                    which: RecordedRole::S,
                    content: ContentState::Modified
                }
            );
        }
        other => panic!("expected active_entry_modified, got {other:?}"),
    }
    assert_eq!(read(f.path(), "config"), WRITER);
    assert_eq!(fs::read(f.displaced_path()).unwrap(), OLD);
    // A third writer replaced the displaced entry.
    let g = Forward::new();
    g.exchange();
    rename_replace(
        g.path(),
        g.step.displaced_name.as_deref().unwrap(),
        b"third\n",
    );
    assert!(matches!(
        g.restore(&g.v()),
        RestoreOutcome::Held(HoldReason::ThirdWriter, _)
    ));
    assert_eq!(read(g.path(), "config"), NEW);
    assert_eq!(fs::read(g.displaced_path()).unwrap(), b"third\n");
    // A third writer replaced the active entry.
    let k = Forward::new();
    k.exchange();
    rename_replace(k.path(), "config", b"third\n");
    assert!(matches!(
        k.restore(&k.v()),
        RestoreOutcome::Held(HoldReason::ThirdWriter, _)
    ));
    assert_eq!(read(k.path(), "config"), b"third\n");
    assert_eq!(fs::read(k.displaced_path()).unwrap(), OLD);
}

/// `restore_with`: the receipt callback runs after the content check and before the
/// exchange; an edit that lands at `BeforeRestoreExchange` (after the check) is moved
/// aside with S and kept in the quarantine by settlement, never deleted. A failing
/// callback moves nothing.
#[test]
fn edit_after_restore_check_is_kept_in_quarantine_never_deleted() {
    let f = Forward::new();
    let x = f.exchange();
    assert_eq!(x.displaced_name.as_deref(), f.names().displaced.as_deref());
    // A failing receipt write: nothing moves.
    let failed = replace::restore_with(
        &f.handle,
        &f.names(),
        &f.expected_s,
        &f.v(),
        HookAt::NONE,
        || Err::<(), &str>("store unavailable"),
    );
    assert_eq!(
        failed,
        Err(RestoreFailure::BeforeExchange("store unavailable"))
    );
    assert_eq!(read(f.path(), "config"), NEW);
    assert_eq!(fs::read(f.displaced_path()).unwrap(), OLD);
    // The edit lands after the check.
    let order = Mutex::new(Vec::<&str>::new());
    let config = f.path().join("config");
    let hook = At::new(ReplacePoint::BeforeRestoreExchange, move || {
        write_in_place(&config, WRITER);
    });
    let out = replace::restore_with(
        &f.handle,
        &f.names(),
        &f.expected_s,
        &f.v(),
        HookAt::new(Some(&hook), 0),
        || {
            order.lock().unwrap().push("restore_started");
            Ok::<(), ()>(())
        },
    );
    assert_eq!(out, Ok(RestoreOutcome::Restored));
    assert_eq!(*order.lock().unwrap(), vec!["restore_started"]);
    assert_eq!(
        *hook.fired.lock().unwrap(),
        vec![ReplacePoint::BeforeRestoreExchange]
    );
    assert_eq!(read(f.path(), "config"), OLD);
    assert_eq!(fs::read(f.staged_path()).unwrap(), WRITER);
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    assert_eq!(
        replace::settle(&f.handle, &q, &f.staged.name, &f.expected_s, &slot(1)),
        SettleOutcome::Modified { slot: slot(1) }
    );
    assert_eq!(read(&f.path().join(".hm-quarantine"), &slot(1)), WRITER);
    assert!(!q.rmdir_if_empty().unwrap());
}

/// ADR-0007 §12.17 item 1: `restore_with` acts on the names it is given, so a fresh
/// handle in a recovering process, which never validated, staged or exchanged
/// anything, restores from the step's names alone. Names whose displaced name holds
/// nothing of the step hold (`third_writer`), and names without a displaced name (a
/// create, restored by settlement instead) hold (`unmatched`); nothing moves.
#[test]
fn restore_with_names_in_a_fresh_handle() {
    let f = Forward::new();
    f.exchange();
    let record = StepRecord {
        staged: Some(f.expected_s.clone()),
        validated: Some(Expected {
            identity: f.v(),
            sha256: sha(OLD),
        }),
        ..StepRecord::default()
    };
    let state = RecoveryState {
        phase: Some(EffectivePhase::RestoreStarted {
            cause: heimdall_domain::operation::RestoreCause::TransactionCheck,
        }),
        restore: RestoreCtx::Started(heimdall_domain::operation::RestoreCause::TransactionCheck),
        settlement: None,
        item: ItemState::RollingBack,
        release_due: false,
    };
    let fresh = DirHandle::open(f.path()).unwrap();
    let obs = replace::observe_step_at(&fresh, &f.step, &record, &state, None);
    assert_eq!(
        obs.path(),
        EntryObs::Recorded {
            which: RecordedRole::S,
            content: ContentState::Unchanged
        }
    );
    let fresh = DirHandle::open(f.path()).unwrap();
    assert_eq!(f.restore_in(&fresh, &f.v()), RestoreOutcome::Restored);
    assert_eq!(read(f.path(), "config"), OLD);
    assert_eq!(fs::read(f.staged_path()).unwrap(), NEW);
    // A displaced name that holds nothing of the step: held, nothing moved.
    let g = Forward::new();
    g.exchange();
    let mut names = g.names();
    names.displaced = Some("not-a-step-name".to_owned());
    let held = replace::restore_with(
        &DirHandle::open(g.path()).unwrap(),
        &names,
        &g.expected_s,
        &g.v(),
        HookAt::NONE,
        || Ok::<(), ()>(()),
    );
    assert!(matches!(
        held,
        Ok(RestoreOutcome::Held(HoldReason::ThirdWriter, _))
    ));
    // No displaced name: a create is never restored by an exchange.
    names.displaced = None;
    let held = replace::restore_with(
        &DirHandle::open(g.path()).unwrap(),
        &names,
        &g.expected_s,
        &g.v(),
        HookAt::NONE,
        || Ok::<(), ()>(()),
    );
    assert!(matches!(
        held,
        Ok(RestoreOutcome::Held(HoldReason::Unmatched, _))
    ));
    assert_eq!(read(g.path(), "config"), NEW);
    assert_eq!(fs::read(g.displaced_path()).unwrap(), OLD);
}

// --- observation (reconcile and held previews) -------------------------------------

fn state(phase: Option<EffectivePhase>) -> RecoveryState {
    RecoveryState {
        phase,
        restore: RestoreCtx::NotDue,
        settlement: None,
        item: ItemState::Open,
        release_due: false,
    }
}

/// `observe_step_at` gives each name one ADR-0007 §5.7 symbol through the normalizing
/// constructor: S/S′ at the path, V at the aside, X for a hard link (rule 1), Q in the
/// slot it is given, `?` everywhere for a directory that is not the step's, and `?` at
/// the slot when the state has a settlement whose slot the caller did not give
/// (ADR-0007 §12.17 item 1: the quarantine is never searched for a slot).
#[test]
fn observe_step_classifies_each_name() {
    let f = Forward::new();
    let x = f.exchange();
    let record = StepRecord {
        staged: Some(f.expected_s.clone()),
        validated: Some(Expected {
            identity: f.v(),
            sha256: sha(OLD),
        }),
        ..StepRecord::default()
    };
    let st = state(Some(EffectivePhase::Exchanged));
    let s = |content| EntryObs::Recorded {
        which: RecordedRole::S,
        content,
    };
    let v = EntryObs::Recorded {
        which: RecordedRole::V,
        content: ContentState::Unchanged,
    };
    let obs = replace::observe_step_at(&f.handle, &f.step, &record, &st, None);
    assert_eq!(
        (obs.path(), obs.aside(), obs.slot()),
        (s(ContentState::Unchanged), v, EntryObs::Absent)
    );
    write_in_place(&f.path().join("config"), WRITER);
    let obs = replace::observe_step_at(&f.handle, &f.step, &record, &st, None);
    assert_eq!(obs.path(), s(ContentState::Modified));
    // Rule 1: a hard link makes the entry X whatever its identity.
    #[cfg(unix)]
    {
        fs::hard_link(f.staged_path(), f.path().join("extra")).unwrap();
        let obs = replace::observe_step_at(&f.handle, &f.step, &record, &st, None);
        assert_eq!(obs.aside(), EntryObs::Foreign);
        fs::remove_file(f.path().join("extra")).unwrap();
    }
    // A step whose directory is not this handle's: every name `?`.
    let mut elsewhere = f.step.clone();
    elsewhere.path = "/scratch/other/config".to_owned();
    let obs = replace::observe_step_at(&f.handle, &elsewhere, &record, &st, None);
    assert_eq!(
        (obs.path(), obs.aside()),
        (EntryObs::Unobservable, EntryObs::Unobservable)
    );
    // Settlement of V: Q at the slot while settling and after `file.settled`.
    let q = Quarantine::open_or_create(&f.handle).unwrap();
    let displaced = x.displaced_name.clone().unwrap();
    let qv = Expected {
        identity: f.v(),
        sha256: sha(OLD),
    };
    assert_eq!(
        replace::settle(&f.handle, &q, &displaced, &qv, &slot(7)),
        SettleOutcome::Settled
    );
    let record = StepRecord {
        settling: Some(qv.clone()),
        ..record
    };
    let settling = RecoveryState {
        phase: Some(EffectivePhase::Settling {
            source: SettleSource::Displaced,
            name: displaced.clone(),
            expected: f.v(),
            expected_sha256: sha(OLD),
            slot: slot(7),
        }),
        restore: RestoreCtx::NotDue,
        settlement: Some(SettleCtx {
            source: SettleSource::Displaced,
            create_restore: false,
        }),
        item: ItemState::Committed,
        release_due: false,
    };
    let q_unchanged = EntryObs::Recorded {
        which: RecordedRole::Q,
        content: ContentState::Unchanged,
    };
    let at = replace::SettlingAt {
        name: displaced.clone(),
        slot: slot(7),
        expected: qv.clone(),
    };
    let obs = replace::observe_step_at(&f.handle, &f.step, &record, &settling, Some(&at));
    assert_eq!((obs.aside(), obs.slot()), (EntryObs::Absent, q_unchanged));
    let settled = RecoveryState {
        phase: Some(EffectivePhase::Settled {
            disposition: SettledDisposition::Quarantined,
        }),
        ..settling.clone()
    };
    let obs = replace::observe_step_at(&f.handle, &f.step, &record, &settled, Some(&at));
    assert_eq!(obs.slot(), q_unchanged);
    // A settlement whose slot is not given is `?` at the slot, never `∅` and never a
    // search of the quarantine.
    let obs = replace::observe_step_at(&f.handle, &f.step, &record, &settled, None);
    assert_eq!(obs.slot(), EntryObs::Unobservable);
    // A quarantine that no longer validates makes the slot `?`, never `∅`.
    #[cfg(unix)]
    {
        let qdir = f.path().join(".hm-quarantine");
        set_mode(&qdir, 0o755);
        let obs = replace::observe_step_at(&f.handle, &f.step, &record, &settled, Some(&at));
        assert_eq!(obs.slot(), EntryObs::Unobservable);
        let obs = replace::observe_step_at(&f.handle, &f.step, &record, &settling, Some(&at));
        assert_eq!(obs.slot(), EntryObs::Unobservable);
        set_mode(&qdir, 0o700);
    }
    let at = replace::SettlingAt::from_receipts(0, &[]);
    assert!(at.is_none());
}

/// On Unix, when K's recorded identity has no birth time, every entry at the lock name
/// is X (ADR-0007 §5.6, QR15); with a birth time, K at the lock is K.
#[cfg(unix)]
#[test]
fn lock_name_without_birth_time_is_foreign() {
    for source in [IdentitySource::Native, IdentitySource::WithoutBirth] {
        let d = scratch();
        let p = d.path();
        let h = DirHandle::open_with(p, source).unwrap();
        let line = lock_holder_line(1, [0x11; 16]);
        let step = FileStep {
            role: FileRole::GitLock,
            path: p.join(".gitconfig.lock").to_string_lossy().into_owned(),
            base: Base::Absent,
            target: Target::Absent,
            content: rendered(&line).into_lock_holder(),
            commit: false,
            staged_name: Some(format!("{:032x}", 0x4b)),
            displaced_name: None,
        };
        let m = materialize(&step, None).unwrap();
        let k = replace::stage(
            &h,
            step.staged_name.as_deref().unwrap(),
            &m,
            Mode::OwnerReadWrite,
        )
        .unwrap();
        replace::rename_noreplace(&h, &k.name, ".gitconfig.lock").unwrap();
        assert_eq!(
            replace::rename_noreplace(&h, ".gitconfig.lock", ".gitconfig.lock"),
            Err(ReplaceError::Io("not a single name".into()))
        );
        let record = StepRecord {
            staged: Some(Expected {
                identity: k.identity.clone(),
                sha256: sha(&line),
            }),
            ..StepRecord::default()
        };
        let st = state(Some(EffectivePhase::Staged {
            identity: k.identity.clone(),
        }));
        let obs = replace::observe_step_at(&h, &step, &record, &st, None);
        let has_birth = matches!(k.identity, FileIdentity::Unix { birth: Some(_), .. });
        if has_birth {
            assert_eq!(
                obs.path(),
                EntryObs::Recorded {
                    which: RecordedRole::S,
                    content: ContentState::Unchanged
                }
            );
        } else {
            assert_eq!(obs.path(), EntryObs::Foreign);
        }
        assert_eq!(obs.aside(), EntryObs::Absent);
        // A second claim onto the occupied lock is refused and moves nothing.
        write(p, "k2", b"other\n");
        assert_eq!(
            replace::rename_noreplace(&h, "k2", ".gitconfig.lock"),
            Err(ReplaceError::Exists)
        );
        assert_eq!(read(p, ".gitconfig.lock"), line);
    }
}

/// ADR-0007 §12.17 item 2: rows F0x and K0x have their one home in the classifier.
/// For a step with no receipt, an entry at the step's own staged name that is a
/// regular file owned by the user with one link is S by digest (S with the target
/// digest, S′ otherwise); anything else there is X. It is never done at the path, so a
/// lock holder's exact bytes at the lock name stay X; and once the step has a receipt
/// an unrecorded entry at its staged name is X again.
#[test]
fn unrecorded_entry_at_staged_name_is_s_by_digest_never_at_lock_name() {
    let s = |content| EntryObs::Recorded {
        which: RecordedRole::S,
        content,
    };
    let none = state(None);
    let empty = StepRecord::default();
    let d = scratch();
    let p = d.path();
    write(p, "config", OLD);
    let h = DirHandle::open(p).unwrap();
    let step = whole_step(FileRole::ManagedSsh, &p.join("config"), Some(OLD), NEW, 1);
    let staged = step.staged_name.clone().unwrap();
    let observe = |st: &RecoveryState, record: &StepRecord| {
        replace::observe_step_at(&h, &step, record, st, None)
    };
    // F0: nothing at the staged name. The user's file at the path has no recorded
    // identity before `file.validated`, so it is X.
    let obs = observe(&none, &empty);
    assert_eq!(
        (obs.path(), obs.aside()),
        (EntryObs::Foreign, EntryObs::Absent)
    );
    // F0x: the target bytes, a partial write, and content past 1 MiB.
    write(p, &staged, NEW);
    assert_eq!(observe(&none, &empty).aside(), s(ContentState::Unchanged));
    write_in_place(&p.join(&staged), &NEW[..4]);
    assert_eq!(observe(&none, &empty).aside(), s(ContentState::Modified));
    write_in_place(&p.join(&staged), &vec![b'a'; READ_MAX + 1]);
    assert_eq!(observe(&none, &empty).aside(), s(ContentState::Modified));
    write_in_place(&p.join(&staged), NEW);
    // Once `file.staged` recorded another identity, the entry at the name is X.
    write(p, "elsewhere", WRITER);
    let other_id = replace::validate(
        &h,
        "elsewhere",
        &Base::Present {
            sha256: sha(WRITER),
        },
    )
    .unwrap()
    .identity
    .unwrap();
    let recorded = StepRecord {
        staged: Some(Expected {
            identity: other_id.clone(),
            sha256: sha(NEW),
        }),
        ..StepRecord::default()
    };
    let staged_state = state(Some(EffectivePhase::Staged { identity: other_id }));
    assert_eq!(observe(&staged_state, &recorded).aside(), EntryObs::Foreign);
    // F0z (Unix): not Heimdall's shape at the staged name is X whatever its bytes.
    #[cfg(unix)]
    {
        fs::hard_link(p.join(&staged), p.join("second-link")).unwrap();
        assert_eq!(observe(&none, &empty).aside(), EntryObs::Foreign);
        fs::remove_file(p.join("second-link")).unwrap();
        assert_eq!(observe(&none, &empty).aside(), s(ContentState::Unchanged));
        fs::remove_file(p.join(&staged)).unwrap();
        std::os::unix::fs::symlink(p.join("config"), p.join(&staged)).unwrap();
        assert_eq!(observe(&none, &empty).aside(), EntryObs::Foreign);
        fs::remove_file(p.join(&staged)).unwrap();
        fs::create_dir(p.join(&staged)).unwrap();
        assert_eq!(observe(&none, &empty).aside(), EntryObs::Foreign);
        fs::remove_dir(p.join(&staged)).unwrap();
    }
    // A removal stages nothing: an entry at its staged name is X.
    let mut removal = step.clone();
    removal.target = Target::Absent;
    removal.content = StepContent::absent();
    write(p, &staged, NEW);
    assert_eq!(
        replace::observe_step_at(&h, &removal, &empty, &none, None).aside(),
        EntryObs::Foreign
    );
    // Windows: only the staged name, never the displaced name, is F0x's.
    #[cfg(windows)]
    {
        fs::remove_file(p.join(&staged)).unwrap();
        let displaced = step.displaced_name.clone().unwrap();
        write(p, &displaced, NEW);
        assert_eq!(observe(&none, &empty).aside(), EntryObs::Foreign);
        write(p, &staged, NEW);
        assert_eq!(observe(&none, &empty).aside(), EntryObs::Foreign);
    }

    // K0x for the `git_lock` step: K's staged name, never the lock name.
    let k = scratch();
    let kp = k.path();
    let hk = DirHandle::open(kp).unwrap();
    let line = lock_holder_line(1, [0x2a; 16]);
    let lock = FileStep {
        role: FileRole::GitLock,
        path: kp.join(".gitconfig.lock").to_string_lossy().into_owned(),
        base: Base::Absent,
        target: Target::Absent,
        content: rendered(&line).into_lock_holder(),
        commit: false,
        staged_name: Some(staged_name("gitconfig.lock", 7)),
        displaced_name: None,
    };
    let k_staged = lock.staged_name.clone().unwrap();
    // The exact holder line at the lock name, with no receipt: X, never K.
    write(kp, ".gitconfig.lock", &line);
    let obs = replace::observe_step_at(&hk, &lock, &empty, &none, None);
    assert_eq!(
        (obs.path(), obs.aside()),
        (EntryObs::Foreign, EntryObs::Absent)
    );
    // K at its staged name: K (S) with the holder digest, K′ otherwise.
    write(kp, &k_staged, &line);
    let obs = replace::observe_step_at(&hk, &lock, &empty, &none, None);
    assert_eq!(
        (obs.path(), obs.aside()),
        (EntryObs::Foreign, s(ContentState::Unchanged))
    );
    write_in_place(
        &kp.join(&k_staged),
        b"heimdall setup lock, generation 1, x\n",
    );
    let obs = replace::observe_step_at(&hk, &lock, &empty, &none, None);
    assert_eq!(obs.aside(), s(ContentState::Modified));
    // The lock name alone, holder bytes included, is never classified as K.
    fs::remove_file(kp.join(&k_staged)).unwrap();
    let obs = replace::observe_step_at(&hk, &lock, &empty, &none, None);
    assert_eq!(
        (obs.path(), obs.aside()),
        (EntryObs::Foreign, EntryObs::Absent)
    );
    assert_eq!(read(kp, ".gitconfig.lock"), line);
}

/// ADR-0007 §12.17 item 1: the name-learning fallbacks are retired. A staged name in
/// the ADR's form (`.<name>.hm-<generation>-<32 hex>`) names nothing by itself: S takes
/// the permission bits of the base validated at the target only when the transaction
/// gave the step's names with `learn_step`; otherwise it gets the mode it was asked
/// for. Nothing is inferred from the name.
#[cfg(unix)]
#[test]
fn stage_names_its_target_only_through_learn_step() {
    let d = scratch();
    let p = d.path();
    write(p, "config", OLD);
    set_mode(&p.join("config"), 0o640);
    let step = whole_step(FileRole::ManagedSsh, &p.join("config"), Some(OLD), NEW, 1);
    let staged = step.staged_name.clone().unwrap();
    assert!(
        staged.starts_with(".config.hm-1-"),
        "the ADR's form names config"
    );
    let m = materialize(&step, Some(OLD)).unwrap();
    // Validated, not learned: the requested mode.
    let h = DirHandle::open(p).unwrap();
    replace::validate(&h, "config", &step.base).unwrap();
    let s = replace::stage(&h, &staged, &m, Mode::OwnerReadWrite).unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o600);
    // Learned in a fresh handle: the original's bits.
    let other = whole_step(FileRole::ManagedSsh, &p.join("config"), Some(OLD), NEW, 2);
    let h = DirHandle::open(p).unwrap();
    replace::validate(&h, "config", &other.base).unwrap();
    h.learn_step(&other);
    let s = replace::stage(
        &h,
        other.staged_name.as_deref().unwrap(),
        &m,
        Mode::OwnerReadWrite,
    )
    .unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o640);
    // Learned, but staged at a name the learned step does not have: the requested mode.
    let s = replace::stage(&h, &staged_name("config", 3), &m, Mode::OwnerReadWrite).unwrap();
    assert_eq!(mode_of(&p.join(&s.name)), 0o600);
    assert_eq!(read(p, "config"), OLD);
}

/// `observe_fingerprint`: identity, type, owner, links, length, change time and a
/// digest, or `unreadable` past 1 MiB; never bytes.
#[test]
fn observe_fingerprint_records_digests_and_metadata_only() {
    let f = Forward::new();
    let st = state(Some(EffectivePhase::Validated { base: Some(f.v()) }));
    let fp = replace::observe_fingerprint(&f.handle, &f.step, &st);
    match &fp.path {
        EntryFingerprint::Present {
            identity,
            file_type,
            owned_by_user,
            link_count,
            len,
            content,
            ..
        } => {
            assert_eq!(*identity, f.v());
            assert_eq!(*file_type, EntryFileType::Regular);
            assert!(*owned_by_user);
            assert_eq!(*link_count, 1);
            assert_eq!(*len, OLD.len() as u64);
            assert_eq!(*content, FingerprintContent::Sha256 { sha256: sha(OLD) });
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(fp.slot, None);
    // Before exchange S is present. Windows also observes the separate displaced
    // name, which does not exist until ReplaceFileW moves D there.
    assert!(matches!(fp.aside[0], EntryFingerprint::Present { .. }));
    if cfg!(windows) {
        assert_eq!(fp.aside.len(), 2);
        assert_eq!(fp.aside[1], EntryFingerprint::Absent);
    } else {
        assert_eq!(fp.aside.len(), 1);
    }
    let big = vec![b'a'; READ_MAX + 1];
    write(f.path(), "config", &big);
    let fp = replace::observe_fingerprint(&f.handle, &f.step, &st);
    assert!(matches!(
        fp.path,
        EntryFingerprint::Present {
            content: FingerprintContent::Unreadable,
            ..
        }
    ));
    assert!(
        !format!("{fp:?}").contains("aaaaaaaa"),
        "no bytes in a fingerprint"
    );
    fs::remove_file(f.path().join("config")).unwrap();
    let fp = replace::observe_fingerprint(&f.handle, &f.step, &st);
    assert_eq!(fp.path, EntryFingerprint::Absent);
}

// --- key files (A01) -------------------------------------------------------------

/// m02-plan U4 `private_key_files_never_opened`: with the private key file at mode
/// 000, the key file is still materialized from the `.pub` alone; it holds only the
/// type and blob (no comment, no private material) at mode 0644.
#[cfg(unix)]
#[test]
fn private_key_files_never_opened() {
    use heimdall_testkit::agent::FixtureKey;
    let d = scratch();
    let ssh = d.path().join("ssh");
    let keys = d.path().join("keys");
    for dir in [&ssh, &keys] {
        fs::create_dir(dir).unwrap();
        set_mode(dir, 0o700);
    }
    let key = FixtureKey::generate();
    key.write_private(&ssh.join("id_ed25519")).unwrap();
    key.write_public(&ssh.join("id_ed25519.pub")).unwrap();
    set_mode(&ssh.join("id_ed25519"), 0o000);
    // Discovery reads the `.pub`; nothing reads the private file.
    let line =
        PublicKeyLine::parse(&fs::read_to_string(ssh.join("id_ed25519.pub")).unwrap()).unwrap();
    assert_eq!(line.as_str(), key.public_line_without_comment());
    let rel = key_file_path(&key.fingerprint());
    let name = rel.file_name().unwrap().to_str().unwrap().to_owned();
    assert_eq!(rel.parent().unwrap(), Path::new("keys"));
    let r = public_key_bytes(&line);
    let step = FileStep {
        role: FileRole::Key,
        path: keys.join(&name).to_string_lossy().into_owned(),
        base: Base::Absent,
        target: Target::Present { sha256: r.sha256() },
        content: r.into_whole(),
        commit: false,
        staged_name: Some(staged_name(&name, 1)),
        displaced_name: None,
    };
    let h = DirHandle::open(&keys).unwrap();
    let v = replace::validate(&h, &name, &step.base).unwrap();
    let m = materialize(&step, None).unwrap();
    let s = replace::stage(
        &h,
        step.staged_name.as_deref().unwrap(),
        &m,
        Mode::PublicRead,
    )
    .unwrap();
    let names = StepNames::of(&step).unwrap();
    replace::recheck_at(&h, &name, &v).unwrap();
    let x = replace::exchange_at(&h, &names, &s, None).unwrap();
    assert_eq!(
        replace::post_validate_at(&h, &names, &x, &v, &s),
        PostValidation::Valid
    );
    let written = fs::read_to_string(keys.join(&name)).unwrap();
    assert_eq!(written, format!("{}\n", key.public_line_without_comment()));
    heimdall_testkit::assert_no_canary(&written);
    assert!(!written.contains("PRIVATE KEY"));
    assert_eq!(mode_of(&keys.join(&name)), 0o644);
    // The private key is still at mode 000, and its armor is refused as a key line.
    assert_eq!(mode_of(&ssh.join("id_ed25519")), 0o000);
    let armor = d.path().join("armor");
    key.write_private(&armor).unwrap();
    let text = fs::read_to_string(&armor).unwrap();
    assert_eq!(PublicKeyLine::parse(&text), Err(KeyLineError::PrivateKey));
    set_mode(&ssh.join("id_ed25519"), 0o600);
}

// --- source rule (ADR-0007 §5.3: no removal outside the quarantine) ---------------

/// This unit's files never remove a name outside `sys::QuarantineDir`: the removal
/// calls appear only inside its `impl` blocks (the crate-wide scan is U4c's
/// `production_code_never_unlinks_outside_quarantine`).
#[test]
fn own_sources_never_remove_outside_the_quarantine() {
    // This crate's sources, through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
    let root = heimdall_testkit::repo::repo_path("crates/localenv");
    let tokens = [
        "unlinkat",
        "remove_file",
        "remove_dir",
        "DeleteFileW",
        "RemoveDirectoryW",
        "FileDispositionInfoEx",
        "unlink(",
    ];
    for rel in [
        "src/projection/replace.rs",
        "src/projection/content.rs",
        "src/materialize.rs",
        "src/sys/quarantine.rs",
    ] {
        let mut text = fs::read_to_string(root.join(rel)).unwrap();
        // Unit tests are not production code.
        if let Some(at) = text
            .find("#[cfg(test)]")
            .or_else(|| text.find("#[cfg(all(test"))
        {
            text.truncate(at);
        }
        let outside = strip_blocks(&text, "impl QuarantineDir {");
        for t in tokens {
            assert!(
                !outside.contains(t),
                "{rel}: `{t}` outside sys::QuarantineDir"
            );
        }
    }
}

/// `text` without each block that starts at `opener` (brace-matched).
fn strip_blocks(text: &str, opener: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(opener) {
        out.push_str(&rest[..at]);
        let body = &rest[at..];
        let mut depth = 0usize;
        let mut end = body.len();
        for (i, c) in body.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &body[end..];
    }
    out.push_str(rest);
    out
}

// --- Windows native (blocked on this host: needs a Windows 11 NTFS volume) ---------

/// m02-plan U4 `windows_replace_preserves_dacl` (`[I]`, ADR-0007 §5.3 step 5):
/// `ReplaceFileW` keeps the replaced file's DACL. A distinctive ACE is added with
/// `icacls` before the replace and compared after.
#[cfg(windows)]
#[test]
fn windows_replace_preserves_dacl() {
    let f = Forward::new();
    let path = f.path().join("config");
    let grant = std::process::Command::new("icacls")
        .arg(&path)
        .args(["/grant", "*S-1-5-32-545:(R)"])
        .output()
        .unwrap();
    assert!(grant.status.success());
    let acl = || {
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.replace(&path.to_string_lossy().into_owned(), ""))
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty() && !l.starts_with("Successfully"))
            .collect::<Vec<_>>()
    };
    let before = acl();
    assert!(
        before
            .iter()
            .any(|l| l.contains("S-1-5-32-545") || l.contains("Users"))
    );
    let x = f.exchange();
    assert_eq!(f.post_validate(&x), PostValidation::Valid);
    assert_eq!(read(f.path(), "config"), NEW);
    assert_eq!(acl(), before, "the replaced file's DACL is kept");
}

/// m02-plan U4 `windows_replace_retains_displaced_identity_without_race` (`[I]`, the
/// race-free case only; ADR-0007 §5.9 item 2 stays `[U]`): the backup's file ID equals
/// the validated identity V, and the path holds S.
#[cfg(windows)]
#[test]
fn windows_replace_retains_displaced_identity_without_race() {
    let f = Forward::new();
    let x = f.exchange();
    let displaced = x.displaced_name.clone().unwrap();
    assert_eq!(displaced, ".config.hm-displaced-1");
    let backup = fs::File::open(f.path().join(&displaced)).unwrap();
    assert_eq!(
        heimdall_localenv::sys::handle_identity(&backup).unwrap(),
        f.v()
    );
    let active = fs::File::open(f.path().join("config")).unwrap();
    assert_eq!(
        heimdall_localenv::sys::handle_identity(&active).unwrap(),
        f.staged.identity
    );
    assert_eq!(read(f.path(), &displaced), OLD);
    assert_eq!(f.post_validate(&x), PostValidation::Valid);
    drop((backup, active));
    assert_eq!(f.restore(&f.v()), RestoreOutcome::Restored);
    assert_eq!(read(f.path(), "config"), OLD);
}
