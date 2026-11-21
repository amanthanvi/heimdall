//! ⟨M06 W3⟩ The one authorized_keys safety module (ADR-0005 §3.3; ADR-0012 §3.5
//! ⟨2026-11-21⟩, ruling 8 (c); ADR-0006 §18.7 reading (c)). Both writers use it: the
//! enrollment writer ([`crate::post_image`], whose remote script runs on the destination
//! and whose post-write checks are the rules here) and the runner's management-line writer
//! (`heimdall_runtime::paired_lines`, a local edit through [`local`]).
//!
//! **The rules** (pure; the first half of this file). A caller names *its* lines with a
//! selector over one raw line (its bytes without the `\n`; a `\r` stays part of the line):
//! * [`selected`], [`without`], [`with_line`], [`append_bytes`]: byte-preserving line
//!   selection and post-image construction. Removing a line removes its bytes and its own
//!   `\n`, nothing else.
//! * [`check_added`]: after an add or a rewrite, exactly one selected line, equal to the
//!   line byte for byte, and the content without it starts with the inspected image (an
//!   administrator append landing after ours is allowed).
//! * [`check_removed`]: after a removal, no selected line, and the content starts with the
//!   post-image.
//!
//! **The local file operations** ([`local`], Unix only; the one place in this otherwise
//! pure crate that touches a file, so the steps exist once):
//! * every read is bounded ([`local::MAX_BYTES`]), regular-file only, and never follows a
//!   symlink or blocks on a FIFO or device;
//! * **add**: one write through `O_APPEND`, never a rewrite; a missing file is created
//!   exclusively, mode 0600, inside an existing owner-only directory;
//! * **rewrite and remove**: compare, then rename. The target's identity, size,
//!   modification time and content are checked again immediately before the rename, and any
//!   difference abandons the edit;
//! * a file that is a symlink, has more than one link, is not owned by the account, or sits
//!   in a directory writable by others is never written (add included);
//! * **after every write** the file is read again and checked with the rules above.
//!
//! **Disclosed limit** (ADR-0005 §3.3): an administrator write landing between the final
//! check and the rename is lost; the window is two system calls. ACLs and security labels
//! are not reproduced by a rewrite.

use crate::line::lines;

/// The lines of `content` that `ours` selects, without their terminator.
pub fn selected(content: &[u8], ours: impl Fn(&[u8]) -> bool) -> Vec<&[u8]> {
    lines(content).filter(|l| ours(l)).collect()
}

/// `content` minus exactly the lines `ours` selects (each with its own `\n`); every other
/// byte kept, in order.
pub fn without(content: &[u8], ours: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len());
    for piece in content.split_inclusive(|b| *b == b'\n') {
        if !ours(piece.strip_suffix(b"\n").unwrap_or(piece)) {
            out.extend_from_slice(piece);
        }
    }
    out
}

/// The bytes an add appends to `pre`: `line` and its `\n`, with a leading newline only
/// when `pre` does not end with one.
#[must_use]
pub fn append_bytes(pre: &[u8], line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len() + 2);
    if !pre.is_empty() && !pre.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(line);
    out.push(b'\n');
    out
}

/// `base` followed by `line` on its own line.
#[must_use]
pub fn with_line(base: &[u8], line: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out.extend_from_slice(&append_bytes(base, line));
    out
}

/// Why a post-write check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostCheckError {
    /// The selected lines are not what the write should have left: not exactly the one
    /// line after an add, or any at all after a removal.
    Lines {
        /// How many lines the selector matched.
        selected: usize,
    },
    /// The rest of the content neither equals nor starts with the inspected image.
    Prefix,
}

/// The re-read check after an add or a rewrite (module docs). `rest_starts_with_image`
/// receives the content without the selected line and answers whether it starts with the
/// image inspected before the write (by bytes or by digest).
///
/// # Errors
/// [`PostCheckError`].
pub fn check_added(
    post: &[u8],
    ours: impl Fn(&[u8]) -> bool,
    line: &[u8],
    rest_starts_with_image: impl FnOnce(&[u8]) -> bool,
) -> Result<(), PostCheckError> {
    let have = selected(post, &ours);
    if have.len() != 1 || have[0] != line {
        return Err(PostCheckError::Lines {
            selected: have.len(),
        });
    }
    if rest_starts_with_image(&without(post, &ours)) {
        Ok(())
    } else {
        Err(PostCheckError::Prefix)
    }
}

/// The re-read check after a removal (module docs). `starts_with_image` answers whether
/// the content starts with the post-image (by bytes or by digest).
///
/// # Errors
/// [`PostCheckError`].
pub fn check_removed(
    post: &[u8],
    ours: impl Fn(&[u8]) -> bool,
    starts_with_image: impl FnOnce(&[u8]) -> bool,
) -> Result<(), PostCheckError> {
    let count = selected(post, ours).len();
    if count != 0 {
        return Err(PostCheckError::Lines { selected: count });
    }
    if starts_with_image(post) {
        Ok(())
    } else {
        Err(PostCheckError::Prefix)
    }
}

/// The local file operations (module docs).
#[cfg(unix)]
pub mod local {
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{append_bytes, check_added, check_removed, selected, with_line, without};

    /// The most bytes a keys file may hold to be read or written: the enrollment
    /// protocol's registry bound ([`crate::hm1::MAX_CONTENT_BYTES`]).
    pub const MAX_BYTES: usize = crate::hm1::MAX_CONTENT_BYTES;

    /// Why a file is not read or written.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Refused {
        /// The path is a symlink.
        Symlink,
        /// Not a regular file (a directory, FIFO, socket or device).
        NotRegular,
        /// More than one link.
        HardLinked,
        /// Not owned by the account.
        NotOwned,
        /// The directory is missing, not a directory, not the account's, or writable by
        /// others.
        Directory,
        /// Larger than the bound (or the write would make it so).
        TooLarge,
    }

    /// Why a local operation did not complete.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum LocalError {
        /// The file is one this module never reads or writes; nothing was changed.
        Refused(Refused),
        /// The file changed concurrently (the compare step, an exclusive create that
        /// lost, or the re-read check). Never retried blindly.
        Changed,
        /// Any other I/O failure.
        Io(std::io::ErrorKind),
    }

    fn io(e: std::io::Error) -> LocalError {
        LocalError::Io(e.kind())
    }

    /// A file as read: its bytes and the metadata of the descriptor they came from.
    #[derive(Debug)]
    pub struct Snapshot {
        /// The content.
        pub bytes: Vec<u8>,
        meta: Metadata,
    }

    /// What [`put`] did.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Put {
        /// The one selected line already equals the line; nothing was written.
        Unchanged,
        /// The file did not exist and was created exclusively.
        Created,
        /// The line was appended.
        Appended,
        /// Selected lines existed and differed: compare, then rename.
        Rewritten,
    }

    /// `O_NONBLOCK`: opening a FIFO or a device never blocks; a regular file is unaffected.
    const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

    /// An open failure: a symlink at the path is a refusal, anything else I/O.
    fn open_error(path: &Path, e: std::io::Error) -> LocalError {
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => LocalError::Refused(Refused::Symlink),
            _ => io(e),
        }
    }

    /// Read `path` without following a symlink: a regular file of at most `max` bytes.
    /// `None` when it does not exist.
    ///
    /// # Errors
    /// [`LocalError::Refused`] for a symlink, a non-regular file or one past `max`
    /// (nothing is read from a FIFO or device, and the call never blocks on one);
    /// [`LocalError::Io`] otherwise.
    pub fn read(path: &Path, max: usize) -> Result<Option<Snapshot>, LocalError> {
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_FLAGS)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(open_error(path, e)),
        };
        let meta = f.metadata().map_err(io)?;
        if !meta.is_file() {
            return Err(LocalError::Refused(Refused::NotRegular));
        }
        let bound = u64::try_from(max).unwrap_or(u64::MAX);
        if meta.len() > bound {
            return Err(LocalError::Refused(Refused::TooLarge));
        }
        let mut bytes = Vec::new();
        f.take(bound.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() > max {
            return Err(LocalError::Refused(Refused::TooLarge));
        }
        Ok(Some(Snapshot { bytes, meta }))
    }

    /// The directory holding `path`: a real directory owned by `uid` and not writable by
    /// others.
    fn owner_only_dir(path: &Path, uid: u32) -> Result<&Path, LocalError> {
        let refused = LocalError::Refused(Refused::Directory);
        let dir = path.parent().ok_or(refused)?;
        let meta = std::fs::symlink_metadata(dir).map_err(|_| refused)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(refused);
        }
        Ok(dir)
    }

    /// A regular file with one link, owned by `uid`.
    fn writable(meta: &Metadata, uid: u32) -> Result<(), LocalError> {
        let why = if !meta.is_file() {
            Refused::NotRegular
        } else if meta.nlink() != 1 {
            Refused::HardLinked
        } else if meta.uid() != uid {
            Refused::NotOwned
        } else {
            return Ok(());
        };
        Err(LocalError::Refused(why))
    }

    fn create_exclusive(path: &Path) -> std::io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    /// Create `path` exclusively (0600) inside its owner-only directory and write `bytes`.
    fn create(path: &Path, uid: u32, bytes: &[u8]) -> Result<(), LocalError> {
        owner_only_dir(path, uid)?;
        let mut f = create_exclusive(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                LocalError::Changed
            } else {
                io(e)
            }
        })?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)
    }

    /// Append `bytes` in one write through `O_APPEND` (never a rewrite).
    fn append(path: &Path, uid: u32, bytes: &[u8]) -> Result<(), LocalError> {
        owner_only_dir(path, uid)?;
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(OPEN_FLAGS)
            .open(path)
            .map_err(|e| open_error(path, e))?;
        writable(&f.metadata().map_err(io)?, uid)?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)
    }

    fn same_file(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
    }

    /// A new exclusive owner-only file beside `path`. The name only has to be unused:
    /// the directory is owner-only and the create is exclusive.
    fn temporary(dir: &Path, name: &str) -> Result<(PathBuf, File), LocalError> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..16 {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let tmp = dir.join(format!(".{name}.hm-{:x}-{t:x}-{n:x}", std::process::id()));
            match create_exclusive(&tmp) {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io(e)),
            }
        }
        Err(LocalError::Io(std::io::ErrorKind::AlreadyExists))
    }

    /// Compare, then rename (module docs): replace `path`, read as `pre`, by `post`.
    /// The edit is abandoned ([`LocalError::Changed`]) when the file is no longer what
    /// `pre` holds immediately before the rename; no temporary file is left behind.
    ///
    /// # Errors
    /// [`LocalError`]; nothing is renamed on any error.
    pub fn rewrite(path: &Path, uid: u32, pre: &Snapshot, post: &[u8]) -> Result<(), LocalError> {
        let dir = owner_only_dir(path, uid)?;
        writable(&pre.meta, uid)?;
        if post.len() > MAX_BYTES {
            return Err(LocalError::Refused(Refused::TooLarge));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(LocalError::Io(std::io::ErrorKind::InvalidInput))?;
        let (tmp, mut f) = temporary(dir, name)?;
        let mut finish = || {
            f.write_all(post).map_err(io)?;
            f.sync_all().map_err(io)?;
            // The compare step, immediately before the rename.
            match read(path, MAX_BYTES) {
                Ok(Some(now)) if now.bytes == pre.bytes && same_file(&pre.meta, &now.meta) => {}
                _ => return Err(LocalError::Changed),
            }
            std::fs::rename(&tmp, path).map_err(io)
        };
        if let Err(e) = finish() {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)
    }

    fn reread(path: &Path) -> Result<Vec<u8>, LocalError> {
        Ok(read(path, MAX_BYTES)?.ok_or(LocalError::Changed)?.bytes)
    }

    /// Make `line` the one line `ours` selects in `path` (module docs): create, append,
    /// or compare-then-rename, then the re-read check.
    ///
    /// # Errors
    /// [`LocalError`]. After `Changed` the file may or may not hold the line; the caller
    /// reconciles, never retries blindly.
    pub fn put(
        path: &Path,
        uid: u32,
        ours: impl Fn(&[u8]) -> bool,
        line: &[u8],
    ) -> Result<Put, LocalError> {
        let (did, base) = match read(path, MAX_BYTES)? {
            None => {
                create(path, uid, &with_line(&[], line))?;
                (Put::Created, Vec::new())
            }
            Some(pre) => {
                let have = selected(&pre.bytes, &ours);
                if have.len() == 1 && have[0] == line {
                    return Ok(Put::Unchanged);
                }
                let added = have.is_empty();
                let base = without(&pre.bytes, &ours);
                if base.len() + line.len() + 2 > MAX_BYTES {
                    return Err(LocalError::Refused(Refused::TooLarge));
                }
                if added {
                    append(path, uid, &append_bytes(&pre.bytes, line))?;
                    (Put::Appended, base)
                } else {
                    rewrite(path, uid, &pre, &with_line(&base, line))?;
                    (Put::Rewritten, base)
                }
            }
        };
        check_added(&reread(path)?, &ours, line, |rest| rest.starts_with(&base))
            .map_err(|_| LocalError::Changed)?;
        Ok(did)
    }

    /// Remove every line `ours` selects from `path` (compare, then rename, then the
    /// re-read check). `false` when there was nothing to remove (or no file).
    ///
    /// # Errors
    /// [`LocalError`].
    pub fn remove(path: &Path, uid: u32, ours: impl Fn(&[u8]) -> bool) -> Result<bool, LocalError> {
        let Some(pre) = read(path, MAX_BYTES)? else {
            return Ok(false);
        };
        if selected(&pre.bytes, &ours).is_empty() {
            return Ok(false);
        }
        let base = without(&pre.bytes, &ours);
        rewrite(path, uid, &pre, &base)?;
        check_removed(&reread(path)?, &ours, |post| post.starts_with(&base))
            .map_err(|_| LocalError::Changed)?;
        Ok(true)
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::local::{self, LocalError, MAX_BYTES, Put, Refused};

    const OURS: &[u8] = b"key-one tag:ours";

    fn ours(l: &[u8]) -> bool {
        l.ends_with(b" tag:ours")
    }

    /// A scratch owner-only directory under the system temporary directory, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "hm-keys-file-{tag}-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Scratch(dir)
        }
        fn file(&self) -> PathBuf {
            self.0.join("authorized_keys")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn uid(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    /// ⟨M06 W3; M06-W2-R03⟩ Through the shared API a symlink and a hard link are refused
    /// by every operation, the add included (the stricter of the two former
    /// implementations: the enrollment script refuses a hard-linked registry before an
    /// append as well), and the link's target is untouched.
    #[test]
    fn links_are_refused_by_every_operation() {
        let s = Scratch::new("links");
        let (path, uid) = (s.file(), uid(&s.0));
        std::fs::write(&path, "user line\n").unwrap();
        let link = s.0.join("elsewhere");
        std::fs::hard_link(&path, &link).unwrap();
        let hard = Err(LocalError::Refused(Refused::HardLinked));
        assert_eq!(local::put(&path, uid, ours, OURS), hard, "append");
        std::fs::write(&path, "user line\nold tag:ours\n").unwrap();
        assert_eq!(local::put(&path, uid, ours, OURS), hard, "rewrite");
        assert_eq!(
            local::remove(&path, uid, ours).map(|_| ()),
            hard.map(|_| ())
        );
        assert_eq!(
            std::fs::read_to_string(&link).unwrap(),
            "user line\nold tag:ours\n"
        );
        std::fs::remove_file(&link).unwrap();
        let real = s.0.join("real");
        std::fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        let sym = LocalError::Refused(Refused::Symlink);
        assert_eq!(local::read(&path, MAX_BYTES).map(|_| ()), Err(sym));
        assert_eq!(local::put(&path, uid, ours, OURS), Err(sym));
        assert_eq!(local::remove(&path, uid, ours), Err(sym));
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            "user line\nold tag:ours\n"
        );
        // A dangling symlink is not "no file": nothing is created through it.
        std::fs::remove_file(&real).unwrap();
        assert_eq!(local::put(&path, uid, ours, OURS), Err(sym));
        assert!(!real.exists());
    }

    /// ⟨M06-W2-R03⟩ A read is bounded and regular-file only: an oversized file, a
    /// directory and a FIFO are refused, and the FIFO does not block the reader.
    #[test]
    fn reads_are_bounded_and_regular_files_only() {
        let s = Scratch::new("reads");
        let path = s.file();
        std::fs::write(&path, vec![b'a'; 65]).unwrap();
        assert_eq!(
            local::read(&path, 64).map(|_| ()),
            Err(LocalError::Refused(Refused::TooLarge))
        );
        assert_eq!(local::read(&path, 65).unwrap().unwrap().bytes.len(), 65);
        assert_eq!(
            local::read(&s.0, MAX_BYTES).map(|_| ()),
            Err(LocalError::Refused(Refused::NotRegular))
        );
        let fifo = s.0.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(
            local::read(&fifo, MAX_BYTES).map(|_| ()),
            Err(LocalError::Refused(Refused::NotRegular))
        );
        assert!(
            local::read(&s.0.join("absent"), MAX_BYTES)
                .unwrap()
                .is_none()
        );
        // A write that would pass the bound is refused before anything is written.
        std::fs::write(&path, vec![b'a'; MAX_BYTES - 4]).unwrap();
        assert_eq!(
            local::put(&path, uid(&s.0), ours, OURS),
            Err(LocalError::Refused(Refused::TooLarge))
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (MAX_BYTES - 4) as u64
        );
    }

    /// The whole procedure through the one API: exclusive create, append with the leading
    /// newline, compare-then-rename, removal; and a directory writable by others is never
    /// written into.
    #[test]
    fn put_and_remove_follow_the_procedure() {
        let s = Scratch::new("put");
        let (path, uid) = (s.file(), uid(&s.0));
        assert_eq!(local::put(&path, uid, ours, OURS), Ok(Put::Created));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(local::put(&path, uid, ours, OURS), Ok(Put::Unchanged));
        assert_eq!(local::remove(&path, uid, ours), Ok(true));
        assert_eq!(local::remove(&path, uid, ours), Ok(false));
        std::fs::write(&path, "user\r\nlast").unwrap();
        assert_eq!(local::put(&path, uid, ours, OURS), Ok(Put::Appended));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"user\r\nlast\nkey-one tag:ours\n"
        );
        assert_eq!(
            local::put(&path, uid, ours, b"key-two tag:ours"),
            Ok(Put::Rewritten)
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"user\r\nlast\nkey-two tag:ours\n"
        );
        std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        let dir = Err(LocalError::Refused(Refused::Directory));
        assert_eq!(local::put(&path, uid, ours, OURS), dir);
        assert_eq!(local::remove(&path, uid, ours).map(|_| ()), dir.map(|_| ()));
        std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(std::fs::read_dir(&s.0).unwrap().count(), 1, "no temporary");
    }
}
