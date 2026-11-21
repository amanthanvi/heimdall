//! ⟨M06⟩ W2: the runner's production authorized_keys writer (ADR-0012 §3.5: "the runner's
//! own Heimdall, using ADR-0005 §3.3's add/remove procedure"; the `heimdall_remote::line::
//! ManagementLines` port), a local file edit as the runner account.
//!
//! **The files.** Every `AuthorizedKeysFile` sshd consults for the account, in order
//! ([`AuthorizedKeysFiles::new`]: the verified policy's list, or sshd's default pair under
//! the account's `~/.ssh`, [`AuthorizedKeysFiles::sshd_default`]). All of them are read, so
//! `key_already_authorized` and the join's line fingerprint see every line sshd would; only
//! the first, the account's own `authorized_keys`, is ever written.
//!
//! **The procedure** (ADR-0005 §3.3, as `heimdall_registry`'s scripts carry it out for an
//! enrolled account, applied locally):
//! * **Add** (no line for the client yet): one write of the line through a descriptor opened
//!   `O_APPEND`, never a rewrite, with a leading newline only when the preimage does not end
//!   with one; a missing file is created exclusively (`O_CREAT|O_EXCL`, mode 0600) inside the
//!   existing owner-only directory.
//! * **Rewrite and remove** (a line for the client exists and differs, or must go): compare,
//!   then rename. The post-image is the preimage minus exactly the lines marked for the
//!   client (every other byte kept, in order), plus the new line for a rewrite. It is written
//!   to an exclusive owner-only file in the same directory; immediately before the rename the
//!   target's identity, size, modification time and content are checked again, and any
//!   difference abandons the edit (`Changed`). A file that is a symlink, has more than one
//!   link, is not owned by the account, or sits in a directory writable by others is not
//!   rewritten.
//! * **After every write** the file is read again; anything but the expected post-image (an
//!   administrator append landing after ours is allowed) is `Changed` and nothing is retried
//!   blindly: the invitation service's reconciler makes the line match the database later.
//! * A line marked for the client in a file Heimdall does not write is never touched; the
//!   edit fails closed (`Io`), and the join's line fingerprint already identifies nobody then.
//!
//! **Disclosed limit** (as ADR-0005 §3.3): an administrator write landing between the final
//! check and the rename is lost; the window is two system calls. ACLs and security labels
//! are not reproduced by a rewrite (the rewritten file is a plain 0600 file).
//!
//! Unix only: elsewhere the port answers `Unavailable` (a runner is headless Linux, ADR-0012
//! §4 item 1).

use std::path::{Path, PathBuf};

use heimdall_contract::ids::ClientId;
#[cfg(unix)]
use heimdall_remote::line::parse_key_line;
use heimdall_remote::line::{KeysFile, LineIoError, ManagementLines};

/// The account's authorized_keys files (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKeysFiles {
    files: Vec<PathBuf>,
}

impl AuthorizedKeysFiles {
    /// Every file sshd consults, in order; the first is the one Heimdall writes. `None` for
    /// an empty list or a relative path.
    #[must_use]
    pub fn new(files: Vec<PathBuf>) -> Option<Self> {
        (!files.is_empty() && files.iter().all(|f| f.is_absolute())).then_some(Self { files })
    }

    /// sshd's default list for an account whose `~/.ssh` is `user_dir`:
    /// `authorized_keys`, then `authorized_keys2`.
    #[must_use]
    pub fn sshd_default(user_dir: &Path) -> Self {
        Self {
            files: vec![
                user_dir.join("authorized_keys"),
                user_dir.join("authorized_keys2"),
            ],
        }
    }

    /// The file Heimdall writes.
    #[must_use]
    pub fn written(&self) -> &Path {
        &self.files[0]
    }

    /// Every file, in order.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }
}

// Unix-only: the writer that calls these is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
/// Whether one raw line (without its `\n`) is marked for `client`.
fn marked(raw: &[u8], client: &ClientId) -> bool {
    std::str::from_utf8(raw)
        .is_ok_and(|t| parse_key_line(t).is_some_and(|k| k.is_marked_for(client)))
}

// Unix-only: the writer that calls these is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
/// The lines of `bytes` marked for `client`, without their terminator.
fn marked_lines(bytes: &[u8], client: &ClientId) -> Vec<Vec<u8>> {
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(|p| p.strip_suffix(b"\n").unwrap_or(p))
        .filter(|l| marked(l, client))
        .map(<[u8]>::to_vec)
        .collect()
}

// Unix-only: the writer that calls these is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
/// `bytes` minus exactly the lines marked for `client` (each with its own `\n`); every
/// other byte kept, in order.
fn without_marked(bytes: &[u8], client: &ClientId) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for piece in bytes.split_inclusive(|b| *b == b'\n') {
        if !marked(piece.strip_suffix(b"\n").unwrap_or(piece), client) {
            out.extend_from_slice(piece);
        }
    }
    out
}

// Unix-only: the writer that calls these is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
/// `base` followed by `line` on its own line.
fn with_line(base: &[u8], line: &str) -> Vec<u8> {
    let mut out = base.to_vec();
    if !out.is_empty() && !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
    out
}

// Unix-only: the writer that calls these is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
/// The post-write check (module docs): after a put, exactly one line marked for the client
/// and equal to `line`, and the rest starting with `base`; after a remove (`line: None`),
/// no marked line and the content starting with `base`.
fn check_post(
    post: &[u8],
    base: &[u8],
    client: &ClientId,
    line: Option<&str>,
) -> Result<(), LineIoError> {
    let have = marked_lines(post, client);
    let ok = match line {
        Some(l) => have.len() == 1 && have[0] == l.as_bytes(),
        None => have.is_empty(),
    };
    if ok && without_marked(post, client).starts_with(base) {
        Ok(())
    } else {
        Err(LineIoError::Changed)
    }
}

#[cfg(unix)]
mod unix {
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::Path;

    use heimdall_remote::line::LineIoError;

    fn io(_: std::io::Error) -> LineIoError {
        LineIoError::Io
    }

    /// The written file's content and metadata, read without following a symlink; `None`
    /// when it does not exist.
    pub(super) fn read_nofollow(path: &Path) -> Result<Option<(Vec<u8>, Metadata)>, LineIoError> {
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let meta = f.metadata().map_err(io)?;
        if !meta.is_file() {
            return Err(LineIoError::Io);
        }
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).map_err(io)?;
        Ok(Some((bytes, meta)))
    }

    /// The directory holding `path`: owned by the account and not writable by others.
    fn owner_only_dir(path: &Path) -> Result<&Path, LineIoError> {
        let dir = path.parent().ok_or(LineIoError::Io)?;
        let meta = std::fs::symlink_metadata(dir).map_err(io)?;
        if !meta.is_dir()
            || meta.uid() != heimdall_localenv::sys::current_uid()
            || meta.mode() & 0o022 != 0
        {
            return Err(LineIoError::Io);
        }
        Ok(dir)
    }

    /// A regular file with one link, owned by the account.
    fn rewritable(meta: &Metadata) -> bool {
        meta.is_file() && meta.nlink() == 1 && meta.uid() == heimdall_localenv::sys::current_uid()
    }

    /// Create the file exclusively (0600) and write `bytes` in one write.
    pub(super) fn create(path: &Path, bytes: &[u8]) -> Result<(), LineIoError> {
        owner_only_dir(path)?;
        let mut f = heimdall_localenv::sys::create_owner_only_exclusive(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                LineIoError::Changed
            } else {
                LineIoError::Io
            }
        })?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)
    }

    /// Append `bytes` in one write through `O_APPEND` (never a rewrite).
    pub(super) fn append(path: &Path, bytes: &[u8]) -> Result<(), LineIoError> {
        owner_only_dir(path)?;
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(io)?;
        let meta = f.metadata().map_err(io)?;
        if !meta.is_file() || meta.uid() != heimdall_localenv::sys::current_uid() {
            return Err(LineIoError::Io);
        }
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

    /// Compare, then rename (module docs): replace `path` (read as `pre` with `pre_meta`) by
    /// `post`, abandoning the edit when the file changed in between.
    pub(super) fn rewrite(
        path: &Path,
        pre: &[u8],
        pre_meta: &Metadata,
        post: &[u8],
    ) -> Result<(), LineIoError> {
        let dir = owner_only_dir(path)?;
        if !rewritable(pre_meta) {
            return Err(LineIoError::Io);
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(LineIoError::Io)?;
        let suffix = heimdall_app::ids::random_u64().map_err(|_| LineIoError::Io)?;
        let tmp = dir.join(format!(".{name}.hm-{suffix:016x}"));
        let written = (|| {
            let mut f = heimdall_localenv::sys::create_owner_only_exclusive(&tmp).map_err(io)?;
            f.write_all(post).map_err(io)?;
            f.sync_all().map_err(io)
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // The compare step, immediately before the rename.
        let unchanged = match read_nofollow(path) {
            Ok(Some((now, now_meta))) => now == pre && same_file(pre_meta, &now_meta),
            _ => false,
        };
        if !unchanged {
            let _ = std::fs::remove_file(&tmp);
            return Err(LineIoError::Changed);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(io(e));
        }
        File::open(dir).and_then(|d| d.sync_all()).map_err(io)
    }
}

impl ManagementLines for AuthorizedKeysFiles {
    fn read_all(&self) -> Result<Vec<KeysFile>, LineIoError> {
        self.files
            .iter()
            .map(|path| {
                let bytes = match std::fs::read(path) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                    Err(_) => return Err(LineIoError::Io),
                };
                Ok(KeysFile {
                    name: path
                        .file_name()
                        .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                    // A file that is not text fails closed.
                    text: String::from_utf8(bytes).map_err(|_| LineIoError::Io)?,
                })
            })
            .collect()
    }

    #[cfg(unix)]
    fn put(&self, client: &ClientId, line: &str) -> Result<(), LineIoError> {
        self.others_unmarked(client)?;
        let path = self.written();
        let base = match unix::read_nofollow(path)? {
            None => {
                unix::create(path, &with_line(&[], line))?;
                Vec::new()
            }
            Some((pre, meta)) => {
                let have = marked_lines(&pre, client);
                if have.len() == 1 && have[0] == line.as_bytes() {
                    return Ok(());
                }
                if have.is_empty() {
                    let lead: &[u8] = if pre.is_empty() || pre.ends_with(b"\n") {
                        b""
                    } else {
                        b"\n"
                    };
                    let mut bytes = lead.to_vec();
                    bytes.extend_from_slice(line.as_bytes());
                    bytes.push(b'\n');
                    unix::append(path, &bytes)?;
                    pre
                } else {
                    let base = without_marked(&pre, client);
                    unix::rewrite(path, &pre, &meta, &with_line(&base, line))?;
                    base
                }
            }
        };
        let post = unix::read_nofollow(path)?.ok_or(LineIoError::Changed)?.0;
        check_post(&post, &base, client, Some(line))
    }

    #[cfg(unix)]
    fn remove(&self, client: &ClientId) -> Result<(), LineIoError> {
        let path = self.written();
        let Some((pre, meta)) = unix::read_nofollow(path)? else {
            return Ok(());
        };
        if marked_lines(&pre, client).is_empty() {
            return Ok(());
        }
        let base = without_marked(&pre, client);
        unix::rewrite(path, &pre, &meta, &base)?;
        let post = unix::read_nofollow(path)?.ok_or(LineIoError::Changed)?.0;
        check_post(&post, &base, client, None)
    }

    #[cfg(not(unix))]
    fn put(&self, _: &ClientId, _: &str) -> Result<(), LineIoError> {
        Err(LineIoError::Unavailable)
    }

    #[cfg(not(unix))]
    fn remove(&self, _: &ClientId) -> Result<(), LineIoError> {
        Err(LineIoError::Unavailable)
    }
}

impl AuthorizedKeysFiles {
    /// No file Heimdall does not write holds a line marked for `client` (module docs).
    #[cfg(unix)]
    fn others_unmarked(&self, client: &ClientId) -> Result<(), LineIoError> {
        for path in &self.files[1..] {
            match std::fs::read(path) {
                Ok(b) if !marked_lines(&b, client).is_empty() => return Err(LineIoError::Io),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(LineIoError::Io),
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use heimdall_remote::line::{
        ManagementLine, PublicKeyText, ServeCommand, key_already_authorized, line_fingerprint,
    };

    use super::*;

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                out.push(if i <= chunk.len() {
                    T[((n >> (18 - 6 * i)) & 63) as usize] as char
                } else {
                    '='
                });
            }
        }
        out
    }

    fn key(n: u8) -> PublicKeyText {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[n; 32]);
        PublicKeyText::parse(&format!("ssh-ed25519 {}", b64(&blob))).unwrap()
    }

    fn line(client: &ClientId, n: u8, expiry: Option<&str>) -> String {
        ManagementLine {
            client: client.clone(),
            command: ServeCommand::new("/opt/heimdall/bin/heimdall", "/srv/runner/heimdall")
                .unwrap(),
            key: key(n),
            expiry: expiry.map(|e| e.parse().unwrap()),
        }
        .render()
        .unwrap()
    }

    fn files(dir: &Path) -> AuthorizedKeysFiles {
        let ssh = dir.join(".ssh");
        std::fs::create_dir(&ssh).unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        AuthorizedKeysFiles::sshd_default(&ssh)
    }

    /// ADR-0005 §3.3 applied locally: the user's own lines (a comment, a CRLF line, no final
    /// newline) are kept byte for byte through an add (created exclusively, then appended
    /// with a leading newline), a rewrite (pending line replaced by the active one) and a
    /// removal; every file is read for uniqueness and the join's fingerprint; a line marked
    /// for the client in the second file (which Heimdall never writes) fails closed; a
    /// symlinked or hard-linked registry is never rewritten.
    #[test]
    fn edits_keep_the_users_lines_and_refuse_what_they_cannot_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let f = files(dir.path());
        let a = ClientId::from_random_bytes([0xa1; 16]);
        let b = ClientId::from_random_bytes([0xb2; 16]);
        // Add to a missing file: created 0600.
        let pending = line(&a, 1, Some("2026-11-21T09:15:00Z"));
        f.put(&a, &pending).unwrap();
        let meta = std::fs::metadata(f.written()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        // The user's own lines, one with CRLF and no final newline.
        let user = "# mine\r\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwn user@laptop";
        let mut text = std::fs::read_to_string(f.written()).unwrap();
        text.push_str(user);
        std::fs::write(f.written(), &text).unwrap();
        // Add a second client: appended with a leading newline, nothing rewritten.
        let other = line(&b, 2, None);
        f.put(&b, &other).unwrap();
        let after_add = std::fs::read_to_string(f.written()).unwrap();
        assert_eq!(after_add, format!("{text}\n{other}\n"));
        // Rewrite: the pending line becomes the active one; every other byte kept in order.
        let active = line(&a, 1, None);
        f.put(&a, &active).unwrap();
        let rewritten = std::fs::read_to_string(f.written()).unwrap();
        assert_eq!(rewritten, format!("{user}\n{other}\n{active}\n"));
        assert!(rewritten.contains("# mine\r\n"));
        // Idempotent: the same line again writes nothing.
        let ino = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(f.written()).unwrap());
        f.put(&a, &active).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(f.written()).unwrap()),
            ino
        );
        // Every file is read: uniqueness and the join's fingerprint.
        let all = f.read_all().unwrap();
        assert!(key_already_authorized(&all, key(2).blob(), Some(&a)));
        assert_eq!(line_fingerprint(&all, &a), Some(key(1).fingerprint()));
        std::fs::write(&f.files()[1], format!("{}\n", key(1).openssh())).unwrap();
        assert_eq!(
            line_fingerprint(&f.read_all().unwrap(), &a),
            None,
            "a shadowing line in authorized_keys2 identifies nobody"
        );
        std::fs::write(&f.files()[1], format!("{active}\n")).unwrap();
        assert_eq!(
            f.put(&a, &active),
            Err(LineIoError::Io),
            "never edits authorized_keys2"
        );
        std::fs::remove_file(&f.files()[1]).unwrap();
        // Remove: only b's line goes.
        f.remove(&b).unwrap();
        assert_eq!(
            std::fs::read_to_string(f.written()).unwrap(),
            format!("{user}\n{active}\n")
        );
        f.remove(&b).unwrap();
        // A hard-linked registry is not rewritten; a symlinked one is not touched.
        let link = dir.path().join("elsewhere");
        std::fs::hard_link(f.written(), &link).unwrap();
        assert_eq!(f.remove(&a), Err(LineIoError::Io));
        std::fs::remove_file(&link).unwrap();
        let real = dir.path().join("real");
        std::fs::rename(f.written(), &real).unwrap();
        std::os::unix::fs::symlink(&real, f.written()).unwrap();
        assert_eq!(f.remove(&a), Err(LineIoError::Io));
        assert_eq!(f.put(&a, &pending), Err(LineIoError::Io));
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            format!("{user}\n{active}\n"),
            "the symlink's target is untouched"
        );
    }

    /// The compare step: a change landing between the read and the rename abandons the
    /// edit (`Changed`), and the administrator's bytes survive.
    #[test]
    fn a_concurrent_change_abandons_the_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let f = files(dir.path());
        let a = ClientId::from_random_bytes([0xa1; 16]);
        f.put(&a, &line(&a, 1, Some("2026-11-21T09:15:00Z")))
            .unwrap();
        let (pre, meta) = unix::read_nofollow(f.written()).unwrap().unwrap();
        let admin = format!("{}admin-line\n", String::from_utf8(pre.clone()).unwrap());
        std::fs::write(f.written(), &admin).unwrap();
        let post = with_line(&without_marked(&pre, &a), &line(&a, 1, None));
        assert_eq!(
            unix::rewrite(f.written(), &pre, &meta, &post),
            Err(LineIoError::Changed)
        );
        assert_eq!(std::fs::read_to_string(f.written()).unwrap(), admin);
        assert_eq!(
            std::fs::read_dir(f.written().parent().unwrap())
                .unwrap()
                .count(),
            1,
            "no temporary file is left"
        );
    }
}
