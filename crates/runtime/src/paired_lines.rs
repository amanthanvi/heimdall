//! ⟨M06⟩ W2: the runner's production authorized_keys writer (ADR-0012 §3.5: "the runner's
//! own Heimdall, using ADR-0005 §3.3's add/remove procedure"; the `heimdall_remote::line::
//! ManagementLines` port), a local file edit as the runner account.
//!
//! **The files.** Every `AuthorizedKeysFile` sshd consults for the account, in order
//! ([`AuthorizedKeysFiles::new`]: the verified policy's list, or sshd's default pair under
//! the account's `~/.ssh`, [`AuthorizedKeysFiles::sshd_default`]). All of them are read
//! (bounded, regular files only, no link followed: a symlinked, oversized or non-regular
//! listed file is `Io`, so nothing is activated on it; M06-W2-R03), so
//! `key_already_authorized` and the join's line fingerprint see every line sshd would; only
//! the first, the account's own `authorized_keys`, is ever written.
//!
//! ⟨M06 W3⟩ **One safety module.** The steps below are not implemented here: they are
//! `heimdall_registry::keys_file` (ADR-0012 §3.5 ⟨2026-11-21⟩, ruling 8 (c)), the module the
//! enrollment writer's post-write checks use too. This file supplies the list of files, the
//! selector ("a key line marked for this client") and the port's error mapping.
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
//!   written at all (⟨W3⟩ the add included, as the enrollment script refuses it).
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
use heimdall_registry::keys_file::{self, local};
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

/// Whether one raw line (without its `\n`) is marked for `client`: the selector this
/// writer gives the shared module.
// Unix-only: the writer that calls it is `#[cfg(unix)]` (Windows has no runner in V1).
#[cfg(unix)]
fn marked(raw: &[u8], client: &ClientId) -> bool {
    std::str::from_utf8(raw)
        .is_ok_and(|t| parse_key_line(t).is_some_and(|k| k.is_marked_for(client)))
}

/// The shared module's outcome as the port's: a concurrent change is `Changed`; a file
/// the module refuses (a link, a non-regular or oversized file, a directory writable by
/// others) and every other failure is `Io`.
#[cfg(unix)]
fn port_error(e: local::LocalError) -> LineIoError {
    match e {
        local::LocalError::Changed => LineIoError::Changed,
        local::LocalError::Refused(_) | local::LocalError::Io(_) => LineIoError::Io,
    }
}

impl AuthorizedKeysFiles {
    /// One listed file's bytes, read through the shared module: bounded, a regular file
    /// only, no link followed, never blocking on a FIFO or device (M06-W2-R03). A missing
    /// file is empty; anything refused is `Io`, so the caller fails closed.
    #[cfg(unix)]
    fn read_listed(path: &Path) -> Result<Vec<u8>, LineIoError> {
        local::read(path, local::MAX_BYTES)
            .map(|s| s.map_or_else(Vec::new, |s| s.bytes))
            .map_err(port_error)
    }

    /// Off Unix there is no writer and no runner (module docs); the read is bounded.
    #[cfg(not(unix))]
    fn read_listed(path: &Path) -> Result<Vec<u8>, LineIoError> {
        use std::io::Read as _;
        const MAX_BYTES: u64 = 128 * 1024;
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_file() && m.len() <= MAX_BYTES => {}
            Ok(_) => return Err(LineIoError::Io),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(LineIoError::Io),
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| LineIoError::Io)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| LineIoError::Io)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(LineIoError::Io);
        }
        Ok(bytes)
    }

    /// No file Heimdall does not write holds a line marked for `client` (module docs).
    #[cfg(unix)]
    fn others_unmarked(&self, client: &ClientId) -> Result<(), LineIoError> {
        for path in &self.files[1..] {
            let bytes = Self::read_listed(path)?;
            if !keys_file::selected(&bytes, |l| marked(l, client)).is_empty() {
                return Err(LineIoError::Io);
            }
        }
        Ok(())
    }
}

impl ManagementLines for AuthorizedKeysFiles {
    fn read_all(&self) -> Result<Vec<KeysFile>, LineIoError> {
        self.files
            .iter()
            .map(|path| {
                Ok(KeysFile {
                    name: path
                        .file_name()
                        .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                    // A file that is not text fails closed.
                    text: String::from_utf8(Self::read_listed(path)?)
                        .map_err(|_| LineIoError::Io)?,
                })
            })
            .collect()
    }

    #[cfg(unix)]
    fn put(&self, client: &ClientId, line: &str) -> Result<(), LineIoError> {
        self.others_unmarked(client)?;
        local::put(
            self.written(),
            heimdall_localenv::sys::current_uid(),
            |l| marked(l, client),
            line.as_bytes(),
        )
        .map(|_| ())
        .map_err(port_error)
    }

    #[cfg(unix)]
    fn remove(&self, client: &ClientId) -> Result<(), LineIoError> {
        local::remove(self.written(), heimdall_localenv::sys::current_uid(), |l| {
            marked(l, client)
        })
        .map(|_| ())
        .map_err(port_error)
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
        let uid = heimdall_localenv::sys::current_uid();
        let pre = local::read(f.written(), local::MAX_BYTES).unwrap().unwrap();
        let admin = format!(
            "{}admin-line\n",
            String::from_utf8(pre.bytes.clone()).unwrap()
        );
        std::fs::write(f.written(), &admin).unwrap();
        let post = keys_file::with_line(
            &keys_file::without(&pre.bytes, |l| marked(l, &a)),
            line(&a, 1, None).as_bytes(),
        );
        assert_eq!(
            local::rewrite(f.written(), uid, &pre, &post).map_err(port_error),
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

    /// ⟨M06-W2-R03; the reviewer's probe `review_probe_read_all_and_others_unmarked_follow_
    /// symlink`, inverted⟩ Every listed file is read bounded, as a regular file, with no
    /// link followed: a symlinked `authorized_keys2` (even to a file holding the client's
    /// line), an oversized one, a directory and a FIFO each fail `read_all` and `put`
    /// closed (`Io`) without blocking, and the written file is untouched.
    #[test]
    fn listed_files_are_read_bounded_and_never_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let f = files(dir.path());
        let a = ClientId::from_random_bytes([0xa1; 16]);
        let active = line(&a, 1, None);
        let second = f.files()[1].clone();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, format!("{active}\n")).unwrap();
        let refused = |what: &str| {
            assert_eq!(f.read_all().map(|_| ()), Err(LineIoError::Io), "{what}");
            assert_eq!(f.put(&a, &active), Err(LineIoError::Io), "{what}");
            assert!(!f.written().exists(), "{what}: nothing written");
        };
        std::os::unix::fs::symlink(&outside, &second).unwrap();
        refused("symlinked authorized_keys2");
        std::fs::remove_file(&second).unwrap();
        std::fs::write(&second, vec![b'#'; local::MAX_BYTES + 1]).unwrap();
        refused("oversized authorized_keys2");
        std::fs::remove_file(&second).unwrap();
        std::fs::create_dir(&second).unwrap();
        refused("directory");
        std::fs::remove_dir(&second).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&second)
                .status()
                .unwrap()
                .success()
        );
        refused("fifo");
        std::fs::remove_file(&second).unwrap();
        // The written file itself, symlinked: the read fails closed too.
        std::os::unix::fs::symlink(&outside, f.written()).unwrap();
        assert_eq!(f.read_all().map(|_| ()), Err(LineIoError::Io));
        std::fs::remove_file(f.written()).unwrap();
        f.put(&a, &active).unwrap();
        assert_eq!(f.read_all().unwrap()[0].text, format!("{active}\n"));
    }
}
