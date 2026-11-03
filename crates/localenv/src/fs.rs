//! The real-filesystem configuration source (m02-plan U3).
//!
//! Non-blocking open, then `fstat`: regular files only (a FIFO include never blocks,
//! `a21_fifo_include_does_not_block`); symlinks followed as OpenSSH does; the bounds of
//! `heimdall_sshconf::limits::Limits`.
//!
//! * [`read_bounded`]: `stat` first (a FIFO, device or directory is refused unopened),
//!   then an `O_NONBLOCK|O_NOCTTY` open (so a FIFO swapped in after the `stat` opens
//!   without waiting for a writer), then `fstat` on the open file, which must be a
//!   regular file of at most the bound. On Windows a path in the device namespace
//!   (`\\.\…`, `\\?\…`, `//./…`; a named pipe, for example the agent's) is refused
//!   before any call, so reading configuration never connects to a pipe.
//! * [`glob_bounded`]: `glob(3)` semantics as OpenSSH calls it (wildcards never match
//!   `/` or a leading `.`), bytewise-sorted, more than the bound refused. A directory
//!   the walk cannot read is an error, not "no match": the tree is then not fully
//!   readable (fail closed; OpenSSH's `glob` would skip it silently).

use std::io::Read;
use std::path::{Path, PathBuf};

use heimdall_sshconf::include::{ConfigSource, SourceBytes, SourceError};
use heimdall_sshconf::limits::Limits;

use crate::env::Env;
use crate::paths::SshPaths;

/// Bounded, read-only access to the real configuration tree.
#[derive(Debug, Clone)]
pub struct BoundedSource {
    paths: SshPaths,
    env: Env,
    limits: Limits,
}

impl BoundedSource {
    /// A source over `paths`, expanding `${VAR}` from `env`.
    #[must_use]
    pub fn new(paths: SshPaths, env: Env, limits: Limits) -> Self {
        Self { paths, env, limits }
    }

    /// The bounds in force.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The paths in force.
    #[must_use]
    pub fn paths(&self) -> &SshPaths {
        &self.paths
    }
}

impl ConfigSource for BoundedSource {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        read_bounded(path, self.limits.file_bytes)
    }

    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        glob_bounded(pattern, self.limits.glob_results)
    }

    fn account_home(&self) -> &Path {
        &self.paths.account_home
    }

    fn user_dir(&self) -> &Path {
        &self.paths.user_dir
    }

    fn system_dir(&self) -> &Path {
        &self.paths.system_dir
    }

    fn env(&self, name: &str) -> Option<String> {
        self.env
            .get(name)
            .and_then(|v| v.to_str())
            .map(str::to_owned)
    }

    /// The trait's rule (ADR-0007 §12.17 item 9) over the raw `HOME`, so a value that
    /// is not UTF-8, which `env` cannot show, is still compared and never taken for an
    /// unset `HOME` (fail closed).
    fn include_home(&self) -> Option<&Path> {
        include_home_for(&self.env, &self.paths.account_home)
    }
}

/// The home an `Include`'s `~` and a relative user `Include` resolve under for this
/// environment (ADR-0007 §12.17 item 9; `ConfigSource::include_home`): the account home
/// when `HOME` is unset (`glob(3)` falls back to the account database) or names it,
/// `None` when `HOME` is anything else. `None` makes those includes undetermined, and
/// the doctor reports `home_mismatch`.
#[must_use]
pub fn include_home_for<'a>(env: &Env, account_home: &'a Path) -> Option<&'a Path> {
    match env.get("HOME") {
        None => Some(account_home),
        Some(value) => heimdall_sshconf::include::home_matches(Path::new(value), account_home)
            .then_some(account_home),
    }
}

/// An I/O error as a [`SourceError`]: its kind only, never the path.
#[must_use]
pub fn map_io(e: &std::io::Error) -> SourceError {
    match e.kind() {
        std::io::ErrorKind::NotFound => SourceError::NotFound,
        std::io::ErrorKind::PermissionDenied => SourceError::PermissionDenied,
        kind => SourceError::Io(format!("{kind:?}")),
    }
}

/// Whether `path` is in the Windows device namespace (`\\.\`, `\\?\`, `//./`, `//?/`),
/// where a "file" may be a pipe or a device. Always `false` off Windows.
#[must_use]
pub fn is_device_namespace(path: &Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let s = path.to_string_lossy();
    let b = s.as_bytes();
    b.len() >= 4
        && matches!(b[0], b'\\' | b'/')
        && matches!(b[1], b'\\' | b'/')
        && matches!(b[2], b'.' | b'?')
        && matches!(b[3], b'\\' | b'/')
        // `\\?\C:\…` is the verbatim form of an ordinary drive path, not a device.
        && !(b[2] == b'?' && b.len() >= 6 && b[5] == b':')
}

/// Read one configuration file: regular files only, at most `max` bytes, never
/// blocking on a FIFO (module documentation). The canonical path follows symlinks.
///
/// # Errors
/// [`SourceError`]: `NotRegular`, `BoundExceeded`, `NotFound`, `PermissionDenied`,
/// `Io`.
pub fn read_bounded(path: &Path, max: usize) -> Result<SourceBytes, SourceError> {
    if is_device_namespace(path) {
        return Err(SourceError::NotRegular);
    }
    if !path.is_absolute() {
        return Err(SourceError::Io("relative path".to_owned()));
    }
    let meta = std::fs::metadata(path).map_err(|e| map_io(&e))?;
    if !meta.is_file() {
        return Err(SourceError::NotRegular);
    }
    let file = open_nonblocking(path).map_err(|e| map_io(&e))?;
    let meta = file.metadata().map_err(|e| map_io(&e))?;
    if !meta.is_file() {
        return Err(SourceError::NotRegular);
    }
    let bound = u64::try_from(max).unwrap_or(u64::MAX);
    if meta.len() > bound {
        return Err(SourceError::BoundExceeded);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0).min(max));
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| map_io(&e))?;
    if bytes.len() > max {
        return Err(SourceError::BoundExceeded);
    }
    let canonical = canonical_path(path).map_err(|e| map_io(&e))?;
    Ok(SourceBytes { canonical, bytes })
}

#[cfg(unix)]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// The canonical path, with Windows' verbatim drive prefix removed so display and
/// comparison use the ordinary form.
///
/// # Errors
/// The path cannot be resolved.
pub fn canonical_path(path: &Path) -> std::io::Result<PathBuf> {
    let c = std::fs::canonicalize(path)?;
    Ok(strip_verbatim(c))
}

#[cfg(windows)]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        return PathBuf::from(rest);
    }
    p
}

#[cfg(not(windows))]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    p
}

/// Expand one absolute pattern with `glob(3)` semantics: bytewise order, at most
/// `max` matches, an unreadable directory an error.
///
/// # Errors
/// [`SourceError`]: `BoundExceeded` above `max`; `PermissionDenied` or `Io` when a
/// directory cannot be read or the pattern is not UTF-8 or malformed; `NotRegular` for
/// a Windows device-namespace pattern.
pub fn glob_bounded(pattern: &Path, max: usize) -> Result<Vec<PathBuf>, SourceError> {
    if is_device_namespace(pattern) {
        return Err(SourceError::NotRegular);
    }
    if !pattern.is_absolute() {
        return Err(SourceError::Io("relative pattern".to_owned()));
    }
    let text = pattern
        .to_str()
        .ok_or_else(|| SourceError::Io("pattern is not UTF-8".to_owned()))?;
    let options = glob::MatchOptions {
        case_sensitive: !cfg!(windows),
        require_literal_separator: true,
        require_literal_leading_dot: true,
    };
    let entries = glob::glob_with(text, options)
        .map_err(|_| SourceError::Io("malformed pattern".to_owned()))?;
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| map_io(e.error()))?;
        out.push(path);
        if out.len() > max {
            return Err(SourceError::BoundExceeded);
        }
    }
    out.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    out.dedup();
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_regular_files_within_the_bound_only() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.conf");
        std::fs::write(&f, b"Host a\n").unwrap();
        let got = read_bounded(&f, 1024).unwrap();
        assert_eq!(got.bytes, b"Host a\n");
        assert_eq!(got.canonical, canonical_path(&f).unwrap());
        assert_eq!(read_bounded(&f, 3).unwrap_err(), SourceError::BoundExceeded);
        assert_eq!(
            read_bounded(dir.path(), 1024).unwrap_err(),
            SourceError::NotRegular
        );
        assert_eq!(
            read_bounded(&dir.path().join("missing"), 1024).unwrap_err(),
            SourceError::NotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_followed_and_canonicalized() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.conf");
        std::fs::write(&target, b"Port 1\n").unwrap();
        let link = dir.path().join("l.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = read_bounded(&link, 1024).unwrap();
        assert_eq!(got.canonical, canonical_path(&target).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("f.conf");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let started = std::time::Instant::now();
        assert_eq!(
            read_bounded(&fifo, 1024).unwrap_err(),
            SourceError::NotRegular
        );
        // A nonblocking open of the FIFO itself (the race the `fstat` closes).
        let f = open_nonblocking(&fifo).unwrap();
        assert!(!f.metadata().unwrap().is_file());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn glob_sorts_bytewise_skips_dotfiles_and_bounds_results() {
        let dir = tempfile::tempdir().unwrap();
        // Names that differ by more than case: APFS and NTFS are case-insensitive.
        for name in ["b2.conf", "B1.conf", "a.conf", ".hidden.conf", "x.txt"] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let pattern = dir.path().join("*.conf");
        let got = glob_bounded(&pattern, 16).unwrap();
        let names: Vec<_> = got
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["B1.conf", "a.conf", "b2.conf"]);
        assert_eq!(
            glob_bounded(&pattern, 2).unwrap_err(),
            SourceError::BoundExceeded
        );
        assert!(
            glob_bounded(&dir.path().join("none-*.conf"), 16)
                .unwrap()
                .is_empty()
        );
        assert!(glob_bounded(Path::new("relative/*.conf"), 16).is_err());
    }

    /// ADR-0007 §12.17 item 9: the include home is the account home only when `HOME`
    /// is unset or names it. A `HOME` that is not UTF-8 is compared too, never taken
    /// for an unset one (the trait's default reads `env`, which cannot show it).
    #[test]
    fn include_home_follows_the_home_rule_over_the_raw_value() {
        use std::ffi::OsString;
        let paths =
            SshPaths::with_test_override(PathBuf::from("/hm/home"), PathBuf::from("/hm/etc"));
        let home = |value: Option<OsString>| {
            let vars: Vec<(OsString, OsString)> = value
                .map(|v| (OsString::from("HOME"), v))
                .into_iter()
                .collect();
            let source = BoundedSource::new(paths.clone(), Env::from_vars(vars), Limits::default());
            source.include_home().map(Path::to_path_buf)
        };
        let account = Some(PathBuf::from("/hm/home"));
        assert_eq!(home(None), account);
        assert_eq!(home(Some("/hm/home".into())), account);
        assert_eq!(home(Some("/hm/home/".into())), account);
        for other in ["/hm/other", "", "hm/home", "/hm/home/x"] {
            assert_eq!(home(Some(other.into())), None, "{other:?}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            assert_eq!(home(Some(OsString::from_vec(b"/hm/\xff".to_vec()))), None);
        }
    }

    #[test]
    fn device_namespace_is_refused_only_on_windows() {
        let pipe = Path::new(r"\\.\pipe\openssh-ssh-agent");
        let fwd = Path::new("//./pipe/openssh-ssh-agent");
        assert_eq!(is_device_namespace(pipe), cfg!(windows));
        assert_eq!(is_device_namespace(fwd), cfg!(windows));
        assert!(!is_device_namespace(Path::new(r"\\?\C:\Users\x")));
        assert!(!is_device_namespace(Path::new("/etc/ssh/ssh_config")));
    }
}
