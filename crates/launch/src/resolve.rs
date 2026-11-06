//! Program resolution, done by Heimdall and never by a shell (m02-plan U8; ADR-0007
//! §8; ADR-0004 Q-B).
//!
//! * Unix: `PATH` without empty entries or `.`; an `argv[0]` containing `/` is used
//!   as given.
//! * Windows: an explicit path, else `PATH` × `PATHEXT` restricted to `.exe`, `.com`,
//!   `.cmd` and `.bat`. Batch targets run with std's escaping; an argument std refuses
//!   to escape, or a script path containing any of `% ! ^ & | < > " ( ) , ; =` or a
//!   control character, is refused. The current directory is never searched.
//! * A resolved path that is not valid Unicode is refused (`refused_path`): the binding
//!   names the executable as text.
//!
//! Readings this module applies (fail-closed, from "never resolved implicitly from
//! the current directory"):
//! * every **relative** `PATH` entry is skipped, not only empty ones and `.`
//!   (`bin` and `..` name the current directory just as implicitly);
//! * with `PATH` unset there is no default search path;
//! * when nothing on `PATH` matches but the current directory would have, the
//!   refusal is [`LaunchRefusal::CurrentDirectory`] rather than `NotFound`;
//! * as a shell does, a `PATH` match that is a regular file without any execute
//!   bit is passed over, and if no executable match exists the refusal is
//!   [`LaunchRefusal::NotExecutable`] (126); directories on `PATH` are ignored;
//! * Windows: an explicit path without an allowed extension is completed with the
//!   `PATHEXT` extensions as `cmd.exe` does; a file that exists without an allowed
//!   extension is `NotExecutable`;
//! * Windows: std runs `<path>.exe` instead of a `<path>` that does not end in
//!   `.exe` when that sibling exists, so such a sibling is refused (`NotFound`)
//!   rather than recording an executable that would not be the one started;
//! * a `PATHEXT` that is set but names none of the four extensions yields no
//!   candidates; an unset or empty one means `.COM;.EXE;.BAT;.CMD`.
//!
//! Unix executability is judged by the mode's execute bits (std has no `access(2)`);
//! a file executable only by another user passes resolution and then fails in
//! `execve`, which is an `exec_error` after `launching`.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use heimdall_localenv::env::{Env, Platform};

use crate::env::var;

/// The largest total argument size `run` accepts (moved here from the contract,
/// m02-plan §5 item 5; argv never crosses IPC).
pub const MAX_ARGV_BYTES: usize = 1 << 20;

/// The extensions a Windows search may complete a name with.
const WINDOWS_EXTENSIONS: [&str; 4] = [".com", ".exe", ".bat", ".cmd"];

/// Characters `cmd.exe` interprets, refused in a batch script's path (Q-B).
const BATCH_PATH_REFUSED: [char; 13] = [
    '%', '!', '^', '&', '|', '<', '>', '"', '(', ')', ',', ';', '=',
];

/// How the program will be started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramKind {
    /// A native executable.
    Native,
    /// A Windows `.cmd`/`.bat` script.
    Batch,
}

/// How it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// An explicit path.
    Explicit,
    /// A `PATH` search.
    Path,
}

/// A resolved program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProgram {
    /// Absolute path.
    pub path: PathBuf,
    /// Native or batch.
    pub kind: ProgramKind,
    /// How it was found.
    pub via: Via,
}

/// Why a program cannot be launched (`LAUNCH_FAILED`). An argument is named by index
/// only; argument text never appears in an error (Q8 as qualified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum LaunchRefusal {
    /// No such program.
    #[error("program not found")]
    NotFound,
    /// Only the current directory would have matched; it is never searched.
    #[error("program found only in the current directory")]
    CurrentDirectory,
    /// A batch script path with a character cmd would interpret.
    #[error("batch script path refused")]
    BatchPathUnsafe,
    /// An argument std refuses to escape for a batch target.
    #[error("argument {index} cannot be passed safely")]
    ArgumentUnescapable {
        /// The argument's index.
        index: usize,
    },
    /// Found but not executable.
    #[error("program not executable")]
    NotExecutable,
    /// The resolved path is not valid Unicode.
    #[error("program path is not Unicode")]
    PathNotUnicode,
}

impl LaunchRefusal {
    /// The stable `snake_case` reason (m02-plan §5 item 14).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            LaunchRefusal::NotFound => "not_found",
            LaunchRefusal::CurrentDirectory => "current_directory",
            LaunchRefusal::BatchPathUnsafe => "refused_batch_path",
            LaunchRefusal::ArgumentUnescapable { .. } => "refused_argument",
            LaunchRefusal::NotExecutable => "not_executable",
            LaunchRefusal::PathNotUnicode => "refused_path",
        }
    }

    /// The exit status: 126 for a program found but not executable, else 127
    /// (ADR-0007 §8; Q-B).
    #[must_use]
    pub fn exit_code(self) -> i32 {
        match self {
            LaunchRefusal::NotExecutable => 126,
            _ => 127,
        }
    }
}

/// Resolve `program` with `env`'s `PATH` (and `PATHEXT`), relative to `cwd` only for
/// an explicit relative path.
///
/// # Errors
/// [`LaunchRefusal`].
pub fn resolve_program(
    program: &OsStr,
    env: &Env,
    cwd: &Path,
    platform: Platform,
) -> Result<ResolvedProgram, LaunchRefusal> {
    let windows = platform.is_windows();
    if program.is_empty() || program.as_encoded_bytes().contains(&0) {
        return Err(LaunchRefusal::NotFound);
    }
    let Some(name) = program.to_str() else {
        return Err(LaunchRefusal::PathNotUnicode);
    };
    if is_explicit(name, windows) {
        let given = Path::new(program);
        let joined = if given.is_absolute() {
            given.to_path_buf()
        } else {
            cwd.join(given)
        };
        // `components()` drops `.` components; `..` stays (symlinks).
        let path: PathBuf = joined.components().collect();
        if !path.is_absolute() {
            return Err(LaunchRefusal::NotFound);
        }
        let found = if windows {
            explicit_windows(&path, env)?
        } else {
            explicit_unix(path)?
        };
        return finish(found, Via::Explicit, windows);
    }

    let names = candidate_names(name, env, windows);
    let mut passed_over = false;
    for dir in search_dirs(env, platform) {
        for candidate in &names {
            let path = dir.join(candidate);
            match probe(&path, windows) {
                Probe::Runnable => return finish(path, Via::Path, windows),
                Probe::NotRunnable if !windows => passed_over = true,
                Probe::NotRunnable | Probe::Directory | Probe::Absent => {}
            }
        }
    }
    if passed_over {
        return Err(LaunchRefusal::NotExecutable);
    }
    if names
        .iter()
        .any(|candidate| probe(&cwd.join(candidate), windows) == Probe::Runnable)
    {
        return Err(LaunchRefusal::CurrentDirectory);
    }
    Err(LaunchRefusal::NotFound)
}

/// Check `args` (the arguments after the program) before anything is recorded. An
/// argument is named by its `argv` index, the program being 0, so the first
/// argument after it is 1.
///
/// * Every target: an argument containing NUL cannot be passed (`execve` and
///   `CreateProcessW` take NUL-terminated strings).
/// * Batch targets: std refuses an argument containing `\r` or `\n` (they can
///   truncate the `cmd.exe` command line); checking first names the index.
///
/// # Errors
/// [`LaunchRefusal::ArgumentUnescapable`].
pub fn check_arguments(kind: ProgramKind, args: &[OsString]) -> Result<(), LaunchRefusal> {
    for (i, arg) in args.iter().enumerate() {
        let bytes = arg.as_encoded_bytes();
        let line_break = bytes.contains(&b'\r') || bytes.contains(&b'\n');
        if bytes.contains(&0) || (kind == ProgramKind::Batch && line_break) {
            return Err(LaunchRefusal::ArgumentUnescapable { index: i + 1 });
        }
    }
    Ok(())
}

/// The checks every launch path repeats on a [`ResolvedProgram`] before anything is
/// recorded (its fields are public, so it need not come from [`resolve_program`]):
/// the arguments ([`check_arguments`]), the batch script path rule, and a Unicode
/// path. Returns the executable as text, for `launching`.
pub(crate) fn preflight<'a>(
    program: &'a ResolvedProgram,
    args: &[OsString],
) -> Result<&'a str, LaunchRefusal> {
    check_arguments(program.kind, args)?;
    let text = program.path.to_str().ok_or(LaunchRefusal::PathNotUnicode)?;
    if program.kind == ProgramKind::Batch && batch_path_refused(text) {
        return Err(LaunchRefusal::BatchPathUnsafe);
    }
    Ok(text)
}

/// Whether a batch script's path holds a character `cmd.exe` interprets.
pub(crate) fn batch_path_refused(path: &str) -> bool {
    path.chars()
        .any(|c| BATCH_PATH_REFUSED.contains(&c) || c.is_control())
}

/// What is at a candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// Nothing (or a dangling link).
    Absent,
    /// A directory.
    Directory,
    /// Something that cannot be started: a regular file without an execute bit
    /// (Unix) or without an allowed extension (Windows), or another file type.
    NotRunnable,
    /// A program this platform starts.
    Runnable,
}

fn probe(path: &Path, windows: bool) -> Probe {
    let Ok(meta) = std::fs::metadata(path) else {
        return Probe::Absent;
    };
    if meta.is_dir() {
        return Probe::Directory;
    }
    if !meta.is_file() {
        return Probe::NotRunnable;
    }
    let runnable = if windows {
        allowed_extension(path.as_os_str()).is_some()
    } else {
        has_execute_bit(&meta)
    };
    if runnable {
        Probe::Runnable
    } else {
        Probe::NotRunnable
    }
}

#[cfg(unix)]
fn has_execute_bit(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn has_execute_bit(_meta: &std::fs::Metadata) -> bool {
    // Unix rules on a host without execute bits: a regular file counts.
    true
}

fn is_explicit(name: &str, windows: bool) -> bool {
    if windows {
        name.contains(['/', '\\', ':'])
    } else {
        name.contains('/')
    }
}

fn explicit_unix(path: PathBuf) -> Result<PathBuf, LaunchRefusal> {
    match probe(&path, false) {
        Probe::Runnable => Ok(path),
        Probe::Absent => Err(LaunchRefusal::NotFound),
        Probe::Directory | Probe::NotRunnable => Err(LaunchRefusal::NotExecutable),
    }
}

fn explicit_windows(path: &Path, env: &Env) -> Result<PathBuf, LaunchRefusal> {
    if allowed_extension(path.as_os_str()).is_some() {
        return match probe(path, true) {
            Probe::Runnable => Ok(path.to_path_buf()),
            Probe::Absent => Err(LaunchRefusal::NotFound),
            Probe::Directory | Probe::NotRunnable => Err(LaunchRefusal::NotExecutable),
        };
    }
    for ext in pathext(env) {
        let mut candidate = path.as_os_str().to_owned();
        candidate.push(ext);
        let candidate = PathBuf::from(candidate);
        if probe(&candidate, true) == Probe::Runnable {
            return Ok(candidate);
        }
    }
    match probe(path, true) {
        Probe::Absent => Err(LaunchRefusal::NotFound),
        _ => Err(LaunchRefusal::NotExecutable),
    }
}

/// Classify and check a found path.
fn finish(path: PathBuf, via: Via, windows: bool) -> Result<ResolvedProgram, LaunchRefusal> {
    let Some(text) = path.to_str() else {
        return Err(LaunchRefusal::PathNotUnicode);
    };
    let ext = if windows {
        allowed_extension(path.as_os_str())
    } else {
        None
    };
    let kind = match ext {
        Some(".bat" | ".cmd") => ProgramKind::Batch,
        _ => ProgramKind::Native,
    };
    if kind == ProgramKind::Batch && batch_path_refused(text) {
        return Err(LaunchRefusal::BatchPathUnsafe);
    }
    if windows && ext != Some(".exe") {
        let mut sibling = path.as_os_str().to_owned();
        sibling.push(".exe");
        if probe(Path::new(&sibling), true) != Probe::Absent {
            return Err(LaunchRefusal::NotFound);
        }
    }
    Ok(ResolvedProgram { path, kind, via })
}

/// The allowed Windows extension `name` ends with (ASCII case-insensitive),
/// lowercase.
fn allowed_extension(name: &OsStr) -> Option<&'static str> {
    let bytes = name.as_encoded_bytes();
    WINDOWS_EXTENSIONS.into_iter().find(|ext| {
        bytes.len() > ext.len()
            && bytes[bytes.len() - ext.len()..].eq_ignore_ascii_case(ext.as_bytes())
    })
}

/// The allowed extensions in `PATHEXT` order (lowercase, no duplicates).
fn pathext(env: &Env) -> Vec<&'static str> {
    let Some(raw) = var(env, "PATHEXT", Platform::Windows).filter(|v| !v.is_empty()) else {
        return WINDOWS_EXTENSIONS.to_vec();
    };
    let raw = raw.to_string_lossy();
    let mut out: Vec<&'static str> = Vec::new();
    for entry in raw.split(';') {
        let entry = entry.trim();
        if let Some(ext) = WINDOWS_EXTENSIONS
            .into_iter()
            .find(|ext| ext.eq_ignore_ascii_case(entry))
            && !out.contains(&ext)
        {
            out.push(ext);
        }
    }
    out
}

/// The names a search tries in each directory.
fn candidate_names(name: &str, env: &Env, windows: bool) -> Vec<String> {
    if !windows || allowed_extension(OsStr::new(name)).is_some() {
        return vec![name.to_owned()];
    }
    pathext(env)
        .into_iter()
        .map(|ext| format!("{name}{ext}"))
        .collect()
}

/// The absolute `PATH` entries, in order.
fn search_dirs(env: &Env, platform: Platform) -> Vec<PathBuf> {
    let Some(raw) = var(env, "PATH", platform) else {
        return Vec::new();
    };
    split_path_var(raw, platform.is_windows())
        .into_iter()
        .filter(|dir| !dir.as_os_str().is_empty() && dir.is_absolute())
        .collect()
}

/// `PATH` entries. The host's own rules split exactly (Unix bytes at `:`; Windows
/// through `std::env::split_paths`); the other platform's rules, used only to test
/// them on this host, split the text.
fn split_path_var(raw: &OsStr, windows: bool) -> Vec<PathBuf> {
    #[cfg(windows)]
    if windows {
        return std::env::split_paths(raw).collect();
    }
    #[cfg(unix)]
    if !windows {
        use std::os::unix::ffi::OsStrExt as _;
        return raw
            .as_bytes()
            .split(|b| *b == b':')
            .map(|entry| PathBuf::from(OsStr::from_bytes(entry)))
            .collect();
    }
    let text = raw.to_string_lossy();
    if windows {
        split_windows_text(&text)
    } else {
        text.split(':').map(PathBuf::from).collect()
    }
}

/// Windows `PATH` entries: `;`-separated, a `"…"` section keeps its `;` and loses
/// its quotes (the rule of `std::env::split_paths` on Windows).
fn split_windows_text(raw: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in raw.chars() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => out.push(PathBuf::from(std::mem::take(&mut current))),
            _ => current.push(c),
        }
    }
    out.push(PathBuf::from(current));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::meta::scratch::Scratch;

    fn write_file(path: &Path, mode: u32) {
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    fn env_path(dirs: &[&Path], sep: &str) -> Env {
        let joined: Vec<String> = dirs
            .iter()
            .map(|d| d.to_str().unwrap().to_owned())
            .collect();
        Env::from_vars([("PATH", joined.join(sep))])
    }

    #[cfg(unix)]
    fn unix() -> Platform {
        Platform::Linux
    }

    #[cfg(unix)]
    #[test]
    fn unix_path_search_takes_the_first_executable_in_order() {
        let s = Scratch::new();
        let (a, b) = (s.path().join("a"), s.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("tool"), 0o644);
        write_file(&b.join("tool"), 0o755);
        let env = env_path(&[&a, &b], ":");
        let found = resolve_program(OsStr::new("tool"), &env, s.path(), unix()).unwrap();
        assert_eq!(
            found,
            ResolvedProgram {
                path: b.join("tool"),
                kind: ProgramKind::Native,
                via: Via::Path
            }
        );
        // Only the non-executable one: 126, as a shell does.
        let env = env_path(&[&a], ":");
        assert_eq!(
            resolve_program(OsStr::new("tool"), &env, s.path(), unix()),
            Err(LaunchRefusal::NotExecutable)
        );
        assert_eq!(
            resolve_program(OsStr::new("absent"), &env, s.path(), unix()),
            Err(LaunchRefusal::NotFound)
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_current_directory_is_never_searched_even_through_dot_empty_or_relative_entries() {
        let s = Scratch::new();
        let cwd = s.path().join("cwd");
        std::fs::create_dir_all(cwd.join("bin")).unwrap();
        write_file(&cwd.join("tool"), 0o755);
        write_file(&cwd.join("bin/tool2"), 0o755);
        for path in [".", "", "::", ":.", "./", "bin", "../cwd"] {
            let env = Env::from_vars([("PATH", path)]);
            assert_eq!(
                resolve_program(OsStr::new("tool"), &env, &cwd, unix()),
                Err(LaunchRefusal::CurrentDirectory),
                "PATH={path:?}"
            );
            assert_eq!(
                resolve_program(OsStr::new("tool2"), &env, &cwd, unix()),
                Err(LaunchRefusal::NotFound),
                "PATH={path:?}"
            );
        }
        // No PATH at all: no default search path either.
        assert_eq!(
            resolve_program(OsStr::new("tool"), &Env::default(), &cwd, unix()),
            Err(LaunchRefusal::CurrentDirectory)
        );
    }

    #[test]
    fn relative_and_empty_path_entries_are_dropped_before_any_probe() {
        // A relative entry would be probed against the process's own working
        // directory, so the list itself must not contain one.
        let abs = std::env::temp_dir();
        let abs_text = abs.to_str().unwrap();
        // Unix rules split at `:` and a Unix path is absolute only on a Unix host, so a
        // Windows host (`C:\...`) can check only that the relative entries all go.
        let unix_relative = Env::from_vars([("PATH", ".::bin:../x:./:")]);
        assert!(search_dirs(&unix_relative, Platform::Linux).is_empty());
        #[cfg(unix)]
        {
            let unix_env = Env::from_vars([("PATH", format!(".::bin:../x:./:{abs_text}:"))]);
            assert_eq!(search_dirs(&unix_env, Platform::Linux), vec![abs.clone()]);
        }
        let win_env = Env::from_vars([("Path", format!(".;;bin;\"\";..\\x;{abs_text};"))]);
        assert_eq!(search_dirs(&win_env, Platform::Windows), vec![abs]);
        assert!(search_dirs(&Env::default(), Platform::Linux).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unix_explicit_paths_are_used_as_given_relative_to_cwd() {
        let s = Scratch::new();
        let cwd = s.path();
        std::fs::create_dir_all(cwd.join("bin")).unwrap();
        write_file(&cwd.join("bin/run"), 0o755);
        write_file(&cwd.join("plain"), 0o600);
        // An empty PATH must not matter for an explicit path.
        let env = Env::default();
        let found = resolve_program(OsStr::new("./bin/run"), &env, cwd, unix()).unwrap();
        assert_eq!(found.path, cwd.join("bin/run"));
        assert_eq!(found.via, Via::Explicit);
        assert!(found.path.is_absolute());
        let found = resolve_program(OsStr::new("bin/run"), &env, cwd, unix()).unwrap();
        assert_eq!(found.path, cwd.join("bin/run"));
        let abs = cwd.join("bin/run");
        let found = resolve_program(abs.as_os_str(), &env, Path::new("/"), unix()).unwrap();
        assert_eq!(found.path, abs);
        assert_eq!(
            resolve_program(OsStr::new("./plain"), &env, cwd, unix()),
            Err(LaunchRefusal::NotExecutable)
        );
        assert_eq!(
            resolve_program(OsStr::new("./bin"), &env, cwd, unix()),
            Err(LaunchRefusal::NotExecutable)
        );
        assert_eq!(
            resolve_program(OsStr::new("./missing"), &env, cwd, unix()),
            Err(LaunchRefusal::NotFound)
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_program_or_location_is_refused_path() {
        use std::os::unix::ffi::OsStrExt as _;
        let env = Env::from_vars([("PATH", "/usr/bin:/bin")]);
        assert_eq!(
            resolve_program(
                OsStr::from_bytes(b"/tmp/\xff/tool"),
                &env,
                Path::new("/"),
                unix()
            ),
            Err(LaunchRefusal::PathNotUnicode)
        );
        assert_eq!(
            resolve_program(OsStr::from_bytes(b"to\xffol"), &env, Path::new("/"), unix()),
            Err(LaunchRefusal::PathNotUnicode)
        );
        // A non-Unicode working directory under a relative explicit path.
        let s = Scratch::new();
        let cwd = s.path().join(OsStr::from_bytes(b"d\xff"));
        if std::fs::create_dir(&cwd).is_ok() {
            write_file(&cwd.join("tool"), 0o755);
            assert_eq!(
                resolve_program(OsStr::new("./tool"), &env, &cwd, unix()),
                Err(LaunchRefusal::PathNotUnicode)
            );
        }
        // NUL and empty never resolve.
        assert_eq!(
            resolve_program(OsStr::new(""), &env, Path::new("/"), unix()),
            Err(LaunchRefusal::NotFound)
        );
        assert_eq!(
            resolve_program(
                OsStr::from_bytes(b"/bin/sh\0x"),
                &env,
                Path::new("/"),
                unix()
            ),
            Err(LaunchRefusal::NotFound)
        );
    }

    #[test]
    fn windows_search_uses_pathext_order_restricted_to_four_extensions() {
        let s = Scratch::new();
        let dir = s.path().join("bin");
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["tool.ps1", "tool.bat", "tool.exe", "tool.com"] {
            write_file(&dir.join(name), 0o644);
        }
        let path = dir.to_str().unwrap().to_owned();
        let find = |pathext: Option<&str>| {
            let mut vars = vec![("PATH".to_owned(), path.clone())];
            if let Some(p) = pathext {
                vars.push(("PATHEXT".to_owned(), p.to_owned()));
            }
            resolve_program(
                OsStr::new("tool"),
                &Env::from_vars(vars),
                s.path(),
                Platform::Windows,
            )
        };
        // .PS1 is not one of the four; .BAT comes next.
        let found = find(Some(".PS1;.BAT;.EXE")).unwrap();
        assert_eq!(found.path, dir.join("tool.bat"));
        assert_eq!(found.kind, ProgramKind::Batch);
        assert_eq!(found.via, Via::Path);
        // Unset or empty: .COM;.EXE;.BAT;.CMD.
        assert_eq!(find(None).unwrap().path, dir.join("tool.com"));
        assert_eq!(find(Some("")).unwrap().path, dir.join("tool.com"));
        assert_eq!(find(Some(".EXE")).unwrap().kind, ProgramKind::Native);
        // Set, but none of the four: no candidates.
        assert_eq!(find(Some(".PS1;.VBS")), Err(LaunchRefusal::NotFound));
    }

    #[test]
    fn windows_name_with_an_allowed_extension_is_searched_as_is() {
        let s = Scratch::new();
        write_file(&s.path().join("Script.CMD"), 0o644);
        write_file(&s.path().join("other.ps1"), 0o644);
        let env = env_path(&[s.path()], ";");
        let found = resolve_program(
            OsStr::new("Script.CMD"),
            &env,
            Path::new("/"),
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(found.kind, ProgramKind::Batch);
        assert_eq!(found.path, s.path().join("Script.CMD"));
        assert_eq!(
            resolve_program(
                OsStr::new("other.ps1"),
                &env,
                Path::new("/"),
                Platform::Windows
            ),
            Err(LaunchRefusal::NotFound)
        );
    }

    #[test]
    fn windows_current_directory_never_searched() {
        let s = Scratch::new();
        let cwd = s.path().join("cwd");
        let empty = s.path().join("empty");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&empty).unwrap();
        write_file(&cwd.join("tool.exe"), 0o644);
        let env = Env::from_vars([("PATH", format!(".;;{}", empty.to_str().unwrap()))]);
        assert_eq!(
            resolve_program(OsStr::new("tool"), &env, &cwd, Platform::Windows),
            Err(LaunchRefusal::CurrentDirectory)
        );
    }

    #[test]
    fn windows_quoted_path_entry_keeps_its_semicolon() {
        let s = Scratch::new();
        let dir = s.path().join("a;b");
        std::fs::create_dir_all(&dir).unwrap();
        write_file(&dir.join("tool.exe"), 0o644);
        let env = Env::from_vars([("Path", format!("\"{}\"", dir.to_str().unwrap()))]);
        let found = resolve_program(OsStr::new("tool"), &env, s.path(), Platform::Windows).unwrap();
        assert_eq!(found.path, dir.join("tool.exe"));
    }

    #[test]
    fn windows_batch_path_with_percent_bang_caret_and_every_cmd_metacharacter_refused_127() {
        let s = Scratch::new();
        for c in BATCH_PATH_REFUSED.into_iter().chain(['\u{1}', '\t']) {
            let dir = s.path().join(format!("d{}x", u32::from(c)));
            let bad = dir.join(format!("a{c}b"));
            if cfg!(windows) && (matches!(c, '<' | '>' | '"' | '|') || c.is_control()) {
                // Not a legal Windows file name, so no such script can exist to be
                // found; the rule itself is still checked on a path naming one.
                let script = ResolvedProgram {
                    path: bad.join("tool.cmd"),
                    kind: ProgramKind::Batch,
                    via: Via::Explicit,
                };
                assert_eq!(
                    preflight(&script, &[]),
                    Err(LaunchRefusal::BatchPathUnsafe),
                    "char {c:?}"
                );
                let native = ResolvedProgram {
                    path: bad.join("native.exe"),
                    kind: ProgramKind::Native,
                    via: Via::Explicit,
                };
                assert!(preflight(&native, &[]).is_ok(), "char {c:?}");
                assert_eq!(LaunchRefusal::BatchPathUnsafe.exit_code(), 127);
                continue;
            }
            std::fs::create_dir_all(&bad).unwrap();
            write_file(&bad.join("tool.cmd"), 0o644);
            write_file(&bad.join("native.exe"), 0o644);
            let refusal = if c == ';' || c == '"' {
                // In a Windows PATH, `;` separates and `"` quotes; check the explicit
                // path for those two.
                resolve_program(
                    bad.join("tool.cmd").as_os_str(),
                    &Env::default(),
                    s.path(),
                    Platform::Windows,
                )
            } else {
                resolve_program(
                    OsStr::new("tool"),
                    &env_path(&[&bad], ";"),
                    s.path(),
                    Platform::Windows,
                )
            };
            assert_eq!(refusal, Err(LaunchRefusal::BatchPathUnsafe), "char {c:?}");
            assert_eq!(LaunchRefusal::BatchPathUnsafe.exit_code(), 127);
            // The rule is for scripts only: a native program there is fine.
            let native = resolve_program(
                bad.join("native.exe").as_os_str(),
                &Env::default(),
                s.path(),
                Platform::Windows,
            )
            .unwrap();
            assert_eq!(native.kind, ProgramKind::Native, "char {c:?}");
        }
    }

    #[test]
    fn windows_explicit_path_is_completed_with_pathext_and_checked() {
        let s = Scratch::new();
        write_file(&s.path().join("ssh.exe"), 0o644);
        write_file(&s.path().join("readme"), 0o644);
        let env = Env::default();
        let base = s.path().join("ssh");
        let found = resolve_program(base.as_os_str(), &env, s.path(), Platform::Windows).unwrap();
        assert_eq!(found.path, s.path().join("ssh.exe"));
        assert_eq!(found.via, Via::Explicit);
        assert_eq!(
            resolve_program(
                s.path().join("readme").as_os_str(),
                &env,
                s.path(),
                Platform::Windows
            ),
            Err(LaunchRefusal::NotExecutable)
        );
        assert_eq!(
            resolve_program(s.path().as_os_str(), &env, s.path(), Platform::Windows),
            Err(LaunchRefusal::NotExecutable)
        );
        assert_eq!(
            resolve_program(
                s.path().join("gone.exe").as_os_str(),
                &env,
                s.path(),
                Platform::Windows
            ),
            Err(LaunchRefusal::NotFound)
        );
    }

    #[test]
    fn windows_sibling_exe_that_std_would_prefer_is_refused() {
        let s = Scratch::new();
        write_file(&s.path().join("tool.bat"), 0o644);
        write_file(&s.path().join("tool.bat.exe"), 0o644);
        let env = env_path(&[s.path()], ";");
        assert_eq!(
            resolve_program(
                OsStr::new("tool.bat"),
                &env,
                Path::new("/"),
                Platform::Windows
            ),
            Err(LaunchRefusal::NotFound)
        );
        std::fs::remove_file(s.path().join("tool.bat.exe")).unwrap();
        assert_eq!(
            resolve_program(
                OsStr::new("tool.bat"),
                &env,
                Path::new("/"),
                Platform::Windows
            )
            .unwrap()
            .kind,
            ProgramKind::Batch
        );
    }

    #[test]
    fn argument_check_names_the_index_and_applies_batch_rules_only_to_batch() {
        let args: Vec<OsString> = ["a", "line\nbreak", "cr\rhere"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert_eq!(check_arguments(ProgramKind::Native, &args), Ok(()));
        assert_eq!(
            check_arguments(ProgramKind::Batch, &args),
            Err(LaunchRefusal::ArgumentUnescapable { index: 2 })
        );
        assert_eq!(
            check_arguments(ProgramKind::Batch, &args[2..]),
            Err(LaunchRefusal::ArgumentUnescapable { index: 1 })
        );
        let nul = vec![OsString::from("ok"), OsString::from("n\0ul")];
        for kind in [ProgramKind::Native, ProgramKind::Batch] {
            let err = check_arguments(kind, &nul).unwrap_err();
            assert_eq!(err, LaunchRefusal::ArgumentUnescapable { index: 2 });
            // The message names the index, never the text.
            assert!(!err.to_string().contains("n\0ul"));
            assert_eq!(err.reason(), "refused_argument");
        }
        // The injection cases std escapes are accepted for batch targets.
        let metas: Vec<OsString> = [
            "%PATH%", "!x!", "a&b", "a|b", "\"q\"", "^", "(x)", "a b", "",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(check_arguments(ProgramKind::Batch, &metas), Ok(()));
    }

    #[test]
    fn batch_path_rule_covers_control_characters() {
        assert!(batch_path_refused("C:\\a\u{7f}b\\x.cmd"));
        assert!(batch_path_refused("C:\\a\nb\\x.cmd"));
        assert!(!batch_path_refused("C:\\Program Files\\node\\npx.cmd"));
    }
}
