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

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use heimdall_localenv::env::{Env, Platform};

/// The largest total argument size `run` accepts (moved here from the contract,
/// m02-plan §5 item 5; argv never crosses IPC).
pub const MAX_ARGV_BYTES: usize = 1 << 20;

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
    let _ = (program, env, cwd, platform);
    todo!("M02-U8 resolve::resolve_program")
}
