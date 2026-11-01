//! The process contract (m02-plan U8; ADR-0007 §8; spec §10.4).
//!
//! `run` resolves the program itself ([`resolve`]), builds the child's environment
//! delta ([`env`]), checks non-interactive eligibility last ([`eligibility`]), writes
//! the side-channel `launching` record ([`meta`]) and then execs (Unix, [`unix`]) or
//! spawns and waits (Windows, [`windows`]). The TUI hands the terminal over through
//! [`handoff`]. `argv` never crosses IPC and never appears in a record, error, event
//! or log.
//!
//! **Status (m02-plan wave 1).** Signatures are fixed. U8 core has written
//! [`resolve`], [`env`], [`meta`], `unix`, `windows` and [`handoff`];
//! [`eligibility::check_noninteractive`] stays `todo!("M02-U8 …")` until wave 3, and
//! [`meta::SideChannel::from_fd`] delegates to `heimdall_localenv::sys`'s
//! `adopt_inherited_fd`, which is still `todo!()`. Neither is reachable: `heimdall run`
//! and `heimdall connect` answer "not available in this build" until the wave-3
//! wiring lands, and nothing else calls this crate.

pub mod eligibility;
pub mod env;
pub mod handoff;
pub mod meta;
pub mod resolve;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub use resolve::MAX_ARGV_BYTES;

use resolve::LaunchRefusal;

/// A launch that did not happen, or whose exec/spawn call failed after `launching`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchFailure {
    /// Refused before any record (`LAUNCH_FAILED`, 127 or 126).
    #[error("launch refused: {0}")]
    Refused(LaunchRefusal),
    /// The `launching` record could not be written: no child (`meta_unavailable`).
    #[error("run record unavailable")]
    MetaUnavailable,
    /// `execve`/`CreateProcessW` failed after `launching` (`exec_error`).
    #[error("launch call failed")]
    ExecError,
}

#[cfg(test)]
mod tests {
    use super::resolve::LaunchRefusal;

    #[test]
    fn launch_refusals_map_to_their_reasons_and_exit_statuses() {
        let cases = [
            (LaunchRefusal::NotFound, "not_found", 127),
            (LaunchRefusal::CurrentDirectory, "current_directory", 127),
            (LaunchRefusal::BatchPathUnsafe, "refused_batch_path", 127),
            (
                LaunchRefusal::ArgumentUnescapable { index: 3 },
                "refused_argument",
                127,
            ),
            (LaunchRefusal::NotExecutable, "not_executable", 126),
            (LaunchRefusal::PathNotUnicode, "refused_path", 127),
        ];
        for (refusal, reason, exit) in cases {
            assert_eq!(refusal.reason(), reason);
            assert_eq!(refusal.exit_code(), exit);
        }
    }

    #[test]
    fn argument_refusal_names_the_index_never_the_text() {
        let msg = LaunchRefusal::ArgumentUnescapable { index: 2 }.to_string();
        assert_eq!(msg, "argument 2 cannot be passed safely");
    }

    #[test]
    fn argv_bound_is_one_mebibyte() {
        assert_eq!(super::MAX_ARGV_BYTES, 1 << 20);
    }
}
