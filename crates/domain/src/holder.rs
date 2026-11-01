//! The process holding a launch binding and its liveness (ADR-0007 §8; m02-plan §5
//! items 5 and 17).
//!
//! The holder is lifecycle metadata, never authorization: it is excluded from the
//! `bind` request hash, and a reused PID never counts because the opaque OS
//! start-time token must match too.

use serde::{Deserialize, Serialize};

/// The holder process: PID and opaque OS start-time token. The wire type of
/// `LaunchBinding.holder`, re-exported so domain, store and ports name one type.
pub use heimdall_contract::request::ProcessHolder;

/// What `ProcessLiveness::state` observed for a holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderState {
    /// A process with this PID and the same start-time token is running.
    Alive,
    /// No such process (the PID is gone, or now names a process with another start
    /// time).
    Exited,
    /// Liveness could not be established; never treated as exited.
    Unknown,
}

/// Bounds of a holder (m02-plan §5 item 5): `pid > 0`, and `started_at` is 1 to 64
/// bytes of `[A-Za-z0-9._:-]`.
#[must_use]
pub fn holder_is_valid(holder: &ProcessHolder) -> bool {
    holder.pid > 0
        && (1..=64).contains(&holder.started_at.len())
        && holder
            .started_at
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn holder_bounds_and_state_wire_names() {
        let ok = ProcessHolder {
            pid: 42,
            started_at: "1730419200.123:boot-a_b".into(),
        };
        assert!(holder_is_valid(&ok));
        for bad in [
            ProcessHolder {
                pid: 0,
                started_at: "t".into(),
            },
            ProcessHolder {
                pid: 1,
                started_at: String::new(),
            },
            ProcessHolder {
                pid: 1,
                started_at: "a".repeat(65),
            },
            ProcessHolder {
                pid: 1,
                started_at: "a b".into(),
            },
        ] {
            assert!(!holder_is_valid(&bad), "{bad:?}");
        }
        for (state, wire) in [
            (HolderState::Alive, "\"alive\""),
            (HolderState::Exited, "\"exited\""),
            (HolderState::Unknown, "\"unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
            assert_eq!(serde_json::from_str::<HolderState>(wire).unwrap(), state);
        }
    }
}
