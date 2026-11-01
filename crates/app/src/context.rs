//! Per-session caller context (ADR-0006 §2.1, §3.1; review F03).
//!
//! The authenticated [`CallerContext`] (OS principal + role) is what authorization
//! and idempotency key on. **Attendance** is a property of the control session,
//! established by the runtime: a session whose hello declared `interactive` and
//! that then sent `Attend` is attended; a `non_interactive` session can never be.
//! Within the same OS user a program can imitate the terminal flow (spec §13.2,
//! §14.2: a compromised owner session is out of scope); this limit is disclosed in
//! setup and documentation, not hidden behind a client-supplied flag.

use heimdall_contract::Timestamp;
use heimdall_contract::request::InteractionMode;
use heimdall_domain::principal::CallerContext;

/// Whether the runtime has marked the session as owner-present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attendance {
    /// Not attended: widening actions, decisions and time confirmation are refused
    /// with `INTERACTION_REQUIRED`.
    Unattended,
    /// Attended since `since` (runtime clock) through the interactive flow.
    Attended {
        /// When the runtime accepted `Attend`.
        since: Timestamp,
    },
}

/// Everything the application layer knows about the caller of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Authenticated principal and role (idempotency namespace).
    pub context: CallerContext,
    /// Session attendance as established by the runtime.
    pub attendance: Attendance,
    /// Interaction mode the session declared in its hello.
    pub interaction: InteractionMode,
}

impl Caller {
    /// An unattended, non-interactive caller (the default for API callers).
    #[must_use]
    pub fn unattended(context: CallerContext) -> Self {
        Self {
            context,
            attendance: Attendance::Unattended,
            interaction: InteractionMode::NonInteractive,
        }
    }

    /// Whether owner-present actions may proceed on this session.
    #[must_use]
    pub fn is_attended(&self) -> bool {
        matches!(self.attendance, Attendance::Attended { .. })
    }

    /// Whether the session may be promoted to attended (`Attend` accepted): only
    /// sessions that declared `interactive`.
    #[must_use]
    pub fn may_attend(&self) -> bool {
        self.interaction == InteractionMode::Interactive
    }
}
