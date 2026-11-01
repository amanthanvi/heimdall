//! Per-session caller context (ADR-0006 §2.1, §3.1; review F03).
//!
//! The authenticated [`CallerContext`] (OS principal + role) is what authorization
//! and idempotency key on. **Attendance** is a property of the control session,
//! established by the runtime: a session whose hello declared `interactive` and
//! that then sent `Attend` is attended; a `non_interactive` session can never be.
//! Attendance is **not** the confirmation of any action (ADR-0006 §3.1, §13.4
//! N04): widening actions and added authority always create a decision record, and
//! only `decide` on an attended session completes one; the client must show the
//! exact recorded action and obtain a typed `yes` before sending it, which the
//! server cannot verify.
//! Within the same OS user a program can imitate the terminal flow (spec §13.2,
//! §14.2: a compromised owner session is out of scope); this limit is disclosed in
//! setup and documentation, not hidden behind a client-supplied flag.

use heimdall_contract::Timestamp;
use heimdall_contract::request::InteractionMode;
use heimdall_domain::principal::CallerContext;

/// Whether the runtime has marked the session as owner-present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attendance {
    /// Not attended: decisions and time confirmation are refused with
    /// `INTERACTION_REQUIRED`; widening actions get a decision record and
    /// `INTERACTION_REQUIRED` with `next.decision_ref`.
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

    /// Whether `decide`/`confirm_time` may be accepted on this session. Never
    /// sufficient by itself to execute a widening action (N04).
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
