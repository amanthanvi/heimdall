//! Bounded lifecycles (ADR-0012 §1 item 5; G06 §3's two probe defects).
//!
//! * **Endpoint close is bounded** at [`CLOSE_BOUND`] (1 s). An unbounded `close().await`
//!   after a peer-closed connection held the probe's ProxyCommand, and so ssh, open until
//!   ssh's `ConnectTimeout` (G06 S03, first run). Every close in this crate goes through
//!   [`bounded`].
//! * **Nothing here reads stdin.** The dial and serve futures depend on no standard stream,
//!   so they never hold a runtime open. The future `heimdall transport connect` CLI leg
//!   copies stdin and stdout itself, and tokio's stdin reader is a blocking thread that a
//!   plain runtime drop waits for while ssh still holds the pipe open (G06 S03: a refused
//!   connection held ssh until its 30 s `ConnectTimeout`). **That leg must end its runtime
//!   with `tokio::runtime::Runtime::shutdown_background`**, never a plain drop, and it
//!   carries its own regression test (W3).
//! * **Exit and failure classes are internal.** This crate defines no process exit codes:
//!   failures are typed ([`crate::policy::PolicyError`], the dial and serve errors) and map
//!   to the contract's reason tokens and `RouteFailureClass`; ssh reports a ProxyCommand
//!   failure with its own exit (ADR-0012 §1 item 5, R08).
//!
//! Application close codes on `/pigeons/0` (the dialer reads them back as a structured
//! cause; [`CLOSE_REFUSED`] is Pigeons' own refusal code, as the probe used).

use std::future::Future;
use std::time::Duration;

/// The bound on closing an endpoint (ADR-0012 §1 item 5).
pub const CLOSE_BOUND: Duration = Duration::from_secs(1);

/// The bound on waiting for closed sessions to end before a suspend is acknowledged or a
/// lease loss completes. Past it the acknowledgement says `complete: false`.
pub const SESSION_DRAIN_BOUND: Duration = Duration::from_secs(1);

/// How often a running server re-reads its lease, so a lease reported lost or moved to an
/// unacknowledged generation closes every stream within this interval even when no
/// connection arrives (it is also checked on every admission and every signal).
pub const LEASE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Normal end of a session or of the server.
pub const CLOSE_DONE: u32 = 0;
/// Admission refused before any byte was forwarded (allowlist, authority, suspension or
/// lease): Pigeons' refusal code.
pub const CLOSE_REFUSED: u32 = 403;
/// Admission withdrawn by the authority: a suspended (revoked) endpoint's live stream.
pub const CLOSE_REVOKED: u32 = 410;
/// The loopback target could not be reached.
pub const CLOSE_TARGET_UNAVAILABLE: u32 = 502;
/// The lease was lost (for good, or by an unacknowledged generation change): every stream
/// closed at once.
pub const CLOSE_LEASE_LOST: u32 = 503;

/// Runs `fut` for at most `bound`. Returns `Some(output)` if it finished in time, `None` if
/// the bound passed (the future is dropped).
pub async fn bounded<F: Future>(bound: Duration, fut: F) -> Option<F::Output> {
    tokio::time::timeout(bound, fut).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (ADR-0012 §1 item 5): a close that never completes returns at the bound.
    #[tokio::test]
    async fn bounded_returns_at_the_bound_for_a_close_that_never_completes() {
        let start = tokio::time::Instant::now();
        let out = bounded(CLOSE_BOUND, std::future::pending::<()>()).await;
        let took = start.elapsed();
        assert!(out.is_none());
        assert!(took >= CLOSE_BOUND, "{took:?}");
        assert!(took < CLOSE_BOUND + Duration::from_millis(500), "{took:?}");
        assert_eq!(bounded(CLOSE_BOUND, async { 5 }).await, Some(5));
    }
}
