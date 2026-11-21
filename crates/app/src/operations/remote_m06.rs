//! ⟨M06⟩ ADR-0006 revision 6 (§18; ADR-0012 §9 item 6): the fail-closed landing of the
//! revision-6 request forms (`Request::{RemoteEnvironment, Device, Route, Transport,
//! Runner}`).
//!
//! Wave 0 serves none of them. A session never reaches this: their capabilities
//! (`remote-control/1`, `routes/1`, `transport-iroh/1`, `runner/1`) are declared and not
//! offered, so the IPC session answers `SCHEMA_UNSUPPORTED` before dispatch. A caller
//! that reaches the application in process gets `CAPABILITY_UNAVAILABLE` with reason
//! `driver_unavailable` before anything is read or written: no operation, idempotency
//! row, decision record or event. The answer is the same for every role, so it tells a
//! limited caller nothing it could not learn from the capability list. The M06 units
//! (m06-plan U1–U5) replace it form by form.

use heimdall_contract::Code;
use heimdall_contract::envelope::EffectStatus;
use heimdall_contract::request::Request;

use crate::{Caller, OpError, OpResult, Operations};

/// The wave-0 refusal of a revision-6 form; `None` for every other request.
#[must_use]
pub fn revision_6_refusal(request: &Request) -> Option<OpError> {
    request.is_revision_6().then(|| {
        OpError::driver_unavailable(&format!(
            "`{}` is not available in this runtime (ADR-0006 revision 6, planned for M06)",
            request.kind()
        ))
    })
}

/// ⟨M06 W2⟩ The application's answer to `Decide` on a runner-local widening record
/// (`DecisionKind::RemoteWidening`, ADR-0012 §3.10): such a record is decided only through
/// the runner runtime's runner-local path, which runs the exact recorded request once and
/// records its terminal result. Reaching the application's decide path, it is refused
/// `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) with nothing written: the record stays
/// pending, not consumed.
#[must_use]
pub fn remote_widening_not_here() -> OpError {
    OpError::driver_unavailable(
        "this decision is a runner-local widening record; it is decided by the runner runtime",
    )
    .with_effect(EffectStatus::None)
}

impl Operations {
    /// ⟨M06⟩ A revision-6 request reached in process (module docs): refused
    /// `driver_unavailable` before any record is written. Any other request is a caller
    /// error (`USAGE_ERROR`), also with nothing written.
    ///
    /// # Errors
    /// Always, in wave 0.
    #[allow(clippy::unused_async)]
    pub async fn revision_6_request(
        &self,
        _caller: &Caller,
        request: &Request,
    ) -> OpResult<serde_json::Value> {
        Err(revision_6_refusal(request).unwrap_or_else(|| {
            OpError::new(Code::UsageError, "not a revision-6 request")
                .with_effect(EffectStatus::None)
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Every revision-6 form is refused `CAPABILITY_UNAVAILABLE` / `driver_unavailable`
    /// with effect `none`; no earlier form is.
    #[test]
    fn only_revision_6_forms_are_refused() {
        let forms = [
            r#"{"op":"remote_environment","action":"status"}"#,
            r#"{"op":"device","action":"retire"}"#,
            r#"{"op":"transport","action":"disable"}"#,
            r#"{"op":"runner","action":"authority_report"}"#,
            r#"{"op":"route","action":"remove","destination":"d","route":"route_01"}"#,
        ];
        for text in forms {
            let r: Request = serde_json::from_str(text).unwrap();
            let e = revision_6_refusal(&r).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(e.code, Code::CapabilityUnavailable, "{text}");
            assert_eq!(
                e.reason.as_deref(),
                Some(heimdall_contract::envelope::reason::DRIVER_UNAVAILABLE)
            );
            assert_eq!(e.effect_status, EffectStatus::None);
        }
        let shutdown: Request = serde_json::from_str(r#"{"op":"shutdown"}"#).unwrap();
        assert!(revision_6_refusal(&shutdown).is_none());
    }
}
