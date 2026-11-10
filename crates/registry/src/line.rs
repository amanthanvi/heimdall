//! The registry line and its marker (ADR-0008 D5 §6.1; m03-plan U5 "Interfaces").
//!
//! The line is `cert-authority,principals="hm:<destination-id>:<account>" <K_ca
//! public> heimdall:<enrollment-id>`. Its character set is
//! `[A-Za-z0-9+/=,:" ._@-]` (no `'`, so a single-quoted script literal holds it).
//!
//! Signatures frozen in wave 0 (U0). [`marker`] is the domain's rule; the body of
//! [`expected_line`] is U5's and **fails closed in wave 0**
//! ([`LineError::Unavailable`]).

use heimdall_contract::ids::EnrollmentId;

/// The registry line's permitted characters (ADR-0008 D5 §6.3).
pub const LINE_CHARSET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=,:\" ._@-";

/// Why no line was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum LineError {
    /// The line builder is not in this build (wave 0; U5 fills it).
    #[error("the registry line builder is not available in this build")]
    Unavailable,
    /// A component is outside [`LINE_CHARSET`] or malformed (`principal_charset`).
    #[error("a registry line component is outside the permitted character set")]
    Charset,
}

/// The marker of an enrollment, `heimdall:<enrollment-id>`
/// (`heimdall_domain::enrollment::marker_for`).
#[must_use]
pub fn marker(id: &EnrollmentId) -> String {
    heimdall_domain::enrollment::marker_for(id)
}

/// The exact registry line for `ca_public` (an OpenSSH public key line), `principal`
/// (`hm:<destination-id>:<account>`) and `marker`.
///
/// **Wave 0:** refuses with [`LineError::Unavailable`].
pub fn expected_line(ca_public: &str, principal: &str, marker: &str) -> Result<String, LineError> {
    let _ = (ca_public, principal, marker);
    Err(LineError::Unavailable)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn charset_has_no_single_quote_and_line_fails_closed() {
        assert!(!LINE_CHARSET.contains('\''));
        assert_eq!(
            expected_line("ssh-ed25519 AAAA", "hm:dst:acct", "heimdall:enr_x"),
            Err(LineError::Unavailable)
        );
    }
}
