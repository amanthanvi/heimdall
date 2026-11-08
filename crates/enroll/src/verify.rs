//! The production verification (ADR-0008 D5 §6.5; m03-plan U5
//! `enroll::verify::Verifier`): two fresh logins (positive and negative certificates)
//! through the operation's verification endpoint, with the generated configuration
//! and known-hosts file from the approved target and the full host-trust pins, the
//! destination clock measurement, and the `-v` trace parsed through
//! [`crate::trace`]. U5 makes it implement `app::ports::VerificationRunner`.
//!
//! **Wave 0:** [`Verifier`] is a skeleton that implements no port, so the runtime has
//! no verification runner to register; every verification is refused before it
//! starts (`CAPABILITY_UNAVAILABLE`, `driver_unavailable`), and the domain's
//! `verification::classify` answers inconclusive.

/// The production verification runner (U5 fills it).
#[derive(Debug, Default)]
pub struct Verifier {
    _private: (),
}

impl Verifier {
    /// A verifier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this build can run a production verification. **Wave 0:** `false`.
    #[must_use]
    pub fn available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave0_verifier_is_unavailable() {
        assert!(!Verifier::new().available());
    }
}
