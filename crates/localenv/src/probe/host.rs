//! The `host_verification` level: verify the host key through the real tree, offering
//! nothing to sign (m02-plan U3). Needs `allow_config_commands`.
//!
//! `ssh -o BatchMode=yes -o PreferredAuthentications=none -o IdentityAgent=none -o
//! IdentityFile=none -o ControlMaster=no -o ControlPath=none <alias>` (ADR-0007 §6):
//! with no agent, no identity file and no authentication method, ssh has nothing to
//! sign with. The result is classified from the exit status (F11) and bounded stderr
//! markers:
//!
//! * `Host key verification failed` with `REMOTE HOST IDENTIFICATION HAS CHANGED` (or
//!   `has changed`): the known key does not match (`known_host_mismatch`,
//!   `HOST_TRUST_CHANGED`);
//! * `Host key verification failed` otherwise: no known key (`known_host_missing`);
//! * authentication refused after the key exchange (`Permission denied`, `No more
//!   authentication methods`, `Too many authentication failures`), or exit 0: the host
//!   key was verified;
//! * anything else: the destination was not reached (`DESTINATION_UNREACHABLE`).

use heimdall_contract::code::Code;
use heimdall_contract::doctor::{ProbeOutcome, ProbeRecord};
use heimdall_contract::provider::ProbeLevel;

use super::ProbeContext;

/// The `ssh` options of the level, in order, before the alias.
pub const HOST_VERIFICATION_ARGS: &[&str] = &[
    "-o",
    "BatchMode=yes",
    "-o",
    "PreferredAuthentications=none",
    "-o",
    "IdentityAgent=none",
    "-o",
    "IdentityFile=none",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
];

/// What host verification established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostVerification {
    /// The host key matched a known key.
    Verified,
    /// No known key for the host.
    Missing,
    /// A known key exists and the host presented another.
    Mismatch,
    /// The host was not reached.
    Unreachable,
}

/// Verify the host key of `alias`.
#[must_use]
pub fn verify(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    verify_observed(ctx, alias).0
}

/// [`verify`], with the classification when the child ran to completion.
#[must_use]
pub fn verify_observed(
    ctx: &ProbeContext<'_>,
    alias: &str,
) -> (ProbeRecord, Option<HostVerification>) {
    let run = super::run_real_tree(
        ctx,
        ProbeLevel::HostVerification,
        alias,
        HOST_VERIFICATION_ARGS,
        &[],
        &|_| None,
    );
    let mut record = run.record;
    let Some(finished) = run.finished else {
        return (record, None);
    };
    if record.outcome != ProbeOutcome::Ok {
        return (record, None);
    }
    let exit = finished.status.and_then(|s| s.code());
    let class = classify(exit, &finished.stderr);
    match class {
        HostVerification::Verified => {}
        HostVerification::Missing => {
            // No trust was changed: there is none yet (`known_host_missing`).
            record.outcome = ProbeOutcome::Failed;
        }
        HostVerification::Mismatch => {
            record.outcome = ProbeOutcome::Failed;
            record.code = Some(Code::HostTrustChanged);
        }
        HostVerification::Unreachable => {
            record.outcome = ProbeOutcome::Failed;
            record.code = Some(Code::DestinationUnreachable);
        }
    }
    (record, Some(class))
}

/// Classify an exit status and stderr (module documentation).
#[must_use]
pub fn classify(exit: Option<i32>, stderr: &[u8]) -> HostVerification {
    let text = String::from_utf8_lossy(stderr);
    if text.contains("Host key verification failed") {
        if text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") || text.contains("has changed") {
            return HostVerification::Mismatch;
        }
        return HostVerification::Missing;
    }
    if exit == Some(0)
        || text.contains("Permission denied")
        || text.contains("No more authentication methods")
        || text.contains("Too many authentication failures")
    {
        return HostVerification::Verified;
    }
    HostVerification::Unreachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_follows_the_markers() {
        assert_eq!(
            classify(
                Some(255),
                b"x@127.0.0.1: Permission denied (publickey).\r\n"
            ),
            HostVerification::Verified
        );
        assert_eq!(
            classify(
                Some(255),
                b"No ED25519 host key is known for [127.0.0.1]:2 and you have requested strict checking.\r\nHost key verification failed.\r\n"
            ),
            HostVerification::Missing
        );
        assert_eq!(
            classify(
                Some(255),
                b"@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nHost key verification failed.\n"
            ),
            HostVerification::Mismatch
        );
        assert_eq!(
            classify(
                Some(255),
                b"ssh: connect to host 127.0.0.1 port 1: Connection refused\r\n"
            ),
            HostVerification::Unreachable
        );
        assert_eq!(classify(Some(0), b""), HostVerification::Verified);
    }
}
