//! The client trace patterns (ADR-0008 D5 §6.5 item 5, §17.4 item 11; m03-plan U5
//! `enroll::trace::patterns_for(family, version)`, `trace_patterns_keyed_by_release_family`).
//!
//! The production verification reads the `-v` trace of each attempt for six events
//! ([`heimdall_domain::verification::TraceEvents`]). How a client spells them is not
//! documented, so the patterns are **keyed by upstream release family** and carry only
//! the version ranges **recorded from real runs** (M-F22):
//! * [`ClientFamily::Portable`]: OpenSSH portable and the distribution builds of it;
//! * [`ClientFamily::Win32`]: Win32-OpenSSH (`OpenSSH_for_Windows_…`).
//!
//! A client outside every recorded range has no patterns: [`patterns_for`] returns
//! [`UnrecordedClient`], every verification result is inconclusive, and the doctor
//! reports [`UNRECORDED_FINDING`] naming the family and the version.
//!
//! **Recorded rows** ([`RECORDED`]). Only what a real run observed:
//! * portable `10.5p1` (the macOS build host's `/usr/bin/ssh`, `OpenSSH_10.5p1,
//!   LibreSSL 3.3.6`), observed by `integration_enroll_verify` against a loopback
//!   `sshd` 10.5p1 (positive accepted, negative refused, host key matched);
//! * portable `9.6p1` (the Linux devbox's `OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL
//!   3.0.13 30 Jan 2024`), observed in two devbox runs against a loopback `sshd` of the
//!   same build: at `5b36b3d8`, `verify_positive_one_signature_negative_zero`'s
//!   `m03 observation: client_trace_row` lines (positive accepted with one signature,
//!   negative refused with none, host key matched); then, on the round-4 tree,
//!   `verification_host_key_mismatch_holds_no_rollback`'s `… field=host_key_failure`
//!   lines (both attempts against a changed host key, exit 255). Its
//!   [`TracePatterns::host_key_failure`] set holds only that changed-key path's lines;
//!   the unknown-host lines (`No … host key is known for`) were not observed on 9.6p1
//!   and are not in it.
//!
//! The Windows clients are **not recorded** until their native runs (the orchestrator's
//! rows); they are inconclusive until then, never assumed.
//!
//! [`parse`] extracts the events with one family's patterns. It is bounded by the
//! caller (`verification_trace_max`, 64 KiB) and reads nothing else.

use std::fmt;

use heimdall_domain::verification::TraceEvents;

/// The doctor finding for a client whose trace is not recorded (ADR-0008 D5 §6.5 item
/// 5).
pub const UNRECORDED_FINDING: &str = "client_trace_family_unrecorded";

/// An upstream release family (ADR-0008 §17.4 item 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ClientFamily {
    /// OpenSSH portable and its distribution builds (`OpenSSH_<v>`).
    Portable,
    /// Win32-OpenSSH (`OpenSSH_for_Windows_<v>`).
    Win32,
}

impl ClientFamily {
    /// The stable name (`portable`, `win32`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClientFamily::Portable => "portable",
            ClientFamily::Win32 => "win32",
        }
    }
}

/// A client's version as `ssh -V` prints it (`OpenSSH_10.5p1, …`,
/// `OpenSSH_for_Windows_9.5p2, …`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientVersion {
    /// The release family.
    pub family: ClientFamily,
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// The portable release (`p1`), when printed.
    pub portable: Option<u16>,
}

impl ClientVersion {
    /// Parse the first `OpenSSH_<major>.<minor>[p<n>]` or
    /// `OpenSSH_for_Windows_<major>.<minor>[p<n>]` in `text` (the output of `ssh -V`).
    #[must_use]
    pub fn parse(text: &str) -> Option<ClientVersion> {
        let start = text.find("OpenSSH_")? + "OpenSSH_".len();
        let rest = text.get(start..)?;
        let (family, rest) = match rest.strip_prefix("for_Windows_") {
            Some(r) => (ClientFamily::Win32, r),
            None => (ClientFamily::Portable, rest),
        };
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == 'p'))
            .unwrap_or(rest.len());
        let v = rest.get(..end)?;
        let (numbers, portable) = match v.split_once('p') {
            Some((n, p)) => (n, Some(p.parse().ok()?)),
            None => (v, None),
        };
        let (major, minor) = numbers.split_once('.')?;
        Some(ClientVersion {
            family,
            major: major.parse().ok()?,
            minor: minor.parse().ok()?,
            portable,
        })
    }
}

impl fmt::Display for ClientVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)?;
        if let Some(p) = self.portable {
            write!(f, "p{p}")?;
        }
        Ok(())
    }
}

/// A client whose family or version has no recorded patterns: every verification
/// result is inconclusive, and the doctor names it (ADR-0008 D5 §6.5 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("client_trace_family_unrecorded: {} {version}", .version.family.as_str())]
pub struct UnrecordedClient {
    /// The client's version (its family included).
    pub version: ClientVersion,
}

impl UnrecordedClient {
    /// The doctor finding's code ([`UNRECORDED_FINDING`]).
    #[must_use]
    pub fn finding(&self) -> &'static str {
        UNRECORDED_FINDING
    }

    /// The finding's text: the family and the version, nothing else.
    #[must_use]
    pub fn detail(&self) -> String {
        format!("{} {}", self.version.family.as_str(), self.version)
    }
}

/// One family's trace patterns for a recorded version range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TracePatterns {
    /// The family.
    pub family: ClientFamily,
    /// The lowest recorded version (inclusive).
    pub from: ClientVersion,
    /// The highest recorded version (inclusive).
    pub to: ClientVersion,
    /// Where the run was recorded (no host or user names).
    pub evidence: &'static str,
    /// `<prefix><server software version>`.
    pub server_version: &'static str,
    /// `<prefix>'<HostKeyAlias>'<suffix>`: the approved key matched under the alias.
    pub host_key_matched: (&'static str, &'static str),
    /// `<prefix>… <TYPE>-CERT <fingerprint> …`: the certificate was offered.
    pub offered: &'static str,
    /// `<prefix>… <TYPE>-CERT <fingerprint> …`: the server accepted it.
    pub accepted: &'static str,
    /// `<prefix>publickey…`: the server answered that public-key authentication may
    /// continue (after an offer, with no acceptance: not accepted).
    pub can_continue: &'static str,
    /// `…<suffix>`: the run ended with a public-key authentication failure.
    pub publickey_failure: &'static str,
    /// Lines that show a host-key verification failure (not an event of the
    /// classification table's trace set; reported by the Verifier separately).
    pub host_key_failure: &'static [&'static str],
}

const fn v(family: ClientFamily, major: u16, minor: u16, portable: u16) -> ClientVersion {
    ClientVersion {
        family,
        major,
        minor,
        portable: Some(portable),
    }
}

/// Every recorded row (module documentation).
pub const RECORDED: &[TracePatterns] = &[
    TracePatterns {
        family: ClientFamily::Portable,
        from: v(ClientFamily::Portable, 10, 5, 1),
        to: v(ClientFamily::Portable, 10, 5, 1),
        evidence: "integration_enroll_verify on the macOS build host (/usr/bin/ssh OpenSSH_10.5p1 \
               against a loopback sshd OpenSSH_10.5p1), M03 wave 1",
        server_version: "debug1: Remote protocol version 2.0, remote software version ",
        host_key_matched: ("debug1: Host ", " is known and matches the "),
        offered: "debug1: Offering public key: ",
        accepted: "debug1: Server accepts key: ",
        can_continue: "debug1: Authentications that can continue: ",
        publickey_failure: ": Permission denied (publickey).",
        host_key_failure: &[
            "Host key verification failed.",
            "REMOTE HOST IDENTIFICATION HAS CHANGED",
            "No ED25519 host key is known for",
            "No ECDSA host key is known for",
            "No RSA host key is known for",
        ],
    },
    // Observed on the devbox in two wave-1 native runs (the redacted logs'
    // `m03 observation: client_trace_row family=portable version=9.6p1` lines). Each
    // string below is a prefix, suffix or substring of one observed line; nothing is
    // inferred.
    //
    // First run, observed on the devbox, `5b36b3d8` (all fields but host_key_failure):
    // * "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1
    //   Ubuntu-3ubuntu13.20" (both attempts);
    // * "debug1: Host 'hm-verify-…' is known and matches the ED25519 host key." (both);
    // * "debug1: Offering public key: <scratch>/…/positive-cert.pub ED25519-CERT
    //   SHA256:… explicit" (the negative offered its certificate and `k_verify.pub
    //   ED25519 SHA256:… explicit agent`);
    // * "debug1: Server accepts key: <scratch>/…/positive-cert.pub ED25519-CERT SHA256:…
    //   explicit" (positive only);
    // * "debug1: Authentications that can continue: publickey" (positive once, negative
    //   three times);
    // * "<user>@127.0.0.1: Permission denied (publickey)." (negative's last line).
    // Parsed with these strings, that run gave positive {accepted, 1 signature, exit 0}
    // and negative {not accepted, 0 signatures, exit 255}.
    //
    // Second run, observed on the devbox on the round-4 tree (uncommitted over
    // `5b36b3d8`; `HM_ONLY="integration_enroll_verify heimdall_enroll-unit"`, 2026-11-10):
    // `verification_host_key_mismatch_holds_no_rollback`'s `… field=host_key_failure`
    // lines, both attempts against a changed host key, both exit 255, each printing:
    // * "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @";
    // * "Host key for hm-verify-… has changed and you have requested strict checking.";
    // * "Host key verification failed." (each attempt's last line).
    // Only this changed-key path was observed: the unknown-host lines the 10.5p1 row
    // also carries (`No … host key is known for`) are not recorded for 9.6p1.
    TracePatterns {
        family: ClientFamily::Portable,
        from: v(ClientFamily::Portable, 9, 6, 1),
        to: v(ClientFamily::Portable, 9, 6, 1),
        evidence: "integration_enroll_verify on the Linux devbox (OpenSSH_9.6p1 \
                   Ubuntu-3ubuntu13.20 client against a loopback sshd of the same build), M03 \
                   wave 1: verify_positive_one_signature_negative_zero at 5b36b3d8; \
                   verification_host_key_mismatch_holds_no_rollback on the round-4 tree \
                   (changed host key only)",
        server_version: "debug1: Remote protocol version 2.0, remote software version ",
        host_key_matched: ("debug1: Host ", " is known and matches the "),
        offered: "debug1: Offering public key: ",
        accepted: "debug1: Server accepts key: ",
        can_continue: "debug1: Authentications that can continue: ",
        publickey_failure: ": Permission denied (publickey).",
        host_key_failure: &[
            "Host key verification failed.",
            "REMOTE HOST IDENTIFICATION HAS CHANGED",
            " has changed and you have requested strict checking.",
        ],
    },
];

/// The patterns for `family` at `version`: the recorded row whose range holds it.
///
/// # Errors
/// [`UnrecordedClient`] for a family or version outside every recorded range (and a
/// `version` whose own family is not `family`).
pub fn patterns_for(
    family: ClientFamily,
    version: ClientVersion,
) -> Result<&'static TracePatterns, UnrecordedClient> {
    if version.family != family {
        return Err(UnrecordedClient { version });
    }
    RECORDED
        .iter()
        .find(|p| p.family == family && p.from <= version && version <= p.to)
        .ok_or(UnrecordedClient { version })
}

/// What [`parse`] matches against, for one attempt.
#[derive(Debug, Clone, Copy)]
pub struct TraceContext<'a> {
    /// The generated `HostKeyAlias`.
    pub host_key_alias: &'a str,
    /// The certificate's key type as the trace prints it (`ED25519-CERT`).
    pub cert_type: &'a str,
    /// K_verify's fingerprint (`SHA256:…`).
    pub key_fingerprint: &'a str,
}

/// The events of one attempt's trace, and whether the trace shows a host-key
/// verification failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedTrace {
    /// The classification table's events.
    pub events: TraceEvents,
    /// A host-key verification failure was printed.
    pub host_key_failure: bool,
}

/// Extract one attempt's events with `patterns` (module documentation).
#[must_use]
pub fn parse(patterns: &TracePatterns, trace: &str, ctx: &TraceContext<'_>) -> ParsedTrace {
    let mut out = ParsedTrace::default();
    let cert_marker = format!(" {} {}", ctx.cert_type, ctx.key_fingerprint);
    let alias = format!("'{}'", ctx.host_key_alias);
    let mut offered = false;
    for raw in trace.lines() {
        let line = raw.trim_end_matches('\r');
        if out.events.server_version.is_none()
            && let Some(rest) = line.strip_prefix(patterns.server_version)
        {
            let version = rest.trim();
            if !version.is_empty() && version.len() <= 256 {
                out.events.server_version = Some(version.to_owned());
            }
            continue;
        }
        let (hk_prefix, hk_suffix) = patterns.host_key_matched;
        if let Some(rest) = line.strip_prefix(hk_prefix)
            && rest.starts_with(&alias)
            && rest[alias.len()..].starts_with(hk_suffix)
        {
            out.events.host_key_matched = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix(patterns.offered) {
            if rest.contains(&cert_marker) {
                out.events.offered_certificate = true;
                offered = true;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix(patterns.accepted) {
            if rest.contains(&cert_marker) {
                out.events.accepted = true;
            }
            continue;
        }
        if offered
            && let Some(rest) = line.strip_prefix(patterns.can_continue)
            && rest.split(',').any(|m| m.trim() == "publickey")
        {
            out.events.not_accepted = true;
            continue;
        }
        if line.ends_with(patterns.publickey_failure) {
            out.events.publickey_failure_final = true;
            continue;
        }
        if patterns.host_key_failure.iter().any(|p| line.contains(p)) {
            out.host_key_failure = true;
        }
    }
    if out.events.accepted {
        // An acceptance after the offer is never "not accepted".
        out.events.not_accepted = false;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_with_their_family() {
        let p = ClientVersion::parse("OpenSSH_10.5p1, LibreSSL 3.3.6").unwrap();
        assert_eq!(p, v(ClientFamily::Portable, 10, 5, 1));
        assert_eq!(p.to_string(), "10.5p1");
        let w = ClientVersion::parse("OpenSSH_for_Windows_9.5p2, LibreSSL 3.4.3").unwrap();
        assert_eq!(w, v(ClientFamily::Win32, 9, 5, 2));
        let n = ClientVersion::parse("OpenSSH_9.6, OpenSSL").unwrap();
        assert_eq!(n.portable, None);
        assert!(ClientVersion::parse("PuTTY 0.80").is_none());
        assert!(ClientVersion::parse("OpenSSH_x").is_none());
    }

    #[test]
    fn only_recorded_rows_have_patterns() {
        let p = patterns_for(ClientFamily::Portable, v(ClientFamily::Portable, 10, 5, 1)).unwrap();
        assert_eq!(p.family, ClientFamily::Portable);
        let d = patterns_for(ClientFamily::Portable, v(ClientFamily::Portable, 9, 6, 1)).unwrap();
        assert_eq!(d.from, v(ClientFamily::Portable, 9, 6, 1));
        // A recorded row recognizes a host-key failure (else that failure would be
        // transport-inconclusive on its client).
        for row in RECORDED {
            assert!(!row.host_key_failure.is_empty(), "{}", row.evidence);
        }
        for unrecorded in [
            v(ClientFamily::Portable, 9, 7, 1),
            v(ClientFamily::Portable, 9, 5, 1),
            v(ClientFamily::Portable, 10, 3, 1),
            v(ClientFamily::Portable, 10, 6, 1),
            v(ClientFamily::Win32, 10, 5, 1),
            v(ClientFamily::Win32, 9, 5, 2),
        ] {
            let e = patterns_for(unrecorded.family, unrecorded).unwrap_err();
            assert_eq!(e.version, unrecorded);
            assert_eq!(e.finding(), UNRECORDED_FINDING);
        }
        // A family that does not match the version is never borrowed from another row.
        assert!(patterns_for(ClientFamily::Win32, v(ClientFamily::Portable, 10, 5, 1)).is_err());
    }

    /// The 9.6p1 row's host-key-failure strings each come from a line the devbox's
    /// second run printed (`verification_host_key_mismatch_holds_no_rollback`, one
    /// attempt's non-debug and host-key lines, redacted: `<scratch>`, `<fp>`), and that
    /// trace parses as a host-key failure with no other event.
    #[test]
    fn devbox_9_6p1_changed_host_key_trace_is_a_host_key_failure() {
        const OBSERVED: &str = "\
OpenSSH_9.6p1 Ubuntu-3ubuntu13.20, OpenSSL 3.0.13 30 Jan 2024
debug1: kex: host key algorithm: ssh-ed25519
debug1: Server host key: ssh-ed25519 SHA256:<fp>
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:<fp>.
Please contact your system administrator.
Add correct host key in <scratch>/rt8/v/d305cf3ae650b76e/known_hosts to get rid of this message.
Offending ED25519 key in <scratch>/rt8/v/d305cf3ae650b76e/known_hosts:1
  remove with:
  ssh-keygen -f '<scratch>/rt8/v/d305cf3ae650b76e/known_hosts' -R 'hm-verify-d305cf3ae650b76e'
Host key for hm-verify-d305cf3ae650b76e has changed and you have requested strict checking.
Host key verification failed.
";
        let p = patterns_for(ClientFamily::Portable, v(ClientFamily::Portable, 9, 6, 1)).unwrap();
        for s in p.host_key_failure {
            assert!(
                OBSERVED.lines().any(|l| l.contains(s)),
                "{s:?} was not observed"
            );
        }
        let ctx = TraceContext {
            host_key_alias: "hm-verify-d305cf3ae650b76e",
            cert_type: "ED25519-CERT",
            key_fingerprint: "SHA256:<fp>",
        };
        let parsed = parse(p, OBSERVED, &ctx);
        assert!(parsed.host_key_failure);
        assert_eq!(parsed.events, TraceEvents::default());
    }
}
