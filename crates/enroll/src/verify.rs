//! The production verification (ADR-0008 D5 §6.5; m03-plan U5 `enroll::verify::Verifier`).
//!
//! [`Verifier`] implements `app::ports::VerificationRunner`: two fresh logins, the
//! positive and the negative certificate, through the operation's verification
//! endpoint ([`VerificationSession`]), with **a generated configuration**, never the
//! user's (M-F4):
//!
//! * `<runtime_dir>/v/<16 hex>/` (owner-only) holds `ssh_config`, `known_hosts` (one
//!   plain line: `hm-verify-<16 hex>` and the **approved** host key), an empty
//!   `global_known_hosts`, K_verify's public key and the two certificates. The directory
//!   is removed when the run ends, and when its future is dropped.
//! * The configuration is `Host hm-verify` with `HostName`, `Port` and `User` from the
//!   plan's approved target, `HostKeyAlias hm-verify-<16 hex>`, the full host-trust pin
//!   set of D5 §6.3 (`UserKnownHostsFile`, `GlobalKnownHostsFile`, `KnownHostsCommand
//!   none`, `VerifyHostKeyDNS no`, `HostKeyAlgorithms` = the approved key's,
//!   `StrictHostKeyChecking yes`, `CheckHostIP no`, `UpdateHostKeys no`,
//!   `NoHostAuthenticationForLocalhost no`, `CanonicalizeHostname no`),
//!   `ForkAfterAuthentication no`, `IdentityAgent` = **the session's locator**,
//!   `IdentitiesOnly yes`, `IdentityFile <K_verify.pub>`, `CertificateFile <the
//!   attempt's certificate>`, public key only, `BatchMode yes`, no multiplexing, no
//!   proxy, no forwarding, `RequestTTY no`, `ConnectTimeout 20` ([`generated_config`]).
//! * Each attempt is `<client> -F <ssh_config> -v -T hm-verify <MEASURE_COMMAND>`, with
//!   `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` removed
//!   from its environment, stdout and stderr read concurrently and bounded (stderr: the
//!   64 KiB `verification_trace_max`), killed on drop and at [`ATTEMPT_TIMEOUT`].
//! * Each certificate is installed in the session ([`VerificationSession::install`])
//!   **just before its attempt**, and the attempt's signatures are the session's count
//!   for K_verify's fingerprint after the attempt minus before it.
//! * **The destination clock** (item 4) is measured in the positive login:
//!   `behind_upper_ms = max(0, t₂ − T + 1 s)`, `rtt_ms = t₂ − t₁`.
//! * **The trace** (item 5) is parsed through [`crate::trace::patterns_for`]. A client
//!   whose family or version is unrecorded runs **no** attempt: the result is
//!   inconclusive and [`VerifierReport::unrecorded`] names it for the doctor.
//! * `log_attestation` is [`LogAttestation::Unavailable`] (ADR-0005 §3.3).
//!
//! The outcome classification is `heimdall_domain::verification::classify` (ADR-0008
//! §17.17 item 14, U5IO-Q4: the D5 §6.5 table). The port's outcome carries what it
//! needs: each attempt's trace has `host_key_failure`, and
//! `VerificationOutcome::unrecorded` names an unrecorded client.
//! [`classify_evidence`] applies it to this module's richer report.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use heimdall_app::ports::{VerificationOutcome, VerificationRunner, VerificationSession};
use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::{ApprovedTarget, EnrollmentPlan};
use heimdall_contract::managed::ClockMeasurement;
use heimdall_contract::provider::EndpointKind;
use heimdall_domain::verification::{AttemptResult, InconclusiveReason, VerificationVerdict};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::trace::{self, ClientVersion, TraceContext, UnrecordedClient};

/// The fixed positive (and negative) command: the destination clock reading (M-F23).
///
/// ADR-0008 §17.17 item 7 (INT-Q3, M-F23 revised): not revision 2's `awk 'BEGIN { srand(); print srand() }'`: Debian
/// 13's mawk 1.3.4 prints **nanoseconds** there (observed on the M00-T03 `enrollable`
/// container). Like the scripts' `heimdall_registry::script::REMOTE_CLOCK_COMMAND`
/// (U5S-Q1), it reads POSIX `date -u` fields and converts them to epoch seconds in
/// `awk`, without `2>/dev/null` (the login shell runs this command, and csh-family
/// shells would read `2` as an argument). [`PLAUSIBLE_READING_SECS`] still guards
/// whatever a target prints.
pub const MEASURE_COMMAND: &str = r#"date -u '+%Y %m %d %H %M %S' | awk 'NF == 6 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/ && $6 ~ /^[0-9]+$/ { y = $1 + 0; m = $2 + 0; if (m <= 2) { y = y - 1; m = m + 12 }; e = int(y / 400); a = y - e * 400; d = a * 365 + int(a / 4) - int(a / 100) + int((153 * (m - 3) + 2) / 5) + $3 - 1; printf "HM1 now=%d\n", (e * 146097 + d - 719468) * 86400 + $4 * 3600 + $5 * 60 + $6 }'"#;

/// The generated `Host` name.
pub const VERIFY_HOST: &str = "hm-verify";

/// One attempt's bound (the client's own `ConnectTimeout` is 20 s).
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// The positive attempt's stdout bound (one `HM1 now=` line).
pub const STDOUT_MAX: usize = 4096;

/// The resolution of the remote reading (whole seconds).
const READING_RESOLUTION_MS: i128 = 1000;

/// ADR-0008 §17.17 item 7 (INT-Q3): the epoch-seconds range a remote `HM1 now=` reading must fall in
/// to be used (2000-01-01 to 3000-01-01 UTC). [`MEASURE_COMMAND`]'s `awk srand()`
/// prints **nanoseconds** on Debian 13's mawk 1.3.4 (U5S-Q1); read as seconds, that
/// would make the destination look far ahead and record `behind_upper_ms = 0`, the
/// least conservative residual. A reading outside the range is discarded, so the
/// clock is **unmeasured** (fail closed: the residual is reported `nominally_expired`
/// and never cleared, D7 item 3).
pub const PLAUSIBLE_READING_SECS: std::ops::RangeInclusive<i64> = 946_684_800..=32_503_680_000;

/// Whether the server log attests the login (ADR-0005 §3.3): never in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LogAttestation {
    /// The server log is not read: it is only the fixtures' test oracle.
    Unavailable,
}

/// Why an attempt did not run, or how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptEnd {
    /// Not started (the reason is [`VerifierReport::refused`] or the unrecorded client).
    NotStarted,
    /// The certificate could not be installed in the session.
    InstallRefused,
    /// The client exited (its status is in the result).
    Exited,
    /// The client ended on a signal.
    Signalled,
    /// [`ATTEMPT_TIMEOUT`] passed; the client was killed.
    TimedOut,
}

/// One attempt's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEvidence {
    /// What the classification reads.
    pub result: AttemptResult,
    /// The trace showed a host-key verification failure.
    pub host_key_failure: bool,
    /// How it ended.
    pub end: AttemptEnd,
}

impl Default for AttemptEvidence {
    fn default() -> Self {
        Self {
            result: AttemptResult::default(),
            host_key_failure: false,
            end: AttemptEnd::NotStarted,
        }
    }
}

/// Why no attempt ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifierRefusal {
    /// The Verifier has no client (this build or configuration).
    Unavailable,
    /// The approved target cannot be written into the generated configuration.
    TargetUnusable,
    /// A certificate line or K_verify does not parse, or is not K_verify's.
    CertificateUnusable,
    /// The endpoint locator cannot be written into the generated configuration.
    EndpointUnusable,
    /// The working directory or a generated file could not be created.
    WorkDir,
}

/// What [`Verifier::run_detailed`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierReport {
    /// The port's outcome.
    pub outcome: VerificationOutcome,
    /// The positive attempt.
    pub positive: AttemptEvidence,
    /// The negative attempt.
    pub negative: AttemptEvidence,
    /// The destination clock measurement (positive attempt with an `HM1 now=` line).
    pub clock: Option<ClockMeasurement>,
    /// The client's trace is unrecorded (the doctor names it).
    pub unrecorded: Option<UnrecordedClient>,
    /// Why nothing ran.
    pub refused: Option<VerifierRefusal>,
    /// `session-bind@openssh.com` extensions the endpoint received during the run.
    pub session_binds: u32,
    /// Always [`LogAttestation::Unavailable`].
    pub log_attestation: LogAttestation,
}

impl VerifierReport {
    fn not_run(client: Option<String>, refused: Option<VerifierRefusal>) -> Self {
        Self {
            outcome: VerificationOutcome {
                positive: AttemptResult::default(),
                negative: AttemptResult::default(),
                client,
                unrecorded: false,
            },
            positive: AttemptEvidence::default(),
            negative: AttemptEvidence::default(),
            clock: None,
            unrecorded: None,
            refused,
            session_binds: 0,
            log_attestation: LogAttestation::Unavailable,
        }
    }
}

/// The verified client the Verifier runs (from M02's client inventory, which the
/// runtime holds; this crate has no `localenv` edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierClient {
    /// The client's absolute path.
    pub path: PathBuf,
    /// Its version as `ssh -V` printed it ([`ClientVersion::parse`]).
    pub version: ClientVersion,
}

/// The production verification runner (module documentation).
#[derive(Debug, Default)]
pub struct Verifier {
    client: Option<VerifierClient>,
    runtime_dir: Option<PathBuf>,
    pause_dir: Option<PathBuf>,
    /// Debug builds only ([`Verifier::with_test_trace_dump`]): where each attempt's raw
    /// `-v` trace is written, for recording an unrecorded client's trace row.
    trace_dump: Option<PathBuf>,
}

/// The pause point once the negative nonce exists (ADR-0008 D13 item 3; the test
/// configuration's `nonce_known`).
pub const NONCE_KNOWN: &str = "nonce_known";

impl Verifier {
    /// A verifier without a client: [`available`](Self::available) is `false` and
    /// every run is refused ([`VerifierRefusal::Unavailable`]), inconclusive.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A verifier that runs `client`, with its generated files under
    /// `<runtime_dir>/v/`.
    #[must_use]
    pub fn with_client(client: VerifierClient, runtime_dir: impl Into<PathBuf>) -> Self {
        Self {
            client: Some(client),
            runtime_dir: Some(runtime_dir.into()),
            pause_dir: None,
            trace_dump: None,
        }
    }

    /// **Test configuration only** (debug builds; wave-1 native run, item C): write each
    /// attempt's raw `-v` trace to `<dir>/positive.trace` and `<dir>/negative.trace`, so
    /// a test can print an unrecorded client's trace lines for its row (recorded only
    /// from a real run's output, never from expectation). The classification is
    /// unchanged; the files are the caller's to read and remove.
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn with_test_trace_dump(mut self, dir: impl Into<PathBuf>) -> Self {
        self.trace_dump = Some(dir.into());
        self
    }

    /// **Test configuration only** (ADR-0008 D13 item 3; the caller's test gate passes
    /// `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`; this crate never reads the environment): before
    /// the negative attempt, when `<dir>/nonce_known` is a FIFO, write the negative
    /// nonce (32 lowercase hex and a newline) to `<dir>/nonce_known.nonce`, then read the
    /// FIFO to its end (the test releases it). Without a FIFO it is a no-op.
    #[must_use]
    pub fn with_test_pause_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.pause_dir = Some(dir.into());
        self
    }

    /// Whether this verifier can run a production verification: it has a client with
    /// recorded trace patterns.
    #[must_use]
    pub fn available(&self) -> bool {
        self.client
            .as_ref()
            .is_some_and(|c| trace::patterns_for(c.version.family, c.version).is_ok())
            && self.runtime_dir.is_some()
    }

    /// Run both attempts and report everything observed (module documentation).
    pub async fn run_detailed(
        &self,
        plan: &EnrollmentPlan,
        positive: &str,
        negative: &str,
        session: &dyn VerificationSession,
    ) -> VerifierReport {
        let (Some(client), Some(runtime_dir)) = (&self.client, &self.runtime_dir) else {
            return VerifierReport::not_run(None, Some(VerifierRefusal::Unavailable));
        };
        let client_label = format!(
            "{} {} {}",
            client.path.display(),
            client.version.family.as_str(),
            client.version
        );
        let patterns = match trace::patterns_for(client.version.family, client.version) {
            Ok(p) => p,
            Err(unrecorded) => {
                let mut r = VerifierReport::not_run(Some(client_label), None);
                r.unrecorded = Some(unrecorded);
                r.outcome.unrecorded = true;
                return r;
            }
        };
        let k_verify = match KeyFacts::of(session.public_key()) {
            Some(k) => k,
            None => {
                return VerifierReport::not_run(
                    Some(client_label),
                    Some(VerifierRefusal::CertificateUnusable),
                );
            }
        };
        if !k_verify.certificate_is_ours(positive) || !k_verify.certificate_is_ours(negative) {
            return VerifierReport::not_run(
                Some(client_label),
                Some(VerifierRefusal::CertificateUnusable),
            );
        }
        let Some(agent) = config_endpoint(session.locator().kind, &session.locator().locator)
        else {
            return VerifierReport::not_run(
                Some(client_label),
                Some(VerifierRefusal::EndpointUnusable),
            );
        };
        let tag = unique_tag();
        let alias = format!("{VERIFY_HOST}-{tag}");
        let Some(known_hosts_line) = known_hosts_line(&alias, &plan.approved_target) else {
            return VerifierReport::not_run(
                Some(client_label),
                Some(VerifierRefusal::TargetUnusable),
            );
        };
        let Ok(work) = WorkDir::create(runtime_dir, &tag) else {
            return VerifierReport::not_run(Some(client_label), Some(VerifierRefusal::WorkDir));
        };
        let files = GeneratedFiles::in_dir(&work.path);
        let written = work.write(&files.known_hosts, known_hosts_line.as_bytes())
            && work.write(&files.global_known_hosts, b"")
            && work.write(
                &files.key,
                format!("{}\n", session.public_key().trim()).as_bytes(),
            )
            && work.write(&files.positive, format!("{}\n", positive.trim()).as_bytes())
            && work.write(&files.negative, format!("{}\n", negative.trim()).as_bytes());
        if !written {
            return VerifierReport::not_run(Some(client_label), Some(VerifierRefusal::WorkDir));
        }
        let configs = [&files.positive, &files.negative].map(|cert| {
            generated_config(&GeneratedConfig {
                target: &plan.approved_target,
                alias: &alias,
                known_hosts: &files.known_hosts,
                global_known_hosts: &files.global_known_hosts,
                identity_agent: &agent,
                identity_file: &files.key,
                certificate_file: cert,
            })
        });
        let [Some(positive_config), Some(negative_config)] = configs else {
            return VerifierReport::not_run(
                Some(client_label),
                Some(VerifierRefusal::TargetUnusable),
            );
        };
        if !(work.write(&files.positive_config, positive_config.as_bytes())
            && work.write(&files.negative_config, negative_config.as_bytes()))
        {
            return VerifierReport::not_run(Some(client_label), Some(VerifierRefusal::WorkDir));
        }
        let binds_before = session.session_binds();
        let ctx = TraceContext {
            host_key_alias: &alias,
            cert_type: k_verify.cert_type,
            key_fingerprint: &k_verify.fingerprint,
        };
        let (positive_evidence, clock) = attempt(
            &client.path,
            &files.positive_config,
            positive,
            session,
            &k_verify.fingerprint,
            patterns,
            &ctx,
            self.trace_dump.as_ref().map(|d| d.join("positive.trace")),
        )
        .await;
        if let Some(dir) = &self.pause_dir
            && let Some(nonce) = negative_nonce(negative)
        {
            pause_at_nonce_known(dir, &nonce).await;
        }
        let (negative_evidence, _) = attempt(
            &client.path,
            &files.negative_config,
            negative,
            session,
            &k_verify.fingerprint,
            patterns,
            &ctx,
            self.trace_dump.as_ref().map(|d| d.join("negative.trace")),
        )
        .await;
        drop(work);
        VerifierReport {
            outcome: VerificationOutcome {
                positive: positive_evidence.result.clone(),
                negative: negative_evidence.result.clone(),
                client: Some(client_label),
                unrecorded: false,
            },
            positive: positive_evidence,
            negative: negative_evidence,
            clock,
            unrecorded: None,
            refused: None,
            session_binds: session.session_binds().saturating_sub(binds_before),
            log_attestation: LogAttestation::Unavailable,
        }
    }
}

#[async_trait]
impl VerificationRunner for Verifier {
    async fn run(
        &self,
        plan: &EnrollmentPlan,
        positive: &str,
        negative: &str,
        session: &dyn VerificationSession,
    ) -> VerificationOutcome {
        self.run_detailed(plan, positive, negative, session)
            .await
            .outcome
    }
}

/// The 32-hex nonce of the negative certificate's `hm:verify-negative:` principal.
fn negative_nonce(line: &str) -> Option<String> {
    let cert = ssh_key::Certificate::from_openssh(line.trim()).ok()?;
    let nonce = cert
        .valid_principals()
        .iter()
        .find_map(|p| p.strip_prefix(heimdall_domain::verification::NEGATIVE_PRINCIPAL_PREFIX))?;
    (nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| nonce.to_owned())
}

/// The test configuration's `nonce_known` pause ([`Verifier::with_test_pause_dir`]).
async fn pause_at_nonce_known(dir: &Path, nonce: &str) {
    let (dir, nonce) = (dir.to_path_buf(), nonce.to_owned());
    let _ = tokio::task::spawn_blocking(move || pause_blocking(&dir, &nonce)).await;
}

/// The FIFO pause (Unix only: a Windows test configuration has no FIFO, so no pause).
#[cfg(unix)]
fn pause_blocking(dir: &Path, nonce: &str) {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;
    let fifo = dir.join(NONCE_KNOWN);
    let is_fifo = std::fs::symlink_metadata(&fifo).is_ok_and(|m| m.file_type().is_fifo());
    let report = dir.join(format!("{NONCE_KNOWN}.nonce"));
    if !is_fifo || std::fs::write(&report, format!("{nonce}\n")).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::File::open(&fifo) {
        let mut sink = Vec::new();
        let _ = f.read_to_end(&mut sink);
    }
}

#[cfg(not(unix))]
fn pause_blocking(_dir: &Path, _nonce: &str) {}

/// One attempt: install, run, count, parse (module documentation). `trace_dump` (debug
/// builds' [`Verifier::with_test_trace_dump`]) receives the raw trace.
#[allow(clippy::too_many_arguments)]
async fn attempt(
    client: &Path,
    config: &Path,
    certificate: &str,
    session: &dyn VerificationSession,
    fingerprint: &str,
    patterns: &trace::TracePatterns,
    ctx: &TraceContext<'_>,
    trace_dump: Option<PathBuf>,
) -> (AttemptEvidence, Option<ClockMeasurement>) {
    if session.install(certificate).is_err() {
        return (
            AttemptEvidence {
                end: AttemptEnd::InstallRefused,
                ..AttemptEvidence::default()
            },
            None,
        );
    }
    let before = session.signatures(fingerprint);
    let mut cmd = tokio::process::Command::new(client);
    cmd.arg("-F")
        .arg(config)
        .args(["-v", "-T", VERIFY_HOST, MEASURE_COMMAND])
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let t1 = SystemTime::now();
    let Ok(mut child) = cmd.spawn() else {
        return (AttemptEvidence::default(), None);
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return (AttemptEvidence::default(), None);
    };
    let trace_max = heimdall_app::operations::Limits::default().verification_trace_max;
    let run = async {
        let (now, trace_bytes, status) = tokio::join!(
            read_reading(stdout),
            read_bounded(stderr, trace_max),
            child.wait()
        );
        (now, trace_bytes, status)
    };
    let (reading, trace_bytes, end, exit) = match tokio::time::timeout(ATTEMPT_TIMEOUT, run).await {
        Ok((reading, trace_bytes, status)) => {
            let code = status.ok().and_then(|s| s.code());
            let end = if code.is_some() {
                AttemptEnd::Exited
            } else {
                AttemptEnd::Signalled
            };
            (reading, trace_bytes, end, code)
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            (None, Vec::new(), AttemptEnd::TimedOut, None)
        }
    };
    let signatures = session.signatures(fingerprint).saturating_sub(before);
    if let Some(path) = trace_dump {
        let _ = std::fs::write(path, &trace_bytes);
    }
    let parsed = trace::parse(patterns, &String::from_utf8_lossy(&trace_bytes), ctx);
    let clock = reading.and_then(|(remote, t2)| measurement(t1, t2, remote));
    (
        AttemptEvidence {
            result: AttemptResult {
                exit_status: exit,
                signatures,
                trace: heimdall_domain::verification::TraceEvents {
                    host_key_failure: parsed.host_key_failure,
                    ..parsed.events
                },
                remote_now: reading.map(|(remote, _)| remote),
            },
            host_key_failure: parsed.host_key_failure,
            end,
        },
        clock,
    )
}

/// The `HM1 now=<seconds>` line and the local wall time it was read at.
async fn read_reading(mut stdout: impl AsyncRead + Unpin) -> Option<(i64, SystemTime)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut found: Option<(i64, SystemTime)> = None;
    loop {
        let n = match stdout.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if buf.len() < STDOUT_MAX {
            let room = STDOUT_MAX - buf.len();
            buf.extend_from_slice(&chunk[..n.min(room)]);
        }
        if found.is_none()
            && let Some(nl) = buf.iter().position(|&b| b == b'\n')
        {
            let at = SystemTime::now();
            let line = String::from_utf8_lossy(&buf[..nl]).into_owned();
            found = line
                .trim_end_matches('\r')
                .strip_prefix("HM1 now=")
                .and_then(|v| v.parse::<i64>().ok())
                .filter(|v| PLAUSIBLE_READING_SECS.contains(v))
                .map(|v| (v, at));
        }
    }
    found
}

/// Read all of `r`, keeping at most `max` bytes (the rest is read and dropped, so the
/// client never blocks on a full pipe).
async fn read_bounded(mut r: impl AsyncRead + Unpin, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = max.saturating_sub(out.len());
                out.extend_from_slice(&chunk[..n.min(room)]);
            }
        }
    }
    out
}

/// ADR-0008 D5 §6.5 item 4: `behind_upper = max(0, t₂ − T + 1 s)`, `rtt = t₂ − t₁`.
#[must_use]
pub fn measurement(t1: SystemTime, t2: SystemTime, remote_secs: i64) -> Option<ClockMeasurement> {
    let ms = |t: SystemTime| -> Option<i128> {
        let d = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
        i128::try_from(d.as_millis()).ok()
    };
    let (t1_ms, t2_ms) = (ms(t1)?, ms(t2)?);
    let remote_ms = i128::from(remote_secs).checked_mul(1000)?;
    let behind = (t2_ms - remote_ms + READING_RESOLUTION_MS).max(0);
    let rtt = (t2_ms - t1_ms).max(0);
    Some(ClockMeasurement {
        behind_upper_ms: u64::try_from(behind).ok()?,
        rtt_ms: u64::try_from(rtt).ok()?,
        measured_at: Timestamp::try_from(t2).ok()?,
    })
}

/// K_verify's facts, from its OpenSSH public-key line.
struct KeyFacts {
    key: ssh_key::PublicKey,
    fingerprint: String,
    cert_type: &'static str,
}

impl KeyFacts {
    fn of(public_line: &str) -> Option<KeyFacts> {
        let key = ssh_key::PublicKey::from_openssh(public_line.trim()).ok()?;
        let cert_type = match key.algorithm() {
            ssh_key::Algorithm::Ed25519 => "ED25519-CERT",
            ssh_key::Algorithm::Ecdsa { .. } => "ECDSA-CERT",
            ssh_key::Algorithm::Rsa { .. } => "RSA-CERT",
            _ => return None,
        };
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        Some(KeyFacts {
            key,
            fingerprint,
            cert_type,
        })
    }

    /// The line is a user certificate whose subject key is K_verify.
    fn certificate_is_ours(&self, line: &str) -> bool {
        let Ok(cert) = ssh_key::Certificate::from_openssh(line.trim()) else {
            return false;
        };
        cert.cert_type() == ssh_key::certificate::CertType::User
            && cert.public_key() == self.key.key_data()
    }
}

/// The paths of the generated files.
struct GeneratedFiles {
    known_hosts: PathBuf,
    global_known_hosts: PathBuf,
    key: PathBuf,
    positive: PathBuf,
    negative: PathBuf,
    positive_config: PathBuf,
    negative_config: PathBuf,
}

impl GeneratedFiles {
    fn in_dir(dir: &Path) -> Self {
        Self {
            known_hosts: dir.join("known_hosts"),
            global_known_hosts: dir.join("global_known_hosts"),
            key: dir.join("k_verify.pub"),
            positive: dir.join("positive-cert.pub"),
            negative: dir.join("negative-cert.pub"),
            positive_config: dir.join("ssh_config.positive"),
            negative_config: dir.join("ssh_config.negative"),
        }
    }
}

/// `<runtime_dir>/v/<16 hex>`, owner-only, removed on drop.
struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn create(runtime_dir: &Path, tag: &str) -> std::io::Result<WorkDir> {
        let base = runtime_dir.join("v");
        match std::fs::create_dir(&base) {
            Ok(()) => owner_only_dir(&base)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let path = base.join(tag);
        std::fs::create_dir(&path)?;
        let dir = WorkDir { path };
        owner_only_dir(&dir.path)?;
        Ok(dir)
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> bool {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(path)
            .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
            .is_ok()
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        // Only the directory this run created, by its exact path.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn owner_only_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// 16 lowercase hex characters, unique per run (a randomly keyed hash of the process,
/// the time and a counter; uniqueness only, never a secret).
fn unique_tag() -> String {
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    if let Ok(d) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    format!("{:016x}", h.finish())
}

/// The approved key's `HostKeyAlgorithms` (ADR-0008 D5 §6.3): its type, or for RSA
/// `rsa-sha2-512,rsa-sha2-256`; never a certificate type.
#[must_use]
pub fn host_key_algorithms(algorithm: &str) -> Option<String> {
    let ok = !algorithm.is_empty()
        && !algorithm.ends_with("-cert-v01@openssh.com")
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.'));
    if !ok {
        return None;
    }
    Some(if algorithm == "ssh-rsa" {
        "rsa-sha2-512,rsa-sha2-256".to_owned()
    } else {
        algorithm.to_owned()
    })
}

/// The generated known-hosts line: the alias and the approved key, nothing else.
fn known_hosts_line(alias: &str, target: &ApprovedTarget) -> Option<String> {
    let key = &target.host_key;
    host_key_algorithms(&key.algorithm)?;
    let b64_ok = !key.key.is_empty()
        && key
            .key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    b64_ok.then(|| format!("{alias} {} {}\n", key.algorithm, key.key))
}

/// A path as a quoted `ssh_config` argument, or `None` when it cannot be written
/// literally: a quote, `%` (a token), `$` (an environment reference) or a control
/// character. Windows separators are written as `/`.
fn config_path(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    };
    let refused = text.is_empty()
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '%' | '$'))
        || (!cfg!(windows) && text.contains('\\'));
    (!refused).then(|| format!("\"{text}\""))
}

/// The session's locator as an `IdentityAgent` argument: a socket path, or a Windows
/// pipe as `//./pipe/<name>` (ADR-0007 F14).
fn config_endpoint(kind: EndpointKind, locator: &str) -> Option<String> {
    match kind {
        EndpointKind::UnixSocket => config_path(Path::new(locator)),
        EndpointKind::NamedPipe => {
            let lower = locator.to_ascii_lowercase();
            let name = [r"\\.\pipe\", "//./pipe/"]
                .iter()
                .find_map(|p| lower.starts_with(p).then(|| &locator[p.len()..]))?;
            let ok = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            ok.then(|| format!("\"//./pipe/{name}\""))
        }
        _ => None,
    }
}

/// The inputs of [`generated_config`].
#[derive(Debug, Clone, Copy)]
pub struct GeneratedConfig<'a> {
    /// The approved target.
    pub target: &'a ApprovedTarget,
    /// The generated `HostKeyAlias`.
    pub alias: &'a str,
    /// The generated known-hosts file (one line).
    pub known_hosts: &'a Path,
    /// The empty global known-hosts file.
    pub global_known_hosts: &'a Path,
    /// `IdentityAgent`, already an `ssh_config` argument.
    pub identity_agent: &'a str,
    /// K_verify's public key file.
    pub identity_file: &'a Path,
    /// The attempt's certificate.
    pub certificate_file: &'a Path,
}

/// The generated configuration of ADR-0008 D5 §6.5 item 3 (module documentation), or
/// `None` when a value cannot be written literally.
#[must_use]
pub fn generated_config(c: &GeneratedConfig<'_>) -> Option<String> {
    let host = &c.target.hostname;
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'));
    let user = c.target.user.as_str();
    let user_ok = !user.is_empty()
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    let alias_ok = c
        .alias
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !(host_ok && user_ok && alias_ok) || c.target.port == 0 {
        return None;
    }
    let algorithms = host_key_algorithms(&c.target.host_key.algorithm)?;
    let lines = [
        format!("Host {VERIFY_HOST}"),
        format!("  HostName {host}"),
        format!("  Port {}", c.target.port),
        format!("  User {user}"),
        format!("  HostKeyAlias {}", c.alias),
        format!("  UserKnownHostsFile {}", config_path(c.known_hosts)?),
        format!(
            "  GlobalKnownHostsFile {}",
            config_path(c.global_known_hosts)?
        ),
        "  KnownHostsCommand none".to_owned(),
        "  VerifyHostKeyDNS no".to_owned(),
        format!("  HostKeyAlgorithms {algorithms}"),
        "  StrictHostKeyChecking yes".to_owned(),
        "  CheckHostIP no".to_owned(),
        "  UpdateHostKeys no".to_owned(),
        "  NoHostAuthenticationForLocalhost no".to_owned(),
        "  CanonicalizeHostname no".to_owned(),
        "  ForkAfterAuthentication no".to_owned(),
        format!("  IdentityAgent {}", c.identity_agent),
        "  IdentitiesOnly yes".to_owned(),
        format!("  IdentityFile {}", config_path(c.identity_file)?),
        format!("  CertificateFile {}", config_path(c.certificate_file)?),
        "  PreferredAuthentications publickey".to_owned(),
        "  PasswordAuthentication no".to_owned(),
        "  KbdInteractiveAuthentication no".to_owned(),
        "  BatchMode yes".to_owned(),
        "  ControlMaster no".to_owned(),
        "  ControlPath none".to_owned(),
        "  ProxyCommand none".to_owned(),
        "  ProxyJump none".to_owned(),
        "  ForwardAgent no".to_owned(),
        "  ClearAllForwardings yes".to_owned(),
        "  RequestTTY no".to_owned(),
        "  ConnectTimeout 20".to_owned(),
    ];
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

// --- the classification table over the Verifier's evidence (U5IO-Q4) -----------------

/// The known offset of the destination clock: `heimdall_domain::verification`'s
/// (ADR-0008 §17.17 item 14 moved the table there).
pub use heimdall_domain::verification::KnownOffset;

/// The ADR-0008 D5 §6.5 classification over the Verifier's evidence: the domain's
/// `heimdall_domain::verification::classify` (§17.17 item 14, U5IO-Q4), with this
/// report's host-key failures, unrecorded client and refusal folded in. A run the
/// Verifier refused (nothing ran) is inconclusive (`unclassified`).
#[must_use]
pub fn classify_evidence(
    report: &VerifierReport,
    offset: Option<KnownOffset>,
    skew_lag_ms: u64,
    skew_lead_ms: u64,
) -> VerificationVerdict {
    if report.unrecorded.is_none() && report.refused.is_some() {
        return VerificationVerdict::Inconclusive {
            reason: InconclusiveReason::Unclassified,
        };
    }
    let fold = |e: &AttemptEvidence| {
        let mut r = e.result.clone();
        r.trace.host_key_failure |= e.host_key_failure;
        r
    };
    heimdall_domain::verification::classify(
        &fold(&report.positive),
        &fold(&report.negative),
        heimdall_domain::verification::VerificationPhase::Initial,
        heimdall_contract::enrollment::EnrollmentForm::Account,
        &heimdall_domain::verification::ClassifyContext {
            unrecorded: report.unrecorded.is_some(),
            offset,
            skew_lag_ms,
            skew_lead_ms,
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_contract::enrollment::{ApprovedHostKey, NoProxy};
    use heimdall_contract::ids::AccountName;
    use heimdall_domain::verification::TraceEvents;

    fn target(algorithm: &str) -> ApprovedTarget {
        ApprovedTarget {
            hostname: "127.0.0.1".into(),
            port: 2222,
            user: AccountName::parse("deploy").unwrap(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm: algorithm.into(),
                key: "AAAAC3NzaC1lZDI1NTE5AAAAIA==".into(),
                fingerprint: "SHA256:x".into(),
            },
        }
    }

    #[test]
    fn verifier_without_a_client_is_unavailable() {
        assert!(!Verifier::new().available());
    }

    #[test]
    fn generated_config_pins_every_host_trust_option() {
        let t = target("ssh-ed25519");
        let c = generated_config(&GeneratedConfig {
            target: &t,
            alias: "hm-verify-0123456789abcdef",
            known_hosts: Path::new("/r/v/x/known_hosts"),
            global_known_hosts: Path::new("/r/v/x/global known_hosts"),
            identity_agent: "\"/r/s/agent.sock\"",
            identity_file: Path::new("/r/v/x/k_verify.pub"),
            certificate_file: Path::new("/r/v/x/positive-cert.pub"),
        })
        .unwrap();
        for line in [
            "Host hm-verify",
            "  HostName 127.0.0.1",
            "  Port 2222",
            "  User deploy",
            "  HostKeyAlias hm-verify-0123456789abcdef",
            "  UserKnownHostsFile \"/r/v/x/known_hosts\"",
            "  GlobalKnownHostsFile \"/r/v/x/global known_hosts\"",
            "  KnownHostsCommand none",
            "  VerifyHostKeyDNS no",
            "  HostKeyAlgorithms ssh-ed25519",
            "  StrictHostKeyChecking yes",
            "  CheckHostIP no",
            "  UpdateHostKeys no",
            "  NoHostAuthenticationForLocalhost no",
            "  CanonicalizeHostname no",
            "  ForkAfterAuthentication no",
            "  IdentityAgent \"/r/s/agent.sock\"",
            "  IdentitiesOnly yes",
            "  CertificateFile \"/r/v/x/positive-cert.pub\"",
            "  BatchMode yes",
            "  ControlPath none",
            "  ProxyCommand none",
            "  ProxyJump none",
        ] {
            assert!(c.lines().any(|l| l == line), "{line}");
        }
        assert_eq!(
            host_key_algorithms("ssh-rsa").as_deref(),
            Some("rsa-sha2-512,rsa-sha2-256")
        );
        assert!(host_key_algorithms("ssh-ed25519-cert-v01@openssh.com").is_none());
        let mut bad = target("ssh-ed25519");
        bad.hostname = "a b".into();
        assert!(
            generated_config(&GeneratedConfig {
                target: &bad,
                alias: "hm-verify-x",
                known_hosts: Path::new("/k"),
                global_known_hosts: Path::new("/g"),
                identity_agent: "\"/a\"",
                identity_file: Path::new("/i"),
                certificate_file: Path::new("/c"),
            })
            .is_none()
        );
        assert!(config_path(Path::new("/a/%h")).is_none());
        assert!(config_path(Path::new("/a/${X}")).is_none());
        assert_eq!(
            config_endpoint(EndpointKind::NamedPipe, r"\\.\pipe\hm-verify-1").as_deref(),
            Some("\"//./pipe/hm-verify-1\"")
        );
    }

    #[test]
    fn measurement_bounds_the_lag() {
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let t2 = t1 + Duration::from_millis(250);
        // The remote reads 30 s behind.
        let m = measurement(t1, t2, 1_000_000 - 30).unwrap();
        assert_eq!(m.rtt_ms, 250);
        assert_eq!(m.behind_upper_ms, 30_000 + 250 + 1000);
        // A destination ahead of local time lags by at most 0.
        let ahead = measurement(t1, t2, 1_000_100).unwrap();
        assert_eq!(ahead.behind_upper_ms, 0);
    }

    /// INT-Q3: the verifier's clock command is the scripts' reading (same conversion),
    /// minus the stderr redirection and with the `HM1 now=` prefix.
    #[test]
    fn measure_command_tracks_the_scripts_clock_reading() {
        let expected = heimdall_registry::script::REMOTE_CLOCK_COMMAND
            .replace(" 2>/dev/null", "")
            .replace(r#"printf "%d\n""#, r#"printf "HM1 now=%d\n""#);
        assert_eq!(MEASURE_COMMAND, expected);
        assert!(!MEASURE_COMMAND.contains("srand"));
    }

    /// INT-Q3: a reading that is not epoch seconds (Debian 13 mawk's `srand()` prints
    /// nanoseconds) is discarded, so the clock reads unmeasured instead of "not behind".
    #[test]
    fn implausible_clock_reading_is_unmeasured_never_not_behind() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let read = |text: &'static [u8]| rt.block_on(read_reading(text)).map(|(v, _)| v);
        assert_eq!(read(b"HM1 now=1794305972\n"), Some(1_794_305_972));
        assert_eq!(read(b"HM1 now=1794305972306619648\n"), None);
        assert_eq!(read(b"HM1 now=1794305972306\n"), None);
        assert_eq!(read(b"HM1 now=0\n"), None);
        assert_eq!(read(b"HM1 now=-5\n"), None);
    }

    fn evidence(exit: i32, signatures: u32, t: TraceEvents, now: Option<i64>) -> AttemptEvidence {
        AttemptEvidence {
            result: AttemptResult {
                exit_status: Some(exit),
                signatures,
                trace: t,
                remote_now: now,
            },
            host_key_failure: false,
            end: AttemptEnd::Exited,
        }
    }

    fn report(p: AttemptEvidence, n: AttemptEvidence) -> VerifierReport {
        let mut r = VerifierReport::not_run(Some("c".into()), None);
        r.positive = p;
        r.negative = n;
        r
    }

    #[test]
    fn classification_table_rows() {
        let seen = TraceEvents {
            server_version: Some("OpenSSH_10.5".into()),
            host_key_matched: true,
            offered_certificate: true,
            ..TraceEvents::default()
        };
        let accepted = TraceEvents {
            accepted: true,
            ..seen.clone()
        };
        let refused_t = TraceEvents {
            not_accepted: true,
            publickey_failure_final: true,
            ..seen.clone()
        };
        let pass = evidence(0, 1, accepted.clone(), Some(1));
        let neg_refused = evidence(255, 0, refused_t.clone(), None);
        let c = |r: &VerifierReport, o| classify_evidence(r, o, 60_000, 300_000);
        assert_eq!(
            c(&report(pass.clone(), neg_refused.clone()), None),
            VerificationVerdict::Passed
        );
        assert_eq!(
            c(
                &report(pass.clone(), evidence(0, 1, accepted.clone(), Some(1))),
                None
            ),
            VerificationVerdict::PrincipalsNotEnforced
        );
        // A signature recorded for a refused negative is not a refusal.
        assert_eq!(
            c(
                &report(pass.clone(), evidence(255, 1, refused_t.clone(), None)),
                None
            ),
            VerificationVerdict::PrincipalsNotEnforced
        );
        // A transport failure of the negative is never a refusal.
        let transport = evidence(255, 0, TraceEvents::default(), None);
        assert!(c(&report(pass.clone(), transport.clone()), None).is_inconclusive());
        assert_eq!(
            c(&report(neg_refused.clone(), neg_refused.clone()), None),
            VerificationVerdict::PositiveRefused
        );
        let skewed = KnownOffset {
            remote_minus_local_ms: -61_000,
            uncertainty_ms: 1_200,
        };
        assert_eq!(
            c(
                &report(neg_refused.clone(), neg_refused.clone()),
                Some(skewed)
            ),
            VerificationVerdict::Inconclusive {
                reason: InconclusiveReason::DestinationClockSkew
            }
        );
        let mut hk = report(transport.clone(), transport.clone());
        hk.positive.host_key_failure = true;
        assert_eq!(c(&hk, None), VerificationVerdict::HostKeyMismatch);
        let mut un = report(pass, neg_refused);
        un.unrecorded = Some(UnrecordedClient {
            version: ClientVersion::parse("OpenSSH_9.7p1").unwrap(),
        });
        assert_eq!(
            c(&un, None),
            VerificationVerdict::Inconclusive {
                reason: InconclusiveReason::UnrecordedClientFamily
            }
        );
        assert!(
            KnownOffset {
                remote_minus_local_ms: 299_000,
                uncertainty_ms: 1_000
            }
            .beyond(60_000, 300_000)
        );
        assert!(
            !KnownOffset {
                remote_minus_local_ms: -10_000,
                uncertainty_ms: 1_000
            }
            .beyond(60_000, 300_000)
        );
    }
}
