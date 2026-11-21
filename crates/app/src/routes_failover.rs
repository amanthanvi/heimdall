//! ⟨M06 U5a⟩ Failover before the forwarding boundary (ADR-0012 §5.5; m06-plan U5a).
//!
//! 1. **The establishment point** is the receipt, through the candidate, of the server's SSH
//!    identification line (`SSH-…`, ending in LF). Until then the client's bytes are held:
//!    the client side is not read at all. Lines the server sends before its identification
//!    (RFC 4253 §4.2) are buffered, at most [`FailoverConfig::max_pre_identification_bytes`]
//!    (8 KiB) and [`FailoverConfig::max_pre_identification_lines`] (32), and forwarded
//!    unchanged with the identification and anything after it; past either bound, or past the
//!    route's identification wait (10 s by default), the attempt fails as
//!    `identification_timeout`. A server that waits for the client to identify first times
//!    out at that bound.
//! 2. **The forwarding boundary** is the first byte forwarded in either direction, which is
//!    the buffered identification itself. Failover is allowed only before it: a connect
//!    refusal or timeout, a jump leg that ends before identification, the identification
//!    bound. After it every failure is terminal for the attempt and recorded
//!    (`terminal_after_forwarding`): an I/O error on either side, or a jump leg that ends
//!    unsuccessfully.
//! 3. **Never** failed over: a leg's own host-key or authentication failure
//!    ([`DialFailure::Terminal`], [`LegEnd::terminal`]). Never tried: a route that is not in
//!    the planned (approved) list; this module only walks that list, in order.
//! 4. **Route health**: one `RouteHealthPayload` when the attempt is established (`health`,
//!    or `failed_over` when earlier routes failed), one more if it later fails after the
//!    boundary, and one when no route is established (`final_route` absent).

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use heimdall_contract::ids::{AccountName, DestinationId, RouteId};
use heimdall_contract::route::{
    RouteAttempt, RouteEventKind, RouteFailureClass, RouteHealthPayload,
};
use heimdall_domain::routes::{PRE_IDENTIFICATION_MAX_BYTES, PRE_IDENTIFICATION_MAX_LINES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::PlannedRoute;

/// The direct leg's connect bound.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 4253 §4.2: the identification line is at most 255 bytes, CR LF included.
pub const IDENTIFICATION_LINE_MAX: usize = 255;

/// The helper's bounds (ADR-0012 §5.5 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverConfig {
    /// Pre-identification bytes buffered (8 KiB).
    pub max_pre_identification_bytes: usize,
    /// Pre-identification lines buffered (32).
    pub max_pre_identification_lines: usize,
    /// The direct leg's connect bound.
    pub connect_timeout: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            max_pre_identification_bytes: PRE_IDENTIFICATION_MAX_BYTES,
            max_pre_identification_lines: PRE_IDENTIFICATION_MAX_LINES,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// Why a leg could not be dialed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialFailure {
    /// Refused (or unavailable in this build): failover allowed.
    Refused,
    /// The connect bound passed: failover allowed.
    Timeout,
    /// The leg's own host-key or authentication failure: never failed over.
    Terminal,
}

/// How a leg ended (the jump leg's `ssh`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegEnd {
    /// It ended successfully.
    pub success: bool,
    /// It ended on a host-key or authentication failure.
    pub terminal: bool,
}

/// The end of a leg that is a process.
#[async_trait]
pub trait LegEnding: Send {
    /// Wait (bounded) for the leg to end, and say how. Idempotent.
    async fn end(&mut self) -> LegEnd;

    /// End the leg now (an attempt that failed before identification), then as
    /// [`LegEnding::end`].
    async fn abort(&mut self) -> LegEnd {
        self.end().await
    }
}

/// A dialed leg: the stream to the server, and its process end when it has one.
pub struct Leg {
    /// Bytes from the server.
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// Bytes to the server.
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    /// The leg's process, when it is one.
    pub ending: Option<Box<dyn LegEnding>>,
}

/// Opens one planned route's leg.
#[async_trait]
pub trait LegDialer: Send + Sync {
    /// Dial `route` (a direct connect is bounded by `connect_timeout`).
    async fn dial(
        &self,
        route: &PlannedRoute,
        connect_timeout: Duration,
    ) -> Result<Leg, DialFailure>;
}

/// Where the identification scan stands ([`scan_identification`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scan {
    /// Not yet: read more.
    NeedMore,
    /// The identification line ends at byte `end` (exclusive).
    Identified {
        /// One past the identification line's LF.
        end: usize,
    },
    /// A bound was exceeded before identification.
    Overflow,
}

/// Scan the bytes a server sent so far for its identification line (module docs).
#[must_use]
pub fn scan_identification(buf: &[u8], config: &FailoverConfig) -> Scan {
    let mut start = 0usize;
    let mut lines = 0usize;
    loop {
        let rest = &buf[start..];
        let maybe_ident =
            rest.starts_with(b"SSH-") || (rest.len() < 4 && b"SSH-".starts_with(rest));
        let newline = rest.iter().position(|b| *b == b'\n');
        if maybe_ident && !rest.is_empty() {
            return match newline {
                Some(i) if i < IDENTIFICATION_LINE_MAX => Scan::Identified { end: start + i + 1 },
                Some(_) => Scan::Overflow,
                None if rest.len() >= IDENTIFICATION_LINE_MAX => Scan::Overflow,
                None => Scan::NeedMore,
            };
        }
        match newline {
            Some(i) => {
                lines += 1;
                start += i + 1;
                if lines > config.max_pre_identification_lines
                    || start > config.max_pre_identification_bytes
                {
                    return Scan::Overflow;
                }
            }
            None if buf.len() > config.max_pre_identification_bytes => return Scan::Overflow,
            None => return Scan::NeedMore,
        }
    }
}

/// The result of one helper run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverOutcome {
    /// Every route-health result recorded, in order.
    pub health: Vec<RouteHealthPayload>,
    /// The route that was established, if any.
    pub final_route: Option<RouteId>,
    /// A failure after the forwarding boundary ended the attempt.
    pub late_failure: bool,
}

impl FailoverOutcome {
    /// Whether the session was established and ended without a recorded failure.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.final_route.is_some() && !self.late_failure
    }
}

/// How waiting for the identification ended.
enum Establish {
    /// The bytes received so far, ending at or after the identification line.
    Identified(Vec<u8>),
    /// Failed before the boundary; `terminal`: never failed over.
    Failed(RouteFailureClass, bool),
}

async fn establish(leg: &mut Leg, timeout: Duration, config: &FailoverConfig) -> Establish {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = vec![0u8; 4096];
    loop {
        match scan_identification(&buf, config) {
            Scan::Identified { .. } => return Establish::Identified(buf),
            Scan::Overflow => {
                return Establish::Failed(RouteFailureClass::IdentificationTimeout, false);
            }
            Scan::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, leg.reader.read(&mut chunk)).await {
            Err(_) => return Establish::Failed(RouteFailureClass::IdentificationTimeout, false),
            Ok(Ok(0)) => {
                let terminal = match leg.ending.as_mut() {
                    Some(e) => e.end().await.terminal,
                    None => false,
                };
                // A terminal ending is a host-key or authentication failure at the jump
                // host (ADR-0012 §5.5 item 3): its own class, never failed over.
                let class = if terminal {
                    RouteFailureClass::AuthenticationOrTrust
                } else {
                    RouteFailureClass::Refused
                };
                return Establish::Failed(class, terminal);
            }
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return Establish::Failed(RouteFailureClass::Refused, false),
        }
    }
}

/// Forward the buffered `prefix`, then both directions, until the server side ends. Returns
/// whether a failure ended the attempt after the boundary.
async fn forward<I, O>(leg: Leg, prefix: Vec<u8>, mut client_in: I, mut client_out: O) -> bool
where
    I: AsyncRead + Unpin + Send,
    O: AsyncWrite + Unpin + Send,
{
    let Leg {
        mut reader,
        mut writer,
        ending,
    } = leg;
    if client_out.write_all(&prefix).await.is_err() || client_out.flush().await.is_err() {
        if let Some(mut e) = ending {
            e.end().await;
        }
        return true;
    }
    let up = async {
        let r = tokio::io::copy(&mut client_in, &mut writer).await;
        let _ = writer.shutdown().await;
        r.is_ok()
    };
    let down = async {
        let r = tokio::io::copy(&mut reader, &mut client_out).await;
        let flushed = client_out.flush().await.is_ok();
        let _ = client_out.shutdown().await;
        r.is_ok() && flushed
    };
    tokio::pin!(up);
    tokio::pin!(down);
    let mut up_ok: Option<bool> = None;
    // The session ends when the server side ends; the client side may stay open (the client
    // is gone or waiting), so it is never awaited after that.
    let down_ok = loop {
        tokio::select! {
            ok = &mut down => break ok,
            ok = &mut up, if up_ok.is_none() => up_ok = Some(ok),
        }
    };
    let mut failed = !down_ok || up_ok == Some(false);
    if let Some(mut e) = ending {
        failed |= !e.end().await.success;
    }
    failed
}

fn payload(
    destination: &DestinationId,
    account: &AccountName,
    attempts: &[RouteAttempt],
    final_route: Option<&RouteId>,
) -> RouteHealthPayload {
    let failed_over = final_route.is_some() && attempts.len() > 1;
    RouteHealthPayload {
        kind: if failed_over {
            RouteEventKind::FailedOver
        } else {
            RouteEventKind::Health
        },
        destination: destination.clone(),
        account: account.clone(),
        attempts: attempts.to_vec(),
        final_route: final_route.cloned(),
    }
}

/// Try `routes` in order with failover before the forwarding boundary, then forward between
/// the client and the established leg (module docs). `record` receives each route-health
/// result as it is produced.
#[allow(clippy::too_many_arguments)]
pub async fn run_failover<D, I, O, F, Fut>(
    destination: &DestinationId,
    account: &AccountName,
    routes: &[PlannedRoute],
    dialer: &D,
    client_in: I,
    client_out: O,
    config: &FailoverConfig,
    record: &F,
) -> FailoverOutcome
where
    D: LegDialer + ?Sized,
    I: AsyncRead + Unpin + Send,
    O: AsyncWrite + Unpin + Send,
    F: Fn(RouteHealthPayload) -> Fut + ?Sized,
    Fut: Future<Output = ()>,
{
    let mut outcome = FailoverOutcome {
        health: Vec::new(),
        final_route: None,
        late_failure: false,
    };
    let mut attempts: Vec<RouteAttempt> = Vec::new();
    let failed = |route: &PlannedRoute, class| RouteAttempt {
        route: route.id.clone(),
        failure: Some(class),
    };
    for route in routes {
        let mut leg = match dialer.dial(route, config.connect_timeout).await {
            Ok(leg) => leg,
            Err(DialFailure::Refused) => {
                attempts.push(failed(route, RouteFailureClass::Refused));
                continue;
            }
            Err(DialFailure::Timeout) => {
                attempts.push(failed(route, RouteFailureClass::Timeout));
                continue;
            }
            Err(DialFailure::Terminal) => {
                attempts.push(failed(route, RouteFailureClass::Refused));
                break;
            }
        };
        match establish(&mut leg, route.identification_timeout, config).await {
            Establish::Failed(class, terminal) => {
                attempts.push(failed(route, class));
                if let Some(mut e) = leg.ending.take() {
                    drop(leg);
                    e.abort().await;
                }
                if terminal {
                    break;
                }
            }
            Establish::Identified(prefix) => {
                attempts.push(RouteAttempt {
                    route: route.id.clone(),
                    failure: None,
                });
                let established = payload(destination, account, &attempts, Some(&route.id));
                record(established.clone()).await;
                outcome.health.push(established);
                outcome.final_route = Some(route.id.clone());
                if forward(leg, prefix, client_in, client_out).await {
                    outcome.late_failure = true;
                    if let Some(last) = attempts.last_mut() {
                        last.failure = Some(RouteFailureClass::TerminalAfterForwarding);
                    }
                    let mut late = payload(destination, account, &attempts, Some(&route.id));
                    late.kind = RouteEventKind::Health;
                    record(late.clone()).await;
                    outcome.health.push(late);
                }
                return outcome;
            }
        }
    }
    let none = payload(destination, account, &attempts, None);
    record(none.clone()).await;
    outcome.health.push(none);
    outcome
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::routes::LegPlan;
    use proptest::prelude::*;
    use tokio::io::DuplexStream;

    /// A scripted server behind one route.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Script {
        /// Dial refused.
        DialRefused,
        /// Dial timed out.
        DialTimeout,
        /// A host-key or authentication failure while dialing.
        DialTerminal,
        /// Closes before identifying (`terminal`: on a host-key or authentication failure).
        EofBeforeIdentification { terminal: bool },
        /// Sends nothing (a client-first server).
        Silent,
        /// Sends `lines` pre-identification lines, then identifies, then echoes the client;
        /// `late`: then fails after the boundary.
        Identifies { lines: usize, late: bool },
    }

    #[derive(Default)]
    struct Log {
        dialed: Vec<RouteId>,
        /// Bytes each route's server received from the client, and whether it had identified
        /// before the first of them.
        received: BTreeMap<RouteId, (Vec<u8>, bool)>,
    }

    struct Dialer {
        scripts: BTreeMap<RouteId, Script>,
        log: Arc<Mutex<Log>>,
    }

    struct End(LegEnd);

    #[async_trait]
    impl LegEnding for End {
        async fn end(&mut self) -> LegEnd {
            self.0
        }
    }

    const IDENT: &[u8] = b"SSH-2.0-OpenSSH_test\r\n";

    async fn serve(mut server: DuplexStream, script: Script, id: RouteId, log: Arc<Mutex<Log>>) {
        let Script::Identifies { lines, late } = script else {
            if script == Script::Silent {
                // Hold the stream open until the helper drops it; anything the helper sent
                // here would have reached a server that never identified.
                let mut sink = Vec::new();
                let _ = server.read_to_end(&mut sink).await;
                if !sink.is_empty() {
                    log.lock().unwrap().received.insert(id, (sink, false));
                }
            }
            return;
        };
        for i in 0..lines {
            let _ = server
                .write_all(format!("banner line {i}\r\n").as_bytes())
                .await;
        }
        let _ = server.write_all(IDENT).await;
        let _ = server.write_all(b"after-ident").await;
        let mut buf = [0u8; 64];
        let n = server.read(&mut buf).await.unwrap_or(0);
        if n > 0 {
            let mut l = log.lock().unwrap();
            let entry = l.received.entry(id).or_insert_with(|| (Vec::new(), true));
            entry.0.extend_from_slice(&buf[..n]);
        }
        if !late {
            let _ = server.write_all(&buf[..n]).await;
        }
        // Dropping the stream ends the server side; a late failure is reported by the leg.
    }

    #[async_trait]
    impl LegDialer for Dialer {
        async fn dial(&self, route: &PlannedRoute, _: Duration) -> Result<Leg, DialFailure> {
            self.log.lock().unwrap().dialed.push(route.id.clone());
            let script = self.scripts[&route.id].clone();
            match script {
                Script::DialRefused => return Err(DialFailure::Refused),
                Script::DialTimeout => return Err(DialFailure::Timeout),
                Script::DialTerminal => return Err(DialFailure::Terminal),
                _ => {}
            }
            let (client, server) = tokio::io::duplex(64 * 1024);
            let ending: Option<Box<dyn LegEnding>> = match &script {
                Script::EofBeforeIdentification { terminal } => Some(Box::new(End(LegEnd {
                    success: false,
                    terminal: *terminal,
                }))),
                Script::Identifies { late: true, .. } => Some(Box::new(End(LegEnd {
                    success: false,
                    terminal: false,
                }))),
                _ => None,
            };
            tokio::spawn(serve(server, script, route.id.clone(), self.log.clone()));
            let (reader, writer) = tokio::io::split(client);
            Ok(Leg {
                reader: Box::new(reader),
                writer: Box::new(writer),
                ending,
            })
        }
    }

    fn planned(n: u8) -> PlannedRoute {
        PlannedRoute {
            id: RouteId::from_random_bytes([n; 16]),
            leg: LegPlan::Direct {
                host: "127.0.0.1".into(),
                port: 1,
            },
            identification_timeout: Duration::from_secs(10),
        }
    }

    /// Run the helper over `scripts` (route i has script i), with the client writing
    /// `b"hello"` and then waiting for the echo.
    fn run(scripts: &[Script]) -> (FailoverOutcome, Log, Vec<u8>, Vec<RouteHealthPayload>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let routes: Vec<PlannedRoute> =
                (0..scripts.len()).map(|i| planned(i as u8 + 1)).collect();
            let log = Arc::new(Mutex::new(Log::default()));
            let dialer = Dialer {
                scripts: routes
                    .iter()
                    .zip(scripts)
                    .map(|(r, s)| (r.id.clone(), s.clone()))
                    .collect(),
                log: log.clone(),
            };
            let (client_side, helper_side) = tokio::io::duplex(64 * 1024);
            let (helper_in, helper_out) = tokio::io::split(helper_side);
            let (mut client_read, mut client_write) = tokio::io::split(client_side);
            // The client writes first (as an OpenSSH client does), then reads until EOF.
            client_write.write_all(b"hello").await.unwrap();
            let reader = tokio::spawn(async move {
                let mut got = Vec::new();
                let _ = client_read.read_to_end(&mut got).await;
                got
            });
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let rec = recorded.clone();
            let record = move |p: RouteHealthPayload| {
                rec.lock().unwrap().push(p);
                async {}
            };
            let outcome = run_failover(
                &DestinationId::parse("lab").unwrap(),
                &AccountName::parse("deploy").unwrap(),
                &routes,
                &dialer,
                helper_in,
                helper_out,
                &FailoverConfig::default(),
                &record,
            )
            .await;
            drop(client_write);
            let got = reader.await.unwrap();
            let log = std::mem::take(&mut *log.lock().unwrap());
            let recorded = recorded.lock().unwrap().clone();
            (outcome, log, got, recorded)
        })
    }

    #[test]
    fn scan_finds_the_identification_within_bounds() {
        let c = FailoverConfig::default();
        assert_eq!(scan_identification(b"", &c), Scan::NeedMore);
        assert_eq!(scan_identification(b"SS", &c), Scan::NeedMore);
        assert_eq!(scan_identification(b"SSH-2.0-x", &c), Scan::NeedMore);
        assert_eq!(
            scan_identification(b"SSH-2.0-x\r\nKEX", &c),
            Scan::Identified { end: 11 }
        );
        assert_eq!(
            scan_identification(b"hello\r\nworld\nSSH-2.0-x\n", &c),
            Scan::Identified { end: 23 }
        );
        let many = "l\n".repeat(32) + "SSH-2.0-x\n";
        assert!(matches!(
            scan_identification(many.as_bytes(), &c),
            Scan::Identified { .. }
        ));
        let too_many = "l\n".repeat(33) + "SSH-2.0-x\n";
        assert_eq!(scan_identification(too_many.as_bytes(), &c), Scan::Overflow);
        let too_long = "x".repeat(8 * 1024 + 1);
        assert_eq!(scan_identification(too_long.as_bytes(), &c), Scan::Overflow);
        // The bound counts every pre-identification byte, line ends included.
        let long_lines = format!("{}\n", "x".repeat(8 * 1024 - 1)) + "SSH-2.0-x\n";
        assert!(matches!(
            scan_identification(long_lines.as_bytes(), &c),
            Scan::Identified { .. }
        ));
        let over = format!("{}\n", "x".repeat(8 * 1024)) + "SSH-2.0-x\n";
        assert_eq!(scan_identification(over.as_bytes(), &c), Scan::Overflow);
        let ident_too_long = format!("SSH-2.0-{}\n", "x".repeat(300));
        assert_eq!(
            scan_identification(ident_too_long.as_bytes(), &c),
            Scan::Overflow
        );
    }

    /// ADR-0012 §5.5: pre-identification lines are forwarded unchanged, in order, with the
    /// identification; the client's bytes reach the server only after it identified.
    #[test]
    fn pre_identification_lines_are_forwarded_in_order() {
        let (outcome, log, got, recorded) = run(&[Script::Identifies {
            lines: 3,
            late: false,
        }]);
        assert!(outcome.succeeded(), "{outcome:?}");
        let expected = b"banner line 0\r\nbanner line 1\r\nbanner line 2\r\nSSH-2.0-OpenSSH_test\r\nafter-identhello";
        assert_eq!(got, expected);
        assert_eq!(log.received.values().next().unwrap().0, b"hello");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, RouteEventKind::Health);
        assert_eq!(recorded[0].final_route, Some(planned(1).id));
    }

    /// A client-first server times out at the bound (`identification_timeout`) and the next
    /// approved route is tried; the result is `failed_over`.
    #[test]
    fn a_client_first_server_times_out_and_fails_over() {
        let (outcome, _, got, recorded) = run(&[
            Script::Silent,
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.succeeded());
        assert!(got.starts_with(IDENT));
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, RouteEventKind::FailedOver);
        assert_eq!(
            recorded[0].attempts,
            [
                RouteAttempt {
                    route: planned(1).id,
                    failure: Some(RouteFailureClass::IdentificationTimeout)
                },
                RouteAttempt {
                    route: planned(2).id,
                    failure: None
                },
            ]
        );
    }

    /// After the boundary a failure is terminal and recorded; no later route is tried.
    #[test]
    fn a_late_failure_is_terminal_and_recorded() {
        let (outcome, log, _, recorded) = run(&[
            Script::Identifies {
                lines: 0,
                late: true,
            },
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.late_failure);
        assert_eq!(
            log.dialed,
            [planned(1).id],
            "never failed over after the boundary"
        );
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[1].attempts,
            [RouteAttempt {
                route: planned(1).id,
                failure: Some(RouteFailureClass::TerminalAfterForwarding)
            }]
        );
        assert_eq!(recorded[1].final_route, Some(planned(1).id));
    }

    /// A host-key or authentication failure of a leg (while dialing or before
    /// identification) is never failed over.
    #[test]
    fn host_key_or_authentication_failures_are_never_failed_over() {
        for first in [
            Script::DialTerminal,
            Script::EofBeforeIdentification { terminal: true },
        ] {
            let (outcome, log, _, recorded) = run(&[
                first.clone(),
                Script::Identifies {
                    lines: 0,
                    late: false,
                },
            ]);
            assert_eq!(outcome.final_route, None, "{first:?}");
            assert_eq!(log.dialed, [planned(1).id], "{first:?}");
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].final_route, None);
        }
        // Without the host-key or authentication marker, a jump leg ending before
        // identification is failed over.
        let (outcome, log, _, _) = run(&[
            Script::EofBeforeIdentification { terminal: false },
            Script::Identifies {
                lines: 0,
                late: false,
            },
        ]);
        assert!(outcome.succeeded());
        assert_eq!(log.dialed.len(), 2);
    }

    fn script() -> impl Strategy<Value = Script> {
        prop_oneof![
            Just(Script::DialRefused),
            Just(Script::DialTimeout),
            Just(Script::DialTerminal),
            any::<bool>().prop_map(|terminal| Script::EofBeforeIdentification { terminal }),
            Just(Script::Silent),
            (0usize..40, any::<bool>())
                .prop_map(|(lines, late)| Script::Identifies { lines, late }),
        ]
    }

    /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (the crate's convention).
    fn config() -> ProptestConfig {
        use proptest::test_runner::{FileFailurePersistence, RngSeed};
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x4d30_3655_3561_0001);
        }
        c
    }

    proptest! {
        #![proptest_config(config())]

        /// m06-plan U5a property: failover never selects a route outside the approved
        /// (planned) list and never fires after the first forwarded byte; it stops at a
        /// host-key or authentication failure; client bytes reach a server only after that
        /// server identified; the health result names exactly the routes tried.
        #[test]
        fn failover_stays_on_approved_routes_and_before_the_first_byte(
            scripts in proptest::collection::vec(script(), 1..6)
        ) {
            let (outcome, log, _, recorded) = run(&scripts);
            let approved: Vec<RouteId> = (0..scripts.len()).map(|i| planned(i as u8 + 1).id).collect();
            // Only approved routes, each at most once, in preference order.
            prop_assert!(log.dialed.len() <= approved.len());
            prop_assert_eq!(&log.dialed[..], &approved[..log.dialed.len()]);
            // The walk stops at the first route that identified (the boundary) or failed
            // terminally; every earlier route failed before any byte was forwarded.
            for (i, id) in log.dialed.iter().enumerate() {
                let s = &scripts[i];
                let stops = matches!(s,
                    Script::DialTerminal
                    | Script::EofBeforeIdentification { terminal: true }
                    | Script::Identifies { lines: 0..=32, .. });
                if stops {
                    prop_assert_eq!(i, log.dialed.len() - 1, "route {} stops the walk", id);
                }
            }
            // Client bytes went only to an identified server.
            for (id, (bytes, identified)) in &log.received {
                prop_assert!(*identified);
                prop_assert_eq!(Some(id), outcome.final_route.as_ref());
                prop_assert!(bytes.len() <= 5);
            }
            // The health result: the routes tried, in order; at most one has no failure, and
            // it is the final route.
            let last = recorded.last().unwrap();
            let tried: Vec<RouteId> = last.attempts.iter().map(|a| a.route.clone()).collect();
            prop_assert_eq!(&tried, &log.dialed);
            prop_assert_eq!(&last.final_route, &outcome.final_route);
            let used: Vec<_> = last.attempts.iter().filter(|a| a.failure.is_none()).collect();
            prop_assert!(used.len() <= 1);
            if let Some(u) = used.first() {
                prop_assert_eq!(Some(&u.route), outcome.final_route.as_ref());
            }
        }
    }
}
