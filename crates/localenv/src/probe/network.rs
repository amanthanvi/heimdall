//! The `network` level: connect and read the server banner only; no key exchange
//! (m02-plan U3).
//!
//! One TCP connection to `host:port` (the first address the name resolves to), then
//! the identification line (RFC 4253 §4.2): lines are read until one starts with
//! `SSH-`, at most 8 KiB in all, then the connection is closed. Heimdall writes
//! nothing to the socket, so the server receives no identification string and no key
//! exchange byte. The whole level is bounded at 5 s. Aliases routed through
//! `ProxyJump` or `ProxyCommand` are not probed (the doctor reports them
//! undetermined).

use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::code::Code;
use heimdall_contract::doctor::{ExcludedEffect, ProbeOutcome, ProbeRecord};
use heimdall_contract::provider::ProbeLevel;

use super::ProbeContext;

/// The level's bound.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

/// Bytes read before giving up on an identification line.
pub const MAX_BANNER_BYTES: usize = 8 * 1024;

/// Read the SSH banner of `host:port`.
#[must_use]
pub fn banner(ctx: &ProbeContext<'_>, host: &str, port: u16) -> ProbeRecord {
    banner_observed(ctx, host, port).0
}

/// [`banner`], with the identification line (printable ASCII only, at most 255
/// characters) when one was read.
#[must_use]
pub fn banner_observed(
    ctx: &ProbeContext<'_>,
    host: &str,
    port: u16,
) -> (ProbeRecord, Option<String>) {
    let _ = ctx;
    let started_at = Timestamp::now();
    let t0 = Instant::now();
    let mut record = super::record(ProbeLevel::Network, &format!("{host}:{port}"), started_at);
    record.effects_excluded.remove(&ExcludedEffect::Network);
    let result = read_banner(host, port, t0 + NETWORK_TIMEOUT);
    record.duration_ms = super::elapsed_ms(t0);
    match result {
        Ok(line) => (record, Some(line)),
        Err(BannerError::Timeout) => {
            record.outcome = ProbeOutcome::Timeout;
            (record, None)
        }
        Err(BannerError::Unreachable | BannerError::NoBanner) => {
            record.outcome = ProbeOutcome::Failed;
            record.code = Some(Code::DestinationUnreachable);
            (record, None)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BannerError {
    Timeout,
    Unreachable,
    NoBanner,
}

/// Resolve `host` within `deadline` (wave-2 review X05; ADR-0007 §12.18 item 5): name
/// resolution is part of the network level's bound, like connect and the banner read.
///
/// A literal address needs no resolver. A name is resolved on a helper thread that the
/// probe waits for only until `deadline`; the system resolver cannot be cancelled, so on
/// a timeout the thread is left to finish on its own. It owns nothing but the lookup and
/// exits when the resolver returns.
fn resolve_within<F>(
    host: &str,
    port: u16,
    deadline: Instant,
    resolve: F,
) -> Result<SocketAddr, BannerError>
where
    F: FnOnce(String, u16) -> std::io::Result<Option<SocketAddr>> + Send + 'static,
{
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        return Err(BannerError::Timeout);
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let name = host.to_owned();
    std::thread::Builder::new()
        .name("hm-probe-resolve".to_owned())
        .spawn(move || {
            let _ = tx.send(resolve(name, port));
        })
        .map_err(|_| BannerError::Unreachable)?;
    match rx.recv_timeout(budget) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(BannerError::Unreachable)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(BannerError::Timeout),
    }
}

/// The system resolver: the first address for `host:port`.
fn system_resolve(host: String, port: u16) -> std::io::Result<Option<SocketAddr>> {
    Ok((host.as_str(), port).to_socket_addrs()?.next())
}

fn read_banner(host: &str, port: u16, deadline: Instant) -> Result<String, BannerError> {
    let addr = resolve_within(host, port, deadline, system_resolve)?;
    let left = |d: Instant| d.saturating_duration_since(Instant::now());
    let budget = left(deadline);
    if budget.is_zero() {
        return Err(BannerError::Timeout);
    }
    let mut stream = TcpStream::connect_timeout(&addr, budget).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            BannerError::Timeout
        } else {
            BannerError::Unreachable
        }
    })?;
    let mut got: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let budget = left(deadline);
        if budget.is_zero() {
            return Err(BannerError::Timeout);
        }
        stream
            .set_read_timeout(Some(budget))
            .map_err(|_| BannerError::Unreachable)?;
        let n = match stream.read(&mut buf) {
            Ok(0) => return Err(BannerError::NoBanner),
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(BannerError::Timeout);
            }
            Err(_) => return Err(BannerError::Unreachable),
        };
        got.extend_from_slice(&buf[..n]);
        let mut start = 0;
        while let Some(pos) = got[start..].iter().position(|&b| b == b'\n') {
            let line = &got[start..start + pos];
            if line.starts_with(b"SSH-") {
                let text: String = line
                    .iter()
                    .copied()
                    .filter(|b| (0x20..0x7f).contains(b))
                    .take(255)
                    .map(char::from)
                    .collect();
                return Ok(text);
            }
            start += pos + 1;
        }
        if got.len() >= MAX_BANNER_BYTES {
            return Err(BannerError::NoBanner);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn reads_the_identification_line_after_preamble_and_writes_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"preamble line\r\nSSH-2.0-HmTest_1.0\r\n")
                .unwrap();
            s.set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
            rest
        });
        let line = read_banner("127.0.0.1", port, Instant::now() + NETWORK_TIMEOUT).unwrap();
        assert_eq!(line, "SSH-2.0-HmTest_1.0");
        assert!(server.join().unwrap().is_empty(), "the client sent bytes");
    }

    #[test]
    fn a_silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
        let started = Instant::now();
        let r = read_banner(
            "127.0.0.1",
            port,
            Instant::now() + Duration::from_millis(300),
        );
        assert_eq!(r, Err(BannerError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(held.join());
    }

    /// X05 (ADR-0007 §12.18 item 5): a resolver slower than the deadline cannot hold the
    /// probe past it. The stand-in resolver sleeps far beyond the 200 ms budget.
    #[test]
    fn a_slow_resolver_is_bounded_by_the_deadline() {
        let started = Instant::now();
        let r = resolve_within(
            "slow.invalid",
            22,
            started + Duration::from_millis(200),
            |_, _| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(None)
            },
        );
        assert_eq!(r, Err(BannerError::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the probe waited for the resolver"
        );
    }

    #[test]
    fn a_literal_address_needs_no_resolver_and_a_failed_lookup_is_unreachable() {
        let far = Instant::now() + NETWORK_TIMEOUT;
        let lit = resolve_within("::1", 22, far, |_, _| panic!("resolver called")).unwrap();
        assert_eq!(
            lit,
            SocketAddr::new(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), 22)
        );
        let none = resolve_within("none.invalid", 22, far, |_, _| Ok(None));
        assert_eq!(none, Err(BannerError::Unreachable));
        let err = resolve_within("err.invalid", 22, far, |_, _| {
            Err(std::io::Error::other("lookup failed"))
        });
        assert_eq!(err, Err(BannerError::Unreachable));
    }
}
