//! The serving side's target (ADR-0012 §2.3 item 2): `127.0.0.1:<port>` or `[::1]:<port>`
//! only, and the outbound connect to it is bound explicitly to the same loopback address
//! before `connect()`, so no wildcard local state can exist (G06 §8, Windows W1 run 1's
//! unexplained `0.0.0.0` reading).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

/// Bound on connecting to the loopback target.
pub const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A target that is not `127.0.0.1` or `::1` with a nonzero port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonLoopbackTarget;

impl std::fmt::Display for NonLoopbackTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the serve target must be 127.0.0.1 or ::1 with a nonzero port")
    }
}

impl std::error::Error for NonLoopbackTarget {}

/// A validated serve target: exactly `127.0.0.1` or `::1`, nonzero port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopbackTarget(SocketAddr);

impl LoopbackTarget {
    /// Validates `addr`. Any other address is refused, including the rest of `127.0.0.0/8`
    /// and the IPv4-mapped `::ffff:127.0.0.1`.
    ///
    /// # Errors
    ///
    /// [`NonLoopbackTarget`] for anything but `127.0.0.1:<port>` or `[::1]:<port>`, port > 0.
    pub fn new(addr: SocketAddr) -> Result<Self, NonLoopbackTarget> {
        let exact = match addr.ip() {
            IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
            IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
        };
        if exact && addr.port() != 0 {
            Ok(Self(addr))
        } else {
            Err(NonLoopbackTarget)
        }
    }

    /// The target address.
    #[must_use]
    pub fn addr(self) -> SocketAddr {
        self.0
    }

    /// The loopback address the outbound socket binds before connecting (port 0).
    #[must_use]
    pub fn local_bind(self) -> SocketAddr {
        SocketAddr::new(self.0.ip(), 0)
    }

    /// A TCP socket of the target's family, already bound to the loopback address (port 0)
    /// and not yet connected.
    ///
    /// # Errors
    ///
    /// The socket's creation or bind failed.
    pub fn bound_socket(self) -> io::Result<TcpSocket> {
        let socket = if self.0.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.bind(self.local_bind())?;
        Ok(socket)
    }

    /// Connects to the target from a socket bound to loopback before `connect()`, within
    /// [`TARGET_CONNECT_TIMEOUT`]. Fails closed if the connected socket's local address is
    /// somehow not loopback.
    ///
    /// # Errors
    ///
    /// The bind or connect failed, timed out, or the local address was not loopback.
    pub async fn connect(self) -> io::Result<TcpStream> {
        let socket = self.bound_socket()?;
        let stream = tokio::time::timeout(TARGET_CONNECT_TIMEOUT, socket.connect(self.0))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "target connect timed out"))??;
        if !stream.local_addr()?.ip().is_loopback() {
            return Err(io::Error::other("target socket is not bound to loopback"));
        }
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// ADR-0012 §2.3 item 2: a target other than `127.0.0.1` or `::1` is refused.
    #[test]
    fn non_loopback_target_is_refused() {
        for bad in [
            "192.0.2.1:22",
            "0.0.0.0:22",
            "[::]:22",
            "127.0.0.2:22",
            "[::ffff:127.0.0.1]:22",
            "[2001:db8::1]:22",
            "127.0.0.1:0",
            "[::1]:0",
        ] {
            assert_eq!(
                LoopbackTarget::new(sa(bad)),
                Err(NonLoopbackTarget),
                "{bad}"
            );
        }
        assert_eq!(
            crate::admission::ServeConfigError::from(NonLoopbackTarget).reason(),
            "transport_unavailable"
        );
        assert_eq!(
            LoopbackTarget::new(sa("127.0.0.1:22")).unwrap().addr(),
            sa("127.0.0.1:22")
        );
        assert_eq!(
            LoopbackTarget::new(sa("[::1]:22")).unwrap().local_bind(),
            sa("[::1]:0")
        );
    }

    /// ADR-0012 §2.3 item 2: the target socket is bound to loopback before `connect()`, and
    /// the connected socket's local address is loopback.
    #[tokio::test]
    async fn target_socket_binds_loopback_before_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = LoopbackTarget::new(listener.local_addr().unwrap()).unwrap();
        // Before connect: already bound to 127.0.0.1 with an assigned port.
        let pre = target.bound_socket().unwrap();
        let local = pre.local_addr().unwrap();
        assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(local.port(), 0);
        drop(pre);
        let (stream, accepted) = tokio::join!(target.connect(), listener.accept());
        let stream = stream.unwrap();
        let (_peer_stream, peer_addr) = accepted.unwrap();
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(peer_addr, stream.local_addr().unwrap());
    }
}
