//! Control-endpoint sessions: hello negotiation, request dispatch, subscriptions
//! (ADR-0006 §2.3–§2.4).

use std::collections::BTreeSet;

use heimdall_contract::envelope::{Envelope, ErrorData};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::ipc::{ClientHello, PeerInfo, PrincipalInfo, ServerHello, capability};
use heimdall_contract::{Code, PROTOCOL_VERSION, SchemaVersion};

/// Capabilities this build serves.
#[must_use]
pub fn server_capabilities() -> BTreeSet<String> {
    [
        capability::OPERATIONS_V1,
        capability::EVENTS_V1,
        capability::OWNER_POLICY_V1,
        capability::SCHEMA_DISCOVERY_V1,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// Negotiate a client hello. Pure: the transport has already authenticated the
/// peer and supplies `principal`.
pub fn negotiate(
    hello: &ClientHello,
    principal: PrincipalInfo,
    environment: EnvironmentId,
    server: PeerInfo,
) -> Result<ServerHello, Box<Envelope<ErrorData>>> {
    use heimdall_contract::envelope::{EffectStatus, ErrorDetail, NextAction};

    let reject = |code: Code, message: &str| {
        Box::new(Envelope::failed(
            None,
            ErrorDetail {
                code,
                effect_status: EffectStatus::None,
                retryable: false,
                resource: None,
                next: NextAction::for_code(code),
                message: message.to_owned(),
            },
        ))
    };

    if hello.protocol != PROTOCOL_VERSION {
        return Err(reject(
            Code::SchemaUnsupported,
            "unsupported IPC protocol version",
        ));
    }
    if !hello.schema_version.is_supported() {
        return Err(reject(
            Code::SchemaUnsupported,
            "unsupported schema major version",
        ));
    }
    let offered = server_capabilities();
    if let Some(missing) = hello.required.iter().find(|r| !offered.contains(*r)) {
        let _ = missing;
        return Err(reject(
            Code::SchemaUnsupported,
            "a required capability is not available",
        ));
    }
    let capabilities: BTreeSet<String> =
        offered.intersection(&hello.capabilities).cloned().collect();
    Ok(ServerHello {
        protocol: PROTOCOL_VERSION,
        schema_version: SchemaVersion::current(),
        server,
        capabilities,
        principal,
        environment_id: environment,
    })
}

/// Per-connection bookkeeping limits (ADR-0006 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// In-flight requests.
    pub max_inflight: usize,
    /// Subscriptions.
    pub max_subscriptions: usize,
    /// Hello deadline.
    pub hello_timeout_ms: u64,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_inflight: heimdall_contract::ipc::MAX_INFLIGHT_REQUESTS_PER_CONNECTION,
            max_subscriptions: heimdall_contract::ipc::MAX_SUBSCRIPTIONS_PER_CONNECTION,
            hello_timeout_ms: heimdall_contract::ipc::HELLO_TIMEOUT_MS,
        }
    }
}

/// Server side of one control connection. Generic over the stream so Unix and
/// Windows share it; the dispatcher is supplied by the runtime.
#[derive(Debug)]
pub struct ControlConnection<S> {
    stream: S,
    limits: ConnectionLimits,
}

impl<S> ControlConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Wrap an authenticated stream.
    #[must_use]
    pub fn new(stream: S, limits: ConnectionLimits) -> Self {
        Self { stream, limits }
    }

    /// Run the hello exchange, then the request/subscription loop until the peer
    /// closes, a limit trips, or `shutdown` fires. Backpressure on a subscription
    /// emits a `ResyncRequired` event rather than buffering without bound.
    pub async fn serve<D>(
        self,
        _principal: PrincipalInfo,
        _dispatcher: D,
        _shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<(), crate::frame::FrameError>
    where
        D: Dispatcher,
    {
        let _ = (&self.stream, self.limits);
        todo!("M01-T04: framed loop with bounded in-flight requests and subscriptions")
    }
}

/// What the runtime provides to a connection.
#[async_trait::async_trait]
pub trait Dispatcher: Send + Sync {
    /// Handle one request for the authenticated principal.
    async fn dispatch(
        &self,
        principal: &PrincipalInfo,
        request: heimdall_contract::request::Request,
    ) -> Envelope<serde_json::Value>;
    /// Subscribe to events (returns the start cursor and a receiver).
    async fn subscribe(
        &self,
        principal: &PrincipalInfo,
        filter: heimdall_contract::event::EventFilter,
        from: Option<heimdall_contract::event::Cursor>,
    ) -> Result<
        (
            heimdall_contract::event::Cursor,
            tokio::sync::broadcast::Receiver<std::sync::Arc<heimdall_contract::event::Event>>,
        ),
        Box<Envelope<ErrorData>>,
    >;
}

/// Client side: connect, hello, request, subscribe.
#[derive(Debug)]
pub struct ControlClient<S> {
    stream: S,
    hello: ServerHello,
}

impl<S> ControlClient<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Perform the hello exchange on a connected stream.
    pub async fn handshake(
        _stream: S,
        _client: PeerInfo,
        _required: BTreeSet<String>,
    ) -> Result<Self, crate::frame::FrameError> {
        todo!("M01-T04/T06")
    }

    /// Negotiated server hello.
    #[must_use]
    pub fn server(&self) -> &ServerHello {
        &self.hello
    }

    /// Send one request and await its response.
    pub async fn request(
        &mut self,
        _request: heimdall_contract::request::Request,
    ) -> Result<Envelope<serde_json::Value>, crate::frame::FrameError> {
        let _ = &self.stream;
        todo!("M01-T06")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn hello(protocol: u16, schema: &str, required: &[&str]) -> ClientHello {
        ClientHello {
            protocol,
            schema_version: SchemaVersion(schema.to_owned()),
            client: PeerInfo {
                name: "t".into(),
                version: "0".into(),
            },
            capabilities: server_capabilities(),
            required: required.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn env() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    #[test]
    fn rejects_wrong_major_and_missing_required_capability() {
        let p = PrincipalInfo::OsUserUnix { uid: 501 };
        let srv = PeerInfo {
            name: "heimdall".into(),
            version: "0".into(),
        };
        let ok = negotiate(
            &hello(PROTOCOL_VERSION, "1", &[]),
            p.clone(),
            env(),
            srv.clone(),
        );
        assert!(ok.is_ok());
        let bad_schema = negotiate(
            &hello(PROTOCOL_VERSION, "2", &[]),
            p.clone(),
            env(),
            srv.clone(),
        );
        assert_eq!(bad_schema.unwrap_err().code, Code::SchemaUnsupported);
        let bad_cap = negotiate(&hello(PROTOCOL_VERSION, "1", &["nope/9"]), p, env(), srv);
        assert_eq!(bad_cap.unwrap_err().code, Code::SchemaUnsupported);
    }
}
