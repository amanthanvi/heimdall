//! The serve-side bridge (ADR-0012 §3.6; M06 U1): the logic behind `heimdall remote serve`.
//! The CLI subcommand that calls [`serve`] with its stdin, stdout and a connection to the
//! runtime's control endpoint is W2's wiring.
//!
//! * **Identity and home from argv only** ([`ServeArgs::parse`]): exactly `--client <cid>
//!   --home <abs>`. Nothing here reads the environment, so `SSH_ORIGINAL_COMMAND` and any
//!   `HEIMDALL_*` variable cannot name the client or the home. ⟨Reading 1⟩ Nor do the
//!   capabilities the remote side advertises: they are negotiation input only. The client
//!   ID the bridge declares is still only a claim until the runner runtime resolves it in
//!   its role table ([`crate::roles::resolve_session`]).
//! * **The remote side's hello is consumed** for version and capability negotiation only,
//!   and never forwarded. A remote hello that asserts a caller identity (a `remote_client`,
//!   `principal`, `role`, `caller` field) closes the session.
//! * **The bridge originates the only local hello**: `ClientHello{…, remote_client: <cid>}`,
//!   always `non_interactive` (a paired remote session is never attended, §3.10), with the
//!   remote side's protocol, schema and capabilities.
//! * **Relay**: every later remote frame is parsed, checked and re-serialized from its typed
//!   form (unknown fields dropped); every runtime frame is relayed as is.
//! * **Closing**: a second hello, or any frame asserting a caller identity, closes the
//!   session with `Goodbye{USAGE_ERROR}` and drops the runtime connection; so does a
//!   malformed or oversized frame. The session stays bound to the argv client for its whole
//!   lifetime: no later frame can change it.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use heimdall_contract::code::Code;
use heimdall_contract::ids::ClientId;
use heimdall_contract::ipc::{
    ClientHello, ClientMessage, HELLO_TIMEOUT_MS, MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES,
    PeerInfo, ServerMessage,
};
use heimdall_contract::request::InteractionMode;
use heimdall_ipc::frame::encode_frame;
use heimdall_ipc::session::parse_frame;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The bridge's peer name in the hello it originates.
pub const BRIDGE_NAME: &str = "heimdall-remote-serve";

/// Keys that assert a caller identity anywhere in a frame.
const IDENTITY_ANYWHERE: &[&str] = &["remote_client", "caller", "caller_context", "principal"];
/// Keys that assert a caller identity at a remote hello's top level.
const IDENTITY_HELLO_TOP: &[&str] = &["role"];
/// Keys that assert a caller identity at a later frame's top level (a request's own
/// `client` or `role` fields sit inside `request` and are not affected).
const IDENTITY_FRAME_TOP: &[&str] = &["role", "client", "identity"];

/// `remote serve`'s arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeArgs {
    /// The client the session is bound to.
    pub client: ClientId,
    /// The Heimdall home whose runtime the bridge connects to.
    pub home: PathBuf,
}

/// Why the arguments were refused. Fixed messages, never the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArgsError {
    /// An argument other than `--client` and `--home`, or a missing value.
    #[error("remote serve takes exactly --client <client> --home <absolute path>")]
    Usage,
    /// `--client` or `--home` given twice.
    #[error("an argument of remote serve was given twice")]
    Duplicate,
    /// The client ID is malformed.
    #[error("the client ID is malformed")]
    Client,
    /// The home is not an absolute path from the permitted set.
    #[error("the home is not an absolute path from the permitted set")]
    Home,
}

impl ServeArgs {
    /// Parse exactly `--client <cid> --home <abs>` (either order) from the arguments after
    /// `remote serve`. Nothing else is read.
    ///
    /// # Errors
    ///
    /// [`ArgsError`].
    pub fn parse<I, S>(args: I) -> Result<Self, ArgsError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut client = None;
        let mut home = None;
        let mut it = args.into_iter();
        while let Some(flag) = it.next() {
            let value = it.next().ok_or(ArgsError::Usage)?;
            let value = value.as_ref().to_str().ok_or(ArgsError::Usage)?.to_owned();
            let slot = match flag.as_ref().to_str() {
                Some("--client") => &mut client,
                Some("--home") => &mut home,
                _ => return Err(ArgsError::Usage),
            };
            if slot.replace(value).is_some() {
                return Err(ArgsError::Duplicate);
            }
        }
        let (Some(client), Some(home)) = (client, home) else {
            return Err(ArgsError::Usage);
        };
        let client = ClientId::parse(&client).map_err(|_| ArgsError::Client)?;
        if !client
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ArgsError::Client);
        }
        crate::line::check_abs_path(&home).map_err(|_| ArgsError::Home)?;
        Ok(Self {
            client,
            home: PathBuf::from(home),
        })
    }
}

/// Why the bridge closed a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Violation {
    /// No hello within the hello timeout.
    HelloTimeout,
    /// The first frame was not a hello.
    FirstFrameNotHello,
    /// A later frame carried a hello.
    SecondHello,
    /// A frame asserted a caller identity.
    IdentityAssertion,
    /// A frame was malformed or truncated.
    Malformed,
    /// A frame exceeded its limit.
    TooLarge,
}

impl Violation {
    fn message(self) -> &'static str {
        match self {
            Self::HelloTimeout => "no hello within the hello timeout",
            Self::FirstFrameNotHello => "the first frame must be a hello",
            Self::SecondHello => "the session already has its hello",
            Self::IdentityAssertion => "a frame asserted a caller identity",
            Self::Malformed => "a frame was malformed",
            Self::TooLarge => "a frame exceeded its limit",
        }
    }
}

/// How a bridged session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BridgeEnd {
    /// The remote side closed.
    RemoteClosed,
    /// The runtime closed (or its connection failed).
    LocalClosed,
    /// The runtime could not be reached (`SERVICE_UNAVAILABLE` was sent).
    LocalUnavailable,
    /// The runtime refused the hello (its answer was relayed).
    Rejected,
    /// The bridge closed the session (`USAGE_ERROR` was sent).
    Violation(Violation),
}

enum FrameRead {
    Eof,
    Frame(Vec<u8>),
    Bad(Violation),
}

/// Read one frame (u32 big-endian length, then the body), refusing a declared length above
/// `limit` before reading the body.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, limit: usize) -> FrameRead {
    let mut header = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match r.read(&mut header[got..]).await {
            Ok(0) if got == 0 => return FrameRead::Eof,
            Ok(0) | Err(_) => return FrameRead::Bad(Violation::Malformed),
            Ok(n) => got += n,
        }
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > limit {
        return FrameRead::Bad(Violation::TooLarge);
    }
    let mut body = vec![0u8; len];
    match r.read_exact(&mut body).await {
        Ok(_) => FrameRead::Frame(body),
        Err(_) => FrameRead::Bad(Violation::Malformed),
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    // Bodies here are at most `MAX_CONTROL_FRAME_BYTES`, so the length fits.
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn has_key_anywhere(v: &serde_json::Value, keys: &[&str]) -> bool {
    match v {
        serde_json::Value::Object(map) => map
            .iter()
            .any(|(k, child)| keys.contains(&k.as_str()) || has_key_anywhere(child, keys)),
        serde_json::Value::Array(items) => items.iter().any(|c| has_key_anywhere(c, keys)),
        _ => false,
    }
}

fn has_key_top(v: &serde_json::Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().any(|k| keys.contains(&k.as_str())))
}

/// Whether the remote side's hello asserts a caller identity.
#[must_use]
pub fn hello_asserts_identity(v: &serde_json::Value) -> bool {
    has_key_top(v, IDENTITY_HELLO_TOP) || has_key_anywhere(v, IDENTITY_ANYWHERE)
}

/// Whether a later frame asserts a caller identity.
#[must_use]
pub fn frame_asserts_identity(v: &serde_json::Value) -> bool {
    has_key_top(v, IDENTITY_FRAME_TOP) || has_key_anywhere(v, IDENTITY_ANYWHERE)
}

/// The hello the bridge sends the runtime for `client`, from the remote side's hello:
/// its protocol, schema and capabilities; the bridge's own peer name; always
/// `non_interactive`; the argv client.
#[must_use]
pub fn local_hello(remote: &ClientHello, client: &ClientId) -> ClientHello {
    ClientHello {
        protocol: remote.protocol,
        schema_version: remote.schema_version.clone(),
        client: PeerInfo {
            name: BRIDGE_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        capabilities: remote.capabilities.clone(),
        required: remote.required.iter().cloned().collect::<BTreeSet<_>>(),
        interaction: InteractionMode::NonInteractive,
        remote_client: Some(client.clone()),
    }
}

fn goodbye(code: Code, message: &str) -> Vec<u8> {
    encode_frame(
        &ServerMessage::Goodbye {
            code,
            message: message.to_owned(),
        },
        MAX_CONTROL_FRAME_BYTES,
    )
    .unwrap_or_default()
}

/// Check one remote hello frame: a `ClientHello` that asserts no identity.
fn remote_hello(frame: FrameRead) -> Result<Option<ClientHello>, Violation> {
    let body = match frame {
        FrameRead::Eof => return Ok(None),
        FrameRead::Bad(v) => return Err(v),
        FrameRead::Frame(b) => b,
    };
    let value: serde_json::Value = parse_frame(&body).map_err(|_| Violation::Malformed)?;
    if value.get("type").and_then(serde_json::Value::as_str) != Some("hello") {
        return Err(Violation::FirstFrameNotHello);
    }
    if hello_asserts_identity(&value) {
        return Err(Violation::IdentityAssertion);
    }
    match serde_json::from_value::<ClientMessage>(value) {
        Ok(ClientMessage::Hello(h)) => Ok(Some(h)),
        Ok(_) => Err(Violation::FirstFrameNotHello),
        Err(_) => Err(Violation::Malformed),
    }
}

/// Check and re-encode one later remote frame.
fn later_frame(body: &[u8]) -> Result<Vec<u8>, Violation> {
    let value: serde_json::Value = parse_frame(body).map_err(|_| Violation::Malformed)?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("hello") {
        return Err(Violation::SecondHello);
    }
    if frame_asserts_identity(&value) {
        return Err(Violation::IdentityAssertion);
    }
    let msg: ClientMessage = serde_json::from_value(value).map_err(|_| Violation::Malformed)?;
    if matches!(msg, ClientMessage::Hello(_)) {
        return Err(Violation::SecondHello);
    }
    encode_frame(&msg, MAX_CONTROL_FRAME_BYTES).map_err(|_| Violation::TooLarge)
}

/// Run one bridged session (module docs). `connect` is given the home from argv and
/// returns a connection to that home's runtime control endpoint.
///
/// # Errors
///
/// Never for a session-level event (each is a [`BridgeEnd`]); the result type leaves room
/// for the wiring's own errors.
pub async fn serve<RI, RO, L, C, F>(
    args: &ServeArgs,
    mut remote_in: RI,
    mut remote_out: RO,
    connect: C,
) -> std::io::Result<BridgeEnd>
where
    RI: AsyncRead + Unpin,
    RO: AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
    C: FnOnce(&Path) -> F,
    F: Future<Output = std::io::Result<L>>,
{
    let hello_timeout = Duration::from_millis(HELLO_TIMEOUT_MS);
    let close = |v: Violation| goodbye(Code::UsageError, v.message());

    // 1. The remote side's hello: consumed, never forwarded.
    let first = tokio::time::timeout(
        hello_timeout,
        read_frame(&mut remote_in, MAX_HELLO_FRAME_BYTES),
    )
    .await
    .unwrap_or(FrameRead::Bad(Violation::HelloTimeout));
    let remote = match remote_hello(first) {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(BridgeEnd::RemoteClosed),
        Err(v) => {
            let _ = remote_out.write_all(&close(v)).await;
            let _ = remote_out.flush().await;
            return Ok(BridgeEnd::Violation(v));
        }
    };

    // 2. The only local hello.
    let Ok(local) = connect(&args.home).await else {
        let _ = remote_out
            .write_all(&goodbye(
                Code::ServiceUnavailable,
                "the runtime is not reachable",
            ))
            .await;
        let _ = remote_out.flush().await;
        return Ok(BridgeEnd::LocalUnavailable);
    };
    let (mut local_rd, mut local_wr) = tokio::io::split(local);
    let hello = ClientMessage::Hello(local_hello(&remote, &args.client));
    let Ok(bytes) = encode_frame(&hello, MAX_HELLO_FRAME_BYTES) else {
        let _ = remote_out.write_all(&close(Violation::TooLarge)).await;
        return Ok(BridgeEnd::Violation(Violation::TooLarge));
    };
    if local_wr.write_all(&bytes).await.is_err() || local_wr.flush().await.is_err() {
        return Ok(BridgeEnd::LocalClosed);
    }
    let reply = tokio::time::timeout(
        hello_timeout,
        read_frame(&mut local_rd, MAX_HELLO_FRAME_BYTES),
    )
    .await
    .unwrap_or(FrameRead::Bad(Violation::HelloTimeout));
    let FrameRead::Frame(reply) = reply else {
        return Ok(BridgeEnd::LocalClosed);
    };
    let accepted = matches!(
        parse_frame::<ServerMessage>(&reply),
        Ok(ServerMessage::Hello(_))
    );
    if remote_out.write_all(&framed(&reply)).await.is_err() || remote_out.flush().await.is_err() {
        return Ok(BridgeEnd::RemoteClosed);
    }
    if !accepted {
        return Ok(BridgeEnd::Rejected);
    }

    // 3. The relay. One writer owns the remote side's output, so a closing goodbye is
    // never interleaved with a relayed frame.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let writer = async move {
        while let Some(bytes) = rx.recv().await {
            if remote_out.write_all(&bytes).await.is_err() || remote_out.flush().await.is_err() {
                break;
            }
        }
    };
    let up_tx = tx.clone();
    let up = async move {
        loop {
            match read_frame(&mut local_rd, MAX_CONTROL_FRAME_BYTES).await {
                FrameRead::Frame(body) => {
                    if up_tx.send(framed(&body)).await.is_err() {
                        return BridgeEnd::RemoteClosed;
                    }
                }
                FrameRead::Eof | FrameRead::Bad(_) => return BridgeEnd::LocalClosed,
            }
        }
    };
    let down = async {
        loop {
            match read_frame(&mut remote_in, MAX_CONTROL_FRAME_BYTES).await {
                FrameRead::Eof => return BridgeEnd::RemoteClosed,
                FrameRead::Bad(v) => return BridgeEnd::Violation(v),
                FrameRead::Frame(body) => match later_frame(&body) {
                    Ok(out) => {
                        if local_wr.write_all(&out).await.is_err()
                            || local_wr.flush().await.is_err()
                        {
                            return BridgeEnd::LocalClosed;
                        }
                    }
                    Err(v) => return BridgeEnd::Violation(v),
                },
            }
        }
    };
    let control = async move {
        let end = tokio::select! {
            e = up => e,
            e = down => e,
        };
        if let BridgeEnd::Violation(v) = end {
            let _ = tx.send(close(v)).await;
        }
        drop(tx);
        end
    };
    let (end, ()) = tokio::join!(control, writer);
    Ok(end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use heimdall_contract::envelope::Envelope;
    use heimdall_contract::ids::EnvironmentId;
    use heimdall_contract::ipc::{PrincipalInfo, ServerHello, capability};
    use heimdall_contract::remote::Role;
    use heimdall_contract::version::SchemaVersion;
    use tokio::io::DuplexStream;

    use super::*;

    const ARGV_HOME: &str = "/srv/runner/heimdall";

    fn cid(n: u8) -> ClientId {
        ClientId::from_random_bytes([n; 16])
    }

    fn args() -> ServeArgs {
        ServeArgs::parse([
            "--client".to_owned(),
            cid(0xa1).to_string(),
            "--home".to_owned(),
            ARGV_HOME.to_owned(),
        ])
        .unwrap()
    }

    /// A frame from a JSON value, as a remote peer would send it.
    fn raw(v: &serde_json::Value) -> Vec<u8> {
        framed(&serde_json::to_vec(v).unwrap())
    }

    fn hello_json() -> serde_json::Value {
        serde_json::json!({
            "type": "hello",
            "protocol": heimdall_contract::PROTOCOL_VERSION,
            "schema_version": SchemaVersion::current(),
            "client": {"name": "remote-controller", "version": "1"},
            "capabilities": [capability::OPERATIONS_V1, capability::REMOTE_CONTROL_V1],
            "required": [],
            "interaction": "interactive"
        })
    }

    async fn next(r: &mut DuplexStream) -> Option<serde_json::Value> {
        match read_frame(r, MAX_CONTROL_FRAME_BYTES).await {
            FrameRead::Frame(b) => Some(serde_json::from_slice(&b).unwrap()),
            _ => None,
        }
    }

    /// An in-process control endpoint that offers `remote-control/1`: it accepts one hello
    /// naming a remote client, then answers each request with its kind. It records every
    /// frame it received.
    async fn test_server(mut end: DuplexStream, seen: Arc<Mutex<Vec<serde_json::Value>>>) {
        let Some(hello) = next(&mut end).await else {
            return;
        };
        seen.lock().unwrap().push(hello.clone());
        let reply = ServerMessage::Hello(ServerHello {
            protocol: heimdall_contract::PROTOCOL_VERSION,
            schema_version: SchemaVersion::current(),
            server: PeerInfo {
                name: "test-runtime".into(),
                version: "0".into(),
            },
            capabilities: [capability::OPERATIONS_V1, capability::REMOTE_CONTROL_V1]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            principal: PrincipalInfo::OsUserUnix { uid: 1000 },
            environment_id: EnvironmentId::from_random_bytes([5; 16]),
            role: Some(Role::Owner),
            remote_client: None,
        });
        end.write_all(&encode_frame(&reply, MAX_HELLO_FRAME_BYTES).unwrap())
            .await
            .unwrap();
        while let Some(frame) = next(&mut end).await {
            seen.lock().unwrap().push(frame.clone());
            if let Some(seq) = frame.get("seq").and_then(serde_json::Value::as_u64) {
                let kind = frame["request"]["op"].clone();
                let resp = ServerMessage::Response {
                    in_reply_to: seq,
                    envelope: Envelope::ok(serde_json::json!({ "op": kind })),
                };
                if end
                    .write_all(&encode_frame(&resp, MAX_CONTROL_FRAME_BYTES).unwrap())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }

    struct Harness {
        remote: DuplexStream,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
        homes: Arc<Mutex<Vec<PathBuf>>>,
        bridge: tokio::task::JoinHandle<BridgeEnd>,
    }

    fn start() -> Harness {
        let (remote, bridge_remote) = tokio::io::duplex(1 << 20);
        let (bridge_local, server_end) = tokio::io::duplex(1 << 20);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let homes = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn(test_server(server_end, Arc::clone(&seen)));
        let h = Arc::clone(&homes);
        let a = args();
        let bridge = tokio::spawn(async move {
            let (ri, ro) = tokio::io::split(bridge_remote);
            serve(&a, ri, ro, move |home: &Path| {
                h.lock().unwrap().push(home.to_owned());
                async move { Ok(bridge_local) }
            })
            .await
            .unwrap()
        });
        Harness {
            remote,
            seen,
            homes,
            bridge,
        }
    }

    fn request(seq: u64) -> serde_json::Value {
        serde_json::json!({"type": "request", "seq": seq, "request": {"op": "inspect", "subject": "capabilities"}})
    }

    async fn happy_path() {
        let mut h = start();
        h.remote.write_all(&raw(&hello_json())).await.unwrap();
        let server_hello = next(&mut h.remote).await.unwrap();
        assert_eq!(server_hello["type"], "hello");
        h.remote.write_all(&raw(&request(1))).await.unwrap();
        let resp = next(&mut h.remote).await.unwrap();
        assert_eq!(resp["in_reply_to"], 1);
        assert_eq!(resp["envelope"]["data"]["op"], "inspect");
        drop(h.remote);
        assert_eq!(h.bridge.await.unwrap(), BridgeEnd::RemoteClosed);
        let seen = h.seen.lock().unwrap().clone();
        // The runtime saw exactly one hello, the bridge's: argv's client, non-interactive,
        // the bridge's own peer name; then the relayed request.
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen[0]["type"], "hello");
        assert_eq!(seen[0]["remote_client"], cid(0xa1).as_str());
        assert_eq!(seen[0]["interaction"], "non_interactive");
        assert_eq!(seen[0]["client"]["name"], BRIDGE_NAME);
        assert_eq!(seen[1], request(1));
        assert_eq!(
            h.homes.lock().unwrap().clone(),
            vec![PathBuf::from(ARGV_HOME)]
        );
    }

    #[tokio::test]
    async fn bridge_originates_the_only_hello_and_relays() {
        happy_path().await;
    }

    async fn closes_on(frame: serde_json::Value, why: Violation) {
        let mut h = start();
        h.remote.write_all(&raw(&hello_json())).await.unwrap();
        let _ = next(&mut h.remote).await.unwrap();
        h.remote.write_all(&raw(&request(1))).await.unwrap();
        let _ = next(&mut h.remote).await.unwrap();
        h.remote.write_all(&raw(&frame)).await.unwrap();
        let bye = next(&mut h.remote).await.unwrap();
        assert_eq!(bye["type"], "goodbye");
        assert_eq!(bye["code"], "USAGE_ERROR");
        assert_eq!(h.bridge.await.unwrap(), BridgeEnd::Violation(why));
        assert!(next(&mut h.remote).await.is_none(), "the session is closed");
        let seen = h.seen.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            2,
            "the offending frame never reached the runtime"
        );
    }

    #[tokio::test]
    async fn a_second_hello_closes_the_session() {
        closes_on(hello_json(), Violation::SecondHello).await;
    }

    #[tokio::test]
    async fn an_identity_frame_closes_the_session() {
        let mut top = request(2);
        top["remote_client"] = serde_json::json!(cid(0xb2).as_str());
        closes_on(top, Violation::IdentityAssertion).await;
        let mut role = request(3);
        role["role"] = serde_json::json!("owner");
        closes_on(role, Violation::IdentityAssertion).await;
        let mut nested = request(4);
        nested["request"]["principal"] = serde_json::json!({"kind": "unix_user", "uid": 0});
        closes_on(nested, Violation::IdentityAssertion).await;
    }

    #[tokio::test]
    async fn a_remote_hello_naming_a_client_is_refused_before_any_local_hello() {
        let mut h = start();
        let mut hello = hello_json();
        hello["remote_client"] = serde_json::json!(cid(0xb2).as_str());
        h.remote.write_all(&raw(&hello)).await.unwrap();
        let bye = next(&mut h.remote).await.unwrap();
        assert_eq!(bye["code"], "USAGE_ERROR");
        assert_eq!(
            h.bridge.await.unwrap(),
            BridgeEnd::Violation(Violation::IdentityAssertion)
        );
        assert!(
            h.homes.lock().unwrap().is_empty(),
            "the runtime was never contacted"
        );
        assert!(h.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_first_frame_must_be_a_hello() {
        let mut h = start();
        h.remote.write_all(&raw(&request(1))).await.unwrap();
        let bye = next(&mut h.remote).await.unwrap();
        assert_eq!(bye["code"], "USAGE_ERROR");
        assert_eq!(
            h.bridge.await.unwrap(),
            BridgeEnd::Violation(Violation::FirstFrameNotHello)
        );
    }

    #[test]
    fn arguments_are_exactly_client_and_home() {
        let c = cid(1).to_string();
        let ok = ServeArgs::parse(["--home", ARGV_HOME, "--client", &c]).unwrap();
        assert_eq!(ok.client, cid(1));
        assert_eq!(ok.home, PathBuf::from(ARGV_HOME));
        for bad in [
            vec!["--client", &c],
            vec!["--client", &c, "--home"],
            vec!["--client", &c, "--home", ARGV_HOME, "--client", &c],
            vec!["--client", &c, "--home", "relative/home"],
            vec!["--client", &c, "--home", "/a b"],
            vec!["--client", "inv_00", "--home", ARGV_HOME],
            vec!["--client", "cl_a:b", "--home", ARGV_HOME],
            vec!["--client", &c, "--home", ARGV_HOME, "--extra", "x"],
        ] {
            assert!(ServeArgs::parse(bad.clone()).is_err(), "{bad:?}");
        }
    }

    /// The bridge ignores `HEIMDALL_*` and `SSH_ORIGINAL_COMMAND`: the same session, run in a
    /// child of this test binary whose environment names another client and home, still
    /// binds argv's client and connects to argv's home. (A child process, because setting
    /// the environment in a threaded test process is unsound.)
    #[test]
    fn bridge_identity_ignores_environment() {
        if std::env::var_os("HM_REMOTE_BRIDGE_ENV_CHILD").is_some() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(happy_path());
            return;
        }
        let other = cid(0xee).to_string();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bridge::tests::bridge_identity_ignores_environment",
                "--test-threads=1",
            ])
            .env("HM_REMOTE_BRIDGE_ENV_CHILD", "1")
            .env(
                "SSH_ORIGINAL_COMMAND",
                format!("exec heimdall remote serve --client {other} --home /elsewhere"),
            )
            .env("HEIMDALL_CLIENT", &other)
            .env("HEIMDALL_REMOTE_CLIENT", &other)
            .env("HEIMDALL_HOME", "/elsewhere")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "the child session bound argv's identity");
    }
}
