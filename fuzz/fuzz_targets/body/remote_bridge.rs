//! Boundary 13 (ADR-0014 §2.1), M06's bridge frames: the byte stream a paired client sends
//! `heimdall remote serve`, fed to the public `heimdall_remote::bridge::serve` as the remote
//! side, against an in-process runtime stub that accepts the bridge's own hello and then
//! reads everything the bridge relays until it closes. The remote hello's checks, every
//! later frame's parse, identity check and re-encoding, and the frame limits (16 KiB hello,
//! 1 MiB after) are the bridge's own code.
//!
//! Shared by the fuzz target `remote_bridge` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`, so the stable toolchain compiles this exact code.

use std::path::{Path, PathBuf};

use heimdall_contract::ids::{ClientId, EnvironmentId};
use heimdall_contract::ipc::{
    MAX_HELLO_FRAME_BYTES, PeerInfo, PrincipalInfo, ServerHello, ServerMessage, capability,
};
use heimdall_contract::remote::Role;
use heimdall_contract::version::SchemaVersion;
use heimdall_ipc::frame::encode_frame;
use heimdall_remote::bridge::{BridgeEnd, ServeArgs, serve};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

thread_local! {
    /// One current-thread runtime per thread (libFuzzer runs one; the seed test many).
    static RUNTIME: Option<tokio::runtime::Runtime> = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .ok();
}

/// Run one bridged session over `data`; `None` only when no runtime could be built.
pub fn run(data: &[u8]) -> Option<BridgeEnd> {
    RUNTIME.with(|rt| rt.as_ref().map(|rt| rt.block_on(session(data))))?
}

/// The runtime's answer to the bridge's hello, framed.
fn server_hello() -> Option<Vec<u8>> {
    let hello = ServerMessage::Hello(ServerHello {
        protocol: heimdall_contract::PROTOCOL_VERSION,
        schema_version: SchemaVersion::current(),
        server: PeerInfo {
            name: "fuzz-runtime".to_owned(),
            version: "0".to_owned(),
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
    encode_frame(&hello, MAX_HELLO_FRAME_BYTES).ok()
}

async fn session(data: &[u8]) -> Option<BridgeEnd> {
    let args = ServeArgs {
        client: ClientId::from_random_bytes([0xa1; 16]),
        home: PathBuf::from("/hm-fuzz/runner/heimdall"),
    };
    let hello = server_hello()?;
    let (bridge_side, runtime_side) = tokio::io::duplex(1 << 16);
    let bridge = serve(&args, data, tokio::io::sink(), move |_: &Path| async move {
        Ok::<_, std::io::Error>(bridge_side)
    });
    let (end, ()) = tokio::join!(bridge, runtime_stub(runtime_side, &hello));
    end.ok()
}

/// Read the bridge's hello (a u32 big-endian length, then the body), answer `hello`, then
/// read and drop whatever is relayed until the bridge closes its side.
async fn runtime_stub(mut end: DuplexStream, hello: &[u8]) {
    let mut header = [0u8; 4];
    if end.read_exact(&mut header).await.is_err() {
        return;
    }
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if len > MAX_HELLO_FRAME_BYTES {
        return;
    }
    let mut body = vec![0u8; len];
    if end.read_exact(&mut body).await.is_err() || end.write_all(hello).await.is_err() {
        return;
    }
    let mut sink = [0u8; 8192];
    while matches!(end.read(&mut sink).await, Ok(n) if n > 0) {}
}
