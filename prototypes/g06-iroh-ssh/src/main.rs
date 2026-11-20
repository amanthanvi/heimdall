//! Disposable G06 probe: ordinary OpenSSH over an embedded iroh 1.4.2 endpoint.
//!
//! Wire protocol: the Pigeons protocol (ALPN `/pigeons/0`): the dialer opens one bidirectional
//! stream and both sides copy raw SSH bytes. Nothing else is framed. That keeps the probe
//! interoperable with a stock `pigeons roost` / `pigeons fly` (iroh-pigeons 0.2.3).
//!
//! Subcommands (all output is one JSON object per line on stderr; stdout carries only SSH bytes):
//!   keygen <path>                 write a fresh 32-byte secret key (mode 0600), print the endpoint id
//!   id <path>                     print the endpoint id of a key file
//!   serve   COMMON --target <ip:port> [--allow <endpoint-id>]...
//!   connect COMMON --peer <endpoint-id> [--addr <ip:port>] [--peer-relay <url>] [--timeout-ms <n>]
//! COMMON: --key <path|ephemeral> --bind <ip:port|none> --relay <disabled|n0|URL> --lookup <none|n0>
//!         --portmapper <on|off>
//!
//! Exit codes: 0 done, 2 usage, 3 connect failed or timed out, 4 refused by the peer's allowlist,
//! 5 key file problem, 6 endpoint bind failed.
//!
//! Not production code. Never imported by production (AGENTS.md).

use std::io::Write as _;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use iroh::endpoint::{PortmapperConfig, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, NetReportConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const ALPN: &[u8] = b"/pigeons/0";
const REFUSED: u32 = 403;

fn log(obj: &str) {
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "{obj}");
}

fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect()
}

struct Common {
    key: String,
    bind: String,
    relay: String,
    lookup: String,
    portmapper: bool,
}

fn parse(args: &[String]) -> Result<(Common, Vec<(String, String)>), String> {
    let mut c = Common {
        key: "ephemeral".into(),
        bind: "127.0.0.1:0".into(),
        relay: "disabled".into(),
        lookup: "none".into(),
        portmapper: false,
    };
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let k = args[i].clone();
        let v = args.get(i + 1).cloned().ok_or(format!("missing value for {k}"))?;
        match k.as_str() {
            "--key" => c.key = v,
            "--bind" => c.bind = v,
            "--relay" => c.relay = v,
            "--lookup" => c.lookup = v,
            "--portmapper" => c.portmapper = v == "on",
            _ if k.starts_with("--") => rest.push((k, v)),
            _ => return Err(format!("unexpected argument {k}")),
        }
        i += 2;
    }
    Ok((c, rest))
}

fn read_key(path: &str) -> Result<SecretKey, String> {
    if path == "ephemeral" {
        return Ok(SecretKey::generate());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read key: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "key file is not 32 bytes".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map_err(|e| format!("stat key: {e}"))?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!("key file mode {:o} is group/other accessible", mode & 0o777));
        }
    }
    Ok(SecretKey::from_bytes(&arr))
}

fn keygen(path: &str) -> Result<EndpointId, String> {
    let k = SecretKey::generate();
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| format!("create key: {e}"))?;
    f.write_all(&k.to_bytes()).map_err(|e| format!("write key: {e}"))?;
    Ok(k.public())
}

async fn endpoint(c: &Common, accept: bool) -> Result<Endpoint, (u8, String)> {
    let key = read_key(&c.key).map_err(|e| (5, e))?;
    let mut b = Endpoint::builder(presets::Minimal).secret_key(key);
    b = match c.relay.as_str() {
        "disabled" => b.relay_mode(RelayMode::Disabled),
        "n0" => b.relay_mode(RelayMode::Default),
        url => {
            let map = RelayMap::try_from_iter([url]).map_err(|e| (2, format!("relay url: {e}")))?;
            b.relay_mode(RelayMode::Custom(map))
        }
    };
    b = match c.lookup.as_str() {
        "none" => b.clear_address_lookup(),
        "n0" => {
            use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
            b.address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns())
        }
        o => return Err((2, format!("unknown --lookup {o}"))),
    };
    b = match c.bind.as_str() {
        "none" => b.clear_ip_transports(),
        "default" => b,
        a => {
            let sa = SocketAddr::from_str(a).map_err(|e| (2, format!("bind addr: {e}")))?;
            b.clear_ip_transports().bind_addr(sa).map_err(|e| (2, format!("bind_addr: {e}")))?
        }
    };
    if !c.portmapper {
        b = b.portmapper_config(PortmapperConfig::Disabled);
    }
    if c.relay == "disabled" || c.bind == "none" {
        b = b.net_report_config(NetReportConfig::minimal());
    }
    if accept {
        b = b.alpns(vec![ALPN.to_vec()]);
    }
    let ep = b.bind().await.map_err(|e| (6, format!("bind: {e}")))?;
    let socks: Vec<String> = ep.bound_sockets().iter().map(|s| format!("\"{s}\"")).collect();
    log(&format!(
        "{{\"event\":\"ready\",\"id\":\"{}\",\"bound\":[{}],\"relay\":\"{}\",\"lookup\":\"{}\",\"portmapper\":{}}}",
        ep.id(),
        socks.join(","),
        esc(&c.relay),
        esc(&c.lookup),
        c.portmapper
    ));
    Ok(ep)
}

/// Endpoint close is bounded: an unbounded `close().await` after a peer-closed connection held the
/// ProxyCommand (and so ssh) open until ssh's ConnectTimeout (observed in S03, first run).
async fn close_bounded(ep: &Endpoint) {
    let _ = tokio::time::timeout(Duration::from_millis(1000), ep.close()).await;
}

fn paths_json(conn: &iroh::endpoint::Connection) -> String {
    let v: Vec<String> = conn
        .paths()
        .iter()
        .map(|p| {
            format!(
                "{{\"relay\":{},\"ip\":{},\"selected\":{},\"remote\":\"{}\"}}",
                p.is_relay(),
                p.is_ip(),
                p.is_selected(),
                esc(&format!("{:?}", p.remote_addr()))
            )
        })
        .collect();
    format!("[{}]", v.join(","))
}

async fn copy_flush<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W) -> std::io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        total += n as u64;
    }
}

async fn serve(c: Common, rest: Vec<(String, String)>) -> Result<(), (u8, String)> {
    let mut target = None;
    let mut allow: Vec<EndpointId> = Vec::new();
    for (k, v) in rest {
        match k.as_str() {
            "--target" => target = Some(SocketAddr::from_str(&v).map_err(|e| (2, format!("target: {e}")))?),
            "--allow" => allow.push(EndpointId::from_str(&v).map_err(|e| (2, format!("allow: {e}")))?),
            _ => return Err((2, format!("unknown option {k}"))),
        }
    }
    let target = target.ok_or((2, "--target required".to_string()))?;
    if !target.ip().is_loopback() {
        return Err((2, "--target must be a loopback address".into()));
    }
    let ep = endpoint(&c, true).await?;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            inc = ep.accept() => {
                let Some(inc) = inc else { break };
                let allow = allow.clone();
                tokio::spawn(async move {
                    let conn = match inc.await {
                        Ok(c) => c,
                        Err(e) => { log(&format!("{{\"event\":\"accept_error\",\"error\":\"{}\"}}", esc(&e.to_string()))); return; }
                    };
                    let peer = conn.remote_id();
                    if !allow.is_empty() && !allow.contains(&peer) {
                        log(&format!("{{\"event\":\"refused\",\"peer\":\"{peer}\"}}"));
                        conn.close(REFUSED.into(), b"not allowed");
                        return;
                    }
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(s) => s,
                        Err(e) => { log(&format!("{{\"event\":\"stream_error\",\"error\":\"{}\"}}", esc(&e.to_string()))); return; }
                    };
                    log(&format!("{{\"event\":\"session\",\"peer\":\"{peer}\",\"paths\":{}}}", paths_json(&conn)));
                    let tcp = match tokio::net::TcpStream::connect(target).await {
                        Ok(t) => t,
                        Err(e) => { log(&format!("{{\"event\":\"target_error\",\"error\":\"{}\"}}", esc(&e.to_string()))); conn.close(1u32.into(), b"target"); return; }
                    };
                    let _ = tcp.set_nodelay(true);
                    let (mut tr, mut tw) = tcp.into_split();
                    let up = async { let r = copy_flush(&mut recv, &mut tw).await; let _ = tw.shutdown().await; r };
                    let down = async { let r = copy_flush(&mut tr, &mut send).await; let _ = send.finish(); r };
                    let (u, d) = tokio::join!(up, down);
                    log(&format!(
                        "{{\"event\":\"session_end\",\"peer\":\"{peer}\",\"bytes_up\":{},\"bytes_down\":{}}}",
                        u.unwrap_or(0), d.unwrap_or(0)
                    ));
                    let _ = conn.closed().await;
                });
            }
        }
    }
    close_bounded(&ep).await;
    log("{\"event\":\"closed\"}");
    Ok(())
}

async fn connect(c: Common, rest: Vec<(String, String)>) -> Result<(), (u8, String)> {
    let mut peer = None;
    let mut addr = None;
    let mut peer_relay = None;
    let mut timeout = Duration::from_millis(15_000);
    for (k, v) in rest {
        match k.as_str() {
            "--peer" => peer = Some(EndpointId::from_str(&v).map_err(|e| (2, format!("peer: {e}")))?),
            "--addr" => addr = Some(SocketAddr::from_str(&v).map_err(|e| (2, format!("addr: {e}")))?),
            "--peer-relay" => peer_relay = Some(RelayUrl::from_str(&v).map_err(|e| (2, format!("peer-relay: {e}")))?),
            "--timeout-ms" => timeout = Duration::from_millis(v.parse().map_err(|_| (2, "timeout".to_string()))?),
            _ => return Err((2, format!("unknown option {k}"))),
        }
    }
    let peer = peer.ok_or((2, "--peer required".to_string()))?;
    let ep = endpoint(&c, false).await?;
    let mut ea = EndpointAddr::new(peer);
    if let Some(a) = addr {
        ea = ea.with_ip_addr(a);
    }
    if let Some(r) = peer_relay {
        ea = ea.with_relay_url(r);
    }
    let t0 = Instant::now();
    let conn = match tokio::time::timeout(timeout, ep.connect(ea, ALPN)).await {
        Err(_) => {
            close_bounded(&ep).await;
            return Err((3, format!("connect timed out after {} ms", timeout.as_millis())));
        }
        Ok(Err(e)) => {
            close_bounded(&ep).await;
            return Err((3, format!("connect: {e}")));
        }
        Ok(Ok(conn)) => conn,
    };
    log(&format!(
        "{{\"event\":\"connected\",\"peer\":\"{peer}\",\"ms\":{},\"paths\":{}}}",
        t0.elapsed().as_millis(),
        paths_json(&conn)
    ));
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| (3, format!("open_bi: {e}")))?;
    log(&format!("{{\"event\":\"stream_open\",\"ms\":{}}}", t0.elapsed().as_millis()));
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let up = async {
        let r = copy_flush(&mut stdin, &mut send).await;
        let _ = send.finish();
        r
    };
    let down = copy_flush(&mut recv, &mut stdout);
    // The session ends when the remote side finishes (sshd closed) or the connection drops.
    tokio::pin!(up);
    tokio::pin!(down);
    let mut up_done = false;
    let res = loop {
        tokio::select! {
            r = &mut up, if !up_done => {
                up_done = true;
                log(&format!("{{\"event\":\"stdin_done\",\"ms\":{},\"result\":\"{}\"}}", t0.elapsed().as_millis(), esc(&format!("{r:?}"))));
            }
            reason = conn.closed() => {
                log(&format!("{{\"event\":\"conn_closed\",\"ms\":{},\"reason\":\"{}\"}}", t0.elapsed().as_millis(), esc(&format!("{reason:?}"))));
                break Err(std::io::Error::other("connection closed"));
            }
            r = &mut down => break r,
        }
    };
    let refused = matches!(conn.close_reason(), Some(iroh::endpoint::ConnectionError::ApplicationClosed(ref a)) if a.error_code == REFUSED.into());
    log(&format!(
        "{{\"event\":\"session_end\",\"ms\":{},\"paths\":{},\"down_result\":\"{}\",\"refused\":{refused}}}",
        t0.elapsed().as_millis(),
        paths_json(&conn),
        esc(&format!("{res:?}"))
    ));
    conn.close(0u32.into(), b"bye");
    close_bounded(&ep).await;
    if refused {
        return Err((4, "refused by peer allowlist".into()));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        log("{\"event\":\"usage\"}");
        return ExitCode::from(2);
    };
    let out: Result<(), (u8, String)> = match cmd.as_str() {
        "keygen" | "id" => {
            let Some(p) = args.get(1) else { return ExitCode::from(2) };
            let r = if cmd == "keygen" { keygen(p) } else { read_key(p).map(|k| k.public()) };
            match r {
                Ok(id) => {
                    println!("{id}");
                    Ok(())
                }
                Err(e) => Err((5, e)),
            }
        }
        "serve" | "connect" => match parse(&args[1..]) {
            Err(e) => Err((2, e)),
            Ok((c, rest)) => {
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
                let r = rt.block_on(async { if cmd == "serve" { serve(c, rest).await } else { connect(c, rest).await } });
                // tokio's stdin reader is a blocking thread; a plain runtime drop waits for it while ssh
                // still holds our stdin open (observed: S03 refusal hung until ssh's ConnectTimeout).
                rt.shutdown_background();
                r
            }
        },
        _ => Err((2, format!("unknown command {cmd}"))),
    };
    match out {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            log(&format!("{{\"event\":\"error\",\"code\":{code},\"message\":\"{}\"}}", esc(&msg)));
            ExitCode::from(code)
        }
    }
}
