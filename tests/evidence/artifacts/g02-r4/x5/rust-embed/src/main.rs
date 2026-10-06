//! M00 G02 round-4 X5 probe (disposable). Not production code.
//!
//! Modes:
//!   x5-iroh selftest [--hold-ms N]  two iroh endpoints in one process, loopback only,
//!                                   one message on ALPN heimdall/x5/0; one result line.
//!   x5-iroh helper                  stdio helper for a supervisor (see PROTOCOL below).
//!
//! PROTOCOL (helper): frames on stdin/stdout, each a u32 big-endian length followed by
//! that many bytes of UTF-8 text, max 65536. Fields are separated by single spaces.
//!   helper -> sup  "ready <endpoint-id> <ip:port>"    once, after the endpoint is bound
//!   sup -> helper  "send <endpoint-id> <ip:port> <hex>" dial the peer, send one message
//!   helper -> sup  "sent <n>"                          the peer read it and closed
//!   helper -> sup  "recv <endpoint-id> <hex>"          a peer sent us one message
//!   sup -> helper  "shutdown"                          close the endpoint, reply "bye", exit 0
//!   helper -> sup  "err <text>"                        a command failed
//! EOF on stdin is treated as "shutdown" (the supervisor went away).
//!
//! Every endpoint: relays disabled, no address lookup (discovery), only a 127.0.0.1:0
//! IP transport, portmapper disabled, net-report optional probes disabled.

use std::io::{Read, Write};

const MAX_FRAME: usize = 65536;

fn read_frame(r: &mut impl Read) -> std::io::Result<Option<String>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame not utf-8"))
}

fn write_frame(text: &str) {
    let mut out = std::io::stdout().lock();
    let b = text.as_bytes();
    let _ = out.write_all(&(b.len() as u32).to_be_bytes());
    let _ = out.write_all(b);
    let _ = out.flush();
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > 2 * 4096 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(feature = "net")]
mod net {
    use super::*;
    use iroh::endpoint::{PortmapperConfig, presets};
    use iroh::{Endpoint, EndpointAddr, EndpointId, NetReportConfig, RelayMode};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    pub const ALPN: &[u8] = b"heimdall/x5/0";

    pub async fn make_endpoint() -> Result<Endpoint, String> {
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .clear_ip_transports()
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| format!("bind_addr: {e}"))?
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(NetReportConfig::minimal())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| format!("bind: {e}"))?;
        let socks = ep.bound_sockets();
        if socks.is_empty() || socks.iter().any(|s| !s.ip().is_loopback()) {
            ep.close().await;
            return Err(format!("non-loopback or no bound socket: {socks:?}"));
        }
        Ok(ep)
    }

    pub fn loopback_addr(ep: &Endpoint) -> SocketAddr {
        ep.bound_sockets()[0]
    }

    /// Dial `peer`, send `msg` on a uni stream, wait until the peer closes the connection.
    pub async fn send_one(ep: &Endpoint, peer: EndpointId, at: SocketAddr, msg: &[u8]) -> Result<usize, String> {
        if !at.ip().is_loopback() {
            return Err("refusing non-loopback peer address".into());
        }
        let addr = EndpointAddr::new(peer).with_ip_addr(at);
        let conn = ep.connect(addr, ALPN).await.map_err(|e| format!("connect: {e}"))?;
        let mut s = conn.open_uni().await.map_err(|e| format!("open_uni: {e}"))?;
        s.write_all(msg).await.map_err(|e| format!("write: {e}"))?;
        s.finish().map_err(|e| format!("finish: {e}"))?;
        // The receiver closes the connection after reading the whole stream.
        let _ = conn.closed().await;
        Ok(msg.len())
    }

    /// Accept one connection, read one uni stream to the end, close the connection.
    pub async fn recv_one(ep: &Endpoint) -> Result<(EndpointId, Vec<u8>), String> {
        let inc = ep.accept().await.ok_or("endpoint closed")?;
        let conn = inc.await.map_err(|e| format!("accept: {e}"))?;
        if conn.alpn() != ALPN {
            return Err("unexpected alpn".into());
        }
        let from = conn.remote_id();
        let mut r = conn.accept_uni().await.map_err(|e| format!("accept_uni: {e}"))?;
        let data = r.read_to_end(4096).await.map_err(|e| format!("read: {e}"))?;
        conn.close(0u32.into(), b"done");
        Ok((from, data))
    }

    pub async fn selftest(hold_ms: u64) -> Result<String, String> {
        let a = make_endpoint().await?;
        let b = make_endpoint().await?;
        let msg = b"heimdall x5 selftest message";
        let a_id = a.id();
        let a_at = loopback_addr(&a);
        let recv = tokio::spawn({
            let a = a.clone();
            async move { recv_one(&a).await }
        });
        let sent = send_one(&b, a_id, a_at, msg).await?;
        let (from, data) = recv.await.map_err(|e| format!("join: {e}"))??;
        let ok = data == msg && from == b.id();
        let line = format!(
            "{{\"mode\":\"selftest\",\"ok\":{ok},\"bytes_sent\":{sent},\"bytes_recv\":{},\"from_matches_dialer\":{},\"a_bound\":\"{}\",\"b_bound\":\"{}\"}}",
            data.len(),
            from == b.id(),
            a_at,
            loopback_addr(&b)
        );
        if hold_ms > 0 {
            eprintln!("x5-iroh: holding {hold_ms} ms for socket inspection (pid {})", std::process::id());
            tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;
        }
        b.close().await;
        a.close().await;
        if ok { Ok(line) } else { Err(line) }
    }

    pub async fn helper() -> i32 {
        let ep = match make_endpoint().await {
            Ok(ep) => ep,
            Err(e) => {
                write_frame(&format!("err {e}"));
                return 1;
            }
        };
        write_frame(&format!("ready {} {}", ep.id(), loopback_addr(&ep)));

        // Blocking stdin reader thread -> channel.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Option<String>>();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                match read_frame(&mut stdin) {
                    Ok(Some(f)) => {
                        if tx.send(Some(f)).is_err() {
                            break;
                        }
                    }
                    _ => {
                        let _ = tx.send(None);
                        break;
                    }
                }
            }
        });

        // Accept loop: report every received message.
        let acceptor = tokio::spawn({
            let ep = ep.clone();
            async move {
                loop {
                    match recv_one(&ep).await {
                        Ok((from, data)) => write_frame(&format!("recv {from} {}", hex(&data))),
                        Err(e) if e == "endpoint closed" => break,
                        Err(e) => write_frame(&format!("err {e}")),
                    }
                }
            }
        });

        let mut code = 0;
        while let Some(cmd) = rx.recv().await {
            let Some(cmd) = cmd else { break }; // EOF: supervisor gone
            let parts: Vec<&str> = cmd.split(' ').collect();
            match parts.as_slice() {
                ["shutdown"] => break,
                ["send", id, at, msg] => {
                    let r = async {
                        let id: EndpointId = id.parse().map_err(|_| "bad endpoint id".to_string())?;
                        let at: SocketAddr = at.parse().map_err(|_| "bad address".to_string())?;
                        let msg = unhex(msg).ok_or("bad hex")?;
                        send_one(&ep, id, at, &msg).await
                    }
                    .await;
                    match r {
                        Ok(n) => write_frame(&format!("sent {n}")),
                        Err(e) => write_frame(&format!("err {e}")),
                    }
                }
                _ => {
                    write_frame("err unknown command");
                    code = 2;
                }
            }
        }
        ep.close().await;
        let _ = acceptor.await;
        write_frame("bye");
        code
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("");
    #[cfg(feature = "net")]
    {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
        match mode {
            "selftest" => {
                let hold = match args.get(1).map(String::as_str) {
                    Some("--hold-ms") => args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0),
                    _ => 0,
                };
                match rt.block_on(net::selftest(hold)) {
                    Ok(line) => {
                        println!("{line}");
                        std::process::exit(0)
                    }
                    Err(e) => {
                        eprintln!("x5-iroh: selftest failed: {e}");
                        std::process::exit(1)
                    }
                }
            }
            "helper" => std::process::exit(rt.block_on(net::helper())),
            _ => {}
        }
    }
    #[cfg(not(feature = "net"))]
    {
        // Baseline build: same frame code, no iroh. "helper" echoes frames until EOF so
        // the frame code is not optimised away.
        if mode == "helper" {
            let mut stdin = std::io::stdin().lock();
            while let Ok(Some(f)) = read_frame(&mut stdin) {
                if f == "shutdown" {
                    break;
                }
                let echo = unhex(&hex(f.as_bytes())).unwrap_or_default();
                write_frame(&format!("err no-iroh build {}", String::from_utf8_lossy(&echo)));
            }
            write_frame("bye");
            std::process::exit(0);
        }
    }
    eprintln!("usage: x5-iroh selftest [--hold-ms N] | x5-iroh helper");
    std::process::exit(64);
}
