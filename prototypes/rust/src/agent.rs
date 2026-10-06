//! SSH-agent identity probe (contract §3, draft-miller-ssh-agent).
//!
//! Only `SSH_AGENTC_REQUEST_IDENTITIES` (11) is ever sent. The response parser is a
//! pure function over bytes and never allocates from an untrusted length before
//! checking it against a fixed bound or the bytes actually present.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::envelope::{Code, Envelope};
use crate::text::replace_controls;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Maximum accepted response frame length (contract §3).
pub const MAX_FRAME: u32 = 262_144;
/// Maximum accepted key count (contract §3).
pub const MAX_KEYS: u32 = 1_024;
/// The only request this prototype sends: uint32 length = 1, byte 11.
pub const REQUEST: [u8; 5] = [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// Connect failure or no complete response within the timeout.
    Unavailable(String),
    /// Bounds violation or malformed frame.
    Protocol(String),
    /// SSH_AGENT_FAILURE.
    Refused,
}

impl AgentError {
    pub fn to_envelope(&self) -> Envelope {
        match self {
            AgentError::Unavailable(m) => {
                Envelope::failure(Code::AgentUnavailable, None, m.clone())
            }
            AgentError::Protocol(m) => Envelope::failure(Code::AgentProtocolError, None, m.clone()),
            AgentError::Refused => {
                Envelope::failure(Code::AgentRefused, None, "agent answered SSH_AGENT_FAILURE")
            }
        }
    }
}

fn proto(m: &str) -> AgentError {
    AgentError::Protocol(m.to_string())
}

/// Cursor over an untrusted message body.
struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn u32(&mut self) -> Result<u32, AgentError> {
        if self.buf.len() < 4 {
            return Err(proto("truncated uint32"));
        }
        let (h, t) = self.buf.split_at(4);
        self.buf = t;
        Ok(u32::from_be_bytes([h[0], h[1], h[2], h[3]]))
    }
    /// SSH `string`: uint32 length + bytes. The length is checked against the
    /// remaining bytes before slicing; nothing is allocated.
    fn string(&mut self) -> Result<&'a [u8], AgentError> {
        let n = self.u32()? as usize;
        if n > self.buf.len() {
            return Err(proto("string length exceeds remaining frame"));
        }
        let (h, t) = self.buf.split_at(n);
        self.buf = t;
        Ok(h)
    }
}

/// Parse a complete message body (the bytes after the 4-byte frame length).
pub fn parse_body(body: &[u8]) -> Result<Vec<Identity>, AgentError> {
    let Some((&ty, rest)) = body.split_first() else {
        return Err(proto("empty frame"));
    };
    match ty {
        SSH_AGENT_IDENTITIES_ANSWER => {}
        SSH_AGENT_FAILURE if rest.is_empty() => return Err(AgentError::Refused),
        SSH_AGENT_FAILURE => return Err(proto("trailing bytes after SSH_AGENT_FAILURE")),
        _ => return Err(proto("unexpected message type")),
    }
    let mut c = Cursor { buf: rest };
    let nkeys = c.u32()?;
    if nkeys > MAX_KEYS {
        return Err(proto("nkeys exceeds 1024"));
    }
    // Each key needs at least 8 bytes (two empty strings); cap capacity by what is present.
    let mut out = Vec::with_capacity((nkeys as usize).min(c.buf.len() / 8));
    for _ in 0..nkeys {
        let blob = c.string()?;
        let comment = c.string()?;
        let key_type = Cursor { buf: blob }
            .string()
            .map_err(|_| proto("key blob does not start with a key type string"))?;
        let digest = Sha256::digest(blob);
        out.push(Identity {
            key_type: replace_controls(&String::from_utf8_lossy(key_type)),
            fingerprint: format!(
                "SHA256:{}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
            ),
            comment: replace_controls(&String::from_utf8_lossy(comment)),
        });
    }
    if !c.buf.is_empty() {
        return Err(proto("trailing bytes after last key"));
    }
    Ok(out)
}

/// Read one response frame from `r`: length checked before any allocation.
/// Contract §9 K3: EOF before any response byte is `Unavailable`; EOF after at
/// least one byte but before a complete frame is `Protocol`.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, AgentError> {
    let mut len = [0u8; 4];
    let first = loop {
        match r.read(&mut len) {
            Ok(k) => break k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(AgentError::Unavailable(format!(
                    "read failed: {:?}",
                    e.kind()
                )));
            }
        }
    };
    if first == 0 {
        return Err(AgentError::Unavailable(
            "peer closed connection before sending any response byte".into(),
        ));
    }
    read_full(r, &mut len[first..])?;
    let n = u32::from_be_bytes(len);
    if n > MAX_FRAME {
        return Err(proto("response frame length exceeds 262144"));
    }
    if n == 0 {
        return Err(proto("empty frame"));
    }
    let mut body = vec![0u8; n as usize];
    read_full(r, &mut body)?;
    Ok(body)
}

/// Read the rest of a frame. Only called after at least one response byte arrived, so
/// the peer ending the connection here is a protocol error: EOF (K3) and, since round
/// 2, a connection reset or abort (K3a; Linux reports `ECONNRESET` on AF_UNIX when the
/// peer closes with unread data, Darwin reports EOF). Other read errors stay
/// `Unavailable`.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), AgentError> {
    use std::io::ErrorKind;
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Err(proto("truncated frame (peer closed connection)")),
            Ok(k) => off += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                ) =>
            {
                return Err(proto("truncated frame (connection reset by peer)"));
            }
            Err(e) => {
                return Err(AgentError::Unavailable(format!(
                    "read failed: {:?}",
                    e.kind()
                )));
            }
        }
    }
    Ok(())
}

/// Send the request and read/parse one response over an established stream.
pub fn exchange<S: Read + Write>(s: &mut S) -> Result<Vec<Identity>, AgentError> {
    s.write_all(&REQUEST)
        .and_then(|_| s.flush())
        .map_err(|e| AgentError::Unavailable(format!("write failed: {:?}", e.kind())))?;
    let body = read_frame(s)?;
    parse_body(&body)
}

pub fn identities_envelope(ids: &[Identity]) -> Envelope {
    let list: Vec<_> = ids
        .iter()
        .map(
            |i| json!({"key_type": i.key_type, "fingerprint": i.fingerprint, "comment": i.comment}),
        )
        .collect();
    Envelope::success(Code::AgentOk, json!({"identities": list}))
}

/// Outcome of a probe that may be cancelled.
#[derive(Debug)]
pub enum ProbeOutcome {
    Done(Result<Vec<Identity>, AgentError>),
    Cancelled,
}

/// Platform connection. Returns the stream plus a closer that aborts I/O from
/// another thread (Unix: `shutdown`; Windows: none, process exit closes it).
#[cfg(unix)]
mod conn {
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    pub type Stream = UnixStream;
    pub struct Closer(Option<UnixStream>);

    pub fn connect(path: &Path) -> std::io::Result<(Stream, Closer)> {
        let s = UnixStream::connect(path)?;
        let c = s.try_clone().ok();
        Ok((s, Closer(c)))
    }

    impl Closer {
        pub fn close(&self) {
            if let Some(s) = &self.0 {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    }
}

/// Windows: a named pipe opened as a file (`\\.\pipe\name`) via std::fs::OpenOptions,
/// refused unless `GetFileType` reports a pipe (round 4, §9.6). Run natively in round 4
/// (tests/windows.rs and tests/native/windows-g02).
#[cfg(windows)]
mod conn {
    use std::fs::{File, OpenOptions};
    use std::path::Path;

    pub type Stream = File;
    pub struct Closer;

    /// `SECURITY_IDENTIFICATION` (SecurityIdentification << 16, winbase.h). With
    /// `security_qos_flags` set, std also sets `SECURITY_SQOS_PRESENT`, so the pipe
    /// server can identify the client but not impersonate it (round-1 review: std's
    /// default of 0 allowed a squatting server to impersonate at SecurityImpersonation).
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    pub fn connect(path: &Path) -> std::io::Result<(Stream, Closer)> {
        use std::os::windows::fs::OpenOptionsExt;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)?;
        // Round 4 (§9.6): only a pipe is an endpoint. A regular file, device or any
        // other non-pipe handle is refused here, before the request frame is written,
        // so the path is never modified (opening it does not change content or mtime).
        if crate::winfile::file_type(&f) != crate::winfile::FILE_TYPE_PIPE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a named pipe",
            ));
        }
        Ok((f, Closer))
    }

    impl Closer {
        pub fn close(&self) {
            // Synchronous pipe handles cannot be cancelled portably from another thread
            // without CancelSynchronousIo; the caller exits the process, closing the handle.
        }
    }
}

/// Probe the agent at `path`. I/O runs on a worker thread so that the timeout
/// and cancellation are enforced by the caller regardless of blocking calls.
/// `cancel` is polled every 10 ms.
pub fn probe(path: &std::path::Path, timeout: Duration, cancel: &Arc<AtomicBool>) -> ProbeOutcome {
    let deadline = Instant::now() + timeout;
    let (tx, rx) = mpsc::channel::<Result<Vec<Identity>, AgentError>>();
    let (ctx, crx) = mpsc::channel::<conn::Closer>();
    let path = path.to_path_buf();
    std::thread::spawn(move || {
        let r = match conn::connect(&path) {
            Ok((mut s, closer)) => {
                let _ = ctx.send(closer);
                exchange(&mut s)
            }
            Err(e) => Err(AgentError::Unavailable(format!(
                "connect failed: {:?}",
                e.kind()
            ))),
        };
        let _ = tx.send(r);
    });
    let mut closer: Option<conn::Closer> = None;
    loop {
        if closer.is_none() {
            closer = crx.try_recv().ok();
        }
        if cancel.load(Ordering::SeqCst) {
            if let Some(c) = &closer {
                c.close();
            }
            return ProbeOutcome::Cancelled;
        }
        let now = Instant::now();
        if now >= deadline {
            if let Some(c) = &closer {
                c.close();
            }
            return ProbeOutcome::Done(Err(AgentError::Unavailable(
                "no complete response within timeout".into(),
            )));
        }
        match rx.recv_timeout((deadline - now).min(Duration::from_millis(10))) {
            Ok(r) => {
                // A cancellation that raced with completion still wins (fail toward cancel).
                if cancel.load(Ordering::SeqCst) {
                    return ProbeOutcome::Cancelled;
                }
                return ProbeOutcome::Done(r);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return ProbeOutcome::Done(Err(AgentError::Unavailable(
                    "probe worker ended".into(),
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    fn key(kt: &str, extra: &[u8], comment: &[u8]) -> Vec<u8> {
        let mut blob = s(kt.as_bytes());
        blob.extend_from_slice(&s(extra));
        let mut v = s(&blob);
        v.extend_from_slice(&s(comment));
        v
    }

    fn answer(keys: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![SSH_AGENT_IDENTITIES_ANSWER];
        b.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for k in keys {
            b.extend_from_slice(k);
        }
        b
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        s(body)
    }

    #[test]
    fn request_is_exactly_type_11() {
        assert_eq!(REQUEST, [0, 0, 0, 1, 11]);
    }

    #[test]
    fn parses_identities_and_fingerprint() {
        let body = answer(&[
            key("ssh-ed25519", &[7u8; 32], b"fixture@heimdall"),
            key("ssh-rsa", b"x", b"bad \xff utf8"),
        ]);
        let ids = parse_body(&body).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].key_type, "ssh-ed25519");
        assert_eq!(ids[0].comment, "fixture@heimdall");
        assert!(ids[0].fingerprint.starts_with("SHA256:"));
        assert_eq!(ids[0].fingerprint.len(), 7 + 43);
        assert_eq!(ids[1].comment, "bad \u{FFFD} utf8");
        // Independent fingerprint check.
        let mut blob = s(b"ssh-ed25519");
        blob.extend_from_slice(&s(&[7u8; 32]));
        let d = Sha256::digest(&blob);
        let expect = format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(d)
        );
        assert_eq!(ids[0].fingerprint, expect);
        assert!(!ids[0].fingerprint.ends_with('='));
    }

    #[test]
    fn zero_keys_ok() {
        assert_eq!(parse_body(&answer(&[])).unwrap(), vec![]);
    }

    #[test]
    fn control_chars_in_comment_replaced() {
        let ids = parse_body(&answer(&[key("ssh-ed25519", b"k", b"x\x1b[2Jy")])).unwrap();
        assert_eq!(ids[0].comment, "x\u{FFFD}[2Jy");
    }

    /// K1: every C0 (incl. TAB, NUL), DEL and C1 code point in comment and key_type
    /// becomes U+FFFD, as does invalid UTF-8; the strings contain no control at all.
    #[test]
    fn k1_all_control_classes_replaced_in_comment_and_key_type() {
        let ctl = "a\u{0}b\tc\u{1f}d\u{7f}e\u{80}f\u{85}g\u{9b}h\u{9f}i";
        let mut bytes = ctl.as_bytes().to_vec();
        bytes.extend_from_slice(b"\xffj");
        let ids = parse_body(&answer(&[key(ctl, b"k", &bytes)])).unwrap();
        let want = "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f\u{FFFD}g\u{FFFD}h\u{FFFD}i";
        assert_eq!(ids[0].key_type, want);
        assert_eq!(ids[0].comment, format!("{want}\u{FFFD}j"));
        for s in [&ids[0].key_type, &ids[0].comment] {
            assert!(!s.chars().any(|c| c.is_control()), "{s:?}");
        }
    }

    /// K4: a type-5 frame must have length exactly 1.
    #[test]
    fn k4_failure_with_payload_is_protocol_error() {
        assert_eq!(parse_body(&[SSH_AGENT_FAILURE]), Err(AgentError::Refused));
        for body in [&[5u8, 0][..], &[5, 0, 0, 0, 0], &[5, b'x', b'y']] {
            let f = framed(body);
            let b = read_frame(&mut &f[..]).unwrap();
            assert!(
                matches!(parse_body(&b), Err(AgentError::Protocol(_))),
                "{body:?}"
            );
        }
    }

    #[test]
    fn oversize_length_rejected_without_reading_body() {
        let mut frame = (MAX_FRAME + 1).to_be_bytes().to_vec();
        frame.push(12); // only 1 byte present; must fail on the length alone
        let e = read_frame(&mut &frame[..]).unwrap_err();
        assert!(matches!(e, AgentError::Protocol(m) if m.contains("262144")));
        let frame = u32::MAX.to_be_bytes();
        assert!(matches!(
            read_frame(&mut &frame[..]),
            Err(AgentError::Protocol(_))
        ));
    }

    #[test]
    fn max_length_frame_accepted_by_reader() {
        let mut frame = MAX_FRAME.to_be_bytes().to_vec();
        frame.resize(4 + MAX_FRAME as usize, 0);
        assert_eq!(
            read_frame(&mut &frame[..]).unwrap().len(),
            MAX_FRAME as usize
        );
    }

    #[test]
    fn huge_nkeys_rejected() {
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(parse_body(&body), Err(AgentError::Protocol(m)) if m.contains("nkeys")));
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&(MAX_KEYS + 1).to_be_bytes());
        assert!(matches!(parse_body(&body), Err(AgentError::Protocol(_))));
        // nkeys within bound but more than present → truncated, not allocation.
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&MAX_KEYS.to_be_bytes());
        assert!(matches!(parse_body(&body), Err(AgentError::Protocol(_))));
    }

    #[test]
    fn exactly_1024_keys_ok() {
        let keys: Vec<_> = (0..MAX_KEYS)
            .map(|_| key("ssh-ed25519", b"k", b""))
            .collect();
        assert_eq!(parse_body(&answer(&keys)).unwrap().len(), 1024);
    }

    #[test]
    fn string_length_exceeding_frame_rejected() {
        let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&u32::MAX.to_be_bytes()); // blob length
        body.extend_from_slice(b"abc");
        assert!(matches!(parse_body(&body), Err(AgentError::Protocol(m)) if m.contains("exceeds")));
        // key type string inside blob too long
        let mut blob = 100u32.to_be_bytes().to_vec();
        blob.extend_from_slice(b"ssh");
        let mut k = s(&blob);
        k.extend_from_slice(&s(b"c"));
        assert!(matches!(
            parse_body(&answer(&[k])),
            Err(AgentError::Protocol(_))
        ));
        // empty blob has no key type
        let mut k = s(b"");
        k.extend_from_slice(&s(b"c"));
        assert!(matches!(
            parse_body(&answer(&[k])),
            Err(AgentError::Protocol(_))
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut body = answer(&[key("ssh-ed25519", b"k", b"c")]);
        body.push(0);
        assert!(
            matches!(parse_body(&body), Err(AgentError::Protocol(m)) if m.contains("trailing"))
        );
        assert!(matches!(
            parse_body(&[SSH_AGENT_FAILURE, 0]),
            Err(AgentError::Protocol(_))
        ));
    }

    #[test]
    fn truncated_rejected() {
        let body = answer(&[key("ssh-ed25519", b"k", b"comment")]);
        for cut in 1..body.len() {
            assert!(
                matches!(parse_body(&body[..cut]), Err(AgentError::Protocol(_))),
                "cut {cut}"
            );
        }
        let frame = framed(&body);
        // K3: zero bytes then EOF is Unavailable; 1..len-1 bytes then EOF is Protocol.
        assert!(matches!(
            read_frame(&mut &frame[..0]),
            Err(AgentError::Unavailable(_))
        ));
        for cut in 1..frame.len() {
            assert!(
                matches!(read_frame(&mut &frame[..cut]), Err(AgentError::Protocol(_))),
                "frame cut {cut}"
            );
        }
        assert!(matches!(
            read_frame(&mut &[0u8, 0, 0, 0][..]),
            Err(AgentError::Protocol(_))
        ));
    }

    /// Reader that yields `data`, then fails with `err` (a reset after a partial frame).
    struct ThenErr<'a> {
        data: &'a [u8],
        err: std::io::ErrorKind,
    }
    impl Read for ThenErr<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.data.is_empty() {
                return Err(self.err.into());
            }
            let n = self.data.len().min(buf.len()).min(1);
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    /// K3a: a reset before any byte is Unavailable; after >= 1 byte it is Protocol.
    #[test]
    fn k3a_reset_classified_like_eof() {
        use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
        let frame = framed(&answer(&[key("ssh-ed25519", b"k", b"comment")]));
        for err in [ConnectionReset, ConnectionAborted, BrokenPipe] {
            assert!(
                matches!(
                    read_frame(&mut ThenErr { data: &[], err }),
                    Err(AgentError::Unavailable(_))
                ),
                "{err:?} before any byte"
            );
            for cut in 1..frame.len() {
                assert!(
                    matches!(
                        read_frame(&mut ThenErr {
                            data: &frame[..cut],
                            err
                        }),
                        Err(AgentError::Protocol(_))
                    ),
                    "{err:?} after {cut} bytes"
                );
            }
        }
        // Not a connection-ending error: stays Unavailable.
        assert!(matches!(
            read_frame(&mut ThenErr {
                data: &frame[..2],
                err: std::io::ErrorKind::PermissionDenied
            }),
            Err(AgentError::Unavailable(_))
        ));
    }

    #[test]
    fn wrong_type_and_failure() {
        assert!(matches!(
            parse_body(&[SSH_AGENTC_REQUEST_IDENTITIES]),
            Err(AgentError::Protocol(_))
        ));
        assert!(matches!(parse_body(&[6]), Err(AgentError::Protocol(_))));
        assert!(matches!(
            parse_body(&[14, 0, 0, 0, 0]),
            Err(AgentError::Protocol(_))
        ));
        assert_eq!(parse_body(&[SSH_AGENT_FAILURE]), Err(AgentError::Refused));
        assert!(matches!(parse_body(&[]), Err(AgentError::Protocol(_))));
    }

    #[test]
    fn envelope_shapes() {
        let ids = parse_body(&answer(&[key("ssh-ed25519", b"k", b"c")])).unwrap();
        let v = identities_envelope(&ids).to_value();
        assert_eq!(v["code"], "AGENT_OK");
        let keys: Vec<_> = v["data"]["identities"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["key_type", "fingerprint", "comment"]);
        assert_eq!(AgentError::Refused.to_envelope().exit_code(), 5);
        assert_eq!(AgentError::Refused.to_envelope().code, Code::AgentRefused);
    }
}
