//! The issuer child process, `heimdall internal issuer` (ADR-0008 D3 items 1, 4–6;
//! m03-plan U3 `child::run`): it refuses a terminal stdin, speaks
//! [`crate::protocol`] on its stdin and stdout pipes, opens the state database
//! read-only, signs by reservation (D3 item 4 steps 1–5), and zeroizes K_ca on EOF,
//! on `unload` and on `shutdown`.
//!
//! The signature of [`run`] is frozen in wave 0 (U0); the body is U3's.
//!
//! **Order at start:** a terminal stdin is refused ([`EXIT_USAGE`]) before anything
//! else; then `heimdall_credential::sys::harden_process()` runs **before any key is
//! loaded** (D1: core dumps off, Linux non-dumpable); then the database is opened
//! with `Store::open_read_only` (a failure is [`EXIT_UNAVAILABLE`]). No key is read
//! before the runtime's `load`.
//!
//! **The loop** handles one request at a time. The first message must be `hello`.
//! Every frame's length is checked before its body is allocated; an oversized,
//! malformed or out-of-order frame closes the channel ([`EXIT_PROTOCOL`]), with every
//! key zeroized first. EOF at a frame boundary (the parent died or closed the pipe)
//! and `shutdown` zeroize and exit 0. A write that fails (the parent is gone) does the
//! same with [`EXIT_PROTOCOL`].
//!
//! **`load`** reads the registered CAs from the database and loads from `store` only
//! those `active` or `pending` (a `retiring` CA is never loaded again; D4 item 3). Any
//! failure (the store unavailable, an item missing or not the registered key) loads
//! nothing and answers `store_unavailable` with the reason: there is no fallback
//! key and no plaintext (D1).
//!
//! **`sign`** is refused `rate_limited` beyond [`SIGNATURES_PER_MINUTE`] signatures in
//! the last minute of the child's continuous clock, or beyond
//! [`CERTIFICATES_PER_SUBJECT`] certificates for one subject key (one K_env per grant
//! activation or re-issue, D6 items 1 and 4, so this is D3 item 5's "per grant per
//! activation or re-issue"). It then runs `check::verify_reservation` and
//! `ca::CaSet::sign`. The child never writes the store and never publishes.
//!
//! **`unload`** zeroizes the CA and answers `unloaded` (retirement's `retiring →
//! unloaded` confirmation; the runtime persists the transition).
//!
//! **Time** is the read-only gate over the database with this child's clock and an
//! unknown synchronization report (M03 never trusts synchronized time, Q13): the
//! runtime's same-boot anchor is the reference, and without one nothing is signed.

use std::collections::{BTreeMap, VecDeque};
use std::io::{IsTerminal, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::timegate::TimeGate;
use heimdall_contract::issuer::CaState;
use heimdall_domain::time::{Clock, SyncStatus, TimePolicy, TimeSync};
use heimdall_store::{NoFaults, Store};

use crate::ca::CaSet;
use crate::check::verify_reservation;
use crate::protocol::{
    HEADER_BYTES, IssuanceRef, IssuerRefusal, PROTOCOL, Request, Response, body_len,
};
use crate::store::{SecretStore, StoreAvailability, StoreError};

/// The child's exit status when the issuer is not in this build (wave 0), or cannot
/// serve at all (`EX_UNAVAILABLE`, 69). The runtime's supervisor reads any nonzero
/// exit as `crashed` (ADR-0008 D3 item 7).
pub const EXIT_UNAVAILABLE: i32 = 69;

/// The exit status for a terminal on stdin (a usage error; the child is started by
/// the runtime on a pipe, never by a person).
pub const EXIT_USAGE: i32 = 2;

/// The exit status after a protocol violation or a lost channel (`EX_PROTOCOL`, 76).
pub const EXIT_PROTOCOL: i32 = 76;

/// At most this many signatures in any minute (ADR-0008 D3 item 5).
pub const SIGNATURES_PER_MINUTE: usize = 600;

/// At most this many certificates for one subject key, i.e. per grant per activation
/// or re-issue (ADR-0008 D3 item 5; module docs).
pub const CERTIFICATES_PER_SUBJECT: u32 = 64;

const MINUTE: Duration = Duration::from_secs(60);

/// The child's synchronization report: always unknown (module docs, "Time").
struct UnknownSync;

impl TimeSync for UnknownSync {
    fn status(&self) -> SyncStatus {
        SyncStatus::Unknown
    }
}

/// The D3 item 5 limits, on the child's continuous clock.
#[derive(Default)]
struct RateLimit {
    recent: VecDeque<Duration>,
    per_subject: BTreeMap<String, u32>,
}

impl RateLimit {
    /// Whether one more signature for `subject` is allowed at continuous time `now`.
    fn admits(&mut self, subject: &str, now: Duration) -> bool {
        while self
            .recent
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= MINUTE)
        {
            self.recent.pop_front();
        }
        self.recent.len() < SIGNATURES_PER_MINUTE
            && self.per_subject.get(subject).copied().unwrap_or(0) < CERTIFICATES_PER_SUBJECT
    }

    fn record(&mut self, subject: &str, now: Duration) {
        self.recent.push_back(now);
        let n = self.per_subject.entry(subject.to_owned()).or_insert(0);
        *n = n.saturating_add(1);
    }
}

/// How one frame read ended.
enum Read1 {
    Frame(Vec<u8>),
    Eof,
    Broken,
}

/// Read one frame: `Eof` only at a frame boundary; the length is checked before the
/// body is allocated.
fn read_frame(input: &mut impl Read) -> Read1 {
    let mut header = [0u8; HEADER_BYTES];
    let mut got = 0;
    while got < HEADER_BYTES {
        match input.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Read1::Eof,
            Ok(0) => return Read1::Broken,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Read1::Broken,
        }
    }
    let Ok(len) = body_len(header) else {
        return Read1::Broken;
    };
    let mut body = vec![0u8; len];
    if input.read_exact(&mut body).is_err() {
        return Read1::Broken;
    }
    Read1::Frame(body)
}

/// The child's state between requests.
struct Child<'a> {
    store: &'a dyn SecretStore,
    db: Arc<Store>,
    gate: TimeGate,
    clock: Arc<dyn Clock>,
    cas: CaSet,
    rate: RateLimit,
    signed_total: u64,
    refused_total: u64,
}

/// The availability a store error reports (never `available`).
fn availability_of(e: &StoreError) -> StoreAvailability {
    match e {
        StoreError::Unavailable(a) if *a != StoreAvailability::Available => *a,
        StoreError::NotFound => StoreAvailability::Missing,
        _ => StoreAvailability::Corrupt,
    }
}

impl Child<'_> {
    /// `load`: every registered `active`/`pending` CA from the store, or nothing.
    fn load(&mut self) -> Response {
        self.cas.clear();
        let availability = self.store.availability();
        if availability != StoreAvailability::Available {
            return Response::StoreUnavailable {
                reason: availability,
            };
        }
        let Ok(registered) = self.db.transaction(|tx| tx.issuers()) else {
            return Response::StoreUnavailable {
                reason: StoreAvailability::Missing,
            };
        };
        for issuer in registered {
            if !matches!(issuer.state, CaState::Active | CaState::Pending) {
                continue;
            }
            let key = match self.store.get(&issuer.ca_fingerprint) {
                Ok(key) => key,
                Err(e) => {
                    self.cas.clear();
                    return Response::StoreUnavailable {
                        reason: availability_of(&e),
                    };
                }
            };
            if self
                .cas
                .insert(&issuer.ca_fingerprint, key, issuer.state)
                .is_err()
            {
                self.cas.clear();
                return Response::StoreUnavailable {
                    reason: StoreAvailability::Corrupt,
                };
            }
        }
        Response::Loaded {
            cas: self.cas.loaded(),
        }
    }

    /// `sign`: the rate limit, steps 1–5, the counters.
    fn sign(&mut self, entry: &IssuanceRef, subject: &str) -> Result<String, IssuerRefusal> {
        let now = self.clock.observe().continuous;
        let subject_key = heimdall_app::issuance_ro::subject_fingerprint(subject)
            .ok_or(IssuerRefusal::SubjectMismatch)?;
        if !self.rate.admits(&subject_key, now) {
            return Err(IssuerRefusal::RateLimited);
        }
        let bounds = verify_reservation(&self.db, &self.gate, entry, subject)?;
        let public = ssh_key::PublicKey::from_openssh(subject)
            .map_err(|_| IssuerRefusal::SubjectMismatch)?;
        let certificate = self.cas.sign(entry.table, &bounds, &public)?;
        let line = certificate
            .to_openssh()
            .map_err(|_| IssuerRefusal::CaNotLoaded)?;
        self.rate.record(&subject_key, now);
        Ok(line)
    }

    /// One request's reply, or `None` for `shutdown`.
    fn handle(&mut self, request: Request) -> Option<Response> {
        Some(match request {
            // A second `hello` is out of order.
            Request::Hello { .. } => return None,
            Request::Load {} => self.load(),
            Request::Sign {
                request_id,
                reservation,
                subject_public_key,
            } => match self.sign(&reservation, &subject_public_key) {
                Ok(certificate) => {
                    self.signed_total = self.signed_total.saturating_add(1);
                    Response::Signed {
                        request_id,
                        certificate,
                    }
                }
                Err(reason) => {
                    self.refused_total = self.refused_total.saturating_add(1);
                    Response::Refused { request_id, reason }
                }
            },
            Request::Status {} => Response::Status {
                cas: self.cas.loaded(),
                signed_total: self.signed_total,
                refused_total: self.refused_total,
            },
            Request::Unload { ca_fingerprint } => {
                self.cas.unload(&ca_fingerprint);
                Response::Unloaded { ca_fingerprint }
            }
            Request::Shutdown {} => return None,
            #[allow(unreachable_patterns)]
            _ => return None,
        })
    }
}

/// Write one reply frame; `false` when it cannot be encoded or written.
fn reply(output: &mut impl Write, response: &Response) -> bool {
    match response.encode() {
        Ok(frame) => output
            .write_all(&frame)
            .and_then(|()| output.flush())
            .is_ok(),
        Err(_) => false,
    }
}

/// Run the issuer over `stdin`/`stdout` until EOF or `shutdown`, reading CA keys
/// from `store` and reservations from the database at `db` (opened read-only), with
/// time from `clock`. Returns the process exit status: 0 after EOF or `shutdown`,
/// [`EXIT_USAGE`] for a terminal stdin, [`EXIT_UNAVAILABLE`] when the database cannot
/// be opened read-only, [`EXIT_PROTOCOL`] after a protocol violation or a lost
/// channel. Every key is zeroized before it returns.
#[must_use]
pub fn run<R, W>(
    stdin: R,
    stdout: W,
    store: Box<dyn SecretStore>,
    db: &Path,
    clock: Arc<dyn Clock>,
) -> i32
where
    R: Read + IsTerminal,
    W: Write,
{
    if stdin.is_terminal() {
        return EXIT_USAGE;
    }
    // D1: the process mitigations before any key is loaded.
    let _hardening = heimdall_credential::sys::harden_process();
    let Ok(ro) = Store::open_read_only(db, Arc::new(NoFaults)) else {
        return EXIT_UNAVAILABLE;
    };
    let ro = Arc::new(ro);
    let gate = TimeGate::new(
        Arc::clone(&ro),
        Arc::clone(&clock),
        Arc::new(UnknownSync),
        TimePolicy::default(),
    );
    let mut child = Child {
        store: store.as_ref(),
        db: ro,
        gate,
        clock,
        cas: CaSet::new(),
        rate: RateLimit::default(),
        signed_total: 0,
        refused_total: 0,
    };
    let status = serve(&mut child, stdin, stdout);
    child.cas.clear();
    status
}

/// The protocol loop (module docs).
fn serve(child: &mut Child<'_>, mut input: impl Read, mut output: impl Write) -> i32 {
    let mut greeted = false;
    loop {
        let body = match read_frame(&mut input) {
            Read1::Frame(body) => body,
            Read1::Eof => return 0,
            Read1::Broken => return EXIT_PROTOCOL,
        };
        let Ok(request) = Request::decode(&body) else {
            return EXIT_PROTOCOL;
        };
        let response = if greeted {
            match request {
                Request::Shutdown {} => return 0,
                other => match child.handle(other) {
                    Some(r) => r,
                    None => return EXIT_PROTOCOL,
                },
            }
        } else {
            match request {
                Request::Hello { protocol, nonce } if protocol == PROTOCOL => {
                    greeted = true;
                    Response::HelloAck {
                        nonce,
                        pid: std::process::id(),
                    }
                }
                _ => return EXIT_PROTOCOL,
            }
        };
        if !reply(&mut output, &response) {
            return EXIT_PROTOCOL;
        }
    }
}
