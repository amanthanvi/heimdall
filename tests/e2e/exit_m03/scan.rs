//! A33's (and A10's K_ca) secret-bytes scan (`e2e_exit_m03` submodule; m03-plan §0.2).
//!
//! **The needles** (never printed; a hit is reported by secret kind, artifact kind and
//! offset only):
//! * `k_env`: the seeded K_env private seeds, `heimdall_testkit::managed::seeded_k_env_nth`
//!   for the first [`K_ENV_INDICES`] keys of `HEIMDALL_TEST_KEY_SEED`, in every
//!   `managed::scan_forms` encoding (raw, lower and upper hex, base64 with and without
//!   padding);
//! * `k_ca`: the test K_ca: its 32-byte private seed and its 64-byte OpenSSH private
//!   field (seed and public key) in the same encodings, plus its unencrypted OpenSSH
//!   encoding (the whole PEM text, and each body line that depends on this key: every
//!   base64 line but the first, which is common to all such keys, and the last);
//! * `canary`: each `HEIMDALL_CANARY_<random>` value the test placed, and the prefix
//!   `HEIMDALL_CANARY_` itself (which also catches the fake adapter's own canary
//!   credential reference, whose value the test cannot know).
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::path::Path;

use heimdall_credential::cert::SecretCaKey;
use heimdall_testkit::managed::{scan_forms, seeded_k_env_nth};

/// How many seeded K_env indices are scanned for. A vault starts at index 0 in every
/// runtime process (the seed is per process), and this flow generates at most a few
/// keys per process.
pub const K_ENV_INDICES: u64 = 16;

/// The needles of one secret kind.
pub struct Needles {
    pub kind: &'static str,
    pub forms: Vec<Vec<u8>>,
}

/// One hit: which secret kind, in which artifact kind, at which offset. Never the bytes.
#[derive(Debug, Clone)]
pub struct Hit {
    pub secret: &'static str,
    pub artifact: String,
    pub offset: usize,
}

/// The seeded K_env needles.
pub fn k_env(seed: &[u8]) -> Needles {
    let mut forms = Vec::new();
    for n in 0..K_ENV_INDICES {
        forms.extend(scan_forms(&seeded_k_env_nth(seed, n)));
    }
    Needles {
        kind: "k_env",
        forms,
    }
}

/// The K_ca needles (module docs).
pub fn k_ca(key: &SecretCaKey) -> Needles {
    let pem = key.to_secret_bytes().unwrap();
    let text = String::from_utf8(pem.to_vec()).unwrap();
    let body: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    let blob = base64_decode(&body.concat()).expect("the PEM body is base64");
    let public = base64_decode(
        key.public_openssh()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap(),
    )
    .unwrap();
    let pub32 = &public[public.len() - 32..];
    // The private field: `uint32 64` then seed (32) and public key (32).
    let private = blob
        .windows(68)
        .find(|w| w[..4] == [0, 0, 0, 64] && &w[36..68] == pub32)
        .map(|w| w[4..68].to_vec())
        .expect("the OpenSSH private field");
    let mut forms = scan_forms(&private[..32]);
    forms.extend(scan_forms(&private));
    forms.push(text.trim().as_bytes().to_vec());
    if body.len() > 2 {
        for line in &body[1..body.len() - 1] {
            forms.push(line.as_bytes().to_vec());
        }
    }
    Needles {
        kind: "k_ca",
        forms,
    }
}

/// The canary needles: each placed value and the prefix.
pub fn canaries(values: &[String]) -> Needles {
    let mut forms: Vec<Vec<u8>> = values.iter().map(|v| v.as_bytes().to_vec()).collect();
    forms.push(heimdall_testkit::CANARY_PREFIX.as_bytes().to_vec());
    Needles {
        kind: "canary",
        forms,
    }
}

/// Scan `data` (artifact kind `artifact`) for every needle; hits are appended.
pub fn scan(artifact: &str, data: &[u8], needles: &[Needles], hits: &mut Vec<Hit>) {
    for n in needles {
        for form in &n.forms {
            if let Some(offset) = find(data, form) {
                hits.push(Hit {
                    secret: n.kind,
                    artifact: artifact.to_owned(),
                    offset,
                });
            }
        }
    }
}

/// The first offset of `needle` in `data` (first-byte skip, then compare).
fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    if needle.len() > data.len() {
        return None;
    }
    let last_start = data.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        let j = data[i..=last_start].iter().position(|&b| b == first)? + i;
        if &data[j + 1..j + needle.len()] == rest {
            return Some(j);
        }
        i = j + 1;
    }
    None
}

/// ⟨M03 wave 6, W6-R04⟩ What [`scan_tree`] covered: only files actually read count as
/// scanned. A file or directory that could not be read is incomplete coverage (A33
/// fails on it); a file that vanished between the listing and the read is listed as
/// unobservable (it was not scanned, and is never counted as scanned).
#[derive(Debug, Default, Clone)]
pub struct TreeScan {
    /// Files read and scanned.
    pub read: usize,
    /// `<kind> file #<n>: <error kind>` or `<kind> directory: <error kind>` (no path).
    pub not_scanned: Vec<String>,
    /// Files listed but gone before they were read.
    pub vanished: Vec<String>,
}

/// Scan every regular file under `root` (not following links), labelling each hit
/// `<kind> file #<n>` ([`TreeScan`]). In the state database files the effect receipts'
/// own `credential_ref` field is not counted ([`neutralize_receipt_refs`]);
/// `receipt_refs` counts those.
pub fn scan_tree(
    kind: &str,
    root: &Path,
    needles: &[Needles],
    hits: &mut Vec<Hit>,
    receipt_refs: &mut usize,
) -> TreeScan {
    let mut t = TreeScan::default();
    let mut files = Vec::new();
    collect_files(kind, root, true, &mut files, &mut t.not_scanned);
    files.sort();
    for (i, f) in files.iter().enumerate() {
        match std::fs::read(f) {
            Ok(mut bytes) => {
                if f.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("state.db"))
                {
                    *receipt_refs += neutralize_receipt_refs(&mut bytes, needles);
                }
                scan(&format!("{kind} file #{i}"), &bytes, needles, hits);
                t.read += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                t.vanished
                    .push(format!("{kind} file #{i} vanished before it was read"));
            }
            Err(e) => t
                .not_scanned
                .push(format!("{kind} file #{i}: {:?}", e.kind())),
        }
    }
    t
}

/// The one place a canary-prefixed value may be stored: the test configuration's fake
/// adapter names its credential reference `HEIMDALL_CANARY_<…>` (`heimdall::testcfg`;
/// its contract: never in an envelope, event or log line), and an operation's effect
/// receipt records the adapter's credential reference by design (`"credential_ref":"…"`,
/// what recovery reconciles against). Each such field in a state database file is
/// blanked before the scan (and counted), unless the value is a canary **this test**
/// placed, which may appear nowhere. Every other occurrence still counts.
fn neutralize_receipt_refs(bytes: &mut [u8], needles: &[Needles]) -> usize {
    const FIELD: &[u8] = b"\"credential_ref\":\"";
    let prefix = heimdall_testkit::CANARY_PREFIX.as_bytes();
    let placed: Vec<&Vec<u8>> = needles
        .iter()
        .filter(|n| n.kind == "canary")
        .flat_map(|n| n.forms.iter())
        .filter(|f| f.as_slice() != prefix)
        .collect();
    let mut count = 0;
    let mut i = 0;
    while let Some(o) = find(&bytes[i..], FIELD) {
        let at = i + o + FIELD.len();
        let rest = &bytes[at..];
        if rest.starts_with(prefix) && !placed.iter().any(|p| rest.starts_with(p)) {
            for b in &mut bytes[at..at + prefix.len()] {
                *b = b'_';
            }
            count += 1;
        }
        i = at;
    }
    count
}

/// Every regular file under `dir`; a directory or entry that cannot be read is recorded
/// in `gaps` (a `root` that does not exist is no gap: nothing was written there).
fn collect_files(
    kind: &str,
    dir: &Path,
    root: bool,
    out: &mut Vec<std::path::PathBuf>,
    gaps: &mut Vec<String>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if root && e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            gaps.push(format!("{kind} directory: {:?}", e.kind()));
            return;
        }
    };
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(err) => {
                gaps.push(format!("{kind} directory entry: {:?}", err.kind()));
                continue;
            }
        };
        let t = match e.file_type() {
            Ok(t) => t,
            Err(err) => {
                gaps.push(format!("{kind} directory entry type: {:?}", err.kind()));
                continue;
            }
        };
        if t.is_dir() {
            collect_files(kind, &e.path(), false, out, gaps);
        } else if t.is_file() {
            out.push(e.path());
        }
    }
}

/// `hits` as a failure message (kinds and offsets only).
pub fn describe(hits: &[Hit]) -> String {
    hits.iter()
        .map(|h| format!("{} in {} at offset {}", h.secret, h.artifact, h.offset))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Standard base64 (padding optional); `None` for another character.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
        }
    }
    Some(out)
}

/// What [`artifacts`] scanned.
#[derive(Debug, Default)]
pub struct Scanned {
    pub outputs: usize,
    pub files: usize,
    pub crash_files: usize,
    pub argv: usize,
    pub environ: usize,
    /// How many of the test's own placed entries the environment readings saw (a
    /// control: the reading sees a value where it was put).
    pub placed_seen: usize,
    /// The fake adapter's canary credential references in effect receipts, not
    /// counted ([`neutralize_receipt_refs`]).
    pub receipt_refs: usize,
    /// What could not be read here, each `<what>: <why>` (no path, user or secret).
    pub unobservable: Vec<String>,
    /// ⟨W6-R04⟩ Files and directories that exist but could not be read: incomplete
    /// coverage, which A33 fails on (never counted as scanned).
    pub not_scanned: Vec<String>,
}

impl Scanned {
    pub fn summary(&self) -> String {
        format!(
            "outputs={} files={} crash_files={} process_argv={} process_environ={}",
            self.outputs, self.files, self.crash_files, self.argv, self.environ
        )
    }
}

/// Scan every artifact of `w` for `needles` (m03-plan §0.2): every output the binary
/// printed (the transcript: envelopes, errors, the doctor report, events), every file
/// under the Heimdall home (the state database and its journal, the runtime and data
/// directories, the log, the rendered managed configuration, the issuer store), the
/// account home's `.ssh` (P's include, known hosts), the worker records, the crash
/// artifacts ([`crash_files`]), and the argument vector and environment of each process
/// in `pids` (`(kind, pid)`, the run's live processes) as far as this platform shows
/// them. `placed` are environment entries (`NAME=VALUE`) the test itself gave those
/// processes (a canary placed in an unrelated variable): exactly those entries are not
/// counted in an environment; anywhere else they are.
pub fn artifacts(
    w: &crate::world::World,
    needles: &[Needles],
    pids: &[(&str, u32)],
    placed: &[String],
    hits: &mut Vec<Hit>,
) -> Scanned {
    let mut s = Scanned::default();
    for (i, (label, bytes)) in w.transcript.lock().unwrap().entries.iter().enumerate() {
        scan(&format!("output #{i} ({label})"), bytes, needles, hits);
        s.outputs += 1;
    }
    let add = |s: &mut Scanned, t: TreeScan| {
        s.files += t.read;
        s.not_scanned.extend(t.not_scanned);
        s.unobservable.extend(t.vanished);
    };
    let t = scan_tree("heimdall home", &w.hh, needles, hits, &mut s.receipt_refs);
    add(&mut s, t);
    let t = scan_tree(
        "account .ssh",
        &w.home.ssh_dir,
        needles,
        hits,
        &mut s.receipt_refs,
    );
    add(&mut s, t);
    if let Ok(entries) = std::fs::read_dir(&w.home.root) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("worker") {
                let t = scan_tree(
                    "worker record",
                    &e.path(),
                    needles,
                    hits,
                    &mut s.receipt_refs,
                );
                add(&mut s, t);
            }
        }
    }
    let (crash, why) = crash_files(w);
    s.unobservable.extend(why);
    for (i, f) in crash.iter().enumerate() {
        match std::fs::read(f) {
            Ok(bytes) => {
                scan(&format!("crash artifact #{i}"), &bytes, needles, hits);
                s.crash_files += 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => s
                .unobservable
                .push(format!("crash artifact #{i} vanished before it was read")),
            Err(e) => s
                .not_scanned
                .push(format!("crash artifact #{i}: {:?}", e.kind())),
        }
    }
    for (kind, pid) in pids {
        if !crate::procs::alive(*pid) {
            continue;
        }
        let (argv, environ) = crate::procs::argv_environ(*pid);
        match argv {
            Ok(b) => {
                scan(&format!("argv of the {kind} process"), &b, needles, hits);
                s.argv += 1;
            }
            Err(why) => s
                .unobservable
                .push(format!("argv of the {kind} process: {why}")),
        }
        match environ {
            Ok(b) => {
                let is_placed = |entry: &&[u8]| placed.iter().any(|p| p.as_bytes() == *entry);
                s.placed_seen += b.split(|&c| c == 0).filter(is_placed).count();
                let kept: Vec<u8> = b
                    .split(|&c| c == 0)
                    .filter(|entry| !is_placed(entry))
                    .flat_map(|entry| entry.iter().copied().chain([0]))
                    .collect();
                scan(
                    &format!("environment of the {kind} process"),
                    &kept,
                    needles,
                    hits,
                );
                s.environ += 1;
            }
            Err(why) => {
                s.unobservable
                    .push(format!("environment of the {kind} process: {why}"));
            }
        }
    }
    s.unobservable.sort();
    s.unobservable.dedup();
    s.not_scanned.sort();
    s.not_scanned.dedup();
    s
}

/// The crash artifacts a run of the binary could have left, and what cannot be looked
/// at here:
/// * every process the world starts runs in the scratch root, so a core file lands
///   there (`core*`);
/// * macOS: the account's `~/Library/Logs/DiagnosticReports` entries named `heimdall*`
///   written since the world started (names and these files only);
/// * Linux: a `core_pattern` that pipes to a handler (systemd-coredump) keeps its dumps
///   where only root reads them (unobservable);
/// * Windows: `%LOCALAPPDATA%\CrashDumps\heimdall*` written since the world started.
pub fn crash_files(w: &crate::world::World) -> (Vec<std::path::PathBuf>, Vec<String>) {
    let mut out = Vec::new();
    #[allow(unused_mut)] // only macOS and Linux add a reason
    let mut why = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&w.home.root) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("core") && e.path().is_file() {
                out.push(e.path());
            }
        }
    }
    let age = heimdall_contract::Timestamp::now().duration_since(w.started);
    let since = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(
            u64::try_from(age.as_secs()).unwrap_or(0) + 5,
        ))
        .unwrap_or(std::time::UNIX_EPOCH);
    #[cfg(target_os = "macos")]
    match heimdall_localenv::sys::account_home() {
        Ok(home) => recent_heimdall(
            &home.join("Library/Logs/DiagnosticReports"),
            since,
            &mut out,
        ),
        Err(_) => why.push("macOS crash reports: the account home is unknown".to_owned()),
    }
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string("/proc/sys/kernel/core_pattern").is_ok_and(|p| p.starts_with('|')) {
        why.push(
            "system core dumps: core_pattern pipes to a handler whose dumps only root reads"
                .to_owned(),
        );
    }
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        recent_heimdall(&Path::new(&local).join("CrashDumps"), since, &mut out);
    }
    let _ = since;
    (out, why)
}

/// The files of `dir` named `heimdall*` (any case) modified at or after `since`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn recent_heimdall(dir: &Path, since: std::time::SystemTime, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        let fresh = e
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| t >= since);
        if name.starts_with("heimdall") && fresh && e.path().is_file() {
            out.push(e.path());
        }
    }
}

/// The scanner's positive control: the CA's **public** blob, which the state database
/// and the registry rendering hold by design, is found under the Heimdall home by the
/// same reading (so a zero count of secret hits is a reading of the real files).
pub fn public_control(w: &crate::world::World) -> usize {
    let blob = w
        .ca_public
        .split_whitespace()
        .nth(1)
        .unwrap()
        .as_bytes()
        .to_vec();
    let needles = [Needles {
        kind: "ca public (control)",
        forms: vec![blob],
    }];
    let mut hits = Vec::new();
    let _ = scan_tree("heimdall home", &w.hh, &needles, &mut hits, &mut 0);
    hits.len()
}
