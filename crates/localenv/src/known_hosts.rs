//! Known-host lookup (m02-plan U3): `ssh-keygen -F` as a local query, or a parse of
//! plain (unhashed) entries. Never writes `known_hosts`.
//!
//! The files are OpenSSH's defaults: `~/.ssh/known_hosts`, `~/.ssh/known_hosts2`,
//! `<system dir>/ssh_known_hosts` and `<system dir>/ssh_known_hosts2`. The name looked
//! up is `host`, or `[host]:port` for a port other than 22. Plain entries are matched
//! here (comma-separated patterns, `*`/`?` wildcards, `!` negation, case-insensitive);
//! a hashed entry (`|1|…`) can be matched only by `ssh-keygen -F <name> -f <file>`
//! (a local query that reads that file only). When a file holds hashed entries and the
//! query cannot run, the lookup is not complete and the doctor claims no
//! `known_host_missing`. `@cert-authority` lines are not host keys and are skipped;
//! `@revoked` keys are reported with `revoked`.
//!
//! ⟨M03⟩ **Raw public keys** (m03-plan U5, §0.4 M10; ADR-0008 §17.1 item 12):
//! [`lookup_raw_in`] is an additive variant of [`lookup_in`] that also returns each
//! key's base64 blob ([`RawHostKeyObservation`]), for `localenv::target`'s
//! `TargetEvaluator`. It reads the same files the same way and never writes; it is
//! stricter about what counts as a host key: a line whose blob does not decode, whose
//! blob names another key type than its type field, or whose type is a certificate
//! type is not a key, and marks the lookup incomplete (it cannot be checked). The M02
//! functions above keep their behaviour.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::fs::read_bounded;
use crate::local_query::{
    LOCAL_QUERY_OUTPUT_BYTES, LOCAL_QUERY_TIMEOUT, LocalQueries, Spec, run_contained,
};
use crate::paths::SshPaths;

/// Bytes read per known-hosts file.
pub const KNOWN_HOSTS_FILE_BYTES: usize = 8 << 20;

/// One host key Heimdall found for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyObservation {
    /// Key type (`ssh-ed25519` …).
    pub key_type: String,
    /// SHA-256 fingerprint (`SHA256:…`).
    pub fingerprint: String,
    /// The known-hosts file and line (display form).
    pub origin_display: String,
    /// Whether the entry is marked `@revoked`.
    pub revoked: bool,
}

/// A lookup with its completeness.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KnownHostsLookup {
    /// The keys found.
    pub keys: Vec<HostKeyObservation>,
    /// Whether every entry of every readable file could be matched (no hashed entry
    /// was left unchecked and no file was unreadable).
    pub complete: bool,
}

/// Known host keys for `host:port` in the default files. Hashed entries are matched
/// with the `ssh-keygen` found on this process's `PATH` (the doctor passes the
/// inventory's through [`lookup_detailed`]).
#[must_use]
pub fn lookup(
    paths: &SshPaths,
    host: &str,
    port: u16,
    queries: LocalQueries,
) -> Vec<HostKeyObservation> {
    let keygen = std::env::var_os("PATH").and_then(|p| {
        let dirs: Vec<PathBuf> = std::env::split_paths(&p)
            .filter(|d| d.is_absolute())
            .collect();
        crate::clients::search_path(&dirs, "ssh-keygen", crate::env::Platform::current())
    });
    lookup_detailed(paths, host, port, queries, keygen.as_deref()).keys
}

/// The default known-hosts files for `paths`, in OpenSSH's order.
#[must_use]
pub fn default_files(paths: &SshPaths) -> Vec<PathBuf> {
    vec![
        paths.user_dir.join("known_hosts"),
        paths.user_dir.join("known_hosts2"),
        paths.system_dir.join("ssh_known_hosts"),
        paths.system_dir.join("ssh_known_hosts2"),
    ]
}

/// The name OpenSSH looks up: `host`, or `[host]:port` when the port is not 22.
#[must_use]
pub fn lookup_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// [`lookup`] over `files`, with the `ssh-keygen` to use for hashed entries.
#[must_use]
pub fn lookup_in(
    files: &[PathBuf],
    home: &Path,
    host: &str,
    port: u16,
    queries: LocalQueries,
    keygen: Option<&Path>,
) -> KnownHostsLookup {
    let name = lookup_name(&host.to_ascii_lowercase(), port);
    let mut out = KnownHostsLookup {
        keys: Vec::new(),
        complete: true,
    };
    for file in files {
        let bytes = match read_bounded(file, KNOWN_HOSTS_FILE_BYTES) {
            Ok(b) => b.bytes,
            Err(heimdall_sshconf::include::SourceError::NotFound) => continue,
            Err(_) => {
                out.complete = false;
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        let display = crate::paths::display_path(home, file);
        let hashed = text.lines().any(|l| {
            let (_, rest) = split_marker(l.trim_start());
            rest.starts_with("|1|")
        });
        if hashed {
            match (queries, keygen) {
                (LocalQueries::Enabled, Some(keygen)) => match keygen_lookup(keygen, file, &name) {
                    Some(found) => {
                        for (line, entry) in found {
                            if let Some(k) = entry_key(&entry, &display, line) {
                                out.keys.push(k);
                            }
                        }
                        continue;
                    }
                    None => out.complete = false,
                },
                _ => out.complete = false,
            }
        }
        for (i, raw) in text.lines().enumerate() {
            let line = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let l = raw.trim_start();
            let (_, rest) = split_marker(l);
            if rest.starts_with("|1|") {
                continue;
            }
            if let Some(hosts) = rest.split_whitespace().next()
                && hosts_match(hosts, &name)
                && let Some(k) = entry_key(l, &display, line)
            {
                out.keys.push(k);
            }
        }
    }
    out
}

/// [`lookup`] with the default files and an explicit `ssh-keygen`.
#[must_use]
pub fn lookup_detailed(
    paths: &SshPaths,
    host: &str,
    port: u16,
    queries: LocalQueries,
    keygen: Option<&Path>,
) -> KnownHostsLookup {
    lookup_in(
        &default_files(paths),
        &paths.account_home,
        host,
        port,
        queries,
        keygen,
    )
}

/// `ssh-keygen -F <name> -f <file>`: the matching lines with their line numbers, or
/// `None` when the query failed.
fn keygen_lookup(keygen: &Path, file: &Path, name: &str) -> Option<Vec<(u32, String)>> {
    let out = run_contained(&Spec {
        program: keygen,
        args: vec!["-F".into(), name.into(), "-f".into(), file.into()],
        env: None,
        cwd: None,
        timeout: LOCAL_QUERY_TIMEOUT,
        max_output: LOCAL_QUERY_OUTPUT_BYTES,
    })
    .ok()?;
    if out.timed_out {
        return None;
    }
    match out.status.and_then(|s| s.code()) {
        Some(0) => {}
        Some(1) => return Some(Vec::new()),
        _ => return None,
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    let mut line = 0u32;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("# Host ") {
            line = rest
                .rsplit_once("found: line ")
                .and_then(|(_, n)| n.trim().parse().ok())
                .unwrap_or(0);
            continue;
        }
        if l.trim().is_empty() || l.starts_with('#') {
            continue;
        }
        found.push((line, l.to_owned()));
    }
    Some(found)
}

fn split_marker(l: &str) -> (Option<&str>, &str) {
    if let Some(rest) = l.strip_prefix('@') {
        let mut it = rest.splitn(2, char::is_whitespace);
        let marker = it.next().unwrap_or_default();
        return (Some(marker), it.next().unwrap_or_default().trim_start());
    }
    (None, l)
}

/// The key of one known-hosts line (`[@marker] hosts type base64 [comment]`), or
/// `None` for a comment, a `@cert-authority` line or a malformed line.
fn entry_key(l: &str, display: &str, line: u32) -> Option<HostKeyObservation> {
    let l = l.trim_start();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    let (marker, rest) = split_marker(l);
    let revoked = match marker {
        None => false,
        Some(m) if m.eq_ignore_ascii_case("revoked") => true,
        Some(_) => return None,
    };
    let mut fields = rest.split_whitespace();
    let _hosts = fields.next()?;
    let key_type = fields.next()?;
    let blob = base64_decode(fields.next()?)?;
    Some(HostKeyObservation {
        key_type: key_type.to_owned(),
        fingerprint: fingerprint(&blob),
        origin_display: format!("{display}:{line}"),
        revoked,
    })
}

/// Whether a plain hosts field (`pattern[,pattern…]`) matches `name` (lowercase).
#[must_use]
pub fn hosts_match(hosts: &str, name: &str) -> bool {
    let mut matched = false;
    for pattern in hosts.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        if wildcard_match(&pattern.to_ascii_lowercase(), name) {
            if negated {
                return false;
            }
            matched = true;
        }
    }
    matched
}

/// `*` and `?` wildcard matching over bytes (OpenSSH `match_pattern`).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// `SHA256:<unpadded base64>` of a public key blob, as `ssh-keygen -l` prints it.
#[must_use]
pub fn fingerprint(blob: &[u8]) -> String {
    let digest = Sha256::digest(blob);
    format!("SHA256:{}", base64_encode_unpadded(&digest))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 without padding.
#[must_use]
pub fn base64_encode_unpadded(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(B64[idx as usize]));
        }
    }
    out
}

// --- ⟨M03⟩ raw public keys (additive; m03-plan U5, M10) --------------------------------

/// ⟨M03⟩ One host key with its raw public key (m03-plan U5; M10): what
/// [`HostKeyObservation`] reports plus the key blob, for an approved target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHostKeyObservation {
    /// Key type (`ssh-ed25519` …), as the line writes it and the blob names it.
    pub key_type: String,
    /// The key blob, standard base64 **with** padding (OpenSSH's own form), re-encoded
    /// from the decoded bytes so that two spellings of one key compare equal.
    pub key_b64: String,
    /// SHA-256 fingerprint (`SHA256:…`) of the blob.
    pub fingerprint: String,
    /// The known-hosts file and line (display form).
    pub origin_display: String,
    /// Whether the entry is marked `@revoked`.
    pub revoked: bool,
}

impl RawHostKeyObservation {
    /// The M02 observation of this key (no blob).
    #[must_use]
    pub fn observation(&self) -> HostKeyObservation {
        HostKeyObservation {
            key_type: self.key_type.clone(),
            fingerprint: self.fingerprint.clone(),
            origin_display: self.origin_display.clone(),
            revoked: self.revoked,
        }
    }
}

/// ⟨M03⟩ A raw-key lookup with its completeness ([`KnownHostsLookup`]'s rule, plus:
/// a matching line that is not a usable host key leaves it incomplete).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawKnownHostsLookup {
    /// The keys found, in file and line order.
    pub keys: Vec<RawHostKeyObservation>,
    /// Whether every entry of every readable file could be matched and decoded.
    pub complete: bool,
}

/// ⟨M03⟩ [`lookup_in`] with each key's raw blob (module documentation). Passive: it
/// reads `files` and, for a file with hashed entries and [`LocalQueries::Enabled`],
/// runs `keygen -F <name> -f <file>` as [`lookup_in`] does. Writes nothing.
#[must_use]
pub fn lookup_raw_in(
    files: &[PathBuf],
    home: &Path,
    host: &str,
    port: u16,
    queries: LocalQueries,
    keygen: Option<&Path>,
) -> RawKnownHostsLookup {
    let name = lookup_name(&host.to_ascii_lowercase(), port);
    let mut out = RawKnownHostsLookup {
        keys: Vec::new(),
        complete: true,
    };
    let push =
        |out: &mut RawKnownHostsLookup, l: &str, display: &str, line: u32| match raw_entry_key(
            l, display, line,
        ) {
            RawEntry::Key(k) => out.keys.push(k),
            RawEntry::NotAKey => {}
            RawEntry::Unusable => out.complete = false,
        };
    for file in files {
        let bytes = match read_bounded(file, KNOWN_HOSTS_FILE_BYTES) {
            Ok(b) => b.bytes,
            Err(heimdall_sshconf::include::SourceError::NotFound) => continue,
            Err(_) => {
                out.complete = false;
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes);
        let display = crate::paths::display_path(home, file);
        let hashed = text.lines().any(|l| {
            let (_, rest) = split_marker(l.trim_start());
            rest.starts_with("|1|")
        });
        if hashed {
            match (queries, keygen) {
                (LocalQueries::Enabled, Some(keygen)) => match keygen_lookup(keygen, file, &name) {
                    Some(found) => {
                        for (line, entry) in found {
                            push(&mut out, &entry, &display, line);
                        }
                        continue;
                    }
                    None => out.complete = false,
                },
                _ => out.complete = false,
            }
        }
        for (i, raw) in text.lines().enumerate() {
            let line = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let l = raw.trim_start();
            let (_, rest) = split_marker(l);
            if rest.starts_with("|1|") {
                continue;
            }
            if let Some(hosts) = rest.split_whitespace().next()
                && hosts_match(hosts, &name)
            {
                push(&mut out, l, &display, line);
            }
        }
    }
    out
}

/// ⟨M03⟩ [`lookup_raw_in`] over the default files of `paths`.
#[must_use]
pub fn lookup_raw_detailed(
    paths: &SshPaths,
    host: &str,
    port: u16,
    queries: LocalQueries,
    keygen: Option<&Path>,
) -> RawKnownHostsLookup {
    lookup_raw_in(
        &default_files(paths),
        &paths.account_home,
        host,
        port,
        queries,
        keygen,
    )
}

enum RawEntry {
    Key(RawHostKeyObservation),
    /// A comment, a blank line or a `@cert-authority` line: not a host key.
    NotAKey,
    /// A matching line that cannot be read as a host key (malformed, mismatched, a
    /// certificate type, an unknown marker): the lookup cannot be complete.
    Unusable,
}

/// The raw key of one matching known-hosts line.
fn raw_entry_key(l: &str, display: &str, line: u32) -> RawEntry {
    let l = l.trim_start();
    if l.is_empty() || l.starts_with('#') {
        return RawEntry::NotAKey;
    }
    let (marker, rest) = split_marker(l);
    let revoked = match marker {
        None => false,
        Some(m) if m.eq_ignore_ascii_case("revoked") => true,
        Some(m) if m.eq_ignore_ascii_case("cert-authority") => return RawEntry::NotAKey,
        Some(_) => return RawEntry::Unusable,
    };
    let mut fields = rest.split_whitespace();
    let (Some(_hosts), Some(key_type), Some(b64)) = (fields.next(), fields.next(), fields.next())
    else {
        return RawEntry::Unusable;
    };
    if key_type.ends_with("-cert-v01@openssh.com") {
        return RawEntry::Unusable;
    }
    let Some(blob) = base64_decode(b64) else {
        return RawEntry::Unusable;
    };
    if blob_key_type(&blob) != Some(key_type) {
        return RawEntry::Unusable;
    }
    RawEntry::Key(RawHostKeyObservation {
        key_type: key_type.to_owned(),
        key_b64: base64_encode_padded(&blob),
        fingerprint: fingerprint(&blob),
        origin_display: format!("{display}:{line}"),
        revoked,
    })
}

/// The key type a public key blob names (its first SSH `string`), when it is ASCII.
fn blob_key_type(blob: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?);
    let end = 4usize.checked_add(usize::try_from(len).ok()?)?;
    let name = blob.get(4..end)?;
    if end >= blob.len() || name.is_empty() || !name.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    std::str::from_utf8(name).ok()
}

/// Standard base64 with padding (the form OpenSSH writes).
#[must_use]
pub fn base64_encode_padded(bytes: &[u8]) -> String {
    let mut out = base64_encode_unpadded(bytes);
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

/// Standard base64 (padding optional); `None` for anything malformed.
#[must_use]
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let t = text.trim_end_matches('=').as_bytes();
    if t.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in t {
        let v = B64.iter().position(|&b| b == c)?;
        acc = (acc << 6) | u32::try_from(v).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A synthetic public key blob (not a real key): `string "ssh-ed25519"`,
    /// `string <32 bytes>`.
    fn blob() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&11u32.to_be_bytes());
        b.extend_from_slice(b"ssh-ed25519");
        b.extend_from_slice(&32u32.to_be_bytes());
        b.extend_from_slice(&[7u8; 32]);
        b
    }

    #[test]
    fn base64_round_trips() {
        for n in 0..10 {
            let data: Vec<u8> = (0..n).map(|i: u8| i.wrapping_mul(37)).collect();
            let enc = base64_encode_unpadded(&data);
            assert_eq!(base64_decode(&enc).unwrap(), data);
        }
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("@@@@").is_none());
    }

    #[test]
    fn plain_entries_match_patterns_ports_negation_and_markers() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        let key = base64_encode_unpadded(&blob());
        std::fs::write(
            &file,
            format!(
                "# comment\n\
                 h1.example,192.0.2.1 ssh-ed25519 {key}\n\
                 [h2.example]:2222 ssh-ed25519 {key} c\n\
                 *.wild.example,!no.wild.example ssh-ed25519 {key}\n\
                 @revoked h3.example ssh-ed25519 {key}\n\
                 @cert-authority h4.example ssh-ed25519 {key}\n\
                 |1|c2FsdA==|aGFzaA== ssh-ed25519 {key}\n"
            ),
        )
        .unwrap();
        let files = vec![file, dir.path().join("absent")];
        let look =
            |h: &str, p: u16| lookup_in(&files, dir.path(), h, p, LocalQueries::Disabled, None);
        let r = look("H1.example", 22);
        assert_eq!(r.keys.len(), 1);
        assert_eq!(r.keys[0].fingerprint, fingerprint(&blob()));
        assert!(r.keys[0].origin_display.ends_with(":2"));
        // The hashed line could not be checked without the query.
        assert!(!r.complete);
        assert_eq!(look("h2.example", 2222).keys.len(), 1);
        assert!(look("h2.example", 22).keys.is_empty());
        assert_eq!(look("a.wild.example", 22).keys.len(), 1);
        assert!(look("no.wild.example", 22).keys.is_empty());
        let revoked = look("h3.example", 22);
        assert!(revoked.keys[0].revoked);
        assert!(look("h4.example", 22).keys.is_empty());
    }

    /// ⟨M03⟩ The raw lookup reports the blob, re-encoded with padding, for exactly the
    /// keys the M02 lookup reports, and leaves the lookup incomplete for a matching line
    /// it cannot use.
    #[test]
    fn raw_lookup_reports_blobs_and_refuses_unusable_lines() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        let key = base64_encode_unpadded(&blob());
        let padded = base64_encode_padded(&blob());
        assert_eq!(padded.len() % 4, 0);
        assert!(padded.starts_with(&key));
        std::fs::write(
            &file,
            format!(
                "# comment\n\
                 h1.example ssh-ed25519 {key}\n\
                 [h2.example]:2222 ssh-ed25519 {padded} c\n\
                 @revoked h3.example ssh-ed25519 {key}\n\
                 @cert-authority h4.example ssh-ed25519 {key}\n\
                 h5.example ssh-rsa {key}\n\
                 h6.example ssh-ed25519-cert-v01@openssh.com {key}\n\
                 h7.example ssh-ed25519 not*base64\n\
                 @other h8.example ssh-ed25519 {key}\n"
            ),
        )
        .unwrap();
        let files = vec![file];
        let raw =
            |h: &str, p: u16| lookup_raw_in(&files, dir.path(), h, p, LocalQueries::Disabled, None);
        let old =
            |h: &str, p: u16| lookup_in(&files, dir.path(), h, p, LocalQueries::Disabled, None);
        for (h, p) in [("h1.example", 22), ("h2.example", 2222), ("h3.example", 22)] {
            let r = raw(h, p);
            assert!(r.complete, "{h}");
            assert_eq!(r.keys.len(), 1, "{h}");
            assert_eq!(r.keys[0].key_b64, padded);
            assert_eq!(r.keys[0].key_type, "ssh-ed25519");
            assert_eq!(r.keys[0].fingerprint, fingerprint(&blob()));
            let o = old(h, p);
            assert_eq!(
                r.keys
                    .iter()
                    .map(RawHostKeyObservation::observation)
                    .collect::<Vec<_>>(),
                o.keys
            );
        }
        assert!(raw("h3.example", 22).keys[0].revoked);
        // A CA line is not a host key, and does not make the lookup incomplete.
        let ca = raw("h4.example", 22);
        assert!(ca.complete && ca.keys.is_empty());
        // A type that disagrees with the blob, a certificate type, a malformed blob
        // and an unknown marker are unusable: no key, incomplete.
        for h in ["h5.example", "h6.example", "h7.example", "h8.example"] {
            let r = raw(h, 22);
            assert!(r.keys.is_empty(), "{h}");
            assert!(!r.complete, "{h}");
        }
        assert!(raw("absent.example", 22).complete);
    }

    #[test]
    fn hashed_entries_are_matched_by_ssh_keygen() {
        let Some(keygen) = std::env::var_os("PATH").and_then(|p| {
            let dirs: Vec<PathBuf> = std::env::split_paths(&p).collect();
            crate::clients::search_path(&dirs, "ssh-keygen", crate::env::Platform::current())
        }) else {
            // ssh-keygen ships with every target client; its absence is a broken host.
            panic!("ssh-keygen not found on PATH");
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("known_hosts");
        let key = base64_encode_unpadded(&blob());
        std::fs::write(&file, format!("[h5.example]:2200 ssh-ed25519 {key}\n")).unwrap();
        // Hash it in place with ssh-keygen -H (scratch file only).
        let status = std::process::Command::new(&keygen)
            .args(["-H", "-f"])
            .arg(&file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.starts_with("|1|"), "not hashed");
        let files = vec![file];
        let r = lookup_in(
            &files,
            dir.path(),
            "h5.example",
            2200,
            LocalQueries::Enabled,
            Some(&keygen),
        );
        assert!(r.complete);
        assert_eq!(r.keys.len(), 1);
        assert_eq!(r.keys[0].fingerprint, fingerprint(&blob()));
        assert!(r.keys[0].origin_display.ends_with(":1"));
        let none = lookup_in(
            &files,
            dir.path(),
            "h6.example",
            22,
            LocalQueries::Enabled,
            Some(&keygen),
        );
        assert!(none.complete && none.keys.is_empty());
        // ⟨M03⟩ The raw lookup reads the hashed entry through the same query.
        let raw = lookup_raw_in(
            &files,
            dir.path(),
            "h5.example",
            2200,
            LocalQueries::Enabled,
            Some(&keygen),
        );
        assert!(raw.complete);
        assert_eq!(raw.keys.len(), 1);
        assert_eq!(raw.keys[0].key_b64, base64_encode_padded(&blob()));
        let raw_off = lookup_raw_in(
            &files,
            dir.path(),
            "h5.example",
            2200,
            LocalQueries::Disabled,
            None,
        );
        assert!(!raw_off.complete && raw_off.keys.is_empty());
    }
}
