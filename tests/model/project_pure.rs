//! M05 U1 (hosted by heimdall-project): the pure project crate. The manifest parser (bounds,
//! authority vocabulary, closed schema, values), the access digest, workspace discovery and
//! `match_workspace` over an in-memory `FsView` (the ADR-0011 §2.3 table, property P11 and
//! ruling §10 item 7's `gitdir` cases), and the portable bundle (round trip, authority
//! sections refused at any depth). Ruling §10 item 9: the hostile byte cases are fixed
//! examples in this file.
//!
//! Nothing here touches the real filesystem, a process or the network; every path below is
//! an in-memory fixture. Seeds: a fixed default, overridden by `PROPTEST_RNG_SEED`; failures
//! persist next to this file in `proptest-regressions`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use heimdall_contract::Timestamp;
use heimdall_contract::envelope::reason::{MANIFEST_AUTHORITY_KEY, MANIFEST_INVALID};
use heimdall_contract::ids::{
    AccountName, DecisionId, DestinationId, EnvironmentId, ProfileId, WorkspaceId,
};
use heimdall_contract::project::{
    MAX_MANIFEST_BYTES, MAX_MANIFEST_PAIRS, PORTABLE_BUNDLE_SCHEMA, PortableDestination,
    PortableIdentity, PortableProfile,
};
use heimdall_contract::request::Capability;
use heimdall_domain::projection::FileIdentity;
use heimdall_domain::workspace::{
    AmbiguityReason, WorkspaceMatch, WorkspaceRecord, WorkspaceState,
};
use heimdall_project::manifest::InvalidReason;
use heimdall_project::{
    BundleError, BundleInput, FsKind, FsView, GitObservation, MANIFEST_AUTHORITY_KEYS,
    ManifestError, ObserveError, ParsedManifest, ReadOutcome, WorkspaceObservation, access_digest,
    emit_bundle, match_workspace, observe_workspace, parse_bundle, parse_manifest,
};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

fn config(cases: u32, seed: u64) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

// =================================================================================
// The in-memory filesystem
// =================================================================================

#[derive(Debug, Clone)]
enum Node {
    Dir,
    File(Vec<u8>),
    Symlink(PathBuf),
    Fifo,
}

/// An in-memory filesystem: absolute Unix-style paths, symlinks, FIFOs, per-entry file
/// identities (or none at all), and a count of manifest-style reads.
#[derive(Debug, Default)]
struct MemFs {
    nodes: BTreeMap<PathBuf, Node>,
    ids: BTreeMap<PathBuf, FileIdentity>,
    no_identities: bool,
    next_ino: u64,
    reads: RefCell<BTreeMap<PathBuf, usize>>,
    refused_path: Option<PathBuf>,
    canonicalizations: RefCell<Vec<PathBuf>>,
}

impl MemFs {
    fn new() -> Self {
        let mut fs = Self {
            next_ino: 1,
            ..Self::default()
        };
        fs.dir("/");
        fs
    }

    fn fresh_identity(&mut self, dev: u64) -> FileIdentity {
        self.next_ino += 1;
        FileIdentity::Unix {
            dev,
            ino: self.next_ino,
            birth: None,
        }
    }

    fn put(&mut self, path: &str, node: Node) {
        let id = self.fresh_identity(1);
        // A pointer file's absolute paths are written the way Git writes them on this
        // platform (`git_text`).
        let node = match node {
            Node::File(bytes)
                if matches!(
                    Path::new(path).file_name().and_then(|n| n.to_str()),
                    Some(".git" | "gitdir")
                ) =>
            {
                Node::File(git_text(&bytes))
            }
            other => other,
        };
        self.nodes.insert(PathBuf::from(p(path)), node);
        self.ids.insert(PathBuf::from(p(path)), id);
    }

    fn dir(&mut self, path: &str) -> &mut Self {
        self.put(path, Node::Dir);
        self
    }
    fn file(&mut self, path: &str, bytes: &[u8]) -> &mut Self {
        self.put(path, Node::File(bytes.to_vec()));
        self
    }
    fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
        // An absolute target is a fixture path (`p`); a relative one stays relative.
        let target = if target.starts_with('/') {
            p(target)
        } else {
            target.to_owned()
        };
        self.put(path, Node::Symlink(PathBuf::from(target)));
        self
    }
    fn fifo(&mut self, path: &str) -> &mut Self {
        self.put(path, Node::Fifo);
        self
    }

    /// `cp -R`: every entry under `from` copied under `to` with fresh identities (on the
    /// device `dev`); symlinks are copied as links.
    fn copy_tree(&mut self, from: &str, to: &str, dev: u64) {
        let from = PathBuf::from(p(from));
        let to = PathBuf::from(p(to));
        let entries: Vec<(PathBuf, Node)> = self
            .nodes
            .iter()
            .filter(|(p, _)| p.starts_with(&from))
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect();
        for (p, n) in entries {
            let dest = to.join(p.strip_prefix(&from).unwrap());
            let id = self.fresh_identity(dev);
            self.nodes.insert(dest.clone(), n);
            self.ids.insert(dest, id);
        }
    }

    /// `rm -r`.
    fn remove_tree(&mut self, path: &str) {
        let path = PathBuf::from(p(path));
        self.nodes.retain(|p, _| !p.starts_with(&path));
        self.ids.retain(|p, _| !p.starts_with(&path));
    }

    /// `mv` within one filesystem: identities travel with the entries.
    fn rename_tree(&mut self, from: &str, to: &str) {
        let from = PathBuf::from(p(from));
        let to = PathBuf::from(p(to));
        let moved: Vec<PathBuf> = self
            .nodes
            .keys()
            .filter(|p| p.starts_with(&from))
            .cloned()
            .collect();
        for p in moved {
            let dest = to.join(p.strip_prefix(&from).unwrap());
            let node = self.nodes.remove(&p).unwrap();
            let id = self.ids.remove(&p).unwrap();
            self.nodes.insert(dest.clone(), node);
            self.ids.insert(dest, id);
        }
    }

    fn id_of(&self, path: &str) -> FileIdentity {
        self.ids[&PathBuf::from(p(path))].clone()
    }

    fn read_count(&self, path: &str) -> usize {
        self.reads
            .borrow()
            .get(&PathBuf::from(p(path)))
            .copied()
            .unwrap_or(0)
    }

    /// Resolve every symlink and `..`.
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        let not_found = || io::Error::from(io::ErrorKind::NotFound);
        let mut queue: Vec<String> = components(path).into_iter().rev().collect();
        let mut resolved = root_of(path).ok_or_else(not_found)?;
        let mut hops = 0;
        while let Some(part) = queue.pop() {
            match part.as_str() {
                "." => {}
                ".." => {
                    resolved.pop();
                }
                name => {
                    let candidate = resolved.join(name);
                    match self.nodes.get(&candidate) {
                        None => return Err(not_found()),
                        Some(Node::Symlink(target)) => {
                            hops += 1;
                            if hops > 40 {
                                return Err(io::Error::other("symlink loop"));
                            }
                            if target.is_absolute() {
                                resolved = root_of(target).ok_or_else(not_found)?;
                            }
                            queue.extend(components(target).into_iter().rev());
                        }
                        Some(Node::Dir) => resolved = candidate,
                        Some(_) => {
                            if !queue.is_empty() {
                                return Err(not_found());
                            }
                            resolved = candidate;
                        }
                    }
                }
            }
        }
        Ok(resolved)
    }

    /// `lstat` resolution: parents resolved, the last component not followed.
    fn lresolve(&self, path: &Path) -> io::Result<Option<PathBuf>> {
        let Some(name) = path.file_name() else {
            return Ok(Some(self.resolve(path)?));
        };
        let Some(parent) = path.parent() else {
            return Ok(root_of(path));
        };
        match self.resolve(parent) {
            Ok(p) => {
                let entry = p.join(name);
                Ok(self.nodes.contains_key(&entry).then_some(entry))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// ⟨W1 Windows fix⟩ A fixture path, written Unix-style in these tests, in the form this
/// platform's canonical paths take. Unix: unchanged. Windows: the verbatim form
/// `std::fs::canonicalize` returns (`/work/proj` → `\\?\C:\work\proj`), so fixture keys
/// and observed roots are what the runtime's real `FsView` produces there.
fn p(unix: &str) -> String {
    if cfg!(windows) && unix.starts_with('/') {
        format!(
            r"\\?\C:\{}",
            unix.trim_start_matches('/').replace('/', "\\")
        )
    } else {
        unix.to_owned()
    }
}

/// A working directory as a caller passes it: on Windows drive-qualified and not
/// canonical (`C:\work\proj`), so every test also proves the canonicalization to `p`'s
/// form. Anything not starting with `/` is passed through unchanged.
fn cwd_arg(unix: &str) -> String {
    if cfg!(windows) && unix.starts_with('/') {
        format!(r"C:\{}", unix.trim_start_matches('/').replace('/', "\\"))
    } else {
        unix.to_owned()
    }
}

/// Pointer-file text (`.git`, `<entry>/gitdir`) with absolute paths written the way Git
/// writes them on this platform: Git for Windows writes `C:/work/...` (a drive letter and
/// forward slashes). An absolute path is one starting at the text's start or right after a
/// space or a newline; relative paths (`../.git/modules/sub`) are unchanged.
fn git_text(bytes: &[u8]) -> Vec<u8> {
    if !cfg!(windows) {
        return bytes.to_vec();
    }
    let mut out = Vec::with_capacity(bytes.len() + 8);
    for (i, &b) in bytes.iter().enumerate() {
        let starts = i == 0 || matches!(bytes[i - 1], b' ' | b'\n');
        if b == b'/' && starts {
            out.extend_from_slice(b"C:");
        }
        out.push(b);
    }
    out
}

/// The root of an absolute path as this platform's canonical form has it: `/` on Unix; on
/// Windows the verbatim drive or UNC root (`\\?\C:\`, `\\?\UNC\server\share\`), whatever
/// form the input used, as `std::fs::canonicalize` returns. `None` for a relative path.
fn root_of(path: &Path) -> Option<PathBuf> {
    use std::path::{Component, Prefix};
    let mut comps = path.components();
    match comps.next()? {
        Component::RootDir if cfg!(unix) => Some(PathBuf::from("/")),
        Component::Prefix(pre) => {
            if comps.next() != Some(Component::RootDir) {
                return None;
            }
            let root = match pre.kind() {
                Prefix::Disk(l) | Prefix::VerbatimDisk(l) => {
                    format!(r"\\?\{}:\", char::from(l).to_ascii_uppercase())
                }
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
                    r"\\?\UNC\{}\{}\",
                    server.to_string_lossy(),
                    share.to_string_lossy()
                ),
                _ => return None,
            };
            Some(PathBuf::from(root))
        }
        _ => None,
    }
}

fn components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            std::path::Component::ParentDir => Some("..".to_owned()),
            _ => None,
        })
        .collect()
}

impl FsView for MemFs {
    fn allows_local_path(&self, path: &Path) -> bool {
        self.refused_path.as_deref() != Some(path)
    }

    fn kind(&self, path: &Path) -> io::Result<Option<FsKind>> {
        Ok(self.lresolve(path)?.map(|p| match &self.nodes[&p] {
            Node::Dir => FsKind::Dir,
            Node::File(_) => FsKind::File,
            Node::Symlink(_) => FsKind::Symlink,
            Node::Fifo => FsKind::Other,
        }))
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.canonicalizations.borrow_mut().push(path.to_owned());
        self.resolve(path)
    }

    fn identity(&self, path: &Path) -> io::Result<Option<FileIdentity>> {
        if self.no_identities {
            return Ok(None);
        }
        Ok(self.lresolve(path)?.and_then(|p| self.ids.get(&p).cloned()))
    }

    fn read_regular_nofollow(&self, path: &Path, max: usize) -> io::Result<ReadOutcome> {
        let Some(entry) = self.lresolve(path)? else {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        };
        *self.reads.borrow_mut().entry(entry.clone()).or_default() += 1;
        Ok(match &self.nodes[&entry] {
            Node::File(bytes) if bytes.len() > max => ReadOutcome::TooLarge,
            Node::File(bytes) => ReadOutcome::Bytes(bytes.clone()),
            _ => ReadOutcome::NotRegular,
        })
    }
}

// =================================================================================
// Fixtures
// =================================================================================

fn env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([1; 16])
}

fn other_env() -> EnvironmentId {
    EnvironmentId::from_random_bytes([2; 16])
}

fn ws(n: u8) -> WorkspaceId {
    WorkspaceId::from_random_bytes([n; 16])
}

fn ts() -> Timestamp {
    "2026-11-18T00:00:00Z".parse().unwrap()
}

const MANIFEST: &str = r#"
schema_version = 1
project = "example-infrastructure"
[access]
profile = "homelab-dev"
pairs = ["lab-db:deploy"]
environments = ["native"]
required_capabilities = ["ssh-authentication"]
[preferences]
background_work = true
[metadata]
owner = "platform"
"#;

/// `MANIFEST` without its `[metadata]` table, for tests that append their own.
const BASE: &str = r#"
schema_version = 1
project = "example-infrastructure"
[access]
profile = "homelab-dev"
pairs = ["lab-db:deploy"]
environments = ["native"]
required_capabilities = ["ssh-authentication"]
[preferences]
background_work = true
"#;

fn ok(text: &str) -> ParsedManifest {
    parse_manifest(text.as_bytes()).unwrap_or_else(|e| panic!("expected ok, got {e:?}"))
}

fn authority(text: &str) -> String {
    match parse_manifest(text.as_bytes()) {
        Err(ManifestError::AuthorityKey(k)) => k,
        other => panic!("expected an authority key, got {other:?}"),
    }
}

fn invalid(bytes: &[u8]) -> InvalidReason {
    match parse_manifest(bytes) {
        Err(ManifestError::Invalid(r)) => r,
        other => panic!("expected invalid, got {other:?}"),
    }
}

// =================================================================================
// Manifest: bounds and the hostile byte cases (ruling §10 item 9)
// =================================================================================

#[test]
fn the_documented_example_parses_and_maps_to_its_fields() {
    let p = ok(MANIFEST);
    assert_eq!(p.manifest.access.profile.as_str(), "homelab-dev");
    assert_eq!(p.pairs.len(), 1);
    assert_eq!(p.pairs[0].destination.as_str(), "lab-db");
    assert_eq!(p.pairs[0].account.as_str(), "deploy");
    assert_eq!(p.capabilities, vec![Capability::SshAuthentication]);
    assert_eq!(p.environments, vec!["native".to_owned()]);
    assert!(p.background_work);
    assert_eq!(p.access_digest, access_digest(&p.manifest));
    assert_eq!(p.access_digest.len(), 64);
    assert!(
        p.access_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}

#[test]
fn bytes_are_bounded_before_parsing() {
    // Over the bound: rejected first, even though the content would be a syntax error and
    // even though it contains an authority key.
    let mut big = b"trust = 1\n".to_vec();
    big.resize(MAX_MANIFEST_BYTES + 1, b'#');
    assert_eq!(invalid(&big), InvalidReason::TooLarge);
    // Exactly at the bound parses (a comment pads it).
    let mut at = MANIFEST.as_bytes().to_vec();
    at.push(b'#');
    at.resize(MAX_MANIFEST_BYTES, b'x');
    ok(std::str::from_utf8(&at).unwrap());
    // Not UTF-8, NUL.
    assert_eq!(
        invalid(b"schema_version = 1\n\xff\xfe"),
        InvalidReason::NotUtf8
    );
    assert_eq!(invalid(b"schema_version = 1\0\n"), InvalidReason::Nul);
    assert_eq!(invalid(b""), InvalidReason::SchemaVersion);
}

#[test]
fn a_nul_escape_in_a_string_is_not_a_raw_nul_but_the_label_still_displays_clean() {
    let text = MANIFEST.replace("example-infrastructure", "a\\u0000b\\u001b[31m");
    let p = ok(&text);
    let shown = p.label_for_display().unwrap();
    assert!(!shown.chars().any(char::is_control), "{shown:?}");
}

#[test]
fn duplicate_keys_and_redefined_tables_are_rejected() {
    for text in [
        "schema_version = 1\nschema_version = 1\n[access]\nprofile = \"p\"\n",
        "schema_version = 1\n[access]\nprofile = \"p\"\nprofile = \"q\"\n",
        "schema_version = 1\n[access]\nprofile = \"p\"\n[access]\npairs = []\n",
        "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata]\na = 1\na = 2\n",
        "schema_version = 1\naccess.profile = \"p\"\n[access]\nprofile = \"q\"\n",
    ] {
        assert_eq!(invalid(text.as_bytes()), InvalidReason::Syntax, "{text}");
    }
}

#[test]
fn depth_rule_root_is_zero_and_each_container_adds_one() {
    // metadata (1) . a (2) . b (3) . c (4): the deepest legal table.
    ok(&format!("{BASE}\n[metadata.a.b.c]\nx = 1\n"));
    // One deeper is invalid.
    assert_eq!(
        invalid(format!("{BASE}\n[metadata.a.b.c.d]\nx = 1\n").as_bytes()),
        InvalidReason::TooDeep
    );
    // Arrays are containers too: metadata (1) . l (2) . [[[1]]] has its innermost array at depth 4.
    ok(&format!("{BASE}\n[metadata]\nl = [[[1]]]\n"));
    assert_eq!(
        invalid(format!("{BASE}\n[metadata]\nl = [[[[1]]]]\n").as_bytes()),
        InvalidReason::TooDeep
    );
}

#[test]
fn authority_outranks_the_depth_bound() {
    let text = format!("{BASE}\n[metadata.a.b.c.d]\ntrust = 1\n");
    assert_eq!(authority(&text), "trust");
}

#[test]
fn nesting_bombs_are_rejected_without_overflowing_the_stack() {
    for open in ["[", "{a=", "[{a=["] {
        let mut text = String::from("schema_version = 1\n[metadata]\nx = ");
        while text.len() < MAX_MANIFEST_BYTES - 8 {
            text.push_str(open);
        }
        assert!(parse_manifest(text.as_bytes()).is_err());
    }
    let mut tables = String::from("schema_version = 1\n[metadata]\nx = ");
    tables.push_str(&"[".repeat(60_000));
    assert!(parse_manifest(tables.as_bytes()).is_err());
}

#[test]
fn too_many_entries_are_rejected_and_the_bound_is_inclusive() {
    let pairs = |n: usize| {
        (0..n)
            .map(|i| format!("\"d{i}:acct\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    let text = |n: usize| {
        format!(
            "schema_version = 1\n[access]\nprofile = \"p\"\npairs = [{}]\n",
            pairs(n)
        )
    };
    assert_eq!(
        ok(&text(MAX_MANIFEST_PAIRS)).pairs.len(),
        MAX_MANIFEST_PAIRS
    );
    assert_eq!(
        invalid(text(MAX_MANIFEST_PAIRS + 1).as_bytes()),
        InvalidReason::TooManyEntries
    );
}

#[test]
fn schema_version_must_be_one() {
    for v in ["0", "2", "\"1\"", "1.0", "true"] {
        let text = MANIFEST.replace("schema_version = 1", &format!("schema_version = {v}"));
        assert_eq!(
            invalid(text.as_bytes()),
            InvalidReason::SchemaVersion,
            "{v}"
        );
    }
    let missing = MANIFEST.replace("schema_version = 1\n", "");
    assert_eq!(invalid(missing.as_bytes()), InvalidReason::SchemaVersion);
}

// --- values -----------------------------------------------------------------------------

fn with_access(line: &str) -> String {
    format!("schema_version = 1\n[access]\n{line}\n")
}

#[test]
fn hostile_values_are_never_accepted() {
    let long = "a".repeat(129);
    let cases: Vec<String> = vec![
        with_access("profile = \"../x\""),
        with_access("profile = \"a/b\""),
        with_access("profile = \"\""),
        with_access("profile = \"$(touch x)\""),
        with_access("profile = \"`id`\""),
        with_access("profile = \"p\\nq\""),
        with_access("profile = \"p q\""),
        with_access("profile = \"https://evil/x\""),
        with_access("profile = \"~/.ssh/id\""),
        with_access("profile = \"ünï\""),
        with_access(&format!("profile = \"{long}\"")),
        with_access("profile = 7"),
        with_access("profile = \"p\"\npairs = [\"$(id):x\"]"),
        with_access("profile = \"p\"\npairs = [\"a:b;rm\"]"),
        with_access("profile = \"p\"\npairs = [\"nodelimiter\"]"),
        with_access("profile = \"p\"\npairs = [\"a:b:c\"]"),
        with_access("profile = \"p\"\npairs = [\":b\"]"),
        with_access("profile = \"p\"\npairs = [\"a:\"]"),
        with_access("profile = \"p\"\npairs = \"a:b\""),
        with_access("profile = \"p\"\nenvironments = [\"a b\"]"),
        with_access("profile = \"p\"\nenvironments = [\"`x`\"]"),
        with_access("profile = \"p\"\nrequired_capabilities = [\"root\"]"),
        with_access("profile = \"p\"\nrequired_capabilities = [\"Ssh-Authentication\"]"),
        with_access("profile = \"p\"\nrequired_capabilities = [\"ssh_authentication\"]"),
        "schema_version = 1\n".to_owned(),
        "schema_version = 1\n[access]\n".to_owned(),
        with_access("profile = \"p\"\nextra = 1"),
        "schema_version = 1\nextra = 1\n[access]\nprofile = \"p\"\n".to_owned(),
        "schema_version = 1\n[access]\nprofile = \"p\"\n[preferences]\nextra = true\n".to_owned(),
    ];
    for text in &cases {
        let r = parse_manifest(text.as_bytes());
        assert!(
            matches!(r, Err(ManifestError::Invalid(_))),
            "should be invalid: {text:?} -> {r:?}"
        );
        assert_eq!(r.unwrap_err().reason(), MANIFEST_INVALID);
    }
    // And the same shell metacharacters in a label are accepted as text but never displayed raw.
    let p = ok("schema_version = 1\nproject = \"x $(id) `y`\\nz\"\n[access]\nprofile = \"p\"\n");
    let shown = p.label_for_display().unwrap();
    assert!(!shown.contains('\n'));
}

#[test]
fn a_manifest_value_cannot_be_a_path_command_url_or_executable() {
    // Every one of these shapes carries a character outside the token set.
    for v in [
        "/etc/passwd",
        "C:\\x",
        "ssh://h",
        "a b",
        "x;y",
        "x&y",
        "x|y",
        "x>y",
        "${H}",
        "*",
    ] {
        let text = with_access(&format!("profile = \"{}\"", v.replace('\\', "\\\\")));
        assert!(parse_manifest(text.as_bytes()).is_err(), "{v}");
    }
}

#[test]
fn label_is_bounded_and_displays_without_control_characters() {
    let long = format!(
        "schema_version = 1\nproject = \"{}\"\n[access]\nprofile = \"p\"\n",
        "x".repeat(129)
    );
    assert_eq!(invalid(long.as_bytes()), InvalidReason::Label);

    let text = "schema_version = 1\nproject = \"a\\u202eb\\u200bc\\u0085d\\u007fe\\r\\nf\\u2028g\\u001b[2Jh\"\n[access]\nprofile = \"p\"\n";
    let shown = ok(text).label_for_display().unwrap();
    assert_eq!(shown, "abcdefg[2Jh");
    for c in shown.chars() {
        assert!(
            !c.is_control()
                && !matches!(c as u32, 0x202a..=0x202e | 0x2066..=0x2069 | 0x200b..=0x200f)
        );
    }

    // Truncation lands on a char boundary.
    let wide = "é".repeat(64); // 128 bytes: at the bound
    let text = format!("schema_version = 1\nproject = \"{wide}\"\n[access]\nprofile = \"p\"\n");
    assert_eq!(ok(&text).label_for_display().unwrap().len(), 128);
    let mut p = ok(MANIFEST);
    p.manifest.project = Some("é".repeat(100));
    let shown = p.label_for_display().unwrap();
    assert!(shown.len() <= 128 && shown.chars().all(|c| c == 'é'));
    p.manifest.project = Some("\u{202e}\n".to_owned());
    assert_eq!(p.label_for_display(), None);
    p.manifest.project = None;
    assert_eq!(p.label_for_display(), None);
}

#[test]
fn errors_never_echo_repository_text() {
    const MARK: &str = "CANARYZZ9";
    for text in [
        format!("schema_version = 1\n[access]\nprofile = \"{MARK}/x\"\n"),
        format!("schema_version = 1\n[access]\nprofile = \"p\"\nunknown_{MARK} = 1\n"),
        format!("schema_version = 1\n[access]\nprofile = \"p\"\npairs = [\"{MARK}\"]\n"),
        format!("schema_version = 1 {MARK}"),
    ] {
        let err = parse_manifest(text.as_bytes()).unwrap_err();
        assert!(!err.to_string().contains(MARK), "{err}");
        assert!(!format!("{err:?}").contains(MARK), "{err:?}");
    }
    // The one allowed echo: an authority key. Every authority name is made of token
    // characters, so what is echoed is a token of at most 64 bytes.
    let key = "Policy-Override";
    let k = authority(&format!("schema_version = 1\n[metadata]\n\"{key}\" = 1\n"));
    assert_eq!(k, key);
    assert!(
        k.len() <= 64
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    );
    // A name that merely contains an authority word is not one (matched whole).
    ok(&format!("{BASE}\n[metadata]\n\"Trust $(id)\\n\" = 1\n"));
}

// --- authority vocabulary ---------------------------------------------------------------

/// Every placement a key can take, as a template with `KEY` for the key.
const PLACEMENTS: &[&str] = &[
    "KEY = 1\nschema_version = 1\n[access]\nprofile = \"p\"\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\nKEY = \"x\"\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[preferences]\nKEY = 1\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata]\nKEY = 1\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata.a]\nKEY = true\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata.a.b.c]\nKEY = []\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[[metadata.list]]\nKEY = 1\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata]\nv = [{ KEY = 1 }]\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[metadata]\nKEY.sub = 1\n",
    "schema_version = 1\n[access]\nprofile = \"p\"\n[KEY]\nx = 1\n",
];

fn vary_case(key: &str, mask: u64) -> String {
    key.chars()
        .enumerate()
        .map(|(i, c)| {
            if mask >> (i % 64) & 1 == 1 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

proptest! {
    #![proptest_config(config(512, 0x5531_4155_5448_0001))]

    /// Every authority key, in any case, with `_` or `-`, bare or quoted, at any placement
    /// (root, `[access]`, `[preferences]`, `[metadata]` at any depth, arrays of tables,
    /// inline tables, dotted keys) is `manifest_authority_key`. `background_work` is the one
    /// name with an allowed path, so it is exercised everywhere except `[preferences]`.
    #[test]
    fn authority_keys_are_rejected_at_any_depth_case_and_quoting(
        idx in 0..MANIFEST_AUTHORITY_KEYS.len(),
        placement in 0..PLACEMENTS.len(),
        mask in any::<u64>(),
        dash in any::<bool>(),
        quoted in any::<bool>(),
    ) {
        let name = MANIFEST_AUTHORITY_KEYS[idx];
        // `preferences.background_work` is the allowed path (a boolean there is fine).
        prop_assume!(!(name == "background_work" && placement == 2));
        let mut key = vary_case(name, mask);
        if dash {
            key = key.replace('_', "-");
        }
        // A key whose text is not a bare TOML key must be quoted; quoting is always legal.
        let key = if quoted || key.contains('.') { format!("\"{key}\"") } else { key };
        let text = PLACEMENTS[placement].replace("KEY", &key);
        match parse_manifest(text.as_bytes()) {
            Err(ManifestError::AuthorityKey(reported)) => {
                prop_assert!(reported.len() <= 64);
                prop_assert_eq!(parse_manifest(text.as_bytes()).unwrap_err().reason(), MANIFEST_AUTHORITY_KEY);
            }
            other => prop_assert!(false, "{} at placement {}: {:?}", key, placement, other),
        }
    }
}

#[test]
fn the_list_covers_the_adr_names_and_the_config_forbidden_keys() {
    for name in [
        "trust",
        "trusted",
        "policy",
        "approve",
        "consent",
        "hook",
        "command",
        "exec",
        "script",
        "key",
        "socket",
        "issuer",
        "enroll",
        "unattended",
        "cutoff",
        "until",
    ] {
        assert!(MANIFEST_AUTHORITY_KEYS.contains(&name), "{name}");
        let text =
            format!("schema_version = 1\n[access]\nprofile = \"p\"\n[metadata]\n\"{name}\" = 1\n");
        assert_eq!(authority(&text), name);
    }
    // Quoted keys are the same names: `"Trust" = 1`.
    assert_eq!(
        authority("schema_version = 1\n\"Trust\" = 1\n[access]\nprofile = \"p\"\n"),
        "Trust"
    );
    // Whole-name matching: names that merely contain one are fine under [metadata].
    ok(&format!(
        "{BASE}\n[metadata.x]\nkeyboard = 1\ntrustworthy = 2\npolicies = 3\n"
    ));
}

#[test]
fn background_work_is_allowed_only_as_a_boolean_at_preferences() {
    // The allowed path.
    assert!(ok(MANIFEST).background_work);
    let off = MANIFEST.replace("background_work = true", "background_work = false");
    assert!(!ok(&off).background_work);
    assert!(!ok(&MANIFEST.replace("[preferences]\nbackground_work = true\n", "")).background_work);
    // A non-boolean at its path is invalid (not an authority key).
    for v in ["\"yes\"", "1", "\"true\"", "[true]", "{ a = 1 }"] {
        let text = MANIFEST.replace("background_work = true", &format!("background_work = {v}"));
        assert_eq!(
            invalid(text.as_bytes()),
            InvalidReason::BackgroundWork,
            "{v}"
        );
    }
    // Anywhere else it is an authority key.
    for text in [
        "background_work = true\nschema_version = 1\n[access]\nprofile = \"p\"\n".to_owned(),
        with_access("profile = \"p\"\nbackground_work = true"),
        format!("{BASE}\n[metadata]\nbackground_work = true\n"),
        format!("{BASE}\n[metadata.deep]\nbackground-work = true\n"),
        format!("{BASE}\n[metadata.p]\n[metadata.p.preferences]\nbackground_work = true\n"),
        "schema_version = 1\n[access]\nprofile = \"p\"\n[[preferences]]\nbackground_work = true\n".to_owned(),
        "schema_version = 1\n[access]\nprofile = \"p\"\n[preferences]\nBackground_Work = true\n".to_owned(),
        "schema_version = 1\n[access]\nprofile = \"p\"\n[preferences]\nbackground-work = true\n".to_owned(),
        "schema_version = 1\n[access]\nprofile = \"p\"\n[preferences.sub]\nbackground_work = true\n".to_owned(),
    ] {
        let k = authority(&text);
        assert!(k.eq_ignore_ascii_case("background_work") || k.eq_ignore_ascii_case("background-work"), "{k}");
    }
}

// =================================================================================
// Totality
// =================================================================================

/// TOML-ish text built from the manifest's own vocabulary, so the interesting paths run.
fn tomlish() -> impl Strategy<Value = String> {
    let frag = prop_oneof![
        Just("schema_version = 1\n".to_owned()),
        Just("[access]\n".to_owned()),
        Just("[preferences]\n".to_owned()),
        Just("[metadata]\n".to_owned()),
        Just("[[metadata.x]]\n".to_owned()),
        Just("profile = \"p\"\n".to_owned()),
        Just("pairs = [\"a:b\", \"c:d\"]\n".to_owned()),
        Just("background_work = true\n".to_owned()),
        Just("project = \"x\"\n".to_owned()),
        Just("trust = true\n".to_owned()),
        Just("a = { b = { c = { d = [[1]] } } }\n".to_owned()),
        "[ -~\n]{0,24}",
        "[\\u{0}-\\u{ff}]{0,8}",
    ];
    prop::collection::vec(frag, 0..14).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(config(2048, 0x5531_544f_5441_0002))]

    /// The parser is total: arbitrary bytes and TOML-shaped text never panic; every refusal
    /// maps to exactly one of the two stable reasons; every acceptance digests consistently.
    #[test]
    fn the_parser_is_total_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..2048),
        text in tomlish(),
    ) {
        for bytes in [raw.as_slice(), text.as_bytes()] {
            match parse_manifest(bytes) {
                Ok(p) => {
                    prop_assert_eq!(&p.access_digest, &access_digest(&p.manifest));
                    prop_assert!(p.pairs.len() <= MAX_MANIFEST_PAIRS);
                    let _ = p.label_for_display();
                }
                Err(e) => {
                    let r = e.reason();
                    prop_assert!(r == MANIFEST_INVALID || r == MANIFEST_AUTHORITY_KEY);
                    let msg = e.to_string();
                    prop_assert!(!msg.chars().any(char::is_control));
                }
            }
        }
    }
}

// =================================================================================
// The access digest
// =================================================================================

#[derive(Debug, Clone)]
struct Spec {
    profile: String,
    pairs: Vec<(String, String)>,
    environments: Vec<String>,
    caps: Vec<&'static str>,
    background: Option<bool>,
    label: Option<String>,
    metadata: Vec<(String, i64)>,
}

fn spec() -> impl Strategy<Value = Spec> {
    (
        "[a-z][a-z0-9._-]{0,15}",
        prop::collection::vec(("[a-z][a-z0-9-]{0,7}", "[a-z][a-z0-9-]{0,7}"), 0..6),
        prop::collection::vec("[a-z]{1,6}", 0..4),
        prop::sample::subsequence(
            vec!["ssh-authentication", "git-signing", "agent-forwarding"],
            0..=3,
        ),
        prop::option::of(any::<bool>()),
        prop::option::of("[a-zA-Z0-9 _.-]{0,20}"),
        prop::collection::vec(("m_[a-z]{1,5}", any::<i64>()), 0..4),
    )
        .prop_map(
            |(profile, pairs, environments, caps, background, label, metadata)| Spec {
                // TOML keys are unique: collapse generated duplicates.
                metadata: metadata
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
                profile,
                pairs,
                environments,
                caps,
                background,
                label,
            },
        )
}

/// A tiny deterministic generator for formatting choices.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % n.max(1)
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.next(i + 1);
            v.swap(i, j);
        }
    }
}

fn quote(rng: &mut Lcg, s: &str) -> String {
    if rng.next(2) == 0 {
        format!("\"{s}\"")
    } else {
        format!("'{s}'")
    }
}

fn list(rng: &mut Lcg, items: &[String]) -> String {
    let mut items: Vec<String> = items.to_vec();
    if !items.is_empty() && rng.next(2) == 0 {
        let dup = items[rng.next(items.len())].clone();
        items.push(dup); // a duplicate
    }
    rng.shuffle(&mut items);
    let sep = [", ", ",", " , ", ",\n  "][rng.next(4)];
    let inner = items
        .iter()
        .map(|s| quote(rng, s))
        .collect::<Vec<_>>()
        .join(sep);
    format!("[{inner}]")
}

/// Render `spec` as TOML, varying key order, whitespace, comments, quoting and list order
/// and duplication with `seed`. `label_and_metadata` false leaves them out.
fn render(spec: &Spec, seed: u64, label_and_metadata: bool) -> String {
    let mut rng = Lcg(seed);
    let ws = |rng: &mut Lcg| ["", " ", "  ", "\t"][rng.next(4)];
    let comment = |rng: &mut Lcg| ["", " # a comment", "  # trust = 1", "\t#"][rng.next(4)];

    let mut root = vec![format!("schema_version = 1{}", comment(&mut rng))];
    if label_and_metadata && let Some(l) = &spec.label {
        root.push(format!("project = \"{l}\""));
    }
    rng.shuffle(&mut root);

    let pairs: Vec<String> = spec.pairs.iter().map(|(d, a)| format!("{d}:{a}")).collect();
    let mut access = vec![format!(
        "profile{}={}\"{}\"",
        ws(&mut rng),
        ws(&mut rng),
        spec.profile
    )];
    if !pairs.is_empty() {
        access.push(format!("pairs = {}", list(&mut rng, &pairs)));
    }
    if !spec.environments.is_empty() {
        access.push(format!(
            "environments = {}",
            list(&mut rng, &spec.environments)
        ));
    }
    if !spec.caps.is_empty() {
        let caps: Vec<String> = spec.caps.iter().map(|c| (*c).to_owned()).collect();
        let key = if rng.next(2) == 0 {
            "required_capabilities"
        } else {
            "\"required_capabilities\""
        };
        access.push(format!("{key} = {}", list(&mut rng, &caps)));
    }
    rng.shuffle(&mut access);

    let mut tables = vec![format!(
        "[access]{}\n{}",
        comment(&mut rng),
        access.join("\n")
    )];
    if let Some(bg) = spec.background {
        tables.push(format!("[preferences]\nbackground_work = {bg}"));
    }
    if label_and_metadata && !spec.metadata.is_empty() {
        let body = spec
            .metadata
            .iter()
            .map(|(k, v)| format!("{k} = {v}"))
            .collect::<Vec<_>>()
            .join("\n");
        tables.push(format!("[metadata]\n{body}"));
    }
    rng.shuffle(&mut tables);
    format!("{}\n\n{}\n", root.join("\n"), tables.join("\n\n"))
}

proptest! {
    #![proptest_config(config(512, 0x5531_4449_4745_0003))]

    /// The digest is invariant under label, `[metadata]`, comments, key order, whitespace and
    /// pair / environment / capability order and duplication.
    #[test]
    fn the_digest_ignores_everything_but_the_policy_fields(
        s in spec(),
        seeds in (any::<u64>(), any::<u64>()),
        other_label in prop::option::of("[a-zA-Z0-9 _.-]{0,20}"),
    ) {
        let base = parse_manifest(render(&s, seeds.0, false).as_bytes()).unwrap();
        let full = parse_manifest(render(&s, seeds.1, true).as_bytes()).unwrap();
        prop_assert_eq!(&base.access_digest, &full.access_digest);
        let mut relabeled = s.clone();
        relabeled.label = other_label;
        relabeled.metadata = vec![("m_other".to_owned(), 7)];
        let r = parse_manifest(render(&relabeled, seeds.1, true).as_bytes()).unwrap();
        prop_assert_eq!(&base.access_digest, &r.access_digest);
        prop_assert_eq!(&base.pairs, &full.pairs);
        prop_assert_eq!(&base.capabilities, &full.capabilities);
        // Absent background_work is false.
        if s.background.is_none() {
            let mut off = s.clone();
            off.background = Some(false);
            let d = parse_manifest(render(&off, seeds.0, false).as_bytes()).unwrap();
            prop_assert_eq!(&base.access_digest, &d.access_digest);
        }
    }

    /// Every policy field changes the digest.
    #[test]
    fn the_digest_is_sensitive_to_each_policy_field(s in spec(), seed in any::<u64>()) {
        let digest = |s: &Spec| parse_manifest(render(s, seed, false).as_bytes()).unwrap().access_digest;
        let base = digest(&s);

        let mut m = s.clone();
        m.profile.push('x');
        prop_assert_ne!(&base, &digest(&m));

        let mut m = s.clone();
        m.pairs.push(("zzzzzzzzz".to_owned(), "zz".to_owned()));
        prop_assert_ne!(&base, &digest(&m));

        let mut m = s.clone();
        m.environments.push("zzzzzzz".to_owned());
        prop_assert_ne!(&base, &digest(&m));

        // Removing the last distinct element changes it too.
        if let Some(last) = s.pairs.last() {
            let mut m = s.clone();
            m.pairs.retain(|p| p != last);
            prop_assert_ne!(&base, &digest(&m));
        }
        if let Some(last) = s.environments.last() {
            let mut m = s.clone();
            m.environments.retain(|e| e != last);
            prop_assert_ne!(&base, &digest(&m));
        }

        for cap in ["ssh-authentication", "git-signing", "agent-forwarding"] {
            let mut m = s.clone();
            if m.caps.contains(&cap) {
                m.caps.retain(|c| *c != cap);
            } else {
                m.caps.push(cap);
            }
            prop_assert_ne!(&base, &digest(&m));
        }

        let mut m = s.clone();
        m.background = Some(!s.background.unwrap_or(false));
        prop_assert_ne!(&base, &digest(&m));
    }
}

#[test]
fn the_digest_separates_fields_and_is_domain_separated() {
    // A pair token cannot be re-split across fields: ["ab:c"] vs profile "a" + ["b:c"]-like shifts.
    let a = ok(&with_access("profile = \"ab\"\npairs = [\"c:d\"]"));
    let b = ok(&with_access("profile = \"a\"\npairs = [\"bc:d\"]"));
    assert_ne!(a.access_digest, b.access_digest);
    let c = ok(&with_access("profile = \"p\"\npairs = [\"a:b\"]"));
    let d = ok(&with_access("profile = \"p\"\nenvironments = [\"a:b\"]"));
    assert_ne!(c.access_digest, d.access_digest);
    // A fixed digest pins the canonical encoding: a change to it must be deliberate.
    let fixed = ok(&with_access(
        "profile = \"homelab-dev\"\npairs = [\"lab-db:deploy\"]",
    ));
    assert_eq!(fixed.access_digest.len(), 64);
    assert_eq!(
        fixed.access_digest,
        ok(&with_access(
            "pairs = [\"lab-db:deploy\", \"lab-db:deploy\"]\nprofile = \"homelab-dev\""
        ))
        .access_digest
    );
}

#[test]
fn metadata_may_hold_any_non_authority_shape_including_datetimes() {
    let p = ok(&format!(
        "{BASE}\n[metadata.when]\nat = 2026-11-18T01:02:03Z\nfloat = nan\nbig = 9223372036854775807\nlist = [1, \"two\", {{ three = 3.5 }}]\n"
    ));
    assert!(p.manifest.metadata.contains_key("when"));
}

// =================================================================================
// Discovery and match_workspace
// =================================================================================

/// A trusted checkout `/work/proj` with a manifest, `.git`, and a subdirectory.
fn base_fs() -> MemFs {
    let mut fs = MemFs::new();
    fs.dir("/work")
        .dir("/work/proj")
        .dir("/work/proj/.git")
        .dir("/work/proj/.git/worktrees")
        .dir("/work/proj/src")
        .file("/work/proj/.heimdall.toml", MANIFEST.as_bytes());
    fs
}

fn observe(fs: &MemFs, cwd: &str) -> WorkspaceObservation {
    observe_workspace(fs, &env(), &cwd_arg(cwd))
        .unwrap_or_else(|e| panic!("observe {cwd}: {e:?}"))
        .unwrap_or_else(|| panic!("observe {cwd}: personal context"))
}

fn record(id: u8, obs: &WorkspaceObservation) -> WorkspaceRecord {
    WorkspaceRecord {
        id: ws(id),
        environment: obs.environment.clone(),
        root: obs.root.clone(),
        root_identity: obs.root_identity.clone().expect("fixture has identities"),
        git_common_identity: match &obs.git {
            Some(GitObservation::Checkout { common_identity }) => common_identity.clone(),
            _ => None,
        },
        decision: DecisionId::from_random_bytes([9; 16]),
        created_at: ts(),
        state: WorkspaceState::Active,
    }
}

#[test]
fn the_manifest_is_read_once_and_the_bytes_hashed_are_the_bytes_parsed() {
    let fs = base_fs();
    let obs = observe(&fs, "/work/proj/src");
    assert_eq!(obs.root, p("/work/proj"));
    assert_eq!(fs.read_count("/work/proj/.heimdall.toml"), 1);
    let parsed = obs.manifest.unwrap().unwrap();
    assert_eq!(parsed.access_digest, ok(MANIFEST).access_digest);
    assert!(matches!(
        obs.git,
        Some(GitObservation::Checkout {
            common_identity: Some(_)
        })
    ));
    assert_eq!(obs.root_identity, Some(fs.id_of("/work/proj")));
}

#[test]
fn a_nonregular_manifest_is_manifest_invalid_and_an_oversized_one_is_a_parse_refusal() {
    for setup in [0, 1, 2] {
        let mut fs = base_fs();
        fs.remove_tree("/work/proj/.heimdall.toml");
        match setup {
            0 => {
                fs.file("/work/real.toml", MANIFEST.as_bytes());
                fs.symlink("/work/proj/.heimdall.toml", "/work/real.toml");
            }
            1 => {
                fs.fifo("/work/proj/.heimdall.toml");
            }
            _ => {
                fs.dir("/work/proj/.heimdall.toml");
            }
        }
        let err = observe_workspace(&fs, &env(), &cwd_arg("/work/proj")).unwrap_err();
        assert_eq!(err, ObserveError::ManifestNotRegular);
        assert_eq!(err.manifest_reason(), Some(MANIFEST_INVALID));
    }
    let mut fs = base_fs();
    fs.file(
        "/work/proj/.heimdall.toml",
        &vec![b'#'; MAX_MANIFEST_BYTES + 1],
    );
    let obs = observe(&fs, "/work/proj");
    assert!(matches!(
        obs.manifest,
        Some(Err(ManifestError::Invalid(InvalidReason::TooLarge)))
    ));
}

#[test]
fn a_symlinked_manifest_is_still_the_root_marker_and_is_never_followed() {
    let mut fs = MemFs::new();
    fs.dir("/w")
        .dir("/w/p")
        .file("/elsewhere", b"x")
        .symlink("/w/p/.heimdall.toml", "/elsewhere");
    assert_eq!(
        observe_workspace(&fs, &env(), &cwd_arg("/w/p")).unwrap_err(),
        ObserveError::ManifestNotRegular
    );
}

#[test]
fn every_row_of_the_adr_0011_table() {
    let mut fs = base_fs();
    let trusted_obs = observe(&fs, "/work/proj");
    let rec = record(1, &trusted_obs);
    let records = [rec.clone()];
    let matches = |fs: &MemFs, cwd: &str| match_workspace(&observe(fs, cwd), &records);

    // Same checkout.
    assert_eq!(
        matches(&fs, "/work/proj"),
        WorkspaceMatch::Trusted { workspace: ws(1) }
    );
    assert_eq!(
        matches(&fs, "/work/proj/src"),
        WorkspaceMatch::Trusted { workspace: ws(1) }
    );

    // Reached through a symlinked path.
    fs.symlink("/link", "/work/proj");
    fs.symlink("/work/srclink", "proj/src");
    assert_eq!(
        matches(&fs, "/link/src"),
        WorkspaceMatch::Trusted { workspace: ws(1) }
    );
    assert_eq!(
        matches(&fs, "/work/srclink"),
        WorkspaceMatch::Trusted { workspace: ws(1) }
    );

    // `cp -R` copy.
    fs.copy_tree("/work/proj", "/work/copy", 1);
    assert_eq!(matches(&fs, "/work/copy"), WorkspaceMatch::Untrusted);

    // `git clone` (a fresh tree with its own manifest).
    fs.dir("/work/clone")
        .dir("/work/clone/.git")
        .file("/work/clone/.heimdall.toml", MANIFEST.as_bytes());
    assert_eq!(matches(&fs, "/work/clone"), WorkspaceMatch::Untrusted);

    // Same path, different identity (re-clone, restore from backup).
    let mut reclone = base_fs();
    reclone.remove_tree("/work/proj");
    reclone
        .dir("/work/proj")
        .dir("/work/proj/.git")
        .file("/work/proj/.heimdall.toml", MANIFEST.as_bytes());
    assert_eq!(
        matches(&reclone, "/work/proj"),
        WorkspaceMatch::Ambiguous {
            workspace: ws(1),
            why: AmbiguityReason::SamePathOtherIdentity
        }
    );

    // `mv` within one filesystem: same identity, other path.
    let mut moved = base_fs();
    moved.rename_tree("/work/proj", "/work/moved");
    assert_eq!(
        matches(&moved, "/work/moved"),
        WorkspaceMatch::Ambiguous {
            workspace: ws(1),
            why: AmbiguityReason::SameIdentityOtherPath
        }
    );

    // A move across filesystems: copied (new identities on another device), old tree gone.
    let mut cross = base_fs();
    cross.dir("/mnt");
    cross.copy_tree("/work/proj", "/mnt/proj", 2);
    cross.remove_tree("/work/proj");
    assert_eq!(matches(&cross, "/mnt/proj"), WorkspaceMatch::Untrusted);

    // Parent directory of a trusted root: discovery never finds the child.
    assert_eq!(
        observe_workspace(&fs, &env(), &cwd_arg("/work")).unwrap(),
        None
    );
    assert_eq!(observe_workspace(&fs, &env(), &cwd_arg("/")).unwrap(), None);

    // A nested manifest inside a trusted tree is its own root, never trusted by the parent.
    fs.dir("/work/proj/pkg")
        .file("/work/proj/pkg/.heimdall.toml", MANIFEST.as_bytes());
    fs.dir("/work/proj/pkg/deep");
    let nested = observe(&fs, "/work/proj/pkg/deep");
    assert_eq!(nested.root, p("/work/proj/pkg"));
    assert_eq!(
        match_workspace(&nested, &records),
        WorkspaceMatch::Untrusted
    );
}

#[test]
fn a_submodule_and_a_nested_repository_are_their_own_workspaces() {
    let mut fs = base_fs();
    let rec = record(1, &observe(&fs, "/work/proj"));
    // A submodule: `.git` is a file pointing into the superproject's modules.
    fs.dir("/work/proj/.git/modules")
        .dir("/work/proj/.git/modules/sub");
    fs.dir("/work/proj/sub")
        .file("/work/proj/sub/.git", b"gitdir: ../.git/modules/sub\n");
    let sub = observe(&fs, "/work/proj/sub");
    assert_eq!(sub.root, p("/work/proj/sub"));
    assert!(matches!(
        sub.git,
        Some(GitObservation::LinkedWorktree {
            verified: false,
            common: None,
            common_identity: None
        })
    ));
    assert_eq!(
        match_workspace(&sub, std::slice::from_ref(&rec)),
        WorkspaceMatch::Untrusted
    );
    // Even with a hostile back-link file inside the modules entry naming the submodule's
    // `.git`, a pointer into `<git>/modules/<n>` is never a verified worktree: the entry's
    // parent must be named `worktrees`.
    fs.file(
        "/work/proj/.git/modules/sub/gitdir",
        b"/work/proj/sub/.git\n",
    );
    let sub = observe(&fs, "/work/proj/sub");
    assert!(matches!(
        sub.git,
        Some(GitObservation::LinkedWorktree {
            verified: false,
            ..
        })
    ));
    assert_eq!(
        match_workspace(&sub, std::slice::from_ref(&rec)),
        WorkspaceMatch::Untrusted
    );
    // A nested repository inside the trusted tree is its own root too.
    fs.dir("/work/proj/nested")
        .dir("/work/proj/nested/.git")
        .dir("/work/proj/nested/x");
    let nested = observe(&fs, "/work/proj/nested/x");
    assert_eq!(nested.root, p("/work/proj/nested"));
    assert_eq!(match_workspace(&nested, &[rec]), WorkspaceMatch::Untrusted);
}

#[test]
fn a_filesystem_without_identities_is_never_matched() {
    let mut fs = base_fs();
    let rec = record(1, &observe(&fs, "/work/proj"));
    fs.no_identities = true;
    let obs = observe(&fs, "/work/proj");
    assert_eq!(obs.root_identity, None);
    // The same canonical path as the record, and still untrusted: no identity, no match
    // (R6: refused, not approximated).
    assert_eq!(obs.root, rec.root);
    assert_eq!(match_workspace(&obs, &[rec]), WorkspaceMatch::Untrusted);
}

#[test]
fn only_active_records_of_the_same_environment_count_and_precedence_holds() {
    let fs = base_fs();
    let obs = observe(&fs, "/work/proj");
    let mut stale = record(1, &obs);
    stale.state = WorkspaceState::Stale;
    let mut elsewhere = record(2, &obs);
    elsewhere.environment = other_env();
    assert_eq!(
        match_workspace(&obs, &[stale.clone(), elsewhere.clone()]),
        WorkspaceMatch::Untrusted
    );

    // Trusted beats Ambiguous beats Untrusted, whatever the order; ties by smallest ID.
    let trusted = record(5, &obs);
    let mut ambiguous = record(3, &obs);
    ambiguous.root_identity = FileIdentity::Unix {
        dev: 9,
        ino: 9,
        birth: None,
    };
    let tie = record(4, &obs);
    for records in [
        vec![ambiguous.clone(), trusted.clone(), tie.clone()],
        vec![tie.clone(), trusted.clone(), ambiguous.clone()],
        vec![trusted.clone(), tie.clone(), ambiguous.clone()],
    ] {
        assert_eq!(
            match_workspace(&obs, &records),
            WorkspaceMatch::Trusted { workspace: ws(4) }
        );
    }
    assert_eq!(
        match_workspace(&obs, &[ambiguous.clone()]),
        WorkspaceMatch::Ambiguous {
            workspace: ws(3),
            why: AmbiguityReason::SamePathOtherIdentity
        }
    );
}

#[test]
fn discovery_rejects_a_bad_working_directory() {
    let fs = base_fs();
    for cwd in ["", "/work/proj\0x"] {
        assert_eq!(
            observe_workspace(&fs, &env(), &cwd_arg(cwd)).unwrap_err(),
            ObserveError::BadCwd
        );
    }
    assert!(matches!(
        observe_workspace(&fs, &env(), &cwd_arg("/work/nope")).unwrap_err(),
        ObserveError::Io(_)
    ));
    assert_eq!(
        observe_workspace(&fs, &env(), &cwd_arg("/work/proj/.heimdall.toml")).unwrap_err(),
        ObserveError::BadCwd
    );
}

// --- linked worktrees: ADR-0011 §2.3 row and ruling §10 item 7 ---------------------------

fn worktree_fs() -> MemFs {
    let mut fs = base_fs();
    fs.dir("/work/proj/.git/worktrees/wt")
        .file("/work/proj/.git/worktrees/wt/gitdir", b"/work/wt/.git\n")
        .dir("/work/wt")
        .file("/work/wt/.git", b"gitdir: /work/proj/.git/worktrees/wt\n");
    fs
}

fn recorded_main(fs: &MemFs) -> WorkspaceRecord {
    record(1, &observe(fs, "/work/proj"))
}

#[test]
fn a_verified_linked_worktree_is_a_member() {
    let fs = worktree_fs();
    let rec = recorded_main(&fs);
    let obs = observe(&fs, "/work/wt");
    assert!(matches!(
        &obs.git,
        Some(GitObservation::LinkedWorktree { verified: true, common: Some(c), common_identity: Some(_) }) if *c == p("/work/proj/.git")
    ));
    assert_eq!(
        match_workspace(&obs, &[rec]),
        WorkspaceMatch::Member { workspace: ws(1) }
    );
}

#[test]
fn remote_git_worktree_pointers_are_not_canonicalized() {
    for (file, prefix, local_calls) in [
        ("/work/wt/.git", "gitdir: ", 1),
        ("/work/proj/.git/worktrees/wt/gitdir", "", 2),
    ] {
        for remote in [
            r"\\server\share\worktree",
            r"\\?\UNC\server\share\worktree",
            r"X:\worktree",
        ] {
            let mut fs = worktree_fs();
            fs.file(file, format!("{prefix}{remote}\n").as_bytes());
            fs.refused_path = Some(PathBuf::from(remote));
            assert!(matches!(
                observe(&fs, "/work/wt").git,
                Some(GitObservation::LinkedWorktree {
                    verified: false,
                    ..
                })
            ));
            assert_eq!(
                fs.canonicalizations.borrow().len(),
                local_calls,
                "passive observation canonicalized a remote pointer"
            );
        }
    }
}

/// ⟨W1 Windows fix⟩ Windows path forms (ADR-0011 §2.3 on Windows): a working directory
/// given drive-qualified, verbatim, with forward slashes or with a lower-case drive letter
/// observes one canonical root, the verbatim form `std::fs::canonicalize` returns, and
/// matches the same record; a linked worktree whose pointer files Git for Windows wrote
/// (`C:/...`) verifies; a UNC share is its own canonical namespace. The comparisons stay
/// exact string and identity equality on canonical forms, never on what a caller typed.
#[cfg(windows)]
#[test]
fn windows_drive_verbatim_forward_slash_and_unc_forms_observe_one_canonical_root() {
    let mut fs = worktree_fs();
    let rec = recorded_main(&fs);
    assert_eq!(rec.root, r"\\?\C:\work\proj");
    for cwd in [
        r"C:\work\proj\src",
        r"\\?\C:\work\proj\src",
        "C:/work/proj/src",
        r"c:\work\proj\src",
    ] {
        let obs = observe_workspace(&fs, &env(), cwd)
            .unwrap()
            .expect("a workspace root");
        assert_eq!(obs.root, r"\\?\C:\work\proj", "{cwd}");
        assert_eq!(
            match_workspace(&obs, std::slice::from_ref(&rec)),
            WorkspaceMatch::Trusted { workspace: ws(1) },
            "{cwd}"
        );
    }
    let wt = observe_workspace(&fs, &env(), r"C:\work\wt")
        .unwrap()
        .expect("the worktree root");
    assert!(matches!(
        &wt.git,
        Some(GitObservation::LinkedWorktree { verified: true, common: Some(c), .. })
            if c == r"\\?\C:\work\proj\.git"
    ));
    assert_eq!(
        match_workspace(&wt, std::slice::from_ref(&rec)),
        WorkspaceMatch::Member { workspace: ws(1) }
    );

    // The share is added to the same filesystem, so its entries get identities of their
    // own, as a second volume's do. (A separate `MemFs` would hand out the same identity
    // numbers again, which would make this a same-identity move and answer `Ambiguous`.)
    fs.dir(r"\\?\UNC\server\share\")
        .dir(r"\\?\UNC\server\share\proj")
        .dir(r"\\?\UNC\server\share\proj\.git")
        .dir(r"\\?\UNC\server\share\proj\src");
    let obs = observe_workspace(&fs, &env(), r"\\server\share\proj\src")
        .unwrap()
        .expect("a workspace root on the share");
    assert_eq!(obs.root, r"\\?\UNC\server\share\proj");
    // A record made on the drive never matches the share, however the paths look alike.
    assert_eq!(
        match_workspace(&obs, std::slice::from_ref(&rec)),
        WorkspaceMatch::Untrusted
    );
}
#[test]
fn a_copied_worktree_whose_gitdir_still_names_the_original_is_untrusted() {
    let mut fs = worktree_fs();
    let rec = recorded_main(&fs);
    fs.copy_tree("/work/wt", "/work/wt-copy", 1);
    // The copy's `.git` text names the original common, and the entry's back-link still
    // names the original worktree: not this root.
    for original_present in [true, false] {
        if !original_present {
            fs.remove_tree("/work/wt");
        }
        let obs = observe(&fs, "/work/wt-copy");
        assert!(matches!(
            &obs.git,
            Some(GitObservation::LinkedWorktree {
                verified: false,
                ..
            })
        ));
        assert_eq!(
            match_workspace(&obs, std::slice::from_ref(&rec)),
            WorkspaceMatch::Untrusted
        );
    }
}

#[test]
fn a_moved_worktree_is_not_verified_until_git_repairs_the_back_link() {
    let mut fs = worktree_fs();
    let rec = recorded_main(&fs);
    fs.rename_tree("/work/wt", "/work/wt-moved");
    let obs = observe(&fs, "/work/wt-moved");
    assert_eq!(
        match_workspace(&obs, std::slice::from_ref(&rec)),
        WorkspaceMatch::Untrusted
    );
    // After `git worktree repair` the back-link names the new location.
    fs.file(
        "/work/proj/.git/worktrees/wt/gitdir",
        b"/work/wt-moved/.git\n",
    );
    // (a rewritten file has a new identity entry of its own, irrelevant to the check)
    let obs = observe(&fs, "/work/wt-moved");
    assert_eq!(
        match_workspace(&obs, &[rec]),
        WorkspaceMatch::Member { workspace: ws(1) }
    );
}

#[test]
fn the_back_link_must_match_by_identity_as_well_as_by_path() {
    // Same canonical path, different file: the worktree's `.git` replaced after the link was
    // written (a fresh file at the same path has a new identity... here simulated with a
    // filesystem that reports no identity for the worktree entries).
    let mut fs = worktree_fs();
    let rec = recorded_main(&fs);
    fs.no_identities = true;
    let obs = observe(&fs, "/work/wt");
    assert!(matches!(
        &obs.git,
        Some(GitObservation::LinkedWorktree {
            verified: false,
            ..
        })
    ));
    assert_eq!(match_workspace(&obs, &[rec]), WorkspaceMatch::Untrusted);
}

/// ⟨M05; review M05-W4-R01⟩ A key repeated in one object, at any depth and however it is
/// escaped, refuses the raw input: a value tree keeps only the last occurrence, so the
/// overwritten one (here an authority section) would never reach the walk.
#[test]
fn a_duplicate_key_refuses_the_raw_bundle() {
    let head = r#"{"schema":"heimdall-portable/1","created_at":"2026-11-18T09:00:00Z","redacted":false,"destinations":[],"identities":[],"#;
    for body in [
        // The reviewer's input: an authority-bearing `profiles` shadowed by an empty one.
        r#""profiles":[{"policy":{"approve":true}}],"profiles":[],"reestablish":[]}"#,
        // The same, with the second key escaped.
        r#""profiles":[{"policy":{"approve":true}}],"\u0070rofiles":[],"reestablish":[]}"#,
        // Nested: a repeated key inside an item.
        r#""profiles":[{"id":"p","id":"q","pairs":[]}],"reestablish":[]}"#,
    ] {
        let raw = format!("{head}{body}");
        assert_eq!(
            parse_bundle(raw.as_bytes()),
            Err(BundleError::DuplicateKey),
            "{raw}"
        );
    }
    // Without the shadow, the authority section is refused as before.
    let plain = format!(r#"{head}"profiles":[{{"policy":{{"approve":true}}}}],"reestablish":[]}}"#);
    assert!(matches!(
        parse_bundle(plain.as_bytes()),
        Err(BundleError::AuthoritySection(_))
    ));
}

#[test]
fn malformed_pointers_are_unverified_never_errors() {
    for git_file in [
        &b""[..],
        b"gitdir:",
        b"gitdir:/work/proj/.git/worktrees/wt\n",
        b"GITDIR: /work/proj/.git/worktrees/wt\n",
        b"gitdir: /work/proj/.git/worktrees/wt\ngitdir: /work/proj/.git/worktrees/wt\n",
        b"gitdir: /work/proj/.git/worktrees/wt\0\n",
        b"gitdir: /work/proj/.git/worktrees/nope\n",
        b"gitdir: /work/proj/.git\n",
        b"gitdir: /work/proj/.git/worktrees\n",
        b"\xff\xfe gitdir: /x",
    ] {
        let mut fs = worktree_fs();
        let rec = recorded_main(&fs);
        fs.file("/work/wt/.git", git_file);
        let obs = observe(&fs, "/work/wt");
        assert!(
            matches!(
                &obs.git,
                Some(GitObservation::LinkedWorktree {
                    verified: false,
                    ..
                })
            ),
            "{git_file:?}"
        );
        assert_eq!(match_workspace(&obs, &[rec]), WorkspaceMatch::Untrusted);
    }
    // An oversized pointer file is not read past its bound.
    let mut fs = worktree_fs();
    fs.file("/work/wt/.git", &vec![b'a'; 100_000]);
    assert!(matches!(
        observe(&fs, "/work/wt").git,
        Some(GitObservation::LinkedWorktree {
            verified: false,
            ..
        })
    ));
}

// --- P11 ----------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Pointer {
    Abs,
    Relative,
    DotDotNoop,
    /// Names the trusted common as text but `..` leaves it for the other repository.
    DotDotEscape,
    Garbage,
    Empty,
}

#[derive(Debug, Clone, Copy)]
enum Backlink {
    Correct,
    Relative,
    Stale,
    Absent,
    OtherPath,
}

/// The worktree world: two repositories (`/work/proj`, `/work/other`), each with a recorded
/// workspace, and one worktree directory whose pointer and back-link vary.
fn p11_world(
    pointer: Pointer,
    backlink: Backlink,
    copied: bool,
) -> (MemFs, String, Vec<WorkspaceRecord>) {
    let mut fs = MemFs::new();
    fs.dir("/work")
        .dir("/work/proj")
        .dir("/work/proj/.git")
        .dir("/work/proj/.git/worktrees")
        .dir("/work/proj/.git/worktrees/wt")
        .dir("/work/other")
        .dir("/work/other/.git")
        .dir("/work/other/.git/worktrees")
        .dir("/work/other/.git/worktrees/wt2")
        .dir("/work/wt");
    let link: Option<&[u8]> = match backlink {
        Backlink::Correct => Some(b"/work/wt/.git\n"),
        Backlink::Relative => Some(b"../../../../wt/.git\n"),
        Backlink::Stale => Some(b"/work/gone/.git\n"),
        Backlink::Absent => None,
        Backlink::OtherPath => Some(b"/work/other/.git\n"),
    };
    for entry in [
        "/work/proj/.git/worktrees/wt",
        "/work/other/.git/worktrees/wt2",
    ] {
        if let Some(l) = link {
            fs.file(&format!("{entry}/gitdir"), l);
        }
    }
    let text: &[u8] = match pointer {
        Pointer::Abs => b"gitdir: /work/proj/.git/worktrees/wt\n",
        Pointer::Relative => b"gitdir: ../proj/.git/worktrees/wt\n",
        Pointer::DotDotNoop => b"gitdir: /work/proj/.git/worktrees/../worktrees/wt\n",
        Pointer::DotDotEscape => {
            b"gitdir: /work/proj/.git/worktrees/../../../other/.git/worktrees/wt2\n"
        }
        Pointer::Garbage => b"gitdir: \x01\x02 ../../../\n",
        Pointer::Empty => b"",
    };
    fs.file("/work/wt/.git", text);
    let proj = record(1, &observe(&fs, "/work/proj"));
    let other = record(2, &observe(&fs, "/work/other"));
    let cwd = if copied {
        fs.copy_tree("/work/wt", "/work/copy", 1);
        "/work/copy"
    } else {
        "/work/wt"
    };
    (fs, cwd.to_owned(), vec![proj, other])
}

/// The independent oracle: which repository (if any) truly has this worktree linked.
fn p11_truth(pointer: Pointer, backlink: Backlink, copied: bool) -> WorkspaceMatch {
    let target = match pointer {
        Pointer::Abs | Pointer::Relative | Pointer::DotDotNoop => Some(1),
        Pointer::DotDotEscape => Some(2),
        Pointer::Garbage | Pointer::Empty => None,
    };
    let back_ok = matches!(backlink, Backlink::Correct | Backlink::Relative);
    match target {
        Some(n) if back_ok && !copied => WorkspaceMatch::Member { workspace: ws(n) },
        _ => WorkspaceMatch::Untrusted,
    }
}

fn pointer_strategy() -> impl Strategy<Value = Pointer> {
    prop_oneof![
        Just(Pointer::Abs),
        Just(Pointer::Relative),
        Just(Pointer::DotDotNoop),
        Just(Pointer::DotDotEscape),
        Just(Pointer::Garbage),
        Just(Pointer::Empty),
    ]
}

fn backlink_strategy() -> impl Strategy<Value = Backlink> {
    prop_oneof![
        Just(Backlink::Correct),
        Just(Backlink::Relative),
        Just(Backlink::Stale),
        Just(Backlink::Absent),
        Just(Backlink::OtherPath),
    ]
}

proptest! {
    #![proptest_config(config(256, 0x5531_5031_3100_0004))]

    /// P11, with ruling §10 item 7's `gitdir` cases (a relative path, a `..` segment, a copied
    /// worktree whose text still names the original common): a worktree is a `Member` of
    /// exactly the repository whose entry it resolves to **and** that links back to it, and of
    /// nothing else. A `gitdir` line whose text starts with the trusted common but resolves
    /// elsewhere (`DotDotEscape`) is never a member of the trusted one.
    #[test]
    fn a_worktree_is_a_member_only_through_a_verified_back_link(
        pointer in pointer_strategy(),
        backlink in backlink_strategy(),
        copied in any::<bool>(),
    ) {
        let (fs, cwd, records) = p11_world(pointer, backlink, copied);
        let obs = observe(&fs, &cwd);
        let got = match_workspace(&obs, &records);
        prop_assert_eq!(&got, &p11_truth(pointer, backlink, copied), "{:?} {:?} {}", pointer, backlink, copied);
        if let WorkspaceMatch::Member { workspace } = &got {
            // Never the repository whose common directory the text merely names.
            if matches!(pointer, Pointer::DotDotEscape) {
                prop_assert_ne!(workspace, &ws(1));
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Case {
    obs_root: u8,
    obs_identity: Option<u8>,
    obs_common: Option<(bool, Option<u8>)>,
    obs_env_other: bool,
    records: Vec<(u8, u8, u8, Option<u8>, bool, bool)>,
}

fn case() -> impl Strategy<Value = Case> {
    (
        0u8..3,
        prop::option::of(0u8..3),
        prop::option::of((any::<bool>(), prop::option::of(0u8..3))),
        any::<bool>(),
        prop::collection::vec(
            (
                1u8..6,
                0u8..3,
                0u8..3,
                prop::option::of(0u8..3),
                any::<bool>(),
                any::<bool>(),
            ),
            0..5,
        ),
    )
        .prop_map(
            |(obs_root, obs_identity, obs_common, obs_env_other, records)| Case {
                obs_root,
                obs_identity,
                obs_common,
                obs_env_other,
                records,
            },
        )
}

fn ident(n: u8) -> FileIdentity {
    FileIdentity::Unix {
        dev: 1,
        ino: u64::from(n) + 100,
        birth: None,
    }
}

proptest! {
    #![proptest_config(config(1024, 0x5531_5031_3100_0005))]

    /// P11 over arbitrary observations and records: a `Trusted` result requires equal
    /// canonical path and equal known identity; a `Member` requires a verified back-link
    /// whose common identity equals the record's; an `Ambiguous` needs a known identity;
    /// stale and other-environment records never match; and the answer does not depend on
    /// the order of the records.
    #[test]
    fn matching_requires_path_and_identity_or_a_verified_back_link(c in case()) {
        let obs = WorkspaceObservation {
            environment: if c.obs_env_other { other_env() } else { env() },
            root: format!("/r/{}", c.obs_root),
            root_identity: c.obs_identity.map(ident),
            git: c.obs_common.map(|(verified, id)| GitObservation::LinkedWorktree {
                common: verified.then(|| "/r/common".to_owned()),
                common_identity: id.map(ident),
                verified,
            }),
            manifest: None,
        };
        // Record IDs are unique in the store.
        let mut seen = std::collections::BTreeSet::new();
        let records: Vec<WorkspaceRecord> = c.records.iter().filter(|r| seen.insert(r.0)).map(|&(id, root, identity, common, stale, other_env_)| WorkspaceRecord {
            id: ws(id),
            environment: if other_env_ { other_env() } else { env() },
            root: format!("/r/{root}"),
            root_identity: ident(identity),
            git_common_identity: common.map(ident),
            decision: DecisionId::from_random_bytes([9; 16]),
            created_at: ts(),
            state: if stale { WorkspaceState::Stale } else { WorkspaceState::Active },
        }).collect();

        let got = match_workspace(&obs, &records);
        let find = |id: &WorkspaceId| records.iter().filter(|r| &r.id == id && r.state == WorkspaceState::Active && r.environment == obs.environment).collect::<Vec<_>>();
        match &got {
            WorkspaceMatch::Trusted { workspace } => {
                prop_assert!(find(workspace).iter().any(|r| r.root == obs.root && obs.root_identity.as_ref() == Some(&r.root_identity)));
            }
            WorkspaceMatch::Member { workspace } => {
                let Some(GitObservation::LinkedWorktree { verified: true, common_identity: Some(ci), .. }) = &obs.git else {
                    return Err(TestCaseError::fail("member without a verified back-link"));
                };
                prop_assert!(find(workspace).iter().any(|r| r.git_common_identity.as_ref() == Some(ci)));
            }
            WorkspaceMatch::Ambiguous { workspace, why } => {
                prop_assert!(obs.root_identity.is_some());
                let witnessed = find(workspace).iter().any(|r| match why {
                    AmbiguityReason::SamePathOtherIdentity => r.root == obs.root && obs.root_identity.as_ref() != Some(&r.root_identity),
                    AmbiguityReason::SameIdentityOtherPath => r.root != obs.root && obs.root_identity.as_ref() == Some(&r.root_identity),
                    _ => false,
                });
                prop_assert!(witnessed);
            }
            _ => {}
        }
        if obs.root_identity.is_none() {
            let strong = matches!(got, WorkspaceMatch::Trusted { .. } | WorkspaceMatch::Ambiguous { .. });
            prop_assert!(!strong);
        }
        let mut reversed = records.clone();
        reversed.reverse();
        prop_assert_eq!(&got, &match_workspace(&obs, &reversed));
    }
}

// =================================================================================
// The portable bundle
// =================================================================================

fn fingerprint(n: usize) -> String {
    // 43 base64 characters from a fixed alphabet, distinct per n.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body: String = (0..43)
        .map(|i| char::from(alphabet[(n * 7 + i * 3) % 64]))
        .collect();
    format!("SHA256:{body}")
}

fn bundle_input() -> impl Strategy<Value = BundleInput> {
    let dest = (
        "[a-z][a-z0-9-]{0,9}",
        "[a-z][a-z0-9._-]{0,9}",
        prop::option::of("[a-z][a-z0-9.-]{0,14}"),
        prop::option::of(any::<u16>()),
        prop::option::of("[a-z][a-z0-9_-]{0,7}"),
        prop::collection::vec(0usize..6, 0..3),
    )
        .prop_map(
            |(id, alias, hostname, port, account, fps)| PortableDestination {
                id: DestinationId::parse(&id).unwrap(),
                alias,
                hostname,
                port,
                account: account.map(|a| AccountName::parse(&a).unwrap()),
                host_key_fingerprints: fps.into_iter().map(fingerprint).collect(),
                jump: None,
            },
        );
    let identity = (
        0usize..8,
        prop::sample::select(vec!["native_agent", "onepassword", "unknown"]),
    )
        .prop_map(|(n, p)| PortableIdentity {
            fingerprint: fingerprint(n + 10),
            provider: p.to_owned(),
        });
    let profile = (
        "[a-z][a-z0-9-]{0,9}",
        prop::collection::vec(("[a-z][a-z0-9-]{0,7}", "[a-z][a-z0-9-]{0,7}"), 0..4),
    )
        .prop_map(|(id, pairs)| PortableProfile {
            id: ProfileId::parse(&id).unwrap(),
            pairs: pairs.into_iter().map(|(d, a)| format!("{d}:{a}")).collect(),
        });
    (
        prop::collection::vec(dest, 0..5),
        prop::collection::vec(identity, 0..4),
        prop::collection::vec(profile, 0..4),
    )
        .prop_map(|(destinations, identities, profiles)| BundleInput {
            destinations,
            identities,
            profiles,
        })
}

/// Walk to an object inside `value` chosen by `pick`, and insert `key`.
fn inject(value: &mut serde_json::Value, pick: &mut usize, key: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            if *pick == 0 {
                map.insert(key.to_owned(), serde_json::json!({"x": 1}));
                return true;
            }
            *pick -= 1;
            map.values_mut().any(|v| inject(v, pick, key))
        }
        serde_json::Value::Array(items) => items.iter_mut().any(|v| inject(v, pick, key)),
        _ => false,
    }
}

const BUNDLE_AUTHORITY: &[&str] = &[
    "policies",
    "policy",
    "workspaces",
    "workspace",
    "grants",
    "grant",
    "decisions",
    "decision",
    "enrollments",
    "enrollment",
    "trust",
    "trusted",
    "permissions",
    "automatic_activation",
    "socket",
    "home",
    "private_key",
    "Automatic-Activation",
    "POLICIES",
    "command",
    "unattended",
];

proptest! {
    #![proptest_config(config(256, 0x5531_4255_4e44_0006))]

    /// emit → serialize → parse is the identity, redaction removes host names, addresses,
    /// ports and aliases, and the bundle always carries the fixed re-establish list.
    #[test]
    fn a_bundle_round_trips(input in bundle_input(), redact in any::<bool>()) {
        let bundle = emit_bundle(&input, redact, ts());
        prop_assert_eq!(&bundle.schema, PORTABLE_BUNDLE_SCHEMA);
        prop_assert_eq!(bundle.redacted, redact);
        prop_assert!(!bundle.reestablish.is_empty());
        if redact {
            for d in &bundle.destinations {
                prop_assert!(d.hostname.is_none() && d.port.is_none());
                prop_assert_eq!(d.alias.as_str(), d.id.as_str());
            }
        }
        let bytes = serde_json::to_vec(&bundle).unwrap();
        prop_assert_eq!(&parse_bundle(&bytes).unwrap(), &bundle);
        // Emission is deterministic and order-insensitive.
        let mut reversed = input.clone();
        reversed.destinations.reverse();
        reversed.profiles.reverse();
        reversed.identities.reverse();
        let again = emit_bundle(&reversed, redact, ts());
        prop_assert_eq!(again.profiles.len(), bundle.profiles.len());
        prop_assert_eq!(again.identities.len(), bundle.identities.len());
        prop_assert_eq!(again.destinations.len(), bundle.destinations.len());
    }

    /// Authority sections and keys are refused at any depth, in any case, and an unknown
    /// top-level key is refused too.
    #[test]
    fn authority_sections_are_refused_at_any_depth(
        input in bundle_input(),
        key in prop::sample::select(BUNDLE_AUTHORITY.to_vec()),
        mut pick in 0usize..12,
    ) {
        let bundle = emit_bundle(&input, false, ts());
        let mut value = serde_json::to_value(&bundle).unwrap();
        if !inject(&mut value, &mut pick, key) {
            // No object at that index: the top level always works.
            inject(&mut value, &mut 0, key);
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        match parse_bundle(&bytes) {
            Err(BundleError::AuthoritySection(k)) => prop_assert!(k.len() <= 64),
            other => prop_assert!(false, "{} -> {:?}", key, other),
        }
    }

    /// The bundle parser is total on arbitrary bytes.
    #[test]
    fn the_bundle_parser_is_total(raw in prop::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_bundle(&raw);
    }
}

#[test]
fn bundle_fixed_cases() {
    let input = BundleInput {
        destinations: vec![PortableDestination {
            id: DestinationId::parse("lab-db").unwrap(),
            alias: "lab-db".into(),
            hostname: Some("db.lab.example".into()),
            port: Some(2222),
            account: Some(AccountName::parse("deploy").unwrap()),
            host_key_fingerprints: vec![fingerprint(1)],
            jump: None,
        }],
        identities: vec![PortableIdentity {
            fingerprint: fingerprint(2),
            provider: "native_agent".into(),
        }],
        profiles: vec![PortableProfile {
            id: ProfileId::parse("homelab-dev").unwrap(),
            pairs: vec!["lab-db:deploy".into()],
        }],
    };
    let good = serde_json::to_value(emit_bundle(&input, false, ts())).unwrap();
    parse_bundle(&serde_json::to_vec(&good).unwrap()).unwrap();

    let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good.clone();
        f(&mut v);
        parse_bundle(&serde_json::to_vec(&v).unwrap())
    };
    // Bad schema, unknown top-level key, unknown nested key, malformed values.
    assert_eq!(
        mutate(&|v| v["schema"] = "heimdall-portable/2".into()),
        Err(BundleError::Schema)
    );
    assert!(
        matches!(mutate(&|v| v["extra"] = 1.into()), Err(BundleError::AuthoritySection(k)) if k == "extra")
    );
    assert_eq!(
        mutate(&|v| v["destinations"][0]["extra"] = 1.into()),
        Err(BundleError::Invalid)
    );
    for bad in ["has space", "-leading", "a;b", "", "x$(y)"] {
        assert_eq!(
            mutate(&|v| v["destinations"][0]["alias"] = bad.into()),
            Err(BundleError::Invalid),
            "{bad}"
        );
    }
    assert_eq!(
        mutate(&|v| v["destinations"][0]["hostname"] = "a b".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["destinations"][0]["id"] = "../x".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["destinations"][0]["host_key_fingerprints"][0] = "SHA256:short".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["identities"][0]["fingerprint"] = "MD5:aa".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["identities"][0]["provider"] = "evil".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["profiles"][0]["pairs"][0] = "a:b:c".into()),
        Err(BundleError::Invalid)
    );
    assert_eq!(
        mutate(&|v| v["destinations"][0]["port"] = 70000.into()),
        Err(BundleError::Invalid)
    );
    // Bounds and syntax.
    assert_eq!(
        parse_bundle(&vec![b' '; (1 << 20) + 1]),
        Err(BundleError::TooLarge)
    );
    assert_eq!(parse_bundle(b"[]"), Err(BundleError::Invalid));
    assert_eq!(parse_bundle(b"not json"), Err(BundleError::Syntax));
    assert_eq!(parse_bundle(b"\xff"), Err(BundleError::Syntax));
    let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    assert!(parse_bundle(deep.as_bytes()).is_err());
    // The real sections of M05 state never fit: a bundle that smuggles a policy is refused
    // as authority even when valid in every other way.
    let mut with_policy = good.clone();
    with_policy["profiles"][0]["policy"] = serde_json::json!({"standing": true});
    assert!(matches!(
        parse_bundle(&serde_json::to_vec(&with_policy).unwrap()),
        Err(BundleError::AuthoritySection(k)) if k == "policy"
    ));
}
