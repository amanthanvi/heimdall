//! The behaviour that matters for access, reduced from an [`Evaluation`] (m02-plan
//! U2; ADR-0007 §3, §5.2).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::provider::{
    Certainty, IdentitiesOnly, IdentityBacking, IdentityEntry, IdentityEntryKind,
    IdentityEntrySource, IdentitySelection, IdentitySelectionReport,
};
use heimdall_domain::projection::{BehaviorDigest, BehaviorState};

use crate::directive::KnownKeyword;
use crate::eval::{Candidate, Evaluation, Resolved, Unresolved, UnresolvedReason, Value};
use crate::include::{ConfigSource, SourceError};
use crate::parse::Span;

/// Which proxy competes and wins (F10: `ProxyJump` and `ProxyCommand` compete; the
/// first obtained of the two wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    /// Neither applies (or `none`).
    None,
    /// `ProxyJump`.
    Jump(Value),
    /// `ProxyCommand` (never run here).
    Command(Value),
}

/// The proxy outcome of an evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyResolution {
    /// Known.
    Determined(Proxy),
    /// One of these, depending on something not evaluated.
    Undetermined(Vec<Proxy>),
}

/// The directives that decide how a host is reached and authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelevantBehavior {
    /// `HostName`.
    pub hostname: Resolved,
    /// `Port`.
    pub port: Resolved,
    /// `User`.
    pub user: Resolved,
    /// `IdentityAgent`.
    pub identity_agent: Resolved,
    /// `IdentityFile`, in order.
    pub identity_files: Vec<Candidate>,
    /// `IdentitiesOnly`.
    pub identities_only: Resolved,
    /// `CertificateFile`, in order.
    pub certificate_files: Vec<Candidate>,
    /// `ProxyJump`/`ProxyCommand` under F10.
    pub proxy: ProxyResolution,
    /// `ControlMaster`.
    pub control_master: Resolved,
    /// `ControlPath`.
    pub control_path: Resolved,
    /// `ControlPersist`.
    pub control_persist: Resolved,
    /// `ForwardAgent`.
    pub forward_agent: Resolved,
    /// `StrictHostKeyChecking`.
    pub strict_host_key_checking: Resolved,
    /// `UserKnownHostsFile`.
    pub user_known_hosts_file: Resolved,
    /// `GlobalKnownHostsFile`.
    pub global_known_hosts_file: Resolved,
    /// `HostKeyAlias`.
    pub host_key_alias: Resolved,
    /// `CanonicalizeHostname`.
    pub canonicalize_hostname: Resolved,
    /// `PermitLocalCommand`.
    pub permit_local_command: Resolved,
    /// `LocalCommand`.
    pub local_command: Resolved,
    /// `KnownHostsCommand`.
    pub known_hosts_command: Resolved,
    /// `AddKeysToAgent`.
    pub add_keys_to_agent: Resolved,
    /// `PKCS11Provider`.
    pub pkcs11_provider: Resolved,
    /// `SecurityKeyProvider`.
    pub security_key_provider: Resolved,
}

/// One relevant directive whose resolved state differs between two behaviours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorChange {
    /// The directive.
    pub directive: KnownKeyword,
    /// Before.
    pub before: Resolved,
    /// After.
    pub after: Resolved,
}

/// Reduce an evaluation to its relevant behaviour. A directive the evaluation does not
/// mention is `Unset`; the proxy follows F10 (see [`ProxyResolution`]).
#[must_use]
pub fn relevant(evaluation: &Evaluation) -> RelevantBehavior {
    let get = |k: KnownKeyword| {
        evaluation
            .values
            .get(&k)
            .cloned()
            .unwrap_or(Resolved::Unset)
    };
    let list = |k: KnownKeyword| evaluation.accumulated.get(&k).cloned().unwrap_or_default();
    RelevantBehavior {
        hostname: get(KnownKeyword::Hostname),
        port: get(KnownKeyword::Port),
        user: get(KnownKeyword::User),
        identity_agent: get(KnownKeyword::IdentityAgent),
        identity_files: list(KnownKeyword::IdentityFile),
        identities_only: get(KnownKeyword::IdentitiesOnly),
        certificate_files: list(KnownKeyword::CertificateFile),
        proxy: proxy_of(
            &get(KnownKeyword::ProxyJump),
            &get(KnownKeyword::ProxyCommand),
        ),
        control_master: get(KnownKeyword::ControlMaster),
        control_path: get(KnownKeyword::ControlPath),
        control_persist: get(KnownKeyword::ControlPersist),
        forward_agent: get(KnownKeyword::ForwardAgent),
        strict_host_key_checking: get(KnownKeyword::StrictHostKeyChecking),
        user_known_hosts_file: get(KnownKeyword::UserKnownHostsFile),
        global_known_hosts_file: get(KnownKeyword::GlobalKnownHostsFile),
        host_key_alias: get(KnownKeyword::HostKeyAlias),
        canonicalize_hostname: get(KnownKeyword::CanonicalizeHostname),
        permit_local_command: get(KnownKeyword::PermitLocalCommand),
        local_command: get(KnownKeyword::LocalCommand),
        known_hosts_command: get(KnownKeyword::KnownHostsCommand),
        add_keys_to_agent: get(KnownKeyword::AddKeysToAgent),
        pkcs11_provider: get(KnownKeyword::Pkcs11Provider),
        security_key_provider: get(KnownKeyword::SecurityKeyProvider),
    }
}

/// `none` (case-insensitive) as the only argument.
fn is_none_value(v: &Value) -> bool {
    v.args.len() == 1 && v.args[0].eq_ignore_ascii_case("none")
}

fn proxy_value(jump: bool, v: &Value) -> Proxy {
    if is_none_value(v) {
        Proxy::None
    } else if jump {
        Proxy::Jump(v.clone())
    } else {
        Proxy::Command(v.clone())
    }
}

/// F10: the evaluator keeps one slot for both, so at most one of them is
/// `Determined`. Anything else is undetermined, and "neither" stays a possibility.
fn proxy_of(jump: &Resolved, command: &Resolved) -> ProxyResolution {
    match (jump, command) {
        (Resolved::Unset, Resolved::Unset) => ProxyResolution::Determined(Proxy::None),
        (Resolved::Determined(v), Resolved::Unset) => {
            ProxyResolution::Determined(proxy_value(true, v))
        }
        (Resolved::Unset, Resolved::Determined(v)) => {
            ProxyResolution::Determined(proxy_value(false, v))
        }
        _ => {
            let mut out = Vec::new();
            let mut push = |p: Proxy| {
                if !out.contains(&p) {
                    out.push(p);
                }
            };
            for (is_jump, r) in [(true, jump), (false, command)] {
                match r {
                    Resolved::Unset => {}
                    Resolved::Determined(v) => push(proxy_value(is_jump, v)),
                    Resolved::Undetermined(vs) => {
                        vs.iter().for_each(|v| push(proxy_value(is_jump, v)))
                    }
                }
            }
            push(Proxy::None);
            ProxyResolution::Undetermined(out)
        }
    }
}

// --- canonical views: what a digest and a diff compare ---------------------------------

/// A directive's state without provenance: what it would make ssh do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum View {
    Unset,
    Det(Vec<String>),
    Undet(Vec<Vec<String>>),
    /// An accumulated list: each entry's certainty and arguments.
    List(Vec<(bool, Vec<String>)>),
}

fn view(r: &Resolved) -> View {
    match r {
        Resolved::Unset => View::Unset,
        Resolved::Determined(v) => View::Det(v.args.clone()),
        Resolved::Undetermined(vs) => View::Undet(vs.iter().map(|v| v.args.clone()).collect()),
    }
}

fn list_view(l: &[Candidate]) -> View {
    View::List(
        l.iter()
            .map(|c| (c.determined, c.value.args.clone()))
            .collect(),
    )
}

/// The list as one `Resolved`, for a [`BehaviorChange`]: `Unset` when empty, one
/// `Determined` value holding every entry's arguments in order when every entry is
/// determined, otherwise `Undetermined` with each entry.
fn list_resolved(l: &[Candidate]) -> Resolved {
    match l.first() {
        None => Resolved::Unset,
        Some(first) if l.iter().all(|c| c.determined) => Resolved::Determined(Value {
            args: l.iter().flat_map(|c| c.value.args.clone()).collect(),
            span: first.value.span,
            condition: None,
        }),
        Some(_) => Resolved::Undetermined(l.iter().map(|c| c.value.clone()).collect()),
    }
}

/// `ProxyJump` and `ProxyCommand` as two `Resolved`s.
fn proxy_split(p: &ProxyResolution) -> (Resolved, Resolved) {
    match p {
        ProxyResolution::Determined(Proxy::None) => (Resolved::Unset, Resolved::Unset),
        ProxyResolution::Determined(Proxy::Jump(v)) => {
            (Resolved::Determined(v.clone()), Resolved::Unset)
        }
        ProxyResolution::Determined(Proxy::Command(v)) => {
            (Resolved::Unset, Resolved::Determined(v.clone()))
        }
        ProxyResolution::Undetermined(ps) => {
            let pick = |jump: bool| {
                let vs: Vec<Value> = ps
                    .iter()
                    .filter_map(|p| match (p, jump) {
                        (Proxy::Jump(v), true) | (Proxy::Command(v), false) => Some(v.clone()),
                        _ => None,
                    })
                    .collect();
                if vs.is_empty() {
                    Resolved::Unset
                } else {
                    Resolved::Undetermined(vs)
                }
            };
            (pick(true), pick(false))
        }
    }
}

/// Every relevant directive with its view and its `Resolved`, in a fixed order.
fn entries(b: &RelevantBehavior) -> Vec<(KnownKeyword, View, Resolved)> {
    let r = |k: KnownKeyword, x: &Resolved| (k, view(x), x.clone());
    let l = |k: KnownKeyword, x: &[Candidate]| (k, list_view(x), list_resolved(x));
    let (jump, command) = proxy_split(&b.proxy);
    let proxy_view = |p: &ProxyResolution| match p {
        ProxyResolution::Determined(Proxy::None) => View::Unset,
        ProxyResolution::Determined(Proxy::Jump(v)) => View::Det(
            std::iter::once("jump".to_owned())
                .chain(v.args.iter().cloned())
                .collect(),
        ),
        ProxyResolution::Determined(Proxy::Command(v)) => View::Det(
            std::iter::once("command".to_owned())
                .chain(v.args.iter().cloned())
                .collect(),
        ),
        ProxyResolution::Undetermined(ps) => View::Undet(
            ps.iter()
                .map(|p| match p {
                    Proxy::None => vec!["none".to_owned()],
                    Proxy::Jump(v) => std::iter::once("jump".to_owned())
                        .chain(v.args.iter().cloned())
                        .collect(),
                    Proxy::Command(v) => std::iter::once("command".to_owned())
                        .chain(v.args.iter().cloned())
                        .collect(),
                })
                .collect(),
        ),
    };
    let pv = proxy_view(&b.proxy);
    vec![
        r(KnownKeyword::Hostname, &b.hostname),
        r(KnownKeyword::Port, &b.port),
        r(KnownKeyword::User, &b.user),
        r(KnownKeyword::IdentityAgent, &b.identity_agent),
        l(KnownKeyword::IdentityFile, &b.identity_files),
        r(KnownKeyword::IdentitiesOnly, &b.identities_only),
        l(KnownKeyword::CertificateFile, &b.certificate_files),
        (KnownKeyword::ProxyJump, pv.clone(), jump),
        (KnownKeyword::ProxyCommand, pv, command),
        r(KnownKeyword::ControlMaster, &b.control_master),
        r(KnownKeyword::ControlPath, &b.control_path),
        r(KnownKeyword::ControlPersist, &b.control_persist),
        r(KnownKeyword::ForwardAgent, &b.forward_agent),
        r(
            KnownKeyword::StrictHostKeyChecking,
            &b.strict_host_key_checking,
        ),
        r(KnownKeyword::UserKnownHostsFile, &b.user_known_hosts_file),
        r(
            KnownKeyword::GlobalKnownHostsFile,
            &b.global_known_hosts_file,
        ),
        r(KnownKeyword::HostKeyAlias, &b.host_key_alias),
        r(KnownKeyword::CanonicalizeHostname, &b.canonicalize_hostname),
        r(KnownKeyword::PermitLocalCommand, &b.permit_local_command),
        r(KnownKeyword::LocalCommand, &b.local_command),
        r(KnownKeyword::KnownHostsCommand, &b.known_hosts_command),
        r(KnownKeyword::AddKeysToAgent, &b.add_keys_to_agent),
        r(KnownKeyword::Pkcs11Provider, &b.pkcs11_provider),
        r(KnownKeyword::SecurityKeyProvider, &b.security_key_provider),
    ]
}

/// The relevant directives whose state differs. States are compared without
/// provenance (a moved line or a comment is no change), as the digest compares them.
/// `IdentityFile` and `CertificateFile` lists are reported as one `Resolved` each
/// (every entry's arguments in order, or `Undetermined` with each entry), and the
/// proxy as `ProxyJump` and `ProxyCommand`.
#[must_use]
pub fn diff(before: &RelevantBehavior, after: &RelevantBehavior) -> Vec<BehaviorChange> {
    let mut out = Vec::new();
    for ((k, vb, rb), (_, va, ra)) in entries(before).into_iter().zip(entries(after)) {
        let differs = match k {
            // The proxy view is shared by both keywords; compare each side's own part.
            KnownKeyword::ProxyJump | KnownKeyword::ProxyCommand => view(&rb) != view(&ra),
            _ => vb != va,
        };
        if differs {
            out.push(BehaviorChange {
                directive: k,
                before: rb,
                after: ra,
            });
        }
    }
    out
}

/// Length-prefixed writer for the canonical digest input.
struct Canon(Vec<u8>);

impl Canon {
    fn str(&mut self, s: &str) {
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(s.as_bytes());
    }

    fn args(&mut self, args: &[String]) {
        self.str(&args.len().to_string());
        for a in args {
            self.str(a);
        }
    }

    fn view(&mut self, v: &View) {
        match v {
            View::Unset => self.str("unset"),
            View::Det(a) => {
                self.str("determined");
                self.args(a);
            }
            View::Undet(cands) => {
                self.str("undetermined");
                self.str(&cands.len().to_string());
                for a in cands {
                    self.args(a);
                }
            }
            View::List(items) => {
                self.str("list");
                self.str(&items.len().to_string());
                for (det, a) in items {
                    self.str(if *det { "determined" } else { "undetermined" });
                    self.args(a);
                }
            }
        }
    }
}

/// The behaviour's digest (ADR-0007 §5.2): SHA-256 over a canonical, length-prefixed
/// encoding of every relevant directive in a fixed order. Each directive enters with
/// its state (`unset`, `determined`, `undetermined`, or a list), its arguments as
/// written, and for an undetermined one every candidate in evaluation order; a list
/// entry enters with its certainty. File, line and condition provenance never enter,
/// so a moved line or a comment does not change the digest, and a value does.
///
/// **Provenance is reduced further than to the source role.** `Span` carries a
/// `SourceId` and no role, and this function receives only the behaviour, so the
/// role (`managed`, `user`, `system`, `default`) cannot enter. Equal digests still
/// mean equal values for every relevant directive (escalated in the unit report).
/// An undetermined state's condition contents never enter either (M2-R03), which is
/// why consent never reuses an undetermined state.
#[must_use]
pub fn behavior_digest(behavior: &RelevantBehavior) -> BehaviorDigest {
    let mut c = Canon(Vec::new());
    c.str("heimdall.behavior.v1");
    let all = entries(behavior);
    for (k, v, _) in &all {
        // The proxy view appears under both keywords; write it once.
        if *k == KnownKeyword::ProxyCommand {
            continue;
        }
        c.str(if *k == KnownKeyword::ProxyJump {
            "Proxy"
        } else {
            k.as_str()
        });
        c.view(v);
    }
    BehaviorDigest::of(&c.0)
}

/// The digest and whether every directive is determined (M2-R03): no `Undetermined`
/// value, no undetermined list entry, and a determined proxy.
#[must_use]
pub fn behavior_state(behavior: &RelevantBehavior) -> BehaviorState {
    let determined = entries(behavior).iter().all(|(_, v, _)| match v {
        View::Unset | View::Det(_) => true,
        View::Undet(_) => false,
        View::List(items) => items.iter().all(|(d, _)| *d),
    });
    BehaviorState {
        digest: behavior_digest(behavior),
        determined,
    }
}

// --- identity selection -----------------------------------------------------------------

/// ssh's default identity files under `~/.ssh` (F20 [S01]).
const DEFAULT_IDENTITIES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_mldsa44_ed25519",
];

/// Which identities ssh may offer for the alias, and whether the adopted key is the
/// only one (ADR-0007 §3 item 3). `source` is used only to stat for a private key's
/// presence and to read `.pub` files; a private key file is never opened.
///
/// See [`identity_selection_with_spans`] for the rules; this is its report alone.
#[must_use]
pub fn identity_selection(
    evaluation: &Evaluation,
    adopted: &Path,
    source: &dyn ConfigSource,
) -> IdentitySelectionReport {
    identity_selection_with_spans(evaluation, adopted, source).0
}

/// [`identity_selection`], with each entry's directive span (`None` for a default
/// identity), aligned with `report.entries`, so a caller that can name the files
/// (`SourceId` → path) can fill `IdentityEntry.provenance`, which this crate cannot.
///
/// **Entries**, in order: every `IdentityFile` entry except `none`; when no entry is
/// certain to apply, the default identities that exist (`Default`, undetermined when
/// some undetermined entry may apply instead); then every `CertificateFile` entry.
/// An entry whose expanded path equals `adopted` is `Managed`; any other is `User`
/// (system entries cannot be told apart, see [`behavior_digest`]). An entry whose path
/// cannot be expanded statically (a `%` token other than `%%`/`%d`, `~user`, a relative
/// path, an opaque candidate) has no fingerprint and `unknown` backing.
///
/// **Backing and fingerprint.** For a path ending in `.pub`, the file is read as the
/// public key and the backing is `agent` (ssh has no private key file for it, F9).
/// Otherwise `<path>.pub` is read for the fingerprint, and the private key's presence
/// is checked with `ConfigSource::glob` on the literal path, a stat that never opens
/// it: present is `file`, absent with a readable `.pub` is `agent`, anything else is
/// `unknown` (including a path with glob metacharacters, which is not statted).
///
/// **Selection** (M2-D01; the fail-closed reading):
/// * `not_exclusive` when any determined entry is not the adopted key (an inherited
///   `IdentityFile` or `CertificateFile`, a default identity), or when the adopted key
///   is not certainly in the list and nothing else is undetermined;
/// * `undetermined` when the adopted key is certainly there, nothing else certainly
///   is, and some other entry may apply; also when `IdentitiesOnly` is undetermined;
/// * `exclusive` only when the list is exactly the adopted key, every entry is
///   determined, and `IdentitiesOnly` is a determined `yes` (otherwise the agent may
///   offer every key it holds, F9), else `not_exclusive`.
#[must_use]
pub fn identity_selection_with_spans(
    evaluation: &Evaluation,
    adopted: &Path,
    source: &dyn ConfigSource,
) -> (IdentitySelectionReport, Vec<Option<Span>>) {
    let adopted_norm = norm(adopted);
    let mut entries = Vec::new();
    let mut spans = Vec::new();
    let ids = evaluation
        .accumulated
        .get(&KnownKeyword::IdentityFile)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for c in ids.iter().filter(|c| !is_none_value(&c.value)) {
        let path = c
            .value
            .args
            .first()
            .and_then(|a| expand_identity_path(a, source));
        let managed = path.as_deref().is_some_and(|p| norm(p) == adopted_norm);
        let (fingerprint, backing) = path
            .as_deref()
            .map_or((None, IdentityBacking::Unknown), |p| key_facts(p, source));
        entries.push(IdentityEntry {
            kind: IdentityEntryKind::IdentityFile,
            source: if managed {
                IdentityEntrySource::Managed
            } else {
                IdentityEntrySource::User
            },
            provenance: None,
            certainty: certainty(c.determined),
            fingerprint,
            backing,
            cleared: None,
        });
        spans.push(Some(c.value.span));
    }
    // F20 [I]: the defaults apply only when no IdentityFile entry (not even `none`) is
    // obtained.
    if !ids.iter().any(|c| c.determined) {
        let certain = ids.is_empty();
        for name in DEFAULT_IDENTITIES {
            let p = source.user_dir().join(name);
            let (fingerprint, backing) = key_facts(&p, source);
            if fingerprint.is_none() && backing == IdentityBacking::Unknown {
                continue; // neither the key nor its `.pub` exists: ssh tries nothing
            }
            entries.push(IdentityEntry {
                kind: IdentityEntryKind::IdentityFile,
                source: IdentityEntrySource::Default,
                provenance: None,
                certainty: certainty(certain),
                fingerprint,
                backing,
                cleared: None,
            });
            spans.push(None);
        }
    }
    let certs = evaluation
        .accumulated
        .get(&KnownKeyword::CertificateFile)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for c in certs.iter().filter(|c| !is_none_value(&c.value)) {
        entries.push(IdentityEntry {
            kind: IdentityEntryKind::CertificateFile,
            source: IdentityEntrySource::User,
            provenance: None,
            certainty: certainty(c.determined),
            fingerprint: None,
            backing: IdentityBacking::Unknown,
            cleared: None,
        });
        spans.push(Some(c.value.span));
    }
    let identities_only = identities_only_of(evaluation);
    let is_adopted = |e: &IdentityEntry| e.source == IdentityEntrySource::Managed;
    let determined = |e: &IdentityEntry| e.certainty == Certainty::Determined;
    let other_det = entries.iter().any(|e| !is_adopted(e) && determined(e));
    let adopted_det = entries.iter().any(|e| is_adopted(e) && determined(e));
    let any_undet = entries.iter().any(|e| !determined(e));
    let selection = if other_det {
        IdentitySelection::NotExclusive
    } else if !adopted_det {
        if any_undet {
            IdentitySelection::Undetermined
        } else {
            IdentitySelection::NotExclusive
        }
    } else if any_undet {
        IdentitySelection::Undetermined
    } else {
        match identities_only {
            IdentitiesOnly::DeterminedYes => IdentitySelection::Exclusive,
            IdentitiesOnly::DeterminedNo => IdentitySelection::NotExclusive,
            _ => IdentitySelection::Undetermined,
        }
    };
    (
        IdentitySelectionReport {
            selection,
            entries,
            identities_only,
        },
        spans,
    )
}

fn certainty(determined: bool) -> Certainty {
    if determined {
        Certainty::Determined
    } else {
        Certainty::Undetermined
    }
}

fn is_yes(v: &Value) -> bool {
    v.args
        .first()
        .is_some_and(|a| a.eq_ignore_ascii_case("yes") || a.eq_ignore_ascii_case("true"))
}

fn identities_only_of(evaluation: &Evaluation) -> IdentitiesOnly {
    match evaluation.values.get(&KnownKeyword::IdentitiesOnly) {
        None | Some(Resolved::Unset) => IdentitiesOnly::DeterminedNo,
        Some(Resolved::Determined(v)) => {
            if is_yes(v) {
                IdentitiesOnly::DeterminedYes
            } else {
                IdentitiesOnly::DeterminedNo
            }
        }
        Some(Resolved::Undetermined(_)) => IdentitiesOnly::Undetermined,
    }
}

/// Paths compared with `/` separators.
fn norm(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Expand an `IdentityFile` argument as far as is known without the query, with U1's
/// [`crate::include::expand`]: `${VAR}`, `%%`, `%d`, then `~`/`~/`. `None` for anything
/// else (another token, `~user`, a relative path, which ssh resolves against its
/// working directory, an unset variable, an argument ssh refuses).
fn expand_identity_path(arg: &str, source: &dyn ConfigSource) -> Option<PathBuf> {
    let out = crate::include::expand(arg, KnownKeyword::IdentityFile, source, &|_| None).ok()?;
    let home = source.account_home();
    if out == "~" {
        return Some(home.to_path_buf());
    }
    if let Some(rest) = out.strip_prefix("~/") {
        return Some(home.join(rest));
    }
    if out.starts_with('~') {
        return None;
    }
    let p = PathBuf::from(out);
    let b = p.to_string_lossy().into_owned();
    let drive = b.len() >= 3
        && b.as_bytes()[0].is_ascii_alphabetic()
        && b.as_bytes()[1] == b':'
        && matches!(b.as_bytes()[2], b'/' | b'\\');
    (p.is_absolute() || drive).then_some(p)
}

/// Fingerprint and backing of an identity path (see
/// [`identity_selection_with_spans`]). Never opens a private key.
fn key_facts(path: &Path, source: &dyn ConfigSource) -> (Option<String>, IdentityBacking) {
    let text = path.to_string_lossy().into_owned();
    if text.ends_with(".pub") {
        return match source.read(path) {
            Ok(b) => (fingerprint_of(&b.bytes), IdentityBacking::Agent),
            Err(_) => (None, IdentityBacking::Unknown),
        };
    }
    let public = source.read(&PathBuf::from(format!("{text}.pub"))).ok();
    let fingerprint = public.as_ref().and_then(|b| fingerprint_of(&b.bytes));
    let private = if text.contains(['*', '?', '[', ']']) {
        None
    } else {
        match source.glob(path) {
            Ok(found) => Some(!found.is_empty()),
            Err(SourceError::NotFound) => Some(false),
            Err(_) => None,
        }
    };
    let backing = match private {
        Some(true) => IdentityBacking::File,
        Some(false) if public.is_some() => IdentityBacking::Agent,
        _ => IdentityBacking::Unknown,
    };
    (fingerprint, backing)
}

/// `SHA256:<base64, unpadded>` of the key blob on the first key line of a `.pub`.
fn fingerprint_of(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let mut parts = line.split_ascii_whitespace();
    let kind = parts.next()?;
    let blob = base64_decode(parts.next()?)?;
    // The blob starts with its own key type, as a length-prefixed string.
    let len = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    if blob.get(4..4 + len)? != kind.as_bytes() {
        return None;
    }
    let hex = BehaviorDigest::of(&blob);
    let raw: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(hex.as_str().get(2 * i..2 * i + 2)?, 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(format!("SHA256:{}", base64_encode_unpadded(&raw)))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| {
        B64.iter()
            .position(|&x| x == c)
            .and_then(|p| u32::try_from(p).ok())
    };
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n: u32 = 0;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * u32::try_from(pad).ok()?;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

fn base64_encode_unpadded(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(char::from(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]));
        }
    }
    out
}

// --- what the probes need ---------------------------------------------------------------

/// Every construct that runs a command: `Match exec`, `ProxyCommand`,
/// `KnownHostsCommand`, and `LocalCommand` with `PermitLocalCommand`.
///
/// Sorted and without duplicates. Only constructs that may take effect are listed: a
/// `ProxyCommand` that a `ProxyJump` beats (F10), a value under a false condition, and
/// a `none` value are not. An opaque candidate (an unreadable part of the tree, which
/// may run anything) is listed with its span. A `LocalCommand` is listed when
/// `PermitLocalCommand` may be `yes`.
#[must_use]
pub fn executing_constructs(evaluation: &Evaluation) -> Vec<Span> {
    let mut spans = BTreeSet::new();
    for u in &evaluation.unresolved {
        if u.reason == UnresolvedReason::MatchExec {
            spans.insert(u.span);
        }
    }
    let runs = |k: KnownKeyword| -> Vec<Span> {
        match evaluation.values.get(&k) {
            Some(Resolved::Determined(v)) if !is_none_value(v) => vec![v.span],
            Some(Resolved::Undetermined(vs)) => vs
                .iter()
                .filter(|v| !is_none_value(v))
                .map(|v| v.span)
                .collect(),
            _ => Vec::new(),
        }
    };
    spans.extend(runs(KnownKeyword::ProxyCommand));
    spans.extend(runs(KnownKeyword::KnownHostsCommand));
    let permit = match evaluation.values.get(&KnownKeyword::PermitLocalCommand) {
        None | Some(Resolved::Unset) => false,
        Some(Resolved::Determined(v)) => is_yes(v),
        Some(Resolved::Undetermined(vs)) => vs.iter().any(|v| v.args.is_empty() || is_yes(v)),
    };
    if permit {
        spans.extend(runs(KnownKeyword::LocalCommand));
    }
    spans.into_iter().collect()
}

/// The unresolved points that make the tree not fully readable for the probes
/// (`IncludeUnreadable`, `BoundExceeded`, a `TokenUnavailable` in an `Include`;
/// ADR-0007 §6). The evaluator records `TokenUnavailable` only for `Include` paths,
/// and records `IncludeUnreadable` as well for an `Include` whose `${VAR}` is unset.
#[must_use]
pub fn unreadable_includes(evaluation: &Evaluation) -> Vec<Unresolved> {
    evaluation
        .unresolved
        .iter()
        .filter(|u| {
            matches!(
                u.reason,
                UnresolvedReason::IncludeUnreadable
                    | UnresolvedReason::BoundExceeded
                    | UnresolvedReason::TokenUnavailable(_)
            )
        })
        .cloned()
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let enc = base64_encode_unpadded(data);
            let mut padded = enc.clone();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            if !data.is_empty() {
                assert_eq!(base64_decode(&padded).unwrap(), data);
            }
        }
        assert_eq!(base64_encode_unpadded(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode_unpadded(b"fo"), "Zm8");
        assert!(base64_decode("Zm9=v").is_none());
    }

    #[test]
    fn fingerprint_matches_openssh_form() {
        // A synthetic public key blob (type string + 32 zero bytes); public data only.
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[0u8; 32]);
        let mut b64 = base64_encode_unpadded(&blob);
        while !b64.len().is_multiple_of(4) {
            b64.push('=');
        }
        let line = format!("ssh-ed25519 {b64} fixture\n");
        let fp = fingerprint_of(line.as_bytes()).unwrap();
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), "SHA256:".len() + 43);
        // A mismatched type string is refused.
        assert!(fingerprint_of(format!("ssh-rsa {b64}\n").as_bytes()).is_none());
    }
}
