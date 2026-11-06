//! The behaviour that matters for access, reduced from an [`Evaluation`] (m02-plan
//! U2; ADR-0007 §3, §5.2).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::doctor::ConfigProvenance;
use heimdall_contract::provider::{
    Certainty, IdentitiesOnly, IdentityBacking, IdentityEntry, IdentityEntryKind,
    IdentityEntrySource, IdentitySelection, IdentitySelectionReport,
};
use heimdall_domain::projection::{BehaviorDigest, BehaviorState};

use crate::directive::{KnownKeyword, keeps_raw};
use crate::eval::{
    Candidate, Evaluation, Invocation, Query, Resolved, SourceRole, Unresolved, UnresolvedReason,
    Value, evaluate,
};
use crate::include::{ConfigSet, ConfigSource, Roots, SourceError};
use crate::limits::Limits;
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
    /// `RemoteCommand` (runs on the server; its text is bound raw like the local
    /// commands, ADR-0007 §12.15 item 2).
    pub remote_command: Resolved,
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
        remote_command: get(KnownKeyword::RemoteCommand),
        known_hosts_command: get(KnownKeyword::KnownHostsCommand),
        add_keys_to_agent: get(KnownKeyword::AddKeysToAgent),
        pkcs11_provider: get(KnownKeyword::Pkcs11Provider),
        security_key_provider: get(KnownKeyword::SecurityKeyProvider),
    }
}

/// Whether ssh clears the option for this value: `none` (case-insensitive) as the whole
/// value. For `ProxyCommand`, `LocalCommand`, `RemoteCommand` and `KnownHostsCommand` the
/// value is the raw text, so `none # why` and `"none"` are commands, not `none`
/// (S01: "The command string extends to the end of the line"; ssh -G on OpenSSH_10.3p1
/// printed both back, and printed nothing for a bare `none`). For every other keyword
/// it is the only argument.
fn is_none_value(v: &Value) -> bool {
    match &v.raw {
        Some(raw) => raw.eq_ignore_ascii_case("none"),
        None => v.args.len() == 1 && v.args[0].eq_ignore_ascii_case("none"),
    }
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

/// What one value is for a digest and a diff: its source role and its content. The file
/// and line never enter, so a line moved within a role or a comment is no change; a value
/// moved from one role to another is (ADR-0007 §5.2, §12.15 item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    role: SourceRole,
    /// Which proxy it is, for the shared proxy view.
    kind: Option<&'static str>,
    content: Content,
}

/// The text of a value: its split arguments, or, for the four command keywords, the raw
/// text ssh stores and hands to a shell (ADR-0007 §12.15 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    Args(Vec<String>),
    Raw(String),
}

/// The content of `v` as a value of `k`: the raw text where the keyword keeps one and the
/// value has it, otherwise the arguments (an opaque candidate has none).
fn content(k: KnownKeyword, v: &Value) -> Content {
    match &v.raw {
        Some(raw) if keeps_raw(k) => Content::Raw(raw.clone()),
        _ => Content::Args(v.args.clone()),
    }
}

fn item(k: KnownKeyword, v: &Value) -> Item {
    Item {
        role: v.role,
        kind: None,
        content: content(k, v),
    }
}

fn proxy_item(p: &Proxy) -> Item {
    match p {
        Proxy::None => Item {
            role: SourceRole::Default,
            kind: Some("none"),
            content: Content::Args(Vec::new()),
        },
        Proxy::Jump(v) => Item {
            role: v.role,
            kind: Some("jump"),
            content: content(KnownKeyword::ProxyJump, v),
        },
        Proxy::Command(v) => Item {
            role: v.role,
            kind: Some("command"),
            content: content(KnownKeyword::ProxyCommand, v),
        },
    }
}

/// A directive's state without its file and line: what it would make ssh do, and which
/// role says so.
#[derive(Debug, Clone, PartialEq, Eq)]
enum View {
    Unset,
    Det(Item),
    Undet(Vec<Item>),
    /// An accumulated list: each entry's certainty and value.
    List(Vec<(bool, Item)>),
}

fn view(k: KnownKeyword, r: &Resolved) -> View {
    match r {
        Resolved::Unset => View::Unset,
        Resolved::Determined(v) => View::Det(item(k, v)),
        Resolved::Undetermined(vs) => View::Undet(vs.iter().map(|v| item(k, v)).collect()),
    }
}

/// What the decision summary shows for the default agent (ADR-0007 §12.16 item 1). Its
/// endpoint is outside configuration: whatever socket the session's `SSH_AUTH_SOCK`
/// names when ssh runs (ADR-0007 §13).
pub const DEFAULT_AGENT_DISPLAY: &str = "the session's SSH_AUTH_SOCK";

/// Whether an `IdentityAgent` value is the default agent (ADR-0007 §12.16 item 1): the
/// literal `SSH_AUTH_SOCK` or `$SSH_AUTH_SOCK` (ssh compares them case-sensitively).
/// `${SSH_AUTH_SOCK}` is not: it is an environment reference, so undetermined.
#[must_use]
pub fn is_default_agent(value: &Value) -> bool {
    matches!(value.args.as_slice(), [a] if a == "SSH_AUTH_SOCK" || a == "$SSH_AUTH_SOCK")
}

/// Whether a resolved `IdentityAgent` is certainly the default agent: unset, or a
/// determined [`is_default_agent`] value. The default agent is determined, with role
/// `default`, whichever of its three forms the configuration uses.
#[must_use]
pub fn agent_is_default(agent: &Resolved) -> bool {
    match agent {
        Resolved::Unset => true,
        Resolved::Determined(v) => is_default_agent(v),
        Resolved::Undetermined(_) => false,
    }
}

/// The one canonical item of the default agent: role `default`, no file, so the three
/// forms (and the file that writes one) compare and digest alike.
fn default_agent_item() -> Item {
    Item {
        role: SourceRole::Default,
        kind: Some("default_agent"),
        content: Content::Args(Vec::new()),
    }
}

/// `IdentityAgent`'s view: [`view`], with every default-agent form, unset included,
/// as [`default_agent_item`] (ADR-0007 §12.16 item 1).
fn agent_view(r: &Resolved) -> View {
    let it = |v: &Value| {
        if is_default_agent(v) {
            default_agent_item()
        } else {
            item(KnownKeyword::IdentityAgent, v)
        }
    };
    match r {
        Resolved::Unset => View::Det(default_agent_item()),
        Resolved::Determined(v) => View::Det(it(v)),
        Resolved::Undetermined(vs) => View::Undet(vs.iter().map(it).collect()),
    }
}

fn list_view(k: KnownKeyword, l: &[Candidate]) -> View {
    View::List(
        l.iter()
            .map(|c| (c.determined, item(k, &c.value)))
            .collect(),
    )
}

/// The list as one `Resolved`, for a [`BehaviorChange`]: `Unset` when empty, one
/// `Determined` value holding every entry's arguments in order when every entry is
/// determined (with the first entry's role), otherwise `Undetermined` with each entry.
fn list_resolved(l: &[Candidate]) -> Resolved {
    match l.first() {
        None => Resolved::Unset,
        Some(first) if l.iter().all(|c| c.determined) => Resolved::Determined(Value {
            args: l.iter().flat_map(|c| c.value.args.clone()).collect(),
            span: first.value.span,
            condition: None,
            role: first.value.role,
            raw: None,
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
    let r = |k: KnownKeyword, x: &Resolved| (k, view(k, x), x.clone());
    let l = |k: KnownKeyword, x: &[Candidate]| (k, list_view(k, x), list_resolved(x));
    let (jump, command) = proxy_split(&b.proxy);
    let pv = match &b.proxy {
        ProxyResolution::Determined(Proxy::None) => View::Unset,
        ProxyResolution::Determined(p) => View::Det(proxy_item(p)),
        ProxyResolution::Undetermined(ps) => View::Undet(ps.iter().map(proxy_item).collect()),
    };
    vec![
        r(KnownKeyword::Hostname, &b.hostname),
        r(KnownKeyword::Port, &b.port),
        r(KnownKeyword::User, &b.user),
        (
            KnownKeyword::IdentityAgent,
            agent_view(&b.identity_agent),
            b.identity_agent.clone(),
        ),
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
        r(KnownKeyword::RemoteCommand, &b.remote_command),
        r(KnownKeyword::KnownHostsCommand, &b.known_hosts_command),
        r(KnownKeyword::AddKeysToAgent, &b.add_keys_to_agent),
        r(KnownKeyword::Pkcs11Provider, &b.pkcs11_provider),
        r(KnownKeyword::SecurityKeyProvider, &b.security_key_provider),
    ]
}

/// The relevant directives whose state differs. States are compared as the digest
/// compares them: by role and content, never by file or line (a moved line or a comment
/// is no change; a value moved to another source role, or a command whose quoting
/// changed, is one). `IdentityFile` and `CertificateFile` lists are reported as one
/// `Resolved` each (every entry's arguments in order, or `Undetermined` with each
/// entry), and the proxy as `ProxyJump` and `ProxyCommand`.
#[must_use]
pub fn diff(before: &RelevantBehavior, after: &RelevantBehavior) -> Vec<BehaviorChange> {
    let mut out = Vec::new();
    for ((k, vb, rb), (_, va, ra)) in entries(before).into_iter().zip(entries(after)) {
        let differs = match k {
            // The proxy view is shared by both keywords; compare each side's own part.
            KnownKeyword::ProxyJump | KnownKeyword::ProxyCommand => view(k, &rb) != view(k, &ra),
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

    /// One value: its role, its proxy kind (empty when it has none), then either its
    /// arguments or, for a command keyword, its raw text, each under its own tag.
    fn item(&mut self, i: &Item) {
        self.str(i.role.as_str());
        self.str(i.kind.unwrap_or(""));
        match &i.content {
            Content::Args(a) => {
                self.str("args");
                self.args(a);
            }
            Content::Raw(raw) => {
                self.str("raw");
                self.str(raw);
            }
        }
    }

    fn view(&mut self, v: &View) {
        match v {
            View::Unset => self.str("unset"),
            View::Det(i) => {
                self.str("determined");
                self.item(i);
            }
            View::Undet(cands) => {
                self.str("undetermined");
                self.str(&cands.len().to_string());
                for i in cands {
                    self.item(i);
                }
            }
            View::List(items) => {
                self.str("list");
                self.str(&items.len().to_string());
                for (det, i) in items {
                    self.str(if *det { "determined" } else { "undetermined" });
                    self.item(i);
                }
            }
        }
    }
}

/// The behaviour's digest (ADR-0007 §5.2): SHA-256 over a canonical, length-prefixed
/// encoding of every relevant directive in a fixed order. Each directive enters with
/// its state (`unset`, `determined`, `undetermined`, or a list) and, for every value, its
/// **source role** (`managed`, `user`, `system`, `default`), its arguments as written and,
/// for an undetermined one, every candidate in evaluation order; a list entry enters
/// with its certainty. File, line and condition provenance never enter, so a line moved
/// within its role or a comment does not change the digest, while a value does, and so
/// does moving a value to another role (ADR-0007 §12.15 item 3).
///
/// **Command text is bound raw** (ADR-0007 §12.15 item 2). For `ProxyCommand`,
/// `LocalCommand`, `RemoteCommand` and `KnownHostsCommand` the digest binds the
/// directive's raw text ([`crate::parse::Directive::raw`]) in place of its split
/// arguments, so a change of quoting alone (`$X` against `'$X'`), which changes what
/// the shell runs, changes the digest. A value with no raw text (an opaque candidate)
/// enters with its arguments.
///
/// An undetermined state's condition contents never enter (M2-R03), which is why consent
/// never reuses an undetermined state.
///
/// **Environment references and the default agent** (ADR-0007 §12.16 item 1). A value
/// that reads the environment is undetermined in the evaluation (reason
/// `environment_reference`), so it enters as written, never expanded, and its state is
/// never determined: two runtimes whose variables differ give equal digests, and
/// consent is never reused across them. `IdentityAgent SSH_AUTH_SOCK`, `IdentityAgent
/// $SSH_AUTH_SOCK` and an unset `IdentityAgent` enter as one determined value of role
/// `default` (the default agent), wherever they are written.
#[must_use]
pub fn behavior_digest(behavior: &RelevantBehavior) -> BehaviorDigest {
    let mut c = Canon(Vec::new());
    c.str("heimdall.behavior.v2");
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
///
/// This is one invocation's state. Consent compares the state across every invocation
/// profile ([`consent_behavior_state`], ADR-0007 §12.21 item 2), which binds this
/// digest per profile.
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

// --- the consent behaviour state: every invocation profile (ADR-0007 §12.21 item 2) ----

/// The tag of a profile-aware behaviour state's digest (ADR-0007 §12.21 item 2). A
/// digest of this tag is never compared with one of the single-invocation tag
/// `heimdall.behavior.v2` ([`behavior_digest`]); no consent of either tag was persisted
/// before this one.
pub const BEHAVIOR_STATE_TAG: &str = "heimdall.behavior.v3";

/// The behaviour state of one item across invocation profiles (ADR-0007 §12.21 item 2),
/// from its relevant behaviour under each profile, in the caller's order (consent uses
/// [`Invocation::consent_profiles`]).
///
/// **Digest.** SHA-256 over the length-prefixed encoding (each field a 4-byte big-endian
/// length, then its UTF-8 bytes) of: the tag [`BEHAVIOR_STATE_TAG`]; the number of
/// profiles, in decimal; then, for each profile in order, its
/// [`Invocation::profile_name`] and its per-profile digest ([`behavior_digest`], lower
/// hex). So a value that only an exec or a subsystem invocation obtains changes the
/// digest, and the profile is part of what is bound.
///
/// **Determined** only when every profile's behaviour is ([`behavior_state`]); an empty
/// list is never determined (fail closed).
#[must_use]
pub fn profiled_behavior_state(per_profile: &[(Invocation, RelevantBehavior)]) -> BehaviorState {
    let mut c = Canon(Vec::new());
    c.str(BEHAVIOR_STATE_TAG);
    c.str(&per_profile.len().to_string());
    let mut determined = !per_profile.is_empty();
    for (invocation, behavior) in per_profile {
        let state = behavior_state(behavior);
        c.str(&invocation.profile_name());
        c.str(state.digest.as_str());
        determined &= state.determined;
    }
    BehaviorState {
        digest: BehaviorDigest::of(&c.0),
        determined,
    }
}

/// The consent behaviour state of `query.host` (ADR-0007 §5.2 as amended by §12.21
/// item 2): `query` evaluated over the tree under each of
/// [`Invocation::consent_profiles`] (its own `invocation` is replaced), each evaluation
/// reduced by [`relevant`], combined by [`profiled_behavior_state`]. Static: nothing
/// executes, and `Match command` is unknown under `Exec(None)`.
///
/// `set` caches the tree's parsed files across the three evaluations; it must belong to
/// this `source`.
#[must_use]
pub fn consent_behavior_state(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    query: &Query,
    limits: &Limits,
) -> BehaviorState {
    let per_profile: Vec<(Invocation, RelevantBehavior)> = Invocation::consent_profiles()
        .into_iter()
        .map(|invocation| {
            let q = Query {
                invocation: invocation.clone(),
                ..query.clone()
            };
            let evaluation = evaluate(set, source, roots, &q, limits);
            (invocation, relevant(&evaluation))
        })
        .collect();
    profiled_behavior_state(&per_profile)
}

// --- identity selection -----------------------------------------------------------------

// ssh's default identity files under `~/.ssh` (F20): the union over every supported
// client and the pinned manuals (`crate::client::DEFAULT_IDENTITIES`, ADR-0007 §12.32
// item 12), so a default key of any of them is never missed.
use crate::client::DEFAULT_IDENTITIES;

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
/// identity), aligned with `report.entries` (additive: the report itself now carries
/// each entry's `provenance`).
///
/// **Entries**, in order: every `IdentityFile` entry except `none`; when no entry is
/// certain to apply, the default identities that exist (`Default`, undetermined when
/// some undetermined entry may apply instead); then every `CertificateFile` entry.
///
/// **Source and provenance** (ADR-0007 §12.15 item 3b). An entry read from a file has
/// the `source` of that value's role ([`Value::role`]): `Managed` for P
/// ([`crate::include::Roots::managed`]), `User` or `System` for the file's tree;
/// a default identity is `Default`. `provenance` is the directive's file and line: the
/// file's path as the configuration names it, as [`Evaluation::files`] recorded it
/// (ADR-0007 §12.28 item 6), shown with `~` for the account home and `/` separators,
/// and the line; `None` for a default identity and for
/// a span the evaluation has no file for. Whether an entry is the adopted key is a
/// separate question, answered by its path (below): an entry that names the adopted
/// path but was read from the user's file is `User`, not `Managed`.
///
/// An entry whose path cannot be expanded statically (a `%` token other than
/// `%%`/`%d`, `~user`, a relative path, an opaque candidate) has no fingerprint and
/// `unknown` backing. So has an entry whose path reads the environment (`${VAR}`):
/// the runtime's value is not a later ssh's, so it is never expanded, and the entry is
/// undetermined (ADR-0007 §12.16 item 1).
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
    // Whether each entry is the adopted key, by its expanded path (parallel to
    // `entries`; independent of the entry's source role).
    let mut adopted_flags = Vec::new();
    let provenance = |span: Span| -> Option<ConfigProvenance> {
        evaluation
            .files
            .get(&span.source)
            .map(|path| ConfigProvenance {
                path_display: display_path(path, source.account_home()),
                line: span.line,
            })
    };
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
            source: entry_source(c.value.role),
            provenance: provenance(c.value.span),
            certainty: certainty(c.determined),
            fingerprint,
            backing,
            cleared: None,
        });
        adopted_flags.push(managed);
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
            adopted_flags.push(false);
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
            source: entry_source(c.value.role),
            provenance: provenance(c.value.span),
            certainty: certainty(c.determined),
            fingerprint: None,
            backing: IdentityBacking::Unknown,
            cleared: None,
        });
        adopted_flags.push(false);
        spans.push(Some(c.value.span));
    }
    let identities_only = identities_only_of(evaluation);
    let determined = |e: &IdentityEntry| e.certainty == Certainty::Determined;
    let other_det = entries
        .iter()
        .zip(&adopted_flags)
        .any(|(e, adopted)| !adopted && determined(e));
    let adopted_det = entries
        .iter()
        .zip(&adopted_flags)
        .any(|(e, adopted)| *adopted && determined(e));
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

/// The entry source for a value's role (ADR-0007 §12.15 item 3b).
fn entry_source(role: SourceRole) -> IdentityEntrySource {
    match role {
        SourceRole::Managed => IdentityEntrySource::Managed,
        SourceRole::User => IdentityEntrySource::User,
        SourceRole::System => IdentityEntrySource::System,
        SourceRole::Default => IdentityEntrySource::Default,
    }
}

/// A file's display form: `~/…` under the account home, otherwise the path, with `/`
/// separators either way (a `--redact` caller reduces it further).
fn display_path(path: &Path, home: &Path) -> String {
    let text = |p: &Path| p.to_string_lossy().replace('\\', "/");
    if home.as_os_str().is_empty() {
        return text(path);
    }
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", text(rest)),
        Err(_) => text(path),
    }
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
/// [`crate::include::expand`]: `%%`, `%d`, then `~`/`~/`. `None` for anything else
/// (a `${VAR}`, which is an environment reference, ADR-0007 §12.16 item 1; another
/// token, `~user`, a relative path, which ssh resolves against its working directory,
/// an argument ssh refuses).
fn expand_identity_path(arg: &str, source: &dyn ConfigSource) -> Option<PathBuf> {
    if arg.contains("${") {
        return None;
    }
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

/// Every construct that runs a command or loads code: `Match exec`, `ProxyCommand`,
/// `KnownHostsCommand`, `LocalCommand` with `PermitLocalCommand`, and, since
/// ADR-0007 §12.15 item 5, `XAuthLocation`, `PKCS11Provider` and `SecurityKeyProvider`,
/// which make ssh run a program or load a library when used. Their value class stays
/// first-wins.
///
/// Sorted and without duplicates. Only constructs that may take effect are listed: a
/// `ProxyCommand` that a `ProxyJump` beats (F10), a value under a false condition, and
/// a `none` value are not. An opaque candidate (an unreadable part of the tree, which
/// may run anything) is listed with its span. A `LocalCommand` is listed when
/// `PermitLocalCommand` may be `yes`.
///
/// `XAuthLocation` is listed whenever it is set, `none` included (ADR-0007 §12.17 item
/// 9): `ssh -G` on OpenSSH_10.3p1 printed `xauthlocation none`, so `none` is a program
/// name there, not a switch. There is no condition on `ForwardX11`: ssh runs the
/// program only when X11 forwarding is in use, and the command line (`-X`, `-Y`) can
/// turn that on whatever the configuration says, which this crate does not model (the
/// fail-closed reading). An unset directive is not listed: ssh's built-in default is
/// not configuration.
///
/// A `none` value of `PKCS11Provider` or `SecurityKeyProvider` is not listed, as
/// ADR-0007 §12.15 item 5 says and ssh does (`ssh -G` on OpenSSH_10.3p1 printed nothing
/// for `none`).
#[must_use]
pub fn executing_constructs(evaluation: &Evaluation) -> Vec<Span> {
    let mut spans = BTreeSet::new();
    for u in &evaluation.unresolved {
        if u.reason == UnresolvedReason::MatchExec {
            spans.insert(u.span);
        }
    }
    // `none_runs`: whether a `none` value names a program too (`XAuthLocation`).
    let runs_with = |k: KnownKeyword, none_runs: bool| -> Vec<Span> {
        let may_run = |v: &Value| none_runs || !is_none_value(v);
        match evaluation.values.get(&k) {
            Some(Resolved::Determined(v)) if may_run(v) => vec![v.span],
            Some(Resolved::Undetermined(vs)) => {
                vs.iter().filter(|v| may_run(v)).map(|v| v.span).collect()
            }
            _ => Vec::new(),
        }
    };
    let runs = |k: KnownKeyword| runs_with(k, false);
    spans.extend(runs(KnownKeyword::ProxyCommand));
    spans.extend(runs(KnownKeyword::KnownHostsCommand));
    spans.extend(runs_with(KnownKeyword::XauthLocation, true));
    for code_loading in [
        KnownKeyword::Pkcs11Provider,
        KnownKeyword::SecurityKeyProvider,
    ] {
        spans.extend(runs(code_loading));
    }
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
/// and records `IncludeUnreadable` as well for an `Include` whose `${VAR}` is unset and
/// for an `Include` whose `~` follows a `HOME` that is not the account home (ADR-0007
/// §12.17 item 9), so neither file is read.
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
