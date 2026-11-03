//! The static evaluator (m02-plan U2; ADR-0007 §3, §6, F1–F10).
//!
//! It computes what OpenSSH would obtain for a host **without executing anything**.
//! Where the result depends on something it cannot know (a `Match exec`, the local
//! network, canonicalization, an unreadable include), the value is `Undetermined` with
//! every candidate, and the reason is recorded.
//!
//! **Model.** The walk follows OpenSSH's reader: the user file, then the system file
//! (F1, F6), each `Include` in place (F3), then, when one is due, the final pass over
//! the same files with every value obtained so far kept. Each line's condition is
//! three-valued (true, false, unknown):
//!
//! * a first-wins directive (F1) is `Determined` once a value applies under a true
//!   condition while it is still unset. A value under an unknown condition while the
//!   directive may still be unset adds a candidate and makes it `Undetermined`; every
//!   later value that may still apply is added too, so for every assignment of the
//!   unknown conditions the concrete result is `Unset` or one of the candidates
//!   (ADR-0007 §6 soundness property; `Undetermined` always admits "unset");
//! * an accumulating directive (F2) keeps every entry in order, each with its
//!   certainty. `IdentityFile` and `CertificateFile` drop an entry whose arguments
//!   repeat a determined earlier entry, as OpenSSH drops duplicates;
//! * `ProxyJump` and `ProxyCommand` share one first-wins slot (F10);
//! * a `Host`/`Match` line's condition is evaluated over every value its inputs may
//!   have (`HostName`, `User`, `Tag` so far); `exec` is never run and is unknown
//!   (reason `MatchExec`, recorded for every `exec` ssh would run, including one a
//!   later criterion of the same line makes false, so
//!   [`crate::relevant::executing_constructs`] can list it); `localnetwork` is unknown;
//!   `canonical`/`final` are true only in the final pass;
//! * an `Include` inside a section is read under that section's condition and the
//!   containing file's section state is restored after it (ADR-0007 §3, `[I]`). An
//!   include under a false condition is still read, as OpenSSH reads it "parse only":
//!   its lines never apply, but its keywords are checked and its `Match exec` lines
//!   are recorded;
//! * a part of the tree that cannot be read (an unreadable include, a bound exceeded,
//!   an include path that cannot be expanded, a line that is not UTF-8) may set
//!   anything. Every directive that may still be unset then gets an **opaque
//!   candidate**: a [`Value`] with no arguments whose span is the unreadable point.
//!   No real value has empty arguments (a directive without one is `invalid`);
//! * **environment references are not determined** (ADR-0007 §12.16 item 1, §12.17
//!   item 9). The runtime's environment is not that of a later `ssh`, so a value that
//!   reads a variable applies under an unknown condition with reason
//!   [`UnresolvedReason::EnvironmentReference`], whatever the variable holds here: a
//!   `${VAR}` in a directive that expands it, an `IdentityAgent` beginning with `$`
//!   other than `$SSH_AUTH_SOCK`, and an `Include` whose path holds a `${VAR}` (its
//!   matches are read under an unknown condition and an opaque point stands for any
//!   other file). An `Include` whose `~` follows a `HOME` that is not the account
//!   home ([`crate::include::ConfigSource::include_home`]) is not read at all: it is
//!   opaque, reasons `EnvironmentReference` and `IncludeUnreadable`. `IdentityAgent
//!   SSH_AUTH_SOCK`, `IdentityAgent $SSH_AUTH_SOCK` and an unset `IdentityAgent` are
//!   the default agent, which stays determined;
//! * `Match sessiontype` reads the `SessionType` in force in the pass when there is
//!   one (`default` defers to the invocation), otherwise the invocation; an
//!   undetermined `SessionType` makes it unknown (ADR-0007 §12.16 item 4). A subsystem
//!   invocation's `-s` is read first, so no `SessionType` line takes effect for it.
//!
//! **Source role** (ADR-0007 §5.2, §12.15 item 3). Every [`Value`] carries the role of
//! the file it was read from: [`SourceRole::Managed`] for P, the Heimdall-owned file
//! whose path the caller gives in [`Roots::managed`] (the walk tells P apart by its
//! path), otherwise [`SourceRole::User`] for the user file and what it includes, or
//! [`SourceRole::System`] for the system file and what it includes. The behaviour
//! digest binds the role, never the file or the line. [`Evaluation::files`] names each
//! file read, so a span can be shown as `file:line`.
//!
//! **Retired keywords** (ADR-0007 §12.15 item 4). A keyword in
//! [`crate::directive::OBSOLETE`] is in ssh's own keyword table, so ssh accepts the line
//! and ignores it, whatever `IgnoreUnknown` says and wherever the line is. It is not
//! `invalid`, it changes no value, and it is recorded in [`Evaluation::ignored`] with
//! what ssh says about it; an `Unsupported` one is the doctor's note.
//!
//! **The final pass.** It runs when a `Match final` line was read in the first pass or
//! `CanonicalizeHostname` is not `no`; when either is unknown the final pass's lines
//! apply under an unknown condition. In the final pass `Host` and `Match host` match
//! the first pass's `HostName` (with `%h` expanded) in lower case; with
//! canonicalization that name is unknown (reason `Canonicalization`), because it needs
//! DNS. `HostName` itself is not set again in the final pass (OpenSSH sets it to the
//! resolved name before re-reading).
//!
//! **Pattern matching** follows OpenSSH: `Host` patterns compare case-sensitively
//! with the name as typed in the first pass and with the lower-cased name in the final
//! pass; `Match host`/`originalhost` compare case-insensitively; the other criteria
//! compare case-sensitively. These details come from the OpenSSH implementation, not
//! the pinned manual, so they are `[I]`, settled per client by U3's
//! `integration_sshconf_vs_ssh_g` corpus.
//!
//! **Not modelled:** `-o`, `-p`, `-P` and `-F` on the command line (Heimdall never
//! passes them for ordinary use); `Query::user` is the only command-line value, and
//! when it is given every `User` directive is ignored (the command line wins, F1), so
//! `User` stays `Unset` in the evaluation and the effective user is `Query::user`.
//! Argument syntax is checked only for presence, `Port` ranges and `HostName` tokens;
//! the rest is ssh's (U3's corpus covers it).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use crate::directive::{
    DirectiveClass, Keyword, KnownKeyword, Obsolete, class, expands_env, obsolete,
};
pub use crate::include::SourceRole;
use crate::include::{
    self, ArgError, ConfigSet, ConfigSource, IncludeArg, IncludeError, IncludeVisitor, Origin,
    Roots, SourceError, Visit,
};
use crate::limits::Limits;
use crate::parse::{Directive, Line, SourceId, Span};

/// The span recorded for the user root file itself (no line), when it cannot be read.
pub const USER_ROOT_SPAN: Span = Span {
    source: SourceId(u32::MAX),
    line: 0,
};

/// The span recorded for the system root file itself (no line), when it cannot be
/// read.
pub const SYSTEM_ROOT_SPAN: Span = Span {
    source: SourceId(u32::MAX - 1),
    line: 0,
};

/// An OpenSSH client version, such as `10.3p1` or `9.5p2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpenSshVersion {
    /// Major version.
    pub major: u16,
    /// Minor version.
    pub minor: u16,
    /// Portable release (`p1`), when present.
    pub portable: Option<u16>,
}

impl OpenSshVersion {
    /// The rules this crate implements (argument splitting, `Match` criteria) are
    /// those of OpenSSH 8.7 and later [G03-S04].
    pub const MINIMUM: OpenSshVersion = OpenSshVersion {
        major: 8,
        minor: 7,
        portable: None,
    };
}

/// How ssh is invoked, for `Match command`/`sessiontype` (F9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Invocation {
    /// An interactive shell.
    Shell,
    /// A remote command, when known.
    Exec(Option<String>),
    /// A subsystem (`sftp`).
    Subsystem(String),
}

impl Invocation {
    /// The invocation profiles a consent behaviour state covers (ADR-0007 §12.21 item
    /// 2), in the order its digest binds them:
    ///
    /// 1. [`Invocation::Shell`], an interactive shell;
    /// 2. `Exec(None)`, any remote command with the command unknown, which covers
    ///    Git over SSH and SCP. `Match command` is unknown under it, so a value behind
    ///    one is undetermined (fail closed);
    /// 3. `Subsystem("sftp")`, SFTP.
    ///
    /// [`crate::relevant::consent_behavior_state`] evaluates a host under each.
    #[must_use]
    pub fn consent_profiles() -> [Invocation; 3] {
        [
            Invocation::Shell,
            Invocation::Exec(None),
            Invocation::Subsystem("sftp".to_owned()),
        ]
    }

    /// The invocation's name as a behaviour state's digest binds it (ADR-0007 §12.21
    /// item 2): `shell`; `exec` for a command that is not known; `exec:<command>` for
    /// a known one; `subsystem:<name>`. Two different invocations never share a name.
    #[must_use]
    pub fn profile_name(&self) -> String {
        match self {
            Invocation::Shell => "shell".to_owned(),
            Invocation::Exec(None) => "exec".to_owned(),
            Invocation::Exec(Some(command)) => format!("exec:{command}"),
            Invocation::Subsystem(name) => format!("subsystem:{name}"),
        }
    }
}

/// What is being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The host name or alias as typed.
    pub host: String,
    /// `-l`/`user@`, when given.
    pub user: Option<String>,
    /// The local account name (for `%u` and `Match localuser`).
    pub local_user: String,
    /// The client that will read the configuration.
    pub client_version: OpenSshVersion,
    /// The invocation.
    pub invocation: Invocation,
}

/// One obtained value with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The arguments as written (tokens unexpanded).
    pub args: Vec<String>,
    /// Where the directive is.
    pub span: Span,
    /// The `Host`/`Match` line that made it apply, if any.
    pub condition: Option<Span>,
    /// The source role of the file the directive was read from (ADR-0007 §5.2,
    /// §12.15 item 3): [`SourceRole::Managed`] for P ([`Roots::managed`]),
    /// [`SourceRole::User`] or [`SourceRole::System`] for the file's tree. An opaque
    /// candidate (an unreadable part of the tree) has the role of the file that
    /// included it.
    pub role: SourceRole,
    /// For `ProxyCommand`, `LocalCommand`, `RemoteCommand` and `KnownHostsCommand`: the
    /// directive's raw text ([`crate::parse::Directive::raw`]), which the behaviour
    /// digest binds in place of `args` (ADR-0007 §12.15 item 2). `None` for every other
    /// directive and for an opaque candidate.
    pub raw: Option<String>,
}

impl Value {
    /// A value with these arguments, span and condition, role [`SourceRole::User`] and
    /// no raw text. Use this rather than a struct literal, so a field added later does
    /// not break the caller.
    #[must_use]
    pub fn new(args: Vec<String>, span: Span, condition: Option<Span>) -> Self {
        Self {
            args,
            span,
            condition,
            role: SourceRole::User,
            raw: None,
        }
    }

    /// This value with another source role.
    #[must_use]
    pub fn with_role(mut self, role: SourceRole) -> Self {
        self.role = role;
        self
    }

    /// This value with raw command text.
    #[must_use]
    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self
    }
}

/// The evaluated state of a first-wins directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// No occurrence applies.
    Unset,
    /// Exactly this value applies.
    Determined(Value),
    /// One of these applies, depending on something not evaluated statically.
    Undetermined(Vec<Value>),
}

/// One entry of an accumulating directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The value.
    pub value: Value,
    /// Whether it certainly applies (`false` behind an undetermined condition).
    pub determined: bool,
}

/// Why something could not be evaluated statically.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnresolvedReason {
    /// `Match exec`: never run (F4, F13).
    MatchExec,
    /// `Match localnetwork`.
    MatchLocalNetwork,
    /// Canonicalization (`CanonicalizeHostname yes`, `Match canonical`/`final`).
    Canonicalization,
    /// An included file could not be read.
    IncludeUnreadable,
    /// A bound of [`Limits`] was exceeded.
    BoundExceeded,
    /// `${VAR}` names an unset variable (F7).
    EnvUnset(String),
    /// A `%` token whose value is not known statically.
    TokenUnavailable(char),
    /// The value reads the environment, which is not the environment of a later `ssh`
    /// (ADR-0007 §12.16 item 1, §12.17 item 9): a `${VAR}` in a directive that expands
    /// it, an `IdentityAgent` whose value begins with `$` other than `$SSH_AUTH_SOCK`,
    /// an `Include` whose path holds a `${VAR}`, or an `Include` whose `~` (or the
    /// implicit `~/.ssh/` of a relative user `Include`) follows a `HOME` that is not the
    /// account home. Stable name `environment_reference`.
    EnvironmentReference,
}

impl UnresolvedReason {
    /// A stable `snake_case` name for the reason (`environment_reference`,
    /// `match_exec` …); [`UnresolvedReason::EnvUnset`] and
    /// [`UnresolvedReason::TokenUnavailable`] name the kind only, never the variable
    /// or the token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            UnresolvedReason::MatchExec => "match_exec",
            UnresolvedReason::MatchLocalNetwork => "match_localnetwork",
            UnresolvedReason::Canonicalization => "canonicalization",
            UnresolvedReason::IncludeUnreadable => "include_unreadable",
            UnresolvedReason::BoundExceeded => "bound_exceeded",
            UnresolvedReason::EnvUnset(_) => "env_unset",
            UnresolvedReason::TokenUnavailable(_) => "token_unavailable",
            UnresolvedReason::EnvironmentReference => "environment_reference",
        }
    }
}

/// An unresolved point with its location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Why.
    pub reason: UnresolvedReason,
    /// Where.
    pub span: Span,
}

/// A directive OpenSSH would refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    /// Where.
    pub span: Span,
    /// A stable `snake_case` reason (`unknown_keyword`, `bad_argument` …).
    pub reason: String,
}

/// A retired keyword ssh ignores (ADR-0007 §12.15 item 4): accepted, no effect on any
/// value, not invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignored {
    /// Where.
    pub span: Span,
    /// The retired keyword, in the table's lower-case spelling.
    pub keyword: &'static str,
    /// What ssh says about it. [`Obsolete::Unsupported`] is the case a doctor notes:
    /// ssh prints an "Unsupported option" error and carries on.
    pub kind: Obsolete,
}

/// The result of one evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evaluation {
    /// First-wins directives.
    pub values: BTreeMap<KnownKeyword, Resolved>,
    /// Accumulating directives, in order.
    pub accumulated: BTreeMap<KnownKeyword, Vec<Candidate>>,
    /// Everything that could not be evaluated.
    pub unresolved: Vec<Unresolved>,
    /// Everything OpenSSH would refuse.
    pub invalid: Vec<Invalid>,
    /// Retired keywords ssh accepts and ignores, in reading order, one entry per line
    /// (ADR-0007 §12.15 item 4). They have no effect on `values` or `accumulated`.
    pub ignored: Vec<Ignored>,
    /// The canonical path of every file the walk read, by the id its spans carry, so a
    /// caller can show `file:line` for a [`Span`] (ADR-0007 §3 item 3).
    pub files: BTreeMap<SourceId, PathBuf>,
}

impl Evaluation {
    /// The retired keywords ssh reports as unsupported (`Unsupported`): the ones a
    /// doctor notes, although the file still loads (ADR-0007 §12.15 item 4).
    pub fn unsupported(&self) -> impl Iterator<Item = &Ignored> {
        self.ignored
            .iter()
            .filter(|i| i.kind == Obsolete::Unsupported)
    }
}

/// Evaluate `query` over the tree rooted at `roots`, reading through `source`.
/// Executes nothing; see the module documentation.
///
/// The files are read by [`crate::include::walk`] (U1), so the evaluation, the
/// include bounds and U3's tree snapshot see one walk; this module is its visitor.
#[must_use]
pub fn evaluate(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    query: &Query,
    limits: &Limits,
) -> Evaluation {
    let mut w = Walker {
        source,
        query,
        first: BTreeMap::new(),
        proxy: Slot::Unset,
        acc: BTreeMap::new(),
        unresolved: Vec::new(),
        unresolved_seen: HashSet::new(),
        invalid: Vec::new(),
        invalid_seen: HashSet::new(),
        ignored: Vec::new(),
        ignored_seen: HashSet::new(),
        files: BTreeMap::new(),
        want_final: Tri::False,
        pass: Pass {
            is_final: false,
            ctx: Tri::True,
            host: Poss::one(query.host.clone()),
            canonicalizing: false,
        },
        frames: Vec::new(),
        visited: BTreeSet::new(),
    };
    include::walk(set, source, roots, limits, &mut w);
    if let Some(pass) = w.plan_final() {
        w.pass = pass;
        include::walk(set, source, roots, limits, &mut w);
    }
    // U1: OpenSSH does not skip a byte-order mark, so upstream clients refuse such a
    // file; whether a given client accepts one is observed per client (ADR-0007 §4).
    let visited: Vec<SourceId> = w.visited.iter().copied().collect();
    for id in visited {
        if set.file(id).is_some_and(|f| f.had_bom) {
            w.invalid(
                Span {
                    source: id,
                    line: 1,
                },
                "byte_order_mark",
            );
        }
    }
    w.finish()
}

// --- three-valued logic ---------------------------------------------------------------

/// A condition's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    False,
    Unknown,
    True,
}

impl Tri {
    fn of(b: bool) -> Self {
        if b { Tri::True } else { Tri::False }
    }

    fn and(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::True, Tri::True) => Tri::True,
            _ => Tri::Unknown,
        }
    }

    fn or(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::False, Tri::False) => Tri::False,
            _ => Tri::Unknown,
        }
    }

    fn not(self) -> Tri {
        match self {
            Tri::False => Tri::True,
            Tri::True => Tri::False,
            Tri::Unknown => Tri::Unknown,
        }
    }
}

/// The strings a value may take: some known ones, and possibly an unknown one.
#[derive(Debug, Clone, Default)]
struct Poss {
    vals: Vec<String>,
    unknown: bool,
}

impl Poss {
    fn one(s: String) -> Self {
        Self {
            vals: vec![s],
            unknown: false,
        }
    }

    fn unknown() -> Self {
        Self {
            vals: Vec::new(),
            unknown: true,
        }
    }

    fn add(&mut self, v: Option<String>) {
        match v {
            Some(s) => {
                if !self.vals.contains(&s) {
                    self.vals.push(s);
                }
            }
            None => self.unknown = true,
        }
    }

    /// The only possible value, when there is exactly one.
    fn single(&self) -> Option<&str> {
        match (self.unknown, self.vals.as_slice()) {
            (false, [one]) => Some(one),
            _ => None,
        }
    }

    /// Evaluate a predicate over every possibility; `on_unknown` is the predicate's
    /// value for an unknown string.
    fn test(&self, f: impl Fn(&str) -> bool, on_unknown: Tri) -> Tri {
        let mut acc: Option<Tri> = None;
        let mut push = |t: Tri| {
            acc = Some(match acc {
                None => t,
                Some(a) if a == t => a,
                Some(_) => Tri::Unknown,
            });
        };
        for v in &self.vals {
            push(Tri::of(f(v)));
        }
        if self.unknown {
            push(on_unknown);
        }
        acc.unwrap_or(Tri::Unknown)
    }
}

// --- OpenSSH pattern matching ---------------------------------------------------------

/// OpenSSH `match_pattern`: `*` matches any run, `?` exactly one byte; bytewise.
pub(crate) fn match_pattern(s: &str, pattern: &str) -> bool {
    let (s, p) = (s.as_bytes(), pattern.as_bytes());
    let (mut si, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

/// OpenSSH `match_pattern_list`: a comma-separated list, `!` negating an item.
/// `1` for a positive match, `-1` for a negated match (which wins), `0` otherwise.
/// With `dolower` the patterns are lower-cased (ASCII). An item of 1023 bytes or more
/// fails the whole list, as in OpenSSH.
pub(crate) fn match_pattern_list(s: &str, list: &str, dolower: bool) -> i8 {
    let b = list.as_bytes();
    let mut i = 0;
    let mut got = false;
    while i < b.len() {
        let negated = b[i] == b'!';
        if negated {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i] != b',' {
            i += 1;
        }
        if i - start >= 1023 {
            return 0;
        }
        let item = &list[start..i];
        if i < b.len() {
            i += 1; // the comma
        }
        let item = if dolower {
            item.to_ascii_lowercase()
        } else {
            item.to_owned()
        };
        if match_pattern(s, &item) {
            if negated {
                return -1;
            }
            got = true;
        }
    }
    i8::from(got)
}

/// A pattern of only `*`: matches every string.
fn all_star(p: &str) -> bool {
    !p.is_empty() && p.bytes().all(|c| c == b'*')
}

/// A `Host` line against one name: any negated match makes it false.
fn host_patterns_match(host: &str, pats: &[(bool, &str)]) -> bool {
    let mut any = false;
    for (neg, p) in pats {
        if match_pattern(host, p) {
            if *neg {
                return false;
            }
            any = true;
        }
    }
    any
}

/// A `Host` line against an unknown name.
fn host_patterns_unknown(pats: &[(bool, &str)]) -> Tri {
    if pats.iter().any(|(n, p)| *n && all_star(p)) {
        Tri::False
    } else if pats.iter().any(|(n, _)| *n) {
        Tri::Unknown
    } else if pats.iter().any(|(_, p)| all_star(p)) {
        Tri::True
    } else {
        Tri::Unknown
    }
}

// --- expansion helpers ----------------------------------------------------------------

/// The names of every `${NAME}` in `s`.
fn env_names(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        let after = &rest[i + 2..];
        let Some(close) = after.find('}') else {
            break;
        };
        out.push(&after[..close]);
        rest = &after[close + 1..];
    }
    out
}

/// `HostName` accepts only `%%` and `%h` (S01 TOKENS).
fn hostname_tokens_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if !matches!(b.get(i + 1), Some(b'%' | b'h')) {
                return false;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    true
}

/// `percent_expand(hostname, "h", host)`.
fn expand_h(hostname: &str, host: &str) -> Option<String> {
    let mut out = String::with_capacity(hostname.len());
    let mut chars = hostname.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('%') => out.push('%'),
                Some('h') => out.push_str(host),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// The retired keyword `spelling` names, in the table's spelling, with what ssh does
/// with it ([`crate::directive::obsolete`]).
fn retired(spelling: &str) -> Option<(&'static str, Obsolete)> {
    let kind = obsolete(spelling)?;
    crate::directive::OBSOLETE
        .iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(spelling))
        .map(|(s, _)| (*s, kind))
}

// --- the walker -----------------------------------------------------------------------

/// A first-wins slot.
#[derive(Debug, Clone)]
enum Slot<T> {
    Unset,
    Det(T),
    /// One of `cands`, or still unset when `open`.
    Undet {
        cands: Vec<T>,
        open: bool,
    },
}

impl<T: PartialEq> Slot<T> {
    fn apply(&mut self, v: T, c: Tri) {
        if c == Tri::False {
            return;
        }
        match self {
            Slot::Det(_) => {}
            Slot::Unset => {
                *self = if c == Tri::True {
                    Slot::Det(v)
                } else {
                    Slot::Undet {
                        cands: vec![v],
                        open: true,
                    }
                };
            }
            Slot::Undet { cands, open } => {
                if *open {
                    // The same value again (the final pass re-reads every line): one
                    // candidate is enough.
                    if !cands.contains(&v) {
                        cands.push(v);
                    }
                    if c == Tri::True {
                        *open = false;
                    }
                }
            }
        }
    }

    /// The possible strings, with `default` for "unset" and `f` for each value
    /// (`None`: unknown).
    fn poss(&self, default: &str, f: impl Fn(&T) -> Option<String>) -> Poss {
        let mut p = Poss::default();
        match self {
            Slot::Unset => p.add(Some(default.to_owned())),
            Slot::Det(v) => p.add(f(v)),
            Slot::Undet { cands, open } => {
                for v in cands {
                    p.add(f(v));
                }
                if *open {
                    p.add(Some(default.to_owned()));
                }
            }
        }
        p
    }

    fn spans(&self, span: impl Fn(&T) -> Span) -> Vec<Span> {
        match self {
            Slot::Unset => Vec::new(),
            Slot::Det(v) => vec![span(v)],
            Slot::Undet { cands, .. } => cands.iter().map(span).collect(),
        }
    }
}

fn first_arg(v: &Value) -> Option<String> {
    v.args.first().cloned()
}

/// The condition lines are read under.
#[derive(Debug, Clone)]
struct Ctx {
    cond: Tri,
    /// The innermost `Host`/`Match` line, if any.
    span: Option<Span>,
}

/// One reading pass.
#[derive(Debug, Clone)]
struct Pass {
    is_final: bool,
    /// The pass's own condition: true, or unknown for a final pass that may not run.
    ctx: Tri,
    /// What `Host` lines (and, in the final pass, `Match host`) match against.
    host: Poss,
    /// The final pass's name is unknown because of canonicalization.
    canonicalizing: bool,
}

/// One file being read: the condition it was included under, and its current
/// section's condition (restored for the including file when it ends, ADR-0007 §3).
#[derive(Debug, Clone)]
struct Frame {
    ctx: Ctx,
    cur: Ctx,
    /// The source role of the file being read.
    role: SourceRole,
    /// The condition the matches of this file's current `Include` argument are read
    /// under, on top of the section's: unknown when the argument reads the environment
    /// (ADR-0007 §12.16 item 1), so the runtime's file is only one of the files a
    /// later `ssh` may read.
    include_cond: Tri,
}

struct Walker<'a> {
    source: &'a dyn ConfigSource,
    query: &'a Query,
    first: BTreeMap<KnownKeyword, Slot<Value>>,
    proxy: Slot<(KnownKeyword, Value)>,
    acc: BTreeMap<KnownKeyword, Vec<Candidate>>,
    unresolved: Vec<Unresolved>,
    unresolved_seen: HashSet<(UnresolvedReason, Span)>,
    invalid: Vec<Invalid>,
    invalid_seen: HashSet<(Span, String)>,
    ignored: Vec<Ignored>,
    ignored_seen: HashSet<Span>,
    files: BTreeMap<SourceId, PathBuf>,
    want_final: Tri,
    pass: Pass,
    frames: Vec<Frame>,
    visited: BTreeSet<SourceId>,
}

impl IncludeVisitor for Walker<'_> {
    fn token(&self, token: char) -> Option<String> {
        let single = |p: Poss| p.single().map(str::to_owned);
        match token {
            'd' => self.source.account_home().to_str().map(str::to_owned),
            'u' => Some(self.query.local_user.clone()),
            'n' => Some(self.query.host.clone()),
            'h' => single(self.match_host_poss()),
            'p' => single(self.slot_poss(KnownKeyword::Port, "22")),
            'r' => single(self.user_poss()),
            'k' => single(self.slot_poss(KnownKeyword::HostKeyAlias, &self.query.host)),
            'j' => single(self.jump_poss()),
            // %C, %i, %L, %l: not known statically.
            _ => None,
        }
    }

    fn enter(&mut self, visit: &Visit) {
        self.visited.insert(visit.source);
        self.files
            .entry(visit.source)
            .or_insert_with(|| visit.canonical.clone());
        let ctx = match self.frames.last() {
            Some(parent) if visit.depth > 0 => Ctx {
                cond: parent.cur.cond.and(parent.include_cond),
                span: parent.cur.span,
            },
            _ => Ctx {
                cond: self.pass.ctx,
                span: None,
            },
        };
        self.frames.push(Frame {
            cur: ctx.clone(),
            ctx,
            role: visit.role,
            include_cond: Tri::True,
        });
    }

    fn line(&mut self, _visit: &Visit, line: &Line) {
        match line {
            Line::Blank(_) | Line::Comment(_) => {}
            Line::Invalid { span, .. } => self.invalid(*span, "lex_error"),
            Line::Directive(d) => self.directive(d),
        }
    }

    fn include(&mut self, visit: &Visit, span: Span, arg: &IncludeArg) {
        let cur = self.frames.last().map(|f| f.cur.clone());
        let (cond_span, cond) = cur.map_or((None, Tri::Unknown), |c| (c.span, c.cond));
        // ADR-0007 §12.16 item 1: a path that reads a variable names the runtime's
        // file, which a later ssh may not read. Its matches are read under an unknown
        // condition, and another file may set anything (an opaque point).
        let reads_env = !env_names(&arg.written).is_empty();
        if let Some(f) = self.frames.last_mut() {
            f.include_cond = if reads_env { Tri::Unknown } else { Tri::True };
        }
        if reads_env {
            self.unresolve(UnresolvedReason::EnvironmentReference, span);
        }
        let error = match &arg.matches {
            Ok(_) => {
                if reads_env {
                    self.opaque(span, cond_span, cond, visit.role);
                }
                return;
            }
            Err(error) => error,
        };
        // Whether the file ssh would read could add values: an argument ssh expands
        // fine (an unknown token, an unset variable, a `~` under another HOME) under a
        // false condition is read "parse only" and adds none; an argument or glob ssh
        // refuses fails the whole configuration, so nothing is known (fail closed).
        let applies = match error {
            ArgError::EnvUnset(name) => {
                self.unresolve(UnresolvedReason::EnvUnset(name.clone()), span);
                self.unresolve(UnresolvedReason::IncludeUnreadable, span);
                cond
            }
            ArgError::EnvironmentReference => {
                // ADR-0007 §12.17 item 9: `~` follows a HOME that is not the account
                // home, so which file ssh reads is not known; the tree is not fully
                // readable for the probes either.
                self.unresolve(UnresolvedReason::EnvironmentReference, span);
                self.unresolve(UnresolvedReason::IncludeUnreadable, span);
                cond
            }
            ArgError::TokenUnavailable(c) => {
                self.unresolve(UnresolvedReason::TokenUnavailable(*c), span);
                cond
            }
            ArgError::Invalid(why) => {
                self.invalid(span, why.as_str());
                self.unresolve(UnresolvedReason::IncludeUnreadable, span);
                Tri::Unknown
            }
            ArgError::Glob(e) => {
                self.unresolve(include_reason(e), span);
                Tri::Unknown
            }
        };
        self.opaque(span, cond_span, applies, visit.role);
    }

    fn include_failed(&mut self, visit: &Visit, span: Span, _path: &Path, error: &IncludeError) {
        if matches!(error, IncludeError::Unreadable(SourceError::NotFound)) {
            // Gone between the glob and the read: OpenSSH skips it too.
            return;
        }
        self.unresolve(include_reason(error), span);
        let cond_span = self.frames.last().and_then(|f| f.cur.span);
        // ssh fails on a file it cannot read, wherever it is: nothing is known.
        self.opaque(span, cond_span, Tri::Unknown, visit.role);
    }

    fn leave(&mut self, _visit: &Visit) {
        self.frames.pop();
    }

    fn root_failed(&mut self, origin: Origin, _path: &Path, error: &IncludeError) {
        if matches!(error, IncludeError::Unreadable(SourceError::NotFound)) {
            return; // no such configuration file
        }
        let span = match origin {
            Origin::User => USER_ROOT_SPAN,
            Origin::System => SYSTEM_ROOT_SPAN,
        };
        self.unresolve(include_reason(error), span);
        self.opaque(span, None, Tri::Unknown, SourceRole::of_origin(origin));
    }
}

/// How an include failure is recorded: a bound of `Limits` or a cycle (OpenSSH
/// recurses to its depth limit and fails) is `BoundExceeded`; anything else is
/// `IncludeUnreadable`.
fn include_reason(error: &IncludeError) -> UnresolvedReason {
    if error.is_bound() || matches!(error, IncludeError::Cycle) {
        UnresolvedReason::BoundExceeded
    } else {
        UnresolvedReason::IncludeUnreadable
    }
}

impl Walker<'_> {
    fn unresolve(&mut self, reason: UnresolvedReason, span: Span) {
        if self.unresolved_seen.insert((reason.clone(), span)) {
            self.unresolved.push(Unresolved { reason, span });
        }
    }

    fn invalid(&mut self, span: Span, reason: &str) {
        if self.invalid_seen.insert((span, reason.to_owned())) {
            self.invalid.push(Invalid {
                span,
                reason: reason.to_owned(),
            });
        }
    }

    fn directive(&mut self, d: &Directive) {
        let Some(frame) = self.frames.last().cloned() else {
            return;
        };
        let (ctx, cur, role) = (frame.ctx, frame.cur, frame.role);
        match &d.keyword {
            Keyword::Unreadable => {
                // Not UTF-8: it may be any directive, so nothing is guessed about it.
                // As a value it applies under the current condition; as a `Host` or
                // `Match` line it would start a section whose condition is unknown,
                // so the lines after it are read under either condition.
                self.invalid(d.span, "unreadable_line");
                self.opaque(d.span, cur.span, cur.cond, role);
                let as_section = ctx.cond.and(Tri::Unknown);
                if let Some(f) = self.frames.last_mut()
                    && f.cur.cond != as_section
                {
                    f.cur = Ctx {
                        cond: Tri::Unknown,
                        span: Some(d.span),
                    };
                }
            }
            Keyword::Unknown(name) => {
                // A retired keyword is in ssh's keyword table: it is neither unknown
                // nor covered by `IgnoreUnknown`, and it changes nothing (ADR-0007
                // §12.15 item 4). ssh reports it wherever the line is, so a section
                // that does not apply does not hide it.
                if let Some((keyword, kind)) = retired(name) {
                    if self.ignored_seen.insert(d.span) {
                        self.ignored.push(Ignored {
                            span: d.span,
                            keyword,
                            kind,
                        });
                    }
                } else if self.ignored(name) != Tri::True {
                    self.invalid(d.span, "unknown_keyword");
                }
            }
            Keyword::Known(kw) => {
                let kw = *kw;
                match class(kw) {
                    DirectiveClass::Section => {
                        let m = if kw == KnownKeyword::Host {
                            self.host_line(d, ctx.cond)
                        } else {
                            self.match_line(d)
                        };
                        if let Some(f) = self.frames.last_mut() {
                            f.cur = Ctx {
                                cond: ctx.cond.and(m),
                                span: Some(d.span),
                            };
                        }
                    }
                    // `include::walk` reads the files; only the line itself is checked.
                    DirectiveClass::Include => {
                        if d.args.is_empty() {
                            self.invalid(d.span, "missing_argument");
                        }
                    }
                    DirectiveClass::Accumulates => self.accumulate(kw, d, &cur, role),
                    DirectiveClass::FirstWins
                    | DirectiveClass::Executes
                    | DirectiveClass::Other => {
                        self.first_wins(kw, d, &cur, role);
                    }
                }
            }
        }
    }

    /// Whether `IgnoreUnknown` (as obtained so far) covers `name`.
    fn ignored(&self, name: &str) -> Tri {
        let lower = name.to_ascii_lowercase();
        match self.first.get(&KnownKeyword::IgnoreUnknown) {
            None => Tri::False,
            Some(slot) => {
                // `\u{0}` stands for "unset": no pattern list ignores nothing.
                slot.poss("\u{0}", first_arg).test(
                    |list| list != "\u{0}" && match_pattern_list(&lower, list, true) == 1,
                    Tri::Unknown,
                )
            }
        }
    }

    // --- sections ---------------------------------------------------------------------

    fn host_line(&mut self, d: &Directive, ctx_cond: Tri) -> Tri {
        if d.args.is_empty() || d.args.iter().any(String::is_empty) {
            self.invalid(d.span, "missing_argument");
            return Tri::Unknown;
        }
        if ctx_cond == Tri::False {
            // OpenSSH reads such a file "parse only": patterns are not matched.
            return Tri::False;
        }
        let pats: Vec<(bool, &str)> = d
            .args
            .iter()
            .map(|a| match a.strip_prefix('!') {
                Some(p) => (true, p),
                None => (false, a.as_str()),
            })
            .collect();
        let r = self.pass.host.test(
            |h| host_patterns_match(h, &pats),
            host_patterns_unknown(&pats),
        );
        if r == Tri::Unknown && self.pass.host.unknown && self.pass.canonicalizing {
            self.unresolve(UnresolvedReason::Canonicalization, d.span);
        }
        r
    }

    fn bad_match(&mut self, d: &Directive) -> Tri {
        self.invalid(d.span, "bad_match_condition");
        Tri::Unknown
    }

    fn match_line(&mut self, d: &Directive) -> Tri {
        let args = &d.args;
        if args.is_empty() {
            return self.bad_match(d);
        }
        let mut result = Tri::True;
        let mut i = 0;
        while i < args.len() {
            let raw = args[i].as_str();
            i += 1;
            let (neg, attr) = match raw.strip_prefix('!') {
                Some(a) => (true, a),
                None => (false, raw),
            };
            let lower = attr.to_ascii_lowercase();
            let r = match lower.as_str() {
                "all" => {
                    let ok = args.len() == 1
                        || (args.len() == 2
                            && i == 2
                            && matches!(
                                args[0].to_ascii_lowercase().as_str(),
                                "canonical" | "final"
                            ));
                    if !ok {
                        return self.bad_match(d);
                    }
                    Tri::True
                }
                "canonical" | "final" => {
                    if lower == "final" && !neg && !self.pass.is_final {
                        self.want_final = Tri::True;
                    }
                    Tri::of(self.pass.is_final)
                }
                _ => {
                    let Some(arg) = args.get(i).map(String::as_str) else {
                        return self.bad_match(d);
                    };
                    i += 1;
                    match lower.as_str() {
                        "host" => {
                            let hosts = self.match_host_poss();
                            let r = hosts.test(
                                |h| match_pattern_list(&h.to_ascii_lowercase(), arg, true) == 1,
                                Tri::Unknown,
                            );
                            if r == Tri::Unknown && hosts.unknown && self.pass.canonicalizing {
                                self.unresolve(UnresolvedReason::Canonicalization, d.span);
                            }
                            r
                        }
                        "originalhost" => Tri::of(
                            match_pattern_list(&self.query.host.to_ascii_lowercase(), arg, true)
                                == 1,
                        ),
                        "user" => self
                            .user_poss()
                            .test(|u| match_pattern_list(u, arg, false) == 1, Tri::Unknown),
                        "localuser" => {
                            Tri::of(match_pattern_list(&self.query.local_user, arg, false) == 1)
                        }
                        "localnetwork" => {
                            self.unresolve(UnresolvedReason::MatchLocalNetwork, d.span);
                            Tri::Unknown
                        }
                        "tagged" => self
                            .slot_poss(KnownKeyword::Tag, "")
                            .test(|t| match_pattern_list(t, arg, false) == 1, Tri::Unknown),
                        "command" => self
                            .command_poss()
                            .test(|c| match_pattern_list(c, arg, false) == 1, Tri::Unknown),
                        "sessiontype" => match self.session_type() {
                            Some(t) => Tri::of(match_pattern_list(t, arg, false) == 1),
                            None => Tri::Unknown,
                        },
                        "version" => Tri::of(match_pattern_list(&self.version(), arg, false) == 1),
                        "exec" => {
                            if result == Tri::False {
                                // OpenSSH skips the command after a failed criterion.
                                Tri::False
                            } else {
                                self.unresolve(UnresolvedReason::MatchExec, d.span);
                                Tri::Unknown
                            }
                        }
                        _ => return self.bad_match(d),
                    }
                }
            };
            result = result.and(if neg { r.not() } else { r });
        }
        result
    }

    // --- values the conditions read ---------------------------------------------------

    fn slot_poss(&self, kw: KnownKeyword, default: &str) -> Poss {
        match self.first.get(&kw) {
            None => Poss::one(default.to_owned()),
            Some(slot) => slot.poss(default, first_arg),
        }
    }

    /// What `Match host` compares with: in the first pass the `HostName` obtained so
    /// far with `%h` expanded (the typed name when unset); in the final pass the
    /// pass's name.
    fn match_host_poss(&self) -> Poss {
        if self.pass.is_final {
            return self.pass.host.clone();
        }
        let host = self.query.host.as_str();
        match self.first.get(&KnownKeyword::Hostname) {
            None => Poss::one(host.to_owned()),
            Some(slot) => slot.poss(host, |v| v.args.first().and_then(|a| expand_h(a, host))),
        }
    }

    fn user_poss(&self) -> Poss {
        match &self.query.user {
            Some(u) => Poss::one(u.clone()),
            None => self.slot_poss(KnownKeyword::User, &self.query.local_user),
        }
    }

    fn command_poss(&self) -> Poss {
        match &self.query.invocation {
            Invocation::Shell => Poss::one(String::new()),
            Invocation::Exec(Some(c)) => Poss::one(c.clone()),
            Invocation::Exec(None) => Poss::unknown(),
            Invocation::Subsystem(s) => Poss::one(s.clone()),
        }
    }

    /// What `Match sessiontype` compares with (ADR-0007 §12.16 item 4): a `SessionType`
    /// already in force in the pass decides (`none`, `subsystem`; `default` leaves it
    /// to the invocation); otherwise the invocation does. `None`, so the condition is
    /// unknown, when the in-force value is itself undetermined or not one ssh accepts.
    /// (A subsystem invocation's `-s` comes first, so no `SessionType` is ever in force
    /// for it; see `settable`.)
    fn session_type(&self) -> Option<&'static str> {
        let by_invocation = match self.query.invocation {
            Invocation::Shell => "shell",
            Invocation::Exec(_) => "exec",
            Invocation::Subsystem(_) => "subsystem",
        };
        match self.first.get(&KnownKeyword::SessionType) {
            None | Some(Slot::Unset) => Some(by_invocation),
            Some(Slot::Det(v)) => match v.args.first().map(|a| a.to_ascii_lowercase()) {
                Some(a) if a == "none" => Some("none"),
                Some(a) if a == "subsystem" => Some("subsystem"),
                Some(a) if a == "default" => Some(by_invocation),
                _ => None,
            },
            Some(Slot::Undet { .. }) => None,
        }
    }

    fn version(&self) -> String {
        let v = self.query.client_version;
        match v.portable {
            Some(p) => format!("OpenSSH_{}.{}p{p}", v.major, v.minor),
            None => format!("OpenSSH_{}.{}", v.major, v.minor),
        }
    }

    fn jump_poss(&self) -> Poss {
        let f = |(kw, v): &(KnownKeyword, Value)| {
            if *kw == KnownKeyword::ProxyJump {
                v.args.first().cloned()
            } else {
                Some(String::new())
            }
        };
        self.proxy.poss("", f)
    }

    // --- values -----------------------------------------------------------------------

    /// Whether the directive reads the environment (ADR-0007 §12.16 item 1): a
    /// `${VAR}` in a directive that expands it, or an `IdentityAgent` whose value
    /// begins with `$` other than `$SSH_AUTH_SOCK` (ssh then reads the socket from
    /// that variable). The runtime's environment is not the environment of a later
    /// ssh, so whether the variable is set here or not, the value is not determined:
    /// it applies under an unknown condition, reason `EnvironmentReference` (an unset
    /// variable, which makes ssh ignore the setting here, F7, is also `EnvUnset`). The
    /// default agent's literal forms, `SSH_AUTH_SOCK` and `$SSH_AUTH_SOCK`, read no
    /// configured variable and stay determined.
    fn env_check(&mut self, kw: KnownKeyword, d: &Directive) -> Tri {
        let mut t = Tri::True;
        if expands_env(kw) {
            let names: Vec<String> = d
                .args
                .iter()
                .flat_map(|a| env_names(a))
                .map(str::to_owned)
                .collect();
            if !names.is_empty() {
                self.unresolve(UnresolvedReason::EnvironmentReference, d.span);
                t = Tri::Unknown;
            }
            for name in names {
                if self.source.env(&name).is_none() {
                    self.unresolve(UnresolvedReason::EnvUnset(name), d.span);
                }
            }
        }
        if kw == KnownKeyword::IdentityAgent
            && d.args
                .first()
                .is_some_and(|a| a.starts_with('$') && a != "$SSH_AUTH_SOCK")
        {
            self.unresolve(UnresolvedReason::EnvironmentReference, d.span);
            t = Tri::Unknown;
        }
        t
    }

    /// Whether a value of `kw` can still be obtained in this pass. The command line is
    /// read first (F1): `-l` sets `User`, and the `-s` of a subsystem invocation sets
    /// the session type, so a `SessionType` line never takes effect then (observed
    /// with `ssh -G -s` on OpenSSH_10.3p1).
    fn settable(&self, kw: KnownKeyword) -> bool {
        !(kw == KnownKeyword::User && self.query.user.is_some()
            || kw == KnownKeyword::Hostname && self.pass.is_final
            || kw == KnownKeyword::SessionType
                && matches!(self.query.invocation, Invocation::Subsystem(_)))
    }

    fn first_wins(&mut self, kw: KnownKeyword, d: &Directive, cur: &Ctx, role: SourceRole) {
        if d.args.is_empty() {
            self.invalid(d.span, "missing_argument");
            return;
        }
        if kw == KnownKeyword::Port
            && d.args[0].bytes().all(|b| b.is_ascii_digit())
            && !matches!(d.args[0].parse::<u32>(), Ok(1..=65535))
        {
            self.invalid(d.span, "bad_port");
            return;
        }
        if kw == KnownKeyword::Hostname && !hostname_tokens_ok(&d.args[0]) {
            self.invalid(d.span, "bad_token");
            return;
        }
        if cur.cond == Tri::False || !self.settable(kw) {
            return;
        }
        let c = cur.cond.and(self.env_check(kw, d));
        let v = Value {
            args: d.args.clone(),
            span: d.span,
            condition: cur.span,
            role,
            raw: d.raw.clone(),
        };
        self.apply_first(kw, v, c);
    }

    fn apply_first(&mut self, kw: KnownKeyword, v: Value, c: Tri) {
        if matches!(kw, KnownKeyword::ProxyJump | KnownKeyword::ProxyCommand) {
            self.proxy.apply((kw, v), c);
        } else {
            self.first.entry(kw).or_insert(Slot::Unset).apply(v, c);
        }
    }

    fn accumulate(&mut self, kw: KnownKeyword, d: &Directive, cur: &Ctx, role: SourceRole) {
        if d.args.is_empty() {
            self.invalid(d.span, "missing_argument");
            return;
        }
        if cur.cond == Tri::False {
            return;
        }
        let c = cur.cond.and(self.env_check(kw, d));
        let v = Value {
            args: d.args.clone(),
            span: d.span,
            condition: cur.span,
            role,
            raw: d.raw.clone(),
        };
        self.push_candidate(kw, v, c == Tri::True);
    }

    fn push_candidate(&mut self, kw: KnownKeyword, v: Value, determined: bool) {
        let dedupe_args = matches!(
            kw,
            KnownKeyword::IdentityFile | KnownKeyword::CertificateFile
        );
        let list = self.acc.entry(kw).or_default();
        // A determined entry with the same arguments (or the same line, re-read in the
        // final pass) is always earlier in the list: ssh never adds this one.
        if list.iter().any(|e| {
            e.determined && (e.value.span == v.span || dedupe_args && e.value.args == v.args)
        }) {
            return;
        }
        // The same line again, still undetermined: nothing new.
        if !determined && list.iter().any(|e| e.value.span == v.span) {
            return;
        }
        list.push(Candidate {
            value: v,
            determined,
        });
    }

    /// A point whose content is unknown. Unless `cond` is false, every directive that
    /// may still be unset may get a value here (under an unknown condition); it may
    /// hold a `Match final` in any case.
    fn opaque(&mut self, span: Span, condition: Option<Span>, cond: Tri, role: SourceRole) {
        if !self.pass.is_final {
            self.want_final = self.want_final.or(Tri::Unknown);
        }
        if cond == Tri::False {
            return;
        }
        let v = Value {
            args: Vec::new(),
            span,
            condition,
            role,
            raw: None,
        };
        for &kw in KnownKeyword::ALL {
            match class(kw) {
                DirectiveClass::Section | DirectiveClass::Include => {}
                DirectiveClass::Accumulates => self.push_candidate(kw, v.clone(), false),
                DirectiveClass::FirstWins | DirectiveClass::Executes | DirectiveClass::Other => {
                    if self.settable(kw) {
                        self.apply_first(kw, v.clone(), Tri::Unknown);
                    }
                }
            }
        }
    }

    // --- the final pass ---------------------------------------------------------------

    fn plan_final(&mut self) -> Option<Pass> {
        let canon_poss = self
            .first
            .get(&KnownKeyword::CanonicalizeHostname)
            .map_or_else(
                || Poss::one("no".to_owned()),
                |s| s.poss("no", |v| v.args.first().map(|a| a.to_ascii_lowercase())),
            );
        let canon = canon_poss.test(|v| v != "no", Tri::Unknown);
        let happens = self.want_final.or(canon);
        if happens == Tri::False {
            return None;
        }
        let (host, canonicalizing) = if canon == Tri::False {
            let mut h = self.match_host_poss();
            for v in &mut h.vals {
                *v = v.to_ascii_lowercase();
            }
            (h, false)
        } else {
            let spans = self
                .first
                .get(&KnownKeyword::CanonicalizeHostname)
                .map(|s| s.spans(|v| v.span))
                .unwrap_or_default();
            for span in spans {
                self.unresolve(UnresolvedReason::Canonicalization, span);
            }
            (Poss::unknown(), true)
        };
        Some(Pass {
            is_final: true,
            ctx: happens,
            host,
            canonicalizing,
        })
    }

    fn finish(self) -> Evaluation {
        let mut values = BTreeMap::new();
        for (kw, slot) in self.first {
            match slot {
                Slot::Unset => {}
                Slot::Det(v) => {
                    values.insert(kw, Resolved::Determined(v));
                }
                Slot::Undet { cands, .. } => {
                    values.insert(kw, Resolved::Undetermined(cands));
                }
            }
        }
        match self.proxy {
            Slot::Unset => {}
            Slot::Det((kw, v)) => {
                values.insert(kw, Resolved::Determined(v));
            }
            Slot::Undet { cands, .. } => {
                for (kw, v) in cands {
                    match values
                        .entry(kw)
                        .or_insert_with(|| Resolved::Undetermined(Vec::new()))
                    {
                        Resolved::Undetermined(list) => list.push(v),
                        Resolved::Unset | Resolved::Determined(_) => {}
                    }
                }
            }
        }
        Evaluation {
            values,
            accumulated: self.acc,
            unresolved: self.unresolved,
            invalid: self.invalid,
            ignored: self.ignored,
            files: self.files,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn patterns_follow_openssh() {
        assert!(match_pattern("web1.example", "web*.example"));
        assert!(match_pattern("a", "?"));
        assert!(!match_pattern("ab", "?"));
        assert!(match_pattern("", "*"));
        assert!(match_pattern("abc", "a*c*"));
        assert!(!match_pattern("abc", "a*d"));
        assert_eq!(match_pattern_list("web1", "web*,!web1", false), -1);
        assert_eq!(match_pattern_list("web2", "web*,!web1", false), 1);
        assert_eq!(match_pattern_list("db", "web*", false), 0);
        assert_eq!(match_pattern_list("web", "WEB", true), 1);
        assert_eq!(match_pattern_list("web", "WEB", false), 0);
        assert_eq!(match_pattern_list("", "a,", false), 0);
    }

    #[test]
    fn three_valued_slot_keeps_every_candidate_that_may_apply() {
        let v = |n: u32| {
            Value::new(
                vec![n.to_string()],
                Span {
                    source: SourceId(0),
                    line: n,
                },
                None,
            )
        };
        let mut s = Slot::Unset;
        s.apply(v(1), Tri::Unknown);
        s.apply(v(2), Tri::False);
        s.apply(v(3), Tri::Unknown);
        s.apply(v(4), Tri::True);
        s.apply(v(5), Tri::True);
        match s {
            Slot::Undet { cands, open } => {
                assert!(!open);
                assert_eq!(
                    cands.iter().map(|c| c.span.line).collect::<Vec<_>>(),
                    vec![1, 3, 4]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn env_names_lists_every_variable() {
        assert_eq!(env_names("${A}x${B}"), vec!["A", "B"]);
        assert!(env_names("$A ${").is_empty());
    }
}
