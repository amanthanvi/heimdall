//! The static evaluator (m02-plan U2; ADR-0007 §3, F1–F10).
//!
//! It computes what OpenSSH would obtain for a host **without executing anything**.
//! Where the result depends on something it cannot know (a `Match exec`, the local
//! network, canonicalization, an unreadable include), the value is `Undetermined` with
//! every candidate, and the reason is recorded.

use std::collections::BTreeMap;

use crate::directive::KnownKeyword;
use crate::include::{ConfigSet, ConfigSource, Roots};
use crate::limits::Limits;
use crate::parse::Span;

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
}

/// Evaluate `query` over the tree rooted at `roots`, reading through `source`.
/// Executes nothing; see the module documentation.
#[must_use]
pub fn evaluate(
    set: &mut ConfigSet,
    source: &dyn ConfigSource,
    roots: &Roots,
    query: &Query,
    limits: &Limits,
) -> Evaluation {
    let _ = (set, source, roots, query, limits);
    todo!("M02-U2 eval::evaluate")
}
