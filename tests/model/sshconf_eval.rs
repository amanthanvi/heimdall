//! `heimdall-sshconf` static evaluation, relevant behaviour, identity selection and
//! rendering (M02-U2; m02-plan U2; ADR-0007 §3, §4, §6, F1–F10).
//!
//! Cargo test target `model_sshconf_eval` hosted by `heimdall-sshconf`. Pure: every
//! source is an in-memory `MemSource` (no file, process or socket). Nothing a
//! configuration names is ever run: the crate's only read port, `ConfigSource`, has no
//! method that runs anything, and the `Match exec` test wraps the source so that any
//! read or glob of a path the command names fails the test.
//!
//! Public-key fixtures are synthetic: a valid OpenSSH public-key *encoding* over a
//! fixed byte pattern, built at run time; no key pair exists for them. Canary values
//! are built at run time and only their absence is asserted.
//!
//! Properties use proptest with 256 cases, a fixed seed unless `PROPTEST_RNG_SEED` is
//! set, and failures persisted beside this file (`*.proptest-regressions`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heimdall_contract::provider::{
    Certainty, IdentitiesOnly, IdentityBacking, IdentityEntryKind, IdentityEntrySource,
    IdentitySelection,
};
use heimdall_sshconf::directive::KnownKeyword;
use heimdall_sshconf::edit::{IncludeBlock, plan_insert};
use heimdall_sshconf::eval::{
    Evaluation, Invocation, OpenSshVersion, Query, Resolved, UnresolvedReason, Value, evaluate,
};
use heimdall_sshconf::include::{
    ConfigSet, ConfigSource, MemEntry, MemSource, Roots, SourceBytes, SourceError,
};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::relevant::{
    Proxy, ProxyResolution, behavior_digest, behavior_state, diff, executing_constructs,
    identity_selection, identity_selection_with_spans, relevant, unreadable_includes,
};
use heimdall_sshconf::render::{
    AliasName, HostName, ManagedAlias, MarkerId, Newline, PathStyle, RenderError, RenderPath,
    render_git_include_block, render_git_managed, render_include_block, render_managed,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const HOME: &str = "/hm/home";
const USER_DIR: &str = "/hm/home/.ssh";
const SYSTEM_DIR: &str = "/hm/etc/ssh";
const USER_CONFIG: &str = "/hm/home/.ssh/config";
const SYSTEM_CONFIG: &str = "/hm/etc/ssh/ssh_config";
const MANAGED: &str = "/hm/home/.config/heimdall/ssh_config";
const MANAGED_REL: &str = "~/.config/heimdall/ssh_config";
const KEYS_REL: &str = "~/.config/heimdall/keys";
const KEYS: &str = "/hm/home/.config/heimdall/keys";
const MARKER: &str = "hm-0123456789abcdef";

fn config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5353_4843_4f4e_4632);
    }
    c
}

fn source() -> MemSource {
    MemSource::new(HOME, USER_DIR, SYSTEM_DIR)
}

fn user_roots() -> Roots {
    Roots {
        user: Some(PathBuf::from(USER_CONFIG)),
        system: Some(PathBuf::from(SYSTEM_CONFIG)),
    }
}

fn q(host: &str) -> Query {
    Query {
        host: host.to_owned(),
        user: None,
        local_user: "fixture".to_owned(),
        client_version: OpenSshVersion {
            major: 10,
            minor: 3,
            portable: Some(1),
        },
        invocation: Invocation::Shell,
    }
}

fn eval_src(src: &dyn ConfigSource, query: &Query) -> Evaluation {
    let mut set = ConfigSet::new();
    evaluate(&mut set, src, &user_roots(), query, &Limits::default())
}

fn eval_user(text: &str, host: &str) -> Evaluation {
    eval_src(&source().with_file(USER_CONFIG, text), &q(host))
}

fn det(ev: &Evaluation, k: KnownKeyword) -> Option<Vec<String>> {
    match ev.values.get(&k) {
        Some(Resolved::Determined(v)) => Some(v.args.clone()),
        _ => None,
    }
}

fn det1(ev: &Evaluation, k: KnownKeyword) -> Option<String> {
    det(ev, k).map(|a| a.join(" "))
}

fn undet(ev: &Evaluation, k: KnownKeyword) -> Option<Vec<String>> {
    match ev.values.get(&k) {
        Some(Resolved::Undetermined(vs)) => Some(vs.iter().map(|v| v.args.join(" ")).collect()),
        _ => None,
    }
}

fn unset(ev: &Evaluation, k: KnownKeyword) -> bool {
    matches!(ev.values.get(&k), None | Some(Resolved::Unset))
}

fn list(ev: &Evaluation, k: KnownKeyword) -> Vec<(String, bool)> {
    ev.accumulated
        .get(&k)
        .map(|l| {
            l.iter()
                .map(|c| (c.value.args.join(" "), c.determined))
                .collect()
        })
        .unwrap_or_default()
}

fn has_reason(ev: &Evaluation, r: &UnresolvedReason) -> bool {
    ev.unresolved.iter().any(|u| &u.reason == r)
}

// --- F1, F2, F3, F10 -------------------------------------------------------------------

#[test]
fn first_obtained_value_wins_including_across_include() {
    let src = source()
        .with_file(
            USER_CONFIG,
            "Include first.conf\nHost box\n    HostName from-user.example\n    User late\n",
        )
        .with_file(
            format!("{USER_DIR}/first.conf"),
            "Host box\n    User early\n    Port 2222\n",
        )
        .with_file(
            SYSTEM_CONFIG,
            "Host *\n    HostName system.example\n    Port 22\n    ForwardAgent no\n",
        );
    let ev = eval_src(&src, &q("box"));
    assert_eq!(det1(&ev, KnownKeyword::User).as_deref(), Some("early"));
    assert_eq!(det1(&ev, KnownKeyword::Port).as_deref(), Some("2222"));
    assert_eq!(
        det1(&ev, KnownKeyword::Hostname).as_deref(),
        Some("from-user.example")
    );
    // A directive only the system file sets still comes from it (F1 source order).
    assert_eq!(det1(&ev, KnownKeyword::ForwardAgent).as_deref(), Some("no"));
    assert!(ev.unresolved.is_empty() && ev.invalid.is_empty(), "{ev:?}");
}

#[test]
fn identity_and_certificate_files_accumulate_in_order() {
    let src = source()
        .with_file(
            USER_CONFIG,
            "Host box\n    IdentityFile ~/.ssh/k1\n    CertificateFile ~/.ssh/c1-cert.pub\n\
             Host *\n    IdentityFile ~/.ssh/k2\n    IdentityFile ~/.ssh/k1\n    CertificateFile ~/.ssh/c2-cert.pub\n",
        )
        .with_file(SYSTEM_CONFIG, "IdentityFile ~/.ssh/k3\n");
    let ev = eval_src(&src, &q("box"));
    assert_eq!(
        list(&ev, KnownKeyword::IdentityFile),
        vec![
            ("~/.ssh/k1".to_owned(), true),
            ("~/.ssh/k2".to_owned(), true),
            ("~/.ssh/k3".to_owned(), true),
        ],
        "in order, the repeated k1 dropped as ssh drops duplicates"
    );
    assert_eq!(
        list(&ev, KnownKeyword::CertificateFile),
        vec![
            ("~/.ssh/c1-cert.pub".to_owned(), true),
            ("~/.ssh/c2-cert.pub".to_owned(), true),
        ]
    );
    // For another host only the wildcard and system entries apply.
    let other = eval_src(&src, &q("other"));
    assert_eq!(
        list(&other, KnownKeyword::IdentityFile)
            .into_iter()
            .map(|(a, _)| a)
            .collect::<Vec<_>>(),
        vec!["~/.ssh/k2", "~/.ssh/k1", "~/.ssh/k3"]
    );
}

#[test]
fn proxyjump_competes_with_proxycommand() {
    let ev = eval_user(
        "Host box\n    ProxyCommand nc %h %p\nHost *\n    ProxyJump jump.example\n",
        "box",
    );
    assert!(unset(&ev, KnownKeyword::ProxyJump), "{ev:?}");
    match relevant(&ev).proxy {
        ProxyResolution::Determined(Proxy::Command(v)) => assert_eq!(v.args[0], "nc"),
        other => panic!("{other:?}"),
    }
    let ev = eval_user(
        "Host box\n    ProxyJump jump.example\nHost *\n    ProxyCommand nc %h %p\n",
        "box",
    );
    assert!(unset(&ev, KnownKeyword::ProxyCommand));
    assert!(matches!(
        relevant(&ev).proxy,
        ProxyResolution::Determined(Proxy::Jump(_))
    ));
    // `none` takes the slot too, so a later ProxyCommand never applies.
    let ev = eval_user(
        "Host box\n    ProxyJump none\nHost *\n    ProxyCommand nc %h %p\n",
        "box",
    );
    assert_eq!(
        relevant(&ev).proxy,
        ProxyResolution::Determined(Proxy::None)
    );
    assert!(executing_constructs(&ev).is_empty());
    // Behind `Match exec` the winner is undetermined, and the losing command stays a
    // candidate.
    let ev = eval_user(
        "Match exec \"probe-a\"\n    ProxyJump jump.example\nHost *\n    ProxyCommand nc %h %p\n",
        "box",
    );
    match relevant(&ev).proxy {
        ProxyResolution::Undetermined(ps) => {
            assert!(ps.iter().any(|p| matches!(p, Proxy::Jump(_))));
            assert!(ps.iter().any(|p| matches!(p, Proxy::Command(_))));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn include_inside_host_or_match_is_conditional() {
    let src = source()
        .with_file(USER_CONFIG, "Host other\n    Include part.conf\n")
        .with_file(format!("{USER_DIR}/part.conf"), "HostName p.example\n");
    assert!(unset(&eval_src(&src, &q("box")), KnownKeyword::Hostname));
    assert_eq!(
        det1(&eval_src(&src, &q("other")), KnownKeyword::Hostname).as_deref(),
        Some("p.example")
    );
    let src = source()
        .with_file(
            USER_CONFIG,
            "Match exec \"probe-b\"\n    Include part.conf\n",
        )
        .with_file(format!("{USER_DIR}/part.conf"), "HostName p.example\n");
    let ev = eval_src(&src, &q("box"));
    assert_eq!(
        undet(&ev, KnownKeyword::Hostname),
        Some(vec!["p.example".to_owned()])
    );
}

#[test]
fn include_restores_the_containing_files_section_state() {
    // ADR-0007 §3 [I]: after the included file, the containing file's section is in
    // force again, so a `Host` section that ends the included file does not capture
    // the lines below the Include. (Settled against real clients by U3.)
    let src = source()
        .with_file(
            USER_CONFIG,
            "Host box\n    Include part.conf\n    User after-include\n",
        )
        .with_file(
            format!("{USER_DIR}/part.conf"),
            "Host nomatch\n    User inside\n",
        );
    let ev = eval_src(&src, &q("box"));
    assert_eq!(
        det1(&ev, KnownKeyword::User).as_deref(),
        Some("after-include")
    );
    // The same shape as P: B at the top including a file whose last section is a
    // managed alias; the user's next line is top-level again.
    let src = source()
        .with_file(
            USER_CONFIG,
            format!("Include \"{MANAGED_REL}\"\nUser top-level\n"),
        )
        .with_file(MANAGED, "Host m1\n    HostName m1.example\n");
    assert_eq!(
        det1(&eval_src(&src, &q("box")), KnownKeyword::User).as_deref(),
        Some("top-level")
    );
}

/// A source that fails the test if anything touches a path a `Match exec` command
/// names (the command would create it). The trait has no way to run a command.
struct NeverRuns<'a> {
    inner: &'a MemSource,
    forbidden: &'a str,
}

impl ConfigSource for NeverRuns<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        assert!(!path.to_string_lossy().contains(self.forbidden));
        self.inner.read(path)
    }
    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        assert!(!pattern.to_string_lossy().contains(self.forbidden));
        self.inner.glob(pattern)
    }
    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }
    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }
    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }
    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }
}

#[test]
fn match_exec_is_undetermined_and_never_executed() {
    let inner = source().with_file(
        USER_CONFIG,
        "Match host box exec \"touch /hm/exec-ran-marker\"\n    HostName via-exec.example\n\
         Host *\n    HostName default.example\n",
    );
    let src = NeverRuns {
        inner: &inner,
        forbidden: "exec-ran-marker",
    };
    let ev = eval_src(&src, &q("box"));
    assert_eq!(
        undet(&ev, KnownKeyword::Hostname),
        Some(vec![
            "via-exec.example".to_owned(),
            "default.example".to_owned()
        ])
    );
    assert!(has_reason(&ev, &UnresolvedReason::MatchExec));
    assert_eq!(executing_constructs(&ev).len(), 1);
    assert!(!behavior_state(&relevant(&ev)).determined);
    // Only the two configuration files were read (the system file is absent).
    assert_eq!(inner.reads(), 2);
    // A failed earlier criterion skips the command, as OpenSSH does: decided false,
    // and nothing is recorded as executing.
    let ev = eval_user(
        "Match host other exec \"probe-c\"\n    HostName via-exec.example\n",
        "box",
    );
    assert!(unset(&ev, KnownKeyword::Hostname));
    assert!(executing_constructs(&ev).is_empty());
}

#[test]
fn match_final_and_canonical_with_canonicalize_hostname_no_and_yes() {
    // CanonicalizeHostname no (the default): `Match canonical` alone never matches,
    // because no final pass runs; a `Match final` asks for one, decided.
    let ev = eval_user("Match canonical\n    User canon\n", "box");
    assert!(unset(&ev, KnownKeyword::User), "{ev:?}");
    let ev = eval_user(
        "Match final\n    Port 2200\nHost box\n    HostName box.example\n",
        "box",
    );
    assert_eq!(det1(&ev, KnownKeyword::Port).as_deref(), Some("2200"));
    // In the final pass `Host` matches the substituted name, lower-cased.
    let ev = eval_user(
        "Host box\n    HostName Real.Example\nMatch final\nHost real.example\n    User by-final-host\n",
        "box",
    );
    assert_eq!(
        det1(&ev, KnownKeyword::User).as_deref(),
        Some("by-final-host")
    );
    assert!(behavior_state(&relevant(&ev)).determined);

    // CanonicalizeHostname yes: the final pass runs on a name that needs DNS.
    let ev = eval_user(
        "CanonicalizeHostname yes\nMatch canonical\n    Port 2201\nHost box.example\n    User canon\n",
        "box",
    );
    assert_eq!(det1(&ev, KnownKeyword::Port).as_deref(), Some("2201"));
    assert_eq!(
        undet(&ev, KnownKeyword::User),
        Some(vec!["canon".to_owned()])
    );
    assert!(has_reason(&ev, &UnresolvedReason::Canonicalization));
    // `Host *` still certainly matches the canonical name.
    let ev = eval_user(
        "CanonicalizeHostname yes\nMatch final\nHost *\n    User any\n",
        "box",
    );
    assert_eq!(det1(&ev, KnownKeyword::User).as_deref(), Some("any"));
}

#[test]
fn command_and_sessiontype_per_invocation() {
    let text = "Match sessiontype subsystem command sftp\n    User sftp-user\n\
                Match sessiontype shell\n    User shell-user\n\
                Match sessiontype exec command git-*\n    User git-user\n";
    let src = source().with_file(USER_CONFIG, text);
    let run = |inv: Invocation| {
        let mut query = q("box");
        query.invocation = inv;
        eval_src(&src, &query)
    };
    assert_eq!(
        det1(&run(Invocation::Shell), KnownKeyword::User).as_deref(),
        Some("shell-user")
    );
    assert_eq!(
        det1(
            &run(Invocation::Subsystem("sftp".into())),
            KnownKeyword::User
        )
        .as_deref(),
        Some("sftp-user")
    );
    assert_eq!(
        det1(
            &run(Invocation::Exec(Some("git-upload-pack 'repo'".into()))),
            KnownKeyword::User
        )
        .as_deref(),
        Some("git-user")
    );
    // An exec whose command is not known: `command` is undecided.
    assert_eq!(
        undet(&run(Invocation::Exec(None)), KnownKeyword::User),
        Some(vec!["git-user".to_owned()])
    );
}

#[test]
fn unknown_keyword_is_invalid_unless_ignore_unknown_covers_it() {
    let ev = eval_user("FrobnicateWidget yes\n", "box");
    assert_eq!(ev.invalid.len(), 1);
    assert_eq!(ev.invalid[0].reason, "unknown_keyword");
    let ev = eval_user("IgnoreUnknown Frob*,Other\nFrobnicateWidget yes\n", "box");
    assert!(ev.invalid.is_empty(), "{:?}", ev.invalid);
    // IgnoreUnknown is not applied to options before it.
    let ev = eval_user("FrobnicateWidget yes\nIgnoreUnknown Frob*\n", "box");
    assert_eq!(ev.invalid.len(), 1);
    // Even inside a section that does not apply, ssh rejects the keyword.
    let ev = eval_user("Host nomatch\n    FrobnicateWidget yes\n", "box");
    assert_eq!(ev.invalid.len(), 1);
}

#[test]
fn unreadable_include_makes_everything_after_it_undetermined_and_is_listed() {
    let src = source()
        .with_file(
            USER_CONFIG,
            "Host box\n    User decided\nInclude denied.conf fifo.conf\n",
        )
        .with_entry(format!("{USER_DIR}/denied.conf"), MemEntry::Denied)
        .with_entry(format!("{USER_DIR}/fifo.conf"), MemEntry::Fifo);
    let ev = eval_src(&src, &q("box"));
    // A value obtained before the include stays determined; anything still unset may
    // now come from the unreadable file.
    assert_eq!(det1(&ev, KnownKeyword::User).as_deref(), Some("decided"));
    assert!(undet(&ev, KnownKeyword::Hostname).is_some());
    assert!(has_reason(&ev, &UnresolvedReason::IncludeUnreadable));
    assert_eq!(unreadable_includes(&ev).len(), 1, "{:?}", ev.unresolved);
    assert!(!behavior_state(&relevant(&ev)).determined);
    // The opaque candidate may run commands too.
    assert!(!executing_constructs(&ev).is_empty());

    // A token that cannot be known statically in an Include path.
    let ev = eval_user("Include conf.d/%L.conf\n", "box");
    assert!(has_reason(&ev, &UnresolvedReason::TokenUnavailable('L')));
    assert_eq!(unreadable_includes(&ev).len(), 1);
    // An unset variable in an Include path: not fully readable either.
    let ev = eval_user("Include ${HM_UNSET_DIR}/x.conf\n", "box");
    assert!(has_reason(
        &ev,
        &UnresolvedReason::EnvUnset("HM_UNSET_DIR".into())
    ));
    assert!(!unreadable_includes(&ev).is_empty());
    // A missing literal include includes nothing and is not an error (OpenSSH).
    let ev = eval_user("Include missing.conf\nUser after\n", "box");
    assert!(ev.unresolved.is_empty());
    assert_eq!(det1(&ev, KnownKeyword::User).as_deref(), Some("after"));
}

#[test]
fn a_line_that_is_not_utf8_is_never_guessed() {
    // It may be `Host *` (so the next line applies) or a value (so it is one).
    let src = source().with_file(
        USER_CONFIG,
        &b"Host nomatch\nHost b\xF4x *\n    User maybe\nHostName after\n"[..],
    );
    let ev = eval_src(&src, &q("box"));
    assert!(ev.invalid.iter().any(|i| i.reason == "unreadable_line"));
    assert_eq!(
        undet(&ev, KnownKeyword::User),
        Some(vec!["maybe".to_owned()]),
        "the line after it may apply: {ev:?}"
    );
    assert!(!behavior_state(&relevant(&ev)).determined);
}

#[test]
fn an_include_ssh_reads_parse_only_adds_no_candidates_but_is_not_fully_readable() {
    let ev = eval_user(
        "Host nomatch\n    Include conf.d/%L.conf\nHost box\n    HostName decided.example\n",
        "box",
    );
    assert!(has_reason(&ev, &UnresolvedReason::TokenUnavailable('L')));
    assert_eq!(unreadable_includes(&ev).len(), 1);
    assert_eq!(
        det1(&ev, KnownKeyword::Hostname).as_deref(),
        Some("decided.example")
    );
    assert!(unset(&ev, KnownKeyword::User));
    // A file that cannot be read fails ssh wherever it is: nothing is known.
    let src = source()
        .with_file(
            USER_CONFIG,
            "Host nomatch\n    Include denied.conf\nHost box\n    HostName decided.example\n",
        )
        .with_entry(format!("{USER_DIR}/denied.conf"), MemEntry::Denied);
    let ev = eval_src(&src, &q("box"));
    assert!(undet(&ev, KnownKeyword::User).is_some());
}

#[test]
fn executing_constructs_lists_only_what_may_run() {
    let ev = eval_user(
        "Host box\n    ProxyCommand nc %h %p\n    KnownHostsCommand /bin/hosts %H\n\
         LocalCommand /bin/notify\n",
        "box",
    );
    // PermitLocalCommand is unset (no), so LocalCommand never runs.
    assert_eq!(executing_constructs(&ev).len(), 2);
    let ev = eval_user(
        "PermitLocalCommand yes\nLocalCommand /bin/notify\nHost nomatch\n    ProxyCommand nc\n",
        "box",
    );
    let spans = executing_constructs(&ev);
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0].line, 2);
}

// --- identity selection (M2-D01) --------------------------------------------------------

/// A synthetic OpenSSH public-key line (valid encoding, no key pair behind it).
fn synthetic_pub(seed: u8, comment: &str) -> String {
    let mut blob = Vec::new();
    blob.extend_from_slice(&11u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend((0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
    format!("ssh-ed25519 {} {comment}\n", b64(&blob))
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &b)| a | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn managed_alias(name: &str, host: &str, port: Option<u16>) -> ManagedAlias {
    ManagedAlias {
        alias: AliasName::parse(name).unwrap(),
        hostname: HostName::parse(host).unwrap(),
        port,
        user: "deploy".to_owned(),
        identity_agent: Some(RenderPath::unix(Path::new("/hm/run/agent.sock")).unwrap()),
        identity_files: vec![
            RenderPath::unix(Path::new(&format!("{KEYS_REL}/{name}.pub"))).unwrap(),
        ],
        identities_only: true,
    }
}

fn include_block(newline: Newline) -> IncludeBlock {
    let marker = MarkerId::parse(MARKER).unwrap();
    let bytes = render_include_block(
        &marker,
        &RenderPath::unix(Path::new(MANAGED_REL)).unwrap(),
        newline,
    );
    IncludeBlock { marker, bytes }
}

/// The tree after setup: B at the top of `user`, P rendered from `aliases`, and the
/// adopted public keys.
fn adopted_tree(user: &[u8], aliases: &[ManagedAlias]) -> MemSource {
    let plan = plan_insert(Some(user), &include_block(Newline::Lf)).unwrap();
    let mut src = source()
        .with_file(USER_CONFIG, plan.bytes)
        .with_file(MANAGED, render_managed(aliases, PathStyle::Unix).unwrap());
    for (i, a) in aliases.iter().enumerate() {
        src.insert(
            format!("{KEYS}/{}.pub", a.alias.as_str()),
            MemEntry::File(synthetic_pub(u8::try_from(i).unwrap(), "adopted").into_bytes()),
        );
    }
    src
}

fn adopted_path(alias: &str) -> PathBuf {
    PathBuf::from(format!("{KEYS}/{alias}.pub"))
}

#[test]
fn identity_selection_exclusive_only_for_adopted_key_alone() {
    let src = adopted_tree(
        b"Host other\n    IdentityFile ~/.ssh/other\n",
        &[managed_alias("m1", "m1.example", None)],
    );
    let ev = eval_src(&src, &q("m1"));
    let report = identity_selection(&ev, &adopted_path("m1"), &src);
    assert_eq!(report.selection, IdentitySelection::Exclusive, "{report:?}");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].source, IdentityEntrySource::Managed);
    assert_eq!(report.entries[0].backing, IdentityBacking::Agent);
    assert!(report.entries[0].fingerprint.is_some());
    assert_eq!(report.identities_only, IdentitiesOnly::DeterminedYes);

    // Without `IdentitiesOnly yes` the agent may offer every key it holds.
    let mut a = managed_alias("m1", "m1.example", None);
    a.identities_only = false;
    let src = adopted_tree(b"", &[a]);
    let ev = eval_src(&src, &q("m1"));
    assert_eq!(
        identity_selection(&ev, &adopted_path("m1"), &src).selection,
        IdentitySelection::NotExclusive
    );
}

#[test]
fn identity_selection_not_exclusive_with_inherited_identityfile_or_certificatefile() {
    for user in [
        &b"Host *\n    IdentityFile ~/.ssh/id_extra\n"[..],
        b"Host m*\n    IdentityFile ~/.ssh/id_extra\n",
        b"Host m1\n    CertificateFile ~/.ssh/c-cert.pub\n",
    ] {
        let src = adopted_tree(user, &[managed_alias("m1", "m1.example", None)]);
        let ev = eval_src(&src, &q("m1"));
        let (report, spans) = identity_selection_with_spans(&ev, &adopted_path("m1"), &src);
        assert_eq!(
            report.selection,
            IdentitySelection::NotExclusive,
            "{}",
            String::from_utf8_lossy(user)
        );
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.entries[0].source, IdentityEntrySource::Managed);
        assert_eq!(report.entries[1].source, IdentityEntrySource::User);
        assert_eq!(report.entries[1].certainty, Certainty::Determined);
        // Every configured entry carries its directive's span for file:line display.
        assert!(spans.iter().all(Option::is_some));
        assert_eq!(spans.len(), report.entries.len());
    }
}

#[test]
fn identity_selection_undetermined_behind_match_exec() {
    let src = adopted_tree(
        b"Match exec \"probe-d\"\n    IdentityFile ~/.ssh/maybe\n",
        &[managed_alias("m1", "m1.example", None)],
    );
    let ev = eval_src(&src, &q("m1"));
    let report = identity_selection(&ev, &adopted_path("m1"), &src);
    assert_eq!(report.selection, IdentitySelection::Undetermined);
    assert_eq!(report.entries[1].certainty, Certainty::Undetermined);
    // With a determined extra entry as well, it is certainly not exclusive.
    let src = adopted_tree(
        b"Match exec \"probe-d\"\n    IdentityFile ~/.ssh/maybe\nHost *\n    IdentityFile ~/.ssh/sure\n",
        &[managed_alias("m1", "m1.example", None)],
    );
    let ev = eval_src(&src, &q("m1"));
    assert_eq!(
        identity_selection(&ev, &adopted_path("m1"), &src).selection,
        IdentitySelection::NotExclusive
    );
}

/// Records every path read.
struct ReadLog<'a> {
    inner: &'a MemSource,
    reads: RefCell<Vec<String>>,
}

impl ConfigSource for ReadLog<'_> {
    fn read(&self, path: &Path) -> Result<SourceBytes, SourceError> {
        self.reads
            .borrow_mut()
            .push(path.to_string_lossy().into_owned());
        self.inner.read(path)
    }
    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        self.inner.glob(pattern)
    }
    fn account_home(&self) -> &Path {
        self.inner.account_home()
    }
    fn user_dir(&self) -> &Path {
        self.inner.user_dir()
    }
    fn system_dir(&self) -> &Path {
        self.inner.system_dir()
    }
    fn env(&self, name: &str) -> Option<String> {
        self.inner.env(name)
    }
}

#[test]
fn identity_selection_reports_fingerprint_and_backing() {
    let mut inner = adopted_tree(
        b"Host *\n    IdentityFile ~/.ssh/agentkey\n    IdentityFile ~/.ssh/filekey\n    IdentityFile ~/.ssh/nopub\n",
        &[managed_alias("m1", "m1.example", None)],
    );
    // agent-backed: only the `.pub` is present.
    inner.insert(
        format!("{USER_DIR}/agentkey.pub"),
        MemEntry::File(synthetic_pub(40, "agent").into_bytes()),
    );
    // file-backed: a private key file the account cannot read (mode 000), and its
    // `.pub`. It is detected by stat (glob) and never opened.
    inner.insert(format!("{USER_DIR}/filekey"), MemEntry::Denied);
    inner.insert(
        format!("{USER_DIR}/filekey.pub"),
        MemEntry::File(synthetic_pub(41, "file").into_bytes()),
    );
    let src = ReadLog {
        inner: &inner,
        reads: RefCell::new(Vec::new()),
    };
    let ev = eval_src(&src, &q("m1"));
    let report = identity_selection(&ev, &adopted_path("m1"), &src);
    let by_name = |n: &str| {
        let i = ev.accumulated[&KnownKeyword::IdentityFile]
            .iter()
            .position(|c| c.value.args[0].ends_with(n))
            .unwrap();
        report.entries[i].clone()
    };
    let agent = by_name("agentkey");
    assert_eq!(agent.backing, IdentityBacking::Agent);
    assert!(agent.fingerprint.as_deref().unwrap().starts_with("SHA256:"));
    let file = by_name("filekey");
    assert_eq!(file.backing, IdentityBacking::File);
    assert!(file.fingerprint.is_some());
    let none = by_name("nopub");
    assert_eq!(none.backing, IdentityBacking::Unknown);
    assert!(none.fingerprint.is_none());
    assert_ne!(agent.fingerprint, file.fingerprint);
    // No private key file was ever read.
    let reads = src.reads.borrow();
    for private in ["/filekey", "/agentkey", "/nopub"] {
        assert!(
            !reads.iter().any(|r| r.ends_with(private)),
            "{private} was opened: {reads:?}"
        );
    }
    assert!(
        report
            .entries
            .iter()
            .all(|e| e.kind == IdentityEntryKind::IdentityFile)
    );
}

#[test]
fn default_identities_count_when_nothing_is_configured() {
    let src = source()
        .with_file(USER_CONFIG, "Host box\n    User u\n")
        .with_file(
            format!("{USER_DIR}/id_ed25519.pub"),
            synthetic_pub(9, "default"),
        );
    let ev = eval_src(&src, &q("box"));
    let report = identity_selection(&ev, &adopted_path("box"), &src);
    assert_eq!(report.selection, IdentitySelection::NotExclusive);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].source, IdentityEntrySource::Default);
}

// --- behaviour digests ------------------------------------------------------------------

#[test]
fn behavior_digest_ignores_line_moves_and_comments_not_values() {
    let a = eval_user("Host box\n    HostName h.example\n    User u\n", "box");
    let b = eval_user(
        "# a comment\n\nHost box\n    User u\n\n    # inside\n    HostName h.example\n",
        "box",
    );
    let c = eval_user("Host box\n    HostName h2.example\n    User u\n", "box");
    let (ra, rb, rc) = (relevant(&a), relevant(&b), relevant(&c));
    assert_eq!(behavior_digest(&ra), behavior_digest(&rb));
    assert_ne!(behavior_digest(&ra), behavior_digest(&rc));
    assert!(diff(&ra, &rb).is_empty());
    let changes = diff(&ra, &rc);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].directive, KnownKeyword::Hostname);
    assert!(behavior_state(&ra).determined);
    // A value in an IdentityFile list changes it too, and so does its certainty.
    let d = eval_user(
        "Host box\n    HostName h.example\n    User u\n    IdentityFile ~/k\n",
        "box",
    );
    let e = eval_user(
        "Match exec \"probe-e\"\n    IdentityFile ~/k\nHost box\n    HostName h.example\n    User u\n",
        "box",
    );
    assert_ne!(
        behavior_digest(&relevant(&d)),
        behavior_digest(&relevant(&e))
    );
    assert!(!behavior_state(&relevant(&e)).determined);
}

// --- rendering (ADR-0007 §4) -------------------------------------------------------------

#[test]
fn render_is_deterministic_and_sorted() {
    let aliases = [
        managed_alias("zeta", "z.example", Some(2222)),
        managed_alias("alpha", "192.0.2.10", None),
        managed_alias("mid", "2001:db8::1", None),
    ];
    let one = render_managed(&aliases, PathStyle::Unix).unwrap();
    let mut rev = aliases.clone();
    rev.reverse();
    assert_eq!(one, render_managed(&rev, PathStyle::Unix).unwrap());
    let text = String::from_utf8(one).unwrap();
    let pos = |s: &str| text.find(s).unwrap();
    assert!(pos("Host alpha") < pos("Host mid") && pos("Host mid") < pos("Host zeta"));
    assert!(text.contains("    Port 2222\n"));
    assert!(text.contains(&format!("    IdentityFile \"{KEYS_REL}/zeta.pub\"\n")));
    assert!(text.contains("    IdentitiesOnly yes\n"));
    // Only literal Host sections and the closed directive set.
    for line in text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    {
        let kw = line.split_whitespace().next().unwrap();
        assert!(
            [
                "Host",
                "HostName",
                "Port",
                "User",
                "IdentityAgent",
                "IdentityFile",
                "IdentitiesOnly"
            ]
            .contains(&kw),
            "{line}"
        );
    }
    // P loads: every managed value is determined, and nothing in it executes.
    let src = source().with_file(USER_CONFIG, text.as_bytes());
    let ev = eval_src(&src, &q("zeta"));
    assert_eq!(det1(&ev, KnownKeyword::Port).as_deref(), Some("2222"));
    assert!(executing_constructs(&ev).is_empty() && ev.invalid.is_empty());
}

#[test]
fn render_refuses_values_the_client_would_read_differently() {
    assert!(HostName::parse("a%h.example").is_err());
    assert!(HostName::parse("-oProxyCommand=x").is_err());
    assert!(HostName::parse("fe80::1%eth0").is_err());
    assert!(HostName::parse("a b").is_err());
    for bad in ["web*", "w?b", "!box", "a,b", "a b", "a%b", "", "-x"] {
        assert_eq!(
            AliasName::parse(bad),
            Err(RenderError::RefusedValue("alias")),
            "{bad}"
        );
    }
    assert!(AliasName::parse(&"a".repeat(65)).is_err());
    assert!(AliasName::parse(&"a".repeat(64)).is_ok());
    for bad in ["/x/${HOME}/k", "/x/\"k", "/x/k\n", "/x\\k", "relative/k"] {
        assert!(RenderPath::unix(Path::new(bad)).is_err(), "{bad:?}");
    }
    let mut a = managed_alias("box", "box.example", None);
    a.user = "bad%user".into();
    assert_eq!(
        render_managed(&[a], PathStyle::Unix),
        Err(RenderError::RefusedValue("user"))
    );
    let mut a = managed_alias("box", "box.example", None);
    a.identity_agent = Some(RenderPath::pipe("openssh-ssh-agent").unwrap());
    assert!(
        render_managed(&[a], PathStyle::Unix).is_err(),
        "a pipe in a Unix file"
    );
}

#[test]
fn render_escapes_percent_and_writes_windows_forms() {
    let p = RenderPath::unix(Path::new("/hm/100%/keys/k.pub")).unwrap();
    let mut a = managed_alias("box", "box.example", None);
    a.identity_files = vec![p];
    let text = String::from_utf8(render_managed(&[a], PathStyle::Unix).unwrap()).unwrap();
    assert!(
        text.contains("IdentityFile \"/hm/100%%/keys/k.pub\""),
        "{text}"
    );

    let w = RenderPath::windows(Path::new("C:\\hm\\fixture\\keys\\k.pub")).unwrap();
    assert_eq!(w.as_str(), "C:/hm/fixture/keys/k.pub");
    let pipe = RenderPath::pipe("\\\\.\\pipe\\openssh-ssh-agent").unwrap();
    assert_eq!(pipe.as_str(), "//./pipe/openssh-ssh-agent");
    assert!(RenderPath::windows(Path::new("\\\\.\\pipe\\x")).is_err());
    let mut a = managed_alias("box", "box.example", None);
    a.identity_agent = Some(pipe);
    a.identity_files = vec![w];
    let text = String::from_utf8(render_managed(&[a], PathStyle::Windows).unwrap()).unwrap();
    assert!(text.contains("IdentityAgent \"//./pipe/openssh-ssh-agent\""));
    assert!(text.contains("IdentityFile \"C:/hm/fixture/keys/k.pub\""));
    assert!(!text.contains('\\'));
    let block = render_include_block(
        &MarkerId::parse(MARKER).unwrap(),
        &RenderPath::windows(Path::new("C:\\hm\\fixture\\AppData\\heimdall\\ssh_config")).unwrap(),
        Newline::CrLf,
    );
    let block = String::from_utf8(block).unwrap();
    assert!(block.contains("Include \"C:/hm/fixture/AppData/heimdall/ssh_config\"\r\n"));
    assert_eq!(block.matches("\r\n").count(), 3);
}

#[test]
fn render_git_values_are_shell_and_git_quoted() {
    let spaced = RenderPath::unix(Path::new("/opt/my tools/ssh")).unwrap();
    let text = String::from_utf8(render_git_managed(&spaced).unwrap()).unwrap();
    assert!(
        text.ends_with("[core]\n\tsshCommand = \"'/opt/my tools/ssh'\"\n"),
        "{text}"
    );
    let win = RenderPath::windows(Path::new("C:\\Windows\\System32\\OpenSSH\\ssh.exe")).unwrap();
    let text = String::from_utf8(render_git_managed(&win).unwrap()).unwrap();
    assert!(text.contains("sshCommand = \"'C:/Windows/System32/OpenSSH/ssh.exe'\""));
    let quote = RenderPath::unix(Path::new("/opt/o'brien/ssh")).unwrap();
    assert_eq!(
        render_git_managed(&quote),
        Err(RenderError::RefusedValue("git_ssh_command_path"))
    );
    assert!(RenderPath::unix(Path::new("/opt/\"q\"/ssh")).is_err());
    let home = RenderPath::unix(Path::new("~/bin/ssh")).unwrap();
    assert!(render_git_managed(&home).is_err(), "not absolute");
    let marker = MarkerId::parse(MARKER).unwrap();
    let block = render_git_include_block(
        &marker,
        &RenderPath::unix(Path::new("/hm/home/.config/heimdall/gitconfig")).unwrap(),
        Newline::Lf,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(block).unwrap(),
        format!(
            "# >>> heimdall managed include (id {MARKER}); remove with `heimdall setup rollback`\n\
             [include]\n\tpath = \"/hm/home/.config/heimdall/gitconfig\"\n\
             # <<< heimdall managed include (id {MARKER})\n"
        )
    );
}

// --- properties ---------------------------------------------------------------------------

/// A `Match` criterion of the generated configurations.
#[derive(Debug, Clone)]
enum Crit {
    Host(&'static str),
    OriginalHost(&'static str),
    User(&'static str),
    LocalUser(bool),
    Tagged(&'static str),
    Final,
    Canonical,
    /// Undecidable: `exec`.
    Exec,
    /// Undecidable: `localnetwork`.
    LocalNet,
}

#[derive(Debug, Clone)]
enum Header {
    Host(Vec<(bool, &'static str)>),
    Match(Vec<(bool, Crit)>),
    MatchAll,
}

#[derive(Debug, Clone)]
enum Dir {
    HostName(&'static str),
    User(&'static str),
    Port(&'static str),
    IdentityFile(&'static str),
    CertificateFile(&'static str),
    ProxyJump,
    ProxyCommand,
    Tag(&'static str),
    IdentitiesOnly(bool),
    IdentityAgent(&'static str),
    Include,
}

#[derive(Debug, Clone)]
struct Cfg {
    top: Vec<Dir>,
    blocks: Vec<(Header, Vec<Dir>)>,
}

const PATTERNS: &[&str] = &["box", "web*", "*", "other", "web1", "m1", "m*"];

fn crit() -> impl Strategy<Value = (bool, Crit)> {
    let c = prop_oneof![
        prop::sample::select(PATTERNS).prop_map(Crit::Host),
        prop::sample::select(&["box", "web*"][..]).prop_map(Crit::OriginalHost),
        prop::sample::select(&["u1", "u*", "fixture"][..]).prop_map(Crit::User),
        any::<bool>().prop_map(Crit::LocalUser),
        prop::sample::select(&["t1", "t2"][..]).prop_map(Crit::Tagged),
        Just(Crit::Final),
        Just(Crit::Canonical),
        Just(Crit::Exec),
        Just(Crit::Exec),
        Just(Crit::LocalNet),
    ];
    (prop::bool::weighted(0.25), c)
}

fn header() -> impl Strategy<Value = Header> {
    prop_oneof![
        3 => prop::collection::vec((prop::bool::weighted(0.2), prop::sample::select(PATTERNS)), 1..3)
            .prop_map(Header::Host),
        3 => prop::collection::vec(crit(), 1..3).prop_map(Header::Match),
        1 => Just(Header::MatchAll),
    ]
}

fn dir() -> impl Strategy<Value = Dir> {
    prop_oneof![
        prop::sample::select(&["a.example", "b.example", "c.example"][..]).prop_map(Dir::HostName),
        prop::sample::select(&["u1", "u2"][..]).prop_map(Dir::User),
        prop::sample::select(&["22", "2222"][..]).prop_map(Dir::Port),
        prop::sample::select(&["k1", "k2", "k3"][..]).prop_map(Dir::IdentityFile),
        prop::sample::select(&["c1", "c2"][..]).prop_map(Dir::CertificateFile),
        Just(Dir::ProxyJump),
        Just(Dir::ProxyCommand),
        prop::sample::select(&["t1", "t2"][..]).prop_map(Dir::Tag),
        any::<bool>().prop_map(Dir::IdentitiesOnly),
        prop::sample::select(&["/hm/run/a.sock", "none"][..]).prop_map(Dir::IdentityAgent),
        Just(Dir::Include),
    ]
}

fn cfg() -> impl Strategy<Value = Cfg> {
    (
        prop::collection::vec(dir(), 0..3),
        prop::collection::vec((header(), prop::collection::vec(dir(), 0..4)), 0..5),
    )
        .prop_map(|(top, blocks)| Cfg { top, blocks })
}

/// The included file: like [`cfg`] without an `Include` of its own, so the tree stays
/// readable (a self-include is a cycle, an unreadable part, which the properties
/// about undecidable conditions and unaffected names do not cover; the unreadable
/// case has its own test).
fn part_cfg() -> impl Strategy<Value = Cfg> {
    cfg().prop_map(|mut c| {
        c.top.retain(|d| !matches!(d, Dir::Include));
        for (_, dirs) in &mut c.blocks {
            dirs.retain(|d| !matches!(d, Dir::Include));
        }
        c
    })
}

/// At most this many undecidable criteria per tree (2^4 assignments).
const MAX_UNDECIDED: usize = 4;

/// Render a configuration. With `assign`, each undecidable criterion `k` becomes a
/// decided one with the same truth value (`localuser fixture` or `localuser nobody`),
/// on the same line, so spans are comparable. `next` numbers them across files.
fn render(c: &Cfg, assign: Option<&[bool]>, next: &mut usize) -> String {
    let mut out = String::new();
    let dir_line = |d: &Dir| match d {
        Dir::HostName(h) => format!("HostName {h}"),
        Dir::User(u) => format!("User {u}"),
        Dir::Port(p) => format!("Port {p}"),
        Dir::IdentityFile(k) => format!("IdentityFile ~/.ssh/{k}"),
        Dir::CertificateFile(k) => format!("CertificateFile ~/.ssh/{k}-cert.pub"),
        Dir::ProxyJump => "ProxyJump jump.example".to_owned(),
        Dir::ProxyCommand => "ProxyCommand nc %h %p".to_owned(),
        Dir::Tag(t) => format!("Tag {t}"),
        Dir::IdentitiesOnly(b) => format!("IdentitiesOnly {}", if *b { "yes" } else { "no" }),
        Dir::IdentityAgent(a) => format!("IdentityAgent {a}"),
        Dir::Include => "Include part.conf".to_owned(),
    };
    for d in &c.top {
        out.push_str(&dir_line(d));
        out.push('\n');
    }
    for (h, dirs) in &c.blocks {
        match h {
            Header::Host(pats) => {
                out.push_str("Host");
                for (neg, p) in pats {
                    out.push(' ');
                    if *neg {
                        out.push('!');
                    }
                    out.push_str(p);
                }
            }
            Header::MatchAll => out.push_str("Match all"),
            Header::Match(crits) => {
                out.push_str("Match");
                for (neg, cr) in crits {
                    out.push(' ');
                    if *neg {
                        out.push('!');
                    }
                    let undecided = |kind: &str, next: &mut usize| -> String {
                        let k = *next;
                        *next += 1;
                        if k >= MAX_UNDECIDED {
                            return "localuser fixture".to_owned();
                        }
                        match assign {
                            None if kind == "exec" => format!("exec \"probe-{k}\""),
                            None => format!("localnetwork 10.{k}.0.0/16"),
                            Some(a) if a[k] => "localuser fixture".to_owned(),
                            Some(_) => "localuser nobody".to_owned(),
                        }
                    };
                    let text = match cr {
                        Crit::Host(p) => format!("host {p}"),
                        Crit::OriginalHost(p) => format!("originalhost {p}"),
                        Crit::User(u) => format!("user {u}"),
                        Crit::LocalUser(b) => {
                            format!("localuser {}", if *b { "fixture" } else { "nobody" })
                        }
                        Crit::Tagged(t) => format!("tagged {t}"),
                        Crit::Final => "final".to_owned(),
                        Crit::Canonical => "canonical".to_owned(),
                        Crit::Exec => undecided("exec", next),
                        Crit::LocalNet => undecided("localnetwork", next),
                    };
                    out.push_str(&text);
                }
            }
        }
        out.push('\n');
        for d in dirs {
            out.push_str("    ");
            out.push_str(&dir_line(d));
            out.push('\n');
        }
    }
    out
}

fn tree_source(user: &Cfg, part: &Cfg, assign: Option<&[bool]>) -> (MemSource, usize) {
    let mut next = 0;
    let u = render(user, assign, &mut next);
    let p = render(part, assign, &mut next);
    let src = source()
        .with_file(USER_CONFIG, u)
        .with_file(format!("{USER_DIR}/part.conf"), p);
    (src, next.min(MAX_UNDECIDED))
}

type Key = (Vec<String>, u32, u32);

fn key(v: &Value) -> Key {
    (v.args.clone(), v.span.source.0, v.span.line)
}

/// The concrete evaluation lies in the abstract one's candidates (ADR-0007 §6).
fn assert_sound(abs: &Evaluation, conc: &Evaluation) -> Result<(), TestCaseError> {
    prop_assert!(
        !conc.unresolved.iter().any(|u| matches!(
            u.reason,
            UnresolvedReason::MatchExec | UnresolvedReason::MatchLocalNetwork
        )),
        "the concrete tree has no undecidable criterion"
    );
    let keys: BTreeSet<KnownKeyword> = abs
        .values
        .keys()
        .chain(conc.values.keys())
        .copied()
        .collect();
    for k in keys {
        let a = abs.values.get(&k).unwrap_or(&Resolved::Unset);
        let c = conc.values.get(&k).unwrap_or(&Resolved::Unset);
        match (a, c) {
            (Resolved::Determined(av), Resolved::Determined(cv)) => {
                prop_assert_eq!(key(av), key(cv), "{:?}", k);
            }
            (Resolved::Unset | Resolved::Undetermined(_), Resolved::Unset) => {}
            (Resolved::Undetermined(cands), Resolved::Determined(cv)) => {
                prop_assert!(
                    cands.iter().any(|v| key(v) == key(cv)),
                    "{:?}: concrete {:?} not among {:?}",
                    k,
                    cv,
                    cands
                );
            }
            _ => prop_assert!(false, "{:?}: abstract {:?} vs concrete {:?}", k, a, c),
        }
    }
    let lists: BTreeSet<KnownKeyword> = abs
        .accumulated
        .keys()
        .chain(conc.accumulated.keys())
        .copied()
        .collect();
    for k in lists {
        let a = abs.accumulated.get(&k).cloned().unwrap_or_default();
        let c = conc.accumulated.get(&k).cloned().unwrap_or_default();
        prop_assert!(c.iter().all(|e| e.determined));
        let mut it = a.iter();
        for ce in &c {
            prop_assert!(
                it.any(|ae| key(&ae.value) == key(&ce.value)),
                "{:?}: concrete list {:?} is not a subsequence of {:?}",
                k,
                c,
                a
            );
        }
        for ae in a.iter().filter(|e| e.determined) {
            prop_assert!(c.iter().any(|ce| ce.value.args == ae.value.args), "{:?}", k);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    /// Soundness: for every assignment of the undecidable conditions, the concrete
    /// evaluation (the same tree with each undecidable criterion replaced by a decided
    /// one of that truth value) is `Unset` or one of the candidates, and every list is
    /// a subsequence of the candidate list that holds every determined entry.
    #[test]
    fn soundness_every_assignment_lies_in_the_candidates(
        user in cfg(),
        part in part_cfg(),
        host in prop::sample::select(&["box", "web1", "web2", "other", "m1"][..]),
    ) {
        let (abstract_src, n) = tree_source(&user, &part, None);
        let abs = eval_src(&abstract_src, &q(host));
        for bits in 0u32..(1 << n) {
            let assign: Vec<bool> = (0..MAX_UNDECIDED).map(|i| bits & (1 << i) != 0).collect();
            let (src, _) = tree_source(&user, &part, Some(&assign));
            let conc = eval_src(&src, &q(host));
            assert_sound(&abs, &conc)?;
        }
    }

    /// Inserting B and P with literal managed aliases leaves `relevant()` identical for
    /// every name that is not a managed alias (CanonicalizeHostname `no`), and with
    /// CanonicalizeHostname `yes` it is either identical or reported undetermined.
    #[test]
    fn unaffected_names_keep_their_behaviour(
        user in cfg(),
        part in part_cfg(),
        canonicalize in any::<bool>(),
        host in prop::sample::select(&["box", "web1", "web2", "other"][..]),
    ) {
        let mut next = 0;
        let mut text = render(&user, None, &mut next);
        if canonicalize {
            text = format!("CanonicalizeHostname yes\n{text}");
        }
        let part_text = render(&part, None, &mut next);
        let before = source()
            .with_file(USER_CONFIG, text.as_bytes())
            .with_file(format!("{USER_DIR}/part.conf"), part_text.as_bytes());
        let mut after = adopted_tree(
            text.as_bytes(),
            &[managed_alias("m1", "m1.example", Some(2022)), managed_alias("m2", "m2.example", None)],
        );
        after.insert(format!("{USER_DIR}/part.conf"), MemEntry::File(part_text.into_bytes()));
        let b = relevant(&eval_src(&before, &q(host)));
        let a = relevant(&eval_src(&after, &q(host)));
        if canonicalize {
            prop_assert!(
                behavior_digest(&a) == behavior_digest(&b) || !behavior_state(&a).determined,
                "a changed behaviour must be reported undetermined"
            );
        } else {
            prop_assert_eq!(behavior_state(&a), behavior_state(&b));
            prop_assert!(diff(&b, &a).is_empty());
        }
    }

    /// Directives P sets are `Determined` for a managed alias whatever follows B.
    #[test]
    fn managed_values_are_determined_whatever_follows(
        user in cfg(),
        part in part_cfg(),
        canonicalize in any::<bool>(),
    ) {
        let mut next = 0;
        let mut text = render(&user, None, &mut next);
        if canonicalize {
            text = format!("CanonicalizeHostname yes\n{text}");
        }
        let part_text = render(&part, None, &mut next);
        let mut src = adopted_tree(
            text.as_bytes(),
            &[managed_alias("m1", "m1.example", Some(2022))],
        );
        src.insert(format!("{USER_DIR}/part.conf"), MemEntry::File(part_text.into_bytes()));
        let ev = eval_src(&src, &q("m1"));
        prop_assert_eq!(det1(&ev, KnownKeyword::Hostname), Some("m1.example".to_owned()));
        prop_assert_eq!(det1(&ev, KnownKeyword::Port), Some("2022".to_owned()));
        prop_assert_eq!(det1(&ev, KnownKeyword::User), Some("deploy".to_owned()));
        prop_assert_eq!(det1(&ev, KnownKeyword::IdentityAgent), Some("/hm/run/agent.sock".to_owned()));
        prop_assert_eq!(det1(&ev, KnownKeyword::IdentitiesOnly), Some("yes".to_owned()));
        let ids = list(&ev, KnownKeyword::IdentityFile);
        prop_assert_eq!(&ids[0], &(format!("{KEYS_REL}/m1.pub"), true));
    }
}
