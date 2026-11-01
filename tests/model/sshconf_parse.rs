//! `heimdall-sshconf` lexer, parser, directive table and include loader (M02-U1;
//! m02-plan U1; ADR-0007 F1–F4, F7, §6).
//!
//! Cargo test target `model_sshconf_parse` hosted by `heimdall-sshconf`. Pure: every
//! source is a `MemSource` (no file, process or socket), and nothing a configuration
//! names is ever run (the crate has no API for it).
//!
//! The ssh_config(5) facts are differential checks against the pinned S01 snapshot
//! (`docs/sources/snapshots/S01.txt.gz`, `pins.json` `normalized_text_sha256`
//! `54d27f61…20dd67`, footer "OpenBSD-current September 20, 2026"). The test cannot
//! inflate the snapshot itself (no gzip decoder in the dependency set), so the keyword
//! list and the quoted fragments below were taken from the decompressed text with
//! `python3 -I` (`gzip.open(...).read()`, the keyword section between "The possible
//! keywords and their meanings are as follows" and "PATTERNS"); every quoted fragment
//! is verbatim.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use heimdall_sshconf::directive::{
    self, ALIASES, DirectiveClass, Keyword, KnownKeyword, Obsolete, Provenance, class, expands_env,
    expands_tokens,
};
use heimdall_sshconf::include::{
    ArgError, ConfigSet, ConfigSource, IncludeError, IncludeVisitor, InvalidArg, MemEntry,
    MemSource, Origin, Roots, SourceError, Visit, expand, expand_include_arg, glob_match, record,
    walk,
};
use heimdall_sshconf::lex::{LexError, split_args};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::{Line, SourceId, Span, parse_file};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const HOME: &str = "/hm/home";
const USER_DIR: &str = "/hm/home/.ssh";
const SYSTEM_DIR: &str = "/hm/etc/ssh";

fn source() -> MemSource {
    MemSource::new(HOME, USER_DIR, SYSTEM_DIR)
}

fn user_root(path: &str) -> Roots {
    Roots {
        user: Some(PathBuf::from(path)),
        system: None,
    }
}

fn no_tokens(_: char) -> Option<String> {
    None
}

fn parse(text: &str) -> Vec<Line> {
    parse_file(SourceId(0), text.as_bytes(), &Limits::default())
        .unwrap()
        .lines
}

fn directive_args(line: &Line) -> (Keyword, Vec<String>) {
    match line {
        Line::Directive(d) => (d.keyword.clone(), d.args.clone()),
        other => panic!("not a directive: {other:?}"),
    }
}

/// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
fn config() -> ProptestConfig {
    config_with(256)
}

/// [`config`] with more cases, for cheap properties whose interesting inputs are rare.
fn config_with(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5531_5f53_5348_434f);
    }
    c
}

// --- lexer goldens --------------------------------------------------------------------

/// `(line, expected)`: `Ok` is keyword then arguments; an empty `Ok` is blank or comment.
fn golden() -> Vec<(&'static str, Result<Vec<&'static str>, LexError>)> {
    use LexError::{MalformedKeyword, UnterminatedQuote};
    vec![
        // keyword separation, `=`
        ("Host a", Ok(vec!["Host", "a"])),
        ("Host=a", Ok(vec!["Host", "a"])),
        ("Host = a", Ok(vec!["Host", "a"])),
        ("Host\t=\ta", Ok(vec!["Host", "a"])),
        ("Host==a", Ok(vec!["Host", "=a"])),
        ("Host a=b", Ok(vec!["Host", "a=b"])),
        ("HOST a", Ok(vec!["HOST", "a"])),
        // whitespace: tabs, leading, trailing, form feed at the end, CR at the end
        ("\tHost\ta\tb\t", Ok(vec!["Host", "a", "b"])),
        ("   Port   22   ", Ok(vec!["Port", "22"])),
        ("Host a\u{c}", Ok(vec!["Host", "a"])),
        ("Host a\r", Ok(vec!["Host", "a"])),
        // only spaces and tabs separate arguments; a CR inside the line is data
        ("Host a\rb", Ok(vec!["Host", "a\rb"])),
        // double and single quotes
        (
            "IdentityFile \"/p/with space\"",
            Ok(vec!["IdentityFile", "/p/with space"]),
        ),
        (
            "IdentityFile '/p/with space'",
            Ok(vec!["IdentityFile", "/p/with space"]),
        ),
        ("Host \"a\"b'c d'", Ok(vec!["Host", "abc d"])),
        ("Host \"it's\"", Ok(vec!["Host", "it's"])),
        ("Host 'say \"hi\"'", Ok(vec!["Host", "say \"hi\""])),
        ("Host \"\"", Ok(vec!["Host", ""])),
        ("Host \"a", Err(UnterminatedQuote)),
        ("Host 'a", Err(UnterminatedQuote)),
        ("Host a\"", Err(UnterminatedQuote)),
        // backslash escapes: \' \" \\ and (outside quotes) "\ "; anything else is kept
        (r"Host a\ b", Ok(vec!["Host", "a b"])),
        (r#"Host a\"b"#, Ok(vec!["Host", "a\"b"])),
        (r"Host a\'b", Ok(vec!["Host", "a'b"])),
        (r"Host a\\b", Ok(vec!["Host", r"a\b"])),
        (r"Host a\nb", Ok(vec!["Host", r"a\nb"])),
        (
            r"IdentityAgent \\.\pipe\x",
            Ok(vec!["IdentityAgent", r"\.\pipe\x"]),
        ),
        (r#"Host "a\ b""#, Ok(vec!["Host", r"a\ b"])),
        (r"Host 'a\'b'", Ok(vec!["Host", "a'b"])),
        (r"Host a\", Ok(vec!["Host", r"a\"])),
        // a backslash before a tab is unrecognised and the tab still separates
        ("Host a\\\tb", Ok(vec!["Host", "a\\", "b"])),
        // comments: whole line, after a token, never inside a token or quotes
        ("# Host a", Ok(vec![])),
        ("  \t# Host a", Ok(vec![])),
        ("#", Ok(vec![])),
        ("Host a # comment", Ok(vec!["Host", "a"])),
        ("Host a #comment \"unclosed", Ok(vec!["Host", "a"])),
        ("Host a#b", Ok(vec!["Host", "a#b"])),
        // pattern operators are data at the lexer level
        (
            "Host !bad.example *.example ?x",
            Ok(vec!["Host", "!bad.example", "*.example", "?x"]),
        ),
        (
            "Match host a,!b exec \"x y\"",
            Ok(vec!["Match", "host", "a,!b", "exec", "x y"]),
        ),
        ("Host \"a # b\"", Ok(vec!["Host", "a # b"])),
        ("Host #", Ok(vec!["Host"])),
        ("Host = #", Ok(vec!["Host"])),
        // blank
        ("", Ok(vec![])),
        ("   \t", Ok(vec![])),
        // refused keyword forms
        ("Host", Err(MalformedKeyword)),
        ("Host   \t", Err(MalformedKeyword)),
        ("Host =", Err(MalformedKeyword)),
        ("=Host a", Err(MalformedKeyword)),
        ("\"Host\" a", Err(MalformedKeyword)),
        ("Host\"a\"", Err(MalformedKeyword)),
        ("\u{c}", Err(MalformedKeyword)),
    ]
}

#[test]
fn lexer_golden_cases() {
    for (line, expected) in golden() {
        let got = split_args(line);
        let expected: Result<Vec<String>, LexError> =
            expected.map(|v| v.into_iter().map(str::to_owned).collect());
        assert_eq!(got, expected, "line {line:?}");
    }
}

#[test]
fn lexer_error_never_echoes_the_line() {
    let secret = "hm-test-value-7d1f";
    for line in [
        format!("IdentityAgent \"{secret}"),
        format!("=Host {secret}"),
        secret.to_owned(),
    ] {
        let err = split_args(&line).unwrap_err();
        assert!(!err.to_string().contains(secret), "{err}");
        assert!(!format!("{err:?}").contains(secret), "{err:?}");
    }
}

#[test]
fn parser_lines_follow_the_lexer_with_crlf_and_tabs() {
    let text = "# head\r\n\r\nHost\ta b\r\n\tHostName = h.example.test # trailing\r\nUser \"x\r\n";
    let file = parse_file(SourceId(7), text.as_bytes(), &Limits::default()).unwrap();
    assert!(file.crlf);
    assert!(!file.had_bom);
    assert_eq!(file.source, SourceId(7));
    assert_eq!(file.lines.len(), 5);
    assert_eq!(
        file.lines[0],
        Line::Comment(Span {
            source: SourceId(7),
            line: 1
        })
    );
    assert_eq!(
        file.lines[1],
        Line::Blank(Span {
            source: SourceId(7),
            line: 2
        })
    );
    let (k, a) = directive_args(&file.lines[2]);
    assert_eq!(k, Keyword::Known(KnownKeyword::Host));
    assert_eq!(a, ["a", "b"]);
    let (k, a) = directive_args(&file.lines[3]);
    assert_eq!(k, Keyword::Known(KnownKeyword::Hostname));
    assert_eq!(a, ["h.example.test"]);
    assert_eq!(
        file.lines[4],
        Line::Invalid {
            span: Span {
                source: SourceId(7),
                line: 5
            },
            error: LexError::UnterminatedQuote
        }
    );
}

#[test]
fn parser_bom_last_line_and_keyword_spelling() {
    let file = parse_file(
        SourceId(0),
        b"\xEF\xBB\xBFhOsTnAmE x\nNoSuch y\nPort 22",
        &Limits::default(),
    )
    .unwrap();
    assert!(file.had_bom);
    assert!(!file.crlf);
    assert_eq!(file.lines.len(), 3);
    assert_eq!(
        directive_args(&file.lines[0]).0,
        Keyword::Known(KnownKeyword::Hostname)
    );
    assert_eq!(
        directive_args(&file.lines[1]).0,
        Keyword::Unknown("NoSuch".into())
    );
    assert_eq!(
        directive_args(&file.lines[2]),
        (Keyword::Known(KnownKeyword::Port), vec!["22".into()])
    );
    // An empty file has no lines; a lone LF is one blank line.
    assert!(parse("").is_empty());
    assert_eq!(parse("\n").len(), 1);
    // A CR without LF at the end of the last line is trailing whitespace, not CRLF.
    let file = parse_file(SourceId(0), b"Port 22\r", &Limits::default()).unwrap();
    assert!(!file.crlf);
}

// --- directive table ---------------------------------------------------------------------

/// The keyword entries of S01, in the manual's order (`Host`, `Match`, `Include`, then
/// alphabetical), extracted from the snapshot as the module documentation says.
const S01_KEYWORDS: &[&str] = &[
    "Host",
    "Match",
    "Include",
    "AddKeysToAgent",
    "AddressFamily",
    "BatchMode",
    "BindAddress",
    "BindInterface",
    "CanonicalDomains",
    "CanonicalizeFallbackLocal",
    "CanonicalizeHostname",
    "CanonicalizeMaxDots",
    "CanonicalizePermittedCNAMEs",
    "CASignatureAlgorithms",
    "CertificateFile",
    "ChannelTimeout",
    "CheckHostIP",
    "Ciphers",
    "ClearAllForwardings",
    "Compression",
    "ConnectionAttempts",
    "ConnectTimeout",
    "ControlMaster",
    "ControlPath",
    "ControlPersist",
    "DynamicForward",
    "EnableEscapeCommandline",
    "EnableSSHKeysign",
    "EscapeChar",
    "ExitOnForwardFailure",
    "FingerprintHash",
    "ForkAfterAuthentication",
    "ForwardAgent",
    "ForwardX11",
    "ForwardX11Timeout",
    "ForwardX11Trusted",
    "GatewayPorts",
    "GlobalKnownHostsFile",
    "GSSAPIAuthentication",
    "GSSAPIDelegateCredentials",
    "HashKnownHosts",
    "HostbasedAcceptedAlgorithms",
    "HostbasedAuthentication",
    "HostKeyAlgorithms",
    "HostKeyAlias",
    "Hostname",
    "IdentitiesOnly",
    "IdentityAgent",
    "IdentityFile",
    "IgnoreUnknown",
    "IPQoS",
    "KbdInteractiveAuthentication",
    "KbdInteractiveDevices",
    "KexAlgorithms",
    "KnownHostsCommand",
    "LocalCommand",
    "LocalForward",
    "LogLevel",
    "LogVerbose",
    "MACs",
    "NoHostAuthenticationForLocalhost",
    "NumberOfPasswordPrompts",
    "ObscureKeystrokeTiming",
    "PasswordAuthentication",
    "PermitLocalCommand",
    "PermitRemoteOpen",
    "PKCS11Provider",
    "Port",
    "PreferredAuthentications",
    "ProxyCommand",
    "ProxyJump",
    "ProxyUseFdpass",
    "PubkeyAcceptedAlgorithms",
    "PubkeyAuthentication",
    "RefuseConnection",
    "RekeyLimit",
    "RemoteCommand",
    "RemoteForward",
    "RequestTTY",
    "RequiredRSASize",
    "RevokedHostKeys",
    "SecurityKeyProvider",
    "SendEnv",
    "ServerAliveCountMax",
    "ServerAliveInterval",
    "SessionType",
    "SetEnv",
    "StdinNull",
    "StreamLocalBindMask",
    "StreamLocalBindUnlink",
    "StrictHostKeyChecking",
    "SyslogFacility",
    "TCPKeepAlive",
    "Tag",
    "Tunnel",
    "TunnelDevice",
    "UpdateHostKeys",
    "User",
    "UserKnownHostsFile",
    "VerifyHostKeyDNS",
    "VersionAddendum",
    "VisualHostKey",
    "WarnWeakCrypto",
    "XAuthLocation",
];

#[test]
fn keyword_table_equals_the_s01_keyword_entries() {
    let mut table: Vec<&str> = KnownKeyword::ALL.iter().map(|k| k.as_str()).collect();
    let mut s01: Vec<&str> = S01_KEYWORDS.to_vec();
    table.sort_unstable();
    s01.sort_unstable();
    assert_eq!(table, s01);
}

#[test]
fn every_known_keyword_is_classified() {
    let mut counts = std::collections::BTreeMap::new();
    for k in KnownKeyword::ALL {
        *counts.entry(format!("{:?}", class(*k))).or_insert(0usize) += 1;
        // The token claim agrees with the token set.
        assert_eq!(
            expands_tokens(*k),
            !directive::tokens(*k).is_empty(),
            "{k:?}"
        );
    }
    assert_eq!(counts.get("Section"), Some(&2));
    assert_eq!(counts.get("Include"), Some(&1));
    assert_eq!(counts.get("Executes"), Some(&3));
    assert_eq!(counts.get("Accumulates"), Some(&6));
    assert_eq!(counts.get("Other"), None);
    assert_eq!(counts.values().sum::<usize>(), KnownKeyword::ALL.len());
}

#[test]
fn accumulating_directives_are_those_s01_says_add_up() {
    // Verbatim S01 fragments (F2 and the forwarding and SendEnv entries).
    let evidence: &[(KnownKeyword, &str)] = &[
        (
            KnownKeyword::IdentityFile,
            "Multiple IdentityFile directives will add to the list of identities tried (this behaviour differs from that of other configuration directives).",
        ),
        (
            KnownKeyword::CertificateFile,
            "Multiple CertificateFile directives will add to the list of certificates used for authentication.",
        ),
        (
            KnownKeyword::LocalForward,
            "Multiple forwardings may be specified, and additional forwardings can be given on the command line.",
        ),
        (
            KnownKeyword::RemoteForward,
            "Multiple forwardings may be specified, and additional forwardings can be given on the command line.",
        ),
        (
            KnownKeyword::DynamicForward,
            "Multiple forwardings may be specified, and additional forwardings can be given on the command line.",
        ),
        (
            KnownKeyword::SendEnv,
            "Multiple environment variables may be separated by whitespace or spread across multiple SendEnv directives.",
        ),
    ];
    let accumulating: Vec<KnownKeyword> = KnownKeyword::ALL
        .iter()
        .copied()
        .filter(|k| class(*k) == DirectiveClass::Accumulates)
        .collect();
    let expected: Vec<KnownKeyword> = evidence.iter().map(|(k, _)| *k).collect();
    let mut a = accumulating.clone();
    let mut e = expected.clone();
    a.sort();
    e.sort();
    assert_eq!(a, e);
    // F1: "Unless noted otherwise, for each configuration directive, the first
    // specified value will be used". Lists given on one line stay first-wins.
    for k in [
        KnownKeyword::Hostname,
        KnownKeyword::User,
        KnownKeyword::Port,
        KnownKeyword::IdentityAgent,
        KnownKeyword::IdentitiesOnly,
        KnownKeyword::UserKnownHostsFile,
        KnownKeyword::GlobalKnownHostsFile,
        KnownKeyword::PermitRemoteOpen,
        KnownKeyword::CanonicalDomains,
        KnownKeyword::SetEnv,
        KnownKeyword::ProxyJump,
        KnownKeyword::IgnoreUnknown,
        KnownKeyword::RemoteCommand,
    ] {
        assert_eq!(class(k), DirectiveClass::FirstWins, "{k:?}");
    }
}

#[test]
fn sections_include_and_executing_directives() {
    assert_eq!(class(KnownKeyword::Host), DirectiveClass::Section);
    assert_eq!(class(KnownKeyword::Match), DirectiveClass::Section);
    assert_eq!(class(KnownKeyword::Include), DirectiveClass::Include);
    // F4: ProxyCommand, LocalCommand and KnownHostsCommand execute commands.
    for k in [
        KnownKeyword::ProxyCommand,
        KnownKeyword::LocalCommand,
        KnownKeyword::KnownHostsCommand,
    ] {
        assert_eq!(class(k), DirectiveClass::Executes, "{k:?}");
    }
}

#[test]
fn token_and_environment_expansion_follow_s01() {
    // "CertificateFile , ControlPath , IdentityAgent , IdentityFile , Include ,
    // KnownHostsCommand , LocalForward , Match exec , RemoteCommand , RemoteForward ,
    // RevokedHostKeys , UserKnownHostsFile and VersionAddendum accept the tokens %%, %C,
    // %d, %h, %i, %j, %k, %L, %l, %n, %p, %r, and %u. KnownHostsCommand additionally
    // accepts the tokens %f, %H, %I, %K and %t. Hostname accepts the tokens %% and %h.
    // LocalCommand accepts all tokens. ProxyCommand and ProxyJump accept the tokens %%,
    // %h, %n, %p, and %r."
    let common = ['C', 'd', 'h', 'i', 'j', 'k', 'L', 'l', 'n', 'p', 'r', 'u'];
    for k in [
        KnownKeyword::CertificateFile,
        KnownKeyword::ControlPath,
        KnownKeyword::IdentityAgent,
        KnownKeyword::IdentityFile,
        KnownKeyword::Include,
        KnownKeyword::LocalForward,
        KnownKeyword::Match,
        KnownKeyword::RemoteCommand,
        KnownKeyword::RemoteForward,
        KnownKeyword::RevokedHostKeys,
        KnownKeyword::UserKnownHostsFile,
        KnownKeyword::VersionAddendum,
    ] {
        assert_eq!(directive::tokens(k), common, "{k:?}");
    }
    let mut khc: Vec<char> = common.to_vec();
    khc.extend(['f', 'H', 'I', 'K', 't']);
    khc.sort_unstable();
    let mut got = directive::tokens(KnownKeyword::KnownHostsCommand).to_vec();
    got.sort_unstable();
    assert_eq!(got, khc);
    assert_eq!(directive::tokens(KnownKeyword::Hostname), ['h']);
    assert_eq!(
        directive::tokens(KnownKeyword::ProxyCommand),
        ['h', 'n', 'p', 'r']
    );
    assert_eq!(
        directive::tokens(KnownKeyword::ProxyJump),
        ['h', 'n', 'p', 'r']
    );
    assert_eq!(directive::tokens(KnownKeyword::LocalCommand).len(), 18);
    // "Arguments to User may use the tokens described in the TOKENS section (with the
    // exception of %r and %C)".
    let user = directive::tokens(KnownKeyword::User);
    assert!(!user.contains(&'r') && !user.contains(&'C') && user.contains(&'h'));
    for k in [
        KnownKeyword::Port,
        KnownKeyword::IdentitiesOnly,
        KnownKeyword::Host,
    ] {
        assert!(!expands_tokens(k), "{k:?}");
    }

    // "The keywords CertificateFile , ControlPath , IdentityAgent , IdentityFile ,
    // Include , KnownHostsCommand , and UserKnownHostsFile support environment
    // variables. The keywords LocalForward and RemoteForward support environment
    // variables only for Unix domain socket paths." (F7), plus the User, SetEnv and
    // RevokedHostKeys entries, which say so themselves.
    let env: Vec<KnownKeyword> = KnownKeyword::ALL
        .iter()
        .copied()
        .filter(|k| expands_env(*k))
        .collect();
    let mut expected = vec![
        KnownKeyword::CertificateFile,
        KnownKeyword::ControlPath,
        KnownKeyword::IdentityAgent,
        KnownKeyword::IdentityFile,
        KnownKeyword::Include,
        KnownKeyword::KnownHostsCommand,
        KnownKeyword::UserKnownHostsFile,
        KnownKeyword::LocalForward,
        KnownKeyword::RemoteForward,
        KnownKeyword::User,
        KnownKeyword::SetEnv,
        KnownKeyword::RevokedHostKeys,
    ];
    expected.sort();
    let mut env = env;
    env.sort();
    assert_eq!(env, expected);
}

#[test]
fn deprecated_aliases_map_and_retired_keywords_are_flagged() {
    // S01: "ChallengeResponseAuthentication is a deprecated alias for this" and "This
    // was formerly named HostbasedKeyTypes".
    assert_eq!(
        KnownKeyword::parse("ChallengeResponseAuthentication"),
        Some(KnownKeyword::KbdInteractiveAuthentication)
    );
    assert_eq!(
        KnownKeyword::parse("hostbasedkeytypes"),
        Some(KnownKeyword::HostbasedAcceptedAlgorithms)
    );
    assert_eq!(
        KnownKeyword::parse("PubkeyAcceptedKeyTypes"),
        Some(KnownKeyword::PubkeyAcceptedAlgorithms)
    );
    let s01: Vec<&str> = ALIASES
        .iter()
        .filter(|(_, _, p)| *p == Provenance::S01)
        .map(|(s, _, _)| *s)
        .collect();
    assert_eq!(
        s01,
        ["challengeresponseauthentication", "hostbasedkeytypes"]
    );
    // No alias shadows a canonical spelling.
    for (alias, _, _) in ALIASES {
        assert!(
            KnownKeyword::ALL
                .iter()
                .all(|k| !k.as_str().eq_ignore_ascii_case(alias))
        );
    }
    // The parser maps an alias to its option, and keeps a retired keyword unknown.
    let lines = parse("ChallengeResponseAuthentication no\nProtocol 2\nUseRoaming no\n");
    assert_eq!(
        directive_args(&lines[0]).0,
        Keyword::Known(KnownKeyword::KbdInteractiveAuthentication)
    );
    assert_eq!(
        directive_args(&lines[1]).0,
        Keyword::Unknown("Protocol".into())
    );
    assert_eq!(directive::obsolete("Protocol"), Some(Obsolete::Ignored));
    assert_eq!(
        directive::obsolete("UseRoaming"),
        Some(Obsolete::Deprecated)
    );
    assert_eq!(
        directive::obsolete("RSAAuthentication"),
        Some(Obsolete::Unsupported)
    );
    assert_eq!(directive::obsolete("NoSuchKeyword"), None);
    for (s, _) in directive::OBSOLETE {
        assert_eq!(KnownKeyword::parse(s), None, "{s}");
    }
}

// --- include semantics ------------------------------------------------------------------

#[test]
fn relative_include_resolves_under_user_or_system_directory() {
    let src = source()
        .with_file("/hm/home/.ssh/config", "Include conf.d/a.conf\n")
        .with_file("/hm/home/.ssh/conf.d/a.conf", "Port 1\n")
        .with_file("/hm/etc/ssh/ssh_config", "Include sys.d/b.conf\n")
        .with_file("/hm/etc/ssh/sys.d/b.conf", "Port 2\n")
        // Decoys beside the including files' other tree: never chosen.
        .with_file("/hm/etc/ssh/conf.d/a.conf", "Port 9\n")
        .with_file("/hm/home/.ssh/sys.d/b.conf", "Port 9\n");
    let roots = Roots {
        user: Some("/hm/home/.ssh/config".into()),
        system: Some("/hm/etc/ssh/ssh_config".into()),
    };
    let mut set = ConfigSet::new();
    let rec = record(&mut set, &src, &roots, &Limits::default(), &no_tokens);
    assert!(rec.failures.is_empty(), "{:?}", rec.failures);
    let visited: Vec<(&Path, Origin, usize)> = rec
        .visits
        .iter()
        .map(|v| (v.canonical.as_path(), v.origin, v.depth))
        .collect();
    assert_eq!(
        visited,
        [
            (Path::new("/hm/home/.ssh/config"), Origin::User, 0),
            (Path::new("/hm/home/.ssh/conf.d/a.conf"), Origin::User, 1),
            (Path::new("/hm/etc/ssh/ssh_config"), Origin::System, 0),
            (Path::new("/hm/etc/ssh/sys.d/b.conf"), Origin::System, 1),
        ]
    );
    assert_eq!(
        rec.includes[0].arg.pattern.as_deref(),
        Some(Path::new("/hm/home/.ssh/conf.d/a.conf"))
    );
    assert_eq!(
        rec.includes[1].arg.pattern.as_deref(),
        Some(Path::new("/hm/etc/ssh/sys.d/b.conf"))
    );
}

#[test]
fn f_file_is_a_user_file_and_its_relative_include_is_not_beside_it() {
    let src = source()
        .with_file("/hm/scratch/test_config", "Include extra.conf\n")
        .with_file("/hm/scratch/extra.conf", "Port 9\n")
        .with_file("/hm/home/.ssh/extra.conf", "Port 3\n");
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/scratch/test_config"),
        &Limits::default(),
        &no_tokens,
    );
    assert_eq!(
        rec.visits[1].canonical,
        PathBuf::from("/hm/home/.ssh/extra.conf")
    );
}

#[test]
fn tilde_and_absolute_include_paths() {
    let src = source();
    let user = |arg: &str| expand_include_arg(arg, Origin::User, &src, &no_tokens);
    assert_eq!(user("~/x.conf"), Ok(PathBuf::from("/hm/home/x.conf")));
    assert_eq!(user("~"), Ok(PathBuf::from("/hm/home")));
    assert_eq!(user("/abs/x.conf"), Ok(PathBuf::from("/abs/x.conf")));
    assert_eq!(user("~other/x"), Err(ArgError::TokenUnavailable('~')));
    assert_eq!(user(""), Err(ArgError::Invalid(InvalidArg::EmptyArgument)));
    assert_eq!(
        expand_include_arg("~/x", Origin::System, &src, &no_tokens),
        Err(ArgError::Invalid(InvalidArg::TildeInSystemFile))
    );
    assert_eq!(
        expand_include_arg("/abs/x", Origin::System, &src, &no_tokens),
        Ok(PathBuf::from("/abs/x"))
    );
}

#[test]
fn glob_results_come_in_bytewise_order() {
    // Inserted out of order; `B` (0x42) < `_` (0x5f) < `a` (0x61) < `b`; a `-` (0x2d)
    // sorts before `.` (0x2e). A case-insensitive or locale order would differ.
    let mut src = source().with_file("/hm/home/.ssh/config", "Include d/*.conf\n");
    for name in [
        "b.conf", "a.conf", "_x.conf", "B.conf", "a-b.conf", "a.b.conf",
    ] {
        src.insert(
            format!("/hm/home/.ssh/d/{name}"),
            MemEntry::File(b"Port 1\n".to_vec()),
        );
    }
    // A dotfile and a nested file do not match `*.conf`.
    src.insert(
        "/hm/home/.ssh/d/.hidden.conf",
        MemEntry::File(b"Port 9\n".to_vec()),
    );
    src.insert(
        "/hm/home/.ssh/d/sub/x.conf",
        MemEntry::File(b"Port 9\n".to_vec()),
    );
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    let order: Vec<String> = rec.visits[1..]
        .iter()
        .map(|v| {
            v.canonical
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        order,
        [
            "B.conf", "_x.conf", "a-b.conf", "a.b.conf", "a.conf", "b.conf"
        ]
    );
}

/// A source whose glob returns its matches reversed: the loader sorts anyway.
struct Reversed(MemSource);

impl ConfigSource for Reversed {
    fn read(&self, path: &Path) -> Result<heimdall_sshconf::include::SourceBytes, SourceError> {
        self.0.read(path)
    }
    fn glob(&self, pattern: &Path) -> Result<Vec<PathBuf>, SourceError> {
        let mut v = self.0.glob(pattern)?;
        v.reverse();
        v.push(v[0].clone());
        Ok(v)
    }
    fn account_home(&self) -> &Path {
        self.0.account_home()
    }
    fn user_dir(&self) -> &Path {
        self.0.user_dir()
    }
    fn system_dir(&self) -> &Path {
        self.0.system_dir()
    }
    fn env(&self, name: &str) -> Option<String> {
        self.0.env(name)
    }
}

#[test]
fn loader_sorts_and_dedups_whatever_the_source_returns() {
    let src = Reversed(
        source()
            .with_file("/hm/home/.ssh/config", "Include d/*\n")
            .with_file("/hm/home/.ssh/d/1", "Port 1\n")
            .with_file("/hm/home/.ssh/d/2", "Port 2\n")
            .with_file("/hm/home/.ssh/d/3", "Port 3\n"),
    );
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    let matches = rec.includes[0].arg.matches.as_ref().unwrap();
    assert_eq!(
        matches,
        &[
            "/hm/home/.ssh/d/1",
            "/hm/home/.ssh/d/2",
            "/hm/home/.ssh/d/3"
        ]
        .map(PathBuf::from)
        .to_vec()
    );
}

#[test]
fn unset_env_in_include_is_recorded_env_unset() {
    let src = source()
        .with_env("HM_SET", "/hm/home/set")
        .with_file(
            "/hm/home/.ssh/config",
            "Include ${HM_UNSET}/x.conf ${HM_SET}/y.conf\n",
        )
        .with_file("/hm/home/set/y.conf", "Port 1\n");
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    assert_eq!(rec.includes.len(), 2);
    assert_eq!(
        rec.includes[0].arg.matches,
        Err(ArgError::EnvUnset("HM_UNSET".into()))
    );
    assert_eq!(rec.includes[0].arg.pattern, None);
    assert_eq!(
        rec.includes[0].span,
        Span {
            source: SourceId(0),
            line: 1
        }
    );
    // The second argument still resolves.
    assert_eq!(
        rec.visits.last().unwrap().canonical,
        PathBuf::from("/hm/home/set/y.conf")
    );
}

#[test]
fn expansion_follows_openssh_rules() {
    let src = source().with_env("V", "%h${W}");
    let tok = |t: char| (t == 'h').then(|| "host.test".to_owned());
    let inc = |s: &str| expand(s, KnownKeyword::Include, &src, &tok);
    // %% is a literal %, a variable's value is not expanded again, `$` alone is data.
    assert_eq!(inc("a%%b"), Ok("a%b".into()));
    assert_eq!(inc("${V}"), Ok("%h${W}".into()));
    assert_eq!(inc("%h/$x"), Ok("host.test/$x".into()));
    // %d falls back to the account home (F19).
    assert_eq!(inc("%d/c"), Ok("/hm/home/c".into()));
    // Unknown statically, unset, refused.
    assert_eq!(inc("%u"), Err(ArgError::TokenUnavailable('u')));
    assert_eq!(inc("${NOPE}"), Err(ArgError::EnvUnset("NOPE".into())));
    assert_eq!(
        inc("%z"),
        Err(ArgError::Invalid(InvalidArg::UnknownToken('z')))
    );
    assert_eq!(
        inc("a%"),
        Err(ArgError::Invalid(InvalidArg::TrailingPercent))
    );
    assert_eq!(
        inc("${A"),
        Err(ArgError::Invalid(InvalidArg::UnterminatedVariable))
    );
    assert_eq!(
        inc("${}"),
        Err(ArgError::Invalid(InvalidArg::EmptyVariable))
    );
    // A refusal anywhere wins over an earlier unresolved value.
    assert_eq!(
        inc("${NOPE}%z"),
        Err(ArgError::Invalid(InvalidArg::UnknownToken('z')))
    );
    // A keyword without tokens or variables keeps the text.
    assert_eq!(
        expand("a%z${X}", KnownKeyword::Port, &src, &tok),
        Ok("a%z${X}".into())
    );
    // Hostname takes %h only, and no variables.
    assert_eq!(
        expand("%h", KnownKeyword::Hostname, &src, &tok),
        Ok("host.test".into())
    );
    assert_eq!(
        expand("%p", KnownKeyword::Hostname, &src, &tok),
        Err(ArgError::Invalid(InvalidArg::UnknownToken('p')))
    );
    assert_eq!(
        expand("${V}", KnownKeyword::Hostname, &src, &tok),
        Ok("${V}".into())
    );
}

#[test]
fn include_cycle_is_detected() {
    // Direct, indirect, and through a symlink to an including file.
    let src = source()
        .with_file(
            "/hm/home/.ssh/config",
            "Include self.conf a.conf link.conf\n",
        )
        .with_file("/hm/home/.ssh/self.conf", "Include self.conf\n")
        .with_file("/hm/home/.ssh/a.conf", "Include b.conf\n")
        .with_file("/hm/home/.ssh/b.conf", "Include a.conf\n")
        .with_entry(
            "/hm/home/.ssh/link.conf",
            MemEntry::Symlink("config".into()),
        );
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    let cycles: Vec<&Path> = rec
        .failures
        .iter()
        .filter(|f| f.error == IncludeError::Cycle)
        .map(|f| f.path.as_path())
        .collect();
    assert_eq!(
        cycles,
        [
            Path::new("/hm/home/.ssh/self.conf"),
            Path::new("/hm/home/.ssh/a.conf"),
            Path::new("/hm/home/.ssh/link.conf"),
        ]
    );
    assert_eq!(rec.failures.len(), 3);
}

#[test]
fn include_in_a_section_that_does_not_apply_is_still_read() {
    // OpenSSH parses included files even when the Include is inside a Host block that
    // does not match: the walk always descends, and the evaluator decides activity.
    let src = source()
        .with_file(
            "/hm/home/.ssh/config",
            "Host never.example\n  Include inner.conf\nHost *\n",
        )
        .with_file("/hm/home/.ssh/inner.conf", "Port 1\n");
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    assert_eq!(rec.visits.len(), 2);
    assert_eq!(rec.visits[1].depth, 1);
}

/// Logs the visitor callbacks, to check the reading order an evaluator sees.
#[derive(Default)]
struct Log(Vec<String>);

impl IncludeVisitor for Log {
    fn enter(&mut self, v: &Visit) {
        self.0.push(format!("enter {}", v.canonical.display()));
    }
    fn line(&mut self, v: &Visit, line: &Line) {
        self.0.push(format!(
            "line {}:{}",
            v.canonical.display(),
            line.span_line()
        ));
    }
    fn include(
        &mut self,
        _: &Visit,
        span: heimdall_sshconf::parse::Span,
        arg: &heimdall_sshconf::include::IncludeArg,
    ) {
        self.0
            .push(format!("include {} {}", span.line, arg.written));
    }
    fn leave(&mut self, v: &Visit) {
        self.0.push(format!("leave {}", v.canonical.display()));
    }
}

trait SpanLine {
    fn span_line(&self) -> u32;
}

impl SpanLine for Line {
    fn span_line(&self) -> u32 {
        match self {
            Line::Blank(s) | Line::Comment(s) | Line::Invalid { span: s, .. } => s.line,
            Line::Directive(d) => d.span.line,
        }
    }
}

#[test]
fn walk_reports_in_reading_order_and_restores_after_each_file() {
    let src = source()
        .with_file("/hm/home/.ssh/config", "Include d/*\nPort 1\n")
        .with_file("/hm/home/.ssh/d/x", "Host x\n")
        .with_file("/hm/home/.ssh/d/y", "Host y\n");
    let mut set = ConfigSet::new();
    let mut log = Log::default();
    let summary = walk(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &mut log,
    );
    assert_eq!(summary.visits, 3);
    assert_eq!(
        log.0,
        [
            "enter /hm/home/.ssh/config",
            "line /hm/home/.ssh/config:1",
            "include 1 d/*",
            "enter /hm/home/.ssh/d/x",
            "line /hm/home/.ssh/d/x:1",
            "leave /hm/home/.ssh/d/x",
            "enter /hm/home/.ssh/d/y",
            "line /hm/home/.ssh/d/y:1",
            "leave /hm/home/.ssh/d/y",
            "line /hm/home/.ssh/config:2",
            "leave /hm/home/.ssh/config",
        ]
    );
}

#[test]
fn cache_reads_each_path_once_and_shares_symlinked_files() {
    let src = source()
        .with_file(
            "/hm/home/.ssh/config",
            "Host a\n Include common.conf\nHost b\n Include common.conf alias.conf\n",
        )
        .with_file("/hm/home/.ssh/common.conf", "Port 1\n")
        .with_entry(
            "/hm/home/.ssh/alias.conf",
            MemEntry::Symlink("common.conf".into()),
        );
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    assert!(rec.failures.is_empty());
    // Four visits (the root, common twice, the alias once), three reads, two files.
    assert_eq!(rec.summary.visits, 4);
    assert_eq!(src.reads(), 3);
    assert_eq!(set.len(), 2);
    let common = set
        .canonical(Path::new("/hm/home/.ssh/alias.conf"))
        .unwrap();
    assert_eq!(common, Path::new("/hm/home/.ssh/common.conf"));
    let id = set.get(common).unwrap().source;
    assert_eq!(set.path_of(id), Some(common));
    // Every visit of the shared file has the same id.
    let ids: Vec<SourceId> = rec.visits[1..].iter().map(|v| v.source).collect();
    assert_eq!(ids, [id, id, id]);
    // load() on a cached path does not read again.
    set.load(
        &src,
        Path::new("/hm/home/.ssh/common.conf"),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(src.reads(), 3);
}

#[test]
fn missing_root_and_missing_literal_include() {
    let src = source().with_file("/hm/home/.ssh/config", "Include absent.conf\n");
    let mut set = ConfigSet::new();
    // A literal include that does not exist matches nothing and is skipped (OpenSSH
    // debug "matched no files"), but a root the caller named is reported.
    let roots = Roots {
        user: Some("/hm/home/.ssh/config".into()),
        system: Some("/hm/etc/ssh/ssh_config".into()),
    };
    let rec = record(&mut set, &src, &roots, &Limits::default(), &no_tokens);
    assert_eq!(rec.includes[0].arg.matches, Ok(vec![]));
    assert_eq!(rec.failures.len(), 1);
    assert_eq!(rec.failures[0].at, None);
    assert_eq!(rec.failures[0].origin, Origin::System);
    assert_eq!(
        rec.failures[0].error,
        IncludeError::Unreadable(SourceError::NotFound)
    );
    // load() never treats a missing file as empty.
    assert_eq!(
        set.load(&src, Path::new("/hm/nowhere"), &Limits::default())
            .err(),
        Some(IncludeError::Unreadable(SourceError::NotFound))
    );
}

#[test]
fn include_tokens_come_from_the_visitor() {
    let src = source()
        .with_file(
            "/hm/home/.ssh/config",
            "Include hosts/%h.conf hosts/%u.conf\n",
        )
        .with_file("/hm/home/.ssh/hosts/alias1.conf", "Port 1\n");
    let mut set = ConfigSet::new();
    let tok = |t: char| (t == 'h').then(|| "alias1".to_owned());
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &tok,
    );
    assert_eq!(
        rec.visits[1].canonical,
        PathBuf::from("/hm/home/.ssh/hosts/alias1.conf")
    );
    assert_eq!(
        rec.includes[1].arg.matches,
        Err(ArgError::TokenUnavailable('u'))
    );
}

#[test]
fn every_parse_of_an_include_keeps_spans_per_file() {
    let src = source()
        .with_file("/hm/home/.ssh/config", "\nInclude a\nHost z\n")
        .with_file("/hm/home/.ssh/a", "\n\nPort 3\n");
    let mut set = ConfigSet::new();
    let rec = record(
        &mut set,
        &src,
        &user_root("/hm/home/.ssh/config"),
        &Limits::default(),
        &no_tokens,
    );
    let root = set.get(Path::new("/hm/home/.ssh/config")).unwrap();
    let inc = set.get(Path::new("/hm/home/.ssh/a")).unwrap();
    assert_ne!(root.source, inc.source);
    assert_eq!(
        rec.includes[0].span,
        Span {
            source: root.source,
            line: 2
        }
    );
    match &inc.lines[2] {
        Line::Directive(d) => assert_eq!(
            d.span,
            Span {
                source: inc.source,
                line: 3
            }
        ),
        other => panic!("{other:?}"),
    }
}

// --- the MemSource matcher against the glob crate (differential) -------------------------

/// Pattern atoms (`glob(3)` syntax the glob crate shares; no `\\` escapes, no `**`),
/// each with characters it is meant to match. The hints only bias generation toward
/// near-matches; the glob crate stays the oracle.
const ATOMS: &[(&str, &str)] = &[
    ("a", "a"),
    ("b", "b"),
    (".", "."),
    ("-", "-"),
    ("*", "ab.]"),
    ("?", "a.]!"),
    ("[ab]", "ab"),
    ("[!a]", "b.]!"),
    ("[a-c]", "abc"),
    ("[]a]", "]a"),
    ("[.]", "."),
    ("[!]]", "a.-"),
    ("[-a]", "-a"),
    ("[a-]", "a-"),
];

fn name_char() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('a'),
        Just('b'),
        Just('c'),
        Just('.'),
        Just(']'),
        Just('-'),
        Just('!')
    ]
}

/// One component as `(pattern, name)`: each atom is paired with an instantiation, a
/// character from its hints three times in four and a random one otherwise (zero to
/// two characters for `*`), so most names nearly match their pattern and every atom's
/// edge (negation, ranges, a leading `]`, the leading-dot rule) is reached.
fn component() -> impl Strategy<Value = (String, String)> {
    proptest::collection::vec(
        (
            proptest::sample::select(ATOMS),
            proptest::collection::vec(
                (0u8..4, any::<proptest::sample::Index>(), name_char()),
                0..3,
            ),
        ),
        1..4,
    )
    .prop_map(|atoms| {
        let mut pattern = String::new();
        let mut name = String::new();
        for ((atom, hints), picks) in atoms {
            pattern.push_str(atom);
            let take = if atom == "*" {
                picks.len()
            } else {
                1.min(picks.len())
            };
            let hints: Vec<char> = hints.chars().collect();
            for (bias, index, random) in picks.into_iter().take(take) {
                name.push(if bias == 0 {
                    random
                } else {
                    *index.get(&hints)
                });
            }
        }
        (pattern, name)
    })
}

/// A path pattern and a name built component by component (`/`-joined), with the
/// component counts occasionally differing.
fn pattern_and_name() -> impl Strategy<Value = (String, String)> {
    (proptest::collection::vec(component(), 1..4), 0usize..4).prop_map(|(parts, skew)| {
        let (p, mut n): (Vec<String>, Vec<String>) = parts.into_iter().unzip();
        match skew {
            0 => n.push("a".into()),
            1 if n.len() > 1 => {
                n.pop();
            }
            _ => {}
        }
        (p.join("/"), n.join("/"))
    })
}

proptest! {
    #![proptest_config(config_with(1024))]

    /// The `MemSource` matcher agrees with `glob::Pattern` (the crate `localenv` uses for
    /// real Include expansion) with `glob(3)`'s options: literal separator, literal
    /// leading dot, case-sensitive. Patterns the crate treats specially (`**`) or
    /// rejects are skipped.
    #[test]
    fn mem_source_matcher_agrees_with_the_glob_crate((pattern, name) in pattern_and_name()) {
        prop_assume!(!pattern.contains("**"));
        let Ok(reference) = glob::Pattern::new(&pattern) else { return Ok(()); };
        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };
        prop_assert_eq!(
            glob_match(&pattern, &name),
            reference.matches_with(&name, options),
            "pattern {:?} name {:?}", pattern, name
        );
    }
}

proptest! {
    #![proptest_config(config())]

    /// Splitting is stable under the parser: a line's directive equals `split_args`.
    #[test]
    fn parser_agrees_with_split_args(line in "[ -~\t]{0,40}") {
        let lines = parse_file(SourceId(0), line.as_bytes(), &Limits::default()).unwrap().lines;
        let split = split_args(&line);
        match (lines.first(), split) {
            (None, Ok(v)) => prop_assert!(v.is_empty()),
            (Some(Line::Blank(_) | Line::Comment(_)), Ok(v)) => prop_assert!(v.is_empty()),
            (Some(Line::Directive(d)), Ok(v)) => {
                prop_assert_eq!(&d.args[..], &v[1..]);
                prop_assert_eq!(d.keyword.clone(), directive::keyword(&v[0]));
            }
            (Some(Line::Invalid { error, .. }), Err(e)) => prop_assert_eq!(error, &e),
            (l, s) => prop_assert!(false, "parser {:?} lexer {:?}", l, s),
        }
    }
}

// --- the inert corpus (tests/fixtures/sshconf/corpus) ------------------------------------

const CORPUS_HEADER: &str = "# inert, ssh -G only";
/// Where the corpus is mounted in the in-memory source (`@CORPUS_DIR@`).
const CORPUS_MOUNT: &str = "/hm/corpus";

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/sshconf/corpus")
}

/// Every corpus file as (path relative to the corpus, bytes), README excluded.
fn corpus_files() -> Vec<(String, Vec<u8>)> {
    fn walk_dir(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk_dir(base, &path, out);
            } else if path.extension().is_some_and(|e| e == "conf") {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    let base = corpus_dir();
    let mut out = Vec::new();
    walk_dir(&base, &base, &mut out);
    out
}

fn corpus_source() -> MemSource {
    let mut src = source();
    for (rel, bytes) in corpus_files() {
        let text = String::from_utf8(bytes)
            .unwrap()
            .replace("@CORPUS_DIR@", CORPUS_MOUNT);
        src.insert(
            format!("{CORPUS_MOUNT}/{rel}"),
            MemEntry::File(text.into_bytes()),
        );
    }
    src
}

#[test]
fn corpus_files_are_inert_and_self_contained() {
    let files = corpus_files();
    assert!(files.len() >= 16, "{}", files.len());
    let executing = [
        KnownKeyword::ProxyCommand,
        KnownKeyword::LocalCommand,
        KnownKeyword::PermitLocalCommand,
        KnownKeyword::KnownHostsCommand,
        KnownKeyword::CanonicalizeHostname,
    ];
    for (rel, bytes) in &files {
        let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        assert!(body.starts_with(CORPUS_HEADER.as_bytes()), "{rel}: header");
        let file = parse_file(SourceId(0), bytes, &Limits::default()).unwrap();
        assert_eq!(file.had_bom, rel == "bom.conf", "{rel}");
        assert_eq!(file.crlf, rel == "crlf.conf", "{rel}");
        for line in &file.lines {
            let d = match line {
                Line::Directive(d) => d,
                Line::Blank(_) | Line::Comment(_) => continue,
                Line::Invalid { .. } => panic!("{rel}: {line:?}"),
            };
            match &d.keyword {
                Keyword::Known(k) => {
                    assert!(!executing.contains(k), "{rel}:{} {k:?}", d.span.line);
                    if *k == KnownKeyword::Match {
                        for arg in &d.args {
                            let criterion = arg.trim_start_matches('!').to_ascii_lowercase();
                            assert!(
                                !["exec", "localnetwork", "canonical", "final"]
                                    .contains(&criterion.as_str()),
                                "{rel}:{} Match {arg}",
                                d.span.line
                            );
                        }
                    }
                    if *k == KnownKeyword::Include {
                        for arg in &d.args {
                            assert!(
                                arg.starts_with("@CORPUS_DIR@/include/"),
                                "{rel}: Include {arg}"
                            );
                        }
                    }
                    if matches!(
                        k,
                        KnownKeyword::IdentityFile
                            | KnownKeyword::CertificateFile
                            | KnownKeyword::IdentityAgent
                    ) {
                        let v = &d.args[0];
                        assert!(
                            v == "none"
                                || v.starts_with("/nonexistent/hm-corpus/")
                                || v.starts_with("/nonexistent/hm corpus/")
                                || v.starts_with("//./pipe/hm"),
                            "{rel}: {k:?} {v}"
                        );
                    }
                }
                Keyword::Unknown(s) => assert!(
                    (rel == "unsupported.conf" && s.starts_with("HmCorpusUnknown"))
                        || (rel == "retired.conf" && directive::obsolete(s).is_some()),
                    "{rel}: unknown keyword {s}"
                ),
                Keyword::Unreadable => panic!("{rel}: unreadable line {}", d.span.line),
            }
        }
    }
}

#[test]
fn corpus_roots_walk_cleanly_in_bytewise_order() {
    let src = corpus_source();
    let roots: Vec<String> = corpus_files()
        .into_iter()
        .map(|(rel, _)| rel)
        .filter(|rel| !rel.contains('/'))
        .collect();
    assert!(roots.len() >= 9, "{roots:?}");
    for root in &roots {
        let mut set = ConfigSet::new();
        let rec = record(
            &mut set,
            &src,
            &user_root(&format!("{CORPUS_MOUNT}/{root}")),
            &Limits::default(),
            &no_tokens,
        );
        assert!(rec.failures.is_empty(), "{root}: {:?}", rec.failures);
        for inc in &rec.includes {
            assert!(
                !inc.arg.matches.as_ref().unwrap().is_empty(),
                "{root}: {:?}",
                inc.arg
            );
        }
        if root == "nested.conf" {
            let order: Vec<String> = rec
                .visits
                .iter()
                .map(|v| {
                    v.canonical
                        .to_string_lossy()
                        .trim_start_matches(CORPUS_MOUNT)
                        .to_owned()
                })
                .collect();
            assert_eq!(
                order,
                [
                    "/nested.conf",
                    "/include/nested/level1.conf",
                    "/include/nested/d/10-first.conf",
                    "/include/nested/d/20-second.conf",
                    "/include/nested/level3.conf",
                    "/include/nested/d/B-upper.conf",
                    "/include/nested/d/a-lower.conf",
                ]
            );
            assert_eq!(rec.visits.iter().map(|v| v.depth).max(), Some(3));
        }
    }
}

#[test]
fn corpus_lexer_file_splits_as_ssh_g_printed() {
    // `ssh -G -F lexer.conf <alias>` on OpenSSH_10.3p1 (macOS) printed, during
    // M02-W1-U1: hostname a#b; user u v; port 2290 and user =eq; user a b; user a\nb;
    // remotecommand echo '$X'  "q"  # c. The U3 corpus test repeats this per client.
    let bytes = std::fs::read(corpus_dir().join("lexer.conf")).unwrap();
    let file = parse_file(SourceId(0), &bytes, &Limits::default()).unwrap();
    let mut host = String::new();
    let mut got = Vec::new();
    for line in &file.lines {
        let Line::Directive(d) = line else { continue };
        match &d.keyword {
            Keyword::Known(KnownKeyword::Host) => host = d.args.join(" "),
            Keyword::Known(k) => got.push((host.clone(), *k, d.args.clone())),
            other => panic!("{other:?}"),
        }
    }
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        got,
        [
            ("lex-hash".to_owned(), KnownKeyword::Hostname, s(&["a#b"])),
            ("lex-quote".to_owned(), KnownKeyword::User, s(&["u v"])),
            ("lex-equals".to_owned(), KnownKeyword::Port, s(&["2290"])),
            ("lex-equals".to_owned(), KnownKeyword::User, s(&["=eq"])),
            ("lex-escape".to_owned(), KnownKeyword::User, s(&["a b"])),
            (
                "lex-unknown-escape".to_owned(),
                KnownKeyword::User,
                s(&[r"a\nb"])
            ),
            // OpenSSH keeps the raw rest of the line for a command keyword; the frozen
            // `Directive` has only split arguments, which drop the quoting and comment
            // (escalated in the M02-W1-U1 report).
            (
                "lex-command".to_owned(),
                KnownKeyword::RemoteCommand,
                s(&["echo", "$X", "q"])
            ),
        ]
    );
}
