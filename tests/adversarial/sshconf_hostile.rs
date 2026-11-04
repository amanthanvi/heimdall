//! `heimdall-sshconf` under hostile configuration input (M02-U1; m02-plan U1
//! "adversarial"; ADR-0007 §6 "bounded and hostile-input safe"; spec R-SE-05).
//!
//! Cargo test target `adversarial_sshconf_hostile` hosted by `heimdall-sshconf`. Pure:
//! every source is an in-memory `MemSource`, which has no way to run anything, so a
//! configuration's commands stay data. The real-filesystem FIFO case
//! (`a21_fifo_include_does_not_block`) is U3's; here the fake reports `NotRegular`.
//! Reproduce a property failure with `PROPTEST_RNG_SEED=<seed>`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::eval::{
    Invocation, OpenSshVersion, Query, Resolved, SourceRole, Value, evaluate,
};
use heimdall_sshconf::include::{
    ArgError, ConfigSet, IncludeError, MemEntry, MemSource, Roots, SourceError, WalkRecord, record,
};
use heimdall_sshconf::lex::split_args;
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::{Line, ParseError, SourceId, parse_file};
use heimdall_sshconf::relevant::{behavior_digest, executing_constructs, relevant};
use heimdall_sshconf::render::{MarkerId, Newline, PathStyle, RenderPath, render_include_block};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const ROOT: &str = "/hm/home/.ssh/config";

fn source() -> MemSource {
    MemSource::new("/hm/home", "/hm/home/.ssh", "/hm/etc/ssh")
}

fn walk_user(src: &MemSource, limits: &Limits) -> (ConfigSet, WalkRecord) {
    let mut set = ConfigSet::new();
    let roots = Roots::new(Some(PathBuf::from(ROOT)), None);
    let rec = record(&mut set, src, &roots, limits, &|_| None);
    (set, rec)
}

/// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
fn config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5531_5f48_4f53_5449);
    }
    c
}

// --- size bounds ------------------------------------------------------------------------

#[test]
fn oversized_file_is_refused_whole() {
    let limits = Limits::default();
    let mut big = b"Port 22\n".repeat(limits.file_bytes / 8);
    assert_eq!(big.len(), limits.file_bytes);
    assert!(parse_file(SourceId(0), &big, &limits).is_ok());
    big.push(b'\n');
    assert_eq!(
        parse_file(SourceId(0), &big, &limits),
        Err(ParseError::FileTooLarge)
    );

    // Through the loader it is a bound (never a truncated file) and is not cached.
    let src = source().with_file(ROOT, big);
    let mut set = ConfigSet::new();
    let err = set.load(&src, Path::new(ROOT), &limits).unwrap_err();
    assert_eq!(err, IncludeError::BoundExceeded);
    assert!(err.is_bound());
    assert!(set.is_empty());
}

#[test]
fn oversized_line_is_refused_with_its_line_number() {
    let limits = Limits::default();
    let at_bound = format!("Host a\nHostName {}\n", "x".repeat(limits.line_bytes - 9));
    assert!(parse_file(SourceId(0), at_bound.as_bytes(), &limits).is_ok());
    // CRLF does not count toward the bound.
    let crlf = at_bound.replace('\n', "\r\n");
    assert!(parse_file(SourceId(0), crlf.as_bytes(), &limits).is_ok());
    let over = format!("Host a\nHostName {}\n", "x".repeat(limits.line_bytes - 8));
    assert_eq!(
        parse_file(SourceId(0), over.as_bytes(), &limits),
        Err(ParseError::LineTooLong { line: 2 })
    );
    // Through an include it is a bound, reported where the Include is.
    let src = source()
        .with_file(ROOT, "Include long.conf\nPort 1\n")
        .with_file("/hm/home/.ssh/long.conf", over);
    let (_, rec) = walk_user(&src, &limits);
    assert_eq!(rec.failures.len(), 1);
    assert_eq!(
        rec.failures[0].error,
        IncludeError::Parse(ParseError::LineTooLong { line: 2 })
    );
    assert!(rec.failures[0].error.is_bound());
    assert_eq!(rec.failures[0].at.map(|s| s.line), Some(1));
}

#[test]
fn total_bytes_bound_over_every_read() {
    let limits = Limits {
        total_bytes: 64,
        ..Limits::default()
    };
    let body = format!("#{}\n", "x".repeat(30)); // 32 bytes
    let src = source()
        .with_file(ROOT, "Include a b c\n") // 14 bytes
        .with_file("/hm/home/.ssh/a", body.clone())
        .with_file("/hm/home/.ssh/b", body.clone())
        .with_file("/hm/home/.ssh/c", body);
    let (_, rec) = walk_user(&src, &limits);
    // 14 + 32 = 46 fits, + 32 = 78 does not, and neither does the third.
    assert_eq!(rec.visits.len(), 2);
    assert_eq!(rec.summary.bytes, 46);
    let errors: Vec<&IncludeError> = rec.failures.iter().map(|f| &f.error).collect();
    assert_eq!(
        errors,
        [&IncludeError::BoundExceeded, &IncludeError::BoundExceeded]
    );

    // The bound is over reads, not over the cache: one 32-byte file included three
    // times is cached once (46 bytes) but read three times (14 + 3 * 32 = 110).
    let src = source()
        .with_file(ROOT, "Include a a a\n") // 14 bytes
        .with_file("/hm/home/.ssh/a", format!("#{}\n", "x".repeat(30)));
    let (set, rec) = walk_user(&src, &limits);
    assert_eq!(set.loaded_bytes(), 46);
    assert_eq!(rec.visits.len(), 2);
    assert_eq!(rec.summary.bytes, 46);
    assert_eq!(rec.failures.len(), 2);
    assert!(
        rec.failures
            .iter()
            .all(|f| f.error == IncludeError::BoundExceeded)
    );
}

// --- depth and count bounds ----------------------------------------------------------------

fn chain(depth: usize) -> MemSource {
    // config (depth 0) -> f1 (1) -> ... -> f<depth> (depth).
    let mut src = source().with_file(ROOT, "Include f1\n");
    for i in 1..=depth {
        src.insert(
            format!("/hm/home/.ssh/f{i}"),
            MemEntry::File(format!("Include f{}\nPort {i}\n", i + 1).into_bytes()),
        );
    }
    src
}

#[test]
fn include_depth_16_loads_and_depth_17_is_a_bound() {
    let limits = Limits::default();
    assert_eq!(limits.depth, 16);
    // Files f1..f16: the deepest is at depth 16, and its `Include f17` matches nothing.
    let (_, rec) = walk_user(&chain(16), &limits);
    assert!(rec.failures.is_empty(), "{:?}", rec.failures);
    assert_eq!(rec.visits.iter().map(|v| v.depth).max(), Some(16));
    // f17 exists: depth 17 is refused, recorded at f16's Include, and nothing deeper is
    // read.
    let src = chain(17);
    let (_, rec) = walk_user(&src, &limits);
    assert_eq!(rec.visits.len(), 17);
    assert_eq!(rec.failures.len(), 1);
    assert_eq!(rec.failures[0].error, IncludeError::BoundExceeded);
    assert_eq!(rec.failures[0].path, PathBuf::from("/hm/home/.ssh/f17"));
    assert_eq!(src.reads(), 17);
}

#[test]
fn file_count_256_loads_and_the_257th_is_a_bound() {
    let limits = Limits::default();
    assert_eq!(limits.files, 256);
    let make = |n: usize| {
        let mut src = source().with_file(ROOT, "Include a/* b/*\n");
        for i in 0..n {
            let dir = if i % 2 == 0 { "a" } else { "b" };
            src.insert(
                format!("/hm/home/.ssh/{dir}/{i:03}"),
                MemEntry::File(b"Port 1\n".to_vec()),
            );
        }
        src
    };
    // Root + 255 = 256 reads.
    let (set, rec) = walk_user(&make(255), &limits);
    assert!(rec.failures.is_empty());
    assert_eq!(rec.summary.visits, 256);
    assert_eq!(set.len(), 256);
    // Root + 256 = 257: the last match is refused.
    let src = make(256);
    let (set, rec) = walk_user(&src, &limits);
    assert_eq!(rec.summary.visits, 256);
    assert_eq!(rec.failures.len(), 1);
    assert_eq!(rec.failures[0].error, IncludeError::BoundExceeded);
    assert_eq!(rec.failures[0].path, PathBuf::from("/hm/home/.ssh/b/255"));
    assert_eq!(set.len(), 256);
    // The refused file was never read.
    assert_eq!(src.reads(), 256);
}

#[test]
fn repeated_inclusion_counts_every_read() {
    // One small file included 300 times: OpenSSH reads it each time, so the walk is
    // bounded by reads, not by distinct files (no 256^16 blow-up).
    let lines: String = (0..300)
        .map(|i| format!("Host h{i}\n Include common\n"))
        .collect();
    let src = source()
        .with_file(ROOT, lines)
        .with_file("/hm/home/.ssh/common", "Port 1\n");
    let (set, rec) = walk_user(&src, &Limits::default());
    assert_eq!(rec.summary.visits, 256);
    assert_eq!(rec.failures.len(), 300 - 255);
    assert!(
        rec.failures
            .iter()
            .all(|f| f.error == IncludeError::BoundExceeded)
    );
    assert_eq!(set.len(), 2);
}

#[test]
fn glob_explosion_is_a_bound_and_reads_nothing() {
    let limits = Limits::default();
    assert_eq!(limits.glob_results, 256);
    let make = |n: usize| {
        let mut src = source().with_file(ROOT, "Include d/*\n");
        for i in 0..n {
            src.insert(
                format!("/hm/home/.ssh/d/{i:04}"),
                MemEntry::File(b"Port 1\n".to_vec()),
            );
        }
        src
    };
    let small = Limits {
        files: 1024,
        ..Limits::default()
    };
    let (_, rec) = walk_user(&make(256), &small);
    assert!(rec.failures.is_empty());
    assert_eq!(rec.includes[0].arg.matches.as_ref().map(Vec::len), Ok(256));

    let src = make(257);
    let (_, rec) = walk_user(&src, &small);
    assert_eq!(
        rec.includes[0].arg.matches,
        Err(ArgError::Glob(IncludeError::BoundExceeded))
    );
    assert_eq!(rec.visits.len(), 1);
    assert_eq!(src.reads(), 1);
}

// --- bytes the parser refuses or does not guess about ----------------------------------------

#[test]
fn nul_byte_refuses_the_whole_file() {
    let bytes = b"Host a\nHostName x\0evil\nPort 22\n";
    assert_eq!(
        parse_file(SourceId(0), bytes, &Limits::default()),
        Err(ParseError::NulByte { line: 2 })
    );
    // Also in a comment: OpenSSH's C strings would cut the line there.
    assert_eq!(
        parse_file(SourceId(0), b"# a\0b\n", &Limits::default()),
        Err(ParseError::NulByte { line: 1 })
    );
    let src = source()
        .with_file(ROOT, "Include nul.conf\n")
        .with_file("/hm/home/.ssh/nul.conf", bytes.to_vec());
    let (_, rec) = walk_user(&src, &Limits::default());
    assert_eq!(
        rec.failures[0].error,
        IncludeError::Parse(ParseError::NulByte { line: 2 })
    );
    assert!(!rec.failures[0].error.is_bound());
}

#[test]
fn invalid_utf8_in_a_comment_versus_in_a_value() {
    let bytes = b"# caf\xe9\nHostName caf\xe9.example\nPort 22 # caf\xe9\n\xff\xfe x\n";
    let file = parse_file(SourceId(0), bytes, &Limits::default()).unwrap();
    assert_eq!(file.lines.len(), 4);
    // A comment line may hold any bytes.
    assert!(matches!(file.lines[0], Line::Comment(_)));
    // A value that is not UTF-8 makes the directive unreadable, with nothing guessed.
    match &file.lines[1] {
        Line::Directive(d) => {
            assert_eq!(d.keyword, Keyword::Unreadable);
            assert!(d.args.is_empty());
            assert_eq!(d.span.line, 2);
        }
        other => panic!("{other:?}"),
    }
    // Bytes after a comment start never reach OpenSSH, so the directive is exact.
    match &file.lines[2] {
        Line::Directive(d) => {
            assert_eq!(d.keyword, Keyword::Known(KnownKeyword::Port));
            assert_eq!(d.args, ["22"]);
        }
        other => panic!("{other:?}"),
    }
    // A keyword that is not UTF-8.
    match &file.lines[3] {
        Line::Directive(d) => assert_eq!(d.keyword, Keyword::Unreadable),
        other => panic!("{other:?}"),
    }
}

#[test]
fn include_of_a_fifo_a_directory_or_an_unreadable_file_is_recorded() {
    let src = source()
        .with_file(ROOT, "Include fifo dir denied d/*\nPort 1\n")
        .with_entry("/hm/home/.ssh/fifo", MemEntry::Fifo)
        .with_entry("/hm/home/.ssh/dir", MemEntry::Directory)
        .with_entry("/hm/home/.ssh/denied", MemEntry::Denied)
        .with_entry("/hm/home/.ssh/d/pipe", MemEntry::Fifo)
        .with_file("/hm/home/.ssh/d/ok", "Port 2\n");
    let (_, rec) = walk_user(&src, &Limits::default());
    let failures: Vec<(&Path, &IncludeError)> = rec
        .failures
        .iter()
        .map(|f| (f.path.as_path(), &f.error))
        .collect();
    assert_eq!(
        failures,
        [
            (
                Path::new("/hm/home/.ssh/fifo"),
                &IncludeError::Unreadable(SourceError::NotRegular)
            ),
            (
                Path::new("/hm/home/.ssh/dir"),
                &IncludeError::Unreadable(SourceError::NotRegular)
            ),
            (
                Path::new("/hm/home/.ssh/denied"),
                &IncludeError::Unreadable(SourceError::PermissionDenied)
            ),
            (
                Path::new("/hm/home/.ssh/d/pipe"),
                &IncludeError::Unreadable(SourceError::NotRegular)
            ),
        ]
    );
    // The walk goes on: the glob's regular file and the root's next line are read.
    assert_eq!(rec.visits.len(), 2);
    assert_eq!(rec.visits[1].canonical, PathBuf::from("/hm/home/.ssh/d/ok"));
}

#[test]
fn shell_metacharacters_in_values_stay_data() {
    // Nothing here is executed: the crate has no API that runs anything, and the
    // MemSource only stores bytes. The arguments come back exactly as OpenSSH would
    // pass them on.
    let text = concat!(
        "Match exec \"touch /tmp/hm-never; $(id) `id` | nc %h %p\" host *\n",
        "  ProxyCommand sh -c 'echo $HOME; rm -rf /nowhere' ; nc %h %p > /dev/null &\n",
        "  LocalCommand $(curl x) && `whoami`\n",
        "  KnownHostsCommand /bin/echo %H; exit 0\n",
        "  HostName a;b|c&d$(e)`f`\n",
        "  Include $(id).conf `id`.conf |x.conf\n",
    );
    let file = parse_file(SourceId(0), text.as_bytes(), &Limits::default()).unwrap();
    let args: Vec<(Keyword, Vec<String>)> = file
        .lines
        .iter()
        .map(|l| match l {
            Line::Directive(d) => (d.keyword.clone(), d.args.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        args[0],
        (
            Keyword::Known(KnownKeyword::Match),
            vec![
                "exec".into(),
                "touch /tmp/hm-never; $(id) `id` | nc %h %p".into(),
                "host".into(),
                "*".into()
            ]
        )
    );
    assert_eq!(
        args[1].1,
        [
            "sh",
            "-c",
            "echo $HOME; rm -rf /nowhere",
            ";",
            "nc",
            "%h",
            "%p",
            ">",
            "/dev/null",
            "&"
        ]
    );
    assert_eq!(args[2].1, ["$(curl", "x)", "&&", "`whoami`"]);
    assert_eq!(args[3].1, ["/bin/echo", "%H;", "exit", "0"]);
    assert_eq!(args[4].1, ["a;b|c&d$(e)`f`"]);

    // An Include of such names is a literal glob through the source: no shell.
    let src = source()
        .with_file(ROOT, text)
        .with_file("/hm/home/.ssh/$(id).conf", "Port 1\n");
    let (_, rec) = walk_user(&src, &Limits::default());
    assert!(rec.failures.is_empty(), "{:?}", rec.failures);
    let matched: Vec<&Path> = rec.visits[1..]
        .iter()
        .map(|v| v.canonical.as_path())
        .collect();
    assert_eq!(matched, [Path::new("/hm/home/.ssh/$(id).conf")]);
    assert_eq!(src.globs(), 3);
}

#[test]
fn command_text_with_shell_metacharacters_is_kept_raw_as_data() {
    // ADR-0007 §12.15 item 2: the four command keywords keep the rest of the line as
    // OpenSSH does, hostile text and trailing comment included. It is only ever data:
    // the MemSource stores bytes and the crate has no API that runs anything.
    let text = concat!(
        "Host box\n",
        "  ProxyCommand sh -c 'echo $HOME; rm -rf /nowhere' ; nc %h %p > /dev/null & # $(id)\n",
        "  LocalCommand $(curl x) && `whoami` | tee \"a b\"\n",
        "  KnownHostsCommand /bin/echo %H; exit 0\n",
        "  RemoteCommand \"; touch /tmp/hm-never; \" \\\n",
        "  HostName a;b|c&d$(e)`f`\n",
    );
    let file = parse_file(SourceId(0), text.as_bytes(), &Limits::default()).unwrap();
    let raws: Vec<Option<&str>> = file
        .lines
        .iter()
        .filter_map(|l| match l {
            Line::Directive(d) if d.keyword != Keyword::Known(KnownKeyword::Host) => {
                Some(d.raw.as_deref())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        raws,
        [
            Some("sh -c 'echo $HOME; rm -rf /nowhere' ; nc %h %p > /dev/null & # $(id)"),
            Some("$(curl x) && `whoami` | tee \"a b\""),
            Some("/bin/echo %H; exit 0"),
            Some("\"; touch /tmp/hm-never; \" \\"),
            None,
        ]
    );

    // The evaluation reads only the configuration file, lists the commands as
    // executing constructs, and binds the hostile text as written: a change of quoting
    // alone, which leaves the split arguments equal, changes the digest.
    let src = source().with_file(ROOT, text);
    let eval = |src: &MemSource| {
        let roots = Roots::new(Some(PathBuf::from(ROOT)), None);
        let query = Query {
            host: "box".to_owned(),
            user: None,
            local_user: Some("fixture".to_owned()),
            client_version: OpenSshVersion {
                major: 10,
                minor: 3,
                portable: Some(1),
            },
            invocation: Invocation::Shell,
        };
        let mut set = ConfigSet::new();
        evaluate(&mut set, src, &roots, &query, &Limits::default())
    };
    let ev = eval(&src);
    assert_eq!(src.reads(), 1);
    assert_eq!(src.globs(), 0);
    assert!(ev.invalid.is_empty(), "{:?}", ev.invalid);
    // ProxyCommand and KnownHostsCommand run here; LocalCommand needs PermitLocalCommand
    // and RemoteCommand runs on the server.
    assert_eq!(executing_constructs(&ev).len(), 2);
    let requoted = source().with_file(ROOT, text.replace("exit 0", "exit '0'"));
    let after = eval(&requoted);
    assert_eq!(
        after.values[&KnownKeyword::KnownHostsCommand],
        Resolved::Determined(match &ev.values[&KnownKeyword::KnownHostsCommand] {
            Resolved::Determined(v) => Value {
                raw: Some("/bin/echo %H; exit '0'".to_owned()),
                ..v.clone()
            },
            other => panic!("{other:?}"),
        }),
        "only the raw text differs; the split arguments are the same"
    );
    assert_ne!(
        behavior_digest(&relevant(&ev)),
        behavior_digest(&relevant(&after))
    );
}

#[test]
fn a_hostile_retired_keyword_line_is_ignored_not_trusted() {
    // A retired keyword has no effect, whatever follows it, and a line that only looks
    // like one (a prefix, a suffix, a different spelling) is still an unknown keyword.
    let text =
        "Host box\n  Protocol 2 ; touch /tmp/hm-never\n  ProtocolX 2\n  Protoco 2\n  Port 2210\n";
    let src = source().with_file(ROOT, text);
    let roots = Roots::new(Some(PathBuf::from(ROOT)), None);
    let query = Query {
        host: "box".to_owned(),
        user: None,
        local_user: Some("fixture".to_owned()),
        client_version: OpenSshVersion {
            major: 10,
            minor: 3,
            portable: Some(1),
        },
        invocation: Invocation::Shell,
    };
    let ev = evaluate(
        &mut ConfigSet::new(),
        &src,
        &roots,
        &query,
        &Limits::default(),
    );
    assert_eq!(ev.ignored.len(), 1);
    assert_eq!(ev.ignored[0].span.line, 2);
    assert_eq!(
        ev.invalid
            .iter()
            .map(|i| (i.span.line, i.reason.as_str()))
            .collect::<Vec<_>>(),
        [(3, "unknown_keyword"), (4, "unknown_keyword")]
    );
    assert!(matches!(
        ev.values.get(&KnownKeyword::Port),
        Some(Resolved::Determined(v)) if v.args == ["2210"]
    ));
}

#[test]
fn pathological_quoting_and_escapes_never_panic() {
    for line in [
        "\\",
        "\"",
        "'",
        "\\\\\\",
        "Host \\",
        "Host \"\\\"",
        "Host '\\''",
        "Host \"'\"'\"'",
        "= = =",
        "#",
        "\t#\t",
        "\u{c}\u{c}",
        "Host \u{c}",
        "a=b=c",
        "Host=\"=\"",
    ] {
        let _ = split_args(line);
        let _ = parse_file(SourceId(0), line.as_bytes(), &Limits::default());
    }
}

const SYSTEM_ROOT: &str = "/hm/etc/ssh/ssh_config";
const MANAGED_FILE: &str = "/hm/home/.config/heimdall/ssh_config";
/// Includes a user-tree file may hold: other user-tree files, P, and a missing file.
const USER_INCLUDES: [&str; 5] = [
    "Include /hm/home/.ssh/f1\n",
    "Include /hm/home/.ssh/f2\n",
    "Include /hm/home/.config/heimdall/ssh_config\n",
    "Include /hm/home/.ssh/missing\n",
    "Include /hm/home/.ssh/f*\n",
];
/// Includes a system-tree file may hold.
const SYSTEM_INCLUDES: [&str; 3] = [
    "Include /hm/etc/ssh/s1\n",
    "Include /hm/etc/ssh/s2\n",
    "Include /hm/etc/ssh/missing\n",
];

/// Four small files of random lines (index 0 is the root of the tree): includes from
/// `includes`, sections, plain and command values, retired keywords, a code-loading
/// keyword, a `Match exec`, and a line that is not UTF-8-safe to guess.
fn tree_lines(includes: &'static [&'static str]) -> impl Strategy<Value = Vec<Vec<String>>> {
    let line = prop_oneof![
        proptest::sample::select(includes.to_vec()).prop_map(str::to_owned),
        Just("Host box\n".to_owned()),
        Just("Host other\n".to_owned()),
        Just("Match exec \"probe\"\n".to_owned()),
        Just("Port 2200\n".to_owned()),
        Just("HostName h.example\n".to_owned()),
        Just("IdentityFile ~/.ssh/k\n".to_owned()),
        Just("ProxyCommand echo '$X' # c\n".to_owned()),
        Just("LocalCommand echo $X\n".to_owned()),
        Just("PermitLocalCommand yes\n".to_owned()),
        Just("Protocol 2\n".to_owned()),
        Just("KerberosAuthentication yes\n".to_owned()),
        Just("PKCS11Provider /hm/lib/p11\n".to_owned()),
        Just("XAuthLocation none\n".to_owned()),
    ];
    proptest::collection::vec(proptest::collection::vec(line, 0..6), 4)
}

proptest! {
    #![proptest_config(config())]

    /// `parse_file` is total over arbitrary bytes: it returns a file or a `ParseError`,
    /// never panics, and a returned file keeps one line per physical line with 1-based,
    /// increasing numbers.
    #[test]
    fn parse_file_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let limits = Limits { line_bytes: 64, file_bytes: 1500, ..Limits::default() };
        match parse_file(SourceId(3), &bytes, &limits) {
            Ok(file) => {
                let body: &[u8] = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes[..]);
                let expected = body.split(|b| *b == b'\n').count()
                    - usize::from(body.is_empty() || body.ends_with(b"\n"));
                prop_assert_eq!(file.lines.len(), expected);
                for (i, line) in file.lines.iter().enumerate() {
                    let span = match line {
                        Line::Blank(s) | Line::Comment(s) | Line::Invalid { span: s, .. } => *s,
                        Line::Directive(d) => d.span,
                    };
                    prop_assert_eq!(span.source, SourceId(3));
                    prop_assert_eq!(span.line as usize, i + 1);
                }
            }
            Err(ParseError::FileTooLarge) => prop_assert!(bytes.len() > 1500),
            Err(ParseError::LineTooLong { line } | ParseError::NulByte { line }) => {
                prop_assert!(line >= 1);
            }
            Err(other) => prop_assert!(false, "unexpected {:?}", other),
        }
    }

    /// The same over byte soup built from the characters the lexer treats specially.
    #[test]
    fn parse_file_never_panics_on_syntax_soup(
        parts in proptest::collection::vec(
            prop_oneof![
                Just(&b"\""[..]), Just(&b"'"[..]), Just(&b"\\"[..]), Just(&b"="[..]),
                Just(&b"#"[..]), Just(&b" "[..]), Just(&b"\t"[..]), Just(&b"\r"[..]),
                Just(&b"\n"[..]), Just(&b"\x0c"[..]), Just(&b"Host"[..]), Just(&b"Include"[..]),
                Just(&b"\xef\xbb\xbf"[..]), Just(&b"\xff"[..]), Just(&b"\xc3\xa9"[..]),
                Just(&b"%"[..]), Just(&b"${"[..]), Just(&b"}"[..]), Just(&b"*"[..]),
            ],
            0..64,
        )
    ) {
        let bytes: Vec<u8> = parts.concat();
        let _ = parse_file(SourceId(0), &bytes, &Limits::default());
    }

    /// The source role of every value is the role of the file it was read from, for any
    /// tree of the user, the system and the managed file with random includes, command
    /// lines, retired keywords and unreadable parts: the user tree's files are `User`,
    /// the system tree's `System`, P `Managed`. `evaluate` never panics, and every
    /// retired keyword it records sits on a line of a file it read.
    #[test]
    fn every_value_has_the_role_of_its_file(
        user in tree_lines(&USER_INCLUDES),
        system in tree_lines(&SYSTEM_INCLUDES),
        managed in tree_lines(&USER_INCLUDES),
    ) {
        let mut src = source();
        let mut add = |path: &str, lines: &[String]| {
            src.insert(path, MemEntry::File(lines.concat().into_bytes()));
        };
        add(ROOT, &user[0]);
        for (i, lines) in user.iter().enumerate().skip(1) {
            add(&format!("/hm/home/.ssh/f{i}"), lines);
        }
        add(SYSTEM_ROOT, &system[0]);
        for (i, lines) in system.iter().enumerate().skip(1) {
            add(&format!("/hm/etc/ssh/s{i}"), lines);
        }
        add(MANAGED_FILE, &managed[0]);
        let roots = Roots::new(Some(PathBuf::from(ROOT)), Some(PathBuf::from(SYSTEM_ROOT)))
            .with_managed(MANAGED_FILE);
        let query = Query {
            host: "box".to_owned(),
            user: None,
            local_user: Some("fixture".to_owned()),
            client_version: OpenSshVersion { major: 10, minor: 3, portable: Some(1) },
            invocation: Invocation::Shell,
        };
        let ev = evaluate(&mut ConfigSet::new(), &src, &roots, &query, &Limits::default());
        let expected = |path: &Path| {
            if path == Path::new(MANAGED_FILE) {
                SourceRole::Managed
            } else if path.starts_with("/hm/etc/ssh") {
                SourceRole::System
            } else {
                SourceRole::User
            }
        };
        let check = |v: &Value| -> Result<(), TestCaseError> {
            // Spans of an unreadable root point at no file; every other span is a file.
            if let Some(path) = ev.files.get(&v.span.source) {
                prop_assert_eq!(v.role, expected(path), "{:?} {:?}", path, v);
            }
            Ok(())
        };
        for r in ev.values.values() {
            match r {
                Resolved::Unset => {}
                Resolved::Determined(v) => check(v)?,
                Resolved::Undetermined(vs) => {
                    for v in vs {
                        check(v)?;
                    }
                }
            }
        }
        for list in ev.accumulated.values() {
            for c in list {
                check(&c.value)?;
            }
        }
        for ig in &ev.ignored {
            prop_assert!(ev.files.contains_key(&ig.span.source));
        }
        // The digest is total over whatever came out.
        let _ = behavior_digest(&relevant(&ev));
        let _ = executing_constructs(&ev);
    }

    /// The include walk is total and bounded over arbitrary trees of small files whose
    /// lines are random Include/Host/Port soup: it never panics, never reads more than
    /// `files` files or `total_bytes` bytes, and never nests deeper than `depth`.
    #[test]
    fn walk_is_total_and_bounded(
        files in proptest::collection::vec(
            proptest::collection::vec(
                prop_oneof![
                    (0u8..6).prop_map(|i| format!("Include f{i}\n")),
                    Just("Include f*\n".to_owned()),
                    Just("Include ${HM_NONE}/x %u ~nobody/x \"\"\n".to_owned()),
                    Just("Host x\n".to_owned()),
                    Just("Port 1\n".to_owned()),
                    Just("Include \"unterminated\n".to_owned()),
                ],
                0..6,
            ),
            1..6,
        )
    ) {
        let mut src = source();
        for (i, lines) in files.iter().enumerate() {
            let path = if i == 0 { ROOT.to_owned() } else { format!("/hm/home/.ssh/f{i}") };
            src.insert(path, MemEntry::File(lines.concat().into_bytes()));
        }
        let limits = Limits { files: 20, depth: 4, total_bytes: 4096, ..Limits::default() };
        let (_, rec) = walk_user(&src, &limits);
        prop_assert!(rec.summary.visits <= 20);
        prop_assert!(rec.summary.bytes <= 4096);
        prop_assert!(rec.visits.iter().all(|v| v.depth <= 4));
        prop_assert_eq!(rec.visits.len(), rec.summary.visits);
        prop_assert!(src.reads() <= 20 * 6 + 1);
    }
}

// --- the renderer's path constructors (ADR-0007 §12.16 item 6) ----------------------------

/// Arbitrary Unicode, and text that starts with part of a pipe prefix, so the prefix
/// length falls inside a multi-byte character as often as not.
fn unicode_text() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        (
            prop::sample::select(vec!["\\\\.\\pipe\\", "//./pipe/", "\\\\.\\PIPE\\"]),
            0usize..10,
            any::<String>(),
        )
            .prop_map(|(prefix, n, rest)| format!("{}{rest}", &prefix[..n.min(prefix.len())])),
        "[a-zé€😀\\\\/.~:%$\"*?\\[\\] {}]{0,24}",
    ]
}

proptest! {
    #![proptest_config(config())]

    /// Y06 (ADR-0007 §12.16 item 6): the public `RenderPath` constructors are total over
    /// arbitrary Unicode: each returns a path or a refusal and never panics, and what
    /// they accept keeps its rules (a pipe has no separator in its name; `absolute` is
    /// never `~`; B never renders a `~` or glob target).
    #[test]
    fn render_path_constructors_never_panic_on_arbitrary_unicode(
        text in unicode_text(),
        home in unicode_text(),
    ) {
        let marker = MarkerId::parse("hm-0123456789abcdef").unwrap();
        let outcome = std::panic::catch_unwind(|| {
            let mut accepted = Vec::new();
            if let Ok(p) = RenderPath::pipe(&text) {
                let name = p.as_str().strip_prefix("//./pipe/").map(str::to_owned);
                accepted.push(("pipe", p, name));
            }
            for (kind, p) in [
                ("unix", RenderPath::unix(Path::new(&text))),
                ("windows", RenderPath::windows(Path::new(&text))),
                ("absolute_unix", RenderPath::absolute(Path::new(&text), PathStyle::Unix)),
                ("absolute_windows", RenderPath::absolute(Path::new(&text), PathStyle::Windows)),
                (
                    "home_unix",
                    RenderPath::home_relative(Path::new(&text), Path::new(&home), PathStyle::Unix),
                ),
                (
                    "home_windows",
                    RenderPath::home_relative(Path::new(&text), Path::new(&home), PathStyle::Windows),
                ),
            ] {
                if let Ok(p) = p {
                    accepted.push((kind, p, None));
                }
            }
            let mut blocks = Vec::new();
            for (kind, p, _) in &accepted {
                blocks.push((*kind, p.as_str().to_owned(), render_include_block(&marker, p, Newline::Lf)));
            }
            (accepted, blocks)
        });
        prop_assert!(outcome.is_ok(), "a constructor panicked");
        let (accepted, blocks) = outcome.unwrap();
        for (kind, p, name) in &accepted {
            if *kind == "pipe" {
                let name = name.clone().unwrap_or_default();
                prop_assert!(!name.is_empty() && !name.contains(['/', '\\']), "{:?}", p.as_str());
            }
            if kind.starts_with("absolute") {
                prop_assert!(!p.as_str().starts_with('~'));
            }
        }
        for (kind, text, block) in blocks {
            if block.is_ok() {
                prop_assert!(!text.starts_with('~') && !text.contains(['*', '?', '[', ']']), "{kind}");
            }
        }
    }
}
