//! The static evaluator against the real client (m02-plan U3 "Tests (A22 static
//! half)"; ADR-0007 §12.15 items 2, 4 and 6).
//!
//! Cargo test target `integration_sshconf_vs_ssh_g` hosted by `heimdall-localenv`
//! (review F09 convention). Every test copies the inert U1 corpus
//! (`tests/fixtures/sshconf/corpus`, "inert, ssh -G only") or writes its own inert
//! configuration into a scratch directory this process created, replaces every
//! `@CORPUS_DIR@` with the scratch copy's absolute path, and runs the local `ssh -G`
//! with **only** isolation on its command line: `-F <scratch file>`, `-o
//! UserKnownHostsFile=<scratch>`, `-o GlobalKnownHostsFile=<scratch empty file>` and
//! `-o BatchMode=yes` (ADR-0007 §9). The child's environment is exactly `PATH` and a
//! scratch `HOME` (plus a fixture variable where a test needs one), so `glob(3)`'s `~`
//! never reaches the account's home. `ssh -G` opens no key, agent or network; nothing
//! in these configurations executes.
//!
//! Each test compares Heimdall's evaluation (through `fs::BoundedSource` over the
//! scratch copy) with what the client printed, and **records** each observation on
//! stderr as one `observation` line (paths shown relative to `<scratch>`, the local
//! user name never printed). A disagreement fails the test with the observation in
//! the message; it is never hidden. Observations specific to one client (the
//! `[I]` facts of ADR-0007 §12.15 item 6) are asserted for the client this test runs
//! on and recorded for the evidence step.
//!
//! **Version gates** (ADR-0007 §12.15 item 4, §12.32 items 11 and 12). Where clients
//! differ, Heimdall reads the client's version through `heimdall_sshconf::client`,
//! whose boundaries come from this test on each client. A client listed in
//! `client::OBSERVED_CLIENTS` must behave as its row says and Heimdall must agree with
//! it exactly. A client the observations do not settle may find Heimdall **stricter**
//! (it refuses a construct the client loads, or treats as environment-dependent a value
//! the client takes literally): that is recorded (`heimdall_stricter`) so the boundary
//! can move with evidence, and does not fail. Heimdall being **laxer** than any client
//! always fails. The default identities a client prints must all be in
//! `client::DEFAULT_IDENTITIES` (the superset rule, §12.32 item 12).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use heimdall_localenv::clients::ENCODING_OBSERVATIONS;
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::fs::BoundedSource;
use heimdall_localenv::local_query::{run_version, version_text};
use heimdall_localenv::paths::SshPaths;
use heimdall_sshconf::client;
use heimdall_sshconf::directive::{Keyword, KnownKeyword};
use heimdall_sshconf::edit::{IncludeBlock, plan_insert};
use heimdall_sshconf::eval::{Evaluation, Invocation, OpenSshVersion, Query, Resolved, evaluate};
use heimdall_sshconf::include::{ConfigSet, Roots};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::parse::{Line, SourceId, parse_file};
use heimdall_sshconf::relevant::{Proxy, ProxyResolution, RelevantBehavior, relevant};
use heimdall_sshconf::render::{MarkerId, Newline, RenderPath, render_include_block};
use heimdall_testkit::home::{Scratch, find_program, ssh_option_path};

// --- the harness ------------------------------------------------------------------------

/// The local client and the scratch tree one test uses.
struct Harness {
    /// Removed on drop, pass or fail.
    _scratch: Scratch,
    /// Canonical scratch root (macOS temporary paths are symlinks).
    root: PathBuf,
    ssh: PathBuf,
    version: OpenSshVersion,
    local_user: String,
}

impl Harness {
    fn new() -> Harness {
        let scratch = Scratch::new().unwrap();
        let root = std::fs::canonicalize(scratch.path()).unwrap();
        for d in ["home", "home/.ssh", "etc-ssh"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("known_hosts"), b"").unwrap();
        std::fs::write(root.join("empty_known_hosts"), b"").unwrap();
        let ssh = find_program("ssh").expect("ssh client on PATH");
        let version = run_version(&ssh).expect("ssh -V");
        #[cfg(unix)]
        let local_user = heimdall_localenv::sys::account_name().unwrap_or_default();
        #[cfg(not(unix))]
        let local_user = std::env::var("USERNAME").unwrap_or_default();
        Harness {
            _scratch: scratch,
            root,
            ssh,
            version,
            local_user,
        }
    }

    /// Copy the U1 corpus into `<scratch>/corpus`, replacing `@CORPUS_DIR@`.
    fn copy_corpus(&self) -> PathBuf {
        // The repository through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
        let src = heimdall_testkit::repo::repo_path("tests/fixtures/sshconf/corpus");
        let dst = self.root.join("corpus");
        copy_tree(&src, &dst, &dst.to_string_lossy());
        dst
    }

    fn client(&self) -> String {
        format!(
            "{}:{}",
            platform_name(Platform::current()),
            version_text(&self.version)
        )
    }

    /// `ssh -G` with isolation only; the exit code and the printed keywords.
    fn ssh_g(
        &self,
        file: &Path,
        alias: &str,
        user: Option<&str>,
        env: &[(&str, &str)],
    ) -> (i32, BTreeMap<String, Vec<String>>, String) {
        self.ssh_g_invoked(file, alias, user, env, &Invocation::Shell)
    }

    /// [`Harness::ssh_g`] for an invocation: `-s <alias> <subsystem>` for a subsystem,
    /// `<alias> <command>` for a remote command (`-G` runs neither).
    fn ssh_g_invoked(
        &self,
        file: &Path,
        alias: &str,
        user: Option<&str>,
        env: &[(&str, &str)],
        invocation: &Invocation,
    ) -> (i32, BTreeMap<String, Vec<String>>, String) {
        let mut cmd = Command::new(&self.ssh);
        cmd.env_clear()
            .envs(client_base_env())
            .env("HOME", self.root.join("home"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(&self.root);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.arg("-G")
            .arg("-F")
            .arg(file)
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                ssh_option_path(&self.root.join("known_hosts"))
            ))
            .arg("-o")
            .arg(format!(
                "GlobalKnownHostsFile={}",
                ssh_option_path(&self.root.join("empty_known_hosts"))
            ))
            .arg("-o")
            .arg("BatchMode=yes");
        if let Some(u) = user {
            cmd.arg("-l").arg(u);
        }
        match invocation {
            Invocation::Shell | Invocation::Exec(None) => {
                cmd.arg(alias);
            }
            Invocation::Exec(Some(command)) => {
                cmd.arg(alias).arg(command);
            }
            Invocation::Subsystem(name) => {
                cmd.arg("-s").arg(alias).arg(name);
            }
        }
        let out = cmd.output().unwrap();
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let (k, v) = line.split_once(' ').unwrap_or((line, ""));
            map.entry(k.to_ascii_lowercase())
                .or_default()
                .push(v.to_owned());
        }
        let stderr = String::from_utf8_lossy(&out.stderr)
            .replace(&*self.root.to_string_lossy(), "<scratch>");
        (out.status.code().unwrap_or(-1), map, stderr)
    }

    /// Heimdall's static evaluation of `file` for `alias`.
    fn heimdall(
        &self,
        file: &Path,
        alias: &str,
        user: Option<&str>,
        env: &[(&str, &str)],
    ) -> (Evaluation, RelevantBehavior) {
        self.heimdall_invoked(file, alias, user, env, Invocation::Shell)
    }

    /// [`Harness::heimdall`] for an invocation.
    fn heimdall_invoked(
        &self,
        file: &Path,
        alias: &str,
        user: Option<&str>,
        env: &[(&str, &str)],
        invocation: Invocation,
    ) -> (Evaluation, RelevantBehavior) {
        let paths = SshPaths::with_test_override(self.root.join("home"), self.root.join("etc-ssh"));
        let mut vars: Vec<(OsString, OsString)> = client_base_env()
            .into_iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
        vars.push(("HOME".into(), self.root.join("home").into_os_string()));
        vars.extend(
            env.iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        );
        let source = BoundedSource::new(paths, Env::from_vars(vars), Limits::default());
        let roots = Roots::new(Some(file.to_path_buf()), None);
        let query = Query {
            host: alias.to_owned(),
            user: user.map(str::to_owned),
            local_user: Some(self.local_user.clone()).filter(|n| !n.is_empty()),
            client_version: self.version,
            invocation,
        };
        let mut set = ConfigSet::new();
        let evaluation = evaluate(&mut set, &source, &roots, &query, &Limits::default());
        let behavior = relevant(&evaluation);
        (evaluation, behavior)
    }

    fn record(&self, test: &str, subject: &str, fields: &[(&str, String)]) {
        let mut line = format!(
            "observation test={test} client={} subject={subject}",
            self.client()
        );
        for (k, v) in fields {
            let v = v
                .replace(&*self.root.to_string_lossy(), "<scratch>")
                .replace(&format!("user {}", self.local_user), "user <local>");
            line.push_str(&format!(" {k}={v:?}"));
        }
        eprintln!("{line}");
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let p = self.root.join(name);
        std::fs::write(&p, text.replace("@SCRATCH@", &self.root.to_string_lossy())).unwrap();
        p
    }
}

/// The environment a client runs with besides the scratch `HOME`: `PATH` only on
/// Unix; on Windows also the system variables `ssh.exe` needs to start.
fn client_base_env() -> Vec<(String, String)> {
    if cfg!(windows) {
        ["PATH", "SystemRoot", "windir", "ProgramData"]
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_owned(), v)))
            .collect()
    } else {
        vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())]
    }
}

/// The render path of a scratch file for this platform's client.
fn render_path(p: &Path) -> RenderPath {
    if cfg!(windows) {
        RenderPath::windows(p).unwrap()
    } else {
        RenderPath::unix(p).unwrap()
    }
}

fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Linux => "linux",
        Platform::MacOs => "macos",
        Platform::Windows => "windows",
        Platform::OtherUnix => "unix",
    }
}

fn copy_tree(src: &Path, dst: &Path, corpus_dir: &str) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&from, &to, corpus_dir);
        } else {
            let bytes = std::fs::read(&from).unwrap();
            let replaced = replace_bytes(&bytes, b"@CORPUS_DIR@", corpus_dir.as_bytes());
            std::fs::write(&to, replaced).unwrap();
        }
    }
}

fn replace_bytes(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

// --- the default mapping (RelevantBehavior -> ssh -G keywords) ------------------------------

fn first_arg(r: &Resolved) -> Option<String> {
    match r {
        Resolved::Determined(v) => v.args.first().cloned(),
        _ => None,
    }
}

fn expand_percent(s: &str, alias: &str) -> String {
    s.replace("%h", alias).replace("%%", "%")
}

/// What `ssh -G` prints for the behaviour Heimdall computed, keyword by keyword:
/// unset values take ssh's defaults; `%%` and `%h` are expanded where ssh expands them
/// before printing.
fn expected(
    alias: &str,
    user: Option<&str>,
    local_user: &str,
    b: &RelevantBehavior,
) -> BTreeMap<&'static str, Vec<String>> {
    let mut m: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    assert!(
        !matches!(b.hostname, Resolved::Undetermined(_)),
        "{alias}: the inert corpus has no undetermined HostName"
    );
    m.insert(
        "hostname",
        vec![
            first_arg(&b.hostname)
                .map_or_else(|| alias.to_ascii_lowercase(), |h| expand_percent(&h, alias)),
        ],
    );
    m.insert(
        "port",
        vec![first_arg(&b.port).unwrap_or_else(|| "22".to_owned())],
    );
    let u = user
        .map(str::to_owned)
        .or_else(|| first_arg(&b.user))
        .unwrap_or_else(|| local_user.to_owned());
    m.insert("user", vec![u]);
    m.insert(
        "identitiesonly",
        vec![
            first_arg(&b.identities_only)
                .map_or_else(|| "no".to_owned(), |v| v.to_ascii_lowercase()),
        ],
    );
    if let Some(a) = first_arg(&b.identity_agent) {
        m.insert("identityagent", vec![expand_percent(&a, alias)]);
    }
    let files: Vec<String> = b
        .identity_files
        .iter()
        .map(|c| c.value.args.first().cloned().unwrap_or_default())
        .collect();
    m.insert("identityfile", files);
    let certs: Vec<String> = b
        .certificate_files
        .iter()
        .map(|c| c.value.args.first().cloned().unwrap_or_default())
        .collect();
    if !certs.is_empty() {
        m.insert("certificatefile", certs);
    }
    match &b.proxy {
        ProxyResolution::Determined(Proxy::None) => {}
        ProxyResolution::Determined(Proxy::Jump(v)) => {
            m.insert("proxyjump", vec![v.args.join(",")]);
        }
        other => panic!("{alias}: unexpected proxy in the inert corpus: {other:?}"),
    }
    m
}

/// Whether `printed` (as `ssh -G` prints an `identityfile`) is one of the default
/// identities Heimdall considers: the union over every client and the pinned manuals
/// (`client::DEFAULT_IDENTITIES`, ADR-0007 §12.32 item 12).
fn is_heimdall_default(printed: &str) -> bool {
    printed
        .strip_prefix("~/.ssh/")
        .is_some_and(|name| client::DEFAULT_IDENTITIES.contains(&name))
}

/// Compare one alias; returns the disagreements (empty when equal).
fn compare_alias(
    h: &Harness,
    test: &str,
    file: &Path,
    alias: &str,
    user: Option<&str>,
) -> Vec<String> {
    compare_alias_invoked(h, test, file, alias, user, &Invocation::Shell)
}

/// [`compare_alias`] for an invocation (both sides invoked the same way).
fn compare_alias_invoked(
    h: &Harness,
    test: &str,
    file: &Path,
    alias: &str,
    user: Option<&str>,
    invocation: &Invocation,
) -> Vec<String> {
    let (exit, printed, stderr) = h.ssh_g_invoked(file, alias, user, &[], invocation);
    let (evaluation, behavior) = h.heimdall_invoked(file, alias, user, &[], invocation.clone());
    let mut diffs = Vec::new();
    if exit != 0 {
        diffs.push(format!("ssh -G exited {exit}: {stderr}"));
    }
    if !evaluation.invalid.is_empty() {
        diffs.push(format!(
            "heimdall reports invalid lines: {:?}",
            evaluation.invalid
        ));
    }
    let want = expected(alias, user, &h.local_user, &behavior);
    for (k, v) in &want {
        let got = printed.get(*k).cloned().unwrap_or_default();
        let equal = match *k {
            "hostname" => got.len() == 1 && got[0].eq_ignore_ascii_case(&v[0]),
            "identityfile" if v.is_empty() => {
                // No IdentityFile configured: ssh adds its defaults (F20), each one a
                // name Heimdall's union list has (§12.32 item 12). The first and the
                // final pass add the same list (diagnosed on 9.6p1, §12.32 item 11 (c)).
                !got.is_empty() && got.iter().all(|g| is_heimdall_default(g))
            }
            _ => got == *v,
        };
        if !equal {
            diffs.push(format!("{k}: heimdall {v:?} ssh -G {got:?}"));
        }
    }
    // Configured identities: no default is added once any IdentityFile is configured
    // (F20, settled per client).
    if !behavior.identity_files.is_empty() {
        let got = printed.get("identityfile").cloned().unwrap_or_default();
        if got.iter().any(|g| is_heimdall_default(g)) {
            diffs.push(format!(
                "a default identity was added to a configured list: {got:?}"
            ));
        }
    }
    h.record(
        test,
        alias,
        &[
            ("agree", diffs.is_empty().to_string()),
            (
                "ssh_g_port",
                printed.get("port").map(|v| v.join(",")).unwrap_or_default(),
            ),
            (
                "ssh_g_identityfile",
                printed
                    .get("identityfile")
                    .map(|v| v.join(","))
                    .unwrap_or_default(),
            ),
        ],
    );
    diffs
}

fn run_corpus(test: &str, root_file: &str, aliases: &[(&str, Option<&str>)]) {
    let h = Harness::new();
    let corpus = h.copy_corpus();
    let file = corpus.join(root_file);
    let mut all = Vec::new();
    for (alias, user) in aliases {
        for d in compare_alias(&h, test, &file, alias, *user) {
            all.push(format!("{root_file} {alias}: {d}"));
        }
    }
    assert!(
        all.is_empty(),
        "disagreements with ssh -G on {}:\n{}",
        h.client(),
        all.join("\n").replace(&h.local_user, "<local>")
    );
}

// --- the corpus ------------------------------------------------------------------------------

#[test]
fn corpus_basic_patterns_wildcards_negation_and_first_value_match_ssh_g() {
    run_corpus(
        "corpus_basic",
        "basic.conf",
        &[
            ("alpha", None),
            ("x.corpus.example", None),
            ("bad.corpus.example", None),
            ("beta", None),
            ("gamma1", None),
            ("gamma-excluded", None),
            ("delta", None),
            ("anything.example", Some("corpus-explicit")),
        ],
    );
}

#[test]
fn corpus_identity_list_matches_ssh_g() {
    run_corpus(
        "corpus_identity_list_matches_ssh_g",
        "identity.conf",
        &[
            ("ident-one", None),
            ("ident-spaced", None),
            ("ident-percent", None),
            ("ident-pipe", None),
            ("ident-pipe-quoted", None),
            ("ident-agent-none", None),
            ("ident-files-none", None),
        ],
    );
    // The default list itself (F20, ADR-0007 §12.32 item 12): an alias with no
    // IdentityFile prints only names of Heimdall's union list, and a client with a
    // recorded list prints exactly that list (the data the matrix cites).
    let h = Harness::new();
    let corpus = h.copy_corpus();
    let (_, printed, _) = h.ssh_g(&corpus.join("basic.conf"), "alpha", None, &[]);
    let got = printed.get("identityfile").cloned().unwrap_or_default();
    let names: Vec<&str> = got
        .iter()
        .map(|g| g.strip_prefix("~/.ssh/").unwrap_or(g))
        .collect();
    let recorded = client::default_identities_of(h.version);
    h.record(
        "corpus_identity_list_matches_ssh_g",
        "default_identities",
        &[
            ("printed", got.join(",")),
            (
                "recorded_for_this_client",
                recorded.map_or_else(|| "none".to_owned(), |l| l.join(",")),
            ),
            (
                "not_in_heimdall_union",
                names
                    .iter()
                    .filter(|n| !client::DEFAULT_IDENTITIES.contains(n))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    );
    assert!(!got.is_empty());
    assert!(
        got.iter().all(|g| is_heimdall_default(g)),
        "{}: a default identity outside client::DEFAULT_IDENTITIES: {got:?}",
        h.client()
    );
    if let Some(recorded) = recorded {
        assert_eq!(
            names,
            recorded,
            "{}: the recorded default list differs",
            h.client()
        );
    }
}

#[test]
fn corpus_nested_includes_and_bytewise_glob_order_match_ssh_g() {
    run_corpus(
        "corpus_nested",
        "nested.conf",
        &[
            ("nested-after", None),
            ("nested-level1", None),
            ("nested-glob", None),
            ("nested-deep", None),
        ],
    );
}

#[test]
fn include_state_is_restored_after_included_file() {
    run_corpus(
        "include_state_is_restored_after_included_file",
        "include-state.conf",
        &[("state-alpha", None), ("state-other", None)],
    );
}

#[test]
fn corpus_unsupported_syntax_loads_and_matches_ssh_g() {
    run_corpus(
        "corpus_unsupported",
        "unsupported.conf",
        &[("unsupported", None)],
    );
}

/// ADR-0007 §12.15 item 4: `retired.conf` through this client. A supported client
/// that refuses it reopens item 4 for that client, so a refusal fails here. Whether
/// Heimdall's evaluator ignores the retired lines (W2-U2r) is recorded, not asserted.
#[test]
fn corpus_retired_keywords_are_accepted_by_the_client() {
    let h = Harness::new();
    let corpus = h.copy_corpus();
    let file = corpus.join("retired.conf");
    let (exit, printed, stderr) = h.ssh_g(&file, "retired", None, &[]);
    let (evaluation, behavior) = h.heimdall(&file, "retired", None, &[]);
    h.record(
        "corpus_retired_keywords_are_accepted_by_the_client",
        "retired",
        &[
            ("ssh_g_exit", exit.to_string()),
            (
                "ssh_g_port",
                printed.get("port").map(|v| v.join(",")).unwrap_or_default(),
            ),
            (
                "heimdall_invalid_lines",
                evaluation.invalid.len().to_string(),
            ),
            (
                "heimdall_port",
                first_arg(&behavior.port).unwrap_or_default(),
            ),
        ],
    );
    assert_eq!(
        exit, 0,
        "the client refused retired.conf (reopens §12.15 item 4): {stderr}"
    );
    assert_eq!(printed.get("port").cloned(), Some(vec!["2801".to_owned()]));
    assert_eq!(first_arg(&behavior.port).as_deref(), Some("2801"));
}

/// ADR-0007 §12.15 item 2: `RemoteCommand` (like `ProxyCommand`, `LocalCommand` and
/// `KnownHostsCommand`) is the raw rest of the line, quotes and trailing comment
/// included, as the client prints it. The raw text here is taken from the file line
/// itself; `Directive.raw` (W2-U2r) must equal it.
#[test]
fn corpus_lexer_matches_ssh_g_and_command_text_is_the_raw_rest_of_the_line() {
    run_corpus(
        "corpus_lexer",
        "lexer.conf",
        &[
            ("lex-hash", None),
            ("lex-quote", None),
            ("lex-equals", None),
            ("lex-escape", None),
            ("lex-unknown-escape", None),
        ],
    );
    let h = Harness::new();
    let corpus = h.copy_corpus();
    let file = corpus.join("lexer.conf");
    let text = std::fs::read_to_string(&file).unwrap();
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("RemoteCommand"))
        .unwrap();
    let raw = line.trim_start()["RemoteCommand".len()..].trim_start();
    let (exit, printed, _) = h.ssh_g(&file, "lex-command", None, &[]);
    let got = printed.get("remotecommand").cloned().unwrap_or_default();
    // A scratch ProxyCommand is printed raw the same way (it is never run by -G).
    let pc = h.write(
        "proxycommand.conf",
        "Host pc-raw\n  ProxyCommand echo '$X'  \"q\"  # c\n",
    );
    let (pc_exit, pc_printed, _) = h.ssh_g(&pc, "pc-raw", None, &[]);
    let pc_got = pc_printed.get("proxycommand").cloned().unwrap_or_default();
    // Heimdall's own raw text: `Directive.raw` from the parser, and `Value.raw` from
    // the evaluator for the ProxyCommand that competes in the proxy slot (F10).
    let parsed = parse_file(SourceId(0), text.as_bytes(), &Limits::default()).unwrap();
    let directive_raw = parsed
        .lines
        .iter()
        .find_map(|l| match l {
            Line::Directive(d) if d.keyword == Keyword::Known(KnownKeyword::RemoteCommand) => {
                Some(d.raw.clone())
            }
            _ => None,
        })
        .flatten();
    let (_, pc_behavior) = h.heimdall(&pc, "pc-raw", None, &[]);
    let value_raw = match &pc_behavior.proxy {
        ProxyResolution::Determined(Proxy::Command(v)) => v.raw.clone(),
        other => panic!("pc-raw: {other:?}"),
    };
    h.record(
        "corpus_lexer_raw_command",
        "lex-command",
        &[
            ("file_rest_of_line", raw.to_owned()),
            ("ssh_g_remotecommand", got.join("|")),
            ("ssh_g_proxycommand", pc_got.join("|")),
            (
                "heimdall_directive_raw",
                directive_raw.clone().unwrap_or_default(),
            ),
            ("heimdall_value_raw", value_raw.clone().unwrap_or_default()),
        ],
    );
    assert_eq!(
        directive_raw.as_deref(),
        Some(raw),
        "Directive.raw differs from ssh -G"
    );
    assert_eq!(
        value_raw.as_deref(),
        Some(raw),
        "Value.raw differs from ssh -G"
    );
    assert_eq!(exit, 0);
    assert_eq!(
        got,
        vec![raw.to_owned()],
        "RemoteCommand is not the raw rest of the line"
    );
    assert_eq!(pc_exit, 0);
    assert_eq!(
        pc_got,
        vec![raw.to_owned()],
        "ProxyCommand is not the raw rest of the line"
    );
}

/// ADR-0007 §4: whether this client loads a user file with B effective when the file
/// starts with a BOM, and when it uses CRLF. The corpus files are checked, then a real
/// block B (rendered and inserted by `heimdall-sshconf`) in front of a scratch P. The
/// result must equal this client's row in `clients::ENCODING_OBSERVATIONS` when it
/// has one; otherwise it is recorded for the evidence step and the table stays
/// "unknown" (`false`).
#[test]
fn bom_and_crlf_acceptance() {
    let h = Harness::new();
    let corpus = h.copy_corpus();
    let (bom_exit, bom_printed, _) = h.ssh_g(&corpus.join("bom.conf"), "bom-check", None, &[]);
    let (crlf_exit, crlf_printed, _) = h.ssh_g(&corpus.join("crlf.conf"), "crlf-check", None, &[]);
    let corpus_bom = bom_exit == 0 && bom_printed.get("port") == Some(&vec!["2602".to_owned()]);
    let corpus_crlf = crlf_exit == 0 && crlf_printed.get("port") == Some(&vec!["2601".to_owned()]);

    let p = h.write("p_config", "Host hm-b-check\n  Port 2603\n");
    let marker = MarkerId::parse("hm-0123456789abcdef").unwrap();
    let b_effective = |user_bytes: &[u8], newline: Newline, name: &str| -> bool {
        let block = IncludeBlock {
            marker: marker.clone(),
            bytes: render_include_block(&marker, &render_path(&p), newline).unwrap(),
        };
        let plan = plan_insert(Some(user_bytes), &block).unwrap();
        let file = h.root.join(name);
        std::fs::write(&file, &plan.bytes).unwrap();
        let (exit, printed, _) = h.ssh_g(&file, "hm-b-check", None, &[]);
        exit == 0 && printed.get("port") == Some(&vec!["2603".to_owned()])
    };
    let bom = b_effective(
        b"\xEF\xBB\xBF# scratch user file with a BOM\nHost other\n  Port 2604\n",
        Newline::Lf,
        "user_bom",
    );
    let crlf = b_effective(
        b"# scratch user file with CRLF\r\nHost other\r\n  Port 2604\r\n",
        Newline::CrLf,
        "user_crlf",
    );
    let lf = b_effective(b"Host other\n  Port 2604\n", Newline::Lf, "user_lf");
    h.record(
        "bom_and_crlf_acceptance",
        "encodings",
        &[
            ("corpus_bom_loads", corpus_bom.to_string()),
            ("corpus_crlf_loads", corpus_crlf.to_string()),
            ("bom_b_effective", bom.to_string()),
            ("crlf_b_effective", crlf.to_string()),
            ("lf_b_effective", lf.to_string()),
        ],
    );
    assert!(lf, "block B is not effective in a plain LF file");
    assert_eq!(
        corpus_bom, bom,
        "the corpus BOM file and the B check disagree"
    );
    assert_eq!(
        corpus_crlf, crlf,
        "the corpus CRLF file and the B check disagree"
    );
    if let Some(row) = ENCODING_OBSERVATIONS
        .iter()
        .find(|r| r.platform == Platform::current() && r.version == h.version)
    {
        assert_eq!(
            (row.bom, row.crlf),
            (bom, crlf),
            "ENCODING_OBSERVATIONS disagrees with {}",
            h.client()
        );
    }
}

/// How one version-gated fact compares (ADR-0007 §12.32 item 11; module documentation).
/// `observed` is this exact client's row in `client::OBSERVED_CLIENTS`, `heimdall`
/// Heimdall's reading for this version, `seen` what the client did, and `strict` the
/// reading the gate takes when the observations do not settle a version. `Ok(true)`:
/// Heimdall is stricter than an unobserved client (recorded, not a failure).
fn judge(observed: Option<bool>, heimdall: bool, seen: bool, strict: bool) -> Result<bool, String> {
    if let Some(row) = observed
        && row != seen
    {
        return Err(format!(
            "the recorded row says {row}, the client did {seen}"
        ));
    }
    if heimdall == seen {
        Ok(false)
    } else if heimdall == strict && observed.is_none() {
        Ok(true)
    } else {
        Err(format!("heimdall {heimdall}, the client {seen}"))
    }
}

/// ADR-0007 §12.15 item 4, §12.32 item 11 (b): each keyword the pinned manual says
/// expands `${VAR}`, checked on this client where `ssh -G` prints the value after
/// expansion, against Heimdall's reading for this client's version
/// (`client::expands_env`). `IdentityFile`, `CertificateFile` and `KnownHostsCommand`
/// are printed before expansion (ssh expands them when it uses them) and
/// `UserKnownHostsFile` is overridden by the isolation option, so for those `-G` cannot
/// tell and the observation says so. `Include` is observed through its effect.
/// OpenSSH 9.6p1 takes `User`, `SetEnv` and `Include` literally; 10.3p1 and 10.5p1
/// expand them.
#[test]
fn s01_env_expansion_keywords_match_the_client() {
    let h = Harness::new();
    let file = h.write(
        "env.conf",
        "Host env-x\n\
         \x20 User u${HM_CORPUS_VAR}\n\
         \x20 SetEnv HMSET=${HM_CORPUS_VAR}\n\
         \x20 RevokedHostKeys /nonexistent/hm-corpus/${HM_CORPUS_VAR}/revoked\n\
         \x20 LocalForward /nonexistent/hm-corpus/${HM_CORPUS_VAR}/l.sock /nonexistent/hm-corpus/${HM_CORPUS_VAR}/r.sock\n\
         \x20 RemoteForward /nonexistent/hm-corpus/${HM_CORPUS_VAR}/rf.sock /nonexistent/hm-corpus/${HM_CORPUS_VAR}/rl.sock\n\
         \x20 CertificateFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/cert\n\
         \x20 ControlPath /nonexistent/hm-corpus/${HM_CORPUS_VAR}/cp\n\
         \x20 IdentityAgent /nonexistent/hm-corpus/${HM_CORPUS_VAR}/agent\n\
         \x20 IdentityFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/id\n\
         \x20 KnownHostsCommand /bin/echo ${HM_CORPUS_VAR}\n\
         \x20 UserKnownHostsFile /nonexistent/hm-corpus/${HM_CORPUS_VAR}/kh\n\
         \x20 Include @SCRATCH@/${HM_CORPUS_VAR}.conf\n",
    );
    h.write("hmexpanded.conf", "Host env-x\n  Port 2950\n");
    let env = [("HM_CORPUS_VAR", "hmexpanded")];
    let (exit, printed, stderr) = h.ssh_g(&file, "env-x", None, &env);
    assert_eq!(exit, 0, "{stderr}");
    let observe = |k: &str| -> &'static str {
        match printed.get(k) {
            None => "absent",
            Some(v) if v.iter().any(|s| s.contains("hmexpanded")) => "expanded",
            Some(v) if v.iter().any(|s| s.contains("${HM_CORPUS_VAR}")) => "literal_in_dump",
            Some(_) => "other",
        }
    };
    let row = client::observed(h.version);
    let gated_row = row.and_then(|r| r.env_in_user_setenv_include);
    let observed_for = |kw: KnownKeyword| -> Option<bool> {
        if client::GATED_EXPANSION_KEYWORDS.contains(&kw) {
            gated_row
        } else {
            // Not gated: every client expands it, as the pinned manual says.
            Some(true)
        }
    };
    let observable: &[(KnownKeyword, &str)] = &[
        (KnownKeyword::User, "user"),
        (KnownKeyword::SetEnv, "setenv"),
        (KnownKeyword::RevokedHostKeys, "revokedhostkeys"),
        (KnownKeyword::LocalForward, "localforward"),
        (KnownKeyword::RemoteForward, "remoteforward"),
        (KnownKeyword::ControlPath, "controlpath"),
        (KnownKeyword::IdentityAgent, "identityagent"),
    ];
    let mut disagreements = Vec::new();
    for (kw, key) in observable {
        let seen = observe(key);
        let heimdall = client::expands_env(*kw, h.version);
        let verdict = judge(observed_for(*kw), heimdall, seen == "expanded", true);
        h.record(
            "s01_env_expansion_keywords_match_the_client",
            kw.as_str(),
            &[
                ("dump", seen.to_owned()),
                ("heimdall_expands_env", heimdall.to_string()),
                (
                    "heimdall_stricter",
                    verdict.clone().unwrap_or(false).to_string(),
                ),
            ],
        );
        if let Err(why) = verdict {
            disagreements.push(format!("{}: {why} ({seen})", kw.as_str()));
        }
    }
    for (kw, key) in [
        (KnownKeyword::IdentityFile, "identityfile"),
        (KnownKeyword::CertificateFile, "certificatefile"),
        (KnownKeyword::KnownHostsCommand, "knownhostscommand"),
        (KnownKeyword::UserKnownHostsFile, "userknownhostsfile"),
    ] {
        h.record(
            "s01_env_expansion_keywords_match_the_client",
            kw.as_str(),
            &[
                ("dump", observe(key).to_owned()),
                (
                    "heimdall_expands_env",
                    client::expands_env(kw, h.version).to_string(),
                ),
                ("note", "not observable through ssh -G".to_owned()),
            ],
        );
    }
    let include_expanded = printed.get("port") == Some(&vec!["2950".to_owned()]);
    let heimdall_include = client::include_expansion(h.version).env;
    let verdict = judge(
        observed_for(KnownKeyword::Include),
        heimdall_include,
        include_expanded,
        true,
    );
    h.record(
        "s01_env_expansion_keywords_match_the_client",
        "Include",
        &[
            (
                "effect",
                if include_expanded {
                    "expanded"
                } else {
                    "not_expanded"
                }
                .to_owned(),
            ),
            ("heimdall_expands_env", heimdall_include.to_string()),
            (
                "heimdall_stricter",
                verdict.clone().unwrap_or(false).to_string(),
            ),
        ],
    );
    if let Err(why) = verdict {
        disagreements.push(format!("Include: {why}"));
    }
    let (evaluation, behavior) = h.heimdall(&file, "env-x", None, &env);
    if heimdall_include {
        // Heimdall's own Include expansion reaches the same file, as a candidate only:
        // a path that reads a variable names the runtime's file, which a later ssh may
        // not read, so the values it brings are undetermined (ADR-0007 §12.16 item 1).
        match &behavior.port {
            Resolved::Undetermined(vs) => assert!(
                vs.iter()
                    .any(|v| v.args.first().map(String::as_str) == Some("2950")),
                "{vs:?}"
            ),
            other => panic!("an environment-dependent Include gave {other:?}"),
        }
    } else {
        // A client that takes the Include literally globs `${HM_CORPUS_VAR}.conf`,
        // which no file matches: the port is the default, determined.
        assert_eq!(behavior.port, Resolved::Unset, "{}", h.client());
        assert_eq!(printed.get("port"), Some(&vec!["22".to_owned()]));
    }
    // The User and SetEnv this client reads literally are determined as written.
    if !client::expands_env(KnownKeyword::User, h.version) {
        assert_eq!(
            first_arg(&behavior.user).as_deref(),
            Some("u${HM_CORPUS_VAR}"),
            "{}",
            h.client()
        );
    }
    // IdentityAgent (and the other ungated keywords) still read the variable on every
    // client: undetermined.
    assert!(
        evaluation
            .unresolved
            .iter()
            .any(|u| u.reason == heimdall_sshconf::eval::UnresolvedReason::EnvironmentReference)
    );
    assert!(
        disagreements.is_empty(),
        "{}: {disagreements:?}",
        h.client()
    );
}

/// ADR-0007 §12.32 item 11 (b), the `%` tokens of `Include` (found with the 9.6p1
/// diagnosis): `Include <scratch>/inc-%h.conf` names `inc-tok-x.conf` on a client that
/// expands tokens there and the file literally named `inc-%h.conf` on one that does not
/// (9.6p1). Heimdall must read the file this client reads. `User u%h` is recorded only:
/// a token-expanding client prints the expanded user, while `Match user` still reads the
/// value as written (observed on 10.5p1), which is what Heimdall evaluates.
#[test]
fn include_tokens_follow_the_client() {
    let h = Harness::new();
    h.write("inc-tok-x.conf", "Host tok-x\n  Port 2962\n");
    h.write("inc-%h.conf", "Host tok-x\n  Port 2965\n");
    let file = h.write("tok_include.conf", "Include @SCRATCH@/inc-%h.conf\n");
    let (exit, printed, stderr) = h.ssh_g(&file, "tok-x", None, &[]);
    assert_eq!(exit, 0, "{stderr}");
    let ssh_port = printed.get("port").map(|v| v.join(",")).unwrap_or_default();
    let (evaluation, behavior) = h.heimdall(&file, "tok-x", None, &[]);
    let heimdall_port = first_arg(&behavior.port).unwrap_or_else(|| "22".to_owned());
    let seen_expanded = ssh_port == "2962";
    let heimdall_expands = client::include_expansion(h.version).tokens;
    let user_file = h.write("tok_user.conf", "Host tok-x\n  User u%h\n");
    let (_, user_printed, _) = h.ssh_g(&user_file, "tok-x", None, &[]);
    h.record(
        "include_tokens_follow_the_client",
        "tok-x",
        &[
            ("ssh_g_port", ssh_port.clone()),
            ("client_expands_include_tokens", seen_expanded.to_string()),
            (
                "heimdall_expands_include_tokens",
                heimdall_expands.to_string(),
            ),
            ("heimdall_port", heimdall_port.clone()),
            (
                "ssh_g_user_for_u%h",
                user_printed
                    .get("user")
                    .map(|v| v.join(","))
                    .unwrap_or_default(),
            ),
        ],
    );
    assert!(evaluation.invalid.is_empty(), "{:?}", evaluation.invalid);
    if let Some(row) = client::observed(h.version).and_then(|r| r.tokens_in_user_setenv_include) {
        assert_eq!(
            row,
            seen_expanded,
            "{}: the recorded row differs",
            h.client()
        );
    }
    // Never laxer: the port Heimdall determines is the one this client uses.
    assert_eq!(
        heimdall_port,
        ssh_port,
        "{}: heimdall expands {heimdall_expands}, the client {seen_expanded}",
        h.client()
    );
}

/// ADR-0007 §12.15 item 6 `[I]` facts, settled on this client by comparing the
/// evaluator with `ssh -G`: the Host-pattern case rule per pass, `Match canonical` and
/// `Match final` with `CanonicalizeHostname no`, `HostName` not set again in the final
/// pass, and includes under a false section read "parse only".
#[test]
fn final_pass_case_canonical_and_parse_only_facts_match_ssh_g() {
    let h = Harness::new();
    let case = h.write(
        "case.conf",
        "Host MixedCase\n  Port 2901\nHost mixedcase\n  Port 2911\n",
    );
    let final_case = h.write(
        "final_case.conf",
        "Match final\n  Port 2912\nHost mixedcase\n  User final-lower-host\n",
    );
    let fin = h.write(
        "final.conf",
        "Host fin-a\n  HostName first.example\nMatch final\n  HostName second.example\n  Port 2902\nMatch canonical\n  User canon-user\nHost fin-b\n  Port 2903\n",
    );
    h.write("inc.conf", "Host target\n  Port 2905\n");
    let parse_only = h.write(
        "parseonly.conf",
        "Host nomatch\n  Include @SCRATCH@/inc.conf\nHost target\n  User target-user\n",
    );
    let cases: &[(&str, &Path, &str)] = &[
        ("host_pattern_case_first_pass", &case, "MixedCase"),
        ("host_pattern_case_first_pass_lower", &case, "mixedcase"),
        ("host_pattern_case_final_pass", &final_case, "MixedCase"),
        ("match_final_and_canonical", &fin, "fin-a"),
        ("hostname_not_set_again_in_final_pass", &fin, "fin-b"),
        (
            "parse_only_include_under_false_section",
            &parse_only,
            "target",
        ),
    ];
    let mut all = Vec::new();
    for (name, file, alias) in cases {
        let diffs = compare_alias(&h, name, file, alias, None);
        all.extend(diffs.into_iter().map(|d| format!("{name} {alias}: {d}")));
    }
    // A parse-only include is still checked: an unknown keyword in it makes ssh
    // refuse the file, and Heimdall reports the line invalid.
    h.write("bad.conf", "Host target\n  NoSuchKeywordHm yes\n");
    let bad = h.write(
        "parsebad.conf",
        "Host nomatch\n  Include @SCRATCH@/bad.conf\n",
    );
    let (exit, _, _) = h.ssh_g(&bad, "target", None, &[]);
    let (evaluation, _) = h.heimdall(&bad, "target", None, &[]);
    h.record(
        "parse_only_include_is_still_checked",
        "target",
        &[
            ("ssh_g_exit", exit.to_string()),
            (
                "heimdall_invalid_lines",
                evaluation.invalid.len().to_string(),
            ),
        ],
    );
    if exit == 0 || evaluation.invalid.is_empty() {
        all.push(format!(
            "parse-only include check: ssh exit {exit}, heimdall invalid {}",
            evaluation.invalid.len()
        ));
    }
    assert!(
        all.is_empty(),
        "disagreements on {}:\n{}",
        h.client(),
        all.join("\n").replace(&h.local_user, "<local>")
    );
}

// --- W2b-fix: ADR-0007 §12.16 items 3 and 4, §12.17 item 9 ------------------------------------

/// Y04 (ADR-0007 §12.16 item 4): `Match sessiontype` reads the `SessionType` in force.
/// The reviewer's case (`SessionType none`, so the `none` section applies and the
/// `shell` one does not) and a `SessionType subsystem` case, for a shell invocation;
/// then both again under `-s`, where the command line's session type comes first and
/// the `SessionType` lines take no effect. Each is compared with this client's `ssh -G`.
///
/// ADR-0007 §12.32 item 11 (a): a client that refuses `Match sessiontype` (9.6p1:
/// "Unsupported Match attribute", exit 255) refuses these files, and Heimdall must
/// report each such line invalid (`unsupported_match_criterion`) for it, deciding
/// nothing from it.
#[test]
fn sessiontype_in_force_matches_ssh_g() {
    let h = Harness::new();
    let reviewer = h.write(
        "sessiontype_none.conf",
        "SessionType none\nMatch sessiontype shell\n    HostName wrong.example\nMatch sessiontype none\n    Port 2202\n",
    );
    let subsystem = h.write(
        "sessiontype_subsystem.conf",
        "SessionType subsystem\nMatch sessiontype subsystem\n    Port 2203\nMatch sessiontype shell\n    Port 2204\n",
    );
    let sftp = Invocation::Subsystem("sftp".to_owned());
    let cases: &[(&str, &Path, &Invocation, &str)] = &[
        (
            "sessiontype_none_shell",
            &reviewer,
            &Invocation::Shell,
            "2202",
        ),
        (
            "sessiontype_subsystem_shell",
            &subsystem,
            &Invocation::Shell,
            "2203",
        ),
        ("sessiontype_none_dash_s", &reviewer, &sftp, "22"),
        ("sessiontype_subsystem_dash_s", &subsystem, &sftp, "2203"),
    ];
    let heimdall_accepts = client::accepts_match_criterion("sessiontype", h.version);
    let row = client::observed(h.version).and_then(|r| r.match_criteria[1]);
    let mut all = Vec::new();
    for (name, file, invocation, port) in cases {
        let (exit, _, stderr) = h.ssh_g_invoked(file, "box", None, &[], invocation);
        let client_accepts = exit == 0;
        let (evaluation, behavior) =
            h.heimdall_invoked(file, "box", None, &[], (*invocation).clone());
        let refused_lines = evaluation
            .invalid
            .iter()
            .filter(|i| i.reason == "unsupported_match_criterion")
            .count();
        let verdict = judge(row, heimdall_accepts, client_accepts, false);
        h.record(
            name,
            "box",
            &[
                ("ssh_g_exit", exit.to_string()),
                ("client_accepts", client_accepts.to_string()),
                ("heimdall_accepts", heimdall_accepts.to_string()),
                ("heimdall_refused_lines", refused_lines.to_string()),
                (
                    "heimdall_stricter",
                    verdict.clone().unwrap_or(false).to_string(),
                ),
            ],
        );
        if let Err(why) = verdict {
            all.push(format!("{name}: {why}: {stderr}"));
            continue;
        }
        if !client_accepts {
            assert!(
                stderr.contains("Unsupported Match attribute sessiontype"),
                "{name}: {stderr}"
            );
        }
        if !heimdall_accepts {
            // Invalid for this client: both Match lines, and nothing they guard is
            // determined.
            if refused_lines != 2 {
                all.push(format!(
                    "{name}: heimdall refused {refused_lines} lines: {:?}",
                    evaluation.invalid
                ));
            }
            if matches!(behavior.port, Resolved::Determined(_))
                || matches!(behavior.hostname, Resolved::Determined(_))
            {
                all.push(format!("{name}: a refused section decided {behavior:?}"));
            }
            continue;
        }
        let diffs = compare_alias_invoked(&h, name, file, "box", None, invocation);
        all.extend(diffs.into_iter().map(|d| format!("{name}: {d}")));
        // The evaluator's own answer, so a client that agreed by accident is noticed.
        let got = first_arg(&behavior.port).unwrap_or_else(|| "22".to_owned());
        if got != *port || !matches!(behavior.hostname, Resolved::Unset) {
            all.push(format!(
                "{name}: heimdall port {got} hostname {:?}",
                behavior.hostname
            ));
        }
        assert!(evaluation.invalid.is_empty(), "{name}");
    }
    let (_, printed, _) = h.ssh_g(&reviewer, "box", None, &[]);
    h.record(
        "sessiontype_in_force_matches_ssh_g",
        "reviewer_case",
        &[
            (
                "ssh_g_sessiontype",
                printed
                    .get("sessiontype")
                    .map(|v| v.join(","))
                    .unwrap_or_default(),
            ),
            (
                "ssh_g_port",
                printed.get("port").map(|v| v.join(",")).unwrap_or_default(),
            ),
        ],
    );
    assert!(
        all.is_empty(),
        "disagreements on {}:\n{}",
        h.client(),
        all.join("\n")
    );
}

/// ADR-0007 §12.32 item 11 (a), every gated construct against this client: the
/// `Match` criteria `command`, `sessiontype` and `version` (`client::GATED_MATCH_CRITERIA`)
/// and the keywords `RefuseConnection`, `VersionAddendum` and `WarnWeakCrypto`
/// (`client::GATED_KEYWORDS`), which OpenSSH 9.6p1 refuses ("Unsupported Match
/// attribute", "Bad configuration option"). Whether ssh loads the file is compared with
/// whether Heimdall reports it invalid for this version, under the rule of the module
/// documentation. A keyword is probed under a `Host` that never matches (ssh checks the
/// name wherever the line is), and once more under `IgnoreUnknown`, which a client that
/// does not know the keyword honours.
#[test]
fn gated_match_criteria_and_keywords_follow_the_client() {
    let h = Harness::new();
    let row = client::observed(h.version);
    let mut all = Vec::new();
    let mut check =
        |name: &str, text: String, observed: Option<bool>, heimdall: bool, alias: &str| {
            let file = h.write(&format!("{name}.conf"), &text);
            let (exit, _, stderr) = h.ssh_g(&file, alias, None, &[]);
            let (evaluation, _) = h.heimdall(&file, alias, None, &[]);
            let client_accepts = exit == 0;
            let heimdall_valid = evaluation.invalid.is_empty();
            let verdict = judge(observed, heimdall, client_accepts, false);
            h.record(
                "gated_match_criteria_and_keywords_follow_the_client",
                name,
                &[
                    ("ssh_g_exit", exit.to_string()),
                    ("heimdall_accepts", heimdall.to_string()),
                    ("heimdall_invalid", (!heimdall_valid).to_string()),
                    (
                        "heimdall_stricter",
                        verdict.clone().unwrap_or(false).to_string(),
                    ),
                ],
            );
            if let Err(why) = verdict {
                all.push(format!("{name}: {why}: {stderr}"));
            }
            // The gate is what the evaluator applies.
            if heimdall_valid != heimdall {
                all.push(format!(
                    "{name}: gate {heimdall}, evaluation invalid {:?}",
                    evaluation.invalid
                ));
            }
        };
    for (i, criterion) in client::GATED_MATCH_CRITERIA.iter().enumerate() {
        let arg = match *criterion {
            "version" => "OpenSSH_*",
            "sessiontype" => "shell",
            _ => "hm-corpus-cmd",
        };
        check(
            &format!("match_{criterion}"),
            format!("Match {criterion} {arg}\n    Port 2317\n"),
            row.and_then(|r| r.match_criteria[i]),
            client::accepts_match_criterion(criterion, h.version),
            "box",
        );
    }
    for (i, keyword) in client::GATED_KEYWORDS.iter().enumerate() {
        let value = match keyword {
            KnownKeyword::VersionAddendum => "none",
            _ => "no",
        };
        let observed = row.and_then(|r| r.keywords[i]);
        let knows = client::knows_keyword(*keyword, h.version);
        check(
            &format!("kw_{}", keyword.as_str()),
            format!("Host hm-corpus-nomatch\n    {} {value}\n", keyword.as_str()),
            observed,
            knows,
            "box",
        );
        // IgnoreUnknown covers a keyword the client does not know, and is harmless
        // for one it knows: the file loads either way.
        check(
            &format!("kw_{}_ignored", keyword.as_str()),
            format!(
                "IgnoreUnknown {}\nHost hm-corpus-nomatch\n    {} {value}\n",
                keyword.as_str().to_ascii_lowercase(),
                keyword.as_str()
            ),
            Some(true),
            true,
            "box",
        );
    }
    assert!(
        all.is_empty(),
        "disagreements on {}:\n{}",
        h.client(),
        all.join("\n")
    );
}

/// ADR-0007 §12.17 item 9: an Include's `~`, and a relative user Include, follow
/// `$HOME`. With `HOME` the account home (the harness's scratch home) Heimdall and
/// `ssh -G` read the same file. Under another `HOME` the client reads that home's file;
/// Heimdall reports the Include undetermined (`environment_reference`) and never
/// claims the account home's value.
#[test]
fn include_tilde_follows_home_and_is_undetermined_under_another_home() {
    use heimdall_sshconf::eval::UnresolvedReason;
    use heimdall_sshconf::relevant::unreadable_includes;
    let h = Harness::new();
    let other = h.root.join("other");
    std::fs::create_dir_all(other.join(".ssh")).unwrap();
    std::fs::write(
        h.root.join("home/inc-t.conf"),
        "Host tilde-x\n  Port 2971\n",
    )
    .unwrap();
    std::fs::write(other.join("inc-t.conf"), "Host tilde-x\n  Port 2972\n").unwrap();
    std::fs::write(
        h.root.join("home/.ssh/rel-t.conf"),
        "Host rel-x\n  Port 2973\n",
    )
    .unwrap();
    std::fs::write(other.join(".ssh/rel-t.conf"), "Host rel-x\n  Port 2974\n").unwrap();
    let file = h.write("tilde.conf", "Include ~/inc-t.conf\nInclude rel-t.conf\n");
    let other_s = other.to_string_lossy().into_owned();
    let mut problems = Vec::new();
    for (alias, home_port, other_port) in [("tilde-x", "2971", "2972"), ("rel-x", "2973", "2974")] {
        let (exit, printed, stderr) = h.ssh_g(&file, alias, None, &[]);
        assert_eq!(exit, 0, "{stderr}");
        let (ev, behavior) = h.heimdall(&file, alias, None, &[]);
        let ssh_port = printed.get("port").map(|v| v.join(",")).unwrap_or_default();
        if ssh_port != home_port || first_arg(&behavior.port).as_deref() != Some(home_port) {
            problems.push(format!(
                "{alias}: HOME = account home: ssh -G {ssh_port}, heimdall {:?}",
                behavior.port
            ));
        }
        if ev
            .unresolved
            .iter()
            .any(|u| u.reason == UnresolvedReason::EnvironmentReference)
        {
            problems.push(format!(
                "{alias}: environment_reference with HOME = account home"
            ));
        }
        let env = [("HOME", other_s.as_str())];
        let (exit, printed, _) = h.ssh_g(&file, alias, None, &env);
        let ssh_other = printed.get("port").map(|v| v.join(",")).unwrap_or_default();
        let (ev, behavior) = h.heimdall(&file, alias, None, &env);
        let claimed = match &behavior.port {
            Resolved::Determined(v) => v.args.first().cloned(),
            _ => None,
        };
        h.record(
            "include_tilde_follows_home_and_is_undetermined_under_another_home",
            alias,
            &[
                ("ssh_g_exit_other_home", exit.to_string()),
                ("ssh_g_port_other_home", ssh_other.clone()),
                ("client_follows_home", (ssh_other == other_port).to_string()),
                ("heimdall_port_determined", format!("{claimed:?}")),
            ],
        );
        if claimed.is_some() {
            problems.push(format!(
                "{alias}: another HOME: heimdall claims port {claimed:?}"
            ));
        }
        if !ev
            .unresolved
            .iter()
            .any(|u| u.reason == UnresolvedReason::EnvironmentReference)
            || unreadable_includes(&ev).is_empty()
        {
            problems.push(format!(
                "{alias}: another HOME: not environment_reference / not unreadable"
            ));
        }
    }
    assert!(problems.is_empty(), "{}: {problems:?}", h.client());
}

/// Y03 (ADR-0007 §12.16 item 3), the reviewer's case against this client: P under
/// `dir[1]` while `dir1` exists. A quoted Include written by hand shows what the client
/// does with the brackets (recorded; the reviewer's 10.3p1 loaded `dir1`). The
/// renderer refuses the target, `unmanageable{include_target_glob}`, so Heimdall never
/// writes such a B.
#[test]
fn include_target_with_glob_metacharacters_is_refused_before_any_edit() {
    use heimdall_sshconf::render::{PathStyle, RenderError};
    let h = Harness::new();
    for (dir, host) in [
        ("dir[1]", "intended.example"),
        ("dir1", "different.example"),
    ] {
        std::fs::create_dir_all(h.root.join(dir)).unwrap();
        std::fs::write(
            h.root.join(dir).join("managed.conf"),
            format!("Host box\n  HostName {host}\n"),
        )
        .unwrap();
    }
    let target = h.root.join("dir[1]").join("managed.conf");
    let written = render_path(&target);
    let file = h.write(
        "glob_user.conf",
        &format!("Include \"{}\"\n", written.as_str()),
    );
    let (exit, printed, _) = h.ssh_g(&file, "box", None, &[]);
    let loaded = printed
        .get("hostname")
        .map(|v| v.join(","))
        .unwrap_or_default();
    h.record(
        "include_target_with_glob_metacharacters_is_refused_before_any_edit",
        "box",
        &[
            ("ssh_g_exit", exit.to_string()),
            ("ssh_g_hostname", loaded.clone()),
            (
                "client_globbed_quoted_include",
                (loaded == "different.example").to_string(),
            ),
        ],
    );
    let style = if cfg!(windows) {
        PathStyle::Windows
    } else {
        PathStyle::Unix
    };
    let marker = MarkerId::parse("hm-0123456789abcdef").unwrap();
    let p = RenderPath::absolute(&target, style).unwrap();
    assert_eq!(
        render_include_block(&marker, &p, Newline::Lf),
        Err(RenderError::Unmanageable("include_target_glob"))
    );
    // Control: the literal directory renders, and the client loads it through B.
    let literal = RenderPath::absolute(&h.root.join("dir1").join("managed.conf"), style).unwrap();
    let block = render_include_block(&marker, &literal, Newline::Lf).unwrap();
    let user = h.root.join("glob_user_b.conf");
    std::fs::write(&user, &block).unwrap();
    let (exit, printed, stderr) = h.ssh_g(&user, "box", None, &[]);
    assert_eq!(exit, 0, "{stderr}");
    assert_eq!(
        printed.get("hostname"),
        Some(&vec!["different.example".to_owned()])
    );
}
