//! Git observation (m02-plan U3 "Tests (Git observation, M2-D10)"; ADR-0007 §5.6, §8,
//! F22).
//!
//! Cargo test target `integration_git_observe` hosted by `heimdall-localenv` (review
//! F09 convention). Every test runs the local `git` with a scratch `HOME` this process
//! created, either `GIT_CONFIG_NOSYSTEM=1` or a scratch `GIT_CONFIG_SYSTEM`, no
//! `GIT_CONFIG_GLOBAL` unless the test redirects it into scratch, and `PATH` only:
//! the owner's Git configuration and `~/.gitconfig` are never read (m02-plan §0).
//! Heimdall's observation gets the same environment through an `Env` snapshot; the
//! test's own `git` runs get it through `env_clear`. Observations specific to this
//! Git (F22 `[I]` facts) are recorded on stderr as `observation` lines, paths shown
//! relative to `<scratch>`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use heimdall_contract::doctor::{
    DoctorReport, Finding, GitScope, GitSshClassification, GitSshSource, finding,
};
use heimdall_contract::setup::{GitFileResolution, GitGlobalFileKind};
use heimdall_localenv::clients::{ClientInventory, ClientsConfig, resolve_clients};
use heimdall_localenv::doctor::{DoctorRequest, LocalContext, run};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::git::{
    GitGlobalObservation, observe_global, observe_global_for, origin_of, parse_origin_values,
    parse_scope_value, resolve_global_file, resolve_run_selection, value_digest,
};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::render::{MarkerId, Newline, RenderPath, render_git_include_block};
use heimdall_testkit::home::{Scratch, find_program};
use heimdall_testkit::{CANARY_PREFIX, assert_no_canary};

/// A scratch Git home.
struct GitHome {
    _scratch: Scratch,
    /// Canonical scratch root.
    root: PathBuf,
    /// The scratch `HOME`.
    home: PathBuf,
    git: PathBuf,
    /// Extra variables for this test (`GIT_CONFIG_SYSTEM`, `GIT_CONFIG_GLOBAL` …).
    vars: BTreeMap<String, OsString>,
}

impl GitHome {
    fn new() -> GitHome {
        let scratch = Scratch::new().unwrap();
        // The product's canonical form: on Windows `std::fs::canonicalize` gives the
        // verbatim `\\?\C:\…` form, which Git for Windows cannot use as `HOME` (exit 128,
        // "unable to access '\?\C:\…\.config/git/config'") and B_git cannot name
        // (ADR-0007 §4 refuses verbatim paths). Unix: the same as `canonicalize`.
        let root = heimdall_localenv::fs::canonical_path(scratch.path()).unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let git = find_program("git").expect("git on PATH");
        let mut vars = BTreeMap::new();
        vars.insert("GIT_CONFIG_NOSYSTEM".to_owned(), OsString::from("1"));
        // Never the runner's XDG directory, whatever it exports (M02 wave 5d).
        vars.insert(
            "XDG_CONFIG_HOME".to_owned(),
            home.join(".config").into_os_string(),
        );
        // Windows: every process has `SystemRoot`, and the client inventory selects the
        // OpenSSH programs from `%SystemRoot%\System32\OpenSSH` only (ADR-0004 E6). A
        // machine-wide value, not the owner's home or configuration.
        if cfg!(windows)
            && let Some(root) = std::env::var_os("SystemRoot")
        {
            vars.insert("SystemRoot".to_owned(), root);
        }
        GitHome {
            _scratch: scratch,
            root,
            home,
            git,
            vars,
        }
    }

    fn path_var(&self) -> OsString {
        let dir = self.git.parent().unwrap().to_path_buf();
        // Windows has no `/usr/bin` or `/bin` (they are not absolute there): the
        // directory of the `ssh` this test environment resolves (the in-box OpenSSH,
        // first on the harness `PATH`) stands in for them.
        let rest = if cfg!(windows) {
            vec![
                find_program("ssh")
                    .expect("ssh on PATH")
                    .parent()
                    .unwrap()
                    .to_path_buf(),
            ]
        } else {
            vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")]
        };
        std::env::join_paths(std::iter::once(dir).chain(rest)).unwrap()
    }

    fn env(&self) -> Env {
        let mut vars: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), self.path_var()),
            ("HOME".into(), self.home.clone().into_os_string()),
        ];
        vars.extend(
            self.vars
                .iter()
                .map(|(k, v)| (OsString::from(k), v.clone())),
        );
        Env::from_vars(vars)
    }

    fn system_file(&mut self, text: &str) -> PathBuf {
        let p = self.root.join("system-gitconfig");
        std::fs::write(&p, text).unwrap();
        self.vars.remove("GIT_CONFIG_NOSYSTEM");
        self.vars
            .insert("GIT_CONFIG_SYSTEM".to_owned(), p.clone().into_os_string());
        p
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text.replace("@HOME@", &self.home.to_string_lossy())).unwrap();
        p
    }

    fn inventory(&self) -> ClientInventory {
        let paths = SshPaths::with_test_override(self.home.clone(), self.root.join("etc-ssh"));
        resolve_clients(
            &self.env(),
            &paths,
            &ClientsConfig::default(),
            LocalQueries::Enabled,
        )
    }

    fn observe(&self) -> GitGlobalObservation {
        observe_global(&self.env(), &self.inventory(), LocalQueries::Enabled)
    }

    /// [`Self::observe`] with `managed` as Heimdall's own P_git (ADR-0007 §12.34 item 8).
    fn observe_for(&self, managed: &Path) -> GitGlobalObservation {
        observe_global_for(
            &self.env(),
            &self.inventory(),
            LocalQueries::Enabled,
            managed,
        )
    }

    /// The passive doctor over this scratch world (no alias is evaluated), with
    /// `managed_ssh` as Heimdall's P (its directory then holds P_git).
    fn doctor(&self, managed_ssh: Option<&Path>, queries: LocalQueries) -> DoctorReport {
        let mut ctx = LocalContext::new(
            SshPaths::with_test_override(self.home.clone(), self.root.join("etc-ssh")),
            self.env(),
            Platform::current(),
            ClientsConfig::default(),
            Limits::default(),
        );
        ctx.managed_file = managed_ssh.map(Path::to_path_buf);
        let mut request = DoctorRequest::passive();
        request.local_queries = queries;
        request.aliases = Some(Vec::new());
        run(&ctx, &request)
    }

    /// Run the local `git` with exactly this test's environment.
    fn git(&self, cwd: &Path, args: &[&str]) -> (i32, Vec<u8>) {
        let mut cmd = Command::new(&self.git);
        cmd.env_clear()
            .env("PATH", self.path_var())
            .env("HOME", &self.home)
            .current_dir(cwd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        (out.status.code().unwrap_or(-1), out.stdout)
    }

    fn record(&self, test: &str, fields: &[(&str, String)]) {
        let (_, version) = self.git(&self.root, &["--version"]);
        let mut line = format!(
            "observation test={test} git={:?}",
            String::from_utf8_lossy(&version).trim()
        );
        for (k, v) in fields {
            // Both forms: Git for Windows prints paths with `/` separators.
            let v = v
                .replace(&*self.root.to_string_lossy(), "<scratch>")
                .replace(&git_path(&self.root), "<scratch>");
            line.push_str(&format!(" {k}={v:?}"));
        }
        eprintln!("{line}");
    }

    /// The origin an observation shows for `rel` under Git's home: `~/` and `/`
    /// separators on every platform (ADR-0007 §12.26 item 7, §12.43 item 1).
    fn display(&self, rel: &str) -> String {
        format!("file:~/{rel}")
    }
}

fn per_scope(obs: &GitGlobalObservation) -> BTreeMap<String, u32> {
    let mut m = BTreeMap::new();
    for v in &obs.values {
        *m.entry(format!("{:?}", v.scope)).or_insert(0) += v.count;
    }
    m
}

#[test]
fn git_config_query_output_parsed() {
    let h = GitHome::new();
    h.write(
        ".gitconfig",
        "[core]\n\tsshCommand = \"ssh -v\" # c\n[include]\n\tpath = inc.conf\n",
    );
    h.write("inc.conf", "[core]\n\tsshCommand = included-ssh\n");
    let (code, out) = h.git(
        Path::new("/"),
        &[
            "config",
            "--global",
            "--includes",
            "--show-origin",
            "-z",
            "--get-all",
            "core.sshCommand",
        ],
    );
    assert_eq!(code, 0);
    let pairs = parse_origin_values(&out).expect("the --show-origin -z form parses");
    // The origin as Git prints it: Git for Windows writes `file:C:/…` with `/`
    // separators (observed on 2.55.0.windows.3); elsewhere the path as given.
    let home = git_path(&h.home);
    assert_eq!(
        pairs,
        vec![
            (format!("file:{home}/.gitconfig"), "ssh -v".to_owned()),
            (format!("file:{home}/inc.conf"), "included-ssh".to_owned()),
        ]
    );
    let (code, out) = h.git(
        Path::new("/"),
        &["config", "--show-scope", "-z", "--get", "core.sshCommand"],
    );
    assert_eq!(code, 0);
    assert_eq!(
        parse_scope_value(&out),
        Some((GitScope::Global, "included-ssh".to_owned())),
        "the --show-scope -z form parses to the winning (last) value"
    );
    // Heimdall's observation reports both origins by digest only.
    let obs = h.observe();
    let origins: Vec<_> = obs
        .values
        .iter()
        .map(|v| {
            (
                v.origin_display.clone().unwrap(),
                v.value_sha256.clone(),
                v.count,
            )
        })
        .collect();
    assert_eq!(
        origins,
        vec![
            (h.display(".gitconfig"), value_digest("ssh -v"), 1),
            (h.display("inc.conf"), value_digest("included-ssh"), 1),
        ]
    );
    assert!(obs.unreadable.is_empty(), "{:?}", obs.unreadable);
}

#[test]
fn git_global_file_resolution_follows_read_order() {
    let h = GitHome::new();
    let env = h.env();
    // Neither file: ~/.gitconfig is created.
    let r = resolve_global_file(&env).unwrap();
    assert_eq!(
        (r.file, r.rule, r.path.clone()),
        (
            GitGlobalFileKind::HomeGitconfig,
            GitFileResolution::Created,
            h.home.join(".gitconfig")
        )
    );
    // Only ~/.gitconfig.
    h.write(".gitconfig", "");
    let r = resolve_global_file(&env).unwrap();
    assert_eq!(
        (r.file, r.rule),
        (
            GitGlobalFileKind::HomeGitconfig,
            GitFileResolution::FirstReadExisting
        )
    );
    // Both: the XDG file, which Git reads first.
    h.write(".config/git/config", "");
    let r = resolve_global_file(&env).unwrap();
    assert_eq!(
        (r.file, r.rule),
        (
            GitGlobalFileKind::XdgConfig,
            GitFileResolution::FirstReadExisting
        )
    );
    assert_eq!(r.path, h.home.join(".config").join("git").join("config"));
    // Only XDG.
    std::fs::remove_file(h.home.join(".gitconfig")).unwrap();
    let r = resolve_global_file(&env).unwrap();
    assert_eq!(
        (r.file, r.rule),
        (
            GitGlobalFileKind::XdgConfig,
            GitFileResolution::FirstReadExisting
        )
    );
    // The read order itself, from this Git: `git var GIT_CONFIG_GLOBAL` lists the XDG
    // file first, and with both files holding a value an unscoped query returns the
    // XDG value first.
    h.write(".gitconfig", "[core]\n\tsshCommand = home-value\n");
    h.write(".config/git/config", "[core]\n\tsshCommand = xdg-value\n");
    let (code, var) = h.git(Path::new("/"), &["var", "GIT_CONFIG_GLOBAL"]);
    let listed: Vec<String> = String::from_utf8_lossy(&var)
        .lines()
        .map(str::to_owned)
        .collect();
    let (_, all) = h.git(
        Path::new("/"),
        &["config", "-z", "--get-all", "core.sshCommand"],
    );
    let values: Vec<String> = all
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    h.record(
        "git_global_file_resolution_follows_read_order",
        &[
            ("git_var_exit", code.to_string()),
            ("git_var_global", listed.join(",")),
            ("unscoped_read_order", values.join(",")),
        ],
    );
    assert_eq!(
        values,
        ["xdg-value", "home-value"],
        "this Git does not read the XDG file first"
    );
    if code == 0 {
        assert_eq!(
            listed.first().map(PathBuf::from),
            Some(h.home.join(".config/git/config"))
        );
    }
    // GIT_CONFIG_GLOBAL redirects: no file is offered.
    let mut r = h;
    r.vars.insert(
        "GIT_CONFIG_GLOBAL".to_owned(),
        r.root.join("other-gitconfig").into_os_string(),
    );
    assert!(resolve_global_file(&r.env()).is_none());
    let obs = r.observe();
    assert!(obs.file.is_none());
    assert!(obs.env_overrides.contains(&"GIT_CONFIG_GLOBAL"));
    assert_eq!(obs.not_applicable_reason(), Some("git_global_redirected"));
}

#[test]
fn git_run_selection_in_cwd_reports_local_override() {
    let h = GitHome::new();
    let repo = h.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert_eq!(h.git(&repo, &["init", "-q"]).0, 0);
    let inv = h.inventory();
    let ssh = inv
        .selected(heimdall_localenv::clients::ClientKind::Ssh)
        .expect("ssh on PATH")
        .path
        .clone();
    let env = h.env();
    // Nothing set anywhere: Git's default. That is `ssh` from PATH, the verified client
    // here, except where Git for Windows ships its own MSYS `ssh.exe` beside its `cmd`
    // or `bin` directory: then Git's default is that bundled client (ADR-0007 §5.6
    // "Git's default SSH", §8, F16).
    let git_root = h.git.parent().and_then(Path::parent).unwrap();
    let git_root = if git_root
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("mingw64"))
    {
        git_root.parent().unwrap()
    } else {
        git_root
    };
    let bundled = cfg!(windows) && git_root.join("usr").join("bin").join("ssh.exe").is_file();
    h.record(
        "git_run_selection_in_cwd_reports_local_override",
        &[("git_bundles_msys_ssh", bundled.to_string())],
    );
    let s = resolve_run_selection(&repo, &env, &inv, LocalQueries::Enabled);
    assert_eq!(s.source, GitSshSource::Default);
    assert_eq!(
        s.classification,
        if bundled {
            GitSshClassification::BundledMsys
        } else {
            GitSshClassification::VerifiedClient
        }
    );
    // A global value naming the verified client, quoted as Heimdall renders it: `/`
    // separators, single-quoted, then Git-config double-quoted (ADR-0007 §4).
    h.write(
        ".gitconfig",
        &format!("[core]\n\tsshCommand = \"'{}'\"\n", git_path(&ssh)),
    );
    let s = resolve_run_selection(&repo, &env, &inv, LocalQueries::Enabled);
    assert_eq!(
        (s.source, s.scope, s.classification),
        (
            GitSshSource::Config,
            Some(GitScope::Global),
            GitSshClassification::VerifiedClient
        )
    );
    // A repository-local value wins in that directory and is reported with its scope.
    assert_eq!(
        h.git(&repo, &["config", "core.sshCommand", "other-ssh -v"])
            .0,
        0
    );
    let s = resolve_run_selection(&repo, &env, &inv, LocalQueries::Enabled);
    assert_eq!(
        (s.source, s.scope, s.classification),
        (
            GitSshSource::Config,
            Some(GitScope::Local),
            GitSshClassification::Other
        )
    );
    // Outside the repository the global value is the selection.
    let s = resolve_run_selection(&h.root, &env, &inv, LocalQueries::Enabled);
    assert_eq!(s.scope, Some(GitScope::Global));
    // GIT_SSH_COMMAND in the child's environment wins over every scope.
    let child = Env::from_vars(
        env.iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .chain([(
                OsString::from("GIT_SSH_COMMAND"),
                OsString::from("other-ssh"),
            )]),
    );
    let s = resolve_run_selection(&repo, &child, &inv, LocalQueries::Enabled);
    assert_eq!((s.source, s.scope), (GitSshSource::EnvGitSshCommand, None));
    // Without local queries a configured value cannot be ruled out.
    let s = resolve_run_selection(&repo, &env, &inv, LocalQueries::Disabled);
    assert_eq!(s.classification, GitSshClassification::Undetermined);
}

#[test]
fn git_values_never_leave_observation() {
    let canary = format!("{CANARY_PREFIX}GITVALUE_{}", std::process::id());
    let value = format!("ssh -o SetEnv=X={canary}");
    let mut h = GitHome::new();
    h.system_file(&format!("[core]\n\tsshCommand = \"{value} system\"\n"));
    h.write(
        ".gitconfig",
        &format!(
            "[core]\n\tsshCommand = \"{value}\"\n[include]\n\tpath = inc.conf\n[includeIf \"gitdir:@HOME@/work/\"]\n\tpath = cond.conf\n"
        ),
    );
    h.write(
        "inc.conf",
        &format!("[core]\n\tsshCommand = \"{value} inc\"\n"),
    );
    h.write(
        "cond.conf",
        &format!("[core]\n\tsshCommand = \"{value} cond\"\n"),
    );
    let repo = h.root.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    assert_eq!(h.git(&repo, &["init", "-q"]).0, 0);
    assert_eq!(
        h.git(
            &repo,
            &["config", "core.sshCommand", &format!("{value} local")]
        )
        .0,
        0
    );
    let inv = h.inventory();
    let obs = observe_global(&h.env(), &inv, LocalQueries::Enabled);
    let sel = resolve_run_selection(&repo, &h.env(), &inv, LocalQueries::Enabled);
    assert_eq!(obs.values.len(), 4, "{:?}", obs.values);
    // `Debug` prints every field of the observation and the selection.
    for text in [format!("{obs:?}"), format!("{sel:?}")] {
        assert_no_canary(&text);
    }
    // The digest is of the value, not of the line.
    assert!(
        obs.values
            .iter()
            .any(|v| v.value_sha256 == value_digest(&value))
    );
}

#[test]
fn git_both_global_files_present_values_in_either_make_item_not_applicable() {
    let h = GitHome::new();
    // A value only in the XDG file, both files present.
    h.write(".gitconfig", "[user]\n\tname = scratch\n");
    h.write(".config/git/config", "[core]\n\tsshCommand = xdg-only\n");
    let obs = h.observe();
    assert_eq!(obs.values.len(), 1, "{:?}", obs.values);
    assert_eq!(
        obs.values[0].origin_display.as_deref(),
        Some(h.display(".config/git/config").as_str())
    );
    assert_eq!(obs.values[0].scope, GitScope::Global);
    assert_eq!(obs.not_applicable_reason(), Some("git_ssh_command_present"));
    // F22 `[I]`: whether this Git's `--global` query reads the XDG file when
    // `~/.gitconfig` exists. Heimdall's static scan does not depend on it.
    let (code, _) = h.git(
        Path::new("/"),
        &[
            "config",
            "--global",
            "--includes",
            "--get-all",
            "core.sshCommand",
        ],
    );
    h.record(
        "git_both_global_files_present_values_in_either_make_item_not_applicable",
        &[(
            "global_query_reads_xdg_when_home_file_exists",
            (code == 0).to_string(),
        )],
    );
    // A value only in ~/.gitconfig, both files present.
    h.write(".gitconfig", "[core]\n\tsshCommand = home-only\n");
    h.write(".config/git/config", "[user]\n\tname = scratch\n");
    let obs = h.observe();
    assert_eq!(obs.values.len(), 1, "{:?}", obs.values);
    assert_eq!(
        obs.values[0].origin_display.as_deref(),
        Some(h.display(".gitconfig").as_str())
    );
    assert_eq!(obs.not_applicable_reason(), Some("git_ssh_command_present"));
}

#[test]
fn git_queries_use_includes_flag_and_expand_includes() {
    let h = GitHome::new();
    h.write(".gitconfig", "[include]\n\tpath = held.conf\n");
    h.write("held.conf", "[core]\n\tsshCommand = held-value\n");
    let obs = h.observe();
    assert_eq!(obs.values.len(), 1);
    assert_eq!(
        obs.values[0].origin_display.as_deref(),
        Some(h.display("held.conf").as_str())
    );
    assert!(!obs.values[0].conditional);
    // The control: the same query without --includes must miss the value, which
    // shows the flag matters on this Git (F22).
    let (with_flag, _) = h.git(
        Path::new("/"),
        &[
            "config",
            "--global",
            "--includes",
            "--show-origin",
            "--get-all",
            "core.sshCommand",
        ],
    );
    let (without_flag, _) = h.git(
        Path::new("/"),
        &[
            "config",
            "--global",
            "--show-origin",
            "--get-all",
            "core.sshCommand",
        ],
    );
    h.record(
        "git_queries_use_includes_flag_and_expand_includes",
        &[
            ("with_includes_exit", with_flag.to_string()),
            ("without_includes_exit", without_flag.to_string()),
        ],
    );
    assert_eq!(with_flag, 0);
    assert_eq!(
        without_flag, 1,
        "a --global query followed include.path without --includes"
    );
}

#[test]
fn git_value_through_conditional_include_is_counted_conditional() {
    let h = GitHome::new();
    std::fs::create_dir_all(h.home.join("work")).unwrap();
    h.write(
        ".gitconfig",
        "[includeIf \"gitdir:@HOME@/work/\"]\n\tpath = cond.conf\n",
    );
    h.write("cond.conf", "[core]\n\tsshCommand = cond-value\n");
    // The query run outside any repository misses it (F22).
    let (code, _) = h.git(
        Path::new("/"),
        &[
            "config",
            "--global",
            "--includes",
            "--get-all",
            "core.sshCommand",
        ],
    );
    h.record(
        "git_value_through_conditional_include_is_counted_conditional",
        &[("query_outside_repository_exit", code.to_string())],
    );
    assert_eq!(
        code, 1,
        "a query outside any repository followed includeIf gitdir:"
    );
    let obs = h.observe();
    assert_eq!(obs.values.len(), 1, "{:?}", obs.values);
    assert!(obs.values[0].conditional);
    assert_eq!(
        obs.values[0].origin_display.as_deref(),
        Some(h.display("cond.conf").as_str())
    );
    assert_eq!(obs.not_applicable_reason(), Some("git_ssh_command_present"));
}

#[test]
fn git_multiplicity_through_includes_counts_each_origin() {
    let mut h = GitHome::new();
    h.system_file("[core]\n\tsshCommand = sys-value\n");
    h.write(
        ".gitconfig",
        "[core]\n\tsshCommand = global-value\n[include]\n\tpath = inc.conf\n",
    );
    h.write("inc.conf", "[core]\n\tsshCommand = inc-value\n");
    let obs = h.observe();
    assert_eq!(obs.values.len(), 3, "{:?}", obs.values);
    let scopes = per_scope(&obs);
    assert_eq!(scopes.get("System"), Some(&1));
    assert_eq!(scopes.get("Global"), Some(&2));
    let origins: Vec<_> = obs
        .values
        .iter()
        .filter_map(|v| v.origin_display.clone())
        .collect();
    assert!(origins.contains(&h.display(".gitconfig")));
    assert!(origins.contains(&h.display("inc.conf")));
}

#[test]
fn git_unreadable_include_makes_item_not_applicable() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let h = GitHome::new();
    h.write(".gitconfig", "[include]\n\tpath = locked.conf\n");
    let locked = h.write("locked.conf", "[core]\n\tsshCommand = hidden\n");
    #[cfg(unix)]
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    #[cfg(windows)]
    let original_dacl = heimdall_testkit::win::dacl_sddl(&locked).unwrap();
    #[cfg(windows)]
    let denied = heimdall_testkit::win::deny_read(&locked).unwrap();
    #[cfg(windows)]
    assert!(std::fs::read(&locked).is_err(), "fixture is unreadable");
    let obs = h.observe();
    #[cfg(unix)]
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
    #[cfg(windows)]
    {
        denied.restore().unwrap();
        assert!(
            heimdall_testkit::win::dacl_sddl(&locked).unwrap() == original_dacl,
            "fixture DACL restored exactly"
        );
        assert!(
            std::fs::read(&locked).is_ok(),
            "fixture readability restored"
        );
    }
    assert!(!obs.unreadable.is_empty());
    assert_eq!(obs.not_applicable_reason(), Some("git_config_unreadable"));

    // An include chain deeper than the bound.
    let h = GitHome::new();
    h.write(".gitconfig", "[include]\n\tpath = c0.conf\n");
    for i in 0..=heimdall_localenv::git::GIT_WALK_DEPTH + 1 {
        h.write(
            &format!("c{i}.conf"),
            &format!("[include]\n\tpath = c{}.conf\n", i + 1),
        );
    }
    let obs = h.observe();
    assert!(
        !obs.unreadable.is_empty(),
        "the depth bound was not enforced"
    );
    assert_eq!(obs.not_applicable_reason(), Some("git_config_unreadable"));
}

// --- Heimdall's own value (ADR-0007 §12.34 item 8, M02 wave 5d) -------------------------

/// Heimdall's P_git as the writer renders it, in shape: one `core.sshCommand`.
const OWN_FILE: &str =
    "# heimdall managed git configuration (fixture)\n[core]\n\tsshCommand = \"'/usr/bin/ssh'\"\n";

/// `p` as a Git configuration path value: forward slashes, which Git reads on every
/// platform (a backslash is an escape in a quoted value).
fn git_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// The block B_git, in shape: a marked unconditional `[include]` naming `managed`.
fn include_of(managed: &Path) -> String {
    format!(
        "# >>> heimdall managed include (id hm-0123456789abcdef); fixture\n[include]\n\tpath = \"{}\"\n# <<< heimdall managed include (id hm-0123456789abcdef)\n",
        git_path(managed)
    )
}

/// After the Git item is applied, B_git includes P_git, which holds Heimdall's own
/// `core.sshCommand`. `observe_global_for` splits it out; `observe_global` (the
/// doctor's) still counts it, as it always has.
#[test]
fn git_own_value_through_the_include_is_split_out_of_values() {
    let h = GitHome::new();
    let managed = h.write("heimdall/gitconfig", OWN_FILE);
    h.write(".gitconfig", &include_of(&managed));

    let obs = h.observe_for(&managed);
    assert!(obs.values.is_empty(), "{:?}", obs.values);
    assert_eq!(obs.own_values.len(), 1, "{:?}", obs.own_values);
    let own = &obs.own_values[0];
    assert_eq!(
        (own.scope, own.count, own.conditional),
        (GitScope::Global, 1, false)
    );
    assert_eq!(own.origin_display, origin_of(&h.env(), &managed));
    assert!(
        own.origin_display
            .as_deref()
            .is_some_and(|o| o.starts_with("file:~") && o.ends_with("gitconfig")),
        "inside Git's home the origin is shown with `~`: {:?}",
        own.origin_display
    );
    assert_eq!(own.value_sha256, value_digest("'/usr/bin/ssh'"));
    assert_eq!(obs.not_applicable_reason(), None, "{obs:?}");

    // The doctor's observation reports what the configuration says, own value included.
    let plain = h.observe();
    assert_eq!(plain.values.len(), 1, "{:?}", plain.values);
    assert!(plain.own_values.is_empty());
    assert_eq!(
        plain.not_applicable_reason(),
        Some("git_ssh_command_present")
    );
    assert_eq!(
        plain.values[0], *own,
        "the same occurrence, only classified"
    );
}

/// The managed file outside Git's home is shown by its canonical path; a managed file
/// that does not exist splits nothing out and has no origin.
#[test]
fn git_own_value_outside_home_and_absent_managed_file() {
    let h = GitHome::new();
    let dir = h.root.join("cfg");
    std::fs::create_dir_all(&dir).unwrap();
    let managed = dir.join("gitconfig");
    std::fs::write(&managed, OWN_FILE).unwrap();
    h.write(".gitconfig", &include_of(&managed));
    let obs = h.observe_for(&managed);
    assert!(
        obs.values.is_empty() && obs.own_values.len() == 1,
        "{obs:?}"
    );
    let origin = origin_of(&h.env(), &managed);
    assert_eq!(obs.own_values[0].origin_display, origin);
    assert!(
        origin.is_some_and(|o| !o.starts_with("file:~")),
        "outside Git's home the origin is the whole path"
    );

    // The file is gone: the include reaches nothing, and nothing is split out.
    let gone = h.root.join("cfg").join("never-written");
    assert_eq!(origin_of(&h.env(), &gone), None);
    let obs = h.observe_for(&gone);
    assert!(
        obs.values.len() == 1 && obs.own_values.is_empty(),
        "{obs:?}"
    );
}

/// A value in any other file stays a user value beside Heimdall's own: in the global
/// file after B_git (what `git config --global` writes), in the XDG file created after
/// the apply (the `git_user_value_shadowed` residual, which wins over B_git in
/// `~/.gitconfig`), and in the system file.
#[test]
fn git_user_value_elsewhere_stays_a_value_beside_the_own_one() {
    // (label, files, expected user-value origin, expected scope)
    type Setup = fn(&mut GitHome, &Path);
    let cases: [(&str, Setup, &str, GitScope); 3] = [
        (
            "after B_git in the same global file",
            |h, managed| {
                h.write(
                    ".gitconfig",
                    &format!("{}[core]\n\tsshCommand = user-after\n", include_of(managed)),
                );
            },
            ".gitconfig",
            GitScope::Global,
        ),
        (
            "XDG file created after the apply",
            |h, managed| {
                h.write(".gitconfig", &include_of(managed));
                h.write(".config/git/config", "[core]\n\tsshCommand = user-xdg\n");
            },
            ".config/git/config",
            GitScope::Global,
        ),
        (
            "system file",
            |h, managed| {
                h.write(".gitconfig", &include_of(managed));
                h.system_file("[core]\n\tsshCommand = user-system\n");
            },
            "",
            GitScope::System,
        ),
    ];
    for (label, setup, origin, scope) in cases {
        let mut h = GitHome::new();
        let managed = h.write("heimdall/gitconfig", OWN_FILE);
        setup(&mut h, &managed);
        let obs = h.observe_for(&managed);
        assert_eq!(obs.own_values.len(), 1, "{label}: {obs:?}");
        assert_eq!(obs.values.len(), 1, "{label}: {obs:?}");
        assert_eq!(obs.values[0].scope, scope, "{label}");
        assert_eq!(obs.values[0].count, 1, "{label}");
        if !origin.is_empty() {
            assert_eq!(
                obs.values[0].origin_display,
                origin_of(&h.env(), &h.home.join(origin)),
                "{label}"
            );
        }
        assert_ne!(
            obs.values[0].origin_display, obs.own_values[0].origin_display,
            "{label}"
        );
        assert_eq!(
            obs.not_applicable_reason(),
            Some("git_ssh_command_present"),
            "{label}: a user value still makes the item not applicable"
        );
    }
}

/// Only B_git's one unconditional global path to the file is Heimdall's own. A second
/// path to the file, a conditional one, one from the system file, or a second key in it
/// is not, and stays a value (fail closed).
#[test]
fn git_own_file_reached_any_other_way_stays_a_value() {
    type Setup = fn(&mut GitHome, &Path);
    let cases: [(&str, Setup, GitScope, bool, u32); 4] = [
        (
            "included twice",
            |h, managed| {
                h.write(
                    ".gitconfig",
                    &format!(
                        "{}[include]\n\tpath = \"{}\"\n",
                        include_of(managed),
                        git_path(managed)
                    ),
                );
            },
            GitScope::Global,
            false,
            2,
        ),
        (
            "only through includeIf",
            |h, managed| {
                std::fs::create_dir_all(h.home.join("work")).unwrap();
                h.write(
                    ".gitconfig",
                    &format!(
                        "[includeIf \"gitdir:@HOME@/work/\"]\n\tpath = \"{}\"\n",
                        git_path(managed)
                    ),
                );
            },
            GitScope::Global,
            true,
            1,
        ),
        (
            "included by the system file",
            |h, managed| {
                h.system_file(&format!("[include]\n\tpath = \"{}\"\n", git_path(managed)));
            },
            GitScope::System,
            false,
            1,
        ),
        (
            "a second key in the file",
            |h, managed| {
                h.write(".gitconfig", &include_of(managed));
                std::fs::write(
                    managed,
                    format!("{OWN_FILE}[core]\n\tsshCommand = a-second-one\n"),
                )
                .unwrap();
            },
            GitScope::Global,
            false,
            2,
        ),
    ];
    for (label, setup, scope, conditional, count) in cases {
        let mut h = GitHome::new();
        let managed = h.write("heimdall/gitconfig", OWN_FILE);
        setup(&mut h, &managed);
        let obs = h.observe_for(&managed);
        assert!(obs.own_values.is_empty(), "{label}: {obs:?}");
        let total: u32 = obs.values.iter().map(|v| v.count).sum();
        assert_eq!(total, count, "{label}: {obs:?}");
        assert!(
            obs.values
                .iter()
                .all(|v| v.scope == scope && v.conditional == conditional),
            "{label}: {obs:?}"
        );
        assert_eq!(
            obs.not_applicable_reason(),
            Some("git_ssh_command_present"),
            "{label}"
        );
    }
}

// --- the doctor and Heimdall's own value (ADR-0007 §12.37 items 1 and 2) ------------------
//
// The doctor observes with P_git's path, so a `core.sshCommand` reached once through an
// intact B_git is Heimdall's own: the projection's Git selection, never
// `git_ssh_command_present`. Every other value is a user's and is reported with its
// origin, and a user value in the other global file, read before Heimdall's, is
// `git_user_value_shadowed`. B_git is rendered by the real renderer, so an intact block
// is byte for byte what the writer wrote.

/// B_git for `managed`, as the writer renders it.
fn heimdall_include(managed: &Path) -> String {
    let marker = MarkerId::parse("hm-0123456789abcdef").unwrap();
    let target = if cfg!(windows) {
        RenderPath::windows(managed)
    } else {
        RenderPath::unix(managed)
    }
    .unwrap();
    String::from_utf8(render_git_include_block(&marker, &target, Newline::Lf).unwrap()).unwrap()
}

fn findings<'a>(report: &'a DoctorReport, code: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.code == code).collect()
}

/// A scratch world where Heimdall's configuration directory is `<home>/heimdall`: P_git
/// holds its one value, and `ssh_config` names P (and so the directory) to the doctor.
fn heimdall_world() -> (GitHome, PathBuf, PathBuf) {
    let h = GitHome::new();
    let managed = h.write("heimdall/gitconfig", OWN_FILE);
    let ssh = h.home.join("heimdall").join("ssh_config");
    (h, managed, ssh)
}

#[test]
fn the_doctor_takes_a_value_reached_once_through_an_intact_b_git_for_heimdalls_own() {
    let (h, managed, ssh) = heimdall_world();
    h.write(".gitconfig", &heimdall_include(&managed));

    let report = h.doctor(Some(&ssh), LocalQueries::Enabled);
    assert!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).is_empty(),
        "{:?}",
        report.findings
    );
    assert!(findings(&report, finding::GIT_USER_VALUE_SHADOWED).is_empty());
    let git = report.git.expect("git is installed on the harness");
    assert!(git.values.is_empty(), "{:?}", git.values);
    // The selection the doctor reports is the projection's: P_git's value, global scope.
    assert_eq!(
        (git.selection.source, git.selection.scope),
        (GitSshSource::Config, Some(GitScope::Global))
    );

    // The control: a value of the user's, set after B_git in the same file, is a present
    // value with its origin; Heimdall's own is still not listed, and the user's value
    // wins (the last occurrence), so nothing is shadowed.
    h.write(
        ".gitconfig",
        &format!(
            "{}[core]\n\tsshCommand = user-after\n",
            heimdall_include(&managed)
        ),
    );
    let report = h.doctor(Some(&ssh), LocalQueries::Enabled);
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "{:?}",
        report.findings
    );
    assert!(findings(&report, finding::GIT_USER_VALUE_SHADOWED).is_empty());
    let git = report.git.unwrap();
    assert_eq!(git.values.len(), 1, "{:?}", git.values);
    assert_eq!(git.values[0].value_sha256, value_digest("user-after"));
    assert_eq!(git.values[0].scope, GitScope::Global);
    assert_eq!(
        git.values[0].origin_display,
        origin_of(&h.env(), &h.home.join(".gitconfig"))
    );
}

/// The value is Heimdall's own only through B_git, intact and naming P_git. In every
/// other arrangement it is a present value, reported with its origin (fail closed).
#[test]
fn the_doctor_reports_the_value_when_no_intact_b_git_links_it() {
    type Setup = fn(&GitHome, &Path);
    let cases: [(&str, Setup, bool); 6] = [
        (
            "the block is edited",
            |h, m| {
                h.write(
                    ".gitconfig",
                    &heimdall_include(m).replacen("\tpath = ", "\tpath =  ", 1),
                );
            },
            true,
        ),
        (
            "the owner's own include, with no Heimdall block",
            |h, m| {
                h.write(
                    ".gitconfig",
                    &format!("[include]\n\tpath = \"{}\"\n", git_path(m)),
                );
            },
            true,
        ),
        (
            "an intact block that names another file",
            |h, m| {
                let other = h.write("heimdall/other", "");
                h.write(
                    ".gitconfig",
                    &format!(
                        "{}[include]\n\tpath = \"{}\"\n",
                        heimdall_include(&other),
                        git_path(m)
                    ),
                );
            },
            true,
        ),
        (
            "the intact block is in both global files",
            |h, m| {
                h.write(".gitconfig", &heimdall_include(m));
                h.write(".config/git/config", &heimdall_include(m));
            },
            true,
        ),
        (
            "B_git is intact but P's directory is not known",
            |h, m| {
                h.write(".gitconfig", &heimdall_include(m));
            },
            false,
        ),
        (
            "no block, and the file is reached by a relative include",
            |h, _| {
                h.write(".gitconfig", "[include]\n\tpath = heimdall/gitconfig\n");
            },
            true,
        ),
    ];
    for (label, setup, known) in cases {
        let (h, managed, ssh) = heimdall_world();
        setup(&h, &managed);
        let report = h.doctor(known.then_some(ssh.as_path()), LocalQueries::Enabled);
        assert_eq!(
            findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
            1,
            "{label}: {:?}",
            report.findings
        );
        let git = report.git.unwrap();
        let own = origin_of(&h.env(), &managed);
        assert!(
            git.values.iter().any(
                |v| v.origin_display == own && v.value_sha256 == value_digest("'/usr/bin/ssh'")
            ),
            "{label}: P_git's value is listed with its origin: {:?}",
            git.values
        );
    }
}

/// B_git is in `~/.gitconfig` because no XDG file existed; the user then creates the XDG
/// file with a value. Git reads that file first, so Heimdall's value wins and the user's
/// is shadowed: the finding names both origins and both digests, and never a value.
#[test]
fn the_doctor_reports_git_user_value_shadowed_with_both_origins() {
    let (h, managed, ssh) = heimdall_world();
    h.write(".gitconfig", &heimdall_include(&managed));
    let xdg = h.write(".config/git/config", "[core]\n\tsshCommand = user-xdg\n");

    let report = h.doctor(Some(&ssh), LocalQueries::Enabled);
    let shadowed = findings(&report, finding::GIT_USER_VALUE_SHADOWED);
    assert_eq!(shadowed.len(), 1, "{:?}", report.findings);
    let f = shadowed[0];
    assert_eq!(f.code, "git_user_value_shadowed");
    let own_origin = origin_of(&h.env(), &managed).unwrap();
    let user_origin = origin_of(&h.env(), &xdg).unwrap();
    for needed in [
        own_origin,
        user_origin,
        value_digest("'/usr/bin/ssh'"),
        value_digest("user-xdg"),
    ] {
        assert!(f.message.contains(&needed), "{needed}: {}", f.message);
    }
    for never in ["user-xdg", "/usr/bin/ssh"] {
        assert!(!f.message.contains(never), "{never}: {}", f.message);
    }
    // The user's value is still a present value with its origin; Heimdall's own is not.
    assert_eq!(
        findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
        1,
        "{:?}",
        report.findings
    );
    let git = report.git.unwrap();
    assert_eq!(git.values.len(), 1, "{:?}", git.values);
    assert_eq!(git.values[0].value_sha256, value_digest("user-xdg"));
}

/// Nothing is shadowed unless Heimdall's own value is the effective one and the user's is
/// in another global file: a user value that wins, one in the system file, and a run
/// without local queries (nobody can say who wins) report no `git_user_value_shadowed`.
#[test]
fn the_doctor_reports_no_shadowing_unless_heimdalls_value_wins_over_a_global_one() {
    type Setup = fn(&mut GitHome, &Path);
    let cases: [(&str, Setup, LocalQueries); 4] = [
        (
            "B_git in the XDG file, the user's value in ~/.gitconfig (read later: it wins)",
            |h, m| {
                h.write(".config/git/config", &heimdall_include(m));
                h.write(".gitconfig", "[core]\n\tsshCommand = user-home\n");
            },
            LocalQueries::Enabled,
        ),
        (
            "the user's value is in the system file",
            |h, m| {
                h.write(".gitconfig", &heimdall_include(m));
                h.system_file("[core]\n\tsshCommand = user-system\n");
            },
            LocalQueries::Enabled,
        ),
        (
            "the case that is shadowed, without local queries",
            |h, m| {
                h.write(".gitconfig", &heimdall_include(m));
                h.write(".config/git/config", "[core]\n\tsshCommand = user-xdg\n");
            },
            LocalQueries::Disabled,
        ),
        (
            "the user's value is in the same file, after B_git",
            |h, m| {
                h.write(
                    ".gitconfig",
                    &format!("{}[core]\n\tsshCommand = user-after\n", heimdall_include(m)),
                );
            },
            LocalQueries::Enabled,
        ),
    ];
    for (label, setup, queries) in cases {
        let (mut h, managed, ssh) = heimdall_world();
        setup(&mut h, &managed);
        let report = h.doctor(Some(&ssh), queries);
        assert!(
            findings(&report, finding::GIT_USER_VALUE_SHADOWED).is_empty(),
            "{label}: {:?}",
            report.findings
        );
        assert_eq!(
            findings(&report, finding::GIT_SSH_COMMAND_PRESENT).len(),
            1,
            "{label}: the user's value is still reported: {:?}",
            report.findings
        );
    }
}
