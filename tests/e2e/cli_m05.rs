//! ⟨M05⟩ U9a (m05-plan U9, U4's client half; ADR-0011 §2–§7, §10 items 3 and 9): the M05
//! command line through the **real binary** (`CARGO_BIN_EXE_heimdall`, or
//! `HEIMDALL_E2E_BIN`) and a real runtime it starts on demand in a scratch home, with the
//! debug build's test configuration (`crates/heimdall/src/testcfg.rs`: the fake adapter,
//! profile `dev` = h1, h2, h3 with the personal policy `pol` covering h1 and h2, profile
//! `ops` = h1 with `pol-ops`).
//!
//! * `hook_creates_no_decision_when_uncovered` (ruling 3, the client half): the hook on a
//!   pseudo-terminal in an untrusted workspace and in a trusted one whose manifest adds a
//!   pair: the decision rows stay as they were, and nothing written to the terminal asks a
//!   question.
//! * `hook_never_evaluates_repository_text`: the real `shell init` script in an interactive
//!   bash and zsh on a pseudo-terminal, entering directories whose names, labels and values
//!   hold `$(…)`, backticks and newlines: the canary files never appear, and the hook ran.
//! * One journey per command family: `project_trust_status_reconcile_untrust`,
//!   `access_targets_stop_and_allow`, `default_profile_set_show_clear`,
//!   `export_then_import_with_the_dry_run_preview`,
//!   `run_without_a_profile_reissues_after_the_trust_decision`.
//! * `workspace_paths_are_quoted_and_bidi_free` (review M05-W3-R03, the reviewer's probe
//!   inverted): `project status` in a checkout whose directory name holds a line break and
//!   a bidirectional override prints each path as one quoted field.
//! * `m05_help_and_shell_script_goldens`: every new command's `--help`
//!   (`tests/contracts/golden/cli-help-m05/`: `cli-help/` is the M03 suite's, which refuses
//!   any file it does not own; its `access.txt` lists `default-profile`) and both shell
//!   scripts (`tests/contracts/golden/shell-init/`); `HM_UPDATE_GOLDENS=1` rewrites them.
//!
//! **Isolation.** Every process gets a cleared environment: `PATH`, a scratch `HOME` and a
//! scratch Heimdall home, `GIT_CONFIG_NOSYSTEM=1`, the test configuration's variables and
//! no `SSH_AUTH_SOCK`; Git repositories are per-run scratch fixtures
//! (`heimdall_testkit::workspace`). The help invocations name the scratch home with
//! `--home` (an `env` value would be printed into the help text). Only runtimes this test
//! started are stopped, through `service stop` on their own scratch homes. Every stdout and
//! stderr byte is scanned for canaries.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]
#![cfg_attr(windows, allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_store::{NoFaults, Store};
use heimdall_testkit::assert_no_canary;
use heimdall_testkit::workspace::{Scratch, manifest, write_manifest};
use serde_json::Value;

/// The binary under test.
fn bin() -> String {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned())
}

/// One finished invocation.
#[derive(Debug)]
struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    /// The last JSON object on stdout (the envelope).
    fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
            .find_map(|l| serde_json::from_str::<Value>(&l).ok())
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }
}

/// A scratch runtime: its Heimdall home, a scratch account home, the scratch workspaces.
struct Rt {
    ws: Scratch,
    home: PathBuf,
    account: PathBuf,
}

impl Rt {
    fn new() -> Rt {
        let ws = Scratch::new().unwrap();
        let account = ws.path("acct");
        std::fs::create_dir_all(&account).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&account, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Rt {
            home: ws.path("hm"),
            account,
            ws,
        }
    }

    fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("HEIMDALL_HOME", self.home.to_string_lossy().into_owned()),
            ("HOME", self.account.to_string_lossy().into_owned()),
            ("GIT_CONFIG_NOSYSTEM", "1".to_owned()),
            ("HEIMDALL_TEST_ADAPTER", "prepare".to_owned()),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
            (
                "HEIMDALL_TEST_SSH_HOME",
                self.account.to_string_lossy().into_owned(),
            ),
        ]
    }

    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear();
        if cfg!(windows) {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        } else {
            cmd.env("PATH", "/usr/bin:/bin");
        }
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        cmd
    }

    /// `heimdall <args>` in `cwd`, stdin closed.
    fn run_in(&self, cwd: &Path, args: &[&str]) -> Out {
        let out = self
            .command(&bin())
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert_no_canary(&out.stdout);
        assert_no_canary(&out.stderr);
        assert!(!out.stderr.contains("panicked"), "{args:?}: {out:?}");
        out
    }

    fn run(&self, args: &[&str]) -> Out {
        self.run_in(self.ws.root(), args)
    }

    /// Start the runtime on demand with an effectful command that changes nothing.
    fn start(&self) {
        let out = self.run(&["--json", "access", "default-profile", "--clear"]);
        assert_eq!(out.code, 0, "{out:?}");
    }

    /// Every decision row, whatever its state (`table_counts`, read-only).
    fn decisions(&self) -> u64 {
        let store = Store::open_read_only(
            &self.home.join("state").join("state.db"),
            Arc::new(NoFaults),
        )
        .unwrap();
        store.transaction(|tx| tx.table_counts()).unwrap().decisions
    }

    /// `heimdall <args>` in `cwd` on a pseudo-terminal (`script(1)`), typing the next of
    /// `answers` each time a new `[y/N]: ` prompt shows (`no` once they run out, which the
    /// assertions then see); stdin stays open until the process exits.
    #[cfg(unix)]
    fn run_pty(&self, cwd: &Path, args: &[&str], answers: &[&str]) -> Out {
        let mut argv = vec![bin()];
        argv.extend(args.iter().map(|a| (*a).to_owned()));
        let mut session = Pty::spawn(self, cwd, &argv, &[]);
        let mut answered = 0;
        let start = Instant::now();
        let code = loop {
            if let Some(code) = session.exited() {
                break code;
            }
            let prompts = session.text().matches("[y/N]: ").count();
            if prompts > answered {
                let answer = answers.get(answered).copied().unwrap_or("no");
                session.type_line(answer);
                answered += 1;
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "{args:?}: did not exit: {}",
                session.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = session.finish();
        assert_no_canary(&stdout);
        assert!(!stdout.contains("panicked"), "{args:?}: {stdout}");
        Out {
            code,
            stdout,
            stderr: String::new(),
        }
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        // The runtime this test started, in its own scratch home (a no-op when none ran).
        let _ = self
            .command(&bin())
            .args(["--json", "service", "stop"])
            .stdin(Stdio::null())
            .output();
    }
}

/// A process on a pseudo-terminal through `script(1)`, its transcript collected.
#[cfg(unix)]
struct Pty {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    seen: Arc<std::sync::Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Pty {
    fn spawn(rt: &Rt, cwd: &Path, argv: &[String], extra: &[(&str, &str)]) -> Pty {
        use std::io::Read as _;
        let mut cmd = if cfg!(target_os = "linux") {
            let quoted: Vec<String> = argv
                .iter()
                .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
                .collect();
            let mut c = rt.command("script");
            c.args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"]);
            c
        } else {
            let mut c = rt.command("script");
            c.args(["-q", "/dev/null"]).args(argv);
            c
        };
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocked: script(1) is needed for the pseudo-terminal cases");
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut stdout = child.stdout.take().unwrap();
        let sink = seen.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Pty {
            stdin: child.stdin.take(),
            child,
            seen,
            reader: Some(reader),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
    }

    fn type_line(&mut self, line: &str) {
        use std::io::Write as _;
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    fn exited(&mut self) -> Option<i32> {
        self.child
            .try_wait()
            .unwrap()
            .map(|s| s.code().unwrap_or(-1))
    }

    /// Wait (bounded) until the transcript contains `needle`.
    fn wait_for(&mut self, needle: &str, limit: Duration) {
        let start = Instant::now();
        while !self.text().contains(needle) {
            assert!(
                self.exited().is_none(),
                "exited before {needle:?}: {}",
                self.text()
            );
            assert!(
                start.elapsed() < limit,
                "no {needle:?} in time: {}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self) -> String {
        let start = Instant::now();
        while self.exited().is_none() {
            assert!(start.elapsed() < Duration::from_secs(60), "did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(self.stdin.take());
        if let Some(r) = self.reader.take() {
            r.join().unwrap();
        }
        self.text()
    }
}

/// What a terminal transcript must never hold when nothing may ask: a question mark, the
/// confirmation prompt, or an invitation to type.
fn asks_nothing(transcript: &str) {
    for needle in ["?", "[y/N]", "Type 'yes'", "confirm"] {
        assert!(
            !transcript.contains(needle),
            "the transcript asks ({needle:?}): {transcript}"
        );
    }
}

// ---- ruling 3: the shell hook never prompts and never creates a decision -----------------

/// Ruling 3, the client half (ADR-0011 §3.2, §10 item 3): `activate --hook` on a
/// pseudo-terminal, in an untrusted workspace whose manifest asks for more than personal
/// access covers, and in a trusted workspace whose manifest adds a pair: the decision rows
/// stay as they were, nothing on the terminal asks a question, the status line is printed
/// when the state changes and not again when it is the same, and only covered access is
/// activated.
#[cfg(unix)]
#[test]
fn hook_creates_no_decision_when_uncovered() {
    let rt = Rt::new();
    let untrusted = rt
        .ws
        .init_repo(
            "untrusted",
            Some(&manifest("u", "dev", &["h3:deploy"], false)),
        )
        .unwrap();
    let trusted = rt
        .ws
        .init_repo(
            "trusted",
            Some(&manifest("t", "dev", &["h3:deploy"], false)),
        )
        .unwrap();
    rt.start();
    let t = trusted.to_str().unwrap();
    let trust = rt.run_pty(&trusted, &["project", "trust", "--cwd", t], &["yes"]);
    assert_eq!(trust.code, 0, "{trust:?}");
    let base = rt.decisions();
    assert_eq!(base, 1, "the trust decision is the only one");

    // An untrusted workspace: nothing is covered, nothing is asked.
    let u = untrusted.to_str().unwrap();
    let out = rt.run_pty(&untrusted, &["activate", "--hook", "--cwd", u], &[]);
    assert_eq!(out.code, 0, "{out:?}");
    asks_nothing(&out.stdout);
    assert!(out.stdout.contains("untrusted 0 0"), "{out:?}");
    assert!(
        out.stdout.contains("this workspace is not trusted"),
        "{out:?}"
    );
    assert_eq!(
        rt.decisions(),
        base,
        "no decision for an untrusted workspace"
    );
    // The same state again: no status line.
    let again = rt.run_pty(
        &untrusted,
        &["activate", "--hook", "--cwd", u, "--last", "untrusted"],
        &[],
    );
    asks_nothing(&again.stdout);
    assert!(!again.stdout.contains("heimdall:"), "{again:?}");

    // The trusted workspace as approved: active, quietly.
    let out = rt.run_pty(&trusted, &["activate", "--hook", "--cwd", t], &[]);
    asks_nothing(&out.stdout);
    assert!(out.stdout.contains("active 0 "), "{out:?}");
    // Its manifest now adds a pair the workspace policy does not hold: the covered part is
    // active, the added pair waits for the owner, and no decision is created.
    write_manifest(
        &trusted,
        &manifest("t", "dev", &["h3:deploy", "h2:deploy"], false),
    )
    .unwrap();
    let out = rt.run_pty(
        &trusted,
        &[
            "--json", "activate", "--hook", "--cwd", t, "--last", "active",
        ],
        &[],
    );
    asks_nothing(&out.stdout);
    assert!(out.stdout.contains("needs_review"), "{out:?}");
    assert!(
        out.stdout
            .contains("asks for access its saved policy does not cover"),
        "{out:?}"
    );
    assert_eq!(
        rt.decisions(),
        base,
        "no decision for a trusted workspace's delta"
    );
    // The foreground asks; the hook still never did (the same delta, now from `run`, makes
    // the one decision the owner reviews).
    let run = rt.run_in(
        &trusted,
        &[
            "--json",
            "--non-interactive",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "exit 0",
        ],
    );
    assert_eq!(run.code, 3, "{run:?}");
    assert_eq!(rt.decisions(), base + 1);
    // The owner reviews that very record (`access allow --workspace`): no second record;
    // afterwards the hook finds everything covered.
    let allow = rt.run_pty(
        &trusted,
        &["access", "allow", "--workspace", "--cwd", t],
        &["yes"],
    );
    assert_eq!(allow.code, 0, "{allow:?}");
    assert!(
        allow.stdout.contains("pairs to add: h2:deploy\r"),
        "{allow:?}"
    );
    assert_eq!(
        rt.decisions(),
        base + 1,
        "the pending record was reviewed, not a new one"
    );
    let out = rt.run_pty(
        &trusted,
        &["activate", "--hook", "--cwd", t, "--last", "needs_review"],
        &[],
    );
    asks_nothing(&out.stdout);
    assert!(out.stdout.contains("active 0 "), "{out:?}");
}

/// The interactive shell on a pseudo-terminal with `extra` in its environment; each of
/// `steps` is typed after the previous one finished (a marker its output prints), then
/// `exit`. Returns the transcript.
#[cfg(unix)]
fn shell_session(rt: &Rt, argv: &[&str], extra: &[(&str, &str)], steps: &[&str]) -> String {
    let argv: Vec<String> = argv.iter().map(|a| (*a).to_owned()).collect();
    let mut s = Pty::spawn(rt, rt.ws.root(), &argv, extra);
    for (i, step) in steps.iter().enumerate() {
        // `HM""STEP` is typed; only the command's output reads `HMSTEP`.
        s.type_line(&format!("{step}; echo HM\"\"STEP{i}"));
        s.wait_for(&format!("HMSTEP{i}\r"), Duration::from_secs(30));
    }
    s.type_line("exit");
    s.finish()
}

/// Every file under `dir` whose name starts with `hm-evaluated` (the canaries).
fn canaries(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for e in entries.flatten() {
        let path = e.path();
        if e.file_name().to_string_lossy().starts_with("hm-evaluated") {
            found.push(path.clone());
        }
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            found.extend(canaries(&path));
        }
    }
    found
}

/// `hook_never_evaluates_repository_text` (m05-plan U4): the static script in a real
/// interactive bash and zsh on a pseudo-terminal, entering three workspaces whose directory
/// names, `project` labels and manifest values hold `$(…)`, backticks and newlines. No
/// canary file appears anywhere, the hook demonstrably ran (its status lines are on the
/// terminal), and no decision exists.
#[cfg(unix)]
#[test]
fn hook_never_evaluates_repository_text() {
    let rt = Rt::new();
    let names = [
        "a$(touch hm-evaluated-1)b",
        "`touch hm-evaluated-2`",
        "line\n$(touch hm-evaluated-3)",
    ];
    let labels = [
        r#"$(touch hm-evaluated-4)"#,
        r#"`touch hm-evaluated-5`"#,
        r#"x\n$(touch hm-evaluated-6)\n`touch hm-evaluated-7`"#,
    ];
    let mut dirs = Vec::new();
    for (i, (name, label)) in names.iter().zip(labels).enumerate() {
        let text = if i == 1 {
            // A refused value: the manifest is invalid, never read further.
            format!(
                "schema_version = 1\nproject = \"{label}\"\n[access]\nprofile = \"dev\"\npairs = [\"$(touch hm-evaluated-8):deploy\"]\n"
            )
        } else {
            manifest(label, "dev", &["h3:deploy"], false)
        };
        dirs.push(rt.ws.init_repo(name, Some(&text)).unwrap());
    }
    rt.start();
    let bindir = Path::new(&bin())
        .parent()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let path = format!("{bindir}:/usr/bin:/bin");
    let d: Vec<String> = dirs
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let extra = [
        ("PATH", path.as_str()),
        ("D0", d[0].as_str()),
        ("D1", d[1].as_str()),
        ("D2", d[2].as_str()),
        ("PS1", "hm> "),
        ("PROMPT", "hm> "),
    ];
    let mut ran = 0;
    for (shell, argv, init) in [
        (
            "/bin/bash",
            vec!["/bin/bash", "--noprofile", "--norc", "-i"],
            r#"eval "$(heimdall shell init bash)""#,
        ),
        (
            "/bin/zsh",
            vec!["/bin/zsh", "-f", "-i"],
            r#"eval "$(heimdall shell init zsh)""#,
        ),
    ] {
        if !Path::new(shell).exists() {
            continue;
        }
        let transcript = shell_session(
            &rt,
            &argv,
            &extra,
            &[
                init,
                r#"cd -- "$D0""#,
                r#"cd -- "$D1""#,
                r#"cd -- "$D2""#,
                "cd /",
            ],
        );
        assert_no_canary(&transcript);
        assert!(
            transcript.contains("heimdall: this workspace is not trusted"),
            "{shell}: the hook ran: {transcript}"
        );
        assert!(
            transcript.contains("heimdall: this workspace asks for access"),
            "{shell}: the refused manifest was reported: {transcript}"
        );
        assert!(canaries(rt.ws.root()).is_empty(), "{shell}: {transcript}");
        ran += 1;
    }
    assert!(
        ran > 0,
        "blocked: neither /bin/bash nor /bin/zsh is present"
    );
    assert!(canaries(rt.ws.root()).is_empty());
    assert_eq!(rt.decisions(), 0, "the hook created no decision");
}

// ---- journeys --------------------------------------------------------------------------

/// `project trust|status|reconcile|untrust` (ADR-0011 §2.1–§2.3): status reads; trust shows
/// the spec §5.2 text, the detail and the label as quoted data, and applies on a typed
/// `yes`; a second trust asks nothing; a re-clone at the same path is ambiguous and one
/// reconcile decision restores trust; untrust removes the workspace policy at once.
#[cfg(unix)]
#[test]
fn project_trust_status_reconcile_untrust() {
    let rt = Rt::new();
    let label = "lab \"x\" $(id)";
    let src = rt
        .ws
        .init_repo("src", Some(&manifest("lab", "dev", &["h3:deploy"], true)))
        .unwrap();
    let repo = rt.ws.clone_repo(&src, "repo").unwrap();
    write_manifest(
        &repo,
        &manifest(&label.replace('"', "\\\""), "dev", &["h3:deploy"], true),
    )
    .unwrap();
    rt.start();
    let r = repo.to_str().unwrap();

    let status = rt.run(&["--json", "project", "status", "--cwd", r]);
    assert_eq!(status.code, 0, "{status:?}");
    assert_eq!(status.json()["data"]["match"], "untrusted");

    // Without a terminal: the decision is recorded and left pending (exit 3).
    let unattended = rt.run(&[
        "--json",
        "--non-interactive",
        "project",
        "trust",
        "--cwd",
        r,
    ]);
    assert_eq!(unattended.code, 3, "{unattended:?}");
    assert!(unattended.json()["next"]["decision_ref"].is_string());

    let trust = rt.run_pty(&repo, &["project", "trust", "--cwd", r], &["yes"]);
    assert_eq!(trust.code, 0, "{trust:?}");
    for needle in [
        "Use dev access automatically for this project?",
        "Work can continue while your desktop and password manager are locked",
        "pairs: h3:deploy",
        "environments: this environment",
        "lock continuity: requested",
        "limits:",
        r#"project label (repository text, shown as data): "lab \"x\" $(id)""#,
        "This workspace is trusted under policy",
    ] {
        assert!(trust.stdout.contains(needle), "{needle}: {}", trust.stdout);
    }
    let status = rt.run(&["--json", "project", "status", "--cwd", r]);
    assert_eq!(status.json()["data"]["match"], "trusted");
    let policy = status.json()["data"]["policy_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let again = rt.run(&[
        "--json",
        "--non-interactive",
        "project",
        "trust",
        "--cwd",
        r,
    ]);
    assert_eq!(again.code, 0, "{again:?}");
    assert_eq!(again.json()["data"]["policy_id"], policy.as_str());
    let decided = rt.decisions();

    // A re-clone at the same path: one reconcile decision.
    rt.ws.reclone_at(&src, &repo).unwrap();
    write_manifest(&repo, &manifest("lab", "dev", &["h3:deploy"], true)).unwrap();
    let status = rt.run(&["--json", "project", "status", "--cwd", r]);
    assert_eq!(status.json()["data"]["match"], "ambiguous", "{status:?}");
    let refused = rt.run(&[
        "--json",
        "--non-interactive",
        "project",
        "trust",
        "--cwd",
        r,
    ]);
    assert_eq!(refused.code, 2, "trust refers to reconcile: {refused:?}");
    let reconcile = rt.run_pty(&repo, &["project", "reconcile", "--cwd", r], &["yes"]);
    assert_eq!(reconcile.code, 0, "{reconcile:?}");
    assert!(
        reconcile
            .stdout
            .contains("Reconcile a moved or re-cloned checkout"),
        "{reconcile:?}"
    );
    assert_eq!(rt.decisions(), decided + 1);
    let status = rt.run(&["--json", "project", "status", "--cwd", r]);
    assert_eq!(status.json()["data"]["match"], "trusted", "{status:?}");

    // Untrust: the workspace policy is removed at once, nothing asked.
    let untrust = rt.run(&[
        "--json",
        "--non-interactive",
        "project",
        "untrust",
        "--cwd",
        r,
    ]);
    assert_eq!(untrust.code, 0, "{untrust:?}");
    let policies = rt.run(&["--json", "inspect", "policies"]);
    let items = policies.json()["data"]["items"].as_array().unwrap().clone();
    assert!(
        items.iter().all(|p| p["workspace_id"].is_null()),
        "only personal policies remain: {items:?}"
    );
    // Outside any workspace: trust is refused, untrust finds nothing.
    let none = rt.run(&["--json", "project", "untrust", "--cwd", "/"]);
    assert_eq!(none.code, 2, "{none:?}");
}

/// `access pause|resume|cutoff` targets, `access stop` (work and profile) and
/// `access allow` (ADR-0011 §4.3, §7): a narrowing applies at once and never asks; a
/// widening is one decision for the whole target, applied on a typed `yes`; a stop revokes
/// now and blocks; a stopped work never reactivates while other work is unaffected; an
/// owner review widens a policy to its profile.
#[cfg(unix)]
#[test]
fn access_targets_stop_and_allow() {
    let rt = Rt::new();
    rt.start();
    // `h1` is in both profiles and covered by both personal policies.
    let ensure = |profile: &str, work: &str| {
        rt.run(&[
            "--json",
            "--non-interactive",
            "access",
            "ensure",
            "--profile",
            profile,
            "--pair",
            "h1:deploy",
            "--work-id",
            work,
            "--request-id",
            work,
        ])
    };
    assert_eq!(ensure("ops", "w-ops").json()["code"], "ACCESS_READY");

    // A targeted pause: immediate, typed result, no decision.
    let pause = rt.run(&[
        "--json",
        "--non-interactive",
        "access",
        "pause",
        "--profile",
        "ops",
    ]);
    assert_eq!(pause.code, 0, "{pause:?}");
    let data = pause.json()["data"].clone();
    assert_eq!(data["target"]["kind"], "profile");
    assert_eq!(data["changed"], true);
    assert_eq!(data["policies"][0]["policy_id"], "pol-ops");
    assert_eq!(data["policies"][0]["paused"], true);
    assert_eq!(ensure("ops", "w-ops-2").json()["code"], "POLICY_PAUSED");
    assert_eq!(rt.decisions(), 0);
    // Resume: one decision for the whole target, on a typed `yes`.
    let resume = rt.run_pty(
        rt.ws.root(),
        &["access", "resume", "--profile", "ops"],
        &["yes"],
    );
    assert_eq!(resume.code, 0, "{resume:?}");
    assert!(
        resume.stdout.contains("policies this applies to:"),
        "{resume:?}"
    );
    assert!(resume.stdout.contains("pol-ops (at revision"), "{resume:?}");
    assert_eq!(rt.decisions(), 1);
    assert_eq!(ensure("ops", "w-ops-3").json()["code"], "ACCESS_READY");

    // Cutoff over every policy: a first cutoff narrows at once; clearing it is a decision.
    let cutoff = rt.run(&[
        "--json",
        "--non-interactive",
        "access",
        "cutoff",
        "--all",
        "--at",
        "2099-01-01T00:00:00Z",
    ]);
    assert_eq!(cutoff.code, 0, "{cutoff:?}");
    assert!(
        cutoff.json()["data"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["cutoff_at"].is_string())
    );
    let clear = rt.run_pty(
        rt.ws.root(),
        &["access", "cutoff", "--all", "--clear"],
        &["yes"],
    );
    assert_eq!(clear.code, 0, "{clear:?}");
    assert_eq!(rt.decisions(), 2);

    // Stop one work: the other work stays; the stopped work ID never reactivates.
    assert_eq!(ensure("ops", "w-a").json()["code"], "ACCESS_READY");
    assert_eq!(ensure("dev", "w-b").json()["code"], "ACCESS_READY");
    let stop = rt.run(&["--json", "access", "stop", "--work", "w-a"]);
    assert_eq!(stop.code, 0, "{stop:?}");
    let again = ensure("ops", "w-a");
    assert_eq!(again.json()["code"], "CREDENTIAL_EXPIRED", "{again:?}");
    assert_eq!(again.json()["data"]["error"]["reason"], "work_stopped");
    let mut other = rt.run(&[
        "--json",
        "--non-interactive",
        "access",
        "ensure",
        "--profile",
        "dev",
        "--pair",
        "h1:deploy",
        "--work-id",
        "w-b",
        "--request-id",
        "w-b-again",
    ]);
    assert_eq!(other.json()["code"], "ACCESS_READY", "{other:?}");

    // Stop a profile: paused and revoked now, in one typed result.
    let stop = rt.run(&["--json", "access", "stop", "--profile", "dev"]);
    assert_eq!(stop.code, 0, "{stop:?}");
    let data = stop.json()["data"].clone();
    assert_eq!(data["policies"][0]["paused"], true);
    assert!(!data["revoked"].as_array().unwrap().is_empty(), "{data}");
    other = ensure("dev", "w-c");
    assert_eq!(other.json()["code"], "POLICY_PAUSED");

    // `access allow --policy`: an owner review that asks only for what `pol` lacks of its
    // profile (h3), and applies it on a typed `yes`; a second review has nothing to ask.
    let resume = rt.run_pty(
        rt.ws.root(),
        &["access", "resume", "--profile", "dev"],
        &["yes"],
    );
    assert_eq!(resume.code, 0, "{resume:?}");
    let before = rt.decisions();
    let allow = rt.run_pty(
        rt.ws.root(),
        &["access", "allow", "--policy", "pol"],
        &["yes"],
    );
    assert_eq!(allow.code, 0, "{allow:?}");
    assert!(
        allow.stdout.contains("pairs to add: h3:deploy\r"),
        "{allow:?}"
    );
    assert_eq!(rt.decisions(), before + 1);
    let full = rt.run(&[
        "--json",
        "--non-interactive",
        "access",
        "allow",
        "--policy",
        "pol",
    ]);
    assert_eq!(full.code, 0, "{full:?}");
    assert_eq!(
        full.json()["data"]["policies"][0]["covers_the_profile"],
        true
    );
    assert_eq!(rt.decisions(), before + 1, "nothing left to review");
    let h3 = rt.run(&[
        "--json",
        "--non-interactive",
        "access",
        "ensure",
        "--profile",
        "dev",
        "--work-id",
        "w-h3",
        "--request-id",
        "w-h3",
    ]);
    assert_eq!(
        h3.json()["code"],
        "ACCESS_READY",
        "the whole profile is covered: {h3:?}"
    );
    let policies = rt.run(&["--json", "inspect", "policies"]);
    assert_eq!(policies.code, 0);
    let preview = rt.run(&["--json", "inspect", "capabilities"]);
    assert!(
        preview.json()["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "trusted-work/1"),
        "trusted-work/1 is offered"
    );
}

/// `access default-profile` (revision 5.1): show, set, show, clear; a preference only.
#[test]
fn default_profile_set_show_clear() {
    let rt = Rt::new();
    rt.start();
    let show = || rt.run(&["--json", "access", "default-profile"]);
    assert!(show().json()["data"]["profile_id"].is_null());
    let set = rt.run(&["--json", "access", "default-profile", "ops"]);
    assert_eq!(set.code, 0, "{set:?}");
    assert_eq!(set.json()["data"]["profile_id"], "ops");
    assert_eq!(show().json()["data"]["profile_id"], "ops");
    let unknown = rt.run(&["--json", "access", "default-profile", "nope"]);
    assert_eq!(unknown.json()["code"], "NOT_FOUND", "{unknown:?}");
    let clear = rt.run(&["--json", "access", "default-profile", "--clear"]);
    assert_eq!(clear.code, 0);
    assert!(show().json()["data"]["profile_id"].is_null());
    assert_eq!(rt.decisions(), 0, "a preference is never a decision");
}

/// `export` then `import` on a second installation (ADR-0011 I4; §17.9): the export file is
/// created exclusively; without a terminal and without `--yes` the dry run's plan is shown
/// and nothing is imported; on a terminal the plan (adds, unchanged, the re-establish list)
/// is shown and a typed `yes` imports it; a re-import has nothing to add; a bundle with an
/// authority section is refused before any runtime contact; the importer's policies are
/// untouched.
#[cfg(unix)]
#[test]
fn export_then_import_with_the_dry_run_preview() {
    let a = Rt::new();
    a.start();
    let out = a.ws.path("bundle.json");
    let o = out.to_str().unwrap();
    let export = a.run(&["--json", "export", "--out", o]);
    assert_eq!(export.code, 0, "{export:?}");
    assert_eq!(export.json()["data"]["profiles"], 2);
    let twice = a.run(&["--json", "export", "--out", o]);
    assert_eq!(twice.code, 2, "never replaces a file: {twice:?}");
    let redacted = a.run(&["export", "--redact"]);
    let bundle: Value = serde_json::from_str(&redacted.stdout).unwrap();
    assert_eq!(bundle["redacted"], true);
    // The importer gets a profile it lacks.
    let mut b_json: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    b_json["profiles"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"id": "imported", "pairs": ["h9:deploy"]}));
    let b = Rt::new();
    let file = b.ws.path("in.json");
    std::fs::write(&file, serde_json::to_vec(&b_json).unwrap()).unwrap();
    let f = file.to_str().unwrap();
    // An authority section: refused before the runtime is contacted.
    let mut evil = b_json.clone();
    evil["policies"] = serde_json::json!([]);
    let evil_file = b.ws.path("evil.json");
    std::fs::write(&evil_file, serde_json::to_vec(&evil).unwrap()).unwrap();
    let refused = b.run(&["--json", "import", "--yes", evil_file.to_str().unwrap()]);
    assert_eq!(refused.code, 2, "{refused:?}");
    assert!(!b.home.join("state").exists(), "no runtime was started");
    b.start();
    let policies_before = b.run(&["--json", "inspect", "policies"]).json()["data"].clone();
    let declined = b.run(&["--json", "--non-interactive", "import", f]);
    assert_eq!(declined.code, 3, "{declined:?}");
    assert!(
        declined.stderr.contains("profile imported: add"),
        "{declined:?}"
    );
    let profiles = b.run(&["--json", "profile", "list"]);
    assert!(
        !profiles.stdout.contains("\"imported\""),
        "nothing imported yet"
    );
    let import = b.run_pty(b.ws.root(), &["import", f], &["yes"]);
    assert_eq!(import.code, 0, "{import:?}");
    for needle in [
        "Import plan (a dry run: nothing has been written)",
        "would add: 1",
        "profile imported: add",
        "Re-establish locally",
        "no host key is trusted",
        "Imported:",
    ] {
        assert!(
            import.stdout.contains(needle),
            "{needle}: {}",
            import.stdout
        );
    }
    let profiles = b.run(&["--json", "profile", "list"]);
    assert!(profiles.stdout.contains("\"imported\""), "{profiles:?}");
    let again = b.run(&["--json", "import", "--yes", f]);
    assert_eq!(again.code, 0, "{again:?}");
    assert_eq!(
        again.json()["data"]["dry_run"],
        true,
        "nothing to add: not applied"
    );
    assert_eq!(
        b.run(&["--json", "inspect", "policies"]).json()["data"],
        policies_before,
        "an import never touches a policy"
    );
    assert_eq!(b.decisions(), 0);
}

/// Review M05-W3-R03, the reviewer's probe inverted: a checkout directory whose name holds
/// a line break and U+202E (RIGHT-TO-LEFT OVERRIDE). `project status` prints the directory
/// and the workspace root as quoted data: no line of stdout starts with the name's second
/// line, no override character reaches stdout, and the line break is shown as `\n`. The
/// `--json` envelope carries the path unchanged (it is data, already escaped).
#[cfg(unix)]
#[test]
fn workspace_paths_are_quoted_and_bidi_free() {
    let rt = Rt::new();
    let name = "r\nOWNER-LINE\u{202e}abc";
    let cwd = rt
        .ws
        .init_repo(
            name,
            Some(&manifest("safe label", "dev", &["h1:deploy"], false)),
        )
        .unwrap();
    rt.start();
    let out = rt.run_in(&cwd, &["project", "status"]);
    assert_eq!(out.code, 0, "{out:?}");
    assert!(
        !out.stdout.lines().any(|l| l.starts_with("OWNER-LINE")),
        "a path started a line of its own: {out:?}"
    );
    assert_eq!(
        out.stdout.chars().filter(|c| *c == '\u{202e}').count(),
        0,
        "{out:?}"
    );
    let shown = format!(
        "{}\\nOWNER-LINEabc\" (invisible formatting characters removed)",
        cwd.parent().unwrap().join("r").display()
    );
    for label in ["directory: \"", "workspace root: \""] {
        assert!(
            out.stdout.contains(&format!("{label}{shown}")),
            "{label}: {out:?}"
        );
    }
    let json = rt.run_in(&cwd, &["--json", "project", "status"]);
    assert_eq!(json.code, 0, "{json:?}");
    let data = &json.json()["data"];
    for key in ["cwd", "root"] {
        assert!(
            data[key].as_str().is_some_and(|p| p.ends_with(name)),
            "{key}: {data}"
        );
    }
}

/// ⟨M05⟩ Review M05-W3-RC01 (the re-check's probe, inverted): the **complete** first-trust and
/// reconcile prompts are inert, not only their detail lines. Trusting a clone whose directory
/// name holds a line break and U+202E, then reconciling its re-clone, through the real binary
/// on a pseudo-terminal: neither prompt carries a raw bidirectional character, in the detail
/// view or in the recorded request's JSON copy (where it is written as `\u202e`), and no line
/// starts with the name's second line.
#[cfg(unix)]
#[test]
fn full_trust_and_reconcile_prompts_are_bidi_free() {
    let rt = Rt::new();
    let src = rt
        .ws
        .init_repo(
            "source",
            Some(&manifest("safe", "dev", &["h3:deploy"], false)),
        )
        .unwrap();
    let repo = rt
        .ws
        .clone_repo(&src, "repo\nRECHECK-LINE\u{202e}abc")
        .unwrap();
    rt.start();
    let trust = rt.run_pty(&repo, &["project", "trust"], &["yes"]);
    assert_eq!(trust.code, 0, "{trust:?}");
    rt.ws.reclone_at(&src, &repo).unwrap();
    let reconcile = rt.run_pty(&repo, &["project", "reconcile"], &["yes"]);
    assert_eq!(reconcile.code, 0, "{reconcile:?}");
    for (name, out) in [("trust", &trust), ("reconcile", &reconcile)] {
        assert!(
            out.stdout
                .contains("invisible formatting characters removed"),
            "{name}: the safe detail line: {out:?}"
        );
        assert_eq!(
            out.stdout.chars().filter(|c| *c == '\u{202e}').count(),
            0,
            "{name}: no raw bidi anywhere in the prompt: {out:?}"
        );
        assert!(
            out.stdout.contains("\\u202e"),
            "{name}: the recorded request's copy writes it as its escape: {out:?}"
        );
        assert!(
            !out.stdout.lines().any(|l| l.starts_with("RECHECK-LINE")),
            "{name}: a path started a line of its own: {out:?}"
        );
    }
}

/// `run` without `--profile` (ADR-0011 §3.2; I-9): in an untrusted workspace whose
/// manifest asks for more than personal access covers, the first-trust decision is shown on
/// the terminal; after a typed `yes` the same request is re-issued and the program runs; the
/// next `run` there asks nothing; a directory outside any workspace uses the default
/// profile, and with none and no manifest it is refused.
#[cfg(unix)]
#[test]
fn run_without_a_profile_reissues_after_the_trust_decision() {
    let rt = Rt::new();
    let repo = rt
        .ws
        .init_repo(
            "repo",
            Some(&manifest("demo", "dev", &["h3:deploy"], false)),
        )
        .unwrap();
    rt.start();
    let first = rt.run_pty(
        &repo,
        &["run", "--", "/bin/sh", "-c", "echo HM-CHILD-RAN"],
        &["yes"],
    );
    assert_eq!(first.code, 0, "{first:?}");
    assert!(
        first
            .stdout
            .contains("Use dev access automatically for this project?"),
        "{first:?}"
    );
    assert!(first.stdout.contains("HM-CHILD-RAN"), "{first:?}");
    assert_eq!(rt.decisions(), 1);
    let second = rt.run_pty(
        &repo,
        &["run", "--", "/bin/sh", "-c", "echo HM-CHILD-AGAIN"],
        &[],
    );
    assert_eq!(second.code, 0, "{second:?}");
    assert!(second.stdout.contains("HM-CHILD-AGAIN"), "{second:?}");
    asks_nothing(&second.stdout.replace("request ID", ""));
    assert_eq!(rt.decisions(), 1, "zero further decisions");
    // Outside any workspace with no default profile: refused, nothing launched.
    let plain = rt.ws.path("plain");
    std::fs::create_dir_all(&plain).unwrap();
    let refused = rt.run_in(
        &plain,
        &[
            "--json",
            "--non-interactive",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "echo NO",
        ],
    );
    assert_ne!(refused.code, 0, "{refused:?}");
    assert!(!refused.stdout.contains("NO"), "{refused:?}");
    // With a default profile (`ops`, covered by `pol-ops`): it runs.
    assert_eq!(
        rt.run(&["--json", "access", "default-profile", "ops"]).code,
        0
    );
    let ran = rt.run_in(
        &plain,
        &[
            "--json",
            "--non-interactive",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "echo HM-PERSONAL",
        ],
    );
    assert_eq!(ran.code, 0, "{ran:?}");
    assert!(ran.stdout.contains("HM-PERSONAL"), "{ran:?}");
    assert_eq!(rt.decisions(), 1);
}

// ---- goldens -----------------------------------------------------------------------------

/// Every M05 command line whose `--help` is a golden, and its file stem
/// (`tests/contracts/golden/cli-help-m05/<stem>.txt`).
const HELP_LINES: &[(&str, &[&str])] = &[
    ("project", &["project"]),
    ("project-trust", &["project", "trust"]),
    ("project-status", &["project", "status"]),
    ("project-untrust", &["project", "untrust"]),
    ("project-reconcile", &["project", "reconcile"]),
    ("access-allow", &["access", "allow"]),
    ("access-stop", &["access", "stop"]),
    ("access-pause", &["access", "pause"]),
    ("access-resume", &["access", "resume"]),
    ("access-cutoff", &["access", "cutoff"]),
    ("access-default-profile", &["access", "default-profile"]),
    ("activate", &["activate"]),
    ("shell", &["shell"]),
    ("shell-init", &["shell", "init"]),
    ("export", &["export"]),
    ("import", &["import"]),
    ("run", &["run"]),
];

/// Compare `text` with the golden `dir/<name>`, or write it under `HM_UPDATE_GOLDENS=1`.
fn golden(dir: &Path, name: &str, text: &str, mismatches: &mut Vec<String>) {
    let path = dir.join(name);
    if std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(g) if g == text => {}
        Ok(g) => {
            let first = text
                .lines()
                .zip(g.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| text.lines().count().min(g.lines().count()));
            mismatches.push(format!(
                "{name}: changed at line {} (got {:?}, golden {:?})",
                first + 1,
                text.lines().nth(first).unwrap_or(""),
                g.lines().nth(first).unwrap_or("")
            ));
        }
        Err(e) => mismatches.push(format!(
            "{}: {e} (HM_UPDATE_GOLDENS=1 writes it)",
            path.display()
        )),
    }
}

/// `m05_help_and_shell_script_goldens`: the `--help` of every new M05 command line, and
/// `shell init zsh|bash`, run from inside a directory whose name holds shell syntax, equal
/// their goldens byte for byte (the scripts interpolate nothing: not the directory, not the
/// environment); `--json` carries the same script.
#[test]
fn m05_help_and_shell_script_goldens() {
    let rt = Rt::new();
    let help_dir = heimdall_testkit::repo::repo_path("tests/contracts/golden/cli-help-m05");
    let mut mismatches = Vec::new();
    let home = rt.home.to_string_lossy().into_owned();
    for (stem, line) in HELP_LINES {
        let mut cmd = rt.command(&bin());
        // `--home`, not `HEIMDALL_HOME`: clap prints an `env` value into the help text.
        cmd.env_remove("HEIMDALL_HOME");
        let out = cmd
            .arg("--home")
            .arg(&home)
            .args(*line)
            .arg("--help")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{line:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.contains(&format!("heimdall {}", line.join(" "))),
            "{line:?}"
        );
        golden(&help_dir, &format!("{stem}.txt"), &text, &mut mismatches);
    }
    let shell_dir = heimdall_testkit::repo::repo_path("tests/contracts/golden/shell-init");
    let odd = rt.ws.path("odd $(touch hm-evaluated) `x`");
    std::fs::create_dir_all(&odd).unwrap();
    for shell in ["zsh", "bash"] {
        let out = rt.run_in(&odd, &["shell", "init", shell]);
        assert_eq!(out.code, 0, "{out:?}");
        assert!(!out.stdout.contains(odd.to_str().unwrap()));
        golden(
            &shell_dir,
            &format!("{shell}.txt"),
            &out.stdout,
            &mut mismatches,
        );
        let json = rt.run_in(&odd, &["--json", "shell", "init", shell]);
        assert_eq!(json.json()["data"]["script"], out.stdout.as_str());
    }
    assert!(canaries(rt.ws.root()).is_empty());
    assert!(
        !rt.home.exists(),
        "help and shell init never create the home"
    );
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// ⟨M05; review M05-W4F-R01; ADR-0006 §17.11 item 24⟩ An imported destination reached
/// through a jump keeps its route intent and is never launched by its bare alias. A bundle
/// names `lab-inner` behind the bastion `bastion`; the receiving machine's own SSH
/// configuration has a direct `lab-inner` alias (disposable), and the verified client is a stub
/// first on `PATH` that records every launch. After the import, `connect lab-inner` refuses
/// (`CAPABILITY_UNAVAILABLE`, `route_pending`, naming the bastion) and launches nothing, and a
/// `run` of a profile with its pair is refused the same way; `connect bastion` (no route of
/// its own) still launches, so the stub is live. A re-export keeps the jump.
#[cfg(unix)]
#[test]
fn an_imported_routed_destination_is_never_launched_by_its_bare_alias() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new().prefix("hjp").tempdir().unwrap();
    let root = dir.path();
    let home = root.join("h");
    let user = root.join("u");
    let bin = root.join("bin");
    for d in [&user, &bin, &user.join(".ssh")] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(user.join(".gitconfig"), b"").unwrap();
    // The receiver's own direct route to the target (it must never be used).
    std::fs::write(
        user.join(".ssh").join("config"),
        "Host lab-inner\n    HostName 127.0.0.1\n    Port 9\n",
    )
    .unwrap();
    let recorded = root.join("argv");
    let stub = bin.join("ssh");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf '%s\\0' \"$@\" >> \"$HM_JUMP_ARGV\"\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bundle = root.join("bundle.json");
    std::fs::write(
        &bundle,
        serde_json::json!({
            "schema": "heimdall-portable/1",
            "created_at": "2026-11-20T09:00:00Z",
            "redacted": false,
            "destinations": [
                {"id": "bastion", "alias": "bastion", "hostname": "bastion.example.invalid", "account": "deploy"},
                {"id": "lab-inner", "alias": "lab-inner", "hostname": "inner.example.invalid", "account": "deploy", "jump": "bastion"}
            ],
            "identities": [],
            "profiles": [{"id": "inner", "pairs": ["lab-inner:deploy"]}],
            "reestablish": []
        })
        .to_string(),
    )
    .unwrap();
    let heimdall = std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
    let run = |args: &[&str]| {
        let out = Command::new(&heimdall)
            .args(args)
            .env_clear()
            .env("HOME", &user)
            .env("HEIMDALL_HOME", &home)
            .env("HEIMDALL_TEST_ADAPTER", "prepare")
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", user.join(".gitconfig"))
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HM_JUMP_ARGV", &recorded)
            .current_dir(root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    };
    struct Stop<'a>(&'a dyn Fn(&[&str]) -> std::process::Output);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = (self.0)(&["service", "stop"]);
        }
    }
    let _stop = Stop(&run);
    // The last envelope on stdout, else on stderr (a launch command keeps stdout for the
    // child it launches).
    let envelope = |out: &std::process::Output| -> Value {
        [&out.stdout, &out.stderr]
            .into_iter()
            .find_map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .rev()
                    .find_map(|l| serde_json::from_str::<Value>(l).ok())
            })
            .unwrap_or(Value::Null)
    };
    let imported = run(&["--json", "import", "--yes", bundle.to_str().unwrap()]);
    assert_eq!(
        imported.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&imported.stdout)
    );
    let plan = envelope(&imported)["data"]["plan"].clone();
    let inner = plan
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "lab-inner")
        .unwrap()
        .clone();
    assert_eq!(inner["status"], "add", "{inner}");
    assert_eq!(inner["reason"], "recorded_route_pending", "{inner}");

    let refused = run(&["--json", "connect", "lab-inner"]);
    let env = envelope(&refused);
    assert_ne!(
        refused.status.code(),
        Some(0),
        "connect must refuse the routed destination, never launch it; launched with argv {:?}",
        std::fs::read(&recorded)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
    );
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{env}");
    assert_eq!(env["data"]["error"]["reason"], "route_pending", "{env}");
    assert!(
        env.to_string().contains("bastion"),
        "the refusal names the bastion: {env}"
    );
    assert!(
        !recorded.exists(),
        "nothing was launched for the routed destination"
    );
    let ran = run(&[
        "--json",
        "run",
        "--profile",
        "inner",
        "--",
        "/bin/sh",
        "-c",
        "true",
    ]);
    let env = envelope(&ran);
    assert_ne!(ran.status.code(), Some(0), "{env}");
    assert_eq!(env["data"]["error"]["reason"], "route_pending", "{env}");
    assert!(!recorded.exists(), "`run` launched nothing either");

    // The stub is live: a destination with no route of its own still launches.
    let control = run(&["connect", "bastion"]);
    assert_eq!(
        control.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert_eq!(std::fs::read(&recorded).unwrap(), b"bastion\0");

    // A re-export keeps the jump.
    let exported = run(&["--json", "export"]);
    assert_eq!(exported.status.code(), Some(0));
    let bundle = envelope(&exported)["data"].clone();
    let again = bundle["destinations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == "lab-inner")
        .unwrap()
        .clone();
    assert_eq!(again["jump"], "bastion", "{again}");
}
