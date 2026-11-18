//! **A02, a normal working week** (spec A02; m05-plan §3 "A02 and zero additional
//! same-authority prompts", R-UX-02; ADR-0011 §3.4) through the real binary, its real
//! issuer child, the system OpenSSH client and Git against the world's fixture `sshd`.
//!
//! [`a02_trusted_week_zero_further_prompts`]: a scratch Git workspace whose manifest asks
//! for the world's managed pair is trusted **once** through `project trust` (one attended
//! `yes` on a terminal: the one decision). Then, with nothing further asked:
//!
//! 1. **re-entry** from another directory of the workspace (the foreground `activate`);
//! 2. **three shells**: Unix, `activate --hook` for three stand-in shell processes (each
//!    binding held by its shell, work `shell:<pid>.<start>.0`); Windows, which has no shell
//!    integration (owner question Q6), three `run` workers in the workspace;
//! 3. `ssh`, `git ls-remote` and `scp` through the **managed alias**, each a real publickey
//!    login the server log attributes, by certificate key ID, to the grant of the binding
//!    that holds the alias's slot (a shell's, under the workspace policy);
//! 4. a **re-issue within the grant**: the first shell's work again (ruling I-1 attaches it
//!    to the same grant);
//! 5. **helper recovery**: the runtime is stopped by its exact PID (a crash); the hook then
//!    starts nothing, and the next command (the foreground `activate`) starts the runtime,
//!    whose recovery re-issues every continuing grant: the next `ssh` logs in with a new
//!    certificate of the same grant;
//! 6. **expiry and re-entry** under fresh work IDs: with `session.max_window` set to
//!    [`WINDOW`], every grant expires; the next activation of each shell starts its next
//!    work (`shell:…​.1`, Unix: the hook's automatic re-entry; Windows: a new `run`) with a
//!    fresh grant, the expired work stays expired, and `ssh` logs in again.
//!
//! Counted at the end: decision records after the first = 0 (the store's rows, and `inspect
//! decisions` lists none pending), attended prompts after the trust = 0 (every `[y/N]` and
//! typed-confirmation invitation in the transcript of everything the binary printed), and
//! provider prompts = 0 (the managed mechanism has no provider; the decoy agent at
//! `SSH_AUTH_SOCK` saw no contact). Printed as `m05 observation: a02 <platform> …`.
//!
//! **Platforms.** Unix runs the hook rows; Windows runs the same journey with `run`
//! workers in place of the hook (Q6) and the harness's WSL sshd. **Blocked rows**
//! (m05-plan §3): the step comparison against the G01 baseline worksheet (B7, ADR-0001
//! §6) and a reboot inside the window (B12, M04-T04) are not part of this test.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::path::Path;
use std::time::Duration;

use heimdall_contract::ids::GrantId;
use heimdall_testkit::workspace::{Scratch, manifest};

use crate::m05::{self, wait_for};
use crate::world::{self, PROFILE, World, WorldOptions};

/// The session window (`session.max_window`): every grant of this world lasts this long,
/// so the journey sees real expiry. Long enough for steps 1–5 on a slow host.
pub const WINDOW: Duration = Duration::from_secs(150);

/// One of the three shells (module docs, step 2).
struct Shell {
    n: usize,
    /// The work it activated last.
    work: String,
    /// The hook's work sequence number (Unix).
    seq: u64,
    #[cfg(unix)]
    standin: m05::StandIn,
    #[cfg(windows)]
    worker: Option<(world::Worker, std::path::PathBuf)>,
}

impl Shell {
    /// Open shell `n` in `cwd` and activate there: the hook (Unix) or `run` (Windows).
    fn open(w: &World, cwd: &Path, n: usize) -> Shell {
        #[cfg(unix)]
        {
            let standin = m05::StandIn::start();
            let answer = m05::hook_until_active(w, cwd, standin.pid, 0);
            Shell {
                n,
                work: answer["work_id"].as_str().unwrap().to_owned(),
                seq: answer["seq"].as_u64().unwrap(),
                standin,
            }
        }
        #[cfg(windows)]
        {
            let mut s = Shell {
                n,
                work: String::new(),
                seq: 0,
                worker: None,
            };
            s.run_work(w, cwd, 0);
            s
        }
    }

    /// Windows: a `run` worker in `cwd` on this shell's work `seq`, held until released.
    #[cfg(windows)]
    fn run_work(&mut self, w: &World, cwd: &Path, seq: u64) {
        if let Some((worker, release)) = self.worker.take() {
            std::fs::write(&release, b"").unwrap();
            let _ = worker.finish(Duration::from_secs(60));
        }
        let work = format!("a02-shell-{}-{seq}", self.n);
        let dir = w.subdir("shell");
        let (started, release) = (dir.join("started"), dir.join("release"));
        let request = format!("{work}-r");
        let mut worker = w.spawn_run(
            cwd,
            &["--work-id", &work, "--request-id", &request],
            vec![
                crate::worker::signal(&started),
                crate::worker::wait(&release, Duration::from_secs(900)),
            ],
        );
        println!("m05 started-pid run-worker {}", worker.pid());
        let _ = worker.wait_signal(&started, Duration::from_secs(120));
        self.work = work;
        self.seq = seq;
        self.worker = Some((worker, release));
    }

    /// The activation again on the same work (the re-issue within the grant, step 4).
    fn again(&mut self, w: &World, cwd: &Path) {
        #[cfg(unix)]
        {
            let answer = m05::hook_until_active(w, cwd, self.standin.pid, self.seq);
            assert_eq!(answer["work_id"], self.work.as_str(), "the same work");
        }
        #[cfg(windows)]
        {
            let request = format!("{}-again", self.work);
            let worker = w.spawn_run(
                cwd,
                &["--work-id", &self.work, "--request-id", &request],
                Vec::new(),
            );
            println!("m05 started-pid run-worker {}", worker.pid());
            let out = worker.finish(Duration::from_secs(120));
            assert_eq!(
                out.code,
                0,
                "run on the same work: {}",
                w.redact(&out.stderr)
            );
        }
    }

    /// After expiry: the shell's next activation (step 6), a fresh work ID.
    fn reenter(&mut self, w: &World, cwd: &Path) {
        #[cfg(unix)]
        {
            let answer = m05::hook_until_active(w, cwd, self.standin.pid, self.seq);
            assert_eq!(
                answer["seq"].as_u64(),
                Some(self.seq + 1),
                "the hook re-entered under the next work: {answer}"
            );
            self.work = answer["work_id"].as_str().unwrap().to_owned();
            self.seq += 1;
        }
        #[cfg(windows)]
        {
            let seq = self.seq + 1;
            self.run_work(w, cwd, seq);
        }
    }
}

#[cfg(windows)]
impl Drop for Shell {
    fn drop(&mut self) {
        if let Some((worker, release)) = self.worker.take() {
            let _ = std::fs::write(&release, b"");
            let _ = worker.finish(Duration::from_secs(60));
        }
    }
}

/// The active binding of `work` (exactly one is expected to hold a reference).
fn grant_of_work(w: &World, work: &str) -> GrantId {
    let active = m05::active_bindings(w, work);
    assert!(!active.is_empty(), "{work} has an active binding");
    let grant = active[0].grant.clone();
    assert!(
        active.iter().all(|b| b.grant == grant),
        "{work}: every binding rests on one grant"
    );
    grant
}

/// Exactly one accepted login on pair 0 since `mark`, with a certificate of `grant` (when
/// given) signed under the world's CA; the certificate.
fn one_login(
    w: &World,
    mark: u64,
    grant: Option<&GrantId>,
    what: &str,
) -> heimdall_testkit::sshd::AcceptedCert {
    let accepted = w.accepted_since(0, mark);
    assert_eq!(
        accepted.len(),
        1,
        "{what}: one accepted login: {accepted:?}"
    );
    let c = accepted[0].clone();
    assert_eq!(
        c.ca_fingerprint,
        w.ca_fingerprint.as_str(),
        "{what}: the CA"
    );
    assert_eq!(
        m05::environment_of(&c.key_id),
        w.environment.as_str(),
        "{what}: this environment's key ID"
    );
    if let Some(g) = grant {
        assert_eq!(m05::grant_of(&c.key_id), g.as_str(), "{what}: {}", c.key_id);
    }
    c
}

/// Step 3: `ssh`, `git ls-remote` and `scp` through the managed alias, each attributed
/// to `grant` (the slot holder's).
fn ssh_git_scp(w: &World, grant: &GrantId, tag: &str) {
    let dir = m05::remote_dir(w, 0, tag);
    let mark = m05::marker(tag);
    let at = w.pairs[0].sshd.log_mark();
    let seeded = m05::ssh(w, 0, &m05::remote_seed(&dir, &mark));
    assert_eq!(seeded.code, 0, "ssh: {}", w.redact(&format!("{seeded:?}")));
    let commit = seeded
        .stdout
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix(&format!("{mark} "))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("ssh ran the remote command: {}", w.redact(&seeded.stdout)));
    one_login(w, at, Some(grant), "ssh");

    let at = w.pairs[0].sshd.log_mark();
    let remote = format!("{}:{dir}/r.git", w.pairs[0].alias);
    let listed = m05::git(w, 0, &["ls-remote", &remote]);
    assert_eq!(
        listed.code,
        0,
        "git ls-remote: {}",
        w.redact(&format!("{listed:?}"))
    );
    assert!(
        listed
            .stdout
            .lines()
            .any(|l| l.trim() == format!("{commit}\trefs/heads/main")),
        "git ls-remote lists the commit: {}",
        w.redact(&listed.stdout)
    );
    one_login(w, at, Some(grant), "git ls-remote");

    let at = w.pairs[0].sshd.log_mark();
    let local = w.subdir("scp").join("m05.txt");
    let copied = m05::scp_get(w, 0, &format!("{dir}/m05.txt"), &local);
    assert_eq!(copied.code, 0, "scp: {}", w.redact(&format!("{copied:?}")));
    assert_eq!(
        std::fs::read_to_string(&local).unwrap().trim(),
        mark,
        "scp copied the file"
    );
    one_login(w, at, Some(grant), "scp");
    // The server-side scratch goes with this login (the server's own scratch otherwise).
    let _ = m05::ssh(w, 0, &format!("rm -rf '{dir}'"));
}

/// The grant whose binding holds the alias's slot now (one of `works`' bindings).
fn slot_grant(w: &World, works: &[String]) -> GrantId {
    let holder = m05::wait_for("the alias's slot is held", Duration::from_secs(60), || {
        m05::slot_holder(w, 0)
    });
    let b = m05::binding(w, &holder);
    assert!(
        works.iter().any(|work| b.work_id.as_str() == work),
        "a shell's binding holds the slot: {} not in {works:?}",
        b.work_id
    );
    b.grant
}

/// The foreground `activate --cwd <dir>` (re-entry; it starts the runtime on demand).
fn activate(w: &World, dir: &Path) -> serde_json::Value {
    let out = w.cli_in(dir, &["--json", "activate", "--cwd", dir.to_str().unwrap()]);
    assert_eq!(out.code, 0, "activate: {}", w.redact(&format!("{out:?}")));
    let env = out.json();
    assert_eq!(
        env["code"],
        "ACCESS_READY",
        "{}",
        w.redact(&env.to_string())
    );
    env["data"].clone()
}

#[cfg(any(unix, windows))]
#[test]
fn a02_trusted_week_zero_further_prompts() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        config_toml: Some(format!(
            "schema_version = 1\n\n[session]\nmax_window = \"{}s\"\n",
            WINDOW.as_secs()
        )),
        ..WorldOptions::default()
    });
    drop(ca);
    println!("m05 started-pid runtime {}", w.runtime_pid());
    let ws = Scratch::new().unwrap();
    let pair = w.pairs[0].pair_arg();
    let repo = ws
        .init_repo(
            "infra",
            Some(&manifest("a02-infra", PROFILE, &[pair.as_str()], false)),
        )
        .unwrap();
    let net = repo.join("modules").join("net");
    std::fs::create_dir_all(&net).unwrap();
    let docs = repo.join("docs");
    std::fs::create_dir_all(&docs).unwrap();
    let (base, pending) = m05::decision_rows(&w);
    assert_eq!(pending, 0, "the world's setup left nothing pending");

    // The first trust: one attended `yes`, one decision.
    let trust = w.confirm_answers(
        &["project", "trust", "--cwd", net.to_str().unwrap()],
        &["yes"],
    );
    assert_eq!(trust.code, 0, "project trust: {}", w.redact(&trust.stdout));
    assert!(
        trust
            .stdout
            .contains("This workspace is trusted under policy"),
        "{}",
        w.redact(&trust.stdout)
    );
    let after_trust = m05::transcript_mark(&w);
    assert_eq!(
        m05::decision_rows(&w).0,
        base + 1,
        "first trust = 1 decision"
    );
    let status = w.cli(&[
        "--json",
        "project",
        "status",
        "--cwd",
        repo.to_str().unwrap(),
    ]);
    let status = status.json()["data"].clone();
    assert_eq!(status["match"], "trusted", "{status}");
    let policy = status["policy_id"].as_str().unwrap().to_owned();
    let workspace = status["workspace_id"].as_str().unwrap().to_owned();

    // 1. Re-entry from another directory of the workspace.
    let again = activate(&w, &docs);
    assert_eq!(again["context"]["kind"], "workspace", "{again}");
    assert_eq!(again["context"]["policy_id"], policy.as_str());

    // 2. Three shells.
    let dirs = [net.clone(), repo.clone(), docs.clone()];
    let mut shells: Vec<Shell> = (0..3).map(|n| Shell::open(&w, &dirs[n], n)).collect();
    let works = |shells: &[Shell]| shells.iter().map(|s| s.work.clone()).collect::<Vec<_>>();
    let mut grants = Vec::new();
    for s in &shells {
        let g = grant_of_work(&w, &s.work);
        assert_eq!(
            m05::grant_policy(&w, &g),
            (Some(policy.clone()), Some(workspace.clone())),
            "shell {}: granted under the workspace policy",
            s.n
        );
        grants.push(g);
    }
    let holder = slot_grant(&w, &works(&shells));
    let refs = m05::references(&w, 0);
    for s in &shells {
        assert!(
            m05::active_bindings(&w, &s.work)
                .iter()
                .any(|b| refs.contains(&b.id)),
            "shell {}'s binding references the alias's slot (shared, ADR-0011 §5.2)",
            s.n
        );
    }

    // 3. ssh, git and scp through the managed alias.
    ssh_git_scp(&w, &holder, "week");

    // 4. A re-issue within the grant: the first shell's work again.
    shells[0].again(&w, &dirs[0]);
    assert_eq!(
        grant_of_work(&w, &shells[0].work),
        grants[0],
        "the same grant"
    );

    // 5. Helper recovery: the runtime stopped by its exact PID, then the next command.
    let before: Vec<usize> = grants
        .iter()
        .map(|g| w.published(g.as_str()).len())
        .collect();
    let serial_before = {
        let at = w.pairs[0].sshd.log_mark();
        let out = m05::ssh(&w, 0, "true");
        assert_eq!(out.code, 0, "{}", w.redact(&out.stderr));
        one_login(&w, at, Some(&holder), "before the crash").serial
    };
    let (killed, issuer) = kill_and_observe(&w);
    #[cfg(unix)]
    {
        let quiet = m05::hook(&w, &dirs[0], shells[0].standin.pid, shells[0].seq);
        assert_eq!(
            quiet["state"], "unavailable",
            "the hook starts no runtime: {quiet}"
        );
        assert!(!crate::procs::alive(killed));
    }
    let recovered = activate(&w, &repo);
    assert_eq!(recovered["context"]["kind"], "workspace");
    let new_pid = w.runtime_pid();
    println!("m05 started-pid runtime {new_pid}");
    assert_ne!(new_pid, killed, "a new runtime process");
    let issuer_ended = m05::old_issuer_ended(issuer);
    wait_for(
        "every shell's grant re-issued",
        Duration::from_secs(90),
        || {
            grants
                .iter()
                .zip(&before)
                .all(|(g, n)| {
                    w.grant_state(g.as_str()) == "active" && w.published(g.as_str()).len() > *n
                })
                .then_some(())
        },
    );
    let at = w.pairs[0].sshd.log_mark();
    let out = m05::ssh(&w, 0, "true");
    assert_eq!(out.code, 0, "ssh after recovery: {}", w.redact(&out.stderr));
    let after = one_login(&w, at, None, "after recovery");
    let holder_now = slot_grant(&w, &works(&shells));
    assert_eq!(m05::grant_of(&after.key_id), holder_now.as_str());
    assert!(grants.contains(&holder_now), "the same grants continue");
    assert_ne!(after.serial, serial_before, "a re-issued certificate");
    assert!(
        w.published(holder_now.as_str())
            .iter()
            .any(|(s, _)| *s == after.serial),
        "the login used the grant's re-issued certificate"
    );

    // 6. Expiry, then re-entry under fresh work IDs.
    let old_works = works(&shells);
    let old_deadlines: Vec<String> = grants.iter().map(|g| deadline(&w, g)).collect();
    wait_for(
        "every shell's grant expired",
        WINDOW + Duration::from_secs(120),
        || {
            grants
                .iter()
                .all(|g| w.grant_state(g.as_str()) != "active")
                .then_some(())
        },
    );
    wait_for("the alias's slot is free", Duration::from_secs(90), || {
        matches!(
            m05::slot(&w, 0),
            heimdall_domain::managed::SlotState::Free { .. }
        )
        .then_some(())
    });
    for (s, dir) in shells.iter_mut().zip(&dirs) {
        s.reenter(&w, dir);
    }
    let fresh: Vec<GrantId> = shells.iter().map(|s| grant_of_work(&w, &s.work)).collect();
    for (s, old) in shells.iter().zip(&old_works) {
        assert_ne!(&s.work, old, "shell {}: a fresh work ID", s.n);
    }
    for g in &fresh {
        assert!(!grants.contains(g), "a fresh grant");
        assert_eq!(m05::grant_policy(&w, g).0, Some(policy.clone()));
    }
    for (g, d) in grants.iter().zip(&old_deadlines) {
        assert_eq!(
            w.grant_state(g.as_str()),
            "expired",
            "the old work stays expired"
        );
        assert_eq!(&deadline(&w, g), d, "never extended");
    }
    let holder = slot_grant(&w, &works(&shells));
    ssh_git_scp(&w, &holder, "next-day");

    // The counts.
    let (rows, pending) = m05::decision_rows(&w);
    let decisions_after_first = rows - (base + 1);
    let listed = m05::pending_listed(&w);
    let prompts = m05::prompts_since(&w, after_trust);
    let provider = w.home.decoy_agent().contact_count();
    println!(
        "m05 observation: a02 {} decisions_after_first={decisions_after_first} pending_listed={listed} attended_prompts={prompts} provider_prompts={provider} recovered_runtime={} issuer_child_after_kill={}",
        world::platform(),
        new_pid != killed,
        if issuer_ended {
            "exited"
        } else {
            "still_running_stopped_by_pid"
        },
    );
    assert_eq!(decisions_after_first, 0, "decisions after the first trust");
    assert_eq!((pending, listed), (0, 0), "nothing pending");
    assert_eq!(prompts, 0, "attended prompts after the first trust");
    assert_eq!(
        provider, 0,
        "provider prompts: no agent of the owner's was contacted"
    );
    drop(shells);
    w.stop_runtime();
}

/// [`m05::kill_runtime`], printed.
fn kill_and_observe(w: &World) -> (u32, Option<u32>) {
    let (pid, issuer) = m05::kill_runtime(w);
    if let Some(i) = issuer {
        println!("m05 started-pid issuer-child {i}");
    }
    (pid, issuer)
}

/// A grant's effective deadline, as stored.
fn deadline(w: &World, g: &GrantId) -> String {
    m05::read(w, |tx| tx.grant(g))
        .map(|g| g.deadline.effective.to_string())
        .unwrap_or_default()
}
