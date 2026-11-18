//! **A16, "defaults don't redirect running work"** (spec A16, R-AU-03; m05-plan §3; ADR-0011
//! §5.1–§5.2), and **A04's default row** (spec A04: "change the default/profile
//! definition"; existing bindings retain their snapshots), through the real binary.
//!
//! * [`a16_two_environments_defaults_and_cleanup`]: **two environments, one OS user**: two
//!   worlds in two scratch Heimdall homes (two runtimes, two environment IDs, two CAs) whose
//!   pairs are on one fixture `sshd` (a non-root `sshd` authenticates only its own account,
//!   and the Windows harness leases one account-form server per test thread; each world's
//!   pairs keep their own principals and CA lines). In each, two jobs (`run` without
//!   `--profile`, so under the environment's default profile `exit-1`) start **at the same
//!   time** on one pair: one materializes the managed alias's slot and the other joins it.
//!   Mid-work, in the first environment only, the default profile moves (`exit-1` →
//!   `exit-2`) and the default profile's policy changes (its profile gains a pair and an
//!   owner review widens `exit-pol-1` to it, one attended `yes`). Every job's pins
//!   (environment, profile and revision, scope, mechanism, grant, context) and grant scope
//!   stay as they were, every job's login keeps working, and every accepted certificate is
//!   its own environment's (key ID and CA: no cross-routing). Stopping one job (`access stop
//!   --work`, the slot's materializer) leaves the other: the slot passes to it and logins
//!   continue with its certificate, while the second environment's slot, holder and
//!   generation are untouched. When every job ends, both environments are left with no
//!   active binding, no slot and no slot reference.
//! * [`a04_default_and_profile_change_never_redirects_bindings`]: two live bindings on one
//!   pair (one materializes the alias, one joins); the default profile changes and the
//!   profile definition changes twice (a pair added, then the bindings' own pair removed):
//!   neither binding's pins, grant scope or slot change and the alias keeps logging in with
//!   the materializer's certificate; only new requests see the change (a new request pins
//!   the new revision, a request for the removed pair is refused, `run` without a profile
//!   uses the new default); no decision is created.
//!
//! **Pending on M03 E5:** a stopped job's grant is asserted *no longer active* here; that
//! it reaches `revoked` once its certificate's validity has passed is
//! `pending_e5::e5_revoked_and_stopped_managed_grants_reach_revoked_after_the_residual`.
//!
//! **Platforms.** Unix and Windows run the same journeys (one server for every pair, so the
//! Windows harness serves them). Not built: the WSL and container environment pairs (ruling
//! D09: M04 adds those rows), and two different remote accounts (one fixture account).
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::GrantId;
use heimdall_domain::managed::SlotState;
use heimdall_testkit::sshd::LoopbackSshd;
use serde_json::Value;

use crate::m05::{self, Pins, wait_for};
use crate::worker;
use crate::world::{Worker, World, WorldOptions};

/// A world of two pairs on `server` (both pairs on it), with the per-pair profiles
/// `exit-1` and `exit-2` and the default profile `exit-1`.
fn world_on(server: &Arc<LoopbackSshd>) -> World {
    let (w, ca) = World::start(WorldOptions {
        pairs: 2,
        per_pair_profiles: true,
        shared_servers: vec![server.clone(), server.clone()],
        ..WorldOptions::default()
    });
    drop(ca);
    println!("m05 started-pid runtime {}", w.runtime_pid());
    let set = w.cli(&["--json", "access", "default-profile", "exit-1"]);
    assert_eq!(set.code, 0, "{}", w.redact(&format!("{set:?}")));
    w
}

/// One job: a `run` worker without `--profile` that logs in through pair 0's alias, then
/// waits; again after `go`; then waits for `end`.
struct Job {
    work: String,
    worker: Option<Worker>,
    started: std::path::PathBuf,
    go: std::path::PathBuf,
    after: std::path::PathBuf,
    end: std::path::PathBuf,
}

impl Job {
    fn start(w: &World, work: &str) -> Job {
        let dir = w.subdir("job");
        let (started, go, after, end) = (
            dir.join("started"),
            dir.join("go"),
            dir.join("after"),
            dir.join("end"),
        );
        let (m1, m2) = (m05::marker("before"), m05::marker("after"));
        let request = format!("{work}-r");
        let worker = w.spawn_run(
            &w.home.root,
            &["--work-id", work, "--request-id", &request],
            vec![
                worker::login("before", &w.login_command(0, &m1), &m1),
                worker::signal(&started),
                worker::wait(&go, Duration::from_secs(600)),
                worker::login("after", &w.login_command(0, &m2), &m2),
                worker::signal(&after),
                worker::wait(&end, Duration::from_secs(600)),
            ],
        );
        println!("m05 started-pid run-worker {}", worker.pid());
        Job {
            work: work.to_owned(),
            worker: Some(worker),
            started,
            go,
            after,
            end,
        }
    }

    fn wait(&mut self, signal: &std::path::Path) -> Vec<Value> {
        let signal = signal.to_path_buf();
        self.worker
            .as_mut()
            .unwrap()
            .wait_signal(&signal, Duration::from_secs(180))
    }

    /// The job's binding (the one active binding of its work).
    fn binding(&self, w: &World) -> heimdall_domain::binding::BindingRecord {
        let active = m05::active_bindings(w, &self.work);
        assert_eq!(active.len(), 1, "{}: one active binding", self.work);
        active[0].clone()
    }

    fn finish(&mut self, w: &World) {
        if let Some(wk) = self.worker.take() {
            std::fs::write(&self.go, b"").unwrap();
            std::fs::write(&self.end, b"").unwrap();
            let out = wk.finish(Duration::from_secs(120));
            w.record_bytes("job (stdout)", out.stdout.as_bytes());
            w.record_bytes("job (stderr)", out.stderr.as_bytes());
        }
    }
}

/// The login labelled `label` succeeded (its marker came back).
fn logged_in(w: &World, results: &[Value], label: &str, what: &str) {
    let r = worker::result(results, "login", Some(label));
    assert!(
        r["exit"] == 0 && r["marker_seen"] == true,
        "{what} {label}: {}",
        w.redact(&r.to_string())
    );
}

/// Every certificate the shared server accepted since `mark` for `w`: exactly `n`, each
/// with `w`'s CA, `w`'s environment and `grant`.
fn accepted_for(
    w: &World,
    all: &[heimdall_testkit::sshd::AcceptedCert],
    n: usize,
    grant: &GrantId,
    what: &str,
) {
    let mine: Vec<_> = all
        .iter()
        .filter(|c| c.ca_fingerprint == w.ca_fingerprint.as_str())
        .collect();
    assert_eq!(
        mine.len(),
        n,
        "{what}: {n} logins of this environment: {all:?}"
    );
    for c in mine {
        assert_eq!(
            m05::environment_of(&c.key_id),
            w.environment.as_str(),
            "{what}: no cross-routing: {}",
            c.key_id
        );
        assert_eq!(
            m05::grant_of(&c.key_id),
            grant.as_str(),
            "{what}: {}",
            c.key_id
        );
    }
}

/// Every pin of `jobs`, in order.
fn pins_of(w: &World, jobs: &[Job]) -> Vec<Pins> {
    jobs.iter()
        .map(|j| m05::pins(w, &j.binding(w).id))
        .collect()
}

/// The stored scope of each job's grant.
fn grant_scopes(w: &World, jobs: &[Job]) -> Vec<heimdall_domain::scope::Scope> {
    jobs.iter()
        .map(|j| {
            let g = j.binding(w).grant;
            m05::read(w, |tx| tx.grant(&g)).unwrap().scope
        })
        .collect()
}

/// `(holder, generation)` of pair 0's slot, asserted held.
fn held(w: &World) -> (heimdall_contract::ids::BindingId, u64) {
    match m05::slot(w, 0) {
        SlotState::Held {
            binding,
            generation,
        } => (binding, generation),
        other => panic!("pair 0's slot is held: {other:?}"),
    }
}

/// The policy view of `id` in `w` (`inspect policies`).
fn policy_view(w: &World, id: &str) -> Value {
    let out = w.cli(&["--json", "inspect", "policies"]);
    out.json()["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["policy_id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("no policy {id}"))
}

/// The default profile `access default-profile` shows.
fn default_profile(w: &World) -> Value {
    w.cli(&["--json", "access", "default-profile"]).json()["data"]["profile_id"].clone()
}

#[cfg(any(unix, windows))]
#[test]
fn a16_two_environments_defaults_and_cleanup() {
    let servers = heimdall_testkit::home::Scratch::new().unwrap();
    let server = Arc::new(m05::server(&servers));
    let a = world_on(&server);
    let b = world_on(&server);
    assert_ne!(a.environment, b.environment, "two environments");
    let rows = (m05::decision_rows(&a).0, m05::decision_rows(&b).0);

    // Concurrent work in each environment: four jobs started at once.
    let mark = server.log_mark();
    let mut ja = vec![Job::start(&a, "a16-a1"), Job::start(&a, "a16-a2")];
    let mut jb = vec![Job::start(&b, "a16-b1"), Job::start(&b, "a16-b2")];
    for (w, jobs) in [(&a, &mut ja), (&b, &mut jb)] {
        for j in jobs.iter_mut() {
            let started = j.started.clone();
            let r = j.wait(&started);
            logged_in(w, &r, "before", &j.work);
        }
    }
    let (holder_a, gen_a) = held(&a);
    let (holder_b, gen_b) = held(&b);
    for (w, jobs, holder) in [(&a, &ja, &holder_a), (&b, &jb, &holder_b)] {
        let ids: BTreeSet<_> = jobs.iter().map(|j| j.binding(w).id).collect();
        assert!(
            ids.contains(holder),
            "a job of this environment materializes its slot"
        );
        let refs: BTreeSet<_> = m05::references(w, 0).into_iter().collect();
        assert_eq!(
            refs, ids,
            "the other job joined; no reference crosses environments"
        );
        assert!(matches!(m05::slot(w, 1), SlotState::Free { .. }));
    }
    let accepted = server_accepted(&a, mark);
    accepted_for(
        &a,
        &accepted,
        2,
        &m05::binding(&a, &holder_a).grant,
        "A before",
    );
    accepted_for(
        &b,
        &accepted,
        2,
        &m05::binding(&b, &holder_b).grant,
        "B before",
    );
    let pins = (pins_of(&a, &ja), pins_of(&b, &jb));
    let scopes = (grant_scopes(&a, &ja), grant_scopes(&b, &jb));

    // Mid-work, in A only: the default profile moves, and the default profile's policy
    // changes (its profile gains pair 1, an owner review widens the policy to it).
    let moved = a.cli(&["--json", "access", "default-profile", "exit-2"]);
    assert_eq!(moved.code, 0, "{}", a.redact(&format!("{moved:?}")));
    let added = a.cli(&[
        "--json",
        "profile",
        "add",
        "exit-1",
        "--pair",
        &a.pairs[1].pair_arg(),
    ]);
    assert_eq!(added.code, 0, "{}", a.redact(&format!("{added:?}")));
    let widened = a.confirm_answers(&["access", "allow", "--policy", "exit-pol-1"], &["yes"]);
    assert_eq!(widened.code, 0, "{}", a.redact(&widened.stdout));
    assert!(
        widened.stdout.contains("pairs to add: ex2:"),
        "{}",
        a.redact(&widened.stdout)
    );
    let pol_a = policy_view(&a, "exit-pol-1");
    let pol_b = policy_view(&b, "exit-pol-1");
    assert_ne!(
        pol_a["revision"], pol_b["revision"],
        "A's policy changed, B's did not"
    );
    assert_eq!(default_profile(&a), "exit-2");
    assert_eq!(default_profile(&b), "exit-1", "B's default is its own");

    // Running work: logins keep working, pins and scopes are unchanged.
    let mark = server.log_mark();
    for (w, jobs) in [(&a, &mut ja), (&b, &mut jb)] {
        for j in jobs.iter_mut() {
            std::fs::write(&j.go, b"").unwrap();
            let after = j.after.clone();
            let r = j.wait(&after);
            logged_in(w, &r, "after", &j.work);
        }
    }
    let accepted = server_accepted(&a, mark);
    accepted_for(
        &a,
        &accepted,
        2,
        &m05::binding(&a, &holder_a).grant,
        "A after",
    );
    accepted_for(
        &b,
        &accepted,
        2,
        &m05::binding(&b, &holder_b).grant,
        "B after",
    );
    assert_eq!(
        pins_of(&a, &ja),
        pins.0,
        "A's defaults redirected no binding"
    );
    assert_eq!(pins_of(&b, &jb), pins.1, "B's bindings are untouched");
    assert_eq!(grant_scopes(&a, &ja), scopes.0, "no running grant widened");
    assert_eq!(grant_scopes(&b, &jb), scopes.1);
    assert_eq!(held(&a), (holder_a.clone(), gen_a));
    assert_eq!(held(&b), (holder_b.clone(), gen_b));

    // Stopping one job (A's materializer) leaves the other.
    let (stopped, kept) = if ja[0].binding(&a).id == holder_a {
        (0, 1)
    } else {
        (1, 0)
    };
    let stopped_grant = ja[stopped].binding(&a).grant;
    let kept_binding = ja[kept].binding(&a);
    let stop = a.cli(&["--json", "access", "stop", "--work", &ja[stopped].work]);
    assert_eq!(stop.code, 0, "{}", a.redact(&format!("{stop:?}")));
    let (to, generation) = wait_for(
        "A's slot passes to the other job",
        Duration::from_secs(90),
        || match m05::slot(&a, 0) {
            SlotState::Held {
                binding,
                generation,
            } if binding == kept_binding.id => Some((binding, generation)),
            _ => None,
        },
    );
    assert_eq!(to, kept_binding.id);
    assert!(generation > gen_a, "handed over under a new generation");
    assert_ne!(
        a.grant_state(stopped_grant.as_str()),
        "active",
        "the stopped job's grant ended"
    );
    assert_eq!(
        a.grant_state(kept_binding.grant.as_str()),
        "active",
        "the other job continues"
    );
    let mark = server.log_mark();
    let out = m05::ssh(&a, 0, "true");
    assert_eq!(
        out.code,
        0,
        "A's alias after the stop: {}",
        a.redact(&out.stderr)
    );
    let out = m05::ssh(&b, 0, "true");
    assert_eq!(out.code, 0, "B's alias: {}", b.redact(&out.stderr));
    let accepted = server_accepted(&a, mark);
    accepted_for(&a, &accepted, 1, &kept_binding.grant, "A after the stop");
    accepted_for(
        &b,
        &accepted,
        1,
        &m05::binding(&b, &holder_b).grant,
        "B after A's stop",
    );
    assert_eq!(held(&b), (holder_b.clone(), gen_b), "B's slot is untouched");
    for j in &jb {
        assert_eq!(b.grant_state(j.binding(&b).grant.as_str()), "active");
    }

    // Cleanup: every job ends; no binding, slot or reference is left in either.
    for (w, jobs) in [(&a, &mut ja), (&b, &mut jb)] {
        for j in jobs.iter_mut() {
            j.finish(w);
        }
    }
    for (w, jobs) in [(&a, &ja), (&b, &jb)] {
        wait_for(
            "every job's binding is released",
            Duration::from_secs(120),
            || {
                jobs.iter()
                    .all(|j| m05::active_bindings(w, &j.work).is_empty())
                    .then_some(())
            },
        );
        wait_for("the slot is clear", Duration::from_secs(120), || {
            (matches!(m05::slot(w, 0), SlotState::Free { .. }) && m05::references(w, 0).is_empty())
                .then_some(())
        });
        let listed = w.cli(&["--json", "inspect", "bindings"]).json()["data"]["bindings"].clone();
        for j in jobs {
            assert!(
                listed
                    .as_array()
                    .is_none_or(|l| l.iter().all(|b| b["work_id"] != j.work.as_str())),
                "{}: no binding is listed: {listed}",
                j.work
            );
        }
    }
    assert_eq!(
        m05::decision_rows(&a).0,
        rows.0 + 1,
        "A: only the owner's review"
    );
    assert_eq!(m05::decision_rows(&b).0, rows.1, "B: none");
    println!(
        "m05 observation: a16 {} environments=2 jobs=4 pins_unchanged=true cross_routed=0 handover_generation={generation} cleanup=clear",
        crate::world::platform()
    );
    drop(ja);
    drop(jb);
    a.stop_runtime();
    b.stop_runtime();
}

/// The certificates the shared server accepted since `mark` (any world's).
fn server_accepted(w: &World, mark: u64) -> Vec<heimdall_testkit::sshd::AcceptedCert> {
    w.accepted_since(0, mark)
}

#[cfg(any(unix, windows))]
#[test]
fn a04_default_and_profile_change_never_redirects_bindings() {
    let servers = heimdall_testkit::home::Scratch::new().unwrap();
    let server = Arc::new(m05::server(&servers));
    let w = world_on(&server);
    let rows = m05::decision_rows(&w).0;
    let mut jobs = vec![Job::start(&w, "a04-a"), Job::start(&w, "a04-b")];
    for j in &mut jobs {
        let started = j.started.clone();
        let r = j.wait(&started);
        logged_in(&w, &r, "before", &j.work);
    }
    let (holder, generation) = held(&w);
    let holder_grant = m05::binding(&w, &holder).grant;
    let refs: BTreeSet<_> = m05::references(&w, 0).into_iter().collect();
    assert_eq!(refs.len(), 2, "one materializes, one joins");
    let pins = pins_of(&w, &jobs);
    assert!(
        pins.iter()
            .all(|(b, _)| b.profile.as_str() == "exit-1" && b.profile_revision == 1)
    );
    let scopes = grant_scopes(&w, &jobs);

    // The default and the profile definition change while both run.
    let moved = w.cli(&["--json", "access", "default-profile", "exit-2"]);
    assert_eq!(moved.code, 0, "{}", w.redact(&format!("{moved:?}")));
    let added = w.cli(&[
        "--json",
        "profile",
        "add",
        "exit-1",
        "--pair",
        &w.pairs[1].pair_arg(),
    ]);
    assert_eq!(added.code, 0, "{}", w.redact(&format!("{added:?}")));
    // A new request pins the new revision.
    let fresh = w.cli(&[
        "--json",
        "access",
        "ensure",
        "--profile",
        "exit-1",
        "--pair",
        &w.pairs[0].pair_arg(),
        "--work-id",
        "a04-new",
        "--request-id",
        "a04-new",
    ]);
    assert_eq!(
        fresh.json()["code"],
        "ACCESS_READY",
        "{}",
        w.redact(&format!("{fresh:?}"))
    );
    assert_eq!(
        fresh.json()["data"]["profile_revision"],
        2,
        "the new revision"
    );
    let removed = w.cli(&[
        "--json",
        "profile",
        "remove",
        "exit-1",
        "--pair",
        &w.pairs[0].pair_arg(),
    ]);
    assert_eq!(removed.code, 0, "{}", w.redact(&format!("{removed:?}")));
    let refused = w.cli(&[
        "--json",
        "--non-interactive",
        "access",
        "ensure",
        "--profile",
        "exit-1",
        "--pair",
        &w.pairs[0].pair_arg(),
        "--work-id",
        "a04-removed",
        "--request-id",
        "a04-removed",
    ]);
    assert_ne!(
        refused.code,
        0,
        "the pair is no longer in exit-1: {}",
        w.redact(&format!("{refused:?}"))
    );
    assert_ne!(refused.json()["code"], "ACCESS_READY");

    // Existing work: no pin, scope, slot or authority moved; the alias still logs in.
    let mark = server.log_mark();
    for j in &mut jobs {
        std::fs::write(&j.go, b"").unwrap();
        let after = j.after.clone();
        let r = j.wait(&after);
        logged_in(&w, &r, "after", &j.work);
    }
    accepted_for(
        &w,
        &server_accepted(&w, mark),
        2,
        &holder_grant,
        "after the changes",
    );
    assert_eq!(pins_of(&w, &jobs), pins, "the bindings keep their pins");
    assert_eq!(
        grant_scopes(&w, &jobs),
        scopes,
        "the grants keep their scope"
    );
    assert_eq!(
        held(&w),
        (holder.clone(), generation),
        "the slot is unchanged"
    );

    // New requests only: `run` without a profile uses the new default.
    assert_eq!(default_profile(&w), "exit-2");
    let next = w.spawn_run(
        &w.home.root,
        &["--work-id", "a04-default", "--request-id", "a04-default"],
        Vec::new(),
    );
    println!("m05 started-pid run-worker {}", next.pid());
    let out = next.finish(Duration::from_secs(120));
    assert_eq!(
        out.code,
        0,
        "run under the new default: {}",
        w.redact(&out.stderr)
    );
    let used = m05::work_bindings(&w, "a04-default");
    assert_eq!(used.len(), 1);
    assert_eq!(used[0].profile.as_str(), "exit-2", "the new default");
    assert_eq!(
        m05::decision_rows(&w).0,
        rows,
        "no decision for a default or profile change"
    );
    println!(
        "m05 observation: a04 {} default_change=redirected_nothing profile_change=redirected_nothing new_request_revision=2",
        crate::world::platform()
    );
    for j in &mut jobs {
        j.finish(&w);
    }
    w.stop_runtime();
}
