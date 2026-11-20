//! **Ordinary `ssh` activates the personal default** (m05-plan U5; ADR-0011 §3.1–§3.3,
//! §7.2, §10 item 4; rulings I-2, I-13, I-20) through the real binary: the system `ssh`
//! through the projection's managed alias, whose `IdentityAgent` is the environment
//! signing endpoint (a Unix socket, or on Windows the named pipe the Windows signer
//! serves: the same identities path).
//!
//! [`u5_ordinary_ssh_activates_the_personal_default`]:
//! 1. **the default at setup**: the world's `setup apply` offers the personal default and
//!    the owner approves it on the terminal (`create {default: true}` for `exit`, the one
//!    decision; the world set the default-profile preference to `exit` first, which the
//!    offer names, and approving it keeps that preference: I-2's "keeps an existing one");
//! 2. **on a free slot** the first ordinary `ssh` triggers the activation of work
//!    `default:<env>:1` under that policy (personal context, an `activated` event, no
//!    decision). Ruling I-13 says that first `ssh` may fail once (OpenSSH reads the slot's
//!    `IdentityFile` before it asks the agent): its outcome is **printed**, never asserted,
//!    as `m05 observation: i13 <platform> <ok|failed>`. The **next** `ssh` logs in with the
//!    default work's certificate;
//! 3. **after a pause** (the default work stopped first, so the slot is free): the next
//!    `ssh` activates nothing (no new work, slot free, a `blocked` event `policy_paused`, no
//!    decision) and does not log in; on Unix the hook's warm-up activates nothing either;
//! 4. **after `resume`** (an attended decision): on Unix, with the hook's warm-up first, the
//!    **first** `ssh` logs in, with default work 2's certificate; on Windows (no shell
//!    integration, Q6) the first `ssh` activates work 2 (printed as
//!    `m05 observation: i13-after-resume windows <ok|failed>`) and the next logs in with it.
//!
//! The decision rows grow only by the setup's `create` and the `resume`: no activation
//! creates one. Before the hook rows the default-profile preference is cleared (a
//! preference, never authority), so the hook's own activation outside a workspace is
//! quiet and only its warm-up of the personal default acts, as `e2e_hook_m05` arranges it.
//!
//! **After M03 E5:** the stopped default work's grant is asserted *no longer active*
//! here; that it reaches `revoked` once its certificate's validity has passed is
//! `pending_e5::e5_revoked_and_stopped_managed_grants_reach_revoked_after_the_residual`.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::time::Duration;

use heimdall_contract::ids::GrantId;
use heimdall_contract::trust::ActivationEventKind;
use heimdall_domain::managed::SlotState;

use crate::m05::{self, wait_for};
use crate::world::{self, World, WorldOptions};

/// The binding of default work `n` holding the slot, once the activation settled.
fn default_holding(w: &World, n: u64) -> GrantId {
    let work = m05::default_work(w, n);
    wait_for(
        &format!("{work} holds the alias's slot"),
        Duration::from_secs(60),
        || {
            let holder = m05::slot_holder(w, 0)?;
            let b = m05::binding(w, &holder);
            (b.work_id.as_str() == work).then_some(b.grant)
        },
    )
}

/// One `ssh` through the managed alias: whether it logged in (its marker came back).
fn login(w: &World, tag: &str) -> bool {
    let marker = m05::marker(tag);
    let out = m05::ssh(w, 0, &format!("echo {marker}"));
    out.code == 0 && out.stdout.lines().any(|l| l.trim() == marker)
}

/// The one certificate the server accepted since `mark`: its grant.
fn accepted_grant(w: &World, mark: u64, what: &str) -> String {
    let accepted = w.accepted_since(0, mark);
    assert_eq!(
        accepted.len(),
        1,
        "{what}: one accepted login: {accepted:?}"
    );
    assert_eq!(accepted[0].ca_fingerprint, w.ca_fingerprint.as_str());
    m05::grant_of(&accepted[0].key_id)
}

#[cfg(any(unix, windows))]
#[test]
fn u5_ordinary_ssh_activates_the_personal_default() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        personal_default: true,
        ..WorldOptions::default()
    });
    drop(ca);
    println!("m05 started-pid runtime {}", w.runtime_pid());
    let pol = w
        .personal_default
        .clone()
        .expect("the setup created the personal default");
    let (base, pending) = m05::decision_rows(&w);
    assert_eq!(pending, 0, "the setup's decisions are settled");
    let shown = w.cli(&["--json", "access", "default-profile"]);
    assert_eq!(
        shown.json()["data"]["profile_id"],
        world::PROFILE,
        "approving the default kept the existing preference (I-2)"
    );
    assert!(
        matches!(m05::slot(&w, 0), SlotState::Free { .. }),
        "a free slot"
    );
    assert!(m05::work_bindings(&w, &m05::default_work(&w, 1)).is_empty());

    // 2. The first ordinary ssh activates the default; the next logs in with it.
    let first = login(&w, "first");
    println!(
        "m05 observation: i13 {} {}",
        world::platform(),
        if first { "ok" } else { "failed" }
    );
    let g1 = default_holding(&w, 1);
    assert_eq!(
        m05::grant_policy(&w, &g1),
        (Some(pol.as_str().to_owned()), None),
        "granted under the personal default, personal context"
    );
    let events = m05::activation_events(&w);
    assert!(
        events
            .iter()
            .any(|e| e.kind == ActivationEventKind::Activated && e.policy_id.as_ref() == Some(&pol)),
        "{events:?}"
    );
    assert_eq!(
        m05::decision_rows(&w),
        (base, 0),
        "the activation created no decision"
    );
    let mark = w.pairs[0].sshd.log_mark();
    assert!(login(&w, "next"), "the next ordinary ssh logs in");
    assert_eq!(
        accepted_grant(&w, mark, "the next ssh"),
        g1.as_str(),
        "with the default work's certificate"
    );

    // The hook rows need the default-profile preference cleared (module docs).
    let cleared = w.cli(&["--json", "access", "default-profile", "--clear"]);
    assert_eq!(cleared.code, 0, "{}", w.redact(&format!("{cleared:?}")));

    // 3. After a pause, nothing activates.
    let stop = w.cli(&[
        "--json",
        "access",
        "stop",
        "--work",
        &m05::default_work(&w, 1),
    ]);
    assert_eq!(stop.code, 0, "{}", w.redact(&format!("{stop:?}")));
    wait_for("the slot is free", Duration::from_secs(90), || {
        matches!(m05::slot(&w, 0), SlotState::Free { .. }).then_some(())
    });
    assert_ne!(
        w.grant_state(g1.as_str()),
        "active",
        "the stopped work's grant ended"
    );
    let paused = w.cli(&["--json", "access", "pause", pol.as_str()]);
    assert_eq!(paused.code, 0, "{}", w.redact(&format!("{paused:?}")));
    assert_eq!(
        m05::decision_rows(&w),
        (base, 0),
        "a pause is never a decision"
    );
    assert!(!login(&w, "paused"), "a paused default logs nothing in");
    #[cfg(unix)]
    let shell = m05::StandIn::start();
    #[cfg(unix)]
    {
        let dir = w.subdir("plain");
        let answer = m05::hook(&w, &dir, shell.pid, 0);
        assert_eq!(
            answer["state"], "none",
            "outside any workspace, no preference: {answer}"
        );
    }
    let blocked = wait_for("a blocked event", Duration::from_secs(10), || {
        m05::activation_events(&w)
            .into_iter()
            .find(|e| e.kind == ActivationEventKind::Blocked && e.policy_id.as_ref() == Some(&pol))
    });
    assert_eq!(blocked.reason.as_deref(), Some("policy_paused"));
    assert!(
        matches!(m05::slot(&w, 0), SlotState::Free { .. }),
        "nothing activated"
    );
    assert!(
        m05::work_bindings(&w, &m05::default_work(&w, 2)).is_empty(),
        "no new work"
    );
    assert_eq!(
        m05::decision_rows(&w),
        (base, 0),
        "no decision while paused"
    );

    // 4. After resume (attended), it activates again.
    let resumed = w.confirm_answers(&["access", "resume", pol.as_str()], &["yes"]);
    assert_eq!(resumed.code, 0, "resume: {}", w.redact(&resumed.stdout));
    assert_eq!(
        m05::decision_rows(&w).0,
        base + 1,
        "the resume is the one decision"
    );
    #[cfg(unix)]
    {
        let dir = w.subdir("plain");
        let answer = m05::hook(&w, &dir, shell.pid, 0);
        assert_eq!(answer["state"], "none", "{answer}");
        let g2 = default_holding(&w, 2);
        let mark = w.pairs[0].sshd.log_mark();
        assert!(
            login(&w, "warmed"),
            "with the hook's warm-up first, the first ssh logs in"
        );
        assert_eq!(accepted_grant(&w, mark, "the warmed ssh"), g2.as_str());
        assert_ne!(g2, g1, "a fresh grant for the next work");
        drop(shell);
    }
    #[cfg(windows)]
    {
        let first = login(&w, "first-after-resume");
        println!(
            "m05 observation: i13-after-resume {} {}",
            world::platform(),
            if first { "ok" } else { "failed" }
        );
        let g2 = default_holding(&w, 2);
        let mark = w.pairs[0].sshd.log_mark();
        assert!(
            login(&w, "next-after-resume"),
            "the next ordinary ssh logs in"
        );
        assert_eq!(accepted_grant(&w, mark, "the next ssh"), g2.as_str());
        assert_ne!(g2, g1);
    }
    assert_eq!(
        m05::decision_rows(&w),
        (base + 1, 0),
        "no activation created a decision"
    );
    println!(
        "m05 observation: u5 {} default_at_setup=1_decision activation_decisions=0 paused=nothing_activated resumed=activated",
        world::platform()
    );
    w.stop_runtime();
}
