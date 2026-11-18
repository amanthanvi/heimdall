//! **Pending on M03 exit build E5** (the integrator's instruction, 2026-11-18): managed
//! revocation end to end. Base `0e47249e` carries M03's E4 code, in which nothing creates
//! the `bounded_by_expiry` obligations, so a revoked managed grant stays `revoking`
//! forever; E5 fixes it in M03's managed revocation. Until E5 lands on this base the
//! assertion below fails, so it is `#[ignore]`d, never relaxed or worked around.
//!
//! [`e5_revoked_and_stopped_managed_grants_reach_revoked_after_the_residual`] holds the
//! one assertion the other rows leave to it: a managed grant ended by the M05 paths the
//! rows use reaches **`revoked`** once its certificate's residual (its validity, at most the
//! grant's deadline) has passed:
//! * A28: a revoked parent and the child it cascades to (`access revoke`);
//! * A16: a stopped job (`access stop --work`);
//! * U5: the stopped default work (`access stop --work default:<env>:1`).
//!
//! `session.max_window` is [`WINDOW`], so the residual passes within the test. The rows
//! themselves assert what holds today: those grants leave `active`, and the logins they
//! carried fail or move to another referencer.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::time::Duration;

use crate::m05::{self, wait_for};
use crate::world::{World, WorldOptions};

/// The session window: every grant (and so every certificate) of this world ends within it.
const WINDOW: Duration = Duration::from_secs(45);

#[cfg(any(unix, windows))]
#[test]
#[ignore = "pending M03 E5: bounded_by_expiry obligations (revoked managed grant stays revoking)"]
fn e5_revoked_and_stopped_managed_grants_reach_revoked_after_the_residual() {
    let (w, ca) = World::start(WorldOptions {
        pairs: 1,
        personal_default: true,
        config_toml: Some(format!(
            "schema_version = 1\n\n[session]\nmax_window = \"{}s\"\n",
            WINDOW.as_secs()
        )),
        ..WorldOptions::default()
    });
    drop(ca);
    println!("m05 started-pid runtime {}", w.runtime_pid());
    let pair = w.pairs[0].pair_arg();
    // A28: a parent and its child; the parent revoked.
    let parent = w.ensure("e5-parent", "e5-parent-r");
    let child = w.cli(&[
        "--json",
        "access",
        "delegate",
        "--parent",
        parent["binding_id"].as_str().unwrap(),
        "--pair",
        &pair,
        "--work-id",
        "e5-child",
        "--request-id",
        "e5-child",
    ]);
    assert_eq!(
        child.json()["code"],
        "ACCESS_READY",
        "{}",
        w.redact(&format!("{child:?}"))
    );
    let child = child.json()["data"].clone();
    // A16: a job stopped by its work.
    let job = w.ensure("e5-job", "e5-job-r");
    // U5: the default work, activated by an ordinary `ssh`, then stopped.
    let _ = m05::ssh(&w, 0, "true");
    let default_work = m05::default_work(&w, 1);
    let default_grant = wait_for("the default work", Duration::from_secs(60), || {
        m05::active_bindings(&w, &default_work)
            .first()
            .map(|b| b.grant.as_str().to_owned())
    });

    let parent_grant = parent["grant_id"].as_str().unwrap().to_owned();
    w.revoke(&parent_grant, "e5-revoke");
    for work in ["e5-job", default_work.as_str()] {
        let out = w.cli(&["--json", "access", "stop", "--work", work]);
        assert_eq!(out.code, 0, "{}", w.redact(&format!("{out:?}")));
    }
    let ended = [
        ("the revoked parent", parent_grant.clone()),
        (
            "the cascaded child",
            child["grant_id"].as_str().unwrap().to_owned(),
        ),
        (
            "the stopped job",
            job["grant_id"].as_str().unwrap().to_owned(),
        ),
        ("the stopped default work", default_grant),
    ];
    // The residual: every certificate is valid no later than its grant's deadline.
    let latest = ended
        .iter()
        .map(|(_, g)| {
            let id = heimdall_contract::ids::GrantId::parse(g).unwrap();
            m05::read(&w, |tx| tx.grant(&id))
                .unwrap()
                .deadline
                .effective
        })
        .max()
        .unwrap();
    let wait = u64::try_from(latest.as_second() - heimdall_contract::Timestamp::now().as_second())
        .unwrap_or(0);
    std::thread::sleep(Duration::from_secs(wait + 5));
    for (what, g) in &ended {
        wait_for(
            &format!(
                "{what} reaches revoked after its residual (state {})",
                w.grant_state(g)
            ),
            Duration::from_secs(90),
            || (w.grant_state(g) == "revoked").then_some(()),
        );
    }
    w.stop_runtime();
}
