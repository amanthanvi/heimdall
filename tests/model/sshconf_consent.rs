//! `heimdall-sshconf` consent classification (M02-U2; m02-plan U2; ADR-0007 §5.2,
//! M2-D04, M2-R03, §12.5 item 3).
//!
//! Cargo test target `model_sshconf_consent` hosted by `heimdall-sshconf`. Behaviour
//! states come from real static evaluations of in-memory trees (`MemSource`), so the
//! tests cover the digest and the classification together. Nothing is executed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use heimdall_domain::projection::{BehaviorState, ItemId, Sha256Hex};
use heimdall_sshconf::consent::{
    ConsentItem, ConsentItemId, ConsentReasonKind, ConsentedStates, classify,
};
use heimdall_sshconf::edit::{IncludeBlock, plan_insert};
use heimdall_sshconf::eval::{Invocation, OpenSshVersion, Query, evaluate};
use heimdall_sshconf::include::{ConfigSet, MemSource, Roots};
use heimdall_sshconf::limits::Limits;
use heimdall_sshconf::relevant::{behavior_state, relevant};
use heimdall_sshconf::render::{
    AliasName, HostName, ManagedAlias, MarkerId, Newline, PathStyle, RenderPath,
    render_include_block, render_managed,
};

const HOME: &str = "/hm/home";
const USER_DIR: &str = "/hm/home/.ssh";
const USER_CONFIG: &str = "/hm/home/.ssh/config";
const MANAGED: &str = "/hm/home/.config/heimdall/ssh_config";

fn state_of(user: &[u8], managed: Option<&[u8]>, host: &str) -> BehaviorState {
    let mut src = MemSource::new(HOME, USER_DIR, "/hm/etc/ssh").with_file(USER_CONFIG, user);
    if let Some(p) = managed {
        src = src.with_file(MANAGED, p);
    }
    let query = Query {
        host: host.to_owned(),
        user: None,
        local_user: "fixture".to_owned(),
        client_version: OpenSshVersion {
            major: 9,
            minor: 5,
            portable: Some(2),
        },
        invocation: Invocation::Shell,
    };
    // P's path, so its values carry the managed role the digest binds (ADR-0007 §12.15
    // item 3a), as in the real flow.
    let roots = Roots::new(Some(PathBuf::from(USER_CONFIG)), None).with_managed(MANAGED);
    let mut set = ConfigSet::new();
    let ev = evaluate(&mut set, &src, &roots, &query, &Limits::default());
    behavior_state(&relevant(&ev))
}

fn managed_p() -> Vec<u8> {
    render_managed(
        &[ManagedAlias {
            alias: AliasName::parse("m1").unwrap(),
            hostname: HostName::parse("m1.example").unwrap(),
            port: None,
            user: "deploy".to_owned(),
            identity_agent: Some(RenderPath::unix(Path::new("/hm/run/agent.sock")).unwrap()),
            identity_files: vec![
                RenderPath::unix(Path::new("~/.config/heimdall/keys/m1.pub")).unwrap(),
            ],
            identities_only: true,
        }],
        PathStyle::Unix,
    )
    .unwrap()
}

fn with_b(user: &[u8]) -> Vec<u8> {
    let marker = MarkerId::parse("hm-a1b2c3d4e5f60718").unwrap();
    let bytes = render_include_block(
        &marker,
        &RenderPath::unix(Path::new("~/.config/heimdall/ssh_config")).unwrap(),
        Newline::Lf,
    );
    plan_insert(Some(user), &IncludeBlock { marker, bytes })
        .unwrap()
        .bytes
}

fn alias_item() -> ConsentItemId {
    ConsentItemId(ItemId::alias("m1").0)
}

fn digest(seed: &str) -> Sha256Hex {
    Sha256Hex::of(seed.as_bytes())
}

fn st(seed: &str, determined: bool) -> BehaviorState {
    BehaviorState {
        digest: digest(seed),
        determined,
    }
}

#[test]
fn consent_byte_identical_rerender_needs_none() {
    // A byte-identical re-render affects no item.
    assert!(!classify(&[]).required);
    // And an item whose after state is its current one needs nothing either.
    let user = with_b(b"Host *\n    User fallback\n");
    let s = state_of(&user, Some(&managed_p()), "m1");
    assert!(s.determined);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: s.clone(),
        after: state_of(&user, Some(&managed_p()), "m1"),
        consented: None,
    }]);
    assert!(!need.required, "{need:?}");
    assert!(need.reasons.is_empty());
}

#[test]
fn consent_rollback_to_consented_restore_needs_none() {
    let user = b"Host *\n    User fallback\n";
    let managed = state_of(&with_b(user), Some(&managed_p()), "m1");
    // The restore column the apply decision showed: m1 without its section.
    let restore = state_of(user, None, "m1");
    assert!(managed.determined && restore.determined);
    assert_ne!(managed.digest, restore.digest);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: managed.clone(),
        after: state_of(user, None, "m1"),
        consented: Some(ConsentedStates {
            managed: managed.clone(),
            restore: restore.clone(),
        }),
    }]);
    assert!(!need.required, "{need:?}");
    // A re-render back to the approved managed state needs none either.
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: restore.clone(),
        after: managed.clone(),
        consented: Some(ConsentedStates { managed, restore }),
    }]);
    assert!(!need.required);
}

#[test]
fn consent_rollback_exposing_new_inherited_hostname_and_agent_needs_decision() {
    let user_at_apply = b"Host *\n    User fallback\n";
    let managed = state_of(&with_b(user_at_apply), Some(&managed_p()), "m1");
    let restore_at_apply = state_of(user_at_apply, None, "m1");
    // After the apply, the user's `Host *` gained a HostName and an IdentityAgent.
    let user_now = b"Host *\n    User fallback\n    HostName inherited.example\n    IdentityAgent ~/.other-agent.sock\n";
    let current = state_of(&with_b(user_now), Some(&managed_p()), "m1");
    // The managed values still win while B is in place (first obtained, F1).
    assert_eq!(current, managed);
    let after = state_of(user_now, None, "m1");
    assert!(after.determined);
    assert_ne!(after.digest, restore_at_apply.digest);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current,
        after,
        consented: Some(ConsentedStates {
            managed,
            restore: restore_at_apply,
        }),
    }]);
    assert!(need.required);
    assert_eq!(need.reasons.len(), 1);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::ExposesInherited);
    assert_eq!(need.reasons[0].item, alias_item());
}

#[test]
fn consent_undetermined_current_or_after_always_needs_decision() {
    // Equal digests do not help when either side is undetermined.
    for (current, after) in [
        (st("x", false), st("x", true)),
        (st("x", true), st("x", false)),
        (st("x", false), st("x", false)),
    ] {
        let need = classify(&[ConsentItem {
            item: alias_item(),
            current,
            after,
            consented: None,
        }]);
        assert!(need.required);
        assert_eq!(need.reasons[0].kind, ConsentReasonKind::UndeterminedState);
    }
    // Neither does a consented state that was recorded as undetermined.
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: st("managed", true),
        after: st("restore", true),
        consented: Some(ConsentedStates {
            managed: st("managed", true),
            restore: st("restore", false),
        }),
    }]);
    assert!(need.required);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::ExposesInherited);
    // One undetermined item among determined ones still requires the decision.
    let need = classify(&[
        ConsentItem {
            item: ConsentItemId(ItemId::alias("a").0),
            current: st("a", true),
            after: st("a", true),
            consented: None,
        },
        ConsentItem {
            item: ConsentItemId(ItemId::alias("b").0),
            current: st("b", true),
            after: st("b2", false),
            consented: None,
        },
    ]);
    assert!(need.required);
    assert_eq!(need.reasons.len(), 1);
    assert_eq!(need.reasons[0].item, ConsentItemId(ItemId::alias("b").0));
}

#[test]
fn consent_match_exec_command_changed_with_same_candidates_needs_decision() {
    // Only the command of a `Match exec` that chooses between the same candidate
    // HostNames changes. The digest cannot see it (M2-R03), so it is equal, and the
    // classification still requires a decision because the state is undetermined.
    let user_one =
        b"Match exec \"probe-one\"\n    HostName a.example\nHost *\n    HostName b.example\n";
    let user_two =
        b"Match exec \"probe-two\"\n    HostName a.example\nHost *\n    HostName b.example\n";
    let managed = state_of(&with_b(user_one), Some(&managed_p()), "m1");
    assert!(managed.determined, "P's values are determined behind B");
    let restore_one = state_of(user_one, None, "m1");
    let restore_two = state_of(user_two, None, "m1");
    assert_eq!(restore_one.digest, restore_two.digest);
    assert!(!restore_one.determined && !restore_two.determined);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: managed.clone(),
        after: restore_two,
        consented: Some(ConsentedStates {
            managed,
            restore: restore_one,
        }),
    }]);
    assert!(need.required);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::UndeterminedState);
}

#[test]
fn consent_new_alias_always_needs_decision() {
    let user = b"Host *\n    User fallback\n";
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: state_of(user, None, "m1"),
        after: state_of(&with_b(user), Some(&managed_p()), "m1"),
        consented: None,
    }]);
    assert!(need.required);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::NewState);
}

#[test]
fn consent_git_selection_change_is_its_own_reason() {
    let need = classify(&[ConsentItem {
        item: ConsentItemId(ItemId::git_selection().0),
        current: st("bundled", true),
        after: st("verified", true),
        consented: None,
    }]);
    assert!(need.required);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::GitSelectionChanged);
}
