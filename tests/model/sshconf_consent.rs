//! `heimdall-sshconf` consent classification (M02-U2; m02-plan U2; ADR-0007 §5.2,
//! M2-D04, M2-R03, §12.5 item 3).
//!
//! Cargo test target `model_sshconf_consent` hosted by `heimdall-sshconf`. Behaviour
//! states come from real static evaluations of in-memory trees (`MemSource`), so the
//! tests cover the digest and the classification together. Nothing is executed.
//!
//! The states are consent's states (ADR-0007 §12.21 item 2): each alias evaluated under
//! `Shell`, `Exec(None)` and `Subsystem("sftp")`, digest tag `heimdall.behavior.v3`.
//! The `v02_*` tests are the wave-2b/2c review's reproducers (V02): a value that only an
//! exec or a subsystem invocation obtains must count, and the single-invocation (shell)
//! state, which the review showed equal, is computed beside them to show the case
//! discriminates.

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
use heimdall_sshconf::relevant::{
    BEHAVIOR_STATE_TAG, behavior_digest, behavior_state, consent_behavior_state, relevant,
};
use heimdall_sshconf::render::{
    AliasName, HostName, ManagedAlias, MarkerId, Newline, PathStyle, RenderPath,
    render_include_block, render_managed,
};

const HOME: &str = "/hm/home";
const USER_DIR: &str = "/hm/home/.ssh";
const USER_CONFIG: &str = "/hm/home/.ssh/config";
const MANAGED: &str = "/hm/home/.config/heimdall/ssh_config";

fn state_of(user: &[u8], managed: Option<&[u8]>, host: &str) -> BehaviorState {
    state_in(user, managed, host, &[])
}

fn source_of(user: &[u8], managed: Option<&[u8]>, env: &[(&str, &str)]) -> MemSource {
    let mut src = MemSource::new(HOME, USER_DIR, "/hm/etc/ssh").with_file(USER_CONFIG, user);
    for (k, v) in env {
        src = src.with_env(k, v);
    }
    if let Some(p) = managed {
        src = src.with_file(MANAGED, p);
    }
    src
}

fn query(host: &str, invocation: Invocation) -> Query {
    Query {
        host: host.to_owned(),
        user: None,
        local_user: Some("fixture".to_owned()),
        // A client observed to accept `Match sessiontype` and `Match command`
        // (ADR-0007 §12.32 item 11); 9.5p2 and 9.6p1 refuse them.
        client_version: OpenSshVersion {
            major: 10,
            minor: 5,
            portable: Some(1),
        },
        invocation,
    }
}

/// P's path, so its values carry the managed role the digest binds (ADR-0007 §12.15
/// item 3a), as in the real flow.
fn roots() -> Roots {
    Roots::new(Some(PathBuf::from(USER_CONFIG)), None).with_managed(MANAGED)
}

/// [`state_of`] in a runtime whose environment holds `env`: consent's state, over every
/// invocation profile (ADR-0007 §12.21 item 2).
fn state_in(
    user: &[u8],
    managed: Option<&[u8]>,
    host: &str,
    env: &[(&str, &str)],
) -> BehaviorState {
    let src = source_of(user, managed, env);
    let mut set = ConfigSet::new();
    consent_behavior_state(
        &mut set,
        &src,
        &roots(),
        &query(host, Invocation::Shell),
        &Limits::default(),
    )
}

/// The single-invocation state under `invocation` (tag `heimdall.behavior.v2`): what
/// consent compared before ADR-0007 §12.21 item 2, with `Shell` for every state.
fn single_state(
    user: &[u8],
    managed: Option<&[u8]>,
    host: &str,
    env: &[(&str, &str)],
    invocation: Invocation,
) -> BehaviorState {
    let src = source_of(user, managed, env);
    let mut set = ConfigSet::new();
    let ev = evaluate(
        &mut set,
        &src,
        &roots(),
        &query(host, invocation),
        &Limits::default(),
    );
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
        &RenderPath::unix(Path::new("/hm/home/.config/heimdall/ssh_config")).unwrap(),
        Newline::Lf,
    )
    .unwrap();
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

/// Y01 reviewer scenario (ADR-0007 §12.16 item 1): the approved restore state holds
/// `IdentityAgent ${HM_AGENT}` with the variable naming agent A. After the apply the
/// variable names agent B. The restore digest is unchanged (the text is bound as
/// written), so a determined state would reuse the consent for A; the state is
/// undetermined, so the rollback needs a decision, reason `undetermined_state`.
#[test]
fn consent_rollback_after_environment_endpoint_change_needs_decision() {
    let user = b"Host *\n    IdentityAgent ${HM_AGENT}\n";
    let a = [("HM_AGENT", "/hm/run/agent-a.sock")];
    let b = [("HM_AGENT", "/hm/run/agent-b.sock")];
    let managed = state_in(&with_b(user), Some(&managed_p()), "m1", &a);
    let restore_at_apply = state_in(user, None, "m1", &a);
    let after = state_in(user, None, "m1", &b);
    assert_eq!(
        after.digest, restore_at_apply.digest,
        "the reviewer's observation"
    );
    assert!(!after.determined && !restore_at_apply.determined);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: managed.clone(),
        after,
        consented: Some(ConsentedStates {
            managed,
            restore: restore_at_apply,
        }),
    }]);
    assert!(need.required, "{need:?}");
    assert_eq!(need.reasons.len(), 1);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::UndeterminedState);
}

/// ADR-0007 §12.16 item 1: the default agent is determined, role `default`, in all
/// three forms. A rollback whose restore state names it another way than the consented
/// one (an unset `IdentityAgent` then, `IdentityAgent SSH_AUTH_SOCK` now) needs none.
#[test]
fn consent_default_agent_forms_are_one_consented_state() {
    let then = b"Host *\n    User fallback\n";
    let managed = state_of(&with_b(then), Some(&managed_p()), "m1");
    let restore = state_of(then, None, "m1");
    for now in [
        &b"Host *\n    User fallback\n    IdentityAgent SSH_AUTH_SOCK\n"[..],
        b"Host *\n    User fallback\n    IdentityAgent $SSH_AUTH_SOCK\n",
    ] {
        let after = state_in(now, None, "m1", &[("SSH_AUTH_SOCK", "/hm/run/d.sock")]);
        assert!(after.determined);
        let need = classify(&[ConsentItem {
            item: alias_item(),
            current: managed.clone(),
            after,
            consented: Some(ConsentedStates {
                managed: managed.clone(),
                restore: restore.clone(),
            }),
        }]);
        assert!(!need.required, "{need:?}");
    }
}

// --- V02: consent covers every invocation profile (ADR-0007 §12.21 item 2) -------------

/// The length-prefixed field encoding of the digest input, restated independently.
fn field(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// ADR-0007 §12.21 item 2: the state's digest is SHA-256 over the tag
/// `heimdall.behavior.v3` and the ordered `(profile, per-profile digest)` pairs, and it
/// is determined only when every profile is. Recomputed here from three independent
/// single-invocation evaluations.
#[test]
fn v02_consent_state_digest_is_v3_over_the_ordered_profile_digests() {
    assert_eq!(BEHAVIOR_STATE_TAG, "heimdall.behavior.v3");
    let user = b"Host *\n    User fallback\nMatch sessiontype exec\n    HostName exec.example\n\
                 Match sessiontype subsystem\n    Port 2222\n";
    let state = state_of(user, None, "m1");
    let profiles = [
        ("shell", Invocation::Shell),
        ("exec", Invocation::Exec(None)),
        ("subsystem:sftp", Invocation::Subsystem("sftp".to_owned())),
    ];
    let mut input = Vec::new();
    field(&mut input, "heimdall.behavior.v3");
    field(&mut input, "3");
    let mut all_determined = true;
    let mut per_profile = Vec::new();
    for (name, invocation) in profiles {
        let src = source_of(user, None, &[]);
        let mut set = ConfigSet::new();
        let ev = evaluate(
            &mut set,
            &src,
            &roots(),
            &query("m1", invocation),
            &Limits::default(),
        );
        let r = relevant(&ev);
        let one = behavior_state(&r);
        assert_eq!(one.digest, behavior_digest(&r));
        field(&mut input, name);
        field(&mut input, one.digest.as_str());
        all_determined &= one.determined;
        per_profile.push(one.digest);
    }
    assert_eq!(state.digest, Sha256Hex::of(&input));
    assert_eq!(state.determined, all_determined);
    assert!(state.determined);
    // The three profiles see three different behaviours here, and the v3 state is none
    // of them (another tag, another input).
    assert_ne!(per_profile[0], per_profile[1]);
    assert_ne!(per_profile[0], per_profile[2]);
    assert!(!per_profile.contains(&state.digest));
}

/// V02 reviewer reproducer 1: a `Match sessiontype exec` `HostName` changed after the
/// apply. A rollback would expose another destination to remote commands and Git over
/// SSH, so it needs a decision (`exposes_inherited`). The shell-only states the review
/// saw are equal, which is how the waiver was granted.
#[test]
fn v02_rollback_after_exec_only_hostname_change_needs_decision() {
    let at_apply =
        b"Host *\n    User fallback\nMatch sessiontype exec\n    HostName exec-a.example\n";
    let now = b"Host *\n    User fallback\nMatch sessiontype exec\n    HostName exec-b.example\n";
    let managed = state_of(&with_b(at_apply), Some(&managed_p()), "m1");
    let restore_at_apply = state_of(at_apply, None, "m1");
    assert!(managed.determined && restore_at_apply.determined);
    // P's HostName wins under every profile while B is in place (first obtained, F1).
    let current = state_of(&with_b(now), Some(&managed_p()), "m1");
    assert_eq!(current, managed);
    let after = state_of(now, None, "m1");
    assert!(after.determined);
    assert_ne!(after.digest, restore_at_apply.digest);
    // The review's observation: under the shell alone nothing changed.
    assert_eq!(
        single_state(now, None, "m1", &[], Invocation::Shell),
        single_state(at_apply, None, "m1", &[], Invocation::Shell)
    );
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current,
        after,
        consented: Some(ConsentedStates {
            managed,
            restore: restore_at_apply,
        }),
    }]);
    assert!(need.required, "{need:?}");
    assert_eq!(need.reasons.len(), 1);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::ExposesInherited);
}

/// V02 reviewer reproducer 2: an environment-dependent `IdentityAgent` behind `Match
/// sessiontype subsystem` added after the apply. The restore state is undetermined for
/// SFTP, so the rollback needs a decision (`undetermined_state`), although the shell-only
/// state is determined and unchanged.
#[test]
fn v02_rollback_after_subsystem_only_environment_agent_needs_decision() {
    let env = [("HM_AGENT", "/hm/run/agent-a.sock")];
    let at_apply = b"Host *\n    User fallback\n";
    let now =
        b"Host *\n    User fallback\nMatch sessiontype subsystem\n    IdentityAgent ${HM_AGENT}\n";
    let managed = state_in(&with_b(at_apply), Some(&managed_p()), "m1", &env);
    let restore_at_apply = state_in(at_apply, None, "m1", &env);
    assert!(managed.determined && restore_at_apply.determined);
    let current = state_in(&with_b(now), Some(&managed_p()), "m1", &env);
    assert_eq!(
        current, managed,
        "P's IdentityAgent wins while B is in place"
    );
    let after = state_in(now, None, "m1", &env);
    assert!(!after.determined);
    // The review's observation: the shell-only restore state is determined and equal.
    let shell_now = single_state(now, None, "m1", &env, Invocation::Shell);
    assert!(shell_now.determined);
    assert_eq!(
        shell_now,
        single_state(at_apply, None, "m1", &env, Invocation::Shell)
    );
    assert!(
        !single_state(
            now,
            None,
            "m1",
            &env,
            Invocation::Subsystem("sftp".to_owned())
        )
        .determined
    );
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current,
        after,
        consented: Some(ConsentedStates {
            managed,
            restore: restore_at_apply,
        }),
    }]);
    assert!(need.required, "{need:?}");
    assert_eq!(need.reasons.len(), 1);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::UndeterminedState);
}

/// ADR-0007 §12.21 item 2: an unchanged configuration still waives, also when it has
/// exec- and subsystem-only sections: the rollback yields exactly the consented restore
/// state under every profile.
#[test]
fn v02_unchanged_configuration_with_profile_sections_still_waives() {
    let user = b"Host *\n    User fallback\nMatch sessiontype exec\n    HostName exec-a.example\n\
                 Match sessiontype subsystem\n    Port 2222\n";
    let managed = state_of(&with_b(user), Some(&managed_p()), "m1");
    let restore = state_of(user, None, "m1");
    assert!(managed.determined && restore.determined);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: state_of(&with_b(user), Some(&managed_p()), "m1"),
        after: state_of(user, None, "m1"),
        consented: Some(ConsentedStates { managed, restore }),
    }]);
    assert!(!need.required, "{need:?}");
}

/// ADR-0007 §12.21 item 2: `Match command` is unknown under `Exec(None)` (the command
/// of a remote invocation is not known), so a value behind it makes the state
/// undetermined, which fails closed: even an equal, consented restore state needs a
/// decision. Shell and SFTP decide the condition.
#[test]
fn v02_match_command_is_unknown_under_exec_none_so_the_state_is_undetermined() {
    let user = b"Host *\n    User fallback\nMatch command \"git-upload-pack*\"\n    HostName git.example\n";
    for (invocation, determined) in [
        (Invocation::Shell, true),
        (Invocation::Exec(None), false),
        (Invocation::Subsystem("sftp".to_owned()), true),
        (
            Invocation::Exec(Some("git-upload-pack 'r'".to_owned())),
            true,
        ),
    ] {
        assert_eq!(
            single_state(user, None, "m1", &[], invocation.clone()).determined,
            determined,
            "{invocation:?}"
        );
    }
    let managed = state_of(&with_b(user), Some(&managed_p()), "m1");
    assert!(managed.determined, "P's HostName wins behind B");
    let restore = state_of(user, None, "m1");
    assert!(!restore.determined);
    let need = classify(&[ConsentItem {
        item: alias_item(),
        current: managed.clone(),
        after: state_of(user, None, "m1"),
        consented: Some(ConsentedStates { managed, restore }),
    }]);
    assert!(need.required);
    assert_eq!(need.reasons[0].kind, ConsentReasonKind::UndeterminedState);
}
