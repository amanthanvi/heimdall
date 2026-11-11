//! m03-plan U5 pure registry, plan, step and classification tests (hosted by
//! heimdall-registry): the post-image and post-write checks, the reconcile table and
//! its redispatch property, the plan's preconditions and digest, the remote step's
//! pins and the effective-configuration check, the not-after bound, the HM1 parser
//! and the step classification. Nothing here runs a process or touches a file.
//!
//! Key-shaped strings below are synthetic (base64 of fixed text, not keys); no key,
//! agent or path of the owner is used.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use heimdall_contract::Code;
use heimdall_contract::Timestamp;
use heimdall_contract::enrollment::{
    DisclosureKind, EndpointSource, EnrollmentForm, EnrollmentPlan, EnrollmentSpec,
    EnrollmentState, RegistryCanonical, RegistryResolvedBy, RemoteStage, RemoteStep,
};
use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId, EnrollmentId, IdentityId};
use heimdall_contract::issuer::{CaState, IssuerState};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource, InteractionProfile,
};
use heimdall_domain::enrollment::{
    CatalogView, Determinism, EnrollmentEvent, EnrollmentEventKind, LateWrite, ProxyRoute,
    RawHostKey, RecordFacts, TargetEvaluation, transition,
};
use heimdall_registry::classify::{
    DirState, Expected, FileKind, HolderRecord, Inspection, LockReading, NotAppliedReason,
    StepClass, StepResult, classify_step,
};
use heimdall_registry::fence::{
    DeadlineNow, FenceSignals, FenceView, HardDeadline, LockView, Observation, OurLock,
    ReconcileClass, ReconcileExpected, ReconcilePurpose, UnresolvedReason, classify_reconcile,
    hard_deadline_passed, late_write_cleared, not_after_remote, step_hard_deadline,
};
use heimdall_registry::hm1::{self, Handshake, Hm1Key, MAX_STDOUT_BYTES, ParseError};
use heimdall_registry::line::{self, expected_line, marker_lines};
use heimdall_registry::plan::{
    AgentReading, CaView, CaViewEntry, PairEnrollment, PlanContext, PlanRefusal, build,
    plan_digest, trust_tag,
};
use heimdall_registry::post_image::{
    PostImageError, PostWriteError, check_post_append, check_post_remove, post_image_without,
};
use heimdall_registry::script::{
    self, AppendParams, FenceParams, InspectParams, Marker, NotAfter, Payload, RegistryLine,
    RegistryLocation, RemoveParams, StepToken,
};
use heimdall_registry::step::{
    self, REMOTE_COMMAND, StageInput, StepEnv, StepError, TrustPaths, UnpinnableKind,
    check_effective, remote_step, ssh_args, trust_pins,
};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, FileFailurePersistence, RngSeed};

fn config() -> ProptestConfig {
    let mut c = ProptestConfig {
        cases: 256,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x5235_5055_5245_3031);
    }
    c
}

// --- fixtures ---------------------------------------------------------------------------

const CA_PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhtLWZpeHR1cmUtY2EtcHVibGljLWtleS0wMQ";
const CA_FP: &str = "SHA256:aG0tZml4dHVyZS1jYS1maW5nZXJwcmludC0wMDAwMDA";
const CA2_FP: &str = "SHA256:aG0tZml4dHVyZS1jYS1maW5nZXJwcmludC0wMDAwMDE";
const HOST_KEY: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGhtLWZpeHR1cmUtaG9zdC1rZXktMDEtMDAwMDAwMA";
const HOST_KEY2: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIGhtLWZpeHR1cmUtaG9zdC1rZXktMDItMDAwMDAwMA";
const ID_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhtLWZpeHR1cmUtaWRlbnRpdHktMDEtMDAw";
const RUNTIME: &str = "/tmp/hm-fixture/runtime";
const AGENT: &str = "/tmp/hm-fixture/agent.sock";
const TOKEN: &str = "00112233445566778899aabbccddeeff";
const OTHER_TOKEN: &str = "ffeeddccbbaa99887766554433221100";

fn enrollment_id() -> EnrollmentId {
    EnrollmentId::from_random_bytes([7; 16])
}

fn identity_id() -> IdentityId {
    IdentityId::from_random_bytes([9; 16])
}

fn host_key(blob: &str, revoked: bool) -> RawHostKey {
    RawHostKey {
        key_type: "ssh-ed25519".into(),
        key_b64: blob.into(),
        fingerprint: "SHA256:aG0tZml4dHVyZS1ob3N0LWZpbmdlcnByaW50LTAwMDA".into(),
        origin_display: "~/.ssh/known_hosts:1".into(),
        revoked,
    }
}

fn identity(source: IdentitySource) -> IdentityRecord {
    IdentityRecord {
        id: identity_id(),
        revision: 1,
        interaction: InteractionProfile::default_for(&source, ID_KEY),
        source,
        public_key: ID_KEY.into(),
        fingerprint: "SHA256:aG0tZml4dHVyZS1pZGVudGl0eS1maW5nZXJwcmludA".into(),
        label: None,
        adopted_at: Timestamp::UNIX_EPOCH,
        updated_at: Timestamp::UNIX_EPOCH,
    }
}

fn catalog() -> CatalogView {
    CatalogView {
        destination: DestinationRecord {
            id: DestinationId::parse("dst_lab").unwrap(),
            alias: "lab".into(),
            revision: 1,
            definition: DestinationDefinition::Managed {
                hostname: "lab.example.invalid".into(),
                port: Some(22),
                account: AccountName::parse("deploy").unwrap(),
                identity: identity_id(),
            },
            label: None,
            updated_at: Timestamp::UNIX_EPOCH,
        },
        identity: Some(identity(IdentitySource::NativeAgent {
            endpoint: EndpointRef {
                kind: EndpointKind::UnixSocket,
                locator: AGENT.into(),
            },
        })),
        heimdall_endpoints: vec![RUNTIME.into(), "\\\\.\\pipe\\heimdall-env".into()],
    }
}

fn target() -> TargetEvaluation {
    TargetEvaluation {
        hostname: "lab.example.invalid".into(),
        port: 22,
        user: "deploy".into(),
        proxy: ProxyRoute::None,
        determinism: Determinism::Determined,
        host_keys: vec![host_key(HOST_KEY, false)],
    }
}

fn trust_files() -> TrustPaths {
    let tag = trust_tag(&enrollment_id());
    TrustPaths {
        user_known_hosts: format!("{RUNTIME}/e/{tag}/known_hosts"),
        global_known_hosts: format!("{RUNTIME}/e/{tag}/global_known_hosts"),
        tag,
    }
}

fn cas() -> CaView {
    let tag = trust_tag(&enrollment_id());
    CaView {
        cas: vec![CaViewEntry {
            fingerprint: CaFingerprint::parse(CA_FP).unwrap(),
            state: CaState::Active,
            public_key: CA_PUBLIC.into(),
        }],
        issuer: Some(IssuerState::Ready),
        context: Some(PlanContext {
            enrollment_id: enrollment_id(),
            trust_files: trust_files(),
            identity_file: Some(format!("{RUNTIME}/e/{tag}/identity.pub")),
            alias_identity_agent: AgentReading::Unset,
            pair_enrollments: Vec::new(),
            lock_continuity_acknowledged: false,
        }),
    }
}

fn spec() -> EnrollmentSpec {
    EnrollmentSpec {
        destination: DestinationId::parse("dst_lab").unwrap(),
        account: None,
        form: EnrollmentForm::Account,
        registry_path: None,
        ca_fingerprint: None,
    }
}

fn good_plan() -> EnrollmentPlan {
    build(&catalog(), &target(), &cas(), spec()).unwrap()
}

fn marker() -> String {
    line::marker(&enrollment_id())
}

fn our_line() -> String {
    expected_line(CA_PUBLIC, "hm:dst_lab:deploy", &marker()).unwrap()
}

fn ctx(view: &mut CaView) -> &mut PlanContext {
    view.context.as_mut().unwrap()
}

fn home() -> RegistryCanonical {
    RegistryCanonical {
        path: None,
        resolved_by: RegistryResolvedBy::RemoteHome,
    }
}

fn env() -> StepEnv<'static> {
    StepEnv {
        client: "/usr/bin/ssh",
        timeout_ms: 120_000,
        interactive: false,
        gssapi_key_exchange: false,
    }
}

// --- post-image ---------------------------------------------------------------------------

/// A registry line that never contains the marker (no `:` outside the fixed forms
/// below, and never this enrollment's ID).
fn other_line() -> impl Strategy<Value = String> {
    prop_oneof![
        "[A-Za-z0-9 #=,\"+/._-]{0,40}",
        "[a-z ]{0,20}".prop_map(|c| format!("# {c}")),
        "[A-Za-z0-9+/]{8,40}".prop_map(|b| format!("ssh-ed25519 AAAA{b} admin@host")),
        "[A-Za-z0-9+/]{8,40}"
            .prop_map(|b| format!("from=\"10.0.0.1\",no-pty,command=\"x\" ssh-rsa AAAA{b}")),
        // Near-duplicates of our line that do not carry our marker.
        Just(
            "cert-authority,principals=\"hm:dst_lab:deploy\" ssh-ed25519 AAAA heimdall:enr_ffffffffffffffffffffffffffffffff"
                .to_owned()
        ),
        Just(format!(
            "cert-authority,principals=\"hm:dst_lab:other\" {CA_PUBLIC} heimdall:enr_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        )),
    ]
}

fn terminator() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("\n"), Just("\r\n")]
}

proptest! {
    #![proptest_config(config())]

    /// m03-plan U5: the post-image keeps every byte that is not one of our lines, in
    /// order: CRLF, no final newline, a BOM, comments, options and near-duplicates.
    #[test]
    fn post_image_preserves_every_other_byte(
        others in prop::collection::vec((other_line(), terminator()), 0..8),
        ours_at in prop::collection::vec(0usize..9, 0..3),
        bom in any::<bool>(),
        final_newline in any::<bool>(),
    ) {
        let ours = our_line();
        let mut pieces: Vec<(String, bool)> = others
            .iter()
            .map(|(l, t)| (format!("{l}{t}"), false))
            .collect();
        if bom {
            pieces.insert(0, ("\u{feff}# header\r\n".to_owned(), false));
        }
        for at in &ours_at {
            let at = (*at).min(pieces.len());
            pieces.insert(at, (format!("{ours}\n"), true));
        }
        if !final_newline && let Some((last, _)) = pieces.last_mut() {
            while last.ends_with('\n') || last.ends_with('\r') {
                last.pop();
            }
        }
        let pre: String = pieces.iter().map(|(p, _)| p.as_str()).collect();
        let want: String = pieces.iter().filter(|(_, o)| !o).map(|(p, _)| p.as_str()).collect();
        let got = post_image_without(pre.as_bytes(), &ours).unwrap();
        prop_assert_eq!(got, want.as_bytes());
        prop_assert_eq!(marker_lines(want.as_bytes(), &marker()), 0);
    }

    /// The post-write check after `append` passes with an administrator append after
    /// ours (and the newline the script added), and fails on every damage: a changed
    /// preimage byte, a line joined to ours, a second copy, a changed line.
    #[test]
    fn check_post_append_accepts_admin_append_after_ours_rejects_damage(
        pre_lines in prop::collection::vec((other_line(), terminator()), 0..6),
        pre_final_newline in any::<bool>(),
        admin in prop::collection::vec((other_line(), terminator()), 0..4),
        flip in any::<prop::sample::Index>(),
    ) {
        let ours = our_line();
        let mut pre: String = pre_lines.iter().map(|(l, t)| format!("{l}{t}")).collect();
        if !pre_final_newline {
            while pre.ends_with('\n') || pre.ends_with('\r') {
                pre.pop();
            }
        }
        let sep = if !pre.is_empty() && !pre.ends_with('\n') { "\n" } else { "" };
        let admin: String = admin.iter().map(|(l, t)| format!("{l}{t}")).collect();
        let post = format!("{pre}{sep}{ours}\n{admin}");
        prop_assert_eq!(check_post_append(pre.as_bytes(), post.as_bytes(), &ours), Ok(()));

        if !pre.is_empty() {
            let i = flip.index(pre.len());
            let mut damaged = post.clone().into_bytes();
            damaged[i] = if damaged[i] == b'~' { b'^' } else { b'~' };
            prop_assert!(check_post_append(pre.as_bytes(), &damaged, &ours).is_err());
        }
        let joined = format!("{pre}{sep}X{ours}\n{admin}");
        let joined_ok = matches!(
            check_post_append(pre.as_bytes(), joined.as_bytes(), &ours),
            Err(PostWriteError::LineDamaged { .. })
        );
        prop_assert!(joined_ok, "a line joined to ours");
        let twice = format!("{pre}{sep}{ours}\n{ours}\n{admin}");
        prop_assert_eq!(
            check_post_append(pre.as_bytes(), twice.as_bytes(), &ours),
            Err(PostWriteError::LineDamaged { marker_lines: 2 })
        );
        let changed = format!("{pre}{sep}{}\n{admin}", ours.replacen("deploy", "deplox", 1));
        let changed_ok = matches!(
            check_post_append(pre.as_bytes(), changed.as_bytes(), &ours),
            Err(PostWriteError::LineDamaged { .. })
        );
        prop_assert!(changed_ok, "a changed line");
    }
}

#[test]
fn post_image_refuses_marker_lines_it_did_not_write() {
    let ours = our_line();
    for (variant, number) in [
        (format!("{ours} "), 2),
        (format!("{ours}\r"), 2),
        (format!("no-pty,{ours}"), 2),
        (format!("# {}", marker()), 2),
    ] {
        let pre = format!("a\n{variant}\n{ours}\nb\n");
        assert_eq!(
            post_image_without(pre.as_bytes(), &ours),
            Err(PostImageError::MarkerLineDiffers {
                line_numbers: vec![number]
            }),
            "{variant:?}"
        );
    }
    let post_image = post_image_without(format!("a\n{ours}\nb").as_bytes(), &ours).unwrap();
    assert_eq!(post_image, b"a\nb");
    assert_eq!(
        check_post_remove(&post_image, b"a\nbc\n", &marker()),
        Ok(())
    );
    assert_eq!(
        check_post_remove(&post_image, format!("a\nb\n{ours}\n").as_bytes(), &marker()),
        Err(PostWriteError::MarkerPresent { marker_lines: 1 })
    );
    assert_eq!(
        check_post_remove(&post_image, b"a\n", &marker()),
        Err(PostWriteError::PostImageChanged)
    );
}

// --- reconcile ----------------------------------------------------------------------------

fn inspection(content: &str, lock: LockReading, remote_now: i64) -> Inspection {
    Inspection {
        path: b"/home/deploy/.ssh/authorized_keys".to_vec(),
        dir: DirState::Present,
        dir_mode: Some("drwx------".into()),
        dir_owner_self: Some(true),
        file: FileKind::Regular,
        links: Some(1),
        mode: Some("-rw-------".into()),
        owner_self: Some(true),
        content: Some(content.as_bytes().to_vec()),
        last_byte_newline: Some(content.ends_with('\n')),
        marker_lines: marker_lines(content.as_bytes(), &marker()) as u64,
        lock,
        remote_now,
    }
}

fn holder(token: &str) -> LockReading {
    LockReading::Held(HolderRecord {
        token: token.into(),
        pid: 4242,
        start_hex: "0a0b".into(),
        boot_hex: "ff00".into(),
        not_after: NA,
    })
}

const NA: i64 = 1_700_000_200;

fn expected<'a>(purpose: ReconcilePurpose, line: &'a str) -> ReconcileExpected<'a> {
    ReconcileExpected {
        purpose,
        line,
        step_token: TOKEN,
        not_after_remote: Some(NA),
        approval_valid: true,
        attended: true,
        route_unchanged: true,
        after_manual_recovery: false,
    }
}

fn observe(content: &str, lock: LockReading, remote_now: i64) -> Observation {
    Observation::Inspected(Box::new(inspection(content, lock, remote_now)))
}

fn view(lock: LockView, attempts: u32) -> FenceView {
    FenceView { lock, attempts }
}

/// The domain event a reconcile class records from `state`.
fn event(class: ReconcileClass) -> Option<EnrollmentEventKind> {
    Some(match class {
        ReconcileClass::Applied => EnrollmentEventKind::ReconcileApplied,
        ReconcileClass::Redispatch => EnrollmentEventKind::ReconcileRedispatch,
        ReconcileClass::Damaged => EnrollmentEventKind::ReconcileDamaged,
        ReconcileClass::ApprovalLapsed => EnrollmentEventKind::ReconcileApprovalLapsed,
        ReconcileClass::HolderUnresolved => EnrollmentEventKind::HolderUnresolved,
        ReconcileClass::Unresolved(_) => EnrollmentEventKind::ReconcileUnresolved,
        _ => return None,
    })
}

const OWN_ACCOUNT: RecordFacts = RecordFacts {
    form: EnrollmentForm::Account,
    foreign: false,
};

/// m03-plan U5: every row of ADR-0008 D5 §6.7's table, with fencing first, for the
/// append, the rollback and the explicit removal; each class's event is a transition
/// of the frozen state table from the purpose's uncertain state.
#[test]
fn reconcile_classification_table_every_row() {
    use ReconcileClass as C;
    use UnresolvedReason as U;
    let ours = our_line();
    let one = format!("a\n{ours}\n");
    let none = "a\nb\n".to_owned();
    let differs = format!("a\n{} \n", ours);
    let two = format!("{ours}\n{ours}\n");
    let past = NA + 1;
    let before = NA - 1;
    struct Row {
        name: &'static str,
        purpose: ReconcilePurpose,
        obs: Observation,
        fence: FenceView,
        tweak: fn(&mut ReconcileExpected<'_>),
        want: ReconcileClass,
        from: Option<(EnrollmentState, EnrollmentState)>,
    }
    let same: fn(&mut ReconcileExpected<'_>) = |_| {};
    let lapsed: fn(&mut ReconcileExpected<'_>) = |e| e.approval_valid = false;
    let unattended: fn(&mut ReconcileExpected<'_>) = |e| e.attended = false;
    let moved: fn(&mut ReconcileExpected<'_>) = |e| e.route_unchanged = false;
    let manual: fn(&mut ReconcileExpected<'_>) = |e| e.after_manual_recovery = true;
    use EnrollmentState as S;
    use ReconcilePurpose as P;
    let rows = vec![
        // Append: the observation table.
        Row {
            name: "append exact line",
            purpose: P::Append,
            obs: observe(&one, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Applied,
            from: Some((S::OutcomeUnknown, S::AppliedUnverified)),
        },
        Row {
            name: "append absent, never taken, not-after passed",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Redispatch,
            from: Some((S::OutcomeUnknown, S::Applying)),
        },
        Row {
            name: "append absent, not-after not passed",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: Some((S::OutcomeUnknown, S::OutcomeUnknown)),
        },
        Row {
            name: "append absent at the not-after second",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, NA),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: None,
        },
        Row {
            name: "append absent, approval lapsed",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: lapsed,
            want: C::ApprovalLapsed,
            from: Some((S::OutcomeUnknown, S::Withdrawn)),
        },
        Row {
            name: "append absent, unattended",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: unattended,
            want: C::Unresolved(U::NotAttended),
            from: None,
        },
        Row {
            name: "append absent, route changed",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: moved,
            want: C::Unresolved(U::RouteChanged),
            from: None,
        },
        Row {
            name: "append line differs",
            purpose: P::Append,
            obs: observe(&differs, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Damaged,
            from: Some((S::OutcomeUnknown, S::Held)),
        },
        Row {
            name: "append two marker lines",
            purpose: P::Append,
            obs: observe(&two, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Damaged,
            from: Some((S::OutcomeUnknown, S::Held)),
        },
        Row {
            name: "unreachable",
            purpose: P::Append,
            obs: Observation::Unavailable,
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Unresolved(U::Unreachable),
            from: Some((S::OutcomeUnknown, S::OutcomeUnknown)),
        },
        // Fencing first.
        Row {
            name: "our lock, not fenced",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Fence,
            from: None,
        },
        Row {
            name: "our lock, alive before not-after",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), before),
            fence: view(
                LockView::Ours(OurLock::Alive {
                    not_after_passed: false,
                    terminated: false,
                }),
                0,
            ),
            tweak: same,
            want: C::Unresolved(U::HolderAlive),
            from: None,
        },
        Row {
            name: "our lock, alive after not-after",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(
                LockView::Ours(OurLock::Alive {
                    not_after_passed: true,
                    terminated: false,
                }),
                0,
            ),
            tweak: same,
            want: C::Terminate,
            from: None,
        },
        Row {
            name: "our lock, still alive after terminate",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(
                LockView::Ours(OurLock::Alive {
                    not_after_passed: true,
                    terminated: true,
                }),
                0,
            ),
            tweak: same,
            want: C::Unresolved(U::StillAlive),
            from: None,
        },
        Row {
            name: "our lock, unproven",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(
                LockView::Ours(OurLock::Unproven {
                    signals: FenceSignals::Term,
                }),
                1,
            ),
            tweak: same,
            want: C::Unresolved(U::Unproven),
            from: None,
        },
        Row {
            name: "our lock, unproven at the last attempt",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(
                LockView::Ours(OurLock::Unproven {
                    signals: FenceSignals::TermKill,
                }),
                2,
            ),
            tweak: same,
            want: C::HolderUnresolved,
            from: Some((S::OutcomeUnknown, S::Held)),
        },
        Row {
            name: "fence gone, absent before not-after",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::Ours(OurLock::Gone), 0),
            tweak: same,
            want: C::Redispatch,
            from: None,
        },
        Row {
            name: "fence gone, exact line",
            purpose: P::Append,
            obs: observe(&one, LockReading::None, before),
            fence: view(LockView::Ours(OurLock::Gone), 0),
            tweak: same,
            want: C::Applied,
            from: None,
        },
        Row {
            name: "fence gone but our lock still shown",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(LockView::Ours(OurLock::Gone), 0),
            tweak: same,
            want: C::Unresolved(U::Inconsistent),
            from: None,
        },
        Row {
            name: "fence alive, then our lock vanished",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, past),
            fence: view(
                LockView::Ours(OurLock::Alive {
                    not_after_passed: true,
                    terminated: true,
                }),
                0,
            ),
            tweak: same,
            want: C::Unresolved(U::Inconsistent),
            from: None,
        },
        Row {
            name: "another enrollment's lock: classify directly",
            purpose: P::Append,
            obs: observe(&one, holder(OTHER_TOKEN), before),
            fence: view(LockView::Other, 0),
            tweak: same,
            want: C::Applied,
            from: None,
        },
        Row {
            name: "another's lock, absent, not-after passed",
            purpose: P::Append,
            obs: observe(&none, holder(OTHER_TOKEN), past),
            fence: view(LockView::Other, 0),
            tweak: same,
            want: C::Redispatch,
            from: None,
        },
        Row {
            name: "an unreadable lock record is another's",
            purpose: P::Append,
            obs: observe(&none, LockReading::HeldForeign, before),
            fence: view(LockView::Other, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: None,
        },
        // Integrator (wave-1 review finding 3): an unreadable record may be this step's,
        // so even past the not-after it never proves the holder gone.
        Row {
            name: "an unreadable lock record past the not-after is no proof",
            purpose: P::Append,
            obs: observe(&none, LockReading::HeldForeign, past),
            fence: view(LockView::Other, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: None,
        },
        Row {
            name: "removal: an unreadable lock record past the not-after is no proof",
            purpose: P::Removal,
            obs: observe(&one, LockReading::HeldForeign, past),
            fence: view(LockView::Other, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: None,
        },
        // Rollback and removal: "marker absent" is applied.
        Row {
            name: "rollback absent",
            purpose: P::Rollback,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Applied,
            from: Some((S::RollbackUnknown, S::VerificationFailed)),
        },
        Row {
            name: "rollback present, proven gone",
            purpose: P::Rollback,
            obs: observe(&one, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: lapsed,
            want: C::Redispatch,
            from: Some((S::RollbackUnknown, S::RollbackPending)),
        },
        Row {
            name: "rollback damaged",
            purpose: P::Rollback,
            obs: observe(&differs, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Damaged,
            from: Some((S::RollbackUnknown, S::Held)),
        },
        Row {
            name: "removal absent",
            purpose: P::Removal,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Applied,
            from: Some((S::RemoveUnknown, S::Removed)),
        },
        Row {
            name: "removal present, not proven",
            purpose: P::Removal,
            obs: observe(&one, LockReading::None, before),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Unresolved(U::HolderNotProvenGone),
            from: Some((S::RemoveUnknown, S::RemoveUnknown)),
        },
        Row {
            name: "removal present, fence gone",
            purpose: P::Removal,
            obs: observe(&one, LockReading::None, before),
            fence: view(LockView::Ours(OurLock::Gone), 0),
            tweak: unattended,
            want: C::Redispatch,
            from: Some((S::RemoveUnknown, S::Removing)),
        },
        Row {
            name: "removal two exact copies (X-Q2)",
            purpose: P::Removal,
            obs: observe(&two, LockReading::None, past),
            fence: view(LockView::None, 0),
            tweak: same,
            want: C::Damaged,
            from: Some((S::RemoveUnknown, S::Held)),
        },
        Row {
            name: "removal unproven at the last attempt",
            purpose: P::Removal,
            obs: observe(&one, holder(TOKEN), past),
            fence: view(
                LockView::Ours(OurLock::Unproven {
                    signals: FenceSignals::None,
                }),
                2,
            ),
            tweak: same,
            want: C::HolderUnresolved,
            from: Some((S::RemoveUnknown, S::Held)),
        },
        // Manual recovery: classify only.
        Row {
            name: "manual recovery, one line",
            purpose: P::Append,
            obs: observe(&one, LockReading::None, before),
            fence: view(LockView::None, 3),
            tweak: manual,
            want: C::ManualRecoveryLinePresent,
            from: None,
        },
        Row {
            name: "manual recovery, no line",
            purpose: P::Append,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::None, 3),
            tweak: manual,
            want: C::ManualRecoveryLineAbsent,
            from: None,
        },
        Row {
            name: "manual recovery, our lock still there",
            purpose: P::Append,
            obs: observe(&none, holder(TOKEN), past),
            fence: view(LockView::Ours(OurLock::Gone), 3),
            tweak: manual,
            want: C::Unresolved(U::LockStillHeld),
            from: None,
        },
        Row {
            name: "manual recovery of a removal, no line",
            purpose: P::Removal,
            obs: observe(&none, LockReading::None, before),
            fence: view(LockView::None, 3),
            tweak: manual,
            want: C::ManualRecoveryLineAbsent,
            from: None,
        },
    ];
    for row in rows {
        let mut exp = expected(row.purpose, &ours);
        (row.tweak)(&mut exp);
        let got = classify_reconcile(&row.obs, &exp, row.fence);
        assert_eq!(got, row.want, "{}", row.name);
        if let Some((from, to)) = row.from {
            let kind = event(got).expect(row.name);
            assert_eq!(
                transition(
                    from,
                    EnrollmentEvent {
                        record: OWN_ACCOUNT,
                        kind
                    }
                ),
                Ok(to),
                "{}",
                row.name
            );
        }
    }
    // The manual-recovery classes are the frozen events of a lock_holder_unresolved hold.
    use heimdall_domain::enrollment::{HoldKind, RecoveryPurpose};
    for (purpose, present, to) in [
        (RecoveryPurpose::Append, true, S::AppliedUnverified),
        (RecoveryPurpose::Append, false, S::Withdrawn),
        (RecoveryPurpose::Removal, false, S::Removed),
        (RecoveryPurpose::Rollback, false, S::VerificationFailed),
    ] {
        let hold = HoldKind::LockHolderUnresolved;
        let kind = if present {
            EnrollmentEventKind::ManualRecoveryLinePresent { hold, purpose }
        } else {
            EnrollmentEventKind::ManualRecoveryLineAbsent { hold, purpose }
        };
        assert_eq!(
            transition(
                S::Held,
                EnrollmentEvent {
                    record: OWN_ACCOUNT,
                    kind
                }
            ),
            Ok(to)
        );
    }
    // Bootstrap: present and checked continues; absent may run again.
    let mut dir_absent = inspection("", LockReading::None, past);
    dir_absent.dir = DirState::Absent;
    dir_absent.file = FileKind::Absent;
    dir_absent.content = None;
    let exp = expected(P::Bootstrap, &ours);
    let obs = Observation::Inspected(Box::new(dir_absent));
    assert_eq!(
        classify_reconcile(&obs, &exp, view(LockView::None, 0)),
        C::Redispatch
    );
    let present = observe("", LockReading::None, past);
    assert_eq!(
        classify_reconcile(&present, &exp, view(LockView::None, 0)),
        C::Applied
    );
    let mut open = inspection("", LockReading::None, past);
    open.dir_mode = Some("drwxr-xr-x".into());
    let open = Observation::Inspected(Box::new(open));
    assert_eq!(
        classify_reconcile(&open, &exp, view(LockView::None, 0)),
        C::Unresolved(U::NotManageable)
    );
}

fn lock_views() -> impl Strategy<Value = LockView> {
    let signals = prop_oneof![
        Just(FenceSignals::None),
        Just(FenceSignals::Term),
        Just(FenceSignals::TermKill)
    ];
    prop_oneof![
        Just(LockView::None),
        Just(LockView::Other),
        Just(LockView::Ours(OurLock::Unfenced)),
        Just(LockView::Ours(OurLock::Gone)),
        (any::<bool>(), any::<bool>()).prop_map(|(not_after_passed, terminated)| {
            LockView::Ours(OurLock::Alive {
                not_after_passed,
                terminated,
            })
        }),
        signals.prop_map(|signals| LockView::Ours(OurLock::Unproven { signals })),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// m03-plan U5: no class authorizes a redispatch unless the holder is proven gone
    /// (fence removed its lock) or its lock was never taken and its not-after has
    /// passed on the remote clock; never from an `alive` or `unproven` fence, never in
    /// manual recovery, and an append's only within the approval, attended, on the
    /// same route.
    #[test]
    fn reconcile_never_redispatches_without_proven_termination(
        shown in 0u8..4,
        fence_lock in lock_views(),
        attempts in 0u32..5,
        content in 0u8..4,
        remote_now in (NA - 5)..(NA + 5),
        not_after in prop::option::of((NA - 3)..(NA + 3)),
        purpose in prop_oneof![
            Just(ReconcilePurpose::Append),
            Just(ReconcilePurpose::Rollback),
            Just(ReconcilePurpose::Removal),
            Just(ReconcilePurpose::Bootstrap),
        ],
        flags in any::<(bool, bool, bool, bool)>(),
    ) {
        let ours = our_line();
        let text = match content {
            0 => format!("a\n{ours}\n"),
            1 => "a\n".to_owned(),
            2 => format!("{ours}\n{ours}\n"),
            _ => format!("{ours}x\n"),
        };
        let lock = match shown {
            0 => LockReading::None,
            1 => holder(TOKEN),
            2 => holder(OTHER_TOKEN),
            _ => LockReading::HeldForeign,
        };
        let obs = observe(&text, lock, remote_now);
        let (approval_valid, attended, route_unchanged, after_manual_recovery) = flags;
        let exp = ReconcileExpected {
            purpose,
            line: &ours,
            step_token: TOKEN,
            not_after_remote: not_after,
            approval_valid,
            attended,
            route_unchanged,
            after_manual_recovery,
        };
        let class = classify_reconcile(&obs, &exp, view(fence_lock, attempts));
        if matches!(
            fence_lock,
            LockView::Ours(OurLock::Alive { .. } | OurLock::Unproven { .. })
        ) {
            prop_assert!(!class.redispatches(), "{fence_lock:?} {class:?}");
        }
        if class.redispatches() {
            prop_assert!(!after_manual_recovery);
            prop_assert!(shown != 1, "our lock is still shown");
            let fenced_gone = fence_lock == LockView::Ours(OurLock::Gone);
            // Integrator (wave-1 review finding 3): an unreadable lock record is never
            // proof by the not-after alone.
            prop_assert!(shown != 3 || fenced_gone, "unreadable lock record read as proof");
            let never_taken = matches!(
                fence_lock,
                LockView::None | LockView::Other | LockView::Ours(OurLock::Unfenced)
            ) && not_after.is_some_and(|na| remote_now > na);
            if purpose != ReconcilePurpose::Bootstrap {
                prop_assert!(fenced_gone || never_taken, "{fence_lock:?} {not_after:?} {remote_now}");
            }
            prop_assert!(route_unchanged);
            if matches!(purpose, ReconcilePurpose::Append | ReconcilePurpose::Bootstrap) {
                prop_assert!(approval_valid && attended);
            }
        }
        if matches!(fence_lock, LockView::Ours(OurLock::Unproven { .. }))
            && shown == 1
            && !after_manual_recovery
        {
            prop_assert!(class.counts_attempt(), "{class:?}");
        }
    }
}

// --- the not-after and the hard deadline -------------------------------------------------

proptest! {
    #![proptest_config(config())]

    /// m03-plan U5: the remote clock has passed the step's not-after by its hard
    /// deadline, with 30 s to spare for the reading's resolution and drift (D5 §6.3).
    #[test]
    fn not_after_computation_bounds_hard_deadline(
        t in 0i64..4_000_000_000,
        resolution_ms in 0u64..1_000,
        transit_ms in 0u64..10_000,
        c_read_ms in 0u64..1_000_000_000,
        age_ms in 0u64..=600_000,
        timeout_ms in prop_oneof![Just(120_000u64), Just(300_000u64), 1u64..400_000],
        drift_ppm in -100i64..=100,
    ) {
        let c_read = Duration::from_millis(c_read_ms);
        let c_issue = Duration::from_millis(c_read_ms + age_ms);
        let timeout = Duration::from_millis(timeout_ms);
        let na = not_after_remote(t, c_read, c_issue, timeout).unwrap();
        let hd = step_hard_deadline(c_issue, timeout).unwrap();
        // The remote clock (ms) when the reading arrived: at least T, as it was read
        // (truncated to seconds) before it arrived.
        let remote_at_read = t * 1000 + resolution_ms as i64 + transit_ms as i64;
        let elapsed = (hd - c_read).as_millis() as i64;
        let remote_at_hd = remote_at_read + elapsed + elapsed * drift_ppm / 1_000_000;
        prop_assert!(
            remote_at_hd >= (na + 30) * 1000 - 100,
            "remote at the hard deadline {remote_at_hd} vs not-after {na}"
        );
        // And the script gets at least the timeout after its issue.
        prop_assert!(na * 1000 >= t * 1000 + age_ms as i64 + timeout_ms as i64 + 60_000 - 2_000);
    }
}

/// m03-plan U5 (B R2-11): after a local reboot the continuous deadline is void; it
/// passes only once **safe** wall time is past the wall deadline (after `time
/// confirm`, Q13).
#[test]
fn hard_deadline_after_reboot_passes_on_safe_wall_time() {
    let wall = Timestamp::from_second(1_700_000_300).unwrap();
    let deadline = HardDeadline {
        continuous: Duration::from_secs(500),
        wall,
        boot_id: "boot-a".into(),
    };
    let same_boot = |c: u64| DeadlineNow {
        boot_id: "boot-a",
        continuous: Duration::from_secs(c),
        safe_wall: None,
    };
    assert!(!hard_deadline_passed(&deadline, &same_boot(500)));
    assert!(hard_deadline_passed(&deadline, &same_boot(501)));
    // Rebooted: a small continuous value proves nothing, nor does a large one.
    for c in [1, 10_000] {
        let rebooted = DeadlineNow {
            boot_id: "boot-b",
            continuous: Duration::from_secs(c),
            safe_wall: None,
        };
        assert!(!hard_deadline_passed(&deadline, &rebooted));
    }
    let after = Timestamp::from_second(1_700_000_301).unwrap();
    let at = DeadlineNow {
        boot_id: "boot-b",
        continuous: Duration::from_secs(1),
        safe_wall: Some(wall),
    };
    assert!(!hard_deadline_passed(&deadline, &at));
    let past = DeadlineNow {
        safe_wall: Some(after),
        ..at
    };
    assert!(hard_deadline_passed(&deadline, &past));
}

/// The pure part of `late_write_residual_cleared_only_by_inspect_after_not_after`
/// (D5 §6.7): only an inspect whose remote reading is past the residual's not-after,
/// with no marker line and no lock of that token, clears it.
#[test]
fn late_write_residual_cleared_only_by_inspect_after_not_after() {
    let residual = LateWrite {
        step_token: TOKEN.into(),
        not_after_remote: NA,
    };
    let m = marker();
    let clean = inspection("a\n", LockReading::None, NA + 1);
    assert!(late_write_cleared(&clean, &residual, &m));
    assert!(!late_write_cleared(
        &inspection("a\n", LockReading::None, NA),
        &residual,
        &m
    ));
    let with_line = inspection(&format!("{}\n", our_line()), LockReading::None, NA + 1);
    assert!(!late_write_cleared(&with_line, &residual, &m));
    assert!(!late_write_cleared(
        &inspection("a\n", holder(TOKEN), NA + 1),
        &residual,
        &m
    ));
    assert!(late_write_cleared(
        &inspection("a\n", holder(OTHER_TOKEN), NA + 1),
        &residual,
        &m
    ));
    assert!(!late_write_cleared(
        &inspection("a\n", LockReading::HeldForeign, NA + 1),
        &residual,
        &m
    ));
    let mut link = inspection("", LockReading::None, NA + 1);
    link.file = FileKind::Symlink;
    link.content = None;
    assert!(!late_write_cleared(&link, &residual, &m));
}

// --- the plan -----------------------------------------------------------------------------

fn refused(
    catalog: &CatalogView,
    target: &TargetEvaluation,
    cas: &CaView,
    spec: EnrollmentSpec,
) -> PlanRefusal {
    build(catalog, target, cas, spec).expect_err("refused")
}

/// m03-plan U5: every D5 §6.1 precondition refuses with its own reason and code, and
/// the good plan names the approved target, the invocation and its endpoint, the
/// host-trust pins, the bootstrap step, the line and the disclosures.
#[test]
fn plan_refusals_each_precondition() {
    let (c, t, v, s) = (catalog(), target(), cas(), spec());
    let plan = good_plan();
    assert_eq!(plan.line, our_line());
    assert_eq!(plan.alias, "lab");
    assert_eq!(plan.registry.path_display, "$HOME/.ssh/authorized_keys");
    assert_eq!(plan.approved_target.hostname, "lab.example.invalid");
    assert_eq!(plan.approved_target.host_key.key, HOST_KEY);
    assert_eq!(plan.existing_access.endpoint, AGENT);
    assert_eq!(
        plan.existing_access.endpoint_source,
        EndpointSource::CatalogRecord
    );
    let tag = trust_tag(&enrollment_id());
    assert_eq!(
        plan.existing_access.invocation,
        [
            "-o".to_owned(),
            format!("IdentityAgent={AGENT}"),
            "-o".to_owned(),
            format!("IdentityFile={RUNTIME}/e/{tag}/identity.pub"),
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            "CertificateFile=none".to_owned(),
            "-o".to_owned(),
            "ControlMaster=no".to_owned(),
            "-o".to_owned(),
            "ControlPath=none".to_owned(),
        ]
    );
    assert_eq!(plan.host_trust.len(), 10);
    assert!(plan.bootstrap.is_some());
    assert_eq!(
        plan.disclosures,
        [
            DisclosureKind::ConfigCommandsRunAsOrdinaryUse,
            DisclosureKind::CaTrustBlastRadius,
            DisclosureKind::RemoveWindow,
            DisclosureKind::LockContinuityOnce,
            DisclosureKind::ReconcileMayStopOwnStaleScript,
            DisclosureKind::OrdinarySshNeedsHeldSlot,
        ]
    );
    let mut acked = cas();
    ctx(&mut acked).lock_continuity_acknowledged = true;
    let p = build(&c, &t, &acked, spec()).unwrap();
    assert!(!p.disclosures.contains(&DisclosureKind::LockContinuityOnce));

    let check = |want: PlanRefusal, got: PlanRefusal, why: &str| {
        assert_eq!(got, want, "{why}");
        assert_eq!(got.code(), want.code());
    };
    // The context the frozen signature lacks (U5P-Q1).
    let mut x = cas();
    x.context = None;
    check(
        PlanRefusal::DriverUnavailable,
        refused(&c, &t, &x, spec()),
        "no context",
    );
    // A CA registered and the issuer ready.
    let mut x = cas();
    x.issuer = Some(IssuerState::NotInitialized);
    check(
        PlanRefusal::IssuerNotInitialized,
        refused(&c, &t, &x, spec()),
        "not initialized",
    );
    let mut x = cas();
    x.cas.clear();
    x.issuer = None;
    check(
        PlanRefusal::IssuerNotInitialized,
        refused(&c, &t, &x, spec()),
        "no CA",
    );
    for state in [
        IssuerState::Crashed,
        IssuerState::Starting,
        IssuerState::StoreUnavailable,
    ] {
        let mut x = cas();
        x.issuer = Some(state);
        check(
            PlanRefusal::IssuerUnavailable,
            refused(&c, &t, &x, spec()),
            "issuer state",
        );
    }
    let mut x = cas();
    x.issuer = None;
    check(
        PlanRefusal::IssuerUnavailable,
        refused(&c, &t, &x, spec()),
        "unknown issuer",
    );
    let mut named = spec();
    named.ca_fingerprint = Some(CaFingerprint::parse(CA2_FP).unwrap());
    check(
        PlanRefusal::IssuerNotInitialized,
        refused(&c, &t, &v, named.clone()),
        "unknown CA",
    );
    for state in [
        CaState::Retiring,
        CaState::Unloaded,
        CaState::Deleted,
        CaState::Retired,
    ] {
        let mut x = cas();
        x.cas[0].state = state;
        let mut s2 = spec();
        s2.ca_fingerprint = Some(CaFingerprint::parse(CA_FP).unwrap());
        check(
            PlanRefusal::CaRetiring,
            refused(&c, &t, &x, s2),
            "retiring CA",
        );
    }
    let mut x = cas();
    x.cas[0].state = CaState::Pending;
    check(
        PlanRefusal::IssuerNotInitialized,
        refused(&c, &t, &x, spec()),
        "no active CA",
    );
    let mut s2 = spec();
    s2.ca_fingerprint = Some(CaFingerprint::parse(CA_FP).unwrap());
    assert!(
        build(&c, &t, &x, s2).is_ok(),
        "rotation names the pending CA"
    );
    // Managed.
    let mut x = catalog();
    x.destination.definition = DestinationDefinition::Observed;
    check(
        PlanRefusal::ObservedAliasUnmanaged,
        refused(&x, &t, &v, spec()),
        "observed",
    );
    // The principal charset.
    let mut x = catalog();
    x.destination.id = DestinationId::parse("dst:lab").unwrap();
    let mut s2 = spec();
    s2.destination = x.destination.id.clone();
    check(
        PlanRefusal::PrincipalCharset,
        refused(&x, &t, &v, s2),
        "destination charset",
    );
    let mut x = catalog();
    if let DestinationDefinition::Managed { account, .. } = &mut x.destination.definition {
        *account = AccountName::parse("de:ploy").unwrap();
    }
    check(
        PlanRefusal::PrincipalCharset,
        refused(&x, &t, &v, spec()),
        "account charset",
    );
    // A determined, direct route.
    let mut x = target();
    x.determinism = Determinism::Undetermined {
        reason: "match_exec".into(),
    };
    check(
        PlanRefusal::RouteUndetermined,
        refused(&c, &x, &v, spec()),
        "undetermined",
    );
    for proxy in [ProxyRoute::Jump, ProxyRoute::Command] {
        let mut x = target();
        x.proxy = proxy;
        check(
            PlanRefusal::RouteUnsupported,
            refused(&c, &x, &v, spec()),
            "proxy",
        );
    }
    let mut x = target();
    x.hostname = "lab%h".into();
    check(
        PlanRefusal::RouteUndetermined,
        refused(&c, &x, &v, spec()),
        "hostname token",
    );
    // Exactly one non-revoked host key.
    for keys in [
        vec![],
        vec![host_key(HOST_KEY, false), host_key(HOST_KEY2, false)],
        vec![host_key(HOST_KEY, true)],
        vec![host_key(HOST_KEY, false), host_key(HOST_KEY, true)],
    ] {
        let mut x = target();
        x.host_keys = keys;
        check(
            PlanRefusal::HostTrustUndetermined,
            refused(&c, &x, &v, spec()),
            "host keys",
        );
    }
    let mut x = target();
    x.host_keys = vec![
        host_key(HOST_KEY, false),
        host_key(HOST_KEY, false),
        host_key(HOST_KEY2, true),
    ];
    assert!(build(&c, &x, &v, spec()).is_ok(), "one distinct key");
    for kind in ["ssh-ed25519-cert-v01@openssh.com", "ssh-dss"] {
        let mut x = target();
        x.host_keys[0].key_type = kind.into();
        check(
            PlanRefusal::HostTrustUndetermined,
            refused(&c, &x, &v, spec()),
            kind,
        );
    }
    // No account override (also account_override_refused below).
    let mut s2 = spec();
    s2.account = Some(AccountName::parse("root").unwrap());
    check(
        PlanRefusal::AccountOverrideRefused,
        refused(&c, &t, &v, s2),
        "override",
    );
    // An adopted identity of a usable kind.
    let mut x = catalog();
    x.identity = None;
    check(
        PlanRefusal::PairNotAdopted,
        refused(&x, &t, &v, spec()),
        "no identity",
    );
    let mut x = catalog();
    x.identity.as_mut().unwrap().id = IdentityId::from_random_bytes([1; 16]);
    check(
        PlanRefusal::PairNotAdopted,
        refused(&x, &t, &v, spec()),
        "another identity",
    );
    let mut x = catalog();
    x.identity.as_mut().unwrap().public_key = "ssh-dss AAAAB3NzaC1kc3M".into();
    check(
        PlanRefusal::ExistingAccessKindUnsupported,
        refused(&x, &t, &v, spec()),
        "dss",
    );
    // A concrete endpoint, never SSH_AUTH_SOCK, never Heimdall's.
    let onepassword = |c: &mut CatalogView| {
        c.identity = Some(identity(IdentitySource::OnePassword { endpoint: None }));
    };
    for reading in [
        AgentReading::Unset,
        AgentReading::Undetermined,
        AgentReading::Determined("SSH_AUTH_SOCK".into()),
        AgentReading::Determined("$SSH_AUTH_SOCK".into()),
        AgentReading::Determined("~/.1password/agent.sock".into()),
        AgentReading::Determined("none".into()),
    ] {
        let mut x = catalog();
        onepassword(&mut x);
        let mut y = cas();
        ctx(&mut y).alias_identity_agent = reading.clone();
        check(
            PlanRefusal::ExistingAccessEndpointUnrecorded,
            refused(&x, &t, &y, spec()),
            &format!("{reading:?}"),
        );
    }
    let mut x = catalog();
    onepassword(&mut x);
    let mut y = cas();
    ctx(&mut y).alias_identity_agent =
        AgentReading::Determined("/tmp/hm-fixture/1p dir/agent.sock".into());
    let p = build(&x, &t, &y, spec()).unwrap();
    assert_eq!(
        p.existing_access.endpoint_source,
        EndpointSource::AliasIdentityAgent
    );
    assert_eq!(p.existing_access.mechanism, "onepassword");
    assert_eq!(
        p.existing_access.invocation[1],
        "IdentityAgent=\"/tmp/hm-fixture/1p dir/agent.sock\""
    );
    let mut x = catalog();
    x.identity = Some(identity(IdentitySource::PublicKeyFile {
        path: "/tmp/hm-fixture/lab.pub".into(),
    }));
    let mut y = cas();
    ctx(&mut y).alias_identity_agent = AgentReading::Determined(AGENT.into());
    let p = build(&x, &t, &y, spec()).unwrap();
    assert_eq!(
        p.existing_access.invocation[3],
        "IdentityFile=/tmp/hm-fixture/lab.pub"
    );
    for heimdall in [
        format!("{RUNTIME}/signing.sock"),
        format!("{RUNTIME}/b/0001/agent.sock"),
        "//./pipe/HEIMDALL-ENV".to_owned(),
    ] {
        let kind = if heimdall.starts_with("//") {
            EndpointKind::NamedPipe
        } else {
            EndpointKind::UnixSocket
        };
        let mut x = catalog();
        x.identity = Some(identity(IdentitySource::NativeAgent {
            endpoint: EndpointRef {
                kind,
                locator: heimdall.clone(),
            },
        }));
        check(
            PlanRefusal::ExistingAccessEndpointIsHeimdall,
            refused(&x, &t, &v, spec()),
            &heimdall,
        );
    }
    // No live enrollment for this (pair, CA).
    let fp = CaFingerprint::parse(CA_FP).unwrap();
    for (state, origin, live) in [
        (EnrollmentState::Verified, false, true),
        (EnrollmentState::OutcomeUnknown, false, true),
        (EnrollmentState::ManualPending, false, true),
        (EnrollmentState::Held, false, true),
        (EnrollmentState::Held, true, false),
        (EnrollmentState::Abandoned, false, false),
        (EnrollmentState::Removing, false, false),
        (EnrollmentState::Removed, false, false),
    ] {
        let mut y = cas();
        ctx(&mut y).pair_enrollments = vec![PairEnrollment {
            ca_fingerprint: fp.clone(),
            state,
            removal_origin_set: origin,
        }];
        let r = build(&c, &t, &y, spec());
        if live {
            assert_eq!(r.unwrap_err(), PlanRefusal::AlreadyEnrolled, "{state:?}");
            assert_eq!(PlanRefusal::AlreadyEnrolled.code(), Code::ConfigConflict);
        } else {
            assert!(r.is_ok(), "{state:?}");
        }
    }
    let mut y = cas();
    ctx(&mut y).pair_enrollments = vec![PairEnrollment {
        ca_fingerprint: CaFingerprint::parse(CA2_FP).unwrap(),
        state: EnrollmentState::Verified,
        removal_origin_set: false,
    }];
    assert!(build(&c, &t, &y, spec()).is_ok(), "another CA's enrollment");
    // The registry path.
    for bad in [
        "relative/authorized_keys",
        "/a/../b",
        "/a b/c",
        "/a/",
        &format!("/{}", "a".repeat(255)),
    ] {
        let mut s2 = spec();
        s2.registry_path = Some(bad.into());
        check(
            PlanRefusal::RegistryPathInvalid,
            refused(&c, &t, &v, s2),
            bad,
        );
        assert_eq!(PlanRefusal::RegistryPathInvalid.code(), Code::UsageError);
    }
    let mut s2 = spec();
    s2.registry_path = Some("/tmp/hm-fixture/reg/authorized_keys".into());
    let p = build(&c, &t, &v, s2.clone()).unwrap();
    assert_eq!(p.registry.resolved_by, RegistryResolvedBy::Explicit);
    assert_eq!(
        p.registry.path_display,
        "/tmp/hm-fixture/reg/authorized_keys"
    );
    s2.form = EnrollmentForm::System;
    check(
        PlanRefusal::RegistryPathInvalid,
        refused(&c, &t, &v, s2),
        "system form path",
    );
    let mut sys = spec();
    sys.form = EnrollmentForm::System;
    let p = build(&c, &t, &v, sys).unwrap();
    assert!(p.bootstrap.is_none());
    assert!(!p.disclosures.contains(&DisclosureKind::RemoveWindow));
    let _ = s;
}

/// m03-plan U5: an `--account` other than the managed definition's is `USAGE_ERROR`,
/// `account_override_refused`; so is a configuration whose evaluated `User` is not
/// the catalog's account (U5P-Q6).
#[test]
fn account_override_refused() {
    let mut s = spec();
    s.account = Some(AccountName::parse("root").unwrap());
    let r = build(&catalog(), &target(), &cas(), s).unwrap_err();
    assert_eq!(r, PlanRefusal::AccountOverrideRefused);
    assert_eq!(r.code(), Code::UsageError);
    assert_eq!(r.reason(), "account_override_refused");
    let mut s = spec();
    s.account = Some(AccountName::parse("deploy").unwrap());
    assert!(build(&catalog(), &target(), &cas(), s).is_ok());
    let mut t = target();
    t.user = "root".into();
    assert_eq!(
        build(&catalog(), &t, &cas(), spec()).unwrap_err(),
        PlanRefusal::AccountOverrideRefused
    );
}

fn leaf_paths(value: &serde_json::Value, prefix: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                leaf_paths(v, format!("{prefix}/{k}"), out);
            }
        }
        _ => out.push(prefix),
    }
}

/// m03-plan U5: `plan_digest` is bare 64 lowercase hex (X-Q4), stable, independent
/// of the `plan_digest` field, and changes with every other field: the approved
/// target, the invocation, the endpoint and the bootstrap step included. The
/// mutation list is checked against the plan's JSON leaves, so a field added later
/// without a mutation fails here.
#[test]
fn plan_digest_covers_every_field() {
    type Mutation = (&'static str, fn(&mut EnrollmentPlan));
    let mutations: Vec<Mutation> = vec![
        ("/destination_id", |p| {
            p.destination_id = DestinationId::parse("dst_x").unwrap()
        }),
        ("/alias", |p| p.alias = "lab2".into()),
        ("/account", |p| {
            p.account = AccountName::parse("other").unwrap()
        }),
        ("/form", |p| p.form = EnrollmentForm::System),
        ("/registry/path_display", |p| {
            p.registry.path_display = "/x/authorized_keys".into()
        }),
        ("/registry/resolved_by", |p| {
            p.registry.resolved_by = RegistryResolvedBy::Explicit
        }),
        ("/line", |p| p.line.push('x')),
        ("/line_sha256", |p| p.line_sha256 = "0".repeat(64)),
        ("/ca_fingerprint", |p| {
            p.ca_fingerprint = CaFingerprint::parse(CA2_FP).unwrap()
        }),
        ("/existing_access/identity_id", |p| {
            p.existing_access.identity_id = IdentityId::from_random_bytes([3; 16]);
        }),
        ("/existing_access/mechanism", |p| {
            p.existing_access.mechanism = "onepassword".into()
        }),
        ("/existing_access/endpoint", |p| {
            p.existing_access.endpoint = "/tmp/other.sock".into()
        }),
        ("/existing_access/endpoint_source", |p| {
            p.existing_access.endpoint_source = EndpointSource::AliasIdentityAgent;
        }),
        ("/existing_access/invocation", |p| {
            p.existing_access.invocation[1] = "IdentityAgent=/tmp/other.sock".into();
        }),
        ("/host_trust", |p| {
            p.host_trust[6] = "StrictHostKeyChecking=accept-new".into()
        }),
        ("/approved_target/hostname", |p| {
            p.approved_target.hostname = "evil.invalid".into()
        }),
        ("/approved_target/port", |p| p.approved_target.port = 2222),
        ("/approved_target/user", |p| {
            p.approved_target.user = AccountName::parse("root").unwrap()
        }),
        ("/approved_target/host_key/algorithm", |p| {
            p.approved_target.host_key.algorithm = "ssh-rsa".into();
        }),
        ("/approved_target/host_key/key", |p| {
            p.approved_target.host_key.key = HOST_KEY2.into()
        }),
        ("/approved_target/host_key/fingerprint", |p| {
            p.approved_target.host_key.fingerprint = "SHA256:other".into();
        }),
        ("/bootstrap", |p| p.bootstrap = None),
        ("/verification/positive_principal", |p| {
            p.verification.positive_principal = "hm:dst_lab:root".into();
        }),
        ("/verification/negative", |p| {
            p.verification.negative = false
        }),
        ("/verification/max_validity_seconds", |p| {
            p.verification.max_validity_seconds = 301
        }),
        ("/disclosures", |p| {
            p.disclosures.pop();
        }),
    ];
    // Fields with a single possible value: covered by the digest, but nothing to vary.
    let single_valued = ["/approved_target/proxy", "/rollback"];

    let plan = good_plan();
    let digest = plan_digest(&plan).unwrap();
    assert_eq!(digest, plan.plan_digest);
    assert_eq!(digest.as_str().len(), 64);
    assert!(
        digest
            .as_str()
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    );
    assert_eq!(good_plan().plan_digest, digest, "deterministic");
    let mut other = plan.clone();
    other.plan_digest = heimdall_contract::setup::PlanDigest::from_sha256([0xee; 32]);
    assert_eq!(
        plan_digest(&other).unwrap(),
        digest,
        "plan_digest itself is excluded"
    );

    let mut leaves = Vec::new();
    leaf_paths(
        &serde_json::to_value(&plan).unwrap(),
        String::new(),
        &mut leaves,
    );
    for leaf in &leaves {
        if leaf == "/plan_digest" || single_valued.contains(&leaf.as_str()) {
            continue;
        }
        assert!(
            mutations.iter().any(|(path, _)| path == leaf),
            "no mutation covers {leaf}"
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for (path, mutate) in &mutations {
        let mut changed = plan.clone();
        mutate(&mut changed);
        assert_ne!(changed, plan, "{path} did not change the plan");
        let d = plan_digest(&changed).unwrap();
        assert_ne!(d, digest, "{path}");
        assert!(seen.insert(d), "{path} collides");
    }
}

// --- the remote step ---------------------------------------------------------------------

fn pin_list(step: &RemoteStep) -> Vec<Vec<(String, String)>> {
    [
        &step.pins.target.0,
        &step.pins.host_trust.0,
        &step.pins.existing_access.0,
        &step.pins.narrowing.0,
    ]
    .into_iter()
    .map(|l| l.iter().map(|o| (o.key.clone(), o.value.clone())).collect())
    .collect()
}

fn kv(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// m03-plan U5: every step carries exactly the pin set of D5 §6.3, in order (target,
/// host trust, existing access, narrowing with `ForkAfterAuthentication=no`), the
/// fixed remote command and the stage's script; a tampered plan, alias, token or
/// not-after is refused.
#[test]
fn remote_step_pins_are_exactly_the_documented_set() {
    let plan = good_plan();
    let tag = trust_tag(&enrollment_id());
    let ukh = format!("{RUNTIME}/e/{tag}/known_hosts");
    let gkh = format!("{RUNTIME}/e/{tag}/global_known_hosts");
    let alias = format!("hm-target-{tag}");
    let idf = format!("{RUNTIME}/e/{tag}/identity.pub");
    let want = vec![
        kv(&[
            ("HostName", "lab.example.invalid"),
            ("Port", "22"),
            ("User", "deploy"),
            ("ProxyCommand", "none"),
            ("ProxyJump", "none"),
            ("CanonicalizeHostname", "no"),
        ]),
        kv(&[
            ("UserKnownHostsFile", &ukh),
            ("GlobalKnownHostsFile", &gkh),
            ("KnownHostsCommand", "none"),
            ("VerifyHostKeyDNS", "no"),
            ("HostKeyAlgorithms", "ssh-ed25519"),
            ("HostKeyAlias", &alias),
            ("StrictHostKeyChecking", "yes"),
            ("CheckHostIP", "no"),
            ("UpdateHostKeys", "no"),
            ("NoHostAuthenticationForLocalhost", "no"),
        ]),
        kv(&[
            ("IdentityAgent", AGENT),
            ("IdentityFile", &idf),
            ("IdentitiesOnly", "yes"),
            ("CertificateFile", "none"),
            ("ControlMaster", "no"),
            ("ControlPath", "none"),
        ]),
        kv(&[
            ("BatchMode", "yes"),
            ("ForwardAgent", "no"),
            ("ClearAllForwardings", "yes"),
            ("PermitLocalCommand", "no"),
            ("RequestTTY", "no"),
            ("ForkAfterAuthentication", "no"),
        ]),
    ];
    let m = Marker::parse(&marker()).unwrap();
    let token = StepToken::parse(TOKEN).unwrap();
    let pre = b"a\n".to_vec();
    let post: Vec<u8> = Vec::new();
    let stages: Vec<(StageInput<'_>, Option<i64>, String)> = vec![
        (
            StageInput::Inspect,
            None,
            script::inspect(&InspectParams {
                registry: RegistryLocation::RemoteHome,
                marker: m.clone(),
            })
            .into_text(),
        ),
        (
            StageInput::Bootstrap,
            None,
            script::bootstrap(&script::BootstrapParams {
                registry: RegistryLocation::RemoteHome,
            })
            .into_text(),
        ),
        (
            StageInput::Append,
            Some(NA),
            script::append(&AppendParams {
                registry: RegistryLocation::RemoteHome,
                marker: m.clone(),
                line: RegistryLine::parse(&our_line(), &m).unwrap(),
                token: token.clone(),
                not_after_remote: NotAfter::new(NA).unwrap(),
            })
            .into_text(),
        ),
        (
            StageInput::Remove {
                preimage: &pre,
                post_image: &post,
            },
            Some(NA),
            script::remove(&RemoveParams {
                registry: RegistryLocation::RemoteHome,
                marker: m.clone(),
                token: token.clone(),
                not_after_remote: NotAfter::new(NA).unwrap(),
                preimage: Payload::new(&pre).unwrap(),
                post_image: Payload::new(&post).unwrap(),
            })
            .into_text(),
        ),
        (
            StageInput::Fence { terminate: true },
            None,
            script::fence(&FenceParams {
                registry: RegistryLocation::RemoteHome,
                token: token.clone(),
                terminate: true,
            })
            .into_text(),
        ),
    ];
    for (stage, not_after, script_text) in stages {
        let step = remote_step(stage, &plan, &home(), TOKEN, 9_000, not_after, &env()).unwrap();
        assert_eq!(step.stage, stage.stage());
        assert_eq!(pin_list(&step), want, "{:?}", step.stage);
        assert_eq!(
            step.remote_command,
            "printf 'HM1 ready\\n'; exec /bin/sh -s"
        );
        assert_eq!(step.remote_command, REMOTE_COMMAND);
        assert_eq!(step.script, script_text, "{:?}", step.stage);
        assert_eq!(step.not_after_remote, not_after);
        assert_eq!((step.timeout_ms, step.hard_deadline_ms), (120_000, 9_000));
        assert_eq!(step.client, "/usr/bin/ssh");
        let args = ssh_args(&step);
        assert_eq!(args[args.len() - 3..], ["-T", "lab", REMOTE_COMMAND]);
        assert_eq!(args.len(), 2 * 28 + 3);
        assert!(args.iter().step_by(2).take(28).all(|a| a == "-o"));
    }
    // Interactive: BatchMode=no. Q23: GSSAPIKeyExchange=no appended to host trust.
    let mut e = env();
    e.interactive = true;
    e.gssapi_key_exchange = true;
    let step = remote_step(StageInput::Inspect, &plan, &home(), TOKEN, 1, None, &e).unwrap();
    assert_eq!(step.pins.narrowing.0[0].value, "no");
    let last = step.pins.host_trust.0.last().unwrap();
    assert_eq!(
        (last.key.as_str(), last.value.as_str()),
        ("GSSAPIKeyExchange", "no")
    );
    // Refusals.
    let refuse = |p: &EnrollmentPlan, stage: StageInput<'_>, token: &str, na: Option<i64>| {
        remote_step(stage, p, &home(), token, 1, na, &env()).unwrap_err()
    };
    let mut p = plan.clone();
    p.host_trust.remove(2);
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::TrustPins
    );
    let mut p = plan.clone();
    p.host_trust[6] = "StrictHostKeyChecking=accept-new".into();
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::TrustPins
    );
    let mut p = plan.clone();
    p.host_trust[4] = "HostKeyAlgorithms=ssh-rsa".into();
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::TrustPins
    );
    let mut p = plan.clone();
    p.existing_access.invocation[1] = "IdentityAgent=SSH_AUTH_SOCK".into();
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::Invocation
    );
    let mut p = plan.clone();
    p.existing_access.invocation.truncate(10);
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::Invocation
    );
    let mut p = plan.clone();
    p.alias = "-oProxyCommand=sh".into();
    assert_eq!(
        refuse(&p, StageInput::Inspect, TOKEN, None),
        StepError::Alias
    );
    assert_eq!(
        refuse(&plan, StageInput::Inspect, "XYZ", None),
        StepError::Token
    );
    assert_eq!(
        refuse(&plan, StageInput::Inspect, TOKEN, Some(NA)),
        StepError::NotAfter
    );
    assert_eq!(
        refuse(&plan, StageInput::Append, TOKEN, None),
        StepError::NotAfter
    );
    let mut e = env();
    e.client = "ssh";
    assert_eq!(
        remote_step(StageInput::Inspect, &plan, &home(), TOKEN, 1, None, &e).unwrap_err(),
        StepError::Client
    );
}

/// m03-plan U5: the host-trust pins are every row of D5 §6.3's table, in order, with
/// the documented values; the table's access and route rows are in the step's other
/// pin groups.
#[test]
fn trust_pins_match_documented_table() {
    let plan = good_plan();
    let files = trust_files();
    let tag = &files.tag;
    let table: [(&str, String); 10] = [
        ("UserKnownHostsFile", files.user_known_hosts.clone()),
        ("GlobalKnownHostsFile", files.global_known_hosts.clone()),
        ("KnownHostsCommand", "none".into()),
        ("VerifyHostKeyDNS", "no".into()),
        ("HostKeyAlgorithms", "ssh-ed25519".into()),
        ("HostKeyAlias", format!("hm-target-{tag}")),
        ("StrictHostKeyChecking", "yes".into()),
        ("CheckHostIP", "no".into()),
        ("UpdateHostKeys", "no".into()),
        ("NoHostAuthenticationForLocalhost", "no".into()),
    ];
    let pins = trust_pins(&plan.approved_target, &files).unwrap();
    let want: Vec<(String, String)> = table
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    assert_eq!(pins, want);
    assert_eq!(plan.host_trust, step::render_pairs(&pins));
    let step = remote_step(StageInput::Inspect, &plan, &home(), TOKEN, 1, None, &env()).unwrap();
    let has = |list: &[heimdall_contract::enrollment::SshOption], k: &str, v: &str| {
        list.iter().any(|o| o.key == k && o.value == v)
    };
    for (k, v) in [("ControlMaster", "no"), ("ControlPath", "none")] {
        assert!(has(&step.pins.existing_access.0, k, v), "{k}");
    }
    for (k, v) in [
        ("ProxyCommand", "none"),
        ("ProxyJump", "none"),
        ("CanonicalizeHostname", "no"),
    ] {
        assert!(has(&step.pins.target.0, k, v), "{k}");
    }
    // HostKeyAlgorithms is exactly the approved key's: RSA's two SHA-2 names.
    for (kind, algorithms) in [
        ("ssh-rsa", "rsa-sha2-512,rsa-sha2-256"),
        ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
        ("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"),
        ("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"),
    ] {
        let mut t = plan.approved_target.clone();
        t.host_key.algorithm = kind.into();
        assert_eq!(trust_pins(&t, &files).unwrap()[4].1, algorithms);
    }
    for kind in [
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-dss",
        "sk-ssh-ed25519@openssh.com",
    ] {
        let mut t = plan.approved_target.clone();
        t.host_key.algorithm = kind.into();
        assert_eq!(
            trust_pins(&t, &files),
            Err(StepError::HostKeyType),
            "{kind}"
        );
    }
    let mut bad = files.clone();
    bad.tag = "XYZ".into();
    assert_eq!(
        trust_pins(&plan.approved_target, &bad),
        Err(StepError::Literal)
    );
    let mut bad = files.clone();
    bad.user_known_hosts = "relative/known_hosts".into();
    assert_eq!(
        trust_pins(&plan.approved_target, &bad),
        Err(StepError::Literal)
    );
    let mut bad = files;
    bad.global_known_hosts = "/tmp/a%h/empty".into();
    assert_eq!(
        trust_pins(&plan.approved_target, &bad),
        Err(StepError::Literal)
    );
}

/// `ssh -G` as OpenSSH_10.5p1 prints the step's pins (observed on the build host:
/// `none` options are absent, some flags print `true`/`false`).
fn ssh_g(step: &RemoteStep) -> String {
    let tag = trust_tag(&enrollment_id());
    let _ = step;
    format!(
        "user deploy\nhostname lab.example.invalid\nport 22\nbatchmode yes\ncanonicalizehostname false\n\
         checkhostip no\ncontrolmaster false\nclearallforwardings yes\nidentitiesonly yes\n\
         nohostauthenticationforlocalhost no\npermitlocalcommand no\nrequesttty false\n\
         forkafterauthentication no\nstricthostkeychecking true\nverifyhostkeydns false\n\
         updatehostkeys false\nhostkeyalgorithms ssh-ed25519\nhostkeyalias hm-target-{tag}\n\
         certificatefile none\nglobalknownhostsfile {RUNTIME}/e/{tag}/global_known_hosts\n\
         userknownhostsfile {RUNTIME}/e/{tag}/known_hosts\nidentityagent {AGENT}\nforwardagent no\n"
    )
}

/// The effective-configuration check (D5 §6.3; `host_trust_unpinnable`), with the
/// Q23 default for `gssapikeyexchange`.
#[test]
fn check_effective_requires_every_trust_pin_and_the_q23_default() {
    let plan = good_plan();
    let step = remote_step(StageInput::Inspect, &plan, &home(), TOKEN, 1, None, &env()).unwrap();
    let out = ssh_g(&step);
    assert_eq!(check_effective(&out, &step.pins), Ok(()));
    let bad = |from: &str, to: &str, option: &str, kind: UnpinnableKind| {
        let changed = out.replace(from, to);
        assert_ne!(changed, out, "{from}");
        let e = check_effective(&changed, &step.pins).unwrap_err();
        assert_eq!(
            (e.option.as_str(), e.kind),
            (option, kind),
            "{from} -> {to}"
        );
    };
    bad(
        "stricthostkeychecking true",
        "stricthostkeychecking ask",
        "stricthostkeychecking",
        UnpinnableKind::Mismatch,
    );
    bad(
        "checkhostip no",
        "checkhostip yes",
        "checkhostip",
        UnpinnableKind::Mismatch,
    );
    bad(
        "updatehostkeys false",
        "updatehostkeys ask",
        "updatehostkeys",
        UnpinnableKind::Mismatch,
    );
    bad(
        "verifyhostkeydns false",
        "verifyhostkeydns true",
        "verifyhostkeydns",
        UnpinnableKind::Mismatch,
    );
    bad(
        "nohostauthenticationforlocalhost no",
        "nohostauthenticationforlocalhost yes",
        "nohostauthenticationforlocalhost",
        UnpinnableKind::Mismatch,
    );
    bad(
        "hostkeyalgorithms ssh-ed25519",
        "hostkeyalgorithms ssh-ed25519,ssh-rsa",
        "hostkeyalgorithms",
        UnpinnableKind::Mismatch,
    );
    bad(
        "hostname lab.example.invalid",
        "hostname evil.invalid",
        "hostname",
        UnpinnableKind::Mismatch,
    );
    bad(
        "controlmaster false",
        "controlmaster auto",
        "controlmaster",
        UnpinnableKind::Mismatch,
    );
    bad(
        "forwardagent no\n",
        "forwardagent no\nknownhostscommand /usr/bin/printkey %H\n",
        "knownhostscommand",
        UnpinnableKind::Mismatch,
    );
    bad(
        "forwardagent no\n",
        "forwardagent no\nproxycommand nc %h %p\n",
        "proxycommand",
        UnpinnableKind::Mismatch,
    );
    bad(
        "forwardagent no\n",
        "forwardagent no\ncontrolpath /tmp/mux\n",
        "controlpath",
        UnpinnableKind::Mismatch,
    );
    bad(
        "userknownhostsfile ",
        "userknownhostsfile ~/.ssh/known_hosts ",
        "userknownhostsfile",
        UnpinnableKind::Mismatch,
    );
    bad(
        "canonicalizehostname false\n",
        "",
        "canonicalizehostname",
        UnpinnableKind::Missing,
    );
    bad(
        "port 22\n",
        "port 22\nport 23\n",
        "port",
        UnpinnableKind::Repeated,
    );
    // Q23: a client that lists gssapikeyexchange needs the pin, and then `no`.
    let with_gss = format!("{out}gssapikeyexchange yes\n");
    assert_eq!(
        check_effective(&with_gss, &step.pins).unwrap_err().kind,
        UnpinnableKind::GssapiPinRequired
    );
    assert!(step::client_lists_gssapi_kex(&with_gss));
    assert!(!step::client_lists_gssapi_kex(&out));
    let mut e = env();
    e.gssapi_key_exchange = true;
    let gss = remote_step(StageInput::Inspect, &plan, &home(), TOKEN, 1, None, &e).unwrap();
    assert_eq!(
        check_effective(&with_gss, &gss.pins).unwrap_err().kind,
        UnpinnableKind::Mismatch
    );
    assert_eq!(
        check_effective(&format!("{out}gssapikeyexchange no\n"), &gss.pins),
        Ok(())
    );
}

// --- HM1 and the step classification ------------------------------------------------------

fn result(exit_status: i32, stdout: &str) -> StepResult {
    StepResult {
        exit_status,
        stdout: stdout.to_owned(),
        stderr_excerpt: String::new(),
    }
}

/// The parser's bounds and handshake lines (D5 §6.3): 512 KiB, `HM1 ready` first,
/// `HM1 v=1` second, and every cut of a valid output is refused or reads a prefix of
/// its fields, never a shortened value.
#[test]
fn hm1_parse_bounds_ready_and_version_lines() {
    let head = "HM1 ready\nHM1 v=1\nHM1 content_hex=";
    let fill = MAX_STDOUT_BYTES - head.len() - 1;
    let exact = format!("{head}{}\n", "0".repeat(fill - fill % 2));
    assert!(exact.len() <= MAX_STDOUT_BYTES);
    let mut over = exact.clone();
    while over.len() <= MAX_STDOUT_BYTES {
        over.insert_str(head.len(), "00");
    }
    assert_eq!(hm1::parse(over.as_bytes()), Err(ParseError::TooLarge));
    assert_eq!(
        hm1::parse(b"Welcome!\nHM1 ready\nHM1 v=1\n"),
        Err(ParseError::NoReadyLine)
    );
    assert_eq!(
        hm1::parse(b"HM1 ready\r\nHM1 v=1\n"),
        Err(ParseError::NoReadyLine)
    );
    assert_eq!(
        hm1::parse(b"HM1 ready\nHM1 v=01\n"),
        Err(ParseError::NoVersionLine)
    );
    assert_eq!(hm1::handshake(b"motd\n"), Handshake::NoReady);

    let full = "HM1 ready\nHM1 v=1\nHM1 path_hex=2f61\nHM1 remote_now=1700000000\nHM1 content_hex=0a41\nHM1 status=ok\n";
    let all = hm1::parse(full.as_bytes()).unwrap();
    for cut in 0..full.len() {
        let prefix = &full.as_bytes()[..cut];
        match hm1::parse(prefix) {
            Ok(rec) => {
                assert!(prefix.ends_with(b"\n"), "a cut line was accepted at {cut}");
                assert_eq!(rec.fields[..], all.fields[..rec.fields.len()]);
            }
            Err(e) => assert!(
                matches!(
                    e,
                    ParseError::NoReadyLine
                        | ParseError::NoVersionLine
                        | ParseError::Malformed { .. }
                ),
                "{e:?}"
            ),
        }
    }
    assert_eq!(all.get(Hm1Key::Status), Some("ok"));
}

/// m03-plan U5: exit 255 without `HM1 v=1` is `NotApplied` for inspect and fence and
/// `Uncertain` for bootstrap, append and remove; a run without `HM1 ready` sent no
/// script and is `NotApplied` for every stage.
#[test]
fn classify_exit_255_and_ready_rules_every_stage() {
    let stages = [
        RemoteStage::Inspect,
        RemoteStage::Bootstrap,
        RemoteStage::Append,
        RemoteStage::Remove,
        RemoteStage::Fence,
    ];
    let mutating = |s: RemoteStage| {
        matches!(
            s,
            RemoteStage::Bootstrap | RemoteStage::Append | RemoteStage::Remove
        )
    };
    let e = Expected::default();
    for stage in stages {
        for status in [255, 1, 0, -1, 137] {
            assert_eq!(
                classify_step(stage, &result(status, "Last login: x\nHM1 ready\n"), &e),
                StepClass::NotApplied(NotAppliedReason::Refused),
                "{stage:?} {status}"
            );
        }
        let ready_255 = classify_step(stage, &result(255, "HM1 ready\n"), &e);
        let want = if mutating(stage) {
            StepClass::Uncertain
        } else {
            StepClass::NotApplied(NotAppliedReason::Refused)
        };
        assert_eq!(ready_255, want, "{stage:?}");
        // A killed client (no remote exit) is treated like 255.
        assert_eq!(
            classify_step(stage, &result(-1, "HM1 ready\n"), &e),
            want,
            "{stage:?}"
        );
        // The remote shell completed without the version line: nothing ran.
        assert_eq!(
            classify_step(stage, &result(2, "HM1 ready\nsh: syntax error\n"), &e),
            StepClass::NotApplied(NotAppliedReason::Refused),
            "{stage:?}"
        );
        // After the version line, a dropped connection.
        let cut = classify_step(
            stage,
            &result(255, "HM1 ready\nHM1 v=1\nHM1 path_hex=2f"),
            &e,
        );
        let want_cut = if stage == RemoteStage::Inspect {
            StepClass::NotApplied(NotAppliedReason::Refused)
        } else {
            StepClass::Uncertain
        };
        assert_eq!(cut, want_cut, "{stage:?}");
    }
    let mut hk = result(255, "");
    hk.stderr_excerpt = "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@".into();
    assert_eq!(
        classify_step(RemoteStage::Append, &hk, &e),
        StepClass::HostTrustChanged
    );
    hk.stderr_excerpt = "sign_and_send_pubkey: signing failed: agent refused operation".into();
    assert_eq!(
        classify_step(RemoteStage::Append, &hk, &e),
        StepClass::ProviderLocked
    );
    hk.stderr_excerpt = "read_passphrase: can't open /dev/tty".into();
    assert_eq!(
        classify_step(RemoteStage::Inspect, &hk, &e),
        StepClass::InteractionRequired
    );
    // A remote that prints the host-key text after the ready line decides nothing.
    let mut late = result(255, "HM1 ready\n");
    late.stderr_excerpt = "Host key verification failed.".into();
    assert_eq!(
        classify_step(RemoteStage::Append, &late, &e),
        StepClass::Uncertain
    );
}

/// Every documented exit code of every stage classifies as the D5 §6.3 table says,
/// and `Confirmed` needs the post-write check.
#[test]
fn classify_documented_exit_codes_per_stage() {
    let ours = our_line();
    let m = marker();
    let pre = b"a\n".to_vec();
    let post_append = format!("a\n{ours}\n");
    let expected = Expected {
        marker: m.clone(),
        line: Some(ours.clone()),
        preimage: Some(pre.clone()),
        post_image: Some(pre.clone()),
        ..Expected::default()
    };
    let hex = |s: &str| hm1::encode_hex(s.as_bytes());
    let out = |body: &str| {
        format!("HM1 ready\nHM1 v=1\nHM1 path_hex=2f61\nHM1 remote_now=1700000000\n{body}")
    };
    let inspect_ok = out(&format!(
        "HM1 dir=present\nHM1 file=regular\nHM1 size=2\nHM1 marker_lines=0\nHM1 content_hex={}\nHM1 lock=none\nHM1 status=ok\n",
        hex("a\n")
    ));
    use NotAppliedReason as R;
    use RemoteStage as S;
    use StepClass as C;
    let rows: Vec<(S, i32, String, C)> = vec![
        (S::Inspect, 0, inspect_ok.clone(), C::Confirmed),
        (
            S::Inspect,
            0,
            out("HM1 dir=present\nHM1 status=ok\n"),
            C::NotApplied(R::Refused),
        ),
        (
            S::Inspect,
            30,
            out("HM1 reason=registry_symlink\n"),
            C::NotApplied(R::Refused),
        ),
        (
            S::Inspect,
            31,
            out("HM1 status=too_large\n"),
            C::NotApplied(R::TooLarge),
        ),
        (
            S::Bootstrap,
            0,
            out(
                "HM1 dir=present\nHM1 dir_mode=drwx------\nHM1 dir_owner_self=yes\nHM1 status=created\n",
            ),
            C::Confirmed,
        ),
        (
            S::Bootstrap,
            11,
            out(
                "HM1 dir=present\nHM1 dir_mode=drwx------\nHM1 dir_owner_self=yes\nHM1 status=already_present\n",
            ),
            C::AlreadyPresent,
        ),
        (
            S::Bootstrap,
            0,
            out("HM1 dir=present\nHM1 dir_mode=drwxr-xr-x\nHM1 status=created\n"),
            C::Uncertain,
        ),
        (
            S::Bootstrap,
            33,
            out("HM1 dir=absent\nHM1 status=parent_absent\n"),
            C::NotApplied(R::ParentAbsent),
        ),
        (
            S::Bootstrap,
            30,
            out("HM1 status=refused\nHM1 reason=parent_symlink\n"),
            C::NotApplied(R::Refused),
        ),
        (S::Bootstrap, 40, out("HM1 status=busy\n"), C::Uncertain),
        (
            S::Append,
            0,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=written\n",
                hex(&post_append)
            )),
            C::Confirmed,
        ),
        (
            S::Append,
            0,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=written\n",
                hex(&format!("{ours}\n"))
            )),
            C::Held,
        ),
        (S::Append, 0, out("HM1 status=written\n"), C::Uncertain),
        (
            S::Append,
            10,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=already_present\n",
                hex(&post_append)
            )),
            C::AlreadyPresent,
        ),
        (
            S::Append,
            10,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=already_present\n",
                hex(&format!("{ours} \n"))
            )),
            C::Held,
        ),
        (
            S::Append,
            10,
            out("HM1 status=already_present\n"),
            C::Uncertain,
        ),
        (
            S::Append,
            30,
            out("HM1 status=refused\nHM1 reason=registry_hardlinked\n"),
            C::NotApplied(R::Refused),
        ),
        (
            S::Append,
            30,
            out("HM1 status=refused\nHM1 reason=write_failed\n"),
            C::Uncertain,
        ),
        (
            S::Append,
            31,
            out("HM1 status=too_large\n"),
            C::NotApplied(R::TooLarge),
        ),
        (
            S::Append,
            32,
            out("HM1 status=dir_absent\n"),
            C::NotApplied(R::DirAbsent),
        ),
        (
            S::Append,
            33,
            out("HM1 status=no_process_group\n"),
            C::NotApplied(R::NoProcessGroup),
        ),
        (
            S::Append,
            40,
            out("HM1 lock=held\nHM1 status=busy\n"),
            C::NotApplied(R::Busy),
        ),
        (
            S::Append,
            41,
            out("HM1 status=not_after_passed\n"),
            C::NotApplied(R::NotAfterPassed),
        ),
        (
            S::Append,
            42,
            out("HM1 status=lock_lost\n"),
            C::NotApplied(R::LockLost),
        ),
        (
            S::Append,
            20,
            out("HM1 status=changed_since_read\n"),
            C::Uncertain,
        ),
        (S::Append, 7, out("HM1 status=ok\n"), C::Uncertain),
        (
            S::Remove,
            0,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=renamed\n",
                hex("a\n")
            )),
            C::Confirmed,
        ),
        (
            S::Remove,
            0,
            out(&format!(
                "HM1 content_hex={}\nHM1 status=renamed\n",
                hex(&post_append)
            )),
            C::Held,
        ),
        (
            S::Remove,
            20,
            out("HM1 status=changed_since_read\n"),
            C::NotApplied(R::ChangedSinceRead),
        ),
        (
            S::Remove,
            30,
            out("HM1 status=refused\nHM1 reason=decode_failed\n"),
            C::NotApplied(R::Refused),
        ),
        (
            S::Remove,
            40,
            out("HM1 status=busy\n"),
            C::NotApplied(R::Busy),
        ),
        (
            S::Remove,
            41,
            out("HM1 status=not_after_passed\n"),
            C::NotApplied(R::NotAfterPassed),
        ),
        (
            S::Remove,
            42,
            out("HM1 status=lock_lost\n"),
            C::NotApplied(R::LockLost),
        ),
        (
            S::Remove,
            10,
            out("HM1 status=already_present\n"),
            C::Uncertain,
        ),
        (
            S::Fence,
            0,
            out("HM1 lock=none\nHM1 fence=none\nHM1 fence_signals=\nHM1 status=none\n"),
            C::Confirmed,
        ),
        (
            S::Fence,
            0,
            out(
                "HM1 fence=alive\nHM1 fence=alive\nHM1 fence=gone\nHM1 fence_signals=TERM,KILL\nHM1 status=gone\n",
            ),
            C::Confirmed,
        ),
        (
            S::Fence,
            43,
            out("HM1 fence=alive\nHM1 fence_signals=\nHM1 status=alive\n"),
            C::NotApplied(R::Busy),
        ),
        (
            S::Fence,
            43,
            out("HM1 fence=alive\nHM1 fence_signals=TERM,KILL\nHM1 status=alive\n"),
            C::Uncertain,
        ),
        (
            S::Fence,
            44,
            out("HM1 fence=unproven\nHM1 fence_signals=\nHM1 status=unproven\n"),
            C::NotApplied(R::Busy),
        ),
        (
            S::Fence,
            44,
            out(
                "HM1 fence=alive\nHM1 fence=unproven\nHM1 fence_signals=TERM\nHM1 status=unproven\n",
            ),
            C::Uncertain,
        ),
        (
            S::Fence,
            40,
            out(
                "HM1 lock=held\nHM1 fence_signals=\nHM1 status=busy\nHM1 reason=lock_other_token\n",
            ),
            C::NotApplied(R::Busy),
        ),
        (
            S::Fence,
            0,
            out("HM1 fence=unproven\nHM1 fence_signals=\nHM1 status=gone\n"),
            C::NotApplied(R::Refused),
        ),
        (
            S::Fence,
            33,
            out("HM1 status=no_process_group\n"),
            C::NotApplied(R::NoProcessGroup),
        ),
    ];
    for (stage, status, stdout, want) in rows {
        let got = classify_step(stage, &result(status, &stdout), &expected);
        assert_eq!(got, want, "{stage:?} exit {status}: {stdout}");
    }
    let rec = hm1::parse(inspect_ok.as_bytes()).unwrap();
    let reading = Inspection::from_record(&rec, &m).unwrap();
    assert_eq!(reading.preimage(), Some(&b"a\n"[..]));
    assert_eq!(reading.remote_now, 1_700_000_000);
    // A script count that disagrees with the content is not a reading.
    let lying = inspect_ok.replace("marker_lines=0", "marker_lines=1");
    let rec = hm1::parse(lying.as_bytes()).unwrap();
    assert!(Inspection::from_record(&rec, &m).is_err());
    assert_eq!(
        classify_step(S::Inspect, &result(0, &lying), &expected),
        C::NotApplied(R::Refused)
    );
}
