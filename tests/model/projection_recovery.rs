//! The pure recovery function and the recovery state (M02-W2-U4b; m02-plan U4;
//! ADR-0007 §5.7 "The recovery state", "Normalization", "The table is checked without
//! its row list", "The properties are stated over concrete effects"; §12.8 item 1,
//! §12.11 items 4 and 5, §12.14 items 1 and 2; M2-S01, M2-T04, M2-T05).
//!
//! Cargo test target `model_projection_recovery` hosted by `heimdall-localenv`. No
//! file is touched and no clock is read: receipt histories go through
//! `RecoveryState::build`, observations through `StepObservation::normalize`, and the
//! results through `recovery::decide`, `decide_item` and `effects`. The
//! filesystem-backed `recovery_generated_observations_preserve_every_entry` and the
//! `reconcile` halves of the M2-T04 cases are W2-U4c's (`tests/integration/
//! projection.rs`). Identities, digests and paths are synthetic constants.
//!
//! The generated domain is built from the type definitions and a restatement of the
//! ADR's phase order, never from the row list; its assertions read the effects of a
//! decision, never its name. The row list is checked in the other direction by
//! `recovery_table_rows_each_have_a_test_vector` (W2b-U4r, ADR-0007 §12.17 item 8),
//! which reads ADR-0007 §5.7's own tables: the row list must be the ADR's, every row
//! needs a vector, and each vector must be the first case its row's phase and symbol
//! columns name, with a decision that agrees with the row's action. Properties use
//! proptest with at least 256 cases, a fixed seed unless `PROPTEST_RNG_SEED` is set,
//! and failures persisted beside this file. The coverage reports are printed (`--nocapture` shows them).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::collections::{BTreeMap, HashSet};

use heimdall_contract::Timestamp;
use heimdall_contract::setup::{ConflictKind, ProjectionItem};
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt,
    ObservedEntry, ObservedName, ObservedNameRole, PostVerdict, RestoreCause, SettleConflictFound,
    SettleSource, SettledDisposition, StageReceipt,
};
use heimdall_domain::projection::{
    Base, ContentState, Contradictory, EffectivePhase, EntryObs, FileIdentity, FileRole, FileStep,
    Impossible, ItemState, RecordedRole, RecoveryState, RestoreCtx, SettleCtx, Sha256Hex,
    StepContent, StepObservation, StepShape, Target,
};
use heimdall_localenv::projection::recovery::{
    AbortStep, Effect, ForwardStep, ItemDecision, ItemReceipts, Name, RestoreStep, SettleStep,
    StepDecision, StepState, decide, decide_item, effects,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

fn config(cases: u32) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(0x4d32_5434_5245_4356);
    }
    c
}

// --- symbols ------------------------------------------------------------------------

const fn rec(which: RecordedRole, content: ContentState) -> EntryObs {
    EntryObs::Recorded { which, content }
}

/// ∅.
const A: EntryObs = EntryObs::Absent;
/// X.
const X: EntryObs = EntryObs::Foreign;
/// ?.
const U: EntryObs = EntryObs::Unobservable;
const S: EntryObs = rec(RecordedRole::S, ContentState::Unchanged);
const SM: EntryObs = rec(RecordedRole::S, ContentState::Modified);
const V: EntryObs = rec(RecordedRole::V, ContentState::Unchanged);
const VM: EntryObs = rec(RecordedRole::V, ContentState::Modified);
const D: EntryObs = rec(RecordedRole::D, ContentState::Unchanged);
const DM: EntryObs = rec(RecordedRole::D, ContentState::Modified);
const Q: EntryObs = rec(RecordedRole::Q, ContentState::Unchanged);
const QM: EntryObs = rec(RecordedRole::Q, ContentState::Modified);

/// The whole `EntryObs` alphabet: every variant, every role and content.
const SYMBOLS: [EntryObs; 11] = [A, S, SM, V, VM, D, DM, Q, QM, X, U];

const SHAPES: [StepShape; 4] = [
    StepShape::Replace,
    StepShape::Create,
    StepShape::GitLock,
    StepShape::Removal,
];

// --- fixtures -----------------------------------------------------------------------

fn identity(ino: u64) -> FileIdentity {
    FileIdentity::Unix {
        dev: 9,
        ino,
        birth: Some(1_000 + i128::from(ino)),
    }
}

fn digest(tag: &str) -> Sha256Hex {
    Sha256Hex::of(tag.as_bytes())
}

/// A file step of `role`; `build` reads only its role, base and target.
fn file_step(role: FileRole, base: bool, target: bool, commit: bool) -> FileStep {
    FileStep {
        role,
        path: format!("/scratch/{}", role.as_str()),
        base: if base {
            Base::Present {
                sha256: digest("base"),
            }
        } else {
            Base::Absent
        },
        target: if target {
            Target::Present {
                sha256: digest("target"),
            }
        } else {
            Target::Absent
        },
        content: StepContent::absent(),
        commit,
        staged_name: Some(format!(".{}.hm-2-00", role.as_str())),
        displaced_name: None,
    }
}

/// The intent whose step 0 has `shape` (for `git_lock`, step 1 is its B_git sibling).
fn intent(shape: StepShape) -> Vec<FileStep> {
    match shape {
        StepShape::Replace => vec![file_step(FileRole::UserSsh, true, true, true)],
        StepShape::Create => vec![file_step(FileRole::ManagedSsh, false, true, false)],
        StepShape::GitLock => vec![
            file_step(FileRole::GitLock, false, false, false),
            file_step(FileRole::GitInclude, true, true, true),
        ],
        StepShape::Removal => vec![file_step(FileRole::ManagedSsh, true, false, false)],
    }
}

fn item_of(shape: StepShape) -> ProjectionItem {
    if shape == StepShape::GitLock {
        ProjectionItem::Git
    } else {
        ProjectionItem::Ssh
    }
}

/// A phase kind, with the fixed payload [`file_phase`] gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ph {
    St,
    Va,
    VaA,
    Ex,
    PvV,
    PvM,
    RsTc,
    RsFm,
    Rd,
    SgS,
    SgD,
    SgP,
    SdQ,
    SdN,
    Sc,
}

use Ph::{Ex, PvM, PvV, Rd, RsFm, RsTc, Sc, SdN, SdQ, SgD, SgP, SgS, St, Va, VaA};

const ALL_PH: [Ph; 15] = [
    St, Va, VaA, Ex, PvV, PvM, RsTc, RsFm, Rd, SgS, SgD, SgP, SdQ, SdN, Sc,
];

fn file_phase(ph: Ph) -> FilePhase {
    let settling = |source: SettleSource, expected: u64| FilePhase::Settling {
        source,
        name: ".scratch.hm-2-00".into(),
        expected: identity(expected),
        expected_sha256: digest("expected"),
        slot: "slot-00".into(),
    };
    match ph {
        St => FilePhase::Staged {
            identity: identity(11),
        },
        Va => FilePhase::Validated {
            base: Some(identity(22)),
        },
        VaA => FilePhase::Validated { base: None },
        Ex => FilePhase::Exchanged,
        PvV => FilePhase::PostValidated {
            verdict: PostVerdict::Valid,
            observed: None,
        },
        PvM => FilePhase::PostValidated {
            verdict: PostVerdict::Mismatch,
            observed: Some(identity(33)),
        },
        RsTc => FilePhase::RestoreStarted {
            cause: RestoreCause::TransactionCheck,
        },
        RsFm => FilePhase::RestoreStarted {
            cause: RestoreCause::FileMismatch,
        },
        Rd => FilePhase::Restored,
        SgS => settling(SettleSource::Staged, 11),
        SgD => settling(SettleSource::Displaced, 22),
        SgP => settling(SettleSource::Path, 11),
        SdQ => FilePhase::Settled {
            disposition: SettledDisposition::Quarantined,
        },
        SdN => FilePhase::Settled {
            disposition: SettledDisposition::NothingDisplaced,
        },
        Sc => FilePhase::SettleConflict {
            found: SettleConflictFound::Missing,
            kept: Vec::new(),
        },
    }
}

fn effective(ph: Ph) -> EffectivePhase {
    EffectivePhase::try_from(file_phase(ph)).unwrap()
}

/// One receipt of a history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Ev {
    /// A file receipt of step `.0`.
    F(u16, Ph),
    /// `item.committed`.
    C(ProjectionItem),
    /// `item.rolling_back`.
    R(ProjectionItem),
    /// `item.finished`.
    Fin(ProjectionItem, ItemFinish),
    /// `file.held` of step `.0`.
    H(u16),
}

use Ev::{C, F, Fin, H, R};

const SSH: ProjectionItem = ProjectionItem::Ssh;
const GIT: ProjectionItem = ProjectionItem::Git;

const OUTCOMES: [ItemFinish; 4] = [
    ItemFinish::Applied,
    ItemFinish::NotApplied,
    ItemFinish::Restored,
    ItemFinish::ConflictPreserved,
];

fn local(ev: Ev) -> LocalReceipt {
    match ev {
        F(step, ph) => LocalReceipt::File {
            step,
            phase: file_phase(ph),
        },
        H(step) => LocalReceipt::File {
            step,
            phase: FilePhase::Held {
                reason: HoldReason::Unmatched,
                observed: vec![ObservedName {
                    name: ObservedNameRole::Path,
                    entry: ObservedEntry::Foreign { identity: None },
                }],
            },
        },
        C(item) => LocalReceipt::Item {
            item,
            phase: ItemPhase::Committed { generation: 2 },
        },
        R(item) => LocalReceipt::Item {
            item,
            phase: ItemPhase::RollingBack {
                reason: ConflictKind::UserConfigChanged,
            },
        },
        Fin(item, outcome) => LocalReceipt::Item {
            item,
            phase: ItemPhase::Finished { outcome },
        },
    }
}

/// The stage receipts of `events`, as the sink writes them (M01 effect fixed by the
/// phase), preceded by one M01 receipt without a local payload, which `build` skips.
fn receipts(events: &[Ev]) -> Vec<StageReceipt> {
    let at: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
    let adapter = AdapterIdentity {
        mechanism: "config_projection".into(),
        instance: "env_fixture".into(),
    };
    let mut out = vec![StageReceipt {
        stage: "prepare".into(),
        recorded_at: at,
        effect: EffectReceipt::NotAttempted,
        local: None,
    }];
    out.extend(events.iter().map(|ev| {
        let local = local(*ev);
        let effect = if local.effect_is_confirmed() {
            EffectReceipt::Confirmed {
                adapter: adapter.clone(),
                credential_ref: "projection/fixture".into(),
            }
        } else {
            EffectReceipt::Attempted {
                adapter: adapter.clone(),
                effect_token: "eff_fixture".into(),
            }
        };
        StageReceipt {
            stage: local.stage().into(),
            recorded_at: at,
            effect,
            local: Some(local),
        }
    }));
    out
}

fn build(shape: StepShape, events: &[Ev]) -> Result<RecoveryState, Contradictory> {
    RecoveryState::build(0, &receipts(events), &intent(shape))
}

fn observe(
    shape: StepShape,
    state: &RecoveryState,
    [p, a, s]: [EntryObs; 3],
) -> Result<StepObservation, Impossible> {
    StepObservation::normalize(p, a, s, state, shape)
}

// --- the phase order, restated from ADR-0007 §5.7 "The recovery state" ---------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    Any,
    /// `item.committed` is on record.
    Committed,
    /// `item.rolling_back` is on record.
    RollingBack,
    /// The step's settlement is a create's restore (`settling{path}`).
    CreateRestore,
}

type Edge = (Option<Ph>, Ph, Cond);

const REPLACE_ORDER: &[Edge] = &[
    (None, St, Cond::Any),
    (Some(St), Va, Cond::Any),
    (Some(St), SgS, Cond::Any),
    (Some(St), Sc, Cond::Any),
    (Some(Va), Ex, Cond::Any),
    (Some(Va), SgS, Cond::Any),
    (Some(Va), Sc, Cond::Any),
    (Some(Ex), PvV, Cond::Any),
    (Some(Ex), PvM, Cond::Any),
    (Some(PvV), SgD, Cond::Committed),
    (Some(PvV), Sc, Cond::Committed),
    (Some(PvV), RsTc, Cond::RollingBack),
    (Some(PvM), RsFm, Cond::Any),
    (Some(RsTc), Rd, Cond::Any),
    (Some(RsFm), Rd, Cond::Any),
    (Some(Rd), SgS, Cond::Any),
    (Some(Rd), Sc, Cond::Any),
    (Some(SgS), SdQ, Cond::Any),
    (Some(SgS), Sc, Cond::Any),
    (Some(SgD), SdQ, Cond::Any),
    (Some(SgD), Sc, Cond::Any),
    (Some(SdQ), Sc, Cond::Any),
];

const CREATE_ORDER: &[Edge] = &[
    (None, St, Cond::Any),
    (Some(St), VaA, Cond::Any),
    (Some(St), SgS, Cond::Any),
    (Some(St), Sc, Cond::Any),
    (Some(VaA), Ex, Cond::Any),
    (Some(VaA), SgS, Cond::Any),
    (Some(VaA), Sc, Cond::Any),
    (Some(Ex), PvV, Cond::Any),
    (Some(PvV), SdN, Cond::Committed),
    (Some(PvV), RsTc, Cond::RollingBack),
    (Some(RsTc), SgP, Cond::Any),
    (Some(SgP), SdQ, Cond::Any),
    (Some(SgP), Sc, Cond::Any),
    (Some(SgS), SdQ, Cond::Any),
    (Some(SgS), Sc, Cond::Any),
    (Some(SdQ), Sc, Cond::Any),
    (Some(SdQ), Rd, Cond::CreateRestore),
    (Some(Sc), Rd, Cond::CreateRestore),
];

const GIT_LOCK_ORDER: &[Edge] = &[
    (None, St, Cond::Any),
    (Some(St), SgS, Cond::Any),
    (Some(St), SgP, Cond::Any),
    (Some(St), Sc, Cond::Any),
    (Some(SgS), SdQ, Cond::Any),
    (Some(SgS), Sc, Cond::Any),
    (Some(SgP), SdQ, Cond::Any),
    (Some(SgP), Sc, Cond::Any),
    (Some(SdQ), Sc, Cond::Any),
];

fn order(shape: StepShape) -> &'static [Edge] {
    match shape {
        StepShape::Replace => REPLACE_ORDER,
        StepShape::Create => CREATE_ORDER,
        StepShape::GitLock => GIT_LOCK_ORDER,
        StepShape::Removal => &[],
    }
}

/// Every phase sequence the shape's order allows, from the empty one to its full
/// length (the conditions are left to the item receipts).
fn sequences(shape: StepShape) -> Vec<Vec<Ph>> {
    let mut out = vec![Vec::new()];
    let mut stack = vec![Vec::new()];
    while let Some(seq) = stack.pop() {
        let last = seq.last().copied();
        for &(from, to, _) in order(shape) {
            if from == last {
                let mut next = seq.clone();
                next.push(to);
                out.push(next.clone());
                stack.push(next);
            }
        }
    }
    out
}

/// Whether the history of step 0 is consistent: the oracle `build` is checked against.
fn consistent(shape: StepShape, events: &[Ev]) -> bool {
    let item = item_of(shape);
    let (mut committed, mut rolling_back, mut finished) = (false, false, false);
    let mut last: Option<Ph> = None;
    let mut create_restore = false;
    for ev in events {
        match *ev {
            H(_) => {}
            C(i) | R(i) if i == item => {
                if finished || committed || rolling_back {
                    return false;
                }
                if matches!(ev, C(_)) {
                    committed = true;
                } else {
                    rolling_back = true;
                }
            }
            Fin(i, outcome) if i == item => {
                let ok = match outcome {
                    ItemFinish::Applied => committed,
                    ItemFinish::NotApplied => !committed && !rolling_back,
                    _ => !committed,
                };
                if finished || !ok {
                    return false;
                }
                finished = true;
            }
            C(_) | R(_) | Fin(..) => {}
            F(step, _) if step != 0 => {}
            F(_, ph) => {
                if finished {
                    return false;
                }
                let edge = order(shape).iter().find(|(from, to, cond)| {
                    *from == last
                        && *to == ph
                        && match cond {
                            Cond::Any => true,
                            Cond::Committed => committed,
                            Cond::RollingBack => rolling_back,
                            Cond::CreateRestore => create_restore,
                        }
                });
                if edge.is_none() {
                    return false;
                }
                create_restore |= ph == SgP && shape == StepShape::Create;
                last = Some(ph);
            }
        }
    }
    true
}

/// The state a consistent history must build to (the derivation rules of ADR-0007
/// §5.7 "The recovery state", restated).
fn expected(shape: StepShape, events: &[Ev], sibling_final: bool) -> RecoveryState {
    let item = item_of(shape);
    let (mut committed, mut rolling_back, mut finished) = (false, false, false);
    let mut last = None;
    let mut started = None;
    let mut restored = false;
    let mut settlement = None;
    for ev in events {
        match *ev {
            F(0, ph) => {
                last = Some(ph);
                match ph {
                    RsTc => started = Some(RestoreCause::TransactionCheck),
                    RsFm => started = Some(RestoreCause::FileMismatch),
                    Rd => restored = true,
                    SgS | SgD | SgP => {
                        let source = match ph {
                            SgS => SettleSource::Staged,
                            SgD => SettleSource::Displaced,
                            _ => SettleSource::Path,
                        };
                        settlement = Some(SettleCtx {
                            source,
                            create_restore: shape == StepShape::Create && ph == SgP,
                        });
                    }
                    _ => {}
                }
            }
            C(i) if i == item => committed = true,
            R(i) if i == item => rolling_back = true,
            Fin(i, _) if i == item => finished = true,
            _ => {}
        }
    }
    let restore = match (started, last) {
        (Some(c), _) if restored => RestoreCtx::Done(c),
        (Some(c), _) => RestoreCtx::Started(c),
        (None, Some(PvM)) => RestoreCtx::Due(RestoreCause::FileMismatch),
        (None, Some(PvV)) if rolling_back => RestoreCtx::Due(RestoreCause::TransactionCheck),
        _ => RestoreCtx::NotDue,
    };
    let item = if finished {
        ItemState::Finished
    } else if committed {
        ItemState::Committed
    } else if rolling_back {
        ItemState::RollingBack
    } else {
        ItemState::Open
    };
    RecoveryState {
        phase: last.map(effective),
        restore,
        settlement,
        item,
        release_due: shape == StepShape::GitLock && sibling_final,
    }
}

/// `events` with `file.held` of step 0 inserted before position `at`.
fn with_held(events: &[Ev], at: usize) -> Vec<Ev> {
    let mut out = events.to_vec();
    out.insert(at, H(0));
    out
}

/// `events` with `file.held` of step 0 between every two receipts and at both ends.
fn held_everywhere(events: &[Ev]) -> Vec<Ev> {
    let mut out = vec![H(0)];
    for ev in events {
        out.push(*ev);
        out.push(H(0));
    }
    out
}

/// The item receipt placements for a sequence of `n` file receipts: committed and
/// rolling_back each absent or before any position, and finished absent, at the end
/// with each outcome, or before any earlier position (with `applied`).
fn item_placements(n: usize, item: ProjectionItem) -> Vec<Vec<(usize, Ev)>> {
    let positions = || (0..=n).map(Some).chain([None]);
    let mut finishes: Vec<Option<(usize, Ev)>> = vec![None];
    finishes.extend(OUTCOMES.iter().map(|o| Some((n, Fin(item, *o)))));
    finishes.extend((0..n).map(|p| Some((p, Fin(item, ItemFinish::Applied)))));
    let mut out = Vec::new();
    for c in positions() {
        for r in positions() {
            for f in &finishes {
                let mut v: Vec<(usize, Ev)> = Vec::new();
                v.extend(c.map(|p| (p, C(item))));
                v.extend(r.map(|p| (p, R(item))));
                v.extend(*f);
                out.push(v);
            }
        }
    }
    out
}

fn interleave(prefix: &[Ev], seq: &[Ph], items: &[(usize, Ev)]) -> Vec<Ev> {
    let mut out = prefix.to_vec();
    for pos in 0..=seq.len() {
        out.extend(items.iter().filter(|(p, _)| *p == pos).map(|(_, ev)| *ev));
        if let Some(ph) = seq.get(pos) {
            out.push(F(0, *ph));
        }
    }
    out
}

/// K's B_git sibling (step 1, a replace): its history, and whether that is final.
const SIBLINGS: [(&[Ph], bool); 4] = [
    (&[], false),
    (&[St], false),
    (&[St, SgS, SdQ], true),
    (&[St, Sc], true),
];

/// One generated history of step 0.
struct Case {
    shape: StepShape,
    events: Vec<Ev>,
    sibling_final: bool,
    /// Insert `held` at every position (else at one position chosen by the case).
    every_position: bool,
}

/// Every generated history (ADR-0007 §5.7 "The table is checked without its row
/// list", first bullet): each shape's phase sequences up to their full length × every
/// item receipt combination and placement (× K's sibling states), plus every sequence
/// over the whole phase alphabet up to length 3, which includes the histories the
/// order refuses.
fn for_each_case(mut f: impl FnMut(&Case)) {
    for shape in SHAPES {
        let item = item_of(shape);
        let siblings: &[(&[Ph], bool)] = if shape == StepShape::GitLock {
            &SIBLINGS
        } else {
            &SIBLINGS[..1]
        };
        for (sibling, sibling_final) in siblings {
            let prefix: Vec<Ev> = sibling.iter().map(|ph| F(1, *ph)).collect();
            for seq in sequences(shape) {
                for (k, items) in item_placements(seq.len(), item).iter().enumerate() {
                    f(&Case {
                        shape,
                        events: interleave(&prefix, &seq, items),
                        sibling_final: *sibling_final,
                        every_position: k == 0,
                    });
                }
            }
        }
        let mut brute: Vec<Vec<Ph>> = vec![Vec::new()];
        for len in 1..=3 {
            let mut next = Vec::new();
            for seq in brute.iter().filter(|s| s.len() == len - 1) {
                for ph in ALL_PH {
                    let mut s = seq.clone();
                    s.push(ph);
                    next.push(s);
                }
            }
            brute.extend(next);
        }
        for seq in brute {
            for items in [vec![], vec![(0, C(item))], vec![(0, R(item))]] {
                f(&Case {
                    shape,
                    events: interleave(&[], &seq, &items),
                    sibling_final: false,
                    every_position: false,
                });
            }
        }
    }
}

/// What the generated histories built to.
#[derive(Default)]
struct Built {
    /// Every distinct state `build` returned.
    states: Vec<RecoveryState>,
    histories: usize,
    contradictory: usize,
}

/// A state's identity in the generated domain (its phase payloads are fixed per kind).
type StateKey = (Option<Ph>, RestoreCtx, Option<SettleCtx>, ItemState, bool);

/// Build every generated history, checking each against the oracle and checking that
/// `held` receipts change nothing; collect the distinct states.
fn build_generated() -> Built {
    let mut built = Built::default();
    let mut seen: HashSet<StateKey> = HashSet::new();
    for_each_case(|case| {
        built.histories += 1;
        let result = build(case.shape, &case.events);
        // `held` is never an effective phase: inserting it anywhere changes nothing.
        let positions: Vec<usize> = if case.every_position {
            (0..=case.events.len()).collect()
        } else {
            vec![built.histories % (case.events.len() + 1)]
        };
        for at in positions {
            assert_eq!(
                build(case.shape, &with_held(&case.events, at)),
                result,
                "held at {at} changed {:?} {:?}",
                case.shape,
                case.events
            );
        }
        assert_eq!(
            build(case.shape, &held_everywhere(&case.events)),
            result,
            "held everywhere changed {:?} {:?}",
            case.shape,
            case.events
        );
        let ok = consistent(case.shape, &case.events);
        match result {
            Ok(state) => {
                assert!(ok, "accepted {:?} {:?}", case.shape, case.events);
                assert_eq!(
                    state,
                    expected(case.shape, &case.events, case.sibling_final),
                    "{:?} {:?}",
                    case.shape,
                    case.events
                );
                let last = case.events.iter().rev().find_map(|ev| match ev {
                    F(0, ph) => Some(*ph),
                    _ => None,
                });
                let key = (
                    last,
                    state.restore,
                    state.settlement,
                    state.item,
                    state.release_due,
                );
                if seen.insert(key) {
                    built.states.push(state);
                }
            }
            Err(Contradictory) => {
                assert!(!ok, "refused {:?} {:?}", case.shape, case.events);
                built.contradictory += 1;
            }
        }
    });
    built
}

// --- the property checker (ADR-0007 §5.7 properties, over concrete effects) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Prop {
    /// Every `?` input is `Hold(Unobservable)`.
    UnobservableHolds,
    /// H performs no effect but a `held` receipt (property 6).
    HoldInert,
    /// `remove_from_slot` only of Q unchanged after `settled`, or of the cleaner's L
    /// unchanged (properties 2, 3).
    RemoveOnlyOwnedUnchanged,
    /// `move_to_slot` only of a recorded entry, never of X or ∅ (properties 2, 3).
    MoveOnlyRecorded,
    /// An X moves only by `put_back` or `keep_as_conflict` (property 3).
    ForeignOnlyPutBack,
    /// `put_back` and `keep_as_conflict` move only an X.
    PutBackOnlyForeign,
    /// `restore_exchange` only with the restore due or started, S unchanged at the
    /// path and D (V, V′ or the mismatch identity) aside (property 4).
    RestoreOnlyOverUnchangedS,
    /// A completed restore exchange is recognized without a move (property 4).
    RecognitionMovesNothing,
    /// The path changes only through the plan (property 5).
    PathOnlyByPlan,
    /// `claim` only from K1 with the lock absent (property 5).
    ClaimOnlyFromK1,
    /// Abort only before the step's exchange, while the item is open (property 7).
    AbortOnlyBeforeExchange,
}

fn is_l(e: EntryObs) -> bool {
    e == V || e == S
}

fn d_or_v(e: EntryObs) -> bool {
    matches!(
        e,
        EntryObs::Recorded {
            which: RecordedRole::D | RecordedRole::V,
            ..
        }
    )
}

fn s_any(e: EntryObs) -> bool {
    matches!(
        e,
        EntryObs::Recorded {
            which: RecordedRole::S,
            ..
        }
    )
}

fn path_move_allowed(shape: StepShape, st: &RecoveryState, obs: &StepObservation) -> bool {
    let p = obs.path();
    let settling_from_path = matches!(st.phase, Some(EffectivePhase::Settling { .. }))
        && st
            .settlement
            .is_some_and(|c| c.source == SettleSource::Path);
    let due = matches!(st.restore, RestoreCtx::Due(_) | RestoreCtx::Started(_));
    match shape {
        // The cleaner's R1, under its locator.
        StepShape::Removal => is_l(p),
        // A create rollback (C7, F8a): S with the target digest, restore due or started.
        StepShape::Create => {
            (due && st.item != ItemState::Committed
                && matches!(
                    st.phase,
                    Some(
                        EffectivePhase::PostValidated { .. }
                            | EffectivePhase::RestoreStarted { .. }
                    )
                )
                && p == S)
                || (settling_from_path && st.settlement.is_some_and(|c| c.create_restore) && p == Q)
        }
        // K's release: a provable K or K′, only from K2 with the release due.
        StepShape::GitLock => {
            (matches!(st.phase, Some(EffectivePhase::Staged { .. }))
                && st.release_due
                && (p == S || p == SM))
                || (settling_from_path && (p == Q || p == QM))
        }
        StepShape::Replace => false,
    }
}

/// The properties `decision` breaks for this cell (empty for a correct table).
fn violations(
    shape: StepShape,
    st: &RecoveryState,
    obs: &StepObservation,
    decision: StepDecision,
) -> Vec<Prop> {
    let eff = effects(decision, shape, st);
    let at = |n: Name| match n {
        Name::Path => obs.path(),
        Name::Aside => obs.aside(),
        Name::Slot => obs.slot(),
    };
    let mut v = Vec::new();
    let phase = st.phase.as_ref();
    if [obs.path(), obs.aside(), obs.slot()].contains(&U)
        && decision != StepDecision::Hold(HoldReason::Unobservable)
    {
        v.push(Prop::UnobservableHolds);
    }
    if matches!(decision, StepDecision::Hold(_))
        && eff.iter().any(|e| *e != Effect::Receipt("held"))
    {
        v.push(Prop::HoldInert);
    }
    for e in &eff {
        match e {
            Effect::Receipt(_) => {}
            Effect::RemoveFromSlot => {
                let ok = if shape == StepShape::Removal {
                    is_l(obs.slot())
                } else {
                    matches!(phase, Some(EffectivePhase::Settled { .. })) && obs.slot() == Q
                };
                if !ok {
                    v.push(Prop::RemoveOnlyOwnedUnchanged);
                }
            }
            Effect::MoveToSlot(n) => {
                let subject = at(*n);
                if subject == X {
                    v.push(Prop::ForeignOnlyPutBack);
                }
                if !matches!(subject, EntryObs::Recorded { .. }) || *n == Name::Slot {
                    v.push(Prop::MoveOnlyRecorded);
                }
                if *n == Name::Path && !path_move_allowed(shape, st, obs) {
                    v.push(Prop::PathOnlyByPlan);
                }
            }
            Effect::ForwardExchange | Effect::ForwardCreate => {
                if obs.path() == X || obs.aside() == X {
                    v.push(Prop::ForeignOnlyPutBack);
                }
                let create = *e == Effect::ForwardCreate;
                let ok = matches!(phase, Some(EffectivePhase::Validated { .. }))
                    && st.item == ItemState::Open
                    && st.restore == RestoreCtx::NotDue
                    && obs.aside() == S
                    && if create {
                        shape == StepShape::Create && obs.path() == A
                    } else {
                        shape == StepShape::Replace && obs.path() == V
                    };
                if !ok {
                    v.push(Prop::PathOnlyByPlan);
                }
            }
            Effect::RestoreExchange => {
                if obs.path() == X || obs.aside() == X {
                    v.push(Prop::ForeignOnlyPutBack);
                }
                let ok = matches!(st.restore, RestoreCtx::Due(_) | RestoreCtx::Started(_))
                    && st.item != ItemState::Committed
                    && obs.path() == S
                    && d_or_v(obs.aside());
                if !ok {
                    v.push(Prop::RestoreOnlyOverUnchangedS);
                }
            }
            Effect::Claim => {
                let ok = shape == StepShape::GitLock
                    && matches!(phase, Some(EffectivePhase::Staged { .. }))
                    && st.item == ItemState::Open
                    && !st.release_due
                    && obs.path() == A
                    && obs.aside() == S;
                if !ok {
                    v.push(Prop::ClaimOnlyFromK1);
                }
            }
            Effect::PutBack(_) => {
                if obs.slot() != X {
                    v.push(Prop::PutBackOnlyForeign);
                }
            }
            Effect::KeepAsConflict(n) => {
                if at(*n) != X {
                    v.push(Prop::PutBackOnlyForeign);
                }
            }
        }
    }
    let recognizing = shape == StepShape::Replace
        && matches!(phase, Some(EffectivePhase::RestoreStarted { .. }))
        && (d_or_v(obs.path()) || obs.path() == X)
        && s_any(obs.aside());
    if recognizing && eff.iter().any(|e| !matches!(e, Effect::Receipt(_))) {
        v.push(Prop::RecognitionMovesNothing);
    }
    if matches!(decision, StepDecision::Abort(_))
        && !(matches!(
            phase,
            None | Some(EffectivePhase::Staged { .. } | EffectivePhase::Validated { .. })
        ) && st.item == ItemState::Open)
    {
        v.push(Prop::AbortOnlyBeforeExchange);
    }
    v
}

/// One normalized cell of the generated domain.
struct Cell {
    shape: StepShape,
    state: usize,
    obs: StepObservation,
}

/// `StepShape` × every built state × path × aside × slot through `normalize`; the
/// rejected cells counted by reason.
fn cells(states: &[RecoveryState]) -> (Vec<Cell>, BTreeMap<String, usize>) {
    let mut out = Vec::new();
    let mut rejected = BTreeMap::new();
    for shape in SHAPES {
        for (i, st) in states.iter().enumerate() {
            for p in SYMBOLS {
                for a in SYMBOLS {
                    for s in SYMBOLS {
                        match observe(shape, st, [p, a, s]) {
                            Ok(obs) => out.push(Cell {
                                shape,
                                state: i,
                                obs,
                            }),
                            Err(why) => *rejected.entry(format!("{why:?}")).or_insert(0) += 1,
                        }
                    }
                }
            }
        }
    }
    (out, rejected)
}

fn decision_kind(d: StepDecision) -> String {
    match d {
        StepDecision::Forward(s) => format!("Forward({s:?})"),
        StepDecision::Restore(s) => format!("Restore({s:?})"),
        StepDecision::Abort(s) => format!("Abort({s:?})"),
        StepDecision::Settle(s) => format!("Settle({s:?})"),
        StepDecision::Hold(r) => format!("Hold({r:?})"),
    }
}

const HOLD_REASONS: [HoldReason; 9] = [
    HoldReason::ActiveEntryReplaced,
    HoldReason::ActiveEntryModified,
    HoldReason::DisplacedMissing,
    HoldReason::DisplacedReplaced,
    HoldReason::ThirdWriter,
    HoldReason::AmbiguousExchange,
    HoldReason::Unobservable,
    HoldReason::Unmatched,
    HoldReason::ContradictoryReceipts,
];

/// Every `StepState`: each unit class, and `Held` with every reason (ADR-0007 §12.17
/// item 4).
fn step_states() -> Vec<StepState> {
    let mut all = vec![
        StepState::Open,
        StepState::CommitNeverExchanged,
        StepState::CommitRestored,
        StepState::ExchangedConsistent,
        StepState::ExchangedInconsistent,
        StepState::Final,
    ];
    all.extend(HOLD_REASONS.iter().map(|r| StepState::Held(*r)));
    all
}

/// Every `decide_item` input: one to three step states × every item receipt combination.
fn item_domain() -> Vec<(Vec<StepState>, ItemReceipts)> {
    let states = step_states();
    let mut lists: Vec<Vec<StepState>> = states.iter().map(|s| vec![*s]).collect();
    for _ in 0..2 {
        let longer: Vec<Vec<StepState>> = lists
            .iter()
            .filter(|l| l.len() == lists.last().map_or(0, Vec::len))
            .flat_map(|l| {
                states.iter().map(move |s| {
                    let mut l = l.clone();
                    l.push(*s);
                    l
                })
            })
            .collect();
        lists.extend(longer);
    }
    let mut out = Vec::new();
    for steps in lists {
        for committed in [false, true] {
            for rolling_back in [None, Some(ConflictKind::UserConfigChanged)] {
                for finished in [false, true] {
                    out.push((
                        steps.clone(),
                        ItemReceipts {
                            committed,
                            rolling_back,
                            finished,
                        },
                    ));
                }
            }
        }
    }
    out
}

/// The item properties `decision` breaks (property 7, TH, and ADR-0007 §12.17 item 4:
/// a held item carries its held step's own reason, the commit step's file-level
/// restore is T3, and `unmatched` is only the reason of a combination no row lists).
fn item_violations(steps: &[StepState], r: &ItemReceipts, d: ItemDecision) -> Vec<&'static str> {
    let any = |s| steps.contains(&s);
    let held = steps.iter().find_map(|s| match s {
        StepState::Held(reason) => Some(*reason),
        _ => None,
    });
    let mut v = Vec::new();
    let quiet = !r.committed && r.rolling_back.is_none() && !r.finished;
    let contradictory = r.committed && (r.rolling_back.is_some() || any(StepState::CommitRestored));
    match d {
        ItemDecision::FinishForward if !r.committed || r.rolling_back.is_some() => {
            v.push("applied only with item.committed");
        }
        ItemDecision::FinishForward if any(StepState::CommitRestored) => {
            v.push("applied never after the commit step's own restore");
        }
        ItemDecision::FinishRestore
            if !(r.rolling_back.is_some() && !r.committed
                || quiet && any(StepState::CommitRestored)) =>
        {
            v.push("restored only after a restore");
        }
        ItemDecision::ResumeOrAbort
            if !quiet
                || !any(StepState::CommitNeverExchanged)
                || any(StepState::CommitRestored) =>
        {
            v.push("not_applied only when the commit step was never exchanged");
        }
        ItemDecision::TransactionCheck
            if !quiet
                || held.is_some()
                || any(StepState::ExchangedInconsistent)
                || any(StepState::CommitNeverExchanged)
                || any(StepState::CommitRestored)
                || !any(StepState::ExchangedConsistent) =>
        {
            v.push("the check runs only at T1");
        }
        ItemDecision::Settle if !r.finished => v.push("settle only once finished"),
        _ => {}
    }
    if r.committed
        && r.rolling_back.is_some()
        && d != ItemDecision::Hold(HoldReason::ContradictoryReceipts)
    {
        v.push("contradictory item receipts hold");
    }
    if !r.finished && !(r.committed && r.rolling_back.is_some()) {
        if let Some(reason) = held {
            if d != ItemDecision::Hold(reason) {
                v.push("a held step holds the item with its own reason");
            }
        } else if r.committed
            && any(StepState::CommitRestored)
            && d != ItemDecision::Hold(HoldReason::ContradictoryReceipts)
        {
            v.push("item.committed with the commit step's own restore holds");
        }
    }
    let listed = r.finished
        || r.committed
        || r.rolling_back.is_some()
        || contradictory
        || held.is_some()
        || [
            StepState::CommitRestored,
            StepState::CommitNeverExchanged,
            StepState::ExchangedConsistent,
            StepState::ExchangedInconsistent,
        ]
        .into_iter()
        .any(any);
    if d == ItemDecision::Hold(HoldReason::Unmatched)
        && listed
        && held != Some(HoldReason::Unmatched)
    {
        v.push("unmatched only where no item row lists the combination");
    }
    v
}

// --- 1. the row list, in the other direction -----------------------------------------

/// Every row ID of ADR-0007 §5.7 (G0–G3 and H0 are withdrawn), in the ADR's order.
/// `recovery_table_rows_each_have_a_test_vector` checks it against the ADR's tables.
const ROW_IDS: &[&str] = &[
    "F0", "F0x", "F0z", "F1", "F1a", "F2a", "F2b", "F2c", "F2d", "F2e", "F2g", "F2j", "F2k", "F2h",
    "F2f", "F3", "F3a", "F3b", "F3c", "F4", "F4a", "F4c", "F4b", "F4d", "F4e", "F5", "F5a", "F5b",
    "F5c", "F5d", "F6", "F6a", "F8d", "F8b", "F8f", "F8a", "F8e", "F8c", "F9", "F9a", "F9b", "F9c",
    "F9d", "C1", "C2", "C3", "C4", "C4b", "C4h", "C6", "C6a", "C5", "C5a", "C5b", "C7", "C7a",
    "C7b", "C8", "K0", "K0x", "K0z", "K1", "K2", "K3", "K4", "R1", "R1a", "R2", "R2a", "R3", "R4",
    "R5", "R6", "T0", "T1", "T1h", "T2", "T3", "T4", "TH",
];

const RP_ST: &[Ev] = &[F(0, St)];
const RP_VA: &[Ev] = &[F(0, St), F(0, Va)];
const RP_EX: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex)];
const RP_PVV: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV)];
const RP_PVV_C: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), C(SSH)];
const RP_PVV_R: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), R(SSH)];
const RP_PVM: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvM)];
const RP_RSFM: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvM), F(0, RsFm)];
const RP_RD: &[Ev] = &[
    F(0, St),
    F(0, Va),
    F(0, Ex),
    F(0, PvM),
    F(0, RsFm),
    F(0, Rd),
];
const RP_SGD: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), C(SSH), F(0, SgD)];
const RP_SDQ: &[Ev] = &[
    F(0, St),
    F(0, Va),
    F(0, Ex),
    F(0, PvV),
    C(SSH),
    F(0, SgD),
    F(0, SdQ),
];
const RP_SC: &[Ev] = &[
    F(0, St),
    F(0, Va),
    F(0, Ex),
    F(0, PvV),
    C(SSH),
    F(0, SgD),
    F(0, Sc),
];
const CR_VA: &[Ev] = &[F(0, St), F(0, VaA)];
const CR_EX: &[Ev] = &[F(0, St), F(0, VaA), F(0, Ex)];
const CR_PVV: &[Ev] = &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV)];
const CR_PVV_C: &[Ev] = &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV), C(SSH)];
const CR_PVV_R: &[Ev] = &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV), R(SSH)];
const CR_RSTC: &[Ev] = &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV), R(SSH), F(0, RsTc)];
const CR_SGP: &[Ev] = &[
    F(0, St),
    F(0, VaA),
    F(0, Ex),
    F(0, PvV),
    R(SSH),
    F(0, RsTc),
    F(0, SgP),
];
const CR_SDQ: &[Ev] = &[
    F(0, St),
    F(0, VaA),
    F(0, Ex),
    F(0, PvV),
    R(SSH),
    F(0, RsTc),
    F(0, SgP),
    F(0, SdQ),
];
const CR_RD: &[Ev] = &[
    F(0, St),
    F(0, VaA),
    F(0, Ex),
    F(0, PvV),
    R(SSH),
    F(0, RsTc),
    F(0, SgP),
    F(0, SdQ),
    F(0, Rd),
];
const K_ST: &[Ev] = &[F(0, St)];
/// K staged, and B_git (step 1) settled after an abort: the release is due.
const K_ST_DUE: &[Ev] = &[F(1, St), F(1, SgS), F(1, SdQ), F(0, St)];
const K_SGP: &[Ev] = &[F(1, St), F(1, SgS), F(1, SdQ), F(0, St), F(0, SgP)];

struct Vector {
    row: &'static str,
    shape: StepShape,
    hist: &'static [Ev],
    obs: [EntryObs; 3],
    want: StepDecision,
    /// The effects, in [`fmt_effects`] notation: the receipts written and the moves.
    effects: &'static str,
}

const fn v(
    row: &'static str,
    shape: StepShape,
    hist: &'static [Ev],
    obs: [EntryObs; 3],
    want: StepDecision,
    effects: &'static str,
) -> Vector {
    Vector {
        row,
        shape,
        hist,
        obs,
        want,
        effects,
    }
}

fn name(n: Name) -> &'static str {
    match n {
        Name::Path => "path",
        Name::Aside => "aside",
        Name::Slot => "slot",
    }
}

fn fmt_effects(eff: &[Effect]) -> String {
    eff.iter()
        .map(|e| match e {
            Effect::Receipt(k) => (*k).to_owned(),
            Effect::ForwardExchange => "forward_exchange".into(),
            Effect::ForwardCreate => "forward_create".into(),
            Effect::RestoreExchange => "restore_exchange".into(),
            Effect::Claim => "claim".into(),
            Effect::MoveToSlot(n) => format!("move_to_slot({})", name(*n)),
            Effect::RemoveFromSlot => "remove_from_slot".into(),
            Effect::PutBack(n) => format!("put_back({})", name(*n)),
            Effect::KeepAsConflict(n) => format!("keep_as_conflict({})", name(*n)),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_lines)]
fn vectors() -> Vec<Vector> {
    use StepShape::{Create as Cr, GitLock as Gl, Removal as Rm, Replace as Rp};
    const FWD: fn(ForwardStep) -> StepDecision = StepDecision::Forward;
    const RST: fn(RestoreStep) -> StepDecision = StepDecision::Restore;
    const ABT: fn(AbortStep) -> StepDecision = StepDecision::Abort;
    const SET: fn(SettleStep) -> StepDecision = StepDecision::Settle;
    const HLD: fn(HoldReason) -> StepDecision = StepDecision::Hold;
    let settle_s = "settling move_to_slot(aside)";
    vec![
        // Replace (base present, target present). Before `validated` the user's file at
        // the path has no recorded identity, so it is X.
        v("F0", Rp, &[], [X, A, A], FWD(ForwardStep::Stage), "staged"),
        v(
            "F0x",
            Rp,
            &[],
            [X, S, A],
            FWD(ForwardStep::RecordStaged),
            "staged",
        ),
        v(
            "F0x",
            Rp,
            &[],
            [X, SM, A],
            FWD(ForwardStep::RecordStaged),
            "staged",
        ),
        v(
            "F0z",
            Rp,
            &[],
            [X, X, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "F1",
            Rp,
            RP_ST,
            [X, S, A],
            FWD(ForwardStep::Revalidate),
            "validated",
        ),
        v(
            "F1",
            Rp,
            RP_ST,
            [X, SM, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "F1a",
            Rp,
            RP_ST,
            [X, A, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "F1a",
            Rp,
            RP_ST,
            [X, X, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "F2a",
            Rp,
            RP_VA,
            [V, S, A],
            FWD(ForwardStep::Revalidate),
            "forward_exchange exchanged",
        ),
        v(
            "F2a",
            Rp,
            RP_VA,
            [VM, S, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "F2a",
            Rp,
            RP_VA,
            [V, SM, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "F2b",
            Rp,
            RP_VA,
            [S, V, A],
            FWD(ForwardStep::RecordExchanged),
            "exchanged",
        ),
        v(
            "F2c",
            Rp,
            RP_VA,
            [S, VM, A],
            RST(RestoreStep::RecordMismatch),
            "exchanged post_validated",
        ),
        v(
            "F2c",
            Rp,
            RP_VA,
            [SM, X, A],
            RST(RestoreStep::RecordMismatch),
            "exchanged post_validated",
        ),
        v(
            "F2d",
            Rp,
            RP_VA,
            [S, A, A],
            HLD(HoldReason::DisplacedMissing),
            "held",
        ),
        v(
            "F2e",
            Rp,
            RP_VA,
            [X, S, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "F2g",
            Rp,
            RP_VA,
            [V, A, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "F2j",
            Rp,
            RP_VA,
            [A, SM, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "F2k",
            Rp,
            RP_VA,
            [VM, X, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "F2h",
            Rp,
            RP_VA,
            [X, V, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "F2h",
            Rp,
            RP_VA,
            [A, V, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "F2f",
            Rp,
            RP_VA,
            [X, X, A],
            HLD(HoldReason::AmbiguousExchange),
            "held",
        ),
        v(
            "F2f",
            Rp,
            RP_VA,
            [A, VM, A],
            HLD(HoldReason::AmbiguousExchange),
            "held",
        ),
        v(
            "F3",
            Rp,
            RP_EX,
            [S, V, A],
            FWD(ForwardStep::PostValidate),
            "post_validated",
        ),
        v(
            "F3a",
            Rp,
            RP_EX,
            [SM, VM, A],
            RST(RestoreStep::RecordMismatch),
            "post_validated",
        ),
        v(
            "F3b",
            Rp,
            RP_EX,
            [S, A, A],
            HLD(HoldReason::DisplacedMissing),
            "held",
        ),
        v(
            "F3c",
            Rp,
            RP_EX,
            [X, V, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "F4",
            Rp,
            RP_PVV,
            [S, V, A],
            FWD(ForwardStep::TransactionCheck),
            "",
        ),
        v(
            "F4",
            Rp,
            RP_PVV,
            [SM, V, A],
            FWD(ForwardStep::TransactionCheck),
            "",
        ),
        v(
            "F4a",
            Rp,
            RP_PVV,
            [S, A, A],
            HLD(HoldReason::DisplacedMissing),
            "held",
        ),
        v(
            "F4c",
            Rp,
            RP_PVV,
            [S, X, A],
            HLD(HoldReason::DisplacedReplaced),
            "held",
        ),
        v(
            "F4c",
            Rp,
            RP_PVV,
            [S, VM, A],
            HLD(HoldReason::DisplacedReplaced),
            "held",
        ),
        v(
            "F4b",
            Rp,
            RP_PVV,
            [X, V, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "F4d",
            Rp,
            RP_PVV_C,
            [S, V, A],
            SET(SettleStep::Begin),
            settle_s,
        ),
        v(
            "F4d",
            Rp,
            RP_PVV_C,
            [X, VM, A],
            SET(SettleStep::Begin),
            settle_s,
        ),
        v(
            "F4e",
            Rp,
            RP_PVV_C,
            [S, A, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F4e",
            Rp,
            RP_PVV_C,
            [S, X, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F5",
            Rp,
            RP_PVM,
            [S, D, A],
            RST(RestoreStep::Exchange),
            "restore_started restore_exchange restored",
        ),
        v(
            "F5",
            Rp,
            RP_PVM,
            [S, VM, A],
            RST(RestoreStep::Exchange),
            "restore_started restore_exchange restored",
        ),
        v(
            "F5",
            Rp,
            RP_PVV_R,
            [S, V, A],
            RST(RestoreStep::Exchange),
            "restore_started restore_exchange restored",
        ),
        v(
            "F5",
            Rp,
            RP_RSFM,
            [S, D, A],
            RST(RestoreStep::Exchange),
            "restore_exchange restored",
        ),
        v(
            "F5a",
            Rp,
            RP_PVM,
            [SM, D, A],
            HLD(HoldReason::ActiveEntryModified),
            "held",
        ),
        v(
            "F5a",
            Rp,
            RP_PVV_R,
            [SM, V, A],
            HLD(HoldReason::ActiveEntryModified),
            "held",
        ),
        v(
            "F5b",
            Rp,
            RP_RSFM,
            [D, S, A],
            RST(RestoreStep::RecognizeRestored),
            "restored",
        ),
        v(
            "F5b",
            Rp,
            RP_RSFM,
            [D, SM, A],
            RST(RestoreStep::RecognizeRestored),
            "restored",
        ),
        v(
            "F5c",
            Rp,
            RP_RSFM,
            [X, S, A],
            RST(RestoreStep::RecognizeRestored),
            "restored",
        ),
        v(
            "F5d",
            Rp,
            RP_RSFM,
            [X, D, A],
            HLD(HoldReason::ThirdWriter),
            "held",
        ),
        v(
            "F5d",
            Rp,
            RP_PVM,
            [D, S, A],
            HLD(HoldReason::ThirdWriter),
            "held",
        ),
        v("F6", Rp, RP_RD, [D, S, A], SET(SettleStep::Begin), settle_s),
        v(
            "F6",
            Rp,
            RP_RD,
            [X, SM, A],
            SET(SettleStep::Begin),
            settle_s,
        ),
        v(
            "F6a",
            Rp,
            RP_RD,
            [D, A, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F6a",
            Rp,
            RP_RD,
            [D, X, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        // The settlement block, on a replace's displaced entry (source: the aside).
        v(
            "F8d",
            Rp,
            RP_SGD,
            [S, Q, X],
            SET(SettleStep::PutBackForeign),
            "put_back(aside) keep_as_conflict(slot) settle_conflict",
        ),
        v(
            "F8d",
            Rp,
            RP_SGD,
            [S, A, X],
            SET(SettleStep::PutBackForeign),
            "put_back(aside) keep_as_conflict(slot) settle_conflict",
        ),
        v(
            "F8b",
            Rp,
            RP_SGD,
            [S, A, Q],
            SET(SettleStep::RecordSettled),
            "settled",
        ),
        v(
            "F8f",
            Rp,
            RP_SGD,
            [S, A, QM],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F8a",
            Rp,
            RP_SGD,
            [S, Q, A],
            SET(SettleStep::Move),
            "move_to_slot(aside)",
        ),
        v(
            "F8a",
            Rp,
            RP_SGD,
            [S, QM, A],
            SET(SettleStep::Move),
            "move_to_slot(aside)",
        ),
        v(
            "F8a",
            Cr,
            CR_SGP,
            [Q, A, A],
            SET(SettleStep::Move),
            "move_to_slot(path)",
        ),
        v(
            "F8a",
            Cr,
            CR_SGP,
            [QM, A, A],
            HLD(HoldReason::ActiveEntryModified),
            "held",
        ),
        v(
            "F8a",
            Gl,
            K_SGP,
            [Q, A, A],
            SET(SettleStep::Move),
            "move_to_slot(path)",
        ),
        v(
            "F8a",
            Gl,
            K_SGP,
            [QM, A, A],
            SET(SettleStep::Move),
            "move_to_slot(path)",
        ),
        v(
            "F8e",
            Rp,
            RP_SGD,
            [S, X, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F8c",
            Rp,
            RP_SGD,
            [S, A, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "F9",
            Rp,
            RP_SDQ,
            [S, A, Q],
            SET(SettleStep::Remove),
            "remove_from_slot",
        ),
        v(
            "F9a",
            Rp,
            RP_SDQ,
            [S, A, QM],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v("F9b", Rp, RP_SDQ, [S, A, A], SET(SettleStep::Done), ""),
        v(
            "F9b",
            Cr,
            CR_SDQ,
            [A, A, A],
            RST(RestoreStep::RecognizeRestored),
            "restored",
        ),
        v("F9c", Rp, RP_SDQ, [S, A, X], SET(SettleStep::Done), ""),
        v("F9d", Rp, RP_SC, [S, A, QM], SET(SettleStep::Done), ""),
        v("F9d", Rp, RP_SC, [X, X, X], SET(SettleStep::Done), ""),
        // Create (base absent): nothing is displaced, the aside is the staged name.
        v(
            "C1",
            Cr,
            CR_VA,
            [A, S, A],
            FWD(ForwardStep::Revalidate),
            "forward_create exchanged",
        ),
        v(
            "C1",
            Cr,
            CR_VA,
            [A, SM, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "C2",
            Cr,
            CR_VA,
            [S, A, A],
            FWD(ForwardStep::RecordExchanged),
            "exchanged",
        ),
        v(
            "C2",
            Cr,
            CR_VA,
            [SM, A, A],
            FWD(ForwardStep::RecordExchanged),
            "exchanged",
        ),
        v(
            "C3",
            Cr,
            CR_VA,
            [X, S, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "C4",
            Cr,
            CR_VA,
            [A, A, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "C4b",
            Cr,
            CR_VA,
            [A, X, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "C4h",
            Cr,
            CR_VA,
            [X, A, A],
            HLD(HoldReason::AmbiguousExchange),
            "held",
        ),
        v(
            "C4h",
            Cr,
            CR_VA,
            [X, X, A],
            HLD(HoldReason::AmbiguousExchange),
            "held",
        ),
        v(
            "C6",
            Cr,
            CR_EX,
            [S, A, A],
            FWD(ForwardStep::PostValidate),
            "post_validated",
        ),
        v(
            "C6",
            Cr,
            CR_EX,
            [SM, X, A],
            FWD(ForwardStep::PostValidate),
            "post_validated",
        ),
        v(
            "C6a",
            Cr,
            CR_EX,
            [X, A, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "C6a",
            Cr,
            CR_EX,
            [A, A, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "C5",
            Cr,
            CR_PVV,
            [S, A, A],
            FWD(ForwardStep::TransactionCheck),
            "",
        ),
        v(
            "C5a",
            Cr,
            CR_PVV,
            [X, A, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "C5b",
            Cr,
            CR_PVV_C,
            [S, A, A],
            FWD(ForwardStep::NothingDisplaced),
            "settled",
        ),
        v(
            "C5b",
            Cr,
            CR_PVV_C,
            [X, X, A],
            FWD(ForwardStep::NothingDisplaced),
            "settled",
        ),
        v(
            "C7",
            Cr,
            CR_PVV_R,
            [S, A, A],
            RST(RestoreStep::CreateRollback),
            "restore_started settling move_to_slot(path)",
        ),
        v(
            "C7",
            Cr,
            CR_RSTC,
            [S, X, A],
            RST(RestoreStep::CreateRollback),
            "settling move_to_slot(path)",
        ),
        v(
            "C7a",
            Cr,
            CR_PVV_R,
            [SM, A, A],
            HLD(HoldReason::ActiveEntryModified),
            "held",
        ),
        v(
            "C7a",
            Cr,
            CR_RSTC,
            [SM, A, A],
            HLD(HoldReason::ActiveEntryModified),
            "held",
        ),
        v(
            "C7b",
            Cr,
            CR_PVV_R,
            [X, A, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v(
            "C7b",
            Cr,
            CR_RSTC,
            [A, A, A],
            HLD(HoldReason::ActiveEntryReplaced),
            "held",
        ),
        v("C8", Cr, CR_RD, [X, A, A], SET(SettleStep::Done), ""),
        v("C8", Cr, CR_RD, [A, X, QM], SET(SettleStep::Done), ""),
        // The Git lock holder: the path is the lock name, the aside K's staged name.
        v("K0", Gl, &[], [X, A, A], FWD(ForwardStep::Stage), "staged"),
        v("K0", Gl, &[], [A, A, A], FWD(ForwardStep::Stage), "staged"),
        v(
            "K0x",
            Gl,
            &[],
            [A, S, A],
            FWD(ForwardStep::RecordStaged),
            "staged",
        ),
        v(
            "K0z",
            Gl,
            &[],
            [X, X, A],
            ABT(AbortStep::NothingToSettle),
            "",
        ),
        v(
            "K1",
            Gl,
            K_ST,
            [A, S, A],
            FWD(ForwardStep::ClaimLock),
            "claim",
        ),
        v(
            "K1",
            Gl,
            K_ST,
            [A, SM, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "K1",
            Gl,
            K_ST,
            [X, S, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v(
            "K1",
            Gl,
            K_ST_DUE,
            [A, S, A],
            ABT(AbortStep::SettleStaged),
            settle_s,
        ),
        v("K2", Gl, K_ST, [S, A, A], FWD(ForwardStep::KeepLock), ""),
        v("K2", Gl, K_ST, [SM, X, A], FWD(ForwardStep::KeepLock), ""),
        v(
            "K2",
            Gl,
            K_ST_DUE,
            [S, A, A],
            SET(SettleStep::Begin),
            "settling move_to_slot(path)",
        ),
        v(
            "K2",
            Gl,
            K_ST_DUE,
            [SM, X, A],
            SET(SettleStep::Begin),
            "settling move_to_slot(path)",
        ),
        v(
            "K3",
            Gl,
            K_ST,
            [A, A, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "K3",
            Gl,
            K_ST,
            [A, X, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "K4",
            Gl,
            K_ST,
            [X, A, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        v(
            "K4",
            Gl,
            K_ST_DUE,
            [X, X, A],
            SET(SettleStep::RecordConflict),
            "settle_conflict",
        ),
        // Removal (the cleaner): L is the locator's entry (V), and it writes no receipt.
        v(
            "R1",
            Rm,
            &[],
            [V, A, A],
            SET(SettleStep::Move),
            "move_to_slot(path)",
        ),
        v("R1a", Rm, &[], [VM, A, A], SET(SettleStep::Done), ""),
        v(
            "R2",
            Rm,
            &[],
            [A, A, V],
            SET(SettleStep::Remove),
            "remove_from_slot",
        ),
        v(
            "R2",
            Rm,
            &[],
            [X, A, V],
            SET(SettleStep::Remove),
            "remove_from_slot",
        ),
        v(
            "R2a",
            Rm,
            &[],
            [X, A, VM],
            SET(SettleStep::RecordConflict),
            "",
        ),
        v("R3", Rm, &[], [A, A, A], SET(SettleStep::Done), ""),
        v("R4", Rm, &[], [X, A, A], SET(SettleStep::Done), ""),
        v(
            "R5",
            Rm,
            &[],
            [A, A, X],
            SET(SettleStep::PutBackForeign),
            "put_back(path) keep_as_conflict(slot)",
        ),
        v(
            "R5",
            Rm,
            &[],
            [X, A, X],
            SET(SettleStep::PutBackForeign),
            "put_back(path) keep_as_conflict(slot)",
        ),
        v("R6", Rm, &[], [V, A, X], HLD(HoldReason::ThirdWriter), ""),
        v("R6", Rm, &[], [VM, A, X], HLD(HoldReason::ThirdWriter), ""),
    ]
}

/// The item rows' vectors: (row, steps, receipts, decision).
#[allow(clippy::too_many_lines)]
fn item_vectors() -> Vec<(&'static str, Vec<StepState>, ItemReceipts, ItemDecision)> {
    use StepState::{
        CommitNeverExchanged, CommitRestored, ExchangedConsistent, ExchangedInconsistent, Final,
        Held, Open,
    };
    let none = ItemReceipts::default();
    let committed = ItemReceipts {
        committed: true,
        ..none
    };
    let rolling_back = ItemReceipts {
        rolling_back: Some(ConflictKind::ManagedFileEdited),
        ..none
    };
    let finished = ItemReceipts {
        finished: true,
        ..none
    };
    vec![
        (
            "T0",
            vec![Open, Open, CommitNeverExchanged],
            none,
            ItemDecision::ResumeOrAbort,
        ),
        (
            "T0",
            vec![Final, CommitNeverExchanged],
            none,
            ItemDecision::ResumeOrAbort,
        ),
        (
            "T1",
            vec![ExchangedConsistent, ExchangedConsistent],
            none,
            ItemDecision::TransactionCheck,
        ),
        (
            "T1",
            vec![ExchangedConsistent, Open, ExchangedConsistent],
            none,
            ItemDecision::TransactionCheck,
        ),
        // T1h: the only inconsistency a step's own row does not hold is a displaced
        // entry that is not the validated base (F2c, F3a before the mismatch is
        // recorded), so the item's reason is F4c's.
        (
            "T1h",
            vec![ExchangedConsistent, ExchangedInconsistent],
            none,
            ItemDecision::Hold(HoldReason::DisplacedReplaced),
        ),
        (
            "T2",
            vec![Open, Final],
            committed,
            ItemDecision::FinishForward,
        ),
        (
            "T2",
            vec![Final, Final, Final],
            committed,
            ItemDecision::FinishForward,
        ),
        (
            "T3",
            vec![Open, ExchangedConsistent],
            rolling_back,
            ItemDecision::FinishRestore,
        ),
        // T3, the commit step's own file-level restore (ADR-0007 §12.17 item 4): read
        // from `CommitRestored`, while the inactive steps still finish and after.
        (
            "T3",
            vec![Open, CommitRestored],
            none,
            ItemDecision::FinishRestore,
        ),
        (
            "T3",
            vec![Final, CommitRestored, Final],
            none,
            ItemDecision::FinishRestore,
        ),
        (
            "T4",
            vec![Final, Final],
            ItemReceipts {
                committed: true,
                finished: true,
                ..none
            },
            ItemDecision::Settle,
        ),
        (
            "T4",
            vec![Held(HoldReason::ThirdWriter), Open],
            finished,
            ItemDecision::Settle,
        ),
        // TH: the held step's own reason (ADR-0007 §12.17 item 4), the first in plan
        // order.
        (
            "TH",
            vec![Open, Held(HoldReason::DisplacedMissing)],
            none,
            ItemDecision::Hold(HoldReason::DisplacedMissing),
        ),
        (
            "TH",
            vec![Held(HoldReason::ActiveEntryModified)],
            committed,
            ItemDecision::Hold(HoldReason::ActiveEntryModified),
        ),
        (
            "TH",
            vec![
                Final,
                Held(HoldReason::ThirdWriter),
                Held(HoldReason::ActiveEntryReplaced),
            ],
            rolling_back,
            ItemDecision::Hold(HoldReason::ThirdWriter),
        ),
        (
            "TH",
            vec![Final],
            ItemReceipts {
                committed: true,
                rolling_back: Some(ConflictKind::UserConfigChanged),
                finished: false,
            },
            ItemDecision::Hold(HoldReason::ContradictoryReceipts),
        ),
        (
            "TH",
            vec![Final, CommitRestored],
            committed,
            ItemDecision::Hold(HoldReason::ContradictoryReceipts),
        ),
    ]
}

// --- the ADR's own tables, read from ADR-0007 §5.7 -------------------------------------

/// Which ADR-0007 §5.7 table a row is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdrTable {
    Replace,
    Settlement,
    Create,
    GitLock,
    Removal,
    Item,
}

/// One row of an ADR-0007 §5.7 recovery table: its ID and its cells by column header,
/// with the revision markers (`⟨r4⟩`) removed.
#[derive(Debug, Clone)]
struct AdrRow {
    id: String,
    table: AdrTable,
    cells: Vec<(String, String)>,
}

impl AdrRow {
    fn cell(&self, header: &str) -> Option<&str> {
        self.cells
            .iter()
            .find(|(h, _)| h == header)
            .map(|(_, c)| c.as_str())
    }

    fn action(&self) -> &str {
        self.cell("Action")
            .or_else(|| self.cell("Recovery action"))
            .unwrap_or_else(|| panic!("ADR row {} has no action column", self.id))
    }
}

fn without_revision_markers(cell: &str) -> String {
    let mut out = cell.to_owned();
    while let Some(at) = out.find('⟨') {
        let Some(len) = out[at..].find('⟩') else {
            break;
        };
        out.replace_range(at..at + len + '⟩'.len_utf8(), "");
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every row of the recovery tables of ADR-0007 §5.7, in document order, read from the
/// ADR itself (repository data; only its tables are parsed). A table is a run of `|`
/// lines whose header's first cell is `Row`; its table is named by the row ID's letter
/// and, for F rows, by the third column (the settlement block's is `Source`).
fn adr_rows() -> Vec<AdrRow> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/decisions/0007-existing-access-integration.md");
    let text = std::fs::read_to_string(&path).expect("ADR-0007 is readable");
    let start = text.find("\n### 5.7 ").expect("ADR-0007 has §5.7");
    let end = start + text[start..].find("\n### 5.8 ").expect("ADR-0007 has §5.8");
    let mut rows = Vec::new();
    let mut header: Option<Vec<String>> = None;
    for line in text[start..end].lines() {
        let Some(body) = line.trim_end().strip_prefix('|') else {
            header = None;
            continue;
        };
        let body = body.strip_suffix('|').unwrap_or(body);
        let cells: Vec<String> = body.split('|').map(without_revision_markers).collect();
        let Some(h) = &header else {
            header = Some(cells);
            continue;
        };
        if h[0] != "Row" || cells.iter().all(|c| c.chars().all(|ch| ch == '-')) {
            continue;
        }
        assert_eq!(cells.len(), h.len(), "ADR-0007 §5.7 row {:?}", cells[0]);
        let id = cells[0].clone();
        let table = match (id.chars().next(), h.get(2).map(String::as_str)) {
            (Some('F'), Some("Path")) => AdrTable::Replace,
            (Some('F'), Some("Source")) => AdrTable::Settlement,
            (Some('C'), _) => AdrTable::Create,
            (Some('K'), _) => AdrTable::GitLock,
            (Some('R'), _) => AdrTable::Removal,
            (Some('T'), _) => AdrTable::Item,
            _ => panic!("ADR-0007 §5.7: unknown row {id:?} under {h:?}"),
        };
        rows.push(AdrRow {
            id,
            table,
            cells: h.iter().cloned().zip(cells).collect(),
        });
    }
    rows
}

/// Whether `st` is in the phase an ADR "Phase" cell names. Every phase form the tables
/// use is listed; any other form fails the test, so a changed table is re-read here.
fn adr_phase_matches(cell: &str, st: &RecoveryState) -> bool {
    if cell.starts_with("restore due") {
        return matches!(st.restore, RestoreCtx::Due(_) | RestoreCtx::Started(_));
    }
    if cell == "none" {
        return st.phase.is_none();
    }
    let token = cell
        .split('`')
        .nth(1)
        .unwrap_or_else(|| panic!("ADR phase cell {cell:?} names no phase"));
    let phase = st.phase.as_ref();
    let in_phase = match token {
        "staged" => matches!(phase, Some(EffectivePhase::Staged { .. })),
        "validated" => matches!(phase, Some(EffectivePhase::Validated { .. })),
        "validated{absent}" => matches!(phase, Some(EffectivePhase::Validated { base: None })),
        "exchanged" => matches!(phase, Some(EffectivePhase::Exchanged)),
        "post_validated{valid}" => matches!(
            phase,
            Some(EffectivePhase::PostValidated {
                verdict: PostVerdict::Valid,
                ..
            })
        ),
        "restore_started" => matches!(phase, Some(EffectivePhase::RestoreStarted { .. })),
        "restored" => matches!(phase, Some(EffectivePhase::Restored)),
        "settling" => matches!(phase, Some(EffectivePhase::Settling { .. })),
        "settled" => matches!(phase, Some(EffectivePhase::Settled { .. })),
        "settle_conflict" => matches!(phase, Some(EffectivePhase::SettleConflict { .. })),
        other => panic!("unknown ADR phase {other:?} in {cell:?}"),
    };
    let item = if cell.ends_with("(open)") {
        st.item == ItemState::Open
    } else if cell.ends_with("(`item.committed`)") {
        st.item == ItemState::Committed
    } else {
        true
    };
    in_phase && item
}

/// Whether `e` is one of the symbols an ADR cell lists. `*`, "any other" and an empty
/// cell match every symbol but `?`; D after a forward exchange is V or V′ (the note
/// under the replace table); K is S for the `git_lock` step, and the removal's L is the
/// locator's entry, `Recorded { V | S }` (ADR-0007 §12.17 item 7). F0x/K0x's "a
/// regular file owned by the user, link count 1" is S or S′ (the classifier's, §12.17
/// item 2).
fn adr_symbol_matches(cell: &str, e: EntryObs) -> bool {
    if cell.is_empty() || cell == "*" || cell == "any other" {
        return e != U;
    }
    if cell == "a regular file owned by the user, link count 1" {
        return e == S || e == SM;
    }
    cell.split(',').any(|token| {
        let token = token.split(" (").next().unwrap_or(token).trim();
        let allowed: &[EntryObs] = match token {
            "∅" => &[A],
            "S" | "K" => &[S],
            "S′" | "K′" => &[SM],
            "V" => &[V],
            "V′" => &[VM],
            "D" => &[D, DM, V, VM],
            "Q" => &[Q],
            "Q′" => &[QM],
            "X" => &[X],
            "L" => &[V, S],
            "L′" => &[VM, SM],
            other => panic!("unknown ADR symbol {other:?} in {cell:?}"),
        };
        allowed.contains(&e)
    })
}

/// The first ADR row that names `(shape, st, obs)`, trying the rows that apply to the
/// step in document order, as `decide` does ("Within each phase's block the rows are
/// tried in order"). A create step also uses F0–F1a ("Rows F0–F1a and the settlement
/// block apply unchanged"); every step in a settlement uses the settlement block.
fn adr_first_match<'r>(
    rows: &'r [AdrRow],
    shape: StepShape,
    st: &RecoveryState,
    obs: &StepObservation,
) -> Option<&'r AdrRow> {
    let settling = matches!(
        st.phase,
        Some(
            EffectivePhase::Settling { .. }
                | EffectivePhase::Settled { .. }
                | EffectivePhase::SettleConflict { .. }
        )
    );
    let source = match st.settlement.map(|c| c.source) {
        Some(SettleSource::Path) => obs.path(),
        _ => obs.aside(),
    };
    let tables: &[AdrTable] = match shape {
        StepShape::Removal => &[AdrTable::Removal],
        _ if settling => &[AdrTable::Settlement],
        StepShape::Replace => &[AdrTable::Replace],
        StepShape::Create => &[AdrTable::Replace, AdrTable::Create],
        StepShape::GitLock => &[AdrTable::GitLock],
    };
    rows.iter()
        .filter(|r| tables.contains(&r.table))
        .filter(|r| {
            shape != StepShape::Create
                || r.table != AdrTable::Replace
                || ["F0", "F0x", "F0z", "F1", "F1a"].contains(&r.id.as_str())
        })
        .find(|r| {
            let phase = r.cell("Phase (item state)").or_else(|| r.cell("Phase"));
            let columns: [(&str, EntryObs); 2] = match r.table {
                AdrTable::Replace | AdrTable::Create => {
                    [("Path", obs.path()), ("Aside", obs.aside())]
                }
                AdrTable::Settlement => [("Source", source), ("Slot", obs.slot())],
                AdrTable::GitLock => [("Staged", obs.aside()), ("Lock", obs.path())],
                AdrTable::Removal => [("Path", obs.path()), ("Slot", obs.slot())],
                AdrTable::Item => unreachable!("item rows are not step rows"),
            };
            phase.is_none_or(|c| adr_phase_matches(c, st))
                && columns.iter().all(|(h, e)| {
                    adr_symbol_matches(r.cell(h).unwrap_or_else(|| panic!("{h}")), *e)
                })
        })
}

/// The `HoldReason` names an ADR action cell gives (`` `displaced_missing` `` …).
fn adr_hold_reasons(action: &str) -> Vec<HoldReason> {
    let snake = |r: HoldReason| match r {
        HoldReason::ActiveEntryReplaced => "active_entry_replaced",
        HoldReason::ActiveEntryModified => "active_entry_modified",
        HoldReason::DisplacedMissing => "displaced_missing",
        HoldReason::DisplacedReplaced => "displaced_replaced",
        HoldReason::ThirdWriter => "third_writer",
        HoldReason::AmbiguousExchange => "ambiguous_exchange",
        HoldReason::Unobservable => "unobservable",
        HoldReason::Unmatched => "unmatched",
        HoldReason::ContradictoryReceipts => "contradictory_receipts",
    };
    HOLD_REASONS
        .into_iter()
        .filter(|r| action.contains(&format!("`{}`", snake(*r))))
        .collect()
}

/// A hold whose row is not marked **H** or names no reason, with the ruling that reads
/// it so: R6 (ADR-0007 §12.17 item 7: for the removal shape, `Hold` is R6's "nothing
/// is moved", the cleaner retries) and T1h (no reason in the table; the residual
/// inconsistency is a displaced entry that is not V, F4c's `displaced_replaced`; see
/// `recovery::decide_item`).
const HOLD_READINGS: &[(&str, HoldReason)] = &[
    ("R6", HoldReason::ThirdWriter),
    ("T1h", HoldReason::DisplacedReplaced),
];

/// Rows whose action is a hold in one case and a move in another: F8a holds a create
/// restore whose source is Q′ and moves otherwise.
const MIXED_ROWS: &[&str] = &["F8a"];

/// Whether `want` agrees with `row`'s action: a hold only where the row is **H** with
/// that reason (or a [`HOLD_READINGS`] entry, or for TH the held step's own reason),
/// and anything else only where the row is not **H** (or is in [`MIXED_ROWS`]).
fn adr_action_agrees(
    row: &AdrRow,
    hold: Option<HoldReason>,
    held_step: Option<HoldReason>,
) -> bool {
    let action = row.action();
    let marked = action.contains("**H**");
    match hold {
        None => !marked || MIXED_ROWS.contains(&row.id.as_str()),
        Some(r) => {
            HOLD_READINGS.contains(&(row.id.as_str(), r))
                || (marked && (adr_hold_reasons(action).contains(&r) || held_step == Some(r)))
        }
    }
}

/// m02-plan U4 `recovery_table_rows_each_have_a_test_vector` (ADR-0007 §5.7 "m02-plan
/// U4 test … keeps the other direction"; §12.17 item 8). In process: each vector's
/// receipts go through `RecoveryState::build`, its observation through
/// `StepObservation::normalize`, and `decide`/`decide_item` give the action. It fails
/// when the row list is not the ADR's, a row has no vector, a vector is not its row's
/// case (another row of the ADR's tables, tried in order, names it first), or the
/// decision, its effects or its hold reason disagree with the row.
#[test]
fn recovery_table_rows_each_have_a_test_vector() {
    // The row list is the ADR's: the same IDs in the same order, each once.
    let adr = adr_rows();
    let adr_ids: Vec<&str> = adr.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        adr_ids, ROW_IDS,
        "ROW_IDS differs from the rows of ADR-0007 §5.7's tables"
    );
    assert_eq!(
        ROW_IDS.iter().collect::<HashSet<_>>().len(),
        ROW_IDS.len(),
        "a row ID twice"
    );
    let vectors = vectors();
    let items = item_vectors();
    for id in ROW_IDS {
        let n = vectors.iter().filter(|v| v.row == *id).count()
            + items.iter().filter(|(row, ..)| row == id).count();
        assert!(n > 0, "row {id} has no test vector");
    }
    let row_of = |id: &str| adr.iter().find(|r| r.id == id);
    for v in &vectors {
        let row = row_of(v.row).unwrap_or_else(|| panic!("unknown row {}", v.row));
        assert_ne!(row.table, AdrTable::Item, "{} is an item row", v.row);
        let state = build(v.shape, v.hist)
            .unwrap_or_else(|_| panic!("{}: history refused: {:?}", v.row, v.hist));
        let obs = observe(v.shape, &state, v.obs)
            .unwrap_or_else(|e| panic!("{}: observation impossible: {e:?}", v.row));
        // The vector is its row's case: the first row of the ADR's tables, tried in
        // order, that names its phase and symbols is its row.
        let first = adr_first_match(&adr, v.shape, &state, &obs).map(|r| r.id.as_str());
        assert_eq!(
            first,
            Some(v.row),
            "vector {} {:?} {:?} is the ADR's row {first:?}",
            v.row,
            v.obs,
            v.hist
        );
        let got = decide(v.shape, &state, &obs);
        assert_eq!(got, v.want, "row {} {:?}", v.row, v.obs);
        let hold = match got {
            StepDecision::Hold(r) => Some(r),
            _ => None,
        };
        assert!(
            adr_action_agrees(row, hold, None),
            "row {}: {got:?} disagrees with the ADR's action {:?}",
            v.row,
            row.action()
        );
        let eff = effects(got, v.shape, &state);
        assert_eq!(fmt_effects(&eff), v.effects, "row {} effects", v.row);
        assert_eq!(
            violations(v.shape, &state, &obs, got),
            Vec::<Prop>::new(),
            "row {}",
            v.row
        );
    }
    for (id, steps, receipts, want) in &items {
        let row = row_of(id).unwrap_or_else(|| panic!("unknown row {id}"));
        assert_eq!(row.table, AdrTable::Item, "{id} is not an item row");
        let got = decide_item(steps, receipts);
        assert_eq!(got, *want, "row {id} {steps:?} {receipts:?}");
        let held_step = steps.iter().find_map(|s| match s {
            StepState::Held(r) => Some(*r),
            _ => None,
        });
        let hold = match got {
            ItemDecision::Hold(r) => Some(r),
            _ => None,
        };
        assert!(
            adr_action_agrees(row, hold, held_step),
            "row {id}: {got:?} disagrees with the ADR's action {:?}",
            row.action()
        );
    }
}

// --- 2. totality over the generated domain --------------------------------------------

#[test]
fn recovery_decide_is_total_over_the_generated_domain() {
    let built = build_generated();
    let (cells, rejected) = cells(&built.states);
    let mut decisions: BTreeMap<String, usize> = BTreeMap::new();
    let mut holds: BTreeMap<String, usize> = BTreeMap::new();
    let mut broken: BTreeMap<Prop, usize> = BTreeMap::new();
    let mut first: Vec<String> = Vec::new();
    for cell in &cells {
        let st = &built.states[cell.state];
        let d = decide(cell.shape, st, &cell.obs);
        *decisions.entry(decision_kind(d)).or_insert(0) += 1;
        if let StepDecision::Hold(r) = d {
            *holds.entry(format!("{r:?}")).or_insert(0) += 1;
        }
        // The same state with or without inserted `held` receipts is one state here,
        // so it gives one decision; `build_generated` checked the states are equal.
        for p in violations(cell.shape, st, &cell.obs, d) {
            *broken.entry(p).or_insert(0) += 1;
            if first.len() < 8 {
                first.push(format!(
                    "{p:?}: {:?} {st:?} {:?} -> {d:?}",
                    cell.shape, cell.obs
                ));
            }
        }
    }
    // A contradictory history holds the step (`reconcile` maps `Contradictory` to
    // `Hold(ContradictoryReceipts)`), and that hold only writes `file.held`.
    *holds
        .entry(format!("{:?}", HoldReason::ContradictoryReceipts))
        .or_insert(0) += built.contradictory;
    for shape in SHAPES {
        let eff = effects(
            StepDecision::Hold(HoldReason::ContradictoryReceipts),
            shape,
            &built.states[0],
        );
        assert!(eff.iter().all(|e| *e == Effect::Receipt("held")), "{eff:?}");
    }
    println!(
        "generated histories: {}, contradictory: {}, distinct states: {}, cells: {}",
        built.histories,
        built.contradictory,
        built.states.len(),
        cells.len()
    );
    println!("rejected cells by reason: {rejected:?}");
    println!("cells by decision: {decisions:?}");
    println!("holds by reason: {holds:?}");
    assert!(
        broken.is_empty(),
        "properties broken: {broken:?}\n{}",
        first.join("\n")
    );
    for reason in HOLD_REASONS {
        assert!(
            holds.get(&format!("{reason:?}")).copied().unwrap_or(0) > 0,
            "HoldReason::{reason:?} is unreachable"
        );
    }
    for why in [
        Impossible::RecordedAtTwoNames,
        Impossible::QuarantineOutsideSettlement,
        Impossible::DisplacedWithoutMismatch,
        Impossible::ValidatedWithoutBase,
        Impossible::SlotWithoutSettlement,
        Impossible::LockStateOnOtherShape,
    ] {
        assert!(
            rejected.get(&format!("{why:?}")).copied().unwrap_or(0) > 0,
            "no cell was rejected as {why:?}"
        );
    }
    for kind in ["Forward", "Restore", "Abort", "Settle", "Hold"] {
        assert!(
            decisions.keys().any(|k| k.starts_with(kind)),
            "no cell decides {kind}"
        );
    }
    // decide_item over every combination of step states and item receipts.
    for (steps, receipts) in item_domain() {
        let d = decide_item(&steps, &receipts);
        assert_eq!(
            item_violations(&steps, &receipts, d),
            Vec::<&str>::new(),
            "{steps:?} {receipts:?} -> {d:?}"
        );
    }
}

// --- 3. negative controls ------------------------------------------------------------

type DecideFn = fn(StepShape, &RecoveryState, &StepObservation) -> StepDecision;

fn source_of(st: &RecoveryState, obs: &StepObservation) -> EntryObs {
    match st.settlement {
        Some(c) if c.source == SettleSource::Path => obs.path(),
        _ => obs.aside(),
    }
}

/// Deliberately wrong `decide` variants (ADR-0007 §5.7 "Negative controls"; m02-plan
/// U4 `recovery_properties_catch_seeded_faults`).
fn seeded_faults() -> Vec<(&'static str, DecideFn)> {
    vec![
        ("a restore exchange over S′", |shape, st, obs| {
            let d = decide(shape, st, obs);
            if shape == StepShape::Replace
                && d == StepDecision::Hold(HoldReason::ActiveEntryModified)
            {
                StepDecision::Restore(RestoreStep::Exchange)
            } else {
                d
            }
        }),
        ("a remove_from_slot of Q′", |shape, st, obs| {
            if matches!(st.phase, Some(EffectivePhase::Settled { .. })) && obs.slot() == QM {
                StepDecision::Settle(SettleStep::Remove)
            } else {
                decide(shape, st, obs)
            }
        }),
        ("a remove_from_slot of V′", |shape, st, obs| {
            if shape == StepShape::Replace
                && st.item == ItemState::Committed
                && matches!(st.phase, Some(EffectivePhase::PostValidated { .. }))
                && obs.aside() == VM
            {
                StepDecision::Settle(SettleStep::Remove)
            } else {
                decide(shape, st, obs)
            }
        }),
        ("the cleaner removing L′", |shape, st, obs| {
            if shape == StepShape::Removal && obs.slot() == VM {
                StepDecision::Settle(SettleStep::Remove)
            } else {
                decide(shape, st, obs)
            }
        }),
        (
            "a foreign entry moved anywhere but back",
            |shape, st, obs| {
                if matches!(st.phase, Some(EffectivePhase::Settling { .. }))
                    && source_of(st, obs) == X
                    && obs.slot() == A
                {
                    StepDecision::Settle(SettleStep::Move)
                } else {
                    decide(shape, st, obs)
                }
            },
        ),
        (
            "a forward exchange after item.rolling_back",
            |shape, st, obs| {
                if shape == StepShape::Replace && st.item == ItemState::RollingBack {
                    StepDecision::Forward(ForwardStep::Revalidate)
                } else {
                    decide(shape, st, obs)
                }
            },
        ),
        ("a create rollback of S′", |shape, st, obs| {
            let d = decide(shape, st, obs);
            if shape == StepShape::Create
                && d == StepDecision::Hold(HoldReason::ActiveEntryModified)
            {
                StepDecision::Restore(RestoreStep::CreateRollback)
            } else {
                d
            }
        }),
        (
            "a second restore exchange where F5b recognizes one",
            |shape, st, obs| {
                let d = decide(shape, st, obs);
                if d == StepDecision::Restore(RestoreStep::RecognizeRestored)
                    && shape == StepShape::Replace
                {
                    StepDecision::Restore(RestoreStep::Exchange)
                } else {
                    d
                }
            },
        ),
        ("K released while B_git is not final", |shape, st, obs| {
            let d = decide(shape, st, obs);
            if d == StepDecision::Forward(ForwardStep::KeepLock) {
                StepDecision::Settle(SettleStep::Begin)
            } else {
                d
            }
        }),
        (
            "an unobservable name decided as absent",
            |shape, st, obs| {
                let d = decide(shape, st, obs);
                if d == StepDecision::Hold(HoldReason::Unobservable) && obs.slot() == U {
                    StepDecision::Settle(SettleStep::Done)
                } else {
                    d
                }
            },
        ),
    ]
}

#[test]
fn recovery_properties_catch_seeded_faults() {
    let built = build_generated();
    let (cells, _) = cells(&built.states);
    let mut report = Vec::new();
    for (fault, faulty) in seeded_faults() {
        let mut caught: BTreeMap<Prop, usize> = BTreeMap::new();
        let mut differing = 0usize;
        for cell in &cells {
            let st = &built.states[cell.state];
            let wrong = faulty(cell.shape, st, &cell.obs);
            if wrong == decide(cell.shape, st, &cell.obs) {
                continue;
            }
            differing += 1;
            for p in violations(cell.shape, st, &cell.obs, wrong) {
                *caught.entry(p).or_insert(0) += 1;
            }
        }
        assert!(
            differing > 0,
            "the variant `{fault}` never differs from decide"
        );
        assert!(
            !caught.is_empty(),
            "the variant `{fault}` passes every property ({differing} differing cells)"
        );
        report.push(format!(
            "{fault}: {differing} differing cells, caught by {caught:?}"
        ));
    }
    println!("{}", report.join("\n"));
    // The checker itself passes the real table (the totality test asserts it cell by
    // cell; here only the count of differing cells matters).
    let real: usize = cells
        .iter()
        .map(|c| {
            let st = &built.states[c.state];
            violations(c.shape, st, &c.obs, decide(c.shape, st, &c.obs)).len()
        })
        .sum();
    assert_eq!(real, 0);
}

// --- 4. the recovery state ignores `held` and keeps the restore context ---------------

#[test]
fn recovery_state_ignores_held_and_keeps_restore_context() {
    // For every generated history, `held` anywhere gives an equal state (asserted
    // inside `build_generated`, for every position on one placement per sequence and
    // for one position and every position on all the others).
    let built = build_generated();
    assert!(built.histories > 10_000, "{}", built.histories);

    // The review's case (M2-T04): two replace steps with the same observation and the
    // same `held` payload, one held after `validated`, one after `restore_started`.
    let first: &[Ev] = &[F(0, St), F(0, Va), H(0)];
    let second: &[Ev] = &[F(0, St), F(0, Va), F(0, Ex), F(0, PvM), F(0, RsFm), H(0)];
    let a = build(StepShape::Replace, first).unwrap();
    let b = build(StepShape::Replace, second).unwrap();
    assert_ne!(a, b);
    assert_eq!(a.phase, Some(effective(Va)));
    assert_eq!(a.restore, RestoreCtx::NotDue);
    assert_eq!(b.phase, Some(effective(RsFm)));
    assert_eq!(b.restore, RestoreCtx::Started(RestoreCause::FileMismatch));
    assert_eq!(a, build(StepShape::Replace, &first[..2]).unwrap());
    assert_eq!(b, build(StepShape::Replace, &second[..5]).unwrap());
    // While both are held they observe the same names: X at the path, X aside.
    let held_obs = [X, X, A];
    let da = decide(
        StepShape::Replace,
        &a,
        &observe(StepShape::Replace, &a, held_obs).unwrap(),
    );
    let db = decide(
        StepShape::Replace,
        &b,
        &observe(StepShape::Replace, &b, held_obs).unwrap(),
    );
    assert!(matches!(da, StepDecision::Hold(_)) && matches!(db, StepDecision::Hold(_)));
    // The owner brings the files back to a recognizable state: the first resumes
    // forward (F2a under T0), the second restores (F5).
    let oa = observe(StepShape::Replace, &a, [V, S, A]).unwrap();
    let ob = observe(StepShape::Replace, &b, [S, D, A]).unwrap();
    let da = decide(StepShape::Replace, &a, &oa);
    let db = decide(StepShape::Replace, &b, &ob);
    assert_eq!(da, StepDecision::Forward(ForwardStep::Revalidate));
    assert_eq!(
        fmt_effects(&effects(da, StepShape::Replace, &a)),
        "forward_exchange exchanged"
    );
    assert_eq!(db, StepDecision::Restore(RestoreStep::Exchange));
    assert_eq!(
        fmt_effects(&effects(db, StepShape::Replace, &b)),
        "restore_exchange restored"
    );
    assert_eq!(
        decide_item(&[StepState::CommitNeverExchanged], &ItemReceipts::default()),
        ItemDecision::ResumeOrAbort
    );

    // The restore context survives the restore and its settlement, with its cause
    // (ADR-0007 §12.14 item 1): a mismatch restore and a clean rollback stay apart.
    let mismatch_done: &[Ev] = &[
        F(0, St),
        F(0, Va),
        F(0, Ex),
        F(0, PvM),
        H(0),
        F(0, RsFm),
        F(0, Rd),
        H(0),
        F(0, SgS),
        F(0, SdQ),
        H(0),
    ];
    let rollback_done: &[Ev] = &[
        F(0, St),
        F(0, Va),
        F(0, Ex),
        F(0, PvV),
        R(SSH),
        H(0),
        F(0, RsTc),
        F(0, Rd),
        F(0, SgS),
        H(0),
        F(0, SdQ),
    ];
    let m = build(StepShape::Replace, mismatch_done).unwrap();
    let r = build(StepShape::Replace, rollback_done).unwrap();
    assert_eq!(m.restore, RestoreCtx::Done(RestoreCause::FileMismatch));
    assert_eq!(r.restore, RestoreCtx::Done(RestoreCause::TransactionCheck));
    assert_eq!(
        m.settlement,
        Some(SettleCtx {
            source: SettleSource::Staged,
            create_restore: false
        })
    );
    // Only after a recorded mismatch can D be observed; after the clean rollback the
    // same entry is V (normalization rule 3).
    assert!(observe(StepShape::Replace, &m, [D, A, A]).is_ok());
    assert_eq!(
        observe(StepShape::Replace, &r, [D, A, A]),
        Err(Impossible::DisplacedWithoutMismatch)
    );
}

// --- 5. contradictory histories ------------------------------------------------------

#[test]
fn recovery_state_refuses_contradictory_histories() {
    let refused: &[(&str, StepShape, &[Ev])] = &[
        (
            "exchanged without validated",
            StepShape::Replace,
            &[F(0, St), F(0, Ex)],
        ),
        ("exchanged without staged", StepShape::Create, &[F(0, Ex)]),
        (
            "settled without settling",
            StepShape::Replace,
            &[F(0, St), F(0, SdQ)],
        ),
        (
            "settled without settling, after the commit",
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), C(SSH), F(0, SdQ)],
        ),
        (
            "a phase after settle_conflict",
            StepShape::Replace,
            &[F(0, St), F(0, Sc), F(0, Va)],
        ),
        (
            "settling after settle_conflict",
            StepShape::Replace,
            &[
                F(0, St),
                F(0, Va),
                F(0, Ex),
                F(0, PvV),
                C(SSH),
                F(0, Sc),
                F(0, SgD),
            ],
        ),
        (
            "item.committed and item.rolling_back",
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), C(SSH), R(SSH)],
        ),
        (
            "item.rolling_back and item.committed",
            StepShape::Create,
            &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV), R(SSH), C(SSH)],
        ),
        (
            "a phase repeated",
            StepShape::Replace,
            &[F(0, St), F(0, St)],
        ),
        (
            "item.committed twice",
            StepShape::Replace,
            &[C(SSH), C(SSH)],
        ),
        (
            "a file receipt after item.finished",
            StepShape::Replace,
            &[F(0, St), Fin(SSH, ItemFinish::NotApplied), F(0, SgS)],
        ),
        (
            "finished{applied} without item.committed",
            StepShape::Replace,
            &[Fin(SSH, ItemFinish::Applied)],
        ),
        (
            "finished{restored} after item.committed",
            StepShape::Replace,
            &[C(SSH), Fin(SSH, ItemFinish::Restored)],
        ),
        (
            "finished{not_applied} after item.rolling_back",
            StepShape::Replace,
            &[R(SSH), Fin(SSH, ItemFinish::NotApplied)],
        ),
        (
            "D settled before item.committed",
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), F(0, SgD)],
        ),
        (
            "restore_started{transaction_check} without item.rolling_back",
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), F(0, RsTc)],
        ),
        (
            "restore_started{file_mismatch} after a valid post-validation",
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), F(0, RsFm)],
        ),
        (
            "validated{absent} on a replace",
            StepShape::Replace,
            &[F(0, St), F(0, VaA)],
        ),
        (
            "validated{V} on a create",
            StepShape::Create,
            &[F(0, St), F(0, Va)],
        ),
        (
            "a mismatch on a create",
            StepShape::Create,
            &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvM)],
        ),
        (
            "restored before a create's settlement",
            StepShape::Create,
            &[
                F(0, St),
                F(0, VaA),
                F(0, Ex),
                F(0, PvV),
                R(SSH),
                F(0, RsTc),
                F(0, Rd),
            ],
        ),
        (
            "validated on the git_lock step",
            StepShape::GitLock,
            &[F(0, St), F(0, VaA)],
        ),
        (
            "settling{displaced} on the git_lock step",
            StepShape::GitLock,
            &[F(0, St), F(0, SgD)],
        ),
        (
            "any file receipt on a removal",
            StepShape::Removal,
            &[F(0, St)],
        ),
    ];
    for (why, shape, events) in refused {
        assert_eq!(build(*shape, events), Err(Contradictory), "{why}");
        assert_eq!(
            build(*shape, &held_everywhere(events)),
            Err(Contradictory),
            "{why}"
        );
    }
    // A `file.settling` that names another identity than its source holds: S (K) for a
    // `staged` or `path` source, V for a `displaced` one.
    let settling = |source: SettleSource, ino: u64| LocalReceipt::File {
        step: 0,
        phase: FilePhase::Settling {
            source,
            name: ".scratch.hm-2-00".into(),
            expected: identity(ino),
            expected_sha256: digest("expected"),
            slot: "slot-00".into(),
        },
    };
    let misnamed: &[(StepShape, &[Ev], LocalReceipt)] = &[
        (
            StepShape::Replace,
            RP_ST,
            settling(SettleSource::Staged, 22),
        ),
        (
            StepShape::Replace,
            RP_PVV_C,
            settling(SettleSource::Displaced, 11),
        ),
        (StepShape::Create, CR_RSTC, settling(SettleSource::Path, 22)),
        (StepShape::GitLock, K_ST, settling(SettleSource::Path, 33)),
    ];
    for (shape, events, bad) in misnamed {
        let mut log = receipts(events);
        let last = log[log.len() - 1].clone();
        log.push(StageReceipt {
            local: Some(bad.clone()),
            ..last
        });
        assert_eq!(
            RecoveryState::build(0, &log, &intent(*shape)),
            Err(Contradictory),
            "{shape:?} {bad:?}"
        );
    }
    // A receipt naming a step or an item the intent does not have refuses every step.
    for shape in SHAPES {
        let other_item = if shape == StepShape::GitLock {
            SSH
        } else {
            GIT
        };
        for events in [&[F(7, St)][..], &[C(other_item)][..], &[H(3)][..]] {
            assert_eq!(
                build(shape, events),
                Err(Contradictory),
                "{shape:?} {events:?}"
            );
        }
    }
    let out_of_range = RecoveryState::build(5, &receipts(&[]), &intent(StepShape::Replace));
    assert_eq!(out_of_range, Err(Contradictory));
    // A contradictory step is held: its one effect is the `held` receipt, nothing
    // moves (`reconcile` writes it once; its idempotence is W2-U4c's test).
    let hold = StepDecision::Hold(HoldReason::ContradictoryReceipts);
    for shape in [StepShape::Replace, StepShape::Create, StepShape::GitLock] {
        let state = build(shape, &[]).unwrap();
        assert_eq!(effects(hold, shape, &state), vec![Effect::Receipt("held")]);
    }
    // The item rows hold an item whose receipts contradict each other (TH).
    let both = ItemReceipts {
        committed: true,
        rolling_back: Some(ConflictKind::UserConfigChanged),
        finished: false,
    };
    assert_eq!(
        decide_item(&[StepState::ExchangedConsistent], &both),
        ItemDecision::Hold(HoldReason::ContradictoryReceipts)
    );
    // The orders the ADR allows are accepted (the controls of the refusals above).
    let accepted: &[(StepShape, &[Ev])] = &[
        (
            StepShape::Replace,
            &[
                F(0, St),
                F(0, Va),
                F(0, Ex),
                F(0, PvV),
                C(SSH),
                F(0, SgD),
                F(0, SdQ),
                F(0, Sc),
            ],
        ),
        (
            StepShape::Replace,
            &[F(0, St), F(0, Va), F(0, Ex), F(0, PvV), C(SSH), F(0, Sc)],
        ),
        (StepShape::Replace, &[F(0, St), F(0, Sc)]),
        (
            StepShape::Create,
            &[
                F(0, St),
                F(0, VaA),
                F(0, Ex),
                F(0, PvV),
                R(SSH),
                F(0, RsTc),
                F(0, SgP),
                F(0, Sc),
                F(0, Rd),
            ],
        ),
        (StepShape::GitLock, &[F(0, St), F(0, Sc)]),
        (
            StepShape::Replace,
            &[R(SSH), Fin(SSH, ItemFinish::Restored)],
        ),
        (
            StepShape::Replace,
            &[Fin(SSH, ItemFinish::ConflictPreserved)],
        ),
    ];
    for (shape, events) in accepted {
        assert!(build(*shape, events).is_ok(), "{shape:?} {events:?}");
    }
}

// --- 6. normalization ----------------------------------------------------------------

#[test]
fn observation_normalization_precedence_and_impossible_combinations() {
    let rp = StepShape::Replace;
    // Q equal to S at the settlement's source is Q: an abort's settlement of S (source
    // `staged`, the aside) accepts Q there and in the slot, and S's identity at a
    // second name is impossible because Q is S.
    let abort = build(rp, &[F(0, St), F(0, SgS)]).unwrap();
    assert!(observe(rp, &abort, [X, Q, A]).is_ok());
    assert!(observe(rp, &abort, [X, A, QM]).is_ok());
    assert_eq!(
        observe(rp, &abort, [S, Q, A]),
        Err(Impossible::RecordedAtTwoNames)
    );
    assert_eq!(
        observe(rp, &abort, [SM, A, Q]),
        Err(Impossible::RecordedAtTwoNames)
    );
    assert_eq!(
        observe(rp, &abort, [Q, A, A]),
        Err(Impossible::QuarantineOutsideSettlement)
    );
    // A displaced settlement moves V: V at the path with Q aside is one identity twice.
    let displaced = build(rp, RP_SGD).unwrap();
    assert!(observe(rp, &displaced, [S, Q, A]).is_ok());
    assert_eq!(
        observe(rp, &displaced, [V, Q, A]),
        Err(Impossible::RecordedAtTwoNames)
    );
    // A create's restore settles the path: Q at the path, never aside.
    let create_restore = build(StepShape::Create, CR_SGP).unwrap();
    assert!(observe(StepShape::Create, &create_restore, [Q, A, A]).is_ok());
    assert_eq!(
        observe(StepShape::Create, &create_restore, [A, Q, A]),
        Err(Impossible::QuarantineOutsideSettlement)
    );
    // A mismatch identity equal to V is V′ (or V): after `post_validated{mismatch}` the
    // aside may hold V′, and F5 restores it as D.
    let mismatch = build(rp, RP_PVM).unwrap();
    let obs = observe(rp, &mismatch, [S, VM, A]).unwrap();
    assert_eq!(
        decide(rp, &mismatch, &obs),
        StepDecision::Restore(RestoreStep::Exchange)
    );
    assert!(observe(rp, &mismatch, [S, D, A]).is_ok());
    assert!(observe(rp, &mismatch, [S, DM, A]).is_ok());
    // S's identity at two names.
    let staged = build(rp, RP_ST).unwrap();
    assert_eq!(
        observe(rp, &staged, [S, S, A]),
        Err(Impossible::RecordedAtTwoNames)
    );
    assert_eq!(
        observe(rp, &staged, [SM, S, A]),
        Err(Impossible::RecordedAtTwoNames)
    );
    let validated = build(rp, RP_VA).unwrap();
    assert_eq!(
        observe(rp, &validated, [V, VM, A]),
        Err(Impossible::RecordedAtTwoNames)
    );
    // D without a mismatch.
    let exchanged = build(rp, RP_EX).unwrap();
    assert_eq!(
        observe(rp, &exchanged, [S, D, A]),
        Err(Impossible::DisplacedWithoutMismatch)
    );
    // V for a step whose base was absent (create, git_lock).
    let created = build(StepShape::Create, CR_EX).unwrap();
    assert_eq!(
        observe(StepShape::Create, &created, [S, V, A]),
        Err(Impossible::ValidatedWithoutBase)
    );
    let k = build(StepShape::GitLock, K_ST).unwrap();
    assert_eq!(
        observe(StepShape::GitLock, &k, [VM, S, A]),
        Err(Impossible::ValidatedWithoutBase)
    );
    // A slot entry with no settlement (and `?` there: no slot is named).
    for slot in [S, X, U] {
        assert_eq!(
            observe(rp, &validated, [V, A, slot]),
            Err(Impossible::SlotWithoutSettlement),
            "{slot:?}"
        );
    }
    let nothing_displaced = build(
        StepShape::Create,
        &[F(0, St), F(0, VaA), F(0, Ex), F(0, PvV), C(SSH), F(0, SdN)],
    )
    .unwrap();
    assert_eq!(
        observe(StepShape::Create, &nothing_displaced, [S, A, X]),
        Err(Impossible::SlotWithoutSettlement)
    );
    // `release_due` on a non-git_lock shape.
    let due = build(StepShape::GitLock, K_ST_DUE).unwrap();
    assert!(due.release_due);
    assert!(observe(StepShape::GitLock, &due, [S, A, A]).is_ok());
    for shape in [StepShape::Replace, StepShape::Create, StepShape::Removal] {
        assert_eq!(
            observe(shape, &due, [A, A, A]),
            Err(Impossible::LockStateOnOtherShape)
        );
    }
    // The cleaner's slot is derived from its locator: L there needs no settlement, but
    // L at the path and in the slot is one identity at two names.
    let rm = StepShape::Removal;
    let none = build(rm, &[]).unwrap();
    assert!(observe(rm, &none, [A, A, V]).is_ok());
    assert!(observe(rm, &none, [X, A, VM]).is_ok());
    assert_eq!(
        observe(rm, &none, [V, A, VM]),
        Err(Impossible::RecordedAtTwoNames)
    );
    assert_eq!(
        observe(rm, &none, [S, A, V]),
        Err(Impossible::RecordedAtTwoNames)
    );
    // `?` is never impossible by itself; it reaches decide, which holds it first.
    let obs = observe(rp, &validated, [U, S, A]).unwrap();
    assert_eq!(
        decide(rp, &validated, &obs),
        StepDecision::Hold(HoldReason::Unobservable)
    );
}

// --- 7. the item rows ----------------------------------------------------------------

#[test]
fn decide_item_vectors_t0_t1_t1h_t2_t3_t4_th() {
    use StepState::{
        CommitNeverExchanged, CommitRestored, ExchangedConsistent, ExchangedInconsistent, Final,
        Held, Open,
    };
    for (row, steps, receipts, want) in item_vectors() {
        assert_eq!(decide_item(&steps, &receipts), want, "{row}");
    }
    let none = ItemReceipts::default();
    let committed = ItemReceipts {
        committed: true,
        ..none
    };
    let rolling = ItemReceipts {
        rolling_back: Some(ConflictKind::UserConfigChanged),
        ..none
    };
    // T0 never with an item receipt: committed or rolling back finishes that way.
    assert_eq!(
        decide_item(&[CommitNeverExchanged], &committed),
        ItemDecision::FinishForward
    );
    assert_eq!(
        decide_item(&[CommitNeverExchanged], &rolling),
        ItemDecision::FinishRestore
    );
    // T1 needs every exchanged step consistent; T1h runs no check.
    assert_eq!(
        decide_item(&[ExchangedInconsistent, ExchangedConsistent], &none),
        ItemDecision::Hold(HoldReason::DisplacedReplaced)
    );
    // T2 never restores, T3 never commits.
    assert_eq!(
        decide_item(&[ExchangedConsistent], &committed),
        ItemDecision::FinishForward
    );
    assert_eq!(
        decide_item(&[ExchangedConsistent], &rolling),
        ItemDecision::FinishRestore
    );
    // TH: a held step holds an open, committed or rolling-back item, with its own
    // reason, never the retired `unmatched` placeholder (ADR-0007 §12.17 item 4).
    for r in [none, committed, rolling] {
        for reason in HOLD_REASONS {
            assert_eq!(
                decide_item(&[Final, Held(reason)], &r),
                ItemDecision::Hold(reason),
                "{r:?}"
            );
        }
    }
    // T3 from the commit step's own restore takes precedence over nothing that holds,
    // and is T3 whatever the other steps are.
    for other in [Open, Final, ExchangedConsistent, ExchangedInconsistent] {
        assert_eq!(
            decide_item(&[other, CommitRestored], &none),
            ItemDecision::FinishRestore,
            "{other:?}"
        );
    }
    assert_eq!(
        decide_item(&[CommitRestored, Held(HoldReason::ThirdWriter)], &none),
        ItemDecision::Hold(HoldReason::ThirdWriter)
    );
    // Every step final with no item receipt and no commit-step class is no item row:
    // the file-level T3 is read from `CommitRestored`, never inferred from `Final`.
    assert_eq!(
        decide_item(&[Final, Final], &none),
        ItemDecision::Hold(HoldReason::Unmatched)
    );
    // An item still in progress (a step's row continues) matches no item row.
    assert_eq!(
        decide_item(&[Open, Final], &none),
        ItemDecision::Hold(HoldReason::Unmatched)
    );
    assert_eq!(
        decide_item(&[], &none),
        ItemDecision::Hold(HoldReason::Unmatched)
    );
}

// --- property tests ------------------------------------------------------------------

/// A five-step intent with every shape: user_ssh replace (commit), git_managed create,
/// git_lock, git_include replace (commit), managed_ssh removal.
fn mixed_intent() -> Vec<FileStep> {
    vec![
        file_step(FileRole::UserSsh, true, true, true),
        file_step(FileRole::GitManaged, false, true, false),
        file_step(FileRole::GitLock, false, false, false),
        file_step(FileRole::GitInclude, true, true, true),
        file_step(FileRole::ManagedSsh, true, false, false),
    ]
}

fn arb_event() -> impl Strategy<Value = Ev> {
    let item = prop_oneof![Just(SSH), Just(GIT)];
    prop_oneof![
        4 => (0u16..5, proptest::sample::select(ALL_PH.to_vec())).prop_map(|(s, p)| F(s, p)),
        1 => item.clone().prop_map(C),
        1 => item.clone().prop_map(R),
        1 => (item, proptest::sample::select(OUTCOMES.to_vec())).prop_map(|(i, o)| Fin(i, o)),
        2 => (0u16..5).prop_map(H),
    ]
}

fn arb_obs() -> impl Strategy<Value = EntryObs> {
    proptest::sample::select(SYMBOLS.to_vec())
}

fn arb_cause() -> impl Strategy<Value = RestoreCause> {
    prop_oneof![
        Just(RestoreCause::FileMismatch),
        Just(RestoreCause::TransactionCheck)
    ]
}

/// Any `RecoveryState` the types allow, built by `build` or not.
fn arb_state() -> impl Strategy<Value = RecoveryState> {
    let phase = proptest::option::of(proptest::sample::select(ALL_PH.to_vec()));
    let restore = prop_oneof![
        Just(RestoreCtx::NotDue),
        arb_cause().prop_map(RestoreCtx::Due),
        arb_cause().prop_map(RestoreCtx::Started),
        arb_cause().prop_map(RestoreCtx::Done),
    ];
    let source = prop_oneof![
        Just(SettleSource::Staged),
        Just(SettleSource::Displaced),
        Just(SettleSource::Path)
    ];
    let settlement = proptest::option::of((source, any::<bool>()).prop_map(
        |(source, create_restore)| SettleCtx {
            source,
            create_restore,
        },
    ));
    let item = prop_oneof![
        Just(ItemState::Open),
        Just(ItemState::Committed),
        Just(ItemState::RollingBack),
        Just(ItemState::Finished)
    ];
    (phase, restore, settlement, item, any::<bool>()).prop_map(
        |(phase, restore, settlement, item, release_due)| RecoveryState {
            phase: phase.map(effective),
            restore,
            settlement,
            item,
            release_due,
        },
    )
}

proptest! {
    #![proptest_config(config(512))]

    /// `build` never panics on any receipt list, and dropping every `held` receipt
    /// from it changes no step's result (M2-T04).
    #[test]
    fn recovery_state_build_ignores_held_in_arbitrary_histories(
        events in proptest::collection::vec(arb_event(), 0..14)
    ) {
        let files = mixed_intent();
        let all = receipts(&events);
        let without: Vec<Ev> = events.iter().copied().filter(|e| !matches!(e, H(_))).collect();
        let without = receipts(&without);
        for step in 0..5u16 {
            let got = RecoveryState::build(step, &all, &files);
            prop_assert_eq!(&got, &RecoveryState::build(step, &without, &files));
            if let Ok(state) = got {
                let shape = StepShape::of(&files[usize::from(step)]);
                prop_assert!(!state.release_due || shape == StepShape::GitLock);
                let last = events.iter().rev().find_map(|e| match e {
                    F(s, ph) if *s == step => Some(effective(*ph)),
                    _ => None,
                });
                prop_assert_eq!(state.phase, last);
            }
        }
    }

    /// `decide` is total over every state the types allow (not only built ones) and
    /// every normalized observation, and keeps every property there too.
    #[test]
    fn recovery_decide_keeps_the_properties_over_arbitrary_states(
        state in arb_state(),
        shape in proptest::sample::select(SHAPES.to_vec()),
        p in arb_obs(),
        a in arb_obs(),
        s in arb_obs(),
    ) {
        if let Ok(obs) = StepObservation::normalize(p, a, s, &state, shape) {
            let d = decide(shape, &state, &obs);
            prop_assert_eq!(violations(shape, &state, &obs, d), Vec::<Prop>::new(), "{:?}", d);
        }
    }
}
