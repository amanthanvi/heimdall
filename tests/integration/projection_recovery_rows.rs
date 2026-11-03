//! m02-plan U4 `recovery_table_rows_each_have_a_test_vector`, filesystem-backed
//! (ADR-0007 §5.7 "m02-plan U4 test … keeps the other direction"; §12.19 item 10).
//!
//! Cargo test target `integration_projection_recovery_rows` hosted by
//! `heimdall-localenv`. For every row ID of ADR-0007 §5.7's recovery tables (F0–F9d,
//! C1–C8, K0–K4, R1–R6, T0–TH; H0 and G0–G3 are withdrawn), read from the ADR the
//! same way `model_projection_recovery`'s `recovery_table_rows_each_decide_as_their_row`
//! reads them, the test has at least one vector. A vector:
//!
//! 1. builds a scratch world (a `heimdall_testkit::home::ScratchHome`) and a real
//!    intent from the writer's own preview (see [`Wk`]);
//! 2. builds the row's observed entries in the scratch directory together with the
//!    step's receipts, appended durably through a store-backed `StageSink` (an
//!    in-memory `heimdall_store::Store` with the operation admitted by
//!    `Txn::insert_setup_operation`, as `integration_projection` does);
//! 3. observes the step through the public classifier (`replace::observe_step_at`
//!    over `RecoveryState::build` and `StepRecord`), checks the symbols, checks that
//!    the first row of the ADR's tables naming that phase and those symbols is the
//!    vector's row, and checks that `recovery::decide` (`decide_item` for the item
//!    rows) gives the vector's action, which must agree with the row's action cell;
//! 4. runs `reconcile` through a fresh `LocalProjection` (the cleaner,
//!    `cleaner::delete_locator`, for the R rows) with a recording `ReplaceHook`, and
//!    asserts the receipts written (in order, read back from the store), the item
//!    outcome, and that the step's first receipts are the receipts of its decided
//!    action (`recovery::effects`);
//! 5. checks properties every correct table has: no entry is lost except by a
//!    verified removal from the quarantine (a `file.settled` for that identity, or the
//!    cleaner's locator identity and digest), no existing file's content changes, a
//!    run that only holds moves nothing, and a second run writes and moves nothing.
//!
//! A row without a vector fails the test. Rows that only a state this filesystem
//! cannot represent reaches are named in [`NOT_REPRESENTABLE`] with the reason, and
//! the test prints them; the list is empty on Unix. T1h is reached on disk through
//! its exchanged step's own hold (see its vector). Vectors marked `ESCALATED` pin the
//! writer's current receipt or outcome where the ADR's row words it differently,
//! pending a ruling.
//!
//! Nothing outside the scratch root is read or written: the writer is configured with
//! `SshPaths::with_test_override`; the specs have no aliases, so no key file and no
//! public key is materialized; no SSH client is run. The only process is `git`, run
//! by the writer's own parse check of B_git's staged bytes in the Git worlds, with the
//! scratch `HOME`, `XDG_CONFIG_HOME` and `GIT_CONFIG_SYSTEM` only (as
//! `integration_projection_git` configures it).
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::print_stdout,
    missing_docs
)]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use heimdall_app::ports::{ItemOutcome, ProjectionWriter, SinkError, StageSink};
use heimdall_contract::ids::{EnvironmentId, OperationId};
use heimdall_contract::setup::{ConflictKind, PreviewIntent, ProjectionItem};
use heimdall_domain::operation::{
    AdapterIdentity, EffectReceipt, FilePhase, HoldReason, ItemFinish, ItemPhase, LocalReceipt,
    PostVerdict, RestoreCause, SettleConflictFound, SettleSource, SettledDisposition, StageReceipt,
};
use heimdall_domain::projection::{
    Base, ConsentRecord, ContentState, EffectivePhase, EntryObs, FileIdentity, FileRole, FileStep,
    ItemCommit, ItemRecord, ItemState, ProjectionLocator, ProjectionRecord, ProjectionSpec,
    RecordedRole, RecoveryState, RestoreCtx, SetupIntent, Sha256Hex, StepContentView,
    StepObservation, StepShape,
};
use heimdall_localenv::clients::{ClientCandidate, ClientInventory, ClientKind, ClientSource};
use heimdall_localenv::env::{Env, Platform};
use heimdall_localenv::local_query::LocalQueries;
use heimdall_localenv::paths::SshPaths;
use heimdall_localenv::projection::cleaner::{delete_locator, slot_name};
use heimdall_localenv::projection::content::{Materialized, materialize};
use heimdall_localenv::projection::recovery::{
    AbortStep, Effect, ForwardStep, ItemDecision, ItemReceipts, RestoreStep, SettleStep,
    StepDecision, StepState, decide, decide_item, effects,
};
use heimdall_localenv::projection::replace::{
    self, DirHandle, Expected, Mode, NameState, Quarantine, SettlingAt, StepRecord, observe_step_at,
};
use heimdall_localenv::projection::{LocalProjection, ProjectionConfig, ReplaceHook, ReplacePoint};
use heimdall_localenv::sys::IdentitySource;
use heimdall_testkit::home::{ScratchHome, find_program};

// --- the ADR's own tables, read from ADR-0007 §5.7 ---------------------------------------
//
// The reader and the matching rules below are `model_projection_recovery`'s
// (`tests/model/projection_recovery.rs`, "the ADR's own tables"), restated here
// because two Cargo test targets share no code: the same row IDs, in the same order,
// with the same phase and symbol readings, so the two tests cover the same rows.

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
fn adr_rows() -> &'static [AdrRow] {
    static ROWS: OnceLock<Vec<AdrRow>> = OnceLock::new();
    ROWS.get_or_init(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
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
    })
}

/// Whether `st` is in the phase an ADR "Phase" cell names (the model test's reading).
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

/// Whether `e` is one of the symbols an ADR cell lists (the model test's reading: `*`,
/// "any other" and an empty cell match every symbol but `?`; D after a forward
/// exchange is V or V′; K is S; the removal's L is the locator's entry, V or S).
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
/// step in document order, as `decide` does.
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

/// The wire (snake_case) name of a unit enum value.
macro_rules! snake {
    ($v:expr) => {
        serde_json::to_value($v)
            .ok()
            .and_then(|j| j.as_str().map(str::to_owned))
            .unwrap_or_else(|| "?".to_owned())
    };
}

/// The `HoldReason` names an ADR action cell gives (`` `displaced_missing` `` …).
fn adr_hold_reasons(action: &str) -> Vec<HoldReason> {
    HOLD_REASONS
        .into_iter()
        .filter(|r| action.contains(&format!("`{}`", snake!(*r))))
        .collect()
}

/// A hold whose row is not marked **H** or names no reason, with the ruling that reads
/// it so (the model test's list): R6 (ADR-0007 §12.17 item 7) and T1h (F4c's reason).
const HOLD_READINGS: &[(&str, HoldReason)] = &[
    ("R6", HoldReason::ThirdWriter),
    ("T1h", HoldReason::DisplacedReplaced),
];

/// Rows whose action is a hold in one case and a move in another (F8a: a create
/// restore whose source is Q′ holds).
const MIXED_ROWS: &[&str] = &["F8a"];

/// Whether a decision agrees with `row`'s action cell: a hold only where the row is
/// **H** with that reason (or a [`HOLD_READINGS`] entry, or for TH the held step's own
/// reason), and anything else only where the row is not **H** (or is mixed).
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

/// Rows only a state this platform's filesystem cannot represent reaches, with the
/// reason. Each is printed and reported by the integrator; none is skipped silently.
/// Empty on Unix: every row is built on disk.
const NOT_REPRESENTABLE: &[(&str, &str)] = &[];

// --- symbols ------------------------------------------------------------------------------

const fn rec(which: RecordedRole, content: ContentState) -> EntryObs {
    EntryObs::Recorded { which, content }
}

const A: EntryObs = EntryObs::Absent;
const X: EntryObs = EntryObs::Foreign;
const U: EntryObs = EntryObs::Unobservable;
const S: EntryObs = rec(RecordedRole::S, ContentState::Unchanged);
const SM: EntryObs = rec(RecordedRole::S, ContentState::Modified);
const V: EntryObs = rec(RecordedRole::V, ContentState::Unchanged);
const VM: EntryObs = rec(RecordedRole::V, ContentState::Modified);
const D: EntryObs = rec(RecordedRole::D, ContentState::Unchanged);
const DM: EntryObs = rec(RecordedRole::D, ContentState::Modified);
const Q: EntryObs = rec(RecordedRole::Q, ContentState::Unchanged);
const QM: EntryObs = rec(RecordedRole::Q, ContentState::Modified);

// --- the scratch worlds ---------------------------------------------------------------------

const USER_TEXT: &str =
    "# my settings\n\nHost personal\n    HostName personal.example.invalid\n    User me\n";

/// The scratch world a vector starts from. Each is the writer's own preview of a spec
/// with no aliases, over files arranged so the intent has the steps named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wk {
    /// A first adoption over an existing user file, with P already holding exactly what
    /// the plan renders (so it has no step): `[U (replace, commit)]`.
    Replace,
    /// A first adoption with no user file and P already rendered: `[U (create,
    /// commit)]`.
    Create,
    /// A first adoption over an existing user file: `[P (create), U (replace,
    /// commit)]`.
    PThenU,
    /// The Git item after the SSH item applied, with P_git already rendered and an
    /// existing (empty) global Git file: `[K (git_lock), B_git (replace, commit)]`.
    Git,
    /// [`Wk::Git`] with the test-only identity source without birth times (a Unix
    /// filesystem that records none; ADR-0007 F25, QR15): K at the lock is not
    /// provable.
    GitNoBirth,
}

impl Wk {
    fn git(self) -> bool {
        matches!(self, Wk::Git | Wk::GitNoBirth)
    }

    fn item(self) -> ProjectionItem {
        if self.git() {
            ProjectionItem::Git
        } else {
            ProjectionItem::Ssh
        }
    }

    fn source(self) -> IdentitySource {
        if self == Wk::GitNoBirth {
            IdentitySource::WithoutBirth
        } else {
            IdentitySource::Native
        }
    }
}

/// A sink that drops everything: only for arranging a world (the SSH item applied
/// before a Git world's intent is previewed).
struct Discard;

impl StageSink for Discard {
    fn append(&mut self, _: &LocalReceipt) -> Result<(), SinkError> {
        Ok(())
    }

    fn commit_item(&mut self, _: ItemCommit) -> Result<(), SinkError> {
        Ok(())
    }
}

/// The test hook: records every point reached; does nothing else.
#[derive(Default)]
struct Recorder(Mutex<Vec<(ReplacePoint, u16)>>);

impl ReplaceHook for Recorder {
    fn at(&self, point: ReplacePoint, step: u16) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((point, step));
    }
}

impl Recorder {
    fn reached(&self, point: ReplacePoint) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(p, _)| *p == point)
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct World {
    home: ScratchHome,
    kind: Wk,
    env: EnvironmentId,
    intent: SetupIntent,
    /// Each step's base bytes as the world left them (`None` for an absent base).
    bases: Vec<Option<Vec<u8>>>,
    store: Arc<heimdall_store::Store>,
    op: OperationId,
}

/// The writer's configuration for a world (the Git worlds' scratch Git environment,
/// local queries and client inventory as `integration_projection_git` sets them).
fn config_for(home: &ScratchHome, kind: Wk) -> ProjectionConfig {
    let paths = SshPaths::with_test_override(home.git_home.clone(), home.root.join("etc-ssh"));
    let mut c = ProjectionConfig::new(paths, Platform::current(), home.config_dir.clone());
    c.test.identity = kind.source();
    if kind.git() {
        let system = home.root.join("gitconfig-system");
        if !system.exists() {
            std::fs::write(&system, b"").unwrap();
        }
        c.env = Env::from_vars(vec![
            ("HOME", home.git_home.to_str().unwrap().to_owned()),
            (
                "XDG_CONFIG_HOME",
                home.git_home.join(".config").to_str().unwrap().to_owned(),
            ),
            ("GIT_CONFIG_SYSTEM", system.to_str().unwrap().to_owned()),
        ]);
        c.queries = LocalQueries::Enabled;
        c.clients = ClientInventory {
            candidates: vec![
                ClientCandidate {
                    kind: ClientKind::Git,
                    path: find_program("git").expect("git is installed on the harness"),
                    source: ClientSource::Path,
                    version: None,
                    sha256: None,
                    selected: true,
                },
                ClientCandidate {
                    kind: ClientKind::Ssh,
                    path: PathBuf::from("/usr/bin/ssh"),
                    source: ClientSource::Path,
                    version: None,
                    sha256: None,
                    selected: true,
                },
            ],
        };
        c.test.git_item_any_default = true;
    }
    c
}

/// The writer's preview of a spec with no aliases.
fn preview_in(
    home: &ScratchHome,
    kind: Wk,
    env: &EnvironmentId,
    intent: &PreviewIntent,
) -> SetupIntent {
    let spec = ProjectionSpec {
        environment: env.clone(),
        aliases: Vec::new(),
        record: None,
        consent: ConsentRecord::default(),
    };
    LocalProjection::new(config_for(home, kind))
        .preview(&spec, intent)
        .unwrap()
        .intent()
}

/// Write the whole content of `role`'s step to its path, as the plan renders it.
fn render(intent: &SetupIntent, role: FileRole) {
    let step = intent.files.iter().find(|s| s.role == role).unwrap();
    let StepContentView::Whole { bytes } = step.content.view() else {
        panic!("{role:?} is not a whole file");
    };
    write_mode(Path::new(&step.path), bytes, 0o600);
}

impl World {
    fn new(kind: Wk) -> World {
        let home = ScratchHome::new();
        std::fs::create_dir(home.root.join("etc-ssh")).unwrap();
        let env = EnvironmentId::from_random_bytes(random());
        match kind {
            Wk::Create => std::fs::remove_file(&home.user_config).unwrap(),
            _ => write_mode(&home.user_config, USER_TEXT.as_bytes(), 0o600),
        }
        let ssh_only = PreviewIntent::Apply { include_git: false };
        let mut intent = preview_in(&home, kind, &env, &ssh_only);
        match kind {
            Wk::Replace | Wk::Create => {
                render(&intent, FileRole::ManagedSsh);
                intent = preview_in(&home, kind, &env, &ssh_only);
            }
            Wk::PThenU => {}
            Wk::Git | Wk::GitNoBirth => {
                let r = LocalProjection::new(config_for(&home, kind))
                    .apply(&intent, &mut Discard)
                    .unwrap();
                assert!(
                    matches!(r.items.as_slice(), [ItemOutcome::Applied { .. }]),
                    "{r:?}"
                );
                let git = PreviewIntent::Apply { include_git: true };
                intent = preview_in(&home, kind, &env, &git);
                render(&intent, FileRole::GitManaged);
                intent = preview_in(&home, kind, &env, &git);
            }
        }
        let shapes: Vec<(FileRole, StepShape, bool)> = intent
            .files
            .iter()
            .map(|s| (s.role, StepShape::of(s), s.commit))
            .collect();
        let want: &[(FileRole, StepShape, bool)] = match kind {
            Wk::Replace => &[(FileRole::UserSsh, StepShape::Replace, true)],
            Wk::Create => &[(FileRole::UserSsh, StepShape::Create, true)],
            Wk::PThenU => &[
                (FileRole::ManagedSsh, StepShape::Create, false),
                (FileRole::UserSsh, StepShape::Replace, true),
            ],
            Wk::Git | Wk::GitNoBirth => &[
                (FileRole::GitLock, StepShape::GitLock, false),
                (FileRole::GitInclude, StepShape::Replace, true),
            ],
        };
        assert_eq!(shapes, want, "the {kind:?} world's intent");
        let bases = intent
            .files
            .iter()
            .map(|s| match s.base {
                Base::Present { .. } => Some(std::fs::read(&s.path).unwrap()),
                Base::Absent => None,
            })
            .collect();
        let w = World {
            home,
            kind,
            env,
            intent,
            bases,
            store: Arc::new(
                heimdall_store::Store::open_in_memory(Arc::new(heimdall_store::NoFaults)).unwrap(),
            ),
            op: OperationId::from_random_bytes(random()),
        };
        w.admit();
        w
    }

    fn config(&self) -> ProjectionConfig {
        config_for(&self.home, self.kind)
    }

    fn hooked(&self, hook: &Arc<Recorder>) -> ProjectionConfig {
        let mut c = self.config();
        let h: Arc<dyn ReplaceHook> = hook.clone();
        c.hook = Some(h);
        c
    }

    fn step_of(&self, role: FileRole) -> u16 {
        u16::try_from(
            self.intent
                .files
                .iter()
                .position(|s| s.role == role)
                .unwrap(),
        )
        .unwrap()
    }

    /// Admit the operation with its intent (`Txn::insert_setup_operation`).
    fn admit(&self) {
        use heimdall_contract::EffectStatus;
        use heimdall_contract::canonical::RequestHash;
        use heimdall_contract::ids::RequestId;
        use heimdall_contract::state::OperationState;
        use heimdall_domain::idempotency::{IdempotencyKey, IdempotencyRecord};
        use heimdall_domain::operation::{
            EffectClass, LocalIntent, OperationKind, OperationRecord, RecoveryIntent,
            RecoveryMetadata,
        };
        use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
        let key = IdempotencyKey {
            caller: CallerContext {
                principal: PrincipalRef::UnixUser { uid: 501 },
                role: ClientRole::Owner,
            },
            kind: OperationKind::SetupApply,
            request_id: RequestId::parse("setup-rows").unwrap(),
        };
        let now = heimdall_contract::Timestamp::now();
        let record = OperationRecord {
            id: self.op.clone(),
            kind: OperationKind::SetupApply,
            environment: self.env.clone(),
            key: key.clone(),
            request_hash: RequestHash(random()),
            effect_class: EffectClass::LocalResources,
            state: OperationState::Running,
            code: None,
            effect_status: EffectStatus::None,
            result: None,
            created_at: now,
            updated_at: now,
            cancellation: None,
            recovery: RecoveryMetadata::default(),
        };
        let idem = IdempotencyRecord {
            key,
            request_hash: record.request_hash,
            operation_id: self.op.clone(),
            created_at: now,
            expires_at: None,
        };
        let recovery = RecoveryIntent {
            request: serde_json::json!({"action": "setup.apply", "request_id": "setup-rows"}),
            resolved: None,
            local: Some(LocalIntent::Setup(self.intent.clone())),
        };
        self.store
            .transaction(|tx| tx.insert_setup_operation(&record, &idem, &recovery, None))
            .unwrap();
    }

    fn sink(&self) -> StoreSink {
        StoreSink {
            store: Arc::clone(&self.store),
            op: self.op.clone(),
            env: self.env.clone(),
        }
    }

    fn receipts(&self) -> Vec<StageReceipt> {
        self.sink().receipts()
    }

    fn dir_of(&self, path: &Path) -> DirHandle {
        DirHandle::open_with(path, self.kind.source()).unwrap()
    }

    /// Observe step `i` through the public classifier, as `reconcile` does.
    fn observe(&self, i: u16, state: &RecoveryState, receipts: &[StageReceipt]) -> StepObservation {
        let step = &self.intent.files[usize::from(i)];
        let dir = self.dir_of(Path::new(&step.path).parent().unwrap());
        let record = StepRecord::from_receipts(i, step, receipts);
        let settling = SettlingAt::from_receipts(i, receipts);
        observe_step_at(&dir, step, &record, state, settling.as_ref())
    }

    /// The item rows' inputs from the receipts and a fresh observation: each step's
    /// `StepState`, classified in `recovery::StepState`'s documented order, and the
    /// item's own receipts.
    fn item_states(&self, receipts: &[StageReceipt]) -> (Vec<StepState>, ItemReceipts) {
        let item = self.kind.item();
        let mut rx = ItemReceipts::default();
        for r in receipts {
            if let Some(LocalReceipt::Item { item: it, phase }) = &r.local
                && *it == item
            {
                match phase {
                    ItemPhase::Committed { .. } => rx.committed = true,
                    ItemPhase::RollingBack { reason } => rx.rolling_back = Some(*reason),
                    ItemPhase::Finished { .. } => rx.finished = true,
                }
            }
        }
        let views: Vec<(u16, Option<RecoveryState>, StepObservation, StepDecision)> =
            (0..self.intent.files.len())
                .map(|i| {
                    let i = u16::try_from(i).unwrap();
                    let shape = StepShape::of(&self.intent.files[usize::from(i)]);
                    match RecoveryState::build(i, receipts, &self.intent.files) {
                        Ok(state) => {
                            let obs = self.observe(i, &state, receipts);
                            let dec = decide(shape, &state, &obs);
                            (i, Some(state), obs, dec)
                        }
                        Err(_) => (
                            i,
                            None,
                            StepObservation::normalize(A, A, A, &blank(), StepShape::Create)
                                .unwrap(),
                            StepDecision::Hold(HoldReason::ContradictoryReceipts),
                        ),
                    }
                })
                .collect();
        let exchanged = |i: u16| {
            receipts.iter().any(|r| {
                matches!(&r.local, Some(LocalReceipt::File { step, phase: FilePhase::Exchanged }) if *step == i)
            })
        };
        let commit_at_t1 = views.iter().any(|(i, st, ..)| {
            self.intent.files[usize::from(*i)].commit
                && st.as_ref().is_some_and(|s| {
                    s.item == ItemState::Open
                        && s.restore == RestoreCtx::NotDue
                        && matches!(
                            s.phase,
                            Some(EffectivePhase::PostValidated {
                                verdict: PostVerdict::Valid,
                                ..
                            })
                        )
                })
        });
        let states = views
            .iter()
            .map(|(i, st, obs, dec)| {
                if let StepDecision::Hold(r) = dec {
                    return StepState::Held(*r);
                }
                let Some(st) = st else {
                    return StepState::Held(HoldReason::ContradictoryReceipts);
                };
                let step = &self.intent.files[usize::from(*i)];
                let ex = exchanged(*i)
                    || (matches!(st.phase, Some(EffectivePhase::Validated { .. }))
                        && matches!(
                            dec,
                            StepDecision::Forward(ForwardStep::RecordExchanged)
                                | StepDecision::Restore(RestoreStep::RecordMismatch)
                        ));
                if step.commit && !ex {
                    return StepState::CommitNeverExchanged;
                }
                if step.commit
                    && matches!(
                        st.restore,
                        RestoreCtx::Started(RestoreCause::FileMismatch)
                            | RestoreCtx::Done(RestoreCause::FileMismatch)
                    )
                {
                    return StepState::CommitRestored;
                }
                if *dec == StepDecision::Settle(SettleStep::Done) {
                    return StepState::Final;
                }
                if commit_at_t1
                    && ex
                    && st.item == ItemState::Open
                    && st.restore == RestoreCtx::NotDue
                {
                    let path_s = matches!(
                        obs.path(),
                        EntryObs::Recorded {
                            which: RecordedRole::S,
                            ..
                        }
                    );
                    let aside_v = StepShape::of(step) != StepShape::Replace
                        || matches!(
                            obs.aside(),
                            EntryObs::Recorded {
                                which: RecordedRole::V,
                                ..
                            }
                        );
                    return if path_s && aside_v {
                        StepState::ExchangedConsistent
                    } else {
                        StepState::ExchangedInconsistent
                    };
                }
                StepState::Open
            })
            .collect();
        (states, rx)
    }

    /// Every file and symbolic link under the scratch `HOME` and Heimdall's
    /// configuration directory, by relative name.
    fn tree(&self) -> BTreeMap<String, Ent> {
        let mut out = BTreeMap::new();
        walk(&self.home.git_home, "home", &mut out);
        walk(&self.home.config_dir, "config", &mut out);
        out
    }
}

fn blank() -> RecoveryState {
    RecoveryState {
        phase: None,
        restore: RestoreCtx::NotDue,
        settlement: None,
        item: ItemState::Open,
        release_due: false,
    }
}

/// One entry of a scratch tree: identity and content (a link's target).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ent {
    dev: u64,
    ino: u64,
    link: bool,
    bytes: Vec<u8>,
}

fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Ent>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd {
        let e = e.unwrap();
        let name = format!("{prefix}/{}", e.file_name().to_string_lossy());
        let m = std::fs::symlink_metadata(e.path()).unwrap();
        if m.is_dir() {
            walk(&e.path(), &name, out);
        } else if m.file_type().is_symlink() {
            let t = std::fs::read_link(e.path()).unwrap();
            out.insert(
                name,
                Ent {
                    dev: m.dev(),
                    ino: m.ino(),
                    link: true,
                    bytes: t.to_string_lossy().as_bytes().to_vec(),
                },
            );
        } else if m.is_file() {
            out.insert(
                name,
                Ent {
                    dev: m.dev(),
                    ino: m.ino(),
                    link: false,
                    bytes: std::fs::read(e.path()).unwrap_or_default(),
                },
            );
        }
    }
}

fn same_inode(id: &FileIdentity, e: &Ent) -> bool {
    matches!(id, FileIdentity::Unix { dev, ino, .. } if *dev == e.dev && *ino == e.ino)
}

// --- the store-backed sink -----------------------------------------------------------------

fn adapter() -> AdapterIdentity {
    AdapterIdentity {
        mechanism: "config_projection".into(),
        instance: "scratch".into(),
    }
}

fn durable(local: &LocalReceipt) -> StageReceipt {
    StageReceipt {
        stage: local.stage().to_owned(),
        recorded_at: heimdall_contract::Timestamp::now(),
        effect: if local.effect_is_confirmed() {
            EffectReceipt::Confirmed {
                adapter: adapter(),
                credential_ref: "projection".into(),
            }
        } else {
            EffectReceipt::Attempted {
                adapter: adapter(),
                effect_token: "eff_scratch".into(),
            }
        },
        local: Some(local.clone()),
    }
}

/// A `StageSink` over the real store (`integration_projection`'s, U5's sink in
/// miniature): each receipt in its own transaction, the commit through
/// `Txn::commit_projection_item` with the record's environment, operation and time
/// filled in.
struct StoreSink {
    store: Arc<heimdall_store::Store>,
    op: OperationId,
    env: EnvironmentId,
}

impl StoreSink {
    fn receipts(&self) -> Vec<StageReceipt> {
        self.store
            .transaction(|tx| tx.stage_receipts(&self.op))
            .unwrap()
    }
}

impl StageSink for StoreSink {
    fn append(&mut self, receipt: &LocalReceipt) -> Result<(), SinkError> {
        let r = durable(receipt);
        self.store
            .transaction(|tx| tx.append_stage_receipt(&self.op, &r))
            .map_err(|e| SinkError(e.to_string()))
    }

    fn commit_item(&mut self, mut commit: ItemCommit) -> Result<(), SinkError> {
        let now = heimdall_contract::Timestamp::now();
        commit.record.environment = self.env.clone();
        for r in commit.record.items.values_mut() {
            r.operation = self.op.clone();
            r.committed_at = now;
        }
        let receipt = durable(&LocalReceipt::Item {
            item: commit.item,
            phase: ItemPhase::Committed {
                generation: commit.generation,
            },
        });
        self.store
            .transaction(|tx| tx.commit_projection_item(&self.op, &commit, &receipt))
            .map_err(|e| SinkError(e.to_string()))
    }
}

/// A receipt as the vectors spell it: `<step>:<phase>` or `<item>:<phase>`, with the
/// verdict, source, disposition, conflict or hold reason where the phase has one.
fn kind(local: &LocalReceipt) -> String {
    match local {
        LocalReceipt::File { step, phase } => {
            let k = match phase {
                FilePhase::Staged { .. } => "staged".to_owned(),
                FilePhase::Validated { .. } => "validated".to_owned(),
                FilePhase::Exchanged => "exchanged".to_owned(),
                FilePhase::PostValidated {
                    verdict: PostVerdict::Valid,
                    ..
                } => "post_validated".to_owned(),
                FilePhase::PostValidated { .. } => "post_validated_mismatch".to_owned(),
                FilePhase::RestoreStarted { .. } => "restore_started".to_owned(),
                FilePhase::Restored => "restored".to_owned(),
                FilePhase::Held { reason, .. } => format!("held:{}", snake!(*reason)),
                FilePhase::Settling { source, .. } => format!("settling:{}", snake!(*source)),
                FilePhase::Settled {
                    disposition: SettledDisposition::Quarantined,
                } => "settled".to_owned(),
                FilePhase::Settled { .. } => "settled_nothing_displaced".to_owned(),
                FilePhase::SettleConflict { found, .. } => {
                    format!("settle_conflict:{}", snake!(*found))
                }
            };
            format!("{step}:{k}")
        }
        LocalReceipt::Item { item, phase } => {
            let i = if *item == ProjectionItem::Ssh {
                "ssh"
            } else {
                "git"
            };
            let k = match phase {
                ItemPhase::Committed { .. } => "committed".to_owned(),
                ItemPhase::RollingBack { .. } => "rolling_back".to_owned(),
                ItemPhase::Finished { outcome } => format!("finished_{}", snake!(*outcome)),
            };
            format!("{i}:{k}")
        }
    }
}

/// The `recovery::effects` receipt kind of one of [`kind`]'s spellings.
fn effect_kind(k: &str) -> &str {
    let phase = k.split(':').nth(1).unwrap_or(k);
    match phase {
        "post_validated_mismatch" => "post_validated",
        "settled_nothing_displaced" => "settled",
        other => other,
    }
}

// --- the bench: building a row's entries and receipts ----------------------------------------

/// Builds the entries of one step in the scratch directory and appends its receipts
/// through the store-backed sink. The identities it records are read back through a
/// `DirHandle` with the world's identity source, as the writer reads them.
struct Bench<'w> {
    w: &'w World,
    sink: StoreSink,
    i: u16,
    /// S (K) as recorded by this bench, per step.
    s: BTreeMap<u16, FileIdentity>,
    /// V as recorded, per step.
    v: BTreeMap<u16, FileIdentity>,
    /// The open settlement's source name and slot, per step.
    settle: BTreeMap<u16, (String, String)>,
}

impl Bench<'_> {
    /// Build the step of `role` from here on.
    fn on(&mut self, role: FileRole) -> &mut Self {
        self.i = self.w.step_of(role);
        self
    }

    fn step(&self) -> &FileStep {
        &self.w.intent.files[usize::from(self.i)]
    }

    fn parent(&self) -> PathBuf {
        Path::new(&self.step().path).parent().unwrap().to_path_buf()
    }

    fn name(&self) -> String {
        Path::new(&self.step().path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(&self.step().path)
    }

    fn aside(&self) -> PathBuf {
        self.parent()
            .join(self.step().staged_name.as_ref().unwrap())
    }

    fn qdir(&self) -> PathBuf {
        self.parent().join(".hm-quarantine")
    }

    fn slot(&self) -> PathBuf {
        let (_, slot) = self.settle.get(&self.i).expect("a settlement is open");
        self.qdir().join(slot)
    }

    fn dir(&self) -> DirHandle {
        self.w.dir_of(&self.parent())
    }

    fn target(&self) -> Materialized {
        materialize(self.step(), self.w.bases[usize::from(self.i)].as_deref()).unwrap()
    }

    fn target_sha(&self) -> Sha256Hex {
        self.target().sha256
    }

    fn base_sha(&self) -> Sha256Hex {
        match &self.step().base {
            Base::Present { sha256 } => sha256.clone(),
            Base::Absent => panic!("the step has no base"),
        }
    }

    /// The identity of the regular file at `path`, as `replace::validate` reads it.
    fn id(&self, path: &Path) -> FileIdentity {
        let bytes = std::fs::read(path).unwrap();
        let dir = self.w.dir_of(path.parent().unwrap());
        let v = replace::validate(
            &dir,
            path.file_name().unwrap().to_str().unwrap(),
            &Base::Present {
                sha256: Sha256Hex::of(&bytes),
            },
        )
        .unwrap();
        v.identity.unwrap()
    }

    fn rec(&mut self, phase: FilePhase) -> &mut Self {
        self.sink
            .append(&LocalReceipt::File {
                step: self.i,
                phase,
            })
            .unwrap();
        self
    }

    fn rec_item(&mut self, phase: ItemPhase) -> &mut Self {
        self.sink
            .append(&LocalReceipt::Item {
                item: self.w.kind.item(),
                phase,
            })
            .unwrap();
        self
    }

    fn mode(&self) -> Mode {
        if self.step().role == FileRole::Key {
            Mode::PublicRead
        } else {
            Mode::OwnerReadWrite
        }
    }

    /// S (K) at the staged name, exclusively created as `replace::stage` does, with
    /// no receipt (rows F0x, K0x).
    fn put_s(&mut self, bytes: Materialized) -> FileIdentity {
        let staged = replace::stage(
            &self.dir(),
            self.step().staged_name.as_ref().unwrap(),
            &bytes,
            self.mode(),
        )
        .unwrap();
        self.s.insert(self.i, staged.identity.clone());
        staged.identity
    }

    /// S with the target bytes at the staged name, no receipt.
    fn stage_raw(&mut self) -> &mut Self {
        let t = self.target();
        self.put_s(t);
        self
    }

    /// A partly written S′ at the staged name, no receipt.
    fn stage_raw_partial(&mut self) -> &mut Self {
        let mut bytes = self.target().bytes;
        bytes.truncate(bytes.len() / 2);
        let sha256 = Sha256Hex::of(&bytes);
        self.put_s(Materialized { bytes, sha256 });
        self
    }

    /// `file.staged{S}` with S at the staged name.
    fn stage(&mut self) -> &mut Self {
        let t = self.target();
        let identity = self.put_s(t);
        self.rec(FilePhase::Staged { identity })
    }

    /// `file.validated{V}` (V the path's identity), or `{absent}` for a create.
    fn validated(&mut self) -> &mut Self {
        let base = match self.step().base {
            Base::Present { .. } => {
                let id = self.id(&self.path());
                self.v.insert(self.i, id.clone());
                Some(id)
            }
            Base::Absent => None,
        };
        self.rec(FilePhase::Validated { base })
    }

    /// The exchange on disk: path ↔ staged name (a create moves S to the path; K's
    /// claim moves K to the lock name).
    fn swap(&mut self) -> &mut Self {
        let (p, a) = (self.path(), self.aside());
        if p.exists() || std::fs::symlink_metadata(&p).is_ok() {
            let tmp = self.parent().join(".rows-swap");
            std::fs::rename(&p, &tmp).unwrap();
            std::fs::rename(&a, &p).unwrap();
            std::fs::rename(&tmp, &a).unwrap();
        } else {
            std::fs::rename(&a, &p).unwrap();
        }
        self
    }

    fn exchanged(&mut self) -> &mut Self {
        self.rec(FilePhase::Exchanged)
    }

    fn post_valid(&mut self) -> &mut Self {
        self.rec(FilePhase::PostValidated {
            verdict: PostVerdict::Valid,
            observed: None,
        })
    }

    /// `post_validated{mismatch}` with the identity now at the aside name (D).
    fn post_mismatch(&mut self) -> &mut Self {
        let observed = Some(self.id(&self.aside()));
        self.rec(FilePhase::PostValidated {
            verdict: PostVerdict::Mismatch,
            observed,
        })
    }

    /// Staged, validated, exchanged on disk and in the receipts, post-validated valid.
    fn forward(&mut self) -> &mut Self {
        self.stage().validated().swap().exchanged().post_valid()
    }

    fn restore_started(&mut self, cause: RestoreCause) -> &mut Self {
        self.rec(FilePhase::RestoreStarted { cause })
    }

    fn restored(&mut self) -> &mut Self {
        self.rec(FilePhase::Restored)
    }

    /// `file.settling` from `source` with a fresh slot: D (V, with the base digest) for
    /// `displaced`, S (K, with the target or holder digest) otherwise.
    fn settling(&mut self, source: SettleSource) -> &mut Self {
        let (name, expected, sha) = match source {
            SettleSource::Displaced => (
                self.step().displaced_name.clone().unwrap(),
                self.v[&self.i].clone(),
                self.base_sha(),
            ),
            SettleSource::Staged => (
                self.step().staged_name.clone().unwrap(),
                self.s[&self.i].clone(),
                self.target_sha(),
            ),
            SettleSource::Path => (self.name(), self.s[&self.i].clone(), self.target_sha()),
        };
        let slot: String = random::<16>().iter().map(|b| format!("{b:02x}")).collect();
        self.settle.insert(self.i, (name.clone(), slot.clone()));
        self.rec(FilePhase::Settling {
            source,
            name,
            expected,
            expected_sha256: sha,
            slot,
        })
    }

    /// Move the settlement's source into its slot (the quarantine created as the writer
    /// creates it).
    fn move_to_slot(&mut self) -> &mut Self {
        let _ = Quarantine::open_or_create(&self.dir()).unwrap();
        let (name, _) = self.settle[&self.i].clone();
        std::fs::rename(self.parent().join(name), self.slot()).unwrap();
        self
    }

    fn settled(&mut self) -> &mut Self {
        self.rec(FilePhase::Settled {
            disposition: SettledDisposition::Quarantined,
        })
    }

    /// The verified removal after `file.settled`.
    fn drop_slot(&mut self) -> &mut Self {
        std::fs::remove_file(self.slot()).unwrap();
        self
    }

    fn settle_conflict(&mut self, found: SettleConflictFound) -> &mut Self {
        self.rec(FilePhase::SettleConflict {
            found,
            kept: Vec::new(),
        })
    }

    /// `item.committed` through the sink's commit transaction, with the locators of the
    /// item's staged managed files.
    fn commit(&mut self) -> &mut Self {
        let item = self.w.kind.item();
        let generation = self.w.intent.generation;
        let resources: Vec<ProjectionLocator> = self
            .w
            .intent
            .files
            .iter()
            .enumerate()
            .filter(|(_, s)| matches!(s.role, FileRole::ManagedSsh | FileRole::GitManaged))
            .filter_map(|(j, s)| {
                let identity = self.s.get(&u16::try_from(j).unwrap())?.clone();
                let heimdall_domain::projection::Target::Present { sha256 } = &s.target else {
                    return None;
                };
                Some(ProjectionLocator {
                    role: s.role,
                    path: s.path.clone(),
                    identity,
                    sha256: sha256.clone(),
                })
            })
            .collect();
        let record = ProjectionRecord {
            environment: self.w.env.clone(),
            items: [(
                item,
                ItemRecord {
                    generation,
                    files: resources.clone(),
                    aliases: Vec::new(),
                    operation: self.w.op.clone(),
                    committed_at: heimdall_contract::Timestamp::now(),
                },
            )]
            .into_iter()
            .collect(),
        };
        self.sink
            .commit_item(ItemCommit {
                item,
                generation,
                resources,
                record,
                consent: ConsentRecord::default(),
            })
            .unwrap();
        self
    }

    fn rolling_back(&mut self) -> &mut Self {
        self.rec_item(ItemPhase::RollingBack {
            reason: ConflictKind::ManagedFileEdited,
        })
    }

    fn finished(&mut self, outcome: ItemFinish) -> &mut Self {
        self.rec_item(ItemPhase::Finished { outcome })
    }

    // Other writers: in-place edits keep the identity (S′, V′, Q′, K′); a rename-replace,
    // a symbolic link or a new file is another identity (X).

    fn edit(&mut self, path: &Path) -> &mut Self {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(b"# edited by another writer\n").unwrap();
        f.sync_all().unwrap();
        self
    }

    fn replace(&mut self, path: &Path) -> &mut Self {
        let tmp = path.with_file_name(".rows-editor-tmp");
        write_mode(&tmp, b"# another writer's file\n", 0o600);
        std::fs::rename(&tmp, path).unwrap();
        self
    }

    fn foreign(&mut self, path: &Path) -> &mut Self {
        assert!(
            std::fs::symlink_metadata(path).is_err(),
            "{}",
            path.display()
        );
        write_mode(path, b"# another writer's new file\n", 0o600);
        self
    }

    fn symlink(&mut self, path: &Path) -> &mut Self {
        std::os::unix::fs::symlink("elsewhere", path).unwrap();
        self
    }

    fn rm(&mut self, path: &Path) -> &mut Self {
        std::fs::remove_file(path).unwrap();
        self
    }

    fn edit_path(&mut self) -> &mut Self {
        let p = self.path();
        self.edit(&p)
    }

    fn edit_aside(&mut self) -> &mut Self {
        let p = self.aside();
        self.edit(&p)
    }

    fn edit_slot(&mut self) -> &mut Self {
        let p = self.slot();
        self.edit(&p)
    }

    fn replace_path(&mut self) -> &mut Self {
        let p = self.path();
        self.replace(&p)
    }

    fn replace_aside(&mut self) -> &mut Self {
        let p = self.aside();
        self.replace(&p)
    }

    fn foreign_path(&mut self) -> &mut Self {
        let p = self.path();
        self.foreign(&p)
    }

    fn foreign_aside(&mut self) -> &mut Self {
        let p = self.aside();
        self.foreign(&p)
    }

    fn foreign_slot(&mut self) -> &mut Self {
        let _ = Quarantine::open_or_create(&self.dir()).unwrap();
        let p = self.slot();
        self.foreign(&p)
    }

    fn rm_path(&mut self) -> &mut Self {
        let p = self.path();
        self.rm(&p)
    }

    fn rm_aside(&mut self) -> &mut Self {
        let p = self.aside();
        self.rm(&p)
    }

    /// The staged S hard-linked over the path: one identity at two names, link count 2
    /// (normalization rule 1: X at both).
    fn link_s_over_path(&mut self) -> &mut Self {
        let tmp = self.parent().join(".rows-link");
        std::fs::hard_link(self.aside(), &tmp).unwrap();
        std::fs::rename(&tmp, self.path()).unwrap();
        self
    }

    // Arrangements several rows share.

    /// A create's forward through `post_validated{valid}`, then `item.rolling_back`.
    fn create_rolling_back(&mut self) -> &mut Self {
        self.forward().rolling_back()
    }

    /// A replace's forward with D replaced by another writer after the exchange and
    /// the mismatch recorded with D's identity.
    fn mismatch_foreign(&mut self) -> &mut Self {
        self.stage()
            .validated()
            .swap()
            .exchanged()
            .replace_aside()
            .post_mismatch()
    }

    /// After a commit, D's settlement begun (`file.settling{displaced}`).
    fn settling_displaced(&mut self) -> &mut Self {
        self.forward().commit().settling(SettleSource::Displaced)
    }

    /// B_git staged and settled after an abort, so K's release is due by receipts.
    fn git_include_settled(&mut self) -> &mut Self {
        let k = self.i;
        self.on(FileRole::GitInclude)
            .stage()
            .settling(SettleSource::Staged)
            .move_to_slot()
            .settled()
            .drop_slot();
        self.i = k;
        self
    }
}

// --- the vectors -----------------------------------------------------------------------------

/// What a vector's decision is checked against.
#[derive(Debug, Clone, Copy)]
enum Want {
    /// A step row: `recovery::decide` for the vector's step.
    Step(StepDecision),
    /// An item row: `recovery::decide_item` for the world's item.
    Item(ItemDecision),
}

/// The item's expected outcome.
#[derive(Debug, Clone)]
enum Out {
    Applied,
    NotApplied(Option<ConflictKind>),
    Restored(Option<ConflictKind>),
    Held(&'static [(u16, HoldReason)]),
}

/// What a vector's extra check sees after the run.
struct Done<'a> {
    w: &'a World,
    hook: &'a Recorder,
    before: &'a BTreeMap<String, Ent>,
    after: &'a BTreeMap<String, Ent>,
}

type Build = fn(&mut Bench<'_>);
type Check = fn(&Done<'_>);

struct Vector {
    row: &'static str,
    world: Wk,
    step: FileRole,
    build: Build,
    obs: [EntryObs; 3],
    want: Want,
    /// The receipts `reconcile` writes, in order ([`kind`]'s spelling).
    written: &'static str,
    outcome: Out,
    check: Option<Check>,
}

#[allow(clippy::too_many_arguments)]
fn sv(
    row: &'static str,
    world: Wk,
    step: FileRole,
    build: Build,
    obs: [EntryObs; 3],
    want: StepDecision,
    written: &'static str,
    outcome: Out,
) -> Vector {
    Vector {
        row,
        world,
        step,
        build,
        obs,
        want: Want::Step(want),
        written,
        outcome,
        check: None,
    }
}

fn iv(
    row: &'static str,
    world: Wk,
    build: Build,
    want: ItemDecision,
    written: &'static str,
    outcome: Out,
) -> Vector {
    Vector {
        row,
        world,
        step: FileRole::UserSsh,
        build,
        obs: [A, A, A],
        want: Want::Item(want),
        written,
        outcome,
        check: None,
    }
}

impl Vector {
    fn check(mut self, f: Check) -> Self {
        self.check = Some(f);
        self
    }
}

fn hold(r: HoldReason) -> StepDecision {
    StepDecision::Hold(r)
}

const FWD: fn(ForwardStep) -> StepDecision = StepDecision::Forward;
const RST: fn(RestoreStep) -> StepDecision = StepDecision::Restore;
const ABT: fn(AbortStep) -> StepDecision = StepDecision::Abort;
const SET: fn(SettleStep) -> StepDecision = StepDecision::Settle;

/// The tail of a forward that commits and settles D (one replace step 0).
const APPLIED_0: &str = "ssh:committed 0:settling:displaced 0:settled ssh:finished_applied";
/// The tail of a file-level restore of step 0 that settles S.
const RESTORED_0: &str = "0:restored 0:settling:staged 0:settled ssh:finished_restored";
/// The Git item's forward from B_git's stage through K's release, last.
const GIT_APPLIED: &str = "1:staged 1:validated 1:exchanged 1:post_validated git:committed 1:settling:displaced 1:settled 0:settling:path 0:settled git:finished_applied";

fn held_0(r: HoldReason) -> &'static [(u16, HoldReason)] {
    match r {
        HoldReason::ActiveEntryReplaced => &[(0, HoldReason::ActiveEntryReplaced)],
        HoldReason::ActiveEntryModified => &[(0, HoldReason::ActiveEntryModified)],
        HoldReason::DisplacedMissing => &[(0, HoldReason::DisplacedMissing)],
        HoldReason::DisplacedReplaced => &[(0, HoldReason::DisplacedReplaced)],
        HoldReason::ThirdWriter => &[(0, HoldReason::ThirdWriter)],
        HoldReason::AmbiguousExchange => &[(0, HoldReason::AmbiguousExchange)],
        HoldReason::Unobservable => &[(0, HoldReason::Unobservable)],
        HoldReason::Unmatched => &[(0, HoldReason::Unmatched)],
        HoldReason::ContradictoryReceipts => &[(0, HoldReason::ContradictoryReceipts)],
    }
}

/// A one-step hold: the step's `file.held` is the only receipt and the outcome holds.
fn held_vector(
    row: &'static str,
    world: Wk,
    build: Build,
    obs: [EntryObs; 3],
    r: HoldReason,
) -> Vector {
    let written: &'static str = Box::leak(format!("0:held:{}", snake!(r)).into_boxed_str());
    sv(
        row,
        world,
        FileRole::UserSsh,
        build,
        obs,
        hold(r),
        written,
        Out::Held(held_0(r)),
    )
}

fn user_unchanged(d: &Done<'_>) {
    assert_eq!(
        std::fs::read(&d.w.home.user_config).unwrap(),
        USER_TEXT.as_bytes(),
        "the user file is the base again"
    );
}

/// The user file holds exactly one intact B before its first section, and without B
/// it is the user's bytes exactly.
fn user_has_block(d: &Done<'_>) {
    use heimdall_sshconf::edit::{BlockPosition, find_blocks};
    let mut bytes = std::fs::read(&d.w.home.user_config).unwrap();
    let blocks = find_blocks(&bytes);
    assert!(
        matches!(blocks.as_slice(), [b] if b.intact && b.position == BlockPosition::BeforeFirstSection),
        "one intact B first"
    );
    bytes.drain(blocks[0].range.clone());
    assert_eq!(
        bytes,
        USER_TEXT.as_bytes(),
        "without B the user file is the user's bytes"
    );
}

fn check_ran(d: &Done<'_>) {
    assert!(
        d.hook.reached(ReplacePoint::BeforeCommit),
        "the transaction check ran"
    );
}

fn check_not_run(d: &Done<'_>) {
    assert!(
        !d.hook.reached(ReplacePoint::BeforeCommit),
        "the transaction check is not run"
    );
}

/// F8d: the foreign entry found in the slot is out of the quarantine, at the source
/// name (moved back) or, when that is occupied, at a conflict name beside it.
fn foreign_kept_beside(d: &Done<'_>, occupied: bool) {
    let foreign = |e: &Ent| e.bytes.starts_with(b"# another writer");
    let at: Vec<&String> = d
        .after
        .iter()
        .filter(|(_, e)| foreign(e))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(at.len(), 1, "{at:?}");
    let staged = d.w.intent.files[0].staged_name.clone().unwrap();
    let name = at[0].rsplit('/').next().unwrap();
    assert!(
        !at[0].contains(".hm-quarantine/"),
        "{at:?} left in the quarantine"
    );
    if occupied {
        assert!(
            name.starts_with(&format!("{staged}.hm-conflict-")),
            "{name}"
        );
    } else {
        assert_eq!(name, staged);
    }
}

fn lock_untouched(d: &Done<'_>) {
    let lock = d.w.home.git_home.join(".gitconfig.lock");
    let name = "home/.gitconfig.lock";
    assert_eq!(
        d.before.get(name),
        d.after.get(name),
        "the lock name is untouched"
    );
    assert!(lock.exists());
}

/// The replace, create and settlement rows on the user file (step 0).
fn file_vectors() -> Vec<Vector> {
    use FileRole::UserSsh as Us;
    use HoldReason as H;
    use Wk::{Create as Cr, Replace as Rp};
    // ESCALATED (M02-W2c-rows): where recovery decides an abort from what it observes
    // (rows F1a, F2e, F2g, F2j, C3, C4; T0 when a precondition fails), the outcome is
    // `not_applied` with no conflict reason, although the rows name one
    // (`concurrent_writer`, or `CONFIG_CONFLICT` `user_config_changed`). Only an abort
    // the live path stops itself carries one (K0 with a foreign lock), and no receipt
    // records it, so a restart reports none (the second run below ignores it). These
    // vectors pin `reason: None` until that is ruled on.
    let not_applied = Out::NotApplied(None);
    let restored_cw = Out::Restored(Some(ConflictKind::ConcurrentWriter));
    let restored_rb = Out::Restored(Some(ConflictKind::ManagedFileEdited));
    vec![
        // --- replace (base present, target present) ---
        sv("F0", Rp, Us, |_| {}, [X, A, A], FWD(ForwardStep::Stage),
            "0:staged 0:validated 0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F0x", Rp, Us, |b| { b.stage_raw(); }, [X, S, A], FWD(ForwardStep::RecordStaged),
            "0:staged 0:validated 0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F0x", Rp, Us, |b| { b.stage_raw_partial(); }, [X, SM, A], FWD(ForwardStep::RecordStaged),
            "0:staged 0:settling:staged 0:settle_conflict:modified ssh:finished_not_applied",
            not_applied.clone()).check(user_unchanged),
        sv("F0z", Rp, Us, |b| { let p = b.aside(); b.symlink(&p); }, [X, X, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()).check(user_unchanged),
        sv("F1", Rp, Us, |b| { b.stage(); }, [X, S, A], FWD(ForwardStep::Revalidate),
            "0:validated 0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F1", Rp, Us, |b| { b.stage().edit_aside(); }, [X, SM, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settle_conflict:modified ssh:finished_not_applied", not_applied.clone()),
        sv("F1a", Rp, Us, |b| { b.stage().rm_aside(); }, [X, A, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()),
        sv("F1a", Rp, Us, |b| { b.stage().replace_aside(); }, [X, X, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()),
        sv("F2a", Rp, Us, |b| { b.stage().validated(); }, [V, S, A], FWD(ForwardStep::Revalidate),
            "0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F2a", Rp, Us, |b| { b.stage().validated().edit_path(); }, [VM, S, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled ssh:finished_not_applied", not_applied.clone()),
        sv("F2a", Rp, Us, |b| { b.stage().validated().edit_aside(); }, [V, SM, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settle_conflict:modified ssh:finished_not_applied", not_applied.clone()),
        sv("F2b", Rp, Us, |b| { b.stage().validated().swap(); }, [S, V, A], FWD(ForwardStep::RecordExchanged),
            "0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F2c", Rp, Us, |b| { b.stage().validated().swap().edit_aside(); }, [S, VM, A], RST(RestoreStep::RecordMismatch),
            "0:exchanged 0:post_validated_mismatch 0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored",
            restored_cw.clone()),
        sv("F2c", Rp, Us, |b| { b.stage().validated().swap().edit_path().replace_aside(); }, [SM, X, A], RST(RestoreStep::RecordMismatch),
            "0:exchanged 0:post_validated_mismatch 0:held:active_entry_modified",
            Out::Held(held_0(H::ActiveEntryModified))),
        held_vector("F2d", Rp, |b| { b.stage().validated().swap().rm_aside(); }, [S, A, A], H::DisplacedMissing),
        sv("F2e", Rp, Us, |b| { b.stage().validated().replace_path(); }, [X, S, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled ssh:finished_not_applied", not_applied.clone()),
        sv("F2g", Rp, Us, |b| { b.stage().validated().rm_aside(); }, [V, A, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()).check(user_unchanged),
        sv("F2j", Rp, Us, |b| { b.stage().validated().rm_path(); }, [A, S, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled ssh:finished_not_applied", not_applied.clone()),
        sv("F2k", Rp, Us, |b| { b.stage().validated().replace_aside(); }, [V, X, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()).check(user_unchanged),
        held_vector("F2h", Rp, |b| { b.stage().validated().swap().replace_path(); }, [X, V, A], H::ActiveEntryReplaced),
        held_vector("F2h", Rp, |b| { b.stage().validated().swap().rm_path(); }, [A, V, A], H::ActiveEntryReplaced),
        held_vector("F2f", Rp, |b| { b.stage().validated().replace_path().replace_aside(); }, [X, X, A], H::AmbiguousExchange),
        // Normalization rule 1 on disk: S hard-linked over the path is one identity at
        // two names with link count 2, so it is X at both.
        held_vector("F2f", Rp, |b| { b.stage().validated().link_s_over_path(); }, [X, X, A], H::AmbiguousExchange),
        sv("F3", Rp, Us, |b| { b.stage().validated().swap().exchanged(); }, [S, V, A], FWD(ForwardStep::PostValidate),
            "0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        sv("F3a", Rp, Us, |b| { b.stage().validated().swap().exchanged().replace_aside(); }, [S, X, A], RST(RestoreStep::RecordMismatch),
            "0:post_validated_mismatch 0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored",
            restored_cw.clone()),
        sv("F3a", Rp, Us, |b| { b.stage().validated().swap().exchanged().edit_aside(); }, [S, VM, A], RST(RestoreStep::RecordMismatch),
            "0:post_validated_mismatch 0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored",
            restored_cw.clone()),
        held_vector("F3b", Rp, |b| { b.stage().validated().swap().exchanged().rm_aside(); }, [S, A, A], H::DisplacedMissing),
        held_vector("F3c", Rp, |b| { b.stage().validated().swap().exchanged().replace_path(); }, [X, V, A], H::ActiveEntryReplaced),
        sv("F4", Rp, Us, |b| { b.forward(); }, [S, V, A], FWD(ForwardStep::TransactionCheck), APPLIED_0, Out::Applied)
            .check(|d| { check_ran(d); user_has_block(d); }),
        sv("F4", Rp, Us, |b| { b.forward().edit_path(); }, [SM, V, A], FWD(ForwardStep::TransactionCheck), APPLIED_0, Out::Applied)
            .check(check_ran),
        held_vector("F4a", Rp, |b| { b.forward().rm_aside(); }, [S, A, A], H::DisplacedMissing),
        held_vector("F4c", Rp, |b| { b.forward().replace_aside(); }, [S, X, A], H::DisplacedReplaced),
        held_vector("F4c", Rp, |b| { b.forward().edit_aside(); }, [S, VM, A], H::DisplacedReplaced),
        held_vector("F4b", Rp, |b| { b.forward().replace_path(); }, [X, V, A], H::ActiveEntryReplaced),
        sv("F4d", Rp, Us, |b| { b.forward().commit(); }, [S, V, A], SET(SettleStep::Begin),
            "0:settling:displaced 0:settled ssh:finished_applied", Out::Applied).check(user_has_block),
        sv("F4d", Rp, Us, |b| { b.forward().commit().replace_path().edit_aside(); }, [X, VM, A], SET(SettleStep::Begin),
            "0:settling:displaced 0:settle_conflict:modified ssh:finished_applied", Out::Applied),
        sv("F4e", Rp, Us, |b| { b.forward().commit().rm_aside(); }, [S, A, A], SET(SettleStep::RecordConflict),
            "0:settle_conflict:missing ssh:finished_applied", Out::Applied),
        sv("F4e", Rp, Us, |b| { b.forward().commit().replace_aside(); }, [S, X, A], SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign ssh:finished_applied", Out::Applied),
        sv("F5", Rp, Us, |b| { b.mismatch_foreign(); }, [S, D, A], RST(RestoreStep::Exchange),
            "0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored", restored_cw.clone()),
        sv("F5", Rp, Us, |b| { b.stage().validated().swap().exchanged().edit_aside().post_mismatch(); }, [S, VM, A],
            RST(RestoreStep::Exchange),
            "0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored", restored_cw.clone()),
        sv("F5", Rp, Us, |b| { b.forward().rolling_back(); }, [S, V, A], RST(RestoreStep::Exchange),
            "0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored", restored_rb.clone())
            .check(user_unchanged),
        sv("F5", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch); }, [S, D, A],
            RST(RestoreStep::Exchange), RESTORED_0, restored_cw.clone()),
        held_vector("F5a", Rp, |b| { b.mismatch_foreign().edit_path(); }, [SM, D, A], H::ActiveEntryModified),
        held_vector("F5a", Rp, |b| { b.forward().rolling_back().edit_path(); }, [SM, V, A], H::ActiveEntryModified),
        sv("F5b", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap(); }, [D, S, A],
            RST(RestoreStep::RecognizeRestored), RESTORED_0, restored_cw.clone()),
        sv("F5b", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().edit_aside(); },
            [D, SM, A], RST(RestoreStep::RecognizeRestored),
            "0:restored 0:settling:staged 0:settle_conflict:modified ssh:finished_restored", restored_cw.clone()),
        sv("F5c", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().replace_path(); },
            [X, S, A], RST(RestoreStep::RecognizeRestored), RESTORED_0, restored_cw.clone()),
        held_vector("F5d", Rp, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).replace_path(); },
            [X, D, A], H::ThirdWriter),
        held_vector("F5d", Rp, |b| { b.mismatch_foreign().swap(); }, [D, S, A], H::ThirdWriter),
        sv("F6", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().restored(); },
            [D, S, A], SET(SettleStep::Begin), "0:settling:staged 0:settled ssh:finished_restored", restored_cw.clone()),
        sv("F6", Rp, Us,
            |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().restored().replace_path().edit_aside(); },
            [X, SM, A], SET(SettleStep::Begin), "0:settling:staged 0:settle_conflict:modified ssh:finished_restored",
            restored_cw.clone()),
        sv("F6a", Rp, Us, |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().restored().rm_aside(); },
            [D, A, A], SET(SettleStep::RecordConflict), "0:settle_conflict:missing ssh:finished_restored", restored_cw.clone()),
        sv("F6a", Rp, Us,
            |b| { b.mismatch_foreign().restore_started(RestoreCause::FileMismatch).swap().restored().replace_aside(); },
            [D, X, A], SET(SettleStep::RecordConflict), "0:settle_conflict:foreign ssh:finished_restored", restored_cw.clone()),
        // --- the settlement block (D's settlement after a commit; a create's restore) ---
        sv("F8d", Rp, Us, |b| { b.settling_displaced().foreign_slot(); }, [S, Q, X], SET(SettleStep::PutBackForeign),
            "0:settle_conflict:foreign ssh:finished_applied", Out::Applied)
            .check(|d| foreign_kept_beside(d, true)),
        sv("F8d", Rp, Us, |b| { b.settling_displaced().rm_aside().foreign_slot(); }, [S, A, X], SET(SettleStep::PutBackForeign),
            "0:settle_conflict:foreign ssh:finished_applied", Out::Applied)
            .check(|d| foreign_kept_beside(d, false)),
        sv("F8b", Rp, Us, |b| { b.settling_displaced().move_to_slot(); }, [S, A, Q], SET(SettleStep::RecordSettled),
            "0:settled ssh:finished_applied", Out::Applied),
        sv("F8f", Rp, Us, |b| { b.settling_displaced().move_to_slot().edit_slot(); }, [S, A, QM], SET(SettleStep::RecordConflict),
            "0:settle_conflict:modified ssh:finished_applied", Out::Applied),
        sv("F8a", Rp, Us, |b| { b.settling_displaced(); }, [S, Q, A], SET(SettleStep::Move),
            "0:settled ssh:finished_applied", Out::Applied),
        sv("F8a", Rp, Us, |b| { b.settling_displaced().edit_aside(); }, [S, QM, A], SET(SettleStep::Move),
            "0:settle_conflict:modified ssh:finished_applied", Out::Applied),
        sv("F8a", Cr, Us,
            |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).settling(SettleSource::Path); },
            [Q, A, A], SET(SettleStep::Move), "0:settled 0:restored ssh:finished_restored", restored_rb.clone()),
        held_vector("F8a", Cr,
            |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).settling(SettleSource::Path).edit_path(); },
            [QM, A, A], H::ActiveEntryModified),
        sv("F8e", Rp, Us, |b| { b.settling_displaced().replace_aside(); }, [S, X, A], SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign ssh:finished_applied", Out::Applied),
        sv("F8c", Rp, Us, |b| { b.settling_displaced().rm_aside(); }, [S, A, A], SET(SettleStep::RecordConflict),
            "0:settle_conflict:missing ssh:finished_applied", Out::Applied),
        sv("F9", Rp, Us, |b| { b.settling_displaced().move_to_slot().settled(); }, [S, A, Q], SET(SettleStep::Remove),
            "ssh:finished_applied", Out::Applied),
        sv("F9a", Rp, Us, |b| { b.settling_displaced().move_to_slot().settled().edit_slot(); }, [S, A, QM],
            SET(SettleStep::RecordConflict), "0:settle_conflict:modified ssh:finished_applied", Out::Applied),
        sv("F9b", Rp, Us, |b| { b.settling_displaced().move_to_slot().settled().drop_slot(); }, [S, A, A], SET(SettleStep::Done),
            "ssh:finished_applied", Out::Applied),
        sv("F9b", Cr, Us,
            |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).settling(SettleSource::Path).move_to_slot().settled().drop_slot(); },
            [A, A, A], RST(RestoreStep::RecognizeRestored), "0:restored ssh:finished_restored", restored_rb.clone()),
        sv("F9c", Rp, Us, |b| { b.settling_displaced().move_to_slot().settled().drop_slot().foreign_slot(); }, [S, A, X],
            SET(SettleStep::Done), "ssh:finished_applied", Out::Applied),
        sv("F9d", Rp, Us,
            |b| { b.settling_displaced().move_to_slot().edit_slot().settle_conflict(SettleConflictFound::Modified); },
            [S, A, QM], SET(SettleStep::Done), "ssh:finished_applied", Out::Applied),
        sv("F9d", Rp, Us,
            |b| { b.settling_displaced().replace_aside().settle_conflict(SettleConflictFound::Foreign).replace_path().foreign_slot(); },
            [X, X, X], SET(SettleStep::Done), "ssh:finished_applied", Out::Applied),
        // --- create (base absent) ---
        sv("C1", Cr, Us, |b| { b.stage().validated(); }, [A, S, A], FWD(ForwardStep::Revalidate),
            "0:exchanged 0:post_validated ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C1", Cr, Us, |b| { b.stage().validated().edit_aside(); }, [A, SM, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settle_conflict:modified ssh:finished_not_applied", not_applied.clone()),
        sv("C2", Cr, Us, |b| { b.stage().validated().swap(); }, [S, A, A], FWD(ForwardStep::RecordExchanged),
            "0:exchanged 0:post_validated ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C2", Cr, Us, |b| { b.stage().validated().swap().edit_path(); }, [SM, A, A], FWD(ForwardStep::RecordExchanged),
            "0:exchanged 0:post_validated ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C3", Cr, Us, |b| { b.stage().validated().foreign_path(); }, [X, S, A], ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled ssh:finished_not_applied", not_applied.clone()),
        sv("C4", Cr, Us, |b| { b.stage().validated().rm_aside(); }, [A, A, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()),
        sv("C4b", Cr, Us, |b| { b.stage().validated().replace_aside(); }, [A, X, A], ABT(AbortStep::NothingToSettle),
            "ssh:finished_not_applied", not_applied.clone()),
        held_vector("C4h", Cr, |b| { b.stage().validated().rm_aside().foreign_path(); }, [X, A, A], H::AmbiguousExchange),
        held_vector("C4h", Cr, |b| { b.stage().validated().replace_aside().foreign_path(); }, [X, X, A], H::AmbiguousExchange),
        sv("C6", Cr, Us, |b| { b.stage().validated().swap().exchanged(); }, [S, A, A], FWD(ForwardStep::PostValidate),
            "0:post_validated ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C6", Cr, Us, |b| { b.stage().validated().swap().exchanged().edit_path().foreign_aside(); }, [SM, X, A],
            FWD(ForwardStep::PostValidate),
            "0:post_validated ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        held_vector("C6a", Cr, |b| { b.stage().validated().swap().exchanged().replace_path(); }, [X, A, A], H::ActiveEntryReplaced),
        held_vector("C6a", Cr, |b| { b.stage().validated().swap().exchanged().rm_path(); }, [A, A, A], H::ActiveEntryReplaced),
        sv("C5", Cr, Us, |b| { b.forward(); }, [S, A, A], FWD(ForwardStep::TransactionCheck),
            "ssh:committed 0:settled_nothing_displaced ssh:finished_applied", Out::Applied).check(check_ran),
        held_vector("C5a", Cr, |b| { b.forward().replace_path(); }, [X, A, A], H::ActiveEntryReplaced),
        sv("C5b", Cr, Us, |b| { b.forward().commit(); }, [S, A, A], FWD(ForwardStep::NothingDisplaced),
            "0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C5b", Cr, Us, |b| { b.forward().commit().replace_path().foreign_aside(); }, [X, X, A],
            FWD(ForwardStep::NothingDisplaced), "0:settled_nothing_displaced ssh:finished_applied", Out::Applied),
        sv("C7", Cr, Us, |b| { b.create_rolling_back(); }, [S, A, A], RST(RestoreStep::CreateRollback),
            "0:restore_started 0:settling:path 0:settled 0:restored ssh:finished_restored", restored_rb.clone())
            .check(|d| assert!(!d.w.home.user_config.exists(), "the created file is settled")),
        sv("C7", Cr, Us,
            |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).foreign_aside(); },
            [S, X, A], RST(RestoreStep::CreateRollback), "0:settling:path 0:settled 0:restored ssh:finished_restored",
            restored_rb.clone()),
        held_vector("C7a", Cr, |b| { b.create_rolling_back().edit_path(); }, [SM, A, A], H::ActiveEntryModified),
        held_vector("C7a", Cr, |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).edit_path(); },
            [SM, A, A], H::ActiveEntryModified),
        held_vector("C7b", Cr, |b| { b.create_rolling_back().replace_path(); }, [X, A, A], H::ActiveEntryReplaced),
        held_vector("C7b", Cr, |b| { b.create_rolling_back().restore_started(RestoreCause::TransactionCheck).rm_path(); },
            [A, A, A], H::ActiveEntryReplaced),
        sv("C8", Cr, Us,
            |b| {
                b.create_rolling_back()
                    .restore_started(RestoreCause::TransactionCheck)
                    .settling(SettleSource::Path)
                    .move_to_slot()
                    .settled()
                    .drop_slot()
                    .restored()
                    .foreign_path();
            },
            [X, A, A], SET(SettleStep::Done), "ssh:finished_restored", restored_rb.clone()),
        sv("C8", Cr, Us,
            |b| {
                b.create_rolling_back()
                    .restore_started(RestoreCause::TransactionCheck)
                    .settling(SettleSource::Path)
                    .move_to_slot()
                    .edit_slot()
                    .settle_conflict(SettleConflictFound::Modified)
                    .restored()
                    .foreign_aside();
            },
            [A, X, QM], SET(SettleStep::Done), "ssh:finished_restored", restored_rb),
    ]
}

/// The Git lock holder's rows (K = step 0, B_git = step 1), and K's release in the
/// settlement block.
fn lock_vectors() -> Vec<Vector> {
    use FileRole::GitLock as Gl;
    use Wk::{Git, GitNoBirth};
    let locked = Out::NotApplied(Some(ConflictKind::GitConfigLocked));
    // ESCALATED (M02-W2c-rows): an abort decided by recovery from what it observes
    // (K1 with a foreign lock, K3) has no conflict reason in the outcome, although the
    // rows name one (`git_config_locked`, `concurrent_writer`); see `file_vectors`.
    let not_applied = Out::NotApplied(None);
    vec![
        sv(
            "K0",
            Git,
            Gl,
            |_| {},
            [A, A, A],
            FWD(ForwardStep::Stage),
            "0:staged 1:staged 1:validated 1:exchanged 1:post_validated git:committed 1:settling:displaced 1:settled 0:settling:path 0:settled git:finished_applied",
            Out::Applied,
        ),
        sv(
            "K0",
            Git,
            Gl,
            |b| {
                b.foreign_path();
            },
            [X, A, A],
            FWD(ForwardStep::Stage),
            "0:staged 0:settling:staged 0:settled git:finished_not_applied",
            locked.clone(),
        )
        .check(lock_untouched),
        sv(
            "K0x",
            Git,
            Gl,
            |b| {
                b.stage_raw();
            },
            [A, S, A],
            FWD(ForwardStep::RecordStaged),
            "0:staged 1:staged 1:validated 1:exchanged 1:post_validated git:committed 1:settling:displaced 1:settled 0:settling:path 0:settled git:finished_applied",
            Out::Applied,
        ),
        sv(
            "K0z",
            Git,
            Gl,
            |b| {
                let p = b.aside();
                b.symlink(&p);
            },
            [A, X, A],
            ABT(AbortStep::NothingToSettle),
            "git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K1",
            Git,
            Gl,
            |b| {
                b.stage();
            },
            [A, S, A],
            FWD(ForwardStep::ClaimLock),
            GIT_APPLIED,
            Out::Applied,
        ),
        sv(
            "K1",
            Git,
            Gl,
            |b| {
                b.stage().edit_aside();
            },
            [A, SM, A],
            ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settle_conflict:modified git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K1",
            Git,
            Gl,
            |b| {
                b.stage().foreign_path();
            },
            [X, S, A],
            ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled git:finished_not_applied",
            not_applied.clone(),
        )
        .check(lock_untouched),
        sv(
            "K1",
            Git,
            Gl,
            |b| {
                b.git_include_settled().stage();
            },
            [A, S, A],
            ABT(AbortStep::SettleStaged),
            "0:settling:staged 0:settled git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K2",
            Git,
            Gl,
            |b| {
                b.stage().swap();
            },
            [S, A, A],
            FWD(ForwardStep::KeepLock),
            GIT_APPLIED,
            Out::Applied,
        ),
        sv(
            "K2",
            Git,
            Gl,
            |b| {
                b.stage().swap().foreign_aside();
            },
            [S, X, A],
            FWD(ForwardStep::KeepLock),
            GIT_APPLIED,
            Out::Applied,
        ),
        // K′ at the lock: K2 keeps the lock, and B_git resumes; but the live path's
        // check before B_git's exchange (ADR-0007 §12.18 item 4, X04, as W2c-U4 reads
        // it: K's identity *and* holder digest) refuses a K′, so B_git is never
        // exchanged, the item aborts, and K′ is released into the quarantine as a
        // conflict artifact.
        sv(
            "K2",
            Git,
            Gl,
            |b| {
                b.stage().swap().edit_path().foreign_aside();
            },
            [SM, X, A],
            FWD(ForwardStep::KeepLock),
            "1:staged 1:validated 1:settling:staged 1:settled 0:settling:path 0:settle_conflict:modified git:finished_not_applied",
            locked.clone(),
        ),
        sv(
            "K2",
            Git,
            Gl,
            |b| {
                b.git_include_settled().stage().swap();
            },
            [S, A, A],
            SET(SettleStep::Begin),
            "0:settling:path 0:settled git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K2",
            Git,
            Gl,
            |b| {
                b.git_include_settled()
                    .stage()
                    .swap()
                    .edit_path()
                    .foreign_aside();
            },
            [SM, X, A],
            SET(SettleStep::Begin),
            "0:settling:path 0:settle_conflict:modified git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K3",
            Git,
            Gl,
            |b| {
                b.stage().rm_aside();
            },
            [A, A, A],
            SET(SettleStep::RecordConflict),
            "0:settle_conflict:missing git:finished_not_applied",
            not_applied.clone(),
        ),
        // ESCALATED (M02-W2c-rows): ADR-0007 row K3 writes `settle_conflict{missing}`
        // for an X at the staged name too ("K is gone"); the writer's
        // `conflict_found` records `{foreign}` naming the staged name. This vector
        // pins the writer's current receipt until that is ruled on.
        sv(
            "K3",
            Git,
            Gl,
            |b| {
                b.stage().replace_aside();
            },
            [A, X, A],
            SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "K4",
            Git,
            Gl,
            |b| {
                b.stage().swap().replace_path();
            },
            [X, A, A],
            SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign git:finished_not_applied",
            not_applied.clone(),
        )
        .check(lock_untouched),
        sv(
            "K4",
            Git,
            Gl,
            |b| {
                b.git_include_settled()
                    .stage()
                    .swap()
                    .replace_path()
                    .foreign_aside();
            },
            [X, X, A],
            SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign git:finished_not_applied",
            not_applied.clone(),
        )
        .check(lock_untouched),
        // K that is not provable: without a birth time, K at the lock name is X.
        sv(
            "K4",
            GitNoBirth,
            Gl,
            |b| {
                b.stage().swap();
            },
            [X, A, A],
            SET(SettleStep::RecordConflict),
            "0:settle_conflict:foreign git:finished_not_applied",
            not_applied.clone(),
        )
        .check(lock_untouched),
        // K's release from the lock in the settlement block.
        sv(
            "F8a",
            Git,
            Gl,
            |b| {
                b.git_include_settled()
                    .stage()
                    .swap()
                    .settling(SettleSource::Path);
            },
            [Q, A, A],
            SET(SettleStep::Move),
            "0:settled git:finished_not_applied",
            not_applied.clone(),
        ),
        sv(
            "F8a",
            Git,
            Gl,
            |b| {
                b.git_include_settled()
                    .stage()
                    .swap()
                    .settling(SettleSource::Path)
                    .edit_path();
            },
            [QM, A, A],
            SET(SettleStep::Move),
            "0:settle_conflict:modified git:finished_not_applied",
            not_applied,
        ),
    ]
}

/// The item rows (T0–TH).
fn item_vectors() -> Vec<Vector> {
    use HoldReason as H;
    use Wk::{PThenU as Pu, Replace as Rp};
    vec![
        iv("T0", Rp, |b| { b.stage(); }, ItemDecision::ResumeOrAbort,
            "0:validated 0:exchanged 0:post_validated ssh:committed 0:settling:displaced 0:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        // The precondition fails (the user file changed while the runtime was down):
        // the item aborts and S is settled.
        iv("T0", Rp, |b| { b.stage().edit_path(); }, ItemDecision::ResumeOrAbort,
            "0:settling:staged 0:settled ssh:finished_not_applied", Out::NotApplied(None)),
        iv("T0", Pu, |b| { b.on(FileRole::ManagedSsh).forward().on(FileRole::UserSsh).stage(); },
            ItemDecision::ResumeOrAbort,
            "1:validated 1:exchanged 1:post_validated ssh:committed 0:settled_nothing_displaced 1:settling:displaced 1:settled ssh:finished_applied",
            Out::Applied).check(user_has_block),
        // An exchanged inactive P is left for the cleaner when the item aborts.
        iv("T0", Pu, |b| { b.on(FileRole::ManagedSsh).forward().on(FileRole::UserSsh).stage().edit_path(); },
            ItemDecision::ResumeOrAbort, "1:settling:staged 1:settled ssh:finished_not_applied", Out::NotApplied(None))
            .check(|d| assert!(d.w.home.config_dir.join("ssh_config").exists(), "P is left for the cleaner")),
        iv("T1", Rp, |b| { b.forward(); }, ItemDecision::TransactionCheck, APPLIED_0, Out::Applied).check(check_ran),
        iv("T1", Pu, |b| { b.on(FileRole::ManagedSsh).forward().on(FileRole::UserSsh).forward(); },
            ItemDecision::TransactionCheck,
            "ssh:committed 0:settled_nothing_displaced 1:settling:displaced 1:settled ssh:finished_applied",
            Out::Applied).check(check_ran),
        // The check fails (P edited after its exchange): `item.rolling_back`, U is
        // restored, and P's own row holds it (C7a).
        iv("T1", Pu, |b| { b.on(FileRole::ManagedSsh).forward().edit_path().on(FileRole::UserSsh).forward(); },
            ItemDecision::TransactionCheck,
            "ssh:rolling_back 1:restore_started 1:restored 1:settling:staged 1:settled 0:held:active_entry_modified",
            Out::Held(&[(0, H::ActiveEntryModified)])).check(|d| { check_ran(d); user_unchanged(d); }),
        // T1h on disk: the commit step at `post_validated{valid}` with the item open, and
        // an exchanged step that observes something other than path S and aside V. Its
        // own row (F4c) holds it before any item row is tried, so `decide_item` reads it
        // as TH with F4c's reason, which is T1h's (HOLD_READINGS); the check never runs.
        iv("T1h", Rp, |b| { b.forward().edit_aside(); }, ItemDecision::Hold(H::DisplacedReplaced),
            "0:held:displaced_replaced", Out::Held(&[(0, H::DisplacedReplaced)])).check(check_not_run),
        iv("T2", Rp, |b| { b.settling_displaced().move_to_slot().settled().drop_slot(); }, ItemDecision::FinishForward,
            "ssh:finished_applied", Out::Applied),
        iv("T2", Pu, |b| { b.on(FileRole::ManagedSsh).forward().on(FileRole::UserSsh).forward().commit(); },
            ItemDecision::FinishForward,
            "0:settled_nothing_displaced 1:settling:displaced 1:settled ssh:finished_applied", Out::Applied)
            .check(check_not_run),
        iv("T3", Rp, |b| { b.forward().rolling_back(); }, ItemDecision::FinishRestore,
            "0:restore_started 0:restored 0:settling:staged 0:settled ssh:finished_restored",
            Out::Restored(Some(ConflictKind::ManagedFileEdited))).check(user_unchanged),
        iv("T3", Rp,
            |b| {
                b.mismatch_foreign()
                    .restore_started(RestoreCause::FileMismatch)
                    .swap()
                    .restored()
                    .settling(SettleSource::Staged)
                    .move_to_slot()
                    .settled()
                    .drop_slot();
            },
            ItemDecision::FinishRestore, "ssh:finished_restored", Out::Restored(Some(ConflictKind::ConcurrentWriter))),
        iv("T3", Pu, |b| { b.on(FileRole::ManagedSsh).forward().on(FileRole::UserSsh).forward().rolling_back(); },
            ItemDecision::FinishRestore,
            "0:restore_started 0:settling:path 0:settled 0:restored 1:restore_started 1:restored 1:settling:staged 1:settled ssh:finished_restored",
            Out::Restored(Some(ConflictKind::ManagedFileEdited)))
            .check(|d| { user_unchanged(d); assert!(!d.w.home.config_dir.join("ssh_config").exists()); }),
        iv("T4", Rp,
            |b| { b.settling_displaced().move_to_slot().settled().drop_slot().finished(ItemFinish::Applied); },
            ItemDecision::Settle, "", Out::Applied),
        iv("T4", Rp,
            |b| { b.stage().settling(SettleSource::Staged).move_to_slot().settled().drop_slot().finished(ItemFinish::NotApplied); },
            ItemDecision::Settle, "", Out::NotApplied(None)),
        iv("TH", Rp, |b| { b.stage().validated().swap().rm_aside(); }, ItemDecision::Hold(H::DisplacedMissing),
            "0:held:displaced_missing", Out::Held(&[(0, H::DisplacedMissing)])),
        iv("TH", Rp, |b| { b.forward().commit().rolling_back(); }, ItemDecision::Hold(H::ContradictoryReceipts),
            "0:held:contradictory_receipts", Out::Held(&[(0, H::ContradictoryReceipts)])),
    ]
}

fn all_step_vectors() -> Vec<Vector> {
    let mut v = file_vectors();
    v.extend(lock_vectors());
    v.extend(item_vectors());
    v
}

// --- running a vector --------------------------------------------------------------------------

fn outcome_matches(item: ProjectionItem, generation: u64, want: &Out, got: &ItemOutcome) -> bool {
    match (want, got) {
        (
            Out::Applied,
            ItemOutcome::Applied {
                item: i,
                generation: g,
            },
        ) => *i == item && *g == generation,
        (Out::NotApplied(r), ItemOutcome::NotApplied { item: i, reason }) => {
            *i == item && reason == r
        }
        (Out::Restored(r), ItemOutcome::Restored { item: i, reason }) => *i == item && reason == r,
        (
            Out::Held(steps),
            ItemOutcome::Held {
                item: i,
                steps: got,
            },
        ) => {
            *i == item
                && got.iter().map(|s| (s.step, s.reason)).collect::<Vec<_>>() == steps.to_vec()
        }
        _ => false,
    }
}

/// Property 2 (no loss) and the content rule: every entry present before is present
/// after with its identity and bytes, unless it was removed from a quarantine slot
/// after a durable `file.settled` for a `file.settling` that expected its identity;
/// and no file present at both times changed its bytes.
fn assert_no_loss(
    before: &BTreeMap<String, Ent>,
    after: &BTreeMap<String, Ent>,
    log: &[StageReceipt],
) {
    let settled: Vec<FileIdentity> = {
        let mut out = Vec::new();
        let mut open: BTreeMap<u16, FileIdentity> = BTreeMap::new();
        for r in log {
            if let Some(LocalReceipt::File { step, phase }) = &r.local {
                match phase {
                    FilePhase::Settling { expected, .. } => {
                        open.insert(*step, expected.clone());
                    }
                    FilePhase::Settled {
                        disposition: SettledDisposition::Quarantined,
                    } => {
                        if let Some(id) = open.get(step) {
                            out.push(id.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    };
    for (name, e) in before {
        let kept = after
            .values()
            .any(|a| a.dev == e.dev && a.ino == e.ino && a.bytes == e.bytes);
        let removed_verified = !e.link && settled.iter().any(|id| same_inode(id, e));
        assert!(
            kept || removed_verified,
            "{name} was lost (not removed by a verified settlement)"
        );
    }
    for (name, a) in after {
        if let Some(b) = before.get(name)
            && b.dev == a.dev
            && b.ino == a.ino
            && !a.link
        {
            assert_eq!(a.bytes, b.bytes, "{name} was rewritten in place");
        }
    }
}

fn run_vector(v: &Vector) {
    let w = World::new(v.world);
    let mut b = Bench {
        w: &w,
        sink: w.sink(),
        i: w.step_of(v.step),
        s: BTreeMap::new(),
        v: BTreeMap::new(),
        settle: BTreeMap::new(),
    };
    (v.build)(&mut b);
    drop(b);
    let history = w.receipts();
    let i = w.step_of(v.step);
    let shape = StepShape::of(&w.intent.files[usize::from(i)]);
    let adr = adr_rows();
    let row = adr
        .iter()
        .find(|r| r.id == v.row)
        .unwrap_or_else(|| panic!("{} is not a row of ADR-0007 §5.7", v.row));
    // The decision, from the entries on disk and the durable receipts.
    let mut first_receipts: Vec<&'static str> = Vec::new();
    match v.want {
        Want::Step(want) => {
            assert_ne!(row.table, AdrTable::Item, "{} is an item row", v.row);
            let state = RecoveryState::build(i, &history, &w.intent.files)
                .unwrap_or_else(|_| panic!("the history is refused"));
            let obs = w.observe(i, &state, &history);
            assert_eq!(
                [obs.path(), obs.aside(), obs.slot()],
                v.obs,
                "the observed symbols"
            );
            let first = adr_first_match(adr, shape, &state, &obs).map(|r| r.id.as_str());
            assert_eq!(
                first,
                Some(v.row),
                "the ADR's first row naming this phase and these symbols"
            );
            let got = decide(shape, &state, &obs);
            assert_eq!(got, want, "recovery::decide");
            let hold = match got {
                StepDecision::Hold(r) => Some(r),
                _ => None,
            };
            assert!(
                adr_action_agrees(row, hold, None),
                "{got:?} disagrees with the ADR's action {:?}",
                row.action()
            );
            first_receipts = effects(got, shape, &state)
                .into_iter()
                .filter_map(|e| match e {
                    Effect::Receipt(k) => Some(k),
                    _ => None,
                })
                .collect();
        }
        Want::Item(want) => {
            assert_eq!(row.table, AdrTable::Item, "{} is not an item row", v.row);
            let (states, rx) = w.item_states(&history);
            let got = decide_item(&states, &rx);
            assert_eq!(got, want, "recovery::decide_item over {states:?} {rx:?}");
            let held_step = states.iter().find_map(|s| match s {
                StepState::Held(r) => Some(*r),
                _ => None,
            });
            let hold = match got {
                ItemDecision::Hold(r) => Some(r),
                _ => None,
            };
            assert!(
                adr_action_agrees(row, hold, held_step),
                "{got:?} disagrees with the ADR's action {:?}",
                row.action()
            );
        }
    }
    // Reconcile with a fresh writer from the durable receipts.
    let before = w.tree();
    let hook = Arc::new(Recorder::default());
    let mut sink = w.sink();
    let out = LocalProjection::new(w.hooked(&hook))
        .reconcile(&w.intent, &history, &mut sink)
        .unwrap_or_else(|e| panic!("reconcile failed: {e}"));
    let log = w.receipts();
    let written: Vec<String> = log[history.len()..]
        .iter()
        .filter_map(|r| r.local.as_ref())
        .map(kind)
        .collect();
    assert_eq!(written.join(" "), v.written, "the receipts written");
    let mine: Vec<&str> = written
        .iter()
        .filter(|k| k.starts_with(&format!("{i}:")))
        .map(|k| effect_kind(k))
        .collect();
    assert!(
        mine.starts_with(&first_receipts),
        "step {i}'s receipts {mine:?} do not begin with its action's {first_receipts:?}"
    );
    let item = w.kind.item();
    assert_eq!(out.items.len(), 1, "{:?}", out.items);
    assert!(
        outcome_matches(item, w.intent.generation, &v.outcome, &out.items[0]),
        "outcome {:?}, expected {:?}",
        out.items[0],
        v.outcome
    );
    let after = w.tree();
    assert_no_loss(&before, &after, &log);
    if !written.is_empty() && written.iter().all(|k| k.contains(":held:")) {
        assert_eq!(after, before, "a hold moves nothing");
    }
    // Property 8: a second run moves nothing more and writes nothing.
    let mut sink = w.sink();
    let again = LocalProjection::new(w.config())
        .reconcile(&w.intent, &log, &mut sink)
        .unwrap();
    assert_eq!(
        w.receipts().len(),
        log.len(),
        "a second reconcile writes nothing"
    );
    assert_eq!(w.tree(), after, "a second reconcile moves nothing");
    // The same outcome, except a `not_applied` reason: no receipt records it (an
    // abort writes only `item.finished{not_applied}`), so a restart reports none.
    let durable = |o: &ItemOutcome| match o {
        ItemOutcome::NotApplied { item, .. } => ItemOutcome::NotApplied {
            item: *item,
            reason: None,
        },
        other => other.clone(),
    };
    assert_eq!(
        again.items.iter().map(durable).collect::<Vec<_>>(),
        out.items.iter().map(durable).collect::<Vec<_>>(),
        "a second reconcile gives the same outcome"
    );
    if let Some(check) = v.check {
        check(&Done {
            w: &w,
            hook: &hook,
            before: &before,
            after: &after,
        });
    }
}

// --- the cleaner's rows (R1–R6) -------------------------------------------------------------------

/// One cleaner vector over a P the Replace world rendered: the locator names P with
/// its identity and digest at generation 1.
struct RVector {
    row: &'static str,
    build: fn(&RBench),
    /// Path and slot.
    obs: [EntryObs; 2],
    want: StepDecision,
    /// `Ok` (`true`) or `Err` (retried on the executor's back-off).
    ok: bool,
    /// Whether P is at its path afterwards.
    p_after: bool,
}

struct RBench {
    p: PathBuf,
    slot: PathBuf,
}

impl RBench {
    fn quarantine(&self) {
        let dir = DirHandle::open(self.p.parent().unwrap()).unwrap();
        let _ = Quarantine::open_or_create(&dir).unwrap();
    }

    fn move_to_slot(&self) {
        self.quarantine();
        std::fs::rename(&self.p, &self.slot).unwrap();
    }

    fn edit(path: &Path) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(b"# edited by another writer\n").unwrap();
    }

    fn foreign_slot(&self) {
        self.quarantine();
        write_mode(&self.slot, b"# another writer's file\n", 0o600);
    }

    fn replace_p(&self, bytes: &[u8]) {
        let tmp = self.p.with_file_name(".rows-editor-tmp");
        write_mode(&tmp, bytes, 0o600);
        std::fs::rename(&tmp, &self.p).unwrap();
    }
}

fn removal_vectors() -> Vec<RVector> {
    let sv = |row, build: fn(&RBench), obs, want, ok, p_after| RVector {
        row,
        build,
        obs,
        want,
        ok,
        p_after,
    };
    vec![
        sv("R1", |_| {}, [V, A], SET(SettleStep::Move), true, false),
        sv(
            "R1a",
            |b| RBench::edit(&b.p),
            [VM, A],
            SET(SettleStep::Done),
            true,
            true,
        ),
        sv(
            "R2",
            |b| b.move_to_slot(),
            [A, V],
            SET(SettleStep::Remove),
            true,
            false,
        ),
        sv(
            "R2",
            |b| {
                b.move_to_slot();
                write_mode(&b.p, b"# another writer's file\n", 0o600);
            },
            [X, V],
            SET(SettleStep::Remove),
            true,
            true,
        ),
        sv(
            "R2a",
            |b| {
                b.move_to_slot();
                RBench::edit(&b.slot);
            },
            [A, VM],
            SET(SettleStep::RecordConflict),
            true,
            false,
        ),
        sv(
            "R3",
            |b| std::fs::remove_file(&b.p).unwrap(),
            [A, A],
            SET(SettleStep::Done),
            true,
            false,
        ),
        // The same bytes under a new identity are not the locator's entry.
        sv(
            "R4",
            |b| {
                let bytes = std::fs::read(&b.p).unwrap();
                b.replace_p(&bytes);
            },
            [X, A],
            SET(SettleStep::Done),
            true,
            true,
        ),
        sv(
            "R5",
            |b| {
                std::fs::remove_file(&b.p).unwrap();
                b.foreign_slot();
            },
            [A, X],
            SET(SettleStep::PutBackForeign),
            true,
            true,
        ),
        sv(
            "R5",
            |b| {
                b.replace_p(b"# the owner's new file\n");
                b.foreign_slot();
            },
            [X, X],
            SET(SettleStep::PutBackForeign),
            true,
            true,
        ),
        sv(
            "R6",
            |b| b.foreign_slot(),
            [V, X],
            hold(HoldReason::ThirdWriter),
            false,
            true,
        ),
        sv(
            "R6",
            |b| {
                RBench::edit(&b.p);
                b.foreign_slot();
            },
            [VM, X],
            hold(HoldReason::ThirdWriter),
            false,
            true,
        ),
    ]
}

fn observe_name(state: NameState) -> EntryObs {
    match state {
        NameState::Absent => A,
        NameState::Expected(ContentState::Unchanged) => V,
        NameState::Expected(ContentState::Modified) => VM,
        NameState::Foreign => X,
        NameState::Unobservable => U,
    }
}

fn run_removal(v: &RVector) {
    let w = World::new(Wk::Replace);
    let p = w.home.config_dir.join("ssh_config");
    let bytes = std::fs::read(&p).unwrap();
    let dir = DirHandle::open(&w.home.config_dir).unwrap();
    let identity = replace::validate(
        &dir,
        "ssh_config",
        &Base::Present {
            sha256: Sha256Hex::of(&bytes),
        },
    )
    .unwrap()
    .identity
    .unwrap();
    let locator = ProjectionLocator {
        role: FileRole::ManagedSsh,
        path: p.to_str().unwrap().to_owned(),
        identity: identity.clone(),
        sha256: Sha256Hex::of(&bytes),
    };
    let slot = slot_name(&locator, 1).unwrap();
    let b = RBench {
        p: p.clone(),
        slot: w.home.config_dir.join(".hm-quarantine").join(&slot),
    };
    (v.build)(&b);
    // The decision: the cleaner's observation of the path and its derived slot, as
    // the locator's entry L (V, with its digest) or not, through `decide`.
    let expected = Expected {
        identity: identity.clone(),
        sha256: locator.sha256.clone(),
    };
    let dir = DirHandle::open(&w.home.config_dir).unwrap();
    let at_path = observe_name(replace::check_name(&dir, "ssh_config", &expected));
    let in_slot = match Quarantine::open_existing(&dir).unwrap() {
        None => A,
        Some(q) => observe_name(q.check_slot(&slot, &expected)),
    };
    drop(dir);
    assert_eq!([at_path, in_slot], v.obs, "the observed symbols");
    let state = blank();
    let obs = StepObservation::normalize(at_path, A, in_slot, &state, StepShape::Removal).unwrap();
    let adr = adr_rows();
    let first = adr_first_match(adr, StepShape::Removal, &state, &obs).map(|r| r.id.as_str());
    assert_eq!(
        first,
        Some(v.row),
        "the ADR's first row naming these symbols"
    );
    let got = decide(StepShape::Removal, &state, &obs);
    assert_eq!(got, v.want, "recovery::decide");
    let row = adr.iter().find(|r| r.id == v.row).unwrap();
    let hold = match got {
        StepDecision::Hold(r) => Some(r),
        _ => None,
    };
    assert!(
        adr_action_agrees(row, hold, None),
        "{got:?} disagrees with {:?}",
        row.action()
    );
    // The cleaner: it writes no stage receipt; its locator is its ownership record.
    let before = w.tree();
    let hook = Arc::new(Recorder::default());
    let result = delete_locator(&w.hooked(&hook), &locator, 1);
    assert_eq!(result.is_ok(), v.ok, "{result:?}");
    assert!(w.receipts().is_empty(), "the cleaner writes no receipt");
    let after = w.tree();
    assert_eq!(p.exists(), v.p_after, "P after the cleaner");
    for (name, e) in &before {
        let kept = after
            .values()
            .any(|a| a.dev == e.dev && a.ino == e.ino && a.bytes == e.bytes);
        let verified = same_inode(&identity, e) && Sha256Hex::of(&e.bytes) == locator.sha256;
        assert!(
            kept || verified,
            "{name} was lost (not the locator's entry)"
        );
    }
    if !v.ok {
        assert_eq!(after, before, "nothing is moved (R6)");
    }
    let again = delete_locator(&w.config(), &locator, 1);
    assert_eq!(again.is_ok(), v.ok, "a second run decides alike");
    assert_eq!(w.tree(), after, "a second run moves nothing");
}

// --- the test ---------------------------------------------------------------------------------

fn panic_text(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_else(|| "a panic".to_owned())
}

/// m02-plan U4 `recovery_table_rows_each_have_a_test_vector` (ADR-0007 §5.7; §12.19
/// item 10): every row of ADR-0007 §5.7's tables has a filesystem vector; each vector
/// builds its entries and receipts on disk, its decided action is its row's, and
/// `reconcile` (the cleaner for R rows) writes the vector's receipts and gives its
/// outcome. A row without a vector fails, and so does a vector whose decision is not
/// its row's action.
#[test]
fn recovery_table_rows_each_have_a_test_vector() {
    let adr = adr_rows();
    let ids: Vec<&str> = adr.iter().map(|r| r.id.as_str()).collect();
    assert!(
        ids.len() >= 80,
        "ADR-0007 §5.7's tables were not read ({} rows)",
        ids.len()
    );
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ids.len(), "a row ID twice in ADR-0007 §5.7");
    for withdrawn in ["H0", "G0", "G1", "G2", "G3"] {
        assert!(!ids.contains(&withdrawn), "{withdrawn} is withdrawn");
    }
    let steps = all_step_vectors();
    let removals = removal_vectors();
    let mut missing = Vec::new();
    for id in &ids {
        let n = steps.iter().filter(|v| v.row == *id).count()
            + removals.iter().filter(|v| v.row == *id).count();
        if n == 0 {
            match NOT_REPRESENTABLE.iter().find(|(r, _)| r == id) {
                Some((r, why)) => println!("row {r}: no filesystem vector on this platform: {why}"),
                None => missing.push(*id),
            }
        }
    }
    assert!(
        missing.is_empty(),
        "rows without a test vector: {missing:?}"
    );
    for (r, _) in NOT_REPRESENTABLE {
        assert!(ids.contains(r), "{r} is not a row of ADR-0007 §5.7");
    }
    let mut failures = Vec::new();
    for (n, v) in steps.iter().enumerate() {
        if let Err(p) = std::panic::catch_unwind(AssertUnwindSafe(|| run_vector(v))) {
            failures.push(format!(
                "{} (vector {n}, {:?}): {}",
                v.row,
                v.world,
                panic_text(p.as_ref())
            ));
        }
    }
    for (n, v) in removals.iter().enumerate() {
        if let Err(p) = std::panic::catch_unwind(AssertUnwindSafe(|| run_removal(v))) {
            failures.push(format!(
                "{} (removal vector {n}): {}",
                v.row,
                panic_text(p.as_ref())
            ));
        }
    }
    println!(
        "{} rows; {} step and item vectors, {} cleaner vectors",
        ids.len(),
        steps.len(),
        removals.len()
    );
    assert!(
        failures.is_empty(),
        "{} vectors failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
