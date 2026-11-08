//! ⟨M03⟩ U0b row 20: **the narrowing protocol** (ADR-0008 D2 item 3a, D7 item 2; rulings
//! §17.4 item 6, §17.7 item 3, §17.9 items 1–2, §17.10 item 1, §17.13 item 1, §17.14
//! items 1–2), used by every narrowing path: an explicit `revoke` and its cascade, authority
//! withdrawn at re-validation (and so an environment-permission removal, reading E6a), a
//! cutoff set or moved earlier, and the lock revocation (row 25).
//!
//! [`Operations::narrow`] runs the steps in this order (the step numbers are row 20's):
//!
//! 1. **Read the set** (one store read; D2 item 3a "Round 0: read the set"). Inside that
//!    same transaction the driver looks for a signing gate on any member. With none
//!    (every grant without a credential instance, which is every grant in wave 0), the
//!    transaction goes on to commit: there is no gate to take, and nothing can sign with
//!    an ungated grant (`SigningGates::admit_shared` answers `NoGate`). A gate created
//!    while this transaction runs admits nobody before it commits, because a signer's
//!    fresh read is a store transaction and the store serializes it after this one. This
//!    is the protocol with an empty gate set, its reads and its commit in one
//!    serializable transaction (questions file G-Q1).
//! 2. With a gated member: the transaction rolls back unwritten, and the narrowing
//!    **marks** every member `narrowing_pending` (step 1) before it waits for anything.
//! 3. **Round 0** (step 2): the set's gates exclusively in global order
//!    (`Narrowing::acquire_all`), then a re-read.
//! 4. **Round 1** (steps 3, 8), only if the re-read found new members: they are marked
//!    **before** any gate is released; every gate is released; the whole set is
//!    reacquired in global order, and as soon as each **root**'s gate (a member whose
//!    parent is not in the set) is held, that root's subtree is read again and any new
//!    member marked and queued (it is deeper, so it sorts after every gate held); then
//!    the set is re-validated.
//! 5. A round-1 re-validation that differs is the `narrowing_set_grew` defect (step 5;
//!    §17.14 item 2): reported, and a further round runs under the same rules. The
//!    commit transaction re-reads the set as well: any member it finds that no round
//!    marked (gated or not; G-Q1, ruled) is the same defect, and again another round
//!    runs. **A narrowing always commits.**
//! 6. **Commit** (one transaction; `committed_at` read inside it, row 27).
//! 7. **Under the gates** (step 10, ⟨r6⟩): in-memory key zeroization and identity
//!    unlisting only ([`NarrowingPoint::UnderGates`]; U10 wires the destruction there).
//! 8. **Release** every gate, then clear this narrowing's marks (`Narrowing::finish`).
//! 9. **Cleanup after the gates** ([`NarrowingPoint::Cleanup`]): slot and binding files,
//!    owned processes (U7/U10), and the M01/M02 adapters' local-denial rounds, which the
//!    callers run after [`Operations::narrow`] returns.
//!
//! "Earlier marks go first" (step 11) is inside `Narrowing::acquire`. A narrowing is
//! **never aborted for time** (step 12): it waits until it holds its gates, and reports
//! `committed_at − requested_at` with the derived bound `H + R(N) + Σ_{X ∈ E(N)} R(X)`,
//! `R(X) = (r_X + 3)·t_read + 4·n_X·ε + t_commit`, in a [`NarrowingReport`] (tracing, the
//! hook's [`NarrowingPoint::Reported`], [`Operations::narrowing_reports`]); past the 20 s
//! target it is also `narrowing_over_target`.
//!
//! Faults and delays are injected through production code only: a [`NarrowingHook`]
//! awaited at every point above (the M01 `StageHook` pattern; production installs none).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{EnvironmentId, GrantId, PolicyId};
use heimdall_store::Txn;

use super::{
    Emit, Ended, Limits, MAX_ANCESTRY, Operations, bound_of, conflict, end_in, grant_context,
    internal,
};
use crate::error::OpError;
use crate::managed::{GateError, GateOrder, Narrowing, SigningGates};
use crate::ports::SessionLockSource;
use crate::timegate::TxnGate;

/// How many reports [`Operations::narrowing_reports`] keeps (the most recent).
const REPORTS_KEPT: usize = 64;

/// Which narrowing path ran (ADR-0008 D2 item 3a "Narrowing commits").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NarrowingKind {
    /// An explicit `revoke` and its cascade.
    Revoke,
    /// Authority withdrawn at re-validation (an environment-permission removal
    /// included, reading E6a).
    Withdrawal,
    /// A cutoff set or moved earlier.
    Cutoff,
    /// The `revoke_on_lock` revocation of a session lock (row 25).
    SessionLock,
}

impl NarrowingKind {
    /// A stable nonsecret name (tracing).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NarrowingKind::Revoke => "revoke",
            NarrowingKind::Withdrawal => "withdrawal",
            NarrowingKind::Cutoff => "cutoff",
            NarrowingKind::SessionLock => "session_lock",
        }
    }
}

/// Which store read of the set a narrowing is about to make (ADR-0008 D2 item 3a
/// "Reads": at most `r + 3` in all).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NarrowingRead {
    /// Before the mark: the read that also decides whether any gate is needed.
    Initial,
    /// Round 0's re-read under the gates.
    Reread,
    /// A root's subtree, read as soon as its gate is held (round ≥ 1).
    Subtree {
        /// The round.
        round: u32,
        /// The root.
        root: GrantId,
    },
    /// A round's re-validation, with every gate held (round ≥ 1).
    Revalidate {
        /// The round.
        round: u32,
    },
}

/// A point of [`Operations::narrow`] at which the [`NarrowingHook`] is awaited, in
/// protocol order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NarrowingPoint {
    /// Before a store read of the set.
    BeforeRead(NarrowingRead),
    /// The marks are set (step 1), before any gate is awaited.
    Marked {
        /// The narrowing's sequence number.
        seq: u64,
        /// The grants marked.
        set: Vec<GrantId>,
    },
    /// Every gate of a round is held, in global order.
    Acquired {
        /// The round (0, 1, …).
        round: u32,
        /// The gates held, in acquisition order.
        held: Vec<GrantId>,
    },
    /// Before the commit transaction (a slow-path commit only).
    BeforeCommit,
    /// Committed, gates still held: in-memory key destruction and identity unlisting.
    UnderGates {
        /// The grants whose keys are destroyed.
        destroy: Vec<GrantId>,
        /// The gates held.
        held: Vec<GrantId>,
    },
    /// Every gate released and this narrowing's marks cleared.
    Released,
    /// The cleanup outside every gate (slot and binding files, owned processes).
    Cleanup {
        /// The grants the cleanup is for.
        grants: Vec<GrantId>,
    },
    /// The narrowing's report (also traced, and kept by
    /// [`Operations::narrowing_reports`]).
    Reported(Box<NarrowingReport>),
}

/// The narrowing fault-injection hook (the M01 `StageHook` pattern): awaited at each
/// [`NarrowingPoint`]. Production installs none ([`Operations::set_narrowing_hook`]).
/// Tests impose the `t_read`/`t_commit` delays and inject set growth here.
pub trait NarrowingHook: Send + Sync {
    /// Called at `point` of a narrowing of `kind`; the narrowing awaits the future.
    fn at<'a>(&'a self, kind: NarrowingKind, point: NarrowingPoint) -> HookFuture<'a>;
}

/// The future a [`NarrowingHook`] returns.
pub type HookFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

/// An earlier narrowing counted in `E(N)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlierNarrowing {
    /// Its sequence number.
    pub seq: u64,
    /// `n_X`: its set size.
    pub members: usize,
    /// `r_X`: its roots.
    pub roots: usize,
}

/// The budgets the derived bound uses (m03-plan §5 item 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundTerms {
    /// `H` = `signing_gate_max_wait`.
    pub h: Duration,
    /// `t_read` = `narrowing_read_budget`.
    pub t_read: Duration,
    /// `t_commit` = `narrowing_commit_budget`.
    pub t_commit: Duration,
    /// `ε` = `pending_check_budget`.
    pub epsilon: Duration,
    /// The 20 s target (`narrowing_gate_wait_max`); reported, never enforced.
    pub target: Duration,
}

impl BoundTerms {
    /// The terms of `limits`.
    #[must_use]
    pub fn of(limits: &Limits) -> Self {
        Self {
            h: limits.signing_gate_max_wait,
            t_read: limits.narrowing_read_budget,
            t_commit: limits.narrowing_commit_budget,
            epsilon: limits.pending_check_budget,
            target: limits.narrowing_gate_wait_max,
        }
    }

    /// `R(X) = (r_X + 3)·t_read + 4·n_X·ε + t_commit` (ADR-0008 D2 item 3a "Work").
    #[must_use]
    pub fn work(&self, members: usize, roots: usize) -> Duration {
        let reads = u32::try_from(roots.saturating_add(3)).unwrap_or(u32::MAX);
        let steps = u32::try_from(members.saturating_mul(4)).unwrap_or(u32::MAX);
        self.t_read
            .saturating_mul(reads)
            .saturating_add(self.epsilon.saturating_mul(steps))
            .saturating_add(self.t_commit)
    }

    /// `H + R(N) + Σ_{X ∈ E(N)} R(X)`.
    #[must_use]
    pub fn bound(&self, members: usize, roots: usize, earlier: &[EarlierNarrowing]) -> Duration {
        earlier
            .iter()
            .fold(self.h.saturating_add(self.work(members, roots)), |b, x| {
                b.saturating_add(self.work(x.members, x.roots))
            })
    }
}

/// What one narrowing reports (ADR-0008 D2 item 3a "It is never aborted for time …
/// Its commit time is reported, together with the derived bound and the terms").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NarrowingReport {
    /// The path.
    pub kind: NarrowingKind,
    /// Its sequence number; `None` when no gate was needed (no marks).
    pub seq: Option<u64>,
    /// When the narrowing was requested (row 27: before any gate wait).
    pub requested_at: Timestamp,
    /// Read inside the commit transaction (row 27).
    pub committed_at: Timestamp,
    /// `committed_at − requested_at` (zero if the wall clock went backwards).
    pub elapsed: Duration,
    /// `n`.
    pub members: usize,
    /// `r`.
    pub roots: usize,
    /// Gates held at the commit.
    pub gates_held: usize,
    /// Rounds after round 0 (0: round 0 sufficed).
    pub rounds: u32,
    /// The `narrowing_set_grew` defect was seen (a round-1 or later re-validation, or
    /// the commit's re-read, found members no round held). Another round ran.
    pub set_grew: bool,
    /// `E(N)`.
    pub earlier: Vec<EarlierNarrowing>,
    /// The budgets used.
    pub terms: BoundTerms,
    /// The derived bound.
    pub bound: Duration,
    /// `elapsed` exceeded the 20 s target (`narrowing_over_target`). Never an abort.
    pub over_target: bool,
}

/// ⟨M03⟩ Row 5: where `admit` takes its time assessment (integrator reading; questions
/// file G-Q3). U3 switches the default to [`AuthorizationTime::ReadOnly`] once
/// `TimeGate::assess_read_only` has its body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorizationTime {
    /// The time gate's rules evaluated over the authorization's own read transaction,
    /// persisting nothing (no high-water mark, no anchor; as `TimeGate::peek`, §0.4
    /// M15). The wave-0 default.
    #[default]
    Peek,
    /// `TimeGate::assess_read_only` (U3; wave 0: always `Uncertain`, so every
    /// signature is refused).
    ReadOnly,
}

/// The state rows 5, 20, 25 and 26 keep in `Operations` (`Inner::narrowing`).
#[derive(Default)]
pub(super) struct NarrowingState {
    hook: RwLock<Option<Arc<dyn NarrowingHook>>>,
    running: Mutex<BTreeMap<u64, Running>>,
    reports: Mutex<VecDeque<NarrowingReport>>,
    pub(super) lock_source: RwLock<Option<Arc<dyn SessionLockSource>>>,
    pub(super) authorization_time: RwLock<AuthorizationTime>,
}

#[derive(Debug, Clone, Default)]
struct Running {
    members: BTreeSet<GrantId>,
    roots: usize,
}

/// Reads a narrowing's set inside a transaction (called for every read of it, and
/// inside the commit transaction).
pub(super) type SetReader =
    Arc<dyn Fn(&mut Txn<'_>) -> heimdall_store::Result<Vec<GrantId>> + Send + Sync>;

/// What the commit closure sees: the commit time read in its transaction, and where
/// it records the grants whose keys are destroyed under the gates.
#[derive(Debug, Clone)]
pub(super) struct CommitCtx {
    /// Read inside the commit transaction (row 27).
    pub(super) committed_at: Timestamp,
    /// Filled by the commit: grants whose key material is destroyed under the gates.
    pub(super) destroy: Vec<GrantId>,
}

/// A committed narrowing.
pub(super) struct Narrowed<R> {
    pub(super) value: R,
    pub(super) report: NarrowingReport,
}

/// One member of a set as the store shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    parent: Option<GrantId>,
    /// Root first, the parent last.
    ancestors: Vec<GrantId>,
}

type Members = BTreeMap<GrantId, Member>;

fn members_of(tx: &mut Txn<'_>, ids: Vec<GrantId>) -> heimdall_store::Result<Members> {
    let mut out = Members::new();
    for id in ids {
        if out.contains_key(&id) {
            continue;
        }
        let parent = tx.grant(&id)?.and_then(|g| g.parent);
        let mut ancestors = Vec::new();
        let mut next = parent.clone();
        while let Some(p) = next {
            if ancestors.len() >= MAX_ANCESTRY || ancestors.contains(&p) {
                break;
            }
            next = tx.grant(&p)?.and_then(|g| g.parent);
            ancestors.push(p);
        }
        ancestors.reverse();
        out.insert(id, Member { parent, ancestors });
    }
    Ok(out)
}

fn roots_of(members: &Members) -> usize {
    members
        .values()
        .filter(|m| m.parent.as_ref().is_none_or(|p| !members.contains_key(p)))
        .count()
}

fn is_root(members: &Members, id: &GrantId) -> bool {
    members
        .get(id)
        .is_some_and(|m| m.parent.as_ref().is_none_or(|p| !members.contains_key(p)))
}

/// The commit time, read inside the commit transaction: the gate's accepted time, else
/// the raw wall clock (as `Operations::narrowing_now`; narrowing never waits for safe
/// time).
pub(super) fn commit_time(gate: &TxnGate, tx: &mut Txn<'_>) -> heimdall_store::Result<Timestamp> {
    Ok(match gate.check(tx)? {
        Ok(s) => s.wall(),
        Err(_) => gate.clock().wall(),
    })
}

fn take_and_commit<R, F>(
    tx: &mut Txn<'_>,
    emit: &mut Emit,
    gate: &TxnGate,
    slot: &Mutex<Option<F>>,
) -> heimdall_store::Result<(R, CommitCtx)>
where
    F: FnOnce(&mut Txn<'_>, &mut Emit, &mut CommitCtx) -> heimdall_store::Result<R>,
{
    let committed_at = commit_time(gate, tx)?;
    let f = slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or_else(|| conflict("the narrowing's commit already ran"))?;
    let mut ctx = CommitCtx {
        committed_at,
        destroy: Vec::new(),
    };
    let value = f(tx, emit, &mut ctx)?;
    Ok((value, ctx))
}

enum Attempt<R> {
    Gated(Members),
    Done(R, CommitCtx, Members),
}

enum Commit<R> {
    Regrow(Members),
    Done(R, CommitCtx),
}

/// Removes a narrowing from the running registry when dropped (`E(N)` counts only
/// still-running narrowings).
struct Registered<'a> {
    state: &'a NarrowingState,
    seq: u64,
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.state
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.seq);
    }
}

impl NarrowingState {
    fn register(&self, seq: u64, members: &Members) -> Registered<'_> {
        self.update(seq, members);
        Registered { state: self, seq }
    }

    fn update(&self, seq: u64, members: &Members) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                seq,
                Running {
                    members: members.keys().cloned().collect(),
                    roots: roots_of(members),
                },
            );
    }

    /// `E(N)`: still-running narrowings with a smaller sequence number whose marks
    /// cover a member (itself or an ancestor).
    fn earlier(&self, seq: u64, members: &Members) -> Vec<EarlierNarrowing> {
        let running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        running
            .range(..seq)
            .filter(|(_, x)| {
                members.iter().any(|(id, m)| {
                    x.members.contains(id) || m.ancestors.iter().any(|a| x.members.contains(a))
                })
            })
            .map(|(s, x)| EarlierNarrowing {
                seq: *s,
                members: x.members.len(),
                roots: x.roots,
            })
            .collect()
    }

    fn keep(&self, report: &NarrowingReport) {
        let mut reports = self.reports.lock().unwrap_or_else(PoisonError::into_inner);
        if reports.len() >= REPORTS_KEPT {
            reports.pop_front();
        }
        reports.push_back(report.clone());
    }
}

impl Operations {
    /// ⟨M03⟩ U0b row 20: install the narrowing fault-injection hook (tests; production
    /// installs none). Replaces any earlier one.
    pub fn set_narrowing_hook(&self, hook: Arc<dyn NarrowingHook>) {
        *self
            .inner
            .narrowing
            .hook
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    /// ⟨M03⟩ U0b row 20: the most recent narrowing reports (oldest first, at most 64).
    #[must_use]
    pub fn narrowing_reports(&self) -> Vec<NarrowingReport> {
        self.inner
            .narrowing
            .reports
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    async fn narrowing_at(&self, kind: NarrowingKind, point: NarrowingPoint) {
        let hook = self
            .inner
            .narrowing
            .hook
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(h) = hook {
            h.at(kind, point).await;
        }
    }

    async fn read_members(&self, reader: &SetReader) -> Result<Members, OpError> {
        let reader = Arc::clone(reader);
        self.write(move |tx, _| {
            let ids = reader(tx)?;
            members_of(tx, ids)
        })
        .await
    }

    async fn read_subtree(&self, root: &GrantId) -> Result<Members, OpError> {
        let root = root.clone();
        self.write(move |tx, _| {
            let mut ids = vec![root.clone()];
            ids.extend(tx.grant_descendants(&root)?);
            members_of(tx, ids)
        })
        .await
    }

    /// Round ≥ 1's reacquisition (D2 item 3a round 1): every gate of `members` in
    /// global order; as soon as a root's gate is held (or, ungated, its turn comes),
    /// its subtree is read again and each new member is marked and queued.
    async fn reacquire_round(
        &self,
        kind: NarrowingKind,
        round: u32,
        narrowing: &mut Narrowing,
        members: &mut Members,
    ) -> Result<(), OpError> {
        let gates = self.signing_gates().clone();
        let order = |gates: &SigningGates, id: &GrantId, m: &Member| {
            gates.order(id).unwrap_or(GateOrder {
                depth: m.ancestors.len(),
                grant: id.clone(),
            })
        };
        let roots: BTreeSet<GrantId> = members
            .keys()
            .filter(|id| is_root(members, id))
            .cloned()
            .collect();
        let mut queue: BTreeSet<GateOrder> =
            members.iter().map(|(id, m)| order(&gates, id, m)).collect();
        while let Some(next) = queue.pop_first() {
            match narrowing.acquire(&next.grant).await {
                Ok(_) => {}
                Err(GateError::OutOfOrder) => {
                    return Err(internal("a narrowing gate was requested out of order"));
                }
                Err(_) => return Err(internal("a narrowing gate could not be taken")),
            }
            if !roots.contains(&next.grant) {
                continue;
            }
            self.narrowing_at(
                kind,
                NarrowingPoint::BeforeRead(NarrowingRead::Subtree {
                    round,
                    root: next.grant.clone(),
                }),
            )
            .await;
            let subtree = self.read_subtree(&next.grant).await?;
            let fresh: Vec<(GrantId, Member)> = subtree
                .into_iter()
                .filter(|(id, _)| !members.contains_key(id))
                .collect();
            if fresh.is_empty() {
                continue;
            }
            narrowing.mark(fresh.iter().map(|(id, _)| id.clone()));
            for (id, m) in fresh {
                queue.insert(order(&gates, &id, &m));
                members.insert(id, m);
            }
        }
        Ok(())
    }

    /// ⟨M03⟩ U0b row 20: run one narrowing (see the module documentation for the steps)
    /// and commit `commit` under every gate of the set `set` reads. `requested_at` is
    /// the caller's admission time (row 27). Never aborted for time; the error paths are
    /// store failures only (and then every gate and mark is released by the drop).
    pub(super) async fn narrow<R, F>(
        &self,
        kind: NarrowingKind,
        requested_at: Timestamp,
        set: SetReader,
        commit: F,
    ) -> Result<Narrowed<R>, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Txn<'_>, &mut Emit, &mut CommitCtx) -> heimdall_store::Result<R>
            + Send
            + 'static,
    {
        let gates = self.signing_gates().clone();
        let gate = self.inner.timegate.in_txn();
        let slot = Arc::new(Mutex::new(Some(commit)));
        // (1) Read the set; with no gated member, commit in the same transaction.
        //
        // G-Q1, ruled (accepted with condition): only when NO member of the set has a
        // gate does the narrowing commit in this one transaction without marks. The
        // moment ANY member has a gate, the full protocol applies to the WHOLE set
        // (marks on every member, gated or not; ordered acquisition; rounds; key
        // destruction under the gates; release, then cleanup).
        //
        // The decision is taken on the full set read in the very transaction that
        // commits, so no "no gate" answer is carried across an await. A gate created
        // after the check (a first credential install) cannot admit a signature that
        // is released after this commit: a signer takes the gate and then makes its
        // fresh read, a store transaction, which the store (`BEGIN IMMEDIATE` and its
        // connection mutex) serializes after this one, so it sees the commit and
        // refuses. A gate that already existed is seen by `contains` (questions file
        // G-Q13 for a gate dropped while a holder still holds it).
        self.narrowing_at(kind, NarrowingPoint::BeforeRead(NarrowingRead::Initial))
            .await;
        let first = {
            let (reader, gates, gate, slot) = (
                Arc::clone(&set),
                gates.clone(),
                gate.clone(),
                Arc::clone(&slot),
            );
            self.write(move |tx, emit| {
                let ids = reader(tx)?;
                let members = members_of(tx, ids)?;
                if members.keys().any(|g| gates.contains(g)) {
                    return Ok(Attempt::Gated(members));
                }
                let (value, ctx) = take_and_commit(tx, emit, &gate, &slot)?;
                Ok(Attempt::Done(value, ctx, members))
            })
            .await?
        };
        let mut members = match first {
            Attempt::Done(value, ctx, members) => {
                return Ok(self
                    .after_commit(
                        kind,
                        requested_at,
                        None,
                        value,
                        ctx,
                        &members,
                        0,
                        false,
                        Vec::new(),
                        None,
                    )
                    .await);
            }
            Attempt::Gated(members) => members,
        };
        // (2) Mark every member before waiting for anything.
        let mut narrowing = gates.begin_narrowing(members.keys().cloned());
        let seq = narrowing.seq();
        let mut earlier = self.inner.narrowing.earlier(seq, &members);
        let registered = self.inner.narrowing.register(seq, &members);
        self.narrowing_at(
            kind,
            NarrowingPoint::Marked {
                seq,
                set: members.keys().cloned().collect(),
            },
        )
        .await;
        // (3) Round 0: the set's gates in global order, then the re-read.
        narrowing
            .acquire_all(members.keys())
            .await
            .map_err(|_| internal("a narrowing gate was requested out of order"))?;
        self.narrowing_at(
            kind,
            NarrowingPoint::Acquired {
                round: 0,
                held: narrowing.held(),
            },
        )
        .await;
        self.narrowing_at(kind, NarrowingPoint::BeforeRead(NarrowingRead::Reread))
            .await;
        let mut fresh: Members = self
            .read_members(&set)
            .await?
            .into_iter()
            .filter(|(id, _)| !members.contains_key(id))
            .collect();
        let mut round: u32 = 0;
        let mut set_grew = false;
        let (value, ctx) = loop {
            if !fresh.is_empty() {
                // (4) Round ≥ 1: mark the new members before releasing any gate,
                // release every gate, reacquire in global order with the roots'
                // subtree re-reads, then re-validate.
                round = round.saturating_add(1);
                narrowing.mark(fresh.keys().cloned());
                members.extend(fresh);
                self.inner.narrowing.update(seq, &members);
                // `E(N)` over the grown set (an earlier narrowing may cover a new member).
                for x in self.inner.narrowing.earlier(seq, &members) {
                    if !earlier.iter().any(|e| e.seq == x.seq) {
                        earlier.push(x);
                    }
                }
                narrowing.release_all();
                self.reacquire_round(kind, round, &mut narrowing, &mut members)
                    .await?;
                self.inner.narrowing.update(seq, &members);
                self.narrowing_at(
                    kind,
                    NarrowingPoint::Acquired {
                        round,
                        held: narrowing.held(),
                    },
                )
                .await;
                self.narrowing_at(
                    kind,
                    NarrowingPoint::BeforeRead(NarrowingRead::Revalidate { round }),
                )
                .await;
                fresh = self
                    .read_members(&set)
                    .await?
                    .into_iter()
                    .filter(|(id, _)| !members.contains_key(id))
                    .collect();
                if !fresh.is_empty() {
                    // (5) The defect: reported, and a further round runs.
                    set_grew = true;
                    tracing::warn!(
                        kind = kind.as_str(),
                        seq,
                        round,
                        new = fresh.len(),
                        "narrowing_set_grew: a re-validation found new members; another round runs"
                    );
                    continue;
                }
            }
            // (6) Commit, re-reading the set inside the transaction.
            self.narrowing_at(kind, NarrowingPoint::BeforeCommit).await;
            let attempt = {
                let (reader, gate, slot) = (Arc::clone(&set), gate.clone(), Arc::clone(&slot));
                let known: BTreeSet<GrantId> = members.keys().cloned().collect();
                self.write(move |tx, emit| {
                    let ids = reader(tx)?;
                    // G-Q1, ruled: the whole set is marked and handled, so any member
                    // no round knew (gated or not) runs another round first.
                    let extra: Vec<GrantId> =
                        ids.into_iter().filter(|g| !known.contains(g)).collect();
                    if !extra.is_empty() {
                        return Ok(Commit::Regrow(members_of(tx, extra)?));
                    }
                    // The commit runs under these gates (a re-run `end_in` defers
                    // only a gated grant outside them).
                    emit.narrowing_set = known;
                    let (value, ctx) = take_and_commit(tx, emit, &gate, &slot)?;
                    Ok(Commit::Done(value, ctx))
                })
                .await?
            };
            match attempt {
                Commit::Done(value, ctx) => break (value, ctx),
                Commit::Regrow(extra) => {
                    set_grew = true;
                    tracing::warn!(
                        kind = kind.as_str(),
                        seq,
                        round,
                        new = extra.len(),
                        "narrowing_set_grew: the commit's re-read found members no round marked; another round runs"
                    );
                    fresh = extra;
                }
            }
        };
        let held = narrowing.held();
        // (7) Under the gates: in-memory key destruction and identity unlisting only.
        self.narrowing_at(
            kind,
            NarrowingPoint::UnderGates {
                destroy: ctx.destroy.clone(),
                held: held.clone(),
            },
        )
        .await;
        // (8) Release every gate, then clear the marks.
        narrowing.finish();
        drop(registered);
        Ok(self
            .after_commit(
                kind,
                requested_at,
                Some(seq),
                value,
                ctx,
                &members,
                round,
                set_grew,
                earlier,
                Some(held.len()),
            )
            .await)
    }

    /// Steps (7)–(9) for the fast path, (8)'s hook and (9) for both, and the report.
    #[allow(clippy::too_many_arguments)]
    async fn after_commit<R>(
        &self,
        kind: NarrowingKind,
        requested_at: Timestamp,
        seq: Option<u64>,
        value: R,
        ctx: CommitCtx,
        members: &Members,
        rounds: u32,
        set_grew: bool,
        earlier: Vec<EarlierNarrowing>,
        held: Option<usize>,
    ) -> Narrowed<R> {
        if held.is_none() {
            self.narrowing_at(
                kind,
                NarrowingPoint::UnderGates {
                    destroy: ctx.destroy.clone(),
                    held: Vec::new(),
                },
            )
            .await;
        }
        self.narrowing_at(kind, NarrowingPoint::Released).await;
        // (9) Cleanup outside every gate: slot and binding files, owned processes
        // (U7/U10 wire them here); the callers' adapter rounds follow.
        self.narrowing_at(
            kind,
            NarrowingPoint::Cleanup {
                grants: ctx.destroy.clone(),
            },
        )
        .await;
        let terms = BoundTerms::of(self.limits());
        let n = members.len();
        let r = roots_of(members);
        let elapsed = Duration::try_from(ctx.committed_at.duration_since(requested_at))
            .unwrap_or(Duration::ZERO);
        let bound = terms.bound(n, r, &earlier);
        let report = NarrowingReport {
            kind,
            seq,
            requested_at,
            committed_at: ctx.committed_at,
            elapsed,
            members: n,
            roots: r,
            gates_held: held.unwrap_or(0),
            rounds,
            set_grew,
            earlier,
            terms,
            bound,
            over_target: elapsed > terms.target,
        };
        if report.over_target {
            tracing::warn!(
                kind = kind.as_str(),
                elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
                members = n,
                roots = r,
                rounds,
                earlier = report.earlier.len(),
                "narrowing_over_target: committed past the 20 s target (reported, never aborted)"
            );
        } else {
            tracing::debug!(
                kind = kind.as_str(),
                elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
                members = n,
                roots = r,
                rounds,
                "narrowing committed"
            );
        }
        self.inner.narrowing.keep(&report);
        self.narrowing_at(kind, NarrowingPoint::Reported(Box::new(report.clone())))
            .await;
        Narrowed { value, report }
    }
}

/// The revoke set of `root`: the root and every descendant (the cascade).
pub(super) fn subtree_reader(root: GrantId) -> SetReader {
    Arc::new(move |tx: &mut Txn<'_>| {
        let mut ids = vec![root.clone()];
        ids.extend(tx.grant_descendants(&root)?);
        Ok(ids)
    })
}

/// Reading E6c: the set of a cutoff on `policy` at `at` is every `active` or
/// `degraded` grant of the policy's profile, the policy applicable to it here, whose
/// bound the cutoff lowers, with its descendants (their bound is at most their
/// parent's). A later cutoff (widening) lowers nothing: the set is empty.
pub(super) fn cutoff_reader(env: EnvironmentId, policy: PolicyId, at: Timestamp) -> SetReader {
    Arc::new(move |tx: &mut Txn<'_>| {
        let Some(p) = tx.policy(&policy)? else {
            return Ok(Vec::new());
        };
        if !tx
            .policies_for(&p.profile, &env)?
            .iter()
            .any(|q| q.id == p.id)
        {
            return Ok(Vec::new());
        }
        let mut out: Vec<GrantId> = Vec::new();
        let mut seen: BTreeSet<GrantId> = BTreeSet::new();
        for g in tx.grants_due(Timestamp::MAX)? {
            if !g.state.permits_use() || seen.contains(&g.id) {
                continue;
            }
            let ctx = grant_context(tx, &g)?;
            if ctx.profile.as_ref() != Some(&p.profile) {
                continue;
            }
            if at >= bound_of(tx, &env, &g, ctx.profile.as_ref())? {
                continue;
            }
            let mut ids = vec![g.id.clone()];
            ids.extend(tx.grant_descendants(&g.id)?);
            for id in ids {
                if seen.insert(id.clone()) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    })
}

impl Operations {
    /// Reading E6c: a cutoff set or moved earlier commits `commit` (the policy write)
    /// through the narrowing protocol. Its keys are not destroyed here: the affected
    /// grants end at the cutoff like expiry (ADR-0008 D7 item 8), and the signer refuses
    /// from the commit on (the bound is in its fresh read).
    pub(super) async fn narrow_cutoff<R, F>(
        &self,
        policy: &PolicyId,
        at: Timestamp,
        requested_at: Timestamp,
        commit: F,
    ) -> Result<R, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Txn<'_>, &mut Emit) -> heimdall_store::Result<R> + Send + 'static,
    {
        let reader = cutoff_reader(self.environment().clone(), policy.clone(), at);
        let n = self
            .narrow(
                NarrowingKind::Cutoff,
                requested_at,
                reader,
                move |tx, emit, _| commit(tx, emit),
            )
            .await?;
        Ok(n.value)
    }

    /// Reading E6b: each withdrawal [`end_in`] detected for a gated cascade, re-run
    /// under the gates: the set is the root's subtree, the commit `end_in` itself
    /// (fresh time assessed in the commit; uncertain time ends nothing, as at every
    /// detection). What it ended is completed by the caller
    /// (`Operations::complete_withdrawals`). A failure leaves the grant as it was:
    /// every use is refused already, and the next use or scheduler pass detects it
    /// again.
    pub(super) async fn narrow_withdrawals(&self, gated: Vec<(GrantId, Timestamp)>) -> Ended {
        let mut out = Ended::default();
        for (root, detected_at) in gated {
            let gate = self.inner.timegate.in_txn();
            let env = self.environment().clone();
            let adapters = self.adapter_infos();
            let retention = self.retention();
            let r = root.clone();
            let done = self
                .narrow(
                    NarrowingKind::Withdrawal,
                    detected_at,
                    subtree_reader(root.clone()),
                    move |tx, emit, ctx| {
                        let Ok(safe) = gate.check(tx)? else {
                            return Ok(Ended::default());
                        };
                        let ended =
                            end_in(tx, emit, &env, &adapters, &gate, &r, &safe, None, retention)?;
                        ctx.destroy = ended
                            .withdrawn
                            .iter()
                            .flat_map(|(_, all)| all.iter().cloned())
                            .collect();
                        Ok(ended)
                    },
                )
                .await;
            match done {
                Ok(n) => out.extend(n.value),
                Err(e) => {
                    tracing::warn!(code = %e.code, "a withdrawal could not commit under its gates; it is detected again");
                }
            }
        }
        out
    }
}

impl Operations {
    /// The policy write of `Operations::policy`: a `cutoff` goes through
    /// [`Self::narrow_cutoff`] (reading E6c), every other action commits as before.
    pub(super) async fn policy_commit<R, F>(
        &self,
        req: &heimdall_contract::request::PolicyAction,
        requested_at: Timestamp,
        commit: F,
    ) -> Result<R, OpError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Txn<'_>, &mut Emit) -> heimdall_store::Result<R> + Send + 'static,
    {
        match req {
            heimdall_contract::request::PolicyAction::Cutoff { policy_id, at } => {
                self.narrow_cutoff(policy_id, *at, requested_at, commit)
                    .await
            }
            _ => self.write(commit).await,
        }
    }
}
