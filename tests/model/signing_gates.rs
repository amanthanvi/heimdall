//! M03 wave 0, U0b row 24 (and the app-layer half of row 21): the signing gates, the
//! pending marks, the delegation hold and the signing permit (`heimdall_app::managed`;
//! ADR-0008 D2 item 3a).
//!
//! Deterministic: every ordering is forced by polling a future exactly once (it
//! queues at the gate and returns `Pending`) or by dropping a guard; no sleep orders
//! anything. The only real-time waits are 1 ms gate timeouts whose outcome cannot
//! depend on timing (the holder never releases). The permit's expiry is checked at
//! explicit clock readings. (`tokio::time::pause` needs tokio's `test-util`, which
//! this crate's dev-dependencies do not enable.)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use heimdall_app::managed::{
    Acquired, GateError, GateOrder, MANAGED_PREPARE_WITHOUT_DRIVER, PermitExpiry, ReleaseRefusal,
    SigningGates, driver_results,
};
use heimdall_app::operations::Limits;
use heimdall_app::ports::{AdapterError, IntegrationSnapshot, ManagedSources};
use heimdall_contract::Timestamp;
use heimdall_contract::ids::GrantId;
use tokio::time::Instant;

const LONG: Duration = Duration::from_secs(3600);
const TINY: Duration = Duration::from_millis(1);

fn g(n: u8) -> GrantId {
    GrantId::from_random_bytes([n; 16])
}

/// A `'static` grant ID, for futures polled across statements.
fn gr(n: u8) -> &'static GrantId {
    Box::leak(Box::new(g(n)))
}

fn leak<const N: usize>(ids: [GrantId; N]) -> &'static [GrantId] {
    Box::leak(Box::new(ids))
}

fn t0() -> Timestamp {
    "2026-11-08T09:00:00Z".parse().unwrap()
}

/// Poll `f` exactly once.
async fn poll_once<F: Future + ?Sized>(f: Pin<&mut F>) -> Poll<F::Output> {
    let mut f = Some(f);
    std::future::poll_fn(move |cx| Poll::Ready(f.take().unwrap().poll(cx))).await
}

/// A forest: roots R (1) and S (2); R → C1 (3) → D (5); R → C2 (4).
fn forest() -> SigningGates {
    let gates = SigningGates::new();
    assert!(gates.retain(&g(1), &[]));
    assert!(gates.retain(&g(2), &[]));
    assert!(gates.retain(&g(3), &[g(1)]));
    assert!(gates.retain(&g(4), &[g(1)]));
    assert!(gates.retain(&g(5), &[g(1), g(3)]));
    gates
}

// --- row 24 -------------------------------------------------------------------------

#[tokio::test]
async fn gate_shared_and_exclusive_semantics() {
    let gates = forest();
    // Shared: any number at once.
    let s1 = gates.acquire_shared(&g(3), LONG).await.unwrap();
    let s2 = gates.acquire_shared(&g(3), LONG).await.unwrap();
    assert_eq!(s1.grant(), &g(3));

    // Exclusive waits for every shared holder.
    let mut n = gates.begin_narrowing([g(3)]);
    {
        let mut x = Box::pin(n.acquire(gr(3)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        drop(s1);
        assert!(poll_once(x.as_mut()).await.is_pending());
        drop(s2);
        assert_eq!(x.await, Ok(Acquired::Held));
    }
    assert!(n.holds(&g(3)));
    assert_eq!(n.acquire(&g(3)).await, Ok(Acquired::AlreadyHeld));

    // While held exclusively, a shared wait times out; other gates are unaffected.
    assert_eq!(
        gates.acquire_shared(&g(3), TINY).await.err(),
        Some(GateError::Timeout)
    );
    assert!(gates.acquire_shared(&g(4), TINY).await.is_ok());

    // A grant without a gate has nothing to take.
    assert_eq!(
        gates.acquire_shared(&g(99), LONG).await.err(),
        Some(GateError::NoGate)
    );
    assert_eq!(n.acquire(&g(99)).await, Ok(Acquired::NoGate));

    // Ending the narrowing releases the gate.
    n.finish();
    assert!(gates.acquire_shared(&g(3), TINY).await.is_ok());
}

#[tokio::test]
async fn exclusive_acquisition_follows_lock_order() {
    let gates = forest();
    // Depth first, then grant ID; ungated grants omitted; duplicates collapsed.
    let order = gates.sort_global([g(5), g(4), g(2), g(99), g(1), g(3), g(4)].iter());
    let expect = vec![
        GateOrder {
            depth: 0,
            grant: g(1),
        },
        GateOrder {
            depth: 0,
            grant: g(2),
        },
        GateOrder {
            depth: 1,
            grant: g(3),
        },
        GateOrder {
            depth: 1,
            grant: g(4),
        },
        GateOrder {
            depth: 2,
            grant: g(5),
        },
    ];
    assert_eq!(order, expect);

    let mut n = gates.begin_narrowing([g(1)]);
    n.acquire_all([g(5), g(3), g(1), g(99)].iter())
        .await
        .unwrap();
    assert_eq!(n.held(), vec![g(1), g(3), g(5)]);

    // Never a gate that sorts before one held: nothing is acquired.
    assert_eq!(n.acquire(&g(4)).await, Err(GateError::OutOfOrder));
    assert_eq!(n.acquire(&g(2)).await, Err(GateError::OutOfOrder));
    assert_eq!(n.held(), vec![g(1), g(3), g(5)]);
    assert!(gates.acquire_shared(&g(4), TINY).await.is_ok());

    // Round 1: release every gate (marks kept), then reacquire in global order.
    n.release_all();
    assert!(n.held().is_empty());
    assert!(gates.is_pending(&g(5)));
    assert!(gates.acquire_shared(&g(5), TINY).await.is_ok());
    n.acquire_all([g(1), g(2), g(3), g(4), g(5)].iter())
        .await
        .unwrap();
    assert_eq!(n.held(), vec![g(1), g(2), g(3), g(4), g(5)]);
}

#[tokio::test]
async fn gate_is_fair_writer_not_starved() {
    // Assumption A3: once a narrowing queues exclusively, no later shared request is
    // granted ahead of it.
    let gates = forest();
    let early = gates.acquire_shared(&g(1), LONG).await.unwrap();

    let mut n = gates.begin_narrowing(Vec::<GrantId>::new());
    let mut x = Box::pin(n.acquire(gr(1)));
    assert!(poll_once(x.as_mut()).await.is_pending()); // queued behind `early`

    // Later shared requests queue behind the writer, even though only a shared
    // holder is present.
    let mut later = Box::pin(gates.acquire_shared(gr(1), LONG));
    assert!(poll_once(later.as_mut()).await.is_pending());
    assert_eq!(
        gates.acquire_shared(&g(1), TINY).await.err(),
        Some(GateError::Timeout)
    );

    // The shared holder ends: the writer, not the later reader, gets the gate.
    drop(early);
    assert!(poll_once(later.as_mut()).await.is_pending());
    assert_eq!(x.await, Ok(Acquired::Held));
    assert!(poll_once(later.as_mut()).await.is_pending());

    // The writer ends: the later reader proceeds.
    n.finish();
    assert!(later.await.is_ok());
}

#[tokio::test]
async fn gate_created_with_first_instance_dropped_with_last() {
    let gates = SigningGates::new();
    assert!(!gates.contains(&g(3)));
    assert!(gates.retain(&g(3), &[g(1)]));
    // A later instance does not re-record the chain.
    assert!(!gates.retain(&g(3), &[g(7), g(8)]));
    assert_eq!(gates.instances(&g(3)), 2);
    assert_eq!(gates.ancestors(&g(3)), Some(vec![g(1)]));
    assert_eq!(
        gates.order(&g(3)),
        Some(GateOrder {
            depth: 1,
            grant: g(3)
        })
    );

    assert!(!gates.release(&g(3)));
    assert!(gates.contains(&g(3)));
    // The last instance with nothing keeping the gate: dropped at once.
    assert!(gates.release(&g(3)));
    assert!(!gates.contains(&g(3)));
    assert_eq!(gates.instances(&g(3)), 0);
    assert!(!gates.release(&g(3)));
    assert_eq!(
        gates.acquire_shared(&g(3), LONG).await.err(),
        Some(GateError::NoGate)
    );
    // Re-created with a new first instance.
    assert!(gates.retain(&g(3), &[g(1)]));
    assert!(gates.acquire_shared(&g(3), TINY).await.is_ok());
}

// --- §17.15: retiring gates -------------------------------------------------------

#[tokio::test]
async fn last_instance_release_keeps_gate_while_signer_holds_it() {
    let gates = forest();
    let wall = t0();
    let gate = gates.admit_shared(&g(5), LONG).await.unwrap();
    let permit = SigningGates::permit(
        gate,
        PermitExpiry::new(
            wall + jiff::SignedDuration::from_secs(60),
            Instant::now() + LONG,
        ),
        Arc::new(move || Some(wall)),
    );
    // The last instance goes while the signer holds the gate: the entry stays.
    assert!(!gates.release(&g(5)));
    assert!(gates.contains(&g(5)));
    assert!(gates.is_retiring(&g(5)));
    assert_eq!(gates.instances(&g(5)), 0);
    assert_eq!(
        gates.order(&g(5)),
        Some(GateOrder {
            depth: 2,
            grant: g(5)
        })
    );
    assert_eq!(gates.sort_global([g(5)].iter()).len(), 1);

    // A narrowing then finds the gate and waits for the signer.
    let mut n = gates.begin_narrowing([g(5)]);
    {
        let mut x = Box::pin(n.acquire(gr(5)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        assert!(poll_once(x.as_mut()).await.is_pending());
        assert!(!permit.may_release()); // the mark refuses the release
        drop(permit);
        assert_eq!(x.await, Ok(Acquired::Held));
    }
    assert!(gates.contains(&g(5)));
    // The narrowing ends (holder and mark gone): the entry is dropped.
    n.finish();
    assert!(!gates.contains(&g(5)));
    assert_eq!(gates.holders(&g(5)), 0);
}

#[tokio::test]
async fn retiring_gate_dropped_once_last_holder_and_mark_gone() {
    let gates = forest();
    let a = gates.acquire_shared(&g(4), LONG).await.unwrap();
    let b = gates.acquire_shared(&g(4), LONG).await.unwrap();
    // A waiter counts too.
    let mut n = gates.begin_narrowing(Vec::<GrantId>::new());
    {
        let mut x = Box::pin(n.acquire(gr(4)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        assert_eq!(gates.holders(&g(4)), 3);
        assert!(!gates.release(&g(4)));
        drop(a);
        assert!(gates.contains(&g(4)));
        drop(b);
        assert_eq!(x.await, Ok(Acquired::Held));
    }
    assert!(gates.contains(&g(4)));
    drop(n);
    assert!(!gates.contains(&g(4)));
    // A delegation hold keeps its chain's gates the same way.
    let hold = gates
        .hold_for_delegation(&g(3), &[g(1)], LONG)
        .await
        .unwrap();
    assert!(!gates.release(&g(3)));
    assert!(gates.is_retiring(&g(3)));
    drop(hold);
    assert!(!gates.contains(&g(3)));
}

#[tokio::test]
async fn pending_mark_keeps_retiring_gate() {
    let gates = forest();
    // A mark on the ancestor covers D; no one holds D's gate.
    let n = gates.begin_narrowing([g(1)]);
    assert!(!gates.release(&g(5)));
    assert!(gates.contains(&g(5)));
    assert!(gates.is_retiring(&g(5)));
    assert_eq!(gates.holders(&g(5)), 0);
    // Only the mark keeps it: cleared, the entry goes.
    n.finish();
    assert!(!gates.contains(&g(5)));
    // An uncovered sibling was never kept.
    assert!(gates.release(&g(4)));
    assert!(!gates.contains(&g(4)));
}

#[tokio::test]
async fn retain_revives_retiring_gate_with_same_lock() {
    let gates = forest();
    let held = gates.acquire_shared(&g(2), LONG).await.unwrap();
    assert!(!gates.release(&g(2)));
    assert!(gates.is_retiring(&g(2)));
    // A new instance revives it, with the same lock: the old holder still excludes.
    assert!(!gates.retain(&g(2), &[]));
    assert!(!gates.is_retiring(&g(2)));
    assert_eq!(gates.instances(&g(2)), 1);
    let mut n = gates.begin_narrowing(Vec::<GrantId>::new());
    {
        let mut x = Box::pin(n.acquire(gr(2)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        drop(held);
        assert_eq!(x.await, Ok(Acquired::Held));
    }
    drop(n);
    assert!(gates.contains(&g(2)));
}

#[tokio::test]
async fn release_exclusive_waits_for_holders_then_releases() {
    let gates = forest();
    let signer = gates.admit_shared(&g(2), LONG).await.unwrap();
    {
        let mut r = Box::pin(gates.release_exclusive(gr(2)));
        assert!(poll_once(r.as_mut()).await.is_pending());
        // Not released while the signer holds the gate.
        assert_eq!(gates.instances(&g(2)), 1);
        drop(signer);
        assert!(r.await);
    }
    assert!(!gates.contains(&g(2)));
    // Not the last instance: the gate stays, unretired.
    gates.retain(&g(1), &[]);
    assert!(!gates.release_exclusive(&g(1)).await);
    assert_eq!(gates.instances(&g(1)), 1);
    assert!(!gates.release_exclusive(&g(99)).await);
}

#[tokio::test]
async fn narrowing_releases_instance_under_its_exclusive_hold() {
    let gates = forest();
    let mut n = gates.begin_narrowing([g(2)]);
    assert_eq!(n.release_instance(&g(2)), Err(GateError::NoGate));
    assert_eq!(gates.instances(&g(2)), 1);
    n.acquire(&g(2)).await.unwrap();
    assert_eq!(n.release_instance(&g(2)), Ok(false)); // kept: held and marked
    assert!(gates.is_retiring(&g(2)));
    n.finish();
    assert!(!gates.contains(&g(2)));
}

// --- pending marks -------------------------------------------------------------------

#[tokio::test]
async fn pending_mark_covers_ancestors_and_later_descendants() {
    let gates = forest();
    let n = gates.begin_narrowing([g(1)]);
    assert!(gates.is_pending(&g(1)));
    assert!(gates.is_pending(&g(3)));
    assert!(gates.is_pending(&g(5))); // grandchild, through the recorded chain
    assert!(!gates.is_pending(&g(2)));
    // A descendant created after the mark is covered from the moment it exists.
    gates.retain(&g(6), &[g(1), g(4)]);
    assert!(gates.is_pending(&g(6)));
    // A grant with no gate yet, with the chain the caller read.
    assert!(gates.is_pending_with(&g(9), &[g(1), g(4), g(6)]));
    assert!(!gates.is_pending_with(&g(9), &[g(2)]));
    // Only the marked grant itself is counted.
    assert_eq!(gates.mark_count(&g(1)), 1);
    assert_eq!(gates.mark_count(&g(3)), 0);
    drop(n);
    assert!(!gates.is_pending(&g(5)));
    assert!(!gates.is_pending(&g(6)));
}

#[tokio::test]
async fn pending_marks_counted_per_narrowing() {
    let gates = forest();
    let a = gates.begin_narrowing([g(3), g(5)]);
    let b = gates.begin_narrowing([g(5)]);
    assert!(a.seq() < b.seq());
    assert_eq!(gates.mark_count(&g(5)), 2);
    assert_eq!(gates.running_narrowings(), vec![a.seq(), b.seq()]);
    // A narrowing clears only its own marks.
    b.finish();
    assert_eq!(gates.mark_count(&g(5)), 1);
    assert!(gates.is_pending(&g(5)));
    assert_eq!(gates.running_narrowings(), vec![a.seq()]);
    drop(a);
    assert_eq!(gates.mark_count(&g(5)), 0);
    assert!(!gates.is_pending(&g(5)));
    assert!(gates.running_narrowings().is_empty());
}

#[tokio::test]
async fn narrowing_marks_new_members_under_its_sequence() {
    let gates = forest();
    let mut n = gates.begin_narrowing([g(4)]);
    assert!(!gates.is_pending(&g(5)));
    n.mark([g(5), g(5)]);
    assert!(gates.is_pending(&g(5)));
    assert_eq!(gates.mark_count(&g(5)), 1);
    assert!(n.marked().contains(&g(5)));
    drop(n);
    assert!(!gates.is_pending(&g(4)));
    assert!(!gates.is_pending(&g(5)));
}

#[tokio::test]
async fn earlier_marks_detected_through_ancestors() {
    let gates = forest();
    let early = gates.begin_narrowing([g(1)]);
    let late = gates.begin_narrowing([g(3)]);
    // C1 is covered by the earlier narrowing through its ancestor R.
    assert_eq!(late.earlier_covering(&g(3)), Some(early.seq()));
    assert_eq!(late.earlier_covering(&g(5)), Some(early.seq()));
    assert_eq!(late.earlier_covering(&g(2)), None);
    // Never by a later one.
    assert_eq!(early.earlier_covering(&g(3)), None);
    drop(early);
    assert_eq!(late.earlier_covering(&g(3)), None);
}

#[tokio::test]
async fn later_narrowing_defers_to_earlier_mark_without_queuing() {
    let gates = forest();
    let mut early = gates.begin_narrowing([g(1)]);
    let mut late = gates.begin_narrowing([g(3)]);

    // The gate is free, but the later narrowing waits for the earlier one instead
    // of queuing for it.
    {
        let mut x = Box::pin(late.acquire(gr(3)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        // Not queued at the gate: the earlier narrowing takes it at once.
        assert_eq!(early.acquire(&g(1)).await, Ok(Acquired::Held));
        let free = tokio::time::timeout(Duration::from_secs(10), early.acquire(&g(3))).await;
        assert_eq!(
            free.ok(),
            Some(Ok(Acquired::Held)),
            "the later narrowing queued"
        );
        assert!(poll_once(x.as_mut()).await.is_pending());
        early.finish();
        assert_eq!(x.await, Ok(Acquired::Held));
    }
    // An uncovered gate is taken without deferring.
    assert_eq!(late.acquire(&g(4)).await, Ok(Acquired::Held));
}

// --- signers and delegations ----------------------------------------------------------

#[tokio::test]
async fn admit_shared_checks_pending_first_and_releases_gate() {
    let gates = forest();
    let mut n = gates.begin_narrowing([g(1)]);
    // The descendant's gate is free, but its ancestor is marked: refused, and the
    // gate is released at once.
    assert_eq!(
        gates.admit_shared(&g(5), LONG).await.err(),
        Some(GateError::Pending)
    );
    assert_eq!(n.acquire(&g(5)).await, Ok(Acquired::Held));
    drop(n);
    let ok = gates.admit_shared(&g(5), LONG).await.unwrap();
    assert!(!ok.is_pending());
}

#[tokio::test]
async fn delegation_holds_ancestor_chain_shared_root_first() {
    let gates = forest();
    // Delegating from D: R, C1 and D held shared, in global order.
    let hold = gates
        .hold_for_delegation(&g(5), &[g(1), g(3)], LONG)
        .await
        .unwrap();
    assert_eq!(hold.held(), vec![g(1), g(3), g(5)]);
    assert!(!hold.is_pending());
    // Signers still proceed (shared).
    assert!(gates.acquire_shared(&g(1), TINY).await.is_ok());

    // A narrowing that takes the root waits for the hold: the subtree is frozen.
    let mut n = gates.begin_narrowing([g(1)]);
    assert!(hold.is_pending()); // the re-check before the child's first install
    {
        let mut x = Box::pin(n.acquire(gr(1)));
        assert!(poll_once(x.as_mut()).await.is_pending());
        assert!(hold.held_for(Instant::now()) < LONG);
        drop(hold);
        assert_eq!(x.await, Ok(Acquired::Held));
    }
}

#[tokio::test]
async fn delegation_refused_from_pending_grant() {
    let gates = forest();
    let _n = gates.begin_narrowing([g(1)]);
    assert_eq!(
        gates.hold_for_delegation(&g(3), &[g(1)], LONG).await.err(),
        Some(GateError::Pending)
    );
    // An unmarked root delegates.
    assert_eq!(
        gates
            .hold_for_delegation(&g(2), &[], LONG)
            .await
            .unwrap()
            .held(),
        vec![g(2)]
    );
    // A parent with no gate has nothing to hold.
    assert_eq!(
        gates.hold_for_delegation(&g(98), &[], LONG).await.err(),
        Some(GateError::NoGate)
    );
}

#[tokio::test]
async fn delegation_rechecks_pending_after_each_awaited_acquisition() {
    let gates = forest();
    // Another narrowing (no marks) holds C1 exclusively.
    let mut blocker = gates.begin_narrowing(Vec::<GrantId>::new());
    blocker.acquire(&g(3)).await.unwrap();

    let mut d = Box::pin(gates.hold_for_delegation(gr(5), leak([g(1), g(3)]), LONG));
    assert!(poll_once(d.as_mut()).await.is_pending()); // R held, waiting for C1

    // A narrowing marks R while the delegation waits.
    let mut n = gates.begin_narrowing([g(1)]);
    blocker.finish();
    // After the awaited acquisition of C1 the re-check finds the mark.
    assert_eq!(d.await.err(), Some(GateError::Pending));
    // Every gate the delegation took was released.
    assert_eq!(n.acquire(&g(1)).await, Ok(Acquired::Held));
    assert_eq!(n.acquire(&g(3)).await, Ok(Acquired::Held));
}

#[tokio::test]
async fn delegation_wait_is_bounded() {
    let gates = forest();
    let mut blocker = gates.begin_narrowing(Vec::<GrantId>::new());
    blocker.acquire(&g(3)).await.unwrap();
    assert_eq!(
        gates.hold_for_delegation(&g(3), &[g(1)], TINY).await.err(),
        Some(GateError::Timeout)
    );
    // R was released on the timeout.
    assert_eq!(blocker.acquire(&g(5)).await, Ok(Acquired::Held));
    let mut other = gates.begin_narrowing(Vec::<GrantId>::new());
    assert_eq!(other.acquire(&g(1)).await, Ok(Acquired::Held));
}

// --- the permit ----------------------------------------------------------------------

#[tokio::test]
async fn permit_release_check_refuses_on_expiry_unsafe_time_or_pending() {
    let gates = forest();
    let now = Instant::now();
    let wall = t0();
    let expiry = PermitExpiry::new(wall + jiff::SignedDuration::from_secs(30), now + LONG)
        .tighten_wall(wall + jiff::SignedDuration::from_secs(10))
        .tighten_wall(wall + jiff::SignedDuration::from_secs(20))
        .tighten_continuous(now + Duration::from_secs(5));
    assert_eq!(expiry.wall, wall + jiff::SignedDuration::from_secs(10));
    assert_eq!(expiry.continuous, now + Duration::from_secs(5));

    let gate = gates.admit_shared(&g(5), LONG).await.unwrap();
    let permit = SigningGates::permit(gate, expiry, Arc::new(move || Some(wall)));
    assert_eq!(permit.grant(), Some(&g(5)));
    assert_eq!(permit.verification(), None);
    assert_eq!(permit.expires_at(), now + Duration::from_secs(5));
    assert_eq!(
        permit.expires_wall(),
        wall + jiff::SignedDuration::from_secs(10)
    );

    assert!(permit.may_release_at(Some(wall), now));
    assert!(permit.may_release());
    // The continuous clock reaches the expiry.
    assert_eq!(
        permit.release_refusal_at(Some(wall), now + Duration::from_secs(5)),
        Some(ReleaseRefusal::ExpiredContinuous)
    );
    // The wall clock reaches it.
    assert_eq!(
        permit.release_refusal_at(Some(wall + jiff::SignedDuration::from_secs(10)), now),
        Some(ReleaseRefusal::ExpiredWall)
    );
    // Time not `Safe`.
    assert_eq!(
        permit.release_refusal_at(None, now),
        Some(ReleaseRefusal::TimeNotSafe)
    );
    // A mark set after admission, on an ancestor.
    let n = gates.begin_narrowing([g(1)]);
    assert_eq!(
        permit.release_refusal_at(Some(wall), now),
        Some(ReleaseRefusal::NarrowingPending)
    );
    assert!(!permit.may_release());
    drop(n);
    assert!(permit.may_release_at(Some(wall), now));

    // The permit holds the gate shared until dropped.
    let mut x = gates.begin_narrowing(Vec::<GrantId>::new());
    {
        let mut fut = Box::pin(x.acquire(gr(5)));
        assert!(poll_once(fut.as_mut()).await.is_pending());
        drop(permit);
        assert_eq!(fut.await, Ok(Acquired::Held));
    }
}

#[tokio::test]
async fn permit_with_unsafe_time_source_never_releases() {
    let gates = forest();
    let gate = gates.admit_shared(&g(2), LONG).await.unwrap();
    let permit = SigningGates::permit(
        gate,
        PermitExpiry::new(
            t0() + jiff::SignedDuration::from_secs(60),
            Instant::now() + LONG,
        ),
        Arc::new(|| None),
    );
    assert!(!permit.may_release());
}

// --- the limits (m03-plan §5 item 17) ----------------------------------------------

#[test]
fn m03_limits_match_plan_item_17() {
    let l = Limits::default();
    assert_eq!(l.signature_authorization_timeout, Duration::from_secs(2));
    assert_eq!(l.signing_gate_wait, Duration::from_secs(1));
    assert_eq!(l.signing_enqueue_timeout, Duration::from_secs(2));
    assert_eq!(l.signing_budget, Duration::from_secs(1));
    assert_eq!(l.signing_holder_max, Duration::from_secs(5));
    assert_eq!(l.delegation_gate_hold_max, Duration::from_secs(10));
    assert_eq!(l.connection_registration_txn_max, Duration::from_secs(2));
    // H is the longest holder bound (Q27).
    assert_eq!(
        l.signing_gate_max_wait,
        l.signing_holder_max
            .max(l.delegation_gate_hold_max)
            .max(l.connection_registration_txn_max)
    );
    assert_eq!(l.signing_gate_max_wait, Duration::from_secs(10));
    assert_eq!(l.narrowing_gate_wait_max, Duration::from_secs(20));
    // R at the budgets: (16 + 3)·t_read + 4·256·ε + t_commit ≈ 4.07 s, so H + R and
    // H + 2R are within the 20 s target (§17.13 item 1).
    let r = l.narrowing_read_budget * (u32::try_from(l.narrowing_root_budget).unwrap() + 3)
        + l.pending_check_budget * (4 * u32::try_from(l.narrowing_set_budget).unwrap())
        + l.narrowing_commit_budget;
    assert_eq!(r, Duration::from_millis(4074));
    assert!(l.signing_gate_max_wait + r * 2 <= l.narrowing_gate_wait_max);
    // Payload limits fit one control frame.
    assert_eq!(l.remote_stdout_max, 512 * 1024);
    assert!(l.remote_stdout_max < heimdall_contract::ipc::MAX_CONTROL_FRAME_BYTES);
    assert_eq!(l.registry_max_bytes, 128 * 1024);
    // Derived step deadlines: timeout + 60 s (+ 30 s).
    assert_eq!(l.enrollment_not_after(false), Duration::from_secs(180));
    assert_eq!(l.enrollment_not_after(true), Duration::from_secs(360));
    assert_eq!(
        l.enrollment_step_hard_deadline(false),
        Duration::from_secs(210)
    );
    assert_eq!(
        l.enrollment_step_hard_deadline(true),
        Duration::from_secs(390)
    );
    assert_eq!(l.residual_drift_ppm, 100);
    assert_eq!(l.verification_attempts, 3);
}

// --- row 21, the app-layer half ---------------------------------------------------

#[test]
fn managed_prepare_from_without_driver_results_is_protocol_error() {
    let protocol = Err::<(), _>(AdapterError::Protocol(
        MANAGED_PREPARE_WITHOUT_DRIVER.to_owned(),
    ));
    assert_eq!(
        driver_results(&IntegrationSnapshot::default()).map(|_| ()),
        protocol
    );
    let without = IntegrationSnapshot {
        managed: Some(ManagedSources::default()),
        ..IntegrationSnapshot::default()
    };
    assert_eq!(driver_results(&without).map(|_| ()), protocol);
}

#[tokio::test]
async fn existing_access_prepare_contract_unchanged() {
    // The M02 contract is unchanged for every existing-access adapter: no managed
    // sources in its snapshot, no remote credential effect, no remote residuals. The
    // app-layer half, over the testkit adapter (the real native-agent and 1Password
    // adapters live in heimdall-adapters).
    use heimdall_app::ports::LockContinuity;
    use heimdall_app::ports::{AdapterDescriptor, CredentialAdapter, InteractionRequirement};
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::operation::AdapterIdentity;

    assert_eq!(IntegrationSnapshot::default().managed, None);
    let descriptor = AdapterDescriptor {
        identity: AdapterIdentity {
            mechanism: "fake".into(),
            instance: "w0".into(),
        },
        capabilities: std::collections::BTreeSet::new(),
        external_side_effects: true,
        interaction: InteractionRequirement::None,
        enforcement: EnforcementEvidence::unknown(),
        lock_continuity: LockContinuity::Unknown,
        remote_credential_effect: false,
    };
    let fake = heimdall_testkit::FakeCredentialAdapter::new(descriptor, []);
    assert!(!fake.descriptor().remote_credential_effect);
    assert_eq!(fake.read_sources(&[]).managed, None);
    let revoked = fake.revoke(&g(1), t0()).await.unwrap();
    assert!(revoked.remote_effects.is_empty());
}

// --- ⟨M03 wave 4⟩ verification gates (ADR-0008 §17.19 item 5, INT-Q13 option (a)) ---

fn op(n: u8) -> heimdall_contract::ids::OperationId {
    heimdall_contract::ids::OperationId::from_random_bytes([n; 16])
}

fn vscope(ca: u8, dest: &str) -> heimdall_app::managed::VerificationScope {
    use heimdall_contract::ids::{AccountName, CaFingerprint, DestinationId};
    heimdall_app::managed::VerificationScope {
        ca: CaFingerprint::parse(&format!(
            "SHA256:{}",
            char::from(b'A' + ca).to_string().repeat(43)
        ))
        .unwrap(),
        pair: heimdall_domain::scope::AccessPair {
            destination: DestinationId::parse(dest).unwrap(),
            account: AccountName::parse("deploy").unwrap(),
        },
    }
}

/// A verification signature is admitted only through its own operation's open gate:
/// refused before the gate is opened, admitted while open (with the opening's scope),
/// refused for another operation, and refused again once the gate is closed. A second
/// opening while one is open is refused.
#[tokio::test]
async fn verification_gate_admits_only_while_open() {
    let gates = SigningGates::new();
    assert_eq!(
        gates.admit_verification(&op(1), LONG).await.unwrap_err(),
        GateError::NoGate,
        "before the session's create"
    );
    let gate = gates.open_verification(&op(1), vscope(1, "h1")).unwrap();
    assert_eq!(
        gates
            .open_verification(&op(1), vscope(1, "h1"))
            .unwrap_err(),
        GateError::AlreadyOpen
    );
    assert!(gates.is_verification_open(&op(1)));
    assert_eq!(gates.verification_scope(&op(1)), Some(vscope(1, "h1")));
    let shared = gates.admit_verification(&op(1), LONG).await.unwrap();
    assert_eq!(shared.scope(), &vscope(1, "h1"));
    assert!(shared.is_open());
    assert_eq!(
        gates.admit_verification(&op(2), LONG).await.unwrap_err(),
        GateError::NoGate,
        "another operation's gate is not this one"
    );
    drop(shared);
    drop(gate);
    assert!(!gates.is_verification_open(&op(1)));
    assert_eq!(gates.verification_scope(&op(1)), None);
    assert_eq!(
        gates.admit_verification(&op(1), LONG).await.unwrap_err(),
        GateError::NoGate,
        "after the session's drop"
    );
    assert_eq!(gates.verification_holders(&op(1)), 0, "the entry is gone");
}

/// A verification permit is built over the operation's gate (never a grant's): its
/// release check refuses once the gate closes (`VerificationClosed`), also when the
/// operation's gate was reopened since (another opening is not the permit's).
#[tokio::test]
async fn verification_permit_release_refused_after_gate_closed() {
    let gates = SigningGates::new();
    let now = Instant::now();
    let wall = t0();
    let expiry = PermitExpiry::new(wall + jiff::SignedDuration::from_secs(60), now + LONG);
    let gate = gates.open_verification(&op(3), vscope(1, "h1")).unwrap();
    let shared = gates.admit_verification(&op(3), LONG).await.unwrap();
    let permit = SigningGates::permit_verification(shared, expiry, Arc::new(move || Some(wall)));
    assert_eq!(permit.grant(), None);
    assert_eq!(permit.verification(), Some(&op(3)));
    assert!(permit.may_release_at(Some(wall), now));
    // The holder keeps the closed entry until it drops.
    drop(gate);
    assert_eq!(
        permit.release_refusal_at(Some(wall), now),
        Some(ReleaseRefusal::VerificationClosed)
    );
    assert_eq!(gates.verification_holders(&op(3)), 1);
    let reopened = gates.open_verification(&op(3), vscope(1, "h1")).unwrap();
    assert_eq!(
        permit.release_refusal_at(Some(wall), now),
        Some(ReleaseRefusal::VerificationClosed),
        "a later opening never revives an earlier permit"
    );
    // The expiry and time checks still apply first.
    assert_eq!(
        permit.release_refusal_at(None, now),
        Some(ReleaseRefusal::TimeNotSafe)
    );
    drop(permit);
    assert!(gates.is_verification_open(&op(3)));
    drop(reopened);
    assert_eq!(gates.verification_holders(&op(3)), 0);
    assert!(!gates.is_verification_open(&op(3)));
}

/// The gate closes for a holder that waited: an admission queued behind an exclusive
/// close (`close_after_holders`) finds the gate closed after its acquisition, and the
/// close waits for the admitted holder first.
#[tokio::test]
async fn verification_gate_close_after_holders_waits_and_fences_waiters() {
    let gates = SigningGates::new();
    let gate = gates.open_verification(&op(4), vscope(1, "h1")).unwrap();
    let holder = gates.admit_verification(&op(4), LONG).await.unwrap();
    let mut close = Box::pin(gate.close_after_holders());
    assert!(
        poll_once(close.as_mut()).await.is_pending(),
        "waits for the holder"
    );
    assert!(gates.is_verification_open(&op(4)));
    let ops4: &'static _ = Box::leak(Box::new(op(4)));
    let mut waiter = Box::pin(gates.admit_verification(ops4, LONG));
    assert!(
        poll_once(waiter.as_mut()).await.is_pending(),
        "queued behind the close"
    );
    drop(holder);
    close.await;
    assert!(!gates.is_verification_open(&op(4)));
    assert_eq!(waiter.await.unwrap_err(), GateError::NoGate);
    assert_eq!(gates.verification_holders(&op(4)), 0);
}

/// Grant gates and verification gates are separate: an operation's verification gate
/// never admits a grant, and a narrowing's marks never touch a verification gate.
#[tokio::test]
async fn verification_gates_are_not_grant_gates() {
    let gates = forest();
    let _gate = gates.open_verification(&op(5), vscope(1, "h1")).unwrap();
    let _narrowing = gates.begin_narrowing([g(1)]);
    let shared = gates.admit_verification(&op(5), TINY).await.unwrap();
    assert!(shared.is_open());
    assert_eq!(
        gates.admit_shared(&g(1), TINY).await.unwrap_err(),
        GateError::Pending
    );
}
