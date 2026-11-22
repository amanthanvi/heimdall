//! ⟨M06 U3⟩ Issue and revoke linearization for runner delivery (m06-plan U3 "model"; ADR-0005
//! §3.5 "Issue and revoke are linearized", §4.3 "Issuance races revocation" and "Revoked while
//! unreachable"; ADR-0012 §4.2, §7.2–§7.3).
//!
//! One certificate's life, every interleaving. The controller's side is its own store (a
//! second in-memory store): the entry is **reserved** first, then the events are ordered in
//! every way:
//! * `P` publish: one transaction that re-reads the controller's tombstone; with one, the entry
//!   is **voided** and nothing is released (the re-check of ADR-0005 §3.5 step 3; the full
//!   predicate is `model_issuer_linearization`'s), else **published** and released;
//! * `V` the controller-side revoke: a tombstone in the controller's store (the runner learns it
//!   only when the effect is delivered);
//! * `T` the delivered `grant_revoke` applied on the runner: the runner's tombstone, and K_env
//!   zeroized (ADR-0012 §7.2);
//! * `N` an unrelated narrowing on the runner that moves its authority generation;
//! * `D` delivery: the released certificate handed to the runner's real
//!   `RunnerIssuance::install` (no-op when nothing was released).
//!
//! **Pass conditions**, asserted for every order:
//! 1. a publish after the controller's revoke voids, and nothing is ever delivered for it;
//! 2. every `reserved` or `published` entry counts in the residual
//!    (`latest_possible_credential_expiry` = its `valid_before`), whether or not it was
//!    delivered or installed; only a voided entry is excluded;
//! 3. the runner installs exactly when the certificate was released and neither its tombstone
//!    nor a generation move came first; otherwise it discards the certificate;
//! 4. after the runner's tombstone, no K_env and no certificate remains on the runner;
//! 5. a revoke the runner has not received does not stop an installed certificate (it stays
//!    within the counted residual: "revoked while unreachable").

#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "../integration/runner_fixture_m06.rs"]
mod fixture;

use std::sync::Arc;

use fixture::*;
use heimdall_contract::ids::{EnvironmentId, GrantId, IssuanceId};
use heimdall_domain::issuance::{
    CertificateBounds, IssuanceEntry, IssuanceRefusal, IssuanceState, principal_for,
};
use heimdall_domain::policy::AuthorityGeneration;
use heimdall_domain::revocation::{RevocationCause, Tombstone};
use heimdall_domain::time::Clock;
use heimdall_runtime::runner::issuance::IssuanceFailure;
use heimdall_store::{NoFaults, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    Publish,
    ControllerRevoke,
    RunnerTombstone,
    Narrowing,
    Deliver,
}

/// Every order of `events` (Heap's algorithm), with `Deliver` after `Publish`.
fn orders(events: &[Ev]) -> Vec<Vec<Ev>> {
    fn permute(k: usize, a: &mut Vec<Ev>, out: &mut Vec<Vec<Ev>>) {
        if k <= 1 {
            out.push(a.clone());
            return;
        }
        permute(k - 1, a, out);
        for i in 0..k - 1 {
            if k.is_multiple_of(2) {
                a.swap(i, k - 1);
            } else {
                a.swap(0, k - 1);
            }
            permute(k - 1, a, out);
        }
    }
    let mut out = Vec::new();
    let mut a = events.to_vec();
    permute(a.len(), &mut a, &mut out);
    out.retain(|o| {
        let p = o.iter().position(|e| *e == Ev::Publish).unwrap();
        let d = o.iter().position(|e| *e == Ev::Deliver).unwrap();
        p < d
    });
    out.sort_by_key(|o| format!("{o:?}"));
    out.dedup();
    out
}

/// The controller's ledger for the runner's grant.
struct Controller {
    store: Store,
    grant: GrantId,
    entry: IssuanceId,
}

impl Controller {
    fn new(grant: &GrantId) -> Self {
        let store = Store::open_in_memory(Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.init_self_environment(&EnvironmentId::from_random_bytes([0xc0; 16]))
            })
            .unwrap();
        Self {
            store,
            grant: grant.clone(),
            entry: IssuanceId::from_random_bytes([0x15; 16]),
        }
    }

    /// Reserve the entry for `bounds` (step 1).
    fn reserve(&self, bounds: &CertificateBounds, now: heimdall_contract::Timestamp) {
        let entry = IssuanceEntry {
            id: self.entry.clone(),
            grant: self.grant.clone(),
            generation: AuthorityGeneration(0),
            pair: pair("h1"),
            bounds: bounds.clone(),
            state: IssuanceState::Reserved,
            reserved_at: now,
            settled_at: None,
            void_reason: None,
            continuing: false,
        };
        self.store
            .transaction(|tx| tx.reserve_issuance(&entry))
            .unwrap();
    }

    /// Publish or void in one transaction that re-reads the tombstone (step 3). `true` when
    /// published (released).
    fn publish(&self, now: heimdall_contract::Timestamp) -> bool {
        self.store
            .transaction(|tx| {
                if tx.tombstone(&self.grant)?.is_some() {
                    tx.void_issuance(&self.entry, &IssuanceRefusal::Tombstoned, now)?;
                    Ok(false)
                } else {
                    tx.publish_issuance(&self.entry, now)?;
                    Ok(true)
                }
            })
            .unwrap()
    }

    fn revoke(&self, now: heimdall_contract::Timestamp) {
        let grant = self.grant.clone();
        self.store
            .transaction(|tx| {
                tx.insert_tombstone(&Tombstone {
                    grant,
                    cascade: Vec::new(),
                    generation: AuthorityGeneration(0),
                    revoked_at: now,
                    remote_pending: Vec::new(),
                    cause: RevocationCause::Revoke,
                })
                .map(drop)
            })
            .unwrap();
    }

    fn residual(&self) -> Option<heimdall_contract::Timestamp> {
        self.store
            .transaction(|tx| tx.issuance_residual(std::slice::from_ref(&self.grant)))
            .unwrap()
    }

    fn state(&self) -> IssuanceState {
        self.store
            .transaction(|tx| tx.issuance_entry(&self.entry))
            .unwrap()
            .unwrap()
            .state
    }
}

fn run(order: &[Ev]) {
    let w = world();
    w.trust(&w.ca_a, &controller_a());
    let g = w.generation();
    let prepared = w
        .runner
        .issuance()
        .prepare(&controller_a(), &w.grant, g)
        .unwrap();
    w.good_sample();
    // Certificates carry whole seconds.
    let valid_before =
        heimdall_contract::Timestamp::from_second(plus(w.clock.wall(), HOUR).as_second()).unwrap();
    let cert = w.sign(&w.ca_a, &prepared, &pair("h1"), valid_before);
    let facts = heimdall_issuer::remote::read_certificate(&cert).unwrap();
    let bounds = CertificateBounds {
        serial: facts.serial,
        key_id: facts.key_id.clone(),
        principal: principal_for(&pair("h1")),
        valid_after: facts.valid_after,
        valid_before: facts.valid_before,
        extensions: facts.extensions.clone(),
        subject_fingerprint: facts.subject_fingerprint.clone(),
        ca_fingerprint: Some(facts.ca_fingerprint.clone()),
    };
    let controller = Controller::new(&w.grant);
    controller.reserve(&bounds, w.clock.wall());
    // Reserved: counted from the start.
    assert_eq!(controller.residual(), Some(valid_before), "{order:?}");

    let mut controller_revoked = false;
    let mut released = false;
    let mut runner_tombstoned = false;
    let mut narrowed = false;
    let mut installed = None;
    for ev in order {
        w.clock.advance(std::time::Duration::from_secs(1));
        let now = w.clock.wall();
        match ev {
            Ev::Publish => {
                released = controller.publish(now);
                // 1. a publish after the controller's revoke voids.
                assert_eq!(released, !controller_revoked, "{order:?}");
            }
            Ev::ControllerRevoke => {
                controller.revoke(now);
                controller_revoked = true;
            }
            Ev::RunnerTombstone => {
                w.tombstone();
                w.runner.issuance().destroy(&w.grant);
                runner_tombstoned = true;
            }
            Ev::Narrowing => {
                let other = GrantId::from_random_bytes([0x77; 16]);
                w.store
                    .transaction(|tx| {
                        tx.insert_tombstone(&Tombstone {
                            grant: other,
                            cascade: Vec::new(),
                            generation: AuthorityGeneration(0),
                            revoked_at: now,
                            remote_pending: Vec::new(),
                            cause: RevocationCause::Revoke,
                        })
                        .map(drop)
                    })
                    .unwrap();
                narrowed = true;
            }
            Ev::Deliver => {
                if !released {
                    continue;
                }
                let r = w
                    .runner
                    .issuance()
                    .install(&controller_a(), &w.grant, g, &cert);
                // 3. installed exactly when neither the runner's tombstone nor a generation
                //    move came first.
                if runner_tombstoned || narrowed {
                    let e = r.unwrap_err();
                    assert!(
                        matches!(
                            e,
                            IssuanceFailure::NoKey
                                | IssuanceFailure::Refused(
                                    IssuanceRefusal::StaleGeneration
                                        | IssuanceRefusal::Tombstoned
                                        | IssuanceRefusal::GrantNotIssuable(_)
                                )
                        ),
                        "{order:?}: {e:?}"
                    );
                } else {
                    installed = Some(r.unwrap_or_else(|e| panic!("{order:?}: {e:?}")));
                }
            }
        }
        // 2. the residual counts every reserved or published entry, delivered or not.
        let expected = (controller.state() != IssuanceState::Voided).then_some(valid_before);
        assert_eq!(controller.residual(), expected, "{order:?} after {ev:?}");
    }
    let certs = w.runner.issuance().keys().certificates(&w.grant);
    if runner_tombstoned {
        // 4. nothing remains on the runner after its tombstone.
        assert!(certs.is_empty(), "{order:?}");
        assert!(w.runner.issuance().keys().public_key(&w.grant).is_none());
    } else if let Some(ok) = &installed {
        // 5. a revoke the runner has not received does not stop it; it is within the
        //    counted residual.
        assert_eq!(certs.len(), 1, "{order:?}");
        assert!(
            ok.valid_before <= controller.residual().unwrap(),
            "{order:?}"
        );
    } else {
        assert!(certs.is_empty(), "{order:?}");
    }
    if controller_revoked
        && order.iter().position(|e| *e == Ev::ControllerRevoke)
            < order.iter().position(|e| *e == Ev::Publish)
    {
        assert_eq!(controller.state(), IssuanceState::Voided, "{order:?}");
        assert_eq!(controller.residual(), None, "{order:?}");
        assert!(installed.is_none(), "{order:?}");
    }
}

#[test]
fn runner_delivery_is_linearized_with_revocation_in_every_order() {
    let full = orders(&[
        Ev::Publish,
        Ev::ControllerRevoke,
        Ev::RunnerTombstone,
        Ev::Narrowing,
        Ev::Deliver,
    ]);
    // 5! / 2 orders with Deliver after Publish.
    assert_eq!(full.len(), 60);
    for o in &full {
        run(o);
    }
    // The subsets: no runner tombstone, no narrowing, neither.
    for events in [
        vec![Ev::Publish, Ev::ControllerRevoke, Ev::Deliver],
        vec![Ev::Publish, Ev::RunnerTombstone, Ev::Deliver],
        vec![Ev::Publish, Ev::Narrowing, Ev::Deliver],
        vec![Ev::Publish, Ev::Deliver],
    ] {
        for o in orders(&events) {
            run(&o);
        }
    }
}
