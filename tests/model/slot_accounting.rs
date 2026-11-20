//! ⟨M05⟩ U6: the slot-accounting model (ADR-0011 §5.2 as ruled in §10 item 6, ruling D06;
//! m05-plan U6; plan §6.3 properties 6 and 8 as narrowed by D06).
//!
//! Random traces of ensure, launch bind (claim, compatible join, incompatible refusal),
//! release, expiry, revocation, cutoff, restart with re-issue, the runtime's cleanup pass
//! (with handover) and a **stale** cleanup of an older generation, over two environments
//! and two pairs. The slot decisions are the production ones of
//! `heimdall_domain::managed` ([`slot_bind`], [`slot_transition`] with
//! [`SlotEvent::HandOver`], [`handover_target`]); the store rows, the slot files (fenced by
//! their generation marker, as `heimdall_adapters::managed::files`) and the signer's
//! environment listing (one binding per pair, by generation, as
//! `heimdall_credential::table`) are modelled beside them, in the order the application
//! and the runtime apply them (`app::operations::slots_m05`,
//! `runtime::managed_store::StoreCleanup`, `runtime::slot_handover`).
//!
//! Invariants after every step (exactly D06's claim, and nothing more):
//! * a listed (materialized) slot has an active materializer that references it, and its
//!   files carry that materializer's grant's certificate for exactly that pair, with
//!   `valid_before` ≤ the grant's deadline;
//! * every held slot's holder references it; after a cleanup pass no slot outlives its
//!   last usable referencer (no `clearing` slot, every held slot's holder usable, a free
//!   slot has no reference);
//! * a cleanup of generation `N` never removes `N + 1`'s files or listing, and never moves
//!   the slot;
//! * the handover goes to the latest-deadline usable referencer (computed independently);
//! * a join never changes any pin, nor the joined slot's state, files or listing;
//! * an incompatible bind is always refused and writes nothing;
//! * environments never share a slot or a reference.
//!
//! Plan §6.3 property 8's most-restrictive clause is **not** asserted (ruling D06): a
//! shorter sibling is enforced on its bound contexts, not on the ordinary alias.
//!
//! Seeds: a fixed default (`RngSeed::Fixed`), overridden by `PROPTEST_RNG_SEED`; failures
//! persist to `tests/model/proptest-regressions/`. 512 cases.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::BindingId;
use heimdall_domain::managed::{
    SlotBind, SlotEvent, SlotReferencer, SlotRefusal, SlotState, handover_target, slot_bind,
    slot_transition,
};
use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngSeed};

const ENVS: usize = 2;
const PAIRS: usize = 2;

fn config(cases: u32, seed: u64) -> ProptestConfig {
    let mut c = ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    };
    if matches!(c.rng_seed, RngSeed::Random) {
        c.rng_seed = RngSeed::Fixed(seed);
    }
    c
}

/// Model time in ticks, as a timestamp.
fn ts(tick: u64) -> Timestamp {
    Timestamp::from_second(1_800_000_000 + i64::try_from(tick).unwrap() * 60).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mech {
    Managed,
    Other,
}

#[derive(Debug, Clone)]
struct Grant {
    deadline: u64,
    ended: bool,
    key_live: bool,
}

/// What a binding pins at activation (ADR-0011 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pins {
    env: usize,
    profile_revision: u64,
    scope: BTreeSet<usize>,
    mechanism: Mech,
    grant: usize,
    context: u8,
}

#[derive(Debug, Clone)]
struct Binding {
    id: BindingId,
    pins: Pins,
    active: bool,
}

/// One slot's files on disk (`key.pub`, `cert.pub` and the generation marker).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Files {
    generation: u64,
    holder: BindingId,
    /// Whose certificate: the grant, the pair (its principal) and `valid_before`.
    grant: usize,
    pair: usize,
    valid_before: u64,
}

type Slot = (usize, usize);

#[derive(Debug, Clone, Default)]
struct World {
    now: u64,
    grants: Vec<Grant>,
    bindings: Vec<Binding>,
    created: Vec<Pins>,
    slots: BTreeMap<Slot, SlotState>,
    /// The last holder of a clearing slot (the store row keeps it).
    clearing_holder: BTreeMap<Slot, BindingId>,
    refs: BTreeMap<Slot, BTreeMap<BindingId, u64>>,
    files: BTreeMap<Slot, Files>,
    listing: BTreeMap<Slot, (BindingId, u64)>,
    /// The highest generation each slot has reached (monotonic).
    high: BTreeMap<Slot, u64>,
    /// The mechanism of a held or clearing slot (its materializers'). Production has one
    /// slot-holding mechanism (`managed_certificate`); the model lets a second one hold
    /// slots too, so the compatibility rule is exercised both ways.
    mech: BTreeMap<Slot, Mech>,
    /// What the trace exercised ([`model_traces_exercise_every_path`]).
    stats: Stats,
}

/// How often each path ran.
#[derive(Debug, Clone, Copy, Default)]
struct Stats {
    joins: usize,
    incompatible_refused: usize,
    handovers: usize,
    handovers_materialized: usize,
    frees: usize,
    stale_fenced: usize,
}

#[derive(Debug, Clone)]
enum Op {
    Ensure {
        env: usize,
        scope: u8,
        managed: bool,
        window: u64,
    },
    Bind(usize),
    Release(usize),
    Advance(u64),
    Revoke(usize),
    Cutoff(usize),
    Restart,
    Reissue(usize),
    Pass,
    StaleCleanup {
        slot: usize,
        back: u64,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..ENVS, 1u8..4, prop::bool::weighted(0.85), 2u64..12).prop_map(
            |(env, scope, managed, window)| Op::Ensure {
                env,
                scope,
                managed,
                window
            }
        ),
        8 => (0usize..16).prop_map(Op::Bind),
        2 => (0usize..16).prop_map(Op::Release),
        1 => (1u64..4).prop_map(Op::Advance),
        1 => (0usize..16).prop_map(Op::Revoke),
        1 => (0usize..16).prop_map(Op::Cutoff),
        1 => Just(Op::Restart),
        1 => (0usize..16).prop_map(Op::Reissue),
        3 => Just(Op::Pass),
        3 => (0usize..(ENVS * PAIRS), 1u64..3).prop_map(|(slot, back)| Op::StaleCleanup { slot, back }),
    ]
}

impl World {
    fn slot(&self, s: Slot) -> SlotState {
        self.slots
            .get(&s)
            .cloned()
            .unwrap_or(SlotState::Free { generation: 0 })
    }

    fn set_slot(&mut self, s: Slot, next: SlotState) {
        let g = next.generation();
        let high = self.high.entry(s).or_insert(0);
        assert!(g >= *high, "a slot's generation never goes back: {s:?}");
        *high = g;
        self.slots.insert(s, next);
    }

    fn binding_index(&self, id: &BindingId) -> Option<usize> {
        self.bindings.iter().position(|b| b.id == *id)
    }

    fn grant_usable(&self, g: usize) -> bool {
        let gr = &self.grants[g];
        !gr.ended && gr.deadline > self.now
    }

    /// `slots_m05::referencer_in`: usable while the binding is active in the slot's
    /// environment with the slot's mechanism and the pair in its scope, and its grant
    /// permits use and has not reached its deadline.
    fn referencer(&self, s: Slot, id: &BindingId) -> SlotReferencer {
        let i = self.binding_index(id).unwrap();
        let b = &self.bindings[i];
        let usable = b.active
            && b.pins.env == s.0
            && self.mech.get(&s) == Some(&b.pins.mechanism)
            && b.pins.scope.contains(&s.1)
            && self.grant_usable(b.pins.grant);
        SlotReferencer {
            binding: id.clone(),
            deadline: ts(self.grants[b.pins.grant].deadline),
            usable,
        }
    }

    /// `files::write_slot`'s marker fence, then the signer's listing (one binding per
    /// pair; a newer listing of the same binding is never replaced by an older one).
    /// Needs the holder's live key. Returns whether the slot was materialized.
    fn materialize(&mut self, s: Slot, b: usize, generation: u64) -> bool {
        let binding = self.bindings[b].clone();
        let g = binding.pins.grant;
        if !self.grants[g].key_live {
            return false;
        }
        if let Some(f) = self.files.get(&s)
            && (f.generation > generation || (f.generation == generation && f.holder != binding.id))
        {
            return false;
        }
        match self.listing.get(&s) {
            Some((holder, _)) if *holder != binding.id => return false,
            Some((_, lg)) if *lg > generation => return false,
            _ => {}
        }
        self.files.insert(
            s,
            Files {
                generation,
                holder: binding.id.clone(),
                grant: g,
                pair: s.1,
                // The issuer bounds every certificate by its grant's deadline.
                valid_before: self.grants[g].deadline,
            },
        );
        self.listing.insert(s, (binding.id, generation));
        true
    }

    /// `ManagedEffectsImpl::clear_slot`: unlist `holder` at exactly `generation`, then
    /// remove the files whose marker names exactly `generation`.
    fn clear_generation(&mut self, s: Slot, holder: Option<&BindingId>, generation: u64) {
        if let Some((b, g)) = self.listing.get(&s)
            && *g == generation
            && holder.is_none_or(|h| h == b)
        {
            self.listing.remove(&s);
        }
        if self
            .files
            .get(&s)
            .is_some_and(|f| f.generation == generation)
        {
            self.files.remove(&s);
        }
    }

    /// The signer's destruction of a grant's key: every binding of it unlisted at once.
    fn destroy_key(&mut self, g: usize) {
        self.grants[g].key_live = false;
        let ids: BTreeSet<BindingId> = self
            .bindings
            .iter()
            .filter(|b| b.pins.grant == g)
            .map(|b| b.id.clone())
            .collect();
        self.listing.retain(|_, (b, _)| !ids.contains(b));
    }

    fn end_grant(&mut self, g: usize) {
        self.grants[g].ended = true;
        self.destroy_key(g);
    }

    fn ensure(&mut self, env: usize, scope: u8, managed: bool, window: u64) {
        let g = self.grants.len();
        self.grants.push(Grant {
            deadline: self.now + window,
            ended: false,
            key_live: true,
        });
        let n = u8::try_from(self.bindings.len() + 1).unwrap();
        let pins = Pins {
            env,
            profile_revision: 1,
            scope: (0..PAIRS).filter(|p| scope & (1 << p) != 0).collect(),
            mechanism: if managed { Mech::Managed } else { Mech::Other },
            grant: g,
            context: n % 2,
        };
        self.created.push(pins.clone());
        self.bindings.push(Binding {
            id: BindingId::from_random_bytes([n; 16]),
            pins,
            active: true,
        });
    }

    /// The launch bind (`slots_m05::claim_or_join_in`, then the slots-only write).
    fn bind(&mut self, b: usize) {
        let binding = self.bindings[b].clone();
        // The bind refuses an inactive binding or an unusable grant before any claim.
        if !binding.active || !self.grant_usable(binding.pins.grant) {
            return;
        }
        let env = binding.pins.env;
        let mut decided = Vec::new();
        let mut refused = false;
        let mut incompatible_holder = false;
        for &p in &binding.pins.scope {
            let s = (env, p);
            let state = self.slot(s);
            let references = self
                .refs
                .get(&s)
                .is_some_and(|r| r.contains_key(&binding.id));
            // The same mechanism as the slot's materializer (a free slot has none).
            let compatible = match &state {
                SlotState::Free { .. } => true,
                _ => self.mech.get(&s) == Some(&binding.pins.mechanism),
            };
            if matches!(&state, SlotState::Held { binding: h, .. } if *h != binding.id)
                && !compatible
            {
                incompatible_holder = true;
            }
            match slot_bind(&state, &binding.id, references, compatible) {
                Ok(d) => decided.push((s, d, references)),
                Err(_) => refused = true,
            }
        }
        if incompatible_holder {
            assert!(refused, "an incompatible bind is always refused");
            self.stats.incompatible_refused += 1;
        }
        if refused {
            return;
        }
        let before = self.clone();
        for (s, decision, references) in decided {
            if decision == SlotBind::Claim {
                let next = slot_transition(
                    &self.slot(s),
                    &SlotEvent::Claim {
                        binding: binding.id.clone(),
                    },
                )
                .unwrap();
                self.set_slot(s, next);
                self.mech.insert(s, binding.pins.mechanism);
            }
            if !references {
                let deadline = self.grants[binding.pins.grant].deadline;
                self.refs
                    .entry(s)
                    .or_default()
                    .insert(binding.id.clone(), deadline);
            }
            if decision == SlotBind::Join {
                self.stats.joins += 1;
            }
            if matches!(decision, SlotBind::Join | SlotBind::Referenced) {
                assert_eq!(self.slot(s), before.slot(s), "a join never moves the slot");
            }
        }
        // The slots-only write: every slot the binding holds, at its store generation;
        // a slot it only references is its materializer's.
        for &p in &binding.pins.scope {
            let s = (env, p);
            if let SlotState::Held {
                binding: h,
                generation,
            } = self.slot(s)
                && h == binding.id
            {
                self.materialize(s, b, generation);
            } else {
                assert_eq!(
                    self.files.get(&s),
                    before.files.get(&s),
                    "a join writes no file"
                );
                assert_eq!(self.listing.get(&s), before.listing.get(&s), "nor lists");
            }
        }
    }

    /// `release` + `release_binding_slots_in` + `after_binding_release_m03`.
    fn release(&mut self, b: usize) {
        if !self.bindings[b].active {
            return;
        }
        self.bindings[b].active = false;
        let id = self.bindings[b].id.clone();
        for r in self.refs.values_mut() {
            r.remove(&id);
        }
        for (s, state) in self.slots.clone() {
            if let SlotState::Held {
                binding: h,
                generation,
            } = &state
                && *h == id
            {
                let next = slot_transition(
                    &state,
                    &SlotEvent::Release {
                        binding: id.clone(),
                        generation: *generation,
                    },
                )
                .unwrap();
                self.set_slot(s, next);
                self.clearing_holder.insert(s, id.clone());
            }
        }
        // The released binding is detached from the signer at once.
        self.listing.retain(|_, (x, _)| *x != id);
    }

    fn restart(&mut self) {
        self.listing.clear();
        for g in &mut self.grants {
            g.key_live = false;
        }
        for (s, state) in self.slots.clone() {
            let ended = match &state {
                SlotState::Held { binding, .. } => {
                    let b = &self.bindings[self.binding_index(binding).unwrap()];
                    !self.grant_usable(b.pins.grant)
                }
                _ => false,
            };
            let next = slot_transition(&state, &SlotEvent::Restart { grant_ended: ended }).unwrap();
            if let (SlotState::Held { binding, .. }, SlotState::Clearing { .. }) = (&state, &next) {
                self.clearing_holder.insert(s, binding.clone());
            }
            self.set_slot(s, next);
        }
    }

    /// The re-issue of a live grant: a new key, then every active binding of it that
    /// holds slots gets them written at their store generations (`restore_consumers`).
    fn reissue(&mut self, g: usize) {
        if !self.grant_usable(g) || self.grants[g].key_live {
            return;
        }
        self.grants[g].key_live = true;
        for b in 0..self.bindings.len() {
            let binding = self.bindings[b].clone();
            if binding.pins.grant != g || !binding.active {
                continue;
            }
            for &p in &binding.pins.scope {
                let s = (binding.pins.env, p);
                if let SlotState::Held {
                    binding: h,
                    generation,
                } = self.slot(s)
                    && h == binding.id
                {
                    self.materialize(s, b, generation);
                }
            }
        }
    }

    /// The runtime's cleanup pass (`Supervisor::ended_slot_pass` → `StoreCleanup`):
    /// each slot whose holder ended is cleared by its own generation (`begin_slot`), then
    /// freed or handed over (`slot_handover::finish_clearing`).
    fn pass(&mut self) {
        for (s, state) in self.slots.clone() {
            let (holder, generation) = match &state {
                SlotState::Held {
                    binding,
                    generation,
                } => {
                    let b = &self.bindings[self.binding_index(binding).unwrap()];
                    if b.active && self.grant_usable(b.pins.grant) {
                        continue;
                    }
                    let next = slot_transition(
                        &state,
                        &SlotEvent::Release {
                            binding: binding.clone(),
                            generation: *generation,
                        },
                    )
                    .unwrap();
                    self.set_slot(s, next);
                    (binding.clone(), *generation)
                }
                SlotState::Clearing { generation } => {
                    (self.clearing_holder[&s].clone(), *generation)
                }
                SlotState::Free { .. } => continue,
                _ => unreachable!(),
            };
            self.clear_generation(s, Some(&holder), generation);
            self.clearing_holder.remove(&s);
            // finish: drop the unusable referencers, then free or hand over.
            let ids: Vec<BindingId> = self
                .refs
                .get(&s)
                .map(|r| r.keys().cloned().collect())
                .unwrap_or_default();
            let referencers: Vec<SlotReferencer> =
                ids.iter().map(|id| self.referencer(s, id)).collect();
            if let Some(r) = self.refs.get_mut(&s) {
                for x in referencers.iter().filter(|x| !x.usable) {
                    r.remove(&x.binding);
                }
            }
            // Independently: the latest-deadline usable referencer, lowest ID on a tie.
            let expected = referencers
                .iter()
                .filter(|r| r.usable)
                .map(|r| (std::cmp::Reverse(r.deadline), r.binding.clone()))
                .min()
                .map(|(_, b)| b);
            let target = handover_target(&referencers).map(|r| r.binding.clone());
            assert_eq!(
                target, expected,
                "handover to the latest-deadline usable referencer"
            );
            let clearing = self.slot(s);
            match target {
                None => {
                    let next = slot_transition(&clearing, &SlotEvent::FilesRemoved { generation })
                        .unwrap();
                    self.set_slot(s, next);
                    self.refs.remove(&s);
                    self.mech.remove(&s);
                    self.stats.frees += 1;
                }
                Some(to) => {
                    let next = slot_transition(
                        &clearing,
                        &SlotEvent::HandOver {
                            generation,
                            to: to.clone(),
                        },
                    )
                    .unwrap();
                    assert_eq!(next.generation(), generation + 1, "a new generation");
                    self.set_slot(s, next.clone());
                    let n = self.binding_index(&to).unwrap();
                    // Re-materialized from the new holder's own grant (fails closed
                    // without its key, e.g. after a restart before its re-issue).
                    self.stats.handovers += 1;
                    if self.materialize(s, n, next.generation()) {
                        self.stats.handovers_materialized += 1;
                    }
                }
            }
        }
    }

    /// A stale pass's cleanup of an older generation `N` of slot `s`: its store events
    /// are refused unless the slot is at `N`, and its unlisting and file removal are
    /// fenced by `N`.
    fn stale_cleanup(&mut self, s: Slot, back: u64) {
        let state = self.slot(s);
        let Some(n) = state.generation().checked_sub(back) else {
            return;
        };
        if n == 0 {
            return;
        }
        let holder = match &state {
            SlotState::Held { binding, .. } => binding.clone(),
            _ => return,
        };
        for event in [
            SlotEvent::Release {
                binding: holder.clone(),
                generation: n,
            },
            SlotEvent::FilesRemoved { generation: n },
            SlotEvent::HandOver {
                generation: n,
                to: holder.clone(),
            },
        ] {
            assert!(
                slot_transition(&state, &event).is_err(),
                "a cleanup of generation {n} never moves a slot at {}",
                state.generation()
            );
        }
        let (files, listing) = (self.files.get(&s).cloned(), self.listing.get(&s).cloned());
        // Any binding's listing of generation N (the old materializer's).
        self.clear_generation(s, None, n);
        if files.as_ref().is_some_and(|f| f.generation > n) {
            self.stats.stale_fenced += 1;
            assert_eq!(self.files.get(&s), files.as_ref(), "N + 1's files stay");
        }
        if listing.as_ref().is_some_and(|(_, g)| *g > n) {
            assert_eq!(
                self.listing.get(&s),
                listing.as_ref(),
                "N + 1's listing stays"
            );
        }
    }

    fn apply(&mut self, op: &Op) {
        let nb = self.bindings.len();
        let ng = self.grants.len();
        match *op {
            Op::Ensure {
                env,
                scope,
                managed,
                window,
            } => self.ensure(env, scope, managed, window),
            Op::Bind(i) if nb > 0 => self.bind(i % nb),
            Op::Release(i) if nb > 0 => self.release(i % nb),
            Op::Advance(dt) => {
                self.now += dt;
                for g in 0..ng {
                    if !self.grants[g].ended && self.grants[g].deadline <= self.now {
                        self.end_grant(g);
                    }
                }
            }
            Op::Revoke(i) if ng > 0 => self.end_grant(i % ng),
            Op::Cutoff(i) if ng > 0 => {
                let g = i % ng;
                self.grants[g].deadline = self.grants[g].deadline.min(self.now);
                self.end_grant(g);
            }
            Op::Restart => self.restart(),
            Op::Reissue(i) if ng > 0 => self.reissue(i % ng),
            Op::Pass => self.pass(),
            Op::StaleCleanup { slot, back } => {
                self.stale_cleanup((slot / PAIRS, slot % PAIRS), back)
            }
            _ => {}
        }
    }

    fn check(&self, after_pass: bool) {
        // A join never changes any pin.
        for (b, pins) in self.bindings.iter().zip(&self.created) {
            assert_eq!(&b.pins, pins, "pins never change");
        }
        for (s, (id, g)) in &self.listing {
            let b = &self.bindings[self.binding_index(id).unwrap()];
            let grant = &self.grants[b.pins.grant];
            assert_eq!(
                self.slot(*s),
                SlotState::Held {
                    binding: id.clone(),
                    generation: *g
                },
                "a listed slot is held by its listed binding at that generation"
            );
            assert!(b.active, "a materialized slot's materializer is active");
            assert_eq!(b.pins.env, s.0, "environments never share a slot");
            assert!(
                self.grant_usable(b.pins.grant) && grant.key_live,
                "its grant can sign"
            );
            assert!(
                self.refs.get(s).is_some_and(|r| r.contains_key(id)),
                "the materializer references its slot"
            );
            let f = self.files.get(s).expect("a listed slot has its files");
            assert_eq!(f.generation, *g);
            assert_eq!(&f.holder, id);
            assert_eq!(
                f.grant, b.pins.grant,
                "the certificate is the materializer's grant's"
            );
            assert_eq!(f.pair, s.1, "its principals are exactly the pair's");
            assert!(
                f.valid_before <= grant.deadline,
                "valid_before ≤ the grant's deadline"
            );
        }
        for (s, state) in &self.slots {
            if let SlotState::Held { binding, .. } = state {
                let b = &self.bindings[self.binding_index(binding).unwrap()];
                assert_eq!(b.pins.env, s.0, "environments never share a slot");
                assert_eq!(
                    self.mech.get(s),
                    Some(&b.pins.mechanism),
                    "a slot is only ever held under one mechanism"
                );
                assert!(
                    self.refs.get(s).is_some_and(|r| r.contains_key(binding)),
                    "a held slot's materializer references it"
                );
                if after_pass {
                    assert!(
                        b.active && self.grant_usable(b.pins.grant),
                        "after the pass no slot outlives its last usable referencer"
                    );
                }
            }
            if after_pass {
                assert!(
                    !matches!(state, SlotState::Clearing { .. }),
                    "the pass leaves no slot clearing"
                );
                if matches!(state, SlotState::Free { .. }) {
                    assert!(
                        self.refs.get(s).is_none_or(BTreeMap::is_empty),
                        "a free slot has no reference"
                    );
                }
            }
        }
        for (s, r) in &self.refs {
            for id in r.keys() {
                let b = &self.bindings[self.binding_index(id).unwrap()];
                assert_eq!(b.pins.env, s.0, "a reference never crosses environments");
                assert!(b.pins.scope.contains(&s.1));
                assert_eq!(
                    self.mech.get(s),
                    Some(&b.pins.mechanism),
                    "only a compatible binding references a slot"
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(config(512, 0x5536_534c_4f54_5341))]

    /// ADR-0011 §5.2 (ruling D06): the slot-accounting invariants hold after every
    /// step of every trace (module docs).
    #[test]
    fn shared_slots_carry_one_grant_hand_over_to_the_latest_deadline_and_end_with_the_last_referencer(
        ops in prop::collection::vec(op(), 1..80),
    ) {
        let mut w = World::default();
        for op in &ops {
            w.apply(op);
            w.check(matches!(op, Op::Pass));
        }
        w.apply(&Op::Pass);
        w.check(true);
    }
}

/// The model is not vacuous: over the property's own strategy and seed, its traces join,
/// refuse incompatible binds, hand over (and re-materialize), free slots, and replay a
/// stale cleanup against a newer generation's files.
#[test]
fn model_traces_exercise_every_path() {
    use proptest::strategy::ValueTree as _;
    let mut runner = proptest::test_runner::TestRunner::new(config(512, 0x5536_534c_4f54_5341));
    let strategy = prop::collection::vec(op(), 1..80);
    let mut total = Stats::default();
    for _ in 0..512 {
        let ops = strategy.new_tree(&mut runner).unwrap().current();
        let mut w = World::default();
        for op in &ops {
            w.apply(op);
        }
        w.apply(&Op::Pass);
        let s = w.stats;
        total.joins += s.joins;
        total.incompatible_refused += s.incompatible_refused;
        total.handovers += s.handovers;
        total.handovers_materialized += s.handovers_materialized;
        total.frees += s.frees;
        total.stale_fenced += s.stale_fenced;
    }
    // About half of what the fixed seed exercises, so another PROPTEST_RNG_SEED passes.
    assert!(total.joins >= 100, "{total:?}");
    assert!(total.incompatible_refused >= 50, "{total:?}");
    assert!(total.handovers >= 25, "{total:?}");
    assert!(total.handovers_materialized >= 12, "{total:?}");
    assert!(total.frees >= 300, "{total:?}");
    assert!(total.stale_fenced >= 15, "{total:?}");
}

/// The pure tables of the join and the handover target, example by example
/// (ADR-0011 §5.2): a compatible bind joins a held slot, an incompatible one is refused
/// `managed_slot_held`, a clearing slot is joined only by a binding already waiting on
/// it; the handover passes over an unusable referencer and breaks a deadline tie by the
/// lowest binding ID; a handover names the clearing generation and lands at the next.
#[test]
fn join_and_handover_tables() {
    let m = BindingId::from_random_bytes([1; 16]);
    let b = BindingId::from_random_bytes([2; 16]);
    let held = SlotState::Held {
        binding: m.clone(),
        generation: 3,
    };
    let clearing = SlotState::Clearing { generation: 3 };
    let free = SlotState::Free { generation: 3 };
    assert_eq!(slot_bind(&free, &b, false, true), Ok(SlotBind::Claim));
    assert_eq!(slot_bind(&held, &m, true, true), Ok(SlotBind::Hold));
    assert_eq!(slot_bind(&held, &b, false, true), Ok(SlotBind::Join));
    assert_eq!(slot_bind(&held, &b, true, true), Ok(SlotBind::Referenced));
    assert_eq!(
        slot_bind(&held, &b, false, false),
        Err(SlotRefusal::ManagedSlotHeld)
    );
    assert_eq!(
        slot_bind(&held, &b, true, false),
        Err(SlotRefusal::ManagedSlotHeld),
        "an incompatible bind is refused, a reference or not"
    );
    assert_eq!(
        slot_bind(&clearing, &b, true, true),
        Ok(SlotBind::Referenced)
    );
    assert_eq!(
        slot_bind(&clearing, &b, false, true),
        Err(SlotRefusal::NotApplicable)
    );
    let r = |n: u8, tick: u64, usable: bool| SlotReferencer {
        binding: BindingId::from_random_bytes([n; 16]),
        deadline: ts(tick),
        usable,
    };
    let refs = [r(3, 9, false), r(4, 5, true), r(5, 7, true), r(6, 7, true)];
    assert_eq!(
        handover_target(&refs).map(|x| x.binding.clone()),
        Some(BindingId::from_random_bytes([5; 16])),
        "the latest usable deadline; the lower ID on a tie; never the unusable one"
    );
    assert_eq!(handover_target(&[r(3, 9, false)]), None);
    assert_eq!(
        slot_transition(
            &clearing,
            &SlotEvent::HandOver {
                generation: 3,
                to: b.clone()
            }
        ),
        Ok(SlotState::Held {
            binding: b.clone(),
            generation: 4
        })
    );
    assert_eq!(
        slot_transition(
            &clearing,
            &SlotEvent::HandOver {
                generation: 2,
                to: b.clone()
            }
        ),
        Err(SlotRefusal::StaleGeneration)
    );
    assert_eq!(
        slot_transition(
            &held,
            &SlotEvent::HandOver {
                generation: 3,
                to: b
            }
        ),
        Err(SlotRefusal::NotApplicable),
        "only a clearing slot is handed over"
    );
}
