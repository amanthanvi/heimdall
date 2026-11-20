//! ⟨M03⟩ Managed pair slots, owned connections and the latched lock epoch
//! (ADR-0008 D10 item 2, D8 item 2, D9; m03-plan §5 item 16; frozen in wave 0).
//!
//! ⟨M05⟩ U6 (ADR-0011 §5.2 as ruled in §10 item 6): a slot is shared by reference. A
//! compatible launch bind joins a slot another binding materializes ([`slot_bind`]);
//! when the materializer ends, the slot passes to the latest-deadline usable referencer
//! under a new generation ([`SlotEvent::HandOver`], [`handover_target`]). The claim is
//! exactly this: the slot carries one pair and one **materializer** grant (its
//! certificate's principals and `valid_before` come from that grant only), and it ends
//! when its last referencer drops. A shorter sibling is enforced on its bound contexts,
//! not on the ordinary alias (`shared_environment_default`, R3).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, ConnectionId, GrantId};
use serde::{Deserialize, Serialize};

pub use heimdall_contract::managed::{ConnectionKind, SessionLockState};

// --- pair slots (ADR-0008 D10 item 2) ------------------------------------------------

/// ⟨M03⟩ The command that holds a managed alias's slot, as the `slot_free` disclosure
/// names it (ADR-0008 D10 item 2: `heimdall run …`; `heimdall bind materialize` is
/// U12's and is not offered until it exists). `<profile>` stays a placeholder: any
/// profile that grants the pair holds the slot, and nothing here knows which one the
/// owner uses. One wording for the projection preview, the doctor, `enroll status`,
/// the TUI and the enrollment result's `ordinary_ssh_needs_held_slot` note (ADR-0008
/// §17.25 item 5); `heimdall_localenv::projection::plan` re-exports it.
#[must_use]
pub fn slot_free_command(alias: &str) -> String {
    format!("heimdall run --profile <profile> -- ssh {alias}")
}

/// One `(environment, destination, account)` slot's state. The generation survives
/// every state, so a cleanup of generation `g` never touches `g + 1`'s files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SlotState {
    /// No binding holds the slot; its files are absent.
    Free {
        /// The last generation (0 before the first claim).
        generation: u64,
    },
    /// `binding` holds the slot at `generation`.
    Held {
        /// The holder.
        binding: BindingId,
        /// Its generation.
        generation: u64,
    },
    /// The key is unlisted; the files of `generation` are being removed.
    Clearing {
        /// The generation being cleared.
        generation: u64,
    },
}

impl SlotState {
    /// The slot's generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        match self {
            SlotState::Free { generation }
            | SlotState::Held { generation, .. }
            | SlotState::Clearing { generation } => *generation,
        }
    }
}

/// An event of the slot table (ADR-0008 D10 item 2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SlotEvent {
    /// `bind materialize` of a managed binding for the pair, or `run`'s
    /// auto-materialize.
    Claim {
        /// The binding asking.
        binding: BindingId,
    },
    /// The holder's grant ended, or the holder was released.
    Release {
        /// The holder.
        binding: BindingId,
        /// The generation it holds.
        generation: u64,
    },
    /// The files of `generation` were removed.
    FilesRemoved {
        /// The cleared generation.
        generation: u64,
    },
    /// Restart reconciliation of the slot row with its files.
    Restart {
        /// The holder's grant has ended.
        grant_ended: bool,
    },
    /// ⟨M05⟩ ADR-0011 §5.2 (as ruled in §10 item 6): the files of the clearing
    /// `generation` were removed while a usable referencer remains; the slot passes to
    /// `to` (the latest-deadline one, [`handover_target`]) at the next generation, to
    /// be re-materialized from `to`'s own grant.
    HandOver {
        /// The cleared generation.
        generation: u64,
        /// The referencer taking the slot.
        to: BindingId,
    },
}

/// Why a slot event is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SlotRefusal {
    /// Another binding holds the slot (`CONFIG_CONFLICT`, `managed_slot_held`, next
    /// `release_binding`).
    #[error("another binding holds the managed slot")]
    ManagedSlotHeld,
    /// The event names another holder or generation than the slot's.
    #[error("the slot's holder or generation differs")]
    StaleGeneration,
    /// The table has no row for this pair.
    #[error("the slot event does not apply in this state")]
    NotApplicable,
}

/// ADR-0008 D10 item 2, ⟨M05⟩ with ADR-0011 §5.2's handover (as ruled in §10 item 6):
///
/// | Slot state | Event | Next |
/// |---|---|---|
/// | `free(g)` | claim by `b` | `held(b, g + 1)` (files written, then listed) |
/// | `held(b, g)` | claim by another binding | refused, `managed_slot_held` (a launch bind decides with [`slot_bind`]: a compatible one joins instead) |
/// | `held(b, g)` | claim by `b` again | `held(b, g)` (idempotent) |
/// | `held(b, g)` | `b`'s grant ends or `b` is released | `clearing(g)` |
/// | `clearing(g)` | files of `g` removed, no usable referencer | `free(g)` |
/// | `clearing(g)` | ⟨M05⟩ files of `g` removed, hand over to `n` ([`handover_target`]) | `held(n, g + 1)` (re-materialized from `n`'s own grant) |
/// | any | restart | `held` stays `held` (degraded until re-issue) unless its grant ended (`clearing(g)`); `clearing` and `free` stay |
///
/// A release, a file removal or a handover naming another holder or generation is
/// refused (`StaleGeneration`), so a cleanup of generation `g` never moves a slot at
/// `g + 1`; a generation overflow refuses (`NotApplicable`). The slot's references (who
/// joined it, and their deadlines) live beside its state (`slot_references`): a join
/// changes no state here, only that set.
pub fn slot_transition(state: &SlotState, event: &SlotEvent) -> Result<SlotState, SlotRefusal> {
    match (state, event) {
        (SlotState::Free { generation }, SlotEvent::Claim { binding }) => Ok(SlotState::Held {
            binding: binding.clone(),
            generation: generation
                .checked_add(1)
                .ok_or(SlotRefusal::NotApplicable)?,
        }),
        (
            SlotState::Held {
                binding: holder, ..
            },
            SlotEvent::Claim { binding },
        ) => {
            if holder == binding {
                Ok(state.clone())
            } else {
                Err(SlotRefusal::ManagedSlotHeld)
            }
        }
        (
            SlotState::Held {
                binding: holder,
                generation,
            },
            SlotEvent::Release {
                binding,
                generation: g,
            },
        ) => {
            if holder == binding && generation == g {
                Ok(SlotState::Clearing {
                    generation: *generation,
                })
            } else {
                Err(SlotRefusal::StaleGeneration)
            }
        }
        (SlotState::Clearing { generation }, SlotEvent::FilesRemoved { generation: g }) => {
            if generation == g {
                Ok(SlotState::Free {
                    generation: *generation,
                })
            } else {
                Err(SlotRefusal::StaleGeneration)
            }
        }
        (SlotState::Held { generation, .. }, SlotEvent::Restart { grant_ended: true }) => {
            Ok(SlotState::Clearing {
                generation: *generation,
            })
        }
        (_, SlotEvent::Restart { .. }) => Ok(state.clone()),
        (SlotState::Clearing { generation }, SlotEvent::HandOver { generation: g, to }) => {
            if generation == g {
                Ok(SlotState::Held {
                    binding: to.clone(),
                    generation: generation
                        .checked_add(1)
                        .ok_or(SlotRefusal::NotApplicable)?,
                })
            } else {
                Err(SlotRefusal::StaleGeneration)
            }
        }
        _ => Err(SlotRefusal::NotApplicable),
    }
}

// --- ⟨M05⟩ shared slots (ADR-0011 §5.2 as ruled in §10 item 6) -------------------------

/// What a managed launch bind does with one pair's slot (ADR-0011 §5.2, ruling D06).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SlotBind {
    /// The slot is free: the binding claims it and materializes it (M03's claim).
    Claim,
    /// The binding already holds the slot (idempotent).
    Hold,
    /// Another binding materializes the slot and this one is compatible: it joins (a
    /// reference is added; the slot, its generation and its files are unchanged).
    Join,
    /// The binding already references the slot (a repeated bind, or a slot clearing
    /// towards a handover the binding is waiting for): nothing changes.
    Referenced,
}

/// ⟨M05⟩ ADR-0011 §5.2 (ruling D06): the decision of a managed launch bind of `binding`
/// on a slot in `state`. `references` says whether `binding` already references the
/// slot; `compatible` whether it may share it: its active grant covers the pair **with
/// the same mechanism** as the slot's materializer.
///
/// | Slot state | Binding | Decision |
/// |---|---|---|
/// | `free(g)` | any | [`SlotBind::Claim`] |
/// | `held(b, g)` | `b` | [`SlotBind::Hold`] |
/// | `held(m, g)`, `m ≠ b` | compatible, already references | [`SlotBind::Referenced`] |
/// | `held(m, g)`, `m ≠ b` | compatible | [`SlotBind::Join`] |
/// | `held(m, g)`, `m ≠ b` | incompatible | refused, [`SlotRefusal::ManagedSlotHeld`] |
/// | `clearing(g)` | compatible, already references | [`SlotBind::Referenced`] (it waits for the handover) |
/// | `clearing(g)` | otherwise | refused, [`SlotRefusal::NotApplicable`] (still being cleared; M03) |
///
/// An incompatible bind is always refused, a reference or not.
///
/// # Errors
/// The [`SlotRefusal`] of the table.
pub fn slot_bind(
    state: &SlotState,
    binding: &BindingId,
    references: bool,
    compatible: bool,
) -> Result<SlotBind, SlotRefusal> {
    match state {
        SlotState::Free { .. } => Ok(SlotBind::Claim),
        SlotState::Held {
            binding: holder, ..
        } if holder == binding => Ok(SlotBind::Hold),
        SlotState::Held { .. } if !compatible => Err(SlotRefusal::ManagedSlotHeld),
        SlotState::Held { .. } if references => Ok(SlotBind::Referenced),
        SlotState::Held { .. } => Ok(SlotBind::Join),
        SlotState::Clearing { .. } if compatible && references => Ok(SlotBind::Referenced),
        SlotState::Clearing { .. } => Err(SlotRefusal::NotApplicable),
    }
}

/// ⟨M05⟩ One referencer of a shared slot as the handover reads it (a `slot_references`
/// row with its binding's and grant's state now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotReferencer {
    /// The referencing binding.
    pub binding: BindingId,
    /// Its grant's effective deadline now (cutoffs included).
    pub deadline: Timestamp,
    /// Whether it can carry the slot now: the binding is active in the slot's
    /// environment with the slot's mechanism, and its grant permits use and has not
    /// reached its deadline. An unusable referencer is dropped, never handed the slot.
    pub usable: bool,
}

/// ⟨M05⟩ ADR-0011 §5.2 (ruling D06): the referencer a slot passes to when its
/// materializer ends: the **usable** one with the **latest deadline** (ties: the
/// lowest binding ID, so the choice is deterministic). `None`: no usable referencer
/// remains and the slot clears (`clearing → free`).
#[must_use]
pub fn handover_target(referencers: &[SlotReferencer]) -> Option<&SlotReferencer> {
    referencers.iter().filter(|r| r.usable).min_by(|a, b| {
        b.deadline
            .cmp(&a.deadline)
            .then_with(|| a.binding.cmp(&b.binding))
    })
}

// --- owned connections (ADR-0008 D8 item 2) ------------------------------------------

/// An owned connection's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OwnedConnectionState {
    /// Written (at bind on Unix; at registration on Windows) and running.
    Up,
    /// Being closed.
    Closing,
    /// Closed or observed exited.
    Closed,
    /// Its identity could not be verified: never signalled, treated as unmanaged.
    Unverified,
}

/// An `owned_connections` row (ADR-0008 D8 item 2; m03-plan §5 item 16). The binding's
/// holder and the connection process are separate records. Before every signal the
/// supervisor re-verifies `pid`, `start_token` and `image`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedConnection {
    /// ID.
    pub id: ConnectionId,
    /// Kind.
    pub kind: ConnectionKind,
    /// The binding.
    pub binding: BindingId,
    /// The grant.
    pub grant: GrantId,
    /// PID (never exposed on the wire).
    pub pid: u32,
    /// Opaque OS start-time (or creation-time) token.
    pub start_token: String,
    /// The verified client's path (the expected image).
    pub image: String,
    /// The master's control path (masters only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_path: Option<String>,
    /// The resource generation.
    pub generation: u64,
    /// State.
    pub state: OwnedConnectionState,
    /// Started (or registered).
    pub started_at: Timestamp,
}

// --- the lock epoch (ADR-0008 D9; §17.1 item 9) ---------------------------------------

/// The session-lock source's latched epoch: a monotonic lock counter and a latched
/// "lock observed" flag, which clears only when the revocation pass acknowledges
/// that epoch (`SessionLockSource::acknowledge`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LockEpoch {
    /// Locks observed so far (monotonic).
    pub epoch: u64,
    /// A lock of `epoch` was observed and not yet acknowledged.
    pub observed: bool,
}

impl LockEpoch {
    /// The epoch after a lock is observed: the counter moves and the flag latches.
    #[must_use]
    pub fn observe_lock(self) -> Self {
        Self {
            epoch: self.epoch.saturating_add(1),
            observed: true,
        }
    }

    /// Acknowledge `epoch`: clears the flag only for that epoch.
    #[must_use]
    pub fn acknowledge(self, epoch: u64) -> Self {
        if epoch == self.epoch {
            Self {
                observed: false,
                ..self
            }
        } else {
            self
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn slot_table() {
        let b = BindingId::from_random_bytes([1; 16]);
        let c = BindingId::from_random_bytes([2; 16]);
        let free = SlotState::Free { generation: 4 };
        let held = slot_transition(&free, &SlotEvent::Claim { binding: b.clone() }).unwrap();
        assert_eq!(
            held,
            SlotState::Held {
                binding: b.clone(),
                generation: 5
            }
        );
        assert_eq!(
            slot_transition(&held, &SlotEvent::Claim { binding: c.clone() }),
            Err(SlotRefusal::ManagedSlotHeld)
        );
        assert_eq!(
            slot_transition(
                &held,
                &SlotEvent::Release {
                    binding: b.clone(),
                    generation: 4
                }
            ),
            Err(SlotRefusal::StaleGeneration)
        );
        let clearing = slot_transition(
            &held,
            &SlotEvent::Release {
                binding: b,
                generation: 5,
            },
        )
        .unwrap();
        assert_eq!(clearing, SlotState::Clearing { generation: 5 });
        assert_eq!(
            slot_transition(&clearing, &SlotEvent::FilesRemoved { generation: 5 }),
            Ok(SlotState::Free { generation: 5 })
        );
        assert_eq!(
            slot_transition(&held, &SlotEvent::Restart { grant_ended: true }),
            Ok(SlotState::Clearing { generation: 5 })
        );
        assert_eq!(
            slot_transition(&held, &SlotEvent::Restart { grant_ended: false }),
            Ok(held.clone())
        );
    }

    #[test]
    fn lock_epoch_latches_until_acknowledged() {
        let e = LockEpoch::default().observe_lock();
        assert!(e.observed);
        let e2 = e.observe_lock();
        assert!(
            e2.acknowledge(e.epoch).observed,
            "an older epoch clears nothing"
        );
        assert!(!e2.acknowledge(e2.epoch).observed);
    }
}
