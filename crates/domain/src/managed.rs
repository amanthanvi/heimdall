//! ⟨M03⟩ Managed pair slots, owned connections and the latched lock epoch
//! (ADR-0008 D10 item 2, D8 item 2, D9; m03-plan §5 item 16; frozen in wave 0).

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{BindingId, ConnectionId, GrantId};
use serde::{Deserialize, Serialize};

pub use heimdall_contract::managed::{ConnectionKind, SessionLockState};

// --- pair slots (ADR-0008 D10 item 2) ------------------------------------------------

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

/// ADR-0008 D10 item 2:
///
/// | Slot state | Event | Next |
/// |---|---|---|
/// | `free(g)` | claim by `b` | `held(b, g + 1)` (files written, then listed) |
/// | `held(b, g)` | claim by another binding | refused, `managed_slot_held` |
/// | `held(b, g)` | claim by `b` again | `held(b, g)` (idempotent) |
/// | `held(b, g)` | `b`'s grant ends or `b` is released | `clearing(g)` |
/// | `clearing(g)` | files of `g` removed | `free(g)` |
/// | any | restart | `held` stays `held` (degraded until re-issue) unless its grant ended (`clearing(g)`); `clearing` and `free` stay |
///
/// A release or a file removal naming another holder or generation is refused
/// (`StaleGeneration`); a generation overflow refuses (`NotApplicable`).
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
        _ => Err(SlotRefusal::NotApplicable),
    }
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
