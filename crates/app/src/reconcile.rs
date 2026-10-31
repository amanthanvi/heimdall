//! Reconciler planning core (spec §13.5; R-RT-01, R-RT-04; plan §6.3 property 6).
//!
//! Pure planning over `ManagedResource` records: desired vs observed state,
//! generation checks, bounded backoff with jitter. Execution (creating a socket,
//! stopping an exact PID) is done by the runtime's supervisor, one owner per
//! resource; adapters never start competing retry loops (spec §11.5).

use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_domain::resource::{
    CleanupDecision, ManagedResource, ResourceGeneration, ResourceState, may_cleanup,
};

/// Bounded exponential backoff with jitter (spec §13.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// First delay.
    pub base: Duration,
    /// Cap.
    pub max: Duration,
    /// Maximum attempts before the resource is marked failed and the operation
    /// reports a durable next step (never indefinite prompts or tight loops).
    pub max_attempts: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_millis(500),
            max: Duration::from_secs(60),
            max_attempts: 8,
        }
    }
}

impl Backoff {
    /// Delay before `attempt` (1-based), before jitter. Saturates at `max`.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(31);
        let scaled = self.base.saturating_mul(1u32 << shift);
        scaled.min(self.max)
    }

    /// Apply jitter in `[0.5, 1.0]` of `delay` using the caller's random `unit`
    /// in `[0, 1)`. Pure so tests are deterministic.
    #[must_use]
    pub fn jittered(&self, attempt: u32, unit: f64) -> Duration {
        let d = self.delay(attempt);
        let factor = 0.5 + 0.5 * unit.clamp(0.0, 1.0);
        d.mul_f64(factor)
    }
}

/// Why a retry must stop (spec §13.5 "stops retrying when authority expires or
/// is revoked"; a watchdog must not resurrect paused access).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The owning grant is no longer usable.
    AuthorityEnded,
    /// Attempts exhausted.
    AttemptsExhausted,
    /// Authentication denied (not a transient failure).
    Denied,
}

/// A planned action for one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create or repair the resource at its current generation.
    Ensure {
        /// Generation the action is bound to.
        generation: ResourceGeneration,
    },
    /// Remove the resource at this generation only (CAS on generation).
    Cleanup {
        /// Generation the cleanup is bound to.
        generation: ResourceGeneration,
    },
    /// Observe before deciding.
    Observe,
    /// Nothing to do.
    None,
}

/// Plan the next action for a resource. Pure.
#[must_use]
pub fn plan(resource: &ManagedResource) -> Action {
    match (resource.desired, resource.observed) {
        (ResourceState::Present, ResourceState::Present)
        | (ResourceState::Absent, ResourceState::Absent) => Action::None,
        (_, ResourceState::Unknown) => Action::Observe,
        (ResourceState::Present, ResourceState::Absent) => Action::Ensure {
            generation: resource.generation,
        },
        (ResourceState::Absent, ResourceState::Present) => Action::Cleanup {
            generation: resource.generation,
        },
        (ResourceState::Unknown, _) => Action::Observe,
    }
}

/// Guard a cleanup that was planned at `planned` against the current record.
#[must_use]
pub fn guard_cleanup(planned: ResourceGeneration, current: &ManagedResource) -> CleanupDecision {
    may_cleanup(planned, current)
}

/// Decide whether a failed attempt may be retried at `now`.
pub fn should_retry(
    attempts: u32,
    backoff: &Backoff,
    authority_usable: bool,
    denied: bool,
) -> Result<(), StopReason> {
    if !authority_usable {
        return Err(StopReason::AuthorityEnded);
    }
    if denied {
        return Err(StopReason::Denied);
    }
    if attempts >= backoff.max_attempts {
        return Err(StopReason::AttemptsExhausted);
    }
    Ok(())
}

/// Resource records whose owner authority ended before `now` must have
/// `desired = Absent` (pure helper used by `tick`).
#[must_use]
pub fn desired_after_deadline(
    resource: &ManagedResource,
    deadline: Timestamp,
    now: Timestamp,
) -> ResourceState {
    if now >= deadline {
        ResourceState::Absent
    } else {
        resource.desired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        let b = Backoff::default();
        assert_eq!(b.delay(1), Duration::from_millis(500));
        assert_eq!(b.delay(2), Duration::from_secs(1));
        assert_eq!(b.delay(40), Duration::from_secs(60));
        let j = b.jittered(3, 0.0);
        assert!(j >= Duration::from_secs(1) && j <= Duration::from_secs(2));
    }

    #[test]
    fn authority_end_stops_retries_before_anything_else() {
        assert_eq!(
            should_retry(0, &Backoff::default(), false, false),
            Err(StopReason::AuthorityEnded)
        );
        assert_eq!(
            should_retry(0, &Backoff::default(), true, true),
            Err(StopReason::Denied)
        );
        assert_eq!(
            should_retry(8, &Backoff::default(), true, false),
            Err(StopReason::AttemptsExhausted)
        );
        assert_eq!(should_retry(1, &Backoff::default(), true, false), Ok(()));
    }
}
