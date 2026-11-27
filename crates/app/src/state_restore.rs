//! ⟨M08 W4 U2b-3b; ADR-0014 H4, H10⟩ The restore's `state_restored` event, through the
//! application's event publisher, the one writer of events (`heimdall_store::restore`'s
//! [`RestoreEvent`]).
//!
//! The restore calls it with the staged generation's store, after the sanitizing transaction
//! and before the staged database is closed, so the event is in the generation before the
//! pointer moves: the first thing a restarted runtime's subscribers can read after the
//! restore. Its payload is what the restore ended, quarantined and voided
//! ([`StateRestoredPayload`]): counts and opaque IDs only. Its time is the restore's.

use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::Timestamp;
use heimdall_contract::event::EventType;
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::lifecycle::StateRestoredPayload;
use heimdall_domain::time::{BootId, Clock};
use heimdall_store::Store;
use heimdall_store::restore::RestoreEvent;

use crate::events::EventPublisher;

/// The restore's event writer ([`RestoreEvent`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct RestoredEvent;

/// The restore's time, as the publisher's clock: the event is stamped with it.
struct AtRestore(Timestamp);

impl Clock for AtRestore {
    fn wall(&self) -> Timestamp {
        self.0
    }
    fn continuous(&self) -> Duration {
        Duration::ZERO
    }
    fn boot_id(&self) -> BootId {
        BootId("restore".to_owned())
    }
}

impl RestoreEvent for RestoredEvent {
    fn append(
        &self,
        store: &Arc<Store>,
        environment: &EnvironmentId,
        payload: &StateRestoredPayload,
        at: Timestamp,
    ) -> heimdall_store::Result<()> {
        let payload = serde_json::to_value(payload)?;
        EventPublisher::new(Arc::clone(store), environment.clone())
            .with_clock(Arc::new(AtRestore(at)))
            .publish(EventType::StateRestored, None, payload)
            .map(drop)
            .map_err(|e| {
                heimdall_store::StoreError::Corrupt(format!("the restore event: {}", e.message))
            })
    }
}
