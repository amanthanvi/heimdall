//! Disconnected status, effects, outbox and resynchronization (ADR-0012 §7; M06 U-later).
//!
//! Will hold the controller's connectivity view (`connected`, `disconnected{last_seen_at}`,
//! `unreachable{reason}`), the typed, keyed effects (`grant_revoke`, `policy_pause`,
//! `policy_cutoff`) with their durable acknowledgements, the outbox, and resynchronization.
//! Empty in the U0 skeleton.
