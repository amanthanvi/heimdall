//! ⟨M05⟩ U2: trust records, standing-policy actions and their decisions (ADR-0011 §2.1, §3.1, §3.4, §10 item 1).
//!
//! Registered by joint wave 0 (ADR-0011 §10 item 10) so the M05 track fills it without
//! touching `operations.rs`'s module list; it holds nothing yet. Until it does, the
//! requests it will serve answer `CAPABILITY_UNAVAILABLE` / `driver_unavailable` from
//! the fail-closed checks in `operations.rs` (ADR-0006 revision 5 §17).
