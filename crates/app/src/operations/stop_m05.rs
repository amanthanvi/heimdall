//! ⟨M05⟩ U3: stop, targets and precedence (ADR-0011 §7).
//!
//! Registered by joint wave 0 (ADR-0011 §10 item 10) so the M05 track fills it without
//! touching `operations.rs`'s module list; it holds nothing yet. Until it does, the
//! requests it will serve answer `CAPABILITY_UNAVAILABLE` / `driver_unavailable` from
//! the fail-closed checks in `operations.rs` (ADR-0006 revision 5 §17).
