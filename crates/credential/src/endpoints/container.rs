//! ⟨M04⟩ U5: the container environment's signing endpoint (`<runtime_dir>/c/<16 hex>/
//! agent.sock`, ADR-0010 §4 items 1–6): one active binding per container environment,
//! the `SO_PEERCRED` UID rule, generation-checked teardown.
//!
//! Registered by joint wave 0 (ADR-0010 §9 items 7 and 9) so the M04 track fills it
//! without touching `endpoints/mod.rs`; it holds nothing yet.
