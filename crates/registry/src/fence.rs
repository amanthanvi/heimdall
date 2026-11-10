//! The reconcile classification and fencing view (ADR-0008 D5 §6.3, §6.7; m03-plan
//! U5): `classify_reconcile(observation, expected, FenceView) -> ReconcileClass`,
//! `not_after_remote` and `late_write_cleared`.
//!
//! U5 fills this module; wave 0 freezes no item here (the `fence` exit codes 43 and 44
//! and the `fence` tokens are in [`crate::hm1`]).
