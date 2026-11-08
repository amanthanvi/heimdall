//! CA retirement (ADR-0008 D4 item 3; m03-plan U4 `retire::step`): the durable,
//! idempotent transitions `retiring → unloaded → deleted → retired`, with the
//! `unload` message of [`crate::protocol`] sent only once the CA is `retiring`.
//!
//! U4 fills this module; wave 0 freezes no item here.
