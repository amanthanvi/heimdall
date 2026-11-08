//! The owner-present ceremonies (ADR-0008 D4 item 1; m03-plan U4
//! `ceremony::{init, rotate_begin, restore, unlock, replace_orphan}`) on the
//! controlling terminal: generate, prepare the backup bytes, register their digest,
//! write exactly, show the passphrase, store, approve.
//!
//! U4 fills this module; wave 0 freezes no item here. Until U4 lands the CLI answers
//! every issuer ceremony with "not available in this build".
