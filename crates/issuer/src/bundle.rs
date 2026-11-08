//! The recovery bundle (ADR-0008 D4 items 4–6; m03-plan U4 `bundle::export`):
//! `heimdall_contract::issuer::RecoveryBundle` with CAs, enrollments, markers and
//! instructions, optionally with host names redacted. It never holds private
//! material.
//!
//! U4 fills this module; wave 0 freezes no item here (the bundle's wire shape is the
//! public `recovery-bundle` schema in `heimdall-contract`).
