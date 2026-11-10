//! The issuer's loaded CAs (ADR-0008 D3 item 4 step 4, D4 item 3; m03-plan U3
//! `ca::CaSet`): CAs by fingerprint in states `active` and `pending`, signing through
//! `heimdall_credential::cert::build_and_sign`.
//!
//! U3 fills this module; wave 0 freezes no item here.
