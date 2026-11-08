//! Signature purpose checking (ADR-0008 D2 item 4; F17; m03-plan U1 `purpose`):
//! `parse_userauth` (SSH userauth requests only, through `ssh-encoding`) and `check`
//! (the key blob must be one of the grant's certificates, and the user the account of
//! the pair whose principal that certificate names).
//!
//! U1 fills this module; wave 0 freezes no item here.
