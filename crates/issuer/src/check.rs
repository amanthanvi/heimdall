//! The issuer's reservation check (ADR-0008 D3 item 4 steps 1–3; m03-plan U3
//! `check::verify_reservation`): the entry's state and age, the subject match, the
//! pure predicate through `app::issuance_ro::assess`, and the format ceilings,
//! refusing with a [`crate::protocol::IssuerRefusal`].
//!
//! U3 fills this module; wave 0 freezes no item here.
