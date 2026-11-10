//! The runtime side of the issuer (ADR-0008 D3 items 6–7; m03-plan U3
//! `client::ChildIssuer`): spawns the child with piped stdin and stdout, speaks
//! [`crate::protocol`] with a 10 s per-request bound and `request_id` matching,
//! discards and zeroizes late replies, supervises the child by exact PID and start
//! token (the D3 item 7 states, with bounded, jittered backoff), and implements
//! `app::ports::IssuerPort`.
//!
//! U3 fills this module. Wave 0 freezes no item here: the frozen pieces are the
//! protocol ([`crate::protocol`]) and the `IssuerPort` port in `app`. Until U3 lands
//! no issuer is started, so every issuer-dependent request is refused
//! `CAPABILITY_UNAVAILABLE` (`driver_unavailable`) by the runtime.
