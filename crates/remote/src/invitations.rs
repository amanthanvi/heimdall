//! Invitations and client revocation (ADR-0012 §3.9, §3.11; M06 U1).
//!
//! Will hold the invitation record with its authenticated pins (both confirmed by explicit
//! fingerprint comparison), the one durable consumption, non-extending expiry, and client
//! revocation and device retirement. Empty in the U0 skeleton.
