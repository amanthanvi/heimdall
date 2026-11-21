//! Verified sshd policy for limited roles (ADR-0012 §3.2; M06 U1).
//!
//! Will hold the check of a runner account's effective sshd policy (from `sshd -T`-style
//! output, treated as untrusted text) and the typed refusals that keep a limited role
//! unavailable until that policy is verified. Empty in the U0 skeleton.
