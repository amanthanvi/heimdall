//! The serve-side bridge (ADR-0012 §3.6; M06 U1).
//!
//! Will hold the bridge behind `heimdall remote serve`: it reads the client ID and home from
//! argv only, originates the only `ClientHello{…, remote_client}` to the runner runtime,
//! consumes the remote side's own hello for negotiation without forwarding it, binds the
//! session to one client, and closes the session (`USAGE_ERROR`) on any later frame that
//! carries a hello or asserts a caller identity. Empty in the U0 skeleton.
