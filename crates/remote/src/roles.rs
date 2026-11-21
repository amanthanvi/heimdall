//! Roles and permissions (ADR-0012 §3.7, §3.8; M06 U1).
//!
//! Will hold the permissions (`view`, `request`, `approve`, `issuer_trust`, `enroll`,
//! `service`, `time_source`), the roles (`owner`, `requester`, `viewer`) as sets of them, the
//! caller context `{principal, role, remote_client}` every caller-keyed namespace includes,
//! and the `role_insufficient` denial. Limited roles never include execution on the runner.
//! Pure: no I/O. Empty in the U0 skeleton.
