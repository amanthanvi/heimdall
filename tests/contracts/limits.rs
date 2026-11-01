//! ADR-0006 section 2 limits, capability names and version constants (golden).
//! A change here is a contract change that needs a new ADR revision and fixtures.

use crate::event::MAX_CURSOR_LEN;
use crate::ipc::{
    EVENT_BUFFER_PER_SUBSCRIPTION, HELLO_TIMEOUT_MS, MAX_CONTROL_CONNECTIONS,
    MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, MAX_INFLIGHT_REQUESTS_PER_CONNECTION,
    MAX_SIGNING_CONNECTIONS, MAX_SIGNING_FRAME_BYTES, MAX_SUBSCRIPTIONS_PER_CONNECTION, capability,
};
use crate::request::{MAX_ARGV_BYTES, MAX_SCOPE_PAIRS};
use crate::{PROTOCOL_VERSION, SCHEMA_VERSION};

#[test]
fn framing_and_connection_limits_match_adr_0006() {
    assert_eq!(MAX_HELLO_FRAME_BYTES, 16 * 1024);
    assert_eq!(MAX_CONTROL_FRAME_BYTES, 1024 * 1024);
    assert_eq!(MAX_SIGNING_FRAME_BYTES, 256 * 1024);
    assert_eq!(HELLO_TIMEOUT_MS, 5_000);
    assert_eq!(MAX_INFLIGHT_REQUESTS_PER_CONNECTION, 16);
    assert_eq!(MAX_SUBSCRIPTIONS_PER_CONNECTION, 4);
    assert_eq!(EVENT_BUFFER_PER_SUBSCRIPTION, 256);
    assert_eq!(MAX_CONTROL_CONNECTIONS, 64);
    assert_eq!(MAX_SIGNING_CONNECTIONS, 64);
    // A length prefix is a u32: the largest frame must fit with room to spare, so a
    // 0xFFFFFFFF prefix is always over the limit.
    assert!(u64::try_from(MAX_CONTROL_FRAME_BYTES).unwrap() < u64::from(u32::MAX));
}

#[test]
fn request_and_cursor_bounds_are_fixed() {
    assert_eq!(MAX_SCOPE_PAIRS, 1024);
    assert_eq!(MAX_ARGV_BYTES, 1 << 20);
    assert_eq!(MAX_CURSOR_LEN, 256);
}

#[test]
fn versions_and_capability_names_are_stable() {
    assert_eq!(SCHEMA_VERSION, "1");
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(capability::OPERATIONS_V1, "operations/1");
    assert_eq!(capability::EVENTS_V1, "events/1");
    assert_eq!(capability::OWNER_POLICY_V1, "owner-policy/1");
    assert_eq!(capability::SCHEMA_DISCOVERY_V1, "schema-discovery/1");
}
