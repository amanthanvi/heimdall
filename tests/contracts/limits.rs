//! ADR-0006 section 2 limits, capability names and version constants (golden).
//! A change here is a contract change that needs a new ADR revision and fixtures.

use heimdall_contract::catalog::{MAX_LABEL_BYTES, MAX_PUBLIC_KEY_BYTES};
use heimdall_contract::doctor::MAX_CONFIG_TREE_DIFFERENCES;
use heimdall_contract::event::MAX_CURSOR_LEN;
use heimdall_contract::ipc::{
    EVENT_BUFFER_PER_SUBSCRIPTION, HELLO_TIMEOUT_MS, MAX_CONTROL_CONNECTIONS,
    MAX_CONTROL_FRAME_BYTES, MAX_HELLO_FRAME_BYTES, MAX_INFLIGHT_REQUESTS_PER_CONNECTION,
    MAX_SIGNING_CONNECTIONS, MAX_SIGNING_FRAME_BYTES, MAX_SUBSCRIPTIONS_PER_CONNECTION, capability,
};
use heimdall_contract::request::{MAX_EXECUTABLE_BYTES, MAX_SCOPE_PAIRS, MAX_STARTED_AT_BYTES};
use heimdall_contract::setup::MAX_DIFF_BYTES;
use heimdall_contract::{PROTOCOL_VERSION, SCHEMA_VERSION};

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
    assert_eq!(MAX_CURSOR_LEN, 256);
}

/// ADR-0006 revision 3 (m02-plan section 5 items 2, 5, 11, 17): `argv` no longer
/// crosses IPC, so `MAX_ARGV_BYTES` left the contract (a `heimdall-launch` limit);
/// the launch binding, diff, public-key and tree-difference bounds are fixed.
#[test]
fn m02_bounds_are_fixed() {
    assert_eq!(MAX_EXECUTABLE_BYTES, 4096);
    assert_eq!(MAX_STARTED_AT_BYTES, 64);
    assert_eq!(MAX_DIFF_BYTES, 64 * 1024);
    assert_eq!(MAX_PUBLIC_KEY_BYTES, 16 * 1024);
    assert_eq!(MAX_LABEL_BYTES, 256);
    assert_eq!(MAX_CONFIG_TREE_DIFFERENCES, 256);
}

#[test]
fn versions_and_capability_names_are_stable() {
    assert_eq!(SCHEMA_VERSION, "1");
    assert_eq!(PROTOCOL_VERSION, 1);
    assert_eq!(capability::OPERATIONS_V1, "operations/1");
    assert_eq!(capability::EVENTS_V1, "events/1");
    assert_eq!(capability::OWNER_POLICY_V1, "owner-policy/1");
    assert_eq!(capability::SCHEMA_DISCOVERY_V1, "schema-discovery/1");
    assert_eq!(capability::SERVICE_CONTROL_V1, "service-control/1");
    // Declared in wave 0, not offered until the activation change set.
    assert_eq!(capability::SETUP_V1, "setup/1");
}
