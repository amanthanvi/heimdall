//! ⟨rev7⟩ ADR-0006 revision 7's preparatory part (ADR-0013 §1.3; m07-plan U0; m08-plan U0):
//! the primitive index (D7) and the reason table (D8), whose goldens are the exported
//! `schemas/public-api/primitives.json` and `reasons.json` (`schema_export` keeps them equal
//! to the model); the declared, not offered capabilities; and the declared reasons and code.

use std::collections::BTreeSet;

use heimdall_contract::code::Code;
use heimdall_contract::envelope::reason;
use heimdall_contract::ipc::capability;
use heimdall_contract::schema::{declared_schemas, public_schemas};
use heimdall_contract::{lifecycle, primitives, reasons};

fn snake(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// D7: six groups; every schema an answer names is published or declared; every
/// capability is defined; every code is in the code table with its own exit and next
/// action; the excluded list names consent and authority, never a primitive.
#[test]
fn primitive_index_names_six_groups_with_known_schemas_codes_and_capabilities() {
    let index = primitives::index();
    let groups = index["groups"].as_array().unwrap();
    let names: Vec<&str> = groups
        .iter()
        .map(|g| g["group"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "inspect",
            "ensure",
            "bind",
            "delegate",
            "observe",
            "release_revoke"
        ]
    );
    let schemas: BTreeSet<&str> = public_schemas()
        .iter()
        .chain(declared_schemas().iter())
        .map(|s| s.name)
        .collect();
    let defined: BTreeSet<&str> = capability::ALL.into_iter().collect();
    for g in groups {
        for s in g["schemas"].as_array().unwrap() {
            assert!(schemas.contains(s.as_str().unwrap()), "{s}");
        }
        for f in g["forms"].as_array().unwrap() {
            for c in f["capabilities"].as_array().unwrap() {
                assert!(defined.contains(c.as_str().unwrap()), "{c}");
            }
            assert!(["required", "none"].contains(&f["request_id"].as_str().unwrap()));
        }
        for row in g["codes"].as_array().unwrap() {
            let code = Code::parse(row["code"].as_str().unwrap());
            assert!(Code::all().contains(&code), "{row}");
            assert_eq!(row["exit_code"], code.exit_code().as_i32());
            assert_eq!(row["next_action"], code.default_next_action());
        }
        assert!(!g["roles"].as_array().unwrap().is_empty());
    }
    for name in index["excluded"].as_array().unwrap() {
        assert!(!names.contains(&name.as_str().unwrap()));
    }
}

/// D8: every reason of every group is an answer row under exactly its group's codes; every
/// code is in the code table (⟨M08 U2b-2⟩ `REQUEST_STALE` included); every row's next action is
/// its code's default unless `NEXT_ACTIONS` names it; the rows are unique and sorted; a
/// constant that is never an error reason is not a row; every M01/M02 constant and every
/// manual reason is accounted for.
#[test]
fn reason_table_lists_every_answer_with_its_code_and_next_action() {
    let table = reasons::table();
    let rows = table["reasons"].as_array().unwrap();
    let mut seen: Vec<(String, String)> = Vec::new();
    for row in rows {
        let r = row["reason"].as_str().unwrap();
        let c = row["code"].as_str().unwrap();
        let next = row["next_action"].as_str().unwrap();
        assert!(snake(r), "{r}");
        let code = Code::parse(c);
        assert!(Code::all().contains(&code), "{r}: {c}");
        let named = reasons::NEXT_ACTIONS
            .iter()
            .find(|(nr, nc, _)| *nr == r && *nc == c)
            .map(|(_, _, a)| *a);
        assert_eq!(next, named.unwrap_or(code.default_next_action()), "{r} {c}");
        seen.push((r.to_owned(), c.to_owned()));
    }
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(seen, sorted, "rows are unique and sorted");
    let has = |r: &str, c: &str| seen.iter().any(|(sr, sc)| sr == r && sc == c);
    let names: BTreeSet<&str> = seen.iter().map(|(r, _)| r.as_str()).collect();
    for group in [
        reason::M03,
        reason::M03_REV5,
        reason::M04,
        reason::M05,
        reason::M06,
        reason::REV7,
    ] {
        for (r, c) in group {
            assert!(has(r, c.as_str()), "{r}: {c}");
        }
    }
    for (r, codes) in reasons::M02_CODES.iter().chain(reasons::M03_LITERAL_CODES) {
        let listed: BTreeSet<&str> = seen
            .iter()
            .filter(|(sr, _)| sr == r)
            .map(|(_, c)| c.as_str())
            .collect();
        assert_eq!(listed, codes.iter().copied().collect(), "{r}");
    }
    // The rulings of 2026-11-24: one reason under two codes; the owner's repair; a newer store.
    assert!(has(reason::RESTORE_EPOCH_STALE, "REQUEST_STALE"));
    assert!(has(reason::RESTORE_EPOCH_STALE, "DECISION_STALE"));
    assert!(has(reason::RESTORED_BEFORE_COMPLETION, "REQUEST_STALE"));
    for (r, next) in [
        (reason::STATE_CORRUPT, "owner_decision"),
        (reason::LEDGER_DAMAGED, "owner_decision"),
        (reason::STATE_NEWER_THAN_BUILD, "change_client"),
    ] {
        let row = rows
            .iter()
            .find(|row| row["reason"] == r && row["code"] == "STATE_UNAVAILABLE")
            .unwrap();
        assert_eq!(row["next_action"], next, "{r}");
    }
    for r in reasons::NOT_ERROR_REASONS {
        assert!(!names.contains(r), "{r} is not an error reason");
    }
    let accounted = |r: &str| names.contains(r) || reasons::NOT_ERROR_REASONS.contains(&r);
    for r in reason::ALL {
        assert!(
            accounted(r),
            "reason::ALL's {r} is neither a row nor listed apart"
        );
    }
    for r in heimdall_contract::setup::manual_reason::ALL {
        assert!(
            accounted(r),
            "manual reason {r} is neither a row nor listed apart"
        );
    }
    for r in heimdall_contract::provider::noninteractive_reason::ALL {
        assert!(
            names.contains(r),
            "{r}: the envelope reason of the same name"
        );
    }
    for r in reason::M06_PENDING {
        assert!(!names.contains(r));
    }
    for r in [reason::SUBSCRIBER_LAGGED, reason::BACKLOG_TOO_LONG] {
        assert!(!names.contains(r));
        assert!(
            table["resync_reasons"]
                .as_array()
                .unwrap()
                .contains(&r.into())
        );
    }
    // ⟨M08 U2b-2⟩ The ruling on ASK-CODE: `REQUEST_STALE` joined the code table with its
    // emitter, so no code is declared apart any more.
    assert_eq!(table["declared_codes"], serde_json::json!([]));
    assert_eq!(Code::parse(lifecycle::REQUEST_STALE), Code::RequestStale);
    assert_eq!(Code::all().len(), 31);
}

/// The revision-7 capabilities: none is still declared and not offered. `pages/1` is offered
/// on every read role's session (m07-plan U3; ADR-0013 §6.1); ⟨M08 U2b-2⟩ `request-epoch/1`
/// (ADR-0014 H13) to the roles that send mutating requests: the owner and ⟨follow-up A⟩ the
/// requester; never the viewer.
#[test]
fn revision_7_pages_offered_to_every_role_request_epoch_declared_not_offered() {
    use heimdall_contract::remote::Role;
    assert!(capability::REVISION_7_DECLARED.is_empty());
    assert!(capability::ALL.contains(&capability::PAGES_V1));
    assert!(capability::ALL.contains(&capability::REQUEST_EPOCH_V1));
    for role in [Role::Owner, Role::Requester, Role::Viewer] {
        assert!(
            capability::for_role(role).contains(&capability::PAGES_V1),
            "{role:?}"
        );
        assert_eq!(
            capability::for_role(role).contains(&capability::REQUEST_EPOCH_V1),
            role != Role::Viewer,
            "{role:?}"
        );
    }
    for role in [Role::Owner, Role::Requester] {
        assert!(
            capability::for_role(role).contains(&capability::REQUEST_EPOCH_V1),
            "{role:?}"
        );
    }
    assert!(!capability::for_role(Role::Viewer).contains(&capability::REQUEST_EPOCH_V1));
}

// --- D20: maximal records (the ruling of 2026-11-24) ---------------------------------------

/// A string of exactly `n` bytes, unique per `seed`, in an ID's alphabet.
fn filled(seed: usize, n: usize) -> String {
    let head = format!("{seed:04}");
    format!("{head}{}", "x".repeat(n - head.len()))
}

fn item_bytes<T: serde::Serialize>(item: &T) -> usize {
    serde_json::to_vec(item).unwrap().len()
}

/// A maximal profile item (every field at its bound: a 128-byte ID, a 256-byte label, 200
/// pairs of 128-byte destination IDs and accounts, every capability) fits the 64 KiB item
/// bound with 4 KiB to spare.
#[test]
fn maximal_profile_item_fits_with_room_to_spare() {
    use heimdall_contract::bounds::{ITEM_SPARE_BYTES, MAX_ITEM_BYTES, MAX_PROFILE_PAIRS};
    use heimdall_contract::ids::MAX_ID_LEN;
    let pairs: Vec<serde_json::Value> = (0..MAX_PROFILE_PAIRS)
        .map(|i| {
            serde_json::json!({
                "destination": filled(i, MAX_ID_LEN),
                "account": filled(i, MAX_ID_LEN),
            })
        })
        .collect();
    let profile: heimdall_contract::views::catalog::ProfileView =
        serde_json::from_value(serde_json::json!({
            "profile_id": filled(0, MAX_ID_LEN),
            "revision": u64::MAX,
            // `"` is allowed in a label and serializes as two bytes: the worst case.
            "label": "\"".repeat(heimdall_contract::catalog::MAX_LABEL_BYTES),
            "pairs": pairs,
            "capabilities": ["ssh-authentication", "git-signing", "agent-forwarding"],
        }))
        .unwrap();
    let n = item_bytes(&profile);
    assert!(
        n + ITEM_SPARE_BYTES <= MAX_ITEM_BYTES,
        "a maximal profile is {n} bytes"
    );
}

/// A maximal destination item: the destination view with every field at its bound (the
/// 255-byte alias and host name, the 256-byte label of `"` (512 bytes escaped), the pair
/// preference with `graceful` and its connection policy's longest wording, the route-health
/// view of the largest report `record_health` accepts (64 attempts with the longest failure
/// class, `terminal_after_forwarding`), listed as its 32 most recent with the dropped count
/// (review U0-RC01), the longest host-pin setting) and its approved routes (8 routes, each
/// with `external_roost`, 8 relays on each of two of them for the destination's 16, every
/// relay URL at 2,048 bytes, 4 consents and 3 direct addresses per route, each address and the
/// interface bind address an IPv6 maximum with a 15-byte zone, 8 host-key pins of 1,536 bytes) fits the 64 KiB item bound with 4 KiB to spare (ruled 2026-11-24).
#[test]
fn maximal_destination_item_fits_with_room_to_spare() {
    use heimdall_contract::bounds::{
        ITEM_SPARE_BYTES, MAX_ADDRESS_BYTES, MAX_ITEM_BYTES, MAX_RELAYS_PER_DESTINATION,
        MAX_RELAYS_PER_ROUTE, MAX_ROUTES_PER_DESTINATION,
    };
    use heimdall_contract::bounds::{
        MAX_CONSENTS_PER_ROUTE as CONSENTS, MAX_DIRECT_ADDRESSES_PER_ROUTE as DIRECT_ADDRESSES,
        MAX_HOST_KEY_LINE_BYTES as HOST_KEY_LINE, MAX_HOST_KEYS_PER_DESTINATION as HOST_KEYS,
    };
    use heimdall_contract::ids::MAX_ID_LEN;
    use heimdall_contract::route::{RELAY_URL_MAX_BYTES, ROUTE_HEALTH_ATTEMPTS_MAX};
    use heimdall_contract::views::catalog::RouteHealthView;
    let hex = |i: usize, n: usize| format!("{i:0n$x}");
    let route_id = |i: usize| format!("route_{}", hex(i, 32));
    let relay = |i: usize| {
        let head = format!("https://relay{i:02}.example.invalid/");
        format!("{head}{}", "p".repeat(RELAY_URL_MAX_BYTES - head.len()))
    };
    // An address string at its ruled worst case: the canonical IPv6 maximum (39 bytes) with a
    // zone of an interface name at its longest (15 bytes), within `MAX_ADDRESS_BYTES`.
    let v6_with_zone = |a: usize| {
        format!(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:{a:04x}%{}",
            "e".repeat(15)
        )
    };
    let address = |text: &str| {
        assert!(text.len() <= MAX_ADDRESS_BYTES, "{text}");
        text.to_owned()
    };
    let mut relays_left = MAX_RELAYS_PER_DESTINATION;
    let routes: Vec<serde_json::Value> = (0..MAX_ROUTES_PER_DESTINATION)
        .map(|i| {
            let n = relays_left.min(MAX_RELAYS_PER_ROUTE);
            relays_left -= n;
            serde_json::json!({
                "id": route_id(i),
                "route": {
                    "kind": "iroh",
                    "endpoint": hex(i, 64),
                    // Serialized only when true: an external-roost route with consent.
                    "external_roost": true,
                    "direct_addresses": (0..DIRECT_ADDRESSES)
                        .map(|a| address(&format!("[{}]:65535", v6_with_zone(a))))
                        .collect::<Vec<_>>(),
                },
                "exposure": {
                    "bind": {"kind": "interface", "address": address(&v6_with_zone(i))},
                    "infrastructure": {
                        "kind": "custom",
                        "relays": (0..n).map(|r| relay(i * 8 + r)).collect::<Vec<_>>(),
                    },
                    "direct_fallback": true,
                    "port": 65535,
                },
                "consents": (0..CONSENTS).map(|c| format!("cns_{}", hex(i * 8 + c, 32))).collect::<Vec<_>>(),
                "identification_timeout_ms": u64::MAX,
            })
        })
        .collect();
    let host_keys: Vec<serde_json::Value> = (0..HOST_KEYS)
        .map(|k| {
            let head = format!("ssh-rsa AAAA{k:02}");
            serde_json::json!({
                "public_key": format!("{head}{}", "B".repeat(HOST_KEY_LINE - head.len())),
                "fingerprint": format!("SHA256:{}", "A".repeat(43)),
            })
        })
        .collect();
    let routes: heimdall_contract::route::DestinationRoutes =
        serde_json::from_value(serde_json::json!({
            "destination": filled(0, MAX_ID_LEN),
            "routes": routes,
            "host_keys": host_keys,
        }))
        .unwrap_or_else(|e| panic!("routes: {e}"));
    // The reports `record_health` accepts at their largest: 64 attempts, every failure the
    // longest class, the final route the one attempt without a failure (or none). The view
    // lists the 32 most recent, so the largest view puts the success among the dropped ones.
    let at: heimdall_contract::Timestamp = "2026-11-24T00:00:00.123456789Z".parse().unwrap();
    let report = |success: Option<usize>| -> heimdall_contract::route::RouteHealthPayload {
        let attempts: Vec<serde_json::Value> = (0..ROUTE_HEALTH_ATTEMPTS_MAX)
            .map(|a| {
                let route = route_id(a % MAX_ROUTES_PER_DESTINATION);
                if success == Some(a) {
                    serde_json::json!({"route": route, "duration_ms": 600_000})
                } else {
                    serde_json::json!({
                        "route": route,
                        "failure": "terminal_after_forwarding",
                        "duration_ms": 600_000,
                    })
                }
            })
            .collect();
        let mut result = serde_json::json!({
            "kind": "failed_over",
            "destination": filled(0, MAX_ID_LEN),
            "account": filled(1, MAX_ID_LEN),
            "attempts": attempts,
        });
        if let Some(a) = success {
            result["final_route"] = route_id(a % MAX_ROUTES_PER_DESTINATION).into();
        }
        serde_json::from_value(result).unwrap_or_else(|e| panic!("report: {e}"))
    };
    let mut view: heimdall_contract::views::catalog::DestinationView =
        serde_json::from_value(serde_json::json!({
            "destination_id": filled(0, MAX_ID_LEN),
            "alias": "a".repeat(255),
            "revision": u64::MAX,
            // `"` is allowed in a label and serializes as two bytes: the worst case.
            "label": "\"".repeat(heimdall_contract::catalog::MAX_LABEL_BYTES),
            "updated_at": "2026-11-24T00:00:00.123456789Z",
            "definition": "managed",
            "hostname": "h".repeat(255),
            "port": 65535,
            "account": filled(1, MAX_ID_LEN),
            "identity_id": format!("idn_{}", hex(1, 32)),
            "jump": filled(2, MAX_ID_LEN),
            // The connection policy's wording is one of a fixed set of disclosure sentences (the
            // longest, strict and not exclusive with owned masters, is about 242 bytes): 256.
            "preference": {
                "mechanism": "managed_certificate",
                "projection": {"state": "applied", "generation": u64::MAX},
                "connection_policy": {
                    "existing": "graceful",
                    "multiplexing": "owned_masters",
                    "wording": "w".repeat(256),
                },
            },
            "host_pin_defeated": {
                "setting": heimdall_contract::route::HOST_PIN_SETTINGS
                    .iter()
                    .max_by_key(|s| s.len())
                    .unwrap(),
                "reported_at": "2026-11-24T00:00:00.123456789Z",
            },
        }))
        .unwrap_or_else(|e| panic!("view: {e}"));
    let mut largest = 0;
    for success in [None, Some(0), Some(ROUTE_HEALTH_ATTEMPTS_MAX - 1)] {
        let health = RouteHealthView::from_report(report(success), at);
        assert_eq!(health.attempts_dropped, Some(32));
        view.route_health = Some(health);
        largest = largest.max(item_bytes(&view));
    }
    let n = largest + item_bytes(&routes);
    assert!(
        n + ITEM_SPARE_BYTES <= MAX_ITEM_BYTES,
        "a maximal destination with its routes is {n} bytes (view {largest}, routes {})",
        item_bytes(&routes)
    );
}

// --- ⟨M07 W10 S2-08⟩ every request form's required capabilities ----------------------------

/// What a form needs beyond `operations/1`, as slices whose union is the form's set.
type Needs = &'static [&'static [&'static str]];

const NONE: Needs = &[];
const SERVICE: &[&str] = &[capability::SERVICE_CONTROL_V1];
const SETUP: &[&str] = &[capability::SETUP_V1];
const ISSUER: &[&str] = &[capability::ISSUER_V1];
const ENROLLMENT: &[&str] = &[capability::ENROLLMENT_V1];
const CONNECTIONS: &[&str] = &[capability::CONNECTIONS_V1];
const ENVIRONMENTS: &[&str] = &[capability::ENVIRONMENTS_V1];
const TRUSTED: &[&str] = &[capability::TRUSTED_WORK_V1];
const PAGES: &[&str] = &[capability::PAGES_V1];
const REMOTE: &[&str] = &[capability::REMOTE_CONTROL_V1];
const ROUTES: &[&str] = &[capability::ROUTES_V1];
const IROH: &[&str] = &[capability::TRANSPORT_IROH_V1];
const RUNNER: &[&str] = &[capability::RUNNER_V1];
/// S2-08 (ADR-0006 §2.4; ruled 2026-11-26): `owner-policy/1` gates exactly the four actions
/// §2.4 names (`pause`, `resume`, `cutoff`, `clear_cutoff`), plain or targeted; every other
/// `policy` action keeps only its own gate. `events/1` covers `observe` of `events` (and
/// `Subscribe`, which is a frame, not a request: `heimdall_ipc::session`'s tests).
const POLICY: &[&str] = &[capability::OWNER_POLICY_V1];
const EVENTS: &[&str] = &[capability::EVENTS_V1];
/// S2-08 (ADR-0006 §2.4; ruled 2026-11-26): `inspect capabilities` needs
/// `schema-discovery/1`, whatever else its form needs; the published primitive index lists it
/// as its own form (ADR-0013 §9).
const DISCOVERY: &[&str] = &[capability::SCHEMA_DISCOVERY_V1];

/// One request of every form the generated request schema admits, with what it needs.
/// Inline forms, then the request examples by file, then the revision-6 golden by kind.
const INLINE: &[(&str, Needs)] = &[
    // inspect: every subject whole, and the revision-7 and revision-5 variations.
    (r#"{"op":"inspect","subject":"capabilities"}"#, &[DISCOVERY]),
    (r#"{"op":"inspect","subject":"environments"}"#, NONE),
    (r#"{"op":"inspect","subject":"profiles"}"#, NONE),
    (r#"{"op":"inspect","subject":"destinations"}"#, NONE),
    (r#"{"op":"inspect","subject":"bindings"}"#, NONE),
    (r#"{"op":"inspect","subject":"grants"}"#, NONE),
    (r#"{"op":"inspect","subject":"operations"}"#, NONE),
    (r#"{"op":"inspect","subject":"decisions"}"#, NONE),
    (r#"{"op":"inspect","subject":"identities"}"#, NONE),
    (r#"{"op":"inspect","subject":"projections"}"#, NONE),
    (r#"{"op":"inspect","subject":"enrollments"}"#, NONE),
    (r#"{"op":"inspect","subject":"issuer"}"#, NONE),
    (r#"{"op":"inspect","subject":"connections"}"#, NONE),
    (
        r#"{"op":"inspect","subject":"workspace","cwd":"/w"}"#,
        &[TRUSTED],
    ),
    (r#"{"op":"inspect","subject":"policies"}"#, &[TRUSTED]),
    (
        r#"{"op":"inspect","subject":"export","redact":true}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"inspect","subject":"capabilities","cwd":"/w"}"#,
        &[TRUSTED, DISCOVERY],
    ),
    (
        r#"{"op":"inspect","subject":"destinations","page":{"limit":10}}"#,
        &[PAGES],
    ),
    (
        r#"{"op":"inspect","subject":"profiles","select":{"ids":["dev"]}}"#,
        &[PAGES],
    ),
    (
        r#"{"op":"inspect","subject":"policies","page":{}}"#,
        &[PAGES, TRUSTED],
    ),
    // the primitives
    (
        r#"{"op":"delegate","parent_binding_id":"binding_0123456789abcdef0123456789abcdef","scope":[{"destination":"dest-1","account":"deploy"}],"work_id":"work-43","request_id":"req-0401"}"#,
        NONE,
    ),
    (
        r#"{"op":"observe","kind":"operation","operation_id":"op_00112233445566778899aabbccddeeff"}"#,
        NONE,
    ),
    (r#"{"op":"observe","kind":"events","filter":{}}"#, &[EVENTS]),
    (
        r#"{"op":"observe","kind":"events","filter":{},"cursor":"c1","limit":10}"#,
        &[EVENTS],
    ),
    (
        r#"{"op":"cancel","operation_id":"op_00112233445566778899aabbccddeeff"}"#,
        NONE,
    ),
    (
        r#"{"op":"release","binding_id":"binding_0123456789abcdef0123456789abcdef"}"#,
        NONE,
    ),
    // policy: the M01 actions, the M03 actions, then revision 5's forms and actions.
    (
        r#"{"op":"policy","action":"pause","policy_id":"p"}"#,
        &[POLICY],
    ),
    (
        r#"{"op":"policy","action":"resume","policy_id":"p"}"#,
        &[POLICY],
    ),
    (
        r#"{"op":"policy","action":"cutoff","policy_id":"p","at":"2026-10-02T10:00:00Z"}"#,
        &[POLICY],
    ),
    (
        r#"{"op":"policy","action":"clear_cutoff","policy_id":"p"}"#,
        &[POLICY],
    ),
    (
        r#"{"op":"policy","action":"set_lock_behavior","policy_id":"p","behavior":"continue"}"#,
        NONE,
    ),
    (
        r#"{"op":"policy","action":"set_connection_policy","policy_id":"p","existing":"strict"}"#,
        NONE,
    ),
    (
        r#"{"op":"policy","action":"resume","target":{"kind":"all"}}"#,
        &[TRUSTED, POLICY],
    ),
    (
        r#"{"op":"policy","action":"clear_cutoff","target":{"kind":"policy","policy_id":"p"}}"#,
        &[TRUSTED, POLICY],
    ),
    (
        r#"{"op":"policy","action":"create","profile":"dev","environments":[]}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"extend_scope","policy_id":"p","background_work":true}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"narrow_scope","policy_id":"p","pairs":[{"destination":"dest-1","account":"deploy"}]}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"set_max_window","policy_id":"p","max_window":"12h"}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"remove","policy_id":"p"}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"reconcile_workspace","workspace":"ws_00112233445566778899aabbccddeeff","cwd":"/w"}"#,
        &[TRUSTED],
    ),
    (
        r#"{"op":"policy","action":"stop","target":{"kind":"profile","profile":"dev"}}"#,
        &[TRUSTED],
    ),
    // the rest without an example
    (
        r#"{"op":"catalog","action":"set_preference","destination":"dest-lab","account":"deploy","mechanism":"managed_certificate","request_id":"req-0209"}"#,
        &[SETUP],
    ),
    (
        r#"{"op":"connections","action":"close","connection_id":"conn_00112233445566778899aabbccddeeff"}"#,
        &[CONNECTIONS],
    ),
    (
        r#"{"op":"connections","action":"register","binding_id":"binding_0123456789abcdef0123456789abcdef","pid":4242,"created_at":"2026-11-10T14:05:00Z","image":"/usr/bin/ssh"}"#,
        &[CONNECTIONS],
    ),
    (r#"{"op":"uninstall_fence","action":"acquire"}"#, &[SERVICE]),
    (r#"{"op":"uninstall_fence","action":"release"}"#, &[SERVICE]),
    (
        r#"{"op":"uninstall_fence","action":"retry_remote_revocations"}"#,
        &[SERVICE],
    ),
];

/// Every `schemas/examples/request.*.json`, by file name.
const EXAMPLES: &[(&str, Needs)] = &[
    ("request.bind-launch.json", NONE),
    ("request.catalog.adopt-identity-onepassword.json", &[SETUP]),
    ("request.catalog.adopt-identity.json", &[SETUP]),
    ("request.catalog.apply-import.dry-run.json", &[TRUSTED]),
    ("request.catalog.apply-import.json", &[TRUSTED]),
    ("request.catalog.declare-interaction.json", &[SETUP]),
    ("request.catalog.remove-destination.json", &[SETUP]),
    ("request.catalog.remove-identity.json", &[SETUP]),
    ("request.catalog.remove-profile.json", &[SETUP]),
    ("request.catalog.set-default-profile.json", &[TRUSTED]),
    ("request.catalog.upsert-destination-observed.json", &[SETUP]),
    ("request.catalog.upsert-destination.json", &[SETUP]),
    ("request.catalog.upsert-profile.json", &[SETUP]),
    ("request.catalog.withdraw-declaration.json", &[SETUP]),
    ("request.confirm-time.json", NONE),
    ("request.decide.json", NONE),
    ("request.enrollment.abandon.json", &[ENROLLMENT]),
    ("request.enrollment.apply.json", &[ENROLLMENT]),
    ("request.enrollment.preview.json", &[ENROLLMENT]),
    ("request.enrollment.reconcile.json", &[ENROLLMENT]),
    ("request.enrollment.remove-foreign.json", &[ENROLLMENT]),
    ("request.enrollment.remove.json", &[ENROLLMENT]),
    ("request.enrollment.step-result.json", &[ENROLLMENT]),
    ("request.enrollment.step.json", &[ENROLLMENT]),
    ("request.enrollment.verify.json", &[ENROLLMENT]),
    ("request.ensure.context.json", &[TRUSTED]),
    ("request.ensure.json", NONE),
    ("request.environment.container-add.json", &[ENVIRONMENTS]),
    ("request.environment.container-remove.json", &[ENVIRONMENTS]),
    ("request.environment.wsl-disable.json", &[ENVIRONMENTS]),
    ("request.environment.wsl-enable.json", &[ENVIRONMENTS]),
    ("request.inspect.page.json", &[PAGES]),
    ("request.inspect.select.json", &[PAGES]),
    ("request.inspect.workspace.json", &[TRUSTED]),
    ("request.issuer.bundle-written.json", &[ISSUER]),
    ("request.issuer.bundle.json", &[ISSUER]),
    ("request.issuer.register-report.json", &[ISSUER]),
    ("request.issuer.register-restore.json", &[ISSUER]),
    ("request.issuer.register-rotation.json", &[ISSUER]),
    ("request.issuer.register.json", &[ISSUER]),
    ("request.issuer.retire-confirm.json", &[ISSUER]),
    ("request.issuer.retire.json", &[ISSUER]),
    ("request.issuer.status.json", &[ISSUER]),
    ("request.issuer.unlock.json", &[ISSUER]),
    ("request.observe-events.json", &[EVENTS]),
    ("request.policy-cutoff.json", &[POLICY]),
    ("request.policy.pause-target.json", &[TRUSTED, POLICY]),
    ("request.policy.trust-workspace.json", &[TRUSTED]),
    ("request.revoke.json", NONE),
    ("request.revoke.work.json", &[TRUSTED]),
    ("request.setup.apply.json", &[SETUP]),
    ("request.setup.preview-apply.json", &[SETUP]),
    ("request.setup.preview-repair.json", &[SETUP]),
    ("request.setup.preview-rollback.json", &[SETUP]),
    ("request.setup.repair.json", &[SETUP]),
    ("request.setup.rollback.json", &[SETUP]),
    ("request.shutdown.json", &[SERVICE]),
];

/// Every form of `tests/contracts/golden/rev6-requests.golden.json`, by kind.
const REVISION_6: &[(&str, Needs)] = &[
    ("device.retire", &[REMOTE]),
    ("remote_environment.activation_probe", &[REMOTE]),
    ("remote_environment.add", &[REMOTE]),
    ("remote_environment.invite", &[REMOTE]),
    ("remote_environment.join", &[REMOTE]),
    ("remote_environment.remove", &[REMOTE]),
    ("remote_environment.revoke_client", &[REMOTE]),
    // ⟨rev6.5; ADR-0006 §18.9 item 5⟩ every role announces its own client's endpoint.
    ("remote_environment.rotate_endpoint", NONE),
    ("remote_environment.runner_policy_recheck", &[REMOTE]),
    ("remote_environment.status", &[REMOTE]),
    ("remote_environment.update", &[REMOTE]),
    ("route.add", &[ROUTES]),
    ("route.prefer", &[ROUTES]),
    ("route.record_health", &[ROUTES]),
    ("route.remove", &[ROUTES]),
    ("route.resolve_binding", &[ROUTES]),
    ("runner.authority_report", &[RUNNER]),
    ("runner.deliver_effect", &[RUNNER]),
    ("runner.install_certificate", &[RUNNER]),
    ("runner.prepare_remote_grant", &[RUNNER]),
    ("runner.time_challenge", &[RUNNER]),
    ("runner.time_response", &[RUNNER]),
    ("runner_local.clear_time_source", &[REMOTE]),
    ("runner_local.designate_time_source", &[REMOTE]),
    ("runner_local.distrust_issuer", &[REMOTE]),
    ("runner_local.enroll_owner", &[REMOTE]),
    ("runner_local.policy_recheck", &[REMOTE]),
    ("runner_local.trust_issuer", &[REMOTE]),
    ("transport.adopt_roost", &[IROH]),
    ("transport.disable", &[IROH]),
    ("transport.enable", &[IROH]),
    ("transport.rotate", &[IROH]),
    // ⟨rev6.3⟩ the controller's own records: served to the local owner only.
    ("controller_record.put_environment", NONE),
    ("controller_record.remove_environment", NONE),
    ("controller_record.resume_issuance", NONE),
];

/// A request's form: its `op` and the tag that selects its variant (`action`; `kind` for
/// `observe`; `subject` for `inspect`), or none.
fn form_of(v: &serde_json::Value) -> (String, Option<String>) {
    let op = v["op"].as_str().unwrap().to_owned();
    let tag = match op.as_str() {
        "inspect" => "subject",
        "observe" => "kind",
        _ => "action",
    };
    (op, v[tag].as_str().map(str::to_owned))
}

/// Every form the generated request schema admits, so a new `Request` variant, action,
/// observe kind or inspect subject has no row until one is added.
fn schema_forms() -> BTreeSet<(String, Option<String>)> {
    let doc = serde_json::to_value(
        public_schemas()
            .into_iter()
            .find(|s| s.name == "request")
            .unwrap()
            .schema,
    )
    .unwrap();
    let consts = |alts: &serde_json::Value, tag: &str| -> Vec<String> {
        alts.as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                a["properties"][tag]["const"]
                    .as_str()
                    .or_else(|| a["const"].as_str())
            })
            .map(str::to_owned)
            .collect()
    };
    let mut out = BTreeSet::new();
    for alt in doc["oneOf"].as_array().unwrap() {
        let op = alt["properties"]["op"]["const"]
            .as_str()
            .unwrap()
            .to_owned();
        let def = alt["$ref"]
            .as_str()
            .and_then(|r| doc.pointer(r.trim_start_matches('#')))
            .unwrap();
        let tags = match op.as_str() {
            "inspect" => consts(&doc["$defs"]["InspectSubject"]["oneOf"], "subject"),
            "observe" => consts(&def["oneOf"], "kind"),
            _ => consts(&def["oneOf"], "action"),
        };
        if tags.is_empty() {
            out.insert((op, None));
        } else {
            out.extend(tags.into_iter().map(|t| (op.clone(), Some(t))));
        }
    }
    out
}

/// ⟨M07 W10 S2-08⟩ Every request form states the capabilities a session must have negotiated
/// to send it (ADR-0006 §2.4), and `Request::required_capabilities` names exactly those, each
/// once: a gated form that declares nothing, or the wrong capability, fails here. The table
/// covers every form of the generated request schema (every variant, action, observe kind and
/// inspect subject), so a new form fails until it is given a row. `required_capability` is
/// one of them whenever it answers.
#[test]
fn every_request_form_declares_its_required_capabilities() {
    use heimdall_contract::request::Request;
    let mut rows: Vec<(String, serde_json::Value, Needs)> = INLINE
        .iter()
        .map(|(json, needs)| {
            (
                (*json).to_owned(),
                serde_json::from_str(json).unwrap(),
                *needs,
            )
        })
        .collect();
    let examples = crate::repo_root().join("schemas/examples");
    let mut on_disk: Vec<String> = std::fs::read_dir(&examples)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("request.") && n.ends_with(".json"))
        .collect();
    on_disk.sort();
    let listed: Vec<String> = EXAMPLES.iter().map(|(f, _)| (*f).to_owned()).collect();
    assert_eq!(on_disk, listed, "every request example has a row, in order");
    for (file, needs) in EXAMPLES {
        let text = std::fs::read_to_string(examples.join(file)).unwrap();
        crate::assert_clean(file, &text);
        rows.push((
            (*file).to_owned(),
            serde_json::from_str(&text).unwrap(),
            *needs,
        ));
    }
    let golden: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            crate::repo_root().join("tests/contracts/golden/rev6-requests.golden.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut kinds = BTreeSet::new();
    for row in ["requests", "no_capability_requests"]
        .iter()
        .flat_map(|k| golden[*k].as_array().unwrap())
    {
        let kind = row["kind"].as_str().unwrap();
        let needs = REVISION_6
            .iter()
            .find(|(k, _)| *k == kind)
            .unwrap_or_else(|| panic!("{kind}: no row"))
            .1;
        kinds.insert(kind);
        rows.push((kind.to_owned(), row["json"].clone(), needs));
    }
    let stated: BTreeSet<&str> = REVISION_6.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, stated, "every revision-6 row is in the golden");

    let mut covered = BTreeSet::new();
    for (what, v, needs) in &rows {
        let r: Request =
            serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{what}: {e}"));
        let got: Vec<&str> = r.required_capabilities().collect();
        let set: BTreeSet<&str> = got.iter().copied().collect();
        assert_eq!(
            set.len(),
            got.len(),
            "{what}: each capability once: {got:?}"
        );
        let want: BTreeSet<&str> = needs.iter().flat_map(|n| n.iter().copied()).collect();
        assert_eq!(set, want, "{what}");
        if let Some(c) = r.required_capability() {
            assert!(set.contains(c), "{what}");
        }
        covered.insert(form_of(v));
    }
    let forms = schema_forms();
    let missing: Vec<_> = forms.difference(&covered).collect();
    assert!(missing.is_empty(), "forms with no row: {missing:?}");
    let unknown: Vec<_> = covered.difference(&forms).collect();
    assert!(unknown.is_empty(), "rows for no schema form: {unknown:?}");
    assert_eq!(forms.len(), 114, "the request schema's forms");
}

/// ⟨M07 W10 S2-08⟩ The primitive index (ADR-0013 §9) states the capabilities the session gate
/// checks: each CLI form below lists `operations/1` and exactly what
/// `Request::required_capabilities` names for its request, so `inspect capabilities` lists
/// `schema-discovery/1` (ADR-0006 §2.4) and an event page `events/1`.
#[test]
fn the_primitive_index_lists_what_the_gate_checks() {
    use heimdall_contract::request::Request;
    let cases = [
        (
            "heimdall --json inspect <subject>",
            r#"{"op":"inspect","subject":"destinations"}"#,
        ),
        (
            "heimdall --json inspect capabilities",
            r#"{"op":"inspect","subject":"capabilities"}"#,
        ),
        (
            "heimdall --json operation show|wait",
            r#"{"op":"observe","kind":"operation","operation_id":"op_00112233445566778899aabbccddeeff"}"#,
        ),
        (
            "heimdall --json operation events [",
            r#"{"op":"observe","kind":"events","filter":{},"cursor":"c1","limit":10}"#,
        ),
    ];
    for (cli, json) in cases {
        let form = primitives::GROUPS
            .iter()
            .flat_map(|g| g.forms)
            .find(|f| f.cli.starts_with(cli))
            .unwrap_or_else(|| panic!("{cli}: no form"));
        let r: Request = serde_json::from_str(json).unwrap();
        let mut gate: BTreeSet<&str> = r.required_capabilities().collect();
        gate.insert(capability::OPERATIONS_V1);
        let listed: BTreeSet<&str> = form.capabilities.iter().copied().collect();
        assert_eq!(listed, gate, "{cli}");
    }
}
