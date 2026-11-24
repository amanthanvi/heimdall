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
/// code is in the code table or is the declared `REQUEST_STALE`; every row's next action is
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
        if c == lifecycle::REQUEST_STALE {
            assert_eq!(next, lifecycle::REQUEST_STALE_NEXT, "{r}");
        } else {
            let code = Code::parse(c);
            assert!(Code::all().contains(&code), "{r}: {c}");
            let named = reasons::NEXT_ACTIONS
                .iter()
                .find(|(nr, nc, _)| *nr == r && *nc == c)
                .map(|(_, _, a)| *a);
            assert_eq!(next, named.unwrap_or(code.default_next_action()), "{r} {c}");
        }
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
    for (r, c) in reason::REV7_DECLARED_CODE {
        assert!(has(r, c), "{r}");
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
    assert_eq!(
        table["declared_codes"],
        serde_json::json!(["REQUEST_STALE"])
    );
    // The ruling on ASK-CODE: `REQUEST_STALE` is declared, not in the code table.
    assert_eq!(
        Code::parse(lifecycle::REQUEST_STALE),
        Code::Unknown("REQUEST_STALE".into())
    );
    assert_eq!(Code::all().len(), 30);
}

/// The revision-7 capabilities are declared and offered to no role.
#[test]
fn revision_7_capabilities_are_declared_not_offered() {
    use heimdall_contract::remote::Role;
    assert_eq!(
        capability::REVISION_7_DECLARED,
        [capability::PAGES_V1, capability::REQUEST_EPOCH_V1]
    );
    for c in capability::REVISION_7_DECLARED {
        assert!(!capability::ALL.contains(&c), "{c}");
        for role in [Role::Owner, Role::Requester, Role::Viewer] {
            assert!(!capability::for_role(role).contains(&c), "{c} {role:?}");
        }
    }
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
/// preference with its connection policy's longest wording, a route-health report of 64
/// attempts, the longest host-pin setting)
/// and its approved routes (8 routes, 8 relays on each of two of them for the destination's
/// 16, every relay URL at 2,048 bytes, 4 consents and 3 direct addresses per route, 8 host-key
/// pins of 1,536 bytes) fits the 64 KiB item bound with 4 KiB to spare (ruled 2026-11-24).
#[test]
fn maximal_destination_item_fits_with_room_to_spare() {
    use heimdall_contract::bounds::{
        ITEM_SPARE_BYTES, MAX_ITEM_BYTES, MAX_RELAYS_PER_DESTINATION, MAX_RELAYS_PER_ROUTE,
        MAX_ROUTES_PER_DESTINATION,
    };
    use heimdall_contract::bounds::{
        MAX_CONSENTS_PER_ROUTE as CONSENTS, MAX_DIRECT_ADDRESSES_PER_ROUTE as DIRECT_ADDRESSES,
        MAX_HOST_KEY_LINE_BYTES as HOST_KEY_LINE, MAX_HOST_KEYS_PER_DESTINATION as HOST_KEYS,
    };
    use heimdall_contract::ids::MAX_ID_LEN;
    use heimdall_contract::route::{RELAY_URL_MAX_BYTES, ROUTE_HEALTH_ATTEMPTS_MAX};
    let hex = |i: usize, n: usize| format!("{i:0n$x}");
    let route_id = |i: usize| format!("route_{}", hex(i, 32));
    let relay = |i: usize| {
        let head = format!("https://relay{i:02}.example.invalid/");
        format!("{head}{}", "p".repeat(RELAY_URL_MAX_BYTES - head.len()))
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
                    "external_roost": false,
                    "direct_addresses": (0..DIRECT_ADDRESSES)
                        .map(|a| format!("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:{a:04x}]:65535"))
                        .collect::<Vec<_>>(),
                },
                "exposure": {
                    "bind": {"kind": "interface", "address": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
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
    let attempts: Vec<serde_json::Value> = (0..ROUTE_HEALTH_ATTEMPTS_MAX)
        .map(|a| {
            serde_json::json!({
                "route": route_id(a % MAX_ROUTES_PER_DESTINATION),
                "failure": "identification_timeout",
                "duration_ms": 600_000,
            })
        })
        .collect();
    let view: heimdall_contract::views::catalog::DestinationView =
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
                    "existing": "strict",
                    "multiplexing": "owned_masters",
                    "wording": "w".repeat(256),
                },
            },
            "route_health": {
                "result": {
                    "kind": "failed_over",
                    "destination": filled(0, MAX_ID_LEN),
                    "account": filled(1, MAX_ID_LEN),
                    "attempts": attempts,
                    "final_route": route_id(15),
                },
                "reported_at": "2026-11-24T00:00:00.123456789Z",
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
    let n = item_bytes(&view) + item_bytes(&routes);
    assert!(
        n + ITEM_SPARE_BYTES <= MAX_ITEM_BYTES,
        "a maximal destination with its routes is {n} bytes (view {}, routes {})",
        item_bytes(&view),
        item_bytes(&routes)
    );
}
