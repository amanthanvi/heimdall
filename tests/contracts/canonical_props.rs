//! Canonical JSON and request-hash properties (spec section 11.4; ADR-0006 section 7.2).
//!
//! * key order never changes the canonical bytes; array order always does;
//! * `request_hash(ctx, a) == request_hash(ctx, b)` exactly when the canonical bytes
//!   of `a` and `b` are equal (and the context participates in the hash);
//! * canonical output is a parseable fixed point of canonicalization;
//! * floats round-trip through text exactly (`serde_json/float_roundtrip`, wave-1 E3),
//!   so a parsed number canonicalizes back to the text it was printed as.

use proptest::prelude::*;
use serde_json::{Map, Number, Value, json};

use heimdall_contract::canonical::{CanonicalError, RequestHash, canonical_json, request_hash};

use crate::proptest_config;

fn arb_string() -> impl Strategy<Value = String> {
    // Any scalar value, including controls, quotes, backslashes and astral planes.
    prop::collection::vec(any::<char>(), 0..8).prop_map(|cs| cs.into_iter().collect())
}

fn arb_key() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9_]{0,6}",
        arb_string(),
        Just("\u{ff5e}".to_owned()),
        Just("\u{10000}".to_owned()),
    ]
}

fn arb_float() -> impl Strategy<Value = Value> {
    (prop::num::f64::NORMAL | prop::num::f64::ZERO | prop::num::f64::SUBNORMAL)
        .prop_filter_map("finite", |f| Number::from_f64(f).map(Value::Number))
}

fn arb_number(floats: bool) -> BoxedStrategy<Value> {
    let ints = prop_oneof![
        any::<i64>().prop_map(|n| json!(n)),
        any::<u64>().prop_map(|n| json!(n)),
    ];
    if floats {
        prop_oneof![ints, arb_float()].boxed()
    } else {
        ints.boxed()
    }
}

/// Values for the properties that re-parse canonical text. Floats are included:
/// the workspace `serde_json` enables `float_roundtrip` (wave-1 E3), so
/// `parse(print(f)) == f` exactly and re-parsing never perturbs the last digit.
/// Typed request payloads contain no floats (no public schema declares
/// `"type": "number"`), but `extra` and raw `Value` payloads may.
fn arb_value() -> impl Strategy<Value = Value> {
    arb_value_with(true)
}

/// Integer-only values (the shape of every typed request payload).
fn arb_int_value() -> impl Strategy<Value = Value> {
    arb_value_with(false)
}

fn arb_value_with(floats: bool) -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        arb_number(floats),
        arb_string().prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map(arb_key(), inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// Render `v` as JSON text with object members emitted in an order derived from
/// `seed` (not sorted), so parsing it back exercises key-order independence even if
/// a dependency enables an insertion-ordered map.
fn to_text_with_key_order(v: &Value, seed: u64, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| {
                let mut h = seed ^ 0x9e37_79b9_7f4a_7c15;
                for b in k.bytes() {
                    h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
                }
                h
            });
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                to_text_with_key_order(&map[*k], seed.rotate_left(7), out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                to_text_with_key_order(item, seed, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&serde_json::to_string(scalar).unwrap()),
    }
}

fn reparse_with_key_order(v: &Value, seed: u64) -> Value {
    let mut text = String::new();
    to_text_with_key_order(v, seed, &mut text);
    serde_json::from_str(&text).unwrap()
}

/// A copy of `v` where the first array with two unequal elements has them swapped.
fn swap_first_unequal_pair(v: &Value) -> Option<Value> {
    match v {
        Value::Array(items) => {
            for i in 0..items.len() {
                for j in (i + 1)..items.len() {
                    if items[i] != items[j] {
                        let mut out = items.clone();
                        out.swap(i, j);
                        return Some(Value::Array(out));
                    }
                }
            }
            for (i, item) in items.iter().enumerate() {
                if let Some(changed) = swap_first_unequal_pair(item) {
                    let mut out = items.clone();
                    out[i] = changed;
                    return Some(Value::Array(out));
                }
            }
            None
        }
        Value::Object(map) => {
            for (k, child) in map {
                if let Some(changed) = swap_first_unequal_pair(child) {
                    let mut out = map.clone();
                    out.insert(k.clone(), changed);
                    return Some(Value::Object(out));
                }
            }
            None
        }
        _ => None,
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn key_order_does_not_change_canonical_bytes(v in arb_value(), s1 in any::<u64>(), s2 in any::<u64>()) {
        let a = reparse_with_key_order(&v, s1);
        let b = reparse_with_key_order(&v, s2);
        let ca = canonical_json(&a).unwrap();
        prop_assert_eq!(&ca, &canonical_json(&b).unwrap());
        prop_assert_eq!(&ca, &canonical_json(&v).unwrap());
        // And the same through a freshly built map with reversed insertion.
        if let Value::Object(map) = &v {
            let mut rev = Map::new();
            for (k, child) in map.iter().rev() {
                rev.insert(k.clone(), child.clone());
            }
            prop_assert_eq!(&ca, &canonical_json(&Value::Object(rev)).unwrap());
        }
    }

    #[test]
    fn array_order_changes_canonical_bytes_and_hash(v in arb_value()) {
        if let Some(swapped) = swap_first_unequal_pair(&v) {
            prop_assert_ne!(canonical_json(&v).unwrap(), canonical_json(&swapped).unwrap());
            prop_assert_ne!(
                request_hash("ensure", &v).unwrap(),
                request_hash("ensure", &swapped).unwrap()
            );
        }
    }

    #[test]
    fn hash_equality_iff_canonical_byte_equality(
        a in arb_value(),
        other in arb_value(),
        pick in 0u8..3,
        seed in any::<u64>(),
    ) {
        let b = match pick {
            0 => a.clone(),
            1 => reparse_with_key_order(&a, seed),
            _ => other,
        };
        let (ca, cb) = (canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        let (ha, hb) = (request_hash("ensure", &a).unwrap(), request_hash("ensure", &b).unwrap());
        prop_assert_eq!(ha == hb, ca == cb);
        if pick < 2 {
            prop_assert_eq!(ha, hb);
        }
    }

    #[test]
    fn context_participates_in_the_hash(v in arb_value(), c1 in "[a-z_]{0,12}", c2 in "[a-z_]{0,12}") {
        let (h1, h2) = (request_hash(&c1, &v).unwrap(), request_hash(&c2, &v).unwrap());
        prop_assert_eq!(h1 == h2, c1 == c2);
    }

    #[test]
    fn canonical_output_is_valid_json_and_idempotent(v in arb_value()) {
        let bytes = canonical_json(&v).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        prop_assert!(!text.contains(|c: char| c.is_ascii_whitespace() && c != ' '));
        let reparsed: Value = serde_json::from_str(text).unwrap();
        prop_assert_eq!(canonical_json(&reparsed).unwrap(), bytes);
    }

    #[test]
    fn hash_equality_iff_bytes_equality_with_floats(a in arb_value_with(true), b in arb_value_with(true)) {
        // Direct comparison, no text re-parse in between.
        let (ca, cb) = (canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        let (ha, hb) = (request_hash("ensure", &a).unwrap(), request_hash("ensure", &b).unwrap());
        prop_assert_eq!(ha == hb, ca == cb);
        prop_assert_eq!(request_hash("ensure", &a).unwrap(), ha, "hashing is deterministic");
    }

    #[test]
    fn integer_documents_reparse_to_identical_canonical_bytes(v in arb_int_value(), seed in any::<u64>()) {
        let reparsed = reparse_with_key_order(&v, seed);
        prop_assert_eq!(&reparsed, &v);
        prop_assert_eq!(canonical_json(&reparsed).unwrap(), canonical_json(&v).unwrap());
    }

    /// Wave-1 E3: a JSON number that serde_json printed is parsed back to the same
    /// `f64` (bit for bit) and canonicalizes to exactly the same text.
    #[test]
    fn float_roundtrip_parsed_number_canonicalizes_identically(
        f in prop::num::f64::NORMAL | prop::num::f64::SUBNORMAL | prop::num::f64::ZERO
    ) {
        let number = Number::from_f64(f).unwrap();
        let text = serde_json::to_string(&number).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(parsed.as_f64().map(f64::to_bits), Some(f.to_bits()), "{}", text);
        prop_assert_eq!(String::from_utf8(canonical_json(&parsed).unwrap()).unwrap(), text.clone());
        // Inside a document as well, where it is a member of a sorted object.
        let doc_text = format!("{{\"b\":[{text}],\"a\":{text}}}");
        let doc: Value = serde_json::from_str(&doc_text).unwrap();
        prop_assert_eq!(
            String::from_utf8(canonical_json(&doc).unwrap()).unwrap(),
            format!("{{\"a\":{text},\"b\":[{text}]}}")
        );
    }

    /// Any decimal text (not only serde_json's own shortest form) reaches a fixed
    /// point after one canonicalization: canonical text re-parses to the same value
    /// and the same bytes.
    #[test]
    fn decimal_text_reaches_a_canonical_fixed_point(
        neg in any::<bool>(),
        int in "[1-9][0-9]{0,20}|0",
        frac in "[0-9]{1,20}",
        exp in prop::option::of(-330i32..330),
    ) {
        let mut text = format!("{}{int}.{frac}", if neg { "-" } else { "" });
        if let Some(e) = exp {
            text.push_str(&format!("e{e}"));
        }
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            // Out of f64 range: serde_json refuses it, nothing to canonicalize.
            return Ok(());
        };
        let once = canonical_json(&v).unwrap();
        let reparsed: Value = serde_json::from_slice(&once).unwrap();
        prop_assert_eq!(&reparsed, &v);
        prop_assert_eq!(canonical_json(&reparsed).unwrap(), once);
    }

    #[test]
    fn hash_hex_round_trips(bytes in any::<[u8; 32]>()) {
        let h = RequestHash(bytes);
        prop_assert_eq!(RequestHash::from_hex(&h.to_hex()).unwrap(), h);
        prop_assert_eq!(RequestHash::from_hex(&h.to_hex().to_uppercase()).unwrap(), h);
        prop_assert_eq!(serde_json::from_value::<RequestHash>(serde_json::to_value(h).unwrap()).unwrap(), h);
    }

    #[test]
    fn hash_parser_is_bounded_and_total(s in prop_oneof![any::<String>(), "[0-9a-fA-F]{0,80}", "[0-9a-f]{62}\\PC{0,3}"]) {
        let parsed = RequestHash::from_hex(&s);
        let well_formed = s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
        prop_assert_eq!(parsed.is_ok(), well_formed);
        if let Err(e) = parsed {
            prop_assert_eq!(e, CanonicalError::BadHash);
        }
    }
}

#[test]
fn object_keys_sort_bytewise_not_by_utf16_or_locale() {
    // U+FF5E (EF BD 9E) < U+10000 (F0 90 80 80) bytewise; UTF-16 order is reversed.
    let v: Value =
        serde_json::from_str("{\"\u{10000}\":1,\"\u{ff5e}\":2,\"b\":3,\"B\":4,\"10\":5,\"9\":6}")
            .unwrap();
    let text = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
    assert_eq!(
        text,
        "{\"10\":5,\"9\":6,\"B\":4,\"b\":3,\"\u{ff5e}\":2,\"\u{10000}\":1}"
    );
}

#[test]
fn strings_use_deterministic_escapes() {
    let v = json!({"k": "a\"b\\c\n\u{1}\u{7f}\u{e9}\u{10000}"});
    let text = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
    assert_eq!(
        text,
        "{\"k\":\"a\\\"b\\\\c\\n\\u0001\u{7f}\u{e9}\u{10000}\"}"
    );
}

#[test]
fn numbers_keep_their_serde_json_form() {
    let v: Value =
        serde_json::from_str(r#"{"a":1,"b":1.0,"c":-0.0,"d":18446744073709551615,"e":1e3}"#)
            .unwrap();
    let text = String::from_utf8(canonical_json(&v).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"a":1,"b":1.0,"c":-0.0,"d":18446744073709551615,"e":1000.0}"#
    );
    // 1 and 1.0 are different documents and so hash differently.
    assert_ne!(
        request_hash("t", &json!(1)).unwrap(),
        request_hash("t", &json!(1.0)).unwrap()
    );
    assert!(
        Number::from_f64(f64::NAN).is_none(),
        "NaN cannot enter a Value"
    );
}

#[test]
fn floats_hash_consistently_and_round_trip_text() {
    // Parsing the same text is deterministic, so two parties that parse the same
    // document agree on its canonical bytes and hash.
    let text = r#"{"x":3.164269124987631e-115,"y":[1.5,2.25e300]}"#;
    let a: Value = serde_json::from_str(text).unwrap();
    let b: Value = serde_json::from_str(text).unwrap();
    assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
    assert_eq!(
        request_hash("t", &a).unwrap(),
        request_hash("t", &b).unwrap()
    );
    // With `float_roundtrip` (wave-1 E3) the canonical text re-parses to the same
    // values: a second party hashing the canonical form agrees with the first.
    let canonical = canonical_json(&a).unwrap();
    let c: Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(c, a);
    assert_eq!(
        request_hash("t", &c).unwrap(),
        request_hash("t", &a).unwrap()
    );
    // A value whose shortest decimal needs all 17 significant digits.
    let tricky = 0.1_f64 + 0.2_f64;
    let printed = serde_json::to_string(&tricky).unwrap();
    assert_eq!(printed, "0.30000000000000004");
    assert_eq!(
        serde_json::from_str::<f64>(&printed).unwrap().to_bits(),
        tricky.to_bits()
    );
    // Non-finite values cannot be constructed, so canonicalization cannot be asked
    // to hash them; the error variant exists for hand-built maps only.
    assert!(Number::from_f64(f64::INFINITY).is_none());
}

#[test]
fn golden_request_hash_vectors() {
    // Vectors computed independently with
    //   printf 'heimdall-request-hash/1\0<ctx>\0<canonical>' | shasum -a 256
    let v: Value = serde_json::from_str(r#"{"b":1,"a":{"d":[1,2],"c":"x"}}"#).unwrap();
    assert_eq!(
        request_hash("ensure", &v).unwrap().to_hex(),
        "fecc2b1661e97588bf97202e3ee10809bd5ee3c33899457411f90f9ea480ecb5"
    );
    assert_eq!(
        request_hash("", &Value::Null).unwrap().to_hex(),
        "dd3ddd5ce4837479e5da27fafd698bf4ac8a9bda72731c838e27e60bf90ff547"
    );
}
