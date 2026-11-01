//! Identifier parser bounds (A29 "parsers bounded"; ADR-0006 section 7.1; spec section 11.2).
//!
//! Every ID type accepts at most `MAX_ID_LEN` bytes of `[A-Za-z0-9._:-]`, rejects
//! everything else without panicking, and the runtime-generated kinds additionally
//! require their wire prefix.

use proptest::prelude::*;

use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, DeviceId, EnvironmentId, EventId, GrantId, IdError,
    MAX_ID_LEN, OperationId, PolicyId, ProfileId, RequestId, ResourceId, WorkId, WorkspaceId,
};

use crate::proptest_config;

type Parser = fn(&str) -> Result<(), IdError>;

fn p<T>(r: Result<T, IdError>) -> Result<(), IdError> {
    r.map(|_| ())
}

/// (prefix, parser) for runtime-generated kinds.
fn prefixed() -> Vec<(&'static str, Parser)> {
    vec![
        ("op", |s| p(OperationId::parse(s))),
        ("grant", |s| p(GrantId::parse(s))),
        ("binding", |s| p(BindingId::parse(s))),
        ("env", |s| p(EnvironmentId::parse(s))),
        ("dev", |s| p(DeviceId::parse(s))),
        ("ws", |s| p(WorkspaceId::parse(s))),
        ("res", |s| p(ResourceId::parse(s))),
        ("evt", |s| p(EventId::parse(s))),
    ]
}

fn tokens() -> Vec<Parser> {
    vec![
        |s| p(RequestId::parse(s)),
        |s| p(WorkId::parse(s)),
        |s| p(ProfileId::parse(s)),
        |s| p(DestinationId::parse(s)),
        |s| p(PolicyId::parse(s)),
        |s| p(AccountName::parse(s)),
    ]
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

#[test]
fn length_bound_is_exactly_128_bytes() {
    for parse in tokens() {
        assert_eq!(parse(""), Err(IdError::Empty));
        assert_eq!(parse(&"a".repeat(MAX_ID_LEN)), Ok(()));
        assert_eq!(parse(&"a".repeat(MAX_ID_LEN + 1)), Err(IdError::TooLong));
        assert_eq!(parse(&"a".repeat(1 << 20)), Err(IdError::TooLong));
    }
    for (prefix, parse) in prefixed() {
        let at_limit = format!("{prefix}_{}", "a".repeat(MAX_ID_LEN - prefix.len() - 1));
        assert_eq!(at_limit.len(), MAX_ID_LEN);
        assert_eq!(parse(&at_limit), Ok(()), "{prefix}");
        assert_eq!(
            parse(&format!("{at_limit}a")),
            Err(IdError::TooLong),
            "{prefix}"
        );
        assert_eq!(parse(""), Err(IdError::Empty));
    }
}

#[test]
fn hostile_inputs_are_rejected_without_panic() {
    let hostile = [
        "has space",
        "tab\there",
        "new\nline",
        "nul\0byte",
        "esc\u{1b}[31m",
        "del\u{7f}",
        "slash/path",
        "back\\slash",
        "../../etc",
        "quote\"",
        "semi;colon",
        "dollar$",
        "percent%20",
        "caf\u{e9}",
        "\u{ff11}\u{ff12}",
        "emoji\u{1f600}",
        "\u{202e}rtl",
        "zero\u{200b}width",
        "\u{feff}bom",
    ];
    for s in hostile {
        for parse in tokens() {
            assert_eq!(parse(s), Err(IdError::ForbiddenChar), "{s:?}");
        }
        for (prefix, parse) in prefixed() {
            assert_eq!(
                parse(&format!("{prefix}_{s}")),
                Err(IdError::ForbiddenChar),
                "{prefix} {s:?}"
            );
        }
    }
}

#[test]
fn prefixed_ids_require_their_own_prefix() {
    for (prefix, parse) in prefixed() {
        assert_eq!(parse(&format!("{prefix}_abc")), Ok(()));
        for bad in [
            prefix.to_owned(),
            format!("{prefix}_"),
            format!("{prefix}abc"),
            format!("{prefix}-abc"),
            format!("x{prefix}_abc"),
            format!("{}_abc", prefix.to_uppercase()),
            "_abc".to_owned(),
        ] {
            assert_eq!(
                parse(&bad),
                Err(IdError::WrongPrefix { expected: prefix }),
                "{bad:?}"
            );
        }
    }
    // A syntactically valid ID of another kind is not accepted.
    assert!(GrantId::parse("op_00112233445566778899aabbccddeeff").is_err());
    assert!(BindingId::parse("env_00112233445566778899aabbccddeeff").is_err());
}

#[test]
fn generated_ids_use_the_documented_wire_form() {
    let id = OperationId::from_random_bytes([0x0f; 16]);
    assert_eq!(id.as_str(), "op_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
    let evt = EventId::from_random_bytes([0xff; 16]);
    assert_eq!(evt.as_str(), "evt_ffffffffffffffffffffffffffffffff");
    assert_eq!(OperationId::parse(id.as_str()).unwrap(), id);
    assert_eq!(id.to_string(), id.as_str());
}

#[test]
fn serde_enforces_the_same_bounds() {
    let long = format!("\"{}\"", "a".repeat(MAX_ID_LEN + 1));
    assert!(serde_json::from_str::<RequestId>(&long).is_err());
    assert!(serde_json::from_str::<RequestId>("\"ok-1\"").is_ok());
    assert!(serde_json::from_str::<RequestId>("42").is_err());
    assert!(serde_json::from_str::<RequestId>("null").is_err());
    assert!(serde_json::from_str::<RequestId>("[\"a\"]").is_err());
    assert!(serde_json::from_str::<RequestId>("\"bad id\"").is_err());
    assert!(serde_json::from_str::<OperationId>("\"grant_abc\"").is_err());
    assert!(serde_json::from_str::<OperationId>("\"op_abc\"").is_ok());
    // Round trip through the wire string.
    let id: WorkId = serde_json::from_str("\"work-1\"").unwrap();
    assert_eq!(serde_json::to_string(&id).unwrap(), "\"work-1\"");
}

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn token_parsers_match_the_bound_oracle(
        s in prop_oneof![
            "[A-Za-z0-9._:-]{0,160}",
            any::<String>(),
            "[A-Za-z0-9._:\\- /\\\\\\x00\\x1b\\xe9]{0,40}",
        ]
    ) {
        for parse in tokens() {
            let got = parse(&s);
            if token_ok(&s) {
                prop_assert_eq!(got, Ok(()));
            } else if s.is_empty() {
                prop_assert_eq!(got, Err(IdError::Empty));
            } else if s.len() > MAX_ID_LEN {
                prop_assert_eq!(got, Err(IdError::TooLong));
            } else {
                prop_assert_eq!(got, Err(IdError::ForbiddenChar));
            }
        }
    }

    #[test]
    fn prefixed_parsers_accept_only_prefixed_tokens(
        rest in "[A-Za-z0-9._:-]{0,150}",
        which in 0usize..8,
        mutate in any::<bool>(),
    ) {
        let kinds = prefixed();
        let (prefix, parse) = kinds[which];
        let s = if mutate { rest.clone() } else { format!("{prefix}_{rest}") };
        let got = parse(&s);
        let expect_ok = token_ok(&s)
            && s.split_once('_').is_some_and(|(pfx, tail)| pfx == prefix && !tail.is_empty());
        prop_assert_eq!(got.is_ok(), expect_ok, "{:?}", s);
    }

    #[test]
    fn random_bytes_always_make_parseable_ids(bytes in any::<[u8; 16]>()) {
        let id = GrantId::from_random_bytes(bytes);
        prop_assert_eq!(id.as_str().len(), "grant_".len() + 32);
        prop_assert!(id.as_str()["grant_".len()..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        prop_assert_eq!(GrantId::parse(id.as_str()).unwrap(), id);
    }
}
