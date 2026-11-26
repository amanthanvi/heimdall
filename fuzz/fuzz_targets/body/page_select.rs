//! Boundary 15 (ADR-0014 §2.1), M07's page tokens and selectors, as far as this tree has
//! them: the outer form of a page token (`heimdall_contract::page::PageToken::parse` and its
//! wire decoding) and the `page` and `select` request forms, decoded as the runtime decodes a
//! frame (`heimdall_ipc::session::parse_frame`), with `Select::is_well_formed`. The token's
//! integrity check (HMAC-SHA256 over the scoped tuple) and the server's selector resolution
//! are M07 U3's and are not in this tree: `pages/1` is declared and not offered
//! (`crates/contract/src/page.rs`), so this target covers only what a client can send today.
//!
//! The invariants: a token is accepted exactly when its wire string is, and only when it is
//! 1 to 256 base64url characters; a decoded page request's token is one `parse` accepts.
//!
//! Shared by the fuzz target `page_select` and the seed test
//! `tests/adversarial/m08_fuzz_seeds.rs`.

use heimdall_contract::page::{MAX_PAGE_TOKEN_LEN, PageRequest, PageToken, Select};
use heimdall_ipc::session::parse_frame;

/// What the input decoded as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decoded {
    /// The text is a well-formed token.
    pub token: bool,
    /// It decodes as a `page` request.
    pub page: bool,
    /// It decodes as a selector, and whether that selector is well formed.
    pub select: Option<bool>,
}

/// Decode `data` every way (module docs); panics (a finding) when an invariant breaks.
pub fn run(data: &[u8]) -> Decoded {
    let mut out = Decoded::default();
    if let Ok(text) = std::str::from_utf8(data) {
        let parsed = PageToken::parse(text);
        if let Ok(t) = &parsed {
            let s = t.as_str();
            assert!(
                !s.is_empty()
                    && s.len() <= MAX_PAGE_TOKEN_LEN
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "a token accepted outside its outer form"
            );
        }
        if let Ok(wire) = serde_json::to_string(text) {
            assert_eq!(
                serde_json::from_str::<PageToken>(&wire).is_ok(),
                parsed.is_ok(),
                "the wire form and the parser disagree"
            );
        }
        out.token = parsed.is_ok();
    }
    if let Ok(page) = parse_frame::<PageRequest>(data) {
        if let Some(t) = &page.token {
            assert!(
                PageToken::parse(t.as_str()).is_ok(),
                "a decoded token parse refuses"
            );
        }
        out.page = true;
    }
    out.select = parse_frame::<Select>(data).ok().map(|s| s.is_well_formed());
    out
}
