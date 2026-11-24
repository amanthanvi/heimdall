//! ⟨rev7⟩ Whole reads, `select` and pages (ADR-0013 §6.1–§6.2, D2, D21). **Declared, not
//! served:** `pages/1` ([`crate::ipc::capability::PAGES_V1`]) is in
//! [`crate::ipc::capability::REVISION_7_DECLARED`] and no runtime offers it, so no session
//! can send these forms. The `inspect` request gains them (and the server its keyset reads,
//! HMAC tokens and role sets) in one later change (U3, ADR-0013 §1.3).
//!
//! * **A whole read** (neither form) answers the complete list, or `USAGE_ERROR` /
//!   `response_too_large` sized before anything is sent.
//! * **[`Select`]** names 1–[`SELECT_MAX`] items and answers [`Selection`]: exactly those
//!   items, plus `missing` for the ones that do not exist or are not visible.
//! * **[`PageRequest`]** answers [`Page`]: `{items, more, next_page_token?}`;
//!   `next_page_token` is present exactly when `more` is true. A traversal ends at the first
//!   page with `more: false`, which may be empty. Content is always complete: no stubs.
//! * `select` together with `page`, and an empty selector, are `USAGE_ERROR` /
//!   `selector_invalid`; a tampered or rescoped token is `USAGE_ERROR` / `page_token_invalid`.

use serde::{Deserialize, Serialize};

/// The default page size.
pub const PAGE_LIMIT_DEFAULT: u32 = 200;
/// The largest page size.
pub const PAGE_LIMIT_MAX: u32 = 1000;
/// A page's serialized budget (768 KiB), below one control frame.
pub const PAGE_BUDGET_BYTES: usize = 768 << 10;
/// The most entries one `select` names.
pub const SELECT_MAX: usize = 64;
/// The longest page token on the wire (ADR-0013 §2.1 "Opaque tokens").
pub const MAX_PAGE_TOKEN_LEN: usize = 256;

/// An opaque page token: base64url, at most [`MAX_PAGE_TOKEN_LEN`] bytes, never parsed by a
/// client. The runtime integrity-protects it (HMAC-SHA256 over a version, the scoped tuple
/// and the position) and re-applies the reader's visibility on every page: a token carries
/// a position, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct PageToken(String);

impl PageToken {
    /// Validate a token's outer form: non-empty, bounded, base64url without padding.
    ///
    /// # Errors
    ///
    /// When the token is empty, longer than [`MAX_PAGE_TOKEN_LEN`], or holds a byte outside
    /// the base64url alphabet.
    pub fn parse(s: &str) -> Result<Self, PageTokenError> {
        if s.is_empty() || s.len() > MAX_PAGE_TOKEN_LEN {
            return Err(PageTokenError);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(PageTokenError);
        }
        Ok(Self(s.to_owned()))
    }

    /// The token's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PageToken {
    type Error = PageTokenError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<PageToken> for String {
    fn from(t: PageToken) -> Self {
        t.0
    }
}

/// A page token's outer form is invalid (`USAGE_ERROR` / `page_token_invalid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a page token is 1 to 256 base64url characters")]
pub struct PageTokenError;

/// `page: {limit?, token?}`: one page of a list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PageRequest {
    /// Items per page: default [`PAGE_LIMIT_DEFAULT`], at most [`PAGE_LIMIT_MAX`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// The previous page's `next_page_token`; absent for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<PageToken>,
}

/// `select: {ids?, aliases?}`: 1 to [`SELECT_MAX`] entries in all, subject-scoped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Select {
    /// Item IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<String>,
    /// Aliases, for the subjects that have them (destinations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
}

impl Select {
    /// Whether the selector holds 1 to [`SELECT_MAX`] entries (otherwise
    /// `selector_invalid`).
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        let n = self.ids.len().saturating_add(self.aliases.len());
        (1..=SELECT_MAX).contains(&n)
    }
}

/// The answer to a `page` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Page<T> {
    /// This page's items, each complete.
    pub items: Vec<T>,
    /// Whether more remain after this page. `false` ends the traversal.
    pub more: bool,
    /// The token for the next page: present exactly when `more` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<PageToken>,
}

impl<T> Page<T> {
    /// Whether `next_page_token` is present exactly when `more` is true.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.more == self.next_page_token.is_some()
    }
}

/// The answer to a `select` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Selection<T> {
    /// The selected items that exist and are visible, each complete.
    pub items: Vec<T>,
    /// The selector entries that matched nothing visible, as given.
    #[serde(default)]
    pub missing: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_bounded_base64url() {
        assert!(PageToken::parse("AbC-_9").is_ok());
        assert!(PageToken::parse("").is_err());
        assert!(PageToken::parse("a=").is_err());
        assert!(PageToken::parse("a+b").is_err());
        assert!(PageToken::parse(&"a".repeat(MAX_PAGE_TOKEN_LEN)).is_ok());
        assert!(PageToken::parse(&"a".repeat(MAX_PAGE_TOKEN_LEN + 1)).is_err());
        let bad: Result<PageToken, _> = serde_json::from_str("\"a/b\"");
        assert!(bad.is_err());
    }

    #[test]
    fn page_and_selector_shapes() {
        let last: Page<u8> = serde_json::from_str(r#"{"items":[],"more":false}"#).unwrap();
        assert!(last.is_well_formed());
        let bad: Page<u8> = serde_json::from_str(r#"{"items":[1],"more":true}"#).unwrap();
        assert!(!bad.is_well_formed());
        assert!(!Select::default().is_well_formed());
        let one = Select {
            ids: vec!["lab".into()],
            aliases: Vec::new(),
        };
        assert!(one.is_well_formed());
        assert_eq!(serde_json::to_string(&one).unwrap(), r#"{"ids":["lab"]}"#);
        let too_many = Select {
            ids: (0..=SELECT_MAX).map(|i| i.to_string()).collect(),
            aliases: Vec::new(),
        };
        assert!(!too_many.is_well_formed());
    }
}
