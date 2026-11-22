//! The typed values a bundle is built from (ADR-0014 §5.1 "No free text leaves the
//! machine").
//!
//! Every value a caller hands [`crate::build`] is one of five types, and no input field
//! is a bare `String`:
//!
//! | Type | Written as |
//! |---|---|
//! | [`Code`] | itself, when it passes [`crate::screen::screen_code`] |
//! | [`Safe`] | itself: a number, a boolean, a duration, a timestamp, a version, a build identifier, a count |
//! | [`Ident`] | a pseudonym `<kind>-<n>` (or, with identifier inclusion, the value) when it passes [`crate::screen::screen_identifier`] |
//! | [`Secret`] | never: it holds no text |
//! | [`FreeText`] | never: it holds no text |
//!
//! The string-holding types keep their text private; only the bundle builder reads it,
//! after its check. Their `Debug` output shows a code, version or build identifier only
//! when it passes its check, and an identifier only as its kind and length, so a stray
//! `{:?}` cannot print what the bundle would withhold.

use std::fmt;
use std::time::Duration;

use crate::screen::{IdentKind, screen_build_id, screen_code, screen_version};

/// An enumerated code: a result code, a reason, a finding ID, a state, a capability or
/// claim key, a setup item kind, a configuration key, a table name. Written only when
/// code-shaped and clear of the secret checks; otherwise withheld and counted.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    /// A code. The check happens when the bundle is built.
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if screen_code(&self.0).is_ok() {
            write!(f, "Code({:?})", self.0)
        } else {
            f.write_str("Code(<withheld>)")
        }
    }
}

/// A schema, protocol, product or platform version (`1.0.0-rc.1`, `9.9p1`, `15.1`): a
/// typed safe value with the shape of [`crate::screen::screen_version`].
#[derive(Clone, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    /// A version. The check happens when the bundle is built.
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if screen_version(&self.0).is_ok() {
            write!(f, "Version({:?})", self.0)
        } else {
            f.write_str("Version(<withheld>)")
        }
    }
}

/// A build identifier (a commit or build digest): 7 to 64 lowercase hex digits.
#[derive(Clone, PartialEq, Eq)]
pub struct BuildId(String);

impl BuildId {
    /// A build identifier. The check happens when the bundle is built.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if screen_build_id(&self.0).is_ok() {
            write!(f, "BuildId({:?})", self.0)
        } else {
            f.write_str("BuildId(<withheld>)")
        }
    }
}

/// A typed safe value, written as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Safe {
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Integer(i64),
    /// A count.
    Count(u64),
    /// A duration, written as whole milliseconds (saturating at `u64::MAX`).
    Duration(Duration),
    /// A timestamp, written as RFC 3339 UTC in whole seconds (`2026-11-22T10:00:00Z`). A
    /// time before the Unix epoch is withheld as malformed.
    Timestamp(jiff::Timestamp),
    /// A version.
    Version(Version),
    /// A build identifier.
    BuildId(BuildId),
}

/// A public identifier (spec §13.6): a user name, host name, alias, label, path,
/// fingerprint, key comment or Heimdall ID. Written as a pseudonym, or with identifier
/// inclusion as the value, and only when it passes the identifier checks.
#[derive(Clone, PartialEq, Eq)]
pub struct Ident {
    kind: IdentKind,
    value: String,
}

impl Ident {
    /// An identifier of `kind`.
    pub fn new(kind: IdentKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    /// A user name.
    pub fn user(value: impl Into<String>) -> Self {
        Self::new(IdentKind::User, value)
    }

    /// A host name or address.
    pub fn host(value: impl Into<String>) -> Self {
        Self::new(IdentKind::Host, value)
    }

    /// An SSH alias.
    pub fn alias(value: impl Into<String>) -> Self {
        Self::new(IdentKind::Alias, value)
    }

    /// A label, profile, destination or policy name.
    pub fn label(value: impl Into<String>) -> Self {
        Self::new(IdentKind::Label, value)
    }

    /// A filesystem path.
    pub fn path(value: impl Into<String>) -> Self {
        Self::new(IdentKind::Path, value)
    }

    /// A key or host-key fingerprint.
    pub fn fingerprint(value: impl Into<String>) -> Self {
        Self::new(IdentKind::Fingerprint, value)
    }

    /// A key comment.
    pub fn key_comment(value: impl Into<String>) -> Self {
        Self::new(IdentKind::KeyComment, value)
    }

    /// One of Heimdall's own IDs.
    pub fn heimdall_id(value: impl Into<String>) -> Self {
        Self::new(IdentKind::HeimdallId, value)
    }

    /// The kind.
    #[must_use]
    pub fn kind(&self) -> IdentKind {
        self.kind
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ident")
            .field("kind", &self.kind)
            .field("bytes", &self.value.len())
            .finish()
    }
}

/// A value typed as secret or opaque: a passphrase, a token, a private or public key,
/// a certificate, an environment value. It holds no text: [`Secret::new`] drops what it
/// is given, so nothing after it can export the value. Identifier inclusion never
/// applies to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secret {
    _private: (),
}

impl Secret {
    /// Mark a secret field as present. The value is not kept.
    pub fn new(_value: impl AsRef<str>) -> Self {
        Self { _private: () }
    }
}

/// Free text: a message, a log line, a diagnostic's detail, an operating-system or `ssh`
/// error string, a command line, file content. It holds no text: [`FreeText::new`] drops
/// what it is given. The bundle records only that the field was present and withheld.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeText {
    _private: (),
}

impl FreeText {
    /// Mark a free-text field as present. The text is not kept.
    pub fn new(_text: impl AsRef<str>) -> Self {
        Self { _private: () }
    }
}

/// One typed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An enumerated code.
    Code(Code),
    /// A typed safe value.
    Safe(Safe),
    /// A public identifier.
    Ident(Ident),
    /// A secret (never written).
    Secret(Secret),
    /// Free text (never written).
    Text(FreeText),
}

impl From<Code> for Value {
    fn from(v: Code) -> Self {
        Value::Code(v)
    }
}

impl From<Safe> for Value {
    fn from(v: Safe) -> Self {
        Value::Safe(v)
    }
}

impl From<Ident> for Value {
    fn from(v: Ident) -> Self {
        Value::Ident(v)
    }
}

impl From<Secret> for Value {
    fn from(v: Secret) -> Self {
        Value::Secret(v)
    }
}

impl From<FreeText> for Value {
    fn from(v: FreeText) -> Self {
        Value::Text(v)
    }
}

macro_rules! safe_from {
    ($($t:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$t> for Safe {
                fn from(v: $t) -> Self {
                    Safe::$variant(v)
                }
            }

            impl From<$t> for Value {
                fn from(v: $t) -> Self {
                    Value::Safe(Safe::$variant(v))
                }
            }
        )*
    };
}

safe_from!(
    bool => Bool,
    i64 => Integer,
    u64 => Count,
    Duration => Duration,
    jiff::Timestamp => Timestamp,
    Version => Version,
    BuildId => BuildId,
);

/// A named, typed field of a record (a finding, a status row, an operation). The name is
/// a `&'static str` so it comes from the caller's code, never from data; it must also be
/// code-shaped, or the field is withheld as malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field name.
    pub name: &'static str,
    /// The value.
    pub value: Value,
}

impl Field {
    /// A field.
    pub fn new(name: &'static str, value: impl Into<Value>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_what_the_bundle_would_withhold() {
        let marker = format!("{}_{}_{}", "HEIMDALL", "CANARY", std::process::id());
        let shown = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            Code::new(marker.clone()),
            Version::new(marker.clone()),
            BuildId::new(marker.clone()),
            Ident::host(marker.clone()),
            Value::from(Secret::new(&marker)),
            Value::from(FreeText::new(&marker)),
        );
        assert!(!shown.contains(&marker));
        assert!(!shown.to_ascii_lowercase().contains("canary"));
        assert_eq!(
            format!("{:?}", Code::new("store_corrupt")),
            "Code(\"store_corrupt\")"
        );
    }
}
