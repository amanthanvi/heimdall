//! The small documents in the state directory: generation names, the pointer, the
//! per-generation operation record and the staging intent.
//!
//! The record and the intent are **sealed**: one line of JSON, then `sha256:<hex>` of that
//! line. A cut or altered file does not parse, so "a generation without a complete record
//! is not a candidate for anything" (ADR-0014 §3.6) is a property of the bytes.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The longest generation name.
pub const MAX_NAME_LEN: usize = 64;
const POINTER_HEADER: &str = "heimdall-current/1";
pub(crate) const RECORD_SCHEMA: &str = "heimdall-generation-record/1";
const INTENT_SCHEMA: &str = "heimdall-staging-intent/1";

/// A generation directory's name: `g-` and then lower-case letters, digits and hyphens.
/// It cannot hold a path separator or a dot, so a pointer cannot name anything outside
/// the `generations` directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GenerationName(String);

impl GenerationName {
    /// Check and wrap a name.
    pub fn parse(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("g-")?;
        let ok = !rest.is_empty()
            && name.len() <= MAX_NAME_LEN
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        ok.then(|| Self(name.to_owned()))
    }

    /// A new name from 16 random bytes: unique, so never reused.
    pub fn fresh() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self(format!("g-{}", hex(&bytes))))
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GenerationName {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value).ok_or("not a generation name")
    }
}

impl From<GenerationName> for String {
    fn from(value: GenerationName) -> Self {
        value.0
    }
}

/// Which operation created a generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// The first store of a new installation.
    Install,
    /// A copy of a store an earlier build wrote directly in the state directory.
    Adopt,
    /// A sanitized backup.
    Restore,
    /// An empty store with a new identity.
    Reset,
}

/// The record every generation holds, written and synced before the generation can become
/// current.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub(crate) schema: String,
    /// The generation this record belongs to. It must equal its directory's name.
    pub generation: GenerationName,
    /// Which operation created the generation.
    pub operation: Operation,
    /// When.
    pub created_at: Timestamp,
    /// The generation that was current before, if any.
    pub from_generation: Option<GenerationName>,
    /// The SHA-256 of the backup a restore staged, as 64 hex digits.
    pub backup_sha256: Option<String>,
    /// The environment ID of the store in this generation.
    pub environment_id: String,
    /// The restore epoch of this generation.
    pub restore_epoch: u64,
    /// The files the caller staged. Start-up checks that each is there.
    pub files: Vec<String>,
}

impl OperationRecord {
    pub(crate) fn encode(&self) -> Vec<u8> {
        seal(&serde_json::to_string(self).unwrap_or_default())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let record: Self = serde_json::from_str(unseal(bytes)?).ok()?;
        (record.schema == RECORD_SCHEMA).then_some(record)
    }
}

/// Whether a staging intent's operation is still to be finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentState {
    /// The generation it names is being staged. The pointer has not been written.
    Pending,
    /// The temporary pointer is written and synced, and its rename over `CURRENT` is next
    /// or done. Written before the rename, so that a missing pointer can be told apart:
    /// with the temporary pointer still there the rename never happened; without it the
    /// pointer was written and something outside removed it.
    Switching,
    /// The generation it names became current.
    Complete,
}

/// The staging intent: written and synced before a generation directory is created, so
/// that start-up can tell a staged leftover (removed) from an earlier generation (kept)
/// without judging any directory by its name, time or content.
///
/// For [`Operation::Adopt`] this is the adoption-intent file of ADR-0014 §3.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    schema: String,
    /// The operation.
    pub operation: Operation,
    /// The generation being created. The name was free when the intent was written.
    pub generation: GenerationName,
    /// For an adoption, the name of the flat family being adopted.
    pub flat_family: Option<String>,
    /// Pending or complete.
    pub state: IntentState,
}

impl Intent {
    pub(crate) fn new(
        operation: Operation,
        generation: GenerationName,
        flat_family: Option<String>,
    ) -> Self {
        Self {
            schema: INTENT_SCHEMA.to_owned(),
            operation,
            generation,
            flat_family,
            state: IntentState::Pending,
        }
    }

    pub(crate) fn with_state(self, state: IntentState) -> Self {
        Self { state, ..self }
    }

    pub(crate) fn completed(self) -> Self {
        Self {
            state: IntentState::Complete,
            ..self
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        seal(&serde_json::to_string(self).unwrap_or_default())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let intent: Self = serde_json::from_str(unseal(bytes)?).ok()?;
        (intent.schema == INTENT_SCHEMA).then_some(intent)
    }
}

/// The pointer's bytes: a header line and the generation's name.
pub(crate) fn encode_pointer(name: &GenerationName) -> Vec<u8> {
    format!("{POINTER_HEADER}\n{}\n", name.as_str()).into_bytes()
}

/// The generation a pointer names, when its bytes are exactly a pointer.
pub(crate) fn decode_pointer(bytes: &[u8]) -> Option<GenerationName> {
    let text = std::str::from_utf8(bytes).ok()?;
    let name = text
        .strip_prefix(POINTER_HEADER)?
        .strip_prefix('\n')?
        .strip_suffix('\n')?;
    GenerationName::parse(name)
}

/// Whether `text` is 64 lower-case hex digits.
pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn seal(line: &str) -> Vec<u8> {
    format!("{line}\nsha256:{}\n", hex(&Sha256::digest(line.as_bytes()))).into_bytes()
}

fn unseal(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (line, rest) = text.split_once('\n')?;
    let digest = rest.strip_prefix("sha256:")?.strip_suffix('\n')?;
    (!line.is_empty() && digest == hex(&Sha256::digest(line.as_bytes()))).then_some(line)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn name(text: &str) -> GenerationName {
        GenerationName::parse(text).expect("a valid name")
    }

    #[test]
    fn names_cannot_leave_the_generations_directory() {
        for bad in [
            "",
            "g-",
            "g",
            "x-1",
            "g-A",
            "g-a/b",
            "g-a\\b",
            "g-..",
            "g-a.b",
            "g-a b",
            "../g-a",
            "g-a\n",
            &format!("g-{}", "a".repeat(63)),
        ] {
            assert!(GenerationName::parse(bad).is_none(), "{bad:?}");
        }
        assert!(GenerationName::parse("g-0a-1").is_some());
        let fresh = GenerationName::fresh().expect("random bytes");
        assert_eq!(fresh.as_str().len(), 34);
        assert_ne!(fresh, GenerationName::fresh().expect("random bytes"));
    }

    #[test]
    fn pointer_is_exact() {
        let bytes = encode_pointer(&name("g-1"));
        assert_eq!(decode_pointer(&bytes), Some(name("g-1")));
        for bad in [
            &b"heimdall-current/1\ng-1"[..],
            b"heimdall-current/1\ng-1\n\n",
            b"heimdall-current/2\ng-1\n",
            b"g-1\n",
            b"",
            b"heimdall-current/1\n../x\n",
            b"heimdall-current/1\r\ng-1\r\n",
        ] {
            assert_eq!(decode_pointer(bad), None);
        }
    }

    #[test]
    fn a_cut_or_altered_record_does_not_decode() {
        let record = OperationRecord {
            schema: RECORD_SCHEMA.to_owned(),
            generation: name("g-2"),
            operation: Operation::Restore,
            created_at: Timestamp::UNIX_EPOCH,
            from_generation: Some(name("g-1")),
            backup_sha256: Some("0".repeat(64)),
            environment_id: "env-1".into(),
            restore_epoch: 3,
            files: vec!["store.db".into()],
        };
        let bytes = record.encode();
        assert_eq!(OperationRecord::decode(&bytes), Some(record));
        for cut in 0..bytes.len() {
            assert_eq!(OperationRecord::decode(&bytes[..cut]), None, "cut at {cut}");
        }
        let mut altered = bytes.clone();
        let at = altered
            .iter()
            .position(|b| *b == b'3')
            .expect("the epoch digit");
        altered[at] = b'4';
        assert_eq!(OperationRecord::decode(&altered), None);
        // An intent is not a record, and the reverse.
        let intent = Intent::new(Operation::Adopt, name("g-2"), Some("store".into()));
        assert_eq!(OperationRecord::decode(&intent.encode()), None);
        assert_eq!(Intent::decode(&bytes), None);
        assert_eq!(Intent::decode(&intent.encode()), Some(intent));
    }
}
