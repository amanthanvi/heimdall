//! Heimdall's support bundle (M08 U6a; ADR-0014 §5.1): typed values in, bundle bytes out.
//!
//! **Pure.** No process, network, file or terminal I/O of its own: the only output is the
//! value [`build`] returns, and [`Bundle::write_to`] writes to a writer the caller hands
//! it. No runtime machinery and no workspace edge (the crate-graph step,
//! `tools/validation/crate_graph.py`, allows `heimdall-contract` only). The input types in
//! [`input`] are this crate's own and **provisional**: M08 U6b maps the frozen public views
//! onto them, a view field being free text unless its type says otherwise.
//!
//! **No free text leaves the machine.** Every input value is typed ([`value`]):
//!
//! * a [`Code`] is written when it is code-shaped and clear of the secret checks
//!   ([`screen::screen_code`]); otherwise it is withheld and counted;
//! * a [`Safe`] value (a number, a boolean, a duration, a timestamp, a [`Version`], a
//!   [`BuildId`], a count) is written as it is, the string-valued ones only in their exact
//!   shapes;
//! * an [`Ident`] (user name, host name, alias, label, path, fingerprint, key comment,
//!   Heimdall ID) is screened ([`screen::screen_identifier`]) and then written as a stable
//!   pseudonym (`host-1`, `user-1`, `path-1`, `fp-1`, `comment-1`, `id-1`; same value and
//!   kind, same pseudonym; a counter per kind). The [`InverseMap`] is returned beside the
//!   bundle and is never in its bytes. With [`Options::include_identifiers`] the value
//!   itself is written instead, still only when it passes the identifier checks;
//! * a [`Secret`] or [`FreeText`] holds no text at all, so it is never written: the
//!   bundle notes that the field was withheld and counts it per field in the manifest.
//!   The log is exported as per-code counts with first and last times, never as lines.
//!
//! The structural log redactor (`heimdall_runtime::telemetry::redact`) is not used and is
//! not the guarantee: unsafe text is never collected.
//!
//! **Built once.** [`build`] returns a [`Bundle`] holding the exact bytes, the manifest's
//! SHA-256, a preview that contains those same bytes, and the inverse map. The command
//! shows the preview and, on confirmation, writes [`Bundle::bytes`]. The bytes are one
//! plain-text container of UTF-8 JSON files (format in [`bundle`]), at most
//! [`MAX_BUNDLE_BYTES`]; a larger bundle is an error, never a truncation.

pub mod bundle;
pub mod input;
pub mod screen;
pub mod value;

pub use bundle::{
    Bundle, BundleError, FIELD_NAME_MAX_LEN, FILES, FORMAT, FORMAT_VERSION, INVERSE_MAP_FORMAT,
    InverseMap, MANIFEST_FILE, MAX_BUNDLE_BYTES, Options, PREVIEW_BEGIN, PREVIEW_END, build,
};
pub use input::{
    BuildInfo, BundleInput, Finding, LogRecord, Operation, PlatformInfo, RowCount, Setting,
    SshClient, StatusRow, StoreContents, StoreInput,
};
pub use jiff::Timestamp;
pub use screen::{IdentKind, Withheld};
pub use value::{BuildId, Code, Field, FreeText, Ident, Safe, Secret, Value, Version};
