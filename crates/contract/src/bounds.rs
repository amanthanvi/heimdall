//! ⟨rev7⟩ Write-time item bounds (ADR-0013 §6.4, D20; the contract owner's ruling on ASK-D20
//! and Q13). **Declared, not enforced yet:** every ingress (CLI and IPC catalog writes,
//! `import`, setup adoption, enrollment, runtime-created records) refuses an item over a bound
//! with `USAGE_ERROR` / [`ITEM_TOO_LARGE`](crate::envelope::reason::ITEM_TOO_LARGE) in the
//! change that enforces it (U3, PC11). A store that already exceeds a bound is reported, never
//! truncated; a legacy over-limit row stays readable by ID.
//!
//! The per-field bounds that existed before revision 7 are cited, not repeated: aliases and
//! host names 255 bytes (`heimdall_app::catalog`), labels
//! [`MAX_LABEL_BYTES`](crate::catalog::MAX_LABEL_BYTES), public keys
//! [`MAX_PUBLIC_KEY_BYTES`](crate::catalog::MAX_PUBLIC_KEY_BYTES), a request scope
//! [`MAX_SCOPE_PAIRS`](crate::request::MAX_SCOPE_PAIRS), a relay URL
//! [`RELAY_URL_MAX_BYTES`](crate::route::RELAY_URL_MAX_BYTES), and M06's 16 host keys per
//! runner.

/// Every list item's serialized form, in bytes (64 KiB). Each maximal-record test fills every
/// field of its item at its bound at once and must leave [`ITEM_SPARE_BYTES`].
pub const MAX_ITEM_BYTES: usize = 64 << 10;
/// A profile's destination/account pairs (the ruling of 2026-11-24: 200, so a maximal
/// profile fits [`MAX_ITEM_BYTES`] with [`ITEM_SPARE_BYTES`] to spare).
pub const MAX_PROFILE_PAIRS: usize = 200;
/// An identity's interaction declarations.
pub const MAX_IDENTITY_DECLARATIONS: usize = 64;
/// A destination's approved routes (ruled 2026-11-24: 8; a realistic destination has 1 to 4).
pub const MAX_ROUTES_PER_DESTINATION: usize = 8;
/// A route's relays.
pub const MAX_RELAYS_PER_ROUTE: usize = 8;
/// A destination's relays, over all its routes.
pub const MAX_RELAYS_PER_DESTINATION: usize = 16;
/// A route's recorded consents.
pub const MAX_CONSENTS_PER_ROUTE: usize = 4;
/// An Iroh route's direct addresses (ruled 2026-11-24: 3 covers dual stack with one spare).
pub const MAX_DIRECT_ADDRESSES_PER_ROUTE: usize = 3;
/// A destination's pinned host keys (three key types through a rotation).
pub const MAX_HOST_KEYS_PER_DESTINATION: usize = 8;
/// A pinned host key's OpenSSH public key line, in bytes (an RSA-8192 line is about 1.4 KB).
pub const MAX_HOST_KEY_LINE_BYTES: usize = 1536;
/// The room a maximal item leaves under [`MAX_ITEM_BYTES`] (4 KiB).
pub const ITEM_SPARE_BYTES: usize = 4 << 10;
/// The `remote_pending` entries an environment view lists, beside `remote_pending_count`
/// (ADR-0013 §6.4 RC06; ruling on Q13). The effects themselves are never capped, dropped or
/// acknowledged because of it.
pub const MAX_REMOTE_PENDING_LISTED: usize = 16;
