//! Heimdall deterministic domain layer (plan §4.1 "Domain/contracts"; spec §13.1
//! "deterministic domain layer independent of UI, transport, and provider SDKs").
//!
//! Everything here is a pure function or plain data over an input snapshot. The
//! crate performs no I/O, holds no clock of its own (time arrives through
//! [`time::Clock`] or as values), and never imports terminal, transport, storage or
//! provider code. Property and model tests (plan §6.3) drive these functions
//! directly; the runtime drives the same functions with real inputs.
//!
//! Must not own: provider SDK calls, UI rendering, hidden I/O, retry loops.

pub mod authority;
pub mod binding;
pub mod decision;
pub mod environment;
pub mod evidence;
pub mod grant;
pub mod idempotency;
pub mod issuance;
pub mod lifecycle;
pub mod operation;
pub mod policy;
pub mod principal;
pub mod profile;
pub mod resource;
pub mod revocation;
pub mod scope;
pub mod time;

pub use heimdall_contract as contract;
pub use heimdall_contract::Timestamp;
pub use heimdall_contract::ids;
