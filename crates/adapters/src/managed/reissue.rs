//! ⟨M03⟩ The re-issue rule (ADR-0005 §3.7 "Recovery rule" rules 1–5; ADR-0008 D6
//! item 4). ⟨wave 4, round 2⟩ ADR-0008 §17.21 item 6: the one implementation lives in
//! [`heimdall_domain::reissue`] (both `app` and `adapters` call it); this module
//! re-exports it unchanged for U6's callers.

pub use heimdall_domain::reissue::*;
