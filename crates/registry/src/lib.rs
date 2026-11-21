//! Heimdall's remote-registry protocol and enrollment plan (ADR-0008 D5 §6.1, §6.3,
//! §6.7, §18; m03-plan §0.6, U5). **Pure: no I/O**, with one stated exception:
//! [`keys_file::local`] (⟨M06 W3⟩, below). Production edges: `contract` and
//! `domain` only (the `crate-graph` step refuses any other workspace edge).
//!
//! **Owns:** the registry line and marker ([`line`](mod@line)), the scripts
//! ([`script`]), the remote step builder ([`step`]), the HM1 grammar and parser
//! ([`hm1`]), post-image construction ([`post_image`]), the step classification
//! ([`classify`]), the reconcile classification and fencing view ([`fence`]), and the
//! enrollment plan ([`plan`]), which `app` calls directly (no port).
//!
//! **Must not own:** any process, network, file or terminal I/O (that is
//! `heimdall-enroll` and the runtime), the journal (`app`), or the target evaluation
//! (`heimdall-localenv`, through `app::ports::TargetEvaluator`).
//!
//! ⟨M06 W3⟩ **The one authorized_keys safety module** ([`keys_file`]; ADR-0012 §3.5
//! ⟨2026-11-21⟩, ADR-0006 §18.7 reading (c)). ADR-0005 §3.3's safety steps exist once,
//! here, because this is the only crate both writers may depend on: the enrollment
//! writer is this crate, and the runner's management-line writer
//! (`heimdall_runtime::paired_lines`) reaches it through an edge the crate graph allows
//! (this crate depends on `contract` and `domain` only, so no cycle can form). Its rules
//! are pure; its `local` submodule (Unix) is the stated exception to "no I/O": bounded,
//! link-refusing edits of one local file, given the path and the account's uid by the
//! caller. It starts no process and opens no network connection.
//!
//! **Units.** U0 froze the HM1 grammar and exit codes ([`hm1`]) and the signatures of
//! [`classify::classify_step`], [`plan::build`], [`plan::plan_digest`] and
//! [`line::expected_line`]. **U5** (wave 1) fills them: the strict HM1 parser, the
//! step classification and the `inspect` reading ([`classify`]), the line and marker
//! ([`line`](mod@line)), the byte-preserving post-image and post-write checks
//! ([`post_image`]), the pinned remote step and the `ssh -G` check ([`step`]), the
//! fencing-first reconcile, the not-after and the late-write residual ([`fence`]), and
//! the plan with its preconditions and digest ([`plan`]); and [`script`].

pub mod classify;
pub mod fence;
pub mod hm1;
// ⟨M06 W3⟩ The shared authorized_keys safety module (see the crate docs).
pub mod keys_file;
pub mod line;
pub mod plan;
pub mod post_image;
// ⟨M06 U5a⟩ The helper's isolated jump leg and the `ssh -G` pin verification (ADR-0012 §5.2,
// §5.4, §5.5).
pub mod routes;
pub mod script;
pub mod step;
