//! Heimdall's remote-registry protocol and enrollment plan (ADR-0008 D5 §6.1, §6.3,
//! §6.7, §18; m03-plan §0.6, U5). **Pure: no I/O.** Production edges: `contract` and
//! `domain` only (the `crate-graph` step refuses any other workspace edge).
//!
//! **Owns:** the registry line and marker ([`line`]), the scripts ([`script`]), the
//! remote step builder ([`step`]), the HM1 grammar and parser ([`hm1`]), post-image
//! construction ([`post_image`]), the step classification ([`classify`]), the
//! reconcile classification and fencing view ([`fence`]), and the enrollment plan
//! ([`plan`]), which `app` calls directly (no port).
//!
//! **Must not own:** any process, network, file or terminal I/O (that is
//! `heimdall-enroll` and the runtime), the journal (`app`), or the target evaluation
//! (`heimdall-localenv`, through `app::ports::TargetEvaluator`).
//!
//! **Units.** U0 froze the HM1 grammar and exit codes ([`hm1`]) and the signatures of
//! [`classify::classify_step`], [`plan::build`], [`plan::plan_digest`] and
//! [`line::expected_line`]; their bodies fail closed until **U5** fills them, together
//! with [`script`], [`step`], [`post_image`] and [`fence`].

pub mod classify;
pub mod fence;
pub mod hm1;
pub mod line;
pub mod plan;
pub mod post_image;
pub mod script;
pub mod step;
