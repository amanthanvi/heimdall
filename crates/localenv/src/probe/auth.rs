//! The `authentication` level: one real authentication through the real tree
//! (m02-plan U3). Needs `allow_config_commands`; refused non-interactively for an
//! unknown or interactive identity, or an uncleared fallback identity (Q2 as
//! qualified).
//!
//! `ssh -T -o BatchMode=yes -o ControlMaster=no -o ControlPath=none <alias> exit 0`
//! (ADR-0007 §6). It offers the identities the configuration selects; how many
//! signatures that causes is not claimed (§6 "Signature counts").
//!
//! **Non-interactive refusal** (`ProbeContext::interactive == false`), decided after
//! the static pass and before anything runs (outcome `refused`, code
//! `INTERACTION_REQUIRED`):
//!
//! * `interaction_unknown`: the alias has no catalog identity, or its identity's
//!   current interaction is not `none` (only a live declaration makes it `none`);
//! * `fallback_identity_interaction` (M2-R05): the identity selection for the adopted
//!   key is not `exclusive`, so ssh may offer an inherited identity whose interaction
//!   is not established. Fallback clearance is the domain rule of U0b phase 2
//!   (ADR-0007 §12.15 item 3(d)); until it lands no fallback is cleared, which fails
//!   closed.

use std::cell::Cell;

use heimdall_contract::code::Code;
use heimdall_contract::doctor::{ProbeOutcome, ProbeRecord};
use heimdall_contract::provider::{IdentitySelection, InteractionKind, ProbeLevel};
use heimdall_sshconf::relevant::identity_selection;

use super::ProbeContext;
use crate::fs::BoundedSource;

/// The `ssh` options of the level, in order, before the alias.
pub const AUTHENTICATION_ARGS: &[&str] = &[
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "ControlMaster=no",
    "-o",
    "ControlPath=none",
];

/// The remote command after the alias.
pub const AUTHENTICATION_COMMAND: &[&str] = &["exit", "0"];

/// Why a non-interactive authentication was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthRefusal {
    /// The identity is unknown or needs an interaction.
    InteractionUnknown,
    /// An inherited fallback identity is not cleared.
    FallbackIdentityInteraction,
}

impl AuthRefusal {
    /// The stable `snake_case` reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthRefusal::InteractionUnknown => "interaction_unknown",
            AuthRefusal::FallbackIdentityInteraction => "fallback_identity_interaction",
        }
    }
}

/// Authenticate to `alias`.
#[must_use]
pub fn authenticate(ctx: &ProbeContext<'_>, alias: &str) -> ProbeRecord {
    authenticate_observed(ctx, alias).0
}

/// [`authenticate`], with the non-interactive refusal reason when there was one.
#[must_use]
pub fn authenticate_observed(
    ctx: &ProbeContext<'_>,
    alias: &str,
) -> (ProbeRecord, Option<AuthRefusal>) {
    let refusal: Cell<Option<AuthRefusal>> = Cell::new(None);
    let gate = |pass: &super::StaticPass| -> Option<Code> {
        if ctx.interactive {
            return None;
        }
        let why = noninteractive_refusal(ctx, alias, pass);
        refusal.set(why);
        why.map(|_| Code::InteractionRequired)
    };
    let run = super::run_real_tree(
        ctx,
        ProbeLevel::Authentication,
        alias,
        AUTHENTICATION_ARGS,
        AUTHENTICATION_COMMAND,
        &gate,
    );
    let mut record = run.record;
    if let Some(finished) = run.finished
        && record.outcome == ProbeOutcome::Ok
        && !finished.status.is_some_and(|s| s.success())
    {
        record.outcome = ProbeOutcome::Failed;
        if String::from_utf8_lossy(&finished.stderr).contains("Host key verification failed") {
            record.code = Some(Code::HostTrustChanged);
        }
    }
    (record, refusal.get())
}

fn noninteractive_refusal(
    ctx: &ProbeContext<'_>,
    alias: &str,
    pass: &super::StaticPass,
) -> Option<AuthRefusal> {
    let Some(identity) = ctx.local.catalog_identity(alias) else {
        return Some(AuthRefusal::InteractionUnknown);
    };
    if identity.interaction != InteractionKind::None {
        return Some(AuthRefusal::InteractionUnknown);
    }
    let source = BoundedSource::new(
        ctx.local.paths.clone(),
        ctx.local.env.clone(),
        ctx.local.limits,
    );
    let report = identity_selection(&pass.evaluation, &identity.public_key_path, &source);
    if report.selection != IdentitySelection::Exclusive {
        return Some(AuthRefusal::FallbackIdentityInteraction);
    }
    None
}
