//! `match_workspace` (ADR-0011 §2.3; property P11): the observation against the local
//! workspace records.
//!
//! Only `Active` records of the observation's environment count. Per record:
//!
//! | observation vs record | result |
//! |---|---|
//! | equal canonical root and equal identity (both known) | `Trusted` |
//! | a **verified** linked worktree whose common-directory identity equals the record's | `Member` |
//! | equal root, different identity | `Ambiguous { SamePathOtherIdentity }` |
//! | equal identity, different root | `Ambiguous { SameIdentityOtherPath }` |
//! | anything else (copy, clone, cross-filesystem move, copied worktree, submodule) | `Untrusted` |
//!
//! An observation without a root identity matches nothing by path or by identity (R6:
//! refused, never approximated). Across records the best result wins, `Trusted` > `Member` >
//! `Ambiguous` > `Untrusted`, ties by the smallest record ID.

use heimdall_domain::projection::FileIdentity;
use heimdall_domain::workspace::{
    AmbiguityReason, WorkspaceMatch, WorkspaceRecord, WorkspaceState,
};

use crate::observe::{GitObservation, WorkspaceObservation};

/// Rank of a per-record result; lower is better.
fn rank(m: &WorkspaceMatch) -> u8 {
    match m {
        WorkspaceMatch::Trusted { .. } => 0,
        WorkspaceMatch::Member { .. } => 1,
        WorkspaceMatch::Ambiguous { .. } => 2,
        _ => 3,
    }
}

fn against(obs: &WorkspaceObservation, rec: &WorkspaceRecord) -> WorkspaceMatch {
    let same_root = obs.root == rec.root;
    let same_identity = obs
        .root_identity
        .as_ref()
        .is_some_and(|i| i.same_file(&rec.root_identity));

    if same_root && same_identity {
        return WorkspaceMatch::Trusted {
            workspace: rec.id.clone(),
        };
    }
    if let (
        Some(GitObservation::LinkedWorktree {
            common_identity: Some(common),
            verified: true,
            ..
        }),
        Some(recorded),
    ) = (&obs.git, &rec.git_common_identity)
        && FileIdentity::same_file(common, recorded)
    {
        return WorkspaceMatch::Member {
            workspace: rec.id.clone(),
        };
    }
    // Both partial matches need a known identity on the observation.
    if obs.root_identity.is_some() {
        if same_root {
            return WorkspaceMatch::Ambiguous {
                workspace: rec.id.clone(),
                why: AmbiguityReason::SamePathOtherIdentity,
            };
        }
        if same_identity {
            return WorkspaceMatch::Ambiguous {
                workspace: rec.id.clone(),
                why: AmbiguityReason::SameIdentityOtherPath,
            };
        }
    }
    WorkspaceMatch::Untrusted
}

/// Match an observation against the records (see the module doc).
#[must_use]
pub fn match_workspace(obs: &WorkspaceObservation, records: &[WorkspaceRecord]) -> WorkspaceMatch {
    let mut best: Option<(u8, &WorkspaceRecord, WorkspaceMatch)> = None;
    for rec in records {
        if rec.state != WorkspaceState::Active || rec.environment != obs.environment {
            continue;
        }
        let m = against(obs, rec);
        let r = rank(&m);
        if r == 3 {
            continue;
        }
        let better = match &best {
            None => true,
            Some((best_rank, best_rec, _)) => {
                r < *best_rank || (r == *best_rank && rec.id < best_rec.id)
            }
        };
        if better {
            best = Some((r, rec, m));
        }
    }
    best.map_or(WorkspaceMatch::Untrusted, |(_, _, m)| m)
}
