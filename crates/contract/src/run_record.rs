//! `run`/`connect` side-channel records and their normative reader (ADR-0007 §8;
//! m02-plan §5 item 12; schema `run-record`).
//!
//! The CLI writes one `RunRecord` per line (NDJSON) to `--meta-fd` or
//! `--meta-file`. No record ever carries `argv`. **Invariant:** Heimdall execs or
//! spawns only after `launching` was written in full, so no `launching` record
//! means not launched. On Unix there is no positive observation of a successful
//! `execve`; [`classify`] therefore never reports a Unix run as launched.

use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::ids::{BindingId, OperationId};
use crate::request::ConsumerOverride;
use crate::version::SchemaVersion;

/// One side-channel record, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunRecord {
    /// Heimdall stopped before launching (or the launch call returned an error).
    PrelaunchFailed {
        /// Major schema version.
        schema_version: SchemaVersion,
        /// The stable code (for example `LAUNCH_FAILED`, `INTERACTION_REQUIRED`).
        code: Code,
        /// The exit status Heimdall uses.
        exit_code: i32,
        /// Stable `snake_case` sub-reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// The operation, when one was created.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<OperationId>,
        /// The binding, when one was created.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<BindingId>,
    },
    /// An **attempt** to launch, written in full before exec or spawn.
    Launching {
        /// Major schema version.
        schema_version: SchemaVersion,
        /// Always 1.
        attempt: u32,
        /// The resolved executable.
        executable: String,
        /// The operation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_id: Option<OperationId>,
        /// The binding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_id: Option<BindingId>,
        /// Heimdall's own PID (the child's on Unix, after exec).
        pid: u32,
        /// Consumer settings another source keeps in force (for example a Git
        /// `core.sshCommand` at some scope).
        #[serde(default)]
        consumer_overrides: Vec<ConsumerOverride>,
    },
    /// Windows only: `CreateProcessW` returned; positive proof of launch.
    Spawned {
        /// Major schema version.
        schema_version: SchemaVersion,
        /// The child's PID.
        pid: u32,
    },
    /// Windows only: the child exited.
    Exited {
        /// Major schema version.
        schema_version: SchemaVersion,
        /// The child's exact exit code.
        exit_code: i64,
    },
}

impl RunRecord {
    /// The record's schema version.
    #[must_use]
    pub fn schema_version(&self) -> &SchemaVersion {
        match self {
            RunRecord::PrelaunchFailed { schema_version, .. }
            | RunRecord::Launching { schema_version, .. }
            | RunRecord::Spawned { schema_version, .. }
            | RunRecord::Exited { schema_version, .. } => schema_version,
        }
    }
}

/// The platform that wrote the records (the meaning of a lone `launching` and of
/// `spawned` differ).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunPlatform {
    /// `exec` model.
    Unix,
    /// Spawn-and-wait model.
    Windows,
}

/// What a reader may conclude from a record sequence (ADR-0007 §8 table).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "classification", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LaunchClassification {
    /// Not launched: no `launching` record, or `launching` followed by
    /// `prelaunch_failed`.
    NotLaunched {
        /// The `prelaunch_failed` code, when one was written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<Code>,
        /// The `prelaunch_failed` reason, when one was written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Launched (Windows: `launching`, `spawned`).
    Launched {
        /// The child's exit code, when `exited` was written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i64>,
    },
    /// Launched, or Heimdall stopped before or during the launch: a reader cannot
    /// tell. Also every sequence the table does not list.
    Indeterminate,
}

/// The normative reader of ADR-0007 §8 (pure).
///
/// | Records, in order | Classification |
/// |---|---|
/// | none | `not_launched` |
/// | … `prelaunch_failed` | `not_launched`, with code and reason |
/// | `launching` and nothing after (Unix or Windows) | `indeterminate` |
/// | `launching`, `spawned` (Windows) | `launched` |
/// | `launching`, `spawned`, `exited` (Windows) | `launched`, with the exit code |
///
/// "…" before `prelaunch_failed` is nothing or one `launching`. Fail-closed
/// readings: a sequence with no `launching`, `spawned` or `exited` record is
/// `not_launched` (the invariant), with the last `prelaunch_failed`'s code and
/// reason; any other sequence the table does not list (a `spawned` on Unix, a
/// record after `exited`, `launching` with `attempt` other than 1, `spawned`
/// without `launching`) and any record with an unsupported schema major is
/// `indeterminate`: it never claims a launch without positive evidence, and never
/// claims no launch after an attempt that was not answered.
#[must_use]
pub fn classify(records: &[RunRecord], platform: RunPlatform) -> LaunchClassification {
    use LaunchClassification::{Indeterminate, Launched, NotLaunched};
    use RunRecord::{Exited, Launching, PrelaunchFailed, Spawned};

    if records.iter().any(|r| !r.schema_version().is_supported()) {
        return Indeterminate;
    }
    let attempted = records.iter().any(|r| match r {
        Launching { .. } | Spawned { .. } | Exited { .. } => true,
        PrelaunchFailed { .. } => false,
    });
    if !attempted {
        return match records.last() {
            Some(PrelaunchFailed { code, reason, .. }) => NotLaunched {
                code: Some(code.clone()),
                reason: reason.clone(),
            },
            _ => NotLaunched {
                code: None,
                reason: None,
            },
        };
    }
    match (platform, records) {
        (_, [Launching { attempt: 1, .. }]) => Indeterminate,
        (
            _,
            [
                Launching { attempt: 1, .. },
                PrelaunchFailed { code, reason, .. },
            ],
        ) => NotLaunched {
            code: Some(code.clone()),
            reason: reason.clone(),
        },
        (RunPlatform::Windows, [Launching { attempt: 1, .. }, Spawned { .. }]) => {
            Launched { exit_code: None }
        }
        (
            RunPlatform::Windows,
            [
                Launching { attempt: 1, .. },
                Spawned { .. },
                Exited { exit_code, .. },
            ],
        ) => Launched {
            exit_code: Some(*exit_code),
        },
        _ => Indeterminate,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn launching(attempt: u32) -> RunRecord {
        RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt,
            executable: "/usr/bin/ssh".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: 4242,
            consumer_overrides: Vec::new(),
        }
    }

    #[test]
    fn unix_is_never_launched() {
        let spawned = RunRecord::Spawned {
            schema_version: SchemaVersion::current(),
            pid: 7,
        };
        assert_eq!(
            classify(&[launching(1), spawned], RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
        assert_eq!(
            classify(&[launching(2)], RunPlatform::Windows),
            LaunchClassification::Indeterminate
        );
    }

    #[test]
    fn unsupported_major_is_indeterminate() {
        let old = RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion("2".to_owned()),
            code: Code::UsageError,
            exit_code: 2,
            reason: None,
            operation_id: None,
            binding_id: None,
        };
        assert_eq!(
            classify(&[old], RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
    }
}
