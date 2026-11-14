//! The claim table (ADR-0008 D12 item 3; m03-plan U0, §5 item 16).
//!
//! The **only** source of platform-mechanism claims: `lock_continuity: verified`,
//! `new_signing_expiry: signer`, `owned_multiplexing: closed_at_deadline`, the
//! `existing_connections` behaviour, `new_authentication_expiry: credential_and_signer`,
//! the summary `enforcement.revocation` and `revocation.remote`. A field without a
//! matching entry for this platform and these versions reads `unknown` (or
//! `not_verified` for `lock_continuity`).
//!
//! The table is a static list compiled into the binary. An entry is added only by a
//! reviewed integrator commit after its native evidence record is `verified`
//! (m03-plan §3, "claim update"). `tools/validation/claims_table.py` (the `check.sh`
//! step `claims-table`) parses [`CLAIMS`] from this file's source and fails unless every
//! entry's record exists, validates, is `verified` for that platform row and names a
//! commit that is an ancestor of `HEAD`. It also fails an entry for a custody-dependent
//! field (`lock_continuity`) whose build profile is not `release` or whose store kind
//! is not the platform's product store: test-store evidence never satisfies a
//! product-store claim (F03).
//!
//! **The M03 baseline table is empty.** Keep each entry as one `Claim { … }` struct
//! literal with every field written out, string literals only, so the validator can
//! read it without a Rust parser.

/// The build profile of the run that produced a claim's evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuildProfile {
    /// An optimized release-profile build (the product build).
    Release,
    /// A debug-profile (test-configured) build. Never satisfies a custody claim.
    Debug,
}

/// The platform row a claim covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Platform {
    /// Operating system: `macos`, `linux` or `windows`.
    pub os: &'static str,
    /// Architecture: `aarch64` or `x86_64`.
    pub arch: &'static str,
}

/// An inclusive version range (`min`..=`max`); `max` empty means "no upper bound".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionRange {
    /// The lowest version the evidence covers.
    pub min: &'static str,
    /// The highest version the evidence covers, or empty for no upper bound.
    pub max: &'static str,
}

/// One claim-table entry (ADR-0008 D12 item 3, ⟨r2⟩ with build profile and store kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Claim {
    /// The reported field, e.g. `lock_continuity` or `enforcement.revocation`.
    pub field: &'static str,
    /// The value the field may report when this entry matches, e.g. `verified`.
    pub value: &'static str,
    /// The platform and architecture of the run.
    pub platform: Platform,
    /// The OS release floor the evidence covers.
    pub os_floor: &'static str,
    /// The OpenSSH client versions the evidence covers.
    pub client_versions: VersionRange,
    /// The Heimdall signer builds the evidence covers.
    pub signer_builds: VersionRange,
    /// The build profile of the run.
    pub build_profile: BuildProfile,
    /// The secret store kind of the run (`None` when the field does not depend on custody).
    pub store_kind: Option<&'static str>,
    /// The evidence record path, relative to the repository root.
    pub record: &'static str,
    /// The commit at which the record was committed (an ancestor of `HEAD`).
    pub record_commit: &'static str,
}

/// Fields whose claim depends on key custody: an entry for one of them needs a
/// release-profile run on the platform's product store (F03).
pub const CUSTODY_FIELDS: &[&str] = &["lock_continuity"];

/// The platform's product secret store kind, by `Platform::os` (ADR-0008 D1).
/// macOS also accepts `macos_data_protection_keychain`; the validator lists both.
#[must_use]
pub fn product_store_kinds(os: &str) -> &'static [&'static str] {
    match os {
        "macos" => &["macos_login_keychain", "macos_data_protection_keychain"],
        "windows" => &["windows_dpapi"],
        "linux" => &["linux_secret_service"],
        _ => &[],
    }
}

/// The claim table. Empty in the M03 baseline (ADR-0008 D12 item 3).
pub const CLAIMS: &[Claim] = &[];

/// ⟨ADR-0008 §17.33 items 6-7⟩ Why a [`Residual`] is accepted rather than fixed (the
/// §17.33 item 6 "record, and do not block the merge" categories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResidualReason {
    /// It only fails closed (a refusal or a delay), with no lasting effect.
    FailClosedOnly,
    /// It needs a hostile same-user program, which spec P03 does not claim to isolate.
    NeedsHostileSameUserProgram,
}

/// The test that shows a [`Residual`]: its source file (relative to the repository
/// root) and its exact test name (the `cargo test` path). Where no test is feasible the
/// residual cites code instead: `test` is empty and `target` starts with `code:`, naming
/// what in `source` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    /// The Cargo invocation that runs it, e.g. `-p heimdall --bin heimdall`.
    pub target: &'static str,
    /// The source file that defines it, relative to the repository root.
    pub source: &'static str,
    /// The test's path, e.g. `uninstall_cmd::tests::some_test`.
    pub test: &'static str,
}

/// ⟨ADR-0008 §17.33 item 7⟩ A named residual: a known, accepted limit of a claim or
/// capability, carried to U13 with its probe. **Never a claim:** it has no value,
/// status, record or commit; nothing reads it to report a field; its ID is never a
/// [`CLAIMS`] field (`tools/validation/claims_table.py` refuses an entry marked
/// verified or presented as a claim, and one whose named test does not exist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Residual {
    /// Stable ID (lowercase, `_`-separated).
    pub id: &'static str,
    /// What remains, precisely.
    pub description: &'static str,
    /// The platform row; `any` for every platform.
    pub platform: Platform,
    /// The claim field or the capability it limits.
    pub limits: &'static str,
    /// The test that shows it.
    pub probe: Probe,
    /// Why it is accepted.
    pub reason: ResidualReason,
    /// The ruling that accepted it.
    pub adr: &'static str,
}

/// ⟨ADR-0008 §17.33 items 4, 7, 8⟩ The named residuals. Keep each entry one
/// `Residual { … }` literal with every field written out, string literals only.
pub const RESIDUALS: &[Residual] = &[
    Residual {
        id: "windows_purge_entry_replaced_between_check_and_delete",
        description: "Windows purge sweep (ADR-0008 §17.34 item 1; the audit's C2): entries are quarantined under random names (MoveFileExW, never replacing), validated, and deleted by path below pinned handles: each directory stays pinned (no share-delete, not a reparse point) while it is listed and emptied, each inspected entry is checked against its inspected file ID just before its deletion, and DeleteFileW/RemoveDirectoryW never follow a reparse point, so nothing outside the purge roots is reached. What remains beyond purge_entry_placed_in_quarantine_is_deleted: in the instant between an entry's unpinning and its DeleteFileW/RemoveDirectoryW, a same-user program that found its random quarantine path can replace it with an entry or link of its own, which is then removed (a link as the link itself). Not yet shown natively: the Windows chain's reparse-point refusal and owner-SID check (this user, SYSTEM or Administrators; ADR-0008 §17.33 item 13), the pinned final read and the deletion are checked by cross-target clippy and unit tests of the pure classification only; native Windows evidence is carried to U13",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        limits: "uninstall.purge_anchored_deletion",
        probe: Probe {
            target: "-p heimdall --bin heimdall (x86_64-pc-windows-msvc, native Windows)",
            source: "crates/heimdall/src/purge_sweep.rs",
            test: "purge_sweep::tests::windows_purge_refuses_a_junction_and_names_its_residual",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.33 items 4 and 7",
    },
    Residual {
        id: "purge_entry_placed_in_quarantine_is_deleted",
        description: "purge sweep, every platform (ADR-0008 §17.34 item 1: an actor can at most cause the deletion of an entry it placed): what the purge deletes was inspected and validated under random quarantine names, and the state database, its -wal and -shm are held and confirmed for the final read (a swap there refuses, nothing deleted); but a same-user program that finds a random quarantine name can, after the last check, add its own entry inside a quarantined directory or put its own entry at a quarantine name, and the deletion removes that entry it placed. Owner data at an inspected path is never deleted and nothing outside the purge roots is reached",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.purge_anchored_deletion",
        probe: Probe {
            target: "-p heimdall --bin heimdall",
            source: "crates/heimdall/src/purge_sweep.rs",
            test: "purge_sweep::tests::an_entry_placed_inside_a_quarantined_directory_is_deleted",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.34 item 1",
    },
    Residual {
        id: "issuer_request_hold_absent_for_leader_and_lease_work",
        description: "an issuer sign sent from a task that holds no fence admission of its own (the verification leader, holder-lease work) is not held by request_hold: when its waiter times out against a child that cannot be verified, the admission ends before the child does, so a fence acquisition can be taken while that child is still alive. No lasting effect: the child never writes the state database and a late signature reaches no reader, so no certificate is published",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.fence_admission (ADR-0008 §17.33 item 2)",
        probe: Probe {
            target: "-p heimdall --test e2e_cli_m03",
            source: "tests/e2e/cli_m03/issuer.rs",
            test: "issuer::residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0008 §17.33 item 11",
    },
    Residual {
        id: "holder_approval_spawns_waiting_work_with_the_holder_lease",
        description: "a decision approved by the fence holder resumes the operations waiting on it, including other connections' work, inside the holder's lease, so that work is not refused by the fence; only an owner program that itself holds the fence can approve, so it needs a hostile owner program holding the fence",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.fence_scope (ADR-0008 §17.33 item 1)",
        probe: Probe {
            target: "code: Operations::decide -> resume of the waiting operations under the caller's lease",
            source: "crates/app/src/operations.rs",
            test: "",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.33 item 11",
    },
    Residual {
        id: "uninstall_sweep_uses_cli_runtime_dir_not_recorded_locators",
        description: "the purge sweeps this CLI's resolved <run> (and <state>), not the endpoint and slot locators the runtime recorded; a runtime that ran with another XDG_RUNTIME_DIR leaves its dead sockets and files there. Leftover local files only, never recovery records; the report names the swept roots (purge_roots) so the owner can find them",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.purge_cleanup_paths (ADR-0008 §17.32 item 7)",
        probe: Probe {
            target: "-p heimdall --bin heimdall",
            source: "crates/heimdall/src/uninstall_cmd.rs",
            test: "uninstall_cmd::tests::uninstall_report_names_the_swept_roots",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0008 §17.33 item 11",
    },
    Residual {
        id: "issuer_cleanup_cancelled_kill_on_drop_signals_unreaped_child",
        description: "cancelling the issuer client's cleanup of an indeterminate request during its exit wait (at most 5 s) drops the child's handle, and kill_on_drop then signals that child although the exact-child check (PID, start token, image) had not verified it, and its admission ends with the cleanup. The signal reaches only that child: it is unreaped, so its PID cannot be reused and the handle cannot reach another process; the child ends and nothing lasts (no store write, no CA loaded, no certificate published)",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "issuer.exact_child_signal (ADR-0008 §17.33 item 2)",
        probe: Probe {
            target: "-p heimdall --test e2e_cli_m03",
            source: "tests/e2e/cli_m03/issuer.rs",
            test: "issuer::recheck4_cancelling_stop_must_not_signal_unverified_child",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0008 §17.34 item 3",
    },
];

/// The entries of [`CLAIMS`] for one field and platform.
pub fn claims_for<'a>(
    field: &'a str,
    platform: &'a Platform,
) -> impl Iterator<Item = &'static Claim> + 'a {
    CLAIMS
        .iter()
        .filter(move |c| c.field == field && c.platform == *platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_table_is_empty() {
        assert!(CLAIMS.is_empty());
        let p = Platform {
            os: "macos",
            arch: "aarch64",
        };
        assert_eq!(claims_for("lock_continuity", &p).count(), 0);
        assert_eq!(product_store_kinds("windows"), ["windows_dpapi"]);
        assert!(product_store_kinds("plan9").is_empty());
    }

    /// `residuals_are_never_claims` (ADR-0008 §17.33 item 7): every residual has a
    /// unique ID that is not a [`CLAIMS`] field, a known platform, the claim or
    /// capability it limits, an accepted reason, and a probe whose source defines the
    /// named test.
    #[test]
    fn residuals_are_never_claims() {
        // The repository through `HM_REPO_ROOT` (testkit `repo`), never the compile-time root.
        let root = heimdall_testkit::repo::repo_root();
        let mut ids = std::collections::BTreeSet::new();
        for r in RESIDUALS {
            assert!(ids.insert(r.id), "{} is listed twice", r.id);
            assert!(
                !r.id.is_empty() && r.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{}",
                r.id
            );
            assert!(
                CLAIMS.iter().all(|c| c.field != r.id),
                "{} is a claim",
                r.id
            );
            assert!(["macos", "linux", "windows", "any"].contains(&r.platform.os));
            assert!(["aarch64", "x86_64", "any"].contains(&r.platform.arch));
            assert!(!r.limits.is_empty() && !r.description.is_empty() && !r.adr.is_empty());
            let src = std::fs::read_to_string(root.join(r.probe.source))
                .unwrap_or_else(|e| panic!("{}: {e}", r.probe.source));
            if r.probe.test.is_empty() {
                assert!(
                    r.probe.target.starts_with("code:"),
                    "{}: no test, no code cited",
                    r.id
                );
                continue;
            }
            let name = r.probe.test.rsplit("::").next().unwrap_or_default();
            assert!(
                src.contains(&format!("fn {name}(")),
                "{}: {} does not define {name}",
                r.id,
                r.probe.source
            );
        }
    }
}
