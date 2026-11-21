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
//! entry's record exists **at the commit it cites**, validates, is `verified` for that
//! platform row there, names a commit that is an ancestor of `HEAD`, and ⟨M03-F1 R06⟩ has
//! bounds equal to that record's host facts: the OS floor its OS release, the client range
//! its client's version, the pinned signer build the workspace version at that commit. It also fails an entry for a custody-dependent
//! field (`lock_continuity`) whose build profile is not `release` or whose store kind
//! is not the platform's product store: test-store evidence never satisfies a
//! product-store claim (F03).
//!
//! **The M03 baseline table was empty**; the M03 claim update adds the A07 and A23 fields
//! ([`CLAIMS`]). ⟨I-28⟩ M04's claim update adds no entry: no M04 record runs a claimed
//! field's tests on a new platform, OS release, client or build, and M04's WSL rows are `wsl`
//! hosts. Keep each entry as one `Claim { … }` struct literal with every field
//! written out, string literals only, so the validator can read it without a Rust parser.
//!
//! ⟨M04 I-28⟩ **Native endpoints only.** Every entry's record ran bindings with a native
//! endpoint: the host's own verified client against the runtime's per-binding endpoint.
//! [`endpoint_covered`] is the gate the report applies beside [`applies`]: a WSL Mode B or
//! container binding reads every claim-table field `unknown`, whatever the host.

pub use heimdall_contract::managed::BindingEndpointKind;

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
    /// Operating system: `macos`, `linux` or `windows`. ⟨M03-F1 R02⟩ A host under WSL is
    /// `wsl`, which no table row names.
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

/// The claim table (ADR-0008 D12 item 3). ⟨M03 claim update⟩ The A07 and A23 fields (m03-plan §3, "claim
/// update"), each from its `verified` row of the M03 exit records at the records commit:
/// `enforcement.revocation` and `revocation.remote` from A07; `new_signing_expiry`,
/// `new_authentication_expiry`, `existing_connections` and `owned_multiplexing` from A23. The rows are
/// debug test-configured runs, so no entry is for a custody field (`lock_continuity` stays
/// `not_verified`, F03). Each covers exactly the OS release and OpenSSH client the run used. Windows has
/// no `owned_multiplexing` entry (no masters there) and no `graceful_dedicated_connections` entry (its
/// A23 row proves the strict deadline only).
pub const CLAIMS: &[Claim] = &[
    Claim {
        field: "enforcement.revocation",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "revocation.remote",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "enforcement.revocation",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "revocation.remote",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "enforcement.revocation",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        os_floor: "10.0.26300.9974",
        client_versions: VersionRange {
            min: "9.5p2",
            max: "9.5p2",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "revocation.remote",
        value: "bounded_by_credential_expiry",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        os_floor: "10.0.26300.9974",
        client_versions: VersionRange {
            min: "9.5p2",
            max: "9.5p2",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a07-revocation.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_signing_expiry",
        value: "signer",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_authentication_expiry",
        value: "credential_and_signer",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "existing_connections",
        value: "strict_disconnect",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "existing_connections",
        value: "graceful_dedicated_connections",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "owned_multiplexing",
        value: "closed_at_deadline",
        platform: Platform {
            os: "macos",
            arch: "aarch64",
        },
        os_floor: "27.2.1",
        client_versions: VersionRange {
            min: "10.5p1",
            max: "10.5p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_signing_expiry",
        value: "signer",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_authentication_expiry",
        value: "credential_and_signer",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "existing_connections",
        value: "strict_disconnect",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "existing_connections",
        value: "graceful_dedicated_connections",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "owned_multiplexing",
        value: "closed_at_deadline",
        platform: Platform {
            os: "linux",
            arch: "x86_64",
        },
        os_floor: "6.8.0-147-generic",
        client_versions: VersionRange {
            min: "9.6p1",
            max: "9.6p1",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_signing_expiry",
        value: "signer",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        os_floor: "10.0.26300.9974",
        client_versions: VersionRange {
            min: "9.5p2",
            max: "9.5p2",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "new_authentication_expiry",
        value: "credential_and_signer",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        os_floor: "10.0.26300.9974",
        client_versions: VersionRange {
            min: "9.5p2",
            max: "9.5p2",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
    Claim {
        field: "existing_connections",
        value: "strict_disconnect",
        platform: Platform {
            os: "windows",
            arch: "x86_64",
        },
        os_floor: "10.0.26300.9974",
        client_versions: VersionRange {
            min: "9.5p2",
            max: "9.5p2",
        },
        signer_builds: VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        },
        build_profile: BuildProfile::Debug,
        store_kind: None,
        record: "tests/evidence/m03-a23-deadline-connections.json",
        record_commit: "9176fc5e57f970ec3f2c5cc81435a030272725dc",
    },
];

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
        description: "purge sweep, every platform (ADR-0008 §17.34 item 1: an actor can at most cause the deletion of an entry it placed): what the purge deletes was inspected and validated under random quarantine names, and the state database, its -wal and -shm are held and confirmed for the final read (a swap there refuses, nothing deleted); but a same-user program that finds a random quarantine name can, after the last check, add its own entry inside a quarantined directory or put its own entry at a quarantine name, and the deletion removes that entry it placed. The owner's quarantined trees are deleted only after their last validation, and the owner's database family only after a recovery copy that opens and reads on its own is bound by the deletion mark; a crash recovery acting on a mark first checks that copy against the mark's binding and every original present against the unit record's identity, and otherwise deletes nothing (ADR-0008 §17.38, W5-I01). A copy and mark forged together is purge_recovery_copy_and_marker_forged_together. Nothing outside the purge roots is reached",
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
        id: "purge_restore_copy_log_placed_between_check_and_rename",
        description: "uninstall purge's restore of the recovery copy (ADR-0008 §17.36 item 1): the copy becomes state.db by one no-replace rename only after checking that state.db, -wal, -shm and -journal are all free; a same-user program that places a -wal at state.db-wal in the instant between that check and the rename attaches its own log to the restored database. A database it places at state.db makes the no-replace rename refuse, and the original family stays in quarantine either way",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.purge_anchored_deletion",
        probe: Probe {
            target: "-p heimdall --bin heimdall",
            source: "crates/heimdall/src/uninstall_cmd.rs",
            test: "uninstall_cmd::tests::r13_review_restore_race_preserves_replacement_record",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.36 item 1",
    },
    Residual {
        id: "purge_recovery_copy_and_marker_forged_together",
        description: "purge crash recovery (ADR-0008 §17.38, W5-I01): a deletion mark makes recovery finish deleting the original database family only when the recovery copy it binds (identity, size, SHA-256) opens read-only on its own, passes the integrity and schema checks and reads, and every original present is the recorded file. A same-user program that forges all of that together (a valid database at the copy's name plus a mark binding its exact identity and digest) gets the originals deleted and its database restored as state.db. That gives it nothing it does not already have: it runs as the owner and can already delete the unit's files or write state.db directly. A planted mark alone, or one beside a missing, mismatched or unreadable copy, or beside an original that is not the recorded file, deletes nothing (probes: uninstall_cmd::tests::w5_i01_planted_marker_without_copy_keeps_database, w5_i01_planted_marker_with_garbage_copy_keeps_database, w5_i01_marker_binding_mismatch_keeps_the_database, w5_i01_original_not_the_recorded_inode_keeps_the_unit; purge_sweep::tests::w5_i01_failed_copy_check_unlinks_nothing)",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.purge_anchored_deletion",
        probe: Probe {
            target: "-p heimdall --bin heimdall",
            source: "crates/heimdall/src/uninstall_cmd.rs",
            test: "uninstall_cmd::tests::w5_i01_planted_marker_with_garbage_copy_keeps_database",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.38",
    },
    Residual {
        id: "purge_recovery_copy_overwritten_between_check_and_unlink",
        description: "uninstall purge's deletion of the original database family, Unix (ADR-0008 §17.39, W5-J01): immediately before the first original is unlinked, the recovery copy is read again by its name through a fresh descriptor and must still match the deletion mark's binding (identity, size, SHA-256), or nothing of the family is unlinked and the unit is kept. A same-user program that overwrites the copy in place in the instant between that re-check and the unlinks gets the original family deleted behind a copy that is no longer the checked one. That deletion is the one the owner confirmed with a typed yes, and such a program could delete the originals itself. Crash recovery acting on a mark is not exposed: it restores the copy as state.db first, verifies the file at the live name from a fresh read, and only then unlinks an original; a copy overwritten before the restore fails that verification and every original is kept. On Windows the copy is held open with no write sharing from its check through the last original's deletion (and through recovery's restore and verification), so no other handle can open it for writing in that window; the hold shares delete (the restore renames the held file through it), so it does not stop the copy's rename or deletion, which on either platform removes the copy rather than altering it, a deletion the program could make of the originals itself. A later overwrite of the live state.db is outside the purge (spec P03)",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.purge_anchored_deletion",
        probe: Probe {
            target: "-p heimdall --bin heimdall",
            source: "crates/heimdall/src/uninstall_cmd.rs",
            test: "uninstall_cmd::tests::w5_j01_copy_overwritten_after_check_keeps_originals",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0008 §17.39",
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
    Residual {
        id: "uninstall_fence_release_stuck_until_holder_work_ends",
        description: "holder work that never ends (a step admitted under the uninstall fence's lease that does not finish) keeps a released fence releasing: every other fenced request stays refused until that work ends or the runtime restarts. Past the 20 s release bound the refusal is uninstall_fence_release_stuck (SERVICE_UNAVAILABLE, exit 5, effect none), naming the restart: heimdall service stop, then heimdall service run --detach. The fence is never stored, so a restarted runtime has none. It only refuses; nothing lasts",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "uninstall.fence_release (ADR-0008 §17.33 items 1 and 9)",
        probe: Probe {
            target: "-p heimdall-app --lib",
            source: "crates/app/src/operations/uninstall_fence_m03.rs",
            test: "operations::uninstall_fence_m03::tests::fence_release_stuck_past_its_bound_refuses_with_the_restart",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0008 §17.33 item 9; §17.35 item 3",
    },
    Residual {
        id: "same_user_agent_with_a_terminal_can_attend",
        description: "a same-user program with a terminal (a prompt-injected agent driving a pseudo-terminal) can run `heimdall decision approve` and type yes at Heimdall's own attended confirmation, or speak the control protocol itself and declare an interactive session. Claimed instead: no repository, manifest or request content ever becomes consent (ADR-0011 I1, I5), and a program without a terminal gets INTERACTION_REQUIRED. Owner question Q8's guard was dropped; this is the residual only",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "consent.attended_decide (ADR-0011 R1)",
        probe: Probe {
            target: "-p heimdall-runtime --test model_operations",
            source: "tests/model/operations.rs",
            test: "a29_only_an_interactive_session_may_attend",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0011 §8 R1; ruling I-23",
    },
    Residual {
        id: "request_working_directory_is_a_same_user_claim",
        description: "the working directory in an ensure, run or hook request is the caller's claim: a same-user process can name any trusted workspace's directory and activate what that workspace's policy covers. Context labels say same_user_context; the claim is only that a directory never gains a workspace trust it does not have, and never moves trust",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "workspace.context_resolution (ADR-0011 R2)",
        probe: Probe {
            target: "-p heimdall-runtime --test adversarial_prompt_injection",
            source: "tests/adversarial/prompt_injection.rs",
            test: "a29_hostile_working_directories_move_no_trust",
        },
        reason: ResidualReason::NeedsHostileSameUserProgram,
        adr: "ADR-0011 §8 R2; ruling I-23",
    },
    Residual {
        id: "first_ordinary_ssh_after_a_free_slot_fails_once",
        description: "the first ordinary ssh after a free-slot period activates the personal default and may fail once, because OpenSSH reads the slot's IdentityFile before it asks the agent; the next ssh logs in. With the shell integration the hook warms the default first; native Windows has no hook and keeps it. Spec §5.4 and §10.3 hold from the second use. It only fails; the activation it triggered stays applied",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "activation.ordinary_ssh_default (ADR-0011 §10 item 12, I-13)",
        probe: Probe {
            target: "-p heimdall --test e2e_exit_m05",
            source: "tests/e2e/exit_m05/u5.rs",
            test: "u5::u5_ordinary_ssh_activates_the_personal_default",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0011 §10 item 12 (I-13); ruling I-23",
    },
    Residual {
        id: "workspace_identity_unavailable_is_refused",
        description: "on a filesystem that reports no stable file identity, a workspace's identity is refused, never approximated by path alone (ADR-0011 §2.3): such a root cannot be matched to a trust record by identity. No fixture filesystem lacks stable identities (APFS, ext4 and NTFS all report one), so the probe cites the code that keeps a missing identity as None",
        platform: Platform {
            os: "any",
            arch: "any",
        },
        limits: "workspace.identity (ADR-0011 R6)",
        probe: Probe {
            target: "code: the observation keeps a missing root and .git identity as None (`Observation`'s identity fields; R6: never approximated)",
            source: "crates/project/src/observe.rs",
            test: "",
        },
        reason: ResidualReason::FailClosedOnly,
        adr: "ADR-0011 §8 R6; ruling I-23",
    },
];

/// ⟨M03-F1⟩ The running Heimdall build, against which a claim's `signer_builds` is judged.
pub const SIGNER_BUILD: &str = env!("CARGO_PKG_VERSION");

/// ⟨M03-F1⟩ What a claim's ranges are judged against on this host (ADR-0008 D12 item 2: a
/// value whose test has not passed for this platform **and these versions** is `unknown`).
/// A fact that could not be read is `None`, and no entry applies on it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostFacts {
    /// The running platform. ⟨M03-F1 R02⟩ A Linux host under WSL is `os: "wsl"`, a platform
    /// no table row names, so it never matches a native Linux entry.
    pub platform: Platform,
    /// The host's OS release in its platform's format ([`os_release_key`]): the macOS
    /// `ProductVersion`, the Linux kernel release, the Windows `major.minor.build.UBR`.
    pub os_release: Option<String>,
    /// The verified OpenSSH client's version, as `10.5p1`.
    pub client_version: Option<String>,
    /// The running Heimdall build ([`SIGNER_BUILD`]).
    pub signer_build: String,
}

/// ⟨M03-F1⟩ Whether `claim` applies on `host`: the same platform, an OS release at least
/// its `os_floor` (both in that platform's format, compared at the floor's full
/// granularity; on Linux the same kernel flavour, R02), a client within its
/// `client_versions` and exactly its pinned signer build.
/// A fact the host could not read, or one that is malformed, never satisfies a bound.
#[must_use]
pub fn applies(claim: &Claim, host: &HostFacts) -> bool {
    let os = claim.platform.os;
    let floor = os_release_key(os, claim.os_floor);
    let release = host
        .os_release
        .as_deref()
        .and_then(|r| os_release_key(os, r));
    claim.platform == host.platform
        && matches!((release, floor), (Some(r), Some(f)) if r.flavour == f.flavour && r.numbers >= f.numbers)
        && host
            .client_version
            .as_deref()
            .is_some_and(|v| client_in_range(v, &claim.client_versions))
        && signer_pinned(&host.signer_build, &claim.signer_builds)
}

/// ⟨M04 I-28⟩ Whether the claim table's entries can hold for a binding whose endpoint is of
/// `kind`: only [`BindingEndpointKind::Native`]. Every entry's record ran native endpoint
/// bindings; none covers a WSL Mode B binding (the distribution's OpenSSH through the bridge)
/// or a container binding (the container's client through the mounted endpoint), so for those
/// every claim-table field reads `unknown` (`not_verified` for `lock_continuity`) on every
/// host. An entry for another kind would need its own platform row, its own evidence and a
/// [`Claim`] field naming the kind. The host's checks ([`applies`]) are unchanged.
#[must_use]
pub fn endpoint_covered(kind: BindingEndpointKind) -> bool {
    kind == BindingEndpointKind::Native
}

/// ⟨M03-F1⟩ The entries of `table` that apply on `host` ([`applies`]).
#[must_use]
pub fn applicable(table: &[Claim], host: &HostFacts) -> Vec<Claim> {
    table.iter().filter(|c| applies(c, host)).copied().collect()
}

/// ⟨M03-F1 R02, R04, R05⟩ An OS release as a claim's floor is compared with it: its numbers,
/// ordered, and the flavour that must be the same (empty except on Linux).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OsRelease {
    /// The ordered numbers: macOS `[major, minor, patch]`, Linux `[major, minor, patch,
    /// ABI]`, Windows `[major, minor, build, UBR]`.
    pub numbers: Vec<u64>,
    /// The Linux kernel flavour (`generic` in `6.8.0-147-generic`); empty elsewhere.
    pub flavour: String,
}

/// ⟨M03-F1 R02, R04, R05⟩ An OS release parsed strictly in the format of the platform `os`;
/// `None` for a malformed text or a platform without one (`wsl` among them), so no entry
/// applies on it. It never panics, whatever the text.
/// * `macos`: the `ProductVersion`, two or three dot-separated numbers (`27.2` is `27.2.0`).
/// * `linux`: a **native** distribution kernel release, exactly
///   `major.minor.patch-ABI-flavour`, the flavour lowercase ASCII letters and digits in
///   `-`-separated words (`6.8.0-147-generic`, `6.1.0-28-amd64`). Anything else, a custom
///   kernel (`6.12.0-custom`), a WSL kernel (`…-microsoft-standard-WSL2`), a release
///   candidate (`6.8.0-rc1`) or a bare version, is not positively native and has none.
/// * `windows`: exactly `major.minor.build.UBR`.
#[must_use]
pub fn os_release_key(os: &str, release: &str) -> Option<OsRelease> {
    let number = |p: &str| -> Option<u64> {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse().ok())
            .flatten()
    };
    let numbers = |s: &str| -> Option<Vec<u64>> { s.split('.').map(number).collect() };
    let plain = |numbers: Vec<u64>| OsRelease {
        numbers,
        flavour: String::new(),
    };
    match os {
        "macos" => {
            let mut key = numbers(release).filter(|k| (2..=3).contains(&k.len()))?;
            key.resize(3, 0);
            Some(plain(key))
        }
        "windows" => numbers(release).filter(|k| k.len() == 4).map(plain),
        "linux" => {
            let mut parts = release.splitn(3, '-');
            let (version, abi, flavour) = (parts.next()?, parts.next()?, parts.next()?);
            let mut key = numbers(version).filter(|k| k.len() == 3)?;
            key.push(number(abi)?);
            let word = |w: &str| {
                !w.is_empty()
                    && w.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            };
            flavour.split('-').all(word).then(|| OsRelease {
                numbers: key,
                flavour: flavour.to_owned(),
            })
        }
        _ => None,
    }
}

/// ⟨M03-F1 R04⟩ The numeric key of an OpenSSH version, exactly `major.minorpN`
/// (`10.5p1` is `[10, 5, 1]`); `None` for anything else.
#[must_use]
pub fn client_version_key(version: &str) -> Option<[u64; 3]> {
    let (number, patch) = version.split_once('p')?;
    let (major, minor) = number.split_once('.')?;
    let n = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    Some([n(major)?, n(minor)?, n(patch)?])
}

/// ⟨M03-F1⟩ Whether the client `version` lies within `range` (an empty bound is open; a
/// malformed version or bound never matches).
fn client_in_range(version: &str, range: &VersionRange) -> bool {
    let Some(v) = client_version_key(version) else {
        return false;
    };
    // An empty bound is open (`Some(None)`); a malformed one is `None`.
    let bound = |b: &str| {
        if b.is_empty() {
            Some(None)
        } else {
            client_version_key(b).map(Some)
        }
    };
    match (bound(range.min), bound(range.max)) {
        (Some(min), Some(max)) => min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m),
        _ => false,
    }
}

/// ⟨M03-F1 R04⟩ Signer builds are identities, not ordered versions: a claim covers exactly
/// the build its range pins (`min` = `max`, non-empty), so `0.1.0-m1` is not `0.1.0-m01`.
fn signer_pinned(build: &str, range: &VersionRange) -> bool {
    !range.min.is_empty() && range.min == range.max && build == range.min
}

/// ⟨M03-F1 R01⟩ `enforcement` with every value only a claim-table entry produces reset to
/// `unknown`: `new_authentication_expiry: credential_and_signer`, `existing_connections:
/// strict_disconnect` or `graceful_dedicated_connections`, `revocation:
/// bounded_by_credential_expiry`, `new_signing_expiry: signer` and `owned_multiplexing:
/// closed_at_deadline` (the managed report's claim-gated values). A stored verdict is
/// history: a current result built from it carries none of them unless they were judged
/// again against the current host. Every other value is kept.
#[must_use]
pub fn without_claimed_values(
    enforcement: &heimdall_contract::request::Enforcement,
) -> heimdall_contract::request::Enforcement {
    use heimdall_contract::managed::{NewSigningExpiry, OwnedMultiplexing};
    use heimdall_contract::request::{
        ExistingConnectionsPolicy as E, NewAuthenticationExpiry as N, RevocationStatus as R,
    };
    let mut e = enforcement.clone();
    if e.new_authentication_expiry == N::CredentialAndSigner {
        e.new_authentication_expiry = N::Unknown;
    }
    if matches!(
        e.existing_connections,
        E::StrictDisconnect | E::GracefulDedicatedConnections
    ) {
        e.existing_connections = E::Unknown;
    }
    if e.revocation == R::BoundedByCredentialExpiry {
        e.revocation = R::Unknown;
    }
    if e.new_signing_expiry == Some(NewSigningExpiry::Signer) {
        e.new_signing_expiry = Some(NewSigningExpiry::Unknown);
    }
    if e.owned_multiplexing == Some(OwnedMultiplexing::ClosedAtDeadline) {
        e.owned_multiplexing = Some(OwnedMultiplexing::Unknown);
    }
    e
}

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

    /// ⟨M03-F1⟩ Host facts for `os`/`arch` with the given release and client, this build.
    fn host(os: &'static str, arch: &'static str, release: &str, client: &str) -> HostFacts {
        HostFacts {
            platform: Platform { os, arch },
            os_release: Some(release.to_owned()),
            client_version: Some(client.to_owned()),
            signer_build: SIGNER_BUILD.to_owned(),
        }
    }

    #[test]
    fn version_keys_parse_strictly_per_platform() {
        let key = |os: &str, r: &str| os_release_key(os, r);
        let rel = |numbers: &[u64], flavour: &str| {
            Some(OsRelease {
                numbers: numbers.to_vec(),
                flavour: flavour.to_owned(),
            })
        };
        assert_eq!(key("macos", "27.2.1"), rel(&[27, 2, 1], ""));
        assert_eq!(key("macos", "27.2"), rel(&[27, 2, 0], ""));
        assert_eq!(
            key("linux", "6.8.0-147-generic"),
            rel(&[6, 8, 0, 147], "generic")
        );
        assert_eq!(
            key("linux", "6.8.0-1-generic"),
            rel(&[6, 8, 0, 1], "generic")
        );
        assert_eq!(
            key("linux", "6.11.0-29-lowlatency"),
            rel(&[6, 11, 0, 29], "lowlatency")
        );
        assert_eq!(key("linux", "6.1.0-28-amd64"), rel(&[6, 1, 0, 28], "amd64"));
        assert_eq!(
            key("linux", "6.8.0-1015-generic-64k"),
            rel(&[6, 8, 0, 1015], "generic-64k")
        );
        assert_eq!(
            key("windows", "10.0.26300.9974"),
            rel(&[10, 0, 26300, 9974], "")
        );
        // ⟨R04⟩ One negative per format: malformed or incomplete releases have no key.
        // ⟨R02⟩ On Linux only a native distribution release is one: a custom kernel, a WSL
        // kernel, a release candidate or a bare version is not. ⟨RC-R03⟩ Never a panic, for
        // non-ASCII text either.
        for (os, bad) in [
            ("macos", "27.3."),
            ("macos", "27"),
            ("macos", "27.2.1.1"),
            ("macos", "27.2.1 (26B131)"),
            ("macos", "27.2é"),
            ("linux", "unreadable"),
            ("linux", "6.8"),
            ("linux", "6.8.0"),
            ("linux", "6.8.0."),
            ("linux", "6.8.0 -147"),
            ("linux", "6.8.0-147-gen eric"),
            ("linux", "6.8.0-147-Generic"),
            ("linux", "6.8.0-147-"),
            ("linux", "6.8.0-147-generic-"),
            ("linux", "6.8.0-rc1"),
            ("linux", "6.12.0-custom"),
            ("linux", "6.12.0-microsoft-standard-WSL2"),
            ("linux", "6.6.87.2-microsoft-standard-WSL2"),
            ("linux", "6.8.0é"),
            ("linux", "6.8.0-é"),
            ("linux", "6.8.0-147-généric"),
            ("linux", "é.8.0-147-generic"),
            ("windows", "10.0.26300"),
            ("windows", "10.0.26300.9974."),
            ("windows", "10.0.26300.99x4"),
            ("windows", "10.0.26300.９９７４"),
            ("wsl", "6.12.0-microsoft-standard-WSL2"),
            ("plan9", "4"),
        ] {
            assert_eq!(key(os, bad), None, "{os} {bad:?}");
        }
        assert_eq!(client_version_key("10.5p1"), Some([10, 5, 1]));
        assert_eq!(client_version_key("9.5p2"), Some([9, 5, 2]));
        for bad in [
            "9.6p1broken",
            "9.6",
            "9.6p",
            "p1",
            "9.6p1 ",
            "OpenSSH_9.6p1",
            "9..6p1",
        ] {
            assert_eq!(client_version_key(bad), None, "{bad:?}");
        }
        let pinned = VersionRange {
            min: "0.1.0-m01",
            max: "0.1.0-m01",
        };
        assert!(signer_pinned("0.1.0-m01", &pinned));
        assert!(
            !signer_pinned("0.1.0-m1", &pinned),
            "an identity, not a number"
        );
        let open = VersionRange {
            min: "0.1.0-m01",
            max: "",
        };
        assert!(!signer_pinned("0.1.0-m01", &open), "only a pinned build");
    }

    /// ⟨M03-F1⟩ Every entry's bounds are well formed: its floor has a key in its platform's
    /// format, its client bounds are OpenSSH versions and its signer build is pinned.
    #[test]
    fn every_entry_bound_is_well_formed() {
        for c in CLAIMS {
            assert!(os_release_key(c.platform.os, c.os_floor).is_some(), "{c:?}");
            for b in [c.client_versions.min, c.client_versions.max] {
                assert!(client_version_key(b).is_some(), "{c:?}");
            }
            assert!(
                signer_pinned(c.signer_builds.min, &c.signer_builds),
                "{c:?}"
            );
        }
    }

    /// ⟨M03-F1⟩ ADR-0008 D12 item 2: the real table's entries apply only on their platform
    /// with an OS release at least the floor (the exact tested release, at its full
    /// granularity), the client in range and exactly the pinned build; WSL (its own
    /// platform), an older revision, another client, build or platform, a malformed fact
    /// or one the host could not read gets none.
    #[test]
    fn real_table_applies_only_within_its_ranges() {
        let fields = |h: &HostFacts| {
            let mut f: Vec<String> = applicable(CLAIMS, h)
                .iter()
                .map(|c| format!("{}={}", c.field, c.value))
                .collect();
            f.sort();
            f
        };
        let a07_a23 = [
            "enforcement.revocation=bounded_by_credential_expiry",
            "existing_connections=graceful_dedicated_connections",
            "existing_connections=strict_disconnect",
            "new_authentication_expiry=credential_and_signer",
            "new_signing_expiry=signer",
            "owned_multiplexing=closed_at_deadline",
            "revocation.remote=bounded_by_credential_expiry",
        ];
        let mac = host("macos", "aarch64", "27.2.1", "10.5p1");
        let linux = host("linux", "x86_64", "6.8.0-147-generic", "9.6p1");
        let windows = host("windows", "x86_64", "10.0.26300.9974", "9.5p2");
        assert_eq!(fields(&mac), a07_a23);
        assert_eq!(fields(&linux), a07_a23);
        assert_eq!(
            fields(&windows),
            [
                "enforcement.revocation=bounded_by_credential_expiry",
                "existing_connections=strict_disconnect",
                "new_authentication_expiry=credential_and_signer",
                "new_signing_expiry=signer",
                "revocation.remote=bounded_by_credential_expiry",
            ],
            "no owned masters and no graceful mode on Windows"
        );
        // ⟨R05⟩ The floor is inclusive (ADR-0008 D12): a later release is covered.
        assert_eq!(fields(&host("macos", "aarch64", "27.3", "10.5p1")), a07_a23);
        assert_eq!(
            fields(&host("linux", "x86_64", "6.8.0-150-generic", "9.6p1")),
            a07_a23
        );
        assert_eq!(
            fields(&host("windows", "x86_64", "10.0.26300.9975", "9.5p2")).len(),
            5
        );
        for (what, h) in [
            // ⟨R02⟩ WSL is its own platform: no native Linux entry, whatever its kernel.
            (
                "WSL with a kernel above the Linux floor and the Linux client",
                host("wsl", "x86_64", "6.12.0-microsoft-standard-WSL2", "9.6p1"),
            ),
            (
                "WSL's kernel read as Linux (below the floor)",
                host(
                    "linux",
                    "x86_64",
                    "6.6.87.2-microsoft-standard-WSL2",
                    "9.6p1",
                ),
            ),
            // ⟨R02⟩ Only a native kernel of the floor's flavour: a markerless custom kernel
            // above the floor, or another flavour, is not.
            (
                "a markerless custom kernel above the Linux floor",
                host("linux", "x86_64", "6.12.0-custom", "9.6p1"),
            ),
            (
                "another flavour above the Linux floor",
                host("linux", "x86_64", "6.11.0-29-lowlatency", "9.6p1"),
            ),
            (
                "a WSL kernel above the Linux floor, read as Linux",
                host("linux", "x86_64", "6.12.0-microsoft-standard-WSL2", "9.6p1"),
            ),
            // ⟨R05⟩ Older revisions of the tested release are below the floor.
            (
                "an older ABI of the Linux release",
                host("linux", "x86_64", "6.8.0-1-generic", "9.6p1"),
            ),
            (
                "a release candidate of the Linux release",
                host("linux", "x86_64", "6.8.0-rc1", "9.6p1"),
            ),
            (
                "an older UBR of the Windows build",
                host("windows", "x86_64", "10.0.26300.9973", "9.5p2"),
            ),
            (
                "a Windows release without its UBR",
                host("windows", "x86_64", "10.0.26300", "9.5p2"),
            ),
            (
                "an older macOS revision",
                host("macos", "aarch64", "27.2", "10.5p1"),
            ),
            // ⟨R04⟩ Malformed facts never satisfy a bound.
            (
                "a malformed macOS release",
                host("macos", "aarch64", "27.3.", "10.5p1"),
            ),
            (
                "an unreadable Linux release",
                host("linux", "x86_64", "unreadable", "9.6p1"),
            ),
            (
                "an incomplete client token",
                host("linux", "x86_64", "6.8.0-147-generic", "9.6p1broken"),
            ),
            ("an older macOS", host("macos", "aarch64", "27.1", "10.5p1")),
            (
                "another client",
                host("macos", "aarch64", "27.2.1", "10.6p1"),
            ),
            (
                "an older client",
                host("linux", "x86_64", "6.8.0-147-generic", "9.5p1"),
            ),
            (
                "an older Windows build",
                host("windows", "x86_64", "10.0.22631.4890", "9.5p2"),
            ),
            (
                "another architecture",
                host("linux", "aarch64", "6.8.0-147-generic", "9.6p1"),
            ),
            (
                "another build",
                HostFacts {
                    signer_build: "0.1.0-m04".to_owned(),
                    ..mac.clone()
                },
            ),
            (
                "a build that only compares equal as a number",
                HostFacts {
                    signer_build: "0.1.0-m1".to_owned(),
                    ..mac.clone()
                },
            ),
            (
                "no OS release",
                HostFacts {
                    os_release: None,
                    ..mac.clone()
                },
            ),
            (
                "no verified client",
                HostFacts {
                    client_version: None,
                    ..mac.clone()
                },
            ),
        ] {
            assert!(fields(&h).is_empty(), "{what}: {:?}", fields(&h));
        }
    }

    #[test]
    fn table_holds_no_custody_claim() {
        // ⟨M03 claim update⟩ Only the A07 and A23 fields, from debug-profile runs: no custody field.
        assert!(!CLAIMS.is_empty());
        for c in CLAIMS {
            assert!(!CUSTODY_FIELDS.contains(&c.field), "{c:?}");
            assert!(c.record.starts_with("tests/evidence/m03-a"), "{c:?}");
        }
        let p = Platform {
            os: "macos",
            arch: "aarch64",
        };
        assert_eq!(claims_for("lock_continuity", &p).count(), 0);
        assert_eq!(product_store_kinds("windows"), ["windows_dpapi"]);
        assert!(product_store_kinds("plan9").is_empty());
    }

    /// The residual IDs an ADR text names. **Recognition rule** (ADR-0008 §17.35 item 3):
    /// a backticked snake_case token (lowercase ASCII letters and digits, at least one
    /// `_`) whose opening backtick is preceded, after one space, by the word `residual`
    /// (any case, as in "the named residual `x`") or by `` `RESIDUALS` gains `` or
    /// `` `RESIDUALS` entry ``.
    fn adr_residual_ids(text: &str) -> Vec<String> {
        let snake = |t: &str| {
            t.contains('_')
                && t.starts_with(|c: char| c.is_ascii_lowercase())
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        };
        let mut out = Vec::new();
        let mut rest = text;
        let mut before_len = 0;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            let token = &after[..close];
            let before = &text[..before_len + open];
            let lower = before.to_ascii_lowercase();
            let named = lower.ends_with(" residual ")
                || lower.ends_with("\nresidual ")
                || lower == "residual "
                || before.ends_with("`RESIDUALS` gains ")
                || before.ends_with("`RESIDUALS` entry ");
            if named && snake(token) {
                out.push(token.to_owned());
            }
            before_len += open + 1 + close + 1;
            rest = &after[close + 1..];
        }
        out
    }

    #[test]
    fn adr_residual_recognition_rule() {
        let t = "The named residual `a_b` and `RESIDUALS` gains `c_d` (and `RESIDUALS` entry `e_f`); \
                 not `g_h`, not residual `Not_Snake`, not a residual: `i_j`.";
        assert_eq!(adr_residual_ids(t), ["a_b", "c_d", "e_f"]);
    }

    /// `every_adr_named_residual_is_listed` (ADR-0008 §17.35 item 3, W5-G03): every
    /// residual ID an ADR names ([`adr_residual_ids`] over `docs/decisions/*.md`) is a
    /// [`RESIDUALS`] entry.
    #[test]
    fn every_adr_named_residual_is_listed() {
        let root = heimdall_testkit::repo::repo_root();
        let dir = root.join("docs/decisions");
        let mut named = Vec::new();
        for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let p = e.unwrap_or_else(|e| panic!("{e}")).path();
            if p.extension().is_some_and(|x| x == "md") {
                let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{e}"));
                named.extend(
                    adr_residual_ids(&text)
                        .into_iter()
                        .map(|id| (p.clone(), id)),
                );
            }
        }
        assert!(
            named
                .iter()
                .any(|(_, id)| id == "uninstall_fence_release_stuck_until_holder_work_ends"),
            "the rule finds ADR-0008 §17.35 item 3's residual"
        );
        for (p, id) in &named {
            assert!(
                RESIDUALS.iter().any(|r| r.id == id),
                "{} names the residual {id}, which RESIDUALS does not list",
                p.display()
            );
        }
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
