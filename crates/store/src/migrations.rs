//! Versioned, transactional schema migrations (spec §13.3 "Migration must be
//! transactional and backed up").

/// Schema version this build writes and the highest it reads.
pub const SCHEMA_VERSION: u32 = 1;

/// A migration step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Target schema version after this step.
    pub version: u32,
    /// Human name.
    pub name: &'static str,
    /// SQL executed inside one transaction.
    pub sql: &'static str,
}

/// All steps in order.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "init",
    sql: include_str!("../migrations/0001_init.sql"),
}];

/// Apply pending migrations to `conn`. Before the first pending step on a file-backed
/// database the caller must have written a backup copy. Refuses to run when the
/// on-disk version exceeds [`SCHEMA_VERSION`].
pub fn apply(
    _conn: &mut rusqlite::Connection,
    _faults: &dyn crate::FaultHook,
) -> crate::Result<u32> {
    todo!(
        "M01-T03: read user_version, apply MIGRATIONS[current..] each in a transaction, set user_version"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_contiguous_from_one() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(m.version as usize, i + 1);
            assert!(!m.sql.trim().is_empty());
        }
        assert_eq!(MIGRATIONS.last().map(|m| m.version), Some(SCHEMA_VERSION));
    }
}
