//! ⟨M04⟩ Store methods for platform realization (ADR-0010 §9 item 1; ADR-0006 revision 5
//! §17; joint wave 0). Schema: `migrations/0007_platform_realization.sql`.
//!
//! Conventions (as [`crate::ext`]): every method runs inside the caller's [`Txn`]; reads
//! return `Option`/`Vec`; the store reads no clock (every instant is the caller's).
//! Every write that changes the managed-environment set moves the authority generation
//! in the same transaction (as environment and policy writes do, ADR-0006 §13.7 item 5),
//! so re-validation runs against the new set.

use heimdall_contract::environment::DistributionGuid;
use heimdall_contract::ids::EnvironmentId;
use heimdall_domain::environment::{
    EnvironmentAdmission, ManagedEnvironment, ManagedState, WslDistributionRecord,
    admit_environment,
};

use crate::{Result, StoreError, Txn, codec};

fn state_str(s: ManagedState) -> Result<String> {
    match serde_json::to_value(s)? {
        serde_json::Value::String(v) => Ok(v),
        _ => Err(codec::doc_error("managed state is not a string")),
    }
}

fn kind_str(m: &ManagedEnvironment) -> Result<String> {
    match serde_json::to_value(m.kind())? {
        serde_json::Value::String(v) => Ok(v),
        _ => Err(codec::doc_error("environment kind is not a string")),
    }
}

impl Txn<'_> {
    /// Insert a managed environment. Its ID must be new: a removed or gone identity is
    /// never re-added ([`StoreError::GenerationConflict`]), and nor is the runtime's own
    /// environment. Moves the authority generation.
    pub fn insert_managed_environment(&mut self, env: &ManagedEnvironment) -> Result<()> {
        if self.self_environment()?.as_ref() == Some(&env.environment) {
            return Err(StoreError::GenerationConflict(
                "the runtime's own environment is not a managed row".into(),
            ));
        }
        if self.managed_environment(&env.environment)?.is_some() {
            return Err(StoreError::GenerationConflict(
                "the managed environment already exists".into(),
            ));
        }
        self.tx.execute(
            "INSERT INTO managed_environments
                 (environment_id, controller, kind, state, record_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                env.environment.as_str(),
                env.controller.as_str(),
                kind_str(env)?,
                state_str(env.state)?,
                codec::doc(env)?,
                codec::ts(env.updated_at),
            ],
        )?;
        self.bump_generation()
    }

    /// One managed environment's row, whatever its state.
    pub fn managed_environment(
        &mut self,
        id: &EnvironmentId,
    ) -> Result<Option<ManagedEnvironment>> {
        self.one_doc(
            "SELECT record_json FROM managed_environments WHERE environment_id = ?1",
            [id.as_str()],
        )
    }

    /// Every managed environment row (any state), ordered by ID.
    pub fn managed_environments(&mut self) -> Result<Vec<ManagedEnvironment>> {
        self.docs(
            "SELECT record_json FROM managed_environments ORDER BY environment_id",
            [],
        )
    }

    /// Move a managed environment to `to` with compare-and-swap on `expected`. A removed
    /// or gone row never returns to the set (`removed`/`gone` are terminal, except
    /// `removed → gone`). Moves the authority generation. Returns the row as stored.
    pub fn set_managed_environment_state(
        &mut self,
        id: &EnvironmentId,
        expected: ManagedState,
        to: ManagedState,
        at: heimdall_contract::Timestamp,
    ) -> Result<ManagedEnvironment> {
        let Some(mut row) = self.managed_environment(id)? else {
            return Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        };
        if row.state != expected {
            return Err(StoreError::GenerationConflict(
                "the managed environment's state moved".into(),
            ));
        }
        let allowed = match (expected, to) {
            (a, b) if a == b => true,
            (ManagedState::Active | ManagedState::NotRunning, _) => true,
            (ManagedState::Removed, ManagedState::Gone) => true,
            _ => false,
        };
        if !allowed {
            return Err(StoreError::GenerationConflict(
                "a removed environment never returns to the set".into(),
            ));
        }
        row.state = to;
        row.updated_at = at;
        self.tx.execute(
            "UPDATE managed_environments SET state = ?2, record_json = ?3, updated_at = ?4
             WHERE environment_id = ?1",
            rusqlite::params![
                id.as_str(),
                state_str(to)?,
                codec::doc(&row)?,
                codec::ts(at)
            ],
        )?;
        self.bump_generation()?;
        Ok(row)
    }

    /// ⟨ADR-0010 §9 item 1⟩ Whether `target` is in this runtime's managed set, read inside
    /// the caller's transaction: the replacement of every `target == own` check. `own` is
    /// the runtime's own environment (`OperationsConfig.environment`, equal to
    /// [`Txn::self_environment`]).
    pub fn admit_environment(
        &mut self,
        own: &EnvironmentId,
        target: &EnvironmentId,
    ) -> Result<EnvironmentAdmission> {
        if target == own {
            return Ok(EnvironmentAdmission::Managed);
        }
        let row = self.managed_environment(target)?;
        Ok(admit_environment(own, target, row.as_ref()))
    }

    /// The environments in this runtime's managed set: `own` first, then every row it
    /// controls in an in-set state, by ID.
    pub fn managed_set(&mut self, own: &EnvironmentId) -> Result<Vec<EnvironmentId>> {
        let mut out = vec![own.clone()];
        for row in self.managed_environments()? {
            if row.controller == *own && row.state.in_set() {
                out.push(row.environment);
            }
        }
        Ok(out)
    }

    /// Insert or replace a WSL distribution record.
    pub fn put_wsl_distribution(&mut self, rec: &WslDistributionRecord) -> Result<()> {
        self.tx.execute(
            "INSERT INTO wsl_distributions (guid, record_json, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(guid) DO UPDATE SET record_json = excluded.record_json,
                 updated_at = excluded.updated_at",
            rusqlite::params![
                rec.guid.as_str(),
                codec::doc(rec)?,
                codec::ts(rec.updated_at)
            ],
        )?;
        Ok(())
    }

    /// One WSL distribution record.
    pub fn wsl_distribution(
        &mut self,
        guid: &DistributionGuid,
    ) -> Result<Option<WslDistributionRecord>> {
        self.one_doc(
            "SELECT record_json FROM wsl_distributions WHERE guid = ?1",
            [guid.as_str()],
        )
    }

    /// Every WSL distribution record, by GUID.
    pub fn wsl_distributions(&mut self) -> Result<Vec<WslDistributionRecord>> {
        self.docs(
            "SELECT record_json FROM wsl_distributions ORDER BY guid",
            [],
        )
    }
}
