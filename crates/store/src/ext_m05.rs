//! ⟨M05⟩ Store methods for trusted work (ADR-0011 §9 "Store" and §10 item 5; m05-plan §4
//! item 12 and U0; joint wave 0). Schema: `migrations/0008_trusted_work.sql`.
//!
//! Conventions (as [`crate::ext_m03`]): every method runs inside the caller's [`Txn`];
//! reads return `Option`/`Vec`; the store reads no clock (every instant is the caller's);
//! inserting a record whose key already exists is a [`StoreError::GenerationConflict`]
//! and writes nothing; a stale compare-and-swap is a [`StoreError::GenerationConflict`]
//! and writes nothing; updating or deleting through a key that does not exist is
//! `StoreError::Sqlite(QueryReturnedNoRows)` where a method says so.
//!
//! **Authority generation.** A write that widens or narrows authority moves the
//! authority generation in the same transaction (as environment and policy writes do,
//! ADR-0006 §13.7 item 5), so re-validation runs against the new record: a workspace
//! insert, a workspace state change, and a work-stop insert. Policy history, decision
//! cooldowns, slot references and a binding's context are bookkeeping written in the
//! same transaction as the policy or binding change that already moves the generation,
//! so they do not move it themselves.

use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, EnvironmentId, PolicyId, WorkId, WorkspaceId,
};
use heimdall_domain::policy::PolicyRevision;
use heimdall_domain::workspace::{
    BindingContext, DecisionCooldown, PolicyHistoryEntry, SlotReference, WorkStop, WorkspaceRecord,
    WorkspaceState,
};
use rusqlite::OptionalExtension as _;

use crate::{Result, StoreError, Txn, codec};

fn conflict(what: &str) -> StoreError {
    StoreError::GenerationConflict(what.into())
}

fn state_str(s: WorkspaceState) -> Result<String> {
    codec::enum_str(&s)
}

impl Txn<'_> {
    // --- workspaces -----------------------------------------------------------------

    /// Insert a workspace record. Its ID must be new
    /// ([`StoreError::GenerationConflict`] otherwise). Moves the authority generation.
    pub fn insert_workspace(&mut self, rec: &WorkspaceRecord) -> Result<()> {
        if self.workspace(&rec.id)?.is_some() {
            return Err(conflict("the workspace already exists"));
        }
        self.tx.execute(
            "INSERT INTO workspaces (id, environment, root, state, record_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                rec.id.as_str(),
                rec.environment.as_str(),
                rec.root,
                state_str(rec.state)?,
                codec::doc(rec)?,
                codec::ts(rec.created_at),
            ],
        )?;
        self.bump_generation()
    }

    /// One workspace record, whatever its state.
    pub fn workspace(&mut self, id: &WorkspaceId) -> Result<Option<WorkspaceRecord>> {
        self.one_doc(
            "SELECT record_json FROM workspaces WHERE id = ?1",
            [id.as_str()],
        )
    }

    /// Every workspace record of an environment (any state), by ID.
    pub fn workspaces_in_environment(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Vec<WorkspaceRecord>> {
        self.docs(
            "SELECT record_json FROM workspaces WHERE environment = ?1 ORDER BY id",
            [environment.as_str()],
        )
    }

    /// Move a workspace to `to` with compare-and-swap on `expected`. The only change of
    /// state is `active → stale`: a stale record is never matched again, so it never
    /// returns to `active` (a new decision writes a new record). A missing record is
    /// `QueryReturnedNoRows`; a stale expectation or a refused move is
    /// [`StoreError::GenerationConflict`]. Moves the authority generation. Returns the
    /// record as stored.
    pub fn set_workspace_state(
        &mut self,
        id: &WorkspaceId,
        expected: WorkspaceState,
        to: WorkspaceState,
    ) -> Result<WorkspaceRecord> {
        let Some(mut row) = self.workspace(id)? else {
            return Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        };
        if row.state != expected {
            return Err(conflict("the workspace's state moved"));
        }
        if expected != to
            && !matches!(
                (expected, to),
                (WorkspaceState::Active, WorkspaceState::Stale)
            )
        {
            return Err(conflict("a stale workspace never returns to active"));
        }
        row.state = to;
        self.tx.execute(
            "UPDATE workspaces SET state = ?2, record_json = ?3 WHERE id = ?1",
            rusqlite::params![id.as_str(), state_str(to)?, codec::doc(&row)?],
        )?;
        self.bump_generation()?;
        Ok(row)
    }

    // --- policy history -------------------------------------------------------------

    /// Append one applied policy change. A second entry for the same (policy, revision)
    /// is refused ([`StoreError::GenerationConflict`]). Does not move the authority
    /// generation: the policy write it accompanies does.
    pub fn append_policy_history(&mut self, entry: &PolicyHistoryEntry) -> Result<()> {
        if self
            .policy_history_entry(&entry.policy, entry.revision)?
            .is_some()
        {
            return Err(conflict("the policy revision is already in the history"));
        }
        self.tx.execute(
            "INSERT INTO policy_history (policy_id, revision, record_json, at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                entry.policy.as_str(),
                codec::int(entry.revision.0)?,
                codec::doc(entry)?,
                codec::ts(entry.at),
            ],
        )?;
        Ok(())
    }

    /// One history entry.
    pub fn policy_history_entry(
        &mut self,
        policy: &PolicyId,
        revision: PolicyRevision,
    ) -> Result<Option<PolicyHistoryEntry>> {
        self.one_doc(
            "SELECT record_json FROM policy_history WHERE policy_id = ?1 AND revision = ?2",
            rusqlite::params![policy.as_str(), codec::int(revision.0)?],
        )
    }

    /// A policy's history, oldest revision first.
    pub fn policy_history(&mut self, policy: &PolicyId) -> Result<Vec<PolicyHistoryEntry>> {
        self.docs(
            "SELECT record_json FROM policy_history WHERE policy_id = ?1 ORDER BY revision",
            [policy.as_str()],
        )
    }

    // --- decision cooldowns ---------------------------------------------------------

    /// Insert or replace a cooldown, by its key. Does not move the authority generation.
    pub fn put_decision_cooldown(&mut self, c: &DecisionCooldown) -> Result<()> {
        self.tx.execute(
            "INSERT INTO decision_cooldowns (key, policy_id, until, record_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET policy_id = excluded.policy_id,
                 until = excluded.until, record_json = excluded.record_json",
            rusqlite::params![c.key, c.policy.as_str(), codec::ts(c.until), codec::doc(c)?],
        )?;
        Ok(())
    }

    /// One cooldown by its key.
    pub fn decision_cooldown(&mut self, key: &str) -> Result<Option<DecisionCooldown>> {
        self.one_doc(
            "SELECT record_json FROM decision_cooldowns WHERE key = ?1",
            [key],
        )
    }

    /// Delete a cooldown. Returns whether a row existed.
    pub fn delete_decision_cooldown(&mut self, key: &str) -> Result<bool> {
        Ok(self
            .tx
            .execute("DELETE FROM decision_cooldowns WHERE key = ?1", [key])?
            > 0)
    }

    /// A policy's cooldowns, by key.
    pub fn decision_cooldowns_for_policy(
        &mut self,
        policy: &PolicyId,
    ) -> Result<Vec<DecisionCooldown>> {
        self.docs(
            "SELECT record_json FROM decision_cooldowns WHERE policy_id = ?1 ORDER BY key",
            [policy.as_str()],
        )
    }

    // --- work stops -----------------------------------------------------------------

    /// Record a work ID as stopped. Insert-once: a stopped work ID never un-stops, so a
    /// second insert is [`StoreError::GenerationConflict`] and there is no delete. Moves
    /// the authority generation.
    pub fn insert_work_stop(&mut self, stop: &WorkStop) -> Result<()> {
        if self.work_stop(&stop.environment, &stop.work_id)?.is_some() {
            return Err(conflict("the work ID is already stopped"));
        }
        self.tx.execute(
            "INSERT INTO work_stops (environment, work_id, stopped_at, record_json)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                stop.environment.as_str(),
                stop.work_id.as_str(),
                codec::ts(stop.stopped_at),
                codec::doc(stop)?,
            ],
        )?;
        self.bump_generation()
    }

    /// A work ID's stop record, when it is stopped.
    pub fn work_stop(
        &mut self,
        environment: &EnvironmentId,
        work_id: &WorkId,
    ) -> Result<Option<WorkStop>> {
        self.one_doc(
            "SELECT record_json FROM work_stops WHERE environment = ?1 AND work_id = ?2",
            [environment.as_str(), work_id.as_str()],
        )
    }

    // --- slot references ------------------------------------------------------------

    /// Add a binding's reference to a shared slot. A second reference by the same
    /// binding to the same slot is [`StoreError::GenerationConflict`]; the binding must
    /// exist (a foreign-key error otherwise). Does not move the authority generation.
    pub fn add_slot_reference(&mut self, r: &SlotReference) -> Result<()> {
        let exists: bool = self.tx.query_row(
            "SELECT count(*) > 0 FROM slot_references
             WHERE environment_id = ?1 AND destination_id = ?2 AND account = ?3
               AND binding_id = ?4",
            [
                r.environment.as_str(),
                r.destination.as_str(),
                r.account.as_str(),
                r.binding.as_str(),
            ],
            |row| row.get(0),
        )?;
        if exists {
            return Err(conflict("the binding already references the slot"));
        }
        self.tx.execute(
            "INSERT INTO slot_references
                 (environment_id, destination_id, account, binding_id, deadline, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                r.environment.as_str(),
                r.destination.as_str(),
                r.account.as_str(),
                r.binding.as_str(),
                codec::ts(r.deadline),
                codec::doc(r)?,
            ],
        )?;
        Ok(())
    }

    /// Remove a binding's reference to a slot. Returns whether a row existed.
    pub fn remove_slot_reference(
        &mut self,
        environment: &EnvironmentId,
        destination: &DestinationId,
        account: &AccountName,
        binding: &BindingId,
    ) -> Result<bool> {
        Ok(self.tx.execute(
            "DELETE FROM slot_references
             WHERE environment_id = ?1 AND destination_id = ?2 AND account = ?3
               AND binding_id = ?4",
            [
                environment.as_str(),
                destination.as_str(),
                account.as_str(),
                binding.as_str(),
            ],
        )? > 0)
    }

    /// The references to one slot, by binding ID.
    pub fn slot_references(
        &mut self,
        environment: &EnvironmentId,
        destination: &DestinationId,
        account: &AccountName,
    ) -> Result<Vec<SlotReference>> {
        self.docs(
            "SELECT record_json FROM slot_references
             WHERE environment_id = ?1 AND destination_id = ?2 AND account = ?3
             ORDER BY binding_id",
            [environment.as_str(), destination.as_str(), account.as_str()],
        )
    }

    /// The slots one binding references, by slot key.
    pub fn slot_references_for_binding(
        &mut self,
        binding: &BindingId,
    ) -> Result<Vec<SlotReference>> {
        self.docs(
            "SELECT record_json FROM slot_references WHERE binding_id = ?1
             ORDER BY environment_id, destination_id, account",
            [binding.as_str()],
        )
    }

    // --- binding context ------------------------------------------------------------

    /// A binding's context; `None` when none is recorded (the column is `NULL`, which
    /// means personal work) or the binding does not exist.
    pub fn binding_context(&mut self, binding: &BindingId) -> Result<Option<BindingContext>> {
        let s: Option<Option<String>> = self
            .tx
            .query_row(
                "SELECT context_json FROM bindings WHERE id = ?1",
                [binding.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        s.flatten().as_deref().map(codec::parse_doc).transpose()
    }

    /// Set a binding's context, once. A binding that does not exist is
    /// `QueryReturnedNoRows`; a second, different value is
    /// [`StoreError::GenerationConflict`] and writes nothing (the same value again is a
    /// no-op). Does not move the authority generation: the binding insert it
    /// accompanies does.
    pub fn set_binding_context(
        &mut self,
        binding: &BindingId,
        context: &BindingContext,
    ) -> Result<()> {
        if self.binding(binding)?.is_none() {
            return Err(StoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        }
        match self.binding_context(binding)? {
            Some(existing) if existing == *context => return Ok(()),
            Some(_) => return Err(conflict("the binding's context is already set")),
            None => {}
        }
        self.tx.execute(
            "UPDATE bindings SET context_json = ?2 WHERE id = ?1 AND context_json IS NULL",
            rusqlite::params![binding.as_str(), codec::doc(context)?],
        )?;
        Ok(())
    }
}
