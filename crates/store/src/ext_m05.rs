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

use heimdall_contract::ids::DecisionId;
use heimdall_contract::ids::{
    AccountName, BindingId, DestinationId, EnvironmentId, PolicyId, WorkId, WorkspaceId,
};
use heimdall_domain::policy::PolicyRevision;
use heimdall_domain::policy::StandingPolicy;
use heimdall_domain::workspace::{
    BindingContext, DecisionBasis, DecisionCooldown, PolicyHistoryEntry, SlotReference, WorkStop,
    WorkspaceRecord, WorkspaceState,
};
use rusqlite::OptionalExtension as _;

use crate::{Result, StoreError, Txn, codec};

fn conflict(what: &str) -> StoreError {
    StoreError::GenerationConflict(what.into())
}

fn state_str(s: WorkspaceState) -> Result<String> {
    codec::enum_str(&s)
}

/// ⟨M05 U2⟩ The `meta` key prefix of a pending decision's [`DecisionBasis`]: an internal
/// bookkeeping row beside the decision record (no schema change; never part of the
/// record's wire form).
const META_M05_DECISION_BASIS: &str = "m05_decision_basis:";

fn basis_key(id: &DecisionId) -> String {
    format!("{META_M05_DECISION_BASIS}{}", id.as_str())
}

/// ⟨M05; review M05-W4F-R01⟩ The `meta` key prefix of an imported destination whose route is
/// pending: a destination a portable bundle names as reached through a jump is recorded as
/// observed with this row (the jump destination's ID), so it keeps its route intent, is never
/// launched by its bare alias, and exports with its jump, until the owner defines it here.
const META_M05_ROUTE_PENDING: &str = "m05_route_pending:";

fn route_pending_key(id: &DestinationId) -> String {
    format!("{META_M05_ROUTE_PENDING}{}", id.as_str())
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

    // --- ⟨M05 U2⟩ policies: listing and removal ----------------------------------------

    /// Every standing policy, by ID (`inspect policies`; the default-flag rule).
    pub fn policies(&mut self) -> Result<Vec<StandingPolicy>> {
        self.docs("SELECT record_json FROM policies ORDER BY id", [])
    }

    /// Delete a standing policy (`policy remove`, a narrowing). Returns whether one existed.
    /// Moves the authority generation when it did (every policy write does, ADR-0006 §13.6
    /// item 5), so the grants resting on it re-validate against what remains. Its history
    /// rows stay (they are the record of what was applied).
    pub fn delete_policy(&mut self, id: &PolicyId) -> Result<bool> {
        let n = self
            .tx
            .execute("DELETE FROM policies WHERE id = ?1", [id.as_str()])?;
        if n > 0 {
            self.bump_generation()?;
        }
        Ok(n > 0)
    }

    // --- ⟨M05; review M05-W4F-R01⟩ imported routes pending ---------------------------

    /// Record that `destination` (an observed destination an import added) must be reached
    /// through `jump`, whose route is not set up here yet. Catalog intent: it moves nothing.
    pub fn put_route_pending(
        &mut self,
        destination: &DestinationId,
        jump: &DestinationId,
    ) -> Result<()> {
        self.set_meta(&route_pending_key(destination), jump.as_str())
    }

    /// The jump an imported destination's route is pending on, when one is recorded.
    pub fn route_pending(&mut self, destination: &DestinationId) -> Result<Option<DestinationId>> {
        self.meta(&route_pending_key(destination))?
            .map(|v| {
                DestinationId::parse(&v)
                    .map_err(|_| StoreError::Corrupt("a pending route names no destination".into()))
            })
            .transpose()
    }

    /// Clear a destination's pending route (the owner defined or removed it). Returns whether
    /// one existed.
    pub fn delete_route_pending(&mut self, destination: &DestinationId) -> Result<bool> {
        Ok(self.tx.execute(
            "DELETE FROM meta WHERE key = ?1",
            [route_pending_key(destination)],
        )? > 0)
    }

    // --- ⟨M05 U2⟩ decision bases ------------------------------------------------------

    /// Record what a pending decision was created from (ADR-0011 I5), in the transaction
    /// that inserts the record; replaces an earlier basis of the same decision. Does not
    /// move the authority generation.
    pub fn put_decision_basis(&mut self, id: &DecisionId, basis: &DecisionBasis) -> Result<()> {
        self.set_meta(&basis_key(id), &codec::doc(basis)?)
    }

    /// A decision's basis, when one is recorded.
    pub fn decision_basis(&mut self, id: &DecisionId) -> Result<Option<DecisionBasis>> {
        self.meta(&basis_key(id))?
            .as_deref()
            .map(codec::parse_doc)
            .transpose()
    }

    /// Delete a decision's basis (the record was consumed). Returns whether one existed.
    pub fn delete_decision_basis(&mut self, id: &DecisionId) -> Result<bool> {
        Ok(self
            .tx
            .execute("DELETE FROM meta WHERE key = ?1", [basis_key(id)])?
            > 0)
    }

    /// Delete the basis of every decision that is no longer pending (or no longer exists):
    /// an expired, stale or withdrawn record is never completed, so its basis is dead
    /// weight. Returns how many were deleted.
    pub fn prune_decision_bases(&mut self) -> Result<usize> {
        let keys: Vec<String> = {
            let mut stmt = self
                .tx
                .prepare("SELECT key FROM meta WHERE substr(key, 1, ?1) = ?2")?;
            let rows = stmt.query_map(
                rusqlite::params![
                    codec::int(META_M05_DECISION_BASIS.len() as u64)?,
                    META_M05_DECISION_BASIS
                ],
                |r| r.get::<_, String>(0),
            )?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut n = 0;
        for key in keys {
            let live = match key
                .strip_prefix(META_M05_DECISION_BASIS)
                .and_then(|id| DecisionId::parse(id).ok())
            {
                Some(id) => self
                    .decision(&id)?
                    .is_some_and(|d| d.state == heimdall_domain::decision::DecisionState::Pending),
                None => false,
            };
            if !live {
                n += self.tx.execute("DELETE FROM meta WHERE key = ?1", [&key])?;
            }
        }
        Ok(n)
    }
}

// --- ⟨M05⟩ U6: the default-profile catalog preference (ADR-0011 §5.1) ---------------------

use heimdall_contract::ids::ProfileId;

/// The `meta` key of `environment`'s default-profile preference.
fn default_profile_key(environment: &EnvironmentId) -> String {
    format!(
        "{}{}",
        crate::ext_m03::META_DEFAULT_PROFILE_PREFIX,
        environment.as_str()
    )
}

impl Txn<'_> {
    /// ⟨M05⟩ U6: `environment`'s default-profile catalog preference (ADR-0011 §5.1), when
    /// one is set. Read only by a new request that omits its profile; a binding never
    /// reads it (R-AU-03). A stored value that is not a profile ID is
    /// [`StoreError::Corrupt`].
    pub fn default_profile(&mut self, environment: &EnvironmentId) -> Result<Option<ProfileId>> {
        self.meta(&default_profile_key(environment))?
            .map(|v| {
                ProfileId::parse(&v)
                    .map_err(|_| StoreError::Corrupt("stored default profile is malformed".into()))
            })
            .transpose()
    }

    /// ⟨M05⟩ U6: set `environment`'s default-profile preference to `profile`, replacing
    /// any earlier one. A preference, not authority: it does not move the authority
    /// generation, and no binding or grant is touched.
    pub fn set_default_profile(
        &mut self,
        environment: &EnvironmentId,
        profile: &ProfileId,
    ) -> Result<()> {
        self.set_meta(&default_profile_key(environment), profile.as_str())
    }

    /// ⟨M05⟩ U6: clear `environment`'s default-profile preference. Returns whether one
    /// was set.
    pub fn clear_default_profile(&mut self, environment: &EnvironmentId) -> Result<bool> {
        let key = default_profile_key(environment);
        let existed = self.meta(&key)?.is_some();
        self.delete_meta(&key)?;
        Ok(existed)
    }
}
