# ADR-0014: Hardening and release artifacts (M08)

**Status:** accepted, revision 4 (its contract and storage deltas H1–H13 wait for the contract owner's handoff) · **Date:** 2026-11-22 · **Milestone:** M08 (T01–T06) · **Gate:** plan §5 M08, "all technical gate decisions recorded"; it also closes ADR-0004 §1 Q-D for the candidate.
**Decided by:** proposal of the M08 design unit; the orchestrator checked revision 4 against its rulings and accepted it on 2026-11-22 (ADR-0009: no further independent design re-check; the independent check of the restore protocol is U2b's implementation review). The soak-only supervision rule (§6.6) takes effect with this acceptance. Revision 2 applies the independent design review (Codex, REVISE, M08-D-R01–R10; `tests/evidence/artifacts/review-m08/design.md`) and the orchestrator's rulings of 2026-11-22 on Q1–Q11 and on each finding. Revision 3 applies the scoped re-check (Codex, NOT CLOSED: R01 and R02 open, RC-N01 new, R10 low; `tests/evidence/artifacts/review-m08/design-recheck.md`) under the orchestrator's rulings of 2026-11-22: a restore epoch with a replay fence, one durable generation switch, and a per-generation operation record. Revision 4 applies the second re-check (Codex, NOT CLOSED: N01 and N02 blocking, N03 moderate; `tests/evidence/artifacts/review-m08/design-recheck2.md`) under the orchestrator's rulings of 2026-11-22: the epoch stamped on every mutating request and the quiet period withdrawn; adoption fenced before it is published; the ledger digest over the full idempotency key. **Revision 4 is the last design round.** The orchestrator checks it against those rulings, and the independent check of the restore protocol moves to U2b's implementation review, where it meets real fault injection.
**Plan:** `docs/architecture/m08-plan.md`. **Probe record:** `tests/evidence/m08-probe-inventory-and-release-binary.json`.
**Affects:** R-RT-08, R-SE-05, R-SE-08, R-QU-03, R-QU-04, R-DI-01, R-DI-03, R-DI-04, R-DI-05, R-DI-07; through the exit cases also R-CR-03, R-CR-04, R-CR-06, R-RT-06 and R-AP-08.

**What this ADR does not do:** it applies no change to the public contract. Everything that would change it is in §7, as a proposal for the contract owner. §3.6 states the restore rule the orchestrator ruled; it becomes contract only when the contract owner lands delta H3.

**G09's record (ruling on Q7).** Gate G09 (expiry, multiplexing, clocks and revocation) has no ADR of its own. Its decision record is ADR-0008's effect table and deadline rules, ADR-0010 §5 for routes and forwarding, and M03's A23 record with A05, A07 and A08. The gate table cites these three; a G09 question none of them answers is recorded as open, not closed by this sentence.

## 1. Context

- **Plan §5 M08** asks for hostile-input hardening, a migration and update story, clean-machine artifacts, provenance, a benchmark table, a 72-hour soak, support bundles and runbooks.
- **Much of the destructive half exists** (m08-plan §1): uninstall and purge, the remote-enrollment inventory, migration backups, refusal of a corrupt or newer store, structural redaction, the release-build refusal of every test variable.
- **The constructive half does not:** no update or recovery path, no archive, no checksum, no inventory, no licence, no bundle, no release measurement.
- **Three facts bound the design:**
  - **Nothing is published** in M08, and no signing key is available to agents.
  - **A release build has no test hooks.** Its faults are applied from outside, and its static pass reads the account's real SSH configuration, so it runs only in a disposable account, container or VM.
  - **ADR-0009** limits review and testing to what is meaningful. §2.3 exists so that fuzzing cannot become the open-ended hardening M03 wave 5 was.

## 2. Hostile input: the boundary list and the stopping rule

### 2.1 Boundaries

A boundary is listed when its input can be written by someone other than the owner at their own terminal: a repository, a remote host, another account, another program, or a file the user was sent.

| # | Boundary | Entry point | Who writes the input | Existing tests | Available |
|---|---|---|---|---|---|
| 1 | OpenSSH client configuration | `sshconf::parse_file`, with `lex`, `include`, `eval` | the user's files, repositories, packages | `sshconf_hostile.rs`; `tests/model/sshconf_{parse,eval}.rs` | now |
| 2 | Git configuration edits | `sshconf::gitedit` | the user's files | `tests/model/sshconf_edit.rs`; `projection_git.rs` | now |
| 3 | Agent replies | `ipc::agent_client` (`exchange`, `parse_reply`); 256 KiB, 1024 identities | another program at the agent socket | `agent_client_frames.rs` | now |
| 4 | Control frames and requests | `ipc::frame::decode_frame`, `BoundedFrameCodec`, request deserialization; 16 KiB hello, 1 MiB after | any same-user program; a paired remote client through M06's bridge | `ipc_frames.rs` | now |
| 5 | Signing-endpoint frames | `ipc::signing` (`parse_sign_request`) | any consumer of a binding's endpoint, a forwarding peer | `agent_frames.rs` | now |
| 6 | Userauth and session-bind requests | `credential::purpose::parse_userauth`, `credential::session_bind` | a remote server, through the client | `signer_requests.rs` | now |
| 7 | The remote registry | `registry::hm1`, `registry::line`, `registry::classify` | a remote account's `authorized_keys`, editable by its administrator | `tests/model/registry_pure.rs` | now |
| 8 | The issuer protocol | `issuer::protocol` | the runtime; a program that reaches the issuer's channel | `issuer_child.rs`, `issuer_m03.rs` | now |
| 9 | Backup and recovery files | `issuer::backup`, `issuer::bundle`; 16 MiB | a file the user restores from | `issuer_ceremony.rs` | now |
| 10 | Project manifests and import bundles | `project::manifest`, `project::portable`; 1 MiB | a repository; a file the user imports | `tests/model/project_pure.rs`; `prompt_injection.rs` | now |
| 11 | Runtime configuration and the advertisement | `runtime::config`, `runtime::instance` | the user's files; a same-user program | `integration/runtime.rs` | now |
| 12 | Known-hosts files and `ssh -G` output | `localenv::known_hosts`; the `ssh -G` reader | the user's files; a hostile configuration through `ssh -G` | `sshconf_vs_ssh_g.rs` | now for the readers; the M06 route checks after M06 |
| 13 | M06's bridge and invitation records | `remote` (frames, the invitation state, the `sshd -T` verifier) | a paired client; a runner's sshd configuration | M06 U1's property and unit tests | after M06 |
| 14 | The route helper | the pre-identification buffer (8 KiB, 32 lines); allow-list and hint parsing in `transport-iroh` | a remote server or relay | M06 U5a, U6a | after M06 |
| 15 | Page tokens and selectors | M07's token decoder and selector parser | any client | M07 U3 | after M07 |

### 2.2 What is not fuzzed

- **Path operations** (symlink, replacement and FIFO races) are not byte parsers. They keep their example tests (M02 U3, M05 U4, the purge sweep) and are checked by spec §14.3's table (m08-plan §7.1).
- **Authority logic** is covered by the fixed-seed model suites under `tests/model/`. Their invariants are plan §6.3's; M08 adds none.
- **Platform FFI.** The modules that allow `unsafe` are inventoried for M09-T03's review. A Linux fuzz build does not reach Windows or macOS calls.

### 2.3 The stopping rule

For each target, on libFuzzer with its address sanitizer, an input length capped just above the boundary's own cap, a 10 s per-input timeout and a 1 GiB memory limit:

1. **Start** from the seeded corpus (the adversarial fixtures and the committed property-test regressions).
2. **Run at least 2 CPU-hours.**
3. **Stop when both hold:** no new coverage in the last 30 minutes, and no open finding.
4. **A finding** (a crash, a hang, a memory blow-up, or a parse that succeeds outside the boundary's documented bound) is minimized, fixed, and turned into a regression test on the pinned stable toolchain. The target then restarts from its saved corpus at step 2.
5. **The ceiling is 8 CPU-hours per target per candidate.** A target still finding coverage there stops anyway. Its coverage curve goes into the record as a residual, and the orchestrator decides whether it buys another round.
6. **A second fix round on one target** means the parser is simplified or bounded more tightly before it is patched again (ADR-0009 §2.1).

**Per candidate, and only where something changed.** Campaigns run on the W0 tree. On a candidate, a target is rerun only if its boundary's crate, a crate it parses through, or the fuzz build inputs changed since its last passing campaign; an unchanged target's earlier campaign is cited by commit. `check.sh` runs only the regressions.

**The ceiling is not a waiver.** New coverage at the ceiling is a residual. A known crash, hang or bound violation is never left open by it.

### 2.4 What a finding blocks

- **Every finding on a listed boundary is fixed before the exit.** A29's pass condition is "parsers bounded", so a crash or hang on outside input fails the case itself.
- **Whether it blocks a merge, and carries a revert proof, is ADR-0009 §2.1's rule,** unchanged.

## 3. Update, drain, rollback and migration recovery

### 3.1 Terms

- **Update:** the user runs a newer archive's install script. Heimdall never updates itself (spec §15.3).
- **Rollback:** the user puts the previous binary back.
- **Restore:** a new store generation is built from one of this installation's **own** backups, sanitized under §3.6, and made current.
- **Reset:** a new, empty store generation with a new environment identity is made current.
- **The store family:** the database file with its write-ahead log, shared-memory file and rollback journal. They are separate directory entries, so a family is never moved or renamed member by member.
- **A generation:** one directory holding exactly one store family and its operation record. **The pointer** (`CURRENT`) names the active generation.
- **The restore epoch:** a counter that every restore raises. Everything minted before a restore belongs to an older epoch.

### 3.2 Guaranteed, and tested (m08-plan §7.2)

1. **Stopping is graceful and bounded.** `service stop` lets in-flight requests settle or reports them, removes the endpoints and leaves the journal durable. What was in flight is recovered or reported after restart, as A17 already proves.
2. **The stop preview is read-only and complete.** Before a stop, the user can see what it interrupts (§3.3). The preview changes nothing.
3. **An update never changes identity or authority records:** the environment ID, policies, cutoffs, pauses, tombstones, the authority generation, enrollments, the catalog, and the references to protected keys.
4. **A migration is transactional and backed up first** (existing). It never makes a grant more active, moves a deadline later, clears a pause, or drops a tombstone. The migration ladder test checks this from every earlier exit build's store.
5. **After an update, nothing returns that had ended.** Unexpired, unrevoked grants are served again only under the existing re-issue rule (ADR-0005 §3.7).
6. **An existing store is never read as empty.** A damaged store, a newer store and an unreadable one each stop unsafe operations with a distinct reason and a named next step. Nothing is rewritten (existing for the store; new for the commands).
7. **An older binary refuses a newer store** and touches nothing (existing).
8. **Rollback with an unchanged schema** is the previous binary serving the same store, under items 3 and 5. **Adoption of the generation layout is a one-way boundary** (§3.6): once an installation's flat store has been fenced for adoption, a build that predates generations refuses it and touches nothing, whether or not the adoption finished. Going back past that boundary is not a rollback; it is a restore, or a reset. Every released build knows the layout, so the boundary lies only between pre-release builds and the first candidate.
9. **Restore keeps identity and ends or quarantines every recovered authority** (§3.6). Every interruption of a restore or a reset leaves either the intact old generation or the complete new one, decided by one pointer. **No request, operation or decision from before a restore runs or is approved after it.**
10. **Reset is never automatic.** It is attended, says that it creates a new identity, and first lists what it orphans: the remote enrollments, pairings and management lines read from the old store or, if that is unreadable, from the last recovery bundle. **When neither is readable, reset says so in plain words** ("Heimdall cannot list what this leaves behind on remote hosts"), names where such residue would live, and needs its own typed confirmation of that sentence. Under `--non-interactive` it refuses. The old generation is kept, never deleted or overwritten.
11. **Replacing the executable is staged and recoverable** (§4.3): at every point of an interrupted install there is a complete, matching executable (and, on Windows, helper) at the install path or beside it, and the script says which.
12. **Integration that names the executable keeps working after an update in place.** The login entry, the shell hook, the route helper and the WSL helper call a fixed install path (§4.3). An executable that has moved is a doctor finding with its repair command, never a silent break and never a silent rewrite of an entry Heimdall can no longer prove is its own.
13. **Uninstall is unchanged** (ADR-0007 §5.5, ADR-0008 D4, ADR-0010): owned local integration is removed, the user's SSH and Git files are restored byte for byte, and what remains is listed.

### 3.3 Disclosed, not prevented

Stopping the runtime, for an update or otherwise, interrupts what the preview lists:

- **New connections and signatures** through Heimdall's endpoints, until the runtime starts again.
- **Working keys held only in memory.** They are gone; grants are re-issued within their unchanged terms after restart.
- **Bindings with a live holder** (`heimdall run` children): the child keeps running; its endpoint is gone until restart.
- **Owned multiplexing masters and dedicated connections:** closed, or left to the client, as M03's deadline table states for each kind. A session already authenticated keeps carrying traffic.
- **WSL bridges and container endpoints:** unavailable inside the distribution or container until restart.
- **M06's transport and runner state:** a served Iroh endpoint stops; a runner whose runtime is down issues nothing.
- **On macOS without a Developer ID signature,** the issuer may lose access to its CA key after the update (the existing M03 note). The preview says so, and says whether an offline backup is recorded.

An emergency restart that cannot wait prints the same list (spec §15.2).

### 3.4 Reported as residue, not removed silently

| Residue | Where it is reported | Removed by |
|---|---|---|
| Migration backups (`<store>.v<N>.backup*`): old state with public metadata | `state status`; the stop preview; uninstall | `uninstall --purge-state`, or the user |
| Earlier store generations kept by a restore or a reset: the old state in full, each with a record saying what it is | `state status`; uninstall | `uninstall --purge-state`, or the user |
| A staged generation that never became current (an interrupted restore) | `state status` | start-up removes it; it holds nothing the current generation lacks |
| The previous binary (`heimdall.previous`) | the install script's output; uninstall | the next update, or uninstall |
| An orphaned macOS keychain item after a restore | `issuer status` (existing) | the user, in Keychain Access |
| A login entry or hook left at an old path | doctor (`executable_moved`) | the named repair command |
| Remote enrollments and M06 pairings | uninstall's inventory (existing; M06 adds pairings) | `enroll remove`, `environment remove`; never promised for an offline target |
| A Heimdall include block the owner moved to the other global Git file | the rollback's result (new; Git residual 1 of ADR-0007 §12.41) | the user |
| Conflict and quarantine copies, logs | uninstall (existing) | the user, or the purge |

### 3.5 Platform notes the tests cover

- **Windows:** a running image cannot be overwritten. The install script stops the runtime, renames the old executable aside and places the new one. A `heimdall run` child that still holds the old image keeps running on it.
- **Unix:** the replacement is an atomic rename in the install directory.
- **WSL:** the Linux helper is replaced with the Windows executable, as one step. A helper that speaks another channel version is already refused at the hello (`wsl/src/client.rs`); the update journey checks that a stale helper is reported and not used.

### 3.6 The restore rule (authority; ruled 2026-11-22; contract delta H3)

A backup is older than every stop, revocation, pause, cutoff, consumption and unpairing made after it. Restoring it unchanged would revive them, which R-RT-07 and plan §5 M08 forbid. **A restore therefore recovers identity and configuration, and no authority.**

**What a restore keeps:** the environment ID; the catalog (destinations, identities, profiles, routes); the enrollment and CA records; projection and setup records; host-key and endpoint pins, **as identity information only**; the event and operation history the backup holds, as history.

**What a restore ends or quarantines,** in the staged generation, before it can become current:

| Recovered state | After the restore |
|---|---|
| Grants and their references, bindings, managed slots, owned connections | Ended, with a tombstone each. Remote effects of ending them go through M06's pending-effects path and are reported as pending until acknowledged. None is dropped silently |
| Standing policies | Paused, with a cutoff at the restore time. Trust records for workspaces need a new attended trust |
| Pending decisions, including pending widening decisions | Closed as stale. None can be approved, and their references belong to the old epoch |
| Operations that were not terminal | Closed as stale (`restored_before_completion`). None resumes |
| Management clients (paired controllers, limited clients) | **Quarantined:** not admitted. Each needs explicit reauthorization at this machine, and for a runner, reconciliation with the runner's own record, before it is served |
| Invitations, pending or consumed | Void. A recovered pending invitation cannot be joined; a recovered consumed one grants nothing |
| Exposure and admission state (transport enablement, relay sets, allow-lists, serve leases) | Disabled. Enabling again is the same local decision as the first time |
| Paired environments | Shown as `held` until reconciled; an environment the current state records as unpaired stays unpaired |
| Issuers | A CA the current state records as retired stays retired. No issuance until the issuer's reconciliation barrier (ADR-0012 §7) has run |

**Carry-forward.** When the generation being replaced is still readable (a rollback, not a corruption), the restore reads it first, read-only, and:
- **keeps the more restrictive of the two states** for every revocation, retirement, unpairing, consumption, cutoff, pause, `owner_only` marker and downgrade marker (M06's restore rule for those markers, extended to the rest);
- **carries forward every terminal operation and idempotency record made after the backup,** so a retry of a request that completed gets its real recorded answer.

When it is not readable, everything recovered is treated as possibly revoked, which is what the table does, and the replay fence below takes the place of the missing records.

**The restore epoch and the replay fence** (the ruling on re-check R01).

1. **Every restore raises `restore_epoch`,** durably, in the staged generation and in its operation record, before the pointer moves. The hello reports it.
2. **Everything the server mints carries its epoch:** operation IDs, decision references and effect IDs. A reference from an older epoch that has no carried record is answered as stale (`restore_epoch_stale`), never as "not found" and never acted on. Approving an old decision reference is refused whatever happened in between.
3. **Every mutating request carries the restore epoch it was minted under** (the ruling on re-check N01). The caller reads the epoch from the hello of the session in which it mints the request ID, **binds the epoch to that ID at mint time,** and a retry reuses both. **The server refuses a mutating request whose epoch is not the current one** with `REQUEST_STALE` (reason `restore_epoch_stale`, next action: a new request under a fresh hello), **attended or not,** before any store write or effect. A retry of a pre-restore request therefore fails closed with no surviving evidence at all, and a request minted after a fresh hello carries the new epoch and proceeds. The CLI, the TUI, the reference wrapper and the harnesses follow the rule: wherever they persist or pass on a request ID for retry, the epoch travels with it.
   - **The residual, stated:** a caller that stamps an old request ID with a new epoch has broken the contract and is not protected by this step. The ledger below still catches it when the ledger or the old store survives.
4. **The request ledger** is the second line, for exactly that case and for answering a known retry precisely:
   - **what it is:** an append-only file in the state directory, **outside every generation.** Before a request's first durable store write, the runtime appends and syncs one fixed-size record: the epoch and a SHA-256 over the **canonically encoded full idempotency key** of ADR-0006 §7.1 as extended by ADR-0012 §3.7: principal, caller role, `remote_client`, operation kind and request ID (the ruling on N03). Two clients, two roles or two operation kinds using the same request ID have different digests. It holds no request content and no identifier in the clear;
   - **lookup:** a fence record in the store is keyed by the same digest, and the idempotency path computes the digest of an incoming key to find it;
   - **at a restore,** every ledger entry that has no terminal record in the staged generation (after the carry-forward, where that was possible) is written into the staged generation as a fence record whose stored answer is `REQUEST_STALE`, reason `restored_before_completion`. A retry is answered from it. **It is never executed again.**
   - **retention follows ADR-0006 §7.4 exactly,** for the ledger and for every carried or written fence: an unresolved key is kept indefinitely; a settled key runs its retention from settlement; the expired-key marker is kept 30 days more. Nothing is trimmed earlier, **including when only the ledger is readable:** a ledger entry whose settlement the restore cannot see is treated as unresolved and kept. The ledger is trimmed only by rewrite and rename under the instance lock, and only of entries whose marker window has ended.
5. **When the old generation and the ledger are both lost,** step 3 is the whole fence, and it is enough: every pre-restore mutating request carries an old epoch and is refused. No quiet period exists (revision 3's is withdrawn: attendance does not make an old request new, and a wait does not either).
6. **Reauthorization and reconciliation do not reopen anything.** Reauthorizing a quarantined client admits requests it mints **after** a fresh hello. Its pre-restore request IDs stay refused by their epoch and answered by their fence records, and its old decision references stay stale.
7. **Remote effects made after the backup:** the runner's own effect ledger is the authority during reconciliation (ADR-0012 §7). An effect the runner applied and the restored controller does not know is adopted as a fact, never sent again and never undone. Effect IDs minted after the restore carry the new epoch, so they cannot collide with one the runner already holds.

**Never, by any path:** a revoked grant active again; a retired issuer issuing; an unpaired environment paired; a revoked client's key, a consumed invitation, or a pre-restore request or decision reference accepted or run.

**Store generations: one durable switch** (the ruling on re-check R02 and RC-N01).

- **Layout.** Each store family lives alone in its own generation directory under the state directory, with a unique name that is never reused. A small pointer file, `CURRENT`, names the active generation. The instance lock and the request ledger stay in the state directory, outside every generation.
- **The operation record.** Every generation holds a small record, written and synced before the generation can become current: which operation created it (`install`, `adopt`, `restore` or `reset`), when, from which earlier generation and which backup (by digest), its environment ID and its restore epoch. Each migration applied to a generation is appended to its record. **The record is what distinguishes a completed reset from a completed restore and from a staged generation that never became current.** A generation without a complete record is not a candidate for anything.
- **Start-up trusts only the pointer.** It opens the generation `CURRENT` names, checks that generation's record, and serves it. It never chooses a generation by name, time or content, and never falls back to another one. A pointer that is unreadable or names a missing or record-less generation is `state_corrupt`: unsafe operations stop and the choices are named.
- **The switch.** The new pointer is written to a temporary file in the state directory, synced, and renamed over `CURRENT`. The rename is the only step that changes which state is live. On POSIX the state directory is then synced. **Before the switch,** the staged generation is complete and durable: its database is checkpointed and closed so that it has no write-ahead log or journal, the file and its record are synced, and its directory is synced.
- **No member is ever renamed or moved.** The earlier generation stays where it is, whole, under its own name. Nothing overwrites it. Repeated restores and resets accumulate generations, each with its record; all but the current one are residue.
- **Interruption.** Before the rename, `CURRENT` names the old generation, which was never touched: start-up serves it and removes the staged generation (and any leftover temporary pointer) as garbage. After the rename, `CURRENT` names the new generation, which was complete before the rename. There is no third state.
- **Platforms.** A same-volume rename over an existing file is atomic on POSIX file systems and on NTFS. Windows has no directory sync; there the rename is made with write-through, and the files are flushed before it. Either pointer value is a complete, safe state, so the design does not depend on which one survives a crash at the boundary. **Not established by any test:** durability across power loss. The fault tests kill the process and inject I/O errors; they cut no power. No reason was found that the single switch fails on macOS, Linux, WSL or Windows, so no per-member intent log is specified.
- **Adoption of today's layout: fence first, then publish** (the ruling on re-check N02). A store written by an earlier build sits directly in the state directory, with no pointer. A build that knows generations adopts it under the instance lock, in this order, each step durable before the next:
  1. **the intent:** a small adoption-intent file in the state directory, synced, naming the flat family and the generation to be created;
  2. **the fence:** the flat family's schema version is set, in one SQLite transaction, to a value no earlier build accepts. From here an older executable refuses that family and touches nothing;
  3. **the copy:** the new build, which reads the fenced family, stages a generation from a consistent copy of it and writes that generation's operation record (`adopt`), all synced;
  4. **the publication:** the pointer switch;
  5. **completion:** the intent is marked complete.

  **What each interruption leaves:** before step 2, the flat family is fully usable by any build, and the new build starts the adoption again. After step 2 and before step 4, an older build refuses the store (fail closed) and the newer build **resumes from the intent:** it discards any staged generation and repeats steps 3 to 5. After step 4, start-up follows the pointer and completes step 5. **Nothing relies on an older build understanding `CURRENT`.** The flat family is never moved and never served again; it is residue. This is the one-way boundary of §3.2 item 8.
- **Every copy and every read of a store goes through SQLite** (the orchestrator's ruling of 2026-11-22, after the soak rehearsal). While a runtime runs, and after any unclean stop, the store's state is in its write-ahead log: before the first checkpoint the main database file is a single 4 KiB page. So a backup, an adoption copy, a restore's staging copy, a carry-forward read and a support bundle's read each use SQLite's online backup, `VACUUM INTO`, or a connection that opens the whole family. **None copies or reads the main database file alone.** Today's two sites already comply: the migration backup is `VACUUM INTO` (`store/src/lib.rs`, `backup`), and uninstall's validating read copies the database with its write-ahead log (`uninstall_cmd.rs`, `read_family_no_write`). The lifecycle journey's kill-before-update variant checks the first one end to end.
- **Migration stays in place.** A schema migration runs inside its generation, in one SQLite transaction, after the existing backup, as today (tested). It does not create a generation. The note of it in the generation's record is completion metadata written after the transaction, rebuilt from the database's schema version if a crash loses it. It never selects a generation: only the pointer does.

**The restore protocol.**
1. **Identity binding.** A backup carries the environment ID of the store it was taken from. Restore refuses a file whose environment ID differs from the one in the current generation's operation record. Replacing the identity is reset, never restore. A file that is not a Heimdall backup, fails its integrity check, or is of a newer schema than the build is refused. For a store not yet adopted and unreadable, there is no record to bind to: restore is then attended only, shows the backup's environment ID, and accepts only a backup found under this installation's own backup names.
2. **Exclusion.** Restore runs only with the runtime and the issuer stopped, confirmed, and holds the runtime's own exclusive instance lock from before it reads anything until after the switch (the purge's rule, ADR-0008 §17.31 item 1).
3. **Staging.** A new generation directory is created. The backup is copied into it. Integrity checks, migration to the build's schema, the carry-forward, the whole sanitization above, the raised epoch and the fence records are applied **in the staged generation**, in one transaction. The carried terminal records, unresolved keys and expired-key markers keep their ADR-0006 §7.4 lifetimes.
4. **Completion.** The staged database is checkpointed and closed; the file, the operation record (`restore`) and the directory are synced.
5. **The switch,** as above.
6. **The report.** Restore lists what it ended, quarantined and voided, the requests it fenced (a count), whether the ledger was readable, what remote effects are pending, the remote residue it cannot remove, and the earlier generation it left behind.

**Reset** is the same switch with a different staged generation: an empty store, a new environment ID, epoch zero, and a record saying `reset` and naming the generation it replaced. A completed reset is a completed generation; nothing about it resembles an interrupted restore.

**Focused fault tests** (m08-plan U2b):
- backup → revoke a grant → restore → the grant stays ended, and a fixture login with its material is refused;
- backup → revoke a management client → restore → the client's key is refused until reauthorized;
- backup → an invitation is consumed (and, separately, expires) → restore → a join and a replay are refused;
- **backup → a request completes → the store becomes unreadable → restore → reauthorize → retry with the same request ID:** answered `REQUEST_STALE` from the fence record, never executed. The same with the old store readable: answered from the carried terminal record, never executed. Both are checked **after reopening and reauthorization,** not only while quarantined;
- backup → a decision is raised → restore → reauthorize → approving the old decision reference is refused;
- **the ledger and the old generation both lost:** backup → a request completes → both are destroyed → restore → reauthorize → the same request ID with its original epoch, sent attended and non-interactive: refused `REQUEST_STALE` both times, and the fixture adapter's ledger shows **no second effect.** A request minted after a fresh hello proceeds;
- equal request IDs from two clients, two roles and two operation kinds: each has its own ledger digest and its own fence; fencing one refuses none of the others;
- retention boundaries (ADR-0006 §7.4): an unresolved key's fence is still answered after any wait; a settled key's fence lasts its retention from settlement and then its 30-day marker; with only the ledger readable, no entry is dropped early;
- a runner applied an effect after the backup → restore → reconciliation adopts it, sends nothing twice;
- backup → retire an issuer, unpair an environment → restore → both stay so;
- a backup from another environment is refused, and nothing changes;
- **a kill and an I/O error before and after each sync and before and after the pointer rename** (the staged database's sync, the record's sync, the generation directory's sync, the temporary pointer's sync, the rename, the state directory's sync): each ends, after restart, in the intact old generation or the complete new one, and a staged leftover is removed;
- an unreadable pointer, and a pointer naming a missing or record-less generation, stop unsafe operations and never select another generation;
- **reset → restart** serves the new generation;
- **restore → restore → reset,** with every earlier generation retained: each has its own name and record, none is overwritten, start-up serves the last one;
- **adoption, a kill at each of its five steps → the older build is started (the rollback) → the newer build is started again:** before the fence the older build serves the flat store and the newer build then adopts it, including what the older build wrote; after the fence the older build refuses and writes nothing, and the newer build resumes from the intent; in no case is a revocation made by the older build missing afterwards.

## 4. Artifacts, provenance, inventory and licences

### 4.1 Targets

The matrix is m08-plan §4: macOS arm64, Linux x86-64 and arm64, Windows x86-64, with WSL2 served by the Linux binary and the Windows archive. One feature set per target, recorded in the build record.

### 4.2 The archive

One archive per target, named `heimdall-<version>-<target>`:

- the executable (and, in the Windows archive, the Linux x86-64 executable as the WSL helper);
- the install script for that platform;
- `LICENSE`, `THIRD-PARTY-NOTICES.txt`, `SECURITY.md`;
- `BUILD-RECORD.json`, the SBOM, and `MANIFEST.sha256` (§4.4);
- the release notes with the limitation statement, and the install, update, recovery, unenrollment and uninstall runbooks;
- **the compatibility matrix as of the candidate** (every provider × client × environment × mechanism row with its label, versions, record and limitation) and **the compatibility and deprecation policy**;
- **a reference configuration** (the documented `config.toml` with every default, and an example manifest) beside the public schemas and example payloads;
- the urgent-fix disclosure procedure, in `SECURITY.md`;
- `examples/` (M07's reference wrapper and harnesses) and `skills/heimdall/` (the optional skill, installed only by the user).

**Not in it:** test binaries, fixtures, anything from `heimdall-testkit`'s data, debug symbols, build-host paths.

### 4.3 Installation

- **A fixed per-user location** on each platform, the same across versions, so nothing that names the executable changes on update.
- **No elevation, no service installation, no edit of `PATH`, shell profiles or `~/.ssh`.** The script prints the line a user may add to their `PATH`. Everything else is `heimdall setup`, attended, as today.
- **Verification before installation is the user's step, against the external index** (§4.4): the runbook's first command checks the archive file against `SHA256SUMS` taken from the repository, before it is unpacked. The script cannot do this for itself: a replaced archive would carry a replaced script. The script does check the unpacked tree against `MANIFEST.sha256` before it copies anything, which catches a damaged or partial extraction, not tampering.
- **Replacement is staged and recoverable:**
  1. the new executable (and helper) are copied into the install directory under temporary names and synced;
  2. their digests are checked against the manifest;
  3. the current files are renamed to `heimdall.previous` (and the helper's equivalent), as a pair;
  4. the new files are renamed into place, as a pair, and the directory is synced.

  A failure in steps 1–2 leaves the installation untouched. A failure in steps 3–4 leaves a complete pair under one of the two names, and rerunning the script finishes or undoes the step. The executable and the WSL helper are never left at different versions without the script saying so.
- **An update** shows the stop preview first.

### 4.4 Digests and the build record

Three layers, none of which hashes itself:

1. **`MANIFEST.sha256`, inside the archive,** lists every file in the archive **except itself**. It is the payload manifest.
2. **`BUILD-RECORD.json`, inside the archive,** states the build inputs and the digests of the **executables only**: the commit and whether the tree was clean; the toolchain, target, profile, feature set and flags; the `Cargo.lock` digest; the builder's operating system; every packaging tool with its pinned version; the times. It holds no digest of itself, of the manifest or of the archive. The manifest lists it like any other file.
3. **`SHA256SUMS`, outside every archive,** is the checksum index: one line per finalized archive, and one per external record (each archive's SBOM and build record, copied out). It is written after the archives are final and never placed inside one.

- **The index and the external records are committed to the repository** under `tests/evidence/artifacts/m08/release/<version>/`. The archives are not uploaded. The repository's history is the anchor a user verifies against.
- **The binary reports the same commit, target and feature set about itself** (H7), and the artifact check compares them once H7 exists.
- **Build-host paths are remapped,** and the artifact check fails on a home path, a cargo or rustup path, or a checkout path (the probe recorded 297 on an unremapped macOS build). A bare user name is not a rule: the product's own identifiers may contain the repository owner's name.

### 4.5 The dependency inventory

- **Format:** CycloneDX JSON, one per target.
- **Source:** the graph cargo selects for **this package, this target and this feature set** (`-p heimdall --target <triple> --features <set>`, normal and build edges). Not the lock file (322 components for every target, no licences), and not a workspace-wide resolution: a workspace resolution enables features the binary's own build does not, and on macOS listed 234 third-party packages where the selected graph holds 209 (review M08-D-R04).
- **Tooling:** one pinned SBOM tool produces the document, and a small validation adapter checks it. The adapter compares the tool's component set with cargo's own selected graph for the same package, target and features, and with the packages the release build actually compiled. A component the selected graph lacks is removed and counted in the record; a selected package the tool missed fails the build. No new resolver is written.
- **Compiled is not linked.** Each component carries one role:
  - `target`: compiled for the target (it may or may not survive linking; the inventory does not claim to know);
  - `host`: a proc macro, a build script, or a dependency of one. It runs on the build machine and is not in the binary;
  - `test-support`: reaches the graph only through `heimdall-testkit` (14 to 16 crates today).

  No string scan of the binary is used as evidence about linkage.
- **Scope:** each component's version, source, checksum and licence expression; the bundled SQLite; vendored code under `third_party/`.
- **Test support is removed from the release graph before the candidate** (ruling on Q8): a small, explicit debug-support feature under the manifest's owner, so that a release build no longer compiles the test-only crates; the same release gate then runs with the selected features. Until that lands, those crates stay in the inventory with their role.
- **Advisories** stay with M06's audit gate. The candidate's record states the advisory database's date and every ignored advisory with its reason.

### 4.6 The licence policy

- **Allowed for linked code:** MIT, Apache-2.0 (with or without the LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, BSL-1.0, Unlicense, CC0-1.0. Where a crate offers a choice, a permitted alternative is selected and recorded.
- **Where the list comes from:** every licence the probe found on `main` (over a superset of the selected graph), plus ISC and CC0-1.0. M06's tree (iroh and its TLS stack) was not inventoried; U4a runs the policy on it, and any licence it needs beyond this list is a recorded decision, not a silent addition.
- **Recorded per-crate exception (2026-11-22, the orchestrator's ruling):** `webpki-roots`, which M06's `iroh` feature brings in, is the Mozilla root-certificate list as data, under CDLA-Permissive-2.0, a permissive data licence. It is allowed for that crate only (`deny.toml` names it, with the reason and the command that found it). Any other crate under CDLA-Permissive-2.0 is refused until it is looked at.
- **Refused without a recorded decision:** any copyleft licence, any licence with a field-of-use or network clause, a crate with no licence, a git or path source outside `third_party/`.
- **Enforced** by one pinned tool, on licences, sources and bans.
- **Notices:** every linked crate's licence text, generated from the same graph. A missing text fails the build.
- **The project's own licence is the owner's decision** (ADR-0001 §8). M08 supplies the compatibility table; it does not choose.
- **Third-party documentation snapshots:** proprietary vendor text is replaced by its hash and archive URL before the candidate (ADR-0004 §4, E8).

### 4.7 Signatures and the reporting route

| Row | Produced only if | Otherwise the release says |
|---|---|---|
| macOS Developer ID and notarization | the owner's Apple Developer membership | "ad-hoc signed; not notarized", with the update limitation |
| Windows Authenticode | an owner-supplied certificate | "unsigned" |
| A signature over `SHA256SUMS` | an owner signing key, used by the owner | "checksums are recorded in the repository history; no signature" |

- **`SECURITY.md`** names one private reporting route, chosen by the owner, and says plainly what is not promised: no monitored inbox, no response time, no advisories service, unless the owner sets one up (plan §10.4).

### 4.8 What a release may say

- "Signed", "notarized", "reproducible" and "clean-machine tested" appear only for a row where that was produced and checked, with the record's name.
- **A fresh account on a developer machine is called that, and never closes a clean-machine row** (ruling on M08-D-R06). Static import checks cannot show that no runtime or subprocess prerequisite is missing. The true clean-machine rows stay `blocked` until a clean VM exists; fresh-account runs are recorded beside them as separate evidence.
- Without closed distribution and provenance rows, the release is `preview-only` (ADR-0004 §1 Q-D).

## 5. Support bundles and privacy defaults

### 5.1 The bundle

- **Opt-in.** A bundle exists only when the user runs the bundle command. Nothing collects one in the background, and nothing sends one anywhere: the output is a local file.
- **No free text leaves the machine.** Every exported value is one of:
  - an enumerated code (a result code, a reason, a finding ID, a state, a capability or claim key, a setup item kind);
  - a typed safe value: a number, a boolean, a duration, a timestamp, a schema or protocol version, a build identifier, a count;
  - a pseudonym (below).

  Messages, log lines, diagnostics' detail text, error strings from the operating system or from `ssh`, command lines and file contents are **omitted**, not redacted. The log is exported as per-code counts with first and last times, never as lines. A diagnostic whose useful content is text is exported as its code and a note that detail was withheld.
- **The structural redactor is not the guarantee.** `telemetry::redact` keeps ordinary words, short strings and Heimdall's own IDs by design, so it cannot promise to remove a short unmarked secret. It stays as it is, for local logs. The bundle's guarantee is that unsafe text is never collected.
- **Every remaining string is pseudonymized.** User names, host names, aliases, labels, paths, fingerprints, key comments and Heimdall's own IDs become stable placeholders within one bundle (`host-1`, `user-1`, `id-7`). **The inverse map stays on the machine,** in a file beside the bundle that the bundle does not contain and the preview says not to send.
- **Identifier inclusion is narrow.** `--include-identifiers` replaces pseudonyms by the real value only for fields typed as public identifiers (spec §13.6: user names, host names, paths, fingerprints). It never turns free text on, and every included value still passes the key-material, key-like-run and canary checks; a value that fails is withheld. It never applies to anything typed as secret or opaque.
- **The preview is the bundle.** The command builds the bundle's bytes once, in memory, shows those bytes (the manifest and every file), and on confirmation writes **those same bytes**. Nothing is collected again between the preview and the write. The manifest's digest is printed in both places.
- **Plain and bounded.** UTF-8 JSON files and a manifest with each file's digest and withheld-field counts. No binary blob. At most 8 MiB.
- **What it holds:** the version, commit, target and feature set; the platform and the SSH client's version; doctor's finding codes with their typed fields; the capability and claims table; setup and projection status as kinds and states; configuration **keys** and the values of non-identifying settings; the store's schema version, integrity result and row **counts**; the last operations as code, state, effect status and times; log counts per code.
- **Never collected:** private or public key material, certificates, the state database, backups, known-hosts content, any SSH or Git configuration text, environment variables, process arguments, shell history, session content, free-text messages.
- **It works when Heimdall is broken:** with the runtime down, and with a store that will not open (it then reports the integrity result code and nothing from inside).
- **It reads the store through SQLite, read-only, as a family** (§3.6): counts taken from the main database file alone would be wrong whenever the write-ahead log holds state.
- **Tests** (m08-plan U6a), none of which exports a planted value even on failure (a failing test reports the field name and a digest):
  - secrets with **no marker**: short passwords, tokens that look like words, a passphrase in an error string;
  - key material **split** across fields and lines, and multiline key blocks with altered armor;
  - diagnostics whose text carries identifiers (a host name inside an error message, a path inside a finding);
  - canaries in every input;
  - `--include-identifiers` with a secret planted in an identifier-typed field;
  - the previewed bytes equal the written bytes;
  - the inverse map is not in the bundle.

### 5.2 Privacy defaults

After a default install, setup and first use:

- **No telemetry.** There is no code path that reports usage; the audit proves the absence by running with no network, and by a capture that shows no packet leaving loopback.
- **No listening TCP or UDP socket.** Local control is Unix sockets and named pipes with the existing owner checks.
- **No transcript.** The store and the logs hold no command, output or keystroke of a session.
- **No public exposure.** The transport is off until the user enables it (M06), and its widening rules are M06's.
- **No extension loading.** Nothing installs or loads a plug-in, a helper or a skill. The skill in the archive is a file the user may copy.
- **No self-update and no version check over the network.**
- **Local history** is kept seven days by default (existing), bounded logs at two 8 MiB generations (existing). Deleting history never deletes a cutoff, a pause or a tombstone.

Each line is a row of `defaults_audit` (m08-plan §7.3).

## 6. Benchmark and soak acceptance

### 6.1 Benchmarks

Spec §15.1's table is the bar, unchanged, on the candidate archive, with the method of m08-plan §6.1:

| Metric | Target | Measured as |
|---|---|---|
| Warm status or inspect, 100 destinations | P95 ≤ 100 ms | one open control session, ≥ 200 requests after 20 warm-ups |
| Warm already-authorized ensure | P95 ≤ 250 ms | the same |
| First useful TUI frame | P95 ≤ 750 ms from launch | spawn to the first complete frame, ≥ 50 launches |
| Key handling under background work | P95 ≤ 100 ms | completed frame for the key, with real slow work in progress |
| Idle CPU | < 0.5 % of one core | three 5-minute samples after 10 minutes of settling |
| Idle memory | ≤ 150 MiB | resident set (Linux), physical footprint (macOS), private working set (Windows) |
| Idle polling | none unrequested | zero requests seen by the fixture sshd and the agent proxy in the idle samples |

- **A row passes** when every measured platform meets it.
- **A row that misses** gets a measured analysis and either a fix or a revised budget recorded by the orchestrator as an amendment here. The benchmark worker never revises a budget, and a miss never removes a security check (spec §15.1).
- **A platform that could not be measured** is `blocked` on its named input; no other platform's number stands in for it.

### 6.2 The soak

The run of m08-plan §6.2 passes when all of these hold:

1. **Duration:** 72 hours of running time. Every gap is listed; gaps above an hour in total extend the run.
2. **Memory (lane S):** the median of the final 6 hours is at most the median of hours 6–12 plus 10 % plus 4 MiB; the least-squares slope over hours 12–72 is at most 0.1 MiB per hour; the maximum is at most 150 MiB.
3. **Descriptors and threads (lane S):** the final 6 hours' maximum is at most the maximum of hours 6–12 plus 4 descriptors and plus 2 threads.
4. **Persistent state,** with retention set to 1 hour for events and 24 hours for operations: the database with its write-ahead log at 72 hours is at most 1.25 times its size at 48 hours; the log directory is at most 17 MiB; the file count under the home at 72 hours is at most the count at 24 hours plus 8. One more home runs the default retention and reports its growth per day, for the limitation statement.
5. **Retries:** during every dependency outage, no two attempts toward the dependency that no caller asked for are less than 1 s apart, there are at most 12 such attempts in any 5 minutes, and the runtime's CPU over the outage is under 2 % of one core. After the dependency returns, the next request succeeds without a restart.
6. **Authority,** stated as the revocation contract states it:
   - **Local admission:** after a grant's deadline, stop or revocation, zero new signatures and zero new connections are admitted through Heimdall's endpoints, masters and helpers for that grant. This is the zero the soak asserts.
   - **Already-issued credentials** are a different thing. A certificate issued before the end stays valid at a destination until its own `valid_before`, and a credential held by a disconnected runner until its bound; these are the accepted residual windows of ADR-0005 and ADR-0012 §7. The harness probes with material it kept from before the end: a login inside the residual window is **recorded and counted against the reported residual**, and fails the run only if it succeeds after the window Heimdall reported.
   - Zero grants whose scope or deadline exceeds the harness's ledger; zero pauses cleared by a restart; the environment ID identical at the start and the end of every lane, across every kill, update and rollback.
7. **Recovery (lane L):** after every stop and kill the next request is served within 30 s; no endpoint, signer, issuer child or bridge from the previous instance is alive 60 s later; an operation in flight at a kill is reported with an honest effect status; the full-volume fault is refused cleanly and leaves a store that passes its integrity check.
8. **Cleanliness:** zero panics, zero `INTERNAL_ERROR`, zero canary strings in any log, output or sample.

### 6.3 Early stop

The harness ends the run as failed at once on: any failure of item 6 or 8; resident memory above 300 MiB; more than 1024 descriptors; disk use above its budget; a heartbeat missing for 10 minutes.

### 6.4 What the soak does and does not claim

- **It names its platform exactly** (ruling on Q2): a Linux arm64 container on a macOS host, with a 6-hour Linux x86-64 cross-check in a disposable WSL2 distribution. **No native macOS or Windows long run exists,** and the record says so as a limitation. Architecture independence of the result is not claimed.
- **Lanes on a debug build are mechanism evidence** (ADR-0008 D12 item 3) and close no release row. The A34 record carries these rows as `blocked`, each with its input, unless a release run on a product store covers it:
  - **release-managed:** the managed recipe on a release build with a product secret store, for 72 hours (needs a verified store where the soak runs: B3 or B11);
  - **provider:** a real provider other than the disposable native agent (the 1Password row: B1);
  - **route:** jump and Iroh routes, and the runner lane, on a release build (blocked if lane R runs on debug builds or cannot run in containers).
- **It injects no clock change, no sleep and no reboot.** Those are A08's rows, on their own platforms.

### 6.5 What invalidates a soak

The soak belongs to **an executable and its build inputs.** After a change, the affected soak is reassessed:

- **The 72-hour run is repeated** when the change can alter a long-lived process: any crate linked into the runtime, the issuer, a helper or a bridge (today `runtime`, `store`, `ipc`, `credential`, `issuer`, `app`, `domain`, `adapters`, `localenv`, `enroll`, `registry`, `sshconf`, `wsl`, and M06's `remote` and `transport-iroh`); the root manifest, the lock file, the feature set, the toolchain or the build flags.
- **A 6-hour confirmation** covers a change confined to short-lived command paths (CLI parsing, output, the TUI's rendering), shown by the diff.
- **Nothing is rerun** for documentation, packaging metadata that does not enter the executable, and tests.
- The orchestrator records which case applied and why. An unchanged executable digest needs no reassessment.

### 6.6 The soak's supervision rule (an exception to ADR-0009 §2.6, for the soak only)

ADR-0009 §2.6 says the agent that starts a long command blocks on it in the same turn. No turn can block for 72 hours. **For the 72-hour soak and its 6-hour cross-checks, and for nothing else:**

1. **The run is detached and supervises itself.** Its container holds the harness, which needs no agent to continue.
2. **It stops itself** on every threshold of §6.3.
3. **It writes a status file** every 30 seconds: the heartbeat, the phase, the lanes' states, the latest measures against their thresholds, and on ending a `DONE` or `FAILED` marker with the reason.
4. **It records real start and stop times,** from the container's clock and from the host's, in the status file and the evidence record. No time is filled in afterwards.
5. **The orchestrator owns the scheduled checks** (at start, +1 h, +6 h, +24 h, +48 h, +72 h). Each check reads the status file; none waits on the run. A heartbeat missing for ten minutes makes the run invalid.
6. **No worker is left waiting on it,** and a worker that starts any other long command still blocks on it.

Accepting this ADR is the authorization for this exception.

## 7. Proposed contract deltas (for the contract owner; none applied)

| # | Delta | Kind | Why |
|---|---|---|---|
| H1 | `heimdall support bundle [--preview] --out <file> [--include-identifiers]`; schema `heimdall-support-bundle/1` for the manifest | new command and schema | §5.1; R-SE-08 |
| H2 | `heimdall service stop --preview`: a read-only list of what stopping interrupts; a schema for it | new flag and schema | §3.2 item 2; R-DI-03 |
| H3 | `heimdall state status`, `heimdall state restore --backup <file>`, `heimdall state reset`: attended, each with a typed confirmation. **With it, §3.6 as an authority rule of the contract:** what a restore keeps, ends, quarantines and voids; the carry-forward of the more restrictive state; identity binding; the refusals; reset's inventory-unavailable disclosure | new commands **and an authority rule** | §3.2 items 6, 9, 10; §3.6; R-RT-08, R-RT-07 |
| H4 | Reasons under `STATE_UNAVAILABLE`: `state_corrupt`, `state_newer_than_build`; an event and a reason for `state_restored_authority_ended` | new reasons | Today both read as one message with no next step. **Observed (lifecycle journey, 2026-11-22, `tests/native/m08/lifecycle/README.md`):** an older build on a store four migrations newer answered `connect` with `SERVICE_UNAVAILABLE`, no reason, "the runtime did not become ready in time"; `status` said "no runtime is running"; `doctor` exited OK |
| H5 | A doctor finding `executable_moved`, with its repair command | new finding | §3.2 item 12 |
| H6 | Residue kinds: `migration_backup`, `earlier_store_generation`, `previous_binary`, `git_block_moved` | new enum values | §3.4; R-DI-04. **Observed (the same journey):** after an update, uninstall's remaining list named the SSH configuration backup and the state store, and neither `state.db.v8.backup` nor `heimdall.previous` |
| H7 | Build provenance in the version output and `inspect capabilities`: commit, target, profile, feature set | new fields | §4.4; "release claims match the shipped builds" |
| H8 | The candidate's version string, replacing `0.1.0-m01` | value | It is carried in the hello |
| H9 | A store migration: `restore_epoch`; the epoch on operations, idempotency records and decision references; the backup's environment binding; a quarantine state for management clients and a void state for invitations, if M06's tables lack them; fence records keyed by the ledger digest, with ADR-0006 §7.4 lifetimes | migration | H3; §3.6 |
| H12 | **A storage-layout change:** generation directories, the `CURRENT` pointer, the per-generation operation record, the request ledger outside the generations (its digest over the full idempotency key), the adoption-intent file, and adoption of today's layout by fence, copy and publication in that order. Every reader of the state path follows the pointer: the runtime, the read-only opens of `doctor` and the CLI, uninstall and the purge sweep, the Windows state-directory protection. **M06 and M07 own the store and path files today,** so this is built in U2b after the handoff | storage delta, for the contract owner | §3.6; R-RT-08 |
| H13 | **The epoch on requests:** the hello reports `restore_epoch`; every mutating request carries the epoch its request ID was minted under, bound at mint time and reused on retry; a request whose epoch is not current is refused, attended or not. The epoch in server-minted references. The refusal `REQUEST_STALE` with reasons `restored_before_completion` and `restore_epoch_stale`. The CLI, the TUI, the reference wrapper and the harnesses carry the epoch with any request ID they keep for retry. The stated residual: a caller that re-stamps an old request with a new epoch is outside the contract | new request field, hello field, code and reasons; a rule for callers | §3.6 |
| H10 | Reasons for the quarantine: `client_quarantined_after_restore`, `invitation_void_after_restore`, `exposure_disabled_after_restore`; a `restore` event | new reasons and event | §3.6 |
| H11 | A debug-support cargo feature that keeps test-only crates out of release builds | manifest change, under the manifest's owner | §4.5; ruling on Q8 |

**Proposed text changes outside ADR-0006:**
- **ADR-0002 §9 (ruled, Q4):** Linux artifacts are dynamic against a glibc 2.31 floor, not static musl. ADR-0002 is amended explicitly at merge; the artifact check enforces the imports and symbol versions; the declared distributions are run.
- **Spec §15.1:** none. The budgets stand until a measurement says otherwise.
- **Spec §13.6:** none. The seven-day default stands; a storage bound is proposed only if §6.2 item 4's default-retention report asks for one.

## 8. Alternatives considered and rejected

| Alternative | Why not |
|---|---|
| Fuzz with property tests only | Already done; the earlier milestones deferred coverage-guided fuzzing to M08 for the parsers that take outside input |
| Fuzz continuously in `check.sh` | Minutes per commit for no finding; the regressions carry the value |
| Move the workspace to a nightly toolchain for fuzzing | The toolchain pin is a recorded decision; the container keeps the nightly out of the product |
| A self-updater | Spec §15.3 forbids hidden self-update; an updater is a privileged, signed, network-facing component the project does not need |
| Native packages now | Each is a publishing channel; nothing is published in M08 |
| An SBOM from the lock file | Wrong per target, includes test crates, carries no licences (probe) |
| Dropping test-support crates from the inventory | The record would disagree with any scanner reading the build graph |
| A blocklist redactor for the bundle | Spec §13.6 rules it out; the allow-list makes the default "not collected" |
| Uploading bundles | No service exists, and none is promised |
| The soak on the Windows PC, the devbox or the VPS | m08-plan §6.2's table |
| A soak on a debug build with injected faults only | The leak and retry claims are about the shipped build |
| Restoring a backup unchanged | It revives revoked and stopped access (§3.6) |
| Restore that only ends grants and pauses policies | A recovered management client, invitation or exposure setting is authority too (review M08-D-R01) |
| No restore, reset only | Loses the environment identity and orphans every enrollment |
| Replaying later tombstones onto the backup from a second log | Not needed: without them the restore ends all authority anyway. The request ledger is the one record kept outside the store, because a caller-minted request ID made after the backup cannot be recognized any other way |
| Renaming the old family aside and the new one into place | A family is four directory entries; a crash between renames leaves a state no rule covers (re-check R02) |
| A per-member intent log with ordered moves | More states to recover than one pointer; kept only as the fallback if a platform could not do the switch, and none was found |
| A quiet period when the store and the ledger are both lost (revision 3) | Attendance does not make an old request new, and neither does a wait (re-check N01). The epoch on the request does |
| The ledger as the only fence | It can be lost with the store. The epoch on the request needs no surviving evidence; the ledger stays for the caller that breaks the rule and for precise answers |
| Publishing the adopted generation before fencing the flat store (revision 3) | A crash between them lets an older build serve the flat store and lose a revocation (re-check N02) |
| A ledger digest over principal and request ID only (revision 3) | It collapses distinct keys (re-check N03) |
| Migrating by generation switch too | The in-place transactional migration with its backup is built and tested; a second mechanism would add recovery cases for no gain |
| A filtered log tail in the bundle | Free text cannot be made safe by a redactor that keeps ordinary words (review M08-D-R03) |
| `SHA256SUMS` inside the archive covering the archive | Self-referential (review M08-D-R07) |
| A hand-written dependency resolver | A pinned tool with a validation adapter is enough (review M08-D-R04) |
| Fresh-account rows closing the clean-machine claim | Machine-wide runtimes remain (review M08-D-R06) |

## 9. Consequences

- **The release's weakest rows are named in advance:** unsigned Windows and Linux artifacts, an ad-hoc macOS build with the update limitation, and Windows and macOS release rows that need a disposable account each.
- **A restore costs the user one round of approvals, and one reauthorization per remote client.**
- **Callers must carry the epoch with a request ID they intend to retry.** This is a rule for every client, not only Heimdall's own.
- **Every mutating request costs one more synced append** (the request ledger). The benchmarks of §6.1 measure it; if it breaks a budget, the ledger's write is the thing to revisit, not the fence.
- **The store's location changes** (H12). Every tool and test that opens the store by path follows the pointer.
- **Earlier generations accumulate** until the user purges them; each holds a full old state and is listed as residue.
- **Two toolchains exist in the project,** one of them only inside a fuzz container.
- **The release graph loses its test-only crates before the candidate** (H11); until then the inventory names them.
- **The bundle is less useful to a maintainer than a log tail would be.** That is the price of sending no free text; a user can still read their own local log.
- **Migration consequences:** H9 is the schema change and H12 the layout change. No existing record changes meaning; a store in today's layout is fenced, copied and left in place, and no build that predates generations opens it again.

## 10. Reopen conditions

- A fuzz target reaches its ceiling still finding coverage on two successive candidates.
- A benchmark row misses on a measured platform.
- The soak fails item 2, 3 or 4 with a cause that is a designed cache or log rather than a leak.
- The owner supplies a signing key, a Developer ID or a publishing channel: §4.7 and m08-plan §10 are then revised.
- M06's exit changes what counts as recovered remote authority (a new durable admission record): §3.6's table gains a row.
- A release run on a product store becomes possible where the soak runs: the release-managed row of §6.4 is then run, not blocked.
- M06's exit changes the transport's V1 scope, and with it the feature set and the inventory.
