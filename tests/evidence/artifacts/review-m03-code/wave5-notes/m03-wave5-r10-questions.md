# M03 wave 5, round 10 — questions for the orchestrator

## Integrator (I)
## P8
None blocking. Readings taken, fail-closed: (a) "every open operation" = open/unresolved enrollment
operations (the recovery-relevant kinds; issuer work has no operation kind; access/setup/catalog
operations are local, and the uninstall's own rollback is one); (b) issuance_log /
verification_issuance are Discarded (bounded-lifetime certificates, no bundle field). If the
orchestrator wants either compared, it is one `TABLE_RECOVERY` entry plus its test case.
## G8
## L5

## Integrator (round-10 records)
- **P8's two readings: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.32 item 6): both
  confirmed.** (1) "Every open operation" = open enrollment operations: foreign removals are covered
  as records in the snapshot, issuer operations have no remote effect and their store items are
  covered by the CA, locator and orphan-item entries; the snapshot's classification test names this
  explicitly for each excluded operation kind. (2) Issuance and verification certificate records
  stay out: certificates are short-lived and create no new remote obligation; the lasting remote
  trust is the CA enrollment, which the snapshot covers. A replacement that only issued certificates
  in the gap does not block the purge; one that added or replaced a CA, enrollment or foreign
  removal does.

## K4
(none)
- **P8's meta keys: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.32 item 7).**
  `remote_revocation:` is IN: a pending remote part of an access grant's revocation is an unfinished
  security action on a remote system. Uninstall makes one `retry_remote_revocation` attempt per
  pending record before stopping the runtime; anything still pending is listed in the inventory and in
  the purge confirmation (human and JSON) and covered by the purge's typed confirmation (no new flag);
  pending remote revocations are part of the recovery snapshot (a change refuses with
  `uninstall_inventory_changed`). Regressions: a pending revocation is listed and confirmed; one added
  during the window refuses. `cleanup_intent:` stays OUT, on condition that uninstall's local cleanup
  removes every path a cleanup intent can name (binding directories, endpoints, slot files), shown
  with code paths plus a test if missing; fix it if not.

## P8 (round 10, §17.32 item 7: the retry route)
**Blocked on a route I do not own.** `Operations::retry_remote_revocation`
(`crates/app/src/operations.rs:10714`) is reached only by the supervisor
(`crates/runtime/src/supervisor.rs:900,933`); no `Request` reaches it, so uninstall cannot make the
one attempt on its own session. An explicit `revoke` re-arms (restarts counts, lifts stops), which is
more than one attempt, so it is not a substitute.
- (a) **Recommended:** additive `UninstallFenceRequest::RetryRemoteRevocations` (holder only, under the
  fence): one `retry_remote_revocation(root, cap)` per pending record, answering the records still
  pending. Owners: integrator (`crates/contract/**`), the dispatcher and G8 (`uninstall_fence_m03.rs`).
  P8 then sends it before `stop_runtime`, records what it observed (as for retirements) and admits
  exactly that change in the final comparison.
- (b) The fence's `Acquire` runs the rounds before answering (no contract change; G8's file).
- **Built meanwhile (fail closed, switch `REMOTE_REVOCATION_RETRY_ROUTE = false` in
  uninstall_cmd.rs):** a purge with a pending remote revocation is refused before its confirmation
  (`CAPABILITY_UNAVAILABLE`, exit 4, effect none, listed); listing (human + JSON) and the purge-prompt
  text are built; the key is in the snapshot.
- **Q-I-R10-1 (the retry route of §17.32 item 7): ANSWERED (orchestrator, 2026-11-13):** additive
  `UninstallFenceRequest::RetryRemoteRevocations` (authorized; ADR-0006 row), holder-only, under the
  held fence, before the shutdown: exactly one `retry_remote_revocation` attempt per pending record,
  never re-arming it (no count reset, no lifted stops; one ordinary attempt under its caps). Uninstall
  then lists what is still pending (human + JSON) in the purge confirmation, covered by the typed
  confirmation. Remove `REMOTE_REVOCATION_RETRY_ROUTE`; do not keep the refusal (a permanently gone
  remote would block uninstall forever). Regressions: one attempt per record without re-arming; a
  non-holder is refused; a still-pending record is listed and confirmed; one added in the window refuses.
