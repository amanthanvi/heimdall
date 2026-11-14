# M03 wave 5, round 13 — questions for the orchestrator

## Integrator (I)
## P8

## Integrator (round-13 records)
- **`heimdall_store::Checkpointer` and `heimdall_ipc::windows::create_dir_owner_only`: ANSWERED
  (orchestrator, 2026-11-14; ADR-0008 §17.35 item 6): both accepted.** `Checkpointer` is an additive
  workspace API, read-write, never creating the file, confirmed by the descriptor census, used only by the
  purge in quarantine; its doc comment states it exists for the §17.35 item 2 checkpoint and must not be
  used to open the live database. `create_dir_owner_only` is in overview §9's `unsafe`-allowed module.
- **Audit D1/D2: ANSWERED (orchestrator, 2026-11-14; ADR-0008 §17.35 item 7): start-up refuses.**
  Before it creates or opens the state database, runtime start-up (and every other path that would
  create `state.db`) checks the anchored `<state>` and refuses if a `.hm-purge-*` quarantine unit or
  directory, or a `-wal`/`-shm`/`-journal` without its database, is present: additive reason
  `uninstall_quarantine_present` (authorized; `SERVICE_UNAVAILABLE`, exit 5), exact paths, next step
  `heimdall uninstall`, which restores the unit under item 1's rule or completes the purge. Uninstall
  detects and handles a leftover unit first, never as foreign. No residual. Regressions: a crash at each
  window in both directions, then a runtime start, refuses and keeps the `-wal` intact; then `heimdall
  uninstall` restores with every commit present or completes the purge. ADR-0006 row.
- **Audit D3/D4/D5: ANSWERED (§17.35 item 8): fix all three** (read, census, then checkpoint; the report
  states only what is on disk; Windows keeps `held` until deletion ends and never lists a purge-created
  file as renamed back). Regressions off Windows; D5 by Windows clippy, named for the native run.
