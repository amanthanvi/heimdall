# M03 wave 5, round 14 — questions for the orchestrator

## Integrator (I)
## P8
- **Q-P8-R14-1 (record-keeping, not blocking): ADR-0008 §17.35 still describes `Checkpointer`.**
  `Checkpointer` is removed (nothing else used it); the ADR-0006 §16.6 row records the removal.
  ADR-0008 is outside P8's grant, so §17.35 items 2 and 6 still name it. Please annotate them
  as superseded by §17.36 item 1, or grant the edit.
- **Q-P8-R14-2 (FYI): a refused purge now leaves the original family in quarantine by design.**
  The runtime then refuses to start until the next `heimdall uninstall`, which confirms the
  restored copy and removes the originals, as §17.36 item 1 requires. The refusal's report
  says so (`kept_in_quarantine`).

## Integrator (round-14 records)
- **Q-P8-R14-1: ANSWERED (orchestrator, 2026-11-15):** the orchestrator annotates ADR-0008 §17.35 items
  2 and 6 as superseded by §17.36 item 1 at commit; ADR-0008 left untouched here.
- **Q-P8-R14-2: ANSWERED (orchestrator, 2026-11-15): accepted.** A refused purge has already rolled back
  setup and stopped the runtime; pointing the owner to `heimdall uninstall` (recover, confirm, delete the
  originals, state kept) matches their intent; recorded as a consequence in the ADR at commit.
