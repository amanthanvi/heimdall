# M03 wave 5, round 12 — questions for the orchestrator

## Integrator (I)
## P8
## K4

## Integrator (round-12 records)
- **P8's two safe wrappers: ANSWERED (orchestrator, 2026-11-14; ADR-0008 §17.34 item 5): accepted**
  (`heimdall_ipc::windows::file_id`, `heimdall_runtime::platform::user_private_group`), both in modules
  overview §9 already allows `unsafe` in.
- **P8's census and two more wrappers: ANSWERED (orchestrator, 2026-11-14; ADR-0008 §17.34 item 6):**
  the per-file census (each held file gains exactly one more descriptor after SQLite's open) is accepted
  instead of a process-wide check, which would race with other threads; a swapped-in file still fails
  (missing descriptor on the held file), named in the check's code comment. `heimdall_ipc::windows::move_no_replace`
  and `heimdall_runtime::platform::regular_file_descriptors` accepted (overview §9 modules).
