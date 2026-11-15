# M03 wave 5 round 8 — worker K4 (W5-C05) worklog

Base 0cd94961. Binding ADR-0008 §17.31 item 5. No commits.

## Decisions
- `finish_retirement` (crates/heimdall/src/issuer_cmd.rs): work split into the current item (refusal
  still answered as before) and displaced items. Displaced: `delete_displaced` → kept (access denied,
  never deleted; note with `keep_instruction`) or any other refusal (kept, note with
  `manual_delete_instruction`). Never fails after the current item is deleted+confirmed.
- render: `retired(st, ca, notes)` passes notes to status; an orphan of a retired CA renders "Heimdall
  deletes it no more; delete it yourself in the store" (no restore advice). A rerun of `issuer retire`
  on a retired CA answers CONFIG_CONFLICT (runtime, out of scope), so no "retire again" advice either.
- JSON success envelopes carry no effect field: "effect applied" = exit 0, code OK, state succeeded,
  no data.error. The regression's retire runs in human mode (to see the note); JSON checked via status.

## Commands (exit codes)
- new e2e recheck_retire_after_new_item_restore_deletes_only_current_generation: 0.
- revert (`if current` → `if current || true`): 101 (retire exit 4 CAPABILITY_UNAVAILABLE); restored,
  sha 2ae17a82… same; rerun 0.
- clippy host (issuer+app all-targets; heimdall bin+e2e; bin test profile): 0/0/0.
- linux-xcheck -p heimdall-issuer -p heimdall: 0. issuer lib 0 (22); --release 0 (21);
  integration_issuer_store 0 (30); heimdall bin `issuer` units 0 (6).
- clippy-windows.sh first run: 101 in crates/heimdall/src/uninstall_cmd.rs:1700 (P8's in-flight file,
  `Outcome` lacks Debug); retried below.
- clippy-windows.sh retry: 0 (P8's file compiled by then).
- e2e_cli_m03 issuer:: x3: all 0 (19 passed, 1 ignored = pty child entry); run 3 at umask 002; owner
  keychain search list/default digest unchanged. Scratch /tmp/k4-r8 removed. DONE.
