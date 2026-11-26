# PC job 65: U2b-2 on native Windows, at `065f3a45` (2026-11-25)

Job file: the M08 lead's `PC-M08-U2b2.md`. Its step 3 was split into one capture per command
(`s3a`, `s3b`). Run with the default `TEMP`, BelowNormal priority, scratch toolchain homes,
`CARGO_BUILD_JOBS=4`, and not elevated. The outputs here are redacted.

| Step | Target | Result |
|---|---|---|
| 1 | `heimdall-runtime --test integration_request_epoch` (named pipe) | 10 of 10 passed, including follow-up A's three tests |
| 2 | `heimdall --test e2e_request_epoch` | 3 of 3 passed, including `run_reports_its_minted_request_id_with_the_epoch`, its first Windows run. The wrapper case is Unix-only and is not built |
| 3a | `heimdall-store --lib fence::` | 3 passed |
| 3b | `heimdall-stategen` | 12 unit and 18 switch-fault tests passed |
| 4 | `heimdall-issuer --test adversarial_issuer_reservation_replay` | 2 of 2 passed. `.tmp*` count in the default `TEMP`: before 609, after 609. U1b's `TempDir` drop-order fix holds on Windows |

Every capture exited 0. The Credential Manager count was 173 before and 173 after.

**Safety check (the PC agent's):** each test `heimdall` gets `env_clear()`, with scratch `HOME`,
`USERPROFILE`, `HEIMDALL_TEST_SSH_HOME` and the three fixture stores, and `PATH` set to
`System32` only. `run`'s child `cmd.exe` is resolved but never started. Nothing starts `ssh`.

**Finding (test-only, fixed in W3's review-fix commit):** `integration_request_epoch` leaves two
`.tmp*` directories, each holding `hh\state\state.db`, in the default `TEMP`. They come from the
two tests that start a `Runner`. That rig's `Drop` only cancels the stop token, so tasks that
hold the store can still have `state.db` open when the `TempDir` drops, and on Windows the delete
then fails silently. The 609 earlier directories predate this job. The PC agent is taking an
inventory of them by name.
