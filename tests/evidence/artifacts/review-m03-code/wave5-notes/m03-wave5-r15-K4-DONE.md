# K4 round 15: done — the two Linux-only recheck3 failures were a product bug, now fixed

**Cause (found with temporary diagnostics on the devbox, since removed).** On Linux, every exact-child check of the issuer child passed except the image check: the image read `None` both at spawn and at signal time. The issuer child makes itself non-dumpable (`PR_SET_DUMPABLE` 0) before any key exists, so its `/proc/<pid>` belongs to root and this user cannot read `/proc/<pid>/exe`. `signal_exact` required both image reads to succeed, so on Linux it never signalled the issuer child. The stopped child kept the admission and the 20 s `ACQUIRE_WAIT` expired. The start token (`/proc/<pid>/stat` field 22) was correct, including for the stopped child. macOS (`proc_pidpath`) is unaffected.

**Impact before the fix:** on Linux the client could never end a hung issuer child (crash, stop fallback, cancelled-request cleanup). Its admission stayed held until it exited on its own. §17.33 item 6: fails closed only (a delay and a refused fence, no write, no certificate); fixed anyway as a product bug.

**Fix (`crates/issuer/src/client.rs`, `signal_exact`).** The image is part of the child's identity only if it was readable at spawn; if so, it must still read the same (unreadable now, or different, refuses). If it wasn't readable at spawn, the check is the PID, the start token and the client's own unreaped handle, whose PID cannot be reused. The child stays non-dumpable (K_ca protection).

**Regressions (unit tests, Unix, real `/bin/sleep` child):**
- `exact_child_signalled_when_its_image_was_never_readable`: with the old rule restored it exits 101; restored (same shasum) it passes.
- `exact_child_refused_when_a_read_identity_no_longer_matches`: refuses on a missing or changed image or token.

**Tests updated (not weakened):** three e2e tests modelled an unverifiable child with a reader that never reads, which is now the normal Linux case. They now use `image_unreadable_after_start()` (readable at spawn, unreadable after): `recheck3_real_issuer_unconfirmed_stop_keeps_the_admission_held`, `recheck4_cancelling_stop_must_not_signal_unverified_child`, `residual_leader_shaped_sign_unconfirmed_stop_keeps_no_admission`.

**Also fixed, same bundle (test defect, §17.33 item 6 does not apply):** `issuer_init_prints_passphrase_only_to_tty` failed on Linux because its file scan read the rig's own copy of the heimdall executable, which contains the prompt text as a literal. It now skips `Rig::program`.

**Other users of the exact-child identity:** `crash()`, `stop()`, the start cleanup, the cancelled-request cleanup and `end_child` all go through `signal_exact`, so the fix covers them. `kill_on_drop` is unchanged. The runtime's owned ssh connections (`ProcessPin::verify`) read dumpable processes, so they are unaffected.

**Runs (umask 002):**
- Devbox, `HM_ONLY=e2e_cli_m03`: run 1 (diagnostics) 54/56; run 2 (fix) exit 0, 56 passed, both recheck3 tests included, 0 leftover processes.
- macOS, all exit 0: `heimdall-issuer --lib` (24), `e2e_cli_m03 issuer::` (24 + 1 ignored), `integration_issuer_child` (36).
- Host clippy (issuer, heimdall bin + `e2e_cli_m03`) 0; `linux-xcheck.sh -p heimdall-issuer -p heimdall` 0.
- `clippy-windows.sh` exit 101 twice, only on `read_with_wal` never used at `crates/heimdall/src/uninstall_cmd.rs:6290` (P8's in-progress file). Needs a rerun once that compiles. Windows target kept.

**Cleanup:** devbox marked FREE in the worklog; no `~/hm-m02-*` left there. Local output dirs and `target/x86_64-unknown-linux-gnu` (36 GB) removed. Diagnostics removed. Owner keychain unchanged, no heimdall processes left. The first devbox run was killed by the server restart during the local cross-build and never reached the devbox.

Files: `crates/issuer/src/client.rs`, `tests/e2e/cli_m03/issuer.rs`. Worklog `.m03-wave5-r15-worklog-K4.md`. No questions.
