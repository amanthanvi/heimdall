# M03 wave 4, round 5 — worker Y-W (Windows enrollment failures) worklog

## Goal / constraints
- (a) Windows `e2e_enroll_m03` at `4866642d`: `existing_access_changed` in two foreign-removal tests;
  `left: Removing, right: Held` in three held-setup tests. Fix root causes, never weaken re-validation;
  held setup must fail loudly when its damage does not land; W4-S01 descriptor regression revert-proven.
- (b) Item 4 (coordinator message): Windows-only observation of the in-box client's changed-host-key path
  (and unknown-host if possible), `m03 observation: client_trace_row … field=host_key_failure line="…"`,
  not gated on the row; plus the ported "host-key change ends held, no rollback" test, gated on the row.
- No Windows host here. Never `crates/enroll/src/trace.rs`. Revert proofs by in-place substitution.

## Root cause 1 — `existing_access_changed` during a foreign removal (evidence)
- Own enrollments store the plan's **rendered** endpoint: `plan::build` step 8 renders the catalog's
  locator with `concrete_endpoint` (`crates/registry/src/plan.rs` ~479 at base), so a catalog pipe
  `\\.\pipe\<name>` becomes `//./pipe/<name>`; `admit.rs:304` stores `endpoint_ref(&plan.existing_access.endpoint)`.
- A foreign removal has no plan: its context is rebuilt by `foreign_image`
  (`crates/app/src/operations/enrollment_m03/steps.rs:101-104` at base) as
  `identity.source.endpoint().map(|e| endpoint_ref(&e.locator))` — the **raw catalog locator**.
- The fixture catalog records the agent as `agent_ref(&agent_locator)` = `\\.\pipe\hm…-existing`
  (`tests/e2e/enroll_m03.rs:1515`; `heimdall_testkit::agent::Endpoint::in_scratch`, pipe form
  `\\.\pipe\{FIXTURE_PIPE_PREFIX}…` on Windows), while `TestHost.agent_path` is the rendered
  `//./pipe/…` (`enroll_m03.rs:1438-1442`).
- `issue()` re-validates before every step: `ports.host.endpoint_valid(&endpoint)` (`steps.rs:653`).
  The test host on Windows compares `endpoint == self.agent_path` (`enroll_m03.rs:413-418`) → the raw
  `\\.\pipe\…` never equals `//./pipe/…` → `existing_access_changed` on the first step of every foreign
  removal. On Unix the catalog socket path renders to itself, so Unix never saw it.
- Also wrong on Windows with the check passed: `step::access_pins` refuses `\` (`step::literal`), and the
  foreign `RemoveEnrollment` decision's disclosed `invocation` (`admit.rs:1260-1265` at base) used the raw
  locator, so on Windows it was silently **empty** (`unwrap_or_default`).
- The check itself was right (it refuses a changed endpoint); the record's endpoint string was wrong.
  Not the agent pipe listing, the second installation's world, or `RuntimeEnrollmentHost`.

## Root cause 2 — held setup not holding (evidence)
- Same root cause. `held_foreign` (`enroll_m03.rs` ~5105 at base) and the journal test (~6936) call
  `let _ = w.drive(&rm).await;` — the drive's `existing_access_changed` error (first step, before any
  inspect) was **discarded**, the record stayed `removing` (approval's `planned → removing`), and the
  assertion read `left: Removing, right: Held`. The damage write itself was not shown faulty: testkit
  `append_line` uses `writeln!` (`\n` on every platform), appends (`OpenOptions::append`), and writes
  `registry` = `HM_FIXTURE_SSHD_REGISTRY`, the same file the WSL sshd/scripts read as `_REMOTE`.
- Mac reproduction: test host `endpoint_valid` forced false → `foreign_removal_held_reuse_needs_the_exact_descriptor`
  panics with exactly the Windows error (below).

## Changes
- `crates/registry/src/plan.rs`: `pub fn catalog_endpoint(&EndpointRef) -> Option<String>` (step 8's rule,
  now used by step 8 itself; pure refactor there).
- `crates/app/src/enrollment.rs`: `pub fn foreign_endpoint(&IdentitySource) -> Option<EndpointRef>` + unit
  test `foreign_endpoint_is_the_concrete_rendering`.
- `steps.rs` `foreign_image`: endpoint = `foreign_endpoint(&identity.source)`.
- `admit.rs` foreign admission: refuse `existing_access_endpoint_unrecorded` when the recorded endpoint is
  absent **or not concrete** (as a plan refuses it); the decision's invocation from the concrete endpoint.
  (These two app files are outside the Y-W row's listed files but in no other worker's region; the root
  cause is there. Noted in the questions file.)
- `crates/testkit/src/sshd.rs`: `append_registry_line` refuses a multi-line line and reads the file back
  (earlier bytes + line + `\n`, else error); unit test `registry_append_is_read_back_or_fails`.
- `tests/e2e/enroll_m03.rs`: `held_foreign` asserts the damage line is in the registry (2 marker lines),
  keeps the drive result; new `assert_held_by_damage` (journal inspect reading: `marker_lines` and
  `marker_class == "damaged"` from the server's read, then `held`; the drive outcome in every message);
  the journal test uses it (4 marker lines).
- `tests/e2e/enroll_m03/windows.rs` (item 4): `observation_redactor` (the matched-path redaction + `AAAA…`
  key blobs masked + canary assert), `host_key_changed_record`, tests
  `windows_client_trace_row_host_key_changed_observation`, `windows_client_trace_row_host_key_unknown_observation`,
  `windows_verification_host_key_mismatch_holds_no_rollback` (gated `require_recorded_client`).

## Commands (this Mac, real exit codes)
- Baseline (my plan.rs refactor only + other workers' WIP): `cargo test -p heimdall --test e2e_enroll_m03` → 66 passed, exit 0.
- `cargo test -p heimdall-testkit --features fixtures,managed,app --lib sshd::` → 7 passed, exit 0.
- `cargo test -p heimdall-app --lib foreign_endpoint` → 1 passed, exit 0. Revert (body → `endpoint_ref(&e.locator)`,
  in place): exit 101 (`left: "\\\\.\\PIPE\\hm-fixture-agent-1" right: "//./pipe/hm-fixture-agent-1"`); restored
  (shasum identical): exit 0.
- After the fix: `cargo test -p heimdall --test e2e_enroll_m03` → 66 passed, exit 0.
- Probe (test host `endpoint_valid` `&& false`, in place): `… foreign_removal_held_reuse_needs_the_exact_descriptor`
  → exit 101, `no inspect reading: the drive ended Err(OpError { code: CapabilityUnavailable, … reason: Some("existing_access_changed") })`
  (the Windows error, now loud at the setup); restored (shasum identical).
- W4-S01 revert (`same_foreign_descriptor`: `held == requested` → `true`, in place): exit 101 at
  `enroll_m03.rs:6781` (`left: ApprovalRequired right: CapabilityUnavailable`); restored (shasum identical): exit 0.
- Item 4 Mac run with the Windows gate temporarily lifted (`enroll_m03.rs:47` `#[cfg(windows)]` →
  `#[cfg(any(unix, windows))]`): first attempt killed by the server restart (exit 137); rerun
  `cargo test -p heimdall --test e2e_enroll_m03 windows::windows_ -- --skip binding --skip follower --skip reissue
  --nocapture --test-threads=1` → 4 passed, exit 0. Observed (10.5p1, socket form):
  - changed key (through the real verifier): `verification=HOST_TRUST_CHANGED Some("enrollment_host_key_mismatch")
    state=Held`; both attempts print the `REMOTE HOST IDENTIFICATION HAS CHANGED` banner, `Host key for
    hm-verify-<tag> has changed and you have requested strict checking.`, `Host key verification failed.`
    (paths redacted to `<scratch>`).
  - unknown host (direct client run): exit 255, `No ED25519 host key is known for hm-verify-0000000000000000 and
    you have requested strict checking.`, `Host key verification failed.`
  - `windows_verification_host_key_mismatch_holds_no_rollback`: passed (10.5p1 is recorded, so the gate is a no-op on Unix).
  Gate restored to `#[cfg(windows)]` (checked: not in `git diff`).
- `rustfmt --edition 2024 --check` on all 7 touched files → exit 0 (after formatting `host_key_changed_record`'s signature).
- `bash tools/validation/clippy-windows.sh`: **no result**. First run stopped at the 30-minute background limit
  (waiting on the shared build lock); rerun stopped at the 2-hour maximum while still checking (last line
  `Checking heimdall-launch`, 0 warnings/errors printed up to then). Not restarted (the tool's limit was reached);
  the helper has no per-package mode.

## Not run (left for the orchestrator)
- `bash tools/validation/clippy-windows.sh` to completion; `cargo clippy --workspace --all-targets -- -D warnings`;
  `bash tools/validation/linux-xcheck.sh -p heimdall -p heimdall-testkit`; a final
  `cargo test -p heimdall --test e2e_enroll_m03` after the last doc-comment/rustfmt edits (the last full run, 66
  passed, was before the item-4 additions; the gate-lifted run compiled the whole target with every later change
  except two doc comments and one rustfmt reflow). Harness scripts unchanged, so their self-tests were not needed.
