# M01-code-review-C — commit 93c60d3b — **fix first**

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

Reviewed `93c60d3b60a8828b2f431a1fef27d3047a8cc917`. The current tests pass, but JSON usage errors bypass the machine contract, and the evidence generator can silently reduce required coverage. No blocker-level finding or unauthorized authority expansion was established in this review.

## Findings

### C01 — Major — JSON argument errors return no envelope

**Location:** `crates/heimdall/src/main.rs:22`; evidence gap at `tests/e2e/cli_m01.rs:550`.

**Defect:** Parse errors call clap's text renderer and return immediately, bypassing envelope rendering even when `--json` was supplied. This breaks the final-result machine contract in spec §11.2. The exit-class test checks the clap error's exit status without requesting JSON or asserting an envelope.

**Concrete failure scenario:** An agent invokes `heimdall --json access ensure --no-such-flag`. Its normal envelope parser receives empty stdout and cannot read `code`, `data`, or `next`.

**Evidence — observed:** Executing that command returned exit **2**, stdout **0 bytes**, stderr **194 bytes**; stdout was not JSON. The exit classification is correct; the structured result is missing.

**Fix:** Preserve human help/version behavior, but render usage failures as a `USAGE_ERROR` envelope when JSON mode was requested. Add binary tests for an unknown flag and a missing required argument with `--json`, asserting exactly one stdout envelope.

### C02 — Major — Wildcard evidence coverage disappears when a target does not run

**Location:** `tests/native/m01/m01-evidence.py:72`, `:188`, `:199`.

**Defect:** Wildcard entries derive their required test inventory from successful discovery in the run logs. A missing target expands to zero tests. The subsequent "every indexed name must exist" check cannot detect it because no names remain to check.

**Concrete failure scenario:** The `contracts` target stops being wired into Cargo, or its output is omitted from the current build's logs. A19 loses its contract checks while its macOS row remains `verified`. `check.sh` likewise cannot discover a target Cargo never announces.

**Evidence — observed through an in-memory mutation:** Using the saved macOS log and current A19 index:

```text
A19 complete logs:          121 indexed tests, verified
A19 contracts target absent: 57 indexed tests, verified
```

No repository file or artifact was changed for this probe. All explicitly indexed function names currently exist in Rust source and in at least one saved log; this finding concerns the generator's acceptance behavior.

**Fix:** Establish the expected inventory independently of completed run logs. At minimum, reject wildcard targets with no discovered tests; preferably retain an explicit required inventory and compare actual runs against it. Add a small self-test removing an entire wildcard target.

### C03 — Minor — Recorded failing command exits do not prevent verification

**Location:** `tests/native/m01/m01-evidence.py:130`, `:147`.

**Defect:** `row_for` assigns status from indexed test lines and absence/staleness flags. It copies `exit_codes` into the row without considering them.

**Concrete failure scenario:** All indexed tests print `ok`, but their binary subsequently fails, or the enclosing required validation command exits nonzero. The row can still become `verified`.

**Evidence — observed through a synthetic function probe:** Calling `row_for` with one passing indexed test and `exit_codes={"check.sh": 101}` produced:

```text
status: verified
exit_codes: {'check.sh': 101}
```

This does **not** establish that an existing record conceals a failing command: the inspected current macOS artifact records exit 0, and the older platform rows disclose their limitations.

**Fix:** Make a required nonzero command exit prevent `verified`. Represent intentionally failing negative probes separately so they cannot be confused with successful validation commands. Test both cases.

## Known deviations already assigned elsewhere

- **Covered by §13.6, item 7:** `crates/heimdall/src/cli.rs:743` sends the initial ensure request before attendance; confirmation subsequently sends `Attend`. The initial interactive owner-present request therefore does not follow the newly ruled attendance order.
- **Covered by §13.6, item 8:** `crates/heimdall/src/service_cmd.rs:12` describes and implements the older Unix signal-based stop path and Windows unavailability, pending owner-channel `Request::Shutdown`.
- **Known: records to be regenerated:** All seven `m01-*.json` records remain `in_progress`, identify an uncommitted historical build, and mark Linux/Windows rows as predating the final build. They do not establish verification of commit `93c60d3b`.

## Checked and found sound

- **Exit handling:** Real-binary tests exercise exits 0–7. Synchronous `ACCEPTED` exits 5 with an observation action; explicit asynchronous acceptance exits 0. `Code::Unknown` maps to internal failure. Operation-wait mapping distinguishes pending and uncertain outcomes.
- **Confirmation:** Non-TTY and `--non-interactive` decision commands return before connecting. PTY tests check EOF, `n`, other refusal input, successful confirmation, pending-decision preservation, and stale second approval. Source inspection places `Decide` after typed confirmation.
- **Fake-adapter gating:** Adapter setup and imports are compiled under `cfg(debug_assertions)`. `service_cmd::run` checks refusal before creating directories. The standard release profile disables this path; its release-only refusal test passed. That test proves the release gate/helper, rather than exercising a release service subprocess.
- **Case-index traceability:** All explicitly indexed names resolve in current Rust source and saved logs. Expanded group inventories contain A06: 29, A07: 32, A08: 71, A19: 121, A29: 64, and A17-local: 31 tests. Assertion sampling covered deadlines, revocation predicates, idempotency, decisions, events, cleanup replacement, bounded retries, and recovery.
- **Crash evidence:** The named process-crash cases actually kill spawned children. CLI service-death cases check the exact child against the advertised PID and assert one durable ledger effect after restart. In-process A06 reconstructions are separately labelled. The core crash case reconstructs recovery in the surviving test parent after actual child death; it is not a complete service-launch test.
- **Evidence integrity:** All seven records validate against `record.schema.json`. Examined statuses follow the documented lowest-row ordering, and missing native platforms have explicit blocked reasons. All 18 manifest-relative artifacts exist and match their hashes; the manifest and gap-fix log hashes match the recorded values.
- **Redaction:** The artifact scan found no matches for home paths, numeric Windows SIDs, IPv4 addresses, or canary values. Inspection found host/user placeholders; this is bounded redaction evidence, not proof against arbitrary identifying text.
- **Validation script:** Cargo test failures retain their exit through `PIPESTATUS[0]`; step failures accumulate. Announced zero-test or count-missing targets fail discovery. Schema checks compare two exports and both checked-in directories recursively, including extra files.

## Commands and validation

| Command or check | Exit | Result |
|---|---:|---|
| `git rev-parse HEAD` | 0 | Confirmed the requested commit |
| Requested `tests/g02/.venv/bin/python -I -c … tests/evidence/m01-*.json` | 127 | Interpreter absent |
| Same schema-validation code using `python3 -I`, with `validate(schema, value)` | 0 | Seven records valid |
| `cargo test --offline --locked -p heimdall --test e2e_cli_m01` | 0 | 15 passed |
| `CARGO_NET_OFFLINE=true bash tools/validation/check.sh` | 0 | 513 passed, 0 failed, 1 ignored; fmt, clippy, Windows-target clippy, discovery and schema checks all passed |
| `cargo test --offline --locked --release -p heimdall --bin heimdall release_profile_build_refuses_the_test_configuration` | 0 | 1 passed, 12 filtered out |
| JSON parse-error subprocess probe | **2** | Empty stdout; no envelope |
| Python source/log inventory, digest, redaction and generator mutation probes | 0 | Results reported above |
| Required prototype-output `du -sh …` inspection | 1 | No matching prototype output directories |
| `du -sh target` | 0 | 3.4 GB before cleanup |
| Scoped Python cleanup and final `git status --short` | 0 | `target/`, review logs and generated Python caches removed; working tree clean |

Other source inspection used `rg`, `cat`, `sed`, and `nl`. No tracked files changed; no commit or push was made.

Native harnesses, network access, and fresh remote-platform validation were skipped as required. Ctrl-C and prompt timeout were inspected in source but not exercised; M01 remains unverified at the integrated release head until the assigned fixes and evidence regeneration complete.

(Orchestrator note: the validator venv `tests/g02/.venv` is untracked and absent from a fresh worktree, so the reviewer's 127 is expected there; the same validation passed with `python3 -I`.)
