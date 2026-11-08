# Evidence records

One JSON file per acceptance-case or gate-probe attempt, validating against
`record.schema.json` (plan.md §6.6, plus `blocked_on` for blocked records).
Raw, redacted command output lives under `artifacts/<case_id>/`.

Rules: a record for an unexecuted command has `observed_result: null`. A
platform-unavailable test is `blocked` with `blocked_on` naming the platform.
Merged-but-unexecuted code is `implemented_unverified`, never `verified`.

## Gate-probe status convention (orchestrator decision, 2026-10-03)

The status vocabulary has no `failed`. Gate probes and experiments (case IDs
`G0x-…`) use it like this:

- `status` describes the evidence, not whether the hypothesis held.
  - `verified`: the probe ran as designed and its raw output is preserved.
    This holds even when the criterion failed.
  - `in_progress`: the probe ran but the evidence is invalid or incomplete,
    for example interrupted or missing a control.
  - `blocked`: the probe could not run here.
- `observed_result.verdict` is required whenever `observed_result` is
  non-null. It is one of `pass`, `fail` or `inconclusive`, and refers to the
  probe's stated criterion.
- A record that names product requirement IDs is never by itself evidence that
  the requirement is met. Harness self-test records carry no product
  requirement IDs.

Acceptance cases (`A01`–`A36`) keep the plan meaning. `verified` means the
pass condition was observed on the stated environment. A failing run stays
`in_progress` or `implemented_unverified`, with expected and observed results.

Multi-row inventory records, such as the fixture inventory, put the
authoritative status for each row in `observed_result.per_fixture` (or an
equivalent per-row map). The top-level `status` is the lowest per-row status
among the rows the record claims to cover. The order, lowest first, is `blocked`,
`not_started`, `in_progress`, `implemented_unverified`, `verified`. A row with
`deferred_with_decision` is not part of the claim and does not count. So a record
with one `blocked` row and every other row `verified` is `blocked`, and its
`blocked_on` names the missing input for that row.

Canary rule: no evidence record or artifact may contain a full
`HEIMDALL_CANARY_…` value. Harness assertion text names a canary by fixture
and key path, never by value. The prefix alone, used as a scan pattern, is
allowed. Synthetic canary values may appear in fixtures and test inputs that
define them; a canary value anywhere else (program output, logs, arguments,
artifacts, redacted evidence) is a defect (ADR-0004 §4).

## M02 additions (existing-access slice; `tests/native/m02/`)

M02 records are `tests/evidence/m02-*.json`, one per exit case or claim of m02-plan §3,
written by `tests/native/m02/m02-evidence.py --write` from `tests/native/m02/runs.json`. Raw,
redacted harness output lives under `tests/evidence/artifacts/m02/exit-<commit>/<platform>/`
(`check.txt` or `tests.txt`, `observations.txt` on macOS, `host.txt`, `commands.txt`,
`skipped.txt`, `canary-scan.txt`). One build, one directory: every row of every record comes
from the same build commit.

- **One record, one row per platform.** `observed_result.rows` has a row per declared
  platform (macOS, Linux, Windows, the WSL disposable distribution) plus a row for each
  owner-input gap. The record's `status` is its lowest row (the order above), so one blocked
  row makes the record `blocked`.
- **Blocked rows name their input.** A row is `blocked` only for a platform that is missing, a
  capability that is missing, or an owner input of m02-plan §7 (B1 to B10), and `blocked_on`
  names it exactly, for example `B3: a disposable macOS standard user account`. A test that
  did not run on a platform that was available is `in_progress` with the reason on the row:
  `incomplete_run`, `harness_gap_not_run` (a test that reads the repository at its
  compile-time path and cannot run off the build host), `no_applicable_test` (m02-plan §4
  declares the row but no indexed test exists on that platform), `excluded_without_rationale`
  or `platform_required_not_passed` (below). Never `blocked`, never `verified`.
- **Required tests come from the case index, never from a run.** `case-index.json` maps each
  case to its tests; `required-inventory.json` resolves those patterns against the sources and
  the cross-built binaries' symbols (`#[cfg]`), and records the digest of the sources it came
  from. The generator refuses another digest (regenerate with
  `tests/native/m02/refresh-inventory.sh` at the build commit), a test that ran but is not in
  the inventory, and a required test that is absent from every log.
- **A platform row covers what the case declares there (ADR-0007 §12.47 item 1).** Applicability
  alone is not coverage: a row that kept only the tests surviving `#[cfg]` would read `verified`
  on whatever few portable tests are left. So on every platform a section declares:
  - **Every exclusion is counted.** Each row reports `excluded_on_this_platform`: how many of the
    section's required tests do not exist on that platform.
  - **(R1) An exclusion needs a written reason.** A test excluded by a `case-index.json`
    `platform_only` entry is listed, by entry, in `excluded_by_rationale`. Every such entry is
    `{"platforms": [...], "rationale": "..."}`, and the rationale cites the plan, the ruling or
    the Windows counterpart that justifies it (the generator refuses an entry without one). A
    test that only the inventory scan excludes has no reason on record. It is listed in
    `excluded_without_rationale`, and the row stays `in_progress`.
  - **(R2) Declared tests are named exactly.** A section's `platform_required`
    (`{platform: {target: [exact test name]}}`) lists the tests the plan names for a platform.
    Each must pass in that platform's log, or it is listed in `platform_required_not_passed`
    with its result (`absent`, `FAILED`, `ignored`), and the row stays `in_progress`. These
    names are never resolved against the inventory, so a planned test that was never written
    reads as not run.
  - **A stale reason is an error.** A `platform_only` entry that leaves a platform out, while
    that platform's log has a result for the test, stops the generator with exit 1: widen the
    entry or remove it.

  So a unit that ports a test to a platform removes the test from its `platform_only` entry. A
  unit that keeps a test platform-only adds one entry for it, with the platforms where it exists
  and the reason. A deferral is a `deferred_with_decision` row citing its ruling, together with the
  `platform_only` entry that excuses the test.
- **Native means native.** A cross-build, a stub, a mock or emulation closes no native claim.
  `tools/validation/native-harness-selftest.sh` exercises every M02 harness against stubs and
  a fake host tree: that is harness evidence only. It never appears in a record as product
  evidence and carries no product requirement ID.
- **Settled facts are recorded with their observation.** A test that settles an ADR-0007 `[I]`
  or `[U]` fact (exchange support per file system, birth time, each client's and Git's
  behaviour) prints a line starting with `observation`. The harnesses keep those lines
  (`--show-output`), and the row of a platform carries `observations` for the tests that
  passed there. A fact not observed on a target stays `[I]` for that target.
- **Evidence wording for A21.** `executed_config_commands` is described as "constructs found
  before execution", never as complete, and `config_tree_changed` as a comparison of two
  observed snapshots (it cannot see a change reverted before the second one).
- **In-process reconstructions are labelled** as such, as in M01 N06. The ADR-0007 §5.9
  unsupported concurrency cases are stated in the compatibility matrix, not counted as
  evidence.
- **Redaction.** Host, user and home names, domain SIDs and non-loopback addresses are
  replaced before anything is saved. Each harness then scans every artifact for those values
  and for the canary prefix; a hit fails the run.
