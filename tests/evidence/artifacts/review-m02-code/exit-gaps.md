# M02 exit gaps: independent review of the evidence tool and the exit-build test changes

Reviewer: Codex (gpt-6.1-sol, independent, read-only), over `c167736e..9bce3f9b` (the M02 evidence generator, the importer and their tests), `517160e0..e4f43f84 -- tests/model/revocation.rs` and `96611c6f -- tests/e2e/run_m02.rs`: the changes the exit record found no review covering. Saved by the orchestrator with home and scratch paths redacted. Rulings: ADR-0007 §12.51 item 9.

**Verdict: fix first.** The requested fixes pass their regressions and independent probes; I found no newly introduced defect in these diffs. Two observed residual defects still violate the broader generator/importer guarantees requested for this review. Both predate the reviewed patches and are identified as such below.

Reviewed committed scope:

- `c167736e..9bce3f9b`: only `tests/native/m02/m02-evidence.py`, `tests/native/m02/import-windows-bundle.py`, and `tests/native/m02/test_m02_evidence.py`.
- `517160e0..e4f43f84`: only `tests/model/revocation.rs`.
- `git show 96611c6f -- tests/e2e/run_m02.rs`: the exact-comparison change.

The working tree has an unrelated staged integration in progress. I did not review or change that integration. All three scoped Python files match their `9bce3f9b` blobs. Rust review used extracted committed blobs, including the production implementation at `e4f43f84`. I read ADR-0007 §12.51, spec §8.2 and plan §6.3 #8. I read `wave6x-recheck.md` after my initial source assessment.

## Findings

### R1 — Medium: an explicit exit-code entry can erase an observed required-command failure

**Location:** `tests/native/m02/m02-evidence.py:859` (`load_platforms`; reaches `command_failures`, `row_for` and `--write`). **Observed; pre-existing, not introduced by this range.**

`load_platforms` reads the required-command logs, then applies `codes.update(p.get("exit_codes") or {})`. A stale or accidentally duplicated zero in the configuration replaces a nonzero exit actually recorded in the log. There is no conflict diagnostic. This defeats the requested guarantee that a required command that was nonzero prevents verification.

Reproduction used the standard synthetic Scratch fixture, with all required tests passing:

- `windows.commands`: `exit 7: the required command`.
- Windows configuration: `"exit_codes": {"the required command": 0}`.
- Ran the generator through `main(..., "--write")` with all paths in scratch.
- **Observed:** generator return 0; Windows G2 status `verified`; emitted exit codes show only the configured zero; four records written; no `evaluation_reported_errors` marker.

This can conceal a failed native validation command when a configuration retains an older zero. Reject conflicting observations, or preserve any nonzero result rather than silently overriding it. Add a regression for the contradictory sources. The ordinary nonzero-log case, without the collision, correctly remains `in_progress`.

### R2 — Medium: repeated leading separators bypass Unix home-path rejection

**Location:** `tests/native/m02/import-windows-bundle.py:85` (`_SENSITIVE` Unix home rule). **Observed; pre-existing, not introduced by this range.**

The negative lookbehind excludes a preceding `/`. Consequently, `//home/synthetic-review-user/key` is accepted although it is an absolute home-path spelling (on Linux, repeated leading slashes resolve to the same `/home/...` path). The later redacted-root rule does not catch it either. This falls within the documented unredacted Unix home-path rejection, beyond the specifically repaired first-character cases.

A checksum-valid six-file fixture bundle carried this invented path in `build.txt`. `import_bundle` accepted it, passed the generator-readability checks, and wrote the path **byte-for-byte** into its destination under scratch. This was an actual import, not only a regex test. A WSL diagnostic using this path spelling can therefore carry an unredacted home/user component into public imported artifacts. Handle repeated leading separators without broadening rejection to the intentional fixture paths such as `/hm/home/fixture`, and add an end-to-end refused-bundle regression.

## Generator results and coverage trace

The requested exact command was executed:

`python3 -I tests/native/m02/m02-evidence.py --config tests/evidence/artifacts/m02/exit-e4f43f84/runs.json`

**Exit 1:** `required inventory: generated from other sources (sources_sha256 differs); regenerate at the build commit`. The current source tree includes the unrelated integration. The guard ran before summary output, so the exact invocation wrote no repository summary. I did not regenerate or alter the inventory.

To evaluate the actual native logs, I extracted the committed `e4f43f84` Rust sources into scratch, copied the configured log/commands/facts files there, and used the case index and inventory from `e4f43f84`. A scratch configuration redirected `sources_root`, `artifacts_root`, `summary_out`, inventory/index paths and every record path to scratch. This preserved the source-digest check rather than bypassing it. Ran the same generator without `--write`: **exit 0**, no evaluation-error marker. All executed native platform rows were verified. Groups A01, A11, A27 and A35 remained blocked on their additional named input/platform rows; A21, A22, R-RT-05, ADR-0006-13.20-3, R-SE-04 and T06 were verified. Deferred rows retained their decisions. These are ratings of supplied artifacts, not a rerun of the underlying native tests.

Independent scratch probes through `main`, including `--write`:

| Scenario | Generator return | Affected row | Records written | Error marker |
| --- | ---: | --- | ---: | --- |
| Whole-target logged test absent from inventory | 1 | in_progress | 0 | true |
| Required tests absent on every applicable host, all naming the missing capability | 0 | blocked on the exact supplied reason | 4 | absent |
| Required test absent on every applicable host, no reason | 1 | in_progress | 0 | true |
| Required test failed | 0 | in_progress | 4 | absent |
| Required command nonzero | 0 | in_progress | 4 | absent |
| Required test absent only on Windows | 0 | Windows in_progress | 4 | absent |
| Stale case-index exclusion with a logged result | 1 | in_progress | 0 | true |
| Inventory-only exclusion without rationale | 0 | in_progress | 4 | absent |
| Explicit platform-required test absent | 0 | in_progress | 4 | absent |
| Contradictory configured zero overriding logged nonzero | 0 | verified (R1) | 4 | absent |

`required` filters applicability; `coverage_guard` records unjustified exclusions, stale exclusions and unsatisfied platform requirements. `row_for` correctly downgrades failure, ignored, missing, stale-build and guard-gap cases. `rows_for` now downgrades the unlisted whole-target-test case and retains its name. `check_found` correctly distinguishes an all-host capability block from unexplained absence. Evaluation errors mark the summary and prevent all record writes. Failures that represent consistent negative evidence can return 0 while writing `in_progress` records; exit 0 alone is not a passing evidence rating. I observed no new loss of legitimate blocked records or misstatement of their reason.

## Importer checks

Checksum-valid end-to-end fixture imports refused the repaired plus-led, non-ASCII-led and emoji-led home components and `.ssh+name`. Exact fixture `.gitconfig`, `.config` and `.ssh` paths under a redacted root were accepted. Synthetic user/domain SID, non-loopback IPv4 and canary-prefix probes were refused. No canary value or sensitive matched content was emitted.

A read-only comparison applied the old and new complete `sensitive()` rules to **180 tracked files under `tests/evidence/artifacts/m02/`**. Both flagged 3 files, with zero changed decisions; the `exit-e4f43f84` subtree had zero flags. This is the bounded subtree requested here, not the earlier report's entire artifacts tree. There is no observed new refusal of those real exit artifacts.

Additional limits observed: a standalone `username=synthetic-review-user`, a relative `home/synthetic-review-user/key`, and a non-loopback IPv6 literal survived end-to-end import byte-for-byte. The importer has no general user-name detector, and its documented address check explicitly covers IPv4. Those are limits on broad personal-data rejection, not new regressions or additional findings against the narrower §12.51 rules. SID checks specifically cover the user/domain forms the implementation documents; this was not an exhaustive SID/encoding fuzz campaign.

## Rust assessment

**Revocation property:** sound by inspection. `block` constructs a current-thread Tokio runtime. `CountCoalesce::before` increments the count and returns synchronously; the no-preallocated-grant path reaches `SingleFlight::join_or_lead` without an intervening await. Other tasks cannot run between that count and the join on this runtime. Holding every adapter preparation until all requests entered Coalesce therefore establishes the intended overlap. A stored Notify permit covers a notification arriving between the count check and the wait. There are enough semaphore permits for every distinct preparation. The fixed seed supplies reproducible generated inputs; synchronization removes the former scheduler-dependent expectation of overlap.

The property still checks exact member/grant scope equality, matching deadlines, separation of distinct scope/deadline combinations, one grant and one effect per distinct input combination, and unusability after passing every deadline even when references were retained. This matches plan §6.3 #8 and spec §8.2's concurrent single-flight contract. The new sequential test awaits the first preparation before starting the second, asserts the same effective deadline, distinct grants, two effects and both grants remaining active. Those are the intended sequential semantics in §12.51 item 7. No Rust execution was performed.

**`run_m02.rs:993` at `96611c6f`:** correct and safe by inspection. Unix `printf '%s'` writes only the value; the Windows `cmd /c echo ... > ...` form includes the space preceding redirection and CRLF. The new assertion accepts exactly those platform-specific bytes instead of arbitrary trailing whitespace. `assert!(got == expected, "the child got it")` prints neither operand on failure, preserving canary-output discipline. No platform branch was executed in this review.

## Commands and actual exit codes

All Python invocations used `-I`. No Cargo command ran.

- Initial read-only shell inspection: `pwd`, targeted `rg` of the memory registry, `cat` of active home/project AGENTS and the code-review skill: composite shell exit **0**. No relevant memory entry was found or relied on.
- Scoped `git diff c167736e 9bce3f9b -- <three harness paths>`, `git diff 517160e0 e4f43f84 -- tests/model/revocation.rs`, `git show 96611c6f -- tests/e2e/run_m02.rs`, `git show <commit>:<path>` reads, `git status --porcelain=v1`, and targeted `rg`/`sed`/`nl`/`cat` reads: shell invocations **0**. These were source inspection, not build/test results. The initial and later status counts were 214; no concurrency state was reset.
- `python3 -I` extraction/identity helper: **0**; confirmed the five inspected Python harness/support working files matched `9bce3f9b`, and saved committed Rust blobs in scratch.
- Exact requested real evaluation above: **1**, source-digest refusal, no summary write.
- `python3 -I` wrapper setting `sys.dont_write_bytecode=True` and `tempfile.tempdir='<scratch>'`, then `runpy.run_path('tests/native/m02/test_m02_evidence.py', run_name='__main__')`: **0**, **117 tests passed** in 7.218 seconds. It ran the unchanged, commit-matching Python suite. The wrapper kept disposable fixtures inside the authorized scratch root.
- `python3 -I` helper extracting `c167736e` importer for comparison: **0**.
- `python3 -I <scratch>/probe.py`: **0**; generator probes, checksum-valid end-to-end importer probes and aggregate artifact comparison described above. Probe return 0 indicates the script completed; individual generator returns are listed in the table.
- `python3 -I <scratch>/real-eval.py`: **0**; committed-source real evaluation subprocess also **0**.
- `python3 -I <scratch>/extra-probes.py`: **0**; conflicting exit-code reproduction and independent coverage-guard probes.
- Scoped staged and unstaged `git diff --name-only -- tests/native/m02 tests/evidence/artifacts/m02`: **0**, both empty.

## Changed files, cleanup and unchecked work

Repository files changed by reviewer: **none**. Retained output: only `<report>`. Scratch scripts, copied committed sources, copied logs, summaries, generated records and imported synthetic bundles were removed from `<scratch>/` after reporting. No commits, pushes, configuration changes or owner credential/agent access occurred.

Not checked: Cargo builds/tests, native Windows/WSL execution, Rust mutation testing, fresh provider/secure-store behavior, or the unrelated integration. No build was run and no shared build output was touched.

Risk: the two observed residual paths can produce falsely verified evidence or import an unredacted home path. Passing Python checks and the successful scratch evaluation do not establish complete personal-data rejection or independently rerun native evidence.

Final output/cleanup validation: the report-writing shell and `python3 -I` cleanup helper exited **0**; the helper confirmed the report exists and `<scratch>/` no longer exists. No scratch evidence is retained outside this report.
