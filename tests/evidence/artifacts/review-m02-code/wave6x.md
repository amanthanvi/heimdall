**Verdict: fix first.** Review of `421c8f41..250029ea`, with line numbers pinned to `250029ea`. Report: [report.md](/tmp/hm-w6x-review/report.md).

The checkout was already at `c51b81666111dc5622ce1ea4c50cc44006c08580`, ahead of the requested range. I reviewed an exported snapshot of the requested endpoint, without changing the checkout. Windows conclusions below are inferred; no Windows execution was performed.

**Findings, ranked by severity**

**W6X-R01 — high — The rendered-pipe fixture guard accepts traversal to a non-fixture agent.**

- **Location:** `crates/testkit/src/home.rs:375–377`; delegated predicate at `crates/testkit/src/agent.rs:99–103`.
- **Failure scenario:** A scratch configuration names `IdentityAgent //./pipe/heimdall-hmtest-x/../openssh-ssh-agent`, alongside a valid scratch `IdentityFile`. The new branch rewrites the prefix and calls `is_fixture_pipe_name`, which checks only the initial prefix and that a suffix exists. The suffix containing `/../` therefore passes. The client receives the original configuration value. Windows normalizes ordinary `\\.\` device paths, converts `/` separators, and resolves `..`; this spelling consequently selects `\\.\pipe\openssh-ssh-agent`. A test can contact the owner's real agent despite passing the guard. The same predicate also accepts a traversal suffix in the existing backslash spelling.
- **Evidence/classification:** **Inferred Windows behavior**, supported by the exact predicate and Microsoft's [path-normalization documentation](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#path-normalization), including its distinction between normalized `\\.\` and unnormalized `\\?\` paths. I did not contact any real agent. The newly added forward-slash branch is in this range; the weak shared predicate predates it.
- **Suggested fix:** Parse both spellings as a named-pipe locator, require a single nonempty pipe-name component, and then validate the fixture prefix. Reject embedded separators and expansion tokens. `heimdall_localenv::agents::locator_for` already rejects separators inside the pipe name. Add regressions for both traversal spellings using a disposable non-fixture-named pipe, never the system agent. This enforces ADR-0007 §9 and m02-plan §0.

**W6X-R02 — medium — A stale exclusion can still be persisted as a verified record.**

- **Location:** `tests/native/m02/m02-evidence.py:724–725`, `:898–902`, and `:1103–1121`.
- **Failure scenario:** A case-index rationale excludes a test on Windows, but that test now exists and appears as `ignored` in the Windows log. Its target can legitimately exit zero. `coverage_guard` records the stale entry; `evaluate` sets `rc = 1`. However, the excluded test is absent from `required()`, `guard_gap()` ignores `stale`, and `row_for()` rates the remaining passing tests `verified`. `main --write` writes the summary and evidence records before returning the nonzero exit code.
- **Evidence/classification:** **Observed** with the endpoint's own synthetic test helpers. The probe produced generator exit **1**, Windows row **verified**, persisted Windows row **verified**, and persisted overall record **verified**. The stale diagnostic explicitly identified the test as `ignored`. The existing stale-entry regression checks the exit code and diagnostic, but not the resulting status or persisted output.
- **Suggested fix:** Include stale exclusions in the row's coverage-gap calculation, and refuse evidence writes when evaluation reports an invalid index/inventory relationship. Add a `--write` regression with an ignored stale test. A nonzero command exit alone does not prevent misleading evidence files from remaining on disk. This violates the coverage guard's purpose in ADR-0007 §12.47 item 1.

**W6X-R03 — medium — The bundle importer still accepts unredacted home paths.**

- **Location:** `tests/native/m02/import-windows-bundle.py:73–77`, consumed by `validate` at `:173–176`.
- **Failure scenario:** The placeholder exemption accepts any dot-prefixed component after `<scratch>/home/`, including a directory rather than a terminal dotfile. Thus `<scratch>/home/.private/synthetic-review-user/key` is accepted. Separately, the Unix/macOS rules recognize only ASCII letters, digits, dot, underscore and hyphen at the beginning of a home component, so `/home/é-review-user/key` and `/Users/é-review-user/key` pass. These are valid possible home-path forms containing an unredacted account name.
- **Evidence/classification:** **Observed.** All three strings returned no sensitive-content finding and were successfully imported in checksum-valid synthetic bundles; the imported `build.txt` retained each string exactly. All names were invented. **This importer is unchanged in the reviewed range**; this is an existing defect in the explicitly requested review scope, not a wave-6x regression.
- **Suggested fix:** Limit the placeholder exemption to a terminal fixture dotfile, disallowing a subsequent path separator, and recognize complete home components without an ASCII-only initial-character restriction. Add end-to-end importer rejection tests for these paths. Preserve the intended `<scratch>/home/.gitconfig` exemption. This is a gap in the home-path leak rules reinforced by ADR-0007 §12.46 item 1.

**W6X-R04 — low — Quarantine validation can create a directory during preview.**

- **Location:** `crates/localenv/src/projection/plan.rs:2408–2412`; creating callee at `crates/localenv/src/projection/replace.rs:425–433`.
- **Failure scenario:** Preview observes an existing empty quarantine with `symlink_metadata`. Before the next call, another operation or cleanup removes it. Preview then calls `Quarantine::open_or_create`, which recreates the quarantine. This causes a filesystem write during a nominally passive preview, on Unix as well as Windows. The initial existence check does not make the creating API read-only.
- **Evidence/classification:** **Inferred from the race and the called implementations.** The Unix implementation calls `mkdirat` when the entry is absent (`sys/quarantine.rs:237–249`); the Windows implementation calls `create_owner_only_dir` (`:433–439`). No timing-based reproduction was run. The new check extends this problem to P/key directories; an analogous older check exists for the user-file directory.
- **Suggested fix:** Use the existing `Quarantine::open_existing` API, handling absence without creation and validation errors conservatively. Add a deterministic removal-between-check-and-open regression. This preserves the preview's no-write contract described in the helper itself and ADR-0007 §12.48 item 5.

**Areas checked and clean within the limits of this review**

- `adopted_key`/`key_matches`: the new separator replacement is gated by the modeled Windows platform; the Unix predicate retains its previous comparison behavior.
- Directory creation: the new Windows descriptors are protected and supplied at creation. Heimdall directories use the user-only DACL; user directories include the user, SYSTEM and Administrators. The Unix recursive creation path retains mode `0700`. No additional defect identified in these changes against ADR-0007 §12.48 item 4.
- Windows `account_name`/`local_account`: token ownership uses RAII; the token-information buffer is aligned and bounded; lookup capacities and returned lengths are checked; UTF-16 conversion errors return an error. No memory-safety defect identified under the documented Win32 API contracts. Unix account lookup remains unchanged.
- Launch eligibility: pipe spelling normalization uses the existing locator parser; the declaration, revision, expiry and per-profile endpoint comparisons remain in place. No new fail-open path identified.
- `PipeFixture`: reviewed first-instance acquisition, descriptor continuity, remote-client refusal, bounded first-write identification, SID verification and open counting. No additional defect identified by static inspection against ADR-0006 §13.21.
- `sshd`/`win` helpers: reviewed strict/default harness selection, per-process key-file leases, drop cleanup, log offsets, account validation, security-allocation lifetimes and handle ownership. No additional defect identified. These are static-review conclusions, not native Windows validation.
- R1/R2 guard basics: unexplained scan exclusions and absent/failed/ignored `platform_required` names keep rows incomplete in the targeted tests. The stale-entry write defect is separated above.

**Commands run and validation**

- Read-only Git inspection: `git status --short`, `git rev-parse HEAD`, `git log --oneline 421c8f41..250029ea`, and scoped `git diff`/`git diff --stat`. Successful inspection commands exited **0**. The initial checkout status was clean. The final status showed concurrent edits to docs/architecture/overview.md and tests/e2e/run_m02.rs; I did not modify either file.
- Exported `250029ea` with `git archive ... | tar -x` under `/tmp/hm-w6x-review/`; used `rg`, `sed`, `nl`, and `cat` to inspect the fixed sources and acceptance documents.
- Ran the endpoint's Python `Patterns`, `Inventory`, `Applicability`, `Rows`, `CoverageGuard`, and `WindowsBundle` test classes with temporary directories restricted to the review directory: **50 tests passed, exit 0**.
- Ran the custom stale-record/importer probe: **exit 0**, confirming W6X-R02 and W6X-R03. Its first attempt exited **1** because the probe used the wrong evidence-field name; after correcting that probe-only error, all assertions passed. The nested generator invocation in the successful probe returned **1**, as reported in W6X-R02.
- Consulted Microsoft's Windows path-normalization documentation for W6X-R01. No Rust build, Cargo test, clippy, validation script, service action, or Git write was performed.

**Changed files:** only `/tmp/hm-w6x-review/report.md` retained. Temporary exported sources and synthetic probe material were removed. No tracked files changed.

Not checked: native Windows execution or the full workspace test suite; this review does not certify the Windows milestone.
Risk: the inferred fixture escape needs a native disposable-pipe regression, and the observed evidence/importer defects need fixes before relying on generated verification records.
