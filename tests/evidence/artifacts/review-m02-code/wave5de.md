# M02-W5de-code-review — ee09084a — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06; the findings, the re-check
table and the validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007
§12.38.

**Reviewed range:** `7dd879f8..ee09084a` (`6fba5ddf`, `fce9a06b`, `ee09084a`), HEAD `ee09084a`
before and after.

The four required checks passed. Four harness and importer defects remain:
* Docker cleanup ownership is still open to a race;
* Windows metadata skips canary protection;
* the importer accepts some unredacted personal home paths;
* the CLI reads reports without an input bound.

No defect was found in the removal-summary implementation, N01, N02 or the reviewed Git
re-preview behaviour.

## Findings

### L01 — High (P1) — Docker cleanup ownership is still inferred from a nonexclusive preflight

**Location:** `tests/native/m02/run-macos.sh:126`, `:132`; `tests/fixtures/ssh/up.sh:16`, `:31`;
`tests/fixtures/ssh/down.sh:14`.

**Defect:** Exit 3 protects resources visible during the initial checks, but those checks take no
exclusive ownership. If another run creates the fixture image afterwards, the second image check
calls `die`, which returns 1. The runner treats that as ownership, sets `docker_up=1` and invokes
the shared teardown, which selects the common fixture resources and the shared runtime directory.

**Evidence:** A disposable fixture copied the actual `up.sh`, `down.sh` and `lib.sh` with a stub
Docker. The stub made another run's image and runtime sentinel appear during `docker pull`. The
actual `up.sh` returned 1, and the actual `down.sh`, invoked as the runner's exit-1 path does,
returned 0 and removed both. **Observed with stubs.** No real Docker resources were touched.

**Fix:** Take exclusive fixture ownership before any startup change and keep it through cleanup,
or use run-specific resources with an ownership token checked at teardown. Add a regression in
which resources appear after the initial preflight.

### L02 — Medium (P2) — Windows bundle metadata bypasses canary masking and accounting

**Location:** `tests/native/m02/run-windows-local.ps1:665`; also `:182`, `:670`.

**Defect:** File bodies go through `Protect-BundleFiles`, which redacts, counts canaries and masks
their values. The label goes only through `Invoke-Redaction`, which does not mask canaries, and is
then serialized into `bundle.json` and the emitted bundle, outside the recorded canary count.

**Evidence:** A PowerShell probe over the actual helpers, with a canary built at run time in the
label, produced bundle JSON containing one canary prefix. **Observed.**

**Fix:** Apply canary counting, masking and leak accounting to metadata before serializing, include
metadata failures in the overall result, and add a regression.

### L03 — Medium (P2) — System-profile exceptions also exempt personal profile names

**Location:** `tests/native/m02/import-windows-bundle.py:61`, `:63`, `:65`.

**Defect:** The home-path exclusions use a word boundary after names such as `Public`, `Default`
and `Shared`. A word boundary also exists before punctuation inside a personal profile name, so
`Public-Alice` is treated as an exempt system profile.

**Evidence:** A disposable bundle with `C:\Users\Public-Alice\src` passed `sensitive()` and was
imported unchanged. **Observed**; the WSL and macOS forms are inferred from the same construction.

**Fix:** Exempt exact profile-directory components (followed by a separator or the end of the
component). Add rejection tests for hyphenated and dotted personal names.

### L04 — Medium (P2) — Report input is read completely before the size check

**Location:** `tests/native/m02/import-windows-bundle.py:94`, `:249`.

**Defect:** `decode()` bounds its input, but `main()` first calls an unbounded `Path.read_text()`.

**Evidence:** With `MAX_REPORT` reduced to 1024, a 4096-character file was read whole before
`main()` refused with exit 1. **Observed at reduced scale.**

**Fix:** Read from the opened file with a hard limit before decoding, and add a CLI-level regression
that checks how much input is consumed.

## Earlier findings re-checked

| Finding | Result |
|---|---|
| P01 Docker ownership | The immediate refusal is fixed; the concurrent case remains as L01 |
| P02 Git configuration isolation | closed (S17 with S10 and S11 controls) |
| N01 unestablished client behaviour | closed |
| N02 existing snapshots | closed (no-follow validation; directory-relative no-replace copy) |
| N03 metadata and content checks | improved; L02 and L03 remain |
| N04 bounded decompression | decompression fixed; the CLI read remains as L04 |
| N05 temporary directories | closed (E01) |

## Checks found sound (summary)

* Removal summaries cover only wholly removed Heimdall-owned files (ManagedSsh, GitManaged,
  KeyFile). Owner files keep full diffs.
* Summary measurements are taken from the previewed bytes.
* The size exception never exempts owner-file changes.
* The confirmation rendering keeps the disclosure, in the CLI and the TUI at both sizes.
* N01 reaches the behaviour and authorization views.
* N02 validates the opened object.
* The Git re-preview fails closed around user values.
* The state-directory guard has active controls.
* The content scan found no leak.

## Commands and validation

| Command or check | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1744 passed, 0 failed, 8 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `bash tools/validation/native-harness-selftest.sh` | 0 | 271 passed; Python suite 100 tests |
| probes (Docker race, PowerShell metadata, home path, reduced-limit read) | 0 | reproduced L01–L04 |
| cleanup; `git diff --check`; final status | 0 | clean |

Not checked: native harness runs against hosts; native Windows and WSL; real Docker concurrency;
live providers; wave 5f's excluded work.
