# M02-W5f-code-review — a961f4d5 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06, verbatim in substance.
Orchestrator resolution: ADR-0007 §12.40.

**Reviewed range:** `ee09084a..a961f4d5` (`74f63f7f`, `3b0154c5`, wave 5f), HEAD `a961f4d5`.

All four validation commands passed. L03 remains partly open: the importer still accepts and
persists personal home paths whose profile component starts with an exempt system name followed by
a space. No other defect was found in the reviewed Rust changes.

## Findings

### K01 — Medium (P2) — System-profile exceptions still admit personal names containing spaces

**Location:** `tests/native/m02/import-windows-bundle.py:63`, `:65`, `:70`; regression coverage at
`tests/native/m02/test_m02_evidence.py:1027`, `:1052`.

**Defect:** The negative lookaheads exempt a system profile name when it is followed by whitespace,
but whitespace can sit inside a personal profile component. The alternation also lets the shorter
`Default` exempt `Default User.Alice`.

**Evidence:** A probe over the actual importer and the `make_bundle` helper imported each of
`C:/Users/Public Alice/src`, `C:/Users/Default User.Alice/src`, `/mnt/c/Users/Public Alice/src` and
`/Users/Shared Alice/src` unchanged. **Observed.**

**Fix:** Recognize the complete component before applying the exception, never treating whitespace
as its end. Add rejection regressions for these cases and keep acceptance controls for exact
system profiles.

## Earlier findings re-checked

| Finding | Result |
|---|---|
| L01 Docker ownership and opt-in | closed within the ratified boundary (M16b, M17b–M17d; the actual `up.sh` with a post-pull image stub exits 3) |
| L02 Windows metadata protection | closed (E02) |
| L03 exact profile components | partly closed; K01 remains |
| L04 bounded report read | closed |

The 3b0154c5 macOS-rule correction is sound for `PATH=...:/Users/x` and `file:/Users/x`.

## Checks found sound (summary)

* Own-value classification checks multiplicity, scope, conditional inclusion and the exact
  rendered B_git bytes.
* The shadowing regressions check both origins and digests, no raw values, and no finding when
  the user value wins or local queries are off.
* Rollback uses the recorded include file, with the ratified fallback.
* `include_file` is additive and serde-defaulted, with round-trip and old-record tests.
* Contract comments match the regenerated schemas.
* The added-line scan found no committed secret or personal path.

## Commands and validation

| Command or check | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1755 passed, 0 failed, 8 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `bash tools/validation/native-harness-selftest.sh` | 0 | 274 passed; 102 Python tests; PowerShell self-test |
| importer probe | 0 | reproduced K01 |
| actual `up.sh` with a post-pull image stub | 3 | correct refusal |
| `git diff --check`; cleanup; final status | 0 | clean |

Not checked: native exit-build runs; real Docker concurrency; live providers; wave 5g.
