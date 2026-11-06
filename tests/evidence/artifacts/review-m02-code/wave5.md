# M02-W5-code-review — d2b78ed5 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06; the findings, the re-check
table and the validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007
§12.33.

**Reviewed range:** `bcad82de..d2b78ed5`, at HEAD `d2b78ed5`.

Q01–Q04 are closed for their reviewed failure scenarios, and the launch-test fork gate covers the
spawning paths in the Unix test process. All five requested validation commands passed. Two harness
safety defects need correcting: the macOS fallback can tear down another run's Docker fixtures, and
the isolated scenario can read and execute hooks from an inherited XDG Git configuration.

## Findings

### P01 — High (P1) — Docker fallback claims cleanup ownership before startup succeeds

**Location:** `tests/native/m02/run-macos.sh:115`, `:64`; supporting behaviour in
`tests/fixtures/ssh/up.sh:9` and `tests/fixtures/ssh/down.sh:14`.

**Defect:** The fallback sets `docker_up=1` before invoking `up.sh`. When `up.sh` refuses because
fixture resources already exist, the EXIT trap still invokes the shared `down.sh`. That teardown
selects the common fixture label, removes containers, networks and the fixture image, and disposes
of the shared runtime key material. Nothing establishes that this invocation created them.

**Evidence:** A disposable fake repository ran the actual `run-macos.sh`, `lib.sh` and
`remote-lib.sh`, with stub Docker entry points. `up.sh` found a pre-existing fixture sentinel and
exited 1 without creating anything; `down.sh` recorded its invocation and removed the sentinel. The
harness exited 1, teardown ran, and the pre-existing sentinel was gone. **Observed with stubs**;
destroying real Docker fixtures is **inferred** from the teardown code. No real Docker resources
were touched.

**Fix:** Establish exclusive per-run fixture ownership before allowing teardown, including cleanup
after a partial startup failure. A refusal caused by pre-existing resources must leave them
untouched. Add a regression for that refusal alongside the existing partial-startup cleanup test.

### P02 — Medium (P2) — Isolated scenario inherits the owner's XDG Git configuration

**Location:** `tests/native/m02/scenario-ordinary-ssh.sh:186`, `:272`; supporting omission in
`tests/native/m02/remote-lib.sh:24`.

**Defect:** `hm2_sanitize_env` clears the `GIT_*` variables but keeps `XDG_CONFIG_HOME`. A scratch
`HOME` plus `GIT_CONFIG_NOSYSTEM=1` still lets Git read `$XDG_CONFIG_HOME/git/config`. The
scenario's init and commit commands can therefore use the owner's configuration and run its hooks
(`init.templateDir`, `core.hooksPath`), includes and credential helpers.

**Evidence:** Two probes sourced the actual `remote-lib.sh` and ran its sanitizer with a scratch
`HOME` and a separate synthetic XDG configuration directory. `git config --global --get` read a value
from outside the scratch home, and a template hook configured there ran on the fixture commit.
Exit 0. **Observed with synthetic configuration**; exposure of a real owner configuration is
**inferred**.

**Fix:** Pin Git's user configuration lookup to disposable paths for every scenario Git invocation:
a scratch `XDG_CONFIG_HOME` and an explicit empty `GIT_CONFIG_GLOBAL` after sanitizing. Add a
regression with an external synthetic XDG configuration and hook, asserting neither is used.

## Earlier findings re-checked

| Finding | Result |
|---|---|
| Q01 attended purge confirmation | closed (refusal, affirmative and rollback-plus-purge e2e tests pass) |
| Q02 skipped authorization | closed (unit interleavings and the real-binary regression pass) |
| Q03 truncated decision content | closed in the renderer (stacking, wrapping, scrolling, end gating) |
| Q04 unreachable authorization entries | closed (independent scrolling, fixed prompt, all 15 entries reached) |
| intermittent pipe test | fix sound; every parent-process spawn path takes the gate; no recursive acquisition |

Sensitivity is inferred from the assertions; the reviewer ran no mutations.

## Checks found sound (summary)

* Typed confirmation is kept on every reviewed path.
* The fork gate does not change production launch behaviour.
* The §12.30 changes have discriminating assertions.
* All 14 m02 records are `blocked`, with each top-level status equal to its lowest row and each
  blocked row naming its input. Read-only regeneration reproduced the summary and all 14 records
  exactly, and the inventory digest matched.
* All 22 artifact hashes in `digests.txt` matched.
* No private keys, concrete canaries, personal home paths, SIDs, tailnet addresses or unredacted
  identifiers were found in the artifacts.

## Commands and validation

| Command or check | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1665 passed, 0 failed, 7 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `bash tools/validation/native-harness-selftest.sh` | 0 | 258 passed; Python suite 91 tests OK |
| `python3 -I tools/validation/validate-records.py` | 0 | 100 records, 0 invalid |
| scratch Git configuration and hook probes | 0 | reproduced P02 |
| stubbed macOS fallback ownership probe | 1 (harness) / 0 (probe) | reproduced P01 without Docker or host access |
| read-only evidence regeneration | 0 (check) | exact match; the generator itself returned 1 with 23 unavailable-platform diagnostics (the known §12.32 item 10 defect) |
| cleanup; final `git status`; `git diff --check` | 0 | clean |

Not checked: native harness runs against any host; native Windows and WSL; live providers; real
Docker teardown; mutation runs.
