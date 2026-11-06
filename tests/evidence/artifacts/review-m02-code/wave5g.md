# M02-W5g-code-review — 1f5b8156 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06, verbatim in substance.
Orchestrator resolution: ADR-0007 §12.42.

**Reviewed range:** `cb5139e4..1f5b8156` (wave 5g `09bdbe10`, inventory refresh `cb16c2d6`, evidence
import `1f5b8156`), HEAD `1f5b8156`.

Two paths still permitted rollback without the decision required by amended ADR-0007 §5.6, and one
regression test did not prove its claim. All three requested validation commands passed.

## Findings

### R01 — P2 — Process-level Git configuration can waive a persistent selection change

**Location:** `crates/localenv/src/projection/plan.rs:1185` (`winning_origin`).

**Defect:** `winning_origin()` queried all scopes, including command-scope values supplied through
`GIT_CONFIG_COUNT`, and treated any winning origin other than P_git as proof that the user's
persistent value already wins. ADR-0007 §5.6 requires setup's before/after selections to cover
system and global configuration; process overrides are handled at runtime.

**Evidence (Observed):** B_git applied into `~/.gitconfig`, then a shadowed `core.sshCommand` added
to XDG. Without an override Git still selected Heimdall. With `GIT_CONFIG_COUNT=1` and a
command-scope `core.sshCommand`, rollback planned B_git removal with
`ConsentNeed { decision_required: false, reasons: [] }`.

**Fix:** Establish the winner across the system and global scopes only, and add the fixture to the
consent regression test.

### R02 — P2 — An incomplete observation can bypass the undeterminable-winner rule

**Location:** `crates/localenv/src/projection/plan.rs:1194`.

**Defect:** Conservative handling was confined to `Some(user_value)`. When observation could not
read the include graph and found no user value, the `None` arm assumed the known default, which
could match the original consent and waive the decision.

**Evidence (Observed):** After applying the Git item, an XDG include pointing to a disposable
directory made `observe_global()` report unreadable configuration and `winning_origin()` return
`None`. Rollback planned B_git removal with `decision_required: false`.

**Fix:** Treat an incomplete observation as undetermined whether or not a user value was found:
require a decision, or refuse the preview until observation succeeds.

### R03 — P3 — The moved-block test does not prove the recorded-file search fallback

**Location:** `tests/integration/projection_git.rs:3727`.

**Defect:** The fixture moved B_git from `~/.gitconfig` into XDG, which is then the first-read file,
so selecting that file succeeded without any search.

**Evidence (Observed):** A mutant that skips the search whenever the recorded file has no block
passed all five `git_reapply_` tests. A scratch fixture that moved B_git the other way, from XDG
into `~/.gitconfig` with an unmarked XDG file kept, passed at HEAD and failed against the mutant.

**Fix:** Add the reverse-move fixture and assert applicability, a P_git-only update, and unchanged
global-file bytes.

## Not findings

- The recorded-file lookup, ordinary search behaviour and Git read order matched the reviewed
  rulings.
- §12.41's explicitly accepted moved-block rollback and edited-target residuals were not counted.
- The new `build_host_paths` entry preserves the evidence tool's semantics: remote absence is
  neutral, build-host absence stays incomplete, and an explicit remote failure stays failed.

## Commands (reviewer)

| Command | Exit / result |
|---|---|
| `cargo test --locked -p heimdall-localenv --test integration_projection_git` | 0, 42 passed |
| `cargo clippy --locked -p heimdall-localenv --all-targets -- -D warnings` | 0 |
| `python3 -I tests/native/m02/test_m02_evidence.py` | 0, 102 passed |
| Scratch probes for R01 and R02 (assert a decision) | 101, both reproduce |
| First-read-only, always-user-wins and never-user-wins mutants | 101 each, caught |
| Mutant that skips the search when the recorded file is empty, against the existing reapply tests | 0, survived |
| Reverse-move scratch test at HEAD / against that mutant | 0 / 101 |
| Canary, private-key-marker and home-path scan of the imported artifacts | 0 |
| `git diff --check cb5139e4..1f5b8156` | 2 (a trailing blank line in imported observations; not raised) |

Native Windows/WSL was not run by the reviewer, so case-only and separator-only path behaviour
stays unverified there. That run is the wave-6w Windows native run.

## Orchestrator follow-up (2026-11-06)

- **R01:** `winning_origin` now runs `git config --show-scope --show-origin -z --get-all` and
  takes the last system or global occurrence (`parse_scope_origin_values`, with unit tests).
- **R02:** `plan_git_rollback` treats `unreadable` or an unestablished global file as
  incomplete; the after-selection is `undetermined`.
- **R03:** the reverse-move fixture was added.
- **Regressions:** two cases were added to `git_rollback_in_the_shadowed_case_needs_a_decision`
  (command scope; unreadable include, `undetermined_state`).
- **Mutation checks (observed on macOS):**
  - R01 filter removed: the command-scope case fails (101).
  - R02 arm disabled: the unreadable-include case fails (101).
  - The reviewer's skip-the-search mutant: `git_reapply_trusts_the_recorded_file_and_follows_a_block_the_owner_moved` fails (101).
- **Results:**
  - `integration_projection_git`: 42 passed.
  - `integration_git_observe`: 24 passed.
  - `integration_doctor`: 17 passed.
  - localenv `git::` unit tests: 4 passed.
