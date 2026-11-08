# M02-W6-code-review — wave 6w (1f5b8156..ce21a76f) — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree on macOS. Windows-only code was reviewed by reading. Saved by the
orchestrator on 2026-11-08, verbatim in substance. Orchestrator resolution: ADR-0007 §12.46.

**Verdict:** fix first. There are two P2 findings, in evidence handling and test coverage, and one
P3 timing-test defect. Reading found no further product defect in the quarantine or pipe
implementation.

## Findings

- **W6W-R01, P2, Observed** (`tests/native/m02/import-windows-bundle.py:72`).
  - **Defect:** the dot-segment exemption `(?!<|\.)` admits every dot-prefixed component after
    `/home/`. The motivating case was only `<scratch>/home/.config` and `.gitconfig`, and Unix home
    locations need not follow user-name rules.
  - **Evidence:** a framed synthetic bundle carrying `/home/.review-fixture-user/private/project` was
    imported unchanged. The `/home/review-fixture-user/...` control was refused.
  - **Fix:** confine the exemption to fixture paths under the redacted scratch root. Add negative
    cases for bare dot-prefixed homes and for `/home/.private/alice/...`.
- **W6W-R02, P2, Inferred** (`crates/testkit/src/agent.rs:918`).
  - **Defect:** `connections()` counts only connections that the production listener has identified.
    On Windows a client can open the pipe, send nothing and close without being counted.
    `tests/integration/adapters.rs:408` still reads zero as "no connection was even opened", and the
    cancellation tests assert zero at `:1645`. On Windows these assertions no longer observe a silent
    open.
  - **Fix:** expose a fixture observation of opens before identification, keep the accepted count
    separate, and use the open count for the passivity assertions. Production authentication stays as
    it is.
- **W6W-R03, P3, Inferred** (`crates/ipc/src/windows.rs:1376`).
  - **Defect:** the silent-client regression measures time around `accept()`, which keeps waiting after
    a refusal, so even an immediate disconnect satisfies the lower bound. The client join has no
    timeout of its own.
  - **Fix:** observe the client's EOF concurrently with `accept()`. Assert that the EOF does not come
    before the bound, and that it comes within a bounded allowance after it. Mutation-check the test
    with a shortened identification timeout.
- **Weakened assertion** (`tests/e2e/run_m02.rs:992`).
  - **Defect:** the argv-canary check became `got.trim_end() == canary` on both platforms, so on Unix
    the exact comparison became equality after removing any trailing whitespace.
  - **Fix:** keep the exact comparison on Unix, and allow only Windows' expected suffix there.

## What the review found sound
- **Quarantine removal:** it reopens with DELETE and checks identity, directory kind, owner and the
  exact protected, kind-specific DACL before deleting through that handle. The live-pin sharing rules
  and the substituted-directory regression match the ruling.
- **Pipe identification:**
  - **Bound:** the pending set is bounded at 64. At saturation, further identification is deferred, as
    ADR-0006 §13.21 allows.
  - **Cancellation:** identification tasks survive the cancellation of `accept()`.
  - **Impersonation:** the readiness `await` comes before impersonation, which is synchronous.
    `RevertToSelf` runs before that function returns, and its failure aborts.
  - **Byte order:** the pinned Mio buffers the completed read and delivers it first, so the client's
    bytes are neither consumed nor reordered.
  - **Rejections kept:** remote clients and an owner SID mismatch are still refused.
- **Paths:** converting separators introduces no collision between distinct ordinary Windows paths.
- **Unix:** there is no unintended Unix product regression.

## Commands (reviewer)
| Command | Exit |
|---|---|
| `cargo test --locked -p heimdall-ipc` | 0 |
| `cargo test --locked -p heimdall-localenv --lib` | 0 (76 passed) |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | 0 |
| `test_m02_evidence.py WindowsBundle` | 0 (11 passed) |
| The scratch R01 reproduction | 0 (the bypass reproduced) |
| Source compared with ce21a76f | identical |

Native Windows and WSL were not run.
