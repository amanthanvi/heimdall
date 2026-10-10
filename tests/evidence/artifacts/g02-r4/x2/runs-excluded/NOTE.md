# X2 cells excluded from scoring

**Status:** excluded. **Recorded:** 2026-10-09 by the orchestrator.

## T1-go-opus1-continuation, T1-rust-opus1-continuation

These two directories hold the results of the T1 opus1 cells from the third
attempt (`heimdall-m00-g02-round4-x2c`). They are kept as evidence but do not
count in the X2 scores.

**Why they are excluded.** Neither cell started from a fresh workspace. In the
second attempt (`heimdall-m00-g02-round4-x2b`), the first implementer of each
cell made 47 tool calls (Go) and 31 tool calls (Rust) before the API rate
limit (HTTP 429) killed it. Both left uncommitted changes in the workspace and
files in `../scratch`. The orchestrator handed the same workspaces to the third
attempt without resetting them. This was an orchestration error.

The transcripts of the third-attempt implementers show what they inherited:

- Go: the git history held only the earlier `start` commit. The tree had
  modified `run_unix.go` and `REPORT.md`, plus new process-state and
  job-control test files. The implementer moved the earlier scratch into
  `scratch/prior-attempt-20261006/` and read from it.
- Rust: the tree had modified `runner.rs`, `tests/cli.rs` and
  `tests/pty_tui.py`. The implementer saved them as
  `scratch/prior-uncommitted.patch` (936 lines).

As a result, the diffs, hidden-test results, tokens and tool calls of these
cells measure two implementers' work, not one. That breaks the X2 fairness rule
that every cell starts from identical inputs.

**Remedy.** Both cells were rerun in fresh workspaces built by
`make-workspace.sh`, whose tree digests match `BASE.json`. The rerun used the
same prompts in a separate workflow (`heimdall-m00-g02-round4-x2d`). Its
results are in `../runs/T1-go-opus1/` and `../runs/T1-rust-opus1/`.

**Checked.** Every other implementer that the second attempt started either
finished in its own fresh workspace (the T2, T3 and T4 opus1 cells) or failed on
its first request without making a tool call. Those failed starts left the
workspace unchanged.
