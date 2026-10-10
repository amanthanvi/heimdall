# T2-go-sonnet1: `heimdall-proto profile lint`

## Changes
- internal/profile/lint.go (new): pure `Lint(*Profile) []Finding` implementing rules 1-5 with the exact messages,
  key paths, destination_ids (first-appearance order, no repeats) and the specified ordering. ASCII-only lowercasing
  (`asciiLower`), not Unicode folding. Result is never nil, so `findings` serialises as `[]`.
- internal/result/result.go: codes LINT_CLEAN (exit 0) and LINT_FINDINGS (exit 3); ExitCode mapping. Envelope unchanged.
- cmd/heimdall-proto/main.go: `profile lint` dispatch; the flag/usage/Load handling of `profile show` was extracted into
  `loadProfileArgs` and is shared by show and lint, so the failure modes (status, state, code, key_path, stderr text, K14,
  K18) are identical by construction. `profile show` output unchanged. Usage text and the `profile` subcommand error message
  now mention lint. Without --json lint prints only `rule: key paths` lines (no profile values, no ids).
- Tests: internal/profile/lint_test.go (rule table with near misses, ordering, JSON shape, asciiLower) and
  cmd/heimdall-proto/lint_test.go (CLI findings/clean, both option orders and `--file=`, value non-echo incl. stderr and
  non-JSON, show/lint equivalence on invalid/oversize/missing/directory/usage inputs, no files written).

## Results (observed)
- `go vet ./...` exit 0; `go test ./...` exit 0 (all packages ok).
- `sh build.sh` exit 0: darwin-arm64, linux-x64, linux-arm64, windows-x64 all built.
- darwin harness: conformance.py exit 0, 139/139 pass (scratch/harness-darwin.json).
- linux harness: tests/g02/linux/run.sh exit 0 (background task), 139/139 pass (scratch/harness-linux.json).
- Manual: FIFO as --file answered USAGE_ERROR exit 2 in ~5 ms.

## Known gaps
- The black-box lint acceptance tests were not available; coverage is from my own tests against the TASK.md table.
- Non-JSON output format is unspecified; chosen minimally.
- Windows target compiled only. The dist/ build output is excluded from diff.patch.
