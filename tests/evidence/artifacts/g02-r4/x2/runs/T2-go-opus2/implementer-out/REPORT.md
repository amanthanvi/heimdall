# T2-go-opus2: `heimdall-proto profile lint` (Go prototype)

Starting point: `git init` + commit `440085b` of the workspace as given. Diff: `diff.patch`
(`git diff 440085b`, excluding `prototypes/go/dist/`).

## What changed and why

- `prototypes/go/internal/lint/lint.go` (new): pure `Lint(*profile.Profile) []Finding`, no I/O. The five
  rules in rule-number order with the task's within-rule orders. Rule 1 groups by (ASCII-lowercased host,
  effective port) in first-member order; rule 4 groups exact label strings per destination in
  first-occurrence order; rule 5 groups by ASCII-lowercased label across the profile and fires only when the
  group has 2+ distinct spellings, listing every occurrence in (i, j) order. ASCII-lowercase is byte-wise
  A-Z only (`strings.ToLower` would fold non-ASCII letters). `destination_ids` are first-appearance, no
  repeats. Arrays are never nil, so a clean result encodes `"findings":[]`.
- `prototypes/go/internal/result/result.go`: codes `LINT_CLEAN` (exit 0) and `LINT_FINDINGS` (exit 3,
  `ExitFindings`). Envelope unchanged; `schemas/` untouched.
- `prototypes/go/cmd/heimdall-proto/main.go`: `profile lint` dispatch and `cmdProfileLint`. The flag
  parsing and `profile.Load` call of `profile show` were moved unchanged into `loadProfileArgs`, now the
  single input path for both subcommands, so every failure (usage, K14 non-regular, INPUT_TOO_LARGE, K2,
  K15, SCHEMA_INVALID; exit, state, code, key_path, message, stderr text) is identical to show. Usage text
  lists lint. Plain output prints only rule id, fixed message and key paths (no ids, no values); exit
  status equals the `--json` one. lint is covered by the existing SIGPIPE-to-EPIPE setup (K12 closed stdout).
- Tests (Go `testing`): `internal/lint/lint_test.go` (each rule, near misses: omitted port vs 22, port
  1024, `Root`/`ROOT`, non-ASCII case not folded, identical labels across destinations, case variants in
  one destination are rule 5 not rule 4, orders, four-member JSON shape); `cmd/heimdall-proto/lint_test.go`
  (exact JSON in both option orders and `--file=`, LINT_CLEAN on homelab and the spaced non-ASCII path,
  large-100 = 33 root-account findings, value non-echo with and without `--json`, byte-identical
  show/lint results on 6 invalid fixtures + oversize + control-char + missing + directory in both modes,
  usage errors in both modes, no file written: real process with empty cwd/HOME/TMPDIR);
  `lint_fifo_test.go` (K14 FIFO, < 2 s, same as show); 3 lint cases added to the K12 closed-stdout test.
- `prototypes/go/REPORT.md`: section "X2 task T2".

## Results (real exit codes)

| Command | Exit | Observed |
|---|---|---|
| `go test ./...` baseline before changes | 0 | all packages ok |
| `go vet ./...` (darwin) and `GOOS=windows GOARCH=amd64 go vet ./...` | 0 | |
| `go test -count=1 ./...` after changes | 0 | cmd, agent, lint, profile, run, tui ok |
| `sh prototypes/go/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all `built:true` |
| `conformance.py --bin dist/darwin-arm64/heimdall-proto --candidate go` | 0 | 139/139 pass, verdict pass (`../scratch/harness-darwin.json`) |
| `tests/g02/linux/run.sh --artifact-dir dist/linux-arm64 --candidate go` | 0 | 139/139 pass, verdict pass, image heimdall-g02-harness:d0c8e448a3a7 (`../scratch/harness-linux.json`) |
| linux-arm64 artifact lint smoke in that image (`--network none`) | 3 / 0 / 0 / 2 | findings profile, spaced non-ASCII fixture --json, homelab plain, FIFO USAGE_ERROR |

During development one of my own tests first failed (assumed `large-100.toml` was clean; it has
`account = "root"` on every third destination) and was corrected to assert the 33 findings.

## Known gaps

- `profile lint --file --json` is parsed by Go's `flag` as the path `--json`: a missing-file USAGE_ERROR on
  stderr only, exit 2, no JSON. This is exactly what `profile show` does today; I kept show-equivalence
  rather than a lint-only special case or a change to show. (The harness reference implementation would
  emit JSON here, because it decides JSON mode by `"--json" in args`.)
- Non-ASCII spaced paths and FIFO were exercised on darwin and in the Linux container; Windows lint is
  compile-checked only (vet + build), not run.
- Running the darwin harness created `tests/fixtures/fake-agent/__pycache__/`; I deleted it, it is not
  in the diff.
