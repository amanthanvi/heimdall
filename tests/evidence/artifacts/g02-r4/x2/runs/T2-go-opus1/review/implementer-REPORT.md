# T2-go-opus1 (written by the orchestrator from the implementer's structured report; the Write tool refused out/REPORT.md)

Status: verified

I implemented `heimdall-proto profile lint --file <path> [--json]` in the Go prototype. All four build targets still compile, the unit tests pass, and the shared harness passes 139/139 on both darwin-arm64 and linux-arm64 (exit 0 each). out/diff.patch and out/artifacts.json are written. out/REPORT.md is not: the Write tool blocked it as a report file, so its content is below for you to write.

**Starting point:** commit 619ed20, the untouched workspace. Diff: /tmp/x2ws-102411dc/out/diff.patch (`git diff --cached 619ed20`, dist excluded), 8 files, +915/-2.

**What changed and why:**
- **`internal/lint/lint.go` (new):** `Lint(*profile.Profile) []Finding` is a pure function with no I/O.
  - The five rules are emitted in rule-number order, and one pass in file order gives the required order within each rule:
    - rule 1 by the group's first member;
    - rules 2 and 3 by destination;
    - rule 4 by destination, then by the first occurrence of the label string;
    - rule 5 by the first (i, j) of the set.
  - Lowercasing is ASCII-only (`asciiLower`), not `strings.ToLower`. Unicode case mapping would wrongly equate, for example, the Kelvin sign with 'k'. A mutation test confirms the unit tests catch that.
  - `destination_ids` keeps first-appearance order with no repeats. All slices are non-nil, so they encode as `[]`.
- **`cmd/heimdall-proto/main.go`:** dispatch, `cmdProfileLint` and usage text.
  - Input handling reuses `profile.Load` and the exact `profile show` error path, so exit status, state, code, `data.error.key_path` and stderr are the same (K2, K14, K15, K18).
  - The existing SIGPIPE handling already covers `profile`, so the K12 closed-stdout rule holds: the exit status is the same with and without `--json` (0, 3 or 2).
  - The JSON is `{"findings":[...]}` with `LINT_CLEAN` (exit 0) or `LINT_FINDINGS` (exit 3).
  - Plain mode prints rule, message and key paths only (no ids, no values) and exits the same way as `--json`.
- **`internal/result/result.go`:** adds the two new codes, `ExitFindings = 3`, and their exit mapping. `schemas/` is untouched.
- **New tests:**
  - `internal/lint/lint_test.go`: each rule with its near misses, ordering, and ASCII-only lowercasing.
  - `cmd/heimdall-proto/lint_test.go`:
    - exact expected JSON in both option orders and with `--file=`;
    - paths with spaces and non-ASCII characters;
    - the same result as `show` on every `invalid-*` fixture and on oversize, missing, directory and duplicate-id inputs;
    - usage errors, no profile value on stdout or stderr in either mode, no canary, no file writes.
  - `lint_fifo_test.go`: K14 FIFO case, with a 2 s bound.
  - Three lint cases added to `TestK12ClosedStdoutExitParity`.
- **`prototypes/go/REPORT.md`:** a short "X2 task T2" section.

**One deliberate difference from `show`:** `profile lint --file --json` treats `--file` as missing its value, so it gives a USAGE_ERROR JSON result and exit 2. The unchanged `profile show` takes '--json' as the path and prints no JSON, with the same exit 2 and code. `--file=--json` still names a file called '--json'. Details are under escalations.

**Verification (real exit codes):**
- `gofmt` clean; `go vet` exit 0 on darwin, and cross-vetted for windows/amd64 and linux/arm64 (exit 0).
- `go test -count=1 ./...` on darwin, final sources: exit 0.
- `build.sh`: exit 0, all four targets built (darwin-arm64, linux-x64, linux-arm64, windows-x64).
- darwin harness (`conformance.py`): exit 0, 139/139 pass, verdict pass.
- Linux harness (`linux/run.sh`, image heimdall-g02-harness:d0c8e448a3a7): exit 0, 139/139 pass, verdict pass.
- linux-arm64 test binaries run in that image: exit 0 for each.
- Smoke test of the linux artifact in the container: findings exit 3, FIFO and directory exit 2.

**Artifacts** (/tmp/x2ws-102411dc/out/artifacts.json):
- darwin-arm64: /tmp/x2ws-102411dc/heimdall/prototypes/go/dist/darwin-arm64/heimdall-proto, sha256 8743d6ed54aec4a53f8e3f0afbb529529c32d2df206c028c374ef919d1d32cdb
- linux-arm64: /tmp/x2ws-102411dc/heimdall/prototypes/go/dist/linux-arm64/heimdall-proto, sha256 4ec1cbbe2404839105f987977acb357cc15b35c1093e6c7315fa19055674edb5

Scratch logs and harness records are in /tmp/x2ws-102411dc/scratch/.

**Known gaps:**
- No independent review; the hidden acceptance tests were not run.
- Windows has not been run natively.
- The `--file --json` difference from `show` described above.

## Commands run
- `git init && git add -A && git commit -m 'starting point' (workspace)` exit 0: starting commit 619ed20
- `gofmt -l . ; go vet ./... (prototypes/go)` exit 0: no gofmt output; vet clean
- `GOOS=windows GOARCH=amd64 go vet ./... ; GOOS=linux GOARCH=arm64 go vet ./...` exit 0: both exit 0, including test files
- `go test -count=1 ./... (darwin-arm64, final sources)` exit 0: all packages ok: cmd/heimdall-proto, agent, lint, profile, run, tui
- `sh prototypes/go/build.sh` exit 0: darwin-arm64, linux-x64, linux-arm64, windows-x64 all built:true; darwin ad-hoc signed with hardened runtime
- `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/go/dist/darwin-arm64/heimdall-proto --candidate go --out ../scratch/harness-darwin.json --artifacts-dir ../scratch/harness-darwin` exit 0: total 139, pass 139, fail 0, error 0, skipped 0; status=verified verdict=pass
- `sh tests/g02/linux/run.sh --artifact-dir prototypes/go/dist/linux-arm64 --candidate go --out ../scratch/harness-linux.json` exit 0: total 139, pass 139, fail 0, error 0, skipped 0; status=verified verdict=pass; image heimdall-g02-harness:d0c8e448a3a7
- `GOOS=linux GOARCH=arm64 go test -c (cmd/heimdall-proto, internal/lint, internal/profile); run in harness image with --network none, uid 10001, cap-drop ALL` exit 0: lint.test 0, profile.test 0, heimdall-proto.test 0. All Lint* tests and TestK12ClosedStdoutExitParity PASS on linux-arm64. The stack trace in the log comes from the existing intentional K10 panic test.
- `docker smoke: linux-arm64 artifact profile lint on a non-ASCII path (--json and plain), FIFO, directory` exit 0: findings JSON exit 3, plain exit 3, FIFO USAGE_ERROR exit 2, directory USAGE_ERROR exit 2
- `mutation check: replace asciiLower with strings.ToLower for hosts, then go test ./internal/lint` exit 1: TestDuplicateEndpointASCIIOnlyLowercase FAILs as intended; original restored and the package passes again (exit 0)
- `git diff --cached 619ed20 (dist excluded) > out/diff.patch` exit 0: 8 files, +915/-2, no dist/ paths

## Limitations
- No independent review was done. All verification is self-written tests plus the shared harness. The hidden black-box acceptance tests were not available or run.
- Windows: lint compiles (windows-x64 built, cross go vet passed) but has not run natively. The FIFO test is !windows. Windows non-regular-file handling is the existing, unchanged profile.Load path.
- The harness run created tests/fixtures/fake-agent/__pycache__/ (Python bytecode from the fake agent) inside the workspace. I removed it; it is not in the diff.
- Plain-mode output (K12, unspecified) prints rule, message and key paths only. Destination ids are left out, which is stricter than the task requires.
- Both harness runs and the smoke tests used the artifacts listed in artifacts.json. After that build only _test.go files and prototypes/go/REPORT.md changed, so the tested binaries match the final non-test sources. The final unit-test run covers the final test files.
- The workspace index has the changes staged (git add, excluding dist) so the diff could be produced. Nothing was committed after the starting commit.

## Escalations
- out/REPORT.md was not written. The Write tool refused it with 'Subagents should return findings as text, not write report files', and I did not route around that guardrail through Bash. The report content is in this summary; the orchestrator can write out/REPORT.md from it if it needs the file.
- Design decision to review: in `profile lint`, `--file` followed directly by one of lint's own flags (for example `--file --json`) counts as a missing value. Lint answers with a USAGE_ERROR JSON result (when --json is present) and exit 2. The unchanged `profile show` takes '--json' as the path there and reports USAGE_ERROR, exit 2, with no JSON. The exit status and code are the same; only the presence of the JSON document differs. `--file=--json` still names a file literally called '--json'.
