# T2-rust-opus1 (written by the orchestrator from the implementer's structured report; the Write tool refused out/REPORT.md)

Status: verified

`heimdall-proto profile lint --file <path> [--json]` is implemented in the Rust prototype. The unit tests, the darwin-arm64 build tests and the full G02 harness 2.4.2 all pass: 139/139 on darwin-arm64 and 139/139 on linux-arm64, both exit 0. All four `build.sh` targets still build. One required output is missing: the runtime blocked me from writing `/tmp/x2ws-2dd1a4d7/out/REPORT.md`, so its full text is below for the orchestrator to write. `diff.patch` and `artifacts.json` are in `/tmp/x2ws-2dd1a4d7/out/`.

=== REPORT.md content (for /tmp/x2ws-2dd1a4d7/out/REPORT.md) ===
# T2-rust-opus1: heimdall-proto profile lint (Rust + Ratatui prototype)

Starting commit: `beab84c` (git init of the workspace). `diff.patch` is `git diff beab84c`, excluding `prototypes/rust/target`, `prototypes/rust/dist` and `__pycache__`. 7 files, +1031/-3.

## What changed and why
- **src/lint.rs (new):** a pure function over the already-validated Profile, plus the result envelope.
  - Five rules, in TASK.md order.
  - Findings are grouped in the order they first appear, so they and their key_paths come out in the required order without sorting. Run time is linear in destinations plus labels.
  - Case folding is `str::to_ascii_lowercase` (A-Z only).
  - The effective port is the loader's `port`, which already defaults to 22.
  - destination_ids come from key_paths: first appearance, no repeats.
  - 10 unit tests.
- **src/envelope.rs:** new codes LINT_CLEAN (exit 0) and LINT_FINDINGS (exit 3). The envelope shape is unchanged, and `schemas/` was not edited.
- **src/cli.rs:** `Cmd::ProfileLint` is parsed with the same `parse_opts(["--file"], json)` as `profile show`, so options can come in either order. A missing `--file`, a flag without a value, or an unknown, repeated or stray argument gives USAGE_ERROR, exit 2, with JSON on stdout only with `--json`. The usage text gains the lint line. Parser unit tests added.
- **src/main.rs:** input goes through `profile::load_file`, the same loader as `show`, with an identical error branch.
  - Exit status, state, code, data (including error.key_path), warnings and stderr match `show` for every failing input: SCHEMA_INVALID, INPUT_TOO_LARGE, and USAGE_ERROR for a missing file, directory, FIFO, socket or device (also K2, K14, K15, K18).
  - On success, `--json` prints the envelope. Plain mode prints the code, the count, and the rule id, key paths and message of each finding; no profile values and no ids.
  - Output goes through the existing EPIPE-tolerant `emit`/`plain`, so K12 closed-stdout parity holds.
  - Nothing is written to disk.
- **src/lib.rs:** registers the `lint` module.
- **tests/cli.rs (black-box):**
  - Exact expected `data` covering all 5 rules and their near misses, in both option orders, on a path with spaces and non-ASCII characters.
  - Same exit status without `--json`; no profile value on stdout or stderr; no file written (directory tree and profile bytes unchanged).
  - `homelab` and the spaced fixture give LINT_CLEAN. `large-100` gives 33 root-account findings, a count I checked independently with grep.
  - Lint and show give identical results, within 2 s, on all 6 invalid fixtures, a missing file, an oversize file, a control character in a value, a duplicate id, a FIFO, a socket, a directory and /dev/null. The plain run also exits 2 with empty stdout.
  - Usage-error tests, and 3 lint cases added to `k12_closed_stdout_exit_parity`.
- **prototypes/rust/REPORT.md:** new §17 describing the subcommand.

## Verification (real exit codes)

| Step | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | |
| `cargo clippy -D warnings` (host and x86_64-pc-windows-gnu) | 0 | |
| `cargo test --locked` (darwin) | 0 | lib 59, bin 5, cli 32 |
| `build.sh` | 0 | all 4 targets built |
| CLI tests against the darwin dist binary (`env -i`) | 0 | 32 passed |
| Linux arm64 native tests (container, `--network none`) | 0 | lib 59, bin 5, cli 32 passed, 1 pre-existing opt-in test ignored |
| `conformance.py`, darwin-arm64 | 0 | 139/139, verified/pass |
| `linux/run.sh`, linux-arm64 | 0 | 139/139, verified/pass |

Artifacts (both unchanged after the harness runs; they match `dist/manifest.json`):
- darwin-arm64: `/tmp/x2ws-2dd1a4d7/heimdall/prototypes/rust/dist/darwin-arm64/heimdall-proto`, sha256 e73c91bdd257d2df3d1019889a690f47db2f08b4e2c78a6a151f98510622cb62
- linux-arm64: `/tmp/x2ws-2dd1a4d7/heimdall/prototypes/rust/dist/linux-arm64/heimdall-proto`, sha256 ba9b4e65ff7821f5e60b1e15226f01571e60f80c028b87c02d4cd7f24ff23b40

No source under `src/` changed after `build.sh`. Harness records and logs are in `/tmp/x2ws-2dd1a4d7/scratch/`.

## Known gaps
- No independent review was available; the checks are my own tests plus the harness.
- Labels `["A","A","a"]` fire both rule 4 and rule 5. This is how I read TASK.md, which only excludes case-variant pairs from rule 4.
- Plain output leaves out destination_ids.
- The Linux native-test step used the local `debian:bookworm-slim` image instead of the pinned digest, which is not present locally. I did not pull it.
- windows-x64 and linux-x64 were built but not run.
- Untracked `__pycache__` directories are left in the workspace; they are excluded from the diff.
=== end REPORT.md ===

## Commands run
- `git init && git add -A && git commit (starting point beab84c)` exit 0: baseline commit beab84c created
- `cargo fmt --check` exit 0: clean
- `cargo clippy --locked --all-targets -- -D warnings` exit 0: no warnings (host)
- `cargo clippy --locked --all-targets --target x86_64-pc-windows-gnu -- -D warnings` exit 0: Windows target still compiles, no warnings
- `cargo test --locked` exit 0: lib 59 passed (10 new lint), bin 5 passed, cli 32 passed (4 new lint tests), windows.rs 0 on Unix
- `sh prototypes/rust/build.sh` exit 0: darwin-arm64, linux-x64, linux-arm64, windows-x64 all built; manifest written
- `env -i ... HEIMDALL_PROTO_BIN=dist/darwin-arm64/heimdall-proto <cli test bin> --test-threads=4` exit 0: 32 passed against the darwin dist artifact
- `HP_LINUX_TEST_IMAGE=debian:bookworm-slim sh tools/linux_tests.sh arm64 aarch64-unknown-linux-musl linux-arm64` exit 0: aarch64 container: lib 59, bin 5, cli 32 passed, 1 ignored (pre-existing opt-in linux_nproc)
- `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/rust/dist/darwin-arm64/heimdall-proto --candidate rust --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` exit 0: harness 2.4.2: total 139, pass 139, fail 0, error 0, skipped 0; status=verified verdict=pass
- `sh tests/g02/linux/run.sh --artifact-dir prototypes/rust/dist/linux-arm64 --candidate rust --out scratch/harness-linux.json` exit 0: harness 2.4.2 linux-arm64: total 139, pass 139, fail 0, error 0, skipped 0; status=verified verdict=pass
- `cargo test --locked --test cli k12 -- --nocapture (after adding lint-findings case)` exit 0: closed-stdout parity: lint clean 0/0, findings 3/3, schema-invalid 2/2 plain vs json
- `shasum -a 256 dist/darwin-arm64/heimdall-proto dist/linux-arm64/heimdall-proto` exit 0: e73c91bd...cb62 and ba9b4e65...3b40, matching manifest written before the harness runs
- `git diff beab84c -- . ':(exclude)prototypes/rust/target' ':(exclude)prototypes/rust/dist' ':(exclude)**/__pycache__/**' > out/diff.patch` exit 0: 7 files, +1031/-3; no HEIMDALL_CANARY_ string in patch

## Limitations
- No independent adversarial review: no reviewer was available in this run, so all verification is my own tests plus the shared harness.
- The Linux native unit and integration tests used the local debian:bookworm-slim arm64 image (digest 7c7b2c96...) instead of the digest pinned in tools/linux_tests.sh, which is not present locally. I did not pull it, to avoid network access. The Linux harness run used its own digest-pinned image.
- windows-x64 and linux-x64 were built but not run. No Windows host was available, and no x64 test run was done in this task.
- A spec reading I chose: in a destination with labels ["A","A","a"], both rule 4 (j=0,1) and rule 5 (j=0,1,2) fire. TASK.md only excludes case-variant pairs from rule 4.
- Plain output (not judged, K12) prints the code, the finding count, and the rule id, key paths and message of each finding. It prints no destination ids and no profile values.
- Harness and tool runs left untracked __pycache__ directories in the workspace. They are excluded from diff.patch.
- I appended §17 to prototypes/rust/REPORT.md, the prototype's own design document, with a shell heredoc. This is part of the code change, not the out/ report.

## Escalations
- I could not write /tmp/x2ws-2dd1a4d7/out/REPORT.md. The subagent runtime blocked the Write tool for it ('Subagents should return findings as text, not write report files'), and I did not get around the block with shell. The full REPORT.md content is in this summary, ready for the orchestrator to write to out/REPORT.md, the same way it did for the earlier prototype REPORT.md. diff.patch and artifacts.json were written.
