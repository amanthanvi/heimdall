# T2-rust-sonnet1: `heimdall-proto profile lint --file <path> [--json]`

## What changed (prototypes/rust only; docs/, schemas/, tests/g02/, fixtures untouched)
- `src/lint.rs` (new, in the library): the five rules, `lint(&Profile) -> Vec<Finding>` and `envelope(&[Finding])`.
  Grouping is hash based (linear time at the 1 MiB bound). Effective port is `Destination.port` (already 22 when omitted).
  Host folding is `str::to_ascii_lowercase` (A-Z only; non-ASCII letters are not folded). `destination_ids` is built from the
  destination indexes of `key_paths`, deduplicated in first-appearance order. A finding carries only the rule id, key paths,
  ids and the exact message, never a host, account, label, name or meta value.
- `src/envelope.rs`: new `Code::LintClean` (`LINT_CLEAN`, exit 0) and `Code::LintFindings` (`LINT_FINDINGS`, exit 3). Envelope shape unchanged.
- `src/cli.rs`: `profile lint` parsed with the same `parse_opts` as `profile show` (either option order, same usage-error and
  `--json`-only JSON USAGE_ERROR behaviour, exit 2); usage text updated.
- `src/main.rs`: `Cmd::ProfileLint` uses `profile::load_file`, so every input failure (SCHEMA_INVALID, INPUT_TOO_LARGE, USAGE_ERROR for
  missing/dir/FIFO/socket/device, K2, K14, K15, K18) is the same code path as `profile show`. Same signal-mask restore as `show`.
  Output goes through the existing `emit`/`plain` helpers, so a closed stdout gives the same wait status with and without `--json` (K12).
  Without `--json` it prints `<rule-id>: <key paths>` lines (no values, no ids); stderr is empty on success.
- Tests: 9 unit tests in `lint.rs`; envelope and `cli.rs` parse/usage unit tests extended; 9 new black-box tests in `tests/cli.rs`
  (exact JSON and order for all rules and near misses, clean/empty, shared fixtures, option orders and plain-mode exit parity,
  value non-echo on stdout and stderr in both modes, equivalence with `show` over FIFO/dir/socket/device/missing/oversize/exactly-1-MiB/
  control char/duplicate id/fixtures, usage errors, no files written, closed-stdout parity, large input).

## Results (real exit codes)
| command | exit | observed |
|---|---|---|
| `cargo fmt` / `cargo clippy --locked --all-targets -- -D warnings` (host) | 0 / 0 | clean |
| `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | clean (windows build compiles) |
| `cargo test --locked` (HEIMDALL_G02_FIXTURES set) | 0 | lib 59 passed, bin 4 passed, tests/cli.rs 38 passed |
| `HEIMDALL_PROTO_BIN=<darwin dist artifact> cargo test --locked --test cli` | 0 | 38 passed |
| `sh prototypes/rust/build.sh` | 0 | darwin-arm64, linux-x64, linux-arm64, windows-x64 all built:true |
| conformance.py on darwin-arm64 artifact | 0 | 139 total, 139 pass, status=verified |
| `sh tests/g02/linux/run.sh --artifact-dir .../dist/linux-arm64 --candidate rust` | 0 | 139 total, 139 pass, status=verified |
| manual `profile lint --json` on darwin and linux-arm64 (docker) artifacts | 3 / 3 | identical LINT_FINDINGS output |

Harness records: `/tmp/x2ws-3aee40ae/scratch/harness-darwin.json`, `.../harness-linux.json` (logs `*.log` next to them).
Artifact sha256: see `artifacts.json` (darwin-arm64 3ae21efe..., linux-arm64 27d94070...).

## Known gaps and notes
- `build.sh` prints "notices generation failed": `tools/gen_notices.py` runs `cargo metadata --locked --offline`, which needs every
  platform's crates in the offline cache (`redox_syscall` is missing in this workspace). No dependency changed (Cargo.toml/Cargo.lock
  untouched); `dist/THIRD-PARTY-NOTICES.txt` is therefore not produced and the build exit status stays 0. Environmental, not caused by this change.
- The harness does not exercise `profile lint`; lint behaviour is covered by the prototype's own tests and manual runs only. The hidden
  black-box tests were not seen.
- Native Windows/WSL behaviour of `lint` is not run (compile and clippy only); the code path is shared with `profile show`.
- Interpretation: rule 4 and rule 5 can both fire on the same labels (e.g. `["Foo","Foo","foo"]` gives a rule 4 finding for `Foo`
  and a rule 5 finding for the whole set); rule 4 never fires for strings that differ only in case.
