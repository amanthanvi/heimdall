# T2-rust-opus2: `heimdall-proto profile lint` (Rust prototype)

The workspace was `git init`ed and committed as the starting point (commit `1c68d78`, "starting point").
`diff.patch` is `git diff` from that commit. It excludes `prototypes/rust/dist/` and `prototypes/rust/target/`.
Only `prototypes/rust/` changed. `docs/`, `schemas/`, `tests/g02/` and the fixtures were not edited. The
`__pycache__` directories that running the tools and the harness created were removed.

## What changed and why

| File | Change |
|---|---|
| `src/lint.rs` (new) | The five rules, the finding model, the `--json` line writer, plain-text lines and 15 unit tests |
| `src/envelope.rs` | New codes `LINT_CLEAN` (exit 0) and `LINT_FINDINGS` (exit 3) |
| `src/cli.rs` | `Cmd::ProfileLint`, parsed by the same `parse_opts` as `profile show` (`--file` and `--json` in any order); usage line; parser tests |
| `src/main.rs` | Dispatch. On load failure, the exact `profile show` error path (same stderr line, same envelope, same exit). On success, findings JSON or plain lines |
| `src/lib.rs` | `pub mod lint` |
| `tests/cli.rs` | 8 black-box tests of the built binary |
| `REPORT.md` | New §17 with the design, tests, results and gaps |

Main decisions:

1. **Input handling is literally `profile show`'s.** It uses the same `profile::load_file` and the same error
   branch, so lint fails exactly like show:
   - SCHEMA_INVALID, INPUT_TOO_LARGE, and USAGE_ERROR for a missing file or a directory;
   - K2 (control characters);
   - K14 (FIFO, socket or device: non-blocking open, regular-file check, answers at once);
   - K15 (size bound before parsing);
   - K18 (no values in errors).

   A test checks byte-identical stdout, stderr and exit status against `profile show` on 11 inputs, with
   `--json` first, last and absent.
2. **Rules** are single-pass hash-map groupings. Rule ids, messages, key-path form and every ordering follow
   TASK.md. The details:
   - Host and label folding is `to_ascii_lowercase`, which maps only A–Z.
   - The effective port is the loader's port, which defaults to 22.
   - `root` is compared exactly.
   - Rule 4 uses exact strings within one destination.
   - Rule 5 is a profile-wide ASCII-fold group with at least two distinct spellings, ordered by first `(i, j)`.
   - `destination_ids` are taken from the places, in first-appearance order, without repeats.
3. **Memory.** The first version built a `serde_json::Value` tree. On a 1 MiB profile with 262k labels it
   measured 187 MiB peak RSS on darwin, against 95 MiB for `profile show` on the same file. The JSON line is
   now written directly into one buffer, with serde_json escaping the ids. That measures 116 MiB on darwin, and
   54 MiB on linux-arm64 against 68 MiB for show. Both runs took about 0.1 s. A unit test proves the writer is
   byte-identical to `Envelope::success(code, data).to_line()`. The old and new binaries also gave
   byte-identical output on the worst-case files and on `large-100.toml`.
4. **Value non-echo.** `--json` output carries key paths, fixed messages and destination ids only. Output
   without `--json` prints `rule: message (key paths)` plus a count, and no ids. Stdout write errors are
   ignored, as `emit` does, so the K12 closed-stdout wait status is the same with and without `--json`.
5. **No disk writes.** The profile is opened read-only, and nothing else is opened.

## Tests and harness (real exit codes)

| Step | Exit | Result |
|---|---|---|
| `cargo fmt --check` | 0 | |
| `cargo clippy --locked --all-targets -- -D warnings` (host) | 0 | |
| `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings` | 0 | |
| `cargo test --locked -- --test-threads=4` (darwin-arm64) | 0 | lib 64, bin 4, cli 36 passed (15 + 8 new lint tests, plus parser cases) |
| `sh prototypes/rust/build.sh` | 0 | all four targets built: darwin-arm64, linux-x64, linux-arm64, windows-x64 |
| cli tests against `dist/darwin-arm64/heimdall-proto` (`env -i`, no toolchain on PATH) | 0 | 36 passed |
| `cargo-zigbuild test --no-run --target aarch64-unknown-linux-musl` | 0 | |
| `tools/linux_tests.sh arm64 …` (pinned Debian container, `--network none`, `dist/linux-arm64`) | 0 | lib 64, bin 4, cli 36 passed, 1 ignored (`linux_nproc`, by design) |
| Differential run against an independent Python reference of TASK.md (`scratch/ref_lint.py`), 3,000 random profiles, darwin artifact | 0 | 0 mismatches |
| Same, linux-arm64 artifact in the harness image (`--network none`, uid 10001) | 0 | 0 mismatches |
| `tests/g02/.venv/bin/python tests/g02/conformance.py --bin prototypes/rust/dist/darwin-arm64/heimdall-proto --candidate rust --out scratch/harness-darwin.json --artifacts-dir scratch/harness-darwin` | **0** | **139/139 pass**, status `verified`, verdict `pass` |
| `sh tests/g02/linux/run.sh --artifact-dir prototypes/rust/dist/linux-arm64 --candidate rust --out scratch/harness-linux.json --artifacts-out scratch/harness-linux` | **0** | **139/139 pass**, status `verified`, verdict `pass` |

The harness records name the final artifacts: darwin `e21a23ef…` and linux-arm64 `7a45aef6…`. See
`artifacts.json`.

An earlier darwin harness run against an intermediate build, before the memory change, also passed 139/139
with exit 0. It is kept under `scratch/prelim/` and is not the verdict.

## Known gaps

- **No independent review.** No independent reviewer was available. The Python reference was written by the
  same agent from TASK.md, so it is a second implementation, not an independent reading.
- **Plain output.** TASK.md does not settle whether `destination_ids` may appear in plain (non-`--json`)
  output. They are omitted there.
- **Schema.** `LINT_CLEAN` and `LINT_FINDINGS` are not in `schemas/g02/result.schema.json`, by instruction. A
  strict schema validation of a lint result fails on `code`.
- **Windows.** The Windows input path is shared with `profile show` (GetFileType, §9.6). It is compile-checked
  only: clippy for windows-gnu and the windows-x64 build. No native Windows run was made.
- **linux-x64.** The linux-x64 artifact was rebuilt but not run through the harness. Only darwin-arm64 and
  linux-arm64 were required.
