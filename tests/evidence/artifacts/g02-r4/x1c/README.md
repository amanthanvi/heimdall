# G02 round 4, X1c: native linux-x64 runs of the post-fix (X1b) artifacts

**Task:** `M00-T05-r5-x1c-linux-x64`, run on 2026-10-31 (UTC).

**Why.** The ADR-0002 review found that the post-fix builds from the round-4 Windows fix round (X1b; Go `84c7665`,
Rust `001a791`) ran natively on Windows x64 and were re-checked on darwin-arm64 and linux-arm64, but never ran on
native linux-x64. Round 4's X1 ran only the round-3 artifacts (Go `38b6b72`, Rust `d8f0cbe`) on linux-x64. X1c
closes that gap with X1's method.

| | go | rust |
|---|---|---|
| Record | `tests/evidence/g02-go-conformance-linux-x64-x1b.json` | `tests/evidence/g02-rust-conformance-linux-x64-x1b.json` |
| Harness 2.4.2 exit / status / verdict | 0 / `verified` / **pass** | 0 / `verified` / **pass** |
| pass / fail / error / skipped of 139 | 139 / 0 / 0 / 0 | 139 / 0 / 0 / 0 |
| Duration (harness) | 181.3 s | 182.3 s |
| No toolchain on PATH (`notoolchain.txt`) | every command ran; same results as X1 | same |
| Per-check outcomes vs every earlier harness result (below) | identical | identical |

## Inputs and digests

| Input | sha256 | Provenance |
|---|---|---|
| `prototypes/go/dist/linux-x64/heimdall-proto` (5,451,936 bytes) | `bfb668bb0f7045e3f50606ccd2acff444ed5c4e733400b997624519e0fc23c3b` | equals `prototypes/go/dist/manifest.json` and the independent reviewer's rebuild, `../x1b/review-go/build/rebuilt-manifest.json` (the reviewer's diff of the two manifests: identical). The fix round itself recorded no linux-x64 digest. |
| `prototypes/rust/dist/linux-x64/heimdall-proto` (887,072 bytes) | `7b1b3fcfc64031fe76625164c06c7181d800f3af1cf51cd0425688f95531769d` | equals `prototypes/rust/dist/manifest.json`, the fix round's `../x1b/rust/build/manifest.after.json`, and the reviewer's rebuild `../x1b/review-rust/build/manifest.review-rebuild.json` (byte-for-byte `cmp` per `../x1b/review-rust/commands.txt`) |
| `harness.tar`: `git archive` of `cfd97d23` (HEAD), `tests/g02` without `selftest-results`, `tests/fixtures/g02`, `tests/fixtures/fake-agent`, `schemas/g02`, `tests/evidence/record.schema.json` | `eabd1340…7dd7` (`inputs.sha256`) | `git diff 772a6b1 HEAD` over these paths is empty, so the harness files are the ones X1 ran. The tar digest differs from X1's because the archive header carries the commit. |

**These are the reviewed post-fix bytes.** Both fix rounds built from their working tree on `e0ead9b` and committed
the fix as `84c7665` / `001a791`. No commit after them touches `prototypes/go` or `prototypes/rust`. X1c did not
rebuild anything, so it did not check that the committed trees reproduce these bytes. The reviewers' rebuilds
came from the working tree, too.

The host re-checked the hashes with `sha256sum -c` (`setup.txt`). Both binaries are statically linked, stripped
x86-64 ELF files ("not a dynamic executable").

## Method

This is X1's method (`../x1/RESULTS.md` §1), with the scripts copied and adapted:

- `setup.sh` unpacks the stage, checks the hashes, and creates the venv with
  `pip install --require-hashes -r tests/g02/requirements.txt` (pyte 0.8.2, wcwidth 0.9.1).
- `run-linux.sh` is `../x1/linux-x64/run-linux.sh` with these changes:
  - scratch path;
  - candidate commits;
  - `--build-commit cfd97d23`;
  - case ids and output names ending in `-x1b`;
  - runner path;
  - a WSL version field.

  It runs the full catalogue natively (no container), Go first and then Rust. It was started detached
  (`setsid nohup`) so that a dropped SSH connection could not kill it.
- `notoolchain.sh` matches X1's except for the scratch path.
- `redact.py` does the redaction. `make-records.py` maps evidence paths and appends the limitations.
  `compare.py` does the comparison. `commands.txt` lists every command with its exit code.

**Host.** The same owner PC as X1, reached only through the task's SSH config, as the non-root WSL user. Nothing
on the Windows side was touched.

| | X1 (2026-10-06) | X1c (2026-10-31) |
|---|---|---|
| Distro | Ubuntu 24.04.5 LTS | Ubuntu 24.04.5 LTS |
| Kernel | 6.18.40.1-microsoft-standard-WSL2 | **6.18.54.1**-microsoft-standard-WSL2 |
| WSL | not recorded | 3.0.3.0 |
| CPU / RAM | 6 | 6 / 16 GB |
| bash | 5.2.21 | 5.2.21 |
| zsh | not installed | not installed |
| OpenSSH (ssh-keygen used for fingerprints) | 9.6p1 Ubuntu-3ubuntu13.19 | 9.6p1 Ubuntu-3ubuntu13.**20** |
| Python | 3.12.3 | 3.12.3 |
| Load average 1/5/15, start → end | go 0.51/0.25/0.15 → 0.89/0.55/0.29 | go 0.08/0.02/0.00 → 0.17/0.05/0.01; rust → 0.24/0.08/0.02 |

The Windows build was not queried, because X1c did not touch Windows.

**Redaction.** The WSL scratch path became `<wslscratch>`. Every hit of the WSL user name was inside that path.
`redact.py` counted 660 hits before the copy and 0 after. These were all 0:

- the host name;
- `/mnt/c` and `Users/`;
- full canary values (`HEIMDALL_CANARY_` followed by a character);
- IPv4 addresses, apart from the kernel and WSL version strings.

The harness's own `canary.no_canary_anywhere` and `harness.canary_selfcheck` both pass: 665 artifact files, 0 hits.

## Results

Console logs: `console-go.log`, `console-rust.log`. Per-check artifacts: `arts-go/`, `arts-rust/`. Timing:
`run-linux.log`.

| | go | rust |
|---|---|---|
| Harness exit | 0 | 0 |
| Summary | 139 pass, 0 fail, 0 error, 0 skipped | same |
| K3a connection reset (before the reply / after one byte) | ECONNRESET / ECONNRESET | same |
| K10 exit form (SIGTERM, SIGHUP, hangup) | 143, 129, 129, 129 | same |
| K16 helper tripwire hits | none | none |
| First TUI frame (observation) | 35.7 ms (X1: 40.2) | 17.6 ms (X1: 20.2) |
| K17 filter p95 (bound 100 ms) | 17.4 ms (X1: 17.7) | 1.8 ms (X1: 2.7) |
| Agent SIGINT exit latency (3 samples) | 1.4, 1.0, 0.9 ms (X1: 1.2, 1.0, 1.3) | 5.8, 5.7, 5.7 ms (X1: 6.3, 6.4, 5.8) |
| Resize relayout, median / max | 15.45 / 17.0 ms | 0.8 / 1.1 ms |

Non-gating failed assertions:

- **Both candidates:** the zsh forms of K6e (`harness precondition: /bin/zsh is executable`), because zsh is not
  installed.
- **Go only:** `[bash SIGSTOP] the stop notice word and the shell's status of the stopped job equal the direct-exec
  control's`. The same assertion also fails, non-gating, in the round-3 linux-x64, linux-arm64 and darwin-arm64
  Go records. It is not new.

**No toolchain** (`notoolchain.txt`). Each artifact ran under `env -i`, with `PATH=/usr/bin:/bin` and with an empty
PATH directory:

| Command | Both PATH forms |
|---|---|
| `version --json` | 0 |
| `profile show` homelab / spaced | 0, `PROFILE_OK` |
| `profile show` forbidden-key | 2, `SCHEMA_INVALID`, 0 canary-prefix hits |
| `run -- /bin/sh -c 'exit 7'` | 7 |
| `agent list` on a missing socket | 5, `AGENT_UNAVAILABLE` |

`run -- true` gives 0 with `PATH=/usr/bin:/bin`. With the empty PATH directory it gives 127, with a different
message per candidate:

- Go: "command not found";
- Rust: "cannot launch command: NotFound".

That is the expected PATH behaviour. All of these match X1.

X1's caveat still applies: `/usr/bin` holds `go`, `gcc`, `cc`, `gofmt` and `node`. So only the empty-PATH run is
free of a toolchain.

## Comparison

All of this is in `compare.txt`. The sources compared were:

- **Round-3 records:** linux-x64 (X1), linux-arm64 and darwin-arm64 (full records).
- **X1b post-fix runs on darwin-arm64 and linux-arm64, fix round and review:**
  - Go: per-check summaries only, because the full Go records stayed outside the repository;
  - Rust: full records.

1. **Check outcomes.** All 139 check ids have the same outcome (`pass`) in all 8 sources, for both candidates.
2. **Assertions against round-3 linux-x64.** Every check has the same assertion count and the same set of failed
   (non-gating) assertions, for both candidates. Against the linux-arm64 records, only the K6e zsh assertions
   differ. Against darwin-arm64, these also differ: the Linux-only `/proc` assertions in `run.k6a_inherited_ignore`
   (58 against 45) and, for Go, darwin's extra non-gating bash SIGSTOP assertion. These are platform and shell
   differences that X1 already found.
3. **heimdall-proto invocations against round-3 linux-x64.** For both candidates, all 228 paired captures have the
   same exit code, timeout state and leftover-process state.

   Stdout digests differ in 18 Go and 17 Rust captures. The 17 that both candidates share have a cause outside the
   artifact:
   - agent listings and the plain `agent list` output carry fingerprints of keys the harness generates per run;
   - `run.argv_exact` and `run.cwd_env_inherited` contain the per-run `/tmp/hmg02-*` directory;
   - `run.k6a_inherited_ignore` prints `/proc/self/status`, which holds PIDs.

   The eighteenth Go capture is the only message difference. In `agent.timeout_whole_response`, the message in the
   JSON result and on stderr reads "read: no complete response within timeout" in X1c but "read failed" in X1.
   Exit 5 and `AGENT_UNAVAILABLE` are the same, and the check gates neither the wording nor the stderr.
   - `internal/agent` is unchanged between `38b6b72` and `84c7665`.
   - `probe.go` sets the connection deadline to the same instant as the context timeout. It reports "no complete
     response" only if `ctx.Err()` is already set when the read error is classified; otherwise it reports
     "`<op>` failed". The wording therefore depends on which deadline is seen first. This is an inference from the
     source.
   - The round-3 linux-arm64 and darwin-arm64 Go records show the same "no complete response" wording as X1c.
4. **Observations.** The only non-timing difference from round-3 linux-x64 is the harness's own OS probe,
   `harness_os_probe_back_to_back_signal_merge`. It measures the kernel's merging of two back-to-back signals that a
   harness wrapper sends, not heimdall-proto. The probe saw a duplicate in:

   | | X1 | X1c |
   |---|---|---|
   | go | 1/10 | 0/10 |
   | rust | 1/10 | 3/10 |

   Against linux-arm64 (round 3, and the X1b Rust record), the differences are this probe and the zsh K6e forms,
   which were not run here. These are the same two structural differences X1 found.

   Everything else differs only in timing. The timings are in the same range as X1 and the arm64 runs.

**What the fix changed on Linux.** The X1b diffs explain why nothing moved:

- **Go:** the only change reachable on Linux is a call to `refuseTarget`, which `run_unix.go` defines as a no-op.
- **Rust:** every source change is `cfg(windows)`.
- **Rust bytes:** `../x1b/rust/build/compare.txt` records that the linux-x64 binary differs from a same-day rebuild
  of the pre-fix HEAD by 2 bytes. The round-3 artifact (`961e3fb9…`, 876,464 bytes) differs more, because of the
  rebuild, not the fix. That cause is from the fix round's record and was not re-checked here.

## Limitations

- **Not a K13 verdict platform.** linux-x64 ran natively under WSL2, not in the pinned container (no
  `--network none`, cap drop or memory limit). The owner's other WSL processes were not controlled; the load was
  ≤ 0.24.
- **Changed host between X1 and X1c.** The WSL kernel moved from 6.18.40.1 to 6.18.54.1 and OpenSSH from 13.19 to
  13.20. So a difference between the X1 and X1c records could come from the host as well as from the artifact.
  None was found beyond those explained above.
- **zsh is not installed**, so the zsh K6e forms (non-gating) were not run, as in X1. bash 5.2.21 gated K6e.
- **Go post-fix arm64 comparison** covers check outcomes only. The X1b Go full records are not in the repository.
- **Artifact provenance.** The artifacts are the bytes the X1b fix round built and its reviewers reproduced. That a
  build of the committed `84c7665` / `001a791` trees gives the same bytes was not checked (no rebuild in this task).
- **One run per candidate.** Timing observations are single samples. Wall-clock bounds passed with wide margins.
- **No independent review of this run.**

## Cleanup

- The WSL scratch `~/hm-m00/M00-T05-r5-x1c` was removed. The parent `~/hm-m00` existed and was empty before the
  task, and it was left in place, empty.
- Before removal, no process had the task id in its command line, and no `heimdall-proto` process was running.
- The Mac staging directory under `/tmp` (raw outputs, identifier file) was removed after the evidence was written.
- Nothing was built, so there are no build outputs to prune.

## Reproduce

1. Stage `harness.tar` (the `git archive` above) and the two `dist/linux-x64` artifacts as `art/<c>/heimdall-proto`,
   with `inputs.sha256`.
2. Run `setup.sh`, then `run-linux.sh`, then `notoolchain.sh`, in `~/hm-m00/M00-T05-r5-x1c`.
3. Run `redact.py copy`, then `make-records.py`, then `compare.py`.
