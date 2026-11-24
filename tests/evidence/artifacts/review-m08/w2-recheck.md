# M08 W2 scoped re-check: `3943738d..605f7286` (`origin/m08/w2`)

Reviewer: the scoped re-check under ADR-0009 §2.1, after the W2 independent review
(`review.md`, MERGE WITH FIXES, M08-W2-R01 to R07) and the orchestrator's rulings
(`orchestrator-rulings.md`). Detached worktree at `605f7286`; no commit, push or branch, and no
edit outside this directory. In scope: `c6b2c68c` (R02), `2e1189b0` (R06, R07), `b8c21e53` (R01,
R04), `0fb0d417` (R03), `605f7286` (R05 records, the W2 review archived). Out of scope, as briefed:
the later evidence-and-docs commit (the rest of R05(f), the recomputed fuzz build-id note, the R03
scratch-volume setup test).

Nothing here ran on Windows, the devbox or in a container. No `heimdall` executable was run, no
release build was made (every `cargo build` in the release script went to a shim that refuses
it), and no ssh or scp was used. Logs and probes are under `logs/` and `probes/` beside this file.

## Verdict: MERGE WITH FIXES

**No finding blocks under ADR-0009 §2.1.** None has a lasting effect on remote trust, recovery
records or the owner's data, and none bypasses consent:

- RC01 leaves a mismatched `.previous` pair, the same effect as R01, which the hello refuses
  (ADR-0014 §3.5) and which was ruled non-blocking.
- RC02 and RC03 affect release and fuzz records.
- The rest are nits.

**Fix before the next fuzz setup: RC03.** As committed, every `run-campaign.sh setup` now exits 1
after building the targets, before the lock-file check, and never records a build identity. That
is fail-safe for the accounting, since runs read `unknown`, but the campaign cannot proceed. The
scratch-volume setup test still to come would hit it at once.

**Fix before the candidate (U3b):** RC01, which is small and has a ready regression in
`probes/probe-rc-marker.ps1`, case C. RC02 can be fixed then or recorded as a limit of the
release script.

| Finding | Status |
|---|---|
| R01 (`install.ps1` marker) | **partly closed**: the reviewer's case is closed; a marker can outlive its update (RC01) |
| R02 (iroh refusal) | **closed** for every feature route tried; one staging route outside the feature list (RC02, not introduced by W2.1) |
| R03 (fuzz build identity) | **partly closed**: the identity covers what the ruling lists, and a killed setup leaves no identity; but setup can no longer complete (RC03) |
| R04 (`install.sh` moved executable) | **closed** |
| R05 (records) | **closed for (b) to (e) and (g); (a) partly, with leftover phrases (RC05)**; (f) partly, as briefed |
| R06 (proxy upstream, container guard) | **closed** |
| R07 (key frame, idle scope) | **closed**, with one nit (RC04) |

## R01: `tools/packaging/install.ps1`, the update marker. Partly closed

**The reviewer's case is closed.** It was reproduced under pwsh 7.7.0 on macOS with fake archives
only (`probes/probe-rc-marker.ps1`; output `probes/probe-rc-marker.txt`; probe exit 0). This is
the logic only, not Windows file semantics.

- **Case A:** W2-R04's state is no `heimdall.exe`, `heimdall.previous.exe` = 1.0.0-nohelper, the
  2.0.0 helper at `linux-x86_64`, and no `.previous` helper.
  - `HM_INSTALL_TEST_STOP_AFTER=1` exits 1 and leaves `.heimdall.new.exe` and
    `.linux-x86_64.new`, with **no marker**.
  - The rerun exits 0 with no "finished an interrupted update". It leaves no
    `linux-x86_64.previous` and says "an older executable is kept as heimdall.previous.exe without
    its WSL helper; install.ps1 -Rollback will refuse it".
  - `-Rollback` then **exits 1**: "the previous pair is incomplete: missing
    linux-x86_64.previous". Nothing changes.
- **Case A2:** the same with `STOP_AFTER=2` gives the same result.

**The marker's life, one stop at a time.** Each case installs `a1`, updates with `a2` stopped
after the named step, reruns `a2`, then runs `-Rollback`. Cases B-1 to B-4b:

| Stop after | State left | The rerun | `-Rollback` | Marker at the end |
|---|---|---|---|---|
| 1, 2 | the old pair, staged copies, no marker | an ordinary update; .previous = 1.0.0 pair | exit 0, back to 1.0.0 | absent |
| 3a | no exe, old helper at current name, prev = 1.0.0, marker (a2's digest) | "finished an interrupted update"; .previous = 1.0.0 pair | exit 0 | absent |
| 3b | no exe, no current helper, 1.0.0 pair under .previous, marker | not finished (no current helper); an update with no current executable; .previous = 1.0.0 pair | exit 0 | absent |
| 4a | 2.0.0 exe, no current helper, 1.0.0 pair under .previous, marker | a repair of the helper; .previous untouched | exit 0 | absent |
| 4b | the complete new pair, 1.0.0 pair under .previous, **marker** | "this version is already installed", exit 0, **marker kept** | exit 0 | **present** |

Three more cases:

- **An injected failure at 3b (case F):** the undo puts back the 1.0.0 pair and the marker is
  removed.
- **A directory at the marker's name** is refused by `Assert-Names`, as the self-test shows.
- **A rerun by a different archive over a 3a stop (case D):** it finishes the move correctly. The
  marker's digest is never read. It is written (`WriteAllText($mark, "$wantExe")`), but the
  decision at `:397` reads only that the marker is a file. So "holds the staged executable's
  digest" is true but has no use.

**The marker can outlive its update and misfire later: see RC01.**

### Commands run

- **`pwsh -NoProfile -File tests/native/m08/lifecycle/install-selftest.ps1`:** exit 0,
  "install-selftest: PASS (77 checks)" (`logs/install-selftest-ps1.txt`). That is 71 + 6 `W2.1-R01:`
  cases, matching the README.
- **`pwsh -NoProfile -File tests/native/m08/lifecycle/install-revert-proofs.ps1`:** **stopped
  part-way, no exit code.** The harness's 30-minute background limit ended it during the W2-R04
  revert's self-test (`logs/install-revert-proofs.txt`). What it printed before that:
  - with every fix in place: exit 0, 0 failing;
  - W01-R01 reverted: exit 1, 12 failing. This now includes "W2.1-R01: a directory at the
    marker's name is refused". It no longer includes W2's "interrupted after 3a", which the
    marker decides now;
  - W01-R02 reverted: exit 1, 6 failing;
  - W1-F1 reverted: exit 1, 3 failing;
  - W1-F1 rollback check reverted: exit 1, 4 failing, now including "W2.1-R01: and the rollback
    that follows refuses".
- **The last two proofs, built exactly as that script builds them, run on their own**
  (`probes/revert-r04-r07.ps1`; `logs/install-revert-r04-r07.txt`; exit 0):
  - **W2-R04 reverted to W2's leftover-file rule:** self-test exit 1, "FAIL (77 checks)". Exactly
    two cases fail: "W2.1-R01: a rerun after a stop at staging is not finished as an interrupted
    update" and "W2.1-R01: and the rollback that follows refuses". The script's check, one match
    on the first, holds.
  - **W2-R07 reverted:** exit 1, one case fails (the tampered staged helper).

  So every proof failed in its expected cases, but the script's own closing "PASS" line was not
  observed.

## R02: the iroh refusal. Closed for every feature route tried

Nothing was built. Each spelling was tried three ways (`probes/iroh-matrix.py`; output
`probes/iroh-matrix.txt`; probe exit 0):

- `cargo tree --offline --locked -p heimdall --target aarch64-apple-darwin -e normal,build --features <s>`,
  to see whether cargo selects the iroh crate;
- `build-release.sh`'s token check (lines 55 to 59, extracted verbatim);
- `python3 -I tools/packaging/provenance.py check-features`.

**Every spelling for which cargo selects iroh is refused by `check-features` (exit 1).** These
are: `iroh`, ` iroh`, `iroh iroh`, `default,iroh`, `default iroh`, a tab, a newline,
U+00A0, U+2003, VT and FF as separators, `iroh,`, `,iroh`, `heimdall/iroh`,
`heimdall-runtime/iroh` and `heimdall-runtime?/iroh`.

- **Spellings cargo itself rejects:** `heimdall-transport-iroh/iroh`, `…?/iroh`, `dep:iroh`, `IROH`
  and `--all-features` as a feature value. `check-features` refuses them too: by the request
  check, or because `cargo tree` failed.
- **The shell check** misses only the separators bash does not split on: U+00A0, U+2003, VT and
  FF. Cargo splits on them. `check-features` catches them before the build (RC06, nit).

**`build-release.sh` end to end, in a scratch copy** (a `git archive` of `605f7286`, committed in
a scratch repository). A `cargo` shim first on `PATH` refuses `build`, `b` and `rustc` (exit 97),
and a fake SBOM tool answers only its version (`probes/build-release-shim.txt`):

| Input | Result |
|---|---|
| no features | `check-features` passes, then the shim refuses the build: exit 1 "cargo build failed" (the path to a build is reached) |
| `iroh`, `default iroh`, `heimdall-runtime?/iroh` | exit 2 at the token check |
| `default<U+00A0>iroh`, `default<VT>iroh` | exit 2, "provenance: refused: release artifacts are built without the iroh feature" / "refused before the build; nothing was built" |
| `--all-features` | exit 2, "--all-features is refused" |

**Turning iroh on through another feature** (`probes/iroh-indirect.sh`; output
`probes/iroh-indirect.txt`; scratch-copy edits, each committed so the tree is clean):

- **`preview = ["iroh"]` and `extras = ["heimdall-runtime/iroh"]` added to `crates/heimdall`:**
  `check-features --features preview` and `--features extras` exit 1, "the build graph holds the
  iroh crate (iroh)". `build-release.sh --features preview` exits 2 before the build.
- **`crates/runtime` with `default = ["iroh"]`, no feature requested:** `check-features` exits 1
  with the same message, and `build-release.sh` exits 2 before the build.
- **`build-record` over that graph,** with build messages naming iroh's and heimdall's manifests
  and a fake executable: exit 1, "the build graph holds the iroh crate", and **no record file is
  written**.
- **On the unmodified graph:**
  - messages without iroh: exit 0, and the record says `iroh_transport: not built …`;
  - messages naming iroh's manifest: exit 1, "the build compiled a package cargo metadata does
    not know", no record;
  - no `--build-messages`: exit 1, "--build-messages is required".

  So "not built" is written only after the request check and the compiled-set check pass
  (`make_record`, then `main` writes `opts["out"]`).

**Environment and configuration** (`probes/iroh-config.sh`; output `probes/iroh-config.txt`):

- `CARGO_FEATURE_IROH=1` leaves the selected graph without iroh (0 lines). The workspace has no
  `build.rs` to read it.
- `RUSTFLAGS` and the config `rustflags` are overridden by the script's
  `CARGO_ENCODED_RUSTFLAGS`. A `--cfg feature="iroh"` there could not link iroh in anyway: the
  crate is not in the graph. This is from reading.
- A repository `.cargo/config.toml` makes the tree dirty (`?? .cargo/config.toml`), so it is
  refused without `--allow-dirty`.
- **`CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR` and `[build] target-dir` move cargo's output**
  (cargo metadata's `target_directory` changes), but the script still stages
  `target/$target/release/heimdall`: see RC02.

**`build-release.ps1`:**

- It splits each comma token on `/`, and `-contains` is case-insensitive.
- Whitespace, `?` and `:` are already refused by its character check.
- It calls `check-features` before the build and passes `--build-messages` to `build-record`.

This was checked by reading only; nothing was run on Windows.

**`python3 -I tools/packaging/provenance.py self-test`:** exit 0, "provenance self-test: 0
failed" (`logs/provenance-selftest.txt`).

## R03: `fuzz/run-campaign.sh`. Partly closed

**Closed: the identity covers what the ruling lists.** It hashes:

- the root `Cargo.toml` and `Cargo.lock`;
- the product's `rust-toolchain.toml`, copied as `product-rust-toolchain.toml` so that it
  selects nothing;
- the line `nightly=$NIGHTLY rustc=<rustc +nightly --version> cargo-fuzz=$CARGO_FUZZ rustflags=$RUSTFLAGS`;
- as before, the linked crates, the fuzz manifest, the fuzz lock and the targets.

`libfuzzer-sys` is pinned through the fuzz lock. Not in the identity, and not asked for by the
ruling: the base image, the mutable tag `debian:13-slim`, which supplies `lld` and `clang`.

**Closed: a killed setup leaves no identity.**

- `setup` first removes `build-id` and `build-id.pending` (`:92`).
- It computes `build-id.pending` from the copied sources before the build (`:119`).
- It renames that to `build-id` only after the lock check and a matching recomputation
  (`:146-158`).
- `run` tags with `unknown` when there is no `build-id`. With an empty `build`, `report` counts
  `own=0`; it finds no `since` (awk `$1 == ""` matches only blank lines, whose `$2` is empty); and
  it marks every `build=` line "not met".

**Not closed: setup can no longer complete (RC03).**

- The old identity call at `:142`, `in_container none "$BUILD_ID_SCRIPT"`, was kept, with no
  arguments.
- The script now starts with `out=$1; net=$2` under `bash -euo pipefail`. So it dies with
  "`$1`: unbound variable", exit 1. Under the outer `set -e`, `setup` stops after building the
  targets and before the lock check.
- The `build-id` subcommand can then record an identity for that unfinished setup.

Reproduced without a container (`probes/r03-line142.sh`, output `probes/r03-line142.txt`). The
script was extracted from the file and run exactly as `in_container` runs it, with a `PATH`
holding no cargo:

- the call shape of `:142`: "campaign: line 2: $1: unbound variable", exit 1;
- with arguments (`- offline`): it passes that line and stops at `cd /vol/work/src`.

`bash -n` is clean. No fuzz container was started, since the defect hunt holds the one capped
container.

## R04: `tools/packaging/install.sh`, a moved executable's process. Closed

- **`-ef` is kept** (`:103`). Two string comparisons are added: the word as given against
  `$cur`, and against `curabs` (the prefix resolved with `cd -P`/`pwd -P`). A word naming
  `heimdall` also has its own directory resolved (`:106-108`). A resolution that fails falls
  back or never matches.
- **The reviewer's probe** (`probes/probe-r04-sh-reviewer.sh`, a copy of `probe-r06-sh.sh`;
  output `probes/probe-r04-sh-reviewer.txt`) was run against `605f7286`. The file is moved out of
  the prefix while its stand-in runs, then `a2`'s `install.sh` runs:
  - **under `/bin/sh`** (bash 3.2.57 in POSIX mode on this Mac): exit 1, "a process started from
    $T/prefix/heimdall is running (pid …)";
  - **under `dash`** (a `sh` link to `/bin/dash` first on `PATH`; `$BASH_VERSION` unset was
    checked): exit 1, the same.

  At `3943738d` the reviewer saw exit 0. Each stand-in was ended by its own PID (the probe's
  trap).
- **`bash tests/native/m08/lifecycle/install-selftest.sh`:**
  - with `/bin/sh`: exit 0, PASS, 45 ok (`logs/install-selftest-sh.txt`);
  - with `dash` as `sh`: exit 0, PASS, 45 ok (`logs/install-selftest-dash.txt`).

  Both include the two new `W2-R04:` cases, an absolute and a relative `--prefix` with the file
  moved inside the prefix.
- **What W1 had:** the string comparison is W1's check, so a process started from the installed
  path still refuses when an update has replaced that file. The relative and linked prefixes of
  W2-R06 still pass.
- **Not checked:** the "both fail with `-ef` alone" revert claim. It is the author's, by hand, and
  needs no revert proof (low, not blocking).

## R05: the records. Closed except as noted

- **(a) R04 on Windows.** The lifecycle README's W2 table now says R04 was reopened, and
  "R05 to R07 are closed on Windows. R04 is not". The progress row says "R05 to R07 closed on
  Windows; R04 reopened … fixed in W2.1, Windows run pending". But the same row keeps "an
  interrupted update is recognised only from the run's own staged executable (R04)", a phrase the
  review named (RC05).
- **(b) The counts.** `install-selftest.sh` "45 checks (43 before W2.1)" and
  `install-selftest.ps1` "77 checks (71 before W2.1)" match what was observed here: 45 under sh
  and dash, 77.
- **(c) stategen.** "12 unit and 18 fault-set tests pass on the Mac (the devbox ran 11 and 18,
  at `19ddcb41`, before the 12th)". 12 `#[test]` functions are in `crates/stategen/src`. The
  tests were not rerun here: W2.1 does not touch stategen.
- **(d)** The R05 row now says "No revert proof (not blocking: a low message fix, ADR-0009 §2.3)".
- **(e)** ADR-0014 §4.4 item 2 and m08-plan's artifact table now say the packed record holds the
  commit time, and that the external record adds the build's start and finish.
- **(f) In part, as briefed.**
  - `project_manifest.closing-extract.txt` is added, in the existing extract format, with no
    path. It is consistent with `results.txt:62` (`project_manifest exit 0 2026-11-23T11:00:59Z
    secs=1800`) and "Done 13412254 runs in 1801 second(s)".
  - `tests/evidence/artifacts/m08-fuzz/README.md:14` still says "`control_frame` and
    `project_manifest` have no extract here" (RC05; likely the coming evidence commit).
- **(g)** The benchmark README's metric table is one table again, and the floor sentence names
  the 50-sample CLI rows (`bench.py:200`, `cli(…, n=50)`).
- **The archived review.** `tests/evidence/artifacts/review-m08/w2.md` is byte-identical to
  `review.md` (`diff` exit 0). Its only path-like strings are the reviewer's own list of scan
  patterns. The stategen log and the cargo-tree probe, which hold a worktree path, are not
  archived.
- **The lifecycle README's W2.1 row** says "a stale marker is then removed". That is not so on
  the "already installed" path (RC01).

## R06: `agent-delay.py` and `bench-world.sh`. Closed

- **`agent-delay.py self-test`:** exit 0, "0 failed of 7" (`probes/r06.txt`).
- **`main()` probed in fresh processes** (`probes/r06-main.py`), in a scratch directory with two
  bound sockets. Each refusal exits 2 and makes **no listen socket**:
  - a link inside `ALLOWED_DIR` to a socket outside ("not inside the allowed directory");
  - a socket outside `ALLOWED_DIR`;
  - a path with `..` climbing out;
  - `ALLOWED_DIR` itself as the upstream;
  - a regular file, a FIFO and a directory inside ("not a socket").

  Each acceptance starts the proxy, listening with mode 0600: the run's socket, a link inside
  to it, and `ALLOWED_DIR` given through a link. Each proxy was ended by its own PID.
- **`bench-world.sh`** checks, before starting the proxy, that `ssh-add -l` on the upstream
  prints exactly k1's fingerprint. A second key, or any other agent, fails it. Together with the
  proxy's own check, the upstream must be this run's fixture agent.
- **The container guard** is character-for-character `lane.sh:17-19` (`in_container`, its
  refusal and the `HEIMDALL_TEST_*` refusal). On this Mac, with a scratch `HOME` and dummy
  arguments, `bench-world.sh` exits 2, "refused: this runs only inside the M08 container", with
  and without `HEIMDALL_TEST_X=1`. Nothing was written: the scratch `HOME` was still empty and the
  out directory was not made. The `HEIMDALL_TEST_*` branch itself needs a container and was not
  reached.
- **Not covered,** as the author says: a socket owned by another account.

## R07: `bench.py`. Closed, with one nit

- **A sample's end needs the key's effect.**
  - One `Screen` is kept for the whole session. The wait for "listings read" now reads it.
  - For each key, chunks are fed to the screen until the selected view's title appears. The
    title is `[2 Destinations]` or `[1 Overview]`: `view.rs` `render_header` wraps only the
    selected tab in brackets (`format!("[{label}]")`), and the others are ` n Title `.
  - Only then does the 20 ms quiet count start. Output without the title never ends a sample,
    and no title within 2 s is an error, with the screen kept.
  - In the normal alternation the expected title is absent before its key, so an unrelated
    redraw cannot end a sample. The exception, after an error, is RC04.
- **`key_to_first_byte`** still times the first output after the key, whatever it is. That is
  its definition, and the frame row no longer depends on it.
- **The idle scope.** The README's quotes match `spec.md:762-763` exactly: "Idle runtime CPU |
  < 0.5% of one logical core over a five-minute idle sample" and "Idle runtime memory | Target ≤
  150 MiB RSS/working set; report platform measurement method".
  - The rows themselves do not say "the process alone". The README's "as the spec's rows say" is
    a reading. It is supported by `spec.md:660` ("The runtime SHOULD be a small supervised
    per-user process") and by "RSS/working set", which are per-process measures.
  - The record now says its scope, and names direct children as `children_not_measured`.
  - Not checked: whether `/proc/<pid>/task/<tid>/children` exists in the container's kernel. If
    it does not, every window records `null`.
- **Not run** against the real TUI. That needs the capped container.

## New findings

### M08-W2-RC01 (low): the update marker can outlive its update, and then pairs an older helper-less executable with the newer helper

- **Blocks:** no (§2.1). The effect is R01's: a mismatched `.previous` pair that `-Rollback` puts
  in place and the hello refuses (ADR-0014 §3.5). Nothing is deleted. The trigger is ordinary, but
  narrower than R01's: a kill in the short window after 4b, on an update from an install with no
  helper, then a lost executable.
- **Where:** `tools/packaging/install.ps1`.
  - `:493` writes the marker for every update with a current executable, including one with no
    current helper, where no rename 3b follows.
  - `:502` removes it after 4b.
  - `:418` exits "already installed" **before** `:430`, the only other place that removes a
    stale marker.
  - `-Rollback` (`:323-365`) never removes it.
- **Reproduced** (`probes/probe-rc-marker.txt`, case C; fake archives under pwsh 7.7.0 on macOS):
  1. Install `a1n` (1.0.0, no helper).
  2. Update with `a2` and `STOP_AFTER=4b`. This leaves the complete 2.0.0 pair, prev = 1.0.0
     alone, and the marker.
  3. The rerun of `a2` exits 0, "this version is already installed", and the **marker stays**.
  4. Delete `heimdall.exe`. This is W1-R04's trigger, and gives the same state the R01 fix
     guards against, with a marker.
  5. The rerun of `a2` exits 0, "finished an interrupted update", and the state is
     `prev=1.0.0-nohelper | prevH=fake helper 2.0.0`.
  6. `-Rollback` **exits 0**: `cur=1.0.0-nohelper | curH=helper 2.0.0`.

  Case B-4b shows the marker surviving the "already installed" rerun and the `-Rollback` too.
- **Records:** the lifecycle README's W2.1 row ("a stale marker is then removed") overstates this.
- **Fix:**
  - Remove a marker that does not describe an interrupted update as soon as `$interruptedUpdate`
    is computed false, before the "already installed" exit, and in `-Rollback`. While it is true,
    keep it until the finish-move is done, as now.
  - Write the marker only when a 3b rename will follow (`(Kind $curH) -ne 'absent'` at `:493`).
  - Either read the digest, for example requiring a staged `.heimdall.new.exe` that matches it,
    or drop the claim that it matters.
  - Add a regression following case C.

### M08-W2-RC02 (low; the staging line predates W2.1): the release scripts stage `./target/<triple>/release/heimdall`, not the executable the build produced, so `iroh_transport: not built` describes the build, not necessarily the archive

- **Blocks:** no. The effect is a release record and SBOM that may not describe the packed
  executable, with no trust or data effect. The trigger is the builder's own environment.
- **Where:**
  - `tools/packaging/build-release.sh:180`: `install -m 0755 "target/$target/release/heimdall" …`;
  - `tools/packaging/build-release.ps1:136`: `Copy-Item "target\$target\release\heimdall.exe" …`;
  - `provenance.py` reads no artifact path from the build messages (no `"executable"` or
    `"filenames"`).
- **What goes wrong** (from reading, plus `probes/iroh-config.txt`):
  1. With `CARGO_TARGET_DIR` or `CARGO_BUILD_TARGET_DIR` set in the builder's environment, or a
     `[build] target-dir` in `$CARGO_HOME/config.toml`, cargo builds elsewhere. Metadata's
     `target_directory` moves, and the tree stays clean.
  2. The script then packs whatever is at `./target/<triple>/release/heimdall`. For example, an
     earlier source build with `--features iroh` and `--target`, the documented way to get the
     preview.
  3. Every check passes on the new build's messages: `check-features`, `build-record`'s compiled
     set and the SBOM. So the record says `iroh_transport: not built` while the archive carries
     it.
  4. `verify_artifact.py` checks only that the record's outputs are the archive's executables.

  Not run: it needs a release build.
- **Fix:** do one of these, in both scripts:
  - stage the path in the `heimdall` package's `compiler-artifact` message (`executable`) from
    the build messages;
  - or refuse when `cargo metadata`'s `target_directory` is not `$repo/target`.

### M08-W2-RC03 (low): `run-campaign.sh setup` always fails at `:142`, and `build-id` can then record an identity for that unfinished setup

- **Blocks:** no (§2.1: fuzz records). **Fix before the next setup.** The failure is fail-safe
  for the accounting, since runs read `unknown`, but no setup can record a build identity.
- **Where:**
  - `fuzz/run-campaign.sh:142`: `in_container none "$BUILD_ID_SCRIPT"` is W2's call, left in
    place with no arguments.
  - `BUILD_ID_SCRIPT` now begins `out=$1; net=$2` (`:68`) and runs under `bash -euo pipefail`.
    So it dies with "$1: unbound variable" (`probes/r03-line142.txt`).
  - The outer `set -e` then ends `setup` with exit 1 before the lock-file check (`:146`), the
    recomputation (`:152`) and the rename to `build-id` (`:158`). `build-id.pending` is left
    behind.
- **The follow-on:** `run-campaign.sh build-id` (`:257-258`) refuses only when `build-id`
  exists. After such a setup, or a killed one, it records the identity of the volume's sources
  without the lock check or the recomputation. That goes against the ruling that a failed or
  killed setup counts toward no build until a setup completes. It is an operator command, and
  its documented use is a build made before setup recorded identities.
- **Fix:**
  1. Delete `:142`.
  2. Make `build-id` refuse while `build-id.pending` exists, saying that a setup started and did
     not finish.
  3. The coming scratch-volume setup test then covers both.

### Nits (not blocking)

- **M08-W2-RC04 (`bench.py` key frames):**
  - The loop checks only that the title is present after the key, not that it was absent before
    it.
  - After an error (a key whose effect did not show), the TUI's view and the expected
    alternation can diverge. The next key's title may then already be on screen, and the first
    unrelated redraw would end that sample. Errors are counted and reported, so a clean run is
    unaffected.
  - Fix: skip the sample (or re-sync) when the title is already present before writing the key.
- **M08-W2-RC05 (records):**
  - `progress.md` row M08 W2 still has "an interrupted update is recognised only from the run's
    own staged executable (R04)".
  - `tests/evidence/artifacts/m08-fuzz/README.md:14` still says `project_manifest` has no
    extract.
  - The lifecycle README's W2.1 row says a stale marker "is then removed" (RC01).
- **M08-W2-RC06 (`build-release.sh:55-59`):**
  - The shell token check splits on `IFS` (space, tab, newline). Cargo also splits on VT, FF and
    Unicode spaces (shown: U+00A0, U+2003).
  - `check-features` refuses those before the build, so there is no effect; the comment "split
    as cargo splits it" overstates the shell half.
- **M08-W2-RC07 (`agent-delay.py`):**
  - `relay` connects to the path as given, not to the `realpath` that was checked, on every
    connection. A link swapped after start-up would be followed.
  - It needs a same-user program inside the container, and nothing of the owner's is there, so
    it is a residual-class nit.
  - Fix: connect to the resolved path.

## Regressions against what the first review found sound

- **Installers.**
  - Nothing added deletes or moves a file the scripts did not create. The marker is a new name
    of the script's own, kept to a file by `Assert-Names`.
  - Every earlier interruption point still settles to complete pairs (cases B-1 to B-4b; the
    self-test's 77 checks).
  - `install.sh`'s `-ef` cases still pass.
- **Provenance.**
  - The packed record is still deterministic (self-test).
  - `build-record` now needs `--build-messages`, and both scripts pass it. Its use of
    `compiled_packages` keeps the strict reader.
- **Fuzz accounting** (`report`): unchanged.
- **Benchmark harness:** unchanged apart from R06 and R07. No socket or `SSH_AUTH_SOCK` reaches
  the container.
- **`shellcheck -S warning`** on `install.sh`, `bench-world.sh`, `build-release.sh` and
  `run-campaign.sh`: exit 1, with one warning only, SC2174 at `bench-world.sh:83`
  (`mkdir -p -m 700 "$HOME/.ssh"`). That line predates W2.1.
- **Parsing:** `bench.py`, `agent-delay.py` and `provenance.py` parse (`ast.parse`).

## Secrets and personal data

All 880 added lines in `3943738d..605f7286` were scanned for:

- `HEIMDALL_CANARY_`;
- home and temp paths (`/Users/`, `/home/`, `/private/`, `/var/folders`);
- the account name, the owner's surname and email domain;
- private-key headers and public-key blobs;
- GitHub, AWS and Slack token prefixes;
- `vps1`, `devbox.`, `.local` and `.ts.net`;
- RFC 1918 and CGNAT addresses;
- e-mail addresses.

**The only hits:**

- the archived review's own list of scan patterns (`w2.md`);
- the lifecycle README's generic "`/var` is a link to `/private/var`".

No canary, key, token or personal datum was found. The new fuzz extract holds no path. This
directory's probes and logs were checked for `/Users/` (none); scratch paths are shown as `$T`,
`<out>`, `<scratch>` or `<repo>`.

## Not checked

- **Native Windows:**
  - NTFS rename and lock semantics, real junctions, Windows PowerShell 5.1, and the W2.1 PC job.
    Every `install.ps1` result here is pwsh 7 on macOS.
  - `build-release.ps1` was read, not run.
- **The devbox and Linux:** not run. `install.sh` ran on macOS only, under bash 3.2 as `sh` and
  under dash.
- **Release builds:** none. RC02 is from reading plus cargo metadata. Whether a real release
  build passes the new `check-features` and `build-record` path end to end is not shown: the shim
  stopped the only run that reached `cargo build`.
- **The fuzz volume and containers:** none started, since the defect hunt holds the one capped
  container. R03 and RC03 are from the code and from local runs of the extracted in-container
  script. The scratch-volume setup test is out of scope.
- **The benchmark against the real TUI and runtime:** not run (it needs the capped container).
  Not checked: whether `/proc/<pid>/task/<tid>/children` exists there.
- **stategen:** not rerun; W2.1 does not touch it.
- **`check.sh` and the workspace gates:** not run.

## Artifacts in this directory

- `recheck.md` (this file) and `DONE`.
- `logs/`:
  - `install-selftest-ps1.txt`;
  - `install-revert-proofs.txt`;
  - `install-selftest-sh.txt` and `install-selftest-dash.txt`;
  - `provenance-selftest.txt`.
- `probes/`:
  - `probe-rc-marker.ps1` and `.txt`;
  - `iroh-matrix.py` and `.txt`;
  - `build-release-shim.txt`;
  - `iroh-indirect.sh` and `.txt`;
  - `iroh-config.sh` and `.txt`;
  - `r03-line142.sh` and `.txt`;
  - `probe-r04-sh-reviewer.sh` and `.txt`;
  - `r06-main.py` and `r06.txt`.
- `logs/install-revert-r04-r07.txt` and `probes/revert-r04-r07.ps1` (the two proofs rerun).
- **Removed after use:**
  - the `cargo` shim. It was a `sh` script that exits 97 for `build`, `b` and `rustc` and
    `exec`s the real cargo otherwise; it named the cargo path, so it is not kept;
  - the `dash` link;
  - the scratch repository copy;
  - every temporary directory the runs made.
- **The worktree's `target/`:** see the cleanup line below.

**Cleanup.**

- **The worktree's `target/`:** nothing was built in the worktree (only `cargo tree` and
  `cargo metadata`), so `target/` was never created. `du -sh target` reports "No such file or
  directory".
- **The worktree:** `git status --porcelain` is empty, and HEAD is detached at `605f7286`.
- **The scratch directory** (the repository copy, the fake SBOM tool and every temporary
  directory) was removed by its exact path, as were the `cargo` shim and the `dash` link.
- **Processes:** every stand-in and proxy process was ended by its own PID. No process from this
  re-check is left running.
- **The probes in `probes/`** that need the scratch repository copy (`iroh-indirect.sh` and
  `iroh-config.sh`) say how it was made: a `git archive` of `605f7286`, committed in a scratch
  repository.
