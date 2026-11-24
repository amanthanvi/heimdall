# Fuzz targets (M08 U1a)

Coverage-guided fuzzing of the parsers that take outside input (ADR-0014 §2). **Provisional,
to be integrated:** seventeen targets cover boundaries 1–12 of ADR-0014 §2.1; 13–15 wait for
M06 and M07. Boundary 12 is covered only in its pure part: the known-hosts file reader and
the `ssh -G` output reader take files and a child process, and have no target.

- **Not part of the workspace.** `fuzz/Cargo.toml` has its own empty `[workspace]` table and
  its own `Cargo.lock`. The product's toolchain pin and lock file are untouched.
- **Built and run only in a container** (`run-campaign.sh`): `debian:13-slim`, the pinned
  nightly, cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13. The repository is mounted read-only; the
  nightly, the crates, the build directory and the corpus live in the Docker volume
  `hm-m08-fuzz`, removed with `run-campaign.sh clean`. `setup` uses the network; `run` has none.
- **A finding is not evidence until it is reproduced on the pinned stable toolchain** as a
  regression test under `tests/adversarial/`. Crash inputs are hostile bytes: copy them out
  with `run-campaign.sh crashes <dir>` into a directory of their own.
- **The stopping rule** is ADR-0014 §2.3: at least 2 CPU-hours per target, no new coverage in
  the last 30 minutes, no open finding; a ceiling of 8 CPU-hours.
  - **"No new coverage" means no new edge** (libFuzzer's `cov`), ruled by the orchestrator on
    2026-11-23 (review M08-W1-R08(b)): the plan's coverage counter. Features (`ft`) and corpus
    entries are recorded beside it and may still grow.
  - **CPU-hours are wall-clock seconds of one target.** Two targets run at a time in a
    container capped at 2 CPUs, so a target's second of `-max_total_time` is about one
    CPU-second (R08(e)).
  - **Time counts per build** (R08(a)). Setup records a build identity: a SHA-256 over every
    file of the workspace crates the fuzz crate links, its manifest, lock file and targets,
    and (since W2.1, review M08-W2-R03) the workspace's root `Cargo.toml` and `Cargo.lock`, the
    product's `rust-toolchain.toml`, the pinned nightly with its `rustc --version`, the
    cargo-fuzz version and `RUSTFLAGS`, and (since W3) the base image, pinned by its digest in
    `run-campaign.sh`. Every run line carries it (`build=`), and the report
    counts only the current build's runs, plus earlier unrecorded runs that
    `fuzz/accounting.txt` declares equivalent, with the reason. It prints the counted time, its
    two parts and the time of all runs.
  - **No run counts until a setup completes** (M08-W2-R03). Setup first removes the recorded
    identity, computes the new one from the copied sources before building, and records it only
    after every step has passed and a recomputation over what was built gives the same value.
    A setup that fails or is killed part-way leaves no identity, so the runs that follow carry
    `build=unknown`, which the report never counts. `build-id show` prints the identity of the
    volume's sources under the current formula and writes nothing.
  - **`13453c69d123f948` was computed before W2.1 widened the formula**, so it covers the linked
    crates, the fuzz manifest, lock and targets only. Recomputed over the same volume sources with
    `build-id show` on 2026-11-24, it is `888d8dd2babf0fc7`, with `toolchain-file=absent` (W2's
    setup did not copy the product's toolchain file) and the toolchain line
    `nightly=nightly-2026-11-15 rustc=rustc_1.102.0-nightly_(5f4effd57_2026-11-13)
    cargo-fuzz=0.13.2 rustflags=-Clink-arg=-fuse-ld=lld`. The recorded identity and the run lines
    keep `13453c69…`: the campaign of record will be set up afresh on the candidate's build under
    the new formula.

| Target | Boundary | Entry points |
|---|---|---|
| `sshconf_parse` | 1 | `sshconf::parse::parse_file` |
| `gitedit_scan` | 2 | `sshconf::gitedit::{scan, find_blocks}` |
| `agent_reply` | 3 | `ipc::agent_client::parse_reply` |
| `control_frame` | 4 | `ipc::decode_frame` as `ClientMessage`, `ServerMessage` and a JSON value |
| `signing_request` | 5 | `ipc::signing::{classify, parse_sign_request, SessionBindRecord::parse}` |
| `userauth_request` | 6 | `credential::purpose::parse_userauth`, `credential::session_bind::parse` |
| `registry_hm1` | 7 | `registry::hm1::parse`, `registry::classify::HolderRecord::parse` |
| `project_manifest` | 10 | `project::manifest::parse_manifest`, `project::parse_bundle` |
| `runtime_config` | 11 | `runtime::config::Config::parse` |
| `runtime_instance` | 11 | `runtime::instance::InstanceInfo`, decoded as `read_file` does |
| `sshconf_eval` | 1 | `sshconf::eval::evaluate` over an in-memory root file and one included file |
| `frame_codec` | 4 | `ipc::session::BoundedFrameCodec`, fed in attacker-chosen chunk sizes |
| `registry_script` | 7 | `registry::script::{RegistryPath, Marker, RegistryLine, StepToken}::parse` |
| `registry_line` | 7 | `registry::line::{lines, marker_of, marker_ok, marker_lines, contains}` |
| `issuer_protocol` | 8 | `issuer::protocol::{Request::decode, Response::decode, split_frame}` |
| `issuer_backup` | 9 | `credential::cert::SecretCaKey::decrypt_openssh` (a fixed fixture passphrase), the recovery bundle's JSON, `issuer::backup::fingerprint_from_file_stem` |
| `known_hosts_match` | 12 | `localenv::known_hosts::{hosts_match, lookup_name}` (the pure part) |

Not reached by any target: the known-hosts file reader and the `ssh -G` output reader.

## Campaigns so far

| Date | Tree | Per target | Result |
|---|---|---|---|
| 2026-11-22 | `m08/w0` at `bd1a8c43` (product code = `main` at `de097dac`) | 300 s, all nine | exit 0 each; 0 findings; about 35 million executions in total. Coverage was still growing on most targets, so **the stopping rule is not met**; this run proves the harness |
| 2026-11-22 | the same | 3600 s more on `sshconf_parse`, `gitedit_scan`, `control_frame`, `project_manifest` (corpus kept from the first run) | exit 0 each; 0 findings; about 67 million executions. A new input was still being found in the last seconds of each, so **the stopping rule is not met** |

**Six runs exited 1 (2026-11-22, 12:08Z to 12:21Z, 300 s requested):** `frame_codec`,
`sshconf_eval`, `registry_line`, `issuer_protocol`, `issuer_backup`, `known_hosts_match`
(review M08-W1-R08(c)). They were build failures, not crashes. The setup before them, which
added these targets, had been killed: the address-sanitizer compile of `heimdall-runtime` ran
out of the container's 4 GiB (`signal: 9, SIGKILL` in the setup log, read at 12:21Z). So
`cargo fuzz run` tried to build each target, failed, and exited 1, at about 2.5-minute
spacing and with no fuzzing. Their artifact directories are empty. Setup was then given
8 GiB and one compile job, and these targets ran from 12:50Z with exit 0. The setup and run
logs of that hour were overwritten and are not kept; this rests on the session's record of
the setup log and on the timing.

**Do not run a campaign while `check.sh` runs.** The second campaign overlapped a `check.sh`
run, and two timing-sensitive issuer tests in `e2e_cli_m03` failed under the load; they
passed three times out of three on a quiet machine, and the gate was rerun alone.

### After the merge of `main` at `6a087fbb` (tree `3b158d94`)

| Date | What | Result |
|---|---|---|
| 2026-11-22 | First 300 s on the seven newer targets (before the merge) | exit 0 each; 0 findings; about 22 million executions. `issuer_backup` showed no timeout |
| 2026-11-22 | Rebuild on the merged tree with the default linker | 14 of 16 built. `runtime_config` and `runtime_instance` failed to link: `relocation truncated to fit: R_AARCH64_CALL26`. The instrumented binary that links the runtime crate is about 250 MB with M06's code |
| 2026-11-22 | Rebuild with `lld` | **16 of 16 built** |
| 2026-11-22 | 2700 s on `agent_reply`, `signing_request`, `userauth_request`, `registry_hm1` | exit 0 each; 0 findings; about 277 million executions. `signing_request` has plateaued (its last new input was number 41 of 82 million) |
| 2026-11-22 to 2026-11-23 | Further batches of 3300 to 3600 s, two targets at a time, on all 17 targets | exit 0 each; 0 findings. Cumulative on 2026-11-23, before the batch then running: 6900 s `runtime_config`, `sshconf_eval`, `frame_codec`; 6600 s `agent_reply`, `signing_request`, `userauth_request`; 6300 s `registry_hm1`; 3900 s `sshconf_parse`, `gitedit_scan`, `control_frame`, `project_manifest`; 3600 s the other six. Most targets logged a new or reduced input close to their last execution, so **the stopping rule is not met for any target** |

**Cumulative time per target is printed by `run-campaign.sh report`,** with a
**stopping-rule column** (added 2026-11-23). It says `met` for a target only when all of
these hold, and `not met` otherwise:

- the target's last run was at least 1800 s, and the edge coverage (`cov`) libFuzzer printed
  when that run had loaded its corpus (`INITED`) equals the coverage at its end, so the whole
  last run found no new coverage. This is stricter than "the last 30 minutes" of a longer
  run, and it is read from one log with no timing estimate;
- the target's runs that exited 0 add up to at least 7200 s;
- its artifact directory holds no finding.

The rule is claimed per target from that column and from nothing else. A target whose
closing run still gains coverage runs on toward the 8 CPU-hour ceiling. The feature
count (`ft`) may still grow while `cov` is flat; the column reads `cov`, and the report
prints both.

### The closing pass (2026-11-23, 09:00Z to 13:31Z)

The fuzz binaries are those built at setup (2026-11-23, 00:07Z to 00:21Z), build identity
`9dd72f8fd9e5c17c`, equal to that of `ec985922` and `b157352e` recomputed from git. W1 changed
only `crates/stategen`, which no target links.

1800 s on every target, two at a time. Every run exited 0; no finding on any target. Fuzz
lock sha256 `c330d00e…`. The figures come from the raw extracts in
`tests/evidence/artifacts/m08-fuzz/`. "Counted on this build" excludes the runs on
`bd1a8c43`'s build (all ending by 2026-11-22T13:05:06Z), per `fuzz/accounting.txt`.

| Target | All runs (s) | Counted on this build (s) | Closing run: edges (`cov`) load → end | Features (`ft`) load → end | Corpus entries load → end | Findings | Stopping rule |
|---|---|---|---|---|---|---|---|
| `sshconf_parse` | 9,000 | 5,100 | 440 → 442 | 3009 → 3020 | 945 → 953 | 0 | not met: edges grew |
| `gitedit_scan` | 9,000 | 5,100 | 817 → 820 | 5160 → 5248 | 1691 → 1727 | 0 | not met: edges grew |
| `agent_reply` | 8,400 | 8,100 | 1240 → 1245 | 2552 → 2976 | 307 → 324 | 0 | not met: edges grew |
| `control_frame` | 5,700 | 1,800 | 2649 → 2818 (report line; extract to follow) | | | 0 | not met: edges grew; under 7200 s on this build |
| `signing_request` | 8,400 | 8,100 | 96 → 96 | 97 → 97 | 20 → 20 | 0 | met |
| `userauth_request` | 8,400 | 8,100 | 600 → 712 | 745 → 881 | 171 → 211 | 0 | not met: edges grew |
| `registry_hm1` | 8,100 | 7,800 | 588 → 588 | 1511 → 1549 | 517 → 547 | 0 | met |
| `project_manifest` | 5,700 | 1,800 | 5388 → 5441 (report line; extract to follow) | | | 0 | not met: edges grew; under 7200 s on this build |
| `runtime_config` | 8,700 | 8,400 | 5761 → 5932 | 27110 → 27919 | 6043 → 6350 | 0 | not met: edges grew |
| `sshconf_eval` | 8,700 | 8,400 | 1595 → 1676 | 6596 → 7119 | 1050 → 1134 | 0 | not met: edges grew |
| `frame_codec` | 8,700 | 8,400 | 98 → 98 | 423 → 423 | 85 → 85 | 0 | met |
| `registry_line` | 9,000 | 8,700 | 115 → 115 | 722 → 723 | 251 → 252 | 0 | met |
| `issuer_protocol` | 9,000 | 8,700 | 2720 → 2766 | 10478 → 10621 | 2632 → 2700 | 0 | not met: edges grew |
| `issuer_backup` | 9,000 | 8,700 | 4951 → 4971 | 12879 → 12984 | 5135 → 5192 | 0 | not met: edges grew |
| `known_hosts_match` | 9,000 | 8,700 | 129 → 129 | 646 → 647 | 204 → 205 | 0 | met |
| `runtime_instance` | 9,000 | 8,700 | 1799 → 1799 | 5224 → 5231 | 2014 → 2018 | 0 | met |
| `registry_script` | 9,000 | 9,000 | 416 → 416 | 1267 → 1267 | 490 → 490 | 0 | met |

**Met (7):** `signing_request`, `registry_hm1`, `frame_codec`, `registry_line`, `known_hosts_match`, `runtime_instance`, `registry_script`.
**Not met (10):** `sshconf_parse`, `gitedit_scan`, `agent_reply`, `control_frame`, `userauth_request`, `project_manifest`, `runtime_config`, `sshconf_eval`, `issuer_protocol`, `issuer_backup`.

The seven met targets are the ones the W1 report recorded; counted per build, each still has
at least 7,800 s. `registry_hm1` added 30 corpus entries in its closing run (517 → 547) and
38 features, with no new edge: observed, and within the rule as ruled. `runtime_instance`,
`known_hosts_match` and `registry_line` likewise gained features or corpus entries but no
edge.

The ten not met run on toward the 8 CPU-hour ceiling (28,800 s counted) and are claimed only
from a later closing run of the counted build with no new edge. `control_frame` and
`project_manifest` have 1,800 s on this build: their 3,900 s before the M06 merge ran on
`bd1a8c43`'s build and do not count (review M08-W1-R08(a)).

Results recorded before the merge are from the older product code; the corpus carries over,
the coverage figures do not.

### The final record of build `9dd72f8fd9e5c17c` (closed 2026-11-23T20:57Z)

Ruled after M06 W5 merged into main (`f0ee5c87`): this build is closed after round 2's closing run
(round 3 not run) and kept as history. M06 W5 changes crates most targets link, so none of this
time counts toward the candidate; the campaign of record runs on the candidate's build. The
closing line is in `results.txt`. Round 2 was 3,600 s on eight targets, then 1,800 s each.

| Result at this build | Targets |
|---|---|
| **Met** (8) | `signing_request`, `userauth_request`, `registry_hm1`, `frame_codec`, `registry_line`, `known_hosts_match`, `runtime_instance`, `registry_script` |
| **Not met, edges still growing** (8) | `sshconf_parse` (444 → 448 in its last run), `agent_reply` (1259 → 1260), `control_frame` (5412 → 6284), `project_manifest` (5506 → 5525), `runtime_config` (6096 → 6195), `sshconf_eval` (1698 → 1705), `issuer_protocol` (2855 → 2897), `issuer_backup` (5006 → 5011) |
| **Not met, a finding** (1) | `gitedit_scan`: M08-W2-F1, below |

### Finding M08-W2-F1: `find_blocks` is quadratic in time and allocation (`gitedit_scan`, 2026-11-23)

- **What the fuzzer saw:** in round 2's closing run, `gitedit_scan` stopped with
  `libFuzzer: out-of-memory` (1,107 MB against `-rss_limit_mb=1024`) after 25,170 executions,
  replaying the corpus (`MS: 0`). The artifact (124,182 bytes, sha256 `63fa15e7…`) is kept out
  of the repository.
- **Triage** (the orchestrator's branches):
  - the input alone, in the sanitizer build: no out-of-memory, peak 263 MB (a 1-byte input:
    42 MB);
  - the whole corpus replayed (25,189 files, 79 MB) at 1,024 MB: out-of-memory again;
  - no single input among the 150 largest exceeds 310 MB;
  - on the pinned stable toolchain, release build, the input alone: peak footprint 2.0 MB. So
    it is not unbounded memory held at once.
- **Cause, measured on stable:** `gitedit::find_blocks` (and the SSH-configuration flavour,
  which shares `edit::locate`) does quadratic work. On the artifact repeated 1, 2, 4 and 8 times:

  | Input | Blocks | Time | Allocations | Bytes allocated in total |
  |---|---|---|---|---|
  | 124 KB | 258 | 63 ms | 2.1 M | 112 MB |
  | 248 KB | 516 | 251 ms | 8.6 M | 453 MB |
  | 497 KB | 1,032 | 1.02 s | 34.7 M | 1.8 GB |
  | 993 KB | 2,064 | 4.16 s | 139 M | 7.3 GB |

  Each doubling multiplies time and allocation by four. Two steps in `crates/sshconf/src/edit.rs`
  cause it: for every begin marker without an end, `locate` scans every later line and
  `is_end_marker` builds a new `String` for each one (`format!`); and `position_of` reclassifies
  every earlier line for every block. The sanitizer's quarantine keeps the freed memory, which
  is why the fuzzer, not the stable build, ran out of it.
- **Effect:** a Git or SSH configuration file near the 1 MiB read limit, holding many
  unterminated Heimdall begin markers, costs seconds of CPU and gigabytes of transient
  allocation each time it is scanned. It is the user's own file, so this is a performance
  defect, not an authority one. **Severity: low.**
- **Owner:** the orchestrator at U0 (`crates/sshconf`). The likely fix: build each end marker's
  text once and find end markers in one pass, and compute block positions in one pass.
- **Regression test (for U0 to land with the fix):** deterministic, not timed. A synthetic input
  of N lines `# >>> heimdall managed include (id hm-d5a1da95ac1fdca4)` with no end marker,
  N = 2,000, 4,000 and 8,000 (three points, so a near-quadratic result cannot pass by luck); with a
  counting allocator in its own test binary, each doubling stays under 2.5 times the allocations,
  and the result reports N blocks, none intact (accepted by the orchestrator, 2026-11-23).
- **Closed (2026-11-24).** Fixed by the orchestrator in `crates/sshconf` (main `b14c210b`, with
  `tests/adversarial/sshconf_block_scan.rs`: allocation ratios at N = 2,000, 4,000 and 8,000, both
  flavours). Checked on the fuzz build `13453c69d123f948` (the merge `1d7b2870`):
  - the whole `gitedit_scan` corpus (25,189 inputs) replayed in the sanitizer build at
    `-rss_limit_mb=1024`: exit 0, peak 636 MB, 6 s (before: out of memory at 1,108 MB);
  - the old artifact alone: 4 ms, 45 MB (before: 363 ms, 263 MB);
  - 3,600 s of fuzzing: exit 0, no new artifact, peak RSS 816 MB, 8.9 million executions.

  The old artifact was moved out of the target's artifact directory into the volume's
  `artifacts-history/9dd72f8fd9e5c17c/`, so the report counts findings on the current build only.
  Watch item: the sanitizer build's peak RSS reached 816 MB of the 1,024 MB limit in one hour; a
  longer run is the next evidence.
- `gitedit_scan` stays **not met** while M08-W2-F1 is open.

### The defect hunt on the merged build `13453c69d123f948` (2026-11-24, 08:47Z to 13:17Z)

After F1 was closed, every target ran 1800 s more on the merged build (two at a time, in the
capped container). Defect hunting, not the campaign of record, which runs on the candidate's build.
- **Every run exited 0, with no finding on any target;** 0 artifacts on all 17.
- The stopping rule is **not met** on any target, as expected: the counted time on this build is
  1800 s per target (5400 s for `gitedit_scan`), below the 7200 s the rule needs.
- **Peak RSS against the 1024 MB limit** (watch items, from each run's statistics):
  `runtime_config` 934 MB, `project_manifest` 904 MB, `gitedit_scan` 737 MB, `issuer_protocol`
  704 MB. The longer campaign of record is the next evidence on whether they stay under it.
- Records: `tests/evidence/artifacts/m08-fuzz/hunt-13453c69/` (the report and one closing
  extract per target), and `results.txt` to 13:17Z.

