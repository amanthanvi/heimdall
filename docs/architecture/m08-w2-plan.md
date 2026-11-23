# M08 W2 plan (after the W1 merge at `b157352e`)

**Status:** approved by the orchestrator, 2026-11-23, with the notes folded in below. It covers W2's remaining units after the W1 review's findings (R01 to R09, done in `33534be6` to `24b1e27b`; PC job 47 pending). Inputs: m08-plan §3 to §7 and §12, ADR-0014, and the read-only M09 pre-audit (its §4, §6.2 and §7 items 2, 9 and 10). Nothing here changes a rule of m08-plan; where a unit cannot run under today's limits, the row says what blocks it.

**Boundaries that shape every unit.**
- A release `heimdall` runs only in a container or a disposable account or VM (AGENTS.md).
- The candidate build does not exist yet. U3b (the candidate archives) waits for the contract handoff after M06's exit (m08-plan rule 2).
- A number measured on any other build is a rehearsal. The record says so and never presents it as the release figure.

## W2-1. Fuzz: the record of the old build, defect hunting, and the campaign of record

Ruled 2026-11-23, after M06 W5 merged into main (`f0ee5c87`):

- **The build `9dd72f8fd9e5c17c` (= `ec985922`'s linked crates) is closed after round 2's closing
  run.** Round 3 is not run. Its final record lists each target as met or not met at that
  build, with counted time, edges and features. It is history: M06 W5 changes crates most
  targets link, so none of its time counts toward the candidate.
- **Until the candidate:** the newest merged build is fuzzed whenever the capped-container slot
  is free, as defect hunting. A crash is a finding, handled as ADR-0014 §2.4 says. Its time
  counts only if no later change touches the target's linked crates, which the per-build
  accounting (`fuzz/accounting.txt`, `build=` per run) shows.
- **The campaign of record runs on the release candidate's build** (U0's contract rev 7 changes
  the contract and store crates again). Record: `tests/evidence/m08-fuzz-campaign.json`, one row
  per target (counted time; the closing run's edges, features and corpus at load and end;
  findings; met or not met). A target at the 8 CPU-hour ceiling still gaining edges is `not met`
  at the ceiling, and the go/no-go draft names it with its final edge count.
- **Where:** the Mac, in the capped container. No PC fuzzing.

## W2-2. A29's spec §14.3 table

- **Now:** confirm the two rows m08-plan §7.1 leaves as "to confirm in U1b", from the existing tests:
  - host alias collision;
  - a stopped service recovering with a stale signing handle.

  **Done (2026-11-23):** both rows are confirmed in m08-plan §7.1's table: host alias collision is **partly covered** and the stale signing handle is **mostly covered** for the runtime signer and partly for the issuer. Each row names its tests and its gaps, which U1b fills with new tests at the frozen tree.
- **After the handoff (U1b):** fuzz boundaries 12 to 15 (M06's bridge frames and invitation records, the route helper's buffer, the `sshd -T` verifier, M07's page tokens and selectors), then the table confirmed at the frozen tree.

## W2-3. A34: benchmarks and the soak

### Where each row can run today

| Row | Host | Build | Today |
|---|---|---|---|
| Linux arm64, benchmarks and the 72-hour soak | The Mac, in one `linux/arm64` container (`--network none`, 2 CPUs, 2 GiB) | The candidate's Linux arm64 archive | **Supplementary.** The native row stays blocked on **B9** |
| Linux x86-64, benchmarks and the 6-hour cross-check | A disposable WSL2 distribution on the PC (m08-plan §4.2, §6.2) | The candidate's x86-64 archive | **Blocked** on the owner's decision to allow one disposable distribution, imported and then unregistered by exact name (on the owner's list since 2026-11-23). The devbox needs **B8** for a release runtime |
| macOS arm64 | A disposable macOS account | The candidate's macOS archive | **Blocked on B3** |
| Windows x86-64, benchmarks and the handle cross-check | A disposable Windows account | The candidate's Windows archive | **Blocked on B2**. Without it, a debug build gives mechanism evidence only, and no Windows soak harness exists |

### Benchmarks (spec §15.1; ADR-0014 §6.1)

- **Harness, before the candidate:** extend `tools/benchmarks/m08/` (U5a).
  - **Fixture:** an import bundle of 100 fixture destinations on loopback.
  - **Request latency on one open control session** through M07's reference wrapper (status, inspect, an already-authorized ensure), so process start is excluded. The CLI's end-to-end time is printed beside it, for information.
  - **First TUI frame:** from spawn to the first complete frame on a pseudo-terminal.
  - **Key handling under real background work:** M05 U0b's delaying agent proxy.
  - **Idle CPU:** three 5-minute samples after 10 minutes of settling.
  - **Idle memory:** resident set size.
  - At least 200 samples per latency metric (a floor), reported as P50 and P95, with the host model, CPU, memory, OS build and power state in the record. The record states each metric's warm and cold conditions: whether the runtime, the session and the file-system caches were already warm, and how a cold sample was produced.
- **Rehearsal:** once, on `main`'s Linux arm64 release archive in the container, labelled a rehearsal. It shows the harness works and gives an early read of the budgets.
- **Figures of record:** at the candidate, per the table above.
- **The debug probe's 306 ms.** M07's P2 measured key-to-first-byte p95 at 306 ms with 3,000 destinations on a debug build. The budget is set at 100 destinations, where the same probe measured 15 to 19 ms. Two checks follow:
  - A20's planned check (m07-plan §6): debug build, macOS, at 100, 1,000, 3,000 and 5,000 rows, key to the completed frame;
  - the release-build rehearsal, at the same sizes.

  Above 100 destinations no budget applies. The record will still show the curve, and the limitations page will name any size at which key handling exceeds 100 ms on the release build.

### The 72-hour soak (spec §15.1, R-QU-04; ADR-0014 §6.2 to §6.6)

- **Build:** the candidate's Linux arm64 archive. For lane L's update and rollback, the previous archive is the last one built before the candidate.
- **Hardware:** the Mac (Apple silicon, Docker Desktop, `linux/arm64`), one container, `--network none --cpus 2 --memory 2g --pids-limit 512`, at most 2 GiB of disk.
- **Lanes:**
  - S and L on the release archive;
  - M on a debug build with the scratch store (mechanism evidence only, as m08-plan §6.2 says);
  - R only if M06's exit supports runners in containers.
- **The Mac is shared** with other workloads. The record says so, and the soak captures the host's load samples (1-, 5- and 15-minute load and free memory, every 30 s) beside its own. A soak whose failure lines up with host overload is run again, never silently discarded.
- **Start:** when U3b freezes the candidate's feature set and archives.
- **Two capped containers in the candidate phase** (ruled 2026-11-23): the 72-hour soak of record and
  the fuzz campaign of record may run at once, each with `--cpus 2` and its memory cap. The host
  load sampling covers both. If the 15-minute load stays above 30 for an hour, the fuzz pauses
  and the soak keeps running; the pause and resume are written into the campaign's `results.txt`. The orchestrator reads the status file at start, +1 h, +6 h, +24 h, +48 h and +72 h.
- **Before the candidate:** one 6-hour rehearsal on `main`'s Linux arm64 release archive, lanes S and L, to confirm the thresholds and the self-stop. It is not a soak of record.
- **Invalidation:** ADR-0014 §6.5. A change to any crate linked into the runtime, the issuer, a helper or a bridge after the soak starts means the soak is run again.
- **Blocked rows, named in A34** (ADR-0014 §6.4):
  - release-managed: B3 or B11;
  - provider: B1;
  - route: M06's runner and Iroh rows on a release build;
  - native macOS and Windows long runs: B3 and B2.

### Every numerical claim (pre-audit §6.2)

| Claim | Covered by |
|---|---|
| Warm status or inspect ≤ 100 ms P95; warm ensure ≤ 250 ms P95 | W2-3 benchmarks (rehearsal now, record at the candidate) |
| First TUI frame ≤ 750 ms P95 | W2-3 benchmarks |
| Key handling ≤ 100 ms P95 under background work | W2-3 benchmarks; the 306 ms debug figure handled as above |
| Idle CPU < 0.5 % of a core; idle memory ≤ 150 MiB | W2-3 benchmarks (idle samples) and the soak's per-process series |
| Stable idle polling | The soak: per-process CPU and descriptors; the fixture sshd's and agent proxy's contact counts in the retry record |
| Zero routine prompts; zero silent widening; zero canary leaks | Existing records (`m05-a02-trusted-week`, `m01-a06`, `m01-a07`, `m03-a33-secrets`). M08 adds the support bundle's and the release artifacts' canary scans (U6b, U3b) |
| 72 hours without unbounded growth | The soak of record |
| 12 h trusted-work window; 7 d retention; 90-day deprecation window | Defaults and a policy, not measured claims. The release notes say so; M09's normal week tests the window (plan §8.4) |
| Matrix observations and M07's caps | Observations and design values. The matrix labels them as probe observations; U0 confirms the caps |
| The fuzz stopping rule | W2-1 |
| Configuration scanning near the 1 MiB read limit | **No spec §15.1 claim covers it.** Finding M08-W2-F1 (low; `edit::locate` is quadratic: a 993 KB file costs 4.2 s and 7.3 GB of transient allocation) is named here so that no later budget or limitation statement about large configuration files omits it |
| Release-binary facts (crate counts, size, the home path) | Superseded at the candidate by its SBOMs, build records and `verify_artifact` (W2-5) |

## W2-4. The floors and the matrix (U7)

- **ADR-0001 §5 and `docs/compatibility/matrix.md`'s floor table:**
  - state ADR-0004 §4's floors as **provisional**, with the status `blocked` for their confirmation:
    - macOS 27 arm64;
    - Windows 11 26H2 x64 with the in-box OpenSSH;
    - WSL2 with Ubuntu 24.04;
    - Ubuntu 24.04 and Debian 13 on Linux;
  - name what confirms each: B15 for Windows and macOS clean machines, the disposable WSL distribution for Linux x86-64 and WSL2, and B9 for arm64.

  This removes the contradiction without claiming a confirmation.
- **The matrix header:**
  - Heimdall builds exist;
  - the first release archives were built and statically verified: macOS arm64, both Linux targets, and Windows on the PC (jobs 40 and 43);
  - none was run on a clean machine or a fresh account;
  - every label stays `not-tested` until ADR-0001 §5 and §6 close.

  The date and version are updated with it.
- **Files:** `docs/decisions/0001-*.md` (§5 only, as an amendment note), `docs/compatibility/matrix.md` (header and floor table). Docs only, ready now.

## W2-5. The release set (plan §10.2)

- **At the candidate (U3b):**
  - the four archives;
  - the external index `tests/evidence/artifacts/m08/release/<version>/SHA256SUMS`;
  - per target: `BUILD-RECORD.json`, the SBOM and `THIRD-PARTY-NOTICES.txt`;
  - the record `tests/evidence/m08-release-artifacts.json`;
  - the examples M07 ships (skill, wrapper, harnesses) inside the archives.
- **How each archive is built:**
  - **macOS arm64:** on the Mac, statically verified. It may not run on the host, so its run row is blocked on B3.
  - **Linux x86-64 and arm64:** through zig on the Mac, statically verified. Arm64 is run in the container; x86-64 waits for the disposable WSL distribution.
  - **Windows x86-64:** on the PC (`build-release.ps1`, proven in jobs 40 and 43), installed as files. Its run is blocked on B2 and B15.
- **Named as blocked in the go/no-go draft** (`docs/release/candidate-worksheet.md`, U8):
  - checksum signing and Authenticode (B16);
  - Developer ID and notarization (B13);
  - the licence and the name decision (B17);
  - the reporting route (B18).

  `LICENSE` and `SECURITY.md` stay out of the tree until the owner decides, and the archives print them as not packaged.
- **Before the candidate:** a dry run of the whole set on `main`. It builds all four archives and the index into scratch, checks that every artifact row is produced or names its blocker, and commits nothing but the record of the run. No archive goes into git.

## W2-6. Reproducible builds

- **Windows:** `-Clink-arg=/Brepro` in `build-release.ps1`. That removes the link timestamp and makes the PDB GUID deterministic, the only differences between jobs 40 and 43.
- **The check, per platform:** two builds of one commit from two checkouts at different paths, compared byte for byte, archive and executables:
  - **macOS** and both **Linux** targets on the Mac (the path remap should already hold; the check proves it);
  - **Windows** on the PC: one job, two scratch clones.
- **Wording:** "reproducible" is written only for a platform where the two builds are identical (ADR-0014 §4.8). Any platform that differs is named with the differing fields, as Windows is today.

**Owner inputs are not assumed.** B8 and the disposable WSL distribution are on the owner's list. This plan does not depend on either being granted: the rows they would open stay `blocked`.

## Order and what waits

1. **Now, in this order:**
   - PC job 47 (in the queue);
   - W2-4, docs;
   - W2-2's two rows;
   - W2-6, which needs one PC job and two Mac builds;
   - W2-3's harness and its rehearsals;
   - W2-5's dry run;
   - W2-1: the old build closed after round 2; defect hunting on the newest merged build when the slot is free.
2. **Before the W2 candidate gate:** merge main (M06 W5 and later) into `m08/w2`. The rehearsals
   name their build's executable digest; at the candidate the record says whether the product code
   differs from what they measured, and the benchmarks are rerun only if it does.
3. **After the contract handoff:** U0's deltas, U2b's wiring of `crates/stategen` (with H15's write-through rename), U6b, U1b, U3c, then the candidate (U3b) and its records.
4. **Gates and reviews:**
   - `check.sh` once per commit to `m08/w2`;
   - Windows and the devbox at the merge candidate;
   - one scoped re-check for W2, covering the R01 to R09 fixes and anything new.
