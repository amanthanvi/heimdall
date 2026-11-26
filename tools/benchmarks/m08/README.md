# Benchmark and soak harness (M08 U5a)

Runs a **release archive** in a container with no network and measures it from outside
(m08-plan §6; ADR-0014 §6). **Provisional, to be integrated:** version 2 covers part of the
soak's workload (it adds per-kind file sizes and lane selection to version 1) and no
dedicated benchmark yet.

| File | What it does |
|---|---|
| `Dockerfile` | `debian:13-slim` with OpenSSH, Git, Python and two unprivileged lane accounts. No toolchain |
| `run-soak.sh` | Starts one run: no network, 2 CPUs, 2 GiB, 512 processes; the repository and the archive read-only; output under `target/m08-soak/<id>/`. `--block` waits and analyzes (rehearsals); without it the run is detached (the 72-hour run only, ADR-0014 §6.6) |
| `entry.sh` | Container entry: starts one process per lane account, and a root-side sampler for descriptor counts (the runtime is non-dumpable, so its own account cannot list them) |
| `lane.sh` | Builds a lane's world as `tests/native/m02/scenario-ordinary-ssh.sh` does: a disposable key, a provider agent, a decoy agent, the fixture sshd on 127.0.0.1, `identity adopt`, `destination add`, `setup apply` with a typed yes. No test variable is set |
| `workload.py` | Per tick: `status`, `inspect capabilities`, an ordinary `ssh` login, a `heimdall connect`; samples the runtime and the account's files; applies the seeded fault schedule; writes the heartbeat; stops itself on its thresholds |
| `analyze.py` | Judges the samples against ADR-0014 §6.2, with windows scaled to the run's length. A run shorter than 72 hours is reported as a rehearsal, never as an A34 result |

**Lanes:** S (steady: the fixture sshd down, the provider agent down) and L (lifecycle: the
same, plus `service stop` and a `SIGKILL` of the runtime). While the sshd is down, a
counting listener on its port records every connection attempt, so unrequested retries are
visible.

**What version 1 does not cover** (each is named in m08-plan §6.2 and must be in the record
of any run made with it): grants with deadlines, explicit stops and expiry probes; the
managed lane; the runner lane; update and rollback; the full-volume and damaged-file
faults; an idle TUI; canary planting; and the benchmark table of spec §15.1 (100
destinations, request timing on one open session through M07's wrapper, the first TUI
frame, idle CPU). The per-tick samples carry the CLI's end-to-end times for `status`,
`inspect` and `connect`, which include process start and are not the §15.1 measures.

**Key stores (the boundary of 2026-11-22).** This harness runs only a release build, only
inside its Linux container, as accounts that exist only there. It never runs a `heimdall`
on the host, so it cannot reach the macOS login keychain, and the container holds no secret
service. The product code it runs today predates M06 and has no management or transport
key. When M06 is merged, a lane that pairs an environment or enables the transport would
use whatever store the build selects **inside the container**; it must still never be
started on the host. Any future debug-build lane (the managed or runner lane) must export
`HEIMDALL_TEST_MGMT_STORE` and `HEIMDALL_TEST_IROH_KEY_STORE` to scratch paths, alongside
`HEIMDALL_HOME`, `HOME` and `HEIMDALL_TEST_SSH_HOME`, before it starts anything.

**Machine rule:** the container is capped at 2 CPUs and takes no heavy-gate slot; run at
most one such container (soak or fuzz) at a time.

## Grant-history growth preflight

Run `bash tools/benchmarks/m08/run-soak.sh --grant-history-growth` before the
lifecycle soak. This workload uses a disposable on-disk store and the same
transactions and query methods as production. It needs Cargo and runs locally
without SSH or a container.

It adds 0, 1,000, 10,000 and 100,000 terminal grants while keeping three live
grants, two of which are due. It samples 1,000 transactions per operation at
each history size and emits JSON lines with p50 and p95 latency in nanoseconds,
the number of documents read and the number of SQLite VM instructions per
operation. Compare latency across sizes on the same machine. The workload
asserts that the row and VM counts stay constant. Timing is reported separately
because other activity on the machine can affect it. The longer release-build
lifecycle soak runs separately.

## Runs so far

| Date | Build | Length | Result |
|---|---|---|---|
| 2026-11-22 | the Linux arm64 rehearsal archive of `bd6e0f40` (`--allow-dirty`), in the Mac's Docker | 400 s, tick 8 s, seed 7 (`smoke3`) | Both lanes DONE and passed the scaled checks. 50 samples each; 4 faults each; 0 unexpected login failures; 0 unrequested connection attempts during sshd outages; the runtime came back by itself after each stop and kill; resident memory about 19 MiB; 16 descriptors. **A smoke run of the harness, not a rehearsal and not evidence** |
| 2026-11-22 13:05–15:05 UTC | the same archive (executable sha256 `79073dad…f55f`), the Mac's Docker, kernel 7.0.14-linuxkit, aarch64 | 7200 s, tick 60 s, seed 20261122 (`rehearsal1`), detached, 2 CPUs, 2 GiB, no network | **The 2-hour rehearsal. Both lanes DONE (exit 0) and passed the scaled checks; a rehearsal of the harness, not an A34 result.** Lane S: 120 samples, 10 faults, 90 logins and 90 connects ok, 30 of each failed during faults as expected, 0 unexpected; one runtime process throughout; resident memory 19.1–19.3 MiB, fitted slope 0.010 MiB/h; 16 descriptors; 3 threads. Lane L: 13 faults, 102 ok, 18 failed as expected, 0 unexpected; 8 runtime processes over the run; the runtime was back by an on-demand start after each of 7 stops and kills. 0 unrequested connection attempts in 8 sshd outages. CLI end-to-end times outside faults, P50/P95 in ms (process start included; not the spec §15.1 measures): `status` 8/17, `inspect capabilities` 13/27, `connect` 103/156 |

| 2026-11-22 20:10–22:10 UTC | the Linux arm64 archive of the `m08/w0` tree at `8f1295f4` (`main` `6a087fbb` merged; executable from archive sha256 `f60f72df…0e71a`), the Mac's Docker | 7200 s, tick 60 s, seed 20261123 (`laneS-v2`), **lane S alone, harness version 2** | Lane S DONE and passed. 120 samples, 9 faults, 93 logins and 93 connects ok, 27 of each failed during faults as expected, 0 unexpected, 0 unrequested attempts; resident memory 21.6 MiB flat. **File sizes by kind: see below** |

**Which file grew in the first rehearsal, and does it have a ceiling? (version 2's answer)**

| Kind | Start | After 20 minutes | Minutes 20 to 119 |
|---|---|---|---|
| Write-ahead log | 1,676,872 bytes | 4,120,032 | **constant at 4,120,032** |
| Database | 4,096 | 684,032 | **constant at 684,032** |
| Shared-memory file | 32,768 | 32,768 | constant |
| Logs | 2,106 | 2,106 | constant |
| Backups, other | 114; 5,584 | the same | constant |

- **It was the write-ahead log.** It grew by about 136 KiB a minute until it reached
  4,120,032 bytes, which is 1000 pages of 4,120 bytes, SQLite's default automatic checkpoint
  point. At that moment the database went from 4 KiB to 684 KiB, and from then on neither
  file changed size for the remaining 100 minutes: the log is reused in place.
- **So the growth has a ceiling within this run:** about 4.1 MB of write-ahead log plus the
  database. The first rehearsal's 1.5 MB to 4.7 MB was this fill, seen as a total. Lane L
  stayed small then because each restart of the runtime checkpoints and truncates the log.
- **What two hours cannot show:** whether the database grows over days as history
  accumulates up to the seven-day retention. Here it did not grow at all after the first
  checkpoint; the 72-hour run, with the retention shortened as ADR-0014 §6.2 item 4 says, is
  what settles that.
- Until the first checkpoint, the database file itself is one 4 KiB page and all state is
  in the write-ahead log. That is ordinary for this journal mode; it matters to anything
  that copies the database file alone (a backup or a support tool must take the family, or
  go through SQLite).

**The first rehearsal's leftover-process result is unreliable.** `rehearsal1` and the smoke
runs before it ran without an init process in the container, so a runtime that exited after
a stop or a kill could stay as a zombie, and a zombie could also have hidden a real leftover.
Nothing about leftover processes may be concluded from them. `laneS-v2` and every later run
use `--init`.

**Is the write-ahead log a backup hazard? Checked, and no defect found** (2026-11-22, the
lifecycle journey's `--kill-before-update` variant, `tests/native/m08/lifecycle/README.md`).
The migration backup is made with `VACUUM INTO` through an open connection, not by copying
the file: with the main file at 4,096 bytes, the destination only in a 1.46 MB write-ahead
log, and the runtime ended by `SIGKILL`, the backup the update made was 532,480 bytes,
passed its integrity check at schema 8, and held 7 rows naming the destination.

Two earlier smoke runs failed on harness defects, not on the product: the lane read a
pseudo-terminal transcript as one JSON document, and it identified processes through
`/proc/<pid>/exe`, which is unreadable for `ssh-agent` and for the non-dumpable runtime, so
an agent it believed stopped was still running.

## The A34 benchmark harness (W2-3)

`bash tools/benchmarks/m08/run-bench.sh --stage <staged Linux archive dir> [--id NAME]` runs the
benchmarks of spec §15.1 on a release archive in the same container (network none, 2 CPUs,
2 GiB), one capped container at a time, and writes `target/m08-bench/<id>/` (never committed).
The stage must include `BUILD-RECORD.json` and its recorded Linux executable. The runner
checks the digest before starting the container. After the container exits, `analyze.py`
writes `evidence.json` against `tests/evidence/record.schema.json`. It records the build,
platform, ADR-0014 §6.1 budgets, measurements, and the verdict for each metric. Re-run
`python3 -I tools/benchmarks/m08/analyze.py --benchmark <run-dir>` to regenerate the record.
An incomplete or failing benchmark exits 1. The current fast-work key timings are retained
as measurements, while the real slow-provider and idle polling rows remain unmeasured.
The world: 100 loopback fixture destinations, the projection applied, a profile `bench`, a
standing personal policy for it (`heimdall access allow --profile bench`, one attended `yes` on
a pty), and a trusted fixture project for the informational hook row. The host's model, CPU,
memory, OS build and power source are recorded, and its load is sampled every 30 s.

| Metric | Definition (ruled 2026-11-23 where marked) |
|---|---|
| `inspect_warm` | `inspect destinations` on one open control session, after 20 warm-up requests (spec "warm status or inspect"; process start excluded) |
| `inspect_session` | the same on a new session each time (connect, hello, request) |
| `ensure_warm` | **the spec "warm already-authorized ensure"** (ruled): one open session, the profile the standing personal policy covers, a new request ID each time, after 20 warm-up requests |
| `ensure_replay` | informational: the approved request ID replayed (answered from its record) |
| `activate_covered` | informational: `heimdall activate --hook --cwd <trusted project>` end to end, including process start |
| `cli_status`, `cli_inspect` | informational: the CLI end to end, including process start |
| `tui_first_useful_frame` | **the spec row** (ruled): spawn of `heimdall tui` on a 120x40 pty to the first screen showing the catalog counts (`<N> destinations,`) |
| `tui_first_runtime_frame` | informational: spawn to the first screen showing "listings read" |
| `key_to_frame` | in one TUI, a view key (`2`, then `1`, in turn) to the last byte before 20 ms of quiet (ruled), timed only once the reconstructed screen shows the key's effect, the selected view's title in the header (`[2 Destinations]`, `[1 Overview]`; review M08-W2-R07): output that does not show it never ends a sample, and no effect within 2 s is an error; a key whose title is already on screen before it is written is dropped (review M08-W2-RC04); both kinds are counted in `errors` and reported under `missed`; measured under **fast concurrent operations**: a second session keeps policy-covered ensures in flight for profile `slow`. They do not contact the provider (observed: P50 about 11 ms), so `agent-delay.py` is not in their path and this is **not** the slow-provider case. That case is the candidate's benchmark of record, with the managed recipe where the runtime itself signs and a slow component in its path (ruled 2026-11-23); until it exists, the go/no-go draft says "measured under fast concurrent operations; slow-provider case not measured" |
| `key_to_frame_quiet` | the same with no background work, for comparison |
| `idle` | after a settle (600 s), three 300 s windows: the runtime's CPU time as a share of one core, and its RSS. **The runtime process alone**, as the spec's rows say ("Idle runtime CPU \| < 0.5% of one logical core over a five-minute idle sample"; "Idle runtime memory \| Target ≤ 150 MiB RSS/working set; report platform measurement method", spec §15.1): its children at each window's end are named in the record (`children_not_measured`), not measured |

The TUI and key rows read a reconstructed screen (`Screen` in `bench.py`: cursor position and forward,
erase, CR, LF, text), never raw bytes: the TUI redraws only changed cells and moves the cursor
over the rest, so a raw byte search misses whole words (`listings\x1b[3;30Hread`).

Every latency metric has at least 200 samples (a floor) except the two informational CLI rows,
`cli_status` and `cli_inspect`, which take 50. Each reports P50 and P95. A run on any
build but the candidate's is a rehearsal and is labelled with its executable's digest.

**The delaying proxy relays only to a fixture agent.** `agent-delay.py`'s upstream is a plain
`ssh-agent` the run starts inside the container, holding a key generated for that run.
Before starting the proxy, `bench-world.sh` checks that the agent at the upstream holds exactly
the key generated for this run. The proxy itself refuses an upstream that, with every link
resolved, is not a socket of the calling account inside the directory named on its command line
(the run's scratch directory; `agent-delay.py self-test` shows it refusing another directory's
socket, a link out, a climb out, a sibling with the same prefix, a file and a missing path).
`bench-world.sh` refuses outside a container and with any `HEIMDALL_TEST_*` variable set, as
`lane.sh` does. The container boundary and `--network none` also keep the owner's agent
unreachable.

