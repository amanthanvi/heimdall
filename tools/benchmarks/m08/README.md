# Benchmark and soak harness (M08 U5a)

Runs a **release archive** in a container with no network and measures it from outside
(m08-plan §6; ADR-0014 §6). **Provisional, to be integrated:** version 1 covers part of the
soak's workload and no dedicated benchmark yet.

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

## Runs so far

| Date | Build | Length | Result |
|---|---|---|---|
| 2026-11-22 | the Linux arm64 rehearsal archive of `bd6e0f40` (`--allow-dirty`), in the Mac's Docker | 400 s, tick 8 s, seed 7 (`smoke3`) | Both lanes DONE and passed the scaled checks. 50 samples each; 4 faults each; 0 unexpected login failures; 0 unrequested connection attempts during sshd outages; the runtime came back by itself after each stop and kill; resident memory about 19 MiB; 16 descriptors. **A smoke run of the harness, not a rehearsal and not evidence** |
| 2026-11-22 13:05–15:05 UTC | the same archive (executable sha256 `79073dad…f55f`), the Mac's Docker, kernel 7.0.14-linuxkit, aarch64 | 7200 s, tick 60 s, seed 20261122 (`rehearsal1`), detached, 2 CPUs, 2 GiB, no network | **The 2-hour rehearsal. Both lanes DONE (exit 0) and passed the scaled checks; a rehearsal of the harness, not an A34 result.** Lane S: 120 samples, 10 faults, 90 logins and 90 connects ok, 30 of each failed during faults as expected, 0 unexpected; one runtime process throughout; resident memory 19.1–19.3 MiB, fitted slope 0.010 MiB/h; 16 descriptors; 3 threads. Lane L: 13 faults, 102 ok, 18 failed as expected, 0 unexpected; 8 runtime processes over the run; the runtime was back by an on-demand start after each of 7 stops and kills. 0 unrequested connection attempts in 8 sshd outages. CLI end-to-end times outside faults, P50/P95 in ms (process start included; not the spec §15.1 measures): `status` 8/17, `inspect capabilities` 13/27, `connect` 103/156 |

**An observation from the rehearsal to follow up, not a finding yet:** lane S's files grew
from 1.5 MB to 4.7 MB in two hours (about 1.6 MB per hour) with the file count constant at
17, while lane L, whose runtime restarts, stayed at 1.5 MB. Version 1 records only the
total, so it cannot say whether that is the log, the database or its write-ahead log, and
its analysis checks the file count, not the bytes. Version 2 must sample those three
separately and apply ADR-0014 §6.2 item 4 to them; a write-ahead log that is only
truncated at restart would matter for a runtime that runs for weeks.

Two earlier smoke runs failed on harness defects, not on the product: the lane read a
pseudo-terminal transcript as one JSON document, and it identified processes through
`/proc/<pid>/exe`, which is unreadable for `ssh-agent` and for the non-dumpable runtime, so
an agent it believed stopped was still running.
