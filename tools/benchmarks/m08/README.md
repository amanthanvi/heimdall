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

**Machine rule:** start every run through `/tmp/hm-tools/heavy-gate.sh`, except a smoke run
of a few minutes.

## Runs so far

| Date | Build | Length | Result |
|---|---|---|---|
| 2026-11-22 | the Linux arm64 rehearsal archive of `bd6e0f40` (`--allow-dirty`), in the Mac's Docker | 400 s, tick 8 s, seed 7 (`smoke3`) | Both lanes DONE and passed the scaled checks. 50 samples each; 4 faults each; 0 unexpected login failures; 0 unrequested connection attempts during sshd outages; the runtime came back by itself after each stop and kill; resident memory about 19 MiB; 16 descriptors. **A smoke run of the harness, not a rehearsal and not evidence** |

Two earlier smoke runs failed on harness defects, not on the product: the lane read a
pseudo-terminal transcript as one JSON document, and it identified processes through
`/proc/<pid>/exe`, which is unreadable for `ssh-agent` and for the non-dumpable runtime, so
an agent it believed stopped was still running.
