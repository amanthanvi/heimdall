# Six-hour soak rehearsal (M08 W2-3, 2026-11-24)

**A rehearsal, not the A34 soak of record** (that is 72 hours on the candidate's archive). It ran
the Linux arm64 release archive of `76595543`, from before M06 W5 (executable sha256
`c5ebf788…`), in one capped container on the Mac (`hm-m08-soak:1`, network none, 2 CPUs, 2 GiB),
lanes S (steady) and L (lifecycle), seed 1, one tick a minute, from 00:05:39Z to 06:05:41Z.
Linux arm64 in a container is supplementary evidence; the native row stays blocked on B9.

**The Mac was shared.** The soak harness had no host-load sampler of its own yet, so one ran beside
it on the host (`host-load.ndjson`: the 1-, 5- and 15-minute load and free pages, every 30 s,
717 samples; the 1-minute load ranged 4.1 to 50.0, mean 10.1). `run-soak.sh` now has it built in.

## Result: both lanes pass (`analysis.txt`, from `tools/benchmarks/m08/analyze.py`)

| | Lane S | Lane L |
|---|---|---|
| Ticks | 360 | 360 |
| Logins / connects OK | 270 / 270 | 297 / 297 |
| Expected failures (during faults) | 90 | 63 |
| **Unexpected login failures** | **0** | **0** |
| Faults applied | 30 (sshd down, agent down) | 42 (also service stop, runtime kill) |
| Unrequested connection attempts | 0 | 0 |
| Recoveries on demand | 0 | 21 |
| Resident memory | peak 21.6 MiB; early and final median 21.6 MiB; slope 0.005 MiB/h | peak 21.4 MiB |
| Database | 4 KiB → 668 KiB (31.5 KiB/h) | 4 KiB → 676 KiB (29.7 KiB/h) |
| Write-ahead log | 1.6 MiB → 3.9 MiB, flat at its ceiling | peak 3.9 MiB, 0.6 MiB at the end (checkpointed) |
| Log | flat (2 KiB) | 2 KiB → 16 KiB (2.3 KiB/h) |

The database grows with operations and events under the default seven-day retention; at the
rehearsal's rate, 72 hours would add about 2.2 MiB. The 72-hour soak of record shows whether it
levels off at retention. Not covered by this harness version (the lane status says so): grants
and expiry, explicit stops, the managed and runner lanes, update and rollback, the full-volume and
damaged-file faults, an idle TUI, canaries.

Files: `host.json`, `run.json`, `end.json`, `host-end.json`, `host-load.ndjson`, `analysis.txt`,
and per lane `status.json`, `samples.ndjson` (one sample a minute), `events.ndjson`,
`root-samples.ndjson` (descriptor counts read as root).
