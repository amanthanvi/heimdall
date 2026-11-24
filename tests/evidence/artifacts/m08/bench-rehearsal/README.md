# A34 benchmark rehearsals (M08 W2-3, 2026-11-23)

**Rehearsals, not the benchmark of record.** Both ran the Linux arm64 release archive of
`76595543`, from before M06 W5 (executable sha256 `c5ebf7884ef740b9bd4dea6d7cb514b10a27ac0375ec047020b61c74ec207b03`).
The candidate's build is measured again, and the figures here are rerun if its product code differs.
Linux arm64 in a container on the Mac is supplementary evidence: the native row stays blocked on B9.

- **Host:** Mac17,6, Apple M5 Max, 64 GiB, macOS 27.2.1 (26B131), on AC power. The Mac is shared:
  `host-load.ndjson` has the 1-, 5- and 15-minute load every 30 s (rehearsal 1: 11 to 14;
  rehearsal 2: 7.2 to 23.5).
- **Container:** `hm-m08-soak:1`, network none, 2 CPUs, 2 GiB; kernel 7.0.14-linuxkit.
- **World:** 100 loopback fixture destinations (plus `hmbslow` in rehearsal 2); a standing personal
  policy for profile `bench` made by `access allow --profile bench`, one attended `yes` on a pty.
- **Harness:** rehearsal 1 at `289c60e5`; rehearsal 2 at `41b39d46` (`host.json` records it).
  Definitions: `tools/benchmarks/m08/README.md`. 200 samples per latency row (50 for the CLI rows),
  P50 and P95, 0 errors in every row of rehearsal 2.

## Rehearsal 2 against spec §15.1

| Spec row | Measured as | P95 | Budget | |
|---|---|---|---|---|
| Warm status or inspect, 100 destinations | `inspect_warm` (one session) | 3.11 ms (P50 2.09) | ≤ 100 ms | within |
| Warm already-authorized ensure | `ensure_warm` (ruled) | 26.17 ms (P50 15.14) | ≤ 250 ms | within |
| First useful TUI frame | `tui_first_useful_frame` (the catalog counts) | 214.23 ms (P50 210.39) | ≤ 750 ms | within |
| Key handling under background operations | `key_to_frame`, under **fast concurrent operations** (615 covered ensures in flight on a second session, P50 10.28 ms; they do not contact the provider) | 0.98 ms (quiet: 1.41) | ≤ 100 ms | **not measured under slow provider work** (ruled: the candidate's benchmark of record, with the managed recipe) |
| Idle CPU, five-minute samples | three 300 s windows after a 600 s settle | 0.227 / 0.200 / 0.203 % of one core | < 0.5 % | within |
| Idle memory | `VmRSS` of the runtime, same windows | 26.5 MiB, flat; 4 threads | ≤ 150 MiB | within |

Informational rows (P95): `inspect_session` 3.53 ms; `ensure_replay` 7.15 ms; `activate_covered`
55.37 ms; `cli_status` 29.99 ms; `cli_inspect` 9.14 ms; `tui_first_runtime_frame` 109.91 ms.

Rehearsal 1 (harness `289c60e5`) measured the same rows without background work and with a TUI
marker that read raw bytes, so its TUI rows failed (0 of 200; the harness's fault, found with a
screen capture). Its other rows agree: inspect 1.13 ms, ensure 49.85 ms, idle 0.21 to 0.28 % and
25.1 MiB.
