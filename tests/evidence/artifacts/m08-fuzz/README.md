# M08 fuzz campaign: extracts kept outside the Docker volume (review M08-W1-R08(d))

Copied read-only from the campaign volume `hm-m08-fuzz` on 2026-11-23, after the closing
pass, so the evidence survives `run-campaign.sh clean`. No corpus, no crash input and no
binary is kept here.

| File | What it is |
|---|---|
| `results.txt` | Every run's line as `run-campaign.sh` wrote it: target, exit code, end time (UTC), requested seconds. Runs before W2 do not record their build; from W2 each line ends with `build=<id>` (`fuzz/accounting.txt` says which earlier runs count) |
| `fuzz-lock.sha256` | The fuzz crate's `Cargo.lock` digest the campaign was built from |
| `artifacts-count.txt` | Files in each target's artifact (crash) directory: 0 for all 17 |
| `<target>.closing-extract.txt` | From the target's log of its closing run (1800 s): the `INITED` line (coverage when the corpus was loaded), the last three coverage lines, and libFuzzer's final statistics |

`control_frame` and `project_manifest` had no extract in the first copy: their logs were being
rewritten by the make-up run when it was taken.
- `project_manifest.closing-extract.txt` was added in W2.1 from that run's log (2026-11-23, ending
  14:56Z). It was copied read-only out of the volume on 2026-11-24 before the defect hunt rewrote it.
- `control_frame.closing-extract.txt` is **not raw lines**. The defect hunt's `control_frame` run
  (started 2026-11-24 09:17Z) rewrote that log before it was copied out. The file holds the
  `run-campaign.sh report` line for the round-2 run, saved on the host when it ended, and says so.

**Second copy (2026-11-24, after the defect hunt; review M08-W2-R05(f)).** Copied read-only out of
the volume after the hunt's last run ended (13:17Z):
- `results.txt`, `build-id`, `fuzz-lock.sha256` and `artifacts-count.txt` now hold every run line
  to that time (from W2, each ends with `build=`), the build identity `13453c69d123f948`, the lock
  digest and 0 artifacts on all 17 targets;
- `hunt-13453c69/`: the defect hunt on the merged build (every target 1800 s, two at a time,
  2026-11-24 08:47Z to 13:17Z). `report.txt` is the report after it; `<target>.extract.txt` are
  the closing extracts of those runs, in the format above. Every run exited 0, with no finding;
- `f1-closure.txt`: M08-W2-F1's closure checks. The corpus replay and the old artifact are
  libFuzzer's own lines (paths shown as `<volume>`). The 3600 s run's raw log was rewritten by
  the hunt, so its line is the saved report line.

`secs` in `results.txt` is the requested `-max_total_time`, in wall-clock seconds. Two
targets ran at a time in a container capped at 2 CPUs, so one wall-clock second of a target
is about one CPU-second; ADR-0014 §2.3's "CPU-hours" are counted that way.
