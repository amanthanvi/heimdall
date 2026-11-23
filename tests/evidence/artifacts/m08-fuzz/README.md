# M08 fuzz campaign: extracts kept outside the Docker volume (review M08-W1-R08(d))

Copied read-only from the campaign volume `hm-m08-fuzz` on 2026-11-23, after the closing
pass, so the evidence survives `run-campaign.sh clean`. No corpus, no crash input and no
binary is kept here.

| File | What it is |
|---|---|
| `results.txt` | Every run's line as `run-campaign.sh` wrote it: target, exit code, end time (UTC), requested seconds. The runs do not record their tree (W2 adds that) |
| `fuzz-lock.sha256` | The fuzz crate's `Cargo.lock` digest the campaign was built from |
| `artifacts-count.txt` | Files in each target's artifact (crash) directory: 0 for all 17 |
| `<target>.closing-extract.txt` | From the target's log of its closing run (1800 s): the `INITED` line (coverage when the corpus was loaded), the last three coverage lines, and libFuzzer's final statistics |

`control_frame` and `project_manifest` have no extract here: their logs were being
rewritten by the make-up run when this copy was taken. Their extracts are added with the
records of that run.

`secs` in `results.txt` is the requested `-max_total_time`, in wall-clock seconds. Two
targets ran at a time in a container capped at 2 CPUs, so one wall-clock second of a target
is about one CPU-second; ADR-0014 §2.3's "CPU-hours" are counted that way.
