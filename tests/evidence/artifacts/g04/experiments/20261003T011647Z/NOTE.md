# Run 20261003T011647Z: interrupted, superseded

This run is **incomplete** and is kept unchanged as history. It is superseded by run
`20261003T182153Z` (same directory level), which produced the `tests/evidence/g04-exp-*.json`
records.

What the files in this directory show (observed, from `exit-codes.txt`,
`e7_mux_after_expiry.stdout.txt`, `e7-mux-after-expiry.results.tsv` and `/tmp/hmg04-final-runall.out`):

- `run_all.sh` started at 2026-10-03T01:16:47Z. E1–E6 and `enroll_marker_key` exited 0.
- `e7_mux_after_expiry.sh` received SIGTERM at 2026-10-03T01:28:42Z. Its stdout shows
  `Terminated: 15`, then the script's `interrupted` handler. It exited 3 after Phase 3(b2), so
  H2c, H2d, Phase 4, H3 and H3b were never observed. The SIGTERM most likely came from the
  ending session of the agent that launched the run (inferred, not observed). The cleanup
  handler terminated its master and agent by exact PID and removed the temp dir
  (`CLEANUP` rows).
- `run_all.sh` itself did not continue: `exit-codes.txt` has no `e7_mux_after_expiry` or
  `e7_mux_stop_race` line, `run.env` has no `finished_at`, and `e7_mux_stop_race.sh` never ran.
- No `tests/evidence/g04-exp-*.json` record was generated from this run.

The scripts changed after this run (see `script-sha256.txt` here versus the superseding run).
Changes: discriminating rejection checks in E3/E4/E5, an E4 seed-only `ops` control, the E2
"certificate no longer in the agent" comparison, an E2 boundary-check fix (perl parsed a
negative number argument as a switch), and the race delay range and post-stop validity check.
So results here are not directly comparable row for row.

Note added 2026-10-03 by task M00-T04-G04-experiments-finish.
