# Dev run dev-finish-e2-181350 (not evidence for any record)

Development run of the modified `e2_cert_expiry.sh` against the previous (still running)
fixtures, with `G04_E2_LEAD=30`. Its `E2-boundary` FAIL is a **harness defect**, not an
OpenSSH observation. The boundary data were consistent with the criterion: 146 attempts,
accepted=76, rejected=70, first rejection started 0.011 s before valid_before and ended after
it, none accepted after valid_before, and all 70 rejections were logged as expired. The final
`perl -e '...' "$ffs" "$lim"` comparison received `-0.011`, which perl parsed as a command-line
switch, so it exited 25 ("Unrecognized switch").

The fix adds `--` before the arguments of every `perl -e` call that can receive a negative
number (`e2_cert_expiry.sh`, `lib.sh` clock_offset, `e7_mux_stop_race.sh`). The superseding
evidence run is `20261003T182153Z`. Note added 2026-10-03 by task
M00-T04-G04-experiments-finish.
