# Dev run dev-finish-race-182028 (not evidence for any record)

Development run of `e7_mux_stop_race.sh` with `G04_RACE_N=12`. The scripts then used start delays
of 0-40 ms for both the client and the stop call. Its `E7R-post-stop-clients-exercised` FAIL is the
new validity check doing its job: only 1 of 12 clients started after the `-O stop` call returned.
The stop call takes about 10 ms, so equal delay ranges rarely put a client after it. Because of
this run, the client delay range was widened to 0-60 ms (`G04_RACE_CLIENT_MAX_MS`). The follow-up
dev run `dev-finish-race2-182121` had 7 of 16 post-stop clients, and the evidence run
`20261003T182153Z` had 32 of 50. Note added 2026-10-03 by task M00-T04-G04-experiments-finish.
