# Round 7 self-test (harness 2.4.1): orchestrator note

The harness-r4-fix agent started the full self-test at 2026-10-05T15:21Z. It
was then killed while polling, by host sleep or a T3 restart, before it could
archive the results or report. The self-test processes themselves ran to
completion:

- macOS: `SELFTEST PASS`, 136/136 observable reference mutations caught
  (race mutations excluded). `agent_reset_unhandled` is caught on Linux only.
- Linux (`tests/g02/linux/run.sh --selftest`): `SELFTEST PASS`.
  `run_mirror_nograce` is recorded as a race and is not required.

The orchestrator copied the console logs from the agent's `/tmp` work
directory. The sha256 prefixes of the harness files in the tree match
`tested-file-sha256-prefixes.txt`, which the agent wrote before the run. The
results therefore belong to the committed harness. No agent report exists
for this fix round.
