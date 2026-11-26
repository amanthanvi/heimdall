# Devbox steps for U2b-1 (Linux x86-64; 2026-11-25), at `a9b038a7`

The test binaries and the debug `heimdall` were cross-built on the Mac with the zig shims, at
the glibc 2.31 floor and with the `native-test` profile, through heavy-gate.
- **Staged:** 277 MB.
- **The run:** in one `mktemp -d` scratch directory (shown as `<scratch>`), with `HOME` and
  `TMPDIR` inside it, no `SSH_AUTH_SOCK`, `nice -n 10`, and `HEIMDALL_E2E_BIN` pointing at the
  copied binary. The script is `run.sh`, and its output `run-a9b038a7.txt`.
- **Free space:** 4,282,740 KiB before (the floor was 3 GB), 4,282,684 KiB after.
- **Cleanup:** the scratch directory was removed by its exact path, and its absence was
  checked.

| Binary | Result |
|---|---|
| `heimdall-stategen` unit tests | 12 passed |
| `adversarial_stategen_switch_faults` | 18 passed |
| `adversarial_store_generations` | 5 passed, 1 filtered out (below) |
| `e2e_store_generations` | 1 passed. `older_build_on_newer_store_refuses_and_touches_nothing` against the real Linux binary; the Windows-only test is not compiled for this target |

The devbox ran the switch, pointer, adoption and write-ahead-log copy sets, including their
real kills of child processes, on Linux.

`no_test_builds_the_state_database_path_by_hand` was skipped there. It scans the repository's
`tests/` sources, which were not copied; it ran in every Mac gate.
