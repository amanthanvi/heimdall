# Devbox steps for U2b-2 (Linux x86-64; 2026-11-25), at `065f3a45`

The test binaries and the debug `heimdall` were cross-built on the Mac in a clean checkout at
`065f3a45`, with the zig shims, at the glibc 2.31 floor and with the `native-test` profile,
through heavy-gate (`m02_cargo_build`).
- **Staged:** 441 MB.
- **The run:** in one `mktemp -d` scratch directory (shown as `<scratch>`), with `HOME` and
  `TMPDIR` inside it, no `SSH_AUTH_SOCK`, `nice -n 10`, and `HEIMDALL_E2E_BIN` pointing at the
  copied binary. The script is `run.sh`, and its output is `run-065f3a45.txt`. The devbox's
  `python3` is 3.12.3.
- **Free space:** 4,238,684 KiB before (above the 3 GB floor), 4,238,676 KiB after.
- **Cleanup:** the scratch directory was removed by its exact path, and its absence was
  checked.

| Binary | Result |
|---|---|
| `integration_request_epoch` | 10 passed: the epoch check, the ledger before the first write, the fences and their retention, a decision from an older epoch, the damaged ledger, and follow-up A's three tests (a refused role and a refused uninstall-fence admission leave the ledger byte-identical; a requester's kept old epoch is stale) |
| `e2e_request_epoch` | 4 passed, against the real Linux binary, including the wrapper case through the reference wrapper (Unix only) and `run`'s minted ID with its epoch |
| `heimdall-store` lib, `fence::` | 3 passed (62 filtered out) |
| `heimdall-stategen` unit tests | 12 passed, including the ledger's |
| `adversarial_stategen_switch_faults` | 18 passed |

The ledger's append, sync and damaged-ledger check ran on Linux ext4 there.
