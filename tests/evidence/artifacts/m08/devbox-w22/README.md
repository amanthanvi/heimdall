# Devbox steps for W2.2 and W2.3 (Linux x86_64, Ubuntu, glibc 2.39; 2026-11-24)

The steps ran after the orchestrator ended the pause, in one scratch directory made by
`mktemp -d` (shown as `<scratch>`), with `HOME` and `TMPDIR` inside it, no `SSH_AUTH_SOCK`, and
`nice -n 10`.
- **What ran:** `run.sh`, over a source subset of `2215e8a0` (`git archive` of `tools`, `fuzz`,
  `tests/native/m08`, `tests/native/m02/lib.sh`, `docs` and the CLI help goldens).
- **Test binaries:** cross-built on the Mac with the zig shims, glibc 2.31 floor, `native-test`
  profile.
- **Output:** `run-2215e8a0.txt`.

| Step | Result |
|---|---|
| `heimdall-stategen` unit / fault set | 12 passed / 18 passed |
| `install-selftest.sh` | PASS |
| `provenance.py self-test` | Exit 2, "No such file or directory": the bundle lacked `Cargo.lock`, which the record test hashes. With `Cargo.lock` copied in: **0 failed** (a bundle omission, not a defect) |
| `agent-delay.py self-test` | **1 failed of 10**: "a replaced upstream socket is refused at connect time", 5 runs of 5. Linux reuses the freed inode number at once, so W2.2's (device, inode) check could not see the replacement. Adding the change time still failed 3 of 5 (ext4's coarse timestamps). Fixed in W2.3 `21e3a3ab`: the proxy pins the peer that answered at start-up (SO_PEERCRED pid and uid), and the test binds the replacement from another process. On the devbox: **0 failed of 10, ten runs of ten**. The benchmark world reached READY with the fixed proxy, its agent adopted through `slow.sock` (Mac, container, 2026-11-24) |
| `fuzz/run-campaign-selftest.sh` | PASS, 16 checks |
| `verify_artifact.py --self-test` | 49 cases, 0 failed |
| `analyze.py --self-test` | 9 cases, 0 failed |
| `docs_commands_check.py --self-test` / the check | 9 cases, 0 failed / 11 files, 0 unknown, 6 planned |

The scratch directory was removed by its exact path after the run.
