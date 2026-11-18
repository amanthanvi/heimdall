# M05 wave 1: native Linux run (the merge candidate)

**What ran:** `tests/native/m03/run-linux.sh <scratch> <owner's Linux host alias>`, the M03
harness, on the integrated wave-1 working tree (base `1f72bb09` + U1, U2, U6, U8 and the
integrator's fixes). The tree was not yet committed; `build.txt` in the scratch artifacts holds
every binary's SHA-256. Run date: 2026-11-18.

**Host** (`linux-host.txt`, redacted by the harness): Ubuntu, Linux 6.8 x86_64, OpenSSH 9.6p1,
Git 2.43.0, ext4 scratch.

**Result** (observed): harness exit 0; 94 test binaries, every one `exit=0`
(`linux-binaries.txt`); 3177 passed, 0 failed, 204 ignored.
- **One skip** (`linux-skipped.txt`): the compile-time repository-root test, which is
  platform-neutral and runs on the build host.
- **Isolation:** the owner's `~/.ssh` and Git configuration digests were unchanged before and
  after; no leftover test processes; 0 canary occurrences (`linux-canary-scan.txt`).

**Wave 1's new targets on Linux:**

| Target | Passed |
|---|---|
| `model_project_pure` | 40 |
| `model_trust_policy` | 7 |
| `model_decision_budget` | 1 |
| `model_slot_accounting` | 3 |
| `e2e_delegation_m05` | 4 |

`heimdall_runtime-unit` (72) includes the five A28 live journeys and U6's three slot journeys
against loopback `sshd`.
