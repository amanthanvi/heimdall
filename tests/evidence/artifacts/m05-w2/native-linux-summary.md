# M05 wave 2: native Linux run (the merge candidate)

**What ran:** `tests/native/m03/run-linux.sh <scratch> <owner's Linux host alias>`, the M03
harness, on the W2 integration tree: `931065e1` (W1, its fix round and the Windows UNC fixture fix)
plus U3, U4, U7, the revision 5.1 draft and the integrator's fixes, uncommitted. Every binary's
SHA-256 is in the scratch `build.txt`. Run 2026-11-18.

**Host** (`linux-host.txt`, redacted by the harness): Ubuntu, Linux 6.8 x86_64, OpenSSH 9.6p1,
Git 2.43.0, ext4 scratch.

**Result** (observed):
- Harness exit 0; 100 test binaries, every one `exit=0` (`linux-binaries.txt`); 3217 passed,
  0 failed, 204 ignored.
- One known skip (`linux-skipped.txt`): the compile-time repository-root test, which runs on
  the build host.
- The owner's `~/.ssh` and Git configuration digests were unchanged before and after; no
  leftover test processes; 0 canary occurrences.

**M05's targets on Linux:**

| Target | Passed |
|---|---|
| `integration_workspace_observe` (the real observer on ext4) | 5 |
| `e2e_context_m05` | 7 |
| `e2e_stop_m05` | 7 |
| `model_precedence_m05` | 1 (256 cases) |
| `integration_portable` | 11 |
| `e2e_portable_m05` | 1 |
| `model_trust_policy` | 8 |
| `model_decision_budget` | 2 |
| `model_project_pure` | 40 |
| `model_slot_accounting` | 3 |
| `e2e_delegation_m05` | 4 |

A targeted run of the W2 targets earlier the same day, before the revision 5.1 delta: 12 binaries,
141 passed, 0 failed.
