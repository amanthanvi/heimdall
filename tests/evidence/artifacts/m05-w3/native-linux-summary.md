# M05 wave 3: native Linux run (the merge candidate)

**What ran:** `tests/native/m03/run-linux.sh <scratch> <owner's Linux host alias>`, the M03
harness, on the W3 integration tree: `27bef72a` (W2 and its fix round) plus U5, U9a, U9b, the
revision 5.2 delta, the shell-hook warm-up, the development home guard and the integrator's fixes,
uncommitted. Every binary's SHA-256 is in the scratch `build.txt`. Run 2026-11-18.

**Host** (`linux-host.txt`, redacted by the harness): Ubuntu, Linux 6.8 x86_64, OpenSSH 9.6p1,
Git 2.43.0, ext4 scratch.

**Result** (observed):
- Harness exit 0; 103 test binaries, every one `exit=0` (`linux-binaries.txt`); 3274 passed,
  0 failed, 204 ignored.
- One known skip (`linux-skipped.txt`): the compile-time repository-root test, which runs on
  the build host.
- The owner's `~/.ssh` and Git configuration digests were unchanged before and after; no
  leftover test processes; 0 canary occurrences.

**M05's targets on Linux:**

| Target | Passed |
|---|---|
| `e2e_cli_m05` (new in W3: the M05 commands, help and shell-script goldens) | 8 |
| `e2e_hook_m05` (new in W3: the hook warm-up, real `ssh` against the loopback `sshd`) | 3 |
| `e2e_dev_home_guard` (new in W3) | 2 |
| `heimdall-runtime` lib, `managed_store::live_tests::default_m05` (U5: ordinary-`ssh` activation, real `ssh` 9.6p1) | 8 |
| `integration_workspace_observe` (the real observer on ext4) | 5 |
| `e2e_context_m05` (W3 adds the inspected-proposal journey) | 8 |
| `e2e_stop_m05` | 8 |
| `model_precedence_m05` | 1 (256 cases) |
| `integration_portable` | 11 |
| `e2e_portable_m05` | 1 |
| `model_trust_policy` | 9 |
| `model_decision_budget` | 2 |
| `model_project_pure` | 40 |
| `model_slot_accounting` | 3 |
| `e2e_delegation_m05` | 4 |

The W2 run (`../m05-w2/native-linux-summary.md`) had 100 binaries and 3217 passed; the three new
binaries are `e2e_cli_m05`, `e2e_hook_m05` and `e2e_dev_home_guard`.

**Not covered here:** native Windows (the orchestrator's PC run) and macOS beyond the build host's
`check.sh`.
