# U0 native runs at the candidate `85319da7`

U0 (contract revision 7, preparatory) at `85319da7539eaa4d857b2c5078749a082ed54d29`, the merge
candidate (`docs/architecture/u0-plan.md` §10). Every count below is from the run's own files in
this directory.

## Linux x86-64 (the devbox), in batches

- **Command:** `tests/native/m06/run-linux-batches.sh <artifacts_root> <linuxhost>
  linux-batch-list.txt` through `/tmp/hm-tools/heavy-gate.sh`, from a checkout of `85319da7` on the
  build host. Free-space floor 3 GiB (`HM_BATCH_FLOOR_KB` default), stage cap 1.5 GiB.
- **The batch list:** `linux-batch-list.txt`, sha256
  `79ac4e7f4ca9cb67cfcb2921e5601360cc7acd2ff1fa0dd555ab07d7a01cb71a`. It is the tree's
  `tests/contracts/native/u0-linux-batches.txt` at `85319da7` (sha256 `a399139e…`) with one line
  changed, `linux-batch-list.diff`: `b13` gains `adversarial_sshconf_block_scan`, a `[[test]]`
  target that reached `u0/rev7` from `main` after `842044c7`, the base of M06's list. The first
  attempt with the tree's list stopped at the runner's coverage check (exit 2, "planned targets in
  no batch: adversarial_sshconf_block_scan") before any host was contacted. The tree's list is
  corrected in the records commit.
- **Result:** exit 101. Plan: 142 targets in 13 batches. **4,185 passed, 2 failed, 208 ignored.**
  Free space before each batch about 5.4 GiB (5,673,376 to 5,676,740 KiB). Every batch removed its
  scratch directory on the host and checked it absent (exit 0, 13 of 13); leak scan 0 and canary 0
  in every batch; no `Failed to add the host to the list of known hosts` and no
  `Operation not permitted` in any file.

  | Batch | Exit, targets | Tests |
  |---|---|---|
  | b01 | exit 0, 12 targets | 660 passed, 0 failed, 0 ignored |
  | b02 | exit 0, 12 targets | 840 passed, 0 failed, 2 ignored |
  | b03 | **exit 101**, 7 targets | 244 passed, **2 failed**, 1 ignored |
  | b04 | exit 0, 12 targets | 377 passed, 0 failed, 173 ignored |
  | b05 | exit 0, 12 targets | 334 passed, 0 failed, 6 ignored |
  | b06 | exit 0, 12 targets | 233 passed, 0 failed, 2 ignored |
  | b07 | exit 0, 11 targets | 192 passed, 0 failed, 4 ignored |
  | b08 | exit 0, 15 targets | 467 passed, 0 failed, 0 ignored |
  | b09 | exit 0, 14 targets | 351 passed, 0 failed, 0 ignored |
  | b10 | exit 0, 9 targets | 156 passed, 0 failed, 4 ignored |
  | b11 | exit 0, 9 targets | 147 passed, 0 failed, 7 ignored |
  | b12 | exit 0, 9 targets | 115 passed, 0 failed, 3 ignored |
  | b13 | exit 0, 8 targets | 69 passed, 0 failed, 6 ignored |

- **The two failures, `blocked` (ruled 2026-11-24):** `heimdall_testkit-unit`'s
  `pinned_ssh::tests::the_built_wrapper_refuses_the_reviewers_proxy_jump` and
  `pinned_ssh::tests::the_built_wrapper_refuses_to_run_without_the_scratch_config`, each failing at
  `locate()` ("hm-pinned-ssh is not built"). Blocked on: the Linux batch harness
  (`tests/native/m02/lib.sh` `m02_artifacts`) does not stage the testkit's `hm-pinned-ssh`. The gap
  dates from M07 W7b (`ff6745a1`), after M06's list base `842044c7`. The tests pass on macOS
  (`check12` at `85319da7`) and run on Windows in PC job 60, where the program is built next to the
  test binaries: there `the_built_wrapper_refuses_to_run_without_the_scratch_config` is `ok`;
  `the_built_wrapper_refuses_the_reviewers_proxy_jump` is `#[cfg(unix)]` and so runs on macOS only. Follow-up **M07-F-PINSTAGE** (M07's): stage `hm-pinned-ssh` in the Linux harness or
  set `HM_PINNED_SSH`, then a targeted devbox run of `heimdall_testkit-unit`.
- **U0's targets, every one passing:** `heimdall_contract-unit` 68, `contracts` 135,
  `contracts_replay` 1, `heimdall_store-unit` 62, `heimdall_app-unit` 157, `heimdall-unit` 386,
  `integration_store` 77, `integration_store_m03` 36, `integration_store_m04_m05` 3,
  `integration_portable` 16, `model_setup` 52, `e2e_cli_m03` 57 (3 ignored), `e2e_cli_m05` 11,
  `e2e_environment_cli_m06` 3, and the added `adversarial_sshconf_block_scan` 4.
- **Files:** `linux/linux-batches.txt` (one `exit N:` line per floor check and batch) and
  `linux/linux-b01` to `linux/linux-b13` (each batch's `build.txt`, `commands.txt`, `host.txt`,
  `skipped.txt`, `tests.txt`, `canary-scan.txt`).

## Windows 11 x64 (PC job 60)

- **Run by the contract owner** on the PC from `docs/architecture/u0-plan.md` §10 (job file
  `pc-job-u0-85319da7.md`): `tests/native/m06/run-windows-local.ps1 -Commit 85319da7… -WslDistro
  Ubuntu`, a fresh scratch root, the clone verified at the commit (`build-commit` in `host.txt`).
- **Imported** with `tests/native/m02/import-windows-bundle.py --label u0-85319da7 --commit
  85319da7539eaa4d857b2c5078749a082ed54d29 --artifacts-root tests/evidence/artifacts/m07` into
  `windows/` (6 files, 3,626 test results; artifact digest
  `9b1211fca0c64168e827ca75afd7429e5bcb247e059f4ebcb81f916eb6d9498b`).
- **Result:** the harness exit 0 (bundle `exit: 0`). **142 binaries, every one exit 0; 3,581
  passed, 0 failed, 45 ignored** by the binaries' `test result` lines (3,569 lines end `... ok`;
  12 more end `... ok (<duration>)`). Only `windows_launch` was not run (it needs `argvdump.exe`;
  `skipped.txt`). `commands.txt`: 27 lines, every one `exit 0:`. Canary 0; `%LOCALAPPDATA%\Heimdall`
  absent before and after; the account's `.ssh` and `.gitconfig` metadata digest unchanged
  (`owner-ssh-git-before` equals `-after`); test pipes 0 before and after; no Heimdall process left.
- **Builds:** `heimdall.exe` (the CLI for the e2e suites) sha256 `9bac1478…`; the iroh-feature
  `heimdall.exe` sha256 `d6263727…` (`build.txt`).
- **U0's targets:** `heimdall_contract-unit` 68, `contracts` 135, `contracts_replay` 1 (every dump
  rebuilt and migrated on NTFS), `heimdall_store-unit` 62 (migration 0014 and the restore-epoch
  tests on a real Windows path), `integration_store` 77, `integration_store_m03` 36,
  `integration_store_m04_m05` 3, `integration_portable` 16, `model_setup` 52,
  `e2e_environment_cli_m06` 3 (`m06_help_goldens`), `adversarial_sshconf_block_scan` 4: as on
  macOS. Platform-gated, every one exit 0: `heimdall_app-unit` 155 passed and 3 ignored (the driver
  defence test among the passed), `heimdall-unit` 354 (the command-tree golden, the help lint and
  `rev7_cmd` among them), `e2e_cli_m03` 30 passed and 1 ignored (`m03_help_and_discovery_goldens`),
  `e2e_cli_m05` 2 (`m05_help_and_shell_script_goldens`).
