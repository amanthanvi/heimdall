# M03 wave 5 round 5 — worker L5 (late_write present, withdrawn removal; ADR-0008 §17.29 item 2)

Base `a7d5c23b`. No commits. `.m03-wave5-r5-api.md` does not exist in this worktree.

## Decisions (questions under "## L5")
- `late_write_present` → `CONFIG_CONFLICT` (exit 6) (Q-L5-1). Present = after the not-after, no
  residual lock, readable file, marker line observed (`kept_because`'s order); everything else
  stays `verification_inconclusive`. Message and CLI `data.next_command`:
  `heimdall enroll remove <id>`.
- Domain: new event `WithdrawnRemovalApproved { late_write: bool }`; `withdrawn → removing` only
  for `late_write: true`, own account form. One golden row (Q-L5-2 has the proposed D5 text).
- Admission (`admit.rs`): withdrawn + late_write only, attended only (INTERACTION_REQUIRED),
  an open late_write check superseded, any other open op refused; precheck and apply accept it;
  apply records an `enroll.remove.late_write` receipt (NotAttempted).
- Clearing (`steps.rs::removal_confirmed`): only for a removal with that receipt and with
  `verify::removal_settles_late_write` (Q-L5-3); the same transaction as the result.
- Issuing set: the CA is kept if another verified/reverifying record of the pair holds it (Q-L5-5).

## Progress
- [x] contract reason + golden + ADR-0006 §16.6 row
- [x] domain transition + unit test + transition golden
- [x] app verify/admit/steps; CLI next_command
- [x] e2e regressions (3 named + CLI next_command test), round-4 test updated
- [x] revert proofs; suites; clippy host/windows; linux-xcheck

## Commands (exit codes; umask 002 for the test runs)
- e2e_enroll_m03 (4 new/updated): 0. CLI two late-write tests: 0
- R1 verify.rs present→`kept` (inconclusive): e2e 2 FAILED exit 101; CLI FAILED 101; restored
  shasum 64775f88… = before
- R1c enroll_cmd next_command dropped: CLI FAILED 101; restored 34cf095d… = before
- R2 admit.rs = HEAD: removal test FAILED 101 (refused); restored f7eb3ae6… = before
- R3 clearing removed: removal test FAILED 101 (residual kept); restored a99a38a6… = before
- R4 admission guard without `late_write.is_some()`: refuse test FAILED 101; restored f7eb3ae6…
- R5a domain `late_write: _`: golden FAILED 101, domain unit FAILED 101; R5b arm removed: golden
  FAILED 101, removal e2e FAILED 101; restored 4b601d26… = before
- R6 issuing guard bypassed: removal test FAILED 101; restored a99a38a6… = before
- heimdall-contract tests 0 (43+90); heimdall --bins 0 (169); heimdall-domain 0 (101+21+2);
  heimdall-app --lib 0 (64); model_operations_m03 0 (37); integration_store_m03 0 (31);
  model_registry_pure 0 (17)
- e2e_enroll_m03 full 0 (76 passed); e2e_cli_m03 full 0 (62 passed, 3 ignored child entries)
- clippy host (-p domain app contract heimdall --all-targets -D warnings) 0;
  clippy-windows.sh 0; linux-xcheck.sh -p domain app contract heimdall 0
- rustfmt --check on touched files 0

## Follow-up (coordinator): §17.29 item 9 (issuing set), Q-L5-8
- Accepted: Q-L5-5 (item 9), `late_write_present` CONFIG_CONFLICT (item 8); Q-L5-8 line added
  under "## L5" (`reverifying` counts; already recorded ANSWERED as item 10 by the integrator).
- New e2e tests (tests/e2e/enroll_m03.rs, loopback sshd, real steps):
  `removing_old_enrollment_keeps_ca_while_a_newer_verified_one_trusts_it` (old abandoned whose
  uncertain append landed + newer verified; managed world; after removal the real managed path
  `managed_legs`: setup apply, ensure with fixture-issuer signing under the CA, ssh login accepted),
  `removing_withdrawn_residual_keeps_ca_while_a_newer_verified_one_trusts_it` (same, withdrawn +
  late_write seeded; residual cleared), `removing_the_last_enrollment_under_a_ca_drops_it_from_the_issuing_set`
  (store issuing set). Earlier proof: `withdrawn_with_late_write_remove_…` (store check only).
- umask 002 `-- removing_` 0 (3 passed). Guard bypassed (`|| true`): 2 keep-tests FAILED, exit
  101; restored shasum a99a38a6… = before. Never drop (`false &&`): last-enrollment test FAILED,
  exit 101; restored a99a38a6… = before; rerun 0.
- e2e_enroll_m03 full 0 (79 passed); e2e_cli_m03 full 0 (62 passed, 3 ignored child entries);
  host clippy 0; clippy-windows.sh 0; rustfmt --check 0.
