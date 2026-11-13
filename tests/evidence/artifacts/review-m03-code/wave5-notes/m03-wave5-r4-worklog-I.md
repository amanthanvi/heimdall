# M03 wave 5 round 4 — integrator worklog

Base `607160ff`. Binding ADR-0008 §17.28 items 3, 5, 6. No commits.
- L4: item 3 (late_write cleared by attended verify --absence after not-after observing absence).
  Owner: crates/app/src/operations/enrollment_m03*.rs (+ verify.rs), store ext_m03 (additive write in
  the same txn if needed), app/runtime/e2e tests.
- K4: items 5, 6. Owner: crates/contract/src/envelope.rs (the two reasons) + golden + ADR-0006 row,
  crates/issuer/src/**, crates/heimdall/src/{issuer_cmd*,doctor_cmd.rs}, localenv doctor (finding if
  needed), app issuer_m03.rs + runtime issuer wiring for the mapping, cli.rs issuer help text (doc
  comments only), docs note, tests.
## State
- [x] L4, K4 started (background, parallel).
- L4 done: verify --absence admitted for account-form records carrying late_write (was refused
  CONFIG_CONFLICT before contacting the remote; Q-L4-1); client-run read-only inspect step +
  registry::fence::late_write_cleared; destination clock (remote_now > not_after_remote); clear +
  settle in one txn (Txn::clear_late_write). Tests e2e_enroll_m03 x4 (any(unix,windows)), e2e_cli_m03
  enroll::enroll_verify_absence_clears_late_write_only_after_not_after (unix). Reverts 101->0.
  Q-L4-2 (verification_inconclusive for kept outcomes), Q-L4-3 (possible_late_write note says
  `enroll remove`; withdrawn can't be removed).
- Integrator (Q-L4-3, built): possible_late_write note command -> `heimdall enroll verify <id> --absence`
  (app enrollment_m03.rs) and the TUI residual line; regression
  operations::enrollment_m03::tests::late_write_note_names_the_absence_check (revert 101 -> 0);
  TUI test m03_enrollment_detail_shows_reason_next_step_and_late_write updated. No snapshot change.
  verify.rs line-present message still says `enroll remove` (left; flagged in Q-L4-3).
- K4 done: issuer_executable_changed (SERVICE_UNAVAILABLE), issuer_store_access_denied
  (CAPABILITY_UNAVAILABLE) + doctor finding issuer_store_access_denied (contract, golden, ADR-0006
  §16.6 x3); macOS errSecAuthFailed on item read (keychain unlocked) -> AccessDenied; help via
  after_help (issuer.txt, issuer-restore.txt goldens); docs/release-notes/m03-macos-ca-key-access.md.
  Regression issuer::issuer_store_access_denied_when_another_binary_reads_the_item (macOS). 7 reverts
  101->0; issuer:: 5x green. K4-Q1: restore alone can't get past the denial (old item undeletable
  without prompt, -25244) -> messages tell owner to delete the item in Keychain Access first.
  Windows/Linux unchanged (no clear equivalent).
- [x] Final validation: check.sh every step 0 (2954 passed, 0 failed, 192 ignored); linux-xcheck 0; release issuer lib 21p, release gate 3p; umask 002 all 0. Notes archived as m03-wave5-r4-*.md.
- K4-Q1 RULED (-> §17.28 item 7): restore to a new item `<environment>#r<n>` via attended
  RegisterIssuer CAS; old item listed in orphan_store_items, never deleted. Marked ANSWERED.
  Stopped the in-flight validation run (stale; no survivors). K4 resumed to build it.
- Orchestrator added F1 (Windows flake integration_projection_git
  git_first_adoption_previews_reproduce_their_plan_digest; hypothesis: 2 s LOCAL_QUERY_TIMEOUT on
  git config -> incomplete observation -> digest change). Worker F1 started (prove/disprove on Mac
  with slow-git wrapper; if confirmed raise to 10 s, diagnosable test, regression). Parallel with K4.
- K4 item-7 done: SecretStore gains defaulted `get_item(&StoreItemRef)` and `put_new_item(fp,key)`
  (defaults keep Windows/Linux unchanged); macOS `<env>#r<n>` (n<=99, attribute-only free check);
  child reads recorded locator; restore CAS via RegisterIssuer; old item never deleted, listed in
  orphan_store_items. Regression issuer::issuer_restore_after_access_denial_writes_a_new_item_and_lists_the_orphan;
  3 reverts 101->0; issuer:: 5x green (2 under umask 002). Wording "delete first" removed everywhere.
  Flag for orchestrator: two defaulted methods on `heimdall_issuer::store::SecretStore` (not app::ports).
- Q-I-R4-1 ANSWERED (-> §17.28 item 8): defaulted SecretStore methods accepted. Waiting on F1.
- F1 done: hypothesis CONFIRMED (slow 3 s `git config --global ... core.sshCommand` at 2 s ->
  `git_config_unreadable`, digest ab7ec777… vs 55760601…). LOCAL_QUERY_TIMEOUT 2 s -> 10 s;
  unreadable entry names the query + "(timed out after N ms)"; injectable bound (test-only
  ProjectionTestConfig.local_query_timeout / git_observed). Regression
  integration_projection_git git_preview_digest_is_stable_under_a_slow_git (unix); revert 101 -> 0.
  Q-F1-1 ADR-0007 l.666, l.2097, m02-plan l.811 still say 2 s (orchestrator's docs). Q-F1-2 test-only API.
- Integrator (Q-F1-3 fixed): localenv integration_doctor 4 failures under umask 002 (real ssh -G
  rejects group-writable config/includes). tests/integration/doctor.rs now writes files 0600 and
  dirs 0700 (write_owner_only / create_dir_owner_only). Revert (umask 002): 20p/4f exit 101 ->
  restored 24p exit 0, shasum OK; 24p under umask 022 too. (Round 2's "hook binary" reading was wrong.)
- [x] Final validation: check.sh every step 0 (2954 passed, 0 failed, 192 ignored); linux-xcheck 0; release issuer lib 21p, release gate 3p; umask 002 all 0. Notes archived as m03-wave5-r4-*.md.
