# M03 wave 5 round 5 — integrator worklog

Base `a7d5c23b`. Binding ADR-0008 §17.29 items 2 and 6. No commits.
- [x] Item 6 (integrator): the localenv hooks are library-only (no production source outside
  crates/localenv/src references them; no HEIMDALL_TEST_* var sets them), so no binary probe can
  reach them. Added a static probe to tools/validation/release-gate.sh (counts as a probe; FAIL if any
  production source outside crates/localenv/src names observe_global_within|observe_global_for_within|
  local_query_timeout|git_observed). Proof: clean [] ; planted crates/heimdall/src/zz_hook_probe.rs ->
  detected; removed -> []. Full gate runs in check.sh.
- [x] L5 done: late_write_present (CONFIG_CONFLICT, exit 6) + golden + ADR-0006 row; domain edge WithdrawnRemovalApproved{late_write:true} withdrawn->removing (golden +1 row); attended admission; residual cleared with the removal result (only past not-after, no lock). Unrequested fix Q-L5-5: confirmed removal kept the CA in the issuing set when another verified/reverifying record uses it (also abandoned). Tests e2e_enroll_m03 x3 (any(unix,windows)), e2e_cli_m03 enroll::enroll_verify_absence_line_present_names_enroll_remove (unix). Reverts 101->0. Q-L5-2,4,6,7.
- [x] Final validation: check.sh every step 0 (2962 passed, 0 failed, 192 ignored; release-gate 26 probes incl. the new hook probe, 0 failed); linux-xcheck 0; umask 002 all 0. Notes archived as m03-wave5-r5-*.md.
- Rulings: late_write_present CONFIG_CONFLICT accepted (§17.29 item 8); Q-L5-5 accepted with own regressions (§17.29 item 9). Recorded ANSWERED. L5 to add the regressions after the running validation finishes.
- Q-L5-8 ANSWERED (-> §17.29 item 10): verified|reverifying counts. Waiting on L5's regressions.
- L5 Q-L5-5 regressions: e2e_enroll_m03 removing_old_enrollment_keeps_ca_while_a_newer_verified_one_trusts_it (real managed issuance + ssh), removing_withdrawn_residual_keeps_ca_while_a_newer_verified_one_trusts_it, removing_the_last_enrollment_under_a_ca_drops_it_from_the_issuing_set; always-drop 101 / never-drop 101 -> 0, shasum OK.
