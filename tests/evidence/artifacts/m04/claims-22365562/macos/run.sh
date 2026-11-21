#!/usr/bin/env bash
# M04 claims update (ruling I-28): the claim-reading reruns on macOS. The M03-F1 command set
# (tests/evidence/artifacts/m03/f1-80304f12/macos/run.sh) plus the I-28 live wiring tests and the M04-CL
# fix round's replay and classification tests (the report tests are in integration_managed_adapter,
# which runs whole). Usage: run-claims.sh <out-dir>
# (checkout root).
set -u
out=${1:?out dir}; mkdir -p "$out"
: >"$out/commands.txt"
free_ok() { local kb; kb=$(df -Pk . | awk 'NR==2{print $4}'); echo "free_kb=$kb" >>"$out/commands.txt"; [ "$kb" -ge 4194304 ]; }
run() {
  local name=$1; shift
  if ! free_ok; then echo "skipped (under 4 GB free): $name" >>"$out/commands.txt"; echo 125 >"$out/$name.exit"; return; fi
  echo "\$ $*" >>"$out/commands.txt"
  "$@" >"$out/$name.log" 2>&1; local rc=$?
  echo "$rc" >"$out/$name.exit"; echo "exit $rc: $name" >>"$out/commands.txt"
}
git rev-parse HEAD >"$out/commit.txt"
run domain cargo test --locked -p heimdall-domain --lib claims::
run localenv cargo test --locked -p heimdall-localenv --lib -- sys::tests:: local_query::tests::
run adapters-lib cargo test --locked -p heimdall-adapters --lib managed::report::
run managed-adapter cargo test --locked -p heimdall-adapters --test integration_managed_adapter
run app-r01 cargo test --locked -p heimdall-app --lib ensure_data_carries_managed_facts_only_from_this_process_outcome
run e2e-r01 cargo test --locked -p heimdall --test e2e_managed_m03 -- fresh_bind_after_reissue_never_carries_the_stored_claim_values client_replaced_while_the_driver_waits_claims_nothing
run runtime-r03 cargo test --locked -p heimdall-runtime --lib managed_store::tests::replaced_client_withholds_the_claims_until_verified_again
run runtime-i28 cargo test --locked -p heimdall-runtime --lib -- managed_store::live_tests::container::a15_container_binding_result_names_its_endpoint_kind_for_the_claim_table managed_store::live_tests::wsl_mode_b::wsl_mode_b_binding_result_names_its_endpoint_kind_for_the_claim_table managed_store::live_tests::container::a15_container_replay_of_a_pre_i28_result_withholds_its_claims managed_store::tests::claim_endpoint_is_native_only_for_the_runtimes_own_environment
run observation cargo test --locked -p heimdall-adapters --test integration_managed_adapter real_claim_table_on_this_host_recorded -- --exact --nocapture
free_ok || true
echo DONE >"$out/DONE"
