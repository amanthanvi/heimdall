# Agent C questions (CLI tree, test gates, uninstall refusal)

1. **Wave-0 envelope: USAGE_ERROR (exit 2) or CAPABILITY_UNAVAILABLE (exit 4)?** Brief §2 and plan line 307 say "M01's 'not available in
   this build' envelope"; git history (d57bf7c4, `not_available_envelope`) shows M01's was `USAGE_ERROR`, effect `none`, next `fix_request`,
   exit 2, message "this command is not available in this build (planned for M02)". verify-doc E4 option (a) proposed
   `CAPABILITY_UNAVAILABLE`/`driver_unavailable`/exit 4 with different wording; api.md E4 only fixes the placement. *Built:* M01's envelope
   exactly (exit 2), message ending "(planned for M03)", built at run time in `crates/heimdall/src/m03_cmd.rs` (not in `M02_SOURCES`). One
   function (`not_available_envelope`) to change if the integrator prefers (a); `tests/e2e/cli_m03.rs` asserts code/exit/message.
2. **Reason and code of the uninstall refusal.** No reason constant fits "purge refused while enrollments remain". *Built:* `CONFIG_CONFLICT`
   (exit 6, the existing purge-refusal class), effect `none`, no `reason`, `data.enrollments[] = {marker, destination_id, state}`.
   `--keep-remote-enrollments` without `--bundle`: `CAPABILITY_UNAVAILABLE` + `bundle_required` (ADR-0008 D4 item 6, existing reason).
   With `--bundle`: the wave-0 envelope (nothing can verify freshness; U12). If the integrator wants a dedicated reason
   (e.g. `enrollments_remain`), it needs a row in `reason::M03` (contract, not mine).
3. **A state store that cannot be read** (not just older schema) refuses `--purge-state` (`CONFIG_CONFLICT`): fail closed, since the
   remaining enrollments are unknown. A pre-6 file (`OlderSchema`) means none (no table existed).
4. **`catalog_cmd.rs` (not in my paths) got one arm** (`DestinationCommand::Prefer(_) => crate::m03_cmd::not_available_outcome()`):
   the exhaustive match in `destination_flow` would not compile otherwise. `dispatch` answers `prefer` first; the arm is the fallback.
5. **`enroll --yes`** appears in plan §5 item 24's note ("`--yes` never skips the decision") but not in the command column; not added.
6. **`access ensure --strict`** is accepted by the tree and answered by the wave-0 envelope whole, before any request is built
   (`EnsureArgs.strict`; `dispatch` guard). Non-strict `ensure` is unchanged.
7. **`service run` with an M03 variable in a debug build** now enters `testcfg::prepare` (as for every variable of `requested_by`), i.e. the
   M01 fixture seeding and fake adapter apply, and the M03 values are validated; U10 wires what they select. `ALL_ENV` is unchanged
   (7 entries); `tools/validation/release-gate.sh` adds the M03 variables itself and reads only `ALL_ENV`/`LAUNCH_ENV`.
8. **Release refusal for `enroll`** is not probed by `release-gate.sh` (it probes `service run` for all four). I checked by hand that the
   release binary exits 2 for `enroll lab` with `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` set and creates nothing. Suggest T add an
   `enroll lab` probe for `HEIMDALL_TEST_SCRIPT_PAUSE_DIR`.
