# Questions from T (validation tools), M03 wave 0

## Q1. How does an M03 evidence record represent "verified for that platform row"?
`tests/evidence/record.schema.json` has no platform-row field. The M02 records
(`tests/evidence/m02-exit-claims.json`, README "One record, one row per platform") use
`observed_result.rows[]`, each row `{ "platform": "macos-arm64 (build host)", "status": ... }`.
`tools/validation/claims_table.py` therefore matches a claim's `platform.os`/`platform.arch` against
`observed_result.rows` (a list, or a mapping keyed by platform) by the row's `platform` string (first
token `macos|linux|windows`; arch token `aarch64|arm64` or `x86_64|x64|amd64`), or by `os` and `arch`
keys. Fail-closed rule: at least one matching row, and **every** matching row must be `verified`.
Consequence to confirm: an M02-style record with an extra row such as `"macos-arm64 ordinary ssh without -F
(a real ~/.ssh/config)"` also matches `macos/aarch64`, so a blocked sibling row would block the claim. If
the M03 records (`m03-a03`, `m03-a07`, `m03-a23`) should instead carry an explicit per-claim marker (for
example `rows[].claims: ["lock_continuity"]`, or one row per `field`), say so and the matcher changes.
Option A (current): platform-string match, all matching rows verified. Option B: a row must name the
claimed field. Evidence: the real record check run against `m02-exit-claims.json` reports 11 non-verified
macOS-arm64 rows.

## Q2. product_store_kinds and CUSTODY_FIELDS are mirrored in the validator
`claims_table.py` keeps a mirror of `CUSTODY_FIELDS` (`["lock_continuity"]`) and `product_store_kinds`
(macos: `macos_login_keychain`, `macos_data_protection_keychain`; windows: `windows_dpapi`; linux:
`linux_secret_service`) and fails if `crates/domain/src/claims.rs` disagrees (the brief asked for read-or-mirror
with an agreement check). Adding a custody field or a store kind in Rust therefore needs the same edit in
`tools/validation/claims_table.py` (`MIRROR_*`). `scratch` and `scratch_test` are rejected for a custody claim
regardless of the Rust table.

## Q3. Registry-purity rule is covered inside an existing self-test name
The brief names exactly three crate-graph self-tests plus a positive control. The `heimdall-registry` purity
mutant (`registry -> store` rejected) is asserted inside
`crate_graph_step_rejects_cycle_and_ipc_to_app_edge` rather than under a fourth name.

## Q4. release-gate probes for the M03 variables use `service run` only
The M03 variables are expected to join `testcfg::requested()` (the `service run` gate and the TUI gate). If the
refusal instead lands in another command, add it to the probe list in `tools/validation/release-gate.sh`
(the `for v in ${service_vars}` loop). A probe passes only on exit 2 **and** the refusal text (`HEIMDALL_TEST_`
or `test configuration`) **and** an untouched scratch HEIMDALL_HOME; the M03 refusal message must keep one of
those two substrings.
