# M03 wave 4, round 5: questions

## Y-S
## Y-C
## Y-W
- **Y-W-Q1 (scope, recorded; no decision needed unless you object):** root cause 1 is in
  `crates/app/src/operations/enrollment_m03/steps.rs` `foreign_image` (the foreign removal's endpoint was the
  raw catalog locator, `\\.\pipe\<name>` on Windows, never the plan's rendered `//./pipe/<name>`), and the
  foreign admission in `admit.rs` disclosed its invocation from the same raw locator (empty on Windows). Neither
  file is in my row's listed files nor in Y-S/Y-C's regions; I changed only those two spots (+ a helper in
  `crates/app/src/enrollment.rs`, and `heimdall_registry::plan::catalog_endpoint`, step 8's rule made public).
  The host check (`endpoint_valid`) is unchanged.
- **Y-W-Q2 (behaviour, fail-closed):** a foreign removal whose local identity records an endpoint that is
  **not concrete** (relative, `..`, `SSH_AUTH_SOCK`, empty pipe name) is now refused at admission with
  `existing_access_endpoint_unrecorded` (as `plan::build` step 8 refuses it for an own enrollment), instead of
  being approved and then failing at its first step. Please confirm this reading.
