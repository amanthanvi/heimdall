# D3 worklog (consent, disclosures, rendering) — M03 wave 5 round 3

Goal: §17.27 items 3 (W5-S02, enroll/removal/reconcile/verify/abandon + generic decision completion),
4 enrollment half (W5-R05/S03), 9 (W5-R06); item 0 shared lock-text helper first.

## Progress
- [x] Item 0: `m03_cmd::{lock_disclosure_text, fetch_lock_disclosure_text, lock_text_unavailable}`;
  published in api "### D3" + Requests line to K3. `cargo check -p heimdall` exit 0.
- [x] Item 3 code: enroll_flow json preface = full preview; setup_cmd::confirm_and_decide +
  cli::confirm_and_decide render recorded disclosures in prose (render::recorded_disclosure_prose),
  cli generic adds render::recorded_preview(kind, request). cli::decide_flow made pub(crate) (unit test).
- [x] Item 4 code: preview(plan, lock) with runtime text; LOCK_TEXT_UNAVAILABLE never general sentence;
  confirm_and_decide refuses (exit 3, nothing sent) when lock_continuity_once and no text (approve only).
- [x] Item 9 code: destination_lines reads items|destinations.
- [x] Unit tests pass (24 enroll_cmd/output).
- [x] e2e: enroll.rs 4 new tests; access.rs item-9 assertions (capture prints removed).
- [x] output.rs `destination_list_renders_the_runtimes_items_shape` (captured real shape).
- [x] Revert proofs A–D all exit 101 reverted; restored (shasum OK); passes after.
- [x] umask 002: e2e enroll::/access:: exit 0 (22 passed); unit exit 0 (168). e2e_cli_m01 exit 0, m02 exit 0.
- [x] clippy host -p heimdall --all-targets exit 0; linux-xcheck -p heimdall exit 0; windows script exit 101
  only on K3's issuer_ceremony.rs:494 (keep-going run: no other diagnostic).
- [x] U3 request: `pub(super) mod world` done.

## Decisions
- Lock text location: `inspect capabilities` data `lock.disclosure` (app `add_capabilities_lock`).
- Sanitizer: `output::sanitize_for_terminal`.

## Commands
- `cargo check -p heimdall` exit 0 (item 0).
