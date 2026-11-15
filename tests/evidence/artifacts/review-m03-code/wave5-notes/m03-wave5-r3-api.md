# M03 wave 5, round 3 — shared seams and ownership (integrator)

Base `a4a41d9e` (rounds 1–2 + reviews committed). Binding: ADR-0008 §17.27 items 1–10, §17.26.
Workers append what they land to their own section; cross-worker needs go under Requests.

## R1. Ownership (write only these + your worklog, questions heading, section here)
| Worker | §17.27 items / findings | Owner files |
|---|---|---|
| **U3** uninstall, inventory, fence | 1 (W5-R01, W5-R02), 2 (W5-S01); item 3 for the uninstall path | `crates/heimdall/src/uninstall_cmd.rs`; `tests/e2e/cli_m03/uninstall_doctor.rs`; `crates/store/src/ext_m03.rs` (a read-only outstanding-obligations read, additive); `crates/app/src/operations/issuer_m03.rs` and `crates/issuer/src/bundle*` / the bundle builder (the additive export fields + freshness inputs; coordinate with K3, who owns the rest of `crates/issuer`); **the contract additions items 1–2 authorize** in `crates/contract/**` (bundle additive fields, the fence request, reasons `uninstall_in_progress` (`SERVICE_UNAVAILABLE`) and `uninstall_inventory_changed` (exit 4)), goldens/schemas for them, their ADR-0006 change rows; the fence's admission gate wherever new enrollment / CA / issuance work is admitted (app `operations.rs` and `operations/*.rs` admission points — named fns only, list them in your section), `crates/runtime/src/dispatch.rs` if the request needs an arm |
| **K3** ceremonies | 5 (W5-R03), 6 (W5-R04/S04), 7 (W5-S05), 8 (W5-S06), 10 (release build), the issuer half of 4 (W5-R05/S03 + §17.26 item 6) and item 3 for the issuer ceremonies | `crates/issuer/src/**` except the bundle builder (U3); `crates/heimdall/src/{issuer_cmd.rs,issuer_cmd/**}`; `tests/e2e/cli_m03/issuer.rs`; `tests/e2e/issuer_ceremony.rs`; `tests/integration/issuer_store.rs` (the `RegisterDecision` constructor, §17.26 item 6); a new release-profile integration test for the deletion gate (name it, register it; tell the integrator the `[[test]]` entry if a Cargo.toml edit is needed) |
| **D3** consent, disclosures, rendering | 3 (W5-S02) for enroll/removal/reconcile/verify and generic decision completion, the enrollment half of 4, 9 (W5-R06) | `crates/heimdall/src/{enroll_cmd.rs,enroll_cmd/**,output.rs,m03_cmd.rs (not its test modules)}`; in `crates/heimdall/src/cli.rs` **only** `confirm_and_decide`, `decide_flow`, `ensure_flow`, `policy_flow` and helpers they call; `crates/heimdall/src/setup_cmd.rs` `confirm_and_decide`/`decided_request`; `tests/e2e/cli_m03/{enroll,access}.rs` |
| integrator | | everything else (`Cargo.toml`s, `testcfg.rs`, the parent `tests/e2e/cli_m03.rs`, docs) |

## R2. Shared seam to publish early
- **D3** publishes, as soon as it compiles, one helper both D3 and K3 use to obtain the runtime's
  conditional lock text: e.g. `m03_cmd::lock_disclosure_text(env_of_inspect_capabilities) ->
  Option<String>` (reads `capabilities.lock.disclosure`, sanitized). K3 uses it to fill
  `RegisterDecision.lock_text`. Until then K3 may code against the documented signature.
- The terminal sanitizer: use the existing one the ordinary renderers use (find it: `output.rs` /
  `tui::data::clean` / `localenv::paths::display_path`); do not write a second one. Name it in your section.

## R3. Readings
- "Interactive invocation" (item 5) = `Ctx::interactive()` (stdin is a TTY and no `--non-interactive`).
- Prompt bound = `prompt::PROMPT_TIMEOUT` (120 s) via `prompt::ask_within` (round 2) — reuse, don't fork.
- Item 3: stdout keeps exactly one envelope; the preview + disclosure prose go to stderr **whenever an
  interactive confirmation will be asked**, in `--json` mode too.

## Requests
- [K3 → integrator] **K3-R1**: register the release deletion-gate test (§17.27 item 10) in
  `crates/issuer/Cargo.toml` (after `integration_issuer_store`):
  ```toml
  # M03 wave 5, round 3 (§17.27 item 10): the release-profile deletion gate of
  # `retire::delete_awaiting` (run with and without `--release`).
  [[test]]
  name = "integration_issuer_release_gate"
  path = "../../tests/integration/issuer_release_gate.rs"
  ```
  Then `cargo test --release -p heimdall-issuer --test integration_issuer_release_gate` (3 tests)
  and the same without `--release`.
- **D3 → K3 (item 4, issuer half):** the lock-text helper is published under "### D3" and compiles: `crate::m03_cmd::lock_disclosure_text(&Envelope<serde_json::Value>) -> Option<String>` (pass the `inspect capabilities` envelope; fill `RegisterDecision.lock_text` with it) or `crate::m03_cmd::fetch_lock_disclosure_text(&mut impl cli::Session).await`. `None` ⇒ refuse to approve a decision carrying `lock_continuity_once` (exit 3; `m03_cmd::lock_text_unavailable(decision, operation)` builds the refusal envelope if you want the same wording).
- **U3 → D3 (§17.27 item 2 race regression, in `tests/e2e/cli_m03/uninstall_doctor.rs`):** please make
  the fixture module in `tests/e2e/cli_m03/enroll.rs` visible to the sibling submodule: `mod world` →
  `pub(super) mod world` (line ~186). No other change: U3 uses `World::new`, `cli`, `env`, `tx`,
  `marker_lines`, `home`, `registry_remote` and `ALIAS` (U3 brings its own pty, whose stdout is a file).
  Until it lands, U3's race test cannot compile; it is the only reference.
  - **D3:** done (`pub(super) mod world`; `e2e_cli_m03` builds, `enroll::`/`access::` 22 passed).
- **U3 → D3 and K3 (§17.27 item 1, additive bundle field):** `heimdall_contract::issuer::RecoveryBundle`
  gains `foreign_removals: Vec<BundleForeignRemoval>` (`#[serde(default, skip_serializing_if =
  "Vec::is_empty")]`: old JSON decodes, empty re-encodes byte-identically). The two struct literals in your
  files need one line `foreign_removals: Vec::new(),`: **D3** `crates/heimdall/src/enroll_cmd.rs` test
  helper `bundle()` (~917); **K3** `tests/integration/issuer_store.rs` `bundle_with` (~1082). `StoreView`
  and `export` are unchanged (U3 adds `bundle::export_with_foreign`), so no other literal changes.
  - **D3:** nothing needed: `enroll_cmd::tests::bundle()` decodes JSON (serde default), no literal; its test passes.
- **D3 → K3:** `tests/e2e/issuer_ceremony.rs:494` `exits_within` is dead code on `x86_64-pc-windows-gnu`
  (`-D dead-code`): `bash tools/validation/clippy-windows.sh` exit 101 on that target alone (with
  `--keep-going` every other `heimdall` target is clean).
- **D3 → U3:** `tests/e2e/cli_m03/uninstall_doctor.rs:288` does not compile (`RecoveryBundle` is missing `foreign_removals`), which blocks every `e2e_cli_m03` build, D3's `enroll::`/`access::` runs included (persisting > 10 min).
  - **U3:** fixed (the literal has `foreign_removals`; `e2e_cli_m03` builds: `cargo test -p heimdall --test e2e_cli_m03 uninstall_doctor::` exit 0). Sorry for the window.
- [K3 → integrator] **K3-R2**: `./target` is 85 GB (`debug` 52 G, `x86_64-unknown-linux-gnu` 31 G,
  `x86_64-pc-windows-gnu` 2.4 G). K3 did not prune shared dirs while other workers build; prune the
  cross-target dirs after the round (the scripts' own advice).
## Worker sections
### U3
- **Landed (compiles; host clippy, clippy-windows, linux-xcheck exit 0):**
  - store `Txn::outstanding_obligations() -> OutstandingObligations { enrollments, foreign_removals,
    operations: Vec<OpenEnrollmentOperation> }` (read-only; `heimdall_store::{OutstandingObligations,
    OpenEnrollmentOperation}`): non-final enrollments + any with `late_write`; non-final foreign removals;
    open/`outcome_unknown` `enrollment.*` operations.
  - contract: `issuer::BundleForeignRemoval`, `RecoveryBundle.foreign_removals` (additive);
    `request::UninstallFenceRequest::{Acquire, Release}` as `Request::UninstallFence` (`service-control/1`,
    synchronous); reasons `UNINSTALL_IN_PROGRESS` (SERVICE_UNAVAILABLE), `UNINSTALL_INVENTORY_CHANGED`
    (CAPABILITY_UNAVAILABLE, exit 4). Goldens: `m03-reasons`, `journaled-kinds`; schemas `request`,
    `ipc.client-message`, `recovery-bundle` regenerated (additions only); `tests/contracts/m02.rs` samples.
    ADR-0006 §16.6.
  - bundle: `app::issuer::bundle::export_with_foreign(view, foreign, redact)` (`export` unchanged);
    `issuer.bundle` exports the outstanding foreign removals.
  - fence (⟨§17.28 item 1⟩ widened): state in `app/src/operations/uninstall_fence_m03.rs`
    (`Inner.uninstall_fence`); `Operations::{uninstall_fence_acquire(conn), uninstall_fence_release(conn),
    uninstall_fence_holder(), uninstall_fence_held(), uninstall_fence_admission()}`,
    `operations::{as_fence_holder, uninstall_in_progress, unresolved_remote_steps}`. **Gate:** the
    dispatcher (`runtime::dispatch::fenced` + `ConnectionScope`): a fenced request from a non-holder holds
    the shared admission guard from the check to the end of its handling (so `acquire`'s ≤ 20 s drain
    covers it); the holder's requests run in `as_fence_holder` and are never refused. App-side checks
    only for work no request carries: `reserve_issuance_with` (`fence_check`, holder scope exempt),
    `reverify_pass`, `managed_reissue_pass` (skip while held).
  - **Request → verdict while another connection holds the fence** (refused = `SERVICE_UNAVAILABLE` /
    `uninstall_in_progress`, effect `none`, nothing written; the holder gets every row as "allowed"):

    | Request | Verdict |
    |---|---|
    | `enrollment` `apply`, `verify`, `remove` (own and foreign), `reconcile`, `abandon`, `step` | refused |
    | `enrollment` `preview` | allowed (read-only) |
    | `enrollment` `step_result` | allowed (a step dispatched before the fence records its truth; no new step can be dispatched) |
    | `issuer` `register` (incl. rotation, restore), `unlock`, `retire` (incl. `deleted_locator` confirmation) | refused |
    | `issuer` `status`, `bundle` | allowed (read-only) |
    | `issuer` `bundle_written` | allowed (records a bundle digest; no remote or CA work) |
    | `decide` `approve` (any kind) | refused |
    | `decide` `deny` | allowed |
    | `ensure`, `bind`, `delegate` | allowed at dispatch; any certificate they need is refused at the reservation |
    | `inspect`, `observe`, `cancel`, `release`, `revoke`, `policy`, `confirm_time`, `setup`, `catalog`, `connections`, `shutdown` | allowed |
    | `uninstall_fence` `acquire` | refused (`uninstall_in_progress`); `release` from a non-holder: no-op |
    | an unknown `enrollment`/`issuer` action | refused (fail closed) |
  - revalidation (⟨§17.28 item 1⟩): under the fence a `--purge-state` with any enrollment operation whose
    journal has `outstanding` (dispatched, no result) or `uncertain` (effect unknown) refuses
    `uninstall_remote_step_unresolved` (CAPABILITY_UNAVAILABLE, exit 4; `data.unresolved_steps`,
    `next_command`), lifts the fence, deletes nothing. ADR-0006 §16.6 row 4; reasons golden.
  - uninstall: inventory = all obligations (listing keys `enrollments` [+`late_write`],
    `foreign_removals`, `enrollment_operations`); guard/ack/bundle check count all; one session with
    `service-control/1`: fence acquired after the typed confirmation, inventory + bundle revalidated
    (exit 4 `uninstall_inventory_changed`, `data.next_command`), Shutdown on the same session, last
    obligations check after the stop before deleting. Sanitizer: prompts go through
    `output::prompt` → `output::sanitize_for_terminal`.
- **Tests:** `uninstall_doctor::{uninstall_purge_refuses_abandoned_foreign_system_form_removal,
  uninstall_purge_refuses_withdrawn_late_write, uninstall_json_shows_the_preview_on_the_terminal (unix),
  uninstall_purge_race_with_concurrent_enrollment_keeps_state (unix)}`; `uninstall_cmd::tests::{same two
  names, a_bundle_lists_outstanding_foreign_removals_and_late_writes, uninstall_revalidates_under_the_fence}`;
  `heimdall-app operations::uninstall_fence_m03::tests::{uninstall_fence_checks_work_no_request_carries,
  uninstall_fence_acquire_waits_for_admissions_in_progress,
  unresolved_remote_steps_lists_dispatched_and_uncertain_steps}`; `heimdall-runtime dispatch::tests::
  {uninstall_fence_is_held_by_its_connection, uninstall_fence_refuses_remote_and_ca_work_from_other_connections,
  uninstall_fence_needs_the_owner}`; e2e (unix) `uninstall_doctor::{uninstall_purge_refuses_unresolved_remote_step,
  uninstall_fence_scope_end_to_end}`;
  `contract issuer::tests::bundle_foreign_removals_are_additive`, `request::tests::uninstall_fence_wire_forms`.
### K3
- **Landed, compiles, tests pass (macOS arm64).**
  - `heimdall_issuer::ceremony`: `ControllingTerminal::open(prompt_timeout: Duration)` (**signature
    change**; the CLI passes `prompt::PROMPT_TIMEOUT`, no second constant). Each read runs on its own
    thread on a cloned handle, bounded; a timeout spends the terminal (later reads `TimedOut`, a late
    `yes` is dropped). Additive `Tty::read_answer(hidden) -> io::Result<TtyRead>` (`Line | Eof |
    Cancelled | TimedOut`; `Debug` never shows a line), default over `read_line`/`read_hidden`, so
    existing fakes are unchanged. `confirm`: only a typed line can be a wrong answer; Eof/Ctrl-C/
    timeout → `NotConfirmed` at once; `show_passphrase` clears the region on every exit.
  - `RegisterDecision.lock_text: Option<String>` (§17.26 item 6). A decision with
    `lock_continuity_once` and no (or blank) lock text, or an unknown kind, is shown without it and
    refused before any question: new `CeremonyError::DisclosureUnavailable` (`INTERACTION_REQUIRED`,
    exit 3; CLI answer = D3's `m03_cmd::lock_text_unavailable(decision, None)`).
  - CLI `issuer_cmd/session.rs`: `!ctx.interactive()` refused right after argument checks, before
    `test_config`, the terminal, connect, attend or the store (exit 3, effect none). The ceremony
    terminal is `SanitizedTerminal`: every `write_text` through **`output::sanitize_for_terminal`**
    (zeroizing copy), only `clear_lines` raw. `WireSession::register` fetches `inspect capabilities` when
    the decision carries `lock_continuity_once` → `m03_cmd::lock_disclosure_text`; an unparseable
    `disclosures` list is refused (exit 3), never shown as none.
  - `retire.rs` test: per-profile `#[cfg(debug_assertions)]` blocks (item 10). New
    `tests/integration/issuer_release_gate.rs` (needs **K3-R1** `[[test]]`).
  - `tests/integration/issuer_store.rs`: `lock_text: None` in the fake's `RegisterDecision`;
    `foreign_removals: Vec::new()` in `bundle_with` (U3's request).
- **Round 3 follow-up: the `issuer_store_locked` flake, root-caused.** Not a lock: the item's access
  list is built by `SecTrustedApplicationCreateFromPath(NULL)`, which reads the code **at the
  program's path on disk**. A concurrent `cargo` build replacing the shared `target/debug/heimdall`
  mid-ceremony made the item trust the new file; the CLI's own read-back (`get` after `put`) then got
  `errSecAuthFailed` (-25293, interaction off) → `InteractionNotAllowed` → `issuer_store_locked`, with
  an orphan item. Product fix: `sys::add_generic_password_trusting_self` refuses before writing unless
  the running code satisfies the trusted app's requirement (`SecTrustedApplicationCopyRequirement` +
  `SecCodeCopySelf` + `SecCodeCheckValidity`) → new `StoreError::ExecutableChanged` →
  `SERVICE_UNAVAILABLE` (K3-Q2). Fixture fix: each `Rig` in `tests/e2e/cli_m03/issuer.rs` runs a
  private snapshot of the binary (`Rig::program`; CLI cases, `rig.cli`, the issuer child, testkit
  ceremony). Regression `issuer::issuer_init_refuses_when_its_executable_is_replaced_mid_ceremony`.
- **Retire's typed confirmation** is the ordinary `setup_cmd::confirm_and_decide` (stdin, `ask_within`,
  `ctx.interactive()` already checked) — not a ceremony read; unchanged.
- **Item 3 (ceremonies):** the ceremony always writes the preview and every disclosure to the
  controlling terminal before asking, whatever `--json`; asserted under `--json` by the two lock tests.
### D3
- **Item 0 (api R2) — landed, compiles (`cargo check -p heimdall` exit 0):** in `crates/heimdall/src/m03_cmd.rs`:
  ```rust
  pub(crate) fn lock_disclosure_text(capabilities: &Envelope<serde_json::Value>) -> Option<String>;
  pub(crate) async fn fetch_lock_disclosure_text<S: crate::cli::Session>(s: &mut S) -> Option<String>;
  pub(crate) fn lock_text_unavailable(decision: Option<&str>, operation: Option<OperationId>) -> Envelope<serde_json::Value>;
  ```
  Reads `data.lock.disclosure` of an `inspect capabilities` answer; sanitized with the ordinary renderers'
  sanitizer **`crate::output::sanitize_for_terminal`** (the TUI's `tui::data::clean` delegates to it), trimmed;
  `None` for a refusal, an absent `lock`, a non-string, or empty text. `lock_text_unavailable` = the exit-3
  `not_confirmed` envelope ("the runtime's lock disclosure could not be read …"), nothing sent.
- **Items 3, 4 (enrollment), 9 — landed.** `setup_cmd::confirm_and_decide` (enroll, removal, verify, and
  U3's/catalog's callers) and `cli::confirm_and_decide` (generic `decision approve|deny`, `ensure`, `policy`)
  now print every disclosure of the recorded request in words before the prompt
  (`enroll_cmd::recorded_disclosure_prose`), and refuse to **approve** one carrying `lock_continuity_once`
  without the runtime's lock text (exit 3, no `decide`). Generic completion also prints the recorded
  enrollment/removal/target-change in human form (`enroll_cmd::recorded_preview`). `--json enroll` puts the
  full preview at the head of the prompt. `render::disclosure_text(kind, alias, lock)` never shows the general
  lock sentence (absent text ⇒ `LOCK_TEXT_UNAVAILABLE`). `output::destination_lines` reads `items`
  (and `destinations`). `cli::decide_flow` is now `pub(crate)` (unit-tested from `enroll_cmd::tests`).
