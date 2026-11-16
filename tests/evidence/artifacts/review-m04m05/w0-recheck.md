merge

# Scoped Re-Check: Joint Wave 0 of M04 and M05 (`a4bcf6c3..e4a0368e`)

- **Checked out commit:** `e4a0368ee23efe4851ad5be4e058a476fc6b43ac` (detached `HEAD`, `origin/m04m05/w0-r2`)
- **Diff under re-check:** `git diff a4bcf6c3..e4a0368e` (against original review [tests/evidence/artifacts/review-m04m05/w0.md](tests/evidence/artifacts/review-m04m05/w0.md))
- **Rules checked:** ADR-0011 §10 item 1, ADR-0006 §17.2 item 2 & §17.6 items 7 and 9 (`R5-Q7`, `R5-Q9`), ADR-0009 §2.1
- **New findings:** None (`W0-C*` = 0). All four original findings (`W0-R01`..`W0-R04`) are correctly and completely fixed.

---

## 1. Correctness and Completeness of Each Fix (with Probes and Exit Codes)

### W0-R01 (was blocking) — Fixed and Complete
- **Fix:** [`with_lock_and_connection`](crates/app/src/operations/lock_connection_m03.rs#L124-L147) now resolves `context = crate::policy_context::grant_context(Some(&origin))` and loads `policies = crate::policy_context::policies_in(tx, &origin.profile, environment, &context)?` (which filters via `heimdall_domain::policy::applicable_policies`). Both `merged_policy(&policies, &context)` and `crate::lock::origin_behavior(&policies, floor)` consume that context-filtered slice.
- **Completeness:** The only two callers of `with_lock_and_connection` are [`crates/app/src/operations.rs:6420`](crates/app/src/operations.rs#L6420) and [`crates/app/src/operations.rs:7079`](crates/app/src/operations.rs#L7079) (both inside `drive_work`'s `GrantOrigin` creation). Under `applicable_policies`, a personal grant (`PolicyContext::Personal`) sees only personal policies; a workspace grant (`PolicyContext::Workspace(w)`) sees workspace `w` plus personal policies (so a stricter personal `RevokeOnLock` applies to workspace work, while another workspace `w'` never reaches it or personal work).
- **Probes (exit code `0`):**
  - Permanent regression [`w0_r01_workspace_lock_behavior_never_reaches_a_personal_grant`](tests/model/operations.rs#L16096-L16131) via `cargo test --locked -p heimdall-runtime --test model_operations w0_` → **exit 0** (5 passed).
  - Equivalent temporary probe `w0_recheck_probe_isolation_and_inspect_gates` (subsequently reverted cleanly) also verified the attended `decide` approval path (`operations.rs:7079`) ignores workspace `RevokeOnLock` (`origin.lock_behavior == None`, `effective_lock_behavior_of == Some(Continue)`): `cargo test --locked -p heimdall-runtime --test model_operations w0_recheck_probe` → **exit 0** (1 passed).

### W0-R02 — Fixed and Complete
- **Fix:** [`Operations::applicable_policies`](crates/app/src/lock.rs#L411-L425) now reads `crate::policy_context::environment_level_policies(tx, &profile.id, &env)?` (`PolicyContext::Personal` only), deduplicates, and sorts by ID.
- **Completeness:** All callers (`lock_disclosure` at [`crates/app/src/lock.rs:440`](crates/app/src/lock.rs#L440), `pending_lock_disclosure` at [`crates/app/src/lock.rs:459`](crates/app/src/lock.rs#L459), `add_capabilities_lock` at [`crates/app/src/operations/lock_connection_m03.rs:252`](crates/app/src/operations/lock_connection_m03.rs#L252), and `label_capabilities_lock` at [`crates/app/src/operations/lock.rs:198`](crates/app/src/operations/lock.rs#L198)) use this helper, so neither lock disclosure nor `inspect capabilities` surfaces workspace policies or workspace-triggered `signal_unverified` warnings.
- **Probes (exit code `0`):**
  - Permanent regression [`w0_r02_lock_disclosure_reads_only_personal_policies`](tests/model/operations.rs#L16137-L16154) via `cargo test --locked -p heimdall-runtime --test model_operations w0_` → **exit 0**.
  - Equivalent temporary probe `w0_recheck_probe_isolation_and_inspect_gates` additionally verified `w.ops.inspect(InspectSubject::Capabilities)` with `LockSignal::LinuxLogind` and a `RevokeOnLock` workspace policy returns `behavior: "continue"` with empty `warnings` → **exit 0**.

### W0-R03 — Fixed and Complete
- **Fix:**
  - [`Operations::delegate`](crates/app/src/operations.rs#L9856-L9906) reads `tx.binding(&pb)?.filter(|b| may_act_on(b, &ctx))` and calls `crate::environments::admit(tx, &own, &environment)?` inside the read/admission check before `compute_hash` or `self.run_work`, returning `NotFound` (`environment_removed` for `Removed`/`Gone`, no reason for unmanaged/foreign binding) with zero database writes.
  - `Operations::delegate` computes `hash` with `environment: &parent_environment` and passes `parent_environment` to `run_work`.
  - [`WorkSpec::from_request`](crates/app/src/operations.rs#L4163-L4191) uses the `environment` parameter (`&st.op.environment` in [`drive_work`](crates/app/src/operations.rs#L6167) and `&op.environment` in [`equivalent_waiting`](crates/app/src/operations.rs#L4626)) for `Request::Delegate`.
- **Probes (exit code `0`):**
  - Permanent regressions [`w0_r03a_delegate_in_a_removed_environment_writes_nothing`](tests/model/operations.rs#L16220-L16250) and [`w0_r03b_equal_delegations_in_a_managed_environment_coalesce`](tests/model/operations.rs#L16255-L16299) via `cargo test --locked -p heimdall-runtime --test model_operations w0_` → **exit 0**.

### W0-R04 — Fixed and Complete
- **Fix:**
  - [`InspectRequest::uses_m05_form`](crates/contract/src/request.rs#L443-L445) returns `self.subject.is_m05() || self.cwd.is_some() || self.redact`.
  - [`Request::required_capability`](crates/contract/src/request.rs#L1486-L1521) gates:
    - `Request::Catalog(CatalogRequest::ApplyImport { .. })` → `Some(TRUSTED_WORK_V1)`
    - `Request::Catalog(CatalogRequest::UpsertDestination { destination, .. })` with `Managed { jump: Some(_), .. }` → `Some(ENVIRONMENTS_V1)`
    - `Request::Setup(SetupRequest::Preview { intent })` when `intent.uses_m04_form()` → `Some(ENVIRONMENTS_V1)`
    - `Request::Inspect(r)` when `r.uses_m05_form()` → `Some(TRUSTED_WORK_V1)`
  - [`crates/ipc/src/session.rs:863-870`](crates/ipc/src/session.rs#L863-L870) refuses unnegotiated `required_capability()` with `Code::SchemaUnsupported` before dispatch.
  - [`Operations::inspect`](crates/app/src/operations.rs#L8815-L8821) checks `if req.uses_m05_form()` at entry before any time or store read, refusing `CAPABILITY_UNAVAILABLE` (`driver_unavailable`).
- **Probes (exit code `0`):**
  - Contract regression [`rev5::rev5_capabilities_declared_not_offered_and_required`](tests/contracts/rev5.rs#L244-L287) via `cargo test --locked -p heimdall-contract` → **exit 0** (45 unit + 95 `contracts`).
  - Equivalent temporary probe `w0_recheck_probe_isolation_and_inspect_gates` additionally verified `w.ops.inspect` refuses `Inspect { subject: Capabilities, cwd: Some("/tmp"), redact: false }` and `Inspect { subject: Capabilities, cwd: None, redact: true }` with `Code::CapabilityUnavailable` / `driver_unavailable` and zero writes → **exit 0**.
  - IPC gating verified via `cargo test --locked -p heimdall-ipc --lib` → **exit 0** (18 passed).

---

## 2. Audit for Remaining Cross-Context Policy Merges or Unadmitted Writes

Audited every call site across `crates/` touching `policies_for`, `applicable_policies`, `merged_policy`, `continuing_policy`, `origin_behavior`, `effective_lock_behavior*`, `effective_behavior*`, `lock_blocks_reissue`, `reissue_eligible`, `pair_connection_policy`, `pair_masters_enabled`, `max_window`, `cutoff_at`, `pause`, `tx.environment`, `doctor`, and store writes:

- **Grant origin & creation:** `with_lock_and_connection` ([`lock_connection_m03.rs:124-147`](crates/app/src/operations/lock_connection_m03.rs#L124-L147)), `resolve_in` ([`operations.rs:4336-4337`](crates/app/src/operations.rs#L4336-L4337)), `bound_of` ([`operations.rs:1695-1704`](crates/app/src/operations.rs#L1695-L1704)), `activation_refusal` ([`operations.rs:2183-2185`](crates/app/src/operations.rs#L2183-L2185)), `decide` waiting/approval checks ([`operations.rs:8713-8715`](crates/app/src/operations.rs#L8713-L8715), [`11416-11419`](crates/app/src/operations.rs#L11416-L11419)) all resolve through `merged_policy` / `policies_in` in the grant/intent's recorded `(environment, PolicyContext)`.
- **Renewal, reissue, background work, cutoff, pause, max window:**
  - `revalidate_chain` ([`operations.rs:1569-1570`](crates/app/src/operations.rs#L1569-L1570)) uses `continuing_policy(&policies, &ctx.policy_context)`.
  - `tick` expiry/cutoff loop ([`operations.rs:11735-11742`](crates/app/src/operations.rs#L11735-L11742)) uses `merged_policy(&policies, &ctx.policy_context)`.
  - `issuance_predicate` ([`operations.rs:12523-12535`](crates/app/src/operations.rs#L12523-L12535)) uses `merged_policy` (new activation) / `continuing_policy` (renewal/reissue) in `ctx.policy_context`.
  - `reissue_eligible` ([`managed_driver_m03.rs:592-595`](crates/app/src/operations/managed_driver_m03.rs#L592-L595)) uses `grant_policies(tx, &g.environment, Some(&origin))`, `effective_behavior_with_floor`, and `merged_policy(&policies, &context).and_then(|p| p.cutoff_at)`.
  - `narrowing::policy_reader` ([`narrowing.rs:1015`](crates/app/src/operations/narrowing.rs#L1015)) checks `grant_policies(tx, &g.environment, origin.as_ref())` so a policy change only narrows grants in its own environment and context.
  - `managed_store::StoreSources::record_terms` ([`crates/runtime/src/managed_store.rs:136-143`](crates/runtime/src/managed_store.rs#L136-L143)) and [`crates/runtime/src/connections.rs:485,1032`](crates/runtime/src/connections.rs#L485) use `grant_policies(tx, &g.environment, origin.as_ref())`.
  - `max_window` is read solely from `resolve_policy` (the target context's own policy, or personal fallback if none) and `lock::disclosure` (`applicable_policies`, now personal-only).
- **Lock handling:** `effective_lock_behavior` ([`operations/lock.rs:64-75`](crates/app/src/operations/lock.rs#L64-L75)), `effective_lock_behavior_of`, and `lock_blocks_reissue` ([`lock.rs:495-522`](crates/app/src/lock.rs#L495-L522)) all read `policies_in` / `grant_policies` for the grant's own `(environment, origin)` context.
- **Inspect / setup / projection / doctor:**
  - `pair_connection_policy` ([`lock_connection_m03.rs:172-193`](crates/app/src/operations/lock_connection_m03.rs#L172-L193)) and `pair_masters_enabled` ([`crates/runtime/src/service.rs:1803-1827`](crates/runtime/src/service.rs#L1803-L1827)) both read `environment_level_policies` (`PolicyContext::Personal` only), keeping workspace connection/multiplexing settings isolated from ordinary alias rendering and `inspect destinations`.
  - `doctor` (`crates/localenv/src/doctor.rs`) is passive local/config/endpoint/known_hosts observation and does not read standing policies from the store.
- **Unadmitted environment-scoped writes:** Checked all operation entrypoints and store mutations in `crates/app/src/`:
  - `ensure` ([`operations.rs:9395`](crates/app/src/operations.rs#L9395)), `bind` ([`operations.rs:9489`](crates/app/src/operations.rs#L9489)), `delegate` ([`operations.rs:9869`](crates/app/src/operations.rs#L9869)), `resolve_in`, `stage_load_authority`, `activation_refusal`, `revalidate_chain`, `issuance_predicate`, `authorize`, and `connections::register_owned_connection` all check `environments::admit`.
  - `revoke` intentionally permits revoking an existing grant even after environment removal (fail closed). Note that `bind` ([`operations.rs:9473`](crates/app/src/operations.rs#L9473)) admits `b.environment` before writing while still hashing `environment: &own` with `binding_id`; because `bind` does not coalesce via `equivalent_waiting` and `binding_id` already pins a single environment, M01–M03 `bind` hashes stay compatible without a coalescing or admission bug.

---

## 3. Regression Check (M01–M03 Delegation Golden Vectors & `apply_import` Test)

- **M01–M03 delegations still hash the runtime's own environment:**
  - Confirmed in [`Operations::delegate`](crates/app/src/operations.rs#L9856-L9890): every M01–M03 parent binding resides in the runtime's own environment (`parent_environment == own`), so `HashInput.environment` for M01–M03 delegations remains `&own`, identical to before `e4a0368e`.
  - Confirmed by:
    - `cargo test --locked -p heimdall-contract` → **exit 0** (45 unit + 95 `contracts`, including `canonical_props::golden_request_hash_vectors`)
    - `cargo test --locked -p heimdall-runtime --test model_operations` → **exit 0** (196 passed)
    - `cargo test --locked -p heimdall-runtime --test model_operations_m03` → **exit 0** (44 passed)
    - `TMPDIR=/tmp cargo test --locked -p heimdall-runtime --test integration_runtime_m03` → **exit 0** (54 passed)
    - `TMPDIR=/tmp cargo test --locked -p heimdall-runtime --lib two_environments_ensure_issue_bind_sign_restart_unmanaged_refused_cleanup_isolated` → **exit 0** (1 passed)
    - `cargo test --locked -p heimdall --test e2e_consumer_m03` → **exit 0** (7 passed, including `existing_access_ensure_bytes_match_base_goldens`)
    - `cargo test --locked -p heimdall --test e2e_cli_m04_m05` → **exit 0** (1 passed)
    - `cargo test --locked -p heimdall-app` → **exit 0** (71 unit + 3 `model_idempotency` + 16 `model_lock_behavior` + 54 `model_revocation` + 29 `model_signing_gates`)
    - `cargo test --locked -p heimdall-domain` → **exit 0** (105 unit + 21 `model_managed_domain` + 2 doc-tests)
    - `cargo test --locked -p heimdall-store` → **exit 0** (22 unit + 3 `integration_store_m04_m05`)
    - `cargo test --locked -p heimdall-testkit --test model_authority two_policy_trace_resolution_is_by_context_never_by_id` → **exit 0** (1 passed)
    - `python3 tools/validation/crate_graph.py` → **exit 0**
- **M02 test expecting `trusted-work/1` for `apply_import` is right:**
  - In [`tests/contracts/m02.rs:283-295`](tests/contracts/m02.rs#L283-L295), `setup_and_catalog_need_setup_1_and_preview_is_read_only` iterates `one_of_every_request()`, which includes `CatalogRequest::ApplyImport`.
  - Under ADR-0006 §17.6 item 7 (`R5-Q7`) and [docs/architecture/m05-plan.md](docs/architecture/m05-plan.md), `catalog.apply_import` is a revision-5 M05 workspace-trust form whose required capability is `trusted-work/1` (`capability::TRUSTED_WORK_V1`), not `setup/1`. Updating that assertion branch for `CatalogRequest::ApplyImport` in `m02.rs` is accurate and preserves the `setup/1` check for all M02 `setup` / `catalog` actions.

---

## 4. Mandatory Revert Verification (W0-R01)

1. Temporarily reverted the W0-R01 fix in [`crates/app/src/operations/lock_connection_m03.rs:129`](crates/app/src/operations/lock_connection_m03.rs#L129) (`policies = tx.policies_for(&origin.profile, environment)?;` instead of `crate::policy_context::policies_in(...)`).
2. Ran:
   `cargo test --locked -p heimdall-runtime --test model_operations w0_r01_workspace_lock_behavior_never_reaches_a_personal_grant`
   - **Exit code:** **101** (`FAILED`)
   - **Observed failure:**
     `assertion left == right failed: the workspace's revoke_on_lock is not recorded in a personal grant's origin` (`left: Some(RevokeOnLock)`, `right: None`).
3. Restored via `git checkout -- crates/app/src/operations/lock_connection_m03.rs` and re-ran:
   `cargo test --locked -p heimdall-runtime --test model_operations w0_`
   - **Exit code:** **0** (`5 passed; 0 failed`).
