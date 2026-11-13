# M03 wave 4 independent correctness review

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`). This is the wave-4 code review of `d6593a7c..e566cc46`, run in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.22.

**Verdict: fix first.**

Reviewed the combined `d6593a7c..e566cc46` diff, including `d74e35cf` and `e566cc46`, at detached HEAD `e566cc460e89e0ab84210edf55cf68d5a9cf3ba5`. All source locations below refer to that head. The checkout was `<scratch>/wt`. No source, configuration, evidence record, commit, or remote was changed. This report is the only retained output.

The activation works on the exercised happy path, including enrollment, real setup apply, managed ensure, and SSH through its binding endpoint. The important remaining defects are in lifecycle paths that the passing tests do not exercise. U12 CLI absence, retirement stopping at `unloaded`, and the known managed `connect` refusal are not counted as findings.

## Findings

### W4-R01 — P1 / high: expiry does not destroy the managed execution key

**Location:** [crates/runtime/src/supervisor.rs:1241](<repo>/crates/runtime/src/supervisor.rs:1241), with [crates/runtime/src/managed_store.rs:461](<repo>/crates/runtime/src/managed_store.rs:461). The existing expiry path is [crates/app/src/operations.rs:11276](<repo>/crates/app/src/operations.rs:11276).

**Scenario:** successfully ensure a managed grant, keep the runtime running, and let its deadline pass. `expire_grant` changes the grant to `expired`, but neither it nor `put_grant` destroys K_env or transitions the installed instance to `destroyed`. The new supervisor cleanup discovers only grants with held/clearing slots. An ensure that has not launch-bound has no slot and receives no managed cleanup at all. Even with a slot, `StoreCleanup::clean` clears slots/files/connections but never calls `effects.destroy` or destroys the credential instance.

The key, signer-table certificate entries and signing-gate retain therefore survive the grant's deadline until another cleanup trigger or process exit. An ensure-only binding's endpoint and files can survive too. The fresh signing predicate still refuses an expired grant; this is a key-lifetime/cleanup defect, not evidence of a successful post-deadline signature.

**Basis:** ADR-0008 D1 key-lifetime table and D2 credential-state table require zeroization at expiry; D7 item 8 requires expiry cleanup. The activation must wire that obligation into M01's expiry path, including expiry detected at use. Enumerating only ended grants with slots is insufficient.

**Evidence:** inferred from the complete expiry-to-supervisor call path. No new runtime reproducer was written in this read-only review. Add a real-vault expiry test with and without a held slot, asserting vault empty, instance destroyed, gate released, and endpoints/files removed.

### W4-R02 — P1 / high: re-issue repairs the grant without restoring its consumers

**Location:** [crates/app/src/operations/managed_driver_m03.rs:500](<repo>/crates/app/src/operations/managed_driver_m03.rs:500), [crates/app/src/managed/driver.rs:157](<repo>/crates/app/src/managed/driver.rs:157), and `reissue_completed` at [managed_driver_m03.rs:606](<repo>/crates/app/src/operations/managed_driver_m03.rs:606).

**Scenario:** an active managed binding holds an environment slot; restart the runtime in the same boot with accepted time and an available issuer. The new signer table is empty. `managed_reissue_pass` generates and installs a replacement K_env, but calls `run_stages(..., false)`, which explicitly selects no binding and skips materialization. It then changes the grant back to `active`.

There is no reconstruction of surviving binding endpoints/attachments, no replacement of their key/certificate files, and no restoration of the environment listing or slot content. The environment endpoint consequently lists no replacement key, while the slot files still name the old subject. A later launch bind cannot repair this: its slots-only materialization requires an in-memory `materialized` entry, which the new process does not have. The grant is reported repaired but ordinary SSH remains broken.

**Basis:** D6 item 4's recovery promise and D10 item 2's restart row: a held slot with a lost key remains degraded **until re-issue**, rather than indefinitely after a successful re-issue. Restore the consumer resources from the stored live bindings/slot generations before committing the repair.

**Evidence:** inferred. The executed `reissue_after_runtime_process_restart_same_boot` test passed, but uses `FixtureEffects` and stops at new fingerprint, installed instance, published entries and active grant ([tests/e2e/managed_m03.rs:1236](<repo>/tests/e2e/managed_m03.rs:1236)); it makes no post-restart SSH/listing/file assertion.

### W4-R03 — P1 / high: coalesced ensures commit bindings that were never materialized

**Location:** [crates/app/src/operations.rs:7785](<repo>/crates/app/src/operations.rs:7785), especially the `!attached` filter at line 7796; the coalescing path skips preparation at [operations.rs:6356](<repo>/crates/app/src/operations.rs:6356).

**Scenario:** two equivalent managed ensure requests coalesce in flight, or join the same pending authority decision. Each resolution has its own pre-minted binding ID. Only the leader runs the effect driver, which materializes only its binding. The follower receives the leader's grant/facts, skips `Reconcile`, and commits its own distinct binding. `stage_commit` supplies a signing endpoint only from the local preparation and explicitly excludes attached bindings; the historical integration also discards endpoints.

The follower returns `ACCESS_READY` for a binding with no endpoint/files/attachment. A launch bind of it fails `binding_not_materialized`. In the cancelled-owner continuation case, the owner can prepare for followers without ever committing an owner binding, making this gap particularly consequential.

**Basis:** §17.21 item 1 requires the binding returned by ensure to be materialized under the ID committed, while preserving the M01 coalescing contract. This concerns an existing reachable pipeline path, not an additional M05 feature. Materialize each accepted follower reference against the existing grant/key, or explicitly refuse an unsupported path before returning success.

**Evidence:** inferred from the coalescing, preparation and commit paths. Current managed replay tests cover the **same** request ID, not distinct coalesced requests.

### W4-R04 — P1 / high: evidence is not invalidated when ensure observes a changed target/client

**Location:** [crates/app/src/operations/enrollment_m03/passes.rs:152](<repo>/crates/app/src/operations/enrollment_m03/passes.rs:152) and [crates/adapters/src/managed/prepare.rs:445](<repo>/crates/adapters/src/managed/prepare.rs:445).

**Scenario:** after successful verification, the evaluated approved host key or client version changes. Before the supervisor completes a successful or contrary-evidence verification, ensure still reads the enrollment as `verified`; `pair_evidence` selects its evidence solely by pair/state/date. The report checks only `fresh_until` ([report.rs:525](<repo>/crates/adapters/src/managed/report.rs:525)) and can still claim `verified_server_principals`, satisfying a requested minimum on invalidated evidence.

The new host-key pass does not make this fail closed: it is asynchronous, suppresses the attempt while the previous verification is younger than `reverify_prompt_delay`, and an unreachable destination yields an inconclusive re-verification that deliberately keeps the record verified with its previous freshness. A client change has the same inconclusive-result problem. Thus stale claims can persist for the original evidence window, not just until the next pass. `pair_evidence` also has no association between the selected evidence and the CA of the newly prepared certificate.

**Basis:** D5 §6.5 requires immediate invalidation at the `inspect`/`ensure` comparison, with `destination_scope: unknown` until re-verified. Invalidation must be distinct from the enrollment's state and the outcome of a later network attempt. R2A-Q1's chosen implementation is not actually fail closed for this claim.

**Evidence:** inferred. The passing `evidence_invalidated_on_host_key_or_client_change` test explicitly calls `reverify_pass` with a reachable replacement-key server and asserts `held`; it does not test an ensure before the pass or an inconclusive attempt after a configuration/client change.

### W4-R05 — P1 / high: a crash before preparation confirmation leaves no cleanup intent

**Location:** [crates/app/src/managed/driver.rs:333](<repo>/crates/app/src/managed/driver.rs:333), [crates/app/src/operations.rs:6922](<repo>/crates/app/src/operations.rs:6922), and [crates/adapters/src/managed/mod.rs:456](<repo>/crates/adapters/src/managed/mod.rs:456).

**Scenario:** kill the runtime after `effects.materialize` has written the binding files but before `confirm` writes the ensure-stage `Confirmed` receipt. The durable ensure receipt is still `Attempted` (the `managed.*` receipts do not advance the ensure pipeline). On restart the new signer has no installed key. The managed adapter's reconcile finds published issuance but no live installation and returns `Unknown`. `stage_reconcile`/`reconcile_unresolved` leave the operation outcome unknown; they do not invoke `fail_managed_preparation` or write a cleanup intent.

The special managed-restart cleanup was added only to **stage_commit**, so this earlier crash never reaches it. The endpoint of the dead process stops, and its private key dies with the process, but the public binding files remain without a durable cleanup owner; the operation also cannot converge by replay alone.

**Basis:** §17.21 item 1 explicitly requires cleanup for a crash between materialization and commit. The test named `crash_between_materialize_and_commit_leaves_no_endpoint_file_or_key` actually injects failure **before Commit**, after the ensure confirmation ([crates/runtime/src/managed_store.rs:1649](<repo>/crates/runtime/src/managed_store.rs:1649)); it misses the materialize-to-confirm interval. It is a library unit test and was inspected, not executed by this review's `--test` commands.

**Evidence:** inferred. Apply the managed lost-process cleanup rule to attempted/uncertain preparation recovery too, or persist a cleanup owner before materialization.

### W4-R06 — P2 / medium: cleanup errors inside a failed driver are forgotten

**Location:** [crates/app/src/managed/driver.rs:210](<repo>/crates/app/src/managed/driver.rs:210), [crates/app/src/operations.rs:7166](<repo>/crates/app/src/operations.rs:7166), and [managed_driver_m03.rs:879](<repo>/crates/app/src/operations/managed_driver_m03.rs:879).

**Scenario:** materialization partially fails, or the following stage-receipt write fails; then clearing the materialized generation encounters a transient filesystem error. `abandon` logs a clear failure, ignores a destroy error, and logs an instance-update failure, but returns only the original preparation error. `run_effect_driver` fills `sources.managed.prepared` only on success, so `driver_ran` is false for this path. The outer failure therefore calls ordinary `fail_running`, without the cleanup intent used for a later `prepare_from` failure.

A failure that occurred after external effects can settle permanently with files/endpoints or an unreconciled instance remaining; fixing the transient error does not cause a retry. The current successful-cleanup test does not inject failure in cleanup itself.

**Basis:** D6 failure cleanup and §17.21 item 1; D7 requires an owed cleanup to remain durable on failure. Record cleanup responsibility based on an attempted managed effect, not only on the existence of a fully successful `ManagedPrepared` result.

**Evidence:** inferred from error handling; no fault injection was added.

### W4-R07 — P2 / medium: freeing the last slot discards the rest of the cleanup retry

**Location:** [crates/runtime/src/managed_store.rs:448](<repo>/crates/runtime/src/managed_store.rs:448), followed by binding cleanup at line 501, and [crates/runtime/src/supervisor.rs:1241](<repo>/crates/runtime/src/supervisor.rs:1241).

**Scenario:** an expired grant has one held slot. `ended_slot_pass` calls `StoreCleanup::clean`; the slot files are cleared and the row transitions to `free`. The subsequent mux-path cleanup or binding-file removal fails. The pass logs that it will retry, but its next enumeration uses `held_slots_of_ended_grants`, which no longer returns this grant. No durable record preserves the unfinished binding/mux cleanup. The same issue affects a best-effort last-release cleanup after its slots were freed.

**Basis:** §17.21 item 11's ended-grant pass must retry incomplete cleanup. A slot row can be its cleanup intent only while that row remains discoverable. Keep an independent obligation until all generation-bound work completes, or discover unfinished ended-binding resources independently of held slots.

**Evidence:** inferred. The executed ended-slot tests cover success, not an error after `slot_files_removed` has committed.

### W4-R08 — P2 / medium: releasing one binding does not release its slot while the grant stays live

**Location:** [crates/app/src/operations.rs:9877](<repo>/crates/app/src/operations.rs:9877), with the grant-only discovery at [crates/runtime/src/supervisor.rs:1241](<repo>/crates/runtime/src/supervisor.rs:1241).

**Scenario:** a managed parent binding holds the pair's slot, then delegates a child. The child holds a reference on the parent grant. Release the parent's consumer binding. The grant remains active because of the child reference, so `after_release_m03` is not called. The slot remains `held` by the released binding; the ended-grant pass cannot see it. Signing through that slot correctly refuses the released holder, but another binding for the pair still receives `managed_slot_held` until the parent grant eventually ends.

This also applies to a shared grant with multiple consumer references. Releasing a slot holder is a binding-level event even when destroying the grant's key would be incorrect.

**Basis:** D10 item 2 explicitly says `held(b,g)` moves to clearing when **b is released or b's grant ends**. Clear the released binding's slots/files independently of the last-reference key cleanup.

**Evidence:** inferred from release/reference accounting and both cleanup selectors. The test `released_binding_held_slot_cleared_after_grant_ends` tests the later grant-end case, not this required binding-release case.

### W4-R09 — P2 / medium: the M02 byte-identity test does not compare M02 results or hashes

**Location:** [tests/e2e/managed_m03.rs:1526](<repo>/tests/e2e/managed_m03.rs:1526).

The test `existing_access_ensure_intent_and_result_byte_identical_to_m02` checks a key-name list, serializes the **new** intent and round-trips it through the **new** decoder, and asserts that the result has no signing endpoint. It never compares serialized `EnsureData` with a baseline result, never asserts a baseline request hash, and never reads actual M02 intent bytes. Removing `binding_id` from a managed intent and round-tripping that does not supply such a baseline either.

**Concrete missed regression:** a result field/default or request-hash input could change while keeping the resolved-intent key set and absent signing endpoint; this test would still pass. The additive serde annotations look correct on source inspection, and the exercised old suites passed, but the stronger byte-identity claim is not established by this test.

**Basis:** §17.21 item 1 explicitly preserves existing-access results/intents/request hashes. Use fixed, deterministic baseline goldens from the base commit, or compare equivalent deterministic executions against that baseline, covering the result and hash as well as decoding compatibility.

**Evidence:** observed test contents and observed passing execution; the hypothetical regression itself was not injected.

## Reading of the escalations

### Round 1 questions

The latest rulings resolve most round-1 questions. They should not be treated as still-open authorizations merely because their original rows remain in the archive.

| Questions | Reading / ruling |
|---|---|
| INT-W4-Q1 / U10C-Q1 | §17.21 item 1 authorizes the pre-minted ID and preparation materialization. The single-request happy path is implemented. W4-R03, R05 and R06 are incomplete edges of that ruling. |
| INT-W4-Q2 / U10C-Q2 | Item 2 authorizes runtime slot claims in `BindForm::Launch`. The new two-pass bind checks all slots before claiming and the CLI only reads the bind outcome. The exercised occupied-slot path fails closed. W4-R07/R08 concern subsequent cleanup. |
| INT-W4-Q3 / U10B-Q2 | Item 3 authorizes `store_locator`. Missing locator/deletion ports really stop at `unloaded`; no deletion is guessed. The remaining reporter/process choices are R2B-Q1/Q2 below, not findings merely because retirement is incomplete. |
| INT-W4-Q4 / U10B-Q1 | Item 3 authorizes durable `RegisterIssuer.ca_public_key` and `backup_created_at`. Approval reads persisted facts; old-shape approval is stale and unconsumed. Both behaviors passed their tests. |
| INT-W4-Q5 / A-Q1 | Item 4 accepts journal receipts but forbids foreign registry bytes in durable receipts. The new digest plus minimized marker reading meets that design on the inspected path; the foreign-comment regression passed. Full images stay in a bounded process-memory cache and are re-inspected after loss. |
| INT-W4-Q6 / U10-D-Q3 | Item 10 explicitly accepts the runtime-only `wire_runtime_projection` and preserves public M02 `wire_projection`. No need to break M02's callers. |
| A-Q2 / U10B-Q4 | Item 5 authorizes the common operation-authority extension. Apply-initial, target-change and system-absence predicates are separate, and reservation/publish/signing use the same store-derived predicate. The relevant authority and operation-gate tests passed. |
| A-Q3, A-Q4, A-Q5 | Item 10 accepts the conservative outer clock measurement, unattended supervisor principal, and `EnrollmentHost` port. No additional permission question is needed. |
| U10B-Q3 | Item 10 accepts conservative bundle staleness and an empty runtime orphan list. It must remain disclosed as this limited view. |
| U10B-Q5 | Item 10 says no test store kind. The reviewed enrollment tests explicitly use fixture issuer ports; they do not prove native secure-store custody. |
| U10C-Q3 / U10C-Q4 | Item 10 accepts destruction under narrowing gates and `NarrowingKind::Enrollment`. Revocation wiring is present; expiry still misses destruction (W4-R01). |
| U10C-Q5 | Item 6 requires one re-issue rule. Both callers reach `heimdall_domain::reissue::eligible`; the moved adapter module is a re-export, not a second policy implementation. W4-R02 concerns the effects after eligibility. |
| U10C-Q6 | Item 7 requires instance lookup by store query. Lookup now uses `credential_instances_for_grant`. Instance creation still derives its ID from a fingerprint, but lookups no longer depend on that derivation; I found no correctness failure from the creation choice. |
| U10-D-Q1 | Item 8 requires a persistent installation token. The portable token persistence/restart test passed on macOS. Native Windows pipe/ensure behavior remains blocked here, not verified by that portable test. |
| U10-D-Q2 | Item 10 explicitly allows no close reason for runtime stop. |
| U10-D-Q4 | Item 9 requires setup-applied stable mux rendering. The unresolved pair-versus-grant policy interpretation is R2D-Q1 below. |

### Round 2 open questions

| Question | Is the chosen path closed? What I would rule |
|---|---|
| **R2A-Q1 — host-key evidence invalidation** | **Not closed for capability reporting; W4-R04.** Choose immediate reader-side invalidation, with `destination_scope: unknown`, independently of enrollment state and network reachability. Preserve the approved target until an attended `ApproveTargetChange` verification passes. D5 §6.5 explicitly forbids automatic host-key re-verification, so the automatic attempt needs an amendment if retained; pinned old-key attempts do not by themselves solve invalidation. Also invalidate for client/CA changes before a successful re-verification. |
| **R2B-Q1 — locator reporter and restore** | Closed: production has no reporter, and the no-locator case stops before deletion. Prefer an explicit additive ceremony report carrying the returned item identity, bound to the registered CA/installation/store. Do not infer ownership from a fingerprint listing. A legitimate restore that creates a new item needs an explicit, recorded replacement rule (expected-old locator or revision); a permanently set-once locator can retire the stale item while leaving the restored key behind. Preserve the displaced item in orphan reporting until resolved. |
| **R2B-Q2 — deletion process** | Closed: the absent deletion port cannot delete. Prefer the owner-present CLI performing the exact recorded deletion after unload, with a durable completion handoff; this preserves the child-does-not-write rule and avoids giving the runtime a general secret-store read handle. If unattended retirement is required, explicitly authorize a narrowly scoped deletion component/protocol instead of silently broadening D3. |
| **R2C-Q2 — bind endpoint missing** | Closed: managed `connect` refuses before launching. Prefer filling the endpoint from the runtime registry for this exact live binding; absence must still refuse. Persisting an endpoint alone is insufficient across restart, and it does not fix W4-R02/R03. This known refusal is not a finding. |
| **R2D-Q1 — pair policy for P** | The conservative standing-policy merge cannot start a master by itself; each master's grant policy is still checked. Accept option (a) as an explicitly documented pair-level rendering rule, with no applicable policy meaning disabled. A one-off owner-decision grant can remain unmultiplexed through P. Do not make P change automatically as slot holders change. |
| **R2E-Q2 — issuer-unavailable degradation** | Choose (b): no grant-state change solely because the issuer is unavailable. D3 item 7 explicitly keeps installed keys signing; losing K_env is the reason for `credential_reissue_pending`. Report issuer state separately. The real endpoint signing test after issuer failure passed. |
| **R2F-Q1 — existing preference status** | The present choice does not enable managed signing: mechanism resolution uses `existing`. For coherent status, record `existing/applied` when its corresponding rendering commits, but do not introduce an `existing` preference row for every M02 pair. Not a merge-blocking authorization expansion. |
| **R2F-Q2 — no-op apply leaves pending** | Closed for managed activation: it keeps resolving existing. Rule that an approved apply can validate the current P and commit its generation/preference metadata even when no file replacement is necessary. A preference toggle back to an already-rendered managed configuration must not become permanently pending. The current limitation is disclosed in the escalation, so I have not counted it as a separate finding. |
| **R2F-Q3 — removed destination's applied row** | Closed for access: the missing catalog destination refuses before managed effects. Prefer returning the preference to pending (or removing the orphan preference) in the authorized catalog-removal transaction; do not rely on a later setup traversal to discover rows it cannot enumerate. |
| **R2F-Q4 — manual mode counts applied** | Accept applied as the status of the journaled **P rendering**, consistent with M02 manual mode. It does not prove that ordinary SSH includes P; retain the explicit manual-include diagnostic and disclosure. `run`/`connect` must continue to enforce their own launch checks. |

The notes mark R2C-Q1, R2E-Q1 and R2E-Q3 resolved. Source inspection agrees: managed interaction values survive the commit recheck, non-exclusive managed selection is refused non-interactively, setup writes the applied preference, and the allowlisted issuer store reasons propagate to activation failures. This is not a substitute for the separate security review of selection/fallback enforcement.

## Setup-apply addition

The new `SetupIntent.managed_pairs` and `ProjectionPlan.managed_pairs` are not explicitly named by §17.21, but the behavior they support is required by D5 §6.6 and U0b row 9: without a production `applied` writer, enrollment never activates managed resolution. I would ratify these additive internal fields as the minimal durable handoff of what the approved rendering actually contains.

The important choices are correct: the pair set is captured with rendering, carried in the intent, and recorded in the same transaction as the SSH item commit; it is not guessed from the current preference afterward. Empty sets are serde-defaulted and omitted for old intents. Rollback/non-managed rendering returns managed preferences to pending; duplicate-marker/include-position repairs do not claim a new P rendering. The executed setup tests cover managed-only marking, rollback/existing rendering, and stale preview refusal. The no-op/manual/removal limitations remain as ruled above. No additional implementation was performed during this review.

## Commands and validation

All Cargo commands ran in the detached checkout, on the pinned Rust 1.99.1 toolchain, with its ordinary root `target/`. No alternate target directory, Docker fixture, live keychain, 1Password account, owner SSH agent, or owner key was used.

| Command | Observed exit / result |
|---|---|
| `git -C <repo> worktree add --detach <scratch>/wt e566cc46` | **0**, detached checkout at the requested head. |
| `git log --oneline d6593a7c..e566cc46` | **0**, exactly the two requested commits. |
| `git diff --stat d6593a7c..e566cc46` | **0**, 101 changed files. |
| `git rev-parse HEAD` | **0**, `e566cc460e89e0ab84210edf55cf68d5a9cf3ba5`. |
| Targeted `git diff d6593a7c..e566cc46 -- <paths>` reads | **0**; ensure/authority, setup/domain/projection, classification, managed effects/reissue, runtime/dispatch/session and CLI-run changes inspected. |
| `cargo test -p heimdall --test e2e_managed_m03 --test e2e_enroll_m03 --locked` | **0**: 16 managed + 62 enrollment passed; no ignored tests. |
| `cargo test -p heimdall-runtime --test integration_runtime_m03 --test integration_issuer_m03 --test model_setup --test model_operations --locked` | **0**: 42 runtime + 17 issuer + 51 setup + 186 operations passed; no ignored tests. |
| `cargo test -p heimdall --test e2e_cli_m01 --test e2e_cli_m02 --test e2e_run_m02 --locked` | **101**: M01 24 passed; M02 CLI 41 passed, 1 failed, 1 child entry ignored. Failure: the disposable agent required the unbuilt `hm-fixture-hook`. Cargo stopped before the run target. This was a fixture prerequisite failure, not adjudicated as a product regression. |
| `cargo test -p heimdall-testkit --test integration_testkit_fixtures --locked` | **0**: 18 passed; also built the required fixture executable. No separate `cargo build` command was used. |
| `cargo test -p heimdall --test e2e_cli_m02 --test e2e_run_m02 --locked` | **0**: 42 CLI + 54 run passed; one child-mode entry ignored in each target. The previous fixture failure is resolved. |
| `cargo test -p heimdall-credential --test integration_managed_signer --locked` | **0**: 39 passed, 1 ignored with explicit blocker B3, a disposable second macOS account. |
| `git diff --check d6593a7c..e566cc46` | **2**: an extra blank line at EOF in `tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r2-api.md:220`. Cosmetic; not a numbered finding. |
| `git status --short` | **0**, empty before cleanup; no tracked/untracked source changes. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` (bash) | **1**: none of those output directories exists in this fresh checkout. |
| `du -sh target` | **0**, **6.5 GB** before checkout removal. This build output is removed with the owned worktree. |

Repeated source-inspection commands were `cat`, `rg -n`, `sed -n`, and `nl -ba` over the requirements, ADR/plan, both questions files, manifests, the named production paths and corresponding tests. Successful reads returned 0. An early optional ancestor-instruction `ls` returned 1 for absent optional files. One exploratory `rg` used a nonexistent split-test path (`tests/e2e/cli_m02/ssh.rs`, exit 2); the actual source is the single `tests/e2e/cli_m02.rs`, which was then inspected. Searches with no matches returned 1. No conclusion relies on the nonexistent path or an unexecuted command. Startup instruction/skill and lightweight memory-registry reads were outside the checkout; no relevant historical Heimdall evidence was found or used.

**Verified test total:** 551 unique tests passed across the final successful executions above. The three ignored entries are two child-mode harness entry points and the explicitly blocked cross-account macOS test. Passing portable token tests do not close Windows claims.

**Cleanup completed:** `git -C <repo> worktree remove --force <scratch>/wt` exited **0**, removing the owned checkout and its 6.5 GB root build directory. `rmdir <scratch>` exited **0**. A final `python3` assert-based report/cleanup check exited **0**: all nine finding headings and the verdict exist, both temporary paths are absent, and a captured `git worktree list --porcelain` (exit **0**, not dumped) contains no registration for the removed checkout. The only retained changed file is `<scratch>-report.md`.

## What was not checked

- **Blocked:** native Windows/WSL behavior and live Windows named-pipe restart/ensure; no such platform was exercised. **Blocked:** the disposable second macOS account needed for cross-account signer isolation. No cross-compile, fake or emulation is represented as native evidence.
- No native secure-store custody, screen-lock cycle, reboot/logout cycle, owner keychain, real 1Password workflow, remote machine, Docker/per-shell matrix, or release build was exercised. The fixture SSH operations used disposable test keys and homes only.
- No whole-workspace suite, library unit-test run, clippy run, fuzzing, or exhaustive security audit. In particular, tests embedded inside `crates/runtime/src/managed_store.rs` were read but not executed by the allowed `--test` target runs.
- The numbered runtime failures are source-inferred except the explicitly described test-coverage finding; I did not edit the repository to add reproducers. Successful existing tests are evidence for their exercised paths, not proof that these missing paths work.
- The review was focused on correctness/contracts in this large combined diff, not an assertion that every changed line or every platform has been exhaustively reviewed. No fixes, commits or pushes were made.

Skipped: U12 commands, live secret stores and unavailable native-platform checks. Risk: passing happy-path suites do not close the lifecycle and evidence-reporting defects above; fix them before merge.
