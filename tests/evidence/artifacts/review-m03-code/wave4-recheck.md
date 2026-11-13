# Heimdall M03 wave-4 independent re-check

**Verdict: fix first.** The submitted regressions pass, but the fixes leave two reproduced defects: **W4-C01 (medium)** retains a released binding's resources after reissue, and **W4-C02 (high)** lets a joined follower meet a scope minimum using invalidated evidence. W4-R04 is therefore not fully resolved.

Reviewed commit `4866642dd824472c99cecbab99e1c503c8224c3b` over `e566cc460e89e0ab84210edf55cf68d5a9cf3ba5`, corresponding to `m03/wave4`. The review checkout was detached at `/tmp/hm-recheck-m03w4/wt`. Rust/Cargo 1.99.1, native macOS. Locations below refer to that immutable head; links point to the original workspace for convenience.

The production diff and relevant specification paths were assessed before reading the original review reports, the §17.22/§17.23 rulings, or the integrator notes. Those documents were then used to map the findings and required regressions. Notes' claimed results were not treated as independently verified results. This was a direct independent re-check, without further delegation.

No repository source, configuration, fixture, instruction, or evidence record was edited, committed or pushed. Reversions and added probe tests ran only in disposable source copies under the authorized scratch root. The detached checkout remained clean. **The only retained deliverable is this report.**

## New findings

### W4-C01 — Medium / P2: releasing a reissued binding with no slot leaves its endpoint and files without a cleanup obligation

**Observed.** Primary location: [crates/app/src/operations/managed_driver_m03.rs:1100](<repo>/crates/app/src/operations/managed_driver_m03.rs:1100). Discovery gap: [crates/store/src/ext_m03.rs:1500](<repo>/crates/store/src/ext_m03.rs:1500).

`after_binding_release_m03` always clears `BINDING_GENERATION` (1). Reissue now restores live bindings at a newer resource generation. Clearing generation 1 successfully does nothing to that newer endpoint and file generation. For a grant that remains live, `managed_cleanup_owed` discovers released bindings only through held/clearing slots. A binding that never claimed a slot consequently has neither a matching immediate clear nor a discoverable retry.

**Concrete reproducer, executed against the fixed production components:**

1. Ensure a managed parent binding without a launch bind; verify all its slots remain free.
2. Delegate a real child, so it retains a reference on the parent's grant.
3. Restart the harness runtime in the same boot, then run the real reissue pass. Check the restored parent endpoint's generation is greater than 1.
4. Release the parent binding. Check the parent grant and child's grant remain active.
5. Query `managed_cleanup_owed` and run `Supervisor::ended_slot_pass`.

The added assertion expecting no retained resources failed with:

```text
released reissued slotless binding: endpoint_retained=true, files_retained=true, cleanup_owed=0, pass_cleaned=0
```

The scenario was reproduced in all three probe runs. It used the existing live harness, real store, vault, signer table, effects and endpoint registry; no mock cleanup implementation. This is introduced by combining the new reissue generations with the new binding-level release path. It is adjacent to W4-R02/R07/R08, whose submitted slot-based scenarios pass.

**Required correction:** clear the binding's actual owned generations and retain a durable retry for released bindings' resources even when no slot exists. Preserve the still-referenced grant's K_env. Add this restart → reissue → slotless release scenario as a regression.

**Limit:** this demonstrates resource retention, not signing after release. Fresh binding authorization still rejects a released binding; no successful unauthorized signature is claimed. The resources can remain through cleanup passes until the grant eventually ends.

### W4-C02 — High / P1: a joined follower can satisfy `verified_server_principals` after its evidence becomes invalid

**Observed.** Primary location: [crates/app/src/operations.rs:7770](<repo>/crates/app/src/operations.rs:7770), with the fallback at [operations.rs:7950](<repo>/crates/app/src/operations.rs:7950). The newly achievable minimum is advertised at [crates/adapters/src/managed/mod.rs:133](<repo>/crates/adapters/src/managed/mod.rs:133).

A normal preparation now compares target/client evidence in `prepare::snapshot`, and selects evidence for the prepared certificate's CA. An attached follower skips that preparation. `stage_commit` instead takes `Facts::from_data` from the leader's result, or falls back to `Facts::conservative` using the grant's recorded enforcement. `with_eligibility` refreshes interaction/availability fields, not the scope evidence. `unmet_minimum` then accepts the cached `VerifiedServerPrincipals` value without a comparison for this follower.

**Concrete reproducer, executed:**

1. Feed fresh valid evidence for both managed pairs and the evidence's original client, `OpenSSH_10.5p1`.
2. Submit two distinct request IDs for equivalent three-hour managed ensures. Both require `destination_scope_at_least = verified_server_principals`; both join one owner decision.
3. Approve the decision. A test `StageHook::after(Commit)` changes the current client to `OpenSSH_10.6p1` immediately after the leader commits and before the joined follower commits. The hook changes only the external evidence feed; it does not alter store facts or bypass an application check.
4. The follower still succeeds on the leader's grant and reports `VerifiedServerPrincipals`.
5. As a control, a fresh preparation with the same scope minimum at the changed client is refused `CAPABILITY_UNAVAILABLE`.

The added assertion expecting the follower's refusal failed with:

```text
joined follower accepted invalid evidence: scope=VerifiedServerPrincipals, same_grant=true
```

Both the corrected probe and its final rerun reproduced this. The final rerun also passed the fresh-preparation refusal control before reaching the failure above. No re-verification pass or network result intervened. An initial trial tried to pause between returned ensure calls, but the decision driver had already committed the follower; that trial's scheduling assertion was a probe setup error, not evidence for this finding. The corrected probe places the change at the actual stage boundary.

**Required correction:** recompute the managed scope claim from current, fresh pair/client/target evidence and the actual installed certificate CA for each newly committed follower, including recovered/continued follower paths. A leader's historical result must not satisfy a follower's present minimum. Extend the existing evidence regression to a decision-joined/coalesced follower.

This is the remaining path of **W4-R04**. The new descriptor now lets scope-needing requests reach this path; the existing fresh-preparation tests alone do not prove the advertised guarantee. The general coalesced/recovered-path extension is source-derived; the decision-joined client-change case above is executed evidence. No remote authentication exploit is claimed: the defect is a false enforcement claim and a required-minimum bypass.

## Original findings

| Finding | Resolved? | Independently checked evidence |
|---|---|---|
| **W4-S01** held foreign-removal descriptor swap | **Resolved — verified.** | **Observed:** `foreign_removal_held_reuse_needs_the_exact_descriptor` runs the held-record scenario through real loopback SSH. Principal/destination, CA and registry variants refuse before mutation; forged mismatched decisions refuse at approval; the original descriptor remains removable. Reverting admission equality and approval equality independently caused this test to fail; each restoration passed. **Inferred:** full `ForeignRemovalTarget` equality also covers account, host, port, alias, form, marker and line hash, rather than only the explicitly varied fields. |
| **W4-S02** foreign marker-bearing bytes in receipts | **Resolved — verified.** | **Observed:** `journal_never_stores_marker_bearing_foreign_lines` covers an owner comment, unrelated key and damaged canonical line through real inspect/StepResult, including foreign removal. It scans stored receipts/results for raw, hex and base64 forms. Canonical entries are kept only on exact match; other marker lines retain count/classification/digest. Reintroducing byte retention in `StoredReading::of` caused the privacy scan to fail; restoration passed. **Inferred:** reconstructed stand-ins preserve the stage machine's damage classification without retaining the foreign bytes. |
| **W4-S03** dropped service retains loaded issuer | **Resolved — verified for the exercised lifecycle.** | **Observed:** all three `wave4::teardown_r3` tests pass: drop before `run`, failure after issuer startup, and failure after managed startup. The first drops public strong handles and checks exact child exit plus a non-upgradable weak vault. Reverting issuer stop and wiring-cycle clearing caused all three to fail; restoration passed. Test guards and the process inventory left no fixture child behind, including after the intentional failures. **Inferred:** the guard is installed before the first relevant cycle and its drop covers subsequent startup errors. The outside-Tokio drop fallback was inspected, not independently exercised. |
| **W4-R01** expiry fails to destroy K_env | **Resolved — verified.** | **Observed:** real-vault expiry at use without slots and scheduler expiry with held slots both empty the vault, destroy instances, release gates and remove endpoints/files. The restart/retry obligation case also passes. Disabling both expiry cleanup calls fails all three tests; restoring them passes. |
| **W4-R02** reissue fails to restore consumers | **Resolved for the reported restart repair — verified; see new W4-C01 for its later release.** | **Observed:** `reissue_restores_binding_endpoint_files_and_slot_so_ssh_signs_with_the_new_key` proves actual SSH through both the restored binding and environment slot, with the replacement fingerprint and newer binding generation. Removing `restore_consumers` makes it fail at the absent binding endpoint; restoration passes. **Inferred:** the reissue returns to active only after restoration, and refuses a partially held slot set. |
| **W4-R03** coalesced/joined bindings unmaterialized | **Resolved for materialization — verified; scope refresh remains W4-C02.** | **Observed:** both distinct-request coalescing and decision-joining regressions pass real SSH through each binding using the shared K_env. Disabling follower materialization fails both at missing follower resources; restoration passes. Exact-created-locator and missing-created-endpoint refusal tests also pass. |
| **W4-R04** evidence not invalidated at comparison | **Not fully resolved.** | **Observed:** fresh preparations reject changed host/client/CA evidence before the pass; an inconclusive client-change re-verification leaves scope unknown. The adapter evidence and CA-selection regressions fail independently when their comparison/CA filter is disabled, and pass restored. **However, W4-C02 reproduces a joined follower accepting the invalidated scope claim.** Fresh preparation is fixed; not every ensure path is fixed. |
| **W4-R05** crash before ensure confirmation lacks cleanup | **Resolved — verified.** | **Observed:** the crash test holds after materialization while the ensure receipt is still `Attempted`, proves the intent already exists, destroys that runtime, then recovers with a new signer. No key, endpoint, binding files, live instance or intent remains. Disabling early intent recording fails the pre-crash intent assertion; separately reverting the managed uncertain-recovery arms fails convergence to `Failed`. Both restorations pass. |
| **W4-R06** failed driver cleanup forgotten | **Resolved in the exercised activation failure — verified.** | **Observed:** materialization writes resources, injects a failure and makes its directory read-only; cleanup cannot remove it, the intent survives repeated passes, then removal succeeds and the intent clears after permissions recover. Removing early intent recording plus the managed failure path makes the test fail with forgotten cleanup; restoration passes. **Inferred:** the durable intent covers earlier failures too, rather than relying on a successful `ManagedPrepared`. |
| **W4-R07** freeing slot loses remaining cleanup retry | **Resolved for the reported slot cleanup — verified; broader slotless obligation gap is W4-C01.** | **Observed:** failure after slot-file removal keeps the slot clearing and the obligation discoverable until binding cleanup completes. Moving `slot_files_removed` back before binding cleanup causes the regression to fail; restoration passes. The first mutation attempt did not compile because its nested Result was unused; only the corrected compiling mutation is used as regression evidence. |
| **W4-R08** released holder retains slot while grant lives | **Resolved for slots — verified; slotless reissued-resource cleanup is W4-C01.** | **Observed:** the regression now uses a real child delegation. Releasing the parent slot holder retains K_env for the child, moves/cleans its slots, and permits another binding to claim them. Disabling `release_binding_slots_in` fails the regression; restoration passes. |
| **W4-R09** no actual M02 byte comparison | **Resolved — verified.** | **Observed:** the current golden test compares serialized EnsureData, wire envelope, stored intent bytes and actual operation request hash. I compiled the same helper and assertion against a disposable `d6593a7c` source snapshot; all four checked-in goldens match the base. Only the three CSPRNG-minted IDs are normalized. Independently perturbing result bytes, intent bytes and request-hash fixture bytes makes each corresponding comparison fail, and restoring each passes. These are fixture-perturbation checks, not production-code reversions. |
| **W4-N01** enrollment target had no Windows tests | **Source port checked; native acceptance blocked/outside this review.** | **Observed source:** 45 tests and shared fixture helpers now permit Unix and Windows; 21 retain explicit Unix-only explanations. Four additional Windows tests cover binding-pipe listing/signing, a decision-joined follower's own pipe, reissued binding pipe/new key, and trace-row observation. Source uses the in-box client path, explicit scratch config, owner-only pipe/fixture DACLs and the WSL registry harness; missing fixture/trace evidence fails rather than silently passing. Native Windows with in-box ssh.exe and the WSL fixture was not available in this macOS run and is assigned to the orchestrator. No native pipe/lock/store claim is closed here. |

## Additional focused checks

- **Cleanup intent/recovery:** the intent is written in the same transaction as the managed attempt, before `generate_key`. A live preparation keeps its intent without being cleaned out from under it; successful commit clears it. Activation failure and lost-process recovery preserve/retry the obligation. Follower cleanup is binding-local and does not destroy the shared grant key. Those exercised paths pass; W4-C01 is the missing released-binding obligation outside the activation-intent path.
- **`managed_cleanup_owed`:** terminal grants with pending/installed/lost instances remain discoverable even without slots, and clearing slots remain obligations through the rest of cleanup. The live, released, slotless binding case is absent; W4-C01 is the counterexample.
- **Typed materialization:** `Fresh`, `InstalledKeyOf` and `SlotsOnly` are explicit variants, not overloaded string conventions. Source and the passing inconsistent-source test check empty/mismatched fresh material, no live named-grant key, mismatched binding grant, and slots-only prerequisites. Installed content is read from the live key and installed certificates of the stored grant scope. The follower names `MaterializedFiles.endpoint`; the passing tests verify the exact returned locator and refuse a result without one.
- **`fresh_pair` and non-interactive use:** the managed key signs in-process, so catalog bootstrap identity interaction is not its current signing interaction. The change restores those managed facts after history conversion. Passing per-pair tests show an exclusive alias delegates non-interactively, while an undetermined or absent observation is refused `fallback_identity_interaction`; a scope containing only the exclusive pair succeeds. No stable-input interaction bypass was found. The minimum bypass I did reproduce is W4-C02: interaction refresh is not scope-evidence refresh.
- **Descriptor scope:** valid, fresh evidence meets the newly advertised minimum on a fresh preparation. Changed route/host/client, missing evidence and another prepared CA fail the comparison in the exercised tests. That does not establish correctness on the skipped-preparation follower path.
- **Issuer registration reports:** the app and store independently compare every registration fact, including public key/fingerprint, store, backup digest/time, rotation, key-only restore and expected old locator. The reported locator alone is attachable, once; same-locator replay is idempotent; a mismatch/second different locator refuses without creating a registration. Integration tests pass for these cases and restore CAS/orphan tracking.
- **Retirement confirmations:** owner role is checked before issuer dispatch; confirmation additionally requires an attended session, a valid locator, and the matching CA's recorded item in an allowed retirement state. Wrong locator, other CA, no recorded locator, premature and unattended confirmations refuse. Scratch-store tests pass for deleting only the named item while preserving another installation's item, and reaching retired only on matching confirmation. **The runtime trusts an authenticated attended owner's assertion of deletion; it does not independently inspect a platform store.** That is the ruled CLI-confirmation boundary, not proof that an arbitrary caller's assertion or a real platform deletion was verified. U12's CLI half is out of scope.
- **Projection changes:** the passing runtime integration target covers existing/applied preference metadata, no-byte-change recommits, destination removal and manual mode, along with live bind-endpoint wiring. M02's deterministic result/intent/hash behavior also matches the actual base.

## Commands and results

All Cargo commands below were launched by `python3 /tmp/hm-recheck-m03w4/run.py <label> <cwd> <command...>`. That wrapper set `TMPDIR=/tmp`, captured output in scratch, and monitored only its process descendants by exact PID/start identity/executable. Test failure output was inspected selectively; no raw environment, authentication configuration, process command lines or bulk runtime logs were emitted.

`WT` means the clean detached checkout, `PROBE` its disposable source copy, and `BASE` the disposable `d6593a7c` snapshot. `PROBE` added only a scratch `[[test]] recheck_internal` pointing at `crates/runtime/src/lib.rs`, making the existing live unit regressions runnable using `cargo test --test`. All three used the checkout's one build-output directory via scratch symlinks; no CARGO_TARGET_DIR or --target-dir was introduced. No repository manifest changed.

Fixed-code baseline results: runtime integration **51**, issuer operation integration **21**, enrollment **66**, consumer **7**, managed e2e **16**, selected real managed live tests **21**, managed adapter **48**, store **31**, issuer child **33**, issuer store **30**: **324 passed, zero failures/ignored in these selected runs**. Workspace all-target Clippy with `-D warnings` also passed. Intentional mutation/probe failures below are separate from that baseline.

| Label / cwd | Executed command | Exit |
|---|---|---|
| baseline-runtime / WT | `cargo test -p heimdall-runtime --test integration_runtime_m03 --test integration_issuer_m03 --locked` | **0** |
| baseline-internal / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked managed_store::live_tests::` | **0** |
| baseline-enroll / WT | `cargo test -p heimdall --test e2e_enroll_m03 --test e2e_consumer_m03 --test e2e_managed_m03 --locked` | **0** |
| revert-R01 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked managed_store::live_tests::cleanup::expiry_ -- --test-threads=1` | **101** |
| restore-R01 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked managed_store::live_tests::cleanup::expiry_ -- --test-threads=1` | **0** |
| revert-R02 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked reissue_restores_binding_endpoint_files_and_slot -- --test-threads=1` | **101** |
| restore-R02 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked reissue_restores_binding_endpoint_files_and_slot -- --test-threads=1` | **0** |
| revert-R03 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked follower_gets_its_own_materialized_binding_and_both_sign -- --test-threads=1` | **101** |
| restore-R03 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked follower_gets_its_own_materialized_binding_and_both_sign -- --test-threads=1` | **0** |
| revert-R05-intent / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked crash_between_materialize_and_confirmation -- --test-threads=1` | **101** |
| restore-R05-intent / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked crash_between_materialize_and_confirmation -- --test-threads=1` | **0** |
| revert-R05-recovery / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked crash_between_materialize_and_confirmation -- --test-threads=1` | **101** |
| restore-R05-recovery / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked crash_between_materialize_and_confirmation -- --test-threads=1` | **0** |
| revert-R08 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked released_slot_holder_frees_its_slots_while_grant_stays_live -- --test-threads=1` | **101** |
| restore-R08 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked released_slot_holder_frees_its_slots_while_grant_stays_live -- --test-threads=1` | **0** |
| new-probes / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked recheck_ -- --test-threads=1` | **101** |
| revert-S01-admission / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked foreign_removal_held_reuse_needs_the_exact_descriptor -- --test-threads=1` | **101** |
| restore-S01-admission / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked foreign_removal_held_reuse_needs_the_exact_descriptor -- --test-threads=1` | **0** |
| revert-S01-approval / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked foreign_removal_held_reuse_needs_the_exact_descriptor -- --test-threads=1` | **101** |
| restore-S01-approval / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked foreign_removal_held_reuse_needs_the_exact_descriptor -- --test-threads=1` | **0** |
| revert-S02 / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked journal_never_stores_marker_bearing_foreign_lines -- --test-threads=1` | **101** |
| restore-S02 / PROBE | `cargo test -p heimdall --test e2e_enroll_m03 --locked journal_never_stores_marker_bearing_foreign_lines -- --test-threads=1` | **0** |
| revert-S03 / PROBE | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked teardown_r3 -- --test-threads=1` | **101** |
| restore-S03 / PROBE | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked teardown_r3 -- --test-threads=1` | **0** |
| new-probes-r2 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked recheck_ -- --test-threads=1` | **101** |
| base-golden / BASE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens` | **101** |
| base-golden-rebuild / BASE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens` | **0** |
| new-probes-final / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked recheck_ -- --test-threads=1` | **101** |
| revert-R04-comparison / PROBE | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked evidence_invalidated_at_the_comparison_before_any_pass -- --test-threads=1` | **101** |
| restore-R04-comparison / PROBE | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked evidence_invalidated_at_the_comparison_before_any_pass -- --test-threads=1` | **0** |
| revert-R04-ca / PROBE | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked pair_evidence_is_for_the_prepared_certificates_ca -- --test-threads=1` | **101** |
| restore-R04-ca / PROBE | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked pair_evidence_is_for_the_prepared_certificates_ca -- --test-threads=1` | **0** |
| revert-R06 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked driver_cleanup_failure_is_retried_until_clean -- --test-threads=1` | **101** |
| restore-R06 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked driver_cleanup_failure_is_retried_until_clean -- --test-threads=1` | **0** |
| revert-R07 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked unfinished_cleanup_after_slot_files_removed_is_retried_until_clean -- --test-threads=1` | **101** |
| restore-R07 / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked unfinished_cleanup_after_slot_files_removed_is_retried_until_clean -- --test-threads=1` | **0** |
| revert-R09-result.json / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **101** |
| restore-R09-result.json / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **0** |
| revert-R09-intent.json / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **101** |
| restore-R09-intent.json / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **0** |
| revert-R09-request-hash.txt / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **101** |
| restore-R09-request-hash.txt / PROBE | `cargo test -p heimdall --test e2e_consumer_m03 --locked existing_access_ensure_bytes_match_base_goldens -- --test-threads=1` | **0** |
| revert-R07-retry / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked unfinished_cleanup_after_slot_files_removed_is_retried_until_clean -- --test-threads=1` | **101** |
| restore-R07-retry / PROBE | `cargo test -p heimdall-runtime --test recheck_internal --locked unfinished_cleanup_after_slot_files_removed_is_retried_until_clean -- --test-threads=1` | **0** |
| adapters / WT | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked` | **0** |
| store / WT | `cargo test -p heimdall-testkit --test integration_store_m03 --locked` | **0** |
| diff-check / WT | `git diff --check e566cc46..HEAD` | **2** |
| issuer-store-child / WT | `cargo test -p heimdall-issuer --test integration_issuer_store --test integration_issuer_child --locked` | **0** |
| clippy / WT | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **0** |

**Interpretation of nonzero exits:**

- `revert-*` exits 101 are expected regression failures, except the first `revert-R07`, which was a compile failure and supplies no regression evidence. `revert-R07-retry` compiled and failed the intended cleanup assertion. Every associated `restore-*` run exited 0.
- `S01-admission` disables descriptor equality at admission; `S01-approval` disables equality at approval. `S02` reintroduces foreign bytes in StoredReading. `S03` disables issuer stopping and managed-wiring clearing. `R01` disables at-use and scheduler end cleanup; `R02` skips consumer restoration; `R03` skips follower materialization. `R05-intent` skips early intent creation; `R05-recovery` disables the managed uncertain-recovery arms. `R06` skips the early intent and managed failure cleanup path. `R07[-retry]` frees slot metadata immediately after clearing its files. `R08` skips the binding-release slot transition. `R04-comparison` skips snapshot invalidation; `R04-ca` ignores the prepared certificate CA. `R09-*` independently perturbs the named expected bytes. These are selected behavioral reversions, not a wholesale revert of the interdependent commit.
- `new-probes` first reproduced C01 but its C02 scheduling assertion failed before the intended check. `new-probes-r2` reproduced both findings. `new-probes-final` reproduced both again, adding the fresh-preparation refusal control for C02.
- The first `base-golden` attempt reused current-head workspace artifacts in the shared target directory and failed compiling the old ceremony against the newer request shape. Removing only this review's workspace fingerprint cache forced a real base rebuild; `base-golden-rebuild` then passed. The cache was invalidated again before returning to fixed-head validation. No base product API was patched to make this pass.
- `diff-check` exit **2** is one trailing space in the committed integrator note `tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r3-worklog-C2.md:36`. It is not a Rust correctness finding, and it was left unchanged.

Other executed setup/inspection commands:

| Command / operation | Exit / observed result |
|---|---|
| `git -C <repo> worktree add --detach /tmp/hm-recheck-m03w4/wt 4866642d` | **0** |
| `git rev-parse HEAD e566cc46`, `git log --oneline e566cc46..HEAD`, `git diff --stat/--name-only e566cc46..HEAD` | **0**; exact revisions pinned, 81 changed files |
| Targeted `git diff`, `rg`, `sed`, `nl`, `cat` over the changed crates/tests/schemas, spec/plan, rulings and then notes | Inspection batches completed; one attempted `rg` path (`crates/runtime/src/enrollment.rs`) did not exist (rg **2**), resolved by reading the host in service.rs. Initial memory search found no relevant Heimdall entry and supplied no review evidence. |
| `cargo --version`, `rustc --version`, `uname -s` | **0**; Rust/Cargo 1.99.1, Darwin |
| `git archive HEAD ...` and `git archive d6593a7c ...`, each piped to `tar -x` in its own scratch source copy | Archive **0**, tar **0**, both copies |
| Python scratch helper/probe generation, selected-mutation restoration, cache invalidation and selective log inspections | **0**; source restoration checked byte-for-byte. Final comparison: **zero differing Rust source files** between PROBE and WT after removing the probe test additions. |
| `git status --porcelain`, `git rev-parse HEAD` before cleanup | **0**, clean; head unchanged |
| Python exact-identity final process audit | **0**; **2,112** distinct PID/start/executable identities tracked, **zero remaining** |
| `du -sh target` | **0**; 13 GB at the observed checkpoint, removed with the checkout |
| `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | **1**; no matching prototype output directories. Independent Python glob inventory was empty. |

## Process and data hygiene

No Docker fixtures, remote machines, public listeners or owner's credential stores were used. Real SSH used disposable loopback sshd, generated fixture keys/CA, scratch SSH configuration and known-host files, and isolated/decoy agent endpoints. No owner's keys, agents, ~/.ssh, Git configuration, login keychain or 1Password were test targets.

The process monitor sampled descendant trees and rechecked each captured exact PID with its start time and executable. Across all 49 recorded command runs, the captured identities included **487 sshd/session processes, 113 ssh processes, 3 heimdall processes, 15 runtime-integration/issuer harness identities, 9 issuer-child harness identities and 19 live-managed harness identities**. All 2,112 captured identities were absent at the final audit. This is an exact-identity audit of captured descendants, not an exhaustive OS spawn trace; very short-lived children can fall between samples. Source inspection additionally verified synchronous child output/wait paths and owned-handle teardown. The lifecycle regressions explicitly capture their issuer PID/start token and have cleanup guards that verify that token before terminating a failed test's child. I did not issue a blanket-name/pattern kill or manually stop any process.

The two scratch probe functions were appended to existing live-test modules only in PROBE, using the setup described under C01/C02. They did not alter production code. All mutation sources were restored; the scratch additions, source snapshots, logs, fixture material and build output are removed at cleanup. No private key or generated canary value is retained in this report.

## Limits

- Native Windows/WSL/Linux execution, real platform secure stores/session locks, second-user socket/pipe isolation, reboot/logout/sleep and the Win32 trace-row recording were not run. Windows enrollment/pipe source was reviewed only; the native run and trace row belong to the orchestrator.
- U12's issuer-deletion CLI implementation is out of scope. Scratch deletion helpers and the runtime confirmation contract were exercised; no real keychain/1Password/platform-store deletion was attempted.
- This was a bounded re-check of the wave-4 fixes and consequential paths, not a full historical security audit or exhaustive interleaving/fuzz campaign. Full workspace tests/check.sh were not run; the selected targets and workspace Clippy above were run.
- The observed follower counterexample changes the client at a deterministic commit boundary. Additional host-key/CA/expired-evidence follower combinations and the cancelled-owner variant were source-traced, not separately reproduced.

## Cleanup confirmation

`git -C <repo> worktree remove --force /tmp/hm-recheck-m03w4/wt` exited **0**. Python then removed only this review's known BASE/PROBE directories, helper/probe files and captured logs, and removed the now-empty `/tmp/hm-recheck-m03w4` with `rmdir` (**0**). A Git worktree inventory confirmed the detached checkout is no longer registered; both checkout and scratch root are absent. The build output (13 GB at the observed checkpoint, subsequently also used by Clippy) and scratch credential material are gone. Final pre-removal status was clean at the pinned SHA. A report identifier/secret-marker check passed; captured logs contained zero canary-prefix or private-key-header occurrences. Only `/tmp/hm-recheck-m03w4-report.md` remains.

Not checked: native Windows/WSL/platform stores and U12's deletion CLI; see the scoped limits above.
Risk: fix the reproduced scope-minimum bypass and released-binding cleanup gap before merging.
