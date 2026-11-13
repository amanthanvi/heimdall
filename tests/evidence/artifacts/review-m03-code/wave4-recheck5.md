# Heimdall M03 wave 4, round 5 — independent re-check

**Verdict: merge.** W4-C01 and W4-C02 are resolved in the current production paths. The endpoint-rendering correction and earlier refusal of non-concrete recorded endpoints are correct. I found no new actionable defect in this diff.

Reviewed `a533fc402c3cef0b6f593d04a5155fdae9449769` over its parent `4866642dd824472c99cecbab99e1c503c8224c3b` (`m03/wave4`). Rust and Cargo were both **1.99.1**, on native macOS. This is a code-review verdict, not closure of native Windows/WSL acceptance evidence.

The diff, specification and implementation paths were assessed before reading the earlier re-check, ADR-0008 §17.22–§17.24, or round-5 notes. Notes' claimed runs were not counted as my observations. The M03 plan actually present at this head is `docs/architecture/m03-plan.md`; the supplied `docs/plans/m03-plan.md` does not exist.

**Repository files changed by this review: none.** All builds, mutations and probe additions ran only in the requested detached worktree. Probe source bytes were restored exactly before final checks. No commits, pushes, main-checkout edits, credential-store changes or remote-machine operations were performed. The only retained file is this report.

## 1. W4-C01 and W4-C02

### W4-C01 — resolved

**Observed source:**

- `crates/app/src/operations.rs:9987` calls the managed release helper inside the release transaction. `crates/app/src/operations/managed_driver_m03.rs:1073` now records a binding-specific cleanup obligation in that transaction, independently of whether the binding holds slots.
- `crates/store/src/ext_m03.rs:1522` discovers those obligations for the environment, including grants that remain live. The record/done methods at `:1542` and `:1558` use durable meta rows.
- `crates/app/src/operations/managed_driver_m03.rs:1138` clears every generation through the grant's credential-instance bound, rather than generation 1 alone.
- `crates/adapters/src/managed/effects.rs:954` additionally enumerates marked on-disk generations and the remembered materialization, attempts every clear, and verifies that no binding directory or registered binding endpoint remains.
- `crates/runtime/src/managed_store.rs:579` performs that verified cleanup; `:601` removes the durable obligation only after binding and slot cleanup succeed. Errors keep the obligation discoverable.
- The live-grant branch at `crates/runtime/src/managed_store.rs:639` cleans only released bindings. Binding clear detaches the binding, not the grant key (`crates/adapters/src/managed/effects.rs:754`). Key destruction remains conditioned on the grant ending.

**Observed execution:**

- Both new re-issued, slotless release regressions pass. The failure case keeps the obligation through repeated failed passes, then clears it after permissions recover; the referenced grant's key remains present.
- All nine tests matching `cleanup` pass, including existing slot-holder, partial-cleanup and crash/restart cases.
- An added disposable probe ran restart → re-issue → release with failed file removal → another restart → cleanup, **with and without held slots**. Both cases retained the obligation across restart, removed the files, freed slots, and retained/re-issued the referenced parent grant while the child remained usable.
- A release during re-issue, followed by cleanup in production pass order, converged with no endpoint, files or outstanding obligation.

**Inferred crash coverage:** release state and cleanup obligation commit atomically. A crash before commit leaves the release unapplied; one after commit but before immediate clearing leaves the durable obligation. Failure during clearing, or after resource removal but before recording done, remains safely retryable. Credential instances are retained, so the generation bound does not shrink. The extra on-disk and in-memory enumeration covers resources beyond the ordinary bound.

### W4-C02 — resolved

**Observed source:**

- All attached managed followers reach `stage_commit` through the durable `Reconcile = NotAttempted` classification (`crates/app/src/operations.rs:816`, `:7757`).
- `crates/app/src/operations.rs:7909` reads a follower's own scope after materialization. At `:7969`, that claim replaces historical enforcement before the caller's minimum is checked. This applies whether facts came from the leader or the stored conservative fallback.
- `crates/app/src/operations/managed_driver_m03.rs:1693` derives CAs from issuance entries attached to **installed** instances of the grant, rather than current issuance preferences or another enrollment's CA. Conflicting CAs leave the pair without a claim.
- `crates/app/src/operations/managed_driver_m03.rs:1744` reads the grant's complete pair set and catalog identities, then uses the managed adapter's source read. That runs the existing current-client/current-target comparison at `crates/adapters/src/managed/prepare.rs:261`.
- `crates/app/src/operations/managed_driver_m03.rs:1670` requires matching verified evidence under the installed CA for every pair, with `fresh_until > now` at the commit's accepted time. Missing inputs yield `unknown`.
- `crates/adapters/src/managed/prepare.rs:599` uses the same CA-specific evidence selector for fresh preparations.

**Observed execution:**

- All four submitted follower-scope regressions pass: decision-joined and coalesced followers reject invalidated evidence; a follower without the minimum reports `unknown`; unchanged valid evidence meets the minimum.
- Additional disposable joined-follower cases rejected a changed host key, changed route, missing client and missing target evaluation after the leader committed.
- Additional CA controls changed the future issuance preference after the leader committed. A follower still accepted valid evidence for its actually installed old CA, even when the new CA had no evidence. Conversely, valid evidence under the new CA did not satisfy the follower when evidence under the installed old CA was withdrawn.
- An interrupted follower resumed in the same process, with no leader-local result carried into the resumed drive, and rejected the changed client's scope evidence.
- A separate interrupted follower survived a runtime restart as an open operation. Recovery refused its lost installed key with `SERVICE_UNAVAILABLE`, committed no binding, settled the operation failed, and cleaned its binding files. It did not fall back to the leader's historical scope.

**Inferred limits:** stale evidence and missing/conflicting installed-CA cases fail the explicit predicates above; I did not separately inject every possible malformed store row. External client/target evaluation is a current snapshot, not an atomic lock on external configuration through commit. I found no path that intentionally substitutes historical leader evidence for that snapshot.

## 2. Windows foreign-removal endpoint and admission refusal

**Correct by source review and platform-independent regression; native Windows execution remains blocked.**

`crates/registry/src/plan.rs:388` exposes the existing plan's concrete-endpoint rendering rule. `crates/app/src/enrollment.rs:768` uses it for foreign removals. Both admission (`crates/app/src/operations/enrollment_m03/admit.rs:1191`) and the foreign execution image (`crates/app/src/operations/enrollment_m03/steps.rs:103`) now use that common rule.

Consequently a catalog pipe in backslash form is rendered as `//./pipe/<name>`, with the correct endpoint kind. The disclosed invocation uses the same rendered locator. This corrects the raw/rendered mismatch; it does not relax the existing-access check.

The per-step route and endpoint checks remain at `crates/app/src/operations/enrollment_m03/steps.rs:642` and `:652`. The fixture's exact rendered-endpoint comparison at `tests/e2e/enroll_m03.rs:413` and runtime validation at `crates/runtime/src/service.rs:2753` are unchanged.

The new admission refusal is appropriately earlier and fail-closed: absent or non-concrete recorded endpoints are rejected before a decision, operation or foreign record is created. The shared renderer rejects relative socket paths, dot/path-traversal components, empty pipe names, environment-derived locators and unsafe literals (`crates/registry/src/plan.rs:355`). Accepted output also satisfies `step::access_pins`' absolute-path and literal checks (`crates/registry/src/step.rs:290`), so the retained invocation fallback is not an accepting path for those invalid inputs.

**Observed:** the rendering unit regression passes, including backslash pipe normalization on macOS. The new admission e2e regression passes and asserts the refusal reason, no new foreign record/open operation, and unchanged registry. All 67 macOS enrollment e2e tests pass, including the five test names reported failing in the prior Windows run. Their macOS passes establish the shared flows, not Windows pipe behavior.

**Inferred:** normalization fixes the supplied Windows failure mechanism. An actual in-box Windows SSH/WSL-fixture rerun is still required to verify that platform result; this review does not replace it.

## 3. Reversion evidence

Each mutation was made only in the disposable worktree, retained the regression, compiled successfully unless explicitly identified as probe setup below, and was restored immediately afterward.

| Finding / behavior | Mutation | Reverted exit and observation | Restored exit |
|---|---|---|---|
| W4-C02 | Suppress applying the fresh follower claim | **101**: three failures; joined/coalesced followers accepted invalidated scope, and the no-minimum follower reported the old scope | **0**, 4 passed |
| W4-C01 generation coverage | Clear only generation 1 | **101**: both new cleanup tests failed; generation-2 endpoint/files remained | **0**, 2 passed |
| W4-C01 durable obligation | Omit recording the release obligation | **101**: both new cleanup tests failed because no obligation was listed | **0**, 2 passed |
| Windows rendering | Return the raw recorded locator | **101**: rendering unit test compared raw backslash pipe against rendered slash pipe and failed | **0**, 1 passed |
| Concrete endpoint admission | Admit any recorded endpoint without concrete rendering | **101**: admission regression received `ApprovalRequired` instead of `CapabilityUnavailable` | **0**, 1 passed |

Thus at least one reversion was independently exercised for each prior finding, with separate checks of both cleanup generation coverage and durable discovery.

## 4. New defects, leakage and test weakening

**No new actionable finding; no W4-D identifiers issued.**

The held-foreign setup is stronger: `tests/e2e/enroll_m03.rs:5182` now requires a server inspection that actually saw the expected damaged marker count, then checks `Held`. Keeping the drive result for diagnostics does not silently discard an unexpected pre-inspection failure. The registry helper at `crates/testkit/src/sshd.rs:912` rejects multiline input and verifies the append by read-back. Its seven selected fixture tests pass.

The new Windows host-key observations are deliberately observations, not acceptance tests. The actual host-key-mismatch acceptance test still requires a recorded client row (`tests/e2e/enroll_m03/windows.rs:834`) and asserts the trust error, held state, unchanged registry and absence of an accepted login/removal. No existing Windows gate was broadened in this diff. These Windows-only additions were read, not run.

Captured test/build output contained **zero canary-prefix-bearing lines**. The enrollment suite's foreign-byte journal regressions also passed. This is bounded output/test evidence, not a new exhaustive secret scan of every artifact or platform.

**Adversarial-probe adjudication:** an artificial test running `ended_slot_pass` concurrently with a paused re-issue reproduced recreated resources after cleanup had acknowledged the obligation. I did **not** classify it as a production finding: source tracing found the production re-issue and ended-binding passes awaited serially in one supervisor loop (`crates/runtime/src/supervisor.rs:734`, `:784`, `:1130`); startup re-issue also precedes that loop (`crates/runtime/src/service.rs:2453`). The control using that production order passed and retained the obligation until cleanup. If those passes are parallelized in future, they will need binding-lifecycle fencing. No production-reachable parallel-pass counterexample was established here.

## Commands and actual exits

Cargo used only the detached worktree's `./target`. No target-directory override or `cargo clean` was used. A scratch Python wrapper captured output, sanitized paths/secret-bearing lines before printing, recorded the real subprocess exit, and restored mutation/probe source in `finally` blocks.

| Executed command / context | Exit | Observed result |
|---|---:|---|
| `git -C $REPO worktree add --detach $WT a533fc402c3cef0b6f593d04a5155fdae9449769` | 0 | Requested detached checkout |
| `rustc --version`; `cargo --version` | 0 each | 1.99.1 each |
| `cargo test -p heimdall-runtime --lib follower_scope` | 0 | Initial baseline, 4 passed |
| `cargo test -p heimdall-runtime --lib cleanup` | 0 | 9 passed |
| `cargo test -p heimdall --test e2e_enroll_m03` | 0 | 67 passed, 0 ignored |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Completed on restored reviewed source |
| `cargo test -p heimdall-runtime --lib follower_scope`, scope override reverted / restored | 101 / 0 | 3 failed / 4 passed |
| `cargo test -p heimdall-runtime --lib reissued_slotless`, generation revert / restore | 101 / 0 | 2 failed / 2 passed |
| Same command, obligation revert / restore | 101 / 0 | 2 failed / 2 passed |
| `cargo test -p heimdall-app --lib foreign_endpoint`, renderer reverted / restored | 101 / 0 | 1 failed / 1 passed |
| `cargo test -p heimdall --test e2e_enroll_m03 foreign_removal_refuses_non_concrete_recorded_endpoint`, admission reverted / restored | 101 / 0 | 1 failed / 1 passed |
| `cargo test -p heimdall-runtime --lib review_ -- --test-threads=1`, first probe setup | 101 | Did not run tests: multithread test attribute lacked Tokio feature |
| `cargo test -p heimdall-runtime --features tokio/rt-multi-thread --lib review_ -- --test-threads=1`, first runnable probes | 101 | Target cases passed; artificial parallel-cleanup case failed; CA setup failed at leader, before testing follower |
| Same feature-enabled command, corrected CA setup and production-order control | 0 | 3 probe functions passed, covering multiple cases |
| `cargo test -p heimdall-runtime --lib review_reissued_release_obligation_survives_restart` | 0 | Both slot/no-slot restart cases passed |
| `cargo test -p heimdall-runtime --lib review_interrupted_follower_continuation_and_restart` | 0 | Continuation and actual harness restart cases passed |
| `cargo test -p heimdall-runtime --lib`, final restored source | 0 | 58 passed |
| `cargo test -p heimdall-store` | 0 | 20 passed; 0 doc tests |
| `cargo test -p heimdall-testkit --features fixtures,managed,app --lib sshd::` | 0 | 7 passed |
| `git diff --exit-code`; `git diff --cached --exit-code`; `git ls-files --others --exclude-standard` | 0 each | No retained changes/untracked files in checkout |
| `git diff --check` | 0 | No whitespace errors |
| `du -sh target` | 0 | 4.1 GB at intermediate inspection; 8.8 GB before removal |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | None of those prototype build-output paths existed in the detached checkout |
| `git -C $REPO worktree remove --force $WT` | 0 | Checkout and its build output removed |
| Python cleanup/registration/absence assertions | 0 | Worktree unregistered; scratch root absent |

`$REPO` denotes the original clone; `$WT` denotes `/tmp/hm-recheck-m03w4r5/wt`. The optional Tokio multithread feature was enabled only for the adversarial scheduling probes, without a manifest or lockfile edit. Final restored-source checks used the normal feature set.

The CA probe was corrected by registering/seeding the second CA **after** the leader commit. Its earlier failure let the newly seeded CA affect the leader's preparation and was a setup error, not evidence of a follower defect. The first probe compilation failure likewise proves no product behavior. Both are retained in the command accounting.

## Limits

- **Blocked: native Windows with the in-box SSH client and WSL fixture server is unavailable on this macOS host.** Windows-only tests, pipe runtime behavior and native client-trace observations were source-reviewed only. No native Windows, WSL, lock or secure-store claim is closed.
- No native Linux run, real keychain/password-manager/agent test, lock/logout/reboot test, cross-user isolation test, full workspace test suite or exhaustive fault/interleaving campaign was performed.
- The retired-evidence CA control exercised the installed-CA selection, not a concurrent cryptographic replacement of an already installed certificate between source snapshot and commit.
- The artificial parallel-pass result is reported with its topology limit above; self-review is not represented as an additional independent review.

## Cleanup confirmation

The requested forced worktree removal exited **0**. A subsequent Git worktree inventory was captured internally and checked that this checkout was no longer registered, without printing other worktree paths. The checkout was absent. A Python assertion checked the exact set of review-owned scratch files, removed them, and confirmed `/tmp/hm-recheck-m03w4r5` absent. The **8.8 GB `target`**, probe additions, helper scripts, logs and fixture runtime material are gone. No pre-existing process was stopped.

Only `/tmp/hm-recheck-m03w4r5-report.md` remains as the review deliverable.

Not checked: native Windows/WSL acceptance and platform-store/lock behavior; those evidence rows remain blocked.
Risk: the merge verdict covers this code diff and current serial supervisor topology, not completion of native platform release gates.

## Supplemental shell-invocation ledger

The tables above give the individual Cargo subprocess exits. This ledger records the surrounding setup, inspection and helper invocations as well. For a compound inspection, the exit shown is the shell invocation's actual final status; intermediate missing-path diagnostics are identified below. Long stdin helper bodies are described by their task, with their executed interpreter retained. Paths to the original clone and instruction/skill/memory roots are represented by variables so this public-safe report contains no home paths.

| # | Shell invocation | Exit |
|---:|---|---:|
| 1 | <code>pwd; test ! -f $GLOBAL_AGENTS \|\| cat $GLOBAL_AGENTS; rg -n 'heimdall\|M03\|wave4' $MEMORY_INDEX</code> | 1 |
| 2 | <code>cat $PONYTAIL_SKILL; cat $CODE_REVIEW_SKILL</code> | 0 |
| 3 | <code>rg --files docs \| rg 'm03\|0008'; sed -n '7700,8090p' crates/app/src/operations.rs; sed -n '1,250p' crates/runtime/src/managed_store/live_tests/follower_scope.rs</code> | 0 |
| 4 | <code>git -C $REPO worktree add --detach $WT a533fc402c3cef0b6f593d04a5155fdae9449769</code> | 0 |
| 5 | <code>git diff 4866642dd824472c99cecbab99e1c503c8224c3b a533fc402c3cef0b6f593d04a5155fdae9449769 --stat; git diff 4866642dd824472c99cecbab99e1c503c8224c3b a533fc402c3cef0b6f593d04a5155fdae9449769 -- crates tests/e2e; rg -n 'cleanup\|re-issu\|follower\|coalesc\|verified_server_principals\|existing.access' spec.md plan.md docs/plans/m03-plan.md</code> | 2 |
| 6 | <code>git diff HEAD^ HEAD -- crates/app/src/operations/managed_driver_m03.rs crates/runtime/src/managed_store.rs crates/store/src/ext_m03.rs crates/runtime/src/supervisor.rs crates/registry/src/plan.rs</code> | 0 |
| 7 | <code>sed -n '365,410p' spec.md; sed -n '290,325p' plan.md; rg -n 'scope\|cleanup\|release\|foreign\|endpoint' docs/plans/m03-plan.md; git diff HEAD^ HEAD -- crates/testkit/src/sshd.rs tests/e2e/enroll_m03.rs; cat rust-toolchain.toml</code> | 0 |
| 8 | <code>cargo test -p heimdall-runtime --lib follower_scope</code> | 0 |
| 9 | <code>sed -n '250,510p' crates/runtime/src/managed_store/live_tests/follower_scope.rs; sed -n '1,430p' crates/runtime/src/managed_store/live_tests/cleanup.rs; sed -n '470,710p' crates/runtime/src/managed_store.rs; sed -n '320,385p' crates/registry/src/plan.rs; rg -n 'invalidate_evidence\|read_sources\|catalog_pairs\|read_prepare_sources\|installed_cas_in\|release_binding_slots_in' crates/adapters/src/managed/prepare.rs crates/app/src/operations* crates/app/src/operations/*.rs; rg -n 'scope\|cleanup\|release\|foreign\|endpoint' docs/architecture/m03-plan.md</code> | 0 |
| 10 | <code>sed -n '470,710p' crates/runtime/src/managed_store.rs; sed -n '1460,1575p' crates/store/src/ext_m03.rs</code> | 0 |
| 11 | <code>rg -n 'reissue\|release\|failed\|retry\|without' crates/runtime/src/managed_store/live_tests/cleanup.rs; sed -n '475,760p' crates/runtime/src/managed_store/live_tests/cleanup.rs</code> | 0 |
| 12 | <code>sed -n '275,385p' crates/registry/src/plan.rs; rg -n 'fn read_sources\|fn invalidate_evidence\|fn read_prepare_sources\|fn catalog_pairs\|fn materialize_follower\|fn reissue_consumers\|fn coalesced' crates/adapters/src/managed/prepare.rs crates/adapters/src/managed.rs crates/app/src/operations.rs crates/app/src/operations/managed_driver_m03.rs; rg -n 'scope\|evidence\|client' crates/adapters/src/managed/prepare.rs</code> | 0 |
| 13 | <code>sed -n '540,590p' crates/app/src/operations.rs; sed -n '805,832p' crates/app/src/operations.rs; sed -n '3650,3715p' crates/app/src/operations.rs; sed -n '1445,1615p' crates/app/src/operations/managed_driver_m03.rs; sed -n '250,355p' crates/adapters/src/managed/prepare.rs</code> | 0 |
| 14 | <code>sed -n '630,800p' crates/app/src/operations/managed_driver_m03.rs; sed -n '790,875p' crates/adapters/src/managed/effects.rs; rg -n 'fn clear\(\|clear_binding\|binding_directories_of' crates/adapters/src/managed/effects.rs crates/adapters/src/managed/files.rs; rg -n 'existing_access\|catalog_endpoint' crates/enroll/src/*.rs</code> | 0 |
| 15 | <code>cat tests/evidence/artifacts/review-m03-code/wave4-recheck.md; rg -n '17.22\|17.23\|17.24' docs/decisions/0008-managed-credential-integration.md; cat tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r5-questions.md; cat tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r5-api.md</code> | 0 |
| 16 | <code>sed -n '4057,4208p' docs/decisions/0008-managed-credential-integration.md; cat tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r5-worklog-S.md; cat tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r5-worklog-C.md</code> | 0 |
| 17 | <code>cat (heredoc) creates $SCRATCH/run.py; python3 $SCRATCH/run.py cleanup-restored cargo test -p heimdall-runtime --lib cleanup</code> | 0 |
| 18 | <code>rg -n 'fn evidence_holds\|endpoint_valid' crates/app/src/enrollment.rs crates/runtime/src/service.rs tests/e2e/enroll_m03.rs; sed -n '740,785p' crates/app/src/enrollment.rs; sed -n '810,905p' crates/adapters/src/managed/effects.rs; sed -n '1165,1290p' crates/app/src/operations/enrollment_m03/admit.rs; cat tests/evidence/artifacts/review-m03-code/wave4-notes/m03-wave4-r5-worklog-W.md</code> | 0 |
| 19 | <code>python3 $SCRATCH/run.py e2e-restored cargo test -p heimdall --test e2e_enroll_m03</code> | 0 |
| 20 | <code>sed -n '670,725p' crates/app/src/enrollment.rs; sed -n '2738,2795p' crates/runtime/src/service.rs; sed -n '400,430p' tests/e2e/enroll_m03.rs; sed -n '625,685p' crates/app/src/operations/enrollment_m03/steps.rs; rg -n 'release_binding_slots_in\|BindingEvent::Release\|state = BindingState::Released\|released_at =' crates/app/src; rg -n 'clear\(\|fn binding_directories_of\|fn certificate\(' crates/adapters/src/managed/effects.rs crates/adapters/src/managed/files.rs; sed -n '1090,1160p' crates/adapters/src/managed/effects.rs; sed -n '400,465p' crates/runtime/src/managed_store.rs</code> | 0 |
| 21 | <code>rg -n 'restart\|recovered\|recovery\|after.*commit\|Commit\|StageHook' crates/runtime/src/managed_store/live_tests/{pipeline,mod,selection}.rs; sed -n '1,215p' crates/runtime/src/managed_store/live_tests/mod.rs</code> | 1 |
| 22 | <code>sed -n '685,790p' crates/adapters/src/managed/effects.rs; sed -n '9950,10085p' crates/app/src/operations.rs; rg -n 'struct LiveFeed\|impl LiveFeed\|fn process_opts\|fn process\(\|struct Opts\|struct Stop\|impl StageHook' crates/runtime/src/managed_store/live_tests.rs; sed -n '1,170p' crates/runtime/src/managed_store/live_tests.rs; sed -n '300,410p' crates/runtime/src/managed_store/live_tests.rs; sed -n '1,120p' crates/runtime/src/managed_store/live_tests/pipeline.rs</code> | 0 |
| 23 | <code>rg -n 'struct LiveFeed\|impl LiveFeed\|fn process_opts\|fn process\(\|struct Opts\|impl StageHook' crates/runtime/src/managed_store.rs; sed -n '1050,1250p' crates/runtime/src/managed_store.rs; sed -n '1340,1515p' crates/runtime/src/managed_store.rs; sed -n '375,410p' crates/adapters/src/managed/effects.rs; sed -n '560,615p' crates/adapters/src/managed/files.rs; sed -n '90,125p' crates/app/src/operations/enrollment_m03/steps.rs</code> | 0 |
| 24 | <code>sed -n '1530,1625p' crates/runtime/src/managed_store.rs; sed -n '1670,1815p' crates/runtime/src/managed_store.rs; sed -n '1815,1920p' crates/runtime/src/managed_store.rs; rg -n 'fn assert_no_canary\|fn append_line\|fn clear_binding_files' crates/testkit/src/lib.rs crates/testkit/src/sshd.rs crates/adapters/src/managed/files.rs; sed -n '500,555p' crates/adapters/src/managed/files.rs; sed -n '1,115p' tests/evidence/artifacts/review-m03-code/wave4-recheck.md</code> | 0 |
| 25 | <code>sed -n '260,410p' crates/runtime/src/managed_store/live_tests/selection.rs; rg -n 'fn .*enrollment\|upsert_enrollment\|seed_enrollment' crates/store/src/ext_m03.rs; rg -n 'NotAttempted\|recover\|attached' crates/app/src/operations.rs \| tail -65; sed -n '1,55p' crates/testkit/src/lib.rs; sed -n '1220,1285p' crates/runtime/src/supervisor.rs; git status --porcelain; du -sh target</code> | 0 |
| 26 | <code>sed -n '125,255p' crates/runtime/src/managed_store/live_tests/selection.rs; sed -n '320,375p' crates/runtime/src/managed_store/live_tests/cleanup.rs; sed -n '790,845p' crates/store/src/ext_m03.rs; sed -n '10760,10870p' crates/app/src/operations.rs; sed -n '6925,7005p' crates/app/src/operations.rs; sed -n '1,70p' tests/e2e/enroll_m03.rs; rg -n 'enrollment_m03\|cfg\(all' crates/runtime/src/managed_store.rs \| tail -10</code> | 0 |
| 27 | <code>python3 (stdin): inspect only PID, PPID, elapsed time and executable basename for Cargo/test processes</code> | 0 |
| 28 | <code>sed -n '695,722p' crates/store/src/ext_m03.rs; rg -n 'enum EnrollmentEventKind\|Evidence\|Verification' crates/domain/src/enrollment.rs \| head -40; sed -n '450,540p' crates/domain/src/enrollment.rs; sed -n '6700,6785p' crates/app/src/operations.rs; sed -n '455,490p' crates/runtime/src/managed_store/live_tests/cleanup.rs</code> | 0 |
| 29 | <code>cat (heredoc) creates $SCRATCH/mutations.py; python3 $SCRATCH/mutations.py</code> | 0 |
| 30 | <code>sed -n '420,635p' crates/app/src/operations/managed_driver_m03.rs; rg -n 'restore_consumers\|reissue_consumers\|instance_installed\|Installed' crates/app/src/managed/reissue.rs crates/app/src/managed/driver.rs; sed -n '1,240p' crates/app/src/managed/reissue.rs; sed -n '915,995p' crates/adapters/src/managed/effects.rs; sed -n '560,595p' tests/e2e/enroll_m03/windows.rs</code> | 0 |
| 31 | <code>sed -n '400,465p' crates/app/src/managed/driver.rs; sed -n '215,355p' crates/runtime/src/managed_store/live_tests/pipeline.rs; sed -n '830,1010p' crates/runtime/src/managed_store/live_tests/pipeline.rs; rg -n 'trait ManagedEffects' crates/app/src/ports*.rs crates/app/src/ports/*</code> | 1 |
| 32 | <code>sed -n '620,700p' crates/adapters/src/managed/effects.rs; sed -n '1,100p' crates/runtime/Cargo.toml; rg -n 'fn reissue_completed\|fn managed_end_destroy_keys' crates/app/src/operations/managed_driver_m03.rs</code> | 0 |
| 33 | <code>python3 $SCRATCH/run.py clippy cargo clippy --workspace --all-targets --locked -- -D warnings</code> | 0 |
| 34 | <code>python3 (stdin): prepare disposable review probe/helper code outside the checkout</code> | 0 |
| 35 | <code>sed -n '610,655p' crates/domain/src/enrollment.rs; sed -n '665,735p' crates/app/src/operations/managed_driver_m03.rs; sed -n '1,110p' crates/app/src/managed/driver.rs; rg -n 'reissue_pass\|async fn run_stages' crates/app/src/managed/driver.rs crates/runtime/src/supervisor.rs; git status --porcelain</code> | 0 |
| 36 | <code>cat (heredoc) creates $SCRATCH/scope-probe.rs</code> | 0 |
| 37 | <code>cat (heredoc) creates $SCRATCH/probes.py; python3 $SCRATCH/probes.py</code> | 101 |
| 38 | <code>nl -ba crates/runtime/src/managed_store.rs \| sed -n '570,615p'; nl -ba crates/app/src/managed/driver.rs \| sed -n '413,449p'; nl -ba crates/app/src/operations/managed_driver_m03.rs \| sed -n '1060,1155p'; nl -ba crates/app/src/operations/managed_driver_m03.rs \| sed -n '1648,1767p'; nl -ba crates/app/src/operations.rs \| sed -n '7890,7977p'</code> | 0 |
| 39 | <code>python3 (stdin): adjust disposable probe setup; python3 $SCRATCH/probes.py</code> | 101 |
| 40 | <code>rustc --version; cargo --version; sed -n '120,160p' crates/app/src/managed/driver.rs; nl -ba crates/app/src/operations/enrollment_m03/admit.rs \| sed -n '1183,1208p'; nl -ba crates/app/src/operations/enrollment_m03/steps.rs \| sed -n '96,109p'; nl -ba crates/registry/src/plan.rs \| sed -n '350,398p'; nl -ba crates/adapters/src/managed/prepare.rs \| sed -n '260,285p'; rg -n 'current_thread\|multi_thread\|Builder::' crates/runtime/src/lib.rs crates/runtime/src/service.rs crates/heimdall/src/main.rs</code> | 0 |
| 41 | <code>sed -n '890,938p' crates/runtime/src/service.rs; rg -n 'tokio::main\|current_thread\|Runtime::\|Builder::' crates/heimdall/src crates/runtime/src/service.rs; sed -n '700,745p' crates/runtime/src/supervisor.rs; sed -n '200,260p' crates/adapters/src/managed/prepare.rs; sed -n '320,375p' crates/adapters/src/managed/prepare.rs; sed -n '70,150p' crates/adapters/src/managed/report.rs</code> | 0 |
| 42 | <code>rg -n 'ended_slot_pass\(\|managed_reissue_pass\(' crates --glob '*.rs'; sed -n '1125,1218p' crates/runtime/src/supervisor.rs; rg -n 'after_release_m03\|end_cleanup\|after_end' crates/app/src/operations/managed_driver_m03.rs crates/runtime/src/service.rs; sed -n '940,1042p' crates/app/src/operations/managed_driver_m03.rs; sed -n '620,685p' crates/runtime/src/supervisor.rs</code> | 0 |
| 43 | <code>sed -n '744,870p' crates/runtime/src/service.rs; sed -n '2427,2468p' crates/runtime/src/service.rs; sed -n '2060,2110p' crates/runtime/src/service.rs; rg -n 'struct Txn\|fn transaction' crates/store/src/lib.rs; sed -n '455,485p' crates/app/src/operations/managed_driver_m03.rs</code> | 0 |
| 44 | <code>python3 (stdin): adjust disposable probe setup; python3 $SCRATCH/probes.py</code> | 0 |
| 45 | <code>cat (heredoc) creates $SCRATCH/restart-probe.rs, $SCRATCH/restart.py</code> | 0 |
| 46 | <code>rg -n 'hook_before\(\|stage_hook\|async fn drive\(\|fn spawn_drive\|drive_on' crates/app/src/operations.rs \| head -50; sed -n '5290,5445p' crates/app/src/operations.rs; rg -n 'recover_at_start\|recovery\|async fn recover' crates/app/src/operations.rs \| tail -25</code> | 0 |
| 47 | <code>python3 $SCRATCH/restart.py</code> | 0 |
| 48 | <code>sed -n '5870,5925p' crates/app/src/operations.rs; sed -n '5984,6025p' crates/app/src/operations.rs; sed -n '11380,11520p' crates/app/src/operations.rs; sed -n '5590,5625p' crates/app/src/operations.rs</code> | 0 |
| 49 | <code>cat (heredoc) creates $SCRATCH/follower-recovery.rs, $SCRATCH/follower-recovery.py; python3 $SCRATCH/follower-recovery.py</code> | 0 |
| 50 | <code>nl -ba tests/e2e/enroll_m03.rs \| sed -n '4700,4736p'; nl -ba tests/e2e/enroll_m03.rs \| sed -n '5160,5198p'; nl -ba crates/testkit/src/sshd.rs \| sed -n '906,938p'; nl -ba tests/e2e/enroll_m03/windows.rs \| sed -n '672,705p'; rg -n 'require_recorded_client\|windows_client_trace_row_host_key\|windows_verification_host_key' tests/e2e/enroll_m03/windows.rs; git diff --exit-code; git status --porcelain</code> | 0 |
| 51 | <code>python3 $SCRATCH/run.py runtime-final cargo test -p heimdall-runtime --lib</code> | 0 |
| 52 | <code>python3 $SCRATCH/run.py store-final cargo test -p heimdall-store</code> | 0 |
| 53 | <code>python3 $SCRATCH/run.py fixture-final cargo test -p heimdall-testkit --features fixtures,managed,app --lib sshd::</code> | 0 |
| 54 | <code>rg -n 'pub fn access_pins\|pub fn literal' crates/registry/src/step.rs; sed -n '525,580p' crates/registry/src/step.rs; git diff --check; git status --porcelain; bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'; du -sh target</code> | 0 |
| 55 | <code>sed -n '175,208p' crates/registry/src/step.rs; sed -n '285,326p' crates/registry/src/step.rs; git rev-parse HEAD HEAD^; git diff --exit-code; git diff --cached --exit-code; git ls-files --others --exclude-standard; bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'</code> | 1 |
| 56 | <code>python3 (read scratch runs.jsonl and inventory known review files)</code> | 0 |
| 57 | <code>python3 (read scratch runs.jsonl into report state)</code> | 0 |
| 58 | <code>git -C $REPO worktree remove --force $WT</code> | 0 |
| 59 | <code>python3 (verify worktree unregistered/absent; remove only enumerated review-owned scratch files; assert scratch root absent)</code> | 0 |
| 60 | <code>python3 (read pinned git blobs to verify report reference line numbers)</code> | 0 |

Inspection diagnostics: the supplied M03-plan path was absent (the first combined diff/search invocation exited 2); a later search for a nonexistent live-test module exited 1; an unmatched ports glob exited 1. Other combined inspections also printed missing guessed module paths before their final successful read. I switched to the actual module locations. The initial memory-index search returned no relevant hit (exit 1); no task conclusion relies on memory. A tool-state store attempt rejected an undefined session value after a completed cleanup test; that was not a shell/test failure, and its succeeding source read was executed afterward. The required prototype-size check exited 1 because all listed build directories were absent; the worktree's own target was measured separately and removed.

Report creation used apply_patch successfully. Final report validation and cleanup-absence assertions are recorded below.

| Final deliverable check | Exit |
|---|---:|
| `test ! -e /tmp/hm-recheck-m03w4r5` | 0 |
| Python report-content and worktree-registration assertions | 0 |

Not checked: native Windows/WSL acceptance, platform stores and lock behavior.
Risk: native release gates remain open; parallelizing the currently serial cleanup/re-issue passes would require lifecycle fencing.

