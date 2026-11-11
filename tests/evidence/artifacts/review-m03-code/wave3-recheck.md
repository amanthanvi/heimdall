# M03 wave-3 independent re-check

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`). This re-checks `3f7a582e..5ee3e143`, the fixes for W3-R01 to R11, W3-S01 to S05 and W3-N01, in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.20 items 15 and 16.

**Verdict: fix first.** The exercised production fixes address the original Unix failure modes. Two verification/fixture defects remain: the new panic cleanup still leaks masters when its store lookup fails, and both green full connection runs leave server-side processes; the symlink regressions also pass when the relevant refusal is removed. See **W3-C01** and **W3-C02**. I found no additional confirmed production defect introduced by this patch. Native Windows and Linux claims remain unverified by this Mac run.

Reviewed `3f7a582efb4519fe44fe73b392eada20763ffa7e..5ee3e143747ca47e93c80de8cdfa807f935cc078` (the latter's direct parent is the former), using the requested detached checkout. Host: Darwin arm64; Rust `1.99.1 (58cf8f9c3 2026-10-13)`; OpenSSH `10.5p1`, LibreSSL `3.3.6`.

I read the original findings, ADR-0008 §17.20, the diff and affected implementations/tests, and formed my assessment before reading `m03-wave3-r2-brief.md`, `m03-wave3-r2-questions.md`, and `m03-wave3-r2-worklog.md`. The integrator's claimed results are context only; the observations below are my executions.

Repository edits: **none**. No commit or push. The sole retained deliverable is this report. Reversion experiments changed disposable source copies under `<scratch>/probe`, never the detached repository. That non-Git mirror reused the checkout's Cargo output through a `target` symlink. Each experiment restored its source afterward; a final byte comparison found no un-restored Rust source. The independent reversion experiments below remove the minimum relevant fix, rather than pretending to have reverted the whole commit with its incompatible API changes.

All source line references below are to **5ee3e143**, even if the working branch later changes. Links point into the owner's repository for navigation, not to an edited working copy.

## Original findings

“Observed” means executed in this review. “Inferred” means assessed from source. A passing Mac test does not close a native Windows/Linux claim.

| Finding | Assessment and evidence |
|---|---|
| **W3-R01** | **Resolved on the reviewed slot paths.** `write_generation` rejects older markers and same-generation different holders. `write_slot_locked` re-reads the authoritative slot before publishing. `ManagedSlotTable::claim`, materialization and pair clear share the effects' per-pair lock, including across clones. Observed: `stale_generation_write_never_rolls_back_the_slot` and `slot_claim_and_clear_are_serialized` pass. Independently removing the marker fence, store check, or claim lock makes the appropriate test fail with exit 101. This covers resurrection after a clear as well as a newer marker. Binding-file writes retain their resource-generation marker fence; U10 must continue to carry distinct slot and resource receipts. |
| **W3-R02** | **Resolved.** The signer stores `(binding,generation)` per pair. Pair clear uses `unmaterialize_pair`; binding-resource clear no longer unlists slots. Observed: the rematerialized generation-2 listing and another pair's listing survive stale/unrelated cleanup. Restoring binding-wide unlisting in either clear path fails the new regressions (101). |
| **W3-R03** | **Resolved for the exercised single-supervisor lifecycle.** One path lock spans replacement, generation choice, readiness and recording; nested replacement-close uses `have_lock=true`, avoiding self-acquisition. Readiness checks the answering master PID against the spawned child, checks child liveness and rereads the socket identity. Close requires inode, PID and start identity before `-O exit`; otherwise it uses the verified-process path. Observed: concurrent starts reserve different generations; stale close leaves the foreign replacement alive; deleting either corresponding guard reproduces the original failure (101). Native Linux still needs its own run. |
| **W3-R04** | **Resolved on exercised restart paths.** `restart_bound` incorporates the grant, ancestors, cutoffs and persisted wall bound; the pass additionally obtains accepted time and calls `TimeGate::admission` for the continuous budget. Missing/uncertain facts close the master. Observed: an otherwise Active grant whose deadline passed during downtime closes its master; no ordinary session succeeds afterward. A state/facts-only keep decision reproduces the original keep (101). Parent/cutoff/budget branches were source-reviewed, not separately fault-injected in this pass. |
| **W3-R05** | **Resolved.** `start_context` checks pair scope, effective owned-masters policy, slot holder and slot generation. `record_master` repeats this after awaited spawn work and compares context. Observed: non-holder and out-of-scope requests leave the holder's master intact; transferring the slot during spawn kills the unrecorded child and leaves no row/socket. Removing the holder check or recording-time recheck independently fails the relevant regression (101). Policy revalidation is inferred from the shared `start_context` call; I did not separately race policy disablement. |
| **W3-R06** | **Resolved.** `check_prepared` requires `valid_after <= now < valid_before`, and refuses absent/mismatched install validity. `compute` bounds both usable/offline times by the shortest certificate; required offline coverage beyond that refuses. Observed: short, expired, future and unknown-start cases pass the regression; restoring deadline-only report coverage fails (101). I did not individually mutate every validity subbranch. |
| **W3-R07** | **Resolved.** Wording uses U8's shared `deadline_wording` with actual selection/policy and adds the owned-master disclosure only where applied. The golden covers undetermined, nonexclusive, exclusive, masters and Windows behavior. Observed: golden passes; restoring the old unconditional wording fails (101). |
| **W3-R08** | **Resolved.** Aggregate clock selection uses lag + RTT + age-dependent drift at report observation time, with missing/overflow bounds conservative. Observed: the review's arithmetic counterexample, both orders, unknown and overflow cases pass; restoring the old sort key fails (101). |
| **W3-R09** | **Resolved in source; Linux-native execution blocked.** The second Unix signal now repeats start/image verification, retaining the Linux pidfd mechanism. Observed on Mac: a process that execs another image during TERM grace returns Pending and survives; removing the second verification reproduces Closed/SIGKILL (101). This emulates the old Linux omission on Mac; it is not a Linux pidfd test. |
| **W3-R10** | **Root test weaknesses addressed in source; native verification blocked: Windows unavailable.** The registration fixture still uses the `fake_agent` mechanism, not an actual managed credential instance, but explicitly retains a real grant gate in `Operations::SigningGates` and contends on it. It therefore exercises the formerly skipped shared-gate branch; it is not evidence of the deferred managed workflow. The non-SSH test now launches through the real `heimdall run`, inspects the child's immediate job, and checks a surviving grandchild. It accepts an inherited enclosing job only if the launcher is also in it. See the native obligations below; no Windows execution or reversion is claimed. |
| **W3-R11** | **Resolved on the reviewed pass APIs.** Enumeration errors become `DiscoveryFailed`/`PassResult`, preserving partial results; per-path failures remain explicit. Restart and uncertain-time discovery fail explicitly, as does Windows reap enumeration in source. Observed: fault injection refuses discovery and retry closes the process; swallowing `close_for` discovery failure again returns an empty success and fails the test (101). |
| **W3-S01** | **Resolved; same root as R04.** Independently reran the expired-while-absent scenario against fixed code and its keep-only reversion. Fixed code closes the master and refuses a post-deadline ordinary session. |
| **W3-S02** | **Resolved in the exercised scenario, with the ruled residual.** The mux directory is verified owner-only; start unlinks an unproven entry before establishing its own master, without signalling the foreign process. End/slot cleanup has the explicit `clear_slot_path` entry point for U10. Observed: a real foreign master is replaced at the namespace entry, remains alive, and ordinary SSH after revocation performs a new authentication rather than reusing it; a subsequently planted socket is removed on slot-path cleanup. Restoring occupied-path refusal instead of removal fails (101). The fixture intentionally still has valid direct credentials: its new-authentication counter proves loss of mux reuse, not production signer revocation. Existing foreign sessions remain `not_controlled`, as ruled. |
| **W3-S03** | **Resolved; same control-path root as R03.** Observed the real `-O stop`, replacement-master, old-row-close probe. Fixed code closes only the old process; removing the control proof kills the unrelated replacement and fails the regression (101). |
| **W3-S04** | **Production correction resolved on Mac, but regression isolation incomplete: C02.** Writes, clears and enumeration below the managed roots use verified handles; parent/leaf symlinks and unsafe permissions are refused. Removal parks a verified regular single-link owned file in quarantine and calls `remove_verified`. Observed: all original security scenarios and an added owner-only symlink-target variant pass on fixed code. Removing permission verification fails (101). Removing child-directory no-follow alone incorrectly leaves the committed integration and unit regressions green; the owner-only-target variant catches it (101). Windows DACL/reparse behavior is source-reviewed only. |
| **W3-S05** | **Resolved; same root as R01.** Observed generation-2 publication followed by delayed generation-1 publication: marker and bytes remain generation 2. Marker/store/claim-lock reversions each fail the relevant regression (101). |
| **W3-N01** | **Protocol correction resolved in source and host simulation; ext4-native re-run blocked: Linux unavailable.** The rewritten test deliberately places N+1's inode tuple in N's locator, then checks stale closes through both existing and fresh supervisors preserve N+1. It no longer assumes inode numbers differ. Observed: test passes; removing the newer-open-generation check fails “generation N+1's socket kept” (101). This is an intentional inode-equality protocol test, not an actual ext4 allocation experiment. |

## New findings

### W3-C01 — Medium: fixture cleanup still leaks processes on both success and store-failure unwind

**Locations:** [World::drop, connections.rs:224](<repo>/tests/integration/connections.rs:224), especially the `.unwrap_or_default()` at line 235 and direct-child-only cleanup at line 239; [dedicated remote command, connections.rs:701](<repo>/tests/integration/connections.rs:701).

**Observed, twice for the successful full suite and once for the failure path.**

1. The unmodified full `integration_connections` target passed all 39 tests twice. At completion, the first run left exact PIDs **36171, 36190, 36195, 36351, 36566** running `sleep`; the restored repeat left **44928, 44930, 44936, 45080, 45139, 45548**. These were descendants observed from those test runs, not a search for similarly named processes. No surviving SSH master was observed from either green run. The World tracks client `Child` handles and stored masters, but does not account for all loopback-server command descendants; stopping a client or the listener does not guarantee those commands terminate. This is a remaining fixture-hygiene gap, not a newly reproduced production revocation failure, and not proof that the sleeps were introduced by this commit.
2. In a disposable probe using the unchanged fixed implementation, I started a master, then deliberately panicked. With the store readable, master **44492** was cleaned and the descendant audit was empty. Repeating after arming the fixture's `BeforeTransaction` failure leaked recorded master **44528** (start token **1794403228.708976**) and its fixture session descendants **44529, 44532**. `World::drop` turns the failed row lookup into an empty vector and consequently never calls `stop_exact` for that master. The `Starting` guard cannot help: the successfully recorded child has already left it.

The new cleanup therefore does not establish its “a panicking test leaks none” claim, and the requested full-suite zero-process check fails despite a green test exit. Retain independent fixture-owned PID/start/image receipts for cleanup when the store cannot be read; track disposable server command processes as well. Cleanup must remain exact-identity based. I stopped the review-owned residuals by exact PID after fresh start/executable checks. A final audit found **zero remaining observed exact identities**, including zombies. No pre-existing process was stopped.

### W3-C02 — Medium: symlink regressions are masked by unsafe target permissions

**Locations:** [integration planted-directory fixture, managed_adapter.rs:4437](<repo>/tests/integration/managed_adapter.rs:4437) and its clear target at line 4462; [managed-directory unit test, managed_dir.rs:546](<repo>/crates/localenv/src/sys/managed_dir.rs:546).

**Observed mutation-surviving regression gap; not an exploit of the fixed implementation.** Both fixtures create symlink targets without setting owner-only permissions. On this host the unit target was explicitly measured as **0755**. Replacing the new `ManagedDir::child` no-follow open with this following open, while retaining ownership/mode verification, makes both committed tests still pass:

```rust
rustix::fs::openat(
    dir, name,
    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
    rustix::fs::Mode::empty(),
).map_err(std::io::Error::from)
```

The permission check rejects the followed 0755 target, masking the missing symlink protection. If the planted link points to another owner-only directory, the reverted implementation accepts it and writes outside the managed root. I set the disposable integration victims to **0700**: the unchanged fixed implementation passed (exit 0), and the same no-follow-only reversion then failed at the first write refusal assertion (exit 101, write returned `Ok`). The regular committed integration regression and the unit regression had each returned 0 with that reversion.

Set the symlink targets explicitly to 0700 before testing parent/leaf traversal, and keep the 0777 refusal as a separate case. Assert an actual no-follow failure independently of permission refusal. This makes the regression fail for the security boundary it claims to test, as required by the round-2 acceptance rule.

## Other requested checks

- **Lock-order review (inferred, with executed concurrency regressions):** I found no lock-order cycle in the changed call graph. Adapter work holds one per-pair lock at a time; store calls, file-global locking and signer operations do not retain an inner guard and acquire that same outer lock in reverse. Runtime replacement uses the already-locked close helper; the live-map guard is released before later slot acquisition. Both concurrent-start and claim/clear regressions passed, and both fail with their outer lock removed. This is not exhaustive schedule exploration or proof about future U10 callbacks.
- **Removal/signal ownership:** the item-6 namespace unlink is intentionally broader than owned-process signalling. It is restricted to a computed direct child of the verified mux directory, refuses directories, rereads entry identity before unlink, and reports the foreign-listener removal. The real foreign-master probe shows it is not signalled. I found no additional confirmed cross-namespace removal introduced by these changes. The final check/unlink and check/control windows remain pathname operations, not an atomic exclusion against arbitrary same-user filesystem mutation; I did not execute an adversarial namespace-swap stress test.
- **M02 quarantine/removal guards:** `ManagedDir::remove` reads identity/digest on a handle, checks regular/owned/single-link shape, parks the name with a no-replace rename, and invokes `QuarantineDir::remove_verified`. It does not add a direct unlink. The unchanged `production_code_never_unlinks_outside_quarantine` and `own_sources_never_remove_outside_the_quarantine` tests passed, as did identity/content mismatch, name substitution, symlink substitution and recovery-row checks. All 142 selected M02 tests passed. I found no regression in those guards.
- **Insertion invariant:** the store now rejects holder-less dedicated rows, and `register_owned_connection` gives `binding_unknown` before the gate for that case. The production master insertion writes its process resource and validates `owned_row_invariant` in the same transaction. The master-resource check is at that supervisor insertion path, not a universal restriction in `Txn::insert_owned_connection`; the store test deliberately still permits fixture master rows without resources. I found no other production master-insertion path bypassing the supervisor check. Observed: 28 store tests and 57 narrowing tests pass; independently removing either new dedicated guard fails its regression (101).
- **Contract example:** the sole example value change is the binding endpoint locator `\\.\pipe\heimdall-0011223344556677-b0123456789abcdef`, JSON-escaped in the file, not P's rendered spelling or the environment signing endpoint. The golden compares consumer output without mapping, the contract checks the binding token/tag form, and all 89 contract tests pass. No schema change.
- **Missing terms:** source now refuses absent terms rather than defaulting to Continue. The `revoke_on_lock_grant_without_terms_never_reports_verified` regression passed in both full adapter runs. I did not independently revert this additional item-14 guard.

## Windows-native obligations

Status: **blocked — native Windows is unavailable on this Mac.** No cross-compile or macOS test result is counted as native evidence. Source inspection found no additional concrete Windows implementation defect, with the fixture qualification for R10 above.

A native run at this exact head must show:

1. `cargo test -p heimdall --test e2e_deadline_m03 --locked windows::windows_register_while_suspended_under_gate -- --exact`: the real retained grant gate is contended; holding it beyond `signing_gate_wait` refuses registration, leaves no row and never resumes/authenticates the suspended child; releasing it while registration waits permits one row/authentication only after release. The fixture is a launch binding with an actual holder. For strict literal compliance with item 12, replace or explicitly accept the fake-agent-with-real-gate fixture; this is not a complete managed-credential workflow.
2. `cargo test -p heimdall --test e2e_deadline_m03 --locked windows::windows_non_ssh_run_has_no_job_object_by_default -- --exact`: the real non-SSH `heimdall run` child has no Heimdall-created job; with no enclosing job, `IsProcessInJob` must be false. Under an ambient harness job, its immediate job must also contain the launcher. The deliberately surviving grandchild must outlive normal launcher exit and then be cleaned by its exact PID/creation identity. A negative mutation adding a kill-on-close child job must make it fail.
3. `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_dir_windows_refuses_inherited_dacl_and_junction -- --exact`: inherited/non-owner-only managed-directory DACL and junction cases refuse with `managed_dir_unsafe`, do not write outside, and the newly created protected-directory positive case succeeds. Also run the whole target: creation, replacement, clear, enumeration and reading by the same user's real `ssh.exe` need native evidence, not just the one fixture-format write. Mutation checks must independently exercise DACL and reparse refusal.
4. The two rewritten Windows tests' intended regressions must fail with their relevant guards reverted. None of those Windows reversions was executed here.

## Commands and exit codes

All Cargo/test/probe subprocess exits were captured by a scratch Python audit wrapper. It set `TMPDIR=/tmp`, captured sanitized output, and sampled **PID, PPID, start time, executable and state only**, following the spawned command's descendants. No process-name search was used to select a cleanup target. Short-lived descendants can escape polling; the counts below are observed identities, not an assertion that every transient command was sampled.

Setup: `git -C <repo> worktree add --detach <scratch>/wt 5ee3e143` → **0**. `git rev-parse`, commit/parent checks, `git log 3f7a582e..HEAD --oneline`, `git diff --stat/--name-only 3f7a582e...HEAD`, and focused source/diff reads established the reviewed revision. Final `git diff --exit-code 5ee3e143 --`, cached diff and porcelain status → **0**, empty output.

Read-only inspection used `cat`, `sed`, `nl` and `rg` over the original reports, ADR/spec/plan, changed source and tests; no edit command was run in the checkout. Preflight read the active home/project instructions and review/Ponytail skills. The memory keyword search returned **1**, no relevant hits. An initial `cat wave3-security.md` at repository root reported no such file; I corrected it to `tests/evidence/artifacts/review-m03-code/wave3-security.md`. One attempted `quarantine/*.rs` inspection had a zsh no-match diagnostic and was replaced by reading the actual `quarantine.rs`. Those compound inspection calls did not capture each constituent command's exit separately; they are not claimed as successful individual checks.

The following table records every Cargo invocation executed by the audit wrapper. `wt` means the unchanged detached checkout; `probe` means the disposable non-Git source mirror. Repeated original commands are included because their cleanup results matter. The wrappers/scripts themselves restored sources and exited 0 even when an intentionally failing Cargo child returned 101; the table gives the **Cargo child** status.

| Run | Directory | Command (TMPDIR=/tmp) | Exit |
|---|---|---|---:|
| `fixed-adapters` | wt | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked` | **0** |
| `fixed-clippy` | wt | `cargo clippy -p heimdall-adapters -p heimdall-runtime -p heimdall-localenv -p heimdall-credential -p heimdall-app -p heimdall-store -p heimdall-contract -p heimdall-launch -p heimdall --all-targets --locked -- -D warnings` | **0** |
| `fixed-connections` | wt | `cargo test -p heimdall-runtime --test integration_connections --locked` | **0** |
| `fixed-contracts` | wt | `cargo test -p heimdall-contract --test contracts --locked` | **0** |
| `fixed-e2e` | wt | `cargo test -p heimdall --test e2e_deadline_m03 --test e2e_run_m02 --locked` | **0** |
| `fixed-m02` | wt | `cargo test -p heimdall-localenv --test integration_projection_replace --test integration_projection --test integration_projection_recovery_rows --locked` | **0** |
| `fixed-narrowing` | wt | `cargo test -p heimdall-runtime --test model_narrowing_m03 --locked` | **0** |
| `fixed-signer` | wt | `cargo test -p heimdall-credential --test integration_managed_signer --locked` | **0** |
| `fixed-store-corrected` | wt | `cargo test -p heimdall-testkit --test integration_store_m03 --locked` | **0** |
| `fixed-store` | wt | `cargo test -p heimdall-store --test integration_store_m03 --locked` | **101** |
| `hygiene-dedicated` | wt | `cargo test -p heimdall-runtime --test integration_connections --locked unix::strict_closes_dedicated_connection_at_deadline -- --exact --nocapture` | **0** |
| `restored-adapters` | wt | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked` | **0** |
| `restored-connections` | wt | `cargo test -p heimdall-runtime --test integration_connections --locked` | **0** |
| `restored-managed-dir` | wt | `cargo test -p heimdall-localenv --lib --locked sys::managed_dir::tests` | **0** |
| `revert-invariant-register` | probe | `cargo test -p heimdall-runtime --test model_narrowing_m03 --locked registration_refused_for_a_binding_no_launcher_holds -- --exact --nocapture` | **101** |
| `revert-invariant-store` | probe | `cargo test -p heimdall-testkit --test integration_store_m03 --locked dedicated_owned_connection_needs_the_binding_holder -- --exact --nocapture` | **101** |
| `revert-n01-generation` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::master_socket_removed_only_if_same_inode -- --exact --nocapture` | **101** |
| `revert-r01-claim-lock` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked slot_claim_and_clear_are_serialized -- --exact --nocapture` | **101** |
| `revert-r01-marker` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked stale_generation_write_never_rolls_back_the_slot -- --exact --nocapture` | **101** |
| `revert-r01-store` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked stale_generation_write_never_rolls_back_the_slot -- --exact --nocapture` | **101** |
| `revert-r02-binding-clear` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked stale_clear_never_unlists_the_current_binding -- --exact --nocapture` | **101** |
| `revert-r02-pair-clear` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked clearing_one_pair_keeps_the_other_pairs_listing -- --exact --nocapture` | **101** |
| `revert-r03-control` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::stale_close_never_controls_a_replacement_listener -- --exact --nocapture` | **101** |
| `revert-r03-lock` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::concurrent_starts_of_one_slot_are_serialized -- --exact --nocapture` | **101** |
| `revert-r04-restart` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::restart_closes_master_whose_deadline_passed_while_absent -- --exact --nocapture` | **101** |
| `revert-r05-holder` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::start_master_refused_for_non_holder -- --exact --nocapture` | **101** |
| `revert-r05-postspawn` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::slot_transfer_during_spawn_leaves_no_recorded_master -- --exact --nocapture` | **101** |
| `revert-r06-coverage` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked coverage_never_exceeds_the_shortest_certificate -- --exact --nocapture` | **101** |
| `revert-r07-wording` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked report_for_local_managed_binding_with_empty_claim_table -- --exact --nocapture` | **101** |
| `revert-r08-clock` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked aggregate_clock_is_the_weakest_now -- --exact --nocapture` | **101** |
| `revert-r09-signal` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::process_that_execs_another_image_during_grace_is_not_killed -- --exact --nocapture` | **101** |
| `revert-r11-discovery` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::pass_discovery_failures_are_explicit -- --exact --nocapture` | **101** |
| `revert-s02-unproven` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::foreign_master_at_stable_path_never_serves_after_revocation -- --exact --nocapture` | **101** |
| `revert-s04-permission` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `revert-s04-symlink` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **0** |
| `review_cleanup_normal_panic` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_cleanup_normal_panic -- --exact --nocapture` | **101** |
| `review_cleanup_store_failure_panic` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_cleanup_store_failure_panic -- --exact --nocapture` | **101** |
| `symlink-private-fixed` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **0** |
| `symlink-private-reverted` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `symlink-unit-mode` | probe | `cargo test -p heimdall-localenv --lib --locked sys::managed_dir::tests::symlinks_and_open_directories_are_refused_never_repaired -- --exact --nocapture` | **0** |
| `symlink-unit-reverted` | probe | `cargo test -p heimdall-localenv --lib --locked sys::managed_dir::tests::symlinks_and_open_directories_are_refused_never_repaired -- --exact --nocapture` | **0** |


The initial `heimdall-store --test integration_store_m03` invocation (101) was a command-selection error, not a test failure: Cargo identifies `heimdall-testkit` as that target's host. The corrected command passed 28 tests.

Fixed-tree results: connections **39/39 twice**; managed adapter **46/46 twice**; projection **112**, replacement **29**, recovery rows **1**; store **28**; narrowing **57**; contract **89**; deadline E2E **1**; M02 run E2E **54** plus one child-mode entry ignored; managed signer **37** plus one blocked second-account test ignored; new managed-directory unit tests **2**. Strict selected-package `cargo clippy --all-targets --locked -- -D warnings` returned **0**. The Mac deadline E2E's single passed test does not run any Windows body.

### Reversion meaning and observed failure

All guard removals were performed in `probe` and restored. Fixed versions passed in the original/restored host suites, except the Windows cases, which were not run.

| Reversion label | Minimum fix removed / observed result |
|---|---|
| `r01-marker` | Removed `write_generation` marker fence: stale write returned Ok; **101**. |
| `r01-store` | Removed `write_slot_locked` current-holder/generation match: a cleared old publication returned Ok; **101**. |
| `r01-claim-lock` | Removed claim's pair-lock acquisition: clear ran between CAS and publication; **101**. |
| `r02-pair-clear` | Pair clear restored binding-wide unlisting: other pair listing became empty; **101**. |
| `r02-binding-clear` | Binding clear restored binding-wide unlisting: current generation-2 listing became None; **101**. |
| `r03-control` | `-O exit` restored to old start-token-only check: replacement master was killed; **101**. |
| `r03-lock` | Removed start's path-lock acquisition: both generations were 1; **101**. |
| `n01-generation` | Replaced stale-removal protocol with inode-only removal: N+1 socket disappeared; **101**. |
| `r04-restart` | Replaced fresh-time/admission decision with persisted facts only: master was kept, closed list empty; **101**. |
| `r05-holder` | Removed slot-holder check: non-holder start returned an owned master; **101**. |
| `r05-postspawn` | Removed recording-time context re-read: transferred-slot start returned a recorded master; **101**. |
| `r06-coverage` | Restored deadline-only coverage: 22:00 claimed instead of 10:15; **101**. |
| `r07-wording` | Restored unconditional old wording: qualified golden mismatched; **101**. |
| `r08-clock` | Restored lag/RTT-only sort: stronger A chosen over drift-weakened B; **101**. |
| `r09-signal` | Removed second Unix image/start verification: exec'd process Closed instead of Pending; **101** on Mac, not native Linux. |
| `r11-discovery` | Swallowed `close_for` discovery error: empty Ok instead of DiscoveryFailed; **101**. |
| `s02-unproven` | Restored occupied-entry refusal without removal: foreign-master scenario stopped at mux_path_occupied; **101**. |
| `s04-permission` | Removed child-directory owner-only verification: 0777 directory accepted; **101**. |
| `s04-symlink` | Removed only child no-follow behavior, retained mode check: committed integration regression **0**, the C02 false negative. |
| `symlink-unit-reverted` / `symlink-unit-mode` | Same no-follow reversion: committed unit regression **0**; explicit measurement reported target 0755. |
| `symlink-private-fixed` / `symlink-private-reverted` | Set integration victim directories to 0700: fixed code **0**; no-follow reversion **101**, outside-root write accepted. |
| `invariant-store` | Removed dedicated holder requirement: holder-less insert accepted; **101**. |
| `invariant-register` | Removed pre-gate holder refusal: error became Unavailable(store), not binding_unknown; **101**. |
| `review_cleanup_normal_panic` | Intentional panic after recorded master: Cargo **101**, no surviving observed descendant. |
| `review_cleanup_store_failure_panic` | Same panic with fixture store fault armed: Cargo **101**, one SSH master and two session descendants survived; C01. |

The full fixed suites reran the security review's practical scenarios: expired-while-absent master, real foreign listener, real stopped/replaced listener, planted directories and delayed old write. The additional owner-only-target and panic probes distinguish their actual failure mechanisms. I did not merely copy the integrator's red/green table.

## Limits and cleanup

Not checked: native Windows, native Linux/ext4/WSL, DPAPI/login keychain/1Password, owner SSH material or agents, real session lock/sleep/logout/reboot, Docker fixtures, a full-workspace check.sh/test run, every possible scheduling interleaving, or an adversarial same-user pathname-swap stress run. No Docker fixture was started. Managed production preparation/install authorization, verification signatures, managed connect, run slot-table wiring and Windows dispatch remain the explicitly deferred U10 work; their absence is not a finding. No release gate is claimed closed.

Build output was reused in the checkout and reached **8.8 GB** before cleanup. The required `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` attempt returned **1** because the checkout contains no matching prototype output directories (zsh no-match); no such build directory was created. Final tracked/index/untracked status was clean. Scratch-source restoration comparison returned **0**, no differences. The final exact-identity process audit returned **0** with an empty remaining set. The audit is bounded by the identities it observed; it does not claim system-wide absence based on names.

Cleanup completed:

- Removed the review-created probe mirror, scripts, redacted logs and PID records (87 scratch entries) before removing the checkout: Python cleanup **0**.
- `git -C <repo> worktree remove --force <scratch>/wt` → **0**; this removed the shared target output with the detached checkout.
- `rmdir <scratch>` → **0**.
- Final report/absent-scratch assertion → **0**. The report is the only retained review artifact.

Skipped native Windows/Linux and deferred U10 end-to-end workflows; no cross-platform gate is closed.
Risk: fixture cleanup and isolated symlink-regression coverage still need correction before this re-check can recommend merge.
