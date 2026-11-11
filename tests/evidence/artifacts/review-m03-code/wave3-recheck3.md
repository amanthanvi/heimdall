# M03 wave 3, round 3 independent re-check

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`). This re-checks `5ee3e143..155d2f6c` (round 3), in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.20 items 16 and 17.

**Verdict: fix first.** W3-C02 and the umask-002 fixture fix are resolved on this Mac. W3-C01's ordinary-run and store-failure cases now pass, but command-process ownership still has a pre-exec/pidfile gap: **W3-C03 (medium)** below. This is a fixture-cleanup defect, not an observed production authorization or revocation defect.

Reviewed **155d2f6cfc77867b72b93d90378b0099b584d4eb**, parent **5ee3e143747ca47e93c80de8cdfa807f935cc078**, using the requested detached checkout. `rustc` and `cargo` both reported **1.99.1**. No repository source, index, branch, Git configuration, commit or remote was changed.

I assessed the code diff before reading the integrator's worklog. My initial assessment was: all changes are tests/documentation; the private targets should remove the symlink-test masking; the umask child/control design is valid; and the ignored image-wait result plus pending-pidfile disposal needed independent probes. I then read the prior re-check, ADR-0008 §17.20 items 15–16, and the worklog as context. Their reported results are not counted as results of this review.

## W3-C01 — not fully resolved

The fixture now keeps independent PID/start-token/image receipts for successful master starts, client children and collected remote commands. A failed store read no longer removes already-held master receipts. Masters and remote commands use `stop_exact`, with start checks before/after pinning and image verification; direct children are killed/waited through their `Child` handles. The fixture's existing sshd and disposable agent own their direct children separately. I inspected every `start_master` call site in the target; successful direct starts have explicit tracking.

Observed at the unchanged reviewed head:

- Full `integration_connections` run 1: **40 passed, exit 0**; **70 distinct fixture receipts**, **0 exact-identity survivors**. The independent descendant sampler plus receipts covered 260 identities, including build processes.
- Full run 2: **40 passed, exit 0**; **70 distinct fixture receipts**, **0 exact-identity survivors**. The sampler plus receipts covered 155 identities.
- Both full runs include the new `panic_with_store_failure_leaks_no_process` regression.
- Independent uncaught-panic probe: started a master and a session through it, armed `BeforeTransaction`, asserted the store read failed, then panicked. Cargo returned **101 for that deliberate panic**, and all **three receipts**—master, client, server command—were gone afterward. The external audit found no surviving sampled descendants either. This reproduces the previous review's store-failure unwind rather than relying only on the new catch/join regression.

Those results resolve the original observed green-run leaks and store-dependent master cleanup in their exercised paths. They do **not** establish that the fixture stops every command it starts. The intended “receipt only once the image is `/bin/sleep`” rule is not enforced on timeout, and a command can also escape the receipt entirely; see C03.

## W3-C02 — resolved on macOS

The integration targets are explicitly 0700, and the unit target is demonstrably acceptable: its root opens and its ordinary child can be created. The tests require a symlink refusal rather than accepting a permission refusal. The separate 0777 refusal case remains. Leaf-write coverage and victim-entry preservation assertions were added; no existing refusal assertion was removed without an equivalent or stronger replacement.

I repeated the exact no-follow mutation in a disposable **non-Git source mirror**, retaining all ownership and mode checks:

```rust
rustix::fs::openat(
    dir, name,
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC,
    rustix::fs::Mode::empty(),
).map_err(std::io::Error::from)
```

Results:

| Mutation scope | Regression outcome |
|---|---|
| Every `ManagedDir::child` open follows | Integration **101**: `parent write: a planted symlink was followed: Ok(())`. |
| Same mutation, unit regression | **101**: `the link was followed: Ok(Some(ManagedDir ...))`. |
| Follow only child named `h1` | **101**: `leaf clear: a planted symlink was followed: Ok(())`. |
| Follow only child named `00112233aabbccdd` | **101**: `binding clear: a planted symlink was followed: Ok(())`. |
| Follow only child named `b` | **101**: `planted b: a planted symlink was followed: Ok(())`. |
| Restored implementation | Integration **0**, unit **0**, one test executed in each. |

The selective mutations let the test reach the later leaf, `b/<tag>` and planted-`b` cases instead of stopping at its first parent assertion. These were assertion failures after successful compilation, not build failures.

## Umask fix — resolved, with a creation-mode coverage limit

The anchors used by the managed-adapter tests and managed-directory unit tests are explicitly owner-only. This matches production's final anchor permissions without weakening `ManagedDir::open_root`.

Executed on this Mac:

- `sh -c 'umask 002; exec cargo test -p heimdall-adapters --test integration_managed_adapter --locked'`: **46 passed, exit 0**.
- `sh -c 'umask 002; exec cargo test -p heimdall-localenv --lib --locked'`: **89 passed, exit 0**.
- `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors -- --nocapture`: **2 passed, exit 0**.

The parent test launches `/bin/sh` with `umask 002 && exec "$0" --exact umask_anchors::umask_child_entry ...`, passing only the scratch home as its fixture variable. The child creates `control` with the default directory mode; the parent requires **0775**. Its passing control assertion is evidence of the child's effective umask, independently of the production directory-mode checks. The test also checks all four fresh directories are 0700, both managed anchors open, existing owned 0775 anchors become 0700, and a subsequent loosening is refused without repair.

Independent mutations of `Paths::ensure`'s Unix helper:

| Mutation | Exit and meaning |
|---|---|
| Remove the handle-based tightening, retaining final validation | **101**. The older-install child fails with `PermissionDenied`; the parent fails its child-success assertion. |
| Create with 0777 and remove tightening | **101**. The fresh-install child fails. |
| Create with 0500, retain tightening | **101**. Fresh `config` fails the exact-0700 assertion. |
| Create with 0777 only, retain tightening | **0**. Tightening repairs the resulting 0775 directory before return. |
| Restore both mechanisms | **0**. |

Thus the test catches broken final permissions and broken existing-directory repair. **It does not independently detect overly broad creation flags when tightening repairs them.** It proves postconditions, not that a fresh directory was never briefly permissive. I have not described the 0777-only mutation as a detected regression. Production's creation mode and tightening code are unchanged by round 3 and remain correct in the inspected source.

## New finding

### W3-C03 — Medium: command cleanup loses ownership before the expected image/pidfile is ready

**File/lines:** [connections.rs:563](<repo>/tests/integration/connections.rs:563), especially the unconditional receipt at line 570; and [connections.rs:572](<repo>/tests/integration/connections.rs:572), reached from drop's zero-bound collection.

**Observed under deterministic scheduling-fault probes.** The probes changed only their own remote command strings in the disposable mirror; `collect_remote`, `World::drop`, `receipt` and `stop_exact` were unchanged.

1. **After pidfile, before exec.** I used the fixture's generated command, inserting the shell builtin `kill -STOP $$` between its existing PID-file write and `exec /bin/sleep 40`. This holds the exact fixture shell at the vulnerable transition. `collect_remote` waited five seconds, ignored its false result, and recorded that shell's PID/start token with the expected `/bin/sleep` image. I armed the store failure and forced an unwind. Drop refused to signal the actual `/bin/zsh` because its image did not match the receipt. The shell survived. The probe then stopped it by its verified start token and **actual** image before failing its explicit no-survivor assertion (**101**). The observed shell was PID **75146**, start token **1794405328.884500**; it was fixture-owned, not found by a name search.
2. **Before the fixture pidfile.** A second probe wrote its shell identity to a separate review-owned pidfile and stopped the shell immediately before executing the fixture's original PID-write/exec command. The fixture's pending pidfile did not exist. A normal, **non-panicking** `drop(w)` drained the pending entry and discarded it at `None if bound.is_zero()`, cleaned its master and client, and **passed its receipt survivor audit**. The shell nevertheless remained alive. After exact-identity cleanup, the probe failed its explicit assertion (**101**). Drop recorded only two receipts, so its audit had no remote-command identity to inspect.

These are injected stalls, not leaks observed in the two ordinary green runs. They demonstrate the unhandled timeout/pre-receipt states; a sufficiently delayed command can reach the same states. `/bin/sleep`'s 40-second bound starts only after exec, so it does not bound the pre-exec shell demonstrated here. Simply lengthening the wait, asserting its result, or skipping a mismatched-image receipt would leave the ownership problem on the failure path.

**Required correction:** account for the server command's whole lifecycle, including failure/panic before its normal pidfile or image is ready. Preserve an exact owned identity and clean it safely through the shell-to-sleep transition, or otherwise prove the pending command cannot run after teardown. Treat image-wait failure explicitly. Keep a regression that delays the command on both sides of the pidfile and proves no exact identity survives, including normal drop's audit.

Both probe-owned stalled shells were stopped through the existing exact-identity verifier using their actual observed images. No owner process was stopped. All post-probe external audits were empty.

## Product scope and Windows source review

Round 3 changes **no product code**. The only production-source file in the diff, `crates/localenv/src/sys/managed_dir.rs`, changes its test module only. The other code changes are in connection, managed-adapter, runtime and Windows E2E tests. I found no assertion weakened in the changed tests. Remote commands now run for 40 seconds instead of 60/120; both full connection targets completed in about 9.5 seconds, with the relevant live-session assertions still exercised. This is not evidence for arbitrarily slow hosts.

**Windows-native execution: blocked — this host is macOS, not native Windows.** Source inspection supports the intended changes, but closes no Windows claim. A native run at this exact head must show:

1. `cargo test -p heimdall --test e2e_deadline_m03 --locked windows::windows_register_while_suspended_under_gate -- --exact`: a held retained grant signing gate refuses registration after timeout without resuming/authenticating the suspended child, and release while waiting permits registration only afterward. The added documentation accurately qualifies this as the real registration gate with a `fake_agent` grant; a complete managed-credential workflow remains U10.
2. `cargo test -p heimdall --test e2e_deadline_m03 --locked windows::windows_non_ssh_run_has_no_job_object_by_default -- --exact` with the real E2E binary configured: with no ambient job, the launched child's `IsProcessInJob` observation must be false; with an ambient job, its immediate job must also contain the launcher. The grandchild must outlive normal launcher exit and then be stopped by the new PID/creation-time/image guard, with the final liveness assertion false. Exercise both ambient-job forms and a negative mutation adding a child job. The guard is installed after the receipt is read; source inspection does not prove cleanup if the child fails before producing a readable receipt.
3. `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_dir_windows_refuses_inherited_dacl_and_junction -- --exact`: the inherited-DACL case still refuses; the junction points at a directory created and verified through `ManagedDir::child`, with Heimdall's protected DACL; refusal specifically names a **reparse point**, and the target stays empty. The ordinary positive case must succeed. Independently removing the reparse guard while retaining DACL checks must make this case fail; independently removing DACL refusal must fail its separate case. Run the complete managed-adapter and localenv suites natively as well.

## Commands and exit codes

All test/probe/clippy commands below ran with `TMPDIR=/tmp`. A scratch Python wrapper captured the actual child exit, stored output locally, sampled descendant **PID/PPID/state/image/start token only**, and combined these with `HM_U7_RECEIPTS`. It used `proc_pidinfo(PROC_PIDTBSDINFO)` for exact macOS start tokens and `proc_pidpath` for image identity. No raw process arguments, authentication configuration, owner keys, environment dumps or name-based cleanup were used. Sampling can miss transient processes; receipt coverage and deterministic probes are reported separately from sampled coverage.

`wt` = unchanged detached checkout. `probe` = disposable non-Git source mirror under the requested scratch root. They reused one review-created build tree. An initial probe invocation unexpectedly reused the original test binary through the shared build cache and executed **zero tests**; it is explicitly listed and is **not evidence**. I invalidated only the review-created local Cargo fingerprints before switching mirrors, reran the probe, confirmed one test ran and the intended panic occurred, and did the same invalidation before final original-checkout clippy. Every later red/green test listed executed one test unless its stated filter selected a suite.

| Run | Location | Command | Exit |
|---|---|---|---:|
| `connections-1` | wt | `cargo test -p heimdall-runtime --test integration_connections --locked` | **0** |
| `connections-2` | wt | `cargo test -p heimdall-runtime --test integration_connections --locked` | **0** |
| `adapters-umask` | wt | `sh -c 'umask 002; exec cargo test -p heimdall-adapters --test integration_managed_adapter --locked'` | **0** |
| `forced-panic` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_store_failure_unwind -- --exact --nocapture` | **0** |
| `localenv-umask` | wt | `sh -c 'umask 002; exec cargo test -p heimdall-localenv --lib --locked'` | **0** |
| `runtime-umask` | wt | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors -- --nocapture` | **0** |
| `forced-panic-rebuilt` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_store_failure_unwind -- --exact --nocapture` | **101** |
| `stalled-image` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_stalled_pre_exec_receipt -- --exact --nocapture` | **101** |
| `nofollow-all-adapter` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `nofollow-all-unit` | probe | `cargo test -p heimdall-localenv --lib --locked sys::managed_dir::tests::symlinks_and_open_directories_are_refused_never_repaired -- --exact --nocapture` | **101** |
| `nofollow-leaf` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `nofollow-binding-tag` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `nofollow-planted-b` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **101** |
| `restored-symlink-adapter` | probe | `cargo test -p heimdall-adapters --test integration_managed_adapter --locked managed_files_never_follow_a_planted_directory -- --exact --nocapture` | **0** |
| `restored-symlink-unit` | probe | `cargo test -p heimdall-localenv --lib --locked sys::managed_dir::tests::symlinks_and_open_directories_are_refused_never_repaired -- --exact --nocapture` | **0** |
| `umask-mode-0777-only` | probe | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors::production_anchors_are_owner_only_under_umask_002 -- --exact --nocapture` | **0** |
| `umask-no-tighten` | probe | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors::production_anchors_are_owner_only_under_umask_002 -- --exact --nocapture` | **101** |
| `umask-both-broken` | probe | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors::production_anchors_are_owner_only_under_umask_002 -- --exact --nocapture` | **101** |
| `umask-mode-0500-only` | probe | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors::production_anchors_are_owner_only_under_umask_002 -- --exact --nocapture` | **101** |
| `restored-umask` | probe | `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked umask_anchors::production_anchors_are_owner_only_under_umask_002 -- --exact --nocapture` | **0** |
| `stalled-before-pidfile` | probe | `cargo test -p heimdall-runtime --test integration_connections --locked unix::review_stalled_before_pidfile -- --exact --nocapture` | **101** |
| `final-clippy` | wt | `cargo clippy -p heimdall-adapters -p heimdall-localenv -p heimdall-runtime -p heimdall --all-targets --locked -- -D warnings` | **0** |


The wrappers themselves returned 0 after recording intentional failures; the table reports the **Cargo/test child** exits. The mutation runner restored all modified probe sources in `finally` blocks; all three modified mirror files were subsequently byte-compared against the unchanged checkout successfully.

Other commands:

- Requested `git -C <repo> worktree add --detach <scratch>/wt 155d2f6c` → **0**.
- `git rev-parse HEAD HEAD^`, `git diff --stat 5ee3e143 155d2f6c`, focused `git diff` reads, `rustc --version`, `cargo --version`, `du -sh crates tests docs schemas prototypes`, and source reads with `rg`, `sed`, `nl`, `cat` → successful inspection. Some were compound invocations, so constituent exit codes were not independently recorded. No output from an unexecuted command is claimed.
- Initial home-instructions read plus memory keyword search → compound **1**, because the search found no Heimdall/M03/wave3 entry; no relevant memory was used. A read-only command ending with `cat .cargo/config.toml` → **1**, file absent. A later inspection containing `crates/localenv/src/sys/process*` → **1**, zsh no match; corrected to actual `sys/mod.rs`. A search of absent `crates/localenv/src/sys.rs` reported an error; corrected to `sys/mod.rs`. These were inspection mistakes, not test failures.
- Scratch mirror/probe-script creation and mutation orchestration → **0**. These wrote only under `<scratch>/`; no tracked checkout source was edited.
- Final combined exact-identity audit across **668 sampled/recorded identities** → **0**, **zero survivors**. This audit ran after the deliberate shell probes had cleaned their owned shells.
- Final `git diff --exit-code 155d2f6c --` → **0**, empty; `git diff --cached --exit-code` → **0**, empty; `git status --porcelain` → **0**, empty.
- Required `sh -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` → **1**: no matching prototype build-output directories existed. `du -sh target` → **0**, **4.6 GB**, all review-created and scheduled for removal with the checkout.

## Limits and cleanup

Not checked: native Windows, Linux/ext4 or WSL; Windows negative mutations; a complete workspace `check.sh` run; real session lock/logout/reboot; secure stores; U10 managed-credential workflows; or exhaustive scheduling/PID-reuse exploration. No cross-compile, emulation, worklog claim or Mac success is counted as native Windows evidence. The macOS check-to-signal reuse window documented by the existing process API is unchanged. No owner SSH material, agents, login keychain or 1Password was used as test material or a test target.

Only this report is retained. Cleanup results follow.

- Removed the review-owned probe mirror, scripts, logs and PID records: **exit 0**, 54 scratch entries removed.
- `git -C <repo> worktree remove --force <scratch>/wt` → **0**, including the 4.6 GB build output.
- Removed the empty `<scratch>` with `rmdir` semantics → **0**; final absent-scratch/present-report assertions → **0**.

Skipped native Windows/Linux/WSL, full-workspace validation and deferred U10 workflows.
Risk: fixture commands can still survive before their expected image or pidfile is ready; fix W3-C03 before merging this cleanup claim.
