fix first — M04-FX-RC01, M04-FX-RC02

Scoped independent re-check of `474fa92e..39f48be87267d0dc78c09b2685c585ac74b09a12`, first-parent diff. The candidate is a merge with second parent `518f5c79`. M03-only changes were identified with `git diff --name-only 474fa92e...518f5c79` and excluded; the exact list is in `m03-excluded.txt`. Shared files were inspected only for their M04 hunks. This is one fix-round re-check, not a new full-wave review.

Host: macOS arm64; `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. Read original W2 R01–R04, AGENTS.md, ADR-0009 §2.1 and amended ADR-0010 §§10–11. No further agents were used: this task is the independent review sub-agent itself.

1. R01 — incomplete; blocking finding RC01 below.

The straightforward original attack setup is now refused. I reran `mode_b_answers_paths_only_through_a_verified_unreplaced_tree`: a nonsticky 0777 base returns `wsl_bridge_run_dir_unsafe`; the test then makes the base safe, realizes a binding, replaces the anchor and checks that re-realization refuses the planted tree and binds no replacement socket. Exit 0, 1 passed. The historical standalone patch named in w2.md is not present in this commit; this is its shared-base/anchor-replacement scenario through the committed regression, supplemented by my independent real-helper exploit below.

For paths without intervening symlink target chains, `secure_chain` checks the supplied base and all lexical ancestors through `/`, then the canonical base and all its ancestors. Root or the real helper effective UID may own them. Group/other write is refused unless sticky. On Linux, a POSIX access ACL's effective group-class permissions are represented by the mode's group mask, so an effective named-user/group write grant makes this check fail; named read grants do not enable replacement. Sticky protection is meaningful because each traversed directory/entry is also required to have a trusted owner. The 0700 anchor/run/binding directories themselves come through ManagedDir's owner/mode/no-child-symlink checks. Native Linux ACL cases were source-analyzed, not executed here.

`ManagedDir::identity()` uses fstat on the pinned directory handle and compares its device/inode to symlink_metadata of the binding directory path. It compares the intended directory, not a config file or an unrelated parent. The pre-write and post-bind checks catch a changed pathname at those instants. They cannot protect a returned path after the last check, or a swap and restoration between checks: that protection depends on the complete nonreplaceable ancestor guarantee. RC01 breaks that guarantee for intermediate symlink targets. The new checks do not make a missing part of the chain safe.

Independent exploit `probe-symlink.rs` runs the real helper loop and Bridge, accepts an unsafe nested-symlink chain, connects to the legitimate socket, replaces a pivot in a shared nonsticky parent after the answer, then reads the planted configuration through the already returned path. Fully isolated `/usr/bin/ssh -F <returned config>` executes its harmless marker ProxyCommand and exits 255. Cargo exit 0, 1 passed. A later realize refuses the changed identity, but the previous answer has already executed the planted command. This is a pathname/permissions proof on one account, not a native second-UID execution.

2. R03 — incomplete; blocking finding RC02 below.

The production WslExeLauncher now performs a fresh Running listing before `linux_helper_path` (the `wslpath` command) and another before spawning the helper. Bridge::start delegates to launch_under so it no longer relies on its old single stale snapshot. I found no additional start-capable wsl.exe call inside that Mode B production launch. Listing commands themselves do not start a distribution. This assessment covers Mode B relaunch, not a renewed review of Mode A.

The supervisor enforces the two-Running-listings/one-recheck delay on its normal tick path and permanently blocks after RunningState::NotRunning/Unknown or SessionError::NotRunning from the pre-launch listings. A successful Allowed start clears that flag; Forbidden success does not explicitly clear it. The existing seven Mode B live tests pass, including the two-listing regression.

However, discovery failure returns early, a first missing GUID continues early, and both preserve the old Running observation without setting the block. My missing-GUID probe demonstrates an unattended Forbidden relaunch after one absent discovery, without another owner ensure. A separate probe demonstrates that WslRealizer::run_dir calls ensure_bridge(Forbidden) and launches even after a stopped listing set the block, without the two-listing delay. Endpoint creation/recovery calls this same entry point; the guarantee is enforced at tick rather than at the shared launch boundary. Both probes exit 0, 1 passed each; they assert the erroneous launch rather than asserting the intended refusal.

The amended contract owner's ruling expressly accepts the remaining stop-after-final-listing race. I did not re-raise that accepted residual. Real Windows cold-start behavior remains blocked here.

3. R02 — corrected for the three requested paths.

`realize_still_wanted` performs the generation/membership post-check for ensure_bridge's relaunch replay, realize_again's re-check, and WslRealizer::realize's first realization. A binding no longer desired at that generation is withdrawn again; first realization also returns wsl_binding_withdrawn. This reuses the existing registry and generation semantics. `wsl_mode_b_withdrawal_during_a_relaunch_leaves_no_endpoint` passes as part of the seven live tests. Withdrawal errors remain best-effort as before; no stronger durability claim is inferred.

4. R04 — corrected.

`sh_word` leaves only nonempty ASCII alphanumeric and `/._-` paths plain; otherwise it single-quotes the entire argument and escapes each embedded quote as POSIX shell `'\''`. Raw descriptor paths remain unchanged. The committed real-Git regression passed with spaces and an embedded single quote. I temporarily extended its config filename with `$(false);&|<>` and backtick command text; the real Git/inert scratch-ssh argument check again passed (exit 0, 1 passed). These tokens reached the scratch ssh as part of one config argument. No network client was used by that Git probe. The fixed container descriptor remains unchanged.

5. Windows fixes — no state-directory weakening found; native execution blocked; harness cleanup gap RC03.

- `platform.rs` changes diagnostics, exposes the existing DACL fact reader and adds a refusal case; the state-directory acceptance predicate is unchanged. The integration test now constructs its own legacy stock list, still checks migration/content retention, and adds the inherited foreign-reader refusal. The file-inheritance assertion replaces an error-swallowing unwrap_or fallback with mandatory exact facts: same owner, one Allow ACE for the user, inherited, and unprotected. It does not weaken the directory predicate. It does not independently assert every bit of the file ACE's access mask; that preexisting coverage limit is not a new acceptance of foreign access.
- The handle-probe name now derives the actual module path rather than matching zero tests. The added alias fixture makes setup apply actually require the intended decision. Existing owner-state comparisons remain, with added comparisons after fixture setup. The A13 restart expectation changes in line with the explicitly amended R03 contract, rather than relaxing it silently.
- Both harnesses' icacls arguments name only their newly allocated run root; the per-test stock_profile_list helpers name their own scratch parents. They remove inheritance and grant the user, SYSTEM and Administrators their stock inheritable full control. No profile or parent directory is an icacls target.
- The renderer joins in-container paths with `/` independent of host and still validates the resulting RenderPath. Empty or slash-containing names are refused. Both container tests pass on this host; actual Windows rendering is not natively verified.
- Startup recovery uses the same open-plus-unresolved operation query, setup-kind/recovery-intent/distribution filters and de-duplication as before. It now reads the IDs inline and only spawns a driver when nonempty. Each selected ID still reaches lead_local_setup. Query/drive failures keep the former warning-and-retained-obligation behavior. I found no newly skipped pending operation in this extraction; operations cannot arrive through the still-unopened control endpoint before this startup snapshot. This does not prove Windows database handle release natively.
- The Mode B harness selects unregister targets from its created-name list, the strict exact-name pattern, the before-set and the current registered set. It uses no wildcard unregister or global shutdown. Normal cleanup and each step's catch/finally structure are sound after ownership is recorded. Ownership recording is not cancellation/failure safe across import; see RC03. Therefore the requested “every exit path, including Ctrl-C” guarantee is not established. PowerShell self-test: exit 0, 22 passed. No actual import, unregister or Ctrl-C native WSL run occurred here.

6. Commands, exits, counts and own revert proof.

Setup: `git fetch origin m04/w2`, `git checkout --detach 39f48be87267d0dc78c09b2685c585ac74b09a12`, `git rev-parse HEAD`: all exit 0; HEAD exactly the requested full SHA. Scope inspection used `git diff --stat 474fa92e 39f48be8`, scoped `git diff 474fa92e 39f48be8 -- <M04 paths>`, and `git diff --name-only 474fa92e...518f5c79`; all were executed. Source inspection additionally used cat, sed, rg and nl. A few guessed-path/no-match inspections returned nonzero and were corrected; they are not validation claims.

Cargo used only this checkout's ./target with no target-dir override or cargo clean. The runner sets TMPDIR to the one scratch root; existing test harnesses also have self-cleaning hardcoded /tmp fixtures. Output was captured and sanitized before being saved/displayed. Commands and sanitized logs are in commands.jsonl and the named .log files.

| Log | Command | Exit | Counts / observation |
|---|---|---:|---|
| wsl | `cargo test --locked -p heimdall-wsl` | 0 | test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s; test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s |
| container | `cargo test --locked -p heimdall-localenv --lib container` | 0 | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 97 filtered out; finished in 0.00s |
| live | `cargo test --locked -p heimdall-runtime --lib managed_store::live_tests::wsl_mode_b` | 0 | test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 74 filtered out; finished in 1.13s |
| channel | `cargo test --locked -p heimdall --test integration_wsl_helper_channel` | 0 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.73s |
| platform | `cargo test --locked -p heimdall --test e2e_platform_m04` | 0 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.99s |
| integration | `cargo test --locked -p heimdall-runtime --test integration_runtime` | 0 | test result: ok. 60 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 2.62s |
| harness-selftest | `pwsh -NoProfile -NonInteractive -File tests/native/m04/run-mode-b-windows.ps1 -SelfTest` | 0 | selftest: 22 passed, 0 failed |
| symlink-probe | `cargo test --locked -p heimdall-wsl review_probe_nested_symlink` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out; finished in 0.04s |
| missing-probe | `cargo test --locked -p heimdall-runtime --lib review_probe_missing_listing` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 81 filtered out; finished in 0.16s |
| r01-attack-refused | `cargo test --locked -p heimdall-wsl mode_b_answers_paths_only_through_a_verified_unreplaced_tree` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.04s |
| r01-safeguard-removed | `cargo test --locked -p heimdall-wsl mode_b_answers_paths_only_through_a_verified_unreplaced_tree` | 101 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.04s |
| r01-safeguard-restored | `cargo test --locked -p heimdall-wsl mode_b_answers_paths_only_through_a_verified_unreplaced_tree` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.04s |
| blocked-bypass-probe | `cargo test --locked -p heimdall-runtime --lib review_probe_forbidden_run_dir` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 81 filtered out; finished in 0.04s |
| r04-metacharacters | `cargo test --locked -p heimdall --test e2e_platform_m04 git_ssh_command_carries_a_config_path_with_spaces_as_one_argument` | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.06s |
| import-recording-probe | `pwsh -NoProfile -NonInteractive -File review-out/probe-import.ps1` | 0 | 1 control-flow assertion passed |
| import-recording-probe | `pwsh -NoProfile -NonInteractive -File review-out/probe-import.ps1` | 0 | 1 control-flow assertion passed |
| final-diff | `git diff --exit-code` | 0 | No unstaged tracked changes |
| final-index | `git diff --cached --exit-code` | 0 | No staged changes |
| final-status | `git status --short` | 0 | Only ?? review-out/ |
| final-head | `git rev-parse HEAD` | 0 | 39f48be87267d0dc78c09b2685c585ac74b09a12 |
| prototype-size | `bash -c du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype output directories |
| target-size | `du -sh ./target` | 0 | 7.4G ./target |

The six requested commands report **98 passed, 0 failed, 2 ignored**. Across the additional Rust test commands there are **104 passing test executions and one intentionally failing test execution** in total, including duplicates/revert runs; these are not 104 distinct tests. The two libtest-ignored entries are `fd_hygiene::detached_spawn_probe` and `u8b::launcher_child_service`, child-process entry points intended to be re-executed by their parent tests; the top-level ignored count does not itself establish whether each child ran. The PowerShell self-test adds 22 passing checks. The mocked import-recording probe is one control-flow assertion, run twice while refining its failure model; both exit 0. Its final model uses an empty unreadable post-import registration listing; no Windows operation occurs.

Own revert proof: saved linux.rs bytes, changed only `if !secure_chain(&base, self.shared.uid)` to `if false && !secure_chain(&base, self.shared.uid)`, ran the committed R01 regression, restored the bytes and reran it. The mutant compiled and failed the unsafe-base refusal assertion with exit 101 (0 passed, 1 failed): unwrap_err received a successful Realized answer. Restored: exit 0 (1 passed). It was an assertion failure, not a build failure. Restoration hashes and byte-for-byte HEAD comparisons for all four temporarily edited tracked files are in restoration.json.

Findings

M04-FX-RC01 — High; blocking; incomplete M04-W2-R01.

Location: `crates/wsl/src/bridge/linux.rs:144`–155 (secure_chain), especially canonicalize at line 152.

Scenario: `<safe>/link -> <shared>/pivot -> <safe>/good`, with `<shared>` nonsticky 0777, both symlinks initially owned by the user, and `<safe>/good/state` private/safely owned. Use `<safe>/link/state` as the base. Lexical lstat checks see link and the resolved state; canonical ancestors see good/state. Neither checks shared, because canonicalize erases the intermediate pivot. The helper accepts and returns paths. Another Linux account able to search shared can remove its pivot without entering the original private tree and replace it with a symlink to its own prebuilt tree. The returned ssh_config now names the attacker's ProxyCommand. Both identity checks have already passed; the owner can consume the descriptor before the next re-check. My probe executed a harmless owner-context marker command through exactly that returned path (SSH 255; Cargo 0, 1 passed).

Smallest correction: fail closed on symlinked components in the base's lexical chain, or securely resolve each symlink expansion while validating every directory traversed, including intermediate target parents. Keeping only lexical plus fully canonical checks is insufficient. Retain a nested-symlink regression that redirects a previously returned config. Under ADR-0009 §2.1 this blocks: another account can execute owner-context configuration and affect owner data/remote trust.

M04-FX-RC02 — Medium; blocking; incomplete M04-W2-R03.

Locations: `crates/runtime/src/wsl_bridge.rs:499`–520 (unreadable/absent discovery exits), `:327` (ensure_bridge shared start path), `:613`–615 (Forbidden run_dir), `:628` (Forbidden realize).

Scenario A: lose a helper while Running; one tick records running_since. One discovery omits the GUID, then the same GUID returns. The missing branch continues without blocking/resetting running_since; after one re-check the supervisor spawns a replacement without the owner's ensure. A discover error similarly returns without changing that state. The probe records exactly that unauthorized continuation (Cargo 0, 1 passed).

Scenario B: a stopped listing has set relaunch_blocked. Once the distribution runs again, a Forbidden WslRealizer::run_dir caller immediately starts a helper through ensure_bridge; neither relaunch_blocked nor running_since is checked there. Endpoint creation uses that method (`crates/credential/src/endpoints/wsl.rs:266`), including the adapter's create-binding effect used by recovery. My direct entry-point probe recorded a second Forbidden helper despite the block (Cargo 0, 1 passed); I did not run a complete runtime-restart recovery scenario.

Smallest correction: place the Forbidden relaunch admission check at the shared helper-start boundary, covering endpoint recovery as well as ticks; mark and reset the block for every unreadable/absent discovery result before returning/continuing. Keep Allowed owner ensure as the authorized release of that block. Preserve the already accepted final-listing residual. This blocks under ADR-0009 §2.1: the amended owner-consent rule explicitly requires cancellation until ensure after an absent/unreadable/stopped observation, and ordinary transient discovery errors/recovery can bypass it. This is not a claim that a native WSL cold start was observed.

M04-FX-RC03 — Low; nonblocking harness cleanup defect introduced by the new harness.

Locations: `tests/native/m04/run-mode-b-windows.ps1:570`–574 (recording after import), `:700`–702 (cleanup only considers recorded names), `:721`–722 (unconditional install-directory deletion).

Scenario: import successfully registers the first disposable distribution; the following Get-Registered call fails or returns no readable names, or Ctrl-C interrupts before created.Add. The import's name is absent from created. The finally block never selects it for unregister, although it can detect a changed registered set later. It then attempts to delete the distribution installation directory anyway. The supplied PowerShell control-flow probe executes the actual import/ownership-recording statements with a simulated successful import and empty unreadable listing, and confirms that the registered name has no cleanup candidate (exit 0, 1 assertion). Native interruption itself was not tested.

Smallest correction: reconcile the exact pending import and its scratch installation identity from a per-import finally, so outer cleanup knows what was registered even when normal import bookkeeping was interrupted. Keep before-set/pattern/identity restrictions, and retain an installation directory if unregister has not succeeded. Add a failure-path self-check at this boundary. It does not meet ADR-0009 §2.1's blocking test here: the affected data/distribution is the harness's disposable fixture, and no owner's preexisting distribution was shown touched.

Files, validation and limits

Tracked files changed: none. Temporary probes touched only linux.rs, channel_tests.rs, wsl_mode_b.rs and wsl_mode_b_m04.rs; each matches HEAD byte for byte, including the index. `git diff --exit-code` and `git diff --cached --exit-code` both exit 0. `git status --short` exits 0 and shows only `?? review-out/`. Added report, DONE, runner/probe sources, saved byte snapshots, command ledger, restoration hashes and sanitized logs are all under review-out. No commit, push or PR.

The single manually created `/tmp/hm-recheck-*` scratch root was removed; no other manual deletion was performed. Existing test temp fixtures clean themselves on drop. `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` exited 1 because none of those prototype output directories exists. `du -sh ./target` exited 0 and reported 7.4G. Target and review-out were retained exactly as the task required; the orchestrator owns worktree cleanup.

Every direct real-SSH probe invocation used a scratch -F config, disabled identity/certificate/agent defaults, supplied scratch known-hosts plus GlobalKnownHostsFile=/dev/null, disabled multiplexing, and removed SSH_AUTH_SOCK. No direct heimdall invocation or cargo run was made; requested test harnesses invoke their built binaries with fixture homes. No owner keys, agents, keychains, password manager or ~/.ssh were selected by my probes. No external network probe was run; requested E2E coverage uses its loopback fixture sshd.

Native Windows: blocked — native Windows unavailable on this Mac. Native WSL: blocked — no wsl.exe or WSL distributions here. Native Linux ACL/second-account exploitation, real WSL interop/cold-start behavior, Windows DACL/DPAPI/handle behavior, and real Ctrl-C/import cleanup remain unverified. Mocks and Mac tests do not close those claims. I did not run the full workspace/check.sh or devbox gates for this read-only scoped re-check. The concrete remaining merge risks are RC01's owner-context configuration execution and RC02's incomplete consent gate; RC03 is recorded separately as nonblocking.
