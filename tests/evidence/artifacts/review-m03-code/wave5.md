# M03 wave 5 review — U12 CLI and TUI surfaces

**Verdict: fix first.** Two purge-inventory gaps can discard unresolved remote recovery records. Issuer ceremonies also miss parts of the required confirmation contract and conditional lock disclosure. The existing suites pass, but the disposable regression probes below expose these gaps.

Reviewed `8710717a..baf2c88fb2033e668fbf2d8ae9611a60a5c076a6`, comprising `dd08b282` and `baf2c88f`. Builds and tests ran in a detached scratch worktree at the exact head, using its ordinary `target/`. Host: macOS arm64, Rust/Cargo 1.99.1, OpenSSH 10.5p1. I formed the initial assessment from the specification and changed code before reading the wave notes and ADR-0008 §17.25–§17.26. Notes are treated as implementation reports, not validation evidence.

## Findings

### W5-R01 — high — Foreign-removal records are absent from uninstall's purge inventory

**Location:** `crates/heimdall/src/uninstall_cmd.rs:221`; related `crates/app/src/operations/issuer_m03.rs:290`.

**Failure scenario:** On a replacement installation, perform a foreign system-form removal, then abandon it while the remote trust remains unresolved. Uninstall reads only `open_enrollments()` and enrollments belonging to registered issuers. The separate `foreign_removals` table has neither representation. Its record is omitted from the displayed inventory, and `enrollment_refusal()` sees an empty inventory and permits a purge without `--keep-remote-enrollments` or a bundle. The subsequent database deletion discards that recovery record. The bundle reader also enumerates only enrollments of registered CAs, so simply requiring the current bundle would not preserve it.

ADR-0008 D4 item 5 explicitly requires an abandoned foreign system-form record to retain `pending_until_line_removed` and remain listed by uninstall and the bundle. Spec §7.7 requires an inventory of managed remote changes.

**Evidence — observed guard failure; inferred final data loss:** Disposable test `uninstall_cmd::tests::review_foreign_removal_blocks_uninstall_purge` created a fresh database, inserted a foreign system-form record, transitioned it through `ManualRemovalConfirmed` to `OwnerAbandon`, and asserted its state was `Abandoned`. It then called the real `Inventory::read()` and `enrollment_refusal()` with purge enabled and no acknowledgment or bundle. The assertion that purge must be refused failed, **exit 101**. The same omission was first reproduced with a planned foreign record. I did not execute the destructive final purge; its reachable database-deletion path was reviewed.

**Suggested fix:** Enumerate outstanding foreign removals in uninstall and recovery-bundle export, including abandoned/manual-removal records and their public removal descriptors. Include them in the acknowledgment, freshness/content checks and purge guard. Add an end-to-end regression for the abandoned foreign system-form case.

### W5-R02 — high — A final state hides an unresolved late-write residual from purge protection

**Location:** `crates/heimdall/src/uninstall_cmd.rs:221`; the empty-inventory bypass is at `crates/heimdall/src/uninstall_cmd.rs:588`.

**Failure scenario:** An uncertain append is reconciled to `withdrawn`, retaining `late_write` because absence after the remote not-after has not yet been observed. `open_enrollments()` excludes the final `withdrawn` state. Although uninstall separately reads final records into `all`, it uses those only for timestamps and store-item planning; the displayed inventory and bundle requirement use `open`. Consequently a purge needs no remote acknowledgment or bundle and can erase the remaining marker/token recovery information while a late write remains unresolved.

ADR-0008 D5 §6.2's final-state row and §6.7 require that residual to remain listed until an inspect after its not-after establishes absence. A nominally final state is insufficient proof that remote recovery is complete.

**Evidence — observed guard failure; inferred final data loss:** Disposable test `uninstall_cmd::tests::review_late_write_residual_blocks_purge` seeded a registered fixture CA and a `Withdrawn` enrollment with `late_write: Some(...)`, read the real inventory, and called the purge guard without acknowledgment or bundle. The expected refusal assertion failed, **exit 101**. No private key or remote server was needed, and the final purge was not executed.

**Suggested fix:** Treat records with unresolved `late_write` as outstanding recovery obligations regardless of their lifecycle state. List the residual and require its recovery metadata to survive any purge. Test both a current not-after and a passed not-after with no subsequent absence observation.

### W5-R03 — medium — Issuer ceremonies disregard non-TTY stdin

**Location:** `crates/heimdall/src/issuer_cmd/session.rs:328`, especially the explicit stdin bypass at line 349.

**Failure scenario:** Run `issuer init` with stdin redirected from a file or `/dev/null`, while the shell still gives the process a controlling terminal. Unlike other decision flows, `ceremony()` checks only `ctx.non_interactive`, opens the controlling terminal and establishes an interactive session irrespective of `ctx.stdin_tty`. It reaches the registration prompt instead of exiting 3 without attending. The same entry handles rotation and restore.

ADR-0006 §3.1 explicitly prohibits `Attend` on non-TTY stdin; U12 requires the non-TTY case for every decision kind. Opening a controlling terminal for secret display does not amend that input rule.

**Evidence — observed:** Disposable test `issuer::review_non_tty_stdin_sends_no_registration` used the existing disposable product-store/PTY harness with a controlling terminal but closed, non-TTY stdin (`CEREMONY` wiring). The real binary reached `Type 'yes' to register this CA`, and the refusal assertion failed, **exit 101**. No affirmative answer was supplied. The existing test's case labeled `non-TTY` uses `NO_TTY`, which removes the controlling terminal too (`tests/e2e/cli_m03/issuer.rs:1089`); it therefore misses this distinction. Existing successful ceremony tests deliberately use non-TTY stdin.

**Suggested fix:** Reject ceremonies when `!ctx.interactive()` before connecting, attending or opening the store. Continue using the controlling terminal for passphrase display/input after that eligibility check. Adjust successful PTY fixtures to provide TTY stdin, and separately test redirected stdin with a controlling terminal still attached.

### W5-R04 — medium — RegisterIssuer's confirmation has no prompt timeout

**Location:** `crates/issuer/src/ceremony.rs:685`; blocking reader at `crates/issuer/src/ceremony.rs:177`.

**Failure scenario:** Start `issuer init` on a TTY and leave its registration confirmation unanswered. Ordinary CLI decisions use the 120-second bounded `prompt::ask`; this ceremony calls synchronous `Tty::read_line()` without a deadline. It stays blocked instead of returning `INTERACTION_REQUIRED`/exit 3. Rotation and restored-registration confirmations share this reader. The ordinary prompt's timeout unit tests do not cover it.

**Evidence — observed:** Disposable test `issuer::review_registration_prompt_has_120_second_timeout` used TTY stdin and the real binary with a disposable product store. After observing the registration prompt, it supplied no input and checked for exit 3 until 123 seconds had elapsed. The process was still running; the test failed, **exit 101**. The harness then killed and reaped only its own exact child through its process handle. No approval or backup write occurred. The combined non-TTY/timeout probe command finished in 124.59 seconds.

**Suggested fix:** Give the ceremony confirmation read a bounded, cancellable implementation that restores terminal modes on timeout and returns `NotConfirmed` without further requests. Add a real ceremony timeout test; checking `prompt::ask_within()` alone cannot protect this separate path.

### W5-R05 — medium — CLI lock disclosures omit the runtime's conditional limits before acknowledging them

**Location:** `crates/issuer/src/ceremony.rs:800`; also `crates/heimdall/src/enroll_cmd/render.rs:45` and `crates/heimdall/src/issuer_cmd/session.rs:195`.

**Failure scenario:** Initialize a CA or approve a first enrollment under a saved policy with a maximum window/cutoff or revoke-on-lock behavior. The issuer ceremony passes `DisclosureContext::default()`, and the enrollment renderer explicitly passes `lock: None`. Both show the general fallback sentence. They omit the runtime's actual policy limits, verification status and platform-specific availability wording, but approval records the once-only acknowledgment. Future decisions can therefore stop showing a disclosure whose required details were never presented.

**Evidence — observed issuer mismatch; inferred enrollment equivalent:** Disposable test `issuer::review_registration_shows_runtime_lock_disclosure` fetched the fixture runtime's `inspect capabilities` `lock.disclosure`, opened registration with TTY stdin, and required that exact text in the pre-approval terminal transcript. The assertion failed, **exit 101**. The enrollment call site always supplies `None`, independently establishing its fallback behavior. No affirmative answer was given in the probe.

D9 item 1 requires conditional saved-limit disclosure. ADR-0008 §17.26 item 6 explicitly recognizes the issuer gap and orders `RegisterDecision.lock_text` for round 3; that required follow-up is still absent at this head. The enrollment path has the same missing context.

**Suggested fix:** Carry `capabilities.lock.disclosure` into both issuer and enrollment confirmations and display it before allowing acknowledgment. Implement the already-ruled `RegisterDecision.lock_text` seam, and test both continuing and revoke-on-lock configurations plus saved limits.

### W5-R06 — low — Destination-list rendering tests use a different shape from the runtime

**Location:** `crates/heimdall/src/output.rs:669`; test fixture at `crates/heimdall/src/output.rs:1081`.

**Failure scenario:** `destination list` and `inspect destinations` receive `{"items":[...]}` from `Operations::destinations_view()`, but `destination_lines()` reads only `destinations`. Its formatted policy lines and explicit “connection policy unknown” fallback are never produced for a real list. Single-destination rendering works. Known policy data remains visible in the raw JSON already printed in human mode, so this is a presentation/test gap rather than loss of the machine field or enforcement.

**Evidence — observed:** Disposable test `output::tests::review_runtime_items_destination_wording` supplied the actual `items` wrapper and a fixture connection-policy sentence. The expected formatted sentence was absent; assertion failed, **exit 101**. The existing named list-rendering test passes a synthetic `destinations` wrapper, so it passes while the real list branch is broken.

**Suggested fix:** Accept `items` as well as the compatibility `destinations` spelling, following the existing TUI/catalog readers, and run the renderer test with the actual runtime shape, including a managed preference whose policy cannot be computed.

## Verified as correct

- The requested baseline suites pass on this host. Enrollment tests exercise client-run steps, interrupted mutations and reconciliation, target-change approval, manual recovery, system-form behavior and preserved fallback. No new defect in those exercised loop paths was established.
- The issuer CLI implements the R2B order: decision/confirmation, unload, exact recorded-locator deletion, `deleted_locator` confirmation, then retirement. Disposable scratch and product-file store tests passed; other store items are protected by identity checks.
- For the ordinary enrollment inventory it actually enumerates, uninstall checks bundle schema, redaction, timestamp/content and the installation's recorded digest. Bundle creation confirms `BundleWritten` after writing and syncing the file. The inventory omissions above limit that protection.
- TUI approval gating matches §17.25–§17.26: enrollment/removal/issuer follow-through stays CLI-only; typed Deny remains available; target-change decisions retain Approve/Deny. TUI tests cover search passivity and terminal restoration.
- Code-to-exit mapping, JSON envelopes and `connections close`'s exit-0 `OK` cases match the contract/ruling in the passing tests. A pending synchronous operation is not treated as async success.
- The additive optional fields use default/omission handling; M03 policy fields are restricted to the M03 policy results. Contract/schema/golden checks passed. Managed result facts originate in the adapter; attached/recovered results conservatively omit them as ruled.
- `validity_start` preserves the strict issuer ceiling, including subsecond grant starts. Its regression passed among 58 app unit tests; the CLI suite's managed paths also use the real issuer child.
- The doctor additions and time-chore predicates have passing coverage. Release builds exclude the product-store selector implementation and refuse test configuration: all 25 release-gate probes passed.
- M02 CLI and TUI regression suites passed after building their required disposable fixture helper.

## Commands and real exit codes

All Cargo commands ran from the detached scratch worktree. Probe tests were temporary additions there, never committed; their fixtures and assertions are described above. Exit 101 on a probe denotes the intended regression assertion failure, not a claimed product exit code.

| Command | Exit | Observed result |
|---|---:|---|
| `git worktree add --detach /tmp/hm-review-m03w5/wt baf2c88fb2033e668fbf2d8ae9611a60a5c076a6` | 0 | Exact review head checked out |
| `git diff --stat 8710717a..baf2c88fb2033e668fbf2d8ae9611a60a5c076a6` | 0 | 159 changed files |
| `cargo test -p heimdall --locked --test e2e_cli_m03 --test e2e_tui_m03 --test e2e_enroll_m03 --bins --lib` | 101 | No library target in package; no tests ran |
| Same command without `--lib` | 0 | Binary 160 passed; CLI 42 passed/2 harness entries ignored; enrollment 69 passed; TUI 5 passed/1 harness entry ignored |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed on the unmodified review head |
| `cargo test -p heimdall --locked --bin heimdall review_` | 101 | Formatter and planned foreign-record probes failed; one existing matching test passed |
| `cargo test -p heimdall --locked --bin heimdall uninstall_cmd::tests::review_foreign_removal_blocks_uninstall_purge -- --exact` | 101 | Abandoned foreign-record guard probe failed |
| `cargo test -p heimdall --locked --bin heimdall uninstall_cmd::tests::review_late_write_residual_blocks_purge -- --exact` | 101 | Late-write guard probe failed |
| `cargo test -p heimdall --locked --test e2e_cli_m03 issuer::review_ -- --test-threads=1` | 101 | Non-TTY and actual timeout probes both failed |
| `cargo test -p heimdall --locked --test e2e_cli_m03 issuer::review_registration_shows_runtime_lock_disclosure -- --exact` | 101 | Conditional-disclosure probe failed |
| `cargo test -p heimdall-contract --locked --test contracts` | 0 | 90 passed |
| `cargo test -p heimdall-app --locked --lib` | 0 | 58 passed, including validity-start regression |
| `cargo build -p heimdall --release --locked` | 0 | Release build succeeded |
| `bash tools/validation/release-gate.sh` | 0 | 25 probes, zero failures |
| `cargo test -p heimdall --locked --test e2e_cli_m02 --test e2e_tui_m02` | 101 | CLI: 41 passed/1 failed/1 ignored; missing `hm-fixture-hook`; TUI target not reached |
| `cargo test -p heimdall --locked --test e2e_cli_m02 ssh::a35_matrix_ssh_git_scp_sftp_ordinary_alias_and_run_bound -- --exact` | 101 | Same missing helper confirmed |
| `cargo build -p heimdall-testkit --bin hm-fixture-hook --locked` | 0 | Required disposable fixture helper built |
| `cargo test -p heimdall --locked --test e2e_cli_m02` | 0 | 42 passed/1 harness entry ignored |
| `cargo test -p heimdall --locked --test e2e_tui_m02` | 0 | 17 passed/1 harness entry ignored |
| `git diff --exit-code` after removing temporary probes | 0 | Scratch source restored to exact head |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype build-output directories existed |
| `du -sh target` | 0 | 8.7 GB before removal; removed with the worktree |
| `rustc --version`, `cargo --version`, `ssh -V`, `git rev-parse HEAD`, `git log --oneline 8710717a..HEAD` | 0 each | Versions/head/commit pair confirmed |
| Worktree removal and scratch-tree removal | 0 | Confirmed below |

Read-only source/specification inspection used `git diff`, `rg`, `sed`, `cat` and `nl`. Searches with no matches returned 1; the exploratory nonexistent source glob also produced a no-match diagnostic. These were navigation results, not failed validation. Captured validation/probe logs were checked before displaying selected output; no canary marker appeared in them. No private key or passphrase is included in this report.

## Limits

- This is code review plus selected macOS validation, not a full milestone-exit or security certification. No native Windows, WSL or Linux run was performed. Windows interactive acceptance remains **blocked: Windows interactive harness (U13)** per §17.26 item 8. Platform-specific paths were reviewed by reading.
- The purge probes exercised the production inventory/refusal functions. Final database deletion and remote late-write timing were inferred from the reachable code, not destructively executed.
- No user key, agent, real keychain, password manager or real server was used as test material. Successful issuer ceremonies used disposable file keychains; failed confirmation probes stopped before key creation in the store or backup writes. Test-owned processes were stopped by their own handles.
- Passing tests do not close the findings: the existing non-TTY test removes the controlling terminal, ordinary prompt-timeout tests miss the ceremony reader, and the list-rendering test uses the wrong wrapper. No existing test assertion was weakened for this review.
- No implementation fixes, commits, pushes, publishing or live configuration changes were made. Temporary probes were removed before cleanup. The only retained review artifact is this report.

## Cleanup confirmation

The detached worktree was removed with `git worktree remove --force /tmp/hm-review-m03w5/wt`. Everything created under `/tmp/hm-review-m03w5`, including the 8.7 GB target tree, temporary tests and logs, was removed. Both scratch paths are absent and the worktree registration is gone. The main checkout and other worktrees were not edited.

Not checked: native Windows/WSL/Linux execution and the complete workspace test suite.
Risk: unresolved remote recovery records can be lost by purge until W5-R01 and W5-R02 are fixed.
