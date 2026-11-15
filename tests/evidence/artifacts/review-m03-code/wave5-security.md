# Heimdall M03 wave 5 — independent security review

**Verdict: fix first.** Two high-severity and four medium-severity findings were reproduced. The highest-impact finding lets a concurrent enrollment survive an uninstall that purges the only local recovery records without requiring a bundle.

Reviewed range: `8710717a47d14b4f625561236ea47cc1d9bbe201..baf2c88fb2033e668fbf2d8ae9611a60a5c076a6`, branch `m03/wave5`. Review date: 2026-11-13. Native host: macOS arm64; `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.

The review used the supplied threat focus, plan §6.7, M03-plan U12 and §5 item 24, ADR-0006 confirmation/output rules, ADR-0008 D4/D5/D9/D13 and §17, especially §§17.25–17.26, and the specification's terminal and trust-boundary requirements. Earlier wave reports were format/depth examples only. This was report-only: production source remained unchanged. All builds and temporary probes ran in the detached review worktree at the exact head, using its single `target/` directory.

## Findings

### W5-S01 — High: purge validates an inventory that can change during the confirmation

**Location:** `crates/heimdall/src/uninstall_cmd.rs:1084`, `:1091`, `:1103`, and `:1204`.

**Scenario and impact.** `uninstall` reads its enrollment/CA inventory and checks the bundle before it waits for the owner to confirm. It continues using that inventory throughout rollback, retirement and shutdown, then deletes the state when projection cleanup is complete. It neither prevents concurrent enrollment admission nor revalidates the final inventory and bundle against the state being destroyed. A second attended CLI can enroll an account while the first waits at the purge prompt. The first CLI then purges without `--keep-remote-enrollments` or `--bundle`, because its original inventory contained no open enrollment. The remote trust line survives, while its enrollment record, marker recovery metadata and issuance history are deleted. The confirmation also never disclosed that this enrollment would be left behind.

**Observed probe.** Temporary test `enroll::security_probe_purge_during_real_enrollment` reused the suite's `World` and two `terminal::Pty` instances. It opened `--json uninstall --purge-state`, waited at the typed confirmation, ran and approved a second CLI's `enroll` against the disposable loopback sshd, verified one open enrollment and one remote marker line, then confirmed the original purge. No store corruption or direct database mutation was used in this end-to-end probe.

Command: `cargo test -p heimdall --test e2e_cli_m03 enroll::security_probe_purge_during_real_enrollment -- --exact --nocapture` — **exit 0**. Observed output:

```text
REAL_PURGE_RACE enroll_cli_exit=Some(0) purge_cli_exit=Some(0) purged=true db_exists=false remote_marker_lines=1
```

A separate store-level interleaving probe also reproduced the stale-inventory result. The end-to-end result above is the basis for this finding.

**Suggested fix.** Serialize destructive uninstall with enrollment/CA admission, drain or refuse outstanding remote mutations, and validate the inventory, required bundle content/digest and owner's confirmation against the final stable state before deleting it. If that state differs from the confirmed state, refuse or present a fresh confirmation and bundle requirement. Merely adding a second unsynchronized read leaves another race.

### W5-S02 — High: interactive JSON enrollment omits the mandatory disclosure text

**Location:** `crates/heimdall/src/enroll_cmd.rs:200`, `:364`, and `:420`; supporting renderer `crates/heimdall/src/setup_cmd.rs:294`.

**Scenario and impact.** The full enrollment preview is passed through `show`, which suppresses it when `ctx.json` is true. Interactive confirmation still proceeds. Its preface supplies the exact registry line, while the generic decision renderer prints the recorded request as JSON. That request contains disclosure enum names, rather than the required explanations. Thus an owner can type `yes` and enroll without being shown the CA trust blast radius, configuration-command execution, removal residual, lock continuity, stale-script signalling, or managed-slot disclosures. JSON output selection should not remove the consent information from the terminal. The module's own output contract says the preview belongs on stderr.

**Observed probe.** Temporary test `enroll::security_probe_json_enrollment_approves_without_disclosure_text` ran `--json enroll` on a real pty with the suite's disposable account, agent and loopback sshd. Before confirming, it asserted that the exact registry line was present and that the disclosure prose was absent. It typed `yes`, observed the pending decision consumed and the remote line written.

Command: `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` — **exit 0** on the final corrected five-probe run. Observed child result:

```text
JSON_DISCLOSURES exact_line_shown=true disclosure_text_shown=false decision_approved=true cli_exit=Some(0) marker_lines=1
```

This is a disclosure omission, not a claim that the typed confirmation or exact registry line was bypassed.

**Suggested fix.** Always render the complete consent preview and required disclosure prose to the interactive terminal/stderr, including with `--json`; retain the single machine-readable envelope on stdout. Apply the same rule to every owner-facing path that can approve these decisions, including generic decision completion.

### W5-S03 — Medium: the CLI records the once-only lock acknowledgement for a generic disclosure

**Location:** `crates/issuer/src/ceremony.rs:800`; `crates/heimdall/src/issuer_cmd/session.rs:195`; `crates/heimdall/src/enroll_cmd/render.rs:45`.

**Scenario and impact.** `WireSession::register` carries only the disclosure kinds into `RegisterDecision`; `show_decision` renders them with a default context, so `lock_continuity_once` uses the generic fallback. The enrollment preview likewise supplies `lock: None`. Neither path uses the conditional runtime text already available in `inspect capabilities.lock.disclosure`. The generic sentence omits the saved policy limits/cutoffs, the verified/not-verified clause and the platform-specific lock-signal qualification. Approval nevertheless records the once-only acknowledgement. Later decisions therefore omit the disclosure even though the owner was never shown the required text.

The reviewed head explicitly records the missing issuer change as the round-3 work in ADR-0008 §17.26 item 6, Q-IS2-5; the ruling is not its implementation.

**Observed probe.** Temporary test `issuer::security_probe_ceremony_ctrl_c_written_and_lock_disclosure` obtained the real runtime's capability disclosure, opened `issuer init` on a controlling pty using a disposable product-kind file keychain, compared the pre-confirmation transcript, and asserted that the conditional text was absent while the generic fallback was present. After completion, `lock_disclosure_ack()` was populated. Only booleans were printed; no passphrase was emitted by the probe.

Command: `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` — **exit 0** on the final corrected five-probe run. Observed result:

```text
WRITTEN_INTERRUPT pending_after_ctrl_c=true final_cli_exit=0 ack_recorded=true conditional_disclosure_shown=false
```

The enrollment half is additionally established by the direct `lock: None` call site; its exact conditional-text mismatch was not separately exercised on a human-mode enrollment pty.

**Suggested fix.** Carry the runtime's conditional lock text into the issuer ceremony as §17.26 specifies, and supply it to the enrollment consent renderer too. Refuse approval if a required disclosure cannot be obtained/rendered. Keep the acknowledgement consume-once behavior, but record it only for a decision whose required text was actually presented.

### W5-S04 — Medium: issuer registration has no prompt timeout

**Location:** `crates/issuer/src/ceremony.rs:177`, `:182`, and `:685`.

**Scenario and impact.** The issuer ceremonies use a blocking controlling-terminal reader, separate from the ordinary CLI prompt's 120-second bound. It has no deadline or timeout result. An unattended registration prompt remains usable beyond the specified timeout and can still complete the previously displayed decision. This breaks U12's timeout-refuses-every-decision requirement. The server's longer decision expiry is not the client prompt timeout.

**Observed probe.** Temporary test `issuer::security_probe_ceremony_prompt_has_no_timeout` used a disposable product-kind keychain and controlling pty. At the registration confirmation it waited **122 seconds**, verified that the process had not exited, then typed `yes` and `written`. The real runtime registered one CA and the CLI exited 0.

Command: `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` — **exit 0** on the final corrected five-probe run. Observed result:

```text
CEREMONY_TIMEOUT waited_seconds=122 late_yes_cli_exit=0 registered=1
```

**Suggested fix.** Bound the controlling-terminal confirmation with the same cancellation/timeout semantics as ordinary CLI confirmations. On timeout restore terminal modes, clear any secret display, zeroize ceremony material, send no further approval/store action and return `NotConfirmed`/exit 3. Test the real terminal reader, not only the separate generic prompt helper.

### W5-S05 — Medium: Ctrl-C at the passphrase acknowledgement does not cancel the ceremony

**Location:** `crates/issuer/src/ceremony.rs:192`, `:685`, and `:819`.

**Scenario and impact.** The new terminal reader maps Ctrl-C to `None`, but `confirm` reduces that to `false`. At the passphrase's `written` prompt, `show_passphrase` treats it as another incorrect answer and retries up to 20 times. A single Ctrl-C therefore leaves the process running with the passphrase display still present; subsequent `written` input can store the key and approve registration. This contradicts §17.26's rule that Ctrl-C at a ceremony prompt cancels and returns `NotConfirmed`/exit 3. EOF takes the same retry branch by inspection; the native probe exercised Ctrl-C.

**Observed probe.** `issuer::security_probe_ceremony_ctrl_c_written_and_lock_disclosure` typed the initial `yes`, waited for the passphrase's `written` prompt, sent raw ETX through the pty, and verified that the process remained alive 500 ms later. It then typed `written` and observed successful registration, exit 0. The combined result is quoted in W5-S03. No secret transcript was printed or retained in the report.

Command: `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` — **exit 0** on the final corrected five-probe run.

**Suggested fix.** Preserve cancellation/EOF as a distinct terminal-read outcome and propagate it immediately through `show_passphrase`. Clear the secret region and restore the terminal on that exit; retry only an ordinary incorrect acknowledgement if retries remain desired.

### W5-S06 — Medium: a backup filename can inject terminal controls into issuer consent

**Location:** `crates/issuer/src/ceremony.rs:796`; raw output sink `crates/issuer/src/ceremony.rs:252`.

**Scenario and impact.** Unlike the ordinary CLI renderers, the ceremony interpolates `backup_out.display()` directly into its decision and sends the resulting bytes to the controlling terminal without sanitizing the path. A command-line path supplied by an untrusted workflow can contain terminal escape sequences. In particular, clear-screen and cursor-home sequences execute after the actual CA fingerprint and backup digest have been printed, allowing a filename to erase or replace that consent context. This breaches the specification's terminal-injection requirement at the sensitive registration prompt. It does not require an existing file or approval before the controls are displayed.

**Observed probe.** Temporary test `issuer::security_probe_ceremony_unsanitized_backup_path` selected a nonexistent filename containing clear-screen and cursor-home controls under its own scratch directory, opened `issuer init` with the disposable product keychain, and waited for the registration prompt. It asserted that the raw sequences reached the pty, then answered `no`. No backup was written and no passphrase was displayed. Only a boolean was printed, never the control-bearing transcript.

Command: `cargo test -p heimdall --test e2e_cli_m03 issuer::security_probe_ceremony_unsanitized_backup_path -- --exact --nocapture` — **exit 0**. Observed output:

```text
CEREMONY_PATH raw_clear_screen_and_home_controls_reached_terminal=true cli_exit=3 backup_written=false
```

**Suggested fix.** Sanitize every untrusted path/string before incorporating it into ceremony text, while retaining only the terminal-control sequences that the ceremony itself generates to clear its secret display. Add a real-pty regression for control-bearing filenames.

## Checked and found sound within the stated scope

- **Ordinary decision gates:** the baseline tests exercise non-TTY input, non-interactive mode, EOF, Ctrl-C and negative input for enrollment decisions; the generic prompt's bounded-reader test passed. ADR-0006 explicitly permits `y` as well as `yes`; accepting `y` is not reported as a defect. Issuer init rejects no controlling terminal and non-interactive mode. Piped stdin cannot supply the ceremony's confirmation: it reads the controlling terminal instead.
- **TUI approval boundaries:** source inspection and the model tests show enrollment, removal, registration, rotation/restore and retirement as CLI-only for approval. Toggling or stale prompt state cannot override the final CLI-only guard. Deny still requires typed confirmation. Target-change approval remains permitted with the full key diff, and the rendering/reading gate requires the content's end to have been drawn. Native TUI restoration and non-terminal refusal tests passed.
- **Exact enrollment/removal content:** the human enrollment preview and JSON confirmation preserve the exact registry line. Target-change displays include both keys. Fourteen foreign-removal regressions passed, including line-hash/host mismatches, exact held-descriptor reuse, second-installation removal, damaged/unknown outcomes and no foreign registry bytes in the journal. Redacted bundles are refused before foreign-removal runtime contact.
- **Secrets and terminal output:** the macOS disposable product-store CLI tests passed for passphrase confinement to the controlling pty, absence from stdout/stderr/argv/artifacts, encrypted-backup round trips, restore and orphan replacement. The ordinary human/TUI output sanitizers strip terminal controls; W5-S06 identifies the ceremony bypass; diagnostic M03 additions expose metadata rather than key bytes. No secret or canary leak was observed in the executed product output paths. This is bounded by the ceremony findings above and the output-path limits below.
- **Bundles:** code inspection confirms exclusive owner-only creation, `write_all` and `sync_all` before `BundleWritten`, and no confirmation of redacted bundles. Existing CLI bundle tests passed for no overwrite, owner-only mode, recorded digest and redaction. A separate native file-creation test passed for 0600, exclusivity and refusal to follow an existing final-component symlink. In a stable inventory, uninstall checks schema, redaction, freshness, current CA/enrollment states and an installation-recorded SHA-256; malformed/hand-made/foreign/stale/partial-file refusals passed. W5-S01 defeats that protection through concurrency.
- **R2B:** the CLI waits for unloading, deletes the recorded exact locator, checks store kind/fingerprint and rereads for absence before confirming. The macOS product-store and debug scratch-store CLI retirement tests passed; another locator is preserved. A missing locator refuses deletion. Already-absent items are intentionally idempotent. Native Linux displaced-item behavior remains outside this host's proof.
- **Release/test isolation:** the release binary refused 18 applicable hook/selector invocations, all with exit 2 and the expected refusal. The product-file selector is compiled out in release; a separate release integration probe confirmed that exact-locator deletion for a test-kind store refuses before list/delete I/O. Debug selector tests passed for relative/outside-home paths, account-home ancestors, keychain-directory paths, missing/wrong/late/insecure markers and symlinks. No real login keychain was a fixture or deletion target.
- **Terminal/process control:** the enrollment Ctrl-C regression passed, reporting uncertainty and requiring reconcile. The loop uses its own interrupt receiver and `StepAbort`; the underlying Unix runner keeps the unreaped child identity while signalling only its owned process group. Agent-held identity checks and the interactive authentication-fallback notice are present. Manual-recovery reconcile refuses a non-inspect step. No blanket-name process stop was used in this review.
- **Lock/report additions:** app and lock model tests passed, including the conditional disclosure generator, once-only acknowledgement, effective behavior and validity ceiling. The native capability-disclosure integration test and enrollment-acknowledgement regression passed. The correct runtime generator does not repair the CLI wiring defect in W5-S03.

The focused existing suites passed **313 tests** in total, with three ignored child-mode launcher entries. The separate release deletion-gate probe and all six disposable counterexample probes completed successfully. The latter confirm the reproduced defects.

## Commands and real exit codes

Commands below ran from the detached worktree unless marked otherwise. `<repo>` and `<scratch>` replace local checkout/scratch prefixes; paths are normalized to avoid personal information. `run.py` only captured output, sanitized it before display and recorded the subprocess's actual exit code. The table lists material build/test/probe/cleanup execution; source inspection used `git diff`, `rg`, `sed`, `nl` and `cat`.

| Command | Exit | Observed result |
|---|---:|---|
| `git -C <repo> worktree add --detach <scratch>/wt baf2c88fb2033e668fbf2d8ae9611a60a5c076a6` | 0 | Exact detached head created. |
| Read-only `security_diff_scan` configuration preflight | 0 | Ready; no further delegation used for this independent sub-agent review. No configuration changed. |
| `cargo build --release -p heimdall` | 0 | Release executable built. |
| `cargo test -p heimdall --bin heimdall --test e2e_cli_m03 --test e2e_tui_m03 -- --test-threads=4` | 0 | 160 unit + 42 CLI + 5 TUI tests passed; 3 ignored entries are child-mode test launchers. |
| Initial `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` | 101 | Probe compilation failed: reviewer initially used a nonexistent `Txn::enrollments` helper; corrected to `open_enrollments`. |
| Initial `python3 <scratch>/release_probes.py` | 1 | Reviewer initially routed launch-only hooks through `service run`, and expected refusal text from the silent internal child. These were probe expectations, not release-hook activation. Corrected command routing. |
| Corrected `python3 <scratch>/release_probes.py` | 0 | 18/18 applicable invocations refused; each child exit 2. |
| `cargo test -p heimdall-issuer --lib` | 0 | 15 passed, including debug product-selector checks and debug test-store exact deletion. |
| `cargo test -p heimdall-app --lib --test model_lock_behavior` | 0 | 58 app + 16 lock model tests passed. |
| Intermediate corrected `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` | 101 | Three probes passed; the first store-level purge fixture lacked its CA foreign-key record. That fixture was corrected; a separate real-CLI race was added. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::security_probe_purge_uses_stale_inventory -- --exact --nocapture` | 0 | Store-level purge interleaving reproduced. |
| `cargo test -p heimdall --test e2e_cli_m03 enroll::security_probe_purge_during_real_enrollment -- --exact --nocapture` | 0 | Real CLI/loopback enrollment survived successful state purge. |
| `cargo test --release -p heimdall-issuer --lib test_store_item_deleted_by_exact_locator_in_debug_builds_only -- --exact retire::tests::test_store_item_deleted_by_exact_locator_in_debug_builds_only` | 101 | Existing test fails compilation at `crates/issuer/src/retire.rs:428`: inline `const { assert!(TEST_STORE_DELETION) }` is evaluated even in the runtime `if cfg!(debug_assertions)` branch. No test ran. Production release build succeeded separately. |
| `cargo test --release -p heimdall-issuer --test security_release_gate` | 0 | Disposable integration probe: release rejects test-kind deletion before store I/O. Existing source/test was not altered to obtain this result. |
| `cargo test -p heimdall --test e2e_enroll_m03 foreign -- --test-threads=4` | 0 | 14 foreign-removal tests passed. |
| `cargo test -p heimdall-runtime --test integration_runtime_m03 lock_disclosure -- --test-threads=4` | 0 | Zero tests matched; no validation credit assigned. |
| `cargo test -p heimdall-runtime --test integration_runtime_m03 inspect_capabilities_reports_lock_behavior -- --test-threads=4` | 0 | One actual capability-disclosure integration test passed. |
| `cargo test -p heimdall-localenv --lib create_owner_only_exclusive_is_0600_exclusive_and_never_follows_a_link` | 0 | One native file-creation regression passed. |
| `cargo test -p heimdall --test e2e_enroll_m03 enroll_account_approval_records_lock_disclosure_acknowledgement_once -- --exact` | 0 | One acknowledgement regression passed. |
| Final `cargo test -p heimdall --test e2e_cli_m03 security_probe -- --nocapture --test-threads=4` | 0 | All five corrected probes passed their counterexample assertions, including the real CLI purge race and 122-second timeout. |
| `cargo test -p heimdall --test e2e_cli_m03 issuer::security_probe_ceremony_unsanitized_backup_path -- --exact --nocapture` | 0 | Sixth disposable counterexample probe passed: raw filename controls reached the consent terminal. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | zsh reported no matching prototype build-output paths. |
| Equivalent nullglob-aware prototype-output inspection | 0 | No prototype build-output directories existed in this worktree. |
| `du -sh target` | 0 | 7.2 GiB before cleanup; the entire directory was removed with the worktree (see cleanup). |
| Main-checkout `git status --short` and `git diff --name-only` | 0 | Both empty at verification. |
| `git -C <repo> worktree remove --force <scratch>/wt` | 0 | Review worktree and its complete `target/` removed. |
| `python3` exact-path scratch removal and post-cleanup assertions | 0 | Scratch root absent; review worktree unregistered; main checkout clean; report retained. |
| `python3` report hygiene assertions | 0 | Six finding IDs; no personal home paths/usernames, raw escapes, canary values or private-key armor. |

## Limits and files

- Native execution covers macOS arm64 only. Windows/ConPTY/DPAPI and Linux/Secret Service/logind behavior received source review, not native validation. Those platform claims remain **blocked: required native Windows or Linux host/harness unavailable in this review**. WSL lock and secure-store claims were not closed by this run.
- Fixtures were disposable scratch installations, generated keys, file keychains outside the search list and loopback sshd/agents. No real account enrollment, owner's SSH configuration/key/agent, login keychain, password manager or real server was used as test material.
- The CLI loopback enrollment tests use their existing fixture issuer/verification wiring. The CA ceremony probes use the real product-kind keychain and real runtime/issuer child. This is not release-profile native custody or physical desktop-lock certification.
- No exhaustive full-workspace, fuzz, power-loss, every-signal, every-output-path or adversarial same-user filesystem-race campaign was run. File write/fsync ordering was read and exercised through normal tests, not through injected fsync failures. The 122-second timeout probe covers registration; other ceremony reads share the unbounded reader by inspection.
- The release-profile library-test compilation failure above is a concrete validation defect; the separate release integration probe supplies narrowly scoped deletion-gate evidence, not a claim that the original release test passed.
- Persistent changed file: this report only. Temporary additions were confined to `tests/e2e/cli_m03/{enroll,issuer}.rs` and `crates/issuer/tests/security_release_gate.rs` inside the disposable worktree, plus scratch scripts, captures, fixtures and build outputs. No implementation fix, commit, push or main-checkout edit was made.

## Cleanup

**Confirmed.** `git worktree remove --force` completed with exit 0. Exact-path removal of the review scratch root completed with exit 0. Subsequent assertions confirmed the scratch tree is absent, the review worktree is absent from Git's worktree list, the main checkout is clean and this report remains.

Every fixture keychain had already been removed by its fixture cleanup; a final pre-removal scan found zero remaining fixture keychain files. Removing the worktree deleted the complete 7.2 GiB `target/`, all temporary probe source, fixture files and captures inside it. Removing the scratch root deleted the command ledger, sanitized captures and probe scripts. No scratch evidence is retained apart from the nonsecret observations and commands transcribed here.

Unchecked: native Windows/Linux/WSL, physical desktop-lock behavior and the full release test suite. Risk: the six reproduced defects remain unfixed in the reviewed head.
