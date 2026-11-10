# M03 wave-1 independent review

Reviewer: Codex (gpt-6.1-sol, independent), over `9b3984ba..a924a4e9` (the M03 wave-1 commit), in the wave-1 worktree. Saved by the orchestrator with home, worktree and scratch paths redacted. Rulings: ADR-0008 §17.18.

**Verdict: fix first.**

Reviewed change: `9b3984ba..a924a4e9`, in the requested checkout. Execution HEAD was `52729afbae126dd791b1e8a093302f5ac5dd2e2c` (the merge with main). `git diff --name-only a924a4e9 HEAD` showed only ADR-0007 and two M02 native-harness files, so the reviewed wave-1 Rust sources were unchanged at execution HEAD. Repository status was clean before and after review. No repository source, configuration, evidence, commit, or remote was changed. The only report written is this file. Cargo used the existing shared `./target`.

The requirements used were ADR-0008 revision 6 with section 17.17 amendments, m03-plan, overview section 9, and targeted spec.md/plan.md requirement and M03 evidence rows. This is a focused security/correctness review with the coverage limits below, not certification of all 45,662 added lines.

## Findings

### W1-R01 — High: Linux restore shares another installation's CA item and retirement can delete it

**Location:** `crates/issuer/src/store/linux.rs:180-188`, `:215-225`, `:249-264`; supporting path `crates/issuer/src/ceremony.rs:737-748` and `crates/issuer/src/retire.rs:206-214`.

**Evidence: inferred from production source; no Linux Secret Service probe run.**

The store writes `heimdall_environment_id` when creating an item, but its duplicate search and `get` search use only application and fingerprint. Its list also returns items across environments. Consider installations A and B of the same OS user: A has stored a CA; B restores the same backup. B's `put` returns `AlreadyExists` because A's item matches. Restore's `store_and_check(..., adopt=true)` then selects that item from `list`, reads the matching key with `get`, and succeeds, returning A's locator as B's recorded item. B never gets its own store item. Retiring B deletes exactly that recorded locator, thereby deleting A's still-required CA item. A subsequently cannot reload its CA. This contradicts section 17.17 item 3's explicit guarantee for a second installation holding the same restored CA.

There is a second manifestation if two separately created items with the same fingerprint exist: `get` returns `Corrupt` merely because the global search returns two, even when exactly one belongs to this installation. The new shared-store regression uses a fake that namespaces its locators by environment; the macOS native regression uses separate account attributes. Neither covers the Linux implementation's omitted environment constraint.

**Required correction:** scope duplicate detection and retrieval to the current environment, preserve distinct item identities across installations, and test restore plus retirement using the actual Linux store in a private Secret Service session. Keep deletion constrained to the recorded item.

### W1-R02 — Medium: restore can record the wrong macOS item when the CA exists in multiple installations

**Location:** `crates/issuer/src/ceremony.rs:739-743`; supporting source `crates/issuer/src/store/macos.rs:310-334`, `:279-281`.

**Evidence: inferred from production source; native retirement tests passed, but no restore reproduction was run.**

On `AlreadyExists`, `store_and_check` adopts the first listed item with the fingerprint. `MacosLoginKeychain::list` deliberately lists every matching service across all environment accounts; its sort compares only fingerprints. If A and B already hold the same CA and B restores its backup again, B's `put` correctly detects B's own existing item, but the adoption search can return A's item first. The subsequent `get` checks B's own account and succeeds, so it does not validate the selected locator. The returned `Restored` value contains A's locator even though the read-back was of B's item. When that result is recorded, B's retirement fails because macOS deletion rejects any locator other than B's expected service/account; its key is left behind and retirement stays unresolved.

This is separate from R01: macOS already stores distinct items correctly; the cross-platform adoption helper discards that identity. The passing macOS regression directly calls `put` and supplies its returned locator to retirement, bypassing the faulty adoption branch.

**Required correction:** obtain the existing item identity from the same environment-scoped lookup used for the read-back, rather than choosing by fingerprint from a global inventory. Add a restore regression with both accounts present and the other account listed first.

### W1-R03 — Medium: the native lock evidence test passes on loss of the lock signal

**Location:** `tests/integration/session_lock.rs:413-416`, `:448-454`; supporting source `crates/runtime/src/session_lock/mod.rs:164-165`, `:210-214`.

**Evidence: inferred from test and source control flow; no real screen lock or signal-failure probe performed.**

`wait_for_real_lock` waits for any epoch increment and then asserts only the increment, the observed latch, and thread affinity. Entering `Unknown` intentionally increments that same epoch. Starting unlocked and then losing the session query (macOS), receiving an unreadable session change (Windows), or losing the logind connection (Linux) therefore satisfies the supposed real-lock test without any screen lock being observed. The test even records `observed_state=Unknown` while returning success. It does not require a lock event count to increase either.

These are the shared assertions behind `macos_lock_signal_observed`, `windows_lock_signal_observed`, and `linux_logind_lock_signal_observed`. Their success is meant to settle M-F12/M-F13 and native signal claims; successful fail-closed revocation on `Unknown` is different evidence and cannot settle those claims.

**Required correction:** require an actual observed `Locked` reading/event attributable to the native lock procedure, with appropriate latching if the screen has already unlocked by the final snapshot. Keep a separate test proving `Unknown` causes revocation. A simulated loss of the query must not pass the real-lock evidence row.

## Validation and command results

All Cargo commands ran in the requested checkout with its pinned toolchain and existing target directory. Commands and final process exit codes:

| Command | Exit | Observed result |
|---|---:|---|
| `cargo test -p heimdall-credential --test integration_credential_cert --locked` | 0 | 16 passed, 0 ignored, including fixture sshd certificate acceptance and session-bind host-key algorithms |
| `cargo test -p heimdall-app --test model_lock_behavior --locked` | 0 | 16 passed, including floor persistence after configuration change/restart, epoch acknowledgement and storm coalescing |
| `cargo test -p heimdall-credential --test adversarial_signer_requests --locked` | 0 | 7 passed, including malformed lengths, oversize and mutated requests |
| `cargo test -p heimdall-registry --test model_registry_pure --locked` | 0 | 17 passed, including fencing classification, post-image preservation and host-trust pins |
| `cargo test -p heimdall-issuer --test integration_issuer_store --locked retirement_` | 0 | 2 passed, 25 filtered out; fake shared-store retirement and disposable macOS shared-keychain retirement |

Total: **58 tests passed**. Cargo initially waited for the shared build lock; it subsequently completed normally. Passing suites do not reproduce or refute R01–R03.

Read-only inspection commands included `pwd`, `git status --short`, `git rev-parse HEAD`, `git diff --stat 9b3984ba a924a4e9`, `git diff --name-only a924a4e9 HEAD`, and `cat`, `sed`, `rg`, `nl`, and `head` reads of the cited source, tests, plans, ADR and cached dependency source. Those inspection batches returned 0 except: the initial combined conventions/skill/memory-search batch returned 1 because the targeted memory search found no Heimdall/M03 entry; the first output-hygiene batch returned 1 because zsh found no `prototypes/*/target` matches. A nullglob retry returned 0; all three prototype globs were empty, so `du` defaulted to the checkout itself and reported 50G. No build output was removed: `./target` is shared with the concurrent native harness, and it was explicitly required for this review. No probe directory was created. No Docker up/down commands, clippy, Git mutation, or push ran.

**Execution limit breached by a test helper:** the macOS retirement test calls `OwnerDigest::capture` and `owner_keychain_digests`. Inspection after execution showed that the former hashes the owner's SSH/Git files and the latter inspects owner keychain state as a preservation guard. This exceeded the review packet's instruction never to touch those real resources, despite the actual store test using only its disposable file keychain. No owner material was deliberately used as key/store test material, no private contents were printed, and the test's before/after guards passed. This is disclosed rather than claiming the test never read owner files. No further such test was run.

## Coverage and limits

Inspected the purpose parser and binding checks, session-bind cryptographic verification, installed-certificate validator, vault seed/zeroization flow, credential memory-hardening wrappers, issuer store implementations, issuer FFI and backup/ceremony/retirement/bundle paths; registry script validation, append/remove/fence goldens, post-images, HM1 and classification; enrollment process containment and excerpts, verification configuration/attempt/classification and trace parsing; session source implementations, FFI, epoch latch and lock-pass/floor logic; selected fixture guards and Docker lifecycle changes. No plaintext fallback was found in the inspected product-store paths. No purpose-check or session-bind signature bypass was identified in the inspected code. That is bounded static review plus the tests above, not proof that no bypass exists.

The append/remove final-check races and PID/process-group reuse windows documented by the ADR were treated as accepted residuals, not new findings. The fence uses stable Darwin boot UUIDs and requires agreement between group control, probe and listing on the ordinary path; unproven results retain the lock. The pure tests passed. I did not run the per-shell live-holder/paused-writer proofs.

**Not checked:** exhaustive line-by-line coverage of all 99 changed files or every test/helper; full workspace clippy/tests; full issuer ceremony/e2e and memory/ptrace suites; all enrollment I/O/verification integration suites; Docker fixtures; dash/bash-as-sh/BusyBox and macOS shell mutation/fence execution; native Windows DPAPI/WTS or Linux logind/Secret Service; WSL; real screen lock/unlock, sleep, logout or reboot; release-profile product-store custody; live canary/argv/environment or heap-remanence scans; dependency-wide cryptographic/unsafe audit. The selected dependency reads were supporting source inspection only. No new downstream delegation was performed: this reviewer acted as the requested independent review sub-agent.

Wave-1 units remain `implemented_unverified` pending the required U13 evidence; these passing checks do not close blocked native-platform claims. R01–R03 need correction and targeted validation before merge.

Report creation/update and final `rg` requirement lookup, `git status --short`, and `wc -l` inspection commands all returned exit 0. Final repository status remained clean.
