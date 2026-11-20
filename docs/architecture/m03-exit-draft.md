# M03 exit draft — managed-certificate vertical slice

> **Status: draft for the orchestrator's exit decision (2026-11-19).** The runs are E5's (the last change outside
> `cfg(windows)`) and E9's Windows harness; the macOS and Linux release `heimdall` are
> byte-identical from E5 to E9. The records are `tests/evidence/m03-*.json`. The macOS lock row is `blocked` on the owner's
> unlock (section 5); the Windows revert proof of E9's fix is **pending**. The exit decision is the
> orchestrator's, under the owner's delegation (ADR-0004).

**Build:** E9, `2b79aac1b6bea72f886cef2331c9e3b5d0a123e8` on `m03/wave6`.

**The rule** (ADR-0008 §17.3 item 6; m03-plan §3, "What the lowest-row rule makes of the exit"). M03 may exit as M01
and M02 did:
- every record is `verified`, except rows blocked only on named owner inputs;
- those rows stay `blocked` with `blocked_on`; the exit record lists each, and no claim is widened to cover them;
- a `deferred_with_decision` row cites its ruling and does not count (`tests/evidence/README.md`);
- the macOS `lock_continuity` claim stays `not_verified` (B3), and a blocked R-CR-02 row keeps the managed unattended
  claim `preview-only` for the affected platforms (plan §10.3).

So `m03-exit-claims.json` is `blocked` even though every runnable row is `verified` (m03-plan §3).

## Build identity

- **The exit builds after E4** (each on `m03/wave6`):
  - E5 `da51b055`: a product fix, the managed residual settles (ADR-0008 §17.42). Every platform reran at E5.
  - E6 `3f61d242`, E7 `7300cfa0` and E8 `7b75c4c1`: test and harness files only (the Windows confirm prompt, the
    fixtures' readiness retry, the leftover sweep, the enrollment suite's step bound, an M01 test's wait bound).
  - E9 `2b79aac1`: `cfg(windows)` product code and Windows tests only (ADR-0008 §17.43, ruling I-24: no console
    window for a background child).
- **Which run is at which build:** macOS with Docker, the devbox, and the WSL M03 and M02 scenarios at E5; the
  Windows harness at E9; the macOS lock run at E8, which binds to E9 (E8..E9 is `cfg(windows)` code and Windows tests
  only). Superseded and kept, not read by the generator: the E7 and E8 Windows bundles and the blocked E7 lock run.
- **Sources digest** (`crates/` and `tests/` `*.rs`, `sources_sha256` in `tests/native/m03/required-inventory.json`):
  `f37e357d1030e0b6e826ff8c910c2c87367759c908ef44ca683b8bc15c7a4b4f`, regenerated at the E9 tree.
- **Release `heimdall`:** macOS arm64 `e9eabf9967827332af931409f96aecc4471c5660edf21dcb5f70d16b81343355` at E5 to E8
  (built at the release worktree's path). E8 and E9 built in one worktree are byte-identical: macOS
  `b9a40f70960492b510243ebb0a75e83e97554a9a44e257f0240a638a7f6f3557`, Linux x86-64
  `6b3af383b43287cc6f3dcd2766d725cc94323372a3cbfd55ae8ffd6f2c8043ba` (the hash depends on the build path).
- **Test-configured Linux `heimdall`** (the devbox and WSL binary, E5): `6e20ec76f50fb8665c29b8625e7583501102615b8477845f870859b7c3fd061c`;
  the WSL runs checked it against `HM_PREBUILT_SHA256` before use.
- **Windows `heimdall.exe`** (native `x86_64-pc-windows-msvc`, E9, `windows/build.txt`):
  `782520ae30266b2e54ee02c30f4b9fbe8c1e8237d5f884124b16287df41b7705`.
- **Artifact digest:** `tests/evidence/artifacts/m03/exit-da51b055/digests.txt` (recomputed when the lock run lands).

## 1. Exit evidence (plan §5 M03; m03-plan §3)

Each cell is the row status and its `passed` count; "excl. *n*" is `excluded_on_this_platform`, each excluded test
carrying a case-index rationale. "n/a" means the case declares no row there.

| Exit case | macOS arm64 | Linux x86-64 (devbox) | Windows 11 x64 | WSL distribution | macOS lock | Rows blocked on owner inputs | Record |
|---|---|---|---|---|---|---|---|
| A03 lock continuity | verified, 19 (excl. 8) | verified, 19 (excl. 8) | verified, 19 (excl. 8) | verified, 1 | blocked (the owner's unlock) | B1, B2, B3, B4, B11 | `m03-a03-lock-continuity.json` |
| A07 revocation | verified, 157 | verified, 157 | verified, 155 (excl. 2) | verified, 3 | n/a | none (the disconnected-runner variant `deferred_with_decision` to M06) | `m03-a07-revocation.json` |
| A09 enrollment | verified, 425 | verified, 250 (excl. 176, the Docker rows) | verified, 108 (excl. 324) | verified, 12 | n/a | B1, B4, B6 | `m03-a09-enrollment.json` |
| A10 scope and issuer | verified, 21 | verified, 19 (excl. 2) | verified, 5 (excl. 16) | verified, 3 | n/a | B11 | `m03-a10-scope-issuer.json` |
| A23 deadlines and connections | verified, 56 | verified, 56 | verified, 24 (excl. 43) | n/a | n/a | none | `m03-a23-deadline-connections.json` |
| A33 secrets | verified, 9 | verified, 9 | verified, 6 (excl. 3) | verified, 1 | n/a | none (support bundles and update artifacts `deferred_with_decision` to M08) | `m03-a33-secrets.json` |
| R-AU-08 reports | verified, 8 | verified, 8 | verified, 8 | n/a | n/a | none | `m03-r-au-08-reports.json` |
| Background work once | verified, 4 | verified, 4 | verified, 4 (excl. 1) | n/a | n/a | B7, B12 | `m03-exit-background-once.json` |
| No self-renewal | verified, 10 | verified, 10 | verified, 10 | n/a | n/a | none | `m03-exit-no-self-renewal.json` |
| Honest limits | verified, 5 | verified, 5 | verified, 4 (excl. 1) | n/a | n/a | none | `m03-exit-honest-limits.json` |
| Fixed provider | verified, 88 | verified, 88 | verified, 79 (excl. 9) | verified, 4 | n/a | B1, B4, B6 (the carried M02 rows) | `m03-exit-fixed-provider.json` |
| K_ca custody, macOS keychain | verified, 10 (mechanism) | n/a | n/a | n/a | n/a | B3 (product row), B13 (data-protection keychain) | `m03-store-macos-keychain.json` |
| K_ca custody, Windows DPAPI | verified, 2 | verified, 2 | verified, 2 | n/a | n/a | B2 (cross-user unprotect) | `m03-store-windows-dpapi.json` |
| K_ca custody, Linux Secret Service | verified, 3 | verified, 3 | verified, 3 | n/a | n/a | B11 | `m03-store-linux-secret-service.json` |
| Sleep, logout, reboot | verified, 14 | verified, 14 | verified, 14 | n/a | n/a | B3, B12 | `m03-sleep-logout-reboot.json` |
| P1 macOS screen lock | n/a | n/a | n/a | n/a | blocked (the owner's unlock) | the owner's unlock | `m03-p1-macos-screen-lock.json` |
| P-W1 Windows desktop lock | n/a | n/a | n/a | n/a | n/a | B2 (the Windows lock row) | `m03-pw1-windows-lock.json` |
| All of the above together (878 indexed tests) | | | | | | the union | `m03-exit-claims.json` |

**Record status:** `verified` are A07, A23, A33, R-AU-08, no self-renewal and honest
limits; P1 is `verified` once its macOS lock row is; every other record is `blocked`, and every one of its rows that is
not `verified` is blocked on a named owner input above, or `deferred_with_decision` with its ruling. The macOS lock
rows of A03 and P1 are `blocked` on a physical input (the owner's unlock within the 12 h bound, from an unlocked
console idle for 15 minutes) and are rewritten when the run happens. No row is `in_progress`.

## 2. Native runs

| Platform | Build | Harness | Exit | Passed / failed / ignored | Canary / leak | Owner-file and clean-up checks |
|---|---|---|---|---|---|---|
| macOS 27.2.1 (26B131) arm64, OpenSSH_10.5p1, Apple Git 2.54.0, APFS; Docker 29.9.3 with the M00-T03 fixtures | E5 | `tests/native/m03/run-macos.sh` | 0 | `check.sh` every step 0: 3126 / 0 / 199; observation pass 605 / 0 / 185; Docker phase 176 / 0 / 0 (`down.sh` CLEANUP CONFIRMED) | 0 / 0 | `~/.ssh` and Git configuration metadata equal before and after; scratch removed and checked absent |
| Linux 6.8.0-147 x86-64 (devbox), glibc 2.39, OpenSSH_9.6p1, git 2.43.0 | E5 | `tests/native/m03/run-linux.sh` | 0 | 3094 / 0 / 204 over 88 binaries in one batch, each `exit=0` | 0 / 0 | `~/.ssh` and Git metadata equal before and after; 0 leftover test processes; scratch removed and checked absent |
| Windows 11 x64 (10.0.26300.9974), Medium integrity, native msvc (rustc 1.99.1, MSVC 18.11.2), in-box OpenSSH_for_Windows_9.5p2, Git for Windows 2.55.0.windows.3 | E9 | `run-windows-local.ps1` by an agent on the PC (local mode, BelowNormal priority, 4 test threads), 27 min 1 s | 0 | 2646 / 0 / 18 over 87 binaries, each `exit=0`; every `e2e_exit_m03` test that runs on Windows `ok` (9; the `lock::` steps ignored as designed), `windows_runtime_children_have_no_console_window` included; no readiness retry | 0 / 0 | `%USERPROFILE%\.ssh` and `.gitconfig` metadata equal before and after; no leftover `heimdall.exe` or `ssh.exe`; both fixture sshds stopped; WSL scratch, clone, build and toolchain removed and checked absent |
| WSL 3.0.5.0, disposable distribution from the pinned Ubuntu 24.04.5 image: the M03 managed scenario | E5 | `tests/native/m03/run-wsl-distro.sh` (local mode), 252 s | 0 | `wsl_managed_ssh` 18 of 18 (the residual step: `revoking` at the revocation, no longer listed 3 s after `valid_before`; uninstall `OK`, both enrollments named) | 0 / 0 | the registered set equal before and after; 0 leftover heimdall processes |
| The same, the M02 scenario at the same build | E5 | `tests/native/m02/run-wsl-distro.sh` (local mode), 76 s | 0 | `wsl_ordinary_ssh` 11 of 11 | 0 / 0 | the registered set equal before and after; 0 leftover heimdall processes |
| macOS lock procedure (debug build, scratch test store, platform session-lock source) | E8 | `tests/native/m03/lock-macos.sh`, armed by the orchestrator's watcher (it starts once the session reads unlocked and the console has been idle 15 minutes) | not run | blocked: the owner's unlock within the 12 h bound; four attempts, none evidence (E5 killed with its session, E7 no unlock within 12 h, E8 attempt 1 refused because the screen was already locked) | — | — |
| Windows lock procedure | — | `tests/native/m03/lock-windows.ps1` | not run | blocked: B2 | — | — |
| Windows revert proof of E9's fix (`m03/e9-revert-proof`, never merged: `windows_runtime_children_have_no_console_window` with `CREATE_NO_WINDOW` removed) | E9 minus the fix | `run-windows-local.ps1` with `HM_ONLY_BINARY` and `HM_TEST_FILTER` | pending | pending (expected to fail) | — | — |

## 3. Known limitations and residuals

1. **macOS lock continuity is mechanism evidence.** A debug build on the scratch test store never yields the macOS
   `lock_continuity` claim, which waits for a release-profile run on the login keychain of a disposable account (B3;
   F03).
2. **The Windows lock row is blocked on B2** (the ruling on I-9). A release runtime projects into the logged-in
   account's own `~/.ssh` (`ProjectionWiring::Account`), so the Windows lock procedure runs only in a disposable second
   account. Windows `lock_continuity` stays `not_verified`; the claim update carries only the A07 and A23 fields.
3. **Lock-revokes grant R reads `revoking` until its residual passes, then `revoked`** (the rulings on I-11 and
   I-12; ADR-0008 §17.42). Local revocation is immediate (0 of R's key IDs accepted after it). Since E5 the managed
   residual settles: R's obligation becomes `bounded_by_expiry` for its pair (unmeasured in the lock world, so
   `nominally_expired`, the record kept), and the supervisor moves R to `revoked` once its certificate's
   `valid_before` has passed. R's window, and so its certificate's validity, is 600 s, so the post-unlock check reads
   `revoked`. Its post-unlock reading waits for the lock run (the A03 macOS lock row is `blocked`, section 5).
4. **Seeded inputs.** The lock driver seeds a verified enrollment and the CA trust line before the lock (I-2). On Linux
   and WSL the scenario records the product's refusal to register a CA on the scratch store (`issuer_store_unavailable`,
   no plaintext fallback), then seeds the CA (I-6).
5. **A refused issuance reads `issuer_unavailable`** (I-8 (2)); the finer reason is ADR-0006 revision 5's (later).
   I-8 (1) is fixed: a verification that never ran is `unclassified`.
6. **Windows `ssh.exe` needs `ProgramData`.** Without it the in-box client exits 255 before printing anything
   (bisected 2026-11-18). The exit suite's minimal Windows environments carry it by name, never the whole environment.
   A runtime started with a stripped environment loses verification silently as `inconclusive`; the product hardening
   (set it from the known-folder API, or report a doctor finding) is M04 U2's.
7. **A plain uninstall right after a revoke** was refused before E4 (`uninstall_inventory_changed`) while the
   supervisor's retry rounds ran, about a minute after each revoke. E4 compares a plain uninstall's pending remote
   revocations without their round bookkeeping (ADR-0008 §17.41); a purge's comparison stays exact (§17.33 item 3).
8. **The live runtime's `state/service.lock` is unreadable on Windows** to other processes (an exclusive whole-range
   `LockFileEx` lock). The exit suite's secret-bytes scan counts an empty file as scanned without opening it; a file
   with bytes that cannot be read is still incomplete coverage.
9. **Debian's and Ubuntu's OpenSSH accept a group-writable registry** whose group is the owner's private group (the
   user-group-modes patch). The WSL StrictModes control asserts the refusal of a world-writable registry and records the
   group-writable case.
10. **Not built in wave 6:** the WSL "`wsl --terminate` as a restart" row (m03-plan §4.2). The process-restart
    property runs natively on macOS, the devbox and Windows (`reissue_after_runtime_process_restart_same_boot`,
    `real_issuer_activation_reissue_revocation_with_fresh_logins`).
11. **Docker rows run on macOS only.** The devbox has no Docker (B8); the Windows PC runs its fixture sshds in WSL
    scratch.
12. **A33's one exemption** (I-4): the fake adapter's credential reference in the state DB's effect receipts is counted
    and exempted; the test's own planted canary is checked everywhere, the DB included.
13. **Two active grants for one work ID** (`access ensure`, then `run`, same work ID; I-5) is passed to M05.
14. **Named residuals** (`crates/domain/src/claims.rs` `RESIDUALS`, each with what remains and what is not yet shown
    natively): the purge sweep's check-to-delete windows, the uninstall fence and sweep residuals, the holder-approval
    lease, and the issuer child's cleanup and request-hold residuals (10 entries).
15. **On Windows, a runtime started on demand keeps its caller's caller's pipes open.** `spawn_detached`
    (`crates/runtime/src/launcher.rs`) makes only the CLI's own standard handles non-inheritable. A handle the CLI
    itself inherited as inheritable still reaches the runtime, and from it the issuer child. The usual case is a
    script's pipe, which the CLI inherits from the program that started it. So a script that pipes a `heimdall`
    command, which starts the runtime on demand, and reads its output to the end waits until that runtime exits.
    Restricting the inherited handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) is M04's (U2, the Windows handle-list
    work). The same path hung an E5 Windows harness run: a test left runtimes running, and they held its binary's
    output pipes. The harness's bounded drain and leftover sweep, and the test's leak fix, follow M03's exit.
16. **On Windows, a debug build's cold start can exceed the CLI's 10 s readiness wait under parallel load.** Before
    a runtime advertises, its start-up runs one step after another (the `ssh -V` probes, migrations, the session-lock
    reading, the issuer start), and six parallel cold starts of a freshly built `heimdall.exe` took longer than 10 s
    in the E6 Windows run. The CLI then answers `SERVICE_UNAVAILABLE` ("the runtime did not become ready in time",
    effect `none`), and the late runtime comes up afterwards. M04 fixes it in the product: the CLI waits 30 s, and a
    late runtime advertises and stays (ADR-0010 §11 item 13). The exit suites' fixtures wait for such a runtime (up
    to 60 s) and retry that one command once, recording a `fixture:` line, so M03's evidence is about M03 behaviour,
    not cold-start latency.
17. **A step the enrollment runner ends at its bound reads as `registry_unsupported`.** With no `HM1 ready` line the
    runtime cannot tell a timeout from a remote shell that is not POSIX (`heimdall_registry::classify::classify_step`).
    The enrollment suite's short step bound was 1 s, and an `inspect` over `ssh` under parallel load on Windows missed
    it; the suite now uses 10 s. A distinct class for a step ended at its bound is a product change after M03's exit.
18. **An M01 model test's 80 ms bound is flaky on a loaded Windows host.** `model_revocation`
    `r138_2_a_decision_resuming_five_waiters_waits_one_bound_in_total` (`MAX_WAIT` 80 ms) failed once, in the E7
    Windows run: it was the first under the PC's new load rules (BelowNormal priority, 4 test threads, 4 jobs), and
    `dec_of` found no `decision_ref` (`tests/model/revocation.rs:1586`). It passed in every earlier Windows run (E4,
    the E5 rerun, E6), and nothing in M03 changed it. E8 (test-only) raised its `MAX_WAIT` to 400 ms and kept the
    assertion `elapsed < 2 × MAX_WAIT`: five waiters still wait one bound in total (under 800 ms), never five
    (2000 ms). The same file's `r138_5_cancelling_the_creator_after_approval_leaves_the_preparation_to_the_waiters`
    sets `max_wait` to 50 ms for the same setup but asserts nothing relative to it, so it was left as it is; measuring
    such waits against a baseline is a follow-up.
19. **A background runtime's children got console windows on Windows; fixed at E9** (ADR-0008 §17.43,
    ruling I-24).
    - **Observed (the code and the platform):** the runtime runs `DETACHED_PROCESS`, and its
      non-interactive children (the issuer child, its `ssh.exe`, the local probes) were spawned without
      `CREATE_NO_WINDOW`. So each got a new console, which Windows hands off to the default terminal: on
      the PC, a Windows Terminal window or tab on the owner's desktop.
    - **Inferred, not proven:** this hand-off is the most likely cause of the E8 Windows failures. There, six
      `e2e_exit_m03` tests failed with the issuer child past its 5 s hello bound (`issuer_restarting`), 21
      commands needed the fixtures' readiness retry, and runtime start-up took 15–20 s. Those stalls happened
      in one window of time and were not reproduced afterwards. The E8 failure stays on the record.
    - **The fix and its outcome (observed):** E9 sets `CREATE_NO_WINDOW` on every non-interactive child
      through one helper (`heimdall_app::no_window!`); launches that share the user's terminal keep the
      terminal. The E9 Windows harness passed with no readiness retry and no leftover process, and
      `windows_runtime_children_have_no_console_window` found its issuer child without a console window. The
      PC's sampler saw no new `WindowsTerminal.exe` and no window on any process under the run's root.
    - **Builds:** E8..E9 changes `cfg(windows)` code and Windows tests only. The macOS and Linux release
      `heimdall` are byte-identical to E5's, so the macOS lock run at E8 binds to E9, and only the Windows
      harness reran.
    - **Pending:** the revert proof (the test with the fix removed, on the PC).

## 4. The claim update: deferred (ruling I-25)

The claim update is `deferred_with_decision`. M03 merges with `CLAIMS` empty, so every claim-table field reads
`unknown` (or `not_verified` for `lock_continuity`), which ADR-0008 D12 item 2 requires for a value whose test has not
passed for this platform and these versions.
- **The reason.** The product matches a claim-table entry by field, value and OS/architecture only. `claims()`
  (`crates/adapters/src/managed/prepare.rs`) and `claimed()`/`claim()` (`crates/adapters/src/managed/report.rs`) check
  none of `os_floor`, `client_versions` or `signer_builds`. So any non-empty table would over-claim on every host of
  that OS/architecture, whatever its OS release or OpenSSH client, WSL included. An empty table was not affected, which is
  why no earlier check caught it.
- **The entries are drafted and approved.** There are 19, for A07 and A23: `enforcement.revocation` and
  `revocation.remote` on macOS aarch64, Linux x86_64 and Windows x86_64; A23's fields on macOS and Linux; on Windows,
  A23 without `owned_multiplexing` or `graceful_dedicated_connections`. Each covers exactly the OS release and OpenSSH
  client of its run, is a debug test-configured row (no custody field), and points at its record at `9176fc5e`.
- **Follow-up unit M03-F1** (the integrator, after the merge, on a fresh branch from main; before the M09 release
  record):
  - version gating in `claims()` and `claimed()`/`claim()`: a host OS release reader per platform, the verified
    client's `ssh -V`, and the signer build;
  - tests per platform, including out-of-range hosts and WSL;
  - then the 19 entries;
  - one Codex review;
  - targeted native reruns on macOS, the devbox and Windows.
- **Plan §3 step 3 moves to M03-F1.** That step reruns `report_with_fixture_claim_table_reports_verified_with_record`
  against the real table, with per-platform expectations.
- **`a03_report_shows_verified_lock_continuity_on_this_platform` is not built,** and does not apply in M03. M03 adds no
  `lock_continuity` claim: that needs a release-profile run on a product store (F03). The macOS row is mechanism
  evidence on a test store, and the Windows release row is blocked on B2.
- Every `RESIDUALS` limit stays listed in section 3 above.

## 5. Before the exit

1. **The Windows revert proof** of E9's fix (the orchestrator, on the PC, `m03/e9-revert-proof` at `4043acb7`): its
   row in section 2 and item 19. If the test does not fail without the fix, the test is fixed before the merge.
2. **The merge** of `m03/wave6` into main, then the M03 exit record (this draft made final) and progress.md.
3. **The macOS lock row of A03 and P1 stays `blocked`** on a physical input: the owner unlocking the Mac within the
   procedure's 12 h bound, from an unlocked console idle for 15 minutes (ADR-0004 §2). The watcher is armed (at E8,
   binding to E9). The row is updated when the run happens; M03 may exit with it `blocked`, as M01 exited with A08 and
   A29-local blocked on physical inputs.
4. **M03-F1**, the claim update with version gating (section 4).
