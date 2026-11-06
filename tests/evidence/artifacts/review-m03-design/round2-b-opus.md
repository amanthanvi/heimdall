# M03 design review, round 2, reviewer B — 150e2f2b — ready after fixes

Reviewer: Claude Opus 5.5 (provider instance `claudeAgent`, effort high), independent, read-only,
separate worktree. Saved by the orchestrator on 2026-11-06, condensed but faithful in substance.
Reviewed revision 2 of `docs/architecture/m03-plan.md` and ADR-0008 at `150e2f2b`, checked against
the text and the code, not the change logs. Changed files: none.

**Verdict: ready after fixes.** The round-1 blockers are addressed in substance; no new blocker; nine
new majors, four in the wave-0 freeze (R2-01, -02, -03, -05). A targeted re-check of the R2 fixes
suffices.

## Closure (round 1)
Partly closed: M03-R01 and F12 (gate bodies land late, R2-01; `SignPermit` crate, R2-02; cascade set,
lock order, timeout, R2-03), M03-R05 (initial-verification retry, R2-06), M03-R06 (unstarted script
R2-04, truncated script R2-10, deadline across reboot R2-11), M03-R12 (bundle carries only a display
path, R2-07), M03-R13 (R2-02), F26 (not synced with §17.3; blocked list incomplete, R2-16).
Closed: every other round-1 finding (M03-R02–R04, R07–R11, R14, R15; F01–F11, F13–F25, F27), each
cited by line in the reviewer's table (e.g. R02 l.712–722, 833–838, 851–856; R03 l.1028–1064; R07
l.776–792; R10 l.1001–1013, 1419–1440; F03 l.1866–1879).

## New findings

| ID | Sev. | Location | Defect | Fix |
|---|---|---|---|---|
| M03-R2-01 | major | plan U0/U0b/U10, §2 (l.262, 381, 397, 1239, 1546, 39–46) | `SigningGates` bodies are U10's (wave 4) while U0b rows 5 and 20 (wave 0) call them, and revoke is a request, so a `todo!()` is reachable; U2 and U6 gate tests need the real gate (Observed). | U0b phase 1 writes the gate bodies; U10 only wires them. |
| M03-R2-02 | major | ADR §18; plan §0.6, U0b row 1, U5, §5 item 19 | (a) `ipc::signing::SignOutcome` names `app::managed::SignPermit`, but `ipc` depends only on `contract` (`ipc/Cargo.toml`; `testkit/Cargo.toml` l.13–15 keeps store and app out of the IPC test build). (b) `EnrollmentPlan::build` lives in `enroll`, above `app`, which needs the plan with no port; an inherent impl in another crate is not allowed (Observed; plan l.377, 262, 773, 784, 809, 2334). | An opaque permit guard in `ipc` (e.g. `Box<dyn Send>`) that `app` fills; plan preconditions and digest in `heimdall-registry` or `domain`, `enroll` only I/O; an `ipc→app` mutant fixture in the crate-graph step. |
| M03-R2-03 | major | ADR D2 item 3a (l.257–262), D7 item 2 (l.1377–1400); plan l.2259 | The cascade set is computed before the gates are taken, so a child delegated in between can install and sign after the acknowledgment; no global lock order (deadlock between a cascade and a lock revocation); revocation holds the exclusive gate while closing masters (up to 5 s plus 5 s); nothing says what a narrowing does when its wait expires (text Observed; race Inferred). | Gates ancestor-first then by grant ID; delegation holds the parent's gate shared until the child's first install, or the revoker re-reads descendants after taking the gates until stable; close processes after releasing the gates (keys destroyed and unlisted while held); a narrowing never proceeds without its gates; deterministic tests for delegation during revocation and two concurrent cascades. |
| M03-R2-04 | major | ADR §6.3 fence (l.882–883, 897–912), §6.7 (l.1124), table (l.778, 791) | The mutation window is measured from the script's own start; nothing bounds when a script starts. A CLI killed while ssh waits on an approval leaves the append in ssh's stdin; reconcile goes `withdrawn` (final, untracked); the stale approval later lets the script take the free lock and append an untracked line. Tests pause only after the lock (Inferred). | Each mutating script carries an absolute remote not-after (E2's `remote_now` plus elapsed continuous time), checked at the lock and before the write (exit 41); `SshStepRunner` ties ssh's lifetime to the CLI (process group and death signal; job object on Windows); a record leaving an uncertain append for `withdrawn`/`abandoned` keeps a possible-late-write residual until an inspect after the not-after; test a script that starts after the hard deadline. |
| M03-R2-05 | major | ADR table (l.776), §6.5 (l.1051), §6.3 (l.835–838), l.735; plan §5 items 10, 18 | `held` exits only to removing, manual removal or abandoned; after a legitimate host-key change every removal is refused `route_changed` and `RemoveEnrollment` carries no target; `abandoned` is non-final and the partial unique index makes re-enrollment `already_enrolled`; only a CA rotation recovers (text Observed). | A decision re-approving the target (new key shown as a diff), or a `RemoveEnrollment` carrying a freshly evaluated target; owner-driven `held → reverifying` for evidence-based holds; `abandoned` out of the uniqueness rule (re-enroll with a new marker, the old residual listed). |
| M03-R2-06 | major | ADR l.780–782, 1052; plan §5 items 3, 10 | After an inconclusive result `enroll verify` retries from `applied_unverified`, a failure goes to `rollback_pending` (a remote removal), but `enrollment.verify` is local and never removes, and the `EnrollAccount` approval lasts 24 h; whether `enrollment.apply` is still open is unstated (Observed). | Retry under the open `enrollment.apply` (via reconcile); after the approval lapses a failure goes to `held` and removal needs `RemoveEnrollment`; add the path to the recovery-path tests. |
| M03-R2-07 | major | ADR D4 item 5 (l.637–663); plan §5 items 9, 16, 18 (l.2128, 2216, 2307), l.182, 337 | `ForeignRemovalRecord.state` has no type or transitions; no reconcile path for a lost reply; the hostname cross-check is unspecified; the bundle carries only `registry_path_display`, which M3 forbids parsing back (Observed). | Reuse the removal sub-machine and §6.7 reconcile by marker; exact evaluated HostName and Port equality, else `bundle_host_mismatch`; the bundle carries a canonical `registry {path, resolved_by}`; a lost-reply test. |
| M03-R2-08 | major | plan U5 l.903; §3 A10 row (l.1567) | The `principals_not_enforced` fixture ("a line without `principals=`") cannot produce that outcome: a bare `cert-authority` line refuses every certificate whose principals lack the user name. **Observed** (OpenSSH 10.5p1 loopback, scratch CA): bare line: positive refused, negative refused; `principals="hm:dst1:acct"`: positive accepted (0), negative refused. | Account form: a line listing `hm:<dest>:<acct>,hm:verify-negative:<nonce>` written at a pause hook once the nonce is known; system form: an `AuthorizedPrincipalsCommand` echoing the presented principals; keep the bare line as a separate `verification_failed` test. |
| M03-R2-09 | major | ADR l.1026, 1072, 1078; plan l.1265 | An unrecorded client makes every verification inconclusive; "client version" granularity unspecified; evidence invalidated on any client change; re-verification only at 80 days, so a routine OpenSSH update strands new enrollments and drops `verified_server_principals` (Inferred). | Key trace patterns by upstream release family (portable, Win32) with recorded ranges; re-verify promptly after a non-contrary invalidation (client or CA change, not host key); an unrecorded family gives a doctor finding naming the version. |

## Minor

| ID | Location | Defect | Fix |
|---|---|---|---|
| M03-R2-10 | ADR §6.3 scripts; plan l.2270 | `sh -s` runs the complete lines of a truncated stream and exits 0; the ~546 KiB remove script exceeds a pipe buffer, so a killed CLI runs a prefix. **Observed** with `/bin/sh` and `dash` (the prefix created the lock and token). | Wrap each script in a function called on its last line; a golden test at every truncation point. |
| M03-R2-11 | ADR l.882–883 | The hard deadline is on the boot-scoped continuous clock, void after a reboot (`domain/time.rs`), so a stale lock is never breakable or behaviour is undefined (Observed). | Persist the issue's wall time and boot ID; after a reboot the deadline passes on safe wall time (after `time confirm`). |
| M03-R2-12 | ADR l.1505 vs plan row 19 (l.395) | The Unix owned-connection row is written on a later holder pass, not at bind; a revocation in the first interval misses it (Observed). | Write the row at bind with the expected image; verify the image before signalling. |
| M03-R2-13 | ADR l.988, 1050; ADR-0005 l.396–400 | A destination lagging >60 s refuses the positive login, classified `verification_failed` with rollback, although E2 recorded `remote_now`. | Use the offset: `verification_inconclusive`, `destination_clock_skew`, no rollback. |
| M03-R2-14 | ADR l.920 | `awk printf "%c"` is locale-dependent (gawk in UTF-8 writes multibyte for ≥128); scripts do not set `LC_ALL=C`. Observed bwk awk 20200816 writes one byte; gawk Inferred. | `export LC_ALL=C`; a non-ASCII registry test on every target shell. |
| M03-R2-15 | plan l.130–131 vs l.392; ADR l.1958 | Release builds both "refuse" and "ignore" the M03 test variables; M01/M02 refuse with exit 2 (`testcfg.rs` l.28–32). | Refuse; rename `release_build_ignores_m03_test_gates`. |
| M03-R2-16 | plan l.60, 1590, 2443; ADR l.1535, 2455 | Q18–Q21 and the exit decision still read as open; the blocked list omits `m03-store-macos-keychain` (B3), `m03-store-linux-secret-service` (B11), `m03-sleep-logout-reboot` (B12). | Sync with §17.3; list every blocked record. |
| M03-R2-17 | plan l.1182, 1193, 1226, 1509, 2359 | U9 in wave 1 depends on U2 (wave 2); it claims `Operations::on_session_lock` in an integrator-only file; `wait_epoch_change()` differs from the frozen `changed()`. | One port signature; operations bodies to U0b; fix the wave. |
| M03-R2-18 | ADR l.1754; plan l.2569 | After `setup apply`, ordinary `ssh <alias>` fails whenever no binding holds the slot (auto-activation is M05), and neither the enrollment result nor the preview says so. | Disclose in `EnrollmentResult.next` and the `ApplyProjection` preview; doctor and TUI report `slot_free` with the command. |

Testability: no "verified" claim can come from a mock, emulator or test store, except the A10
`principals_not_enforced` evidence (R2-08).

## Commands (reviewer)
Read-only reads (exit 0); probe 1 (awk version, `%c` 200 under UTF-8 and C, srand, truncated script:
exit 1, a cut inside line 1); probe 2 (whole-line cut with `/bin/sh -s` and `dash -s`: sh 0 with lock
and token created; dash "File exists"); sshd fixture setup (0); four sshd probe runs on 127.0.0.1 with
`ssh -F /dev/null`, `IdentityAgent=none` (255, 255, 0, 255, as in R2-08); no listener left; scratch
removed; status clean. No builds or tests.
