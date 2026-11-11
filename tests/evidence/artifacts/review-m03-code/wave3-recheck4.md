# Heimdall M03 wave-3 round-4 independent re-check

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`). This re-checks `155d2f6c..66932c68` (round 4), in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.20 items 16 and 17.

**Verdict: fix first.** W3-C03 is **not fully resolved**: the committed regressions pass, but a before-pidfile shell still survives a successful normal drop if its client closes before teardown. The new descendant walk also has a separate ancestor-PID-reuse ownership gap (W3-C04).

Reviewed `66932c681e4680fc5a4e055d132ceeb3d4e66fba`, parent `155d2f6cfc77867b72b93d90378b0099b584d4eb`, in the requested detached checkout. Native platform: Darwin 27.2.0 arm64; `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. I formed the initial assessment from the code diff and its callees before reading the round-4 worklog. The worklog's reported runs were not counted as my validation.

## W3-C03 — medium, test fixture: incompletely resolved

**Observed.** The two original stall positions work when the client stays connected until `World::drop` begins. The after-pidfile receipt now preserves the actual shell image and accepts the same process's subsequent sleep image. The before-pidfile shell is found through the still-intact sshd tree. Both committed regressions passed in four full runs and a separate focused run.

However, the before-pidfile identity is still lost when its session ends before the tree walk. Relevant locations at the reviewed commit:

- `tests/integration/connections.rs:343`: teardown creates cancellation, collects available pidfiles, then snapshots the remaining server descendants at line 352.
- `tests/integration/connections.rs:728`: a receipt is made only after a fixture pidfile can be read; the missing one remains pending.
- `tests/integration/connections.rs:433`: outstanding pending entries are counted for the diagnostic, but the assertion at line 439 checks only survivors already discovered. An orphan is outside the root's current tree and has no receipt.

I copied the committed test source outside the checkout and changed only the shared stall regression body to close its own client before dropping the world. After the existing assertions established the shell was stalled and had not exec'd sleep, I inserted:

```rust
let client_token = process_start_time(client).unwrap();
let client_image = image_of(client).unwrap();
stop_exact(client, &client_token, &[client_image]);
std::thread::sleep(Duration::from_millis(750));
// Observe shell identity and PPID, then use the original catch_unwind(drop(w)),
// survivor check, exact-identity fallback cleanup, and assertions.
```

The existing `_client` binding was renamed `client`; diagnostics printed whether the normal drop audit passed. No cleanup logic was changed in this probe. The client was a disposable SSH child started by this test, stopped through the committed token/image verification path.

**Result:** both shells became PPID 1 while retaining their exact identities. After-pidfile still passed because its pidfile supplied a receipt. Before-pidfile failed: the normal drop audit passed, but the exact shell survived the subsequent five-second check. I repeated the before-pidfile probe twice more; both failed identically:

| Probe | Shell PID / start token | Before drop | Normal drop audit | Regression exit |
|---|---|---|---|---|
| Client closed, both positions | Before: `1420 / 1794407094.397970` | alive, PPID 1 | passed (no audit panic) | 101; after passed, before failed |
| Before, repeat 2 | `1695 / 1794407136.027090` | alive, PPID 1 | explicitly `normal_drop_audit_ok=true` | 101 |
| Before, repeat 3 | `1843 / 1794407142.406504` | alive, PPID 1 | explicitly `normal_drop_audit_ok=true` | 101 |

Each failed probe printed `the stalled shell survived the fixture's teardown`. The regression's fallback then stopped that exact shell using its captured token and actual image. Subsequent independent tree and receipt audits found zero survivors. No process was selected for signalling by name or pattern.

The cancellation file cannot help a stopped shell that has already passed its initial check and never resumes to perform its second check. Keeping a missing pidfile pending also cannot recover an identity after reparenting. This is the same unregistered before-pidfile lifecycle problem as W3-C03, rather than a separate newly numbered finding.

**Required follow-up:** preserve ownership of the command before session/client teardown can orphan it, and cover this client-closed-before-drop sequence. A successful normal-drop audit must not declare this case clean.

## W3-C04 — medium, test fixture: intermediate parent reuse can admit an unrelated process

**Location:** `tests/integration/connections.rs:312`–`327`, especially the numeric PPID check at line 318 and `frontier.push(pid)` at line 327. Consequence reaches `stop_exact` at lines 469–483.

**Inferred OS race; confirmed in a deterministic model of the unchanged walker, not by forcing live OS PID reuse or signalling an unrelated process.** The root sshd is indeed an unreaped child, so its PID cannot be reused. Its intermediate children are not held unreaped by the fixture, however. The frontier stores only their numeric PIDs and never revalidates their recorded start tokens when walking through them.

Concrete schedule:

1. The `ps` snapshot contains owned root R → session P → command C.
2. The walker reads P's owned token/image and reconfirms PPID(P) = R, then pushes numeric P.
3. Before C is examined, P and C exit and are reaped. Unrelated P' and its child C' reuse those two numeric PIDs.
4. The walker examines the stale C → P pair. It reads C' **current** token and image and sees PPID(C') = numeric P. This passes, although P's recorded identity is gone and P' is outside the fixture tree.
5. The resulting receipt authorizes C'. `stop_exact` correctly verifies C' current token and image, so its verification cannot recover the missing ownership proof and may signal C'.

The standalone Rust probe extracted the `descendants` function body unchanged. Stubbed process observations supplied that schedule, using synthetic PIDs 10000/10001/10002 and `/bin/sleep` as the replacement image. Assertions confirmed the walker returned an `unrelated-reused-child` receipt, its token/image matched the replacement, and its recorded ancestor token was stale. Probe exit 0. A control model carrying the recorded parent token in the frontier and checking it after the child's PPID observation rejected that replacement; exit 0. Neither model sent any signal.

The current reconfirmation therefore does **not** establish the claimed live, already-identified parent at every edge. The PID/image guard protects a receipt's identity after capture; it does not prove that a newly captured identity belongs to the fixture. The walk needs to preserve and reconfirm ancestor identity across admission, with coverage for reuse during that interval. Ordinary successful tree walks do not close this race.

## Regression sensitivity and full-target validation

All runs used disposable fixture credentials and loopback SSH servers. `TMPDIR=/tmp` was set. The fixture receipt audit compared each recorded PID's **current start token** with the recorded one using the workspace's `process_start_time`; it did not search executable names.

| Full `integration_connections` run | Exit | Result | Fixture receipt audit |
|---|---:|---|---|
| 1, verbose build | 0 | 42 passed, 0 failed; 9.41 s test execution | 92 identities, 0 survivors |
| 2 | 0 | 42 passed, 0 failed; 9.54 s | 92 identities, 0 survivors |
| 3, independent observer | 0 | 42 passed, 0 failed; 9.54 s | 92 identities, 0 survivors |
| 4, independent observer | 0 | 42 passed, 0 failed; 9.51 s | 92 identities, 0 survivors |

For runs 3 and 4, an additional external observer started the test command as its own child and sampled numeric PID/PPID trees while it ran. It retained exact PID/start-token pairs and audited those identities after command exit: respectively **174 identities / 166 snapshots** and **178 identities / 164 snapshots**, both zero survivors. This is sampled observation, not proof that every arbitrarily short-lived process was captured.

A separate focused run of the two **unchanged committed** regressions passed, exit 0: 2 passed, 40 filtered out; 8 fixture receipts, 2 explicit stalled-shell identities, and 13 independently observed tree identities all had zero survivors.

I also restored round-3 cleanup behavior in a source copy outside the checkout: the old `World::drop` and `collect_remote` bodies, including the assumed sleep image, discarded zero-bound pending entry, and lack of a subtree walk. The only compatibility adaptations were the new receipt field representation and a boolean return required by the newer call sites; neither changes the exercised teardown behavior. The new stall hooks and regression assertions remained present.

Running both regressions against that copy exited **101**, 0 passed / 2 failed:

- After pidfile: PID `98647`, token `1794407020.519303`; old drop audit reported the survivor, followed by the regression's survivor failure.
- Before pidfile: PID `99474`, token `1794407036.025061`; old normal drop audit passed, followed by the regression's survivor failure.

The regression fallback cleaned both exact identities. The three mutant fixture receipts and two independently recorded stalled-shell identities subsequently had zero survivors. Thus both regressions detect the original round-3 behavior, despite missing the client-closed variation in the committed code.

## Scope and assertion check

The actual commit changes three files, not two: `tests/integration/connections.rs`, the stated round-4 worklog, and the notes `README.md` (two added lines). **No product code changed.** I found no weakened existing test assertion: the prior receipt-survivor assertion remains, the new subtree audit adds coverage, and the two bounded pidfile collection call sites now assert success. The unresolved problem is incomplete ownership/audit coverage, not removal of an existing assertion.

Reviewer repository changes: **none**. Scratch source copies and probes were created only under the requested temporary task directory. No commits, pushes, Git configuration changes, owner SSH material, owner agents, keychains, or 1Password were used.

## Commands and exit codes

Commands were executed from the detached checkout unless an absolute `git -C` path is shown. Python wrappers captured output without emitting bulk logs and reported the child command's actual exit status.

- `git -C <repo> worktree add --detach <scratch>/wt 66932c68` — 0.
- `git diff 155d2f6c 66932c68 -- tests/integration/connections.rs`; `git diff --stat 155d2f6c 66932c68`; `git diff --numstat 155d2f6c 66932c68`; `git diff 155d2f6c 66932c68 -- tests/evidence/artifacts/review-m03-code/wave3-notes/README.md`; `git show 155d2f6c:tests/integration/connections.rs` — each 0.
- `git rev-parse HEAD HEAD^`; `git log --format='%h %s' 155d2f6c..66932c68`; `git status --porcelain`; `git diff --exit-code`; `git diff --cached --exit-code`; `git diff --check 155d2f6c 66932c68` — each 0; status/diffs empty where checking reviewer edits.
- `rustc --version`; `uname -srm`; targeted `cat`, `sed`, `nl`, and `rg` inspections of instructions, test code, fixture/process APIs, manifests, spec and plan — 0. A memory-registry search for Heimdall/W3-C03 had no matches, exit 1; no historical memory evidence was used.
- `TMPDIR=/tmp HM_U7_RECEIPTS=<per-run file> cargo test -p heimdall-runtime --test integration_connections --locked -v` — run 1, exit 0.
- `TMPDIR=/tmp HM_U7_RECEIPTS=<per-run file> cargo test -p heimdall-runtime --test integration_connections --locked` — runs 2, 3 and 4, each exit 0; runs 3 and 4 invoked through the independent observer.
- Standalone audit and observer compilation: `rustc --edition=2024 <audit.rs or watch.rs> -L <captured dependency/native search paths> --extern heimdall_runtime=<built rlib> -o <scratch executable>` — each 0. Search paths and library argument came directly from Cargo's verbose integration-test rustc invocation.
- Scratch integration copies compiled by replaying that captured rustc argument vector, replacing only the source path, crate name/output, and output metadata/emit options — round-3 copy, closed-client copy, and instrumented closed-client copy each 0. No repository source was edited.
- `<committed integration binary> remote_command_stalled_ --nocapture --test-threads=1` through the observer — 0, both pass.
- `<round3_cleanup> remote_command_stalled_ --nocapture --test-threads=1` — 101, both expected failures.
- `<closed_client_probe> remote_command_stalled_ --nocapture --test-threads=1` through the observer — 101, after passes / before fails.
- `<closed_client_probe> remote_command_stalled_before_its_pidfile_leaves_no_process --nocapture --test-threads=1` through the observer — twice, each 101; normal drop audit passed and exact orphan survived in each run before the regression's fallback cleanup.
- `rustc --edition=2024 -Awarnings <ancestor_reuse_probe.rs or ancestor_reuse_control.rs> -o <corresponding scratch executable>` — each 0; each executable — 0, asserting the counterexample and rejection control respectively.
- Exact-identity audit executable on each full-run, mutant, focused, closed-client, and explicit shell receipt file — every invocation 0, zero survivors after test/fallback cleanup. Observer process-tree audits also found zero survivors after probe fallback cleanup, including each intentionally failing probe.
- `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` — 1 because none of those prototype output paths existed in this checkout. `du -sh target` — 0, 1.9 GB; removed with the worktree.

## Cleanup

`git -C <repo> worktree remove --force <scratch>/wt` completed with exit 0. It removed the checkout and its 1.9 GB Cargo target. A Python cleanup removed the 553 reviewer-created scratch files (sources, binaries, compiler objects, logs and receipts), then removed the now-empty `<scratch>`; exit 0. Immediately before removal, a final audit of all 20 receipt files (784 recorded identity entries, including repeated entries across audit types) found zero survivors and exited 0. The report is the sole retained artifact.

Not checked: Linux/Windows/WSL native execution, the full workspace suite, clippy, actual forced OS PID reuse, and broader M03 product behavior. The PID-reuse finding is an inferred race with a deterministic model, not an observed wrong-process signal.
Risk: the stopped before-pidfile shell can still leak after client closure while the fixture audit passes; intermediate-parent reuse can also admit an unrelated identity into cleanup.
