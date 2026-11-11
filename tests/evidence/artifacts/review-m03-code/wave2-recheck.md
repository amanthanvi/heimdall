# Heimdall M03 wave-2 independent re-check

Reviewer: Codex (gpt-6.1-sol, independent). This re-checks `0478f6cd..5adb67da`, the fixes for W2-R01/W2-S01, W2-R02 and W2-R03 and the Windows test fixes, in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.19.

**Verdict: merge.** No new actionable defect found in `0478f6cd..5adb67da`.

Reviewed detached head `5adb67da21a2eaa46c0c72cc6749ab79a339109b` in `<scratch>/wt`, on macOS, using the pinned Rust 1.99.1 toolchain. This is a review of the committed fixes, not release or native Windows certification. I formed the initial assessment from the diff and surrounding callers before reading `wave2.md`, `wave2-security.md`, and ADR-0008 §17.19. No source, tests, fixtures, configuration, commits or remote state were changed. The only retained file is this report.

## Claimed fixes

### W2-R01 = W2-S01 — resolved

At `crates/app/src/operations/authorize.rs:172`, both precheck and gated admission call the same authorization transaction. Its ReadOnly branch now receives SafeNow from `TxnGate::assess_read_only`. At `crates/app/src/timegate.rs:185`, that method assesses once and constructs SafeNow from `a.now`, `a.sync`, and `a.tolerance`; it retains the same-boot anchor/confirmation requirement. The public read-only assessment delegates to this implementation without substituting an observation.

Counter-scenarios considered: rollback before assessment is judged by the gate; rollback immediately after assessment retains the earlier baseline and is detected at release; a boot change fails the permit boot check or release check. The separate paired observation in `admit_signature` maps absolute expiry and does not replace the assessed baseline. Peek constructs SafeNow from its own assessed observation. `TxnGate::admission` takes another observation but combines it with the assessed admission using the stricter verdict; it does not bless that observation as SafeNow. Reserve/publication use `issuance_time` → `gate.check`, which also returns its assessed observation. The issuer's signing check (`crates/issuer/src/check.rs:204`) passes the anchor and verdict returned together by `assess_read_only_in` to `issuance_ro::assess`. I found no remaining version of the reported double-observation defect on those paths.

Observed: `signature_refused_when_wall_clock_steps_back_after_the_time_assessment` passed through the real signer/enqueue fixture, including its zero-step release control. All 37 runnable signer tests passed. I did not revert the fix to independently demonstrate a red regression run.

### W2-R02 — resolved

`crates/domain/src/issuance.rs:201` adds a default-false, omitted-when-false stored field. `reserve_issuance_with` persists the facts assessed in its transaction (`operations.rs:10994`). `issuer_facts` reads the stored field rather than sign-request data (`issuance_ro.rs:61`). Publication ORs caller new-activation with `!entry.continuing` (`operations.rs:11094`), so a later caller cannot relabel a new-activation reservation as continuing.

Counter-scenarios considered:

- A sign request cannot set the field: it carries an entry reference and public subject, and the issuer rereads the entry from the store.
- A caller publishing a false/new-activation entry with continuing facts still gets the activation predicate. The new integration regression explicitly exercises that attempt under a pause and observes a voided entry with PausedActivation.
- The initial internal Rust reserve API does accept `IssuanceFacts.new_activation` from its caller, as it already did. This patch persists that existing trust decision; it does not independently prove renewal provenance. There is no IPC contract field or runtime dispatch path exposing that bool to an agent request in this head. Issuance still requires an existing permitted grant and the full reserve predicate; new grant authorization is a separate operation. Future managed-driver wiring must supply truthful facts. I found no newly reachable untrusted request that can use this addition to create a grant or bypass its activation authorization.
- Generation-only re-reservation explicitly copies `entry.continuing` (`operations.rs:11142`). Store publication/voiding deserialize and mutate the entire entry (`crates/store/src/ext.rs:1491`); list/read paths likewise deserialize the full record. They preserve the field. The sole production entry constructor is the shared reserve helper. Test constructors were updated.
- Old rows deserialize as false and continue to get the previous issuer's activation check. False reserialization omits the key, preserving that record shape. True adds the key to record_json; no SQL column/index migration is needed. The domain record has no JsonSchema derive and is not referenced from the public contract/schema tree. This is an additive persisted-record and internal Rust struct change, not a public JSON schema-golden change. In-tree constructors compile.

Observed: the paused continuing-reissue/new-activation integration regression passed; the fixed-seed 256-case predicate-equivalence property passed with its generated continuing bool, pause/cutoff/generation and other mutations. The six issuer linearization model tests passed. The dedicated old-row serialization unit regression was inspected and compiled by all-target clippy, but was not separately executed.

### W2-R03 — resolved

`crates/issuer/src/client.rs:640` invalidates the lifecycle before awaiting anything, takes the task handles, aborts and awaits them, then acquires the link. Restart checks the lifecycle after its delay and again inside `start_once` after acquiring the link; reload checks inside the held link. Demand while stopped does not start either recovery path. Explicit start/reload can begin a new lifecycle.

Counter-scenarios considered: stop during backoff, waiting for the link, hello, or load. Tracked task cancellation drops the async link guard; stop does not hold that guard or the synchronous view/tasks locks while awaiting a task, so I found no new lock-order cycle. Aborted protocol exchange retains the existing dirty/outstanding bookkeeping; shutdown skips a dirty write and falls back to the child-exit timeout. A task registered concurrently just after stop drains the handle list is not joined by that particular drain, but its captured old lifecycle fails the check before spawn/load; it cannot resurrect the stopped issuer. This is a narrow bookkeeping race, not an identified authority or child-lifetime escape after stop returns. An operation already past a check can progress concurrently with stop until cancellation/link acquisition; stop completes cleanup before returning. No stronger instantaneous-preemption guarantee is inferred.

Observed: `stop_during_restart_backoff_spawns_no_child_and_reloads_no_ca` passed, including demand after stop, virtual-time advancement, and explicit restart. Existing real-child lifecycle/crash/late-reply tests also passed. I found no introduced deadlock or hanging stop scenario; exhaustive scheduler interleavings were not executed.

### Windows test changes — resolved by source inspection; native validation blocked

The identity-form listener uses `Endpoint::in_scratch`, retaining a real listener and the same agent protocol/assertions while satisfying the fixture-only guard. Consumer `ssh -G` fixtures now use the admitted fixture pipe prefix; those names are only rendered, with no listener or connection intended. The Unix path positive checks remain on Unix; Windows now explicitly asserts rejection of host-built mixed-separator Unix paths. In `projection_managed.rs:452`, percent escaping, Windows mux refusal and socket-length checks still run on every host. No whole test was cfg-skipped by this patch. These changes preserve the tests' intended host semantics. I did not execute the changed Windows branches or their consumer targets.

### M02 pipe retry — resolved as a bounded passive retry; intermittent-failure hypothesis unverified

At `crates/adapters/src/detect.rs:118`, each attempt only enumerates the local pipe namespace, with the existing per-listing name bound. At most three listings run; the first matching name returns Present, otherwise the last complete/failed result determines Absent/Unknown. A permanently absent name cannot become Present solely because of retry, and there is no pipe open/connect, sleep or wait-for-pipe operation.

A listed pipe can close before the function returns, as with the old single enumeration; Present remains an observation of a listed name, not a guarantee of current availability or ownership. The retry triples worst-case enumeration work. The name-count bound is not a wall-clock deadline: OS enumeration latency remains unmeasured here. This is not evidence that the intermittent native failure is fixed. The unit test for scripted listing outcomes was inspected and compiled by clippy, not executed; native Windows behavior remains blocked by the missing Windows execution platform in this review.

## New findings

None. No W2-C01 or later finding assigned. The explicit limits above are not newly demonstrated defects.

## Commands and observed exits

All builds/tests ran only in the requested checkout, using disposable fixtures. No owner keys, real agents, SSH/Git configuration, login keychain or 1Password were used as test targets. No commit or push command ran.

| Command | Exit | Observed result |
| --- | ---: | --- |
| `git -C <repo> worktree add --detach <scratch>/wt 5adb67da` | 0 | Detached requested head |
| `git diff --stat 0478f6cd..5adb67da`; `git diff 0478f6cd..5adb67da -- crates`; corresponding tests diff; `git diff --name-only 0478f6cd..HEAD`; `git log --oneline 0478f6cd..HEAD`; `git rev-parse HEAD` | 0 | One commit, 21 changed files; pinned full head above |
| `cargo test -p heimdall-issuer --test integration_issuer_child --locked` | 0 | 33 passed, 0 failed; property run included, suite 92.21 s |
| `cargo test -p heimdall-credential --test integration_managed_signer --locked` | 0 | 37 passed, 0 failed, 1 ignored/blocked: B3 disposable second macOS account; suite 11.48 s |
| `cargo test -p heimdall-issuer --test model_issuer_linearization --locked` | 0 | 6 passed, 0 failed; suite 3.83 s |
| `cargo clippy -p heimdall-app -p heimdall-domain -p heimdall-issuer -p heimdall-adapters --all-targets --locked -- -D warnings` | 0 | No warnings/errors |
| `git status --short` / `git status --porcelain`; `git diff --exit-code`; `git diff --cached --exit-code` | 0 | No tracked or untracked review edits |
| `du -sh target` | 0 | Root build output 2.3 GB, removed with checkout |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` under zsh, then bash | 1 / 1 | No matching prototype output directories; zsh unmatched glob, bash absent-path diagnostics |

Read-only inspection also used `cat`, `sed -n`, `nl -ba`, and targeted `rg -n` over manifests/toolchain, spec/plan, changed functions, all entry constructors/copy paths, signing/time callers, tests, the prior reports and §17.19. Successful file reads exited 0. Initial searches with `crates/runtime/src/managed*` and `issuer*` hit zsh unmatched-glob errors; corrected directory searches succeeded. Two schema searches included nonexistent `tests/golden`/`tests/contract` paths (rg exit 2); the corrected `rg -n 'IssuanceEntry' crates/contract schemas` returned no matches (exit 1). A targeted historical memory-registry search for Heimdall/M03 returned no matches (exit 1); no memory evidence was used. Home instructions and the code-review skill were read with exit 0. Inspection batches sometimes returned only the final shell command's status; failed constituent searches are disclosed here rather than treated as successes.

## What I did not check

No native Windows, WSL or Linux execution; no native pipe timing/stress reproduction; no disposable second macOS account; no product secure-store or privileged-service tests. No full workspace test run, release-profile build, standalone unit-test run, full schema-golden suite, or independent revert-to-red run. The changed projection/consumer Windows fixtures were reviewed, not rerun. Later U6/U7/U10 managed end-to-end wiring and verification signing remain outside this fix re-check. No extra reviewer was spawned: this task itself is the independent review.

Cleanup observed: `git -C <repo> worktree remove --force <scratch>/wt` exited 0; `rmdir <scratch>` exited 0. A final `test -s` on this report and `test ! -e` on both checkout and parent exited 0. The checkout and all of its build outputs are gone.

The principal remaining risk is native Windows behavior and latency of the speculative pipe mitigation; these passing macOS suites do not close that platform claim.
