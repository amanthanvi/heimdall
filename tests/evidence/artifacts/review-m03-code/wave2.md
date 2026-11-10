# M03 wave-2 independent correctness review

Reviewer: Codex (gpt-6.1-sol, independent), the code review of `961c6201..0478f6cd` (M03 wave 2), in its own scratch checkout. Saved by the orchestrator with paths redacted. Rulings: ADR-0008 §17.19.

**Verdict: fix first.**

Reviewed commit `0478f6cd28cf9e44db9b76494d81489975f311c4`, whose parent is `961c6201a3638c2bed5dba372c710a91c97774bb`, in the requested detached checkout. No repository source, tests, fixtures, configuration, commits or remote state were changed. The sole retained output is this report. The detached worktree, including its 5.3 GB build directory, was removed, and its empty parent directory was removed.

## Findings

### W2-R01 — High / P1: the new authorization default blesses an unchecked clock observation

**Location:** `crates/app/src/operations/narrowing.rs:295` (enables this path by default); `crates/app/src/operations/authorize.rs:166–178` (the affected path).

**Evidence classification: inferred from source; no clock-race reproduction was added or executed.**

The `ReadOnly` branch calls `assess_read_only`, retains only its `TimeStatus`, then calls `clock.observe()` again to construct `SafeNow`. The second observation was never judged by the time gate. It is then used in the authorization transaction, and becomes the reference observation for `AdmittedTime`'s release check. This differs from the previous `Peek` default, which assessed the actual observation used by authorization inside that transaction.

Concrete scenario: a same-boot clock step backwards beyond the allowed rollback/skew occurs after the read-only assessment returns `Safe`, but before the second observation. The grant still has continuous budget remaining. Authorization sees a wall value before the deadline and an open continuous budget, and can admit the request. If the clock then progresses normally from that stepped value, the release check compares against the new, unchecked baseline and can also pass. `admit_signature`'s paired observation constrains expiry and checks boot identity, but does not assess drift between that observation and the unchecked `SafeNow`. Thus it does not restore the missing time-uncertainty refusal. The continuous budget remains a useful upper bound; this finding does not claim it disappears.

ADR-0008 D2 items 3/3a require fresh safe-time authorization, not a safe verdict borrowed from an earlier reading. Use the observation and verdict returned by `assess_read_only_in` together in the authorization transaction, preserving the gate's time semantics. Add a deterministic clock test that steps between the two current observations and asserts that nothing is released.

### W2-R02 — Medium / P2: the issuer disagrees with publication for continuing re-issue during a pause

**Location:** `crates/app/src/issuance_ro.rs:48–51`; supporting paths `crates/app/src/operations.rs:11444–11448` and `tests/integration/issuer_child.rs:247–250`.

**Evidence classification: inferred from source; the existing predicate-equivalence test passed, but does not cover this distinction.**

`ISSUER_FACTS.new_activation` is always `true`. Reserve/publication accept caller facts with `new_activation = false` for a re-issue within an existing grant. The shared snapshot assembly deliberately uses `continuing_policy` for that case, removing the pause; the issuer instead uses `merged_policy`, retaining it. The domain predicate then refuses `PausedActivation`.

Concrete scenario: an active grant loses its execution key while its standing policy is paused. Its existing deadline, enrollment, CA and other predicates still permit continuing work. The runtime can reserve a re-issue and its publication predicate can pass, but the issuer refuses that reservation as a new activation. The grant cannot recover until the owner unpauses a policy that is meant to block new work only. This violates the continuing-work semantics documented in `operations.rs:903–911` (spec §5.6 / ADR-0006 §13.6 item 1), and ADR-0008 D3 item 4's predicate agreement.

The integrator explicitly records this as unresolved U3-Q2; disclosure does not establish equivalent behavior. Resolve how the reservation records or proves activation versus re-issue, rather than inferring authority from untrusted request fields. The equivalence property currently returns `issuance_ro::ISSUER_FACTS` from its own `facts()` helper, so it forces both sides to use `true` and cannot expose the mismatch. Cover a real continuing re-issue with `false` under a paused policy. The linearization model exercises re-issue, but its event set does not cover this paused continuing-work case.

### W2-R03 — Medium / P2: a pending restart survives `stop()` and can recreate the issuer

**Location:** `crates/issuer/src/client.rs:448–452`, `client.rs:469–479`, and `client.rs:560–587`.

**Evidence classification: inferred from source; no additional lifecycle reproduction was executed.**

`supervise()` starts a detached task holding `Arc<Inner>`. `restart_cycle()` sleeps and then calls `start_once()` unconditionally. `stop()` takes and closes the current link, but neither cancels/joins the restart task nor sets a state that the task checks before spawning. Its final `Unavailable` state is not a stop fence.

Concrete scenario: a protocol failure crashes the child and schedules the first restart delay. The owner/runtime calls `stop()` during that delay. With no link, stop returns promptly. The outstanding restart task subsequently spawns and loads another issuer and changes state to `Ready`. Dropping the last public `ChildIssuer` handle does not prevent this, because the restart task itself retains `Inner`. This breaks shutdown's child-lifetime and key-unloading contract, even though it does not bypass reservation checking or publication.

Fence restart/reload work by a lifecycle generation or cancellation mechanism, and have stop wait for or invalidate work belonging to the stopped lifecycle. Test stop during backoff and verify that no child is spawned or CA reloaded afterwards without a new explicit start/demand.

## Other review conclusions and evidence limits

- The managed signer follows purpose → precheck → gate admission → bounded blocking signature → permit-bearing release. The reviewed table distinguishes pending/installed state, requires published matching entries and an installation view, checks vault-slot continuity after admission, and removes grant identities before key destruction. Endpoint cleanup checks binding generation and locator. No additional confirmed defect was found in those paths.
- The issuer checks frame length before body allocation, rejects malformed/out-of-order frames, opens the database read-only, and does not publish. The client retains partial response bytes and tracks replies owed after cancellation. Existing tests exercised oversized/malformed frames, EOF, late replies, crash accounting and real child-process lifetime. Those passing cases do not test the stop/backoff race above.
- On this host's actual **OpenSSH 10.5p1**, INT-Q10 observed `CertificateAsIdentityFile` and the actual rendered P row both complete login with one certificate sign request and one accepted certificate login. D10-as-written failed with exit 255 and no sign request; making the public files owner-only did not repair it. The verification-shaped row listing both plain key and certificate requested the plain key and authenticated with the certificate.
- The proposed form is sound for the observed isolated certificate-only path. `IdentitiesOnly yes` does **not** make arbitrary inherited `IdentityFile`/`CertificateFile` entries disappear. It therefore does not establish universal absence of fallback. D10 item 6's `not_exclusive`/`undetermined` classification and M02 fallback clearance remain necessary. This review found no reason to weaken the plain-K_env refusal.
- `ManagedSigner::purpose` allows a verification request naming plain K_verify only if the signed userauth data contains an installed positive certificate, matches its pair/account, and equals the currently installed certificate. Plain-key userauth data fails that check. Production verification still refuses signatures via `Operations`, as documented by unresolved INT-Q13; the successful verification endpoint tests use a fixture authority. Installation also lacks plan-CA/pair binding, already disclosed in the INT-Q13 addendum. These remain integration limits, not verified production verification.
- The selected identity form differs from D10's literal identity lines. §17.18 authorizes investigation of alternative forms; the notes still identify the D10 amendment and native 9.5p2 evidence as outstanding. I did not independently verify the notes' container/native claims. INT-Q10 intentionally asserts only its control and invariants, not candidate success; its green status alone is not a per-client compatibility verdict. The successful selected row above was actually observed.
- Existing-access projection byte identity passed its dedicated test. All 54 ordinary M02 launch tests passed, including environment/argv preservation, observed-alias connect, noninteractive fallback refusal, replay, side-channel failures and binary ssh/git/scp/sftp flows. The M03 consumer target passed, but its managed connect argument test inspects rendered options through real `ssh -G`; it is not an end-to-end managed `ensure`/`bind`/connect launch. Managed runtime wiring remains staged.

## Commands and exit codes

Commands below ran in `<scratch>/wt` unless a different path is shown. Cargo used the pinned Rust 1.99.1 toolchain and the normal workspace target directory; no alternate target directories were created. Several builds waited for Cargo's shared build lock.

| Command | Exit | Observed result |
|---|---:|---|
| `git -C <repo> worktree add --detach <scratch>/wt 0478f6cd` | 0 | Requested detached checkout created |
| `git diff --stat 961c6201 0478f6cd`; `git log --oneline 961c6201..0478f6cd` | 0 | One commit; 43 changed files |
| `git diff 961c6201 0478f6cd -- <reviewed paths>` | 0 | Inspected app, consumer, projection and discovery changes |
| `cargo test -p heimdall-credential --test integration_managed_signer --locked` | 0 | 36 passed; 1 ignored, explicitly blocked on B3 disposable second macOS account |
| `cargo test -p heimdall-issuer --test integration_issuer_child --locked` | 0 | 31 passed, including the 256-case predicate property; 96.92 s test execution |
| `cargo test -p heimdall-localenv --test integration_projection_managed --locked` (first run) | 101 | 10 passed, 3 failed because `hm-fixture-hook` was not built |
| `cargo test -p heimdall-credential --test integration_managed_identity_forms --locked -- --nocapture` | 0 | 1 observation test passed; actual per-form outcomes described above |
| `cargo test -p heimdall-issuer --test model_issuer_linearization --locked` | 0 | 6 passed |
| `cargo test -p heimdall-testkit --test integration_testkit_fixtures --locked` | 0 | 18 passed; also built the required fixture hook |
| `cargo test -p heimdall --test e2e_consumer_m03 --locked` | 0 | 6 passed |
| `cargo test -p heimdall-localenv --test integration_projection_managed --locked` (rerun) | 0 | 13 passed |
| `cargo test -p heimdall --test e2e_run_m02 --locked` | 0 | 54 passed; 1 ignored child-mode entry, invoked by the PTY tests |
| `git diff --check 961c6201 0478f6cd` (twice) | 0 | No whitespace errors |
| `git rev-parse HEAD`; `git rev-parse HEAD^`; `git status --short` | 0 | Exact requested head/parent; clean worktree |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | 1 | No matching prototype build directories; first zsh invocation rejected the unmatched glob, bash retry reported absent paths |
| `du -sh target` | 0 | 5.3 GB before removal |
| `git -C <repo> worktree remove --force <scratch>/wt` | 0 | Checkout and all its build outputs removed |
| `rmdir <scratch>` | 0 | Empty parent removed |

Additional read-only inspection used `cat`, `sed -n`, `nl -ba` and targeted `rg -n` on the named source/test files, workspace manifests/toolchain, ADR-0008 (including §17.17–17.18), m03-plan U2/U3/U8, relevant spec/plan sections, and the wave-2 notes. Those inspection batches exited 0. Startup inspection of the active Codex home instructions and review skill exited 0; a targeted memory-registry search found no Heimdall/M03 entry (exit 1), and no historical memory evidence was used. No Docker fixture scripts, Git configuration commands, commit or push commands ran.

## What was not checked

Native Windows in-box 9.5p2, native devbox 9.6p1, WSL, second-account access, product secure stores, release-profile custody, full workspace/clippy checks, Docker fixtures and later U6/U7/U10 runtime integration were not executed. Tests used disposable fixture material; no owner's SSH keys, agents, SSH files, login keychain or 1Password were test targets.

The three findings are source-based failure scenarios, not newly executed reproductions. Passing tests establish the listed cases only; they do not close native compatibility or the authorization/re-issue/shutdown risks above.
