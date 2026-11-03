# M02-W2-code-review — 3e51f49b — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved verbatim by the orchestrator on 2026-11-03. This is the
cross-model review that progress.md recorded as owed. Orchestrator resolution: ADR-0007 §12.18.

Reviewer: Codex, independent review sub-agent. Mode: **READ-ONLY**.

Reviewed commit: `3e51f49bf942d85b90588b3af6c39d6ee27f4358`. Change range: `c380ddf4..3e51f49b`.

The required workspace tests, formatting check and Clippy check pass. However, four additional scratch-only probes reproduced defects outside the acknowledged §12.16/§12.17 follow-ups. These affect descriptor ownership, preservation of active edits, preview stability and Git locking. A fifth finding concerns an unbounded DNS lookup and is inferred from the implementation. Fix these before shipping this wave.

## Findings

### X01 — P1 — Safe descriptor adoption can redirect writes into an unrelated file

**Location:** `crates/localenv/src/sys/mod.rs:273`, `crates/localenv/src/sys/mod.rs:444`, `crates/localenv/src/sys/mod.rs:454`.

**Defect:** `adopt_inherited_fd` is a safe public function that constructs an `OwnedFd` from an arbitrary open descriptor number. Its checks establish type and access mode, but cannot establish exclusive ownership. The one-adoption guard prevents two calls to this function; it does not prevent another `File` or `OwnedFd` from already owning the descriptor.

**Concrete failure scenario:** A caller passes a writable `File`'s `as_raw_fd()`. Adoption succeeds. Dropping the returned `OwnedFd` closes the descriptor. Opening another file reuses that number, and a write through the original, still-live `File` writes into the unrelated file.

**Evidence:** A compiled scratch probe performed this sequence using safe Rust and two disposable files. The assertion that the unrelated file remained empty failed with exit **101**. No owner data was involved. The production safety comment explicitly leaves the exclusivity invariant to the caller.

**Observed or inferred:** **Observed** through the exported API. This was not a CLI end-to-end reproduction.

**Fix:** Accept ownership through an owned descriptor, or put raw ownership transfer behind an explicitly unsafe boundary whose caller proves exclusivity. Propagate the ownership contract through `SideChannel::from_fd`. The atomic one-adoption guard is insufficient.

### X02 — P1 — Create rollback moves a newer edit before checking its content

**Location:** `crates/localenv/src/projection/apply.rs:1691`, `crates/localenv/src/projection/apply.rs:1970`, `crates/localenv/src/projection/replace.rs:1659`.

**Defect:** The create-rollback branch fires `BeforeRestoreCheck`, then records the restore and begins settlement without checking the active file's digest again. `settle_with` checks identity before moving, but checks content only after the move into quarantine.

This violates §5.3 step 7 and row C7a: an already-modified active S must remain at its path and hold the operation.

**Concrete failure scenario:** First adoption creates an absent user SSH configuration. A failed transaction check triggers rollback. An editor appends a new host entry at `BeforeRestoreCheck`, before the promised content check. Heimdall moves the edited configuration into quarantine, leaving the active configuration path absent.

**Evidence:** A scratch probe forced rollback by editing inactive P after the user step's post-validation, then appended to the created user configuration at `BeforeRestoreCheck`. The assertion that the user configuration still existed failed with exit **101**. The bytes are preserved as an artifact, but the newer edit disappears from its active location.

**Observed or inferred:** **Observed** through the real transaction and existing hook interface.

**Fix:** Recheck identity and target digest before moving an active create-rollback source, and return `ActiveEntryModified` when it changed. Apply the same protection when continuing a path-source settlement. Add the concurrent-edit regression alongside the existing crash-while-down C7a test.

### X03 — P1 — First-adoption previews cannot reproduce their approved digest

**Location:** `crates/localenv/src/projection/plan.rs:264`, `crates/localenv/src/projection/plan.rs:1127`, `crates/localenv/src/projection/plan.rs:1093`.

**Defect:** Every first-adoption preview generates a fresh random marker. That marker changes the inserted block, its target digest and the canonical plan digest. Git first adoption also calls `new_marker`.

**Concrete failure scenario:** Preview an unchanged first adoption, approve it, then recompute the plan as required by §5.4 step 1. The recomputed digest differs solely because of the new marker, so the required stale-preview check refuses the approved operation despite no configuration or catalog change.

**Evidence:** A compiled probe called preview twice with the same `ProjectionSpec`, files and intent. Equality of `plan_digest` failed with exit **101**. The existing determinism test at `tests/integration/projection.rs:739` compares previews only after adoption, when the plan has no file changes, so it misses this case.

**Observed or inferred:** Digest instability is **observed**. Rejection by the future driver is **inferred** from the binding §5.4 recomputation requirement; that driver was not exercised.

**Fix:** Make marker selection reproducible for the same proposed generation and inputs, or carry a fixed marker through the preview/admission contract. Keep binding the actual target bytes. Test two unchanged first-adoption previews for both SSH and Git.

### X04 — P2 — Fresh Git apply continues after losing K before B_git commits

**Location:** `crates/localenv/src/projection/apply.rs:754`, `crates/localenv/src/projection/apply.rs:930`, `crates/localenv/src/projection/apply.rs:949`.

**Defect:** After claiming K, fresh apply immediately advances to the next file step without observing whether K still owns the lock name. The transaction check explicitly skips `GitLock`. Recovery's K3/K4 rules therefore do not govern this part of the live path.

**Concrete failure scenario:** After Heimdall claims K, another process replaces the lock with its own lock file before B_git begins. Heimdall still exchanges B_git and commits the item while the other writer holds Git's lock. Under K4, an item whose commit step has never exchanged must abort.

**Evidence:** A scratch probe replaced K with a different-identity lock at `AfterLockClaim`. The subsequent assertion that the global Git file remained unchanged failed with exit **101**: B_git had committed. The probe used the existing Unix Git transaction fixture and its explicit test-only applicability switch.

**Observed or inferred:** **Observed** in the shared transaction implementation on macOS. Native Windows behavior was not run.

**Fix:** Before advancing B_git toward its commit point, establish that the lock still belongs to recorded K and obey K3/K4 when it does not. Exercise lock loss and foreign replacement before B_git's exchange on both fresh apply and restart paths.

### X05 — P2 — DNS resolution is outside the network probe's timeout

**Location:** `crates/localenv/src/probe/network.rs:71`.

**Defect:** `read_banner` synchronously calls `to_socket_addrs()` before checking the deadline. Neither the TCP connection timeout nor the socket read timeout bounds that resolver call.

**Concrete failure scenario:** A configured hostname reaches a slow or unavailable system resolver. The lookup takes longer than five seconds, blocking doctor beyond the network level's advertised bound. The expired deadline is noticed only after resolution returns.

**Evidence:** The call sequence is synchronous resolution at lines 72–76, followed by the first remaining-budget check at lines 77–80. The existing network tests use numeric loopback addresses, so they bypass DNS and do not cover this bound.

**Observed or inferred:** **Inferred from code**. No external DNS traffic or resolver manipulation was performed.

**Fix:** Include name resolution in the same bounded operation as connect and banner reading. Add a deterministic slow-resolution test that verifies return within the level's deadline.

## Checks found sound

- Unix exchanges and no-replace moves use the corresponding atomic rename operations. I found no plain-rename fallback.
- File removal is confined to `QuarantineDir`; empty-directory removal is separate. Removal checks recorded identity and expected digest, subject to the documented §5.9 residuals.
- Replacement bases reject symlinks, nonregular files, foreign owners, multiple links and unsafe Unix write permissions. Directory operations use validated handles.
- Replacement restore checks active content before exchanging. X02 concerns the separate create-rollback path.
- Default doctor separates static work and permitted local queries from explicit agent/network/real-tree probes. Real-tree probes check readability and require `allow_config_commands` before starting the child.
- Git observations return value digests rather than command values.
- The inspected integration fixtures use disposable paths and isolated Git/SSH configuration; listeners are loopback-bound.
- The changed-file scan found no actual credential or personal-home-path leak. Matches inspected were synthetic fixtures, refusal-test strings or expected canary construction.
- The acknowledged §12.16/§12.17 work is excluded from these findings.

## Commands and validation

The Cargo commands ran with scratch HOME/Git isolation, owner agent variables removed, offline dependency access and the checkout's own `target/`.

| Command | Exit code | Result |
|---|---:|---|
| `git rev-parse HEAD`, `git status --short`, range diff and targeted source/design inspections | 0 | Pinned head confirmed; checkout initially clean |
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | **1,278 passed, 0 failed, 4 ignored**; ignored entries are subprocess helper entry points |
| `cargo fmt --all --check` | 0 | Passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | Passed |
| `rustc --edition=2024 --test … -L dependency=target/debug/deps --extern …` | 0 | Scratch projection and Git review harnesses compiled |
| Projection review harness, filter `review_` | 101 | X02 and X03 assertions failed; one existing matching test passed |
| Git review harness, filter `review_` | 101 | X04 assertion failed |
| `rustc --edition=2024 …` for descriptor-ownership probe | 0 | Compiled |
| Descriptor-ownership probe | 101 | X01 assertion failed after descriptor reuse redirected the write |
| Changed-file secret/canary/home-path scan | 0 | No actual secret or personal-data finding |
| Build-output size inspection | 0 | Checkout `target/` was **4.0 GB**; no matching prototype output directories |
| Guarded cleanup and final Git checks | 0 | `target/` and review scratch removed; checkout remains clean at the pinned head |

Initial ad-hoc harness compilation attempts exited **1** because of missing `--extern` arguments and selection of the wrong cached `getrandom` version. Correcting the harness invocation produced the successful compilations above.

**Changed files:** none. No source edits, commits, pushes or Git state-changing operations were performed.

## What was not checked

Native Linux, WSL and Windows execution remains **blocked** by unavailable native platforms in this review. Windows handle/DACL behavior, power-loss durability, the future setup-driver approval flow and the acknowledged real process-abort follow-up were not independently verified.

The passing repository suite does not cover the four reproduced defects above; the DNS timeout failure remains a code-supported inference.
