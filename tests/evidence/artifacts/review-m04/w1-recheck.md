fix first — M04-W1-RC01

# M04 wave 1 scoped re-check

Reviewed **806ab489..02108f8c**, at HEAD `02108f8c98cdd555f9ad76c34276eb725dd50568`, on macOS arm64 with `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. This is the one scoped re-check of R01/R02 and the fix range, not another wave-1 review. Read the original review's R01/R02 first, then AGENTS.md, ADR-0009 §2.1 and ADR-0010 §5 item 5, §9 items 3–4, §10 items 5–6.

## Setup

Executed:

- `git fetch origin m04/w1` — exit 0.
- `git checkout --detach 02108f8c98cdd555f9ad76c34276eb725dd50568` — exit 0.
- `git rev-parse HEAD` — exit 0; exactly `02108f8c98cdd555f9ad76c34276eb725dd50568`.
- `git diff --stat 806ab489..02108f8c` and scoped diffs/source/caller searches — reviewed the actual fix range, including every test deletion/replacement and the I-9 constant/golden changes.

## 1. R01 completeness — verified within this scope

`crates/app/src/enrollment.rs:746` now detects a determined evaluation of the approved HostName/Port/User with anything other than exactly the approved key, independently of proxy kind or catalog jump. Missing live keys, extra different live keys, and revocation of the approved key count as a change. `route_matches_via` retains the previous exact-key and route checks through the extracted helpers.

The supervisor (`operations/enrollment_m03/passes.rs:182`) and manual verification (`operations/enrollment_m03/verify.rs:185`) both use that rule. The mismatch is recorded before the connection gate: the record is held as `host_key_changed`, and the existing grant-degradation path runs for a previously verified enrollment. It does not accept the replacement key automatically.

There is one `run_verification` caller in production app code. All verification entry routes join `verify_operation` and reach the new gate at `verify.rs:205` before endpoint creation, verification reservations, signing or the runner. A non-direct evaluation ends inconclusive without those effects; without an evaluator a catalog jump also refuses the session. A direct evaluation still permits verification before a catalog jump is rendered, consistently with the design. An undetermined proxy in the concrete local evaluator is represented as Jump/Command, so it does not masquerade as a direct proxy.

Other paths checked:

- `--approve-target-change`: `proposed_target` requires a determined direct evaluation with the same approved HostName/Port/User and one new pinnable key; a routed evaluation cannot propose a replacement. The common verification gate also applies after approval, including a route change between proposal and verification.
- Preview/apply: `enrollment_plan` calls the existing registry planner, and apply rebuilds the plan rather than trusting the preview. Enrollment mutations remain direct-only; they do not provide an alternate verification runner.
- A change of HostName/Port/User does not create a host-key hold, but it cannot make the new target inherit the old evidence: `evidence_holds` / `route_matches_via` require the approved tuple and key. Before a client-executed remote mutation, `steps.rs:664` evaluates again and refuses `route_changed` before generating a step or writing its stage receipt. The targeted existing regression below independently passed. Verification pins the old approved target; it cannot approve the changed tuple.

The new enrollment regression checks endpoint creation, issuer signing and accepted-certificate counters, then the evaluation-only hold and grant degradation. The binary route regression checks both server login logs, record state and grant degradation. No remaining routed-verification bypass or changed-final-key exception was found in the scoped paths.

## 2. R02 safety — incomplete; see M04-W1-RC01

The CLI now preserves the typed `StateDirUnsafe` error as `STATE_UNAVAILABLE` / `state_dir_unsafe`, using the service's shared envelope. This addresses the swallowed typed ACL refusal. Static inspection confirms that the normal pre-M04 inherited user/SYSTEM/Administrators list can reach migration on CLI startup, allowing rollback/uninstall to use the runtime after migration.

The OS mutation opens one `READ_CONTROL | WRITE_DAC` handle with `FILE_FLAG_OPEN_REPARSE_POINT`, re-reads that handle's descriptor and judges it again, then sets only DACL/protection on the same handle. It does not set owner, group or SACL. A final reparse point is opened as the link, not followed; the path-level check first requires a real directory. A foreign owner, NULL DACL, deny/unknown ACE, or another trustee is not accepted by the legacy classifier. The owner check is repeated on the mutation handle, so a path replacement cannot cause a foreign-owned object to pass the rule.

However, the classifier does not retain or check ACE access masks or flags. The new mutation therefore does not establish the required property that it only removes access. Details and the smallest correction are below.

**Native Windows validation: blocked — this checkout is running on macOS, with no native Windows runtime in this review.** Windows DACL mutation, propagation, reparse behavior, rollback and uninstall were read, not executed. The five platform-filtered tests are portable rules and do not close those native claims. The added Windows tests were inspected; their ordinary default inherited ACL has full owner rights and therefore misses RC01.

A supplemental source-extraction probe compiled the exact portable `state_dir_acl` module and asserted that an unprotected owner allow entry is `LegacyInherited`. `AceFacts` cannot represent either a read-only mask or an inherit-only flag, so these cannot change that classification. This was a classifier check, **not** a Windows SDDL parse or native ACL test:

- `rustc --edition=2024 --crate-name acl_shape_probe review-out/acl-shape-probe.rs -o target/acl-shape-probe` — exit 0.
- `./target/acl-shape-probe` — exit 0; actual judge accepted the unprotected owner allow entry. Source retained under review-out.

## 3. Test weakening and I-9

No unrelated weakened assertion was found in this range.

- **Substituted keys:** the generated include stays the same. Only the client's `-F` configuration and UserKnownHostsFile are copied, with the same copy passed to the implicit jump client. The runtime evaluates the original files, preventing its stronger hold from racing the intended client check. The control still proves successful authentication at both hops. Bastion substitution still requires host-key verification failure, zero bastion public-key attempts, no final connection, no key offering and no authentication. Final substitution still requires successful bastion authentication but zero final public-key attempts, no final authentication and no remote marker. The inherited KnownHostsCommand case still requires rejection before bastion authentication. The new final status assertion requires enrollments to remain verified, confirming that runtime holds did not substitute for client enforcement.
- **Managed bastion:** retained successful `run` and `connect` logins at both hops, one grant's certificates at both hops, certificate extension assertions, dependency-scope refusal and unapproved-route evidence invalidation. Accepting either immediate evidence refusal or `pair_not_enrolled` on changed-key ensure accommodates the supervisor race. The new awaited host-key hold and refusal after restoration strengthen the durable-state requirement; expecting restoration to succeed would now be wrong.
- **Other test replacements:** Windows inherited-directory expectations change from rejection to the intended migration, with content preservation and idempotence added. Wider inherited and protected Everyone grants remain refused. No old foreign-principal refusal is removed. Their missing mask/flag case is RC01.
- **I-9:** additive `finding::M04` and `M04_REASONS` use the same existing emitted string values. The golden checks exact membership, sub-reason mapping, disjointness from earlier findings and the unchanged 30-code table. Contract tests passed.

The route command reported 9 passing Rust tests. Its unrelated forwarding case contains an existing early-return `blocked` guard on recent OpenSSH without a scratch-account opt-in; captured successful-test output does not establish whether that row ran. This report does not claim forwarding/native-platform coverage from the aggregate count.

## 4. Commands, real exits and counts

All builds used this worktree's own `./target`; no `CARGO_TARGET_DIR`, `--target-dir`, `cargo clean`, or `cargo run` was used. I made no direct heimdall invocation. Test harnesses supplied disposable fixture homes and loopback sshds; I did not read or edit the owner's SSH files or use personal keys, agents or keychains.

| Command | Exit | Observed Rust test results |
|---|---:|---|
| `cargo test --locked -p heimdall-app` | 0 | 73 unit + 3 + 16 + 54 + 29 integration = **175 passed**, 0 failed, 0 ignored; doc tests 0 |
| `cargo test --locked -p heimdall --test e2e_route_m04` | 0 | **9 passed**, 0 failed, 0 ignored; existing early-return caveat above |
| `cargo test --locked -p heimdall --test e2e_enroll_m03 routed_` | 0 | **1 passed**, 0 failed, 0 ignored, 100 filtered out |
| `cargo test --locked -p heimdall-runtime --lib platform::` | 0 | **5 passed**, 0 failed, 0 ignored, 69 filtered out |
| `cargo test --locked -p heimdall-contract` | 0 | 45 unit + 95 contracts = **140 passed**, 0 failed, 0 ignored; doc tests 0 |
| `cargo test --locked -p heimdall --test e2e_enroll_m03 step_refused_when_route_changed_after_approval` | 0 | **1 passed**, 0 failed, 0 ignored, 100 filtered out |

The five required commands reported **330 passing tests** in total. Logs and machine-readable results are in `review-out/{app,route,enroll-routed,platform,contract}.log` and `test-results.json`; the extra dispatch check is in `route-change-step.log` / `.json`.

### Independent R01 revert proof

Temporarily changed only `verification_may_connect`'s evaluated-route arm from `Some(e) => e.proxy == ProxyRoute::None` to `Some(_e) => true`. This deliberately restores the ability to open a session around the approved jump; key-change detection was left intact.

1. `cargo test --locked -p heimdall --test e2e_enroll_m03 routed_` with that mutation — **exit 101**, **0 passed / 1 failed**, 100 filtered out. The regression expected `verification_inconclusive`, but the bypass reached verification and returned `enrollment_host_key_mismatch`. This is a real test assertion failure, not a compile failure.
2. Restored `crates/app/src/enrollment.rs` from the saved original bytes in a `finally` block.
3. The same command after restoration — **exit 0**, **1 passed / 0 failed**, 100 filtered out.

SHA-256 before/after: `a36dbd9780b38bcaf43a2eeb9cc06e896983dc75d7f43c6f478c2cff6ed0c81c`. Byte equality with both the saved original and `git show HEAD:crates/app/src/enrollment.rs` was asserted. See `r01-revert.log`, `r01-restored.log`, `revert-results.json`, and `enrollment.rs.before-proof`.

## Findings

### M04-W1-RC01 — Medium; fix first: legacy migration can broaden owner access

**Location:** `crates/runtime/src/platform.rs:1260` (legacy predicate), `:1329` (replacement full-control ACL), and `:1578` (mask/flags discarded when reading ACEs).

**Concrete scenario:** the user has deliberately restricted their own state directory to read-only access, with an unprotected ACL such as `O:<user>D:(A;;FR;;;<user>)`. It is owned by the current user, has a DACL, is unprotected and contains only an owner allow ACE. The new `judge` therefore classifies it `LegacyInherited`, even though it is not the normal inherited full-control profile ACL. Ownership supplies the `READ_CONTROL`/`WRITE_DAC` authority needed to open the migration handle. On any start, migration replaces it with `D:P(A;OICI;GA;;;<user>)`: the owner gains write/delete/full-control access and newly inheritable full control. An inherit-only owner allow ACE also passes because AceFlags are discarded. This is not a removal-only transformation, and an intentionally restricted shape is silently rewritten rather than refused unchanged.

**Why introduced/in scope:** the pre-fix rule rejected all unprotected descriptors. This range adds automatic rewriting of them based on principal names alone. Ordinary default inherited full-control ACLs can migrate correctly, and foreign-principal refusal remains intact, but neither fact establishes safety for all accepted descriptors.

**Smallest correction:** retain each allow ACE's Mask and AceFlags and admit migration only when the current user's applicable rights and inheritance already cover the full-control/OI/CI rights that the replacement grants. Refuse other shapes unchanged; do not broaden them to make startup work. Alternatively, preserve the owner's existing masks/flags while removing the allowed legacy extra principals and protecting the DACL, if that still satisfies startup requirements. Add the narrow portable predicate case and a targeted Windows fixture with a read-only or inherit-only owner ACE, asserting that startup refuses it and leaves the descriptor unchanged.

**ADR-0009 §2.1 ruling:** this is an ordinary owner's ACL edit, not a hostile same-user race. The automatic start makes a lasting change to the access policy guarding state/recovery data and exceeds the authorized removal-only migration. It therefore violates the consent boundary of this fix. The verdict is fix first for RC01; R01 itself is corrected.

**Evidence limit:** this finding follows from the actual descriptor reader, predicate and replacement SDDL, supported by the portable-classifier probe. The Windows mutation was not executed here.

## Final state and limits

- Tracked files changed: **none**. The only temporary tracked edit was the R01 proof and was restored byte for byte. Both unstaged and staged diffs are empty.
- Added only task artifacts under `review-out/` and build output in `./target`; no commit, push or PR.
- Ran the requested prototype-output size inspection: no prototype target/node_modules/dist directories exist in this checkout. `du -sh ./target` reported **7.0G**. Nothing was deleted, including build output or scratch artifacts, per the explicit task instruction; the orchestrator owns worktree removal.
- Native Windows execution is **blocked: native Windows platform unavailable in this macOS review**. No remote Windows/devbox run, full workspace gate, or review of the rest of wave 1 was performed; these were outside this scoped packet.
