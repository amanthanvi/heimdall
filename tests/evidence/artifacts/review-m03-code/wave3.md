# Heimdall M03 wave 3 independent correctness review

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`), the wave-3 code review of `1b5c1758..3f7a582e`, in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.20.

**Verdict: fix first.**

Reviewed commit `3f7a582efb4519fe44fe73b392eada20763ffa7e` against `1b5c17580b54f0bbc6f3d27be50c0c9e1de4ed48`, using the requested detached checkout. The findings below concern U6/U7 behavior or the evidence their tests actually establish. The deferred U10 driver, signer install view, verification signatures, managed connect, run slot-table wiring, and Windows registration dispatcher are not reported as missing implementation defects.

All line numbers refer to the reviewed commit. File links open the corresponding file in the original workspace; that workspace was not edited and can subsequently diverge from the reviewed commit.

## Findings

### W3-R01 — High: stale materialization can overwrite the current generation

**Location:** [crates/adapters/src/managed/files.rs:391](<repo>/crates/adapters/src/managed/files.rs:391), especially lines 397–405; [effects.rs:546](<repo>/crates/adapters/src/managed/effects.rs:546).

**Failure scenario:** a slot claim for binding A commits at generation 1, and its blocking materialization is delayed. A is subsequently cleared/released, and binding B claims and materializes generation 2. When A's queued materialization runs, `write_generation` unconditionally replaces the marker with `1 A` and overwrites B's public files. A subsequent generation-1 clear can now delete those files. The process-wide mutex serializes individual writes/clears, but does not validate their order against the current slot or reject an older generation. The store CAS in `ManagedSlotTable::claim` happens before the filesystem operation, leaving this interval open.

**Basis:** inferred from the implementation; no race reproducer was added under the read-only constraint. The passing generation test covers a late clear after ordered writes, not a late writer. This violates the stale-generation protection in plan §6 and U6's generation-bound file contract. Serialize the claim/materialization/clear lifecycle per slot, or revalidate ownership with a generation-aware publication protocol. Individual atomic renames do not supply that protocol.

### W3-R02 — High: stale clears unlist the current binding before checking generation

**Location:** [crates/adapters/src/managed/effects.rs:274](<repo>/crates/adapters/src/managed/effects.rs:274), lines 280–282; [effects.rs:416](<repo>/crates/adapters/src/managed/effects.rs:416), lines 417–418.

**Failure scenario:** a binding is rematerialized after re-issue at a newer resource/slot generation, then an old cleanup intent calls `clear(binding, old_generation)` or `clear_slot(binding, pair, old_generation)`. The files correctly survive their marker check, but `table.unmaterialize(binding)` has already removed the binding's *current* environment listing. Ordinary SSH through the current slot stops working. In addition, clearing one pair unlists every other pair held by that binding because `SignerTable::unmaterialize` is binding-wide.

**Basis:** inferred; the existing stale-clear tests assert surviving files, not surviving signer listings for a rematerialized binding. D10's immediate unlisting must still be restricted to the claimed binding/pair generation. Track the generation in the listing operation and make stale cleanup a no-op there too.

### W3-R03 — High: master replacement has no per-slot serialization or ownership proof

**Location:** [crates/runtime/src/connections.rs:838](<repo>/crates/runtime/src/connections.rs:838), lines 838–847; [connections.rs:875](<repo>/crates/runtime/src/connections.rs:875), lines 879–880; [connections.rs:1105](<repo>/crates/runtime/src/connections.rs:1105).

**Failure scenario:** two concurrent `start_master` calls both finish `replace_previous`, choose the same next generation, observe no socket, and spawn. Once either child binds, both `spawn_once` calls accept that socket as their own; they do not prove which child owns it or even check child exit first. OpenSSH can disable multiplexing when its control path is occupied, so a surviving direct `-N` child can be recorded as the master of another child's socket. Both rows can carry the same generation/inode, and inserting into `live[path]` replaces the earlier child record.

The close path aggravates this: `-O exit` is sent to the stable pathname without checking that its inode still belongs to the row being closed. Overlapping close/replacement operations can therefore control a newer master even though the later unlink is inode-protected.

**Basis:** inferred interleaving, not stress-tested. The successive-binding test is sequential and the inode test checks only removal. D8 item 3 requires generation protection for the master lifecycle, not only unlink. Serialize start/replace/close for a slot, reserve its generation atomically, prove readiness belongs to that child, and protect the control operation as well as deletion.

### W3-R04 — High: restart retains masters whose deadline passed during downtime

**Location:** [crates/runtime/src/connections.rs:1215](<repo>/crates/runtime/src/connections.rs:1215), lines 1215–1220.

**Failure scenario:** the runtime stops while a grant is active; its owned master survives and D passes while the runtime is down. The stored grant remains active (or becomes degraded when restart marks its credential lost). `connection_restart_pass` checks only stored lifecycle state, binding release, and tombstones. It never checks the admission deadline, current cutoff, persisted continuous-time anchor, or whether time is accepted, so it reports this master as kept. Existing multiplex admissions need no signer and can continue after D until another pass fixes the state.

**Basis:** inferred; `runtime_restart_closes_masters_of_ended_grants_first` explicitly changes the fixture grant to `Expired` before calling the pass. Application restart recovery marks instances lost and drives unfinished operations; it does not globally expire all grants before this pass. This is a defect in U7's restart decision, not a complaint that U10 has not called it yet. Evaluate safe admission/current bounds before keeping a recovered master, with uncertain time closing masters.

### W3-R05 — High: a non-holder can replace the environment slot's master

**Location:** [crates/runtime/src/connections.rs:784](<repo>/crates/runtime/src/connections.rs:784), lines 784–802; [connections.rs:921](<repo>/crates/runtime/src/connections.rs:921), lines 921–929.

**Failure scenario:** A holds a pair's materialized environment slot. B has another valid binding and endpoint/certificate for the same pair but does not hold that slot. `start_master(B, pair)` checks the binding, grant state, destination and connection policy, but never checks `tx.slot(environment, pair)`, its holder/generation, or even that the requested pair is in B's scope. It closes A's master and starts B's at the path used by ordinary SSH through A's projection. The shared path can therefore serve a credential other than its slot holder's.

The post-spawn “narrowing wins” check also does not re-read the slot or effective multiplexing policy. A slot transfer or a narrowing to disabled during spawn can still leave the wrong master recorded.

**Basis:** inferred from the complete pre/post-spawn checks. D8 item 3 explicitly limits masters to materialized bindings and says the live master is always the slot holder's. Enforce those facts inside the slot lifecycle, including revalidation after awaited work; do not make an undocumented future caller precondition carry this invariant.

### W3-R06 — High: accepted short certificates are reported as covering the entire grant

**Location:** [crates/adapters/src/managed/prepare.rs:238](<repo>/crates/adapters/src/managed/prepare.rs:238), lines 238–245; [report.rs:431](<repo>/crates/adapters/src/managed/report.rs:431), lines 431–434.

**Failure scenario:** a prepared result contains exactly the requested pairs, but one certificate expires in 15 minutes while the grant's effective deadline is 12 hours away. `check_prepared` accepts any `valid_before <= deadline`, including already-expired certificates. With a ready issuer and no pending re-issue, `compute` nevertheless returns `usable_until = offline_until = D` and `ThroughDeadline`. A required offline minimum beyond the real certificate expiry passes.

**Basis:** inferred directly from the comparison and report computation; existing coverage tests supply full-lifetime certificates. This contradicts spec §6.5 and D6 item 6's explicit prohibition on reporting a short credential as covering longer work. Reject incomplete coverage under the one-certificate-for-the-grant recipe, or conservatively bound readiness by the minimum actual certificate expiry.

### W3-R07 — Medium: deadline wording ignores identity selection and multiplexing

**Location:** [crates/adapters/src/managed/report.rs:386](<repo>/crates/adapters/src/managed/report.rs:386), lines 386–392; [report.rs:598](<repo>/crates/adapters/src/managed/report.rs:598).

**Failure scenario:** the normal wave-3 outcome deliberately uses `SelectionClass::Undetermined`, yet its policy wording says “New connections stop at the deadline.” An inherited user identity may still authenticate then. D8 item 6 requires the qualified “through Heimdall's key” wording and the disclosure that other identities are not controlled. Separately, graceful policy with owned masters still says sessions may stay connected, without D8 item 3's disclosure that sessions shared through Heimdall's connection end at the deadline.

**Basis:** observed source behavior; the golden test exercises only exclusive selection with multiplexing disabled. Make the computation depend on selection and multiplexing, and cover these combinations.

### W3-R08 — Medium: weakest destination clock can select a stronger bound

**Location:** [crates/adapters/src/managed/report.rs:398](<repo>/crates/adapters/src/managed/report.rs:398), especially line 405.

**Failure scenario:** pair A has `behind_upper + rtt = 1400 ms`, measured now. Pair B has 1000 ms, measured 10,000 seconds ago. D7's 100-ppm drift makes B's current uncertainty 2000 ms, larger than A's 1400 ms. `weakest_clock` selects A because it compares only initial lag/RTT; for tied values it even prefers the newer measurement. The aggregate revocation clock therefore understates the weakest pair.

**Basis:** inferred arithmetic counterexample, not a native clock experiment. Select by the completion allowance at the report's observation time, with overflow/unknown remaining conservative. Per-pair residual reporting is separate and does not repair an incorrect aggregate report.

### W3-R09 — Medium: Linux skips the required image recheck before SIGKILL

**Location:** [crates/runtime/src/connections.rs:593](<repo>/crates/runtime/src/connections.rs:593), lines 593–604.

**Failure scenario:** a verified process survives SIGTERM and executes another image during the grace interval. On Linux the second signal uses the original `VerifiedProcess` without re-reading the executable; only non-Linux Unix builds call `verify` again. The pidfd prevents signalling a reused PID, but it does not prevent that same process from changing its image. SIGKILL can therefore target an image that no longer satisfies the ownership check.

**Basis:** inferred; no adversarial executable/exec test was run. D8 item 2 says to reverify the start identity and expected Unix image before *every* signal. Keep the Linux pidfd and repeat the image check before the second signal. The macOS branch already rechecks both; its small final check-to-kill reuse window is expressly disclosed by D8 and is not independently a finding.

### W3-R10 — Medium: Windows tests do not establish their named gate and non-SSH claims

**Location:** [tests/e2e/deadline_m03.rs:428](<repo>/tests/e2e/deadline_m03.rs:428), with the fixture descriptor at line 158; [deadline_m03.rs:772](<repo>/tests/e2e/deadline_m03.rs:772).

**Failure scenario:** `windows_register_while_suspended_under_gate` creates a `fake_agent` grant with no managed credential/signing gate. The real registration operation explicitly accepts `GateError::NoGate` and uses store ordering alone. Thus this test can pass even if managed shared-gate acquisition is broken; the sequential revoke-before/register-before tests do not add gate contention coverage.

Also, `windows_non_ssh_run_has_no_job_object_by_default` checks the Boolean selector and a direct `spawn_and_wait(cmd /c exit 3)` status. It does not launch through `run`, inspect job membership, or prove a deliberately surviving grandchild survives normal launcher exit. It can pass if the M02 no-job semantics regress.

**Basis:** inferred from fixtures/assertions; these Windows-only bodies were not executed on this Mac. Use a managed fixture with a real registered gate and controlled contention for the first claim; add an actual non-SSH process-tree workflow for the second, or narrow the evidence names/claims until those checks exist. This does not demand U10 wiring to test the available primitives.

### W3-R11 — Medium: pass-level store failures disappear from the cleanup result

**Location:** [crates/runtime/src/connections.rs:1158](<repo>/crates/runtime/src/connections.rs:1158); lines 1201 and 1228 repeat the pattern.

**Failure scenario:** a transient store failure prevents `close_for` from reading a revoked grant's rows. It simply continues and returns an empty `PassReport`, with no failed cleanup indicated. Restart and time-uncertain enumeration failures similarly return empty reports. A caller cannot distinguish “nothing to close” from “could not discover the masters that still accept sessions,” so it cannot reliably retain/retry cleanup or prevent startup admission based on this result.

**Basis:** inferred; no store-fault injection was run. D7 item 2 requires failed cleanup to remain represented by a cleanup intent. Return a pass-level error (or an explicit discovery failure) so U10 can enforce that obligation. A strict fallback policy in `effective_policy` does not help when row discovery itself failed.

## Escalations and recommended rulings

These are recommendations for the integrator, not new authority decisions made by this reviewer.

| Escalation | Reading and recommended ruling |
|---|---|
| W3-Q1 | Accept (a): the master must reuse only the foreground pin from `OWNED_LAUNCH_PINS`, then its own master options and the shared managed identity renderer. The actual argv uses certificate-as-IdentityFile, no key.pub/CertificateFile, matching §17.19 item 4. The host argv/real-master tests passed. A separately named renderer constant is optional maintenance, not a blocker. |
| U7-Q1 | Resolved in this commit: the runtime → sshconf dependency exists and compiles. Accept the direct edge; it avoids retyping the frozen identity form. No semantic ruling remains. |
| U6-Q1 | Resolved: parsing by inferred `ssh_key::Certificate` type is legitimate Rust; no new dependency is necessary. |
| U6-Q2 | Accept the grant-scope source. `NoGrantScopes` returns no pairs and generation refuses before a key is generated. U10 must supply store-derived scope, not request/process-file reconstruction. This default is fail-closed. |
| U6-Q3 | Accept unknown until classification exists. The report's identity-selection enforcement remains unknown for undetermined selection. The accompanying wording is not conservative yet: W3-R07. |
| U6-Q4 | Accept separate slot and binding-resource generations, but keep them separate throughout cleanup. `clear(binding, resource_generation)` cannot be relied on to clear an independently claimed slot: its slot scan filters for the same numeric generation. U10 must explicitly clear each slot using its store generation, as the expiry fixture does. The claimed protection still needs W3-R01/R02 fixed. No port change is inherently necessary if the driver carries both receipts. |
| U6-Q5 | Accept an in-memory, pre-recorded terms source to keep store reads outside the bound, with an explicit availability contract. Do **not** bless the assertion that missing terms can never overclaim: default terms are Continue, so with a matching fixture/future lock-continuity claim, an actual revoke-on-lock grant whose terms were not recorded can be reported Verified and pass the unattended minimum. The empty baseline claim table currently prevents that particular overclaim. Rule that terms must be present before computation, or make unavailable terms refuse; require a regression case before enabling real claims. |
| U6-Q6 | Prefer the binding endpoint for a binding's consumer integration, consistent with D10 item 4 and connect's derivation. Update the golden through the integrator rather than changing the implementation to the environment endpoint. The current test openly excludes consumer and should not be represented as a complete serialized EnsureData golden. |
| U7-Q2 | Accept a Windows reap pass for exact ssh.exe process identities. On the intended launch path the holder indexes the binding; it remains stored after exit, so the discovery union can still find the row. Native coverage is still needed, especially exit/revoke/reap ordering. |
| U7-Q3 | Accept events emitted by U10 around the operation, provided event emission is part of its delivery contract. Ignoring reason here is not itself a U7 correctness defect; `PassReport` must, however, preserve actual failures (W3-R11). |
| U7-Q4 | The holder ∪ master-resource enumeration is complete for the stated invariant: dedicated rows belong to launch bindings with holders, masters have resources. Keep that invariant checked at insertion and test it. Caller-supplied ended/revoked/released grant lists are reasonable, but they do not cure the restart-bound check or swallowed discovery errors (W3-R04/R11). |
| U7-Q5 | Accept the recorded behavior. Closing must use `-O exit` and then exact verified process termination, never rely on `-O stop`. The host test passed; its “per client” name means the client installed on this host, not all supported clients. No new authority ruling is needed. |

## What held up in this review

- Re-issue eligibility checks store provenance, live state, tombstones, deadline/cutoff, accepted time/admission, and both current and origin revoke-on-lock terms. `same_grant` preserves the stored pairs and deadline. Pause does not incorrectly block recovery. These are source conclusions supported by the passing helper/property tests, not a claim that the deferred production driver ran.
- The paths written by U6 match the slot projection and binding-file derivation used by connect, including certificate-as-identity. Each individual file replacement is atomic; multi-file generation/lifecycle safety has the findings above.
- Reconcile distinguishes nothing published, complete published/installed matching-token preparation, and partial/unknown results. In-memory revoke destroys the supplied cascade's keys; file work is outside that operation, consistent with the amended gate scope.
- With the empty claim table, the tested platform mechanism fields remain unknown/not_verified. Runtime per-pair destination verification evidence is treated separately.
- The source Windows path creates the child suspended, assigns a non-breakaway kill-on-close job, registers, and resumes only on Registered. Refusal/failure closes the job. The job remains held during the wait; ordinary non-SSH launches still select M02's existing path. These are static conclusions only.
- Dedicated close rejects a mismatched start token and defers a matching-token wrong-image process instead of signalling the pre-exec launcher. Host tests exercised pre-exec deferral, later close, exit races, and the policy matrix.

## Validation

Host: Darwin arm64, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.

| Check | Observed result |
|---|---|
| Managed adapter integration | exit 0; 38 passed. Includes a no-op issuer-child entry, so this is not 38 independent production workflows. |
| Connection integration | exit 0; 28 passed against real disposable loopback SSH fixtures on this Mac. |
| Deadline target | exit 0 for that target; 1 portable reason/exit-code test. Windows-only ownership bodies were not compiled/executed on this host. |
| M02 run regression, first attempt | combined Cargo invocation exit 101; 52 passed, 2 failed solely because hm-fixture-hook was not built, 1 fixture entry ignored. |
| Fixture target preparation | exit 0 with --no-run; built the disposable hook through its owning test target. The fixture suite itself was not executed. |
| M02 run regression, rerun | exit 0; 54 passed, 1 intentional fixture entry ignored. |
| Clippy, affected crates and all host targets | exit 0 with --locked and -D warnings. |
| Tracked working-tree changes | git status --short exit 0, no output before removal. No source, manifest, evidence or repository documentation was edited; no commits or pushes. |

The high-severity scenarios are source-inferred counterexamples. Passing existing tests does not reproduce or refute those untested interleavings.

## Commands run and exit codes

Unless explicitly absolute, commands below ran in `<scratch>/wt`. Read commands were bounded source/diff inspection; their output is not a separate persisted artifact. Tool session waits only collected the same command's final status.

1. Exit **1**: `pwd; printenv CODEX_HOME; ls -ld <scratch> <scratch>/wt 2>/dev/null; rg -n 'heimdall|M03|wave3' <home>/.codex/memories/MEMORY.md` — Preparatory inspection in the original cwd: review paths absent and no matching memory entry; no memory-derived project facts used.

2. Exit **0**: `cat <home>/.codex/AGENTS.md; cat <home>/.agents/skills/code-review/SKILL.md; cat <home>/.codex/plugins/cache/ponytail/ponytail/5.3.3/skills/ponytail/SKILL.md` — Preparatory instruction/skill reads outside the checkout.

3. Exit **0**: `git -C <repo> worktree add --detach <scratch>/wt 3f7a582e`

4. Exit **0**: `git rev-parse HEAD 1b5c1758`

5. Exit **0**: `git diff --stat 1b5c1758...HEAD`

6. Exit **0**: `cat tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-questions.md`

7. Exit **0**: `cat Cargo.toml rust-toolchain.toml`

8. Exit **0**: `rg -n '^#{1,5} |§17.19|identity|IdentityFile' docs/decisions/0008-managed-credential-integration.md`

9. Exit **0**: `sed -n '1975,2452p' docs/decisions/0008-managed-credential-integration.md`

10. Exit **0**: `sed -n '2646,2736p' docs/decisions/0008-managed-credential-integration.md; sed -n '3795,3808p' docs/decisions/0008-managed-credential-integration.md`

11. Exit **0**: `cat crates/adapters/src/managed/reissue.rs crates/adapters/src/managed/mod.rs`

12. Exit **0**: `cat crates/adapters/src/managed/prepare.rs`

13. Exit **0**: `rg -n '^|.' crates/adapters/src/managed/files.rs`

14. Exit **0**: `cat crates/adapters/src/managed/reissue.rs`

15. Exit **0**: `cat crates/adapters/src/managed/mod.rs`

16. Exit **0**: `cat crates/adapters/src/managed/prepare.rs`

17. Exit **0**: `sed -n '1,370p' crates/adapters/src/managed/report.rs`

18. Exit **0**: `sed -n '370,663p' crates/adapters/src/managed/report.rs`

19. Exit **0**: `cat crates/adapters/src/managed/effects.rs`

20. Exit **0**: `sed -n '1,420p' crates/runtime/src/connections.rs`

21. Exit **0**: `rg -n 'fn materialize|fn unmaterialize|pub fn binding_grant|pub fn destroy_grant' crates/credential/src/table.rs; rg -n '3.7|Recovery rule|7.2|3.8|3.4' docs/decisions/0005*; rg -n '\[\[test\]\]|name =|path =' crates/adapters/Cargo.toml crates/runtime/Cargo.toml crates/heimdall/Cargo.toml`

22. Exit **0**: `sed -n '420,850p' crates/runtime/src/connections.rs`

23. Exit **0**: `sed -n '850,1275p' crates/runtime/src/connections.rs`

24. Exit **0**: `sed -n '1275,1540p' crates/runtime/src/connections.rs; sed -n '620,710p' crates/credential/src/table.rs; sed -n '2290,2452p' docs/decisions/0008-managed-credential-integration.md`

25. Exit **0**: `git diff 1b5c1758...HEAD -- crates/heimdall/src/run_cmd.rs crates/launch/src/windows.rs`

26. Exit **0**: `git diff 1b5c1758...HEAD -- crates/localenv/src/sys/mod.rs`

27. Exit **0**: `rg -n '^fn |^async fn |#\[ignore|cfg\(' tests/integration/connections.rs tests/e2e/deadline_m03.rs tests/integration/managed_adapter.rs`

28. Exit **0**: `TMPDIR=/tmp cargo test -p heimdall-adapters --test integration_managed_adapter --locked`

29. Exit **0**: `sed -n '250,610p' crates/localenv/src/sys/mod.rs`

30. Exit **0**: `rg -n 'fn process_start_time|pbi_status|SZOMB' crates/runtime/src/platform.rs; sed -n '1,200p' tests/integration/connections.rs; sed -n '680,1080p' tests/integration/connections.rs`

31. Exit **0**: `sed -n '409,454p' docs/decisions/0005*; sed -n '2646,2736p' docs/decisions/0008-managed-credential-integration.md; cat schemas/examples/ensure-data.managed.json`

32. Exit **0**: `sed -n '640,725p' crates/runtime/src/platform.rs; sed -n '1463,1657p' tests/integration/managed_adapter.rs; sed -n '2739,2892p' tests/integration/managed_adapter.rs`

33. Exit **0**: `sed -n '43,290p' tests/e2e/deadline_m03.rs; sed -n '290,608p' tests/e2e/deadline_m03.rs`

34. Exit **0**: `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections --locked`

35. Exit **0**: `cat docs/architecture/m03-plan.md | sed -n '1,200p'; rg -n 'U6|U7|connection|atomic|generation' spec.md plan.md | head -90`

36. Exit **0**: `sed -n '1277,1390p' tests/integration/managed_adapter.rs; sed -n '3507,3590p' tests/integration/managed_adapter.rs; sed -n '1,165p' crates/adapters/src/managed/files.rs`

37. Exit **0**: `sed -n '1080,1470p' tests/integration/connections.rs`

38. Exit **101**: `TMPDIR=/tmp cargo test -p heimdall --test e2e_deadline_m03 --test e2e_run_m02 --locked`

39. Exit **0**: `sed -n '1277,1390p' tests/integration/managed_adapter.rs; sed -n '3507,3590p' tests/integration/managed_adapter.rs; sed -n '3620,3649p' tests/integration/managed_adapter.rs; sed -n '1580,1625p' tests/integration/connections.rs`

40. Exit **0**: `sed -n '1000,1135p' crates/app/src/ports.rs; sed -n '1,180p' crates/app/src/operations/connections.rs; sed -n '1090,1165p' crates/store/src/ext_m03.rs; rg -n 'binding_holders|clear_binding_holder|remove_binding_holder' crates/store/src crates/app/src/operations/bind_connection_m03.rs`

41. Exit **0**: `sed -n '1980,2075p' crates/store/src/ext.rs; cat crates/app/src/operations/bind_connection_m03.rs; cat crates/domain/src/connection.rs`

42. Exit **0**: `rg -n 'pub fn policies_for|pub fn policies' crates/store/src/ext.rs; rg -n 'fn applicable|workspace|covers' crates/domain/src/policy.rs; rg -n 'fn bound_of|pub.*bound_of' crates/app/src/operations.rs crates/app/src/operations/*.rs; sed -n '381,455p' crates/domain/src/policy.rs; sed -n '100,155p' spec.md`

43. Exit **0**: `sed -n '832,880p' crates/store/src/ext.rs; sed -n '1630,1715p' crates/app/src/operations.rs; sed -n '1,145p' crates/domain/src/policy.rs; sed -n '608,792p' tests/e2e/deadline_m03.rs`

44. Exit **0**: `sed -n '1150,1240p' crates/app/src/ports.rs; rg -n 'start_master|slot|materialized' tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-api.md; sed -n '2320,2440p' tests/integration/managed_adapter.rs; sed -n '1,100p' tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-worklog.md`

45. Exit **0**: `sed -n '2420,2569p' tests/integration/managed_adapter.rs; sed -n '105,145p' tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-api.md; sed -n '299,337p' tests/evidence/artifacts/review-m03-code/wave3-notes/m03-wave3-api.md; sed -n '1,55p' tests/e2e/deadline_m03.rs`

46. Exit **0**: `cat crates/testkit/Cargo.toml; rg -n 'hm-fixture-hook|HOOK_BINARY|FIXTURE_HOOK' crates/testkit/src tests/e2e/run_m02.rs | head -55; rg -n 'rust-version|1.99' docs/architecture/dependencies.md`

47. Exit **0**: `cargo test -p heimdall-testkit --test integration_testkit_fixtures --locked --no-run`

48. Exit **0**: `nl -ba crates/adapters/src/managed/effects.rs | sed -n '264,294p;419,455p'; nl -ba crates/adapters/src/managed/files.rs | sed -n '389,407p'; nl -ba crates/adapters/src/managed/prepare.rs | sed -n '234,257p'; nl -ba crates/adapters/src/managed/report.rs | sed -n '385,414p;443,461p;564,595p'; nl -ba crates/runtime/src/connections.rs | sed -n '555,601p;823,852p;874,895p;937,951p;1000,1048p;1115,1160p;1224,1252p'`

49. Exit **0**: `TMPDIR=/tmp cargo test -p heimdall --test e2e_run_m02 --locked`

50. Exit **0**: `rg -n '^### U6|^### U7|^### U8|^### U5' docs/architecture/m03-plan.md; nl -ba crates/runtime/src/connections.rs | sed -n '765,802p;914,932p;1098,1118p;1201,1225p'; nl -ba crates/adapters/src/managed/report.rs | sed -n '428,441p;594,604p'; nl -ba tests/e2e/deadline_m03.rs | sed -n '154,181p;413,445p;763,792p'; nl -ba crates/adapters/src/managed/effects.rs | sed -n '411,420p'`

51. Exit **0**: `cargo clippy -p heimdall-adapters -p heimdall-runtime -p heimdall-localenv -p heimdall-launch -p heimdall --all-targets --locked -- -D warnings`

52. Exit **0**: `cat crates/domain/src/binding.rs | sed -n '1,170p'; sed -n '1219,1410p' docs/architecture/m03-plan.md`

53. Exit **0**: `sed -n '3268,3403p' tests/integration/managed_adapter.rs; sed -n '3146,3165p' tests/integration/managed_adapter.rs; sed -n '1625,1717p' tests/integration/connections.rs`

54. Exit **0**: `git status --short`

55. Exit **0**: `rustc --version`

56. Exit **0**: `uname -sm`

57. Exit **0**: `du -sh target`

58. Exit **1**: `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist`

59. Exit **0**: `rg -n 'pub async fn start|tick\(|recover|restart' crates/app/src/operations.rs crates/app/src/operations/start.rs crates/app/src/recovery.rs crates/runtime/src/service.rs; sed -n '390,530p' crates/app/src/operations.rs`

60. Exit **0**: `sed -n '5525,5608p' crates/app/src/operations.rs; sed -n '1,155p' crates/app/src/operations/restart_m03.rs; rg -n 'revalidate.*grant|all_grants|grants\(' crates/app/src/operations.rs | tail -12`

61. Exit **0**: `git -C <repo> worktree remove --force <scratch>/wt`

62. Exit **0**: `rmdir <scratch>`

63. Exit **0**: `test ! -e <scratch>`

Report generation used Python's `Path.write_text` with this document as a quoted argument (exit 0); no other report artifact was written.

## Cleanup and limits

The detached checkout was clean before removal. The root Cargo target directory reached 5.4 GB; removing this review worktree removed all of that build output. The required prototype-output size command returned 1 because no matching prototype target/node_modules/dist directories existed in the checkout. `git worktree remove --force`, removal of the empty parent with `rmdir`, and the final absence check all returned 0. No fixture files or build outputs were deliberately retained. This report is the only persistent file created for delivery: `<scratch>-report.md`.

Not checked: native Windows/WSL/Linux runs, Windows process/job/gate behavior, DPAPI, real session lock/sleep/logout/reboot, the deferred U10 production workflows, Docker fixtures, a full-workspace test run, or dedicated reproducer tests for the inferred races. No owner SSH material, keychain, password manager, Git configuration, or pre-existing service was used as a test target. The reported prior native/cross-platform runs in the integrator notes were read as historical claims, not independently rerun or promoted to current evidence.

Skipped native Windows and other-platform validation; the passing host suites and clippy do not close those claims.
Risk: stale generations, master lifecycle races and readiness overclaims remain unresolved; fix these before merge.

Final report/cleanup assertion: Python checked the report header, verdict, W3-R01 through W3-R11, resolved command statuses, and absent checkout; exit 0.
