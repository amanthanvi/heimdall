# Heimdall M03 wave 4 — independent security review

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`). This is the plan §6.7 security review of `d6593a7c..e566cc46`, run in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.22.

**Verdict: fix first.** Three security-boundary findings are reproduced below. The repository regression targets passed **269 tests**, with **one test blocked/ignored because it requires a disposable second macOS account**. Passing regressions do not cover the reproduced counterexamples.

Reviewed the combined change `d6593a7c4fd2864490e42d02e76af914bbfeb8d0..e566cc460e89e0ab84210edf55cf68d5a9cf3ba5` (commits `d74e35cf` and `e566cc46`, branch `m03/wave4`). All source inspection and execution used the requested detached checkout `<scratch>/wt`. Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`. This was a read-only review: no source, test, instruction, Git configuration, or evidence record was edited or committed. The only retained deliverable is this report.

The review model was the supplied ten guarantees, checked against ADR-0008 D2–D10 and its §17 rulings, ADR-0005, spec §§5–8 and the security boundary in spec §14, and plan §6.7. Relevant integrator notes were treated as background, not proof. Threats considered included malicious or buggy consumers requesting owner decisions, hostile registry contents, revocation/lock interleavings, and incomplete runtime lifecycles. This does not claim protection from a fully compromised owner OS account or kernel.

## Findings

### W4-S01 — High: a held foreign removal can execute a different descriptor from the one approved

**Location:** [crates/app/src/operations/enrollment_m03/admit.rs:1238](<repo>/crates/app/src/operations/enrollment_m03/admit.rs:1238), particularly 1245–1258; the decision is built from the new `t` at 1314–1328. Execution rebuilds from the retained record at [steps.rs:64](<repo>/crates/app/src/operations/enrollment_m03/steps.rs:64).

**Guarantees broken:** #4 (the attended decision must authorize the actual foreign removal, including the exact line/hash and host), ADR-0008 D4 item 5 and §17.7 item 4; the request-to-approval boundary of spec §14.2.

Admission validates the newly supplied descriptor `t`, hashes it into the new operation, and presents it in `RemoveEnrollment`. However, lookup of an existing removal uses **only its marker**. When the prior record is `held`, `Some(f) => f` reuses its old target without comparing it to `t`. The new journal names that old record. `foreign_image` subsequently reads the old destination, account, CA, registry and line hash from `f.target`. The decision precheck checks its state/form, not equality with the decision's target.

**Concrete scenario:** an earlier removal of descriptor A became held because the registry had a duplicate/damaged marker line. The server owner repairs A's line. A consumer requests removal B with the same marker and host but a different bundle destination/principal and a correctly recomputed line hash. The owner approves the decision displaying B. The driver removes A's line, even though B's line never existed. The example needs no forged decision or store corruption, and all remote execution still goes through the normal owner step path.

**Observed:** the scratch probe used the existing enrollment fixture machinery and real loopback sshd. It first obtained a held record, repaired only its marker lines while preserving bootstrap access, submitted a changed descriptor, checked that the pending decision contained the changed descriptor, approved it, and drove the operation. The record retained the old descriptor; the real remove step returned `confirmed`, state `Removed`, and the old line disappeared:

```text
swap_stage: remote=Inspect class=confirmed state=Removing
swap_stage: remote=Remove class=confirmed state=Removed
foreign_approval_probe: approved_new_descriptor=true executed_old_descriptor=true old_line_removed=true
```

**Required correction:** bind held-record reuse to the exact descriptor being approved, or refuse mismatched descriptors. Recheck that binding at approval as well. Add a regression varying principal/CA/registry and verifying that approval for B cannot remove A.

### W4-S02 — Medium: journal minimization persists foreign lines that mention the marker

**Location:** [crates/registry/src/classify.rs:399](<repo>/crates/registry/src/classify.rs:399), especially 403–405; persisted through [crates/app/src/enrollment.rs:309](<repo>/crates/app/src/enrollment.rs:309) and `marker_entries_hex` at 328–331. The driver stores this at [steps.rs:276](<repo>/crates/app/src/operations/enrollment_m03/steps.rs:276).

**Guarantees broken:** #4's prohibition on persisting foreign `authorized_keys` content, #9's confidentiality requirement for data carried into the journal, and ADR-0008 §17.21 item 4.

`without_foreign_lines` keeps every complete line containing the marker as a substring. That is appropriate for counting suspicious marker lines, but it does not establish ownership of the line. A server-owner comment mentioning the marker, an unrelated key whose comment mentions it, or arbitrary extra data appended to a damaged Heimdall line is retained verbatim and then hex-encoded into durable stage receipts. Hex encoding preserves the content.

**Concrete scenario:** during enrollment inspection, the server's registry contains `# <private owner note> ... <this enrollment's marker>`, or an unrelated authorized key with that marker in its comment. A hostile server can also deliberately place sensitive or canary material on such a line. The inspector stores those bytes even if a later stage correctly refuses the damaged registry.

**Observed twice:** a direct call to the production `StoredReading::of` retained both a foreign comment and an unrelated key line, and serialized them. A second probe added a marker-bearing comment to a disposable registry, ran the actual enrollment inspect/StepResult path, and found the comment's hex bytes in the stored operation receipts:

```text
privacy_probe: foreign_comment_retained=true foreign_key_retained=true serialized=true
persisted_privacy_probe: foreign_comment_in_durable_receipt=true
```

The stock `journal_never_stores_foreign_registry_bytes` test passes because its foreign lines do not contain the marker. No actual secret or canary value was printed or used in these probes.

**Required correction:** persist the exact canonical own entry only when it matches, plus parsed classification facts/counts/digests for malformed or additional marker lines. Do not persist arbitrary marker-bearing line bytes to retain damage detection.

### W4-S03 — Medium: dropping a started service does not stop its loaded issuer

**Location:** [crates/runtime/src/service.rs:2425](<repo>/crates/runtime/src/service.rs:2425). The reference cycle is established at [service.rs:2143](<repo>/crates/runtime/src/service.rs:2143) and [service.rs:2292](<repo>/crates/runtime/src/service.rs:2292); the normal stop breaks it at 2414.

**Guarantee broken:** #7's issuer termination on runtime teardown; the new drop/failure fallback's own documented contract. This is distinct from the ordinary signal path, which passed.

`ManagedRuntime::drop` empties the vault and stops endpoints, but neither stops the issuer lifecycle nor clears `Operations`' managed wiring. The `Operations -> verification_endpoints/EndpointRegistry -> SignatureAuthority/Operations` cycle retains the issuer port/lifecycle (and other state). Dropping the direct `ChildIssuer` handles therefore does not reach `kill_on_drop`.

**Concrete failure scenario:** a managed `Service` starts and loads its CA, then is dropped before `run` (or a later startup failure unwinds the service). The API caller can continue running, but the old child remains alive with its CA loaded after the advertised service and endpoints have gone. Process exit eventually closes its pipes; service teardown alone does not. The same omission matters for failed-start cleanup, although a failed-start fault was not separately injected.

**Observed:** a probe started the real service with a generated CA in `ScratchSecretStore`, obtained only a weak vault reference plus the child's exact PID/start identity, then dropped the service and every public issuer handle. After 200 ms the child was still alive and the weak reference could still be upgraded, despite an empty vault and removed endpoint:

```text
drop_probe: issuer_alive=true vault_retained=true vault_empty=true endpoint_removed=true
drop_probe_cleanup: exact_child_terminated=true
```

The probe terminated only its own exact child, after rechecking the captured start identity. A subsequent sanitized process inventory found no remaining probe/fixture process. The stock startup-order test explicitly calls `issuer.stop().await` after `drop(svc)`, so it does not cover this case.

**Required correction:** make failure/drop teardown fence and stop the issuer and break the ownership cycles, including when `run` is never entered. Add a regression that drops all public strong handles and proves the fixture child exits without a separate explicit stop.

## Guarantee-by-guarantee assessment

| # | Result and evidence |
|---|---|
| **1 — signing** | **Held in the reviewed paths.** `operations/authorize.rs:172,298,430` admits under the grant or verification gate and performs a fresh store/time assessment. Permits carry absolute wall/continuous limits; the signer keeps the permit through release. `credential/src/signer.rs:325` and `purpose.rs:401` require the presented certificate, its pair account, and allowed purpose/flags; plain K_env is refused. Endpoint resolution plus the authorization store read binds the subject to its binding/environment slot. Verification gates carry the plan's CA/pair; install and admission enforce them; `VERIFICATION_UNGATED_SIGNING` is false. The managed signer suite covered cross-grant listings, time rollback, deadline/queue races, tombstones, lock, revocation, verification CA/pair mismatch and gate lifetime. The adversarial parser suite passed. Native second-account socket isolation remains blocked. |
| **2 — installs** | **Held by source trace, with positive end-to-end execution.** `managed_driver_m03.rs:124` reads safe time, grant state/bounds, ancestor denial/tombstones, the exact published entry/bounds/generation and revalidation. `runtime/managed_store.rs` wires `OpsInstallView`. `credential/table.rs:552` validates certificate subject, CA, principal and reserved bounds before the view check and rereads the key after the await. The enrollment-to-managed-ssh test exercised the real install view. I did not add a separate mutation matrix for every install refusal. |
| **3 — activation/preference, including R2C-Q1 and R2E-Q1** | **Held on the production construction paths inspected.** `pair_mechanism_m03.rs:69` requires a verified CA before using the managed preference, and only `Applied` selects managed. `projection/plan.rs:492,2303` records pairs with the rendering and supplies an empty set when no SSH step is planned. `setup.rs:2393,2500` records preference state in the SSH commit transaction; rollback/existing rendering clears the managed applied state. The three setup-switch runtime regressions passed, as did the real setup→ensure→ssh enrollment flow. IPC accepts a preview digest/spec, not arbitrary `managed_pairs`; the setup intent is stored immutably and the plan is recomputed. **Limit:** `SetupIntent::validate` does not independently prove that an arbitrarily manufactured `managed_pairs` set matches file content, and the plan digest does not directly hash that set; the conclusion relies on the trusted production builder/store path, not arbitrary database corruption or a hostile injected `ProjectionWriter`. R2C-Q1 keeps the in-process signer's interaction facts, but `fresh_fallback_refusal` refuses non-exclusive/undetermined managed selection non-interactively; `check_minimums` and commit `unmet_minimum` remain. No interaction/minimum bypass was found; I did not separately execute a new non-interactive ensure probe. |
| **4 — enrollment** | **Not fully held: W4-S01 and W4-S02.** Initial enrollment and target-change decisions require attended owner `decide`; system form stays manual and needs absence verification. Step tokens are 128-bit OS-random values, checked against the outstanding operation in the committing transaction and consumed on result. Route/host trust are pinned and reevaluated before dispatch. The 62-test enrollment target passed wrong-token/outstanding-step, route-change, attended decision, fence/unproven holder/termination, host-key reapproval, foreign hash/host checks, system absence, reconciliation, rollback and rotation cases. The held foreign-descriptor mismatch and marker-bearing foreign-content cases are missing from those regressions. |
| **5 — issuer** | **Held for request/approval binding and retirement safety; lifecycle exception W4-S03.** Registration parses a comment-free Ed25519 public key; persisted public key/time are compared in `RegisterAsk::same` and read/revalidated from the decision at approval (`issuer_m03.rs:245`). Old decisions without facts are stale, not consumed. The issuer protocol carries public subjects/certificates, not K_ca. Runtime custody stays in the child; the CLI ceremony's intentional transient generation is an existing D4 design, not a runtime export. Retirement passes only the recorded locator; no locator or no deletion port stops at `unloaded`, deleting nothing. The 17-test issuer target passed restart approval, stale/denied cases, verification authorization and exact-locator/no-locator retirement. Production's locator reporter and deletion port are still unwired per the notes, so successful real-store retirement is not claimed. |
| **6 — revocation/lock** | **Held in the exercised model and real-signer paths.** Narrowing sets pending marks and takes the globally ordered cascade gates, destroys/unlists K_env under them (`narrowing.rs:813`; `managed_driver_m03.rs:640`), then releases them before filesystem/process cleanup. The production destroy effect is synchronous in-memory work within its async method. Tests passed no-signature-after-ack, fresh-read/gate interleavings, growing cascades, overlapping narrowings, instance release, lock epoch acknowledgement and fail-closed unknown lock state. No native desktop lock/store claim is closed by these synthetic-source tests. |
| **7 — runtime start/stop** | **Partial; not fully held because of W4-S03.** Recovery precedes managed setup/listeners. The ready-issuer ordering regression, ordinary shutdown, and Unix signal-fallback regression passed; the latter proved vault zeroization and child stop. Normal stop empties the vault, awaits issuer stop, removes endpoints and breaks wiring cycles. The drop fallback does not stop the child. **Literal readiness caveat:** `service.rs:2331–2347` logs a failed issuer start and still starts the environment endpoint; later control listening also proceeds. Thus the code guarantees an issuer-start attempt before listening, not unconditional issuer readiness. With no loaded working key, issuance/reissue fails closed. This availability behavior should be reconciled with the requested stricter wording; it was not counted as a separate authority-bypass finding. |
| **8 — supervisor principal** | **Held by source trace.** `enrollment_m03/passes.rs:175` uses unattended `UnixUser { uid: u32::MAX }`, owner role, only for presence re-verification. Transport callers are constructed from authenticated session identity (`dispatch.rs:65`); Unix endpoints accept only the runtime's actual UID, and Windows callers use SID principals. The synthetic principal has no attended session, and `Operations::decide` checks attendance and owner independently. I did not execute a native Windows principal probe. |
| **9 — secrets** | **No private-key/passphrase/backup export found in the changed runtime request/effect/report paths, but the journal confidentiality guarantee is not fully held (W4-S02).** Persisted issuer facts and recovery bundles are public metadata; managed receipts contain stage/handle/issuance references; errors and added logs mostly use fixed codes. Raw remote stdout/stderr is classified and not directly persisted. W4-S02 still allows arbitrary remote content into hex journal fields. All executed fixtures used generated disposable keys and scratch custody, never the owner's agent, SSH directory, keychain or 1Password. No exhaustive allocator/memory-forensics, native custody-store or canary-across-every-sink campaign was run. |
| **10 — IPC** | **Held in the reviewed/exercised paths.** `dispatch.rs:88` enforces owner-only Step/StepResult/Reconcile and Connections Close/Register before driver dispatch; enrollment checks again. `inspect connections` is owner-filtered and excludes PID/start-token/image. M03 capabilities must be negotiated; unwired drivers refuse. Runtime regressions passed non-owner denial, capability offering, close routing and owner-only connection inspection; narrowing tests covered registration refusal for ended/tombstoned/unheld bindings and ordering with revocation. No native Windows named-pipe ACL run was performed. |

## Commands and results

All Cargo commands ran in the detached checkout with `TMPDIR=/tmp`; no Docker fixture, remote host or owner credential store was used.

| Command | Exit/result |
|---|---|
| `git -C <repo> worktree add --detach <scratch>/wt e566cc46` | **0**; detached HEAD at the full head SHA above. |
| `git rev-parse HEAD d6593a7c`; `git status --porcelain`; `git diff --stat d6593a7c..e566cc46` | **0**; pinned revisions, clean checkout, 101 changed files. Repeated final `git status --porcelain` was also **0**, empty. |
| `rustc --version` | **0**; Rust 1.99.1. |
| `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_runtime_m03 --test integration_issuer_m03 --locked` | **0**; 42 + 17 passed. |
| `TMPDIR=/tmp cargo test -p heimdall --test e2e_enroll_m03 --locked` | **0**; 62 passed, 0 ignored; real disposable loopback sshd, 66.59 s test execution. |
| `TMPDIR=/tmp cargo test -p heimdall-credential --test integration_managed_signer --test adversarial_signer_requests --locked` | **0**; 39 + 7 passed, 1 ignored/blocked (disposable second macOS account missing). |
| `TMPDIR=/tmp cargo test -p heimdall-app --test model_signing_gates --test model_lock_behavior --locked` | **0**; 29 + 16 passed. |
| `TMPDIR=/tmp cargo test -p heimdall-runtime --test model_narrowing_m03 --locked` | **0**; 57 passed. |
| Python-generated `<scratch>/security_probe.rs`; `rustc --edition=2024 <source> -L dependency=<checkout>/target/debug/deps --extern <the built workspace/runtime dependencies> -o <scratch>/security_probe` | **0** on both compilations. Linked existing Cargo rlibs; no alternate Cargo target directory. |
| `TMPDIR=/tmp <scratch>/security_probe <scratch>/lifecycle-fixture-2 <checkout>/target/debug/deps/integration_runtime_m03-12d30ef7c4343eef` | **0**; W4-S02 direct filter/serialization and W4-S03 lifecycle counterexamples. Its own exact fixture child was terminated, identity rechecked first. An initial identical trial under `lifecycle-fixture` yielded before completion and its final exit status was not retained; no finding relies on that trial. No probe process remained at cleanup inventory. |
| Python copied the unedited `tests/e2e/enroll_m03.rs` into scratch and appended two probe tests; `rustc --edition=2024 --test <scratch>/enrollment_security_probe.rs -L dependency=<checkout>/target/debug/deps --extern <built dependencies> -o <scratch>/enrollment_security_probe` | **0** on all three compilations. Repository files were not edited. |
| Initial enrollment probe run, `.../enrollment_security_probe security_probe_ --nocapture --test-threads=1`; diagnostic rerun filtered to `security_probe_held_foreign_decision_effect_swap` | **101**, then **101**. The privacy case passed; the foreign-removal test setup had overwritten its bootstrap authorized key, so inspect could not authenticate and the 16-step helper exhausted. This was a probe-fixture error, not product evidence. |
| Corrected `TMPDIR=/tmp <scratch>/enrollment_security_probe security_probe_ --nocapture --test-threads=1` | **0**; 2 passed. Corrected setup preserved all non-marker registry lines. Reproduced durable foreign-comment persistence and removal of the old descriptor's line after approval of the new descriptor. |
| Read-only `git diff d6593a7c..HEAD -- <reviewed crates>` and targeted `rg`, `sed`, `nl`, `cat` over code, manifests, ADRs, spec, plan, tests and relevant wave-4 notes | Inspection batches **0**, except the build-hygiene glob below. No bulk runtime logs, raw process arguments, environments or authentication configuration were emitted. Initial memory-registry search had no relevant Heimdall matches and was not used as review evidence. |
| `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` | **1**: zsh reported no matching prototype target path in the fresh checkout. Equivalent Python glob inventory found **no matching prototype build directories**. |
| Python ran `du -sh target` and a sanitized `ps -axo pid=,ppid=,comm=` inventory, selecting only the exact probe executables | **0**; checkout target was 4.9 GB; remaining probe/fixture processes: **0**. All build output is removed with the detached worktree below. |
| Cleanup | See final cleanup confirmation below. |

The exact standalone probe dependency paths were selected from the just-built rlibs. Scratch probe sources/binaries and generated fixture custody were deleted after execution, as requested. To reproduce W4-S01, append the described case to a scratch copy of the existing enrollment fixture test and run only that case; no product modification is needed. To reproduce W4-S02, include the current enrollment marker in a foreign comment before the first inspect and scan receipt JSON for its hex bytes. To reproduce W4-S03, drop a ready managed service before `run`, drop all issuer handles, and compare the child's exact start identity and a weak vault reference.

## Limits and risks

- **Native platform gaps:** no Windows, WSL or native Linux execution, real session-lock event, secure-store lock/unlock, logout/reboot/sleep, or second-macOS-account test. The missing second account is explicitly **blocked**, not a pass. Stable Windows token source logic and its cross-platform regression passed, but that is not native named-pipe proof.
- No full workspace/check.sh/clippy run; no package publishing, deployment, remote fixtures, Docker invocation or external account operation. The independent general-correctness reviewer remains responsible for its separate scope.
- Review followed the changed security behavior into its supporting code; this was not a line-by-line audit of every historical module, generated documentation, or all test scaffolding. No exhaustive secret-sink fuzzing or postmortem memory analysis was performed.
- R2C-Q1 and R2E-Q1 have no confirmed security finding within the production construction paths. Do not extend that conclusion to arbitrary forged internal writers/intents or tampered database documents.
- The three findings are counterexamples with observed fixture execution; the failed-start extension of W4-S03 and the readiness caveat are source-derived. They do not establish private-key exfiltration or an ungated signing exploit.

**Remaining risk:** an attended removal can act on a different foreign descriptor; foreign registry data can persist in receipts; and a dropped service can retain a loaded issuer. Fix and recheck these before merging.

## Cleanup confirmation

`git -C <repo> worktree remove --force <scratch>/wt` exited **0**. The final checkout status before removal was clean and HEAD remained `e566cc460e89e0ab84210edf55cf68d5a9cf3ba5`. Python then removed only this review's known probe files and fixture directories, and removed the empty `<scratch>` with `rmdir`; exit **0**. Both the detached checkout and scratch root are absent, so the 4.9 GB Cargo output and disposable key material are gone. The report is the only retained file.
