# Heimdall M03 wave-3 independent security review

Reviewer: Codex (gpt-6.1-sol, independent, through `codex-cpamc`), the plan §6.7 security review of `1b5c1758..3f7a582e`, in its own scratch checkout. The orchestrator saved it with paths redacted. The rulings are in ADR-0008 §17.20.

**Verdict: fix first.** Five findings below prevent the wave-3 components from meeting the requested guarantees. Four attack/failure cases and the stale-generation primitive were reproduced against the unchanged libraries. No Windows-specific vulnerability is asserted.

Reviewed revision: `3f7a582efb4519fe44fe73b392eada20763ffa7e`, parent/base `1b5c17580b54f0bbc6f3d27be50c0c9e1de4ed48` (`m03/wave3`). The review used the requested detached checkout exclusively for repository inspection and execution. All source locations below refer to that fixed revision; the checkout has been removed.

Host actually tested: Darwin arm64, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, `OpenSSH_10.5p1, LibreSSL 3.3.6`.

This is a security review of the new adapter, connection supervisor, launcher changes, and unsafe boundary. It is not the separate correctness review or a completed M03 release gate. Production managed preparation, install authorization, verification signatures, slots and connection dispatch remain unavailable pending U10. The reproduced connection failures exercise the real wave-3 supervisor with the existing disposable `LoopbackSshd`/fixture-agent harness, rather than claiming that a production managed `run` already works.

## Findings

### W3-S01 — High — Restart preserves an overdue master and its new session admissions

**Location:** [connections.rs:1215](<repo>/crates/runtime/src/connections.rs:1215), `connection_restart_pass`; related state-only start checks at [connections.rs:792](<repo>/crates/runtime/src/connections.rs:792) and [connections.rs:926](<repo>/crates/runtime/src/connections.rs:926).

**Guarantee broken:** 1, deadline ends mux admissions; ADR-0008 D7 items 1/8/10 and D8 item 3 restart rule; ADR-0005 §3.8.

The restart pass decides whether a grant ended using only its recorded state, binding release and ancestor denial. It never assesses the current admission deadline, continuous budget, cutoff or time safety. A runtime that was down at the deadline can legitimately leave the persisted grant `Active` or `Degraded`. Its existing master does not need another signature to admit another session. The restart pass returns that master in `kept`.

**Concrete scenario:** Start a master for a grant whose stored deadline is two seconds away. Drop its supervisor, allowing the master to survive as designed. Restart after three seconds, with no scheduler having updated the stored state. `connection_restart_pass` keeps the master, and an ordinary `ssh <alias> true` succeeds over it after the deadline without another authentication. `Operations::recover_after_restart` does not itself run the deadline scheduler, so its existence is not counterevidence to this component defect.

**Evidence: observed.** Scratch test `unix::secrev_restart_keeps_overdue_active_master`, using the real supervisor and loopback server:

```text
SECREV_RESTART kept=true mux_session_after_deadline=true
```

The probe checked that the server's accepted-authentication count did not increase, then explicitly closed the persisted master by its recorded identity. The existing `runtime_restart_closes_masters_of_ended_grants_first` passes, but it manually changes the grant state to `Expired` before calling the pass and does not cover this case.

**Required correction:** Judge restart retention against fresh, accepted admission/time facts, including the parent/cutoff/continuous bound, and close masters when admission has ended or time is uncertain. Reuse the existing time/admission machinery. Add a restart test where the absolute deadline passes while the runtime is absent and the stored state is still live.

### W3-S02 — High — Refusing an occupied mux path still lets ordinary SSH reuse its unowned master

**Location:** [connections.rs:840](<repo>/crates/runtime/src/connections.rs:840), `start_master_impl`; the promised direct-connection fallback is described at the start of this new module.

**Guarantees broken:** 1 and 5; a managed alias must use only the current slot holder's owned master, and revocation must end its mux admissions. ADR-0008 D8 items 3/4 and spec §8.2.

Returning `mux_path_occupied` refuses to create or register a master. It does not stop ordinary SSH from connecting to the already configured stable `ControlPath`. `ControlMaster no` prevents creation of a master but still permits reuse of a listening master. The foreign master is absent from the owned rows, so revocation finds nothing to close.

**Concrete scenario:** Another process of the same user, or a leftover master not represented by the ownership records, listens at the slot's stable mux path. Starting the managed master returns `mux_path_occupied`. Ordinary clients nevertheless use the foreign connection. Ending/revoking the grant and running its close pass leaves that listener alive and it admits another session without consulting the signer. This needs write access to the runtime path and a working foreign connection; it is not a cross-user escape from a correctly protected 0700 directory. The task explicitly asks about another local process and misplaced/reused masters, and the same-user workload limitation does not make that master owned.

**Evidence: observed.** Scratch test `unix::secrev_unowned_master_reused_after_revocation` created a real foreground OpenSSH master directly, with disposable keys, outside the supervisor's ownership table. It then called the real supervisor:

```text
SECREV_UNOWNED start_refusal=Unavailable("mux_path_occupied") closed_rows=0 new_mux_session_after_revocation=true
```

The grant was changed to `Revoked`, its real `revocation_close` ran, and the subsequent ordinary command succeeded with no increase in accepted certificate authentications. The foreign master was owned and stopped by the probe itself; no owner's connection was touched.

**Required correction:** An unverified listener must prevent admission through that mux path, not merely prevent starting another master. Propagate the ownership failure into the managed slot/binding's usable state, and ensure ordinary clients cannot keep using the configured foreign path. Validate protected directories and actual listener ownership when establishing readiness. The integrator must reconcile fail-closed ordinary-client behavior with the approved stable-path projection; retrying `start_master` alone does not solve it.

### W3-S03 — Medium — Closing an old master sends `-O exit` to a replacement socket owner

**Location:** [connections.rs:1105](<repo>/crates/runtime/src/connections.rs:1105), `close_master`.

**Guarantees broken:** 3 and 5, ownership verification before affecting a process and generation-protected replacement; ADR-0008 D8 item 3; spec §8.2. This is an ownership failure in the control-command path, even though the later Unix signals use the verified process helper.

Before running `ssh -O exit`, the code checks only that the old PID still has its recorded start token. It does not compare the current socket with the persisted socket inode, or establish that the socket still belongs to that process. The same-inode check occurs only when deleting the socket after closure. It cannot prevent an earlier exit command from terminating someone else's master.

**Concrete scenario:** An owned master receives `-O stop`, removes its control socket, and remains alive with an existing session. A different live binding or independent master binds the same pathname. Closing the old row sends `-O exit` to the replacement, terminating its sessions, before the supervisor goes on to signal the old PID.

**Evidence: observed.** Scratch test `unix::secrev_close_old_master_kills_replacement_socket_owner` used two real OpenSSH masters and a live preaccepted session. The second master was started directly by the probe and had no supervisor ownership row:

```text
SECREV_REPLACEMENT alive_before=true old_close=Closed unrelated_replacement_exited=true
```

The existing `master_socket_removed_only_if_same_inode` tests unlink protection, not which server receives the control request.

**Required correction:** Establish the current socket's ownership before sending a control request. At minimum a changed/missing recorded inode must skip `-O exit` and use only the old verified process. Preserve generation/identity protection across control-command and unlink operations, rather than applying it only to final deletion. Add the stop/replacement/old-close regression above.

### W3-S04 — Medium — Managed-file operations follow planted directories outside their roots

**Locations:** [files.rs:296](<repo>/crates/adapters/src/managed/files.rs:296), `ensure_dir`; [files.rs:411](<repo>/crates/adapters/src/managed/files.rs:411), `clear_generation`; enumeration at [files.rs:619](<repo>/crates/adapters/src/managed/files.rs:619). The binding-file operations use the same primitives.

**Guarantee broken:** 6, no symlink/planted-file write redirection or cleanup outside the managed directories; spec §8.2's shared-resource integrity boundary.

The write path checks the final directory with `symlink_metadata`, but follows parent components when creating/opening/renaming. An existing final directory is accepted without checking owner or permissions. The clear path does not even reject a symlink at the final directory: it reads the marker and removes filenames through it. A plaintext marker is not proof that the traversed directory belongs to Heimdall.

**Concrete scenarios:**

1. Plant `<state_dir>/managed` as a symlink to a disposable unrelated directory. `write_slot` creates/writes its destination directory under that target and returns success.
2. Plant `<state_dir>/managed/d1` as a symlink to an unrelated directory containing a matching plaintext `.generation` marker. `clear_slot` follows it and deletes that directory's `key.pub`, `cert.pub` and marker.
3. Precreate the leaf directory mode 0777. It stays 0777 after a successful managed write, so the intended owner-only-directory condition is never established.

These scenarios require the ability to plant filesystem entries under the relevant root, or an already unsafe directory. They do not imply that another UID can traverse a correctly protected root. Atomic rename of the final filename prevents a simple final-file symlink overwrite, but does not stop ancestor traversal or unsafe clear traversal.

**Evidence: observed.** A standalone Rust probe linked the real `heimdall_adapters`, `heimdall_contract` and `heimdall_domain` libraries. All targets were under the review scratch root:

```text
PARENT_SYMLINK_WRITE accepted=true outside_cert=true
LEAF_SYMLINK_CLEAR result=Removed unrelated_files_deleted=true
EXISTING_DIR mode=777 file_mode=644
```

No secret key material was used. The files were public-format fixture lines or unrelated public-file sentinels. Mode 0644 alone is not reported as a private-key disclosure: ADR-0008 D10 calls these files public. Their integrity still depends on validated owner-only directories. The literal owner-only-file requirement is stronger than the current 0644 implementation and should not be claimed without resolving that difference.

**Required correction:** Anchor operations to verified owner-only directory handles, reject symlink/reparse components for writes and cleanup, and verify existing directory ownership/mode/ACL instead of accepting any directory. Reuse the repository's existing handle-relative, identity-checked filesystem patterns. Test both parent-component and final-directory symlinks, including restart enumeration/cleanup.

### W3-S05 — Medium — A stale write can roll a slot back to an older generation

**Location:** [files.rs:391](<repo>/crates/adapters/src/managed/files.rs:391), `write_generation`; the split claim/write caller is [effects.rs:554](<repo>/crates/adapters/src/managed/effects.rs:554).

**Guarantee broken:** 6, generation-bound slot/binding files; spec §8.2, cleanup must not affect a replacement belonging to another live binding.

`write_generation` unconditionally replaces the marker before replacing the data files. It never checks whether the directory already carries a newer generation or another holder. The global mutex only serializes calls; it does not establish their generation order. `ManagedSlotTable::claim` commits its store claim before calling this file operation, so an old worker may be delayed across subsequent lifecycle changes unless U10 provides an additional fence.

**Concrete scenario:** A write for generation 1 is delayed after its claim. A release and new claim publish generation 2. The old write resumes, writes generation 1's marker and certificate over generation 2, and returns success. `slot_generation` now reports 1. A generation-2 clear sees `OtherGeneration(1)` and leaves the stale files. The current legitimate holder's alias is broken, and the file state no longer represents the store's ownership generation.

**Evidence: observed primitive; concurrent scheduling consequence inferred.** The files probe first wrote generation 2 and then submitted generation 1 using the real `write_slot` API. Both returned success:

```text
LATE_WRITE generation=Some(1) stale_content=true
```

The probe used public-format placeholder certificates and did not demonstrate authentication with a revoked key. The signer/store authorization checks remain a separate defense against such authentication. The existing generation test covers a late *clear* of generation 1 after a generation-2 write, not a late *write*.

**Required correction:** Fence writes as well as clears against the current generation and holder. Refuse backward/mismatched generations and coordinate in-flight blocking writes with slot release/replacement. Preserve enough authoritative lifecycle information to prevent a cleared old operation from recreating files. Add a delayed old-write/new-claim test that proves the new marker and bytes remain unchanged.

## Assessment of every requested guarantee

| # | Assessment | Evidence and limits |
|---|---|---|
| 1. Revocation/deadline/cascade | **Not held in full.** | Key destruction/cascade and stale-certificate refusal hold in the exercised adapter/Operations composition. The connection policy tests close dedicated connections on revocation under both policies and at strict deadlines. W3-S01 and W3-S02 leave post-end mux admission paths. Production cleanup/gate wiring remains U10 work. |
| 2. Re-issue never widens | **Held by the reviewed checks and focused tests.** | `reissue::eligible` refuses non-store input, ended/tombstoned grants, deadlines/cutoffs, either recorded/current `revoke_on_lock`, unsafe time and missing anchors. `same_grant` compares grant ID, exact pairs and absolute deadline; `reissue_from` bounds the outcome. All corresponding managed-adapter tests passed. No process file is consulted by these functions. Actual production re-issue remains unavailable. |
| 3. Signal only exact owned processes | **Held for direct signalling at the reviewed boundary, with the accepted macOS residual; not held for all connection-closing effects.** | The pin is opened before start-token/image verification. Linux sends through its pidfd; Windows queries creation time/image and terminates on the same handle. macOS verifies PID/start/image immediately before TERM and re-verifies before KILL after the grace period. An unverifiable dedicated holder was left alive by the native test. W3-S03 bypasses equivalent ownership checks with a mux control command. Native Linux/Windows execution is blocked on those missing platforms. |
| 4. Windows containment | **Code ordering held; native verification blocked.** | The new predicate requires a managed binding and the verified SSH program. `spawn_suspended` sets `CREATE_SUSPENDED`, assigns the child to a new kill-on-close job without breakaway, then reads creation time. Assignment/time-read failure kills and reaps. The launcher calls the registrar while suspended and resumes only on `Registered`; refusal/failure closes the job. The job remains until the SSH child exits, covering its descendants. Other programs take M02's `spawn_and_wait`. These Windows paths were not executed on macOS. |
| 5. Master ownership, forwarding and foreground behavior | **Not held in full.** | W3-S02 and W3-S03 break ownership/replacement protection. `create_private_dir` also accepts an existing directory without verifying its owner/mode or symlink ancestry, so its name is not a permission proof. Positive tests for preaccepted-session closure, master foreground pins, user `ControlMaster` precedence, ordinary owned-master reuse and refusal of forwarding without `permit-port-forwarding` all passed on OpenSSH 10.5p1. The server rejects the forwarded channel; a local forwarding listener/control request may still exist, as the test correctly distinguishes. |
| 6. Files and identity selection | **Not held in full.** | Writes use exclusive temporary creation, sync and per-file rename; ordinary generation-matching clears work and late clears preserve a newer generation. W3-S04 and W3-S05 defeat root/generation integrity. Managed identity argv uses the certificate as `IdentityFile`, pins `IdentityAgent` and `IdentitiesOnly=yes`, and does not name the plain K_env public key as a usable identity. No branch switches to `SSH_AUTH_SOCK` or another provider after an adapter failure. However inherited `IdentityFile`/`CertificateFile` entries remain possible under §17.19 item 4: absolute exclusive identity selection is not established by this form alone. The adapter conservatively reports selection as unknown pending classification/U10. |
| 7. Secrets | **No new leak found in the reviewed paths; bounded verification.** | Generation returns only public-key registration; K_env remains in the vault and destroy removes it. Install parsing errors become fixed codes. File effects use public key/certificate lines. Connection rows/locators contain IDs, PID/start/image/path/inode, not private keys. `remote_effects` contains pair IDs, expiry, clock measurement/status and bounds. New file/connection error paths avoid dumping input bytes or argv. The changed-file scan found zero private-key PEM blocks, literal canary assignments and home paths. No owner key/store/agent was used. This is not exhaustive secret-leak fuzzing or proof for arbitrary inherited process environments. |
| 8. New unsafe blocks | **No confirmed invariant violation found by source review; Windows execution blocked.** | macOS buffer lengths are checked before constructing paths. Windows raw handles are adopted once into `OwnedHandle`; job, snapshot, thread and process handle lifetimes cover each call. Process termination uses the same verified handle. No double close was found. The primary-thread concern was investigated and rejected using the pinned Rust source, described below. |

### Windows thread-handle counterevidence

An initial concern was that `resume_only_thread` enumerates a thread ID and opens it later. It would be wrong to report thread-ID reuse without checking the standard library's handle lifetime. The official pinned [Rust 1.99.1 Windows process source](https://raw.githubusercontent.com/rust-lang/rust/1.99.1/library/std/src/sys/process/windows.rs) constructs `Process` with both `pi.hProcess` and `pi.hThread` wrapped as owned handles. Its `Process` retains `main_thread_handle`. Therefore the suspended `std::process::Child` keeps the original primary-thread object/ID pinned while this code enumerates and opens it. The process handle also prevents process-ID reuse. This is counterevidence to the suspected reuse bug, not a Windows finding or a native Windows test result.

## Deferred U10 seams and bypass assessment

| Seam | Current fixed-revision behavior | Assessment |
|---|---|---|
| Managed effect driver | [app/managed.rs:1025](<repo>/crates/app/src/managed.rs:1025) returns `MANAGED_DRIVER_NOT_WIRED` before effects/store work. The adapter's plain `prepare` refuses; `prepare_from` requires driver results. | Fails closed. The test fixture driver is explicitly separate. |
| Signer install view | [credential/table.rs:536](<repo>/crates/credential/src/table.rs:536) obtains the optional view; absent view returns `StoreViewUnavailable` before installing. The new effects implementation does not set a view. | Fails closed. Test-installed views do not prove production authorization. |
| Verification signatures | The signer requires a permit for verification as for grants; production `Operations` refuses verification subjects until their operation gate is wired. `VERIFICATION_UNGATED_SIGNING` stays false. | No ungated path added by wave 3. |
| Managed `connect` | The catalog's missing managed preference leaves the existing M02 path. Its eligibility checks remain. A recognized managed result requires managed ensure/bind; that preparation is unavailable. The separate Windows managed-connect refusal remains at [connect_cmd.rs:398](<repo>/crates/heimdall/src/connect_cmd.rs:398). | No new successful managed-connect route. The existing-access path is not evidence of managed enforcement. |
| `run` slot table | [run_cmd.rs:279](<repo>/crates/heimdall/src/run_cmd.rs:279) still calls managed checks with `UnavailableSlots`; its state/claim operations refuse. The new `ManagedSlotTable` is not silently substituted into this production call. | Fails closed before a managed child launch. |
| Windows registration request | [runtime/dispatch.rs:238](<repo>/crates/runtime/src/dispatch.rs:238) still returns `driver_unavailable` for `Connections` requests, after owner authorization. The new production registrar accepts only `Code::Ok`; every other reply is failure/refusal and closes the suspended child's job. | Fails closed. The focused dispatch test also proved no record changes. |

A search of production callers found no runtime construction/use of `ConnectionSupervisor` outside its new module; the U10 supervisor/service integration is still absent. No wave-3 code opens a successful product route around the six deferred seams. This does **not** make the component findings safe to merge as completed security boundaries: they must be corrected before those components enforce the described guarantees. The tests deliberately inject store/endpoints/install hooks to exercise them now.

## Executed validation and command ledger

Commands were run from `<scratch>/wt` unless an absolute `git -C` path or another directory is shown. Cargo output was captured by a Python wrapper that emitted only test names/results, compiler error headings and return codes, and filtered canary-marked lines before output. No raw authentication configuration, environment dump, process command lines or bulk service logs were emitted. Probe output contained only fixed labels, booleans, modes, generation numbers and nonsecret error variants.

### Build/test commands

| Executed command | Exit | Observed result |
|---|---:|---|
| `cargo test -p heimdall-adapters --test integration_managed_adapter --locked` | 0 | 38 passed, 0 failed, 0 ignored. Includes re-issue, destruction under exclusive gates, cascade, stale approval/certificate refusal, real issuer-child issuance-step injections, residual reporting and file cleanup cases. |
| `TMPDIR=/tmp cargo test -p heimdall-runtime --test integration_connections --locked` | 0 | 28 passed, 0 failed, 0 ignored. Real disposable loopback OpenSSH masters/dedicated connections. |
| `cargo test -p heimdall --test e2e_deadline_m03 --locked` | 0 | 1 passed: registration failure reason-to-exit mapping. Windows tests are excluded by `cfg(windows)`, not passed. |
| `cargo test -p heimdall --test e2e_consumer_m03 --locked` | 0 | 6 passed: owned foreground pins, explicit option refusals, binding identity argv and unchanged existing-access connect flow. |
| `cargo test -p heimdall-runtime --test integration_runtime_m03 --locked w0_m03_requests_fail_closed_before_any_record` | 0 | 1 passed, 21 filtered out. Real dispatcher refuses unwired M03 requests without changing the store. |

Total existing tests actually executed in these invocations: **74 passed**. This is not a Windows/Linux support claim.

### Scratch probes

The probes did not modify a repository file. `files-probe.rs` was a standalone program; `connections-probe.rs` was a scratch copy of the existing connection-test harness with the additional `secrev_*` tests inserted into its Unix module. They linked the actual compiled libraries from this detached checkout. No production implementation was patched or stubbed.

| Executed command/action | Exit | Observed result |
|---|---:|---|
| Python creation of `<scratch>/{files-probe.rs,connections-probe.rs}` | 0 | Only scratch probe sources written. |
| `rustc --edition=2024 <scratch>/files-probe.rs -L dependency=target/debug/deps -o <scratch>/files-probe` with `--extern` for the built adapters, contract and domain `.rlib` files | 0 | Linked unchanged file implementation. |
| `<scratch>/files-probe` | 0 | Asserted parent-symlink write redirection, final-directory-symlink cleanup, acceptance of mode 0777, and backward generation overwrite. Exact output is in W3-S04/W3-S05. |
| `rustc --test --edition=2024 <scratch>/connections-probe.rs -L dependency=target/debug/deps -o <scratch>/connections-probe` with built `--extern` libraries | 0 | Initial probe build. Dependencies were selected from the checkout's `target/debug/deps` by the external crate names referenced in the harness. |
| `TMPDIR=/tmp <scratch>/connections-probe secrev_ --nocapture --test-threads=1` | 0 | 2 probes passed their assertions that the defects occur: old-close kills replacement; overdue active master retained and reused. 28 existing harness tests filtered out. |
| Python insertion of `secrev_unowned_master_reused_after_revocation`, followed by the same Rust probe build | 1 | First rebuild selected a newer `heimdall-testkit` library lacking the `managed` feature; compilation failed with E0432 (`ca` configured out). No test executed on this attempt. |
| Same Rust probe build, selecting the `heimdall-testkit` `.rlib` whose Cargo fingerprint includes `managed` | 0 | Corrected dependency selection only; no product change. |
| `TMPDIR=/tmp <scratch>/connections-probe secrev_unowned_ --nocapture --test-threads=1` | 0 | Foreign master reused after grant revocation, despite `mux_path_occupied`; 30 other tests filtered out. |

Probe reproduction details that matter:

- For W3-S01, set the fixture grant's deadline to `Timestamp::now() + 2s` using `tx.update_grant_state`, start the real supervisor master, drop that supervisor, wait 3s, construct another supervisor over the same store, call `connection_restart_pass`, and issue ordinary SSH through the fixture alias. Keep the recorded state active. Verify success and unchanged server auth count before closing the master.
- For W3-S02, use the harness's `master_argv`, binding certificate and fixture endpoint to start a master directly as a probe-owned `Child`, then call supervisor `start_master`, mark the fixture grant revoked, call `revocation_close`, and issue an ordinary command. Verify `mux_path_occupied`, no closed rows and unchanged auth count on success.
- For W3-S03, start one supervisor master and an ordinary `sleep 120` session through it; send isolated `-O stop`; wait for its socket to disappear while both processes remain alive; start a second probe-owned master at the same path; call `close_one` on the first row and observe the second `Child` exit.
- For W3-S04/W3-S05, call the public `files::{write_slot,clear_slot,slot_generation}` APIs with scratch `SlotRoot`, typed fixture IDs, `ssh-ed25519 AAAA public-probe` and a public-format placeholder certificate. The redirection victim and marker were created by this probe, outside its state directory but inside its own scratch root. No valid private key was needed or supplied.

### Read-only inspection/setup commands and diagnostics

The following describes all inspection command groups, including unsuccessful lookups; repeated `sed`/`nl` slices of the same listed files were source reads, not additional validation runs.

| Command/group actually run | Exit/result |
|---|---|
| Initial `pwd` and `rg --files -g AGENTS.md <home>/.codex <home>/GitRepos 2>/dev/null | head -80` inventory | Batch exit 0. Instruction discovery only. |
| `cat` of active Codex-home `AGENTS.md`, security-diff-scan/ponytail-review skill files, and the security plugin's config-preflight/artifact-storage references | All exit 0. User's report-only/read-only scope superseded extra scan artifact workflows. No delegated child was started. |
| `git -C <repo> worktree add --detach <scratch>/wt 3f7a582e` | 0. Detached fixed head created as requested. |
| `python3 .../codex-security/0.1.32/scripts/config_preflight.py --profile security_diff_scan --cwd <scratch>/wt --runtime-check delegation_available=false --runtime-check goal_tools_available=true` | 0, `ready`. Delegation warning: this explicitly independent review sub-agent performed its own review; no nested delegation. No configuration was changed. |
| `git rev-parse HEAD HEAD^`, `git status --short`, `git diff --stat 1b5c1758 3f7a582e`, `git diff --numstat 1b5c1758 3f7a582e` | All exit 0. Exact head/base above, 26 changed files, clean review source tree. |
| `cat rust-toolchain.toml Cargo.toml`; `rg --files` to locate ADR-0005/0008 and SECURITY.md; `rg`/`sed` over `spec.md`, `plan.md`, ADR-0005/0008, architecture overview | Exit 0. Read the specified guarantees/rulings and unsafe table. No SECURITY.md was returned by the inventory. Some broad heading output was truncated; the relevant decision sections were subsequently read with bounded slices. |
| `cat tests/evidence/artifacts/review-m03-code/wave3-notes/*.md`, then bounded `sed` reads of the shared API notes | Exit 0. Treated as integrator context/claims, not proof of test execution or as instructions to edit. |
| `nl -ba`/`sed` over every new `adapters/src/managed/{mod,effects,prepare,reissue,report,files}.rs` and `runtime/src/connections.rs` | All exit 0. Traced effects, re-issue, materialization, reporting, process ownership and lifecycle passes. |
| `git diff 1b5c1758 3f7a582e -- crates/localenv/src/sys/mod.rs`, followed by bounded `nl`/`sed` reads of the new process/job helpers | Exit 0. Reviewed new FFI calls, buffer bounds and handle ownership. |
| `git diff` for `run_cmd.rs`, `launch/windows.rs`, the changed manifests, exports and Cargo.lock; bounded reads of launcher code | Exit 0. Reviewed production routing, guard predicate, registration refusal and dependency deltas. No added package in the lock; dependency arrays/features changed. |
| Bounded reads/searches of all three changed test files; related `consumer_m03.rs`, `runtime_m03.rs`, `credential/{table,signer}.rs`, `app/managed.rs`, `app/operations/{authorize,connections,bind_connection_m03,restart_m03}.rs`, `app/operations.rs`, `runtime/{service,supervisor,platform,dispatch}.rs`, and `heimdall/{connect_cmd,launch_flow,run_cmd}.rs` | Source-read batches exit 0 except the missing-path searches listed next. Traced actual callers, production stubs, table destruction and fixture substitution. |
| One `rg` search including shell glob `tests/unit/*.rs` | Not executed: zsh reported `no matches found: tests/unit/*.rs`. Later commands in that batch ran and the batch ended 0. No conclusion relies on that failed search. |
| Corrected `rg` search that also named nonexistent `crates/app/src/ensure` | `rg` exit 2. Existing-file matches were returned; missing directory was a path error. Subsequent inspection used actual `app/managed.rs` and `operations.rs` instead. |
| Later `rg` search that also named nonexistent `tests/integration/signer.rs` | `rg` exit 2. Located actual managed signer sources afterward. No signer test was falsely counted as run. |
| `rg --files tests | rg 'sign|credential|managed|runtime_m03'` | Pipeline exit 0; overly broad filename inventory was truncated. It was not used as security-log evidence. |
| `rustc --version`, `uname -sm`, `ssh -V` | Each exit 0; versions/host above. |
| Python targeted scan of the 26 changed files, obtained with `git diff --name-only` | 0. `private_key_pem_matches=0`, `literal_canary_assignment_matches=0`, `home_paths_matches=0`. Counts only were emitted, never matched secret bytes. |
| Python `rustc --print sysroot` plus exact installed-standard-library source-path check | 0; installed Windows Rust source and the installed std source directory were absent. |
| Python public-source lookups | Wrapper exits 0. Old `1.92.0/.../sys/pal/windows/process.rs` reference URL returned HTTP 404. Exact `1.99.1/.../sys/process/windows.rs` returned source confirming retained primary-thread handle. A current rustdoc source URL returned HTTP 404. Only the exact pinned source was used as counterevidence. |
| `git status --porcelain=v1` and final Python status check | 0; zero source/untracked changes in the review checkout before removal. |
| `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'` | `du` exit 1: none of those output directories existed in this detached checkout. The surrounding inspection batch ended 0 because its final `du -sh target` succeeded. |
| `du -sh target`, repeated before removal | 0; 3.8G root Cargo output. It was removed with this review's own worktree, not left in the workspace or shared into another checkout. |

No `cargo clippy`, cross-compilation, Docker fixture up/down, remote host command, package publishing, commit or push was run.

## Cleanup, changed files and remaining limits

Cleanup commands actually executed:

1. Python unlinked exactly this review's `files-probe.rs`, `files-probe`, `connections-probe.rs`, `connections-probe`, and removed its `files-fixture` directory: **exit 0**.
2. `git -C <repo> worktree remove --force <scratch>/wt`: **exit 0**. This also removed the 3.8G build output inside that worktree.
3. `rmdir <scratch>`: **exit 0**.
4. Python checked `git worktree list --porcelain` without emitting other checkout paths: **exit 0**, `review_worktree_registered=False`, `scratch_root_exists=False`.

Report creation and this structural validation used Python: both **exit 0**. Validation checked the five numbered findings, all eight guarantee rows, verdict, cleanup absence and absence of private-key PEM blocks.

**Changed repository files: none.** No commit, push, stash, owner SSH/key/agent change or service reconfiguration occurred. The sole retained output is `<scratch>-report.md`. Probes and the standard test harness used disposable keys/agents/loopback services and exact probe-owned child PIDs, with fixture/child cleanup; no process was stopped by a name/pattern match.

**Not checked:** native Windows containment/ACLs/registration/revoke-before-resume or Linux pidfd behavior; WSL; real owner lock/secure-store behavior; exhaustive race/secret fuzzing; the full workspace/lint suites; and successful production U10 workflows. Windows and Linux native claims are **blocked** on the missing Windows and Linux test platforms, respectively. Cross-compilation or fixture reports from another run were not counted as native proof.

**Risk:** The positive macOS tests do not cover the newly reproduced adversarial cases. Keep the U10 seams closed and fix W3-S01 through W3-S05 before claiming deadline, master-ownership or managed-file integrity guarantees.
