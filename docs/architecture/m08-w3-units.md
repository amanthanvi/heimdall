# M08 W3: the unit order with owners, and the U2b brief (after the U0 handoff at `eda7d35d`)

**Status:** approved by the orchestrator, 2026-11-24, with its notes folded in (§1 H13 readers; §2.5 review).
- **Inputs:**
  - `docs/architecture/m08-w3-plan.md` (approved in outline);
  - the handoff message of 2026-11-24 (the write scope by unit);
  - `docs/architecture/m07-u0-handoff.md` and `m06-u0-handoff.md`;
  - ADR-0006 §19 (rev7 preparatory: §19.3 H1 to H15, §19.4 the restore rule);
  - `docs/architecture/u0-plan.md` §3 (H13) and §9 (lines outside U0);
  - the U0 rulings (`/tmp/hm-tools/u0-rulings.md`).
- **The branch:** `m08/w3` = `760117ee`, with `main` `eda7d35d` merged into `efe311c4`.

## 1. Units, order and owners

The integrator is the M08 track lead (this agent). It integrates, commits and runs the gates.
Workers never commit or push (AGENTS.md).

| # | Unit | Owner | Write scope (from the handoff) | Waits for | Size |
|---|---|---|---|---|---|
| 1 | **U3c**, the test-kit edge | the integrator | `crates/testkit/Cargo.toml` and its `cfg` on the strategies module; one manifest line in each crate that depends on the kit with default features off and uses the strategies; the new test `release_graph_holds_no_test_only_crate` | — | about half a day |
| 2 | **U2b**, lifecycle (§2 below) | **one implementer, Claude Opus 5.5 at the strongest effort** (authority-adjacent), with the integrator reviewing each slice; one independent review (a fresh Opus, §2.5) and one scoped re-check for the wave (ADR-0009) | as §2.2 | — (U2b-1 can start now) | about 3 to 5 days, in four slices |
| 3 | **U1b**, the new boundaries and the hostile-input table | one implementer, Claude Opus 5.5 at the strongest effort, reviewed by the integrator | `fuzz/**` (targets 12 to 15); `tests/adversarial/**` for any §14.3 row without a test; the `unsafe` inventory (a doc and a check); Q10's producers (`alias_collision` doctor finding, `AliasCollision` setup conflict) and the legacy case-variant report, in `crates/localenv/**` and the doctor's finding table; M06's follow-ups F3, F5, F6 and F8 (`crates/localenv/**`); ISS-F1, once the issuer fix's record names it | — (in parallel with U2b) | about 2 days |
| 4 | **U6b** (`support bundle`) and **U7b** (the defaults audit, then the final text and matrix) | the integrator, or one implementer for U6b | U6b: replace `rev7_cmd.rs`'s `support bundle` arm (H1) over `crates/support`. U7b: `docs/**` | U2b-2 for the bundle's state fields | about 1 day each |
| 5 | **The candidate commit** (U3b's start) | the integrator | `1.0.0-rc.1` set once, with U8's claims-table update (ASK-VERSION); the frozen feature set (default, no `iroh`); `examples/` packaged | 1 to 4 merged to `main` | — |
| 6 | **U3b, U4b, U5b, U8** | the integrator, with PC and devbox jobs | per m08-w3-plan W3-2 to W3-6 | 5 | per W3-1 |

**W3 closes at its review, and W4 follows (the orchestrator, 2026-11-25).**
- **W3** is U3c, U2b-1, U1b and U2b-2 with follow-ups A and B, to `065f3a45`, plus the fixes
  for the W3 independent review's findings.
  - The scoped re-check covers only those fixes.
  - The merge candidate is `065f3a45`, plus the fixes, plus the documentation and evidence
    commits. It gets one gate, and Windows and devbox runs for the fix diff only. U2b-2's PC
    job 65 and its devbox run (`devbox-u2b2/`) stand.
  - Then `m08/w3` merges to main. That unblocks M07's W10 readers, and its rebuild on U2b-1.
- **W3's rig audit is partly resolved** (PC job 66). `integration_managed_adapter` still leaves
  `.tmp*` directories on Windows. It is test-only and does not block (ADR-0009 §2.1).
  - **W4's first item:** find what holds the store or the files past the scratch directory's
    drop (another rig in that file, or a thread, task or child process that outlives `World`)
    and fix it. Look for the same pattern in other rigs. Prove it on Windows with a `.tmp*`
    count.
  - **Not run in job 66 (a harness prerequisite):**
    - `e2e_deadline_m03`'s `windows::*` tests: the next full m02 Windows harness run, at the W4
      candidate at the latest.
    - `e2e_tui_m02`'s `console::*` tests: covered by job 66c (3 passed, with an owner-only
      `TEMP`, and `.tmp*` from 0 to 0). Job 66b, with the default `TEMP`, was refused with
      `StateDirUnsafe`, the correct refusal.
- **Two load flakes in the merge candidate's gate** (`ae600472`, which ran for about 2.5 hours
  under another project's build). Each passed three focused runs. They are W4 test-only fixes:
  - `e2e_environment_runner_m06`
    `driver_e2e::a_controller_policy_naming_the_runner_issues_for_a_runner_originated_grant`:
    `operation wait --timeout-ms 120000` returned the operation still `running` (`next:
    observe`), which is the contract's answer to a caller timeout. The test asserts only `OK`.
    Fix: loop the wait until the operation settles, or assert the settled state so that it
    fails clearly.
  - `e2e_enroll_m03` `enroll_reconcile_not_applied_within_validity`: the 10 s `SHORT_STEP`
    bound was exceeded. Fix: give the bound headroom under load, or run the test serially,
    whichever the Windows constraint in its comment allows.
- **W4** is everything after: U2b-3 (in two slices, U2b-3a and U2b-3b), U2b-4, GRANT-LIVE, U6b,
  U7b and rows 5 and 6 above. It has its own independent review and re-check at the W4
  candidate. Units 4 to 6 in the table above move to W4.

**W4's review is split by the author's model family (the orchestrator, 2026-11-26).** W4 has
one review cycle (ADR-0009), divided so that every unit is reviewed by the other family.
- **Gemini 4 Neon** (`antigravity`, `gemini-4-neon`, `thought_level` xhigh) **reviews the units
  Opus wrote:** W4-T1, U2b-3a and U2b-3b, U2b-4, U6b and U7b. It replaces GPT-6.2 Sol (amended
  2026-11-26), because GPT-6.2 Sol stops security-boundary review partway through with a
  "possible cybersecurity risk" flag. GPT is used only if Gemini is unavailable. The review
  brief is phrased defensively: which guarantee fails and when, no exploit code, and a
  regression test as the evidence (template: `/tmp/hm-m09-secreview/brief-common-v2.md`).
- **One Opus reviewer reviews the units GPT wrote:** GRANT-LIVE, and any later unit given to GPT.
- **Both reviewers get:**
  - the same brief shape;
  - the wave's cross-cutting diffs that touch their units: the integration merges and the
    migration numbering (GRANT-LIVE takes `0015`, U2b-3a `0016` if it needs one).
- **The scoped re-check** is split the same way.
- **The record** names each unit's implementer family and reviewer family.
- **If Opus is rate-limited** when the review is due, the GRANT-LIVE half waits for it. GPT
  never reviews GPT's code.
- **The standing fallback (2026-11-26).** If Opus is rate-limited when a review is due, a unit
  Gemini wrote may be reviewed by GPT-6.2 Sol instead, on the defensive brief. If GPT stops on
  its cybersecurity flag, that half waits for Opus. A unit is never reviewed by its own family.
- **The security units from M09's early review (S1 to S4), grouped by file:**
  - SEC-1 (Opus): the issuer barrier and the remote ingress (S1-01, S1-02, S1-04, S2-04, S3-02).
  - SEC-2 (GPT): the projection pin and Windows paths (S4-01, S4-03, S4-04, S4-05).
  - SEC-3a (Gemini): the runtime (S2-01, with U2b-3a's item 2; S2-02; S3-05).
  - SEC-3b: S2-05's design (Gemini) and its code items.
  - SEC-4 (GPT): cutoff latching (S3-01, S3-03, S3-06, S3-07).
  - S3-04 goes to U2b-3b.
  - **SEC-5's record.** Authors: Gemini 4 Neon wrote the WIP (`b0affd8f`), and Opus finished it
    (`1a95fc9a`). The reviewer is Gemini.
    - **Rulings of 2026-11-26:**
      - A fired `profile:` or `workspace:` row from another controller blocks every policy until
        the attended lift. This is accepted as fail-closed for 1.0; `ReportedPolicy` membership is
        the post-1.0 path.
      - Ruling 7 also applies to `submit_ensure`.
      - The new `credential_lifecycle.cause` values are approved; the field is an
        `Option<String>`, so they are additive.
      - An unreadable runner answer must never block a local removal.
      - The grammar-fit residual is accepted.
    - **SEC-5F, next on Gemini, carries:** those follow-ups, and U2b-3a's held item 4, which
      moved out of U2b-3b so that `remote_env*.rs` and `m06_cmd.rs` have one owner.
  - **A defect found during W4 (U2b-3a-F, Gemini):** `OperationsDispatcher::handle_as`, the
    dispatcher entry that a local `LimitedConsumer` caller reaches, bypassed the request fence
    completely (`Gate::open()`). Requests through it were never stamped, never added to the
    request ledger and never held to the per-caller share.
    - Fixed in `61081b38`. `handle_as` now runs the pre-fence refusal, the fence keyed by the
      caller, the stamp and the terminal record.
    - Test: `a_local_requester_principal_is_bounded_by_its_share`. It fails at the base, and fails
      again with only the fix reverted.
    - **Ruling of 2026-11-27:** paired owners stay share-limited; only the local owner is exempt
      (ADR-0006 §19.3).
  - **A W4 load flake:** `e2e_tui_m07` `pty::a20_key_latency` (M07's A20, debug build) failed the
    gate at `95043b74`. The search keystroke's completed-frame P95 was 105.5 ms against a 100 ms
    budget; Tab and PageDown were well inside it.
    - The load averages were 10, 11 and 20, with three workers and other tracks running.
    - SEC-5 touches no TUI code.
    - Three focused reruns at the same SHA all passed, at load averages of 5 to 8. The full tip
      `f3f0c082` was then regated.
    - **Ruled 2026-11-27:** keep the budget and run A20 **serially** in the gate. It is never
      skipped under load. It goes to M07. The authoritative A20 numbers come from the release
      build on a quiet host at the candidate's benchmark run; the gate's debug run stays a
      regression guard.
  - **A product-facing installer defect, found by PC jobs 70 and 71.** `install.ps1`, run by
    Windows PowerShell 5.1 from a PowerShell 7 parent (Windows Terminal's default), fails with
    `Get-FileHash` not recognized. The cause: `pwsh`'s modules path is inherited through
    `PSModulePath`.
    - It would have shipped. It came to light only because the payload self-test gained a run
      under 5.1 and the capture of the installer's own output.
    - **The fix unit:** the installer no longer depends on the inherited `PSModulePath`. The
      self-test runs it under 5.1 with both a clean `PSModulePath` and a `pwsh`-like one.
    - The PC reruns it from both parent shells (job 72).
  - **The store split while U2b-3b and SEC-3b run in parallel** (approved):
    - **U2b-3b:** migration `0017`, `layout`, the backup, open and restore paths in `lib.rs`,
      `stategen` and `fence`.
    - **SEC-3b:** migration `0018`, `ext_m06*`, `ext_runner`, `ext_effects` and the report
      builder. Its new `Txn` methods go in its own ext files.
    - They are integrated one at a time.
  - **SEC-4's record.** Authors: GPT-6.2 Sol wrote the WIP (`82c98040`, then stopped on its
    cyber flag), and Opus finished it (`80de1241`). The reviewer is Gemini.
    - **Confirmed, 2026-11-26:** under uncertain time, a fired cutoff cuts an anchored grant's
      continuous budget to the floor, and the next tick ends the grant. This is the intended
      fail-closed direction (ADR-0012 §7.2 and §7.4).
    - **Moved to SEC-5:** the ended grant's reason, and its status and readiness text; S3-07's
      single transaction (`timegate.rs` granted); the "fired while time was uncertain" wording;
      and the wait at `tests/e2e/exit_m06/m06.rs:89` (granted, test only).
    - **The sibling waits:** `environment_runner_m06.rs:1670`, `exit_m06/t06.rs:98`,
      `exit_m06/a25_limited.rs:643` and `exit_m06/m06.rs:89` (that last one via SEC-5) were made
      robust after the M06 exit, and what they assert did not change. `lift.rs` keeps single
      waits, because its steps assert that a request stays pending.
    - **SEC-4 and SEC-1 interact; the reviewers of both should see this.** At `2a5adff3`, SEC-1's
      S3-02 test `another_controllers_cutoff_that_fired_early_blocks_reserve_and_publish`
      failed. It had pinned `fired_uncertain_at` to the runner's fast wall-clock reading (10:00).
      SEC-4's latch now stores the floor instead (08:59:55).
      - The test-only fix `7d17d9f6` asserts the property S3-01 guarantees,
        `fired_uncertain_at <= certain`.
      - The blocking outcomes are unchanged: `all`, `policy:P` and `profile:dev` refuse, and
        `profile:ops` issues.
      - The orchestrator accepted the fix on 2026-11-26.
  - **SEC-3a's record.** Authors: Gemini 4 Neon wrote the WIP (`82f7637b`), and GPT-6.2 Sol
    finished it (`8c3649ee`). The reviewer is Opus.
    - The worker's `check.sh` showed 124 failures in the enroll suites. They came from its
      environment, not from SEC-3a: a temporary release wrapper was shadowing `bash`.
    - The lead's gate at `e5cab15f` was green, at 4327/0/204, with no enroll failure.
    - Since then, the worker rules forbid a wrapper ahead of system tools on `PATH` for a gate
      run.
  - **SEC-1's open items, as ruled on 2026-11-26:**
    - **S2-04:** a real tombstone still bumps the authority generation once. This is accepted
      for 1.0, because it fails safe: a pending decision must be confirmed again. SEC-3b may
      narrow it to a bump only when a local grant or decision is affected, if that is cheap
      there.
    - **SEC-5, a new unit, must be fixed before the candidate:**
      - a runner's success data is screened at the remote ingress, to each field's local
        grammar; this changes values only, never a shape;
      - an unknown `Code` is bounded;
      - S3-02's reading is corrected: `all` always applies, and the time a policy was created
        is never evidence that a row does not apply;
      - the void reason for a gone record;
      - `forward_ensure` refuses a runner-named grant ID that equals a local grant;
      - `ManagementAnnouncer`'s `key_ready()` moves off the service executor.

      SEC-5 is security-boundary work, so it never runs on GPT.
    - **A post-1.0 note:** the issuer child's own check of the source policy is defence in
      depth. Publication enforces the policy since SEC-1.
- **The U7b defaults inventory** (GPT-6.2 Sol, at `904743a6`; `/tmp/hm-w3/u7b/DEFAULTS.md`): it
  found 12 differences. The orchestrator ruled on them on 2026-11-26.
  - **Routed to other units:**
    - D02: U2b-3a, the ledger trim.
    - D03 and D05: the candidate-tooling unit, which runs on GPT.
    - D04: U6b.
    - D06: the candidate commit.
    - D12: U2b-4.
  - **D01, `strict_disconnect`: retired for 1.0, and refused rather than ignored.**
    - The key is removed from the parser, the published schema and the reference.
    - `config.toml` refuses unknown fields, so a file that still sets it is refused at load,
      with the existing usage error naming the per-request and policy controls. Add a test.
    - The ADR that owns the config schema gets a dated note.
    - The post-1.0 path is a narrowing-only default, OR'd into the effective strict flag.
  - **D07, the `[clients]` overrides: deferred to post-1.0.** The parser already rejects the
    table.
    - ADR-0010 §2 and ADR-0007 §8 get dated amendments, and the m02-plan reference is
      corrected.
    - `limitations.md` gets one line: the client is the platform default and cannot be
      overridden in 1.0.
  - **D08, the P04 disclosure.** Setup shows the effective configured ceiling, not a fixed
    "12 hours", and where to change it, even with an empty catalog.
    - Add a test with a non-default ceiling.
    - **Owner decision, 2026-11-26: no setup-time setter for the grant window in 1.0.** P04 is
      met by setup showing the effective configured ceiling and where to change it (the config
      file and the policy actions). The D08 commit records this decision in the U7b record, and
      as a dated note on spec P04's "adjustable during setup" wording, citing the owner's
      answer.
  - **D10, the login registration.** ADR-0010 §6 item 1 is reconciled with the explicit
    `service autostart enable` journey.
    - Setup's summary names that command when managed credentials exist and login
      registration is off.
    - Setup itself registers nothing.
    - Test both behaviours.
  - **D09 and D11 are text fixes.**
  - **Where they land:** D01, D07's text, D08, D09, D10 and D11 go in **U7b-final**, together
    with the final text and matrix. A part that touches a file another unit owns at the time
    goes with that unit.
  - **A known follow-up from SEC-2, for M07:** `destination inspect` and readiness do not yet show
    a typed `host_pin_defeated` reason when the native passive pin check finds a defeated pin.
    Today that reason comes only from the route helper's report. Adding it needs changes in
    `runtime/src/dispatch.rs` and `contract/src/views/catalog.rs`.
    - **Routed to M07 W10,** to land after W4 is merged into main and M07 has merged main.
      Doing it sooner would collide with SEC-3a's `dispatch.rs` and with M07's catalog views,
      which are in flight.
    - **Not blocking:** projection fails closed, and doctor reports the defeated pin and names
      the directive.
  - **W4-T1's follow-up: four sibling single waits** (granted test-only, 2026-11-26). These
    are `tests/e2e/environment_runner_m06.rs:1670` (including its direct read of
    `data.grant_id`), `exit_m06/t06.rs:98`, `exit_m06/lift.rs:91` and
    `exit_m06/a25_limited.rs:643`.
    - Each gets the same settle loop, then asserts the settled outcome.
    - They go with the next unit that touches tests.
    - The M06 exit record stays as it is. The W4 record notes that these exit tests were made
      robust after the exit, and that what they assert did not change.
  - **SEC-3b's rulings (2026-11-26, on the S2-05 design):**
    - **The override:** a narrowing that has an authority effect is never refused. The caps
      with `BACKPRESSURE` apply only to entries with no effect.
    - **R1 to R4:** pruning under safe time, with the conditions the ruling states.
    - **R4's sweep of expired paired `Pending` decisions** is a fix: they had already expired.
    - **R5:** no paging in 1.0. A proved worst-case report size for a stated envelope, written
      into `limitations.md`, and a fail-closed refusal beyond it that recovers once retention
      runs.
    - **The post-1.0 path:** report paging behind `runner-sync-pages/1`, with an HMAC page
      token over `(client, connection, authority_generation, section, key)`, pages of 768 KiB
      or 512 items, at most 16 pages and 3 drift restarts. The controller reconciles only on
      the final page. It is recorded here unchanged from the design.
    - **When SEC-3b runs:** after GRANT-LIVE integrates (both touch the store), and not beside
      SEC-3a or SEC-4 (both touch the runtime).
  - The blocking and must-fix units land before U2b-4, U6b and U7b.

**H13's reader side and M07.** H13 is one change, owned by U2b-2. Its readers today are M07's:
- the TUI's request paths (`crates/heimdall/src/tui/worker.rs`, `tui/m05.rs`, `tui/m07.rs`);
- the reference wrapper (`examples/reference-wrapper/reference_wrapper.py`);
- both harnesses (`examples/harnesses/cli/`, `examples/harnesses/goal-loop/`), including H2's
  frozen code-table row for `REQUEST_STALE` (u0-plan §9: M07 U5h);
- the CLI's retry path (`crates/heimdall/src/client.rs` and the commands that take
  `--request-id`).

**Granted to M08 U2b-2 for that one merge only** (the orchestrator, 2026-11-24):
- the TUI files `tui/worker.rs`, `tui/m05.rs` and `tui/m07.rs`;
- `examples/reference-wrapper/reference_wrapper.py`;
- `examples/harnesses/cli/**` and `examples/harnesses/goal-loop/**`, with H2's frozen code table.

The conditions:
1. **M07's lead reviews those diffs before the merge,** routed by the orchestrator, and their
   objections block.
2. **U2b-2 rebases on `main` just before its gate** (M07 edits `tui/` for U7b and U7a). A
   conflict that touches M07's logic, not the request path, stops the slice and goes to the
   orchestrator.
3. **After U2b-2 merges, the files return to M07.**

`crates/heimdall/src/client.rs` (the CLI retry path) and the commands that take `--request-id`
are inside U2b's scope (confirmed).

## 2. The U2b brief

### 2.1 Goal

ADR-0014 §3 in full, with §3.6, as ADR-0006 §19.4 adopts it into the contract:
- a restore recovers identity and configuration and **no authority**;
- one durable generation switch (H12);
- the restore epoch and the replay fence (H9, H13);
- attended `state restore --backup <file>`, `state reset` and `state repair` (Q8), replacing
  the skeletons in `crates/heimdall/src/rev7_cmd.rs`;
- `service stop --preview` (H2);
- the doctor finding `executable_moved` (H5);
- the residue kinds (H6);
- H15's Windows write-through.

Each lands with its emitters, every in-tree reader and its goldens (ADR-0013 §1.3).

### 2.2 Write scope (the handoff)

- `crates/stategen/**`. Its code moves into the store and runtime, or is depended on from
  there.
- The store and runtime code H12 and H13 need:
  - `crates/store/**`: migration 0014 exists; its writers, the fence table, the generation layout,
    the metadata epoch and the backup's environment binding;
  - `crates/runtime/**`: start-up from the pointer, the hello's `restore_epoch`, the server check,
    the instance lock during a restore.
- The state-path readers:
  - the runtime;
  - the read-only opens of `doctor` and the CLI;
  - `uninstall` and `purge` (the residue rows; purging every generation under the lock);
  - the Windows state-directory protection.
- `crates/heimdall/src/rev7_cmd.rs`: the `state *` arms and the `service stop --preview` arm,
  plus new `state_cmd.rs` and the stop-preview code in `service_cmd.rs`.
- The H15 write-through call in the existing Windows platform module.
- `Code::RequestStale` into `Code::all()`, `schema show codes` and `codes.json`, in the change
  that adds its emitter (ASK-CODE). Goldens move with it.
- `crates/localenv/src/projection/`: the moved-block report (`git_block_moved`).
- **H13's readers** (§1): as the orchestrator grants them.

**Not in scope:**
- M07 U3's live corrections (Q1 to Q7, Q11 to Q14);
- U1b's items;
- `support bundle` (U6b);
- H7 (U3).

### 2.3 Slices, each merged on its own with its gate

1. **U2b-1, the layout (H12).**
   - Move stategen's generation switch, pointer, operation record, staging intent and adoption
     order into the store's open path.
   - Today's flat store is adopted (intent, fence, copy, pointer, completion). Schema 14 counts
     as flat, per the ruling.
   - Start-up trusts only the pointer and never picks another generation.
   - The readers (doctor, the CLI's read-only opens, uninstall, purge) follow the pointer.
   - H15 is in this slice.
   - Tests:
     - `switch_interrupted_before_and_after_each_sync_and_the_rename`;
     - `unreadable_or_dangling_pointer_stops_and_never_picks_another_generation`;
     - `adoption_killed_at_each_step_then_older_build_then_newer_build`;
     - `older_build_on_newer_store_refuses_and_touches_nothing` (two real binaries);
     - `no_store_copy_reads_the_main_file_alone`;
     - `purge_removes_every_generation_under_the_lock`.
2. **U2b-2, the epoch and the fence (H9, H13), one change with its readers.**
   - The ledger and fence table are keyed by `stategen::ledger::key_digest` over the full
     idempotency key (N03).
   - `ServerHello.restore_epoch`.
   - `ClientMessage::Request.request_epoch`, outside every request hash (ASK-H13a).
   - `request-epoch/1` offered.
   - The server check before any write: `restore_epoch_stale`; the fence answers
     `restored_before_completion`.
   - `--request-epoch` on every command with `--request-id`, the envelope's `request_epoch`, and
     the CLI binding the hello's epoch at send.
   - A kept epoch facing a runtime that does not offer the capability refuses
     (`SCHEMA_UNSUPPORTED`).
   - `Code::RequestStale` with its emitter.
   - The readers: TUI, wrapper, H1, H2.
   - The damaged-ledger refusal (ruled 2026-11-23) carries over from stategen.
   - Tests:
     - `ledger_append_precedes_the_first_store_write`;
     - `stale_epoch_is_refused_before_any_write` (every mutating kind, through the CLI, the TUI's
       requests and the wrapper);
     - `clients_carry_the_epoch_with_a_kept_request_id`;
     - `equal_request_ids_across_clients_roles_and_kinds_have_separate_fences`;
     - `fence_retention_follows_the_idempotency_contract`.
3. **U2b-3, restore, reset and repair (H3, Q8, H4, H10).**
   - Identity binding (`backup_environment_id`).
   - Exclusion under the instance lock (refused while a runtime or issuer runs).
   - Staging and sanitization; activation by the one pointer switch.
   - The carry-forward of the more restrictive state and of later terminal records.
   - What a restore keeps, ends, quarantines and voids (ADR-0014 §3.6's table; the reasons
     `state_restored_authority_ended`, `client_quarantined_after_restore`,
     `invitation_void_after_restore`, `exposure_disabled_after_restore`).
   - `EventType::StateRestored` with `StateRestoredPayload`.
   - `state repair`: attended only. Carry the decodable records forward as fences, raise the
     epoch, truncate at the first damaged record, report the count and the residual.
   - Reset is the same switch, and discloses when no inventory is readable.
   - `STATE_UNAVAILABLE` (`ledger_damaged`, `state_corrupt`, `next.action` `owner_decision`) and
     `state_newer_than_build` (`change_client`).
   - Tests: the restore fault set of m08-plan U2b, each a focused case:
     - `restore_keeps_a_later_revoked_grant_ended`;
     - `restore_quarantines_a_later_revoked_management_client`;
     - `restore_voids_consumed_and_expired_invitations`;
     - `request_completed_after_the_backup_is_never_run_again` (both variants);
     - `old_decision_reference_is_refused_after_restore_and_reauthorization`;
     - `no_duplicate_effect_when_store_and_ledger_are_both_lost`;
     - `runner_effect_applied_after_the_backup_is_adopted_not_resent`;
     - `restore_keeps_a_retired_issuer_retired_and_an_unpaired_environment_unpaired`;
     - `restore_disables_exposure_and_closes_pending_widening_decisions`;
     - `restore_refuses_another_environments_backup_and_changes_nothing`;
     - `restore_is_refused_while_a_runtime_or_issuer_runs`.

     Plus:
     - `reset_is_attended_and_says_it_creates_a_new_identity`;
     - `reset_without_any_readable_inventory_says_so_and_refuses_non_interactive`;
     - `reset_then_restart_serves_the_new_generation`;
     - `restore_restore_reset_keeps_every_earlier_generation`;
     - `corrupt_store_stops_unsafe_operations_and_offers_recovery`;
     - `migration_ladder_keeps_identity_and_authority` (over U0's replay corpus).
4. **U2b-4, the rest.**
   - `service stop --preview` (H2): read-only, and `stop_preview_lists_what_stopping_interrupts`.
   - `executable_moved` (H5): `moved_executable_is_a_doctor_finding_and_never_a_silent_break`.
   - The residue kinds and uninstall's list (H6):
     `uninstall_lists_backups_earlier_generations_previous_binary_and_remote_pairings`.
   - `rollback_reports_a_moved_git_block`.
   - The remainder of D14's help rewrite.

### 2.4 Rules the implementer follows

- **Every backup, adoption copy, staging copy and carry-forward read goes through SQLite.** None
  copies the main database file alone (ruling of 2026-11-22).
- **Every new authority path fails closed.** The skeletons keep answering "not available in this
  build" until their slice lands (ASK-H3).
- **Fixtures only:**
  - disposable stores and keys;
  - every hand-run `heimdall` with scratch `HEIMDALL_HOME`, `HOME` and `HEIMDALL_TEST_SSH_HOME`,
    and the scratch secret, management and transport stores;
  - release binaries only in containers.
- **Native:** the switch's fault set and the restore fault set run natively on macOS, the devbox
  and Windows at each slice's merge candidate. The rename and sync calls differ, and Windows has
  no directory sync. Power loss is not tested anywhere, and the record says so.
- **Evidence:** a revert proof for each merge-blocking fix (ADR-0009). `check.sh` once per
  commit, through heavy-gate.

### 2.5 Review

- One independent review for the wave. It checks the restore protocol line by line against
  ADR-0014 §3.6 (m08-plan §0a's last row), with the fault sets run natively.
  - **Stated limit:** no other model family is available now (the others are throttled or at
    their usage limit). The reviewer is a fresh Claude Opus with no prior context, the same
    family as the implementer.
- One scoped re-check.

## 2b. Follow-ups carried in W3

- **F-LOCKFLAKE:** the M03 lock-harness self-test's timeouts of about 1 s under load
  (`tests/native/m03/selftest.sh`, `lock_harness_records_unverified_lock_as_blocked`).
  Test-only. Assigned by the orchestrator.
- **F-PORTFLAKE** (added 2026-11-24, with U3c): in `integration_testkit_m03`,
  `faults_each_produce_the_intended_transport_failure`'s `ClosePortBetweenAttempts` case got
  `Connection reset` instead of `Connection refused` under load in M07's gate. It passed 5/5
  alone. **Fixed with U3c:** a connect that lands in the backlog of the listener being closed is
  reset, not refused, and both mean "port closed", so the test accepts both for this fault
  only. The other faults' expectations are unchanged.

- **U2b-1's Windows run (PC job 63, at `a9b038a7`):** every step passed except four
  `uninstall_cmd::tests` tests. They failed with `state_dir_unsafe`: their `state_dir()` helper
  made the state directory with a plain `create_dir`, which on Windows inherits TEMP's ACL, and
  that PC's TEMP grants a local group read access. The runtime's start check refuses that,
  correctly. **Test-only fix** (with U1b's integration): on Windows the helper builds the
  directories with `Paths::ensure`, so the state directory gets its protected owner-only DACL.
  The `purge_sweep` test helpers that make state directories start no runtime, so they are
  unaffected. Windows proof: `uninstall_cmd::tests` rerun with the default TEMP, at the merge
  candidate.
  - **H15 (corrected with the W3 review fixes, W3-R03):** H15 exercised on the normal path in
    job 63; under a fault by
    `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation`
    (`heimdall-runtime`'s unit tests), in the fix-diff PC run (pending). The switch set in
    `adversarial_store_generations` runs over `RealFs`, not the production `PlatformFs`.

- **The W3 review's residuals W3-R04 and W3-R05** are recorded in `docs/user/limitations.md`.
  R04 is `purge_layout_removal_interrupted_leaves_state_corrupt` (`purge_sweep.rs`), and a
  second `uninstall --purge-state` refuses too. R05 is an interrupted first install followed
  by a pre-release build's flat store (`refused: WrongState`). Their recoveries are U2b-3a's.

- **M07's page-token key (2026-11-25; M07 W10 U3-1/D2, `pages/1`; landed in M07's `bbe92261`
  on `m07/w10`):** 32 random bytes in the store's `meta` table, named **`page_token_hmac_key`**,
  classified in `META_RECOVERY` as **never in the snapshot** (corrected by the orchestrator,
  replacing the earlier "travels in a backup" note). M07's U3-1a also has two granted lines in
  the brokered `tui/worker.rs` (`select: None, page: None` in its two `InspectRequest`
  literals), outside the request-ID and epoch path; U2b-2 builds on them or rebases over them.
  - **U6b:** the support bundle excludes that `meta` entry, and its leak test proves it.
  - **U2b-3/U2b-4:** nothing carries the key and nothing rotates it on purpose. It does not
    travel in a backup; a restore or `state reset` yields a new key, which only invalidates
    outstanding page tokens (tokens also bind `restore_epoch`). Snapshot and restore code
    never copy it in either direction, and its `META_RECOVERY` class stays as M07 set it.

- **U2b-2's rulings (orchestrator, 2026-11-25, on `3cfcfdfc`):**
  - **Before U2b-2 merges to main (follow-ups A and B):**
    - **A:**
      - The role checks and the uninstall-fence admission run before the request ledger's
        append, so a refused frame leaves no entry. This is tested, with a revert proof.
      - `request-epoch/1` is offered to `REQUESTER` as well as the owner.
    - **B:**
      - The epoch appears beside the request ID in `environment invite`'s pending message and
        in `run`'s minted ID.
      - `request-epoch/1` is in `inspect capabilities`.
      - The `parse_args` error is formatted.
  - **To U2b-3:**
    - **Soak precondition: the ledger is bounded.** The append is deduped by the key's digest,
      and the trim is wired. A bound test covers an authorized session's flood of distinct
      keys: the ledger stays bounded, and an append's cost does not grow with history beyond
      the bound. **The soak does not start until this test passes.**
    - **Stale decision references:** a decision reference with an epoch older than the
      current one answers `DECISION_STALE` / `restore_epoch_stale`, whether or not the decision
      is recorded, and never `NOT_FOUND` (§3.6 step 2).
    - **Terminal records before restore lands:** the M06 request-ID kinds get terminal records
      before restore lands. Those kinds are `environment invite`, the runner-local trust,
      designate, enroll and policy-recheck, `route add`/`prefer`, and `transport enable`/`adopt`
      (the M06 files are granted).
      - Until then, a raise fences them fail-closed: a retry gets `REQUEST_STALE`, and nothing
        runs twice.
      - With this, `environment invite`'s management session offers `request-epoch/1` when the
        runner does.
    - **`access release`:** `--request-id` and `--request-epoch` (U0-Q7(a), ASK-FLAGS), with
      its check.
    - **`run --parent-binding`** prints the request ID it mints without the epoch
      (`delegate_cmd.rs`, granted to U2b-3).
      - **This is a known gap in U2b-2 until then.** A retry after a restore that carries no
        epoch is bound at receipt. The window is narrow, but it is real.
    - **Checks that still run after the request fence** (ruling of 2026-11-25 on `065f3a45`):
      - The attended-only rule for an unattended local owner's widening `runner_local` forms
        (`trust_issuer`, `designate_time_source`, `policy_recheck`) moves into one dispatcher
        check before the fence.
      - The application's own refusals inside `ops.*` keep their ledger entry, because the
        idempotency contract records the ID. The dedupe and the trim bound them.
  - **Follow-ups A and B landed** (`94fb545e`, merged as `065f3a45`, gate green):
    - `PairedRunner::frame` is split into the check and the runner's answer. The orchestrator,
      as M06's owner after its exit, ratified the split.
    - Ordering is confirmed: authorization comes first, so a frame refused for its role gets
      the role refusal, stamped with its frame epoch, even when that epoch is stale.
    - ADR-0006 §18.1 row 4, §18.2 reading 5 and §19.3 now give the requester set as including
      `request-epoch/1`.
  - **M07's owner review of the readers (`ee022654..3cfcfdfc`): accepted, with nothing
    blocking.** One non-blocking nit, for a later change: the TUI's `kept_epochs` gains one
    entry per request the owner starts and is never pruned. Human actions in a single TUI
    session bound it, so it is acceptable for 1.0. A later change can drop an entry once its
    operation is terminal.
  - **To M07, after U2b-2 is on main:**
    - `docs/api/local-protocol.md`, the skill ("keep the pair") and the wrapper's README.
    - The missing `routes/1` in `inspect capabilities`.

- **GRANT-LIVE (orchestrator, 2026-11-25; found by M07 in U3-2 S2). A store unit, after U2b-3,
  landing before the soak.**
  - **The problem:** `Txn::grants_due` (`crates/store/src/lib.rs`) selects every grant whose
    `deadline_effective <= ?1` and drops the terminal ones in Rust. Nothing deletes ended
    grants. At least 11 product callers pass `Timestamp::MAX`: environments, operations (4),
    container_m04, enrollment_m03, lock, managed_driver_m03 (2) and narrowing (2). So each lock
    event, narrowing pass and enrollment parses every grant ever issued.
  - **Store:**
    - an indexed live-state column on `grants`, or an equivalent the store prefers, in a
      migration after U2b's;
    - adoption across the generations layout;
    - a live-grant accessor;
    - `grants_due(now)` bounded the same way.
  - **Callers:** each caller that needs only live grants moves to the accessor. Diffs in
    M07-owned files go to M07 through the orchestrator.
  - **Tests:**
    - a store with a large terminal history reads only the live rows;
    - the deadline path reads only rows that are due and live.
  - **Soak precondition:** a grant-history-growth workload shows per-operation latency and store
    reads staying flat as the history grows. **The soak does not start until it does.**
  - **Out of scope: pruning terminal grants (retention).** If it is needed for 1.0, it comes
    with ADR-0005 §3.5's residual-counting reading: reserved or published entries stay counted.
  - **Follow-on:** M07's later merged-keyset page unit for `grants`/`bindings` builds on this
    column and index, after U3-3, and adds no migration of its own.

## 3. Order of the first days

1. U3c, by the integrator, merged first (small, and it frees the release graph).
2. U2b-1 and U1b start in parallel, in separate worktrees. U2b-1 merges after its native
   runs.
3. U2b-2 follows, with H13's readers as the orchestrator grants.
4. U2b-3, U2b-4 and U6b follow.
5. The F1 issuer fix's rerun of the probe's fresh-install case (`ss6`) runs when that fix lands
   on `main`.
