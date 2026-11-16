# M05 plan: trusted work, quiet and concurrent

**Status:** proposed, draft 1 (task M05-T00-design).
**Design ADR:** ADR-0011, proposed. Its rulings and the §6 answers close the design gate under
ADR-0009 §2.8: one draft, one independent review, one ruling pass.
**Basis:** `main` at `3e75c2f9` (M03 waves 0–5 merged). **Delivery rules:** ADR-0009.

**Inputs:**
- plan §5 M05 (T01–T06 and the exit evidence), §3 G05, §6.3 and §6.4;
- spec §5, §6.1–§6.3, §6.7, §8.2–§8.3, §8.7, §10.3, §11.3, §12.3, §13.3–§13.5 and §14;
- the nine requirements M05 owns: R-UX-02, R-UX-06, R-AU-02, R-AU-03, R-AU-07, R-EN-07, R-SE-01,
  R-SE-02 and R-SE-03;
- ADR-0006 revision 4, ADR-0007 Q3 and Q5, ADR-0008 D6, D10, Q5 and Q15, and ADR-0005 §3.10.

**Exit evidence:** A02, A04, A05, A16, A18, A28 and A29 pass. "Zero additional same-authority
prompts", "defaults don't redirect running work", "fresh work IDs can't evade a hard cutoff" and "a
repository file can't become an approval instruction" each have a journey (§3).

## 0. Rules

- **Writing:** each unit writes only its owner paths and its own test files.
- **Shared files (the skeleton rule, as in M03):**
  - U0 alone edits the shared hot files: `cli.rs`, `dispatch.rs`, `session.rs`, the `operations.rs`
    dispatch arms and module list, `WorkSpec`, the policy-selection functions, `ports.rs`, `error.rs`,
    the migration, `ext_m05.rs` and every `Cargo.toml` `[[test]]` list.
  - U0 routes each new path into a function in a unit-owned file. Until a unit replaces that body, it
    fails closed:
    - new actions and requests answer `CAPABILITY_UNAVAILABLE` with reason `driver_unavailable`,
      before any record is written;
    - new decision kinds are refused, not consumed;
    - the CLI gives its "not available in this build" envelope;
    - `trusted-work/1` is declared but not offered.
  - No `todo!()` is reachable from a request, the CLI, recovery or a supervisor pass.
- **Tests (ADR-0009 §2.3):**
  - plan §6.3 invariants are proven by extending the existing proptest suites under `tests/model/`
    (fixed seed, `PROPTEST_RNG_SEED` override), not by many example tests;
  - each exit claim gets one end-to-end journey;
  - new example tests cover only boundaries no existing test covers.
- **Gates:** focused crate tests while iterating. `check.sh`, `linux-xcheck --workspace` and the
  umask-002 targets run once per commit to the branch.
- **Native runs:** Windows and the devbox run at each merge candidate, plus targeted runs for
  platform-specific changes (U4's observer, U5's endpoint hook).
- **Statuses:** every unit stays `implemented_unverified` until U10's records exist.
- **Fixtures:** disposable fixtures only. Git repositories, clones, worktrees, symlinks and
  submodules are created per run in scratch directories (`testkit/src/workspace.rs`). The
  managed-credential rows use the M03 loopback sshd and the CA fixtures. No owner keys, agents or
  real repositories.

## 1. Units

Each unit lists its owner paths, dependencies, tests and acceptance.

### U0: Contract revision 5, migration and skeleton (the integrator, as contract owner)

- **Owns:**
  - `crates/contract/**` (§4) and `schemas/**`;
  - `tests/contracts/**`, including the goldens and `cli-help/*`;
  - type-only edits to `crates/domain/src/{policy,decision,binding,grant,lib}.rs`, and the new
    `domain/src/workspace.rs`;
  - `crates/store/migrations/0007_trusted_work.sql`, `store/src/{migrations.rs, lib.rs REQUIRED_*}`,
    and `store/src/ext_m05.rs` (the accessors written in full: they are mechanical);
  - the shared hot files listed in §0;
  - `crates/project/` skeleton, root `Cargo.toml` member, `tools/validation/crate_graph.py`
    (`project → contract, domain` only; `app → project`);
  - `testkit/src/{lib.rs, workspace.rs}`;
  - ADR-0006 §17.
- **Also, U0b, the G05 spike** (scratch only; record `m05-g05-agent-context.json`). On in-box OpenSSH
  on macOS, the devbox and Windows (9.5p2), record:
  - that an agent's `REQUEST_IDENTITIES` carries no working-directory or repository context;
  - the delay an identities answer can take without failing `ssh` and Git (0.5, 1, 2 and 5 s);
  - when `session-bind@openssh.com` arrives.
  - U5's wait budget is set from this.
  - **Result (joint wave 0, 2026-11-15; scripts `tests/native/m05/u0b/`, results
    `tests/evidence/artifacts/m05/u0b/`, record `tests/evidence/m05-g05-agent-context.json`).**
    A delaying proxy in front of a disposable `ssh-agent`, a loopback-only scratch `sshd`,
    real publickey logins, clients run from a canary-named Git working tree:

    | Platform | Client | Identities answer delayed by | Result | Failure point | Budget |
    |---|---|---|---|---|---|
    | macOS arm64 | OpenSSH 10.5p1, Git 2.54.0 | 0, 0.5, 1, 2, 5, 10, 30 s (`LoginGraceTime 120`); 65 s (`LoginGraceTime 0`) | `ssh` and `git ls-remote` succeed every time (observed) | 125 s with `LoginGraceTime 120`: the **server** closed the connection; no client agent timeout up to 65 s | **2 s** (ADR-0011 §3.2 (a)) |
    | Linux devbox (Ubuntu 24.04) | OpenSSH 9.6p1, Git 2.43.0 | as macOS | as macOS (observed) | as macOS | **2 s** |
    | Windows 11 | in-box OpenSSH 9.5p2 | script `windows-agent-wait-spike.ps1` | **blocked:** the owner's PC run | — | undecided: no identities-path call on Windows until the run (ADR-0011 §10 item 4) |

    - **No directory context:** across 52 agent messages per platform (`session-bind`,
      `REQUEST_IDENTITIES`, `SIGN_REQUEST` only), none carried the working directory, the
      repository name or the canary (observed).
    - **`session-bind@openssh.com` arrives first** on every connection, before
      `REQUEST_IDENTITIES` (observed): a later per-destination narrowing can key on it.
    - **Not determined:** whether a client agent timeout exists above 65 s (the server's
      grace ended the 125 s runs first). The 2 s budget is far inside every observed bound.
- **Depends:** the ADR-0011 ruling.
- **Tests:**
  - contract goldens: the code table unchanged at 30, the new `m05-reasons.golden.json`, the
    journaled kinds, and one example per new request and result;
  - schema export, including the new `schemas/project/{manifest,portable}.schema.json`;
  - the 0006→0007 migration on a v6 fixture database, keeping every row, with `verify_schema`
    passing;
  - `ext_m05` CAS and generation tests;
  - one fail-closed acceptance test per new path.
- **Acceptance:** `check.sh` 0. Every new `[[test]]` target holds at least its fail-closed test, so
  none runs zero tests.

### U1: `heimdall-project`, the pure crate (ADR-0011 §2.2–§2.4)

- **Owns:** `crates/project/**`, `tests/model/project_pure.rs`, `tests/adversarial/manifest.rs`.
- **Depends:** U0.
- **Builds:**
  - the bounded manifest parser with its closed schema and authority-key rejection;
  - `access_digest`;
  - discovery over an `FsView` trait;
  - `match_workspace(observation, records) → Trusted(id) | Member(id) | Untrusted | Ambiguous{why}`;
  - the portable bundle (v1): emit, parse, and authority-section rejection.
- **Tests (proptest):**
  - the parser is total and bounded on arbitrary bytes;
  - authority keys are rejected at any depth, case or quoting;
  - the digest is invariant under label, `[metadata]`, comment, order and whitespace edits, and
    sensitive to every policy field;
  - the match table holds for every ADR-0011 §2.3 event;
  - **P11:** a match requires either an equal path and equal identity, or a verified worktree
    back-link to the recorded common directory;
  - the bundle round-trips, and authority sections are refused.
- **Adversarial:** NUL, non-UTF-8, duplicate keys, depth and size limits, `profile = "../x"`, and
  shell metacharacters in values.

### U2: Trust, standing policies and scope review (the authority core; ADR-0011 §2.1, §3.1, §3.4, §4)

- **Owns:**
  - `crates/app/src/operations/{trust_m05,review_m05}.rs`;
  - the bodies of the U0-stubbed policy-selection functions;
  - the logic in `domain/src/{policy,decision}.rs`;
  - `tests/model/trust_policy.rs`, `tests/model/decision_budget.rs`.
- **Depends:** U0, U1 (types).
- **Builds:**
  - `PolicyAction::{Create, ExtendScope, NarrowScope, SetMaxWindow, Remove, TrustWorkspace,
    ReconcileWorkspace}`, with targets;
  - widening goes through a decision; narrowing is immediate, through the existing narrowing protocol;
  - an applied decision is one transaction: the workspace record, the policy, the environment's
    `automatic_activation`, the lock-disclosure acknowledgement, the `policy_history` row and the
    generation;
  - policy selection for workspace and personal contexts, with fail-closed merged blocks;
  - delta routing: a manifest delta in a trusted workspace becomes `WidenPolicy{ExtendScope}`;
    anything else stays `ApproveAuthority`;
  - the coalescing key, the cooldown, and `covered_only` subset resolution;
  - `inspect workspace` and `inspect policies` (with history).
- **Tests (model):**
  - **P9:** in random traces over every request kind, including hostile manifests, imports and
    unattended `decide`, no policy, workspace record or environment permission widens without an
    applied attended decision. Narrowing applies immediately.
  - The `tests/model/authority.rs` generators gain personal and workspace policies:
    - scope stays within every bound;
    - a personal pause blocks workspace work;
    - a workspace pause leaves personal work alone.
  - **P10:** with N concurrent equivalent requests, manifest flips and deny, approve or expire:
    - at most one pending record per (policy, revision, delta);
    - none during a cooldown, and none from `covered_only`;
    - a broader delta never joins a narrower one;
    - an approval widens exactly the recorded delta.
- **Acceptance:** every existing `tests/model` suite passes unchanged, so M01–M03 semantics don't
  drift.

### U3: Stop, targets and precedence (ADR-0011 §7)

- **Owns:**
  - `crates/app/src/operations/stop_m05.rs`;
  - the body of the U0 work-stop check inside `activation_refusal`;
  - `tests/model/precedence_m05.rs`, `tests/e2e/m05_stop.rs`.
- **Depends:** U2.
- **Builds:**
  - `Policy{Stop}` by target;
  - pause, resume, cutoff and clear-cutoff by target set: one transaction, and one decision for a
    widening set;
  - `Revoke{target: Work}`, with the work tombstone.
- **Tests:**
  - **Model:** the trace generator of `tombstones_and_cutoffs_are_never_defeated_by_stale_callbacks_or_new_ids`
    is extended with stop (work and policy), targeted pause and cutoff, resume and clear decisions,
    background triggers and restart. The invariants:
    - no activation while paused, stopped or past a cutoff, whatever the request or work ID;
    - no grant past min(window, parent, cutoff);
    - terminal grants and stopped work IDs never reactivate;
    - pins never change;
    - `Resume` never clears a cutoff.
  - **End to end:**
    - `a05_expiry_reentry_and_hard_cutoff`;
    - `a05_stop_profile_revokes_and_blocks_until_resume`;
    - `stop_one_job_leaves_the_other`.

### U4: Context activation and the shell integration (ADR-0011 §2.2–§2.3, §3.2–§3.3)

- **Owns:**
  - `crates/app/src/operations/context_m05.rs`;
  - `crates/runtime/src/workspace_observe.rs`;
  - `crates/heimdall/src/activate_cmd.rs`;
  - the M05 parts of `heimdall/src/{run_cmd,launch_flow}.rs`: the profile-resolution call and the
    group split only (§5);
  - `tests/integration/workspace_observe.rs`, `tests/e2e/m05_context.rs`.
- **Depends:** U1, U2.
- **Builds:**
  - `ensure` with `context`: discovery, then observation, then the match, then the request (manifest
    ∩ the latest profile snapshot, or the trust record's own scope when there is no manifest), then
    `run_work`. The observation covers the canonical root, its `FileIdentity`, a no-follow bounded read
    of the manifest from the opened handle, and the worktree back-link.
  - `run` without `--profile` (the context, else the default profile);
  - the mechanism-group split (`next.groups`);
  - `heimdall activate --hook` (`covered_only`, holder = the shell, work ID `shell:<pid>.<start>.<n>`);
  - `heimdall shell init zsh|bash` (a static script).
- **Tests:**
  - observer integration:
    - a symlinked root is canonicalized;
    - a symlinked, FIFO or device manifest is refused;
    - a manifest swapped between observation and read is caught: the hashed bytes are the parsed
      bytes;
    - `FileIdentity` works on all three OSes.
  - end to end:
    - `a02_trusted_week_zero_same_authority_prompts`;
    - `a04_edits_branches_and_added_destination`;
    - `a18_copy_clone_worktree_symlink_move_submodule`.
  - the hook script golden, and `hook_never_evaluates_repository_text`: labels and values holding
    `$(…)`, backticks or newlines leave a canary file absent.
- **Acceptance:** in A02, after first trust, decision records = 0, attended prompts = 0 and provider
  prompts = 0. All three are counted from the store and the event stream.

### U5: Personal default and ordinary-`ssh` activation (ADR-0011 §3.1–§3.3)

- **Owns:**
  - `crates/app/src/operations/default_activation_m05.rs`;
  - `crates/runtime/src/default_activation.rs`;
  - the personal-default offer in `heimdall/src/setup_cmd.rs`;
  - `tests/e2e/m05_default.rs`;
  - the single hook call in `crates/credential/src/endpoints.rs`, a shared file (§5).
- **Depends:** U2, U3, U6, and U0b's budget.
- **Builds:**
  - the setup offer (a `Create{default}` decision with the spec §5.2 disclosure);
  - `DefaultActivation`: covered-only, single-flight per environment, bounded wait;
  - `activation_blocked` events, rate-limited.
- **Tests (end to end, managed fixture):**
  - `ordinary_ssh_activates_default_under_personal_policy`;
  - `ordinary_ssh_after_expiry_starts_new_work`;
  - `paused_or_cut_off_default_never_activates_and_creates_no_decision`;
  - `concurrent_ssh_single_activation`.
- **Acceptance:** where U0b finds a client timeout below the budget, that platform's claim is
  "activation through `run`, `ensure` or the shell integration", and the record says so.

### U6: Bindings and shared resources (ADR-0011 §5)

- **Owns:**
  - `crates/domain/src/managed.rs` (slot transitions);
  - `crates/app/src/operations/slots_m05.rs`;
  - the handover step in `crates/app/src/managed/driver.rs`;
  - `crates/runtime/src/slot_handover.rs`;
  - the default-profile preference in `crates/app/src/catalog.rs`;
  - `tests/model/slot_accounting.rs`, `tests/e2e/m05_concurrency.rs`.
- **Depends:** U0.
- **Builds:**
  - slot references: a compatible bind joins (`slot_shared`); an incompatible one is still refused
    with `managed_slot_held`;
  - handover to the referencer with the latest deadline, under a new generation;
  - the context pin on bindings, and the policy ID in the grant origin.
- **Tests:**
  - **Model** (extends plan §6.3 properties 6 and 8). In random traces of bind, join, release,
    expire, revoke, cutoff and restart:
    - a materialized slot has an active, referencing materializer;
    - the slot's `valid_before` ≤ the materializer's deadline;
    - no slot outlives its last referencer;
    - cleanup of generation N never removes N+1;
    - a join never changes any pin.
  - **End to end:**
    - `a16_concurrent_environments_defaults_and_cleanup`, parametrized over environment
      realizations (§3, Q9), with the TUI worker harness changing defaults mid-run;
    - `a04_default_and_profile_change_never_redirects_bindings`.
- **Acceptance:** the M03 slot tests pass, with `managed_slot_held` now narrowed to incompatible
  holders. U0 updates that golden.

### U7: Export and import of portable intent (ADR-0011 §2.4 I4)

- **Owns:** `crates/app/src/operations/portable_m05.rs`, `crates/heimdall/src/portable_cmd.rs`,
  `tests/integration/portable.rs`, `tests/e2e/m05_portable.rs`.
- **Depends:** U1.
- **Builds:**
  - `inspect export`, with redaction and a preview;
  - `catalog apply_import`: one journaled operation applying a plan of add, unchanged and conflict
    entries;
  - the list of local items to re-establish.
- **Tests:**
  - `a18_export_has_no_authority_or_secrets`: a scan for canaries, private material, policy,
    workspace and grant IDs, and, when redacted, socket and home paths;
  - `a18_import_on_second_installation_creates_intent_only`: the authority tables and known-hosts
    files are unchanged, and an `ensure` in the imported profile needs a decision;
  - `import_rejects_authority_sections`;
  - re-import is idempotent.

### U8: Delegation and the narrower binding (ADR-0011 §6; A28)

- **Owns:**
  - `crates/heimdall/src/delegate_cmd.rs` (`run --parent-binding`);
  - the delegation path of `crates/app/src/operations/narrowing.rs` and the child enforcement labels;
  - `tests/e2e/m05_delegation.rs`.
- **Depends:** U0 (the M03 child keys).
- **Tests (end to end, on the `ca1`/`ca2` and two-`LoopbackSshd` fixtures):**
  - `a28_child_subset_server_enforced`: the child's certificate is refused by a second host that
    trusts the same CA under a different principal mapping;
  - `a28_broader_or_longer_child_refused`;
  - `a28_child_handle_has_no_owner_functions`: the child endpoint refuses control and issuance frames,
    and a child binding ID gives nothing for `decide`, a policy change or a wider `delegate`;
  - `a28_parent_end_cascades_child_login_fails`, by revoke, by expiry and by cutoff;
  - `a28_existing_access_child_labelled_convenience`.
- **M04 rows (Q9):** forwarding (M04-T06) and the container recipe (M04-T05, `owner_functions:
  unreachable`).

### U9: TUI and CLI surfaces

- **Owns:**
  - `crates/heimdall/src/{m05_cmd.rs, tui/m05.rs}` and the M05 parts of `tui/{model,view,worker}.rs`;
  - the M05 help goldens and TUI snapshots.
- **Depends:** U2–U4, U7.
- **Builds:**
  - workspace status;
  - the first-trust view: the spec §5.2 text, with a detail view of pairs, environments, lock
    continuity and limits;
  - the delta review, showing only the added authority;
  - the stop menu: pause, stop this work, stop all for a profile, cutoff at a time;
  - policy history;
  - `project trust|status|untrust|reconcile`, `access allow|stop`, and targets on
    `pause|resume|cutoff`.
- **Tests:**
  - snapshots: `delta_review_shows_only_added_authority`,
    `first_trust_detail_lists_scope_environments_and_limits`, `stop_menu_distinguishes_four_actions`
    and `project_label_rendered_as_quoted_data`;
  - help goldens.

### U10: Hostile input, exit suite and evidence

- **Owns:** `tests/adversarial/prompt_injection.rs`, `tests/native/m05/**`, `tests/evidence/m05-*.json`,
  `docs/architecture/m05-exit.md`, and the M05 rows of the claims table and the matrix.
- **Depends:** every other unit.
- **Builds:**
  - **A29:** a prompt-injected agent fixture.
    - A non-interactive `decide` gets `INTERACTION_REQUIRED`.
    - Decision references taken from repository text get `NOT_FOUND` or `DECISION_STALE`.
    - Approval claims in labels, work IDs or agent names have no effect.
    - An untrusted repository whose `.heimdall.toml` has `trusted = true`, `[policy]`, `hook =` or
      `background_work = true` gets no unattended access and no applied decision.
    - The M01/M03 A29-local rows are reused by reference: cross-owner idempotency, signing/control
      confusion and oversized IPC.
  - **Evidence:** the case index, the native runs at the merge candidate (macOS arm64, devbox, Windows
    11, and the disposable WSL distribution for the shell hook), the records and the exit record.

## 2. Waves

```text
W0  U0 contract rev 5 + migration + skeleton;  U0b G05 spike
W1  U1 project crate │ U2 authority core │ U6 shared resources │ U8 delegation   (disjoint files)
W2  U3 stop/precedence (U2) │ U4 context + shell (U1, U2) │ U7 export/import (U1)
W3  U5 personal default + ssh activation (U2, U3, U6, U0b) │ U9 TUI/CLI (U2–U4, U7)
W4  U10 hostile input, exit suite, native runs, records
```

- **W0** lands ADR-0006 revision 5 whole: types, reasons, the migration, the fail-closed skeleton, the
  new crate and its graph rule. This is the only wave that edits the shared hot files, which is why
  later waves rarely conflict, with M04 or with each other. U0b runs alongside on scratch fixtures
  and fixes U5's wait budget, or withdraws the ordinary-`ssh` claim on a platform before anyone
  builds it.
- **W1** builds four independent pieces, each in its own files:
  - the pure manifest and identity crate;
  - the authority core (trust records, policy actions, delta routing, cooldown), which carries the
    P9 and P10 model tests;
  - slot reference accounting, which carries the slot model test;
  - the A28 delegation evidence, which needs only M03's child keys.
  - It gets the wave's security review, because it touches authority (plan §6.7).
- **W2** turns those pieces into behaviour:
  - stop and targeted precedence, with the extended A05 trace model;
  - context activation, the observer and the shell integration, with the A02, A04 and A18 identity
    journeys;
  - export and import.
  - The observer and import parse untrusted input, so W2 gets the security review.
  - Windows and the devbox run the observer and the hook natively.
- **W3** adds the two surfaces that need everything below them:
  - ordinary-`ssh` activation for the personal default, which needs the one shared hook call in
    `credential/src/endpoints.rs` (§5);
  - the TUI and CLI views.
- **W4** produces the A29 suite and the exit evidence. Native runs happen at the merge candidate.

**Reviews:** this plan and ADR-0011 get one independent review before W0. Then each wave gets one
review and one scoped re-check (ADR-0009 §2.1).

## 3. Exit mapping

Records live in `tests/evidence/m05-*.json` and follow the lowest-row rule. "All" means macOS arm64,
the Linux devbox and Windows 11.

| Claim or case | Proven by | Record | Platforms |
|---|---|---|---|
| **A02** and "zero additional same-authority prompts" (R-UX-02) | U4 `a02_trusted_week_zero_same_authority_prompts`: trust once, re-enter, open three shells through the hook, run Git, ssh and scp, re-issue within a grant, kill and recover the endpoint helper, expire and re-enter; decisions, attended prompts and provider prompts all count 0. U5's default rows. U2 P10 | `m05-a02-trusted-week.json` | All. Windows uses `run` and ordinary `ssh`, with no shell hook (Q6). **Blocked rows:** the step comparison with the G01 baseline worksheet (B7, ADR-0001 §6); a reboot inside the window (B12, M04-T04) |
| **A04** (R-UX-06, R-AU-03) | U4 `a04_edits_branches_and_added_destination` (edits and branch switches: 0 decisions; an added destination: 1 decision showing only that pair; two live bindings unchanged). U6 `a04_default_and_profile_change_never_redirects_bindings`. U2 P10 | `m05-a04-access-changes.json` | All |
| **A05**, "fresh work IDs can't evade a hard cutoff" (R-AU-02) | U3 `a05_expiry_reentry_and_hard_cutoff` (expire; the same work ID is refused; distinct work proceeds with no decision; after the cutoff, fresh work IDs, a restarted runtime, the hook and default activation are all refused; clearing needs an attended decision). U3's precedence model. The M01 A05 model rows | `m05-a05-expiry-cutoff.json` | All |
| **A16**, "defaults don't redirect running work" (R-AU-03) | U6 `a16_concurrent_environments_defaults_and_cleanup`. U6 slot model. U3 `stop_one_job_leaves_the_other` | `m05-a16-concurrent.json` | All, with two native environments in scratch homes (labelled "two environments, one OS user"). The WSL and container pairs follow Q9 |
| **A18** (R-EN-07) | U4 `a18_copy_clone_worktree_symlink_move_submodule`. U7 `a18_export_has_no_authority_or_secrets` and `a18_import_on_second_installation_creates_intent_only`. U1 P11 | `m05-a18-portable-trust.json` | All |
| **A28** (R-AU-07, R-SE-03) | U8's five journeys | `m05-a28-delegation.json` | All, for the managed rows. Forwarding and container rows follow Q9 |
| **A29**, "a repository file can't become an approval instruction" (R-SE-01, R-SE-02) | U10 `prompt_injection.rs`. U1 adversarial manifests. U2 P9. U4 `hook_never_evaluates_repository_text`. U9 `project_label_rendered_as_quoted_data`. M01/M03 A29-local rows by reference | `m05-a29-hostile-input.json` | All. Cross-user rows stay blocked (B2) |
| G05 agent context | U0b | `m05-g05-agent-context.json` | All |
| All of the above | `tests/native/m05/case-index.json` | `m05-exit-claims.json` | — |

**The exit rule** is the one M01 and M03 used: every record is `verified`, except rows blocked only on
named owner inputs, which stay `blocked` with `blocked_on`. No claim is widened to cover them.

## 4. Contract deltas: ADR-0006 revision 5

All are additive (`serde(default)`, omitted when empty). Schema major stays `"1"`. The code table
stays at 30 rows.

1. **`EnsureRequest`:**
   - new `context: Option<WorkContext>` (`{cwd}`: absolute, at most 4 KiB, metadata only);
   - new `covered_only: bool`;
   - `profile` becomes optional when `context` is present;
   - the hash `extra` includes the resolved workspace ID and the access digest.
2. **`PolicyAction`:**
   - new variants `Create{profile, environments, max_window, default}` (widening), `ExtendScope`
     (widening), `NarrowScope`, `SetMaxWindow` (widening when longer), `Remove`, `TrustWorkspace{cwd,
     access_digest, proposal}` (widening), `ReconcileWorkspace{workspace, cwd}` (widening) and `Stop`
     (narrowing);
   - `Pause`, `Resume`, `Cutoff` and `ClearCutoff` accept `target: PolicyTarget` (`policy | profile |
     workspace | all`) as an alternative to `policy`, with exactly one of the two present.
3. **`RevokeRequest`:** new `target: RevokeTarget` (`grant` by default, or `work{environment,
   work_id}`).
4. **`CatalogRequest::ApplyImport{bundle}`:** journaled under kind `catalog`, owner only, no decision.
5. **`InspectSubject`:** new `Workspace{cwd}`, `Policies` (with history) and `Export{redact}`.
6. **Decision kinds:** new `TrustWorkspace` and `ReconcileWorkspace`. `WidenPolicy` carries the new
   widening actions.
7. **Results:**
   - the ensure data gains `context{kind: workspace|personal|delegation|explicit, workspace_id?,
     policy_id, policy_revision, provenance: same_user_context}` and `uncovered` (the `covered_only`
     remainder);
   - bindings gain `context`;
   - grant origins gain `policy_id`;
   - enforcement reports gain `ordinary_aliases` and `owner_functions`;
   - new result types for `inspect workspace` and `inspect policies`.
8. **Events:** new `EventType::Activation` (`activated | blocked | not_covered`).
9. **Reasons** (`reason::M05`, plus a golden):

   | Reason | Code |
   |---|---|
   | `workspace_untrusted`, `workspace_ambiguous` | APPROVAL_REQUIRED or INTERACTION_REQUIRED, with a decision reference |
   | `workspace_identity_unavailable` | CAPABILITY_UNAVAILABLE |
   | `manifest_invalid`, `manifest_authority_key` | USAGE_ERROR |
   | `manifest_profile_unknown`, `policy_target_empty` | NOT_FOUND |
   | `decision_cooldown` | APPROVAL_REQUIRED or INTERACTION_REQUIRED, with `retry_after` and no new decision reference |
   | `not_covered` | INTERACTION_REQUIRED, with no decision reference |
   | `work_stopped` | CREDENTIAL_EXPIRED |
   | `slot_shared` | a warning |

   `mixed_mechanisms` gains `next.groups`.
10. **Capability:** `trusted-work/1`, declared at W0 and offered once W3 is wired.
11. **Schemas:** `schemas/project/manifest.schema.json` (the manifest) and
    `schemas/project/portable.schema.json` (the bundle). The trust record is exposed through `inspect
    workspace` and `inspect policies`, whose result schemas join `schemas/public-api/`.
12. **Store** (not the contract, but frozen at W0): migration 0007 adds `workspaces`,
    `policy_history`, `decision_cooldowns`, `work_stops`, `slot_references` and
    `bindings.context_json`.

## 5. Crate ownership against M04

| Area | M05 | M04 |
|---|---|---|
| `domain` | `policy`, `decision`, `binding`, `grant`, `workspace` (new), `managed` (slots) | `environment`, `enrollment` (routes), `time`, `procstat` |
| `app` | `operations/{trust,review,stop,context,default_activation,slots,portable}_m05.rs`, `operations/narrowing.rs` (delegation), `managed/driver.rs` (handover), `catalog.rs` (preference) | `operations/{lock,lock_connection_m03,bind_connection_m03,connections,restart_m03}.rs`, `lock.rs`, `operations/enrollment_m03/*` (routes) |
| `store` | `ext_m05.rs` | `ext_m04.rs` |
| `runtime` | `workspace_observe.rs`, `default_activation.rs`, `slot_handover.rs` (all new) | `platform.rs`, `session_lock/*`, `paths.rs`, `instance.rs`, `launcher.rs`, `connections.rs` |
| new crate | `crates/project/` | — |
| `heimdall` | `activate_cmd.rs`, `delegate_cmd.rs`, `portable_cmd.rs`, `m05_cmd.rs`, `tui/m05.rs`, `setup_cmd.rs` (offer) | `service_cmd.rs`, `uninstall_cmd.rs`, `purge_sweep.rs`, `doctor_cmd.rs`, `tui/term.rs` |
| Entirely M04 | — | `ipc`, `launch`, `localenv`, `sshconf`, `registry`, `enroll`, `issuer/store/*`, `adapters/{detect,native_agent,onepassword}` |

**Files both tracks must change, and the rule for each:**

1. **`crates/contract/**`, `schemas/**`, `tests/contracts/**`:** one contract owner (ADR-0009 §2.6).
   Revision 5 is M05's W0. M04's deltas land as revision 5.1, through the same owner. Each reason
   string is used once.
2. **`crates/store/migrations/`, `migrations.rs`, `lib.rs` `REQUIRED_*`:** the first track to merge
   takes 0007, and the second renumbers at merge (a file rename and the version constant). The two
   tracks' tables and columns are disjoint, so order does not matter.
3. **`crates/heimdall/src/cli.rs` and the `cli-help` goldens:** each track's W0 adds its own
   subcommand enums. The second merger regenerates the goldens.
4. **`crates/runtime/src/{service,supervisor}.rs`:** wiring lines only, each calling a function in a
   track-owned file.
5. **`crates/runtime/src/dispatch.rs`, `crates/ipc/src/session.rs`:** M05 adds no `Request` variant
   (§4 extends existing ones), so only the capability list changes.
6. **`crates/credential/src/endpoints.rs`:** owned by M04, for the WSL and container binding
   endpoints. M05 adds one `DefaultActivation` call in the environment endpoint's identities path
   (U5, W3). Whichever track lands second rebases.
7. **`crates/heimdall/src/{run_cmd,launch_flow}.rs`:** M04 owns the WSL Mode A and Windows launch
   changes. M05 keeps its logic in `activate_cmd.rs` and changes only the profile-resolution call and
   the group split.
8. **Append-only lists:**
   - `app/src/{ports,error,lib}.rs` and the `operations.rs` module list;
   - `testkit/src/lib.rs`, `heimdall/src/testcfg.rs`;
   - root and per-crate `Cargo.toml` `[[test]]` lists;
   - `tools/validation/{check.sh,crate_graph.py,native-harness-selftest.sh}`;
   - `domain/src/claims.rs`;
   - `docs/architecture/overview.md`, `progress.md`.

**Dependencies between the tracks:**

- the A16 WSL and container pairs, and A28's forwarding and container rows, need M04 (Q9);
- the WSL namespace for workspace identity is M04's (ADR-0011 §2.3);
- runtime start at login (M04-T04) makes ordinary-`ssh` activation work after login without a
  command, but M05 does not depend on it.

## 6. Questions for the owner

Each question has a recommendation, and ADR-0011 is written to it.

| # | Question | Recommendation |
|---|---|---|
| Q1 | Linked worktrees, moves and re-clones. | A **verified linked worktree** of a trusted checkout is a member of it, with no prompt (agents create worktrees constantly, and they add no authority). A **move** or **re-clone** needs one `ReconcileWorkspace` decision. Copies and clones never match |
| Q2 | Does approving a manifest's added access remember it? | **Yes, for a trusted workspace's manifest:** `WidenPolicy{ExtendScope}` on that workspace's policy, as a new revision. Explicit ad-hoc requests stay one-off `ApproveAuthority` |
| Q3 | The cooldown after a denial. | **Until the policy's saved window has elapsed (default 12 h)**, keyed by (policy, delta). It is cleared by a revision change, a different delta, or any owner-initiated widening. Expired, unanswered decisions get no cooldown |
| Q4 | Two jobs on the same managed pair in one environment. | **Slot references with handover.** Ordinary aliases are labelled `shared_environment_default`. The alternative keeps `managed_slot_held`, which blocks two agents in one project from sharing a host |
| Q5 | Should an ordinary `ssh` activate the personal default? | **Yes:** covered-only, the `default` personal policy only, a bounded wait set by U0b. A platform where the spike fails falls back to `run`, `ensure` and the shell hook |
| Q6 | The shell family for the one context integration. | **zsh and bash** (macOS, Linux, WSL). PowerShell goes to M07. Native Windows uses `run` and ordinary-`ssh` activation |
| Q7 | Profiles that mix existing-access and managed pairs. | **One binding per mechanism group under one work ID.** A single mixed grant stays deferred (ADR-0008 Q5 re-deferred, with this decision) |
| Q8 | A same-user agent with a terminal can type `yes` at `decision approve` (ADR-0011 R1). | **Record it as a residual.** Also add a ~20-line CLI guard that refuses an attended `decide` inside a `run`-bound process (environment marker), labelled convenience and never claimed |
| Q9 | Who closes the A16 rows (WSL, container) and A28 rows (forwarding, container) that need M04? | **M04's exit.** A13 and A15 already cover those realizations. M05 ships the parametrized tests, and its A16 record uses two native environments, honestly labelled. If you want those rows in M05's own exit, M05's exit waits for M04-T03, T05 and T06 |
| Q10 | Should an untrusted workspace activate under the personal policy when that policy already covers the whole request? | **Yes, with no trust prompt:** it adds no authority beyond environment-level personal access. Trust is needed only for access beyond personal, and for project-level pause and stop |

## 7. Owner inputs and handoffs

**Owner inputs.** No new B-IDs are needed.
- **B7:** the A02 baseline-comparison row. The G01 worksheet (ADR-0001 §6) is blocked on it. The
  human walkthrough is M09's.
- **B12:** a reboot or logout inside the A02 window.
- **B2:** A29's cross-user rows, carried.
- **B9:** the arm64 rows.

**Handed on:**

| Item | Where |
|---|---|
| PowerShell context integration | M07 |
| Per-destination ordinary-`ssh` activation through `session-bind@openssh.com` | later, by its own ADR |
| A single grant with per-pair mechanisms | re-deferred (Q7) |
| OS user-presence approval (Touch ID, Windows Hello, polkit) | later candidate (ADR-0011 R1) |
| Machine-local remapping of manifest references (spec §13.4 "can map") | M07, if needed |
| One workspace identity across Windows and WSL | M04 (WSL Mode A) |
| A30 comprehension, and the normal-week study | M09 |
