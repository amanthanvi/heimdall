# ADR-0011: Trusted work (M05): manifests and trust records, activation, scope review, delegation, stop precedence

**Status:** proposed · **Date:** 2026-11-15 · **Task:** M05 design (draft 1)
**Decided by:** pending. Under ADR-0009 §2.8 this draft gets one independent review and one ruling
pass. The owner questions are in `docs/architecture/m05-plan.md` §6.
**Gate:** G05 (trusted project activation and context provenance), plus the M05 parts of G08 and G09.
**Basis:** `main` at `3e75c2f9`. Spec §4.1–§4.2, §5.2–§5.6, §6.1–§6.3, §6.7, §8.2–§8.3, §8.7,
§10.3, §11.3–§11.4, §12.3, §13.3–§13.5, §14. Plan §3 G05, §5 M05, §6.3. ADR-0006 revision 4 (§13.5–§13.11).
ADR-0007 Q3 and Q5. ADR-0008 D6 item 5, D10, Q5 and Q15. ADR-0005 §3.10.
**Plan:** `docs/architecture/m05-plan.md`. The ADR-0006 revision-5 deltas are listed in its §4.

## 1. Context

M01–M03 already provide most of the authority machinery M05 needs, each piece with tests:

- **Resolution:** the pure resolver (`domain/src/authority.rs`) computes the intersection, the
  narrowest deadline, the delta and the role check.
- **Pause and cutoff:** both block new grants and bindings, including fresh request and work IDs
  (ADR-0006 §13.6 item 1). A cutoff bounds existing grants.
- **Decisions:** a decision is completed only by an attended `Decide`. Equivalent waiters share one
  decision, and a broader request never joins (§13.7–§13.8). A request the policy has come to cover
  resumes without a prompt (`proceed_covered`).
- **Bindings:** each binding pins its environment, profile revision, scope, mechanism and grant.
  Profile snapshots are immutable. Equivalent work is single-flight, with separate references.
- **Delegation:** a child's scope must be a subset of its parent's and end no later (a wider or longer
  request is refused with `DELEGATION_EXCEEDS_PARENT`). The parent's end cascades to the child.
  Managed children get their own key and subset certificates (ADR-0008 D6 item 5).
- **Slots:** one ordinary-alias slot per environment, destination and account, generation-fenced
  (ADR-0008 D10).

M05 adds what does not exist yet:

- **No standing policy is ever created in production.** M02 deferred it to M05-T02 (ADR-0007 Q3).
  `automatic_activation` is never set on a real environment, so today every `ensure` needs a decision.
- **Workspaces:** no workspace identity, manifest or trust record. `StandingPolicy.workspace` exists,
  but it is always `None`.
- **Prompt control:** no cooldown after a denial, and no "stop" that pauses and revokes at once
  (spec §5.6).
- **Shared aliases:** a second binding on a pair is refused (`managed_slot_held`, ADR-0008 Q15).
- **Mixed mechanisms:** a profile that mixes existing-access and managed pairs is refused
  (`mixed_mechanisms`, ADR-0008 Q5).
- **Activation and portability:** no export or import, no activation from an ordinary `ssh`, and no
  A28 server-side attenuation evidence.

This ADR decides the authority semantics of those additions. It changes no M01–M03 semantics, except
where §5.2 narrows the `managed_slot_held` refusal.

## 2. Manifests, trust records, and why import cannot self-authorize

### 2.1 The model

Options:

- **(A) The trust record is a standing policy whose `workspace` is set, plus a local workspace
  identity record.**
- (B) A separate `TrustRecord` object that references a policy.
- (C) Trust carried by the repository, for example as a signed manifest. Spec §5.3 and §13.4 rule
  this out.

**Decision: (A).** A workspace trust record is:

- a `WorkspaceRecord`: the workspace ID, the canonical root path, the root directory's
  `FileIdentity` (`domain::projection::FileIdentity`), the identity of the Git common directory when
  there is one, and the decision that created it;
- a `StandingPolicy` with `workspace: Some(id)`: profile, scope, environments, `max_window`, pause,
  cutoff, lock behaviour, connection policy, revision, and `manifest_basis` (the access digest it was
  approved against).

Both live only in the local state store.

**Reasons:**

- Pause, cutoff, the fail-closed merge, revisions, generations and decision staleness already work
  on standing policies. A second object would duplicate all of them.
- ADR-0006 §13.6 item 5 already anticipates per-workspace policy records.

### 2.2 The manifest

The manifest is `.heimdall.toml` at a workspace root. It is a **request**, never an authorization:

```toml
schema_version = 1
project = "example-infrastructure"         # descriptive label only
[access]
profile = "homelab-dev"                    # a catalog reference, resolved locally
pairs = ["lab-db:deploy"]                  # optional subset of the profile
environments = ["native"]                  # optional, by environment label
required_capabilities = ["ssh-authentication"]
[preferences]
background_work = true                     # a requested lock behaviour, shown at review
[metadata]                                 # the only open table; ignored
```

- **Closed schema.** Any key outside the schema rejects the whole file (`manifest_invalid`), except
  under `[metadata]`.
- **Authority vocabulary.** Key names such as `trust`, `trusted`, `policy`, `approve`, `consent`,
  `hook`, `command`, `exec`, `script`, `key`, `socket`, `issuer`, `enroll`, `unattended`, `cutoff` and
  `until` are rejected with `manifest_authority_key` at any depth, `[metadata]` included. Names are
  matched whole and case-insensitively. The list extends `FORBIDDEN_KEYS` in `runtime/src/config.rs`.
- **Values.** Values are bounded tokens (`[A-Za-z0-9._:-]`, at most 128 bytes) resolved against the
  local catalog. A value is never a path, command, URL or executable.
- **Bounds.** At most 64 KiB, 256 pairs and nesting depth 4. Valid UTF-8, no NUL, no duplicate keys.
- **Reading.** The file is opened without following a symlink on its last component. It must be a
  regular file. It is read once from that handle, and the bytes hashed are the bytes parsed.
- **The access digest** covers the canonical form of the policy-sensitive fields: profile, pairs,
  environments, capabilities and `background_work`. The label, `[metadata]`, comments, key order and
  whitespace do not change it.
- **Who reads it.** The runtime reads the manifest, never the client. The CLI, the shell hook and API
  callers send only the working directory (§3.2), so there is one implementation.

**Discovery.** Walk up from the working directory. The first directory holding `.heimdall.toml` is
the workspace root. A directory holding `.git` but no manifest is a manifest-less workspace root, which
the owner may still trust explicitly, with the trust record supplying the request.

Discovery never crosses a `.git` boundary, so a submodule or nested repository is its own workspace.
It never descends from a parent directory either: trust is not recursive (spec §5.3).

### 2.3 Workspace identity

Identity is a local observation recorded at the owner's decision. The Git remote URL, `.git`
contents and the manifest's `project` label are descriptive only.

| Event | Observation against the record | Result |
|---|---|---|
| Same checkout, or reached through a symlinked path | canonical path and root `FileIdentity` equal | trusted |
| `cp -R` copy, `git clone`, or an import on another device | different path and identity | untrusted (`workspace_untrusted`) |
| Re-clone at the same path, or restore from backup | same path, different identity | ambiguous: one `ReconcileWorkspace` decision |
| `mv` within one filesystem | same identity, different path | ambiguous: one `ReconcileWorkspace` decision |
| Move across filesystems | new identity | untrusted; the old record is listed as stale |
| Linked worktree of a trusted checkout (owner question Q1) | all three hold: the `.git` file's `gitdir` names `<common>/worktrees/<n>`; that entry's `gitdir` file points back to this root; the common directory's identity equals the recorded one | member of the trusted workspace |
| Copied worktree directory | the back-link names the original path | untrusted |
| Submodule, or a nested manifest inside a trusted tree | its own root | a separate workspace |
| Parent directory of a trusted root | discovery never finds the child | personal context |
| Filesystem without a stable identity | no `FileIdentity` | `workspace_identity_unavailable`: trust is refused there |

Each environment identifies workspaces in its own path namespace. Whether a WSL view of a Windows
checkout maps to the Windows record is M04's decision (WSL Mode A path handling).

### 2.4 Invariants (why import cannot self-authorize)

- **I1. One path creates or widens authority.** Standing policies, workspace records, environment
  `automatic_activation` and approval bases are created or widened only when an attended owner
  `Decide` applies a decision. Every other path can only read them or narrow them: manifest reads,
  import, catalog changes, `ensure`, `delegate`, background activation and restart.
- **I2. A manifest's only power is to make a request.** It has no authority vocabulary, and its
  values resolve only against local records.
- **I3. Identity comes from local observation recorded by the owner (§2.3), never from repository
  content.**
- **I4. Export carries portable intent only:**
  - included: catalog destinations, identity references (public fingerprints and provider kind),
    profiles, preferences;
  - redactable on request: host names, addresses and labels;
  - never included: policies, workspace records, environment permissions, grants, decisions,
    enrollments, socket or home paths, private material.
  - Each bundle lists what must be re-established locally.
  - Import is one journaled catalog reconciliation with a preview. It applies catalog intent only. It
    never trusts a host key: exported host-key fingerprints are shown in the preview for comparison,
    then discarded. Adding pairs to a profile never widens a policy (spec §6.2).
- **I5. A decision's action is fixed at creation, from server-side state.** Approval applies exactly
  that action. Repository or request text appears in a decision only as quoted, bounded data with
  control characters stripped, such as the project label. It is never the decision's title or action.

**Rejected:**

- Trusting every clone of a remote URL (spec §5.3).
- A marker file inside the repository or `.git`, which copies with the tree.
- Recursive parent trust.

## 3. Activation and the prompt budget

### 3.1 Policies and selection

- **Personal policy** (`workspace: None`):
  - created by an owner `PolicyAction::Create`, offered during setup with the spec §5.2 disclosure;
  - at most one personal policy per environment is marked `default`;
  - it governs repository-free work, and ordinary `ssh` (§3.2).
- **Workspace policy:** created by `TrustWorkspace` (§2.1).
- **Which policy covers a request:**
  - in a workspace context with a matching workspace policy, that policy alone;
  - otherwise, the personal policy for the profile and environment.
  - An untrusted workspace whose request the personal policy already covers therefore activates
    under the personal policy with no trust decision (owner question Q10). This adds no authority:
    any process in the environment can already use personal access.
  - A trusted workspace is governed by its own policy alone. A later manifest request that only the
    personal policy covers is raised as a delta on the workspace policy (§4.1). This edge is accepted,
    so that each grant rests on exactly one policy.
- **Blocks:** blocks are still merged fail-closed over every applicable policy, personal and
  workspace (ADR-0006 §13.6 item 5).
  - A pause or cutoff on a personal policy stops that profile's project work too.
  - A project pause does not stop personal work.
- **The approving decision** also sets the environment's `automatic_activation`, and records the
  M03 lock disclosure if it has not yet been acknowledged.

### 3.2 Triggers

| Trigger | Context | Policy | May create a decision? |
|---|---|---|---|
| `ensure` with `context.cwd`; `run` without `--profile` | the discovered workspace, else the personal default profile | §3.1 | yes: it is a foreground request |
| Shell integration (`heimdall shell init zsh\|bash`, opt-in; owner question Q6) | the shell's working directory, on directory change and after expiry | §3.1 | **no**: covered subset only |
| Ordinary `ssh` to a managed alias whose slot is free (Q5) | the environment | the personal `default` policy only | **no**: covered subset only |
| `delegate` | the parent binding | the parent's | no: it is refused, never escalated |

**Background activation is covered-or-nothing.**

- **What activates:** the background triggers ask with `covered_only`. They activate requested ∩
  covered, never create a decision record, and report the uncovered part.
- **Prompts:** only a request someone made in the foreground can prompt. A repository therefore
  cannot raise prompts by being entered (`cd`).
- **Unaffected access:** access the policy already covers stays usable while added authority waits
  for review (spec §5.3).

**Ordinary `ssh` activation.** Options:

- **(a) Activate when the environment endpoint is asked for identities.** This is the recommendation.
- (b) Have the supervisor keep the default binding active at all times. This is continuous renewal
  with no use behind it.
- (c) A `Match exec` or `ProxyCommand` hook in the projection. This breaks the M02/M03 rule that the
  projection never renders an executing directive.

**Decision: (a).**

- **The hook:** one call from the environment endpoint, through an `app::ports::DefaultActivation`
  port, with a bounded wait (default 2 s, confirmed by the wave-0 spike in the plan).
- **Single-flight** per environment.
- **When blocked:** it emits at most one `activation_blocked` event per policy and reason per hour.
- **Scope:** the agent protocol carries no destination or directory context (spec §5.4; the spike
  records this), so (a) activates the whole covered scope of the default personal policy. Narrowing
  this per destination through `session-bind@openssh.com` is later work.

**The shell integration:**

- **The hook script is static** and contains only Heimdall's code. It never interpolates repository
  text.
- **What it runs:** `heimdall activate --hook --cwd "$PWD"`, with a 1 s timeout.
- **Bindings:** each shell has its own binding, holder = the shell's PID and start time, released
  when the shell exits (ADR-0007 Q5).
- **Output:** one status line, only when the state changes (untrusted, paused, needs review).

### 3.3 Automatic re-entry

Spec §6.1:

- an expired binding is never extended, and its work ID stays expired (`work_deadline`, M01);
- new work under a standing policy gets a fresh grant.

**The reading:** background triggers start new work at the next use after expiry. The shell gets work
ID `shell:<pid>.<start>.<n+1>`, and the default endpoint gets an internal `default:<env>:<n>`. This is
"automatic reentry" (A05).

**Consequences:**

- The window is a usability bound. The stop is the pause or the cutoff, as spec §6.1 says.
- The first-trust and setup disclosures say so: "access starts again automatically when you next use
  it, within your saved limits; pause or set a stop time to end it."

### 3.4 The prompt budget

| Event | Heimdall decisions |
|---|---|
| Personal default at setup | 1 (`WidenPolicy{Create}`) |
| First trust of a workspace whose request exceeds personal coverage | 1 (`TrustWorkspace`; includes the environment permission and, if pending, the lock disclosure) |
| Equivalent work; fresh work under policy; renewal within a grant; helper recovery; duplicate requests | 0 |
| Source edits, branch switches with the same access digest, or back to an approved digest | 0 |
| Changing defaults or a profile definition | 0 (new requests only; §5.1) |
| A verified linked worktree (if Q1 is accepted as recommended) | 0 |
| Move or re-clone of a trusted checkout | 1 (`ReconcileWorkspace`) |
| A distinct added authority (policy, revision, delta) | ≤ 1 while pending, shared by every concurrent caller; 0 during its cooldown (§4.3) |
| Any background trigger | 0, always |

Provider interactions (a vault unlock, a touch) are counted separately and are not Heimdall prompts
(spec §5.5). Chores after a reboot (runtime start, `time confirm`) are M04-T04 and G09 territory, so
the A02 journey runs within one boot.

## 4. Scope-delta review and coalescing

### 4.1 Where an approved delta goes

Options:

- (A) Every delta is a one-off `ApproveAuthority` for one operation, as now. A repeated manifest
  request after expiry would prompt again.
- **(B) A delta raised by a trusted workspace's manifest becomes a `WidenPolicy{ExtendScope}` on
  that workspace's policy.** Approval writes a new revision. Every waiter it now covers resumes
  through `proceed_covered`, and later work is covered.
- (C) The approver chooses "once" or "remember" when deciding. This breaks ADR-0006's rule that
  `Decide` applies exactly the recorded action.

**Decision: (B)** (owner question Q2) for deltas whose source is a manifest in a trusted workspace. Explicit deltas in
other contexts (a `--scope`, `--until` or environment beyond the policy) stay one-off
`ApproveAuthority`, unchanged.

**Reasons:**

- "No repeated equivalent prompts" across sessions needs the approval to persist.
- The resume and coalescing machinery already exists.
- Approving only the delta keeps spec §5.3's "only the added authority requires a decision".

### 4.2 Coalescing

- **The coalescing key:** policy ID, policy revision, environment, and the canonical digest of the
  delta (added pairs, capabilities, environments and lock behaviour).
- **Joining:** concurrent requesters with the same key share the one pending record. ADR-0006 §13.7
  item 4's ownership transfer applies. A broader delta never joins a narrower one; it gets its own
  record.
- **Display:** the record shows only the added authority (spec §12.3).
- **Narrowing:** a manifest that asks for less never narrows the policy. Only the owner narrows a
  policy. A narrowing outside a grant's basis ends that grant (§13.7 item 3).

### 4.3 Cooldown

Spec §5.5 asks for cooldowns. The duration is a provisional default (owner question Q3).

- **When a cooldown starts:** a **denied** decision records a cooldown for its key.
- **How long it lasts:** until the policy's saved window has elapsed (P04, default 12 h), or until
  the policy's revision changes or the delta changes.
- **During the cooldown:** an equivalent request from a requester gets `decision_cooldown` (exit 3)
  with `retry_after` and the denied decision's reference. No new record is created.
- **Owner-initiated widening** (`access allow …`, or "review again" in the TUI) always creates its
  decision. The cooldown only suppresses requests that come from requesters.
- **An expired, unanswered decision has no cooldown:** a retry gets a fresh record (ADR-0006 §13.3
  item 3). This bounds re-notification to one per decision lifetime (15 min).

### 4.4 Revisions

- **Applied changes:** every applied policy change appends a `policy_history` row (revision, record,
  cause, time), which `inspect policies` shows.
- **Effect on running work:**
  - running bindings keep their snapshot when the policy or profile revision moves (A04);
  - a profile revision never widens a policy;
  - a policy narrowing ends only the grants outside their basis.

## 5. Bindings and shared resources

### 5.1 Pins and defaults

- **What a binding pins:** M01's environment, profile revision, scope, mechanism and grant, and now
  also its **context**: the workspace ID or `personal`. The grant origin records the **policy ID**.
- **Defaults:** the default profile is a catalog preference. It is read only when a new request
  omits the profile. A default cannot redirect existing work, because existing bindings never read
  defaults (R-AU-03).

### 5.2 Ordinary-alias slots

Options:

- (A) Keep refusing a second binding on a held pair (`managed_slot_held`). Two agents in one project
  could not share a host without wrappers.
- **(B) Reference accounting with handover.**
- (C) A per-process bound configuration through a `PATH` shim or `ProxyCommand`. That is a wrapper,
  and it executes directives.

**Decision: (B)** (owner question Q4). The slot gets a materializer binding plus a set of
references.

- **Joining:** a bind whose active grant covers the pair, with the same mechanism, joins the slot
  (`slot_shared`). A different mechanism is still refused with `managed_slot_held`.
- **Handover:** when the materializer ends, the slot passes to the remaining referencer with the
  latest deadline. The handover re-materializes under a new generation, using the existing CAS and
  `may_cleanup` fencing. When no referencer remains, the slot clears.
- **Certificate bound:** the slot's certificate never outlives its current materializer's grant.

**Honest label.**

- **Ordinary aliases are environment-level** (spec P03).
- **Sharing a pair:** while another binding holds the pair, a job's own deadline is enforced for its
  bound contexts (`connect`, delegated endpoints), not for ordinary aliases.
- **Reporting:** results report `ordinary_aliases: shared_environment_default`.
- **Plan §6.3 property 8 still holds:** the slot carries only that pair's authority, always from one
  grant, and only for as long as some referencer holds that authority.

### 5.3 Mixed mechanisms

- **Splitting:** a context or profile that spans mechanisms activates as **one binding per mechanism
  group under one work ID**.
  - The refusal now carries `next.groups`; the CLI and the hook re-request each group.
  - `work_deadline` caps each later group to the earliest group's deadline.
  - The groups' readiness is summarized at the weakest value.
- **Re-deferred:** a single grant with per-pair adapters (ADR-0008 Q5) is re-deferred, with this
  decision. Owner question Q7.

## 6. Delegation and the narrower binding

### 6.1 The enforced recipe

Options:

- **(A) Managed child certificates: subset principals and `valid_before` ≤ the parent's** (ADR-0005
  §3.10), enforced by the destination's sshd.
- (B) A separately enforced execution context, the M04-T05 container recipe.
- (C) A signer key filter only. This is convenience, and spec §14.4 forbids calling it isolation.

**Decision: (A)** is M05's one enforced recipe.

- **Scope:** A28's scope proof is a child certificate refused by a second host that trusts the same
  CA under a different principal mapping (spec §14.3).
- **Expiry:** the expiry proof is the parent's end destroying the child's key, after which the
  child's next login fails.
- **(B) is an additional row** when M04-T05 lands. It is what makes owner functions *unreachable*,
  not just *not delegated* (§6.2).

### 6.2 Owner management stays out of child authority

**Structural guarantees, claimed:**

- **What the child holds:** a child binding ID and a child signing endpoint.
  - The signing endpoint accepts only signing operations. Control frames and issuance requests are
    refused (R-RT-03).
  - Binding IDs are references, not bearer credentials (spec §11.2).
- **Delegation confers no new powers:**
  - nothing can be approved or widened without an attended owner `Decide`;
  - a policy cannot be changed by holding a binding;
  - the child's own `delegate` can only narrow further.
- **What a worker launched with `run --parent-binding` receives:** only the child endpoint in its
  environment. No control-endpoint locator is passed to it.

**What is labelled, not claimed:**

- A same-user child can open the owner's control endpoint itself. The result reports
  `owner_functions: not_delegated` and `workload_isolation: shared_os_user`.
- Only an M04 container row that mounts only the child endpoint reports `owner_functions:
  unreachable`.

### 6.3 Labels

| Parent mechanism | `destination_scope` | `workload_isolation` | `owner_functions` |
|---|---|---|---|
| Managed (B1) with verified pairs | `verified_server_principals` | `shared_os_user` | `not_delegated` |
| Managed, inside the M04 container recipe | `verified_server_principals` | `tested_isolated_workload` (M04 evidence) | `unreachable` |
| Existing access, or unverified managed pairs | `client_routing` or `unenforced_intent` | `shared_os_user` | `not_delegated` |

## 7. Pause, expiry, cutoff and stop: precedence

### 7.1 Order

The order, strongest first:

1. revocation tombstone (per grant, permanent, cascades);
2. hard cutoff (per policy, timed, lifted only by an attended decision);
3. stop (pause and end now);
4. pause (future activations);
5. normal expiry (per grant);
6. standing permission.

An explicit deny and every block outrank allow (spec §6.2).

### 7.2 Effects

| | New activation (any request or work ID) | Same work ID | Existing grants | Renewal within a grant | Background triggers | Lifted by |
|---|---|---|---|---|---|---|
| Revoke (grant) | not affected by itself | not blocked by the revocation itself; a new grant stays capped at the work's first deadline (M01 `work_deadline`) | that grant and its descendants end now | refused | — | never (terminal) |
| Cutoff at T | refused from T (`POLICY_CUTOFF`) | refused from T | end at min(deadline, T); certificates ≤ T | until T | refused from T | attended `ClearCutoff` or later cutoff |
| Stop (policy target) | refused (`POLICY_PAUSED`) | refused | revoked now, with cascade | refused | refused | attended `Resume`; ended grants stay ended |
| Stop (work) | other work unaffected | refused (`work_stopped`) | unshared grants of that work revoked; shared grants lose that work's references only | refused for that work | — | never for that work ID |
| Pause | refused (`POLICY_PAUSED`) | a new binding is refused; existing bindings stay usable; a same-key replay returns its recorded result | continue to their deadline | continues | refused | attended `Resume` |
| Expiry | new work allowed under policy | refused (`CREDENTIAL_EXPIRED`) | that grant ends | refused | start new work (§3.3) | n/a |

### 7.3 Rules

- **Targets:** narrowing actions accept a target: a policy, a profile (every policy for it), a
  workspace, or all. They apply in one transaction with one generation bump. Widening actions across
  a target create one decision that lists every affected policy.
- **Independence of blocks:**
  - `Resume` does not clear a cutoff;
  - `ClearCutoff` does not resume a pause;
  - lifting a block never revives a terminal grant.
- **The supervisor, recovery, lazy activation and the shell hook are all activations.** None can
  resurrect paused, stopped or cut-off access (spec §13.5).
- **Narrowing actions** are never blocked by uncertain time. Widening actions are refused while time
  is uncertain (ADR-0006 §13.6 item 6).

## 8. Residuals and non-claims

These are recorded in `RESIDUALS` and in the claims table, with probes, under ADR-0009 §2.1.

- **R1. A same-user agent with a terminal can drive the attended confirmation.** A prompt-injected
  agent with a pseudo-terminal could run `heimdall decision approve` and type `yes`.
  - **Claimed:** no repository, manifest or request content ever becomes consent (I1, I5).
  - **Not claimed:** that a same-user program cannot impersonate the human at Heimdall's own prompt
    (spec §14.2, "a compromised owner session").
  - **Owner question Q8:** an optional convenience guard.
- **R2. The working directory in a request is a same-user claim.** A same-user process can name any
  trusted workspace. Context labels say `same_user_context`.
- **R3. Ordinary aliases are shared across jobs in an environment** (§5.2).
- **R4. Lazy ordinary-`ssh` activation activates the default policy's whole covered scope**, because
  of how the agent protocol works (§3.2).
- **R5. Re-entry makes the window a usability bound** (§3.3). Pause and cutoff are the stops.
- **R6. Workspace identity on filesystems without a stable identity is refused**, not approximated
  (§2.3).

## 9. Consequences and reopen conditions

- **Contract:** ADR-0006 revision 5 is listed in m05-plan §4. It is additive, the code table stays at
  30, and new distinctions are sub-reasons.
- **Store:** one migration (`workspaces`, `policy_history`, `decision_cooldowns`, `work_stops`,
  `slot_references`, `bindings.context_json`).
- **Reopen this ADR** if any of the following happens:
  - the wave-0 spike finds an OpenSSH client that times out within the activation wait (then §3.2
    (a) is not claimed on that platform);
  - the owner answers Q1–Q10 differently;
  - M04's WSL Mode A path handling changes workspace namespaces;
  - a stronger approval boundary is adopted, such as OS user-presence confirmation;
  - a single mixed-mechanism grant becomes necessary.
