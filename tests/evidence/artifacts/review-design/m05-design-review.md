# M05 design review (ADR-0009 §2.8)

**Verdict: revise first.** Blocking: M05-D01, M05-D02, M05-D03, M05-D04, M05-D05, M05-D06.

Reviewed `a69fe86fbf5b9f12bb30c3cb9f186bab3428e78a` (`docs/architecture/m05-plan.md`, `docs/decisions/0011-trusted-work.md`) against `spec.md`, `plan.md` §5 M05 and §6.3–§6.4, ADR-0009, ADR-0006 revision 4, ADR-0007 Q3/Q5, ADR-0008 D6/D10/Q5/Q15, and the M04 draft at `b91aaabb` (`docs/architecture/m04-plan.md`). No tracked files were edited.

**Authority, in short.** A repository file does not become consent under invariants I1–I5, and a fresh work ID does not evade a pause or a hard cutoff in the §7.2 table: those checks are on the activation, and re-entry IDs are new work under a live policy, which spec §6.1 allows. Four paths still widen authority or turn repository entry into a prompt: the existing first-by-ID policy merge once two policies share a profile, `background_work` copied off the manifest, the shell hook running as an interactive TTY, and a workspace `ExtendScope` leaking through that merge. Import, clone/copy matching, delegation, cooldown, and coalescing do not widen authority if the findings below are applied.

**Coverage, in short.** T01–T06 each have a unit. A02, A04, A05, A16, A18, A28, and A29 each have a named journey. Plan §6.3 properties 3, 5, and 6 are actually extended. Property 1 is extended only if personal and workspace policies are separate generators (M05-D01). Property 8 is claimed and not proved (M05-D06). Properties 4 and 7 are not extended (M05-D07). The hook's "no prompt" claim and the mixed-mechanism deadline are unproven.

**Feasibility, in short.** The spike is the right experiment. The hook is specified on a file that does not serve `REQUEST_IDENTITIES`, and the fallback unclaims the path instead of omitting it (M05-D04). The other units sit on code that already exists (resolver, `activation_refusal`, `work_deadline`, slot CAS, child keys, `LoopbackSshd` principals, `FileIdentity` on Unix and Windows).

## Findings

### M05-D01 — blocking — workspace scope is selected by policy ID, so a project approval widens personal and ordinary `ssh`

`crates/store/src/ext.rs:846-860`, `crates/app/src/operations.rs:891-924`, `crates/domain/src/authority.rs:227-244`, `docs/decisions/0011-trusted-work.md:45-46`, `docs/decisions/0011-trusted-work.md:173-189`, `docs/decisions/0006-public-contract-baseline.md:752-760`.

`policies_for` returns every standing policy for a profile and environment. `choose_policy` then takes the first by ID and `merged_policy` uses that policy's scope, while folding every pause and the earliest cutoff into the same view. ADR-0006 §13.6 item 5 froze that merge because workspace records were legitimate and, in production, unused (ADR-0011's own premise: no standing policy is created today).

M05 creates a personal policy and a workspace policy for the same profile and environment (`StandingPolicy.profile` plus `workspace: Some`). A trusted project's `ExtendScope` (Q2) writes the added pair onto the workspace policy only. Whichever policy sorts first then becomes the scope for every activation of that profile, including ordinary `ssh` and a second workspace. A workspace-only `prod` pair becomes personal access with no further decision. The reverse also happens: a workspace pause blocks personal work, which §3.1 forbids, while a personal cutoff stops project work only when both policies stay in the merged set.

§3.1 states the right rule and then says M05 changes no M01–M03 semantics except the slot refusal. Keeping `choose_policy` to honour that sentence is the breach. `Ambiguous` and `Untrusted` are also not named as non-matches, so a same-path re-clone can keep the old workspace policy if an implementer treats "same path" as enough.

**Change.** Replace `choose_policy` on every resolution path (`ensure`, `run`, renewal, `activation_refusal`, ordinary `ssh`, the shell hook), not only in the new context module. A workspace policy applies only when the match is `Trusted` or `Member` of that workspace. Personal scope never includes another policy's pairs. Personal pause and cutoff apply to that profile's workspace work; a workspace pause, cutoff, or scope does not apply to personal work or to any other workspace. `Ambiguous` does not use the old record: one `ReconcileWorkspace` decision, no workspace grant. Extend the U2 model with a two-policy trace whose assertions are: a workspace-only pair is absent from ordinary `ssh` and from a second workspace; a same-path re-clone does not activate the old scope; a workspace pause leaves personal work usable.

### M05-D02 — blocking — `background_work` is both a forbidden authority key and the manifest field that selects lock behaviour

`docs/decisions/0011-trusted-work.md:79-99`, `spec.md:684-697`, `crates/runtime/src/config.rs:200-238`.

The manifest example sets `preferences.background_work = true`, and spec §13.4 says an untrusted repository cannot use that key to grant itself unattended access. The same section says the denylist extends `FORBIDDEN_KEYS`, matched whole and case-insensitively, including under `[metadata]`. `FORBIDDEN_KEYS` already contains `background_work` (`config.rs:230`), because a config file must not carry unattended consent. Extending that list makes the spec's own fixture `manifest_authority_key`.

The value rule makes the same field unparsable a second way: values are bounded tokens (`[A-Za-z0-9._:-]`, at most 128 bytes). TOML `true` is a boolean, not one of those tokens.

Nothing then says activation ignores the field. U4 builds the request as "manifest ∩ latest profile snapshot". Lock behaviour is not a scope pair. A literal intersection can copy `continue` (work while locked) onto a binding whose policy is `revoke_on_lock`, which is a widening the file performs without a decision. Q10 makes this worse: an untrusted workspace whose pairs the personal policy already covers activates with no trust decision.

**Change.** Keep `background_work` forbidden everywhere except the one schema field `preferences.background_work`, which is a boolean. Reject it under `[metadata]` and at any other path. Do not extend `FORBIDDEN_KEYS` blindly. Coverage of a request includes lock behaviour. Activation uses the policy's recorded lock behaviour only. The manifest flag is stored on the policy solely by an attended `TrustWorkspace` or `ExtendScope`. Add that case to P9: `background_work = true` under a `revoke_on_lock` policy yields no `continue` grant and no decision from a background trigger.

### M05-D03 — blocking — the shell hook runs on a TTY, and a TTY prompts

`crates/heimdall/src/cli.rs:39-49`, `crates/heimdall/src/cli.rs:1541-1580`, `docs/decisions/0011-trusted-work.md:199-209`, `docs/decisions/0011-trusted-work.md:230-237`, `spec.md:226-227`.

On an interactive TTY the CLI sends `Attend` before `access ensure` and, if the runtime returns a pending decision, asks for `yes` and sends `Decide`. `heimdall activate --hook --cwd "$PWD"` is invoked from `chpwd` / `PROMPT_COMMAND` with the user's terminal as stdin. The plan never says `--hook` is noninteractive.

`covered_only` is specified as creating no decision, but the prompt lives in the CLI, which does not know that until after `Attend`. Entering a repository whose manifest exceeds coverage, or any path that still returns `APPROVAL_REQUIRED`, raises a Heimdall prompt from `cd`. That is a repository file causing an approval interaction. Spec §5.3 says a manifest never introduces an approval decision. The A02 journey counts prompts only after a successful first trust, so it does not prove this.

**Change.** `--hook` forces noninteractive: no `Attend`, no prompt, no `Decide`. The server, given `covered_only`, activates the covered subset or returns `not_covered` with no decision row. Add `hook_creates_no_decision_when_uncovered`: `cd` into an untrusted manifest and into a trusted manifest that adds a pair; decision rows stay 0 and no prompt is written. A02's prompt counters stay as they are.

### M05-D04 — blocking — ordinary `ssh` is hooked on the wrong function, and a failed spike only withdraws the claim

`crates/credential/src/signer.rs:444-446`, `crates/ipc/src/signing.rs:325-352`, `docs/architecture/m05-plan.md:67-72`, `docs/architecture/m05-plan.md:204-223`, `docs/architecture/m05-plan.md:339-343`, `docs/architecture/m05-plan.md:466-469`, `docs/decisions/0011-trusted-work.md:220-228`, `docs/decisions/0011-trusted-work.md:497-498`, and M04 `docs/architecture/m04-plan.md:48-49` at `b91aaabb`. `plan.md:149-157`.

`REQUEST_IDENTITIES` is answered by `ManagedSigner::identities`, which lists keys already in the signer table. It does not run in `credential/src/endpoints.rs`. `Signer::session_bind` is specified as must-not-block, so it cannot host a 2 s activation either. U5 and the shared-file list put the one call in `endpoints.rs`. M04's W0 replaces that file with `endpoints/mod.rs` plus `container.rs` and `wsl.rs`. As written, the hook is either never on the agent path, or it is a rebase onto a file M04 is splitting for a different reason.

The spike itself is right: the agent request carries no directory, and the client's wait is the budget. The fallback is not. W0 says to withdraw ordinary-`ssh` activation before anyone builds it. U5's acceptance and ADR §9 only change the claim to "`run`, `ensure`, or the shell" while leaving the call in place. A client that times out inside the budget then fails ordinary `ssh` on every identities request. G05's failure action is to simplify the integration, not to keep a delay and stop claiming it. The plan also never says what the agent answers if activation exceeds the budget: blocking past it breaks `ssh`; failing the agent request does too.

**Change.** Hook `Signer::identities` for the environment endpoint (name `crates/credential/src/signer.rs` in §5). Do not hook `session_bind`. If U0b finds any in-box client whose `ssh` or Git fails inside the budget, that platform gets no identities-path call and no added delay; the record says activation is `run`, `ensure`, and the shell hook. On a platform where the budget holds, a wait that expires returns the identities already admitted and does not fail the agent request. Already-active and already-refused (pause, cutoff, cooldown) return immediately.

### M05-D05 — blocking — both drafts own ADR-0006 revision 5, and M05's hash extra can change old ensure hashes

`docs/architecture/m05-plan.md:387-395`, `docs/architecture/m05-plan.md:453-460`, `docs/decisions/0011-trusted-work.md:492-495`, and M04 `docs/architecture/m04-plan.md:37-41`, `docs/architecture/m04-plan.md:73-74`, `docs/architecture/m04-plan.md:343-375`, `docs/architecture/m04-plan.md:452-454` at `b91aaabb`. `docs/decisions/0009-delivery-economy.md:66-69`.

M05 W0 "lands ADR-0006 revision 5 whole" and assigns M04's deltas to revision 5.1. M04 Q5 says the orchestrator holds revision 5 and each track delivers a patch. ADR-0009 §2.6 gives the public contract one owner. Two W0s will both edit `crates/contract/**`, the capability list, `cli.rs`, and `dispatch.rs` under incompatible stories. Reason strings do not collide (`workspace_*` / `manifest_*` / `decision_cooldown` / `not_covered` / `work_stopped` / `slot_shared` versus M04's `wsl_*`, `environment_*`, `route_*`, `login_entry_conflict`). The ownership story does.

Migration `0007` is not a second conflict. Both plans say the first merge takes `0007` and the second renumbers. ADR-0011 §9 still freezes the number as `0007`, which the second merger would have to contradict.

The hash rule is a real contract break. M05 puts the resolved workspace ID and the access digest into the ensure hash extra. M04's revision-5 acceptance is that every M01–M03 document and request hash stays unchanged. A context-free `EnsureRequest` that newly hashes those fields will `REQUEST_CONFLICT` on retry of an in-flight M03 operation, or fail M04's "hash unchanged" check, depending on which patch lands first.

**Change.** One revision, owned by the orchestrator, containing both wave-0 patches. Neither plan lands revision 5 whole or numbers the other 5.1. State that the new ensure extras are omitted from the canonical hash when `context` is absent, and that a context-free vector keeps its M03 hash. Leave the migration number as first-merge-wins in the ADR as well as the plan.

### M05-D06 — blocking — "property 8 still holds" is false for the slot this design builds

`docs/decisions/0011-trusted-work.md:352-369`, `docs/architecture/m05-plan.md:241-247`, `plan.md:440`, `crates/domain/src/managed.rs:107-138`.

Plan §6.3 property 8: sharing must not merge unrelated authority or retain a resource past the most restrictive applicable boundary. The design hands the slot to the referencer with the latest deadline and says the shorter job's deadline is not enforced on the ordinary alias. That is the least restrictive deadline, labelled `shared_environment_default`. The label matches spec §6.3 (a shared grant lives while some authorized referencer holds it) and ADR-0008 Q15 (ordinary aliases are environment-level). The sentence "property 8 still holds" does not.

U6's model asserts a materializer, `valid_before` ≤ that materializer, cleanup fencing, and stable pins. It does not assert the most-restrictive bound, so the suite would pass while the ADR claims a property the code does not keep. The M03 machine still refuses a second holder (`managed.rs:131-137`); narrowing that refusal is acknowledged and is not this finding.

**Change.** Delete "property 8 still holds". Claim what Q4 actually is: one pair, one materializer grant, certificate principals and `valid_before` taken from that grant only, slot gone when the last referencer drops, shorter siblings enforced on bound contexts and not on the ordinary alias (R3). Point the U6 model at those assertions. Do not describe it as extending property 8's most-restrictive clause.

### M05-D07 — non-blocking — three plan §6.3/§6.4 obligations have no proving test

`plan.md:429-448`, `docs/architecture/m05-plan.md:127-140`, `docs/architecture/m05-plan.md:373-379`, `crates/app/src/operations.rs:3613-3626`, `docs/decisions/0011-trusted-work.md:119-134`.

- **Property 4.** U2 says the existing model suites pass unchanged. They do not generate `context` or an access digest. §4 puts both into the ensure hash. Nothing asserts that the same request ID with a different digest is `REQUEST_CONFLICT`, or that a same-digest retry converges. A digest left out of the hash replays an operation against a manifest that has since changed.
- **Property 7.** A caller that times out during `DefaultActivation` is not classified. Spec §11.4: a caller timeout is not cancellation, and an uncertain effect is not "not applied". The spike's `ssh` timeout is exactly this case.
- **Property 2, the new half.** U3 caps grants at `min(window, parent, cutoff)`. It does not say the second mechanism group's certificate `valid_before` is capped by `work_deadline` (`operations.rs:3613`). Q7 depends on that cap. No test covers `next.groups`.
- **§6.4.** The trust apply is one transaction, so a crash between its writes is the store's existing atomicity. Import is "one journaled operation" and is not in the fault-injection list. One sentence is enough if it really is a single transaction; a multi-step journal needs one crash-before-commit case, not a new suite.
- **Worktree path.** §2.3's three checks are sound only on a canonical `gitdir` that is a direct child of `<common>/worktrees/`. P11 should include a relative `gitdir`, a `..` segment, and a copied worktree whose `gitdir` text still names the original common. The copied-worktree row is otherwise easy to implement as a string prefix.

**Change.** Extend the existing idempotency property with the two new extras. State that an identities-path timeout leaves a committed activation as applied and does not roll it back. Add one mixed-profile example: two groups, one work ID, the later group's deadline ≤ the earlier group's. Say import is one transaction, or name the single fault test. Add the three `gitdir` cases to P11.

### M05-D08 — non-blocking — the shared-file list is not the set either draft will touch

`docs/architecture/m05-plan.md:441-479`, M04 `docs/architecture/m04-plan.md:401-430` at `b91aaabb`.

The crate split is workable. M05's `project` crate depends only on `contract` and `domain`; M04's `wsl` crate does not depend on it. `domain` policy/decision/binding/grant/workspace/managed versus M04's environment/enrollment/time is a real boundary. `ext_m05` and `ext_m04` can stay disjoint. Reason strings do not overlap (M05-D05).

The §5 list is still short, and M04's list is long in the wrong places:

- Both edit `crates/heimdall/src/setup_cmd.rs` (M05's personal-default offer, M04's shared item 6). M05's ownership table mentions the offer and §5 does not list the file.
- U10 writes the matrix; M04 lists `docs/compatibility/matrix.md`. M05 §5 does not.
- Both add a workspace member (`project` and `wsl`) in the root `Cargo.toml` and `Cargo.lock`. §5 mentions `[[test]]` lists only.
- M04 also lists `app/src/setup.rs`, `ensure.rs`, `adapters/src/managed/*`, `localenv` projection `content.rs` / `materialize.rs`, and `domain/src/issuance.rs` as files M05 will edit. This design does not: first trust is a `PolicyAction`, not a setup item; `ensure.rs` is the stage enum; handover calls the existing materializer; issuance stays M03's. Do not edit those to satisfy M04's list. `signer.rs` is the file to add (M05-D04).

**Change.** Add `setup_cmd.rs`, `docs/compatibility/matrix.md`, root `Cargo.toml` members, and `Cargo.lock` to §5. Add one line that M05 does not take M04's projection, setup-item, or issuance files. Keep the first-merge-wins rebase rule.

### M05-D09 — non-blocking — two extras support no claim

`docs/architecture/m05-plan.md:501`, `docs/architecture/m05-plan.md:249-250`, `docs/decisions/0011-trusted-work.md:474-480`, `crates/heimdall/src/cli.rs:50-52`, `docs/decisions/0009-delivery-economy.md:50-55`.

- Q8's ~20-line guard refuses `decide` when an environment marker says the process is inside `run`. The CLI already records that a same-user program can imitate the prompt, and unsetting the marker bypasses the guard. The residual is the honest claim. The guard is not.
- A16's "parametrized over environment realizations" builds WSL and container rows whose evidence Q9 assigns to M04. M05's record is two native environments. The parameters are a second matrix with nothing to run.

U1's adversarial file mostly repeats the proptest (NUL, depth, size, authority keys). Keep the proptest. Keep U4's symlink, FIFO, and swapped-manifest cases; those are the TOCTOU claim and are not redundant. The four U9 snapshots are the §12.3 and I5 rendering proofs; keep them.

**Change.** Drop the guard. Let M04 add A16's WSL and container rows to the test M05 leaves behind. Fold U1's byte cases into the proptest regressions.

## The ten questions

Agree, except where a finding narrows the recommendation.

| # | Agree? | Reason |
|---|---|---|
| Q1 | Yes | A verified worktree back-link adds no scope; a move or re-clone stays `Ambiguous` and needs `ReconcileWorkspace`. Pin the path rules in M05-D07. |
| Q2 | Yes | Remembering the delta on the workspace policy is what makes "no repeated equivalent prompts" true, and `Decide` still applies only the recorded action. M05-D01 is what keeps that write off the personal policy. |
| Q3 | Yes | A denied key stays quiet for the saved window; a different delta is new authority, and spec §5.5 does not require a global prompt cap. |
| Q4 | Yes | Two jobs on one pair need a shared slot, and the environment-level label is the honest one. Claim that, not property 8 (M05-D06). |
| Q5 | Yes, with M05-D04 | Ordinary `ssh` should activate the personal default, covered-only. A failed spike means the identities hook is absent, not merely unclaimed. |
| Q6 | Yes | One opt-in integration is zsh and bash. Windows still has `run` and ordinary `ssh`, which is what spec §10.3 requires of that platform. |
| Q7 | Yes | One binding per mechanism keeps M03's one-mechanism grant and uses `work_deadline` for the shared work ID. Add the one example in M05-D07. A single mixed grant stays deferred. |
| Q8 | The residual only | Record R1. Do not add the guard (M05-D09). |
| Q9 | Yes | M04 closes the WSL, container, and forwarding rows. M05's A16 record stays "two native environments, one OS user". Do not pre-build those parameters. |
| Q10 | Yes, with M05-D02 | Covered personal access in an untrusted directory adds no authority. "Covers the whole request" must include lock behaviour, or the manifest's `background_work` is the authority. |

## What is already sound

- I1–I5, the closed manifest, no-follow read, and "hashed bytes are the parsed bytes" match spec §5.3, §8.3, and §13.4, once M05-D02 is fixed. Import applies catalog intent, drops host-key fingerprints, and the A18 test checks that an `ensure` still needs a decision.
- Copy, clone, cross-filesystem move, and submodule-as-own-root match spec §5.3. `FileIdentity` already distinguishes Unix `(dev, ino, birth)` and Windows file IDs (`crates/domain/src/projection.rs:114-161`), and a missing identity refuses trust.
- Pause, cutoff, and policy stop in §7.2 match ADR-0006 §13.6 item 1 and spec §6.1. A fresh work ID is refused because it is a new activation, not because the ID is recognized. Expiry re-entry with `shell:` / `default:` IDs is the behaviour spec §6.1 requires, and the disclosure string says so.
- Delegation (A28) is the ADR-0005 §3.10 recipe already implemented through `Operations::delegate`. The five U8 journeys on two `LoopbackSshd` principal maps would actually show server refusal. Same-user reach of the control endpoint stays `not_delegated` / `shared_os_user`.
- Cooldown and coalescing do not grant authority. A broader delta does not join a narrower one. Owner-initiated widening bypasses the cooldown; a manifest cannot.
- Blocked rows B7, B12, B2, and B9 stay blocked. The exit rule does not widen claims over them. That part of §3 is right.
