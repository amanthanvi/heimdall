# M02 independent design review — proceed after fixes

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, separate worktree.
Saved verbatim by the orchestrator on 2026-11-01.

**Task:** M02-T00-design-review
**Commit reviewed:** `f217bb28adea3ab9caee71a69cfeeb7e5e319e7e`
**Verdict:** **proceed after fixes**. Resolve the blocker and major findings before starting implementation waves against frozen interfaces.

The overall direction is appropriate: a nonexecuting parser, a bounded managed projection, direct use of external agents, attended projection decisions, Unix process replacement, and explicitly separated native evidence. However, the proposed design overstates identity selection, transaction safety, probe isolation and launch observability. Its implementation ownership also omits necessary changes to M01.

This was a read-only review. No files were changed, no build was performed, and no network or native harness was used. "Observed" below means inspected in the checkout; consequences of unimplemented behavior are marked **inference**.

## Findings

### M2-D01 — blocker — Inherited identity files defeat the promised single-key selection

**Locations:** `docs/decisions/0007-existing-access-integration.md:129`, `:381`; `docs/architecture/m02-plan.md:207`, `:583`.

**Defect:** D2 explicitly retains accumulated user `IdentityFile` entries, while D6 promises that the agent signs only with the adopted key and that there is no fallback to other agent keys. These promises are incompatible. `IdentitiesOnly yes` restricts authentication to configured identities, including inherited configured identities.

**Evidence, observed:**

- ADR-0007 D2: "A user `Host *` IdentityFile is appended after Heimdall's."
- ADR-0007 D6: "there is no fallback to other agent keys."
- Pinned S01, `IdentityFile`: "Multiple IdentityFile directives will add to the list of identities tried."
- Pinned S01, `IdentitiesOnly`: configured identities include those "explicitly configured in the ssh_config files".

**Consequence, inference:** If the adopted key is rejected and a second inherited identity is accepted, ordinary SSH can authenticate with that second key. An inherited local private-key path also permits authentication outside the selected agent. The planned wrong-key test does not specify this fixture.

**Fix:** Preserve user configuration, but refuse or explicitly downgrade single-key readiness whenever additional effective identity/certificate entries permit fallback. Do not claim adopted-key-only selection for that configuration. Add a native test with a rejected adopted key, an inherited accepted second key, and both agent-backed and file-backed variants. The result must refuse the stronger claim or prevent the fallback.

### M2-D02 — major — Updating P before checking B can change active routing despite reporting a conflict

**Locations:** `docs/decisions/0007-existing-access-integration.md:190–205`, `:240`; `docs/architecture/m02-plan.md:335`.

**Defect:** The P-before-B ordering is safe against a missing include target during first adoption, but does not provide the stated behavior for an existing installation. B already points to P. Replacing P changes ordinary SSH behavior immediately, before the user-file comparison in step 4.

**Evidence, observed:**

- Step 3 replaces P; step 4 compares and replaces the user file.
- The concurrency section promises: "A mismatch is `CONFIG_CONFLICT`: nothing is overwritten."
- Spec §10.1 requires an effective-behavior comparison and preservation of existing edits.

**Consequence, inference:** A user-file edit after preview can cause step 4 to fail after P has already redirected active aliases. A crash at the same point leaves the new projection active. The proposed partial-state description "P written, B not" does not distinguish first adoption from replacement of an already referenced P.

**Fix:** Define the commit point and partial-effect contract separately for first adoption and updates. Revalidate all relevant preconditions before activation; durably record enough information to reconcile an already-active P. A post-activation failure must report the applied/partial effect rather than imply no change. Add an existing-installation test that edits the user file between replacing P and checking B, plus a process-crash variant.

### M2-D03 — major — Digest checks do not preserve concurrent edits or prove cleanup ownership

**Locations:** `docs/decisions/0007-existing-access-integration.md:208–226`; `docs/architecture/m02-plan.md:316–318`.

**Defect:** The ADR correctly discloses the check-to-rename race, but still promises that concurrent edits survive. A second digest check is not a filesystem compare-and-swap. Separately, U4 describes cleanup in terms of digest equality even though deterministic generations can have identical bytes.

**Evidence, observed:**

- ADR-0007 acknowledges "the window between the last digest check and the rename".
- Spec A22 requires "unrelated content and newer edits survive".
- Spec §13.5 requires validation of the **current generation** before deletion.
- M01's `ResourceCleaner` contract in `crates/app/src/ports.rs` requires generation-bound deletion and explicitly leaves replacement instances untouched.

**Consequences, inference:**

1. An editor can replace or modify the user file after the final check; the subsequent rename loses that edit from the active path.
2. A newer projection instance with identical contents can pass a digest-only cleanup check.

**Fix:** Specify a replacement strategy that retains the displaced file until post-replacement validation completes, with conflict recovery that preserves its contents. Recheck file identity, type, ownership and permissions at the write boundary, including symlink/reparse-point substitution. Cleanup must validate generation and recorded filesystem identity, not just content. Add race-injection tests after the final comparison and a same-bytes/new-file-identity cleanup test. Explicitly document any remaining unsupported concurrency behavior rather than treating disclosure as satisfaction of A22.

### M2-D04 — major — Rollback and removal are not inherently narrowing actions

**Locations:** `docs/decisions/0007-existing-access-integration.md:554–563`, `:610–612`; `docs/architecture/m02-plan.md:359–364`.

**Defect:** Q1 classifies every rollback/removal as narrowing and permits it on any same-user control connection. Removing a projection can expose different inherited routing, identities, agents or forwarding behavior. This is not equivalent to releasing a Heimdall binding.

**Evidence, observed:**

- Q1 requires confirmation for changes to HostName, Port, User, agent or identity.
- Its exception permits rollback/removal without confirmation.
- ADR-0006 §13.1 names `Pause`, `Cutoff`, `Revoke` and `Release` as narrowing actions; it does not establish that arbitrary configuration removal narrows behavior.
- Spec §14.2 requires independently enforced authority rather than accepting an agent request as consent.

**Consequence, inference:** Removing an approved `IdentityAgent` or `HostName` can restore a user wildcard that points to a broader personal agent or another host, without an attended decision.

**Fix:** Classify rollback/removal by the before/after behavior. Require a decision when removal changes effective routing or authentication to another usable configuration, unless that exact rollback was included in prior recorded consent. Test removal exposing an inherited HostName and agent.

### M2-D05 — major — Native-agent interaction defaults can violate the no-popup guarantee

**Locations:** `docs/decisions/0007-existing-access-integration.md:346–365`, `:564–570`; `docs/architecture/m02-plan.md:752`.

**Defect:** Native-agent identities default to `interaction = none` even though confirm constraints cannot be detected passively. The proposed adoption request also has no explicit interaction declaration field.

**Evidence, observed:**

- ADR-0007 acknowledges that "confirm-constrained keys cannot be detected passively".
- Nevertheless, ordinary native-agent keys are assigned `none (declared)`.
- A11 requires noninteractive calls to return explicit interaction/capability state "without a popup".
- Q2 refuses launch only when the recorded interaction is not `none`.

**Consequence, inference:** An ordinary Ed25519 key loaded with confirmation required can pass the prelaunch guard and cause a provider confirmation request. Disclosure does not prevent the popup.

**Fix:** Default uncertain interaction to `unknown`, which follows the refusal path. Define an explicit, attributable declaration workflow if the product allows the owner to assert no interaction; preserve its uncertainty and freshness limits. Add a disposable `ssh-agent` confirm-constrained-key test and verify refusal before provider contact.

### M2-D06 — major — Probe levels promise effects they cannot exclude

**Locations:** `docs/decisions/0007-existing-access-integration.md:299–307`; `docs/architecture/m02-plan.md:279–287`.

**Defect:** The `evaluate` level permits arbitrary `Match exec` execution but promises "never" network or signing. An arbitrary shell command can perform either operation. Similarly, process groups are not containment for descendants that deliberately detach. The authentication probe also cannot generally promise exactly one signature.

**Evidence, observed:**

- Pinned S01: "The exec keyword executes the specified command under the user's shell."
- Spec §10.2 requires probe levels to state their effects accurately.
- ADR-0007 allows `ssh -G` on executable user configuration, then claims network/signing exclusion.
- The planned authentication test asserts "signs once".

**Consequences, inference:** An evaluation-authorized hook can contact an agent, sign, use the network or mutate files. Authentication may try multiple identities, negotiate different algorithms or fail before signing. A Unix descendant can leave the original process group.

**Fix:** Describe evaluation of arbitrary configuration as execution with arbitrary hook effects, and obtain explicit authorization for that fact. If stronger exclusions are required, evaluate a sanitized configuration or use actual platform containment and state its limits. Make exact-signature-count assertions fixture-specific. Add hooks that attempt network access, agent contact, mutation and process-group escape; verify either prevention or accurate classification.

### M2-D07 — major — EOF after `launching` does not prove successful exec

**Locations:** `docs/decisions/0007-existing-access-integration.md:407–408`, `:438–447`; `docs/architecture/m02-plan.md:511`.

**Defect:** D7 acknowledges that Heimdall can die between writing `launching` and `execve`, but then defines EOF after `launching` as proof that the child launched.

**Evidence, observed:**

- ADR-0007: pre-exec death is "indistinguishable from the child dying by the same signal".
- The same section says EOF after `launching` "means the child was launched".
- Spec §10.4 requires structured metadata to distinguish setup failure from child status.

**Consequence, inference:** Machine orchestration can falsely attribute a launcher crash to a launched child. A regular metadata file does not supply a close-on-exec notification at all.

**Fix:** Treat `launching` as an attempt, with an explicit indeterminate outcome if no stronger observation exists. Specify separate fd and file protocols and their failure cases. If positive launch proof is mandatory, add an observer/acknowledgment mechanism compatible with the Unix process contract. Test injected termination immediately before exec and exec failure followed by metadata-write failure.

### M2-D08 — major — The ownership plan omits necessary M01 integration work

**Locations:** `docs/architecture/m02-plan.md:90–103`, `:350–358`, `:855`; `crates/app/src/operations.rs:3198`, `:3246`, `:5965`, `:7280`; `crates/domain/src/operation.rs:17`.

**Defect:** New modules and public types do not suffice to implement the proposed flow. Necessary changes to existing M01 decision dispatch, bind validation, prepared-result propagation and operation recovery are not assigned.

**Evidence, observed:**

- `Operations::decide` exhaustively handles existing decision variants in `operations.rs`; adding `ApplyProjection` requires changing it.
- `Operations::bind` validates the existing `Launch { argv }` form.
- `Facts::from_outcome` and `ensure_data` do not propagate adapter consumer integration; `ensure_data` constructs empty integration fields.
- `OperationKind` has no setup/catalog variants.
- U5 owns `setup.rs` and `catalog.rs`, but does not own `operations.rs`; U0's enumerated domain paths omit `operation.rs`.

**Consequence, inference:** Workers cannot complete the advertised interfaces within their ownership grants. Adding fields alone either fails compilation or leaves integration unavailable on live, replayed or restarted bindings.

**Fix:** Assign these shared changes explicitly to U0/the integrator. Define durable setup intent/receipt representation, decision completion and recovery dispatch. Specify how integration/provider facts reach `ensure`, `bind`, replay and restart results, including multiple identity/profile pairs. Add end-to-end contract tests through the real M01 dispatcher and store.

### M2-D09 — major — The default SSH fixture can bypass projection selection

**Locations:** `docs/architecture/m02-plan.md:462–464`, `:579–587`.

**Defect:** `ScratchHome::ssh_command` supplies command-line `IdentityAgent`. Command-line configuration wins over the projection and user file, so tests using this helper cannot prove that projected `IdentityAgent` was effective.

**Evidence, observed:**

- The helper "adds -F, UserKnownHostsFile, IdentityAgent from the scratch".
- Pinned S01 and ADR-0007 F1 put command-line options before user configuration.
- A35 requires verification of the actual executable and identity under configuration that overrides `SSH_AUTH_SOCK`.

**Consequence, inference:** An incorrectly rendered or ignored projected agent path can still yield a passing login and the expected accepted fingerprint.

**Fix:** Separate fixture isolation from configuration under test. Projection/A35 tests should pass only scratch `-F` and necessary trust isolation; put agent selection in the configuration being tested. Use two counting agents and assert which one was contacted. Include a mutation check: breaking the rendered `IdentityAgent` must fail the relevant test.

### M2-D10 — major — The Git projection lacks a transaction and effective-selection contract

**Locations:** `docs/decisions/0007-existing-access-integration.md:474–478`, `:594–599`; `docs/architecture/m02-plan.md:298`, `:744`.

**Defect:** Q7 authorizes a global Git configuration edit, but U4's transaction/recovery design covers P, B and public-key files only. The design names `GitConfigChange` without specifying its fields, preimage, multiplicity, ownership, conflict checks or crash recovery. The stated global/system queries also cannot establish repository-effective Git selection.

**Evidence, observed:**

- Q7 relies on Git's lock file and says rollback occurs only if the value is unchanged.
- Spec §10.1 requires preserved edits and ownership-aware rollback.
- Spec §10.3 requires accounting for Git's selected executable.
- The proposed static queries inspect global/system `core.sshCommand`; the run rule refers to the **effective** command.

**Consequences, inference:** A lock serializes an individual Git write; it does not by itself compare that write with the approved preview or make it atomic with P/B. Repository-local selection can differ from the inventory used to prepare the launch environment.

**Fix:** Define and assign `GitConfigChange`, including configuration scope/origin, exact previous values, absence versus multiplicity, conditional updates, receipts and recovery. Resolve run-time Git selection in the actual child working directory, respecting explicit environment/config overrides and without recording command arguments. Test concurrent Git edits, local overrides, paths requiring quoting, crash boundaries and rollback after a later user change.

## Assessment of Q1–Q8

| Ruling | Assessment |
|---|---|
| **Q1 — attended projection apply** | Sound for apply and behavior-changing repair. **Revise the unconditional rollback/removal exception** under M2-D04. Byte-identical rendering is reasonably exempt when ownership and safety are unchanged. |
| **Q2 — refuse implicit provider interaction** | Sound intent. **Incomplete enforcement** because uncertain native keys default to `none` (M2-D05). Explicit opt-in must clearly describe the provider behavior it permits. |
| **Q3 — uniform grants for existing-access work bindings** | Sound. Ordinary aliases/connect remain useful without grants, while work bindings reuse authority rules. Do not imply these grants constrain external-agent use outside Heimdall; the proposed enforcement labels correctly disclose that limit. |
| **Q4 — bounded local queries in passive doctor** | Reasonable under spec §10.2's distinction between local inspection and executable configuration. Keep queries bounded, avoid shell interpolation, and distinguish their observations from effective SSH/Git behavior. A canary test is necessary but does not establish executable provenance or all possible side effects. |
| **Q5 — release after exact holder exit** | Sound if `Unknown` liveness never counts as exit. On Windows, document/test that the holder is the launcher and that forced launcher termination can leave the child running. Release must retain M01's no-revoke/no-cascade semantics. |
| **Q6 — preserve state unless explicitly purged** | Sound and aligned with authority-state retention. Uninstall must retain conflict/recovery artifacts when rollback is incomplete; purge must not turn an unresolved cleanup into a success claim. |
| **Q7 — optional global Git integration** | Reasonable user-facing choice, **not sufficiently specified for implementation**; see M2-D10. |
| **Q8 — remove argv from bind** | Sound and necessary. Preserve arguments locally as OS strings; cover errors, batch refusals, replay and side-channel records as well as normal IPC. M01 bind handling must actually be changed under an assigned owner. |

The blanket acceptance in ADR-0007 §12.1 therefore needs qualification before it takes effect.

## OpenSSH and platform facts

**Directly checked against the committed S01/S02 snapshots:**

- First-obtained precedence, accumulating identity/certificate entries, conditional Include placement and user/system-relative Include resolution are supported.
- `IdentityAgent` overrides `SSH_AUTH_SOCK`; public `IdentityFile` selection and `IdentitiesOnly` are supported, subject to M2-D01.
- `Match exec` executes a shell command, and `ssh -G` evaluates Host/Match. Keeping arbitrary `ssh -G` out of default doctor is correct.
- `-F` replaces normal user-file selection and suppresses the system configuration. Scratch `-F` evidence consequently cannot close ordinary default-path discovery.
- The include-state restoration claim and passwd-home claim are explicitly marked inference in the design. They should remain unresolved until their differential/native tests run. The manuals alone do not prove those implementation details.

**Reviewed as historical repository evidence, not independently reproduced:**

The G03 register and native-observation descriptions support the proposed Windows in-box baseline, pipe spelling, bundled-MSYS limitation and Git command precedence. I did not independently re-read the external Win32/Git source bodies at their pins or reproduce those native observations. Hash/register entries are not equivalent to inspecting the source bodies. This review therefore does not upgrade those facts to newly verified evidence.

ADR-0004 Q-B's required batch support is represented in U8, including refusal of unsafe script paths. No contradiction was found in that choice; native injection, quoting and full 32-bit exit-code tests remain necessary.

## Exit mapping, native feasibility and owner inputs

The mapping covers all six required cases, but currently describes a **planned** suite. No M02 pass claim follows from this review.

- **A01:** WSL/container disposable homes are appropriate for default-path ordinary SSH. Scratch `-F` on macOS/Windows proves only the scratch configuration path. Their native ordinary-path rows correctly remain blocked.
- **A11:** FakeAgent states prove Heimdall's classification against fixtures, not live 1Password lock/approval behavior. Add the confirm-constrained native-agent case from M2-D05.
- **A21:** The passive canary/contact counters are useful. Explicit-level claims need M2-D06's corrections.
- **A22:** Extend fault coverage to an already-active P, final-check races, same-content replacement generations and Windows reparse points. CRLF/BOM byte preservation tests do not alone prove the target client accepts the file; either demonstrate acceptance or refuse unsupported encodings without modification.
- **A27:** The planned native Unix/Windows process tests are appropriate. Correct launch metadata under M2-D07. A documentation-only SIGPIPE test records a limitation; it does not prove inherited signal-disposition fidelity.
- **A35:** Correct the fixture override and inherited-key tests. Fake Windows pipes do not close system-agent or 1Password rows.

**Feasibility assessment, inference:** The M01 remote-runner patterns provide a credible basis for Linux and Windows scratch execution. The proposed macOS non-root sshd attempt with an explicit Docker fallback is reasonable. Windows-client-to-WSL-loopback connectivity must be checked on the actual host before using it; harness failure must remain visible. A fallback also needs enough fixture control to configure accepted keys, `MaxAuthTries`, host-key substitution and accepted-fingerprint logs.

The disposable WSL distribution is expressly authorized by ADR-0004. Its evidence remains WSL Linux evidence; container runs remain supplementary. Neither closes native macOS, Windows or Linux arm64 gaps.

**Owner inputs:** B1–B6 and B9 identify concrete physical/account/platform gaps. B7 appropriately separates a human walkthrough from automated fixture evidence. B8 correctly says it blocks nothing in the proposed exit. I found no reason to block parser, renderer, fixture, projection or process implementation on these inputs. The unresolved source excerpts, transaction details and shared-code ownership are engineering work, not owner-only blockers.

## Commands and validation

The following read-only command groups were executed; repeated `sed`/`nl` selections are grouped for readability.

| Commands run | Exit/result |
|---|---|
| `pwd`; `git rev-parse HEAD`; `git status --short`; reviewer's own instruction file; targeted `rg` of the memory registry | Initial combined invocation **1**, from the memory search finding no Heimdall match. HEAD matched the requested commit; status was empty. |
| `nl -ba`, `sed -n`, and `rg -n` over M02 plan, ADR-0007, spec, plan, ADR-0004/0005/0006, architecture and G03 research | Successful document-read invocations **0**. |
| `rg --files` inventories of crates, sources, native harnesses and evidence; `ls -d tests/fixtures/ssh/*` | Inventories inspected; successful invocation results **0**. |
| `cat`/`sed`/`rg` over M01 ports, decision/profile/operation types, request types, operations, paths and reconciliation code | Files read successfully. One guessed `cat crates/contract/src/bind.rs` returned **1**: file absent; actual bind definitions were subsequently inspected in `request.rs`. Its containing multi-command invocation ended **0**. |
| Python standard-library `gzip` readers over committed `S01.txt.gz` and `S02.txt.gz` | **0**. Initial line-oriented extraction produced no excerpts because normalized snapshots are single-line text; subsequent substring extraction produced the cited sections. |
| `sed` over `tests/native/m01/run-linux.sh` and `run-windows.sh` | **0**. Scripts read, never executed. |
| `sed -n '1,160p' tests/fixtures/ssh/MANIFEST.md` | **1**, incorrect guessed path; no file changed. |
| `rg` including guessed `tests/native/windows/pins.json` | **2** for the missing path; containing pipeline/invocation ended **0**. No source-body verification is claimed from it. |
| `git diff --exit-code`; `git diff --stat`; `git status --porcelain=v1`; `test ! -d target` | **0**; no diff, clean status, checkout `target/` absent. |

**Changed files:** none. No commit, push, artifact write or native operation was performed.

Not run: `bash tools/validation/check.sh`, builds, native harnesses or network source retrieval. Runtime/platform behavior remains unverified; the findings above must be resolved before treating this design as ready for implementation waves.
