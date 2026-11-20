merge

Scoped independent re-check of **`ddbdc295..0e47249ed352e232dc497933b57bb41fe899c5d5`**, one commit, 22 files, +2,117/−139 lines. The merge at the start of the range was excluded. Platform: Darwin arm64; rustc and cargo **1.99.1**.

**R01 and R02 are fixed; I-20 is sound in the examined paths. R03 is only partly fixed:** its named detail renderers are safe, but the complete trust and reconcile prompts still emit raw bidi in their second, JSON-formatted copy of the recorded request. This is **M05-W3-RC01, Medium, nonblocking**. Under ADR-0009 §2.1, the demonstrated presentation defect has neither a demonstrated lasting data/trust effect nor a demonstrated consent bypass, so it does not change the merge verdict.

This is the one requested scoped re-check. No nested reviewer, implementation, commit, push, or PR was performed. The only retained additions are this report and supporting artifacts under `review-out/`; all temporary tracked edits were restored byte for byte.

## Setup and scope

| Executed command | Exit | Observation |
|---|---:|---|
| `git fetch origin m05/w3` | 0 | Fetched the requested branch. |
| `git checkout --detach 0e47249ed352e232dc497933b57bb41fe899c5d5` | 0 | Detached at the requested fix commit. |
| `git rev-parse HEAD` | 0 | `0e47249ed352e232dc497933b57bb41fe899c5d5`. |
| `git rev-list --count ddbdc295..0e47249e` | 0 | `1`. |
| `git diff --stat ddbdc295..0e47249e` | 0 | 22 files, +2,117/−139. |
| `rustc --version`; `cargo --version`; `uname -sm` | 0 each | Rust/cargo 1.99.1; Darwin arm64. |

Read R01–R03 in [the archived W3 review](tests/evidence/artifacts/review-m05/w3.md:7), [ADR-0009 §2.1](docs/decisions/0009-delivery-economy.md:27), ADR-0011 §7.3 and §10 I-20, and ADR-0006 §17.10 item 22. Traced changed functions through their callers and adjacent approval, recovery, slot materialization, and rendering paths. No finding is raised about the excluded merge or unrelated earlier work.

## 1. R01: recorded create scope and every built-in approval surface

**The recorded scope matches what approval applies.** [decision_scope](crates/app/src/operations.rs:5564) reads the decision's `DecisionBasis::Create.profile_revision`, then the immutable snapshot at that revision. It takes environments from the stored action and uses the same default lock behavior as [apply_widening](crates/app/src/operations/trust_m05.rs:1767). Approval independently refuses a missing basis or snapshot as stale. A catalog edit cannot silently replace the approved snapshot with the newest profile.

**Scope is confined to create records.** The helper first matches `WidenPolicy { Create }`; all other kinds return `None`. The inspect loop inserts the key only for `Some`. This includes omission for `extend_scope`, targeted resume/clear-cutoff/cutoff, and M01 forms. The diff changes only the revision-5.2 golden; earlier revision-5/5.1 goldens and schema text are untouched. Contract tests, including `rev5::rev5_2_decision_scope`, pass. The golden test checks serialization and omission; the real setup regression separately checks production inspect output and absence on an actual `extend_scope` record.

**Setup:** [offer_personal_default](crates/heimdall/src/setup_cmd.rs:635) derives the disclosure from the same inspected decision entry that supplies the recorded request, rather than its earlier profile listing. Missing/malformed scope prevents the question and Decide request. Its catalog-edit regression passes and compares the resulting policy's pairs, capabilities, environments and lock behavior with the shown record.

**CLI and JSON-mode workflow:** all create approval routes through [confirm_and_decide](crates/heimdall/src/cli.rs:2237), which checks `approve_block` before prompting. [create_review](crates/heimdall/src/m05_cmd.rs:539) displays the recorded revision, pairs, capabilities, environments and lock behavior. `--json` does not bypass this attended prompt. I temporarily changed the existing create-review test's context to `json: true`: it still verified disclosure and that missing/malformed scope sent no Decide, then restored the source exactly. The untyped inspect JSON contains the typed scope for external consumers; arbitrary IPC clients are not required to echo it as an approval argument. Server approval still requires the stored basis/snapshot. The documented same-user attendance limit is unchanged.

**TUI:** [Decision::scope](crates/heimdall/src/tui/data.rs:305) is parsed from the decision, and create detail uses its revision and scope. [the modal send path](crates/heimdall/src/tui/model.rs:1635) invokes the M05 refusal before sending Approve. Malformed/missing scope is refused; Deny remains available. The existing read-to-end confirmation gate remains in place.

Executed checks: setup **15 passed**; contract **145 passed**; TUI **65 passed**; M05 renderer tests **4 passed**; additional JSON-context create review **1 passed**, all exit **0**. Commands and logs are listed below.

## 2. R02: transactional background-bind eligibility and recovery

**The guard and claim share one write transaction.** The internal default bind records and hashes its planned policy/revision. [drive_bind_pass](crates/app/src/operations.rs:10110) loads the durable marker and calls `background_bind_refusal` in the same `self.write` closure that later calls `claim_bind_slots_in`. Time is assessed by that transaction's gate. The re-derived plan checks pause, cutoff, default identity/revision, automatic activation, covered scope, and current usable binding/work; work stop is checked in bind admission and current-binding selection. The grant's recorded policy context receives an additional block check. Malformed internal markers fail closed.

**Slot files follow a successful committed claim.** Filesystem writes are deliberately outside SQLite: [drive_bind](crates/app/src/operations.rs:10002) writes them only if the first pass returns a claimed binding. A refusal returns no binding, so the materializer is not called. This is the amended claim-as-activation boundary: a pause committed before the claim prevents it; a pause committed after a valid claim does not retroactively revoke continuing work.

**Other background routes and recovery:** default new work goes through covered-only ensure and then this same marked bind; there is no second unmarked default-bind call site. Restart recovery drives stored `OperationKind::Bind` through the same first pass, with `slots_ready = false`, even if slot references already exist. A paused plan refuses before the `Step::Active` case can allow re-drive.

I also executed a recovery probe, with one explicit scheduling seam: temporarily stop `drive_bind` immediately after the actual first-pass claim, before files or settlement. A real default activation left an open bind containing `m05_default_bind`; a production owner pause then committed. After dropping the old in-process runtime and starting a new one over the same store, recovery settled that bind with **`POLICY_PAUSED`**, preserved the claim, and wrote **zero slot files**. **Exit 0, 1 passed.** This is an interrupted-driver seam, not a physical OS-crash test. The production source and test file were restored exactly.

**Foreground semantics:** client `bind` calls `bind_with(..., None)`, preserving `Activation::Existing`. My independent foreground probe paused the actual policy, successfully launch-bound the existing binding, and verified its slot was held. **Exit 0, 1 passed** as part of the two independent binding probes.

**Hash compatibility:** `None` leaves the original `{"binding_id", "form"}` extra unchanged. Only internally marked background binds add `m05_default_bind`; public wire structs and other hash constructors are untouched. The stored marker and hash marker are built from the same value. This is source tracing plus passing existing tests, not a new exhaustive hash-golden test.

**Independent revert proof:** removed only the first-pass background refusal block, ran `paused_default_never_binds_an_existing_work_to_the_alias`, and observed **exit 101, 0 passed/1 failed**: actual `Activated`, expected `Blocked(policy_paused)`. Restored the file byte for byte and ran the identical command: **exit 0, 1 passed**. The original regression also exercises a cutoff racing the bind and verifies unchanged binding, free slot and no slot files. A final clean-source rerun after the separate recovery probe passed again.

## 3. I-20: reuse only current-default personal bindings within coverage

[current_binding](crates/app/src/operations/default_activation_m05.rs:318) requires:

- active binding and a usable, unexpired grant;
- exact pair equality, expressed as subset checks in both directions;
- binding capabilities contained in the default's current covered capabilities;
- grant origin `policy_id == current default` and `workspace == None`;
- no work stop.

A rejection leaves that binding alone and causes the plan to choose work n+1. The committed test for a default moved to another policy passes in the nine-test live default suite. Workspace-origin and extra-capability rejection were source-traced at the explicit predicates; I did not add separate dynamic probes for those two cases.

**Independent wider-binding probe:** seeded two managed pairs, created a genuine unslotted work-1 binding for both through `Operations::ensure` under the current personal default, then narrowed the latest profile snapshot to one pair. Thus the existing binding remained under the same current default policy but was wider than its current covered set. Production `activate_default` started **work 2**, with only the remaining pair. The old binding was byte-equal to its original record, held no slot references, and the excluded pair had no slot references. **Exit 0, 1 passed**, alongside the foreground-pause control. No synthetic replacement of `current_binding` was used.

## 4. R03: quoted fields, filtering, and complete human output

The three named detail renderers now use `quoted_field`: workspace cwd/root, first-trust directory/label, and reconcile directory. The M05 renderer tests pass; the real-binary status regression passes and confirms `--json` preserves the original path.

The new field renderer escapes quotes, backslashes, all C0/C1 controls (including ESC), line/tab/paragraph separators, and removes the listed Unicode format characters. I independently parsed its ranges and compared them against Python's **Unicode 17.0.0** database: **170 Cf code points, zero missing**. The quoted-field test also passed for escape sequences, line breaks, C1 U+0085, bidi controls and tag characters. TUI safe/quoted text uses the same format-character class.

**The full human-output claim still fails.** Generic confirmation appends `serde_json::to_string_pretty(record.request)` after that safe detail view. JSON escaping prevents a literal newline from the path, but leaves U+202E intact; the final human prompt sanitizer does not remove Cf. My real-binary/real-runtime pseudo-terminal probe completed both a trust and a re-clone reconcile in a directory containing newline and U+202E. Each safe detail was present, yet each complete prompt contained **one raw U+202E**, specifically in `"cwd"`. **Exit 101, 0 passed/1 failed**, at the intended assertion that both complete prompts contain zero bidi characters. See RC01.

## 5. Executed validation and artifacts

All six requested suites ran on the untouched requested head before temporary probes: **421 passed, zero failed, zero ignored**. App counts below are its five executable test targets; doc-test counts are zero. Logs redact account-home prefixes and fixture-token patterns before being written.

| Command | Exit | Actual counts | Log |
|---|---:|---|---|
| `cargo test --locked -p heimdall --bin heimdall setup_cmd` | 0 | 15 passed, 0 failed, 276 filtered | [setup.log](review-out/setup.log) |
| `cargo test --locked -p heimdall --test e2e_cli_m05` | 0 | 9 passed, 0 failed | [cli-m05.log](review-out/cli-m05.log) |
| `cargo test --locked -p heimdall-runtime --lib managed_store::live_tests::default_m05` | 0 | 9 passed, 0 failed, 74 filtered | [default-m05.log](review-out/default-m05.log) |
| `cargo test --locked -p heimdall-contract` | 0 | 45 unit + 100 contract passed, 0 failed | [contract.log](review-out/contract.log) |
| `cargo test --locked -p heimdall --bin heimdall tui` | 0 | 65 passed, 0 failed, 226 filtered | [tui.log](review-out/tui.log) |
| `cargo test --locked -p heimdall-app` | 0 | 75 + 4 + 16 + 54 + 29 = 178 passed, 0 failed | [app.log](review-out/app.log) |
| `cargo test --locked -p heimdall --bin heimdall m05_cmd` | 0 | 4 passed, 0 failed, 287 filtered | [m05-renderers.log](review-out/m05-renderers.log) |
| `cargo test --locked -p heimdall --bin heimdall output::tests::a_data_field_is_one_inert_quoted_token` | 0 | 1 passed, 0 failed, 290 filtered | [quoted-field.log](review-out/quoted-field.log) |
| `cargo test --locked -p heimdall-runtime --lib managed_store::live_tests::default_m05::reviewer_` (temporary wider/foreground probes) | 0 | 2 passed, 0 failed, 83 filtered | [independent-bindings.log](review-out/independent-bindings.log) |
| `cargo test --locked -p heimdall --test e2e_cli_m05 reviewer_full_trust_and_reconcile_prompts_are_bidi_free -- --nocapture` (temporary probe) | 101 | 0 passed, 1 failed, 9 filtered; raw bidi counts `[1, 1]` | [full-prompts.log](review-out/full-prompts.log) |
| `cargo test --locked -p heimdall-runtime --lib managed_store::live_tests::default_m05::paused_default_never_binds_an_existing_work_to_the_alias` (guard removed) | 101 | 0 passed, 1 failed, 82 filtered | [r02-reverted.log](review-out/r02-reverted.log) |
| Same command (guard restored) | 0 | 1 passed, 0 failed, 82 filtered | [r02-restored.log](review-out/r02-restored.log) |
| `cargo test --locked -p heimdall --bin heimdall m05_cmd::tests::a_create_review_shows_the_recorded_scope_or_refuses` (context temporarily `json: true`) | 0 | 1 passed, 0 failed, 290 filtered | [json-create-review.log](review-out/json-create-review.log) |
| `cargo test --locked -p heimdall-runtime --lib managed_store::live_tests::default_m05::reviewer_recovery_of_claimed_background_bind_fails_closed_on_pause` (temporary interrupted-bind seam) | 0 | 1 passed, 0 failed, 83 filtered | [recovery-background-bind.log](review-out/recovery-background-bind.log) |
| Original paused-bind regression again, after restoring recovery seam | 0 | 1 passed, 0 failed, 82 filtered | [final-restored.log](review-out/final-restored.log) |

Probe sources are retained for reproduction: [wider/foreground](review-out/wider-binding-probe.rs), [complete prompts](review-out/full-prompts-probe.rs), and [recovery](review-out/recovery-bind-probe.rs). The revert-proof guard fragment and restoration hashes are also retained under `review-out/`.

## Findings

### M05-W3-RC01 — Medium; nonblocking — R03 leaves raw bidi in the complete trust/reconcile prompt

**Locations:** [cli.rs:2277](crates/heimdall/src/cli.rs:2277), [cli.rs:2302](crates/heimdall/src/cli.rs:2302), and [output.rs:260](crates/heimdall/src/output.rs:260). This is an incomplete fix of R03, not a new review of unrelated rendering.

**Concrete scenario:** the owner runs `project trust`, or reconciles a re-cloned checkout, from a directory containing U+202E. The newly safe directory-detail line removes it, but the same confirmation prompt then prints the recorded request's `cwd` via pretty JSON, which retains it. The human-only terminal sanitizer drops controls/ESC sequences but allows Cf. A real pseudo-terminal run observed **one raw U+202E in each complete prompt**, despite the safe detail line. The current regression checks status; the renderer unit test checks only `recorded_preview`, so neither checks this second copy.

**Smallest correction:** filter format/bidi characters in the shared human-only sanitizer, or escape them in the human recorded-request rendering, while preserving machine `--json` data. Extend the existing path regression to inspect complete trust and reconcile prompts, not just their detail builders.

**Why it does not block:** the directory is an ordinary-user trigger, but this probe demonstrates presentation corruption only. It does not demonstrate a lasting remote-trust/recovery/data effect or an approval of different authority from that recorded. Therefore both ADR-0009 §2.1 conditions do not hold, matching the original R03 classification. No terminal code execution or consent bypass is claimed.

## Limits, final state, and risks

- Native Windows/WSL verification is **blocked** by the missing native Windows/WSL platform in this checkout session. No devbox run, full validation script, release build, native keychain/lock claim, or new remote-login claim was made. The requested host suites use their own disposable adapters, stores, certificates, loopback SSH fixtures and scratch homes.
- Workspace-origin and extra-capability I-20 refusal were checked in source; the independent new live probe covers the requested wider-pair case. Recovery used the explicitly described interruption seam rather than a real machine crash. Hash compatibility was traced, not exhaustively regenerated.
- No direct manual `ssh` invocation was added. CLI probes used the existing real `target/debug/heimdall` harness, with separate scratch `HOME` and `HEIMDALL_HOME` environment entries and no owner SSH agent. No owner keys, shell rc files, SSH configuration, keychain or password manager were read or changed.
- Probe runtimes were stopped by the harness's scratch-home service stop or in-process cancellation/drop. A sanitized exact-PID process inventory found only two pre-existing `heimdall` processes, started at 05:03:57, with neither this worktree nor the probe scratch roots referenced; neither was stopped. No probe-owned runtime remained. No blanket process termination was used.
- Temporary-path deviation: the two probe runners used **two sequential** `/tmp/hm-recheck-*` roots rather than retaining one root for the whole review. Both were removed, including their fixture material. Test-harness-owned temporary fixtures used their existing cleanup behavior.
- `git diff --exit-code` returned **0**; `git status --short` showed only **`?? review-out/`**. All temporary tracked edits were restored to the requested commit. `./target` and `review-out/` were preserved as explicitly requested; no build outputs were deleted. The prototype hygiene `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` ran through bash and returned **1** because all three globs had no matching directories. The workspace target occupied **8.7 GB** at the final measurement; the orchestrator owns its removal.
- Remaining product risk: RC01 still permits bidi presentation corruption in complete human trust/reconcile prompts. R01's consent disclosure and R02's transactional activation fence passed their scoped checks.
