# M01-T00-design-review-round2 — `f9ed3454909a3f334ccf81648e2acef351ad0ba1`

Reviewer: Codex GPT-6.1 Sol (reasoning effort high), independent, read-only, in a separate
worktree at the reviewed commit. Saved verbatim by the orchestrator on 2026-10-31.

**Verdict: proceed after fixes.** The revision supplies most of the missing architecture, but wave 2 should not implement the current time, issuance, and event contracts unchanged. Five major findings and one minor finding remain below.

This is an independent, read-only static review. File contents and Cargo target discovery were observed. Behavioral counterexamples are **inferences from code**, except for the explicitly identified arithmetic check. Planned wave-2 `todo!` bodies are not findings by themselves. No files were changed, committed, or pushed; no network host was contacted.

## Resolution of F01–F10

"Resolved" means the original design/interface defect is addressed; it does not mean the future application/runtime behavior has been verified.

| Finding | Status | Documentation evidence | Code evidence and remaining limit |
|---|---|---|---|
| **F01 — time model** | **partially** | ADR-0006:448–503 specifies boot-scoped continuous time, persisted high-water, shared gate, grant budgets and tolerance deductions. | `crates/domain/src/time.rs:377–454,519–586` implements the pure rules; `crates/store/src/ext.rs:134–221` persists them; `crates/app/src/operations.rs:60–75,151–154` exposes shared gate/hook inputs. **N01, N02 and N05 remain.** `TimeGate` wiring is still pending at `crates/app/src/timegate.rs:105–152`. |
| **F02 — expired request keys** | **resolved** | ADR-0006:368–385 makes pending keys non-expiring, starts retention at settlement, leaves markers, and explicitly documents reuse beyond the marker window as unsupported caller behavior. | `crates/domain/src/idempotency.rs:149–164` distinguishes live markers from new requests; `crates/store/src/lib.rs:724–760` leaves markers on purge; `crates/store/src/ext.rs:234–260` provides settlement. Migration `0002_design_fix.sql:7–39` preserves unsettled keys. This is a **bounded retry guarantee**, not indefinite deduplication. |
| **F03 — attended confirmation / decisions** | **partially** | ADR-0006:194–226 defines exact, generation-bound decisions and attended completion; :688–694 still requires an explicit confirmation step. | `crates/domain/src/decision.rs:23–42,103–124` and `crates/store/src/ext.rs:376–405` supply completion and consume-once persistence. `crates/ipc/src/session.rs:763–779` gates completion and establishes session attendance. **N04:** attendance is sufficient for later widening actions without a specified action-specific confirmation. |
| **F04 — store completeness** | **resolved** | ADR-0006:624–640 lists bindings, snapshots, environments, policy and ancestor-denial reads. | `crates/store/src/ext.rs:426–558` supplies binding/reference ownership and repeat release; :567 onward supplies immutable profile snapshots and related lookups. Migration `0002_design_fix.sql:55–74` supplies the binding columns and snapshot table. Public APIs now support the previously missing operations. End-to-end use is pending U5/U8. |
| **F05 — recoverable intent / receipts** | **resolved** | ADR-0006:590–604 requires durable resolved intent and an `Attempted` receipt before effects, followed by reconciliation. | `crates/domain/src/operation.rs:134–206` carries pinned intent, adapter identity and effect receipts; `crates/app/src/ports.rs:100–140,165–171` supplies effect tokens and reconciliation; `crates/store/src/ext.rs:107–127,740–763` preserves immutable intent and ordered receipts. Actual process-crash evidence remains pending; see N06. |
| **F06 — issuance substrate** | **partially** | ADR-0006:75–81 adds the issuer boundary; :606–622 defines reserve/publish/void and conservative residual accounting. | `crates/domain/src/issuance.rs:24–145` supplies records; `crates/store/src/ext.rs:773–880` supplies transactions and residual reads. **N02:** the advertised refusal predicate omits required checks, including continuous-budget expiry. |
| **F07 — unknown versus final outcome** | **resolved** | ADR-0006:253–262 distinguishes active, settled and unresolved states and excludes unresolved records from retention purge. | `crates/contract/src/state.rs:37–58` implements the classifications; `crates/store/src/ext.rs:949–958` lists unresolved operations; `crates/store/src/lib.rs:724–730` purges settled operations only. Runtime reconciliation remains wave-2 work. |
| **F08 — snapshot/replay/live events** | **partially** | ADR-0006:387–418 defines neutral sequences, snapshot boundaries, receiver-before-read ordering and client subscription APIs. | `crates/app/src/events.rs:71–85` and `crates/ipc/src/session.rs:182–198` represent the handoff. Session code sends backlog before live and filters overlap at :695–697,875–907. **N03:** oversized-event replacement advances the stored cursor across an undelivered event. |
| **F09 — executable acceptance harness** | **partially** | `docs/architecture/m01-plan.md:22–38` assigns actual Cargo targets and production fault hooks; :269–278 assigns exit evidence. | Cargo metadata confirms existing contract, authority, lifecycle, time, store and IPC targets. `OperationsConfig.stage_hook` exists at `crates/app/src/operations.rs:73–75`; `tools/validation/check.sh` checks discovered target counts. Wave-2 targets remain to be added. **N06:** the acceptance definitions still omit consequential recovery/cleanup evidence. |
| **F10 — required capabilities** | **resolved** | ADR-0006:119–126 explicitly requires `required ⊆ negotiated`. | `crates/ipc/src/session.rs:131–140` computes the intersection before checking the subset. Client verification also checks required capabilities at :1131–1138. |

## New findings

### N01 — major — Shortening a tolerance-adjusted budget loses its safety margin

**Location:** `crates/domain/src/time.rs:519–550`.

**Defect:** `anchor_grant_with_tolerance` subtracts uncertainty from the budget, but `shorten` recomputes the new bound using ordinary `anchor_grant`, discarding that adjustment. Taking the minimum with the old budget prevents lengthening the old budget; it does **not** ensure enforcement of a newly earlier cutoff.

**Evidence:**

- ADR-0005:318–325 requires an earlier cutoff to shorten the budget and defines admission by the earlier absolute/continuous limit.
- ADR-0006:491–497 promises tolerance-adjusted re-anchoring is "early, never late."
- Code at `time.rs:525–530` uses `wall + tolerance`; code at :547 instead calls `anchor_grant(..., new_bound)` without that tolerance.

**Counterexample — inference from code; arithmetic independently checked:** Let anchor wall and continuous readings be zero, actual time be 60 seconds later, tolerance be 60 seconds, and the old absolute bound be 3600. The safe budget ends at continuous 3540. Narrow the bound to 3570. `shorten` returns `min(3570,3540) = 3540`; the correct adjusted end is 3510. With the wall consistently 60 seconds behind, admission can continue **30 seconds past the new cutoff**.

The model trace generator at `tests/model/time.rs:1103–1133` has no cutoff/shorten step, so its true-bound property does not exercise this composition.

**Fix:** Shorten the existing continuous budget by the absolute bound reduction, using saturating subtraction, or persist and preserve the original uncertainty adjustment. Add a regression combining tolerance-aware anchoring, cutoff narrowing, wall lag, and admission at the new true bound.

### N02 — major — The issuance predicate does not implement its advertised refusal list

**Location:** `crates/domain/src/issuance.rs:151–229`; `crates/store/src/ext.rs:843–846`.

**Defect:** `issuance::check` claims to implement ADR-0005's refusal list, but:

1. It receives only wall `now` and `TimeStatus`; it cannot evaluate a grant's continuous-budget expiry.
2. It never validates `bounds.principal` against the selected destination/account.
3. It never checks `bounds.extensions` against granted permissions.
4. Its generation check covers the grant only. There is no explicit comparison of expected/current policy or ancestor revisions, nor a requirement that a delegated grant supply its recorded parent.

Store publication performs a reserved-state CAS and delegates predicate enforcement to the caller.

**Evidence:**

- ADR-0005:229–245 requires publication to reapply **every** predicate, including the §3.6 deadline.
- ADR-0005:262–274 requires ancestor/policy revision checks, correct principals and permitted extensions.
- ADR-0006:612–615 assigns those predicates to `check(IssuanceCheck)`.
- Code checks pair membership at :191–197, wall bounds at :199–218, a subject-registration boolean at :220, a critical-option boolean at :223, and time confidence at :226. It never reads the principal or extensions.

**Consequences — inference:** A grant can have `TimeStatus::Safe` while its continuous budget has expired—for example, a wall lag still inside the skew tolerance. `check` can return `Ok(())`. Likewise, an otherwise valid input with an incorrect principal or unauthorized extension passes this predicate.

The module's tests at `issuance.rs:244–283` exercise residual accounting, not the refusal predicate.

**Fix:** Complete the shared predicate before U5 builds A07 around it: include current continuous admission evidence, validate exact principal and extension permissions, and represent/check required parent and policy revision expectations. Add refusal tests and reserve/publish interleavings that invoke the production predicate.

### N03 — major — Oversized-event resync advances past the missing event

**Location:** `crates/ipc/src/session.rs:699–734,887–901,943–968`.

**Defect:** `send_event` replaces an oversized event with `ResyncRequired` but returns `Ok(())`, indistinguishable from delivery of the original event. Both live and backlog paths then retain a cursor past the undelivered event.

**Evidence:**

- Spec:597 requires at-least-once events and resumable observation without silently missing state.
- ADR-0006:406–412 requires resync to carry the last delivered cursor.
- The live path updates `state.last_cursor` at :701 **before** calling `send_event`.
- `send_event` emits resync at the old cursor at :958–966 but reports ordinary success.
- The backlog path advances `last` unconditionally at :896 and initializes live state to the boundary cursor at :901.

**Consequence — inference:** After an oversized event is replaced, a later lag/resync can advertise a cursor beyond that event. The subscription continues without requiring completion of a fresh snapshot. The initial resync warning does not preserve the promised last-delivered position for subsequent recovery.

**Fix:** Return an explicit delivery outcome from `send_event`. On replacement, preserve the prior cursor and terminate or suspend the subscription until resync. Apply the same rule to backlog delivery. Test oversized backlog/live events followed by further publication, lag and reconnect.

### N04 — major — Session attendance substitutes for the required explicit confirmation

**Location:** ADR-0006:207–224,560,688–694; `docs/architecture/m01-plan.md:255–265`; `crates/ipc/src/session.rs:777–779`.

**Defect:** The revision retains the requirement for an explicit confirmation step but also says an attended session executes widening policy actions directly because "the session is the confirmation." U9 specifies TTY detection plus `Attend` before owner-present actions, without requiring the confirmation prompt or binding confirmation to the selected action.

**Evidence:**

- ADR-0006:688–691 requires an attended interactive confirmation with an **explicit confirmation step**.
- ADR-0006:210–211 instead permits direct execution on an attended session.
- IPC accepts `Attend` based only on the hello's interaction mode and keeps the resulting session-wide boolean.
- `crates/app/src/context.rs:52–60` similarly treats attendance as sufficient and permits attendance solely from interaction mode.

**Consequence — inference:** A conforming U9 implementation can send `Attend` automatically whenever stdin is a TTY, then resume or clear a cutoff without showing the owner the action and asking for confirmation.

This finding concerns the specified owner workflow. Same-user imitation remains the explicitly disclosed limitation; it is not a newly claimed security boundary.

**Fix:** Require an explicit affirmative CLI/TUI confirmation after displaying the exact action or decision. Specify cancellation/EOF behavior and tests. Either bind attendance to that action or state clearly that session attendance alone does not authorize the client to skip confirmation.

### N05 — minor — Reboot acceptance contradicts ADR-0005, and §13.3 narrows its threat model

**Location:** `crates/domain/src/time.rs:380–395`; ADR-0006:582–586; `tests/model/time.rs:1081–1095`.

**Defect:** The gate applies the rollback tolerance before the reboot synchronization branch, allowing synchronized reboot time below the high-water mark. The model test explicitly expects acceptance four seconds below it. ADR-0005 requires reboot time to be at or above the mark.

Separately, §13.3 declares a wrongly synchronized report outside ADR-0005's threat model, although that ADR covers accidental clock/sync faults and explicitly identifies unreliable synchronized-time signals as a reopen condition.

**Evidence:**

- ADR-0005:333–341 says reboot acceptance requires **both** at/above high-water and synchronization.
- `time.rs:380–387` refuses only a deficit greater than the tolerance; :392–393 then accepts synchronization.
- ADR-0005:303–306 includes accidental faults; :1088 onward requires reopening the rule if the signal reports synchronized while wrong under those faults.
- ADR-0006:585–586 instead excludes that case.

**Assessment:** The rollback deduction mitigates the immediate budget risk; this is a concrete contract inconsistency, not proof of an additional authority extension. Platform synchronization reliability is still unverified.

**Fix:** Enforce the strict reboot high-water condition unless the explicit owner-confirmation path applies. Align tests and ADR-0006. Describe truthful synchronization as an assumption requiring native evidence, preserving ADR-0005's reopen condition.

### N06 — major — Wave-2 exit coverage still omits actual cleanup races and process-loss reconciliation

**Location:** `docs/architecture/m01-plan.md:146–174,238–248,269–278`; `crates/testkit/src/lib.rs:221–236,259–294`.

**Defect:** Two required evidence paths remain underspecified:

- U8's "A17 local" tests cover attempted-receipt recovery, pause and identity persistence, but omit generation-N cleanup racing replacement N+1 **at the actual deletion boundary**, and repeated dependency failures with bounded retry ownership.
- U5's lost-reply/restart scenario can pass by retaining the same in-memory fake adapter. A new fake starts with an empty effect map; `reconcile` then reports `NotApplied`. That cannot establish one-effect reconciliation across actual service-process death where the external effect survives.

**Evidence:**

- Plan:438 requires cleanup of N never delete N+1.
- Plan:446 requires killing the service while the caller waits and replacing sockets.
- Spec A17:1084–1086 explicitly requires the replacement-cleanup race and a single bounded supervisor.
- U8's assigned tests at `m01-plan.md:238–248` omit that race.
- `FakeCredentialAdapter::new` creates an empty map at `testkit/lib.rs:228`; reconciliation equates absence from that map with `NotApplied` at :291–294.

**Consequence — inference:** U10 can assemble the listed tests and still lack evidence for stale-cleanup protection and service-death A06 recovery. In-process reconstruction is useful evidence but must not be labeled process-crash verification.

**Fix:** Add explicit U8/U10 acceptance cases for actual resource replacement and cleanup, plus repeated unavailable-provider failures. For service-death A06, use a disposable effect ledger that survives the killed service process, or a separate local fixture process. Verify the effect count after restarting both service and client. Also add the §13.3 pending-approval deadline-expiry case explicitly to U5's acceptance list.

## Commands run and exit codes

| Command / inspection | Observed exit |
|---|---:|
| `pwd`; initial and final `git status --short`; `git rev-parse HEAD` | **0** each; status clean, HEAD unchanged |
| reviewer's own global instruction file (read) | **0** |
| reviewer's memory search for project facts | **1** — no matches; no project memory facts used |
| `cat`, `nl -ba`, `sed`, `rg` and `rg --files` inspections of the original review, spec, plan, ADRs, architecture, crate sources, manifests, migrations and tests cited above | **0**, except the no-match search below |
| `rg -n 'shorten\|Cutoff' tests/model/time.rs` | **1** — no matches |
| `git diff --stat f5616784..HEAD` | **0** |
| `cargo metadata --offline --locked --no-deps --format-version 1` piped to a Python package/target-name filter | **0** pipeline; listed the existing test targets and no runtime/application exit-suite target |
| In-memory Python assertions reproducing `time.rs:525–550` budget arithmetic | **0** — observed old/returned end **3540**, required narrowed end **3510**, possible overrun **30 seconds**; this was not execution of the Rust function |

**Changed files:** none. No build outputs or review artifacts were created.

**Not checked:** Rust test execution, native clocks/IPC/custody, or end-to-end runtime behavior.
**Risk:** passing existing tests would not close the missing issuance predicates, tolerance-shortening regression, event-resync behavior, or process-crash evidence identified above.
