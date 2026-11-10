# M03 wave 0: questions and escalations from agent R (runtime rows 6, 7 supervisor, 8, 13, 14, 17, 23, 28; E7; §5 item 22)

Each item names the fail-closed reading built now. None is decided by R.

## R1. Row 23: what "resumes at start" may do without an issuer child (escalated reading)
* ADR-0008 D4 item 3 (`docs/decisions/0008-managed-credential-integration.md:899–909`): `retiring → unloaded`
  needs the child's unload confirmation; `unloaded → deleted` needs the store item deleted and a re-read finding it
  absent; `deleted → retired` needs nothing external. Wave 0 has no issuer child and no store step.
* Built: `Operations::resume_ca_retirements(issuer: Option<&dyn IssuerPort>, store_items: Option<&dyn
  CaStoreItemDeletion>)` (`crates/app/src/operations/restart_m03.rs`). Each step is a CAS persisted only after its
  effect is confirmed. Restart recovery calls it with `None, None`: `retiring` and `unloaded` stay (listed
  `stalled`), **`deleted → retired` completes** (store-only step; the plan names only `retiring`/`unloaded`, the ADR
  says "each step is idempotent"). `do_not_load` = every CA not `pending`/`active`: the value U3 must hand to the
  issuer child ("told not to load a `retiring` CA"); wave 0 has nobody to tell, so it is only returned and logged.
* `CaStoreItemDeletion` is a new small **synchronous** trait in `app::operations` (the issuer crate's `SecretStore`
  is synchronous), not in `app::ports` (A2's file). Options: (a) keep it there; (b) move it to `app::ports` beside
  `IssuerPort` (integrator/A2). Also: should `deleted → retired` wait for an issuer as well (option: stop at
  `deleted`)? R's reading: complete it.

## R2. Row 28 / E9: the shared parser has no start-time-only entry
* `heimdall_domain::procstat` exposes only `parse`, which requires the process group ≥ 1 (`procstat.rs:57`). E9
  reading (a) asks for "a start-time-only entry … or an equivalent".
* Built (equivalent, in `crates/runtime/src/platform.rs::stat_start_time`): call `parse`; if it refuses with
  `BadProcessGroup` alone, call `parse` again on the same text with that one token read as `1`; then apply the
  `Z`/`X` rule. All other validation is the shared parser's. The test keeps the old rule verbatim as the oracle and
  agrees on > 1000 synthetic lines (group 0 included).
* Documented deltas, all for text no kernel produces: a multi-letter state (old accepted, new refuses), a start time
  with leading zeros (old kept the text `007`, new yields `7`), a start time beyond `u64` (old accepted, new
  refuses). Non-UTF-8 `comm` is unchanged only because `read_to_string` is kept (it returned `None` before and
  still does; with byte reading it would parse). Request (A1/X, owner of `procstat.rs`): add
  `procstat::start_time(text) -> Result<(char, u64), ProcStatError>` (no group requirement) and R's helper becomes
  one call.

## R3. §5 item 22: `lock_behavior` exists as a typed M01 key (`[session] lock_behavior`)
* `crates/runtime/src/config.rs:19–50` has `SessionConfig.lock_behavior: LockBehavior {Continue, Revoke}` (M01, spec
  §6.4), exercised by `tests/integration/runtime.rs:185`. Adding `lock_behavior` to the depth-wide
  `FORBIDDEN_KEYS` broke that M01 test, so the two keys are refused **under `[x]` only**, as the plan's wording says
  (`FORBIDDEN_UNDER_X`; `registry_path` outside `[x]` is an unknown key, refused by `deny_unknown_fields`).
* Open question (integrator/ADR-0008): in M03 lock behaviour is a standing policy (`StandingPolicy.lock_behavior`,
  widening needs an attended decision). Does the M01 config key `session.lock_behavior = "revoke"` still mean
  anything, is it ignored, or should it be retired (a config schema change)? Nothing reads it in wave 0 as far as R
  saw; R changed nothing about it.

## R4. Row 6: settled bounded obligations — RULED (ADR-0008 §17.15), implemented
* A `nominally_expired` obligation keeps its record (never shown as cleared); its grant still moves `revoking →
  revoked`; a record of only `bounded_complete` obligations is removed. Kept obligations are reported in
  `BoundedReport::nominally_expired` (the supervisor's `RevocationReport::bounded`) and through `inspect grants`
  (the existing path lists an ended grant while a record covers it); `RevokeData.remote_effects` is not built by
  any wave-0 path. **Settle path: none in wave 0** — `residual_step` never moves `nominally_expired` and no
  measurement or verified removal exists; the record stays until the later unit (U10) settles it.
* The two one-line edits in `operations.rs` stand: `plan_obligation_calls` skips bounded obligations (no call, no
  attempt) and `complete_round_in` never lets an adapter confirmation clear one. No-ops for M01/M02 records.

## R5. Row 13: order of the owner-role refusal
* Built: attended-only check (dispatcher, as before) → **owner role** for `Enrollment::{Step, StepResult,
  Reconcile}` and `Connections::{Close, Register}` (`CAPABILITY_UNAVAILABLE`, no reason, effect `none`, message
  "this request needs the owner role") → `driver_unavailable`. Reason: authorization before capability, so a non-owner
  learns nothing about which drivers this build has; neither answer touches the store. The other M03 requests answer
  `driver_unavailable` to any role. Is a reason wanted for the role refusal (none exists in `reason::M03`)? The M02
  precedent (`setup`, `catalog`) has none.

## R6. Row 17: `owner_reconcile` has no constant in the contract
* E8 says the M03 reason list is separate; `owner_reconcile` is a `runtime_lifecycle` payload value, not an error
  reason, and is not in `reason::M03`. Built: `heimdall_app::operations::OWNER_RECONCILE`. Option: move it to the
  contract (`envelope::reason` or an event-payload module) when ADR-0006 rev 4 lists it.

## R7. Row 7: back-off scope and cap
* Built in `Supervisor::revocation_pass`: only when some configured adapter has `remote_credential_effect`, each
  cleanup intent runs on its own schedule (new: at once; kept: after `retry_delay(revocation backoff, n, jitter)`;
  capped at `max_attempts` processings per process, then kept for the next restart, which processes every intent
  once). Without such an adapter the M02 path (`process_cleanup_intents`, every intent every pass) is unchanged.
  While a remote-effect adapter is configured, an intent kept for another reason (its applying adapter not
  configured) is backed off too. G's app part (`keep_intent` on a timed-out remote-effect call) is in
  `operations.rs` and calls R's `process_cleanup_intent_reporting` contract; R's test covers both.

## Requests to other owners
* A1/X (`crates/domain/src/procstat.rs`): R2's `start_time` entry.
* Integrator: `tests/model/narrowing_m03.rs:252` (G's) failed `clippy --all-targets -D warnings` (`type_complexity`)
  during R's first clippy run; a later run of the same command exited 0 (resolved by its owner).
