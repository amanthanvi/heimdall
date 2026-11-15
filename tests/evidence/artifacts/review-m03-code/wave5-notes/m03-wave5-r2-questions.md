# M03 wave 5, round 2 — questions for the orchestrator

Format per question: ID, question, evidence (file:line), options, recommendation, what is built now
and behind which switch. One heading per worker.

## Integrator (I)

### Q-I-R2-1 — record: the managed-activation validity fix (A2-Q1), please confirm
A production defect, found by driving a managed `access ensure` through the real binary and the real
issuer child for the first time: the driver set `valid_after = floor(now) − 60 s`, while the issuer's
ceiling is `deadline − starts_at + 60 s` (`heimdall_issuer::check::validity_within_ceiling`). Within
the grant's first second `floor(now) < starts_at`, so the real issuer refused every first activation
(`ceiling_exceeded`). Every earlier managed test used a fixture issuer.
Fixed (integrator, `crates/app/src/managed/driver.rs` `validity_start`): `valid_after =
max(now, ceil(starts_at)) − 60 s`, on whole seconds; the issuer's check is unchanged (stays strict).
Unit test `managed::driver::tests::validity_start_never_exceeds_the_issuers_ceiling`; revert proof:
unit 101 → 0, and the two managed e2e halves 101 (`CAPABILITY_UNAVAILABLE`) → 0.
Options: (a) keep this (recommended: certificate starts never precede the grant's start minus the
skew allowance, and the issuer keeps its exact ceiling); (b) widen the issuer's slack by 1 s instead.

### Q-I-R2-2 — readings taken on C's shape questions (please confirm)
C-Q1 `hold.next` is a list (a host-key hold has two exits); C-Q2 `hold.reason` is a string (domain's
`HoldReason` name; contract cannot depend on domain); C-Q4 the M03 policy results report **this
policy's own stored values**; C-Q5 `preference.connection_policy` is present only when the runtime can
compute it (R2's Q-R2-1: the strictest standing policy covering the pair). Built as stated.
## C (contract and port seams)

### C-Q1: the shape of `EnrollmentView.hold.next` (§17.25 item 4)
Question: §17.25 item 4 says `hold: {reason, next}` and "the same command" (singular), but a
`host_key_changed` hold has two exits (`enroll verify <id> --approve-target-change` or `enroll remove
<id>`), and `lock_holder_unresolved` needs a manual step and then a command.
Evidence: `crates/heimdall/src/enroll_cmd/render.rs:300` (`held_next` returns `Vec<String>`);
`crates/heimdall/src/tui/m03.rs:273` (the round-1 TUI reads `next` as one string);
`crates/contract/src/enrollment.rs:741` (`EnrollmentResult.commands: Vec<String>`, the precedent for
commands in a view).
Options: (a) `next: Vec<String>`, the commands in order, omitted when empty; (b) `next: String`, one
line joining the alternatives; (c) `next: Option<EnrollmentNext>` plus `commands: Vec<String>`, as
`EnrollmentResult` has.
Recommendation: (a). Built: (a), `crates/contract/src/enrollment.rs:833`. The TUI parser needs to read
an array (T2).

### C-Q2: `EnrollmentHoldView.reason` is a `String`, not a typed enum
Question: `HoldReason` is in `heimdall-domain` (`crates/domain/src/enrollment.rs:42`), which the
contract crate cannot depend on. A typed contract enum would duplicate it.
Options: (a) `String` with the `HoldReason` wire name, as `ErrorDetail.reason` is (readers tolerate
unknown values); (b) a new contract enum `EnrollmentHoldReason`, which domain then re-exports (a domain
change no one is granted this round).
Recommendation: (a) for M03. Built: (a).

### C-Q3: shared literals outside the explicit grant (record)
Adding `Warning.reason` (§17.25 item 15) and `EnrollmentView.hold` (item 4) broke every struct
literal. To keep the workspace compiling I added `reason: None` to the 7 `Warning { .. }` literals
(`app/src/lock.rs`, `app/src/operations.rs:8646`, `app/src/operations/pair_mechanism_m03.rs`,
`heimdall/src/{setup_cmd,doctor_cmd}.rs`, `heimdall/src/tui/{m03,view}.rs`) and `hold: None` to the
3 `EnrollmentView { .. }` literals (`app/src/operations/enrollment_m03.rs:1079`,
`heimdall/src/uninstall_cmd.rs`, `tests/integration/issuer_store.rs`). They change nothing at run time.
Please confirm, or name another way.

### C-Q4: which values the two M03 policy results report (§17.25 item 22)
Question: should `lock_behavior` / `connection` in the `set_lock_behavior` / `set_connection_policy`
result be **this policy's** stored values after the action, or the **effective** strictest values
across the floor and every applicable policy (what `inspect capabilities`' `lock.behavior` shows)?
Evidence: `crates/app/src/operations.rs:12250` (`policy_view` is per-policy);
`crates/app/src/lock.rs:255` (`LockDisclosure.behavior` is the strictest).
Options: (a) the policy's own values (`StandingPolicy.{lock_behavior, connection}`); (b) the effective
values; (c) both, under different keys (a new authorization).
Recommendation: (a). The result describes the policy that changed, and `inspect capabilities` shows the
effective behaviour. Built: nothing (the keys are documented in `.m03-wave5-r2-api.md` R0 item 22).

### C-Q5: when `preference.connection_policy` is present (§17.25 item 19)
Question: for which `inspect destinations` items does `preference.connection_policy` appear?
Options: (a) only for a `managed_certificate` preference whose report the runtime can compute, and
absent otherwise (the TUI shows "unknown"); (b) for every item that has a `preference`.
Recommendation: (a). Built: nothing (the key is documented, R0 item 19).

## E2 (enroll)

### E2-Q1: readings taken for `hold.next` and the slot-free note (record; no decision needed unless you disagree)
- `hold` is filled only for `state == held` with a `record.hold` (a `reverifying` record that keeps
  its hold reason gets none). Evidence: `app/src/operations/enrollment_m03.rs` `hold_view`.
- `lock_holder_unresolved` without an open operation: nothing can be reconciled, so `next` is
  [manual step, `heimdall enroll remove <e>`] (D5 §6.2 `held -> removing`; its reconcile may break the
  stale lock once the holder is proven gone, §6.7) instead of a `reconcile <op>` naming no operation.
- A non-evidence-based `principals_not_enforced`/`positive_refused` hold gets [remove, abandon], never
  `enroll verify` (D5 §6.2: re-verification is for evidence-based holds only).
- §17.25 item 5: the note's command is `slot_free_command(alias)`, whose `<profile>` is the literal
  placeholder the preview, `status` and the doctor already show (the runtime does not know which
  profile the owner uses). When the destination's alias is unknown (record gone), `command` is
  omitted, never a guessed command. Options: (a) as built; (b) a literal `<alias>` placeholder.
  Recommendation: (a).

### E2-Q2: an unusable pause directory refuses steps (record)
`ManagedOptions::script_pause_dir` that is not a `PauseDir` (non-UTF-8, or outside
`[A-Za-z0-9._/-]`) is kept as "set but unusable": every step is refused `driver_unavailable` before
anything is written (debug builds only), so a test that relies on pauses never runs unpaused. The
CLI's own validation (`testcfg::enroll_hooks`) is unchanged (absolute path only).

## IS2 (issuer)

### Q-IS2-1: what proves "a path that existed before the test created it" (§17.25 item 7 (b))
Question: the CLI cannot see who created a file. My reading: the test creates a marker
`<path>.heimdall-test-store` (exclusive, owner-only, naming the store) **before** the store, and the
selector requires the marker, its content, owner-only mode and uid equal to the scratch home's and
the store's, and marker birth time ≤ store birth time (a store older than its marker, or a platform
without birth times, is refused).
Evidence: `crates/issuer/src/store/test_product.rs` (`refusal`, `create`); unit test
`store::test_product::tests::product_file_selector_refuses_exactly_the_four_cases` (revert of the
birth-order check: exit 101).
Options: (a) as built; (b) additionally a per-run nonce in the marker that the test passes in the
selector value (`product-file:<path>#<nonce>`); (c) the CLI itself creates the store on first use
(needs a keychain password source, which must not be an argument or variable).
Recommendation: (a). Built: (a). Also: the "scratch home" is the explicit `HEIMDALL_HOME`, and a home
that is the account's home or one of its ancestors is refused.

### Q-IS2-2: Ctrl-C at a ceremony prompt (record; the typed-`yes` row "Ctrl-C sends nothing, exit 3")
Question: the ceremonies read `/dev/tty` synchronously, so Ctrl-C used to kill the CLI with `SIGINT`
(no envelope, exit by signal). I made each ceremony read turn `ISIG` off and set `VEOL` to ETX for
the read (restored after it): Ctrl-C ends the line as a cancellation (`NotConfirmed`, exit 3). Unix
only; Windows keeps the console's default (Ctrl-C ends the process), to be checked natively.
Evidence: `crates/issuer/src/ceremony.rs` `ControllingTerminal::read_in_mode`; e2e
`issuer::issuer_init_register_issuer_typed_yes_sends_nothing_without_yes` (revert: exit 101, the
Ctrl-C case exits -1). Options: (a) as built; (b) keep the signal (exit by signal). Recommendation: (a).

### Q-IS2-3: the log-intact restore "with a new locator" on macOS (record)
Question: a keychain locator is `service=heimdall-issuer/<fp>;account=<environment>`, so a restore on
the same installation always rewrites the **same** locator (no new decision; tested). A recorded
locator that differs can only name another installation's item, which this store never deletes
(exact-identity rule), so the displaced-item step ends exit 4 after the re-registration and the
compare-and-swap succeeded (tested by seeding such a record). A genuinely new locator in the same
store arises only on the Linux Secret Service (random item paths), which has no disposable fixture.
Options: (a) as built (macOS proves the re-registration and swap; Linux-native row for the deletion);
(b) map a foreign keychain locator to "already absent" (would confirm a deletion that did not happen:
rejected). Recommendation: (a).

### Q-IS2-4: what `issuer.bundle_written` trusts (§17.25 item 8; record)
The runtime refuses a malformed digest and a `created_at` later than its clock, and otherwise records
what the owner's CLI confirms (the request is owner-only). It does not check that it built a bundle
with that `created_at` (it keeps no record of answered bundles). Uninstall's acceptance still needs
the file's content check **and** a recorded digest. Options: (a) as built; (b) the runtime remembers
the `created_at` values it answered since start and refuses others (a restart loses them).
Recommendation: (a).

### Q-IS2-5: the lock disclosure in the CLI's registration decision (record)
The ceremony shows `lock_continuity_once` with the general sentence (`DisclosureContext::default()`):
`RegisterDecision` has no field for the runtime's conditional `lock.disclosure`, and adding one would
break a constructor in `tests/integration/issuer_store.rs` (not mine). Options: (a) as built; (b) add
`RegisterDecision.lock_text: Option<String>` (filled by the CLI from `inspect capabilities`) with that
test updated by its owner. Recommendation: (b) in a later round.

## U2 (uninstall, doctor)

### Q-U2-1: is `client_trace_family_unrecorded` shown only where managed certificates are set up?
Question: §17.25 item 13 says the finding comes from the local client's version against
`heimdall_enroll::trace::RECORDED`; it does not say whether an M02-only installation (no issuer CA)
sees it too.
Evidence: `crates/heimdall/src/doctor_cmd.rs` `doctor()` (`client_trace_finding` + `ca_registered`).
Options: (a) only when an issuer CA is registered (not deleted/retired); (b) always, whenever the
selected ssh's version is known.
Recommendation: (a): the row matters only for enrollment verification; M02 users get no new
problem-severity finding. Built: (a). Switching to (b) is removing `&& ca_registered(ctx)`.

### Q-U2-2: the bundle content check also requires every CA in its current state (record)
§17.25 item 8 says "created_at no earlier than the last enrollment or CA change". CA state changes
(`active → retiring → unloaded → deleted`) carry no timestamp (`IssuerRecord` has only `created_at`,
`backup_created_at`, `retired_at`), so U2 also requires the bundle's `cas` to list every registered
CA in its current state (the bundle exporter lists every CA, so a bundle this installation wrote
after the change passes). Please confirm.

## R2 (runtime, app, adapters)

### Q-R2-1: which policy `inspect destinations`' `preference.connection_policy` reports (record)
Reading taken (item 19 + C-Q5): a destination has no grant, so the report uses the pair-level
policy: the strictest (`effective_connection_policy`) over every current standing policy in this
environment whose scope names the pair, the same merge `service.rs` `pair_masters_enabled` uses for
P. No covering policy, a non-`managed_certificate` preference, or no wired wording source: key
absent. Evidence: `crates/app/src/operations/lock_connection_m03.rs` `pair_connection_policy`.
Options: (a) as built; (b) per profile (one report per covering policy). Recommendation: (a).

### Q-R2-2: an attached managed binding's result omits the six fields (record)
`Facts::from_data` (C's seam) stays `None`, so a second work attached to a managed grant reports
the fields absent ("unknown"), as after a restart. Copying the leader's values would show a policy
narrowed by another request's `--strict`. Built: absent (fail closed). Confirm or rule otherwise.

### Q-R2-3: item 23 skips storing `LockSignal::None` (record)
`PlatformSessionLockSource::signal()` answers `None` while it reads `unavailable`. Storing that
would make `Operations::session_lock_signal` answer `None` forever, even if the source later read
a state (no `signal_unverified` label: not fail closed). Built: `set_session_lock_signal(p.signal())`
only when it is not `None` (`service.rs` `ManagedParts::start`).

## T2 (TUI)

### Q-T2-1: may the read-only M03 decision modals still send Deny? (§17.25 item 10)
**ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.26):** allow Deny on every read-only decision view, after the usual typed confirmation. Deny grants no authority and needs no owner-present follow-through. Approve stays CLI-only for those kinds.
Question: item 10 says the CLI-completed kinds are "shown read-only, with their CLI command". Deny
needs no owner-present follow-through (it is narrowing: the waiting operation is refused).
Evidence: `crates/heimdall/src/tui/model.rs` `decision_key` (the `cli_only` early return, the
Tab guard `decided_in_cli`); `crates/heimdall/src/tui/m03.rs` `cli_only`.
Options: (a) read-only means no verdict at all (the owner denies in the CLI, or lets it expire);
(b) Deny is offered (typed `yes`, as for every other decision), Approve is not.
Recommendation: (b). Denial ends a decision the owner may not have started, from where they see
it, and has nothing to follow through. Built: (a), the most fail-closed. Switching to (b): let Tab
toggle and let `Verdict::Deny` pass the `cli_only` early return, and draw the normal prompt for Deny.

### Q-T2-2: which kinds are read-only beyond the ruling's list (record; please confirm)
**ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.26): confirmed.** Enrollment removal is a client-executed loop, so `remove_enrollment` (own and foreign) is read-only in the TUI with its `heimdall enroll remove …` command, Deny allowed.
- `remove_enrollment` is read-only (command `heimdall enroll remove <e>`, or the `--from-bundle`
  form for a foreign line): its follow-through is the CLI's step loop on the owner's terminal
  (`enroll_cmd::remove_flow` -> `settle` -> `drive::drive`).
- `approve_target_change` keeps Approve and Deny: approval makes the runtime run the verification
  itself (`app/src/operations/enrollment_m03.rs` `enrollment_after_decision` -> `verify_operation`),
  and it carries no disclosures. The TUI shows the key diff (item 6).
- `register_issuer`'s command is inferred from the record: `rotation_of` -> `heimdall issuer rotate
  begin --backup-out <path>`; `restored_without_log` or `expected_store_locator` -> `heimdall issuer
  restore --backup <file>`; otherwise `heimdall issuer init --backup-out <path>`. A log-intact
  restore with no recorded locator reads as `init` (the record does not say which ceremony made it).
  The paths are placeholders: the record has none.

## A2 (access, connections, output)

### A2-Q1: the real issuer child refused every managed activation's certificate — **fixed by the integrator (driver `validity_start`)**
Observed (macOS arm64, this worktree, the real binary's own runtime and its real `internal issuer`
child over the scratch store; `tests/e2e/cli_m03/access.rs` `ManagedPair`): `access ensure` of a
managed pair answers `CAPABILITY_UNAVAILABLE` (resource `adapter`, effect `none`); the operation's
stage receipts reach `managed.reserve` and never `managed.sign`. The reserved `issuance_log` entry:
`valid_after 08:06:15Z`, `valid_before 10:07:15.040016Z`; the grant: `starts_at 08:07:15.04153Z`,
`deadline.effective 10:07:15.040016Z`. `heimdall_issuer::check::validity_within_ceiling(&entry.bounds,
window)` is `false` (window `7199.998479s`): span 2h1m0.04s > window + 60 s = 2h0m59.998s, so the
child answers `ceiling_exceeded` (mapped to `AdapterError::CapabilityUnavailable`, reason lost).
Cause: `app::managed::driver::run_stages` sets `valid_after = from_second(now.as_second() - 60)`
(truncated to the second, `VALID_AFTER_SKEW_SECS` = 60) while `check::validity_within_ceiling`
allows exactly `deadline − starts_at + 60 s` (`VALIDITY_SLACK`), and `starts_at` is after the
truncated second. So the span always exceeds the ceiling by the sub-second part plus the commit
latency: every managed activation through the real issuer fails. Every other managed test uses a
fixture issuer (`TestIssuer`, `FlakyIssuer`, `FixtureIssuer`), so none caught it.
Options: (a) driver: `valid_after` = the grant's `starts_at` rounded **up** to the second, minus
60 s (never earlier than the ceiling allows; the issuer stays as strict as it is);
(b) issuer: compare whole seconds (`valid_before − floor(starts_at)`), i.e. widen the ceiling by
under a second; (c) both clamp to the grant window. Recommendation: (a) — it changes only the
runtime's request, keeps the issuer's fail-closed ceiling unchanged, and matches ADR-0005 §3.4's
"60 s skew allowance" up to a sub-second; add a regression through the real child
(`tests/integration/issuer_child.rs` signing a driver-built entry with a fractional `starts_at`).
Owners: `crates/app/src/managed/driver.rs` (R2's area) or `crates/issuer/src/check.rs` (IS2's).
**Status: fixed by the integrator (driver `validity_start`: the grant's start rounded up to the
second, the later of that and `now`, minus 60 s; own unit test; revert proof by the integrator).**
The switch is removed; the managed halves run unconditionally through the real binary.
