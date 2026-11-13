# M03 wave 5 — questions for the orchestrator

Format per question: ID, question, evidence (file:line), options, recommendation, what is built now
and behind which switch.

## Integrator (I-*)

### Q-I1 — U5IO-Q3: the terminal handoff for interactive remote steps
Question: an interactive enrollment step (an identity needing a passphrase / PIN / confirmation on
`/dev/tty`) runs ssh in its own background process group, so a `/dev/tty` prompt stops it (`SIGTTIN`)
until the step's 300 s bound kills it (fail closed). ADR-0008 §17.17/§17.18 (U5IO-Q3 (c), line ~3719):
"U12 prefers agent-held identities for interactive steps, and rules the terminal handoff with its own
escalation." This is that escalation.
Evidence: `crates/enroll/src/remote.rs:44-50, 93-96` (`INTERACTIVE_FOREGROUND_HANDOFF = false`);
`crates/launch/src/handoff.rs` (M02's `system(3)`-model foreground handoff for the TUI: child in the
caller's group, SIGINT/SIGQUIT handlers, no `setpgid`).
Options:
- (a) Foreground handoff by group: `tcsetpgrp` to the step's process group and back, with `SIGTTOU`
  ignored/blocked around the switch-back. Needs signal-mask `unsafe` outside overview §9 or a pinned
  signal crate (both escalations). Keeps the step's own group, so `StepAbort` still kills the group.
- (b) Keep ssh in the CLI's foreground group for interactive steps only (M02 `run_foreground` model):
  the prompt works with no new `unsafe`; the CLI survives Ctrl-C via its handlers; but the step is no
  longer a separate group, so the bound/abort must kill exactly the verified ssh PID (not a group),
  and a Ctrl-C at the prompt also reaches ssh (which is the owner's intent at a prompt).
- (c) Keep as built: interactive steps fail closed at the bound; the CLI refuses up front when the
  step's identity is not agent-held (`interaction_required`-style refusal with the next step "add the
  key to an agent"), so the owner never waits 300 s.
Recommendation: **(c) now, (b) later.** (c) is the fail-closed choice and needs no ruling beyond this
one; refusing up front turns a silent 300 s stall into an immediate, explained refusal. (b) is the
smallest working handoff (reuses an audited M02 model, no new `unsafe`) if the owner wants passphrase
keys enrolled directly.
Built now: (c) — the switch stays `remote::INTERACTIVE_FOREGROUND_HANDOFF = false`; worker E adds
the up-front refusal/notice (its switch is named in E's heading).

### Q-I2 — registering `managed_dir_unsafe` as a doctor finding (please confirm)
ADR-0008 §17.20 item 15 says "the doctor (U12) reports it", but no ruling names a finding code, and
`doctor::finding::M03` is contract. Built: `doctor::finding::MANAGED_DIR_UNSAFE` added to
`finding::M03`, the reasons golden's `doctor_findings`, m03-plan §5 item 14 and ADR-0006 §16.1 row 14.
Options: (a) keep it (recommended: the doctor needs a stable code, and the addition is additive);
(b) report it under an existing finding code; (c) revert it, so the doctor only notes the refusal reason.

### Q-I3 — two plan tests under the TUI heading name CLI commands (reading)
`enroll_verify_approve_target_change_shows_key_diff_and_needs_decision` and
`enroll_reconcile_after_manual_recovery_never_redispatches` are listed under U12's "TUI:" bullet but
exercise `enroll verify --approve-target-change` and `enroll reconcile --after-manual-recovery`.
Built: both are in `e2e_cli_m03` (`enroll::`). Recommendation: accept this reading. The TUI shows
the same target-change key diff in its decision modal (snapshot `m03_decision_target_change_*`).


### Q-E1 — the CLI-side script pause points need a `heimdall -> heimdall-registry` edge
Question: `HEIMDALL_TEST_SCRIPT_PAUSE_DIR` is read only by the `enroll` CLI (`testcfg::enroll_hooks`), and inserting the
pause points needs `heimdall_registry::script::test_form::insert_pause_points` (`crates/registry/src/script.rs:1538`,
`cfg(debug_assertions)`); `heimdall-registry` is not a dependency of the `heimdall` crate (`crates/heimdall/Cargo.toml`;
`tools/validation/crate_graph.py`).
Options: (a) add the workspace-internal edge (no new package; registry is pure and already in the graph via app/enroll)
and insert the points CLI-side in debug builds; (b) the runtime inserts them when it builds a step (the runtime already
has `ManagedOptions::script_pause_dir`, today used only for the verifier's pause), the CLI only validates; (c) keep the
variable unusable for enroll.
Recommendation: (b) if the step's `script` may differ in debug builds (it never leaves the CLI-runtime pair and the
digest covers the plan, not the script), else (a). Both keep release builds unchanged.
Built now (fail closed): switch `enroll_cmd::SCRIPT_PAUSE_POINTS_CONSUMED = false`: a set pause directory refuses every
`enroll` form except `status` (USAGE_ERROR, exit 2, before any runtime contact), so a test that relies on pauses never
runs unpaused. Request E-R1 in api.md.

### Q-E2 — Q-I1 option (c) as built (record)
Switch `enroll_cmd::REFUSE_UNHELD_INTERACTIVE_IDENTITY = true`, active while
`remote::INTERACTIVE_FOREGROUND_HANDOFF = false`: (1) before `Apply`, an interactive enrollment whose plan's
existing-access invocation is not agent-held (`IdentityAgent` concrete — absolute path or pipe, never `none`/
`SSH_AUTH_SOCK` — and `IdentitiesOnly=yes`) is refused `INTERACTION_REQUIRED` (exit 3, nothing applied, `data.plan`);
(2) an interactive step (`BatchMode=no`) whose access pins are not agent-held is not run (no result sent; next
`reconcile`); (3) before the first interactive step the CLI prints `drive::HANDOFF_NOTICE`. Today every M03 plan pins an
agent (`registry::step::access_pins`), so (1)/(2) never fire on a valid plan; a server that falls back to password or
keyboard-interactive authentication still stalls until the step bound (ssh's own prompt; nothing the CLI can see up
front). No decision needed unless the owner wants (b) of Q-I1.

### Q-E3 — `enroll status` has no hold reason to show (contract gap)
`EnrollmentView` (`crates/contract/src/enrollment.rs:776`) carries no `hold`; U12 ⟨r3⟩ wants "a held record's reason and
next step". Options: (a) additive `hold` field (E-R2 / T-R2); (b) derive from `inspect operations`. Recommendation (a).
Built now: the reason is read when present; otherwise "reason not reported by this runtime" and all applicable commands.

### Q-E4 — the result's `ordinary_ssh_needs_held_slot` note names `heimdall connect <alias>`
`app/src/operations/enrollment_m03.rs:933` puts `command: "heimdall connect <alias>"` on a verified result, while R3 says
the `slot_free` command is `slot_free_command(alias)` (`heimdall run --profile <profile> -- ssh <alias>`). The CLI prints
the envelope's command verbatim in results (never retyped) and uses `slot_free_command` in the preview and `status`.
Recommendation: the runtime uses `slot_free_command` too (integrator, app).

## I (issuer CLI)

### Q-IS1 — S3: a test-configured CLI cannot register, nor delete, on the scratch store
Question: U4-Q1 (b) authorized a `#[doc(hidden)]` test store kind; U10B-Q5 (§17.21 item 10) later
accepted "no test store kind". With the shipped code, a test-configured `issuer init|rotate
begin|restore` on the scratch store stops at the registration (`RegisterRequest::to_issuer_request`
→ `TestStoreNotRegistrable`), **and** the R2B retire deletion stops at `unloaded`
(`retire::delete_awaiting` refuses a store whose kind is not a product kind). So on this host no
CLI run can reach the passphrase step (D4 step 5 follows step 3) or the `deleted_locator`
confirmation. The only product stores reachable are the owner's (login keychain, Secret Service) —
forbidden — and Windows DPAPI under a scratch `HEIMDALL_HOME` (product kind at a scratch path; no
pty harness on Windows).
Evidence: `crates/issuer/src/ceremony.rs:34-39, 298-319`; `crates/issuer/src/retire.rs:229-268`;
`crates/heimdall/src/m03_cmd.rs` `issuer_store` (scratch → `Test("scratch_test")`);
`crates/issuer/src/store/macos.rs:10-16, 91-160` (a debug-only disposable **file** keychain of
product kind `macos_login_keychain` exists, but no selector reaches it from the CLI/child).
Options:
- (a) U4-Q1 (b): a `#[doc(hidden)]` test `StoreKind` variant on the wire (contract change; reverses
  U10B-Q5 and F23's "no test variant" golden `store_kind_has_no_test_variant`).
- (b) A debug-only **disposable product store** selector: `HEIMDALL_TEST_SECRET_STORE=file-keychain:<abs
  path>` (macOS: `MacosLoginKeychain::disposable_file_keychain`, product kind, outside the search
  list; Windows: DPAPI under the scratch home, already); the CLI and `internal issuer` select it
  through `m03_cmd::issuer_store`; Linux stays gated (no disposable Secret Service fixture). Needs
  testcfg.rs + m03_cmd (integrator/A); no contract change; claims stay disqualified by the debug
  build profile (F03).
- (c) Keep as built: the scratch store is never registrable or deletable through the product path;
  the full chain is evidenced at the ceremony level (U4 fakes) and the runtime level (U10), and the
  CLI e2e tests pin the clean refusals.
- (d) Scratch deletion only: treat a test-kind store's item as deletable by exact locator in debug
  builds (my switch below), registration stays (c).
Recommendation: **(b)**, with (d) as its interim. (b) exercises the real registration, the
passphrase on the tty and the R2B deletion on a real keychain code path natively on macOS and
Windows, without a public test kind. (d) alone already proves the R2B order end to end on the
scratch store.
Built now: (c). Switch `issuer_cmd::S3_TEST_STORE_DELETION = false` (+ its mirror in
`tests/e2e/cli_m03/issuer.rs`). With both set `true` (local run, restored, shasum verified),
`issuer_retire_typed_yes_and_r2b_deletion_on_scratch_store` passed the whole chain (approve →
unloaded → exact delete → `deleted_locator` → `retired`, item gone): exit 0.
Blocked on the ruling: `issuer_init_prints_passphrase_only_to_tty`'s passphrase assertions (shown
on the tty, absent elsewhere, decrypts the backup), the `register_issuer` typed-yes e2e, the
log-intact/log-lost restore past the registration, and testkit's
`test_ca_ceremony_captures_passphrase_only_from_pty` (its `ceremony::run` gets
`NoPassphrase` on the scratch store; on a product store it would need (b)).

### Q-IS2 — who records `last_bundle_at`, and how uninstall proves a bundle "fresh" (D4 item 6)
Question: U10B-Q3 (b) authorizes an additive `last_bundle_at` meta key refining `bundle_stale`. The
runtime builds the bundle but the CLI writes the file, so the runtime cannot know a file exists.
Options:
- (a) The runtime records it when it answers `issuer.bundle` (unredacted only). Simple; but a CLI
  that then fails to write (path exists, disk full) leaves status claiming "fresh".
- (b) The CLI confirms after the write + fsync (additive request field, e.g. `IssuerRequest::Bundle
  { written_created_at }`, or a new action): accurate; a contract change.
- (c) Never recorded: `bundle_stale` stays "true while any enrollment exists" (wave-4 reading).
And for uninstall (worker U): independent of who records it, freshness of a **given** `--bundle`
file can be proven from the file itself: `schema`, unredacted, its `created_at` ≥ every
enrollment's `updated_at` and every CA's `created_at`/`retired_at` in the state DB (the same rule as
`app::operations::issuer_m03::bundle_stale`), and its non-final enrollment set equal to the DB's.
Recommendation: **(b)** for `issuer status`; uninstall proves freshness from the file as above
(never from `last_bundle_at` alone, which says nothing about which file the owner holds).
Built now: (c) behind `app::operations::issuer_m03::RECORD_LAST_BUNDLE_AT_ON_REPLY = false`; the
getter/setter (`Txn::{last_bundle_at, set_last_bundle_at}`, never lowers) and `bundle_stale(cas,
enrollments, last_bundle_at)` exist and are unit-tested; switching to (a) is the one constant.

## U (uninstall, doctor, status chores)

### Q-U1 — how uninstall proves a `--bundle` is "fresh" (D4 item 6; R5)
Question: D4 item 6 calls a bundle fresh when it was "written after the last enrollment change, whose path the command records". Which part proves freshness, and who records the bundle (worker I's `last_bundle_at`, U10B-Q3 (b))?
Evidence: ADR-0008 D4 item 6 (~1031-1034), §17.20 item 10 (~4035); `crates/heimdall/src/uninstall_cmd.rs` `check_bundle`, `BUNDLE_WRITE_RECORD_REQUIRED`.
Options: (a) content only: the file parses as `heimdall-recovery-bundle/1`, is not redacted, `created_at` ≥ the last enrollment record's `updated_at`, and lists every non-final enrollment by marker in its current state; (b) (a) plus this installation's record of having written **that** bundle (`last_bundle_at` and the path or SHA-256, recorded by the CLI after the file is written, U-R3), so a hand-made or foreign file is not accepted; (c) record only.
Recommendation: (b), with the CLI recording after a complete write (the runtime never sees the file). The content check stops a stale or partial bundle, and the record stops a file this installation did not write.
Built: (b), fail closed. The content check is implemented and unit-tested. `BUNDLE_WRITE_RECORD_REQUIRED = true`, and nothing records a bundle yet, so every `--bundle` is refused `bundle_required` (exit 4). Setting it `false` gives (a). `uninstall` also records the accepted path in its result (`data.bundle.path_display`).

### Q-U2 — what "offers `enroll remove` first" means for a plain `uninstall`
Question: D4 item 6: uninstall "lists every enrollment that is not final … and offers `enroll remove` first". Does a plain `uninstall` (state kept) only list them, or does it ask?
Evidence: ADR-0008 D4 item 6, §18 (~4343); `uninstall_cmd::PLAIN_UNINSTALL_ACK_REQUIRED`, `confirm_plain`.
Options: (a) list and go on (the state database, which is the inventory, is kept); (b) list, then require a typed `yes` to leave them enrolled; without a terminal or under `--non-interactive`, exit 3 with nothing changed. With (b), a scripted plain uninstall cannot go on while enrollments live, because `--keep-remote-enrollments` `requires = "purge_state"` in `cli.rs`.
Recommendation: (b). It is the fail-closed reading and keeps the runtime from being started and stopped before the owner sees them. If scripted uninstalls matter, the integrator can relax `--keep-remote-enrollments` to also acknowledge a plain uninstall (a `cli.rs` change).
Built: (b), switch `PLAIN_UNINSTALL_ACK_REQUIRED = true`; `false` gives (a). No M02 path is affected, since an M02 store has no enrollments.

### Q-U3 — deleting the K_ca store item inline in uninstall
Question: D4 item 6 says uninstall "offers deleting it (the retirement steps of item 3, run to `retired`) behind a typed confirmation". The R2B sequence (decision, typed yes, poll for `unloaded`, `delete_awaiting`, `deleted_locator`) is worker I's code, and the brief forbids duplicating it.
Options: (a) offer it as the command `heimdall issuer retire <fingerprint>`, which has its own typed confirmation; (b) run I's sequence inline before the runtime stops, once I exposes an entry (U-R4).
Recommendation: (b) once U-R4 lands, (a) until then.
Built: (a). The fate is stated in JSON (`store_items[]`) and in the human text and the purge prompt. An item whose locator was never recorded is kept, with reason `locator_unrecorded`, because it can never be deleted by fingerprint.

### Q-U4 — the chore's surface and trigger (`time_confirmation_after_reboot`)
Question: which CLI surface shows the chore, and when is it pending?
Evidence: plan U12 (~1868); ADR-0008 D9 item 5; `authorize.rs:93`; `domain::time::gate` (a same-boot runtime anchor or confirmation is the only reference, since `SystemTimeSync` is always `Unknown`).
Built: the bare `heimdall` status (U-R1, `data.chores`, additive). It is pending when the store holds a time reference (anchor or confirmation) from an earlier boot and none for this boot. A store that never had one is not counted as "after a reboot". The doctor does not show it: `DoctorReport` and `finding::M03` have no chore code, so adding one would be a contract change. Open: should a never-confirmed store also show the chore, and should it show only when a managed pair exists?

### Q-U5 — doctor findings owed but not emitted anywhere
`reverification_inconclusive`, `enrollment_evidence_stale` and `client_trace_family_unrecorded` are registered (`finding::M03`) but nothing emits them as doctor findings. The first two need enrollment evidence and re-verification state that the doctor could read from the store (`EnrollmentRecord.evidence.fresh_until`, the open re-verify operation). The third is `heimdall_enroll::trace::UNRECORDED_FINDING`, an error's `finding()`. None is named in U12's test list. Not implemented; listed for a ruling on where they land (U12 or U13).

## A (access, destination, connections, output, goldens)

### Q-A1 — exit status of a `connections close` that did not close
Question: the runtime answers `OK` with `state` `closed`, `unverified` (process identity not verified, never signalled) or `closing` (pending, retried). Which exit?
Evidence: `crates/runtime/src/supervisor.rs` `close_request`; ADR-0006 §5 (no row for this).
Options: (a) 0 for all (envelope is the runtime's `OK`); (b) 0 for `closed`, 4 for `unverified`, 5 for `closing` (the owner asked for a close that did not happen).
Recommendation: (b). Built: (b) behind `connections_cmd::INCOMPLETE_CLOSE_IS_NONZERO` (set `false` for (a)); the JSON envelope is unchanged either way.

### Q-A2 — the retyped ordinary-`ssh` note text
Question: `RevokeData.notes` carries only the code `ordinary_connections_not_closed`; no constant holds its sentence. Output shows `output::ORDINARY_CONNECTIONS_NOTE` (derived from ADR-0008 D7 item 2 step 6). Should the sentence move to a contract/adapters constant shared with the TUI (T)?
Recommendation: yes, one constant in `heimdall_adapters::managed::report`; T and A then share it. Built: the CLI constant, `pub(crate)` for T to reuse.

## T (TUI)

All five build the most fail-closed view now, behind the named switch or the absence of
the field. None changes authority. The TUI sends only read-only `inspect`, plus `Attend`
and `Decide` after the owner types `yes`.

### Q-T1: a held enrollment's reason and next step are not in `inspect enrollments`
Question: U12 r3 says the TUI shows "a held record's reason and next step". `EnrollmentView` has no hold field (`crates/contract/src/enrollment.rs:776-822`). The reason lives only in the domain record (`EnrollmentRecord.hold`, `crates/domain/src/enrollment.rs:198`).
Options:
- (a) Add an optional `hold: {reason, next}` to `EnrollmentView`. The app would fill it from `record.hold`, with the next-step command computed in the app so E's `enroll status` and the TUI share it. This is a contract change.
- (b) The TUI reads the store read-only.
- (c) Keep "unknown".

Recommendation: (a).
Built now: the TUI parses `hold {reason, next}` if present. If `next` is missing, it uses the two next steps the plan names (`host_key_changed` → `enroll verify <id> --approve-target-change` / `enroll remove <id>`; `lock_holder_unresolved` → `enroll reconcile <op> --after-manual-recovery`). Any other reason reads "unknown". With no field, it shows "Held: reason unknown (not reported by the runtime)". The e2e `enrollment_states_rendered` observes that last line today.

### Q-T2: managed readiness and the D8 deadline wording have no read-only source
Question: the deadline wording is only in an `ensure` answer (`EnsureData.connection_policy`). Even there it is always `None` (`crates/app/src/operations.rs:5133`, which drops `ManagedReport.connection_policy`). No `inspect` subject has a pair's effective policy.
Options:
- (a) `inspect destinations` items gain `preference.connection_policy: ConnectionPolicyReport`, with `wording` from `adapters::managed::report::connection_wording`.
- (b) A new `InspectSubject::Readiness`.
- (c) The TUI infers the policy from `inspect connections` rows. This is a guess: a row's policy is the one recorded when that connection started.

Recommendation: (a), and fix `ensure_data` at the same time (A's request (1)).
Built now: the TUI parses `preference.connection_policy`. If the runtime's `wording` is there, it is shown verbatim. If only the modes are there, it uses `deadline_wording(selection, existing)`; an unknown selection reads `undetermined` (§17.20 item 9). With nothing, it shows "unknown: no connection policy is reported for this pair".

### Q-T3: `OWNED_MASTERS_DISCLOSURE` cannot be used from `heimdall`
Question: `heimdall-adapters` is only a dev-dependency of `heimdall` (`crates/heimdall/Cargo.toml:73`).
Options:
- (a) Make it a normal dependency. This adds a `Cargo.lock` dependency edge but no new package.
- (b) Move the constant next to `DEADLINE_*` in `localenv::projection::plan` and have adapters re-export it.
- (c) Get it only through the runtime's wording, as in Q-T2 (a).

Recommendation: (c), and (b) if a local fallback is wanted.
Built now: switch `tui::m03::switch::OWNED_MASTERS_LINE = None`. When owned masters apply and the runtime sent no wording, the base text is followed by "[??] owned masters are applied: what happens to sessions shared through them is not known here". The sentence is never retyped.

### Q-T4: there is no shared text for enrollment and issuer disclosures
Question: the only texts are in the private `heimdall_issuer::ceremony::disclosure_text`, and it covers 5 of the 9 `DisclosureKind`s. The `EnrollAccount` record also carries only `line_sha256`, not the exact line.
Options:
- (a) I makes `disclosure_text` public and covers every kind (request T-R1). The TUI and E's preview then use it.
- (b) A contract-level text function.
- (c) Keep refusing Approve in the TUI.

Recommendation: (a). Separately, rule whether a TUI approval of `enroll_account` needs the exact line, which is not in the record today.
Built now: switch `tui::m03::switch::disclosure_text` returns `None`. An M03 decision with a disclosure the TUI cannot show is listed as "[text not available in the TUI]". Approve is not offered: a typed `yes` sends nothing, and the status says "approve not sent". Deny still works. (`ordinary_ssh_needs_held_slot` is shown from `localenv`'s `slot_free_disclosure`.)

### Q-T5: the lock behaviour and the D9 disclosure have no read-only source
Question: D9 item 1 says the disclosure is shown in `inspect capabilities`, and "the TUI detail always shows the current behaviour". Neither is exposed. `Operations::lock_disclosure` and `pending_lock_disclosure` (`crates/app/src/lock.rs:413/435`) have no callers.
Also, the acknowledgement is set only when a `RegisterIssuer` with `lock_continuity_once` is approved (`issuer_m03.rs:1191`). Approving an `EnrollAccount` never sets it. Please confirm that is the intended reading of "shown once".
Options:
- (a) `inspect capabilities` gains `lock: {behavior, disclosure, acknowledged_at?}` from `lock_disclosure()`. This is read-only.
- (b) A new `InspectSubject::Lock`.
- (c) Keep "unknown".

Recommendation: (a), since D9 names `capabilities`.
Built now: the TUI parses `capabilities.lock`. With no `lock` field, it shows "Lock behaviour: unknown (not reported by the runtime)". The lock disclosure in a decision uses the runtime's text when present; otherwise it is unavailable and Approve is not offered (Q-T4).

### Q-T6: the time chore does not know its reason while the runtime is connected
Question: the TUI shows `time_confirmation_after_reboot` when any `inspect` answer carries `TIME_UNCERTAIN` (`operations.rs:8632`). That warning also covers skew and rollback, not only a reboot. With no runtime, the TUI uses U's `doctor_cmd::pending_chores`, which does know the reboot rule.
Options:
- (a) The runtime adds a distinct warning, or `next: time_confirm`, for `Unsynchronized`.
- (b) Also use U's reader while connected. It compares against the system boot ID, which a fixture clock cannot fake.
- (c) Keep it as built.

Recommendation: (a).
Built now: while connected, the chore comes from the runtime's `TIME_UNCERTAIN` warning, and its command comes first: "run `heimdall time confirm` (<runtime message>; after a reboot it needs one attended confirmation)". With no runtime connected, it comes from U's reader.

## R (runtime gaps)

### Q-R1 — the managed report never reaches `EnsureData` (A's request (1), T's Q-T2)
Question: `EnsureData.{lock_continuity, conditions, refresh_condition, revocation, evidence, connection_policy}` are always absent (`operations.rs` `ensure_data`, "fail closed until U0b"), so `access ensure --strict` never shows the D8 strict wording. How should the managed report reach the runtime's result?
Evidence: `adapters::managed::report::compute` builds `ManagedReport` (all six fields; its doc: "The runtime copies it into the result") in `prepare::outcome`, but `ManagedCertificateAdapter::prepare_from` returns `.map(|(o, _)| o)` (`managed/mod.rs` ~436) and `reissue_from` drops it too (`let (outcome, _)`). The only carrier is `CredentialAdapter::prepare_from -> PrepareOutcome` (`app::ports`), which has no field for any of them; m03-plan §0 row M2 freezes `PrepareOutcome`'s shape. app cannot compute the wording itself: `deadline_wording`/`DEADLINE_*` live in `heimdall-localenv` and `OWNED_MASTERS_DISCLOSURE` in `heimdall-adapters`, both forbidden edges for `heimdall-app` (`tools/validation/crate_graph.py`). After a restart the commit uses `Facts::conservative` (stored `PreparedFacts`, also frozen), so a report carried only in memory is absent there (fail closed).
Options:
- (a) Additive `PrepareOutcome.managed: Option<ManagedResultFacts>` (a new `app::ports` struct holding the six contract values; `None` for every M01/M02 adapter). The adapter fills it from `compute`; `Facts` carries it; `ensure_data` copies it for a managed binding. A frozen-port change (M2), but one source of truth and the plan's stated design. Every struct literal of `PrepareOutcome` gains `managed: None`.
- (b) No port change: an `Operations` setter the runtime calls at start (as `set_session_lock_source`), e.g. `set_connection_wording(fn(IdentitySelection, &ConnectionPolicy) -> String)` wired to `report::connection_wording`; app fills `connection_policy` from the grant's effective policy (origin + current policies, as `inspect connections` does) and the pairs' selection, and `lock_continuity` from the effective lock behaviour and `AdapterDescriptor.lock_continuity`. Covers the two fields U12 renders; the other four stay absent; it duplicates `compute`'s selection/policy rules in app (drift risk).
- (c) Move the D8 texts (`DEADLINE_*`, `deadline_wording`, `OWNED_MASTERS_DISCLOSURE`) into `heimdall-contract::managed` (re-exported where they are now) and compute (b)'s two fields in app without a setter. A contract addition.
Recommendation: (a). Built now: nothing (the fields stay absent, the fail-closed reading; the CLI and TUI print "unknown"). Not a switch: the carrier does not exist.

### Q-R2 — the policy result has no lock-behaviour field (A's request (3))
Question: D9 item 1 ("the current behaviour is always shown") — should the `access lock-behavior` / `connection-policy` result carry `lock_behavior` (and `connection {existing, multiplexing}`)?
Evidence: there is no contract type for the policy result: `policy_view` (`operations.rs` ~12230) is untyped JSON `{policy_id, revision, paused, cutoff_at, changed}`, the M01 shape that `tests/model/operations.rs` and `tests/integration/runtime.rs` read. No field exists to fill.
Options: (a) add `lock_behavior` and `connection` keys to `policy_view` for every action (an additive wire change of an M01 result: ADR-0006 additive rule, needs the integrator's contract record); (b) only for the two M03 actions; (c) none: the TUI detail (Q-T5) and `inspect` show the current behaviour.
Recommendation: (b), recorded as an additive ADR-0006 row. Built now: nothing (no field added, as instructed).

### Q-R3 — which signal the label uses (U9-Q3 (a), implemented)
Reading taken (please confirm): `Operations` did not know the platform signal, and `app::ports::SessionLockSource` has no `signal()` (frozen). Added `Operations::set_session_lock_signal(LockSignal)` and `session_lock_signal()`: `None` without a source or while it reads `unavailable`; else the runtime-named signal, else `LockSignal::of_platform()` (= `heimdall_runtime::session_lock`'s per-platform `SIGNAL`). So a test-configured fake source on Linux is labelled like logind (a warning only: the conservative side). The runtime need not call the setter for the platform source (same value); integrator may wire `ops.set_session_lock_signal(p.signal())` in `service.rs` (~2268) for clarity.
