# M03 wave 5, round 4 — questions for the orchestrator

## Integrator (I)
## L4 (late_write clearing)
- **Q-L4-1 (which observation `verify --absence` makes for a `late_write` record).** Fact: the
  residual is only ever set on account-form records (an uncertain E3 append), in `withdrawn`,
  `abandoned`, or an abandoned record's later states (`removing`, `remove_unknown`, `removed`,
  `held`). Before this round `enroll verify --absence` was admitted only from
  `manual_removal_pending` (system form): every `late_write` state was refused `CONFIG_CONFLICT`
  (`enrollment_state`) before any remote contact, so the ruling could not take effect without
  opening it. The existing absence check (§6.9) is the runtime Verifier's positive-certificate
  refusal, which sees neither the marker line nor the uncertain step's lock; D5 §6.7 clears the
  residual only on an `inspect` past `not_after_remote` with no marker line and no lock with the
  residual's token (`heimdall_registry::fence::late_write_cleared`), since a writer holding the lock
  can still append after the not-after. Options: (a) as built: for an account-form record carrying
  `late_write` (any state, no other open operation), an attended `--absence` admits an
  `enrollment.verify` op that issues one read-only, non-interactive client-executed `inspect`
  (the same authority as `enroll reconcile`'s inspect; no certificate, no state move) and
  evaluates `late_write_cleared`; (b) the Verifier's certificate refusal (cannot see the lock:
  unsafe); (c) both. Recommendation: (a). Clock: the destination's, as the existing computation:
  the HM1 inspect's `remote_now` strictly past `not_after_remote`; no local/safe time and no
  `RESIDUAL_DRIFT_PPM` (that is the revocation residual's). Built: (a), no switch (it is the
  ruling's path; the fail-closed alternative would make the ruling vacuous).
- **Q-L4-2 (kept-outcome reason).** A check that keeps the residual settles failed
  `CAPABILITY_UNAVAILABLE`, reason `verification_inconclusive` (the system absence check's
  existing reason), with the specific cause in the message (not-after not passed / lock present /
  registry unreadable / marker line present, next `heimdall enroll remove <id>`); an incomplete read
  keeps the class's code (host trust, provider locked, interaction required). `possible_late_write`
  is a warning code, not an error reason, so it is not used. No contract change. Options: (a) as
  built; (b) a new reason per cause (contract change). Recommendation: (a).
- **Q-L4-3 (the `possible_late_write` note's command; not changed).** The result note
  (`enrollment_m03.rs` `result_for`) and the TUI (`tui/m03.rs` ~470, its own text) name
  `heimdall enroll remove <id>`. By the D5 §6.2 table a `withdrawn` record takes no
  `RemoveEnrollmentApproved` (inference from `domain::enrollment::target`; not run), so for the
  commonest residual the named command cannot help, while `enroll verify <id> --absence` (after
  the not-after) is now the clearing command. Options: (a) leave as is; (b) the note names
  `heimdall enroll verify <id> --absence` (and the TUI text follows; goldens in
  `cli_m03/enroll.rs`, `tui/view.rs` change). Recommendation: (b), in one change across app + TUI
  by their owners. Built: nothing (the TUI and its tests are not mine; a one-sided change would
  make the two disagree).
## K4 (issuer reasons)

**K4-Q1 — the ruled recovery (`heimdall issuer restore --backup <file>`) cannot replace the
unreadable item by itself (§17.28 item 6).** Observed here (disposable file keychain, unlocked):
after the program is replaced by a re-signed copy, the new identity's read is `errSecAuthFailed`
(now `issuer_store_access_denied`), and a deletion without UI (`SecItemDelete`, exact
service+account) is `errSecInvalidOwnerEdit` (-25244). So the log-intact restore's `put` (which
first reads to refuse overwriting) is denied too: a bare restore answers
`issuer_store_access_denied` again and deletes nothing. Once the old item is gone, the restore
works end to end (regression: modelled by recreating the test's keychain; the issuer returns to
`ready`). Whether Keychain Access deletes it on the real login keychain is not verified here (never
the owner's keychain).
- (a) **Built (most fail-closed; nothing is deleted by Heimdall):** next_command stays the restore;
  every message, the `issuer`/`issuer restore` help and the release note say "remove the old
  `heimdall-issuer/<fingerprint>` item in Keychain Access (login password; Heimdall never shows that
  prompt), then `heimdall issuer restore --backup <file>`".
- (b) The restore writes a second item under a new locator and records it through the existing
  compare-and-swap, the unreadable one listed as displaced for the owner to remove. Needs a
  store-design change (`SecretStore::get` reads by fingerprint + account, frozen U0 trait; the
  displaced-item deletion would fail the same way), so not built.
- (c) Developer ID signing (ADR-0004 Q-F), owner-blocked; removes the cause.
**Recommendation:** (a) for M03, (c) as the release fix; U13's claims table records the limit.
No switch: (a) is wording plus the refusal Heimdall already gives.
**ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.28 item 7), built in round 4:** restore to a
**new** item, never require a manual delete first. When the recorded K_ca item is unreadable with
`issuer_store_access_denied`, `issuer restore --backup <file>` writes the restored key to a new item with a
distinct locator (macOS: same service, account `<environment>#r<n>`, never colliding), recorded through
the attended `RegisterIssuer` decision with a compare-and-swap against the expected old locator (the
existing log-intact new-locator path, §17.22 item 12 / §17.23 item 4; no new authority). The old item is
listed in `orphan_store_items` with its exact service and account and the instruction to delete it in
Keychain Access; Heimdall never deletes it. `issuer status`, the doctor and the release note say exactly
this. Regression (macOS): copy A writes, copy B restores to a new locator; decision records it; old item
listed as orphan; B reads its new item; nothing deleted; fails with the fix reverted. Windows/Linux unchanged.

**K4-Q2 — code for `issuer_store_access_denied`.** Built `CAPABILITY_UNAVAILABLE` (exit 4), like the
other issuer store reasons: retrying or waiting cannot help, the owner must act (remove + restore);
`SERVICE_UNAVAILABLE` would mark it retryable. Confirm.

**K4-Q3 — doctor source.** No issuer-store section existed, so a new finding
`issuer_store_access_denied` (contract addition: `finding::M03`, golden `doctor_findings`, ADR-0006
row). It is read from an **already-running** runtime's `issuer.status` (the doctor never starts it
and never reads K_ca, ADR-0008 D1 custody); with no runtime running it reports nothing. Confirm
that limit.

## F1 (Windows git digest flake)
- **Q-F1-1 (docs owned by the orchestrator; edit or record):** `LOCAL_QUERY_TIMEOUT` is now 10 s
  (was 2 s). Normative text that still says 2 s for local queries: ADR-0007 l.666 ("Observation at
  preview uses local queries (Q4): bounded at 2 s"), ADR-0007 l.2097 ("It is a local query (2 s, no
  shell, stdin null)"), m02-plan l.811 ("Bounded at 2 s; the environment is not modified; Q4").
  Not edited (ADR/plan text). Recommendation: an ADR-0007 amendment line "local queries are bounded
  at 10 s (M03 wave 5 r4 F1; the bound is for a hung program, not latency)".
- **Q-F1-2 (additive localenv API, record):** `ProjectionTestConfig.local_query_timeout:
  Option<Duration>` and `ProjectionConfig.git_observed: Option<GitObserved>` (test-only, `None` in
  production), `git::observe_global_within` / `observe_global_for_within`. No exhaustive literal of
  either struct exists in the workspace. Recommendation: accept.
- **Q-F1-3 (note, not mine):** `integration_doctor` under `umask 002` fails 4 tests
  (`home_resolution_matches_ssh_g`, three `a21_*` Match-exec tests: the real `ssh -G` exits non-zero);
  under `umask 077` all 24 pass. Fixture files created group-writable (ssh refuses them); unrelated
  to F1's change. Owner: whoever owns `tests/integration/doctor.rs` fixtures.

## Integrator (round-4 records)
- **Q-I-R4-1 (record; confirm):** §17.28 item 7 needed a read by exact locator, so
  `heimdall_issuer::store::SecretStore` gained two **defaulted** methods (`get_item(&StoreItemRef)`,
  `put_new_item(fp, key)`; the default `put_new_item` refuses, so DPAPI and Secret Service are
  unchanged). No existing signature changed, and the trait is the issuer crate's, not `app::ports`.
  Recommendation: accept as built.
  **ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.28 item 8): confirmed**, accepted as an
  additive change.
- **Q-I-R4-2 (Q-L4-3, built):** the `possible_late_write` note and the TUI residual line now name
  `heimdall enroll verify <id> --absence` (the only command that clears the residual, §17.28 item 3),
  not `enroll remove`. The line-present message in `verify.rs` still suggests `enroll remove`; confirm
  whether a `withdrawn` record with its line present should be pointed elsewhere.
