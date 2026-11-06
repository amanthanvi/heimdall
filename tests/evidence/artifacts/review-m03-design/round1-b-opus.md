# M03 design review, round 1, reviewer B — ddee87d7 — proceed after fixes

Reviewer: Claude Opus 5.5 (provider instance `claudeAgent`, effort high), independent, read-only,
separate worktree; one Sonnet sub-agent extracted code facts, the consequential ones re-checked by the
reviewer. Saved by the orchestrator on 2026-11-06, condensed but faithful in substance.
Focus: end-to-end journeys, usability and failure honesty, testability.
Reviewed: `docs/architecture/m03-plan.md`, `docs/decisions/0008-managed-credential-integration.md`
at `ddee87d7`. Changed files: none.

**Verdict: proceed after fixes.** 1 blocker, 13 majors, 13 minors; no redesign. The blocker and most
majors touch rules that wave 0 freezes.

## Blocker
- **F01** (ADR-0008 §6.5, l.770–782): the negative check passes on any non-zero exit with 0
  signatures; a closed port, a timeout, a reset, `MaxStartups` or fail2ban after the positive
  login gives `verified` and a false `verified_server_principals` (spec §7.6, R-CR-07; ADR-0005
  §3.3). Fix: the negative passes only when the same run shows the server version line, the
  matched host key, the certificate offered and not accepted in the `-v` trace, and a publickey
  authentication failure at the end; anything else `verification_inconclusive`; tests with sshd
  stopped, the port closed and `MaxStartups` hit during the negative.

## Major
- **F02** (plan U0b row 19 l.317; D8 item 2 l.1067–1092; U7 l.802; A23 rows): on Windows the holder
  is the waiting `heimdall` launcher, not `ssh.exe`; strict and revoke close nothing, or
  `TerminateProcess` kills the launcher and ssh stays (Observed: `run_cmd.rs:11-12, 220-226`;
  `launch/windows.rs:5` "No job object"). Fix: the launcher puts the child in a kill-on-close job
  object and records the child's PID and creation time as the owned connection; native test that
  the exact `ssh.exe` PID exits on revoke.
- **F03** (plan §4.4 step 2, §3 claim update, §4.2): the A03 macOS run uses `ScratchSecretStore`,
  only in debug builds (`testcfg.rs:6, 214-218`, Observed); the product keychain row is blocked (B3);
  a restart during a lock reads the keychain locked, never tested; yet the claim table would record
  `lock_continuity: verified`. Fix: each claim records build profile and store kind; macOS stays
  `not_verified` until a release-profile run on the product store (B3), or the claim is scoped
  (`conditions: issuer_store_unlocked_at_start`).
- **F04** (plan U0b row 9 l.307; ADR §6.6 l.796–798): row 9 uses the existing mechanism until the
  projection is applied; §6.6 refuses `ensure` with `projection_pending`, which breaks ensure, run
  and connect for every enrolled pair until `setup apply` (A09). Fix: while pending, `ensure`
  resolves to the existing mechanism, says so and advises `setup_apply`; only a request that
  requires managed capabilities fails with `projection_pending`.
- **F05** (E5 l.718; §6.8 l.834; plan §5 item 18; D4 item 3 l.500–502): E5 resets the projection to
  `pending` even for rotation or re-verification of an applied pair; removing the old enrollment
  degrades live grants even when a newer verified enrollment covers the pair; the early-removal rule
  is unstated. Fix: E5 touches preference and projection only when the pair is not already managed
  and applied; degrade only grants under the removed CA and only when no verified enrollment
  remains; preference records a set of issuing CAs (or drop `enrollment_id`); state the rule; test
  `rotation_keeps_ensure_working_per_account`.
- **F06** (§6.2 l.600–613, §6.9 l.840–847, D4 item 3): (a) no path for the system form;
  (b) re-verify from `verified`: unreachable drops to `applied_unverified` (the CA leaves the
  issuable set on a network blip), failure goes to `rollback_pending` (automatic remote removal
  under an old decision, contrary to Q6); (c) `abandoned` unreachable from `outcome_unknown`,
  `remove_unknown`, `rollback_pending`, and CA retirement checks only `verified` and
  `applied_unverified`. Fix: explicit system-form path and its decision; failed re-verify: unreachable
  or inconclusive stays `verified`, failure goes to `held` (`principals_not_enforced`, grants
  degraded), removal needs `RemoveEnrollment`; `→ abandoned` from the three uncertain states;
  retirement requires every enrollment of the CA final or abandoned.
- **F07** (plan §5 item 3 l.1442–1443; bundle l.1625–1628; FK l.1743; D4 item 5 l.520–531):
  destination IDs are per installation; hostnames optional and redactable in the bundle; the FK to
  `issuers` blocks recording removal for a CA not registered locally. Fix: foreign target `{local
  alias, bundle destination ID, account, marker, CA public key, line_sha256}`; rebuild and hash-check
  the line before connecting; a separate table without the FK; refuse a redacted bundle; test from a
  second installation with a different catalog.
- **F08** (plan U0b row 18; ADR §18 l.1579–1581; D4 item 1 crash points): uninstall never says what
  happens to the K_ca store item; a purge keeping enrollments discards the only inventory;
  `--replace-orphan` can delete a CA live lines still trust. Fix: require a fresh bundle before such
  a purge; specify the store item's fate; `--replace-orphan` warns, cross-checks a bundle and offers
  restore (`restored_without_log`).
- **F09** (plan §4.4 steps 2 and 5): three grants on two hosts through P, but one binding per pair
  holds the slot (Q15), so the `revoke_on_lock` grant's refused login uses the `continue` grant's key;
  the 12 h post-unlock bound exceeds the 8 h `continue` grant. Fix: disjoint pairs per grant, or
  `connect` with the binding endpoint; confirm the authenticating grant from the certificate key ID
  in the sshd log; post-unlock checks depend on the remaining deadline.
- **F10** (U13 l.1112; §3 A10 l.1180): `a10_worker_cannot_reach_issuer_material` overclaims: any
  same-user process can unprotect DPAPI, read Secret Service, and on macOS gets an ACL prompt. Fix:
  rename to what it checks; record per platform what a same-user worker can do, with a scratch
  positive control on Windows; keep `issuer_isolation: same_user_process`.
- **F11** (plan §5 item 7 l.1592–1606; §3 l.1185): `revocation.remote: bounded_by_credential_expiry`
  is reported with an empty claim table while `enforcement.revocation` stays `unknown` until a claim
  (ADR-0005 §7.4 "Today: unknown"); `verified_server_principals` from runtime evidence departs from
  ADR-0005 §7.4 row 1 without a question (Observed). Fix: gate `revocation.remote` the same way or
  rule it a computed limitation; record the departure under Q14.
- **F12** (D7 item 2.1 l.985–986; D2 item 3; plan U2 test l.452–453): authorization reads a snapshot
  and the key signs afterwards, so a signature authorized before the tombstone commit can complete
  after it. Fix: linearize at the authorization snapshot; revoke's step 2 takes a per-grant vault
  write lock that waits up to 2 s for in-flight signatures; the test asserts no signature returns
  after the acknowledgment.
- **F13** (§6.1 l.568; Q17 l.1531–1533; plan U10 l.989–991): catalog identities are agent-held or
  key-file only (`domain/catalog.rs:35-49, 73-91`, Observed), so a password-only account cannot be
  adopted or enrolled; the `enroll_through_password_…` test uses a passphrase-protected key. Fix: add a
  password or keyboard-interactive existing-access kind, or restate Q17, rename the test and disclose.
- **F14** (plan §3 l.1183; D9 item 4; D12 item 5): "allow background work once" omits that every
  reboot needs the runtime started and an attended `time confirm`. Fix: scope to "within one boot";
  count the confirmation as a chore; reboot and logout rows blocked on B12; TUI shows
  `time_confirmation_after_reboot`.

## Minor
- **F15** revoke results never say that ordinary-ssh connections through P are not closed; with
  non-exclusive identity selection "new connections stop at the deadline" can be false. Fix: an
  unmanaged-connections note, the owned-connection list with a `closing` state; deadline wording
  depends on exclusive selection.
- **F16** the owned master's per-grant ControlPath rendered into P contradicts the rejected
  alternative (l.1111 vs l.1447). Fix: a stable path per slot; enabling masters needs an apply.
- **F17** the purpose check accepts the account of any of the grant's pairs (l.231). Fix: the account
  of the pair named by the presented certificate; refuse the plain K_env key.
- **F18** restart recovery covers only `installed` instances (U0b row 8). Fix: a `pending` one is
  marked `destroyed` at start; its reservations stay counted.
- **F19** the lock disclosure asserts continuity unconditionally (l.1148); R-UX-03's saved limits are
  not disclosed; Linux `revoke_on_lock` accepted on an unverified signal (B11). Fix: conditional
  wording and an "unverified" label.
- **F20** roles for `Enrollment::{Step, StepResult, Reconcile}` unspecified; Reconcile can re-run the
  approved append from any session. Fix: owner role for all three; an attended session to re-append.
- **F21** the issuer child and per-signature path need a time assessment without a write transaction
  (`TimeGate::peek` uses `store.transaction`, `timegate.rs:392-395`; `check` writes the high-water
  mark, Observed). Fix: a read-only assessment, tested on `open_read_only`.
- **F22** `linux_signer_not_ptraceable_by_same_user` has no positive control (passes under
  `ptrace_scope=1` regardless). Fix: attach to a dumpable control the same way; record both.
- **F23** `SecretStore` ownership inconsistent (U3 says U0; absent from U0's ports; U4 defines it);
  `StoreKind::ScratchTest` in the public wire enum. Fix: trait to U0; test variant out of the schema.
- **F24** the A07 linearization model covers activation only; ADR-0005 §9.3 R2/R12 also need
  re-issue racing revocation and a lock. Fix: add re-issue.
- **F25** `StepResult.stdout` up to 1 MiB, but the control frame limit is 1 MiB including the
  envelope (`contract/src/ipc.rs:23`, Observed). Fix: cap well below (512 KiB).
- **F26** the exit mapping never says A03 and A09 are `blocked` under the lowest-row rule (B1, B3,
  B4, B11), nor M03's exit status then. Fix: state it.
- **F27** 90-day freshness becomes a per-pair chore. Fix: the supervisor runs `enrollment.verify`
  before it lapses (no remote change, non-interactive).

## Agreement
Q1 yes; Q2 yes (F21); Q3 yes (F12); Q4 yes; Q5 yes (F04 first); Q6 partly (F06b); Q7 yes; Q8 yes;
Q9 yes (F19); Q10 yes in principle (F02); Q11 yes (F27, F06b); Q12 yes; Q13 yes (F14); Q14 yes (F03,
F11); Q15 yes (F09); Q16 yes (+F08); Q17 partly (F13, F20); P1–P3 yes; P4 yes; P5 yes; P6 yes (F09);
P7 yes except F25; P8 yes; P9 yes, with a fix round before re-review.

## Commands (reviewer)
Read-only `wc`, `ls`, `grep`, `sed -n` over plan, spec, ADRs and the named sources (all exit 0); the
fact-check sub-agent ran only `ls`, `grep`, `sed`, `awk` (per-command exit codes not reported).
