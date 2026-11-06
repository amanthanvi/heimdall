# M03 design review, round 1, reviewer A — ddee87d7 — proceed after fixes

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06, condensed but faithful in
substance: every finding, its location, evidence class and fix, and every agreement.
Reviewed: `docs/architecture/m03-plan.md` and `docs/decisions/0008-managed-credential-integration.md`
at `ddee87d7`. Changed files: none.

**Verdict: proceed after fixes.** 3 blockers, 12 majors. B1 stays a reasonable architecture; the
reservation protocol, CA/execution-key separation, unchanged grant deadlines and explicit native
blockers are sound directions. "Observed" = verified in document text, current code or a scratch
probe; consequences for the unimplemented design are "Inferred".

## Findings

| ID | Severity | Location | Defect | Fix |
|---|---|---|---|---|
| M03-R01 | blocker | ADR-0008 D2 (l.190–213); plan U2 (l.411–415) | Authorization and signing have no shared linearization point: `authorize()` returns `Admit` before `KeyVault::sign()`, and the store releases its transaction and mutex on return (`store/lib.rs:369`, Observed). A request can be admitted, pause, let revocation commit, then sign (Inferred), contradicting D2 and A07 (`spec.md:311`, `:996`). | One synchronization protocol from authorization through signing, shared with revocation, cutoff and authority changes; say whether the linearized effect is the signature or its release; a deterministic pause-after-authorize-then-revoke test (uncontrolled interleavings alone are not enough). |
| M03-R02 | blocker | ADR-0008 D5 §6.1 (l.554), §6.3 (l.646) | Remote mutations are not bound to the approved destination, account and host key: the invocation uses the ordinary alias without pinning HostName, Port, User or the approved key; `EnrollmentSpec.account` may override while verification takes User from the catalog (l.756) (Observed). A config change after approval can redirect the append (Inferred; `spec.md:360`). | Bind every remote step to the approved host, port, account and host key; revalidate the route before dispatch; refuse overrides that cannot be realized consistently. |
| M03-R03 | blocker | ADR-0008 D5 §6.5 outcome table (l.773) | The negative verification accepts `exit ≠ 0` with zero signatures; only the version line is parsed (l.770). A scratch model accepted a connection-refused negative after a good positive (Observed). Zero signatures does not prove the pinned server refused the negative principal (ADR-0005 l.163; `spec.md:374`). | Require evidence that the negative attempt reached the pinned server and completed public-key rejection; transport, host-trust, startup and ambiguous failures are inconclusive; faults between the two attempts. |
| M03-R04 | major | D5 §6.3 (l.646); D10 (l.1199) | Remote maintenance steps use the ordinary alias with P included, and after the projection P selects the managed agent, key and certificate (an isolated `ssh -G` probe kept all three, Observed). Rotation, removal, rollback and reconcile can depend on the credential they repair (`spec.md:362`). | An explicit, approved existing-access invocation for maintenance that stays usable after the switch; test rotation and removal with every managed binding released and the issuer unavailable. |
| M03-R05 | major | Q6 (l.1482); verification outcomes (l.777); plan operation contracts (l.1400) | Re-verification is "nonmutating" and decision-free (`enrollment.verify` local), yet the shared outcome table rolls the line back on failure (Observed). | Separate the initial verification's rollback (authorized by the enrollment decision) from later re-verification: a later failure invalidates the evidence and reports degradation; removal needs its own approved operation. |
| M03-R06 | major | client-executed steps (l.625); append (l.683); reconcile (l.804) | Timeout recovery does not fence a still-running remote mutation: a timeout is uncertain, reconcile may see no marker and dispatch again; `step_token` rejects stale reports but not the old script. Overlapping check-then-append produced two marker lines in a scratch probe (Observed; `spec.md:587`, `plan.md:436`). | Remote serialization around marker check and mutation, stale-lock handling, one outstanding step locally; absence read after a timeout never authorizes redispatch by itself; test a first script that survives the timeout and resumes. |
| M03-R07 | major | D5 state table (l.600); plan U0 golden (l.265) | The frozen table has no `verifying → held` (host-key mismatch needs it, l.781) and no `outcome_unknown → withdrawn` (lapsed approval, l.810); `remove_unknown` loses whether removal was explicit or a failed enrollment's rollback (Observed). | Reconcile the state/event table, stage receipts and outcomes before freezing; keep removal purpose across uncertainty; test every documented recovery path. |
| M03-R08 | major | plan M5 (l.165), U0b row 19 (l.317); D8 (l.1067) | `run` registers its own PID as holder (`run_cmd.rs:219`) and on Windows spawns a separate child (`launch/windows.rs:69`): ending the launcher need not end ssh. `connect` binds nothing today (`connect_cmd.rs:38`) (Observed). | Separate binding holder from controlled connection process; durable registration of the spawned ssh PID and start token before strict control is advertised; design connect's ensure/bind/ownership flow; test launcher death with ssh alive. |
| M03-R09 | major | plan U9 (l.901, l.931) | `watch::Receiver<LockState>` keeps only the last value (Tokio 1.54.1 `watch.rs:521–522`, Observed): locked→unlocked before the supervisor reads can erase the lock that must permanently revoke (D9 l.1159–1164). | A monotonic lock epoch or latched "lock observed" that cannot clear before the revocation pass acknowledges it; current state kept separately; test with the consumer paused. |
| M03-R10 | major | D7 time-bounded obligations (l.1003) | Obligations clear at local `valid_before`, while destination clock error is unmeasured (l.995–998); ADR-0005 bounds the remote residual by expiry plus destination clock error (ADR-0005 l.719). | Distinguish nominal expiry from a bounded remote completion; clear only with an established server-clock bound or verified removal/rejection, otherwise keep an explicit unknown residual; slow-server-clock case (`spec.md:313`). |
| M03-R11 | major | D4 ceremony (l.444), retirement (l.503); plan Register (l.1348) | `Register` needs the backup ciphertext hash before D4 creates the backup; retirement deletes from the store and issuer memory with no durable multi-step state (Observed; `plan.md:446`). | Prepare the exact encrypted backup bytes before submitting their digest, write and verify them after approval; retirement as a durable transition (disable issuance, unload, delete), idempotent on restart; failures between each step. |
| M03-R12 | major | RemovalTarget (plan l.1439); RecoveryBundle (l.1625); system form (ADR l.838) | `RemovalTarget::Foreign` drops the bundle's registry path and form and lacks the public CA line; system-form trust lives in administrator-managed files, which the authorized-keys removal does not touch (Observed; `spec.md:382`, ADR-0005 §6.3). | Carry the full validated public removal descriptor, covered by the decision and request hash; a separate manual removal and re-verification workflow for system form, never claimed as removed automatically. |
| M03-R13 | major | plan U6 (l.715), U10 (l.950), ports (l.1778) | `IntegrationSnapshot` cannot carry enrollments, slots, claims or issuer status (`ports.rs:185`); `prepare_from` forbids store and live reads (`ports.rs:298`) while U6 needs reserve/publish; app calls `heimdall_enroll::registry` while enroll implements `app::ports::VerificationRunner` (cycle); known-host observations keep fingerprints, not raw lines (`known_hosts.rs:29`) (Observed). | Draw and check the dependency graph before freezing signatures; pure enrollment types below app or injected through ports; extend preparation inputs and define a managed effect-driver contract; raw host-key support and a read-only issuance check with owners. |
| M03-R14 | major | plan U4 test (l.563) | The interop test runs `ssh-keygen -y -P <pass> -f <backup>`, putting the passphrase in argv, which U4 itself forbids (l.580; `spec.md:344`; AGENTS.md). | Drive stock ssh-keygen through a PTY and type the passphrase at its prompt; restrict transcript capture. |
| M03-R15 | major | D8 master start and P (l.1100); plan U8 (l.853) | A master gets a random runtime ControlPath that P must name, but P changes only through approved setup transactions and D10 uses stable slots to avoid that. | A stable, generation-protected per-pair multiplex slot/path inside the approved projection, or an explicit reapply; define restart, replacement and cleanup; test two successive bindings with ordinary ssh. |

## Agreement with the recommended answers

| Item | Verdict | Reason |
|---|---|---|
| Q1 no issuer listener | agree | less exposure; fits B1's disclosed same-user boundary |
| Q2 sign by reservation | agree | never trusts caller bounds |
| Q3 signer in runtime | agree with R01 | placement fine; needs real sign/revoke synchronization |
| Q4 defer Recipe A | agree, recorded | record the delivery change against ADR-0004/0005 |
| Q5 one mechanism per grant | agree | mixed requests fail before effects |
| Q6 decisions | agree only after R05 | re-verification must stay nonmutating |
| Q7 24 h retry | conditional | same approved target and effect, safe elapsed time, R02/R06 fencing |
| Q8 create `.ssh` | agree | in the approved plan, restrictive mode, refuse unsafe or raced state |
| Q9 lock revokes | agree with R09 | latching event model |
| Q10 connection policy | agree with R08, R15 | |
| Q11 90-day freshness | conditional | invalidate earlier on destination, account, host-key, CA or client change or contrary evidence |
| Q12 clear by local expiry | disagree | R10 |
| Q13 no synchronized-time trust | agree | |
| Q14 claim table | agree with constraints | native evidence matching custody, versions, architecture and claim |
| Q15 one binding per pair | agree for M03 | conflicting `run` fails before launch; `connect` per R08 |
| Q16 `--not-stolen` | agree | keep unknown residuals; working removal (R12) |
| Q17 CLI runs remote steps | agree with fixes | R02, R04, R06 |
| P1 unit split | conditional | R13; one integrator landing rule for U0b row 19 and U10 |
| P2 three crates | conditional | remove the app/enroll cycle |
| P3 zbus | agree | Linux evidence blocked until measured |
| P4 WSL rootfs download | agree | verified provenance and hash, exact cleanup |
| P5 display sleep only | agree | display sleep is not lock proof |
| P6 separate lock runs | agree | |
| P7 limits | conditional | derive payload limits with serialization overhead; truthful timeout outcomes |
| P8 shared evidence helpers | agree | |
| P9 design review | agree | |

Platform plan: evidence boundaries generally preserved; keep the lowest-row rule.

## Commands (reviewer)
Read-only `git`, `rg`, `nl`/`sed`, `wc` (exit 0); one `rg` on a non-existent path (exit 2); a
`python3` scratch probe with an isolated `ssh -G -F <scratch>` (exit 0: managed selections kept,
duplicate append under overlap, negative predicate accepting a transport failure); a Tokio watch
documentation lookup (exit 0); final `git diff --exit-code` clean (exit 0). No builds, no tests, no
native runs; the scratch directory was removed.
