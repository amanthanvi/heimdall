# M03 design targeted re-check, round 3 — 993c0348 — ready after fixes (one blocker)

Reviewer: Codex GPT-6.1 Sol (`codex-cpamc`, reasoning effort high), independent, read-only, separate
worktree; disposable loopback sshd and agent probes with per-run keys only. Saved by the orchestrator
on 2026-11-06, condensed but faithful in substance. Scope: closure of the round-2 findings (both
reviewers) and new defects in the revision-3 areas. Changed files: none.

**Verdict: ready after fixes.** The fencing blocker reopens through the specified dash process-group
check (M03-R3-01); three majors and one implementer-facing minor. The reviewer recommends another
round after correcting the blocker.

## Findings

| ID | Severity | Location | Defect | Fix |
|---|---|---|---|---|
| M03-R3-01 | blocker | D:1153 (esp. 1157); P:995–1003 | The leader-absent branch treats failure of `kill -0 -- -PID` as proof the group is empty; dash rejects that syntax. **Observed** (scratch model): holder killed and reaped, its mutation child stopped just before the write; `/bin/kill -0 -- -PGID` 0 (group alive); `dash -c 'kill -0 -- -"$1"'` 2 ("Illegal number: -"); dash `kill -s 0 -- -PGID` 0; applying the failure-as-gone rule, unlocking, writing the replacement and resuming the old child lost the replacement write. Reopens A R2-02. | A group probe that works on every supported shell; syntax errors, permission failures and unrecognized results are **unproven**, never gone; add the leader-absent, live-child case to the fencing tests. |
| M03-R3-02 | major | D:265, 270–280; P:421 | Step 6 checks expiry and safe time, then step 7 (the linearized enqueue) may wait up to 2 s. A deterministic bounded-queue model checked at t=9, expired at 10, enqueued at 11 (Inferred). The transport awaits `write_all` then `flush` (`ipc/src/signing.rs:180`). | Reserve outbound capacity first, then `may_release()` immediately before a non-waiting complete-frame enqueue; expiry cancels the capacity wait; a test crossing the deadline after the release check while enqueue is blocked. |
| M03-R3-03 | major | D:291, 295–301; P:440 | A newly discovered descendant sorts after its parent but not after every gate already held: cascade holds R, H; L (< H) finished delegating before R was taken; another narrowing holds L and waits for H; the cascade waits for L: H→L→H. A lock model reached the cycle (Inferred). | When the set grows, release and reacquire the whole set in global order, then re-validate; or serialize membership changes so the initial set is stable; define an overall wait bound across acquisitions. |
| M03-R3-04 | major | D:742, 893; P:316, 2501–2504 | Foreign removal needs `planned → removing` through the same `transition`, but the frozen table lets `planned` enter only `applying`, `manual_pending` or `withdrawn`; the seven-state foreign subset excludes the manual-removal states although D4:752–753 sends system-form entries to §6.9 (Inferred). | Put the foreign-removal admission event in the frozen contract and golden; state whether system-form foreign records use the manual states or an instructions-only lifecycle; cover approval, denial, lost reply, held recovery and the system-form route. |
| M03-R3-05 | minor | D:896, 1277–1280; P:1435 | The table replaces the approved host key on `held → reverifying`; the driver replaces it only on a verification pass, while the verifier reads the approved target (Inferred). | Keep the proposed target on the verification operation and use it for that attempt's pins; replace the approved target atomically only on success; state failure and inconclusive behaviour in the table. |

## Closure

Reviewer A's round-2 findings:
- R2-01: closed. The full pin set refuses every wrong-key case before any command runs.
- R2-02: not closed (R3-01).
- R2-03, R2-04, R2-05, R2-07, R2-08 and R2-09: closed. For R2-04 the managed-context probe showed 1 existing-agent signature and 0 managed messages.
- R2-06: partly closed (R3-02).

Reviewer B's round-2 findings:
- M03-R2-01, -02, -04, -06 and -08 to -18: closed. R2-04 is closed for delayed starts; termination is R3-01.
- M03-R2-03: partly closed (R3-03).
- M03-R2-05: partly closed (R3-05).
- M03-R2-07: partly closed (R3-04).

## Probes (exit codes)

OpenSSH 10.5p1. Fixture sshd config check: 0.

**Host-key trust.** The full pin set was used with approved key A and server key B.
- Each of the following was refused with 255, with no remote command run:
  - an inherited `KnownHostsCommand`;
  - an inherited user known-hosts file;
  - an inherited global known-hosts file;
  - `VerifyHostKeyDNS=yes`;
  - `NoHostAuthenticationForLocalhost=yes`;
  - host-certificate configuration;
  - all of them combined.
- A server presenting only a certificate was refused with 255, while a CA-trust control was accepted with 0.
- With an executable named `none` on PATH, the approved key was accepted (0), and neither `none` nor the inherited key supplier ran.
- `ssh -G` with the pins exited 0 and showed foreground `no`. With `-f -N`, `ssh -G` still reported `forkafterauthentication yes`, which confirms that `-f` must be refused.

**Maintenance in a managed context:** ssh 0, with 1 existing-agent signature and 0 managed signatures.

**Ready handshake:** ssh 0. The ready line preceded script delivery, and the remote shell led its own process group.

**`ln -s` lock:**
- An existing dangling lock returned 1 and was left unchanged.
- Two contenders returned 0 and 1, leaving one link.
- Pointing at a directory returned 0 and created the link inside the directory, which confirms the directory guard is needed.

**Writers and termination:**
- A writer paused just before its write, then terminated (with termination proven), then replaced: one marker, and unrelated data was kept.
- A stopped holder ignored TERM (it stayed alive); KILL ended it (exit -9); the group probe after reaping returned 1.
- Leader absent but a child still alive: shown under R3-01 above.

**Function-wrapper prefixes:** incomplete bodies never ran under sh or dash. Dropping only the final newline still runs the complete call, so the every-prefix golden must distinguish that valid case.

**Other models:**
- The macOS start and boot identity reads were stable across repeated reads.
- The enqueue and gate-order models reproduced R3-02 and R3-03.

**Cleanup:** ports closed, processes reaped, scratch removed.

**Not run:** builds, the production suite, native Windows/WSL/Linux, a real reboot, and a DNSSEC-positive SSHFP fixture.
