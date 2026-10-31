# M00-T04-G04-adr-review-r2

Verdict: **accept after fixes**. Resolution: **6 resolved, 2 partly, 0 not**. New findings: **0 blockers, 3 majors, 1 minor**.

Reviewed revision 2 of `docs/decisions/0005-managed-credential-recipe.md` in the working tree (SHA-256 `4135a9d54108c1cf10eeab9d765b53f68c7451821bb19b2177c90c79c6dff008`); repository HEAD `03eabdfea48328bb86ed15d6e4ebd861df04cec2`. The ADR is untracked at this snapshot, so its hash identifies the review input.

## Scope and authority

Independent read-only review against spec.md §4.3, §6, §7, §8.7, §13.2–§13.3, §14, A07–A10, plan.md G04/G09 and §6.3–§6.6, the round-one report, current ADR-0004 §2, and G04 evidence metadata/limitations. The supplied orchestrator rulings are treated as decisions, including the disclosed registry replacement race and D2 supersession. No nested delegates, tracked-file edits, commits, pushes, service interaction, real credentials, or native probes.

## R1–R8 resolution

- **R1: resolved.** Resolved against the supplied orchestrator ruling: single-write O_APPEND/exclusive creation for add, compare-then-rename for removal/rotation, durable intent, reread/outcome_unknown reconciliation, explicit irrecoverable race disclosure, accurately scoped E4/ENR, and planned interleaving tests (§3.3, §6.5, §9.3). This accepts the ruled design limitation; it does not prove the full spec §7.5/A09 concurrent-edit preservation guarantee. Implementation and interleaving evidence remain not_started.

- **R2: resolved.** The original revoke/log race is closed at the design level (§3.5): reservation commits complete bounds before signing; revoke and publish serialize on current generations/ancestor/policy revisions; reserved and published entries count even on delivery/ack loss. A stale post-revoke publication is voided. Crash recovery never republishes a reserved entry. Release after an earlier successful publication may still arrive after revocation, but is already counted; local use must pass §3.6 and disconnected-runner use remains remote_pending. No unreported certificate follows from the specified crash ordering with an intact store. New time-at-publication omission is R12, separate from the original generation race.

- **R3: partly.** Live-process sleep-counting monotonic limits, high-water persistence, forward/rollback uncertainty, signing refusal and master closure are now specified. Restart validation remains insufficient (R9); runner receipt-time rebasing expressly permits extra time (R10). Destination skew is disclosed, but is not evidence of a measured finite server-error bound. A08/G09 cases remain not_started/blocked.

- **R4: resolved.** ADR-0004 §2 now explicitly supersedes D2 under the delegation supplied in the brief. §3.7 requires unchanged scope/D, unexpired/non-revoked/non-released/non-cutoff authority, validated time, transactional generations/tombstones, no process-file authority, and no recovery with lock-revokes. Process restart, logout/login, reboot/login and runner restart are separately listed for testing. §3.5 additionally excludes other terminal states. The decision conflict is resolved; whether time validation actually establishes unexpired authority is the remaining R3/R9 defect, not a renewed objection to the authorized D2 ruling.

- **R5: resolved.** §3.3 specifies an independent constrained SSH client, no user config/fallback/multiplexing, host verification, positive signature observation and a wrong-principal refusal; log attestation is optional/unavailable without access. §7.4/§9.3 require a log-inaccessible-account test. This resolves the account-level log-authority prerequisite as a design change; the new verifier has not run.

- **R6: partly.** Random OS-CSPRNG 64-bit serials remove dependence on a lost counter; probabilistic collision risk is disclosed. But §5.3 now replaces unknown residuals with restore time plus the longest validity in saved policies/default 12 h, which is not necessarily an upper bound on certificates issued under missing historical policies (R11). Random serials alone do not reconstruct issuance history or make that bound conservative.

- **R7: resolved.** §5.2 now explicitly says no selected login-keychain run exists, distinguishes the disposable file-keychain X4 result, and requires disposable-account/update validation before availability or ACL claims. Native Heimdall custody remains unverified.

- **R8: resolved.** §5.2 and §9.1/§9.3 incorporate WSS as verified/pass for Rust store mechanics, preserve the Go TPM-delete failure and self-review/no-positive-export-control limitations, and keep lock/signout/sleep/reboot and cross-user claims open. Parsed the current WSS record and checked those scopes; did not rerun native tests.


## New findings

### major: R9 — §3.6 lines 285–304; §3.7 lines 330–350; §9.3 A08 restart criterion line 868

Consistency with a persisted wall-clock high-water mark does not establish safe current time after downtime. Restart discards the monotonic budget and constructs a fresh one from the current wall clock. A rollback that remains above the last trusted mark can therefore revive elapsed authority without triggering TIME_UNCERTAIN.

**Evidence / trace.** Static counterexample: last trusted persisted time 10:00, D=11:00, runtime stops; real time reaches 12:00 while stopped; wall clock is reset to 10:01; reboot/login occurs. 10:01 exceeds the high-water mark and a new monotonic reference has no prior elapsed interval, so the stated predicates permit reissue and a new 59-minute budget. The grant was not running to persist an expired state. A correctly timed destination may refuse the old D, but local signing and owned-master admission still exceed the original elapsed authority; correlated server rollback is also not excluded. spec §6.4/A08 and plan §6.3 require restart not to reset time or restore expired authority. This is a design trace, not an executed product failure.

**Required correction.** Define what startup validation trusts across each lifecycle event. Preserve a grant/boot-scoped continuous-clock anchor across same-boot process restarts. After reboot or loss of that anchor, require a trustworthy current-time bound that establishes remaining validity; high-water consistency alone is insufficient. Otherwise remain TIME_UNCERTAIN and do not reissue/sign/admit. Never reset a surviving grant budget at key reload. Test downtime spanning D followed by rollback to a value above the persisted high-water mark, separately from rollback below it.

### major: R10 — §3.6 lines 305–313; §3.8 lines 370–377; §7.2 lines 730–732

The runner starts its monotonic budget at receipt using the controller's remaining duration at send time. This knowingly adds delivery time to the budget, contrary to the no-extra-authority and owned-master deadline guarantees. The absolute branch does not eliminate the extra interval when the runner clock lags within tolerated skew, and the delivery check does not define a safe delay/clock-offset bound.

**Evidence / trace.** Static counterexample for any positive allowed tolerance: controller sends at T with D=T+60 s; delivery takes 10 s; runner wall clock is 10 s behind. At receipt its wall clock reads T and the controller-stated remaining duration is still 60 s, so both wall and receipt-based monotonic deadlines expire at actual T+70 s. Comparing the runner reading with the send timestamp sees no disagreement; even a current-time comparison allows this if tolerance >=10 s. An owned master authenticated before D can admit new sessions for the extra 10 s regardless of a correctly timed destination rejecting fresh authentication. §3.6 expressly acknowledges ending late by delivery time, while spec §6.4/§6.6/A08 disallow this authority extension. No product execution was performed.

**Required correction.** Derive the runner deadline from a conservative upper bound on current controller time / transit age using an authenticated time exchange or another explicit bounded-delay/skew mechanism; subtract uncertainty so the runner may stop early. Retain that deadline for the grant rather than restarting it on receipt/reissue. If a safe bound is unavailable, report TIME_UNCERTAIN/CAPABILITY_UNAVAILABLE and do not claim deadline admission. Add delayed/replayed delivery, tolerated negative runner skew, and live-master admission tests.

### major: R11 — §5.3 lines 582–588; §6.2 line 613; §9.3 key-only restore line 870

The key-only restore fallback can underreport outstanding certificate validity. The longest validity any saved policy permits is not necessarily the longest validity any historical policy permitted, especially after the database and issuance log were lost. The 12-hour proposed default is not a historical issuance ceiling. Elapsing the guessed bound cannot safely complete reconciliation.

**Evidence / trace.** Static counterexample: a prior policy allowed a 7-day grant and the CA issued a 7-day certificate immediately before database loss. Restore K_ca an hour later with only a 12-hour saved/default policy. §5.3 substitutes restore+12 h for unknown and considers reconciliation complete then, while the certificate may remain valid for almost 7 days. spec §6.5/§6.7 require truthful maximum residuals; §2 P04 is a default and §6.1 allows saved policies to outlive/change separately from issued grants. Clock validation cannot recover the missing historical validity ceiling.

**Required correction.** Keep residual unknown/unbounded unless a verified durable historical maximum for all possibly outstanding certificates is recovered (or an immutable previously enforced issuance ceiling is provable). Alternatively remove/rotate trust at every affected account and track unreachable accounts as pending. Do not infer a bound from current policies or defaults. Test an old long-validity certificate plus a shorter restored policy and no recovered issuance log.

### minor: R12 — §3.5 lines 216–226, 240–254; §9.3 line 867

Publication rechecks generation/revisions/tombstones but omits current time, TIME_UNCERTAIN and the grant state/refusal predicates. Passage of D/cutoff or a new time fault need not advance any revision, so a reservation made just before the deadline can still be published afterwards.

**Evidence / trace.** Static trace: reserve at D−1 s; signing is delayed; publish at D+1 s with unchanged generations and no tombstone yet. The stated publish transaction succeeds although the refusal list says the minimum deadline has passed. Likewise a time-confidence failure between reserve and publish does not inherently change generation. The certificate remains in the residual log and a correct signer should refuse it, so this is not an unreported-certificate race, but the issuer refusal/recovery contract is incomplete.

**Required correction.** At publication reapply all current authorization/admission predicates, including grant state, effective deadline/cutoff/parent and time confidence, along with generation checks; void on failure. Require receiver installation/admission to check its own current generation, tombstone and safe deadline. Extend deterministic tests to expiry, cutoff passage without an edit, and TIME_UNCERTAIN between reserve/sign/publish/delivery.

## Reserve/sign/publish crash and race assessment

| Interruption/order | Consequence under §3.5 |
|---|---|
| Before reservation commits | Signing is prohibited; no credential exists. |
| After reservation commit, before/during sign | Reserved bounds are durable and count; after restart never publish that reservation. |
| After signing, before publish | Still reserved and counted; no release permitted. Lost result cannot create an unlogged certificate. |
| Revoke/cutoff edit wins before reserve | Current state/generation prevents reservation. |
| Revoke/cutoff/ancestor revision wins between reserve and publish | Publication recheck voids; no release, so exclusion of voided entries is sound within this contract. |
| Publish commits, process crashes before/during release | Published entry remains counted even without delivery acknowledgment. |
| Publish commits, revoke commits, delayed release arrives | Possible post-revocation delivery, already included in residual. A reachable local signer must enforce current tombstones/generation per signature; disconnected runner remains remote_pending. Publication is not delivery acknowledgment. |
| Natural expiry or time uncertainty between reserve and publish | Revisions may remain unchanged; R12 requires a current-time publication guard. |

The invariant depends on durable transactional storage and never releasing before a confirmed publish commit. Crash recovery may conservatively overcount reserved entries, which is safe. Key-only loss of that log is a different failure domain (R11). No deterministic protocol test has run in this review.

## Time and recovery assessment

Within a continuously running process the earlier-of rule accounts for sleep and prevents a backward wall step from enlarging the original budget. Forward jumps may cause early denial and are expressly uncertain. Wake validates before admission. Destination clock error is now separately disclosed, but no finite measured skew bound is established; capability fields must remain conditional. The remaining defects are loss/rebasing of the elapsed budget across restart (R9) and delayed runner receipt (R10). Recovery predicates otherwise preserve scope/deadline and reject terminal/cutoff/revoked grants; R9 prevents treating their wall-clock expiry check as sufficient proof. No authority exists in a process file under the revised rule.

## Evidence and validation

Commands executed: `pwd`, `rg --files`, targeted `rg -n`, `cat`, `nl -ba ... | sed -n ...`, `sed -n`, `wc -l`, `git status --short`, `git rev-parse HEAD`, and Python standard-library JSON parsing, SHA-256 hashing, artifact writing and schema-shape assertions. Read active home/repository AGENTS.md. The targeted memory registry search returned no task-relevant hit; no memory-derived conclusion was used.

Parsed all 28 current `tests/evidence/g04-*.json` records. Experiment verdicts remain scoped mechanism observations; E7P is verified/fail, not erased. WSS is verified/pass for Rust mechanics with the Go TPM-delete failure and native lifecycle exclusions retained. E2 expressly excludes skew/rollback; E4/ENR do not exercise the final-check/rename race; E6 uses fixture administrator logs. Checked these limits against ADR wording. Did not independently rerun their harnesses or audit every artifact byte.

Changed files: only this directory’s `review.json` and `review.md`. JSON is validated for the requested top-level structure, eight unique R1–R8 resolutions, allowed resolution statuses/verdict and finding fields.

Skipped implementation and native lifecycle tests; this review establishes design findings only. Remaining risk: the three major traces can extend local authority or understate residual certificate validity until corrected.
