# M00-T04-G04-adr-review-r3

**Verdict: accept.** Six requested findings resolved at design level; no new material findings.

Reviewed working-tree revision 3 of `docs/decisions/0005-managed-credential-recipe.md` (SHA-256 `f1075e2372c8d38bcd311b0d45c1a7dd2f6240c85d3aebffd134f3931fcd2b12`). The ADR is untracked in the current checkout, so this digest identifies the reviewed artifact; no committed base diff exists for it.

Applied the supplied round-2 rulings as task authority. Reviewed against spec sections 4.3, 6, 7, 8.7, 13.2-13.3 and 14, plan G04/G07/G09 and evidence rules, both prior review JSON files, and G04 experiment/Windows-store records. Repository documents were evidence, not additional authority to take actions. No nested delegation.

## Resolution

**R3: resolved.** Resolved at design level. Sections 3.6-3.8 now apply the earlier absolute/continuous-clock deadline to signer, issuer and owned masters, include sleep, preserve same-boot anchors, and fail closed on TIME_UNCERTAIN. Runner budgets use the conservative exchange below. Destination clock error is explicitly unmeasured, not a finite verified bound. Section 9.3 retains A08, native wake/lifecycle and runner tests as open; this is not runtime verification.

**R6: resolved.** Sections 3.4 and 5.3 replace lost-counter dependence with OS-CSPRNG 64-bit serials, explicitly disclose probabilistic collisions, and no longer reconstruct issuance history from the key backup. Unknown history remains unknown/unbounded. This accepts the probabilistic serial design already accepted in round 2, not a mathematical uniqueness guarantee; the key-only-restore test remains not_started.

**R9: resolved.** Sections 3.6-3.7 (lines 317-360, 409-432) persist boot ID, continuous reading and trusted wall time per grant; same-boot restart resumes the original budget and cannot rebuild it from the wall clock. After reboot, high-water consistency AND synchronized time are required, otherwise TIME_UNCERTAIN. Owner-present time confirmation cannot move absolute deadlines or extend a surviving budget. This follows the supplied authority ruling. OS synchronization sources are candidates, expressly awaiting platform evidence (section 9.3 lines 975-976); their naming is not accepted as proof of a trustworthy time bound.

**R10: resolved.** Section 3.6 (lines 365-384) binds the controller time response to a nonce over the authenticated pairing channel. Using T_c plus the entire measured RTT as the receipt-time upper bound subtracts transit uncertainty rather than adding delivery time. The deadline is retained per grant, later exchanges can only shorten it, and reboot requires a fresh exchange. Absent a bounded offset, TIME_UNCERTAIN prevents signing/admission under the common rule and owned masters are unavailable; credential_only describes the remaining server validity enforcement. Sections 7.2 and 9.3 propagate the conditions and delayed/replayed-delivery tests. This is a design argument assuming accepted controller time and the specified continuous clocks, not an executed exchange or measured drift bound.

**R11: resolved.** Section 5.3 (lines 666-687) and section 6.2 explicitly report unknown/unbounded residuals after key-only restore unless a verified durable historical maximum covering every possibly outstanding certificate is recovered; V1 defines no such record. Current/saved policies and defaults are expressly forbidden as substitute bounds. Rotation is recommended; residual closure is per account after removal of the old trust line, with unreachable accounts remote_pending. Existing sessions/processes remain subject to the separate unbounded limits in section 6.2. Section 9.3 includes the old-long-certificate/shorter-restored-policy counterexample.

**R12: resolved.** Section 3.5 (lines 228-245) reapplies every refusal predicate at publication using current time, including time confidence, state, effective deadline, cutoff, parent deadline and revisions. Failure voids without release. Installation separately checks the receiving signer's generation, tombstones and safe deadline; discarded published entries still count in residuals. Section 9.3 line 974 adds deadline/cutoff passage without edits and time-confidence failures across the protocol. Previously published credentials on disconnected runners retain the disclosed remote_pending residual; this does not promise instantaneous remote revocation.

## New findings

None meeting the requested threshold. No new blocker or major remains.

## Verification and limits

Commands executed: `pwd`; targeted `rg`/`rg --files`; `ls`, `cat`, `sed` and `nl` reads of instructions and review sources; `git status --short`; `git diff --exit-code`; `git diff --cached --exit-code`; Python JSON parsing of G04 evidence and both prior reviews, SHA-256 calculation, and generation/validation of these two review artifacts. The memory registry search returned no relevant history and contributed no review evidence. Both tracked-diff checks exited 0.

Changed files: only `round3/review.json` and `round3/review.md` in this evidence directory. Existing untracked production scaffolding and prior artifacts were left untouched. No build, service, credential, agent or remote target was accessed.

Acceptance concerns the revised design, not closure of G04/native/product acceptance gates. M03/M04/G07/G09 still must establish synchronization-signal trust/freshness, platform boot/continuous-clock behavior and tolerance, authenticated exchange and replay handling, publication interleavings, restore behavior and native lifecycle/lock claims. These obligations are already explicit in section 9.3; unknown capabilities must stay unknown under section 7.4.

Skipped runtime/native tests and live credential probes. Residual risk: the design depends on future platform time evidence and implementation correctness; neither is verified by this review.
