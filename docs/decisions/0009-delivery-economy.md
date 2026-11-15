# ADR-0009: Delivery economy, M03 wave 6 onward (2026-11-15)

**Status:** accepted · **Date:** 2026-11-15 · **Decided by:** the orchestrator, under the owner's
delegation (ADR-0004), on the owner's instruction of 2026-11-15: find where delivery can go faster,
finish every milestone end to end, and run only tests and work that are meaningful, not
performative.
**Scope:** how waves are reviewed, verified, tested and recorded from M03 wave 6 onward. Spec and plan
obligations are unchanged. Plan §6.7 already asks for the smallest appropriate regression, focused
tests during development, and full suites at integration points; this ADR applies that literally.

## 1. Context: where M03 wave 5 spent its time

- **The work:** 16 rounds, 8 independent review passes and 5 in-integrator audits. Rounds 11–16
  all hardened one feature (the purge's handling of the state database) against progressively
  narrower races by a hostile same-user program, under ADR-0008 §17.33 item 10.
- **The native runs:** a Windows run (about 22 min) and a devbox run (about 50 min, two batches,
  each forcing a full Linux cross-rebuild) followed most rounds.
- **The overhead:**
  - `check.sh` (15–25 min) ran several times per round;
  - every regression carried a three-run revert proof;
  - each round added an ADR section, 15 for the wave.
- **The losses:**
  - workers ended their turns while waiting on background commands, losing about 10 hours in one
    stall and several shorter ones;
  - a provider's content filter stopped two reviews.

## 2. Decisions

1. **One review cycle per wave.** One independent review of the wave's diff, adding plan §6.7's
   security review where the wave touches its listed boundaries. Then one scoped re-check of the
   fixes, then the merge.
   - **What blocks the merge:** a finding blocks only if both of these hold:
     - it has a lasting effect on remote trust, recovery records or the owner's data, or it
       bypasses consent;
     - its trigger is one Heimdall must withstand: an ordinary crash, an I/O error, the user's own
       action, a remote party, or another account.
   - **Hostile same-user programs:** a finding that needs a hostile program running as the same
     user (spec P03) is recorded in `RESIDUALS` with its probe. The exception is a finding that
     gains that program something it could not do itself: privilege, a remote effect, another
     user's data, or authority beyond the owner's. That one blocks.
   - **What this replaces:** this replaces ADR-0008 §17.33 item 10's extension to same-user
     programs for new work. The residuals already recorded stand.
   - **When a design needs a second re-check:** the design gets simplified before it is patched
     again.
2. **Native runs at merge candidates.**
   - **Per wave:** Windows and the devbox run once, on the merge candidate.
   - **Platform-specific changes:** in between, they get a targeted run (`HM_ONLY`, or a filtered
     `cargo test`).
   - **Exit evidence** is produced at milestone exits.
3. **Meaningful tests only.**
   - **New tests:** a new test covers a behaviour no existing test covers. That means one
     regression per fixed defect, and an end-to-end case only when the behaviour crosses a
     boundary.
   - **Reviewer probes:** a reviewer's probe becomes a permanent test only when no existing test
     covers that property.
   - **Revert proofs:** only fixes that block a merge carry one: the test fails with the fix
     reverted and passes with it restored.
   - **Residuals:** a residual's probe points at an existing test.
4. **Gates at commit points.** While iterating, run the affected crates' tests. `check.sh`,
   `linux-xcheck --workspace` and the umask-002 targets run once per commit that goes to a branch.
5. **Lean records.**
   - **ADR sections:** an ADR section records authority, contract, threat-model or residual
     decisions, one section per review cycle.
   - **Notes and archives:** round worklogs stay out of the repository. Reviews and the final
     native-run summaries are archived.
6. **Parallel tracks and blocking workers.**
   - **Worktrees:** independent milestone tracks run at the same time, each with its own
     integrator, worktree and crate ownership. A single owner holds the public contract (ADR-0006
     revisions) and merges contract changes.
   - **Long commands:** an agent runs its long commands in the foreground, or blocks on them in
     the same turn. A worker ends by writing a `DONE` file, which its parent reads.
   - **Models:** well-specified implementation units use a fast model; design, integration and
     review use the strongest. Code that has triggered a content filter is reviewed on a different
     provider's model.
7. **Faster native harnesses.**
   - **Stable shims:** the cross-build shims live at a stable path under `target/`, so Linux and
     Windows cross builds stay incremental between runs.
   - **Smaller binaries:** native test binaries are built with a lean debug-info profile, so the
     devbox runs every binary in one batch.
8. **Design compression.** A milestone design gets one draft, one independent review and one ruling
   pass before implementation starts.

## 3. Consequences

- **Parallel work:** M03 wave 6 (U13, the exit evidence) runs alongside the M04 and M05 designs and
  builds. M05 is pure application logic, and the plan already runs it in parallel with M04. The M07
  surface work joins as its dependencies land.
- **Accepted risk:** more same-user edge cases are recorded as residuals instead of fixed. Each one
  is still named in the claims table, carried to the release record, and reviewed in M09-T03.
