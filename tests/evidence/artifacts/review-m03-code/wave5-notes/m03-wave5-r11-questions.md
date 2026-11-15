# M03 wave 5, round 11 — questions for the orchestrator

## Integrator (I)
## G8
- **Q-G8-R11-1 (release bound hit; built fail-closed, recommend accepting as a named residual under §17.33
  item 6, "fails closed, no lasting effect").** When the holder's in-flight work outlives `RELEASE_WAIT`
  (20 s), the `release` request answers `SERVICE_UNAVAILABLE` / `uninstall_in_progress`; the fence stays
  **releasing** (leases invalid, so that work is refused at its next check; new fenced work still refused)
  and is lifted only when the last lease ends. A connection drop releases the same way. So a holder step
  that hangs forever (e.g. an adapter call with no bound) keeps the fence releasing until it returns or the
  runtime restarts (the fence is never stored). Options: (a) as built; (b) force-lift at the bound, relying
  on the generation check to refuse the stale work afterwards. Recommendation: (a). Probe:
  `heimdall-app uninstall_fence_m03::tests::holder_spawned_task_keeps_the_lease` (releasing while holder
  work runs).
## K4
## P8
- **Q-P8-R11-2 (§17.33 item 12, Windows owner check):** the Windows rule is "no reparse point,
  owned by this user or the system"; the sweep refuses every reparse point on the chain, but reading
  a directory's owner needs the Win32 security API (`windows-sys` `Win32_Security` features), which
  the heimdall crate does not link: adding that edge changes `Cargo.lock`'s heimdall entry, an
  escalation. Options: (a) **recommended:** add `windows-sys` (already in the workspace, `=0.61.2`) to
  heimdall's `[target.'cfg(windows)'.dependencies]` with `Win32_Security`/`Win32_Security_Authorization`
  and check each component's owner SID (this user's or `S-1-5-18`/`Administrators`); (b) record it as a
  residual. Assumed meanwhile: the default `%LOCALAPPDATA%\heimdall` sits in the user's profile, whose
  access list denies other ordinary users entry creation. Not decided by P8.
- **Note (item 12, Linux test hosts):** the rule refuses a sticky `/tmp` parent, so a real-binary e2e
  purge under a `/tmp` scratch home is refused on Linux; `cfg(test)` unit tests trust the temp dir's
  own chain only. The native Linux harness should set `TMPDIR` to a non-sticky, owner-controlled
  directory for purge cases. macOS `/var/folders/.../T` passes (observed on this Mac).
- **Q-P8-R11-1 (claims-table residual line):** §17.33 item 4 asks the Windows residual window to be
  named in the claims table, but `crates/domain/src/claims.rs` `CLAIMS` accepts only verified claims
  (each needs a `verified` evidence record; `claims_table.py` fails otherwise) and has no residual
  format. Options: (a) **recommended:** an additive `pub const RESIDUALS: &[Residual]` in
  `claims.rs` (name, platform, probe, ADR ref), parsed and listed by `claims_table.py` (integrator);
  (b) record it in `docs/compatibility/matrix.md`'s residuals list. Named in code meanwhile:
  `purge_sweep::WINDOWS_RESIDUAL` = `windows_purge_entry_replaced_between_check_and_delete`.
- **Record-not-block candidate (item 6, not decided by P8):** the final inventory read, the bundle
  check and the instance lock open the state database and `service.lock` by path; a same-user program
  that swaps `<state>` for a link between the lock and the final read makes the read see another
  database (the deletion itself is anchored and refuses). Only a hostile same-user program can do it
  (spec P03). Probe: `uninstall_purge_never_follows_state_root_replacement` covers the deletion side.

## Integrator (round-11 records)
- **Q-P8-R11-1: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.33 item 7): accepted.** An
  additive `RESIDUALS` list in `crates/domain/src/claims.rs`; each entry names the residual, its
  platform, the claim it limits, the probe or test that shows it, and the §17.33 item 6 category it is
  accepted under (fail-closed only / needs a hostile same-user program). The claims-table validator and
  `claims_table.py` read it; a residual is never presented as a verified claim. First entries: the
  Windows `WINDOWS_RESIDUAL` sweep window, and the item below.
- **The `<state>`-opened-by-path candidate: ANSWERED (orchestrator, 2026-11-13; §17.33 item 8):
  recorded as a residual, not fixed** (needs a hostile same-user program, P03; the anchored deletion
  still refuses, so no lasting effect on recovery records). Named precisely in `RESIDUALS`, with a test
  showing the deletion refusing after such a swap.
- **Q-G8-R11-1: ANSWERED (orchestrator, 2026-11-13; to be ADR-0008 §17.33 item 9): accepted as built,
  a named residual (fail-closed only).** A `RESIDUALS` entry states that a holder step that never ends
  keeps the fence "releasing" (fenced requests refused) until that step ends or the runtime restarts,
  and that a restart clears it, pointing at the bound-hit test. While stuck releasing past its bound,
  the refusal other requests get must say the uninstall's release is waiting and how to clear it (an
  additive reason `uninstall_fence_release_stuck` is authorized if needed).
  **Integrator note:** there is no `heimdall service restart` (only `service run|status|stop`); the
  next step built is `heimdall service stop` (the next command starts the runtime on demand). Confirm,
  or rule a `service restart` command.
- **Audit B3/B4: ANSWERED (orchestrator, 2026-11-13; ADR-0008 §17.33 item 10): fix now.** Precedence:
  a finding in both item-6 buckets that is a destructive deletion path with a lasting effect on owner
  data is fixed, whoever triggers it (spec §14.3). Open `<state>` once without following links from a
  trusted ancestor chain (lstat each component up to the home/XDG root; owner-only, this user); take
  `service.lock`, run the final read, check the bundle and run the sweep through that one handle,
  comparing dev/ino at each step; refuse on a swap or linked ancestor, nothing deleted. B4: all-roots
  check pass + re-verify each root's dev/ino immediately before the first unlink (no partial deletion).
  Correct the RESIDUALS `<state>` text to what remains after the fix. Regressions: replaced common
  parent -> refuses, nothing deleted; swapped owner-only `<state>` refuses; link between passes deletes nothing.
- **Audit B2/B5/B6: ANSWERED (§17.33 item 11): recorded as RESIDUALS**, each with probe/test, the claim
  it limits and its category (B2 no lasting effect; B5 needs a hostile owner program holding the fence;
  B6 leftover local files only), carried to U13; the uninstall report must say which `<run>` it swept.
- **P8's ancestor rule: ANSWERED (orchestrator, 2026-11-13; ADR-0008 §17.33 item 12): confirmed as the
  standard secure-path rule (OpenSSH StrictModes).** Roots `<state>` and `<run>`: owner-only, owned by
  this user. Each ancestor up to the top of the chain: owned by this user or root, not writable by
  group or others; a group/other-writable directory (e.g. sticky `/tmp`) refuses (refuse chosen unless
  a supported default layout needs it; then a RESIDUALS entry). Defaults must pass: macOS (`~/Library/...`,
  per-user `TMPDIR` under `/var/folders`), Linux (`~/.local/state`, `/run/user/<uid>` with root-owned
  `/run/user` 0755), Windows (by reading); a test per platform's default layout.
- **Q-P8-R11-2: ANSWERED (orchestrator, 2026-11-14; ADR-0008 §17.33 item 13): add the edge.** Enable
  the needed `windows-sys` security features for `heimdall` (already a workspace dependency at its
  pinned version); `Cargo.lock` changes only by that edge and its features, never a new package or
  version (lock diff shown in the report). Each ancestor's owner SID: this user, SYSTEM or the
  Administrators group passes, anything else refuses; reparse points still refuse. Windows clippy here
  plus a unit test of the owner classification with fixed SIDs; native evidence in U13, named in the
  claims table until then.
- **Linux test chain: ANSWERED (§17.33 item 14): debug test-config hook
  `HEIMDALL_TEST_PURGE_TRUSTED_TOP=<abs dir>`** (debug-only, via `testcfg`, refused in release builds,
  release-gate probe). It must be absolute, owned by this user, owner-only, and a strict ancestor of
  `HEIMDALL_HOME` (or of the roots), else refuse; the chain check starts at it instead of `/`, and
  everything below it is still checked by the full rule; e2e fixtures set it to their owner-only scratch
  base. At least one test keeps proving the full chain from `/` without the hook.
