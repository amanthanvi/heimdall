# M02-W2bc-code-review — 88ac9850 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03. Orchestrator resolution:
ADR-0007 §12.21.

The reviewer's full text was returned to the orchestrator thread. This record keeps the verdict,
both findings, the re-check table and the validation results verbatim in substance.

**Reviewed range:** `270a8b49..88ac9850` (`26f94dc8`, `88ac9850`), validated at HEAD `88ac9850`.

The workspace tests, formatting and Clippy pass. The original Y01–Y06 and X01–X05 reproducers are
addressed, with substantive regression assertions. Two further probes reproduced consent defects
in the new preview integration. Manual mode can change an active projection without asking for a
decision. Shell-only evaluation can waive consent for changed or undetermined non-shell behaviour.

## Findings

### V01 — High — Manual-mode updates omit active aliases from consent classification

**Location:** `crates/localenv/src/projection/plan.rs:359`, `:368`, `:1447`.

**Defect:** Both manual-mode branches return before populating `user_now`. They still plan writes to
P and the key files, so `affected_aliases` sees no active user block and returns empty current and
after alias sets, and `consent::classify` reports that no decision is required. An unmanageable user
file does not mean that P is inactive: OpenSSH can still read a symlinked configuration containing B.

**Scenario and evidence:** The reviewer adopted `work`, then replaced the user configuration with a
symlink to the same bytes, then changed `work`'s hostname. Preview selected manual mode, planned a
`ManagedSsh` write, and applying it changed P. The scratch probe printed
`manual_active_p_hostname_changed=true; applied=true; decision_required=false` and its assertion
failed with exit 101. **Observed.**

**Fix:** Compute affected aliases for manual-mode P changes too. Separate "may the user file be
edited" from "does it activate P". Where activation or behaviour cannot be established, classify the
state as undetermined and require a decision. Add a regression with an active B in a symlinked user
configuration.

### V02 — High — Shell-only consent evaluation misses changed and undetermined non-shell behaviour

**Location:** `crates/localenv/src/projection/plan.rs:1614` (`:1638`).

**Defect:** Every current, after and restore behaviour state used for consent is evaluated with
`Invocation::Shell`. Conditions that apply only to exec or subsystem invocations are therefore
treated as false, instead of contributing their behaviour or their uncertainty. §5.2 allows a
waiver only for determined, equivalent behaviour, and §6 distinguishes the shell, exec and
subsystem profiles.

**Scenario and evidence:**
* A `Match sessiontype exec` HostName changed after adoption. Rollback would expose a different
  destination for remote commands and Git-over-SSH, but the waiver was granted.
* An environment-dependent `IdentityAgent` behind `Match sessiontype subsystem` was added. Its
  restore state is undetermined, but the waiver was granted.

The probes printed `exec_restore_digest_changed=true; decision_required=false` and
`subsystem_restore_determined=false; decision_required=false`; exit 101. **Observed.**

**Fix:** Bind consent to behaviour across the supported invocation profiles, keeping the profile in
the canonical digest. Require a decision when any affected profile is undetermined. Add rollback
regressions for both examples.

## Earlier findings re-checked

| Finding | Status |
|---|---|
| Y01 environment references | Closed for the original reproducer (V02 is a separate omission) |
| Y02 fixture invocation coverage | Closed for the original reproducer |
| Y03 Include glob expansion | Closed |
| Y04 effective SessionType | Closed |
| Y05 Unix backslash | Closed |
| Y06 Unicode pipe panic | Closed |
| X01 descriptor ownership | Closed |
| X02 create rollback moves a newer edit | Closed |
| X03 unstable first-adoption preview | Closed |
| X04 lost K before B_git | Closed |
| X05 unbounded DNS wait | Closed |

Regression sensitivity was assessed by comparing assertions with the pre-fix code. The reviewer did
not mutate repository source.

## Checks found sound (summary)

* The recovery-row test exercises the filesystem and the engine: 80 rows, 132 step and item vectors
  and 11 cleaner vectors, all passing.
* F0x/K0x classification has one implementation.
* The name-taking replace API removes the inference machinery.
* Create rollback preserves edits at both reviewed boundaries.
* K's release after an abort is derived again at restart.
* The Git parse check runs before B_git's exchange.
* Removal stays confined to the quarantine.
* X01's ownership boundary is sound.
* The SSH path fixes are covered, including unset, mismatching and non-UTF-8 HOME.
* The targeted content scan found no secret or personal data.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1327 passed, 0 failed, 4 ignored (subprocess entry points) |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `cargo test -p heimdall-localenv --test integration_projection_recovery_rows -- --nocapture` | 0 | 80 rows; 132 step and item vectors; 11 cleaner vectors |
| scratch projection harness, filter `review_` | 101 | V01 and both V02 cases reproduced |
| targeted content scan; `git diff --check 270a8b49..88ac9850` | 0 | clean |
| `ssh -V` | 0 | OpenSSH 10.3p1, LibreSSL 3.3.6 |
| cleanup of target/ (4.4 GB) and scratch; final `git status` | 0 | clean |

Not checked: native Windows, WSL and Linux (blocked: no native environment in this review);
power-loss durability; wave-3 admission, the setup driver and U8 wiring. No owner keys, agents,
keychains, SSH or Git configuration were used.
