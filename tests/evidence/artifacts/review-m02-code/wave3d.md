# M02-W3d-code-review — d23a66c5 — fix first

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-03; the finding, the re-check
table and the validation results are kept verbatim in substance. Orchestrator resolution: ADR-0007
§12.29.

**Reviewed range:** `ed9b2d21..d23a66c5`, validated at HEAD `d23a66c5`.

The original T01–T04 scenarios are closed by the fixes, and their regressions are exercised. All
checks passed: 1526 tests passed, 0 failed, 5 ignored child-entry helpers; fmt and clippy clean.
One more authentication-probe bypass remains.

## Findings

### R01 — High (P1) — The authentication probe accepts a replaced adopted public key

**Location:** `crates/localenv/src/probe/auth.rs:170–174`; the supporting behaviour is at
`crates/sshconf/src/relevant.rs:728`.

**Defect:** The authentication gate accepts `IdentitySelection::Exclusive` without checking that
the selected key's fingerprint still matches the adopted catalog identity. Exclusivity is
established against `identity.public_key_path`, so replacing that file's contents changes the
selected identity while it stays exclusive. The endpoint check establishes the agent, but a
declaration covers one identity at that endpoint, not every key that agent holds.
`catalog_identities` checks recorded fingerprints on the fallback path only.

**Scenario:** K1 is declared interaction-free at agent A. The alias selects K1's public-key path
with `IdentitiesOnly yes` and `IdentityAgent A`. Before the probe, the public-key file is replaced
with K2's public key; K2 has no declaration and could require confirmation. The selection stays
`Exclusive`, the endpoint check passes, and the non-interactive authentication probe starts ssh
with K2 selected. No change between the static pass and the run is needed.

**Evidence:** A scratch executable linked against the production libraries called
`authenticate_observed` with a non-interactive `ProbeContext`, two synthetic Ed25519 public keys,
a scratch configuration and `-F`, and a marker-writing ssh stub. No private keys, real agents or
providers were used. For both managed and observed aliases: the original key gave `Exclusive`, a
fingerprint match, `Ok` and a client run; the replaced key gave `Exclusive`, **no** fingerprint
match, `Ok`, **no refusal**, and a client run. Exit 0 (assertions confirming the defect).
**Observed.** A real agent's confirmation prompt is **inferred**.

**Fix:** Bind exclusive success to the adopted identity's fingerprint, failing closed when the
selected adopted key cannot be established or no longer matches. Keep the endpoint check. Add a
regression that replaces only the adopted public-key file and asserts refusal with no client run,
plus the unchanged-key control.

## Earlier findings re-checked

| Finding | Result | Regression fails without the fix? |
|---|---|---|
| T01 | closed: `a11::t01_exec_only_and_subsystem_only_entries_are_refused_before_launch`, the observed-alias regression and `probe::auth::tests::the_probe_evaluates_the_exec_invocation_it_runs` | yes (inferred from the parent code) |
| T02 | closed: `a11::t02_localuser_fallback_is_refused_with_user_unset_or_naming_another_account` and the observe/consent/doctor/probe account regressions | yes |
| T03 | closed: `probe::auth::tests::exclusive_selection_through_another_agent_is_refused_before_anything_runs` | yes (R01 is a different missing check) |
| T04 | closed: `t04_overlapping_runs_of_one_binding_refuse_the_second_and_keep_the_first_holder` and the app holder tests | yes |

## Checks found sound (summary)

* The pre-launch selection covers all three profiles for managed and observed aliases.
* Holder check and registration share one transaction.
* `binding_released` and `binding_in_use` are distinguished.
* `OpError.entries` round-trips through detail, stored-error reconstruction and the envelope.
* The ensure refusal names the refused lines.
* A changed alias needs a decision in manual mode.
* `read_sources` and `prepare_from` have no default bodies.
* The committed-content scan was clean.

## Commands and validation

| Command | Exit code | Result |
|---|---:|---|
| `CARGO_NET_OFFLINE=true cargo test --workspace --locked` | 0 | 1526 passed, 0 failed, 5 ignored |
| `cargo fmt --all --check` | 0 | passed |
| `CARGO_NET_OFFLINE=true cargo clippy --workspace --all-targets --locked -- -D warnings` | 0 | passed |
| `git diff --check ed9b2d21..d23a66c5`; content scan | 0 | clean |
| scratch authentication probe (control and replacement, managed and observed) | 0 | reproduced R01 |
| cleanup; final `git status` | 0 | clean |

Not checked: native Windows and WSL, live provider dialogs, mutation testing of the parent code.
