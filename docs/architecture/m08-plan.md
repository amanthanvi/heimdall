# M08 plan: harden and package what is actually supported

**Status:** draft, revision 1 (2026-11-22), from the M08 design unit. It awaits one independent design review and one scoped re-check (ADR-0009 §2.8). No production code was written for it.
**Design ADR:** ADR-0014 (proposed): the fuzz boundary list and stopping rule, the update and recovery contract, the artifact and provenance policy, the support-bundle and privacy defaults, and the benchmark and soak thresholds. ADR-0014 wins wherever this plan differs.
**Basis:** `main` at `de097dac` (the M01–M05 exits, M03's claim gating, M04's claims update, the accepted M06 design, the M07 design). Read for write sets only: `origin/m06/w4` at `c4e9a5b5` and `origin/m07/w2` at `8e5bb1d6`.
**Delivery rules:** ADR-0009.

**Inputs:**
- plan §5 M08 (T01–T06 and the exit evidence) and M09, §3 (every gate), §6, §7, §9, §10, §11;
- spec §3.2, §7.7, §13.3, §13.6, §14, §15.1–§15.3 and cases A29, A31, A33, A34;
- the ten requirements M08 owns: R-RT-08, R-SE-05, R-SE-08, R-QU-03, R-QU-04, R-DI-01, R-DI-03, R-DI-04, R-DI-05 and R-DI-07. It also closes, for the exit cases, R-CR-03, R-CR-04, R-CR-06, R-EN-01, R-EN-04, R-AP-08, R-RT-03, R-RT-06, R-SE-01, R-SE-02, R-SE-03, R-SE-06, R-QU-02 and R-DI-02;
- ADR-0002 §9–§11 and ADR-0004 §1 (Q-D, Q-F) and §4 (E8, the version floors);
- the items earlier milestones handed to M08 (§1.4).

**Exit evidence** (plan §5 M08): A29, A31, A33 and A34 pass; runtime behaviour and release claims match the shipped builds; unsupported claims are removed or blocked; no state migration resets authority or silently adopts a new identity.

**Hard limits on this milestone:**
- **Nothing is published.** Artifacts are built and verified locally. Only digests and records go into the repository.
- **No signing key exists.** Every signature row is an owner input with a documented-provenance alternative (§5).
- **A release build's TUI, `doctor`, `setup` and runtime run only in a disposable account, container or VM** (AGENTS.md). §4 says which machine gives which row.

## 0. Rules

1. **One contract owner.** The integrator holds ADR-0006. No M08 unit edits `crates/contract/**`, `schemas/**`, `tests/contracts/**`, the CLI subcommand table in `cli.rs`, `runtime/src/dispatch.rs`, `ipc/src/session.rs` or the store. A unit that needs one of ADR-0014 §7's deltas waits for U0.
2. **Parallel-safe now** means both of these hold:
   - **The write set is outside M06's and M07's.** M06's is m06-plan §1 plus what `origin/m06/w4` changed: `crates/{app, runtime, credential, heimdall, store, transport-iroh, contract, remote, domain, issuer, registry, sshconf, enroll, testkit, ipc, adapters}`, `schemas/`, `third_party/`, `.cargo/`, the root `Cargo.toml` and `Cargo.lock`, `tools/validation/{check.sh, crate_graph.py, audit_gate.py, audit-ignore.txt}`, and the existing files under `tests/{adversarial, contracts, e2e, integration, model}`. M07's is m07-plan §2 plus what `origin/m07/w2` changed: `crates/heimdall/**`, `examples/**`, `skills/**`, `docs/api/`, `docs/user/adapters.md`, `tools/validation/{skill_lint.py, adapter_page_check.py}`.
   - **The unit uses only commands, fields and files that exist on `main` today.**

   Everything else is **after M07 freeze**: after M06's exit is merged and the contract owner has landed revision 7 as provisional (m07-plan §3).
3. **Shared lines are handed over, not edited.** Root and per-crate manifests, `[[test]]` lists and `check.sh` steps belong to the integrator who owns them at the time (M06's, then M07's). A W0 unit lists its lines in its `DONE` file.
4. **Fixtures only.** Per-run keys, the loopback fixture sshd, disposable agents and the AGENTS.md option set on every fixture `ssh`. Never the owner's keys, agent, keychain, password manager or `~/.ssh`.
5. **Scratch launch environment.** Every debug `heimdall` a harness starts gets scratch `HOME`, `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME`, checked before the spawn (m07-plan rule 4). Every release `heimdall` that runs a static pass runs inside a container, a disposable WSL distribution or a disposable account.
6. **No public listeners.** Containers run with `--network none`, or on an internal Docker network when two containers must talk.
7. **Tests (ADR-0009 §2.3).** A new test covers behaviour no existing test covers. Earlier milestones' groups are reused by reference in the M08 case index. Fuzz findings become regression tests on the pinned toolchain; the campaign itself is not a `check.sh` step.
8. **Gates and native runs (ADR-0009 §2.2–§2.4).** Focused tests while iterating; `check.sh`, `linux-xcheck --workspace` and the umask-002 targets once per commit to a branch; Windows and the devbox once per merge candidate; one combined exit suite.
9. **Build hygiene.** One `./target` per checkout. The fuzz build is the one exception in mechanism, not in intent: it happens inside a container whose writable layer holds its build directory, and the container is removed by name (§2 U1). Release artifacts are assembled under `target/release-artifacts/`.
10. **Statuses.** Every unit stays `implemented_unverified` until U8's records exist.

## 1. Gap audit

### 1.1 Headline

- **Uninstall is built and proven.** Rollback of every item, the remote-enrollment inventory, the K_ca store plan, the attended purge with its lock and the residue listing all exist with native records (`m02-t06-clean-uninstall.json`, `m04-a31-setup-uninstall.json`). M08 adds only what M06 and M08 themselves introduce.
- **Migration safety is half built.** The store refuses a newer schema, treats a damaged file as corrupt and never as new, and writes a backup before the first schema change, all tested. **Missing is the user's way out:** a corrupt store answers "recovery required" and no command recovers it; there is no restore from a backup, no rollback path and no statement of what a restore does to authority.
- **Nothing exists for update.** `service stop` drains, but nothing tells the user what stopping interrupts, nothing installs or replaces a binary, and every login entry, hook and WSL helper embeds the executable's path.
- **Nothing exists for packaging or provenance:** no release script, archive, checksum, dependency inventory, licence notice, `LICENSE` or reporting route. The licence is still the `UNLICENSED` placeholder and the version is `0.1.0-m01`.
- **Two probes changed the design** (§9; record `m08-probe-inventory-and-release-binary.json`):
  - **The release binary embeds the build host's home path 297 times** [observed on macOS], through cargo registry paths. A shared artifact would carry the builder's user name.
  - **16 to 20 test-only crates (proptest, rusty-fork, tempfile and others) are in the release build graph** through `heimdall-testkit`, a normal dependency of the binary. A naive inventory names them as shipped components.
- **Hostile-input coverage is broad but not coverage-guided.** Six adversarial suites (76 tests), 37 files with fixed-seed property tests and the M05 prompt-injection suite exist. Earlier milestones deferred fuzzing of nine parsers to M08. A29's records are blocked only on B2 and B9.
- **A33 is verified for M03's surface.** Support bundles and update artifacts were deferred to M08. The redactor exists (`runtime/src/telemetry.rs`, structural, canary-tested); no bundle exists.
- **A34 has not started.** Only debug-build measurements exist (`m07-probe-tui-and-lists.json`, `first_frame_latency_measured_and_recorded`), and the G02 benchmark scripts measure the prototypes.
- **The largest owner dependency:** native release rows on Windows and macOS need a disposable account or VM on each (B2, B3). Without them those rows of A31 and A34 stay `blocked`.

### 1.2 Tasks

| Task | Exists now | Missing → unit |
|---|---|---|
| **T01** Adversarial parser, IPC, path and authority tests; fuzzing; leaks and races | `tests/adversarial/`: `sshconf_hostile.rs` (19 tests), `agent_client_frames.rs` (18), `agent_frames.rs` (16), `ipc_frames.rs` (10), `signer_requests.rs` (7), `prompt_injection.rs` (6) with `prompt_injection/{agent,cli}.rs`. Property suites under `tests/model/` (authority, revocation, idempotency, lifecycle, timegate, projection recovery, sshconf parse/eval/edit). Path cases: FIFO includes and input files, symlinks, swapped manifests (M02 U3, M05 U4). Records `m01-a29-local-hostile-input.json` and `m05-a29-hostile-input.json` (blocked on B2, B9) | Coverage-guided fuzzing of the boundaries in ADR-0014 §2. A spec §14.3 coverage table, with a test for any item that has none. M06's and M07's new boundaries. The A29 run at the exit build (U1) |
| **T02** Migration, corrupt-state recovery, drain/update/rollback, uninstall and remote residue | `store/src/lib.rs`: `NewerSchema`, `OlderSchema`, `Corrupt`; `integrity_check` and `foreign_key_check` at open; a backup `<file>.v<N>.backup[.<n>]` before the first pending step, never overwritten; tests `garbage_header_is_corrupt_not_fresh`, `damaged_page_is_corrupt_not_fresh`, `truncated_file_is_corrupt_not_fresh`, `newer_schema_is_refused_and_untouched`, `open_read_only_refuses_newer_reports_older_and_never_writes`, `fresh_file_needs_no_backup_and_pending_step_is_backed_up_first`. `service stop` with a 10 s drain. `uninstall` and `purge_sweep` in full. The macOS ad-hoc update note (`docs/release-notes/m03-macos-ca-key-access.md`), `issuer_executable_changed`, `issuer restore`. The Windows state-directory upgrade path (ADR-0010 §10 item 5) | A recovery command for a corrupt or newer store. Restore from a backup with a stated effect on authority (Q1). A stop preview. An install and update procedure with a kept previous binary. Detection of a moved executable. Identity and authority invariants across the migration ladder. Residue rows for backups, the previous binary and M06's remote state. The three Git residuals (U2) |
| **T03** Clean-machine artifacts for the declared matrix | `[profile.release]` (size-optimized, LTO, stripped). `release-gate.sh` (the release build refuses every `HEIMDALL_TEST_*`). The zig cross shims (glibc 2.31 floor). G02's toolchain-free runs of the prototype, not the product | The release script, archives, install scripts, the static artifact checks, clean-machine runs (U3; §4) |
| **T04** Signatures or documented provenance, checksums, inventory, notices, reporting | Exact version pins, committed `Cargo.lock`, `docs/architecture/dependencies.md`. M06 adds the cargo-audit gate (`audit_gate.py`, 0.22.1) and `third_party/netdev-0.47.0` | Checksums, a build record, an SBOM per target, licence policy and notices, `LICENSE`, `SECURITY.md`, the E8 snapshot replacement, the name check (U4; §5) |
| **T05** Benchmarks and the 72-hour soak | Debug-build latency probes. `FaultHook` and the `HEIMDALL_TEST_*` hooks (debug only). `tools/benchmarks/g02/` (prototype measurement scripts). M05 U0b's delaying agent proxy | The release benchmark harness, the soak harness and schedule, the runs (U5; §6) |
| **T06** Support bundles, privacy defaults, release notes, runbooks | `telemetry::redact` with its tests; bounded logs (two 8 MiB generations); no telemetry code; retention config (`7d`, floor 24 h for operations); the recovery bundle (a different thing: issuer recovery). `CANARY-REDACTION.md` | The support bundle, a defaults audit, release notes, the limitation statement, install/update/recovery/unenrollment runbooks, the agent-use guide packaging (U6, U7) |

### 1.3 Exit cases

| Case | Exists now | Missing |
|---|---|---|
| **A29** | M01's and M05's records and suites (§1.2 T01); M06 adds invitation replay, cross-owner request IDs and role confusion in A25; M07 adds page tokens and selectors | Fuzz campaigns; the §14.3 table; one run of everything at the exit build |
| **A31** | Setup and uninstall on every platform (`m04-a31-setup-uninstall.json`, blocked on B12 with B2, B3); store refusal tests | Install from an artifact on a clean machine; update, rollback and recovery journeys; provenance inspection; M06's remote residue |
| **A33** | `m03-a33-secrets.json` (`verified`): errors, crashes, export, logs, events, arguments | Support bundle rows; update-artifact rows; the scan of built archives; the defaults audit |
| **A34** | Nothing on a release build | Everything |

### 1.4 Carried into M08

| Item | Source | Disposition |
|---|---|---|
| Fuzzing of `sshconf::parse_file`, `sshconf::gitedit`, `ipc::agent_client` | m02-exit §7 | U1a |
| Fuzzing of the HM1 parser, the issuer protocol, the userauth purpose parser, the session-bind parser | m03-plan §8 | U1a |
| Support bundles; update artifacts in A33 | m03-exit; `m03-a33-secrets.json` | U6, U8 |
| Packaging, update and rollback parts of A31 | m04-plan §3 | U2, U3 |
| Spec §15.1's full table on release builds | m07-plan §9 | U5 |
| The three Git residuals | ADR-0007 §12.41; m07-plan Q8 | U2b: the moved block is reported as residue; the other two stay disclosed (§10) |
| The recovery runbook behind the lost-device guidance | m07-plan §11 | U7 |
| Packaging the skill, the wrapper and the harnesses as examples | m07-plan §11 | U3b |
| Closing "practical distribution" and signing (Q-D); darwin signing (Q-F) | ADR-0004 §1 | U3, U4; B13 |
| Replace proprietary vendor snapshots by hash and archive URL | ADR-0004 §4 (E8) | U4a |
| Re-confirm the version floors on clean machines | ADR-0004 §4 | U3b |
| The cargo-deny ignore for the three zbus advisories | ADR-0008 §17.15 item 8 | Already carried by M06's audit gate; U4a adds no second advisory gate |
| Tunable limits (the revocation cap, P7, P12) | m01-exit, m02-plan, m03-plan | No change proposed: no measurement asks for one (§10) |
| Export above the 1 MiB bundle cap | m07-plan §9 | Deferred (§10) |
| Licence and project-name checks | ADR-0001 §8 | U4a (the checks); B17 (the decision) |
| **M04-F4** (a follower commit must check its own lock continuity) | `progress.md` | Not M08's to fix. It blocks any `lock_continuity` claim entry, so U8's claim audit refuses a candidate that ships such an entry while F4 is open |
| The M04 exit, waiting on the owner's A03 lock row | `m04-exit-draft.md` | A gate-ledger row (§1.5) |

### 1.5 The gate ledger

Plan §5 gates M08 on "all technical gate decisions recorded". U8 writes the ledger into `m08-exit.md`. Today:

| Gate | Recorded in | Open |
|---|---|---|
| G01 | ADR-0001 (**proposed**); ADR-0004 §4 (provisional floors) | The floors' clean-machine confirmation (U3b). The baseline worksheet (B7, M09) |
| G02 | ADR-0002 (accepted) | Q-D: practical distribution and signing, closed by U3 and U4 or the release is `preview-only` |
| G03 | ADR-0010 (accepted); the G03 records | Rows blocked on B2, B4, B5 |
| G04 | ADR-0005 (accepted); ADR-0008 (**proposed**, revision 6) | The M04 exit decision (the A03 lock row); B3, B11, B12, B13; M04-F4 |
| G05 | ADR-0011 (accepted) | None |
| G06, G07 | ADR-0012 (accepted) | Both close at M06's exit |
| G08 | ADR-0006 (**proposed**, baseline); ADR-0013 (**proposed**) | Ratification after M07's U9 |
| G09 | No single record: the effect table is spread over ADR-0008, ADR-0010 §5 and M03's A23 | **Q7:** one consolidated record, or a ruling that the spread is the record |

## 2. Units

Each unit lists its marking, owner role, owned paths, what it builds, its tests and its native runs. Models follow ADR-0009 §2.6. At most two workers run at a time while M06 and M07 use workers.

### U0: Contract deltas and skeleton (the integrator, as contract owner) — after M07 freeze

- **Owns:** `crates/contract/**`, `schemas/**`, `tests/contracts/**`, the `cli.rs` subcommand table, the store migration, `check.sh` steps, the root manifest; ADR-0006's next revision section.
- **Builds:** ADR-0014 §7's deltas as accepted by the contract owner, each as an addition that fails closed until its unit lands (the M05 skeleton rule): the support-bundle command and schema; the stop preview; the state commands; the new reasons, doctor findings and residue kinds; the build-provenance fields.
- **Tests:** schema goldens; the command-tree golden; migration up; every new command answers its "not available in this build" envelope until its unit replaces it.
- **Native:** Windows and the devbox at the merge candidate.

### U1: Hostile input (T01)

**U1a — parallel-safe now.**
- **Owner:** a security implementer (strongest model for target selection and triage; a fast model writes the targets).
- **Owns:** `fuzz/**` (a crate outside the workspace, with its own empty `[workspace]` table and lock file); `tests/adversarial/m08_fuzz_regressions.rs` (new; its `[[test]]` line is handed over); `tests/adversarial/corpus/m08/**` (minimized seeds, synthetic only).
- **Builds:**
  - one libFuzzer target per boundary 1–11 of ADR-0014 §2, calling the same public or `#[doc(hidden)]` entry points the adversarial tests call. A boundary with no reachable entry point is listed for its crate's owner, not patched;
  - seeds from the existing adversarial fixtures and the committed proptest regression files;
  - **the campaign**, in a Linux container on the Mac (`--network none`, 4 CPUs, 6 GiB memory, a pinned nightly installed in the image only). The workspace keeps its pinned stable toolchain. The source is mounted read-only; the build directory lives in the container and goes with it;
  - **the stopping rule of ADR-0014 §2.3**, applied per target.
- **Tests:** every crash, hang or memory blow-up becomes a minimized regression in `m08_fuzz_regressions.rs`, on the pinned toolchain. A finding that blocks a merge (ADR-0009 §2.1) carries a revert proof.
- **Native:** the regressions run everywhere with the workspace suite. The campaign runs on the Mac container only; its record says so.

**U1b — after M07 freeze.**
- **Builds:** targets for boundaries 12–15 (M06's bridge frames and invitation records, the route helper's pre-identification buffer, the `sshd -T` verifier, M07's page tokens and selectors). The spec §14.3 table (§7.1), with one new test per item that has none. An inventory of the modules that allow `unsafe`, for M09-T03's review. The A29 run at the exit build.
- **Native:** macOS, the devbox and Windows at the merge candidate.

### U2: Lifecycle: update, drain, rollback and recovery (T02)

**U2a — parallel-safe now.**
- **Owner:** a lifecycle implementer (strongest model: this is authority-adjacent).
- **Owns:** `tools/packaging/install.sh`, `tools/packaging/install.ps1`; `tests/native/m08/lifecycle/**` (the journey driver and its fixtures).
- **Builds:**
  - **the install scripts** of ADR-0014 §4.3: a fixed per-user location, no elevation, no edit of `PATH`, shell profiles or `~/.ssh`; the previous binary kept as `heimdall.previous`; on Windows the Linux helper placed beside `heimdall.exe`;
  - **the journey driver**, taking two archives ("old" and "new") and a platform, and running install → setup → active work → stop → update → restart → rollback → uninstall in a container or disposable distribution. In W0 it runs the M05 exit build against `main`, as a rehearsal only.
- **Tests:** the driver's self-test against a fake archive pair; the Windows replace-while-running case (a `heimdall run` child holds the image open).
- **Native:** rehearsals in the Mac container and a disposable WSL distribution.

**U2b — after M07 freeze.**
- **Owns:** new `crates/heimdall/src/state_cmd.rs` and the stop-preview code in `service_cmd.rs`; the restore path in `crates/store`; the doctor finding for a moved executable; the residue rows in `uninstall_cmd.rs`; the moved-block report in `crates/localenv/src/projection/`.
- **Depends:** U0; the ruling on Q1.
- **Builds:** ADR-0014 §3 in full.
- **Tests:**
  - **`migration_ladder_keeps_identity_and_authority`:** over M07 U0's replay corpus (stores written by the M02, M03, M04/M05 and M06 exit builds), after migration to the candidate schema the environment ID, tombstones, cutoffs, pauses, grant deadlines and the authority generation are unchanged, and no grant is more active than before. The corpus is M07's; this test adds only these assertions;
  - `corrupt_store_stops_unsafe_operations_and_offers_recovery` (real binary: `status`, `ensure` and `doctor` each name the recovery choices; nothing is written);
  - `restore_from_backup_ends_authority_and_keeps_identity` (Q1's rule, whichever is ruled);
  - `reset_is_attended_and_says_it_creates_a_new_identity`;
  - `older_build_on_newer_store_refuses_and_touches_nothing` (two real binaries: the candidate and a test-configuration build one schema version ahead);
  - `stop_preview_lists_what_stopping_interrupts` (read-only: the store and the endpoints are unchanged after it);
  - `moved_executable_is_a_doctor_finding_and_never_a_silent_break`;
  - `uninstall_lists_backups_previous_binary_and_remote_pairings`;
  - `rollback_reports_a_moved_git_block`.
- **Native:** the A31 journeys of §7.2, at the merge candidate and again at the exit build.

### U3: Release artifacts (T03)

**U3a — parallel-safe now.**
- **Owner:** a packaging implementer (fast model), reviewed by the integrator.
- **Owns:** `tools/packaging/build-release.sh`, `tools/packaging/build-release.ps1` (the PC), `tools/packaging/verify_artifact.py`, `tools/packaging/README.md`.
- **Builds:**
  - **the release build for each target of §4**, from a clean checkout of one commit, `--locked`, with build-host paths remapped (the probe's finding) and a static C runtime on Windows;
  - **the archive layout** of ADR-0014 §4.2;
  - **`verify_artifact.py`**, the static check every archive passes before anything else is done with it:
    - only the allowed dynamic libraries per target (system frameworks and `libSystem`/`libiconv` on macOS; `libc`, `libm`, `libgcc_s` and the loader on Linux, with no symbol version above glibc 2.31; operating-system DLLs only on Windows);
    - no build-host home path, user name or checkout path in any file;
    - no full canary value and no private-key armor;
    - the version, commit and target the binary reports equal the build record;
    - every file is listed in `SHA256SUMS` with a matching digest.
- **Tests:** `verify_artifact.py`'s self-test against known-bad fixtures (a planted home path, a planted canary, an extra library, a digest mismatch).
- **Native:** in W0, one rehearsal build per target from `main`; the Linux archive run in `debian:13-slim` and `ubuntu:24.04` containers with no toolchain.
- **How the path remap is delivered** is the unit's first step: flags passed by the script, or a profile setting. A profile setting is a root `Cargo.toml` line, handed to its owner. The `check.sh` release gate must then build the same way, so the gated binary is the shipped one.

**U3b — after M07 freeze.**
- **Builds:** the candidate archives from the candidate commit, with M07's skill, wrapper and harnesses under `examples/`; the feature set ruled in Q5; the clean-machine runs of §4.2; the floors' confirmation for ADR-0001 §5.
- **Native:** §4.2's table.

### U4: Provenance (T04)

**U4a — parallel-safe now.**
- **Owner:** a packaging implementer (fast model); the licence policy is reviewed by the integrator.
- **Owns:** `deny.toml`; `tools/packaging/{sbom.sh, notices.py, build_record.py}`; `SECURITY.md`; `docs/sources/snapshots/**` (E8 only); `docs/release/name-and-licence-check.md`.
- **Builds:** ADR-0014 §4.4–§4.7:
  - **the licence and source policy** (`cargo-deny`, pinned, licences, sources and bans only; advisories stay with M06's audit gate);
  - **an SBOM per target** (CycloneDX JSON from the resolved graph for that target and feature set), with the test-only crates that arrive through `heimdall-testkit` marked as built but not referenced;
  - **`THIRD-PARTY-NOTICES.txt`**, generated from the same graph with each crate's licence text, failing when a text is missing;
  - **`BUILD-RECORD.json`** and `SHA256SUMS`;
  - **`SECURITY.md`**, with the reporting route the owner chooses (B18);
  - **E8:** proprietary vendor snapshots replaced by their hashes and archive URLs;
  - **the name and licence check:** read-only lookups of the project name against the registries a release might use, and a compatibility table of the dependency licences against the candidate project licences. The decision is the owner's (B17).
- **Tests:** the policy passes on `main` and fails on a fixture lock file with a copyleft crate and one with a git source; the notices generator fails on a crate with no licence text; the SBOM for each target lists exactly the resolved set (compared with `cargo metadata`).
- **Native:** none; the tools run on the build hosts.

**U4b — after M07 freeze.**
- **Builds:** the final SBOMs, notices, build records and checksums for the candidate; the same-host rebuild comparison; signatures only where a key exists (§5).

### U5: Benchmarks and soak (T05)

**U5a — parallel-safe now.**
- **Owner:** a harness implementer (fast model), reviewed by the integrator.
- **Owns:** `tools/benchmarks/m08/**` (the bench driver, the sampler, the fault scheduler, the analysis script, the container definition).
- **Builds:** §6's harness, and **a 2-hour rehearsal** of lanes S and L in the Mac container on a release build of `main`. The rehearsal proves the harness and yields first numbers. It is not exit evidence.
- **Tests:** the analysis script's self-test on synthetic series (a leak, a plateau, a tight retry loop, a gap); the scheduler replays the same schedule from the same seed.
- **Native:** the Mac container.

**U5b — after M07 freeze.**
- **Builds:** the benchmark runs on the candidate (§6.1) and the 72-hour soak (§6.2), with M07's reference wrapper as the timing client and M06's runner lane.
- **Native:** §6's tables.

### U6: The support bundle (T06)

**U6a — parallel-safe now.**
- **Owner:** an implementer on the strongest model (redaction is a security boundary).
- **Owns:** a new crate `crates/support/**` (pure: it takes typed inputs and produces the bundle's files; its manifest line and crate-graph rule are handed over); `tests/adversarial/support_bundle_redaction.rs` (new; its `[[test]]` line is handed over).
- **Builds:** ADR-0014 §5's collector and pseudonymizer over an allow-list of typed inputs. It reuses `telemetry::redact` for free text.
- **Tests:**
  - `bundle_holds_only_allow_listed_files_and_fields`;
  - `canaries_in_every_input_never_reach_the_bundle` (canaries in log lines, configuration values, host names, user names, paths, key comments, operation messages and environment values);
  - a fixed-seed property: any text containing a canary, a key block or a key-like run comes out redacted;
  - `identifiers_are_pseudonymized_consistently_within_one_bundle`;
  - `bundle_is_plain_text_and_bounded`.

**U6b — after M07 freeze.**
- **Owns:** new `crates/heimdall/src/support_cmd.rs`.
- **Depends:** U0, U6a.
- **Builds:** `heimdall support bundle`, with the preview, working when the runtime is down or the store is unreadable.
- **Tests:** the A33 journey of §7.3; `bundle_works_with_a_corrupt_store`; `bundle_writes_nothing_without_the_command`.
- **Native:** macOS, the devbox and Windows at the merge candidate.

### U7: Privacy defaults, release notes and runbooks (T06)

**U7a — parallel-safe now.**
- **Owner:** the integrator writes the limitation statement (strongest model); a fast model drafts the runbooks.
- **Owns:** `docs/operations/{install.md, update-and-rollback.md, recovery.md, unenrollment.md, uninstall.md}`; `docs/user/limitations.md`; `docs/security/privacy-defaults.md`; `docs/release-notes/v1-candidate.md`; `tools/validation/docs_commands_check.py` (its `check.sh` line is handed over).
- **Builds:** drafts on today's command names. Each runbook's commands are checked against the command-tree golden by `docs_commands_check.py`, so M06's renames (`env` → `environment`) fail the check until the draft follows them.
- **Tests:** the check's self-test against a runbook naming a command that does not exist.

**U7b — after M07 freeze.**
- **Builds:** the final text on the frozen names; the defaults audit of §7.3; the agent-use guide (M07's skill and protocol document, packaged); `docs/compatibility/matrix.md` relabelled from the exit records.
- **Tests:** `defaults_audit` (§7.3), run in the container.

### U8: Exit suite, evidence and the candidate record (the integrator) — after M07 freeze

- **Owns:** `tests/native/m08/{case-index.json, runs.json, required-inventory.json}`; `tests/evidence/m08-*.json`; `tests/evidence/artifacts/m08/**`; `docs/architecture/m08-exit.md`; the M08 sections of `progress.md` and the claims table.
- **Builds:** the case index, reusing earlier groups by reference; the combined native runs; the records; the gate ledger; **the claim audit** (every claim-table entry and every sentence of the limitation statement and release notes maps to a record at the candidate build, or is removed); the inputs to M09's go/no-go worksheet (§11).

## 3. Waves, and staying mergeable while M06 and M07 land

```text
W0  (now, beside M06 W5 and M07 W3)   U1a fuzz │ U3a packaging │ U4a provenance │ U5a harness + rehearsal │ U6a bundle crate │ U7a drafts │ U2a install + journey driver
W1  (trigger: M07 freeze, below)      U0 contract deltas and skeleton
W2                                    U2b lifecycle │ U6b bundle command │ U1b new boundaries + §14.3 table │ U7b defaults audit
W3  (the candidate commit)            U3b archives + clean machines │ U4b provenance │ U5b benchmarks, then the 72-hour soak │ U7b final text
W4                                    U8 exit suite, records, claim audit, the candidate record
```

**The trigger:** M06's exit is merged to `main`, and the contract owner has landed revision 7 as provisional. U0 may draft earlier; it merges only after the trigger.

**The candidate commit** is `main` after W2 merges. The soak starts on it. §6.3 says what a later fix invalidates.

**How a W0 unit stays mergeable:**
- **It adds files; it changes none of M06's or M07's.** The W0 write set is `fuzz/**`, `tools/packaging/**`, `tools/benchmarks/m08/**`, `crates/support/**`, `deny.toml`, `SECURITY.md`, `docs/operations/**`, `docs/security/**`, `docs/release/**`, `docs/user/limitations.md`, `docs/release-notes/v1-candidate.md`, `docs/sources/snapshots/**`, `tests/native/m08/**`, `tests/adversarial/{m08_fuzz_regressions.rs, support_bundle_redaction.rs, corpus/m08/**}` and `tools/validation/docs_commands_check.py`.
- **It hands shared lines to their owner** (rule 3): two `[[test]]` lines, one workspace member with its crate-graph rule, two `check.sh` steps, and possibly one release-profile line.
- **It uses only today's commands.** Harnesses take the binary and every command name from one table per harness, so a rename is one edit.
- **It rebases at each M06 and M07 merge to `main`** and reruns its own self-tests. No W0 unit holds a branch that edits a file another track owns.
- **W0 results are rehearsals.** Every number, archive and campaign is repeated on the candidate; only the regression tests and tools carry over.

**Reviews:** one review and one scoped re-check per wave. The plan §6.7 security review covers:
- **W0:** the bundle's redaction (U6a); the install scripts (U2a); the fuzz triage (U1a);
- **W2:** restore and reset (U2b); the bundle command (U6b);
- **W3:** the archives and the provenance set against ADR-0014 §4.

## 4. The declared release matrix and the clean-machine proof

**The targets** are spec §3.2's, at ADR-0004 §4's provisional floors.

| Target | Triple and linkage | Built on | Archive | Signature today |
|---|---|---|---|---|
| macOS arm64 (floor: macOS 27) | `aarch64-apple-darwin`; system frameworks, `libSystem`, `libiconv` only [observed] | the Mac | `.tar.gz` | ad-hoc, linker-signed [observed]; Developer ID and notarization need B13 |
| Linux x86-64 (floors: Ubuntu 24.04, Debian 13) | `x86_64-unknown-linux-gnu`, dynamic, glibc 2.31 link floor (**Q4**) | the Mac, through the zig shims every native run has used since M01 | `.tar.gz` | none |
| Linux arm64 | `aarch64-unknown-linux-gnu`, the same floor | the Mac, zig | `.tar.gz` | none. The native row is blocked on B9 |
| Windows x86-64 (floor: Windows 11 26H2, in-box OpenSSH) | `x86_64-pc-windows-msvc`, static C runtime | the PC (the toolchain every native Windows run used) | `.zip`, containing the Linux x86-64 `heimdall` as the WSL helper beside `heimdall.exe` (`crates/wsl/src/host.rs`) | none (B16 for Authenticode) |
| WSL2 x86-64 (floor: Ubuntu 24.04) | the Linux x86-64 binary inside the distribution; the Windows archive on the host | — | no archive of its own | — |

### 4.1 What "clean machine" means here

A clean machine has no Rust toolchain, no compiler or SDK, no Heimdall state and no test variables. The proof has two parts, and a row needs both:

1. **Static:** `verify_artifact.py` shows the archive needs nothing the bare operating system lacks.
2. **Run:** the install script and the first journey (install, `--version`, `setup` on a scratch SSH configuration, one fixture login, `doctor`, uninstall) run on the clean machine, from the archive alone.

### 4.2 Where each row runs

| Target | Clean machine | Owner input | Without it |
|---|---|---|---|
| Linux x86-64 | A fresh disposable WSL2 distribution on the PC, imported from the stock Ubuntu 24.04 root file system and unregistered by exact name (ADR-0004 §3's authorized pattern). Debian 13 as a container inside it | none (an idle window on the PC) | — |
| WSL2 x86-64 | The same distribution for the Linux side | none for Mode B's Linux side | — |
| Windows x86-64 | **A disposable non-administrator Windows account** on the PC, with a minimal `PATH`. A fresh account on a developer machine is **not** a clean machine: machine-wide runtimes are present. The static check carries the "no hidden runtime" claim; the run carries "it installs and works without the developer's profile" | **B2** (one elevation consent). **B15** for a true clean VM (Windows Sandbox or a disposable VM) | The run row is `blocked` on B2; the static row stands |
| macOS arm64 | **A disposable standard account** on the Mac. The same caveat: the command-line tools are machine-wide | **B3** (admin consent). **B15** for a macOS VM | The run row is `blocked` on B3; the static row stands |
| Linux arm64 | `debian:13-slim` and `ubuntu:24.04` containers on the Mac's Docker (linux/arm64). Supplementary, as in every earlier milestone | **B9** for the native row | The native row is `blocked` on B9 |
| Linux x86-64, a second host | The devbox, in a disposable local account or a rootless container | **B8** | Not needed for the exit: the WSL distribution carries the row |

**Q3** asks the orchestrator whether "fresh account plus static check" closes the Windows and macOS clean-machine rows, or whether they stay `blocked` on B15.

## 5. Provenance without publishing

Every candidate archive carries, and the repository records under `tests/evidence/artifacts/m08/release/<version>/`:

| Item | What it is | Checked by |
|---|---|---|
| `SHA256SUMS` | SHA-256 of every archive and of every file inside it | `verify_artifact.py`; `shasum -a 256 -c` on the clean machine |
| `BUILD-RECORD.json` | The commit, a clean-tree flag, the toolchain and target, the feature set, the flags, the `Cargo.lock` digest, the builder's OS, each tool's pinned version, the times, each output's digest | Compared with what the binary reports about itself |
| SBOM | One CycloneDX JSON per target, from the resolved graph for that target and feature set | Compared with `cargo metadata` for the same target |
| `THIRD-PARTY-NOTICES.txt` | Every linked crate with its licence text; `third_party/netdev` included | The generator fails on a missing text |
| `LICENSE` | The project's licence | **B17** |
| `SECURITY.md` | How to report a vulnerability; what is and is not monitored | **B18** |
| The rebuild comparison | The same commit built twice on the same host: identical or not, stated as observed | U4b |

**The digests are committed to the public repository; the archives are not uploaded anywhere.** A user who later receives an archive checks it against digests anchored in the repository's history.

**Signatures.** No signing key is available to agents, so each row is an owner input with an alternative that claims only what was produced:

| Row | Needs | Alternative used until then |
|---|---|---|
| macOS Developer ID signature and notarization | **B13** (Apple Developer membership) | The ad-hoc signature, stated as such. The release notes keep the M03 note: an update can cut the issuer off from its CA key until `issuer restore` |
| Windows Authenticode | **B16** (a code-signing certificate) | Unsigned, stated as such |
| A signature over `SHA256SUMS` | **B16** (an owner signing key, used by the owner) | The digests in the repository's history, with the build record |

The release never says "signed" or "reproducible" for a row where that was not produced and verified (spec §15.3).

## 6. Benchmarks and the 72-hour soak

### 6.1 Benchmarks (spec §15.1)

- **Build:** the candidate archive for each target, installed by its script.
- **Catalog:** 100 destinations, from an import bundle of fixture aliases on loopback.
- **Method:**
  - **Request latency excludes process start** by timing requests on one open control session, through M07's reference wrapper. The CLI's end-to-end time is reported beside it, for information;
  - **the first TUI frame** is timed from spawn to the first complete frame on a pseudo-terminal;
  - **key handling under background work** uses real slow work (the delaying agent proxy from M05 U0b), because the release build refuses the test hooks;
  - **idle CPU** is three five-minute samples after ten minutes of settling; **idle memory** is resident set size on Linux, physical footprint on macOS and private working set on Windows, the method named in the record;
  - at least 200 samples per latency metric; P50 and P95; the host's model, CPU, memory, OS build and power state in the record.
- **Passing** is ADR-0014 §6.1.

| Platform | Where | Owner input |
|---|---|---|
| Linux x86-64 and WSL2 | the disposable WSL2 distribution on the PC, in an idle window | none |
| Windows x86-64 | the disposable Windows account | B2 |
| macOS arm64 | the disposable macOS account | B3 |
| Linux arm64 | the Mac's Docker; supplementary | B9 for a native row |

### 6.2 The soak

**Recommendation: the Mac, in one Linux container** (Docker Desktop, linux/arm64), running the Linux arm64 candidate archive.

| Machine | Verdict | Why |
|---|---|---|
| **The Mac, in a container** | **Recommended** | It needs no owner input and can start the day the candidate exists. It has the disk. The container is the isolation AGENTS.md requires for a release runtime, and `--network none` removes every listener question. Other tracks' builds cost it CPU, which the soak's measures (growth and retry counts) tolerate |
| The devbox | Second choice, and only with B8 | Native x86-64 and always on. But a release runtime there needs a disposable account or rootless container (B8), and about 2 GiB of usable disk is shared with M06's and M07's native runs for three days |
| The Windows PC | Not for 72 hours | The owner uses it; an idle window is hours, not days. It gives the 6-hour x86-64 cross-check below |
| The VPS | No | It is small, runs the owner's services, and would need the same owner authorization as the devbox |

**Budget:** `--network none --cpus 2 --memory 2g --pids-limit 512`; at most 2 GiB of disk (the harness stops itself at 1.5 GiB); samples every 30 s.

**Lanes,** each a separate scratch home and runtime in the container:

| Lane | Build | What it does | What it shows |
|---|---|---|---|
| **S, steady** | the release archive | One runtime that is never restarted on purpose. The workload below, an idle TUI on a pseudo-terminal with a key every minute, and an event follower. Dependency faults only: the fixture sshd down, the agent down, the agent locked | Resource growth over one 72-hour process lifetime; retry behaviour during outages |
| **L, lifecycle** | the release archive, and the previous build for update and rollback | The same workload, plus a seeded schedule repeating every 6 hours: a graceful stop and restart; `SIGKILL` at rest; `SIGKILL` during a burst of writes; the dependency faults; the scratch volume filled until writes fail, then freed (daily); the configuration file and `instance.json` damaged (daily); an update to the candidate and a rollback (twice) | Recovery, persistent-state growth, identity and authority across restarts |
| **M, managed** | a debug build on the scratch store, unless the rehearsal shows a product secret store works in the container | Managed-credential work: issue, expire, re-issue after restart, revoke | The managed recipe's lifecycle under the same faults. Mechanism evidence if on the debug build |
| **R, runner** | M06's exit configuration, two containers on an internal network | A paired runner whose controller leaves and returns; a revocation delivered while disconnected | Joins only if M06's exit supports it in containers; mechanism evidence |

**Workload** (seeded; per lane): every minute a mix of `status`, `inspect`, an already-authorized `ensure`, and a fresh fixture login through `run`; every ten minutes a grant taken with a ten-minute window, left to expire, then probed; every thirty minutes an explicit stop followed by a probe. About 430 expiries and 140 stops per lane.

**Measured, every 30 s:** per process, resident memory, threads, open descriptors and CPU time; per home, the database and its write-ahead log, the log directory, the backups and the file count; per fixture, connections accepted by the sshd and requests seen by the agent proxy (the retry record); per run, the harness's own ledger of what it asked for and what it was given.

**Supervision.** The container runs detached and supervises itself: a heartbeat, a `status.json`, and a `DONE` or `FAILED` file. It **stops early** on any authority failure, panic, canary, or runaway resource (ADR-0014 §6.3), so a bad run costs hours, not days. The orchestrator owns the run and reads `status.json` at start, +1 h, +6 h, +24 h, +48 h and +72 h. No worker turn waits on it (**Q6**: this is an exception to the blocking-worker rule). A heartbeat missing for ten minutes ends the run as invalid. A host sleep shows as a gap; the run continues until 72 hours of running time, and total gaps above an hour extend it.

**Cross-checks,** six hours each, the same harness, lanes S and L:
- **Linux x86-64:** the disposable WSL2 distribution on the PC, in an idle window. No owner input.
- **Windows:** handle and working-set growth of the Windows runtime, in the disposable account (B2). Without B2, a debug build with the scratch SSH home gives mechanism evidence only.
- **macOS:** the same, in the disposable account (B3), with the same fallback.

**Passing** is ADR-0014 §6.2.

### 6.3 What a later fix invalidates

A change to the candidate after the soak starts reruns:
- **the 72-hour soak,** if it touches the runtime's long-lived paths: `crates/{runtime, store, ipc, credential, issuer, app}`;
- **a 6-hour confirmation,** for any other change under `crates/`;
- **nothing,** for documentation, packaging metadata and tests.

## 7. Exit mapping

Records live in `tests/evidence/m08-*.json`. The lowest-row rule applies. "All" means macOS arm64, the Linux devbox (debug builds) and Windows 11; release rows run where §4.2 says.

### 7.1 A29 — hostile input and authorization forgery

- **Requirements:** R-SE-05, R-SE-01, R-SE-02, R-SE-03, R-SE-06, R-RT-03, R-AP-08.
- **Platforms:** all, plus the Mac container for the fuzz campaign.
- **Fixtures:** the adversarial fixtures of M01–M07; the fuzz corpus (synthetic only); the prompt-injected agent of M05; M06's invitation and role fixtures; the skill and its lint (R-AP-08: the skill never creates consent).
- **Passing means:**
  - every indexed adversarial and property test passes at the exit build;
  - every fuzz target met the stopping rule with no open finding;
  - every spec §14.3 item maps to a passing test;
  - no test shows an unauthorized mutation or authority, an unbounded parser, a silent denial, or request content treated as consent.
- **The §14.3 table** (U1b confirms each row at the frozen tree and fills any gap):

| Spec §14.3 item | Known coverage today |
|---|---|
| Manifest path traversal; symlink and replacement races | M05 U1 and U4 (`project_pure`, the FIFO, symlink and swapped-manifest cases) |
| Shell metacharacters in labels and paths | M02's path and quoting fixtures; M04's WSL quoting rows |
| Hostile `Match exec` | `sshconf_hostile.rs`; `m02-a21-passive-doctor.json` |
| Forged approval metadata | `prompt_injection.rs` |
| Request-ID collision across owners | `tests/model/idempotency.rs`; M06 U0's two-client case |
| Replayed invitations | M06 U1's property and A25 |
| Malformed and oversized agent messages | `agent_frames.rs`, `agent_client_frames.rs` |
| Signing and control namespace confusion | `signer_requests.rs`; A14's endpoint rows |
| Inherited authority across unrelated jobs | M05's A16 and A28 |
| Host alias collision | to confirm in U1b |
| Stale configuration rollback | `projection_recovery` |
| Expiry and revoke races | `tests/model/{revocation, timegate}.rs`; M03's A07 |
| Another destination trusting the same CA | M03's A10 |
| A child asking for a later deadline | `tests/model/authority.rs`; M05's delegation tests |
| A repeated work ID after a cutoff | M05's A05 |
| A stopped service recovering with a stale signing handle | to confirm in U1b (A17's groups) |
| A forwarding peer reaching identities outside the set | M04's A15 and A28 forwarding rows |

- **Rows not run natively:** the cross-user rows (B2); the arm64 rows (B9).

### 7.2 A31 — packaging, update, recovery and uninstall

- **Requirements:** R-DI-01, R-DI-02, R-DI-03, R-DI-04, R-DI-05, R-RT-08, R-CR-06, R-EN-01, R-EN-04, R-QU-02.
- **Platforms:** §4.2's table, each target's archive on its clean machine.
- **Fixtures:** the candidate archive and the previous build's archive; a preexisting SSH configuration with wildcard, `Include` and `Match` blocks and a Git configuration (M02's conflict corpus); active work (a held `run` and a live fixture session); a store one schema version ahead; a damaged store; an M03 enrollment and an M06 pairing against fixtures.
- **Journeys:**
  1. **Install and start:** from the archive alone, with the static check first.
  2. **Update with active work:** the stop preview names the held run and the live session; the update keeps the environment ID, policies, cutoffs, pauses and enrollments; unexpired grants are served again after restart under the existing re-issue rule; nothing expired or stopped returns.
  3. **Rollback, same schema:** the previous binary serves the same store.
  4. **Rollback across a schema change:** the older binary refuses the newer store and touches nothing; the restore follows Q1's rule.
  5. **Recover:** a damaged store stops unsafe operations; `doctor` names the choices; a restore keeps the identity; a reset says it creates a new one and lists what it orphans.
  6. **Uninstall:** the preexisting SSH and Git configuration is byte-identical to before install; the remaining remote enrollments and pairings are listed; backups and the previous binary are listed.
  7. **Provenance:** every file matches `SHA256SUMS`; the SBOM matches the resolved graph; the notices are complete; the signature status printed in the release notes equals what `codesign` and the Windows signature check report.
- **Passing means:** no hidden build dependency; truthful checksums and signature statements; the SSH setup preserved; no identity reset; the remaining remote enrollment explicit.
- **Rows not run natively:** Windows and macOS run rows (B2, B3); true clean VMs (B15, subject to Q3); arm64 (B9); a real-account login after logout (B12, carried).

### 7.3 A33 — secrets and data minimization

- **Requirements:** R-CR-03, R-CR-04, R-SE-08, R-DI-07.
- **Platforms:** all for the bundle rows; the Mac container for the defaults audit and the archive scan.
- **Fixtures:** M03's canary set (store, provider, key comments) plus canaries in host names, user names, paths, a fixture session's command and output, and environment values; the candidate archives.
- **Rows:**
  - **M03's rows,** by reference, rerun at the exit build;
  - **the support bundle:** the preview shows exactly what the bundle will hold; nothing is written before the confirmation; the bundle holds no canary, no key material, no database, no session content and no identifier outside the pseudonym map; it works with the runtime down;
  - **update artifacts:** the archives, the previous-binary copy, the migration backups and the install scripts' output hold no canary and no private key; the backups are listed as residue with their sensitivity stated;
  - **the defaults audit** (`defaults_audit`): a default install, setup and first journey in a container with no network completes; a second run on an internal network with a capture shows no packet leaving loopback and no listening TCP or UDP socket; the store and the logs hold none of the fixture session's content; the transport feature and every bundle are off until asked for; nothing loads an extension.
- **Passing means:** no secret leakage or plaintext fallback; preview and redaction work; telemetry and transcript collection are off by default.
- **Rows not run natively:** the cross-user rows (B2).

### 7.4 A34 — performance and soak

- **Requirements:** R-QU-03, R-QU-04, R-RT-06.
- **Platforms, fixtures and method:** §6.
- **Passing means:** ADR-0014 §6: each budget met on each measured platform, or revised by a recorded decision with the measurement; 72 hours with no unbounded queue or leak, no permission widening and no tight retry loop.
- **Rows not run natively:** Windows and macOS release benchmarks (B2, B3); the Linux x86-64 72-hour row, if the container run is not accepted for it (Q2); arm64 native (B9).

### 7.5 Records

| Record | Case |
|---|---|
| `m08-a29-hostile-input.json` | A29 |
| `m08-fuzz-campaign.json` | A29's fuzz row: targets, time, coverage curve, findings |
| `m08-a31-lifecycle.json` | A31 |
| `m08-release-artifacts.json` | A31's provenance row: digests, build record, SBOM digests, signature status |
| `m08-a33-secrets.json` | A33 |
| `m08-a34-benchmarks.json` | A34, the table |
| `m08-a34-soak.json` | A34, the soak and its cross-checks |
| `m08-exit-claims.json` | The claim audit and the gate ledger |

### 7.6 The exit rule

**M08 exits** when every record is `verified`, except rows blocked solely on named owner inputs and rows deferred by decision (the M01–M07 rule). The candidate is then handed to M09 with its record. **M08 does not decide `go`, `preview-only` or `no-go`;** it states which rows a `go` would have to waive.

## 8. Contract deltas

ADR-0014 §7 lists them for the contract owner. None is applied by this plan. In brief: the support-bundle command and schema; a stop preview; state status, restore and reset; reasons for a corrupt store, a newer store and a restored one; a doctor finding for a moved executable; residue kinds for backups, the previous binary and a moved Git block; build-provenance fields in the version output; the candidate's version string.

## 9. Probes run in this design unit

**Record:** `tests/evidence/m08-probe-inventory-and-release-binary.json`. **Raw output:** `tests/evidence/artifacts/m08/probe/`. **Driver:** `prototypes/m08-probe/`. **Build:** `main` at `de097dac`. No `heimdall` binary was executed.

| Probe | Question | Observed | What it changed |
|---|---|---|---|
| P1 | What does a dependency and licence inventory hold per target, with no new tool? | 221 (Windows) to 265 (Linux x86-64) third-party crates in the binary's graph; every one has a licence field and offers a permissive choice; `libsqlite3-sys` is the only bundled native library; no git or path source | The licence policy is an allow-list of what is already there. The SBOM is per target |
| P2 | Does a lock-file scan give the same answer? | No: 322 components for every target, test crates included, and no licences | The SBOM comes from the resolved graph, not from the lock file |
| P3 | What reaches the release graph only through the test kit? | 16 to 20 crates (proptest, rusty-fork, tempfile and others). The stripped macOS binary holds no `proptest` string | The SBOM marks them (ADR-0014 §4.5); Q8 asks whether to cut the edge |
| P4 | What does the macOS release binary need, and what does it carry? | System libraries only; ad-hoc signature; 13.8 MB; **the build host's home path 297 times**; no private-key armor | Path remapping and the artifact scan are part of U3a, before any archive is shared |

**Not probed, and why:** a Linux release build in a clean container (the product's Linux binaries already run on the devbox at every merge candidate; the open question, static musl or the glibc floor, is Q4 and needs a new toolchain target, so it is U3a's first step); a fuzz toolchain (it needs a nightly image; U1a's first step).

## 10. Deferred, each with a reason

| Item | Reason |
|---|---|
| Publishing to any registry, store or release page | The owner's separate authorization (plan §10.3) |
| Self-update | Spec §15.3: no hidden self-update. Updating is the user running a newer archive's install script |
| Native packages (`.pkg`, MSI, `.deb`, Homebrew, winget) | Each is a publishing channel with its own signing and review. The archives and scripts are the V1 artifact; a channel is a post-V1 decision |
| Static musl Linux builds | No native run has ever used one (Q4) |
| A whole-workspace sanitizer campaign (thread, address) | `unsafe` is denied workspace-wide and confined to platform FFI modules in six production crates (311 blocks at `de097dac`, mostly Windows and macOS calls), which a Linux sanitizer build would not exercise. The fuzz targets already run under libFuzzer's address sanitizer. Races are covered by the model suites and lane L. U1b hands M09-T03's review an inventory of the `unsafe` modules instead |
| Fuzzing in `check.sh` | Campaigns run per candidate; their findings are permanent regressions |
| The two Git residuals other than the moved block | Disclosed in the limitation statement; no requirement needs more |
| Tunable limits (the revocation cap, P7, P12) | No measurement asks for a change; they stay proposals |
| Export above the 1 MiB bundle cap | No user need recorded |
| A storage-size bound in configuration | Reported from the soak first (ADR-0014 §6.2 item 4); a new setting is a contract delta only if the measurement asks for it |
| The LLM agent evaluations, the user study, the independent security review | M09-T01 to T03 |

## 11. Questions for the orchestrator

Each has a recommendation. Q1 is an authority-semantics question and is escalated, not decided.

| # | Question | Recommendation |
|---|---|---|
| **Q1** | **What does restoring a pre-update backup do to authority?** A backup predates every stop, revocation and cutoff made after it. Restoring it as it stands would revive them | **Restore keeps identity and configuration and ends authority:** every grant in the restored store is ended, every standing policy is paused, and the restore is recorded as an event. The user approves again. Remote effects reconcile through M06's report. The alternative, refusing restore and offering only a reset, loses the identity and orphans every enrollment |
| **Q2** | Does a 72-hour run in the Mac's Linux container satisfy A34's soak, with the declared hardware stated? | **Yes,** with the 6-hour x86-64 cross-check in the disposable WSL2 distribution. The soak's properties (growth, retries, authority across restarts) do not depend on the architecture. If no, the row is `blocked` on B8 |
| **Q3** | Do "fresh account plus static check" rows close the Windows and macOS clean-machine claim? | **Yes, stated as a limitation,** and upgraded when a VM exists (B15). Linux and WSL get truly clean machines either way |
| **Q4** | Linux artifacts: dynamic against a glibc 2.31 floor, or static musl as ADR-0002 §9 sketched? | **The glibc floor.** Every Linux run since M01 used it, and the floors (Ubuntu 24.04, Debian 13) are far above it. Shipping musl would ship a build nothing has tested |
| **Q5** | Which features does the candidate build enable, in particular `iroh`? | **Whatever M06's exit rules for the transport's V1 scope,** one feature set per target, recorded in the build record. The benchmarks and the soak run that set |
| **Q6** | May the soak run detached, with scheduled checks by the orchestrator, as an exception to "the agent that starts a long command blocks on it"? | **Yes.** No turn can block for 72 hours. The self-supervising container and the heartbeat rule replace the block |
| **Q7** | G09 has no single decision record. One consolidated record, or a ruling that ADR-0008, ADR-0010 §5 and M03's A23 together are the record? | **A ruling,** written into the gate ledger with the three references. A new ADR would restate what is decided |
| **Q8** | Cut the `heimdall` → `heimdall-testkit` edge from release builds (a cargo feature), or keep it and mark those crates in the SBOM? | **Keep and mark.** Cutting it changes how the gated release binary is built, late, for no behavioural gain. Revisit after V1 |
| **Q9** | The candidate's version string (today `0.1.0-m01`; it is in the hello) | **`1.0.0-rc.1`,** set by the contract owner at U0. A `preview-only` decision at M09 renames it |
| **Q10** | The fuzz toolchain: a pinned nightly inside a container only, with every finding reproduced on the pinned stable toolchain | **Yes.** The workspace pin does not move, and the evidence is the stable regression test |
| **Q11** | A new crate `crates/support` for the bundle collector, or a module inside `crates/heimdall`? | **A new crate:** pure, testable without the binary, and mergeable now with one handed manifest line |

## 12. Owner inputs and handoffs

**Owner inputs that block a row** (B14 is M07's participant; the new ones start at B15):

| Input | Blocks |
|---|---|
| **B2:** the disposable second Windows account (one elevation consent) | Windows release rows of A31 (install, update, uninstall) and A34 (benchmarks, the handle cross-check); A29's and A33's cross-user rows |
| **B3:** a disposable macOS standard account (admin consent) | macOS release rows of A31 and A34; the macOS K_ca row across an update |
| **B8:** a disposable account or rootless container on the devbox | Only an alternative: a native x86-64 home for the soak, if Q2 is answered no |
| **B9:** a native Linux arm64 host | Every arm64 native row |
| **B12:** an operator for logout and reboot | The login-after-logout row (carried); the reboot inside lane L is not attempted |
| **B13:** Apple Developer membership | A signed and notarized macOS build; without it the macOS update limitation stays in the release notes |
| **B15 (new):** a clean Windows VM or Windows Sandbox, and a macOS VM | True clean-machine rows on Windows and macOS, unless Q3 is answered yes |
| **B16 (new):** a signing key (a checksum-signing key the owner uses; optionally a Windows code-signing certificate) | Any signature claim beyond the macOS ad-hoc one |
| **B17 (new):** the project licence, and confirmation of the project name | `LICENSE`, the manifest's licence field, the notices header; a release of any kind |
| **B18 (new):** the vulnerability-reporting route (for example, private reporting enabled on the repository, or a contact address) | `SECURITY.md`'s content |
| An idle window on the PC of about 8 hours | The Linux x86-64 and WSL clean-machine rows, benchmarks and the 6-hour cross-check. No consent needed, only time |

**M09 needs these from M08** (plan §10.3's worksheet):

| Worksheet field | Where M08 leaves it |
|---|---|
| Build digest; stack and dependency versions | `m08-release-artifacts.json`; `BUILD-RECORD.json`; the SBOMs |
| Gate ADR status | The gate ledger in `m08-exit.md` |
| Requirement and case results; platform coverage; skipped tests | `m08-exit-claims.json`; the relabelled matrix |
| Unresolved defects; known limitations | `RESIDUALS`; `docs/user/limitations.md` |
| Benchmark and soak references | `m08-a34-benchmarks.json`; `m08-a34-soak.json` |
| Update and rollback test | `m08-a31-lifecycle.json` |
| Independent-review status; owner authorization | M09's |
| The shipped help, schemas and skill for the agent evaluations | The candidate archives (`examples/`, `skills/`) |
