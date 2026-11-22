# M08 plan: harden and package what is actually supported

**Status:** accepted, revision 4 (2026-11-22), from the M08 design unit; the orchestrator checked revision 4 against its rulings and accepted it with ADR-0014. **Revision 4 is the last design round.** The orchestrator checks it against the rulings below. **The independent check of the restore protocol moves to U2b's implementation review,** where it meets real fault injection. No production code was written for the design.

**Revision 4:**
- **What it applies:** the second re-check (Codex, NOT CLOSED: N01 and N02 blocking, N03 moderate; `tests/evidence/artifacts/review-m08/design-recheck2.md`) under the orchestrator's rulings of 2026-11-22: the epoch on every mutating request and no quiet period; adoption fenced before it is published; the ledger digest over the full idempotency key.
- **Where to find the changes:** §13's last three rows.

**Revision 3:**
- **What it applies:** the scoped re-check (Codex, NOT CLOSED: R01 and R02 open, RC-N01 new, R10 low; `tests/evidence/artifacts/review-m08/design-recheck.md`) under the orchestrator's rulings of 2026-11-22: a restore epoch and replay fence, one durable generation switch, a per-generation operation record, and P2 relabelled.
- **Where to find the changes:** §13's last four rows.

**Revision 2:**
- **What it applies:** the independent design review (Codex, REVISE, M08-D-R01–R10; `tests/evidence/artifacts/review-m08/design.md`) and the orchestrator's rulings of 2026-11-22 on Q1–Q11 and on each finding (§0a).
- **Where to find the changes:** §13 maps each finding to its place.
**Design ADR:** ADR-0014 (proposed, revision 4; accepted at merge, with its contract and storage deltas H1–H13 pending the contract owner's handoff): the fuzz boundary list and stopping rule, the update and recovery contract, the artifact and provenance policy, the support-bundle and privacy defaults, and the benchmark and soak thresholds. ADR-0014 wins wherever this plan differs.
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

## 0a. The orchestrator's rulings (2026-11-22), folded

| Ruling | Where it lands |
|---|---|
| **Q1, with D-R01 and D-R02:** a restore keeps identity and configuration and recovers no authority. It ends grants (remote effects through M06's pending-effects path), pauses policies, and quarantines management clients, invitations, exposure and admission state and pending widening decisions until reauthorized and reconciled. It keeps the more restrictive of the two states where the old store is readable, and never revives a revoked grant, a retired issuer or an unpaired environment. Pins stay as identity information. It is identity-bound, excludes runtimes and issuers, sanitizes a staged copy, activates by one pointer switch and keeps the old generation (revision 3). Reset discloses or refuses when no inventory is readable | ADR-0014 §3.2, §3.6, H3, H9, H10; U2b |
| **Q2:** the container soak is accepted, named exactly, with the absence of a native macOS or Windows long run stated | ADR-0014 §6.4; §6.2, §7.4 |
| **Q3, reversed by D-R06:** the true clean-machine rows stay `blocked` on B15. Fresh-account runs are separate evidence and close nothing | ADR-0014 §4.8; §4.1, §4.2, §7.2 |
| **Q4:** the glibc 2.31 floor; ADR-0002 §9 amended at merge | ADR-0014 §7; §4 |
| **Q5:** M06's exit rules the feature set; one per target, in the build record, frozen before inventories, benchmarks and soak | §4, U3b |
| **Q6:** the soak runs detached under an explicit rule in the ADR, for the soak only | ADR-0014 §6.6; §6.2 |
| **Q7:** ADR-0008, ADR-0010 §5 and M03's A23 are G09's record | ADR-0014 header; §1.5 |
| **Q8: cut the test-kit edge,** by a small explicit debug-support feature under the manifest's owner, before the candidate. It needs changes in `crates/testkit` and in other crates' manifests, which M06 and M07 own today, so it is scheduled after the handoff (U3c). The inventory marks those crates until then | ADR-0014 §4.5, H11; U3c |
| **Q9:** `1.0.0-rc.1`, set once at U0; the digest and version stay immutable if M09 labels the same artifact a preview | U0 |
| **Q10:** a pinned nightly in a container, stable regressions; image and tool pins recorded | U1a |
| **Q11:** a new crate `crates/support`, with private data types | U6a |
| **D-R03:** no free text in a bundle; codes and typed values only; every remaining string pseudonymized, the inverse map kept out; the previewed bytes are the written bytes; identifier inclusion never bypasses secret checks | ADR-0014 §5.1; U6a, U6b |
| **D-R04:** a package-, target- and feature-selected graph with host and build distinctions, through a pinned SBOM tool and a validation adapter; counts corrected | ADR-0014 §4.5; §1.1, §9, U4a |
| **D-R05:** shared edits wait for an explicit contract-owner handoff after M07's relevant emitters and readers land. W0's units are provisional, to be integrated | rule 2, §3 |
| **D-R07:** an inner manifest that excludes itself, an external index over finalized archives and records, verification against the repository-anchored digest before install, staged recoverable replacement | ADR-0014 §4.3, §4.4; U2a, U3a, §5 |
| **D-R08:** the blocked A34 rows named; invalidation by executable, paths and build inputs; "zero after revoke" stated as local admission against already-issued credentials | ADR-0014 §6.2 item 6, §6.4, §6.5; §6.3, §7.4 |
| **D-R09:** the final matrix and a reference configuration packaged; the compatibility and deprecation policy and the urgent-fix procedure assigned; a populated candidate worksheet handed to M09 | ADR-0014 §4.2; U7, U8, §12 |
| **D-R10:** real invocations and exits recorded where they exist; the rest labelled as not reproducible | the probe record; §9 |
| **Re-check R01 (ruled): a restore epoch.** Restore raises it; everything minted before belongs to the old epoch; later terminal operations and idempotency facts carry forward when the old store is readable; otherwise every pre-restore request without a terminal record is refused as stale; reauthorization revives nothing; the runner's effect ledger is the authority for later remote effects | ADR-0014 §3.6 "The restore epoch and the replay fence", H9, H13; U2b |
| **Re-check R02 and RC-N01 (ruled): one durable generation switch.** Each family in its own generation directory; a `CURRENT` pointer written, synced and renamed; start-up trusts only the pointer; earlier generations kept under unique names with an operation record (install, adopt, restore, reset; migrations appended) | ADR-0014 §3.6 "Store generations", H12; U2b |
| **Re-check 2, N01 (ruled): the epoch on requests; no quiet period.** Every mutating request carries the epoch its ID was minted under, bound at mint time and reused on retry; the server refuses a non-current epoch, attended or not. The CLI, TUI, wrapper and harnesses follow it. The ledger and every fence follow ADR-0006 §7.4's retention exactly | ADR-0014 §3.6 fence steps 3–6, H13, H9; U2b; a line for M07's wrapper and harnesses in the handoff |
| **Re-check 2, N02 (ruled): fence first, then publish.** Intent, legacy schema fence, copy, pointer, completion; never relying on an older build understanding the pointer; a one-way boundary | ADR-0014 §3.2 item 8, §3.6 "Adoption"; U2b; §7.2 journeys 3–4 |
| **Re-check 2, N03 (ruled):** the ledger digest covers the full idempotency key | ADR-0014 §3.6 fence step 4; U2b |
| **Re-check R10 (ruled):** P2 is a recorded summary, not independently checked | §9; the probe record |
| **Economy (the review's answer 6):** an unchanged fuzz target is not rerun on a candidate; minimized cases extend existing seeds where a suite has them | ADR-0014 §2.3; U1 |

## 0. Rules

1. **One contract owner.** The integrator holds ADR-0006. No M08 unit edits `crates/contract/**`, `schemas/**`, `tests/contracts/**`, the CLI subcommand table in `cli.rs`, `runtime/src/dispatch.rs`, `ipc/src/session.rs` or the store. A unit that needs one of ADR-0014 §7's deltas waits for U0.
2. **Provisional now** (written "provisional now" in revision 1) means both of these hold:
   - **The write set is outside M06's and M07's.** M06's is m06-plan §1 plus what `origin/m06/w4` changed: `crates/{app, runtime, credential, heimdall, store, transport-iroh, contract, remote, domain, issuer, registry, sshconf, enroll, testkit, ipc, adapters}`, `schemas/`, `third_party/`, `.cargo/`, the root `Cargo.toml` and `Cargo.lock`, `tools/validation/{check.sh, crate_graph.py, audit_gate.py, audit-ignore.txt}`, and the existing files under `tests/{adversarial, contracts, e2e, integration, model}`. M07's is m07-plan §2 plus what `origin/m07/w2` changed: `crates/heimdall/**`, `examples/**`, `skills/**`, `docs/api/`, `docs/user/adapters.md`, `tools/validation/{skill_lint.py, adapter_page_check.py}`.
   - **The unit uses only commands, fields and files that exist on `main` today.**

   **Provisional is not contract-independent.** A W0 unit builds tooling, harnesses, drafts and private data types. Its command tables, its drafts' wording, the bundle's input adapters, the final feature set and every inventory count are provisional, and each is updated when the unit is integrated.

   Everything else is **after the contract handoff:** an explicit message from the contract owner, sent after M06's exit is merged **and** the M07 emitters and readers a unit depends on have landed (m07-plan U3's corrections, not merely revision 7 becoming provisional). The handoff names what may be edited. Without it, no M08 unit edits the CLI, the schemas, the contract or the store.
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
  - **14 to 16 test-only crates (proptest, rusty-fork, tempfile and others) are in the binary's selected build graph** through `heimdall-testkit`, a normal dependency of the binary [observed with `cargo tree -p heimdall`, revision 2]. They are compiled for a release build; whether the linker keeps anything of them was not established.
  - **A workspace-wide resolution overstates the graph.** `cargo metadata` listed 234 third-party packages for macOS where cargo's package-selected graph holds 209 (review M08-D-R04). The inventory must be selected by package, target and features.
- **Hostile-input coverage is broad but not coverage-guided.** Six adversarial suites (76 tests), 37 files with fixed-seed property tests and the M05 prompt-injection suite exist. Earlier milestones deferred fuzzing of nine parsers to M08. A29's records are blocked only on B2 and B9.
- **A33 is verified for M03's surface.** Support bundles and update artifacts were deferred to M08. The redactor exists (`runtime/src/telemetry.rs`, structural, canary-tested); no bundle exists.
- **A34 has not started.** Only debug-build measurements exist (`m07-probe-tui-and-lists.json`, `first_frame_latency_measured_and_recorded`), and the G02 benchmark scripts measure the prototypes.
- **The largest owner dependency:** native release rows on Windows and macOS need a disposable account on each (B2, B3), and the clean-machine rows of A31 need a clean VM on each (B15). Without them those rows stay `blocked`.

### 1.2 Tasks

| Task | Exists now | Missing → unit |
|---|---|---|
| **T01** Adversarial parser, IPC, path and authority tests; fuzzing; leaks and races | `tests/adversarial/`: `sshconf_hostile.rs` (19 tests), `agent_client_frames.rs` (18), `agent_frames.rs` (16), `ipc_frames.rs` (10), `signer_requests.rs` (7), `prompt_injection.rs` (6) with `prompt_injection/{agent,cli}.rs`. Property suites under `tests/model/` (authority, revocation, idempotency, lifecycle, timegate, projection recovery, sshconf parse/eval/edit). Path cases: FIFO includes and input files, symlinks, swapped manifests (M02 U3, M05 U4). Records `m01-a29-local-hostile-input.json` and `m05-a29-hostile-input.json` (blocked on B2, B9) | Coverage-guided fuzzing of the boundaries in ADR-0014 §2. A spec §14.3 coverage table, with a test for any item that has none. M06's and M07's new boundaries. The A29 run at the exit build (U1) |
| **T02** Migration, corrupt-state recovery, drain/update/rollback, uninstall and remote residue | `store/src/lib.rs`: `NewerSchema`, `OlderSchema`, `Corrupt`; `integrity_check` and `foreign_key_check` at open; a backup `<file>.v<N>.backup[.<n>]` before the first pending step, never overwritten; tests `garbage_header_is_corrupt_not_fresh`, `damaged_page_is_corrupt_not_fresh`, `truncated_file_is_corrupt_not_fresh`, `newer_schema_is_refused_and_untouched`, `open_read_only_refuses_newer_reports_older_and_never_writes`, `fresh_file_needs_no_backup_and_pending_step_is_backed_up_first`. `service stop` with a 10 s drain. `uninstall` and `purge_sweep` in full. The macOS ad-hoc update note (`docs/release-notes/m03-macos-ca-key-access.md`), `issuer_executable_changed`, `issuer restore`. The Windows state-directory upgrade path (ADR-0010 §10 item 5) | A recovery command for a corrupt or newer store. Restore from a backup under ADR-0014 §3.6's rule. A stop preview. An install and update procedure with a kept previous binary. Detection of a moved executable. Identity and authority invariants across the migration ladder. Residue rows for backups, the previous binary and M06's remote state. The three Git residuals (U2) |
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
| G09 | **Ruled (Q7):** ADR-0008's effect table, ADR-0010 §5 and M03's A23 record (with A05, A07, A08) together are the record; ADR-0014's header states it | A G09 question none of the three answers is recorded as open, not closed by the ruling |

## 2. Units

Each unit lists its marking, owner role, owned paths, what it builds, its tests and its native runs. Models follow ADR-0009 §2.6. At most two workers run at a time while M06 and M07 use workers.

### U0: Contract deltas and skeleton (the integrator, as contract owner) — after the contract handoff

- **Starts** on the contract owner's explicit handoff (rule 2), which names the files.
- **Owns:** `crates/contract/**`, `schemas/**`, `tests/contracts/**`, the `cli.rs` subcommand table, the store migration, `check.sh` steps, the root manifest; ADR-0006's next revision section; the version string (`1.0.0-rc.1`, set once).
- **Builds:** ADR-0014 §7's deltas as accepted by the contract owner, each as an addition that fails closed until its unit lands (the M05 skeleton rule): the support-bundle command and schema; the stop preview; the state commands **with §3.6's restore rule as an authority rule of the contract**; the restore epoch, the backup's environment binding and the quarantine states (H9, H10); **the storage layout of H12** (generation directories, the pointer, the operation record, the adoption intent, the request ledger), which M06 and M07 own the files of today, so it is named in the handoff; the epoch in the hello **and on every mutating request,** with the stale-request refusal (H13), which the CLI, the TUI and M07's wrapper and harnesses must follow in the same change; the new reasons, doctor findings and residue kinds; the build-provenance fields.
- **Tests:** schema goldens; the command-tree golden; migration up; every new command answers its "not available in this build" envelope until its unit replaces it.
- **Native:** Windows and the devbox at the merge candidate.

### U1: Hostile input (T01)

**U1a — provisional now.**
- **Owner:** a security implementer (strongest model for target selection and triage; a fast model writes the targets).
- **Owns:** `fuzz/**` (a crate outside the workspace, with its own empty `[workspace]` table and lock file); `tests/adversarial/m08_fuzz_regressions.rs` (new; its `[[test]]` line is handed over); `tests/adversarial/corpus/m08/**` (minimized seeds, synthetic only).
- **Builds:**
  - one libFuzzer target per boundary 1–11 of ADR-0014 §2, calling the same public or `#[doc(hidden)]` entry points the adversarial tests call. A boundary with no reachable entry point is listed for its crate's owner, not patched;
  - seeds from the existing adversarial fixtures and the committed proptest regression files;
  - **the campaign**, in a Linux container on the Mac (`--network none`, 4 CPUs, 6 GiB memory, a pinned nightly installed in the image only). The workspace keeps its pinned stable toolchain. The source is mounted read-only; the build directory lives in the container and goes with it;
  - **the stopping rule of ADR-0014 §2.3**, applied per target.
- **Tests:** every crash, hang or memory blow-up becomes a minimized regression on the pinned toolchain: in `m08_fuzz_regressions.rs`, or handed to the owner of an existing suite as a new regression seed where that suite already replays seeds, so no case is tested twice. An unchanged target is not rerun on a candidate (ADR-0014 §2.3). The image, the nightly and the fuzzer are pinned and recorded. A finding that blocks a merge (ADR-0009 §2.1) carries a revert proof.
- **Native:** the regressions run everywhere with the workspace suite. The campaign runs on the Mac container only; its record says so.

**U1b — after the contract handoff.**
- **Builds:** targets for boundaries 12–15 (M06's bridge frames and invitation records, the route helper's pre-identification buffer, the `sshd -T` verifier, M07's page tokens and selectors). The spec §14.3 table (§7.1), with one new test per item that has none. An inventory of the modules that allow `unsafe`, for M09-T03's review. The A29 run at the exit build.
- **Native:** macOS, the devbox and Windows at the merge candidate.

### U2: Lifecycle: update, drain, rollback and recovery (T02)

**U2a — provisional now.**
- **Owner:** a lifecycle implementer (strongest model: this is authority-adjacent).
- **Owns:** `tools/packaging/install.sh`, `tools/packaging/install.ps1`; `tests/native/m08/lifecycle/**` (the journey driver and its fixtures).
- **Builds:**
  - **the install scripts** of ADR-0014 §4.3: a fixed per-user location, no elevation, no edit of `PATH`, shell profiles or `~/.ssh`; the unpacked tree checked against `MANIFEST.sha256` before anything is copied; **the staged, recoverable replacement** (temporary names, digest check, the old pair renamed to `heimdall.previous`, the new pair renamed into place); on Windows the Linux helper replaced with `heimdall.exe` as a pair;
  - **the journey driver**, taking two archives ("old" and "new"), the external `SHA256SUMS` and a platform, and running verify → install → setup → active work → stop → update → restart → rollback → uninstall in a container or disposable distribution. In W0 it runs the M05 exit build against `main`, as a rehearsal only.
- **Tests:**
  - the driver's self-test against a fake archive pair;
  - `install_interrupted_at_each_step_leaves_a_complete_pair` (a kill and a full-disk error after each of the four steps; rerunning the script finishes or undoes it);
  - `install_refuses_a_tree_that_differs_from_its_manifest`;
  - the Windows replace-while-running case (a `heimdall run` child holds the image open).
- **Native:** rehearsals in the Mac container and a disposable WSL distribution.

**U2b — after the contract handoff.**
- **Owns:** new `crates/heimdall/src/state_cmd.rs` and the stop-preview code in `service_cmd.rs`; **in `crates/store` and `crates/runtime` (the store and path files, M06's and M07's today, named in the handoff):** the generation layout, the pointer, the operation record, the adoption (intent, fence, copy, pointer), the request ledger, the restore staging and sanitization; the doctor finding for a moved executable; the residue rows in `uninstall_cmd.rs` and the purge sweep's handling of generations; the moved-block report in `crates/localenv/src/projection/`.
- **Depends:** U0; M06's exit (its client, invitation, exposure, pending-effect and effect-ledger records are what §3.6 quarantines and reconciles).
- **Requirement (ADR-0014 §3.6, ruling of 2026-11-22):** every backup, adoption copy, staging copy and carry-forward read goes through SQLite and never copies the main database file alone. Test: `no_store_copy_reads_the_main_file_alone` (a store whose state is only in its write-ahead log, after a kill: each of those paths still sees it).
- **Builds:** ADR-0014 §3 in full, with §3.6: the generation switch, the restore epoch and replay fence, identity binding, exclusion under the instance lock, staging, sanitization, the report; reset as a generation.
- **Tests:**
  - **`migration_ladder_keeps_identity_and_authority`:** over M07 U0's replay corpus (stores written by the M02, M03, M04/M05 and M06 exit builds), after adoption and migration to the candidate schema the environment ID, tombstones, cutoffs, pauses, grant deadlines and the authority generation are unchanged, and no grant is more active than before. The corpus is M07's; this test adds only these assertions;
  - `corrupt_store_stops_unsafe_operations_and_offers_recovery` (real binary: `status`, `ensure` and `doctor` each name the recovery choices; nothing is written);
  - **the restore fault set of ADR-0014 §3.6,** each a focused case:
    - `restore_keeps_a_later_revoked_grant_ended` (the fixture login with its material is refused);
    - `restore_quarantines_a_later_revoked_management_client` (its key is refused until reauthorized);
    - `restore_voids_consumed_and_expired_invitations` (a join and a replay are refused);
    - **`request_completed_after_the_backup_is_never_run_again`:** backup → the request completes → the store is made unreadable → restore → reauthorize → retry with the same request ID. It is answered `REQUEST_STALE` from the fence record, and the fixture adapter's ledger shows no second execution. Checked **after reopening and reauthorization.** A second variant keeps the old store readable: the retry gets the carried terminal answer;
    - `old_decision_reference_is_refused_after_restore_and_reauthorization`;
    - **`no_duplicate_effect_when_store_and_ledger_are_both_lost`:** backup → the request completes → the store and the ledger are destroyed → restore → reauthorize → the same request ID with its original epoch, sent attended and sent non-interactive. Both are refused `REQUEST_STALE`; the fixture adapter's ledger shows no second effect. A request minted after a fresh hello proceeds;
    - `stale_epoch_is_refused_before_any_write` (for every mutating request kind, through the CLI, the TUI's requests and the wrapper);
    - `clients_carry_the_epoch_with_a_kept_request_id` (the CLI's `--request-id` retry path, the wrapper and both harnesses);
    - `equal_request_ids_across_clients_roles_and_kinds_have_separate_fences`;
    - `fence_retention_follows_the_idempotency_contract` (an unresolved key's fence is answered after any wait; a settled key's lasts its retention from settlement and then the 30-day marker; with only the ledger readable nothing is dropped early);
    - `runner_effect_applied_after_the_backup_is_adopted_not_resent`;
    - `restore_keeps_a_retired_issuer_retired_and_an_unpaired_environment_unpaired`;
    - `restore_disables_exposure_and_closes_pending_widening_decisions`;
    - `restore_refuses_another_environments_backup_and_changes_nothing`;
    - `restore_is_refused_while_a_runtime_or_issuer_runs`;
  - **the generation-switch fault set:**
    - **`switch_interrupted_before_and_after_each_sync_and_the_rename`:** a kill and an injected I/O error at each of: the staged database's sync, the operation record's sync, the generation directory's sync, the temporary pointer's sync, the rename, the state directory's sync. After restart each ends in the intact old generation or the complete new one, and a staged leftover is removed;
    - `unreadable_or_dangling_pointer_stops_and_never_picks_another_generation`;
    - **`reset_then_restart_serves_the_new_generation`;**
    - **`restore_restore_reset_keeps_every_earlier_generation`** (unique names, one record each, none overwritten; start-up serves the last);
    - **`adoption_killed_at_each_step_then_older_build_then_newer_build`:** a kill after each of the five steps (intent, fence, copy, pointer, completion); then the older build is started; then the newer one. Before the fence the older build serves the flat store, and the newer build then adopts it with what the older one wrote. After the fence the older build refuses and writes nothing, and the newer build resumes from the intent. A revocation made by the older build is never missing afterwards;
    - `ledger_append_precedes_the_first_store_write` (a kill between them leaves a ledger entry and no record; an ordinary restart ignores it; a restore fences it);
  - `reset_is_attended_and_says_it_creates_a_new_identity`;
  - `reset_without_any_readable_inventory_says_so_and_refuses_non_interactive`;
  - `older_build_on_newer_store_refuses_and_touches_nothing` (two real binaries: the candidate and a test-configuration build one schema version ahead);
  - `stop_preview_lists_what_stopping_interrupts` (read-only: the store and the endpoints are unchanged after it);
  - `moved_executable_is_a_doctor_finding_and_never_a_silent_break`;
  - `uninstall_lists_backups_earlier_generations_previous_binary_and_remote_pairings`, and `purge_removes_every_generation_under_the_lock`;
  - `rollback_reports_a_moved_git_block`.
- **Native:** the A31 journeys of §7.2, at the merge candidate and again at the exit build. **The switch's fault set runs natively on macOS, the devbox and Windows:** the rename and sync calls differ per platform, and Windows has no directory sync. Power loss is not tested anywhere, and the record says so.

### U3: Release artifacts (T03)

**U3a — provisional now** (started 2026-11-22 on `m08/w0`).
- **Owner:** a packaging implementer, reviewed by the integrator.
- **Owns:** `tools/packaging/build-release.sh`, `tools/packaging/build-release.ps1` (the PC), `tools/packaging/verify_artifact.py`, `tools/packaging/README.md`.
- **Builds:**
  - **the release build for each target of §4**, from a clean checkout of one commit, `--locked`, with build-host paths remapped for Rust and for the bundled C code, and a static C runtime on Windows;
  - **the archive layout** of ADR-0014 §4.2, with the inner `MANIFEST.sha256` that lists every file except itself;
  - **the external checksum index** `SHA256SUMS` over the finalized archives and their external records, written last and never packed (ADR-0014 §4.4);
  - **`verify_artifact.py`**, the static check every archive passes before anything else is done with it:
    - only the allowed dynamic libraries per target (system frameworks and `libSystem`/`libiconv` on macOS; glibc's own libraries with no symbol version above 2.31 on Linux; operating-system DLLs only on Windows);
    - no build-host home, cargo, rustup or checkout path in any file;
    - no full canary value and no private-key armor;
    - every file is listed in the manifest with a matching digest, and nothing else is;
    - the build record names the target and the executables' digests;
    - given the external index, the archive's own digest is in it;
    - once H7 exists, the version, commit and target the binary reports equal the build record.
- **Tests:** `verify_artifact.py`'s self-test against known-bad fixtures (a planted registry path, a planted canary, a key block, an extra library, a symbol version above the floor, a digest mismatch, an unlisted file, an archive member that leaves the root, an archive missing from the index).
- **Native:** in W0, one rehearsal build per target from `main`; the Linux archive run in `debian:13-slim` and `ubuntu:24.04` containers with no toolchain.
- **The path remap is passed by the script** (no manifest line). The candidate's release gate must test a binary built the same way: U3b hands `check.sh`'s owner the one-line change that points the gate at the script's build.

**U3b — after the contract handoff.**
- **Builds:** the candidate archives from the candidate commit, with M07's skill, wrapper and harnesses under `examples/`; the feature set ruled at M06's exit, frozen before the inventories, benchmarks and soak; the final compatibility matrix and the reference configuration (U7b's); the clean-machine runs and the fresh-account runs of §4.2, recorded separately; the floors' confirmation for ADR-0001 §5 where a truly clean machine ran.
- **Native:** §4.2's table.

**U3c — after the contract handoff, before the candidate** (the ruling on Q8).
- **Owner:** the manifests' owner (the integrator), or an implementer under an explicit handoff.
- **Why it is not W0:** `proptest` and `tempfile` are unconditional dependencies of `heimdall-testkit`. By reading, `tempfile` is used only in the kit's own tests and `proptest` by its strategies module. Cutting them means a change in `crates/testkit` (its manifest and a `cfg` on that module) and, for every crate that depends on the kit with default features off and uses the strategies, one manifest line. `crates/testkit` and those manifests are M06's or M07's today.
- **Builds:** the smallest change that removes the crates: `tempfile` becomes a dev-dependency of the kit if no non-test code needs it; `proptest` moves behind a kit feature that the binary's edge does not enable. If that is not enough, the binary's edge to the kit becomes an explicit debug-support feature. A release build then compiles none of the 14 to 16 crates.
- **Tests:** `release_graph_holds_no_test_only_crate` (cargo's selected graph for the release feature set, per target); the existing release gate, run on the binary built with the selected features.

### U4: Provenance (T04)

**U4a — provisional now** (the inventory, notices and build record started 2026-11-22 on `m08/w0`).
- **Owner:** a packaging implementer; the licence policy is reviewed by the integrator.
- **Owns:** `deny.toml`; `tools/packaging/provenance.py` (the validation adapter, the notices generator, the build record, the manifest and index writers, the packer); `SECURITY.md` and `LICENSE` (after B18 and B17); `docs/sources/snapshots/**` (E8 only); `docs/release/name-and-licence-check.md`.
- **Builds:** ADR-0014 §4.4–§4.7:
  - **the licence and source policy** (`cargo-deny`, pinned; licences, sources and bans only; advisories stay with M06's audit gate);
  - **an SBOM per target:** a pinned SBOM tool produces CycloneDX JSON for the package, target and feature set; **the validation adapter** compares it with cargo's own selected graph (`cargo tree -p heimdall --target <triple> --features <set> --edges normal,build`) and with the packages the release build compiled, removes and counts what the selected graph lacks, fails on anything missing, and labels each component `target`, `host` or `test-support`;
  - **`THIRD-PARTY-NOTICES.txt`**, generated from the same selected set with each crate's licence text, failing when a text is missing;
  - **`BUILD-RECORD.json`,** `MANIFEST.sha256` and the external `SHA256SUMS`;
  - **E8:** proprietary vendor snapshots replaced by their hashes and archive URLs;
  - **the name and licence check:** read-only lookups of the project name against the registries a release might use, and a compatibility table of the dependency licences against the candidate project licences. It also lists the product identifiers that embed the repository owner's account name (the macOS login entry's label), for the owner's naming decision (B17).
- **Tests:** the policy passes on `main` and fails on a fixture lock file with a copyleft crate and one with a git source; the notices generator fails on a crate with no licence text; the adapter fails when the tool's output lacks a selected package, drops and counts an unselected one, and labels a proc macro `host`.
- **Native:** none; the tools run on the build hosts.

**U4b — after the contract handoff.**
- **Builds:** the final SBOMs, notices, build records, manifests and the external index for the candidate; the same-host rebuild comparison; signatures only where a key exists (§5).

### U5: Benchmarks and soak (T05)

**U5a — provisional now.**
- **Owner:** a harness implementer (fast model), reviewed by the integrator.
- **Owns:** `tools/benchmarks/m08/**` (the bench driver, the sampler, the fault scheduler, the analysis script, the container definition).
- **Builds:** §6's harness, and **a 2-hour rehearsal** of lanes S and L in the Mac container on a release build of `main`. The rehearsal proves the harness and yields first numbers. It is not exit evidence.
- **Tests:** the analysis script's self-test on synthetic series (a leak, a plateau, a tight retry loop, a gap); the scheduler replays the same schedule from the same seed.
- **Native:** the Mac container.

**U5b — after the contract handoff.**
- **Builds:** the benchmark runs on the candidate (§6.1) and the 72-hour soak (§6.2), with M07's reference wrapper as the timing client and M06's runner lane.
- **Native:** §6's tables.

### U6: The support bundle (T06)

**U6a — provisional now.**
- **Owner:** an implementer on the strongest model (this is a disclosure boundary).
- **Owns:** a new crate `crates/support/**` (pure: private data types in, bundle bytes out; no runtime machinery and no copy of the public views; its manifest line and crate-graph rule are handed over); `tests/adversarial/support_bundle_redaction.rs` (new; its `[[test]]` line is handed over).
- **Builds:** ADR-0014 §5.1: a collector whose inputs are **typed** as code, safe value, public identifier, secret or free text. Codes and safe values are written; identifiers are pseudonymized, with the inverse map returned separately; secrets and free text are never written. The bundle's bytes are built once and returned as one value, which the command previews and then writes. Its input types are private and provisional: U6b maps the frozen views onto them.
- **Tests,** none of which prints or writes a planted value (a failure names the field and a digest):
  - `bundle_holds_only_codes_safe_values_and_pseudonyms` (a walk over every string in the bundle against the three shapes);
  - `free_text_is_never_exported` (messages, log lines, operating-system and `ssh` error strings, finding detail);
  - `unmarked_secrets_never_reach_the_bundle` (short passwords, word-like tokens, a passphrase inside an error string, planted in every free-text and identifier input);
  - `split_and_multiline_key_material_never_reaches_the_bundle` (a key block split across fields and lines, altered armor);
  - `identifier_bearing_diagnostics_are_withheld_or_pseudonymized` (a host name inside an error message; a path inside a finding);
  - `include_identifiers_never_bypasses_secret_checks` (a secret planted in an identifier-typed field is withheld);
  - `the_inverse_map_is_not_in_the_bundle`;
  - `previewed_bytes_are_the_written_bytes`;
  - `canaries_in_every_input_never_reach_the_bundle`;
  - `bundle_is_plain_text_and_bounded`.

**U6b — after the contract handoff.**
- **Owns:** new `crates/heimdall/src/support_cmd.rs`.
- **Depends:** U0, U6a.
- **Builds:** `heimdall support bundle`, with the frozen-bytes preview, working when the runtime is down or the store is unreadable; the mapping of the frozen views onto U6a's input types, in which **a field is free text unless its type says otherwise**.
- **Requirements carried from U6a's review (2026-11-22; orchestrator's ruling):**
  - **The bundle reads the store through SQLite, as a family, read-only** (ADR-0014 §5.1). Test: `bundle_counts_see_state_that_is_only_in_the_write_ahead_log`.
  - **Codes come only from enumerations.** No string that arrives as data (a name, a label, a reason text) is passed to the collector as a code. A code-shaped host name would otherwise be exported.
  - **Identifier inclusion never exports a word-like value typed as an identifier, unless its type is an enumerated identifier kind** (user name, host name, alias, path, fingerprint, Heimdall ID). A field whose kind is not one of those stays pseudonymized or withheld even with `--include-identifiers`.
  - **Random-looking path segments stay withheld.** More withheld fields than expected is the safe direction and is not "fixed" by loosening the check.
- **Tests:** the A33 journey of §7.3; `bundle_works_with_a_corrupt_store`; `bundle_writes_nothing_without_the_command`; `every_view_field_has_a_declared_export_type`; `codes_are_taken_only_from_enumerations` (a source check on the mapping); `identifier_inclusion_needs_an_enumerated_kind`; (a source check: a new field with no declared type fails the build, so it cannot be exported by default).
- **Native:** macOS, the devbox and Windows at the merge candidate.

### U7: Privacy defaults, release notes, policies and runbooks (T06; plan §10.2–§10.4)

**U7a — provisional now.**
- **Owner:** the integrator writes the limitation statement and the two policies (strongest model); a fast model drafts the runbooks.
- **Owns:** `docs/operations/{install.md, update-and-rollback.md, recovery.md, unenrollment.md, uninstall.md, urgent-fix-disclosure.md}`; `docs/compatibility/policy.md`; `docs/user/limitations.md`; `docs/security/privacy-defaults.md`; `docs/release-notes/v1-candidate.md`; `examples/reference-config/**` (new; `examples/` is otherwise M07's, so this directory is named in the handoff list); `tools/validation/docs_commands_check.py` (its `check.sh` line is handed over).
- **Builds,** as drafts on today's command names:
  - **the runbooks,** each beginning with the verification of the archive against the repository's `SHA256SUMS`;
  - **the compatibility and deprecation policy** (plan §10.4): what a version number promises for the CLI, the schemas and the store; ADR-0013 §3.3's deprecation rule (at least two minor releases and 90 days) restated for users; how provider and OS version changes are recorded. The contract owner approves it with revision 7;
  - **the urgent-fix disclosure procedure** (plan §10.4): how an urgent fix is announced (the release notes and `SECURITY.md` in the repository), what an emergency restart interrupts, how a user opts into an update, and that no monitoring or notification service is promised;
  - **the reference configuration:** `config.toml` with every default and its meaning, and an example manifest, each validated against the published schema.
- **Tests:** `docs_commands_check.py` checks every command in a runbook against the command-tree golden, so a rename fails until the draft follows it; its self-test against a runbook naming a command that does not exist; the reference configuration parses and validates.

**U7b — after the contract handoff.**
- **Builds:** the final text on the frozen names; the defaults audit of §7.3; the agent-use guide (M07's skill and protocol document, packaged); **the final compatibility matrix,** regenerated from the exit records (every row's label, versions, record and limitation) and packaged in the archive, not only relabelled in the repository.
- **Tests:** `defaults_audit` (§7.3), run in the container; `matrix_rows_cite_existing_records` (every label other than `not-tested` names a record at the candidate build).

### U8: Exit suite, evidence and the candidate worksheet (the integrator) — after the contract handoff

- **Owns:** `tests/native/m08/{case-index.json, runs.json, required-inventory.json}`; `tests/evidence/m08-*.json`; `tests/evidence/artifacts/m08/**`; `docs/architecture/m08-exit.md`; `docs/release/candidate-worksheet.md`; the M08 sections of `progress.md` and the claims table.
- **Builds:**
  - the case index, reusing earlier groups by reference; the combined native runs; the records; the gate ledger;
  - **the claim audit:** every claim-table entry and every sentence of the limitation statement and release notes maps to a record at the candidate build, or is removed;
  - **the candidate worksheet** (plan §10.3), **populated, not a template:** for the candidate, the build digests; the stack and dependency versions; each gate ADR's status; every requirement's and case's result; platform coverage; unresolved defects and residuals; the known limitations; the benchmark and soak references; the update and rollback test. It ends with two lists: **the rows a `go` would have to waive,** each with its blocking input, and **the authorizations still missing** (the owner inputs of §12, the independent review, the release authorization). The decision field is left empty.
- **The M09 step that finishes it:** M09-T04 audits the worksheet against all 80 requirements and 36 cases; M09-T03 fills the independent-review field; M09-T05 records `go`, `preview-only` or `no-go`; M09-T06 seeks the owner's authorization.

## 3. Waves, and staying mergeable while M06 and M07 land

```text
W0  (now, beside M06 W5 and M07 W3)   U3a packaging │ U4a provenance │ U1a fuzz │ U5a harness + rehearsal │ U6a bundle crate │ U7a drafts │ U2a install + journey driver
W1  (trigger: the contract handoff)   U0 contract deltas and skeleton │ U3c test-kit edge
W2                                    U2b lifecycle │ U6b bundle command │ U1b new boundaries + §14.3 table │ U7b defaults audit
W3  (the candidate commit)            U3b archives, clean machines, fresh accounts │ U4b provenance │ U5b benchmarks, then the 72-hour soak │ U7b final text and matrix
W4                                    U8 exit suite, records, claim audit, the candidate worksheet
```

**The trigger is a message, not a state.** The contract owner hands off explicitly, after M06's exit is merged and after the M07 emitters and readers each unit depends on have landed (m07-plan U3's corrections). Revision 7 becoming provisional is not enough: M07's U0 lands only unused types, and its U3 then changes live shapes. The handoff names the files M08 may edit. U0 may draft earlier; it merges only after the handoff. If the handoff comes in parts, W2's units start in the order their dependencies are handed over.

**The candidate commit** is `main` after W2 and U3c merge, with the feature set frozen. The soak starts on it. §6.3 says what a later change invalidates.

**W0's units are provisional, to be integrated:**
- **They add files; they change none of M06's or M07's.** The W0 write set is `fuzz/**`, `tools/packaging/**`, `tools/benchmarks/m08/**`, `crates/support/**`, `deny.toml`, `docs/operations/**`, `docs/security/**`, `docs/release/**`, `docs/compatibility/policy.md`, `docs/user/limitations.md`, `docs/release-notes/v1-candidate.md`, `docs/sources/snapshots/**`, `examples/reference-config/**`, `tests/native/m08/**`, `tests/adversarial/{m08_fuzz_regressions.rs, support_bundle_redaction.rs, corpus/m08/**}` and `tools/validation/docs_commands_check.py`. `LICENSE` and `SECURITY.md` wait for B17 and B18.
- **They hand shared lines to their owner** (rule 3): two `[[test]]` lines, one workspace member with its crate-graph rule, two `check.sh` steps and the release gate's build line.
- **They use only today's commands,** through one table per harness, so a rename is one edit.
- **What integration will change, known in advance:** the harnesses' command tables (M06's renames, M07's frozen names); the runbooks' wording; the bundle's input adapters (the typed views); the feature set and so every inventory count; the archive's contents (the examples, the matrix, the policies).
- **They rebase at each M06 and M07 merge to `main`** and rerun their own self-tests.
- **W0 results are rehearsals.** Every number and archive is repeated on the candidate. The tools and regression tests carry over; a fuzz campaign carries over for a target whose inputs did not change (ADR-0014 §2.3).

**Reviews:** one review and one scoped re-check per wave. The plan §6.7 security review covers:
- **W0:** the bundle's typed collector (U6a); the install scripts (U2a); the fuzz triage (U1a);
- **W2:** restore and reset (U2b), against ADR-0014 §3.6 line by line; the bundle command and its field typing (U6b);
- **W3:** the archives and the provenance set against ADR-0014 §4.

## 4. The declared release matrix and the clean-machine proof

**The targets** are spec §3.2's, at ADR-0004 §4's provisional floors.

| Target | Triple and linkage | Built on | Archive | Signature today |
|---|---|---|---|---|
| macOS arm64 (floor: macOS 27) | `aarch64-apple-darwin`; system frameworks, `libSystem`, `libiconv` only [observed] | the Mac | `.tar.gz` | ad-hoc, linker-signed [observed]; Developer ID and notarization need B13 |
| Linux x86-64 (floors: Ubuntu 24.04, Debian 13) | `x86_64-unknown-linux-gnu`, dynamic, glibc 2.31 link floor (ruled) | the Mac, through the zig shims every native run has used since M01 | `.tar.gz` | none |
| Linux arm64 | `aarch64-unknown-linux-gnu`, the same floor | the Mac, zig | `.tar.gz` | none. The native row is blocked on B9 |
| Windows x86-64 (floor: Windows 11 26H2, in-box OpenSSH) | `x86_64-pc-windows-msvc`, static C runtime | the PC (the toolchain every native Windows run used) | `.zip`, containing the Linux x86-64 `heimdall` as the WSL helper, in the `linux-x86_64` directory beside `heimdall.exe` where the product looks for it (`crates/wsl/src/spawn.rs`) | none (B16 for Authenticode) |
| WSL2 x86-64 (floor: Ubuntu 24.04) | the Linux x86-64 binary inside the distribution; the Windows archive on the host | — | no archive of its own | — |

### 4.1 What "clean machine" means here

A clean machine has no Rust toolchain, no compiler or SDK, no developer runtime installed machine-wide, no Heimdall state and no test variables. The proof has two parts, and a row needs both:

1. **Static:** `verify_artifact.py` shows the archive imports nothing the bare operating system lacks. This alone proves little: it cannot show that no runtime or subprocess prerequisite is missing.
2. **Run:** the archive is verified against the external index, installed by its script, and taken through the first journey (`--version`, `setup` on a scratch SSH configuration, one fixture login, `doctor`, uninstall) on the clean machine, from the archive alone.

**A fresh account on a developer machine is not a clean machine** (ruling on D-R06): machine-wide runtimes and tools remain. Runs there are recorded as **fresh-account rows,** separate evidence that the product installs and works outside the developer's profile. They never close a clean-machine row.

### 4.2 Where each row runs

| Target | Clean-machine row | Fresh-account row (separate) |
|---|---|---|
| Linux x86-64 | A fresh disposable WSL2 distribution on the PC, imported from the stock Ubuntu 24.04 root file system and unregistered by exact name (ADR-0004 §3's authorized pattern); Debian 13 as a container inside it. No owner input beyond an idle window | — |
| WSL2 x86-64 | The same distribution, for the Linux side | — |
| Windows x86-64 | **`blocked` on B15:** a clean Windows VM or Windows Sandbox | A disposable non-administrator account on the PC with a minimal `PATH` (**B2**, one elevation consent) |
| macOS arm64 | **`blocked` on B15:** a clean macOS VM | A disposable standard account on the Mac (**B3**, admin consent) |
| Linux arm64 | **`blocked` on B9** for the native row. `debian:13-slim` and `ubuntu:24.04` containers on the Mac's Docker (linux/arm64) run as supplementary evidence, as in every earlier milestone | — |

The devbox (B8) is not needed for the exit: the WSL distribution carries the Linux x86-64 row.

## 5. Provenance without publishing

**Inside each archive:**

| Item | What it is | Checked by |
|---|---|---|
| `MANIFEST.sha256` | SHA-256 of every file in the archive **except itself** | `verify_artifact.py`; the install script before it copies |
| `BUILD-RECORD.json` | The commit, a clean-tree flag, the toolchain and target, the feature set, the flags, the `Cargo.lock` digest, the builder's OS, each tool's pinned version, the times, and the digests of the **executables only** | Listed in the manifest; compared with what the binary reports about itself once H7 exists |
| SBOM | One CycloneDX JSON for this target, from the package-, target- and feature-selected graph, each component labelled `target`, `host` or `test-support` | The validation adapter, against cargo's selected graph and the build's compiled packages |
| `THIRD-PARTY-NOTICES.txt` | Every component with its licence text; `third_party/netdev` included | The generator fails on a missing text |
| `LICENSE` | The project's licence | **B17** |
| `SECURITY.md` | How to report a vulnerability; the urgent-fix procedure; what is and is not monitored | **B18** |

**Outside every archive,** committed under `tests/evidence/artifacts/m08/release/<version>/`:

| Item | What it is |
|---|---|
| `SHA256SUMS` | The checksum index: one line per finalized archive and per external record. Written last. Never packed |
| Each archive's SBOM and build record | Copies, so they can be read without the archive |
| The rebuild comparison | The same commit built twice on the same host: identical or not, stated as observed |

**The archives are not uploaded anywhere.** A user who later receives one verifies it against the index in the repository's history **before unpacking it**; the runbooks begin with that command.

**Signatures.** No signing key is available to agents, so each row is an owner input with an alternative that claims only what was produced:

| Row | Needs | Alternative used until then |
|---|---|---|
| macOS Developer ID signature and notarization | **B13** (Apple Developer membership) | The ad-hoc signature, stated as such. The release notes keep the M03 note: an update can cut the issuer off from its CA key until `issuer restore` |
| Windows Authenticode | **B16** (a code-signing certificate) | Unsigned, stated as such |
| A signature over `SHA256SUMS` | **B16** (an owner signing key, used by the owner) | The index in the repository's history, with the build records |

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

**What the lanes do not cover, named as blocked rows of A34** (ADR-0014 §6.4), unless a release run on a product store covers one:
- **release-managed:** the managed recipe on a release build with a product secret store for 72 hours. Lane M on a debug build is mechanism evidence and does not close it. Needs a verified store where the soak runs (B3 on macOS, B11 on Linux);
- **provider:** a provider other than the disposable native agent (the 1Password row, B1);
- **route:** jump and Iroh routes and the runner on a release build. Lane R on debug builds, or absent, leaves it blocked.

**Supervision** follows ADR-0014 §6.6, the explicit exception for the soak only. The container runs detached and supervises itself: a status file every 30 s with the heartbeat and the measures, real start and stop times from the container and the host, and a `DONE` or `FAILED` marker. It **stops itself** on any authority failure, panic, canary or resource threshold (ADR-0014 §6.3), so a bad run costs hours, not days. The orchestrator owns the scheduled reads of the status file (start, +1 h, +6 h, +24 h, +48 h, +72 h). No worker waits on it. A heartbeat missing for ten minutes ends the run as invalid. A host sleep shows as a gap; the run continues until 72 hours of running time, and total gaps above an hour extend it.

**Cross-checks,** six hours each, the same harness, lanes S and L:
- **Linux x86-64:** the disposable WSL2 distribution on the PC, in an idle window. No owner input.
- **Windows:** handle and working-set growth of the Windows runtime, in the disposable account (B2). Without B2, a debug build with the scratch SSH home gives mechanism evidence only.
- **macOS:** the same, in the disposable account (B3), with the same fallback.

**Passing** is ADR-0014 §6.2.

### 6.3 What a later change invalidates

ADR-0014 §6.5: the soak belongs to an executable and its build inputs.
- **The 72-hour run is repeated** when a change can alter a long-lived process: any crate linked into the runtime, the issuer, a helper or a bridge (M06's `remote` and `transport-iroh` and the WSL crate included), the root manifest, the lock file, the feature set, the toolchain or the build flags.
- **A 6-hour confirmation** covers a change confined to short-lived command paths, shown by the diff.
- **Nothing is rerun** for documentation, tests, and packaging metadata that does not enter the executable.
- An unchanged executable digest needs no reassessment. The orchestrator records which case applied.

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
- **Fixtures:** the candidate archive, the previous build's archive and the external `SHA256SUMS`; a preexisting SSH configuration with wildcard, `Include` and `Match` blocks and a Git configuration (M02's conflict corpus); active work (a held `run` and a live fixture session); a store one schema version ahead; a damaged store; an M03 enrollment and an M06 pairing against fixtures.
- **Journeys:**
  1. **Verify, install and start:** the archive checked against the external index before it is unpacked; then from the archive alone. An install interrupted at each step leaves a complete executable pair.
  2. **Update with active work:** the stop preview names the held run and the live session; the update keeps the environment ID, policies, cutoffs, pauses and enrollments; unexpired grants are served again after restart under the existing re-issue rule; nothing expired or stopped returns.
  3. **Rollback, same schema:** the previous binary serves the same store. **Adoption of the generation layout is one-way** (ADR-0014 §3.2 item 8): once the flat store is fenced, a build that predates generations refuses it, finished or not; the journey kills the adoption at each step, starts the older build, then the newer one, and no revocation is lost.
  4. **Rollback across a schema change:** the older binary refuses the newer store and touches nothing; the restore follows ADR-0014 §3.6: nothing revoked, consumed, retired or unpaired after the backup returns; recovered clients, invitations and exposure are quarantined; a request that completed after the backup is never run again, also after reauthorization and also when the store and the ledger are both lost; another environment's backup is refused; an interruption before or after each sync and the pointer rename ends in the old generation or the new one.
  5. **Recover:** a damaged store stops unsafe operations; `doctor` names the choices; a restore keeps the identity and recovers no authority; a reset says it creates a new identity and lists what it orphans, or says that it cannot list it; after a reset, a restart serves the new generation; repeated restores and a reset keep every earlier generation.
  6. **Uninstall:** the preexisting SSH and Git configuration is byte-identical to before install; the remaining remote enrollments and pairings are listed; backups and the previous binary are listed.
  7. **Provenance:** the archive matches the external index and every file matches the inner manifest; the SBOM matches the selected graph; the notices are complete; the signature status printed in the release notes equals what `codesign` and the Windows signature check report.
- **Passing means:** no hidden build dependency; truthful checksums and signature statements; the SSH setup preserved; no identity reset; the remaining remote enrollment explicit.
- **Rows that stay `blocked`:** the Windows and macOS clean-machine rows (B15); the Windows and macOS fresh-account rows, which are separate and close nothing (B2, B3); arm64 native (B9); a real-account login after logout (B12, carried).

### 7.3 A33 — secrets and data minimization

- **Requirements:** R-CR-03, R-CR-04, R-SE-08, R-DI-07.
- **Platforms:** all for the bundle rows; the Mac container for the defaults audit and the archive scan.
- **Fixtures:** M03's canary set (store, provider, key comments) plus canaries in host names, user names, paths, a fixture session's command and output, and environment values; the candidate archives.
- **Rows:**
  - **M03's rows,** by reference, rerun at the exit build;
  - **the support bundle:** the previewed bytes are the written bytes; nothing is written before the confirmation; every string in the bundle is a code, a typed safe value or a pseudonym; no free text, no unmarked secret, no split or multiline key material, no canary, no database and no session content is in it; the inverse map is not in it; `--include-identifiers` exports no value that fails the secret checks; it works with the runtime down;
  - **update artifacts:** the archives, the previous-binary copy, the migration backups and the install scripts' output hold no canary and no private key; the backups are listed as residue with their sensitivity stated;
  - **the defaults audit** (`defaults_audit`): a default install, setup and first journey in a container with no network completes; a second run on an internal network with a capture shows no packet leaving loopback and no listening TCP or UDP socket; the store and the logs hold none of the fixture session's content; the transport feature and every bundle are off until asked for; nothing loads an extension.
- **Passing means:** no secret leakage or plaintext fallback; preview and redaction work; telemetry and transcript collection are off by default.
- **Rows not run natively:** the cross-user rows (B2).

### 7.4 A34 — performance and soak

- **Requirements:** R-QU-03, R-QU-04, R-RT-06.
- **Platforms, fixtures and method:** §6.
- **Passing means:** ADR-0014 §6: each budget met on each measured platform, or revised by a recorded decision with the measurement; 72 hours with no unbounded queue or leak, no permission widening and no tight retry loop.
- **The soak row names its platform exactly:** a Linux arm64 container on a macOS host, with a 6-hour Linux x86-64 cross-check in a disposable WSL2 distribution. **Limitation, stated in the record:** no native macOS or Windows long run exists.
- **"Zero after the end" means local admission** (ADR-0014 §6.2 item 6): no new signature or connection is admitted for an ended grant. An already-issued credential used inside the residual window Heimdall reported is counted against that residual, not as a failure.
- **Rows that stay `blocked`:** Windows and macOS release benchmarks and leak cross-checks (B2, B3); the release-managed soak row (B3 or B11); the provider row (B1); the route and runner row, unless lane R runs on a release build; arm64 native (B9).

### 7.5 Records

| Record | Case |
|---|---|
| `m08-a29-hostile-input.json` | A29 |
| `m08-fuzz-campaign.json` | A29's fuzz row: targets, time, coverage curve, findings |
| `m08-a31-lifecycle.json` | A31 |
| `m08-release-artifacts.json` | A31's provenance row: digests, build record, SBOM digests, signature status |
| `m08-a33-secrets.json` | A33 |
| `m08-a34-benchmarks.json` | A34, the table |
| `m08-a34-soak.json` | A34, the soak and its cross-checks, with the blocked rows named |
| `docs/release/candidate-worksheet.md` | Plan §10.3's worksheet, populated for the candidate (not an evidence record) |
| `m08-exit-claims.json` | The claim audit and the gate ledger |

### 7.6 The exit rule

**M08 exits** when every record is `verified`, except rows blocked solely on named owner inputs and rows deferred by decision (the M01–M07 rule). The candidate is then handed to M09 with its record. **M08 does not decide `go`, `preview-only` or `no-go`.** It hands M09 the populated worksheet (U8), which lists the rows a `go` would have to waive and the authorizations still missing.

## 8. Contract deltas

ADR-0014 §7 lists them for the contract owner. None is applied by this plan. In brief: the support-bundle command and schema (H1); a stop preview (H2); state status, restore and reset, **with the restore rule as an authority rule** (H3), the store's generation layout and request ledger as a storage delta (H12), the epoch and the stale-request refusals (H13); reasons for a corrupt and a newer store (H4); a doctor finding for a moved executable (H5); residue kinds (H6); build-provenance fields (H7); the candidate's version string (H8); the restore record, the backup's environment binding and the quarantine states (H9); the quarantine reasons and the restore event (H10); the debug-support feature that keeps test-only crates out of release builds (H11).

## 9. Probes run in this design unit

**Record:** `tests/evidence/m08-probe-inventory-and-release-binary.json`. **Raw output:** `tests/evidence/artifacts/m08/probe/` (`commands-r2.txt` holds the revision 2 invocations with their exits). **Driver:** `prototypes/m08-probe/`. **Build:** `main` at `de097dac`. No `heimdall` binary was executed.

| Probe | Question | Observed | Standing | What it changed |
|---|---|---|---|---|
| P1 | What does the binary's dependency graph hold per target? | **Revision 2, cargo's package-selected graph** (`cargo tree -p heimdall --target <triple> --edges normal,build`, exit 0 for each): 206 (Windows), 209 (macOS), 254 (Linux arm64) and 255 (Linux x86-64) third-party crates. Revision 1's 221 to 265 came from `cargo metadata`, which resolves features for the whole workspace, and is withdrawn | Reproducible: commands and exits recorded | The inventory is selected by package, target and features, through a pinned tool and an adapter (U4a) |
| P1b | Is anything unlicensed or non-permissive? | Every crate in the metadata graph, a superset of the selected one, has a licence field and offers a permissive choice; `libsqlite3-sys` is the only crate that bundles a native library; no git or path source | Reproducible from the saved summaries | The licence policy is an allow-list of what is already there |
| P2 | Does a lock-file scan give the same answer? | No: 322 components for every target and no licences (rerun in revision 2, exit 0) | **A recorded summary, not independently checked:** only the counts and a digest of the component list were kept, not the list | The SBOM does not come from the lock file |
| P3 | What reaches the graph only through the test kit? | **Revision 2:** 14 to 16 crates (proptest, rusty-fork, tempfile, rand and others), from `cargo tree` with and without `--prune heimdall-testkit`. Revision 1's list of 16 to 20 is withdrawn. Nothing was established about what the linker keeps; the absence of a `proptest` string in the binary is not evidence | Reproducible | The edge is cut before the candidate (U3c); the inventory labels those crates until then |
| P4 | What does the macOS release binary need, and what does it carry? | System libraries only; ad-hoc signature; 13,810,096 bytes; the build host's home path 297 times; no private-key armor found | **Recorded, not reproducible:** the binary was deleted, and the individual commands' exits were not kept | Path remapping and the artifact scan are part of U3a |

**Since the design unit:** the U3a rehearsal on `m08/w0` rebuilt the macOS binary with the paths remapped and found no home path in it (reported with that unit, not as design evidence).

**Not probed, and why:** a Linux release build in a clean container (it is U3a's rehearsal); a fuzz toolchain (it needs a nightly image; U1a's first step).

## 10. Deferred, each with a reason

| Item | Reason |
|---|---|
| Publishing to any registry, store or release page | The owner's separate authorization (plan §10.3) |
| Self-update | Spec §15.3: no hidden self-update. Updating is the user running a newer archive's install script |
| Native packages (`.pkg`, MSI, `.deb`, Homebrew, winget) | Each is a publishing channel with its own signing and review. The archives and scripts are the V1 artifact; a channel is a post-V1 decision |
| Static musl Linux builds | Ruled out for V1 (Q4): no native run has ever used one |
| A whole-workspace sanitizer campaign (thread, address) | `unsafe` is denied workspace-wide and confined to platform FFI modules in six production crates (311 blocks at `de097dac`, mostly Windows and macOS calls), which a Linux sanitizer build would not exercise. The fuzz targets already run under libFuzzer's address sanitizer. Races are covered by the model suites and lane L. U1b hands M09-T03's review an inventory of the `unsafe` modules instead |
| Fuzzing in `check.sh` | Campaigns run per candidate; their findings are permanent regressions |
| The two Git residuals other than the moved block | Disclosed in the limitation statement; no requirement needs more |
| Tunable limits (the revocation cap, P7, P12) | No measurement asks for a change; they stay proposals |
| Export above the 1 MiB bundle cap | No user need recorded |
| A storage-size bound in configuration | Reported from the soak first (ADR-0014 §6.2 item 4); a new setting is a contract delta only if the measurement asks for it |
| The LLM agent evaluations, the user study, the independent security review | M09-T01 to T03 |

## 11. Questions for the orchestrator

**None is open.** Q1–Q11 were ruled on 2026-11-22 (§0a); Q3 was reversed by the ruling on D-R06; the re-check's R01, R02, RC-N01 and R10 were ruled the same day. **The choices revision 3 makes within those rulings, for the orchestrator's review:**
- **The epoch on requests is the fence; the request ledger is the second line** (ADR-0014 §3.6, fence steps 3–5; ruled). The ledger is kept for a caller that breaks the rule by re-stamping an old ID, and so that a known retry gets a precise stored answer. Its digest covers the full idempotency key, and its retention is ADR-0006 §7.4's. Its cost is one more synced append per mutating request. **Revision 3's quiet period is withdrawn.**
- **Adoption** of a store in today's layout: intent, fence, copy, pointer, completion, in that order (ruled). No family member is ever moved, and the boundary is one-way.
- **Migration stays in place** inside a generation, recorded in the generation's operation record; it does not switch generations.
- **The carry-forward** covers every revocation, retirement, unpairing, consumption, cutoff and pause (revision 2), and now every terminal operation and idempotency record.
- **Reset with no readable inventory** discloses and asks for a typed confirmation when attended, and refuses under `--non-interactive` (revision 2).

One observation for the owner's list, not a question: the macOS login entry's label embeds the repository owner's account name, so it is part of the naming decision (B17).

## 12. Owner inputs and handoffs

**Owner inputs that block a row** (B14 is M07's participant; the new ones start at B15):

| Input | Blocks |
|---|---|
| **B2:** the disposable second Windows account (one elevation consent) | The Windows fresh-account rows of A31 (install, update, uninstall) and the Windows release rows of A34 (benchmarks, the handle cross-check); A29's and A33's cross-user rows |
| **B3:** a disposable macOS standard account (admin consent) | The macOS fresh-account rows of A31 and the macOS release rows of A34; the macOS K_ca row across an update; one way to run the release-managed soak row |
| **B1:** a disposable 1Password account | A34's provider row (carried from M02 and M03) |
| **B8:** a disposable account or rootless container on the devbox | Nothing in the exit; it would allow a native x86-64 72-hour run |
| **B11:** a Linux desktop host with a secret service | One way to run the release-managed soak row |
| **B9:** a native Linux arm64 host | Every arm64 native row |
| **B12:** an operator for logout and reboot | The login-after-logout row (carried); the reboot inside lane L is not attempted |
| **B13:** Apple Developer membership | A signed and notarized macOS build; without it the macOS update limitation stays in the release notes |
| **B15 (new):** a clean Windows VM or Windows Sandbox, and a clean macOS VM | The clean-machine rows of A31 on Windows and macOS. Nothing else closes them |
| **B16 (new):** a signing key (a checksum-signing key the owner uses; optionally a Windows code-signing certificate) | Any signature claim beyond the macOS ad-hoc one |
| **B17 (new):** the project licence, and confirmation of the project name and of the product identifiers that embed the owner's account name | `LICENSE`, the manifest's licence field, the notices header; a release of any kind |
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
| Independent-review status; owner authorization | M09's (M09-T03, M09-T06) |
| **The worksheet itself, populated** | `docs/release/candidate-worksheet.md` (U8), ending with the rows a `go` would waive and the authorizations still missing. M09-T04 audits it; M09-T05 records the decision |
| The compatibility matrix, the reference configuration, the compatibility and deprecation policy, the urgent-fix procedure | In the candidate archives and under `docs/` (U7) |
| The shipped help, schemas and skill for the agent evaluations | The candidate archives (`examples/`, `skills/`) |

## 13. Findings map (review M08-D-R01–R10)

| Finding | Where it is addressed |
|---|---|
| **D-R01** (blocking): a restore must not recover remote authority | ADR-0014 §3.6 (the table: management clients quarantined, invitations void, exposure disabled, pending decisions closed, pins as identity only; the carry-forward; "never, by any path"); H3, H9, H10; U2b's restore fault set; §7.2 journey 4 |
| **D-R02** (blocking): restore and reset at the dangerous boundaries | ADR-0014 §3.6 "The protocol" (identity binding, exclusion, staging, preservation, activation, start-up recovery) and §3.2 items 9–10 (reset's inventory-unavailable disclosure); U2b's `restore_refuses_another_environments_backup…`, `reset_without_any_readable_inventory…`; the activation and recovery steps were replaced in revision 3 by the generation switch (the re-check R02 row below) |
| **D-R03** (blocking): the bundle's free-text channels | ADR-0014 §5.1 (codes, typed values and pseudonyms only; free text omitted; the redactor is not the guarantee; the inverse map kept out; the preview is the bundle; narrow identifier inclusion); U6a's and U6b's tests; §7.3 |
| **D-R04:** the inventory graph | ADR-0014 §4.5; U4a (a pinned tool and a validation adapter; `target`, `host`, `test-support`); §1.1 and §9 corrected (206–255; 14–16); the probe record's revision 2 block |
| **D-R05:** the trigger for shared edits | Rule 2; U0 "Starts"; §3 "The trigger is a message, not a state" and "provisional, to be integrated" |
| **D-R06:** clean machines | ADR-0014 §4.8; §4.1, §4.2 (two separate row kinds); §7.2's blocked rows; §12 (B15) |
| **D-R07:** digests and installation | ADR-0014 §4.3 (the user's verification against the external index; staged, recoverable replacement) and §4.4 (three layers); §5; U2a's interruption test; U3a |
| **D-R08:** the soak's coverage, invalidation and the revoke rule | ADR-0014 §6.2 item 6, §6.4 (the three blocked rows), §6.5; §6.2, §6.3, §7.4; §12 (B1, B3, B11) |
| **D-R09:** release artifacts and the handoff to M09 | ADR-0014 §4.2 (the matrix, the reference configuration, the policy, the procedure); U7a, U7b; U8's populated worksheet and the M09 steps; §12 |
| **D-R10:** the probe evidence | The record: `commands-r2.txt` with exits; revision 1's static observations and counts labelled "recorded, not reproducible"; the withdrawn figures marked; §9's "Standing" column |
| **The review's answers on Q6, Q8, economy** | ADR-0014 §6.6 (the soak's supervision rule); U3c and H11; ADR-0014 §2.3 and U1a (no rerun of an unchanged target) |
| **Re-check R01:** a request completed after the backup could be retried after a restore | ADR-0014 §3.6 "The restore epoch and the replay fence" (the epoch in every server-minted reference; carried terminal records; the request ledger and fence records; reauthorization reopens nothing; revision 3's quiet period was withdrawn in revision 4; the runner's effect ledger); H9, H13; U2b's `request_completed_after_the_backup_is_never_run_again`, `old_decision_reference_is_refused…`, `runner_effect_applied_after_the_backup…`; §7.2 journey 4 |
| **Re-check R02:** recovery from a crash between family members | ADR-0014 §3.6 "Store generations: one durable switch" (no member is ever renamed; the staged generation durable before the pointer moves; start-up trusts only the pointer; platforms and what is not tested); H12; U2b's `switch_interrupted_before_and_after_each_sync_and_the_rename`, `unreadable_or_dangling_pointer_…`, the adoption cases |
| **Re-check RC-N01:** a completed reset looked like an inconsistent restore | ADR-0014 §3.6 (the per-generation operation record; "Reset is the same switch"); U2b's `reset_then_restart_serves_the_new_generation`, `restore_restore_reset_keeps_every_earlier_generation` |
| **Re-check R10:** P2's standing | §9 P2 ("a recorded summary, not independently checked"); the probe record's limitation |
| **Re-check 2, N01:** replay when the store and the ledger are both lost; retention | ADR-0014 §3.6 fence step 3 (the epoch on every mutating request, refused when not current, attended or not; the stated residual), step 4 (the ledger's retention is ADR-0006 §7.4's, also when only the ledger is readable), step 5 (the quiet period withdrawn); H13; U2b's `no_duplicate_effect_when_store_and_ledger_are_both_lost`, `stale_epoch_is_refused_before_any_write`, `clients_carry_the_epoch_with_a_kept_request_id`, `fence_retention_follows_the_idempotency_contract` |
| **Re-check 2, N02:** the adoption crash window | ADR-0014 §3.6 "Adoption of today's layout: fence first, then publish" and §3.2 item 8 (the one-way boundary); §7.2 journey 3; U2b's `adoption_killed_at_each_step_then_older_build_then_newer_build` |
| **Re-check 2, N03:** the ledger's namespace | ADR-0014 §3.6 fence step 4 (the digest over principal, caller role, `remote_client`, operation kind and request ID; lookup by digest); U2b's `equal_request_ids_across_clients_roles_and_kinds_have_separate_fences` |
| **Where the independent check goes next** | Revision 4 is the last design round. U2b's implementation review (the plan §6.7 security review of W2) checks the restore protocol line by line against ADR-0014 §3.6, with the fault sets run natively |
