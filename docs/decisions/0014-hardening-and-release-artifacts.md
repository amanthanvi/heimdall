# ADR-0014: Hardening and release artifacts (M08)

**Status:** proposed, revision 1 · **Date:** 2026-11-22 · **Milestone:** M08 (T01–T06) · **Gate:** plan §5 M08, "all technical gate decisions recorded"; it also closes ADR-0004 §1 Q-D for the candidate.
**Decided by:** not yet. It awaits one independent design review, one scoped re-check and the orchestrator's rulings (ADR-0009 §2.8).
**Plan:** `docs/architecture/m08-plan.md`. **Probe record:** `tests/evidence/m08-probe-inventory-and-release-binary.json`.
**Affects:** R-RT-08, R-SE-05, R-SE-08, R-QU-03, R-QU-04, R-DI-01, R-DI-03, R-DI-04, R-DI-05, R-DI-07; through the exit cases also R-CR-03, R-CR-04, R-CR-06, R-RT-06 and R-AP-08.

**What this ADR does not do:** it applies no change to the public contract. Everything that would change it is in §7, as a proposal for the contract owner. It decides no authority semantics: §3.6 is an escalation.

## 1. Context

- **Plan §5 M08** asks for hostile-input hardening, a migration and update story, clean-machine artifacts, provenance, a benchmark table, a 72-hour soak, support bundles and runbooks.
- **Much of the destructive half exists** (m08-plan §1): uninstall and purge, the remote-enrollment inventory, migration backups, refusal of a corrupt or newer store, structural redaction, the release-build refusal of every test variable.
- **The constructive half does not:** no update or recovery path, no archive, no checksum, no inventory, no licence, no bundle, no release measurement.
- **Three facts bound the design:**
  - **Nothing is published** in M08, and no signing key is available to agents.
  - **A release build has no test hooks.** Its faults are applied from outside, and its static pass reads the account's real SSH configuration, so it runs only in a disposable account, container or VM.
  - **ADR-0009** limits review and testing to what is meaningful. §2.3 exists so that fuzzing cannot become the open-ended hardening M03 wave 5 was.

## 2. Hostile input: the boundary list and the stopping rule

### 2.1 Boundaries

A boundary is listed when its input can be written by someone other than the owner at their own terminal: a repository, a remote host, another account, another program, or a file the user was sent.

| # | Boundary | Entry point | Who writes the input | Existing tests | Available |
|---|---|---|---|---|---|
| 1 | OpenSSH client configuration | `sshconf::parse_file`, with `lex`, `include`, `eval` | the user's files, repositories, packages | `sshconf_hostile.rs`; `tests/model/sshconf_{parse,eval}.rs` | now |
| 2 | Git configuration edits | `sshconf::gitedit` | the user's files | `tests/model/sshconf_edit.rs`; `projection_git.rs` | now |
| 3 | Agent replies | `ipc::agent_client` (`exchange`, `parse_reply`); 256 KiB, 1024 identities | another program at the agent socket | `agent_client_frames.rs` | now |
| 4 | Control frames and requests | `ipc::frame::decode_frame`, `BoundedFrameCodec`, request deserialization; 16 KiB hello, 1 MiB after | any same-user program; a paired remote client through M06's bridge | `ipc_frames.rs` | now |
| 5 | Signing-endpoint frames | `ipc::signing` (`parse_sign_request`) | any consumer of a binding's endpoint, a forwarding peer | `agent_frames.rs` | now |
| 6 | Userauth and session-bind requests | `credential::purpose::parse_userauth`, `credential::session_bind` | a remote server, through the client | `signer_requests.rs` | now |
| 7 | The remote registry | `registry::hm1`, `registry::line`, `registry::classify` | a remote account's `authorized_keys`, editable by its administrator | `tests/model/registry_pure.rs` | now |
| 8 | The issuer protocol | `issuer::protocol` | the runtime; a program that reaches the issuer's channel | `issuer_child.rs`, `issuer_m03.rs` | now |
| 9 | Backup and recovery files | `issuer::backup`, `issuer::bundle`; 16 MiB | a file the user restores from | `issuer_ceremony.rs` | now |
| 10 | Project manifests and import bundles | `project::manifest`, `project::portable`; 1 MiB | a repository; a file the user imports | `tests/model/project_pure.rs`; `prompt_injection.rs` | now |
| 11 | Runtime configuration and the advertisement | `runtime::config`, `runtime::instance` | the user's files; a same-user program | `integration/runtime.rs` | now |
| 12 | Known-hosts files and `ssh -G` output | `localenv::known_hosts`; the `ssh -G` reader | the user's files; a hostile configuration through `ssh -G` | `sshconf_vs_ssh_g.rs` | now for the readers; the M06 route checks after M06 |
| 13 | M06's bridge and invitation records | `remote` (frames, the invitation state, the `sshd -T` verifier) | a paired client; a runner's sshd configuration | M06 U1's property and unit tests | after M06 |
| 14 | The route helper | the pre-identification buffer (8 KiB, 32 lines); allow-list and hint parsing in `transport-iroh` | a remote server or relay | M06 U5a, U6a | after M06 |
| 15 | Page tokens and selectors | M07's token decoder and selector parser | any client | M07 U3 | after M07 |

### 2.2 What is not fuzzed

- **Path operations** (symlink, replacement and FIFO races) are not byte parsers. They keep their example tests (M02 U3, M05 U4, the purge sweep) and are checked by spec §14.3's table (m08-plan §7.1).
- **Authority logic** is covered by the fixed-seed model suites under `tests/model/`. Their invariants are plan §6.3's; M08 adds none.
- **Platform FFI.** The modules that allow `unsafe` are inventoried for M09-T03's review. A Linux fuzz build does not reach Windows or macOS calls.

### 2.3 The stopping rule

For each target, on libFuzzer with its address sanitizer, an input length capped just above the boundary's own cap, a 10 s per-input timeout and a 1 GiB memory limit:

1. **Start** from the seeded corpus (the adversarial fixtures and the committed property-test regressions).
2. **Run at least 2 CPU-hours.**
3. **Stop when both hold:** no new coverage in the last 30 minutes, and no open finding.
4. **A finding** (a crash, a hang, a memory blow-up, or a parse that succeeds outside the boundary's documented bound) is minimized, fixed, and turned into a regression test on the pinned stable toolchain. The target then restarts from its saved corpus at step 2.
5. **The ceiling is 8 CPU-hours per target per candidate.** A target still finding coverage there stops anyway. Its coverage curve goes into the record as a residual, and the orchestrator decides whether it buys another round.
6. **A second fix round on one target** means the parser is simplified or bounded more tightly before it is patched again (ADR-0009 §2.1).

**Per candidate, not per commit.** Campaigns run on the W0 tree and again on the candidate. `check.sh` runs only the regressions.

### 2.4 What a finding blocks

- **Every finding on a listed boundary is fixed before the exit.** A29's pass condition is "parsers bounded", so a crash or hang on outside input fails the case itself.
- **Whether it blocks a merge, and carries a revert proof, is ADR-0009 §2.1's rule,** unchanged.

## 3. Update, drain, rollback and migration recovery

### 3.1 Terms

- **Update:** the user runs a newer archive's install script. Heimdall never updates itself (spec §15.3).
- **Rollback:** the user puts the previous binary back.
- **Restore:** the state store is replaced by one of its own backups.
- **Reset:** the state store is discarded and a new installation begins, with a new environment identity.

### 3.2 Guaranteed, and tested (m08-plan §7.2)

1. **Stopping is graceful and bounded.** `service stop` lets in-flight requests settle or reports them, removes the endpoints and leaves the journal durable. What was in flight is recovered or reported after restart, as A17 already proves.
2. **The stop preview is read-only and complete.** Before a stop, the user can see what it interrupts (§3.3). The preview changes nothing.
3. **An update never changes identity or authority records:** the environment ID, policies, cutoffs, pauses, tombstones, the authority generation, enrollments, the catalog, and the references to protected keys.
4. **A migration is transactional and backed up first** (existing). It never makes a grant more active, moves a deadline later, clears a pause, or drops a tombstone. The migration ladder test checks this from every earlier exit build's store.
5. **After an update, nothing returns that had ended.** Unexpired, unrevoked grants are served again only under the existing re-issue rule (ADR-0005 §3.7).
6. **An existing store is never read as empty.** A damaged store, a newer store and an unreadable one each stop unsafe operations with a distinct reason and a named next step. Nothing is rewritten (existing for the store; new for the commands).
7. **An older binary refuses a newer store** and touches nothing (existing).
8. **Rollback with an unchanged schema** is the previous binary serving the same store, under items 3 and 5.
9. **Restore keeps identity and ends authority,** subject to §3.6.
10. **Reset is never automatic.** It is attended, says that it creates a new identity, and first lists what it orphans: the remote enrollments and pairings read from the old store or, if that is unreadable, from the last recovery bundle.
11. **Integration that names the executable keeps working after an update in place.** The login entry, the shell hook, the route helper and the WSL helper call a fixed install path (§4.3). An executable that has moved is a doctor finding with its repair command, never a silent break and never a silent rewrite of an entry Heimdall can no longer prove is its own.
12. **Uninstall is unchanged** (ADR-0007 §5.5, ADR-0008 D4, ADR-0010): owned local integration is removed, the user's SSH and Git files are restored byte for byte, and what remains is listed.

### 3.3 Disclosed, not prevented

Stopping the runtime, for an update or otherwise, interrupts what the preview lists:

- **New connections and signatures** through Heimdall's endpoints, until the runtime starts again.
- **Working keys held only in memory.** They are gone; grants are re-issued within their unchanged terms after restart.
- **Bindings with a live holder** (`heimdall run` children): the child keeps running; its endpoint is gone until restart.
- **Owned multiplexing masters and dedicated connections:** closed, or left to the client, as M03's deadline table states for each kind. A session already authenticated keeps carrying traffic.
- **WSL bridges and container endpoints:** unavailable inside the distribution or container until restart.
- **M06's transport and runner state:** a served Iroh endpoint stops; a runner whose runtime is down issues nothing.
- **On macOS without a Developer ID signature,** the issuer may lose access to its CA key after the update (the existing M03 note). The preview says so, and says whether an offline backup is recorded.

An emergency restart that cannot wait prints the same list (spec §15.2).

### 3.4 Reported as residue, not removed silently

| Residue | Where it is reported | Removed by |
|---|---|---|
| Migration backups (`<store>.v<N>.backup*`): old state with public metadata | `state status`; the stop preview; uninstall | `uninstall --purge-state`, or the user |
| The previous binary (`heimdall.previous`) | the install script's output; uninstall | the next update, or uninstall |
| An orphaned macOS keychain item after a restore | `issuer status` (existing) | the user, in Keychain Access |
| A login entry or hook left at an old path | doctor (`executable_moved`) | the named repair command |
| Remote enrollments and M06 pairings | uninstall's inventory (existing; M06 adds pairings) | `enroll remove`, `environment remove`; never promised for an offline target |
| A Heimdall include block the owner moved to the other global Git file | the rollback's result (new; Git residual 1 of ADR-0007 §12.41) | the user |
| Conflict and quarantine copies, logs | uninstall (existing) | the user, or the purge |

### 3.5 Platform notes the tests cover

- **Windows:** a running image cannot be overwritten. The install script stops the runtime, renames the old executable aside and places the new one. A `heimdall run` child that still holds the old image keeps running on it.
- **Unix:** the replacement is an atomic rename in the install directory.
- **WSL:** the Linux helper is replaced with the Windows executable, as one step. A helper that speaks another channel version is already refused at the hello (`wsl/src/client.rs`); the update journey checks that a stale helper is reported and not used.

### 3.6 Escalated: what a restore does to authority

A backup is older than every stop, revocation, pause and cutoff made after it. Restoring it unchanged would revive them, which R-RT-07 and plan §5 M08 forbid. The options:

| Option | Effect | Cost |
|---|---|---|
| **(a) Restore identity and configuration, end authority** | Every grant in the restored store is ended and every standing policy paused, in the restore's own transaction, with an event. The user approves again. Remote effects are reconciled from M06's runner report | One round of re-approval after a restore |
| (b) Restore unchanged | Fast | Revives revoked and stopped access. Rejected by this ADR |
| (c) No restore; reset only | Simple | Loses the environment identity and orphans every enrollment |
| (d) Replay later tombstones onto the backup | Keeps live grants | Needs a second durable log outside the store; a new mechanism for a rare path |

**Recommendation: (a).** This is authority semantics, so the contract owner rules it (m08-plan Q1). U2b does not build restore until then.

## 4. Artifacts, provenance, inventory and licences

### 4.1 Targets

The matrix is m08-plan §4: macOS arm64, Linux x86-64 and arm64, Windows x86-64, with WSL2 served by the Linux binary and the Windows archive. One feature set per target, recorded in the build record.

### 4.2 The archive

One archive per target, named `heimdall-<version>-<target>`:

- the executable (and, in the Windows archive, the Linux x86-64 executable as the WSL helper);
- the install script for that platform;
- `LICENSE`, `THIRD-PARTY-NOTICES.txt`, `SECURITY.md`;
- `BUILD-RECORD.json`, the SBOM, `SHA256SUMS`;
- the release notes with the limitation statement, and the install, update, recovery, unenrollment and uninstall runbooks;
- `examples/` (M07's reference wrapper and harnesses) and `skills/heimdall/` (the optional skill, installed only by the user);
- the public schemas and example payloads.

**Not in it:** test binaries, fixtures, anything from `heimdall-testkit`'s data, debug symbols, build-host paths.

### 4.3 Installation

- **A fixed per-user location** on each platform, the same across versions, so nothing that names the executable changes on update.
- **No elevation, no service installation, no edit of `PATH`, shell profiles or `~/.ssh`.** The script prints the line a user may add to their `PATH`. Everything else is `heimdall setup`, attended, as today.
- **The script verifies `SHA256SUMS` before it copies anything.**
- **An update** keeps the old executable as `heimdall.previous` and shows the stop preview first.

### 4.4 Checksums and the build record

- **`SHA256SUMS`** covers every archive and every file inside one.
- **`BUILD-RECORD.json`** states: the commit and whether the tree was clean; the toolchain, target, profile, feature set and flags; the `Cargo.lock` digest; the builder's operating system; every packaging tool with its pinned version; the times; each output's digest.
- **The binary reports the same commit, target and feature set about itself,** and the artifact check compares them.
- **Build-host paths are remapped,** and the artifact check fails on a home path, a user name or a checkout path (the probe found 297 on the unremapped macOS build).
- **The digests and the record are committed to the repository.** The archives are not uploaded.

### 4.5 The dependency inventory

- **Format:** CycloneDX JSON, one per target.
- **Source:** the resolved dependency graph for that target and feature set, not the lock file (the probe: a lock-file scan lists 322 components for every target and no licences).
- **Scope:** every crate reached through normal and build edges, with its version, source, checksum and licence expression; the bundled SQLite; vendored code under `third_party/`.
- **Test support:** the crates that reach the graph only through `heimdall-testkit` are listed with the property `built, not referenced by a release build`. They are not dropped: a scanner reading the build graph will see them, and the record should agree with it.
- **Advisories** stay with M06's audit gate. The candidate's record states the advisory database's date and every ignored advisory with its reason.

### 4.6 The licence policy

- **Allowed for linked code:** MIT, Apache-2.0 (with or without the LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0, BSL-1.0, Unlicense, CC0-1.0. Where a crate offers a choice, a permitted alternative is selected and recorded.
- **Where the list comes from:** every licence the probe found on `main`, plus ISC and CC0-1.0. M06's tree (iroh and its TLS stack) was not inventoried; U4a runs the policy on it, and any licence it needs beyond this list is a recorded decision, not a silent addition.
- **Refused without a recorded decision:** any copyleft licence, any licence with a field-of-use or network clause, a crate with no licence, a git or path source outside `third_party/`.
- **Enforced** by one pinned tool, on licences, sources and bans.
- **Notices:** every linked crate's licence text, generated from the same graph. A missing text fails the build.
- **The project's own licence is the owner's decision** (ADR-0001 §8). M08 supplies the compatibility table; it does not choose.
- **Third-party documentation snapshots:** proprietary vendor text is replaced by its hash and archive URL before the candidate (ADR-0004 §4, E8).

### 4.7 Signatures and the reporting route

| Row | Produced only if | Otherwise the release says |
|---|---|---|
| macOS Developer ID and notarization | the owner's Apple Developer membership | "ad-hoc signed; not notarized", with the update limitation |
| Windows Authenticode | an owner-supplied certificate | "unsigned" |
| A signature over `SHA256SUMS` | an owner signing key, used by the owner | "checksums are recorded in the repository history; no signature" |

- **`SECURITY.md`** names one private reporting route, chosen by the owner, and says plainly what is not promised: no monitored inbox, no response time, no advisories service, unless the owner sets one up (plan §10.4).

### 4.8 What a release may say

- "Signed", "notarized", "reproducible" and "clean-machine tested" appear only for a row where that was produced and checked, with the record's name.
- A fresh account on a developer machine is called that, not a clean machine.
- Without closed distribution and provenance rows, the release is `preview-only` (ADR-0004 §1 Q-D).

## 5. Support bundles and privacy defaults

### 5.1 The bundle

- **Opt-in.** A bundle exists only when the user runs the bundle command. Nothing collects one in the background, and nothing sends one anywhere: the output is a local file.
- **Previewable.** The preview shows the manifest and the exact content of every file. The bundle written is byte-identical to what was previewed.
- **Plain text.** UTF-8 text and JSON files with a manifest listing each file's digest and redaction counts. No binary blob, so the user can read all of it. At most 8 MiB.
- **An allow-list, not a filter.** The collector takes typed inputs and writes named fields. A field not on the list is not collected:
  - the version, commit, target and feature set; the platform and the SSH client's version and provenance;
  - doctor's findings; the capability and claims table; setup and projection status with provenance;
  - configuration **keys**, and the values of the non-identifying settings (durations, limits, booleans);
  - the store's schema version, integrity result and row **counts**;
  - the last operations as code, state, effect status and times;
  - the log's tail, redacted again on the way in.
- **Never collected:** private or public key material, certificates, the state database, backups, known-hosts content, the body of any SSH or Git configuration outside Heimdall's own managed block, environment variables, process arguments, shell history, session content.
- **Identifiers are pseudonymized by default.** User names, host names, aliases, paths, fingerprints and Heimdall's own IDs become stable placeholders within one bundle (`host-1`, `user-1`). Keeping the real ones is a separate, explicit flag, shown in the preview.
- **It works when Heimdall is broken:** with the runtime down, and with a store that will not open (it then reports the integrity result and nothing from inside).
- **Redaction is tested with canaries in every input,** and does not rely on a prefix list (spec §13.6): the structural redactor (`telemetry::redact`) covers free text, and the allow-list covers everything else.

### 5.2 Privacy defaults

After a default install, setup and first use:

- **No telemetry.** There is no code path that reports usage; the audit proves the absence by running with no network, and by a capture that shows no packet leaving loopback.
- **No listening TCP or UDP socket.** Local control is Unix sockets and named pipes with the existing owner checks.
- **No transcript.** The store and the logs hold no command, output or keystroke of a session.
- **No public exposure.** The transport is off until the user enables it (M06), and its widening rules are M06's.
- **No extension loading.** Nothing installs or loads a plug-in, a helper or a skill. The skill in the archive is a file the user may copy.
- **No self-update and no version check over the network.**
- **Local history** is kept seven days by default (existing), bounded logs at two 8 MiB generations (existing). Deleting history never deletes a cutoff, a pause or a tombstone.

Each line is a row of `defaults_audit` (m08-plan §7.3).

## 6. Benchmark and soak acceptance

### 6.1 Benchmarks

Spec §15.1's table is the bar, unchanged, on the candidate archive, with the method of m08-plan §6.1:

| Metric | Target | Measured as |
|---|---|---|
| Warm status or inspect, 100 destinations | P95 ≤ 100 ms | one open control session, ≥ 200 requests after 20 warm-ups |
| Warm already-authorized ensure | P95 ≤ 250 ms | the same |
| First useful TUI frame | P95 ≤ 750 ms from launch | spawn to the first complete frame, ≥ 50 launches |
| Key handling under background work | P95 ≤ 100 ms | completed frame for the key, with real slow work in progress |
| Idle CPU | < 0.5 % of one core | three 5-minute samples after 10 minutes of settling |
| Idle memory | ≤ 150 MiB | resident set (Linux), physical footprint (macOS), private working set (Windows) |
| Idle polling | none unrequested | zero requests seen by the fixture sshd and the agent proxy in the idle samples |

- **A row passes** when every measured platform meets it.
- **A row that misses** gets a measured analysis and either a fix or a revised budget recorded by the orchestrator as an amendment here. The benchmark worker never revises a budget, and a miss never removes a security check (spec §15.1).
- **A platform that could not be measured** is `blocked` on its named input; no other platform's number stands in for it.

### 6.2 The soak

The run of m08-plan §6.2 passes when all of these hold:

1. **Duration:** 72 hours of running time. Every gap is listed; gaps above an hour in total extend the run.
2. **Memory (lane S):** the median of the final 6 hours is at most the median of hours 6–12 plus 10 % plus 4 MiB; the least-squares slope over hours 12–72 is at most 0.1 MiB per hour; the maximum is at most 150 MiB.
3. **Descriptors and threads (lane S):** the final 6 hours' maximum is at most the maximum of hours 6–12 plus 4 descriptors and plus 2 threads.
4. **Persistent state,** with retention set to 1 hour for events and 24 hours for operations: the database with its write-ahead log at 72 hours is at most 1.25 times its size at 48 hours; the log directory is at most 17 MiB; the file count under the home at 72 hours is at most the count at 24 hours plus 8. One more home runs the default retention and reports its growth per day, for the limitation statement.
5. **Retries:** during every dependency outage, no two attempts toward the dependency that no caller asked for are less than 1 s apart, there are at most 12 such attempts in any 5 minutes, and the runtime's CPU over the outage is under 2 % of one core. After the dependency returns, the next request succeeds without a restart.
6. **Authority:** zero successful fixture logins through Heimdall-held material after a grant's deadline, stop or revocation; zero grants whose scope or deadline exceeds the harness's ledger; zero pauses cleared by a restart; the environment ID identical at the start and the end of every lane, across every kill, update and rollback.
7. **Recovery (lane L):** after every stop and kill the next request is served within 30 s; no endpoint, signer, issuer child or bridge from the previous instance is alive 60 s later; an operation in flight at a kill is reported with an honest effect status; the full-volume fault is refused cleanly and leaves a store that passes its integrity check.
8. **Cleanliness:** zero panics, zero `INTERNAL_ERROR`, zero canary strings in any log, output or sample.

### 6.3 Early stop

The harness ends the run as failed at once on: any failure of item 6 or 8; resident memory above 300 MiB; more than 1024 descriptors; disk use above its budget; a heartbeat missing for 10 minutes.

### 6.4 What the soak does not claim

- **It runs on declared hardware, stated in the record.** A run in a container on the Mac is Linux arm64 in a virtual machine and is recorded as that.
- **Lanes on a debug build are mechanism evidence** (ADR-0008 D12 item 3).
- **It injects no clock change, no sleep and no reboot.** Those are A08's rows, on their own platforms.

## 7. Proposed contract deltas (for the contract owner; none applied)

| # | Delta | Kind | Why |
|---|---|---|---|
| H1 | `heimdall support bundle [--preview] --out <file> [--include-identifiers]`; schema `heimdall-support-bundle/1` for the manifest | new command and schema | §5.1; R-SE-08 |
| H2 | `heimdall service stop --preview`: a read-only list of what stopping interrupts; a schema for it | new flag and schema | §3.2 item 2; R-DI-03 |
| H3 | `heimdall state status`, `heimdall state restore --backup <file>`, `heimdall state reset`: attended, each with a typed confirmation | new commands | §3.2 items 6, 9, 10; R-RT-08. `restore`'s semantics wait on §3.6 |
| H4 | Reasons under `STATE_UNAVAILABLE`: `state_corrupt`, `state_newer_than_build`; an event and a reason for `state_restored_authority_ended` | new reasons | Today both read as one message with no next step |
| H5 | A doctor finding `executable_moved`, with its repair command | new finding | §3.2 item 11 |
| H6 | Residue kinds: `migration_backup`, `previous_binary`, `git_block_moved` | new enum values | §3.4; R-DI-04 |
| H7 | Build provenance in the version output and `inspect capabilities`: commit, target, profile, feature set | new fields | §4.4; "release claims match the shipped builds" |
| H8 | The candidate's version string, replacing `0.1.0-m01` | value | It is carried in the hello |
| H9 | A store migration recording a restore and its time | migration | H3, if §3.6 (a) is ruled |

**Proposed text changes outside ADR-0006:**
- **ADR-0002 §9:** Linux artifacts are dynamic against a glibc 2.31 floor, not static musl (m08-plan Q4).
- **Spec §15.1:** none. The budgets stand until a measurement says otherwise.
- **Spec §13.6:** none. The seven-day default stands; a storage bound is proposed only if §6.2 item 4's default-retention report asks for one.

## 8. Alternatives considered and rejected

| Alternative | Why not |
|---|---|
| Fuzz with property tests only | Already done; the earlier milestones deferred coverage-guided fuzzing to M08 for the parsers that take outside input |
| Fuzz continuously in `check.sh` | Minutes per commit for no finding; the regressions carry the value |
| Move the workspace to a nightly toolchain for fuzzing | The toolchain pin is a recorded decision; the container keeps the nightly out of the product |
| A self-updater | Spec §15.3 forbids hidden self-update; an updater is a privileged, signed, network-facing component the project does not need |
| Native packages now | Each is a publishing channel; nothing is published in M08 |
| An SBOM from the lock file | Wrong per target, includes test crates, carries no licences (probe) |
| Dropping test-support crates from the inventory | The record would disagree with any scanner reading the build graph |
| A blocklist redactor for the bundle | Spec §13.6 rules it out; the allow-list makes the default "not collected" |
| Uploading bundles | No service exists, and none is promised |
| The soak on the Windows PC, the devbox or the VPS | m08-plan §6.2's table |
| A soak on a debug build with injected faults only | The leak and retry claims are about the shipped build |
| Restoring a backup unchanged | §3.6 (b) |

## 9. Consequences

- **The release's weakest rows are named in advance:** unsigned Windows and Linux artifacts, an ad-hoc macOS build with the update limitation, and Windows and macOS release rows that need a disposable account each.
- **A restore costs the user one round of approvals,** if §3.6 (a) is ruled.
- **Two toolchains exist in the project,** one of them only inside a fuzz container.
- **The inventory names crates that are built and not linked.** The alternative is a later change to how the release binary is built (m08-plan Q8).
- **Migration consequences:** H9 is the only schema change proposed. No existing record changes meaning.

## 10. Reopen conditions

- A fuzz target reaches its ceiling still finding coverage on two successive candidates.
- A benchmark row misses on a measured platform.
- The soak fails item 2, 3 or 4 with a cause that is a designed cache or log rather than a leak.
- The owner supplies a signing key, a Developer ID or a publishing channel: §4.7 and m08-plan §10 are then revised.
- The contract owner rules §3.6 other than (a).
- M06's exit changes the transport's V1 scope, and with it the feature set and the inventory.
