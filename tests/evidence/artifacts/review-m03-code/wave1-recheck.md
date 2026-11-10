# Heimdall M03 wave-1 independent re-check

Reviewer: Codex (gpt-6.1-sol, independent), the re-check of `52729afb..5b36b3d8` (the fixes for W1-R01 to W1-R03), run in its own scratch checkout. Saved by the orchestrator with paths redacted. Rulings: ADR-0008 §17.18 item 5.

**Verdict: merge.** W1-R01, W1-R02 and W1-R03 are resolved in the committed change `52729afb..5b36b3d8`. No blocking new defect was identified. One low-severity test-oracle weakness is recorded below. This verdict applies to this fix diff, not to M03 exit readiness or native custody/lock claims.

Reviewed source exclusively through Git objects in the requested repository. Tests ran in a detached scratch checkout of `5b36b3d8`, with its own target directory. The earlier report was read only after independently inspecting the fixes and their counter-scenarios. Its requested path is absent from the reviewed commit, so that report alone was read from the supplied working-tree path. No working-tree source was used as review evidence. No repository files, commits, remotes, owner keys, owner agents, SSH configuration, Git configuration, login keychain or 1Password were changed or used as test targets. No nested delegation was performed.

## Original findings

### W1-R01 — resolved

Evidence: `crates/issuer/src/store/attributes.rs:116-138,159-218,221-240`; `store/linux.rs:154-175,195-235,245-255`; `ceremony.rs:744-758` (line numbers throughout refer to `5b36b3d8`). Static inspection plus one executed regression.

Linux delegates put/get/delete/list to AttributeStore. Every fingerprint search carries application, fingerprint and environment; inventory carries application and environment. Returned fingerprints/environments are checked again. Reading and deleting re-search with the scope and require the exact object path. Thus A's same-fingerprint item neither prevents B creating an item nor makes B's read Corrupt, and B cannot delete A's locator. Adoption requires exactly one scoped candidate of the correct store kind; duplicate own-environment candidates refuse rather than selecting arbitrarily.

The executed `two_installations_restore_and_retire_on_a_shared_attribute_store` exercises B restoring while A holds the key, B restoring again, exact adoption, retirement, A's surviving read, and attempted cross-environment deletion. It passed. This exercises the production scoping logic with an in-memory backend; it does not verify Linux D-Bus interoperability.

Counter-scenarios:

- **Missing environment attribute:** ignored by all own-item searches/inventory. Get returns NotFound, and deletion of that unscoped locator refuses. Restoring a backup creates a scoped item instead of guessing ownership. This can leave an unscoped orphan invisible to this installation's inventory; it does not adopt/delete another installation's item. The baseline Linux put already wrote the environment attribute, so this is not an incompatibility for an item normally created by the baseline implementation. No executable missing-attribute regression was added or run in this review.
- **Pre-existing normal Linux item:** retains the same application, fingerprint and environment attributes and object path, so lookup and adoption continue to work. A baseline restore that incorrectly recorded another environment's locator now refuses deletion of it; repairing that stale record is preferable to deleting the other installation's key.
- **Windows DPAPI:** `store/windows.rs:49-57` now returns a distinct default directory for each environment. EnvironmentId is a typed identifier, not arbitrary path input. The signature change has no committed caller to update (`git grep` found only the definition/documentation). Exact-locator deletion remains constrained to that store's computed blob path.
- **Old Windows default-path blob:** a blob directly under the old issuer directory is not discovered by the new default subdirectory; there is no migration. An explicit `in_dir(old_directory, env)` still addresses it. This is a concrete compatibility limit, not evidence of automatic migration. Because no product caller of default_dir exists yet in either reviewed tree, I do not treat it as an introduced, reachable product upgrade failure in this wave. Before U10 wires it, decide how any pre-release blobs are handled without deleting or claiming unproven ownership.
- **Windows explicit directory constructor:** `in_dir` still trusts its caller to supply an installation-specific directory; its environment field does not independently namespace paths or validate the DPAPI description on read. Passing one directory to two different environments can still share a blob. That behavior predates this diff; the new default helper avoids it only when the caller actually uses the helper. No native Windows isolation claim is closed here.

### W1-R02 — resolved

Evidence: `crates/issuer/src/store/macos.rs:318-326`; `ceremony.rs:744-758`; new shared-disposable-keychain test at `tests/integration/issuer_store.rs:2156-2174`. Static inspection; native keychain test deliberately not executed.

macOS list now retains only the store's own environment account, matching the service/account identity already used by put, get and delete. With A and B holding the same fingerprint, B's repeat restore can select only B's item. The helper refuses zero or multiple matching candidates. A missing account is skipped; another account is excluded; a pre-existing normal B item already has B's account and remains adoptable. A stale previously recorded A locator still fails B's exact-locator deletion rather than deleting A. The added regression invokes the real restore/adoption branch rather than passing put's result directly to retirement.

The macOS regression's preservation guards read owner SSH/Git/keychain state, so running it would violate this review packet even though its actual store target is disposable. I did not run it.

### W1-R03 — resolved

Evidence: `crates/runtime/src/session_lock/mod.rs:127-149,232-255,348-356`; `tests/integration/session_lock.rs:403-465`. Static inspection plus ordinary session-source integration execution; no real lock procedure.

Only entry into Locked increments locked_entries and sets last_locked. Unknown still advances the security epoch, preserving fail-closed revocation, but cannot satisfy locked_since. The native test requires a larger locked count than its initial unlocked snapshot and an advanced, observed epoch. A subsequent unlock cannot erase the count. Consequently an Unlocked→Unknown trace alone now fails this row.

Repeated identical Locked readings do not double-count because record short-circuits unchanged states. Locked→Unknown→Locked does count two entries, although there may have been only one physical lock; these are explicitly state-entry counters, not a count of physical lock actions. The native test needs existence of a real Locked reading, so that distinction does not create the old false pass. The new code does not change which readings the platform sources deliver, nor their existing polling limitations. A lock entirely between polls can remain unseen; this is not introduced by the counter change. The focused unit regression for Unknown is present but was not separately executed (the permitted commands were integration-target Cargo tests).

## New findings

### W1-C01 — Low: an externally supplied CLI chooses its own expected build profile

**Location:** `tests/e2e/cli_m03.rs:319-325` (downstream branch at `:339-343`). **Evidence: inferred from test control flow; no mutant executed. Nonblocking.**

When HEIMDALL_E2E_BIN is set, debug_build is inferred from the same refusal message being tested, and its agreement with an independently known build profile is not checked. A release binary accidentally behaving like a debug binary can return the debug relative-path error, select debug_build=true, then return the debug wave-0 answer for an absolute path and pass. Conversely a staged debug CLI that always refuses as release can select the other branch. The test still checks exit status, variable diagnostics and absence of runtime writes; those assertions are not vacuous. Its profile-specific assertion is self-selecting for staged binaries.

Use independently supplied profile provenance for staged binaries, or explicitly limit this test's claim to the shared validation behavior. The existing `tools/validation/release-gate.sh` separately builds the release CLI and probes its gates; this change does not remove that independent check. That is why this finding does not block merging the three requested fixes. The release gate was inspected, not executed in this review.

## Other changes and vacuity checks

- **PerSourcePenalties:** the fixture first tries the option, retries without it only after a failed sshd -t naming the option, then still requires successful validation. No authentication assertion is skipped. On older sshd there is no such penalty feature to disable. No bypass of the actual verification test was found.
- **GSSAPI:** the changed test first requires GssapiPinRequired when the effective config lists the extension, then regenerates with its disabling pin and requires the full effective-config check to succeed. The targeted test passed on this host. The extension-specific branch was not independently shown to execute here.
- **Decoy IdentityFile:** certificate acceptance, signature counts, purpose parsing and session-bind assertions remain real assertions against a fixture server/agent. Replacing K_env's own public identity file with an unrelated public key narrows what these tests prove: their success no longer proves that the proposed managed-alias identity-file shape works on old OpenSSH. The new observation test deliberately asserts only its decoy control; its two managed-shape cases can both fail authentication and the test can still pass. This is explicitly disclosed in the committed INT-Q10 escalation and the observation test's documentation. Treat those cases as observations, never as a compatibility gate; U2/U8 compatibility remains unresolved. I did not find a changed production identity-selection path concealed by this diff, since those integrations are later-wave work. The 17-test credential suite passed here, but captured successful-test observation text was not emitted by Cargo and I do not claim observed outcomes for those individual cases.
- **Shell comparison:** version equality was removed, but the live, empty-group and invalid-syntax status triples are still compared exactly, and injected-disagreement fence assertions remain. This accepts different package versions with the same measured behavior, not different triples. The separate invalid-with-double-dash reading remains observational as before. No native shell rows were executed here.
- **Staging and Windows test paths:** model/architecture inputs are added to the explicit staging list and its self-check expected count; the endpoint and nonexistent-client fixtures now use platform-correct forms. No removed assertion or newly skipped check was identified there.
- **Debug trace dump:** the enabling method is cfg(debug_assertions), the field is private, and all constructors initialize it to None. In the committed release profile, no safe reachable path sets it, so the retained write branch cannot be enabled by an environment variable or ordinary caller. The observation helper supplies a recorded parser label only to a separate test verifier; its result is discarded, then the ordinary verifier still rejects the actual unrecorded version and the test fails. It cannot turn that test into successful verification. Raw traces are stored only under the fixture's private scratch root and removed; stdout from the remote measurement is not dumped. Normal SSH -v traces expose public fingerprints and paths, not private key bytes/passphrases. However this API is a raw stderr sink, not a general secret sanitizer: arbitrary banners/client diagnostics containing sensitive text would be written verbatim, and the test printer's marker filter plus scratch/user replacement is not a canary filter. No such secret source or actual leak was found in the committed controlled fixture path. Do not repurpose it for live accounts or treat it as a safe support-log exporter.

## Commands and validation

All Cargo commands below ran in `<scratch>/wt` at the pinned commit, using its Rust toolchain. No source edits or mutation tests were performed.

| Command | Exit | Result |
|---|---:|---|
| `git worktree add --detach <scratch>/wt 5b36b3d8` | 0 | Detached checkout created |
| `cargo test -p heimdall-issuer --test integration_issuer_store --locked two_installations_restore_and_retire_on_a_shared_attribute_store -- --exact` | 0 | 1 passed, 28 filtered |
| `cargo test -p heimdall-runtime --test integration_session_lock --locked` | 0 | 4 passed, 1 ignored (real lock) |
| `cargo test -p heimdall-enroll --test integration_enroll_verify --locked effective_config_has_every_trust_pin -- --exact` | 0 | 1 passed, 51 filtered |
| `cargo test -p heimdall-credential --test integration_credential_cert --locked` | 0 | 17 passed |
| `git diff --check 52729afb 5b36b3d8` | 0 | No whitespace errors |
| `du -sh target` | 0 | Scratch target was 2.3G before removal |
| guarded `du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist` via Bash nullglob array | 0 | No matching prototype build outputs; avoided bare du fallback |
| `git worktree remove --force <scratch>/wt` | 0 | Checkout and build outputs removed |
| `rm -rf <scratch>` | not executed | Tool policy rejected rm -f style commands; no process exit code |
| `rmdir <scratch>` | 0 | Empty parent removed safely |
| `test ! -e <scratch>` | 0 | Scratch cleanup verified |

Total executed tests: **23 passed, 0 failed, 1 ignored**, with filters as listed. No native lock claim is established by that result.

Read-only inspection commands: `git diff --stat 52729afb 5b36b3d8`; path-limited `git diff 52729afb 5b36b3d8 -- ...` for all 20 changed paths, grouped by issuer, runtime, enroll/localenv, native/e2e and integration tests; `git show 5b36b3d8:<path>` with `nl`, `sed`, `tail` or `rg` selections for the cited source, tests, Cargo manifests, ADR-0008, m03-plan, testkit home isolation and release-gate script; `git grep -n` for default_dir, Windows store callers, locked_since, trace_dump, release-gate and external-binary references. These completed with exit 0 except (1) `git show 5b36b3d8:tests/evidence/artifacts/review-m03-code/wave1.md`, exit 128 (report absent from commit), and (2) the combined Cargo release-profile / credential-test owner-resource search, exit 1 from the second rg having no matches. The report was then read with `cat tests/evidence/artifacts/review-m03-code/wave1.md`, exit 0. Initial `pwd`, home AGENTS.md and code-review skill reads returned 0; the targeted memory search had no Heimdall hits and supplied no review evidence. Report creation and final report/cleanup checks are separate artifact-only actions.

## Not checked and risks

No full workspace tests, clippy, release compilation, release-gate execution, external-binary E2E execution or mutation probes. No real screen lock, signal-loss injection or Unknown/Locked counter execution beyond ordinary integration tests. No native Linux Secret Service/logind, Windows DPAPI/WTS, WSL, shell-family matrix, Docker or native-harness staging execution. No macOS keychain test, because its guards would read forbidden owner resources. No dynamic legacy-item migration, missing-environment-attribute probe, arbitrary-stderr secret injection or general dependency/security audit. Native platform and custody claims remain unverified by this report.

Only durable file created: `<report>`. The scratch checkout and its 2.3G target were removed. The remaining practical limits are staged-binary profile provenance, old DPAPI-path handling before U10 wiring, caller discipline for Windows in_dir, and the explicitly unresolved old-client managed-identity shape; none is represented here as verified compatibility.
