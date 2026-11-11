# M03 wave-2 independent security review

Reviewer: Codex (gpt-6.1-sol, independent), the plan §6.7 security review of the signer, issuer and projection boundaries in `961c6201..0478f6cd` (M03 wave 2), in its own scratch checkout. Saved by the orchestrator with paths redacted. Rulings: ADR-0008 §17.19.

**Verdict: fix first.** One confirmed security-boundary defect: W2-S01 allows a managed userauth signature to be released after a clock rollback that the time gate considers uncertain.

Reviewed immutable head `0478f6cd28cf9e44db9b76494d81489975f311c4` against `961c6201a3638c2bed5dba372c710a91c97774bb` (the requested `m03/wave2` change). Review date: 2026-11-10. Execution host: macOS; Rust and Cargo 1.99.1. The detached checkout was created at the requested path and removed after review. No tracked repository files were edited, committed or pushed. The sole retained deliverable is this report.

This is the plan §6.7 review of signer/issuer boundaries and their projection/launch consumers. General correctness is a separate review. Normative references were ADR-0008 D1–D3, D10 and the applicable §17 rulings, ADR-0005 custody/certificate/issuance rules, and spec §§5, 7.2–7.3 and 8. The threat model is the supplied boundary model: untrusted agent requests and issuer frames, racing narrowing/time changes, untrusted rendered values and consumer arguments, with the disclosed same-user-process limitation. A compromised OS account or a writer of the state database is not treated as an isolation boundary this design promises to defeat.

## Findings

### W2-S01 — Medium: the default signer time path blesses a clock reading the gate never assessed

**Location:** `crates/app/src/operations/authorize.rs:164–178`, especially line 175; activated by `crates/app/src/operations/narrowing.rs:293–296` and the implemented `crates/app/src/timegate.rs:520–528`. Downstream release check: `authorize.rs:99–108`; signer admission/signing: `crates/credential/src/signer.rs:403–436`.

**Guarantee broken:** ADR-0008 D2 item 3 requires time Safe for the fresh admission under the signing gate; item 3a requires the release-time assessment to remain Safe. The accepted time observation must be the one used to admit and establish the release reference. The signing gate and the permit's paired expiry computation do not repair a falsely accepted time anchor.

**What happens:** the ReadOnly branch awaits `assess_read_only()`, receives only a `TimeStatus`, then independently calls `clock.observe()` to construct `SafeNow`. A clock change between these observations is never assessed against the persisted runtime anchor/high-water mark. `AdmittedTime` subsequently checks drift relative to this second, unassessed observation, so it can accept the new clock value as its baseline.

**Concrete failure scenario, observed in a disposable probe:**

1. Prepare a valid active grant and installed certificate using the existing test world, real `Operations`, `ManagedSigner`, vault and enqueue path.
2. Let the unlocked precheck pass.
3. Under the shared signing gate, take the paired expiry observation and the read-only time assessment at the original time.
4. Immediately after that assessment's observation, roll the test wall clock back one hour, leaving the continuous clock and boot unchanged.
5. The second observation at line 175 captures the rolled-back time and is labeled Safe without assessment.
6. The real signer signs and `enqueue_signed` releases an `SSH_AGENT_SIGN_RESPONSE`. An independent fresh `assess_read_only` on the resulting clock is not Safe.
7. A control using `AuthorizationTime::Peek` with the same clock transition refuses the release.

The final two-case probe exited 0 because it explicitly asserted the unwanted release in ReadOnly mode and the refusal in the Peek control. This is a reproduction of the defect, not a passing security acceptance test. No production source was modified; only a copied fixture clock in the review's temporary probe was instrumented. The reproduction patch is preserved below.

**Impact and limits:** a userauth operation can obtain a signature during a clock-confidence failure where policy requires refusal. This does not establish a general deadline extension, arbitrary-purpose signing, private-key exposure or a revocation bypass. It is a short race involving an actual clock transition, hence Medium severity. This commit makes it relevant by implementing the previously fail-closed ReadOnly assessment, selecting it by default, and providing the real signer path.

**Required correction:** keep the assessed `TimeAnchor` and verdict together through admission; preferably use `TimeGate::assess_read_only_in` inside the fresh authorization transaction and construct `SafeNow` from that returned observation. Do not manufacture SafeNow from a later unassessed `clock.observe()`. Add the rollback interleaving as a regression through the real enqueue/release path.

No other independently reachable security failure was confirmed in this review. The incomplete verification/consumer wiring described below remains a concrete limit, not evidence that the enabled end-to-end feature has been verified.

## Guarantee-by-guarantee assessment

### 1. Signer

| Guarantee | Held? / status | Evidence and limits |
| --- | --- | --- |
| Signs only SSH userauth | Held for the reviewed path; verified | `purpose.rs:202–268, 417–455` bounds and parses the complete request, requires message 50, service ssh-connection, supported publickey method, TRUE, matching certificate algorithm, zero Ed25519 flags, and no trailing bytes. `signer.rs:332–340` calls it before authorization. Seven adversarial parser cases and 17 credential/certificate tests passed, including SSHSIG, malformed lengths, wrong account/algorithm and plain-key refusal. |
| Signed data carries the grant certificate and its pair account; no plain K_env | Held; verified | `signer.rs:337–340` additionally equates the agent-request blob and signed-data blob for grants. `purpose::check` uses exact installed certificate bytes and its account. `table.rs:888–916` resolves only certificates on grant endpoints. Real-client logins and grant-isolation tests passed. |
| Fresh gated admission with expiring permit and Safe time | **Not held; implemented_unverified**, W2-S01 | Shared-gate acquisition, fresh grant/slot reads, pending checks and bounded permits exist (`authorize.rs:288–351`), but the ReadOnly time verdict is attached to a different observation. The probe observed release under uncertain time. |
| Revocation linearized against signing | Held at the specified **enqueue** linearization point; verified | Shared guard survives signing into IPC; `ipc/src/signing.rs:625–666` reserves capacity, checks expiry/pending/time, enqueues without awaiting, then drops the guard. Existing deterministic tests covered precheck/revoke, under-gate revoke, acknowledged revocation, blocked enqueue, pending marks, cascades and concurrent interleavings. No post-ack enqueue was observed. Bytes already enqueued before acknowledgement can be drained by the socket writer later; ADR-0008 explicitly defines enqueue, not eventual peer receipt, as the effect. |
| Owner-only endpoints | macOS Unix paths held; verified. Native Windows and cross-account checks blocked | `endpoints.rs:359–430` reuses M01 listeners and peer checks. `ipc/src/unix.rs:107–175, 315–347` verifies directory owner/mode and inode, binds socket 0600, and authenticates peer UID. The native macOS endpoint-mode test passed. Windows source uses protected owner-only DACL, first-instance creation, remote-client rejection and client SID checks; no Windows execution was performed. The macOS cross-account test was ignored with exact missing platform/prerequisite: B3, a disposable second macOS account. |
| One endpoint never signs for another grant | Held for admitted requests; verified | `table.rs:903–916` resolves by environment materialized pair/binding mapping; the fresh authority read checks that the store still serves this grant and held slot (`authorize.rs:202–237`). Binding/grant isolation and held-slot tests passed. This is endpoint behavior within the disclosed same-user boundary, not protection against the owner accessing another same-user endpoint. |
| Verification endpoint signs only its operation's verification certificates | Currently fail-closed; enabled production behavior blocked | Resolution uses only that operation's separately generated K_verify and current certificate (`table.rs:917–940`), and purpose requires the current positive certificate (`signer.rs:333–355`). The fixture-authority test rejects grant certificates, plain signed-data keys, stale positive certificates, wrong accounts and the negative certificate. **Production Operations refuses every Verification subject** (`authorize.rs:292–295, 358–359`), observed by its test. Thus no production verification signature is currently released. Full positive-path authorization is unfinished. In particular `install_verification` checks signature against the certificate's own CA, subject, shape and validity, but has no plan CA/pair input; it cannot yet enforce the operation's planned CA/pair. That must be resolved before enabling verification signing. |

Session-bind checks were also traced: `session_bind.rs:82–148` uses established decoders and host-signature verification; `signer.rs:461–485` poisons a failed bind and retains forwarding status; bound requests must match session/host key and forwarding capability. Existing host-key/forwarding tests passed. No destination restriction is inferred from session-bind.

### 2. Issuer child and client

| Guarantee | Held? / status | Evidence and limits |
| --- | --- | --- |
| K_ca never crosses the child protocol boundary | Held in the reviewed issuance path; source-backed, verified protocol behavior | `child.rs:171–230` loads keys into CaSet and emits certificates, not private bytes. The client only sends reservation references/public subject keys and receives certificates/status. `ca.rs:27–31, 139–195` holds SecretCaKey locally. Ceremony/store operations are separate authorized custody paths, not an assertion that K_ca exists only in a child throughout its complete lifecycle. No product keychain/store was used in this review. |
| Zeroized on EOF/shutdown | Drop/clear path held by source; process exit behavior verified | `child.rs:326–328, 333–345` clears CaSet on all normal serve returns; `ca.rs:129–136` drops keys; SecretCaKey uses ssh-key private-key drop semantics. EOF and shutdown tests passed and emitted no extra response. This is not a forensic proof that every compiler/library temporary or terminated-process page was physically overwritten. SIGKILL/abort cannot run Rust destructors. |
| Refuses a TTY stdin | Held; verified | `child.rs:301–303` checks it before opening the child DB/loading a key; disposable-PTY test passed. The CLI also dispatches terminal stdin to the usage refusal. |
| Signs only a reservation accepted by a read-only snapshot check | Held for the store-backed predicate; verified | `check.rs:182–205` reads reserved state, ceilings, current verification CA state, and the assessed time plus issuance predicate in one transaction. `issuance_ro.rs:166–194` checks lookup/state, age ≤60 s and subject fingerprint before shared predicate assembly. Published/voided/missing/stale/subject-mismatch/tombstoned/retiring-CA cases passed. The DB is opened read-only by `child.rs:306`. |
| Same predicate as publish | Shared predicate held; **exact equivalence is qualified**, not a universal claim | `operations.rs:11314–11545` shares snapshot/predicate assembly and `verification_m03.rs:191–233` shares verification facts/checks. The 256-case comparison test passed for the mutations it generates. But issuer facts deliberately treat every issuance as new activation (`issuance_ro.rs:48–52`), so a paused reissue may be refused although runtime publish permits it. The issuer also cannot know the runtime's adapter configuration; publish checks that separately. Those differences do not bypass publication/installation and do not justify claiming identical verdicts for every possible runtime state. |
| Exact certificate profile, no wider bounds | Held; verified | `ca.rs:182–195` signs CertificateProfile::from_bounds; `credential/src/cert.rs:341–379` checks subject and CA, sets one user principal, serial, key ID, exact whole-second validity and only reserved extensions, then self-validates. `check.rs:126–146` adds principal/extension/window/key-ID ceilings. Exact-bounds and two-principal/X11/excess-validity/CA-subject cases passed. No critical option is constructed; validity truncation rounds the end down. |
| Rate limits | Held per running child; verified | `child.rs:97–115, 215–229`: 600 successful signatures/minute on continuous time, 64 per subject key (the per-activation/reissue K_env). Both limit tests passed. State is process-local and resets on restart; ADR-0008 calls this a runaway-loop bound, not a security boundary. |
| Malformed frame/crash releases no signature authority | Held in exercised cases; verified | Frame length checked before allocation (`child.rs:127–146`), decode/order violations return without signing, and the serve exit clears keys. Extra probe: five malformed bodies plus truncated header/body, all closed with EXIT_PROTOCOL 76 and no reply. Existing oversized-frame, child-crash-mid-sign, runtime-death and late-reply-after-drop tests passed. `client.rs:290–322, 665–704` retains cancel-safe framing and matches request IDs; late responses are drained/discarded. A previously completed valid sign is not retroactively cancelled by malformed later input. Publication remains the usable-authority boundary. |

The issuer/client suites completed 31 integration tests and six model tests. Client stderr is discarded in this implementation (`client.rs:351–356`); it is not evidence of a fully wired redacted runtime logger.

### 3. Read-only time assessment and check/publish races

`TimeGate::assess_read_only_in` returns its actual observation and verdict together (`timegate.rs:546–564`), performs no anchor/high-water writes, and refuses Safe without a same-boot anchor/confirmation. The read-only-store and absent-anchor tests passed. The issuer consumes this paired result in the same DB snapshot; W2-S01 is its signer consumer's misuse of the status-only wrapper.

**Can the issuer produce a certificate that a subsequent publish refuses? Yes.** A revoke, cutoff, expiry, clock-confidence change or generation move after the read-only snapshot can make publication refuse or re-reserve. That is the designed reserve–sign–publish protocol, not proof of a release bug. `publish_issuance` (`operations.rs:11023–11148`) rechecks current state and assessed time in the publishing transaction; rejected entries are voided, generation-only changes get bounded fresh reservations, and a reservation from another runtime instance cannot publish. Crash/late-reply tests and the issuance interleaving model exercised withheld publication/residual accounting.

Certificates cannot be installed through `SignerTable::install` as reserved entries: it requires published state, matching subject/pair/CA/profile, and a separate InstallView (`table.rs:536–606`). The production InstallView and managed effect driver are still unwired; absent a view, installation refuses. Therefore this review does not claim a completed live managed issuance-to-consumer workflow.

### 4. Projection and consumer launches

- **Directive injection: held for checked inputs; verified.** The renderer uses closed typed sections and validated aliases/hostnames/users/ports. Paths reject quotes, controls, backslashes on Unix and environment-expansion syntax; SSH percent tokens are escaped (`render.rs:184–264, 337–339, 483–487, 684–730`). A review probe rejected 17 hostile values across aliases, hostname, Unix path, pipe and user, including newline directive injection. Slot components reject traversal/device/stream/case-collision forms (`projection/content.rs:324–346`); existing slot-path tests passed.

- **Other-identity/agent fallback: held for an exclusive managed configuration; qualified by D10 item 6.** P pins IdentityAgent and IdentitiesOnly, with the selected certificate file; connect supplies binding identity options before config-file values (`render.rs:710–718, 828–850`; `connect_cmd.rs:417–432`). Native macOS projection tests demonstrated ordinary SSH/Git/scp/sftp using the managed endpoint, and an absent slot failing without contacting the decoy SSH_AUTH_SOCK agent. **Inherited user IdentityFile/CertificateFile entries remain additive.** D10 explicitly allows classification as not_exclusive; IdentitiesOnly does not mean only Heimdall's one identity in that situation. There is no universal no-fallback claim for arbitrary user configuration. Noninteractive fallback clearance and qualified deadline wording remain required. The new certificate-file form does not remove those pre-existing limits.

- **Owned connection stays foreground and does not reuse an unowned master: checked option boundary held; verified within local test coverage.** OWNED_LAUNCH_PINS precede user arguments (`render.rs:804–811`); the parser refuses -f/-M/-S/-O and conflicting -o forms, including options after the destination (`render.rs:960–1066`). Six consumer tests passed, including real local ssh -G checks against inherited ForkAfterAuthentication/ControlMaster/ControlPath settings. Connect builds the pinned argument vector itself. Full managed ensure/bind/launch is blocked pending managed driver/slot wiring; Windows owned launches explicitly refuse until contained-spawn support is wired. These static/local tests do not establish native Windows process containment or actual deadline-driven connection teardown.

The projection tests initially failed three fixture launches because hm-fixture-hook was absent in the new checkout. Running its authorized test target built the helper; the unchanged projection suites then passed 13 managed tests and six state-directory guard tests. The initial exit 101 was an unmet fixture prerequisite, not reported as a passing run or a product security finding.

### 5. Secrets

**No leak was observed or identified in the reviewed new production paths; broader absence is implemented_unverified.**

K_env/K_verify remain in the vault, which exports public halves and signatures, not private seed accessors. The key owns a zeroized buffer and derives a temporary ssh-key private key for signing (`vault.rs:247–323, 416–438`). CaSet has no private-key serialization in the protocol path; SecretCaKey's serialization API uses Zeroizing buffers for custody operations (`cert.rs:60–65, 120–140`). Signer refusal records are static bounded codes (`signer.rs:308–314`); issuer protocol errors carry fixed reason/length fields rather than frame bodies. The client discards child stderr and does not log request payloads. New managed projection files contain public keys/certificates, not private keys or passphrases.

The credential memory/interface tests passed, and executed real-client/consumer fixtures perform canary-output assertions. No actual owner key, agent, SSH configuration, Git configuration, login keychain or password manager was used as test material. Fixture secrets were disposable, per-run material.

Limits: I did not run a complete A33 output/artifact sweep, inspect live process memory/argv/environment, audit all ssh-key/zeroize internals or compiler-generated temporaries, or exercise all product SecretStore implementations. Passing drop-path/interface tests does not prove absence of every unzeroized transient buffer. This report makes no such claim.

### 6. INT-Q10

**The proposed form does not weaken F17 in the reviewed signer path.** P and connect select CertificateAsIdentityFile in one place (`render.rs:585–604`): IdentitiesOnly yes plus IdentityFile naming cert.pub. The endpoint still lists/resolves grant certificates only, and the signed data must carry that same certificate and its pair account. No plain K_env compatibility exception was added.

Independently rerun local observation, OpenSSH_10.5p1 / LibreSSL 3.3.6:

| Form | SSH exit | Requested blob | Sign requests | Accepted certificate logins |
| --- | ---: | --- | ---: | ---: |
| D10 as written: IdentityFile key.pub + CertificateFile cert.pub | 255 | none | 0 | 0 |
| IdentityFile cert.pub | 0 | cert | 1 | 1 |
| IdentityFile cert.pub + CertificateFile cert.pub | 0 | cert | 1 | 1 |
| Product-rendered default P | 0 | cert | 1 | 1 |
| Verification-shaped context listing both public key and certificate | 0 | plain | 1 | 1 |

The observation test records candidates rather than asserting all candidates succeed; its exit 0 alone would not establish the selected candidate's success. The measured rows above do.

**Plain K_verify agent request:** this is compatible with a certificate-only signed purpose. `signer.rs:333–350` permits a plain outer K_verify handle only on verification endpoints, then requires the data's blob to be the current positive certificate and its matching algorithm/account. The real endpoint fixture test exercised this distinction: outer plain + current certificate data signed; plain signed-data key, wrong user, grant certificate, negative certificate and stale positive certificate refused. Production Operations currently refuses even the positive case pending verification authorization. The latent missing plan-CA/pair check at install must be fixed when enabling that path; accepting an outer plain handle does not itself create it.

I did not independently run Windows in-box 9.5p2, devbox native 9.6p1, Linux or WSL. Their INT-Q10 compatibility/support claims remain blocked for this review.

## Validation commands and results

All Cargo commands below ran in the detached checkout with --locked and disposable fixture material.

| Command | Exit | Result |
| --- | ---: | --- |
| cargo test -p heimdall-credential --test integration_managed_signer --test adversarial_signer_requests --test integration_credential_cert --test integration_credential_memory --locked | 0 | 36 signer passed, 1 cross-account macOS ignored; 7 adversarial, 17 cert/purpose and 7 memory/interface passed |
| cargo test -p heimdall-issuer --test integration_issuer_child --test model_issuer_linearization --locked | 0 | 31 integration + 6 model passed; includes fixed-seed 256-case predicate comparison |
| cargo test -p heimdall-localenv --test integration_projection_managed --test integration_projection_state_dir_guard --locked (first run) | 101 | 10 passed, 3 failed for missing fixture helper; second target not reached |
| cargo test -p heimdall-testkit --test integration_testkit_fixtures --locked hook | 0 | Helper built; hook self-test passed, 17 unrelated tests filtered |
| Same localenv command, unchanged rerun | 0 | 13 managed projection + 6 state-directory guard passed |
| cargo test -p heimdall-credential --test integration_managed_identity_forms --locked | 0 | Observation test passed; candidate results separately captured in the table above |
| cargo test -p heimdall --test e2e_consumer_m03 --locked | 0 | 6 passed |
| cargo test -p heimdall-credential --test integration_managed_identity_forms --locked -- --nocapture (Python captured output, emitted observation metrics only) | 0 | Local client observations above |
| rustc --edition=2024 --test clock_probe.rs with original credential-test dependency artifacts; clock_probe review_probe_ --test-threads=1 | 0 / 0 | Two probes passed: reproduced unsafe release and Peek refusal control |
| rustc --edition=2024 --test protocol_probe.rs; protocol_probe review_probe_malformed_frames_release_nothing --exact | 0 / 0 | 7 malformed/truncated frame cases, no reply, exit 76 each |
| rustc --edition=2024 --test render_probe.rs; render_probe | 0 / 0 | 17 injection values refused |
| git diff --exit-code; git diff --cached --exit-code | 0 | No tracked edits |
| git worktree remove --force <scratch>/wt, using the requested repository -C path | 0 | Detached checkout and its 5.2 GB root target removed |
| Python pathlib cleanup with exact directory-content and regular-file checks | 0 | Six review-owned probe sources/executables removed; empty <scratch> removed and absence asserted |

Temporary harness setup attempts are not hidden: the first probe driver exited 1 because its dependency finder looked only for rlibs, missing the async-trait proc-macro dylib; a later control-probe compile exited 1 after selecting a newer tokio feature variant without test-util. Selecting the original credential-test artifacts resolved this; both final clock probes compiled and ran with exit 0. No production change was made to fix either harness issue.

Build hygiene: the required prototype du command was attempted, first under zsh (unmatched glob, exit 1), then under bash (three absent paths, exit 1). This checkout contained no prototype target/node_modules/dist output directories. The root target measured 5.2 GB and was completely removed with the worktree. A shell rm -f cleanup attempt was rejected before execution by command review; the exact-file checked pathlib cleanup succeeded instead. No removal result is inferred from the rejected command.

## Reproduction patch for W2-S01

This is a diff from the immutable tests/integration/managed_signer.rs to the temporary clock_probe.rs; apply it only to a disposable copy. It changes the fixture clock, not production code. PROBE_READS is armed after the unlocked precheck: read 0 is the permit's paired observation, read 1 is the read-only assessment's observation. That observation is returned unchanged, but the clock rolls back before the caller's next read. The two cases must run serially because they share the probe counter.

```diff
--- tests/integration/managed_signer.rs (0478f6cd)
+++ temporary clock_probe.rs
@@ -296,6 +296,16 @@
     }
     fn boot_id(&self) -> BootId {
         BootId("tokio-boot-1".into())
+    }
+    fn observe(&self) -> heimdall_domain::time::TimeAnchor {
+        let a = heimdall_domain::time::TimeAnchor {
+            wall: self.wall(), continuous: self.continuous(), boot_id: self.boot_id(),
+        };
+        let n = PROBE_READS.load(Ordering::SeqCst);
+        if n != usize::MAX && PROBE_READS.fetch_add(1, Ordering::SeqCst) == 1 {
+            *self.wall_back.lock().unwrap() = HOUR;
+        }
+        a
     }
 }
 
@@ -3197,3 +3207,38 @@
     );
     assert_eq!(r.w.table.instance_state(r.g.id()), None);
 }
+
+static PROBE_READS: AtomicUsize = AtomicUsize::new(usize::MAX);
+struct ProbeHook;
+impl SignHook for ProbeHook {
+    fn at<'a>(&'a self, _: &'a SignerEndpoint, step: SignStep) -> heimdall_credential::signer::HookFuture<'a> {
+        Box::pin(async move {
+            if step == SignStep::Prechecked { PROBE_READS.store(0, Ordering::SeqCst); }
+        })
+    }
+}
+#[tokio::test(start_paused = true)]
+async fn review_probe_clock_jump_between_safe_verdict_and_anchor() {
+    let w = world().await;
+    let g = w.grant("probe-clock", &[h1()]).await;
+    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), Arc::new(ProbeHook));
+    let log = Arc::new(Mutex::new(Vec::new()));
+    let frame = spawn_signed(&s, &g, &h1(), &log).await.unwrap();
+    PROBE_READS.store(usize::MAX, Ordering::SeqCst);
+    let assessed = w.ops.timegate().assess_read_only(&w.store);
+    assert_ne!(assessed, heimdall_domain::time::TimeStatus::Safe);
+    assert!(is_signature(&frame), "probe expected the suspected signature release");
+}
+
+#[tokio::test(start_paused = true)]
+async fn review_probe_clock_jump_peek_control() {
+    let w = world().await;
+    w.ops.set_authorization_time(AuthorizationTime::Peek);
+    let g = w.grant("probe-peek", &[h1()]).await;
+    let s = w.signer_with(SignerEndpoint::Binding(g.binding().clone()), Arc::new(ProbeHook));
+    let log = Arc::new(Mutex::new(Vec::new()));
+    let frame = spawn_signed(&s, &g, &h1(), &log).await.unwrap();
+    PROBE_READS.store(usize::MAX, Ordering::SeqCst);
+    assert!(!is_signature(&frame));
+    assert_ne!(w.ops.timegate().assess_read_only(&w.store), heimdall_domain::time::TimeStatus::Safe);
+}
```

The probes were compiled with rustc --edition=2024 --test, -L dependency=<checkout>/target/debug/deps and --extern entries for the dependencies already built by the credential tests (async_trait proc-macro dylib; heimdall_app, heimdall_contract, heimdall_credential, heimdall_domain, heimdall_ipc, heimdall_store, heimdall_testkit, heimdall_sshconf, ssh_key, tokio with test-util, tokio_util, tempfile rlibs). No dependency or build-output directory was added.

Observed final clock-probe output:

```text
running 2 tests
test review_probe_clock_jump_between_safe_verdict_and_anchor ... ok
test review_probe_clock_jump_peek_control ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 37 filtered out
```

## Remaining limits and risk

- Native Windows pipe DACL/cross-account behavior, Windows 9.5p2, WSL modes and Linux/native devbox 9.6p1 were not exercised; blocked with those exact missing platforms.
- The ignored macOS cross-account row needs a disposable second macOS account (B3). The synthetic peer and owner-mode tests do not close it.
- No live screen lock, vault lock, sleep/wake, logout, reboot, product secure-store, cross-machine or hostile-account test was performed. No Docker fixture was started.
- Full production managed issuance/install/verification/owned-launch wiring is incomplete at this commit. Tests using InstallView/verification authority/slot fixtures are labeled accordingly; no product end-to-end claim is derived from them.
- No full workspace suite, clippy, dependency-internals audit, exhaustive secret sweep or general correctness review was run. Checks were selected for these boundaries.
- The confirmed unsafe-time release remains unfixed in the reviewed commit; this read-only task made no implementation changes.

## Read/inspection command ledger

The following is the complete shell-command ledger before report authoring. Heredoc descriptions name their executed action; the security-critical probe modification is preserved above. For batched shell strings, the exit is the shell's overall exit, not a claim that every subcommand in a pipeline had the same exit. Tool polling is retrieval of these commands' completion, not another test run.

1. Exit 0: `pwd`

2. Exit 1: `ls -ld <scratch> <report>`

3. Exit 1: `rg -n -i 'heimdall|M03|signer|issuer' <home>/.codex/memories/MEMORY.md`

4. Exit 0: `Read active Codex-home and ancestor AGENTS.md files (shell for loop)`

5. Exit 0: `cat security-diff-scan/SKILL.md`

6. Exit 0: `git -C <repo> worktree add --detach <scratch>/wt 0478f6cd`

7. Exit 0: `cat codex-security/references/config-preflight.md`

8. Exit 0: `cat <home>/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.32/references/artifact-storage.md`

9. Exit 0: `git rev-parse HEAD 961c6201 && git diff --stat 961c6201 0478f6cd && git diff --name-only 961c6201 0478f6cd`

10. Exit 2: `rg --files -g 'SECURITY.md' -g 'AGENTS.md' -g '*0008*' -g '*0005*' -g '*issu*' -g '*sign*' -g '*render*' -g '*projection*' -g '*launch_flow*' -g '*connect_cmd*' -g '*run_cmd*' -g 'Cargo.toml' -g '*toolchain*' -g 'config.toml' .cargo crates docs tests`

11. Exit 0: `sed -n '1,230p' Cargo.toml; cat rust-toolchain.toml; rg -n '^##|^###|D1|D2|D3|D10|17\.16|R4|F17|INT-Q10' docs/decisions/0008-managed-credential-integration.md`

12. Exit 0: `sed -n '1,300p' crates/credential/src/signer.rs; sed -n '1,260p' crates/credential/src/purpose.rs; cat crates/credential/src/session_bind.rs`

13. Exit 0: `sed -n '1,280p' crates/issuer/src/ca.rs; cat crates/issuer/src/check.rs; cat crates/issuer/src/protocol.rs`

14. Exit 0: `nl -ba crates/credential/src/signer.rs | sed -n '1,540p'`

15. Exit 0: `sed -n '211,405p' docs/decisions/0008-managed-credential-integration.md; sed -n '560,812p' docs/decisions/0008-managed-credential-integration.md; sed -n '2527,2611p' docs/decisions/0008-managed-credential-integration.md`

16. Exit 0: `nl -ba crates/issuer/src/child.rs | sed -n '1,440p'; nl -ba crates/issuer/src/ca.rs | sed -n '1,300p'; nl -ba crates/issuer/src/check.rs | sed -n '1,300p'`

17. Exit 0: `nl -ba crates/app/src/issuance_ro.rs | sed -n '1,450p'; git diff 961c6201 0478f6cd -- crates/app/src/timegate.rs; rg -n 'issuance_ro|publish_issuance|assess_read_only|SignPermit|async fn admit|may_release' crates/app/src/operations* crates/app/src/managed* crates/ipc/src/signing.rs; cat crates/credential/Cargo.toml; cat crates/issuer/Cargo.toml`

18. Exit 0: `rg -n '^fn |^async fn |#\[ignore|Command::|SSH_AUTH|HEIMDALL_|fixture|docker' tests/integration/managed_signer.rs tests/integration/issuer_child.rs tests/integration/managed_identity_forms.rs; sed -n '1,200p' crates/credential/src/table.rs; sed -n '1,220p' crates/credential/src/endpoints.rs`

19. Exit 0: `rustc --version; cargo --version; rg --files -g SECURITY.md -g AGENTS.md -g config.toml -g config . | rg -v 'tests/evidence|prototypes'`

20. Exit 0: `cargo test -p heimdall-credential --test integration_managed_signer --test adversarial_signer_requests --test integration_credential_cert --test integration_credential_memory --locked`

21. Exit 0: `nl -ba crates/credential/src/table.rs | sed -n '260,760p'`

22. Exit 0: `nl -ba crates/credential/src/table.rs | sed -n '759,1040p'; nl -ba crates/app/src/operations/authorize.rs | sed -n '90,400p'; nl -ba crates/app/src/managed.rs | sed -n '900,1010p'`

23. Exit 0: `nl -ba crates/sshconf/src/render.rs | sed -n '1,510p'`

24. Exit 0: `nl -ba crates/sshconf/src/render.rs | sed -n '507,1030p'`

25. Exit 0: `nl -ba crates/sshconf/src/render.rs | sed -n '1030,1125p'; nl -ba crates/heimdall/src/launch_flow.rs; nl -ba crates/heimdall/src/connect_cmd.rs | sed -n '1,560p'`

26. Exit 0: `git diff 961c6201 0478f6cd -- crates/heimdall/src/run_cmd.rs crates/heimdall/src/launch_flow.rs crates/heimdall/src/m03_cmd.rs crates/localenv/src/agents.rs crates/localenv/src/projection/mod.rs crates/localenv/src/projection/content.rs crates/localenv/src/projection/plan.rs`

27. Exit 0: `nl -ba crates/issuer/src/client.rs | sed -n '1,390p'`

28. Exit 0: `nl -ba crates/issuer/src/client.rs | sed -n '388,780p'`

29. Exit 0: `rg -n 'SecretCaKey|SecretKey|Zeroiz|PrivateKey|to_openssh|to_bytes|seed|fn sign|build_and_sign' crates/credential/src/cert.rs crates/credential/src/vault.rs crates/credential/src/sys.rs; sed -n '1,285p' crates/credential/src/cert.rs; sed -n '110,340p' crates/credential/src/vault.rs`

30. Exit 0: `nl -ba crates/credential/src/endpoints.rs | sed -n '300,730p'`

31. Exit 0: `nl -ba crates/credential/src/endpoints.rs | sed -n '730,1010p'; sed -n '1,240p' crates/ipc/src/unix.rs; rg -n 'DACL|SDDL|owner|first_pipe|reject_remote' crates/ipc/src/windows.rs; sed -n '610,690p' crates/ipc/src/signing.rs`

32. Exit 0: `git diff 961c6201 0478f6cd -- crates/app/src/operations.rs crates/app/src/operations/authorize.rs crates/app/src/operations/verification_m03.rs crates/app/src/operations/narrowing.rs crates/store/src/ext.rs crates/store/src/ext_m03.rs`

33. Exit 0: `sed -n '1,118p' tests/integration/managed_signer.rs; sed -n '292,560p' tests/integration/managed_signer.rs; sed -n '630,890p' tests/integration/managed_signer.rs`

34. Exit 0: `sed -n '260,308p' tests/integration/managed_signer.rs; sed -n '1712,1747p' tests/integration/managed_signer.rs; sed -n '1270,1344p' tests/integration/managed_signer.rs; rg -n 'pub struct TimeAnchor|fn observe|pub fn timegate' crates/domain/src/time.rs crates/app/src/operations.rs; sed -n '10990,11155p' crates/app/src/operations.rs; sed -n '470,520p' tests/integration/issuer_child.rs`

35. Exit 0: `cargo test -p heimdall-issuer --test integration_issuer_child --test model_issuer_linearization --locked`

36. Exit 1: `python3 heredoc: copy managed_signer fixture into clock_probe.rs; instrument test Clock::observe to roll back one hour after the admitted read-only observation; rustc --edition=2024 --test with existing rlibs; run clock_probe review_probe_clock_jump_between_safe_verdict_and_anchor --exact`

37. Exit 0: `python3 heredoc: compile clock_probe.rs with rustc --test (resolve proc macro dylib as well as rlibs), then run the exact review probe`

38. Exit 0: `nl -ba crates/heimdall/src/run_cmd.rs | sed -n '375,568p'; git diff 961c6201 0478f6cd -- crates/localenv/src/agents.rs crates/localenv/src/projection/content.rs; rg -n '6\.7|security|review' plan.md | head -50; rg -n '^## 5|^## 8|^### 5|^### 8|secret|canary' spec.md | head -85; rg -n '17\.16|R4|17\.18|INT-Q13|INT-Q10' docs/decisions/0008-managed-credential-integration.md | tail -25`

39. Exit 0: `sed -n '202,250p' spec.md; sed -n '334,360p' spec.md; sed -n '386,445p' spec.md; sed -n '481,491p' plan.md; sed -n '3623,3652p' docs/decisions/0008-managed-credential-integration.md; sed -n '3740,3792p' docs/decisions/0008-managed-credential-integration.md; sed -n '165,285p' docs/decisions/0005-managed-credential-recipe.md; rg -n 'name =|path =' crates/localenv/Cargo.toml crates/sshconf/Cargo.toml crates/heimdall/Cargo.toml | tail -100`

40. Exit 101: `cargo test -p heimdall-localenv --test integration_projection_managed --test integration_projection_state_dir_guard --locked`

41. Exit 0: `cargo test -p heimdall-credential --test integration_managed_identity_forms --locked`

42. Exit 0: `cargo test -p heimdall --test e2e_consumer_m03 --locked`

43. Exit 0: `sed -n '3634,3650p' docs/decisions/0008-managed-credential-integration.md; sed -n '3752,3771p' docs/decisions/0008-managed-credential-integration.md; sed -n '1,230p' crates/credential/src/purpose.rs; sed -n '230,460p' crates/credential/src/purpose.rs`

44. Exit 0: `sed -n '650,710p' tests/integration/issuer_child.rs; sed -n '1140,1315p' tests/integration/issuer_child.rs; sed -n '1,210p' tests/e2e/consumer_m03.rs; sed -n '1,160p' tests/integration/managed_identity_forms.rs; sed -n '1,130p' crates/testkit/src/managed.rs`

45. Exit 0: `sed -n '2780,2945p' tests/integration/managed_signer.rs; rg -n '^fn |^async fn |HEIMDALL_|canary|secret|inject|fallback|exclusive|owned|[Ii]gnor' tests/integration/projection_managed.rs tests/e2e/consumer_m03.rs; sed -n '140,240p' crates/domain/src/verification.rs; sed -n '341,397p' crates/credential/src/cert.rs; sed -n '300,353p' crates/ipc/src/unix.rs`

46. Exit 0: `cat crates/testkit/Cargo.toml; sed -n '1,120p' crates/testkit/src/bin/hm-fixture-hook.rs; sed -n '930,979p' tests/integration/projection_managed.rs; sed -n '116,220p' crates/app/src/operations/verification_m03.rs; git diff 961c6201 0478f6cd -- Cargo.lock crates/heimdall/Cargo.toml crates/localenv/Cargo.toml tests/e2e/cli_m03.rs tests/model/narrowing_m03.rs`

47. Exit 0: `rg -n '^fn |^async fn ' tests/integration/testkit_fixtures.rs`

48. Exit 0: `cargo test -p heimdall-testkit --test integration_testkit_fixtures --locked hook`

49. Exit 0: `sed -n '520,602p' tests/integration/issuer_child.rs; sed -n '1,90p' tests/integration/issuer_child.rs; rg -n 'struct Assessment|fn assess\(' crates/app/src/timegate.rs; sed -n '80,190p' crates/app/src/timegate.rs; git diff 961c6201 0478f6cd -- crates/testkit/src/managed.rs`

50. Exit 1: `python3 heredoc: append Peek control to clock_probe.rs; rustc --test using existing dependencies; run clock_probe review_probe_ --test-threads=1`

51. Exit 0: `python3 heredoc: recompile clock probes against the original credential-test rlibs (earliest feature variants); run clock_probe review_probe_ --test-threads=1`

52. Exit 0: `cargo test -p heimdall-localenv --test integration_projection_managed --test integration_projection_state_dir_guard --locked`

53. Exit 0: `sed -n '470,640p' tests/integration/managed_identity_forms.rs; sed -n '280,347p' crates/issuer/src/protocol.rs; sed -n '310,380p' crates/credential/src/session_bind.rs`

54. Exit 0: `python3 heredoc: copy issuer_child World/InProc fixture helpers to protocol_probe.rs; rustc --test using existing rlibs; run review_probe_malformed_frames_release_nothing --exact (5 malformed bodies and 2 truncations)`

55. Exit 0: `nl -ba crates/credential/src/session_bind.rs | sed -n '1,255p'; nl -ba crates/heimdall/src/connect_cmd.rs | sed -n '1,122p'; sed -n '1,110p' tests/model/issuer_linearization.rs; sed -n '1,85p' tests/evidence/artifacts/review-m03-code/wave2-notes/m03-wave2-questions.md; rg -n 'secret|canary|no_clone|zeroiz' tests/integration/issuer_child.rs tests/integration/managed_signer.rs tests/e2e/consumer_m03.rs`

56. Exit 0: `python3 subprocess capture/filter: cargo test -p heimdall-credential --test integration_managed_identity_forms --locked -- --nocapture (emit observation metrics only)`

57. Exit 0: `python3 heredoc: write/render_probe.rs; rustc --test with existing heimdall_sshconf rlib; assert rejection of 17 directive-injection values across alias, hostname, paths, pipe and user`

58. Exit 1: `git status --short; git rev-parse HEAD; du -sh target; du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist`

59. Exit 0: `nl -ba crates/app/src/operations/authorize.rs | sed -n '147,181p'; nl -ba crates/app/src/operations/narrowing.rs | sed -n '281,302p'; nl -ba crates/app/src/timegate.rs | sed -n '512,567p'; nl -ba crates/app/src/operations/authorize.rs | sed -n '91,110p'`

60. Exit 0: `python3 difflib: compare immutable managed_signer.rs against the temporary clock probe (report reproduction patch)`

61. Exit 0: `git diff --exit-code; git diff --cached --exit-code`

62. Exit 1: `bash -c 'du -sh prototypes/*/target prototypes/*/node_modules prototypes/*/dist'`

63. Exit 0: `git -C <repo> worktree remove --force <scratch>/wt`

64. Exit not executed: command rejected; rm -f style commands not permitted, use safer approach: `rm -f six explicit review-owned probe paths`

65. Exit 0: `python3 pathlib: assert scratch directory contains exactly the six review-owned regular probe files, unlink each, rmdir, assert absence`
