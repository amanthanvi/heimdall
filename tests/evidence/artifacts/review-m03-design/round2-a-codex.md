# M03 design review, round 2, reviewer A — 150e2f2b — another design round needed

Reviewer: Codex GPT-6.1 Sol (provider instance `codex-cpamc`, reasoning effort high), independent,
read-only, separate worktree. Saved by the orchestrator on 2026-11-06, condensed but faithful in
substance. Reviewed revision 2 of `docs/architecture/m03-plan.md` (P) and ADR-0008 (D) at
`150e2f2b`. Changed files: none. "Closed" means the design addresses the finding and names suitable
verification, not that an implementation passed.

**Verdict: another design round needed.** Most round-1 findings are closed at the design level; two
blockers remain (exclusive host-key enforcement; stale-writer fencing), plus seven majors.

## Round-1 closure

| Finding | Verdict | Reason |
|---|---|---|
| M03-R01 | partly | D:231–274 gate and enqueue linearization; timing and cancellation bounds incomplete (R2-06) |
| M03-R02 | partly | D:834–859 route check and pins; inherited `KnownHostsCommand` defeats the key pin (R2-01) |
| M03-R03 | closed | D:1025–1052 |
| M03-R04 | partly | D:850–867; the session-agent alternative can resolve to the managed signer (R2-04) |
| M03-R05 | closed | D:1046–1052 |
| M03-R06 | not closed | D:928–931 lets the stale writer write after lock breaking, contradicting D:1124 (R2-02) |
| M03-R07 | partly | D:776–792; system-form cancellation paths unsafe (R2-05) |
| M03-R08 | partly | D:1499–1574; forking clients and registration racing revocation (R2-07, R2-08) |
| M03-R09 | closed | D:1680–1689 |
| M03-R10 | closed | D:1014–1024, 1405–1439 |
| M03-R11 | closed | D:524–541, 597–613 |
| M03-R12 | partly | D:637–663; system removal cancellation and finality unsafe (R2-05) |
| M03-R13 | partly | the verification lifecycle and the drawn graph have gaps (R2-09) |
| M03-R14 | closed | D:1926–1929, P:697–700 |
| M03-R15 | closed | D:1582–1626 |
| F01 | closed | D:1025–1052 |
| F02 | partly | resume precedes registration, which is not fenced against revocation (R2-08) |
| F03–F05, F07–F11, F13–F27 | closed | (each cited by line in the reviewer's table: D:1864–1881, 1093–1100, 588–596, 637–663, 563–571, P:1692–1728, D:1898–1915, 1851–1862, 734, 1323–1332, 1396–1399, 1582–1626, 290–294, 332–339, 1651–1660, 1206–1209, 407–412, P:481–484, 251, 637–647, D:817–818, P:1580–1592, D:1066–1080) |
| F06 | partly | state-table defects in R2-05 remain |
| F12 | partly | bounded gate incomplete (R2-06) |

## New and remaining findings

| ID | Severity | Location | Defect | Fix |
|---|---|---|---|---|
| R2-01 | blocker | D:840–859; P:1870–1878 | The invocation pins known-hosts files but not `KnownHostsCommand`, which the evaluator treats apart from route fields (`sshconf/src/relevant.rs:89`). **Observed** (disposable loopback, OpenSSH 10.5p1): approved key A in the generated file, server key B, an inherited `KnownHostsCommand` supplying B: ssh accepted B and ran the command (exit 0); with `KnownHostsCommand=none` it failed host verification (exit 255). An append or removal can run against an unapproved key (Inferred). | Make the generated file the exclusive trust source: `KnownHostsCommand=none`, `VerifyHostKeyDNS=no`, and every other alternative trust source off; a wrong-key fixture with an inherited key provider, refused before any mutation. |
| R2-02 | blocker | D:894–931, 1111–1137; ruling D:2202–2208 | The script checks elapsed time and token, then writes; reconcile can rename its lock away while it is paused between check and write (D:928–931 says so; D:1124 says it "can no longer write"). **Observed** (scratch model): old writer passes checks, reconcile renames the lock, new writer appends, old writer resumes and appends: two marker lines. No safe rule for another enrollment's live lock; serialization is per registry remotely but per enrollment locally. | Never authorize redispatch by renaming a lock away from a process that may still write: process-owned exclusion held through the mutation with proven termination before replacement, or keep the operation uncertain and require manual recovery; token and deadline ownership across concurrent enrollments and delayed starts; the pause just before the write must pass the no-duplicate/no-loss test. |
| R2-03 | major | D:894–919; P:832–839 | Every mutation first runs `mkdir <registry dir>/.hm-lock.<name>`, but the absent registry directory is created inside the locked append. **Observed:** ENOENT at lock acquisition. | Journal a safe directory bootstrap before the lock, or lock in an existing validated directory; distinguish a missing parent from a busy lock. |
| R2-04 | major | D:850–867, 2298–2301 | The pin allows `IdentityAgent=SSH_AUTH_SOCK`, and the launcher can set `SSH_AUTH_SOCK` to the binding endpoint (`launch/src/env.rs:84–87`); IdentityFile and CertificateFile accumulate. **Observed** (disposable loopback): with the documented pins, `SSH_AUTH_SOCK` at the fixture managed agent and inherited managed files, ssh authenticated with the managed certificate (exit 0) despite `CertificateFile=none`. | Resolve and approve a concrete existing-access endpoint and refuse any Heimdall managed endpoint; rediscover the source endpoint independently of the managed launch environment; extend the zero-managed-signatures test to maintenance run from inside a managed `run`. |
| R2-05 | major | D:779–795, 1187–1199 | `held → manual_removal_pending → verified` and `abandoned → manual_removal_pending → verified` on cancel, with no verification; `verifying → manual_pending → withdrawn` (inconclusive, cancel) after the owner may have installed system trust, while `withdrawn` is final with no trust. | Persist the state and evidence manual removal began from and return there on cancel; after system trust may exist, keep an uncertain/held/abandoned inventory entry until absence is verified; test the full paths before freezing the golden. |
| R2-06 | major | D:237–264; P:424, 2254–2259 | The last deadline/time check is at the authorization read; signing and up to 2 s of enqueue follow with no expiry check at the enqueue (the linearized effect); the 5 s narrowing bound assumes a bounded `KeyVault::sign`, which is synchronous and unbounded, with no cancellation owner. A request admitted just before D can release after D (Inferred). | The permit carries an absolute expiry from the wall and continuous admission limits; refuse release once it or the safe-time predicate fails; an enforceable end-to-end holder budget with a cancellation owner; deterministic tests pausing after the read, crossing D without edits, asserting no release. |
| R2-07 | major | D:1504–1509, 1558–1579, 1767–1774 | Ownership assumes exec makes the holder PID the connection PID; nothing forbids `-f` or inherited `ForkAfterAuthentication yes`. **Observed:** `ssh -G` with the documented dedicated options kept `forkafterauthentication yes`. | Owned dedicated launches stay in the foreground: pin `ForkAfterAuthentication=no` and refuse conflicting `run ssh` arguments, or transfer ownership durably; test inherited configuration and explicit `-f`. |
| R2-08 | major | D:1511–1524; P:1966–1971 | The Windows child is resumed before durable registration; registration checks launcher ownership, creation time and image, not grant state, tombstones, the deadline or ordering with revocation (bindings have their own lifecycle, `domain/src/binding.rs:17–24`). A revocation between can miss the connection (Inferred). | Register while suspended, under a transaction or gate ordered with grant ending, refusing ended or unsafe grants; define the resume acknowledgment so a revocation between registration and resume kills the child; pauses on both sides. |
| R2-09 | major | P:513–524, 1253–1254, 2315–2353; D:2399–2425 | `app::enrollment::run_verification` must reserve and publish K_verify certificates, but `app` cannot depend on `credential`, `VerificationEndpoint` exposes only a locator and counters, `ManagedEffects::generate_key`/`install` take a GrantId, and no frozen port creates, registers, installs or destroys an operation's verification endpoint. IPC's `SignOutcome` holds `app::managed::SignPermit` (P:377): an `ipc → app` edge absent from the drawn graphs. | Specify the operation-scoped verification lifecycle through a factory/effect port (key registration, install, drop cleanup) or move it into runtime orchestration with defined inputs; put the transport permit below `app` or declare and check the edge; the checker resolves package names and includes optional and target-specific dependencies, and tests a cycle and the forbidden app edge. |

## Agreement with §17.3
Q18 agree; Q19 agree, with R2-04 for the independence claim; Q20 agree; Q21 agree, add R2-06's
passage-of-time test. The registry crate, stable mux path and measured-versus-nominal residual follow
the rulings; the lagging-clock fixture tests the arithmetic only, not sshd's validation clock (P:1360–1362).

## Commands (reviewer)
Read-only inspection (exit 0); a disposable loopback host-key-provider probe (ssh 0 with the
inherited provider, 255 with it disabled); a scratch fencing and bootstrap model (duplicate count 2,
missing-parent lock failure, rename of another token's lock); an `ssh -G` option probe (forking kept);
a disposable maintenance-agent probe (ssh 0 with the managed certificate); `ssh -V` OpenSSH 10.5p1,
`rustc` 1.99.1; final `git diff --exit-code` and status clean. Fixture sshd and agents were stopped by
exact handles; scratch removed. Not run: Rust builds and tests, native Windows, desktop lock, product
secure stores.
