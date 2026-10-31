# G04 research: managed credentials and lock continuity

**Task:** M00-T04-G04-research · **Gate:** G04, preliminary G09 · **Status:** `in_progress`. The
research and design are complete; the lock-dependent measurements are `blocked` on owner-driven
lock cycles and on missing platforms. · **Written:** 2026-10-03 (UTC) · **Host used:** macOS 27.0
(26A428) arm64, OpenSSH_10.3p1 / LibreSSL 3.3.6, Docker Engine 29.8.0 · **Revised:** 2026-10-03
(task M00-T04-G04-fix) after independent review M00-review-g04
(`tests/evidence/artifacts/m00-wf2/review-g04.json`): experiment results integrated (§1.3), the
`-O stop` conclusion corrected (§2 item 8, F-7), and the residual window split into new
authentication, live connections and remote processes (§3, §4, §7). The revision itself has not
been independently re-reviewed.

**Requirements in scope:** R-CR-02, R-CR-03, R-CR-04, R-CR-07, R-AU-05, R-AU-08, R-UX-03
(plus R-EN-04 for the probes) · **Acceptance:** A03, A09, A10, A23 · **Spec:** §6.4–§6.7,
§7.1–§7.7, §13.2, §14 · **Plan:** §3 G04, §3 G09, §6.4

This document compares candidate recipes and designs the experiments. **It does not decide.**
The recommendation in §7 is a recommendation pending experiments. Choosing a recipe is the
G04 ADR, which needs the evidence listed in §8 and the owner decisions in §9.

## 0. How to read the labels

Every factual statement carries one of these labels:

| Label | Meaning |
|---|---|
| `[S:key]` | Pinned primary source; see the register in §1.1. |
| `[O:id]` | Observed in this task by running a command; exit codes and artifacts in §1.2. |
| `[OX:id]` | Observed by another M00 agent; cited with their evidence path. Not re-verified here. |
| `[X:id]` | Observed in the G04 experiment run (§1.3): real exit codes and records listed there. |
| `[I]` | Inference from the cited sources. Not observed. |
| `[U]` | Unknown. Needs the named experiment. |

Recipe properties that are design proposals, not facts, are written as "Heimdall would ..." or
"proposed".

## 1. Evidence base

### 1.1 Source register

**Local, installed on this host.** Rendered text is in
`tests/evidence/artifacts/g04/research/sources/local-man/`, with SHA-256 digests in
`SHA256SUMS.txt`. These describe the installed tools. OS floors other than macOS 27.0 are
not covered.

| Key | Source | Revision |
|---|---|---|
| `ssh-keygen.1` | ssh-keygen(1) | OpenBSD rev 1.237, 2025-12-22 |
| `ssh-agent.1` | ssh-agent(1) | rev 1.86, 2025-10-04 |
| `ssh-add.1` | ssh-add(1) | rev 1.89, 2026-03-05 (Apple build adds `--apple-*` options) |
| `ssh.1` | ssh(1) | rev 1.447, 2025-12-22 |
| `ssh_config.5` | ssh_config(5) | rev 1.423, 2026-03-23 |
| `sshd_config.5` | sshd_config(5) | rev 1.397, 2026-03-28 |
| `sshd.8` | sshd(8) | rev 1.328, 2025-10-04 |
| `ssh-keychain.8` | Apple ssh-keychain(8) (`/usr/lib/ssh-keychain.dylib`) | dated 2020-02-10 |
| `sc_auth.8` | Apple sc_auth(8) (CTK identities) | macOS 27.0 |
| `security.1` | Apple security(1) | macOS 27.0 |
| `clock_gettime.3` | macOS clock_gettime(3) | macOS 27.0 |

**Web, fetched 2026-10-03 00:05–00:35 UTC.** The URL, HTTP status, raw-response SHA-256 and
fetch time are in `tests/evidence/artifacts/g04/research/sources/web/MANIFEST.tsv`. The
extracted text that was actually read is retained next to it (`RETAINED_SHA256SUMS.txt`). Raw
HTML of vendor pages was not retained (see escalation Q3). Mutable pages describe current
behavior, not the behavior of any particular installed release.

| Key | Source (version/date as stated by the source) |
|---|---|
| `RFC9987` | RFC 9987 *SSH Agent Protocol*, Standards Track, May 2026 (raw text retained) |
| `PROTOCOL.agent`, `PROTOCOL.mux`, `misc.c`, `ssh-agent.c`, `ssh-add.c`, `mux.c` | openssh-portable at commit `87f0cd1892e501f835dd210abea5461807c8deba` (2026-10-01), retained |
| `OpenSSH-RN-5.9` | openssh.org release notes, 5.9 section (excerpt retained) |
| `agent-restrict` | openssh.org/agent-restrict.html (spec S03) |
| `TN3137` | Apple TN3137 *On Mac keychain APIs and implementations*, revision history last entry 2026-09-24 |
| `Apple-DPKeychain` | Apple doc `kSecUseDataProtectionKeychain` |
| `Apple-AfterFirstUnlock`, `Apple-WhenUnlocked` | Apple docs for those accessibility constants |
| `Apple-RestrictAccess` | Apple *Restricting keychain item accessibility* |
| `Apple-SEKeys` | Apple *Protecting keys with the Secure Enclave* |
| `Apple-PS-Keychain`, `Apple-PS-DPClasses` | Apple Platform Security guide: *Keychain data protection*, *Data Protection classes* (both "Published Date: December 19, 2024") |
| `MS-CryptProtectData`, `MS-CryptUnprotectData` | Microsoft Learn, dpapi.h |
| `MS-CredWrite`, `MS-CREDENTIAL` | Microsoft Learn, wincred.h (`CredWriteW`, `CREDENTIALW.Persist`) |
| `MS-NCryptCreatePersistedKey`, `MS-KSP-Props` | Microsoft Learn, ncrypt.h / Key Storage Property Identifiers |
| `MS-TPM` | Microsoft Learn, *TPM fundamentals* |
| `MS-OpenSSH-Keys` | Microsoft Learn, *OpenSSH key management* (spec S13) |
| `FDO-SS-Locking` | freedesktop Secret Service API draft, *Locking and Unlocking* |
| `GNOME-Keyring-PAM` | wiki.gnome.org/Projects/GnomeKeyring/Pam (site marked retired) |
| `keyrings.7`, `user-keyring.7`, `session-keyring.7`, `persistent-keyring.7`, `systemd-creds.1` | man7.org pages |
| `tpm2-pkcs11-SSH` | tpm2-pkcs11 `docs/SSH.md` at commit `d8375fa68e4c` |
| `Step-Tutorial` (spec S11), `Step-Provisioners`, `Step-Config`, `Step-SSH-Renew`, `Step-SSH-Revoke`, `Step-SSH-Login` | smallstep.com docs |
| `Step-License` | smallstep/certificates `LICENSE` at `fdeb6fdf53f9` (Apache License 2.0) |
| `1P-Security`, `1P-Authorization` | 1password.dev SSH agent security / authorization (spec S06, S07) |

### 1.2 Observations made in this task

All runs used disposable material only. `SSH_AUTH_SOCK` was unset, and nothing touched the
owner's `~/.ssh`, agent, login keychain or 1Password.

| ID | What | Command / artifact | Real exit |
|---|---|---|---|
| `O:F1` | CA key held only in a dedicated "issuer" ssh-agent signs a user cert via `ssh-keygen -U -s`; worker agent signs after its private file is deleted; agent removal of expired cert; `ssh-add -t` lifetime. Note: the transcript label "(c) plain working key still signs after cert removal" is misworded. The listing just above it shows the certificate was **still loaded** (inside `CERT_EXPIRY_GRACE`); the line only shows the working key still signs. | `tests/evidence/artifacts/g04/research/f1-issuer-agent-cert/{run.sh,transcript.log}` | 0 |
| `O:K1` | Disposable custom keychain mechanics via `security -i`; search list / default keychain unchanged; default settings; ioreg lock keys while unlocked | `.../k1-keychain-mechanics/{run.sh,transcript.log}` | 0 |
| `O:SMOKE-1` | Lock probe smoke, attempt 1: **probe defect**. macOS `ps` truncates a non-final `comm` column, so the agent identity check failed. The script then forgot the agent PID, and its keyless dedicated agent was orphaned. The orphan was identified by start time, executable and socket path, then terminated manually. Record corrected in place. | `tests/evidence/g04-macos-lock-probe-smoke-20261003T002226Z.json`, `.../lock-probe/20261003T002226Z-smoke/CORRECTION.txt` | 3 |
| `O:SMOKE-2` | Lock probe smoke after the fix: 5/5 samples agent signing and keychain read OK; cleanup complete | `tests/evidence/g04-macos-lock-probe-smoke-20261003T002454Z.json` | 0 |
| `O:SMOKE-3` | Interruption path (`SIGTERM` after about 10 s): cleanup complete, record `in_progress` | `tests/evidence/g04-macos-lock-probe-smoke-20261003T002636Z.json` | 5 |
| `O:SMOKE-4` | Lock probe v2 (gate-probe convention: `observed_result.verdict`, no requirement IDs on smoke records) smoke run: 5/5 agent signing and keychain read OK; cleanup complete; user keychain search list and default keychain digests unchanged (checked independently around the run) | `tests/evidence/g04-macos-lock-probe-smoke-20261003T192414Z.json` (verified, verdict pass) | 0 |
| `O:SMOKE-5` | Lock probe v2 `--fixture-runtime` path against the **real** M00-T03 fixture (run 20261003T192323Z, before `down.sh`): 5/5 fresh certificate logins to ca1; ca2 principal-mismatch and no-agent controls rc 255; cleanup complete. The reviewer first ran this path against the real fixture (`tests/evidence/artifacts/review-g04/lock-probe-smoke-fixture-20261003T190014Z*`). | `tests/evidence/g04-macos-lock-probe-smoke-20261003T193955Z.json` (verified, verdict pass) | 0 |
| `O:SELFTEST` | `--fixture-runtime` path against two disposable loopback sshd containers mirroring fixture ca1/ca2 (server `OpenSSH_10.0p2 Debian-7+deb13u4`): 5/5 fresh certificate logins accepted by ca1; the ca2 principal-mismatch control and the no-agent control both rc 255; no container, image, temp-dir or process residue | `tests/evidence/g04-macos-lock-probe-smoke-20261003T002755Z.json` (run 1; self-test exit not captured, see log note), `...T002820Z.json` + `.../selftest/selftest-run2.log` | 0 (run 2) |
| `O:P5` | P5 unlocked run, v1 (task M00-T04-g04-P5, owner decision D4; probe `g04_ctk_probe.sh` v1, 2026-10-09T05:36:16Z, agent process in the launchd **Background** session, screen unlocked). One `p-256-ne -t none` CTK identity created, used, deleted; store held no other identity before or after. Fixture login unmeasured (v1 probe defect). Results per sub-row in the record (kept under `rows.unlocked.earlier_runs`); summary in §5.1 | `tests/evidence/g04-macos-secure-enclave-ctk-probe.json`, `tests/evidence/artifacts/g04/p5/20261009T053616Z-unlocked/` | 1 (verdict fail; cleanup complete) |
| `O:P5-V3` | P5 unlocked run, v3 (probe `g04_ctk_probe.sh` v3, blob committed at 34ffe3e, sha256 `c9b2fcc1…5dd2`; 2026-10-31T20:09:28Z; run by the orchestrator in the launchd **Aqua** session on macOS 27.0.1 (26A434), screen unlocked; self-test re-run just before: pass=132 fail=0; fixture up/down and the post-run empty identity list are orchestrator reports, not archived). One `p-256-ne -t none` CTK identity created, used, deleted by exact hash; store empty before, identity list equal to the pre-run list after. Create, export-refusal, delete and dedicated-agent signing pass; the `KEYCHAIN_CERTIFICATES` limit fails again (a non-matching hash still loaded one key); fresh certificate login to ca1 through the agent passes in the setup check and 3/3 samples, with the ca2 and no-agent controls refused; signing after delete fails (agent lists the key, cannot sign). Run without the owner's confirmation that D4 covers a further run (owner question open). Record: unlocked row `verified`, verdict fail | `tests/evidence/g04-macos-secure-enclave-ctk-probe.json`, `tests/evidence/artifacts/g04/p5/20261031T200928Z-unlocked/` | 1 (verdict fail; cleanup complete) |
| `O:P5-OFFER` | Client-side check, no identity created, no agent: with the deleted identity's public key and a fixture certificate, ssh without `SecurityKeyProvider` ignores the sk key; with it, ssh offers the `ECDSA-SK-CERT` and ca1 answers "Server accepts key" (no signature possible) | `tests/evidence/artifacts/g04/p5/v2-client-offer-check-20261009T054018Z/` | 255 / 255 (expected; rc from the check driver's output, transcribed in its NOTE.txt) |
| `O:P5-H2` | With a controlling terminal and stdin `/dev/null`, `ssh-add -K -S` and `ssh-add -s` block on the PIN prompt when `SSH_ASKPASS_REQUIRE=never` (killed after 15 s); with `SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/usr/bin/true` both return at once. Empty store, dedicated agent, no identity created | `tests/evidence/artifacts/g04/p5/h2-tty-prompt-check-20261009/` | 124, 124 / 1, 1 |
| `O:P5-REH` | Rehearsals of probe v3 with disposable **software** keys and the fake `sc_auth` against the fixture (not CTK evidence): the first exposed that v2's `SecurityKeyProvider` line broke every generated `ssh_config` under bash 3.2; after the fix, unlocked mode passed every clause, a foreign key was rejected, and lock mode ran end to end in a pseudo-terminal with scripted answers | `tests/evidence/artifacts/g04/p5/rehearsal-v3-20261009T061500Z/`, `…rehearsal-v3-20261009T061826Z/` | 1, 1 (by design in hook mode) |
| `O:P5-SELFTEST` | `g04_ctk_probe_selftest.sh` (fake `sc_auth`, never the real store): identity lifecycle, timeouts with exact-PID termination, partial creation, unexpected export, refused delete, non-empty store, interruption (also during create, and a second signal during cleanup), redaction of other identities and local times, bash-3.2 parsing of the generated `ssh_config` | `tests/evidence/artifacts/g04/p5/selftest/`: `selftest-20261009T053417Z.log` (v1, pass=81), `…T053913Z.log` (v2, pass=92), later logs for v3 (final of 2026-10-09: `…T090152Z.log`, pass=132; re-run immediately before the v3 real run: `…20261031T200815Z.log`, pass=132 fail=0) | 0 each for the 2026-10-09 runs; the exit status of the 2026-10-31 re-run was not captured (its log ends `result: pass=132 fail=0`) |

The smoke records `…T002226Z` to `…T002820Z` were written by probe v1 without
`observed_result.verdict` and with product requirement IDs. They were corrected in place on
2026-10-03 (verdict derived from their own observations: `…002226Z` and `…002636Z` inconclusive,
the others pass; requirement IDs removed; a limitation entry records the correction).

The two self-test runs were the only network use beyond source fetching. Each ran a
`docker build` of a throwaway image from the pinned Debian digest, with `apt-get install
openssh-server`. The image was removed afterwards (observed `image_remaining=0`). No
host-level toolchain was installed.

### 1.3 Experiment runs (E1–E7)

The experiments designed in §8.1 are implemented in `tests/native/g04/` and were run from scratch
on 2026-10-03: `tests/native/g04/fresh_run.sh` (fixture `down.sh`, `up.sh` with new keys/CA,
`smoke.sh` pass=60 fail=0, then every experiment), stamp `20261003T192323Z`, artifacts in
`tests/evidence/artifacts/g04/experiments/20261003T192323Z/`, fixture `down.sh` afterwards
(`CLEANUP CONFIRMED`, exit 0). Client `/usr/bin/ssh` OpenSSH_10.3p1; server openssh-server
1:10.0p1-7+deb13u4 in the fixture containers; container-host clock offset 0.007–0.015 s. Every
experiment exited 0. Records (gate-probe convention: `status` = evidence state,
`observed_result.verdict` = against the stated criterion):

| Key | Record (`tests/evidence/`) | Status / verdict | Main observation |
|---|---|---|---|
| `X:E1` | `g04-exp-e1-dedicated-agent.json` | verified / pass | Dedicated agent only; `ssh-add -t 120` ends signing (`ssh-add -T` rc 1, login rc 255) |
| `X:E2` | `g04-exp-e2-cert-expiry.json` | verified / pass | sshd stops **new** authentication at `valid_before`: 153 back-to-back logins, 80 accepted, 73 refused as expired, none accepted starting after it; agent-held expired certificates refused like disk ones |
| `X:E3` | `g04-exp-e3-principal-scope.json` | verified / pass | `{p-host1}` only on ca1, `{p-host2}` only on ca2, the two-principal certificate on both; username, rogue CA, bare key refused |
| `X:E4` | `g04-exp-e4-account-ca-principals.json` | verified / pass | Account-level `cert-authority,principals="hm:fx-enroll:enroll"` accepts only that principal; removal by marker restores the seed bytes |
| `X:ENR` | `g04-exp-enroll-marker-key.json` | verified / pass | Marker-only fresh authentication; concurrent admin edit preserved |
| `X:E5` | `g04-exp-e5-issuer-separation.json` | verified / pass | Worker endpoint cannot see or use the CA; child certificate narrower and enforced. Findings: a same-user process with the issuer socket path can mint; the CA private **file** stayed readable by the same user |
| `X:E6` | `g04-exp-e6-fresh-login-verification.json` | verified / pass | Verification gives exactly one new Accepted line; reuse gives none |
| `X:E7` | `g04-exp-g09-prelim-mux-after-expiry.json` | verified / pass (criterion scoped to **new** control connections) | H1/H1b: sessions admitted after expiry, even without a client credential. H2: new clients after `-O stop` fall back and are refused. H3: `-O exit` closes the master. H3b: the remote no-tty shell survives `-O exit` |
| `X:E7P` | `g04-exp-g09-prelim-mux-preconnected-after-stop.json` | verified / **fail** | Control connections accepted **before** `-O stop` were granted a session at stop+2 s and stop+15 s (after expiry), a local forward, a remote forward and a stdio forward. `-O exit` and exact-PID SIGTERM close them |
| `X:E7R` | `g04-exp-g09-prelim-mux-stop-race.json` | verified / pass (criterion cannot see pre-accepted connections) | 0 of 25 clients that started after stop returned were admitted; 1 of 7 overlapping clients admitted |

Phase 5 (`X:E7P`) was added after the review's independent probe
(`tests/evidence/artifacts/review-g04/probe_preconnected_mux.py`, two runs) refuted the earlier
summary "`-O stop`: admissions stopped". A development run of phase 5 on an earlier fixture
(`…/experiments/dev-fix-e7p-192131/`, exit 0) showed the same outcome.

## 2. Common substrate (all recipes)

Every candidate needs a **working key used by a signer that remains usable while the desktop
and the personal vault are locked**. The candidates differ in how a destination comes to
accept that key and in where deadlines and revocation are enforced. Facts that apply to all
of them:

1. **The agent protocol exposes use, not export.** RFC 9987 lists no message that returns
   private key material. Its stated design intent is that "an attacker with unprivileged access
   to their victim's agent should be prevented from gaining a copy of any keys", but "this may
   not preclude the attacker from stealing use of those keys" `[S:RFC9987 §8.1, §10]`.
   The protocol "does not include any authentication"; access control is socket permissions
   or peer identity checks `[S:RFC9987 §10]`. The socket "is easily abused by root or another
   instance of the same user" `[S:ssh-agent.1]`. **Consequence:** any signer endpoint is a
   same-user authority boundary, not a sandbox (spec §14.1, §13.2) `[I]`.
2. **A dedicated agent can be fully separated from the owner's.** `ssh-agent -a <path>` binds
   a chosen socket; `-U` prevents scanning or cleaning `$HOME/.ssh/agent`; the default socket
   location is `$HOME/.ssh/agent/s.*` on this OpenSSH `[S:ssh-agent.1]`. `IdentityAgent`
   overrides `SSH_AUTH_SOCK`, and `none` disables agent use `[S:ssh_config.5]`. Observed
   working with `HOME=<tmp> ssh-agent -U -a <tmp>/sock` `[O:F1][O:SMOKE-2]`.
3. **Agent-side lifetimes.** `ssh-add -t` sets a maximum lifetime `[S:ssh-add.1]`. A key added
   with `-t 20` could no longer sign 85 s later (rc 1) `[O:F1]`. Lifetimes are computed with
   `monotime()`, which uses `CLOCK_BOOTTIME`, else `CLOCK_MONOTONIC` `[S:misc.c, ssh-agent.c]`.
   On macOS, `CLOCK_MONOTONIC` "will continue to increment while the system is asleep"
   `[S:clock_gettime.3]`, so an agent lifetime would count sleep time and ignore wall-clock
   changes `[I]` (Apple's build configuration not inspected `[U]`, probe P4).
4. **Certificates in agents are removed late, so they are not an enforcement point.** By
   default `ssh-add` asks the agent to delete a certificate "shortly after" expiry
   `[S:ssh-add.1 -N]`. The source sets that to `valid_before + CERT_EXPIRY_GRACE` with
   `CERT_EXPIRY_GRACE = 5*60` s `[S:ssh-add.c]`. Observed: certificate still loaded 25 s
   after `valid_before` `[O:F1]`. Server-side validity is the enforcement point for new
   authentication `[S:ssh-keygen.1 CERTIFICATES "A certificate that is presented at a time
   outside this range will not be considered valid"]`.
5. **A CA key can live in a separate signer.** `ssh-keygen -U -s ca.pub` signs with a CA key
   held in an agent; `-D` uses a PKCS#11 token `[S:ssh-keygen.1]`. Observed on OpenSSH 10.3p1
   with the CA private file deleted after loading into a separate issuer agent `[O:F1]`.
6. **Server-side trust primitives.**
   - `TrustedUserCAKeys`: a certificate from a listed CA "may be used for authentication for
     any user listed in the certificate's principals list"; certificates without principals
     are refused `[S:sshd_config.5]`.
   - `AuthorizedPrincipalsFile`: restricts accepted principals. With the default `none`, "the
     username of the user must appear in a certificate's principals list" `[S:sshd_config.5]`.
   - Account-level trust: `cert-authority` lines in `authorized_keys`, with `principals="..."`
     ("at least one name from the list must appear in the certificate's list of principals")
     and `expiry-time="timespec"` (key not accepted after that time). Where certificate
     restrictions and key options both apply, "the most restrictive union of the two is
     applied" `[S:sshd.8]`.
   - `AuthorizedPrincipalsFile` "is not consulted for certification authorities trusted via
     ~/.ssh/authorized_keys" `[S:sshd_config.5]`.
   - Revocation lists (`RevokedKeys`, KRL) are an `sshd_config` setting `[S:sshd_config.5]`,
     so they need server administration and are not available with account-level trust alone
     `[I]`.
7. **Unknown critical options fail closed.** Unknown critical options cause refusal, while
   unknown extensions may be ignored. `-V` defaults to "valid from the Unix Epoch to the
   distant future" if unspecified `[S:ssh-keygen.1]`, so a managed issuer must always set
   `-V` `[I]`.
8. **Multiplexing control.** `ssh -O stop` asks the master "to stop accepting further
   multiplexing requests" `[S:ssh.1]`. Its release note: "removes its listener socket and
   refuse future multiplexing requests but don't kill existing connections"
   `[S:OpenSSH-RN-5.9]`, and `PROTOCOL.mux` §8 agrees. In the source the handler frees **only
   the listener channel** and clears the control path; with `ControlMaster ask/autoask` it first
   asks for confirmation `[S:mux.c]`. The session and forwarding handlers do not consult the
   listener state `[S:mux.c][I]`. A client using `ControlMaster no` "will fall back to connecting
   normally if the control socket does not exist" `[S:ssh_config.5]`. `ControlPersist` keeps an
   idle master up to a timeout and is not a grant timer `[S:ssh_config.5]` (spec §6.6). Observed
   on the host client (OpenSSH_10.3p1):
   - **Certificate expiry does not stop multiplexed admissions.** After `valid_before` a fresh
     login was refused, but a new session through the existing master was admitted with no new
     connection or authentication, also for a client with `PubkeyAuthentication=no` `[X:E7 H1,
     H1b]`.
   - **`-O stop` closes the door to new control connections only.** Afterwards the socket is
     gone, `-O check` fails, and a new client falls back to a fresh connection that is refused
     after expiry; the open session continues `[X:E7 H2a–H2c][X:E7R]`.
   - **A control connection the master accepted before `-O stop` keeps working after it.** It
     was granted a new session 2 s and 15 s after stop returned (after certificate expiry), and
     a local forward, a remote forward and a stdio forward, all with no new connection or
     authentication `[X:E7P H2e–H2h]` (independently first shown by the review probe). Any
     same-user process that reaches the control socket, or an ssh client caught between connect
     and request, holds such a connection `[I]`. So `-O stop` is **not** a tested mechanism that
     stops admissions (spec §6.6), and owned masters must be closed.
   - The stopped master exits after its last session only if no control connection is open; an
     idle pre-accepted connection kept it running with no session for 12 s `[X:E7 H2d][X:E7P
     H2d-held, H2d-exit]`.
   - **Closing works:** `-O exit` terminates the master, its sessions, pre-accepted control
     connections and later clients `[X:E7 H3][X:E7P H3c]`; SIGTERM to the exact master PID closes
     pre-accepted connections and the forward listeners `[X:E7P H3d]`. **Closing is not
     remote-process termination:** the remote no-tty shell of a session closed by `-O exit` was
     still running 7 s and 20 s later `[X:E7 H3b]`.
   - Not tested: `MUX_C_PROXY`, dynamic and streamlocal forwards (expected alike `[I]`); other
     OpenSSH versions; detached (`nohup`/`setsid`) remote processes.
9. **Destination-constrained agent keys.** `ssh-add -h` constraints are enforced "by
   ssh-agent ... when a key is used, or when it is forwarded by a cooperating ssh(1)". They do
   not stop an attacker with a remote `SSH_AUTH_SOCK` from re-forwarding "to a permitted
   destination" `[S:ssh-add.1]`. The session-bind extension binds an agent connection to a
   host key `[S:PROTOCOL.agent]`. This is an "authenticated agent restriction" (spec §4.3),
   still inside the same-user boundary `[I]`.
10. **The fixed-provider baseline does not survive lock.** For 1Password, "The SSH agent
    doesn't keep your private keys in memory when 1Password is locked ... the app needs to be
    unlocked for the agent to access your private keys" `[S:1P-Security]`. This is why a
    managed lifecycle is needed (spec §7.1); a relay cannot fix it (plan G04 failure action).

## 3. Candidate recipes

Notation: **K_env** = the working key of one execution environment. **K_ca** = a per-user
issuer key. **C** = an OpenSSH user certificate. **G** = a grant with deadline **D** and
resolved destination/account scope.

### 3.1 Recipe A: protected per-environment execution key, supervised signer, account-level enrollment

```text
   owner (present, approves)                destination account (capability 2, spec §7.4)
        |  enrollment transaction §7.5             ~/.ssh/authorized_keys  (or the account's
        |  using EXISTING access  ───────────────▶   real registry): one line per environment
        |                                            restrict,[from=...],[expiry-time=...] K_env.pub  heimdall:<marker>
        v
 Heimdall runtime in environment E ──generates──▶ K_env ──stored in──▶ platform store S_E (§5)
        |                                                    │ load at supervisor start
        v                                                    v
 signer endpoint (agent protocol, owner-only socket/pipe) holds K_env (memory or HW handle)
        ▲   checks per signature: grant G active? now < D? pause/cutoff? purpose = ssh-auth?
        │
 ordinary ssh / git (IdentityAgent=<binding endpoint>, IdentitiesOnly=yes)
```

| Question | Recipe A |
|---|---|
| Who can issue | Nobody; no issuer. Authority is created by the **enrollment act**: a remote write made with the owner's existing access. Every new destination/account and every rotation is another remote write. |
| Who can sign | The environment's signer, and any same-user process that can reach its endpoint `[S:RFC9987 §10][S:ssh-agent.1]`. Heimdall would check the grant per signature (proposed). |
| What can be exported | A software K_env in a file keychain, DPAPI blob or Secret Service item can be read by same-user code with access to that store item `[I]`. It is non-exportable only if hardware-backed: Secure Enclave keys cannot leave the enclave and are P-256 only `[S:Apple-SEKeys]`; TPM keys "can never leave the TPM" `[S:MS-TPM]`. The agent protocol itself exports nothing `[S:RFC9987]`. |
| What persists | K_env in S_E; one authorized-key line per enrolled account (remote); Heimdall state (grants, tombstones, enrollment inventory). |
| Where deadlines are enforced | **Local only.** The signer refuses after D, a pause or a cutoff (proposed). Optional secondary bound: `ssh-add -t` lifetime in a stock agent `[S:ssh-add.1][O:F1]`. The server knows no deadline unless `expiry-time=` was written at enrollment `[S:sshd.8]`, and that value is static: extending or rotating it is a remote write. |
| If the controller disappears | An environment-local signer continues with no refresh dependency, so offline coverage is unlimited `[I]`. This is good for G07, bad for revocation. |
| If an issuer disappears | Not applicable. |
| Revocation | Local: immediate (signer refuses; tombstone). Remote: delete the line on each account. Unreachable accounts stay `remote_pending`. |
| Residual window | **New authentication:** unbounded for a copied software K_env until the line is removed; bounded by `expiry-time` if set; for a non-exportable K_env, as long as the device itself can be driven to sign `[I]`. **Live connections and remote processes:** not bounded by the key or its line, as in B `[X:E7][X:E7P]` (removing the line does not close established connections `[I]`, untested). |
| Lost device | From another device with access, remove the lost environment's line on every enrolled account (needs the enrollment inventory, spec §7.7). Offline destinations stay exposed until reached `[I]`. |
| Principal scope, two CA-trusting hosts | No CA, so the CA-scope mistake cannot occur. Scope is exactly the set of accounts holding the line. An account without the line rejects the key `[S:sshd.8 AUTHORIZED_KEYS]`. If the same K_env is enrolled on many accounts, it works on all of them; that is explicit but broad. |
| Narrower delegation (A28) | Needs either a per-child key **and** per-child enrollment (remote write per child), or signer-side restriction: a per-binding endpoint plus destination constraints via session-bind `[S:PROTOCOL.agent]`. Signer-side restriction is same-user unless isolated (spec §8.7). |

### 3.2 Recipe B: OpenSSH user certificate on a protected working key, separated per-user issuer

```text
 owner approval (present) ──▶ grant G {scope: (dest d, account a)…, deadline D, policy rev}
                                   │ issuance request (authenticated, scope+deadline checked)
                                   v
 ISSUER process (per user; separate endpoint, never exposed to projects/workers)
   K_ca in store S_ca (software) or hardware (SE CTK / TPM / token via PKCS#11)
   signs C = cert(K_env.pub, principals = { "hm:<d-id>:<a>" … }, valid = [now-skew, min(D, cutoff)],
                  key_id = <grant/env id>, no unknown critical options)
                                   │ C is public; delivered to the environment
                                   v
 environment E signer: K_env (as in A) + C ──▶ ssh (IdentitiesOnly, CertificateFile/agent cert)
                                                     │
 destination trusts K_ca.pub (enrolled once):        v
   capability 2: account line  cert-authority,principals="hm:<d-id>:<a>"[,expiry-time=…] K_ca.pub
   capability 3: TrustedUserCAKeys + AuthorizedPrincipalsFile mapping account → "hm:<d-id>:<a>"
   sshd checks validity + principal on EVERY new authentication
```

| Question | Recipe B |
|---|---|
| Who can issue | Whoever holds K_ca: the issuer process, plus anything that can drive its issuance API or read S_ca. Spec §14.2 requires a narrow, authenticated issuance API that verifies scope and deadline. A same-user process that can reach the issuer endpoint is inside the issuer's compromise boundary unless the issuer runs under a separate OS account, on another host, or behind user presence (spec §7.3). |
| Who can sign (authentication) | The environment signer holding K_env, as in A. |
| What can be exported | Certificates are public. K_env as in A. K_ca must never reach a worker or a project endpoint (R-CR-04). A software K_ca is readable by same-user code with store access `[I]`; a hardware K_ca is not exportable `[S:Apple-SEKeys][S:MS-TPM]`. A P-256 CA key can be used through PKCS#11 (`ssh-keygen -D`) `[S:ssh-keygen.1]`, and macOS 27 can create non-exportable Secure Enclave CTK identities exposed to ssh through `ssh-keychain.dylib` `[S:sc_auth.8][S:ssh-keychain.8]`. Such a `-t none` identity loaded into a dedicated ssh-agent (via `ssh-add`) only through the FIDO-style provider path (as `sk-ecdsa`), not through PKCS#11, and the agent signed with it without needing a prompt `[O:P5][O:P5-V3]`; with a fixture-CA certificate for its public key, a fresh login to the fixture through that agent succeeded while the screen was unlocked `[O:P5-V3]`. Using it as K_ca (`ssh-keygen -s` with an sk key) was not tested. Behavior while locked, or without a GUI login, is `[U]` (P5 lock row). |
| What persists | Trust lines/config on destinations (one per account or per server, long-lived); K_ca; K_env; certificates until expiry. |
| Where deadlines are enforced | **Server-side**, at every new authentication, through `valid_before` `[S:ssh-keygen.1]`; observed rejection of expired and not-yet-valid certificates on the fixture `[OX:M00-T03 smoke, tests/fixtures/MANIFEST.md row 3]`. **Locally**, the signer refuses after D, a pause or a cutoff (proposed). The agent's own certificate removal lags by up to 5 min and is not enforcement `[S:ssh-add.c][O:F1]`. |
| If the controller disappears | Issued certificates stay valid to `valid_before`, so the environment can keep authenticating until then without the controller `[I]`. New certificates need the issuer. Offline coverage = remaining validity (spec §6.5). For a runner job, issue for the whole grant or arrange a reachable issuer (G07). |
| If the issuer disappears | No new certificates. Existing work continues to `valid_before`, then new authentication fails closed (`CAPABILITY_UNAVAILABLE`). Falling back to another key is prohibited (spec §15.2). |
| Revocation | Local: immediate (signer refuses; issuer refuses further certificates for the grant or environment). Remote: account-level trust has no KRL; `RevokedKeys` needs `sshd_config` control `[S:sshd_config.5][I]`. Emergency "revoke everything" at account level = remove the `cert-authority` line (remote write). |
| Residual window | Spec §6.5 asks for the maximum residual remote-access window; spec §6.6 separates its parts, and they have different bounds. **(1) New authentication:** ≤ remaining validity of the newest certificate issued for that key: ≤ D ≤ the default 12 h window (spec P04) `[S:ssh-keygen.1][X:E2]`. With capability 3 plus a distributed KRL it can be shorter (not in the minimal recipe). **(2) Live connections and their admissions:** **not bounded by the certificate.** An authenticated connection or master keeps carrying new sessions and forwards after `valid_before`, even for clients that hold no credential `[X:E7 H1, H1b]`, and `-O stop` does not stop admissions on control connections it already accepted `[X:E7P]`. For Heimdall-owned connections the bound is when Heimdall closes them: masters closed at D by `-O exit` or exact-PID termination `[X:E7 H3][X:E7P H3c, H3d]`, dedicated connections closed only under the strict policy (the draft graceful policy keeps them, spec §6.6). That bound holds only while the Heimdall supervisor on that device runs `[I]`. Unmanaged connections (not made through Heimdall) are not bounded by the recipe. **(3) Remote processes:** not bounded; closing a connection does not terminate its remote no-tty shell `[X:E7 H3b]`. |
| Lost device | **Lost environment:** issue nothing more to its K_env. **New authentication** with its outstanding certificates ends within part (1) of the residual window, with no remote write `[X:E2]`. **Connections that are live on the lost device** stay usable while that device runs and the connection stays up, whatever the certificate validity `[X:E7 H1, H1b]`. They are bounded only if the lost device's own Heimdall closes them, which cannot be relied on for a stolen, running device `[I]`. Removing the CA trust line does not close established connections either (sshd checks authorization when authenticating) `[I]`, untested. Remote processes it started continue `[X:E7 H3b]`. **Lost issuer host:** if K_ca is software, assume compromise. Remove the CA trust from every destination and enroll a new CA (blast radius = every account trusting K_ca) `[I]`. A hardware K_ca turns this into "the thief must operate the unlocked device" `[I]`. |
| Principal scope, two CA-trusting hosts | **This is the main risk.** If both hosts trust K_ca and the certificate carries a generic principal (the account name), it authenticates on both: with `TrustedUserCAKeys` and no principals file, the username suffices `[S:sshd_config.5]`. The same holds for an account-level `cert-authority` line without `principals=`; the exact principal check for that case is inferred from the `sshd.8` / `sshd_config.5` wording `[I]`, to be tested in E4. Mitigation (proposed): one unique principal per destination/account (`hm:<destination-id>:<account>`), accepted only by that destination (`principals=` or the principals file); the issuer refuses multi-destination principals unless the grant covers all of them. The fixture shows a p-host1 certificate accepted by ca1 and rejected by ca2, and a two-principal certificate accepted by both `[OX:M00-T03 smoke]`. |
| Narrower delegation (A28) | A child gets its own ephemeral key plus a certificate with a subset of principals and an earlier `valid_before`. The server enforces both, with no remote write per child `[I]` (E5 tests it). |

### 3.3 Recipe C: integrate an existing issuer (Smallstep step-ca)

```text
 step-ca server (always-on, reachable; holds its own CA keys)  ◀── provisioner auth ──  client in environment E
   provisioners: OIDC (browser), JWK (password-decrypted key), X5C (client cert), SSHPOP, …      `step ssh certificate|login`
   claims: user cert default 16h [tutorial]; min/max/default are configurable claims             adds cert+key to an agent
 destinations: TrustedUserCAKeys (tutorial flow, admin)  — or account-level cert-authority lines (manual)
```

| Question | Recipe C |
|---|---|
| Who can issue | step-ca, for any client that passes a provisioner. In the tutorial a JWK provisioner asks for "the password to decrypt the provisioner key" `[S:Step-Tutorial]`; OIDC is offered for identity-provider login `[S:Step-Tutorial]`. |
| Who can sign | The environment's key, held in an agent (`step ssh login` "adds a SSH certificate into the authentication agent") `[S:Step-SSH-Login]`. |
| What can be exported | Certificates (public); K_env per client handling. **Unattended refresh needs a provisioner credential in the environment** (JWK password/key, X5C client key). That credential is issuance authority, bounded only by provisioner policy and templates `[I]` (escalation Q1). "By design, SSH user certificates cannot be renewed by any provisioner"; a fresh certificate means re-authenticating to a provisioner `[S:Step-Provisioners]`. `step ssh renew` renews **host** certificates `[S:Step-SSH-Renew]`. |
| What persists | The step-ca deployment and database; host trust config; the provisioner credential, if unattended. |
| Where deadlines are enforced | Server-side certificate validity, as in B. "The default lifetime of an SSH certificate from step-ca is 16 hours" `[S:Step-Tutorial]`. The claims `minUserSSHCertDuration`, `maxUserSSHCertDuration` and `defaultUserSSHCertDuration` bound it; the documentation's **example** configuration sets them to 5m / 24h / 16h `[S:Step-Config]`, so the limits of a given deployment are its own configuration `[I]`. |
| If the controller disappears | Continues while step-ca is reachable from the environment and a usable provisioner credential is present `[I]`. |
| If the issuer disappears | As in B: work continues to `valid_before`, then fails closed. |
| Revocation | `step ssh revoke` exists `[S:Step-SSH-Revoke]`. sshd only consults `RevokedKeys` `[S:sshd_config.5]`; whether step-ca revocation reaches sshd without KRL distribution is `[U]`. The documentation's "passively revoked ... valid until it expires" sentence is about **admin** certificates `[S:Step-Provisioners]`, not SSH. |
| Residual window | New authentication: ≤ certificate validity (16 h default) unless a KRL is distributed. Live connections and remote processes: as in B, not bounded by the certificate. |
| Lost device | Disable its provisioner credential or account; outstanding certificates expire. |
| Principal scope, two CA-trusting hosts | As in B. Note: "If no principals are passed we will use the identity as a principal" `[S:Step-SSH-Login]`, which is broad by default `[I]`. Needs templates or policy plus per-destination principal mapping. |
| Extra cost | Another always-on service to operate and expose to every environment that refreshes; admin-level host configuration in the documented flow; Apache-2.0 license `[S:Step-License]`. The spec makes it optional (§7.6). |

### 3.4 Custody rules per recipe (spec §7.3)

Spec §7.3 requires, for every private-key class: generation, storage, unlocking, use while
locked, loss, rotation, backup policy, destruction, and recovery. The table below gives the
proposal per class. "Store" means the platform store chosen per §5 after the probes.
Plaintext fallback is prohibited for every class.

| Key class | Generation | Storage | Unlocking | Use while locked | Loss | Rotation | Backup policy | Destruction | Recovery |
|---|---|---|---|---|---|---|---|---|---|
| **A: K_env** | Heimdall, per environment, at enrollment; never imported from the personal vault | Store, or hardware (P-256) | At supervisor start in the user session (store-specific; §5) | Signer holds the key in memory or as a hardware handle and checks the grant per signature; depends on P1-class evidence | Remove its line from every enrolled account | New key + new line everywhere, then retire the old line (A09 flow): N remote writes | None. Environment-local; reenroll on replacement. Recovery bundle holds public metadata only (spec §7.7). | Delete the store item; signer drops its copy; remove remote lines. A software copy taken earlier cannot be recalled `[I]`. | New environment identity + enrollment through existing access |
| **B: K_env** | Same as A; may be ephemeral per grant or child | Same as A, or memory-only for ephemeral keys | Same as A | Same as A, plus a certificate issued at approval that covers the grant | Stop issuing to it; new-authentication residual ≤ certificate validity; live connections and remote processes are not bounded by it (§3.2) | **Free:** new key + new certificate, no remote write | None | Delete; certificates expire by themselves | New key + new certificate |
| **B: K_ca** | Heimdall issuer on the owner-chosen issuer host; P-256 if hardware-backed | Separate store item or hardware, **never** reachable from project or worker endpoints | At issuer start; may require user presence if issuance only happens at approval time (decision D1) | Needed only if new grants must be issued while locked (D1) | Treat as compromise: remove trust lines everywhere, new CA | Add a new CA line beside the old one, switch issuance, remove the old line after the maximum validity | **Owner decision D5** (proposal: none; reenroll on loss) | Delete K_ca; remove trust lines | New CA + reenrollment through existing access |
| **C: provisioner credential** | Created in step-ca by its admin | Store in the environment, if unattended | At start | Needed for refresh while locked | Revoke the provisioner or key in step-ca | step-ca procedure | step-ca's | step-ca's | step-ca's |
| **Certificates (B, C)** | Issuer | Next to the key handle; public | Not applicable | Not applicable | Not applicable (public) | Reissue | Not needed | Expire | Reissue |

## 4. Comparison

| Criterion | A | B | C |
|---|---|---|---|
| New authentication stops at the deadline without the local signer (R-AU-05, §6.6) | No (only static `expiry-time`) | **Yes**, server-checked `valid_before` | Yes |
| Bounded residual window after revocation or loss, **new authentication** (R-AU-04, §6.5, A07) | No (unbounded until remote removal) | **≤ certificate validity ≤ D** `[X:E2]` | ≤ certificate validity (default 16 h) |
| Residual window, **live connections and remote processes** (§6.5, §6.6, A23) | Not bounded by the credential. Owned connections: until Heimdall closes them; unmanaged connections and remote processes: unbounded | Same as A `[X:E7][X:E7P]` | Same as A |
| Issuer authority kept out of workers and projects (R-CR-04, A10) | Trivially (no issuer) | Must be engineered; testable (E5) | Provisioner credential on workers if unattended (Q1) |
| Per-destination scope claim (R-CR-07) | Enrollment set (explicit) | Unique principals + server mapping (E3/E4) | Same as B, broad by default |
| Remote writes per new environment, rotation or child | One per account, each time | One per account, **once** (CA line); none afterwards | Host admin once |
| Narrower delegation enforced by servers (R-AU-07, A28) | Needs per-child enrollment | Child certificate | Child certificate via provisioner |
| Lock continuity within an approved grant (R-CR-02, A03) | Needs a K_env signer that works under lock | Same, **plus nothing** if the certificate covers the grant | Same, plus provisioner credential if refreshing |
| Works with servers lacking OpenSSH user certificates | **Yes** | No | No |
| Extra infrastructure | None | Issuer process (local) | Always-on step-ca service |
| Offline coverage for a remote runner (G07) | Unlimited (revocation weak) | = certificate validity (explicit tradeoff, §6.5) | = certificate validity |

## 5. Platform secret stores: availability under screen lock, logout, reboot, headless

Each cell gives the source or label. "Unsigned CLI" means a binary without Apple/Microsoft
code-signing entitlements, which is the default for a freshly built Heimdall prototype.

### 5.1 macOS

| Store | Screen lock | Logout | Reboot (before login) | Headless (launchd daemon / no GUI login) | Unsigned CLI? |
|---|---|---|---|---|---|
| **Dedicated ssh-agent memory** (what P1 measures) | `[U]` (P1); an ordinary user process keeps running `[I]` | The process ends with the session `[I]`; key must be reloaded | Gone `[I]` | Runs if launched by a launchd agent or daemon, but needs a key source `[I]` | Yes `[O:SMOKE-2]` |
| **File-based custom keychain** (P1 measures it with auto-lock disabled) | `[U]` (P1). Per-keychain settings include lock on sleep and lock after timeout `[S:security.1]`. New keychains default to `lock-on-sleep timeout=300s` `[O:K1]`, so Heimdall must set them explicitly | File persists; locked again `[I]`; needs its password to unlock, which must come from another store or from the user `[I]` | `[U]` (P3); with FileVault, the user volume is unavailable before login `[U]` (not sourced here) | Allowed: programs "outside of a user context, like a launchd daemon, must target the file-based keychain" `[S:TN3137]` | Yes `[O:K1]`. `SecKeychainCreate` deprecated since the macOS 12 SDK; file-based keychain "on the road to deprecation" `[S:TN3137]`. On macOS 26.4+ a keychain file may depend on a protected entropy file in `/var/db/SystemKeys` `[S:TN3137]` |
| **Login keychain** | Not used and not touched by Heimdall tests (boundary). Behavior `[U]` | — | — | — | — |
| **Data-protection keychain** (SecItem + `kSecUseDataProtectionKeychain`) | Accessibility classes: `WhenUnlocked` is the default, "accessed only while the device is unlocked" `[S:Apple-WhenUnlocked]`; `AfterFirstUnlock` stays accessible "until the next restart", for background use `[S:Apple-AfterFirstUnlock]`. **But on macOS:** "Data Protection isn't used directly to enforce these guarantees" `[S:Apple-PS-Keychain]`, and on Apple-silicon Macs "a security boundary is established around logging in and out (not locking or unlocking as on iPad and iPhone)" `[S:Apple-PS-DPClasses]`. Exact `WhenUnlocked` behavior at macOS screen lock `[U]` (P6) | Class A keys discarded "shortly after the last user is logged out" `[S:Apple-PS-DPClasses]`; DP keychain "only available in a user login context" `[S:TN3137]` | `AfterFirstUnlock`: not before first unlock `[S:Apple-AfterFirstUnlock]` | **Not available** to daemons `[S:TN3137]` | **No.** Access groups come from code-signing entitlements "authorized by a provisioning profile"; this needs an app-like bundle `[S:TN3137]`. Probe P6 is blocked on signing |
| **Secure Enclave key via SecItem** | `[U]`; Apple's example uses `WhenUnlockedThisDeviceOnly` and says other options suit apps that operate "in the background" `[S:Apple-SEKeys]` | As the DP keychain `[I]` | As the DP keychain `[I]` | No `[I]` | **No.** Requires the data-protection keychain `[S:TN3137]`; P-256 only; existing keys cannot be imported `[S:Apple-SEKeys]` |
| **Secure Enclave CTK identity** (`sc_auth create-ctk-identity -k p-256-ne`) used through `ssh-keychain.dylib` | `[U]` (P5 lock row, needs an owner lock cycle) | `[U]` | `[U]` | `[U]` (the unlocked runs were in agent processes, a launchd Background session in v1 and an Aqua session in v3; a LaunchAgent or daemon was not measured; see the paragraph below) | **Loads through the FIDO-style path only** `[O:P5][O:P5-V3]`: `ssh-add -K -S /usr/lib/ssh-keychain.dylib` loads the key as `sk-ecdsa-sha2-nistp256@openssh.com`; `ssh-add -s` (PKCS#11) loads nothing for it, matching ssh-keychain(8) (PKCS#11 serves RSA) `[S:ssh-keychain.8]`. Unlocked, it signed in a dedicated agent and a fresh certificate login to the fixture through that agent succeeded `[O:P5-V3]`. `KEYCHAIN_CERTIFICATES` did **not** limit the FIDO-style load, in both runs `[O:P5][O:P5-V3]`. With a terminal attached, the load waits on a PIN prompt unless askpass is forced `[O:P5-H2]`. Non-exportable "-ne" keys are protected by the Secure Enclave; `-t bio` or `-t none` sets per-use protection `[S:sc_auth.8]`. Writes the real user token store, so it needs owner authorization (D4). `ssh-agent -P /usr/lib/ssh-keychain.dylib` accepted the provider `[O:P5]` |
| **1Password SSH agent** (fixed provider) | Private keys not held while 1Password is locked; app must be unlocked `[S:1P-Security]` | — | — | — | Not a managed store; reported as interaction-required (A11) |

**P5, unlocked run (v3 2026-10-31, v1 2026-10-09; record `g04-macos-secure-enclave-ctk-probe.json`).**
Two runs, each with the screen unlocked (IORegistry, 3/3 samples) and one identity in the real user
token store (owner decision D4). The current evidence is the v3 run `[O:P5-V3]`: probe v3,
2026-10-31T20:09:28Z, macOS 27.0.1 (26A434), an agent process in the launchd **Aqua** session. The v1
run `[O:P5]` (2026-10-09, macOS 27.0 (26A428), launchd **Background** session) stays as history; the
items below say where it agrees. Each item is `[O:P5-V3]` unless marked otherwise. Record status:
**blocked** (lock row). Unlocked row: `verified`, verdict **fail**.
- **Creation:** `sc_auth create-ctk-identity -k p-256-ne -t none` succeeded in under a second (rc 0;
  v1 the same). It needed no prompt: with stdin `/dev/null` and askpass forced, nothing blocked.
  Whether a non-blocking notification appeared on screen is not observable to the probe.
- **Load paths (both runs):**
  - `ssh-add -s` (PKCS#11) loaded nothing: "agent refused operation".
  - `ssh-add -K -S` loaded one `sk-ecdsa-sha2-nistp256@openssh.com` key into the dedicated agent.
    Its fingerprint equals `sc_auth list-ctk-identities -t ssh`, and SHA-1 of its EC point equals
    the CTK public-key hash.
- **Signing (both runs):** the agent signed in every setup check and in 3/3 samples (`ssh-add -T`,
  `ssh-keygen -Y sign`, `check-novalidate`).
- **Limit (fail, reproduced):** with a random non-matching `KEYCHAIN_CERTIFICATES`, `ssh-add -K -S`
  again loaded one key (control agent: load rc 0, 1 key), so the variable did not select identities
  on this path, on two OS builds and two launchd sessions. The control's key fingerprint was not kept
  in either run. It was presumably the run's own identity, because the store held no other CTK
  identity and no smart card was reported `[I]`. With other ecdsa256 identities present (CTK
  identities, smart cards or other tokens, all served by ssh-keychain.dylib `[S:ssh-keychain.8]`), it
  would presumably load them all `[I]`. Not tested: whether the variable is read at all on this path,
  and a store with two or more identities.
- **Export (both runs):** `export-ctk-identity` wrote no file and printed "hardware bounded and
  cannot be exported", but exited 0.
- **Fixture login (measured in v3; unmeasured in v1):** a fresh certificate login to ca1 through the
  dedicated agent succeeded in the setup check and in 3/3 samples, with a default-extension
  certificate (principal `p-host1`, `-V -1m:+10m`). ca1's log shows 4 `Accepted publickey ...
  ECDSA-SK-CERT` lines carrying the agent key's fingerprint. Both controls were refused (rc 255): ca2
  (principal mismatch) refused the offer at the query stage, and ca1 with `IdentityAgent=none`
  accepted the certificate at the query stage but the client had no private key to sign with. The v1
  failure was a probe defect: without `SecurityKeyProvider` ssh ignored the sk certificate and never
  offered the key `[O:P5][O:P5-OFFER]`; v3 sets it. sshd accepted without the `no-touch-required`
  option, logged no user-presence line, and the fixture sets no `PubkeyAuthOptions`, so the
  signature presumably carried the user-presence flag `[I]`; the flag itself was not observed. The
  `no-touch-required` certificate was not needed and not issued.
- **Deletion (both runs):** in the one check right after `delete-ctk-identity` (same log second in
  v3), the agent still listed the key but could not sign with it (`ssh-add -T` rc 1, `-Y sign`
  rc 255). A certificate issued for the key is not revoked by the delete and would stay valid until
  it expires `[I]`.
- **Cleanup:** in-run, the identity list equalled the pre-run list (0 identities) and the
  AuthenticationAuthority digest was unchanged. The orchestrator reports 0 identities listed after
  the v3 run; no file of that was kept.
- **Not measured:** screen lock (the lock row needs the owner at the console); `-t bio`; a LaunchAgent
  or daemon context; using the CTK key as K_ca.
- **Disclosure:** the v1 record said a v3 real-store run needed confirmation that D4 covers it. The
  orchestrator ran v3 relying on the note in `progress.md`, without that confirmation. The identity was
  deleted by its exact hash and the store matched its pre-run state. Open owner question: does D4
  cover further real-store runs, including the lock run?
- **Consequence for Heimdall `[I]`:**
  - A CTK working key loads only through the FIDO-style provider. Loaded that way, in an unlocked
    Aqua session with one identity and `-t none`, it signed and logged in to the fixture with a
    CA-signed certificate.
  - Heimdall would have to select the key itself (for example, add one downloaded key handle)
    rather than rely on `KEYCHAIN_CERTIFICATES`.
  - Lock behavior is still `[U]`.

### 5.2 Windows

| Store | Workstation lock (Win+L) | Sign-out | Reboot (before logon) | Headless / service | Notes |
|---|---|---|---|---|---|
| **DPAPI user scope** (`CryptProtectData`) | `[U]` (P-W1). Decryption needs "the same logon credential" `[S:MS-CryptProtectData]`; the logon session persists while locked `[I]` | `[U]` | `[U]` | `CRYPTPROTECT_UI_FORBIDDEN` exists for no-UI contexts `[S:MS-CryptProtectData]`. `CRYPTPROTECT_LOCAL_MACHINE` lets **any local user** decrypt `[S:MS-CryptProtectData]`, so it is unacceptable for user secrets `[I]`. Service-context behavior `[U]` (P-W2) | The prompt-based flow is "deprecated and will be removed in February 2027" `[S:MS-CryptProtectData]` |
| **Credential Manager** (`CredWrite`/`CredRead`) | `[U]` (P-W1) | `CRED_PERSIST_SESSION` "will not exist after this user logs off"; `LOCAL_MACHINE` persists for later sessions of the same user on that computer `[S:MS-CREDENTIAL]` | `LOCAL_MACHINE` persists `[S:MS-CREDENTIAL]`; usable before logon `[U]` | "Network logon sessions do not have an associated credential set" `[S:MS-CredWrite]`, so a runner reached over SSH with a network logon cannot use it `[I]` | — |
| **CNG with TPM** (Platform Crypto Provider) | `[U]` (P-W1) | `[U]` | Keys persist `[S:MS-NCryptCreatePersistedKey]` | `NCRYPT_MACHINE_KEY_FLAG` gives machine keys `[S:MS-NCryptCreatePersistedKey]` (machine scope, not user) | TPM keys non-exportable ("can never leave the TPM") `[S:MS-TPM]`; export policy flags `[S:MS-KSP-Props]`; optional UI policy `[S:MS-KSP-Props]`; TPM anti-hammering lockout `[S:MS-TPM]`. Ed25519 support `[U]` |
| **Windows OpenSSH ssh-agent service** | `[U]` (P-W1) | `[U]` | Service can start at boot `[S:MS-OpenSSH-Keys]`; usable before logon `[U]` | Machine-global service; named-pipe scoping is a G03 question | Keys stored "within a Windows security context that's associated with your Windows account"; private key "can't be retrieved from the agent when a strong algorithm ... is used" `[S:MS-OpenSSH-Keys]` |

### 5.3 Linux

| Store | Desktop screen lock | Logout | Reboot | Headless (no desktop session) | Notes |
|---|---|---|---|---|---|
| **Secret Service** (gnome-keyring, KWallet) | `[U]` (P-L1). The spec lets a service "lock previously unlocked items for any reason at any time ... in response to user actions, timeouts, or external actions (such as the computer sleeping)" `[S:FDO-SS-Locking]`; implementation-specific | gnome-keyring PAM unlocks the login keyring at login; if the PAM module started the daemon, "it is killed" when the PAM session closes `[S:GNOME-Keyring-PAM]` | Locked until next login `[I]` | Unavailable unless something unlocks it, which needs the login secret `[I]` | A locked item's secret "cannot be accessed" `[S:FDO-SS-Locking]` |
| **Kernel user keyring** | No coupling to desktop lock `[I]` (P-L1 to confirm) | Kept while any process of that UID runs `[S:user-keyring.7]`; the session keyring is typically revoked by PAM at logout `[S:session-keyring.7]` | Gone (kernel memory) `[I]` | Usable by a lingering user service `[I]` | keys "require unswappable kernel memory" and a `user` key "is kept entirely within kernel memory" `[S:keyrings.7]`; same-UID processes have access (same-user boundary) `[S:keyrings.7][I]` |
| **Kernel persistent keyring** | As above | Survives logout; expires after `persistent_keyring_expiry` (default 259200 s = 3 days), reset on each access `[S:persistent-keyring.7][S:keyrings.7]` | Gone `[I]` | Usable `[I]` | — |
| **systemd-creds** | Not coupled `[I]` | Encrypted file persists `[S:systemd-creds.1]` | Decryptable with the original TPM2 and/or host key `[S:systemd-creds.1]` | System-scoped credentials suit services at boot; `--user` (since systemd 256) binds UID, user name and machine-id `[S:systemd-creds.1]` | The host key is root-only; user-scope decryption goes through system services `[U]` |
| **TPM2 via tpm2-pkcs11** | `[U]` | `[U]` | Key persists in the TPM-backed store `[I]` | Needs TPM device access `[U]` | Works as an ssh PKCS#11 provider (`ssh-keygen -D libtpm2_pkcs11.so`) `[S:tpm2-pkcs11-SSH]` |
| **Dedicated ssh-agent memory** | `[U]` (P-L1); ordinary process `[I]` | Ends with the session unless lingering/supervised `[I]` | Gone | Yes, if supervised `[I]` | — |

**Cross-platform reading:** `[I]` On every platform, a signer process that already holds the
key in memory should not be affected by screen lock. The open questions are (a) whether the
store it loads from can be read again after the signer restarts during a lock, logout, reboot
or in a headless context, and (b) whether that custody is acceptable (decision D2). P1, P-W1
and P-L1 measure (a) for screen lock.

## 6. What the lock-continuity requirement actually needs

Spec §6.4 and C05 require that **approved work** continues to its deadline through lock.
A03's pass condition is fresh authentications before the deadline after lock. Two cases:

1. **Within an approved grant:** the grant is approved while the owner is present. With
   Recipe B, the issuer can issue a certificate covering the whole grant at approval time.
   During the lock, only the **working-key signer** must keep working. The issuer key can then
   be strongly protected (even presence-gated), because it never signs while the desktop is
   locked `[I]`.
2. **New grants while locked** (standing policy activating new work at 03:00 while the
   desktop is locked, spec §5.3): the issuer must sign under lock, or new work reports
   `interaction-required`. The spec does not say which is required. This is decision D1.

Shorter certificate chunks (for example 1 h, renewed under lock) would shrink the
new-authentication part of the residual window (§6.5 tradeoff), not live connections, but they need the issuer under lock and reduce a runner's offline
coverage to the chunk length.

## 7. Recommended minimal V1 recipe (pending experiments; not a decision)

**Recommendation: Recipe B, account-level form ("B1").**

- Each execution environment has its own protected working key K_env, held by a
  Heimdall-supervised signer on an owner-only endpoint. The signer checks the grant, pause
  and cutoff per signature. K_env is P-256 hardware-backed where a probe shows it is usable;
  otherwise it is a software key in the platform store selected by the §5 probes.
- One per-user issuer key K_ca lives in a separate issuer process. Its endpoint is never
  exposed to projects, workers, containers, or forwarded agents.
- Destinations trust K_ca through one account-level line written once through the §7.5
  enrollment transaction:
  `cert-authority,principals="hm:<destination-id>:<account>" K_ca.pub <marker>`. The system
  form (`TrustedUserCAKeys` + `AuthorizedPrincipalsFile`) is used only where the owner
  administers the host.
- Certificates carry exactly one destination/account principal per enrolled pair, an
  explicit `-V`, and `valid_before = min(grant deadline, cutoff)`. They are issued at
  approval time and cover the grant (default ≤ 12 h). The issuer refuses unknown critical
  options and principal sets wider than the grant.
- Recipe A is not part of the minimal claim. A shares the entire signer substrate, so it
  remains a cheap, explicitly labeled fallback for destinations without OpenSSH certificate
  support (falsifier F-5).

**Reasons**, each tied to evidence:

1. **The server enforces the end of new authentication** independent of the local signer
   (R-AU-05; spec §6.6) `[S:ssh-keygen.1][OX:M00-T03]`. Recipe A cannot do this without
   remote edits.
2. **A stateable bound on new authentication** after revocation or device loss: ≤ certificate
   validity ≤ D (R-AU-04, A07; spec §6.5 requires the recipe to state the residual window)
   `[X:E2]`. Recipe A's is unbounded. This bound covers **new authentication only**. The
   residual window B1 must state also has a live-connection part, bounded only by Heimdall
   closing the connections it owns, and a remote-process part. Unmanaged connections and remote
   processes are not bounded by any candidate recipe `[X:E7][X:E7P]` (§3.2 "Residual window";
   escalation Q4). Certificate validity must not be quoted as the whole residual window.
3. **Lock continuity reduces to the working-key signer** for approved grants (§6, case 1).
   That is the narrowest thing the lock probes must prove, and it is shared with every other
   candidate (§6, case 1).
4. **Account-level enrollment suffices** (spec §7.4 capability 2) `[S:sshd.8]`. After one CA
   line per account, rotation, new environments and delegation need no remote writes (A09
   blast radius shrinks).
5. **Issuer separation is mechanically available and testable** (R-CR-04, A10): OpenSSH signs
   certificates with a CA key that exists only inside a separate signer `[O:F1]`, or inside a
   PKCS#11 token `[S:ssh-keygen.1]`.
6. **Per-destination scope is server-enforced** with unique principals and is testable on the
   existing fixture (R-CR-07) `[OX:M00-T03]`. Delegation attenuation is server-enforced too
   (R-AU-07, A28).
7. **No new infrastructure.** It uses OpenSSH only (spec P07), is local-first, and has no
   mandatory service; Recipe C would add an always-on issuer service.

**Explicit non-claims of B1:**

- No immediate remote revocation at account level (no KRL); the residual window is
  disclosed instead, in its three parts (§3.2).
- Certificate validity bounds new authentication only. It does not stop multiplexed admissions
  on a live master, nor anything on a live connection, and it does not terminate remote
  processes `[X:E7 H1, H1b, H3b]`. `ssh -O stop` does not stop admissions on already-accepted
  control connections `[X:E7P]`. So owned masters must be **closed** at the deadline (`-O exit`
  or exact-PID termination), as spec §6.6 requires absent a tested stop mechanism. Unmanaged
  connections and detached remote processes are outside the recipe's control (spec §6.6).
- The same-user issuer boundary is disclosed (spec §7.3): a process running as the owner that
  reaches the issuer endpoint can request certificates `[X:E5]`. A software K_ca in a store or
  file readable by that user is exposed the same way: in E5 the fixture CA's private key file
  stayed readable from the worker-only environment `[X:E5]`. Stronger isolation needs a separate OS
  account, host, or presence-gated K_ca.
- Hardware-backed keys are optional hardening until P5 and the Windows/Linux probes report.

**What would falsify the recommendation:**

| ID | Experiment | Falsifying observation | Consequence |
|---|---|---|---|
| F-1 | P1 (macOS), P-W1, P-L1 | The dedicated signer cannot sign during screen lock on a supported platform, **and** no store or hardware option restores it | Lock continuity fails for all recipes on that platform; change signer custody (hardware or separate service), not wording |
| F-2 | E2 | sshd accepts a certificate outside `[valid_after, valid_before]` beyond measured clock offset | Server-side deadline claim false; B1 loses its main advantage over A |
| F-3 | E3, E4 | A `p-host1`/`hm:…` certificate authenticates on a host mapped to a different principal; or the account-level `principals=` line does not restrict | Per-destination scope claim false at capability 2; need capability 3 mapping or A per destination |
| F-4 | E5 | K_ca is reachable through a worker or project endpoint, or a certificate wider or later than the grant can be minted through the worker path | Issuer separation false (R-CR-04); redesign issuer boundary |
| F-5 | G01 destination inventory | A material share of the owner's account-enrollable destinations run SSH servers without OpenSSH user-certificate support (for example Dropbear or some appliance SSH stacks; `[U]` for the owner's fleet) | B1 cannot be the only managed recipe; A must ship for those destinations |
| F-6 | Owner decision D1, plus P1 for the issuer store | New grants must be created while locked **and** K_ca cannot be used under lock without weakening its protection | Recommendation changes (A for unattended new work, or a separately isolated issuer service) |
| F-7 | E7 (G09) | `-O stop` does not stop admissions (including on control connections accepted before it), or kills sessions | Affects all recipes equally: owned masters must be closed at the deadline. Does not change the recipe choice. **Triggered** (outcomes below) |

**Falsifier outcomes (run 20261003T192323Z, §1.3):**

- **F-2 not triggered** `[X:E2]`. No acceptance outside the window: the last acceptance ended
  0.029 s before `valid_before`, nothing that started after it was accepted, and all 73
  refusals were logged as expired. The offset was 0.008–0.015 s.
- **F-3 not triggered** `[X:E3][X:E4]`. Single-principal certificates authenticate only where
  mapped. Account-level `principals=` restricts. The two-principal certificate works on both
  hosts, as designed, and is reported as "usable on both".
- **F-4 not triggered on its criterion** `[X:E5]`. K_ca was not reachable through the worker
  endpoint, and the child certificate was narrower and expired earlier. The same-user boundary
  is confirmed as a disclosed limit, not a falsification: the issuer socket mints for any
  same-user caller, and the fixture CA file was same-user readable.
- **F-7 triggered (for already-accepted control connections)** `[X:E7P]`. `-O stop` stops new
  control connections and does not kill sessions `[X:E7][X:E7R]`. A control connection
  accepted before the stop, however, was still granted sessions and forwards. Consequence as
  stated: owned masters are closed at the deadline (`-O exit` or exact PID; both observed to
  close pre-accepted connections `[X:E7P H3c, H3d]`). The recipe choice is unchanged.
- **F-1, F-5, F-6 open.** They are blocked on owner lock cycles and missing platforms (§8.2),
  on the G01 inventory, and on decision D1.

## 8. Experiment design

### 8.1 Runnable now against the Docker fixtures (another agent implements these under `tests/native/g04/`)

**Fixture:** `tests/fixtures/ssh/` (M00-T03): `ca1`/`ca2` trust the per-run user CA with
principal files `p-host1`/`p-host2` for account `cert`; `enrollable` (account `enroll`,
account-owned `authorized_keys` seeded with unrelated lines, including someone else's
`cert-authority,principals="ops"`); `fixed-auth` (root-owned registry); sshd
`LogLevel VERBOSE`; ports in `runtime/ports.env`; host keys in `runtime/known_hosts`; CA in
`runtime/keys/user_ca` `[OX:M00-T03 MANIFEST]`.

**Harness rules for every experiment:**

- `unset SSH_AUTH_SOCK`; call `/usr/bin/ssh`, `/usr/bin/ssh-keygen`, `/usr/bin/ssh-agent`
  explicitly.
- **Generate a per-experiment `ssh_config` in a temp dir**, with HostName, Port, User,
  HostKeyAlias, the fixture's `known_hosts`, `StrictHostKeyChecking yes`,
  `GlobalKnownHostsFile /dev/null`, `IdentityAgent <dedicated socket>`,
  `IdentitiesOnly yes`, `IdentityFile <K.pub>`, `CertificateFile <C>`, `BatchMode yes`, and
  `ControlMaster no` + `ControlPath none` except where E6/E7 say otherwise. **Do not reuse
  the fixture's `runtime/ssh_config` aliases.** They set `IdentityFile .../user_cert`, and
  `IdentityFile` entries accumulate `[S:ssh_config.5]`, so the fixture's own private key
  would also be offered and could make a test pass for the wrong reason `[I]`. The probe's
  generated config (`tests/native/macos/g04_lock_probe.sh`) is a working template
  `[O:SELFTEST]`.
- Use a dedicated agent per experiment: `HOME=<tmp> ssh-agent -U -a <tmp>/agent.sock`, private
  files deleted after `ssh-add`, kill exact PID only.
- Use a unique certificate key ID per step (`-I g04-e<n>-<step>-<run>`) so server logs
  (`docker logs`, "Accepted publickey for cert ... ID ...") attribute each authentication. An
  authentication counts as fresh only if a new accepted line with that ID appears.
- Record real exit codes, the host/container clock offset (`date -u +%s` on both sides), and
  versions (`ssh -V`, container `sshd -V`).
- Suggested record names: `tests/evidence/g04-e<n>-<slug>.json`.

| ID | Requirement / case | Setup | Steps | Pass | Fail |
|---|---|---|---|---|---|
| **E1** dedicated non-personal agent with a disposable managed key | R-CR-02, R-CR-03, A03 (substrate) | Dedicated agent; disposable K_env (ed25519); certificate from fixture CA, principal `p-host1`, `-V -1m:+10m`; `ssh-add -t 120`; delete private file | (a) `ssh-add -l` on the dedicated socket lists exactly K_env + its certificate. (b) Fresh login to ca1. (c) Same with `-o IdentityAgent=none`. (d) `ssh -v` log shows the agent socket used is the temp path. (e) After the `-t` lifetime: `ssh-add -T` and a fresh login. (f) Kill exact PID; check socket. | (a) exactly 2 entries; (b) rc 0 + new accepted line with the ID; (c) rc 255; (d) only the temp socket; (e) both rc ≠ 0; (f) process and socket gone | Any deviation; any use of a non-temp socket |
| **E2** certificate validity window and expiry | R-AU-05, R-CR-07, A23 (preliminary), F-2 | Three certificates on fresh keys: C1 `-V -1m:+90s`, C2 `+5m:+10m` (not yet valid), C3 `-10m:-5m` (expired); variants loaded with default `ssh-add` and with `ssh-add -N` | Login with C1 before expiry; again at `valid_before + 5 s`; logins with C2, C3; repeat the after-expiry login while the agent still holds C1 (default `ssh-add`, inside the 5 min grace) | C1 before: rc 0. C1 after: rc 255 and the server log gives an expiry reason. C2 and C3: rc 255. After-expiry rejection is the same with and without the agent still holding the certificate. Time from `valid_before` to first rejection ≤ 2 s + measured offset | Any acceptance outside the window beyond offset. *Limitation:* container clocks share the Docker VM clock; skewed-server cases go to G09 virtual-clock tests |
| **E3** principal scope across two CA-trusting hosts (system-level trust) | R-CR-07, A10, F-3 | Fixture ca1/ca2 | Certificates with principals {p-host1}, {p-host2}, {p-host1,p-host2}, {cert} (the username), a rogue-CA certificate, and the bare key; each tried on ca1 and ca2 | {p-host1}: ca1 ok, ca2 rc 255; {p-host2}: mirror; two-principal: **both ok, recorded as "certificate usable on both", never reported as scoped**; {cert}: both rc 255 (principals file present); rogue CA and bare key: rc 255 on both | Any other outcome. Re-runs parts of the fixture's own smoke under the G04 harness with the dedicated agent |
| **E4** account-level CA trust with principal restriction (capability 2) | R-CR-05, R-CR-06, R-CR-07, A09, F-3 | Fixture `enrollable` | Add `cert-authority,principals="hm:fx-enroll:enroll" <fixture CA pub> heimdall-g04-e4` with a §7.5-style transaction: preimage hash, temp file + atomic `mv`, marker. Then try: certificate principal `hm:fx-enroll:enroll`; principal `enroll` (the username); principal `ops` from **our** CA; a certificate without the line. Remove by marker; compare seed hash | `hm:…`: rc 0. `enroll`: rc 255 (principals= restricts). `ops` from our CA: rc 255 (the seed's `ops` line trusts a different CA key). Without the line: rc 255. Unrelated lines byte-identical; seed SHA-256 restored | Any acceptance of `enroll` or `ops`; any change to unrelated bytes |
| **E5** issuer separation and attenuation | R-CR-04, R-AU-07, A10, A28, F-4 | Issuer agent in its own 0700 temp dir holds the fixture CA (`ssh-add` of `runtime/keys/user_ca`, used read-only); worker agent in another temp dir holds K_env | (a) From an environment with only the worker socket: `ssh-add -L` (CA must not appear); `ssh-keygen -U -s ca.pub ...` against the worker socket. (b) Issuer mints a child certificate for a new K_child, principal subset `{p-host1}` and earlier `valid_before` than the parent `{p-host1,p-host2}`; child tries ca2, and ca1 after its own expiry. (c) Scan the worker temp dir, its environment, and the argv of its own processes (`ps -o args` for the exact PIDs only) for CA private material: for each file, `ssh-keygen -y -f` must never yield the CA public key | (a) CA absent; signing fails. (b) Child: ca2 rc 255; ca1 rc 255 after child expiry while the parent still works. (c) Nothing found | CA reachable from the worker path; child broader or longer than its parent. *Limitation:* same-user separation by endpoint only; disclose (spec §7.3). The run also records that the fixture CA private file stays same-user readable from the worker environment |
| **E6** independent fresh-login verification | R-CR-05, A09, spec §7.5 | ca1; a live ControlMaster to ca1 already open (`ControlMaster=yes`, `ControlPath=<tmp>/cm`) | Verification command: `ssh -F <cfg> -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes -o IdentityAgent=<dedicated> -o IdentityFile=<K.pub> -o CertificateFile=<C> -o PreferredAuthentications=publickey -o BatchMode=yes ca1 true`. Negative control: the same with `-o ControlMaster=auto -o ControlPath=<tmp>/cm` | Verification: rc 0 **and** exactly one new accepted line with the expected key ID. Negative control: rc 0 with **no** new accepted line, which documents why connection reuse is not verification | Verification succeeds without a new accepted line, or the line carries another key ID |
| **E7** (preliminary G09) multiplexing after expiry; `ssh -O stop` | R-AU-05, A23, plan G09, F-7 | Certificate `-V -1m:+2m`. Master: `ssh -o ControlMaster=yes -o ControlPath=<tmp>/cm -o ControlPersist=10m -N -f ca1`. Long session S1 through the master printing a heartbeat every 5 s (`while :; do date -u +%s; sleep 5; done`; the fixture has `PermitTTY no`, so no tty) | **Phase 1** (before expiry): new mux session `ssh -S <tmp>/cm ca1 true`. **Phase 2** (after `valid_before` + 10 s): (a) fresh login with `ControlMaster=no`, `ControlPath=none`; (b) new mux session through the master; (c) S1 heartbeat. **Phase 3:** `ssh -S <tmp>/cm -O stop ca1`; then (a) `-O check`; (b) `ssh -o ControlMaster=no -o ControlPath=<tmp>/cm ca1 true`; (c) S1 heartbeat for ≥ 30 s; (d) observe whether the master exits when S1 ends. **Phase 4** (second master, strict variant): `-O exit` closes everything. **Phase 5** (added after review M00-review-g04; `e7_mux_preconnected.py`): a raw mux client connects to the control socket **before** `-O stop`, stays idle, and after stop returned requests a new session (ca1, after expiry, at stop+2 s and stop+15 s), a local forward, a remote forward and a stdio forward (bastion), with controls before the stop; then `-O exit` and exact-PID SIGTERM with a pre-accepted connection open. **Race:** 50 iterations of client connect vs `-O stop` with randomized delay; count admissions of clients that started after stop returned | Hypotheses recorded as confirmed or refuted: **H1**: Phase 2(b) rc 0 with no new accepted line, so certificate expiry alone does not stop admissions (confirmed `[X:E7]`). **H2** (new control connections only): after `stop`, (a) fails, (b) is a new connection (server log shows a new, rejected authentication attempt) and rc 255, and (c) S1 continues (confirmed `[X:E7]`). **Phase 5 criterion:** every request on a pre-accepted connection after stop is refused (refuted for all five requests: verdict fail `[X:E7P]`). Race: 0 admissions of clients that started after stop returned (confirmed `[X:E7R]`; this criterion cannot detect pre-accepted connections) | H2 or the phase 5 criterion refuted (any admission after stop, or S1 killed). The result feeds the ordinary/strict policy choice (spec P06); it does not by itself pass or fail the recipe |

### 8.2 Owner-run, human-in-the-loop probes

| ID | Platform | What | Script / state | Record (status) |
|---|---|---|---|---|
| **P1** | macOS | Screen lock: dedicated agent signing, disposable custom keychain read, optional fresh SSH logins to fixture ca1 during the lock (A03-style) | `tests/native/macos/g04_lock_probe.sh --mode lock [--fixture-runtime tests/fixtures/ssh/runtime]`. Smoke path executed `[O:SMOKE-2][O:SELFTEST]` | `tests/evidence/g04-macos-screen-lock-probe.json` (**blocked**: owner-driven lock cycle) |
| **P2** | macOS | Logout and re-login: does a launchd-user-agent signer survive (expected not)? Is the custom keychain locked? What restores signing without the personal vault? | Not implemented (design: run the signer as a disposable LaunchAgent from a temp location; record state before logout and after re-login; remove the LaunchAgent afterwards) | `g04-macos-logout-probe.json` (**blocked**) |
| **P3** | macOS | Reboot with FileVault: what is available before the first login (a launchd daemon context) and after it | Not implemented | `g04-macos-reboot-headless-probe.json` (**blocked**) |
| **P4** | macOS | Sleep across a deadline: does an `ssh-add -t` lifetime and a certificate `valid_before` that elapse during sleep take effect at wake before any new signing? (spec §6.4) | Not implemented; G09 | `g04-macos-sleep-probe.json` (**blocked**) |
| **P5** | macOS | Secure Enclave CTK identity (`sc_auth create-ctk-identity -k p-256-ne -t none`) used through `/usr/lib/ssh-keychain.dylib` (`ssh-add -s` PKCS#11 and `ssh-add -K -S` FIDO-style) into a dedicated agent (`KEYCHAIN_CERTIFICATES` set to the probe hash, with a non-matching-hash control); certificate login to fixture ca1; export must fail; signing across screen lock; then `sc_auth delete-ctk-identity -h <own hash>` | `tests/native/macos/g04_ctk_probe.sh --mode unlocked\|lock [--fixture-runtime tests/fixtures/ssh/runtime]` (v3) and `g04_ctk_probe_selftest.sh` `[O:P5-SELFTEST]`. The first unlocked run used v1 `[O:P5]`. v2 and v3 fix what that run, an independent review and a rehearsal exposed `[O:P5-OFFER][O:P5-H2][O:P5-REH]`. v3 stops before creating anything unless the CTK store is empty and no smart card is present. v3 ran unlocked against the real store on 2026-10-31 `[O:P5-V3]`. Lock mode not executed (owner) | `g04-macos-secure-enclave-ctk-probe.json` (**blocked**: lock row needs a lock cycle (owner, or idle-console lock per ADR-0004 §2); D4 covers further runs (ADR-0004 §2). Unlocked row `verified`, verdict fail: create/export/delete, agent signing and fixture login with controls pass, the `KEYCHAIN_CERTIFICATES` limit fails in both unlocked runs) |
| **P6** | macOS | Data-protection keychain items (`AfterFirstUnlock` vs `WhenUnlocked`) read across screen lock | Needs a provisioning-profile-signed test bundle `[S:TN3137]` | `g04-macos-data-protection-keychain-probe.json` (**blocked**) |
| **P-W1** | Windows | Win+L: DPAPI unprotect, Credential Manager read (`SESSION` and `LOCAL_MACHINE`), TPM (Platform Crypto Provider) key signature, dedicated-agent signature; same sampling and evidence shape as P1 | PowerShell probe, not implemented (with the G03 agent) | `g04-windows-desktop-lock-probe.json` (**blocked**: native Windows) |
| **P-W2** | Windows | Sign-out, reboot, service context (DPAPI and Credential Manager from a service; Windows OpenSSH agent service before logon) | Not implemented | `g04-windows-signout-reboot-probe.json` (**blocked**) |
| **P-L1** | Linux desktop | Session lock (`loginctl lock-session`): Secret Service item read for a **disposable test user's** collection (never the owner's keyring), kernel user-keyring read, dedicated-agent signature | Not implemented | `g04-linux-desktop-lock-probe.json` (**blocked**: Linux desktop session) |
| **P-L2** | Linux desktop + headless runner | Logout, reboot, headless: persistent keyring expiry, `systemd-creds --user` decrypt from a lingering user service, TPM2 PKCS#11 key, gnome-keyring after logout | Not implemented | `g04-linux-logout-reboot-headless-probe.json` (**blocked**) |

## 9. Open owner decisions and escalations

These are not decided here.

| ID | Question | Why it matters |
|---|---|---|
| **D1** | Must standing-policy automatic activation create **new** grants while the desktop is locked, or is continuity of grants approved before the lock (A03) enough for V1? | Decides whether the issuer must sign under lock (§6), and with that K_ca custody (F-6) |
| **D2** | Is memory-only custody of a working key acceptable on platforms where no store is readable under lock or after a restart? The signer would hold it from approval to deadline, and loss at logout/reboot would need a new approval. | Spec §7.3 asks for protection "at rest and through a signer where supported"; memory-only changes recovery semantics (R-RT-07) |
| **D3** | Will Heimdall ship a provisioning-profile-signed, app-like bundle on macOS? | Required for the data-protection keychain and Secure Enclave via SecItem `[S:TN3137]`; affects G02 distribution |
| **D4** | May P5 create (and then delete) a CTK identity in the owner's real user token store? | The only shipped macOS path to a non-exportable Secure Enclave key for an unsigned CLI found here |
| **D5** | K_ca backup policy: none (reenroll on loss), or an encrypted offline backup? | Spec §7.3 custody rule for the issuer class |
| **Q1** (escalation) | Does a provisioner credential limited by step-ca policy (Recipe C) count as "unrestricted issuer authority" that may not be copied to a worker (spec §6.5, §7.3)? | Authority-semantics ambiguity; only relevant if C is pursued |
| **Q2** (escalation, **resolved**) | The status vocabulary has no "failed". Resolved by the orchestrator's gate-probe convention (`tests/evidence/README.md`, 2026-10-03): `status` describes the evidence, `observed_result.verdict` is pass/fail/inconclusive. Lock probe v2 and the corrected smoke records follow it. | Evidence semantics shared with other agents |
| **Q4** (escalation) | For the §6.5 "maximum residual remote-access window" and A07's "maximum residual validity": does stating the live-connection and remote-process parts as "until Heimdall closes owned connections; unbounded for unmanaged connections and remote processes" satisfy the obligation? And after **revocation** (not expiry), must Heimdall close owned dedicated connections, or may the graceful policy keep them as at expiry (spec §6.6, §6.7)? | Authority semantics; decides the stated window and what revocation does to live connections. Not decided here |
| **Q3** (escalation) | Retention of third-party documentation snapshots. Retained: extracted text of Apple, Microsoft, 1Password, Smallstep and freedesktop pages, plus permissively licensed raw texts (OpenSSH, RFC, man7, tpm2-pkcs11). Raw vendor HTML was discarded; hashes are kept in `MANIFEST.tsv`. | Copyright before any public release (spec §15.3); evidence pinning (plan §1.4) |

### 9.1 Decisions recorded 2026-10-06

| ID | Decision | By |
|---|---|---|
| D1 | **Yes.** Standing-policy activation may create new grants while the desktop is locked. The issuer must therefore be able to sign under lock, which constrains K_ca custody (F-6) | owner |
| D2 | **Yes.** Memory-only custody of a working key is acceptable where no store is readable under lock or after a restart. The cost: loss at logout or reboot needs a new approval | owner |
| D3 | **Yes.** Heimdall ships a provisioning-profile-signed, app-like bundle on macOS. This needs the owner's Apple Developer membership and signing identity when the time comes. It feeds G02 distribution | owner |
| D4 | **Yes.** P5 may create, and then delete, a CTK identity in the owner's real user token store | owner |
| D5 | **Yes.** K_ca gets an encrypted offline backup | owner |
| Q4 | Decided by the orchestrator under owner delegation ("choose what works best"); see below | orchestrator |
| Recipe | **B1 selected** on 2026-10-31 under the owner's delegation (ADR-0004 §2); specification in ADR-0005. P5 further real-store runs are covered by D4 | orchestrator |

**Q4.**
- **(a) The residual window is stated per component:**
  - Credential: `latest_possible_credential_expiry`, never later than the
    grant deadline.
  - Heimdall-owned multiplexed masters: closed at the deadline or on
    revocation, because `ssh -O stop` does not stop control connections that
    were already accepted (E7 phase 5).
  - Heimdall-owned dedicated connections: as described in (b).
  - Unmanaged connections and detached remote processes: unbounded, and
    disclosed as such.
  - This satisfies spec §6.5 and A07 because each part is stated together
    with its mechanism. Spec §6.6 already excludes unmanaged connections and
    detached processes from control.
- **(b) Expiry and revocation behave differently:**
  - **Expiry** follows the graceful default (spec §6.6): new connections stop
    at the deadline, and existing dedicated sessions may stay connected.
  - **Revocation**, and lock-revokes when the user chooses it, is an explicit
    "stop now". Heimdall closes every owned connection immediately, both
    masters and dedicated sessions. The revoke confirmation lists the
    sessions it will close, and the result reports `local_applied`,
    `remote_pending` and `latest_possible_credential_expiry` (spec §6.7).
  - Rationale: a user who revokes expects access to end. Silently keeping
    shells alive after revocation would mislead them, while the graceful
    policy suits expiry, where the user did not act.

## 10. Status of this task's deliverables

| Deliverable | Status | Evidence |
|---|---|---|
| Recipe comparison, custody rules, platform tables, recommendation (this document) | `implemented_unverified`. Independently reviewed (M00-review-g04); its findings were corrected here, and the corrections have not been re-reviewed. The recommendation is still pending the lock probes (F-1) and owner decisions | §1–§7 |
| Experiments E1–E6, enrollment, E7 phases 1–5 and race (`tests/native/g04/`) | `verified` (run 20261003T192323Z, all exit 0, records schema-valid). Verdicts: all pass except E7 phase 5 (`G09-prelim-mux-preconnected-after-stop`): **fail**. The E7 and race passes are against criteria scoped to new control connections | §1.3, `tests/evidence/g04-exp-*.json` |
| Owner-run probe design (P1–P6, P-W1/2, P-L1/2) | `implemented_unverified` (design only; P2–P6, P-W*, P-L* harnesses not implemented) | §8.2 |
| `tests/native/macos/g04_lock_probe.sh` (v2) + README | Smoke path `verified` (v2: exit 0 without and with the real fixture, `[O:SMOKE-4]`, `[O:SMOKE-5]`; v1: interruption exit 5 with clean cleanup, self-test exit 0). The v2 lock-mode verdict logic was not executed (it needs an owner lock cycle). Lock path `blocked` | §1.2 |
| `tests/native/macos/g04_lock_probe_selftest.sh` | `verified` for its run (exit 0) | `tests/evidence/artifacts/g04/research/selftest/selftest-run2.log` |
| `tests/native/macos/g04_ctk_probe.sh` (P5) + `g04_ctk_probe_selftest.sh` | Self-test `verified` for v1, v2 and v3 (exit 0; v3 final: pass=132, `selftest-20261009T090152Z.log`). Unlocked mode executed twice against the real store: v1 on 2026-10-09 (`[O:P5]`; its login clause was unmeasured) and v3 on 2026-10-31 (`[O:P5-V3]`; exit 1 = verdict fail; record unlocked row `verified`). v3 was also rehearsed with software keys (`[O:P5-REH]`). Lock mode `blocked` (owner) | `tests/evidence/artifacts/g04/p5/` |
| Lock, logout, reboot, sleep, and other-platform records | `blocked` (10 records; P5 now also carries an unlocked row) | `tests/evidence/g04-*-probe.json` |
