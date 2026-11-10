# Fixture manifest (plan.md §6.2)

Owner of every row unless stated: **Heimdall M00 fixtures** (task M00-T03).
Statuses use the project vocabulary only. `verified` means `tests/fixtures/ssh/smoke.sh` actually
exercised that scenario and passed (evidence: `tests/evidence/m00-t03-fixtures.json` and
`tests/evidence/artifacts/m00-t03/`; final post-fix runs under `.../m00-t03/fix/`). Nothing here has touched a real host, the owner's `~/.ssh`,
an SSH agent, a keychain, or a password manager.

## Environment actually used

| Item | Observed value |
|---|---|
| Host | macOS 27.0 (arm64), Docker Desktop, linux/arm64, Compose not used. Engine 29.8.0 in the original (pre-fix) runs, 29.8.1 in the post-fix runs in `artifacts/m00-t03/fix/` (Desktop updated in between; `docker version` observed 29.8.1). |
| Base image | `debian@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1` (Debian trixie; the digest the tag `debian:trixie` resolved to on the pulling machine; `docker pull` of the digest succeeded; image id `sha256:1c833814c4af...`) |
| Fixture image | `heimdall-m00-t03-sshd:local`, built from `tests/fixtures/ssh/Dockerfile` by `up.sh`; image id differs per build |
| Server software | `openssh-server 1:10.0p1-7+deb13u4`, `sshd -V`: `OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026` (observed inside the containers, `artifacts/m00-t03/versions.txt`) |
| Client | `/usr/bin/ssh` = `OpenSSH_10.3p1, LibreSSL 3.3.6` (macOS system client) |
| Version pinning limit | The base image is pinned by digest, but `apt-get install openssh-server` floats with the Debian archive at build time. The version above is what was observed, not a pin. A later rebuild may differ; `up.sh` records the installed version in `runtime/versions.txt` each run. |

## Layout and lifecycle

All fixture code is in `tests/fixtures/ssh/`: `up.sh`, `smoke.sh`, `reset.sh`, `down.sh`, `lib.sh`,
`Dockerfile`, `entrypoint.sh`, `conflicting-config/ssh_config`, plus two diagnostic scripts: `penalty-repro.sh`
(deliberate PerSourcePenalties reproduction on disposable variant containers) and `down-failure-case.sh`
(fault-injected case for `down.sh`'s failure branch; run only with the fixtures down). Generated material goes to
`tests/fixtures/ssh/runtime/` (gitignored by `tests/fixtures/**/runtime/`).

```
tests/fixtures/ssh/up.sh      # pull pinned base, build image, generate keys/CA/host keys, start 7 containers (M03: + enroll2)
tests/fixtures/ssh/up.sh ca-trust-test-ca <pub>  # M03: add the run's test CA to ca1/ca2 TrustedUserCAKeys (container-internal)
tests/fixtures/ssh/smoke.sh   # exits 0 only if every check passed; prints one PASS/FAIL line per check
tests/fixtures/ssh/reset.sh   # recreate containers pristine, keep keys; --rekey = down.sh + up.sh
tests/fixtures/ssh/down.sh    # remove containers/networks/image (M03: + leftover m03-shells containers and their built image), overwrite+delete keys, print CLEANUP CONFIRMED
tests/fixtures/ssh/penalty-repro.sh [N] [POLL]  # needs up.sh; two throwaway sshd variants, N failed auths, exit 0 iff reproduced
tests/fixtures/ssh/down-failure-case.sh         # needs fixtures DOWN; injects an unlabelled network, expects down.sh exit 1
```

Use: `/usr/bin/ssh -F tests/fixtures/ssh/runtime/ssh_config <alias>` where alias is one of
`fixed-auth`, `fixed-wrongkey` (negative control), `enrollable`, `enrollable-marker`, `enrollable2` (M03), `ca-host1`,
`ca-host2` (these two need `-o CertificateFile=...`; `smoke.sh` signs certs into `runtime/certs/`),
`bastion`, `internal-target`. The generated config sets `StrictHostKeyChecking yes`,
`UserKnownHostsFile` to the generated `runtime/known_hosts`, `GlobalKnownHostsFile /dev/null`,
`IdentitiesOnly yes`, `IdentityAgent none`, `ForwardAgent no`, `BatchMode yes`, `ControlMaster no`.
It never uses `accept-new` or `no`. Always `unset SSH_AUTH_SOCK` and call `/usr/bin/ssh` explicitly.

Containers run with `--cap-drop ALL` plus the minimum sshd needs, `no-new-privileges`, pid/memory limits,
and label `heimdall.fixture=m00-t03`; `down.sh` only touches resources carrying that label.
Every published port is `127.0.0.1:<ephemeral>` (docker assigns it; read `runtime/ports.env`; ports change
after `reset.sh`). The `target` container has no published port at all.

Fixture sshd deviation from defaults: `PerSourcePenalties no`. OpenSSH >= 9.8 by default penalises a source
address after repeated failed authentications and then drops new connections from it, valid ones included. All
fixture traffic reaches each container from one source (the docker gateway, `172.18.0.1` in the observed runs), so
the negative checks in `smoke.sh` can make later checks fail. Real servers can behave this way, so retry policy for
repeated failures (plan.md §6.4) must not assume the server keeps answering, and a dropped connection can look
like silent exit 255 with no client message at the default client `LogLevel`.

Evidence for this, all re-observed in the fix cycle (`artifacts/m00-t03/fix/`):

- Mechanism, directly reproduced (`penalty-repro.sh`, runs `penalty-repro.1.log` and `penalty-repro.2.log`, both exit 0):
  a throwaway container with the default `PerSourcePenalties` (`sshd -T`: `authfail:5 ... min:15`) accepted a valid
  login, accepted/rejected 3 wrong-key attempts normally, then dropped the 4th to 8th wrong-key attempts and all 3
  following valid logins (exit 255, empty client output); sshd logged `srclimit_penalise ... activating ipv4 penalty of 16
  seconds for penalty: failed authentication` and `drop connection #0 from [...] penalty: failed authentication`; a valid login worked again after
  about 20 s. The control container (`PerSourcePenalties no`) accepted all 8 wrong-key attempts and all 3 later valid logins and logged no
  penalty line. Both runs agreed.
- The smoke flake, directly reproduced (`smoke-with-default-penalties*.log`): with the default setting injected into the running ca1 and
  ca2 containers, `smoke.sh` run once passed 61/61 and the next run launched immediately after it
  (`smoke-with-default-penalties.rerun2.run2.full.log`) exited 1 with `FAIL ca:p-host1 cert -> host1 accepted` and
  `FAIL ca:broad cert works on BOTH hosts` (host1 exit=255, host2 exit=0), while the ca1 log shows
  `drop connection ... penalty: failed authentication`. The first injected run (no predecessor) and two runs started about 11 s after
  the previous run passed 61/61, so the flake is timing dependent (1 failure in 4 injected runs) (the penalty from the previous run's late negative checks lasts about 20 s).
  After `reset.sh`, `sshd -T` shows `persourcepenalties no` on both again and two further smoke runs pass (61/61).
- Correction of an earlier claim: this manifest and the evidence record previously cited
  `attempt-smoke.3-after-reset.log` as showing the flake. That was wrong: that log is a clean 60/60 pass, and the
  original failing run and its ca1 log excerpt were never retained. The original failure's cause is therefore an
  unretained inference; what is now evidenced is that the same symptom (two CA positive checks failing on a rerun, ca1
  log showing a penalty drop) is reproducible with the default setting and absent with `PerSourcePenalties no`.

## Key and material disposal

- Created per run by `up.sh`, never committed (`.gitignore` covers `runtime/`, `*.key`, `id_*`, `*.pem`):
  user keys (fixed, enroll, marker, cert, bastion, final), the user CA and a rogue CA, six host keys plus a
  "swap" host key, three throwaway "unrelated" keys (their private halves are deleted immediately; only public
  halves seed the enrollable account's `authorized_keys`), signed certs, generated `ssh_config`, `known_hosts`.
- Inside containers: host key and `authorized_keys`/CA public key are copied in with `docker cp`; destroyed with the container.
- `down.sh` removes all containers, both networks, and the fixture image, overwrites each private key file
  (`shred -n 1 -z -u`, falling back to `dd`+`rm`), deletes the whole `runtime/` directory and prints
  `CLEANUP CONFIRMATION ... containers_remaining=0 networks_remaining=0 image_remaining=0 runtime_dir_remaining=0 ...`
  and `CLEANUP CONFIRMED` (exit 0); exit 1 and `CLEANUP INCOMPLETE` otherwise.
- Limit: overwrite-then-unlink does not guarantee erasure on APFS/SSD (copy-on-write, wear leveling). These keys
  are valid only for fixture containers that no longer exist, so residual bytes carry no authority. The base image
  `debian@sha256:f324...` is deliberately not removed if it already existed before `up.sh` (it did).
- No key here is, or may be reused as, a real credential. Do not load these keys into any agent other than a fixture agent.

## Inventory (plan.md §6.2 required fixtures)

| # | Fixture | Owner | Image / machine | Versions | Scenario role | Reset procedure | Cleanup confirmation | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | Fixed-auth host, no remote writes (`hm-m00t03-fixed`, account `fixed`) | Heimdall M00 fixtures | fixture image on pinned base | OpenSSH 10.0p2 Debian-7+deb13u4 | A01 (existing access, no mutation), A09 negative (insufficient authority), A10/A11 later. Registry is `/etc/ssh/authorized_keys.d/fixed`, root-owned 0644; home is root-owned so `~/.ssh` cannot be created. | `reset.sh` | `down.sh` output `CLEANUP CONFIRMED` | verified (smoke: login ok; append to registry and `mkdir ~/.ssh` denied; registry sha256 unchanged; unrelated key rejected) |
| 2 | Account-enrollable host (`hm-m00t03-enroll`, account `enroll`) | Heimdall M00 fixtures | same | same | A09 (enrollment/rotation/rollback). Account owns `~/.ssh/authorized_keys` (0600). Seed has a comment with UTF-8, a `command=...,no-pty` entry, a `from=...` entry, a `cert-authority,principals=` entry, blank line, a working-path key and a trailer comment. | `reset.sh` restores the seeded file (sha256 in `runtime/seed/enroll_authorized_keys.sha256`) | same | verified (smoke: marker key added, fresh-auth login with marker key only, concurrent admin line appended, marker removed by atomic mv, unrelated + concurrent bytes identical, mode/owner preserved, seed sha256 restored). Not exercised: interrupted mutation / lost response (see row 14). |
| 3 | Two CA-trusting hosts, different principal maps (`hm-m00t03-ca1` principals file `p-host1`; `hm-m00t03-ca2` principals file `p-host2`; account `cert`; `TrustedUserCAKeys` = per-run user CA; `AuthorizedKeysFile none`) | Heimdall M00 fixtures | same | same | A10, later A23 and M03 managed-credential recipe. Shows per-destination scope only comes from server-side principal mapping. | `reset.sh` (certificates are not server state) | same | verified (smoke: p-host1 cert accepted by host1, rejected by host2; p-host2 mirror; broad two-principal cert accepted by both, recorded as the scope caveat; bare key rejected; expired, not-yet-valid and rogue-CA certs rejected; server log shows expiry reason). The CA private key stays in `runtime/keys/` on the host; it was not placed in any container. |
| 4 | Bastion + final target (`hm-m00t03-bastion` accounts `jump`; `hm-m00t03-target` account `final`) | Heimdall M00 fixtures | same | same | A15 (bastion flow), R-SS-06. `target` is attached only to the `--internal` network `hm-m00t03-internal`; bastion bridges edge (loopback-published) and internal. Bastion `PermitOpen hm-m00t03-target:22`, `PermitTTY no`. | `reset.sh` | same | verified for the bastion/ProxyJump portion (smoke: ProxyJump works with `ForwardAgent no`, target sees no `SSH_AUTH_SOCK`; `-W` to a non-permitted destination refused by the bastion (`administratively prohibited`; `-W` to the permitted target returns the sshd banner as a control; the effective-config check now asserts `forwardagent no`, `proxyjump bastion`, `identityagent none`); target has one network which is `Internal=true`, no ports, no egress to 1.1.1.1:443, container IP not reachable from host, direct ssh without jump fails). The "explicitly test forwarding" half of A15 is not exercised here (not_started, needs the Heimdall forwarding recipe in M04). |
| 5 | Host-key substitution route | Heimdall M00 fixtures | swaps the `fixed` container's host key for the per-run "swap" key using `docker cp` + `kill -HUP` of sshd, then restores it | same | R-SE-04, A09/A26: a changed host key must hard-fail, never prompt or auto-accept. | restored by `smoke.sh`; `reset.sh` recreates the container with its original key | same | verified (smoke: login ok, then exit 255 with `REMOTE HOST IDENTIFICATION HAS CHANGED` / `Host key verification failed`; `StrictHostKeyChecking=ask` also fails; `known_hosts` sha256 unchanged; login ok after restore). Tested for the loopback-port + `HostKeyAlias` route only, not a hostname/DNS change or a bastion-hop substitution. |
| 6 | Conflicting SSH config (`tests/fixtures/ssh/conflicting-config/ssh_config`) | Heimdall M00 fixtures | none (inert text file, uses TEST-NET-1 `192.0.2.x`, nonexistent paths; never connect with it, only `ssh -G`) | observed with `/usr/bin/ssh -G` (OpenSSH_10.3p1) | Overlapping `Host` blocks, first-value-wins and merged directives (User, Port, HostName, IdentityFile, IdentityAgent, ProxyJump, ForwardAgent, StrictHostKeyChecking, ControlMaster). | none needed (static) | nothing to clean | implemented_unverified (manually observed only: `artifacts/m00-t03/conflicting-config-G-conflict-a.txt`; not part of `smoke.sh` and not yet exercised by Heimdall) |
| 7 | Instrumented fake agent | another M00 task owns `tests/fixtures/fake-agent/` | n/a | n/a | A10/A11/A33 canaries, truncated/oversize frames, locked state | defined by its owner | defined by its owner | not assessed here: directory exists but is owned and verified by another agent. This manifest only references it. |
| 8 | Locked / interaction-required provider | Heimdall M00 fixtures (M00-T04 / M03) | none | n/a | A11 (fixed provider with touch/MFA/lock) | n/a | n/a | blocked, blocked_on: a locked secure-store or touch/MFA-gated provider needing a real FIDO2/`sk` authenticator or an interactive native OS lock (macOS login keychain/Secure Enclave or Windows Hello); explicitly off limits to touch here. A fake-agent "locked" mode can model the protocol only. |
| 9 | Replay / oversize agent messages | fake-agent owner | n/a | n/a | adversarial agent-protocol tests | n/a | n/a | not_started (belongs with fake-agent; no sshd involvement) |
| 10 | Delayed issuer | Heimdall M00 fixtures (M03) | not built | n/a | A10, A28 issuer latency/timeouts; would wrap the per-run CA behind a loopback signer | n/a | n/a | not_started |
| 11 | Stale named pipe / socket | Heimdall M00 fixtures (M01/M04) | not built | n/a | stale-endpoint detection; Unix socket variant is possible on this host, Windows named pipe variant is not | n/a | n/a | not_started (Unix socket); blocked, blocked_on: native Windows host (named pipe), none available on this macOS arm64 machine |
| 12 | Native Windows + WSL | Heimdall M00 fixtures (M00-T04) | none | n/a | G03 Windows/WSL endpoint selection, exposure and lifecycle (A12-A14); the Linux sshd containers are not a substitute | n/a | n/a | blocked, blocked_on: a native Windows host with WSL2 (not available here; this machine is macOS 27.0 arm64). Docker/Linux emulation does not close any Windows claim. |
| 13 | Two concurrent execution environments | Heimdall M00 fixtures (M05) | not built | n/a | A16 | n/a | n/a | not_started |
| 14 | Partial enrollment response loss | Heimdall M00 fixtures (M03) | not built; plan: a loopback TCP fault proxy in front of `enroll` that drops the response after the mutation, plus a remote-change canary count | n/a | A09 `outcome_unknown` reconciliation | n/a | n/a | not_started |
| 15 | Paired remote Linux runner | Heimdall M00 fixtures (M06) | not built; the fixture image/base could be reused | n/a | A24, A25 | n/a | n/a | not_started (needs the Heimdall runner artifact and the language decision G02) |
| 16 | Limited management client | Heimdall M00 fixtures (M06/M07) | not built | n/a | role-limited controller tests | n/a | n/a | not_started |
| 17 | Local Linux container bound to scoped access | Heimdall M00 fixtures (M04) | not built; the sshd containers here are SSH targets, not the Heimdall-bound execution container | n/a | A15 container half (UID/endpoint change, cleanup, no broad agent mounted) | n/a | n/a | not_started (needs the Heimdall container recipe) |
| 18 | Iroh direct/relay configuration | Heimdall M00 fixtures (G06/M06) | not built | n/a | only if G06 enables Iroh | n/a | n/a | not_started (conditional on G06 decision; requires no UDP listener beyond loopback/container networks when built) |
| 19 | ⟨M03⟩ Second account-enrollable host `enrollable2` (`hm-m00t03-enroll2`, account `enroll`) | Heimdall M03 fixtures (m03-plan U11) | fixture image on the pinned M00 base (`debian@sha256:f324…`) | observed 2026-11-10: `openssh-server 1:10.0p1-7+deb13u4`, `OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6`; Docker Engine 29.9.2; host client `OpenSSH_10.5p1` | A10 on two hosts; the default-registry-path production verification on an account that cannot read the sshd log (ADR-0005 §9.3 R5; ADR-0008 D13 item 2). Seeded like `enrollable` by `up.sh`'s `seed_like_enrollable` with its own keys (`unrelated_4..6`, `user_enroll2`); sha256 in `runtime/seed/enroll2_authorized_keys.sha256`; sshd logs to the container's stderr only (`docker logs`), so the account cannot read it | `reset.sh` restores the seeded file | `down.sh` output `CLEANUP CONFIRMED` | implemented_unverified (observed passing by U11 on 2026-11-10, no evidence record yet: smoke 72/72 incl. `enroll2:seed-intact`, `enroll2:same-shape-as-enrollable`, `enroll2:own-keys`, `enroll2:sshd-log-not-readable`; `integration_testkit_m03::docker_enrollable2_seeded_like_enrollable` exit 0) |
| 20 | ⟨M03⟩ Test-CA hook `up.sh ca-trust-test-ca <pub>` for `ca1`/`ca2` | Heimdall M03 fixtures (m03-plan U11) | `lib.sh` `ca_trust_test_ca` → `docker exec -i <ca1/ca2> fixture-entrypoint.sh ca-trust-test-ca` (stdin) | as row 3 | Writes the run's test CA (`ssh-ed25519 <base64>` only; anything else exit 2) into the container's `TrustedUserCAKeys` (`/etc/ssh/user_ca.pub`), container-internal only; nothing is written on the host (A10 system form on two hosts; ADR-0008 D13 item 2) | `reset.sh` recreates `ca1`/`ca2` without it | `down.sh` output `CLEANUP CONFIRMED` (the CA lives only in the removed containers) | implemented_unverified (observed passing by U11 on 2026-11-10, no evidence record yet: smoke `cahook:*` 6 checks; `integration_testkit_m03::docker_ca_hook_is_container_internal_only` exit 0: malformed line refused, both hosts trust the CA, other containers and the host `runtime/` tree unchanged, the CA's certificate accepted per host principal only) |
| 21 | ⟨M03⟩ Shell container, bash as `sh` (`hm-m03-shell-bash-as-sh-<hex>`; testkit `shells::ShellContainers`) | Heimdall M03 fixtures (m03-plan U11; ADR-0008 §17.7 item 1, §17.9 item 5) | image `heimdall-m03-shell-debian:local` built from `debian@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` (the round-4 re-check's image) + `procps`, `/bin/sh` → bash (`shells::DEBIAN_DOCKERFILE`); the network is attached only to that build step | observed 2026-11-10: `GNU bash, version 5.2.37(1)-release (aarch64-unknown-linux-gnu)`, procps `ps` at `/usr/bin/ps`, util-linux `setsid` (package versions float with the Debian archive at build time; not pinned) | The per-shell group-proof and fencing rows no sshd target covers (bash as `sh`), the live `comm` procstat fixtures. Runs `--network none` (only `lo`), `--cap-drop ALL`, `no-new-privileges`, pids/memory limits, `--init`, label `heimdall.fixture=m03-shells`; scripts run as `setsid /bin/sh -s` (each leads its own session and group) | none: a fresh container per `ShellContainers::start` | removed by exact name on drop (`docker rm -f <name>`); `down.sh` removes leftovers and the built image by label (never the pinned base) | implemented_unverified (observed passing by U11 on 2026-11-10, no evidence record yet: `integration_testkit_m03::shell_containers_run_each_shell_as_group_leader` exit 0) |
| 22 | ⟨M03⟩ Shell container, BusyBox `ash` (`hm-m03-shell-busybox-ash-<hex>`) | Heimdall M03 fixtures (m03-plan U11) | `alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a` as is (no build) | observed 2026-11-10: `BusyBox v1.37.0 (2026-01-10 15:38:28 UTC)`; BusyBox `ps`, `kill` (rejects `--`), `setsid` (no `-w`) | As row 21 for BusyBox `ash` (expected `unproven` fence outcomes, ADR-0008 §17.10 item 5) | as row 21 | as row 21 | implemented_unverified (as row 21) |
| 23 | ⟨M03⟩ Synthetic `/proc/<pid>/stat` set (`tests/fixtures/procstat/*.stat`, `golden.json`, README) | Heimdall M03 wave 0 (U0b row 28); row added by U11 at the wave-0 request | inert committed text files (synthetic, hand-written; no host capture) | n/a | The shared parser's rule (ADR-0008 D5 §6.3, §17.13 item 2): `comm` with spaces, parentheses, a newline, spoofed fields, a zombie, exactly 20 tokens, and the malformed rejections. Also loaded by testkit `procstat::Fixtures::committed()` for U5's awk agreement test; the in-code set `procstat::Fixtures::synthetic()` adds `)(` and a 15-byte name | none needed (static) | nothing to clean | implemented_unverified (read by `model_managed_domain` `procstat_parse_golden`; `integration_testkit_m03::procstat_fixtures_cover_spaces_parentheses_and_newline` observed passing by U11 on 2026-11-10; no evidence record yet) |

## Evidence

- Record: `tests/evidence/m00-t03-fixtures.json` (per-fixture statuses live in `observed_result.per_fixture`).
- Final post-fix run logs (current scripts, `smoke.sh` now has 61 checks): `tests/evidence/artifacts/m00-t03/fix/{up,smoke.run1,smoke.run2,smoke.run3,reset,smoke.after-reset,smoke.after-reset2,down}.log`,
  each ending with `exit=<real exit code>`; plus `penalty-repro.{1,2}.log`, `smoke-with-default-penalties*.log`,
  `negctl-effective-config.log`, `down-failure-case.log`, `after-reset-persourcepenalties.txt`.
- Pre-fix logs under `tests/evidence/artifacts/m00-t03/*.log` (60-check `smoke.sh`, earlier script digests) are kept as history
  only: `attempt-*.log` are earlier attempts (attempt 1 had 7 failing checks caused by faulty checks in `smoke.sh`: a grep that
  matched a comment, a whitespace compare, and a wrong-key control that was additive with the configured key; fixed in the
  script). A later cycle passed, a rerun showed an intermittent ca1 failure whose log was not retained; its attribution to
  `PerSourcePenalties` was inference then and is evidenced by the reproduction above.
- `down.sh` failure branch: exercised once by fault injection (`down-failure-case.sh`, `fix/down-failure-case.log`): an
  unlabelled network named `hm-m00t03-internal` made `down.sh` leave it alone, print `networks_remaining=1 problems=1` and
  `CLEANUP INCOMPLETE`, and exit 1. Other failure causes (a container or image that cannot be removed) remain unexercised.
- Not covered by `smoke.sh`: certificate-expiry-during-session / multiplexing effects (A23), enrollment interruption,
  forwarding tests, hostname/DNS or bastion-hop host-key substitution, anything run on Linux hosts other than the Docker Desktop VM.
- Provenance caveat: the scripts are untracked in git (working tree on top of commit `18bb8df`); the evidence binds to
  per-script sha256 digests, not to a commit.
