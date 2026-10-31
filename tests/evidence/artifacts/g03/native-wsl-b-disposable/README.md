# G03 WSL Mode B on a disposable second distribution (M00-T04-g03-wsl-b, 2026-10-31)

Probes P-B08 (`G03-wsl-b-multi-distro-exposure`), P-B09 (`G03-wsl-b-distro-restart`) and P-B10
(`G03-wsl-b-idle-timeout`), research doc `docs/research/g03-windows-wsl.md` §4.3. Authority: ADR-0004 §3
(one disposable distribution created with `wsl --import`; `--terminate`/`--unregister` of that
distribution only; never `--shutdown`; the owner's distributions untouched). P-B11 (other Windows user)
was not attempted. In this file **[O]** means observed by a command that ran here (exit codes below and
in the transcripts), **[I]** inference, **[U]** unknown.

Redaction tokens: `<wsluser>`, `<wslhome>`, `<winuser>`, `<winhome>`, `<winhost>`, `S-1-5-21-<redacted>`,
`<ip>`; the owner's distribution is `<owner-distro-A>`. `hm-g03b-732254` and its user `hg03t` were
created by this task and are not redacted.

## 1. Host and roles [O]

- Owner's Windows 11 PC (the host of §0.1/§0.2 of the research doc), non-elevated Windows user `<winuser>`.
  `wsl --version`: WSL 3.0.3.0, kernel 6.18.54.1-1, WSLg 1.0.79, Windows version 10.0.26300.9711.
  `wslinfo --networking-mode` printed `nat` in both distributions (the harness read no `.wslconfig`).
- **Distribution 1, controller:** `<owner-distro-A>`, the owner's existing distribution and the only one
  registered before and after this task. Ubuntu 24.04.5 LTS, WSL2, systemd PID 1, uid 1000, OpenSSH
  9.6p1 (Ubuntu-3ubuntu13.20), Python 3.12.3. Only client-side harness actions ran there; no listener was
  started in it. Reached by SSH from the Mac (dedicated test key), then
  `wsl.exe -d <owner-distro-A> --cd <scratch> --exec /bin/bash scripts/run.sh …` (a WSL-launched
  session; the SSH session was confirmed to be in that distribution by comparing mount-namespace ids).
- **Distribution 2, target:** `hm-g03b-732254`, created by this task (§3) and unregistered at the end (§7).

## 2. Root filesystem provenance [O]

| Item | Value |
|---|---|
| Source | `https://releases.ubuntu.com/noble/ubuntu-24.04.5-wsl-amd64.wsl` (official Ubuntu 24.04.5 WSL image; `cloud-images.ubuntu.com/wsl/` states that WSL image publication moved to cdimages.ubuntu.com, and `releases.ubuntu.com/noble/` publishes this released image with a signed `SHA256SUMS`) |
| Size | 388 975 696 bytes (HTTP `Content-Length`, and on disk after download) |
| SHA-256 | `bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e`: `sha256sum` in the controller (exit 0) and `Get-FileHash` on Windows give the same value; it equals the `ubuntu-24.04.5-wsl-amd64.wsl` line of `rootfs/SHA256SUMS` |
| Signature | `rootfs/SHA256SUMS.gpg` verifies over `rootfs/SHA256SUMS` (gpg exit 0, `GOODSIG`/`VALIDSIG` by `843938DF228D22F7B3742BC0D94AA3F0EFE21092`, "Ubuntu CD Image Automatic Signing Key (2012)"). The key was fetched from keyserver.ubuntu.com by that full fingerprint into a throwaway keyring: `rootfs/gpg-verify.txt` |
| Image config (read from the tarball) | `/etc/wsl-distribution.conf`: `[oobe] command = /usr/lib/wsl/wsl-setup`, `defaultUid = 1000`, `defaultName = Ubuntu-24.04` (the image's built-in name, unused: `--import` names the distribution); `[shortcut] icon`; `[windowsterminal] ProfileTemplate`. `/etc/wsl.conf`: `[boot] systemd=true`. No passwd entry with uid ≥ 1000 |
| Packages (image `.manifest`) | cloud-init 26.1-0ubuntu1~24.04.1, openssh-client 1:9.6p1-3ubuntu13.19, python3 3.12.3-0ubuntu2.1, systemd 255.4-1ubuntu8.17, wsl-setup 0.5.10~24.04.2 |
| cloud-init input | `%USERPROFILE%\.cloud-init` and `%USERPROFILE%\.ubuntupro` do not exist (existence check only), so the image's cloud-init WSL datasource had no user data to apply |

The tarball was downloaded on the PC into `%LOCALAPPDATA%\hm-m00\M00-T04-g03-wsl-b\rootfs\` and deleted with
that scratch directory. It is not in the repository; `rootfs/` keeps only the checksum files and the
verification transcript.

## 3. Creating and preparing the target (`transcripts/import.txt`) [O]

| Step | Exit |
|---|---|
| `wsl --import hm-g03b-732254 <winhome>\AppData\Local\hm-m00\M00-T04-g03-wsl-b\distro <…>\rootfs\ubuntu-24.04.5-wsl-amd64.wsl --version 2` (wsl.exe also printed "Sparse VHDs are currently experimental"; the host WSL configuration that causes this was not read) | 0 |
| `wsl -l -v`: `<owner-distro-A>` Running (default), `hm-g03b-732254` Stopped, both version 2 | 0 |
| First launch `wsl -d hm-g03b-732254 -u root --exec /bin/bash target_facts.sh` (non-interactive; the image OOBE did not run): root, Ubuntu 24.04.5 LTS, PID 1 systemd, `systemctl is-system-running` = running, python3/ssh-keygen/ssh-agent/ssh-add/setsid/nohup present | 0 |
| `target_setup.sh` as root: `useradd -m -u 1000 -U -s /bin/bash hg03t` (no password), append `[user] default=hg03t` to `/etc/wsl.conf` | 0 |
| `wsl --terminate hm-g03b-732254` (own distribution, so the default user applies) | 0 |
| Relaunch without `-u`: user `hg03t` uid 1000, PID 1 systemd | 0 |

Why a uid-1000 default user: the image's interactive OOBE (`defaultUid = 1000`) would create one, and the
controller user is uid 1000. With the root default, the `/mnt/wsl` listener socket (mode 0600) would be
owned by root and refused to uid 1000. That would hide the same-uid exposure P-B08 must measure [I].

Side effects of the import, measured by `scripts/sidefx.ps1`. It prints counts only, for this one name.

| Counter | before | after import | after unregister |
|---|---|---|---|
| HKCU `…\Lxss` subkeys (total / named `hm-g03b-732254`) | 1 / 0 | 2 / 1 | 1 / 0 |
| Start-menu `.lnk` named after the target | 0 | 0 | 0 |
| Windows Terminal fragment files mentioning the target | 0 | 1 | 0 |

## 4. Harness and runs

The harness was `tests/native/wsl/` at HEAD `c6dd982b` (unchanged in `8b62719c`), run from a copy without
`.git` (so `build_commit` is null). It had one patch: `harness/lifecycle.patch`, with the patched file in
`harness/run_g03_wsl_lifecycle.sh` (sha256 `8cc5698c23967c9e77c3a3e3273dfeac3b71a500aab8ebe71942f8dda929138f`;
in-tree `265d9a3cd2f8647d73d9dca30f09f9cd748c85316a6a8c3696a489c8b3d422f4`). The multi probe referred to the
target state file in the Windows scratch, and `g03_cleanup` deletes that scratch at exit. The patch copies
the state file into the case artifacts. No criterion or step changed. Every other harness file has its
in-tree sha256 (`environment.harness_sha256_*` in each record). The in-tree harness, its README and
`CHANGELOG-native.md` were not edited, because they are outside this task's write scope.

The wrapper `scripts/run.sh` pinned `TMPDIR` and Windows `TEMP`/`TMP` (`WSLENV=TEMP/p:TMP/p`) to the task
scratch. Every run used `--target-distro hm-g03b-732254 --allow-terminate-target`.

| Run | What | Exit | UTC |
|---|---|---|---|
| **r1** (promoted) | all three probes, shipped config (systemd=true), idle watch 120 s | 0 | 22:55:41–22:58:07 |
| c1-systemd (supplementary) | `scripts/idle_control.sh`: terminate, `wsl -d target --exec /bin/true` (no background process), poll every 5 s for 180 s | 0 | 22:58:40– |
| r2-idle600 (supplementary) | `--probes idle --idle-wait-seconds 600`, systemd=true | 0 | 22:59:20–23:09:37 |
| variant | `scripts/variant_nosystemd.sh`: `/tmp` facts under systemd, then `systemd=false` in the target's `/etc/wsl.conf`, terminate, facts. The script's exit 1 is the last check's `&&` chain (no systemctl in that configuration); every state-changing step exited 0 (`transcripts/variant-nosystemd.txt`) | 1 | 23:10:01– |
| c2-nosystemd (supplementary) | the c1 control with systemd=false (PID 1 = WSL init) | 0 | 23:10:10– |
| r3-nosystemd (supplementary) | `--probes restart,idle`, systemd=false, idle watch 120 s | 0 | 23:10:39–23:12:52 |

The commands inside each probe, with exit codes, are in each record's `commands_or_harness`. Raw records,
observations and stdout/stderr are in `runs/<run>/`, and console logs in `transcripts/<run>.console.txt`.
All 15 stderr files of the three runs are empty.

## 5. Results [O]

**P-B08 (r1): `verified`, verdict `pass`.** Criteria: the endpoint serves inside the target, the private
path is not visible from the controller, and the exposure matrix was measured. Matrix:

| Placement in the target (user `hg03t`, uid 1000) | From the controller (`<owner-distro-A>`, uid 1000) | From Windows (same user) |
|---|---|---|
| private path `/tmp/hg03-…/ep/agent.sock` (dir 0700) | not visible (separate mount namespace) | the socket file is visible through `\\wsl.localhost\hm-g03b-732254\…` (`Test-Path` = True; connecting was not attempted) |
| abstract namespace `@hg03-…` | reachable (banner) | not measured |
| `/mnt/wsl/hg03-….sock` (bound under umask 0177, i.e. 0600, per `exposure_listener.py`) | reachable (banner) | not measured |
| loopback TCP `127.0.0.1:<port>` | reachable (banner) | reachable (banner via PowerShell `TcpClient`, networking mode `nat`) |
| the agent endpoint itself via `wsl.exe -d hm-g03b-732254 -u hg03t -- python3 agent_client.py …` | the list succeeded (type 12, the target key) | — |

Namespaces: network namespace shared (`net:[4026531833]` in both), mount namespace different.

**P-B09 (r1): `verified`, verdict `pass`.** Before restart, the `/tmp` proxy served the list. After
`wsl --terminate` the target was not running at the first check (0 s). After the restart the proxy
process was gone (pid plus start token). The `/tmp` socket was absent and the `$HOME/.cache` socket was
present but stale: the client got ECONNREFUSED (errno 111, exit 2), so the stale endpoint failed cleanly.
In the systemd target `/tmp` is not a separate mount and `systemd-tmpfiles-setup.service` is active, so
boot-time `/tmp` cleaning is the likely reason the socket disappeared [I]. **r3, without systemd:** same
criteria, all true. But the `/tmp` socket was **present** (stale) after the restart as well, and the
client on the `$HOME` socket again got ECONNREFUSED.

**P-B10 (r1): `verified`, verdict `pass`.** This is an observation criterion (timeline recorded). With the
detached endpoint (agent_proxy plus ssh-agent started with `setsid nohup`, no session left), the target was
`running` at every poll from t+0 to t+115 s, and `stopped_after_seconds` is null. Supplementary results:

| Run | init | Background process | Result |
|---|---|---|---|
| c1-systemd | systemd | none (`/bin/true`) | stopped at the t+15 s poll (running at t+10 s) |
| r1 | systemd | detached endpoint | running through t+115 s (120 s watch) |
| r2-idle600 | systemd | detached endpoint | running through t+595 s (600 s watch) |
| c2-nosystemd | WSL init | none | stopped at the t+15 s poll |
| r3-nosystemd | WSL init | detached endpoint | running through t+115 s (120 s watch) |

The `t+N` values are nominal sleep seconds. Each poll also runs `wsl.exe -l --running -q`, so wall time is
longer: the whole r2 harness run (terminate, start, 120 polls) took 617 s. Reading [I]: in both init configurations the instance stops at about
the documented 15 s `instanceIdleTimeout` once nothing runs, while a detached endpoint process keeps it
running for at least 10 minutes. A Mode B helper is therefore not ended by idle shutdown while it runs,
and it also keeps the distribution (and its share of the VM) alive. The supervisor must stop it
explicitly. How long it would persist beyond 600 s was not observed [U].

## 6. Inventory before and after (`transcripts/inventory-*.txt`, `inventory-compare.txt`) [O]

```
before (22:54:44Z)                         after (23:13:08Z)
  NAME      STATE           VERSION          NAME      STATE           VERSION
* <owner-distro-A>    Running         2    * <owner-distro-A>    Running         2
```

The NUL-stripped `wsl -l -v` outputs compare equal: `diff` exit 0. The same holds against the task's first
inventory, taken before the image download. The default distribution is unchanged. During the task, only
`hm-g03b-732254` was added, terminated and unregistered. `--shutdown` was never run, and no other
distribution was terminated, exported or modified.

## 7. Cleanup [O]

- `wsl --terminate hm-g03b-732254` exit 0. `wsl --unregister hm-g03b-732254` exit 0. Unregister also
  deleted the install directory: the follow-up `ls` exits 2 (`transcripts/cleanup.txt`).
- Afterwards, side-effect counters are back to the "before" values (§3). Registered `hm-g03b-*`
  distributions: 0.
- In the controller: harness-like processes (proxy, listener, keepalive, harness) 0; ssh-agents on
  `/tmp/hg03*` sockets 0; `hg03-*` directories in `/tmp` and `$XDG_RUNTIME_DIR` 0. Process checks printed
  counts only.
- `%LOCALAPPDATA%\hm-m00\M00-T04-g03-wsl-b\` (tarball, scripts, harness temp) and
  `~/hm-m00/M00-T04-g03-wsl-b/` were removed (rm exit 0, both absent afterwards). The parent `hm-m00`
  directories date from 2026-10-06 and were left in place.
- The Mac-side temporary download, bundle and work directories were removed.

## 8. Limitations

- One host, WSL 3.0.3.0, Windows 10.0.26300.9711, networking mode `nat` only. Mirrored and Consomme modes
  were not measured, and the loopback rows hold for `nat` only.
- The target is the official Ubuntu 24.04.5 image with a task-created uid-1000 default user instead of
  the image's OOBE user. A root-default target and other distributions (e.g. Debian) were not measured.
- P-B08 measures default reachability, not isolation. Microsoft states that distributions of one user
  are not a security boundary. Windows visibility of the private-path socket file was measured; a
  Windows-side connection to it was not.
- P-B10: the owner's `.wslconfig` idle settings were not read. The c1/c2 controls measure the effective
  baseline instead. The polling granularity is 5 s nominal.
- r2, r3, c1 and c2 are supplementary. Their outcomes are added to the promoted r1 records under
  `observed_result.supplementary_not_harness_criteria`. r3 and c2 ran with `systemd=false`, set only in
  the disposable distribution.
- While the distribution existed (22:55–23:13Z), WSL had a Windows Terminal profile fragment for it.
  Windows Terminal's own settings were not read, so whether Terminal recorded the generated profile is
  [U]. The fragment itself was removed by unregister.
- Redaction: `tests/native/wsl/evidence.py redact-tree` (user, host, home and profile paths, SIDs,
  e-mail), then `scripts/redact_extra.py` (the owner's distribution name in context, private IPv4). A
  Mac-side scan of this directory for the actual user, host and home values, the owner's distribution
  name in context, SIDs, private IPv4, the canary prefix and private-key headers found nothing. The only
  hits were the Ubuntu CD-image key name and e-mail address in `rootfs/gpg-verify.txt`.
