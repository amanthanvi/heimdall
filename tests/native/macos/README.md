# macOS native probes (G04 / M00-T04)

Owner-run, human-in-the-loop probes. Agents can run only the non-lock smoke path; any
lock, logout, sleep, or reboot measurement needs you at the console. Background and the
full experiment design: [`docs/research/g04-managed-credentials.md`](../../../docs/research/g04-managed-credentials.md).

## `g04_lock_probe.sh` — does a dedicated signer and a disposable keychain survive screen lock?

Every few seconds (default 5 s) it records:

1. Whether a **dedicated `ssh-agent`** can still sign. The probe starts this agent itself and
   loads a freshly generated disposable key, then deletes the private key file, so the key
   exists only in that agent's memory. It checks with `ssh-add -T` and
   `ssh-keygen -Y sign` + `-Y check-novalidate`.
2. Whether an item in a **disposable custom keychain** is still readable. The probe creates
   this keychain with `security create-keychain` in a temp dir, with auto-lock disabled, and
   stores a random value in it. That value is compared inside the script and never printed.
3. Optionally, with `--fixture-runtime`, whether a **fresh SSH login** still succeeds. It
   uses `ControlMaster=no`, `IdentitiesOnly=yes`, only the dedicated agent, and a
   short-lived certificate (principal `p-host1`) from the M00-T03 fixture CA. Fixture `ca1`
   must accept the login. Before sampling starts, `ca2` must reject it (principal scope) and
   `ca1` must reject it without the agent (no fallback path).
4. Two IORegistry lock signals (`IOConsoleLocked`, `CGSSessionScreenIsLocked`), as
   corroboration only. They are undocumented. Only these two booleans are kept.

### What it never touches

Your `~/.ssh` (the agent gets `HOME=<temp>`, `-U`, and `-a <temp socket>`), your
`SSH_AUTH_SOCK` agent (unset at start), the login keychain, 1Password, or any host other
than loopback fixture containers. At cleanup it kills only the exact PIDs it started, after
re-checking each PID's start time and executable. It never uses `pkill`/`killall`.

Side effects you should know about:
- A `caffeinate -i` idle-sleep assertion while it runs (`--no-caffeinate` to skip). It
  exits with the probe.
- On macOS 27.0 the new keychain was observed **not** to join your keychain search list, and
  the search list and default keychain digests were unchanged after cleanup
  (`tests/evidence/artifacts/g04/research/k1-keychain-mechanics/transcript.log`). The probe
  re-checks both at cleanup and reports any change.
- On macOS 26.4 and later, a keychain file may reference a protected entropy file in
  `/var/db/SystemKeys` (Apple TN3137). Whether `delete-keychain` removes it cannot be
  inspected without disabling SIP. Treat it as possible residue.
- If, after you unlock, macOS asks for the password of a keychain named
  `heimdall-g04-probe`, click **Cancel**. Answer **y** to the second question; that dialog is
  itself a finding.

### Run it

1. Smoke test first (screen stays unlocked, about 30 s):

   ```sh
   tests/native/macos/g04_lock_probe.sh --mode smoke
   ```

   Expect `exit=0`, `status=verified` and `verdict=pass`.

2. Optional, for A03-style fresh SSH logins during the lock: bring up the fixture with
   `tests/fixtures/ssh/up.sh` and add `--fixture-runtime tests/fixtures/ssh/runtime` to the
   command in step 3. Run `tests/fixtures/ssh/down.sh` afterwards.
   - The probe certificate is valid for about 30 minutes beyond `--lock-seconds`, so do not
     stay locked longer than that.
   - A failed login during the lock with successful agent signing points to the fixture
     side (Docker Desktop), not the signer. The record keeps the two separately.

3. The lock run, about 2–3 minutes:

   ```sh
   tests/native/macos/g04_lock_probe.sh --mode lock            # add --fixture-runtime ... if wanted
   ```

   - Wait for the baseline samples. When told to, lock the screen with **Control-Command-Q**.
     Do not log out, sleep, or close the lid.
   - Stay locked for at least 60 s (`--lock-seconds` changes the advice).
   - Unlock, return to the terminal, and press **Enter**. It takes a few more samples and asks:
     - Did the screen really lock for about that long?
     - Did any `heimdall-g04-probe` keychain dialog appear?

### Output

- Evidence record: `tests/evidence/g04-macos-screen-lock-probe-<UTC>.json`
  (smoke: `g04-macos-lock-probe-smoke-<UTC>.json`). It follows
  `tests/evidence/record.schema.json`. It contains OS version and build, architecture,
  hardware model and OpenSSH version, but no hostname or user name.
- Raw samples and log: `tests/evidence/artifacts/g04/research/lock-probe/<UTC>-<mode>/`
  (`samples.ndjson`, `samples.tsv`, `run.log`, which ends with `exit=<code>`).
- Exit status:

  | Code | Meaning |
  |---|---|
  | 0 | Measurement valid (`status: verified`), `verdict: pass`, cleanup complete |
  | 1 | Completed, but no valid measurement (for example no lock window: `status: in_progress`, `verdict: inconclusive`) or `verdict: fail` |
  | 2 | Usage error |
  | 3 | Precondition or setup failure |
  | 4 | Cleanup incomplete, or a canary was found in the artifacts |
  | 5 | Interrupted (cleanup still runs) |

- `status: verified` in a lock record means **the measurement is valid**: a lock window was
  established by the IORegistry signal or by your attestation, cleanup was complete, and no
  canary was found. The availability answer is in `observed_result.outcomes_in_window`
  (`available_all_samples`, `unavailable_all_samples`, `intermittent`, `not_measured`). A
  valid measurement can be negative.
- Records follow the gate-probe convention in `tests/evidence/README.md` (probe v2, since
  M00-T04-G04-fix). `observed_result.verdict` is `pass`, `fail` or `inconclusive` against the
  `observed_result.criterion` written into the record. Lock mode: pass when the dedicated agent
  signs (and, with `--fixture-runtime`, the fresh SSH login succeeds) in every lock-window sample;
  the disposable keychain outcome is recorded but is not part of the verdict. The verdict is
  `inconclusive` whenever `status` is not `verified`. Smoke records carry no product requirement
  IDs, because a smoke run exercises no lock. Lock records list R-CR-02/R-CR-03/R-EN-04 for
  traceability only.

After a run, send the record path to whoever integrates M00. The blocked placeholder
`tests/evidence/g04-macos-screen-lock-probe.json` is then superseded, not edited.

### If something goes wrong

The terminal shows each PID it started (`dedicated ssh-agent pid=...`, `caffeinate ... pid=...`).
If the record reports `cleanup.complete: false`, check only those PIDs, for example
`ps -o pid=,lstart=,comm= -p <pid>`, and end a leftover probe agent with `kill <pid>`. Do not
kill other `ssh-agent` processes; your own agent must stay running.

## `g04_lock_probe_selftest.sh` — agent-runnable check of the `--fixture-runtime` path

It needs Docker and does not need the M00-T03 fixture. It does the following:

- Builds a throwaway sshd image from the same pinned Debian digest. This downloads
  `openssh-server`.
- Starts two loopback-only containers that mimic fixture `ca1`/`ca2`.
- Writes a fixture-shaped runtime dir in a temp dir outside the repository, because it
  holds a disposable CA private key.
- Runs the probe in smoke mode against them.
- Removes the containers, the image and the temp dir.

Extra arguments are passed to the probe.
