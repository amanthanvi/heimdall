# G04 / preliminary G09 OpenSSH mechanism experiments

These scripts run the experiments designed in
`docs/research/g04-managed-credentials.md` §8.1 (E1–E7 plus enrollment mechanics) against the
disposable Docker sshd fixtures in `tests/fixtures/ssh/` (M00-T03).

**What this is:** evidence about OpenSSH mechanisms. The host client is `/usr/bin/ssh`, and
`sshd` runs in the fixture containers. **What this is not:** evidence of Heimdall behavior (no
Heimdall code exists or runs here). It is also not desktop-lock, sleep, logout, reboot or
secure-store evidence (those are the owner-run probes P1–P6 / P-W* / P-L*). Nothing here closes
a native Windows, WSL or Linux-host claim.

## How to run

```sh
# complete fresh run: fixture down -> up (new keys/CA/containers) -> smoke -> all experiments
tests/native/g04/fresh_run.sh          # fixtures are left up for review / single re-runs
STAMP=<the G04_RUN_STAMP it printed>
tests/fixtures/ssh/down.sh > tests/evidence/artifacts/g04/experiments/$STAMP/fixture-down-post.log 2>&1
# (redact <repo>/<home> in that log, then append "exit=<rc>")
python3 -m venv tests/native/g04/.venv && tests/native/g04/.venv/bin/pip install jsonschema   # once
tests/native/g04/.venv/bin/python tests/native/g04/make_records.py $STAMP --validate
```

`run_all.sh` alone runs the experiments against fixtures that are already up. A single
experiment can be run directly (`tests/native/g04/e3_principal_scope.sh`). Set
`G04_RUN_STAMP` to choose the output directory. Knobs (defaults in `run.env` of each run):
`G04_E1_LIFETIME` (120 s), `G04_E2_LEAD` (90 s), `G04_E2_GRACE_CHECK` (1),
`G04_E5_CHILD_LIFE` (60 s), `G04_E7_VALID` (90 s), `G04_E7_PERSIST` (10m), `G04_RACE_N` (50),
`G04_RACE_PERSIST` (3 s), `G04_RACE_CLIENT_MAX_MS` (60), `G04_RACE_STOP_MAX_MS` (40), `G04_E7P_VALID` (40 s),
`G04_E7P_DELAY1` (2 s), `G04_E7P_DELAY2` (15 s). A full run takes about 20 minutes. E2 waits out the fixed 300 s
agent-side certificate grace. Run it detached (not in a terminal or tool call that can time out):
an interrupted run is incomplete evidence.

Outputs go to `tests/evidence/artifacts/g04/experiments/<stamp>/`:

- `<exp>.log`: a redacted transcript, with every command, its output and its real `rc`, plus the
  relevant new sshd log lines.
- `<exp>.results.tsv`: `CHECK` / `OBS` / `FACT` / `CLEANUP` / `EXIT` rows.
- `exit-codes.txt`, `run.env`, `script-sha256.txt`, `fixture-versions.txt`, `fixture-*.log`.

`make_records.py` turns one run into `tests/evidence/g04-exp-*.json`.

## Exit codes and record semantics

Each experiment exits with one of these codes:

- `0`: it ran to completion and every `CHECK` held.
- `1`: it ran to completion and at least one `CHECK` did not hold.
- `3`: setup failure or interruption (incomplete).

`OBS` rows are hypotheses, recorded as CONFIRMED or REFUTED. A refuted hypothesis is a finding,
so it never changes the exit code.

Records follow the gate-probe convention in `tests/evidence/README.md`. `status` describes the
evidence:

- `verified`: it ran as designed and all validity preconditions held.
- `in_progress`: it was incomplete or invalid.

`observed_result.verdict` is `pass`, `fail` or `inconclusive` against the experiment's stated
criterion, which is copied into the record. `make_records.py` classifies each row:

- **validity:** preconditions that make the measurement meaningful.
- **criterion:** rows that decide the verdict.
- **info / finding:** recorded, but not part of the criterion.

The tables in `make_records.py` define the classification.

## What each experiment shows (and does not)

| Script | Shows | Does not show |
|---|---|---|
| `e1_dedicated_agent.sh` (E1) | A dedicated `ssh-agent -U -a <tmp>` holds a disposable key and certificate whose private file was deleted. A fresh login works only through that agent (`IdentityAgent=none` fails), and only the temp socket is used (`ssh -G`, `-vvv`, agent debug log). The `ssh-add -t` lifetime ends signing. An exact-PID kill removes the process and socket. | Agent behavior across lock, sleep, logout or reboot. Secure erasure of the deleted key file. |
| `e2_cert_expiry.sh` (E2) | sshd enforces the certificate window for **new** authentication. Not-yet-valid and expired certificates are refused with the logged reason. Back-to-back logins around `valid_before` show where acceptance stops. Refusal after expiry is the same whether or not the agent still holds the certificate (default `ssh-add` grace vs `-N`, before and after agent-side removal). | Existing connections or multiplexed sessions (E7). Skewed or rolled-back server clocks: host and container share the Docker VM clock. |
| `e3_principal_scope.sh` (E3) | System-level trust (`TrustedUserCAKeys` + per-host principals file): a `{p-host1}` certificate works on ca1 only, and `{p-host2}` on ca2 only. A two-principal certificate works on **both**; this is recorded as "usable on both", never as scoped. The username principal, a rogue CA and the bare key are refused. Each refusal requires that sshd evaluated that certificate (Failed line with its ID) and, where relevant, logged the principal reason. | Account-level trust (E4). Scope enforced by anything other than the server's principal map. |
| `e4_account_ca_principals.sh` (E4) | Account-level `cert-authority,principals="hm:fx-enroll:enroll"` added by a preimage-checked, temp-file and atomic-rename, marker-tagged transaction. Only the `hm:` principal is accepted. The username principal and our CA's `ops` principal are refused with the principal reason. A control shows our `ops` certificate is also refused by the seed's own `ops` line (different CA key) before our line exists. Removal by marker restores the seed bytes exactly. | The check-then-rename race window. Interrupted mutation or lost responses (`outcome_unknown`). KRL / `RevokedKeys`. |
| `enroll_marker_key.sh` | Enrollment mechanics (spec §7.5): add a marker key alongside existing access. Verify a fresh authentication offering only that key, with no mux and no fallback. A concurrent administrator edit lands. Remove only the marker line; every unrelated byte and the concurrent edit are preserved. | Discovery of the authoritative registry on real hosts. Rotation. Interrupted mutation. |
| `e5_issuer_separation.sh` (E5) | The CA lives only in an issuer agent. The worker-only environment cannot see or use it, and no CA material is present in the worker/child files, agent argv/env or worker env. The issued child certificate carries a principal subset and earlier expiry (read back with `ssh-keygen -L`). sshd refuses the child on the other host and after its expiry, while the parent keeps working. Also recorded as findings: a same-user process that knows the issuer socket path **can** obtain signatures, and the fixture CA private key file stays readable by the same user from the worker-only environment (the separation is environment and endpoint only). | Any OS-level isolation (all are one user). Issuance policy enforcement: `ssh-agent` signs whatever it is asked. Process-memory scanning. |
| `e6_fresh_login_verification.sh` (E6) | With a live ControlMaster open, the verification command produces exactly one new `Accepted publickey ... ID <id>` line. Reuse through the control socket succeeds with no new authentication, so reuse is not verification. | Freshness on servers without VERBOSE logging. |
| `e7_mux_after_expiry.sh` (E7, preliminary G09) | Whether an existing master admits new sessions after certificate expiry (H1, H1b), and what `ssh -O stop` does to clients that connect **after** the stop (H2a–H2c: socket gone, new clients fall back to a fresh and refused connection, the open session continues). Whether the master exits after its last session when no other control connection is open (H2d). What `-O exit` does to the master, the open session and the remote no-tty shell (H3, H3b). | Control connections accepted **before** the stop (phase 5 below). Policy selection (ordinary/strict, spec P06). Detached remote processes (`nohup`/`setsid`). Unmanaged connections. Other OpenSSH versions. |
| `e7_mux_preconnected.py` via `e7_mux_preconnected.sh` (E7 phase 5, preliminary G09; adopted from the M00-review-g04 probe) | Whether a mux control connection the master accepted **before** `ssh -O stop` can still obtain, after stop returned: a new session on ca1 after certificate expiry (H2e at stop+2 s, H2e2 at stop+15 s), a local forward (H2f), a remote forward (H2g) and a stdio forward (H2h) on the bastion fixture. Controls show each request type works before the stop. Findings: the stopped master stays up while an idle pre-accepted connection is open (H2d-held) and exits when it closes (H2d-exit); `-O exit` (H3c) and exact-PID SIGTERM (H3d) close pre-accepted connections and forwards. Uses a raw mux protocol v4 client (Python 3.9, fd passing). | `MUX_C_PROXY`, dynamic and streamlocal forwards. Pre-accepted connections made by a real ssh client in mid-start (the raw client stands in for any same-user process). Other OpenSSH versions. |
| `e7_mux_stop_race.sh` (E7 race) | 50 iterations of a client that cannot authenticate, racing `-O stop` on a fresh master with randomized start delays (client 0–60 ms, stop 0–40 ms). Counts admissions of clients that started after the stop call returned; at least 5 such clients are required for a valid run. Overlapping cases are reported separately. | The exact `MUX_S_OK` instant (not observable from the host). Proof that no race exists. That `-O stop` stops admissions: classification is by client process start time, so a client whose control connection was accepted before the listener closed is not distinguished (phase 5 shows such connections are still admitted). |

## Safety rules (enforced in `lib.sh`)

- `SSH_AUTH_SOCK` is unset, and `/usr/bin/ssh*` is called by absolute path.
- Every `ssh` call uses `-F <generated config>` with `StrictHostKeyChecking yes`, the fixture
  `known_hosts`, `GlobalKnownHostsFile /dev/null`, `IdentitiesOnly yes`, and a dedicated agent or
  `none`.
- The owner's `~/.ssh`, agent, keychains and live hosts are never touched. Only loopback fixture
  ports are contacted.
- Private keys are generated in a 0700 temp dir and deleted right after `ssh-add`.
- Agents and masters are tracked by PID plus start time plus executable, and are signalled only
  after that identity is re-checked. Nothing is killed by name or pattern.
- Logs are redacted. CA private material is never printed: the E5 scan prints counts only.
