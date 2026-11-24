<!-- Archived scoped re-check (Claude Opus), M06 wave 5 (25229f74..2305a46c), 2026-11-23: NOT CLOSED on M06-W5-RC01; RC01..RC05 fixed in 5bd0bdbe (RC01 by ruling option (b)). Verbatim, except one canary-shaped fixture token in RC05 shown as HEIMDALL_CANARY_<fixture>. -->
# M06 W5: the scoped re-check

- **Candidate:** `2305a46c749523dc98ab97ca314c3b03472614d5` (`origin/m06/w5`).
- **Scope:** `git diff 25229f74 2305a46c`, without the main merge `e8341954`. The commits in scope are `cde5766b`, `b15b67ec`, `9946cd33`, `7605623b` and `2305a46c`.
- **Reviewer:** the single scoped re-check (ADR-0009 §2 item 1).
- **Input:** I read the independent review (`m06-w5-review-out/report.md` and its `probes/`) first.
- **Method:**
  - I read the diff by item.
  - I ran focused crate tests, `e2e_exit_m06` and `tools/validation/release-gate.sh` in a detached worktree at the candidate.
  - I added three scratch probe tests to that worktree only (`probes/recheck-probes.diff`). They were never committed, and the worktree has been removed.
  - I ran nothing remote, no `check.sh`, no `connect` or `run -- ssh`, and nothing that touches the owner's keys, agent, keychain or `~/.ssh`.

## Verdict: NOT CLOSED (ADR-0009 §2)

The five findings and items 3 to 6 are closed as ruled, with one exception: R01 is **partly closed**. The verdict rests on **M06-W5-RC01** alone.

**What RC01 is (reproduced):**
- A paired owner controller's `policy remove` is a narrowing. It needs no decision and leaves no record.
- That removal makes the runner report another controller's delivered cutoff as no longer in force.
- No runner-local approval ever named that cutoff.
- After the removal, the second controller's barrier admits issuance that the cutoff was still blocking.
- This contradicts ADR-0006 §18.9 item 4 ("only a runner-local lift clears it").
- It also contradicts the R01 ruling: "a paired session's request that would lift a delivered effect is refused at request time … only the runner's local owner lifts a delivered effect" (ADR-0012 §7.4, `:679`).

**Why both §2.1 conditions hold, in my reading:**
- **A lasting effect on remote trust, and a bypass of the runner-local consent:** the in-force flag is never set again once cleared, and every other controller's barrier reads it.
- **A trigger Heimdall must withstand:** a remote party, namely an owner-role paired controller.

**The hinge:**
- **Precondition:** the runner's owner must first have cleared, attended, every other policy the cutoff applied to.
- **The runner's own checks are unchanged:** its install check against its standing policies is the same. So what the second controller can now issue is what the runner's policies already allow.
- **The delivering controller is still protected:** its own two keys still hold.
- **If the orchestrator rules otherwise:** if the in-force flag counts as controller coordination rather than "remote trust" under §2.1, RC01 becomes fix-soon and this verdict becomes CLOSED (merge).

**Where it came from:** RC01 has been in the wave since its first candidate `25229f74`. I established that by comparing the source; I did not re-run the probe there. The fix commits did not introduce it. R01's fix named every lift that an approval causes, but kept the implicit report-time lift rule that RC01 goes through.

**The other new findings** are low or nit and do not block.

## The findings and rulings

| Item | Status | Evidence at `2305a46c` | Pinned by | What I ran |
|---|---|---|---|---|
| **R01** every lift named; untargeted form; paired refusal; stale re-check; `decision_binding_mismatch` kept | **Partly closed** | See "R01 evidence" below | Five new tests in `tests/integration/runner_effects_m06.rs`: `resume_of_a_held_policy_names_…`, `clear_cutoff_of_a_policy_names_…`, `a_record_made_before_…`, `a_paired_sessions_request_…`, `a_cutoff_delivered_after_…`. Plus e2e `a_delivered_pause_of_a_held_policy_is_named_by_access_resume` | `integration_runner_effects_m06`: 19/19. `integration_controller_driver_m06`: 30/30. `e2e_exit_m06`: 10/10 |
| **R02** a different relay set for an approved Iroh route is `CONFIG_CONFLICT` | Closed | `crates/app/src/routes_ops.rs:368-381` (`EXPOSURE_DIFFERS` `:69`), inside `add_inner`. The dry run (`:283`, which `add_precheck` uses) runs the same check, so nothing is recorded first | `dispatch::tests::a_local_widening_is_recorded_and_approved_only_by_the_attended_local_owner` (`CONFIG_CONFLICT`, no record, routes unchanged) | `heimdall-runtime --lib dispatch::tests`: 14 passed |
| **R03** the ADR text matches the code | Closed | ADR-0012 §2.3 `:142` and ADR-0006 §18.9 item 1 `:2598` say "disable, then enable; any other configuration is `CONFIG_CONFLICT`". The code is unchanged and agrees (`crates/app/src/transport.rs:597-612`) | — | Read |
| **R04** the runner-side scripts set the three fixture-store variables | Closed | `tests/native/m06/crosshost-runner.sh`: `:113-127` (`hm_env`), `:155-156` (runtime), `:263-265` (work launcher). `tests/native/m06/windows-controller-runner.sh`: `:113-117`, `:224-229` (`hm`), `:271` (sshd `SetEnv`), `:353-365` (runtime), `:494` (store directory created), `:541-542` (seed driver) | `selftest.sh:625` `m06_runner_scripts_start_heimdall_with_the_three_fixture_key_stores` | That check's Python body, standalone on both scripts: exit 0, nothing missing. I did not run `selftest.sh` as a whole |
| **R05** a relay URL is shown only as scheme, host, port and a short digest | Closed (for answers) | `crates/contract/src/route.rs:302` (`relay_display`) and `:351` (`display_relay_urls`, keys `relays` and `relays_added` at any depth: the only relay-bearing fields I found). Applied to every answer at `crates/runtime/src/dispatch.rs:588` (`handle`) and `:680` (`handle_as`). The refusal detail uses it at `crates/runtime/src/local_widening.rs:111`. Stored as given | `dispatch::tests::a_relay_urls_path_is_stored_and_never_shown` (refusal, `APPROVAL_REQUIRED`, `inspect decisions`, approval, `inspect destinations`, event page, `already_present`). `route::tests::a_relay_url_is_shown_without_its_path` | `dispatch::tests`: 14 passed. `heimdall-contract --lib route`: 6 passed. See observation 3 for the limits |
| **3** the management key agent: socket directory, typed reasons, blame | Closed on Unix. Windows read only. One wording gap: RC03 | See "Item 3 evidence" below | `heimdall-credential --lib mgmt::agent`, 13 tests (the sweep, squatting, fresh names, path limit, denied base, live agent). `remote_env::tests::a_runner_refusal_worded_as_this_controllers_fault_is_not_reclassified`. The `heimdall` bin tests `assert_agent_class` and `every_session_opener_failure_on_this_controller_is_classed_as_its_fault` | mgmt::agent: 13 passed. app `remote_env`: 32 passed. contracts `rev6`: 6 passed. I read the bin unit tests but did not run them: that crate's unit tests are outside the brief's list |
| **4** an unreached runner's reasons by whether a retry can help | Closed | See "Item 4 evidence" below | `remote_env::ssh::tests::an_unreached_runner_is_classified_from_the_clients_own_words` (the POSIX and Win32 lines as sourced) | app `remote_env`: 32 passed |
| **5** debug-only `HEIMDALL_TEST_SSH_STDERR_FILE`, refused by a release build | Closed | See "Item 5 evidence" below | `testcfg` tests (read). The release-gate probe | `release-gate.sh`: exit 0, 42 probes, 0 failed. That includes `HEIMDALL_TEST_SSH_STDERR_FILE` for `run -- true`, `connect x` and `environment add`, plus "the bootstrap's ssh diagnostic file was not written by the release build: PASS" |
| **6** Windows `ProgramData` | Closed in code. Windows behaviour not observed | See "Item 6 evidence" below | `a_windows_client_without_program_data_is_never_started`. `wsl_exe_carries_what_an_interop_ssh_exe_needs` (only its non-Windows branch runs here). `the_windows_inbox_client_preflight_from_a_pseudoconsole` (Windows only) | app `remote_env`: 32 passed. `heimdall-wsl --lib spawn`: 4 passed |

### R01 evidence (all in `crates/app/src/operations/stop_m05.rs` unless named)

- **Every lift named:** `implied_lifts` `:346`, over `Txn::lifted_if` and `judged_lifted` (`crates/store/src/ext_effects.rs:980` and `:1000`). The result is unioned into the targeted basis at `:942`.
- **The untargeted form on a held policy:** converted at `:728` (`delivered_lift_form`).
- **The paired refusal:** `:456`, called before any record at `:842` (targeted) and at `crates/app/src/operations.rs:12131` (untargeted).
- **The approval re-check:** `lift_binding` `:403`, through `precheck` `:1115` and `crates/app/src/operations.rs:12344`. An unnamed lift answers `DECISION_STALE`, writes nothing and leaves the record pending.
- **Named lifts are cleared at approval:** `:1156`.
- **`decision_binding_mismatch`:** the diff never touches it.
- **The gaps:** RC01 and RC02.

### Item 3 evidence

**The socket directory** (`crates/credential/src/mgmt/agent.rs` unless named):
- `AgentDir::create` `:473` sweeps leftovers, then calls `create_fresh` `:490`, which tries at most three names, and only after "in use".
- `create_in` `:515` checks the tag and the length before `mkdir`.
- `crates/ipc/src/unix.rs:350` creates the directory exclusively with mode 0700, then verifies it. `crates/ipc/src/unix.rs:366` verifies the owner, the mode, and that `lstat` and `fstat` agree.
- **The base:** `agent_dir_base` `:560` uses an owner-only `$XDG_RUNTIME_DIR` on Linux, read without following a link, and `/tmp` otherwise.

**Stale cleanup:**
- The sweep (`:584`) needs the exact name, a real directory, this uid, mode exactly 0700, at least 60 s since the last change, and only `a.sock`/`p.sock`, each a dead socket of this uid.
- `remove_agent_dir` `:650` re-checks the directory's `(dev, ino)` identity, unlinks only those two names (sockets of this uid), and removes the directory without recursing.
- The test covers live, foreign-content, 0755, misnamed, link, plain-file and recent entries, and all of them are kept.
- In my reading, cleanup never removes anything that is not its own. A same-user race is spec P03.

**Reasons:**
- `crates/heimdall/src/m06_cmd.rs:2414` (`agent_failed`).
- `crates/contract/src/envelope.rs:871-874`, and the golden file.

**Blame:**
- The flag is `crates/app/src/error.rs:63`.
- It is set only by `crates/app/src/remote_env.rs:573` (`controller_fault`) and `:584` (`on_this_controller`).
- `from_detail` (`crates/app/src/error.rs:220`) always leaves it false, so a runner's refusal is never reclassified.

**Windows (read only):**
- `start_pipe_from` `:218` and `bind_pipe` `:260`.
- `:274` maps `ERROR_ACCESS_DENIED` to "in use", as ruled.

### Item 4 evidence (`crates/app/src/remote_env_ssh.rs` unless named)

- **The causes:** `UnreachableCause` `:408`, with the code split in `code()`.
- **The markers:** `unreachable_cause` `:518` reads them, the client's own refusal first.
- **The authentication marker:** `classify_preflight` `:539` narrows it to "Permission denied (", so an `EACCES` on a file can no longer read as a verified host.
- **A silent client:** `classify_preflight_run` `:606` treats silence with an exit status outside 0–255 as "not started".
- **In the preflight:** a spawn failure is "not started" and a timeout is "timed out".
- **The management session:** uses `crates/heimdall/src/m06_cmd.rs:2340` (`session_error`).

### Item 5 evidence

- **The variable:** `crates/heimdall/src/testcfg.rs:96`, in `LAUNCH_ENV` (`:100-107`). The path must be absolute.
- **Where it is written:** only by `append_stderr_record` (`crates/app/src/remote_env_ssh.rs:618`). It creates and appends, with mode 0600 on Unix, and bounds what it writes to `STDERR_MAX`.
- **Which runs write it:** the preflight, the bootstrap session (`-E`) and a failed management session (`crates/heimdall/src/m06_cmd.rs:2703`).
- **Release refusal:** `launch_hooks` refuses any `LAUNCH_ENV` variable in a release build (`crates/heimdall/src/testcfg.rs:193-199`), and `environment` checks it before anything else.
- **Limits:** see RC05 and observation 4.

### Item 6 evidence (`crates/app/src/remote_env_ssh.rs` unless named)

- **The refusal:** `:574`, active only under `cfg!(windows)` (`:593`).
- **Where it is checked:**
  - in the preflight before the spawn (`:726`), and the bootstrap session runs only after the preflight;
  - in `spawn_management` (`:862`), flagged as this controller's fault through `ssh_spawn_failed`.
- **The test driver** passes `ProgramData` (`tests/e2e/windows_controller_m06.rs:336-347`).
- **The WSL helper:** `crates/wsl/src/spawn.rs:92` fills only the variables the child would lack, from the operating system, never from the parent.
- **Not verified (inference):** that a WSL interop `ssh.exe` inherits the environment of `wsl.exe`.

## New findings

### M06-W5-RC01 (moderate; blocking in my reading of §2.1): a paired `policy remove` lifts another controller's delivered effect with no approval naming it

**Where:**
- `crates/store/src/ext_effects.rs:1000-1046` (`judged_lifted`, the rule at `:1032`: "at least one applied policy still exists and none that exists is blocked"). It runs at every authority report: `note_lifted_policy_revisions` `:954`, called from `authority_report`.
- `crates/app/src/operations/trust_m05.rs:719`: `Narrow::Remove` deletes the policy, with no decision.
- `crates/remote/src/roles.rs:278`: a paired owner's non-widening `Policy` request is `Narrow`, dispatched as is (`crates/runtime/src/dispatch.rs:891` passes it to `ops.policy`).

**Reproduced:** a scratch test on the runner fixture (`probes/recheck-probes.diff`, `probes/recheck-probes-output.txt`):
1. The runner holds `pol` and `pol-b` in the same profile. Controller A delivers a cutoff of `all`, which cuts both. The report says `in_force [true]`, and B's reserve naming `pol-b` is refused `PolicyCutoff`.
2. The runner's attended owner runs `clear-cutoff --policy pol-b`. Its `lifted_effects` is `null`, which is correct because `pol` is still cut. They approve it. The report still says `[true]`, and B is still refused `PolicyCutoff`.
3. Controller B, a paired owner session, sends `policy remove pol`. The answer is `OK`, and the number of pending decisions stays 0.
4. The next report says `in_force [false]`. B's reserve naming `pol-b` is now `Ok(())`.

The same sequence with a `profile` cutoff gave the same result (the first probe: B's reserve naming no policy goes from `PolicyUnnamed` to `Ok`).

A's own resumption still needs its own owner's acknowledgement. Inference: the runner owner's own unattended `policy remove` lifts the effect the same way.

**Smallest acceptable fix**, either of these:
- **(a) Keep the row in force:** in `judged_lifted`, keep a row in force when any policy its acknowledgement names no longer exists.
  - This is three lines (`probes/rc01-candidate-fix-a.diff`).
  - With it applied, both removal probes fail as intended, and the existing 19 + 30 + 7 tests of `integration_runner_effects_m06`, `integration_controller_driver_m06` and `heimdall-store --lib ext_effects` still pass.
  - The local owner can still lift such an effect by its exact scope (`delivered_lifts`).
- **(b) The simplification** (ADR-0009 §2 "simplify before patching again"): drop the report-time implicit clearing. The flag would then clear only through `lift_remote_policy_revision`, for lifts that an approved decision names. Approvals already clear every named lift (`stop_m05.rs:1156`). The store test `the_report_says_which_delivered_effects_are_still_in_force` would change.

In both cases, add the probe as the regression test. If RC01 blocks, it also needs a revert proof.

### M06-W5-RC02 (low): a lift followed by a local re-pause before the next report now reads as lifted, contrary to ADR-0012 §7.4

**Where:** ADR-0012 `:680` says "A lift followed by a local re-pause before the next report reads as still in force". Since `cde5766b`:
- the held-policy resume names the implied lift (`stop_m05.rs:942`);
- the approval clears that lift at once (`stop_m05.rs:1156`).

**Reproduced** (third probe): approve `resume --policy` (it names A's pause), then pause the policy locally before any report. The next report says `in_force [false]`.

**Impact:** issuance stays blocked. A's reserve naming that policy after its acknowledgement is `PolicyPaused`, because the re-pause shows in the report's standing policies. So the only problem is that the text and the code differ.

**Fix:** amend the ADR sentence: the effect reads lifted, and the runner's own re-pause keeps every controller blocked for that policy. Alternatively, leave the clearing to the report.

### M06-W5-RC03 (low): a management session whose own ssh client refuses its options is not flagged as this controller's fault, so `environment add` blames the runner's runtime

**Where:**
- `crates/heimdall/src/m06_cmd.rs:2340` (`session_error`, returned at `:2705`) builds the `ssh_client_config_rejected` error with `OpError::new`, so `controller_local` stays false.
- `after_bootstrap` (`crates/app/src/remote_env.rs:609`) therefore puts `AFTER_BOOTSTRAP_NO_SESSION` (`:546`) in front: "The usual cause is that the runner's runtime is not running … start it on the runner". The session's own error follows: "this controller's OpenSSH client refused its own options or configuration…".

**The ruling it contradicts:** ADR-0006 §18.9 item 12 (`:2627`): "Every other failure of the session opener on this controller names this controller, never the runner's runtime".

**Failure scenario** (source-derived; no test covers this pair): an in-box Win32-OpenSSH client that rejects an option in the rendered `mgmt.conf`. That is hypothesis H1 of PC job 42. The user is sent to the runner.

**Fix:** pass `ClientRejected` (and `ClientNotStarted`) through `on_this_controller` in `session_error`. Their messages already start with "this controller's", so only the flag changes. Add a row for it to `every_session_opener_failure_on_this_controller_is_classed_as_its_fault`.

### M06-W5-RC04 (low, record): the six `ssh_*` reasons and the `ProgramData` refusal are not recorded in ADR-0006 §18.9

**Where:**
- `crates/contract/src/envelope.rs:803-830` adds six public reasons with their codes, and the golden file pins them. The comment at `:804` cites "ADR-0006 §18.9, the `w5v` row".
- No `w5v` row exists: a grep for `w5v` in ADR-0006 and ADR-0012 finds nothing.
- The accepted interim deviation from ADR-0010 §10 item 4 (`:503`, "Every product launch of `ssh.exe` gets `ProgramData`…", filled from the operating system) is not recorded in an ADR. Inference: it is recorded only in the commit messages.

**Fix:** add §18.9 item 13, covering:
- the six reasons and their codes;
- the placement rule;
- the `ProgramData` refusal;
- its deviation from ADR-0010 §10 until the M06 exit.

### M06-W5-RC05 (nit): `Protect-SshStderr` keeps addresses, fingerprints, unlisted names and canary-shaped tokens

**Where:** `tests/native/m06/run-windows-controller.ps1:328`. Its comment promises "never a path separator, address or quote".

**Observed:** I extracted the two functions and ran them under PowerShell 7 on macOS (`probes/rc05-*`). The output kept:
- `172?28?1?5` for an IPv4 address;
- `SHA256?AbCdEf0123456789??xyz` for a host-key fingerprint;
- a name not in `$Known`, verbatim;
- `HEIMDALL_CANARY_<fixture>`, verbatim.

Inference: in practice the input is fixture data (loopback or WSL addresses, disposable host keys).

**Fix:** replace dotted quads, `SHA256:` fingerprints and `HEIMDALL_CANARY_\w+` with placeholders before `Protect-Reason`, or state the limit. Scan `out\ssh-stderr.txt` before any of it goes into `tests/evidence/artifacts/`.

## Observations (not findings)

1. **The cross-host socket-length check models the old layout.** `run-crosshost.sh` `socket_room` assumes the agent socket is `<home>/run/mgmt/<12 hex>/a.sock`. The product now puts it under `/tmp/heimdall-mgmt-<16 hex>/`. The check is stricter than it needs to be, but harmless.
2. **Some paired requests still get their old answer.** A paired request whose only lift would be an exact-scope one (a policy-less runner, or a policy added later) answers as before (`POLICY_TARGET_EMPTY`, or `changed: false`), not `role_insufficient`. Nothing is recorded and nothing is lifted, as the existing tests pin.
3. **R05's limits:**
   - Live event pushes (`EventRelay::spawn`, `crates/runtime/src/dispatch.rs:1370`) bypass `display_relay_urls`. The payloads I read (decision, policy, `route.health`) carry no relay URL (source-derived).
   - The iroh library's own logging was not checked. Logs are outside the ruling's list.
4. **A release `service run` ignores the stderr variable rather than refusing it.** A release `service run` does not refuse `HEIMDALL_TEST_SSH_STDERR_FILE`, because `LAUNCH_ENV` is not in `requested_by`. It never reads it either: `launch_hooks(..).ok()` gives `None` at `crates/heimdall/src/m06_cmd.rs:2699` and `:2829`. That is the existing pattern for the other launch variables. The capture also follows a link at the given path; that path is the operator's own.
5. **R02 compares the whole exposure policy.** So re-adding an approved Iroh route without its relays is also `CONFIG_CONFLICT`, consistent with `transport enable`.

## What I ran (all in a detached worktree at `2305a46c`, then removed)

**`tools/validation/release-gate.sh`:** exit 0, 42 probes, 0 failed (`release-gate.log`).

**Focused tests** (`CARGO_BUILD_JOBS=4 … --locked`; `focused-tests.log`):

| Target | Result |
|---|---|
| `heimdall-store --lib ext_effects` | 7 passed |
| `heimdall-credential --lib mgmt::agent` | 13 passed |
| `heimdall-credential --test integration_remote_env_mgmt_m06` | 3 passed |
| `heimdall-ipc --lib unix` | 1 passed |
| `heimdall-wsl --lib spawn` | 4 passed |
| `heimdall-contract --lib route` | 6 passed |
| `heimdall-contract --test contracts rev6` | 6 passed |
| `heimdall-app --lib remote_env` | 32 passed |
| `heimdall-app --lib routes` | 19 passed |
| `heimdall-runtime --lib dispatch::tests` | 14 passed |
| `heimdall-runtime --test integration_runner_effects_m06` | 19 existing tests passed, plus the 3 scratch probes |
| `heimdall-runtime --test integration_controller_driver_m06` | 30 passed |
| `heimdall --test e2e_exit_m06` | 10 passed (`e2e_exit_m06.log`) |

**Fix (a), applied temporarily:** the same targets passed, and the two removal probes failed as intended. I then reverted it.

**`Protect-Reason` and `Protect-SshStderr` only,** under PowerShell 7 on macOS.

**Cleanup:**
- I deleted the worktree's `target/` (11 GB) and removed the worktree.
- None of my processes were left running.
- No `/tmp/heimdall-mgmt-*` was left behind.

## What I could not check, and why

- **Native Windows:** there is no Windows host in this re-check, and the brief rules out remote runs. Not observed:
  - the named-pipe retry and the `ERROR_ACCESS_DENIED` mapping;
  - the `windows_tests` of the agent;
  - the product's `ProgramData` refusal, which only runs under `cfg!(windows)`;
  - the Windows branch of `wsl_exe_carries_…`;
  - the ConPTY preflight test;
  - whether the WSL interop `ssh.exe` inherits the environment of `wsl.exe`;
  - `run-windows-controller.ps1` end to end.
- **The devbox and the cross-host journeys:** ruled out by the brief.
- **Linux paths:** this is a macOS host, so the `$XDG_RUNTIME_DIR` branch and the Linux socket limit (107) did not run.
- **Not run, by the brief:** `check.sh`, `linux-xcheck`, the umask-002 sets and `selftest.sh` as a whole.
- **Not run, outside the brief's crate list:** the `heimdall` bin unit tests (`m06_cmd` classification tests, `testcfg` tests). I read them only.
- **RC01 at `25229f74`:** not re-run. I compared the source only.
