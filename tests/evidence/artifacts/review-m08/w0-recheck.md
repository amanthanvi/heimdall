# Heimdall M08 W0 scoped re-check

**Verdict: NOT CLOSED — M08-W01-R01 blocks merge.** The Windows installer recursively deletes an unexpected directory at an executable staging name, without establishing that its contents belong to the installer. An ordinary install into an existing prefix can therefore erase unrelated owner data. This is a source-derived finding; Windows execution was expressly excluded from this Mac review. The other findings below do not satisfy both blocking conditions in ADR-0009 §2.1.

Reviewed commit: `b7c3ab1ad2e79e972b2b10c5ccd50dbc7256dfb4`, detached, after `git fetch origin`. Reviewed range: `git diff 064134a3 b7c3ab1a -- . ':!docs/architecture' ':!progress.md'`. Read the original `/tmp/hm-tools/m08-w0-review-out/report.md` first and the current ADR-0009 before reviewing/testing. This is the single scoped re-check, with no nested delegation, implementation, commit or push.

## Original findings

“Partly closed” means that a fix or documented limitation addresses some of the finding, but the entire reported behavior is not closed. Windows native behavior remains **blocked: native Windows unavailable in this review**; source inspection does not close that evidence.

| Finding | Status | Evidence and remaining limit |
|---|---|---|
| M08-W0-R01 | **closed** | `bash tests/native/m08/lifecycle/install-selftest.sh`: exit 0, 31 checks. The failing-hard-link/failing-copy case observes exit 1, current 2.0.0, previous 1.0.0, no staged file. Reverted only the R01 backup call site in a scratch copy: `HM_INSTALL_UNDER_TEST=<copy> bash tests/native/m08/lifecycle/install-selftest.sh` exits 1 and fails exactly R01, observing installer exit 0, current 3.0.0, previous 1.0.0. |
| M08-W0-R02 | **closed for install.sh** | Supplied self-test covers dangling `.heimdall.new`, the other staging links, current-executable link refusal, and directory refusal. My additional probes put symlinks to an outside **directory containing a file** at `.heimdall.new`, `.heimdall.swap`, and `heimdall.previous.tmp`: each install exits 0, preserves the outside file and installs an ordinary executable. Windows has a separate new finding, R01 below. |
| M08-W0-R03 | **closed** | Supplied self-test: tampered README on an unterminated final manifest line is refused, exit 1, no executable installed. The loop now reads its final unterminated line. |
| M08-W0-R04 | **partly closed** | The fake unreachable and silent executables are now refused, and the explicit `--assume-stopped` route is exercised. However, the real `service status` implementation itself uses the “none” message for an unconnectable endpoint belonging to a live advertised process. See the source trace below. My shim emitting that exact message exits 1, yet the installer proceeds and replaces it, exit 0. This proves the installer half of the remaining path; no real runtime was started. |
| M08-W0-R05 | **closed** | `CARGO_BUILD_JOBS=2 cargo test -p heimdall-support`: exit 0, 11 unit tests and 14 adversarial tests, including the original tag/variation-selector/invisible cases in include-identifiers mode. An external probe against this worktree's freshly built library screened every `Cf` character in Python's Unicode 17.0.0 database: 170 checked, zero accepted. |
| M08-W0-R06 | **partly closed** | A non-placeholder `/Users/realperson/Desktop/x` is rejected. **All three original bob cases still pass** without `--forbid`: macOS Desktop, Linux `.local/share`, Windows AppData. `bob` and `alice` are globally exempted as placeholders; these can be real accounts. Unicode names and names containing spaces also evade the ASCII-only name class. An explicit `--forbid /Users/bob` does reject that fixture. Docs now describe the exemption, but the generic rule still cannot distinguish a real account from an example. |
| M08-W0-R07 | **partly closed** | Verifier self-test: exit 0, 36 cases. My overlap reproduction is rejected; ASCII forbidden text in file content is rejected in UTF-16LE/BE at either alignment; tar owner and Unix PAX cases are rejected. CLI empty-forbid handling and the explicitly documented short-name/canary-shape limitations are addressed. New metadata probes still pass: UTF-16 ZIP comments, Windows paths in PAX values, gzip comments beyond the 4096-byte sample. See R05 below. |
| M08-W0-R08 | **partly closed** | `entry.sh`, `lane.sh`, `workload.py`, and `journey.sh --build release` each refuse on this Mac, exit 2, before any runtime starts. Targeted journey kill now obtains the advertised PID and checks uid/run-specific executable text. The leftover-process branch still signals every PID returned by `own_procs` (`pgrep -f`), rather than an identity recorded when the process was started. That is narrower than the old bare-name kill, but is still a process-pattern cleanup, contrary to the task's process rule. I did not run that signaling branch. |
| M08-W0-R09 | **partly closed** | The new backup-error, symlink, runtime-output and rollback-r2 cases pass. The deny exception fixtures pass in the redirected equivalent harness; reference-config self-test exits 0 (12 cases), and normal validation exits 0. Journey source creates profiles and `.ssh` before installation. But the rollback test covers only `r2`; stopping at **r1** and rerunning destroys the older rollback target, reproduced below. Windows self-test also lacks the newly identified failure/collision cases. |
| M08-W0-R10 | **partly closed** | Dash-prefix and `heimdall.previous` directory-refusal cases pass in the shell self-test. Windows installer/self-test now exist but have not been executed here. Rustup download is version/digest checked; the separate fuzz dependency graph is still outside the reported deny gate. Updated general operations text says the install path always holds a complete executable, while the Windows script explicitly removes it between two renames; that statement needs a Windows qualification. |

## Remaining R04 path: the “none” message does not prove no runtime exists

Source: [instance.rs:125][instance-read], [instance.rs:263][instance-endpoints], [service_cmd.rs:428][service-status], [install.sh:70][install-state].

1. `InstanceInfo::read_valid` first checks the advertised process/start time.
2. Even with a matching live process, it returns `Ok(None)` when `endpoints_connectable` is false: a missing socket, wrong socket type, or failed connect suffices on Unix.
3. `service status` maps **every** `Ok(None)` to `message: "no runtime is running"`.
4. `runtime_state` accepts that message as `none`, ignoring the expected nonzero status exit code, and proceeds.

The fix closes the path where a socket is connectable but the hello fails and yields another message. It does not close the earlier endpoint-liveness path, nor missing/malformed/oversized advertisements while a process remains alive. These conclusions follow from the pinned source; only the installer/message portion was executed with a fake binary. The original R04 severity remains **low** under ADR-0009: no demonstrated lasting trust/data/consent effect, and the older runtime/store compatibility checks remain outside this re-check.

## New findings

### M08-W01-R01 — blocking: Windows staging cleanup recursively erases an unexpected directory

Source: [install.ps1:107][ps-cleanup]; the rollback has analogous unconditional recursive cleanup at [install.ps1:70][ps-rollback].

`Test-Path` accepts a directory at `$Prefix/.heimdall.new.exe`. The next command is `Remove-Item -Recurse -Force -LiteralPath $p`. There is no leaf/directory/reparse check or evidence that the tree was created by an earlier installer. Therefore a directory with unrelated files at that name is erased before the runtime guard or the same-version early return. The shell counterpart explicitly refuses a directory at that executable staging name.

**Disposable native Windows reproduction to run (not executed here):** prepare a valid fake archive as the Windows self-test does; choose a new scratch prefix; create a directory `PREFIX/.heimdall.new.exe` and put `keep.txt` inside it; run that archive's `install.ps1 -Prefix PREFIX`. The code at line 107 recursively deletes the directory and its file, then stages the executable. No current executable or real Heimdall runtime is needed. The assertion should be refusal with `keep.txt` unchanged. A corresponding directory at `.heimdall.swap.exe` reaches line 70 during rollback.

This trigger is the owner's ordinary action of installing into a pre-existing prefix, and the effect is irreversible loss of a file unrelated to the archive. It needs no hostile same-user program, and meets both ADR-0009 blocking conditions. **Source-derived, not a claim of a native run.** Refuse unexpected object types before writes and establish ownership before recursive cleanup. Windows junction/reparse traversal is an additional unverified risk; I do not rely on it to establish this finding.

### M08-W01-R02 — moderate: a partially completed Windows replacement can leave a mixed or missing pair, then report success on rerun

Source: [install.ps1:145][ps-replace], [install.ps1:148][ps-undo], [install.ps1:107][ps-cleanup], [install.ps1:111][ps-already].

**Source-derived reproduction, not executed:** start with a complete v1 executable/helper pair and stage v2. Allow the executable rename at line 145, then inject an I/O/sharing failure into the helper rename at line 146. The catch does not restore the executable because `$cur` already exists; it restores the v1 helper because `$curHelper` is absent. The result is v2 executable + v1 helper, despite “the previous one was put back.” Rerun: cleanup deletes the staged v2 helper, then the executable-only hash comparison returns success without repairing the pair.

A crash between those two renames similarly leaves v2 executable with no current helper; a rerun deletes the surviving staged helper and exits “already installed.” The analogous rollback catch can also retain the newly renamed executable while undoing only the helper.

This violates ADR-0014 §4.3's pair/recovery promise. The old executable/helper and archive remain recoverable, and no lasting remote trust or owner-state effect is demonstrated, so it is **moderate, not blocking** under ADR-0009. Verify/recover the complete pair before the early return and undo both halves after a partial replace.

### M08-W01-R03 — low: Windows retains the original fail-open runtime guard

Source: [install.ps1:55][ps-running].

**Source-derived reproduction, not executed:** install a fake executable whose `service status` produces no output or an error without `"running":true`, then update from another fake archive. `Running` returns false; an invocation exception explicitly returns false too. The update proceeds instead of refusing an unknown state. The Windows self-test only injects a known Boolean answer, so it cannot catch this. Apply the same three-state policy as the shell installer, while accounting for the R04 source issue above.

### M08-W01-R04 — low: the shell rollback recovery assumes the executable rename already happened

Source: [install.sh:115][install-recovery], [install.sh:137][install-rollback]. **Reproduced.**

Install v1, then v2. Run rollback with `HM_INSTALL_TEST_STOP_AFTER=r1`. At this point current=v2, previous=v1, swap=v2, staged-new=v1. Rerun the v2 installer normally. The unconditional “finish rollback” block moves swap over previous, then removes staged-new. The same-version check exits 0 with current=v2 and previous=v2; **v1 is gone**. An ordinary crash at this point has the same file state as the test stop.

Observed output from `probe_installer.py`: `interrupted_exit=1`, before `(cur,prev,swap)=('2','1','2')`, rerun exit 0, after `(cur,prev)=('2','2')`. The r2 counterpart yields the intended `(1,2)`. This is a regression in recovery before the rename, missed by the new r2-only test. Archives can recreate either executable; no state/recovery record is changed, so this remains **low**, like original R09.

### M08-W01-R05 — low: metadata collection still leaves scan holes

Source: [verify_artifact.py:133][verify-gzip], [verify_artifact.py:137][verify-pax], [verify_artifact.py:437][verify-metadata]. **Reproduced with otherwise valid archives and manifests.**

- A ZIP archive comment containing `builder-name` in UTF-16LE or UTF-16BE passes `verify(..., forbid=['builder-name'])`. The UTF-8 control is rejected. Metadata scanning explicitly passes `wide=False`.
- A PAX value `C:\Users\realperson\x` passes the generic home-path rule. PAX values are scanned through `repr(sorted(...))`, which doubles the backslashes rather than scanning the original value. The Unix-path PAX control is rejected.
- A valid gzip FCOMMENT containing 5000 filler bytes followed by `builder-name` passes with that forbidden text. A short-comment control is rejected. Only the first 4096 archive bytes are collected, even though gzip comments have no such small bound.

The packer normally zeroes/omits this metadata; these are static verification gaps for malformed/foreign archives or a future packer regression, not a demonstrated owner-data/trust effect. Hence **low**. Scan decoded field values, the complete bounded/rejected header, and both wide-string views for metadata too.

## Commands, results and artifacts

All executions were on this macOS host. No real Heimdall binary was started, no SSH connection or agent/keychain/credential-store access was used, and no container was started. Installer tests execute fake shell scripts only.

| Command | Observed result |
|---|---|
| `git fetch origin && git checkout --detach b7c3ab1ad2e79e972b2b10c5ccd50dbc7256dfb4` | exit 0; exact head verified again at completion |
| `python3 -I tools/packaging/verify_artifact.py --self-test` | exit 0; 36 cases, 0 failed |
| `TMPDIR=<report>/scratch bash tests/native/m08/lifecycle/install-selftest.sh` | exit 0; 31 checks |
| `python3 -I <report>/probe_installer.py` | exit 0; executes the R01 revert proof, rollback r1/r2, directory-symlink and message-state probes; results in `installer-probes.txt` |
| `bash tools/packaging/deny-selftest.sh` | **exit 2**, this worktree lacks `target/tools/bin/cargo-deny` |
| Redirected copy of `deny-selftest.sh` | exit 0; all six checks pass (real workspace, iroh feature, permissive fixture, copyleft rejection exit 4, webpki exception, non-webpki rejection exit 4) |
| `python3 -I examples/reference-config/check.py --self-test` | exit 0; 12 cases, 0 failed |
| `python3 -I examples/reference-config/check.py` (README command) | exit 0; PASS |
| `CARGO_BUILD_JOBS=2 cargo test -p heimdall-support` | exit 0; 11 unit + 14 adversarial tests pass; doc-tests: zero tests |
| `python3 -I <report>/probe_support.py` | exit 0; 170 Unicode 17.0.0 Cf characters screened, none accepted |
| `python3 -I <report>/probe_verifier.py` | exit 0; acceptance/rejection observations in `verifier-probes.txt` |
| `bash entry.sh`, `bash lane.sh`, `python3 -I workload.py`, `bash journey.sh --build release` (full repository paths) | exit 2 each, container refusal before launch |
| `bash -n` on changed POSIX installer/lifecycle/journey/soak/fuzz scripts | exit 0 |

The redirected deny harness preserves the test commands, policy, workspace and fixture bytes. Only three path assignments change: the reviewed repository root; the existing producer-worktree `cargo-deny` path (its version check enforces **0.22.0**); and a scratch copy of the fixture tree, so Cargo.lock files are never written into the read-only repository. This equivalent run is not represented as a pass of the original unmodified script, whose exit was 2. No workspace-wide cargo command was run; the focused support-crate test does not require the heavy gate.

Retained report artifacts: `report.md`, `installer-probes.txt`, `verifier-probes.txt`, and the three small `probe_*.py` sources. Probe sources contain synthetic fixture values only and regenerate disposable fixtures under the report's `scratch` directory. The report's probe commands returning 0 mean the probe program completed, not that every artifact was safe: the explicit ACCEPTED rows above identify verifier misses.

## What I did not check

- **Native Windows:** `install.ps1`, its self-test, reparse/junction behavior, actual mapped-image replacement, sharing violations and WSL pairing were read only. All Windows findings above are source inferences with disposable reproduction procedures, not native observations.
- **Real lifecycle:** no real release or debug Heimdall binary, release archive build, full debug/release journey, soak, remote host/devbox, signing/key store, process signal, or workload was run. The producer's journey counts and incident report were read as reported evidence only.
- **Fuzzing:** read the new `registry_script` target and runner changes; did not run/build the campaign, confirm downloaded rustup digests against a live upstream, or close fuzz dependency auditing. The new target exercises parsers; it does not itself demonstrate script-rendering invariants.
- Did not run `tools/validation/check.sh`, per instruction. The producer's green result is not independently verified here. No new full-wave review or out-of-scope implementation audit was performed.
- Native Windows/devbox merge-candidate obligations in ADR-0009 remain the integrator's responsibility; this Mac re-check cannot replace them.

## Changes and cleanup

Repository files changed: **none**. The authorized detached checkout was performed; final tracked/untracked Git status is clean. Build output was created only for the focused support-crate test and external pure-library probe. This worktree's `target/` and all owned scratch fixtures/copies were removed before completion. No prototype build-output directory matched the required hygiene inspection. The report directory and its small evidence/probe sources are the only retained task outputs; `DONE` marks completion.

[instance-read]: crates/runtime/src/instance.rs:125
[instance-endpoints]: crates/runtime/src/instance.rs:263
[service-status]: crates/heimdall/src/service_cmd.rs:428
[install-state]: tools/packaging/install.sh:70
[install-recovery]: tools/packaging/install.sh:115
[install-rollback]: tools/packaging/install.sh:137
[ps-cleanup]: tools/packaging/install.ps1:107
[ps-rollback]: tools/packaging/install.ps1:70
[ps-running]: tools/packaging/install.ps1:55
[ps-replace]: tools/packaging/install.ps1:145
[ps-undo]: tools/packaging/install.ps1:148
[ps-already]: tools/packaging/install.ps1:111
[verify-gzip]: tools/packaging/verify_artifact.py:133
[verify-pax]: tools/packaging/verify_artifact.py:137
[verify-metadata]: tools/packaging/verify_artifact.py:437
