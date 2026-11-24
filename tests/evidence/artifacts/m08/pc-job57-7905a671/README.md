# PC job 57: the W2 merge candidate `7905a671` on Windows (2026-11-24)

The job file was `PC-M08-W2.md` (the M08 track's; staged by the orchestrator, sha256 `06bbf88d…`).
Its input was the Linux x86_64 helper `e6ba25f7…`, the executable of the Linux x86_64 archive of
`7905a671`, cross-built on the Mac. Root `%LOCALAPPDATA%\hm-m08-w2pc` (shown as `<R>`). The
Windows account name is redacted as `<user>` (one line, `logs/step0.txt`). Two files the PC
agent wrote for its own monitoring (a CPU and free-space sampler, and a pre-run snapshot of the
account) are not kept. The zips are not kept either; their digests are below and in
`c1/SHA256SUMS` and `c2/SHA256SUMS`.

| Step | Result |
|---|---|
| 0 | The helper hash matched. pwsh 7.6.10 and Windows PowerShell 5.1.26100 |
| 1 | Two clones (`<R>\c1`, `<R>\deeper\path\c2`) at `7905a671`, clean, LF |
| 2 | `install-selftest.ps1` PASS, 85 checks, under both shells (W2.1-R01 6/6, W2.2-RC01 8/8). `install-revert-proofs.ps1` under both, full output kept and identical between the shells. W2-R04's revert failed exactly its 2 cases, W2-RC01's 6 including case C, and W2-R07's 1. Closing line `install-revert-proofs: PASS` |
| 3 | `heimdall-stategen`: 12 unit tests and 18 fault-set tests passed |
| 4 | Both clones under 5.1. check-features printed "no iroh feature requested and no iroh crate in the selected graph". **`provenance: staged the executable the build reported (sha256 5152a7a7c05f…)`** (stage-exe's first Windows release run). Then "compiled set checked: yes", `verify_artifact: PASS` twice, exit 0. **The two zips are byte-identical**, `7e47f12448af14b203a51e367a07389bb8865a18140042b5038a72861f6a7bfb`, and so are the two `heimdall.exe`, `5152a7a7…`. The `SHA256SUMS` files differ only on the external build record's line, whose `started_at` and `finished_at` differ (checked on the Mac: no other field). The record says commit `7905a671` and `iroh_transport: not built …`. Verified again on the Mac: `verify_artifact` PASS on the c1 zip against its index |
| 5 | `-Features iroh`, `heimdall-runtime/iroh` and `"iroh iroh"`: refused before any build, as expected. **`-Features default,iroh` unquoted (5c): finding M08-W2-F2.** Windows PowerShell 5.1 passes it as an array; binding it to the `[string]` parameter failed with `ParameterArgumentTransformationError` (exit 1), before the script's own refusal. Nothing was built, so it failed closed (the release directory's file count and newest time were unchanged). `-AllFeatures`: PowerShell's "parameter not found", exit 1 |
| 6 | With `CARGO_TARGET_DIR` set: refused before the build, exit 2. `%LOCALAPPDATA%\hm-w22-td` was never created. The planted stale file was put back and removed by exact path |
| 7 | 7a to 7e as expected: the reviewer's R01 case, the 3a stop, case C, the 4b-stop marker cases and the job-47 message. `heimdall.exe` was never run |

**F2 is found by job 57, fixed in W2.3 (`2215e8a0`), and its PC self-test is pending**
(`tools/packaging/build-release-features-selftest.ps1`, job file `PC-M08-W23.md`).

**Harness note.** The first step-4 attempt hung: cargo blocked writing to the PC wrapper's
PowerShell `2>&1` pipe. Steps 4 to 7 were rerun with `cmd /c … > file 2>&1` (`logs/steps.log`,
"job57b"). This is harness behaviour, not a product finding; later job files say to capture
that way.
