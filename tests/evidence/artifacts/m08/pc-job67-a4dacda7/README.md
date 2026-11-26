# PC job 67: W4-T1 (the TempDir holders) on native Windows, at `a4dacda7` (2026-11-26)

- **Job file:** `PC-M08-W4T1.md`, root `hm-m08-w4t1pc`.
- **Environment:** BelowNormal priority, scratch toolchain homes, `CARGO_BUILD_JOBS=4`, not elevated.
- **Method:** around each run, every new name in the run's TEMP was listed, not only `.tmp*`.
- **Redaction:** the outputs here are redacted.

| Run | TEMP | Result | New entries |
|---|---|---|---|
| `integration_managed_adapter` | default | 52 passed | none (job 66 left 15) |
| `e2e_setup_dispatch` | default | 9 passed | none |
| `model_setup` | default | 52 passed | none of Heimdall's (see below) |
| `e2e_tui_m02 console::` | owner-only (`D:PAI`, a single owner ACE) | 2 passed | 0 before, 0 after |
| `e2e_enroll_m03` | owner-only | **not run (harness prerequisite):** `HM_FIXTURE_SSHD_*` unset, so no sshd was started | — |
| `e2e_deadline_m03 windows::` | owner-only | **not run (harness prerequisite)**, the same reason | — |

**`model_setup`'s two transient files.** During the run, two GUID-named `.tmp` files appeared,
then disappeared within minutes. They are not Heimdall's:
- they are files, not directories;
- the test source creates nothing with that naming;
- the default TEMP already holds 302 entries of that shape.

**What this run verifies:** W4-T1's fix for the managed-adapter holder, on Windows. Its `Weak<Store>`
guard also runs on every platform. The `hm-*`-home rigs (`e2e_setup_dispatch`, `e2e_tui_m02`
console) leave nothing behind either. The two not-run targets wait for the full m02 Windows
harness at the W4 candidate.

**The host:**
- Credential Manager: 173 entries before and after, none of them Heimdall's.
- DWM: 373 MB, not changed by the job.
- Another interactive application was running, and the job's process tree was idled.
- No firewall prompt appeared.
