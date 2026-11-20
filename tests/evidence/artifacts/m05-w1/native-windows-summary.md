# M05 wave 1: native Windows run (the merge candidate)

**What ran:** `tests/native/m03/run-windows-local.ps1 -Commit 22dfb168fe93ae0b99b957bded048e4a3357d674`
on the owner's PC, through the orchestrator's agent: Windows 11 (10.0.26300), in-box
OpenSSH_for_Windows 9.5p2, Git 2.55.0.windows.3, native MSVC build. Started
2026-11-18T08:28:14Z, finished 08:54:51Z. Bundle digest and full output: the orchestrator's
read-only copy of `bundle.json`.

**Result** (observed): harness exit 1. 94 binaries: 2702 passed, **14 failed**, 18 ignored.
0 canary and 0 leak findings. Four binaries exited nonzero.

| Binary | Failed | Cause | Owner |
|---|---|---|---|
| `e2e_exit_m03` | 4 | `NonScratchAgent` | M03 test defect, fixed on `m03/wave6` (E2/E3), not M05's |
| `e2e_cli_m03` | 2 | console wrap; `setup apply` with no pending decision | M03, fixed on `m03/wave6`, not M05's |
| `model_project_pure` | 4 | **test fixture:** the in-memory `FsView` wrote Unix-shaped paths. On Windows `Path` joined them with `\` (`"/work\\proj"`), and string assertions compared them with `/` | M05 W1, fixed in the review-fix round |
| `model_trust_policy` | 4 (P9 among them) | **test fixture:** the trust tests' working directories (`/w/repo`, `/w/dN`) are not absolute on Windows. `WorkContext::validate` refused every trust request `USAGE_ERROR` before any probe or record. So no decision was created (`decision_ref` panics), `UsageError` came instead of `InteractionRequired`, and P9 saw reason `None` where it expected the hostile manifest's `manifest_authority_key` | M05 W1, fixed in the review-fix round |

**What the eight M05 failures were not:**
- In the four trust tests, each refused request was refused before anything was read or
  written. No record was created and nothing was widened.
- The fix proves this with the property itself rather than by reasoning:
  - P9 gains a `BadCwd` step that sends such working directories, including the drive-less
    rooted `/w/dN` form on Windows. It asserts `USAGE_ERROR`, no record, and no change to the
    policies or workspace records. The I1 check runs after every step.
  - The minimal Windows input (`Hostile{dir: 54, which: 0}`, `Trust{dir: 3, tamper: 0,
    attended: false}`) is replayed as a fixed case on every platform.
  - The targeted Windows re-run at the fix commit closes it.

**Product path handling on Windows** (read, then proven by the re-run):
- `heimdall-project` compares only paths its `FsView` canonicalized: the observed root, the
  linked worktree's entry and back-link, and the record's root. On Windows the runtime's
  `FsView` returns `std::fs::canonicalize`'s verbatim forms.
- The fake `FsView` now models that:
  - canonical roots are `\\?\C:\…` and `\\?\UNC\server\share\…`;
  - callers pass drive-qualified working directories;
  - Git pointer files are written as Git for Windows writes them, `C:/…`.
- A new Windows-only case runs drive-qualified, verbatim, forward-slash and lower-case-drive
  working directories, a linked worktree and a UNC share through observation and matching.
- **Not modelled:** case-insensitive comparison. Canonicalization returns the on-disk case on
  both sides. U4's observer test on the real filesystem covers a case-variant working directory
  in W2.
