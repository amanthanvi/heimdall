# The `unsafe` inventory (for M09-T03)

**Status:** prepared by M08 U1b on 2026-11-24 at `m08/w3` `c113e3f5`, rechecked at `3a7ed285`
(m08-plan U1b; §10's deferred sanitizer campaign: this inventory is what M09-T03's review gets
instead). Its counts, the rows of `platform.rs` and testkit's `win.rs`, and the wiring note
were corrected in the W3 review fixes (`a8641372`; review W3-R06), to the scan at `064f812b`.
**The rule:** `unsafe_code = "deny"` in the root manifest's `[workspace.lints.rust]`, and every
workspace member opts into the workspace lints (`[lints] workspace = true`). A module that needs
FFI opts in with `#[allow(unsafe_code)]` and a justification. The prose inventory with each
call's invariant stays in `docs/architecture/overview.md` §9 and in each module's own table;
this document is the list, kept honest by a check.

**The check:** `python3 tools/validation/unsafe_inventory.py --check` scans every Rust file of
`crates/`, `tests/` (not `tests/evidence/artifacts/`) and `fuzz/`, with comments and string
literals removed, for `unsafe_code` allowances and for `unsafe` code (`unsafe` before a block,
`fn`, `impl`, `extern` or `trait`, and the `#[unsafe(...)]` attribute form). It fails when the set
below differs from the scan, when `unsafe` code has no allowance covering it, or when the lint
configuration above no longer holds. `--list` prints the scan with its counts.
`tools/validation/check.sh` runs `--check` as its `unsafe-inventory` step.

## The modules

Counts are the scan's at `064f812b` (every `unsafe` block, `unsafe fn`, `unsafe impl`,
`unsafe extern` and `#[unsafe(...)]` attribute), informational: the check compares the set of
modules, not the counts. 380 constructs in 19 files: 327 in production crates, 36 in the
test-only `heimdall-testkit`, 17 in test binaries. The last two groups are for tests: since U3c
(`d45b0df9`, in this tree from `3a7ed285`) the binary reaches testkit only through its default
feature `test-config`, every release build uses `--no-default-features`, and
`tools/packaging/provenance.py`'s `release_graph_holds_no_test_only_crate` check holds the kit
out of the release graph.

| Module | Crate (kind) | Allowance | Platforms | `unsafe` | Reason, as the code states it | Tests |
|---|---|---|---|---|---|---|
| `crates/credential/src/sys.rs` | credential (production) | `#![allow]` | Unix, Windows | 43 | "memory locking of K_env and K_verify, and the process-wide mitigations applied at runtime start and in the issuer child" (overview §9 item 4; ADR-0008 D1, D2); "mitigations, not a boundary" | 2 unit tests; `integration_credential_memory`, `integration_managed_signer` |
| `crates/enroll/src/sys.rs` | enroll (production) | `#![allow]` | Linux | 1 | "a step's `ssh` child receives `SIGKILL` when the thread of the CLI that spawned it dies (`PR_SET_PDEATHSIG`)"; one `pre_exec` closure, two async-signal-safe calls (overview §9 item 7) | no unit test; `integration_enroll_verify` runs the step runner |
| `crates/ipc/src/windows.rs` | ipc (production) | `#![allow]` | Windows | 32 (37 since M07 S2-07) | "the raw security-attributes pointer passed to `create_with_security_attributes_raw`, the SDDL conversion, the impersonation/token calls, the owner query on a client handle, and the server-process query on a client handle (`GetNamedPipeServerProcessId`, `OpenProcess`, `OpenProcessToken`)" (overview §9 item 1). ⟨M07 S2-07⟩ The five new blocks: `server_process_id` (`GetNamedPipeServerProcessId`; the handle is owned by the caller's `NamedPipeClient` for the call, the PID out-pointer is a local) and `process_user_sid` (`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, a null result an error; the process handle owned by an `OwnedHandle` at once; `OpenProcessToken(TOKEN_QUERY)` with an out-pointer to a local, the token owned by an `OwnedHandle` at once; each closed exactly once; then the existing `TokenUser` read with its checked size). Every failure is a refusal, never a pass | 20 unit tests (native Windows); ⟨S2-07⟩ 4 more: the same-user positive, the injected read failures, the real reads' failing paths (`OpenProcess` of PID 0, `GetNamedPipeServerProcessId` on a file handle), the foreign-owner case (ignored: needs a second account, B2) |
| `crates/issuer/src/sys.rs` | issuer (production) | `#![allow]` | macOS, Windows | 36 | "the keychain access list and item creation on macOS, DPAPI, owner-only DACLs and the console mode on Windows" (ADR-0008 D1) | no unit test; `integration_issuer_store`, `integration_issuer_release_gate` |
| `crates/localenv/src/sys/mod.rs` | localenv (production) | `#![allow]` | Unix, Windows | 80 | "the third `unsafe` module": the account database (`getpwuid_r`, never `$HOME`), process groups and job objects, the suspended-spawn and process pin (overview §9 item 3; ADR-0007 §13) | 11 unit tests; `integration_doctor`, `integration_projection*` |
| `crates/localenv/src/sys/lxss.rs` | localenv (production) | under `sys/mod.rs` | Windows | 6 | "read-only Lxss registry read for WSL distribution discovery", `KEY_READ` only (ADR-0010 §2) | none of its own; the WSL discovery rows (native Windows) |
| `crates/localenv/src/sys/openssh_env.rs` | localenv (production) | under `sys/mod.rs` | Windows | 4 | the Win32-OpenSSH environment fill: `SHGetKnownFolderPath(FOLDERID_ProgramData \| FOLDERID_Windows)`, `CoTaskMemFree` (sys table, ⟨M04⟩ row) | 3 unit tests (one a child process on Windows) |
| `crates/localenv/src/sys/quarantine.rs` | localenv (production) | under `sys/mod.rs` | Unix, Windows | 19 | "Windows `ReplaceFileW` and handle identity, and the quarantine with the crate's only removal" (ADR-0007 §5.3, §12.15 item 9) | 8 unit tests; `integration_projection_replace` |
| `crates/localenv/src/sys/spawn.rs` | localenv (production) | under `sys/mod.rs` | Windows (its Unix half is safe std) | 14 | "a child started here inherits exactly its three standard stream handles": `CreateProcessW` with a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (ADR-0010 §1 item 6) | 6 unit tests |
| `crates/runtime/src/autostart/windows.rs` | runtime (production) | `#![allow]` | Windows | 10 | "the registry calls below, each wrapped in a safe function": the per-user Run value (ADR-0010 §1) | none of its own; `e2e_platform_m04` (`service_login_m04.rs`, native Windows, a scratch subkey) |
| `crates/runtime/src/platform.rs` | runtime (production) | `#![allow]` | all | 58 | the boot-scoped continuous clock and boot ID, process identity, standard-handle and descriptor hygiene, the time-synchronization queries, the state directory's DACL (overview §9 item 2); ⟨M08 U2b-1, H15⟩ the store-generation pointer's write-through rename on Windows, `MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH)` (`rename_replacing`; the module's own table) | 6 unit tests; `integration_runtime`, `integration_runtime_m03`; the rename under a fault: `heimdall-runtime`'s `state_store::tests::platform_fs_pointer_rename_interrupted_then_restart_serves_only_the_pointers_generation` (native Windows) |
| `crates/runtime/src/session_lock/sys.rs` | runtime (production) | `#![allow]` | macOS, Windows | 24 | "the only `unsafe` of the session-lock sources: each block is one FFI call ... wrapped in a safe function" (overview §9 item 6; ADR-0008 D9 item 3) | none of its own; `integration_session_lock` (native) |
| `crates/testkit/src/conpty.rs` | testkit (test only) | `#![allow]` | Windows | 14 | "the Windows pseudoconsole (ConPTY) behind `crate::console`" (ADR-0008 §17.26 item 8) | 2 unit tests; the console users in `e2e_cli_m02`, `e2e_cli_m03`, `e2e_exit_m03` (native Windows) |
| `crates/testkit/src/hook.rs` | testkit (test only) | `#[allow]` on `mod win` | Windows | 1 | "the one Windows system call the hook makes": `SetHandleInformation` on its own standard handles | the hook's e2e users (native Windows) |
| `crates/testkit/src/win.rs` | testkit (test only) | `#![allow]` | Windows | 21 | "Windows access-control helpers for the fixtures": owner-only DACLs, deny-read ACEs (ADR-0007 §12.47 item 8); ⟨M07 W9e⟩ "a pipe's server": `hm-pinned-ssh`'s check that a declared agent pipe is served by the test's own runtime (`GetNamedPipeServerProcessId`, `OpenProcess`, `GetProcessTimes`) | 6 unit tests (native Windows) |
| `tests/adversarial/sshconf_block_scan.rs` | test binary | `#[allow]` on `unsafe impl GlobalAlloc` | all | 9 | "`GlobalAlloc` is an `unsafe` trait. Every method forwards its arguments unchanged to `System`" (the counting allocator of M08-W2-F1's regression) | itself |
| `tests/e2e/run_m02.rs` | test binary (`e2e_run_m02`) | `#[allow]` on one static | Windows | 1 | "the attribute that places this function pointer in the CRT's initializer table" (`#[unsafe(link_section = ".CRT$XCU")]`) | itself (native Windows) |
| `tests/e2e/windows_m04.rs` | test binary (`e2e_platform_m04`) | `#[allow]` on `mod ffi` | Windows | 3 | "three read or flag-setting calls on handles this test owns" | itself (native Windows) |
| `tests/integration/projection.rs` | test binary | `#[allow]` on `mod win` | Windows | 4 | "an arbitrary DACL for the cases a Windows rule must refuse, the file ID and link count of an entry itself ..., Win32-OpenSSH's rule, and junctions" | itself (native Windows) |

## Not in the scan, and why

- **`third_party/netdev-0.47.0`**: a vendored, patched dependency (ADR-0012 §1 item 3), not a
  workspace member; the workspace lints do not apply to it. Dependencies' own `unsafe` is
  M09-T03's dependency review (`cargo geiger` was not run here).
- **`prototypes/`**: disposable G02 evidence, never imported (AGENTS.md).
- **`tests/evidence/artifacts/`**: evidence snapshots of earlier prototype runs, not compiled.
- **`fuzz/`** is scanned, and has none. It is outside the workspace and so outside its lints:
  `unsafe` there would not be denied by the compiler, only caught by this check.

## The inventory the check compares

One line per module: `<path> <kind>` (`allow-module`, `allow-item`, or `under:<module>` for a
file whose `unsafe` code is covered by its parent module's inner allowance).

<!-- unsafe-inventory:begin -->
```text
crates/credential/src/sys.rs allow-module
crates/enroll/src/sys.rs allow-module
crates/ipc/src/windows.rs allow-module
crates/issuer/src/sys.rs allow-module
crates/localenv/src/sys/lxss.rs under:crates/localenv/src/sys/mod.rs
crates/localenv/src/sys/mod.rs allow-module
crates/localenv/src/sys/openssh_env.rs under:crates/localenv/src/sys/mod.rs
crates/localenv/src/sys/quarantine.rs under:crates/localenv/src/sys/mod.rs
crates/localenv/src/sys/spawn.rs under:crates/localenv/src/sys/mod.rs
crates/runtime/src/autostart/windows.rs allow-module
crates/runtime/src/platform.rs allow-module
crates/runtime/src/session_lock/sys.rs allow-module
crates/testkit/src/conpty.rs allow-module
crates/testkit/src/hook.rs allow-item
crates/testkit/src/win.rs allow-module
tests/adversarial/sshconf_block_scan.rs allow-item
tests/e2e/run_m02.rs allow-item
tests/e2e/windows_m04.rs allow-item
tests/integration/projection.rs allow-item
```
<!-- unsafe-inventory:end -->
