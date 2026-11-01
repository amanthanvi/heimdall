# Windows named-pipe endpoint: native tests (M01-U6w; server-owner check M01-U6b)

The tests live next to the code they test, in `crates/ipc/src/windows.rs`
(`#[cfg(test)] mod tests`), because the module is `cfg(windows)` and its helpers are
private. They compile only for a Windows target and run only on a Windows host.

Status of the server-owner check (wave-1 E14, ADR-0006 §2.1 rev2):
`implemented_unverified`. The three `connect_with_owner_*` tests below compile for
`x86_64-pc-windows-gnu` (`cargo clippy --target x86_64-pc-windows-gnu -p heimdall-ipc
--all-targets -- -D warnings`) and their binary cross-links, but they have not run on
a Windows host yet; cross-compilation does not close the claim (AGENTS.md).

| Test | Claim (m01-plan.md U6w; ADR-0006 §2.1) |
|---|---|
| `same_user_connect_reports_owner_sid_and_owner_only_dacl` | same-user connect succeeds twice (next instance pre-created); `PeerIdentity::Windows` carries the owner SID and this process's pid; `verify_peer` yields `PrincipalInfo::OsUserWindows { sid }`; the connection is local (`ERROR_PIPE_LOCAL`); bytes pass both ways; the instance DACL read back from the handle is exactly `D:P(A;;FA;;;<owner SID>)` |
| `non_pipe_endpoints_refused_before_any_open` | a regular file (4096 bytes, spaced non-ASCII path), a directory, `NUL`, `\\.\NUL`, a `\\.\pipe\..\<file>` escape and a missing path are classified `NotPipe` and `connect` returns `InvalidInput` with no OS error. The file and directory are held open with share mode 0 during the attempts, so any open would have failed with a sharing violation instead; bytes and mtime are unchanged afterwards |
| `existing_name_makes_bind_fail_first_instance` | a second `bind` of a live name fails (`PermissionDenied`), and so does `bind` over a name pre-created by another server without the first-instance flag, which still answers its own clients afterwards |
| `dacl_denies_unlisted_principal` | with the DACL granting only a different (synthetic) SID, this user's open is denied by the kernel. This shows the DACL is enforced; it is not the cross-user test |
| `sid_mismatch_is_disconnected_and_listener_keeps_waiting` | a client the DACL admits but whose SID is not the expected owner is disconnected and never returned by `accept`; an instance still answers afterwards |
| `classify_path_namespace_rules` | the `GetFullPathNameW` + `\\.\pipe\` / `\\?\pipe\` rule, including `..` escapes, UNC `\\localhost\pipe\`, `GLOBALROOT`, empty names and embedded NUL |
| `bind_refuses_non_pipe_names_and_non_sid_owners`, `sid_string_validation_rejects_aliases_and_injection` | `bind` refuses non-pipe names and owner strings that are SDDL aliases or ACE injections |
| `bind_outside_runtime_errors_instead_of_panicking`, `missing_pipe_is_not_found`, `current_user_sid_is_a_literal_sid` | error-path and helper checks |
| `connect_with_owner_accepts_a_same_user_server` (U6b, E14) | a same-user server is accepted with `ServerOwner::CurrentUser` and with `ServerOwner::Sid(<this user's SID>)`; the owner SID read back from the client handle (`GetSecurityInfo`, `OWNER_SECURITY_INFORMATION`) equals the current user's SID; bytes flow. Run non-elevated: an elevated server's pipes carry its token's default owner (typically `BUILTIN\Administrators`), which is what `ServerOwner::Sid` exists for |
| `connect_with_owner_refuses_an_unexpected_owner` (U6b, E14) | our own pipe, but the client expects a different (synthetic) SID: `PermissionDenied` from the owner comparison itself (no OS error code), no SID in the error text, and the listener still serves a correctly-expecting client afterwards. This exercises the comparison; it is not the cross-user test |
| `connect_with_owner_refuses_bad_input_before_any_open` (U6b, E14) | an expected owner that is not a literal SID (`""`, `WD`, `BA`, an ACE injection, lower-case `s-1-…`) and a path outside the pipe namespace are `InvalidInput` with no OS error, before any open (an absent pipe would otherwise answer `NotFound`, which the last case confirms) |

The platform-neutral IPC suites are separate Cargo test targets since the F09
harness migration and run on Windows too: `adversarial_ipc_frames` (control framing,
attendance refusal, paused-time hello deadline) and `adversarial_agent_frames`
(signing framer). `integration_ipc_unix` is `#![cfg(unix)]` and must report
`0 passed` on Windows.

## Running

On a Windows host with the Rust toolchain: `cargo test -p heimdall-ipc --lib windows::`
for the pipe tests, `cargo test -p heimdall-ipc` for every target.

From macOS (what M01-U6w used): `tests/native/windows-ipc/run-native.sh <artifact-dir>`.
It cross-builds the four `heimdall-ipc` test binaries (lib, `adversarial_ipc_frames`,
`adversarial_agent_frames`, `integration_ipc_unix`) for `x86_64-pc-windows-gnu` with
zig as the linker (two shims in a temporary directory: `zig cc -target
x86_64-windows-gnu` with cargo-zigbuild-style argument filtering, and `zig dlltool`
for the `raw-dylib` import libraries that `windows-sys` 0.61 uses), copies them to the
owner's Windows PC over ssh, runs them as the non-elevated user through WSL interop
from `%LOCALAPPDATA%\hm-m00\<run>\` with `TEMP`/`TMP` pointed there (the lib's
`windows::` tests first, then every binary in full, each exit code recorded), saves
redacted output, scans it for `HEIMDALL_CANARY_`, and removes both scratch
directories. `HM_BUILD_ONLY=1` stops after the cross-build and records the binaries'
SHA-256 (no ssh); M01-U6b ran only that mode.

Since review B01/B03 (M01-review-fix-R2): `<run>` is `<HM_TASK>-<random>`; both run
directories (`~/hm-m00/<run>` in WSL and the Windows one) are created exclusively by
one remote step (`scratch-lib.sh`: an existing directory is an error, a symlinked
`hm-m00` root is refused, `HM_TASK` `.`/`..` are rejected), and only the exact
directories that step created are removed. The harness exits nonzero when either the
`windows::` run or the full run fails; `commands.txt` records both exits.
`tools/validation/native-harness-selftest.sh` checks all of this locally with stub
`ssh`/`scp`/`cargo` and stub test binaries, reaching no host (it is a `check.sh`
step). Earlier evidence used the fixed directory `M01-U6w`.

## Not covered (blocked)

* **Cross-user rejection** with a real second Windows account: blocked on the
  disposable second account (ADR-0004 §3). The two DACL/SID tests above exercise the
  same code paths with a synthetic SID, not a second principal.
* **Server-owner check against a pipe created by another user** (E14 native proof):
  blocked on the same disposable second Windows account. Plan: as the second account
  (non-elevated; for example a scheduled task or `runas` started by the owner),
  create `\\.\pipe\hm-M01-U6b-<n>-control` with a DACL that also grants the test
  user read/write; as the test user, `connect` (no owner check) succeeds, which shows
  the pipe is reachable, and `connect_with_owner(.., ServerOwner::CurrentUser)` is
  refused with `PermissionDenied` before any byte is written; the second account's
  server sees the client close without data. Expected status after that run:
  `verified` for the E14 claim; until then `blocked` (second account) with the
  same-user and synthetic-SID cases `implemented_unverified`.
* **Remote-client rejection** over SMB: not run, because it would need a pipe that
  accepts network clients (no network listeners). `PIPE_REJECT_REMOTE_CLIENTS` is
  set on every instance, and `client_sid` independently refuses any connection for
  which `GetNamedPipeClientComputerNameW` does not answer `ERROR_PIPE_LOCAL`; only
  the local branch of that check is observed.
