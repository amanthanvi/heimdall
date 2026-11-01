# Windows named-pipe endpoint: native tests (M01-U6w)

The tests live next to the code they test, in `crates/ipc/src/windows.rs`
(`#[cfg(test)] mod tests`), because the module is `cfg(windows)` and its helpers are
private. They compile only for a Windows target and run only on a Windows host.

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

## Running

On a Windows host with the Rust toolchain: `cargo test -p heimdall-ipc --lib windows::`.

From macOS (what M01-U6w used): `tests/native/windows-ipc/run-native.sh <artifact-dir>`.
It cross-builds the `heimdall-ipc` lib test binary for `x86_64-pc-windows-gnu` with
zig as the linker (two shims in a temporary directory: `zig cc -target
x86_64-windows-gnu` with cargo-zigbuild-style argument filtering, and `zig dlltool`
for the `raw-dylib` import libraries that `windows-sys` 0.61 uses), copies it to the
owner's Windows PC over ssh, runs it as the non-elevated user through WSL interop
from `%LOCALAPPDATA%\hm-m00\M01-U6w\` with `TEMP`/`TMP` pointed there, saves redacted
output, scans it for `HEIMDALL_CANARY_`, and removes both scratch directories.

## Not covered (blocked)

* **Cross-user rejection** with a real second Windows account: blocked on the
  disposable second account (ADR-0004 §3). The two DACL/SID tests above exercise the
  same code paths with a synthetic SID, not a second principal.
* **Remote-client rejection** over SMB: not run, because it would need a pipe that
  accepts network clients (no network listeners). `PIPE_REJECT_REMOTE_CLIENTS` is
  set on every instance, and `client_sid` independently refuses any connection for
  which `GetNamedPipeClientComputerNameW` does not answer `ERROR_PIPE_LOCAL`; only
  the local branch of that check is observed.
