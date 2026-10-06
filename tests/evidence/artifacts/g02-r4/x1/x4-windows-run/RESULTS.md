# X4 Windows spike, native run inside X1 (pipe checks only)

Task `M00-T05-x1-g02-native`, 2026-10-06. Host: the owner's Windows 11 Pro 26300 x64 PC, non-elevated user,
Windows PowerShell 5.1.26100.9549. Spike: `../../x4/windows/` (not modified; its file hashes were the same
before and after the rebuild).

## What ran and why only part of it

- **Binaries.** The spike directory holds no built binaries, only its source, `build.sh` and `build.log`.
  I rebuilt both with the spike's own `build.sh` on the Mac, offline (`GOPROXY=off`,
  `CARGO_NET_OFFLINE=true`, cargo-zigbuild from the frozen Rust prototype's tool directory), into a scratch
  directory. Build exit 0 (`build-x4.log`). The SHA-256 of both outputs equal the ones recorded in the
  spike's RESULTS.md, so these are the spike's binaries (`hashes.txt`). I checked them again on the host
  before the run.
- **Runner.** I did not run `run-x4-windows.ps1` as is. It always:
  - creates and deletes a persisted P-256 key in the user's key store (Software KSP, under the user
    profile);
  - tries a TPM-backed key (Platform Crypto Provider);
  - uses the user's DPAPI master key.

  On the owner's personal PC, X1 was authorized for the scratch directories only. Those three actions sit
  on the keychain boundary in CLAUDE.md, so they need an explicit owner decision (escalated).
  `run-x4-pipe-subset.ps1` is a mechanical derivative of the spike runner. The DPAPI, CNG and TPM blocks
  are replaced by `blocked` checks, and the named-pipe checks and the reporting are the original text.
  Compare it with the original using `diff`.
- **Invocation.** It ran from WSL through interop:
  ```
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File run-x4-pipe-subset.ps1 -BinDir <scratch>\x4bin -OutDir <scratch>\out-ps51
  ```
  Exit code 0. The summary line was `pass=10 fail=0 blocked=18 info=0`. The raw output is in `out-ps51/`,
  together with `results.json`. The spike already redacts SID bodies.

## Results (observed)

| Check | go | rust |
|---|---|---|
| `pipe.accept_same_user` (Identification client accepted, server sees level 1, PID cross-check agrees) | pass | pass |
| `pipe.refuse_foreign_sid` (server expecting S-1-5-32-545 refuses the real user) | pass | pass |
| `pipe.refuse_anonymous_level` (Anonymous client refused, fail closed) | pass (OpenThreadToken error 1347) | pass (OpenThreadToken 1347) |
| `pipe.control_impersonation_level` (info: level 2 seen) | pass | pass |
| `pipe.first_instance_exclusive` (second server on the same name fails) | pass (go-winio: "Access is denied") | pass (CreateNamedPipeW error 5) |
| `pipe.dacl_refuses_other_user` | blocked: needs a second local non-admin account | blocked: same |
| `pipe.reject_remote_clients` | blocked: needs a second Windows machine | blocked: same |
| `dpapi.roundtrip` | blocked: owner authorization to use the DPAPI master key on the personal PC (or a disposable account or host) | blocked: same |
| `cng.probe`, `cng.create`, `cng.create.duplicate_fails`, `cng.sign.new_process`, `cng.delete` | blocked: owner authorization to create and delete a persisted key in the user's key store (or a disposable account or host) | blocked: same |
| `cng.platform_tpm` | blocked: owner authorization for a TPM-backed key on the owner's TPM (or a disposable host) | blocked: same |

The host block in `results.json` reads TPM `present: null`. `Get-Tpm` needs elevation, so nothing was
learned about the TPM.

## What this answers for X4

- Both languages' pipe servers work natively on Windows 11 as written. In particular:
  - `ImpersonateNamedPipeClient` with `OpenThreadToken` succeeds at Identification level;
  - an Anonymous-level client yields error 1347 and is refused;
  - the first-instance flag is exclusive.

  The Go spike's hand-bound `ImpersonateNamedPipeClient` call worked as written.
- Still open: whether the DPAPI and NCrypt hand bindings in Go work. In particular, the untyped
  `LazyProc.Call` argument risk from the spike RESULTS is still unverified, because those checks were not
  run.

## Not covered

DPAPI, CNG, TPM, a second account, a remote client. There was no independent review of this run.
