# X4 Windows secure stores, native run: DPAPI, CNG Software KSP, CNG Platform Crypto Provider (TPM)

Task `M00-T04-x4-windows-stores`, 2026-10-31 (UTC). Authorized by ADR-0004 §3: uniquely named test
keys created in the current user's Software KSP and Platform Crypto Provider, used, and deleted by
exact name in the same run; DPAPI protect/unprotect of test data only; key-name inventory before and
after must match. Record: `tests/evidence/g04-windows-secure-store-spike.json`.

This run covers the DPAPI, CNG and TPM checks that the X4 spike (`../windows/`) could not run in X1
(`../../x1/x4-windows-run/`, pipe subset only). Lock, logout, sleep and reboot are not part of it.

## Outcome (attempt 3 is the current evidence)

| Store | Rust (selected language, adapted spike) | Go (unmodified spike) |
|---|---|---|
| (a) CNG Software KSP, ECDSA P-256, persisted | create, duplicate refused, reopen and sign in a new process, verify with the exported public key (BCrypt and OpenSSL), delete: **all pass**. Export policy 0 read back; private export refused | create, duplicate refused, reopen and sign in a new process, delete: **all pass**. Exportability and public-key verification not covered by the Go source |
| (b) CNG Platform Crypto Provider (TPM 2.0), ECDSA P-256, persisted | **all pass**, the same checks as (a). Export policy 0 read back; private export refused (`NTE_BAD_TYPE`); provider Impl Type = hardware. Delete needs `dwFlags = 0`: with `NCRYPT_SILENT_FLAG` the PCP returns `NTE_BAD_FLAGS` (found in attempt 2, fixed in attempt 3) | create, duplicate refused, reopen and sign in a new process: pass. **Delete fails** with `0x80090009 NTE_BAD_FLAGS`, the same spike defect (Go source left unmodified). The runner's sweep then deleted the key by exact name with the fixed Rust binary |
| (c) DPAPI, CurrentUser | in-process round trip, wrong entropy and tampered blob rejected; **protect in process 1, unprotect in process 2: pass** | in-process round trip, wrong entropy and tampered blob rejected: pass. Cross-process not covered by the Go source |
| Inventory | per provider, the count and the SHA-256 of the sorted key-name list are equal before and after; no key with the run prefix before or after (spike enumeration and certutil): **pass** | (same inventory, one runner) |

The host was not elevated (`IsInRole(Administrator)` false), and no elevation was requested. No process
blocked on a prompt: every spike process finished in at most 0.3 s, and with `NCRYPT_SILENT_FLAG` a UI
requirement would fail rather than wait. The console screen itself was not observed. The runner made no
service, firewall or registry write of its own (it reads `HKLM\…\CurrentVersion` for the build number)
and no network connection. The key files are written by the KSPs themselves in the user profile.

## Host and reach

- The owner's Windows 11 Pro, `DisplayVersion` 26H2, build 26300.9711, AMD64; Windows PowerShell
  5.1.26100.9711. TPM, read without elevation through the PCP provider property
  `PCP_PLATFORM_TYPE`: `TPM-Version:2.0 -Level:0-Revision:1.59-VendorID:'AMD '-Firmware:393248.6`
  (AMD firmware TPM).
- Reach: `ssh -F <hosts-dir>/<winhost>/ssh_config <winhost>`, which lands in WSL2 as the non-root user.
  Windows through WSL interop, with full paths to `cmd.exe`, `powershell.exe` and `certutil.exe`.
  Scratch: `~/hm-m00/M00-T04-x4-stores/` (WSL) and `%LOCALAPPDATA%\hm-m00\M00-T04-x4-stores\`
  (Windows). Both are removed; see Cleanup.
- Nothing touched `~/.ssh` on either side, the ssh-agent service or pipe, 1Password, or the Git/SSH
  global config.

## Build provenance (Mac, darwin/arm64; scratch `~/.local/share/heimdall-m00/r4-scratch/M00-T04-x4-stores/`)

Toolchain: rustc 1.99.1 and cargo 1.99.1. The `x86_64-pc-windows-gnu` target was already installed
(rustup not used). zig 0.17.0 (Homebrew, present). go 1.27.3.

| # | Command (all in scratch) | Exit | Note |
|---|---|---|---|
| B1 | `CARGO_HOME=<scratch>/cargo-home cargo fetch --locked` | 0 | downloaded windows-sys 0.61.2 and windows-link 0.2.1 from crates.io. The shared cargo cache did not have them. Checksums come from `Cargo.lock` |
| B2 | plain `cargo build --release --locked --target x86_64-pc-windows-gnu` | 101 | `error calling dlltool 'x86_64-w64-mingw32-dlltool'` (as in the original spike RESULTS). Seen in the session; no log kept |
| B3 | `cargo install --locked cargo-zigbuild --version 0.23.4 --root <scratch>/tools` (CARGO_TARGET_DIR=<scratch>/tools-build) | 0 | the prototype's `target/tools` copy no longer exists. Version as in `prototypes/rust/build.sh`. `logs/install-cargo-zigbuild.log` |
| B4 | `cargo-zigbuild zigbuild --release --locked` on the **unmodified** spike source | 0 | toolchain check only, not run on Windows: 361,472 B, sha256 `7227893b…1c69`. This differs from the spike RESULTS hash, which used a different rustc and zig |
| B5 | `cargo clippy --locked --target x86_64-pc-windows-gnu -- -D warnings` (adapted source) | 0 | |
| B6 | `build-stores.sh` first version (`GOPROXY=off`) | 1 | Go: `module lookup disabled by GOPROXY=off`. The shared module cache holds extracted sources but no download zips. Rust part 0. Log overwritten by B7; seen in the session |
| B7 | `scripts/build-stores.sh` as saved (scratch `GOMODCACHE`, default proxy, `-mod=readonly`) | 0 | `logs/build-attempt2.log`: go vet 0, go build 0, clippy 0, zigbuild 0. Binaries for attempts 1 and 2 |
| B8 | `scripts/build-stores.sh` after the attempt-3 source change | 0 | `logs/build-attempt3.log`. Binaries for attempt 3 |
| B9 | rebuild of the reconstructed attempt-2 source, then of the attempt-3 source, at the same path | 0, 0 | `logs/rebuild-attempt2-reconstruction.log`, `logs/rebuild-attempt3-check.log`: hashes `28cee3f5…` and `52ebcf30…`, the same as the binaries that ran |

| Binary | Used in | Size | SHA-256 |
|---|---|---|---|
| `x4-rust.exe` (adapted, attempt-2 source) | attempts 1 and 2 | 389,120 | `28cee3f5a478e47b322c3e40bfd6f253028d4288f98feb7d74365c67bb10184e` |
| `x4-rust.exe` (adapted, attempt-3 source = `rust/src/`) | attempt-2 cleanup, attempt 3, final inventory | 390,144 | `52ebcf30abfc502eaf81911db6a54f160395a93d7e3f70ccbd7d08e19491f80d` |
| `x4-go.exe` (unmodified `../windows/go/`, `diff -r` identical) | attempts 1–3 | 3,283,968 | `8da7cc73cf009b99f21f6436c0f1ef348544123594aeb10e0426a43b9500a3ce` |

Each binary has 0 `/Users/` hits. The same hashes were checked again on WSL (`sha256sum -c`) and by the
runner on Windows (`results.json` → `binaries`). The flags match the spike's `build.sh`: Go
`CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags='-s -w'`; Rust `--remap-path-prefix`,
`-C link-arg=-Wl,/Brepro`, profile `opt-level=z, lto, codegen-units=1, strip, panic=abort`.

### Spike adaptation (Rust only; `rust/x4-windows-to-attempt2.patch`, `rust/attempt2-to-attempt3.patch`)

`Cargo.toml`, `Cargo.lock` and `pipe.rs` are unchanged. The existing ops keep their fields. Added:

- `dpapi --op protect --out F --iterations N` and `dpapi --op unprotect --in F --iterations N`:
  two processes, timed. The plaintext is the spike's fixed non-secret marker and is never printed.
- `cng --op inventory --provider P --prefix X`: `NCryptEnumKeys` over the current user's keys. It prints
  the count, the SHA-256 of the sorted names, and the names with the run prefix only. Other keys' names
  are never printed.
- `create`:
  - times `NCryptCreatePersistedKey` and `NCryptFinalizeKey`;
  - records the status of `NCryptSetProperty(Export Policy = 0)` and reads the property back;
  - tries to export the private key as `ECCPRIVATEBLOB` and as `PKCS8_PRIVATEKEY`. Any bytes would be
    wiped and never printed; none were returned;
  - writes the `ECCPUBLICBLOB` to a file and prints it in hex.
- `sign --iterations N --msg M --sig-out F`:
  - opens the key in the new process, timed;
  - reads the export policy again;
  - signs SHA-256(M) (`BCryptHash`) N times, timing each `NCryptSignHash`;
  - verifies the last signature with the key handle and writes it out.
- `verify-pub`: opens no provider. It imports the exported `ECCPUBLICBLOB` with `BCryptImportKeyPair`
  (`BCRYPT_ECDSA_P256_ALG_HANDLE`) and verifies the signature. A tampered signature and a different
  digest must both fail.
- `probe` reads `PCP_PLATFORM_TYPE`. Attempt 3 also reads Impl Type from the provider handles: on key
  handles both providers return `0x80090029 NTE_NOT_SUPPORTED`.
- Attempt 3 fix to `delete`: try `NCryptDeleteKey(k, NCRYPT_SILENT_FLAG)`; on `NTE_BAD_FLAGS`, retry
  with `dwFlags = 0`. Both statuses are recorded.

The attempt-2 source is not a saved copy: I edited it in place. I reconstructed it by reverting the two
attempt-3 edits. Its rebuild gives the exact attempt-2 binary hash (B9), so the patch chain is the
source that actually ran.

### Runner (`scripts/run-x4-stores.ps1`; diff to the original: `scripts/run-x4-windows-to-stores.diff`)

This is a mechanical derivative of `../windows/run-x4-windows.ps1`:

- The pipe block is removed. The DPAPI and CNG blocks and the helpers are kept.
- Spikes run with `-WorkingDirectory` set to a work dir, so file arguments are bare names.
- Each check has a per-process wall time.
- The TPM runs as separate create, sign and delete processes for both languages. The original used
  `--op all` in one process.
- Added: Rust-only extra checks, an inventory before, after each create and delete, and after, and a
  final sweep that deletes leftover run-prefix keys by exact name.
- certutil cross-check: `certutil -user -silent -csp <provider> -key`. Only the count of lines with the
  run prefix is kept; the raw output stays in memory.
- Key names: `heimdall-m00-t04-x4-<8 hex run id>-<lang>-<sw|tpm>`.

Attempt 1 used `scripts/run-x4-stores.attempt1.ps1`; the fix is in `scripts/run-x4-stores.attempt1-to-2.diff`.
Driver on WSL: `scripts/wsl-driver.sh stage|run|collect|cleanup`. The `run` step is
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <winscratch>\run-x4-stores.ps1 -BinDir <winscratch>\bin -OutDir <winscratch>\out -Iterations 20`.
Runner SHA-256: attempt 1 `a040dbf6…7476`; attempts 2 and 3 `8ecc9dfb262837c40992f285f320a7d61fde3c228a95828c5dd587eb3aa41c44`.

## Run log (Windows side, UTC)

| When | Step | Exit | Result |
|---|---|---|---|
| before 22:57 | copy to WSL (scp) + `sha256sum -c`; `wsl-driver.sh stage` | 0, 0 | hashes OK |
| before 22:57 | preflight, read-only: `x4-rust.exe cng --op probe`, `inventory` software/platform (`--prefix heimdall-`), certutil for both providers | 0 each | `logs/preflight.txt`: software 60 user keys, platform 2, none starting `heimdall`. **Correction:** my first certutil preflight command echoed a hard-coded `heimdall_lines=0` without measuring it. I deleted those two lines from the log and re-ran with a measured count (0 and 0). The kept lines are the measured ones |
| 22:57:09 | attempt 1 (`attempt1/`) | runner 1 | runner defect: PowerShell names are case-insensitive, so `$started = <string>` overwrote `$script:Started`. The first `Start-X4` threw after launching one read-only inventory (`attempt1/out/inv-before-software.out.txt`: 60 keys, hash `02c84226…`, prefix count 0); the `finally` then failed on `Stop-Process -Id $null`. No key was created |
| 22:58:06 | attempt 2, run id `958f7d29` (`attempt2/`) | runner 1 | pass 27, fail 8, info 2. Every Rust and Go check passed except TPM delete in both languages: `NCryptDeleteKey` returned `0x80090009 NTE_BAD_FLAGS`. The resulting failures: the two absent-after-delete checks, Go's TPM visible-in-inventory (Rust's leftover key was also listed), both sweeps (same binary and flag) and `inventory.unchanged` (platform 2 → 4 names) |
| 22:59:35 | attempt-2 cleanup with the fixed Rust binary (`logs/cleanup-attempt2.txt`) | 0 each | both leftover TPM keys deleted by exact name: silent flag `0x80090009`, `dwFlags = 0` `0x00000000`, reopen `NTE_BAD_KEYSET`. Platform back to 2 names, hash `4305099e…`; software 60, hash `02c84226…`; certutil 0 run-prefix lines for both |
| 22:59:53 | **attempt 3**, run id `3d2d51ca` (`attempt3/`) | runner 1 | pass 32, fail 2 (Go TPM delete, Go TPM absent-after-delete), info 2. The sweep deleted `…-3d2d51ca-go-tpm` by exact name (exit 0). `inventory.unchanged`: pass |
| 23:04:49 | final read-only inventory, then remote cleanup (`logs/final-inventory-and-remote-cleanup.txt`) | 0 each | software 60 / `02c84226…`, platform 2 / `4305099e…`, 0 `heimdall` names, certutil 0 and 0. Both remote scratch dirs removed |

Every spike invocation, with its argv, exit code and wall time, is in `attempt*/out/results.json` →
`commands`. Raw stdout and stderr for each process are in `attempt*/out/<tag>.out.txt` and `.err.txt`.
Every stderr file is empty. The work files (DPAPI ciphertext, `.bin` copies of the public keys and
signatures) were not copied: the ciphertext is bound to the user's DPAPI master key, and the public
keys and signatures are in the JSON as hex.

## Per-check results, attempt 3 (`attempt3/out/results.json`)

| Check | Rust | Go |
|---|---|---|
| `dpapi.roundtrip` (in-process; wrong entropy and tamper rejected) | pass | pass |
| `dpapi.protect.process1` → `dpapi.unprotect.new_process` | pass, pass | not covered |
| `cng.probe` (info) | both providers open; Software KSP provider Impl Type 34 = 0x22 (SOFTWARE \| VIRTUAL_ISOLATION flags); PCP provider Impl Type 1 (HARDWARE) | both open |
| `cng.sw.create` | pass | pass |
| `cng.sw.non_exportable` | pass: set status 0, export policy 0, `ECCPRIVATEBLOB` and `PKCS8` refused `0x80090029 NTE_NOT_SUPPORTED` | not covered |
| `cng.sw.visible_in_inventory` (spike + certutil) | pass (exactly this key; certutil 1 line) | pass |
| `cng.sw.create.duplicate_fails` | pass (`0x8009000F NTE_EXISTS`) | pass |
| `cng.sw.sign.new_process` | pass: reopened, export policy 0 again, 64-byte signature, handle verify ok, tampered signature rejected, 20 timed signatures | pass (64 bytes, verify ok, tamper rejected) |
| `cng.sw.verify_exported_pub` (BCrypt, public key only, new process) | pass (tampered and wrong-digest rejected) | not covered |
| `cng.sw.delete` (reopen → `NTE_BAD_KEYSET`) | pass (the silent flag was accepted) | pass |
| `cng.sw.absent_after_delete` | pass | pass |
| `cng.tpm.create` | pass | pass |
| `cng.tpm.non_exportable` | pass: set status 0, export policy 0, `ECCPRIVATEBLOB` and `PKCS8` refused `0x8009000A NTE_BAD_TYPE` | not covered |
| `cng.tpm.visible_in_inventory` | pass | pass |
| `cng.tpm.create.duplicate_fails` | pass (`NTE_EXISTS`) | pass |
| `cng.tpm.sign.new_process` | pass (as for sw) | pass |
| `cng.tpm.verify_exported_pub` | pass | not covered |
| `cng.tpm.delete` | pass: silent `0x80090009`, then `dwFlags = 0` success, reopen `NTE_BAD_KEYSET` | **fail**: `0x80090009 NTE_BAD_FLAGS` |
| `cng.tpm.absent_after_delete` | pass | **fail** (1 run-prefix key), until the sweep |
| `runner/sweep.platform` | deleted `…-go-tpm` with the Rust binary, exit 0 | |
| `runner/inventory.unchanged` | pass | |

### Independent verification on the Mac (`scripts/verify_openssl.py`, `logs/verify-openssl-attempt{3,2}.json`)

The script builds an SPKI PEM from each exported `ECCPUBLICBLOB` (`ECS1`, 32-byte X and Y) and a DER
signature from the raw `r||s`. It then runs
`openssl dgst -sha256 -verify pub.pem -signature sig.der msg.bin` (OpenSSL 4.1.0) on the signed message
and checks that SHA-256(message) equals the digest the spike signed. Results, for both the software and
the TPM key in attempts 3 and 2: `Verified OK` (exit 0); with the first byte flipped,
`Verification failure` (exit 1). Script exit 0 for both attempts. These are public keys of test keys
that were deleted afterwards.

## Timings (Rust, attempt 3; attempt 2 in parentheses; n = 20 per series, microseconds)

| Operation | Software KSP | Platform Crypto Provider (TPM) |
|---|---|---|
| provider open | 1,554–1,714 | 2,021–2,227 |
| create + finalize (one key) | 1,803 (1,773) | 85,367 (84,404) |
| key open in a new process | 467 (452) | 3,327 (3,206) |
| `NCryptSignHash` P-256: median, min–max | **114** (114), 111–135 | **12,485** (12,424), 11,900–12,900 |
| first signature in the process | 124 (113) | 12,599 (12,613) |
| verify with the exported public key (BCrypt, one call) | 62 (62) | 64 (63) |

DPAPI CurrentUser, Rust: `CryptProtectData` median **187** µs (188), first 824 (795);
`CryptUnprotectData` in a new process, median **147** µs (151), first 790 (780).
Process wall times are measured by the runner and include process start. Rust TPM sign process
(20 signatures) 299 ms; Go TPM sign process (1 signature + 2 verifications) 52 ms; Go Software KSP sign
process 17 ms; Go and Rust TPM create processes 107 and 104 ms. These are single-run figures on a warm
host, not a benchmark.

## Inventory (current user's keys only; no machine keys were created)

| Phase (attempt 3) | Software KSP: count / SHA-256 of names / run-prefix / certutil | Platform KSP: same |
|---|---|---|
| before | 60 / `02c84226f01ae9f6…` / 0 / 0 | 2 / `4305099e2f5f0dd9…` / 0 / 0 |
| after each create | 61 / differs / 1 / 1 (sw creates) | 3 / differs / 1 / 1 (tpm creates) |
| after each delete | 60 / `02c84226…` / 0 / 0 | Rust: 2 / `4305099e…` / 0 / 0; Go: 3 / 1 / 1 (delete failed) |
| after (before sweep) | 60 / `02c84226…` / 0 / 0 | 3 / `7d0700df…` / 1 / 1 |
| after sweep | **60 / `02c84226…` / 0 / 0** | **2 / `4305099e…` / 0 / 0** |

The full hashes are in `results.json` → `inventory`. The same before values appear in the preflight,
attempts 1 and 2, the attempt-2 cleanup and the final inventory at 23:04:49Z. The comparison covers key
names only, not the material or properties of other keys.

## What this means for ADR-0005 (Windows custody of K_env and K_ca)

Observed:

- A non-elevated user can create, persist, reopen in a new process, use, and delete an ECDSA P-256
  key in both the Software KSP and the TPM-backed Platform Crypto Provider. No UI was needed:
  `NCRYPT_SILENT_FLAG` was used on create, finalize and open, and no call failed with a silent-context
  error.
- The TPM key refuses private export for both blob types. Its export policy reads 0 and its provider is
  hardware. The Software KSP key with export policy 0 also refuses private export.
- The public key the spike exports verifies the signatures in two independent implementations.
- Signing costs about 0.11 ms with the Software KSP and about 12.5 ms with the TPM (AMD fTPM).
  TPM key creation takes about 85 ms.
- DPAPI CurrentUser protect and unprotect work across processes in about 0.15–0.19 ms.
- Product requirement: `NCryptDeleteKey` on the PCP must use `dwFlags = 0`. `NCRYPT_SILENT_FLAG` gives
  `NTE_BAD_FLAGS` there, while the Software KSP accepts it. Impl Type must be read from the provider
  handle; on key handles both providers return `NTE_NOT_SUPPORTED`.

Inferences (`[I]`, not observed here):

- The Software KSP's refusal is policy. Its key material sits in the user profile, protected by the user's
  DPAPI keys, so same-user code with profile access is the residual risk. The TPM key's material does
  not leave the TPM in clear (vendor documentation; not tested by moving the key file).
- The Software KSP provider reports the VIRTUAL_ISOLATION flag. These keys were created without
  `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG`, so nothing is claimed about VBS isolation.

Untested (`[U]`):

- whether any of this works while the desktop is locked or after sign-out or reboot (P-W1, P-W2;
  `g04-windows-desktop-lock-probe.json`, `g04-windows-signout-reboot-probe.json`);
- cross-user isolation;
- a TPM other than this AMD fTPM.

## Limitations

- One host, one user and one current run (attempt 3), plus attempt 2 for repeat timings. The TPM is an
  AMD firmware TPM, revision 1.59. Discrete TPMs and Pluton are untested.
- The private-export refusal has no positive control. No exportable key was created to show that the
  same call succeeds when export is allowed. The refusal statuses are as observed.
- Go coverage is narrower: the source is unmodified. Its TPM delete fails because of the same
  `NCRYPT_SILENT_FLAG` defect. The fix is shown only in Rust; a Go fix was not tested.
- The spike and the runner changed after results were seen: the attempt-1 runner fix, and the
  attempt-2 → 3 delete flag and provider Impl Type changes. The checks and pass criteria did not change.
  Both changes are in the diffs.
- The inventory compares the current user's key names: count and SHA-256 of the sorted list, plus the
  run-prefix names. It does not compare other keys' properties, and it does not cover machine keys.
  The certutil cross-check counts run-prefix lines only.
- Timings come from one run with 20 samples, measured with `std::time::Instant`. Process wall times
  include PowerShell `Start-Process` overhead.
- Lock, logout, sleep and reboot are out of scope. No second account and no other Windows host.
- Self-review only; no independent review of this run.

## Cleanup

- Windows: test keys. In attempt 3 each language's keys were deleted by exact name (Go's TPM key by the
  sweep). The two attempt-2 TPM leftovers were deleted by exact name at 22:59:35Z. The final inventory
  equals the before inventory (see above).
- Windows scratch `%LOCALAPPDATA%\hm-m00\M00-T04-x4-stores\`: removed (`windows_scratch_present=no`).
  The parent `hm-m00` holds another task's directory and was left alone.
- WSL scratch `~/hm-m00/M00-T04-x4-stores/`: removed (`wsl_scratch_present=no`). The other entry under
  `~/hm-m00` belongs to another task and was left alone.
- Mac scratch `~/.local/share/heimdall-m00/r4-scratch/M00-T04-x4-stores/` was removed at 23:09Z
  (`rm -rf` exit 0). It held the sources, scratch `CARGO_HOME`, `GOMODCACHE`, `GOCACHE`, cargo-zigbuild,
  the cargo `target/`, binaries and collected output: 394,260 KB (385 MB) just before deletion.
- I also removed two build caches. Both were created by this task's first zigbuild at 22:47:37Z (birth
  time), and every file in them dates from this task's builds; no zig process was running:
  `~/.cache/zig` (61,708 KB) and `~/Library/Caches/cargo-zigbuild` (16 KB). The shared cargo registry,
  Go module cache, Go build cache and rustup were not written; the scratch homes were used instead.
- Disk: `~/.local/share/heimdall-m00/r4-scratch` was 3.4 MB before the task and 3.4 MB after.
  `df -k /` available: 1,250,784,056 KB at 22:46:49Z, 1,249,780,612 KB just before deletion,
  1,250,232,060 KB at 23:09:24Z. The remaining difference to the start includes other activity on the
  host and is not attributed to this task.
- Nothing was built under `prototypes/`.

## Layout

```
README.md
scripts/   build-stores.sh  wsl-driver.sh  run-x4-stores.ps1 (attempts 2 and 3)  run-x4-stores.attempt1.ps1
           run-x4-stores.attempt1-to-2.diff  run-x4-windows-to-stores.diff  verify_openssl.py
rust/      Cargo.toml  Cargo.lock  src/{main,cng,dpapi,pipe}.rs (attempt 3)  x4-windows-to-attempt2.patch  attempt2-to-attempt3.patch
logs/      build-attempt2.log  build-attempt3.log  install-cargo-zigbuild.log  rebuild-attempt2-reconstruction.log
           rebuild-attempt3-check.log  preflight.txt  cleanup-attempt2.txt  verify-openssl-attempt{2,3}.json
           final-inventory-and-remote-cleanup.txt
attempt1/  runner-console.txt  out/inv-before-software.{out,err}.txt
attempt2/  runner-console.txt  out/*.txt  out/results.json
attempt3/  runner-console.txt  out/*.txt  out/results.json
```

Redaction: home paths become `<home>` and `<winhome>` in the build logs and in the attempt-1 console.
No other file needed it. A scan for the Windows and Mac user names, host names, the PC's address,
`S-1-5-21-` SIDs, `HEIMDALL_CANARY_` and private-key headers found nothing else. The files from Windows
keep their original encoding and line endings.
