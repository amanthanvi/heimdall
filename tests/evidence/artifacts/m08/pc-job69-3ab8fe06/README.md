# PC job 69: the Windows zip pair at `3ab8fe06` (2026-11-26)

**How it ran:**
- **Job file:** `PC-M08-WINZIP.md`, root `hm-m08-winzip`.
- **Input:** the Linux x86-64 archive, its two external records and `SHA256SUMS`, built on the Mac
  at `3ab8fe06` from a clean tree. All four SHA-256 values were checked on the PC before use.
- **Build only:** no release `heimdall.exe` was run.
- **Shell:** Windows PowerShell 5.1.26100.

## Results

**Reproducibility.** Two clean checkouts at different paths gave **byte-identical zips**:
- `fc /b` found no differences;
- SHA-256 `9bb6bd6ede59f0f8676b5baf0f4de893e6b885a0fbbe27fed48006f8dd786ee0`;
- 23,937,889 bytes.

The SBOM (`.cdx.json`) is identical too. **The claim covers the zip and its SBOM.** The external
`.build-record.json` is excluded by design: it is time-stamped metadata and differs only in
`started_at` and `finished_at`, so `SHA256SUMS` differs only on that one line.

| Check | Result |
|---|---|
| `build-release-wsl-selftest.ps1` | 8/8 passed |
| `build-release-features-selftest.ps1` | 18/18 passed, across both PowerShell editions |
| `build-release.ps1 -CheckWSLHelperOnly` (D03) | verified the Linux x86-64 WSL helper, sha256 `530c57f7ab0a…` |
| `verify_artifact` on both zips | PASS |
| `payload-install-selftest.py --shell powershell` | **FAIL**, exit 1: `FAIL install.ps1 fresh install (installer exit 0)` |

## Open follow-ups (W4)

1. **The payload self-test fails under Windows PowerShell 5.1,** the first time this test ran on
   it. The installer itself exits 0, so one of the test's snapshot checks (stage, home or prefix)
   failed, and the test does not say which.
   - The PC agent's reading, not verified: PowerShell 5.1 writes
     `StartupProfileData-NonInteractive` under the scratch `LOCALAPPDATA`.
   - Fix: make the test name the failing check and the unexpected paths, then fix the cause.
2. **`build-release.ps1` needs the pinned `cargo-cyclonedx`** under `target\tools\bin\`. The PC
   agent installed it with the script's own suggested command (`cargo install --locked --version
   =0.5.10 --root target\tools cargo-cyclonedx`). That step belongs in the docs or the packager.
3. **The helper check prints only the digest.** It should also print the commit, the target and
   the features that D03 checks.
