# Release-set dry run at `76595543` (M08 W2-5, 2026-11-23)

A rehearsal of the release set of plan §10.2 at the `m08/w2` tip, so the candidate (U3b) finds
no surprise. **Not a release, not the candidate.** No archive is committed; this directory
holds the record and the external index the Mac builds wrote (`SHA256SUMS-mac`).

## The builds

| Target | Built by | Result | Archive sha256 | Executable sha256 | SBOM |
|---|---|---|---|---|---|
| `aarch64-apple-darwin` | `build-release.sh`, the Mac | exit 0; `verify_artifact` PASS (stage, archive, index) | `df65cdc3…` | `b184b454…` | 229 components (25 removed as unselected; compiled set checked) |
| `x86_64-unknown-linux-gnu` | `build-release.sh`, the Mac (zig) | exit 0; PASS | `23246a6d…` | `3b90dfc9…` | 275 (20 removed; checked) |
| `aarch64-unknown-linux-gnu` | `build-release.sh`, the Mac (zig) | exit 0; PASS | `96151465…` | `c5ebf788…` | 274 (20 removed; checked) |
| `x86_64-pc-windows-msvc` | `build-release.ps1`, the PC | from PC job 47 part B at `2bcf4dc0`, not built at `76595543` (ruled: no extra PC build for a dry run); exit 0, `verify_artifact` PASS. Differences from this commit: its packed `BUILD-RECORD.json` still carries the build times (the split landed in `a186a293`); its executable is linked with `/Brepro`, as here | `987e7640…` (clone 1) | `0624fbbf…` (both clones) | built on the PC (its SBOM is in job 47's artifacts) |

Each build record names commit `76595543`, a clean tree, and the flags it used (macOS adds
`-Clink-arg=-Wl,-S`). The three executables equal those of the two-checkout comparisons
(`fb96ac35` for macOS, `a186a293` for Linux), as expected: the product code did not change. The
archives differ from those runs because their records name a different commit.

## The plan §10.2 artifacts

| # | Artifact | In this dry run |
|---|---|---|
| 1 | Binaries for each declared platform | Three of four built and verified; Windows from job 47. Run rows: macOS blocked on B3, Windows on B2 and B15, Linux arm64 native on B9, Linux x86-64 on the disposable WSL distribution (owner's decision) |
| 2 | Checksums | The external index (`SHA256SUMS-mac`): every archive, SBOM and external build record. At the candidate it is committed under `tests/evidence/artifacts/m08/release/<version>/` |
| 3 | Signing and provenance | Provenance: build records, SBOMs, the inner `MANIFEST.sha256`. Signing: macOS ad-hoc and linker-signed only; Developer ID and notarization **blocked on B13**; checksum signing and Authenticode **blocked on B16** |
| 4 | Dependency inventory | One SBOM per target (above). The test-only crates in the release graph stay until U3c (H11) |
| 5 | Licence notices | `THIRD-PARTY-NOTICES.txt` in every archive. The project's own `LICENSE` is **not packaged: blocked on B17** (the script prints it as not in the tree) |
| 6 | Install, update and uninstall instructions | Drafts in `docs/operations/`; `install.sh` and `install.ps1` in the archives |
| 7 | Reference configuration and schema examples | `examples/reference-config/`, `schemas/`: in the tree, provisional until G08; packaging them into the archives is U3b |
| 8 | Compatibility matrix | `docs/compatibility/matrix.md` v2; every label `not-tested` |
| 9 | Migration and recovery runbooks | Drafts; restore and reset wait for U0 and U2b |
| 10 | Unenrollment guide | Draft |
| 11 | Agent-use guide | `skills/heimdall/`, `examples/reference-wrapper/`, `examples/harnesses/`: in the tree; packaging them into the archives is U3b |
| 12 | Security-reporting route | `SECURITY.md` **not packaged: blocked on B18** |
| 13 | Limitation statement | `docs/user/limitations.md` (draft; now also names expiry and OpenSSH connection sharing) |

The go/no-go draft (U8) names B13, B16, B17 and B18 as the blockers of rows 3, 5 and 12.
