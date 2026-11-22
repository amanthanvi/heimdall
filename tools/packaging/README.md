# Release packaging (M08 U3a, U4a)

Builds and checks Heimdall release archives **locally**. Nothing here uploads, publishes or
signs anything. See `docs/architecture/m08-plan.md` §4–§5 and ADR-0014 §4.

**Status (2026-11-22, branch `m08/w0`): provisional, to be integrated.** The archive's
contents, the feature set and every inventory count change when M06, M07 and the rest of
M08 land. Archives built now are rehearsals, not release evidence.

## Files

| File | What it does |
|---|---|
| `build-release.sh <target>` | Builds one archive on the Mac: `aarch64-apple-darwin`, or `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` through zig with a glibc 2.31 floor. Remaps build-host paths, stages the archive, writes the inventory, notices, build record and inner manifest, packs, verifies, and rewrites the external index |
| `build-release.ps1 -LinuxHelper <file>` | The same for `x86_64-pc-windows-msvc`, on the PC, with a static C runtime and the Linux helper in place. **Not yet run** |
| `verify_artifact.py <archive>` | The static check: allowed dynamic libraries only, no build-host path, no key block or canary value, the inner manifest complete and correct, the build record consistent, and (with `--index`) the archive's digest in the external index. Executes nothing |
| `provenance.py` | `sbom` (runs the pinned cargo-cyclonedx and validates its output against cargo's selected graph and the build's compiled packages), `notices`, `build-record`, `manifest`, `pack`, `index` |

Both Python scripts use the standard library only and have a self-test:

```
python3 -I tools/packaging/verify_artifact.py --self-test
python3 -I tools/packaging/provenance.py self-test
```

## One-time setup

```
cargo install --locked --version =0.5.10 --root target/tools cargo-cyclonedx
cargo install --locked --version =0.22.0 --root target/tools cargo-deny
rustup target add --toolchain 1.99.1 x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
```

- **The rust targets are a build prerequisite** on the pinned toolchain only (`rust-toolchain.toml`).
  Each is reversible with `rustup target remove --toolchain 1.99.1 <triple>`.
- The tools live under `./target/tools`, the one build directory. `cargo clean` removes them.
- **The licence, source and ban policy** is `deny.toml` at the repository root:
  `target/tools/bin/cargo-deny --locked --offline check licenses sources bans`. Advisories
  are M06's audit gate, not this.

## Rehearsal on the merged tree (`3b158d94`: `main` at `6a087fbb` with M06 W3–W4 and M07 W0–W3)

Rebuilt 2026-11-22 with `--allow-dirty`, default features (the `iroh` feature off). All
three passed verification, with the build's compiled packages equal to cargo's selected graph:

| Target | Components in the inventory | Removed as unselected |
|---|---|---|
| `aarch64-apple-darwin` | 229 | 25 |
| `x86_64-unknown-linux-gnu` | 275 | 20 |
| `aarch64-unknown-linux-gnu` | 274 | 20 |

`deny-selftest.sh` passes on the merged tree, **with the `iroh` feature on as well.** With
`iroh`, cargo's selected graph for the binary grows from 209 to 367 third-party crates on
macOS arm64, 255 to 387 on Linux x86-64 and 206 to 366 on Windows. One licence was new:
`webpki-roots` (the Mozilla root-certificate list) under CDLA-Permissive-2.0, recorded in
`deny.toml` as an exception for that crate only. Sources and bans passed unchanged,
including the vendored `third_party/netdev`. **Not done with `iroh` on:** an archive build,
its inventory and its notices.

## What each target's archive has had (rehearsals on `bd6e0f40`, 2026-11-22)

| Target | Built | Static check | Run |
|---|---|---|---|
| `aarch64-apple-darwin` | yes | passed | not run (a release binary needs a disposable account: B3) |
| `x86_64-unknown-linux-gnu` | yes | passed | `--version` and `service status` in `debian:13-slim` and `ubuntu:24.04`, no toolchain, no network, **under amd64 emulation**: a smoke check, not evidence |
| `aarch64-unknown-linux-gnu` | yes | passed | the same two containers, natively on the Mac's Docker: supplementary. **Its native rows stay blocked on B9** |
| `x86_64-pc-windows-msvc` | no | — | `build-release.ps1` has not been run |

**Linux arm64 note:** zig's linker does not accept rustc's `--fix-cortex-a53-843419`, so the
shim drops it (as cargo-zigbuild does). The archive is therefore linked without that
erratum workaround for early Cortex-A53 cores. This is recorded for the candidate's
limitations and is a reason to revisit the arm64 linker before any arm64 support claim.

## Output

Everything goes under `target/release-artifacts/`:

- `heimdall-<version>-<target>.tar.gz` (or `.zip`): the archive. Inside it, `MANIFEST.sha256`
  lists every file **except itself**; `BUILD-RECORD.json` holds the build inputs and the
  digests of the executables only.
- `heimdall-<version>-<target>.cdx.json` and `.build-record.json`: copies of the inventory and
  the build record, readable without the archive.
- `SHA256SUMS`: **the external index** over the archives and those records. It is never
  packed. For a candidate, it and the records are committed under
  `tests/evidence/artifacts/m08/release/<version>/`; the archives are not uploaded.

## Rules

- **A release binary is run only in a container, a disposable account or a VM** (AGENTS.md).
  These scripts never run what they build.
- **A dirty tree is refused** unless `--allow-dirty`, which records `tree_clean: false`.
- **The inventory is cargo's selected graph** for the package, target and features. The pinned
  tool resolves features for the whole workspace and over-reports; the adapter removes and
  counts what the selected graph lacks, and fails if anything is missing or if the build
  compiled a different set.
- **Roles:** `target` (compiled for the target; nothing is claimed about what the linker
  kept), `host` (a proc macro, a build script, or a dependency of one), `test-support`
  (reached only through `heimdall-testkit`; removed from release builds before the candidate).
- **The builder's user name is forbidden everywhere except one exact string:** the macOS
  login-entry label prefix, which embeds the repository owner's account name. The verifier
  masks exactly those bytes (`--allow-exact`) and nothing else, so the name anywhere else
  still fails. The allowance goes away if the label is renamed (owner input B17).

## Not done yet

- `LICENSE`, `SECURITY.md` (owner inputs B17, B18) and the install scripts (U2a) are packaged
  when they exist; today the build prints them as missing.
- The binary does not yet report its own commit and target (contract delta H7), so the check
  cannot compare them with the build record.
- `deny-selftest.sh` checks `deny.toml` against the real workspace, a permissive fixture and a copyleft fixture. The `[sources]` rules have no fixture: a git dependency cannot be resolved offline.
- The `check.sh` step for the two self-tests is handed to that file's owner.
