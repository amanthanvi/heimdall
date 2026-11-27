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
| `build-release.ps1 -LinuxArchive <file> -LinuxIndex <SHA256SUMS>` | Builds the Windows archive with a static C runtime. Stages its WSL helper from the verified Linux x86-64 archive and records that archive's digest, the helper's digest, commit, target and feature set |
| `verify_artifact.py <archive>` | Statically checks the release payload, allowed dynamic libraries, privacy rules, manifest and build record. With `--index` it checks the archive digest against the external index |
| `provenance.py` | Generates the SBOM, notices, build record, manifest, archive and index, and verifies the Windows helper's source |
| `rebuild-compare.sh <target> [--commit <ref>]` | Builds one commit twice in clean checkouts at different paths, compares the archives byte for byte, and writes a record under `target/rebuild-compare/` |

The Python scripts use the standard library only and require Python 3.11 or later.

```
python3 -I tools/packaging/verify_artifact.py --self-test
python3 -I tools/packaging/provenance.py self-test
python3 -I tools/packaging/rebuild_compare.py --self-test
python3 -I tools/packaging/payload-install-selftest.py --shell bash
pwsh -NoProfile -File tools/packaging/build-release-wsl-selftest.ps1
python -I tools/packaging/payload-install-selftest.py --shell pwsh
```

### PC command list

From the checkout root, run the packaging self-tests with Windows PowerShell 5.1.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\packaging\build-release-wsl-selftest.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools\packaging\build-release-features-selftest.ps1
python -I tools\packaging\payload-install-selftest.py --shell powershell
```

The Windows packager takes the Linux archive and the external `SHA256SUMS` from the release
build's trusted index. Use `-CheckWSLHelperOnly` to check the pair without compiling and print
the helper's digest, commit, target and features.
Build both from the same frozen commit with the same Cargo feature selection.

Before building the Windows zip, run the pinned SBOM tool setup from the root of each PC checkout
(both checkouts for the reproducibility run).

```powershell
cargo install --locked --version =0.5.10 --root target\tools cargo-cyclonedx
```

Both packagers exit 2 if their checkout's `target/tools/bin` lacks `cargo-cyclonedx` 0.5.10.

### Payload and candidates

`release_payload.py` stages the reference configuration from `tools/packaging/config.toml`
with its example manifest, the public schemas and payload examples, the release documents,
and the M07 wrapper, harnesses and skill. The install scripts verify these files as archive
members. Installation copies only the platform executable and, on Windows, the WSL helper.

Use `--candidate` or `-Candidate` for a finalized candidate. Replace the U7b placeholder in
`tools/packaging/compatibility-matrix.md` with the candidate's final matrix and supply
`LICENSE` and `SECURITY.md` first. These checks also run when passing `--candidate` directly
to the verifier. The D01 `strict_disconnect` and D07 client overrides are pending rulings.

The rebuild comparison uses the selected commit's `build-release.sh`, with a private
temporary checkout for each build. It compares the archive files, reports the zero-based
compressed offset and the first affected tar member and offset when applicable, and removes
both checkouts. The Windows packager already passes `/Brepro`. Repeat the PC two-checkout
comparison on the final commit using the same verified Linux archive and index for both zips.

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
| `x86_64-pc-windows-msvc` | yes, on the PC (job 40, `5348551b`, Windows PowerShell 5.1) | passed on the PC (stage, zip, external index) and again on the Mac from the returned zip | not run: a release binary on the PC needs a disposable account (B2) or a clean VM (B15). Installed as files only (install, repeat, update to a marked copy, rollback) |

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
- **What the verifier's rules match, exactly:** a home path is `/Users/<name>/`,
  `/home/<name>/` or `<drive>:\Users\<name>\`, where the name is any run of characters other
  than a separator or a control character (Unicode names and names with spaces count). No
  account name is exempt; only the three literal placeholder paths in `verify_artifact.py`
  (`HOME_PLACEHOLDER_PATHS`, written with `<name>`) are. A canary is `HEIMDALL_CANARY_`,
  optional upper-case `KIND_` parts and 8 or more lower-case hex digits, and no other shape.
  Each rule is looked for as bytes and as ASCII-range UTF-16, in every file and in each text
  field of the archive itself (member, owner and group names, PAX keys and values, ZIP
  comments and extra fields, the gzip header's name and comment at any length). An empty
  `--forbid` is a usage error. A builder user name shorter than 4 characters is not
  forbidden as a bare string, and both build scripts say so.
- **The builder's user name is forbidden everywhere except one exact string:** the macOS
  login-entry label prefix, which embeds the repository owner's account name. The verifier
  masks exactly those bytes (`--allow-exact`) and nothing else, so the name anywhere else
  still fails. The allowance goes away if the label is renamed (owner input B17).

## Not done yet

- `LICENSE` and `SECURITY.md` (owner inputs B17, B18) are packaged when they exist; today the
  build prints them as missing. `install.sh` is packaged. `install.ps1` has been rehearsed
  under PowerShell 7 on macOS only and has not been run on Windows; its self-test and revert
  proofs wait for a PC job.
- **The runtime guard in both installers** refuses on a live process started from the
  installed path whatever the executable answers, because `service status` says "no runtime
  is running" for an unreachable endpoint too. It does not see a runtime started from
  another path; that needs the product's typed reason (ADR-0014 §7, H14).
- The binary does not yet report its own commit and target (contract delta H7), so the check
  cannot compare them with the build record.
- `deny-selftest.sh` checks `deny.toml` against the real workspace, a permissive fixture and a copyleft fixture. The `[sources]` rules have no fixture: a git dependency cannot be resolved offline.
- The `check.sh` step for the two self-tests is handed to that file's owner.

## The Windows archive's first runs on the PC (2026-11-23)

| Job | Commit | Result |
|---|---|---|
| 34 | `c3abefbf` | `cargo build --release` finished (5 min); then `provenance: refused`, the compiled set lacked `cfg-if`. Windows PowerShell 5.1's `Out-File -Encoding utf8` had written cargo's messages with a byte order mark, and the old reader skipped the first line. No archive. Fixed in `7ec2d33a` (raw-byte capture; a strict, BOM-tolerant reader) |
| 36 | `7ec2d33a` | Provenance passed (226 components, 25 removed as unselected, compiled set checked); then `verify_artifact` failed: `heimdall.exe` imports `combase.dll` (`CoTaskMemFree`, linked there by windows-sys 0.61). No archive. Fixed in `5348551b` (`combase` allowed, with its reason) |
| 40 | `5348551b` | **PASS.** Build exit 0; `verify_artifact` PASS on the stage, the zip and against the external index. Zip `heimdall-0.1.0-m01-x86_64-pc-windows-msvc.zip`, 22,343,623 bytes, sha256 `4b87c78e06d044fd86be5468568780dce7fb02f17c30334573d28dd9093e6a56`; `heimdall.exe` sha256 `fc1448be…` (30,905,344 bytes); the helper `linux-x86_64/heimdall` sha256 `3b90dfc9…`, the Linux archive's executable of `c3abefbf` (no product change since). Build record: commit `5348551b`, tree clean, Rust 1.99.1. Verified again on the Mac from the returned zip and `SHA256SUMS`: PASS. `LICENSE` and `SECURITY.md` are not packaged: not in the tree (B17, B18) |
| 43 | `3c8265c5` | **PASS.** Build exit 0 in 295 s under Windows PowerShell 5.1; provenance as in job 40; `verify_artifact` PASS on the stage, the zip and the external index, and again on the Mac. Zip sha256 `6811f627f72de1ac94d8d8491735c3c4c8fcde487410f51796f7aefaa452f2a9`; `heimdall.exe` `027f22fe…` (30,905,344 bytes); helper `3b90dfc9…`. The installer runs of M08-W1-F1's fix: see the lifecycle README |

**Two builds of the same product code differ.** Jobs 40 and 43 built `heimdall.exe` from the same product source with the same toolchain (Rust 1.99.1), and the results differ in 27 bytes: the PE link timestamp (the COFF header and three debug-directory entries, 05:31:53Z and 09:55:02Z, the link times) and the PDB GUID. MSVC's linker writes both unless it is told to be deterministic (`/Brepro`). So the Windows build is **not reproducible** today, and nothing claims it is (ADR-0014 §4.8). The fix and its check are W2 items.

**Where the SBOM tool goes.** `build-release.ps1` takes `cargo-cyclonedx` only from `target\tools\bin` of the checkout (its error message gives the install command, `cargo install --locked --version =0.5.10 --root target\tools cargo-cyclonedx`). Job 43 installed it there, inside the scratch clone. That is the expected place, not a deviation.

In every job `heimdall.exe` was never executed. The toolchain and cargo homes were scratch
directories under the job's root, except one diagnostic `cargo tree` in job 36 that used the
account's own cargo home and refreshed only its sparse-index cache (reported by the PC agent).
Job 40's install steps (install, repeat, update to a marked copy, `-Rollback`, all with
`-AssumeStopped`) exited 0, and showed finding M08-W1-F1, fixed in `1ea93bf2`
(`tests/native/m08/lifecycle/README.md`).

## Two builds of one commit (W2-6, 2026-11-23)

Commit `9e0ff073`, built by `build-release.sh` from two checkouts at different paths (the
gated worktree and a second worktree, `m08-repro`, each with its own `./target`), on the Mac,
one after the other. Nothing was executed from the archives.

| Target | Executable | Archive | What differs |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | **identical** (`3b90dfc9…`, also equal to `c3abefbf`'s: the product code is unchanged) | differs | Only `BUILD-RECORD.json` (its `started_at` and `finished_at`, the build's wall-clock times) and so `MANIFEST.sha256` |
| `aarch64-unknown-linux-gnu` | **identical** (`c5ebf788…`) | differs | The same two files, for the same reason |
| `aarch64-apple-darwin` | differs: 47 bytes in two places, same size (15,903,984 bytes) | differs | The Mach-O `LC_UUID` (16 bytes at offset 1944: `2AC12813-…` and `BAAFDA7F-…`), and the one 32-byte page hash of the ad-hoc code signature that covers it (at offset 15,780,688, inside the signature at 15,780,544). Then `BUILD-RECORD.json` and `MANIFEST.sha256` as on Linux |

So no archive is reproducible today, and the word is not used. The two Linux executables are
byte-identical across checkout paths. Two causes remain:
- **the build record's two wall-clock fields,** packed into every archive;
- **on macOS, the linker's UUID,** which depends on something that differs between the two
  checkouts (to be found; the path remap already covers Rust and C sources).

**After the record fix (`a186a293`, the same day): the Linux archives are reproducible.**
Built again at `a186a293` from two checkouts at different paths (the dev worktree and a fresh
second worktree, each with its own `./target`), on the Mac, through zig:

| Target | Archive (both checkouts) | Executable |
|---|---|---|
| `x86_64-unknown-linux-gnu` | **identical**, sha256 `2ff57e87b0cf8784963efbc09fce73da4a4fb1635144233cdd5c3283f04d3906` | identical, `3b90dfc9…` |
| `aarch64-unknown-linux-gnu` | **identical**, sha256 `f07ac725db32da48db564388ec064db1608e4f93ab8503cee167f711f0f18214` | identical, `c5ebf788…` |

So the Linux x86-64 and Linux arm64 archives of `a186a293` are **reproducible** across checkout
paths on this build host, with this toolchain: two builds give byte-identical archives. Not shown:
a build on another host, or with another zig or Rust release. The external
`<name>.build-record.json` still carries each build's start and finish, as intended.

**macOS, after `fb96ac35`: reproducible too.** The cause of the differing `LC_UUID`: ld64
derives the UUID from a hash of the output it writes ("a hash of the output file's content",
`man ld`), and rustc strips the binary only afterwards (`strip = true`). Before stripping, that
output still holds the linker's debug map, whose object paths name the checkout and rustc's
temporary directory. `build-release.sh` now links the macOS target with `-Wl,-S` (no debug
information in the linker's output), and the stripped executable is the same size as before
(15,903,984 bytes). Built at `fb96ac35` from the same two checkouts:

| Target | Archive (both checkouts) | Executable | `LC_UUID` |
|---|---|---|---|
| `aarch64-apple-darwin` | **identical**, sha256 `872b0497f4772c1413d8da3633450ead4b4e00c8b86c968a5413cddeedd73918` | identical, `b184b454…` | `7E42955C-139A-3A5C-9275-06F1F351AC0D` in both; ad-hoc, linker-signed |

So the macOS arm64 archive of `fb96ac35` is **reproducible** across checkout paths on this host,
with the same limits as Linux. Neither `-no_uuid` (dyld needs the UUID) nor `-oso_prefix` (it
cannot cover rustc's random temporary directory) is used.

**Windows, PC job 47 part B, at `2bcf4dc0` (`/Brepro`, before the record split):** two clones at
different paths and depths, each built by `build-release.ps1` under Windows PowerShell 5.1.
The two `heimdall.exe` are **identical** (`0624fbbf6dd33fe33ba8d30041b49fd7a98f4cdd77f21fe363648ca2f741b9a8`,
30,905,344 bytes). The zips differ (`987e7640…`, 22,346,201 bytes, and `9fef1dbd…`, 22,346,200
bytes) only in `BUILD-RECORD.json`'s `started_at` and `finished_at` and its `MANIFEST.sha256`
line, which `a186a293` fixes. So the Windows **executable** of `2bcf4dc0` is reproducible across
checkout paths on the PC, with the same limits as the others. The Windows **archive** is shown
reproducible only by a PC pair at a commit with the record split: the candidate's PC build
(ruled; no job before it).

**The Windows archive is reproducible: PC job 57 at `7905a671` (the W2 merge candidate,
2026-11-24).**
- **The build:** two clones at different paths and depths, each built by `build-release.ps1`
  under Windows PowerShell 5.1.
- **The zips are byte-identical**, `7e47f12448af14b203a51e367a07389bb8865a18140042b5038a72861f6a7bfb`.
  So are the two `heimdall.exe`, `5152a7a7…`.
- **The indexes:** the two `SHA256SUMS` differ only on the external build record's line. That
  record differs only in `started_at` and `finished_at`.
- **Packaging:** the same job was `stage-exe`'s first Windows release run ("staged the executable
  the build reported"). Its first release run anywhere was the Linux x86_64 archive of
  `7905a671`, cross-built on the Mac: archive `0a6e1545d643b5635732ace8d346a0a76bb734e3a73e595ba8bbfc755b14d3be`,
  executable `e6ba25f7…`, record `iroh_transport: not built`.
- **Records:** `tests/evidence/artifacts/m08/pc-job57-7905a671/`.
- **Finding M08-W2-F2** (step 5c): an unquoted `-Features default,iroh` failed PowerShell's
  parameter binding before the script's own refusal. It failed closed: nothing was built. It
  was fixed in W2.3 (`2215e8a0`; `-Features` is a list). **Closed by PC job 59 at `8ba4f28c`:**
  `build-release-features-selftest: PASS (18 checks)` under Windows PowerShell 5.1 and
  PowerShell 7. The unquoted `default,iroh` now reaches the refusal (exit 2) in both.

## The release feature set has no test kit (M08 U3c, 2026-11-24)

The binary's edge to `heimdall-testkit` (the debug-build test configuration) is the optional
default feature `test-config` (`crates/heimdall/Cargo.toml`). Every release build is made
with `--no-default-features`: `build-release.sh`, `build-release.ps1`,
`tools/validation/release-gate.sh` and every cargo call in `provenance.py`
(`RELEASE_FEATURE_ARGS`). A debug build without the feature fails to compile, and says why
(`crates/heimdall/src/main.rs`).

- **The check:** `provenance.py check-features` now also runs
  `release_graph_holds_no_test_only_crate`. The test-only set is what the debug graph reaches
  only through the kit: the default graph minus the same graph with `--prune heimdall-testkit`,
  plus the kit itself. None of it may be in the release graph.
- **Observed on `aarch64-apple-darwin`:** 14 such crates (`bit-set`, `bit-vec`, `core_detect`,
  `fastrand`, `fnv`, `heimdall-testkit`, `proptest`, `quick-error`, `rand_xorshift`,
  `regex-syntax`, `rusty-fork`, `tempfile`, `unarray`, `wait-timeout`). The release graph holds
  none of them.
- **Shown failing without the fix:** with `RELEASE_FEATURE_ARGS` emptied, `check-features`
  refuses and names all 14.
- **The record:** the build record, the SBOM's `heimdall:features` and the notices header now
  name the set as `--no-default-features` (plus `--features …` if any), not `default`.
- **A forgotten flag cannot ship the kit** (the orchestrator's condition, 2026-11-24).
  - `check-features` and `build-record` refuse a request naming `test-config` (or
    `--all-features`).
  - `build-record` refuses a build whose compiled set holds any test-only crate. That is what a
    build without `--no-default-features` produces.
  - The record states `test_kit: not included …` only after that check, as for `iroh`.
  - The release gate checks that its release build's graph has no `heimdall-testkit`, and says
    that every `HEIMDALL_TEST_*` it probes is refused at run time.
- **The release graph, observed** (`cargo tree --no-default-features -p heimdall -e normal
  --target aarch64-apple-darwin`): 203 packages, none of them `heimdall-testkit`, `proptest` or
  `tempfile`.
