# X3: supply-chain and security tooling, Go vs Rust (G02 round 4)

- **Task:** M00-T05-r4-x3. **Status:** `verified` for every row marked observed below;
  open items are listed under "Limitations".
- **Run window:** 2026-10-06 05:46 to 06:20 UTC (timestamps from `date -u`; per-step
  `*-run-utc.txt` files).
- **Host:** macOS (darwin/arm64), Docker 29.8.1 (linux/arm64 VM) for the Linux checks.
- **Inputs:** `git archive 38b6b72 prototypes/go` and `git archive d8f0cbe prototypes/rust`, extracted
  into `/tmp/hm-r4/M00-T05-r4-x3/`. `prototypes/` was not edited. Fuzz targets, `deny.toml`,
  `about.toml`, `.goreleaser.yaml` and `dist-workspace.toml` were added only to scratch copies.
  Copies of those files are kept here.
- **Toolchains:** go1.27.1, rustc/cargo 1.99.0, nightly-2026-10-05 (rustc 1.101.0-nightly) installed in an
  isolated `RUSTUP_HOME` under `/tmp/hm-r4/tools/x3/`, zig 0.16.0 (Homebrew build, plus the official
  tarball for one check).
- **Tool pins:** `tools/tool-versions.txt` and `tools/install_tools.sh`. All installs are user-level
  under `/tmp/hm-r4/tools/x3/`:
  - Go tools: govulncheck v1.8.0, cyclonedx-gomod v1.12.0, go-licenses/v2 v2.0.1, goreleaser v2.18.2.
  - Rust tools: cargo-audit 0.22.2, cargo-deny 0.20.2, cargo-cyclonedx 0.5.9, cargo-fuzz 0.13.2,
    cargo-zigbuild 0.23.4, cargo-about 0.9.2, cargo-auditable 0.7.7, cargo-dist 0.32.0,
    cargo-geiger 0.13.0, libfuzzer-sys =0.4.13.
  - syft 1.42.1 was already installed via Homebrew and is not pinned by this task.
- **Network:** read-only GETs only, for tool and crate/module downloads, vuln.go.dev, the RustSec
  advisory-db git clone, ziglang.org, and Docker Hub image pulls. Nothing was published or pushed, and
  no listeners were opened.
- **Wording:** "Observed" means the command ran here and its exit code is quoted. "Inference" is
  labelled where used. Wall times are noisy, so they are reported but not scored.

---

## 1. Dependencies (direct / transitive)

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Declared direct deps | 7 `require` (plus 11 `// indirect`) | 10: 5 on all targets, 4 `cfg(unix)`, 1 `cfg(windows)` | go.mod; `cargo metadata` root deps | `deps/go-list-m-all.txt`, `deps/cargo-metadata-summary.txt` |
| Full resolution (all platforms, incl. test/unused) | 26 modules in the build list (`go list -m all`, rc=0); 85 `go mod graph` edges | 116 packages in Cargo.lock (`cargo metadata --locked`, rc=0) | build list vs lockfile | same |
| Actually linked, darwin-arm64 | 17 modules (20 non-std packages) | 81 crates (normal edges), 84 with build-deps and proc-macros | `go list -deps` per GOOS/GOARCH with CGO_ENABLED=0; `cargo tree -e normal[,build] --target` | `deps/go-linked-modules-*.txt`, `deps/cargo-tree-normal*-*.txt` |
| Actually linked, linux x64/arm64 | 17 modules | 82 crates (normal), 85 (normal+build) | same | same |
| Actually linked, windows-x64 | 17 modules (go-winio replaces termios), 24 non-std packages | 77 crates (normal), 79 (normal+build) | same | same |
| Duplicate versions | none (MVS selects one version per module) | hashbrown x2, signal-hook x2, syn x2 (cargo-deny `bans` warnings) | cargo-deny `check bans` | `vuln/cargo-deny-check-all.txt` |

**Assessment.** On every target the Rust prototype compiles in roughly 4.5 to 5 times as many
third-party units as the Go prototype (77 to 82 crates against 17 modules). The two languages count
at different granularity: a Go module often bundles what Rust splits into several crates. Even so,
the gap in independently versioned, independently published units is large. The Go prototype takes
SHA-256, base64, JSON and signal handling from the standard library (`crypto/sha256`,
`encoding/base64`, `encoding/json`, `os/signal`), where the Rust prototype uses crates (sha2, base64,
serde_json, signal-hook). The
Rust graph also holds three duplicate-version pairs.

## 2. unsafe / cgo / C / asm surface

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Prototype's own code | 0 packages import `unsafe` | 2 `unsafe` blocks in `src/sigdisp.rs` (`sigaction` query, `assume_init`) and 2 in `tests/cli.rs` (`wait4`). `lib.rs` has `#![deny(unsafe_code)]` and `main.rs` has `#![forbid(unsafe_code)]` | grep, `go list` Imports | `unsafe/go-unsafe-*.tsv`, `unsafe/rust-grep-unsafe-*.tsv` |
| Third-party units using unsafe, linux-arm64 | 2 of 26 non-std packages import `unsafe`: x/sys/unix (624 `unsafe.` tokens) and charmbracelet/x/ansi (5) | 55 of 86 crates contain the `unsafe` keyword; 14,117 tokens (upper bound, not cfg-filtered) | Go: compiled files only (`go list` GoFiles for the target). Rust: every .rs file in each crate, regex `\bunsafe\b` | same |
| Third-party unsafe, windows-x64 | 6 packages in 4 modules: x/sys/windows 1057, go-winio 121 over 3 packages, x/windows 6, x/ansi 5 | 49 of 80 crates; 16,031 tokens | same | same |
| Third-party unsafe, darwin-arm64 | 2 packages (x/sys/unix 364, x/ansi 5) | 54 of 85 crates; 7,185 tokens | same | same |
| cargo-geiger (Rust only, host target) | n/a (no maintained Go equivalent was run) | 82 crates; 42 have unsafe used by the build; 13,477 of 25,908 unsafe expressions used; 12 crates declare forbid. **rc=1**: the report was printed, but geiger exits 1 on "Found 10 warnings" about unscanned files | `cargo geiger --locked --output-format Ascii` | `unsafe/rust-cargo-geiger-host-aarch64-apple-darwin.txt`, `unsafe/rust-cargo-geiger.stderr.txt` |
| cgo / C compiled from deps | 0 (`CGO_ENABLED=0`; `CgoFiles`=0 on all targets) | 0 C compiled by deps. signal-hook's `extract.c` sits behind the disabled `extended-siginfo-raw` feature, and `cc` is not in the build graph. 14 crates have build.rs | `go list` CgoFiles; build.rs and feature inspection | same |
| Assembly in deps | x/sys/unix: 1 .s file (linux) or 2 (darwin); none on windows | 6 crates contain `asm!`/`global_asm!` (rustix, compact_str, ...; not cfg-filtered) | `go list` SFiles; regex | same |
| C runtime linked into the artifact | none: Go runtime and stdlib only (they contain unsafe and asm, which is not counted above) | musl libc, statically linked on linux (zig-built); mingw-w64 CRT on windows-gnu; Rust std also contains unsafe (not counted) | inspection of the build method | `hardening/checksec-linux-artifacts*.txt` |

**Assessment.** The Rust prototype's own code has 2 audited `unsafe` blocks behind a crate-wide
deny. Its dependency graph, though, has far more crates containing `unsafe`, and the Linux and Windows
artifacts link a C runtime (musl or mingw). The Go prototype's own code has no `unsafe`. Its
third-party unsafe is concentrated in `golang.org/x/sys` (syscall wrappers) plus a few lines in
charmbracelet `ansi`, and its artifacts contain no C. The two measurement methods differ: Go's counts
are cfg-filtered by the toolchain, while Rust's grep counts are an upper bound. cargo-geiger's
"used" count is the closer Rust analogue.

## 3. Vulnerability scanning

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Scanner / DB | govulncheck v1.8.0; vuln.go.dev, DB updated 2026-10-01 20:24 UTC | cargo-audit 0.22.2 and cargo-deny 0.20.2; RustSec advisory-db commit ef6173cb (2026-10-03), 1,290 advisories | pinned tool installs | `vuln/govulncheck-version.txt`, `vuln/cargo-audit.txt` |
| Source/lockfile scan of the prototype | 4 targets, all **rc=0**, "No vulnerabilities found" (170 OSV entries considered on linux-arm64) | cargo-audit **rc=0**: 0 vulnerabilities, 0 warnings over 117 lock entries. cargo-deny `check advisories bans licenses sources` **rc=0** with unmaintained=all and yanked=deny | `govulncheck -show verbose ./...` per GOOS/GOARCH; `cargo audit`; `cargo deny --locked check` | `vuln/govulncheck-source-*.txt`, `vuln/cargo-audit.txt`, `vuln/cargo-deny-check-all.txt` |
| Reachability analysis | yes (symbol level). Positive control (x/text v0.3.7): source mode rc=0, reporting "affected by 0" with 1 imported and 1 required vuln (GO-2022-1059, GO-2026-5970) not called; `-scan module` rc=3 | no (lockfile level). Positive control (smallvec =1.6.0): cargo-audit rc=1 with RUSTSEC-2021-0003 | scratch modules with a known-vulnerable dep | `vuln/posctl-*.txt` |
| Scanning the shipped binary | `govulncheck -mode binary` on the build.sh artifacts works without extra build steps (linux-arm64 and windows-x64 rc=0; 18 modules from buildinfo (17 third-party plus main)) | `cargo audit bin` on build.sh artifacts rc=0, but warns "was not built with 'cargo auditable', the report will be incomplete (25 dependencies recovered)". After `cargo auditable build`, it found auditable data for 103 deps | as stated | `vuln/govulncheck-binary-go-*.txt`, `vuln/cargo-audit-bin-rust-*.txt` |
| Policy gating beyond CVEs | not built into govulncheck (no license, source or duplicate policy) | cargo-deny adds license allow-lists, source allow-lists, ban/duplicate rules, and yanked/unmaintained checks in one tool | config in `license/rust-deny.toml` | `vuln/cargo-deny-check-all.txt` |

**Assessment.** Both ecosystems have working, maintained scanners, and both scanned the prototypes
clean on 2026-10-01/03 data. govulncheck gives call-graph reachability, so it has fewer false
positives, and it scans shipped binaries natively because Go embeds buildinfo. Its default exit
code is 0 when a vulnerable symbol is not called, which matters for CI gating. cargo-audit is
lockfile-level, so it reports any vulnerable crate present. Binary scanning on the Rust side needs
`cargo auditable` in the release build. cargo-deny is a broader policy gate than anything
first-party on the Go side.

## 4. License scanning

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Tool and result | go-licenses v2.0.1. `report`: 17 third-party modules, of which 15 MIT and 2 BSD-3-Clause (x/sys, x/sync). `check` with an allow-list (MIT/Apache-2.0/BSD-2/BSD-3) and `--ignore` of the unlicensed prototype: **rc=0** on linux/arm64, windows/amd64 and darwin/arm64. Without `--ignore`, rc=1 because the prototype itself has no license | cargo-deny `check licenses` **rc=0** (allow-list in `rust-deny.toml`; private root ignored). cargo-about 0.9.2 `generate --format json` **rc=0**: 95 crates, 53 license texts; first-accepted license per crate MIT 94, Apache-2.0 1, Unicode-3.0 1, Zlib 1 | as stated | `license/go-licenses-*.{csv,txt}`, `license/cargo-about-summary.txt`, `vuln/cargo-deny-check-all.txt` |
| License expressions seen | MIT, BSD-3-Clause | 12 distinct expressions: mostly `MIT OR Apache-2.0`, plus MIT, Zlib, Unicode-3.0, BSL-1.0, Unlicense, `Apache-2.0 WITH LLVM-exception` | metadata | `deps/cargo-metadata-summary.txt` |
| Gaps (both) | go-licenses does not list the Go stdlib/runtime (BSD-3), which is linked into every binary | cargo-deny and cargo-about do not list Rust std (MIT/Apache), musl (MIT) or the mingw CRT, which are linked into the artifacts | tool behaviour | n/a |
| Notes | go-licenses warns that x/sys/unix "contains non-Go code that can't be inspected" (asm) | the prototype already ships `THIRD-PARTY-NOTICES.txt` via its own script; cargo-about could replace that | | `license/*stderr*` |

**Assessment.** Both languages have adequate tooling. Rust needs more of it because its graph is
larger and has more license variety (12 expressions against 2). cargo-deny makes license policy a
CI gate together with advisories. Neither tool covers the toolchain's own runtime, nor (for Rust)
the C runtime it links.

## 5. SBOM generation

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Native source SBOM | cyclonedx-gomod v1.12.0 `app -licenses -packages -main cmd/heimdall-proto` gave CycloneDX 1.6 with 17 modules on linux-arm64 (37 including package subcomponents), all with purl and license. **Needs a git repo:** the first run on the git-archive copy failed rc=1 ("failed to determine version of main module: no git repository found") and passed rc=0 in a git-initialised copy | cargo-cyclonedx 0.5.9 `--target aarch64-unknown-linux-musl` **rc=0**: CycloneDX 1.5, 103 components, all with purl and license. **Over-reports:** 18 crates that are not in the target's normal+build tree (e.g. palette, time, serde, approx) | as stated; compared against `cargo tree` | `sbom/go-cyclonedx-gomod-app-*.cdx.json`, `sbom/rust-cargo-cyclonedx-linux-arm64.cdx.json`, `sbom/sbom-summary.txt` |
| SBOM from the shipped binary | cyclonedx-gomod `bin`: 17 modules, rc=0 (licenses not resolved, "module not in cache"). syft 1.42.1: SPDX 2.3 with 20 packages | syft on the build.sh artifact: 1 package (only the file itself; no dep data in the binary). syft on a `cargo auditable` build: 81 packages | `syft scan file:<artifact> -o spdx-json` | `sbom/syft-*.spdx.json`, `sbom/go-cyclonedx-gomod-bin-linux-arm64.cdx.json` |
| Release-pipeline integration | goreleaser `sboms:` (runs syft) produced 4 archive SBOMs in the snapshot run | cargo-dist config keys `cargo-cyclonedx = true` and `cargo-auditable = true` (docs; not exercised) | as stated | `release/goreleaser-snapshot.log` |

**Assessment.** Go binaries carry their dependency list, so any tool can produce an accurate
artifact-level SBOM with no extra build step. Rust needs `cargo auditable` in the release build to
get the same. Without it, artifact SBOMs are empty. Its source-level SBOM (cargo-cyclonedx) listed
18 crates that are not compiled for the target, so it is less precise than the Go module-based one.
That reading rests on comparison with `cargo tree`; the cause was not diagnosed.

## 6. Reproducible builds

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Two clean builds, same host, different checkout paths, fresh caches | **Identical** sha256 for all 4 targets. darwin 31c3ee17..., linux-x64 429063bf..., linux-arm64 d55b4ffe..., windows-x64 ca5145d1... (build.sh rc=0 twice) | **Identical** sha256 for all 4 targets plus the notices file. darwin 496684ed..., linux-x64 961e3fb9..., linux-arm64 47160fdd..., windows-x64 dde9662f... (build.sh rc=0 twice) | each prototype's own `build.sh`; paths `go-a` vs `go-build-bbbb`, `rust-a` vs `rust-build-bbbb` | `repro/go-sha256-compare.txt`, `repro/rust-sha256-compare.txt`, `repro/*-build-*.log` |
| What the build needs for this | `-trimpath -buildvcs=false`, `CGO_ENABLED=0` | 5 `--remap-path-prefix` flags, `-oso_prefix` (darwin), `/Brepro` (windows), an exact rustc pin and a pinned cargo-zigbuild. Cargo's `trim-paths` profile option is still unstable on 1.99.0 (probe rc=101: "feature `trim-paths` is required") | build scripts; probe | `repro/rust-stable-trim-paths-probe.txt` |
| Cross-host (macOS host vs linux/arm64 container, same toolchain versions) | **Identical** for linux-x64, linux-arm64 and windows-x64 (golang@sha256:6e725de5...). darwin matches only after the same ad-hoc hardened-runtime `codesign` on macOS with the same file name (31c3ee17...) | **Different** for all 3 targets; container-built darwin is not possible. Container run1 equals run2. The macOS Homebrew-zig build embeds "Homebrew clang/LLD 21.1.8", while the official zig embeds 21.1.0. With official zig 0.16.0 on macOS the bytes still differ from the container's, and windows-x64 differs by 640,029 bytes. Inference (not verified): host-dependent rustc/cargo inputs, such as the host triple feeding cargo metadata hashes | containers rust@sha256:59037199... and golang@sha256:6e725de5... | `repro/go-cross-host-container.txt`, `repro/rust-cross-host.txt`, `repro/*container*` |
| Builder path leak in artifacts | 0 home-path strings (build.sh artifact) | build.sh artifact: 0. **cargo-dist default build:** 26 lines (linux-arm64) and 7 (darwin) containing the builder's home directory and `.cargo/registry` paths | `grep -a -c -F "$HOME"` | `release/artifact-builder-path-leak-check.txt` |

**Assessment.** On one host, both are bit-for-bit reproducible once each prototype's build script
is used. Go gets there with two standard flags and is also reproducible across hosts. Rust needed
hand-tuned remap and linker flags. It was not reproducible across hosts here, and the zig
distribution (Homebrew vs official) changed the output, so independent rebuild verification of
Rust releases would need a pinned build environment (for example a pinned container).

## 7. Fuzzing (60 s smoke on the profile parser)

| Metric | Go | Rust | Method | Evidence |
|---|---|---|---|---|
| Toolchain requirement | built in (`go test -fuzz`), stable go1.27.1, no extra deps | cargo-fuzz 0.13.2 plus libfuzzer-sys =0.4.13, which builds libFuzzer (C++) through `cc`. The default ASan mode needs **nightly**; `-s none` works on stable 1.99 | as stated | `fuzz/rust-fuzz-Cargo.toml`, `fuzz/rust-cargo-fuzz-build.log` |
| Target | `FuzzParse`: `profile.Parse(b)` returns exactly one of (profile, error) | `fuzz_target!`: `heimdall_proto::profile::parse_bytes(data)`, no panic | same 6 seeds from `tests/fixtures/g02/profiles` (2 canary-bearing fixtures excluded) | `fuzz/go-x3_fuzz_test.go`, `fuzz/rust-profile_parse.rs` |
| 60 s, 8 workers | rc=0 PASS: 6,854,181 execs, 346 corpus entries, 0 failures | `-fork=8`, ASan, rc=0: 3,085,322 execs, cov 3,182, ft 18,365, corpus 3,151, oom/timeout/crash 0/0/0 | `-parallel 8` / `-fork=8` | `fuzz/go-fuzz-60s.txt`, `fuzz/rust-cargo-fuzz-60s-fork8.txt` |
| 60 s, 1 worker | default settings: rc=0 PASS but **stalled**: 8,317 execs, 0 execs/s from 3 s to 60 s. With `-fuzzminimizetime 2s`: 427,131 execs, 140 corpus, rc=0. Inference: the stall is the default 60 s minimisation of a new input | ASan nightly: rc=0, 424,519 runs, cov 2,890, corpus 2,534. Stable `-s none`: rc=0, 1,403,817 runs, cov 2,161 | as stated | `fuzz/go-fuzz-60s-parallel1*.txt`, `fuzz/rust-cargo-fuzz-60s-1proc.trimmed.txt`, `fuzz/rust-cargo-fuzz-stable-sanitizer-none-60s.trimmed.txt` |
| Crashes found | none | none | | |

**Assessment.** Neither parser failed in 60 s. Go fuzzing is zero-setup and runs as part of
`go test`. With one worker, its default minimisation can starve a short run. Rust has the more
capable engine (libFuzzer with sanitizer and coverage metrics) at the cost of a nightly toolchain
for ASan and a C++ build dependency. Exec counts are not directly comparable: they use different
engines and instrumentation, and ASan was on.

## 8. Release tooling

| Metric | Go (GoReleaser v2.18.2, OSS) | Rust (cargo-dist 0.32.0) | Method | Evidence |
|---|---|---|---|---|
| Local dry run | `goreleaser check` rc=0. `release --snapshot --clean --skip=publish,sign` rc=0 in about 5 s: 4 targets, archives, checksums, 4 syft SBOMs. Binaries are byte-identical to build.sh output | `dist init --yes` rc=255: "doesn't have anything for dist to Release" (`publish = false`), and it silently added 4 extra default targets plus `[profile.dist] lto="thin"`. After `dist = true` and a placeholder `repository`: generate rc=0, plan rc=0. Local `dist build`: darwin rc=0, linux-arm64 rc=0, linux-x64 rc=0 (uses cargo-zigbuild); **windows-gnu rc=255** ("required ... cargo-xwin" missing; not installed) | scratch git-initialised copies; nothing published | `release/goreleaser-*.{log,txt,yaml}`, `release/cargo-dist-*` |
| Archive reproducibility | two snapshot runs gave identical binaries but **different archives**, even with `builds_info.mtime`: the binary's tar mtime equals the run time in snapshot mode. Tar headers also carry the local uid and owner names by default. The tag-release path was not tested | not measured. Note that the default dist build embeds builder home paths (section 6) | sha256 of checksums.txt | `release/goreleaser-snapshot-checksums-*.txt`, `release/goreleaser-archive-repro-notes.txt` |
| CI generation | none generated here (goreleaser-action exists; not evaluated) | generates a 296-line GitHub workflow. Actions are tag-pinned (`actions/checkout@v6`), not SHA-pinned, and dist is installed with `curl ... | sh` | generated file | `release/cargo-dist-generated-release.yml` |
| Supply-chain features (docs, not exercised) | SBOMs, cosign/gpg signing, attestations, checksums. macOS sign and notarize cross-platform via quill is in OSS; native App Bundle/pkg signing is **Pro-only**. nFPM deb/rpm, Homebrew, Scoop, Winget, Nix, AUR, Chocolatey, Snapcraft | `github-attestations`, `cargo-auditable`, `cargo-cyclonedx`, `omnibor`, checksums (sha256/512, sha3, blake2), Windows signing via ssl.com or Azure, installers (shell, powershell, npm, homebrew, msi) | goreleaser.com/customization, /customization/sign/notarize, /blog/reproducible-builds; axodotdev.github.io/cargo-dist/book/reference/config.html (fetched 2026-10-06) | n/a (docs) |

**Assessment.** GoReleaser built the full matrix locally on the first try, with artifacts identical
to the hand-written build. Its archive reproducibility needs more configuration than tested here.
cargo-dist covers comparable features with Rust-specific supply-chain hooks (auditable,
cyclonedx). On this host it needed manual configuration fixes, could not build windows-gnu without
cargo-xwin, and its default profile produced artifacts that leak the builder's home path. The
prototype's own build.sh avoids that leak.

## 9. Hardening flags (checksec in a linux/arm64 container)

Container: `debian@sha256:7c7b2c96...` (bookworm-slim, arm64) with checksec 2.6.0-2, binutils 2.40-2
and file 5.44-3. Docker rc=0 for both rounds. Script: `hardening/inspect.sh`.

| Artifact (linux-arm64 unless noted) | ELF type | PIE | RELRO | NX | Canary | BTI/PAC insns | Evidence |
|---|---|---|---|---|---|---|---|
| Go build.sh default | EXEC static | no | no (no GNU_RELRO) | yes | no (n/a: no C) | 0/0 | `hardening/checksec-linux-artifacts.txt` |
| Go `-buildmode=pie` (CGO_ENABLED=0) | DYN, INTERP `/lib/ld-linux-aarch64.so.1` | yes | partial | yes | no | 0 | same |
| Go `-buildmode=pie -ldflags=-bindnow` | DYN, BIND_NOW | yes | **full** | yes | no | 0 | `hardening/checksec-linux-artifacts-round2.txt` |
| Rust build.sh default (zig, musl) | EXEC static | no | partial | yes | no | 0 | `checksec-linux-artifacts.txt` |
| Rust stable `-C relocation-model=pie`, `-C relro-level=full`, `-Wl,-z,relro,-z,now`, or rust-lld | EXEC static (all variants) | no | partial | yes | no | 0 | same |
| Rust nightly `-Zstack-protector=strong` (unstripped) | EXEC static | no | partial | yes | **yes**: 358 `bl __stack_chk_fail` call sites (0 with `=none`) | 0 | round2 |
| Rust nightly `-Zbuild-std` + stack-protector + `-Zbranch-protection=bti,pac-ret` | EXEC static | no | partial | yes | (stripped; not detectable) | paciasp 1,413, bti 2,692, but **no GNU property note** | `checksec-linux-artifacts.txt` |
| x64 Go / x64 Rust defaults | EXEC static | no | no / partial | yes | no | n/a | same |
| windows-x64 PE (both) | Go: DYNAMIC_BASE, HIGH_ENTROPY_VA, NX_COMPAT; no GUARD_CF; TimeDateStamp 0. Rust: same flags; no GUARD_CF; load_config 0; TimeDateStamp is a `/Brepro` hash | | | | | | `hardening/pe-dllcharacteristics-windows-x64.txt` |
| darwin-arm64 Mach-O (both) | PIE; ad-hoc signature with hardened runtime (flags 0x10002 adhoc,runtime) | | | | | | `hardening/macho-darwin-arm64.txt` |

Flag availability: `hardening/toolchain-hardening-flags.txt` and `hardening/rust-target-spec-hardening-fields.txt`.

- **Go:** offers `-buildmode=pie` and `-bindnow` (linker). No stack-protector, CFI, CFG, BTI or PAC
  option appears in `go tool link -help`.
- **Rust stable:** `-C relocation-model`, `-C relro-level` and `-C control-flow-guard` (Windows).
- **Rust nightly:** `-Z stack-protector`, `-Z branch-protection` (needs `-Zbuild-std`; without it,
  rc=101 with "mixing `-Zbranch-protection` will cause an ABI mismatch"), `-Z sanitizer=cfi`,
  `-Z cf-protection` and `-Z ehcont-guard`.
- **aarch64-unknown-linux-musl target spec:** lacks `static-position-independent-executables`, while
  x86_64-musl has it. Even so, the zig-linked x64 artifact was still EXEC.

**Assessment.**
- Both default artifacts are non-PIE static executables with NX on Linux, and PIE plus hardened
  runtime on macOS.
- Go can reach PIE and full RELRO on stable with two flags. That gives a glibc-interpreter dynamic
  PIE, which by inference would not run on musl-only systems; this was not tested.
- Rust on stable did not reach PIE for the static musl target through any flag tried. Its stronger
  options (stack protector, BTI/PAC, CFI) are nightly-only.
- The BTI build emitted no ELF property note, so by inference the kernel would not enforce BTI;
  musl/crt objects without BTI likely drop the note. This was not verified.
- For a memory-safe language, the canary and CFI rows mainly guard the linked C runtime. Rust links
  one on Linux and Windows; Go does not.

---

## Limitations and incidents

- **Rust cross-host reproducibility:** the cause is not diagnosed past the inference stated above.
  The Go cross-host check covers one Linux image. Windows and darwin native rebuild hosts were not
  used.
- **cargo-geiger rc=1:** this is the tool's warnings-as-error behaviour. The report was still
  produced; geiger 0.13.0 dates from 2025-08.
- **Go unsafe tooling:** no Go equivalent of geiger was run; the counts come from `go list` plus grep.
- **Unmeasured release paths:** goreleaser tag-release mode, signing and notarisation, cargo-dist
  windows (cargo-xwin) and its CI workflow were not run. Release feature rows marked "docs" are from
  documentation only.
- **checksec on static binaries:** "partial RELRO" mostly reflects the missing BIND_NOW flag. For a
  static non-PIE binary, whether GNU_RELRO is actually mprotected at runtime was not tested.
- **Canary detection:** this needs symbols. Only the unstripped nightly variants were checked for
  `__stack_chk_fail`.
- **Fuzz logs:** two libFuzzer logs were trimmed for size (first 60 and last 80 lines kept). The
  original line count and sha256 are recorded in each file header; the full logs are only in scratch.
- **Incident (reversed):** running `cargo fuzz` with `RUSTUP_TOOLCHAIN=1.99.0` made rustup
  auto-install a toolchain named `1.99.0-aarch64-apple-darwin` into the user's default rustup home.
  It was uninstalled twice: once, then again after a later env-var command re-triggered the install.
  `rustup toolchain list` was verified back to the original set (stable, 1.88, 1.92.0, 1.93.0,
  1.98.1). All other toolchains and tools went to `/tmp/hm-r4/tools/x3/`. Crate and module downloads
  for prototype builds used the existing user caches (`~/.cargo/registry`, `~/go/pkg/mod`).
- **Evidence records:** no `tests/evidence/*.json` evidence record was written, because that path is
  outside this task's write ownership.

## Scripts

`tools/scripts/` holds go_unsafe.sh, rust_unsafe.py, repro_go.sh, repro_rust.sh, versions.sh,
pe_flags.py and x3_fuzz_test.go. `hardening/inspect.sh` and `repro/container-*.sh` hold the
container scripts.
