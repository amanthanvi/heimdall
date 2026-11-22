# M08 design probes (disposable)

Never imported by production code. Outputs: `tests/evidence/artifacts/m08/probe/`,
record `tests/evidence/m08-probe-inventory-and-release-binary.json`.

- `inventory.py`: summarizes `cargo metadata --format-version 1 --locked --offline
  --filter-platform <triple>` for the `heimdall` binary: third-party crates reached through
  normal and build edges, licence expressions, crates without a licence field, build scripts,
  native `links`. Dev-only edges are skipped. No build runs.
- The release-binary inspection was done with `otool -L`, `codesign -dv`, `stat`, `shasum` and
  `strings` on `target/release/heimdall` (built with `cargo build --release --locked --offline
  -p heimdall`, `CARGO_BUILD_JOBS=4`). The binary was **not executed**.
