# third_party

Vendored third-party source that the workspace builds in place of the crates.io release.
Nothing here is Heimdall's own code except the patch files.

## netdev 0.47.0, patched (`netdev-0.47.0/`)

- **What:** the crates.io `netdev` 0.47.0 package, extracted as published, with
  `netdev-0.47.0.hm-no-route-probe.patch` applied. The patch adds the cargo feature
  `hm-no-route-probe` (`Cargo.toml`) and, with it on, makes `net::ip::get_local_ipaddr()`
  return `None` before it creates a socket (`src/net/ip.rs`). Seven added lines; its callers
  already handle `None`.
- **Why:** iroh 1.4.2 calls `netwatch` unconditionally at endpoint creation, and netwatch's
  interface scan reaches `netdev::net::ip::get_local_ipaddr()`, which binds a wildcard UDP
  socket and connects it to learn the default-route address. No iroh setting avoids that bind,
  and ADR-0012 §2 requires an endpoint to open only the sockets its exposure policy names.
  See `docs/research/g06-iroh-pigeons.md` §3 ("The netdev patch") and ADR-0012 §1 item 3
  (the ruling on Q8). Cost: netdev no longer marks a default interface, and netwatch's
  `my_ip` is `None`.
- **How it is wired:** the root `Cargo.toml` has
  `[patch.crates-io] netdev = { path = "third_party/netdev-0.47.0" }`, and the feature `iroh`
  of `heimdall-transport-iroh` enables `netdev/hm-no-route-probe`. The vendored crate is
  not a workspace member (the workspace builds and tests only Heimdall's crates). Without the
  `iroh` feature nothing in the build graph uses netdev. `tools/validation/check.sh` step
  `iroh-check` keeps the patched build compiling.
- **Upstream:** https://github.com/shellrow/netdev, crates.io package `netdev` 0.47.0
  (`https://static.crates.io/crates/netdev/netdev-0.47.0.crate`), SHA-256
  `98a4d13f8061600697d721c5fd45262aba533a7d4a7670e7c64fd02d68e4a9fb` (the crates.io
  checksum).
- **Differences from the published package:**
  - the patch;
  - the published `Cargo.lock` is removed (cargo ignores a dependency's lockfile, and the
    package's own `.gitignore` would keep git from tracking it);
  - nothing else: `.cargo_vcs_info.json` and `Cargo.toml.orig` are kept as published.
- **Re-derive and check** (from the repository root; the archive is untrusted data, so extract
  it in a fresh directory and never run its build scripts outside cargo):

  ```sh
  d=$(mktemp -d)
  curl -fsSL -o "$d/netdev.crate" https://static.crates.io/crates/netdev/netdev-0.47.0.crate
  echo "98a4d13f8061600697d721c5fd45262aba533a7d4a7670e7c64fd02d68e4a9fb  $d/netdev.crate" | shasum -a 256 -c -
  tar xzf "$d/netdev.crate" -C "$d"
  (cd "$d/netdev-0.47.0" && patch -p1 < "$OLDPWD/third_party/netdev-0.47.0.hm-no-route-probe.patch")
  rm -f "$d/netdev-0.47.0/Cargo.lock"
  diff -r "$d/netdev-0.47.0" third_party/netdev-0.47.0 && echo identical
  rm -rf "$d"
  ```

- **License obligation:** netdev is MIT (`netdev-0.47.0/LICENSE`, "Copyright (c) 2021-2026
  shellrow"). The notice must stay with the source here, and the MIT notice goes into the
  release license bundle (plan §10.2; ADR-0012 §1 item 3). Keep `LICENSE` untouched. The patch
  file is Heimdall's change to MIT code and carries no license of its own.
- **Bumping netdev:** a new upstream version needs a new directory, a re-derived patch, and a
  recorded decision in `docs/architecture/dependencies.md`. A request to upstream for a
  supported way to turn the probe off is the way to retire this directory (ADR-0012 §1 item 3).
