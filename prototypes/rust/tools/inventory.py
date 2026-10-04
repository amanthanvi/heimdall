#!/usr/bin/env python3
"""Shared inventory of everything statically linked into the Rust G02 artifacts.

Used by gen_licenses.py (LICENSES.md) and gen_notices.py (dist/THIRD-PARTY-NOTICES.txt).
Sources, all local (no network):
  * crates.io crates: `cargo tree --locked --offline` per target, and `cargo metadata`
    for each crate's source directory (license files);
  * Rust standard library: the `rust-src` component of the active toolchain
    (library/Cargo.lock, library/*/Cargo.toml, library/vendor/*), plus the toolchain's
    share/doc/rust (COPYRIGHT and license texts);
  * native runtime pieces (musl, LLVM libunwind, mingw-w64, GCC crt objects): the
    linker inputs rustc passes (observed with `--print=link-args`, round 2) and the
    license files shipped with the zig installation that cargo-zigbuild links with.
"""
import json
import os
import re
import subprocess

TARGETS = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-x64": "x86_64-unknown-linux-musl",
    "linux-arm64": "aarch64-unknown-linux-musl",
    "windows-x64": "x86_64-pc-windows-gnu",
}

# Standard-library crates that std is built from for these four targets
# (library/std/Cargo.toml dependency set, excluding wasm/sgx/uefi/hermit/... targets).
STD_CRATES = ["std", "core", "alloc", "panic_unwind", "panic_abort", "unwind",
              "compiler_builtins", "std_detect", "cfg-if", "hashbrown", "rustc-demangle",
              "addr2line", "gimli", "object", "memchr", "miniz_oxide", "adler2", "libc",
              "windows-link"]
STD_WINDOWS_ONLY = {"windows-link"}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def sysroot():
    return run(["rustc", "--print", "sysroot"]).strip()


def crate_tree(edges, triple):
    out = run(["cargo", "tree", "--locked", "--offline", "-e", edges, "--target", triple,
               "--prefix", "none", "--format", "{p}|{l}"])
    rows = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        pkg, _, lic = line.partition("|")
        pkg = pkg.replace(" (*)", "").strip()
        lic = lic.replace(" (*)", "").strip()
        proc = "(proc-macro)" in pkg
        pkg = re.sub(r"\s*\(.*?\)", "", pkg).strip()
        if pkg.startswith("heimdall-proto "):
            continue
        rows[pkg] = (lic, proc)
    return rows


def crates():
    """{ "name vX": {license, targets:set, kind:set} } for all four targets."""
    allpk = {}
    for name, triple in TARGETS.items():
        normal = crate_tree("normal,no-proc-macro", triple)
        withbuild = crate_tree("normal,build", triple)
        for pkg, (lic, proc) in withbuild.items():
            e = allpk.setdefault(pkg, {"license": lic, "targets": set(), "kind": set()})
            e["targets"].add(name)
            if pkg in normal:
                e["kind"].add("linked")
            elif proc:
                e["kind"].add("build-time (proc-macro)")
            else:
                e["kind"].add("build-time (proc-macro/build-script dependency)")
    return allpk


def crate_dirs():
    """{ "name vX": source dir } from cargo metadata."""
    md = json.loads(run(["cargo", "metadata", "--locked", "--offline", "--format-version", "1"]))
    return {f'{p["name"]} v{p["version"]}': os.path.dirname(p["manifest_path"]) for p in md["packages"]}


def _toml_field(path, field):
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r'^%s\s*=\s*"([^"]*)"' % field, text, re.M)
    return m.group(1) if m else None


def std_crates():
    """[(name, version, license, source dir)] for the standard library set."""
    lib = os.path.join(sysroot(), "lib/rustlib/src/rust/library")
    lock = open(os.path.join(lib, "Cargo.lock"), encoding="utf-8").read()
    versions = {}
    for m in re.finditer(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock):
        versions[m.group(1)] = m.group(2)
    out = []
    for name in STD_CRATES:
        ver = versions.get(name.replace("-", "_")) or versions.get(name)
        cands = [os.path.join(lib, "vendor", f"{name}-{ver}"), os.path.join(lib, name),
                 os.path.join(lib, name.replace("-", "_")), os.path.join(lib, "compiler-builtins", name.replace("_", "-"))]
        d = next((c for c in cands if os.path.isfile(os.path.join(c, "Cargo.toml"))), None)
        lic = _toml_field(os.path.join(d, "Cargo.toml"), "license") if d else None
        out.append((name, ver or "?", lic or "MIT OR Apache-2.0 (Rust project; not declared in this Cargo.toml)", d))
    return out


ZIG_LIB = None


def zig_lib():
    global ZIG_LIB
    if ZIG_LIB is None:
        try:
            env = run(["zig", "env"])
            m = re.search(r'lib_dir"?\s*[=:]\s*"([^"]+)"', env)
            ZIG_LIB = m.group(1) if m else ""
        except (OSError, subprocess.CalledProcessError):
            ZIG_LIB = ""
    return ZIG_LIB


def native_components():
    """Native runtime pieces linked into the artifacts (not crates)."""
    z = zig_lib()
    lic_dir = os.path.join(sysroot(), "share/doc/rust/licenses")
    return [
        {"component": "musl libc (static libc.a and crt1/crti/crtn objects)", "targets": "linux-x64, linux-arm64",
         "license": "MIT (musl COPYRIGHT; text taken from zig's musl copy, which may differ in version from the libc.a actually linked)",
         "evidence": "rustc link line: -lc and self-contained crt objects; artifacts are static ELF",
         "texts": [os.path.join(z, "libc/musl/COPYRIGHT")] if z else []},
        {"component": "LLVM libunwind (static)", "targets": "linux-x64, linux-arm64, windows-x64",
         "license": "Apache-2.0 WITH LLVM-exception",
         "evidence": "rustc link line: -lunwind (musl) / -lgcc_eh (windows-gnu, provided by zig); 'libunwind:' strings in the artifacts",
         "texts": [os.path.join(z, "libunwind/LICENSE.TXT")] if z else []},
        {"component": "GCC crtbegin.o/crtend.o (Rust's self-contained musl objects)", "targets": "linux-arm64 (observed), linux-x64 (crtbeginS/crtendS on the link line)",
         "license": "GPL-3.0-or-later WITH GCC-exception-3.1",
         "evidence": "rustc link line lists self-contained crtbegin/crtend objects; 'GCC: (GNU) 9.4.0' .comment string in the linux-arm64 artifact",
         "texts": [os.path.join(lic_dir, "GPL-3.0-or-later.txt"), os.path.join(lic_dir, "GCC-exception-3.1.txt")]},
        {"component": "mingw-w64 runtime (static parts: crt objects, libmingw32, libmingwex)", "targets": "windows-x64",
         "license": "ZPL-2.1, except parts marked Public Domain, BSD or LGPL (mingw-w64 COPYING); which marked parts are linked was not determined",
         "evidence": "rustc link line: -lmingw32 -lmingwex -lmsvcrt; 'Mingw-w64 runtime failure:' string in the artifact",
         "texts": [os.path.join(z, "libc/mingw/COPYING")] if z else []},
        {"component": "macOS libSystem and libiconv (dynamic, provided by the OS, not redistributed)", "targets": "darwin-arm64",
         "license": "Apple system libraries (not shipped)", "evidence": "otool -L", "texts": []},
        {"component": "Windows system DLLs and UCRT api-ms-win-crt-* (dynamic, provided by the OS, not redistributed)", "targets": "windows-x64",
         "license": "Microsoft system components (not shipped)", "evidence": "PE import table", "texts": []},
    ]


def rust_license_texts():
    """Rust project license texts shipped with the toolchain (share/doc/rust/licenses)."""
    d = os.path.join(sysroot(), "share/doc/rust/licenses")
    return [os.path.join(d, n) for n in ("Apache-2.0.txt", "MIT.txt", "LLVM-exception.txt")
            if os.path.isfile(os.path.join(d, n))]


def license_files(d):
    if not d or not os.path.isdir(d):
        return []
    names = sorted(n for n in os.listdir(d)
                   if re.match(r"(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE)", n, re.I)
                   and os.path.isfile(os.path.join(d, n)))
    return [os.path.join(d, n) for n in names]
