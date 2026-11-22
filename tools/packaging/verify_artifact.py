#!/usr/bin/env python3
"""Static check of a Heimdall release archive (m08-plan U3a; ADR-0014 sections 4.2 and 4.4).

Usage:
    python3 -I tools/packaging/verify_artifact.py <archive.tar.gz|archive.zip|directory>
            [--target <triple>] [--index <SHA256SUMS>] [--forbid <text>]... [--forbid-file <file>]
            [--allow-exact <text>]...
    python3 -I tools/packaging/verify_artifact.py --self-test

Nothing in the archive is executed. Exit code 0 only when every check passes; 1 when
any check fails (each failure is one line on stdout); 2 on a usage or setup error.

Checks:
  * layout: one top-level directory; no link, device or path that leaves it;
  * MANIFEST.sha256, the inner payload manifest, lists every file except itself with a
    matching digest, and nothing else; SHA256SUMS, the external index, is never inside;
  * with --index, the archive's own digest is in that external index (ADR-0014 section 4.4);
  * no file holds a build-host path (a home directory, a cargo registry or rustup
    toolchain path), a private-key block, a full canary value, or any --forbid text
    (the build script passes the builder's home, cargo, rustup and checkout paths and the
    builder's user name). `--allow-exact <text>` names one exact string that may contain a
    forbidden text: each occurrence of exactly those bytes is masked before the scan, so the
    same text anywhere else still fails. It exists for the product's own identifiers (the
    macOS login-entry label embeds the repository owner's account name), not for paths;
  * each executable imports only the libraries the bare operating system has:
    macOS system frameworks, libSystem and libiconv; glibc's own libraries with no
    symbol version above the floor; Windows system DLLs with no separate C runtime;
  * BUILD-RECORD.json, when present, names the target and lists exactly the executables,
    with their digests, and no digest of itself, the manifest or the archive.

Standard library only. `--forbid` values are never printed: a hit names the rule.
"""
import hashlib
import json
import os
import re
import struct
import sys
import tarfile
import tempfile
import zipfile

GLIBC_FLOOR = (2, 31)
SUMS = "MANIFEST.sha256"
INDEX = "SHA256SUMS"
RECORD = "BUILD-RECORD.json"

# Generic build-host traces. Standard-library paths are remapped by rustc itself to
# /rustc/<hash>/ and are not build-host paths.
GENERIC = [
    ("cargo registry path", re.compile(rb"\.cargo[/\\]registry[/\\]")),
    ("cargo git checkout path", re.compile(rb"\.cargo[/\\]git[/\\]checkouts")),
    ("rustup toolchain path", re.compile(rb"\.rustup[/\\]toolchains")),
    ("home directory path", re.compile(
        rb"(?:/Users/|/home/|[A-Za-z]:\\Users\\)[A-Za-z0-9._-]{1,64}[/\\](?:\.cargo|\.rustup|\.t3|GitRepos|src|code|work|dev|projects)[/\\]")),
    ("private key block", re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("canary value", re.compile(rb"HEIMDALL_CANARY_(?:[A-Z0-9]+_)*[0-9a-f]{8,}")),
]

MACOS_ALLOWED = re.compile(
    r"^(?:/System/Library/Frameworks/[A-Za-z0-9]+\.framework/Versions/[A-Z0-9]+/[A-Za-z0-9]+"
    r"|/usr/lib/libSystem\.B\.dylib|/usr/lib/libiconv\.2\.dylib)$")
LINUX_ALLOWED = re.compile(
    r"^(?:libc\.so\.6|libm\.so\.6|libgcc_s\.so\.1|libpthread\.so\.0|libdl\.so\.2|librt\.so\.1"
    r"|libutil\.so\.1|ld-linux-x86-64\.so\.2|ld-linux-aarch64\.so\.1)$")
WINDOWS_ALLOWED = re.compile(
    r"^(?:kernel32|kernelbase|ntdll|advapi32|bcrypt|bcryptprimitives|crypt32|ncrypt|secur32"
    r"|ws2_32|userenv|user32|shell32|ole32|oleaut32|rpcrt4|iphlpapi|netapi32|psapi|dbghelp"
    r"|synchronization|sspicli|wtsapi32|api-ms-win-core-[a-z0-9-]+)\.dll$")


class Failure(Exception):
    """A setup problem: the archive cannot be examined at all."""


# --------------------------------------------------------------------------- unpack

def unpack(src, dest):
    """Extract `src` into `dest` with every member checked; return the root directory."""
    if os.path.isdir(src):
        return os.path.abspath(src)
    if src.endswith((".tar.gz", ".tgz")):
        with tarfile.open(src, "r:gz") as tar:
            for m in tar.getmembers():
                if not (m.isreg() or m.isdir()):
                    raise Failure(f"archive member is not a regular file or directory: {m.name}")
                _safe_name(m.name)
            for m in tar.getmembers():
                target = os.path.join(dest, m.name)
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with tar.extractfile(m) as fh, open(target, "wb") as out:
                    out.write(fh.read())
    elif src.endswith(".zip"):
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                _safe_name(info.filename)
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Failure(f"archive member is a link: {info.filename}")
                target = os.path.join(dest, info.filename)
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    out.write(z.read(info))
    else:
        raise Failure("not a directory, .tar.gz or .zip")
    tops = sorted(os.listdir(dest))
    if len(tops) != 1 or not os.path.isdir(os.path.join(dest, tops[0])):
        raise Failure("the archive must hold exactly one top-level directory")
    return os.path.join(dest, tops[0])


def _safe_name(name):
    parts = name.replace("\\", "/").split("/")
    if name.startswith(("/", "\\")) or ".." in parts or (len(name) > 1 and name[1] == ":"):
        raise Failure(f"archive member leaves the archive root: {name}")


def files_under(root):
    out = []
    for base, dirs, names in os.walk(root):
        dirs.sort()
        for n in sorted(names):
            full = os.path.join(base, n)
            if os.path.islink(full) or not os.path.isfile(full):
                raise Failure(f"not a regular file: {os.path.relpath(full, root)}")
            out.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ binary formats

def macho_dylibs(data):
    """Names of the dynamic libraries a 64-bit little-endian Mach-O loads."""
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, libs = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if size < 8 or off + size > len(data):
            raise Failure("malformed Mach-O load command")
        # LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB
        if cmd in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023):
            name_off = struct.unpack_from("<I", data, off + 8)[0]
            raw = data[off + name_off:off + size]
            libs.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        off += size
    return libs


def elf_needed(data):
    """(needed libraries, required symbol versions) of a 64-bit little-endian ELF."""
    if data[4] != 2 or data[5] != 1:
        raise Failure("only 64-bit little-endian ELF is supported")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    loads, dyn = [], None
    for i in range(phnum):
        p_type, _flags, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
            "<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:
            dyn = (p_offset, p_filesz)
    if dyn is None:
        return [], []  # statically linked

    def at(vaddr):
        for va, fo, sz in loads:
            if va <= vaddr < va + sz:
                return fo + (vaddr - va)
        raise Failure("ELF address outside every loaded segment")

    tags = {}
    needed_offs = []
    for i in range(dyn[1] // 16):
        tag, val = struct.unpack_from("<qQ", data, dyn[0] + i * 16)
        if tag == 0:
            break
        if tag == 1:
            needed_offs.append(val)
        else:
            tags[tag] = val
    if 5 not in tags:
        raise Failure("ELF dynamic section has no string table")
    strtab = at(tags[5])

    def cstr(o):
        end = data.index(b"\0", strtab + o)
        return data[strtab + o:end].decode("utf-8", "replace")

    needed = [cstr(o) for o in needed_offs]
    versions = []
    if 0x6FFFFFFE in tags:  # DT_VERNEED, DT_VERNEEDNUM
        off = at(tags[0x6FFFFFFE])
        for _ in range(tags.get(0x6FFFFFFF, 0)):
            _ver, cnt, _file, aux, nxt = struct.unpack_from("<HHIII", data, off)
            aoff = off + aux
            for _ in range(cnt):
                _hash, _fl, _other, name, anext = struct.unpack_from("<IHHII", data, aoff)
                versions.append(cstr(name))
                if anext == 0:
                    break
                aoff += anext
            if nxt == 0:
                break
            off += nxt
    return needed, versions


def pe_imports(data):
    """Lower-cased DLL names in a PE's import and delay-import tables."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise Failure("not a PE image")
    nsect, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    ddir = opt + (112 if magic == 0x20B else 96)
    sects = []
    for i in range(nsect):
        s = opt + optsize + i * 40
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        sects.append((vaddr, max(vsize, rsize), raw))

    def at(rva):
        for va, sz, raw in sects:
            if va <= rva < va + sz:
                return raw + (rva - va)
        raise Failure("PE address outside every section")

    def name_at(rva):
        o = at(rva)
        return data[o:data.index(b"\0", o)].decode("ascii", "replace").lower()

    names = []
    imp_rva, _ = struct.unpack_from("<II", data, ddir + 1 * 8)
    if imp_rva:
        o = at(imp_rva)
        while True:
            ilt, _t, _f, nm, iat = struct.unpack_from("<IIIII", data, o)
            if not (ilt or nm or iat):
                break
            names.append(name_at(nm))
            o += 20
    delay_rva, _ = struct.unpack_from("<II", data, ddir + 13 * 8)
    if delay_rva:
        o = at(delay_rva)
        while True:
            _attr, nm = struct.unpack_from("<II", data, o)
            if not nm:
                break
            names.append(name_at(nm))
            o += 32
    return names


def check_binary(rel, data, target, fail):
    """Check one executable's imports against its platform's allow-list."""
    kind = None
    if data[:4] == b"\xcf\xfa\xed\xfe":
        kind = "macho"
        for lib in macho_dylibs(data):
            if not MACOS_ALLOWED.match(lib):
                fail(f"{rel}: loads a library outside the macOS system set: {lib}")
    elif data[:4] == b"\x7fELF":
        kind = "elf"
        needed, versions = elf_needed(data)
        for lib in needed:
            if not LINUX_ALLOWED.match(lib):
                fail(f"{rel}: needs a library outside glibc's own: {lib}")
        for v in versions:
            m = re.match(r"^GLIBC_(\d+)\.(\d+)", v)
            if m and (int(m.group(1)), int(m.group(2))) > GLIBC_FLOOR:
                fail(f"{rel}: needs {v}, above the glibc {GLIBC_FLOOR[0]}.{GLIBC_FLOOR[1]} floor")
    elif data[:2] == b"MZ":
        kind = "pe"
        for dll in pe_imports(data):
            if not WINDOWS_ALLOWED.match(dll):
                fail(f"{rel}: imports a DLL outside the Windows system set: {dll}")
    elif data[:4] in (b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe"):
        fail(f"{rel}: a universal or 32-bit Mach-O is not a declared artifact")
    if kind and target:
        want = ("macho" if "apple" in target else "pe" if "windows" in target else "elf")
        # The Windows archive carries the Linux helper beside heimdall.exe (ADR-0014 section 4.2).
        if kind != want and not (want == "pe" and kind == "elf"):
            fail(f"{rel}: a {kind} executable in an archive for {target}")
    return kind


# -------------------------------------------------------------------------- verify

def verify(src, target=None, forbid=(), index=None, allow_exact=()):
    """Return the list of failures for `src` (empty when it passes)."""
    failures = []
    fail = failures.append
    if index is not None:
        if os.path.isdir(src):
            fail("--index checks an archive file, not a directory")
        else:
            want = None
            with open(index, encoding="utf-8") as fh:
                for line in fh.read().splitlines():
                    m = re.match(r"^([0-9a-f]{64})  (\S.*)$", line)
                    if m and m.group(2) == os.path.basename(src):
                        want = m.group(1)
            if want is None:
                fail(f"the archive is not listed in the external index")
            elif want != sha256(src):
                fail(f"the archive's digest differs from the external index")
    with tempfile.TemporaryDirectory(prefix="hm-verify-") as tmp:
        root = unpack(src, tmp)
        files = files_under(root)

        if INDEX in files:
            fail(f"{INDEX} is the external index and must not be inside the archive")
        listed = {}
        if SUMS not in files:
            fail(f"{SUMS} is missing")
        else:
            with open(os.path.join(root, SUMS), encoding="utf-8") as fh:
                for line in fh.read().splitlines():
                    m = re.match(r"^([0-9a-f]{64})  (\S.*)$", line)
                    if not m:
                        fail(f"{SUMS}: malformed line")
                        continue
                    listed[m.group(2)] = m.group(1)
        actual = {f: sha256(os.path.join(root, f)) for f in files if f != SUMS}
        for f, digest in sorted(actual.items()):
            if f not in listed:
                fail(f"{f}: not listed in {SUMS}")
            elif listed[f] != digest:
                fail(f"{f}: digest differs from {SUMS}")
        for f in sorted(set(listed) - set(actual)):
            fail(f"{f}: listed in {SUMS} but absent")

        # Generic rules always scan the real bytes; only the --forbid texts scan the masked
        # copy, so an allowed string can never hide a path, a key block or a canary.
        rules = [(label, rx, False) for label, rx in GENERIC] + [
            (f"forbidden text #{i + 1}", re.compile(re.escape(t.encode("utf-8"))), True)
            for i, t in enumerate(forbid) if t]
        kinds = 0
        executables = set()
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                data = fh.read()
            scanned = data
            for exact in allow_exact:
                raw = exact.encode("utf-8")
                if raw:
                    scanned = scanned.replace(raw, b"\0" * len(raw))
            for label, rx, masked in rules:
                n = len(rx.findall(scanned if masked else data))
                if n:
                    fail(f"{f}: {label}, {n} occurrence(s)")
            try:
                if check_binary(f, data, target, fail):
                    kinds += 1
                    executables.add(f)
            except (Failure, struct.error, ValueError, IndexError) as e:
                fail(f"{f}: executable could not be parsed ({e})")
        if kinds == 0:
            fail("the archive holds no executable")

        if RECORD in files:
            try:
                with open(os.path.join(root, RECORD), encoding="utf-8") as fh:
                    rec = json.load(fh)
            except ValueError:
                rec = None
                fail(f"{RECORD}: not JSON")
            if rec is not None:
                if target and rec.get("target") != target:
                    fail(f"{RECORD}: target is not {target}")
                outs = rec.get("outputs") or []
                for out in outs:
                    if actual.get(out.get("path")) != out.get("sha256"):
                        fail(f"{RECORD}: digest of {out.get('path')} differs from the file")
                if {o.get("path") for o in outs} != executables:
                    fail(f"{RECORD}: its outputs are not exactly the archive's executables")
    return failures


# ----------------------------------------------------------------------- self-test

def _elf(needed, version=None):
    """A minimal ELF64 with one PT_LOAD and a PT_DYNAMIC naming `needed`."""
    strtab = b"\0"
    offs = []
    for n in needed:
        offs.append(len(strtab))
        strtab += n.encode() + b"\0"
    ver_name = None
    if version:
        ver_name = len(strtab)
        strtab += version.encode() + b"\0"
    base = 64 + 2 * 56
    dyn_entries = [(1, o) for o in offs]
    str_off = base + 16 * (len(dyn_entries) + (4 if version else 2))
    dyn_entries.append((5, str_off))
    verneed = b""
    if version:
        vn_off = str_off + len(strtab)
        dyn_entries += [(0x6FFFFFFE, vn_off), (0x6FFFFFFF, 1)]
        verneed = struct.pack("<HHIII", 1, 1, 0, 16, 0) + struct.pack("<IHHII", 0, 0, 2, ver_name, 0)
    dyn_entries.append((0, 0))
    dyn = b"".join(struct.pack("<qQ", t, v) for t, v in dyn_entries)
    body = dyn + strtab + verneed
    total = base + len(body)
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    hdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)
    dynp = struct.pack("<IIQQQQQQ", 2, 6, base, base, base, len(dyn), len(dyn), 8)
    return hdr + load + dynp + body


def _tree(tmp, name, files, sums=True, tamper=None):
    root = os.path.join(tmp, name, "heimdall-0.0.0-test")
    os.makedirs(root)
    for rel, data in files.items():
        with open(os.path.join(root, rel), "wb") as fh:
            fh.write(data)
    if sums:
        lines = [f"{sha256(os.path.join(root, r))}  {r}" for r in sorted(files)]
        if tamper:
            lines = [l for l in lines if not l.endswith("  " + tamper)] + [f"{'0' * 64}  {tamper}"]
        with open(os.path.join(root, SUMS), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    return root


def self_test():
    """Each known-bad fixture must fail for its own reason, and the good one must pass."""
    good = _elf(["libc.so.6", "libm.so.6"], "GLIBC_2.17")
    home = b"/Users/" + b"builder" + b"/.cargo/registry/src/x/lib.rs"
    canary = b"HEIMDALL_CANARY_" + b"AGENT_" + b"0123abcd4567ef89"
    key = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    cases = [
        ("good", {"heimdall": good, "README": b"ok\n"}, {}, None),
        ("bare canary marker is allowed", {"heimdall": good + b"HEIMDALL_CANARY_\0x"}, {}, None),
        ("home path", {"heimdall": good + home}, {}, "cargo registry path"),
        ("canary", {"heimdall": good, "notes.txt": canary}, {}, "canary value"),
        ("private key", {"heimdall": good, "k": key}, {}, "private key block"),
        ("forbidden text", {"heimdall": good + b"xx-builder-name-xx"}, {"forbid": ["builder-name"]},
         "forbidden text #1"),
        ("forbidden text inside an allowed exact string passes",
         {"heimdall": good + b"\0io.example.builder-name.label.\0"},
         {"forbid": ["builder-name"], "allow": ["io.example.builder-name.label."]}, None),
        ("the same text elsewhere still fails",
         {"heimdall": good + b"\0io.example.builder-name.label.\0/x/builder-name/y"},
         {"forbid": ["builder-name"], "allow": ["io.example.builder-name.label."]}, "forbidden text #1"),
        ("a near miss of the allowed string still fails",
         {"heimdall": good + b"\0io.example.builder-name.other\0"},
         {"forbid": ["builder-name"], "allow": ["io.example.builder-name.label."]}, "forbidden text #1"),
        ("an allowed string does not mask a generic rule",
         {"heimdall": good + home}, {"allow": ["/.cargo/"]}, "home directory path"),
        ("extra library", {"heimdall": _elf(["libc.so.6", "libssl.so.3"])}, {}, "libssl.so.3"),
        ("glibc above the floor", {"heimdall": _elf(["libc.so.6"], "GLIBC_2.38")}, {}, "GLIBC_2.38"),
        ("no executable", {"README": b"ok\n"}, {}, "no executable"),
        ("digest mismatch", {"heimdall": good}, {"tamper": "heimdall"}, "digest differs"),
        ("wrong platform", {"heimdall": good}, {"target": "aarch64-apple-darwin"}, "elf executable"),
    ]
    bad = 0
    with tempfile.TemporaryDirectory(prefix="hm-verify-selftest-") as tmp:
        for i, (name, files, opt, expect) in enumerate(cases):
            root = _tree(tmp, f"c{i}", files, tamper=opt.get("tamper"))
            got = verify(root, target=opt.get("target"), forbid=opt.get("forbid", ()),
                         allow_exact=opt.get("allow", ()))
            ok = (not got) if expect is None else any(expect in g for g in got)
            if not ok:
                bad += 1
                print(f"self-test FAILED: {name}: {got}")
        # An unlisted file, and no SHA256SUMS at all.
        root = _tree(tmp, "unlisted", {"heimdall": good})
        with open(os.path.join(root, "extra"), "wb") as fh:
            fh.write(b"x")
        if not any("not listed" in g for g in verify(root)):
            bad += 1
            print("self-test FAILED: unlisted file")
        root = _tree(tmp, "nosums", {"heimdall": good}, sums=False)
        if not any("is missing" in g for g in verify(root)):
            bad += 1
            print("self-test FAILED: missing manifest")
        # The external index inside an archive, and a build record naming a non-executable.
        root = _tree(tmp, "index-inside", {"heimdall": good, INDEX: b"x\n"})
        if not any("must not be inside" in g for g in verify(root)):
            bad += 1
            print("self-test FAILED: external index inside the archive")
        rec = json.dumps({"target": "x86_64-unknown-linux-gnu", "outputs": [
            {"path": "heimdall", "sha256": hashlib.sha256(good).hexdigest()},
            {"path": "README", "sha256": hashlib.sha256(b"ok\n").hexdigest()}]}).encode()
        root = _tree(tmp, "record", {"heimdall": good, "README": b"ok\n", RECORD: rec})
        if not any("not exactly the archive's executables" in g for g in verify(root)):
            bad += 1
            print("self-test FAILED: build record listing a non-executable")
        # An archive checked against an external index: listed, tampered, absent.
        import shutil
        root = _tree(tmp, "packed", {"heimdall": good})
        arc = shutil.make_archive(os.path.join(tmp, "heimdall-0.0.0-test"), "gztar",
                                  os.path.dirname(root), os.path.basename(root))
        idx = os.path.join(tmp, "IDX")
        for label, line, expect in (
                ("listed", f"{sha256(arc)}  {os.path.basename(arc)}\n", None),
                ("tampered", f"{'0' * 64}  {os.path.basename(arc)}\n", "differs from the external index"),
                ("absent", f"{sha256(arc)}  other.tar.gz\n", "not listed in the external index")):
            with open(idx, "w", encoding="utf-8") as fh:
                fh.write(line)
            got = verify(arc, index=idx)
            if (not got) != (expect is None) or (expect and not any(expect in g for g in got)):
                bad += 1
                print(f"self-test FAILED: external index, {label}: {got}")
        # A tar member that leaves the root is refused before extraction.
        evil = os.path.join(tmp, "evil.tar.gz")
        with tarfile.open(evil, "w:gz") as tar:
            info = tarfile.TarInfo("../escape")
            info.size = 0
            tar.addfile(info)
        try:
            verify(evil)
            bad += 1
            print("self-test FAILED: escaping tar member accepted")
        except Failure:
            pass
        if os.path.exists(os.path.join(os.path.dirname(tmp), "escape")):
            bad += 1
            print("self-test FAILED: escaping tar member written")
    print(f"verify_artifact self-test: {len(cases) + 8} cases, {bad} failed")
    return 1 if bad else 0


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    src, target, forbid, index, allow = None, None, [], None, []
    it = iter(argv)
    try:
        for a in it:
            if a == "--target":
                target = next(it)
            elif a == "--index":
                index = next(it)
            elif a == "--allow-exact":
                allow.append(next(it))
            elif a == "--forbid":
                forbid.append(next(it))
            elif a == "--forbid-file":
                with open(next(it), encoding="utf-8") as fh:
                    forbid += [l for l in fh.read().splitlines() if l]
            elif a.startswith("-"):
                raise Failure(f"unknown option {a}")
            elif src is None:
                src = a
            else:
                raise Failure("one archive at a time")
        if src is None:
            raise Failure("no archive given")
        failures = verify(src, target, forbid, index, allow)
    except StopIteration:
        print("verify_artifact: an option is missing its value")
        return 2
    except (Failure, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        print(f"verify_artifact: cannot examine the archive: {e}")
        return 2
    for f in failures:
        print(f"FAIL {f}")
    print(f"verify_artifact: {'PASS' if not failures else 'FAIL'} ({len(failures)} failure(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
