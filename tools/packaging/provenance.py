"""Dependency inventory, licence notices, build record, manifests and archive packing for a
Heimdall release artifact (m08-plan U4a; ADR-0014 sections 4.2, 4.4 and 4.5).

Usage (`build-release.sh` calls these in this order):
    provenance.py sbom         --target T [--features F] --commit C --time ISO --tool PATH
                               [--build-messages FILE] --out FILE
    provenance.py notices      --target T [--features F] --out FILE
    provenance.py build-record --target T [--features F] --commit C --time ISO --clean yes|no
                               --flags TEXT --started ISO --finished ISO --stage DIR --out FILE
    provenance.py manifest     --stage DIR          (writes DIR/MANIFEST.sha256, excluding itself)
    provenance.py pack         --stage DIR --time ISO --out FILE.tar.gz|FILE.zip
    provenance.py index        --dir DIR            (writes DIR/SHA256SUMS over archives and records)
    provenance.py self-test

**The inventory is the graph cargo selects for one package, target and feature set**
(`cargo tree -p heimdall --target T --features F --edges normal,build`), never the lock file
and never a workspace-wide resolution (review M08-D-R04). `sbom` runs the pinned SBOM tool
(cargo-cyclonedx, version `CYCLONEDX_VERSION`) and then acts as its **validation adapter**:
  * a component the selected graph lacks is removed and counted (the tool resolves features
    for the whole workspace and over-reports);
  * a selected package the tool missed is a failure;
  * with --build-messages (the release build's `--message-format=json` output), the packages
    the build compiled must equal the selected set;
  * each component gets one role: `target` (compiled for the target; nothing is claimed about
    what the linker kept), `host` (a proc macro, a build script or a dependency of one) or
    `test-support` (reached only through heimdall-testkit);
  * build-host paths in the tool's references are replaced, the serial number is derived
    from the commit and target, and the bundled SQLite is added.
`cargo metadata` is used only to look up a selected package's source directory and licence.

Exit code 0 on success; 1 when the inventory is refused (a missing or unselected-only
package, a crate with no licence or licence text, a source outside crates.io and the
repository, a tool of another version); 2 on a usage or setup error. Nothing written holds a
build-host path, a user name or a host name. Standard library only.
"""
import gzip
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile

ROOT_CRATE = "heimdall"
TEST_KIT = "heimdall-testkit"
CYCLONEDX_VERSION = "0.5.10"
MANIFEST = "MANIFEST.sha256"
INDEX = "SHA256SUMS"
RECORD = "BUILD-RECORD.json"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LICENCE_NAMES = re.compile(r"^(licen[sc]e|copying|copyright|unlicense|notice)([-_.].*)?$", re.I)
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


class Refused(Exception):
    """The inventory cannot be produced truthfully."""


def run(cmd, cwd=None, env=None):
    out = subprocess.run(cmd, cwd=cwd or REPO, env=env, capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise Refused(f"{os.path.basename(cmd[0])} {cmd[1] if len(cmd) > 1 else ''} failed (exit {out.returncode})")
    return out.stdout


# ------------------------------------------------------------------------ selection

def tree(target, features, edges, offline, extra=()):
    cmd = ["cargo", "tree", "--locked", "-p", ROOT_CRATE, "--target", target, "--edges", edges,
           "--prefix", "depth", "--no-dedupe", "--format", "{p}"]
    if offline:
        cmd.append("--offline")
    if features:
        cmd += ["--features", features]
    return run(cmd + list(extra))


TREE_LINE = re.compile(r"^(\d+)(\S+) v(\S+)( \(proc-macro\))?( \(.*\))?$")


def parse_tree(text):
    """[(depth, name, version, is_proc_macro, is_path)] from `cargo tree --prefix depth`."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = TREE_LINE.match(line.replace(" (*)", ""))
        if not m:
            raise Refused("unexpected cargo tree line")
        rows.append((int(m.group(1)), m.group(2), m.group(3), bool(m.group(4)), bool(m.group(5))))
    return rows


def classify(all_rows, normal_rows, pruned_rows):
    """{(name, version): role} for the selected graph, the root excluded.

    `all_rows`: normal and build edges. `normal_rows`: normal edges only; whatever is reached
    there without passing through a proc macro is compiled for the target. `pruned_rows`:
    normal and build edges with the test kit pruned.
    """
    selected = {(n, v) for _, n, v, _, _ in all_rows}
    target, skip = set(), None
    for depth, n, v, pm, _ in normal_rows:
        if skip is not None and depth > skip:
            continue
        skip = None
        if pm:
            skip = depth
            continue
        target.add((n, v))
    without_kit = {(n, v) for _, n, v, _, _ in pruned_rows}
    roles = {}
    root = (all_rows[0][1], all_rows[0][2])
    for key in selected - {root}:
        if key not in without_kit:
            roles[key] = "test-support"
        elif key in target:
            roles[key] = "target"
        else:
            roles[key] = "host"
    return root, roles


def selection(target, features, offline):
    all_rows = parse_tree(tree(target, features, "normal,build", offline))
    normal_rows = parse_tree(tree(target, features, "normal", offline))
    pruned_rows = parse_tree(tree(target, features, "normal,build", offline, ("--prune", TEST_KIT)))
    return classify(all_rows, normal_rows, pruned_rows)


def cargo_metadata(target, features, offline):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target]
    if offline:
        cmd.append("--offline")
    if features:
        cmd += ["--features", features]
    cwd = os.path.join(REPO, "crates", ROOT_CRATE) if features else REPO
    return json.loads(run(cmd, cwd=cwd))


def lookup(meta, roles, repo=None):
    """Attach the metadata package to every selected key. Returns ordered components."""
    repo = repo or REPO
    by_key = {}
    for p in meta["packages"]:
        by_key.setdefault((p["name"], p["version"]), p)
    comps = []
    for key in sorted(roles):
        p = by_key.get(key)
        if p is None:
            raise Refused(f"{key[0]} {key[1]}: selected by cargo tree but unknown to cargo metadata")
        src = p["source"]
        if src is None:
            rel = os.path.relpath(os.path.dirname(p["manifest_path"]), repo).replace(os.sep, "/")
            if rel.startswith("../"):
                raise Refused(f"{p['name']}: a path dependency outside the repository")
            origin = "vendored" if rel.startswith("third_party/") else "workspace"
        elif src.startswith(CRATES_IO):
            rel, origin = None, "crates.io"
        else:
            raise Refused(f"{p['name']} {p['version']}: source is neither crates.io nor this repository")
        comps.append({"pkg": p, "origin": origin, "path": rel, "role": roles[key]})
    return comps


def lock_checksums(path):
    """{(name, version): sha256} from Cargo.lock, without a TOML library."""
    sums, cur = {}, {}
    with open(path, encoding="utf-8") as fh:
        for line in fh.read().splitlines() + ["[[package]]"]:
            if line.strip() == "[[package]]":
                if "name" in cur and "checksum" in cur:
                    sums[(cur["name"], cur.get("version", ""))] = cur["checksum"]
                cur = {}
                continue
            m = re.match(r'^(name|version|checksum) = "([^"]*)"$', line)
            if m:
                cur[m.group(1)] = m.group(2)
    return sums


def spdx(expr):
    """Cargo's legacy `A/B` means `A OR B`."""
    return re.sub(r"\s*/\s*", " OR ", expr.strip()) if expr else None


def purl(name, version):
    return f"pkg:cargo/{name}@{version}"


def compiled_packages(messages_path, meta):
    """{(name, version)} of the packages a `cargo build --message-format=json` run compiled.

    Read strictly, because a line skipped here is a package missing from the comparison with
    the selected graph (PC job 34: Windows PowerShell 5.1 wrote the file with a UTF-8 byte
    order mark, the first line no longer started with `{`, and `cfg-if` vanished silently).
    A leading byte order mark is accepted; every other non-blank line must be one JSON object,
    and the file must end with cargo's `build-finished` message reporting success. Anything
    else is refused with the line number, never skipped."""
    by_manifest = {p["manifest_path"]: (p["name"], p["version"]) for p in meta["packages"]}
    seen = set()
    finished = False
    with open(messages_path, encoding="utf-8-sig") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            if not line.startswith("{"):
                raise Refused(f"the build messages are malformed at line {number}: not a JSON object")
            try:
                msg = json.loads(line)
            except ValueError:
                raise Refused(f"the build messages are malformed at line {number}: not valid JSON") from None
            if not isinstance(msg, dict):
                raise Refused(f"the build messages are malformed at line {number}: not a JSON object")
            if finished:
                raise Refused(f"the build messages continue after build-finished, at line {number}")
            if msg.get("reason") == "compiler-artifact":
                key = by_manifest.get(msg.get("manifest_path"))
                if key is None:
                    raise Refused("the build compiled a package cargo metadata does not know")
                seen.add(key)
            elif msg.get("reason") == "build-finished":
                if msg.get("success") is not True:
                    raise Refused("the build messages record a failed build")
                finished = True
    if not finished:
        raise Refused("the build messages have no successful build-finished message (cut short?)")
    return seen


# ----------------------------------------------------------------------------- sbom

def run_tool(tool, target, features, time):
    """Run the pinned cargo-cyclonedx for the binary and return its document. The tool writes
    beside each manifest; every file it creates is removed again."""
    tool = os.path.abspath(tool)
    version = run([tool, "cyclonedx", "--version"]).strip()
    if version.split()[-1:] != [CYCLONEDX_VERSION]:
        raise Refused(f"the SBOM tool is not cargo-cyclonedx {CYCLONEDX_VERSION}")
    before = set(_tool_outputs())
    cmd = [tool, "cyclonedx", "--manifest-path", "Cargo.toml", "-f", "json", "--describe", "binaries",
           "--target", target, "--spec-version", "1.5", "-qq"]
    if features:
        cmd += ["--features", features]
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch(time)))
    made = os.path.join(REPO, "crates", ROOT_CRATE, ROOT_CRATE + TOOL_SUFFIX)
    if made in before:
        raise Refused("an SBOM file from an earlier run is in the source tree; remove it first")
    try:
        run(cmd, cwd=os.path.join(REPO, "crates", ROOT_CRATE), env=env)
        with open(made, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        for f in set(_tool_outputs()) - before:
            os.remove(f)


TOOL_SUFFIX = "_bin.cdx.json"


def _tool_outputs():
    """The files cargo-cyclonedx writes: one per binary, beside each package's manifest."""
    out = []
    for base in ("crates", "third_party"):
        root = os.path.join(REPO, base)
        if not os.path.isdir(root):
            continue
        for d in sorted(os.listdir(root)):
            sub = os.path.join(root, d)
            if os.path.isdir(sub):
                out += [os.path.join(sub, f) for f in sorted(os.listdir(sub)) if f.endswith(TOOL_SUFFIX)]
    return out


def sqlite_component(comps):
    """The SQLite amalgamation bundled by libsqlite3-sys, when its header is present."""
    for c in comps:
        if c["pkg"]["name"] != "libsqlite3-sys":
            continue
        header = os.path.join(os.path.dirname(c["pkg"]["manifest_path"]), "sqlite3", "sqlite3.h")
        try:
            with open(header, encoding="utf-8", errors="replace") as fh:
                m = re.search(r'#define SQLITE_VERSION\s+"([0-9.]+)"', fh.read(200000))
        except OSError:
            return None
        if m:
            ref = f"pkg:generic/sqlite@{m.group(1)}"
            return {"type": "library", "bom-ref": ref, "name": "sqlite", "version": m.group(1), "purl": ref,
                    "licenses": [{"license": {"name": "Public Domain (SQLite blessing)"}}],
                    "properties": [{"name": "heimdall:role", "value": "target"},
                                   {"name": "heimdall:origin", "value": "bundled by libsqlite3-sys"}]}
    return None


def adapt(doc, root, comps, sums, target, features, commit, time, compiled=None):
    """Validate the tool's document against the selected graph and rewrite it."""
    selected = {(c["pkg"]["name"], c["pkg"]["version"]): c for c in comps}
    by_ref, kept, dropped = {}, {}, []
    for tc in doc.get("components", []):
        key = (tc.get("name"), tc.get("version"))
        if key in selected:
            kept[key] = tc
            by_ref[tc.get("bom-ref")] = purl(*key)
        elif key != root:
            dropped.append(f"{key[0]} {key[1]}")
            by_ref[tc.get("bom-ref")] = None
    missing = sorted(f"{n} {v}" for n, v in set(selected) - set(kept))
    if missing:
        raise Refused("the SBOM tool did not report selected packages: " + ", ".join(missing))
    if compiled is not None:
        want = set(selected) | {root}
        if compiled != want:
            extra = sorted(f"{n} {v}" for n, v in compiled - want)
            lack = sorted(f"{n} {v}" for n, v in want - compiled)
            raise Refused(f"the build's compiled packages differ from the selected graph "
                          f"(compiled only: {extra}; selected only: {lack})")
    out = []
    for key in sorted(selected):
        c, tc, p = selected[key], kept[key], selected[key]["pkg"]
        entry = {"type": "library", "bom-ref": purl(*key), "name": key[0], "version": key[1],
                 "purl": purl(*key)}
        lic = spdx(p.get("license"))
        if c["origin"] == "crates.io":
            if not lic:
                raise Refused(f"{key[0]} {key[1]}: no licence field")
            if key not in sums:
                raise Refused(f"{key[0]} {key[1]}: no checksum in Cargo.lock")
            entry["licenses"] = [{"expression": lic}]
            entry["hashes"] = [{"alg": "SHA-256", "content": sums[key]}]
        elif tc.get("licenses"):
            entry["licenses"] = tc["licenses"]
        entry["scope"] = "required" if c["role"] == "target" else "excluded"
        entry["properties"] = [{"name": "heimdall:role", "value": c["role"]},
                               {"name": "heimdall:origin", "value": c["origin"]}]
        if c["path"]:
            entry["properties"].append({"name": "heimdall:path", "value": c["path"]})
        out.append(entry)
    sqlite = sqlite_component(comps)
    if sqlite:
        out.append(sqlite)
    root_ref = purl(*root)
    by_ref[(doc.get("metadata", {}).get("component") or {}).get("bom-ref")] = root_ref
    deps = {}
    for d in doc.get("dependencies", []):
        ref = by_ref.get(d.get("ref"))
        if ref is None:
            continue
        on = sorted({by_ref[x] for x in d.get("dependsOn", []) if by_ref.get(x)})
        deps[ref] = sorted(set(deps.get(ref, [])) | set(on))
    if sqlite:
        for ref in deps:
            if ref.startswith("pkg:cargo/libsqlite3-sys@"):
                deps[ref] = sorted(set(deps[ref]) | {sqlite["bom-ref"]})
    counts = {}
    for c in comps:
        counts[c["role"]] = counts.get(c["role"], 0) + 1
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"heimdall:{commit}:{target}:{features or 'default'}")),
        "metadata": {
            "timestamp": time,
            "tools": [{"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": CYCLONEDX_VERSION},
                      {"name": "heimdall tools/packaging/provenance.py (validation adapter)"}],
            "component": {"type": "application", "bom-ref": root_ref, "name": root[0],
                          "version": root[1], "purl": root_ref},
            "properties": [
                {"name": "heimdall:target", "value": target},
                {"name": "heimdall:features", "value": features or "default"},
                {"name": "heimdall:commit", "value": commit},
                {"name": "heimdall:inventory",
                 "value": "cargo's selected graph for this package, target and feature set; normal and build edges"},
                {"name": "heimdall:roles",
                 "value": "target = compiled for the target (linker retention not claimed); host = proc macro, "
                          "build script or a dependency of one; test-support = reached only through heimdall-testkit"},
                {"name": "heimdall:role-counts", "value": json.dumps(counts, sort_keys=True)},
                {"name": "heimdall:removed-as-unselected", "value": str(len(dropped))},
                {"name": "heimdall:compiled-set-checked", "value": "yes" if compiled is not None else "no"}]},
        "components": out,
        "dependencies": [{"ref": r, "dependsOn": d} for r, d in sorted(deps.items())],
    }, sorted(dropped)


# -------------------------------------------------------------------------- notices

def licence_files(pkg):
    base = os.path.dirname(pkg["manifest_path"])
    found = []
    try:
        names = sorted(os.listdir(base))
    except OSError:
        names = []
    for n in names:
        full = os.path.join(base, n)
        if LICENCE_NAMES.match(n) and os.path.isfile(full) and not os.path.islink(full):
            found.append(full)
    lf = pkg.get("license_file")
    if lf:
        full = os.path.normpath(os.path.join(base, lf))
        if os.path.isfile(full) and full not in found:
            found.append(full)
    return found


ROLE_NOTE = {"target": "", "host": " [build-time only: runs on the build machine]",
             "test-support": " [test support: built, not referenced by a release build]"}


def make_notices(root, comps, target, features):
    texts, missing, lines = {}, [], []
    for c in comps:
        p = c["pkg"]
        if c["origin"] == "workspace":
            continue
        files = licence_files(p)
        if not files:
            missing.append(f"{p['name']} {p['version']}")
            continue
        for f in files:
            with open(f, "rb") as fh:
                body = fh.read().decode("utf-8", "replace").replace("\r\n", "\n").strip() + "\n"
            key = hashlib.sha256(body.encode("utf-8")).hexdigest()
            texts.setdefault(key, {"body": body, "users": []})
            texts[key]["users"].append(f"{p['name']} {p['version']} ({os.path.basename(f)})")
    if missing:
        raise Refused("no licence text in the crate source for: " + ", ".join(missing))
    lines.append(f"Third-party notices for {root[0]} {root[1]} ({target}, features: {features or 'default'})")
    lines.append("")
    lines.append("Every third-party component in the build graph cargo selects for this artifact,")
    lines.append("with its declared licence, followed by the licence texts found in each")
    lines.append("component's source.")
    lines.append("")
    lines.append("== Components ==")
    for c in comps:
        if c["origin"] == "workspace":
            continue
        p = c["pkg"]
        lines.append(f"{p['name']} {p['version']} - {spdx(p.get('license')) or 'see text'}"
                     f" - {c['origin']}{ROLE_NOTE[c['role']]}")
    sqlite = sqlite_component(comps)
    if sqlite:
        lines.append(f"sqlite {sqlite['version']} - public domain - bundled by libsqlite3-sys")
    lines.append("")
    lines.append("== Licence texts ==")
    for key in sorted(texts, key=lambda k: sorted(texts[k]["users"])[0]):
        t = texts[key]
        lines.append("")
        lines.append("-" * 78)
        lines.append("Applies to: " + "; ".join(sorted(t["users"])))
        lines.append("-" * 78)
        lines.append(t["body"].rstrip("\n"))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------ records and manifests

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_files(stage):
    out = []
    for base, dirs, names in os.walk(stage):
        dirs.sort()
        for n in sorted(names):
            full = os.path.join(base, n)
            if os.path.islink(full) or not os.path.isfile(full):
                raise Refused("the stage holds something that is not a regular file")
            out.append(os.path.relpath(full, stage).replace(os.sep, "/"))
    return out


def is_executable_image(path):
    with open(path, "rb") as fh:
        magic = fh.read(4)
    return magic in (b"\x7fELF", b"\xcf\xfa\xed\xfe") or magic[:2] == b"MZ"


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip().splitlines()[0] if out.returncode == 0 and out.stdout.strip() else None


def builder_os():
    """Operating system and version only: no host name, no user name."""
    system = platform.system()
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]} {platform.machine()}"
    if system == "Windows":
        return f"Windows {platform.version()} {platform.machine()}"
    return f"{system} {platform.release()} {platform.machine()}"


def toolchain_record(run=subprocess.run):
    """The compiler and cargo that built the executables. A build record with no toolchain
    describes nothing, so a host without `rustc` or `cargo` is refused by name."""
    got = {}
    for tool, args in (("rustc", ["-Vv"]), ("cargo", ["-V"])):
        try:
            out = run([tool] + args, capture_output=True, text=True, check=False, timeout=30)
        except FileNotFoundError:
            raise Refused(f"{tool} was not found on PATH: a build record needs the toolchain "
                          "that built the executables") from None
        except (OSError, subprocess.TimeoutExpired) as e:
            raise Refused(f"{tool} could not be run ({type(e).__name__})") from None
        if out.returncode != 0 or not out.stdout.strip():
            raise Refused(f"{tool} {' '.join(args)} failed (exit {out.returncode})")
        got[tool] = out.stdout
    return {"rustc": dict(l.split(": ", 1) for l in got["rustc"].splitlines() if ": " in l),
            "cargo": got["cargo"].strip().splitlines()[0]}


def make_record(a):
    """The build inputs and the digests of the executables only (ADR-0014 section 4.4): no
    digest of the record itself, of the manifest or of the archive."""
    stage = a["stage"]
    outputs = [{"path": f, "sha256": sha256(os.path.join(stage, f)),
                "size": os.path.getsize(os.path.join(stage, f))}
               for f in stage_files(stage) if is_executable_image(os.path.join(stage, f))]
    if not outputs:
        raise Refused("the stage holds no executable")
    toolchain = a.get("toolchain") or toolchain_record()
    return {
        "schema": "heimdall-build-record/1",
        "commit": a["commit"], "commit_time": a["time"], "tree_clean": a["clean"] == "yes",
        "target": a["target"], "profile": "release", "features": a.get("features") or "default",
        "rustflags": a["flags"],
        "toolchain": toolchain,
        "cargo_lock_sha256": sha256(os.path.join(REPO, "Cargo.lock")),
        "builder_os": builder_os(),
        "tools": {"zig": tool_version(["zig", "version"]), "python": platform.python_version(),
                  "cargo-cyclonedx": CYCLONEDX_VERSION},
        "started_at": a["started"], "finished_at": a["finished"],
        "signature": a.get("signature") or "none",
        "outputs": outputs}


def write_manifest(stage):
    """MANIFEST.sha256: every file in the stage except the manifest itself."""
    lines = [f"{sha256(os.path.join(stage, f))}  {f}" for f in stage_files(stage) if f != MANIFEST]
    with open(os.path.join(stage, MANIFEST), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")


def write_index(directory):
    """SHA256SUMS: the external index over finalized archives and external records. It lists
    regular files directly in `directory`, never itself, and is never packed."""
    names = sorted(n for n in os.listdir(directory)
                   if n != INDEX and os.path.isfile(os.path.join(directory, n))
                   and not os.path.islink(os.path.join(directory, n)))
    if not names:
        raise Refused("nothing to index")
    with open(os.path.join(directory, INDEX), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(f"{sha256(os.path.join(directory, n))}  {n}\n" for n in names))


# ----------------------------------------------------------------------------- pack

def epoch(iso):
    import datetime
    return int(datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def pack(stage, out, time):
    """A deterministic archive: sorted members, one timestamp, no owner names."""
    top = os.path.basename(os.path.normpath(stage))
    files = stage_files(stage)
    if INDEX in files:
        raise Refused(f"{INDEX} is the external index and is never packed")
    mtime = epoch(time)
    if out.endswith(".zip"):
        stamp = __import__("time").gmtime(mtime)[:6]
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                full = os.path.join(stage, f)
                info = zipfile.ZipInfo(f"{top}/{f}", stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if os.access(full, os.X_OK) else 0o644
                info.external_attr = (0o100000 | mode) << 16
                with open(full, "rb") as fh:
                    z.writestr(info, fh.read())
        return
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for f in files:
            full = os.path.join(stage, f)
            info = tarfile.TarInfo(f"{top}/{f}")
            info.size = os.path.getsize(full)
            info.mtime = mtime
            info.mode = 0o755 if os.access(full, os.X_OK) else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with open(full, "rb") as fh:
                tar.addfile(info, fh)
    with open(out, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime) as gz:
        gz.write(buf.getvalue())


# ------------------------------------------------------------------------ self-test

def self_test():
    bad = []

    def check(name, cond):
        if not cond:
            bad.append(name)

    reg = CRATES_IO
    all_tree = "\n".join([
        "0heimdall v0.0.1 (/x/crates/heimdall)", "1linked v1.0.0", "2shared v1.1.0",
        "1derive v2.0.0 (proc-macro)", "2syn v2.1.0", "2shared v1.1.0",
        "1heimdall-testkit v0.0.1 (/x/crates/testkit)", "2kitonly v3.0.0", "2linked v1.0.0 (*)",
        "1buildonly v4.0.0"]) + "\n"
    normal_tree = "\n".join([
        "0heimdall v0.0.1 (/x/crates/heimdall)", "1linked v1.0.0", "2shared v1.1.0",
        "1derive v2.0.0 (proc-macro)", "2syn v2.1.0", "2shared v1.1.0",
        "1heimdall-testkit v0.0.1 (/x/crates/testkit)", "2kitonly v3.0.0", "2linked v1.0.0"]) + "\n"
    pruned_tree = "\n".join([
        "0heimdall v0.0.1 (/x/crates/heimdall)", "1linked v1.0.0", "2shared v1.1.0",
        "1derive v2.0.0 (proc-macro)", "2syn v2.1.0", "2shared v1.1.0", "1buildonly v4.0.0"]) + "\n"
    root, roles = classify(parse_tree(all_tree), parse_tree(normal_tree), parse_tree(pruned_tree))
    check("root", root == ("heimdall", "0.0.1"))
    check("roles", roles == {
        ("linked", "1.0.0"): "target", ("shared", "1.1.0"): "target", ("derive", "2.0.0"): "host",
        ("syn", "2.1.0"): "host", ("buildonly", "4.0.0"): "host",
        ("heimdall-testkit", "0.0.1"): "test-support", ("kitonly", "3.0.0"): "test-support"})
    try:
        parse_tree("garbage line\n")
        check("malformed tree refused", False)
    except Refused:
        pass
    check("legacy licence slash", spdx("MIT/Apache-2.0") == "MIT OR Apache-2.0")

    with tempfile.TemporaryDirectory(prefix="hm-prov-selftest-") as tmp:
        def pkg(name, version, source, lic, sub):
            d = os.path.join(tmp, sub, f"{name}-{version}" if source else name)
            os.makedirs(d, exist_ok=True)
            if source:
                with open(os.path.join(d, "LICENSE-MIT"), "w", encoding="utf-8") as fh:
                    fh.write(f"MIT text for {name}\n")
            return {"name": name, "version": version, "source": source, "license": lic,
                    "license_file": None, "manifest_path": os.path.join(d, "Cargo.toml")}
        meta = {"packages": [
            pkg("heimdall", "0.0.1", None, None, "crates"), pkg("heimdall-testkit", "0.0.1", None, None, "crates"),
            pkg("linked", "1.0.0", reg, "MIT/Apache-2.0", "src"), pkg("shared", "1.1.0", reg, "MIT", "src"),
            pkg("derive", "2.0.0", reg, "MIT", "src"), pkg("syn", "2.1.0", reg, "MIT", "src"),
            pkg("kitonly", "3.0.0", reg, "MIT", "src"), pkg("buildonly", "4.0.0", reg, "MIT", "src"),
            pkg("unselected", "9.0.0", reg, "MIT", "src")]}
        comps = lookup(meta, roles, repo=tmp)
        sums = {(c["pkg"]["name"], c["pkg"]["version"]): "a" * 64 for c in comps}

        def tool_doc(names):
            ref = lambda n, v: f"path+file://{tmp}/x#{n}@{v}"
            return {"metadata": {"component": {"bom-ref": ref("heimdall", "0.0.1"), "name": "heimdall", "version": "0.0.1"}},
                    "components": [{"bom-ref": ref(n, v), "name": n, "version": v} for n, v in names],
                    "dependencies": [{"ref": ref("heimdall", "0.0.1"),
                                      "dependsOn": [ref(n, v) for n, v in names]}]}
        full = sorted(roles) + [("unselected", "9.0.0")]
        args = ("t", None, "0" * 40, "2026-01-01T00:00:00Z")
        bom, dropped = adapt(tool_doc(full), root, comps, sums, *args)
        check("unselected dropped and counted", dropped == ["unselected 9.0.0"])
        check("sbom components", sorted(c["name"] for c in bom["components"]) == sorted(n for n, _ in roles))
        role_of = {c["name"]: c["properties"][0]["value"] for c in bom["components"]}
        check("proc macro is host", role_of["derive"] == "host" and role_of["syn"] == "host")
        check("test support labelled", role_of["kitonly"] == "test-support")
        check("licence normalised", any(c.get("licenses") == [{"expression": "MIT OR Apache-2.0"}] for c in bom["components"]))
        check("no build-host path", tmp not in json.dumps(bom))
        check("deterministic", json.dumps(bom, sort_keys=True) == json.dumps(
            adapt(tool_doc(full), root, comps, sums, *args)[0], sort_keys=True))
        check("dependencies rewritten", bom["dependencies"][0]["ref"] == "pkg:cargo/heimdall@0.0.1"
              and "pkg:cargo/unselected@9.0.0" not in bom["dependencies"][0]["dependsOn"])
        for label, call in [
            ("tool missing a selected package refused",
             lambda: adapt(tool_doc([k for k in full if k[0] != "linked"]), root, comps, sums, *args)),
            ("compiled set differing refused",
             lambda: adapt(tool_doc(full), root, comps, sums, *args, compiled={root, ("linked", "1.0.0")})),
            ("no checksum refused",
             lambda: adapt(tool_doc(full), root, comps, {}, *args)),
        ]:
            try:
                call()
                check(label, False)
            except Refused:
                pass
        ok_compiled = set(roles) | {root}
        check("compiled set equal accepted", adapt(tool_doc(full), root, comps, sums, *args, compiled=ok_compiled)[0] is not None)
        m2 = json.loads(json.dumps(meta))
        m2["packages"][2]["source"] = "git+https://example.invalid/x"
        try:
            lookup(m2, roles, repo=tmp)
            check("git source refused", False)
        except Refused:
            pass
        m3 = json.loads(json.dumps(meta))
        m3["packages"][2]["license"] = None
        try:
            adapt(tool_doc(full), root, lookup(m3, roles, repo=tmp), sums, *args)
            check("no licence field refused", False)
        except Refused:
            pass

        notices = make_notices(root, comps, "t", None)
        check("notices text", "MIT text for linked" in notices and "MIT text for kitonly" in notices)
        check("notices roles", "derive 2.0.0 - MIT - crates.io [build-time only" in notices)
        check("notices carry no build-host path", tmp not in notices)
        os.remove(os.path.join(tmp, "src", "linked-1.0.0", "LICENSE-MIT"))
        try:
            make_notices(root, comps, "t", None)
            check("missing licence text refused", False)
        except Refused:
            pass

        stage = os.path.join(tmp, "stage", "heimdall-0.0.1-t")
        os.makedirs(stage)
        for n, body in (("heimdall", b"\x7fELFx"), ("README", b"hello\n")):
            with open(os.path.join(stage, n), "wb") as fh:
                fh.write(body)
        os.chmod(os.path.join(stage, "heimdall"), 0o755)
        write_manifest(stage)
        with open(os.path.join(stage, MANIFEST), encoding="utf-8") as fh:
            body = fh.read()
        check("manifest excludes itself", body.count("\n") == 2 and MANIFEST not in body)
        write_manifest(stage)
        with open(os.path.join(stage, MANIFEST), encoding="utf-8") as fh:
            check("manifest stable when rewritten", fh.read() == body)
        # A stub toolchain record: the self-test must pass on a host with no Rust toolchain.
        stub = {"rustc": {"release": "0.0.0", "host": "stub"}, "cargo": "cargo 0.0.0 (stub)"}
        rec = make_record({"stage": stage, "commit": "0" * 40, "time": "2026-01-01T00:00:00Z", "clean": "yes",
                           "target": "t", "flags": "f", "started": "s", "finished": "f",
                           "toolchain": stub})
        check("record lists executables only", [o["path"] for o in rec["outputs"]] == ["heimdall"])
        check("record carries the toolchain it was given", rec["toolchain"] == stub)

        # The build messages are read strictly (PC job 34): a byte order mark is accepted, a
        # malformed or cut file is refused by line, never skipped.
        meta = {"packages": [{"manifest_path": "/m/a/Cargo.toml", "name": "a", "version": "1.0.0"},
                             {"manifest_path": "/m/b/Cargo.toml", "name": "b", "version": "2.0.0"}]}
        art = lambda m: json.dumps({"reason": "compiler-artifact", "manifest_path": m})
        done = json.dumps({"reason": "build-finished", "success": True})
        msgs = os.path.join(tmp, "messages.json")

        def compiled(text, encoding="utf-8"):
            with open(msgs, "w", encoding=encoding, newline="") as fh:
                fh.write(text)
            try:
                return compiled_packages(msgs, meta)
            except Refused as e:
                return str(e)
        good = "\n".join([art("/m/a/Cargo.toml"), art("/m/b/Cargo.toml"), done]) + "\n"
        both = {("a", "1.0.0"), ("b", "2.0.0")}
        check("messages: plain", compiled(good) == both)
        check("messages: a byte order mark keeps the first package", compiled(good, "utf-8-sig") == both)
        check("messages: CRLF and blank lines", compiled(good.replace("\n", "\r\n") + "\r\n") == both)
        check("messages: a non-JSON line is refused by number",
              compiled(art("/m/a/Cargo.toml") + "\nwarning: x\n" + done + "\n") ==
              "the build messages are malformed at line 2: not a JSON object")
        check("messages: a broken JSON line is refused by number",
              compiled("{\"reason\": \n" + done + "\n") == "the build messages are malformed at line 1: not valid JSON")
        check("messages: a doubled byte order mark is refused",
              compiled("\ufeff" + good, "utf-8-sig") == "the build messages are malformed at line 1: not a JSON object")
        check("messages: cut before build-finished is refused",
              str(compiled(art("/m/a/Cargo.toml") + "\n")).startswith("the build messages have no successful"))
        check("messages: a failed build is refused",
              compiled(json.dumps({"reason": "build-finished", "success": False}) + "\n") ==
              "the build messages record a failed build")

        def absent(cmd, **_):
            if cmd[0] == "cargo":
                raise FileNotFoundError(cmd[0])
            return subprocess.CompletedProcess(cmd, 0, "rustc 0.0.0\nrelease: 0.0.0\n", "")
        try:
            toolchain_record(absent)
            check("an absent cargo is refused", False)
        except Refused as e:
            check("an absent cargo is refused by name", "cargo was not found on PATH" in str(e))
        try:
            toolchain_record(lambda cmd, **_: subprocess.CompletedProcess(cmd, 1, "", ""))
            check("a failing rustc is refused", False)
        except Refused as e:
            check("a failing rustc is refused by name", str(e).startswith("rustc -Vv failed"))
        a, b = os.path.join(tmp, "out", "a.tar.gz"), os.path.join(tmp, "out", "b.tar.gz")
        os.makedirs(os.path.dirname(a))
        pack(stage, a, "2026-01-01T00:00:00Z")
        os.utime(os.path.join(stage, "README"), (1, 1))
        pack(stage, b, "2026-01-01T00:00:00Z")
        check("pack deterministic", sha256(a) == sha256(b))
        with tarfile.open(a) as tar:
            members = tar.getmembers()
        check("pack layout", sorted(m.name for m in members) == [
            "heimdall-0.0.1-t/MANIFEST.sha256", "heimdall-0.0.1-t/README", "heimdall-0.0.1-t/heimdall"])
        check("pack no owner", all(m.uid == 0 and m.uname == "" for m in members))
        write_index(os.path.dirname(a))
        with open(os.path.join(os.path.dirname(a), INDEX), encoding="utf-8") as fh:
            idx = fh.read()
        check("index covers archives, not itself", idx.count("\n") == 2 and INDEX not in idx)
        with open(os.path.join(stage, INDEX), "w", encoding="utf-8") as fh:
            fh.write("x\n")
        try:
            pack(stage, os.path.join(tmp, "c.tar.gz"), "2026-01-01T00:00:00Z")
            check("index never packed", False)
        except Refused:
            pass
        os.remove(os.path.join(stage, INDEX))
        z = os.path.join(tmp, "a.zip")
        pack(stage, z, "2026-01-01T00:00:00Z")
        with zipfile.ZipFile(z) as zf:
            check("zip layout", len(zf.namelist()) == 3)
    for b_ in bad:
        print(f"self-test FAILED: {b_}")
    print(f"provenance self-test: {len(bad)} failed")
    return 1 if bad else 0


# ------------------------------------------------------------------------------ cli

def parse(argv):
    opts, it = {}, iter(argv)
    for a in it:
        if a == "--offline":
            opts["offline"] = True
        elif a.startswith("--"):
            try:
                opts[a[2:].replace("-", "_")] = next(it)
            except StopIteration:
                raise SystemExit(f"provenance: {a} is missing its value")
        else:
            raise SystemExit(f"provenance: unexpected argument {a}")
    return opts


def need(opts, *keys):
    for k in keys:
        if k not in opts:
            raise SystemExit(f"provenance: --{k.replace('_', '-')} is required")


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, opts = argv[0], parse(argv[1:])
    try:
        if cmd == "self-test":
            return self_test()
        if cmd in ("sbom", "notices"):
            need(opts, "target", "out")
            target, features, offline = opts["target"], opts.get("features"), opts.get("offline")
            root, roles = selection(target, features, offline)
            meta = cargo_metadata(target, features, offline)
            comps = lookup(meta, roles)
            if cmd == "sbom":
                need(opts, "commit", "time", "tool")
                compiled = compiled_packages(opts["build_messages"], meta) if "build_messages" in opts else None
                doc, dropped = adapt(run_tool(opts["tool"], target, features, opts["time"]), root, comps,
                                     lock_checksums(os.path.join(REPO, "Cargo.lock")), target, features,
                                     opts["commit"], opts["time"], compiled)
                text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
                print(f"provenance: sbom for {target}: {len(doc['components'])} components; "
                      f"{len(dropped)} removed as unselected; compiled set checked: "
                      f"{'yes' if compiled is not None else 'no'}")
            else:
                text = make_notices(root, comps, target, features)
        elif cmd == "build-record":
            need(opts, "target", "commit", "time", "clean", "flags", "started", "finished", "stage", "out")
            text = json.dumps(make_record(opts), indent=1, sort_keys=True) + "\n"
        elif cmd == "manifest":
            need(opts, "stage")
            write_manifest(opts["stage"])
            return 0
        elif cmd == "index":
            need(opts, "dir")
            write_index(opts["dir"])
            return 0
        elif cmd == "pack":
            need(opts, "stage", "time", "out")
            pack(opts["stage"], opts["out"], opts["time"])
            return 0
        else:
            print(f"provenance: unknown subcommand {cmd}")
            return 2
        with open(opts["out"], "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return 0
    except Refused as e:
        print(f"provenance: refused: {e}")
        return 1
    except OSError as e:
        print(f"provenance: {e.strerror or 'I/O error'}")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
