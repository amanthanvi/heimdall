#!/usr/bin/env python3
"""Workspace crate-graph check (m03-plan section 0.6; ADR-0008 section 18, revision 3).

Usage (from anywhere; stdlib only, Python 3.11+ for tomllib):

    python3 -I tools/validation/crate_graph.py               # the real workspace, then the self-tests
    python3 -I tools/validation/crate_graph.py --self-test   # the self-tests only
    python3 -I tools/validation/crate_graph.py --root DIR    # a workspace at DIR, no self-tests

Exit code: 0 only when every check passes; 1 on a violation or a failed self-test;
2 on a usage error or an unreadable manifest.

What it reads. Every workspace member manifest listed in the root `Cargo.toml`
`[workspace] members` (a trailing `*` glob is expanded; `exclude` is honoured).
Dependency keys are resolved to **package names**: a key may differ from the package
name through `package = "..."`, and `{ workspace = true }` entries resolve through
`[workspace.dependencies]` (whose own entries may carry `path` and `package`). A
`path` entry resolves to the package name of the manifest it points at. Production
edges are `[dependencies]`, every `[target.'cfg(...)'.dependencies]` table (all
targets) and optional dependencies (features included). `[dev-dependencies]` and
`[build-dependencies]` are ignored: a dev-dependency cycle through `heimdall-testkit`
is allowed (Cargo allows it, and `heimdall-ipc` already has one).

What it rejects (exit 1, with the reason):
  * any production cycle among workspace crates;
  * an edge `heimdall-app` -> {heimdall-credential, heimdall-issuer, heimdall-enroll,
    heimdall-adapters, heimdall-localenv, heimdall-runtime};
  * an edge `heimdall-ipc` -> any workspace crate but `heimdall-contract`
    (third-party dependencies are fine);
  * an edge `heimdall-registry` -> any workspace crate but `heimdall-contract` and
    `heimdall-domain` (the registry is pure).
The rules are vacuous for a crate that does not exist yet, so the check works whether
or not the M03 crates (registry, credential, issuer, enroll) exist.

Self-tests build mutant fixture workspaces in a `tempfile.mkdtemp()` directory that is
removed afterwards (never a glob; the exact path):
  crate_graph_step_rejects_app_edge_to_enroll
  crate_graph_step_rejects_cycle_and_ipc_to_app_edge
  crate_graph_reads_package_names_optional_and_target_dependencies
  crate_graph_positive_control (the clean fixture and the real workspace pass)
Each name is printed with PASS or FAIL; the step fails if any self-test fails.
"""
import os
import shutil
import sys
import tempfile

try:
    import tomllib
except ImportError:  # pragma: no cover - Python older than 3.11
    sys.stderr.write(
        "crate_graph: Python 3.11+ (tomllib) is required; found %s\n"
        % sys.version.split()[0]
    )
    sys.exit(2)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

APP_FORBIDDEN = {
    "heimdall-credential",
    "heimdall-issuer",
    "heimdall-enroll",
    "heimdall-adapters",
    "heimdall-localenv",
    "heimdall-runtime",
}
# crate -> the only workspace crates it may depend on (production).
ONLY_ALLOWED = {
    "heimdall-ipc": {"heimdall-contract"},
    "heimdall-registry": {"heimdall-contract", "heimdall-domain"},
}


class GraphError(Exception):
    """An unreadable manifest or an unresolvable workspace (exit 2)."""


def _load(path):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GraphError("cannot read %s: %s" % (path, exc))


def _members(root, ws):
    out = []
    excluded = {os.path.normpath(e) for e in ws.get("exclude", [])}
    for m in ws.get("members", []):
        if m.endswith("/*"):
            base = os.path.join(root, m[:-2])
            try:
                names = sorted(os.listdir(base))
            except OSError as exc:
                raise GraphError("cannot list %s: %s" % (base, exc))
            cands = [m[:-2] + "/" + n for n in names]
            cands = [c for c in cands if os.path.isfile(os.path.join(root, c, "Cargo.toml"))]
        else:
            cands = [m]
        for c in cands:
            if os.path.normpath(c) not in excluded:
                out.append(os.path.normpath(c))
    return out


def _dep_tables(manifest):
    """Yield (table_label, {key: spec}) for every production dependency table."""
    if isinstance(manifest.get("dependencies"), dict):
        yield "dependencies", manifest["dependencies"]
    for cfg, tbl in (manifest.get("target") or {}).items():
        if isinstance(tbl, dict) and isinstance(tbl.get("dependencies"), dict):
            yield "target.%s.dependencies" % cfg, tbl["dependencies"]


def load_workspace(root):
    """Return (members, edges): members {package: dir}, edges {pkg: {dep_pkg: [why]}}."""
    root = os.path.abspath(root)
    top = _load(os.path.join(root, "Cargo.toml"))
    ws = top.get("workspace")
    if not isinstance(ws, dict):
        raise GraphError("%s has no [workspace]" % os.path.join(root, "Cargo.toml"))
    dirs = _members(root, ws)
    manifests = {}
    by_dir = {}
    for d in dirs:
        m = _load(os.path.join(root, d, "Cargo.toml"))
        name = (m.get("package") or {}).get("name")
        if not isinstance(name, str):
            raise GraphError("%s/Cargo.toml has no [package] name" % d)
        if name in manifests:
            raise GraphError("duplicate package name %s" % name)
        manifests[name] = m
        by_dir[os.path.normpath(os.path.join(root, d))] = name
    ws_deps = ws.get("dependencies") or {}

    def package_of(base_dir, key, spec, label):
        """Resolve one dependency entry to a package name (or None for a non-path
        external crate). base_dir is the directory relative paths are against."""
        if not isinstance(spec, dict):
            return key  # "x = \"1\"": a registry crate named by its key
        if spec.get("workspace") is True:
            wspec = ws_deps.get(key)
            if wspec is None:
                raise GraphError("%s: %s = { workspace = true } has no [workspace.dependencies] entry" % (label, key))
            pkg = spec.get("package")
            if pkg is None:
                return package_of(root, key, wspec, "[workspace.dependencies]")
            return pkg
        if "path" in spec:
            target = os.path.normpath(os.path.join(base_dir, spec["path"]))
            if target in by_dir:
                return by_dir[target]
            tm = os.path.join(target, "Cargo.toml")
            if os.path.isfile(tm):
                tname = (_load(tm).get("package") or {}).get("name")
                if isinstance(tname, str):
                    return tname
            return spec.get("package", key)
        return spec.get("package", key)

    edges = {}
    for name, m in manifests.items():
        mdir = [d for d, n in by_dir.items() if n == name][0]
        out = {}
        for label, tbl in _dep_tables(m):
            for key, spec in tbl.items():
                pkg = package_of(mdir, key, spec, "%s (%s)" % (name, label))
                if pkg in manifests:
                    why = label + (" optional" if isinstance(spec, dict) and spec.get("optional") else "")
                    if key != pkg:
                        why += " as `%s`" % key
                    out.setdefault(pkg, []).append(why)
        edges[name] = out
    return {n: None for n in manifests}, edges


def find_cycles(edges):
    """Return a list of cycles (each a list of package names, first == last)."""
    cycles, seen_sets = [], set()
    color = {}
    stack = []

    def visit(n):
        color[n] = 1
        stack.append(n)
        for d in sorted(edges.get(n, {})):
            if color.get(d, 0) == 0:
                visit(d)
            elif color.get(d) == 1:
                cyc = stack[stack.index(d):] + [d]
                key = frozenset(cyc)
                if key not in seen_sets:
                    seen_sets.add(key)
                    cycles.append(cyc)
        stack.pop()
        color[n] = 2

    for n in sorted(edges):
        if color.get(n, 0) == 0:
            visit(n)
    return cycles


def violations(members, edges):
    bad = []
    for cyc in find_cycles(edges):
        bad.append("production cycle: " + " -> ".join(cyc))
    for dep in sorted(edges.get("heimdall-app", {})):
        if dep in APP_FORBIDDEN:
            bad.append(
                "forbidden edge: heimdall-app -> %s (%s); app reaches it through ports only"
                % (dep, "; ".join(edges["heimdall-app"][dep]))
            )
    for crate, allowed in sorted(ONLY_ALLOWED.items()):
        for dep in sorted(edges.get(crate, {})):
            if dep not in allowed:
                bad.append(
                    "forbidden edge: %s -> %s (%s); %s may depend only on %s among workspace crates"
                    % (crate, dep, "; ".join(edges[crate][dep]), crate, ", ".join(sorted(allowed)))
                )
    return bad


def check(root, quiet=False):
    """Check the workspace at root. Returns the list of violations."""
    members, edges = load_workspace(root)
    bad = violations(members, edges)
    if not quiet:
        print("resolved production graph (%d workspace crates):" % len(members))
        for n in sorted(members):
            deps = ", ".join(sorted(edges[n])) or "(none)"
            print("  %s -> %s" % (n, deps))
        absent = [c for c in ("heimdall-registry", "heimdall-credential", "heimdall-issuer", "heimdall-enroll") if c not in members]
        if absent:
            print("not present yet: " + ", ".join(absent))
    return bad


# ---------------------------------------------------------------------------
# Self-tests: mutant fixture workspaces

# crate -> production dependencies (workspace crates), per m03-plan section 0.6.
CLEAN = {
    "contract": [],
    "domain": ["contract"],
    "store": ["contract", "domain"],
    "registry": ["contract", "domain"],
    "app": ["contract", "domain", "store", "registry"],
    "ipc": ["contract"],
    "localenv": ["contract", "domain", "app", "ipc"],
    "credential": ["contract", "domain", "ipc", "app"],
    "issuer": ["contract", "domain", "store", "app", "credential"],
    "enroll": ["contract", "domain", "registry", "app"],
    "adapters": ["contract", "domain", "app", "ipc", "localenv", "credential"],
    "runtime": ["contract", "domain", "store", "app", "ipc", "localenv", "adapters", "credential", "issuer", "enroll"],
    "testkit": [],
    "heimdall": ["contract", "domain", "app", "ipc", "runtime", "localenv", "store", "issuer", "enroll", "testkit"],
}


def _manifest(crate, spec):
    """`spec` = dict(deps=[...], raw=[...], extra=str). `deps` use `{ workspace = true }`."""
    lines = ["[package]", 'name = "heimdall-%s"' % crate, 'version = "0.0.0"', "", "[dependencies]"]
    for d in spec.get("deps", []):
        lines.append("heimdall-%s = { workspace = true }" % d)
    lines.extend(spec.get("raw", []))  # raw dependency lines
    lines.append('serde = "1"')  # a third-party dependency is always fine
    lines.append("")
    lines.append(spec.get("extra", ""))
    return "\n".join(lines) + "\n"


def build_fixture(root, mutate=None, ws_extra=""):
    """Write a clean fixture workspace under root; `mutate(specs)` edits the specs first."""
    specs = {c: {"deps": list(d), "extra": ""} for c, d in CLEAN.items()}
    # A dev-dependency cycle through testkit, allowed: ipc dev-depends on testkit and
    # testkit optionally depends on ipc.
    specs["ipc"]["extra"] = '[dev-dependencies]\nheimdall-testkit = { workspace = true }\n'
    specs["testkit"]["extra"] = (
        '[dev-dependencies]\nheimdall-app = { workspace = true }\n'
    )
    # testkit's optional production edges (feature `managed`) point at crates that do
    # not depend on testkit in production, so no cycle.
    specs["testkit"]["deps"] = ["contract", "domain"]
    specs["testkit"]["extra"] += (
        '[target.\'cfg(unix)\'.dependencies]\nheimdall-credential = { workspace = true, optional = true }\n'
    )
    if mutate:
        mutate(specs)
    members = []
    ws_deps = []
    for c, spec in specs.items():
        d = os.path.join(root, "crates", c)
        os.makedirs(d)
        with open(os.path.join(d, "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write(_manifest(c, spec))
        members.append('"crates/%s"' % c)
        ws_deps.append('heimdall-%s = { path = "crates/%s" }' % (c, c))
    with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as f:
        f.write("[workspace]\nmembers = [%s]\n\n[workspace.dependencies]\n%s\n%s\n" % (", ".join(members), "\n".join(ws_deps), ws_extra))


def _run_fixture(mutate=None, ws_extra=""):
    tmp = tempfile.mkdtemp(prefix="crate-graph-fixture-")
    try:
        build_fixture(tmp, mutate, ws_extra)
        return check(tmp, quiet=True)
    finally:
        shutil.rmtree(tmp)


def _expect(bad, *needles):
    """True when some violation contains every needle."""
    return any(all(n in b for n in needles) for b in bad)


def _t_app_edge_to_enroll():
    def m(specs):
        specs["app"]["deps"].append("enroll")
    bad = _run_fixture(m)
    return _expect(bad, "forbidden edge: heimdall-app -> heimdall-enroll"), bad


def _t_cycle_and_ipc_to_app():
    def cyc(specs):
        specs["store"]["deps"].append("app")  # store -> app -> store
    bad1 = _run_fixture(cyc)
    ok1 = _expect(bad1, "production cycle:", "heimdall-store", "heimdall-app")

    def ipc_app(specs):
        specs["ipc"]["deps"].append("app")
    bad2 = _run_fixture(ipc_app)
    ok2 = _expect(bad2, "forbidden edge: heimdall-ipc -> heimdall-app")

    # The registry is pure: an edge to store is rejected too (same rule family).
    def reg_store(specs):
        specs["registry"]["deps"].append("store")
    bad3 = _run_fixture(reg_store)
    ok3 = _expect(bad3, "forbidden edge: heimdall-registry -> heimdall-store")
    return ok1 and ok2 and ok3, bad1 + bad2 + bad3


def _t_package_names_optional_target():
    # (a) a forbidden edge hidden behind a renamed key with an explicit path + package.
    def renamed_path(specs):
        specs["app"]["extra"] += (
            '[dependencies.shortname]\npath = "../enroll"\npackage = "heimdall-enroll"\n'
        )
    bad_a = _run_fixture(renamed_path)
    ok_a = _expect(bad_a, "forbidden edge: heimdall-app -> heimdall-enroll", "as `shortname`")

    # (b) hidden behind a renamed [workspace.dependencies] key that a member inherits.
    def renamed_ws(specs):
        specs["ipc"]["raw"] = ["en = { workspace = true }"]
    bad_b = _run_fixture(
        renamed_ws,
        ws_extra='en = { path = "crates/enroll", package = "heimdall-enroll" }',
    )
    ok_b = _expect(bad_b, "forbidden edge: heimdall-ipc -> heimdall-enroll", "as `en`")

    # (c) an optional dependency.
    def optional(specs):
        specs["app"]["extra"] += '[dependencies.heimdall-credential]\npath = "../credential"\noptional = true\n'
    bad_c = _run_fixture(optional)
    ok_c = _expect(bad_c, "forbidden edge: heimdall-app -> heimdall-credential", "optional")

    # (d) a target-specific dependency.
    def target(specs):
        specs["app"]["extra"] += "[target.'cfg(windows)'.dependencies]\nheimdall-adapters = { workspace = true }\n"
    bad_d = _run_fixture(target)
    ok_d = _expect(bad_d, "forbidden edge: heimdall-app -> heimdall-adapters", "target.cfg(windows).dependencies")

    # (e) negative control: the same edges as dev-dependencies are NOT production edges.
    def dev_only(specs):
        specs["app"]["extra"] += "[dev-dependencies]\nheimdall-enroll = { workspace = true }\n[build-dependencies]\nheimdall-runtime = { workspace = true }\n"
    bad_e = _run_fixture(dev_only)
    ok_e = not bad_e
    return ok_a and ok_b and ok_c and ok_d and ok_e, bad_a + bad_b + bad_c + bad_d + bad_e


def _t_positive():
    bad_fixture = _run_fixture()
    try:
        bad_real = check(REPO_ROOT, quiet=True)
    except GraphError as exc:
        bad_real = ["real workspace unreadable: %s" % exc]
    return (not bad_fixture) and (not bad_real), bad_fixture + bad_real


SELF_TESTS = [
    ("crate_graph_step_rejects_app_edge_to_enroll", _t_app_edge_to_enroll),
    ("crate_graph_step_rejects_cycle_and_ipc_to_app_edge", _t_cycle_and_ipc_to_app),
    ("crate_graph_reads_package_names_optional_and_target_dependencies", _t_package_names_optional_target),
    ("crate_graph_positive_control", _t_positive),
]


def self_tests():
    failed = 0
    for name, fn in SELF_TESTS:
        try:
            ok, detail = fn()
        except Exception as exc:  # a crashing self-test is a failing one
            ok, detail = False, ["exception: %r" % (exc,)]
        print("self-test %s: %s" % (name, "PASS" if ok else "FAIL"))
        if not ok:
            failed += 1
            for d in detail:
                print("    observed: " + d)
    return failed


def main(argv):
    only_self = "--self-test" in argv
    root = None
    if "--root" in argv:
        i = argv.index("--root")
        if i + 1 >= len(argv):
            sys.stderr.write("crate_graph: --root needs a directory\n")
            return 2
        root = argv[i + 1]
    unknown = [a for a in argv if a not in ("--self-test", "--root") and a != root]
    if unknown:
        sys.stderr.write("crate_graph: unknown arguments: %s\n" % " ".join(unknown))
        return 2
    rc = 0
    try:
        if not only_self:
            bad = check(root or REPO_ROOT)
            if bad:
                rc = 1
                for b in bad:
                    print("VIOLATION: " + b)
            else:
                print("crate graph: OK (no production cycle, no forbidden edge)")
        if root is None:
            if self_tests():
                rc = 1
    except GraphError as exc:
        sys.stderr.write("crate_graph: %s\n" % exc)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
