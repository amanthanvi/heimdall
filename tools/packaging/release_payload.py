"""The shared release payload and its checks for both packagers."""

import json
from pathlib import Path
import re
import runpy
import shutil
import tomllib

REPO = Path(__file__).resolve().parents[2]
MATRIX = "docs/compatibility/matrix.md"
MATRIX_MARKER = b"HEIMDALL-COMPATIBILITY-MATRIX-PLACEHOLDER"
SKILL = "skills/heimdall/SKILL.md"
CONFIG = "examples/reference-config/config.toml"
MANIFEST = "examples/reference-config/heimdall.toml"
CONFIG_SCHEMA = "schemas/configuration/config.schema.json"
MANIFEST_SCHEMA = "schemas/project/manifest.schema.json"

# Keep the ADR's skill location and a copy alongside the other M07 examples. Only the
# explicit files go into the release; tests and development fixtures stay in the checkout.
EXAMPLES = (
    "examples/reference-wrapper/README.md",
    "examples/reference-wrapper/reference_wrapper.py",
    "examples/reference-wrapper/reference_wrapper_windows.py",
    "examples/reference-wrapper/journey.py",
    "examples/harnesses/cli/README.md",
    "examples/harnesses/cli/harness.py",
    "examples/harnesses/goal-loop/README.md",
    "examples/harnesses/goal-loop/harness.py",
)
DOCS = (
    "docs/release-notes/v1-candidate.md",
    "docs/operations/install.md",
    "docs/operations/update-and-rollback.md",
    "docs/operations/recovery.md",
    "docs/operations/unenrollment.md",
    "docs/operations/uninstall.md",
    "docs/operations/urgent-fix-disclosure.md",
    "docs/compatibility/policy.md",
)
SCHEMA_DIRS = ("configuration", "project", "public-api", "examples")
WORKSPACE_PAYLOAD_EXAMPLES = {
    "schemas/examples/inspect.workspace.json",
    "schemas/examples/inspect.workspace.proposal.json",
    "schemas/examples/request.ensure.context.json",
    "schemas/examples/request.inspect.workspace.json",
    "schemas/examples/request.policy.trust-workspace.json",
}


def payload():
    files = {name: name for name in (*EXAMPLES, *DOCS, SKILL, MANIFEST, CONFIG_SCHEMA, MANIFEST_SCHEMA)}
    files[f"examples/{SKILL}"] = SKILL
    files[CONFIG] = "tools/packaging/config.toml"
    files[MATRIX] = "tools/packaging/compatibility-matrix.md"
    for directory in SCHEMA_DIRS:
        for path in sorted((REPO / "schemas" / directory).rglob("*.json")):
            name = path.relative_to(REPO).as_posix()
            files[name] = name
    return files


def stage(root):
    for dest, source in payload().items():
        path = root / dest
        path.parent.mkdir(parents=True, exist_ok=True)
        if dest in WORKSPACE_PAYLOAD_EXAMPLES:
            # These published example strings use the synthetic account "dev". Use the
            # same explicit placeholder as the runbooks, under the regular privacy scan.
            path.write_bytes((REPO / source).read_bytes().replace(b'"/home/dev/', b'"/home/<name>/'))
        else:
            shutil.copyfile(REPO / source, path)


def installer_references_examples(data):
    """Reject direct references to optional resources in installer code, including comments.

    The file-only install regression also checks actual side effects with the full payload.
    """
    return re.search(rb"\b(?:skills?|examples)\b|(?<![\w.-])\.(?:claude|codex|agents)\b",
                     data, flags=re.IGNORECASE) is not None


def check(root, files, target, candidate, fail):
    required = set(payload())
    if candidate:
        required.update(("LICENSE", "SECURITY.md"))
    required.update(("BUILD-RECORD.json", "THIRD-PARTY-NOTICES.txt"))
    install = "install.ps1" if target == "x86_64-pc-windows-msvc" else "install.sh"
    required.add(install)
    if target:
        required.add(f"heimdall-{target}.cdx.json")
    else:
        if not any(re.fullmatch(r"heimdall-[^/]+\.cdx\.json", name) for name in files):
            fail("release payload: SBOM is missing")
    names = set(files)
    for name in sorted(required - names):
        fail(f"release payload: {name} is missing")
    if MATRIX in names:
        matrix = (root / MATRIX).read_bytes()
        if not matrix.strip() or (candidate and MATRIX_MARKER in matrix):
            fail("release payload: compatibility matrix is empty or still a placeholder")
    if install in names and installer_references_examples((root / install).read_bytes()):
        fail(f"{install}: installer must leave the skill and examples inert")

    schema_check = runpy.run_path(str(REPO / "examples/reference-config/check.py"))
    for name, schema_name in ((CONFIG, CONFIG_SCHEMA), (MANIFEST, MANIFEST_SCHEMA)):
        if name not in names:
            continue
        try:
            schema = json.loads((REPO / schema_name).read_text(encoding="utf-8"))
            value = tomllib.loads((root / name).read_text(encoding="utf-8"))
            for error in schema_check["validate"](value, schema, schema):
                fail(f"release payload: {name}: {error}")
        except (ValueError, schema_check["Unsupported"], KeyError) as exc:
            fail(f"release payload: {name}: schema validation failed ({type(exc).__name__})")
