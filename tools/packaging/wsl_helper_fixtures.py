"""Generate indexed, non-runnable archive fixtures for the Windows packager self-test."""
import hashlib
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent


def make_cases(root, commit):
    verifier = runpy.run_path(str(HERE / "verify_artifact.py"))
    provenance = runpy.run_path(str(HERE / "provenance.py"))
    elf = verifier["_elf"](["libc.so.6"])
    target = verifier["WSL_TARGET"]
    for case in ("good", "commit", "target", "features", "digest", "index", "machine"):
        directory = root / case
        stage = directory / ("heimdall-0.0.0-" + target)
        stage.mkdir(parents=True)
        verifier["PAYLOAD"]["stage"](stage)
        binary = elf if case != "machine" else elf[:18] + b"\xb7\x00" + elf[20:]
        (stage / "heimdall").write_bytes(binary)
        (stage / "THIRD-PARTY-NOTICES.txt").write_text("Fixture notices\n", encoding="utf-8")
        (stage / f"heimdall-{target}.cdx.json").write_text("{}\n", encoding="utf-8")
        (stage / "install.sh").write_text("# fixture\n", encoding="utf-8")
        record = {
            "schema": "heimdall-build-record/1", "profile": "release", "tree_clean": True,
            "commit": commit if case != "commit" else ("0" if commit != "0" * 40 else "1") * 40,
            "target": target if case != "target" else "aarch64-unknown-linux-gnu",
            "features": "--no-default-features" + (" --features another-feature" if case == "features" else ""),
            "outputs": [{"path": "heimdall", "sha256": hashlib.sha256(binary).hexdigest()
                         if case != "digest" else "0" * 64}],
        }
        (stage / "BUILD-RECORD.json").write_text(json.dumps(record), encoding="utf-8")
        archive = directory / "linux.tar.gz"
        provenance["write_manifest"](str(stage))
        provenance["pack"](str(stage), str(archive), "2026-11-26T00:00:00Z")
        provenance["write_index"](str(directory))
        if case == "index":
            (directory / "SHA256SUMS").write_text(f"{'0' * 64}  {archive.name}\n", encoding="utf-8")


if __name__ == "__main__":
    make_cases(Path(sys.argv[1]), sys.argv[2])
