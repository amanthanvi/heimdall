"""M00-T05-r4-x2-xrev-T3-verify: write the two disposable profiles the cases use.
  homelab.toml: a copy of the repository fixture tests/fixtures/g02/profiles/homelab.toml
  wide.toml:    the cross-review's CJK profile (probe_lib.PROFILES["wide"]), same writer format
Usage: python3 -I make_profiles.py <repo-root> <out-dir>
"""
import shutil
import sys
from pathlib import Path

WIDE = [  # alias, account, host, port
    ("東京-サーバー-本番", "deploy", "db.東京.example", 22),
    ("lab-server", "aman", "lab.example.internal", 22),
    ("大阪", "ops", "osaka.example.jp", 2200),
    ("nas", "admin", "nas.example.internal", 22),
    ("名古屋-backup-東", "root", "ngy.example.invalid", 22),
]


def toml_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    repo, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repo / "tests" / "fixtures" / "g02" / "profiles" / "homelab.toml", out / "homelab.toml")
    lines = ["schema_version = 1", 'name = "wide"', "revision = 1", ""]
    for i, (alias, account, host, port) in enumerate(WIDE):
        lines += ["[[destinations]]", 'id = "dst_%03d"' % i, "alias = " + toml_str(alias), "host = " + toml_str(host),
                  "port = %d" % port, "account = " + toml_str(account), ""]
    (out / "wide.toml").write_text("\n".join(lines), encoding="utf-8")
    print("wrote", out / "homelab.toml", out / "wide.toml")


if __name__ == "__main__":
    main()
