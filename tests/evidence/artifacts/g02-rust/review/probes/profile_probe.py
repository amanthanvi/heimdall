#!/usr/bin/env python3
"""Independent profile-parser probes (reviewer-owned, disposable)."""
import json, os, resource, subprocess, sys, tempfile, time

BIN = sys.argv[1]
OUT = sys.argv[2]
D = tempfile.mkdtemp(prefix="hr profile ü ")
ENV = {"PATH": "/usr/bin:/bin", "HOME": D}
CAN = "HEIMDALL_" + "CANARY_review_7f3a"  # assembled at runtime so this file holds no literal canary
results = []
HEAD = 'schema_version = 1\nname = "p"\nrevision = 1\n'


def run(name, content=None, path=None, timeout=20, expect=None, note=None):
    if path is None:
        path = os.path.join(D, name + " ü.toml")
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
    t0 = time.monotonic()
    try:
        p = subprocess.run([BIN, "profile", "show", "--file", path, "--json"], capture_output=True, env=ENV, timeout=timeout)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = "timeout", b"", b""
    el = round((time.monotonic() - t0) * 1000, 1)
    try:
        doc = json.loads(out)
        code = doc["code"]
        kp = doc["data"].get("error", {}).get("key_path") if isinstance(doc.get("data"), dict) else None
    except Exception:
        doc, code, kp = None, None, None
    leak = CAN.encode() in out or CAN.encode() in err
    r = {"case": name, "exit_code": rc, "code": code, "key_path": kp, "elapsed_ms": el, "canary_leak": leak, "stderr_tail": err.decode("utf-8", "replace")[-140:]}
    if note:
        r["note"] = note
    if expect is not None:
        r["verdict"] = "pass" if (rc, code) == tuple(expect) and not leak else "fail"
    results.append(r)
    print(json.dumps(r, ensure_ascii=False)[:300])


depth = 200_000
run("deep_nested_arrays_in_meta", HEAD + "[meta]\nx = " + "[" * depth + "]" * depth + "\n", expect=(0, "PROFILE_OK"), note="[meta] content tolerated; a stack overflow would abort")
run("deep_nested_arrays_top_level_unknown_key", HEAD + "x = " + "[" * depth + "]" * depth + "\n", expect=(2, "SCHEMA_INVALID"))
run("deep_nested_inline_tables_in_meta", HEAD + "[meta]\nx = " + "{a=" * 100_000 + "1" + "}" * 100_000 + "\n", expect=(0, "PROFILE_OK"))
run("deep_dotted_key_in_meta", HEAD + "[meta]\n" + ".".join(["a"] * 150_000) + " = 1\n", expect=(0, "PROFILE_OK"))
run("unclosed_deep_arrays", HEAD + "x = " + "[" * 300_000 + "\n", expect=(2, "SCHEMA_INVALID"))

# many destinations under 1 MiB: duplicate check is O(n^2)
rows = []
i = 0
body = HEAD
while True:
    row = f'[[destinations]]\nid="d{i}"\nalias="a{i}"\nhost="h"\naccount="u"\n'
    if len(body) + len(row) > 1_048_000:
        break
    body += row
    i += 1
run(f"many_destinations_{i}", body, expect=(0, "PROFILE_OK"))
run("exactly_1MiB_plus_1", HEAD + "#" * (1_048_577 - len(HEAD)), expect=(2, "INPUT_TOO_LARGE"))
run("exactly_1MiB", HEAD + "#" * (1_048_576 - len(HEAD) - 1) + "\n", expect=(0, "PROFILE_OK"))

# canary echo checks
run("canary_in_unterminated_string", HEAD + f'[[destinations]]\nid = "{CAN}\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_duplicate_key", HEAD + f'name = "{CAN}"\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_bad_type_port", HEAD + f'[[destinations]]\nid="a"\nalias="b"\nhost="h"\naccount="u"\nport="{CAN}"\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_invalid_escape", HEAD + f'[[destinations]]\nid = "{CAN}\\q"\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_huge_revision", HEAD.replace("revision = 1", f"revision = 99999999999999999999 # {CAN}"), expect=(2, "SCHEMA_INVALID"))
run("canary_as_unknown_key_value_float", HEAD + f'secret = "{CAN}"\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_schema_version_string", f'schema_version = "{CAN}"\nname="p"\nrevision=1\n', expect=(2, "SCHEMA_INVALID"))
run("canary_in_invalid_utf8_line", (HEAD + f'name2 = "{CAN}').encode() + b"\xff\"\n", expect=(2, "SCHEMA_INVALID"))
run("bidi_override_in_alias_accepted", HEAD + '[[destinations]]\nid="a"\nalias="ab‮cd"\nhost="h"\naccount="u"\n', note="U+202E is Cf, not a control per K2; accepted and echoed", expect=(0, "PROFILE_OK"))

# special paths
run("dev_zero", path="/dev/zero", expect=(2, "INPUT_TOO_LARGE"))
run("dev_null_empty", path="/dev/null", expect=(2, "SCHEMA_INVALID"))
fifo = os.path.join(D, "fifo profile")
os.mkfifo(fifo)
run("fifo_no_writer", path=fifo, timeout=3, note="contract: missing/unreadable -> USAGE_ERROR; a FIFO with no writer blocks")
run("directory", path=D, expect=(2, "USAGE_ERROR"))
nonutf = os.path.join(D.encode(), b"bad\xff name.toml")
with open(nonutf, "wb") as f:
    f.write((HEAD).encode())
p = subprocess.run([BIN.encode(), b"profile", b"show", b"--file", nonutf, b"--json"], capture_output=True, env=ENV, timeout=10)
r = {"case": "non_utf8_path", "exit_code": p.returncode, "code": json.loads(p.stdout)["code"] if p.stdout else None}
r["verdict"] = "pass" if p.returncode == 0 else "fail"
results.append(r)
print(json.dumps(r))

json.dump(results, open(OUT, "w"), indent=1, ensure_ascii=False)
fails = [r["case"] for r in results if r.get("verdict") == "fail"]
print("FAILS:", fails)
sys.exit(1 if fails else 0)
