#!/usr/bin/env python3
"""Validate every JSON document the Go prototype emits against
schemas/g02/result.schema.json, plus dist/manifest.json shape.
Usage: python schema_check.py <heimdall-proto> <repo-root>   (needs jsonschema)
"""
import json, os, socket, struct, subprocess, sys, tempfile, threading

import jsonschema

BIN, REPO = sys.argv[1], sys.argv[2]
FIX = os.path.join(REPO, "tests/fixtures/g02/profiles")
schema = json.load(open(os.path.join(REPO, "schemas/g02/result.schema.json")))
V = jsonschema.Draft202012Validator(schema)
ENV = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
ok_all = True


def validate(name, raw, want_code=None, want_exit=None, exit_code=None):
    global ok_all
    errs = []
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        errs.append("not exactly one JSON line")
    try:
        doc = json.loads(raw)
        errs += [e.message for e in V.iter_errors(doc)]
        if want_code and doc.get("code") != want_code:
            errs.append(f"code {doc.get('code')} != {want_code}")
    except Exception as e:  # noqa
        errs.append(f"invalid JSON: {e}")
    if b"\x1b" in raw or b"HEIMDALL_CANARY_" in raw:
        errs.append("escape or canary in output")
    if want_exit is not None and exit_code != want_exit:
        errs.append(f"exit {exit_code} != {want_exit}")
    ok = not errs
    ok_all &= ok
    print("PASS" if ok else "FAIL", name, f"exit={exit_code}", "; ".join(errs))


def cli(name, args, code, exit_):
    p = subprocess.run([BIN] + args, capture_output=True, env=ENV)
    validate(name, p.stdout, code, exit_, p.returncode)
    if b"HEIMDALL_CANARY_" in p.stderr:
        print("FAIL", name, "canary on stderr"); globals()["ok_all"] = False


for f, code, ex in [("homelab.toml", "PROFILE_OK", 0), ("large-100.toml", "PROFILE_OK", 0),
                    ("spaced dir ü/prøfile homelab.toml", "PROFILE_OK", 0),
                    ("invalid-forbidden-key.toml", "SCHEMA_INVALID", 2), ("invalid-unknown-dest-key.toml", "SCHEMA_INVALID", 2),
                    ("invalid-malformed.toml", "SCHEMA_INVALID", 2), ("invalid-schema-version.toml", "SCHEMA_INVALID", 2),
                    ("invalid-duplicate-alias.toml", "SCHEMA_INVALID", 2), ("invalid-port.toml", "SCHEMA_INVALID", 2)]:
    cli("profile:" + f, ["profile", "show", "--file", os.path.join(FIX, f), "--json"], code, ex)

with tempfile.TemporaryDirectory(prefix="hp ü ") as d:
    big = os.path.join(d, "oversize.toml")
    open(big, "wb").write(b"#" * (1048576 + 1))
    cli("profile:oversize", ["profile", "show", "--file", big, "--json"], "INPUT_TOO_LARGE", 2)
    cli("profile:missing", ["profile", "show", "--file", os.path.join(d, "nope"), "--json"], "USAGE_ERROR", 2)
    meta = os.path.join(d, "meta.json")
    for name, argv, ex, code in [("exit3", ["sh", "-c", "exit 3"], 3, "CHILD_EXITED"),
                                 ("missing", ["no-such-cmd-hp"], 127, "CHILD_LAUNCH_FAILED"),
                                 ("signal", ["sh", "-c", "kill -TERM $$"], 143, "CHILD_EXITED")]:
        p = subprocess.run([BIN, "run", "--meta-file", meta, "--"] + argv, capture_output=True, env=ENV)
        validate("run-meta:" + name, open(meta, "rb").read(), code, ex, p.returncode)
cli("version", ["version", "--json"], "VERSION_OK", 0)
cli("usage:unknown-subcommand", ["frobnicate", "--json"], "USAGE_ERROR", 2)
cli("usage:unknown-flag", ["profile", "show", "--nope", "--json"], "USAGE_ERROR", 2)
cli("usage:missing-file-arg", ["profile", "show", "--json"], "USAGE_ERROR", 2)

d = tempfile.mkdtemp(prefix="hpa", dir="/tmp")
path = os.path.join(d, "s")
srv = socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1)
def serve():
    c, _ = srv.accept(); c.recv(16)
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"\x02" * 32
    body = b"\x0c" + struct.pack(">I", 1) + struct.pack(">I", len(blob)) + blob + struct.pack(">I", 4) + b"a\x1bb\xff"
    c.sendall(struct.pack(">I", len(body)) + body); c.close()
threading.Thread(target=serve, daemon=True).start()
cli("agent:ok", ["agent", "list", "--socket", path, "--json"], "AGENT_OK", 0)
cli("agent:unavailable", ["agent", "list", "--socket", path + "x", "--json"], "AGENT_UNAVAILABLE", 5)

m = json.load(open(os.path.join(os.path.dirname(os.path.dirname(BIN)), "manifest.json")))
mok = m["candidate"] == "go" and all(set(t) == {"target", "path", "bytes", "sha256", "built", "error"} for t in m["targets"])
ok_all &= mok
print("PASS" if mok else "FAIL", "manifest shape", [(t["target"], t["built"]) for t in m["targets"]])
sys.exit(0 if ok_all else 1)
