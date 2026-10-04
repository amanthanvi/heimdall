#!/usr/bin/env python3
import json, os, sys
e = os.environ
rec = {"argv1": sys.argv[1:3], "keys": sorted(e.keys()), "HOME": e.get("HOME"), "TMPDIR": e.get("TMPDIR"),
       "cwd": os.getcwd(), "SSH_AUTH_SOCK_present": "SSH_AUTH_SOCK" in e,
       "SSH_AUTH_SOCK_is_harness_sentinel": e.get("SSH_AUTH_SOCK") == "/tmp/hm-review-sentinel-agent.sock",
       "secret_env_is_canary": e.get("HM_G02_SECRET_ENV", "").startswith("HEIMDALL_CANARY_"),
       "PATH_entries": e.get("PATH", "").split(":"), "ppid": os.getppid(), "sid_is_self_or_parent": None,
       "isatty": [os.isatty(i) for i in (0, 1, 2)]}
with open("/tmp/hm-review-envprobe/log.jsonl", "a") as f:
    f.write(json.dumps(rec) + "\n")
sys.exit(2)
