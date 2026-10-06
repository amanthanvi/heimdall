import os, signal, subprocess, sys
FIX = "tests/fixtures/g02/profiles"
cases = {"version": ["version"], "profile-ok": ["profile", "show", "--file", FIX + "/homelab.toml"],
         "profile-missing": ["profile", "show", "--file", "/nonexistent/x.toml"],
         "profile-invalid": ["profile", "show", "--file", FIX + "/invalid-port.toml"],
         "agent-unavail": ["agent", "list", "--socket", "/nonexistent/sock"]}
env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/tmp"}
def ign():
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
def dfl():
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
for b in sys.argv[1:]:
    for dname, fn in (("SIGPIPE default", dfl), ("SIGPIPE inherited ignored", ign)):
        row = []
        for k, a in cases.items():
            st = {}
            for v in ("json", "plain"):
                r, w = os.pipe(); os.close(r)
                p = subprocess.run([b] + a + (["--json"] if v == "json" else []), stdout=w, stderr=subprocess.DEVNULL,
                                   env=env, preexec_fn=fn, timeout=20)
                os.close(w)
                st[v] = p.returncode
            row.append("%s json=%s plain=%s%s" % (k, st["json"], st["plain"], "" if st["json"] == st["plain"] else " DIFF"))
        print(b.split("/")[1] if b.startswith("prototypes") else b, "|", dname, "|", "; ".join(row))
