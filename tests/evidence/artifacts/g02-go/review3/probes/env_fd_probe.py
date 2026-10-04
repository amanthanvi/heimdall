#!/usr/bin/env python3
"""Review-3 probe: does `heimdall-proto run` pass the raw environment block and
inherited non-stdio descriptors through like exec(2) would?

usage: env_fd_probe.py HEIMDALL_BIN OUT_JSON

env: a raw envp with a duplicate key (first and last values differ), an entry
without '=', and an empty-value entry is passed with libc execve; the child
(/usr/bin/env) prints its environ verbatim. Control: the same envp to
/usr/bin/env directly.
fd: fd 5 opened without O_CLOEXEC on a file is inherited; the child lists its
open descriptors. Control: the same without heimdall-proto.
"""
import ctypes
import ctypes.util
import json
import os
import subprocess
import sys

HP = os.path.abspath(sys.argv[1])
OUT = sys.argv[2]
ENV = "/usr/bin/env"


def raw_exec_capture(argv, envp):
    """fork; child calls libc execve with exactly these argv/envp byte strings."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.dup2(w, 1)
        os.dup2(w, 2)
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        A = (ctypes.c_char_p * (len(argv) + 1))(*[a.encode() for a in argv], None)
        E = (ctypes.c_char_p * (len(envp) + 1))(*[e.encode() for e in envp], None)
        libc.execve(argv[0].encode(), A, E)
        os._exit(99)
    os.close(w)
    out = b""
    while True:
        d = os.read(r, 65536)
        if not d:
            break
        out += d
    os.close(r)
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st), out.decode("utf-8", "replace").splitlines()


def main():
    res = {}
    envp = ["PATH=/usr/bin:/bin", "DUPKEY=first", "NOEQUALS_ENTRY", "EMPTY=", "DUPKEY=last", "LANG=C"]
    rc_c, out_c = raw_exec_capture([ENV], envp)
    rc_h, out_h = raw_exec_capture([HP, "run", "--", ENV], envp)
    res["env"] = {"envp_passed": envp, "control": {"rc": rc_c, "child_environ": out_c},
                  "heimdall": {"rc": rc_h, "child_environ": out_h},
                  "identical": out_c == out_h}

    lister = ("import os;print(sorted(int(x) for x in os.listdir('/dev/fd')))")
    fd = os.open("/etc/hosts", os.O_RDONLY)
    if fd != 5:
        os.dup2(fd, 5)
        os.close(fd)
    os.set_inheritable(5, True)
    c = subprocess.run(["python3", "-c", lister], pass_fds=(5,), capture_output=True, text=True)
    h = subprocess.run([HP, "run", "--", "python3", "-c", lister], pass_fds=(5,), capture_output=True, text=True)
    os.close(5)
    res["fd5_inherited"] = {"control": {"rc": c.returncode, "fds": c.stdout.strip()},
                            "heimdall": {"rc": h.returncode, "fds": h.stdout.strip()}}
    with open(OUT, "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
