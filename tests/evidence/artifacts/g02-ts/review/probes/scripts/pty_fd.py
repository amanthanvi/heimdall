import os, pty, sys, time, select, json
B=sys.argv[1]
pid, fd = pty.fork()
if pid==0:
    os.execv(B,[B,"run","--","/usr/bin/python3","/tmp/hm-review-probes/fdflags.py"])
out=b""
while True:
    try: c=os.read(fd,4096)
    except OSError: break
    if not c: break
    out+=c
_,st=os.waitpid(pid,0)
print(json.dumps({"rc":os.waitstatus_to_exitcode(st),"out":out.decode(errors="replace").strip()}))
