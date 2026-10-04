import os, pty, sys, time, select, signal, json
B=sys.argv[1]; mode=sys.argv[2]
wrap = f"'{B}' run --" if mode=="proto" else "/usr/bin/env"
cmd = f"{wrap} /bin/sh -c 'printf line1; sleep 2' | /usr/bin/less; echo PIPE_DONE"
pid, fd = pty.fork()
if pid == 0:
    os.execve("/bin/bash", ["/bin/bash","--norc","--noprofile","-i","-c",cmd], {"PATH":"/usr/bin:/bin","TERM":"xterm","HOME":"/tmp/hm-review-probes/h","LESS":"","LESSHISTFILE":"-"})
out=b""; t0=time.monotonic(); sent=False; rc=None
while time.monotonic()-t0<8:
    r,_,_=select.select([fd],[],[],0.1)
    if r:
        try: out+=os.read(fd,4096)
        except OSError: pass
    if not sent and time.monotonic()-t0>1.0:
        os.write(fd,b"q"); sent=True
    w=os.waitpid(pid,os.WNOHANG)
    if w[0]==pid: rc=w[1]; break
hung= rc is None
if hung: os.kill(pid,signal.SIGKILL); os.waitpid(pid,0)
txt=out.decode(errors="replace")
print(json.dumps({"mode":mode,"hung":hung,"elapsed_s":round(time.monotonic()-t0,2),"saw_line1":"line1" in txt,"stopped":"Stopped" in txt,"done":"PIPE_DONE" in txt}))
