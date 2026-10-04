# A pipeline running as the terminal's foreground job: `X sleep 2 | reader`, where reader
# reads one byte from /dev/tty. X is heimdall-proto run -- or /usr/bin/env (control).
import os, pty, sys, time, select, signal, json
B=sys.argv[1]; mode=sys.argv[2]
wrap = f"'{B}' run --" if mode=="proto" else "/usr/bin/env"
reader = "/usr/bin/python3 -c 'import os;fd=os.open(\"/dev/tty\",os.O_RDWR);os.write(fd,b\"PROMPT\\n\");b=os.read(fd,1);os.write(fd,b\"GOT:\"+b+b\"\\n\")'"
cmd = f"{wrap} /bin/sleep 2 | {reader}; echo PIPE_DONE"
pid, fd = pty.fork()
if pid == 0:
    os.execv("/bin/sh", ["/bin/sh", "-c", cmd])
out=b""; t0=time.monotonic(); sent=0; rc=None
while time.monotonic()-t0 < 10:
    r,_,_=select.select([fd],[],[],0.1)
    if r:
        try: c=os.read(fd,4096)
        except OSError: c=b""
        out+=c
    if b"PROMPT" in out and sent==0 and time.monotonic()-t0>0.5:
        os.write(fd,b"y\n"); sent=1
    if b"PROMPT" in out and sent==1 and time.monotonic()-t0>4:
        os.write(fd,b"z\n"); sent=2
    w=os.waitpid(pid, os.WNOHANG)
    if w[0]==pid: rc=w[1]; break
hung = rc is None
if hung:
    os.kill(pid, signal.SIGKILL); os.waitpid(pid,0)
print(json.dumps({"mode":mode,"hung_after_10s":hung,"elapsed_s":round(time.monotonic()-t0,2),"output":out.decode(errors="replace")}))
