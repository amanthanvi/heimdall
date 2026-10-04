import os, pty, sys, time, select, json, struct, fcntl, termios
B=sys.argv[1]; PROF=sys.argv[2]
pid,fd=pty.fork()
if pid==0:
    os.chdir("/tmp/hm-review-probes/h")
    os.execve(B,[B,"tui","--file",PROF],{"PATH":"/usr/bin:/bin","HOME":"/tmp/hm-review-probes/h","TERM":"xterm","TMPDIR":"/tmp/hm-review-probes/h/t/"})
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH",24,80,0,0))
out=b""; t0=time.monotonic(); s=0; rc=None
while time.monotonic()-t0<6:
    r,_,_=select.select([fd],[],[],0.05)
    if r:
        try: out+=os.read(fd,65536)
        except OSError: pass
    if s==0 and time.monotonic()-t0>1: os.write(fd,b"j"); s=1
    if s==1 and time.monotonic()-t0>1.4: os.write(fd,b"\r"); s=2
    w=os.waitpid(pid,os.WNOHANG)
    if w[0]==pid: rc=os.waitstatus_to_exitcode(w[1]); break
time.sleep(0.1)
try: out+=os.read(fd,65536)
except OSError: pass
txt=out.decode(errors="replace")
print(json.dumps({"rc":rc,"selected_line":[l for l in txt.split("\n") if "SELECTED" in l][-1:] ,"alt_screen_left":"\x1b[?1049l" in txt}))
