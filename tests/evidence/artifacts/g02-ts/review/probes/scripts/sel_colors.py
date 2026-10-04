import os, pty, sys, time, select, json, struct, fcntl, termios
import pyte
B=sys.argv[1]; PROF="<repo>/tests/fixtures/g02/profiles/homelab.toml"
pid,fd=pty.fork()
if pid==0:
    os.execve(B,[B,"tui","--file",PROF],{"PATH":"/usr/bin:/bin","HOME":"/tmp/hm-review-probes/h","TERM":sys.argv[2]})
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH",24,80,0,0))
out=b""; t0=time.monotonic(); s=0
while time.monotonic()-t0<5:
    r,_,_=select.select([fd],[],[],0.05)
    if r:
        try: out+=os.read(fd,65536)
        except OSError: pass
    if s==0 and time.monotonic()-t0>1.2:
        snap=out; os.write(fd,b"q"); s=1
    if os.waitpid(pid,os.WNOHANG)[0]==pid: break
scr=pyte.Screen(80,24); st=pyte.ByteStream(scr); st.feed(snap)
def cell(r,c):
    ch=scr.buffer[r][c]; return {"data":ch.data,"fg":ch.fg,"bg":ch.bg,"reverse":ch.reverse,"bold":ch.bold}
print(json.dumps({"TERM":sys.argv[2],"row0_text":scr.display[0][:45],"row0_col2":cell(0,2),"row1_col2":cell(1,2)}))
