import os, pty, sys, time, select, json, struct, fcntl, termios
B=sys.argv[1]; D="/tmp/hm-review-probes/otui"
PROF="<repo>/tests/fixtures/g02/profiles/homelab.toml"
def session(extra_env, cwd):
    os.makedirs(cwd, exist_ok=True)
    before=set(os.listdir(cwd))
    pid, fd = pty.fork()
    if pid==0:
        os.chdir(cwd)
        env={"PATH":"/usr/bin:/bin","HOME":cwd,"TERM":"xterm-256color","TMPDIR":cwd+"/"}
        env.update(extra_env)
        os.execve(B,[B,"tui","--file",PROF],env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH",24,80,0,0))
    out=b""; t0=time.monotonic(); step=0
    while time.monotonic()-t0<6:
        r,_,_=select.select([fd],[],[],0.05)
        if r:
            try: out+=os.read(fd,65536)
            except OSError: break
        el=time.monotonic()-t0
        if step==0 and el>0.8: os.write(fd,b"/hunter2-SECRET"); step=1
        elif step==1 and el>1.4: os.write(fd,b"\x1b"); step=2
        elif step==2 and el>1.9: os.write(fd,b"q"); step=3
        w=os.waitpid(pid,os.WNOHANG)
        if w[0]==pid: break
    else:
        w=(0,0)
    rc=os.waitstatus_to_exitcode(w[1]) if w[0]==pid else None
    after=set(os.listdir(cwd))
    new=sorted(after-before)
    return rc,new
res={}
for name,env in [("baseline",{}),("OTUI_STDIN_LOG",{"OTUI_STDIN_LOG":D+"/stdin-capture.log"}),("OTUI_DEBUG_FFI",{"OTUI_DEBUG_FFI":"1"}),("OTUI_DUMP_CAPTURES",{"OTUI_DUMP_CAPTURES":"1"})]:
    cwd=f"{D}/cwd-{name}"
    rc,new=session(env,cwd)
    entry={"rc":rc,"new_files_in_cwd":new}
    if name=="OTUI_STDIN_LOG":
        p=D+"/stdin-capture.log"
        if os.path.exists(p):
            data=open(p,"rb").read()
            entry["capture_file_exists"]=True; entry["capture_bytes"]=len(data); entry["capture_contains_typed_secret"]=b"hunter2-SECRET" in data
            entry["capture_mode"]=oct(os.stat(p).st_mode & 0o777)
        else: entry["capture_file_exists"]=False
    if name=="OTUI_DEBUG_FFI":
        entry["ffi_log_sizes"]={f:os.path.getsize(os.path.join(cwd,f)) for f in new}
    res[name]=entry
print(json.dumps(res,indent=1))
