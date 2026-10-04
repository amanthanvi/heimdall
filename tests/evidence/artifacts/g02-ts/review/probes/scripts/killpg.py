import os, signal, subprocess, sys, time, json
B=sys.argv[1]; m="/tmp/hm-review-probes/killpg-marker"
try: os.unlink(m)
except FileNotFoundError: pass
child='import os,sys,time\nopen(sys.argv[1],"w").write(str(os.getpid()))\ntime.sleep(5)\n'
env={k:v for k,v in os.environ.items() if k!="SSH_AUTH_SOCK"}
res={}
for wrapper in ("proto","direct-sh"):
    try: os.unlink(m)
    except FileNotFoundError: pass
    argv=[B,"run","--","/usr/bin/python3","-c",child,m] if wrapper=="proto" else ["/bin/sh","-c",'/usr/bin/python3 -c "$0" "$1"; :',child,m]
    p=subprocess.Popen(argv,env=env,start_new_session=True,stdin=subprocess.DEVNULL)
    for _ in range(200):
        if os.path.exists(m) and open(m).read(): break
        time.sleep(0.01)
    cpid=int(open(m).read())
    os.killpg(p.pid, signal.SIGKILL)   # group kill, as CI job cancellation / supervisors do
    p.wait(); time.sleep(0.2)
    try: os.kill(cpid,0); alive=True
    except ProcessLookupError: alive=False
    res[wrapper]={"wrapper_rc":p.returncode,"child_alive_after_group_SIGKILL":alive}
    if alive: os.kill(cpid, signal.SIGKILL)  # exact pid we started
print(json.dumps(res))
