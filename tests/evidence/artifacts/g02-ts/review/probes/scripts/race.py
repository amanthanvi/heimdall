import os, signal, subprocess, sys, time, json, collections
B=sys.argv[1]; SIG=getattr(signal, sys.argv[2]); reps=int(sys.argv[3])
child='import os,sys,time\nopen(sys.argv[1],"w").write(str(os.getpid()))\ntime.sleep(4)\n'
env={k:v for k,v in os.environ.items() if k!="SSH_AUTH_SOCK"}
res=collections.Counter(); bad=[]
for rep in range(reps):
  for d_ms in range(0,60,2):
    m=f"/tmp/hm-review-probes/race-marker"
    try: os.unlink(m)
    except FileNotFoundError: pass
    t0=time.monotonic()
    p=subprocess.Popen([B,"run","--","/usr/bin/python3","-c",child,m],env=env,stdin=subprocess.DEVNULL)
    time.sleep(d_ms/1000); p.send_signal(SIG)
    try: rc=p.wait(timeout=10)
    except subprocess.TimeoutExpired:
      p.kill(); rc=p.wait(); bad.append((d_ms,"timeout")); continue
    el=time.monotonic()-t0
    cpid=None
    for _ in range(20):
      if os.path.exists(m):
        s=open(m).read()
        if s: cpid=int(s); break
      time.sleep(0.01)
    alive=False
    if cpid:
      try: os.kill(cpid,0); alive=True
      except ProcessLookupError: pass
    if cpid is None: cls="no_child_started"
    elif alive: cls="ORPHAN_child_alive_after_proto_exit"
    elif el>3.5: cls="LOST_signal_child_ran_to_end"
    else: cls="delivered"
    res[(cls,rc)]+=1
    if cls.startswith(("ORPHAN","LOST")): bad.append((d_ms,cls,rc,round(el,3)))
    if alive:
      # we started this child (pid read from its own marker); reap it via signal to that exact pid
      os.kill(cpid, signal.SIGKILL)
print(json.dumps({"signal":sys.argv[2],"counts":{f"{k[0]} rc={k[1]}":v for k,v in res.items()},"bad":bad[:20]}))
