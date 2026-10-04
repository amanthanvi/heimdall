import os, sys, subprocess, time, json, select
sys.path.insert(0, "<repo>/tests/g02")
m, s = os.openpty()
ctl_r, ctl_w = os.pipe(); st_r, st_w = os.pipe()
fwd = sys.argv[1] == "fwd"
p = subprocess.Popen([sys.executable, "<repo>/tests/g02/pty_shim.py", str(ctl_r), str(st_w)] + ([] if fwd else ["--no-hup-forward"]) + ["--"] + sys.argv[2:],
    stdin=s, stdout=s, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=(ctl_r, st_w))
os.close(ctl_r); os.close(st_w)
log = os.environ["PROBE_LOG"]
end = time.time() + 8
while time.time() < end:
    r,_,_ = select.select([m],[],[],0.05)
    if r:
        try: os.read(m, 65536)
        except OSError: pass
    if os.path.exists(log) and b"ready" in open(log,"rb").read(): break
time.sleep(0.3)
os.close(m)
buf=b""; end=time.time()+6; rc=None
while time.time()<end and rc is None:
    r,_,_=select.select([st_r],[],[],0.1)
    if r:
        buf+=os.read(st_r,4096)
        for line in buf.split(b"\n"):
            if b"exited" in line: rc=json.loads(line)["rc"]
print("rc", rc)
os.close(ctl_w); p.wait(timeout=5)
