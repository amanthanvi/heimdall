import fcntl, os, sys
out=[]
for fd in (0,1,2):
    try:
        fl=fcntl.fcntl(fd, fcntl.F_GETFL)
        out.append(f"fd{fd}:nonblock={bool(fl & os.O_NONBLOCK)}")
    except OSError as e:
        out.append(f"fd{fd}:err{e.errno}")
# also list open fds
fds=sorted(int(x) for x in os.listdir('/dev/fd'))
out.append("fds="+",".join(map(str,fds)))
out.append(f"pgid_eq_pid={os.getpgrp()==os.getpid()}")
sys.stderr.write(" ".join(out)+"\n")
