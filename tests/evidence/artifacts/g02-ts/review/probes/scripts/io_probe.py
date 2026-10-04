# Drives heimdall-proto run with: slow stdin writer (EOF propagation), 8 MiB stdout read slowly,
# 4 MiB stderr written while stdout is not being read. Checks byte integrity via sha256.
import hashlib, os, subprocess, sys, threading, time
B=sys.argv[1]
child = r'''
import sys, os, hashlib
data = sys.stdin.buffer.read()            # must see EOF
h = hashlib.sha256(data).hexdigest()
err = bytes(range(256))*16384             # 4 MiB stderr first, while parent is not reading stdout
os.write(2, b"")
sys.stderr.buffer.write(err); sys.stderr.flush()
out = (bytes(range(256))*32768)           # 8 MiB stdout
sys.stdout.buffer.write(out); sys.stdout.flush()
sys.stderr.buffer.write(("\nIN:"+h+"\n").encode()); sys.stderr.flush()
'''
env={k:v for k,v in os.environ.items() if k!="SSH_AUTH_SOCK"}
p=subprocess.Popen([B,"run","--","/usr/bin/python3","-c",child],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
inp=os.urandom(3_000_000)+b"\x00\xff\xfe"
def w():
    for i in range(0,len(inp),65536):
        p.stdin.write(inp[i:i+65536]); p.stdin.flush(); time.sleep(0.005)
    time.sleep(0.5); p.stdin.close()
errbuf=bytearray()
def r_err():
    while True:
        c=p.stderr.read(65536)
        if not c: break
        errbuf.extend(c)
t1=threading.Thread(target=w); t2=threading.Thread(target=r_err); t1.start(); t2.start()
# Do not read stdout for 2 s while stderr is being produced, then read slowly
time.sleep(2.0)
outbuf=bytearray()
while True:
    c=p.stdout.read(4096)
    if not c: break
    outbuf.extend(c)
    if len(outbuf) % (1<<20) < 4096: time.sleep(0.01)
t1.join(); t2.join(); rc=p.wait()
exp_err=bytes(range(256))*16384
exp_out=bytes(range(256))*32768
print("rc",rc)
print("stdout_ok", bytes(outbuf)==exp_out, len(outbuf))
print("stderr_prefix_ok", bytes(errbuf[:len(exp_err)])==exp_err)
print("stdin_sha_match", ("IN:"+hashlib.sha256(inp).hexdigest()).encode() in errbuf)
