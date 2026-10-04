# Crafted SSH-agent responses against heimdall-proto agent list. Loopback AF_UNIX only.
import os, socket, struct, subprocess, sys, threading, time, json, resource
B=sys.argv[1]; D="/tmp/hm-review-probes/agent"
def s(b): return struct.pack(">I",len(b))+b
def blob(kt=b"ssh-ed25519", extra=b"\x00"*36): return s(kt)+s(extra) if extra is not None else s(kt)
def frame(body): return struct.pack(">I",len(body))+body
def ident(keys): return frame(bytes([12])+struct.pack(">I",len(keys))+b"".join(s(k)+s(c) for k,c in keys))
big_kblob = None
def exact_max():
    # body = 1(type)+4(nkeys)+4+len(blob)+4+len(comment) = 262144
    comment=b"c"
    bl_len=262144-1-4-4-4-len(comment)
    kt=b"ssh-ed25519"; filler=bl_len-4-len(kt)-4
    bl=s(kt)+s(b"\x00"*filler); assert len(bl)==bl_len
    f=ident([(bl,comment)]); assert len(f)==4+262144; return f
cases = {
 "len_ffffffff":       [struct.pack(">I",0xFFFFFFFF)],
 "len_262145":         [struct.pack(">I",262145)+b"\x0c"],
 "len_exact_max_ok":   [exact_max()],
 "nkeys_ffffffff":     [frame(bytes([12])+struct.pack(">I",0xFFFFFFFF))],
 "nkeys_1024_ok":      [ident([(blob(),b"k%d"%i) for i in range(1024)])],
 "nkeys_1025":         [ident([(blob(),b"k") for i in range(1025)])],
 "strlen_ffffffff":    [frame(bytes([12])+struct.pack(">I",1)+struct.pack(">I",0xFFFFFFFF))],
 "inner_keytype_overrun":[ident([(struct.pack(">I",1000)+b"ssh",b"c")])],
 "blob_lt4":           [ident([(b"\x00\x00",b"c")])],
 "empty_keytype":      [ident([(s(b""),b"c")])],
 "trailing_same_write":[ident([(blob(),b"c")])+b"\x00\x00\x00\x01\x05"],
 "trailing_later_write":[ident([(blob(),b"c")]), b"\x00\x00\x00\x01\x05"],
 "byte_by_byte_ok":    ["BYTEWISE", ident([(blob(),b"c")])],
 "success_type6":      [frame(b"\x06")],
 "failure_len1":       [frame(b"\x05")],
 "failure_len5":       [frame(b"\x05\x00\x00\x00\x00")],
 "zero_len_frame":     [frame(b"")],
 "slowloris_header_then_drip":["DRIP", struct.pack(">I",100)+b"\x0c"],
 "control_and_invalid_comment":[ident([(blob(b"ssh-\x1b[31med"),b"a\x1b]0;x\x07\xff\xc2\x85\xe2\x80\xa8z")])],
 "respond_then_hold_open":["HOLD", ident([(blob(),b"c")])],
}
def serve(path, plan, rec):
    srv=socket.socket(socket.AF_UNIX); srv.bind(path); srv.listen(1); srv.settimeout(8)
    try:
        c,_=srv.accept()
    except socket.timeout:
        rec["accepted"]=False; return
    c.settimeout(0.5); got=b""
    try:
        while len(got)<5:
            x=c.recv(64)
            if not x: break
            got+=x
    except socket.timeout: pass
    rec["request_hex"]=got.hex()
    try:
        if plan[0]=="BYTEWISE":
            for b in plan[1]: c.send(bytes([b])); time.sleep(0.0005)
        elif plan[0]=="DRIP":
            c.send(plan[1])
            for i in range(40): time.sleep(0.1); c.send(b"\x00")
        elif plan[0]=="HOLD":
            c.send(plan[1]); time.sleep(3)
        else:
            for i,chunk in enumerate(plan):
                if i: time.sleep(0.05)
                c.sendall(chunk)
            time.sleep(0.3)
        c.settimeout(0.2)
        try:
            extra=c.recv(64); rec["extra_after"]=extra.hex()
        except Exception: pass
    except (BrokenPipeError, ConnectionResetError) as e:
        rec["server_send_error"]=type(e).__name__
    finally:
        c.close(); srv.close()
results={}
env={k:v for k,v in os.environ.items() if k!="SSH_AUTH_SOCK"}
for name,plan in cases.items():
    path=f"{D}/s {name[:20]} ü.sock"
    try: os.unlink(path)
    except FileNotFoundError: pass
    rec={}
    t=threading.Thread(target=serve,args=(path,plan,rec)); t.start(); time.sleep(0.05)
    t0=time.monotonic()
    p=subprocess.run(["/usr/bin/time","-l",B,"agent","list","--socket",path,"--timeout-ms","1500","--json"],capture_output=True,env=env,timeout=20)
    el=round((time.monotonic()-t0)*1000)
    t.join()
    try: os.unlink(path)
    except FileNotFoundError: pass
    rss=None
    for line in p.stderr.decode(errors="replace").splitlines():
        if "maximum resident set size" in line: rss=int(line.split()[0])//1024
    try:
        j=json.loads(p.stdout); code=j["code"]; extra=j["data"]
    except Exception: code=None; extra=p.stdout[:200].decode(errors="replace")
    results[name]={"rc":p.returncode,"code":code,"ms":el,"maxrss_kib":rss,"request_hex":rec.get("request_hex"),
                   "data": extra if name in ("control_and_invalid_comment","empty_keytype") else None,
                   "server": {k:v for k,v in rec.items() if k!="request_hex"} or None}
print(json.dumps(results, indent=1, ensure_ascii=True))
