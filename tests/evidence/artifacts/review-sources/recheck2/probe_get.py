import sys, time, urllib.request
url, ua = sys.argv[1], sys.argv[2]
t = time.time()
req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Encoding": "identity"}, method="GET")
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        b = r.read()
        print(r.status, len(b), "%.2fs" % (time.time() - t), r.headers.get("content-length"), r.headers.get("connection"))
except Exception as e:
    print("ERR", type(e).__name__, "%.2fs" % (time.time() - t))
