# Reviewer-chosen TOML shapes up to 1 MiB; wall time and peak RSS of profile show.
import json, os, platform, subprocess, sys, tempfile, time
P = sys.argv[1]; LIM = 1 << 20
HDR = 'schema_version = 1\nname = "x"\nrevision = 1\n'
def fill(prefix, unit, suffix=""):
    n = (LIM - len(prefix) - len(suffix)) // len(unit)
    return prefix + unit * n + suffix
shapes = {}
shapes["int_array_500k"] = fill(HDR + "[meta]\na = [", "1,", "1]\n")
shapes["str_array_short"] = fill(HDR + "[meta]\na = [", '"",', '""]\n')
shapes["flat_keys_meta"] = HDR + "[meta]\n" + "".join("k%06d = 1\n" % i for i in range(60000))
shapes["flat_keys_meta_65k_short"] = HDR + "[meta]\n" + "".join("%x=1\n" % i for i in range(70000))
shapes["inline_tables_array"] = fill(HDR + "[meta]\na = [", "{b=1},", "{b=1}]\n")
shapes["empty_arrays_array"] = fill(HDR + "[meta]\na = [", "[],", "[]]\n")
shapes["empty_inline_array"] = fill(HDR + "[meta]\na = [", "{},", "{}]\n")
shapes["nested31_arrays_repeat"] = fill(HDR + "[meta]\na = [", "[" * 30 + "]" * 30 + ",", "1]\n")
shapes["nested_inline_31"] = HDR + "[meta]\n" + "".join("k%d = " % i + "{a=" * 30 + "1" + "}" * 30 + "\n" for i in range(2000))
shapes["nested_inline_8000_round1"] = HDR + "[meta]\nx = " + "{a=" * 8000 + "1" + "}" * 8000 + "\n"
shapes["array_tables_meta"] = fill(HDR, "[[meta.t]]\n")
shapes["array_tables_with_key"] = fill(HDR, "[[meta.t]]\na=1\n")
shapes["subtables_unique"] = HDR + "".join("[meta.t%d]\n" % i for i in range(60000))
shapes["dotted_31_keys"] = HDR + "[meta]\n" + "".join(".".join("k%d" % j for j in range(30)) + "_%d = 1\n" % i for i in range(1000))
shapes["long_header_many_keys"] = HDR + "[meta." + ".".join(["h" * 3000] * 30) + "]\n" + "".join("k%d=1\n" % i for i in range(20000))
shapes["big_string"] = fill(HDR + '[meta]\ns = "', "a", '"\n')
shapes["escapes_string"] = fill(HDR + '[meta]\ns = "', "\\u0041", '"\n')
shapes["multiline_string_quotes"] = fill(HDR + '[meta]\ns = """', 'a""', 'a"""\n')
shapes["datetimes"] = fill(HDR + "[meta]\na = [", "1979-05-27T07:32:00Z,", "1979-05-27T07:32:00Z]\n")
shapes["floats"] = fill(HDR + "[meta]\na = [", "1.5e300,", "1.0]\n")
shapes["destinations_max"] = HDR + "".join('[[destinations]]\nid="d%d"\nalias="a%d"\nhost="h"\naccount="u"\n' % (i, i) for i in range(12000))
shapes["dup_key_late"] = HDR + "[meta]\n" + "".join("k%06d = 1\n" % i for i in range(60000)) + "k000000 = 2\n"
shapes["comments_only"] = fill(HDR, "#" * 99 + "\n")
shapes["crlf_lines"] = HDR.replace("\n", "\r\n") + "[meta]\r\n" + "".join("k%d=1\r\n" % i for i in range(60000))
shapes["near_units_inline3"] = HDR + "[meta]\na = [" + ",".join("{b=1,c=2,d=3}" for _ in range(16000)) + "]\n"
shapes["near_long_keys"] = HDR + "[meta]\n" + "".join("k%04d%s = 1\n" % (i, "x" * 990) for i in range(1000))
shapes["near_tiny_arrays"] = HDR + "[meta]\na = [" + ",".join("[1]" for _ in range(60000)) + "]\n"
shapes["near_nested31_repeat"] = HDR + "[meta]\na = [" + ",".join("[" * 30 + "1" + "]" * 30 for _ in range(2000)) + "]\n"
shapes["near_nested_inline_rep"] = HDR + "[meta]\n" + "".join("k%d = " % i + "{a=" * 15 + "1" + "}" * 15 + "\n" for i in range(2000))
shapes["near_quoted_unicode_keys"] = HDR + "[meta]\n" + "".join('"%s%d" = 1\n' % ("\u00e9" * 150, i) for i in range(1200))
res = {"platform": platform.system() + "-" + platform.machine(), "shapes": {}}
d = tempfile.mkdtemp()
worst = (0, 0)
for name, text in shapes.items():
    b = text.encode()
    if len(b) > LIM:
        b = b[:LIM]  # truncation may make it malformed; still a valid probe
    f = os.path.join(d, name + ".toml"); open(f, "wb").write(b)
    t0 = time.monotonic()
    so_f = open(os.path.join(d, name + ".out"), "wb+"); se_f = open(os.path.join(d, name + ".err"), "wb+")
    pr = subprocess.Popen([P, "profile", "show", "--file", f, "--json"], stdout=so_f, stderr=se_f)
    killed = False; rc = None; ru = None
    end = time.monotonic() + 20
    while True:
        pid, status, ru = os.wait4(pr.pid, os.WNOHANG)
        if pid: rc = os.waitstatus_to_exitcode(status); break
        if time.monotonic() > end:
            os.kill(pr.pid, 9); pid, status, ru = os.wait4(pr.pid, 0); rc = os.waitstatus_to_exitcode(status); killed = True; break
        time.sleep(0.002)
    pr.returncode = rc
    el = time.monotonic() - t0
    so_f.seek(0); so = so_f.read(); se_f.seek(0); se = se_f.read()
    rss_mib = ru.ru_maxrss / (1 << 20) if platform.system() == "Darwin" else ru.ru_maxrss / 1024
    res["shapes"][name] = {"bytes": len(b), "exit": pr.returncode, "elapsed_s": round(el, 3), "peak_rss_mib": round(rss_mib, 1), "k15_ok": (el < 2.0 and rss_mib < 256 and not killed and pr.returncode in (0, 2)), "killed": killed,
                            "code": (json.loads(so).get("code") if so else None), "stderr": se.decode()[:120]}
res["k15_violations"] = [k for k, v in res["shapes"].items() if not v["k15_ok"]]
print(json.dumps(res, indent=1))
sys.exit(1 if res["k15_violations"] else 0)
