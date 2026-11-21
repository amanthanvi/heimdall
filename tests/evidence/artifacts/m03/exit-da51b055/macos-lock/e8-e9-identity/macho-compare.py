# macho-compare.py A B: compare two arm64/x86_64 Mach-O 64 executables section by section, the
# non-debug symbol table, and report what differs (LC_UUID, stabs, code signature are reported apart).
import hashlib, struct, sys

def parse(path):
    data = open(path, "rb").read()
    magic, cpu, sub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from("<IiiIIIII", data, 0)
    assert magic == 0xFEEDFACF, hex(magic)
    off = 32
    secs, uuid, symtab, codesig = {}, None, None, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for i in range(nsects):
                sect = data[so:so + 16].rstrip(b"\0").decode()
                addr, sz, foff = struct.unpack_from("<QQI", data, so + 32)
                stype = struct.unpack_from("<I", data, so + 64)[0] & 0xFF
                zerofill = stype in (0x1, 0xC, 0x12)
                body = b"" if zerofill else data[foff:foff + sz]
                secs["%s,%s" % (segname, sect)] = (addr, sz, hashlib.sha256(body).hexdigest())
                so += 80
        elif cmd == 0x1B:
            uuid = data[off + 8:off + 24].hex()
        elif cmd == 0x2:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
            symtab = (symoff, nsyms, stroff, strsize)
        elif cmd == 0x1D:
            codesig = struct.unpack_from("<II", data, off + 8)
        off += size
    syms, stabs = [], []
    symoff, nsyms, stroff, strsize = symtab
    for i in range(nsyms):
        strx, ntype, nsect, ndesc, nvalue = struct.unpack_from("<IBBHQ", data, symoff + 16 * i)
        end = data.index(b"\0", stroff + strx)
        name = data[stroff + strx:end].decode("utf-8", "replace")
        (stabs if ntype & 0xE0 else syms).append((name, ntype, nsect, ndesc, nvalue))
    return {"sections": secs, "uuid": uuid, "syms": syms, "stabs": stabs, "codesig": codesig, "size": len(data)}

a, b = parse(sys.argv[1]), parse(sys.argv[2])
diff_secs = [s for s in sorted(set(a["sections"]) | set(b["sections"])) if a["sections"].get(s) != b["sections"].get(s)]
print("sections compared: %d; differing: %s" % (len(set(a["sections"]) | set(b["sections"])), ", ".join(diff_secs) or "none"))
for s in diff_secs:
    print("  %s A=%s B=%s" % (s, a["sections"].get(s), b["sections"].get(s)))
print("non-debug symbols: %d vs %d; identical: %s" % (len(a["syms"]), len(b["syms"]), a["syms"] == b["syms"]))
oso = lambda st: [x for x in st if x[1] == 0x66]  # N_OSO: object file path, n_value = its mtime
nos = lambda st: [(n, t, s, d, v) for (n, t, s, d, v) in st if t != 0x66]
print("debug-map stabs: %d vs %d; identical: %s; excluding N_OSO object timestamps: %s"
      % (len(a["stabs"]), len(b["stabs"]), a["stabs"] == b["stabs"],
         nos(a["stabs"]) == nos(b["stabs"])))
oa, ob = oso(a["stabs"]), oso(b["stabs"])
print("N_OSO entries: %d vs %d; same paths: %s; timestamps differing: %d"
      % (len(oa), len(ob), [x[0] for x in oa] == [x[0] for x in ob],
         sum(1 for x, y in zip(oa, ob) if x[4] != y[4])))
print("LC_UUID: %s vs %s" % (a["uuid"], b["uuid"]))
