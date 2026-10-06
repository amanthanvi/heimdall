"""Print the DLL names in a PE32+ file's import directory. Usage: python3 -I pe_imports.py <exe>"""
import struct, sys
d = open(sys.argv[1], "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
opt = pe + 24
assert struct.unpack_from("<H", d, opt)[0] == 0x20B, "not PE32+"
imp_rva = struct.unpack_from("<I", d, opt + 112 + 8)[0]
secs = [struct.unpack_from("<8sIIII", d, opt + optsz + 40 * i) for i in range(nsec)]
def off(rva):
    for _n, vsz, va, rsz, raw in secs:
        if va <= rva < va + max(vsz, rsz):
            return raw + rva - va
    raise ValueError(rva)
o = off(imp_rva); names = []
while True:
    f = struct.unpack_from("<IIIII", d, o)
    if f == (0, 0, 0, 0, 0):
        break
    s = off(f[3]); names.append(d[s:d.index(b"\0", s)].decode())
    o += 20
print(" ".join(sorted(set(n.lower() for n in names))))
