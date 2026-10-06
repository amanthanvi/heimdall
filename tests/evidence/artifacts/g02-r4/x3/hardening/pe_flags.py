# Parse PE optional-header DllCharacteristics (read-only).
import struct, sys
F = {0x20:"HIGH_ENTROPY_VA",0x40:"DYNAMIC_BASE",0x80:"FORCE_INTEGRITY",0x100:"NX_COMPAT",0x200:"NO_ISOLATION",0x400:"NO_SEH",0x1000:"APPCONTAINER",0x4000:"GUARD_CF",0x8000:"TERMINAL_SERVER_AWARE"}
for label, p in zip(sys.argv[1::2], sys.argv[2::2]):
    b = open(p, "rb").read()
    pe = struct.unpack_from("<I", b, 0x3c)[0]
    machine, nsec, ts = struct.unpack_from("<HHI", b, pe + 4)
    chars = struct.unpack_from("<H", b, pe + 22)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    dllc = struct.unpack_from("<H", b, opt + 70)[0]
    # data directory 5 = base relocation table; PE32+ data dirs start at opt+112
    reloc_rva, reloc_sz = struct.unpack_from("<II", b, opt + 112 + 5 * 8)
    lc_rva, lc_sz = struct.unpack_from("<II", b, opt + 112 + 10 * 8)
    print(f"{label}: magic=0x{magic:x} TimeDateStamp=0x{ts:08x} RELOCS_STRIPPED={'yes' if chars & 1 else 'no'} reloc_dir_size={reloc_sz} load_config_size={lc_sz} DllCharacteristics=0x{dllc:04x} [{', '.join(v for k, v in F.items() if dllc & k)}]")
