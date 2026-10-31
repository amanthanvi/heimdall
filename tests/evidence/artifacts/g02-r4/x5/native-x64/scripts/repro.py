import struct,sys,hashlib
def pe(p):
    b=bytearray(open(p,'rb').read()); o=struct.unpack_from('<I',b,0x3c)[0]
    ts=struct.unpack_from('<I',b,o+8)[0]; struct.pack_into('<I',b,o+8,0)
    return ts,b
def comment(p):
    b=open(p,'rb').read(); shoff=struct.unpack_from('<Q',b,0x28)[0]; es,n,si=struct.unpack_from('<HHH',b,0x3a)
    secs=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*es) for i in range(n)]; so=secs[si][4]
    for s in secs:
        nm=b[so+s[0]:b.index(b'\0',so+s[0])]
        if nm==b'.comment': return [x.decode() for x in b[s[4]:s[4]+s[5]].split(b'\0') if x]
mode=sys.argv[1]
if mode=='pe':
    (t1,b1),(t2,b2)=pe(sys.argv[2]),pe(sys.argv[3])
    print(f'first   build TimeDateStamp={t1} sha256(TimeDateStamp zeroed)={hashlib.sha256(b1).hexdigest()}')
    print(f'rebuild build TimeDateStamp={t2} sha256(TimeDateStamp zeroed)={hashlib.sha256(b2).hexdigest()}')
    print('bytes differing after zeroing:', sum(1 for x,y in zip(b1,b2) if x!=y), 'lengths', len(b1), len(b2))
else:
    for p in sys.argv[2:]: print(p.split('/bin/')[-1], comment(p))
