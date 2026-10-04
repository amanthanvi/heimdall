import sys,re
f='raw/md_%s.md'%sys.argv[1]
t=re.sub(r'\s+',' ',open(f).read())
for pat in sys.argv[2:]:
    ms=list(re.finditer(pat,t,re.I))
    print('##',sys.argv[1],pat,len(ms))
    for m in ms[:2]: print('   ',t[max(0,m.start()-60):m.start()+350])
