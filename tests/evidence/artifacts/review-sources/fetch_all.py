import json,subprocess,hashlib,sys,re
d=json.load(open('docs/sources/pins.json'))
out=[]
for s in d['sources']:
    u=s.get('fetched_url') or s['url']
    p='/tmp/rs/%s.body'%s['id']
    r=subprocess.run(['curl','-sL','-m','60','-D','/tmp/rs/%s.hdr'%s['id'],'-o',p,'-w','%{http_code}',u],capture_output=True,text=True)
    b=open(p,'rb').read()
    out.append(dict(id=s['id'],url=u,http=r.stdout,rc=r.returncode,bytes=len(b),raw_sha=hashlib.sha256(b).hexdigest(),pinned_raw=s['pin'].get('raw_body_sha256')))
json.dump(out,open('tests/evidence/artifacts/review-sources/refetch.json','w'),indent=1)
for o in out: print(o['id'],o['http'],o['rc'],o['bytes'],o['raw_sha']==o['pinned_raw'],o['url'])
