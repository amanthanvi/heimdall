# Reviewer re-fetch (read-only GET). Run from repo root.
import json,subprocess,hashlib
d=json.load(open('docs/sources/pins.json'))
res=[]
for s in d['sources']:
    sid=s['id']; u=s.get('fetched_url') or s['url']
    p='tests/evidence/artifacts/review-sources/raw/%s.body'%sid
    h='tests/evidence/artifacts/review-sources/raw/%s.hdr'%sid
    r=subprocess.run(['curl','-sL','-m','60','-D',h,'-o',p,'-w','%{http_code}',u],capture_output=True,text=True)
    b=open(p,'rb').read()
    res.append(dict(id=sid,url=u,http=r.stdout,rc=r.returncode,bytes=len(b),raw_sha=hashlib.sha256(b).hexdigest(),pinned_raw=s['pin'].get('raw_body_sha256'),pinned_text=s['pin'].get('text_sha256')))
json.dump(res,open('tests/evidence/artifacts/review-sources/my_refetch.json','w'),indent=1)
for o in res: print(o['id'],o['http'],o['rc'],o['bytes'],'RAWMATCH' if o['raw_sha']==o['pinned_raw'] else 'rawdiff')
