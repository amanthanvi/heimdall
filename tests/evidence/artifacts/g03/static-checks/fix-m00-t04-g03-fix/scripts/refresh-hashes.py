import json, hashlib, glob, os
os.chdir('<home>/GitRepos/heimdall')
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
n = 0
for f in sorted(glob.glob('tests/evidence/g03-*.json')):
    d = json.load(open(f)); h = d['environment']['harness']
    h['sha256'] = sha(h['path'])
    h['supporting_sha256'] = {p: sha(p) for p in h['supporting_sha256']}
    open(f, 'w', encoding='utf-8').write(json.dumps(d, indent=2, ensure_ascii=False) + '\n'); n += 1
print('refreshed harness hashes in %d placeholder records' % n)
