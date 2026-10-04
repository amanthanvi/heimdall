# Refreshes the harness sha256 values in every blocked G03 placeholder and stamps recorded_at
# with the real UTC time of the refresh (M00-T04-G03-fix2). Status/observed_result untouched.
import json, hashlib, glob, os, sys, datetime
os.chdir(sys.argv[1])
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
n = 0
for f in sorted(glob.glob('tests/evidence/g03-*.json')):
    d = json.load(open(f)); h = d['environment']['harness']
    assert d['status'] == 'blocked' and d['observed_result'] is None, f
    h['sha256'] = sha(h['path'])
    h['supporting_sha256'] = {p: sha(p) for p in h['supporting_sha256']}
    d['environment']['recorded_at'] = now
    d['environment']['task'] = 'M00-T04-G03 (harness revised by M00-T04-G03-fix and M00-T04-G03-fix2)'
    open(f, 'w', encoding='utf-8').write(json.dumps(d, indent=2, ensure_ascii=False) + '\n'); n += 1
print('refreshed harness hashes in %d placeholder records at %s' % (n, now))
