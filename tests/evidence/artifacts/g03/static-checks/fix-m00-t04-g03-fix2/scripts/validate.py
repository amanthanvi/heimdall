import json, glob, sys, hashlib, re
from jsonschema import Draft202012Validator
schema = json.load(open('tests/evidence/record.schema.json'))
v = Draft202012Validator(schema)
files = sorted(glob.glob('tests/evidence/g03-*.json')) + sorted(glob.glob('tests/evidence/artifacts/g03/harness-selftest/**/records/*.json', recursive=True))
bad = 0; conv = 0; hashed = 0
for f in files:
    d = json.load(open(f))
    errs = list(v.iter_errors(d))
    o = d.get('observed_result')
    # gate-probe convention checks (tests/evidence/README.md)
    if isinstance(o, dict):
        if o.get('verdict') not in ('pass', 'fail', 'inconclusive'): errs.append('verdict missing/invalid')
        if o.get('verdict') == 'inconclusive' and d['status'] != 'in_progress': errs.append('inconclusive must be in_progress')
        if o.get('verdict') in ('pass', 'fail') and d['status'] != 'verified': errs.append('pass/fail must be verified')
    if d['status'] == 'blocked' and (o is not None or not d.get('blocked_on')): errs.append('blocked needs null observed_result and blocked_on')
    if 'harness-selftest-' in d['case_id'] and d['requirement_ids']: errs.append('self-test record names requirement ids')
    h = d.get('environment', {}).get('harness') if f.startswith('tests/evidence/g03-') else None
    if h:
        sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()
        if sha(h['path']) != h['sha256']: errs.append('harness sha256 mismatch: ' + h['path'])
        for p, want in h.get("supporting_sha256", {}).items():
            if sha(p) != want: errs.append('supporting sha256 mismatch: ' + p)
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', d['environment'].get('recorded_at', '')): errs.append('recorded_at not an exact UTC timestamp')
        hashed += 1
    if errs:
        bad += 1; print('INVALID', f, [str(getattr(e, 'message', e)) for e in errs])
print('files=%d invalid=%d placeholders_hash_checked=%d' % (len(files), bad, hashed))
sys.exit(1 if bad else 0)
