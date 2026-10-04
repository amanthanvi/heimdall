import json, glob, sys
from jsonschema import Draft202012Validator
schema = json.load(open('tests/evidence/record.schema.json'))
v = Draft202012Validator(schema)
files = sorted(glob.glob('tests/evidence/g03-*.json')) + sorted(glob.glob('tests/evidence/artifacts/g03/harness-selftest/**/records/*.json', recursive=True))
bad = 0; conv = 0
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
    if errs:
        bad += 1; print('INVALID', f, [str(getattr(e, 'message', e)) for e in errs])
print('files=%d invalid=%d' % (len(files), bad))
sys.exit(1 if bad else 0)
