import os,sys,json,subprocess,pathlib,concurrent.futures,tempfile,shutil,hashlib
D=pathlib.Path('tests/evidence/artifacts/review-sources/recheck3'); T='docs/sources/tools/fetch_pins.py'; PY='/opt/homebrew/bin/python3.13'
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'); env.pop('SSH_AUTH_SOCK',None)
def run(name,args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env)
 out=p.stdout.decode(errors='replace').replace(str(pathlib.Path.cwd()),'<repo>')
 (D/(name+'.out')).write_text('$ '+ ' '.join(args)+'\n'+out+'\nexit='+str(p.returncode)+'\n')
 print(name,p.returncode,flush=True); return p.returncode
def tool(name,*args,py=PY):return run(name,[py,'-I',T,*args])
pins=json.loads(pathlib.Path('docs/sources/pins.json').read_text())
files=[T,'docs/sources/pins.json','docs/sources/README.md','docs/decisions/0003-source-pins.md','docs/compatibility/matrix.md','tests/evidence/g04-macos-secure-enclave-ctk-probe.json','plan.md']
(D/'reviewed-hashes.json').write_text(json.dumps({f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest() for f in files},indent=2))
run('inspection',['git','diff','HEAD','--','docs/sources','docs/decisions/0003-source-pins.md','docs/compatibility/matrix.md'])
run('versions',[PY,'-I','-c','import sys,ssl; print(sys.version); print(ssl.OPENSSL_VERSION)'])
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
 jobs=[ex.submit(tool,'selftest','selftest'),ex.submit(tool,'excerpts-local','excerpts','--set','all'),ex.submit(tool,'excerpts-git','excerpts','--set','all','--fetch-git'),ex.submit(tool,'tags','tags','--out',str(D/'tags.json')),ex.submit(tool,'upstream','upstream','--out',str(D/'upstream.json'))]
 for f in jobs:f.result()
for s in pins['sources']+pins['auxiliary_sources']:
 snap=s.get('pin_v2',{}).get('snapshot')
 if snap:
  print('SNAP SHAPE',type(snap).__name__,flush=True);break
scratch=pathlib.Path(tempfile.mkdtemp(prefix='scratch-',dir=D))
try:
 tool('fetch-live','fetch','--set','all','--out',str(D/'fresh.json'),'--snapshots-dir',str(scratch),'--snapshot-ids',','.join(s['id'] for s in pins['sources']+pins['auxiliary_sources']))
 tool('compare-live','compare','docs/sources/fetch-baseline.json',str(D/'fresh.json'),'--all')
 tool('compare-aux-live','compare','docs/sources/fetch-baseline-aux.json',str(D/'fresh.json'),'--all')
 tool('compare-fresh-fresh','compare',str(D/'fresh.json'),str(D/'fresh.json'))
 # Keep no downloaded snapshots, bodies, or scratch runtime material.
finally:shutil.rmtree(scratch)
for s in pins['sources']+pins['auxiliary_sources']:
 path=pathlib.Path('docs/sources/snapshots')/(s['id']+'.txt.gz')
 if path.exists():tool('verify-'+s['id'],'verify','--fetch-result','docs/sources/fetch-baseline-aux.json' if s['id'].startswith('A') else 'docs/sources/fetch-baseline.json','--id',s['id'],'--snapshot',str(path))
