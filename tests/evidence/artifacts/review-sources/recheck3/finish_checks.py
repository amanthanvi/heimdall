import pathlib,json,hashlib,importlib.util,subprocess,sys,re
D=pathlib.Path(__file__).parent
sp=importlib.util.spec_from_file_location('m','docs/sources/tools/fetch_pins.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
# Capture a narrower residual edge case separately from the fixed original n4 case.
x=b'<html><head><title>Title</title>Hello world</html>'
print('omitted head and body tags, direct body text:',repr(m.normalize(x,'text/html','u')),'expected visible text: Hello world')
h=json.loads((D/'reviewed-hashes.json').read_text()); drift=[f for f,v in h.items() if hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()!=v];print('reviewed files changed during review:',drift);assert not drift
rec=json.loads(pathlib.Path('tests/evidence/g04-macos-secure-enclave-ctk-probe.json').read_text());print('CTK status:',rec['status']);print('CTK blocked_on:',rec['blocked_on']);print('CTK relevant selected fields:')
def walk(o,path=''):
 if isinstance(o,dict):
  for k,v in o.items():
   if k in ('status','verdict','criterion') and isinstance(v,str):print(path+'.'+k+': '+v)
   elif isinstance(v,(dict,list)):walk(v,path+'.'+k)
 elif isinstance(o,list):
  for i,v in enumerate(o):walk(v,path+'.'+str(i))
walk(rec.get('observed',{}))
p=subprocess.run(['git','diff','--check'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);print('git diff --check exit',p.returncode);print(p.stdout.decode());assert p.returncode==0
# Remove personal checkout/interpreter prefixes from saved diagnostic text before publication.
for f in D.rglob('*'):
 if f.is_file() and f.suffix in ('.out','.json'):
  text=f.read_text();text=text.replace(str(pathlib.Path.cwd()),'<repo>').replace(str(pathlib.Path.home())+'/', '<home>/');f.write_text(text)
print('evidence sanitized; no scratch directories remain:',not any(p.is_dir() for p in D.iterdir()))
