import importlib.util,pathlib,json,difflib,concurrent.futures,gzip
D=pathlib.Path(__file__).parent
sp=importlib.util.spec_from_file_location('fp','docs/sources/tools/fetch_pins.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
p=json.loads(pathlib.Path('docs/sources/pins.json').read_text())
def one(s):
 r=m.http_get(m.fetch_url_for(s)); txt=m.normalize(r['body'],r['headers'].get('content-type',''),m.fetch_url_for(s)); fr=m.excerpt_fragments(s.get('excerpt')); loose=m.loose(txt)
 lines=[s['id']+' '+s.get('title',''), 'CLAIM: '+s.get('claim',''), 'PINNED EXCERPT: '+s.get('excerpt',''), 'LIVE: HTTP '+str(r['status'])]
 for f in fr:
  found=m.contains_words(loose,f);lines.append('FRAGMENT '+str(found)+': '+f)
  if found:
   pos=loose.find(m.loose(f));lines.append('CONTEXT: '+' '.join(loose[max(0,pos-220):pos+len(m.loose(f))+380].split()))
 snap=pathlib.Path('docs/sources/snapshots')/(s['id']+'.txt.gz')
 if snap.exists():
  old=gzip.decompress(snap.read_bytes()).decode().split(); new=txt.split(); ops=[(tag,' '.join(old[a:b])[:450],' '.join(new[c:d])[:450]) for tag,a,b,c,d in difflib.SequenceMatcher(None,old,new,autojunk=False).get_opcodes() if tag!='equal'];lines.append('CHANGE BLOCKS '+str(len(ops)));lines.extend(str(x) for x in ops[:12])
 if s.get('upstream'):
  r=m.http_get(s['upstream']['url']);text=r['body'].decode(errors='replace');lines.append('BRANCH '+str(r['status']))
  for f in fr:
   needle=m.loose(f);l=m.loose(text);pos=l.find(needle);lines.append('BRANCH FRAGMENT '+str(m.contains_words(l,f))+': '+f);lines.append('BRANCH CONTEXT: '+l[max(0,pos-180):pos+len(needle)+380] if pos>=0 else 'LOST')
  if s['id']=='S29':lines.extend(x for x in text.splitlines() if any(k in x.lower() for k in ['zig','bun','experimental','terminal']))
 return '\n'.join(lines)+'\n'
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
 for s,out in zip(p['sources']+p['auxiliary_sources'],ex.map(one,p['sources']+p['auxiliary_sources'])):(D/('claim-'+s['id']+'.out')).write_text(out)
print('38 sources: fresh GETs and contextual fragment/diff inspection saved; no bodies retained')
