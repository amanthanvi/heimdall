import sys,importlib.util,pathlib,json,tempfile,subprocess,os,shutil,time
D=pathlib.Path(__file__).parent; spec=importlib.util.spec_from_file_location('fetchpins','docs/sources/tools/fetch_pins.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Each CLI invocation is a fresh process; only HTTP responses are replaced with disposable fixtures.
if len(sys.argv)>1:
 mode=sys.argv[1]; p=pathlib.Path(sys.argv[2]); body=b'A quoted claim remains here.'
 status=404 if 'gone' in mode else 403 if 'failed' in mode else 200
 if 'deadline' in mode:
  class Slow:
   def open(self,*a,**k):time.sleep(3);raise TimeoutError()
  m._OPENER=Slow();m.DEADLINE_GRACE_S=.05
 else:
  m.http_get=lambda url,**kw:dict(status=status,headers={},body=body,final_url=url)
 if mode.startswith('fetch'):sys.argv=['fetch_pins.py','fetch','--pins',str(p),'--out',str(p.parent/'out.json'),'--deadline','.05']
 else:sys.argv=['fetch_pins.py','upstream','--pins',str(p)]
 m.main()
 raise SystemExit('unreachable')
E=dict(os.environ,PYTHONDONTWRITEBYTECODE='1');E.pop('SSH_AUTH_SOCK',None)
checks=[]
def run(name,args,want):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=E);out=p.stdout.decode().replace(str(pathlib.Path.cwd()),'<repo>')
 (D/(name+'.out')).write_text('$ '+' '.join(args)+'\n'+out+'\nexit='+str(p.returncode)+'\n');assert p.returncode==want,(name,p.returncode,want);checks.append((name,p.returncode))
def check(name,actual,want):assert actual==want,(name,actual,want);checks.append((name,actual))
scratch=pathlib.Path(tempfile.mkdtemp(prefix='crafted-',dir=D))
try:
 base=dict(id='S1',http_status=200,raw_body_sha256='r',normalized_text_sha256='n',markers={})
 a=scratch/'a.json';b=scratch/'b.json';pin=scratch/'pins.json'
 def result(path,rows):path.write_text(json.dumps(dict(results=rows)))
 result(a,[base]); pin.write_text(json.dumps(dict(sources=[dict(id='S1',pin_v2=dict(primary='raw_body_sha256',raw_body_sha256='r'))])))
 for name,rows,want in [('same',[base],0),('raw-onpin',[base],4),('offpin',[dict(base,raw_body_sha256='other')],5),('failed',[dict(base,http_status=503)],3),('content',[dict(base,normalized_text_sha256='changed')],2),('gone404',[dict(base,http_status=404)],2),('gone410',[dict(base,http_status=410)],2),('missing',[],2)]:
  result(b,rows)
  # RAW_ONLY on-pin uses a reference with different raw bytes and a candidate reproducing its pin.
  result(a,[dict(base,raw_body_sha256='older')] if name=='raw-onpin' else [base])
  run('crafted-compare-'+name,[sys.executable,'-I','docs/sources/tools/fetch_pins.py','compare',str(a),str(b),'--pins',str(pin)],want)
 # Mixed precedence at the real CLI boundary.
 rows=[dict(base,id='S'+str(i)) for i in range(5)]; result(a,rows)
 for name,statuses,want in [('all',[dict(rows[0],normalized_text_sha256='new'),dict(rows[1],http_status=503),dict(rows[2],raw_body_sha256='new'),rows[3],rows[4]],2),('failure',[rows[0],dict(rows[1],http_status=503),dict(rows[2],raw_body_sha256='new'),rows[3],rows[4]],3),('offpin',[rows[0],rows[1],dict(rows[2],raw_body_sha256='new'),rows[3],rows[4]],5)]:
  pin.write_text(json.dumps(dict(sources=[dict(id=x['id'],pin_v2=dict(primary='raw_body_sha256',raw_body_sha256='r')) for x in rows])));result(b,statuses)
  run('crafted-precedence-'+name,[sys.executable,'-I','docs/sources/tools/fetch_pins.py','compare',str(a),str(b),'--pins',str(pin)],want)
 body=b'A quoted claim remains here.'
 source=dict(id='S1',url='https://github.com/example/repo',pin=dict(permalink='https://github.com/example/repo/blob/'+'a'*40+'/README.md',blob_sha=m.git_blob_sha1(body),path='README.md'),upstream=dict(url='https://raw.githubusercontent.com/example/repo/HEAD/README.md',ref='HEAD'),excerpt='"A quoted claim remains here"')
 for mode,want in [('fetch-ok',0),('fetch-mismatch',2),('fetch-failed',3),('fetch-deadline',3),('upstream-same',0),('upstream-drift',4),('upstream-lost',2),('upstream-noquotes',2),('upstream-gone',2),('upstream-failed',3)]:
  s=json.loads(json.dumps(source))
  if mode in ['fetch-mismatch','upstream-drift','upstream-lost','upstream-noquotes']:s['pin']['blob_sha']='b'*40
  if mode=='upstream-lost':s['excerpt']='"An entirely different long quote"'
  if mode=='upstream-noquotes':s['excerpt']='no quoted fragment'
  pin.write_text(json.dumps(dict(sources=[s])))
  run('crafted-'+mode,[sys.executable,'-I',__file__,mode,str(pin)],want)
 for rows,want in [([dict(result='drifted',fragments_total=1,fragments_found=0),dict(result='fetch_failed')],2),([dict(result='drifted',fragments_total=1,fragments_found=1),dict(result='fetch_failed')],3),([dict(result='gone'),dict(result='fetch_failed')],2)]:check('upstream mixed precedence',m.upstream_exit(rows),want)
 check('fetch mismatch beats failure',m.fetch_exit([dict(base,git_blob_matches_pin=False),dict(base,http_status=503)])[0],2)
 for text,want in [('<head><title>x</title><body><p>Body preserved</p>','Body preserved'),('<head><title>x</title><p>Body preserved</p>','Body preserved'),('<head><script>hidden</script><style>hidden</style><body>Body preserved','Body preserved')]:check('omitted head',m.normalize(text.encode(),'text/html','u'),want)
 check('word end',m.contains_words(m.loose('not permitted by defaults'),'not permitted by default'),False)
 check('word start',m.contains_words(m.loose('xthis is allowed'),'this is allowed'),False)
 check('word valid',m.contains_words(m.loose('This is *allowed*.'),'this is allowed'),True)
finally:shutil.rmtree(scratch)
(D/'crafted-summary.json').write_text(json.dumps(checks,indent=2));print(json.dumps(checks));print('all independent assertions passed')
