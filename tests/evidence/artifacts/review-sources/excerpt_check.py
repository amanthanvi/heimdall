import json,re,html
from html.parser import HTMLParser
class T(HTMLParser):
    def __init__(s): super().__init__(); s.o=[]; s.skip=0
    def handle_starttag(s,t,a):
        if t in('script','style'): s.skip+=1
    def handle_endtag(s,t):
        if t in('script','style') and s.skip: s.skip-=1
    def handle_data(s,d):
        if not s.skip: s.o.append(d)
def text(b):
    t=b.decode('utf8','replace')
    p=T(); p.feed(t); x=' '.join(p.o)
    return re.sub(r'\s+',' ',html.unescape(x))
d=json.load(open('docs/sources/pins.json'))
frags=re.compile(r'"([^"]{12,})"')
for s in d['sources']:
    b=open('tests/evidence/artifacts/review-sources/raw/%s.body'%s['id'],'rb').read()
    tx=text(b)
    # also raw (for json embedded / markdown)
    raw=re.sub(r'\s+',' ',html.unescape(b.decode('utf8','replace')))
    res=[]
    for f in frags.findall(s['excerpt']):
        for piece in [x.strip() for x in f.split('...') if len(x.strip())>10]:
            piece=re.sub(r'\s+',' ',piece)
            res.append((piece[:50], piece in tx, piece in raw))
    print(s['id'],len(tx),res)
