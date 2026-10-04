import sys,re,html
sys.path.insert(0,'.')
from html.parser import HTMLParser
class T(HTMLParser):
    def __init__(s): super().__init__(); s.o=[]; s.skip=0
    def handle_starttag(s,t,a):
        if t in('script','style'): s.skip+=1
    def handle_endtag(s,t):
        if t in('script','style') and s.skip: s.skip-=1
    def handle_data(s,d):
        if not s.skip: s.o.append(d)
def text(sid):
    b=open('raw/%s.body'%sid,'rb').read().decode('utf8','replace')
    p=T(); p.feed(b); return re.sub(r'\s+',' ',html.unescape(' '.join(p.o)))
sid,pat=sys.argv[1],sys.argv[2]; w=int(sys.argv[3]) if len(sys.argv)>3 else 300
t=text(sid)
for m in list(re.finditer(pat,t,re.I))[:4]:
    print('...',t[max(0,m.start()-w//3):m.start()+w],'\n')
