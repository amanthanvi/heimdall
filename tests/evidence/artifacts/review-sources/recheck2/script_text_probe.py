"""For an HTML source: GET it (listed URL, same UA as the fetcher), then look for prose-like
word sequences inside <script>/<template>/<noscript> content that do not occur in the
normalizer's visible text. Such text is invisible to `compare` CONTENT detection: a change
there yields RAW_ONLY (exit 4, "text identical")."""
import importlib.util, json, re, sys
tool, pins_path, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
ids = sys.argv[4].split(",")
spec = importlib.util.spec_from_file_location("fp", tool)
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
pins = json.load(open(pins_path))
srcs = {s["id"]: s for s in pins["sources"] + pins.get("auxiliary_sources", [])}

class Grab(fp.html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.hidden = []
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "template", "noscript"):
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and tag == self.stack[-1]:
            self.stack.pop()
    def handle_data(self, data):
        if self.stack:
            self.hidden.append(data)

for i in ids:
    s = srcs[i]
    url = fp.fetch_url_for(s)
    r = fp.http_get(url)
    body = r["body"]
    open("%s/%s.body" % (out_dir, i), "wb").write(body)
    norm = fp.normalize(body, r["headers"].get("content-type", ""), url)
    vis = fp.loose(norm)
    g = Grab()
    g.feed(body.decode("utf-8", "replace"))
    hidden = " ".join(g.hidden)
    # unescape common JS string escapes so prose is comparable
    hidden = hidden.replace('\\"', '"').replace("\\n", " ").replace("\\u0026", "&")
    cands = re.findall(r"[A-Z][a-z]+(?: [a-zA-Z,'’()-]+){7,30}[.]", hidden)
    missing = []
    seen = set()
    for c in cands:
        lc = fp.loose(c)
        if len(lc) < 50 or lc in seen:
            continue
        seen.add(lc)
        if lc not in vis:
            missing.append(c)
    print("%s http=%s raw=%d norm_chars=%d hidden_chars=%d prose_candidates=%d not_in_visible=%d" % (
        i, r["status"], len(body), len(norm), len(hidden), len(seen), len(missing)))
    for m in missing[:4]:
        print("    e.g.", repr(m[:160]))
