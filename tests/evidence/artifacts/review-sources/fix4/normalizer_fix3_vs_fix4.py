#!/usr/bin/env python3
"""M00-T02-fix4 (R3-1): does the revised normalizer give the same text as the fix3 normalizer (and as the
committed 3622c56 one) for every pinned source as the pages are served now, and is the second (implied-head) pass
ever run on a real source?

Usage (repository root): <python> -I -B normalizer_fix3_vs_fix4.py <scratch_dir>
  - fix3 module: rebuilt in <scratch_dir> from the current docs/sources/tools/fetch_pins.py by undoing the four
    fix4 edits (HEAD_TAGS line, _TextExtractor class, docstring paragraph, selftest block). The result must have
    sha256 bc369c6d... (the file hash recheck3 recorded in reviewed-hashes.json); otherwise the script stops.
  - 3622c56 module: `git show 3622c56:docs/sources/tools/fetch_pins.py` into <scratch_dir>.
  - Each of the 38 sources (S01-S34, A01-A04) is fetched once with the revised tool's fetch_url_for() and
    http_get() (GET, https only) and normalized by all three modules. "second_pass" says whether the revised
    normalizer had to parse the document a second time (a <head> without </head>); where it is "no", the
    document cannot be affected by the implied-head rule at all.
  - Offline part: synthetic documents, fix3 -> fix4.
Exit 0 = no difference on any live source and every fetch worked; 1 = a difference or a failed fetch;
2 = the rebuilt fix3 file does not have the recorded hash.
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys

scr = sys.argv[1]
os.makedirs(scr, exist_ok=True)
sys.path.insert(0, "docs/sources/tools")
import fetch_pins as new  # noqa: E402

CUR = open("docs/sources/tools/fetch_pins.py", encoding="utf-8").read()

# (fix4 text, fix3 text) pairs, each present exactly once in the current file
EDITS = [
    ('HEAD_TAGS = {"head", "title", "meta", "link", "base", "script", "style", "noscript", "template"}\n'
     'HTML_SPACE = " \\t\\n\\f\\r"  # the HTML whitespace characters; character data other than these implies </head><body>\n',
     'HEAD_TAGS = {"head", "title", "meta", "link", "base", "script", "style", "noscript", "template"}\n'),
    ('''        self.head_open = False  # a <head> was opened and no </head> has closed it
        self.title_open = False  # a <title> is open directly in the head (second pass only)

    def _head_only_open(self):
        # Second pass only (document without </head>): skip == 1 means that only the head itself
        # is open (no script/style/noscript/template/svg inside it).
        return self.implied_head_end and self.head_open and self.skip == 1

    def _end_head_if_implied(self, tag):
        if self._head_only_open() and tag not in HEAD_TAGS:
            self.skip = 0
            self.head_open = False

    def handle_starttag(self, tag, attrs):
        self._end_head_if_implied(tag)
        if tag == "title" and self._head_only_open():
            self.title_open = True
        if tag in SKIP_TAGS:''',
     '''        self.head_open = False  # a <head> was opened and no </head> has closed it

    def _end_head_if_implied(self, tag):
        # Second pass only (document without </head>): skip == 1 means that only the head itself
        # is open (no script/style/noscript/template/svg inside it).
        if self.implied_head_end and self.head_open and self.skip == 1 and tag not in HEAD_TAGS:
            self.skip = 0
            self.head_open = False

    def handle_starttag(self, tag, attrs):
        self._end_head_if_implied(tag)
        if tag in SKIP_TAGS:'''),
    ('''    def handle_endtag(self, tag):
        if tag == "title":
            self.title_open = False
        if tag in SKIP_TAGS and self.skip:''',
     '''    def handle_endtag(self, tag):
        if tag in SKIP_TAGS and self.skip:'''),
    ('''    def handle_data(self, data):
        # R3-1 (fix4): text in the head, outside <title> and outside script/style/noscript/template, is body text
        # (an HTML parser's implied </head><body>). Only HTML whitespace (tab, LF, FF, CR, space) is ignored there.
        if self._head_only_open() and not self.title_open and data.strip(HTML_SPACE):
            self.skip = 0
            self.head_open = False
        if not self.skip:''',
     '''    def handle_data(self, data):
        if not self.skip:'''),
    ('''     The head ends at </head>. If the document has a <head> but no </head>
     at all, it is parsed again and the head ends, as an HTML parser's
     implied </head><body> would end it, at the first start tag that cannot
     be in a head (anything but title, meta, link, base, script, style,
     noscript, template), which includes <body>, or at the first character
     data other than HTML whitespace (tab, LF, FF, CR, space) that is
     outside <title> and outside an open script, style, noscript or template
     element; that character data is kept. Text inside <title> and inside a
     script, style, noscript or template element that is open in the head
     stays dropped.
     (fix3: before, such a document normalized to the empty string. fix4: the
     character-data end was missing, so <head><title>T</title>Hello</html>
     still normalized to the empty string. The output is unchanged for every
     document whose head is closed or absent, so NORMALIZER_VERSION stays 1.)''',
     '''     The head ends at </head>. If the document has a <head> but no </head>
     at all, it is parsed again and the head ends at the first start tag that
     cannot be in a head (anything but title, meta, link, base, script, style,
     noscript, template), which includes <body>; text inside a script, style,
     noscript or template element that is open in the head stays dropped.
     (fix3: before, such a document normalized to the empty string. The
     output is unchanged for every document whose head is closed or absent,
     so NORMALIZER_VERSION stays 1.)'''),
]
# selftest block added in fix4: from the "R3-1 (fix4)" comment up to (not including) the closed-head v1-rule comment
a = CUR.index("    # R3-1 (fix4): character data outside the head-only elements")
b = CUR.index("    # the v1 rule is kept for every document that has </head>")
fix3 = CUR[:a] + CUR[b:]
for n4, n3 in EDITS:
    assert fix3.count(n4) == 1, "edit target not found exactly once: " + n4[:60]
    fix3 = fix3.replace(n4, n3)
h = hashlib.sha256(fix3.encode("utf-8")).hexdigest()
want = json.load(open("tests/evidence/artifacts/review-sources/recheck3/reviewed-hashes.json"))["docs/sources/tools/fetch_pins.py"]
print("rebuilt fix3 file sha256 %s %s" % (h, "== recorded by recheck3" if h == want else "!= recorded by recheck3 (%s)" % want))
if h != want:
    sys.exit(2)

paths = {"fix3": os.path.join(scr, "fetch_pins_fix3.py"), "old": os.path.join(scr, "fetch_pins_3622c56.py")}
open(paths["fix3"], "w", encoding="utf-8").write(fix3)
with open(paths["old"], "wb") as f:
    f.write(subprocess.run(["git", "show", "3622c56:docs/sources/tools/fetch_pins.py"], check=True, capture_output=True).stdout)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


m3, mold = load("fp_fix3", paths["fix3"]), load("fp_old", paths["old"])

print("python", sys.version.split()[0])
bad = 0
second_pass_runs = 0
pins = json.load(open("docs/sources/pins.json"))
for s in pins["sources"] + pins["auxiliary_sources"]:
    url = new.fetch_url_for(s)
    r = new.http_get(url)
    if r["status"] != 200:
        print(s["id"], "FETCH", r["status"], r.get("error", ""))
        bad += 1
        continue
    ct = r["headers"].get("content-type", "")
    is_html = "html" in ct.lower() or (not ct and url.lower().endswith((".html", "/")))
    second = False
    if is_html:
        _, unclosed = new._html_text(r["body"].decode("utf-8", errors="replace"), False)
        second = unclosed
        second_pass_runs += unclosed
    n4, n3, n1 = new.normalize(r["body"], ct, url), m3.normalize(r["body"], ct, url), mold.normalize(r["body"], ct, url)
    same = n4 == n3 == n1
    bad += 0 if same else 1
    print(s["id"], "html" if is_html else "other", "second_pass=%s" % ("yes" if second else "no"),
          "chars 3622c56=%d fix3=%d fix4=%d" % (len(n1), len(n3), len(n4)), "SAME" if same else "DIFFERENT")
print("sources whose document has a <head> without </head> (second pass runs): %d" % second_pass_runs)

print("-- synthetic documents (fix3 -> fix4)")
docs = {
    "R3-1: text after </title>, no </head>": b"<html><head><title>Title</title>Hello world</html>",
    "text straight after <head>, no </head>": b"<html><head>Hello world</html>",
    "<body> start tag alone ends the head": b"<head><title>t</title><body><title>kept</title>",
    "whitespace between head elements": b"<head>\n <title>t</title>\n <meta charset=x>\r\n\t<link rel=y>\f\n Hello <b>two</b>",
    "title text only": b"<html><head><title>Only a title</title>\n</html>",
    "unclosed title only": b"<html><head><title>Only a title",
    "script, style, noscript text only": b"<head><script>var a = 1;</script> <style>p{}</style> <noscript>hid</noscript>",
    "text after script/style/noscript": b"<head><title>t</title><script>var a</script><style>p{}</style><noscript>hid</noscript> shown <i>too</i>",
    "no-break space ends the head": "<head>\u00a0<title>Kept</title>".encode("utf-8"),
    "closed head, text in the head (v1)": b"<head><title>t</title>stray text</head><body>x</body>",
    "closed head": b"<html><head><title>T</title></head><body><p>Hello</p></body></html>",
    "no head": b"<html><body><p>a</p></body></html>",
    "head without </head>, with <body>": b"<html><head><title>t</title><body><p>Hello world</p></body></html>",
    "head without </head>, no <body>": b"<html><head><title>t</title><link rel=x><p>Para</p>",
}
for name, body in docs.items():
    a3, a4 = m3.normalize(body, "text/html", "u"), new.normalize(body, "text/html", "u")
    print("%-42s fix3=%r fix4=%r %s" % (name, a3, a4, "same" if a3 == a4 else "changed"))
sys.exit(1 if bad else 0)
