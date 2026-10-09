#!/usr/bin/env python3
"""Reproducible source pinning for spec section 19 (M00-T02-fix, revised by M00-T02-fix2).

Read-only: HTTP GET only (https only, also after redirects), Python standard
library only, no credentials, no writes outside --out / --snapshots-dir. It
never calls any archive "save" endpoint and never pushes or POSTs anything.

Exit codes common to every subcommand: 64 = usage error (bad arguments);
1 = input error (for example an unreadable pins file or an empty reference
file). The codes below are per subcommand.

Subcommands
  fetch     GET every source in docs/sources/pins.json (--set spec: S01-S34,
            the default; --set aux: auxiliary sources A01..; --set all), write a
            result file with raw-body sha256, normalized-text sha256 (script
            NORMALIZER_VERSION), size, HTTP status, selected response headers and
            in-page date markers; for GitHub sources also the git blob sha1 and
            whether it equals the pinned blob. Optionally write deterministic
            .txt.gz snapshots of the normalized text. Exit 0 = every source HTTP
            200 (and every GitHub blob equal to its pin), 1 = otherwise.
  compare   Compare two fetch result files, the first being the reference
            (normally docs/sources/fetch-baseline.json). Each source gets exactly
            one class:
              IDENTICAL     raw bytes, normalized text and date markers equal
              RAW_ONLY      normalized text and markers equal, raw bytes differ
                            (page chrome or a site rebuild; text unchanged)
              MARKER_ONLY   normalized text equal, a date marker moved (for
                            example HTTP Last-Modified or embedded dateModified);
                            raw bytes may or may not differ
              CONTENT       normalized text differs: the visible text changed;
                            also a GitHub body whose blob sha1 is not the pinned
                            blob (integrity failure, flagged blob_mismatch)
              FETCH_FAILED  either side is not HTTP 200 or had a network error;
                            hashes are not compared (a bot-challenge page is not
                            a content change)
              MISSING       the id is in the first file but not in the second
              EXTRA         the id is only in the second file (informational)
            Unless --no-pins is given, the pins file (--pins, default
            docs/sources/pins.json) must be readable, and each line also says
            whether the second file still matches the source's primary pin
            (pin_v2.primary hash in pins.json): primary_same.
            Exit: 2 = at least one CONTENT or MISSING; else 3 = at least one
            FETCH_FAILED; else 4 = only RAW_ONLY / MARKER_ONLY differences (text
            identical everywhere it was fetched); 0 = all IDENTICAL.
  verify    Compare a stored snapshot file against the normalized hash recorded
            in a fetch result (offline). Exit 0 match, 3 mismatch.
  upstream  Optional drift check for the GitHub sources. `fetch` reads them at the
            pinned commit, so `compare` can never see later changes on the branch
            the spec URL names. `upstream` GETs the raw file on that branch
            (raw.githubusercontent.com/<repo>/<branch>/<path>, the raw rendering of
            the spec URL; repo-root URLs use HEAD and the pinned path), recomputes
            the git blob sha1, compares it with pin.blob_sha, and counts the quoted
            excerpt fragments still in the branch text. Exit 0 = every blob equals
            its pin; 4 = some drifted but every quoted fragment is still there;
            2 = a drifted source lost a quoted fragment; 3 = a fetch failed (and
            nothing scored 2).
  tags      Resolve the release tags listed in pins.json `tag_pins` to immutable
            ids by reading the repository's public git ref advertisement
            (GET https://github.com/<repo>.git/info/refs?service=git-upload-pack,
            protocol v0, no POST). The advertisement is validated (service line,
            pkt-line lengths, 40-hex ids); an invalid one counts as a failed fetch.
            Reports the ref sha (annotated tag object or commit) and the peeled
            commit, and compares them with the pinned values. Exit 0 = all pinned
            and equal, 2 = a tag moved or is missing, 3 = a fetch failed, 4 = some
            entries have no pinned value yet.
  excerpts  Excerpt-attribution check: every straight-double-quoted fragment
            (>= 12 characters, split at "..." / U+2026) of every source's
            `excerpt` field in pins.json must occur in that source's own pinned
            copy: the committed snapshot (paths resolved from the repository that
            holds --pins), or for GitHub sources the body at the pinned commit,
            fetched only with --fetch-git and accepted only if its blob sha1 equals
            the pin. A fragment missing from its own copy is reported together with
            any other source whose copy contains it (an S26-type misattribution).
            Matching is a substring test on lowercased word sequences
            (punctuation, quote style and markdown emphasis/links ignored). Not
            covered: quotes in excerpts/notes.md and in `candidates`. Exit 0 =
            every source checked, each with at least one fragment, all found;
            2 = a fragment was not found; 3 = a source was skipped (no copy) or has
            no quoted fragment, and nothing scored 2.
  selftest  Offline checks of the normalizer, the compare classes, primary_same,
            exit precedences, the ref-advertisement parser, URL and fragment
            helpers, and the https-only rule. Exit 0 = pass, 1 = fail.
  archive   Query the Internet Archive availability API (GET only) for the
            closest snapshot to each URL, GET that snapshot's raw ("id_") body,
            and report whether its raw / normalized hash equals the fetched one.

Normalization (NORMALIZER_VERSION 1), so a third party can reproduce it:
  1. Decode the body as UTF-8 with errors="replace".
  2. If the content type or URL is HTML: parse with html.parser; drop the
     entire content of <head>, <script>, <style>, <noscript>, <template>,
     <svg>; keep all other text nodes (html.parser unescapes entities); a
     space is inserted at every tag boundary so adjacent text never fuses.
     Otherwise (markdown, plain text) use the decoded text as is.
  3. Unicode NFC.
  4. Replace every run of Unicode whitespace (str.split()) with one U+0020 and
     strip. The result is UTF-8 encoded and hashed with sha256.

Usage (from the repository root):
  python3 -I docs/sources/tools/fetch_pins.py selftest
  python3 -I docs/sources/tools/fetch_pins.py fetch --out /tmp/new.json
  python3 -I docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline.json /tmp/new.json
  python3 -I docs/sources/tools/fetch_pins.py fetch --set aux --out /tmp/aux.json
  python3 -I docs/sources/tools/fetch_pins.py compare docs/sources/fetch-baseline-aux.json /tmp/aux.json
  python3 -I docs/sources/tools/fetch_pins.py upstream
  python3 -I docs/sources/tools/fetch_pins.py tags
  python3 -I docs/sources/tools/fetch_pins.py excerpts --set all --fetch-git
"""
import argparse
import gzip
import hashlib
import html.parser
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

NORMALIZER_VERSION = 1
# Unchanged since the 2026-10-03 baseline so that servers see the same client.
USER_AGENT = "heimdall-source-pins/1 (read-only GET; M00-T02-fix)"
MD_VARIANT_HOSTS = ("developers.openai.com", "learn.chatgpt.com")
SKIP_TAGS = {"head", "script", "style", "noscript", "template", "svg"}
GITHUB_PERMALINK = re.compile(r"^https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/(.+)$")
GITHUB_BLOB_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/(.+)$")
GITHUB_REPO_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+?)/?$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
KEEP_HEADERS = ("content-type", "last-modified", "etag", "content-length")
SETS = ("spec", "aux", "all")
PINS_REL = os.path.join("docs", "sources", "pins.json")

MARKER_PATTERNS = {
    "mdoc_footer": re.compile(r"OpenBSD-current\s+([A-Z][a-z]+ \d{1,2}, \d{4})\s+[A-Z_-]+\(\d\)"),
    "page_dateModified": re.compile(r'"dateModified"\s*:\s*"([^"]+)"'),
    "ms_date": re.compile(r'name="ms\.date"\s+content="([^"]+)"'),
    "updated_at": re.compile(r'name="updated_at"\s+content="([^"]+)"'),
    "last_updated_on": re.compile(r"Last updated on\s+([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2})"),
}

# compare classes and exit codes
IDENTICAL, RAW_ONLY, MARKER_ONLY, CONTENT = "IDENTICAL", "RAW_ONLY", "MARKER_ONLY", "CONTENT"
FETCH_FAILED, MISSING, EXTRA = "FETCH_FAILED", "MISSING", "EXTRA"
CLASSES = (IDENTICAL, RAW_ONLY, MARKER_ONLY, CONTENT, FETCH_FAILED, MISSING, EXTRA)
EXIT_INPUT, EXIT_CONTENT, EXIT_FETCH_FAILED, EXIT_TEXT_SAME, EXIT_USAGE = 1, 2, 3, 4, 64


class InputError(Exception):
    pass


class _TextExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP_TAGS:
            self.skip += 1
        self.parts.append(" ")

    def handle_startendtag(self, tag, attrs):
        self.parts.append(" ")

    def handle_endtag(self, tag):
        if tag in SKIP_TAGS and self.skip:
            self.skip -= 1
        self.parts.append(" ")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def normalize(body: bytes, content_type: str, url: str) -> str:
    text = body.decode("utf-8", errors="replace")
    is_html = "html" in (content_type or "").lower() or (
        not content_type and url.lower().endswith((".html", "/"))
    )
    if is_html:
        p = _TextExtractor()
        p.feed(text)
        p.close()
        text = "".join(p.parts)
    text = unicodedata.normalize("NFC", text)
    return " ".join(text.split())


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git_blob_sha1(body: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(body) + body).hexdigest()


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != "https":
            raise urllib.error.URLError("redirect to a non-https URL refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect())


def http_get(url: str, timeout: int = 60, retries: int = 2):
    """GET over https only (also after redirects). Returns status 0 and an
    `error` name for a refused scheme or a network failure."""
    if urllib.parse.urlparse(url).scheme != "https":
        return {"status": 0, "final_url": url, "headers": {}, "body": b"", "error": "SchemeNotAllowed"}
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
            method="GET",
        )
        try:
            with _OPENER.open(req, timeout=timeout) as r:
                body = r.read()
                return {
                    "status": r.status,
                    "final_url": r.geturl(),
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body,
                }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "final_url": url,
                "headers": {k.lower(): v for k, v in e.headers.items()},
                "body": e.read(),
            }
        except Exception as e:  # network error: retry
            last = e
            time.sleep(1.5 * (attempt + 1))
    return {"status": 0, "final_url": url, "headers": {}, "body": b"", "error": type(last).__name__}


def fetch_url_for(source: dict) -> str:
    """URL actually fetched: the pins.json fetched_url, with the site's .md
    variant for OpenAI/ChatGPT docs (the HTML is script-heavy)."""
    url = source.get("fetched_url") or source["url"]
    pm = GITHUB_PERMALINK.match(source.get("pin", {}).get("permalink", "") or "")
    if pm:  # GitHub sources are fetched at the pinned commit, never at "main"
        return "https://raw.githubusercontent.com/%s/%s/%s" % pm.groups()
    host = urllib.parse.urlparse(url).hostname or ""
    if host in MD_VARIANT_HOSTS and not url.endswith(".md"):
        return url.rstrip("/") + ".md"
    return url


def upstream_url_for(source: dict):
    """Raw URL of the file on the branch the spec URL names (not the pin)."""
    m = GITHUB_BLOB_URL.match(source["url"])
    if m:
        repo, ref, path = m.groups()
        return "https://raw.githubusercontent.com/%s/%s/%s" % (repo, ref, path), ref
    m = GITHUB_REPO_URL.match(source["url"])
    if m:
        path = source.get("pin", {}).get("path") or "README.md"
        return "https://raw.githubusercontent.com/%s/HEAD/%s" % (m.group(1), path), "HEAD"
    return None, None


def markers_for(raw_text: str, norm_text: str, headers: dict) -> dict:
    """Date markers searched in the raw body first, then in the normalized
    text (man page footers and 'Last updated on' only exist as visible text)."""
    out = {}
    if "last-modified" in headers:
        out["http_last_modified"] = headers["last-modified"]
    for name, pat in MARKER_PATTERNS.items():
        m = pat.search(raw_text) or pat.search(norm_text)
        if m:
            out[name] = m.group(1)
    return out


def write_snapshot(path: str, normalized: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = normalized.encode("utf-8")
    # mtime=0 and no filename in the header keep the .gz byte-reproducible.
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as g:
            g.write(data)


def load_pins(pins_path: str) -> dict:
    try:
        with open(pins_path) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise InputError("cannot read pins file %r: %s" % (pins_path, type(e).__name__))


def repo_root_for(pins_path: str) -> str:
    """Repository root that holds pins_path (snapshot paths in pins.json are
    relative to it); the current directory if pins_path is not at
    docs/sources/pins.json."""
    ap = os.path.abspath(pins_path)
    if ap.endswith(os.sep + PINS_REL):
        return ap[: -len(PINS_REL) - 1]
    return os.getcwd()


def load_sources(pins_path: str, only, which: str = "spec"):
    d = load_pins(pins_path)
    srcs = []
    if which in ("spec", "all"):
        srcs += d["sources"]
    if which in ("aux", "all"):
        srcs += d.get("auxiliary_sources", [])
    if only:
        srcs = [s for s in srcs if s["id"] in only]
    return srcs


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cmd_fetch(a):
    only = set(a.only.split(",")) if a.only else None
    snap_ids = set(a.snapshot_ids.split(",")) if a.snapshot_ids else set()
    results = []
    for s in load_sources(a.pins, only, a.set):
        url = fetch_url_for(s)
        r = http_get(url)
        body = r["body"]
        ct = r["headers"].get("content-type", "")
        norm = normalize(body, ct, url)
        text_for_markers = body.decode("utf-8", errors="replace")
        rec = {
            "id": s["id"],
            "spec_url": s["url"],
            "fetched_url": url,
            "final_url": r["final_url"],
            "http_status": r["status"],
            "retrieved_at_utc": utc_now(),
            "raw_bytes": len(body),
            "raw_body_sha256": sha256(body),
            "normalized_text_sha256": sha256(norm.encode("utf-8")),
            "normalized_text_chars": len(norm),
            "normalizer_version": NORMALIZER_VERSION,
            "headers": {k: v for k, v in r["headers"].items() if k in KEEP_HEADERS},
            "markers": markers_for(text_for_markers, norm, r["headers"]),
        }
        if GITHUB_PERMALINK.match(s.get("pin", {}).get("permalink", "") or ""):
            blob = git_blob_sha1(body)
            rec["git_blob_sha1"] = blob
            rec["git_blob_matches_pin"] = blob == s["pin"].get("blob_sha")
        if "error" in r:
            rec["error"] = r["error"]
        if s["id"] in snap_ids and r["status"] == 200 and a.snapshots_dir:
            p = os.path.join(a.snapshots_dir, s["id"] + ".txt.gz")
            write_snapshot(p, norm)
            with open(p, "rb") as f:
                rec["snapshot"] = {"path": p, "gz_sha256": sha256(f.read())}
        results.append(rec)
        print(s["id"], r["status"], rec["raw_bytes"], rec["raw_body_sha256"][:12], rec["normalized_text_sha256"][:12])
        time.sleep(0.3)
    out = {"tool": "fetch_pins.py", "normalizer_version": NORMALIZER_VERSION, "set": a.set, "results": results}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    bad = [x["id"] for x in results if x["http_status"] != 200 or "error" in x]
    blob_bad = [x["id"] for x in results if x.get("git_blob_matches_pin") is False]
    if bad:
        print("non-200:", ",".join(bad), file=sys.stderr)
    if blob_bad:
        print("git blob differs from the pin:", ",".join(blob_bad), file=sys.stderr)
    return 1 if bad or blob_bad else 0


def archive_lookup(url: str, ts: str):
    q = urllib.parse.urlencode({"url": url, "timestamp": ts})
    r = http_get("https://archive.org/wayback/available?" + q, timeout=60, retries=3)
    if r["status"] != 200:
        return None, r["status"]
    try:
        snap = json.loads(r["body"]).get("archived_snapshots", {}).get("closest")
    except ValueError:
        return None, r["status"]
    return snap, r["status"]


def cmd_archive(a):
    with open(a.fetch_result) as fh:
        fetched = {x["id"]: x for x in json.load(fh)["results"]}
    only = set(a.only.split(",")) if a.only else None
    ts = a.timestamp
    out = []
    for s in load_sources(a.pins, only):
        f = fetched[s["id"]]
        url = f["fetched_url"]
        if "git_blob_sha1" in f:  # commit permalink is already immutable
            continue
        snap, st = archive_lookup(url, ts)
        rec = {"id": s["id"], "queried_url": url, "availability_http": st}
        if snap and snap.get("available"):
            stamp = snap["timestamp"]
            rec["archive_timestamp"] = stamp
            rec["archive_url"] = "https://web.archive.org/web/%s/%s" % (stamp, url)
            raw_url = "https://web.archive.org/web/%sid_/%s" % (stamp, url)
            r = http_get(raw_url, timeout=90, retries=2)
            rec["archive_raw_http"] = r["status"]
            if r["status"] == 200:
                ct = r["headers"].get("content-type", "")
                n = normalize(r["body"], ct, url)
                rec["archive_raw_sha256"] = sha256(r["body"])
                rec["archive_normalized_sha256"] = sha256(n.encode("utf-8"))
                rec["raw_matches_fetch"] = rec["archive_raw_sha256"] == f["raw_body_sha256"]
                rec["normalized_matches_fetch"] = rec["archive_normalized_sha256"] == f["normalized_text_sha256"]
        else:
            rec["archive_url"] = None
        out.append(rec)
        print(s["id"], rec.get("archive_timestamp"), rec.get("raw_matches_fetch"), rec.get("normalized_matches_fetch"))
        time.sleep(1.0)
    with open(a.out, "w") as f:
        json.dump({"tool": "fetch_pins.py archive", "timestamp_query": ts, "results": out}, f, indent=1, sort_keys=True)
        f.write("\n")
    return 0


def classify(x: dict, y):
    """Class of one source, x = reference record, y = new record (or None)."""
    if y is None:
        return MISSING, {}
    sx, sy = x.get("http_status"), y.get("http_status")
    detail = {"http": "%s/%s" % (sx, sy)}
    if sx != 200 or sy != 200 or "error" in x or "error" in y:
        return FETCH_FAILED, detail
    rs = x["raw_body_sha256"] == y["raw_body_sha256"]
    ns = x["normalized_text_sha256"] == y["normalized_text_sha256"]
    mx, my = x.get("markers", {}), y.get("markers", {})
    ms = mx == my
    detail.update({"raw_same": rs, "norm_same": ns, "markers_same": ms})
    if not ms:
        detail["moved"] = sorted(k for k in set(mx) | set(my) if mx.get(k) != my.get(k))
    if y.get("git_blob_matches_pin") is False:
        detail["blob_mismatch"] = True
        return CONTENT, detail
    if not ns:
        return CONTENT, detail
    if not ms:
        return MARKER_ONLY, detail
    if not rs:
        return RAW_ONLY, detail
    return IDENTICAL, detail


def compare_exit(counts: dict) -> int:
    if counts.get(CONTENT) or counts.get(MISSING):
        return EXIT_CONTENT
    if counts.get(FETCH_FAILED):
        return EXIT_FETCH_FAILED
    if counts.get(RAW_ONLY) or counts.get(MARKER_ONLY):
        return EXIT_TEXT_SAME
    return 0


def primary_pins(pins: dict) -> dict:
    """id -> (primary kind, pinned primary hash) from a loaded pins.json."""
    out = {}
    for s in pins.get("sources", []) + pins.get("auxiliary_sources", []):
        v = s.get("pin_v2") or {}
        if v.get("primary") in ("raw_body_sha256", "normalized_text_sha256"):
            out[s["id"]] = (v["primary"], v.get(v["primary"]))
    return out


def yn(v):
    return "yes" if v else "no"


def compare_results(A: dict, B: dict, prim: dict):
    """Counts per class and one output line per non-identical source."""
    counts = {c: 0 for c in CLASSES}
    lines = []
    for i in sorted(A):
        x, y = A[i], B.get(i)
        cls, det = classify(x, y)
        counts[cls] += 1
        parts = [i, cls]
        if "http" in det:
            parts.append("http=" + det["http"])
        if "raw_same" in det:
            parts += ["raw_same=" + yn(det["raw_same"]), "norm_same=" + yn(det["norm_same"]),
                      "markers_same=" + yn(det["markers_same"])]
        if det.get("moved"):
            parts.append("moved=" + ",".join(det["moved"]))
        if det.get("blob_mismatch"):
            parts.append("blob_mismatch=yes")
        if i in prim and y is not None and cls != FETCH_FAILED:
            kind, pinned = prim[i]
            parts.append("primary=%s primary_same=%s" % ("raw" if kind == "raw_body_sha256" else "norm",
                                                         yn(y.get(kind) == pinned)))
        lines.append((cls, " ".join(parts)))
    for i in sorted(set(B) - set(A)):
        counts[EXTRA] += 1
        lines.append((EXTRA, "%s %s (only in second file)" % (i, EXTRA)))
    return counts, lines


def read_results(path: str) -> dict:
    try:
        with open(path) as f:
            res = json.load(f)["results"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise InputError("cannot read fetch result %r: %s" % (path, type(e).__name__))
    return {x["id"]: x for x in res}


def cmd_compare(a):
    A, B = read_results(a.a), read_results(a.b)
    if not A:
        raise InputError("reference file %r has no results" % a.a)
    prim = {} if a.no_pins else primary_pins(load_pins(a.pins))
    counts, lines = compare_results(A, B, prim)
    print("sources: %d  " % len(A) + "  ".join("%s=%d" % (c, counts[c]) for c in CLASSES))
    for cls, ln in lines:
        if cls != IDENTICAL or a.all:
            print(ln)
    rc = compare_exit(counts)
    print("exit %d: %s" % (rc, {0: "all identical", EXIT_CONTENT: "content change or missing source",
                                EXIT_FETCH_FAILED: "fetch failure (no content change among fetched sources)",
                                EXIT_TEXT_SAME: "text identical; only raw bytes and/or date markers moved"}[rc]))
    return rc


def cmd_verify(a):
    f = read_results(a.fetch_result)[a.id]
    with gzip.open(a.snapshot, "rb") as g:
        norm = g.read()
    ok = sha256(norm) == f["normalized_text_sha256"]
    print(a.id, "snapshot normalized hash matches" if ok else "MISMATCH")
    return 0 if ok else 3


def loose(t: str) -> str:
    """Word-sequence form used for excerpt matching: lowercase, markdown links
    reduced to their text, every run of non [0-9a-z'] characters to one space,
    apostrophes dropped."""
    t = t.replace("’", "'").replace("‘", "'")
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    return " ".join(re.sub(r"[^0-9a-z']+", " ", t.lower()).replace("'", "").split())


def excerpt_fragments(excerpt: str):
    frags = re.findall(r'"([^"]{12,})"', excerpt or "")
    return [p for f in frags for p in re.split(r"\s*(?:\.\.\.|…)\s*", f) if len(p) >= 12]


def upstream_exit(rows) -> int:
    lost = [r for r in rows if r.get("result") == "drifted" and r.get("fragments_found") != r.get("fragments_total")]
    if lost:
        return EXIT_CONTENT
    if any(r.get("result") == "fetch_failed" for r in rows):
        return EXIT_FETCH_FAILED
    if any(r.get("result") == "drifted" for r in rows):
        return EXIT_TEXT_SAME
    return 0


def cmd_upstream(a):
    rows = []
    for s in load_sources(a.pins, set(a.only.split(",")) if a.only else None, "spec"):
        pin = s.get("pin", {})
        if not GITHUB_PERMALINK.match(pin.get("permalink", "") or ""):
            continue
        url, ref = upstream_url_for(s)
        r = http_get(url)
        rec = {"id": s["id"], "url": url, "ref": ref, "http_status": r["status"], "pinned_blob": pin.get("blob_sha"),
               "retrieved_at_utc": utc_now()}
        if r["status"] != 200 or "error" in r:
            rec["result"] = "fetch_failed"
        else:
            rec["branch_blob"] = git_blob_sha1(r["body"])
            rec["result"] = "same" if rec["branch_blob"] == pin.get("blob_sha") else "drifted"
            text = loose(r["body"].decode("utf-8", errors="replace"))
            frs = excerpt_fragments(s.get("excerpt"))
            rec["fragments_total"] = len(frs)
            rec["fragments_found"] = sum(1 for p in frs if loose(p) in text)
        rows.append(rec)
        print(s["id"], rec["retrieved_at_utc"], rec["http_status"], ref, "branch blob", (rec.get("branch_blob") or "-")[:12],
              "pinned blob", (rec["pinned_blob"] or "-")[:12], rec["result"].upper(),
              "excerpt fragments on branch %s/%s" % (rec.get("fragments_found", "-"), rec.get("fragments_total", "-")))
        time.sleep(0.3)
    if a.out:
        with open(a.out, "w") as f:
            json.dump({"tool": "fetch_pins.py upstream", "results": rows}, f, indent=1, sort_keys=True)
            f.write("\n")
    return upstream_exit(rows)


def parse_ref_advertisement(data: bytes) -> dict:
    """Parse a git smart-HTTP protocol-v0 upload-pack advertisement into
    {ref: 40-hex sha}. Raises ValueError on anything malformed."""
    i, refs, lines = 0, {}, []
    while i < len(data):
        if i + 4 > len(data):
            raise ValueError("truncated pkt-line header")
        try:
            n = int(data[i:i + 4], 16)
        except ValueError:
            raise ValueError("bad pkt-line length")
        if n == 0:
            i += 4
            continue
        if n < 4 or i + n > len(data):
            raise ValueError("bad pkt-line length %d" % n)
        lines.append(data[i + 4:i + n].decode("ascii", errors="strict").rstrip("\n"))
        i += n
    if not lines or lines[0] != "# service=git-upload-pack":
        raise ValueError("not an upload-pack advertisement")
    for line in lines[1:]:
        if line.startswith("ERR "):
            raise ValueError("server error packet")
        sha, sep, ref = line.split("\0")[0].partition(" ")
        if not sep or not HEX40.match(sha) or not ref:
            raise ValueError("bad ref line")
        refs[ref] = sha
    return refs


def ref_advertisement(repo: str):
    url = "https://github.com/%s.git/info/refs?service=git-upload-pack" % repo
    r = http_get(url)
    if r["status"] != 200 or "error" in r:
        return None, url, r["status"], "http"
    try:
        return parse_ref_advertisement(r["body"]), url, r["status"], None
    except (ValueError, UnicodeDecodeError) as e:
        return None, url, r["status"], "bad advertisement: %s" % e


def cmd_tags(a):
    d = load_pins(a.pins)
    cache, rows = {}, []
    moved = failed = unpinned = 0
    for t in d.get("tag_pins", []):
        repo, tag = t["repo"], t["tag"]
        if repo not in cache:
            cache[repo] = ref_advertisement(repo)
            time.sleep(0.3)
        refs, url, st, why = cache[repo]
        rec = {"label": t.get("label"), "repo": repo, "tag": tag, "advertisement_url": url, "http_status": st,
               "retrieved_at_utc": utc_now()}
        if refs is None:
            rec["result"] = "fetch_failed"
            rec["reason"] = why
            failed += 1
        elif "refs/tags/" + tag not in refs:
            rec["result"] = "tag_missing"
            moved += 1
        else:
            ref_sha = refs["refs/tags/" + tag]
            peeled = refs.get("refs/tags/" + tag + "^{}")
            rec.update({"ref_sha": ref_sha, "annotated": peeled is not None, "commit": peeled or ref_sha})
            if not t.get("commit"):
                rec["result"] = "unpinned"
                unpinned += 1
            elif t.get("commit") == rec["commit"] and t.get("ref_sha") == ref_sha:
                rec["result"] = "same"
            else:
                rec["result"] = "moved"
                moved += 1
        rows.append(rec)
        print(repo, tag, (rec.get("ref_sha") or "-")[:12], "annotated" if rec.get("annotated") else "lightweight",
              "commit", (rec.get("commit") or "-")[:12], rec["result"].upper(), rec.get("reason") or "")
    if a.out:
        with open(a.out, "w") as f:
            json.dump({"tool": "fetch_pins.py tags", "results": rows}, f, indent=1, sort_keys=True)
            f.write("\n")
    if moved:
        return 2
    if failed:
        return 3
    if unpinned:
        return 4
    return 0


def pinned_copy(s: dict, root: str, fetch_git: bool):
    sn = (s.get("pin_v2") or {}).get("snapshot")
    if sn:
        p = os.path.join(root, sn["path"])
        if os.path.exists(p):
            with gzip.open(p, "rb") as g:
                return g.read().decode("utf-8"), "snapshot"
        return None, "snapshot file missing: %s" % sn["path"]
    if GITHUB_PERMALINK.match(s.get("pin", {}).get("permalink", "") or ""):
        if not fetch_git:
            return None, "GitHub source, no local copy (use --fetch-git)"
        r = http_get(fetch_url_for(s))
        if r["status"] == 200 and git_blob_sha1(r["body"]) == s["pin"].get("blob_sha"):
            return r["body"].decode("utf-8", errors="replace"), "pinned commit (blob verified)"
        return None, "pinned commit fetch failed or blob mismatch (HTTP %s)" % r["status"]
    return None, "no pinned copy"


def cmd_excerpts(a):
    srcs = load_sources(a.pins, None, a.set)
    root = repo_root_for(a.pins)
    copies, how = {}, {}
    for s in srcs:
        txt, how[s["id"]] = pinned_copy(s, root, a.fetch_git)
        if txt is not None:
            copies[s["id"]] = loose(txt)
    bad, unchecked, total = [], [], 0
    for s in srcs:
        i = s["id"]
        frs = excerpt_fragments(s.get("excerpt"))
        if i not in copies:
            unchecked.append(i)
            print(i, "SKIPPED", how[i], "fragments=%d" % len(frs))
            continue
        if not frs:
            unchecked.append(i)
            print(i, "NO_QUOTES (excerpt has no double-quoted fragment of 12+ characters)", "copy=" + how[i])
            continue
        total += len(frs)
        miss = [p for p in frs if loose(p) not in copies[i]]
        print(i, "OK" if not miss else "NOT_FOUND", "fragments=%d found=%d" % (len(frs), len(frs) - len(miss)), "copy=" + how[i])
        for p in miss:
            elsewhere = [j for j in copies if j != i and loose(p) in copies[j]]
            print("   missing: %r%s" % (p[:100], ("  (found in %s)" % ",".join(elsewhere)) if elsewhere else ""))
        if miss:
            bad.append(i)
    print("sources=%d checked=%d fragments=%d not_found_in=%s unchecked=%s" % (
        len(srcs), len(srcs) - len(unchecked), total, bad, unchecked))
    if bad:
        return 2
    return 3 if unchecked else 0


def cmd_selftest(a):
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    html_body = (b"<html><head><title>T</title></head><body><p>Caf\xc3\xa9</p><script>x()</script>"
                 b"<p>a&amp;b</p><svg><text>no</text></svg><p>e\xcc\x81</p></body></html>")
    check("normalize html", normalize(html_body, "text/html", "u"), "Café a&b é")
    check("normalize md", normalize(b"# A\n\n  b\tc  ", "text/markdown", "u.md"), "# A b c")
    base = {"http_status": 200, "raw_body_sha256": "r1", "normalized_text_sha256": "n1", "markers": {"m": "1"}}
    cases = [
        ("identical", dict(base), IDENTICAL),
        ("raw only", dict(base, raw_body_sha256="r2"), RAW_ONLY),
        ("marker only, raw same", dict(base, markers={"m": "2"}), MARKER_ONLY),
        ("marker only, raw differs", dict(base, raw_body_sha256="r2", markers={"m": "2"}), MARKER_ONLY),
        ("content", dict(base, normalized_text_sha256="n2"), CONTENT),
        ("content and marker", dict(base, normalized_text_sha256="n2", markers={}), CONTENT),
        ("git blob mismatch, text same", dict(base, raw_body_sha256="r2", git_blob_matches_pin=False), CONTENT),
        ("git blob match", dict(base, git_blob_matches_pin=True), IDENTICAL),
        ("challenge page 403", dict(base, http_status=403, normalized_text_sha256="n9"), FETCH_FAILED),
        ("network error", dict(base, http_status=0, error="URLError"), FETCH_FAILED),
        ("missing", None, MISSING),
    ]
    for name, y, want in cases:
        check("classify " + name, classify(base, y)[0], want)
    check("classify reference failed", classify(dict(base, http_status=403), dict(base))[0], FETCH_FAILED)
    check("exit identical", compare_exit({IDENTICAL: 3}), 0)
    check("exit text same", compare_exit({IDENTICAL: 1, RAW_ONLY: 1, MARKER_ONLY: 1}), EXIT_TEXT_SAME)
    check("exit fetch failed", compare_exit({RAW_ONLY: 1, FETCH_FAILED: 1}), EXIT_FETCH_FAILED)
    check("exit content wins", compare_exit({CONTENT: 1, FETCH_FAILED: 1}), EXIT_CONTENT)
    check("exit missing", compare_exit({MISSING: 1}), EXIT_CONTENT)
    check("exit extra only", compare_exit({IDENTICAL: 1, EXTRA: 2}), 0)
    pins = {"sources": [{"id": "S1", "pin_v2": {"primary": "raw_body_sha256", "raw_body_sha256": "r1"}},
                        {"id": "S2", "pin_v2": {"primary": "normalized_text_sha256", "normalized_text_sha256": "pinned"}}],
            "auxiliary_sources": [{"id": "A1", "pin_v2": {"primary": "normalized_text_sha256", "normalized_text_sha256": "n1"}}]}
    prim = primary_pins(pins)
    check("primary_pins", prim, {"S1": ("raw_body_sha256", "r1"), "S2": ("normalized_text_sha256", "pinned"),
                                 "A1": ("normalized_text_sha256", "n1")})
    A = {"S1": dict(base), "S2": dict(base), "A1": dict(base)}
    B = {"S1": dict(base, raw_body_sha256="r2"), "S2": dict(base), "A1": dict(base), "X9": dict(base)}
    counts, lines = compare_results(A, B, prim)
    check("compare_results counts", (counts[RAW_ONLY], counts[IDENTICAL], counts[EXTRA]), (1, 2, 1))
    txt = "\n".join(ln for _, ln in lines)
    check("primary_same raw changed", "S1 RAW_ONLY" in txt and "primary=raw primary_same=no" in txt, True)
    check("primary_same against the pin, not the reference", "S2 IDENTICAL" in txt and "primary=norm primary_same=no" in txt, True)
    check("primary_same aux", "A1 IDENTICAL http=200/200 raw_same=yes norm_same=yes markers_same=yes primary=norm primary_same=yes" in txt, True)

    def pkt(s):
        b = s.encode()
        return b"%04x" % (len(b) + 4) + b

    sha_t, sha_c = "a" * 40, "b" * 40
    adv = (pkt("# service=git-upload-pack\n") + b"0000" + pkt(sha_c + " HEAD\0multi_ack symref=HEAD:refs/heads/main\n")
           + pkt(sha_t + " refs/tags/v1\n") + pkt(sha_c + " refs/tags/v1^{}\n") + b"0000")
    check("parse advertisement", parse_ref_advertisement(adv),
          {"HEAD": sha_c, "refs/tags/v1": sha_t, "refs/tags/v1^{}": sha_c})
    for name, body in [("html body", b"<html>sign in</html>"), ("empty body", b""),
                       ("ERR packet", pkt("# service=git-upload-pack\n") + b"0000" + pkt("ERR access denied\n")),
                       ("length 0003", pkt("# service=git-upload-pack\n") + b"0003"),
                       ("truncated", pkt("# service=git-upload-pack\n") + b"00ff" + b"x" * 10),
                       ("short sha", pkt("# service=git-upload-pack\n") + pkt("abc refs/tags/v1\n"))]:
        try:
            parse_ref_advertisement(body)
            fails.append("parse advertisement %s: no error raised" % name)
        except (ValueError, UnicodeDecodeError):
            pass
    check("https only: file", http_get("file:///etc/hosts").get("error"), "SchemeNotAllowed")
    check("https only: http", http_get("http://example.invalid/").get("error"), "SchemeNotAllowed")
    check("upstream exit same", upstream_exit([{"result": "same"}]), 0)
    check("upstream exit benign drift", upstream_exit([{"result": "drifted", "fragments_found": 2, "fragments_total": 2}]),
          EXIT_TEXT_SAME)
    check("upstream exit lost fragment", upstream_exit([{"result": "drifted", "fragments_found": 1, "fragments_total": 2},
                                                        {"result": "fetch_failed"}]), EXIT_CONTENT)
    check("upstream exit fetch failed", upstream_exit([{"result": "same"}, {"result": "fetch_failed"}]), EXIT_FETCH_FAILED)
    check("fragments", excerpt_fragments('"Alpha beta gamma ... delta epsilon zeta" and "short"'),
          ["Alpha beta gamma", "delta epsilon zeta"])
    check("loose", loose("**Be very specific**: [link](http://x) it’s"), "be very specific link its")
    check("blob sha1 of empty", git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
    check("upstream url blob", upstream_url_for({"url": "https://github.com/o/r/blob/main/docs/a.md"}),
          ("https://raw.githubusercontent.com/o/r/main/docs/a.md", "main"))
    check("upstream url repo", upstream_url_for({"url": "https://github.com/o/r", "pin": {"path": "README.md"}}),
          ("https://raw.githubusercontent.com/o/r/HEAD/README.md", "HEAD"))
    check("repo root from pins path", repo_root_for(os.path.join(os.sep, "x", "y", PINS_REL)), os.path.join(os.sep, "x", "y"))
    for f in fails:
        print("FAIL", f)
    print("selftest: %d checks failed" % len(fails) if fails else "selftest: all checks passed")
    return 1 if fails else 0


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # usage errors must not look like a compare result (exit 2)
        self.print_usage(sys.stderr)
        print("%s: error: %s" % (self.prog, message), file=sys.stderr)
        sys.exit(EXIT_USAGE)


def main():
    ap = _Parser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    f = sub.add_parser("fetch")
    f.add_argument("--pins", default=PINS_REL)
    f.add_argument("--out", required=True)
    f.add_argument("--only")
    f.add_argument("--set", choices=SETS, default="spec")
    f.add_argument("--snapshots-dir")
    f.add_argument("--snapshot-ids")
    f.set_defaults(fn=cmd_fetch)
    r = sub.add_parser("archive")
    r.add_argument("--pins", default=PINS_REL)
    r.add_argument("--fetch-result", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--only")
    r.add_argument("--timestamp", default="20261002235600")
    r.set_defaults(fn=cmd_archive)
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    c.add_argument("--pins", default=PINS_REL)
    c.add_argument("--no-pins", action="store_true", help="do not annotate primary_same (no pins file needed)")
    c.add_argument("--all", action="store_true", help="also list IDENTICAL sources")
    c.set_defaults(fn=cmd_compare)
    v = sub.add_parser("verify")
    v.add_argument("--fetch-result", required=True)
    v.add_argument("--id", required=True)
    v.add_argument("--snapshot", required=True)
    v.set_defaults(fn=cmd_verify)
    u = sub.add_parser("upstream")
    u.add_argument("--pins", default=PINS_REL)
    u.add_argument("--only")
    u.add_argument("--out")
    u.set_defaults(fn=cmd_upstream)
    t = sub.add_parser("tags")
    t.add_argument("--pins", default=PINS_REL)
    t.add_argument("--out")
    t.set_defaults(fn=cmd_tags)
    e = sub.add_parser("excerpts")
    e.add_argument("--pins", default=PINS_REL)
    e.add_argument("--set", choices=SETS, default="spec")
    e.add_argument("--fetch-git", action="store_true")
    e.set_defaults(fn=cmd_excerpts)
    s = sub.add_parser("selftest")
    s.set_defaults(fn=cmd_selftest)
    a = ap.parse_args()
    try:
        rc = a.fn(a)
    except InputError as err:
        print("input error:", err, file=sys.stderr)
        rc = EXIT_INPUT
    sys.exit(rc)


if __name__ == "__main__":
    main()
