#!/usr/bin/env python3
"""Reproducible source pinning for spec section 19 (M00-T02-fix).

Read-only: HTTP GET only, Python standard library only, no credentials, no
writes outside --out / --snapshots-dir. It never calls any archive "save"
endpoint.

Subcommands
  fetch    GET every source in docs/sources/pins.json, write a result file with
           raw-body sha256 (primary pin), normalized-text sha256 (script
           NORMALIZER_VERSION), size, status, selected response headers and
           in-page date markers. Optionally write deterministic .txt.gz
           snapshots of the normalized text.
  archive  Query the Internet Archive availability API (GET only) for the
           closest snapshot to each URL, GET that snapshot's raw ("id_") body,
           and report whether its raw / normalized hash equals the fetched one.
  compare  Compare two fetch result files (ignores timestamps and headers
           that carry time, reports raw and normalized hash differences).
  verify   Compare a stored snapshot file against the normalized hash recorded
           in a fetch result (offline).

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
  python3 docs/sources/tools/fetch_pins.py fetch --out /tmp/run1.json
  python3 docs/sources/tools/fetch_pins.py fetch --out /tmp/run2.json
  python3 docs/sources/tools/fetch_pins.py compare /tmp/run1.json /tmp/run2.json
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
USER_AGENT = "heimdall-source-pins/1 (read-only GET; M00-T02-fix)"
MD_VARIANT_HOSTS = ("developers.openai.com", "learn.chatgpt.com")
SKIP_TAGS = {"head", "script", "style", "noscript", "template", "svg"}
GITHUB_PERMALINK = re.compile(r"^https://github\.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/(.+)$")
KEEP_HEADERS = ("content-type", "last-modified", "etag", "content-length")

MARKER_PATTERNS = {
    "mdoc_footer": re.compile(r"OpenBSD-current\s+([A-Z][a-z]+ \d{1,2}, \d{4})\s+[A-Z_-]+\(\d\)"),
    "page_dateModified": re.compile(r'"dateModified"\s*:\s*"([^"]+)"'),
    "ms_date": re.compile(r'name="ms\.date"\s+content="([^"]+)"'),
    "updated_at": re.compile(r'name="updated_at"\s+content="([^"]+)"'),
    "last_updated_on": re.compile(r"Last updated on\s+([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2})"),
}


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


def http_get(url: str, timeout: int = 60, retries: int = 2):
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
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


def load_sources(pins_path: str, only):
    d = json.load(open(pins_path))
    srcs = d["sources"]
    if only:
        srcs = [s for s in srcs if s["id"] in only]
    return srcs


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def cmd_fetch(a):
    only = set(a.only.split(",")) if a.only else None
    snap_ids = set(a.snapshot_ids.split(",")) if a.snapshot_ids else set()
    results = []
    for s in load_sources(a.pins, only):
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
            blob = hashlib.sha1(b"blob %d\0" % len(body) + body).hexdigest()
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
    out = {"tool": "fetch_pins.py", "normalizer_version": NORMALIZER_VERSION, "results": results}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    bad = [x["id"] for x in results if x["http_status"] != 200]
    if bad:
        print("non-200:", ",".join(bad), file=sys.stderr)
        return 1
    return 0


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
    fetched = {x["id"]: x for x in json.load(open(a.fetch_result))["results"]}
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


def cmd_compare(a):
    A = {x["id"]: x for x in json.load(open(a.a))["results"]}
    B = {x["id"]: x for x in json.load(open(a.b))["results"]}
    raw_same = norm_same = 0
    diffs = []
    for i in sorted(A):
        x, y = A[i], B.get(i)
        if not y:
            diffs.append((i, "missing in second"))
            continue
        rs = x["raw_body_sha256"] == y["raw_body_sha256"]
        ns = x["normalized_text_sha256"] == y["normalized_text_sha256"] and x["markers"] == y["markers"]
        raw_same += rs
        norm_same += ns
        if not (rs and ns):
            diffs.append((i, "raw_same=%s normalized_same=%s" % (rs, ns)))
    print("sources: %d  raw identical: %d  normalized identical: %d" % (len(A), raw_same, norm_same))
    for d in diffs:
        print("DIFF", *d)
    return 0 if not diffs else 2


def cmd_verify(a):
    f = {x["id"]: x for x in json.load(open(a.fetch_result))["results"]}[a.id]
    norm = gzip.open(a.snapshot, "rb").read()
    ok = sha256(norm) == f["normalized_text_sha256"]
    print(a.id, "snapshot normalized hash matches" if ok else "MISMATCH")
    return 0 if ok else 3


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--pins", default="docs/sources/pins.json")
    f.add_argument("--out", required=True)
    f.add_argument("--only")
    f.add_argument("--snapshots-dir")
    f.add_argument("--snapshot-ids")
    f.set_defaults(fn=cmd_fetch)
    r = sub.add_parser("archive")
    r.add_argument("--pins", default="docs/sources/pins.json")
    r.add_argument("--fetch-result", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--only")
    r.add_argument("--timestamp", default="20261002235600")
    r.set_defaults(fn=cmd_archive)
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    c.set_defaults(fn=cmd_compare)
    v = sub.add_parser("verify")
    v.add_argument("--fetch-result", required=True)
    v.add_argument("--id", required=True)
    v.add_argument("--snapshot", required=True)
    v.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
