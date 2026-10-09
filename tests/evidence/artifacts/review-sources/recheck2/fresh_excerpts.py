"""Check excerpt fragments of the sources whose text changed (S26, S28) against today's fresh snapshot, and size the change."""
import difflib, gzip, importlib.util, json, sys
tool, pins_path, snapdir, committed = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("fp", tool)
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)
src = {s["id"]: s for s in json.load(open(pins_path))["sources"]}
for i in ("S26", "S28"):
    new = gzip.open("%s/%s.txt.gz" % (snapdir, i)).read().decode()
    old = gzip.open("%s/%s.txt.gz" % (committed, i)).read().decode()
    frs = fp.excerpt_fragments(src[i].get("excerpt"))
    found = sum(1 for p in frs if fp.loose(p) in fp.loose(new))
    sm = difflib.SequenceMatcher(None, old.split(), new.split(), autojunk=False)
    ops = [o for o in sm.get_opcodes() if o[0] != "equal"]
    added = sum(j2 - j1 for t, i1, i2, j1, j2 in ops if t in ("insert", "replace"))
    removed = sum(i2 - i1 for t, i1, i2, j1, j2 in ops if t in ("delete", "replace"))
    print("%s fragments in today's text %d/%d; word diff ops=%d removed_words=%d added_words=%d" % (i, found, len(frs), len(ops), removed, added))
    for t, i1, i2, j1, j2 in ops[:6]:
        print("    %s old=%r new=%r" % (t, " ".join(old.split()[i1:i2])[:90], " ".join(new.split()[j1:j2])[:90]))
