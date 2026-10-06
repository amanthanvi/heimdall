#!/bin/sh
# Two clean Rust builds (build.sh) from git archive d8f0cbe in different paths, fresh target dirs.
R=/tmp/hm-r4/M00-T05-r4-x3/repro; E=<home>/<repo>/tests/evidence/artifacts/g02-r4/x3
mkdir -p $R
for d in rust-a rust-build-bbbb; do
  rm -rf $R/$d; mkdir -p $R/$d
  git -C <home>/<repo> archive d8f0cbe prototypes/rust | tar -x -C $R/$d
  ( cd $R/$d/prototypes/rust && CARGO_ZIGBUILD=/tmp/hm-r4/tools/x3/bin/cargo-zigbuild sh build.sh ) > $E/repro/rust-build-$d.log 2>&1
  echo "$d build.sh rc=$?"
done
for d in rust-a rust-build-bbbb; do echo "== $d"; python3 -I -c 'import json,sys;m=json.load(open(sys.argv[1]));[print(t["target"],t["bytes"],t["sha256"],t["built"]) for t in m["targets"]];print("notices",m.get("notices",{}).get("sha256"))' $R/$d/prototypes/rust/dist/manifest.json; done
