#!/bin/sh
# Two clean Go builds (build.sh) from git archive 38b6b72 in different paths, fresh GOCACHE each.
R=/tmp/hm-r4/M00-T05-r4-x3/repro; E=<home>/<repo>/tests/evidence/artifacts/g02-r4/x3
mkdir -p $R
for d in go-a go-build-bbbb; do
  rm -rf $R/$d $R/cache-$d; mkdir -p $R/$d $R/cache-$d
  git -C <home>/<repo> archive 38b6b72 prototypes/go | tar -x -C $R/$d
  ( cd $R/$d/prototypes/go && GOCACHE=$R/cache-$d GOTOOLCHAIN=local sh build.sh ) > $E/repro/go-build-$d.log 2>&1
  echo "$d build.sh rc=$?"
done
for d in go-a go-build-bbbb; do echo "== $d"; python3 -I -c 'import json,sys;[print(t["target"],t["bytes"],t["sha256"]) for t in json.load(open(sys.argv[1]))["targets"]]' $R/$d/prototypes/go/dist/manifest.json; done
