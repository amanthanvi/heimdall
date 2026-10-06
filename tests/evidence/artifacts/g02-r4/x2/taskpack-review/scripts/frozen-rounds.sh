#!/bin/sh
# Re-run baseline rows against digest-verified copies of the frozen 38b6b72/d8f0cbe builds
# (the repository's dist/ was rebuilt by another task during round 2).
W=/tmp/hm-r4/M00-T05-r4-taskpack-review
HID=<home>/.local/share/heimdall-m00/r4-hidden
export HM_REPO=<home>/<repo>
export HM_G02_VENV=$HM_REPO/tests/g02/.venv
unset SSH_AUTH_SOCK
cd "$HM_REPO" || exit 2
run() { # outdir platform task lang
  o=$1; p=$2; t=$3; c=$4; mkdir -p $o/$p
  st=$(date -u +%FT%TZ)
  if [ $p = darwin ]; then
    python3 -I $HID/run.py --task $t --bin $W/frozen/$c/darwin-arm64/heimdall-proto --platform darwin --out $o/darwin/$t-base-$c.json > $o/darwin/$t-base-$c.console.txt 2>&1; rc=$?
  else
    d=$o/linux/$t-base-$c.d
    sh $HID/docker-run.sh --task $t --artifact-dir $W/frozen/$c/linux-arm64 --out-dir $d > $o/linux/$t-base-$c.console.txt 2>&1; rc=$?
    [ -f $d/$t-linux.json ] && mv $d/$t-linux.json $o/linux/$t-base-$c.json; rmdir $d 2>/dev/null
  fi
  printf '%s\t%s\tbase-%s\t%s\t%s\t%s\n' $p $t $c $([ $t = T4 ] && echo green || echo red) $rc $st >> $o/exit-codes.tsv
}
o=$W/round2b; mkdir -p $o; printf 'platform\ttask\tsubject\texpected\texit\tstarted_utc\n' > $o/exit-codes.tsv
run $o linux T1 rust; run $o linux T4 go; run $o linux T4 rust
o=$W/round3b; mkdir -p $o; printf 'platform\ttask\tsubject\texpected\texit\tstarted_utc\n' > $o/exit-codes.tsv
for p in darwin linux; do for t in T2 T3 T1 T4; do for c in go rust; do run $o $p $t $c; done; done; done
date -u +%FT%TZ > $W/frozen-rounds.finished
