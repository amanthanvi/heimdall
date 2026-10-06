#!/bin/sh
# Three sequential rounds of the hidden-test matrix (baselines, positive controls, seeded T4).
W=/tmp/hm-r4/M00-T05-r4-taskpack-review
export HM_REPO=<home>/<repo>
unset SSH_AUTH_SOCK
cd "$HM_REPO" || exit 2
for r in 1 2 3; do
  date -u +%FT%TZ > $W/round$r.started
  sh <home>/.local/share/heimdall-m00/r4-hidden/verify-matrix.sh $W/seedbin $W/round$r both > $W/round$r.log 2>&1
  echo "rc=$?" >> $W/round$r.log
  date -u +%FT%TZ > $W/round$r.finished
done
