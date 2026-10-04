B=/tmp/hm-review-root/prototypes/ts/dist/darwin-arm64/heimdall-proto
mkdir -p /tmp/hm-review-probes/h
FOOV=$(printf 'a\377b')
run_env() { env -i PATH=/usr/bin:/bin HOME=/tmp/hm-review-probes/h "FOO=$FOOV" BAR= "$@"; }
echo "direct  $(run_env /usr/bin/env -0 | shasum -a 256)"
echo "proto   $(run_env $B run -- /usr/bin/env -0 | shasum -a 256)"
run_env $B run -- /usr/bin/env > p.env; run_env /usr/bin/env > d.env; diff d.env p.env && echo env-identical
echo "--- cwd: $(cd /tmp/hm-review-probes && $B run -- /bin/pwd)"
echo "--- umask/nofile via proto: $(umask 027; $B run -- /bin/sh -c 'umask; ulimit -n' | tr '\n' ' ')"
echo "--- umask/nofile direct:    $(umask 027; /bin/sh -c 'umask; ulimit -n' | tr '\n' ' ')"
