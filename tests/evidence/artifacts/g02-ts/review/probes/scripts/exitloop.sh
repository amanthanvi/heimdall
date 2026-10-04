B=$1; bad=0; n=0
for i in $(seq 1 150); do
  c=$((i % 256)); $B run -- /bin/sh -c "exit $c"; r=$?; n=$((n+1)); [ $r -ne $c ] && { bad=$((bad+1)); echo "mismatch want=$c got=$r"; }
done
for s in 15 9 6; do $B run -- /bin/sh -c "kill -$s \$\$"; r=$?; n=$((n+1)); [ $r -ne $((128+s)) ] && { bad=$((bad+1)); echo "sig mismatch $s got=$r"; }; done
echo "runs=$n mismatches=$bad"
