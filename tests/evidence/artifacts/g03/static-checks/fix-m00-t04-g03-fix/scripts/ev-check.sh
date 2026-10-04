set -u
rm -rf /tmp/g03fix/ev && mkdir /tmp/g03fix/ev && cd /tmp/g03fix/ev || exit 1
E=<home>/GitRepos/heimdall/tests/native/wsl/evidence.py; fail=0
t() { name="$1" crit="$2" want="$3"; shift 3; echo "$crit" > c.json; echo '{}' > o.json; python3 "$E" record --out r.json --case-id G03-x --obs o.json --criteria c.json "$@" >/dev/null; got="$(python3 -c 'import json;d=json.load(open("r.json"));print(d["status"]+"/"+d["observed_result"]["verdict"]+" reqs="+",".join(d["requirement_ids"])+" failed="+",".join(d["observed_result"]["failed_criteria"]))')"; [ "$got" = "$want" ] && s=ok || { s=MISMATCH; fail=1; }; printf '%-20s %-55s %s\n' "$name" "$got" "$s"; }
t "all true" '{"a": true}' "verified/pass reqs=R-EN-03 failed=" --req R-EN-03
t "one false" '{"a": true, "b": false}' "verified/fail reqs=R-EN-03 failed=b" --req R-EN-03
t "null and false" '{"a": null, "b": false}' "in_progress/inconclusive reqs= failed=b"
t "empty criteria" '{}' "in_progress/inconclusive reqs= failed="
echo "FAILURES=$fail"; exit $fail
