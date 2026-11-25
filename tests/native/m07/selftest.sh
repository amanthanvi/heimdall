#!/usr/bin/env bash
# M07-U9: self-test of the M07 evidence harness, run by tools/validation/native-harness-selftest.sh.
# Reaches no host, builds nothing and starts no process but python3 and bash: the "M02 script" the
# wrapper reaches is a stub, and every log is synthetic. Everything lives under one mktemp directory,
# removed on exit, pass or fail. No record is written into tests/evidence/.
#
# Checks:
#   m07_generator_*   the generator over synthetic logs (selftest_synthetic.py: verified rows when every
#                     required test passed; a missing required test, a failed test and a nonzero
#                     command give no verified row; a platform that did not run is blocked on it; the
#                     case index's own rows: blocked stays blocked with its reason, deferred stays
#                     deferred, a row claiming a run's status or lacking its reason is refused; A30 is
#                     never reported passing, in its own record or the exit record; m07 observation
#                     lines; HM_SKIP_TARGETS refuses --write; the committed files agree)
#   m07_cli_*         m07-evidence.py --help, and --check-inventory over the committed case index and
#                     inventory (structure only; it reads no run and writes nothing)
#   m07_wrapper_*     refresh-inventory.sh reaches the M02 script with the M07 generator and harness
#                     directory, without a feature, and passes HM_SKIP_TARGETS through
# Prints one line per check and `m07-selftest: N passed, M failed`; exit 0 only when every check passed.

# The checks run their predicates through `bash -c` with single-quoted bodies on purpose.
# shellcheck disable=SC2016
set -u
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
T=$(mktemp -d /tmp/hm-m07-st.XXXXXX) || exit 2
T=$(cd "$T" && pwd -P)
trap 'rm -rf "$T"' EXIT
passes=0
fails=0
check() {
    local name=$1
    shift
    if "$@"; then
        echo "ok   $name"
        passes=$((passes + 1))
    else
        echo "FAIL $name"
        fails=$((fails + 1))
    fi
}

# --- the generator over synthetic logs ----------------------------------------------------------

PYTHONDONTWRITEBYTECODE=1 python3 -I "$here/selftest_synthetic.py" >"$T/gen.out" 2>&1
gen_rc=$?
gen_n=$(sed -n 's/^Ran \([0-9]*\) tests.*/\1/p' "$T/gen.out" | tail -1)
check "m07_generator_dry_runs_over_synthetic_logs (${gen_n:-0} tests: verified, missing test, failed test, nonzero exit, missing platform, index rows, deferred, A30 never passing, observations, skip)" \
    bash -c '[ "$1" = 0 ] && grep -q "^OK$" "$2"' _ "$gen_rc" "$T/gen.out"
[ "$gen_rc" = 0 ] || grep -E '^(FAIL|ERROR):' "$T/gen.out" | head -20

# --- the generator's own modes ------------------------------------------------------------------

(cd "$root" && PYTHONDONTWRITEBYTECODE=1 python3 -I -B "$here/m07-evidence.py" --help) >"$T/help.out" 2>&1
check "m07_cli_help_exits_0_and_names_the_m02_modes" \
    bash -c '[ "$1" = 0 ] && grep -q -- "--generate-inventory" "$2" && grep -q -- "--check-inventory" "$2" && grep -q -- "--write" "$2"' _ "$?" "$T/help.out"
(cd "$root" && PYTHONDONTWRITEBYTECODE=1 python3 -I -B "$here/m07-evidence.py" --config tests/native/m07/runs.json --check-inventory) >"$T/check.out" 2>&1
check "m07_cli_check_inventory_accepts_the_committed_index_and_inventory" \
    bash -c '[ "$1" = 0 ] && grep -q "^required inventory matches the case index" "$2"' _ "$?" "$T/check.out"

# --- the wrapper -------------------------------------------------------------------------------

W="$T/wrap"
mkdir -p "$W/m02" "$W/m07"
cp "$here/refresh-inventory.sh" "$W/m07/refresh-inventory.sh"
cat >"$W/m02/refresh-inventory.sh" <<'EOF'
#!/usr/bin/env bash
# Stub of the M02 script: prints the settings the M07 wrapper gave it.
{
    echo "script=$(basename "$0")"
    echo "args=$*"
    echo "HM_HARNESS_DIR=${HM_HARNESS_DIR:-unset}"
    echo "HM_EVIDENCE=${HM_EVIDENCE:-unset}"
    echo "HM_FEATURE=${HM_FEATURE:-unset}"
    echo "HM_FEATURE_UNIT=${HM_FEATURE_UNIT:-unset}"
    echo "HM_SKIP_TARGETS=${HM_SKIP_TARGETS:-unset}"
} >"$HM_ST_OUT"
EOF
HM_FEATURE=iroh HM_FEATURE_UNIT=heimdall-transport-iroh HM_ST_OUT="$W/out" bash "$W/m07/refresh-inventory.sh" a b >"$W/log" 2>&1
check "m07_wrapper_refresh_inventory_selects_the_m07_generator_without_a_feature" \
    bash -c 'W=$1; [ "$2" = 0 ] && grep -qxF "script=refresh-inventory.sh" "$W/out" && grep -qxF "args=a b" "$W/out" &&
        grep -qxF "HM_EVIDENCE=m07-evidence.py" "$W/out" && grep -qxF "HM_HARNESS_DIR=$W/m07" "$W/out" &&
        grep -qxF "HM_FEATURE=unset" "$W/out" && grep -qxF "HM_FEATURE_UNIT=unset" "$W/out"' _ "$W" "$?"
rm -f "$W/out"
HM_SKIP_TARGETS=a,b HM_ST_OUT="$W/out" bash "$W/m07/refresh-inventory.sh" >/dev/null 2>&1
check "m07_wrapper_refresh_inventory_passes_HM_SKIP_TARGETS_through" grep -qxF "HM_SKIP_TARGETS=a,b" "$W/out"
check "m07_wrapper_harness_directory_holds_the_generator_and_runs_json_the_m02_script_needs" \
    bash -c '[ -f "$1/m07-evidence.py" ] && [ -f "$1/runs.json" ] && grep -q "HM_EVIDENCE:-m02-evidence.py" "$2/refresh-inventory.sh"' _ "$here" "$here/../m02"

echo "m07-selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
