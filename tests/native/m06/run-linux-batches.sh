#!/usr/bin/env bash
# M06 exit (RESEARCH §0 item 4, §1 step 3): the devbox row in HM_ONLY batches, as W5 ran it (14
# batches), with a free-space floor on the devbox and a size cap on each batch's staged set.
#
# Usage: tests/native/m06/run-linux-batches.sh <artifacts_root> <ssh-host-alias> [<batch list>]
#   <batch list> default tests/native/m06/linux-batches.txt: one batch per line, `b<NN> target...`
#                (target names as run-linux.sh plans them; `#` starts a comment).
#   HM_BATCH_FLOOR_KB      the devbox's free space (KiB, df -Pk of the account's home) below which
#                          no batch starts: default 3145728 (3 GiB); a lower value is refused.
#   HM_BATCH_STAGE_MAX_KB  the cap on each batch's staged set (the binaries of the batch, both
#                          heimdall builds, hm-fixture-hook and the repository files): default
#                          1572864 (1.5 GiB), passed to run-linux.sh as HM_STAGE_MAX_KB, which
#                          measures the set (`du -skL`) and exits 7 before anything is copied.
#
# Steps:
#   1. The plan: tests/native/m06/run-linux.sh with HM_BUILD_ONLY=1 into a scratch directory (no
#      host contacted). Every planned target (each `<target> sha256:` line of its build.txt) must
#      be in exactly one batch and every batch target must be planned: otherwise exit 2 before
#      anything runs (a stale list never silently drops a target).
#   2. Per batch, in list order: `ssh -n <alias> df -Pk "$HOME"`; below the floor (or unreadable)
#      the run stops with exit 3 (blocked: free space on the devbox), naming the batch. Then
#      `HM_ONLY=<its targets> HM_STAGE_MAX_KB=<cap> tests/native/m06/run-linux.sh
#      <artifacts_root>/linux-<batch> <alias> </dev/null`. run-linux.sh removes its own scratch
#      directory (~/hm-m06-<hex>) on exit; a batch that exits 3, 4 (host unreachable) or 7 (over
#      the cap) stops the run, any other nonzero exit is recorded and the next batch runs.
#   The list is read on fd 3 and every ssh here runs with -n (and every run-linux.sh with
#   stdin from /dev/null): nothing in the loop can consume the list (an earlier loop lost its
#   input to ssh).
#
# Output: <artifacts_root>/linux-<batch>/ per batch (run-linux.sh's files), and
# <artifacts_root>/linux-batches.txt: one `exit N: ...` line per floor check and batch, the form
# m06-evidence.py reads as a commands log (list it in platforms.linux.commands_logs). Prints the
# platforms.linux logs/commands_logs/facts entries for the exit configuration.
# Exit: 0 every batch passed; 6 when the only failures were blocked iroh-feature builds; 2 usage
# or a list that does not cover the plan; 3 below the floor; otherwise the first failing batch's.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=tests/native/m02/lib.sh
. "$here/../m02/lib.sh"
root=${1:?usage: run-linux-batches.sh <artifacts_root> <ssh-host-alias> [<batch list>]}
host=${2:?usage: run-linux-batches.sh <artifacts_root> <ssh-host-alias> [<batch list>]}
list=${3:-$here/linux-batches.txt}
m02_valid_alias "$host" || { echo "bad host alias" >&2; exit 2; }
[ -f "$list" ] || { echo "no batch list: $list" >&2; exit 2; }
floor=${HM_BATCH_FLOOR_KB:-3145728}
cap=${HM_BATCH_STAGE_MAX_KB:-1572864}
case "$floor$cap" in *[!0-9]*) echo "HM_BATCH_FLOOR_KB and HM_BATCH_STAGE_MAX_KB are KiB counts" >&2; exit 2 ;; esac
[ "$floor" -ge 3145728 ] || { echo "HM_BATCH_FLOOR_KB below 3 GiB is refused" >&2; exit 2; }
[ "$cap" -gt 0 ] || { echo "HM_BATCH_STAGE_MAX_KB must be positive" >&2; exit 2; }
mkdir -p "$root"
root=$(cd "$root" && pwd)
log="$root/linux-batches.txt"
[ ! -e "$log" ] || { echo "$log exists: one batch run per exit directory" >&2; exit 2; }
plan=$(mktemp -d)
trap 'rm -rf "$plan"' EXIT

# --- 1. the plan, and the list's coverage of it ---------------------------------------------------
set +e
HM_BUILD_ONLY=1 bash "$here/run-linux.sh" "$plan/out" </dev/null >"$plan/build.log" 2>&1
rc=$?
set -e
if [ "$rc" != 0 ] && [ "$rc" != 6 ]; then
    tail -n 20 "$plan/build.log" >&2
    echo "the build-only plan failed (exit $rc)" >&2
    exit "$rc"
fi
sed -n 's/^\([A-Za-z0-9_-]*\) sha256: [0-9a-f]\{64\}$/\1/p' "$plan/out/build.txt" | LC_ALL=C sort -u >"$plan/planned"
: >"$plan/listed"
: >"$plan/batches"
while read -r -u 3 label rest; do
    case "$label" in '' | '#'*) continue ;; esac
    case "$label" in b[0-9]*) ;; *) echo "bad batch label: $label" >&2; exit 2 ;; esac
    case "$label" in *[!a-z0-9]*) echo "bad batch label: $label" >&2; exit 2 ;; esac
    read -r -a words <<<"${rest%%#*}"
    [ ${#words[@]} -gt 0 ] || { echo "batch $label names no target" >&2; exit 2; }
    for t in "${words[@]}"; do
        case "$t" in *[!A-Za-z0-9_-]*) echo "bad target name in $label: $t" >&2; exit 2 ;; esac
        echo "$t" >>"$plan/listed"
    done
    printf '%s %s\n' "$label" "${words[*]}" >>"$plan/batches"
done 3<"$list"
dup=$(LC_ALL=C sort "$plan/listed" | uniq -d)
[ -z "$dup" ] || { echo "targets in more than one batch: $(tr '\n' ' ' <<<"$dup")" >&2; exit 2; }
[ -z "$(cut -d' ' -f1 "$plan/batches" | LC_ALL=C sort | uniq -d)" ] || { echo "a batch label is used twice" >&2; exit 2; }
LC_ALL=C sort -u "$plan/listed" >"$plan/listed.sorted"
missing=$(LC_ALL=C comm -23 "$plan/planned" "$plan/listed.sorted")
unplanned=$(LC_ALL=C comm -13 "$plan/planned" "$plan/listed.sorted")
[ -z "$missing" ] || { echo "planned targets in no batch (update $list): $(tr '\n' ' ' <<<"$missing")" >&2; exit 2; }
[ -z "$unplanned" ] || { echo "batch targets the build does not plan (update $list): $(tr '\n' ' ' <<<"$unplanned")" >&2; exit 2; }
echo "plan: $(wc -l <"$plan/planned" | tr -d ' ') targets in $(wc -l <"$plan/batches" | tr -d ' ') batches"

# --- 2. the batches -------------------------------------------------------------------------------
: >"$log"
first_bad=0
saw6=0
ran=()
while read -r -u 3 label targets; do
    set +e
    free=$(ssh -n -o BatchMode=yes -o ConnectTimeout=20 "$host" 'df -Pk "$HOME" | awk "NR == 2 { print \$4 }"' 2>/dev/null)
    frc=$?
    set -e
    case "$free" in '' | *[!0-9]*) free="" ;; esac
    if [ "$frc" != 0 ] || [ -z "$free" ]; then
        m02_record "$log" "ssh -n <linuxhost> df -Pk \$HOME before batch $label (free space unreadable)" 4
        echo "batch $label: the devbox's free space could not be read (exit $frc)" >&2
        first_bad=4
        break
    fi
    if [ "$free" -lt "$floor" ]; then
        m02_record "$log" "ssh -n <linuxhost> df -Pk \$HOME before batch $label: ${free} KiB free, below the ${floor} KiB floor (blocked)" 3
        echo "batch $label refused: the devbox has ${free} KiB free, below the ${floor} KiB floor" >&2
        first_bad=3
        break
    fi
    m02_record "$log" "ssh -n <linuxhost> df -Pk \$HOME before batch $label: ${free} KiB free (floor ${floor} KiB)" 0
    set +e
    HM_ONLY="$targets" HM_STAGE_MAX_KB="$cap" bash "$here/run-linux.sh" "$root/linux-$label" "$host" </dev/null >"$plan/$label.log" 2>&1
    rc=$?
    set -e
    n=$(echo "$targets" | wc -w | tr -d ' ')
    m02_record "$log" "HM_ONLY=<the $n targets of batch $label> HM_STAGE_MAX_KB=$cap tests/native/m06/run-linux.sh <artifacts_root>/linux-$label <linuxhost>" "$rc"
    echo "batch $label ($n targets): exit $rc"
    ran+=("$label")
    case "$rc" in
        0) ;;
        6) saw6=1 ;;
        3 | 4 | 7) [ "$first_bad" != 0 ] || first_bad=$rc; tail -n 5 "$plan/$label.log" >&2; break ;;
        *) [ "$first_bad" != 0 ] || first_bad=$rc; tail -n 5 "$plan/$label.log" >&2 ;;
    esac
done 3<"$plan/batches"

if [ ${#ran[@]} -gt 0 ]; then
    echo "exit configuration, platforms.linux:"
    printf '  "logs": [%s],\n' "$(printf '"linux-%s/tests.txt", ' "${ran[@]}" | sed 's/, $//')"
    printf '  "commands_logs": ["linux-batches.txt", %s],\n' "$(printf '"linux-%s/commands.txt", ' "${ran[@]}" | sed 's/, $//')"
    printf '  "facts": ["linux-%s/host.txt"]\n' "${ran[0]}"
fi
[ "$first_bad" = 0 ] || exit "$first_bad"
[ "$saw6" = 0 ] || exit 6
exit 0
