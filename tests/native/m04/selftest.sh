#!/usr/bin/env bash
# Self-test of tests/native/m04/container-engines.sh (M04, the container row A15).
#
# Reaches no network, installs, pulls and starts nothing real, and needs no root: `podman`,
# `docker`, `dockerd`, `apt-get`, `usermod`, `runuser`, `newuidmap` and `id` are stubs first
# on a PATH that holds nothing else but symlinks to the plain tools the script uses (so a
# real podman or docker on the build host is never reached). The engine stubs keep a fake
# engine in files (container and image IDs), log every argv, and refuse an argument that is
# not what the script is documented to send (a short ID, podman without runuser, docker
# as a user). The script runs in its self-test mode (HM_ENGINES_SELFTEST=1) with /etc,
# /usr/sbin, /tmp and /proc redirected into a mktemp sandbox, removed on exit, pass or fail.
#
# Checks (one line each; the first is the plan's named check):
#   container_harness_removes_only_its_images_and_containers
#   preexisting_image_is_never_recorded_or_removed
#   cleanup_without_snapshot_removes_nothing
#   snapshot_is_refused_when_one_exists
#   guard_refuses_wrong_distribution_or_non_root_before_any_engine
#   guard_selftest_mode_needs_its_sandbox_roots
#   image_refuses_bad_base_ref_and_tag
#   engine_and_user_arguments_are_validated
#   state_directory_is_checked
#   install_without_apt_permission_exits_3
#   install_with_apt_blocks_services_and_ensures_subid_and_group
#   install_second_run_changes_nothing
#   install_keeps_an_existing_policy_rc_d
#   dockerd_stop_kills_nothing_for_a_reused_pid_or_another_program
#   dockerd_start_and_stop_manage_exactly_the_recorded_process
#   dockerd_that_never_answers_is_stopped
#   bash -n of container-engines.sh
#
# Usage: bash tests/native/m04/selftest.sh [root]
#   root  directory holding tests/native/m04 (default: this checkout)
# Exit: 0 when every check passes, 1 otherwise. Prints `ok   NAME` or `FAIL NAME` per check
# and `selftest: N passed, M failed` (HM_SELFTEST_VERBOSE=1 also prints a failed check's
# script output and stub log, which hold sandbox paths).

set -u
here=$(cd "$(dirname "$0")/../../.." && pwd) || exit 2
root=${1:-$here}
root=$(cd "$root" && pwd) || exit 2
script="$root/tests/native/m04/container-engines.sh"
[ -f "$script" ] || { echo "selftest: container-engines.sh not found" >&2; exit 2; }

T=$(mktemp -d "${TMPDIR:-/tmp}/hm-m04-selftest.XXXXXX") || exit 2
T=$(cd "$T" && pwd -P)
sentinels=""
cleanup() {
    local p
    for p in $sentinels; do kill "$p" 2>/dev/null; done
    rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

STUB="$T/bin"
TOOLS="$T/tools"
passes=0
fails=0
verbose=${HM_SELFTEST_VERBOSE:-0}

check() {
    local name=$1
    shift
    if "$@"; then
        echo "ok   $name"
        passes=$((passes + 1))
    else
        echo "FAIL $name"
        fails=$((fails + 1))
        if [ "$verbose" = 1 ]; then
            echo "--- exit $rc; stdout:"
            cat "$OUT" 2>/dev/null
            echo "--- stderr:"
            cat "$ERR" 2>/dev/null
            echo "--- stub log:"
            cat "$LOG" 2>/dev/null
        fi
    fi
}

# --- the plain tools the script uses, linked so PATH holds nothing else ----------------------

mkdir -p "$TOOLS" "$T/home"
for n in bash sh env awk sed grep cat tr cut sort head tail mkdir rm chmod mv cp touch sleep nohup ln wc basename mktemp; do
    p=$(command -v "$n" 2>/dev/null)
    case "$p" in /*) ln -s "$p" "$TOOLS/$n" ;; *) echo "selftest: no $n on this host" >&2; exit 2 ;; esac
done

# --- the stubs ------------------------------------------------------------------------------------

write_stubs() {
    cat >"$T/engine.stub" <<'EOF'
#!/usr/bin/env bash
# Fake podman/docker over files: containers, images (bare IDs), refs ("REF ID" lines).
set -u
name=$(basename "$0")
{ printf '%s' "$name"; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
eng=$HM_STUB_ENG
if [ "${1:-}" = --version ]; then
    # Works for root, like the real ones.
    if [ "$name" = podman ]; then echo "podman version 5.0.0-stub"; else echo "Docker version 26.0.0-stub, build stub"; fi
    echo "second line"
    exit 0
fi
if [ "$name" = podman ]; then
    [ -n "${HM_STUB_RUNAS:-}" ] || { echo "stub: podman not run through runuser" >&2; exit 99; }
    pre=""
else
    [ -z "${HM_STUB_RUNAS:-}" ] || { echo "stub: docker run as a user" >&2; exit 99; }
    pre="sha256:"
fi
C="$eng/$name.containers"
I="$eng/$name.images"
REFS="$eng/$name.refs"
is_id() { case "$1" in '' | *[!0-9a-f]*) return 1 ;; esac; [ "${#1}" = 64 ]; }
drop() { grep -Fxv -- "$2" "$1" >"$1.new"; mv "$1.new" "$1"; }
add_image() { grep -Fxq -- "$1" "$I" || echo "$1" >>"$I"; }
case "${1:-}" in
    info)
        [ "$name" = docker ] && [ -e "$eng/dockerd-up" ]
        ;;
    ps)
        [ "$*" = "ps -a -q --no-trunc" ] || exit 98
        [ -z "${HM_STUB_FAIL_LIST:-}" ] || exit 1
        cat "$C"
        ;;
    images)
        [ "$*" = "images -q --no-trunc" ] || exit 98
        sed "s/^/$pre/" "$I"
        ;;
    pull)
        [ "$#" = 2 ] || exit 98
        [ -z "${HM_STUB_PULL_FAIL:-}" ] || exit 1
        id=${HM_STUB_BASE_ID:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}
        add_image "$id"
        echo "$2 $id" >>"$REFS"
        ;;
    build)
        [ "$#" = 6 ] && [ "$2" = -t ] && [ "$4" = -f ] || exit 98
        [ -d "$6" ] && [ -f "$5" ] || exit 97
        [ -z "${HM_STUB_BUILD_FAIL:-}" ] || exit 1
        n=$(cat "$eng/seq" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" >"$eng/seq"
        id=$(printf 'd%063x' "$n")
        cp "$5" "$eng/last-containerfile"
        add_image "$id"
        echo "$3 $id" >>"$REFS"
        ;;
    image)
        [ "$#" = 5 ] && [ "$2" = inspect ] && [ "$3" = --format ] && [ "$4" = '{{.Id}}' ] || exit 98
        id=$(awk -v r="$5" '$1 == r { id = $2 } END { if (id == "") exit 1; print id }' "$REFS" 2>/dev/null) || exit 1
        echo "$pre$id"
        ;;
    rm)
        [ "$#" = 3 ] && [ "$2" = -f ] && is_id "$3" || exit 98
        grep -Fxq -- "$3" "$C" || exit 1
        drop "$C" "$3"
        ;;
    rmi)
        [ "$#" = 3 ] && [ "$2" = -f ] && is_id "$3" || exit 98
        grep -Fxq -- "$3" "$I" || exit 1
        drop "$I" "$3"
        ;;
    *) exit 98 ;;
esac
EOF
    cat >"$T/runuser.stub" <<'EOF'
#!/usr/bin/env bash
{ printf 'runuser'; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
[ "${1:-}" = -u ] && [ "${3:-}" = -- ] || exit 98
u=$2
shift 3
HM_STUB_RUNAS=$u exec "$@"
EOF
    cat >"$T/apt-get.stub" <<'EOF'
#!/usr/bin/env bash
{ printf 'apt-get'; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
prc="$HM_STUB_ROOT/usr/sbin/policy-rc.d"
if [ -f "$prc" ] && sh "$prc" x start; [ $? = 101 ]; then st=blocking; else st=absent; fi
echo "note apt-get ${1:-} policy-rc.d=$st" >>"$HM_STUB_LOG"
[ -z "${HM_STUB_APT_FAIL:-}" ] || exit 100
if [ "${1:-}" = install ]; then cp "$HM_STUB_AVAIL"/* "$HM_STUB_BIN"/; fi
exit 0
EOF
    cat >"$T/usermod.stub" <<'EOF'
#!/usr/bin/env bash
{ printf 'usermod'; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
[ "$1" = -aG ] && [ "$2" = docker ] || exit 98
echo docker >>"$HM_STUB_GROUPS/$3"
EOF
    cat >"$T/id.stub" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    "-u hmtest") echo 1000 ;;
    "-u root") echo 0 ;;
    "-nG hmtest") echo "hmtest $(tr '\n' ' ' <"$HM_STUB_GROUPS/hmtest" 2>/dev/null)" ;;
    *) exit 1 ;;
esac
EOF
    cat >"$T/newuidmap.stub" <<'EOF'
#!/usr/bin/env bash
{ printf 'newuidmap'; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
EOF
    cat >"$T/dockerd.stub" <<'EOF'
#!/usr/bin/env bash
# Fake dockerd: a real process with a fake /proc entry; answers `docker info` by creating
# dockerd-up unless told not to; ends on SIGTERM (removing its entries) or when its entry goes.
{ printf 'dockerd'; printf ' %s' "$@"; echo; } >>"$HM_STUB_LOG"
[ "${1:-}" = --pidfile ] || exit 98
pidfile=$2
me=$$
d="$HM_STUB_PROC/$me"
mkdir -p "$d"
echo dockerd >"$d/comm"
echo "$me (dockerd) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 ${HM_STUB_START:-4242} 0 0" >"$d/stat"
echo "$me" >"$pidfile"
trap 'rm -rf "$d"; rm -f "$HM_STUB_ENG/dockerd-up"; exit 0' TERM
[ -n "${HM_STUB_NOREPLY:-}" ] || : >"$HM_STUB_ENG/dockerd-up"
n=0
while [ -d "$d" ] && [ "$n" -lt 600 ]; do
    sleep 0.2
    n=$((n + 1))
done
exit 0
EOF
}
write_stubs

# --- the sandbox ----------------------------------------------------------------------------------

state="$T/state"
OUT="$T/out"
ERR="$T/err"
LOG="$T/log"
rc=0
distro=hm-m04-0a1b2c3d-1
fake_uid=0
eroot="$T/root"
start_wait=5
stop_wait=5
s_base_id="" s_fail_list="" s_noreply="" s_build_fail="" s_apt_fail="" s_start="" s_pull_fail=""

# new_world present|missing: fresh sandbox; `present` has the four tools on PATH, `missing`
# only has them where the apt-get stub installs them from.
new_world() {
    rm -rf "$T/world" "$STUB" "$T/avail" "$T/root" "$T/proc" "$T/eng" "$T/groups" "$state" "$T/elsewhere"
    mkdir -p "$STUB" "$T/avail" "$T/root/etc" "$T/root/usr/sbin" "$T/root/tmp" "$T/proc" "$T/eng" "$T/groups"
    local e t
    for e in podman docker; do
        : >"$T/eng/$e.containers"
        : >"$T/eng/$e.images"
        : >"$T/eng/$e.refs"
    done
    for t in podman docker; do cp "$T/engine.stub" "$T/avail/$t"; done
    cp "$T/dockerd.stub" "$T/avail/dockerd"
    cp "$T/newuidmap.stub" "$T/avail/newuidmap"
    cp "$T/runuser.stub" "$STUB/runuser"
    cp "$T/apt-get.stub" "$STUB/apt-get"
    cp "$T/usermod.stub" "$STUB/usermod"
    cp "$T/id.stub" "$STUB/id"
    [ "$1" = present ] && cp "$T/avail"/* "$STUB"/
    chmod +x "$T/avail"/* "$STUB"/*
    : >"$T/root/etc/subuid"
    : >"$T/root/etc/subgid"
    printf 'docker:x:999:\n' >"$T/root/etc/group"
    : >"$LOG"
    distro=hm-m04-0a1b2c3d-1
    fake_uid=0
    eroot="$T/root"
    start_wait=5
    stop_wait=5
    s_base_id="" s_fail_list="" s_noreply="" s_build_fail="" s_apt_fail="" s_start="" s_pull_fail=""
}

# run ARGS...: container-engines.sh STATE ARGS in the sandbox; sets rc, writes OUT/ERR.
run() {
    env -i PATH="$STUB:$TOOLS" HOME="$T/home" LANG=C \
        HM_ENGINES_SELFTEST=1 HM_ENGINES_FAKE_UID="$fake_uid" HM_ENGINES_ROOT="$eroot" \
        HM_ENGINES_PROC="$T/proc" HM_ENGINES_START_WAIT="$start_wait" HM_ENGINES_STOP_WAIT="$stop_wait" \
        WSL_DISTRO_NAME="$distro" \
        HM_STUB_LOG="$LOG" HM_STUB_ENG="$T/eng" HM_STUB_PROC="$T/proc" HM_STUB_ROOT="$T/root" \
        HM_STUB_AVAIL="$T/avail" HM_STUB_BIN="$STUB" HM_STUB_GROUPS="$T/groups" \
        HM_STUB_BASE_ID="$s_base_id" HM_STUB_FAIL_LIST="$s_fail_list" HM_STUB_NOREPLY="$s_noreply" \
        HM_STUB_BUILD_FAIL="$s_build_fail" HM_STUB_APT_FAIL="$s_apt_fail" HM_STUB_START="$s_start" \
        HM_STUB_PULL_FAIL="$s_pull_fail" \
        "$BASH" "$script" "$state" "$@" >"$OUT" 2>"$ERR" </dev/null
    rc=$?
}

# --- helpers --------------------------------------------------------------------------------------

# mk CHAR: 64 copies of the hex digit CHAR.
mk() { printf '%064d' 0 | tr 0 "$1"; }
base_ref() { printf 'alpine@sha256:%s' "$(mk f)"; }
built_id() { printf 'd%063x' "$1"; }
out_has() { grep -Fxq -- "$1" "$OUT"; }
log_has() { grep -Fxq -- "$1" "$LOG"; }
log_count() { grep -cE -- "$1" "$LOG"; }
file_is() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }
# fake_proc PID COMM START: a fake /proc entry.
fake_proc() {
    mkdir -p "$T/proc/$1"
    echo "$2" >"$T/proc/$1/comm"
    echo "$1 ($2) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 $3 0 0" >"$T/proc/$1/stat"
}
# sentinel: a real, harmless process whose liveness shows whether it was signalled.
sentinel() {
    sleep 300 &
    sentinel_pid=$!
    sentinels="$sentinels $sentinel_pid"
}
is_alive() { kill -0 "$1" 2>/dev/null; }
# wait_dead PID: up to 3 s for the process to be gone.
wait_dead() {
    local i=0
    while [ "$i" -lt 30 ] && is_alive "$1"; do sleep 0.1; i=$((i + 1)); done
    ! is_alive "$1"
}

# --- the checks ----------------------------------------------------------------------------------

t_lifecycle() {
    local e pre_c pre_i built cont
    pre_c=$(mk a)
    pre_i=$(mk 1)
    cont=$(mk c)
    built=$(built_id 1)
    for e in podman docker; do
        new_world present
        printf '%s\n' "$pre_c" >"$T/eng/$e.containers"
        printf '%s\n' "$pre_i" >"$T/eng/$e.images"
        run snapshot "$e" hmtest
        [ "$rc" = 0 ] || return 1
        file_is "$state/$e-containers-before.txt" "$pre_c" || return 1
        file_is "$state/$e-images-before.txt" "$pre_i" || return 1
        run image "$e" hmtest "$(base_ref)" localhost/hm-fixture
        [ "$rc" = 0 ] || return 1
        out_has "image-$e=$built" || return 1
        out_has "image-$e-base=$(mk b)" || return 1
        file_is "$state/$e-images-created.txt" "$(mk b)
$built" || return 1
        file_is "$state/$e-Containerfile" "FROM $(base_ref)
RUN apk add --no-cache openssh-client" || return 1
        file_is "$T/eng/last-containerfile" "FROM $(base_ref)
RUN apk add --no-cache openssh-client" || return 1
        [ -z "$(ls -A "$T/root/tmp")" ] || return 1
        printf '%s\n' "$cont" >>"$T/eng/$e.containers"
        : >"$LOG"
        run cleanup "$e" hmtest
        [ "$rc" = 0 ] || return 1
        file_is "$T/eng/$e.containers" "$pre_c" || return 1
        file_is "$T/eng/$e.images" "$pre_i" || return 1
        out_has "removed-container=$cont" || return 1
        out_has "removed-image=$built" || return 1
        out_has "removed-image=$(mk b)" || return 1
        out_has "cleanup-$e=ok" || return 1
        [ "$(log_count "^$e rmi? ")" = 3 ] || return 1
        [ "$(log_count "^$e rm -f [0-9a-f]{64}\$")" = 1 ] || return 1
        [ "$(log_count "^$e rmi -f [0-9a-f]{64}\$")" = 2 ] || return 1
        ! grep -qF "$pre_c" "$LOG" || return 1
        ! grep -qF "$pre_i" "$LOG" || return 1
    done
    return 0
}

t_preexisting_image() {
    new_world present
    s_base_id=$(mk 1)
    printf '%s\n' "$(mk 1)" >"$T/eng/podman.images"
    run snapshot podman hmtest
    run image podman hmtest "$(base_ref)" localhost/hm-fixture
    [ "$rc" = 0 ] || return 1
    file_is "$state/podman-images-created.txt" "$(built_id 1)" || return 1
    grep -q "image-podman-preexisting=$(mk 1)" "$OUT" || return 1
    : >"$LOG"
    run cleanup podman hmtest
    [ "$rc" = 0 ] || return 1
    file_is "$T/eng/podman.images" "$(mk 1)" || return 1
    ! grep -qF "$(mk 1)" "$LOG" || return 1
    # A hand-edited record naming a pre-existing image is not removed either.
    printf '%s\n' "$(mk 1)" >>"$state/podman-images-created.txt"
    : >"$LOG"
    run cleanup podman hmtest
    [ "$rc" = 0 ] || return 1
    ! grep -qF "rmi -f $(mk 1)" "$LOG" && file_is "$T/eng/podman.images" "$(mk 1)"
}

t_no_snapshot() {
    new_world present
    printf '%s\n' "$(mk a)" >"$T/eng/podman.containers"
    printf '%s\n' "$(mk 1)" >"$T/eng/podman.images"
    run cleanup podman hmtest
    [ "$rc" = 1 ] || return 1
    out_has "cleanup-podman=no-snapshot (nothing removed)" || return 1
    [ ! -s "$LOG" ] || return 1
    file_is "$T/eng/podman.containers" "$(mk a)" || return 1
    # Only one of the two before files present: still no snapshot.
    printf '%s\n' "$(mk a)" >"$state/podman-containers-before.txt"
    printf '%s\n' "$(mk 9)" >>"$T/eng/podman.containers"
    run cleanup podman hmtest
    [ "$rc" = 1 ] && [ "$(log_count ' (rm|rmi) ')" = 0 ] || return 1
    file_is "$T/eng/podman.containers" "$(mk a)
$(mk 9)" || return 1
    # image refuses too, before any engine call.
    new_world present
    : >"$LOG"
    run image podman hmtest "$(base_ref)" localhost/hm-fixture
    [ "$rc" = 1 ] && [ ! -s "$LOG" ] || return 1
    # A failing listing never yields a snapshot (so a later cleanup removes nothing).
    s_fail_list=1
    run snapshot docker hmtest
    [ "$rc" = 1 ] && [ ! -e "$state/docker-containers-before.txt" ] && [ ! -e "$state/docker-images-before.txt" ]
}

t_snapshot_once() {
    new_world present
    run snapshot docker hmtest
    [ "$rc" = 0 ] || return 1
    run snapshot docker hmtest
    [ "$rc" = 1 ]
}

t_guard() {
    local d u nl
    nl=$(printf 'hm-m04-0a1b2c3d-1\nx')
    new_world present
    for d in Ubuntu hm-m04-0A1B2C3D-1 hm-m03-0a1b2c3d hm-m04-0a1b2c3d-3 hm-m04-0a1b2c3d-1x \
        xhm-m04-0a1b2c3d-1 hm-m04-0a1b2c3d hm-m04-0a1b2c3-1 ''; do
        rm -rf "$state"
        : >"$LOG"
        distro=$d
        run snapshot podman hmtest
        [ "$rc" = 2 ] && [ ! -s "$LOG" ] && [ ! -e "$state" ] || return 1
    done
    distro=$nl
    run snapshot podman hmtest
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] && [ ! -e "$state" ] || return 1
    distro=hm-m04-0a1b2c3d-1
    for u in 1000 '' x 00; do
        fake_uid=$u
        for d in snapshot cleanup install dockerd-start dockerd-stop bogus; do
            run "$d" podman hmtest
            [ "$rc" = 2 ] && [ ! -s "$LOG" ] && [ ! -e "$state" ] || return 1
        done
    done
    fake_uid=0
    # Both accepted names pass the guard.
    for d in hm-m04-0a1b2c3d-1 hm-m04-ffffffff-2; do
        rm -rf "$state"
        distro=$d
        run snapshot podman hmtest
        [ "$rc" = 0 ] || return 1
    done
    return 0
}

t_guard_selftest_mode() {
    new_world present
    eroot=""
    run snapshot podman hmtest
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    eroot="relative/dir"
    run snapshot podman hmtest
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    # Without HM_ENGINES_SELFTEST=1 the override variables are ignored: the real `id -u`
    # decides (this check holds for a non-root build host; a root one cannot show it).
    [ "$(id -u)" = 0 ] && return 0
    env -i PATH="$STUB:$TOOLS" HM_ENGINES_FAKE_UID=0 HM_ENGINES_ROOT="$T/root" HM_ENGINES_PROC="$T/proc" \
        WSL_DISTRO_NAME=hm-m04-0a1b2c3d-1 HM_STUB_LOG="$LOG" HM_STUB_ENG="$T/eng" \
        "$BASH" "$script" "$state" snapshot podman hmtest >"$OUT" 2>"$ERR" </dev/null
    rc=$?
    [ "$rc" = 2 ] && [ ! -s "$LOG" ]
}

t_image_args() {
    local b
    new_world present
    run snapshot podman hmtest
    : >"$LOG"
    for b in 'alpine:3.20' "alpine@sha256:$(mk f)x" "alpine@sha256:$(mk F)" "alpine@sha256:$(printf '%063d' 0 | tr 0 f)" \
        "alpine@sha256:abc" "@sha256:$(mk f)" "-evil@sha256:$(mk f)" "alpine sha@sha256:$(mk f)" \
        "alpine@sha1:$(mk f)" "alpine@sha256:$(mk f)
FROM evil" ''; do
        run image podman hmtest "$b" localhost/hm-fixture
        [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    done
    for b in hm-fixture docker.io/hm-fixture localhost/ localhost/-x localhost/UPPER 'localhost/a b' \
        'localhost/a:b' 'localhost/a/b' 'xlocalhost/a' ''; do
        run image podman hmtest "$(base_ref)" "$b"
        [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    done
    # The right shape is accepted (digest by sha256, any registry-ish name).
    run image podman hmtest "registry.example.test:5000/library/alpine@sha256:$(mk f)" localhost/hm-fixture.1_x
    [ "$rc" = 0 ]
}

t_engine_user_args() {
    local u
    new_world present
    : >"$LOG"
    for u in root Root 1abc 'a b' '' -x 'a/b' "$(printf 'hmtest\nx')"; do
        run snapshot podman "$u"
        [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    done
    run snapshot rkt hmtest
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    run snapshot Podman hmtest
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    run snapshot podman ghost
    [ "$rc" = 1 ] && [ ! -s "$LOG" ] || return 1
    run snapshot podman
    [ "$rc" = 2 ] || return 1
    run bogus
    [ "$rc" = 2 ] || return 1
    run install root 1
    [ "$rc" = 2 ] && [ ! -s "$LOG" ] || return 1
    run install hmtest maybe
    [ "$rc" = 2 ] && [ ! -s "$LOG" ]
}

t_state_dir() {
    new_world present
    mkdir -p "$T/elsewhere"
    ln -s "$T/elsewhere" "$state"
    run snapshot podman hmtest
    [ "$rc" = 2 ] && [ -z "$(ls -A "$T/elsewhere")" ] && [ ! -s "$LOG" ] || return 1
    rm -f "$state"
    : >"$state"
    run snapshot podman hmtest
    [ "$rc" = 2 ] || return 1
    rm -f "$state"
    local saved=$state
    for state in relative/state "$T/a/../state" "$T/.." "$T/a/.." ''; do
        run snapshot podman hmtest
        [ "$rc" = 2 ] || { state=$saved; return 1; }
    done
    state="$T/missing-parent/state"
    run snapshot podman hmtest
    [ "$rc" = 1 ] || { state=$saved; return 1; }
    state=$saved
    run snapshot podman hmtest
    [ "$rc" = 0 ] || return 1
    [ "$(ls -ld "$state" | cut -c1-10)" = "drwx------" ]
}

t_install_no_apt() {
    new_world missing
    printf 'other:100000:65536\n' >"$T/root/etc/subuid"
    run install hmtest 0
    [ "$rc" = 3 ] || return 1
    grep -q 'missing:\? *podman docker dockerd newuidmap' "$OUT" || grep -q 'lacks: podman docker dockerd newuidmap' "$OUT" || return 1
    [ "$(log_count '^apt-get')" = 0 ] && [ ! -e "$T/root/usr/sbin/policy-rc.d" ] || return 1
    file_is "$T/root/etc/subuid" "other:100000:65536" || return 1
    [ ! -s "$T/root/etc/subgid" ] && [ ! -s "$T/groups/hmtest" ] || return 1
    # Partly installed: the missing ones are named, the present ones are not.
    cp "$T/avail/podman" "$T/avail/docker" "$STUB"/
    run install hmtest 0
    [ "$rc" = 3 ] && grep -q 'dockerd newuidmap' "$OUT" && ! grep -q 'lacks: podman' "$OUT"
}

t_install_apt() {
    new_world missing
    printf 'other:100000:65536\n' >"$T/root/etc/subuid"
    printf 'other:100000:65536' >"$T/root/etc/subgid"
    run install hmtest 1
    [ "$rc" = 0 ] || return 1
    log_has "apt-get update" || return 1
    log_has "apt-get install -y --no-install-recommends podman uidmap docker.io slirp4netns fuse-overlayfs" || return 1
    log_has "note apt-get update policy-rc.d=blocking" || return 1
    log_has "note apt-get install policy-rc.d=blocking" || return 1
    [ ! -e "$T/root/usr/sbin/policy-rc.d" ] || return 1
    out_has "installed=yes" || return 1
    out_has "podman-version=podman version 5.0.0-stub" || return 1
    out_has "docker-version=Docker version 26.0.0-stub, build stub" || return 1
    out_has "subid=added" || return 1
    out_has "docker-group=added" || return 1
    log_has "usermod -aG docker hmtest" || return 1
    # The existing line is untouched, and the new range starts after it.
    file_is "$T/root/etc/subuid" "other:100000:65536
hmtest:165536:65536" || return 1
    # A file without a final newline gets one before the new line; an empty file starts at 100000.
    file_is "$T/root/etc/subgid" "other:100000:65536
hmtest:165536:65536" || return 1
    : >"$T/root/etc/subuid"
    rm -f "$T/groups/hmtest"
    run install hmtest 0
    [ "$rc" = 0 ] && file_is "$T/root/etc/subuid" "hmtest:100000:65536" || return 1
    # A failing apt-get stops the run, still removing policy-rc.d.
    new_world missing
    s_apt_fail=1
    run install hmtest 1
    [ "$rc" = 1 ] && [ ! -e "$T/root/usr/sbin/policy-rc.d" ] && [ ! -s "$T/root/etc/subuid" ]
}

t_install_twice() {
    local before_uid before_gid
    new_world missing
    printf 'other:100000:65536\n' >"$T/root/etc/subuid"
    run install hmtest 1
    [ "$rc" = 0 ] || return 1
    before_uid=$(cat "$T/root/etc/subuid")
    before_gid=$(cat "$T/root/etc/subgid")
    : >"$LOG"
    run install hmtest 0
    [ "$rc" = 0 ] || return 1
    out_has "subid=present" || return 1
    out_has "docker-group=present" || return 1
    out_has "installed=no (podman, docker, dockerd and newuidmap are all present)" || return 1
    [ "$(cat "$T/root/etc/subuid")" = "$before_uid" ] && [ "$(cat "$T/root/etc/subgid")" = "$before_gid" ] || return 1
    [ "$(grep -c '^hmtest:' "$T/root/etc/subuid")" = 1 ] && [ "$(grep -c '^hmtest:' "$T/root/etc/subgid")" = 1 ] || return 1
    [ "$(log_count '^apt-get')" = 0 ] && [ "$(log_count '^usermod')" = 0 ] || return 1
    # Everything installed and the user already set up: apt is not needed even with permission.
    run install hmtest 1
    [ "$rc" = 0 ] && [ "$(log_count '^apt-get')" = 0 ]
}

t_install_policy() {
    new_world missing
    printf '#!/bin/sh\n# the distribution'"'"'s own\nexit 101\n' >"$T/root/usr/sbin/policy-rc.d"
    run install hmtest 1
    [ "$rc" = 0 ] || return 1
    file_is "$T/root/usr/sbin/policy-rc.d" "#!/bin/sh
# the distribution's own
exit 101" || return 1
    log_has "note apt-get install policy-rc.d=blocking" || return 1
    # An existing policy-rc.d that does not block: refused, nothing installed.
    new_world missing
    printf '#!/bin/sh\nexit 0\n' >"$T/root/usr/sbin/policy-rc.d"
    run install hmtest 1
    [ "$rc" = 1 ] && [ "$(log_count '^apt-get')" = 0 ] && [ -e "$T/root/usr/sbin/policy-rc.d" ]
}

t_stop_reuse() {
    new_world present
    mkdir -m 700 "$state"
    sentinel
    local p=$sentinel_pid
    # Same PID, different start time: pid reused, nothing killed.
    fake_proc "$p" dockerd 100
    printf 'pid=%s\nstart=999\n' "$p" >"$state/dockerd.state"
    run dockerd-stop
    [ "$rc" = 0 ] && out_has "dockerd=pid-reused" && is_alive "$p" || return 1
    # Same start time, another program: nothing killed.
    fake_proc "$p" sleep 999
    printf 'pid=%s\nstart=999\n' "$p" >"$state/dockerd.state"
    run dockerd-stop
    [ "$rc" = 1 ] && out_has "dockerd=not-dockerd" && is_alive "$p" || return 1
    # Gone from /proc: reported, and the live process of that number (here unrelated) is left.
    rm -rf "$T/proc/$p"
    run dockerd-stop
    [ "$rc" = 0 ] && out_has "dockerd=gone" && is_alive "$p" || return 1
    # No record, and a damaged one.
    run dockerd-stop
    [ "$rc" = 0 ] && out_has "dockerd=none" || return 1
    printf 'pid=abc\nstart=1\n' >"$state/dockerd.state"
    run dockerd-stop
    [ "$rc" = 1 ] && out_has "dockerd=bad-state" && is_alive "$p" || return 1
    kill "$p" 2>/dev/null
    return 0
}

t_start_stop() {
    local pid
    new_world present
    start_wait=20
    stop_wait=20
    run dockerd-start
    [ "$rc" = 0 ] && out_has "dockerd=started" || return 1
    pid=$(sed -n 's/^pid=//p' "$state/dockerd.state")
    sentinels="$sentinels $pid"
    [ -n "$pid" ] && is_alive "$pid" || return 1
    file_is "$state/dockerd.state" "pid=$pid
start=4242" || return 1
    file_is "$state/dockerd.pid" "$pid" || return 1
    log_has "dockerd --pidfile $state/dockerd.pid" || return 1
    # A second start is refused while the recorded one lives, and starts nothing.
    run dockerd-start
    [ "$rc" = 1 ] && [ "$(log_count '^dockerd ')" = 1 ] || return 1
    # Another process owning the same PID file name does not matter: stop acts on the record.
    run dockerd-stop
    [ "$rc" = 0 ] && out_has "dockerd=stopped" || return 1
    wait_dead "$pid" || return 1
    [ ! -e "$state/dockerd.state" ] || return 1
    # docker info already answering (a dockerd this run did not start): refused.
    : >"$T/eng/dockerd-up"
    : >"$LOG"
    run dockerd-start
    [ "$rc" = 1 ] && [ "$(log_count '^dockerd ')" = 0 ]
}

t_never_answers() {
    local pid
    new_world present
    s_noreply=1
    start_wait=2
    stop_wait=10
    run dockerd-start
    [ "$rc" = 1 ] || return 1
    grep -q '^dockerd=not-answering' "$OUT" || return 1
    pid=$(sed -n 's/^pid=//p' "$state/dockerd.state" 2>/dev/null)
    [ -z "$pid" ] || sentinels="$sentinels $pid"
    # The process it started is gone, and nothing is recorded as running.
    [ "$(log_count '^dockerd ')" = 1 ] || return 1
    [ -z "$(ls -A "$T/proc")" ] && [ ! -e "$state/dockerd.state" ]
}

t_syntax() { bash -n "$script"; }

check container_harness_removes_only_its_images_and_containers t_lifecycle
check preexisting_image_is_never_recorded_or_removed t_preexisting_image
check cleanup_without_snapshot_removes_nothing t_no_snapshot
check snapshot_is_refused_when_one_exists t_snapshot_once
check guard_refuses_wrong_distribution_or_non_root_before_any_engine t_guard
check guard_selftest_mode_needs_its_sandbox_roots t_guard_selftest_mode
check image_refuses_bad_base_ref_and_tag t_image_args
check engine_and_user_arguments_are_validated t_engine_user_args
check state_directory_is_checked t_state_dir
check install_without_apt_permission_exits_3 t_install_no_apt
check install_with_apt_blocks_services_and_ensures_subid_and_group t_install_apt
check install_second_run_changes_nothing t_install_twice
check install_keeps_an_existing_policy_rc_d t_install_policy
check dockerd_stop_kills_nothing_for_a_reused_pid_or_another_program t_stop_reuse
check dockerd_start_and_stop_manage_exactly_the_recorded_process t_start_stop
check dockerd_that_never_answers_is_stopped t_never_answers
check "bash -n of container-engines.sh" t_syntax

echo "selftest: $passes passed, $fails failed"
[ "$fails" = 0 ]
