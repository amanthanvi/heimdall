#!/usr/bin/env bash
# M04 (A15, the container row): the container engines inside the disposable WSL
# distribution the native harness imported (a distribution named hm-m04-<8 hex>-1 or -2,
# the only kind that harness unregisters). The PowerShell harness sends this file into
# that distribution and runs it as root; it installs podman and docker there, builds the
# fixture image, and afterwards removes only what this run created. Never run elsewhere:
# every command refuses unless it is root inside such a distribution.
#
# Usage (as root, through `wsl.exe -d <name> -u root --exec /bin/bash`):
#   container-engines.sh STATE_DIR COMMAND [ARGS...]
# STATE_DIR is an absolute directory (no `..` component) created 0700 when missing (its
# parent must exist; a symlink or a non-directory is refused). Everything this script
# records lives in it, and it acts on nothing else but the engines, /etc/subuid,
# /etc/subgid, the docker group, the policy-rc.d it creates and the build context it
# creates (a temporary directory under /tmp, removed before the command ends).
#
# Commands:
#   install USER ALLOW_APT      (ALLOW_APT 0|1)
#       when podman, docker, dockerd and newuidmap are all present install nothing; else
#       with ALLOW_APT 0 print what is missing and stop with exit 3; with 1 run
#       `apt-get update` and `apt-get install -y --no-install-recommends podman uidmap
#       docker.io slirp4netns fuse-overlayfs` with every service blocked first
#       (/usr/sbin/policy-rc.d returning 101; removed afterwards only when this script
#       created it; a policy-rc.d that already exists is kept, and refused unless it
#       blocks). Then ensure USER (must exist, not root) has a subuid and a subgid range
#       (a line USER:START:65536 is appended only when USER has no entry; START is 100000,
#       or the end of the last existing range when that is higher, so ranges never
#       overlap; no other line is touched) and is in group docker (usermod -aG, only when
#       not already). Facts: installed=, podman-version=, docker-version=,
#       subid=added|present, docker-group=added|present.
#   dockerd-start
#       start `dockerd --pidfile STATE/dockerd.pid` in the background (no systemd), log in
#       STATE/dockerd.log, wait up to 60 s for `docker info`, record STATE/dockerd.state
#       (pid= and start=, the /proc/<pid>/stat start time). Exit 1 when it never answers
#       (the dockerd it started is stopped) or a dockerd is already running (recorded and
#       alive, or `docker info` already answers).
#   dockerd-stop
#       stop exactly the recorded dockerd: dockerd=gone when /proc/<pid> is gone;
#       dockerd=pid-reused (nothing killed) when the start time differs;
#       dockerd=not-dockerd (nothing killed, exit 1) when /proc/<pid>/comm is not dockerd;
#       else SIGTERM, up to 30 s, then SIGKILL, and dockerd=stopped. Never by name or
#       pattern.
#   snapshot ENGINE USER
#       ENGINE is podman (run as USER through `runuser -u USER -- podman`, rootless) or
#       docker (as root). Record the full IDs of the existing containers (`ps -a -q
#       --no-trunc`) and images (`images -q --no-trunc`) in STATE/ENGINE-containers-before.txt
#       and STATE/ENGINE-images-before.txt. Must run before `image`; a second snapshot is
#       refused (it would claim this run's images as older ones).
#   image ENGINE USER BASE_REF TAG
#       BASE_REF is NAME@sha256:<64 lowercase hex> (no tag-only reference), TAG is
#       localhost/<name>. Pull the base by digest, build TAG from `FROM BASE_REF` and
#       `RUN apk add --no-cache openssh-client` (the base is Alpine; a copy of the build
#       file is kept in STATE/ENGINE-Containerfile), and append the base's and the built
#       image's full IDs to STATE/ENGINE-images-created.txt, never an ID listed in
#       ENGINE-images-before.txt. Facts: image-ENGINE-base=, image-ENGINE=.
#   cleanup ENGINE USER
#       remove (a) every container that exists now and is not in the containers-before
#       file (`rm -f <full id>`, one at a time) and (b) every ID in images-created that is
#       not in images-before (`rmi -f <full id>`, newest first). Facts: removed-container=,
#       removed-image=, cleanup-ENGINE=ok|incomplete. Without the snapshot it removes
#       NOTHING (cleanup-ENGINE=no-snapshot, exit 1).
#
# Exit: 0 ok; 1 a step failed; 2 usage or refused; 3 blocked (tools missing and apt not
# allowed).
#
# Safety rules:
#   * root and WSL_DISTRO_NAME matching ^hm-m04-[0-9a-f]{8}-[12]$ are checked before
#     anything else, by every command.
#   * Engine objects are removed by full ID only, and only when they are absent from the
#     before snapshot. Nothing is stopped by name or pattern.
#   * Outputs are key=value facts only: no environment, command line, credential or log
#     text. Engine output goes to STATE/*.log.
#   * Self-test only (tests/native/m04/selftest.sh): with HM_ENGINES_SELFTEST=1 the root
#     check reads HM_ENGINES_FAKE_UID instead of `id -u` (the distribution-name check
#     still applies), /etc, /usr/sbin and /tmp are read below HM_ENGINES_ROOT, /proc is
#     read from HM_ENGINES_PROC, and the waits come from HM_ENGINES_START_WAIT and
#     HM_ENGINES_STOP_WAIT (seconds). HM_ENGINES_ROOT and HM_ENGINES_PROC must then be
#     absolute directories, so the mode cannot touch the real ones. Outside that mode
#     all four variables are ignored.

set -u
export LC_ALL=C
umask 077

refuse() {
    echo "refusing: $*" >&2
    exit 2
}
usage() {
    echo "usage: container-engines.sh STATE_DIR install|dockerd-start|dockerd-stop|snapshot|image|cleanup [ARGS...]" >&2
    exit 2
}

re_distro='^hm-m04-[0-9a-f]{8}-[12]$'
re_user='^[a-z_][a-z0-9_-]{0,31}$'
re_id='^[0-9a-f]{64}$'
re_base='^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$'
re_tag='^localhost/[a-z0-9][a-z0-9._-]*$'

# --- the guard (before anything else) -------------------------------------------------------

R=""
PROC=/proc
START_WAIT=60
STOP_WAIT=30
if [ "${HM_ENGINES_SELFTEST:-}" = 1 ]; then
    R=${HM_ENGINES_ROOT:-}
    PROC=${HM_ENGINES_PROC:-}
    case "$R" in /?*) ;; *) refuse "self-test mode needs HM_ENGINES_ROOT (an absolute directory)" ;; esac
    case "$PROC" in /?*) ;; *) refuse "self-test mode needs HM_ENGINES_PROC (an absolute directory)" ;; esac
    uid=${HM_ENGINES_FAKE_UID:-}
    START_WAIT=${HM_ENGINES_START_WAIT:-$START_WAIT}
    STOP_WAIT=${HM_ENGINES_STOP_WAIT:-$STOP_WAIT}
else
    uid=$(id -u)
    PATH="$PATH:/usr/sbin:/sbin"
fi
[ "$uid" = 0 ] || refuse "needs root inside the disposable distribution"
[[ ${WSL_DISTRO_NAME:-} =~ $re_distro ]] || refuse "not inside a disposable hm-m04 distribution"
case "$START_WAIT$STOP_WAIT" in '' | *[!0-9]*) refuse "bad wait" ;; esac

# --- the state directory -------------------------------------------------------------------

[ $# -ge 2 ] || usage
state=$1
cmd=$2
shift 2
case "$state" in /?*) ;; *) refuse "the state directory must be an absolute path" ;; esac
case "$state" in */.. | */../*) refuse "the state directory path has a .. component" ;; esac
[ ! -L "$state" ] || refuse "the state directory is a symlink"
if [ -e "$state" ]; then
    [ -d "$state" ] || refuse "the state directory is not a directory"
else
    mkdir -m 700 -- "$state" 2>/dev/null || { echo "cannot create the state directory" >&2; exit 1; }
fi
cd / || exit 1

# --- helpers -------------------------------------------------------------------------------

# Services blocked while apt installs (policy-rc.d), and the build context directory:
# the two things this script creates outside STATE_DIR, both removed on every exit.
prc="$R/usr/sbin/policy-rc.d"
prc_created=0
ctx=""
on_exit() {
    if [ "$prc_created" = 1 ]; then
        rm -f -- "$prc"
        prc_created=0
    fi
    if [ -n "$ctx" ]; then
        rm -rf -- "$ctx"
        ctx=""
    fi
}
trap on_exit EXIT

is_num() {
    case "$1" in '' | *[!0-9]*) return 1 ;; esac
    return 0
}
is_full_id() { [[ $1 =~ $re_id ]]; }
# has_id ID FILE: ID is a whole line of FILE.
has_id() { grep -Fxq -- "$1" "$2" 2>/dev/null; }
read_kv() { sed -n "s/^$1=//p" "$2" 2>/dev/null | head -n 1; }
lines_of() { awk 'END { print NR }' "$1"; }

proc_comm() { head -n 1 "$PROC/$1/comm" 2>/dev/null; }
# The start time: /proc stat field 22 (what is left after the "pid (comm) " prefix, field 20).
proc_start() { sed -e 's/^.*) //' "$PROC/$1/stat" 2>/dev/null | awk '{ print $20 }'; }
proc_state() { sed -e 's/^.*) //' "$PROC/$1/stat" 2>/dev/null | cut -c1; }
# alive PID: present and not a zombie awaiting its reaper.
alive() { [ -d "$PROC/$1" ] && [ "$(proc_state "$1")" != Z ]; }

valid_engine() {
    case "$1" in podman | docker) return 0 ;; esac
    return 1
}
# check_user USER: the name has the account-name shape, is not root, and exists.
check_user() {
    local uid2
    [[ $1 =~ $re_user ]] || refuse "bad user name"
    [ "$1" != root ] || refuse "the user must not be root"
    uid2=$(id -u "$1" 2>/dev/null) || { echo "the user does not exist" >&2; exit 1; }
    [ "$uid2" != 0 ] || refuse "the user must not be root"
}
# check_engine_user ENGINE USER
check_engine_user() {
    valid_engine "$1" || refuse "the engine must be podman or docker"
    check_user "$2"
}

# eng ENGINE USER ARGS...: the engine's command line (podman rootless as USER, docker as root).
eng() {
    local e=$1 u=$2
    shift 2
    if [ "$e" = podman ]; then
        runuser -u "$u" -- podman "$@" </dev/null
    else
        docker "$@" </dev/null
    fi
}

# list_ids ENGINE USER containers|images OUT: the sorted full IDs (a "sha256:" prefix is
# dropped, so docker's and podman's listings compare). Fails, leaving no OUT, when the
# listing fails or any line is not a 64-hex ID.
list_ids() {
    local e=$1 u=$2 kind=$3 out=$4 raw id
    if [ "$kind" = containers ]; then
        raw=$(eng "$e" "$u" ps -a -q --no-trunc 2>>"$state/$e-engine.log") || return 1
    else
        raw=$(eng "$e" "$u" images -q --no-trunc 2>>"$state/$e-engine.log") || return 1
    fi
    : >"$out.tmp" || return 1
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        id=${id#sha256:}
        is_full_id "$id" || { rm -f -- "$out.tmp"; return 1; }
        printf '%s\n' "$id" >>"$out.tmp"
    done <<EOF
$raw
EOF
    sort -u "$out.tmp" >"$out" || { rm -f -- "$out.tmp"; return 1; }
    rm -f -- "$out.tmp"
}

# --- install --------------------------------------------------------------------------------

have_tool() { command -v "$1" >/dev/null 2>&1; }
missing_tools() {
    local t m=""
    for t in podman docker dockerd newuidmap; do
        have_tool "$t" || m="$m $t"
    done
    printf '%s' "$m"
}

# block_services: policy-rc.d exit 101, created here (and removed by on_exit) unless the
# distribution already has one, which is kept and must itself answer 101.
block_services() {
    if [ -e "$prc" ] || [ -L "$prc" ]; then
        sh "$prc" hm-m04 start >/dev/null 2>&1
        [ $? = 101 ] || return 1
        return 0
    fi
    printf '#!/bin/sh\nexit 101\n' >"$prc" || return 1
    chmod 755 "$prc" || { rm -f -- "$prc"; return 1; }
    prc_created=1
}

# ensure_subid FILE USER: prints added|present; appends USER:START:65536 only when USER
# has no entry. START is 100000, or past the end of every existing range when that is more.
ensure_subid() {
    local f=$1 u=$2 start
    if [ -f "$f" ] && grep -q -- "^$u:" "$f"; then
        echo present
        return 0
    fi
    [ -e "$f" ] || { : >"$f" && chmod 644 "$f"; } || return 1
    start=$(awk -F: 'BEGIN { n = 100000 }
        $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $2 + $3 > n { n = $2 + $3 }
        END { printf "%.0f\n", n }' "$f") || return 1
    {
        [ -z "$(tail -c 1 "$f")" ] || printf '\n'
        printf '%s:%s:65536\n' "$u" "$start"
    } >>"$f" || return 1
    echo added
}

cmd_install() {
    [ $# = 2 ] || usage
    local user=$1 allow=$2 missing rc sub=present r
    case "$allow" in 0 | 1) ;; *) refuse "allow-apt must be 0 or 1" ;; esac
    check_user "$user"
    missing=$(missing_tools)
    if [ -z "$missing" ]; then
        echo "installed=no (podman, docker, dockerd and newuidmap are all present)"
    else
        echo "missing-before=$missing"
        if [ "$allow" != 1 ]; then
            echo "blocked=the image lacks:$missing (allow-apt 1 installs them inside this distribution)"
            exit 3
        fi
        block_services || { echo "install=refused (services cannot be blocked: policy-rc.d exists and does not answer 101)"; exit 1; }
        DEBIAN_FRONTEND=noninteractive apt-get update >"$state/apt.log" 2>&1 </dev/null
        rc=$?
        if [ "$rc" = 0 ]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                podman uidmap docker.io slirp4netns fuse-overlayfs >>"$state/apt.log" 2>&1 </dev/null
            rc=$?
        fi
        on_exit
        echo "apt-install-exit=$rc"
        [ "$rc" = 0 ] || exit 1
        missing=$(missing_tools)
        [ -z "$missing" ] || { echo "installed=incomplete (still missing:$missing)"; exit 1; }
        echo "installed=yes"
    fi
    for f in subuid subgid; do
        r=$(ensure_subid "$R/etc/$f" "$user") || { echo "install=failed (/etc/$f)"; exit 1; }
        [ "$r" = added ] && sub=added
    done
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq docker; then
        r=present
    else
        grep -q '^docker:' "$R/etc/group" 2>/dev/null || { echo "install=failed (no docker group)"; exit 1; }
        usermod -aG docker "$user" >>"$state/install.log" 2>&1 || { echo "install=failed (usermod)"; exit 1; }
        r=added
    fi
    echo "podman-version=$(podman --version 2>/dev/null | head -n 1)"
    echo "docker-version=$(docker --version 2>/dev/null | head -n 1)"
    echo "subid=$sub"
    echo "docker-group=$r"
}

# --- dockerd --------------------------------------------------------------------------------

# resolve_dockerd PIDFILE LAUNCHED: the dockerd's PID (the one in its pid file, else the
# launched process), only when /proc says its comm is dockerd.
resolve_dockerd() {
    local p
    if [ -s "$1" ]; then
        p=$(head -n 1 "$1" | tr -dc '0-9')
        if [ -n "$p" ] && [ "$(proc_comm "$p")" = dockerd ]; then
            echo "$p"
            return 0
        fi
    fi
    if [ "$(proc_comm "$2")" = dockerd ]; then
        echo "$2"
    fi
    return 0
}

# stop_recorded: stop exactly the dockerd recorded in dockerd.state; prints dockerd=...;
# returns 0 when nothing of it is left to stop or it stopped, 1 otherwise.
stop_recorded() {
    local sf="$state/dockerd.state" pid start i max
    [ -f "$sf" ] || { echo "dockerd=none"; return 0; }
    pid=$(read_kv pid "$sf")
    start=$(read_kv start "$sf")
    if ! is_num "$pid" || ! is_num "$start"; then
        echo "dockerd=bad-state"
        return 1
    fi
    if [ ! -d "$PROC/$pid" ]; then
        echo "dockerd=gone"
        rm -f -- "$sf" "$state/dockerd.pid"
        return 0
    fi
    if [ "$(proc_start "$pid")" != "$start" ]; then
        echo "dockerd=pid-reused"
        rm -f -- "$sf" "$state/dockerd.pid"
        return 0
    fi
    if [ "$(proc_comm "$pid")" != dockerd ]; then
        echo "dockerd=not-dockerd"
        return 1
    fi
    kill -TERM "$pid" 2>/dev/null
    i=0
    max=$((STOP_WAIT * 5))
    while [ "$i" -lt "$max" ] && alive "$pid"; do
        sleep 0.2
        i=$((i + 1))
    done
    if alive "$pid"; then
        kill -KILL "$pid" 2>/dev/null
        i=0
        while [ "$i" -lt 25 ] && alive "$pid"; do
            sleep 0.2
            i=$((i + 1))
        done
    fi
    if alive "$pid"; then
        echo "dockerd=still-running"
        return 1
    fi
    rm -f -- "$sf" "$state/dockerd.pid"
    echo "dockerd=stopped"
}

cmd_dockerd_start() {
    [ $# = 0 ] || usage
    local sf="$state/dockerd.state" pf="$state/dockerd.pid" lg="$state/dockerd.log"
    local rec_pid rec_start launched pid="" i=0 max=$((START_WAIT * 2)) comm
    if [ -f "$sf" ]; then
        rec_pid=$(read_kv pid "$sf")
        rec_start=$(read_kv start "$sf")
        if is_num "$rec_pid" && [ -d "$PROC/$rec_pid" ] && [ "$(proc_start "$rec_pid")" = "$rec_start" ]; then
            echo "dockerd=already-running (recorded)"
            exit 1
        fi
    fi
    if docker info >/dev/null 2>&1 </dev/null; then
        echo "dockerd=already-answering (not started by this run)"
        exit 1
    fi
    rm -f -- "$sf" "$pf"
    if command -v setsid >/dev/null 2>&1; then
        setsid dockerd --pidfile "$pf" >"$lg" 2>&1 </dev/null &
    else
        nohup dockerd --pidfile "$pf" >"$lg" 2>&1 </dev/null &
    fi
    launched=$!
    while :; do
        if [ -z "$pid" ]; then
            pid=$(resolve_dockerd "$pf" "$launched")
            if [ -n "$pid" ]; then
                # Recorded as soon as it is known, so dockerd-stop finds it even if this
                # script is interrupted while waiting.
                printf 'pid=%s\nstart=%s\n' "$pid" "$(proc_start "$pid")" >"$sf.tmp" && mv -f "$sf.tmp" "$sf"
            fi
        fi
        if [ -n "$pid" ] && docker info >/dev/null 2>&1 </dev/null; then
            echo "dockerd=started"
            echo "dockerd-pid=$pid"
            return 0
        fi
        [ "$i" -lt "$max" ] || break
        sleep 0.5
        i=$((i + 1))
    done
    if [ -n "$pid" ]; then
        stop_recorded
    else
        # Never identified as dockerd: stop only our own launched process, and only while
        # it is still one of the three programs this script launches.
        comm=$(proc_comm "$launched")
        case "$comm" in setsid | nohup | dockerd) kill -TERM "$launched" 2>/dev/null ;; esac
    fi
    echo "dockerd=not-answering (it never answered docker info; what this run started was stopped)"
    exit 1
}

cmd_dockerd_stop() {
    [ $# = 0 ] || usage
    stop_recorded || exit 1
}

# --- snapshot, image, cleanup ---------------------------------------------------------------

cmd_snapshot() {
    [ $# = 2 ] || usage
    local e=$1 u=$2
    check_engine_user "$e" "$u"
    local cb="$state/$e-containers-before.txt" ib="$state/$e-images-before.txt"
    if [ -e "$cb" ] || [ -e "$ib" ] || [ -e "$state/$e-images-created.txt" ]; then
        echo "snapshot-$e=refused (this run already has a snapshot or created images)"
        exit 1
    fi
    list_ids "$e" "$u" images "$ib.new" || { echo "snapshot-$e=failed (images)"; exit 1; }
    if ! list_ids "$e" "$u" containers "$cb.new"; then
        rm -f -- "$ib.new"
        echo "snapshot-$e=failed (containers)"
        exit 1
    fi
    mv -f "$ib.new" "$ib" && mv -f "$cb.new" "$cb" || { echo "snapshot-$e=failed (record)"; exit 1; }
    echo "snapshot-$e-containers=$(lines_of "$cb")"
    echo "snapshot-$e-images=$(lines_of "$ib")"
}

cmd_image() {
    [ $# = 4 ] || usage
    local e=$1 u=$2 base=$3 tag=$4 id created="$state/$1-images-created.txt"
    check_engine_user "$e" "$u"
    [[ $base =~ $re_base ]] || refuse "the base must be NAME@sha256:<64 lowercase hex>"
    [[ $tag =~ $re_tag ]] || refuse "the tag must be localhost/<name>"
    if [ ! -f "$state/$e-containers-before.txt" ] || [ ! -f "$state/$e-images-before.txt" ]; then
        echo "image-$e=no-snapshot (run snapshot first)"
        exit 1
    fi
    # record_image ID: kept for cleanup unless it existed before the run (or is recorded).
    record_image() {
        if has_id "$1" "$state/$e-images-before.txt"; then
            echo "image-$e-preexisting=$1 (not recorded: it existed before this run)"
        elif ! has_id "$1" "$created"; then
            printf '%s\n' "$1" >>"$created"
        fi
    }
    eng "$e" "$u" pull "$base" >>"$state/$e-pull.log" 2>&1 || { echo "image-$e=pull-failed"; exit 1; }
    id=$(eng "$e" "$u" image inspect --format '{{.Id}}' "$base" 2>>"$state/$e-engine.log") || { echo "image-$e=inspect-failed (base)"; exit 1; }
    id=${id#sha256:}
    is_full_id "$id" || { echo "image-$e=inspect-failed (base id)"; exit 1; }
    record_image "$id" || exit 1
    echo "image-$e-base=$id"
    # The build file is also copied into STATE (evidence); the build itself reads a
    # world-readable temporary context, because the rootless podman user cannot enter the
    # 0700 STATE directory.
    ctx=$(mktemp -d "$R/tmp/hm-m04-build.XXXXXX") || { echo "image-$e=failed (no build context)"; exit 1; }
    chmod 755 "$ctx" || exit 1
    printf 'FROM %s\nRUN apk add --no-cache openssh-client\n' "$base" >"$state/$e-Containerfile" || exit 1
    cp "$state/$e-Containerfile" "$ctx/Containerfile" && chmod 644 "$ctx/Containerfile" || exit 1
    eng "$e" "$u" build -t "$tag" -f "$ctx/Containerfile" "$ctx" >>"$state/$e-build.log" 2>&1 || { echo "image-$e=build-failed"; exit 1; }
    id=$(eng "$e" "$u" image inspect --format '{{.Id}}' "$tag" 2>>"$state/$e-engine.log") || { echo "image-$e=inspect-failed (built)"; exit 1; }
    id=${id#sha256:}
    is_full_id "$id" || { echo "image-$e=inspect-failed (built id)"; exit 1; }
    record_image "$id" || exit 1
    echo "image-$e=$id"
}

cmd_cleanup() {
    [ $# = 2 ] || usage
    local e=$1 u=$2 id rc=0 cb ib created now rev
    check_engine_user "$e" "$u"
    cb="$state/$e-containers-before.txt"
    ib="$state/$e-images-before.txt"
    created="$state/$e-images-created.txt"
    now="$state/$e-now.txt"
    rev="$state/$e-created-reversed.txt"
    if [ ! -f "$cb" ] || [ ! -f "$ib" ]; then
        echo "cleanup-$e=no-snapshot (nothing removed)"
        exit 1
    fi
    # (a) containers that exist now and were not there before the run.
    if list_ids "$e" "$u" containers "$now"; then
        while IFS= read -r id; do
            [ -n "$id" ] || continue
            has_id "$id" "$cb" && continue
            if eng "$e" "$u" rm -f "$id" >>"$state/$e-cleanup.log" 2>&1; then
                echo "removed-container=$id"
            else
                echo "failed-container=$id"
                rc=1
            fi
        done <"$now"
    else
        echo "failed-container-listing=1"
        rc=1
    fi
    # (b) images this run created (newest first, so a child goes before its base).
    if [ -f "$created" ]; then
        awk '{ a[NR] = $0 } END { for (i = NR; i >= 1; i--) print a[i] }' "$created" >"$rev" || rc=1
        while IFS= read -r id; do
            [ -n "$id" ] || continue
            if ! is_full_id "$id"; then
                echo "failed-image=invalid-record"
                rc=1
            elif has_id "$id" "$ib"; then
                echo "kept-image=$id (it existed before this run)"
            elif eng "$e" "$u" rmi -f "$id" >>"$state/$e-cleanup.log" 2>&1; then
                echo "removed-image=$id"
            elif list_ids "$e" "$u" images "$now" && ! has_id "$id" "$now"; then
                echo "absent-image=$id"
            else
                echo "failed-image=$id"
                rc=1
            fi
        done <"$rev"
    fi
    if [ "$rc" = 0 ]; then
        echo "cleanup-$e=ok"
    else
        echo "cleanup-$e=incomplete"
    fi
    exit "$rc"
}

case "$cmd" in
    install) cmd_install "$@" ;;
    dockerd-start) cmd_dockerd_start "$@" ;;
    dockerd-stop) cmd_dockerd_stop "$@" ;;
    snapshot) cmd_snapshot "$@" ;;
    image) cmd_image "$@" ;;
    cleanup) cmd_cleanup "$@" ;;
    *) usage ;;
esac
