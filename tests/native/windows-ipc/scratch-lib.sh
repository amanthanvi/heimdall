# shellcheck shell=bash
# Scratch-directory helpers for the Windows native harnesses (review B01):
# tests/native/windows-ipc/run-native.sh and tests/native/m01/run-windows.sh send
# this file to the WSL host ahead of every remote script (on stdin, with
# `bash -s`), and tools/validation/native-harness-selftest.sh sources it locally.
# Bash 3.2 compatible; no `set -e` assumptions.
#
# Rules:
#   * Every run uses its own directory `<parent>/hm-m00/<task>-<random>`, created
#     with a plain `mkdir` (no `-p`): an existing entry of that name is an error,
#     never reused.
#   * The scratch root `<parent>/hm-m00` may be created, but a symlink or
#     non-directory there is refused (never followed).
#   * Removal takes the exact path a successful creation printed, re-checks its
#     shape (`/.../hm-m00/<run>`) and that neither it nor its root is a symlink,
#     and removes only that directory.
#   * Names are `[A-Za-z0-9][A-Za-z0-9._-]*`, never `.` or `..`.

# hm_valid_name NAME: 0 when NAME is an acceptable task or run name.
hm_valid_name() {
    case "$1" in
        '' | . | .. | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}

# hm_scratch_root PARENT: print PARENT/hm-m00 once it is a real directory (created
# when absent; a symlink or a non-directory is refused).
hm_scratch_root() {
    local root="$1/hm-m00"
    if [ ! -e "$root" ] && [ ! -L "$root" ]; then
        # A concurrent creator is fine: the checks below decide.
        mkdir -m 700 -- "$root" 2>/dev/null || true
    fi
    if [ -L "$root" ] || [ ! -d "$root" ]; then
        echo "scratch root is a symlink or not a directory; refusing" >&2
        return 1
    fi
    printf '%s\n' "$root"
}

# hm_scratch_create PARENT RUN: create PARENT/hm-m00/RUN exclusively and print
# its path. Fails, creating nothing, if RUN is invalid, the root is refused, or
# an entry named RUN already exists.
hm_scratch_create() {
    local root run="$2"
    hm_valid_name "$run" || { echo "invalid run name" >&2; return 2; }
    root=$(hm_scratch_root "$1") || return 1
    if ! mkdir -m 700 -- "$root/$run" 2>/dev/null; then
        echo "run directory exists or cannot be created; refusing to reuse it" >&2
        return 1
    fi
    printf '%s\n' "$root/$run"
}

# hm_scratch_remove PATH RUN: remove exactly PATH, a directory this run created.
# An empty PATH means nothing was created: nothing to do.
hm_scratch_remove() {
    local path="$1" run="$2"
    [ -n "$path" ] || return 0
    hm_valid_name "$run" || { echo "invalid run name" >&2; return 2; }
    case "$path" in
        # Only an absolute, normalized path (no '.', '..' or empty components).
        */./* | */../* | *//* | ./* | ../*) echo "refusing to remove an unexpected path" >&2; return 1 ;;
        /*/hm-m00/"$run") ;;
        *) echo "refusing to remove an unexpected path" >&2; return 1 ;;
    esac
    if [ -L "${path%/*}" ] || [ -L "$path" ]; then
        echo "refusing to remove through a symlink" >&2
        return 1
    fi
    [ -d "$path" ] || return 0
    rm -rf -- "$path"
}
