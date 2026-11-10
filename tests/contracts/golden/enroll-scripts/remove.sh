# Heimdall remote registry script: remove (HM1 v=1; ADR-0008 D5 6.3).
# Every value is a validated literal in single quotes. /bin/sh -s reads this
# after the HM1 ready line; nothing runs before the call on the last line.
hm_main() {
  export LC_ALL=C
  umask 077
  export TZ=UTC0
  set -f
  HM_STAGE='remove'
  HM_REG_ARG=''
  HM_MARKER='heimdall:enr_0123456789abcdef0123456789abcdef'
  HM_TOKEN='00112233445566778899aabbccddeeff'
  HM_NOT_AFTER='1800000000'
  HM_LOCKED=no
  HM_PRE_MADE=no
  HM_POST_MADE=no
  HM_REFUSAL=
  hm_out() {
    printf 'HM1 %s=%s\n' "$1" "$2"
  }
  hm_hex() {
    od -An -v -tx1 | awk '{ for (i = 1; i <= NF; i++) printf "%s", $i }'
  }
  hm_unlock() {
    if [ "$HM_LOCKED" = yes ]; then
      HM_LOCKED=no
      hm_lock_read
      if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_RECORD" ]; then
        rm -f "$HM_LOCK"
      fi
    fi
  }
  hm_cleanup() {
    if [ "$HM_PRE_MADE" = yes ]; then
      rm -f "$HM_PRE"
    fi
    if [ "$HM_POST_MADE" = yes ]; then
      rm -f "$HM_POST"
    fi
    hm_unlock
  }
  hm_end() {
    hm_unlock
    hm_out status "$2"
    if [ -n "$3" ]; then
      hm_out reason "$3"
    fi
    exit "$1"
  }
  hm_refuse() {
    if [ "$HM_STAGE" = inspect ]; then
      if [ -z "$HM_REFUSAL" ]; then
        HM_REFUSAL=$1
      fi
    else
      hm_end 30 refused "$1"
    fi
  }
  hm_clock() {
    HM_NOW=$(date -u '+%Y %m %d %H %M %S' 2>/dev/null | awk 'NF == 6 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/ && $6 ~ /^[0-9]+$/ { y = $1 + 0; m = $2 + 0; if (m <= 2) { y = y - 1; m = m + 12 }; e = int(y / 400); a = y - e * 400; d = a * 365 + int(a / 4) - int(a / 100) + int((153 * (m - 3) + 2) / 5) + $3 - 1; printf "%d\n", (e * 146097 + d - 719468) * 86400 + $4 * 3600 + $5 * 60 + $6 }')
    case "$HM_NOW" in
      ''|*[!0-9]*) hm_end 30 refused clock_unavailable ;;
    esac
  }
  hm_resolve() {
    if [ -n "$HM_REG_ARG" ]; then
      HM_REG=$HM_REG_ARG
    else
      case "${HOME-}" in
        /*) HM_REG="$HOME/.ssh/authorized_keys" ;;
        *) hm_end 30 refused home_unset ;;
      esac
    fi
    HM_NAME=${HM_REG##*/}
    HM_DIR=${HM_REG%/*}
    if [ -z "$HM_DIR" ]; then
      HM_DIR=/
    fi
    HM_LOCK="$HM_DIR/.hm-lock.$HM_NAME"
    HM_PRE="$HM_DIR/.hm-pre.${HM_TOKEN-}"
    HM_POST="$HM_DIR/.hm-post.${HM_TOKEN-}"
    printf 'HM1 path_hex='
    printf '%s' "$HM_REG" | hm_hex
    printf '\n'
  }
  hm_uid() {
    HM_UID=$(id -u 2>/dev/null)
    case "$HM_UID" in
      ''|*[!0-9]*) hm_end 30 refused uid_unavailable ;;
    esac
  }
  hm_ls() {
    HM_LS_MODE=
    HM_LS_OUT=$(ls -ldn "$1" 2>/dev/null) || return 1
    set -- $HM_LS_OUT
    if [ "$#" -lt 5 ]; then
      return 1
    fi
    HM_LS_MODE=$1
    HM_LS_LINKS=$2
    HM_LS_UID=$3
    HM_LS_SIZE=$5
    case "$HM_LS_LINKS:$HM_LS_UID:$HM_LS_SIZE" in
      *[!0-9:]*|:*|*::*|*:) return 1 ;;
    esac
    case "$HM_LS_MODE" in
      ??????????) HM_MODE10=$HM_LS_MODE; HM_MODE_IND= ;;
      ??????????[+@.]) HM_MODE10=${HM_LS_MODE%?}; HM_MODE_IND=${HM_LS_MODE#??????????} ;;
      *) return 1 ;;
    esac
    case "$HM_MODE10" in
      *[!A-Za-z-]*) return 1 ;;
    esac
  }
  hm_lock_read() {
    HM_LOCK_REC=
    if [ -L "$HM_LOCK" ]; then
      HM_LOCK_STATE=held
      HM_LOCK_LS=$(ls -ld "$HM_LOCK" 2>/dev/null)
      case "$HM_LOCK_LS" in
        l*' -> '*) HM_LOCK_REC=${HM_LOCK_LS##* -> } ;;
      esac
    elif [ -e "$HM_LOCK" ]; then
      HM_LOCK_STATE=other
    else
      HM_LOCK_STATE=none
    fi
  }
  hm_record_ok() {
    case "$1" in
      hm1-*-*-*-*-*) ;;
      *) return 1 ;;
    esac
    case "$1" in
      *[!0-9a-z-]*|*--*|*-) return 1 ;;
    esac
    HM_R_IFS=$IFS
    IFS=-
    set -- $1
    IFS=$HM_R_IFS
    if [ "$#" -ne 6 ]; then
      return 1
    fi
    HM_R_TOKEN=$2
    HM_R_PID=$3
    HM_R_START=$4
    HM_R_BOOT=$5
    HM_R_NA=$6
    case "$HM_R_TOKEN" in
      ????????????????????????????????) ;;
      *) return 1 ;;
    esac
    case "$HM_R_TOKEN:$HM_R_START:$HM_R_BOOT" in
      *[!0-9a-f:]*) return 1 ;;
    esac
    case "$HM_R_PID" in
      0*|*[!0-9]*) return 1 ;;
    esac
    case "$HM_R_NA" in
      *[!0-9]*) return 1 ;;
    esac
  }
  hm_lock_report() {
    hm_lock_read
    if [ "$HM_LOCK_STATE" = none ]; then
      hm_out lock none
    else
      hm_out lock held
      if hm_record_ok "$HM_LOCK_REC"; then
        hm_out lock_holder "$HM_LOCK_REC"
      fi
    fi
  }
  hm_check_dir() {
    if hm_ls "$HM_DIR"; then
      hm_out dir present
      hm_out dir_mode "$HM_LS_MODE"
      if [ "$HM_LS_UID" = "$HM_UID" ]; then
        hm_out dir_owner_self yes
      else
        hm_out dir_owner_self no
      fi
    else
      hm_out dir present
      hm_refuse dir_unreadable
      return 0
    fi
    case "$HM_MODE10" in
      d*) ;;
      *) hm_refuse dir_not_directory ;;
    esac
    if [ "$HM_LS_UID" != "$HM_UID" ]; then
      hm_refuse dir_owner_foreign
    fi
    case "$HM_MODE10" in
      ?????w????|????????w?) hm_refuse dir_writable_by_others ;;
    esac
    if [ "$HM_MODE_IND" = + ]; then
      hm_refuse dir_acl
    fi
  }
  hm_check_file() {
    HM_SIZE=0
    if [ -L "$HM_REG" ]; then
      HM_FILE=symlink
      hm_out file symlink
      hm_refuse registry_symlink
    elif [ ! -e "$HM_REG" ]; then
      HM_FILE=absent
      hm_out file absent
    elif [ ! -f "$HM_REG" ]; then
      HM_FILE=other
      hm_out file other
      hm_refuse registry_not_regular
    elif hm_ls "$HM_REG"; then
      HM_FILE=regular
      HM_SIZE=$HM_LS_SIZE
      hm_out file regular
      hm_out links "$HM_LS_LINKS"
      hm_out mode "$HM_LS_MODE"
      if [ "$HM_LS_UID" = "$HM_UID" ]; then
        hm_out owner_self yes
      else
        hm_out owner_self no
      fi
      hm_out size "$HM_LS_SIZE"
      if [ "$HM_LS_LINKS" != 1 ]; then
        hm_refuse registry_hardlinked
      fi
      if [ "$HM_LS_UID" != "$HM_UID" ]; then
        hm_refuse registry_owner_foreign
      fi
      if [ -n "$HM_MODE_IND" ]; then
        hm_refuse registry_acl_or_label
      fi
    else
      HM_FILE=other
      hm_out file other
      hm_refuse registry_unreadable
    fi
  }
  hm_content() {
    if [ ! -r "$HM_REG" ]; then
      if [ "$1" = check ]; then
        hm_refuse registry_unreadable
      fi
      return 0
    fi
    HM_LAST=$(tail -c 1 "$HM_REG" 2>/dev/null | hm_hex)
    if [ "$HM_LAST" = 0a ]; then
      hm_out last_byte_newline yes
    else
      hm_out last_byte_newline no
    fi
    HM_COUNT=$(grep -c -F -e "$HM_MARKER" "$HM_REG" 2>/dev/null)
    case "$HM_COUNT" in
      ''|*[!0-9]*)
        if [ "$1" = check ]; then
          hm_refuse registry_unreadable
        fi
        return 0
        ;;
    esac
    hm_out marker_lines "$HM_COUNT"
    printf 'HM1 content_hex='
    hm_hex < "$HM_REG"
    printf '\n'
  }
  hm_procstat() {
    awk '{ b = b $0 "\n" } END { i = length(b); while (i > 0 && substr(b, i, 1) != ")") i--;
        if (i == 0) exit 2; n = split(substr(b, i + 1), f, " ");
        if (n < 20 || f[1] !~ /^[A-Za-z]$/ || f[3] !~ /^[0-9]+$/ || f[3] + 0 < 1 ||
            f[20] !~ /^[0-9]+$/) exit 2; print f[3], f[20] }' "/proc/$1/stat" 2>/dev/null
  }
  hm_identity_fail() {
    if [ "$HM_STAGE" = fence ]; then
      hm_out fence unproven
      hm_fence_end 44 unproven start_identity_unavailable
    fi
    hm_end 30 refused start_identity_unavailable
  }
  hm_identity() {
    HM_OS=$(uname -s 2>/dev/null)
    HM_PGID=
    HM_START_RAW=
    HM_BOOT_RAW=
    HM_BOOT_STABLE=no
    case "$HM_OS" in
      Linux)
        HM_PS=$(hm_procstat "$$") || hm_identity_fail
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=${2-}
        HM_BOOT_RAW=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
        HM_BOOT_STABLE=yes
        ;;
      Darwin)
        HM_PS=$(ps -o pgid= -p "$$" 2>/dev/null)
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=$(ps -o lstart= -p "$$" 2>/dev/null | awk '{ $1 = $1; print }')
        HM_BOOT_RAW=$(sysctl -n kern.bootsessionuuid 2>/dev/null)
        HM_BOOT_STABLE=yes
        ;;
      FreeBSD|NetBSD|OpenBSD)
        HM_PS=$(ps -o pgid= -p "$$" 2>/dev/null)
        set -- $HM_PS
        HM_PGID=${1-}
        HM_START_RAW=$(ps -o lstart= -p "$$" 2>/dev/null | awk '{ $1 = $1; print }')
        HM_BOOT_RAW=$(sysctl -n kern.boottime 2>/dev/null | awk '{ i = index($0, "}"); if (i > 0) { print substr($0, 1, i); exit } }')
        ;;
      *) hm_identity_fail ;;
    esac
    case "$HM_PGID" in
      ''|*[!0-9]*) hm_identity_fail ;;
    esac
    if [ -z "$HM_START_RAW" ] || [ -z "$HM_BOOT_RAW" ]; then
      hm_identity_fail
    fi
    if [ "$HM_PGID" != "$$" ]; then
      hm_out pgid "$HM_PGID"
      if [ "$HM_STAGE" = fence ]; then
        hm_fence_end 33 no_process_group no_process_group
      fi
      hm_end 33 no_process_group no_process_group
    fi
    HM_START=$(printf '%s' "$HM_START_RAW" | hm_hex)
    HM_BOOT=$(printf '%s' "$HM_BOOT_RAW" | hm_hex)
  }
  hm_take_lock() {
    HM_RECORD="hm1-$HM_TOKEN-$$-$HM_START-$HM_BOOT-$HM_NOT_AFTER"
    if [ -d "$HM_LOCK" ] && [ ! -L "$HM_LOCK" ]; then
      hm_out lock held
      hm_end 30 refused lock_is_directory
    fi
    if [ -L "$HM_LOCK" ] || [ -e "$HM_LOCK" ]; then
      hm_lock_report
      hm_end 40 busy ''
    fi
    if ln -s "$HM_RECORD" "$HM_LOCK" 2>/dev/null; then
      :
    elif [ -L "$HM_LOCK" ] || [ -e "$HM_LOCK" ]; then
      hm_lock_report
      hm_end 40 busy ''
    else
      hm_end 30 refused lock_not_created
    fi
    hm_lock_read
    if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_RECORD" ]; then
      HM_LOCKED=yes
      return 0
    fi
    if [ -d "$HM_LOCK" ] && [ -L "$HM_LOCK/$HM_RECORD" ]; then
      HM_INNER=$(ls -ld "$HM_LOCK/$HM_RECORD" 2>/dev/null)
      if [ "${HM_INNER##* -> }" = "$HM_RECORD" ]; then
        rm -f "$HM_LOCK/$HM_RECORD"
      fi
    fi
    hm_end 30 refused lock_not_verified
  }
  hm_recheck() {
    hm_lock_read
    if [ "$HM_LOCK_STATE" != held ] || [ "$HM_LOCK_REC" != "$HM_RECORD" ]; then
      HM_LOCKED=no
      hm_end 42 lock_lost ''
    fi
    hm_clock
    if [ "$HM_NOW" -ge "$HM_NOT_AFTER" ]; then
      hm_end 41 not_after_passed ''
    fi
  }
  hm_before_lock() {
    hm_identity
    hm_out pgid "$$"
    hm_out start_identity "$HM_START"
    hm_out boot_identity "$HM_BOOT"
    if [ ! -L "$HM_DIR" ] && [ ! -e "$HM_DIR" ]; then
      hm_out dir absent
      hm_end 32 dir_absent ''
    fi
    if [ "$HM_NOW" -ge "$HM_NOT_AFTER" ]; then
      hm_end 41 not_after_passed ''
    fi
    hm_check_dir
  }
  hm_decode() {
    awk 'BEGIN { h = "0123456789abcdef" } { n = length($0); if (n % 2) exit 3; for (i = 1; i < n; i += 2) { a = index(h, substr($0, i, 1)); b = index(h, substr($0, i + 1, 1)); if (a == 0 || b == 0) exit 3; v = (a - 1) * 16 + b - 1; if (v == 0) exit 4; printf "%c", v } }'
  }
  hm_perm() {
    HM_PERM=$(printf '%s' "$HM_MODE10" | awk '{ s = ""; for (i = 2; i <= 10; i += 3) { t = substr($0, i, 3); if (t == "rw-") s = s "6"; else if (t == "r--") s = s "4"; else if (t == "---") s = s "0"; else exit 1 } print s }')
    case "$HM_PERM" in
      [0-7][0-7][0-7]) ;;
      *) hm_end 30 refused registry_mode_unsupported ;;
    esac
  }
  trap 'hm_cleanup' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  hm_before_lock
  hm_take_lock
  hm_check_file
  if [ "$HM_FILE" = absent ]; then
    hm_end 20 changed_since_read registry_absent
  fi
  if [ "$HM_SIZE" -gt 131072 ]; then
    hm_end 31 too_large ''
  fi
  hm_perm
  set -C
  if : > "$HM_PRE" 2>/dev/null; then
    HM_PRE_MADE=yes
  else
    set +C
    hm_end 30 refused temp_create_failed
  fi
  if : > "$HM_POST" 2>/dev/null; then
    HM_POST_MADE=yes
  else
    set +C
    hm_end 30 refused temp_create_failed
  fi
  set +C
  if hm_decode > "$HM_PRE" <<'HM_HEX_PRE'
232061646d696e206c696e650a636572742d617574686f726974792c7072696e636970616c733d22686d3a6473745f676f6c64656e3a656e726f6c6c22207373
682d656432353531392041414141676f6c64656e53796e7468657469634e6f74414b6579206865696d64616c6c3a656e725f3031323334353637383961626364
6566303132333435363738396162636465660a
HM_HEX_PRE
  then
    :
  else
    hm_end 30 refused decode_failed
  fi
  if hm_decode > "$HM_POST" <<'HM_HEX_POST'
232061646d696e206c696e650a
HM_HEX_POST
  then
    :
  else
    hm_end 30 refused decode_failed
  fi
  if ! chmod "$HM_PERM" "$HM_POST"; then
    hm_end 30 refused write_failed
  fi
  if ! cmp -s "$HM_REG" "$HM_PRE"; then
    hm_end 20 changed_since_read ''
  fi
  hm_recheck
  if mv -f "$HM_POST" "$HM_REG"; then
    HM_POST_MADE=no
  else
    hm_end 30 refused write_failed
  fi
  rm -f "$HM_PRE"
  HM_PRE_MADE=no
  hm_content keep
  hm_end 0 renamed ''
}
hm_main
