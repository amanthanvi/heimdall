# Heimdall remote registry script: inspect (HM1 v=1; ADR-0008 D5 6.3).
# Every value is a validated literal in single quotes. /bin/sh -s reads this
# after the HM1 ready line; nothing runs before the call on the last line.
hm_main() {
  export LC_ALL=C
  umask 077
  export TZ=UTC0
  set -f
  HM_STAGE='inspect'
  HM_REG_ARG=''
  HM_MARKER='heimdall:enr_0123456789abcdef0123456789abcdef'
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
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  if [ -L "$HM_DIR" ] || [ -e "$HM_DIR" ]; then
    hm_lock_report
    hm_check_dir
    hm_check_file
    if [ "$HM_FILE" = regular ]; then
      if [ "$HM_SIZE" -gt 131072 ]; then
        hm_end 31 too_large ''
      fi
      hm_content check
    fi
  else
    hm_out dir absent
    hm_out file absent
    hm_out lock none
  fi
  if [ -n "$HM_REFUSAL" ]; then
    hm_end 30 refused "$HM_REFUSAL"
  fi
  hm_end 0 ok ''
}
hm_main
