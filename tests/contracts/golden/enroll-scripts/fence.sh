# Heimdall remote registry script: fence (HM1 v=1; ADR-0008 D5 6.3).
# Every value is a validated literal in single quotes. /bin/sh -s reads this
# after the HM1 ready line; nothing runs before the call on the last line.
hm_main() {
  export LC_ALL=C
  umask 077
  export TZ=UTC0
  set -f
  HM_STAGE='fence'
  HM_REG_ARG=''
  HM_TOKEN='00112233445566778899aabbccddeeff'
  HM_TERMINATE='yes'
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
  HM_SIGNALS=
  hm_fence_end() {
    hm_out fence_signals "$HM_SIGNALS"
    hm_end "$1" "$2" "$3"
  }
  hm_holder_pid() {
    HM_PIDSTATE=unreadable
    HM_HSTART_RAW=
    if [ "$HM_OS" = Linux ]; then
      if [ -e "/proc/$HM_R_PID/stat" ]; then
        if HM_HP=$(hm_procstat "$HM_R_PID"); then
          set -- $HM_HP
          HM_HSTART_RAW=${2-}
        else
          return 0
        fi
      else
        HM_PIDSTATE=absent
        return 0
      fi
    else
      HM_HSTART_RAW=$(ps -o lstart= -p "$HM_R_PID" 2>/dev/null | awk '{ $1 = $1; print }')
      if [ -z "$HM_HSTART_RAW" ]; then
        HM_PIDSTATE=absent
        return 0
      fi
    fi
    if [ -z "$HM_HSTART_RAW" ]; then
      return 0
    fi
    HM_HSTART=$(printf '%s' "$HM_HSTART_RAW" | hm_hex)
    hm_out start_identity "$HM_HSTART"
    if [ "$HM_HSTART" = "$HM_R_START" ]; then
      HM_PIDSTATE=same
    else
      HM_PIDSTATE=different
    fi
  }
  hm_decide() {
    hm_out pgid "$HM_R_PID"
    hm_out boot_identity "$HM_BOOT"
    if [ "$HM_BOOT" != "$HM_R_BOOT" ] && [ "$HM_BOOT_STABLE" = yes ]; then
      HM_FENCE=gone
      hm_out fence gone
      return 0
    fi
    kill -s 0 -- "-$$" 2>/dev/null
    HM_GC=$?
    kill -s 0 -- "-$HM_R_PID" 2>/dev/null
    HM_GK=$?
    HM_GL=$(ps -A -o pgid= 2>/dev/null)
    HM_GLS=$?
    HM_GLV=$(printf '%s\n' "$HM_GL" | awk -v own="$$" -v tgt="$HM_R_PID" 'NF == 0 { next } NF != 1 || $1 !~ /^[0-9]+$/ { bad = 1; next } $1 == own "" { o = 1 } $1 == tgt "" { t = 1 } END { if (bad || !o) print "invalid"; else if (t) print "yes"; else print "no" }')
    if [ "$HM_GLS" -ne 0 ]; then
      HM_GLV=invalid
    fi
    hm_out group_control "$HM_GC"
    hm_out group_probe "$HM_GK"
    case "$HM_GLV" in
      yes|no) hm_out group_listed "$HM_GLV" ;;
    esac
    HM_GROUP=unproven
    if [ "$HM_GC" -eq 0 ]; then
      if [ "$HM_GK" -ne 0 ] && [ "$HM_GLV" = no ]; then
        HM_GROUP=empty
      elif [ "$HM_GK" -eq 0 ] && [ "$HM_GLV" = yes ]; then
        HM_GROUP=live
      fi
    fi
    hm_holder_pid
    case "$HM_GROUP:$HM_PIDSTATE" in
      empty:absent|empty:different) HM_FENCE=gone ;;
      live:absent|live:same) HM_FENCE=alive ;;
      *) HM_FENCE=unproven ;;
    esac
    hm_out fence "$HM_FENCE"
  }
  hm_wait() {
    HM_I=0
    while [ "$HM_I" -lt 5 ]; do
      sleep 1
      hm_decide
      if [ "$HM_FENCE" != alive ]; then
        return 0
      fi
      HM_I=$((HM_I + 1))
    done
  }
  printf 'HM1 v=1\n'
  hm_resolve
  hm_clock
  hm_out remote_now "$HM_NOW"
  hm_uid
  hm_identity
  hm_lock_read
  if [ "$HM_LOCK_STATE" = none ]; then
    hm_out lock none
    hm_out fence none
    hm_fence_end 0 none ''
  fi
  hm_out lock held
  if [ "$HM_LOCK_STATE" != held ]; then
    hm_fence_end 30 refused lock_not_symlink
  fi
  if ! hm_record_ok "$HM_LOCK_REC"; then
    hm_fence_end 40 busy lock_foreign
  fi
  hm_out lock_holder "$HM_LOCK_REC"
  if [ "$HM_R_TOKEN" != "$HM_TOKEN" ]; then
    hm_fence_end 40 busy lock_other_token
  fi
  HM_HOLDER_REC=$HM_LOCK_REC
  hm_decide
  if [ "$HM_FENCE" = alive ] && [ "$HM_TERMINATE" = yes ]; then
    if [ "$HM_NOW" -gt "$HM_R_NA" ]; then
      kill -s TERM -- "-$HM_R_PID" 2>/dev/null
      HM_SIGNALS=TERM
      hm_wait
      if [ "$HM_FENCE" = alive ]; then
        kill -s KILL -- "-$HM_R_PID" 2>/dev/null
        HM_SIGNALS=TERM,KILL
        hm_wait
      fi
    else
      hm_fence_end 43 alive not_after_not_passed
    fi
  fi
  case "$HM_FENCE" in
    alive) hm_fence_end 43 alive '' ;;
    unproven) hm_fence_end 44 unproven '' ;;
  esac
  hm_lock_read
  if [ "$HM_LOCK_STATE" = held ] && [ "$HM_LOCK_REC" = "$HM_HOLDER_REC" ]; then
    rm -f "$HM_LOCK"
    if [ -L "$HM_LOCK" ]; then
      hm_fence_end 30 refused lock_not_removed
    fi
  elif [ "$HM_LOCK_STATE" != none ]; then
    hm_fence_end 40 busy lock_replaced
  fi
  hm_fence_end 0 gone ''
}
hm_main
