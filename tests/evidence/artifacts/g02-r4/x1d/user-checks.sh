#!/bin/bash
# X1d: what a user without the toolchain needs, per candidate (complements the harness; read README.md):
#  1. one file: the staged art/<c>/ directory holds only heimdall-proto; file(1) and ldd(1) output
#  2. location: copied alone into a directory whose path has spaces and non-ASCII characters, run from there
#     (absolute and ./ invocation, working directory = that directory) under env -i with an empty PATH directory
#     and no HOME/TMPDIR; the profile and socket paths are in the same directory
#  3. read-only: the same commands with HOME, TMPDIR and the working directory read-only (chmod 555)
#  4. write-class system calls of the same commands, by strace -f (only where strace is installed), with a
#     control that must show a write
#  5. read-only root: the same commands inside bwrap --ro-bind / / (only where bwrap is installed), with controls
#     that must fail to write
# Commands: version --json; profile show of the spaced fixture copy; profile show of the forbidden-key fixture;
# run -- /bin/sh -c 'exit 7'; agent list on a missing socket. Expected exits 0, 0, 2, 7, 5.
set -u
T=$HOME/hm-m00/M00-T05-r5-x1d
F=$T/repo/tests/fixtures/g02/profiles
E=$T/empty-path-u; mkdir -p "$E"
U="$T/u dir ü 東 spaced"
red() { sed "s#$HOME#<home>#g"; }

cmds() { # $1 = how to call the binary (absolute path or ./heimdall-proto), $2 = its directory; env prefix in ENVP
  local B=$1 D=$2 out rc
  out=$(cd "$D" && "${ENVP[@]}" "$B" version --json 2>&1); rc=$?
  echo "    version --json rc=$rc code=$(echo "$out" | grep -o '"code":"[A-Z_]*"' | head -1)"
  out=$(cd "$D" && "${ENVP[@]}" "$B" profile show --file "$D/prøfile homelab ü.toml" --json 2>&1); rc=$?
  echo "    profile show (spaced copy in this dir) rc=$rc code=$(echo "$out" | grep -o '"code":"[A-Z_]*"' | head -1)"
  out=$(cd "$D" && "${ENVP[@]}" "$B" profile show --file "$F/invalid-forbidden-key.toml" --json 2>&1); rc=$?
  echo "    profile show forbidden-key rc=$rc code=$(echo "$out" | grep -o '"code":"[A-Z_]*"' | head -1) canary_prefix_hits=$(echo "$out" | grep -c HEIMDALL_CANARY_)"
  out=$(cd "$D" && "${ENVP[@]}" "$B" run -- /bin/sh -c 'exit 7' 2>&1); rc=$?
  echo "    run -- /bin/sh -c 'exit 7' rc=$rc out_bytes=${#out}"
  out=$(cd "$D" && "${ENVP[@]}" "$B" agent list --socket "$D/no such sock ü.sock" --json 2>&1); rc=$?
  echo "    agent list (missing socket in this dir) rc=$rc code=$(echo "$out" | grep -o '"code":"[A-Z_]*"' | head -1)"
}

echo "strace: $(command -v strace >/dev/null && echo present || echo absent); bwrap: $(command -v bwrap >/dev/null && echo present || echo absent)"
for c in go rust; do
  echo "=== $c"
  echo "1. staged art/$c/ entries: $(ls -A "$T/art/$c" | tr '\n' ' ')"
  echo "   file: $(file -b "$T/art/$c/heimdall-proto")"
  echo "   ldd: $(ldd "$T/art/$c/heimdall-proto" 2>&1 | head -1 | sed 's/^[[:space:]]*//') (ldd rc=$(ldd "$T/art/$c/heimdall-proto" >/dev/null 2>&1; echo $?))"
  D="$U/$c bin ü"; mkdir -p "$D"
  cp "$T/art/$c/heimdall-proto" "$D/heimdall-proto"
  cp "$F/spaced dir ü/prøfile homelab.toml" "$D/prøfile homelab ü.toml"
  echo "   copy sha256 $(sha256sum "$D/heimdall-proto" | cut -c1-64); directory (redacted): $(echo "$D" | red)"
  echo "2. spaced/non-ASCII directory, env -i PATH=<empty dir>, no HOME or TMPDIR"
  ENVP=(env -i PATH="$E")
  echo "  absolute path:"; cmds "$D/heimdall-proto" "$D"
  echo "  ./heimdall-proto:"; cmds ./heimdall-proto "$D"
  echo "3. read-only HOME, TMPDIR and working directory (chmod 555), env -i PATH=<empty dir>"
  RH="$U/ro home $c"; RT="$U/ro tmp $c"; mkdir -p "$RH" "$RT"; chmod 555 "$RH" "$RT" "$D"
  ENVP=(env -i PATH="$E" HOME="$RH" TMPDIR="$RT")
  echo "  write control: $( (: > "$D/ctl") 2>/dev/null && echo 'WRITE SUCCEEDED (control invalid)' || echo 'write refused (control ok)')"
  cmds "$D/heimdall-proto" "$D"
  echo "  entries afterwards: cwd $(ls -A "$D" | wc -l) (2 = binary + profile), HOME $(ls -A "$RH" | wc -l), TMPDIR $(ls -A "$RT" | wc -l)"
  if command -v strace >/dev/null 2>&1; then
    echo "4. strace -f write-class calls (open/openat/openat2 with O_WRONLY, O_RDWR, O_CREAT, O_TRUNC or O_APPEND;"
    echo "   creat, mkdir*, rename*, unlink*, rmdir, link*, symlink*, truncate, chmod*, chown*, utimensat, mknod*, bind)"
    S=$T/out/strace-$c; mkdir -p "$S"   # raw logs kept (copied back and redacted)
    TR=(strace -f -qq -e trace=open,openat,openat2,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,link,linkat,symlink,symlinkat,truncate,chmod,fchmodat,chown,fchownat,lchown,utimensat,mknod,mknodat,bind)
    "${TR[@]}" -o "$S/control.log" /bin/sh -c ': > "$1"' sh "$S/control-file"; echo "  control (sh writing a file) rc=$?"
    i=0
    for args in "version --json" "profile show --file @P --json" "profile show --file @F --json" "run -- /bin/sh -c exit\\ 7" "agent list --socket @S --json"; do
      i=$((i+1))
      case $i in
        1) A=(version --json);;
        2) A=(profile show --file "$D/prøfile homelab ü.toml" --json);;
        3) A=(profile show --file "$F/invalid-forbidden-key.toml" --json);;
        4) A=(run -- /bin/sh -c 'exit 7');;
        5) A=(agent list --socket "$D/no such sock ü.sock" --json);;
      esac
      (cd "$D" && "${TR[@]}" -o "$S/cmd$i.log" env -i PATH="$E" HOME="$RH" TMPDIR="$RT" "$D/heimdall-proto" "${A[@]}" >/dev/null 2>&1); echo "  cmd$i ($args) rc=$?"
    done
    for f in "$S"/control.log "$S"/cmd*.log; do
      n=$(wc -l < "$f")
      w=$(grep -E '^[0-9]+ +(open|openat|openat2)\(.*(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)|^[0-9]+ +(creat|mkdir|mkdirat|rename|renameat|renameat2|unlink|unlinkat|rmdir|link|linkat|symlink|symlinkat|truncate|chmod|fchmodat|chown|fchownat|lchown|utimensat|mknod|mknodat|bind)\(' "$f" \
          | sed -E 's/^[0-9]+ +//' | red | sort -u)
      echo "  $(basename "$f"): $n traced calls; write-class: $( [ -n "$w" ] && echo "$(echo "$w" | wc -l)" || echo 0)"
      [ -n "$w" ] && echo "$w" | cut -c1-200 | sed 's/^/      /'
    done
  else
    echo "4. strace not installed: write-class syscall trace not run on this host"
  fi
  if command -v bwrap >/dev/null 2>&1; then
    echo "5. bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid --die-with-parent (whole file system read-only)"
    BW=(bwrap --ro-bind / / --dev /dev --proc /proc --unshare-pid --die-with-parent)
    "${BW[@]}" /bin/true; echo "  positive control /bin/true rc=$?"
    for tgt in "$T/bw-ctl" "/tmp/x1d-bw-ctl-$$" "$HOME/x1d-bw-ctl"; do
      out=$("${BW[@]}" /bin/sh -c ': > "$1"' sh "$tgt" 2>&1); rc=$?
      echo "  write control $(echo "$tgt" | red | sed "s/-$$\$/-<pid>/") rc=$rc ($(echo "$out" | red | sed "s/-$$/-<pid>/" | tail -1 | cut -c1-120))"
      [ -e "$tgt" ] && { echo "  CONTROL FILE EXISTS (control invalid)"; rm -f "$tgt"; }
    done
    ENVP=("${BW[@]}" env -i PATH="$E")
    cmds "$D/heimdall-proto" "$D"
  else
    echo "5. bwrap not installed: read-only root run not done on this host"
  fi
  chmod 755 "$RH" "$RT" "$D"
done
rm -rf "$U" "$E"
echo "removed the check directories"
