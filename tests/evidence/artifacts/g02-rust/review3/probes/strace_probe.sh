#!/bin/bash
# Review3 Linux probe: strace every heimdall-proto command (non-run, and run up to its child exec)
# for execve and write-capable opens outside the named paths. Env selects helpers if honoured.
# usage: strace_probe.sh <heimdall-proto> <fixtures dir> <workdir>
HP=$1; FX=$2; W=$3; rm -rf "$W"; mkdir -p "$W/fake"; cd "$W" || exit 1
unset SSH_AUTH_SOCK
for t in tput tmux infocmp stty tset resize toe clear; do printf '#!/bin/sh\necho %s >> %s/helper-ran\n' $t "$W" > fake/$t; chmod +x fake/$t; done
export PATH="$W/fake:$PATH" TERM=tmux-256color TMUX=/tmp/x,1,0 TERM_PROGRAM=tmux HOME="$W/home" TMPDIR="$W/tmpdir"
mkdir -p home tmpdir
ST="strace -f -qq -e trace=execve,execveat,open,openat,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,symlink,symlinkat,link,linkat,truncate,ftruncate,chmod,fchmodat -e signal=none"
run() { name=$1; shift; $ST -o "st.$name" "$@" > "out.$name" 2> "err.$name"; echo "$name exit=$?"; }
run version "$HP" version --json
run profile "$HP" profile show --file "$FX/large-100.toml" --json
run profile_bad "$HP" profile show --file "$FX/invalid-port.toml" --json
run agent_missing "$HP" agent list --socket "$W/nosock" --json
run run_meta "$HP" run --meta-file "$W/meta.json" -- /bin/true
# TUI in a pty (python), keys, resize, quit
cat > tui.py <<'EOF'
import os, pty, sys, time, select, fcntl, struct, termios, signal
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
def rd(t):
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], max(0, end - time.time()))
        if r:
            try:
                if not os.read(fd, 65536): return
            except OSError: return
rd(1.0)
for c, r in ((30, 6), (100, 30)):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0)); rd(0.3)
os.write(fd, b"/vps"); rd(0.3); os.write(fd, b"\x1b"); rd(0.2); os.write(fd, b"q"); rd(1.0)
_, st = os.waitpid(pid, 0); print("tui_exit", os.waitstatus_to_exitcode(st))
EOF
python3 tui.py $ST -o st.tui "$HP" tui --file "$FX/large-100.toml" > out.tui 2> err.tui; echo "tui driver exit=$? $(cat out.tui)"
echo "--- execve calls (any program other than heimdall-proto itself; run: the child /bin/true expected)"
grep -h -E 'execve(at)?\(' st.* | grep -v -F "\"$HP\"" | sed -E 's/^[0-9]+ +//' | cut -c1-120
echo "--- write-capable opens/creates/renames outside the named paths"
grep -h -E 'O_WRONLY|O_RDWR|O_CREAT|creat\(|mkdir|rename|unlink|symlink|link\(|truncate|chmod' st.* | grep -v -E '/dev/(tty|pts/|null)|meta.json' | sed -E 's/^[0-9]+ +//' | cut -c1-140
echo "--- helper marker: $(cat helper-ran 2>/dev/null || echo none)"
echo "--- files created in HOME/TMPDIR: $(find home tmpdir -mindepth 1 | wc -l)"
