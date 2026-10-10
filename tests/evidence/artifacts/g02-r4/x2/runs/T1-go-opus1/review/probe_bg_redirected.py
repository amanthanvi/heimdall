# Reviewer probe (read-only against the built artifact): a background job of an
# interactive bash with all stdio redirected; a third party SIGSTOPs the job's
# process (plain exec) or the launcher's child (heimdall-proto). Does the shell
# list the job as stopped in both cases?
# Usage: python3 -I probe_bg_redirected.py <heimdall-proto binary>
import os, pty, select, sys, time

HP = sys.argv[1]
SIG = sys.argv[2] if len(sys.argv) > 2 else "STOP"
env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TERM": "dumb", "PS1": "PROMPT$ "}


def run(shell_argv, script):
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(shell_argv[0], shell_argv, env)
    out = b""

    def drain(t):
        nonlocal out
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    out += os.read(fd, 4096)
                except OSError:
                    return

    drain(0.8)
    os.write(fd, b"set +H; stty cols 400\n")
    drain(0.4)
    for line, wait in script:
        os.write(fd, (line + "\n").encode())
        drain(wait)
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(fd)
    return out.decode(errors="replace")


common_tail = [
    ("sleep 0.3; kill -" + SIG + " $C; sleep 0.7", 1.5),
    ("ps -o pid=,stat= -p $C; ps -o pid=,stat= -p $J", 0.8),
    ("jobs -l", 0.8),
    ("kill -KILL $C $J 2>/dev/null; wait; echo CLEANED", 1.0),
]
plain = [("/bin/sleep 30 </dev/null >/dev/null 2>&1 & J=$!; C=$J; echo J=$J", 0.5)] + common_tail
hp = [
    (HP + " run -- /bin/sleep 30 </dev/null >/dev/null 2>&1 & J=$!; sleep 0.5; C=$(pgrep -P $J); echo J=$J C=$C", 1.2)
] + common_tail

for name, script in (("plain", plain), ("heimdall-proto", hp)):
    print("=====", name, "(bash)")
    print(run(["/bin/bash", "--norc", "--noprofile", "-i"], script))
