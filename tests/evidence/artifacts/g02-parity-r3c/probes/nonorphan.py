#!/usr/bin/env python3
"""parity-r3c helper: run argv in a NEW process group whose parent (this process) stays in the
caller's group and session, so the probe's group is not an orphaned process group and a SIGTSTP
sent to a process in it is not discarded by the kernel.  Exit status: the command's.
Used because both the Claude Code Bash tool (darwin) and `docker run` (linux, probe tree under
PID 1) start the probes in an orphaned process group."""
import subprocess
import sys
sys.exit(subprocess.run(sys.argv[1:], process_group=0).returncode)
