import os, sys, signal
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
os.setpgid(0, 0)
os.tcsetpgrp(0, os.getpgrp())
signal.signal(signal.SIGTTOU, signal.SIG_DFL)
os.execv("/bin/sh", ["/bin/sh", "-c", sys.argv[1]])
