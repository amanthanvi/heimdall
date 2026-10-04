import os, sys
d = sys.argv[1]
open(os.path.join(d, "ready"), "w").write("%d %d %d\n" % (os.getpid(), os.getpgrp(), os.getppid()))
sys.stdout.write("READY\n"); sys.stdout.flush()
line = sys.stdin.readline()
open(os.path.join(d, "got"), "w").write(line)
sys.exit(3)
