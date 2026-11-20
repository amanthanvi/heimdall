PC job 11's first WSL hook attempt at 84d7c44e (the harness of that commit): a failed attempt, kept on record.
The bundle as the PC wrote it (sha256 e25b11b6f33624f5809fdca9258ff668afbe67add7dc497a9b7a1cecf4df4e96) and its six files, decoded on the build host
(format heimdall-m05-wsl-hook-bundle/1; every file's sha256 matched the bundle's; no unredacted value and no canary prefix).
import-windows-bundle.py refuses it (tests.txt has no test results the generator reads): no journey ran.
Cause: Read-LxssRows returned its rows wrapped in one array, so the ownership check matched no row and refused the run's own
freshly imported distribution; the run left it registered and the PC removed it by exact name. Fixed at 5aa752c0 (harness only).
