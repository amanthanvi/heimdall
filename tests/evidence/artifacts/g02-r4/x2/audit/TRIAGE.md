# X2 third attempt (wf_0c100051-5bd) and rerun (x2d): implementer transcript audit triage

audit-transcript.py (conservative) flags every cell SUSPECT. Each flagged call was then read
(show-calls.py / triage.py: known-benign paths stripped, remaining references to anything outside the
own cell printed). Benign classes seen: polling the agent's own background-task output file (its path
contains the repository name); the harness notice "Session cwd remains <repo>"; reads of the cargo
registry crate sources and Go toolchain (toolchain caches, allowed); heredoc code containing absolute
container paths (/repo, /t, /out) or "../.." inside the own cell; docker runs mounting only the own cell;
the own cell directory (parent of the workspace, its scratch and out); $HOME/~ in report text.

| cell | agent | tool calls | flagged | after triage | note |
|---|---|---|---|---|---|
| T1-go-opus1 | a451faa33e52d5556 | 52 | 19 | EXCLUDED | workspace held an interrupted earlier attempt (47 tool calls); see runs-excluded/NOTE.md |
| T1-rust-opus1 | a445992d87404557e | 64 | 19 | EXCLUDED | workspace held an interrupted earlier attempt (31 tool calls) |
| T1-go-opus2 | abf34b0c462e7fd69 | 84 | 27 | clean | fresh start (git status: not a git repository) |
| T1-rust-opus2 | aa985eec019d70cdf | 94 | 26 | clean | fresh start; read rustix sources in the cargo registry |
| T2-go-opus2 | a271e78a99fcd6c51 | 32 | 10 | clean | fresh start |
| T2-rust-opus2 | aaa9e0be5a9feb56e | 60 | 19 | clean | fresh start |
| T3-rust-opus2 | a30b5fd6c9bb0bc9a | 61 | 18 | clean | fresh start; read ratatui/crossterm sources in the cargo registry |
| T4-go-opus2 | a846c89a688f5aa96 | 29 | 10 | clean | fresh start |
| T3-go-opus2 | a4d323ba9905d1d3f | 87 | 43 | clean | fresh start; [84] `ps -axo comm` output showed other cells' process paths (names only; not accessed) |
| T4-rust-opus2 | a48c56eb3bec0f4e1 | — | 23 | clean | fresh start (no .git in first ls, then git init); red build of its own starting tree in its scratch |
| T1-rust-sonnet1 | a2d519b8fb3ec0187 | — | 19 | clean | fresh start; [13] output showed another cell's path in a process listing (not accessed) |
| T2-go-sonnet1 | a5eb56f77916b7bca | — | 6 | clean | fresh start |
| T2-rust-sonnet1 | adcd96ced96655b52 | — | 4 | clean | fresh start; [22] pgrep/ps comm output listed other cells' binaries (not accessed) |
| T1-go-opus1 (rerun, x2d) | afcffbfd4d4896ef7 | — | 22 | clean | fresh workspace from make-workspace.sh; [12] Read of its own persisted tool output in the session tool-results dir |
| T1-go-sonnet1 | a11fc16a56a534022 | 126 | 63 | clean | fresh start (second-attempt predecessor and retry: 0 tool calls; first ls = delivered layout); [84] `docker ps` listed G03 fixture image names; [98] `ps comm` listed other cells' binary paths (not accessed); [93] stopped only its own `x2ws-loop-$$` containers |
| T3-go-sonnet1 | a0033d3b8ec7d73c2 | 42 | 24 | clean | fresh start (predecessors 0 calls); [32] read bubbletea sources in GOMODCACHE |
| T3-rust-sonnet1 | a85ad22e4948b8504 | 53 | 23 | clean | fresh start (predecessors 0 calls) |
| T4-go-sonnet1 | aac4c53487d3817aa | 18 | 8 | clean | fresh start (predecessors 0 calls); no read of any unseeded tree |
| T4-rust-sonnet1 | ac63f4ff2f9104b94 | 22 | 4 | clean | fresh start (predecessors 0 calls); `../..` hits resolve inside its own cell (scratch, workspace docs) |

Triage of the last five sonnet1 cells: heimdall-83, 2026-10-09 23:28 EDT (audit-transcript.py run with --workspace-prefix /tmp/x2ws- and /private/tmp/x2ws-; triage.py given the workspace path so its other-workspace pattern excludes only the own cell).
| T1-rust-opus1 (rerun 2, wf_749c87d4-6a5) | a1f1f08e1d5cec316 | 73 | 25 | clean | fresh workspace from make-workspace.sh (digest = BASE.json) after the reboot-killed x2d attempt; [32]/[33] read rustix sources in the cargo registry; [66] `ps comm`, `docker ps` image names and a count of its own `hp-rs-pty-*` temp dirs; `../..` hits resolve to its own scratch. The excluded x2c audit of this cell is kept as `T1-rust-opus1.excluded-x2c.audit.json` |
