| probe | variant | base-go-pinned | base-go | T3-go-opus1 | T3-go-opus2 | T3-go-sonnet1 | base-rust | T3-rust-opus1 | T3-rust-opus2 | T3-rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|---|---|
| P01 | homelab 80x24 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P01 | homelab 50x8 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P01 | homelab 49x8 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P01 | homelab 30x6 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P01 | homelab 20x5 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 80x24 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 60x10 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 50x10 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 40x10 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 30x8 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 21x6 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P02 | wide 20x5 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P03 | long 80x10 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 60x10 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 50x10 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 49x10 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 33x10 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 21x6 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P03 | long 20x5 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P04 | help behaviour | skip | skip | - | - | - | skip | - | - | - |
| P04 | help behaviour 80x24 | - | - | pass | pass | pass | - | pass | pass | pass |
| P05 | tiny sizes and resize, homelab from 20x5 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P05 | tiny sizes and resize, wide from 20x5 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P06 | help open + SIGTERM | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | help open + SIGHUP | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | help open + SIGINT (kill) | FAIL 1 | FAIL 1 | FAIL 1 | FAIL 1 | FAIL 1 | pass | pass | pass | pass |
| P06 | help open + terminal hangup | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | help open + Ctrl-C | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | filter mode + SIGTERM | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | help: q ignored, then ? closes, q quits | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | help: Esc closes, Down, Enter selects | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P06 | wide filter + help + SIGTERM at 20x5 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P07 | NO_COLOR homelab 80x24 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P07 | NO_COLOR homelab 20x5 | FAIL 1 | FAIL 1 | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P07 | NO_COLOR wide 40x10 | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | pass |
| P08 | TERM=xterm-256color | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=xterm | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=xterm-color | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=screen | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=screen-256color | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=tmux-256color | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=linux | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=vt100 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=vt220 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=ansi | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=rxvt-unicode-256color | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=alacritty | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=xterm-kitty | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=xterm-ghostty | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P08 | TERM=dumb | pass | pass | FAIL 2 | FAIL 2 | FAIL 2 | pass | pass | pass | pass |
| P08 | TERM=(unset) | pass | pass | FAIL 2 | FAIL 2 | FAIL 2 | pass | pass | pass | pass |
| P09 | rapid batches homelab 80x24 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P09 | rapid batches large-100 80x8 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P10 | large-100 scroll 80x24 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P10 | large-100 scroll 80x8 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P10 | large-100 scroll 20x5 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P11 | unicode case/combining 80x24 (combining marks ignored) | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | FAIL 1 |
| P11 | unicode case/combining 40x12 (combining marks ignored) | pass | pass | FAIL 1 | pass | FAIL 1 | pass | pass | pass | FAIL 1 |
| P12 | zero-width and bidi aliases 80x24 (process state, raw bytes) | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P13 | help residue after resize | skip | skip | - | - | - | skip | - | - | - |
| P13 | help open, resize 30x6, close; reopen, resize 80x24, Esc | - | - | pass | pass | pass | - | pass | pass | pass |
| P13 | wide: CJK filter kept, help, resize 20x5, Esc, resize 40x10 | - | - | pass | pass | pass | - | pass | pass | pass |
| P14 | disappear/reappear, empty results 80x24 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P14 | disappear/reappear, empty results 20x5 | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P15 | combining accent through highlight split (observation) | pass | pass | pass | pass | pass | pass | pass | pass | pass |
| P16 | random walk, 6 runs x 120 keys (runs failing) | 4/6 | 4/6 | 3/6 | 0/6 | 3/6 | 0/6 | 0/6 | 0/6 | 0/6 |
| P17 | fresh start + one filter char + Backspace, 90 variants (variants failing) | 0/90 | 0/90 | 4/90 | 0/90 | 4/90 | 0/90 | 0/90 | 0/90 | 0/90 |
