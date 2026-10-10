# X2 T3 cross-review, N1 verified in real terminal implementations (M00-T05-r4-x2-xrev-T3-verify)

Status: `implemented_unverified` (this task's own observations; nobody has re-run them). Everything
below was executed on darwin-arm64 (Darwin 27.0.0) on 2026-10-10. Exit codes and screens are as
observed.

## Question

The cross-review (`../README.md`, finding N1) reports from the pyte screen emulator plus a by-hand
byte decode that T3-go-opus1 and T3-go-sonnet1 corrupt list rows and the status line when a filter
edit restyles cells next to double-width characters, while both baselines, T3-go-opus2 and the three
Rust cells render correctly. Terminals differ in how they treat writes into or next to a wide
character, so this task reproduces the reported cases, and the cross-review's controls, in two real
terminal implementations that are not pyte:

- **tmux 3.8** on a private socket (`tmux -L hvT3`), detached sessions of the exact size, keys via
  `send-keys -H`, screen via `capture-pane -p` (and `-p -e` for attributes), bytes via `pipe-pane`.
- **xterm.js 6.0.0 headless** (`@xterm/headless`, npm-installed into the scratch root, node
  v24.18.0), fed the exact bytes each binary wrote to its pty for the same keys, recorded by a plain
  pty driver (`scripts/pty_record.py`, no emulator in the loop).

The cross-review's pyte oracle (`../scripts/repro_bytes.py`, pyte 0.8.2 in `tests/g02/.venv`) was
also run on this task's binaries for every case, as the third column.

## Answer

**The reported major defect reproduces in both real terminal implementations, byte for byte as the
cross-review described.** On T3-go-opus1 and T3-go-sonnet1 every reported case (R1, R2, R3, and the
CJK-profile `/-` edit at 40x10 and 20x5) is corrupted in tmux (6/6 runs each: 3 repeats under
`TERM=tmux-256color` and 3 under `TERM=xterm-256color`), in xterm.js (both TERM values) and in pyte,
with the identical wrong text in all three. Both Go baselines, T3-go-opus2 and the three Rust cells
render every case correctly in all three emulators. The controls (R5, R6) are correct everywhere.

The one place the emulators disagree is **R4**, the cross-review's pre-existing status-line case
P-A (not part of N1): tmux shows the intended `1/3 /京`, xterm.js and pyte show `1/3 /`. The
bytes explain it (below): EL issued from the right half of a wide character erases the whole
character in xterm-family terminals and leaves it in tmux. Both Go baselines behave the same way
there as go-opus1 and go-sonnet1, so this does not bear on N1.

## Builds

Base trees are `git archive` copies of the pinned base commits (Go 84c7665, Rust 001a791), each
committed once into a scratch git repo. Tree digests (BASE.json method) equal `hidden-pack/BASE.json`:
Go `9ee4b916…`, Rust `58c9fef5…` (`raw/build/tree-digest-*.txt`). Each cell's implementer
`diff.patch` (the same file the cross-review used, sha256 recorded in `raw/build/provenance.txt`)
was applied with `git apply` (all six clean) and the tree built with its own `build.sh`; Rust used
the repository's `target/tools/bin/cargo-zigbuild` copied into the scratch target dir. All eight
builds exit 0 with all 4 targets built (`raw/build/manifest-*.json`). Only darwin-arm64 was used.

| build | darwin-arm64 sha256 (this task) | equals the cross-review's build? |
|---|---|---|
| base-go-pinned | `bdfd64a2f5a0…` (repository `prototypes/go/dist`, not rebuilt) | yes (same file) |
| base-go | `f812084ff36d…` | yes |
| T3-go-opus1 | `3cb494cec404…` | yes (and, as there, not the evaluated `9ad3ce9c…`: go1.27.2 here vs go1.27.1; the source is identical) |
| T3-go-opus2 | `87f81fb90346…` | yes |
| T3-go-sonnet1 | `9eb467768617…` | yes |
| base-rust | `f9a3ec8b4683…` | yes |
| T3-rust-opus1 | `9c6606190083…` | yes |
| T3-rust-opus2 | `7287e8c691f4…` | yes |
| T3-rust-sonnet1 | `a49cc5b0a443…` | yes |

Toolchains: go1.27.2, rustc 1.99.0 (the build.sh pin). Every sha256 equals the cross-review's
`raw/build/provenance-*.txt` value, so the two reviews probed the same bytes. Full digests in
`raw/build/provenance.txt`.

## Cases

Taken from the cross-review's `raw/repro/` headers (profile, size, keys), plus the CJK-profile `/-`
edit at the two other sizes the review names (P02/P17, matrix.json). Profiles: the repository
fixture `homelab.toml` and the review's `wide` profile (`raw/wide.toml`, written by the review's
writer format). Environment of the program: `PATH=/usr/bin:/bin`, private `HOME` and `TMPDIR` in a
fresh sandbox, `LANG=LC_ALL=en_US.UTF-8`, no `SSH_AUTH_SOCK`; `TERM` per column.

| case | profile | size | keys | cross-review's claim |
|---|---|---|---|---|
| R1 | homelab | 20x5 | `/`, `東`, `京` | go-opus1/go-sonnet1 row 0 `> vps- 京` |
| R2 | wide | 80x24 | `/`, `-` | go-opus1/go-sonnet1 row 2 `  名古 -bbackup-東  …` |
| R2-40x10 | wide | 40x10 | `/`, `-` | a corrupted row (P02/P17) |
| R2-20x5 | wide | 20x5 | `/`, `-` | rows 0-1 `> 東 --サーバー-本番`, `  la-sserver` (P02/P17) |
| R3 | wide | 40x10 | `/`, `屋`, Backspace | go-opus1/go-sonnet1 row 4 `> 名 屋 -backup-東` |
| R4 | homelab | 80x24 | `/`, `京`, Enter, `/` | P-A (pre-existing): status `1/3 /` on all Go builds but go-opus2 |
| R5 | homelab | 40x10 | `/`, `東`, `京` | control: correct everywhere |
| R6 | homelab | 80x24 | `/`, `東`, `京` | control: correct everywhere |

The expected screen after the last key is the spec-correct one (list rows from row 0, blank rows,
then the language's status line: Go `n/m /f`, Rust `n/m  /f`). For the three baselines, R3 expects
the contract-K9 selection (row 0) instead of the T3 part-C one. Only text is judged, by exact row
position; attributes were captured (`-e`, xterm.js cells) but not scored.

### Method details

- **tmux.** `scripts/tmux_drive.py`: for every (build, case, TERM variant, repeat) a detached session
  of the exact size runs a wrapper that waits for a flag file, so `pipe-pane -o` records every byte
  the program writes. Keys are sent as exact bytes (`send-keys -H`; `7f` Backspace, `0d` Enter,
  UTF-8 for characters). After the bytes file has been quiet for 0.4 s the pane is captured. `03`
  ends the program; sessions are killed by exact name on this socket only. Two TERM variants:
  *default* (tmux's own `TERM=tmux-256color`, with `TMUX`, `TMUX_PANE`, `TERM_PROGRAM` kept) and
  *xterm* (`TERM=xterm-256color`, no `TMUX` variables: the cross-review's pyte environment). 3
  repeats each. Pane size equalled the requested size in all 432 sessions (status line off via
  `scripts/tmux.conf`; no outer client).
- **xterm.js.** `scripts/pty_record.py` runs each binary in a fresh `openpty()` of the exact size and
  records the bytes after each key (settle 0.4 s; exit 130 after Ctrl-C in all 144 recordings).
  `scripts/xterm_replay.js` writes the recording chunk by chunk into a `Terminal({cols, rows})` and
  snapshots rows, cursor, underline columns and raw cells. Recorded under `TERM=xterm-256color` and
  `TERM=tmux-256color`.
- **Same bytes.** For every Go cell and case checked, the last-key bytes captured by `pipe-pane` in
  tmux equal the pty recording under the same TERM, apart from the synchronized-output wrapper
  (`CSI ? 2026 h` … `CSI ? 2026 l`) that Bubble Tea adds only when the terminal answers its
  `DECRQM 2026` query (tmux does, a bare pty does not). Under `TERM=tmux-256color` the Go renderer
  uses HPA (`CSI Pn \``) where it uses CHA under xterm-256color, as the cross-review's CSI audit
  said; the screens are the same.
- **pyte.** The cross-review's own `repro_bytes.py` (its `probe_lib.Session` with the HPA/REP fixes),
  run from the repository with this task's `bins/` (`raw/pyte/*.txt`). For R1-R6 its screens equal
  the cross-review's `raw/repro/` screens for all nine builds.

## Per-case table (build × case × emulator)

`correct` = the expected rows and status, `CORRUPT` = anything else (the rows seen are listed
below). tmux cells show agreeing runs / runs (3 repeats). The last column is the cross-review's own
pyte run (`../raw/repro/`, R1-R6 only).

| build | case | tmux TERM=tmux-256color | tmux TERM=xterm-256color | xterm.js TERM=xterm-256color | xterm.js TERM=tmux-256color | pyte (this run) | pyte (cross-review) |
|---|---|---|---|---|---|---|---|
| base-go-pinned | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go-pinned | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go-pinned | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-go-pinned | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-go-pinned | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go-pinned | R4 | correct (3/3) | correct (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| base-go-pinned | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go-pinned | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-go | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-go | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go | R4 | correct (3/3) | correct (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| base-go | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-go | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus1 | R1 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-opus1 | R2 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-opus1 | R2-40x10 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | n/a |
| T3-go-opus1 | R2-20x5 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | n/a |
| T3-go-opus1 | R3 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-opus1 | R4 | correct (3/3) | correct (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-opus1 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus1 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-go-opus2 | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-go-opus2 | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R4 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-opus2 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-sonnet1 | R1 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-sonnet1 | R2 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-sonnet1 | R2-40x10 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | n/a |
| T3-go-sonnet1 | R2-20x5 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | n/a |
| T3-go-sonnet1 | R3 | CORRUPT (3/3) | CORRUPT (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-sonnet1 | R4 | correct (3/3) | correct (3/3) | CORRUPT | CORRUPT | CORRUPT | CORRUPT |
| T3-go-sonnet1 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-go-sonnet1 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-rust | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| base-rust | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R4 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| base-rust | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-opus1 | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-opus1 | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R4 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus1 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-opus2 | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-opus2 | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R4 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-opus2 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R1 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R2 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R2-40x10 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-sonnet1 | R2-20x5 | correct (3/3) | correct (3/3) | correct | correct | correct | n/a |
| T3-rust-sonnet1 | R3 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R4 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R5 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |
| T3-rust-sonnet1 | R6 | correct (3/3) | correct (3/3) | correct | correct | correct | correct |

Rows seen where a verdict is `CORRUPT` (identical in every emulator and run that is marked
`CORRUPT`; go-sonnet1 shows the same rows as go-opus1 in every case, from the same bytes):

| case | go-opus1 and go-sonnet1 rows after the last key | expected |
|---|---|---|
| R1 | `> vps- 京` / `1/3 /東京` | `> vps-東京` |
| R2 | `> 東京-サーバー-本番  deploy@db.東京.example:22` / `  lab-server  aman@lab.example.internal:22` / `  名古 -bbackup-東  root@ngy.example.invalid:22` / `3/5 /-` | row 2 `  名古屋-backup-東  root@ngy.example.invalid:22` |
| R2-40x10 | `> 東京-サーバー-本番` / `  lab-server` / `  名古 -bbackup-東` / `3/5 /-` | row 2 `  名古屋-backup-東` |
| R2-20x5 | `> 東 --サーバー-本番` / `  la-sserver` / `  名古屋-backup-東` / `3/5 /-` | rows 0-1 `> 東京-サーバー-本番`, `  lab-server` |
| R3 | `  東京-サーバー-本番` / `  lab-server` / `  大阪` / `  nas` / `> 名 屋 -backup-東` / `5/5 /` | row 4 `> 名古屋-backup-東` |
| R4 (xterm.js and pyte only; also both Go baselines) | `> vps-東京  deploy@vps1.example.invalid:2222` / `1/3 /` | status `1/3 /京` |

tmux attribute capture agrees with xterm.js on where the underline landed, e.g. R1 go-opus1 row 0 in
tmux: `ESC[1m ESC[36m > vps- ESC[0m   ESC[1;4m ESC[36m 京 ESC[0m` (the underline is on the misplaced
京, column 8-9), xterm.js underline columns `{0: [7]}` (0-based start cell of 京). The misplaced
character is the underlined one in every N1 case (`results.json`, `xtermjs.*.underline`).

## Byte-level explanation

Five minimal sequences isolate the primitives (`scripts/primitives.py`, `raw/primitives.json`),
written to a fresh 20x3 terminal in tmux, xterm.js and the harness's pyte screen:

| primitive | bytes | tmux | xterm.js | pyte (harness) |
|---|---|---|---|---|
| E1 wide char written onto the right half of a wide char (R1) | `> vps-東京` `CSI 8 G` `京` | `> vps- 京` | `> vps- 京` | `> vps- 京` |
| E2 narrow chars written onto the right half (R2) | `  名古屋-backup` `CSI 8 G` `-b` | `  名古 -bbackup` | same | same |
| E5 VPA keeps the column (R1 as emitted) | `  vps-東京` CR LF LF `1/3 /東` `CSI 8 G` `CSI 1 d` `京` | row 1 `  vps- 京` | same | same |
| E3 BS onto the right half, then EL (R4 status bytes) | `1/3` `CSI 5 G` `/京` BS `CSI K` `CSI 7 G` | **`1/3 /京`** | **`1/3 /`** | **`1/3 /`** |
| E4 control: EL from after the wide char | `1/3` `CSI 5 G` `/京` `CSI K` | `1/3 /京` | `1/3 /京` | `1/3 /京` |

**N1 (E1, E2, E5): all three agree.** The go-opus1/go-sonnet1 bytes position the cursor on the
right half of a wide character and then write there. In R1 the frame for `東` ends with
`1/3 /東 CSI 8 G` (cursor at column 8, 1-based); the frame for `京` starts with `CSI 1 d` (VPA to
row 1, column unchanged) and writes `京`. Column 8 is the right half of `東` (`> vps-` is 6 cells, `東`
occupies 7-8). Writing there destroys `東` (its right half is overwritten, every emulator blanks the
orphaned left half) and the new `京` at 8-9 overwrites the left half of the old `京` at 9-10, so that
one vanishes too: `> vps- 京`. In R2 the row is reached by LF after `CSI 10 G` on the row above,
which leaves the cursor at column 7 = the right half of `屋`; `-` lands on it and `b` overwrites the
original `-`: `  名古 -bbackup-東`. The renderer intended column 8 in both cases and emitted no move
because its own cursor model was one column off after a wide cell; a correct terminal has no way to
recover the intended column, so the misplacement is fixed by the bytes on any ECMA-48 terminal, and
the three emulators also agree on the resulting text because all of them blank the orphaned half of
a wide character that is overwritten (xterm's rule; tmux does the same on overwrite).

**R4 (E3): the emulators differ, and only on EL.** The R4 status bytes end `/京 BS CSI K`: after
`京` the cursor is at column 8; BS moves it to column 7, the right half of `京`; EL erases from there.
xterm.js (`BufferLine.replaceCells`) and the harness's pyte render rule treat a wide character whose
right half is erased as gone, so `京` disappears: `1/3 /`. tmux's EL clears cells from the cursor
without touching the wide character's first cell, so its grid keeps `京`: `1/3 /京`. With EL from
column 8 (E4) all three keep `京`. This case belongs to the pre-existing P-A (both Go baselines emit
the same bytes); go-opus2's full repaint avoids it. It shows that P-A is terminal-dependent (visible
in xterm-family terminals, not in tmux), and it does not touch N1, whose mechanism (overwriting a
half) is handled the same way everywhere tested.

## Limitations

- **Two emulators, not a display.** tmux's grid was read with `capture-pane`, xterm.js's buffer with
  its API; no pixels were seen and no GUI terminal (Terminal.app, iTerm2, kitty, Alacritty, Ghostty,
  Windows Terminal) was driven. All of them implement the overwrite-a-half rule in some form, but that
  they show the same text as tmux and xterm.js is an inference from the bytes, not an observation.
- **xterm.js saw a replay, not a live pty.** It received the bytes recorded by a plain pty driver,
  so queries the program sends (DECRQM, DA, kitty keyboard) were never answered, and the Go builds
  did not use synchronized output there. tmux answered them live. The bytes that draw the rows are
  the same in both (checked for every Go cell and case).
- **Timing.** Captures were taken after 0.4 s of output silence (xterm.js recordings: 0.4 s; tmux:
  0.4 s on the pipe-pane file). Frames shorter than that were not judged.
- **Scope.** The eight cases are the cross-review's R1-R6 plus two sizes of its P02/P17 edit. The
  P11 status-line variant (`/ＦＵ`) and the P16 random walks were not re-run here. Only text was
  scored; underline placement was captured and inspected, not scored.
- **Toolchain.** go1.27.2 (the evaluated T3-go-opus1 was go1.27.1); the source is identical.
- **darwin-arm64 only**, as in the cross-review.

## Files

- `scripts/`: `build_verify.sh` (builds and provenance), `make_profiles.py`, `cases.json`,
  `pty_record.py` + `run_pty_all.py` + `xterm_replay.js` (pty bytes and xterm.js replay),
  `tmux_drive.py` + `tmux.conf` (tmux runs), `primitives.py`, `compare.py` (table and
  `results.json`).
- `table.md`, `results.json`: the per-case verdicts with rows, cursor, underline columns and the
  last-key bytes per emulator.
- `raw/tmux/<build>/<case>-<variant>-r<n>.json`: 432 tmux runs (screen after every key, `-e`
  capture, cursor, pane size, the program's environment, pipe-pane bytes per key).
- `raw/pty/<build>/<case>-<TERM>.json`: 144 pty recordings (bytes per key, exit code).
- `raw/xtermjs/<build>/<case>-<TERM>.json`: the xterm.js snapshots after every key (rows, cursor,
  underline, raw cells).
- `raw/pyte/<case>.txt`: the cross-review's `repro_bytes.py` on this task's binaries.
- `raw/primitives.json`, `raw/build/` (provenance, tree digests, manifests), `raw/logs/`,
  `raw/wide.toml`.

Paths in the artifacts are redacted to `<home>` / `<sandbox>`; the tmux socket value to
`<private-socket>`. Scratch root: `<home>/.local/share/heimdall-m00/r4-scratch/M00-T05-r4-x2-xrev-T3-verify/`
(peak 541 MB: Rust target 483 MB, Go tree 21 MB, binaries 28 MB, node_modules 1.9 MB). Build
trees, target dir, binaries, node_modules and sandboxes were deleted at the end; the private tmux
server had no sessions left and its socket was removed.
