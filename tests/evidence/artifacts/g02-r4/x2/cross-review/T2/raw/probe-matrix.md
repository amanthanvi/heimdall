| probe | go-opus1 | go-opus2 | go-sonnet1 | rust-opus1 | rust-opus2 | rust-sonnet1 |
|---|---|---|---|---|---|---|
| P1 random profiles vs reference model (400 profiles, seed 20261010; 343 with findings) | 400/400 match | 400/400 match | 400/400 match | 400/400 match | 400/400 match | 400/400 match |
| P1 plain-mode exit equals --json exit (80 runs) | yes | yes | yes | yes | yes | yes |
| P1 stderr empty on success | yes | yes | yes | yes | yes | yes |
| P2 same output in 40 runs (interleaved groups) | 1 distinct, correct | 1 distinct, correct | 1 distinct, correct | 1 distinct, correct | 1 distinct, correct | 1 distinct, correct |
| P3 hand-made edge profiles (12) | 12/12 | 12/12 | 12/12 | 12/12 | 12/12 | 12/12 |
| P4 no profile value (incl. canary-prefixed) on stdout/stderr, 4 runs | none echoed | none echoed | none echoed | none echoed | none echoed | none echoed |
| P4 ids printed without --json | no | no | no | no | no | no |
| P5 inputs (43) where lint differs from show / >2 s / echo | 0 | 0 | 0 | 0 | 0 | 0 |
| P6 argv templates (23) where lint differs from show | --file --json | 0 | 0 | 0 | 0 | 0 |
| P7 1 MiB adversarial profiles (11): worst wall s / peak RSS MiB, K15 | 0.11 s / 117 MiB, within | 0.11 s / 122 MiB, within | 0.10 s / 124 MiB, within | 0.17 s / 190 MiB, within | 0.09 s / 117 MiB, within | 0.16 s / 205 MiB, within |
| P7 cases where lint output != reference (all = show rejects too) | 4 | 4 | 4 | 0 | 0 | 0 |
| P8 closed-stdout exit parity (5 cases) | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| P9 files changed in cwd/profile dir/HOME/TMPDIR | 0 | 0 | 0 | 0 | 0 | 0 |
| P10 stdin pipe held open: exit, seconds | 3, 0.00 | 3, 0.00 | 3, 0.00 | 3, 0.00 | 3, 0.00 | 3, 0.00 |
| P12 commands (21) whose output differs from the baseline | 11 | 11 | 11 | 11 | 11 | 11 |

P7 per case (lint --json; worst of 5 runs): secs / peak RSS MiB

| case | base-go | base-rust | go-opus1 | go-opus2 | go-sonnet1 | rust-opus1 | rust-opus2 | rust-sonnet1 |
|---|---|---|---|---|---|---|---|---|
| A one destination, 209690 copies of one label (rule 4) (1048574 B, 1 findings, 209690 key paths) | show 0: 0.04 / 35 | show 0: 0.06 / 87 | 3: 0.07 / 62 | 3: 0.06 / 63 | 3: 0.09 / 63 | 3: 0.08 / 113 | 3: 0.07 / 97 | 3: 0.10 / 126 |
| B one destination, 209690 labels alternating a/A (rules 4 and 5) (1048574 B, 3 findings, 419380 key paths) | show 0: 0.04 / 38 | show 0: 0.06 / 87 | 3: 0.09 / 106 | 3: 0.09 / 102 | 3: 0.08 / 102 | 3: 0.13 / 164 | 3: 0.07 / 104 | 3: 0.13 / 194 |
| B2 one destination, 262112 labels alternating a/A, no spaces (most key paths per MiB) (1048573 B, 3 findings, 524224 key paths) | show 0: 0.04 / 46 | show 0: 0.06 / 95 | 3: 0.11 / 117 | 3: 0.11 / 122 | 3: 0.10 / 124 | 3: 0.17 / 190 | 3: 0.09 / 117 | 3: 0.16 / 205 |
| C one destination, 95313 distinct labels (no finding) (1048567 B, 0 findings, 0 key paths) | show 0: 0.03 / 26 | show 0: 0.03 / 42 | 0: 0.06 / 58 | 0: 0.05 / 51 | 0: 0.06 / 46 | 0: 0.04 / 55 | 0: 0.04 / 53 | 0: 0.04 / 57 |
| D 16473 destinations, same host and port (rule 1, one group) (1048570 B, 1 findings, 16473 key paths) | show 2: 0.01 / 9 | show 0: 0.06 / 89 | 2: 0.01 / 10 | 2: 0.01 / 10 | 2: 0.01 / 9 | 3: 0.10 / 57 | 3: 0.05 / 56 | 3: 0.05 / 56 |
| E 12435 destinations, labels x/X each (rule 5, one set over all destinations) (1048560 B, 1 findings, 24870 key paths) | show 2: 0.01 / 9 | show 0: 0.06 / 80 | 2: 0.01 / 9 | 2: 0.01 / 10 | 2: 0.01 / 10 | 3: 0.09 / 56 | 3: 0.06 / 56 | 3: 0.05 / 56 |
| F 14088 destinations, same host, port 21, root (rules 1-3) (1048513 B, 28177 findings, 42264 key paths) | show 2: 0.01 / 10 | show 0: 0.07 / 76 | 2: 0.01 / 10 | 2: 0.01 / 10 | 2: 0.01 / 10 | 3: 0.13 / 133 | 3: 0.05 / 54 | 3: 0.09 / 137 |
| G 12435 destinations, label x twice each (rule 4, one finding each) (1048560 B, 12435 findings, 24870 key paths) | show 2: 0.01 / 9 | show 0: 0.07 / 81 | 2: 0.01 / 10 | 2: 0.01 / 10 | 2: 0.01 / 10 | 3: 0.08 / 89 | 3: 0.05 / 56 | 3: 0.07 / 88 |
| H 10000 destinations, same host and port (rule 1, one group; under the Go guard) (627825 B, 1 findings, 10000 key paths) | show 0: 0.03 / 28 | show 0: 0.04 / 55 | 3: 0.04 / 29 | 3: 0.04 / 28 | 3: 0.03 / 28 | 3: 0.04 / 37 | 3: 0.03 / 37 | 3: 0.03 / 37 |
| I 8000 destinations, labels x/X each (rule 5 over all; under the Go guard) (668715 B, 1 findings, 16000 key paths) | show 0: 0.04 / 28 | show 0: 0.05 / 54 | 3: 0.04 / 28 | 3: 0.04 / 28 | 3: 0.04 / 28 | 3: 0.07 / 40 | 3: 0.03 / 40 | 3: 0.04 / 40 |
| J 8000 destinations, same host, port 21, root (rules 1-3; under the Go guard) (589825 B, 16001 findings, 24000 key paths) | show 0: 0.09 / 27 | show 0: 0.04 / 44 | 3: 0.04 / 32 | 3: 0.04 / 33 | 3: 0.04 / 32 | 3: 0.07 / 76 | 3: 0.03 / 32 | 3: 0.06 / 81 |
