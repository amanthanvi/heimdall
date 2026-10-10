### Repeated race runs (P10r, P11r; 10 reps per build and platform, bash)

Cell: runs with at least one re-stop right after `fg` / runs; total re-stops; whether a second `fg` recovered every re-stop.

| build | darwin P10r | darwin P11r | linux P10r | linux P11r |
|---|---|---|---|---|
| plain | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-go | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-go-pinned | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-go-opus1 | 0/10; 0; yes | 0/10; 0; yes | 2/10; 2; yes | 0/10; 0; yes |
| T1-go-opus2 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-go-sonnet1 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| base-rust | 1/10; 2; yes | 0/10; 0; yes | 0/10; 0; yes | 10/10; 10; NO |
| T1-rust-opus1 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-rust-opus2 | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |
| T1-rust-sonnet1 | 1/10; 1; yes | 0/10; 0; yes | 0/10; 0; yes | 0/10; 0; yes |

### Escalating recovery (P1x: background job, stdio redirected; P2x: stdio on the terminal; third-party SIGTSTP of the child; 2 reps, bash)

Cell: `jobs` state after the stop; what gave the prompt back after `fg` (`fg` = the job finished; otherwise the first of ^C, ^Z, ^\ that did; `none` = nothing did).

| build | darwin P1x | darwin P2x | linux P1x | linux P2x |
|---|---|---|---|---|
| plain | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| base-go | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| base-go-pinned | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| T1-go-opus1 | running -> ctrl-backslash | stopped[Suspended: 18] -> fg | running -> none | stopped[Stopped] -> fg |
| T1-go-opus2 | running -> ctrl-backslash | running -> ctrl-backslash | running -> none | running -> none |
| T1-go-sonnet1 | running -> ctrl-backslash | stopped[Suspended: 18] -> fg | running -> none | stopped[Stopped] -> fg |
| base-rust | stopped[Suspended: 18] -> fg | stopped[Suspended: 18] -> fg | stopped[Stopped] -> fg | stopped[Stopped] -> fg |
| T1-rust-opus1 | running -> ctrl-z | stopped[Suspended: 18] -> fg | running -> ctrl-z | stopped[Stopped] -> fg |
| T1-rust-opus2 | running -> ctrl-z | stopped[Suspended: 18] -> fg | running -> ctrl-z | stopped[Stopped] -> fg |
| T1-rust-sonnet1 | running -> ctrl-z | running -> ctrl-z | running -> ctrl-z | running -> ctrl-z |

### P9e follow-up: repeated `fg` (P9e0-fg3: suspend, fg; P9e-bg-fg3: suspend, bg, fg; 2 reps)

Cell: after which `fg` the job-control child answered (0 = not after three) and where the typed `xq-ping` lines went (child / shell = ran as a command in the outer shell / nowhere = no answer).

| build | darwin-bash P9e0-fg3 | darwin-bash P9e-bg-fg3 | darwin-zsh P9e0-fg3 | darwin-zsh P9e-bg-fg3 | linux-bash P9e0-fg3 | linux-bash P9e-bg-fg3 |
|---|---|---|---|---|---|---|
| plain | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| base-go | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 1; child | 1; child |
| T1-go-opus1 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| T1-go-opus2 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| T1-go-sonnet1 | 1; child | 1; child | 1; child | 1; child | 1; child | 1; child |
| base-rust | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere | 0; nowhere |
| T1-rust-opus1 | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell |
| T1-rust-opus2 | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell | 1; child | 0; shell,shell,shell |
| T1-rust-sonnet1 | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell | 0; shell,shell,shell |

### S3 resume window (P12-S3)

Milliseconds, sampled every few microseconds for 1 s after the third party's SIGCONT to the launcher, during which the launcher was not stopped while the child still was (per rep). Plain exec has no launcher; `jobs` 1 s later is in the matrix.

| build | darwin-bash | linux-bash | darwin-zsh |
|---|---|---|---|
| base-go | 0.3, 0.3 | 3.3, 0.1 | 0.2, 0.2 |
| base-go-pinned | 0.3, 0.1 | 0.2, 0.6 | 0.6, 0.6 |
| T1-go-opus1 | 0.5, 0.4 | 0.9, 0.5 | 0.3, 0.6 |
| T1-go-opus2 | 0.1, 0.2 | 0.1, 1.2 | 0.3, 0.1 |
| T1-go-sonnet1 | 0.3, 0.1 | 0.1, 0.1 | 0.4, 0.3 |
| base-rust | 999.9, 999.8 | 999.9, 999.9 | 999.8, 999.9 |
| T1-rust-opus1 | 10.0, 10.4 | 11.2, 10.7 | 10.4, 10.2 |
| T1-rust-opus2 | 0.1, 0.1 | 0.9, 0.1 | 0.1, 0.1 |
| T1-rust-sonnet1 | 32.2, 31.5 | 31.3, 31.3 | 30.1, 30.3 |
