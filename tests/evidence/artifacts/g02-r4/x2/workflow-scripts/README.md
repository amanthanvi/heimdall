# X2 workflow scripts

The scripts that ran the X2 cells, with the home directory replaced by `<home>`:

- `heimdall-m00-g02-round4-x2b.js`: second attempt (`wf_21d21205-c96`). API rate limits killed most
  agents; the T2, T3 and T4 opus1 implementations (and the T2-go-opus1 evaluation) completed.
- `heimdall-m00-g02-round4-x2c.js`: third attempt (`wf_0c100051-5bd`); the completed x2b results were
  passed in through `args`. Its T1 opus1 cells are excluded (`../runs-excluded/NOTE.md`).
- `heimdall-m00-g02-round4-x2d.js`: reruns of T1-go-opus1 (`wf_9661f31f-f4b`) and T1-rust-opus1
  (`wf_749c87d4-6a5`, args naming only that cell, after a host reboot killed the first x2d attempt).

The implementer prompts of the three scripts are identical except for one sentence that x2c and x2d
add (write report files with the shell).
