# X2 implementer transcript audit

- `*.audit.json`: output of `hidden-pack/audit-transcript.py` (conservative; flags every call that could
  reach outside the cell) per scored cell of the third attempt and the reruns. The excluded x2c audit of
  T1-rust-opus1 is `T1-rust-opus1.excluded-x2c.audit.json`; the x2c audit of the excluded T1-go-opus1
  continuation was overwritten by the rerun's audit before this copy was made.
- `TRIAGE.md`: every flagged call read and classified; all scored cells clean.
- `x2-triage.txt`: the same for the six second-attempt (x2b) implementations.
- `triage.py`, `show-calls.py`: triage helpers. `evals.py`, `reviews.py`, `metrics.py`: journal readers.
  `aggregate.py` builds `../results.json`; `stats.py` prints the summary statistics in `../RESULTS.md`.

In these copies the home directory is `<home>` and the Claude Code project directory name is
`<project-slug>`, so the helper regexes do not run unchanged.
