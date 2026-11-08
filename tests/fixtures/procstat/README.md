# Synthetic `/proc/<pid>/stat` fixtures

Every file here is **synthetic**: written by hand (through a small generator) for the M03 shared
`/proc/<pid>/stat` parser, never captured from a real host or process. PIDs, process groups and
start times are made-up numbers.

* Rule under test (ADR-0008 D5 §6.3; §17.13 item 2; m03-plan U0b row 28): take the whole text,
  find the **last** `)`, split the suffix on whitespace; token 1 is the state (one letter), token 3
  the process group (decimal, at least 1), token 20 the start time (decimal); at least 20 tokens.
* `golden.json` lists each file with its expected `state`, `process_group` and `start_time`, or the
  `error` it must be rejected with. `comm-newline.stat` holds a newline inside `comm`;
  `exactly-20-tokens.stat` has no trailing newline; `empty.stat` is empty.
* Read by `tests/model/managed_domain.rs` (`procstat_parse_golden`,
  `procstat_comm_with_spaces_parentheses_and_newline`). The enrollment scripts' `awk` mirror (U5) is
  checked against the same files.
