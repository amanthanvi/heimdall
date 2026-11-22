# H2 goal-directed harness

H2 is a planner. You give it a goal, it holds one typed state, and it reaches the
goal through Heimdall's public CLI. The goal names the first call. Every step after
that is one row of a transition table, chosen from the current state and the last
answer's `code` and `next.action`. It checks every answer against the exit class of
its process. It never reads an answer's message text.

It needs Python 3.9 or newer and uses the standard library only. It was written
independently of H1 (`../cli`) and of the reference wrapper, and imports neither.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B examples/harnesses/goal-loop/harness.py \
  --heimdall-bin "$debug_bin" --scratch-root "$scratch" \
  --goal '{"goal": "discover"}' \
  --goal '{"goal": "access", "profile": "<profile>", "work_id": "<work-id>"}'
```

## Launch environment

The fixture driver owns the scratch runtime, the fixture profiles and the cleanup. It
starts H2 with `HOME`, `HEIMDALL_HOME` and `HEIMDALL_TEST_SSH_HOME` set. Before every
call H2 checks that each is an existing directory inside `--scratch-root`, and that
none is the same as, or inside, another. A missing or foreign one fails the goal
before anything is launched.

The driver also sets `HEIMDALL_TEST_MGMT_STORE=fixture-file:<absolute path>` and
`HEIMDALL_TEST_IROH_KEY_STORE=<absolute path>`. H2 checks that both paths resolve
inside `--scratch-root`. The fixture store files may be absent.

Each `heimdall` child then gets the checked homes and store paths as given,
`HEIMDALL_TEST_SECRET_STORE=scratch`, and fixed `PATH`, `LANG`, and `TERM`.
On Windows, H2 requires an absolute
`SystemRoot` and builds `PATH` from the in-box OpenSSH directory, `System32`,
and `SystemRoot`. It sets `USERPROFILE`, `ProgramData`, `ALLUSERSPROFILE`,
`APPDATA`, `LOCALAPPDATA`, `TEMP`, and `TMP` to the checked fixture `HOME`.
H2 passes no `SSH_AUTH_SOCK`. Supply an absolute path to `--heimdall-bin`.

## Goals

Repeat `--goal` to run a sequence. The state carries over from one goal to the next,
and so does the list of bindings H2 holds.

Every changing request (`access ensure`, `run`) gets a request ID of its own. The ID
guards one request against being applied twice. It never carries work on from an
earlier request.

| Goal | First call | Met in state | Fields |
| --- | --- | --- | --- |
| `discover` | `schema show codes` | `discovered` | none |
| `access` | `access ensure` | `ready` | `profile`, `work_id`; optional `pairs`, `timeout_ms`, `require_unattended`, `expect_refusal` |
| `run` | `run` | `running` | `profile`, `work_id`, `argv` |
| `stop` | `access release` | `stopped` | none: it releases every binding H2 holds |

Any goal may carry a `task` label for its record.

- **`discover`** reads the installed code table and fails if it lacks a code the
  transition table uses.
- **`access` with `pairs`** asks for only those `destination:account` pairs.
- **`access` with `expect_refusal`** is met when Heimdall refuses with that code and
  reports effect `none`. H2 records the refusal and stops.
- **`run`** starts `argv[0]`, an executable inside the scratch root, under a binding
  for the work. The child must print one line when it is up and exit when its input
  closes. The launch's run record names the binding the child runs under. After
  `access` for the same profile and work, that may be the binding already prepared
  or a second one: Heimdall decides. H2 holds the prepared binding and the child's.
- **`stop`** begins wherever H2 holds a binding, whatever became of the goals before
  it. It releases each binding H2 holds, one call for each, the newest first. If a
  child is running, H2 then closes the child's input and waits for it. A child that
  stays is stopped through its own handle and the goal fails.
  - From `ready`, `running` or `releasing` it goes on with that state's binding.
  - From any other state, such as `failed` after a later goal, it begins in
    `releasing` with the newest binding on the list.
  - A stop the step limit cuts short fails and leaves the rest held. The next stop
    goes on from there: seven bindings take two stops.
  - A release Heimdall refuses is recorded, and the stop goes on with the other
    bindings. The stop then fails. See "Refused releases" below.
  - With nothing held, a stop fails without a call.

## States and transitions

`start`, `discovered`, `observing(operation_id)`, `reconciling(operation_id)`,
`pending_approval(decision_ref, operation_id)`, `pending_provider(provider, kind)`,
`ready(binding_id)`, `running(pid, binding_id)`, `releasing(binding_id)`, `stopped`,
`failed(code)`, `inconsistent(code, exit_code)`, `unresolved(code, operation_id)`.

- `observing` holds an accepted operation that is neither an approval nor a provider
  wait, such as the one left by a caller timeout.
- `reconciling` holds the operation of an uncertain outcome while H2 observes it.
- `releasing` holds the next binding to release.
- `failed` also carries `operation_id` when its code is `OUTCOME_UNKNOWN` and an
  operation is known. When a stop ends because a release was refused, it carries the
  refusal's code, its `binding_id` and its `exit_code`.
- `inconsistent` ends a goal: an answer's process ended in another exit class than
  the one documented for its code. It carries that code and the exit status.
- `unresolved` ends a goal: the operation of an uncertain outcome was still unfinished
  at the step limit. It carries the code `OUTCOME_UNKNOWN` and that operation's ID.

Beside the state, H2 keeps the list of bindings it holds: every binding it was given
and has not released. A binding leaves the list when its release is answered `OK`
with exit 0, and only then: a binding Heimdall refused to release stays on it. A
binding joins the list when:

- an answer leads to `ready` or `running` with it;
- an answer names it and then fails its exit-class check;
- a run record names it and the launch then fails, for example because the child
  ended before it wrote a line.

`TRANSITIONS` in `harness.py` is the whole table. A row names the states it applies
to, a code, a `next.action`, the new state, and the typed fields of the answer that
the new state is built from. The first row whose fields the answer carries wins. A
field written `=VALUE` is that fixed value.

- **No row** means failure. A code the table does not know is reported as an unknown
  code. Nothing is retried.
- **An observation** (`operation wait`) carries the operation's own code in
  `data.code` once it has one. H2 reads that as the answer's code.
- **The exit class** of every call is checked together with its answer. See
  "Exit classes" below.
- **A launch** has no envelope. Its run record's `type` (`launching`) stands where
  the code would. H2 passes `--meta-file` with a new file of its own inside the
  scratch root, reads the record from it and removes it. That file is the only one
  H2 reads.
- **An uncertain outcome** (`OUTCOME_UNKNOWN`) never sends the request again. H2
  observes the operation named in `next.operation_id` (`operation wait`) until it
  ends, within the goal's step limit:
  - `ACCESS_READY`: the goal goes on from `ready`.
  - A failure code of the operation: `failed` with that code.
  - `OUTCOME_UNKNOWN` as the operation's own code: `failed` with that code and the
    operation's ID. The same holds for an operation H2 was observing after an
    approval or a caller timeout.
  - Not finished yet: H2 stays in `reconciling` and observes the same operation again.
  - Still unfinished at the step limit: `unresolved`, with the code `OUTCOME_UNKNOWN`
    and the operation's ID. The goal fails, and its record's `final_state` is
    `{"state": "unresolved", "code": "OUTCOME_UNKNOWN", "operation_id": "<operation>"}`.
  - The answer's `next` named no operation: `failed(OUTCOME_UNKNOWN)`, with no
    further call. It carries the envelope's own `operation_id` when there is one.
- **The step limit** is `MAX_STEPS` calls for one goal (6), and it is the only bound:
  an uncertain outcome has no limit of its own. After the request that leaves 5
  observations, each waiting up to `OBSERVE_MS` (20 s). When the limit runs out, the
  table is asked once more, with the limit standing where the code would and the
  state's own fields as `state.*`. Only `reconciling` has a row for that. In any other
  state the goal fails where it stands, as before.
- **A release** answers for one binding. H2 checks that the answer names the binding
  it asked about, takes that binding off its list, and puts the next binding to ask
  for into the answer's facts as `held.binding_id`. The table then moves to
  `releasing` with it, or to `stopped` when none is left.

## Refused releases

A release answered with any code other than `OK` is a refusal, once its exit class
has been checked. H2 decides this from the code and the exit status alone.

- **It is recorded.** The record has three typed fields: `binding_id`, the refusal's
  `code`, and the `exit_code` of its process.
- **The stop goes on.** The refused binding is set aside, and the stop asks for the
  next binding it holds, the newest first, within the same step limit. It asks for
  each binding once: a refused binding is not asked for again in the same stop.
- **The binding stays held.** It stays on the list of held bindings and is reported
  in `held`. H2 never reports it as released.
- **The stop fails.** When no binding is left to ask for, the stop ends in
  `failed(code, binding_id, exit_code)`, which names the first refusal of that stop.
  Its record has `success` false. This holds even when every later release was
  answered `OK`.
- **The run exits 1.**

In the table the refusal is an answer of the planner's own, as the step limit and the
exit-class mismatch are. Its step in `transitions` has the code `(a refused release)`.
The facts carry `held.binding_id`, and `refused.*` for the first refusal of the stop.

Three limits apply:

- **The exit class comes first.** A refusal whose exit status is not the class
  documented for its code ends the stop in `inconsistent`, as for any other answer.
  It is not recorded as a refusal, and its binding stays held. A code `EXIT_CLASSES`
  lacks has no documented class to check, so it is recorded with the exit status it
  came with.
- **A stop cut short keeps what it set aside.** A stop that begins in `releasing`
  goes on with the stop the step limit cut short, and does not ask again for a
  binding that stop was refused. It still fails, naming that refusal. A stop that
  begins in any other state is a new one and asks for every held binding again.
- **A running child is left to the close.** A stop ends its child only when it
  reaches `stopped`.

## Exit classes

`EXIT_CLASSES` in `harness.py` is the one table of the exit class documented for each
code the transition table acts on (`docs/api/local-protocol.md`, "Exit classes"):

| Class | Meaning | Codes |
| --- | --- | --- |
| 0 | success | `OK`, `ACCESS_READY` |
| 2 | usage, schema or lookup | `NOT_FOUND`: checked for a refused release only, and it has no row |
| 3 | needs a person | `APPROVAL_REQUIRED`, `INTERACTION_REQUIRED`, `PROVIDER_LOCKED` |
| 4 | not allowed | `CAPABILITY_UNAVAILABLE`, `POLICY_PAUSED`, `POLICY_CUTOFF`, `OPERATION_CANCELLED` |
| 5 | unavailable for now | `ACCEPTED`; an observation that found its operation unfinished (`OK` with `next.action` `observe`) |
| 6 | conflict | `REQUEST_CONFLICT` |
| 7 | uncertain | `OUTCOME_UNKNOWN` |

H2 never asks asynchronously, so `ACCEPTED` always means that the bounded wait ran
out (class 5). An observation exits in the class of the operation's own code.

When the exit status is not the documented class, the goal fails in
`inconsistent(code, exit_code)`. Its last step in `transitions` has the code
`(the exit class)`. Nothing is retried, and a refusal a goal expected does not count
either. A binding that answer named stays on the list of held bindings, so a stop
still releases it. A release that fails this check leaves its binding held.

Three answers are not checked:

- a launch that started, because its process is the child and still runs;
- a code the table lacks, because it has no row and fails the goal anyway;
- output that is not one envelope, which fails the goal before any check.

## Handoffs

H2 never approves, denies or answers a prompt. Its calls run with
`--non-interactive` and no input.

On entering `pending_approval` or `pending_provider` it writes one JSON line to
stderr and waits for `continue` and a newline on stdin:

```json
{"handoff": "approval", "decision_ref": "<decision>", "operation_id": "<operation>"}
{"handoff": "provider", "provider": "<provider>", "kind": "<kind>"}
```

After an approval handoff it observes the same operation. After a provider handoff
it makes the goal's request once more, as a new request; a second provider answer
ends the goal.

## Records

Stdout is one JSON summary: `harness`, `call_set`, one record per goal in `tasks`,
and `close`. A record has the fields H1's records have (`task`, `success`, `calls`,
`round_trips`, `human_handoffs`, `invalid_retries`, `wall_time_ms`,
`discovery_bytes`, `detail`, `skipped`) and adds `goal`, `final_state`,
`transitions` (the path it took), `held` (the bindings H2 still holds after the
goal) and `refused_releases` (the releases Heimdall refused during the goal).

Before it exits, H2 releases whatever the goals left held and ends a child that is
still running. `close` reports that: `released` lists the bindings released then,
and `held` lists any it could not release. The close is one stop, made in rounds
that are each bounded by the step limit. It follows the same rule as a stop goal: a
refused binding is recorded and set aside, and the rest are still released. A round
that neither releases a binding nor is refused one ends it.

The summary's own `refused_releases` lists every refused release of the run, in
order: those of the goals, then those of the close. Each entry is one refused call:

```json
{"binding_id": "<binding>", "code": "<code>", "exit_code": 4}
```

A binding a stop goal was refused is asked for once more when H2 closes, so it has
two entries if Heimdall refuses it again.

- Calls and round trips count CLI subprocesses.
- A goal that ends in `unresolved` has one last step in `transitions` that is not a
  call: its `code` is `(the step limit)`.
- A refused release is a call, and it is counted. Its step in `transitions` has the
  code `(a refused release)`.
- The releases H2 makes when it closes are in no record's counts.
- Wall time excludes the time spent in a handoff.
- Discovery bytes are the stdout bytes of the discovery call.
- Invalid retries count answers whose `next.action` is `fix_request` or
  `new_request_id`: Heimdall saying the request was wrong or wrongly repeated.

The process exits 0 when every goal was met, no release was refused and nothing is
left held. It exits 1 otherwise.

## Held

- **The call set.** It is to come from the installed binary's
  `schema show primitives`. Today's build does not serve that, so `load_call_set`
  returns the one local table in `harness.py`. That function is the only place that
  changes when it is served. Held for U4b.
- **Native Windows.** The launch environment awaits native verification. The
  `run` goal still needs to handle the Windows `spawned` record.
- **Provider waits, `APPROVAL_REQUIRED`, `OUTCOME_UNKNOWN` and a refused release.**
  These rows are covered by the stub tests only: no fixture of the real-binary run
  produces them.
- **A release answered in the wrong exit class.** The stop ends there, in
  `inconsistent`. That binding and any older one stay held and are reported in
  `held`. H2 does not skip it to release the others.

## Tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B -m unittest discover -s examples/harnesses/goal-loop/tests
```

The tests use a stub `heimdall` in a temporary directory. They cover:

- every row of the table for every state it names, and the unknown-code failure;
- that message text changes no transition;
- cleanup: a stop after a failed goal, a close with bindings held and a child
  running, and seven bindings released by two stops;
- refused releases: with three bindings held, a refusal of the first, the middle or
  the last one asked for, and of all three, in a stop goal and in the close; more
  refusals than one stop may ask for; and the exit status of the run;
- exit classes: the stub ends an answer in the wrong class for each kind of call,
  and the goal fails;
- an uncertain outcome: its operation is observed until it ends, the request is
  never repeated however many observations that takes, and every report that can
  name the operation does.

Set `HEIMDALL_HARNESS_SMOKE_BIN` to the absolute path of the built debug binary to add
the discovery smoke. It checks the table's codes and exit classes against the real
code table and starts no runtime.

`tests/e2e/harness_m07.rs` runs H1 and H2 against the real binary.
