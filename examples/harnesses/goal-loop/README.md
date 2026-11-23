# H2 goal-directed harness

H2 is a planner. You give it a goal, it holds one typed state, and it reaches the
goal through Heimdall's public CLI. The goal names the first call. Every step after
that is one row of a transition table, chosen from the current state and the last
answer's `code` and `next.action`. It checks the exit status of each answer's process
against the exit class documented for that answer: every published code has one. It
never reads an answer's message text.

It follows the contract's rules where a shortcut would be easier, on failure paths
too. Four of them:

- A request whose outcome is uncertain is never sent again, and a release is no
  exception. One new release can follow an uncertain one in one case only: the
  uncertain answer named an operation, and that operation ended without succeeding
  and says the release did not happen.
- A release that was started and brought no answer is uncertain too. It may have
  reached Heimdall before its process ran past its time limit.
- A request (`access ensure`, `run`) that was started and brought no answer is
  remembered too. It may have made a binding H2 was never told of. H2 never sends it
  again. A later stop, or the close, observes what became of it and releases every
  binding that shows.
- An operation is read by the typed `state` of its view. Only a terminal state says
  what became of it.

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
earlier request. A request that brought no answer ends its goal, and no later goal
sends it again. See "Requests with no answer" below.

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
  - A release answered `OUTCOME_UNKNOWN` is recorded apart from a refusal, and the
    stop goes on with the other bindings. The stop then fails. A later stop observes
    that release before it sends anything, and in most cases sends nothing. See
    "Uncertain releases" below.
  - A release that brought no answer is recorded too, and the stop goes on with the
    other bindings. The stop then fails. See "Calls with no answer" below.
  - A request that brought no answer is observed first, before any binding is asked
    about. A binding that observation shows is released by the same stop. See
    "Requests with no answer" below.
  - A stop that fails does not end its child. A stop ends its child only when it
    reaches `stopped`. A child that is still running when H2 closes is ended then.
  - With nothing held and no such request to observe, a stop fails without a call.

## States and transitions

`start`, `discovered`, `observing(operation_id)`, `reconciling(operation_id)`,
`pending_approval(decision_ref, operation_id)`, `pending_provider(provider, kind)`,
`ready(binding_id)`, `running(pid, binding_id)`, `releasing(binding_id)`,
`observing_release(binding_id, operation_id)`, `inspecting_release(binding_id)`,
`observing_request(request_id, operation_id)`, `inspecting_request(request_id, work_id)`,
`stopped`, `failed(code)`, `inconsistent(code, exit_code)`,
`unresolved(code, operation_id)`.

- `observing` holds an accepted operation that is neither an approval nor a provider
  wait, such as the one left by a caller timeout.
- `reconciling` holds the operation of an uncertain outcome while H2 observes it.
- `releasing` holds the next binding to release.
- `observing_release` holds a binding whose release was answered uncertainly, and the
  operation that answer named. H2 waits on that operation. This is the only state
  from which a new release of the same binding can follow.
- `inspecting_release` holds such a binding where the answer named no operation. H2
  reads the binding's own state from `inspect bindings`. No release follows from it.
- `observing_request` holds a request that brought no answer, and the operation it
  named before that. H2 waits on that operation.
- `inspecting_request` holds such a request where it named no operation. H2 reads
  `inspect bindings` for the bindings of the request's work. Neither state is followed
  by the request itself.
- `failed` also carries `operation_id` when its code is `OUTCOME_UNKNOWN` and an
  operation is known. When a stop ends with a binding it did not release, `failed`
  names the first one: its `binding_id`, the `exit_code` of the answer about it, and
  the code. The code is the refusal's own, or `OUTCOME_UNKNOWN` for a release that is
  still uncertain. A release that was never sent has no code, and `not_started`
  stands where the code would. `exit_code` is absent when the call had no exit status
  of its own: it was never started, or H2 ended it at its time limit.
  After a request that brought no answer, `failed` names the request: its
  `request_id`, the operation it named when it named one, and the code
  `OUTCOME_UNKNOWN`, or `not_started` when it was never sent. A stop that could not
  learn what became of such a request ends in `failed` with the same fields.
- `inconsistent` ends a goal: an answer's process ended in another exit class than
  the one documented for its code. It carries that code and the exit status. An
  answer about a release never ends there. See "Refused releases".
- `unresolved` ends a goal: the operation of an uncertain outcome was still unfinished
  at the step limit. It carries the code `OUTCOME_UNKNOWN` and that operation's ID.

Beside the state, H2 keeps the list of bindings it holds: every binding it was given
and has not released. A binding leaves the list in three ways only:

- its release is answered `OK` with exit 0, by a process that ended by itself;
- an observation says that its uncertain release happened: its operation is in the
  terminal state `succeeded`, or the list of bindings gives it the state `released`;
- after an uncertain release that named no operation, the complete list of
  `inspect bindings` does not name it. It is then `not_listed`: not held, and not
  recorded as released.

A binding Heimdall refused to release stays on the list. So does one whose release
is still uncertain, brought no answer, or was never sent. A binding joins the list
when:

- an answer leads to `ready` or `running` with it;
- an answer names it and then fails its exit-class check;
- a run record names it and the launch then fails, for example because the child
  ended before it wrote a line;
- a request that brought no answer named it before its process stopped;
- the observation of such a request shows it. See "Requests with no answer".

`TRANSITIONS` in `harness.py` is the whole table. A row names the states it applies
to, a code, a `next.action`, the new state, and the typed fields of the answer that
the new state is built from. The first row whose fields the answer carries wins. A
field written `=VALUE` is that fixed value.

- **No row** means failure. A code the table does not know is reported as an unknown
  code. Nothing is retried.
- **An observation** (`operation wait`) is read by the typed `state` of the
  operation's view, `data.state`. `OPERATION_STATES` in `harness.py` is the one table
  of the published states (`OperationState` in
  `schemas/public-api/envelope.schema.json`):

  | State | The operation | H2 reads the view's own `data.code` as the answer's code |
  | --- | --- | --- |
  | `queued`, `running`, `awaiting_approval` | is still going | no: the answer is "unfinished", whatever else the view carries |
  | `succeeded` | ended (terminal), and succeeded | yes |
  | `failed`, `cancelled` | ended (terminal), without succeeding | yes |
  | `outcome_unknown` | is unresolved: not going, and not terminal | yes |

  A view in a state the table lacks, or in none, is read as unfinished too.
- **The exit class** of every call is checked together with its answer, for every
  published code. See "Exit classes" below.
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

  A release answered `OUTCOME_UNKNOWN` is not sent again either, but it does not end
  its stop there. See "Uncertain releases".
- **The step limit** is `MAX_STEPS` calls for one goal (6), and it is the only bound:
  an uncertain outcome has no limit of its own. After the request that leaves 5
  observations, each waiting up to `OBSERVE_MS` (20 s). When the limit runs out, the
  table is asked once more, with the limit standing where the code would and the
  state's own fields as `state.*`. Only `reconciling` has a row for that. In any other
  state the goal fails where it stands, as before.
- **A release** answers for one binding. H2 checks that the answer names the binding
  it asked about and takes that binding off its list. `RELEASE_SAYS` in `harness.py`
  is the table that reads every answer about a release, with its exit class. The
  transition table gets that reading, with the planner's own facts:
  - `held.binding_id`: the next binding to release;
  - `uncertain.binding_id`: the next binding, when its last release was answered
    uncertainly, with `uncertain.operation_id` when that answer named an operation;
  - `unreleased.*`: the first binding this stop did not release.

  The table then moves to `releasing`, `observing_release` or `inspecting_release`
  with the next binding. When none is left, it moves to `stopped`, or to `failed`
  when the stop did not release every binding it asked about.

## Refused releases

A release is refused when it is not answered `OK` in the exit class documented for
`OK`. H2 decides this from the code and the exit status alone. One code is never a
refusal: `OUTCOME_UNKNOWN`. See "Uncertain releases". A call that brought no answer
is no refusal either. See "Calls with no answer".

- **It is recorded.** The record has three typed fields: `binding_id`, the answer's
  `code`, and the `exit_code` of its process.
- **The stop goes on.** The refused binding is set aside, and the stop asks about the
  next binding it holds, the newest first, within the same step limit. It asks about
  each binding once: a refused binding is not asked for again in the same stop.
- **The binding stays held.** It stays on the list of held bindings and is reported
  in `held`. H2 never reports it as released.
- **The stop fails.** When no binding is left to ask about, the stop ends in
  `failed(code, binding_id, exit_code)`, which names the first binding that stop did
  not release. Its record has `success` false. This holds even when every later
  release was answered `OK`.
- **The run exits 1.**
- **A stop that fails this way does not end its child.** The close does.

In the table the refusal is an answer of the planner's own, as the step limit and the
exit-class mismatch are. Its step in `transitions` has the code `(a refused release)`.

**A release whose exit class does not fit its code is treated like a refusal.** The
stop records it and goes on with the other bindings. That covers a refusal in the
wrong exit class, and `OK` with an exit status other than 0. The binding stays held,
and the run exits 1.

- Its record carries `"inconsistent": true`.
- Its record carries a `detail` that names the mismatch as a probable product defect:
  Heimdall's own code table gives each code one exit class.
- A stop whose first unreleased binding is such a one has that `detail` as its own.

Every published code has a documented class, so this covers every refusal Heimdall
can publish: for example `SERVICE_UNAVAILABLE` (class 5) with exit 0. A code that no
code table has has no documented class to check, so it is recorded with the exit
status it came with.

Two limits apply:

- **A stop cut short keeps what it set aside.** A stop that begins in `releasing`,
  `observing_release` or `inspecting_release` goes on with the stop the step limit
  cut short. It does not ask again about a binding that stop set aside, and it still
  fails, naming that binding. A stop that begins in any other state is a new one and
  asks about every held binding again.
- **A running child is left to the close.** A stop ends its child only when it
  reaches `stopped`.

## Uncertain releases

A release answered `OUTCOME_UNKNOWN` may have happened or not. H2 never sends it
again while that is unknown. Release is no exception to that rule.

**The stop that gets the answer** records it, sets the binding aside and goes on with
the other bindings, as after a refusal. The binding stays held, the stop fails in
`failed(OUTCOME_UNKNOWN, binding_id, exit_code)`, and the run exits 1. The record is
kept apart from the refusals, in `outcome_unknown`:

```json
{"binding_id": "<binding>", "code": "OUTCOME_UNKNOWN", "exit_code": 7,
 "request_id": null, "operation_id": "<operation>"}
```

- `operation_id` is present when the answer names an operation: the one in
  `next.operation_id`, else the envelope's own.
- `request_id` is `null`. Today's `access release` takes no request ID, so there is
  none to record. There is also no replay under the same request ID to fall back on.
  An uncertain release can only be observed.
- An `OUTCOME_UNKNOWN` answer is uncertain whatever its exit status. In the wrong
  exit class, its record also carries `"inconsistent": true` and the `detail`.

**A later stop, or the close, observes it first.** For a binding whose release is
uncertain, the first call is an observation, not a release:

| The uncertain answer | H2 observes | State |
| --- | --- | --- |
| named an operation | that operation: `operation wait <operation>` | `observing_release` |
| named no operation | the binding's own state: `inspect bindings` | `inspecting_release` |

`RELEASE_SAYS` reads the observation from typed fields only. Each observation is one
attempt, recorded with one of four outcomes.

**Where the answer named an operation,** H2 waits on it once, for up to `OBSERVE_MS`
(20 s), within the stop's step limit. It then acts on what that operation says:

| The operation | Outcome | H2 then |
| --- | --- | --- |
| is in the terminal state `succeeded`, with its own code `OK`, `next.action` `none`, exit 0 | `released` | takes the binding off its list and sends nothing |
| is in the terminal state `failed` or `cancelled`, with another code, `next.action` `none` and `effect_status` `none`, in that code's exit class | `not_run` | sends one new release of that binding |
| anything else | `still_unknown` | keeps the binding held and reports it; sends nothing |

"Anything else" covers an operation still unfinished when the wait ran out, one whose
own code is `OUTCOME_UNKNOWN`, one that ended with an effect other than `none`, a
wait that was itself refused or brought no answer, and any answer in the wrong exit
class.

**Only a terminal view is evidence.** An operation that is still going says nothing
about the release, whatever its envelope says. Take a view in the state `running`,
with no code and effect `unknown`, answered `OK` with no next action and exit 0. H2
reads it as unfinished: `still_unknown`, the binding stays held, and nothing is sent.
The exit class documented for an operation that is still going is 5, so that answer
is also recorded with `"inconsistent": true`. In the same way, a refusal's code with
effect `none` means "the release did not happen" only in the terminal states `failed`
and `cancelled`.

**Where the answer named no operation,** H2 reads the binding's `state` in the
complete list of `inspect bindings`. Nothing it reads there is followed by a release:

| The list of bindings | Outcome | H2 then |
| --- | --- | --- |
| gives the binding the state `released` | `released` | takes the binding off its list and sends nothing |
| does not name the binding | `not_listed` | takes the binding off its list and sends nothing; it is not recorded as released |
| gives the binding the state `active` | `still_unknown` | keeps the binding held and reports it; sends nothing |
| anything else | `still_unknown` | the same |

"Anything else" covers a state no table has, a binding listed in two states, a list
that could not be read or is not the complete list, and any answer in the wrong exit
class.

Four rules follow from the contract owner's rulings of 2026-11-22:

- **An `active` binding alone is not evidence that the release never ran.** The
  release may not have been applied yet. H2 sends no new release. It reports
  `still_unknown`, keeps the binding held, and the run exits 1.
- **A binding the complete list does not name is `not_listed`.** That means "not
  held". It never means "released": the binding may as well have expired or been
  revoked. The stop counts it as not held, so the binding leaves `held` and the stop
  can still reach `stopped`. The record says `not_listed`, and no record says that
  H2 observed a release.
- **One new release can follow an uncertain one in one case only.** The uncertain
  answer named an operation H2 can wait on, H2 waited, and the operation ended saying
  that the release did not happen (`not_run`). The transition table has that row for
  `observing_release` alone, and no row of `RELEASE_SAYS` for `inspect bindings`
  gives that reading. The new release is read like any other: answered, refused or
  uncertain.
- **Still unknown is an end, not a retry.** The binding stays held, the stop goes on
  with the other bindings and fails, and the run exits 1. A later stop, or the close,
  observes once more. An observation in the wrong exit class is recorded with
  `"inconsistent": true`.

Each outcome has a step code of its own in `transitions`:

| Outcome | Step code | Moves to |
| --- | --- | --- |
| `released`, by an observation | `(a release observed)` | the next binding, or the end of the stop |
| `not_run` | `(a release that never ran)` | `releasing`, with the same binding |
| `still_unknown` | `(a release still unknown)` | the next binding, or `failed` |
| `not_listed` | `(a binding not listed)` | the next binding, or the end of the stop |

`(an uncertain release)` is the step of the release that was itself answered
`OUTCOME_UNKNOWN`.

**The stop or close that receives the uncertain answer does not observe it itself.**
Each stop observes an uncertain binding once, and only one that an earlier stop left
uncertain. The next stop, or the close, observes it. So a single close that receives
`OUTCOME_UNKNOWN` ends with the binding held, and the run exits 1. Its record names
the operation to observe, when the answer named one.

## Calls with no answer

A call about a release can end without an answer H2 can use. H2 records each one as
an attempt with a typed `fault`, and goes on with the other bindings. One binding's
failure never keeps the others from being asked about, in a stop or in the close.

| `fault` | What happened | Was the call sent? |
| --- | --- | --- |
| `timed_out` | the call ran past its time limit (`CALL_SECONDS`, 40 s) and H2 ended its process | it may have been |
| `unreadable` | the process ended, and what it printed is not one envelope about what was asked | it may have been |
| `not_started` | the CLI could not be started, or the launch environment failed its check | no |

**A release that may have been sent is uncertain.** H2 remembers it exactly like a
release answered `OUTCOME_UNKNOWN`, and never sends it again blindly. A later stop,
or the close, observes it first, by the same two tables as above.

- Its outcome is `unanswered`, and its record is in the goal's `unanswered` list. The
  stop fails in `failed(OUTCOME_UNKNOWN, binding_id)`, and the run exits 1.
- H2 keeps what the process printed before it stopped, from typed fields only. It
  reads the first complete line. If that line is an envelope, the attempt records its
  `code`, and H2 remembers the operation it names, to wait on later.
- A complete `OUTCOME_UNKNOWN` line is kept whole. The attempt is then an
  `outcome_unknown` one, with its `operation_id`, `"exit_code": null` and the fault:

  ```json
  {"binding_id": "<binding>", "code": "OUTCOME_UNKNOWN", "exit_code": null,
   "request_id": null, "operation_id": "<operation>", "fault": "timed_out",
   "detail": "a CLI call ran past its time limit"}
  ```
- No other answer is taken from such a process. A line that says `OK` is not a
  release: the process did not end by itself, so its exit class was never seen. The
  same holds for `OK` about another binding than the one asked for.

**A release that was never sent is not uncertain.** Its outcome is `not_sent`, in the
goal's `not_sent` list. The binding stays held and is set aside for that stop, as
after a refusal. The stop fails in `failed(not_started, binding_id)`. A later stop,
or the close, sends the release.

**An observation with no answer settles nothing.** Its outcome is `still_unknown`,
with the fault. The release stays uncertain, and nothing is sent.

## Requests with no answer

`access ensure` and `run` are requests: each asks Heimdall to change something, and
each carries a request ID of its own. One that ends without an answer H2 can use may
still have reached Heimdall and made a binding. H2 records it as an attempt with the
same typed `fault` as above, and the goal fails.

| `fault` | What happened | Outcome |
| --- | --- | --- |
| `timed_out` | `access ensure` ran past `CALL_SECONDS` (40 s), or the child of `run` wrote no line within `LAUNCH_SECONDS` (30 s). H2 ended the process | `unanswered` |
| `unreadable` | the process ended, and what it left is not one envelope, or not the run record of a launch | `unanswered` |
| `not_started` | the CLI could not be started, or the launch environment failed its check | `not_sent` |

**A request that was never sent is not uncertain.** Nothing is remembered. The goal
ends in `failed(not_started, request_id)`.

**A request that may have been sent is remembered.** The goal ends in
`failed(OUTCOME_UNKNOWN, request_id)`, with the operation when one was named. H2 never
sends that request again: every later goal is a new request with a new ID.

**What it printed before it stopped is kept,** from typed fields only: the first
complete line as an envelope, and the run records of a launch.

- **A binding it named is held at once.** That is `next.binding_id` of the envelope, or
  `binding_id` of a run record. The goal still fails: a printed `ACCESS_READY` from a
  process that did not end by itself is not `ready`. Nothing is left to observe. A
  stop, or the close, releases that binding like any other.
- **An operation it named is remembered** with the request: `next.operation_id`, else
  the envelope's own, else the run record's.
- H2 holds no child from a launch that ran past its time limit. It ends that process
  through its own handle at the limit, as it ends any call that does.

**A later stop, or the close, observes it first,** before it asks about any binding.
Each stop observes each remembered request once.

| The request | H2 observes | State |
| --- | --- | --- |
| named an operation | that operation: `operation wait <operation>` | `observing_request` |
| named no operation | the bindings of its work: `inspect bindings` | `inspecting_request` |

`REQUEST_SAYS` in `harness.py` reads the observation from typed fields only.

**Where it named an operation:**

| The operation | Outcome | H2 then |
| --- | --- | --- |
| is in the terminal state `succeeded`, with its own code `ACCESS_READY`, `next.action` `none`, exit 0, and names a binding in `data.result.binding_id` | `binding_found` | holds that binding, and the same stop releases it |
| is in the terminal state `failed` or `cancelled`, with another code, `next.action` `none` and `effect_status` `none`, in that code's exit class | `not_run` | has nothing to release |
| anything else | `still_unknown` | keeps the request as uncertain, and sends nothing |

**Where it named no operation,** today's CLI has no way to observe a request by its
request ID: `operation show` and `operation wait` take an operation ID, and no
`inspect` subject takes a request ID. The typed means left is the complete list of
`inspect bindings`. H2 reads three fields of each entry: `work_id`, `state` and
`binding_id`.

| The list of bindings | Outcome | H2 then |
| --- | --- | --- |
| names a binding for the request's work, in the state `active`, that H2 does not hold | `binding_found` | holds every such binding, and the same stop releases them |
| names no such binding | `still_unknown` | keeps the request as uncertain, and sends nothing |
| could not be read, is not the complete list, or came in the wrong exit class | `still_unknown` | the same |

Three rules follow from the contract owner's ruling of 2026-11-22:

- **An `active` binding for that work is a binding to release.** H2 holds it and
  releases it under the same rules as every other binding.
- **A list that names none is no evidence that the request never ran.** It may not
  have been applied yet. That is also what the list says when the only bindings for
  the work are ones H2 held before. The request stays `still_unknown`.
- **Still unknown is an end, not a retry.** The stop goes on with the bindings it
  holds, and then fails in `failed(OUTCOME_UNKNOWN, request_id)`. The run exits 1, and
  the summary names the request. A later stop, or the close, observes once more.

**What the list cannot say.** It carries no request ID. So H2 cannot tell which
request made a binding it shows, whether the request reached Heimdall at all, or
whether it is still in progress and will make a binding later. Only the operation of
a request can say that it never ran.

Each outcome has a step code of its own in `transitions`:

| Outcome | Step code | Moves to |
| --- | --- | --- |
| `unanswered` | `(no answer)` | `failed`, in the goal that sent the request |
| `not_sent` | `(not started)` | `failed`, in the goal that did not send it |
| `binding_found` | `(a request observed)` | the next request, or the first binding to release |
| `not_run` | `(a request that never ran)` | the next request or binding, or the end of the stop |
| `still_unknown` | `(a request still unknown)` | the next request or binding, or `failed` |

No real-binary run produces any of these answers today. The stub tests alone cover
them.

## The list of bindings

**The reading of `inspect bindings` comes from the contract's binding list, not from
an observed run.** H2 has the list's word for the binding's state. It did not see
the release run, and no real-binary run answers a release uncertainly today. The
stub tests alone cover this reading. The same holds for the bindings the list names
for a work: `work_id` is a field of the list as today's build prints it.

**`inspect bindings` is the one call H2 uses that the skill does not list yet**
(`skills/heimdall/SKILL.md`). It is a read-only call of the CLI contract. The skill
gains it later.

## Exit classes

Every published code has a documented exit class (`docs/api/local-protocol.md`, "Exit
classes"), and H2 checks each answer against the class of its code. That includes
the codes the transition table has no row for.

**Where the classes come from.** The `discover` goal reads the installed binary's
code table (`schema show codes`). After it, the class checked for a code is the one
that table gives. `EXIT_CLASSES` in `harness.py` is a frozen copy of the published
table (`schemas/public-api/codes.json`). H2 falls back to it before discovery, and
for a row that gives no usable class:

| Class | Meaning | Codes |
| --- | --- | --- |
| 0 | success | `OK`, `ACCESS_READY`, `ACCEPTED` |
| 1 | internal | `INTERNAL_ERROR` |
| 2 | usage, schema or lookup | `USAGE_ERROR`, `SCHEMA_UNSUPPORTED`, `NOT_FOUND` |
| 3 | needs a person | `APPROVAL_REQUIRED`, `INTERACTION_REQUIRED`, `PROVIDER_LOCKED` |
| 4 | not allowed | `CAPABILITY_UNAVAILABLE`, `POLICY_PAUSED`, `POLICY_CUTOFF`, `CREDENTIAL_EXPIRED`, `HOST_TRUST_CHANGED`, `DELEGATION_EXCEEDS_PARENT`, `OPERATION_CANCELLED` |
| 5 | unavailable for now | `DESTINATION_UNREACHABLE`, `TIME_UNCERTAIN`, `UNSUPPORTED_CLIENT`, `SERVICE_UNAVAILABLE`, `STATE_UNAVAILABLE`, `BACKPRESSURE` |
| 6 | conflict | `REQUEST_CONFLICT`, `CONFIG_CONFLICT`, `REQUEST_EXPIRED`, `RESYNC_REQUIRED`, `DECISION_STALE` |
| 7 | uncertain | `OUTCOME_UNKNOWN` |
| 127 | a launch that failed | `LAUNCH_FAILED` |

**The command-specific exceptions** stand whichever table gave the class.
`EXIT_EXCEPTIONS` and `OPERATION_STATES` in `harness.py` hold them:

| Answer | Class | Why |
| --- | --- | --- |
| `ACCEPTED` | 5 | H2 never asks asynchronously, so `ACCEPTED` always means that the bounded wait ran out |
| `LAUNCH_FAILED` with `data.error.reason` `not_executable` | 126 | the program is not one that can be run |
| an observation of an operation that is still going (`queued`, `running`, `awaiting_approval`) | 5 | still pending after a bounded wait |
| an observation of an operation in the state `outcome_unknown` | 7 | its outcome is uncertain |
| an observation of an operation that ended (`succeeded`, `failed`, `cancelled`) | the class of the operation's own code | `succeeded` with no code of its own is class 0 |

When the exit status is not the documented class, the goal fails in
`inconsistent(code, exit_code)`. Its last step in `transitions` has the code
`(the exit class)`. Nothing is retried, and a refusal a goal expected does not count
either. A binding that answer named stays on the list of held bindings, so a stop
still releases it.

An answer about a release is the exception: it never ends in `inconsistent`.
`RELEASE_SAYS` reads its exit class together with its code. A release that fails the
check is recorded like a refusal, and an observation that fails it leaves the release
uncertain. Each carries `"inconsistent": true`, and the stop goes on.

Four answers are not checked:

- a launch that started, because its process is the child and still runs;
- a code that neither code table has, because no class is documented for it. It has
  no row either, so it fails the goal anyway;
- output that is not one envelope, which has no code to check. It fails the goal, and
  a request or a release is then remembered as uncertain;
- a call H2 ended at its time limit, because its process has no exit status of its
  own.

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
`close`, `release_attempts` and `request_attempts`. A record has the fields H1's records have (`task`, `success`, `calls`,
`round_trips`, `human_handoffs`, `invalid_retries`, `wall_time_ms`,
`discovery_bytes`, `detail`, `skipped`) and adds `goal`, `final_state`,
`transitions` (the path it took), `held` (the bindings H2 still holds after the
goal), and six lists of what the goal's calls about releases came to:

| List | Holds |
| --- | --- |
| `refused_releases` | the releases Heimdall refused during the goal |
| `outcome_unknown` | the releases answered `OUTCOME_UNKNOWN` during the goal |
| `unanswered` | the releases of the goal that were started and brought no answer |
| `not_sent` | the releases of the goal that were never sent: the CLI could not be started |
| `still_unknown` | the observations of the goal that did not say what became of an uncertain release |
| `not_listed` | the bindings the goal found missing from the complete list of bindings |

A binding in one of the first five is still held. A binding in `not_listed` is not.

Three more lists are about requests that brought no answer. They stand beside the
lists about releases, so that an entry of either kind has one shape:

| List | Holds |
| --- | --- |
| `requests_unanswered` | the requests of the goal that were started and brought no answer |
| `requests_not_sent` | the requests of the goal that were never sent: the CLI could not be started |
| `requests_still_unknown` | the observations of the goal that did not say what became of such a request |

Before it exits, H2 releases whatever the goals left held and ends a child that is
still running. `close` reports that: `released` lists the bindings released then, by
an answer or by an observed release, and `held` lists those still on H2's list. A
binding the close found `not_listed` is in neither: it is not held, and it was not
observed to be released. `release_attempts` names it.

The close is always a stop of its own, whatever state the goals left, and every call
it makes is an attempt of its own, recorded with `by` `close`. It is made in rounds
that are each bounded by the step limit.

- It asks about every held binding once, whatever an earlier stop was answered. A
  binding a stop goal was refused is asked for once more.
- It follows the same rules as a stop goal: a binding it does not release is recorded
  and set aside, and the rest are still released.
- It observes a release an earlier stop left uncertain, and does not send it again.
- It does not observe a release that it was itself answered uncertainly.
- It observes each request that brought no answer first, once, and does not send it
  again. `released` also names a binding such an observation showed and the close then
  released.
- Every call it makes about a binding is an attempt, a call with no answer included.
  So a failure about one binding never ends it while another binding is still to be
  asked about.

The summary's `release_attempts` is keyed by binding. It has one entry for each
binding with an attempt that did not release it. The entry says whether the binding
is still `held`, and lists every attempt about that binding in order: those of the
stop goals, then those of the close.

```json
{"<binding>": {"held": true, "attempts": [
  {"by": "stop", "outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4},
  {"by": "close", "outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}]}}
```

An attempt is one call. Its fields:

| Field | Meaning |
| --- | --- |
| `by` | `stop` for a stop goal, `close` for the close |
| `outcome` | `released`, `refused`, `outcome_unknown` (the release was answered `OUTCOME_UNKNOWN`), `unanswered` (the release was started and brought no answer), `not_sent` (the CLI could not be started), `still_unknown` (an observation did not say what became of it), `not_run` (its operation ended and said the release did not happen) or `not_listed` (the complete list of bindings does not name the binding) |
| `code`, `exit_code` | the answer's code and the exit status of its process. For an observed operation, the code is the operation's own once its state says the operation is over. After a call with no answer, `code` is the code of the first complete line it printed, or `null`; `exit_code` is `null` when the call was never started or H2 ended it |
| `observed` | present on an observation: `operation` or `bindings` |
| `state` | present on a `bindings` observation that could be read: the binding's state, or `(not listed)` |
| `request_id`, `operation_id` | present while the outcome is `outcome_unknown`, `unanswered` or `still_unknown`. See "Uncertain releases" |
| `inconsistent` | present when the exit class does not fit the answer: `true` |
| `fault` | present after a call with no answer: `timed_out`, `unreadable` or `not_started`. See "Calls with no answer" |
| `detail` | present with `inconsistent` (the mismatch named as a probable product defect) or with `fault` (what went wrong with the call) |

An entry in one of a goal's six lists about releases is the same attempt with its
`binding_id`, and without `by` and `outcome`.

The summary's `request_attempts` is keyed by request ID. It has one entry for each
request that brought no answer. The entry says what was asked (`call`: `access ensure`
or `run`; `profile`; `work_id`), whether H2 still does not know what became of it
(`uncertain`), and lists every attempt about it in order: the request itself, then
each observation.

```json
{"<request-id>": {"call": "access ensure", "profile": "<profile>", "work_id": "<work-id>",
  "uncertain": false, "attempts": [
  {"by": "access", "outcome": "unanswered", "code": "ACCEPTED", "exit_code": null,
   "fault": "timed_out", "detail": "a CLI call ran past its time limit",
   "operation_id": "<operation>"},
  {"by": "close", "outcome": "binding_found", "code": "ACCESS_READY", "exit_code": 0,
   "observed": "operation", "operation_id": "<operation>", "bindings": ["<binding>"]}]}}
```

| Field | Meaning |
| --- | --- |
| `by` | the goal that made the call (`access`, `run`, `stop`), or `close` |
| `outcome` | `unanswered` or `not_sent` for the request itself; `binding_found`, `not_run` or `still_unknown` for an observation |
| `code`, `exit_code` | as for a release. For the request itself, `code` is the code of the first complete line it printed, or `null` |
| `fault`, `detail`, `inconsistent` | as for a release |
| `operation_id` | present when the request named an operation |
| `observed` | present on an observation: `operation` or `bindings` |
| `listed` | present on a `bindings` observation that could be read: the bindings the list names for the work in the state `active` |
| `bindings` | the bindings this attempt gave H2, which it then holds: the one the request named before it stopped, or those an observation showed |

An entry in one of a goal's three lists about requests is the same attempt with its
`request_id`, `call`, `profile` and `work_id`, and without `by` and `outcome`.

A release whose operation said it did not happen, and that was then released, has
three attempts: `outcome_unknown`, `not_run`, `released`. A binding found missing
from the list has two, and it is not held:

```json
{"<binding>": {"held": false, "attempts": [
  {"by": "stop", "outcome": "outcome_unknown", "code": "OUTCOME_UNKNOWN", "exit_code": 7,
   "request_id": null},
  {"by": "close", "outcome": "not_listed", "code": "OK", "exit_code": 0,
   "observed": "bindings", "state": "(not listed)"}]}}
```

- Calls and round trips count CLI subprocesses.
- A goal that ends in `unresolved` has one last step in `transitions` that is not a
  call: its `code` is `(the step limit)`.
- A refused release is a call, and it is counted. Its step in `transitions` has the
  code `(a refused release)`. An observation of an uncertain release is a call too.
- The releases H2 makes when it closes are in no record's counts.
- Wall time excludes the time spent in a handoff.
- Discovery bytes are the stdout bytes of the discovery call.
- Invalid retries count answers whose `next.action` is `fix_request` or
  `new_request_id`: Heimdall saying the request was wrong or wrongly repeated.

The process exits 0 when every goal was met, `release_attempts` and
`request_attempts` are empty and nothing is left held. It exits 1 otherwise: a release
that was refused, uncertain, unanswered or not sent fails the run, whatever a later
attempt made of it. That includes a binding later found `not_listed`. A request that
brought no answer fails the run too, whatever an observation then showed.

## Held

- **The call set.** It is to come from the installed binary's
  `schema show primitives`. Today's build does not serve that, so `load_call_set`
  returns the one local table in `harness.py`. That function is the only place that
  changes when it is served. Held for U4b.
- **Native Windows.** The launch environment awaits native verification. The
  `run` goal still needs to handle the Windows `spawned` record.
- **Provider waits, `APPROVAL_REQUIRED` and `OUTCOME_UNKNOWN`.** These rows are
  covered by the stub tests only: no fixture of the real-binary run produces them.
- **Every answer about a release other than `OK`.** A refused release, one in the
  wrong exit class, an uncertain one, one with no answer, and each result of
  observing it are covered by the stub tests only. That includes an operation view
  that contradicts its envelope. No real-binary run produces any of these answers
  today.
- **Every request that brought no answer.** A request that ran past its time limit,
  one whose answer could not be read, one that was never started, and each result of
  observing one are covered by the stub tests only. No real-binary run produces any of
  these today.
- **Observing a request by its request ID.** Today's CLI has no such call, so a
  request that named no operation is observed through `inspect bindings` for its work.
  That list cannot say whether the request ran. If the contract gains such a call, H2
  uses it there.
- **The request ID of a release.** Today's `access release` takes none. If it takes
  one later, H2 records it in `request_id`. Whether H2 may then send the release
  again under the same ID is the contract owner's to say.
- **`inspect bindings` in the skill.** It is the one call H2 uses that
  `skills/heimdall/SKILL.md` does not list yet. It is a read-only call of the CLI
  contract, and the skill gains it later.

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
- a release in the wrong exit class: it is recorded like a refusal with
  `inconsistent`, and the rest are still released. That holds for a published code
  the table has no row for (`SERVICE_UNAVAILABLE` with exit 0), and for a code only
  the installed table lists;
- uncertain releases: the record; each result of observing one, in a later stop and
  in the close. By its operation: released, not released (one new release, and only
  then), and still unfinished. By the list of bindings: `active` (no new release),
  not listed (`not_listed`, never `released`), and `released`. Also that the release
  is never sent again while its outcome is unknown; that a close alone ends with the
  binding held; and the summary by binding with the exit status of the run;
- an operation view read by its state: one that is still `running` is never read as
  a release or as a release that never ran, whatever its envelope, code and exit
  status say, and such a contradictory answer is recorded with `inconsistent`;
- calls with no answer: a release whose process prints its answer and then stays
  past the time limit is remembered with what it printed, and observed before any
  other release of that binding; with three bindings held and no call about a
  release ever ending, every binding is still asked about, by the stop and by the
  close; a CLI that cannot be started sends nothing, and each binding still has its
  attempt;
- requests with no answer: `access ensure` that prints `ACCESS_READY` with a binding
  and then stays (the close releases it); one that names an operation and then stays,
  observed to have succeeded (the binding is released), to have failed with effect
  `none` (nothing to release) and to be still unfinished (`still_unknown`); one that
  stays without a word, or prints no envelope, observed by the list of bindings for
  its work; a binding H2 already held for that work, which is no evidence; a launch
  whose run record was written before the time limit, and one that left none; a
  request that was never started (`not_sent`); that no such request is ever sent
  again; and the exit status of the run;
- exit classes: the stub ends an answer in the wrong class for each kind of call,
  and the goal fails; every published code is checked against its class; the frozen
  tables are compared with `schemas/public-api` when the example sits in the
  repository;
- an uncertain outcome: its operation is observed until it ends, the request is
  never repeated however many observations that takes, and every report that can
  name the operation does.

Set `HEIMDALL_HARNESS_SMOKE_BIN` to the absolute path of the built debug binary to add
the discovery smoke. It checks the table's codes against the real code table, and
that the frozen exit classes are that table's, code for code. It starts no runtime.

Five tests run `main` against a stub started through its interpreter line, so they
run on POSIX only. The other tests start the stub through the Python interpreter.

`tests/e2e/harness_m07.rs` runs H1 and H2 against the real binary.
