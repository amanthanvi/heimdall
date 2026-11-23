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
  again. A later stop, or the close, observes what became of it and releases a binding
  that shows, but only one it can tie to that request. The same holds for a request
  that was answered `OUTCOME_UNKNOWN`, and for one whose goal ends while its operation
  is still open, however the goal ends. See "Requests answered with their operation
  left open".
- Nothing uncertain is a success. A goal never expects `OUTCOME_UNKNOWN` as its
  refusal, and the run exits 1 while any request or release is still uncertain.
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
  reports effect `none`. H2 records the refusal and stops. `OUTCOME_UNKNOWN` is never a
  refusal a goal can expect: it is uncertain, whatever effect it reports. A refusal the
  goal expected does not meet it either while the request is still uncertain.
- **`run`** starts `argv[0]`, an executable inside the scratch root, under a binding
  for the work. On Windows `argv[0]` may also be the in-box OpenSSH client,
  `%SystemRoot%\System32\OpenSSH\ssh.exe`. H2 starts it as the goal gives it and adds
  nothing: H2 adds no isolation to a child it did not build, so the caller's goal decides
  which ssh profile a `run` child uses (M07-W7-R02). Without `-F` that client reads the
  token profile's real `%USERPROFILE%\.ssh\config` and default identities, and without
  `IdentityAgent=none` it may ask the system agent pipe `\\.\pipe\openssh-ssh-agent`.
  The fixture driver's goal carries `-F <scratch config>` and the isolated options on the
  client's own command line, and `tests/e2e/harness_m07.rs` checks every such goal it
  gives. The child must print one line when
  it is up and exit when its input closes. The launch's run record names the binding the child runs under. After
  `access` for the same profile and work, that may be the binding already prepared
  or a second one: Heimdall decides. H2 holds the prepared binding and the child's.
- **`stop`** begins wherever H2 holds a binding, whatever became of the goals before
  it. It releases each binding H2 holds, one call for each, the newest first. If a
  child is running, H2 then closes the child's input and waits for it. A child that
  stays is stopped through its own handle and the goal fails. On Windows that handle is
  Heimdall's, not the child's: see "A launch" below.
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
  wait, such as the one left by a caller timeout. A goal that ends while it, or
  `pending_approval` or `reconciling`, waits on the request's operation leaves the
  request uncertain, and H2 remembers it. See "Requests answered with their operation
  left open".
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
  `OUTCOME_UNKNOWN`, or `not_started` when it was never sent. After an accepted
  request whose wait brought no answer or that was still open at the step limit,
  `failed` names the request, its operation and the code `OUTCOME_UNKNOWN`. So does an
  observed operation whose own code is `OUTCOME_UNKNOWN`. A stop that could not
  learn what became of such a request ends in `failed` with the same fields.
- `inconsistent` ends a goal: an answer's process ended in another exit class than
  the one documented for its code. It carries that code and the exit status. An
  answer about a release never ends there. See "Refused releases".
- `unresolved` ends a goal: the operation of an uncertain outcome was still unfinished
  at the step limit. It carries the code `OUTCOME_UNKNOWN` and that operation's ID.
  H2 remembers the request with that operation, and a later stop observes it.

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
- the observation of such a request shows it, in the right exit class or not. See
  "Requests with no answer".

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
  scratch root, reads the records from it, and removes it once the launch has ended.
  That file is the only one H2 reads. What makes a launch is the platform's own
  sequence (`LAUNCHED`, ADR-0007 §8): `launching` on Unix, where Heimdall execs into
  the child; `launching` then `spawned` on Windows, where Heimdall spawns the child and
  waits for it. There `launching`'s `pid` is Heimdall's own, the process H2 started,
  and H2 reads the file again for up to `SPAWNED_SECONDS` (5 s) when the child's line
  comes before `spawned`. Any other sequence is no launch, and the child is ended.
  **A limit on Windows (M07-W7-R03, carried to the next wave):** there the process H2
  started, and so the one it ends, is `heimdall.exe`, which spawned the child and waits
  for it. Ending it (a stop, the close, a sequence that is no launch, a time limit) ends
  Heimdall, not the child, and H2 does not use the PID the `spawned` record names. A
  child that ignores the end of its input outlives H2. The in-box client of the fixture
  driver's task 5 exits when its input ends.
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
    H2 remembers the request with that operation. See "Requests with no answer".
  - The answer's `next` named no operation: `failed(OUTCOME_UNKNOWN)`, with no
    further call. It carries the envelope's own `operation_id` when there is one. H2
    remembers the request, with that operation when there is one. See "Requests
    answered with their operation left open".

  A release answered `OUTCOME_UNKNOWN` is not sent again either, but it does not end
  its stop there. See "Uncertain releases".
- **The step limit** is `MAX_STEPS` calls for one goal (6), and it is the only bound:
  an uncertain outcome has no limit of its own. After the request that leaves 5
  observations, each waiting up to `OBSERVE_MS` (20 s). When the limit runs out, the
  table is asked once more, with the limit standing where the code would and the
  state's own fields as `state.*`. The three states that wait on the operation of the
  request in progress have a row for that: `reconciling` ends in `unresolved`, and
  `observing` and `pending_approval` end in `failed(OUTCOME_UNKNOWN, request_id,
  operation_id)`. In any other state the goal fails where it stands.
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

### Requests answered with their operation left open

A request that was answered may still make a binding after its goal ends: its answer
was uncertain, or its operation was still open. H2 remembers each such request in the
same way, with that operation (ruled 2026-11-23; W7).

**An answer of `OUTCOME_UNKNOWN`** is uncertain whatever its effect, its exit class or
its row. Where it leads to `reconciling`, H2 observes its operation within the goal.
Where it ends the goal (its `next` names no operation, or its exit class does not
fit), the request's attempt is `outcome_unknown`, with the answer's code and exit
status and the operation it named, if any (`next.operation_id`, else the envelope's
own), in `requests_outcome_unknown`.

**A goal that ends while it waits on the operation** of its own answered request
(`observing` after `ACCEPTED`, `pending_approval` after an approval, `reconciling` after
`OUTCOME_UNKNOWN`) leaves the request uncertain. Only an answer that says how the
operation ended settles it. H2 reads that last answer by `REQUEST_SAYS`, as it reads a
later observation:

- **Settled:** a binding found (the goal reached `ready` with it), or an operation that
  ended without succeeding, with effect `none`. Nothing is remembered.
- **Anything else:** the request is remembered. Its attempt is `still_unknown`, with
  that answer's code and exit status (`observed: "operation"` where it was a wait), in
  `requests_still_unknown`.

| The goal ends | In | The request's attempt |
| --- | --- | --- |
| at the step limit while reconciling | `unresolved(OUTCOME_UNKNOWN, operation_id)` | `outcome_unknown`, with the code and exit status of the request's answer, in `requests_outcome_unknown` |
| at the step limit while observing or pending approval: each wait found the operation unfinished (Heimdall's own timeout, exit 5) | `failed(OUTCOME_UNKNOWN, request_id, operation_id)` | `still_unknown`: the last wait, `OK`, exit 5 |
| a wait that ran past its time limit, came back unreadable or could not be started, in any of the three states | `failed(OUTCOME_UNKNOWN, request_id, operation_id)` | `still_unknown`, with its `fault` |
| a wait refused for now, such as `SERVICE_UNAVAILABLE` (exit 5): a code with no row there | `failed(<code>)` | `still_unknown`, with that code |
| a wait in the wrong exit class | `inconsistent(code, exit_code)` | `still_unknown`, with `inconsistent: true`. A binding it named is held and released |
| an observed operation whose own code is `OUTCOME_UNKNOWN` | `failed(OUTCOME_UNKNOWN, request_id, operation_id)` | `still_unknown`, code `OUTCOME_UNKNOWN`, exit 7 |
| an approval handoff the person never came back from | `pending_approval` | `still_unknown`, with the code of the request's own answer (no `observed`) |

The request is never sent again. A later stop, or the close, observes it like any
remembered request.

### Observing a remembered request

**A later stop, or the close, observes it first,** before it asks about any binding.
Each stop observes each remembered request once.

| The request | H2 observes | State |
| --- | --- | --- |
| named an operation | that operation: `operation wait <operation>` | `observing_request` |
| named no operation | the list of bindings: `inspect bindings` | `inspecting_request` |

`REQUEST_SAYS` in `harness.py` reads the observation from typed fields only.

**Where it named an operation:**

| The operation | Outcome | H2 then |
| --- | --- | --- |
| is in the terminal state `succeeded`, with its own code `ACCESS_READY`, `next.action` `none`, exit 0, and names a binding in `data.result.binding_id` | `binding_found` | holds that binding, and the same stop releases it |
| the same, in another exit class | `still_unknown`, with `inconsistent: true` | holds that binding all the same, and the same stop releases it. The request stays uncertain |
| is in the terminal state `failed` or `cancelled`, with another code, `next.action` `none` and `effect_status` `none`, in that code's exit class | `not_run` | has nothing to release |
| anything else | `still_unknown` | keeps the request as uncertain, and sends nothing |

**Where it named no operation,** today's CLI has no way to observe a request by its
request ID: `operation show` and `operation wait` take an operation ID, and no
`inspect` subject takes a request ID. The typed means left is the complete list of
`inspect bindings`.

**H2 never releases a binding it cannot tie to its own request** (ruled 2026-11-23).
Each entry of the list carries `binding_id`, `grant_id`, `work_id`, `profile`,
`profile_revision`, `state` and `created_at`. No field names a caller or a request:
the list is this caller's own. A binding is a candidate only if it passes every check
of `ATTRIBUTION` in `harness.py`:

| Field | Check |
| --- | --- |
| `state` | `active` |
| `work_id` | the request's work |
| `profile` | the request's profile |
| `created_at` | an RFC 3339 instant in UTC, later than the moment H2 sent the request (taken just before the process started) |

A binding H2 was ever given is not a candidate: it is the binding of the answer that
gave it. `grant_id` and `profile_revision` tie a binding to no request.

| The list of bindings | Outcome | H2 then |
| --- | --- | --- |
| names exactly one candidate | `binding_found` | holds it, and the same stop releases it |
| the same, in another exit class | `still_unknown`, with `inconsistent: true` | holds it all the same, and the same stop releases it. The request stays uncertain |
| names more than one candidate | `still_unknown` | releases none of them: which one is the request's is not known |
| names none: another profile, an older binding, one with no creation time, one H2 was given, or no binding for the work | `still_unknown` | keeps the request as uncertain, and sends nothing |
| could not be read, or is not the complete list | `still_unknown` | the same |

Rules that follow from the contract owner's rulings of 2026-11-22 and 2026-11-23:

- **A binding the observation names is held, whatever its exit class.** Cleanup is
  the safer side. An answer in the wrong exit class still settles nothing, so the
  request stays `still_unknown`, and the attempt is marked `inconsistent`.
- **A binding H2 cannot tie to its request is left alone.** That covers a binding of
  the same work for another profile, or made before the request was sent.
- **Requests of one work and profile are observed together** (M07-W6-R02). One read of
  the list observes every remembered request a stop may still observe that named no
  operation and asked for the same work and profile. They are read the newest first,
  and a binding credited to one is held, so it is no candidate of the next: each
  binding is credited to one request at most. A binding made after a request was sent
  was made after every older request was sent too, so the newest has the fewest
  candidates. Requests that named an operation are observed before any of these, so
  the list never offers a binding their operation names to another request. What the
  list cannot settle stays as it was: two bindings both made after the newest request
  was sent are two candidates for it, and none is released.
- **Newest first can credit the wrong request (M07-W7-R04, a stated limit carried to
  the next wave).** Take two remembered silent requests, R1 then R2, for the same work
  and profile, and one listed binding made after R2 was sent. H2 credits it to R2,
  releases it and stops observing R2, but R1 may have made it, for example when its
  operation was slow. R1 then stays `still_unknown`, and a binding R2's own operation
  makes later is not looked at or released. No field names the request that made a
  binding (U0-Q7). The run still exits 1, because R1 is uncertain.
- **A list that names none is no evidence that the request never ran.** It may not
  have been applied yet. The request stays `still_unknown`.
- **Still unknown is an end, not a retry.** The stop goes on with the bindings it
  holds, and then fails in `failed(OUTCOME_UNKNOWN, request_id)`. The run exits 1, and
  the summary names the request. A later stop, or the close, observes once more.

**What the list cannot say.** It carries no request ID. So H2 cannot tell whether the
request reached Heimdall at all, or whether it is still in progress and will make a
binding later. Only the operation of a request can say that it never ran. A creation
time is the runtime's wall clock, compared with H2's own on the same host.

Each outcome has a step code of its own in `transitions`:

| Outcome | Step code | Moves to |
| --- | --- | --- |
| `unanswered` | `(no answer)` | `failed`, in the goal that sent the request |
| `not_sent` | `(not started)` | `failed`, in the goal that did not send it |
| `still_unknown` of a wait in `observing`, `pending_approval` or `reconciling` | `(no answer)` or `(not started)` | `failed`, in the goal that sent the request |
| `binding_found` | `(a request observed)` | the next request, or the first binding to release |
| `not_run` | `(a request that never ran)` | the next request or binding, or the end of the stop |
| `still_unknown` | `(a request still unknown)` | the next request or binding, or `failed` |
| `still_unknown`, with a binding held | `(a binding found out of its exit class)` | the next request or binding, or `failed` |

A request that ends `unresolved` has the step code `(the step limit)`, as any
`unresolved` goal does.

No real-binary run produces any of these answers today. The stub tests alone cover
them.

## The list of bindings

**The reading of `inspect bindings` comes from the contract's binding list, not from
an observed run.** H2 has the list's word for the binding's state. It did not see
the release run, and no real-binary run answers a release uncertainly today. The
stub tests alone cover this reading. The same holds for the bindings the list names
for a request: `work_id`, `profile` and `created_at` are fields of the list as today's
build prints it (`crates/app/src/operations.rs`, the bindings arm of `inspect`). No
published schema covers `inspect bindings` yet.

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

Stdout is one JSON summary. Every field H2 writes is in this table. "Task" is one
record of `tasks`, one for each goal. "Attempt" is one call about a release or about
a request, as `release_attempts` and `request_attempts` list it; an entry of a task's
lists is the same attempt with the fields named there.

| Field | Meaning | Where it appears |
| --- | --- | --- |
| `harness` | `H2` | the summary |
| `call_set` | where the call set came from | the summary |
| `tasks` | one record for each goal, in order | the summary |
| `close` | what the close did: `released` and `held` | the summary |
| `release_attempts` | each binding with an attempt that did not release it, keyed by binding ID | the summary |
| `request_attempts` | each request whose outcome was ever unknown or that was never sent, keyed by request ID | the summary |
| `released` | the bindings the close released, by an answer or by an observed release, in the order H2 first held them | `close` |
| `held` | the bindings H2 still holds | `close`; a task, after its goal; an entry of `release_attempts` (`true` or `false`) |
| `task` | the goal's task label (its `task`, else the goal's name) | a task |
| `goal` | the goal's name: `discover`, `access`, `run` or `stop` | a task |
| `success` | whether the goal was met | a task |
| `calls`, `round_trips` | how many CLI processes the goal started (the same number) | a task |
| `human_handoffs` | how many times the goal handed off to a person | a task |
| `invalid_retries` | answers whose `next.action` is `fix_request` or `new_request_id` | a task |
| `wall_time_ms` | the goal's wall time, without the time spent in a handoff | a task |
| `discovery_bytes` | the stdout bytes of the discovery call | a task |
| `detail` | how the goal was met, or why it failed | a task |
| `skipped` | always `false` | a task |
| `final_state` | the state the goal ended in, with its fields | a task |
| `transitions` | the path the goal took: one step for each call, and one for the step limit | a task |
| `from`, `to`, `code`, `action`, `by_table` | a step: the states before and after, the answer's code (or a step code of H2's own), its `next.action`, and whether a row of the table chose it | each step of `transitions` |
| `child_exit_code` | the exit status of the child a stop ended | a task of a stop that ended a child |
| `refused_releases` | the releases Heimdall refused during the goal | a task |
| `outcome_unknown` | the releases answered `OUTCOME_UNKNOWN` during the goal | a task |
| `unanswered` | the releases of the goal that were started and brought no answer | a task |
| `not_sent` | the releases of the goal that were never sent | a task |
| `still_unknown` | the observations of the goal that did not say what became of an uncertain release | a task |
| `not_listed` | the bindings the goal found missing from the complete list of bindings | a task |
| `requests_outcome_unknown` | the requests of the goal answered `OUTCOME_UNKNOWN` that were left uncertain: their operation was unfinished at the step limit, or the answer ended the goal | a task |
| `requests_unanswered` | the requests of the goal that were started and brought no answer | a task |
| `requests_not_sent` | the requests of the goal that were never sent | a task |
| `requests_still_unknown` | the answers of the goal that did not say what became of a request whose operation it left open (see "Requests answered with their operation left open"), and each later observation that settled nothing | a task |
| `attempts` | every attempt about the binding or the request, in order: the stop goals', then the close's | an entry of `release_attempts` or `request_attempts` |
| `call` | `access ensure` or `run` | an entry of `request_attempts`; an entry of a task's `requests_*` list |
| `profile`, `work_id` | what the request asked for | the same |
| `uncertain` | whether H2 still does not know what became of the request | an entry of `request_attempts` |
| `by` | who made the call: `stop` or `close` for a release; the goal (`access`, `run`, `stop`) or `close` for a request | an attempt. Not in a task's lists |
| `outcome` | what the call came to. Release: `released`, `refused`, `outcome_unknown`, `unanswered`, `not_sent`, `still_unknown`, `not_run`, `not_listed`. Request: `outcome_unknown`, `unanswered`, `not_sent`, `binding_found`, `not_run`, `still_unknown` | an attempt. Not in a task's lists: the list names it |
| `binding_id` | the binding the release was about | an entry of a task's six release lists |
| `request_id` | the request's ID. For a release it is `null`: today's `access release` takes none | an entry of a task's `requests_*` list; a release attempt while it is `outcome_unknown`, `unanswered` or `still_unknown` |
| `code`, `exit_code` | the answer's code and the exit status of its process. For an observed operation, the code is the operation's own once its state says it is over. After a call with no answer, `code` is that of the first complete line it printed, or `null`, and `exit_code` is `null` when the call was never started or H2 ended it | an attempt |
| `operation_id` | the operation the answer or the request named, to observe later | a release attempt while it is uncertain; a request attempt where an operation is known |
| `observed` | an observation: `operation` or `bindings` | an attempt that is an observation |
| `state` | the binding's state in the list, or `(not listed)` | a release attempt that read the list of bindings |
| `listed` | the bindings the list names for the request's work in the state `active` | a request attempt that read the list |
| `candidates` | those of `listed` that pass every check of `ATTRIBUTION` and that H2 was never given | a request attempt that read the list |
| `bindings` | the bindings this attempt gave H2 to hold: the one the request named before it stopped, or the one an observation showed | a request attempt that gave H2 a binding |
| `inconsistent` | `true`: the exit class does not fit the answer | an attempt in the wrong exit class |
| `fault` | why the call brought no answer: `timed_out`, `unreadable` or `not_started` | an attempt after a call with no answer |
| `detail` | with `inconsistent`, the mismatch named as a probable product defect; with `fault`, what went wrong | an attempt with either |

A binding in one of a task's first five release lists is still held. A binding in
`not_listed` is not.

Before it exits, H2 releases whatever the goals left held and ends a child that is
still running. A binding the close found `not_listed` is in neither of `close`'s
lists: it is not held, and it was not observed to be released. `release_attempts`
names it.

The close is always a stop of its own, whatever state the goals left, and every call
it makes is an attempt of its own, recorded with `by` `close`. It is made in rounds
that are each bounded by the step limit.

- It asks about every held binding once, whatever an earlier stop was answered. A
  binding a stop goal was refused is asked for once more.
- It follows the same rules as a stop goal: a binding it does not release is recorded
  and set aside, and the rest are still released.
- It observes a release an earlier stop left uncertain, and does not send it again.
- It does not observe a release that it was itself answered uncertainly.
- It observes each remembered request first, once, and does not send it again.
  `released` also names a binding such an observation showed and the close then
  released.
- Every call it makes about a binding is an attempt, a call with no answer included.
  So a failure about one binding never ends it while another binding is still to be
  asked about.

`release_attempts`, for a binding refused twice:

```json
{"<binding>": {"held": true, "attempts": [
  {"by": "stop", "outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4},
  {"by": "close", "outcome": "refused", "code": "CAPABILITY_UNAVAILABLE", "exit_code": 4}]}}
```

`request_attempts`, for a request that ran past its time limit after naming its
operation, and whose operation the close then found to have made a binding:

```json
{"<request-id>": {"call": "access ensure", "profile": "<profile>", "work_id": "<work-id>",
  "uncertain": false, "attempts": [
  {"by": "access", "outcome": "unanswered", "code": "ACCEPTED", "exit_code": null,
   "fault": "timed_out", "detail": "a CLI call ran past its time limit",
   "operation_id": "<operation>"},
  {"by": "close", "outcome": "binding_found", "code": "ACCESS_READY", "exit_code": 0,
   "observed": "operation", "operation_id": "<operation>", "bindings": ["<binding>"]}]}}
```

A request observed through the list, where two bindings could be its own:

```json
{"by": "close", "outcome": "still_unknown", "code": "OK", "exit_code": 0,
 "observed": "bindings", "listed": ["<binding-a>", "<binding-b>"],
 "candidates": ["<binding-a>", "<binding-b>"]}
```

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
- Invalid retries count answers with which Heimdall said the request was wrong or
  wrongly repeated.

The process exits 0 when every goal was met, `release_attempts` and
`request_attempts` are empty, nothing is left held, and no request or release is still
uncertain (`exit_status` in `harness.py`). It exits 1 otherwise: a release that was
refused, uncertain, unanswered or not sent fails the run, whatever a later attempt made
of it. That includes a binding later found `not_listed`. A request whose outcome was
ever unknown, or that was never sent, fails the run too, whatever an observation then
showed. And whatever the goals' own results, the run exits 1 while anything is still
uncertain.

## Held

- **The call set.** It is to come from the installed binary's
  `schema show primitives`. Today's build does not serve that, so `load_call_set`
  returns the one local table in `harness.py`. That function is the only place that
  changes when it is served. Held for U4b.
- **Native Windows.** The launch environment was verified natively (W4.1). The `run`
  goal reads the Windows `spawned` record and accepts the in-box OpenSSH client as its
  child (W7). That path is covered by the stub here and by A32's task 5 in
  `tests/e2e/harness_m07.rs`, which runs on Windows only on the native runner.
- **Provider waits, `APPROVAL_REQUIRED` and `OUTCOME_UNKNOWN`.** These rows are
  covered by the stub tests only: no fixture of the real-binary run produces them.
- **Every answer about a release other than `OK`.** A refused release, one in the
  wrong exit class, an uncertain one, one with no answer, and each result of
  observing it are covered by the stub tests only. That includes an operation view
  that contradicts its envelope. No real-binary run produces any of these answers
  today.
- **Every request whose outcome is unknown.** A request that ran past its time limit,
  one whose answer could not be read, one that was never started, one answered
  `OUTCOME_UNKNOWN`, one whose goal ended with its operation open, and each result of
  observing one are covered by the stub tests only. No real-binary run produces any
  of these today.
- **Observing a request by its request ID.** Today's CLI has no such call, so a
  request that named no operation is observed through `inspect bindings`, tied to the
  request by its work, its profile and a creation time later than its sending. That
  list cannot say whether the request ran, and has no field that names the caller. If
  the contract gains such a call, H2 uses it there.
- **Two requests the list cannot tell apart.** Two remembered requests of one work
  and profile whose bindings were both made after the newer one was sent: the list
  names two candidates for the newer, and H2 releases neither. Only a field that names
  the request (U0-Q7) can settle that.
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
  observed to have succeeded (the binding is released), to have succeeded in the
  wrong exit class (the binding is released, and the request stays unknown), to have
  failed with effect `none` (nothing to release) and to be still unfinished
  (`still_unknown`); one that stays without a word, or prints no envelope, observed by
  the list of bindings; a binding H2 already held for that work, which is no
  evidence; a launch whose run record was written before the time limit, and one that
  left none; a request that was never started (`not_sent`); that no such request is
  ever sent again; and the exit status of the run;
- the list of bindings, read for a request: a binding of the same work with another
  profile, one made before the request was sent, and one with no creation time are
  left alone; two that can be the request's are both left alone; one in the wrong
  exit class is released, and the request stays unknown; every check of
  `ATTRIBUTION`, and the reading of a creation time;
- requests answered with their operation left open: `OUTCOME_UNKNOWN` with the
  operation unfinished at the step limit, and `ACCEPTED` whose wait runs past its
  time limit or comes back unreadable; each observed later to have made a binding
  (released by the stop or the close) or still unfinished (`still_unknown`), and the
  exit status of the run;
- W7: `observing` and `pending_approval` at the step limit (every wait answered by
  Heimdall's own timeout), and a wait refused with `SERVICE_UNAVAILABLE`, in either
  state; `OUTCOME_UNKNOWN` whose `next` names no operation, observed later through the
  list or by the envelope's own operation; a wait with no answer while reconciling or
  pending approval; an in-goal wait in the wrong exit class, with and without a
  binding; an observed operation whose own code is `OUTCOME_UNKNOWN`; an approval
  handoff the person abandons. Each is remembered and observed later;
- W7: `expect_refusal: OUTCOME_UNKNOWN` with effect `none` is never met, and the run
  exits 1 while a request or a release is still uncertain;
- W7: two requests of one work and profile observed through the list in one read,
  each binding credited to one request at most (both made one; only the newer made
  one), and requests that named an operation observed first;
- W7: the Windows launch sequence (`launching`, `spawned`) and the Unix one, each
  refused on the other platform, and the in-box OpenSSH client as the only child
  outside the scratch root;
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

Five tests run H2 as a whole process against the stub. On POSIX they call `main`, with
the stub started through its interpreter line. On Windows they call `run`, the internal
entry that `main` calls once it has parsed its arguments, with the stub started through
the interpreter (`[sys.executable, "-IB", stub]`): the same goals, exit code and summary.
So the exit-code paths are checked on Windows through `run`. One more test compares
`main` and `run` on POSIX. The other tests start the stub through the Python
interpreter.

`tests/e2e/harness_m07.rs` runs H1 and H2 against the real binary.
