# H2 goal-directed harness

H2 is a planner. You give it a goal, it holds one typed state, and it reaches the
goal through Heimdall's public CLI. The goal names the first call. Every step after
that is one row of a transition table, chosen from the current state and the last
answer's `code` and `next.action`. It checks every answer against the exit class of
its process. It never reads an answer's message text.

It follows the contract's rules where a shortcut would be easier. One of them: a
request whose outcome is uncertain is never sent again, and a release is no exception.
One new release can follow an uncertain one in one case only: the uncertain answer
named an operation, and that operation ended saying the release did not happen.

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
  - A release answered `OUTCOME_UNKNOWN` is recorded apart from a refusal, and the
    stop goes on with the other bindings. The stop then fails. A later stop observes
    that release before it sends anything, and in most cases sends nothing. See
    "Uncertain releases" below.
  - A stop that fails does not end its child. A stop ends its child only when it
    reaches `stopped`. A child that is still running when H2 closes is ended then.
  - With nothing held, a stop fails without a call.

## States and transitions

`start`, `discovered`, `observing(operation_id)`, `reconciling(operation_id)`,
`pending_approval(decision_ref, operation_id)`, `pending_provider(provider, kind)`,
`ready(binding_id)`, `running(pid, binding_id)`, `releasing(binding_id)`,
`observing_release(binding_id, operation_id)`, `inspecting_release(binding_id)`,
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
- `failed` also carries `operation_id` when its code is `OUTCOME_UNKNOWN` and an
  operation is known. When a stop ends with a binding it did not release, `failed`
  names the first one: its `binding_id`, the `exit_code` of the answer about it, and
  the code. The code is the refusal's own, or `OUTCOME_UNKNOWN` for a release that is
  still uncertain.
- `inconsistent` ends a goal: an answer's process ended in another exit class than
  the one documented for its code. It carries that code and the exit status. An
  answer about a release never ends there. See "Refused releases".
- `unresolved` ends a goal: the operation of an uncertain outcome was still unfinished
  at the step limit. It carries the code `OUTCOME_UNKNOWN` and that operation's ID.

Beside the state, H2 keeps the list of bindings it holds: every binding it was given
and has not released. A binding leaves the list in three ways only:

- its release is answered `OK` with exit 0;
- an observation says that its uncertain release happened;
- after an uncertain release that named no operation, the complete list of
  `inspect bindings` does not name it. It is then `not_listed`: not held, and not
  recorded as released.

A binding Heimdall refused to release stays on the list. So does one whose release
is still uncertain. A binding joins the list when:

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
refusal: `OUTCOME_UNKNOWN`. See "Uncertain releases".

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

A code `EXIT_CLASSES` lacks has no documented class to check, so it is recorded with
the exit status it came with.

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
| ended with its own code `OK`, `next.action` `none`, exit 0 | `released` | takes the binding off its list and sends nothing |
| ended with another code, `next.action` `none` and `effect_status` `none`, in that code's exit class | `not_run` | sends one new release of that binding |
| anything else | `still_unknown` | keeps the binding held and reports it; sends nothing |

"Anything else" covers an operation still unfinished when the wait ran out, one whose
own code is `OUTCOME_UNKNOWN`, one that ended with an effect other than `none`, a
wait that was itself refused, and any answer in the wrong exit class.

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

**The reading of `inspect bindings` comes from the contract's binding list, not from
an observed run.** H2 has the list's word for the binding's state. It did not see
the release run, and no real-binary run answers a release uncertainly today. The
stub tests alone cover this reading.

**`inspect bindings` is the one call H2 uses that the skill does not list yet**
(`skills/heimdall/SKILL.md`). It is a read-only call of the CLI contract. The skill
gains it later.

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
still releases it.

An answer about a release is the exception: it never ends in `inconsistent`.
`RELEASE_SAYS` reads its exit class together with its code. A release that fails the
check is recorded like a refusal, and an observation that fails it leaves the release
uncertain. Each carries `"inconsistent": true`, and the stop goes on.

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
`close` and `release_attempts`. A record has the fields H1's records have (`task`, `success`, `calls`,
`round_trips`, `human_handoffs`, `invalid_retries`, `wall_time_ms`,
`discovery_bytes`, `detail`, `skipped`) and adds `goal`, `final_state`,
`transitions` (the path it took), `held` (the bindings H2 still holds after the
goal), and four lists of what the goal's calls about releases came to:

| List | Holds |
| --- | --- |
| `refused_releases` | the releases Heimdall refused during the goal |
| `outcome_unknown` | the releases answered `OUTCOME_UNKNOWN` during the goal |
| `still_unknown` | the observations of the goal that did not say what became of an uncertain release |
| `not_listed` | the bindings the goal found missing from the complete list of bindings |

A binding in one of the first three is still held. A binding in `not_listed` is not.

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
- A round that makes no attempt ends it.

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
| `outcome` | `released`, `refused`, `outcome_unknown` (the release was answered `OUTCOME_UNKNOWN`), `still_unknown` (an observation did not say what became of it), `not_run` (its operation ended and said the release did not happen) or `not_listed` (the complete list of bindings does not name the binding) |
| `code`, `exit_code` | the answer's code and the exit status of its process. For an observed operation, the code is the operation's own once it has one |
| `observed` | present on an observation: `operation` or `bindings` |
| `state` | present on a `bindings` observation that could be read: the binding's state, or `(not listed)` |
| `request_id`, `operation_id` | present while the outcome is `outcome_unknown` or `still_unknown`. See "Uncertain releases" |
| `inconsistent`, `detail` | present when the exit class does not fit the code: `true`, and the mismatch named as a probable product defect |

An entry in one of a goal's four lists is the same attempt with its `binding_id`, and
without `by` and `outcome`.

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

The process exits 0 when every goal was met, `release_attempts` is empty and nothing
is left held. It exits 1 otherwise: a release that was refused or uncertain fails the
run, whatever a later attempt made of it. That includes a binding later found
`not_listed`.

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
  wrong exit class, an uncertain one, and each result of observing it are covered by
  the stub tests only. No real-binary run produces any of these answers today.
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
  `inconsistent`, and the rest are still released;
- uncertain releases: the record; each result of observing one, in a later stop and
  in the close. By its operation: released, not released (one new release, and only
  then), and still unfinished. By the list of bindings: `active` (no new release),
  not listed (`not_listed`, never `released`), and `released`. Also that the release
  is never sent again while its outcome is unknown; that a close alone ends with the
  binding held; and the summary by binding with the exit status of the run;
- exit classes: the stub ends an answer in the wrong class for each kind of call,
  and the goal fails;
- an uncertain outcome: its operation is observed until it ends, the request is
  never repeated however many observations that takes, and every report that can
  name the operation does.

Set `HEIMDALL_HARNESS_SMOKE_BIN` to the absolute path of the built debug binary to add
the discovery smoke. It checks the table's codes and exit classes against the real
code table and starts no runtime.

`tests/e2e/harness_m07.rs` runs H1 and H2 against the real binary.
