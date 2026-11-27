# Heimdall reference wrapper

Python 3.9+, standard library only. Give the control endpoint and its expected
environment ID explicitly. The endpoint is the control socket's path on Unix
and the control pipe's name on Windows. See the [local protocol][protocol].

From the repository root, inspect the destination catalog with a running runtime:

```sh
python3 -I - /path/to/control.sock expected-environment-id <<'PY'
import sys

sys.path.insert(0, "examples/reference-wrapper")  # Isolated mode leaves it off the import path.
from reference_wrapper import Client, code_defaults

with Client(sys.argv[1], sys.argv[2]) as client:
    result = client.request("inspect", subject="destinations")
    outcome = code_defaults(result)
    if outcome.success:
        print(result["data"]["items"])
    raise SystemExit(outcome.exit_code)
PY
```

## Windows

On Windows, `Client` connects with `open_pipe`, and the endpoint is a pipe name
of the form `\\.\pipe\heimdall-<token>-control`. Pass `connector=open_unix` or
`connector=open_pipe` to choose the transport yourself. The pipe transport is
`reference_wrapper_windows.py` (standard library and `ctypes`). Keep it beside
`reference_wrapper.py`. The wrapper loads it from its own directory, so it is
found under `python3 -I` and `runpy.run_path` too.

`open_pipe` raises `ProtocolError` and writes nothing unless every check passes,
in this order:

1. after `GetFullPathNameW`, the path is in the `\\.\pipe\` or `\\?\pipe\`
   namespace, and its single name component starts with `heimdall-` and ends
   in `-control`;
2. `CreateFileW` opens it with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`;
3. the handle is a pipe;
4. the pipe's owner SID equals your user SID;
5. the process serving the pipe runs as your user SID.

The wrapper opens the control pipe only. It refuses the runtime's signing and
issuer pipes by name (`heimdall-<token>-signing`, `heimdall-<token>-issuer`)
before it opens anything.

SIDs are compared with `EqualSid`. The wrapper has no setting for another
expected owner SID, so it refuses a pipe that an elevated runtime created with
a different default owner. Reads and writes are overlapped. At the `Client`
timeout the transfer is cancelled with `CancelIoEx`, and the connection ends
with `Disconnected`. A wait cannot be interrupted before its timeout.

## Using the client

`Client.request` returns the server envelope. Classify it with `code_defaults`,
then read the operation state and actual effect from the result as needed.
Successful replies to the wrapper's requests must carry a `data` object.
A successful destinations inspection must carry an array at `data.items`.
The client closes the connection and raises `ProtocolError` if the payload
fails either check.
Use the names in `REQUESTS` and the request fields in the protocol document.
Set `asynchronous=True` when classifying an `ACCEPTED` result requested
asynchronously. `LAUNCH_FAILED` follows the CLI's exit convention of 126 for
`data.error.reason == "not_executable"` and 127 for other launch failures.
If requesting a long wait, pass a `Client` timeout in seconds
longer than the requested `wait_ms` duration.

For a live stream, pass a factory for a fresh authenticated `Client` to
`Subscription` along with callbacks `apply_snapshot(snapshot)`,
`apply_event(event)` and `persist(cursor)`. Initialize with the durable
cursor, if available. Call `start()`, then `step()` until it returns
`False` or you stop. Every gap ends the stream with one `resync_required`
event. `ending` is then `"resync_required"` and `gap` holds the event's
reason: `subscriber_lagged`, `history_trimmed` or `event_too_large`. Nothing
after the gap is applied. A head that restarts from a whole snapshot although
you sent a cursor names why in `resync_reason`. After an ending, call
`start()` again to resume from `subscription.cursor` with the same filter. Call `stop()` in a `finally`
block when leaving a stream early. Application callbacks should support replay
if saving a checkpoint fails. The sample keeps seen event IDs in memory until
the next snapshot. A long-running consumer should coordinate deduplication and
checkpoint storage with its own application state.

## Tests

Run the suite. The fake-server tests need Unix sockets. The pipe checks run
against fakes on every platform, and one test loads the wrapper in a fresh
`python -I` to check that it finds the pipe transport. `test_windows_native.py`
runs on Windows only, against an owner-only pipe that the test process serves
itself:

```sh
python3 -I -B -m unittest discover -s examples/reference-wrapper/tests
```

Run the same suite and the real-binary smoke test with an existing debug build:

```sh
HEIMDALL_WRAPPER_SMOKE_BIN="$PWD/target/debug/heimdall" \
  python3 -I -B -m unittest discover -s examples/reference-wrapper/tests
```

The smoke test starts its own runtime with scratch homes and scratch key stores.
Supply a debug executable with the test SSH-home redirect enabled.

On Windows, from the repository root in PowerShell:

```powershell
$env:HEIMDALL_WRAPPER_SMOKE_BIN = "$PWD\target\debug\heimdall.exe"
py -3 -I -B -m unittest discover -v -s examples\reference-wrapper\tests
```

There the smoke test takes the pipe name from `data.control_endpoint` in
`heimdall --json service status`. It is skipped while the build does not report
that field.

[protocol]: ../../docs/api/local-protocol.md
