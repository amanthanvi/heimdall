# Heimdall reference wrapper

Python 3.9+, standard library only. Give the caller's control socket and its
expected environment ID explicitly. See the [local protocol][protocol].

From the repository root, inspect the destination catalog with a running runtime:

```sh
python3 -I - /path/to/control.sock expected-environment-id <<'PY'
import runpy
import sys

wrapper = runpy.run_path("examples/reference-wrapper/reference_wrapper.py")
with wrapper["Client"](sys.argv[1], sys.argv[2]) as client:
    result = client.request("inspect", subject="destinations")
    outcome = wrapper["code_defaults"](result)
    if outcome.success:
        print(result["data"]["items"])
    raise SystemExit(outcome.exit_code)
PY
```

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
`False` or you stop. After an ending, call `start()` again to resume from
`subscription.cursor` with the same filter. Call `stop()` in a `finally`
block when leaving a stream early. Application callbacks should support replay
if saving a checkpoint fails. The sample keeps seen event IDs in memory until
the next snapshot. A long-running consumer should coordinate deduplication and
checkpoint storage with its own application state.

Run the fake-server suite:

```sh
python3 -I -B -m unittest discover -s examples/reference-wrapper/tests
```

Run the same suite and the real-binary smoke test with an existing debug build:

```sh
HEIMDALL_WRAPPER_SMOKE_BIN="$PWD/target/debug/heimdall" \
  python3 -I -B -m unittest discover -s examples/reference-wrapper/tests
```

The smoke test starts its own scratch runtime. Supply a debug executable with
the test SSH-home redirect enabled.

[protocol]: ../../docs/api/local-protocol.md
