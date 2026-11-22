"""JSON-lines driver for the Rust real-binary tests. Never starts a process."""

import json
from pathlib import Path
import runpy
import sys
import traceback


wrapper = runpy.run_path(str(Path(__file__).with_name("reference_wrapper.py")))
Client = wrapper["Client"]
Subscription = wrapper["Subscription"]
Refused = wrapper["Refused"]


class JourneyClient(Client):
    """Record actual sent request frames, including test-only raw probes."""

    def __init__(self, *args, major=None, **kwargs):
        self.major = major
        self.sent = []
        super().__init__(*args, **kwargs)

    def _write(self, message):
        if message["type"] == "hello" and self.major is not None:
            message = {**message, "schema_version": self.major}
        super()._write(message)
        if message["type"] in ("request", "subscribe"):
            self.sent.append(message)


class Journey:
    def __init__(self, endpoint, environment):
        # U3/U4b: verified-hello discovery is held. Both values come from the harness.
        self.endpoint = endpoint
        self.environment = environment
        self.stream = None
        self.stream_client = None
        self.applied = []

    def connect(self, **options):
        return JourneyClient(self.endpoint, self.environment, timeout=6, **options)

    def hello(self, **options):
        try:
            with self.connect(**options) as client:
                return {"capabilities": sorted(client.capabilities)}
        except Refused as refusal:
            return {"refusal": refusal.envelope}

    def request(self, kind, fields):
        with self.connect() as client:
            result = client.request(kind, **fields)
            return {"result": result, "requests_sent": len(client.sent)}

    def attend(self):
        # Only this denial probe sends Attend. The wrapper allowlist never sends it.
        with self.connect() as client:
            before = client.request("inspect", subject="bindings")
            denied = client._result(client._exchange("attend"))
            after = client.request("inspect", subject="bindings")
            return {"before": before, "denied": denied, "after": after}

    def subscribe(self, filter=None):
        if self.stream is None:
            def connect():
                self.stream_client = self.connect()
                return self.stream_client

            self.stream = Subscription(
                connect,
                lambda snapshot: self.applied.append({"snapshot": snapshot["cursor"]}),
                lambda event: self.applied.append({"event": event}),
                lambda cursor: self.applied.append({"checkpoint": cursor}),
                filter=filter,
            )
        self.applied.clear()
        head = self.stream.start()
        return {**self.stream_state(), "head": head, "sent": self.stream_client.sent}

    def stream_state(self):
        return {"cursor": self.stream.cursor, "ending": self.stream.ending, "applied": self.applied}

    def step(self):
        self.applied.clear()
        continued = self.stream.step()
        return {**self.stream_state(), "continued": continued}

    def stop_stream(self):
        self.applied.clear()
        self.stream.stop()
        return self.stream_state()

    def backpressure(self, operation_id):
        # The wrapper normally serializes requests. Exercise its response reader on
        # the real 17th in-flight refusal by deliberately pipelining 17 held reads.
        with self.connect() as client:
            wait = wrapper["REQUESTS"]["wait"]
            for seq in range(1, 18):
                client._write({
                    "type": "request", "seq": seq, "request": {
                        **wait, "operation_id": operation_id, "wait_ms": 2500,
                    },
                })
            first = client._read()
            refusal = client._result(first)
            assert first["in_reply_to"] == 17 and refusal["code"] == "BACKPRESSURE", (
                "the 17th request was not refused while the first 16 were held"
            )
            remaining = {}
            for _ in range(16):
                response = client._read()
                remaining[response["in_reply_to"]] = client._result(response)["code"]
            return {
                "refusal": refusal, "remaining": remaining, "requests_sent": len(client.sent),
                "defaults": wrapper["code_defaults"](refusal)._asdict(),
            }

    def close(self):
        if self.stream is not None:
            self.stream.stop()


COMMANDS = {
    "hello": Journey.hello,
    "request": Journey.request,
    "attend": Journey.attend,
    "subscribe": Journey.subscribe,
    "step": Journey.step,
    "stop_stream": Journey.stop_stream,
    "backpressure": Journey.backpressure,
}


def main():
    endpoint, environment = sys.argv[1:]
    journey = Journey(endpoint, environment)
    try:
        for line in sys.stdin:
            message = json.loads(line)
            command = COMMANDS[message["command"]]
            try:
                result = command(journey, **message.get("args", {}))
            except Exception as error:
                frame = traceback.extract_tb(error.__traceback__)[-1]
                result = {"driver_error": f"{type(error).__name__} at "
                          f"{Path(frame.filename).name}:{frame.lineno}"}
                print(json.dumps(result), flush=True)
                raise SystemExit(1) from None
            print(json.dumps(result, separators=(",", ":")), flush=True)
    finally:
        journey.close()


if __name__ == "__main__":
    main()
