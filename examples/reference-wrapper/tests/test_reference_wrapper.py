from __future__ import annotations

from contextlib import contextmanager
from functools import partial
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest

# Isolated mode removes the example directory from the default import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reference_wrapper import (  # noqa: E402
    CAPABILITIES, CONTROL_LIMIT, EPOCH_CAPABILITY, HELLO_LIMIT, MUTATING, Client, ProtocolError,
    Refused, Subscription, code_defaults, open_unix,
)


ENVIRONMENT = "fixture-environment"
DATA = {"environment_id": ENVIRONMENT, "authority_generation": 0}


def receive(conn):
    def read(size):
        data = bytearray()
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise EOFError("client closed mid-frame")
            data.extend(chunk)
        return data

    size, = struct.unpack(">I", read(4))
    return json.loads(read(size))


def send(conn, message):
    body = json.dumps(message).encode("utf-8")
    conn.sendall(struct.pack(">I", len(body)) + body)


def hello(conn, **overrides):
    assert receive(conn) == {
        "type": "hello", "protocol": 1, "schema_version": "1",
        "client": {"name": "reference-wrapper", "version": "0.1"},
        "capabilities": sorted(CAPABILITIES), "required": [], "interaction": "non_interactive",
    }
    reply = {
        "type": "hello", "protocol": 1, "schema_version": "1",
        "environment_id": ENVIRONMENT, "capabilities": list(CAPABILITIES),
        "new_field": True,
    }
    send(conn, {**reply, **overrides})


def respond(conn, request, *, code="OK", **fields):
    send(conn, {
        "type": "response", "in_reply_to": request["seq"], "future_field": {},
        "envelope": {"schema_version": "1", "code": code, "state": "succeeded", **fields},
    })


def head(conn, message, cursor, **fields):
    send(conn, {
        "type": "subscribed", "in_reply_to": message["seq"], "subscription": 1,
        "cursor": cursor, **fields,
    })


def event(ident, cursor, kind="operation_state_changed", **fields):
    return {"event_id": ident, "cursor": cursor, "type": kind, "schema_version": "1", **fields}


def send_event(conn, item):
    send(conn, {"type": "event", "subscription": 1, "event": item})


def closed(conn):
    try:
        assert conn.recv(1) == b"", "client sent data after a refusal or stop"
    except ConnectionResetError:
        pass  # The client may drop unread frames.


@contextmanager
def listener(mode=0o600):
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="hm-wrap-") as tmp:
        endpoint = Path(tmp) / "control.sock"
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(2)
            sock.bind(os.fspath(endpoint))
            endpoint.chmod(mode)
            sock.listen()
            yield endpoint, sock


@contextmanager
def server(*scripts):
    with listener() as (endpoint, sock):
        errors = []

        def run():
            try:
                for script in scripts:
                    conn, _ = sock.accept()
                    with conn:
                        conn.settimeout(2)
                        script(conn)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        try:
            yield endpoint
        finally:
            thread.join()
        if errors:
            raise errors[0]


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "requires Darwin or Linux Unix sockets")
class WrapperTests(unittest.TestCase):
    def test_oversized_headers_close_without_waiting_for_body(self):
        for limit in (HELLO_LIMIT, CONTROL_LIMIT):
            with self.subTest(limit=limit):
                def oversized(conn):
                    if limit == HELLO_LIMIT:
                        receive(conn)
                    else:
                        hello(conn)
                        receive(conn)
                    conn.sendall(struct.pack(">I", limit + 1))
                    closed(conn)  # Send only the header and wait for EOF.

                with server(oversized) as endpoint:
                    with self.assertRaisesRegex(ProtocolError, f"limit {limit} bytes"):
                        with Client(endpoint, ENVIRONMENT, timeout=1) as client:
                            client.request("inspect", subject="destinations")

    def test_reject_and_unsupported_hello_major(self):
        def reject(conn):
            receive(conn)
            send(conn, {"type": "reject", "schema_version": "1", "code": "SCHEMA_UNSUPPORTED"})
            closed(conn)

        with server(reject) as endpoint:
            with self.assertRaisesRegex(Refused, "hello refused: SCHEMA_UNSUPPORTED"):
                Client(endpoint, ENVIRONMENT)

        def wrong_major(conn):
            hello(conn, schema_version="2")
            closed(conn)

        with server(wrong_major) as endpoint:
            with self.assertRaisesRegex(ProtocolError, "unsupported schema major"):
                Client(endpoint, ENVIRONMENT)

    def test_reader_rules_and_sequence_validation(self):
        def script(conn):
            hello(conn)
            request = receive(conn)
            self.assertEqual(request, {
                "seq": 1, "type": "request", "request": {"op": "inspect", "subject": "destinations"},
            })
            respond(conn, request, code="FUTURE_CODE", extra={"skipped": 1})
            request = receive(conn)
            respond(conn, request, code="OUTCOME_UNKNOWN", data={"error": {"reason": "future_reason"}})
            request = receive(conn)
            respond(conn, {"seq": request["seq"] + 1})
            closed(conn)

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            self.assertEqual(client.capabilities, frozenset(CAPABILITIES))
            unknown = code_defaults(client.request("inspect", subject="destinations"))
            self.assertEqual(tuple(unknown), (1, "unknown", False, "report", False))
            reason = code_defaults(client.request("inspect", subject="destinations"))
            self.assertEqual(tuple(reason), (7, "unknown", False, "reconcile", False))
            with self.assertRaisesRegex(ProtocolError, "sequence mismatch"):
                client.request("inspect", subject="destinations")

    def test_rejects_unsupported_response_major(self):
        def script(conn):
            hello(conn)
            respond(conn, receive(conn), schema_version="2")
            closed(conn)

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            with self.assertRaisesRegex(ProtocolError, "unsupported schema major"):
                client.request("inspect", subject="capabilities")

    def test_rejects_malformed_success_payload(self):
        for fields, error in [
            ({}, r"data must be an object"),
            ({"data": []}, r"data must be an object"),
            ({"data": DATA}, r"data\.items must be an array"),
            ({"data": {"items": {}}}, r"data\.items must be an array"),
        ]:
            with self.subTest(fields=fields):
                def script(conn):
                    hello(conn)
                    respond(conn, receive(conn), **fields)
                    closed(conn)

                with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
                    with self.assertRaisesRegex(ProtocolError, error):
                        client.request("inspect", subject="destinations")

    def test_launch_failure_exit_class_uses_the_reason(self):
        for error, expected in [({"reason": "not_executable"}, 126),
                                ({"reason": "other"}, 127), ({}, 127)]:
            with self.subTest(error=error):
                result = code_defaults({"code": "LAUNCH_FAILED", "data": {"error": error}})
                self.assertEqual(tuple(result), (expected, "none", False, "fix_request", False))

    def test_endpoint_and_peer_checks_run_before_requests(self):
        with listener() as (endpoint, sock):
            endpoint.parent.chmod(0o750)
            try:
                with self.assertRaisesRegex(ProtocolError, "untrusted endpoint directory"):
                    Client(endpoint, ENVIRONMENT)
            finally:
                endpoint.parent.chmod(0o700)
            endpoint.chmod(0o640)
            with self.assertRaisesRegex(ProtocolError, "untrusted endpoint socket"):
                Client(endpoint, ENVIRONMENT)
            endpoint.chmod(0o600)
            alias = endpoint.parent / "alias"
            alias.symlink_to(endpoint)
            with self.assertRaisesRegex(ProtocolError, "untrusted endpoint socket"):
                Client(alias, ENVIRONMENT)
            alias_dir = endpoint.parent / "alias-dir"
            alias_dir.symlink_to(endpoint.parent, target_is_directory=True)
            with self.assertRaisesRegex(ProtocolError, "untrusted endpoint directory"):
                Client(alias_dir / endpoint.name, ENVIRONMENT)
            sock.setblocking(False)
            with self.assertRaises(BlockingIOError):
                sock.accept()

        with server(closed) as endpoint:
            connector = partial(open_unix, peer_uid=lambda _: os.geteuid() + 1)
            with self.assertRaisesRegex(ProtocolError, "Unix peer uid mismatch"):
                Client(endpoint, ENVIRONMENT, connector=connector)

        def other_environment(conn):
            hello(conn, environment_id="other-environment")
            closed(conn)

        with server(other_environment) as endpoint:
            with self.assertRaisesRegex(ProtocolError, "environment ID mismatch"):
                Client(endpoint, ENVIRONMENT)

    def test_request_forms_and_event_page_reader(self):
        cases = [
            ("ensure", {"profile": "p", "work_id": "w", "request_id": "r1"},
             {"op": "ensure", "interaction": "non_interactive"}),
            ("bind", {"binding_id": "b", "request_id": "r2"},
             {"op": "bind", "form": {"form": "materialize"}}),
            ("delegate", {"parent_binding_id": "p", "scope": [], "work_id": "w", "request_id": "r3"},
             {"op": "delegate"}),
            ("show", {"operation_id": "o"}, {"op": "observe", "kind": "operation"}),
            ("wait", {"operation_id": "o", "wait_ms": 50}, {"op": "observe", "kind": "operation"}),
            ("cancel", {"operation_id": "o"}, {"op": "cancel"}),
            ("release", {"binding_id": "b"}, {"op": "release"}),
            ("revoke", {"grant_id": "g", "request_id": "r4"}, {"op": "revoke"}),
            ("events", {"cursor": "before", "limit": 2}, {"op": "observe", "kind": "events"}),
        ]

        def script(conn):
            hello(conn, restore_epoch=5)
            for seq, (kind, sent, wire) in enumerate(cases, 1):
                request = receive(conn)
                frame = {"type": "request", "seq": seq, "request": {**sent, **wire}}
                if kind in MUTATING:
                    # A request that changes something carries the hello's restore epoch.
                    frame["request_epoch"] = 5
                self.assertEqual(request, frame)
                respond(conn, request, data={
                    "cursor": "after", "more": True,
                    "events": [event("known", "a"), event("new", "b", "future_type")],
                })

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            for kind in ("decide", "confirm_time", "attend"):
                with self.assertRaises(KeyError):
                    client.request(kind)
            with self.assertRaises(ValueError):
                client.request("bind", op="decide")
            with self.assertRaises(ValueError):
                client.request("inspect", subject="destinations", page={})
            for kind, fields, _ in cases:
                result = client.request(kind, **fields)
            self.assertEqual(result["data"]["events"], [event("known", "a")])
            self.assertTrue(result["data"]["more"])
            self.assertEqual(result["data"]["cursor"], "after")

    def test_clients_carry_the_epoch_with_a_kept_request_id(self):
        # ADR-0014 H13: a fresh request binds the hello's epoch; a retry of a kept request ID
        # sends the epoch kept with it, never the current one; a read carries none.
        ensure = {"profile": "p", "work_id": "w", "request_id": "r1"}

        def script(conn):
            hello(conn, restore_epoch=7)
            sent = []
            for _ in range(3):
                sent.append(receive(conn))
                respond(conn, sent[-1], data={})
            fresh, kept, read = sent
            self.assertEqual(fresh["request_epoch"], 7)
            self.assertEqual((kept["request"]["request_id"], kept["request_epoch"]), ("r1", 4))
            self.assertNotIn("request_epoch", read)

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            self.assertIn(EPOCH_CAPABILITY, client.capabilities)
            self.assertEqual(client.restore_epoch, 7)
            client.request("ensure", **ensure)
            client.request("ensure", request_epoch=4, **ensure)
            client.request("inspect", subject="bindings")
            with self.assertRaises(ValueError):
                client.request("inspect", subject="bindings", request_epoch=4)

    def test_kept_epoch_against_a_runtime_without_request_epoch_refuses_schema_unsupported(self):
        # The ruling on ASK-H13b: a kept epoch is never sent to a runtime that does not offer
        # request-epoch/1. The answer is SCHEMA_UNSUPPORTED with effect none, nothing is sent,
        # and the session stays usable.
        older = [c for c in CAPABILITIES if c != EPOCH_CAPABILITY]

        def script(conn):
            hello(conn, capabilities=older)
            read = receive(conn)
            self.assertEqual(read["request"]["op"], "inspect", "the kept request was not sent")
            respond(conn, read, data={})

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            refused = client.request("revoke", request_epoch=3, grant_id="g", request_id="r4")
            self.assertEqual(refused["code"], "SCHEMA_UNSUPPORTED")
            self.assertEqual(refused["data"]["error"]["effect_status"], "none")
            self.assertEqual(code_defaults(refused).exit_code, 2)
            self.assertTrue(code_defaults(client.request("inspect", subject="bindings")).success)

    def test_fresh_request_without_kept_epoch_is_sent_without_one(self):
        # The ruling on ASK-H13b: with no kept epoch, the request goes to an older runtime
        # exactly as before, with no request_epoch field.
        older = [c for c in CAPABILITIES if c != EPOCH_CAPABILITY]

        def script(conn):
            hello(conn, capabilities=older)
            request = receive(conn)
            self.assertEqual(request, {"type": "request", "seq": 1, "request": {
                "grant_id": "g", "request_id": "r4", "op": "revoke"}})
            respond(conn, request, data={})

        with server(script) as endpoint, Client(endpoint, ENVIRONMENT) as client:
            self.assertNotIn(EPOCH_CAPABILITY, client.capabilities)
            self.assertEqual(client.restore_epoch, 0)
            client.request("revoke", grant_id="g", request_id="r4")

    def test_request_stale_is_a_conflict_that_asks_for_a_new_request_id(self):
        stale = code_defaults({"code": "REQUEST_STALE"})
        self.assertEqual((stale.exit_code, stale.effect_status, stale.retryable, stale.next_action),
                         (6, "none", False, "new_request_id"))
        self.assertFalse(stale.success)

    def test_gap_freezes_cursor_closes_old_stream_and_resumes_same_filter(self):
        # Every gap ends the stream (ADR-0013 §5.4); lag and trim are told apart by the
        # resync's reason, and nothing after it is applied.
        for reason in ("history_trimmed", "subscriber_lagged"):
            with self.subTest(reason=reason):
                self._gap_ends_the_stream(reason)

    def _gap_ends_the_stream(self, reason):
        applied, persisted = [], []
        operation = {"operation_id": "fixture-operation", "types": ["operation_state_changed"]}

        def first(conn):
            hello(conn)
            message = receive(conn)
            self.assertEqual(message["filter"], operation)
            self.assertNotIn("from_cursor", message)
            head(conn, message, "base", snapshot={"cursor": "base", "data": DATA})
            send_event(conn, event("one", "c1", new_field=True))
            send_event(conn, event("unknown", "c2", "new_event_type"))
            send_event(conn, event("one", "c1"))  # Replay must not rewind the cursor.
            gap = event("gap", "unapplied", "resync_required",
                        payload={"reason": reason, "subscription_ended": True})
            later = event("old", "late")
            frames = [json.dumps({"type": "event", "subscription": 1, "event": e}).encode()
                      for e in (gap, later)]
            conn.sendall(b"".join(struct.pack(">I", len(frame)) + frame for frame in frames))
            closed(conn)

        def resume(conn):
            hello(conn)
            message = receive(conn)
            self.assertEqual(message["filter"], operation)
            self.assertEqual(message["from_cursor"], "c2")
            head(conn, message, "h2", backlog=2)
            send_event(conn, event("two", "c3"))
            send_event(conn, event("three", "c4"))
            closed(conn)

        with server(first, resume) as endpoint:
            stream = Subscription(
                partial(Client, endpoint, ENVIRONMENT), lambda _: applied.append("snapshot"),
                lambda e: applied.append(e["event_id"]), persisted.append, filter=operation,
            )
            self.addCleanup(stream.stop)
            stream.start()
            for _ in range(3):
                self.assertTrue(stream.step())
            self.assertFalse(stream.step())
            self.assertEqual((stream.ending, stream.gap), ("resync_required", reason))
            self.assertEqual(applied, ["snapshot", "one"])
            self.assertEqual(persisted, ["base", "c1", "c2"])
            stream.start()
            self.assertEqual((stream.gap, stream.resync_reason), (None, None))
            self.assertEqual(stream.cursor, "c2")
            self.assertTrue(stream.step())
            self.assertEqual(stream.cursor, "c3")
            self.assertTrue(stream.step())
            self.assertEqual(stream.cursor, "h2")
            stream.stop()
        self.assertEqual(applied, ["snapshot", "one", "two", "three"])
        self.assertEqual(persisted, ["base", "c1", "c2", "c3", "c4", "h2"])

    def test_restart_from_a_snapshot_names_its_reason(self):
        # A cursor the runtime cannot resume (here, below the retained tail) restarts from
        # a whole snapshot whose head says why; the snapshot's cursor is the checkpoint.
        persisted = []

        def script(conn):
            hello(conn)
            message = receive(conn)
            self.assertEqual(message["from_cursor"], "trimmed")
            head(conn, message, "fresh", snapshot={"cursor": "fresh", "data": DATA},
                 resync_reason="history_trimmed")
            closed(conn)

        with server(script) as endpoint:
            stream = Subscription(partial(Client, endpoint, ENVIRONMENT), lambda _: None,
                                  lambda _: None, persisted.append, cursor="trimmed")
            self.addCleanup(stream.stop)
            stream.start()
            self.assertEqual(stream.resync_reason, "history_trimmed")
            self.assertEqual(persisted, ["fresh"])
            stream.stop()

    def test_a_gap_without_a_reason_is_a_protocol_error(self):
        def script(conn):
            hello(conn)
            head(conn, receive(conn), "h", backlog=0)
            send_event(conn, event("gap", "h", "resync_required", payload={}))
            closed(conn)

        with server(script) as endpoint:
            stream = Subscription(partial(Client, endpoint, ENVIRONMENT), lambda _: None,
                                  lambda _: None, lambda _: None, cursor="saved")
            self.addCleanup(stream.stop)
            stream.start()
            with self.assertRaises(ProtocolError):
                stream.step()
            self.assertEqual((stream.ending, stream.cursor), ("read_failed", "h"))

    def test_revocation_disconnect_and_early_stop_freeze_unapplied_head(self):
        for ending in ("revoked", "disconnected", "stopped"):
            with self.subTest(ending=ending):
                def script(conn):
                    hello(conn)
                    message = receive(conn)
                    self.assertEqual(message["from_cursor"], "saved")
                    head(conn, message, "unapplied", backlog=1)
                    if ending == "revoked":
                        send_event(conn, event("end", "later", "client", payload={"kind": "revoked"}))
                    if ending != "disconnected":
                        closed(conn)

                def resume(conn):
                    hello(conn)
                    message = receive(conn)
                    self.assertEqual(message["from_cursor"], "saved")
                    head(conn, message, "new-head")
                    closed(conn)

                with server(script, resume) as endpoint:
                    def unexpected(_):
                        self.fail("unapplied work was applied or persisted")

                    stream = Subscription(partial(Client, endpoint, ENVIRONMENT), unexpected,
                                          unexpected, unexpected, cursor="saved")
                    self.addCleanup(stream.stop)
                    stream.start()
                    if ending == "stopped":
                        stream.stop()
                    else:
                        self.assertFalse(stream.step())
                    self.assertEqual((stream.cursor, stream.ending), ("saved", ending))
                    stream.start()
                    self.assertEqual(stream.cursor, "saved")
                    stream.stop()

    def test_snapshot_apply_failure_leaves_checkpoint_unchanged(self):
        def script(conn):
            hello(conn)
            head(conn, receive(conn), "head", snapshot={"cursor": "head", "data": DATA})
            closed(conn)

        def fail_snapshot(_):
            raise RuntimeError("application failed")

        with server(script) as endpoint:
            persisted = []
            stream = Subscription(partial(Client, endpoint, ENVIRONMENT), fail_snapshot,
                                  lambda _: None, persisted.append, cursor="previous")
            with self.assertRaisesRegex(RuntimeError, "application failed"):
                stream.start()
            self.assertEqual((stream.cursor, persisted), ("previous", []))

    def test_snapshot_data_is_typed_and_sections_are_read_only_when_present(self):
        cases = [
            ({**DATA, "operation": {"operation_id": "op", "state": "running"}}, None),
            ({**DATA, "operations": [], "pending_decisions": [], "boundary_seq": 3}, None),
            ({"operations": []}, "environment_id"),
            ({**DATA, "authority_generation": -1}, "authority_generation"),
            ({**DATA, "operations": {}}, "snapshot operations"),
        ]
        for data, error in cases:
            with self.subTest(data=data):
                def script(conn, data=data):
                    hello(conn)
                    head(conn, receive(conn), "head", snapshot={"cursor": "head", "data": data})
                    closed(conn)

                with server(script) as endpoint:
                    applied, persisted = [], []
                    stream = Subscription(partial(Client, endpoint, ENVIRONMENT), applied.append,
                                          lambda _: None, persisted.append)
                    if error is None:
                        stream.start()
                        stream.stop()
                        self.assertEqual((len(applied), persisted), (1, ["head"]))
                    else:
                        with self.assertRaisesRegex(ProtocolError, error):
                            stream.start()
                        self.assertEqual((applied, persisted, stream.ending),
                                         ([], [], "start_failed"))

    def test_snapshot_over_a_cap_refuses_the_subscribe_with_no_head(self):
        refusal = {
            "schema_version": "1", "code": "USAGE_ERROR", "state": "failed",
            "data": {"error": {
                "code": "USAGE_ERROR", "effect_status": "none", "retryable": False,
                "next": {"action": "narrow_request"}, "message": "over its cap",
                "reason": "response_too_large", "section": "operations",
                "narrow": "filter.operation_id",
            }},
        }

        def script(conn):
            hello(conn)
            message = receive(conn)
            send(conn, {"type": "response", "in_reply_to": message["seq"], "envelope": refusal})
            closed(conn)

        with server(script) as endpoint:
            applied, persisted = [], []
            stream = Subscription(partial(Client, endpoint, ENVIRONMENT), applied.append,
                                  applied.append, persisted.append, cursor="saved")
            with self.assertRaisesRegex(Refused, "subscribe refused: USAGE_ERROR") as caught:
                stream.start()
            error = caught.exception.envelope["data"]["error"]
            self.assertEqual((error["section"], error["narrow"]),
                             ("operations", "filter.operation_id"))
            # The refusal names its own next action; the code's default is fix_request.
            self.assertEqual(error["next"]["action"], "narrow_request")
            self.assertEqual(code_defaults(caught.exception.envelope).exit_code, 2)
            self.assertEqual((applied, persisted, stream.cursor, stream.ending),
                             ([], [], "saved", "start_failed"))


if __name__ == "__main__":
    unittest.main()
