"""A synchronous, non-interactive reference consumer of Heimdall's local IPC."""

from __future__ import annotations

import copy
import ctypes
import importlib.util
import json
import os
import socket
import stat
import struct
import sys
from typing import NamedTuple


HELLO_LIMIT = 16 * 1024
CONTROL_LIMIT = 1024 * 1024
PROTOCOL = 1
SCHEMA = "1"
# `request-epoch/1` is offered, never required: a runtime that checks the restore epoch
# negotiates it, and an older one is still served, with no epoch on any request.
EPOCH_CAPABILITY = "request-epoch/1"
CAPABILITIES = ("operations/1", "events/1", "schema-discovery/1", EPOCH_CAPABILITY)
REQUESTS = {
    "inspect": {"op": "inspect"},
    "ensure": {"op": "ensure", "interaction": "non_interactive"},
    "bind": {"op": "bind", "form": {"form": "materialize"}},
    "delegate": {"op": "delegate"},
    "show": {"op": "observe", "kind": "operation"},
    "wait": {"op": "observe", "kind": "operation"},
    "events": {"op": "observe", "kind": "events"},
    "cancel": {"op": "cancel"},
    "release": {"op": "release"},
    "revoke": {"op": "revoke"},
}
# The requests that change something: each carries the restore epoch its request ID was
# minted under. Reads carry none.
MUTATING = frozenset({"ensure", "bind", "delegate", "cancel", "release", "revoke"})
EVENT_TYPES = frozenset({
    "operation_state_changed", "grant_state_changed", "policy_changed",
    "resource_changed", "credential_lifecycle", "decision", "runtime_lifecycle",
    "enrollment", "connection", "session_lock", "activation", "resync_required",
    "client",
})


class CodeDefaults(NamedTuple):
    exit_code: int
    effect_status: str
    retryable: bool
    next_action: str
    success: bool


# Default classes from schemas/public-api/codes.json.
CODE_DEFAULTS = {
    "OK": CodeDefaults(0, "applied", False, "none", True),
    "ACCESS_READY": CodeDefaults(0, "applied", False, "use_binding", True),
    "ACCEPTED": CodeDefaults(0, "none", False, "observe", True),
    "APPROVAL_REQUIRED": CodeDefaults(3, "none", False, "observe", False),
    "INTERACTION_REQUIRED": CodeDefaults(3, "none", False, "interact", False),
    "PROVIDER_LOCKED": CodeDefaults(3, "none", True, "interact", False),
    "CAPABILITY_UNAVAILABLE": CodeDefaults(4, "none", False, "narrow_request", False),
    "POLICY_PAUSED": CodeDefaults(4, "none", False, "owner_decision", False),
    "POLICY_CUTOFF": CodeDefaults(4, "none", False, "owner_decision", False),
    "CREDENTIAL_EXPIRED": CodeDefaults(4, "none", False, "new_work", False),
    "HOST_TRUST_CHANGED": CodeDefaults(4, "none", False, "review_host_trust", False),
    "DELEGATION_EXCEEDS_PARENT": CodeDefaults(4, "none", False, "narrow_request", False),
    "OPERATION_CANCELLED": CodeDefaults(4, "partial", False, "none", False),
    "DESTINATION_UNREACHABLE": CodeDefaults(5, "none", True, "retry_after", False),
    "TIME_UNCERTAIN": CodeDefaults(5, "none", True, "retry_after", False),
    "UNSUPPORTED_CLIENT": CodeDefaults(5, "none", False, "change_client", False),
    "SERVICE_UNAVAILABLE": CodeDefaults(5, "none", True, "retry_after", False),
    "STATE_UNAVAILABLE": CodeDefaults(5, "none", True, "retry_after", False),
    "BACKPRESSURE": CodeDefaults(5, "none", True, "retry_after", False),
    "REQUEST_CONFLICT": CodeDefaults(6, "none", False, "new_request_id", False),
    "CONFIG_CONFLICT": CodeDefaults(6, "none", False, "review_config", False),
    "REQUEST_EXPIRED": CodeDefaults(6, "none", False, "new_request_id", False),
    "RESYNC_REQUIRED": CodeDefaults(6, "none", False, "resync", False),
    "DECISION_STALE": CodeDefaults(6, "none", False, "fix_request", False),
    "REQUEST_STALE": CodeDefaults(6, "none", False, "new_request_id", False),
    "OUTCOME_UNKNOWN": CodeDefaults(7, "unknown", False, "reconcile", False),
    "USAGE_ERROR": CodeDefaults(2, "none", False, "fix_request", False),
    "SCHEMA_UNSUPPORTED": CodeDefaults(2, "none", False, "fix_request", False),
    "NOT_FOUND": CodeDefaults(2, "none", False, "fix_request", False),
    "INTERNAL_ERROR": CodeDefaults(1, "none", False, "report", False),
    "LAUNCH_FAILED": CodeDefaults(127, "none", False, "fix_request", False),
}
UNKNOWN_CODE = CodeDefaults(1, "unknown", False, "report", False)


class ProtocolError(Exception):
    """The endpoint or wire exchange failed a client check."""


class Disconnected(ProtocolError):
    """The transport ended or timed out."""


class Refused(ProtocolError):
    """A hello or subscription was refused with a result envelope."""

    def __init__(self, action, envelope):
        self.envelope = envelope
        code = _string(envelope, "code")
        super().__init__(f"{action} refused: {code if code in CODE_DEFAULTS else 'unknown code'}")


def _object(value, field):
    if not isinstance(value, dict):
        raise ProtocolError(f"{field} must be an object")
    return value


def _string(obj, field):
    value = obj.get(field)
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{field} must be a nonempty string")
    return value


def _uint(value, field):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ProtocolError(f"{field} must be an unsigned 64-bit integer")
    return value


def _check_schema(obj):
    if _string(obj, "schema_version") != SCHEMA:
        raise ProtocolError(f"unsupported schema major (expected {SCHEMA})")


def _envelope(value):
    env = _object(value, "envelope")
    _check_schema(env)
    code = _string(env, "code")
    if CODE_DEFAULTS.get(code, UNKNOWN_CODE).success:
        _object(env.get("data"), "data")
    return env


def code_defaults(envelope, *, asynchronous=False):
    """Classify with CLI exit classes. Read actual effects from the envelope."""
    code = _string(envelope, "code")
    if code == "ACCEPTED" and not asynchronous:
        return CodeDefaults(5, "none", False, "observe", False)
    defaults = CODE_DEFAULTS.get(code, UNKNOWN_CODE)
    if code == "LAUNCH_FAILED":
        data = envelope.get("data")
        error = data.get("error") if isinstance(data, dict) else None
        if isinstance(error, dict) and error.get("reason") == "not_executable":
            return defaults._replace(exit_code=126)
    return defaults


def kept_epoch_unsupported():
    """The local answer to a kept epoch the runtime cannot check: nothing was sent."""
    error = {
        "code": "SCHEMA_UNSUPPORTED", "effect_status": "none", "retryable": False,
        "next": {"action": "fix_request"},
        "message": "this request keeps the restore epoch it was first sent with, and the "
                   "runtime does not offer request-epoch/1, so it could not check it: "
                   "nothing was sent",
    }
    return dict(schema_version=SCHEMA, state="failed", code="SCHEMA_UNSUPPORTED",
                data={"error": error}, warnings=[], next=None)


def _event_type(event):
    _check_schema(_object(event, "event"))
    return _string(event, "type")


def _peer_uid(link):
    if sys.platform == "linux":
        size = struct.calcsize("=iII")
        _, uid, _ = struct.unpack("=iII", link.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size))
        return uid
    if sys.platform == "darwin":
        getpeereid = ctypes.CDLL(None).getpeereid
        getpeereid.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint))
        getpeereid.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if getpeereid(link.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0:
            return uid.value
    raise ProtocolError("Unix peer credentials unavailable")


def open_unix(endpoint, timeout, *, peer_uid=_peer_uid):
    """Verify the two filesystem entries and then the connected Unix peer."""
    path = os.fspath(endpoint)
    if {".", ".."}.intersection(path.split("/")):
        raise ProtocolError("endpoint path must omit dot components")
    uid = os.geteuid()
    for name, check, label in (
        (os.path.dirname(path) or ".", stat.S_ISDIR, "directory"),
        (path, stat.S_ISSOCK, "socket"),
    ):
        info = os.lstat(name)
        if not check(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise ProtocolError(f"untrusted endpoint {label}")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(timeout)
        conn.connect(path)
        if peer_uid(conn) != uid:
            raise ProtocolError("Unix peer uid mismatch")
    except BaseException:
        conn.close()
        raise
    return conn


def _pipe_transport():
    """Load `reference_wrapper_windows` from beside this file.

    Isolated mode (`python3 -I`) and `runpy.run_path` leave this directory off `sys.path`.
    """
    name = "reference_wrapper_windows"
    module = sys.modules.get(name)
    if module is None:
        beside = os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".py")
        spec = importlib.util.spec_from_file_location(name, beside)
        module = sys.modules[name] = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[name]
            raise
    return module


def open_pipe(endpoint, timeout, **options):
    """Open a Windows control pipe after `reference_wrapper_windows` checks it."""
    windows = _pipe_transport()
    try:
        return windows.open_pipe(endpoint, timeout, **options)
    except windows.PipeRefused as error:
        raise ProtocolError(str(error)) from error


def _read_exact(link, size):
    body = bytearray()
    while len(body) < size:
        chunk = link.recv(size - len(body))
        if not chunk:
            raise Disconnected("connection closed during frame")
        body.extend(chunk)
    return body


def _bad_constant(_):
    raise ValueError("non-JSON number")


class Client:
    """One request in flight and one subscription per connection."""

    def __init__(self, endpoint, expected_environment, *, offered=CAPABILITIES, required=(),
                 timeout=35.0, connector=None):
        if not isinstance(expected_environment, str) or not expected_environment:
            raise ValueError("the expected environment ID is required")
        offered, required = frozenset(offered), frozenset(required)
        connector = connector or (open_pipe if sys.platform == "win32" else open_unix)
        self._link = connector(endpoint, min(timeout, 5.0))
        self._limit, self._seq, self._subscription = HELLO_LIMIT, 0, None
        try:
            self._link.settimeout(min(timeout, 5.0))
            self._write({
                "type": "hello", "protocol": PROTOCOL, "schema_version": SCHEMA,
                "client": {"name": "reference-wrapper", "version": "0.1"},
                "capabilities": sorted(offered), "required": sorted(required),
                "interaction": "non_interactive",
            })
            reply = self._read()
            if reply.get("type") == "reject":
                raise Refused("hello", _envelope(reply))
            if reply.get("type") != "hello":
                raise ProtocolError("expected server hello or rejection")
            _check_schema(reply)
            if _uint(reply.get("protocol"), "protocol") != PROTOCOL:
                raise ProtocolError("unsupported protocol version")
            if _string(reply, "environment_id") != expected_environment:
                raise ProtocolError("server environment ID mismatch")
            capabilities = reply.get("capabilities")
            if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
                raise ProtocolError("invalid negotiated capabilities")
            self.capabilities = frozenset(capabilities)
            if not required <= self.capabilities <= offered:
                raise ProtocolError("invalid capability negotiation")
            # The runtime's restore epoch, 0 when the hello omits it.
            epoch = reply.get("restore_epoch", 0)
            self.restore_epoch = 0 if epoch is None else _uint(epoch, "restore_epoch")
            self._limit = CONTROL_LIMIT
            self._link.settimeout(timeout)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self._link.close()

    def _write(self, msg):
        try:
            data = json.dumps(msg, separators=(",", ":"), allow_nan=False).encode("utf-8")
            if len(data) > self._limit:
                raise ProtocolError(f"outgoing frame exceeds {self._limit} bytes")
            self._link.sendall(struct.pack(">I", len(data)) + data)
        except OSError:
            self.close()
            raise Disconnected("connection failed while sending frame") from None
        except ProtocolError:
            self.close()
            raise

    def _read(self):
        try:
            size, = struct.unpack(">I", _read_exact(self._link, 4))
            if not 0 < size <= self._limit:
                raise ProtocolError(f"invalid frame length (limit {self._limit} bytes)")
            message = _object(json.loads(_read_exact(self._link, size).decode("utf-8"),
                                         parse_constant=_bad_constant), "frame")
            if message.get("type") == "goodbye":
                raise Disconnected("server closed the connection (goodbye)")
            return message
        except OSError:
            self.close()
            raise Disconnected("connection failed while receiving frame") from None
        except (ValueError, RecursionError):
            self.close()
            raise ProtocolError("invalid UTF-8 JSON frame") from None
        except ProtocolError:
            self.close()
            raise

    def _exchange(self, kind, **fields):
        self._seq += 1
        self._write({"type": kind, "seq": self._seq, **fields})
        while True:
            message = self._read()
            if kind == "unsubscribe" and message.get("type") == "event":
                continue  # Already stopped applying events from this subscription.
            if (type(message.get("in_reply_to")) is int
                    and message["in_reply_to"] == self._seq):
                return message
            self.close()
            raise ProtocolError("response sequence mismatch")

    def _result(self, message):
        try:
            if message.get("type") != "response":
                raise ProtocolError("expected a response")
            return _envelope(message.get("envelope"))
        except ProtocolError:
            self.close()
            raise

    def request(self, kind, *, request_epoch=None, **fields):
        """Send an allowlisted request and return its envelope, including failures.

        A request that changes something carries a restore epoch. Pass `request_epoch` to
        retry a request ID with the epoch it was first sent with: the answer's
        `request_epoch`, which a caller keeps with the `request_id`. Without it, the runtime's
        current epoch from the hello is used. A kept epoch is never sent to a runtime that did
        not negotiate `request-epoch/1`: the answer is then `SCHEMA_UNSUPPORTED`, and nothing
        is sent. A request with no kept epoch goes to such a runtime without one."""
        if self._subscription is not None:
            raise ValueError("use a separate connection for requests during a subscription")
        fixed = REQUESTS[kind]
        if fixed.keys() & fields.keys():
            raise ValueError("request discriminator and fixed fields cannot be overridden")
        if kind == "inspect" and {"select", "page"} & fields.keys():
            raise ValueError("this client supports whole inspect reads")
        if kind == "show" and "wait_ms" in fields:
            raise ValueError("use the wait request to supply wait_ms")
        if kind == "wait" and not _uint(fields.get("wait_ms"), "wait_ms"):
            raise ValueError("wait_ms must be positive")
        frame = {"request": {**fields, **fixed}}
        if kind in MUTATING:
            if request_epoch is not None:
                _uint(request_epoch, "request_epoch")
                if EPOCH_CAPABILITY not in self.capabilities:
                    return kept_epoch_unsupported()
                frame["request_epoch"] = request_epoch
            elif EPOCH_CAPABILITY in self.capabilities:
                frame["request_epoch"] = self.restore_epoch
        elif request_epoch is not None:
            raise ValueError("only a request that changes something carries a restore epoch")
        result = self._result(self._exchange("request", **frame))
        if code_defaults(result).success:
            try:
                data = result["data"]
                if kind == "inspect" and fields.get("subject") == "destinations":
                    if not isinstance(data.get("items"), list):
                        raise ProtocolError("data.items must be an array")
                if kind == "events" and fields.get("cursor") is not None:
                    events = data.get("events")
                    if not isinstance(events, list):
                        raise ProtocolError("data.events must be an array")
                    data["events"] = [event for event in events if _event_type(event) in EVENT_TYPES]
            except ProtocolError:
                self.close()
                raise
        return result

    def subscribe(self, *, filter=None, cursor=None):
        """Read the subscription head; callers decide when its cursor is applied."""
        if self._subscription is not None:
            raise ValueError("connection already has a subscription")
        fields = {"filter": {} if filter is None else filter}
        if cursor is not None:
            fields["from_cursor"] = cursor
        reply = self._exchange("subscribe", **fields)
        try:
            if reply.get("type") != "subscribed":
                raise Refused("subscribe", self._result(reply))
            self._subscription = _uint(reply.get("subscription"), "subscription")
            _string(reply, "cursor")
        except ProtocolError:
            self.close()
            raise
        return reply

    def next_event(self):
        if self._subscription is None:
            raise ValueError("no active subscription")
        reply = self._read()
        try:
            if (reply.get("type") != "event"
                    or _uint(reply.get("subscription"), "subscription") != self._subscription):
                raise ProtocolError("expected an event for the active subscription")
            event = _object(reply.get("event"), "event")
            _event_type(event)
        except ProtocolError:
            self.close()
            raise
        return event

    def unsubscribe(self):
        if self._subscription is None:
            raise ValueError("no active subscription")
        reply = self._result(self._exchange("unsubscribe", subscription=self._subscription))
        if not code_defaults(reply).success:
            self.close()
        self._subscription = None
        return reply


class Subscription:
    """Apply one stream at a time. Call start again after an ending to resume."""

    def __init__(self, connect, apply_snapshot, apply_event, persist, *, filter=None, cursor=None):
        self._connect = connect
        self._apply_snapshot, self._apply_event, self._persist = apply_snapshot, apply_event, persist
        self._filter = copy.deepcopy({} if filter is None else filter)
        self.cursor, self.ending = cursor, None
        self._client, self._seen = None, set()

    def _checkpoint(self, cursor):
        if cursor != self.cursor:
            self._persist(cursor)
            self.cursor = cursor

    def start(self):
        if self._client is not None:
            raise ValueError("stop the current stream before starting another")
        self.ending = None
        try:
            self._client = self._connect()
            head = self._client.subscribe(filter=self._filter, cursor=self.cursor)
            self._head = head["cursor"]
            self._backlog = None
            snapshot = head.get("snapshot")
            if snapshot is not None:
                if _string(_object(snapshot, "snapshot"), "cursor") != self._head:
                    raise ProtocolError("snapshot cursor differs from subscription head")
                if "data" not in snapshot:
                    raise ProtocolError("snapshot has no data")
                self._apply_snapshot(snapshot)
                self._checkpoint(self._head)
                self._seen.clear()
            elif self.cursor is None:
                raise ProtocolError("initial subscription has no snapshot")
            elif "backlog" in head:
                self._backlog = _uint(head["backlog"], "backlog")
                if self._backlog == 0:
                    self._checkpoint(self._head)
            return head
        except BaseException:
            self.stop("start_failed")
            raise

    def step(self):
        """Consume a frame. Return False on a terminal event or disconnect."""
        if self._client is None:
            raise ValueError("start the stream before reading events")
        try:
            try:
                event = self._client.next_event()
            except Disconnected:
                self.stop("disconnected")
                return False
            kind = event["type"]
            if kind == "resync_required":
                self.stop(kind)
                return False
            if kind == "client" and _string(_object(event.get("payload"), "payload"), "kind") == "revoked":
                self.stop("revoked")
                return False
            ident, cursor = _string(event, "event_id"), _string(event, "cursor")
            if ident not in self._seen:
                if kind in EVENT_TYPES:
                    self._apply_event(event)
                self._checkpoint(cursor)
                self._seen.add(ident)
            if self._backlog:
                self._backlog -= 1
                if self._backlog == 0:
                    self._checkpoint(self._head)
            return True
        except BaseException:
            self.stop("read_failed")
            raise

    def stop(self, reason="stopped"):
        """Drop the dedicated connection without advancing the checkpoint."""
        if self._client is not None:
            self._client.close()
            self._client = None
        self.ending = reason
